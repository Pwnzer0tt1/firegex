
#ifndef NFQUEUE_CLASS_CPP
#define NFQUEUE_CLASS_CPP

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <tins/tcp_ip/stream_identifier.h>
#include <libmnl/libmnl.h>
#include <tins/tins.h>

using namespace std;

namespace Firegex{
namespace NfQueue{

enum class FilterAction{ DROP, ACCEPT, MANGLE, NOACTION };
enum class L4Proto { TCP, UDP, RAW };
typedef Tins::TCPIP::StreamIdentifier stream_id;


template<typename T>
class PktRequest {
	private:
	FilterAction action = FilterAction::NOACTION;
	mnl_socket* nl = nullptr;
	nfgenmsg * nfg = nullptr;
	nfqnl_msg_packet_hdr *ph;
	shared_ptr<char[]> packet_buffer; // Will be deallocated here
	size_t data_size = 0;
	public:
	const bool is_ipv6;
	Tins::IP* ipv4 = nullptr;
	Tins::IPv6* ipv6 = nullptr;
	Tins::TCP* tcp = nullptr;
	Tins::UDP* udp = nullptr;
	const L4Proto l4_proto;
	const bool is_input;
	
	const string packet;
	const string data;
	const stream_id sid;

	T* ctx;

	private:

	inline void fetch_data_size(Tins::PDU* pdu){
		auto inner = pdu->inner_pdu();
		if (inner == nullptr){
			data_size = 0;
		}else{
			data_size = inner->size();
		}
	}

	L4Proto fill_l4_info(){
		if (is_ipv6){
			tcp = ipv6->find_pdu<Tins::TCP>();
			if (tcp == nullptr){
				udp = ipv6->find_pdu<Tins::UDP>();
				if (udp == nullptr){
					fetch_data_size(ipv6);
					return L4Proto::RAW;
				}else{
					fetch_data_size(udp);
					return L4Proto::UDP;
				}
			}else{
				fetch_data_size(tcp);
				return L4Proto::TCP;
			}
		}else{
			tcp = ipv4->find_pdu<Tins::TCP>();
			if (tcp == nullptr){
				udp = ipv4->find_pdu<Tins::UDP>();
				if (udp == nullptr){
					fetch_data_size(ipv4);
					return L4Proto::RAW;
				}else{
					fetch_data_size(udp);
					return L4Proto::UDP;
				}
			}else{
				fetch_data_size(tcp);
				return L4Proto::TCP;
			}
		}
	}

	public:

	PktRequest(shared_ptr<char[]> buf, Tins::IP* ipv4, const char* payload, size_t plen, stream_id sid, T* ctx, mnl_socket* nl, nfgenmsg *nfg, nfqnl_msg_packet_hdr *ph, bool is_input):
		is_ipv6(false), ipv4(ipv4), packet(string(payload, plen)), sid(sid), ctx(ctx), nl(nl), nfg(nfg), ph(ph),
		is_input(is_input), packet_buffer(buf), l4_proto(fill_l4_info()), data(string(payload+(plen-data_size), data_size)) {}

	PktRequest(shared_ptr<char[]> buf, Tins::IPv6* ipv6, const char* payload, size_t plen, stream_id sid, T* ctx, mnl_socket* nl, nfgenmsg *nfg, nfqnl_msg_packet_hdr *ph, bool is_input):
		is_ipv6(true), ipv6(ipv6), packet(string(payload, plen)), sid(sid), ctx(ctx), nl(nl), nfg(nfg), ph(ph),
		is_input(is_input), packet_buffer(buf), l4_proto(fill_l4_info()), data(string(payload+(plen-data_size), data_size)) {}

	void drop(){
		if (action == FilterAction::NOACTION){
			action = FilterAction::DROP;
			perfrom_action();
		}else{
			throw invalid_argument("Cannot drop a packet that has already been dropped or accepted");
		}
	}

	void accept(){
		if (action == FilterAction::NOACTION){
			action = FilterAction::ACCEPT;
			perfrom_action();
		}else{
			throw invalid_argument("Cannot accept a packet that has already been dropped or accepted");
		}
	}

	void mangle(){
		if (action == FilterAction::NOACTION){
			action = FilterAction::MANGLE;
			perfrom_action();
		}else{
			throw invalid_argument("Cannot mangle a packet that has already been accepted or dropped");
		}
	}

	FilterAction get_action(){
		return action;
	}

	~PktRequest(){
		if (ipv4 != nullptr){
            delete ipv4;
        }
        if (ipv6 != nullptr){
            delete ipv6;
        }
	}

	private:
	void perfrom_action(){
		char buf[MNL_SOCKET_BUFFER_SIZE];
		struct nlmsghdr *nlh_verdict;
		nlh_verdict = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, ntohs(nfg->res_id));
		switch (action)
		{
			case FilterAction::ACCEPT:
				nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_ACCEPT );
				break;
			case FilterAction::DROP:
				nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_DROP );
				break;
			case FilterAction::MANGLE:{
				if (is_ipv6){
					nfq_nlmsg_verdict_put_pkt(nlh_verdict, ipv6->serialize().data(), ipv6->size());
				}else{
					nfq_nlmsg_verdict_put_pkt(nlh_verdict, ipv4->serialize().data(), ipv4->size());
				}
				nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_ACCEPT );
				break;
			}
			default:
				throw invalid_argument("Invalid action");
		}
		if (mnl_socket_sendto(nl, nlh_verdict, nlh_verdict->nlmsg_len) < 0) {
			throw runtime_error( "mnl_socket_send" );
		}
	}

};

struct internal_nfqueue_execution_data_tmp{
    mnl_socket* nl = nullptr;
    void *data = nullptr;
	shared_ptr<char[]> packet_buffer;
};

const size_t NFQUEUE_BUFFER_SIZE = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
/*  NfQueue wrapper class to handle nfqueue packets
    this class is made to be possible enqueue multiple packets to multiple threads
    --> handle function is responsable to delete the PktRequest object */
template <typename D, void handle_func(PktRequest<D>*)>
class NfQueue {
    private:
	mnl_socket* nl = nullptr;
	unsigned int portid;
    public:

	const uint16_t queue_num;

	NfQueue(u_int16_t queue_num): queue_num(queue_num) {
		nl = mnl_socket_open(NETLINK_NETFILTER);
		
		if (nl == nullptr) { throw runtime_error( "mnl_socket_open" );}

		if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
			mnl_socket_close(nl);
			throw runtime_error( "mnl_socket_bind" );
		}
		portid = mnl_socket_get_portid(nl);

		char queue_msg_buffer[NFQUEUE_BUFFER_SIZE];

		if (_send_config_cmd(NFQNL_CFG_CMD_BIND, queue_msg_buffer) < 0) {
			_clear();
			throw runtime_error( "mnl_socket_send" );
		}
		//TEST if BIND was successful
		if (_send_config_cmd(NFQNL_CFG_CMD_NONE, queue_msg_buffer) < 0) { // SEND A NONE command to generate an error meessage
			_clear();
			throw runtime_error( "mnl_socket_send" );
		}
		if (_recv_packet(queue_msg_buffer) == -1) { //RECV the error message
			_clear();
			throw runtime_error( "mnl_socket_recvfrom" );
		}

		struct nlmsghdr *nlh = (struct nlmsghdr *) queue_msg_buffer;
		
		if (nlh->nlmsg_type != NLMSG_ERROR) {
			_clear();
			throw runtime_error( "unexpected packet from kernel (expected NLMSG_ERROR packet)" );
		}		
		//nfqnl_msg_config_cmd
		nlmsgerr* error_msg = (nlmsgerr *)mnl_nlmsg_get_payload(nlh);	

		// error code taken from the linux kernel:
		// https://elixir.bootlin.com/linux/v5.18.12/source/include/linux/errno.h#L27
		#define ENOTSUPP	524	/* Operation is not supported */

		if (error_msg->error != -ENOTSUPP) {
			_clear();
			throw invalid_argument( "queueid is already busy" );
		}
		
		//END TESTING BIND
		nlh = nfq_nlmsg_put(queue_msg_buffer, NFQNL_MSG_CONFIG, queue_num);
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

		mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
		mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

		if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
			_clear();
			throw runtime_error( "mnl_socket_send" );
		}

		/*
		* ENOBUFS is signalled to userspace when packets were lost
		* on kernel side.  In most cases, userspace isn't interested
		* in this information, so turn it off.
		*/
		int tmp = 1;
		mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &tmp, sizeof(int));

	}

	void handle_next_packet(D* data){
		auto queue_msg_buffer = make_shared<char[]>(NFQUEUE_BUFFER_SIZE);
		int ret = _recv_packet(queue_msg_buffer.get(), NFQUEUE_BUFFER_SIZE);
		if (ret == -1) {
			throw runtime_error( "mnl_socket_recvfrom" );
		}
		internal_nfqueue_execution_data_tmp raw_ptr = {
			nl: nl,
			data: data,
			packet_buffer: queue_msg_buffer
		};

		ret = mnl_cb_run(queue_msg_buffer.get(), ret, 0, portid, _real_queue_cb, &raw_ptr);
		if (ret <= 0){
			cerr << "[error] [NfQueue.handle_next_packet] mnl_cb_run error with: " << ret << endl;
			throw runtime_error( "mnl_cb_run error!" );
		}
	}
	
	~NfQueue() {
		char queue_msg_buffer[NFQUEUE_BUFFER_SIZE];
		_send_config_cmd(NFQNL_CFG_CMD_UNBIND, queue_msg_buffer);
		_clear();
	}
    
    private:

	template<typename T, typename = enable_if_t<is_base_of_v<Tins::PDU, T>>>
	static void inline _send_verdict(shared_ptr<char[]> raw_buf, T* packet, char *payload, uint16_t plen, nfgenmsg *nfg, nfqnl_msg_packet_hdr *ph, internal_nfqueue_execution_data_tmp* ctx, bool is_input){
		handle_func(new PktRequest<D>(
			raw_buf, packet, payload, plen,
			stream_id::make_identifier(*packet),
			(D*)ctx->data, ctx->nl, nfg, ph, is_input
		));
	}

    static int _real_queue_cb(const nlmsghdr *nlh, void *data_ptr) {
		
        internal_nfqueue_execution_data_tmp* info = (internal_nfqueue_execution_data_tmp*) data_ptr;

		//Extract attributes from the nlmsghdr
		nlattr *attr[NFQA_MAX+1] = {};
		
		if (nfq_nlmsg_parse(nlh, attr) < 0) {
			cerr << "[error] [NfQueue._real_queue_cb] problems parsing" << endl;
			return MNL_CB_ERROR;
		}
		if (attr[NFQA_PACKET_HDR] == nullptr) {
			cerr << "[error] [NfQueue._real_queue_cb] packet header not set" << endl;
			return MNL_CB_ERROR;
		}
		if (attr[NFQA_MARK] == nullptr) {
			cerr << "[error] [NfQueue._real_queue_cb] mark not set" << endl;
			return MNL_CB_ERROR;
		}
		
		//Get Payload
		uint16_t plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
		char *payload = (char *)mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
		
		//Return result to the kernel
		struct nfqnl_msg_packet_hdr *ph = (nfqnl_msg_packet_hdr*) mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
		struct nfgenmsg *nfg = (nfgenmsg *)mnl_nlmsg_get_payload(nlh);

		bool is_input = ntohl(mnl_attr_get_u32(attr[NFQA_MARK])) & 0x1; // == 0x1337 that is odd
		// Check IP protocol version
		if ( (payload[0] & 0xf0) == 0x40 ){
			_send_verdict(info->packet_buffer, new Tins::IP((uint8_t*)payload, plen), payload, plen, nfg, ph, info, is_input);
		}else{
			_send_verdict(info->packet_buffer, new Tins::IPv6((uint8_t*)payload, plen), payload, plen, nfg, ph, info, is_input);
		}
		return MNL_CB_OK;
    }

	inline void _clear(){
		if (nl != nullptr) {
			mnl_socket_close(nl);
			nl = nullptr;
		}
	}

    inline ssize_t _send_config_cmd(nfqnl_msg_config_cmds cmd, char* buf){
		struct nlmsghdr *nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
		nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, cmd);
		return mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
	}

	inline ssize_t _recv_packet(char* buf, size_t buf_size = NFQUEUE_BUFFER_SIZE){
		return mnl_socket_recvfrom(nl, buf, buf_size);
	}	

};



uint32_t hash_stream_id(const stream_id &sid) {
    uint32_t addr_hash = 0;
    const uint32_t* min_addr = reinterpret_cast<const uint32_t*>(sid.min_address.data());
    const uint32_t* max_addr = reinterpret_cast<const uint32_t*>(sid.max_address.data());
    addr_hash ^= min_addr[0] ^ min_addr[1] ^ min_addr[2] ^ min_addr[3];
    addr_hash ^= max_addr[0] ^ max_addr[1] ^ max_addr[2] ^ max_addr[3];

    uint32_t ports = (static_cast<uint32_t>(sid.min_address_port) << 16) | sid.max_address_port;
    
    uint32_t hash = addr_hash ^ ports;
    
    hash *= 0x9e3779b9;
    
    return hash;
}

}}
#endif // NFQUEUE_CLASS_CPP