
#ifndef NFQUEUE_CLASS_CPP
#define NFQUEUE_CLASS_CPP

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <tins/tcp_ip/stream_identifier.h>
#include <libmnl/libmnl.h>
#include <tins/tins.h>
#include <map>

using namespace std;

namespace Firegex{
namespace NfQueue{

enum class FilterAction{ DROP, ACCEPT, MANGLE, NOACTION };
enum class L4Proto { TCP, UDP, RAW };
typedef Tins::TCPIP::StreamIdentifier stream_id;

struct tcp_ack_seq_ctx{
	int64_t in = 0;
	int64_t out = 0;
	tcp_ack_seq_ctx(){}
	void reset(){
		in = 0;
		out = 0;
	}
};

typedef map<stream_id, tcp_ack_seq_ctx*> tcp_ack_map;

template<typename T>
class PktRequest {
	private:
	FilterAction action = FilterAction::NOACTION;
	mnl_socket* nl = nullptr;
	uint16_t res_id;
	uint32_t packet_id;
	size_t _original_size;
	size_t _data_original_size;
	size_t _header_size;
	bool need_tcp_fixing = false;
	public:
	bool is_ipv6;
	Tins::IP* ipv4 = nullptr;
	Tins::IPv6* ipv6 = nullptr;
	Tins::TCP* tcp = nullptr;
	Tins::UDP* udp = nullptr;
	L4Proto l4_proto;
	bool is_input;

	string packet;
	stream_id sid;

	tcp_ack_seq_ctx* ack_seq_offset = nullptr;

	T* ctx = nullptr;

	private:

	static inline size_t inner_data_size(Tins::PDU* pdu){
		if (pdu == nullptr){
			return 0;
		}
		auto inner = pdu->inner_pdu();
		if (inner == nullptr){
			return 0;
		}
		return inner->size();
	}

	inline void __internal_fetch_data_size(Tins::PDU* pdu){
		_data_original_size = inner_data_size(pdu);
		_header_size = _original_size - _data_original_size;
	}

	L4Proto fill_l4_info(){
		if (is_ipv6){
			tcp = ipv6->find_pdu<Tins::TCP>();
			if (tcp == nullptr){
				udp = ipv6->find_pdu<Tins::UDP>();
				if (udp == nullptr){
					__internal_fetch_data_size(ipv6);
					return L4Proto::RAW;
				}else{
					__internal_fetch_data_size(udp);
					return L4Proto::UDP;
				}
			}else{
				__internal_fetch_data_size(tcp);
				return L4Proto::TCP;
			}
		}else{
			tcp = ipv4->find_pdu<Tins::TCP>();
			if (tcp == nullptr){
				udp = ipv4->find_pdu<Tins::UDP>();
				if (udp == nullptr){
					__internal_fetch_data_size(ipv4);
					return L4Proto::RAW;
				}else{
					__internal_fetch_data_size(udp);
					return L4Proto::UDP;
				}
			}else{
				__internal_fetch_data_size(tcp);
				return L4Proto::TCP;
			}
		}
	}

	bool need_tcp_fix(){
		return tcp && ack_seq_offset != nullptr && (ack_seq_offset->in != 0 || ack_seq_offset->out != 0);
	}

	public:

	PktRequest(const char* payload, size_t plen, T* ctx, mnl_socket* nl, nfgenmsg *nfg, nfqnl_msg_packet_hdr *ph, bool is_input):
		ctx(ctx), nl(nl), res_id(nfg->res_id),
		packet_id(ph->packet_id), is_input(is_input),
		packet(string(payload, plen)),
		action(FilterAction::NOACTION),
		is_ipv6((payload[0] & 0xf0) == 0x60)
	{
		if (is_ipv6){
			ipv6 = new Tins::IPv6((uint8_t*)packet.c_str(), plen);
			sid = stream_id::make_identifier(*ipv6);
			_original_size = ipv6->size();
		}else{
			ipv4 = new Tins::IP((uint8_t*)packet.c_str(), plen);
			sid = stream_id::make_identifier(*ipv4);
			_original_size = ipv4->size();
		}
		l4_proto = fill_l4_info();
		#ifdef DEBUG
		if (tcp){			
			cerr << "[DEBUG] NEW_PACKET " << (is_input?"-> IN ":"<- OUT")  << " [SIZE: " << data_size() << "] FLAGS: " << (tcp->get_flag(Tins::TCP::FIN)?"FIN ":"") << (tcp->get_flag(Tins::TCP::SYN)?"SYN ":"") << (tcp->get_flag(Tins::TCP::RST)?"RST ":"") << (tcp->get_flag(Tins::TCP::ACK)?"ACK ":"") << (tcp->get_flag(Tins::TCP::PSH)?"PSH ":"") << endl;
			cerr << "[SEQ: " << tcp->seq() << "] [ACK: " << tcp->ack_seq() << "]" << " [WIN: " << tcp->window() << "] [FLAGS: " << tcp->flags() << "]\n" << endl;
		}
		#endif
	}

	inline size_t header_size(){
		return _header_size;
	}

	char* data(){
		return packet.data()+_header_size;
	}

	size_t data_size(){
		return packet.size()-_header_size;
	}

	size_t data_original_size(){
		return _data_original_size;
	}

	void reserialize(){
		auto data = serialize();
		packet.resize(data.size());
		memcpy(packet.data(), data.data(), data.size());
	}

	void set_data(const char* data, const size_t& data_size){
		auto bef_raw = before_raw_pdu_ptr();
		if (bef_raw){
			delete before_raw_pdu_ptr()->release_inner_pdu();
			if (data_size > 0){
				before_raw_pdu_ptr() /= move(Tins::RawPDU((uint8_t*)data, data_size));
			}
		}
	}

	Tins::PDU* before_raw_pdu_ptr(){
		if (tcp){
			return tcp;
		}else if (udp){
			return udp;
		}else if (ipv4){
			return ipv4;
		}else if (ipv6){
			return ipv6;
		}
		return nullptr;
	}

	void set_packet(const char* data, size_t data_size){
		// Parsing only the header with libtins
		Tins::PDU *data_pdu = nullptr;
		size_t total_size;
		if (is_ipv6){
			delete ipv6;
			ipv6 = nullptr;
			if (data_size >= 40){ // 40 == fixed size of ipv6 header
				// Resetting payload length before parsing to libtins
				uint16_t payload_len = htons(data_size-40);
				memcpy(((uint8_t *)data)+4, &payload_len, 2);
			}
			ipv6 = new Tins::IPv6((uint8_t*)data, data_size);
			if (tcp){
				tcp = ipv6->find_pdu<Tins::TCP>();
				data_pdu = tcp;
			}else if (udp){
				udp = ipv6->find_pdu<Tins::UDP>();
				data_pdu = udp;
			}else{
				data_pdu = ipv6;
			}
			total_size = ipv6->size();
		}else{
			delete ipv4;
			ipv4 = nullptr;
			ipv4 = new Tins::IP((uint8_t*)data, data_size);
			if (tcp){
				tcp = ipv4->find_pdu<Tins::TCP>();
				data_pdu = tcp;
			}else if(udp){
				udp = ipv4->find_pdu<Tins::UDP>();
				data_pdu = udp;
			}else{
				data_pdu = ipv4;
			}
			total_size = ipv4->size();
		}
		_header_size = total_size - inner_data_size(data_pdu);
		// Libtins can skip data if the lenght is changed to a bigger len (due to ip header total lenght), so we need to specify the data section manually
		set_data(data+_header_size, data_size-_header_size);
	}

	void fix_tcp_ack(){
		need_tcp_fixing = need_tcp_fix();
		if(!need_tcp_fixing){
			return;
		}
		#ifdef DEBUG
		cerr << "[DEBUG] Fixing ack_seq with offsets " << ((int32_t)ack_seq_offset->in) << " " << ((int32_t)ack_seq_offset->out) << endl;
		#endif
		if (is_input){
			tcp->seq(tcp->seq() + ack_seq_offset->in);
			tcp->ack_seq(tcp->ack_seq() - ack_seq_offset->out);
		}else{
			tcp->ack_seq(tcp->ack_seq() - ack_seq_offset->in);
			tcp->seq(tcp->seq() + ack_seq_offset->out);
		}
		#ifdef DEBUG
		size_t new_size = inner_data_size(tcp);
		cerr << "[DEBUG] FIXED PKT  " << (is_input?"-> IN ":"<- OUT")  << " [SIZE: " << data_size() << "] FLAGS: " << (tcp->get_flag(Tins::TCP::FIN)?"FIN ":"") << (tcp->get_flag(Tins::TCP::SYN)?"SYN ":"") << (tcp->get_flag(Tins::TCP::RST)?"RST ":"") << (tcp->get_flag(Tins::TCP::ACK)?"ACK ":"") << (tcp->get_flag(Tins::TCP::PSH)?"PSH ":"") << endl;
		cerr << "[SEQ: " << tcp->seq() << "] [ACK: " << tcp->ack_seq() << "]" << " [WIN: " << tcp->window() << "] [FLAGS: " << tcp->flags() << "]\n" << endl;
		#endif
	}

	void fix_data_payload(){
		//Stream follower move the payload data, so we need to reinizialize RawPDU
		auto bef_raw = before_raw_pdu_ptr();
		if (bef_raw){
			delete bef_raw->release_inner_pdu();
			auto new_data_size = packet.size()-_header_size;
			if (new_data_size > 0){
				bef_raw /= move(Tins::RawPDU((uint8_t*)packet.data()+_header_size, new_data_size));
			}
		}
	}
		
	void drop(){
		if (action == FilterAction::NOACTION){
			action = FilterAction::DROP;
			perfrom_action();
		}else{
			throw invalid_argument("Cannot drop a packet that has already been dropped or accepted");
		}
	}

	size_t original_size(){
		return _original_size;
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

	void reject(){
		if (tcp){
			//If the packet has data, we have to remove it
			set_data(nullptr, 0);
			//For the first matched data or only for data packets, we set FIN bit
			//This only for client packets, because this will trigger server to close the connection
			//Packets will be filtered anyway also if client don't send packets
			if (_data_original_size != 0){
				tcp->set_flag(Tins::TCP::FIN,1);
				tcp->set_flag(Tins::TCP::ACK,1);
				tcp->set_flag(Tins::TCP::SYN,0);
			}
			//Send the edited packet to the kernel
			mangle();
		}else{
			drop();
		}
	}

	void mangle_custom_pkt(const char* raw_pkt, size_t raw_pkt_size){
		if (action == FilterAction::NOACTION){
			try{
				set_packet(raw_pkt, raw_pkt_size);
				reserialize();
				action = FilterAction::MANGLE;
			}catch(const std::exception& e){
				#ifdef DEBUG
				cerr << "[DEBUG] [PktRequest.mangle_custom_pkt] " << e.what() << endl;
				#endif
				action = FilterAction::DROP;
			}
			perfrom_action(false);
		}else{
			throw invalid_argument("Cannot mangle a packet that has already been accepted or dropped");
		}
	}

	FilterAction get_action(){
		return action;
	}

	~PktRequest(){
		delete ipv4;
        delete ipv6;
	}

	Tins::PDU::serialization_type serialize(){
		if (is_ipv6){
			return ipv6->serialize();
		}else{
			return ipv4->serialize();
		}
	}

	private:
	void perfrom_action(bool do_serialize = true){
		char buf[MNL_SOCKET_BUFFER_SIZE];
		struct nlmsghdr *nlh_verdict = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, ntohs(res_id));
		switch (action)
		{
			case FilterAction::ACCEPT:
				if (need_tcp_fixing){
					if (do_serialize){
						fix_data_payload();
						reserialize();
					}
					nfq_nlmsg_verdict_put_pkt(nlh_verdict, packet.data(), packet.size());
				}
				nfq_nlmsg_verdict_put(nlh_verdict, ntohl(packet_id), NF_ACCEPT );
				break;
			case FilterAction::DROP:
				nfq_nlmsg_verdict_put(nlh_verdict, ntohl(packet_id), NF_DROP );
				break;
			case FilterAction::MANGLE:{
				//If not custom data, use the data in the packets
				if(do_serialize){
					reserialize();
				}
				nfq_nlmsg_verdict_put_pkt(nlh_verdict, packet.data(), packet.size());
				#ifdef DEBUG
				if (tcp){
					cerr << "[DEBUG] MANGLEDPKT " << (is_input?"-> IN ":"<- OUT")  << " [SIZE: " << data_size() << "] FLAGS: " << (tcp->get_flag(Tins::TCP::FIN)?"FIN ":"") << (tcp->get_flag(Tins::TCP::SYN)?"SYN ":"") << (tcp->get_flag(Tins::TCP::RST)?"RST ":"") << (tcp->get_flag(Tins::TCP::ACK)?"ACK ":"") << (tcp->get_flag(Tins::TCP::PSH)?"PSH ":"") << endl;
					cerr << "[SEQ: " << tcp->seq() << "] [ACK: " << tcp->ack_seq() << "]" << " [WIN: " << tcp->window() << "] [FLAGS: " << tcp->flags() << "]\n" << endl;
				}
				#endif
				if (tcp && ack_seq_offset && packet.size() != _original_size){
					if (is_input){
						ack_seq_offset->in += data_size() - _data_original_size;
					}else{
						ack_seq_offset->out += data_size() - _data_original_size;
					}
				}
				nfq_nlmsg_verdict_put(nlh_verdict, ntohl(packet_id), NF_ACCEPT );
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
	char* queue_msg_buffer = nullptr;
	const uint16_t queue_num;

	NfQueue(u_int16_t queue_num): queue_num(queue_num) {
		queue_msg_buffer = new char[NFQUEUE_BUFFER_SIZE];
		nl = mnl_socket_open(NETLINK_NETFILTER);
		
		if (nl == nullptr) { throw runtime_error( "mnl_socket_open" );}

		if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
			mnl_socket_close(nl);
			throw runtime_error( "mnl_socket_bind" );
		}
		portid = mnl_socket_get_portid(nl);

		if (_send_config_cmd(NFQNL_CFG_CMD_BIND) < 0) {
			_clear();
			throw runtime_error( "mnl_socket_send" );
		}
		//TEST if BIND was successful
		if (_send_config_cmd(NFQNL_CFG_CMD_NONE) < 0) { // SEND A NONE command to generate an error meessage
			_clear();
			throw runtime_error( "mnl_socket_send" );
		}
		if (_recv_packet() == -1) { //RECV the error message
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

		char * enable_fail_open = getenv("FIREGEX_NFQUEUE_FAIL_OPEN");

		if (strcmp(enable_fail_open, "1") == 0){
			mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO|NFQA_CFG_F_FAIL_OPEN));
			mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO|NFQA_CFG_F_FAIL_OPEN));
		}else{
			mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
			mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));
		}

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
		int ret = _recv_packet();
		if (ret == -1) {
			throw runtime_error( "mnl_socket_recvfrom" );
		}
		internal_nfqueue_execution_data_tmp raw_ptr = {
			nl: nl,
			data: data
		};

		ret = mnl_cb_run(queue_msg_buffer, ret, 0, portid, _real_queue_cb, &raw_ptr);
		if (ret <= 0){
			cerr << "[error] [NfQueue.handle_next_packet] mnl_cb_run error with: " << ret << endl;
			throw runtime_error( "mnl_cb_run error!" );
		}
	}
	
	~NfQueue() {
		_send_config_cmd(NFQNL_CFG_CMD_UNBIND);
		_clear();
	}
    
    private:

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
		handle_func(new PktRequest<D>(
			payload, plen, (D*)info->data, info->nl, nfg, ph, is_input
		));
		
		return MNL_CB_OK;
    }

	inline void _clear(){
		if (nl != nullptr) {
			mnl_socket_close(nl);
			nl = nullptr;
		}
		delete[] queue_msg_buffer;
	}

    inline ssize_t _send_config_cmd(nfqnl_msg_config_cmds cmd){
		struct nlmsghdr *nlh = nfq_nlmsg_put(queue_msg_buffer, NFQNL_MSG_CONFIG, queue_num);
		nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, cmd);
		return mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
	}

	inline ssize_t _recv_packet(){
		return mnl_socket_recvfrom(nl, queue_msg_buffer, NFQUEUE_BUFFER_SIZE);
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