#ifndef PROXY_TUNNEL_CPP
#define PROXY_TUNNEL_CPP

#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <tins/tins.h>
#include <tins/tcp_ip/stream_follower.h>
#include <tins/tcp_ip/stream_identifier.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/types.h>
#include <stdexcept>
#include <iostream>
#include "../classes/netfilter.cpp"
#include <functional>

using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;
using namespace std;

typedef Tins::TCPIP::StreamIdentifier stream_id;

class SocketTunnelQueue: public NfQueueExecutor {
	public:

	StreamFollower follower;

    void before_loop() override {
		follower.new_stream_callback(bind(on_new_stream, placeholders::_1));
		follower.stream_termination_callback(bind(on_stream_close, placeholders::_1));
    }

    void * callback_data_fetch() override{
        return nullptr;
    }

	static bool filter_action(){
		return true;
	}
	
	static void on_data_recv(Stream& stream, string data, bool is_input) {
		bool result = filter_action();
		if (!result){
			stream.ignore_client_data();
			stream.ignore_server_data();
		}
	}
	
	//Input data filtering
	static void on_client_data(Stream& stream) {
		on_data_recv(stream, string(stream.client_payload().begin(), stream.client_payload().end()), true);
	}
	
	//Server data filtering
	static void on_server_data(Stream& stream) {
		on_data_recv(stream, string(stream.server_payload().begin(), stream.server_payload().end()), false);
	}
	
	
	// A stream was terminated. The second argument is the reason why it was terminated
	static void on_stream_close(Stream& stream) {
		stream_id stream_id = stream_id::make_identifier(stream);
	}
	
	static void on_new_stream(Stream& stream) {
		stream.auto_cleanup_payloads(true);
		if (stream.is_partial_stream()) {
			return;
		}
		stream.client_data_callback(bind(on_client_data, placeholders::_1));
		stream.server_data_callback(bind(on_server_data, placeholders::_1));
		stream.stream_closed_callback(bind(on_stream_close, placeholders::_1));
	}
	
	
	template<typename T>
	static void build_verdict(T packet, uint8_t *payload, uint16_t plen, nlmsghdr *nlh_verdict, nfqnl_msg_packet_hdr *ph){
		sctx->tcp_match_util.matching_has_been_called = false;
		sctx->follower.process_packet(packet);
		if (sctx->tcp_match_util.matching_has_been_called && !sctx->tcp_match_util.result){
			Tins::PDU* data_layer = tcp->release_inner_pdu();
			if (data_layer != nullptr){
				delete data_layer;
			}
			tcp->set_flag(Tins::TCP::FIN,1);
			tcp->set_flag(Tins::TCP::ACK,1);
			tcp->set_flag(Tins::TCP::SYN,0);
			nfq_nlmsg_verdict_put_pkt(nlh_verdict, packet.serialize().data(), packet.size());
		}
		nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_ACCEPT );
	}
	
	static int queue_cb(const nlmsghdr *nlh, const mnl_socket* nl, void *data_ptr) {
	
		//Extract attributes from the nlmsghdr
		nlattr *attr[NFQA_MAX+1] = {};
		
		if (nfq_nlmsg_parse(nlh, attr) < 0) {
			perror("problems parsing");
			return MNL_CB_ERROR;
		}
		if (attr[NFQA_PACKET_HDR] == nullptr) {
			fputs("metaheader not set\n", stderr);
			return MNL_CB_ERROR;
		}
		//Get Payload
		uint16_t plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
		uint8_t *payload = (uint8_t *)mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
		
		//Return result to the kernel
		struct nfqnl_msg_packet_hdr *ph = (nfqnl_msg_packet_hdr*) mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
		struct nfgenmsg *nfg = (nfgenmsg *)mnl_nlmsg_get_payload(nlh);
		char buf[MNL_SOCKET_BUFFER_SIZE];
		struct nlmsghdr *nlh_verdict;
	
		nlh_verdict = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, ntohs(nfg->res_id));
	
		// Check IP protocol version
		if ( (payload[0] & 0xf0) == 0x40 ){
			build_verdict(Tins::IP(payload, plen), payload, plen, nlh_verdict, ph);
		}else{
			build_verdict(Tins::IPv6(payload, plen), payload, plen, nlh_verdict, ph);
		}
	
		if (mnl_socket_sendto(nl, nlh_verdict, nlh_verdict->nlmsg_len) < 0) {
			throw runtime_error( "mnl_socket_send" );
		}
	
		return MNL_CB_OK;
	}

	SocketTunnelQueue(int queue) : NfQueueExecutor(queue, &queue_cb) {}

	~SocketTunnelQueue() {
		// TODO
	}

};

#endif // PROXY_TUNNEL_CPP