#ifndef PROXY_TUNNEL_CLASS_CPP
#define PROXY_TUNNEL_CLASS_CPP

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
#include <thread>
#include <hs.h>
#include <syncstream>
#include <iostream>
#include "../classes/netfilter.cpp"
#include "stream_ctx.cpp"
#include "settings.cpp"

using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;
using namespace std;

class PyProxyQueue: public NfQueueExecutor {
	public:
	stream_ctx sctx;

    void before_loop() override {
		sctx.follower.new_stream_callback(bind(on_new_stream, placeholders::_1, &sctx));
		sctx.follower.stream_termination_callback(bind(on_stream_close, placeholders::_1, &sctx));
    }

    void * callback_data_fetch() override{
        return &sctx;
    }

	static bool filter_action(packet_info& info){
		shared_ptr<PyCodeConfig> conf = config;
		auto stream_search = info.sctx->streams_ctx.find(info.sid);
		pyfilter_ctx stream_match;
		if (stream_search == info.sctx->streams_ctx.end()){
			// TODO: New pyfilter_ctx
		}else{
			stream_match = stream_search->second;
		}

		bool has_matched = false;
		//TODO exec filtering action

		if (has_matched){
			// Say to firegex what filter has matched
			//osyncstream(cout) << "BLOCKED " << rules_vector[match_res.matched] << endl;
			return false;
		}
		return true;
	}

	//If the stream has already been matched, drop all data, and try to close the connection
	static void keep_fin_packet(stream_ctx* sctx){
		sctx->match_info.matching_has_been_called = true;
		sctx->match_info.already_closed = true;
	}
	
	static void on_data_recv(Stream& stream, stream_ctx* sctx, string data) {
		sctx->match_info.matching_has_been_called = true;
		sctx->match_info.already_closed = false;
		bool result = filter_action(*sctx->match_info.pkt_info);
		if (!result){
			sctx->clean_stream_by_id(sctx->match_info.pkt_info->sid);
			stream.client_data_callback(bind(keep_fin_packet, sctx));
			stream.server_data_callback(bind(keep_fin_packet, sctx));
		}
		sctx->match_info.result = result;
	}
	
	//Input data filtering
	static void on_client_data(Stream& stream, stream_ctx* sctx) {
		sctx->match_info.pkt_info->is_input = true;
		on_data_recv(stream, sctx, string(stream.client_payload().begin(), stream.client_payload().end()));
	}
	
	//Server data filtering
	static void on_server_data(Stream& stream, stream_ctx* sctx) {
		sctx->match_info.pkt_info->is_input = false;
		on_data_recv(stream, sctx, string(stream.server_payload().begin(), stream.server_payload().end()));
	}
	
	// A stream was terminated. The second argument is the reason why it was terminated
	static void on_stream_close(Stream& stream, stream_ctx* sctx) {
		stream_id stream_id = stream_id::make_identifier(stream);
		sctx->clean_stream_by_id(stream_id);
	}
	
	static void on_new_stream(Stream& stream, stream_ctx* sctx) {
		stream.auto_cleanup_payloads(true);
		if (stream.is_partial_stream()) {
			//TODO take a decision about this...
			stream.enable_recovery_mode(10 * 1024);
		}
		stream.client_data_callback(bind(on_client_data, placeholders::_1, sctx));
		stream.server_data_callback(bind(on_server_data, placeholders::_1, sctx));
		stream.stream_closed_callback(bind(on_stream_close, placeholders::_1, sctx));
	}

	template<typename T>
	static void build_verdict(T packet, uint8_t *payload, uint16_t plen, nlmsghdr *nlh_verdict, nfqnl_msg_packet_hdr *ph, stream_ctx* sctx, bool is_ipv6){
		Tins::TCP* tcp = packet.template find_pdu<Tins::TCP>();
		if (!tcp){
			throw invalid_argument("Only TCP and UDP are supported");
		}
		Tins::PDU* application_layer = tcp->inner_pdu();
		u_int16_t payload_size = 0;
		if (application_layer != nullptr){
			payload_size = application_layer->size();
		}
		packet_info pktinfo{
			payload: string(payload+plen - payload_size, payload+plen),
			sid: stream_id::make_identifier(packet),
			is_ipv6: is_ipv6,
			sctx: sctx,
			packet_pdu: &packet,
			tcp: tcp,
		};
		sctx->match_info.matching_has_been_called = false;
		sctx->match_info.pkt_info = &pktinfo;
		sctx->follower.process_packet(packet);
		// Do an action only is an ordered packet has been received
		if (sctx->match_info.matching_has_been_called){
			bool empty_payload = pktinfo.payload.empty();
			//In this 2 cases we have to remove all data about the stream
			if (!sctx->match_info.result || sctx->match_info.already_closed){
				#ifdef DEBUG
					cerr << "[DEBUG] [NetfilterQueue.build_verdict] Stream matched, removing all data about it" << endl;
				#endif
				sctx->clean_stream_by_id(pktinfo.sid);
				//If the packet has data, we have to remove it
				if (!empty_payload){
					Tins::PDU* data_layer = tcp->release_inner_pdu();
					if (data_layer != nullptr){
						delete data_layer;
					}
				}
				//For the first matched data or only for data packets, we set FIN bit
				//This only for client packets, because this will trigger server to close the connection
				//Packets will be filtered anyway also if client don't send packets
				if ((!sctx->match_info.result || !empty_payload) && is_input){
					tcp->set_flag(Tins::TCP::FIN,1);
					tcp->set_flag(Tins::TCP::ACK,1);
					tcp->set_flag(Tins::TCP::SYN,0);
				}
				//Send the edited packet to the kernel
				nfq_nlmsg_verdict_put_pkt(nlh_verdict, packet.serialize().data(), packet.size());
			}
		}
		nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_ACCEPT );

	}
	
	static int queue_cb(const nlmsghdr *nlh, const mnl_socket* nl, void *data_ptr) {
	
		stream_ctx* sctx = (stream_ctx*)data_ptr;
	
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
			build_verdict(Tins::IP(payload, plen), payload, plen, nlh_verdict, ph, sctx, false);
		}else{
			build_verdict(Tins::IPv6(payload, plen), payload, plen, nlh_verdict, ph, sctx, true);
		}
	
		if (mnl_socket_sendto(nl, nlh_verdict, nlh_verdict->nlmsg_len) < 0) {
			throw runtime_error( "mnl_socket_send" );
		}
		return MNL_CB_OK;
	}

	PyProxyQueue(int queue) : NfQueueExecutor(queue, &queue_cb) {}

	~PyProxyQueue() {
		sctx.clean();
	}

};

#endif // PROXY_TUNNEL_CLASS_CPP