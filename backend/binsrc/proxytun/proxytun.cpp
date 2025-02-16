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
#include <syncstream>
#include <iostream>
#include "../classes/netfilter.cpp"
#include "stream_ctx.cpp"
#include "settings.cpp"

using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;
using namespace std;

namespace Firegex {
namespace PyProxy {

class PyProxyQueue: public NfQueue::ThreadNfQueue<PyProxyQueue> {
	public:
	stream_ctx sctx;
	StreamFollower follower;

	struct {
		bool matching_has_been_called = false;
		bool already_closed = false;
		bool result;
		NfQueue::PktRequest<PyProxyQueue>* pkt;
	} match_ctx;

    void before_loop() override {
		follower.new_stream_callback(bind(on_new_stream, placeholders::_1, this));
		follower.stream_termination_callback(bind(on_stream_close, placeholders::_1, this));
    }

	bool filter_action(NfQueue::PktRequest<PyProxyQueue>* pkt){
		shared_ptr<PyCodeConfig> conf = config;

		auto stream_search = sctx.streams_ctx.find(pkt->sid);
		pyfilter_ctx* stream_match;
		if (stream_search == sctx.streams_ctx.end()){
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
	static void keep_fin_packet(PyProxyQueue* pkt){
		pkt->match_ctx.matching_has_been_called = true;
		pkt->match_ctx.already_closed = true;
	}
	
	static void on_data_recv(Stream& stream, PyProxyQueue* pkt, string data) {
		pkt->match_ctx.matching_has_been_called = true;
		pkt->match_ctx.already_closed = false;
		bool result = pkt->filter_action(pkt->match_ctx.pkt);
		if (!result){
			pkt->sctx.clean_stream_by_id(pkt->match_ctx.pkt->sid);
			stream.client_data_callback(bind(keep_fin_packet, pkt));
			stream.server_data_callback(bind(keep_fin_packet, pkt));
		}
		pkt->match_ctx.result = result;
	}
	
	//Input data filtering
	static void on_client_data(Stream& stream, PyProxyQueue* pkt) {
		on_data_recv(stream, pkt, string(stream.client_payload().begin(), stream.client_payload().end()));
	}
	
	//Server data filtering
	static void on_server_data(Stream& stream, PyProxyQueue* pkt) {
		on_data_recv(stream, pkt, string(stream.server_payload().begin(), stream.server_payload().end()));
	}
	
	// A stream was terminated. The second argument is the reason why it was terminated
	static void on_stream_close(Stream& stream, PyProxyQueue* pkt) {
		stream_id stream_id = stream_id::make_identifier(stream);
		pkt->sctx.clean_stream_by_id(stream_id);
	}
	
	static void on_new_stream(Stream& stream, PyProxyQueue* pkt) {
		stream.auto_cleanup_payloads(true);
		if (stream.is_partial_stream()) {
			//TODO take a decision about this...
			stream.enable_recovery_mode(10 * 1024);
		}
		stream.client_data_callback(bind(on_client_data, placeholders::_1, pkt));
		stream.server_data_callback(bind(on_server_data, placeholders::_1, pkt));
		stream.stream_closed_callback(bind(on_stream_close, placeholders::_1, pkt));
	}


	void handle_next_packet(NfQueue::PktRequest<PyProxyQueue>* pkt) override{
		if (pkt->l4_proto != NfQueue::L4Proto::TCP){
			throw invalid_argument("Only TCP and UDP are supported");
		}
		Tins::PDU* application_layer = pkt->tcp->inner_pdu();
		u_int16_t payload_size = 0;
		if (application_layer != nullptr){
			payload_size = application_layer->size();
		}
		match_ctx.matching_has_been_called = false;
		match_ctx.pkt = pkt;
		if (pkt->is_ipv6){
			follower.process_packet(*pkt->ipv6);
		}else{
			follower.process_packet(*pkt->ipv4);
		}
		// Do an action only is an ordered packet has been received
		if (match_ctx.matching_has_been_called){
			bool empty_payload = payload_size == 0;
			//In this 2 cases we have to remove all data about the stream
			if (!match_ctx.result || match_ctx.already_closed){
				sctx.clean_stream_by_id(pkt->sid);
				//If the packet has data, we have to remove it
				if (!empty_payload){
					Tins::PDU* data_layer = pkt->tcp->release_inner_pdu();
					if (data_layer != nullptr){
						delete data_layer;
					}
				}
				//For the first matched data or only for data packets, we set FIN bit
				//This only for client packets, because this will trigger server to close the connection
				//Packets will be filtered anyway also if client don't send packets
				if ((!match_ctx.result || !empty_payload) && pkt->is_input){
					pkt->tcp->set_flag(Tins::TCP::FIN,1);
					pkt->tcp->set_flag(Tins::TCP::ACK,1);
					pkt->tcp->set_flag(Tins::TCP::SYN,0);
				}
				//Send the edited packet to the kernel
				return pkt->mangle();
			}
		}
		return pkt->accept();
	}

	~PyProxyQueue() {
		sctx.clean();
	}

};

}}
#endif // PROXY_TUNNEL_CLASS_CPP