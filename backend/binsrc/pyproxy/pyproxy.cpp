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
#include <Python.h>

using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;
using namespace std;

namespace Firegex {
namespace PyProxy {

class PyProxyQueue: public NfQueue::ThreadNfQueue<PyProxyQueue> {
	private:
	u_int16_t latest_config_ver = 0;
	public:
	stream_ctx sctx;
	StreamFollower follower;
	PyGILState_STATE gstate;
	PyInterpreterConfig py_thread_config = {
		.use_main_obmalloc = 0,
		.allow_fork = 0,
		.allow_exec = 0,
		.allow_threads = 0,
		.allow_daemon_threads = 0,
		.check_multi_interp_extensions = 1,
		.gil = PyInterpreterConfig_OWN_GIL,
	};
	PyThreadState *tstate = NULL;
	PyStatus pystatus;

	struct {
		bool matching_has_been_called = false;
		bool already_closed = false;
		bool rejected = true;
		NfQueue::PktRequest<PyProxyQueue>* pkt;
	} match_ctx;

    void before_loop() override {
		// Create thred structure for python
		gstate = PyGILState_Ensure();
		// Create a new interpreter for the thread
		pystatus = Py_NewInterpreterFromConfig(&tstate, &py_thread_config);
		if (PyStatus_Exception(pystatus)) {
			Py_ExitStatusException(pystatus);
			cerr << "[fatal] [main] Failed to create new interpreter" << endl;
			exit(EXIT_FAILURE);
		}
		// Setting callbacks for the stream follower
		follower.new_stream_callback(bind(on_new_stream, placeholders::_1, this));
		follower.stream_termination_callback(bind(on_stream_close, placeholders::_1, this));
    }

	inline void print_blocked_reason(const string& func_name){
		osyncstream(cout) << "BLOCKED " << func_name << endl;
	}

	inline void print_mangle_reason(const string& func_name){
		osyncstream(cout) << "MANGLED " << func_name << endl;
	}

	inline void print_exception_reason(){
		osyncstream(cout) << "EXCEPTION" << endl;
	}

	//If the stream has already been matched, drop all data, and try to close the connection
	static void keep_fin_packet(PyProxyQueue* proxy_info){
		proxy_info->match_ctx.matching_has_been_called = true;
		proxy_info->match_ctx.already_closed = true;
	}

	void filter_action(NfQueue::PktRequest<PyProxyQueue>* pkt, Stream& stream){
		auto stream_search = sctx.streams_ctx.find(pkt->sid);
		pyfilter_ctx* stream_match;
		if (stream_search == sctx.streams_ctx.end()){
			shared_ptr<PyCodeConfig> conf = config;
			//If config is not set, ignore the stream
			if (conf->glob == nullptr || conf->local == nullptr){
				stream.client_data_callback(nullptr);
				stream.server_data_callback(nullptr);
				return pkt->accept();
			}
			stream_match = new pyfilter_ctx(conf->glob, conf->local);
			sctx.streams_ctx.insert_or_assign(pkt->sid, stream_match);
		}else{
			stream_match = stream_search->second;
		}
		auto result = stream_match->handle_packet(pkt);
		switch(result.action){
			case PyFilterResponse::ACCEPT:
				pkt->accept();
			case PyFilterResponse::DROP:
				print_blocked_reason(*result.filter_match_by);
				sctx.clean_stream_by_id(pkt->sid);
				stream.client_data_callback(nullptr);
				stream.server_data_callback(nullptr);
				break;
			case PyFilterResponse::REJECT:
				sctx.clean_stream_by_id(pkt->sid);
				stream.client_data_callback(bind(keep_fin_packet, this));
				stream.server_data_callback(bind(keep_fin_packet, this));
				pkt->ctx->match_ctx.rejected = true; //Handler will take care of the rest
				break;
			case PyFilterResponse::MANGLE:
				print_mangle_reason(*result.filter_match_by);
				pkt->mangle_custom_pkt((uint8_t*)result.mangled_packet->c_str(), result.mangled_packet->size());
				break;
			case PyFilterResponse::EXCEPTION:
			case PyFilterResponse::INVALID:
				print_exception_reason();
				sctx.clean_stream_by_id(pkt->sid);
				//Free the packet data
				stream.client_data_callback(nullptr);
				stream.server_data_callback(nullptr);
				pkt->accept();
				break;
		}
	}


	static void on_data_recv(Stream& stream, PyProxyQueue* proxy_info, string data) {
		proxy_info->match_ctx.matching_has_been_called = true;
		proxy_info->match_ctx.already_closed = false;
		proxy_info->filter_action(proxy_info->match_ctx.pkt, stream);
	}
	
	//Input data filtering
	static void on_client_data(Stream& stream, PyProxyQueue* proxy_info) {
		on_data_recv(stream, proxy_info, string(stream.client_payload().begin(), stream.client_payload().end()));
	}
	
	//Server data filtering
	static void on_server_data(Stream& stream, PyProxyQueue* proxy_info) {
		on_data_recv(stream, proxy_info, string(stream.server_payload().begin(), stream.server_payload().end()));
	}
	
	// A stream was terminated. The second argument is the reason why it was terminated
	static void on_stream_close(Stream& stream, PyProxyQueue* proxy_info) {
		stream_id stream_id = stream_id::make_identifier(stream);
		proxy_info->sctx.clean_stream_by_id(stream_id);
	}
	
	static void on_new_stream(Stream& stream, PyProxyQueue* proxy_info) {
		stream.auto_cleanup_payloads(true);
		if (stream.is_partial_stream()) {
			stream.enable_recovery_mode(10 * 1024);
		}
		stream.client_data_callback(bind(on_client_data, placeholders::_1, proxy_info));
		stream.server_data_callback(bind(on_server_data, placeholders::_1, proxy_info));
		stream.stream_closed_callback(bind(on_stream_close, placeholders::_1, proxy_info));
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
			if (!match_ctx.rejected || match_ctx.already_closed){
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
				if ((!match_ctx.rejected || !empty_payload) && pkt->is_input){
					pkt->tcp->set_flag(Tins::TCP::FIN,1);
					pkt->tcp->set_flag(Tins::TCP::ACK,1);
					pkt->tcp->set_flag(Tins::TCP::SYN,0);
				}
				//Send the edited packet to the kernel
				return pkt->mangle();
			}else{
				//Fallback to the default action
				if (pkt->get_action() == NfQueue::FilterAction::NOACTION){
					return pkt->accept();
				}
			}
		}else{
			return pkt->accept();
		}
	}

	~PyProxyQueue() {
		// Closing first the interpreter
		Py_EndInterpreter(tstate);
		// Releasing the GIL and the thread data structure
		PyGILState_Release(gstate);
		sctx.clean();
	}

};

}}
#endif // PROXY_TUNNEL_CLASS_CPP