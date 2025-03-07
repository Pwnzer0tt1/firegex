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
#include "../classes/nfqueue.cpp"
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
	PyThreadState * tstate = nullptr;

	PyInterpreterConfig py_thread_config = {
		.use_main_obmalloc = 0,
		.allow_fork = 0,
		.allow_exec = 0,
		.allow_threads = 0,
		.allow_daemon_threads = 0,
		.check_multi_interp_extensions = 1,
		.gil = PyInterpreterConfig_OWN_GIL,
	};
	NfQueue::PktRequest<PyProxyQueue>* pkt;
	NfQueue::tcp_ack_seq_ctx* current_tcp_ack = nullptr;

	PyObject* handle_packet_code = nullptr;

    void before_loop() override {
		PyStatus pystatus;
		// Create a new interpreter for the thread
		tstate = PyThreadState_New(PyInterpreterState_Main());
		PyEval_AcquireThread(tstate);
		pystatus = Py_NewInterpreterFromConfig(&tstate, &py_thread_config);
		if(tstate == nullptr){
			cerr << "[fatal] [main] Failed to create new interpreter" << endl;
			throw invalid_argument("Failed to create new interpreter (null tstate)");
		}
		if (PyStatus_Exception(pystatus)) {
			cerr << "[fatal] [main] Failed to create new interpreter" << endl;
			Py_ExitStatusException(pystatus);
			throw invalid_argument("Failed to create new interpreter (pystatus exc)");
		}

		if(!PyGC_IsEnabled()){
			PyGC_Enable();
		}

		handle_packet_code = unmarshal_code(py_handle_packet_code);
		// Setting callbacks for the stream follower
		follower.new_stream_callback(bind(on_new_stream, placeholders::_1, this));
		follower.stream_termination_callback(bind(on_stream_close, placeholders::_1, this));
    }

	inline void print_blocked_reason(const string& func_name){
		control_socket << "BLOCKED " << func_name << endl;
	}

	inline void print_mangle_reason(const string& func_name){
		control_socket << "MANGLED " << func_name << endl;
	}

	inline void print_exception_reason(){
		control_socket << "EXCEPTION" << endl;
	}

	//If the stream has already been matched, drop all data, and try to close the connection
	static void keep_fin_packet(PyProxyQueue* pyq){
		pyq->pkt->reject();// This is needed because the callback has to take the updated pkt pointer!
	}

	static void keep_dropped(PyProxyQueue* pyq){
		pyq->pkt->drop();// This is needed because the callback has to take the updated pkt pointer!
	}

	void filter_action(NfQueue::PktRequest<PyProxyQueue>* pkt, Stream& stream, const string& data){
		auto stream_search = sctx.streams_ctx.find(pkt->sid);
		pyfilter_ctx* stream_match;
		if (stream_search == sctx.streams_ctx.end()){
			shared_ptr<PyCodeConfig> conf = config;
			//If config is not set, ignore the stream
			PyObject* compiled_code = conf->compiled_code();
			if (compiled_code == nullptr){
				stream.client_data_callback(nullptr);
				stream.server_data_callback(nullptr);
				stream.ignore_client_data();
				stream.ignore_server_data();
				return pkt->accept();
			}else{
				try{
					stream_match = new pyfilter_ctx(compiled_code, handle_packet_code);
				}catch(invalid_argument& e){
					cerr << "[error] [filter_action] Failed to create the filter context" << endl;
					print_exception_reason();
					sctx.clean_stream_by_id(pkt->sid);
					stream.client_data_callback(nullptr);
					stream.server_data_callback(nullptr);
					stream.ignore_client_data();
					stream.ignore_server_data();
					return pkt->accept();
				}
				sctx.streams_ctx.insert_or_assign(pkt->sid, stream_match);
			}
		}else{
			stream_match = stream_search->second;
		}		

		auto result = stream_match->handle_packet(pkt, data);
		switch(result.action){
			case PyFilterResponse::ACCEPT:
				return pkt->accept();
			case PyFilterResponse::DROP:
				print_blocked_reason(*result.filter_match_by);
				sctx.clean_stream_by_id(pkt->sid);
				stream.client_data_callback(bind(keep_dropped, this));
				stream.server_data_callback(bind(keep_dropped, this));
				return pkt->drop();
			case PyFilterResponse::REJECT:
				print_blocked_reason(*result.filter_match_by);
				sctx.clean_stream_by_id(pkt->sid);
				stream.client_data_callback(bind(keep_fin_packet, this));
				stream.server_data_callback(bind(keep_fin_packet, this));
				return pkt->reject();
			case PyFilterResponse::MANGLE:
				pkt->mangle_custom_pkt(result.mangled_packet->c_str(), result.mangled_packet->size());
				if (pkt->get_action() == NfQueue::FilterAction::DROP){
					cerr << "[error] [filter_action] Failed to mangle: the packet sent is not serializzable... the packet was dropped" << endl;
					print_blocked_reason(*result.filter_match_by);
					print_exception_reason();
				}else{
					print_mangle_reason(*result.filter_match_by);
				}
				return;
			case PyFilterResponse::EXCEPTION:
			case PyFilterResponse::INVALID:
				print_exception_reason();
				sctx.clean_stream_by_id(pkt->sid);
				//Free the packet data
				stream.ignore_client_data();
				stream.ignore_server_data();
				stream.client_data_callback(nullptr);
				stream.server_data_callback(nullptr);
				return pkt->accept();
		}
	}


	static void on_data_recv(Stream& stream, PyProxyQueue* pyq, const string& data) {
		pyq->pkt->fix_data_payload();
		pyq->filter_action(pyq->pkt, stream, data); //Only here the rebuilt_tcp_data is set
	}
	
	//Input data filtering
	static void on_client_data(Stream& stream, PyProxyQueue* pyq) {
		auto data = stream.client_payload();
		on_data_recv(stream, pyq, string((char*)data.data(), data.size()));
	}
	
	//Server data filtering
	static void on_server_data(Stream& stream, PyProxyQueue* pyq) {
		auto data = stream.server_payload();
		on_data_recv(stream, pyq, string((char*)data.data(), data.size()));
	}
	
	// A stream was terminated. The second argument is the reason why it was terminated
	static void on_stream_close(Stream& stream, PyProxyQueue* pyq) {
		stream_id stream_id = stream_id::make_identifier(stream);
		pyq->sctx.clean_stream_by_id(stream_id);
		pyq->sctx.clean_tcp_ack_by_id(stream_id);
	}
	
	static void on_new_stream(Stream& stream, PyProxyQueue* pyq) {
		stream.auto_cleanup_payloads(true);
		if (stream.is_partial_stream()) {
			stream.enable_recovery_mode(10 * 1024);
		}

		if (pyq->current_tcp_ack != nullptr){
			pyq->current_tcp_ack->reset();
		}else{
			pyq->current_tcp_ack = new NfQueue::tcp_ack_seq_ctx();
			pyq->sctx.tcp_ack_ctx.insert_or_assign(pyq->pkt->sid, pyq->current_tcp_ack);
			pyq->pkt->ack_seq_offset = pyq->current_tcp_ack; // Set ack context
		}

		//Should not happen, but with this we can be sure about this
		auto tcp_ack_search = pyq->sctx.tcp_ack_ctx.find(pyq->pkt->sid);
		if (tcp_ack_search != pyq->sctx.tcp_ack_ctx.end()){
			tcp_ack_search->second->reset();
		}
		
		stream.client_data_callback(bind(on_client_data, placeholders::_1, pyq));
		stream.server_data_callback(bind(on_server_data, placeholders::_1, pyq));
		stream.stream_closed_callback(bind(on_stream_close, placeholders::_1, pyq));
	}

	void handle_next_packet(NfQueue::PktRequest<PyProxyQueue>* _pkt) override{
		pkt = _pkt; // Setting packet context

		if (pkt->l4_proto != NfQueue::L4Proto::TCP){
			throw invalid_argument("Only TCP and UDP are supported");
		}

		auto tcp_ack_search = sctx.tcp_ack_ctx.find(pkt->sid);
		if (tcp_ack_search != sctx.tcp_ack_ctx.end()){
			current_tcp_ack = tcp_ack_search->second;
			pkt->ack_seq_offset = current_tcp_ack;
		}else{
			current_tcp_ack = nullptr;
			//If necessary will be created by libtis new_stream callback
		}

		pkt->fix_tcp_ack();

		if (pkt->is_ipv6){
			follower.process_packet(*pkt->ipv6);
		}else{
			follower.process_packet(*pkt->ipv4);
		}

		//Fallback to the default action
		if (pkt->get_action() == NfQueue::FilterAction::NOACTION){
			return pkt->accept();
		}
	}

	~PyProxyQueue() {
		// Closing first the interpreter
		
		Py_EndInterpreter(tstate);
		PyEval_ReleaseThread(tstate);
		PyThreadState_Clear(tstate);
		PyThreadState_Delete(tstate);
		Py_DECREF(handle_packet_code);
	
		sctx.clean();
	}

};

}}
#endif // PROXY_TUNNEL_CLASS_CPP