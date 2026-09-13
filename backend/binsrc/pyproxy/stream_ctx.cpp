
#ifndef STREAM_CTX_CPP
#define STREAM_CTX_CPP

#include <iostream>
#include <tins/tcp_ip/stream_identifier.h>
#include <map>
#include <atomic>
#include <chrono>
#include <Python.h>
#include "../classes/netfilter.cpp"
#include "../classes/nfqueue.cpp"
#include "settings.cpp"
#include "../utils.cpp"

using namespace std;


namespace Firegex {
namespace PyProxy {
	
class PyCodeConfig;
class PyProxyQueue;

enum PyFilterResponse {
	ACCEPT = 0,
	DROP = 1,
	REJECT = 2,
	MANGLE = 3,
	EXCEPTION = 4,
	INVALID = 5
};

const PyFilterResponse VALID_PYTHON_RESPONSE[4] = {
	PyFilterResponse::ACCEPT,
	PyFilterResponse::DROP,
	PyFilterResponse::REJECT,
	PyFilterResponse::MANGLE
};

struct py_filter_response {
	PyFilterResponse action;
	string* filter_match_by = nullptr;
	// The rewritten application payload, never a packet: nothing below the
	// application layer crosses into the filter, so nothing below it comes back.
	string* mangled_data = nullptr;

	py_filter_response(PyFilterResponse action, string* filter_match_by = nullptr, string* mangled_data = nullptr):
		action(action), filter_match_by(filter_match_by), mangled_data(mangled_data){}

	~py_filter_response(){
		delete mangled_data;
		delete filter_match_by;
	}
};

typedef Tins::TCPIP::StreamIdentifier stream_id;

// How long between two tracebacks out of this process, in seconds.
//
// Filter code that throws throws on every packet — a typo does not fire once — and a
// traceback is a dozen lines. Unthrottled, one broken filter writes thousands of lines a
// minute into a log that is a bounded ring, so the flood does not merely repeat itself:
// it pushes out the first traceback, which was the one worth reading, along with
// everything that was in the log before the filter broke.
//
// The `EXCEPTION` sent to the backend is deliberately *not* throttled with it. That is
// one token, it costs nothing, and it is what the backend counts to say "still raising,
// N more since" — so the operator still learns how often this is happening while being
// shown the traceback once.
constexpr int64_t TRACEBACK_QUIET_SECONDS = 30;

// Process-wide rather than per stream: the flood is one broken filter, not one broken
// connection, and throttling per connection would let a hundred connections print a
// hundred copies of the same fault. Relaxed ordering is enough — two threads racing here
// print one traceback each, which is not a problem worth a lock.
static std::atomic<int64_t> last_traceback_at{-TRACEBACK_QUIET_SECONDS * 2};

inline bool traceback_is_due() {
	const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
	int64_t previous = last_traceback_at.load(std::memory_order_relaxed);
	if (now - previous < TRACEBACK_QUIET_SECONDS) return false;
	return last_traceback_at.compare_exchange_strong(
		previous, now, std::memory_order_relaxed);
}

struct pyfilter_ctx {

	PyObject * glob = nullptr;
	PyObject * py_handle_packet = nullptr;
	
	pyfilter_ctx(PyObject * compiled_code, PyObject * handle_packet_code){
		py_handle_packet = handle_packet_code;
		Py_INCREF(py_handle_packet);
		glob = PyDict_New();
		PyObject* result = PyEval_EvalCode(compiled_code, glob, glob);
		Py_XDECREF(compiled_code);
		if (PyErr_Occurred()){
			PyErr_Print();
			Py_XDECREF(glob);
			std::cerr << "[fatal] [main] Failed to compile the code" << endl;
			throw invalid_argument("Failed to execute the code, maybe an invalid filter code has been provided");
		}
		Py_XDECREF(result);
	}

	~pyfilter_ctx(){
		Py_DECREF(glob);
		Py_DECREF(py_handle_packet);
		PyGC_Collect();
	}

	inline void set_item_to_glob(const char* key, PyObject* value){
		set_item_to_dict(glob, key, value);
	}

	inline PyObject* get_item_from_glob(const char* key){
		return PyDict_GetItemString(glob, key);
	}

	void del_item_from_glob(const char* key){
		if (PyDict_DelItemString(glob, key) != 0){
			if (PyErr_Occurred())
				PyErr_Print();
			throw invalid_argument("Failed to delete item from dict");
		}
	}

	inline void set_item_to_dict(PyObject* dict, const char* key, PyObject* value){
		if (PyDict_SetItemString(dict, key, value) != 0){
			if (PyErr_Occurred())
				PyErr_Print();
			throw invalid_argument("Failed to set item to dict");
		}
		Py_DECREF(value);
	}

	py_filter_response handle_packet(
		NfQueue::PktRequest<PyProxyQueue>* pkt,
		const string& data,
		bool is_client
	){
		PyObject * packet_info = PyDict_New();
		
		pkt->reserialize();
		// The application payload, and metadata about everything under it. No header
		// bytes cross this boundary in either direction: a filter reads where the
		// traffic came from and edits what it carries, which is the one contract both
		// network layers can honestly offer.
		string src_ip = pkt->src_ip(), dst_ip = pkt->dst_ip();
		set_item_to_dict(packet_info, "data", PyBytes_FromStringAndSize(data.c_str(), data.size()));
		set_item_to_dict(packet_info, "is_input", PyBool_FromLong(is_client));
		set_item_to_dict(packet_info, "is_ipv6", PyBool_FromLong(pkt->is_ipv6));
		set_item_to_dict(packet_info, "is_tcp", PyBool_FromLong(pkt->l4_proto == NfQueue::L4Proto::TCP));
		set_item_to_dict(packet_info, "src_ip", PyUnicode_FromStringAndSize(src_ip.c_str(), src_ip.size()));
		set_item_to_dict(packet_info, "dst_ip", PyUnicode_FromStringAndSize(dst_ip.c_str(), dst_ip.size()));
		set_item_to_dict(packet_info, "src_port", PyLong_FromLong(pkt->src_port()));
		set_item_to_dict(packet_info, "dst_port", PyLong_FromLong(pkt->dst_port()));

		// Set packet info to the global context
		set_item_to_glob("__firegex_packet_info", packet_info);
		PyObject * result = PyEval_EvalCode(py_handle_packet, glob, glob);
		PyGC_Collect();
		del_item_from_glob("__firegex_packet_info");

		if (PyErr_Occurred()){
			// Shown at most once every TRACEBACK_QUIET_SECONDS; the EXCEPTION below goes
			// every time, and is what carries the count.
			if (traceback_is_due()){
				cerr << "[error] [handle_packet] Failed to execute the code " << result << endl;
				PyErr_Print();
			} else {
				PyErr_Clear();
			}
			#ifdef DEBUG
			cerr << "[DEBUG] [handle_packet] Exception raised" << endl;
			#endif
			return py_filter_response(PyFilterResponse::EXCEPTION);
		}
			
		Py_DECREF(result);

		result = get_item_from_glob("__firegex_pyfilter_result");
		if (result == nullptr){
			#ifdef DEBUG
			cerr << "[DEBUG] [handle_packet] No result found" << endl;
			#endif
			return py_filter_response(PyFilterResponse::INVALID);
		}

		if (!PyDict_Check(result)){
			if (PyErr_Occurred()){
				PyErr_Print();
			}
			#ifdef DEBUG
			cerr << "[DEBUG] [handle_packet] Result is not a dict" << endl;
			#endif
			del_item_from_glob("__firegex_pyfilter_result");
			return py_filter_response(PyFilterResponse::INVALID);
		}
		PyObject* action = PyDict_GetItemString(result, "action");
		if (action == nullptr){
			#ifdef DEBUG
			cerr << "[DEBUG] [handle_packet] No result action found" << endl;
			#endif
			del_item_from_glob("__firegex_pyfilter_result");
			return py_filter_response(PyFilterResponse::INVALID);
		}
		if (!PyLong_Check(action)){
			#ifdef DEBUG
			cerr << "[DEBUG] [handle_packet] Action is not a long" << endl;
			#endif
			del_item_from_glob("__firegex_pyfilter_result");
			return py_filter_response(PyFilterResponse::INVALID);
		}
		PyFilterResponse action_enum = (PyFilterResponse)PyLong_AsLong(action);

		//Check action_enum
		bool valid = false;
		for (auto valid_action: VALID_PYTHON_RESPONSE){
			if (action_enum == valid_action){
				valid = true;
				break;
			}
		}
		if (!valid){
			#ifdef DEBUG
			cerr << "[DEBUG] [handle_packet] Invalid action" << endl;
			#endif
			del_item_from_glob("__firegex_pyfilter_result");
			return py_filter_response(PyFilterResponse::INVALID);
		}

		if (action_enum == PyFilterResponse::ACCEPT){
			del_item_from_glob("__firegex_pyfilter_result");
			return py_filter_response(action_enum);
		}
		PyObject *func_name_py = PyDict_GetItemString(result, "matched_by");
		if (func_name_py == nullptr){
			del_item_from_glob("__firegex_pyfilter_result");
			#ifdef DEBUG
			cerr << "[DEBUG] [handle_packet] No result matched_by found" << endl;
			#endif
			return py_filter_response(PyFilterResponse::INVALID);
		}
		if (!PyUnicode_Check(func_name_py)){
			del_item_from_glob("__firegex_pyfilter_result");
			#ifdef DEBUG
			cerr << "[DEBUG] [handle_packet] matched_by is not a string" << endl;
			#endif
			return py_filter_response(PyFilterResponse::INVALID);
		}
		string* func_name = new string(PyUnicode_AsUTF8(func_name_py));
		if (action_enum == PyFilterResponse::DROP || action_enum == PyFilterResponse::REJECT){
			del_item_from_glob("__firegex_pyfilter_result");
			return py_filter_response(action_enum, func_name);
		}
		if (action_enum == PyFilterResponse::MANGLE){
			PyObject* mangled_data = PyDict_GetItemString(result, "mangled_data");
			if (mangled_data == nullptr){
				del_item_from_glob("__firegex_pyfilter_result");
				#ifdef DEBUG
				cerr << "[DEBUG] [handle_packet] No result mangled_data found" << endl;
				#endif
				return py_filter_response(PyFilterResponse::INVALID);
			}
			if (!PyBytes_Check(mangled_data)){
				#ifdef DEBUG
				cerr << "[DEBUG] [handle_packet] mangled_data is not a bytes" << endl;
				#endif
				del_item_from_glob("__firegex_pyfilter_result");
				return py_filter_response(PyFilterResponse::INVALID);
			}
			string* pkt_str = new string(PyBytes_AsString(mangled_data), PyBytes_Size(mangled_data));
			del_item_from_glob("__firegex_pyfilter_result");
			return py_filter_response(PyFilterResponse::MANGLE, func_name, pkt_str);
		}
		
		//Should never reach this point, but just in case of new action not managed...
		del_item_from_glob("__firegex_pyfilter_result");
		return py_filter_response(PyFilterResponse::INVALID);
	}

};

typedef map<stream_id, pyfilter_ctx*> matching_map;


struct stream_ctx {

	matching_map streams_ctx;

	NfQueue::tcp_ack_map tcp_ack_ctx;

	void clean_stream_by_id(stream_id sid){
		auto stream_search = streams_ctx.find(sid);
		if (stream_search != streams_ctx.end()){
			auto stream_match = stream_search->second;
			delete stream_match;
			streams_ctx.erase(stream_search->first);
		}
	}

	void clean_tcp_ack_by_id(stream_id sid){
		auto tcp_ack_search = tcp_ack_ctx.find(sid);
		if (tcp_ack_search != tcp_ack_ctx.end()){
			auto tcp_ack = tcp_ack_search->second;
			delete tcp_ack;
			tcp_ack_ctx.erase(tcp_ack_search->first);
		}
	}

	// Keep the number of live filter contexts under a ceiling.
	//
	// A TCP flow is released when libtins sees the connection close. A datagram has no
	// close to observe, so a UDP service under a spoofed-source flood would otherwise
	// accumulate one set of Python module globals per forged address until the process
	// died. Which context is dropped is arbitrary — the map is ordered by flow id, not
	// by age — and that is the honest trade: the bound is the point, and a flow that
	// loses its globals starts again from a clean state rather than taking the service
	// with it.
	void enforce_limit(size_t limit){
		while (streams_ctx.size() >= limit && !streams_ctx.empty()){
			auto victim = streams_ctx.begin();
			delete victim->second;
			streams_ctx.erase(victim);
		}
	}

	void clean(){
		for (auto ele: streams_ctx){
			delete ele.second;
		}
		for (auto ele: tcp_ack_ctx){
			delete ele.second;
		}
		tcp_ack_ctx.clear();
		streams_ctx.clear();
	}
};


}}
#endif // STREAM_CTX_CPP