
#ifndef STREAM_CTX_CPP
#define STREAM_CTX_CPP

#include <iostream>
#include <tins/tcp_ip/stream_identifier.h>
#include <map>
#include <list>
#include <set>
#include <cstdlib>
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

// The library's `Action` values, which are the wire format between it and this binary.
// 3 was `MANGLE`, a rewrite of the payload; it is gone from the library, and the number
// stays unused so that nothing old can ever mean something new. Anything outside the
// valid set is `INVALID`, which fails open and is reported like an exception.
enum PyFilterResponse {
	ACCEPT = 0,
	DROP = 1,
	REJECT = 2,
	EXCEPTION = 4,
	INVALID = 5
};

const PyFilterResponse VALID_PYTHON_RESPONSE[3] = {
	PyFilterResponse::ACCEPT,
	PyFilterResponse::DROP,
	PyFilterResponse::REJECT,
};

struct py_filter_response {
	PyFilterResponse action;
	string* filter_match_by = nullptr;

	py_filter_response(PyFilterResponse action, string* filter_match_by = nullptr):
		action(action), filter_match_by(filter_match_by){}

	~py_filter_response(){
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

// How many dropped filter contexts may wait for a full collection, and how many have on
// this queue thread — each thread runs an interpreter of its own, so each counts its own.
constexpr unsigned COLLECT_EVERY = 64;
static thread_local unsigned dropped_since_collect = 0;

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
		// The module's functions hold these globals and the globals hold the functions,
		// so a context is a cycle only the collector frees. Left to the interpreter's
		// own schedule, one that lived long enough to be promoted waits for a full pass,
		// which is triggered by object counts rather than by bytes — measured, a filter
		// building a table at module level held ~200 MB more across a stream of short
		// connections. A full pass per context held memory flat and cost ~1 ms each, a
		// ceiling of about two hundred connections a second per queue thread. One pass
		// every `COLLECT_EVERY` contexts keeps both.
		if (++dropped_since_collect >= COLLECT_EVERY){
			dropped_since_collect = 0;
			PyGC_Collect();
		}
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
		// No collection here. The interpreter's own collector is on (`before_loop`
		// makes sure), and a full pass per packet cost about a millisecond with the
		// library loaded — a ceiling of a thousand packets a second per queue thread,
		// spent finding nothing.
		PyObject * result = PyEval_EvalCode(py_handle_packet, glob, glob);
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
		//Should never reach this point, but just in case of new action not managed...
		delete func_name;
		del_item_from_glob("__firegex_pyfilter_result");
		return py_filter_response(PyFilterResponse::INVALID);
	}

};

typedef map<stream_id, pyfilter_ctx*> matching_map;


// How long a UDP flow keeps its filter's state with nothing arriving. A datagram has no
// close to observe, so this is the only thing that ends a flow — the same minute the
// proxy layer's relay gives one.
constexpr int64_t UDP_IDLE_SECONDS = 60;

inline long long env_number(const char* name){
	const char* env = getenv(name);
	if (env == nullptr) return 0;
	char* end = nullptr;
	long long parsed = strtoll(env, &end, 10);
	return end != env ? parsed : 0;
}

// How many UDP flows one queue thread may hold a filter's state for at once: the
// service's own "most connections at once", shared out between the threads — each holds
// the contexts of the flows hashed to it, so a limit applied per thread would be the
// operator's number times the thread count. 0, missing or unreadable means no limit, and
// idle flows still go after `UDP_IDLE_SECONDS`, which is what keeps that from growing
// without end.
inline size_t max_udp_flows(){
	static const size_t value = [](){
		const long long limit = env_number("FIREGEX_MAX_FLOWS");
		if (limit <= 0) return (size_t)0;
		const long long threads = env_number("NTHREADS") > 0 ? env_number("NTHREADS") : 1;
		return (size_t)((limit + threads - 1) / threads);
	}();
	return value;
}

inline int64_t steady_seconds(){
	return std::chrono::duration_cast<std::chrono::seconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
}

struct stream_ctx {

	matching_map streams_ctx;

	NfQueue::tcp_ack_map tcp_ack_ctx;

	// The UDP flows holding a context, most recently used first, with when each was
	// last seen — so the one to let go of, whether for being idle or to make room, is
	// always at the back. TCP contexts are not in here and are never evicted: a TCP
	// stream is released when libtins sees it close, and dropping its state while it
	// is still open would have its next packet parsed from a clean slate mid-message.
	list<pair<stream_id, int64_t>> udp_recent;
	map<stream_id, list<pair<stream_id, int64_t>>::iterator> udp_where;

	// The TCP streams whose filter context was thrown away while they were open — new
	// code arrived — so the context built for their next packet knows it is taking over
	// halfway, possibly in the middle of a message.
	set<stream_id> taken_over;

	void clean_stream_by_id(stream_id sid){
		taken_over.erase(sid);
		auto stream_search = streams_ctx.find(sid);
		if (stream_search != streams_ctx.end()){
			auto stream_match = stream_search->second;
			delete stream_match;
			streams_ctx.erase(stream_search->first);
		}
		auto flow = udp_where.find(sid);
		if (flow != udp_where.end()){
			udp_recent.erase(flow->second);
			udp_where.erase(flow);
		}
	}

	// This UDP flow was just used.
	void udp_touch(const stream_id& sid){
		auto flow = udp_where.find(sid);
		if (flow != udp_where.end()){
			udp_recent.erase(flow->second);
		}
		udp_recent.emplace_front(sid, steady_seconds());
		udp_where[sid] = udp_recent.begin();
	}

	// Let go of the UDP flows nothing has arrived on for `idle` seconds.
	void udp_expire(int64_t idle){
		const int64_t now = steady_seconds();
		while (!udp_recent.empty() && now - udp_recent.back().second >= idle){
			stream_id sid = udp_recent.back().first;
			clean_stream_by_id(sid);
		}
	}

	// Make room for one more UDP flow under `limit`, letting the least recently used go;
	// a limit of zero is none. Only UDP flows are counted and only UDP flows go: the
	// ceiling used to be applied to every context, so a burst of datagrams could take the
	// state of a TCP connection still in the middle of a request.
	void udp_make_room(size_t limit){
		while (limit > 0 && udp_where.size() >= limit && !udp_recent.empty()){
			stream_id sid = udp_recent.back().first;
			clean_stream_by_id(sid);
		}
	}

	// Every filter context, TCP and UDP alike, for when the code they were built from is
	// no longer the code in force. The sequence bookkeeping stays: it belongs to the
	// connection, not to the filter, and a stream whose payload was already cut would
	// have its acknowledgements go wrong without it.
	void clean_filters(){
		for (auto ele: streams_ctx){
			if (udp_where.find(ele.first) == udp_where.end()){
				taken_over.insert(ele.first);
			}
			delete ele.second;
		}
		streams_ctx.clear();
		udp_recent.clear();
		udp_where.clear();
	}

	void clean_tcp_ack_by_id(stream_id sid){
		auto tcp_ack_search = tcp_ack_ctx.find(sid);
		if (tcp_ack_search != tcp_ack_ctx.end()){
			auto tcp_ack = tcp_ack_search->second;
			delete tcp_ack;
			tcp_ack_ctx.erase(tcp_ack_search->first);
		}
	}

	void clean(){
		clean_filters();
		taken_over.clear();
		for (auto ele: tcp_ack_ctx){
			delete ele.second;
		}
		tcp_ack_ctx.clear();
	}
};


}}
#endif // STREAM_CTX_CPP