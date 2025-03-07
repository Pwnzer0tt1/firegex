
#ifndef STREAM_CTX_CPP
#define STREAM_CTX_CPP

#include <iostream>
#include <tins/tcp_ip/stream_identifier.h>
#include <map>
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
	string* mangled_packet = nullptr;

	py_filter_response(PyFilterResponse action, string* filter_match_by = nullptr, string* mangled_packet = nullptr):
		action(action), filter_match_by(filter_match_by), mangled_packet(mangled_packet){}

	~py_filter_response(){
		delete mangled_packet;
		delete filter_match_by;
	}
};

typedef Tins::TCPIP::StreamIdentifier stream_id;

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
		const string& data
	){
		PyObject * packet_info = PyDict_New();
		
		pkt->reserialize();
		set_item_to_dict(packet_info, "data", PyBytes_FromStringAndSize(data.c_str(), data.size()));
		set_item_to_dict(packet_info, "l4_size", PyLong_FromLong(pkt->data_size()));
		set_item_to_dict(packet_info, "raw_packet", PyBytes_FromStringAndSize(pkt->packet.c_str(), pkt->packet.size()));
		set_item_to_dict(packet_info, "is_input", PyBool_FromLong(pkt->is_input));
		set_item_to_dict(packet_info, "is_ipv6", PyBool_FromLong(pkt->is_ipv6));
		set_item_to_dict(packet_info, "is_tcp", PyBool_FromLong(pkt->l4_proto == NfQueue::L4Proto::TCP));

		// Set packet info to the global context
		set_item_to_glob("__firegex_packet_info", packet_info);
		PyObject * result = PyEval_EvalCode(py_handle_packet, glob, glob);
		PyGC_Collect();
		del_item_from_glob("__firegex_packet_info");

		if (PyErr_Occurred()){
			cerr << "[error] [handle_packet] Failed to execute the code " << result << endl;
			PyErr_Print();
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
			PyObject* mangled_packet = PyDict_GetItemString(result, "mangled_packet");
			if (mangled_packet == nullptr){
				del_item_from_glob("__firegex_pyfilter_result");
				#ifdef DEBUG
				cerr << "[DEBUG] [handle_packet] No result mangled_packet found" << endl;
				#endif
				return py_filter_response(PyFilterResponse::INVALID);
			}
			if (!PyBytes_Check(mangled_packet)){
				#ifdef DEBUG
				cerr << "[DEBUG] [handle_packet] mangled_packet is not a bytes" << endl;
				#endif
				del_item_from_glob("__firegex_pyfilter_result");
				return py_filter_response(PyFilterResponse::INVALID);
			}
			string* pkt_str = new string(PyBytes_AsString(mangled_packet), PyBytes_Size(mangled_packet));
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