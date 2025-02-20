
#ifndef STREAM_CTX_CPP
#define STREAM_CTX_CPP

#include <iostream>
#include <tins/tcp_ip/stream_identifier.h>
#include <map>
#include <Python.h>
#include "../classes/netfilter.cpp"
#include "settings.cpp"

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

struct py_filter_response {
	PyFilterResponse action;
	string* filter_match_by = nullptr;
	string* mangled_packet = nullptr;
	~py_filter_response(){
		delete mangled_packet;
		delete filter_match_by;
	}
};

typedef Tins::TCPIP::StreamIdentifier stream_id;

struct pyfilter_ctx {

	PyObject * glob = nullptr;
	PyObject * local = nullptr;
	
	pyfilter_ctx(PyObject * original_glob, PyObject * original_local){
		PyObject *copy = PyImport_ImportModule("copy");
		if (copy == nullptr){
			PyErr_Print();
			throw invalid_argument("Failed to import copy module");
		}
		PyObject *deepcopy = PyObject_GetAttrString(copy, "deepcopy");
		glob = PyObject_CallFunctionObjArgs(deepcopy, original_glob, NULL);
		if (glob == nullptr){
			PyErr_Print();
			throw invalid_argument("Failed to deepcopy the global dict");
		}
		local = PyObject_CallFunctionObjArgs(deepcopy, original_local, NULL);
		if (local == nullptr){
			PyErr_Print();
			throw invalid_argument("Failed to deepcopy the local dict");
		}
		Py_DECREF(copy);
	}

	~pyfilter_ctx(){
		Py_XDECREF(glob);
		Py_XDECREF(local);
	}

	inline void set_item_to_glob(const char* key, PyObject* value){
		set_item_to_dict(glob, key, value);
	}

	inline PyObject* get_item_from_glob(const char* key){
		return PyDict_GetItemString(glob, key);
	}

	void del_item_from_glob(const char* key){
		if (PyDict_DelItemString(glob, key) != 0){
			PyErr_Print();
			throw invalid_argument("Failed to delete item from dict");
		}
	}

	inline void set_item_to_local(const char* key, PyObject* value){
		set_item_to_dict(local, key, value);
	}

	inline void set_item_to_dict(PyObject* dict, const char* key, PyObject* value){
		if (PyDict_SetItemString(dict, key, value) != 0){
			PyErr_Print();
			throw invalid_argument("Failed to set item to dict");
		}
	}

	py_filter_response handle_packet(
		NfQueue::PktRequest<PyProxyQueue>* pkt
	){
		PyObject * packet_info = PyDict_New();

		set_item_to_dict(packet_info, "data", PyBytes_FromStringAndSize(pkt->data, pkt->data_size));
		set_item_to_dict(packet_info, "raw_packet", PyBytes_FromStringAndSize(pkt->packet.c_str(), pkt->packet.size()));
		set_item_to_dict(packet_info, "is_input", PyBool_FromLong(pkt->is_input));
		set_item_to_dict(packet_info, "is_ipv6", PyBool_FromLong(pkt->is_ipv6));
		set_item_to_dict(packet_info, "is_tcp", PyBool_FromLong(pkt->l4_proto == NfQueue::L4Proto::TCP));

		// Set packet info to the global context
		set_item_to_glob("__firegex_packet_info", packet_info);
		PyObject * result = PyEval_EvalCode(py_handle_packet_code, glob, local);
		del_item_from_glob("__firegex_packet_info");
		Py_DECREF(packet_info);

		if (!result){
			PyErr_Print();
			return py_filter_response{PyFilterResponse::EXCEPTION, nullptr};
		}
		Py_DECREF(result);

		result = get_item_from_glob("__firegex_pyfilter_result");
		if (result == nullptr){
			return py_filter_response{PyFilterResponse::INVALID, nullptr, nullptr};
		}

		if (!PyDict_Check(result)){
			PyErr_Print();
			del_item_from_glob("__firegex_pyfilter_result");
			return py_filter_response{PyFilterResponse::INVALID, nullptr, nullptr};
		}
		PyObject* action = PyDict_GetItemString(result, "action");
		if (action == nullptr){
			del_item_from_glob("__firegex_pyfilter_result");
			return py_filter_response{PyFilterResponse::INVALID, nullptr, nullptr};
		}
		if (!PyLong_Check(action)){
			del_item_from_glob("__firegex_pyfilter_result");
			return py_filter_response{PyFilterResponse::INVALID, nullptr, nullptr};
		}
		PyFilterResponse action_enum = (PyFilterResponse)PyLong_AsLong(action);

		if (action_enum == PyFilterResponse::ACCEPT || action_enum == PyFilterResponse::EXCEPTION || action_enum == PyFilterResponse::INVALID){
			del_item_from_glob("__firegex_pyfilter_result");
			return py_filter_response{action_enum, nullptr, nullptr};
		}else{
			PyObject *func_name_py = PyDict_GetItemString(result, "matched_by");
			if (func_name_py == nullptr){
				del_item_from_glob("__firegex_pyfilter_result");
				return py_filter_response{PyFilterResponse::INVALID, nullptr, nullptr};
			}
			if (!PyUnicode_Check(func_name_py)){
				del_item_from_glob("__firegex_pyfilter_result");
				return py_filter_response{PyFilterResponse::INVALID, nullptr, nullptr};
			}
			string* func_name = new string(PyUnicode_AsUTF8(func_name_py));
			if (action_enum == PyFilterResponse::DROP || action_enum == PyFilterResponse::REJECT){
				del_item_from_glob("__firegex_pyfilter_result");
				return py_filter_response{action_enum, func_name, nullptr};
			}
			if (action_enum != PyFilterResponse::MANGLE){
				PyObject* mangled_packet = PyDict_GetItemString(result, "mangled_packet");
				if (mangled_packet == nullptr){
					del_item_from_glob("__firegex_pyfilter_result");
					return py_filter_response{PyFilterResponse::INVALID, nullptr, nullptr};
				}
				if (!PyBytes_Check(mangled_packet)){
					del_item_from_glob("__firegex_pyfilter_result");
					return py_filter_response{PyFilterResponse::INVALID, nullptr, nullptr};
				}
				string* pkt_str = new string(PyBytes_AsString(mangled_packet), PyBytes_Size(mangled_packet));
				del_item_from_glob("__firegex_pyfilter_result");
				return py_filter_response{PyFilterResponse::MANGLE, func_name, pkt_str};
			}
		}
		del_item_from_glob("__firegex_pyfilter_result");
		return py_filter_response{PyFilterResponse::INVALID, nullptr, nullptr};
	}

};

typedef map<stream_id, pyfilter_ctx*> matching_map;

struct stream_ctx {
	matching_map streams_ctx;

	void clean_stream_by_id(stream_id sid){
		auto stream_search = streams_ctx.find(sid);
		if (stream_search != streams_ctx.end()){
			auto stream_match = stream_search->second;
			delete stream_match;
		}
	}
	void clean(){
		for (auto ele: streams_ctx){
			delete ele.second;
		}
	}
};


}}
#endif // STREAM_CTX_CPP