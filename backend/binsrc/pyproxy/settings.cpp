#ifndef PROXY_TUNNEL_SETTINGS_CPP
#define PROXY_TUNNEL_SETTINGS_CPP

#include <Python.h>
#include <marshal.h>
#include <vector>
#include <memory>
#include <iostream>
#include "../utils.cpp"

using namespace std;

namespace Firegex {
namespace PyProxy {

class PyCodeConfig;

shared_ptr<PyCodeConfig> config;
UnixClientConnection control_socket;

PyObject* unmarshal_code(string encoded_code){
	if (encoded_code.empty()) return nullptr;
	return PyMarshal_ReadObjectFromString(encoded_code.c_str(), encoded_code.size());
}

class PyCodeConfig{
	public:
		string encoded_code;

		PyCodeConfig(const string& pycode){
			PyObject* compiled_code = Py_CompileStringExFlags(pycode.c_str(), "<pyfilter>", Py_file_input, NULL, 2);
			if (compiled_code == nullptr){
				std::cerr << "[fatal] [main] Failed to compile the code" << endl;
				throw invalid_argument("Failed to compile the code");
			}
			PyObject* glob = PyDict_New();
			PyObject* result = PyEval_EvalCode(compiled_code, glob, glob);
			Py_DECREF(glob);
			if (PyErr_Occurred()){
				PyErr_Print();
				Py_DECREF(compiled_code);
				std::cerr << "[fatal] [main] Failed to execute the code" << endl;
				throw invalid_argument("Failed to execute the code, maybe an invalid filter code has been provided");
			}
			Py_XDECREF(result);
			PyObject* code_dump = PyMarshal_WriteObjectToString(compiled_code, 4);
			Py_DECREF(compiled_code);
			if (code_dump == nullptr){
				if (PyErr_Occurred())
					PyErr_Print();
				std::cerr << "[fatal] [main] Failed to dump the code" << endl;
				throw invalid_argument("Failed to dump the code");
			}
			if (!PyBytes_Check(code_dump)){
				std::cerr << "[fatal] [main] Failed to dump the code" << endl;
				Py_DECREF(code_dump);
				throw invalid_argument("Failed to dump the code");
			}
			encoded_code = string(PyBytes_AsString(code_dump), PyBytes_Size(code_dump));
			Py_DECREF(code_dump);
		}

		PyObject* compiled_code(){
			return unmarshal_code(encoded_code);
		}

		PyCodeConfig(){}
};

void init_control_socket(){
	char * socket_path = getenv("FIREGEX_NFPROXY_SOCK");
	if (socket_path == nullptr) throw invalid_argument("FIREGEX_NFPROXY_SOCK not set");
	if (strlen(socket_path) >= 108) throw invalid_argument("FIREGEX_NFPROXY_SOCK too long");
	control_socket = UnixClientConnection(socket_path);
}

string py_handle_packet_code;

void init_handle_packet_code(){
	PyObject* compiled_code = Py_CompileStringExFlags(
		"firegex.nfproxy.internals.handle_packet(globals())\n", "<pyfilter>",
	Py_file_input, NULL, 2);
	PyObject* code_dump = PyMarshal_WriteObjectToString(compiled_code, 4);
	Py_DECREF(compiled_code);
	if (code_dump == nullptr){
		if (PyErr_Occurred())
			PyErr_Print();
		std::cerr << "[fatal] [main] Failed to dump the code" << endl;
		throw invalid_argument("Failed to dump the code");
	}
	if (!PyBytes_Check(code_dump)){
		std::cerr << "[fatal] [main] Failed to dump the code" << endl;
		Py_DECREF(code_dump);
		throw invalid_argument("Failed to dump the code");
	}
	py_handle_packet_code = string(PyBytes_AsString(code_dump), PyBytes_Size(code_dump));
	Py_DECREF(code_dump);
}

}}
#endif // PROXY_TUNNEL_SETTINGS_CPP

