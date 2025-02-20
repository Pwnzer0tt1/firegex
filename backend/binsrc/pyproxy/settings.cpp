#ifndef PROXY_TUNNEL_SETTINGS_CPP
#define PROXY_TUNNEL_SETTINGS_CPP

#include <Python.h>

#include <vector>
#include <memory>
#include <iostream>

using namespace std;

namespace Firegex {
namespace PyProxy {


class PyCodeConfig{
	public:
		PyObject* glob = nullptr;
		PyObject* local = nullptr;

	private:
		void _clean(){
			Py_XDECREF(glob);
			Py_XDECREF(local);
		}
	public:

		PyCodeConfig(const string& pycode){
			
			PyObject* compiled_code = Py_CompileStringExFlags(pycode.c_str(), "<pyfilter>", Py_file_input, NULL, 2);
			if (compiled_code == nullptr){
				std::cerr << "[fatal] [main] Failed to compile the code" << endl;
				_clean();
				throw invalid_argument("Failed to compile the code");
			}
			glob = PyDict_New();
			local = PyDict_New();
			PyObject* result = PyEval_EvalCode(compiled_code, glob, local);
			Py_XDECREF(compiled_code);
			if (!result){
				PyErr_Print();
				_clean();
				std::cerr << "[fatal] [main] Failed to execute the code" << endl;
				throw invalid_argument("Failed to execute the code, maybe an invalid filter code has been provided");
			}
			Py_DECREF(result);
		}
		PyCodeConfig(){}

		~PyCodeConfig(){
			_clean();
		}
};

shared_ptr<PyCodeConfig> config;
PyObject* py_handle_packet_code = nullptr;

void init_handle_packet_code(){
	py_handle_packet_code = Py_CompileStringExFlags(
		"firegex.nfproxy.internals.handle_packet()\n", "<pyfilter>",
	Py_file_input, NULL, 2);

	if (py_handle_packet_code == nullptr){
		std::cerr << "[fatal] [main] Failed to compile the utility python code (strange behaviour, probably a bug)" << endl;
		throw invalid_argument("Failed to compile the code");
	}
}

}}
#endif // PROXY_TUNNEL_SETTINGS_CPP

