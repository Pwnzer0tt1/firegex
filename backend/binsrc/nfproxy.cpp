#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "proxytun/settings.cpp"
#include "proxytun/proxytun.cpp"
#include "classes/netfilter.cpp"
#include <syncstream>
#include <iostream>
#include <stdexcept>
#include <cstdlib>

using namespace std;
using namespace Firegex::PyProxy;
using Firegex::NfQueue::MultiThreadQueue;

ssize_t read_check(int __fd, void *__buf, size_t __nbytes){
	ssize_t bytes = read(__fd, __buf, __nbytes);
	if (bytes == 0){
		cerr << "[fatal] [updater] read() returned EOF" << endl;
		throw invalid_argument("read() returned EOF");
	}
	if (bytes < 0){
		cerr << "[fatal] [updater] read() returned an error" << bytes << endl;
		throw invalid_argument("read() returned an error");
	}
	return bytes;
}

void config_updater (){
	while (true){
		uint32_t code_size;
		read_check(STDIN_FILENO, &code_size, 4);
		vector<uint8_t> code(code_size);
		read_check(STDIN_FILENO, code.data(), code_size);
		cerr << "[info] [updater] Updating configuration" << endl;
		try{
			config.reset(new PyCodeConfig(code));
			cerr << "[info] [updater] Config update done" << endl;
			osyncstream(cout) << "ACK OK" << endl;
		}catch(const std::exception& e){
			cerr << "[error] [updater] Failed to build new configuration!" << endl;
			osyncstream(cout) << "ACK FAIL " << e.what() << endl;
		}
	}
}

int main(int argc, char *argv[]){

	Py_Initialize();
	atexit(Py_Finalize);

	if (freopen(nullptr, "rb", stdin) == nullptr){ // We need to read from stdin binary data
		cerr << "[fatal] [main] Failed to reopen stdin in binary mode" << endl;
		return 1;
	}
	int n_of_threads = 1;
   	char * n_threads_str = getenv("NTHREADS");
   	if (n_threads_str != nullptr) n_of_threads = ::atoi(n_threads_str);
	if(n_of_threads <= 0) n_of_threads = 1;

	config.reset(new PyCodeConfig());
	MultiThreadQueue<PyProxyQueue> queue(n_of_threads);

	osyncstream(cout) << "QUEUE " << queue.queue_num() << endl;
	cerr << "[info] [main] Queue: " << queue.queue_num() << " threads assigned: " << n_of_threads << endl;

	thread qthr([&](){
		queue.start();
	});
	config_updater();
	qthr.join();
}
