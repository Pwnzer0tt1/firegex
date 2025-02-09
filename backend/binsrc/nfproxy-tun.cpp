#include "proxytun/proxytun.cpp"
#include "utils.hpp"
#include <iostream>
#include <syncstream>

using namespace std;

int main(int argc, char *argv[]){
	int n_of_threads = 1;
   	char * n_threads_str = getenv("NTHREADS");
   	if (n_threads_str != nullptr) n_of_threads = ::atoi(n_threads_str);
	if(n_of_threads <= 0) n_of_threads = 1;
	
	NFQueueSequence<SocketTunnelQueue> queues(n_of_threads);
	queues.start();

	osyncstream(cout) << "QUEUES " << queues.init() << " " << queues.end() << endl;
	cerr << "[info] [main] Queues: " << queues.init() << ":" << queues.end() << " threads assigned: " << n_of_threads << endl;

}
