#include "proxytun/settings.cpp"
#include "proxytun/proxytun.cpp"
#include "classes/netfilter.cpp"
#include <syncstream>
#include <iostream>

using namespace std;

void config_updater (){
	while (true){
		//TODO read config getline(cin, line);
		if (cin.eof()){
			cerr << "[fatal] [updater] cin.eof()" << endl;
			exit(EXIT_FAILURE);
		}
		if (cin.bad()){
			cerr << "[fatal] [updater] cin.bad()" << endl;
			exit(EXIT_FAILURE);
		}
		cerr << "[info] [updater] Updating configuration" << endl;
		
		try{
			//TODO add data config.reset(new PyCodeConfig(""));
			cerr << "[info] [updater] Config update done" << endl;
			osyncstream(cout) << "ACK OK" << endl;
		}catch(const std::exception& e){
			cerr << "[error] [updater] Failed to build new configuration!" << endl;
			osyncstream(cout) << "ACK FAIL " << e.what() << endl;
		}
	}
}

int main(int argc, char *argv[]){
	int n_of_threads = 1;
   	char * n_threads_str = getenv("NTHREADS");
   	if (n_threads_str != nullptr) n_of_threads = ::atoi(n_threads_str);
	if(n_of_threads <= 0) n_of_threads = 1;

	config.reset(new PyCodeConfig(""));
	
	NFQueueSequence<PyProxyQueue> queues(n_of_threads);
	queues.start();

	osyncstream(cout) << "QUEUES " << queues.init() << " " << queues.end() << endl;
	cerr << "[info] [main] Queues: " << queues.init() << ":" << queues.end() << " threads assigned: " << n_of_threads << endl;

	config_updater();
}
