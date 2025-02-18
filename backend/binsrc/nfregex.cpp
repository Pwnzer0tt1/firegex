#include "regex/regex_rules.cpp"
#include "regex/regexfilter.cpp"
#include "classes/netfilter.cpp"
#include <syncstream>
#include <iostream>

using namespace std;
using namespace Firegex::Regex;
using Firegex::NfQueue::MultiThreadQueue;

/*
Compile options:
USE_PIPES_FOR_BLOKING_QUEUE - use pipes instead of conditional variable, queue and mutex for blocking queue
*/


void config_updater (){
	string line;
	while (true){
		getline(cin, line);
		if (cin.eof()){
			cerr << "[fatal] [updater] cin.eof()" << endl;
			exit(EXIT_FAILURE);
		}
		if (cin.bad()){
			cerr << "[fatal] [updater] cin.bad()" << endl;
			exit(EXIT_FAILURE);
		}
		cerr << "[info] [updater] Updating configuration with line " << line << endl;
		istringstream config_stream(line);
		vector<string> raw_rules;
		
		while(!config_stream.eof()){
			string data;
			config_stream >> data;
			if (data != "" && data != "\n"){
				raw_rules.push_back(data);
			}
		}
		try{
			regex_config.reset(new RegexRules(raw_rules, regex_config->stream_mode()));
			cerr << "[info] [updater] Config update done to ver "<< regex_config->ver() << endl;
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

	char * matchmode = getenv("MATCH_MODE");
	bool stream_mode = true;
	if (matchmode != nullptr && strcmp(matchmode, "block") == 0){
		stream_mode = false;
	}
	
	bool fail_open = strcmp(getenv("FIREGEX_NFQUEUE_FAIL_OPEN"), "1") == 0;

	regex_config.reset(new RegexRules(stream_mode));

	MultiThreadQueue<RegexNfQueue> queue_manager(n_of_threads);
	osyncstream(cout) << "QUEUE " << queue_manager.queue_num() << endl;
	cerr << "[info] [main] Queue: " << queue_manager.queue_num() << " threads assigned: " << n_of_threads << " stream mode: " << stream_mode << " fail open: " << fail_open << endl;

	thread qthr([&](){
		queue_manager.start();
	});
	config_updater();
	qthr.join();

}
