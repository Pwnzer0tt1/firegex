#include "regex/regex_rules.cpp"
#include "regex/regexfilter.cpp"
#include "classes/netfilter.cpp"
#include <syncstream>
#include <iostream>

using namespace std;

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

	regex_config.reset(new RegexRules(stream_mode));
	
	NFQueueSequence<RegexQueue> queues(n_of_threads);
	queues.start();

	osyncstream(cout) << "QUEUES " << queues.init() << " " << queues.end() << endl;
	cerr << "[info] [main] Queues: " << queues.init() << ":" << queues.end() << " threads assigned: " << n_of_threads << " stream mode: " << stream_mode << endl;

	config_updater();
}
