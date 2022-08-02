#include "classes/regex_filter.hpp"
#include "classes/netfilter.hpp"
#include "utils.hpp"
#include <iostream>

using namespace std;

shared_ptr<regex_rules> regex_config;

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
		regex_rules *regex_new_config = new regex_rules();
		while(!config_stream.eof()){
			string data;
			config_stream >> data;
			if (data != "" && data != "\n"){
				regex_new_config->add(data.c_str());
			}
		}
		regex_config.reset(regex_new_config);
		cerr << "[info] [updater] Config update done" << endl;

	}
	
}

template <bool is_input>
bool filter_callback(const uint8_t *data, uint32_t len){
	shared_ptr<regex_rules> current_config = regex_config;
	return current_config->check((unsigned char *)data, len, is_input);
}

int main(int argc, char *argv[])
{
	int n_of_threads = 1;
   	char * n_threads_str = getenv("NTHREADS");
   	if (n_threads_str != NULL) n_of_threads = ::atoi(n_threads_str);
	if(n_of_threads <= 0) n_of_threads = 1;
	if (n_of_threads % 2 != 0 ) n_of_threads++;
	cerr << "[info] [main] Using " << n_of_threads << " threads" << endl;
	regex_config.reset(new regex_rules());
	NFQueueSequence<filter_callback<true>> input_queues(n_of_threads/2);
	input_queues.start();
	NFQueueSequence<filter_callback<false>> output_queues(n_of_threads/2);
	output_queues.start();

	cout << "QUEUES INPUT " << input_queues.init() << " " << input_queues.end() << " OUTPUT " << output_queues.init() << " " << output_queues.end() << endl;
	cerr << "[info] [main] Input queues: " << input_queues.init() << ":" << input_queues.end() << " threads assigned: " << n_of_threads/2 << endl;
	cerr << "[info] [main] Output queues: " << output_queues.init() << ":" << output_queues.end() << " threads assigned: " << n_of_threads/2 << endl;

	config_updater();
}
