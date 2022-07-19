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
	if(!is_sudo()){
		cerr << "[fatal] [main] You must be root to run this program" << endl;
		exit(EXIT_FAILURE);
	}
	int n_of_queue = 1;
	if (argc >= 2) n_of_queue = atoi(argv[1]);
	regex_config.reset(new regex_rules());
	NFQueueSequence<filter_callback<true>> input_queues(n_of_queue);
	input_queues.start();
	NFQueueSequence<filter_callback<false>> output_queues(n_of_queue);
	output_queues.start();

	cout << "QUEUES INPUT " << input_queues.init() << " " << input_queues.end() << " OUTPUT " << output_queues.init() << " " << output_queues.end() << endl;

	config_updater();
}
