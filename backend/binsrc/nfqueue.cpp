#include "classes/regex_rules.cpp"
#include "classes/netfilter.cpp"
#include "utils.hpp"
#include <iostream>

using namespace std;

shared_ptr<RegexRules> regex_config;

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
		}catch(...){
			cerr << "[error] [updater] Failed to build new configuration!" << endl;
			// TODO send a row on stdout for this error
		}
	}
	
}

void inline scratch_setup(regex_ruleset &conf, hs_scratch_t* & scratch){
	if (scratch == nullptr && conf.hs_db != nullptr){
		if (hs_alloc_scratch(conf.hs_db, &scratch) != HS_SUCCESS) {
			throw invalid_argument("Cannot alloc scratch");
		}
	}
}

struct matched_data{
	unsigned int matched = 0;
	bool has_matched = false;
};

bool filter_callback(packet_info & info){
	shared_ptr<RegexRules> conf = regex_config;
	if (conf->ver() != info.sctx->latest_config_ver){
		info.sctx->clean_scratches();
	}
	scratch_setup(conf->input_ruleset, info.sctx->in_scratch);
	scratch_setup(conf->output_ruleset, info.sctx->out_scratch);

	hs_database_t* regex_matcher = info.is_input ? conf->input_ruleset.hs_db : conf->output_ruleset.hs_db;
	if (regex_matcher == nullptr){
		return true;
	}
	matched_data match_res;
	hs_error_t err;
	hs_scratch_t* scratch_space = info.is_input ? info.sctx->in_scratch: info.sctx->out_scratch;
	auto match_func = [](unsigned int id, auto from, auto to, auto flags, auto ctx){
		auto res = (matched_data*)ctx;
		res->has_matched = true;
		res->matched = id;
		return -1; // Stop matching
	};
	hs_stream_t* stream_match;
	if (conf->stream_mode()){
		matching_map match_map = info.is_input ? info.sctx->in_hs_streams : info.sctx->out_hs_streams;
		auto stream_search = match_map.find(info.sid);
		
		if (stream_search == match_map.end()){
            if (hs_open_stream(regex_matcher, 0, &stream_match) != HS_SUCCESS) {
                cerr << "[error] [filter_callback] Error opening the stream matcher (hs)" << endl;
                throw invalid_argument("Cannot open stream match on hyperscan");
            }
			if (info.is_tcp){
				match_map[info.sid] = stream_match;
			}
		}else{
			stream_match = stream_search->second;
		}
		err = hs_scan_stream(
			stream_match,info.payload.c_str(), info.payload.length(),
			0, scratch_space, match_func, &match_res
		);
	}else{
		err = hs_scan(
			regex_matcher,info.payload.c_str(), info.payload.length(),
			0, scratch_space, match_func, &match_res
		);
	}
	if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED) {
		cerr << "[error] [filter_callback] Error while matching the stream (hs)" << endl;
		throw invalid_argument("Error while matching the stream with hyperscan");
	}
	if (
		!info.is_tcp && conf->stream_mode() && 
		hs_close_stream(stream_match, scratch_space, nullptr, nullptr) != HS_SUCCESS
	){
		cerr << "[error] [filter_callback] Error closing the stream matcher (hs)" << endl;
		throw invalid_argument("Cannot close stream match on hyperscan");
	}
	if (match_res.has_matched){
		auto rules_vector = info.is_input ? conf->input_ruleset.regexes : conf->output_ruleset.regexes;
		stringstream msg;
		msg << "BLOCKED " << rules_vector[match_res.matched] << "\n";
		cout << msg.str() << flush;
		return false;
	}
	return true;
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
	cerr << "[info] [main] Using " << n_of_threads << " threads, stream mode: " << stream_mode << endl;
	regex_config.reset(new RegexRules(stream_mode));
	
	NFQueueSequence<filter_callback> queues(n_of_threads);
	queues.start();

	cout << "QUEUES " << queues.init() << " " << queues.end() << endl;
	cerr << "[info] [main] Queues: " << queues.init() << ":" << queues.end() << " threads assigned: " << n_of_threads << endl;

	config_updater();
}
