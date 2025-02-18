#ifndef REGEX_FILTER_CPP
#define REGEX_FILTER_CPP

#include <iostream>
#include <cstring>
#include <sstream>
#include "../utils.cpp"
#include <vector>
#include <hs.h>
#include <memory>

using namespace std;

namespace Firegex {
namespace Regex {

enum FilterDirection{ CTOS, STOC };

struct decoded_regex {
	string regex;
	FilterDirection direction;
	bool is_case_sensitive;
};

struct regex_ruleset {
	hs_database_t* hs_db = nullptr;
	vector<string> regexes;
};

decoded_regex decode_regex(string regex){

	size_t arg_len = regex.size();
	if (arg_len < 2 || arg_len%2 != 0){
		cerr << "[warning] [decode_regex] invalid arg passed (" << regex << "), skipping..." << endl;
		throw runtime_error( "Invalid expression len (too small)" );
	}
	if (regex[0] != '0' && regex[0] != '1'){
		cerr << "[warning] [decode_regex] invalid is_case_sensitive (" << regex[0] << ") in '" << regex << "', must be '1' or '0', skipping..." << endl;
		throw runtime_error( "Invalid is_case_sensitive" );
	}
	if (regex[1] != 'C' && regex[1] != 'S'){
		cerr << "[warning] [decode_regex] invalid filter_direction (" << regex[1] << ") in '" << regex << "', must be 'C', 'S', skipping..." << endl;
		throw runtime_error( "Invalid filter_direction" );
	}
	string hex(regex.c_str()+2), expr;
	if (!unhexlify(hex, expr)){
		cerr << "[warning] [decode_regex] invalid hex regex value (" << hex << "), skipping..." << endl;
		throw runtime_error( "Invalid hex regex encoded value" );
	}
	decoded_regex ruleset{
		regex: expr,
		direction: regex[1] == 'C' ? CTOS : STOC,
		is_case_sensitive: regex[0] == '1'
	};
	return ruleset;
}

class RegexRules{
	public:
		regex_ruleset output_ruleset, input_ruleset;
		
	static void compile_regex(char* regex){
		hs_database_t* db = nullptr;
		hs_compile_error_t *compile_err = nullptr;
		if (
			hs_compile(
				regex,
				HS_FLAG_SINGLEMATCH | HS_FLAG_ALLOWEMPTY,
				HS_MODE_BLOCK,
				nullptr, &db, &compile_err
			) != HS_SUCCESS
		) {
			string err = string(compile_err->message);
			hs_free_compile_error(compile_err);
			throw runtime_error(err);
		}else{
			hs_free_database(db);
		}
		
	}

	private:
		static inline u_int16_t glob_seq = 0;
		u_int16_t version;
		vector<pair<string, decoded_regex>> decoded_input_rules;
		vector<pair<string, decoded_regex>> decoded_output_rules;
		bool is_stream = true;

		void free_dbs(){
			if (output_ruleset.hs_db != nullptr){
				hs_free_database(output_ruleset.hs_db);
				output_ruleset.hs_db = nullptr;
			}
			if (input_ruleset.hs_db != nullptr){
				hs_free_database(input_ruleset.hs_db);
				input_ruleset.hs_db = nullptr;
			}
		}



		void fill_ruleset(vector<pair<string, decoded_regex>> & decoded, regex_ruleset & ruleset){
			size_t n_of_regex = decoded.size();
			if (n_of_regex == 0){
				return;
			}
			vector<const char*> regex_match_rules(n_of_regex);
			vector<unsigned int> regex_array_ids(n_of_regex);
			vector<unsigned int> regex_flags(n_of_regex);
			for(int i = 0; i < n_of_regex; i++){
				regex_match_rules[i] = decoded[i].second.regex.c_str();
				regex_array_ids[i] = i;
				regex_flags[i] = HS_FLAG_SINGLEMATCH | HS_FLAG_ALLOWEMPTY;
				if (!decoded[i].second.is_case_sensitive){
					regex_flags[i] |= HS_FLAG_CASELESS;
				}
			}
			#ifdef DEBUG
			cerr << "[DEBUG] [RegexRules.fill_ruleset] compiling " << n_of_regex << " regexes..." << endl;
			for (int i = 0; i < n_of_regex; i++){
				cerr << "[DEBUG] [RegexRules.fill_ruleset] regex[" << i << "]: " << decoded[i].first << " " << decoded[i].second.regex << endl;
				cerr << "[DEBUG] [RegexRules.fill_ruleset] regex_match_rules[" << i << "]: " << regex_match_rules[i] << endl;
				cerr << "[DEBUG] [RegexRules.fill_ruleset] regex_flags[" << i << "]: " << regex_flags[i] << endl;
				cerr << "[DEBUG] [RegexRules.fill_ruleset] regex_array_ids[" << i << "]: " << regex_array_ids[i] << endl;
			}
			#endif
			hs_database_t* rebuilt_db = nullptr;
			hs_compile_error_t *compile_err = nullptr;
			if (
				hs_compile_multi(
					regex_match_rules.data(),
					regex_flags.data(),
					regex_array_ids.data(),
					n_of_regex,
					is_stream?HS_MODE_STREAM:HS_MODE_BLOCK,
					nullptr, &rebuilt_db, &compile_err
				) != HS_SUCCESS
			) {
				cerr << "[warning] [RegexRules.fill_ruleset] hs_db failed to compile: '" << compile_err->message << "' skipping..." << endl;
				hs_free_compile_error(compile_err);
				throw runtime_error( "Failed to compile hyperscan db" );
			}
			ruleset.hs_db = rebuilt_db;
			ruleset.regexes = vector<string>(n_of_regex);
			for(int i = 0; i < n_of_regex; i++){
				ruleset.regexes[i] = decoded[i].first;
			}
		}

	public:
		RegexRules(vector<string> raw_rules, bool is_stream){
			this->is_stream = is_stream;
			this->version = ++glob_seq; // 0 version is a invalid version (useful for some logics)
			for(string ele : raw_rules){
				try{
					decoded_regex rule = decode_regex(ele);
					if (rule.direction == FilterDirection::CTOS){
						decoded_input_rules.push_back(make_pair(ele, rule));
					}else{
						decoded_output_rules.push_back(make_pair(ele, rule));
					}
				}catch(...){
					throw current_exception();
				}
			}
			fill_ruleset(decoded_input_rules, input_ruleset);
			try{
				fill_ruleset(decoded_output_rules, output_ruleset);
			}catch(...){
				free_dbs();
				throw current_exception();
			}
		}

		u_int16_t ver(){
			return version;
		}

		RegexRules(bool is_stream){
			vector<string> no_rules;
			RegexRules(no_rules, is_stream);
		}

		bool stream_mode(){
			return is_stream;
		}



		RegexRules(){
			RegexRules(true);
		}
		
		~RegexRules(){
			free_dbs();
		}
};

shared_ptr<RegexRules> regex_config;

void inline scratch_setup(regex_ruleset &conf, hs_scratch_t* & scratch){
	if (scratch == nullptr && conf.hs_db != nullptr){
		if (hs_alloc_scratch(conf.hs_db, &scratch) != HS_SUCCESS) {
			throw invalid_argument("Cannot alloc scratch");
		}
	}
}

}}
#endif // REGEX_FILTER_CPP

