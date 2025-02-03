#include <iostream>
#include <cstring>
#include <sstream>
#include "../utils.hpp"
#include <vector>
#include <hs.h>

using namespace std;

#ifndef REGEX_FILTER_HPP
#define REGEX_FILTER_HPP

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
			const char* regex_match_rules[n_of_regex];
			unsigned int regex_array_ids[n_of_regex];
			unsigned int regex_flags[n_of_regex];
			for(int i = 0; i < n_of_regex; i++){
				regex_match_rules[i] = decoded[i].second.regex.c_str();
				regex_array_ids[i] = i;
				regex_flags[i] = HS_FLAG_SINGLEMATCH | HS_FLAG_ALLOWEMPTY;
				if (!decoded[i].second.is_case_sensitive){
					regex_flags[i] |= HS_FLAG_CASELESS;
				}
			}

			hs_database_t* rebuilt_db;
			hs_compile_error_t *compile_err;
			if (
				hs_compile_multi(
					regex_match_rules,
					regex_flags,
					regex_array_ids,
					n_of_regex,
					is_stream?HS_MODE_STREAM:HS_MODE_BLOCK,
					nullptr,&rebuilt_db, &compile_err
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

#endif // REGEX_FILTER_HPP

