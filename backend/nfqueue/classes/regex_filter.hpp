#include <iostream>
#include <cstring>
#include <jpcre2.hpp>
#include <sstream>
#include "../utils.hpp"


#ifndef REGEX_FILTER_HPP
#define REGEX_FILTER_HPP

typedef jpcre2::select<char> jp;
typedef std::pair<std::string,jp::Regex> regex_rule_pair;
typedef std::vector<regex_rule_pair> regex_rule_vector;
struct regex_rules{
   regex_rule_vector output_whitelist, input_whitelist, output_blacklist, input_blacklist;

   regex_rule_vector* getByCode(char code){
      switch(code){
         case 'C': // Client to server Blacklist
            return &input_blacklist;  break;
         case 'c': // Client to server Whitelist
            return &input_whitelist;  break;
         case 'S': // Server to client Blacklist
            return &output_blacklist;  break;
         case 's': // Server to client Whitelist
            return &output_whitelist;  break;
      }
      throw std::invalid_argument( "Expected 'C' 'c' 'S' or 's'" );
   }

   int add(const char* arg){
		//Integrity checks
		size_t arg_len = strlen(arg);
		if (arg_len < 2 || arg_len%2 != 0){
			std::cerr << "[warning] [regex_rules.add] invalid arg passed (" << arg << "), skipping..." << std::endl;
			return -1;
		}
		if (arg[0] != '0' && arg[0] != '1'){
			std::cerr << "[warning] [regex_rules.add] invalid is_case_sensitive (" << arg[0] << ") in '" << arg << "', must be '1' or '0', skipping..." << std::endl;
			return -1;
		}
		if (arg[1] != 'C' && arg[1] != 'c' && arg[1] != 'S' && arg[1] != 's'){
			std::cerr << "[warning] [regex_rules.add] invalid filter_type (" << arg[1] << ") in '" << arg << "', must be 'C', 'c', 'S' or 's', skipping..." << std::endl;
			return -1;
		}
		std::string hex(arg+2), expr;
		if (!unhexlify(hex, expr)){
			std::cerr << "[warning] [regex_rules.add] invalid hex regex value (" << hex << "), skipping..." << std::endl;
			return -1;
		}
		//Push regex
		jp::Regex regex(expr,arg[0] == '1'?"gS":"giS");
		if (regex){
			std::cerr << "[info] [regex_rules.add] adding new regex filter: '" << expr << "'" << std::endl;			
			getByCode(arg[1])->push_back(std::make_pair(std::string(arg), regex));
		} else {
			std::cerr << "[warning] [regex_rules.add] compiling of '" << expr << "' regex failed, skipping..." << std::endl;
			return -1;
		}
		return 0;
	}

	bool check(unsigned char* data, const size_t& bytes_transferred, const bool in_input){
		std::string str_data((char *) data, bytes_transferred);
		for (regex_rule_pair ele:(in_input?input_blacklist:output_blacklist)){
			try{
				if(ele.second.match(str_data)){
					std::stringstream msg;
					msg << "BLOCKED " << ele.first << "\n";
					std::cout << msg.str() << std::flush;
					return false;
				}
			} catch(...){
				std::cerr << "[info] [regex_rules.check] Error while matching blacklist regex: " << ele.first << std::endl;
			}
		}
		for (regex_rule_pair ele:(in_input?input_whitelist:output_whitelist)){
			try{
				std::cerr << "[debug] [regex_rules.check] regex whitelist match " << ele.second.getPattern() << std::endl;
				if(!ele.second.match(str_data)){
					std::stringstream msg;
					msg << "BLOCKED " << ele.first << "\n";
					std::cout << msg.str() << std::flush;
					return false;
				}
			} catch(...){
				std::cerr << "[info] [regex_rules.check] Error while matching whitelist regex: " << ele.first << std::endl;
			}      
		}
		return true;
	}

};

#endif // REGEX_FILTER_HPP