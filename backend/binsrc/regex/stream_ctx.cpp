
#ifndef STREAM_CTX_CPP
#define STREAM_CTX_CPP

#include <iostream>
#include <hs.h>
#include <tins/tcp_ip/stream_identifier.h>
#include <functional>
#include <map>
#include "regexfilter.cpp"

using namespace std;

namespace Firegex {
namespace Regex {

typedef Tins::TCPIP::StreamIdentifier stream_id;
typedef map<stream_id, hs_stream_t*> matching_map;

ostream& operator<<(ostream& os, const Tins::TCPIP::StreamIdentifier::address_type &sid){
	bool first_print = false;
	for (auto ele: sid){
		if (first_print || ele){
			first_print = true;
			os << (int)ele << ".";
		}
	}
	return os;
}

ostream& operator<<(ostream& os, const stream_id &sid){
	os << sid.max_address << ":" << sid.max_address_port << " -> " << sid.min_address << ":" << sid.min_address_port;
	return os;
}

struct stream_ctx {
	matching_map in_hs_streams;
	matching_map out_hs_streams;
	hs_scratch_t* in_scratch = nullptr;
	hs_scratch_t* out_scratch = nullptr;

	void clean_scratches(){
		if (out_scratch != nullptr){
			hs_free_scratch(out_scratch);
			out_scratch = nullptr;
		}
		if (in_scratch != nullptr){
			hs_free_scratch(in_scratch);
			in_scratch = nullptr;
		}
	}

	void clean_stream_by_id(stream_id sid){
		auto stream_search = in_hs_streams.find(sid);
		hs_stream_t* stream_match;
		if (stream_search != in_hs_streams.end()){
			stream_match = stream_search->second;
			if (hs_close_stream(stream_match, in_scratch, nullptr, nullptr) != HS_SUCCESS) {
                cerr << "[error] [NetfilterQueue.clean_stream_by_id] Error closing the stream matcher (hs)" << endl;
                throw invalid_argument("Cannot close stream match on hyperscan");
            }
			in_hs_streams.erase(stream_search);
		}

		stream_search = out_hs_streams.find(sid);
		if (stream_search != out_hs_streams.end()){
			stream_match = stream_search->second;
			if (hs_close_stream(stream_match, out_scratch, nullptr, nullptr) != HS_SUCCESS) {
                cerr << "[error] [NetfilterQueue.clean_stream_by_id] Error closing the stream matcher (hs)" << endl;
                throw invalid_argument("Cannot close stream match on hyperscan");
            }
			out_hs_streams.erase(stream_search);
		}
	}

	void clean(){
		if (in_scratch){
			for(auto ele: in_hs_streams){
				if (hs_close_stream(ele.second, in_scratch, nullptr, nullptr) != HS_SUCCESS) {
					cerr << "[error] [NetfilterQueue.clean_stream_by_id] Error closing the stream matcher (hs)" << endl;
					throw invalid_argument("Cannot close stream match on hyperscan");
				}
			}
			in_hs_streams.clear();
		}
		
		if (out_scratch){
			for(auto ele: out_hs_streams){
				if (hs_close_stream(ele.second, out_scratch, nullptr, nullptr) != HS_SUCCESS) {
					cerr << "[error] [NetfilterQueue.clean_stream_by_id] Error closing the stream matcher (hs)" << endl;
					throw invalid_argument("Cannot close stream match on hyperscan");
				}
			}
			out_hs_streams.clear();
		}
		clean_scratches();
	}
};

}}
#endif // STREAM_CTX_CPP