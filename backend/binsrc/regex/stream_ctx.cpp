
#ifndef STREAM_CTX_CPP
#define STREAM_CTX_CPP

#include <iostream>
#include <hs.h>
#include <tins/tcp_ip/stream_follower.h>
#include <tins/tcp_ip/stream_identifier.h>

using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;
using namespace std;

typedef Tins::TCPIP::StreamIdentifier stream_id;
typedef map<stream_id, hs_stream_t*> matching_map;

/* Considering to use unorder_map using this hash of stream_id 

namespace std {
	template<>
	struct hash<stream_id> {
		size_t operator()(const stream_id& sid) const
		{
			return std::hash<std::uint32_t>()(sid.max_address[0] + sid.max_address[1] + sid.max_address[2] + sid.max_address[3] + sid.max_address_port + sid.min_address[0] + sid.min_address[1] + sid.min_address[2] + sid.min_address[3] + sid.min_address_port);
		}
	};
}

*/

#ifdef DEBUG
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
#endif


struct packet_info;

struct tcp_stream_tmp {
	bool matching_has_been_called = false;
	bool result;
	packet_info *pkt_info;
};

struct stream_ctx {
	matching_map in_hs_streams;
	matching_map out_hs_streams;
	hs_scratch_t* in_scratch = nullptr;
	hs_scratch_t* out_scratch = nullptr;
	u_int16_t latest_config_ver = 0;
	StreamFollower follower;
	tcp_stream_tmp tcp_match_util;

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
		#ifdef DEBUG
		cerr << "[DEBUG] [NetfilterQueue.clean_stream_by_id] Cleaning stream context of " << sid << endl;
		#endif
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

		#ifdef DEBUG
		cerr << "[DEBUG] [NetfilterQueue.clean] Cleaning stream context" << endl;
		#endif

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

struct packet_info {
	string packet;
	string payload;
	stream_id sid;
	bool is_input;
	bool is_tcp;
	stream_ctx* sctx;
};


#endif // STREAM_CTX_CPP