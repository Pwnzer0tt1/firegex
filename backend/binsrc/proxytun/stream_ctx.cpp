
#ifndef STREAM_CTX_CPP
#define STREAM_CTX_CPP

#include <iostream>
#include <tins/tcp_ip/stream_identifier.h>
#include <map>

using namespace std;

typedef Tins::TCPIP::StreamIdentifier stream_id;

struct pyfilter_ctx {
	void * pyglob; // TODO python glob???
	string pycode;
};

typedef map<stream_id, pyfilter_ctx*> matching_map;

struct stream_ctx {
	matching_map streams_ctx;

	void clean_stream_by_id(stream_id sid){
		auto stream_search = streams_ctx.find(sid);
		if (stream_search != streams_ctx.end()){
			auto stream_match = stream_search->second;
			//DEALLOC PY GLOB TODO
			delete stream_match;
		}
	}
	void clean(){
		for (auto ele: streams_ctx){
			//TODO dealloc ele.second.pyglob
			delete ele.second;
		}
	}
};

#endif // STREAM_CTX_CPP