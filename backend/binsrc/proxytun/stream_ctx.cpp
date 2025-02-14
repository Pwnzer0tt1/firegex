
#ifndef STREAM_CTX_CPP
#define STREAM_CTX_CPP

#include <iostream>
#include <tins/tcp_ip/stream_follower.h>
#include <tins/tcp_ip/stream_identifier.h>

using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;
using namespace std;

typedef Tins::TCPIP::StreamIdentifier stream_id;

struct pyfilter_ctx {
	void * pyglob; // TODO python glob???
	string pycode;
};

typedef map<stream_id, pyfilter_ctx> matching_map;

struct packet_info;

struct tcp_stream_tmp {
	bool matching_has_been_called = false;
	bool already_closed = false;
	bool result;
	packet_info *pkt_info;
};

struct stream_ctx {
	matching_map streams_ctx;
	StreamFollower follower;
	tcp_stream_tmp match_info;
	void clean_stream_by_id(stream_id sid){
		auto stream_search = streams_ctx.find(sid);
		if (stream_search != streams_ctx.end()){
			auto stream_match = stream_search->second;
			//DEALLOC PY GLOB TODO
		}
	}
	void clean(){
		for (auto ele: streams_ctx){
			//TODO dealloc ele.second.pyglob
		}
	}
};

struct packet_info {
	string payload;
	stream_id sid;
	bool is_input;
	bool is_ipv6;
	stream_ctx* sctx;
	Tins::PDU* packet_pdu;
	Tins::TCP* tcp;
};


#endif // STREAM_CTX_CPP