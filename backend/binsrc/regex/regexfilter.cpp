#ifndef REGEX_FILTER_CLASS_CPP
#define REGEX_FILTER_CLASS_CPP

#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <tins/tins.h>
#include <tins/tcp_ip/stream_follower.h>
#include <tins/tcp_ip/stream_identifier.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/types.h>
#include <stdexcept>
#include <thread>
#include <hs.h>
#include <syncstream>
#include <functional>
#include <iostream>
#include "../classes/netfilter.cpp"
#include "stream_ctx.cpp"
#include "regex_rules.cpp"

using namespace std;


namespace Firegex {
namespace Regex {

using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;



class RegexNfQueue : public NfQueue::ThreadNfQueue<RegexNfQueue> {
public:
	stream_ctx sctx;
	u_int16_t latest_config_ver = 0;
	StreamFollower follower;
	struct {
		bool matching_has_been_called = false;
		bool already_closed = false;
		bool result;
		NfQueue::PktRequest<RegexNfQueue>* pkt;
	} match_ctx;
	

	bool filter_action(NfQueue::PktRequest<RegexNfQueue>* pkt){
		shared_ptr<RegexRules> conf = regex_config;

		auto current_version = conf->ver();
		if (current_version != latest_config_ver){
			sctx.clean();
			latest_config_ver = current_version;
		}
		scratch_setup(conf->input_ruleset, sctx.in_scratch);
		scratch_setup(conf->output_ruleset, sctx.out_scratch);
	
		hs_database_t* regex_matcher = pkt->is_input ? conf->input_ruleset.hs_db : conf->output_ruleset.hs_db;
		if (regex_matcher == nullptr){
			return true;
		}
		
		struct matched_data{
			unsigned int matched = 0;
			bool has_matched = false;
		} match_res;

		hs_error_t err;
		hs_scratch_t* scratch_space = pkt->is_input ? sctx.in_scratch: sctx.out_scratch;
		auto match_func = [](unsigned int id, auto from, auto to, auto flags, auto ctx){
			auto res = (matched_data*)ctx;
			res->has_matched = true;
			res->matched = id;
			return -1; // Stop matching
		};
		hs_stream_t* stream_match;
		if (conf->stream_mode()){
			matching_map* match_map = pkt->is_input ? &sctx.in_hs_streams : &sctx.out_hs_streams;
			auto stream_search = match_map->find(pkt->sid);
			
			if (stream_search == match_map->end()){
				if (hs_open_stream(regex_matcher, 0, &stream_match) != HS_SUCCESS) {
					cerr << "[error] [filter_callback] Error opening the stream matcher (hs)" << endl;
					throw invalid_argument("Cannot open stream match on hyperscan");
				}
				if (pkt->l4_proto == NfQueue::L4Proto::TCP){
					match_map->insert_or_assign(pkt->sid, stream_match);
				}
			}else{
				stream_match = stream_search->second;
			}
			err = hs_scan_stream(
				stream_match,pkt->data.c_str(), pkt->data.size(),
				0, scratch_space, match_func, &match_res
			);
		}else{
			err = hs_scan(
				regex_matcher,pkt->data.c_str(), pkt->data.size(),
				0, scratch_space, match_func, &match_res
			);
		}
		if (
			pkt->l4_proto != NfQueue::L4Proto::TCP && conf->stream_mode() && 
			hs_close_stream(stream_match, scratch_space, nullptr, nullptr) != HS_SUCCESS
		){
			cerr << "[error] [filter_callback] Error closing the stream matcher (hs)" << endl;
			throw invalid_argument("Cannot close stream match on hyperscan");
		}
		if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED) {
			cerr << "[error] [filter_callback] Error while matching the stream (hs)" << endl;
			throw invalid_argument("Error while matching the stream with hyperscan");
		}
		if (match_res.has_matched){
			auto& rules_vector = pkt->is_input ? conf->input_ruleset.regexes : conf->output_ruleset.regexes;
			osyncstream(cout) << "BLOCKED " << rules_vector[match_res.matched] << endl;
			return false;
		}
		return true;
	}

	void handle_next_packet(NfQueue::PktRequest<RegexNfQueue>* pkt) override{
		bool empty_payload = pkt->data.size() == 0;
		if (pkt->tcp){
			match_ctx.matching_has_been_called = false;
			match_ctx.pkt = pkt;

			if (pkt->ipv4){
				follower.process_packet(*pkt->ipv4);
			}else{
				follower.process_packet(*pkt->ipv6);
			}
	
			// Do an action only is an ordered packet has been received
			if (match_ctx.matching_has_been_called){
	
				//In this 2 cases we have to remove all data about the stream
				if (!match_ctx.result || match_ctx.already_closed){
					sctx.clean_stream_by_id(pkt->sid);
					//If the packet has data, we have to remove it
					if (!empty_payload){
						Tins::PDU* data_layer = pkt->tcp->release_inner_pdu();
						if (data_layer != nullptr){
							delete data_layer;
						}
					}
					//For the first matched data or only for data packets, we set FIN bit
					//This only for client packets, because this will trigger server to close the connection
					//Packets will be filtered anyway also if client don't send packets
					if ((!match_ctx.result || !empty_payload) && pkt->is_input){
						pkt->tcp->set_flag(Tins::TCP::FIN,1);
						pkt->tcp->set_flag(Tins::TCP::ACK,1);
						pkt->tcp->set_flag(Tins::TCP::SYN,0);
					}
					//Send the edited packet to the kernel
					return pkt->mangle();
				}
			}
			return pkt->accept();
		}else{
			if (!pkt->udp){
				throw invalid_argument("Only TCP and UDP are supported");
			}
			if(empty_payload){
				return pkt->accept();
			}else if (filter_action(pkt)){
				return pkt->accept();
			}else{
				return pkt->drop();
			}
		}
	}
	//If the stream has already been matched, drop all data, and try to close the connection
	static void keep_fin_packet(RegexNfQueue* nfq){
		nfq->match_ctx.matching_has_been_called = true;
		nfq->match_ctx.already_closed = true;
	}

	static void on_data_recv(Stream& stream, RegexNfQueue* nfq, string data) {
		nfq->match_ctx.matching_has_been_called = true;
		nfq->match_ctx.already_closed = false;
		bool result = nfq->filter_action(nfq->match_ctx.pkt);
		if (!result){
			nfq->sctx.clean_stream_by_id(nfq->match_ctx.pkt->sid);
			stream.client_data_callback(bind(keep_fin_packet, nfq));
			stream.server_data_callback(bind(keep_fin_packet, nfq));
		}
		nfq->match_ctx.result = result;
	}

	//Input data filtering
	static void on_client_data(Stream& stream, RegexNfQueue* nfq) {
		on_data_recv(stream, nfq, string(stream.client_payload().begin(), stream.client_payload().end()));
	}

	//Server data filtering
	static void on_server_data(Stream& stream, RegexNfQueue* nfq) {
		on_data_recv(stream, nfq, string(stream.server_payload().begin(), stream.server_payload().end()));
	}

	// A stream was terminated. The second argument is the reason why it was terminated
	static void on_stream_close(Stream& stream, RegexNfQueue* nfq) {
		stream_id stream_id = stream_id::make_identifier(stream);
		nfq->sctx.clean_stream_by_id(stream_id);
	}

	static void on_new_stream(Stream& stream, RegexNfQueue* nfq) {
		stream.auto_cleanup_payloads(true);
		if (stream.is_partial_stream()) {
			stream.enable_recovery_mode(10 * 1024);
		}
		stream.client_data_callback(bind(on_client_data, placeholders::_1, nfq));
		stream.server_data_callback(bind(on_server_data, placeholders::_1, nfq));
		stream.stream_closed_callback(bind(on_stream_close, placeholders::_1, nfq));
	}

	void before_loop() override{
		follower.new_stream_callback(bind(on_new_stream, placeholders::_1, this));
		follower.stream_termination_callback(bind(on_stream_close, placeholders::_1, this));
	}

	~RegexNfQueue(){
		sctx.clean();
	}

};

}}
#endif // REGEX_FILTER_CLASS_CPP