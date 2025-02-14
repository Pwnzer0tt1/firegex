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
#include <iostream>
#include "../classes/netfilter.cpp"
#include "stream_ctx.cpp"
#include "regex_rules.cpp"

using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;
using namespace std;

class RegexQueue: public NfQueueExecutor {
	public:
	stream_ctx sctx;

    void before_loop() override {
		sctx.follower.new_stream_callback(bind(on_new_stream, placeholders::_1, &sctx));
		sctx.follower.stream_termination_callback(bind(on_stream_close, placeholders::_1, &sctx));
    }

    void * callback_data_fetch() override{
        return &sctx;
    }

	static bool filter_action(packet_info& info){
		shared_ptr<RegexRules> conf = regex_config;
		auto current_version = conf->ver();
		if (current_version != info.sctx->latest_config_ver){
			#ifdef DEBUG
			cerr << "[DEBUG] [filter_callback] Configuration has changed (" << current_version << "!=" << info.sctx->latest_config_ver << "), cleaning scratch spaces" << endl;
			#endif
			info.sctx->clean();
			info.sctx->latest_config_ver = current_version;
		}
		scratch_setup(conf->input_ruleset, info.sctx->in_scratch);
		scratch_setup(conf->output_ruleset, info.sctx->out_scratch);
	
		hs_database_t* regex_matcher = info.is_input ? conf->input_ruleset.hs_db : conf->output_ruleset.hs_db;
		if (regex_matcher == nullptr){
			return true;
		}
		
		#ifdef DEBUG
		cerr << "[DEBUG] [filter_callback] Matching packet with " << (info.is_input ? "input" : "output") << " ruleset" << endl;
		#endif
		
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
			matching_map* match_map = info.is_input ? &info.sctx->in_hs_streams : &info.sctx->out_hs_streams;
			#ifdef DEBUG
			cerr << "[DEBUG] [filter_callback] Dumping match_map " << match_map << endl;
			for (auto ele: *match_map){
				cerr << "[DEBUG] [filter_callback] " << ele.first << " -> " << ele.second << endl;
			}
			cerr << "[DEBUG] [filter_callback] End of match_map" << endl;
			#endif
			auto stream_search = match_map->find(info.sid);
			
			if (stream_search == match_map->end()){
				
				#ifdef DEBUG
				cerr << "[DEBUG] [filter_callback] Creating new stream matcher for " << info.sid << endl;
				#endif
				if (hs_open_stream(regex_matcher, 0, &stream_match) != HS_SUCCESS) {
					cerr << "[error] [filter_callback] Error opening the stream matcher (hs)" << endl;
					throw invalid_argument("Cannot open stream match on hyperscan");
				}
				if (info.is_tcp){
					match_map->insert_or_assign(info.sid, stream_match);
				}
			}else{
				stream_match = stream_search->second;
			}
			#ifdef DEBUG
			cerr << "[DEBUG] [filter_callback] Matching as a stream" << endl;
			#endif
			err = hs_scan_stream(
				stream_match,info.payload.c_str(), info.payload.length(),
				0, scratch_space, match_func, &match_res
			);
		}else{
			#ifdef DEBUG
			cerr << "[DEBUG] [filter_callback] Matching as a block" << endl;
			#endif
			err = hs_scan(
				regex_matcher,info.payload.c_str(), info.payload.length(),
				0, scratch_space, match_func, &match_res
			);
		}
		if (
			!info.is_tcp && conf->stream_mode() && 
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
			auto rules_vector = info.is_input ? conf->input_ruleset.regexes : conf->output_ruleset.regexes;
			osyncstream(cout) << "BLOCKED " << rules_vector[match_res.matched] << endl;
			return false;
		}
		return true;
	}

	//If the stream has already been matched, drop all data, and try to close the connection
	static void keep_fin_packet(stream_ctx* sctx){
		sctx->match_info.matching_has_been_called = true;
		sctx->match_info.already_closed = true;
	}
	
	static void on_data_recv(Stream& stream, stream_ctx* sctx, string data) {
		sctx->match_info.matching_has_been_called = true;
		sctx->match_info.already_closed = false;
		bool result = filter_action(*sctx->match_info.pkt_info);
		#ifdef DEBUG
			cerr << "[DEBUG] [NetfilterQueue.on_data_recv] result: " << result << endl;
		#endif
		if (!result){
			#ifdef DEBUG
				cerr << "[DEBUG] [NetfilterQueue.on_data_recv] Stream matched, removing all data about it" << endl;
			#endif
			sctx->clean_stream_by_id(sctx->match_info.pkt_info->sid);
			stream.client_data_callback(bind(keep_fin_packet, sctx));
			stream.server_data_callback(bind(keep_fin_packet, sctx));
		}
		sctx->match_info.result = result;
	}
	
	//Input data filtering
	static void on_client_data(Stream& stream, stream_ctx* sctx) {
		on_data_recv(stream, sctx, string(stream.client_payload().begin(), stream.client_payload().end()));
	}
	
	//Server data filtering
	static void on_server_data(Stream& stream, stream_ctx* sctx) {
		on_data_recv(stream, sctx, string(stream.server_payload().begin(), stream.server_payload().end()));
	}
	
	// A stream was terminated. The second argument is the reason why it was terminated
	static void on_stream_close(Stream& stream, stream_ctx* sctx) {
		stream_id stream_id = stream_id::make_identifier(stream);
		#ifdef DEBUG
			cerr << "[DEBUG] [NetfilterQueue.on_stream_close] Stream terminated, deleting all data" << endl;
		#endif
		sctx->clean_stream_by_id(stream_id);
	}
	
	static void on_new_stream(Stream& stream, stream_ctx* sctx) {
		#ifdef DEBUG
			cerr << "[DEBUG] [NetfilterQueue.on_new_stream] New stream detected" << endl;
		#endif
		stream.auto_cleanup_payloads(true);
		if (stream.is_partial_stream()) {
			#ifdef DEBUG
				cerr << "[DEBUG] [NetfilterQueue.on_new_stream] Partial stream detected" << endl;
			#endif
			stream.enable_recovery_mode(10 * 1024);
		}
		stream.client_data_callback(bind(on_client_data, placeholders::_1, sctx));
		stream.server_data_callback(bind(on_server_data, placeholders::_1, sctx));
		stream.stream_closed_callback(bind(on_stream_close, placeholders::_1, sctx));
	}

	template<typename T>
	static void build_verdict(T packet, uint8_t *payload, uint16_t plen, nlmsghdr *nlh_verdict, nfqnl_msg_packet_hdr *ph, stream_ctx* sctx, bool is_input, bool is_ipv6){
		Tins::TCP* tcp = packet.template find_pdu<Tins::TCP>();
	
		if (tcp){
			Tins::PDU* application_layer = tcp->inner_pdu();
			u_int16_t payload_size = 0;
			if (application_layer != nullptr){
				payload_size = application_layer->size();
			}
			packet_info pktinfo{
				payload: string(payload+plen - payload_size, payload+plen),
				sid: stream_id::make_identifier(packet),
				is_input: is_input,
				is_tcp: true,
				is_ipv6: is_ipv6,
				sctx: sctx,
				packet_pdu: &packet,
				layer4_pdu: tcp,
			};
			sctx->match_info.matching_has_been_called = false;
			sctx->match_info.pkt_info = &pktinfo;
			#ifdef DEBUG
				cerr << "[DEBUG] [NetfilterQueue.build_verdict] TCP Packet received " << packet.src_addr() << ":" << tcp->sport() << " -> " << packet.dst_addr() << ":" << tcp->dport() << " thr: " << this_thread::get_id() <<  ", sending to libtins StreamFollower" << endl;
			#endif
			sctx->follower.process_packet(packet);
			#ifdef DEBUG
			if (sctx->tcp_match_util.matching_has_been_called){
				cerr << "[DEBUG] [NetfilterQueue.build_verdict] StreamFollower has called matching functions" << endl;
			}else{
				cerr << "[DEBUG] [NetfilterQueue.build_verdict] StreamFollower has NOT called matching functions" << endl;
			}
			#endif
			// Do an action only is an ordered packet has been received
			if (sctx->match_info.matching_has_been_called){
				bool empty_payload = pktinfo.payload.empty();
				//In this 2 cases we have to remove all data about the stream
				if (!sctx->match_info.result || sctx->match_info.already_closed){
					#ifdef DEBUG
						cerr << "[DEBUG] [NetfilterQueue.build_verdict] Stream matched, removing all data about it" << endl;
					#endif
					sctx->clean_stream_by_id(pktinfo.sid);
					//If the packet has data, we have to remove it
					if (!empty_payload){
						Tins::PDU* data_layer = tcp->release_inner_pdu();
						if (data_layer != nullptr){
							delete data_layer;
						}
					}
					//For the first matched data or only for data packets, we set FIN bit
					//This only for client packets, because this will trigger server to close the connection
					//Packets will be filtered anyway also if client don't send packets
					if ((!sctx->match_info.result || !empty_payload) && is_input){
						tcp->set_flag(Tins::TCP::FIN,1);
						tcp->set_flag(Tins::TCP::ACK,1);
						tcp->set_flag(Tins::TCP::SYN,0);
					}
					//Send the edited packet to the kernel
					nfq_nlmsg_verdict_put_pkt(nlh_verdict, packet.serialize().data(), packet.size());
				}
			}
			nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_ACCEPT );
		}else{
			Tins::UDP* udp = packet.template find_pdu<Tins::UDP>();
			if (!udp){
				throw invalid_argument("Only TCP and UDP are supported");
			}
			Tins::PDU* application_layer = udp->inner_pdu();
			u_int16_t payload_size = 0;
			if (application_layer != nullptr){
				payload_size = application_layer->size();
			}
			if((udp->inner_pdu() == nullptr)){
				nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_ACCEPT );
			}
			packet_info pktinfo{
				payload: string(payload+plen - payload_size, payload+plen),
				sid: stream_id::make_identifier(packet),
				is_input: is_input,
				is_tcp: false,
				is_ipv6: is_ipv6,
				sctx: sctx,
				packet_pdu: &packet,
				layer4_pdu: udp,
			};
			if (filter_action(pktinfo)){
				nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_ACCEPT );
			}else{
				nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_DROP );
			}
		}
	}
	
	static int queue_cb(const nlmsghdr *nlh, const mnl_socket* nl, void *data_ptr) {
	
		stream_ctx* sctx = (stream_ctx*)data_ptr;
	
		//Extract attributes from the nlmsghdr
		nlattr *attr[NFQA_MAX+1] = {};
		
		if (nfq_nlmsg_parse(nlh, attr) < 0) {
			perror("problems parsing");
			return MNL_CB_ERROR;
		}
		if (attr[NFQA_PACKET_HDR] == nullptr) {
			fputs("metaheader not set\n", stderr);
			return MNL_CB_ERROR;
		}
		if (attr[NFQA_MARK] == nullptr) {
			fputs("mark not set\n", stderr);
			return MNL_CB_ERROR;
		}
		//Get Payload
		uint16_t plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
		uint8_t *payload = (uint8_t *)mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
		
		//Return result to the kernel
		struct nfqnl_msg_packet_hdr *ph = (nfqnl_msg_packet_hdr*) mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
		struct nfgenmsg *nfg = (nfgenmsg *)mnl_nlmsg_get_payload(nlh);
		char buf[MNL_SOCKET_BUFFER_SIZE];
		struct nlmsghdr *nlh_verdict;
	
		nlh_verdict = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, ntohs(nfg->res_id));
	
		bool is_input = ntohl(mnl_attr_get_u32(attr[NFQA_MARK])) & 0x1; // == 0x1337 that is odd
		#ifdef DEBUG
			cerr << "[DEBUG] [NetfilterQueue.queue_cb] Packet received" << endl;
			cerr << "[DEBUG] [NetfilterQueue.queue_cb] Packet ID: " << ntohl(ph->packet_id) << endl;
			cerr << "[DEBUG] [NetfilterQueue.queue_cb] Payload size: " << plen << endl;
			cerr << "[DEBUG] [NetfilterQueue.queue_cb] Is input: " << is_input << endl;
		#endif
		
		// Check IP protocol version
		if ( (payload[0] & 0xf0) == 0x40 ){
			build_verdict(Tins::IP(payload, plen), payload, plen, nlh_verdict, ph, sctx, is_input, false);
		}else{
			build_verdict(Tins::IPv6(payload, plen), payload, plen, nlh_verdict, ph, sctx, is_input, true);
		}
	
		if (mnl_socket_sendto(nl, nlh_verdict, nlh_verdict->nlmsg_len) < 0) {
			throw runtime_error( "mnl_socket_send" );
		}
	
		return MNL_CB_OK;
	}

	RegexQueue(int queue) : NfQueueExecutor(queue, &queue_cb) {}

	~RegexQueue() {
		sctx.clean();
	}

};

#endif // REGEX_FILTER_CLASS_CPP