use std::env;

use std::collections::HashMap;

#[derive(Hash, Eq, PartialEq, Debug)]
struct ConnectionFlux {
    src_ip: String,
    src_port: i16,
    dst_ip: String,
    dst_port: i16,
}

impl ConnectionFlux{
    fn new(src_ip: &str, src_port: i16, dst_ip: &str, dst_port: i16) -> ConnectionFlux {
        ConnectionFlux { src_ip: src_ip.to_string(), src_port, dst_ip: dst_ip.to_string(), dst_port}
    }
}


fn main() {
    let str_of_threads = env::var("NTHREADS").unwrap_or("1".to_string());
    let mut n_of_threads = str_of_threads.parse::<i32>().unwrap_or(1);
    if n_of_threads <= 0 {
        n_of_threads = 1;
    }

    let _connections = HashMap::from([
        (ConnectionFlux::new("127.0.0.1", 1337, "127.0.0.1", 1337), 25),
    ]);
    
    eprintln!("[info][main] Using {} threads", n_of_threads)
   
}
/*

shared_ptr<regex_rules> regex_config;

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
		regex_rules *regex_new_config = new regex_rules();
		while(!config_stream.eof()){
			string data;
			config_stream >> data;
			if (data != "" && data != "\n"){
				regex_new_config->add(data.c_str());
			}
		}
		regex_config.reset(regex_new_config);
		cerr << "[info] [updater] Config update done" << endl;

	}
	
}

template <bool is_input>
bool filter_callback(const uint8_t *data, uint32_t len){
	shared_ptr<regex_rules> current_config = regex_config;
	return current_config->check((unsigned char *)data, len, is_input);
}

int main(int argc, char *argv[])
{
	regex_config.reset(new regex_rules());
	NFQueueSequence<filter_callback<true>> input_queues(n_of_threads/2);
	input_queues.start();
	NFQueueSequence<filter_callback<false>> output_queues(n_of_threads/2);
	output_queues.start();

	cout << "QUEUES INPUT " << input_queues.init() << " " << input_queues.end() << " OUTPUT " << output_queues.init() << " " << output_queues.end() << endl;
	cerr << "[info] [main] Input queues: " << input_queues.init() << ":" << input_queues.end() << " threads assigned: " << n_of_threads/2 << endl;
	cerr << "[info] [main] Output queues: " << output_queues.init() << ":" << output_queues.end() << " threads assigned: " << n_of_threads/2 << endl;

	config_updater();
}

#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <tins/tins.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/types.h>
#include <stdexcept>
#include <thread>

#ifndef NETFILTER_CLASSES_HPP
#define NETFILTER_CLASSES_HPP

typedef bool NetFilterQueueCallback(const uint8_t*,uint32_t);

Tins::PDU * find_transport_layer(Tins::PDU* pkt){
	while(pkt != NULL){
		if (pkt->pdu_type() == Tins::PDU::TCP || pkt->pdu_type() == Tins::PDU::UDP) {
			return pkt;
		}
		pkt = pkt->inner_pdu();
	}
	return pkt;
}

template <NetFilterQueueCallback callback_func>
class NetfilterQueue {
	public:
	size_t BUF_SIZE = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
	char *buf = NULL;
	unsigned int portid;
	u_int16_t queue_num;
	struct mnl_socket* nl = NULL;

	NetfilterQueue(u_int16_t queue_num): queue_num(queue_num) {

		nl = mnl_socket_open(NETLINK_NETFILTER);
		
		if (nl == NULL) { throw std::runtime_error( "mnl_socket_open" );}

		if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
			mnl_socket_close(nl);
			throw std::runtime_error( "mnl_socket_bind" );
		}
		portid = mnl_socket_get_portid(nl);

		buf = (char*) malloc(BUF_SIZE);

		if (!buf) {
			mnl_socket_close(nl);
			throw std::runtime_error( "allocate receive buffer" );
		}

		if (send_config_cmd(NFQNL_CFG_CMD_BIND) < 0) {
			_clear();
			throw std::runtime_error( "mnl_socket_send" );
		}
		//TEST if BIND was successful
		if (send_config_cmd(NFQNL_CFG_CMD_NONE) < 0) { // SEND A NONE cmmand to generate an error meessage
			_clear();
			throw std::runtime_error( "mnl_socket_send" );
		}
		if (recv_packet() == -1) { //RECV the error message
			_clear();
			throw std::runtime_error( "mnl_socket_recvfrom" );
		}

		struct nlmsghdr *nlh = (struct nlmsghdr *) buf;
		
		if (nlh->nlmsg_type != NLMSG_ERROR) {
			_clear();
			throw std::runtime_error( "unexpected packet from kernel (expected NLMSG_ERROR packet)" );
		}		
		//nfqnl_msg_config_cmd
		nlmsgerr* error_msg = (nlmsgerr *)mnl_nlmsg_get_payload(nlh);	

		// error code taken from the linux kernel:
		// https://elixir.bootlin.com/linux/v5.18.12/source/include/linux/errno.h#L27
		#define ENOTSUPP	524	/* Operation is not supported */

		if (error_msg->error != -ENOTSUPP) {
			_clear();
			throw std::invalid_argument( "queueid is already busy" );
		}
		
		//END TESTING BIND
		nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);
		

		mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
		mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

		if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
			_clear();
			throw std::runtime_error( "mnl_socket_send" );
		}

	}



	void run(){
		/*
		* ENOBUFS is signalled to userspace when packets were lost
		* on kernel side.  In most cases, userspace isn't interested
		* in this information, so turn it off.
		*/
		int ret = 1;
		mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

		for (;;) {
			ret = recv_packet();
			if (ret == -1) {
				throw std::runtime_error( "mnl_socket_recvfrom" );
			}

			ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, nl);
			if (ret < 0){
				throw std::runtime_error( "mnl_cb_run" );
			}
		}
	}
	
	~NetfilterQueue() {
		send_config_cmd(NFQNL_CFG_CMD_UNBIND);
		_clear();
	}
	private:

	ssize_t send_config_cmd(nfqnl_msg_config_cmds cmd){
		struct nlmsghdr *nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
		nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, cmd);
		return mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
	}

	ssize_t recv_packet(){
		return mnl_socket_recvfrom(nl, buf, BUF_SIZE);
	}	

	void _clear(){
		if (buf != NULL) {
			free(buf);
			buf = NULL;
		}
		mnl_socket_close(nl);
	}

	static int queue_cb(const struct nlmsghdr *nlh, void *data)
	{
		struct mnl_socket* nl = (struct mnl_socket*)data;
		//Extract attributes from the nlmsghdr
		struct nlattr *attr[NFQA_MAX+1] = {};
		
		if (nfq_nlmsg_parse(nlh, attr) < 0) {
			perror("problems parsing");
			return MNL_CB_ERROR;
		}
		if (attr[NFQA_PACKET_HDR] == NULL) {
			fputs("metaheader not set\n", stderr);
			return MNL_CB_ERROR;
		}	
		//Get Payload
		uint16_t plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
		void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
		
		//Return result to the kernel
		struct nfqnl_msg_packet_hdr *ph = (nfqnl_msg_packet_hdr*) mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
		struct nfgenmsg *nfg = (nfgenmsg *)mnl_nlmsg_get_payload(nlh);
		char buf[MNL_SOCKET_BUFFER_SIZE];
		struct nlmsghdr *nlh_verdict;
		struct nlattr *nest;

		nlh_verdict = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, ntohs(nfg->res_id));

		/*
			This define allow to avoid to allocate new heap memory for each packet.
			The code under this comment is replicated for ipv6 and ip
			Better solutions are welcome. :)
		*/
		#define PKT_HANDLE 																						\
		Tins::PDU *transport_layer = find_transport_layer(&packet); 											\
		if(transport_layer->inner_pdu() == nullptr || transport_layer == nullptr){ 								\
			nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_ACCEPT );								\
		}else{																									\
			int size = transport_layer->inner_pdu()->size();													\
			if(callback_func((const uint8_t*)payload+plen - size, size)){										\
				nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_ACCEPT );							\
			} else{																								\
				if (transport_layer->pdu_type() == Tins::PDU::TCP){												\
					((Tins::TCP *)transport_layer)->release_inner_pdu();										\
					((Tins::TCP *)transport_layer)->set_flag(Tins::TCP::FIN,1);									\
					((Tins::TCP *)transport_layer)->set_flag(Tins::TCP::ACK,1);									\
					((Tins::TCP *)transport_layer)->set_flag(Tins::TCP::SYN,0);									\
					nfq_nlmsg_verdict_put_pkt(nlh_verdict, packet.serialize().data(), packet.size());			\
					nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_ACCEPT );						\
				}else{																							\
					nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_DROP );							\
				}																								\
			}																									\
		}

		// Check IP protocol version
		if ( (((uint8_t*)payload)[0] & 0xf0) == 0x40 ){
			Tins::IP packet = Tins::IP((uint8_t*)payload,plen);
			PKT_HANDLE
		}else{
			Tins::IPv6 packet = Tins::IPv6((uint8_t*)payload,plen);
			PKT_HANDLE
		}	

		/* example to set the connmark. First, start NFQA_CT section: */
		nest = mnl_attr_nest_start(nlh_verdict, NFQA_CT);

		/* then, add the connmark attribute: */
		mnl_attr_put_u32(nlh_verdict, CTA_MARK, htonl(42));
		/* more conntrack attributes, e.g. CTA_LABELS could be set here */

		/* end conntrack section */
		mnl_attr_nest_end(nlh_verdict, nest);

		if (mnl_socket_sendto(nl, nlh_verdict, nlh_verdict->nlmsg_len) < 0) {
			throw std::runtime_error( "mnl_socket_send" );
		}

		return MNL_CB_OK;
	}

};

template <NetFilterQueueCallback func>
class NFQueueSequence{
	private:
		std::vector<NetfilterQueue<func> *> nfq;
		uint16_t _init;
		uint16_t _end;
		std::vector<std::thread> threads;
	public:
		static const int QUEUE_BASE_NUM = 1000;

		NFQueueSequence(uint16_t seq_len){
			if (seq_len <= 0) throw std::invalid_argument("seq_len <= 0");
			nfq = std::vector<NetfilterQueue<func>*>(seq_len);
			_init = QUEUE_BASE_NUM;
			while(nfq[0] == NULL){
				if (_init+seq_len-1 >= 65536){
					throw std::runtime_error("NFQueueSequence: too many queues!");
				}
				for (int i=0;i<seq_len;i++){
					try{
						nfq[i] = new NetfilterQueue<func>(_init+i);
					}catch(const std::invalid_argument e){
						for(int j = 0; j < i; j++) {
							delete nfq[j];
							nfq[j] = nullptr;
						}
						_init += seq_len - i;
						break;
					}
				}
			}
			_end = _init + seq_len - 1;
		}
		
		void start(){
			if (threads.size() != 0) throw std::runtime_error("NFQueueSequence: already started!");
			for (int i=0;i<nfq.size();i++){
				threads.push_back(std::thread(&NetfilterQueue<func>::run, nfq[i]));
			}
		}

		void join(){
			for (int i=0;i<nfq.size();i++){
				threads[i].join();
			}
			threads.clear();
		}

		uint16_t init(){
			return _init;
		}
		uint16_t end(){
			return _end;
		}
		
		~NFQueueSequence(){
			for (int i=0;i<nfq.size();i++){
				delete nfq[i];
			}
		}
};

#endif // NETFILTER_CLASSES_HPP
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

#include <string>
#include <unistd.h>

#ifndef UTILS_HPP
#define UTILS_HPP

bool unhexlify(std::string const &hex, std::string &newString) {
   try{
      int len = hex.length();
      for(int i=0; i< len; i+=2)
      {
         std::string byte = hex.substr(i,2);
         char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
         newString.push_back(chr);
      }
      return true;
   }
   catch (...){
      return false;
   }
}

#endif
*/