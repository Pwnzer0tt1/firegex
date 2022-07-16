#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <type_traits>
#include <tins/tins.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <stdexcept>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <sstream>
#include <thread>
#include <mutex>
#include <jpcre2.hpp>


using namespace std;
using namespace Tins;
typedef jpcre2::select<char> jp;
mutex stdout_mutex;


bool unhexlify(string const &hex, string &newString) {
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


typedef pair<string,jp::Regex> regex_rule_pair;
typedef vector<regex_rule_pair> regex_rule_vector;
struct regex_rules{
   regex_rule_vector regex_s_c_w, regex_c_s_w, regex_s_c_b, regex_c_s_b;

   regex_rule_vector* getByCode(char code){
      switch(code){
         case 'C': // Client to server Blacklist
            return &regex_c_s_b;  break;
         case 'c': // Client to server Whitelist
            return &regex_c_s_w;  break;
         case 'S': // Server to client Blacklist
            return &regex_s_c_b;  break;
         case 's': // Server to client Whitelist
            return &regex_s_c_w;  break;
      }
      throw invalid_argument( "Expected 'C' 'c' 'S' or 's'" );
   }

   int add(const char* arg){
		//Integrity checks
		size_t arg_len = strlen(arg);
		if (arg_len < 2 || arg_len%2 != 0){
			cerr << "[warning] [regex_rules.add] invalid arg passed (" << arg << "), skipping..." << endl;
			return -1;
		}
		if (arg[0] != '0' && arg[0] != '1'){
			cerr << "[warning] [regex_rules.add] invalid is_case_sensitive (" << arg[0] << ") in '" << arg << "', must be '1' or '0', skipping..." << endl;
			return -1;
		}
		if (arg[1] != 'C' && arg[1] != 'c' && arg[1] != 'S' && arg[1] != 's'){
			cerr << "[warning] [regex_rules.add] invalid filter_type (" << arg[1] << ") in '" << arg << "', must be 'C', 'c', 'S' or 's', skipping..." << endl;
			return -1;
		}
		string hex(arg+2), expr;
		if (!unhexlify(hex, expr)){
			cerr << "[warning] [regex_rules.add] invalid hex regex value (" << hex << "), skipping..." << endl;
			return -1;
		}
		//Push regex
		jp::Regex regex(expr,arg[0] == '1'?"gS":"giS");
		if (regex){
			cerr << "[info] [regex_rules.add] adding new regex filter: '" << expr << "'" << endl;			
			getByCode(arg[1])->push_back(make_pair(string(arg), regex));
		} else {
			cerr << "[warning] [regex_rules.add] compiling of '" << expr << "' regex failed, skipping..." << endl;
			return -1;
		}
		return 0;
	}

};

bool check(unsigned char* data, const size_t& bytes_transferred, const bool in_input, regex_rules* rules){
	string str_data((char *) data, bytes_transferred);
	for (regex_rule_pair ele:in_input?rules->regex_c_s_b:rules->regex_s_c_b){
		try{
			if(ele.second.match(str_data)){
				unique_lock<mutex> lck(stdout_mutex);
				cout << "BLOCKED " << ele.first << endl;
				return false;
			}
		} catch(...){
			cerr << "[info] [regex_rules.check] Error while matching blacklist regex: " << ele.first << endl;
		}
	}
	for (regex_rule_pair ele:in_input?rules->regex_c_s_w:rules->regex_s_c_w){
		try{
			if(!ele.second.match(str_data)){
				unique_lock<mutex> lck(stdout_mutex);
				cout << "BLOCKED " << ele.first << endl;
				return false;
			}
		} catch(...){
			cerr << "[info] [regex_rules.check] Error while matching whitelist regex: " << ele.first << endl;
		}      
	}
	return true;
}

shared_ptr<regex_rules> regex_config;

typedef bool NetFilterQueueCallback(const uint8_t*,uint32_t);

PDU * find_transport_layer(PDU* pkt){
	while(pkt != NULL){
		if (pkt->pdu_type() == PDU::TCP || pkt->pdu_type() == PDU::UDP) {
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
		
		struct nlmsghdr *nlh;
		nl = mnl_socket_open(NETLINK_NETFILTER);
		
		if (nl == NULL) { throw runtime_error( "mnl_socket_open" );}

		if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
			mnl_socket_close(nl);
			throw runtime_error( "mnl_socket_bind" );
		}
		portid = mnl_socket_get_portid(nl);

		buf = (char*) malloc(BUF_SIZE);
		if (!buf) {
			mnl_socket_close(nl);
			throw runtime_error( "allocate receive buffer" );
		}

		if (send_config_cmd(NFQNL_CFG_CMD_BIND) < 0) {
			_clear();
			throw runtime_error( "mnl_socket_send" );
		}

//TESTING QUEUE: TODO find a legal system to test if the queue was binded successfully
		if (send_config_cmd(NFQNL_CFG_CMD_NONE) < 0) {
			_clear();
			throw runtime_error( "mnl_socket_send" );
		}
		if (recv_packet() == -1) {
			_clear();
			throw std::runtime_error( "mnl_socket_recvfrom" );
		}
		/*
		I checked that if this byte (that is the only one that changes) is set to 1,
		this message is the NFQNL_CFG_CMD_BIND error, instead
		if it is set to 0, this message is the error generated by NFQNL_CFG_CMD_NONE
		So NFQNL_CFG_CMD_BIND doesn't sended any error and it's all ok.
		*/
		if (nlh->nlmsg_len < 45 && buf[44] == 1){
			_clear();
			throw std::invalid_argument( "queueid is already busy" );
		}
//END TESTING QUEUE
		nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);
		

		mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
		mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

		if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
			_clear();
			throw runtime_error( "mnl_socket_send" );
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
		PDU *transport_layer = find_transport_layer(&packet); 													\
		if(transport_layer->inner_pdu() == nullptr || transport_layer == nullptr){ 								\
			nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_ACCEPT );								\
		}else{																									\
			int size = transport_layer->inner_pdu()->size();													\
			if(callback_func((const uint8_t*)payload+plen - size, size)){										\
				nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_ACCEPT );							\
			} else{																								\
				if (transport_layer->pdu_type() == PDU::TCP){													\
					((TCP *)transport_layer)->release_inner_pdu();												\
					((TCP *)transport_layer)->set_flag(TCP::FIN,1);												\
					((TCP *)transport_layer)->set_flag(TCP::ACK,1);												\
					((TCP *)transport_layer)->set_flag(TCP::SYN,0);												\
					nfq_nlmsg_verdict_put_pkt(nlh_verdict, packet.serialize().data(), packet.size());			\
					nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_ACCEPT );						\
				}else{																							\
					nfq_nlmsg_verdict_put(nlh_verdict, ntohl(ph->packet_id), NF_DROP );							\
				}																								\
			}																									\
		}

		// Check IP protocol version
		if ( (((uint8_t*)payload)[0] & 0xf0) == 0x40 ){
			IP packet = IP((uint8_t*)payload,plen);
			PKT_HANDLE
		}else{
			IPv6 packet = IPv6((uint8_t*)payload,plen);
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


bool is_sudo(){
	return getuid() == 0;
}

void config_updater (){
	string line, data;
	while (true){
		getline(cin, line);
		if (cin.bad()){
			cerr << "[fatal] [upfdater] cin.bad() != 0" << endl;
			exit(EXIT_FAILURE);
		}
		cerr << "[info] [updater] Updating configuration with line " << line << endl;
		istringstream config_stream(line);
		regex_rules *regex_new_config = new regex_rules();
		while(!config_stream.eof()){
			config_stream >> data;
			regex_new_config->add(data.c_str());
		}
		regex_config.reset(regex_new_config);
		cerr << "[info] [updater] Config update done" << endl;

	}
	
}

template <NetFilterQueueCallback func>
class NFQueueSequence{
	private:
		vector<NetfilterQueue<func> *> nfq;
		uint16_t _init;
		uint16_t _end;
		vector<thread> threads;
	public:
		static const int QUEUE_BASE_NUM = 1000;

		NFQueueSequence(uint16_t seq_len){
			if (seq_len <= 0) throw invalid_argument("seq_len <= 0");
			nfq = vector<NetfilterQueue<func>*>(seq_len);
			_init = QUEUE_BASE_NUM;
			while(nfq[0] == NULL){
				if (_init+seq_len-1 >= 65536){
					throw runtime_error("NFQueueSequence: too many queues!");
				}
				for (int i=0;i<seq_len;i++){
					try{
						nfq[i] = new NetfilterQueue<func>(_init+i);
					}catch(const invalid_argument e){
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
			if (threads.size() != 0) throw runtime_error("NFQueueSequence: already started!");
			for (int i=0;i<nfq.size();i++){
				threads.push_back(thread(&NetfilterQueue<func>::run, nfq[i]));
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

template <bool is_input>
bool filter_callback(const uint8_t *data, uint32_t len){
	shared_ptr<regex_rules> current_config = regex_config;
	return check((unsigned char *)data, len, is_input, current_config.get());
}

int main(int argc, char *argv[])
{
	if(!is_sudo()){
		cerr << "[fatal] [main] You must be root to run this program" << endl;
		exit(EXIT_FAILURE);
	}
	int n_of_queue = 1;
	if (argc >= 2) n_of_queue = atoi(argv[1]);
	regex_config.reset(new regex_rules());
	NFQueueSequence<filter_callback<true>> input_queues(n_of_queue);
	input_queues.start();
	NFQueueSequence<filter_callback<false>> output_queues(n_of_queue);
	output_queues.start();

	cout << "QUEUES INPUT " << input_queues.init() << " " << input_queues.end() << " OUTPUT " << output_queues.init() << " " << output_queues.end() << endl;

	config_updater();
}


/*

libpcre2-dev
libnetfilter-queue-dev
libtins-dev
libmnl-dev

c++ nfqueue.cpp -o nfqueue -pthread -lpcre2-8 -ltins -lnetfilter_queue -lmnl

WORKDIR /tmp/
RUN git clone --branch release https://github.com/jpcre2/jpcre2
WORKDIR /tmp/jpcre2
RUN ./configure; make; make install
WORKDIR /

//NFQNL_CFG_CMD_UNBIND ???

*/