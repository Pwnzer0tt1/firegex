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

using namespace std;
using namespace Tins;

typedef bool NetFilterQueueCallback(const uint8_t*,uint32_t);
typedef struct mnl_socket* NetFilterQueueSocket;

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
	NetFilterQueueSocket nl = NULL;

	NetfilterQueue(u_int16_t queue_num): queue_num(queue_num) {
		
		struct nlmsghdr *nlh;
		nl = mnl_socket_open(NETLINK_NETFILTER);
		
		if (nl == NULL) {
			throw std::runtime_error( "mnl_socket_open" );
		}

		if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
			throw std::runtime_error( "mnl_socket_bind" );
		}
		portid = mnl_socket_get_portid(nl);

		buf = (char*) malloc(BUF_SIZE);
		if (!buf) {
			throw std::runtime_error( "allocate receive buffer" );
		}

		nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
		nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

		if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
			free(buf);
			throw std::runtime_error( "mnl_socket_send" );
		}

		nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

		mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
		mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

		if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
			free(buf);
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
			ret = mnl_socket_recvfrom(nl, buf, BUF_SIZE);
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
		if (buf != NULL) {
			free(buf);
			buf = NULL;
		}
		mnl_socket_close(nl);
	}
	private:

	static int queue_cb(const struct nlmsghdr *nlh, void *data)
	{
		NetFilterQueueSocket nl = (NetFilterQueueSocket)data;
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


bool callb(const uint8_t *data, uint32_t len){
	return true;
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("Usage: %s [queue_num]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	NetfilterQueue<callb>* queue = new NetfilterQueue<callb>(atoi(argv[1]));
	queue->run();
	return 0;
}
