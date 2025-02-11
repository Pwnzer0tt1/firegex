#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/types.h>
#include <stdexcept>
#include <thread>
#include <iostream>

using namespace std;

#ifndef NETFILTER_CLASS_CPP
#define NETFILTER_CLASS_CPP

typedef int QueueCallbackFunction(const nlmsghdr *, const mnl_socket*, void *);

struct nfqueue_execution_data_tmp{
    mnl_socket* nl = nullptr;
    function<QueueCallbackFunction> queue_cb = nullptr;
    void *data = nullptr;
};

class NfQueueExecutor {
    private:
    size_t BUF_SIZE = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
    char *queue_msg_buffer = nullptr;
   	QueueCallbackFunction * _queue_callback_hook = nullptr;
    public:

    unsigned int portid;
    u_int16_t queue_num;
    mnl_socket* nl = nullptr;

	NfQueueExecutor(u_int16_t queue_num, QueueCallbackFunction* queue_cb): queue_num(queue_num), _queue_callback_hook(queue_cb){
		nl = mnl_socket_open(NETLINK_NETFILTER);
		
		if (nl == nullptr) { throw runtime_error( "mnl_socket_open" );}

		if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
			mnl_socket_close(nl);
			throw runtime_error( "mnl_socket_bind" );
		}
		portid = mnl_socket_get_portid(nl);

		queue_msg_buffer = (char*) malloc(BUF_SIZE);

		if (!queue_msg_buffer) {
			mnl_socket_close(nl);
			throw runtime_error( "allocate receive buffer" );
		}

		if (_send_config_cmd(NFQNL_CFG_CMD_BIND) < 0) {
			_clear();
			throw runtime_error( "mnl_socket_send" );
		}
		//TEST if BIND was successful
		if (_send_config_cmd(NFQNL_CFG_CMD_NONE) < 0) { // SEND A NONE cmmand to generate an error meessage
			_clear();
			throw runtime_error( "mnl_socket_send" );
		}
		if (_recv_packet() == -1) { //RECV the error message
			_clear();
			throw runtime_error( "mnl_socket_recvfrom" );
		}

		struct nlmsghdr *nlh = (struct nlmsghdr *) queue_msg_buffer;
		
		if (nlh->nlmsg_type != NLMSG_ERROR) {
			_clear();
			throw runtime_error( "unexpected packet from kernel (expected NLMSG_ERROR packet)" );
		}		
		//nfqnl_msg_config_cmd
		nlmsgerr* error_msg = (nlmsgerr *)mnl_nlmsg_get_payload(nlh);	

		// error code taken from the linux kernel:
		// https://elixir.bootlin.com/linux/v5.18.12/source/include/linux/errno.h#L27
		#define ENOTSUPP	524	/* Operation is not supported */

		if (error_msg->error != -ENOTSUPP) {
			_clear();
			throw invalid_argument( "queueid is already busy" );
		}
		
		//END TESTING BIND
		nlh = nfq_nlmsg_put(queue_msg_buffer, NFQNL_MSG_CONFIG, queue_num);
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

		mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
		mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

		if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
			_clear();
			throw runtime_error( "mnl_socket_send" );
		}

	}

    NfQueueExecutor(u_int16_t queue_num): NfQueueExecutor(queue_num, nullptr) {}

    // --- Functions to be implemented by the user

    virtual void before_loop() {
        // Do nothing by default
    }

    virtual void * callback_data_fetch(){
        return nullptr;
    }

    // --- End of functions to be implemented by the user

	void run(){
		/*
		* ENOBUFS is signalled to userspace when packets were lost
		* on kernel side.  In most cases, userspace isn't interested
		* in this information, so turn it off.
		*/
		int ret = 1;
		mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));
		
        before_loop();

		for (;;) {
			ret = _recv_packet();
			if (ret == -1) {
				throw runtime_error( "mnl_socket_recvfrom" );
			}
			nfqueue_execution_data_tmp data = {
                nl: nl,
                queue_cb: _queue_callback_hook,
                data: callback_data_fetch()
            };
			ret = mnl_cb_run(queue_msg_buffer, ret, 0, portid, _real_queue_cb, &data);
			if (ret < 0){
				throw runtime_error( "mnl_cb_run" );
			}
		}
	}
	
	
	~NfQueueExecutor() {
		_send_config_cmd(NFQNL_CFG_CMD_UNBIND);
		_clear();
	}
    
    private:

    static int _real_queue_cb(const nlmsghdr *nlh, void *data_ptr) {
        nfqueue_execution_data_tmp* info = (nfqueue_execution_data_tmp*) data_ptr;
        if (info->queue_cb == nullptr) return MNL_CB_OK;
        return info->queue_cb(nlh, info->nl, info->data);
    }

	inline void _clear(){
		if (queue_msg_buffer != nullptr) {
			free(queue_msg_buffer);
			queue_msg_buffer = nullptr;
		}
		mnl_socket_close(nl);
		nl = nullptr;
	}

    inline ssize_t _send_config_cmd(nfqnl_msg_config_cmds cmd){
		struct nlmsghdr *nlh = nfq_nlmsg_put(queue_msg_buffer, NFQNL_MSG_CONFIG, queue_num);
		nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, cmd);
		return mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
	}

	inline ssize_t _recv_packet(){
		return mnl_socket_recvfrom(nl, queue_msg_buffer, BUF_SIZE);
	}	

};


template <typename Executor, typename = enable_if_t<is_base_of_v<NfQueueExecutor, Executor>>>
class NFQueueSequence{

	private:
		vector<Executor *> nfq;
		uint16_t _init;
		uint16_t _end;
		vector<thread> threads;
	public:
		static const int QUEUE_BASE_NUM = 1000;

		NFQueueSequence(uint16_t seq_len){
			if (seq_len <= 0) throw invalid_argument("seq_len <= 0");
			nfq = vector<Executor*>(seq_len);
			_init = QUEUE_BASE_NUM;
			while(nfq[0] == nullptr){
				if (_init+seq_len-1 >= 65536){
					throw runtime_error("NFQueueSequence: too many queues!");
				}
				for (int i=0;i<seq_len;i++){
					try{
						nfq[i] = new Executor(_init+i);
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
				threads.push_back(thread([executor = nfq[i]](){
                    executor->run();
                }));
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

#endif // NETFILTER_CLASS_CPP