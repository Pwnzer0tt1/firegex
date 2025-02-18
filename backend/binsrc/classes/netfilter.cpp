#include <vector>
#include <thread>
#include <type_traits>
#include "../utils.cpp"
#include "nfqueue.cpp"

#ifndef NETFILTER_CLASS_CPP
#define NETFILTER_CLASS_CPP

namespace Firegex {
namespace NfQueue {

template <typename Derived>
class ThreadNfQueue {
public:
    ThreadNfQueue() = default;
    virtual ~ThreadNfQueue() = default;

    std::thread thr;
    BlockingQueue<PktRequest<Derived>*> queue;

    virtual void before_loop() {}
	virtual void handle_next_packet(PktRequest<Derived>* pkt){}
    
    void loop() {
        static_cast<Derived*>(this)->before_loop();
        PktRequest<Derived>* pkt;
        for(;;) {
            queue.take(pkt);
            static_cast<Derived*>(this)->handle_next_packet(pkt);
            delete pkt;
        }
    }

    void run_thread_loop() {
        thr = std::thread([this]() { this->loop(); });
    }
};

template <typename Worker, typename = is_base_of<ThreadNfQueue<Worker>, Worker>>
void __real_handler(PktRequest<std::vector<Worker>>* pkt) {
    const size_t idx = hash_stream_id(pkt->sid) % pkt->ctx->size();

    auto* converted_pkt = reinterpret_cast<PktRequest<Worker>*>(pkt);
    converted_pkt->ctx = &((*pkt->ctx)[idx]);
    
    converted_pkt->ctx->queue.put(converted_pkt);
}


template <typename Worker, typename = is_base_of<ThreadNfQueue<Worker>, Worker>>
class MultiThreadQueue {
    static_assert(std::is_base_of_v<ThreadNfQueue<Worker>, Worker>,
        "Worker must inherit from ThreadNfQueue<Worker>");

private:
    std::vector<Worker> workers;
    NfQueue<std::vector<Worker>, __real_handler<Worker>> * nfq;
    uint16_t queue_num_;
	
    
public:
    const size_t n_threads;
    static constexpr int QUEUE_BASE_NUM = 1000;

    explicit MultiThreadQueue(size_t n_threads) 
        : n_threads(n_threads), workers(n_threads) 
    {
        if(n_threads == 0) throw std::invalid_argument("At least 1 thread required");
        
        for(uint16_t qnum = QUEUE_BASE_NUM; ; qnum++) {
            try {
                nfq = new NfQueue<std::vector<Worker>, __real_handler<Worker>>(qnum);
                queue_num_ = qnum;
                break;
            }
            catch(const std::invalid_argument&) {
                if(qnum == std::numeric_limits<uint16_t>::max())
                    throw std::runtime_error("No available queue numbers");
            }
        }
    }

    ~MultiThreadQueue() {
        delete nfq;
    }

    void start() {
        for(auto& worker : workers) {
            worker.run_thread_loop();
        }
		for (;;){
        	nfq->handle_next_packet(&workers);
		}
    }

    uint16_t queue_num() const { return queue_num_; }
};

}} // namespace Firegex::NfQueue
#endif // NETFILTER_CLASS_CPP