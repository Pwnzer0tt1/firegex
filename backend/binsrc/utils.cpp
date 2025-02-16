#include <string>
#include <unistd.h>
#include <queue>
#include <condition_variable>

#ifndef UTILS_CPP
#define UTILS_CPP

bool unhexlify(std::string const &hex, std::string &newString) {
   try{
      int len = hex.length();
      for(int i=0; i< len; i+=2)
      {
         std::string byte = hex.substr(i,2);
         char chr = (char) (int)strtol(byte.c_str(), nullptr, 16);
         newString.push_back(chr);
      }
      return true;
   }
   catch (...){
      return false;
   }
}

template<typename T, int MAX = 1024> //same of kernel nfqueue max
class BlockingQueue
{
private:
    std::mutex mut;
    std::queue<T> private_std_queue;
    std::condition_variable condNotEmpty;
    std::condition_variable condNotFull;
    size_t count; // Guard with Mutex
public:
    void put(T new_value)
    {
      
        std::unique_lock<std::mutex> lk(mut);
        //Condition takes a unique_lock and waits given the false condition
        condNotFull.wait(lk,[this]{
            if (count == MAX) {
               return false;
            }else{
               return true;
            }
            
        });
        private_std_queue.push(new_value);
        count++;
        condNotEmpty.notify_one();
    }
    void take(T& value)
    {
        std::unique_lock<std::mutex> lk(mut);
         //Condition takes a unique_lock and waits given the false condition
        condNotEmpty.wait(lk,[this]{return !private_std_queue.empty();});
        value=private_std_queue.front();
        private_std_queue.pop();
        count--;
        condNotFull.notify_one();
    }
};

#endif // UTILS_CPP