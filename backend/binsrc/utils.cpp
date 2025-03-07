#ifndef UTILS_CPP
#define UTILS_CPP

#include <string>
#include <unistd.h>
#include <queue>
#include <condition_variable>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <cerrno>
#include <sstream>

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

class UnixClientConnection {
public:
    int sockfd = -1;
    struct sockaddr_un addr;
private:
    // Internal buffer to accumulate the output until flush
    std::ostringstream streamBuffer;
public:

    UnixClientConnection(){};

    UnixClientConnection(const char* path) {
        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sockfd == -1) {
            throw std::runtime_error(std::string("socket error: ") + std::strerror(errno));
        }
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
        if (connect(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            throw std::runtime_error(std::string("connect error: ") + std::strerror(errno));
        }
    }

    // Delete copy constructor and assignment operator to avoid resource duplication
    UnixClientConnection(const UnixClientConnection&) = delete;
    UnixClientConnection& operator=(const UnixClientConnection&) = delete;

    // Move constructor
    UnixClientConnection(UnixClientConnection&& other) noexcept 
        : sockfd(other.sockfd), addr(other.addr) {
        other.sockfd = -1;
    }

    // Move assignment operator
    UnixClientConnection& operator=(UnixClientConnection&& other) noexcept {
        if (this != &other) {
            if (sockfd != -1) {
                close(sockfd);
            }
            sockfd = other.sockfd;
            addr = other.addr;
            other.sockfd = -1;
        }
        return *this;
    }

    void send(const std::string& data) {
        if (::write(sockfd, data.c_str(), data.size()) == -1) {
            throw std::runtime_error(std::string("write error: ") + std::strerror(errno));
        }
    }

    std::string recv(size_t size) {
        std::string buffer(size, '\0');
        ssize_t bytesRead = ::read(sockfd, &buffer[0], size);
        if (bytesRead <= 0) {
            throw std::runtime_error(std::string("read error: ") + std::strerror(errno));
        }
        buffer.resize(bytesRead);  // resize to actual bytes read
        return buffer;
    }

    // Template overload for generic types
    template<typename T>
    UnixClientConnection& operator<<(const T& data) {
        streamBuffer << data;
        return *this;
    }

    // Overload for manipulators (e.g., std::endl)
    UnixClientConnection& operator<<(std::ostream& (*manip)(std::ostream&)) {
        // Check if the manipulator is std::endl (or equivalent flush)
        if (manip == static_cast<std::ostream& (*)(std::ostream&)>(std::endl)){
            streamBuffer << '\n';  // Add a newline
            std::string packet = streamBuffer.str();
            streamBuffer.str("");  // Clear the buffer
            // Send the accumulated data as one packet
            send(packet);
        }
        if (static_cast<std::ostream& (*)(std::ostream&)>(std::flush)) {
            std::string packet = streamBuffer.str();
            streamBuffer.str("");  // Clear the buffer
            // Send the accumulated data as one packet
            send(packet);
        } else {
            // For other manipulators, simply pass them to the buffer
            streamBuffer << manip;
        }
        return *this;
    }

    // Overload operator<< to allow printing connection info
    friend std::ostream& operator<<(std::ostream& os, const UnixClientConnection& conn) {
        os << "UnixClientConnection(sockfd=" << conn.sockfd 
           << ", path=" << conn.addr.sun_path << ")";
        return os;
    }

    ~UnixClientConnection() {
        if (sockfd != -1) {
            close(sockfd);
        }
    }
};


#ifdef USE_PIPES_FOR_BLOKING_QUEUE

template<typename T>
class BlockingQueue
{
private:
      int pipefd[2];
public:
   BlockingQueue(){
      if (pipe(pipefd) == -1) {
         throw std::runtime_error("pipe");
      }
   }

    void put(T new_value)
    {
        if (write(pipefd[1], &new_value, sizeof(T)) == -1) {
            throw std::runtime_error("write");
        }
    }
    void take(T& value)
    {
        if (read(pipefd[0], &value, sizeof(T)) == -1) {
            throw std::runtime_error("read");
        }
    }
};

#else

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

#endif

#endif // UTILS_CPP