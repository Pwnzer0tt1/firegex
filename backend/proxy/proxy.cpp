#include <cstdlib>
#include <cstddef>
#include <iostream>
#include <string>
#include <csignal>
#include <fstream>
#include <unistd.h>

#include <boost/regex.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/thread/mutex.hpp>
#include <map>

#include <cctype> // is*

using namespace std;

#define DEBUG

int to_int(int c) {
  if (not isxdigit(c)) return -1; // error: non-hexadecimal digit found
  if (isdigit(c)) return c - '0';
  if (isupper(c)) c = tolower(c);
  return c - 'a' + 10;
}

template<class InputIterator, class OutputIterator> int
unhexlify(InputIterator first, InputIterator last, OutputIterator ascii) {
  while (first != last) {
    int top = to_int(*first++);
    int bot = to_int(*first++);
    if (top == -1 or bot == -1)
      return -1; // error
    *ascii++ = (top << 4) + bot;
  }
  return 0;
}

namespace tcp_proxy{
   class acceptor;
};


struct regex_filter_table{
   vector<pair<string,boost::regex>>
      regex_s_c_w, regex_c_s_w, regex_s_c_b, regex_c_s_b;
};
struct regex_proxy{
   string config_file;
   tcp_proxy::acceptor *acceptor;
   int* status_code;
   regex_filter_table filter_tab;
   void (*incrementCallback)(const char *) = nullptr;
};
map<pid_t, regex_proxy*> proxy_map;

auto firewall(){
   return proxy_map[gettid()];
}

void push_regex(char* arg, bool case_sensitive, vector<pair<string,boost::regex>> &v){
   size_t expr_len = (strlen(arg)-2)/2;
   char expr[expr_len];
   unhexlify(arg+2, arg+strlen(arg)-1, expr);
   if (case_sensitive){
      boost::regex regex(reinterpret_cast<char*>(expr),
      reinterpret_cast<char*>(expr) + expr_len);
      #ifdef DEBUG
      cout << "Added case sensitive regex " << expr << endl;
      #endif
      v.push_back(make_pair(string(arg), regex));
   } else {
      boost::regex regex(reinterpret_cast<char*>(expr),
      reinterpret_cast<char*>(expr) + expr_len, boost::regex::icase);
      #ifdef DEBUG
      cout << "Added case insensitive regex " << expr << endl;
      #endif
      v.push_back(make_pair(string(arg), regex));
   }
}

void update_regex(){
   fstream fd;
   fd.open(firewall()->config_file,ios::in); 
   if (!fd.is_open()){
      std::cerr << "Error: config file couln't be opened" << std::endl;
      *(firewall()->status_code) = 2;
      return;
   }

   firewall()->filter_tab.regex_s_c_w.clear();
   firewall()->filter_tab.regex_c_s_w.clear();
   firewall()->filter_tab.regex_s_c_b.clear();
   firewall()->filter_tab.regex_c_s_b.clear();

   string line;
   while(getline(fd, line)){
      char tp[line.length() +1];
      strcpy(tp, line.c_str());

      if (strlen(tp) >= 2){
         bool case_sensitive = true;
         if(tp[0] == '0'){
            case_sensitive = false;
         }
         switch(tp[1]){
            case 'C': { // Client to server Blacklist
               push_regex(tp, case_sensitive, firewall()->filter_tab.regex_c_s_b);
               break;
            }
            case 'c': { // Client to server Whitelist
               push_regex(tp, case_sensitive, firewall()->filter_tab.regex_c_s_w);
               break;
            }
            case 'S': { // Server to client Blacklist
               push_regex(tp, case_sensitive, firewall()->filter_tab.regex_s_c_b);
               break;
            }
            case 's': { // Server to client Whitelist
               push_regex(tp, case_sensitive, firewall()->filter_tab.regex_s_c_w);
               break;
            }
         }
      }
   }
}

bool filter_data(unsigned char* data, const size_t& bytes_transferred, vector<pair<string,boost::regex>> const &blacklist, vector<pair<string,boost::regex>> const &whitelist){
   #ifdef DEBUG
   cout << "---------------- Packet ----------------" << endl;
   for(int i=0;i<bytes_transferred;i++){
      cout << data[i];
   }
   cout << "\n" << "---------------- End Packet ----------------" << endl;
   #endif
   for (pair<string,boost::regex> ele:blacklist){
      boost::cmatch what;
      if (boost::regex_match(reinterpret_cast<const char*>(data),
            reinterpret_cast<const char*>(data) + bytes_transferred, what, ele.second)){
         if (firewall()->incrementCallback != nullptr) firewall()->incrementCallback(ele.first.c_str());
         return false;
      }
   }
   for (pair<string,boost::regex> ele:whitelist){
      boost::cmatch what;
      if (!boost::regex_match(reinterpret_cast<const char*>(data),
            reinterpret_cast<const char*>(data) + bytes_transferred, what, ele.second)){
         if (firewall()->incrementCallback != nullptr) firewall()->incrementCallback(ele.first.c_str());
         return false;
      }
   }
   #ifdef DEBUG
   cout << "Packet Accepted!" << endl;
   #endif
   return true;
}

namespace tcp_proxy
{
   namespace ip = boost::asio::ip;

   typedef ip::tcp::socket socket_type;
   class bridge : public boost::enable_shared_from_this<bridge>
   {
   public:
      bridge(boost::asio::io_service& ios)
      : downstream_socket_(ios),
        upstream_socket_  (ios)
      {}

      socket_type& downstream_socket()
      {
         return downstream_socket_;
      }

      socket_type& upstream_socket()
      {
         return upstream_socket_;
      }

      void start(const std::string& upstream_host, unsigned short upstream_port)
      {
         // Attempt connection to remote server (upstream side)
         upstream_socket_.async_connect(
              ip::tcp::endpoint(
                   boost::asio::ip::address::from_string(upstream_host),
                   upstream_port),
               boost::bind(&bridge::handle_upstream_connect,
                    shared_from_this(),
                    boost::asio::placeholders::error));
      }

      void handle_upstream_connect(const boost::system::error_code& error)
      {
         if (!error)
         {
            // Setup async read from remote server (upstream)
            upstream_socket_.async_read_some(
                 boost::asio::buffer(upstream_data_,max_data_length),
                 boost::bind(&bridge::handle_upstream_read,
                      shared_from_this(),
                      boost::asio::placeholders::error,
                      boost::asio::placeholders::bytes_transferred));

            // Setup async read from client (downstream)
            downstream_socket_.async_read_some(
                 boost::asio::buffer(downstream_data_,max_data_length),
                 boost::bind(&bridge::handle_downstream_read,
                      shared_from_this(),
                      boost::asio::placeholders::error,
                      boost::asio::placeholders::bytes_transferred));
         }
         else
            close();
      }

      /*
         Section A: Remote Server --> Proxy --> Client
         Process data recieved from remote sever then send to client.
      */

      // Read from remote server complete, now send data to client
      void handle_upstream_read(const boost::system::error_code& error,
                                const size_t& bytes_transferred) // Da Server a Client
      {
         if (!error)
         {
            if (filter_data(upstream_data_, bytes_transferred, firewall()->filter_tab.regex_s_c_b, firewall()->filter_tab.regex_s_c_w)){
               async_write(downstream_socket_,
                  boost::asio::buffer(upstream_data_,bytes_transferred),
                  boost::bind(&bridge::handle_downstream_write,
                        shared_from_this(),
                        boost::asio::placeholders::error));
            }else{
               close();
            }
         }
         else
            close();
      }

      // Write to client complete, Async read from remote server
      void handle_downstream_write(const boost::system::error_code& error)
      {
         if (!error)
         {
            upstream_socket_.async_read_some(
                 boost::asio::buffer(upstream_data_,max_data_length),
                 boost::bind(&bridge::handle_upstream_read,
                      shared_from_this(),
                      boost::asio::placeholders::error,
                      boost::asio::placeholders::bytes_transferred));
         }
         else
            close();
      }
      // *** End Of Section A ***


      /*
         Section B: Client --> Proxy --> Remove Server
         Process data recieved from client then write to remove server.
      */

      // Read from client complete, now send data to remote server
      void handle_downstream_read(const boost::system::error_code& error,
                                  const size_t& bytes_transferred) // Da Client a Server
      {
         if (!error)
         {
            if (filter_data(downstream_data_, bytes_transferred, firewall()->filter_tab.regex_c_s_b, firewall()->filter_tab.regex_c_s_w)){
               async_write(upstream_socket_,
                  boost::asio::buffer(downstream_data_,bytes_transferred),
                  boost::bind(&bridge::handle_upstream_write,
                        shared_from_this(),
                        boost::asio::placeholders::error));
            }else{
               close();
            }
         }
         else
            close();
      }

      // Write to remote server complete, Async read from client
      void handle_upstream_write(const boost::system::error_code& error)
      {
         if (!error)
         {
            downstream_socket_.async_read_some(
                 boost::asio::buffer(downstream_data_,max_data_length),
                 boost::bind(&bridge::handle_downstream_read,
                      shared_from_this(),
                      boost::asio::placeholders::error,
                      boost::asio::placeholders::bytes_transferred));
         }
         else
            close();
      }
      // *** End Of Section B ***

      void close()
      {
         boost::mutex::scoped_lock lock(mutex_);

         if (downstream_socket_.is_open())
         {
            downstream_socket_.close();
         }

         if (upstream_socket_.is_open())
         {
            upstream_socket_.close();
         }
      }

      socket_type downstream_socket_;
      socket_type upstream_socket_;

      enum { max_data_length = 8192 }; //8KB
      unsigned char downstream_data_[max_data_length];
      unsigned char upstream_data_  [max_data_length];
      boost::mutex mutex_;

      };

   class acceptor
   {
   public:

      acceptor(boost::asio::io_service& io_service,
               const std::string& local_host, unsigned short local_port,
               const std::string& upstream_host, unsigned short upstream_port)
      : io_service_(io_service),
         localhost_address(boost::asio::ip::address_v4::from_string(local_host)),
         acceptor_(io_service_,ip::tcp::endpoint(localhost_address,local_port)),
         upstream_port_(upstream_port),
         upstream_host_(upstream_host)
      {

         boost::asio::socket_base::reuse_address option(true);
         acceptor_.set_option(option);
      }

      bool accept_connections()
      {
         try
         {
            session_ = boost::shared_ptr<bridge>(new bridge(io_service_));

            acceptor_.async_accept(session_->downstream_socket(),
                  boost::bind(&acceptor::handle_accept,
                        this,
                        boost::asio::placeholders::error));
            
         }
         catch(std::exception& e)
         {
            std::cerr << "acceptor exception: " << e.what() << std::endl;
            return false;
         }

         return true;
      }

      void close(){
         cout << "acceptor 1: " << endl;
         acceptor_.close();
         cout << "acceptor 2: " << endl;
         acceptor_.cancel();
         cout << "acceptor 3: " << endl;
         session_->close();
         cout << "acceptor 4: " << endl;
      }

   private:

      void handle_accept(const boost::system::error_code& error)
      {
         if (!error)
         {
            session_->start(upstream_host_,upstream_port_);

            if (!accept_connections())
            {
               std::cerr << "Failure during call to accept." << std::endl;
            }
         }
         else
         {
            std::cerr << "Error: " << error.message() << std::endl;
         }
      }

      boost::asio::io_service& io_service_;
      ip::address_v4 localhost_address;
      ip::tcp::acceptor acceptor_;
      boost::shared_ptr<bridge> session_;
      unsigned short upstream_port_;
      std::string upstream_host_;
   };


}

static void signal_handler(int signal_num){
   if (signal_num == SIGUSR1){
      #ifdef DEBUG
      cout << "Updating configurtation: " << gettid() << endl;
      #endif
      update_regex();
   }else if(signal_num == SIGUSR2){
      #ifdef DEBUG
      cout << "Killed: " << gettid() << endl;
      #endif
      *(firewall()->status_code) = 0;
      #ifdef DEBUG
      cout << "Exiting PT1: " << gettid() << endl;
      #endif
      proxy_map.erase(gettid());
      #ifdef DEBUG
      cout << "Exiting PT2: " << gettid() << endl;
      #endif
      //firewall()->acceptor->close();
      #ifdef DEBUG
      cout << "Exiting PT3: " << gettid() << endl;
      #endif
   }
}

extern "C" void start_proxy(
   char* local_host,unsigned short local_port,
   char* forward_host, unsigned short forward_port,
   char* config_file, int* status_code, void (*incrementCallback)(const char *)
){
   #ifdef DEBUG
   cout << "Starting: " << gettid() << endl;
   #endif
   regex_proxy tmp;
   proxy_map[gettid()] = &tmp;
   tmp.config_file = config_file;
   tmp.status_code = status_code;
   tmp.incrementCallback = incrementCallback;
   update_regex();
   boost::asio::io_service ios;
   signal(SIGUSR1, signal_handler);
   signal(SIGUSR2, signal_handler);
   try
   {
      tcp_proxy::acceptor acceptor(ios,
                                          local_host, local_port,
                                          forward_host, forward_port);
      firewall()->acceptor = &acceptor;
      acceptor.accept_connections();
      ios.run();
   }
   catch(std::exception& e)
   {
      std::cerr << "Error: " << e.what() << std::endl;
      *(firewall()->status_code) = 1;
      proxy_map.erase(gettid());
      return;
   }

   #ifdef DEBUG
   cout << "Exiting: " << gettid() << endl;
   #endif
   *(firewall()->status_code) = 0;
   proxy_map.erase(gettid());


}

/*
 * [Note] On posix systems the tcp proxy server build command is as follows:
 * c++ -pedantic -ansi -Wall -Werror -O3 -o tcpproxy_server tcpproxy_server.cpp -L/usr/lib -lstdc++ -lpthread -lboost_thread -lboost_system
 */
