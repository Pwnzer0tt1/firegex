/* 
   Copyright (c) 2007 Arash Partow (http://www.partow.net)
   URL: http://www.partow.net/programming/tcpproxy/index.html
   Modified and adapted by Pwnzer0tt1
*/
#include <cstdlib>
#include <cstddef>
#include <iostream>
#include <string>
#include <mutex>

#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/bind/bind.hpp>
#include <boost/asio.hpp>
#include <boost/thread/mutex.hpp>
#include <jpcre2.hpp>

typedef jpcre2::select<char> jp;
using namespace std;

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

   void add(const char* arg){
      
      //Integrity checks
      size_t arg_len = strlen(arg);
      if (arg_len < 2 || arg_len%2 != 0) return;
      if (arg[0] != '0' && arg[0] != '1') return;
      if (arg[1] != 'C' && arg[1] != 'c' && arg[1] != 'S' && arg[1] != 's') return;
      string hex(arg+2), expr;
      if (!unhexlify(hex, expr)) return;
      //Push regex
      jp::Regex regex(expr,arg[0] == '1'?"gS":"giS");
      if (regex){
         #ifdef DEBUG
         cerr << "Added regex " << expr << " " << arg << endl;
         #endif
         getByCode(arg[1])->push_back(make_pair(string(arg), regex));
      } else {
         cerr << "Regex " << arg << " was not compiled successfully" << endl;
      }
   }

};
shared_ptr<regex_rules> regex_config;

mutex update_mutex;

bool filter_data(unsigned char* data, const size_t& bytes_transferred, regex_rule_vector const &blacklist, regex_rule_vector const &whitelist){
   #ifdef DEBUG_PACKET
   cerr << "---------------- Packet ----------------" << endl;
   for(int i=0;i<bytes_transferred;i++) cerr << data[i];
   cerr << endl;
   for(int i=0;i<bytes_transferred;i++) fprintf(stderr, "%x", data[i]);
   cerr << endl;
   cerr << "---------------- End Packet ----------------" << endl;
   #endif
   string str_data((char *) data, bytes_transferred);
   for (regex_rule_pair ele:blacklist){
      try{
         if(ele.second.match(str_data)){
            stringstream msg;
            msg << "BLOCKED " << ele.first << endl;
            cout << msg.str() << std::flush;
            return false;
         }
      } catch(...){
         cerr << "Error while matching regex: " << ele.first << endl;
      }
   }
   for (regex_rule_pair ele:whitelist){
      try{
         if(!ele.second.match(str_data)){
            stringstream msg;
            msg << "BLOCKED " << ele.first << endl;
            cout << msg.str() << std::flush;
            return false;
         }
      } catch(...){
         cerr << "Error while matching regex: " << ele.first << endl;
      }      
   }
   #ifdef DEBUG
   cerr << "Packet Accepted!" << endl;
   #endif
   return true;
}

namespace tcp_proxy
{
   namespace ip = boost::asio::ip;

   class bridge : public boost::enable_shared_from_this<bridge>
   {
   public:

      typedef ip::tcp::socket socket_type;
      typedef boost::shared_ptr<bridge> ptr_type;

      bridge(boost::asio::io_context& ios)
      : downstream_socket_(ios),
        upstream_socket_  (ios),
        thread_safety(ios)
      {}

      socket_type& downstream_socket()
      {
         // Client socket
         return downstream_socket_;
      }

      socket_type& upstream_socket()
      {
         // Remote server socket
         return upstream_socket_;
      }

      void start(const string& upstream_host, unsigned short upstream_port)
      {
         // Attempt connection to remote server (upstream side)
         upstream_socket_.async_connect(
              ip::tcp::endpoint(
                   boost::asio::ip::address::from_string(upstream_host),
                   upstream_port),
               boost::asio::bind_executor(thread_safety,
               boost::bind(
                  &bridge::handle_upstream_connect,
                    shared_from_this(),
                    boost::asio::placeholders::error)));
      }

      void handle_upstream_connect(const boost::system::error_code& error)
      {
         if (!error)
         {
            // Setup async read from remote server (upstream)

            upstream_socket_.async_read_some(
                 boost::asio::buffer(upstream_data_,max_data_length),
                 boost::asio::bind_executor(thread_safety,
                     boost::bind(&bridge::handle_upstream_read,
                     shared_from_this(),
                     boost::asio::placeholders::error,
                     boost::asio::placeholders::bytes_transferred)));

            // Setup async read from client (downstream)
            downstream_socket_.async_read_some(
                 boost::asio::buffer(downstream_data_,max_data_length),
                 boost::asio::bind_executor(thread_safety,
                     boost::bind(&bridge::handle_downstream_read,
                     shared_from_this(),
                     boost::asio::placeholders::error,
                     boost::asio::placeholders::bytes_transferred)));
         }
         else
            close();
      }

   private:

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
            shared_ptr<regex_rules> regex_old_config = regex_config;
            if (filter_data(upstream_data_, bytes_transferred, regex_old_config->regex_s_c_b, regex_old_config->regex_s_c_w)){
               async_write(downstream_socket_,
                  boost::asio::buffer(upstream_data_,bytes_transferred),
                  boost::asio::bind_executor(thread_safety,
                        boost::bind(&bridge::handle_downstream_write,
                        shared_from_this(),
                        boost::asio::placeholders::error)));
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
                 boost::asio::bind_executor(thread_safety,
                     boost::bind(&bridge::handle_upstream_read,
                     shared_from_this(),
                     boost::asio::placeholders::error,
                     boost::asio::placeholders::bytes_transferred)));
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
            shared_ptr<regex_rules> regex_old_config = regex_config;
            if (filter_data(downstream_data_, bytes_transferred, regex_old_config->regex_c_s_b, regex_old_config->regex_c_s_w)){
               async_write(upstream_socket_,
                  boost::asio::buffer(downstream_data_,bytes_transferred),
                  boost::asio::bind_executor(thread_safety,
                        boost::bind(&bridge::handle_upstream_write,
                        shared_from_this(),
                        boost::asio::placeholders::error)));
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
                 boost::asio::bind_executor(thread_safety,
                     boost::bind(&bridge::handle_downstream_read,
                     shared_from_this(),
                     boost::asio::placeholders::error,
                     boost::asio::placeholders::bytes_transferred)));
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
      boost::asio::io_context::strand thread_safety;
      boost::mutex mutex_;
   public:

      class acceptor
      {
      public:

         acceptor(boost::asio::io_context& io_context,
                  const string& local_host, unsigned short local_port,
                  const string& upstream_host, unsigned short upstream_port)
         : io_context_(io_context),
           localhost_address(boost::asio::ip::address_v4::from_string(local_host)),
           acceptor_(io_context_,ip::tcp::endpoint(localhost_address,local_port)),
           upstream_port_(upstream_port),
           upstream_host_(upstream_host)
         {}

         bool accept_connections()
         {
            try
            {
               session_ = boost::shared_ptr<bridge>(new bridge(io_context_));

               acceptor_.async_accept(session_->downstream_socket(),
                    boost::asio::bind_executor(session_->thread_safety,
                    boost::bind(&acceptor::handle_accept,
                         this,
                         boost::asio::placeholders::error)));
            }
            catch(exception& e)
            {
               cerr << "acceptor exception: " << e.what() << endl;
               return false;
            }

            return true;
         }

      private:

         void handle_accept(const boost::system::error_code& error)
         {
            if (!error)
            {
               session_->start(upstream_host_,upstream_port_);

               if (!accept_connections())
               {
                  cerr << "Failure during call to accept." << endl;
               }
            }
            else
            {
               cerr << "Error: " << error.message() << endl;
            }
         }

         boost::asio::io_context& io_context_;
         ip::address_v4 localhost_address;
         ip::tcp::acceptor acceptor_;
         ptr_type session_;
         unsigned short upstream_port_;
         string upstream_host_;
      };

   };
}

void update_config (boost::asio::streambuf &input_buffer){
      #ifdef DEBUG
      cerr << "Updating configuration" << endl;
      #endif
      std::istream config_stream(&input_buffer);
      std::unique_lock<std::mutex> lck(update_mutex);
      regex_rules *regex_new_config = new regex_rules();
      string data;
      while(true){
         config_stream >> data;
         if (config_stream.eof()) break;
         regex_new_config->add(data.c_str());
      }
      regex_config.reset(regex_new_config);
}

class async_updater
{
public:
  async_updater(boost::asio::io_context& io_context) : input_(io_context, ::dup(STDIN_FILENO)), thread_safety(io_context)
  {
   
      boost::asio::async_read_until(input_, input_buffer_, '\n',
          boost::asio::bind_executor(thread_safety,
          boost::bind(&async_updater::on_update, this,
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred)));
  }

  void on_update(const boost::system::error_code& error, std::size_t length)
  {
    if (!error)
    {
      update_config(input_buffer_);
      boost::asio::async_read_until(input_, input_buffer_, '\n',
         boost::asio::bind_executor(thread_safety,
          boost::bind(&async_updater::on_update, this,
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred)));
    }
    else
    {
      close();
    }
  }

  void close()
  {
    input_.close();
  }

private:
  boost::asio::posix::stream_descriptor input_;
  boost::asio::io_context::strand thread_safety;
  boost::asio::streambuf input_buffer_;
};


int main(int argc, char* argv[])
{
   if (argc < 5)
   {
      cerr << "usage: tcpproxy_server <local host ip> <local port> <forward host ip> <forward port>" << endl;
      return 1;
   }

   const unsigned short local_port   = static_cast<unsigned short>(::atoi(argv[2]));
   const unsigned short forward_port = static_cast<unsigned short>(::atoi(argv[4]));
   const string local_host      = argv[1];
   const string forward_host    = argv[3];
   
   int threads = 1;
   char * n_threads_str = getenv("NTHREADS");
   if (n_threads_str != NULL) threads = ::atoi(n_threads_str);

   boost::asio::io_context ios;

   boost::asio::streambuf buf;
   boost::asio::posix::stream_descriptor cin_in(ios, ::dup(STDIN_FILENO));
   boost::asio::read_until(cin_in, buf,'\n');
   update_config(buf);

   async_updater updater(ios);
   
   #ifdef DEBUG
   cerr << "Starting Proxy" << endl;
   #endif
   try
   {
      tcp_proxy::bridge::acceptor acceptor(ios,
                                           local_host, local_port,
                                           forward_host, forward_port);

      acceptor.accept_connections();
      
      if (threads > 1){
         boost::thread_group tg;
         for (unsigned i = 0; i < threads; ++i)
            tg.create_thread(boost::bind(&boost::asio::io_context::run, &ios));

      tg.join_all();
      }else{
         ios.run();
      }
   }
   catch(exception& e)
   {
      cerr << "Error: " << e.what() << endl;
      return 1;
   }
   #ifdef DEBUG
   cerr << "Proxy stopped!" << endl;
   #endif

   return 0;
}
