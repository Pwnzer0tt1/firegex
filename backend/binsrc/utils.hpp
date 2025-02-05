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
         char chr = (char) (int)strtol(byte.c_str(), nullptr, 16);
         newString.push_back(chr);
      }
      return true;
   }
   catch (...){
      return false;
   }
}

#endif