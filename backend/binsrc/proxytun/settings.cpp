#ifndef PROXY_TUNNEL_SETTINGS_CPP
#define PROXY_TUNNEL_SETTINGS_CPP

#include <iostream>
#include <cstring>
#include <sstream>
#include "../utils.hpp"
#include <vector>
#include <hs.h>
#include <memory>

using namespace std;

class PyCodeConfig{
	public:
		const string code;
	public:
		PyCodeConfig(string pycode): code(pycode){}
		
		~PyCodeConfig(){}
};

shared_ptr<PyCodeConfig> config;

#endif // PROXY_TUNNEL_SETTINGS_CPP

