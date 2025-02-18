#ifndef PROXY_TUNNEL_SETTINGS_CPP
#define PROXY_TUNNEL_SETTINGS_CPP

#include <vector>
#include <memory>

using namespace std;

class PyCodeConfig{
	public:
		const vector<uint8_t> code;
	public:
		PyCodeConfig(vector<uint8_t> pycode): code(pycode){}
		PyCodeConfig(): code(vector<uint8_t>()){}
		
		~PyCodeConfig(){}
};

shared_ptr<PyCodeConfig> config;

#endif // PROXY_TUNNEL_SETTINGS_CPP

