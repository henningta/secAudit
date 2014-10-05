#ifndef __UNTRUSTED_OBJECT_HPP__
#define __UNTRUSTED_OBJECT_HPP__

#include "Log.hpp"

class UntrustedObject {
private:
	Log _log;
public:
	void generateInitMessage();
	void verifyInitResponse();
	void createLogEntry();
	void closeLog();
};

#endif // __UNTRUSTED_OBJECT_HPP__
