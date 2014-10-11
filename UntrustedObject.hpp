#ifndef __UNTRUSTED_OBJECT_HPP__
#define __UNTRUSTED_OBJECT_HPP__

#include "Log.hpp"

class UntrustedObject {
private:
	Log _log;
public:
	void generateInitMessage();
	void verifyInitResponse();
	bool createLog(const std::string & logName);
	void createLogEntry(const std::string & message);
	void closeLog();
};

#endif // __UNTRUSTED_OBJECT_HPP__
