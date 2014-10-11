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
	bool addEntry(const std::string & message);
	bool closeLog();

	inline const std::string & getLogName() { return _log.getName(); }
	inline int getNumEntries() { return _log.getNumEntries(); }
};

#endif // __UNTRUSTED_OBJECT_HPP__
