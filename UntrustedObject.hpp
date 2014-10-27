#ifndef __UNTRUSTED_OBJECT_HPP__
#define __UNTRUSTED_OBJECT_HPP__

/**
 * UntrustedObject.hpp
 *
 * Class representing the untrusted machine which creates, appends to, and
 * closes log files (client machine).
 *
 * @author(s) 	Travis Henning
 */

#include "Log.hpp"

class UntrustedObject {
private:
	Log _log;
public:
	void generateInitMessage(); 	// TODO
	void verifyInitResponse(); 		// TODO
	bool createLog(const std::string & logName);
	bool addEntry(const std::string & message);
	bool closeLog();

	inline const std::string & getLogName() { return _log.getName(); }
	inline int getNumEntries() { return _log.getNumEntries(); }
};

#endif // __UNTRUSTED_OBJECT_HPP__

