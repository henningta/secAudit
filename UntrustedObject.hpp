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
#include "LogEntry.hpp"
#include "Message.hpp"
#include "cryptsuite.hpp"
#include <map>

typedef std::map<std::string, std::vector<LogEntry>> ClosedLogEntries;

class UntrustedObject {
private:
	Log			_log;
	ClosedLogEntries	_closedLogEntries;
	MessageMaker		msgFact;
	EVP_PKEY 		*pub;
	EVP_PKEY 		*priv;
	EVP_PKEY 		*trustPub;
	std::string 		Aj;
	std::string		trustedHashedX0;
	long int 		d_max;

public:
	UntrustedObject();
	Message createLog(const std::string & logName);
	Message addEntry(const std::string & message, const EntryType ENTRY_TYPE);
	Message closeLog();
	void verifyInitResponse(Message M1);
	void incrementAj();

	ClosedLogEntries & getClosedLogEntries() {
		return _closedLogEntries;
	}

	inline const std::string & getLogName() { return _log.getName(); }
	inline int getNumEntries() { return _log.getNumEntries(); }
	std::vector<LogEntry> & getEntries() { return _log.getEntries(); }
};

#endif // __UNTRUSTED_OBJECT_HPP__

