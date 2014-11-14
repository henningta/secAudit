#ifndef __LOG_HPP__
#define __LOG_HPP__

/**
 * Log.hpp
 *
 * Log object which stores (encrypted) entries made by the untrusted
 * machine. Able to open, close, append itself.
 *
 * @author(s)	Travis Henning
 */

#include <fstream>
#include <string>
#include <vector>

#include "LogEntry.hpp"

std::string hashY(const std::string & prevY,
		  const std::string & encryptedMessage,
		  EntryType entryType);


class Log {
private:
	std::fstream 			_logFile;
	std::string 			_logName;
	std::vector<LogEntry> 	_logEntries;

	std::string _Yj;
	std::string _Zj;
public:
	Log() {}
	Log(std::string logName) : _logName(logName) {}

	inline const std::string & getName() const { return _logName; }
	inline void setName(const std::string & logName) { _logName = logName; }

	bool openExisting(const std::string & fileName);

	bool open(const std::string & D0, const std::string & A0);
	bool close(const std::string & Aj);
	bool append(const std::string & message, const std::string & Aj, const EntryType ENTRY_TYPE);

	inline bool isOpen() { return _logFile.is_open(); }
	inline int getNumEntries() { return _logEntries.size(); }
	inline std::string getLogName() { return _logName; }

	LogEntry & getEntry(int pos) { return _logEntries.at(pos); }
	std::vector<LogEntry> & getEntries() { return _logEntries; }

	void clear();
};

#endif // __LOG_HPP__
