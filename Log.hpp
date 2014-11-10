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

class Log {
private:
	std::ofstream 			_logFile;
	std::string 			_logName;
	std::vector<LogEntry> 	_logEntries;

	std::string _Yj;
	std::string _Zj;
public:
	Log() {}
	Log(std::string logName) : _logName(logName) {}

	inline const std::string & getName() const { return _logName; }
	inline void setName(const std::string & logName) { _logName = logName; }

	bool open(const std::string & D0, const std::string & A0);
	bool close(const std::string & Aj);
	bool append(const std::string & message, const std::string & Aj);

	inline bool isOpen() { return _logFile.is_open(); }
	inline int getNumEntries() { return _logEntries.size(); }
};

#endif // __LOG_HPP__
