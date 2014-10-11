#ifndef __LOG_HPP__
#define __LOG_HPP__

#include <string>
#include <vector>

#include "LogEntry.hpp"

class Log {
private:
	std::string 			_logName;
	std::vector<LogEntry> 	_logEntries;
public:
	Log(std::string logName) : _logName(logName) {}

	bool open();
	void close();
	void append(const std::string & message);
};

#endif // __LOG_HPP__
