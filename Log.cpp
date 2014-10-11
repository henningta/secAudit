#include "Log.hpp"

#include <iostream>

// travis henning
bool Log::open() {
	_logFile.open(_logName.c_str(), std::ios::app);

	if (!_logFile.is_open()) {
		return false;
	}

	std::string message = "Log file \"" + _logName + "\" created.";
	LogEntry entry(LOG_ENTRY_OPEN, message);
	_logEntries.push_back(entry);

	_logFile << entry.getMessage();

	return true;
}

// travis henning
bool Log::close() {
	if (_logFile.is_open()) {
		std::string message = "\nLog file \"" + _logName + "\" closed.";
		LogEntry entry(LOG_ENTRY_CLOSE, message);
		_logEntries.push_back(entry);

	_logFile << entry.getMessage();

		_logFile.close();
		return true;
	}

	return false;
}

// travis henning
bool Log::append(const std::string & message) {
	if (!_logFile.is_open()) {
		return false;
	}

	LogEntry entry(LOG_ENTRY_APPEND, message);
	_logEntries.push_back(entry);

	_logFile << '\n' << entry.getMessage();

	return true;
}

