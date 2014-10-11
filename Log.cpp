#include "Log.hpp"

#include <iostream>
#include <fstream>

// travis henning
bool Log::open() {
	std::ofstream logFile;
	logFile.open(_logName.c_str());

	if (!logFile.is_open()) {
		return false;
	}

	std::string message = "Log file \"" + _logName + "\" created.";
	LogEntry entry(OPEN, message);
	_logEntries.push_back(entry);

	logFile << entry.getMessage();
	logFile.close();

	return true;
}
