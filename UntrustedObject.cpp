#include "UntrustedObject.hpp"

/**
 * UntrustedObject::createLog
 *
 * Creates a log of the given name by calling its _log member's open
 * function
 *
 * @param 	logName 	the name of the log file to be created (opened)
 * @return 	bool
 * @author 	Travis Henning
 */
bool UntrustedObject::createLog(const std::string & logName) {
	_log.setName(logName);
	return _log.open();
}

/**
 * UntrustedObject::addEntry
 *
 * Adds entry with provided message to log by calling _log member's append
 * function
 *
 * @param 	message 	the message of the log entry to be appended
 * @return 	bool
 * @author 	Travis Henning
 */
bool UntrustedObject::addEntry(const std::string & message) {
	return _log.append(message);
}

/**
 * UntrustedObject::closeLog
 *
 * Attempts to close an open log by calling _log member's close function
 *
 * @return 	bool
 * @author 	Travis Henning
 */
bool UntrustedObject::closeLog() {
	return _log.close();
}

