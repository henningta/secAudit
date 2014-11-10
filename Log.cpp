#include "Log.hpp"
#include "cryptsuite.hpp"
#include <iostream>

std::string hashTypeKey(EntryType type, const std::string & keyAj) {
	// entry type to string
	std::string entryType;
	if (type == LOG_ENTRY_OPEN) {
		entryType = "LOG_ENTRY_OPEN";
	} else if (type == LOG_ENTRY_APPEND) {
		entryType = "LOG_ENTRY_APPEND";
	} else if (type == LOG_ENTRY_CLOSE) {
		entryType = "LOG_ENTRY_CLOSE";
	}

	// concatenate with delim || and hash
	std::string concat = entryType + "||" + keyAj;
	unsigned char *outHash = 0x0;
	if (cryptsuite::calcMD(
				(unsigned char *)concat.c_str(),
				concat.length(),
				&outHash) == 0) {
		return 0x0;
	}

	std::string hashedKey((const char *)outHash);
	return hashedKey;
}

std::string encryptMessage(const std::string & message,
		const std::string & hashedKey) {
	// symEncrypt message
	unsigned char *outSym = 0x0;
	//size_t encryptSize =
	cryptsuite::symEncrypt(
			(unsigned char *)message.c_str(),
			message.length(),
			&outSym,
			(unsigned char *)hashedKey.c_str());

	std::string encryptedMessage((const char *)outSym);
	return encryptedMessage;
}

/**
 * Log::open
 *
 * Opens file of specified name and adds an entry indicating the log has
 * been created
 *
 * @return 	bool
 * @author 	Travis Henning
 */
bool Log::open() {
	_logFile.open(_logName.c_str(), std::ios::app);

	if (!_logFile.is_open()) {
		return false;
	}

	std::string message = "Log file \"" + _logName + "\" created.";

	// create hash of entry type and key A to form symKey
	std::string keyAj = "blahblahblah";
	std::string hashedKey = hashTypeKey(LOG_ENTRY_OPEN, keyAj);

	// symEncrypt message with symKey created from hash
	std::string encryptedMessage = encryptMessage(message, hashedKey);

	// add encrypted "open" entry to log
	LogEntry entry(LOG_ENTRY_OPEN, encryptedMessage);
	_logEntries.push_back(entry);

	_logFile << entry.getMessage();

	return true;
}

/**
 * Log::close
 *
 * Closes current log file and adds an entry indicating the log has been
 * closed
 *
 * @return 	bool
 * @author 	Travis Henning
 */
bool Log::close() {
	if (!_logFile.is_open()) {
		return false;
	}

	std::string message = "\nLog file \"" + _logName + "\" closed.";

	// create hash of entry type and key A to form symKey
	std::string keyAj = "blahblahblah";
	std::string hashedKey = hashTypeKey(LOG_ENTRY_CLOSE, keyAj);

	// symEncrypt message with symKey created from hash
	std::string encryptedMessage = encryptMessage(message, hashedKey);

	// add encrypted "close" entry to log
	LogEntry entry(LOG_ENTRY_CLOSE, encryptedMessage);
	_logEntries.push_back(entry);

	_logFile << '\n' << entry.getMessage();

	_logFile.close();
	return true;
}

/**
 * Log::append
 *
 * Appends string message to open log file
 *
 * @param 	message 	the entry message to be appended
 * @return 	bool
 * @author 	Travis Henning
 */
bool Log::append(const std::string & message) {
	if (!_logFile.is_open()) {
		return false;
	}

	// create hash of entry type and key A to form symKey
	std::string keyAj = "blahblahblah";
	std::string hashedKey = hashTypeKey(LOG_ENTRY_APPEND, keyAj);

	// symEncrypt message with symKey created from hash
	std::string encryptedMessage = encryptMessage(message, hashedKey);

	// add encrypted "append" entry to log
	LogEntry entry(LOG_ENTRY_APPEND, encryptedMessage);
	_logEntries.push_back(entry);

	_logFile << '\n' << entry.getMessage();

	return true;
}

