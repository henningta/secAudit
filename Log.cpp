#include "Log.hpp"
#include "cryptsuite.hpp"
#include "Common.hpp"
#include "utils.hpp"

#include <iostream>

/**
 *	encryptMessage
 *
 *	Encrypts string with symmetric key
 *
 *	@param 	message 	string to be encrypted
 *	@param 	hashedKey 	key used to encrypt
 *	@return string 		encrypted string result
 *
 *	@author Travis Henning
 */
std::string encryptMessage(const std::string & message,
		const std::string & hashedKey) {
	unsigned char *outSym = 0x0;
	size_t encryptSize =
	cryptsuite::symEncrypt(
			(unsigned char *)message.c_str(),
			message.length(),
			&outSym,
			(unsigned char *)hashedKey.c_str());

	std::string encryptedMessage((const char *)outSym, encryptSize);
	return encryptedMessage;
}

/**
 * Log::openExisting
 *
 * Opens existing log file for verification purposes
 *
 * @param 	fileName 	name of log file to open
 * @author 	Travis Henning
 */
bool Log::openExisting(const std::string & fileName) {
	_logName = fileName;
	_logFile.open(_logName, std::ios::in);

	if (!_logFile.is_open()) {
		return false;
	}

	// shove entire file text into string
	std::ostringstream fileStream;
	fileStream << _logFile.rdbuf();
	std::string fileText = fileStream.str();

	std::string buf = "";
	int sizes[4];
	int sep = 0;

	// iterate through string
	for (std::string::iterator i = fileText.begin(); i < fileText.end();
			i++) {
		if (*i == '|') {
			sizes[sep] = std::atoi(buf.c_str());
			buf.clear();
			if (++sep == 4) {
				// pass pipe char
				i++;

				// read values
				std::string typeStr(i, i + sizes[0]);
				i += sizes[0];
				std::string Dj(i, i + sizes[1]);
				i += sizes[1];
				std::string Yj(i, i + sizes[2]);
				i += sizes[2];
				std::string Zj(i, i + sizes[3]);
				i += sizes[3];

				// add entry
				EntryType type = stringToEntryType(typeStr);
				LogEntry entry(type, Dj, Yj, Zj);
				_logEntries.push_back(entry);

				// reset separation
				sep = 0;
			}
		} else {
			buf += *i;
		}
	}

	_logFile.close();

	return true;
}

/**
 * Log::open
 *
 * Opens file of specified name and adds an entry indicating the log has
 * been created
 *
 * @param 	D0 		message of first log entry
 * @param 	A0 		key A0 for first entry
 * @return 	bool 	success of open
 *
 * @author 	Travis Henning
 */
bool Log::open(const std::string & D0, const std::string & A0) {
	_logFile.open(_logName.c_str(), std::ios::out);

	if (!_logFile.is_open()) {
		return false;
	}

	const EntryType ENTRY_TYPE = LOG_ENTRY_OPEN;

	// create hash of entry type and key A to form symKey
	std::string hashedKey = Common::hashTypeKey(ENTRY_TYPE, A0);

	// symEncrypt message with symKey created from hash
	std::string encryptedMessage = encryptMessage(D0, hashedKey);

	// initialize Yj and Zj
	_Yj = Common::hashY("00000000000000000000", encryptedMessage, ENTRY_TYPE);
	_Zj = Common::hashZ(_Yj, A0);

	// add encrypted "open" entry to log
	LogEntry entry(ENTRY_TYPE, encryptedMessage, _Yj, _Zj);
	_logEntries.push_back(entry);

	// add sizes for reading entries from file later
	_logFile << entryTypeToString(ENTRY_TYPE).length() << '|';
	_logFile << encryptedMessage.length() << '|';
	_logFile << _Yj.length() << '|';
	_logFile << _Zj.length() <<'|';

	// add concatenated message to log
	_logFile << entry.getMessage();

	return true;
}

/**
 * Log::close
 *
 * Closes current log file and adds an entry indicating the log has been
 * closed
 *
 * @param 	Aj 		current Aj key used in sym encryption
 * @return 	bool 	success of close
 *
 * @author 	Travis Henning
 */
bool Log::close(const std::string & Aj) {
	if (!_logFile.is_open()) {
		return false;
	}

	const EntryType ENTRY_TYPE = LOG_ENTRY_CLOSE;

	std::string message = "Log file \"" + _logName + "\" closed.";

	// create hash of entry type and key A to form symKey
	std::string hashedKey = Common::hashTypeKey(ENTRY_TYPE, Aj);

	// symEncrypt message with symKey created from hash
	std::string encryptedMessage = encryptMessage(message, hashedKey);

	// initialize Yj and Zj
	std::string prevY = _Yj;
	_Yj = Common::hashY(prevY, encryptedMessage, ENTRY_TYPE);
	_Zj = Common::hashZ(_Yj, Aj);

	// add encrypted "close" entry to log
	LogEntry entry(ENTRY_TYPE, encryptedMessage, _Yj, _Zj);
	_logEntries.push_back(entry);

	// add sizes for reading entries from file later
	_logFile << '\n' << entryTypeToString(ENTRY_TYPE).length() << '|';
	_logFile << encryptedMessage.length() << '|';
	_logFile << _Yj.length() << '|';
	_logFile << _Zj.length() <<'|';

	// add concatenated message to log (on new line)
	_logFile << entry.getMessage();

	_logFile.close();
	return true;
}

/**
 * Log::append
 *
 * Appends string message to open log file
 *
 * @param 	message 	the entry message to be appended
 * @param 	Aj 			current key Aj used in sym encryption
 * @param	ENTRY_TYPE	Wj
 * @return 	bool 		success of append
 * @author 	Travis Henning
 */
bool Log::append(const std::string & message, const std::string & Aj, const EntryType ENTRY_TYPE) {
	if (!_logFile.is_open()) {
		return false;
	}

	// create hash of entry type and key A to form symKey
	std::string hashedKey = Common::hashTypeKey(ENTRY_TYPE, Aj);

	// symEncrypt message with symKey created from hash
	std::string encryptedMessage = encryptMessage(message, hashedKey);

	// initialize Yj and Zj
	std::string prevY = _Yj;
	_Yj = Common::hashY(prevY, encryptedMessage, ENTRY_TYPE);
	_Zj = Common::hashZ(_Yj, Aj);

	// add encrypted "append" entry to log
	LogEntry entry(ENTRY_TYPE, encryptedMessage, _Yj, _Zj);
	_logEntries.push_back(entry);

	// add sizes for reading entries from file later
	_logFile << '\n' << entryTypeToString(ENTRY_TYPE).length() << '|';
	_logFile << encryptedMessage.length() << '|';
	_logFile << _Yj.length() << '|';
	_logFile << _Zj.length() <<'|';

	// add concatenated message to log (on new line)
	_logFile << entry.getMessage();

	return true;
}

/**
 * clear
 *
 * Clears all data from log (useful when creating new logs)
 *
 * @author Travis Henning
 */
void Log::clear() {
	_logFile.clear();
	_logName.clear();
	_logEntries.clear();
	_Yj.clear();
	_Zj.clear();
}

