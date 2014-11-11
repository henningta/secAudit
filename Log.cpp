#include "Log.hpp"
#include "cryptsuite.hpp"
#include <iostream>
#include "utils.hpp"

std::string entryTypeToString(EntryType type) {
	std::string entryType;

	if (type == LOG_ENTRY_OPEN) {
		entryType = "LOG_ENTRY_OPEN";
	} else if (type == LOG_ENTRY_APPEND) {
		entryType = "LOG_ENTRY_APPEND";
	} else if (type == LOG_ENTRY_CLOSE) {
		entryType = "LOG_ENTRY_CLOSE";
	}

	return entryType;
}

std::string hashTypeKey(EntryType type, const std::string & keyAj) {
	// entry type to string
	std::string entryType = entryTypeToString(type);

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

std::string hashY(const std::string & prevY,
		const std::string & encryptedMessage, EntryType entryType) {
	std::string type = entryTypeToString(entryType);

	// concatenate items
	std::string concat = prevY + "||" + encryptedMessage + "||" + type;

	unsigned char *outHash = 0x0;
	if (cryptsuite::calcMD(
				(unsigned char *)concat.c_str(),
				concat.length(),
				&outHash) == 0) {
		return 0x0;
	}

	std::string hashedY((const char *)outHash);
	return hashedY;
}

std::string hashZ(const std::string & Yj, const std::string & keyAj) {
	unsigned char *outHash = 0x0;
	if (cryptsuite::calcHMAC(
				(unsigned char *)Yj.c_str(),
				Yj.length(),
				&outHash,
				(unsigned char *)keyAj.c_str(),
				keyAj.length()) == 0) {
		return 0x0;
	}

	std::string hashedZ((const char *)outHash);
	return hashedZ;
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
bool Log::open(const std::string & D0, const std::string & A0) {
	_logFile.open(_logName.c_str(), std::ios::app);

	if (!_logFile.is_open()) {
		return false;
	}

	const EntryType ENTRY_TYPE = LOG_ENTRY_OPEN;

	//std::string message = "Log file \"" + _logName + "\" created.";
	std::string message = D0;

	// create hash of entry type and key A to form symKey
	std::string keyAj = A0;
	std::string hashedKey = hashTypeKey(ENTRY_TYPE, keyAj);

	// symEncrypt message with symKey created from hash
	std::string encryptedMessage = encryptMessage(message, hashedKey);

	// initialize Yj and Zj
	_Yj = hashY("00000000000000000000", encryptedMessage, ENTRY_TYPE);
	_Zj = hashZ(_Yj, keyAj);

	std::string sizes =
	  numToString<int>(entryTypeToString(ENTRY_TYPE).length())+
          "|"+numToString<int>(encryptedMessage.length())+
          "|"+numToString<int>(_Yj.length())+
          "|"+numToString<int>(_Zj.length());

	// concatenate items for entry
	std::string concatenatedMessage =
	  sizes + "|" + entryTypeToString(ENTRY_TYPE)
	  + encryptedMessage + _Yj + _Zj;

	// add encrypted "open" entry to log
	LogEntry entry(ENTRY_TYPE, concatenatedMessage);
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
bool Log::close(const std::string & Aj) {
	if (!_logFile.is_open()) {
		return false;
	}

	const EntryType ENTRY_TYPE = LOG_ENTRY_CLOSE;

	std::string message = "Log file \"" + _logName + "\" closed.";

	// create hash of entry type and key A to form symKey
	std::string keyAj = Aj;
	std::string hashedKey = hashTypeKey(ENTRY_TYPE, keyAj);

	// symEncrypt message with symKey created from hash
	std::string encryptedMessage = encryptMessage(message, hashedKey);

	// initialize Yj and Zj
	std::string prevY = _Yj;
	_Yj = hashY(prevY, encryptedMessage, ENTRY_TYPE);
	_Zj = hashZ(_Yj, keyAj);

	std::string sizes = numToString<int>(entryTypeToString(ENTRY_TYPE).length())+
          "|"+numToString<int>(encryptedMessage.length())+
          "|"+numToString<int>(_Yj.length())+
          "|"+numToString<int>(_Zj.length());



	// concatenate items for entry
	std::string concatenatedMessage = sizes+ "|"
	  +  entryTypeToString(ENTRY_TYPE) +
	  encryptedMessage + _Yj  + _Zj;

	// add encrypted "close" entry to log
	LogEntry entry(ENTRY_TYPE, concatenatedMessage);
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
bool Log::append(const std::string & message, const std::string & A0) {
	if (!_logFile.is_open()) {
		return false;
	}

	const EntryType ENTRY_TYPE = LOG_ENTRY_APPEND;

	// create hash of entry type and key A to form symKey
	std::string keyAj = A0;
	std::string hashedKey = hashTypeKey(ENTRY_TYPE, keyAj);

	// symEncrypt message with symKey created from hash
	std::string encryptedMessage = encryptMessage(message, hashedKey);

	// initialize Yj and Zj
	std::string prevY = _Yj;
	_Yj = hashY(prevY, encryptedMessage, ENTRY_TYPE);
	_Zj = hashZ(_Yj, keyAj);

	// concatenate items for entry
	std::string sizes = numToString<int>(entryTypeToString(ENTRY_TYPE).length())+
	  "|"+numToString<int>(encryptedMessage.length())+
	  "|"+numToString<int>(_Yj.length())+
	  "|"+numToString<int>(_Zj.length());

	std::string concatenatedMessage =sizes + "|" +  entryTypeToString(ENTRY_TYPE) + encryptedMessage +  _Yj  + _Zj;

	// add encrypted "append" entry to log
	LogEntry entry(ENTRY_TYPE, concatenatedMessage);
	_logEntries.push_back(entry);

	_logFile << '\n' << entry.getMessage();

	return true;
}

