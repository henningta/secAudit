#include "Log.hpp"
#include "cryptsuite.hpp"
#include "utils.hpp"

#include <iostream>

/**
 *	hashTypeKey
 *
 *	Hashes log entry type concatenated with key Aj
 *
 *	@param 	type 	entry type of current LogEntry
 *	@param 	keyAj 	key from TrustedObject derived by hashes of prev keys
 *	@return string 	hash of type concatenated with key
 *
 *	@author Travis Henning
 */
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
 *	hashY
 *
 *	Hash Yj value of log entry based on prev Yj, encrypted Dj, and Wj
 *
 *	@param 	prevY 				previous Yj (hashed) value
 *	@param 	encryptedMessage 	encrypted Dj of current entry
 *	@param 	entryType 			Wj value of current entry
 *	@return string 				Yj (hashed) for current entry
 *
 *	@author Travis Henning
 */
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

/**
 *	hashZ
 *
 *	@param 	Yj 		Yj (hashed) of current entry
 *	@param 	keyAj 	current Aj key
 *	@return string 	Zj (hashed) of current entry
 *
 *	@author Travis Henning
 */
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
 * @param 	D0 		message of first log entry
 * @param 	A0 		key A0 for first entry
 * @return 	bool 	success of open
 *
 * @author 	Travis Henning
 */
bool Log::open(const std::string & D0, const std::string & A0) {
	_logFile.open(_logName.c_str(), std::ios::app);

	if (!_logFile.is_open()) {
		return false;
	}

	const EntryType ENTRY_TYPE = LOG_ENTRY_OPEN;

	// create hash of entry type and key A to form symKey
	std::string hashedKey = hashTypeKey(ENTRY_TYPE, A0);

	// symEncrypt message with symKey created from hash
	std::string encryptedMessage = encryptMessage(D0, hashedKey);

	// initialize Yj and Zj
	_Yj = hashY("00000000000000000000", encryptedMessage, ENTRY_TYPE);
	_Zj = hashZ(_Yj, A0);

	// add encrypted "open" entry to log
	LogEntry entry(ENTRY_TYPE, encryptedMessage, _Yj, _Zj);
	_logEntries.push_back(entry);

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
	std::string hashedKey = hashTypeKey(ENTRY_TYPE, Aj);

	// symEncrypt message with symKey created from hash
	std::string encryptedMessage = encryptMessage(message, hashedKey);

	// initialize Yj and Zj
	std::string prevY = _Yj;
	_Yj = hashY(prevY, encryptedMessage, ENTRY_TYPE);
	_Zj = hashZ(_Yj, Aj);

	// add encrypted "close" entry to log
	LogEntry entry(ENTRY_TYPE, encryptedMessage, _Yj, _Zj);
	_logEntries.push_back(entry);

	// add concatenated message to log (on new line)
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
 * @param 	Aj 			current key Aj used in sym encryption
 * @return 	bool 		success of append
 * @author 	Travis Henning
 */
bool Log::append(const std::string & message, const std::string & Aj) {
	if (!_logFile.is_open()) {
		return false;
	}

	const EntryType ENTRY_TYPE = LOG_ENTRY_APPEND;

	// create hash of entry type and key A to form symKey
	std::string hashedKey = hashTypeKey(ENTRY_TYPE, Aj);

	// symEncrypt message with symKey created from hash
	std::string encryptedMessage = encryptMessage(message, hashedKey);

	// initialize Yj and Zj
	std::string prevY = _Yj;
	_Yj = hashY(prevY, encryptedMessage, ENTRY_TYPE);
	_Zj = hashZ(_Yj, Aj);

	// add encrypted "append" entry to log
	LogEntry entry(ENTRY_TYPE, encryptedMessage, _Yj, _Zj);
	_logEntries.push_back(entry);

	// add concatenated message to log (on new line)
	_logFile << '\n' << entry.getMessage();

	return true;
}

