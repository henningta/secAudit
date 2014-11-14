#ifndef __LOG_ENTRY_HPP__
#define __LOG_ENTRY_HPP__

/**
 * LogEntry.hpp
 *
 * Entry object for log files. Contains information on entry type (open,
 * close, append) as well as the entry message.
 *
 * @author(s) Travis Henning
 *
 */

#include <string>

enum EntryType {
	LOG_ENTRY_OPEN,
	LOG_ENTRY_CLOSE,
	LOG_ENTRY_APPEND,
	LOG_ENTRY_ABNORMAL_CLOSE
};

std::string entryTypeToString(EntryType type);
EntryType stringToEntryType(const std::string & typeStr);

class LogEntry {
private:
	EntryType 	_entryType;
	std::string _encryptedDj;
	std::string _Yj;
	std::string _Zj;
public:
	LogEntry(EntryType entryType, std::string encryptedDj, std::string Yj,
			std::string Zj)
		: _entryType(entryType), _encryptedDj(encryptedDj),
		_Yj(Yj), _Zj(Zj) {}

	friend std::ostream & operator << (std::ostream & out, LogEntry & entry) {
		out << entryTypeToString(entry._entryType) << entry._encryptedDj
			<< entry._Yj << entry._Zj;
		return out;
	}

	inline EntryType getEntryType() const { return _entryType; }
	inline std::string getEncryptedDj() const { return _encryptedDj; };
	inline std::string getYj() const { return _Yj; };
	inline std::string getZj() const { return _Zj; };

	std::string getMessage() const {
		return entryTypeToString(_entryType) +
			_encryptedDj + _Yj + _Zj;
	}
};

#endif // __LOG_ENTRY_HPP__

