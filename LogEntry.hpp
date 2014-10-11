#ifndef __LOG_ENTRY_HPP__
#define __LOG_ENTRY_HPP__

#include <string>

enum EntryType {
	LOG_ENTRY_OPEN,
	LOG_ENTRY_CLOSE,
	LOG_ENTRY_APPEND
};

class LogEntry {
private:
	EntryType 	_entryType;
	std::string _message;
public:
	LogEntry(EntryType entryType, std::string message)
		: _entryType(entryType), _message(message) {}

	inline EntryType getEntryType() const { return _entryType; }
	inline std::string getMessage() const { return _message; }
};

#endif // __LOG_ENTRY_HPP__
