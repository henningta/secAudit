#include "LogEntry.hpp"
#include <string>

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

