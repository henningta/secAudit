#include "LogEntry.hpp"
#include <string>

// converts entry type to string
// Travis Henning
std::string entryTypeToString(EntryType type) {
	std::string entryType;

	if (type == LOG_ENTRY_OPEN) {
		entryType = "LOG_ENTRY_OPEN";
	} else if (type == LOG_ENTRY_APPEND) {
		entryType = "LOG_ENTRY_APPEND";
	} else if (type == LOG_ENTRY_CLOSE) {
		entryType = "LOG_ENTRY_CLOSE";
	} else if (type == LOG_ENTRY_ABNORMAL_CLOSE) {
		entryType = "LOG_ENTRY_ABNORMAL_CLOSE";
	}

	return entryType;
}

// converts string to entry type
// Travis Henning
EntryType stringToEntryType(const std::string & typeStr) {
	EntryType type = LOG_ENTRY_OPEN;

	if (typeStr == "LOG_ENTRY_OPEN") {
		type = LOG_ENTRY_OPEN;
	} else if (typeStr == "LOG_ENTRY_APPEND") {
		type = LOG_ENTRY_APPEND;
	} else if (typeStr == "LOG_ENTRY_CLOSE") {
		type = LOG_ENTRY_CLOSE;
	} else if (typeStr == "LOG_ENTRY_ABNORMAL_CLOSE") {
		type = LOG_ENTRY_ABNORMAL_CLOSE;
	}

	return type;
}

