#include "UntrustedObject.hpp"

// travis henning
bool UntrustedObject::createLog(const std::string & logName) {
	_log.setName(logName);
	return _log.open();
}

//travis henning
bool UntrustedObject::addEntry(const std::string & message) {
	return _log.append(message);
}

//travis henning
bool UntrustedObject::closeLog() {
	return _log.close();
}

