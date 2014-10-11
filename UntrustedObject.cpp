#include "UntrustedObject.hpp"

// travis henning
bool UntrustedObject::createLog(const std::string & logName) {
	_log.setName(logName);
	return _log.open();
}

