#ifndef __COMMON_HPP__
#define __COMMON_HPP__

/**
 * Common.hpp
 *
 * Functions that are common to all objects
 *
 * @author(s)	Timothy Thong
 */

#include <fstream>
#include <string>
#include <vector>

#include "cryptsuite.hpp"
#include "LogEntry.hpp"

namespace Common {


	std::string incrementHash(const std::string & base, int count);
	std::string hashTypeKey(EntryType type, const std::string & keyAj);
	std::string hashY(const std::string & prevY, const std::string & encryptedMessage, EntryType entryType);
	std::string hashZ(const std::string & Yj, const std::string & keyAj);
};

#endif // __COMMON_HPP__
