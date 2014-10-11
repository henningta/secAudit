#ifndef UTILS
#define UTILS

#include <vector>
#include <string>
#include <sstream>
/* utils.hpp
 * useful fuctions for general use cases
 */

//Strings

//Tokenize a string, example:
//std::vector<std::string> x = split("one:two::three", ':');
std::vector<std::string> split(const std::string &s, char delim);
std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems);

/*
 * NumToString
 * Converts number to string and returns the value
 */
template<typename T>
std::string numToString(T num) {
	std::ostringstream ss;
	ss << num;
	return ss.str();
}

#endif // UTILS

