#ifndef UTILS
#define UTILS

#include <vector>
#include <string>
#include <sstream>
/**
 * utils.hpp
 *
 * Useful fuctions for general use cases
 *
 * @author(s) Jackson Reed, Travis Henning
 */

//Strings

//jackson reed
//Tokenize a string, example:
//std::vector<std::string> x = split("one:two::three", ':');
std::vector<std::string> split(const std::string &s, char delim);
std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems);

/*
 * numToString
 * Converts number to string and returns the value
 *
 * @param 		num 	the number to be converted to a string
 * @return 		string
 * @author(s) 	Travis Henning
 */
template<typename T>
std::string numToString(T num) {
	std::ostringstream ss;
	ss << num;
	return ss.str();
}

#endif // UTILS

