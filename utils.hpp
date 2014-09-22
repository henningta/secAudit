#ifndef UTILS
#define UTILS

#include <vector>
#include <string>
#include <sstream>
/* utils.hpp
 * usefull fuctions for general use cases
 */

//Strings

//Tokenize a string, example:
//std::vector<std::string> x = split("one:two::three", ':');
std::vector<std::string> split(const std::string &s, char delim);
std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems);

#endif

