#include "utils.hpp"

// jackson reed
std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    elems.push_back(item);
  }
  return elems;
}

// jackson reed
std::vector<std::string> split(const std::string &s, char delim) {
  std::vector<std::string> elems;
  split(s, delim, elems);
  return elems;
}

// travis henning
std::string readToChar(char stop, std::istream & iStream) {
	std::string buf;
	char c;
	while (iStream >> std::noskipws >> c) {
		if (c == stop) {
			break;
		}
		buf += c;
	}
	return buf;
}
