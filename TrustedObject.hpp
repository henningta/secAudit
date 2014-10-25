#ifndef __TRUSTED_OBJECT_HPP__
#define __TRUSTED_OBJECT_HPP__

/**
 * TrustedObject.hpp
 *
 * Represents the trusted machine which is used to generate the initial key
 * as well as perform other encryption-related functions
 *
 * @author(s)	Travis Henning
 */

#include <string>

class TrustedObject {
private:
	std::string _keyA0;

public:
	void verifyInitMessage();	// TODO
	void generateStuff();		// TODO

};

#endif // __TRUSTED_OBJECT_HPP__

