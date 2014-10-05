#ifndef __TRUSTED_OBJECT_HPP__
#define __TRUSTED_OBJECT_HPP__

#include <string>

class TrustedObject {
private:
	std::string _keyA0;

public:
	void verifyInitMessage();
	void generateStuff();

};

#endif // __TRUSTED_OBJECT_HPP__
