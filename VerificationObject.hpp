#ifndef __VERIFICATION_OBJECT_HPP__
#define __VERIFICATION_OBJECT_HPP__

#include "Log.hpp"
#include "TrustedObject.hpp"
#include "UntrustedObject.hpp"

class VerificationObject {
public:
	void connectWith(TrustedObject & trustedObject);
	void connectWith(UntrustedObject & untrustedObject);
	void verifyEntry(Log & log);
	void verifyAll();
};

#endif // __VERIFICATION_OBJECT_HPP__
