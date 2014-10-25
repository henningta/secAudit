#ifndef __VERIFICATION_OBJECT_HPP__
#define __VERIFICATION_OBJECT_HPP__

/**
 * VerificationObject.hpp
 *
 * Represents the verification server which checks logs and log entries for
 * integrity after encryption
 *
 * @author(s)	Travis Henning
 */

#include "Log.hpp"
#include "TrustedObject.hpp"
#include "UntrustedObject.hpp"

class VerificationObject {
public:
	void connectWith(TrustedObject & trustedObject);		// TODO
	void connectWith(UntrustedObject & untrustedObject);	// TODO
	void verifyEntry(Log & log);							// TODO
	void verifyAll(); 										// TODO
};

#endif // __VERIFICATION_OBJECT_HPP__

