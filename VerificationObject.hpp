#ifndef __VERIFICATION_OBJECT_HPP__
#define __VERIFICATION_OBJECT_HPP__

/**
 * VerificationObject.hpp
 *
 * Represents the verification server which checks logs and log entries for
 * integrity after encryption
 *
 * @author(s)	Travis Henning, Jackson Reed
 */

#include "Log.hpp"
#include "TrustedObject.hpp"
#include "UntrustedObject.hpp"
#include "Message.hpp"

class VerificationObject {

private:
  MessageMaker mkr;
public:

  Message
  verifyEntryStart(Log & log , int n);

  Message
  verifyEntryTwo(Log & log , int n);

  Message
  verifyAllStart(Log & log);

  Message
  verifyAllTwo(Log & log);

};

#endif // __VERIFICATION_OBJECT_HPP__

