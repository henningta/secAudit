#ifndef __UNTRUSTED_OBJECT_HPP__
#define __UNTRUSTED_OBJECT_HPP__

/**
 * UntrustedObject.hpp
 *
 * Class representing the untrusted machine which creates, appends to, and
 * closes log files (client machine).
 *
 * @author(s) 	Travis Henning
 */

#include "Log.hpp"
#include "Message.hpp"
#include "cryptsuite.hpp"


class UntrustedObject {
private:
  Log _log;
  MessageMaker msgFact;
  EVP_PKEY *pub;
  EVP_PKEY *priv;
  EVP_PKEY *trustPub;
  std::string Aj;
  
public:

  UntrustedObject();
  Message createLog(const std::string & logName);
  Message addEntry(const std::string & message);
  Message closeLog();
  void incrementAj();
  
  inline const std::string & getLogName() { return _log.getName(); }
  inline int getNumEntries() { return _log.getNumEntries(); }
};

#endif // __UNTRUSTED_OBJECT_HPP__

