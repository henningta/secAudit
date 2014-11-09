#include "UntrustedObject.hpp"
#include <chrono>
#include <ctime>
#include <sstream>
#include <stdexcept>


UntrustedObject::UntrustedObject(){
  msgFact= MessageMaker(U_ID, MessageState::UNINITIALIZED);
  cryptsuite::loadRSAPublicKey(UNTRUSTED_PUB, &pub);
  cryptsuite::loadRSAPrivateKey(UNTRUSTED_PRIV , &priv);
  cryptsuite::loadRSAPrivateKey(TRUSTED_PUB , &trustPub);

}

/**
 * UntrustedObject::createLog
 *
 * Creates a log of the given name by calling its _log member's open
 * function
 *
 * @param 	logName 	the name of the log file to be created (opened)
 * @return 	Message
 * @author 	Travis Henning , Jackson Reed
 */
Message UntrustedObject::createLog(const std::string & logName) {
  std::stringstream sstm;

  //see the paper pg 5
  std::string K0="TODO:";//random session key
  std::string d = "TODO:";//time stamp
  std::string IDlog ="TODO:";//logs unique id
  //p = unique step indetifyer
  sstm<<MessageState::VER_INIT_REQ;
  std::string p = sstm.str();
  std::string Cu=UNTRUSTED_CERT;
  std::string A0="TODO:";//a random starting point
  std::string IDu= U_ID;


  std::string X0=""+p+d+Cu+A0;
  std::string SIGNSKuX0="TODO:";

  msgFact.clear_payload();
  msgFact.set_ID(U_ID);
  msgFact.set_MessageState(MessageState::VER_INIT_REQ);
  msgFact.set("p",p.length(),(unsigned char *)&p[0]);
  msgFact.set("IDu",IDu.length(),(unsigned char *)&IDu[0]);
  msgFact.set_encrypt("K0",K0.length(), (unsigned char *)&K0[0],trustPub);
  msgFact.set_encrypt("X0",X0.length(),(unsigned char *) &X0[0],trustPub);
  msgFact.set_encrypt("SIGNSKuX0",SIGNSKuX0.length(),(unsigned char *) &SIGNSKuX0[0],trustPub);

  //for convience lets add X0 indvidualy so we dont have to parse it

  //p is alrady known and if you add it again you will overite the old value
  msgFact.set_encrypt("d",d.length(),(unsigned char *) &d[0],trustPub);
  msgFact.set_encrypt("Cu",Cu.length(),(unsigned char *) &Cu[0],trustPub);
  msgFact.set_encrypt("A0",A0.length(),(unsigned char *) &A0[0],trustPub);


  _log.setName(logName);
  if (!_log.open()){
    throw std::runtime_error("Open Log returned false");
  }

  return msgFact.get_message();
}

/**
 * UntrustedObject::addEntry
 *
 * Adds entry with provided message to log by calling _log member's append
 * function
 *
 * @param 	message 	the message of the log entry to be appended
 * @return 	Messgae 
 * @author 	Travis Henning , Jackson Reed
 */
Message UntrustedObject::addEntry(const std::string & message) {
  bool app = _log.append(message);
  if (!app){
    throw std::runtime_error("Append Log returned false");
  }

  return msgFact.get_message();

}

/**
 * UntrustedObject::closeLog
 *
 * Attempts to close an open log by calling _log member's close function
 *
 * @return 	Messgae
 * @author 	Travis Henning , Jackson Reed
 */
Message UntrustedObject::closeLog() {
  bool close = _log.close();
  if (!close){
    throw std::runtime_error("Close Log returned false");
  }

  return msgFact.get_message();

}

