#ifndef __TRUSTED_OBJECT_HPP__
#define __TRUSTED_OBJECT_HPP__

/**
 * TrustedObject.hpp
 *
 * Represents the trusted machine which is used to generate the initial key
 * as well as perform other encryption-related functions
 *
 * @author(s)	Travis Henning Jackson Reed
 */

#include <string>
#include "Message.hpp"
#include "cryptsuite.hpp"

class TrustedObject {
private:
  std::string _keyA0;
  Message M0;
  EVP_PKEY * mPublic;
  EVP_PKEY * mPrivate;
  std::map< std::string , EVP_PKEY * > keyTable;

public:
  TrustedObject();
  //ID needs to be unique!
  //TODO:
  void addPublicKeys(std::string ID, EVP_PKEY * PublicKey);

  Message verifyInitMessage(Message M0);

private:
  MessageMaker mkr;
};

#endif // __TRUSTED_OBJECT_HPP__

