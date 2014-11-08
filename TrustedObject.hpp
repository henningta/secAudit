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
  EVP_PKEY mPublic;
  EVP_PKEY mPrivate;
  std::map< std::string , std::string > keyTable;

public:
  TrustedObject(EVP_PKEY PublicKey,EVP_PKEY PrivateKey);
  //This is temporary so the code compiles, Dont use this
  TrustedObject();
  //ID needs to be unique!
  //TODO:
  void addPublicKeys(std::string ID, std::string PublicKey);

  Message verifyInitMessage(Message M0);

private:
  MessageMaker mkr;
};

#endif // __TRUSTED_OBJECT_HPP__

