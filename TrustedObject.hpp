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
#include "message.hpp"
#include "cryptsuite.hpp"


class TrustedObject {
private:
  std::string _keyA0;
  Message M0;
  EVP_PKEY mPublic;
  EVP_PKEY mPrivate;
  std::map< std::string , std::string > keyTable;

public:
<<<<<<< HEAD
  TrustedObject(EVP_PKEY PublicKey,EVP_PKEY PrivateKey);
  //This is temporary so the code compiles, Dont use this
  TrustedObject();
  //ID needs to be unique!
  void addPublicKeys(std::string ID, std::string PublicKey);

  Message verifyInitMessage(Message M0);
=======
	void verifyInitMessage();	// TODO
	void generateStuff();		// TODO
>>>>>>> 1979d48bb4468ca5668c6d769cabe3836bf4cdce

private:
  MessageMaker mkr;
  
};

#endif // __TRUSTED_OBJECT_HPP__

