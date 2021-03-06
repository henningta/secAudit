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
#include <map>
#include <openssl/safestack.h>
#include <openssl/x509_vfy.h>
#include "Message.hpp"
#include "UntrustedObject.hpp"
#include "LogEntry.hpp"
#include "cryptsuite.hpp"

enum VerifyMode {
	VERIFY_ENTRY,
	VERIFY_ALL
};

class TrustedObject {
private:
  std::string _keyA0;
  std::map<std::string, std::string> logNameA0Map;
  Message M0;
  EVP_PKEY *pub;
  EVP_PKEY *priv;
  EVP_PKEY *untrustPub;
  X509_STORE_CTX *ctx;
  X509 *CA;
  X509_STORE *store;

public:
  TrustedObject();
  Message verifyInitMessage(Message M0);
  std::vector<std::string> verificationResponse(Message M, Log& openedLog, ClosedLogEntries c);
  int verifyCertificate(X509 *cert);

private:
  MessageMaker mkr;
};

#endif // __TRUSTED_OBJECT_HPP__

