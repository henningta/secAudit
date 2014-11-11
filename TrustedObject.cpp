#include "TrustedObject.hpp"
#include <stdexcept>
#include "utils.hpp"
#include "debug.hpp"
#include "cryptsuite.hpp"
#include <openssl/safestack.h>
#include <openssl/x509.h>
extern FILE* fpErr;

TrustedObject::TrustedObject() {
	
	// add keys
	pub = EVP_PKEY_new();
	priv = EVP_PKEY_new();
	untrustPub = EVP_PKEY_new();

	cryptsuite::loadRSAPublicKey(TRUSTED_PUB, &pub);
	cryptsuite::loadRSAPrivateKey(TRUSTED_PRIV, &priv);
	cryptsuite::loadRSAPublicKey(UNTRUSTED_PUB, &untrustPub);
	mkr.set_ID(T_ID);

	// load trusted certificate
	if ( ! cryptsuite::loadX509Cert(TRUSTED_CERT, &CA) ) {
		fprintf(fpErr, "Error: Could not load CA cert\n");
	}

	// create X509 context
	ctx = X509_STORE_CTX_new();
	if (ctx == NULL) {
		fprintf(fpErr, "Error: Failed to create certificate store\n");
	}

	// add trusted certificate to stack
	STACK_OF(X509) *sk = sk_X509_new_null();
	sk_X509_push(sk, CA);
	if ( X509_STORE_CTX_init(ctx, NULL, NULL, NULL) != 1) {
		fprintf(fpErr, "Error: Failed to init cert store\n");
	} 
	X509_STORE_CTX_trusted_stack(ctx, sk);
}

/**
 * UntrustedObject::verifyCertificate
 *
 * Creates a log of the given name by calling its _log member's open
 * function
 *
 * @param       cert	X509 cert
 * @return      	1 if verified, other values otherwise
 * @author      	Timothy Thong
 */
int TrustedObject::verifyCertificate(X509 *cert) {
	OpenSSL_add_all_algorithms();
	X509_STORE_CTX_set_cert(ctx, cert);	
	int ret = X509_verify_cert(ctx);
	EVP_cleanup();

	return ret;
}

/**
 * UntrustedObject::verifyInitMessage
 *
 * Creates a log of the given name by calling its _log member's open
 * function
 *
 * @param       cert	X509 cert
 * @return      	1 if verified, other values otherwise
 * @author      	Timothy Thong, Jackson Reed
 */
Message TrustedObject::verifyInitMessage(Message M0) {
	std::vector<unsigned char> 	tmpVector;
	std::string			K0;
	std::string			decX0Data;
	unsigned char			*tmpBuf;
	unsigned char			tmpFixedBuf[5000];
	size_t				decBytes;
	size_t				len;
	size_t				X0Len;
	size_t				cuLen;
	X509				*untrustCert;

	// obtain K0
	tmpVector = M0.get_payload("ENCRYPTED_K0");
	cryptsuite::pkDecrypt((unsigned char *) &tmpVector[0], tmpVector.size(), &tmpBuf, priv);
	K0 = std::string((const char *) tmpBuf, SESSION_KEY_LEN);
	delete tmpBuf;

	// obtain X0 || signedX0
	tmpVector = M0.get_payload("ENCRYPTED_X0_DATA");
	decBytes = cryptsuite::symDecrypt((unsigned char *) &tmpVector[0], tmpVector.size(),
						&tmpBuf, (unsigned char *) &K0[0]); 
	decX0Data = std::string((const char *) tmpBuf, decBytes);
	delete tmpBuf;

	// verify X0 - p, d, Cu, A0
	tmpVector = M0.get_payload("X0LEN");
	tmpVector.push_back('\0');
	X0Len = atoi((const char *) &tmpVector[0]);	

	if ( ! cryptsuite::verifySignature((unsigned char *) &decX0Data[0], X0Len, 
			(unsigned char *) &decX0Data[0] + X0Len, untrustPub) ) {
		fprintf(fpErr, "Error: Signature verification failed\n");
	}	
	
	// get DER-encoded cert and read into X509 struct
	tmpVector = M0.get_payload("CULEN");
	tmpVector.push_back('\0');
	cuLen = atoi((const char *) &tmpVector[0]);
	untrustCert = cryptsuite::derToX509((unsigned char *) &decX0Data[0] + MSTATE_LEN + TSTMP_LEN, cuLen);

	// verify cert
	if ( ! verifyCertificate(untrustCert) ) {
		fprintf(fpErr, "Error: Certificate verification failed\n");
	}

	// read in A0
	_keyA0 = std::string((const char *) &decX0Data[0] + MSTATE_LEN + TSTMP_LEN + cuLen, AUTH_KEY_LEN);

	// form X1 - p, IDlog, hash(X0)
	// generate random key K1 and encrypt it
	// sign X1
	// EK1(encrypt X1 || signedX1)
	// form M1
	
	mkr.set_ID(T_ID);
	mkr.set_MessageState(MessageState::VER_INIT_RESP);
	//mkr.clear_payload();

	return mkr.get_message();
}


