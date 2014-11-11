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
 * Verifies a given certificate
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
 * Verifies M0 and sends back M1
 *
 * @param       M0	Message from UntrustedObject
 * @return      	M1
 * @author      	Timothy Thong, Jackson Reed
 */
Message TrustedObject::verifyInitMessage(Message M0) {
	std::vector<unsigned char> 	tmpVector;
	std::string			K0;
	std::string			K1;
	std::string			X1;
	std::string			encK1;
	std::string			signedX1;
	std::string			X1DataSig;
	std::string			encX1Data;
	std::string			decX0Data;
	std::string			p;
	std::string			hashedX0;
	std::string			M1;
	std::string			tmpStr;
	Message				M1part;
	unsigned char			*tmpBuf;
	unsigned char			tmpFixedBuf[5000];
	size_t				decBytes;
	size_t				X0Len;
	size_t				cuLen;
	X509				*untrustCert;

	mkr = MessageMaker(T_ID, MessageState::VER_INIT_RESP);

	// obtain K0
	tmpVector = M0.get_payload("ENCRYPTED_K0");
	cryptsuite::pkDecrypt((unsigned char *) &tmpVector[0], tmpVector.size(), &tmpBuf, priv);
	K0 = std::string((const char *) tmpBuf, SESSION_KEY_LEN);
	delete[] tmpBuf;

	// obtain X0 || signedX0
	tmpVector = M0.get_payload("ENCRYPTED_X0_DATA");
	decBytes = cryptsuite::symDecrypt((unsigned char *) &tmpVector[0], tmpVector.size(),
						&tmpBuf, (unsigned char *) &K0[0]); 
	decX0Data = std::string((const char *) tmpBuf, decBytes);
	delete[] tmpBuf;

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

	// form X1 - p, hash(X0) TODO: How does T know IDLog?!
	mkr.set_MessageState(MessageState::VER_INIT_RESP);
	p = std::to_string(VER_INIT_RESP);

	if ( ! cryptsuite::calcMD((unsigned char *) &decX0Data[0], X0Len, &tmpBuf) ) {
		fprintf(fpErr, "Error: Could not hash X0\n");
	}
	hashedX0 = std::string((const char *) tmpBuf, MD_BYTES);
	delete[] tmpBuf;

	X1 = p;
	X1.replace(X1.length(), MD_BYTES, (const char *) &hashedX0[0], MD_BYTES);
	
	// generate random key K1 and encrypt it
	cryptsuite::genRandBytes(tmpFixedBuf, SESSION_KEY_LEN);
	K1 = std::string((const char *) tmpFixedBuf, SESSION_KEY_LEN);
	mkr.set_pkencrypt("ENCRYPTED_K1", SESSION_KEY_LEN,
			(unsigned char *) &K1[0], untrustPub);

	// sign X1
	mkr.set_sign("SIGNED_X1", X1.length(), (unsigned char *) &X1[0], priv);
		
	// EK1(encrypt X1 || signedX1)
	M1part = mkr.get_message();
	tmpVector = M1part.get_payload("SIGNED_X1");
	signedX1 = std::string(tmpVector.begin(), tmpVector.end());

	X1DataSig = X1;
	X1DataSig.replace(X1DataSig.length(), signedX1.length(),
			(const char *) &signedX1[0], signedX1.length());

	mkr.set_symencrypt("ENCRYPTED_X1_DATA", X1DataSig.length(),
			(unsigned char *) &X1DataSig[0], (unsigned char *) &K1[0]);

	// form M1
	M1part = mkr.get_message();
	tmpVector = M1part.get_payload("ENCRYPTED_K1");
	encK1 = std::string(tmpVector.begin(), tmpVector.end());
	tmpVector = M1part.get_payload("ENCRYPTED_X1_DATA");
	encX1Data = std::string(tmpVector.begin(), tmpVector.end());
	
	M1 = p;
	M1.replace(M1.length(), strlen(T_ID), T_ID, strlen(T_ID));
	M1.replace(M1.length(), encK1.length(),
		(const char *) &encK1[0], encK1.length());
	M1.replace(M1.length(), encX1Data.length(),
		(const char *) &encX1Data[0], encX1Data.length());

	mkr.clear_payload();
	mkr.set("M1", M1.length(), (unsigned char *) &M1[0]);

	// add length markers for parsing later
	tmpStr = std::to_string(encX1Data.length());
        mkr.set("ENCRYPTED_X1_DATA_LEN", tmpStr.length(), (unsigned char *) &tmpStr[0]);
        tmpStr = std::to_string(X1.length());
        mkr.set("X1LEN", tmpStr.length(), (unsigned char *) &tmpStr[0]);


	return mkr.get_message();
}


