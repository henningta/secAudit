#include "TrustedObject.hpp"
#include "Common.hpp"
#include "LogEntry.hpp"
#include <stdexcept>
#include "utils.hpp"
#include "debug.hpp"
#include "cryptsuite.hpp"
#include <openssl/safestack.h>
#include <openssl/x509.h>
extern FILE* fpErr;

/**
 * TrustedObject::TrustedObject()
 *
 * TrustedObject constructor
 *
 * @author      	Timothy Thong
 */

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
 * TrustedObject::verifyCertificate
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
 * TrustedObject::verifyInitMessage
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
	std::string			logName;
	Message				M1part;
	unsigned char			*tmpBuf;
	unsigned char			tmpFixedBuf[5000];
	size_t				decBytes;
	size_t				X0Len;
	size_t				cuLen;
	X509				*untrustCert;

	mkr = MessageMaker(T_ID, MessageState::VER_INIT_RESP);
	mkr.clear_payload();

	// obtain K0
	tmpVector = M0.get_payload("ENCRYPTED_K0");
	if ( ! cryptsuite::pkDecrypt((unsigned char *) &tmpVector[0], tmpVector.size(), &tmpBuf, priv) ) {
		fprintf(fpErr, "Failed to obtain K0\n");
		// TODO: Stop here?
	}
	K0 = std::string((const char *) tmpBuf, SESSION_KEY_LEN);
	delete[] tmpBuf;

	// obtain X0 || signedX0
	tmpVector = M0.get_payload("ENCRYPTED_X0_DATA");
	decBytes = cryptsuite::symDecrypt((unsigned char *) &tmpVector[0], tmpVector.size(),
						&tmpBuf, (unsigned char *) &K0[0]); 

	if (decBytes <= 0) {
		fprintf(fpErr, "Failed to decrypt X0DATASIG\n");
		// TODO: Stop here?
	}
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
		// TODO: Stop here?
	}

	// read in A0 and associate it with current log
	_keyA0 = std::string((const char *) &decX0Data[0] + MSTATE_LEN + TSTMP_LEN + cuLen, AUTH_KEY_LEN);
	tmpVector = M0.get_payload("logName");
	logName = std::string(tmpVector.begin(), tmpVector.end());
	logNameA0Map[logName] = _keyA0;
	

	// form X1 - p, IDlog hash(X0)
	mkr.set_MessageState(MessageState::VER_INIT_RESP);
	p = std::to_string(VER_INIT_RESP);

	if ( ! cryptsuite::calcMD((unsigned char *) &decX0Data[0], X0Len, &tmpBuf) ) {
		fprintf(fpErr, "Error: Could not hash X0\n");
	}
	hashedX0 = std::string((const char *) tmpBuf, MD_BYTES);
	delete[] tmpBuf;

	X1 = p;
	X1.replace(X1.length(), logName.length(), &logName[0], logName.length());
	X1.replace(X1.length(), MD_BYTES, (const char *) &hashedX0[0], MD_BYTES);
	
	// generate random key K1 and encrypt it
	cryptsuite::genRandBytes(tmpFixedBuf, SESSION_KEY_LEN);
	K1 = std::string((const char *) tmpFixedBuf, SESSION_KEY_LEN);

	if ( ! mkr.set_pkencrypt("ENCRYPTED_K1", SESSION_KEY_LEN,
			(unsigned char *) &K1[0], untrustPub) ) {
		fprintf(fpErr, "Error could not encrypt K1\n");
		// TODO Stop here?
	}

	// sign X1
	if ( ! mkr.set_sign("SIGNED_X1", X1.length(), (unsigned char *) &X1[0], priv) ) {
		fprintf(fpErr, "Error: Failed to sign X1\n");
		// TODO: Stop here?
	}
		
	// EK1(encrypt X1 || signedX1)
	M1part = mkr.get_message();
	tmpVector = M1part.get_payload("SIGNED_X1");
	signedX1 = std::string(tmpVector.begin(), tmpVector.end());

	X1DataSig = X1;
	X1DataSig.replace(X1DataSig.length(), signedX1.length(),
			(const char *) &signedX1[0], signedX1.length());

	if ( ! mkr.set_symencrypt("ENCRYPTED_X1_DATA", X1DataSig.length(),
			(unsigned char *) &X1DataSig[0], (unsigned char *) &K1[0]) ) {
		fprintf(fpErr, "Error: Failed to encrypt X1DATASIG\n");
		// TODO: Stop here?
	}

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

	mkr.set("M1", M1.length(), (unsigned char *) &M1[0]);

	// add length markers for parsing later
	tmpStr = std::to_string(encX1Data.length());
        mkr.set("ENCRYPTED_X1_DATA_LEN", tmpStr.length(), (unsigned char *) &tmpStr[0]);
        tmpStr = std::to_string(X1.length());
        mkr.set("X1LEN", tmpStr.length(), (unsigned char *) &tmpStr[0]);

	/* DEBUG
	first4Last4("verifyInit K0", (unsigned char *) &K0[0], SESSION_KEY_LEN); 	
	first4Last4("verifyInit A0", (unsigned char *) &decX0Data[0] + MSTATE_LEN + TSTMP_LEN + cuLen, AUTH_KEY_LEN);
	first4Last4("verifyInit X0", (unsigned char *) &decX0Data[0], X0Len);
	first4Last4("verifyInit X0||signedX0", (unsigned char *) &decX0Data[0], decX0Data.length()); 	
	printf("\n");
	first4Last4("verifyInit K1", (unsigned char *) &K1[0], SESSION_KEY_LEN);
	first4Last4("verifyInit X1||signedX1", (unsigned char *) &X1DataSig[0], X1DataSig.length());
	*/

	return mkr.get_message();
}

/**
 * TrustedObject::verificationResponse
 *
 * sends decryption keys to verifier
 *
 * @param	M		the message that contains information necessary for verification
 * @param	openedLog	pointer to the last opened log in memory
 * @return	keys		decryption keys to be sent to verifier
 * @author      Timothy Thong
 */
std::vector<std::string> TrustedObject::verificationResponse(Message M, Log& openedLog, ClosedLogEntries c) {
	std::string			logName;
	std::string			p;
	std::string			V_Af;	// verifier
	std::string			V_Yf;
	std::string			V_Zf;
	std::string			U_Yf;	// untrusted
	std::string			T_A0;	// trusted
	std::string			T_Af;
	std::string			T_Zf;
	std::string			key;
	std::vector<std::string> 	keys;
	EntryType			Wj;
	std::string			tmpStr;
	std::vector<unsigned char> 	tmpVector;
	std::vector<LogEntry>		logEntries;
	ClosedLogEntries		closedLogs;
	VerifyMode			vMode;
	std::string			Aj;
	std::string			Kj;
	int				f;
	
	tmpVector = M.get_payload("IDlog");
	logName = std::string(tmpVector.begin(), tmpVector.end());

	// verify closed log
	if ( ! openedLog.isOpen() ) {
		if ( c.count(logName) == 0 ) {
			throw std::runtime_error("Failed verification");
		}
		logEntries = c[logName];
		vMode = VERIFY_ALL;

	// verify opened log
	} else {
		logEntries = openedLog.getEntries();
		vMode = VERIFY_ENTRY;
	}
	
	// Obtain correct  A0 for the log
	T_A0 = logNameA0Map[logName]; 

	tmpVector = M.get_payload("Zf");
	V_Zf = std::string(tmpVector.begin(), tmpVector.end());
	
	// Obtain f
	tmpVector = M.get_payload("f");
	tmpVector.push_back('\0');
	tmpStr = std::string(tmpVector.begin(), tmpVector.end());
	f = atoi(&tmpStr[0]);

	U_Yf = logEntries.at(f).getYj();
	T_Af = Common::incrementHash(T_A0, f);
	T_Zf = Common::hashZ(U_Yf, T_Af);
		
	if (T_Zf.compare(V_Zf) != 0) {
		throw std::runtime_error("Failed verification");
	}

	if (vMode == VERIFY_ENTRY) {
		Aj = Common::incrementHash(T_A0, f);
		Wj = logEntries.at(f).getEntryType();
		Kj = Common::hashTypeKey(Wj, Aj);
		
		keys.push_back(Kj);
		
	} else if (vMode == VERIFY_ALL) {
		Aj = T_A0;
		for (size_t i = 0; i < logEntries.size(); i++) {
			Wj = logEntries.at(i).getEntryType();
			Kj = Common::hashTypeKey(Wj, Aj);
			keys.push_back(Kj);	
			Aj = Common::incrementHash(Aj, 1);
		}
	}

	return keys;

}
