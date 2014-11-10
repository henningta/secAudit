#include "UntrustedObject.hpp"
#include "debug.hpp"
#include "Message.hpp"
#include <chrono>
#include <ctime>
#include <sstream>
#include <stdexcept>

extern FILE* fpErr;

UntrustedObject::UntrustedObject(){
	msgFact= MessageMaker(U_ID, MessageState::UNINITIALIZED);

	// allocate memory for keys (mandatory)
	pub = EVP_PKEY_new();
	priv = EVP_PKEY_new();
	trustPub = EVP_PKEY_new();

	// read keys into EVP_PKEY stucts
	cryptsuite::loadRSAPublicKey(UNTRUSTED_PUB, &pub);
	cryptsuite::loadRSAPrivateKey(UNTRUSTED_PRIV, &priv);
	cryptsuite::loadRSAPublicKey(TRUSTED_PUB, &trustPub);

}

/**
 * UntrustedObject::createLog
 *
 * Creates a log of the given name by calling its _log member's open
 * function
 *
 * @param 	logName 	the name of the log file to be created (opened)
 * @return 	Message
 * @author 	Travis Henning , Jackson Reed, Timothy Thong
 */
Message UntrustedObject::createLog(const std::string & logName) {
	std::string			p;
	std::string 			K0;
	std::string 			A0;
	std::string			encK0;
	std::string   			Cu;
	std::string   			X0;
	std::string			d;
	std::string			d_limit;
	std::string			M0;
	std::string			D0;
	std::string			signedX0;
	std::string			X0DataSig;
	std::string			encX0Data;
	Message				M0part;
	std::vector<unsigned char>	tmpVector;
	size_t				CuLen;
	X509 				*pemCert;
	unsigned char 			*tmpBuf;
        unsigned char			tmpFixedBuf[5000];

	p = std::to_string(MessageState::VER_INIT_REQ);

	// generate random bytes for K0 and A0
	cryptsuite::genRandBytes( tmpFixedBuf, SESSION_KEY_LEN );
	K0 = std::string((const char *) tmpFixedBuf, SESSION_KEY_LEN);
	cryptsuite::genRandBytes( tmpFixedBuf, AUTH_KEY_LEN );
	A0 = std::string((const char *) tmpFixedBuf, AUTH_KEY_LEN);

	// update Aj for current log entry
	Aj = A0;

	// load X509 cert and re-encode to DER
	if ( ! cryptsuite::loadX509Cert(UNTRUSTED_CERT, &pemCert) ) {
		fprintf(fpErr, "Error: Could not load U's cert\n");
	}
	CuLen = cryptsuite::x509ToDer(pemCert, &tmpBuf);
	tmpBuf = tmpBuf - CuLen;
	Cu = std::string((const char *) tmpBuf, CuLen);

	// get current timestamp d and set d+
	d = std::to_string( cryptsuite::getCurrentTimeStamp() );
	d_limit = std::to_string( atol(&d[0]) + MAX_WAIT );

	// setup X0 - p, d, Cu, A0
	X0 = p;
	X0.replace(X0.length(), d.length(), (const char *) &d[0], d.length());
	X0.replace(X0.length(), CuLen, (const char *) &Cu[0], CuLen);
	X0.replace(X0.length(), AUTH_KEY_LEN, (const char *) &A0[0], AUTH_KEY_LEN);

	// sign X0
	msgFact.set_sign("SIGNED_X0", X0.length(), (unsigned char *) &X0[0], priv);

	// encrypt K0
	msgFact.set_pkencrypt("ENCRYPTED_K0", SESSION_KEY_LEN,
			(unsigned char *) &K0[0], trustPub);

	M0part = msgFact.get_message();
	tmpVector = M0part.get_payload("SIGNED_X0");
	signedX0 = std::string(tmpVector.begin(), tmpVector.end());

	X0DataSig = X0;
	X0DataSig.replace(X0DataSig.length(), signedX0.length(),
			(const char *) &signedX0[0], signedX0.length());

	// encrypt signed X0 data
	msgFact.set_symencrypt("ENCRYPTED_X0_DATA", X0DataSig.length(),
			(unsigned char *) &X0DataSig[0], (unsigned char *) &K0[0]);

	// form M0 - p, IDu, Pk(K0), Ek(X0, signedX0)
	M0part = msgFact.get_message();
	tmpVector = M0part.get_payload("ENCRYPTED_K0");
	encK0 = std::string(tmpVector.begin(), tmpVector.end());
	tmpVector = M0part.get_payload("ENCRYPTED_X0_DATA");
	encX0Data = std::string(tmpVector.begin(), tmpVector.end());

	M0 = p;
	M0.replace(M0.length(), strlen(U_ID), U_ID, strlen(U_ID));
	M0.replace(M0.length(), encK0.length(),
			(const char *) &encK0[0], encK0.length());
	M0.replace(M0.length(), encX0Data.length(),
			(const char *) &encX0Data[0], encX0Data.length());

	msgFact.set("M0", M0.length(), (unsigned char *) &M0[0]);

	// form D0 - d, d+, IDlog, M0
	D0 = d;
	D0.replace(D0.length(), d_limit.length(),
			(const char *) &d_limit[0], d_limit.length());
	D0.replace(D0.length(), logName.length(),
			(const char *) &logName[0], logName.length());
	D0.replace(D0.length(), M0.length(),
			(const char *) &M0[0], M0.length());

	_log.setName(logName);
	if (!_log.open(D0, Aj)) {
		throw std::runtime_error("Open Log returned false");
	}

	// increment Aj key
	incrementAj();

	return msgFact.get_message();
}

/**
* UntrustedObject::incrementAj
*
* Increment Aj for the next log entry
*
* @author      Timothy Thong
*/
void UntrustedObject::incrementAj() {

  	unsigned char *newKey;
	cryptsuite::calcMD((unsigned char *) &Aj[0], AUTH_KEY_LEN, &newKey);
  	Aj.replace(0, AUTH_KEY_LEN, (const char *) newKey, AUTH_KEY_LEN);

  	delete[] newKey;
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
	bool app = _log.append(message, Aj);
	if (!app){
		throw std::runtime_error("Append Log returned false");
	}

	// increment Aj key
	incrementAj();

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
	bool close = _log.close(Aj);
	if (!close){
		throw std::runtime_error("Close Log returned false");
	}

	// increment Aj key
	incrementAj();

	return msgFact.get_message();

}

