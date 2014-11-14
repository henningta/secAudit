#include "UntrustedObject.hpp"
#include "debug.hpp"
#include "Message.hpp"
#include "Common.hpp"
#include <chrono>
#include <ctime>
#include <sstream>
#include <stdexcept>

extern FILE* fpErr;

UntrustedObject::UntrustedObject() {
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
	std::string			d_max_str;
	std::string			M0;
	std::string			D0;
	std::string			signedX0;
	std::string			X0DataSig;
	std::string			encX0Data;
	std::string			tmpStr;
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
		// TODO: Stop here?
	}
	CuLen = cryptsuite::x509ToDer(pemCert, &tmpBuf);
	tmpBuf = tmpBuf - CuLen;
	Cu = std::string((const char *) tmpBuf, CuLen);

	// get current timestamp d and set d+
	d_max = cryptsuite::getCurrentTimeStamp() + MAX_WAIT;
	d = std::to_string(d_max - MAX_WAIT);
	d_max_str = std::to_string(d_max);

	// setup X0 - p, d, Cu, A0
	X0 = p;
	X0.replace(X0.length(), d.length(), (const char *) &d[0], d.length());
	X0.replace(X0.length(), CuLen, (const char *) &Cu[0], CuLen);
	X0.replace(X0.length(), AUTH_KEY_LEN, (const char *) &A0[0], AUTH_KEY_LEN);

	// sign X0
	if ( ! msgFact.set_sign("SIGNED_X0", X0.length(), (unsigned char *) &X0[0], priv) ) {
		fprintf(fpErr, "Error: Could not sign X0\n");
		// TODO: Stop here?
	}

	// encrypt K0
	if ( ! msgFact.set_pkencrypt("ENCRYPTED_K0", SESSION_KEY_LEN,
					(unsigned char *) &K0[0], trustPub) ) {
		fprintf(fpErr, "Error: Could not encrypt K0\n");
		// TODO: Stop here?
	}

	//EK0( X0 || signedX0)
	M0part = msgFact.get_message();
	tmpVector = M0part.get_payload("SIGNED_X0");
	signedX0 = std::string(tmpVector.begin(), tmpVector.end());

	X0DataSig = X0;
	X0DataSig.replace(X0DataSig.length(), signedX0.length(),
			(const char *) &signedX0[0], signedX0.length());

	if ( ! msgFact.set_symencrypt("ENCRYPTED_X0_DATA", X0DataSig.length(),
			(unsigned char *) &X0DataSig[0], (unsigned char *) &K0[0]) ) {
		fprintf(fpErr, "Error: Could not do symmetric encryption\n");
		// TODO: Stop here?
	}

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

  	// add length markers for parsing later
        tmpStr = std::to_string(encX0Data.length());
        msgFact.set("ENCRYPTED_X0_DATA_LEN", tmpStr.length(), (unsigned char *) &tmpStr[0]);
        tmpStr = std::to_string(CuLen);
        msgFact.set("CULEN", tmpStr.length(), (unsigned char *) &tmpStr[0]);
        tmpStr = std::to_string(X0.length());
        msgFact.set("X0LEN", tmpStr.length(), (unsigned char *) &tmpStr[0]);

	// form D0 - d, d+, IDlog
	D0 = d;
	D0.replace(D0.length(), 1, " ", 1);
	D0.replace(D0.length(), d_max_str.length(),
			(const char *) &d_max_str[0], d_max_str.length());
	D0.replace(D0.length(), 1, " ", 1);
	D0.replace(D0.length(), logName.length(),
			(const char *) &logName[0], logName.length());
	//D0.replace(D0.length(), M0.length(),
	//		(const char *) &M0[0], M0.length());

	// set log name and open log
	_log.clear();
	_log.setName(logName);
	if (!_log.open(D0, Aj)) {
		throw std::runtime_error("Open Log returned false");
	}

	// increment Aj key
	incrementAj();

	// update own copy of hashedX0
	if ( ! cryptsuite::calcMD((unsigned char *) &X0[0], X0.length(), &tmpBuf) ) {
		fprintf(fpErr, "Failed to calculate hash of X0\n");
		// TODO: Stop here?
	}
	trustedHashedX0 = std::string((const char *) tmpBuf, MD_BYTES);

	// add log name to payload
	msgFact.set("logName", logName.length(), (unsigned char *) &logName[0]);


	/* DEBUG
        first4Last4("createLog K0", (unsigned char *) &K0[0], SESSION_KEY_LEN);
        first4Last4("createLog A0", (unsigned char *) &A0[0], AUTH_KEY_LEN);
        first4Last4("createLog X0", (unsigned char *) &X0[0], X0.length() );
        first4Last4("createLog X0||signedX0", (unsigned char *) &X0DataSig[0], X0DataSig.length());
	*/

	return msgFact.get_message();
}
/**
* UntrustedObject::verifyInitResponse
*
* The final step of startup- verify M1
*
* @author
*/
void UntrustedObject::verifyInitResponse(Message M1) {

	std::vector<unsigned char>      tmpVector;
        std::string                     K1;
        std::string                     decX1Data;
        std::string                     hashedX0;
	std::string			logName;
	std::string 			M1Entry;
	std::string			tmpStr;
        unsigned char 			*tmpBuf;
        size_t                          decBytes;
        size_t                          X1Len;
	bool				close_log;

        tmpVector = M1.get_payload("ENCRYPTED_K1");

        // obtain K1
        if ( ! cryptsuite::pkDecrypt((unsigned char *) &tmpVector[0],
					tmpVector.size(), &tmpBuf, priv) ) {
                fprintf(fpErr, "Error: Could not decrypt K1\n");
		close_log = true;
		goto err;
        }
        K1 = std::string((const char *) tmpBuf, SESSION_KEY_LEN);
        delete[] tmpBuf;

        // obtain X1 || signedX1
        tmpVector = M1.get_payload("ENCRYPTED_X1_DATA");
        decBytes = cryptsuite::symDecrypt((unsigned char *) &tmpVector[0],
					tmpVector.size(),&tmpBuf, (unsigned char *) &K1[0]);

        if (decBytes <= 0) {
                fprintf(fpErr, "Error: Failed to decrypt X1DATASIG\n");
		close_log = true;
		goto err;
        }

        decX1Data = std::string((const char *) tmpBuf, decBytes);
        delete[] tmpBuf;

        // verify X1 - p, IDlog, hashedX0
        tmpVector = M1.get_payload("X1LEN");
        tmpVector.push_back('\0');
        X1Len = atoi((const char *) &tmpVector[0]);

	logName = decX1Data.substr(1, decX1Data.length() - MD_BYTES - SIG_BYTES - 1);

	// verify X1
	if ( ! cryptsuite::verifySignature((unsigned char *) &decX1Data[0], X1Len,
					(unsigned char *) &decX1Data[0] + X1Len, trustPub) ) {
		fprintf(fpErr, "Error: Could not verify X1\n");
		close_log = true;
		goto err;
	}

        // obtain hashedX0
        hashedX0 = std::string((const char *) &decX1Data[0] + MSTATE_LEN + logName.length(), MD_BYTES);

	// verify hashedX0 with own copy
	if ( trustedHashedX0.compare(hashedX0) != 0 ) {
		fprintf(fpErr, "Error: Hash verification failed\n");
		close_log = true;
		goto err;
	}

        // message is stale
        if (cryptsuite::getCurrentTimeStamp() > d_max) {
		fprintf(fpErr, "Received stale response from T\n");
		close_log = true;
		goto err;
        }

	// form a new log entry with a 'M1 verified message'
	// as opposed to Dj = M1
	addEntry("M1_verified", LOG_ENTRY_APPEND);

	/* DEBUG
        first4Last4("verifyResp K1", (unsigned char *) &K1[0], SESSION_KEY_LEN);
        first4Last4("verifyResp X1||signedX1", (unsigned char *) &decX1Data[0], decX1Data.length());
	*/

err:
	// abnormal close type according to spec
	if (close_log) {
		std::string ts = std::to_string(cryptsuite::getCurrentTimeStamp());
		std::string reason = "M1_INVALID_OR_EXCEEDED_MAX_WAIT";

		addEntry(ts + " " + reason, LOG_ENTRY_ABNORMAL_CLOSE);
		closeLog();

	}

}

/**
* UntrustedObject::incrementAj
*
* Increment Aj for the next log entry
*
* @author      Timothy Thong
*/
void UntrustedObject::incrementAj() {
	Aj = Common::incrementHash(Aj, 1);
}

/**
 * UntrustedObject::addEntry
 *
 * Adds entry with provided message to log by calling _log member's append
 * function
 *
 * @param 	message 	the message of the log entry to be appended
 * @return 	Message
 * @author 	Travis Henning , Jackson Reed
 */
Message UntrustedObject::addEntry(const std::string & message, const EntryType ENTRY_TYPE) {
	bool app = _log.append(message, Aj, ENTRY_TYPE);
	if (!app) {
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
	if (!close) {
		throw std::runtime_error("Close Log returned false");
	}

	// insert entries vector into map of closed entries by log name
	_closedLogEntries.insert(
			std::make_pair(_log.getLogName(), _log.getEntries()));

	// increment Aj key
	incrementAj();

	return msgFact.get_message();
}

