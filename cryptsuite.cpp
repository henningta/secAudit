/**
  cryptsuite.cpp
  
  Functions related to signing/verification, encryption/decryption
  and certificates.

  @author(s) Timothy Thong

*/
	
// TODO: - Use malloc for all enryptions (and decryptions?)
//	 - Move genLogID and getCurrentTimeStamp to more log-related code?

#include "cryptsuite.hpp"

extern FILE *fpErr;

namespace cryptsuite {

/**

  loadRSAPublicKey

  Loads an RSA public key into an EVP_PKEY struct for high-level
  EVP functions.

  @param keyPath The path to the public key file
  @param pkey    Address of pointer to the EVP_PKEY struct

  @return        0 if successful, -1 otherwise

*/
int loadRSAPublicKey(const char *keyPath, EVP_PKEY **pkey) {

	FILE 		*fpub;
	RSA 		*rsaPub;
	int		ret;

	ret = 0;

	rsaPub = RSA_new();

	if ( (fpub = fopen(keyPath, "r")) == NULL ) {
		ret = -1;
		goto err;
	}

	// read public key formatted in X509 style
	PEM_read_RSA_PUBKEY(fpub, &rsaPub, NULL, NULL);
	if (rsaPub == NULL) {
		ret = -1;
		goto err;
	}

	// allocate key for use in EVP functions
	if ( ! EVP_PKEY_set1_RSA(*pkey, rsaPub) ) {
		ret = -1;
		goto err;
	}
err:
	ERR_print_errors_fp(fpErr);

	// clean up
	if (rsaPub)
		RSA_free(rsaPub);
	if (fpub)
		fclose(fpub);

	return ret;

}

/**

  loadRSAPrivateKey

  Loads an RSA private key into an EVP_PKEY struct for high-level
  EVP functions.

  @param keyPath  The path to the private key file
  @param pkey     Address of pointer to the EVP_PKEY struct

  @return         0 if successful, -1 otherwise

*/
int loadRSAPrivateKey(const char *keyPath, EVP_PKEY **pkey) {

	FILE		*fpriv;
	RSA 		*rsaPriv;
	int		ret;

	ret = 0;

	rsaPriv = RSA_new();

	if ( (fpriv = fopen(keyPath, "r")) == NULL ) {
		ret = -1;
		goto err;
	}

	// read private key in traditional format
	PEM_read_RSAPrivateKey(fpriv, &rsaPriv, NULL, NULL);

	if (rsaPriv == NULL) {
		ret = -1;
		goto err;
	}

	// allocate key for use in EVP functions
	if ( ! EVP_PKEY_set1_RSA(*pkey, rsaPriv) ) {
		ret = -1;
		goto err;
	}
err:
	ERR_print_errors_fp(fpErr);

	// clean up
	if (rsaPriv)
		RSA_free(rsaPriv);
	if (fpriv)
		fclose(fpriv);

	return ret;
}

/**

  loadX509Cert

  Loads a PEM-encoded X509 certificate

  @param certPath   The path to the certificate
  @param crt        Address of pointer to the X509 struct

  @return           0 if successful, -1 otherwise

*/
int loadX509Cert(const char *certPath, X509 **crt) {
	
	FILE		*fpCrt;
	int		ret;

	ret = 0;
	
	if( (fpCrt = fopen(certPath, "r")) == NULL ) {
		ret = -1;
		goto err;
	}

	if ( (*crt = PEM_read_X509(fpCrt, NULL, NULL, NULL)) == NULL ) {
		ret = -1;
		goto err;
	}
err:
	ERR_print_errors_fp(fpErr);

	// clean up
	if (fpCrt)
		fclose(fpCrt);

	return ret;
}

/**

  createSignature

  Outputs a signed message digest from a message

  @param in     Plaintext
  @param inLen  Length of the plaintext
  @param out    Digital signature buffer
  @param pkey   Private key

  @return      0 if successful, -1 otherwise

*/
int createSignature(unsigned char *in, int inLen, unsigned char *out, EVP_PKEY *pkey) {

	size_t		sigLen;
	unsigned char 	sig[sigLen];
	EVP_MD_CTX 	*mdctx;
	int 		ret;
	
	sigLen = SIG_BYTES;
	mdctx = NULL;
	ret = 0;

	// create and initialize Message Digest Context
	if ( ! (mdctx = EVP_MD_CTX_create()) ) {
		ret = -1;
		goto err;
	}

	// initialize the signing operation
	if ( EVP_DigestSignInit(mdctx, NULL, SIG_MD_ALGO, NULL, pkey) != 1 ) {
		ret = -1;
		goto err;
	}

	// update the message
	if ( EVP_DigestSignUpdate(mdctx, in, inLen) != 1 ) {
		ret = -1;
		goto err;
	}
	
	// obtain the signature
	if ( EVP_DigestSignFinal(mdctx, sig, &sigLen) != 1 ){
		ret = -1;
		goto err;
	}

	// copy signature to buffer for verification
	memcpy(out, sig, SIG_BYTES);

err:	
	ERR_print_errors_fp(fpErr);

	// clean up
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);

	return ret;
}

/**

  verifySignature

  Verifies a signed message digest by hashing the plaintext
  and comparing the output with the decrypted one

  @param in     Plaintext
  @param inLen  Length of the plaintext
  @param sig    Digital signature buffer
  @param pkey   Public key

  @return      0 if successful, -1 otherwise

*/
int verifySignature(unsigned char *in, int inLen, unsigned char *sig, EVP_PKEY *pkey) {

	size_t		sigLen;
	EVP_MD_CTX 	*mdctx;
	int 		ret;
	
	sigLen = SIG_BYTES;
	mdctx = NULL;
	ret = 0;

	// create and initialize Message Digest Context
	if ( ! (mdctx = EVP_MD_CTX_create()) ) {
		ret = -1;
		goto err;
	}

	// initialize the verification operation
	if ( EVP_DigestVerifyInit(mdctx, NULL, SIG_MD_ALGO, NULL, pkey) != 1 ) {
		ret = -1;
		goto err;
	}

	// hash plain data into verification context mdctx
	if ( EVP_DigestVerifyUpdate(mdctx, in, inLen) != 1 ) {
		ret = -1;
		goto err;
	}

	// verify data using pkey against the bytes in sig buffer
	if ( EVP_DigestVerifyFinal(mdctx, sig, sigLen) != 1 ) {
		ret = -1;
		goto err;
	}

err:
	ERR_print_errors_fp(fpErr);

	// clean up
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);

	return ret;
}

/**

  pkEncrypt

  Performs a public-key encryption of a message

  @param in     Plaintext
  @param inLen  Length of the plaintext
  @param out    Encrypted output
  @param pkey   Public key

  @return      0 if successful, -1 otherwise

*/
int pkEncrypt(unsigned char *in, int inLen, unsigned char *out, EVP_PKEY *pkey) {
	EVP_PKEY_CTX 	*ctx;
	size_t 		outlen;
	int		ret;
	
	ret = 0;
	
	if ( ! (ctx = EVP_PKEY_CTX_new(pkey, NULL)) ) {
		ret = -1;
		goto err;
	}

	if ( EVP_PKEY_encrypt_init(ctx) != 1) {
		ret = -1;
		goto err;
	}
	if ( EVP_PKEY_encrypt(ctx, out, &outlen, in, inLen) != 1 ) {
		ret = -1;
		goto err;
	}

err:
	ERR_print_errors_fp(fpErr);
	
	
	return ret;
}

/**

  pkDecrypt

  Performs a public-key decryption of a message

  @param in     Plaintext
  @param inLen  Length of the plaintext
  @param out    Decrypted output
  @param pkey   Private key

  @return      0 if successful, -1 otherwise

*/
int pkDecrypt(unsigned char *in, int inLen, unsigned char *out, EVP_PKEY *pkey) {

	EVP_PKEY_CTX 	*ctx;
	size_t 		outlen;
	int		ret;
	
	ret = 0;
	
	if ( ! (ctx = EVP_PKEY_CTX_new(pkey, NULL)) ) {
		ret = -1;
		goto err;
	}

	if ( EVP_PKEY_decrypt_init(ctx) != 1) {
		ret = -1;
		goto err;
	}

	if ( EVP_PKEY_decrypt(ctx, out, &outlen, in, inLen) != 1 ) {
		ret = -1;
		goto err;
	}
err:
	ERR_print_errors_fp(fpErr);
	
	return ret;
}

/**

  symEncrypt

  Performs a symmetric encryption of a message. The 
  cipher, mode and key length used are specified in
  the header file and can be changed accordingly

  @param in      Plaintext
  @param inLen   Length of the plaintext
  @param key     Key (Refer to header file for recommended length)
  @param out     Encrypted buffer (size should be >= inLen + 1 block size)
  @param outLen  Bytes written to encrypted buffer

  @return      0 if successful, -1 otherwise

*/
int symEncrypt(unsigned char *in, int inLen, unsigned char *key, unsigned char *out, int *outLen) {

	EVP_CIPHER_CTX *ctx;
	int tmpLen;
	int ret;
	
	ret = 0;

	// create and initalize context
	if ( ! (ctx = EVP_CIPHER_CTX_new()) ){
		ret = -1;
		goto err;
	}

	// initialize encryption operation (not using an IV)	
	if ( EVP_EncryptInit_ex(ctx, SYM_ALGO, NULL, key, NULL) != 1) {
		ret = -1;
		goto err;
	}

	// encrypt message
	if ( EVP_EncryptUpdate(ctx, out, &tmpLen, in, inLen) != 1 ) {
		ret = -1;
		goto err;
	}
	*outLen = tmpLen;

	// finalize encryption
	if ( EVP_EncryptFinal_ex(ctx, out + tmpLen, &tmpLen) != 1) {
		ret = -1;
		goto err;
	}
	*outLen += tmpLen;
	
err:
	ERR_print_errors_fp(fpErr);

	// clean up
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	return ret;
}

/**

  symDecrypt

  Performs a symmetric decryption of a message. The 
  cipher, mode and key length used are specified in
  the header file and can be changed accordingly

  @param in      Plaintext
  @param inLen   Length of the plaintext
  @param key     Key (same key used in symEncrypt)
  @param out     Decrypted buffer
  @param outLen  Bytes written to decrypted buffer

  @return      0 if successful, -1 otherwise

*/
int symDecrypt(unsigned char *in, int inLen, unsigned char *key, unsigned char *out, int *outLen) {

	EVP_CIPHER_CTX *ctx;
	int tmpLen;
	int ret;
	
	ret = 0;

	// create and initalize context
	if ( ! (ctx = EVP_CIPHER_CTX_new()) ){
		ret = -1;
		goto err;
	}

	// initialize decryption operation (not using an IV)	
	if ( EVP_DecryptInit_ex(ctx, SYM_ALGO, NULL, key, NULL) != 1) {
		ret = -1;
		goto err;
	}

	// decrypt message
	if ( EVP_DecryptUpdate(ctx, out, &tmpLen, in, inLen) != 1 ) {
		ret = -1;
		goto err;
	}
	*outLen = tmpLen;

	// finalize decryption
	if ( EVP_DecryptFinal_ex(ctx, out + tmpLen, &tmpLen) != 1) {
		ret = -1;
		goto err;
	}
	*outLen += tmpLen;
	
err:
	ERR_print_errors_fp(fpErr);

	// clean up
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	
	return ret;
}

/**

  genLogID 

  Generates a new log ID based on the date and time
  in the following format: YYYYMMDD_HHMM_SS

  @param id     string buffer for the ID

  @return      0 if successful, -1 otherwise

*/
int genLogID(unsigned char *id) {
	time_t 		t;
	struct tm 	*tmp;

	t = time(NULL);
	tmp = localtime(&t);

	strftime((char *) id, LOG_ID_LEN , "%Y%m%d_%k%M_%S", tmp);

	return 0;
}

/**

  getCurrentTimeStamp

  Gets the current time in expressed in seconds since Jan 1 1970.
  Used as a time reference in the creation of a log

  @return  Time in seconds

*/
long int getCurrentTimeStamp(void) {
	struct 		timeval tv;

  	gettimeofday(&tv, NULL);
	
	return tv.tv_sec;
}

} // namespace cryptsuite

