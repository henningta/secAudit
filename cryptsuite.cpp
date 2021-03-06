/**
  cryptsuite.cpp

  Functions related to signing/verification, encryption/decryption
  and certificates.

  @author Timothy Thong

*/

#include "cryptsuite.hpp"

#define REDIRECT_ERR // comment-out this line to use external file
#ifdef REDIRECT_ERR
	FILE *fpErr = stdout;
#else
	extern FILE *fpErr;
#endif

namespace cryptsuite {

/**

  loadRSAPublicKey

  Loads an RSA public key into an EVP_PKEY struct for high-level
  EVP functions.

  @param keyPath The path to the public key file
  @param pkey    Address of pointer to the EVP_PKEY struct

  @return        1 if successful, 0 otherwise

*/
int loadRSAPublicKey(const char *keyPath, EVP_PKEY **pkey) {

	FILE 		*fpub;
	RSA 		*rsaPub;
	int		ret;

	ret = 1;

	rsaPub = RSA_new();

	if ( (fpub = fopen(keyPath, "r")) == NULL ) {
		fprintf(fpErr, "loadRSAPublicKey: '%s' does not exist\n", keyPath);
		ret = 0;
		goto err;
	}

	// read public key formatted in X509 style
	PEM_read_RSA_PUBKEY(fpub, &rsaPub, NULL, NULL);
	if (rsaPub == NULL) {
		fprintf(fpErr, "loadRSAPublicKey: Fail to read '%s'\n", keyPath);
		ret = 0;
		goto err;
	}

	// allocate key for use in EVP functions
	if ( ! EVP_PKEY_set1_RSA(*pkey, rsaPub) ) {
		fprintf(fpErr, "loadRSAPublicKey: Fail to set key in EVP_PKEY\n");
		ret = 0;
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

  @return         1 if successful, 0 otherwise

*/
int loadRSAPrivateKey(const char *keyPath, EVP_PKEY **pkey) {

	FILE		*fpriv;
	RSA 		*rsaPriv;
	int		ret;

	ret = 1;

	rsaPriv = RSA_new();

	if ( (fpriv = fopen(keyPath, "r")) == NULL ) {
		fprintf(fpErr, "loadRSAPrivateKey: '%s' does not exist\n", keyPath);
		ret = 0;
		goto err;
	}

	// read private key in traditional format
	PEM_read_RSAPrivateKey(fpriv, &rsaPriv, NULL, NULL);
	if (rsaPriv == NULL) {
		fprintf(fpErr, "loadRSAPrivateKey: Fail to read '%s'\n", keyPath);
		ret = 0;
		goto err;
	}

	// allocate key for use in EVP functions
	if ( ! EVP_PKEY_set1_RSA(*pkey, rsaPriv) ) {
		fprintf(fpErr, "loadRSAPrivateKey: Fail to set key in EVP_PKEY\n");
		ret = 0;
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

  @return           1 if successful, 0 otherwise

*/
int loadX509Cert(const char *certPath, X509 **crt) {

	FILE		*fpCrt;
	int		ret;

	ret = 1;

	if( (fpCrt = fopen(certPath, "r")) == NULL ) {
		fprintf(fpErr, "loadX509Cert: '%s' does not exist\n", certPath);
		ret = 0;
		goto err;
	}

	if ( (*crt = PEM_read_X509(fpCrt, NULL, NULL, NULL)) == NULL ) {
		fprintf(fpErr, "loadX509Cert: Fail to read '%s'\n", certPath);
		ret = 0;
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

  x509ToDer

  Encodes a PEM certificate into DER format

  @param crt	X509 cert
  @param dst 	buffer

  @return       length of bytes written to buffer

*/
size_t x509ToDer(X509 *crt, unsigned char **dst) {
        int len;
        unsigned char *buf;
        
        len = i2d_X509(crt, NULL);
        buf = new unsigned char[len];
        
        if (buf == NULL)
                fprintf(fpErr, "Error: Could not convert to DER cert\n");

        *dst = buf;
        i2d_X509(crt, dst);

        return len;
}

/**

  derToX509 

  Re-encode a DER formatted certificate into PEM format

  @param der		DER formatted cert
  @param derLen 	length of the cert

  @return       	PEM formatted cert, NULL otherwise

*/
X509* derToX509(unsigned char *der, size_t derLen) {

        unsigned char *p;
        X509 *decoded;

        p = der;
        decoded = NULL;
        decoded = d2i_X509(NULL, (const unsigned char **) &p, derLen);

        if (decoded == NULL)
                printf("Error: Could not convert to X509 cert\n");

        return decoded;
}

/**

  createSignature

  Outputs a signed message digest from a message

  @param in     Plaintext
  @param inLen  Length of the plaintext
  @param out    Digital signature buffer
  @param pkey   Private key

  @return       1 if successful, 0 otherwise

*/
int createSignature(unsigned char *in, size_t inLen, unsigned char **sig, EVP_PKEY *pkey) {

	size_t		sigLen;
	EVP_MD_CTX 	*mdctx;
	int		bufAllocated;
	int 		ret;

	sigLen = SIG_BYTES;
	mdctx = NULL;
	bufAllocated = 0;
	ret = 1;

	*sig = new unsigned char[SIG_BYTES];
	if (*sig == NULL) {
		fprintf(fpErr, "createSignature: Cannot allocate buffer\n");
		ret = 0;
		goto err;
	}
	memset(*sig, '\0', sigLen);
	bufAllocated = 1;

	// create and initialize Message Digest Context
	if ( ! (mdctx = EVP_MD_CTX_create()) ) {
		fprintf(fpErr, "createSignature: Cannot create MD context\n");
		ret = 0;
		goto err;
	}

	// initialize the signing operation
	if ( EVP_DigestSignInit(mdctx, NULL, SIG_MD_ALGO, NULL, pkey) != 1 ) {
		fprintf(fpErr, "createSignature: Cannot init signing operation\n");
		ret = 0;
		goto err;
	}

	// update the message
	if ( EVP_DigestSignUpdate(mdctx, in, inLen) != 1 ) {
		fprintf(fpErr, "createSignature: Cannot sign\n");
		ret = 0;
		goto err;
	}

	// obtain the signature
	if ( EVP_DigestSignFinal(mdctx, *sig, &sigLen) != 1 ) {
		fprintf(fpErr, "createSignature: Cannot complete signing\n");
		ret = 0;
		goto err;
	}

err:
	ERR_print_errors_fp(fpErr);

	// clean up
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);

	if (ret == 0 && bufAllocated == 1) {
		delete[] *sig;
		*sig = NULL;
	}

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

  @return       1 if successful, 0 otherwise

*/
int verifySignature(unsigned char *in, size_t inLen, unsigned char *sig, EVP_PKEY *pkey) {

	size_t		sigLen;
	EVP_MD_CTX 	*mdctx;
	int 		ret;

	sigLen = SIG_BYTES;
	mdctx = NULL;
	ret = 1;

	// create and initialize Message Digest Context
	if ( ! (mdctx = EVP_MD_CTX_create()) ) {
		fprintf(fpErr, "verifySignature: Cannot create MD context\n");
		ret = 0;
		ret = 0;
		goto err;
	}

	// initialize the verification operation
	if ( EVP_DigestVerifyInit(mdctx, NULL, SIG_MD_ALGO, NULL, pkey) != 1 ) {
		fprintf(fpErr, "verifySignature: Cannot init verification operation\n");
		ret = 0;
		goto err;
	}

	// hash plain data into verification context mdctx
	if ( EVP_DigestVerifyUpdate(mdctx, in, inLen) != 1 ) {
		fprintf(fpErr, "verifySignature: Cannot verify\n");
		ret = 0;
		goto err;
	}

	// verify data using pkey against the bytes in sig buffer
	if ( EVP_DigestVerifyFinal(mdctx, sig, sigLen) != 1 ) {
		fprintf(fpErr, "verifySignature: Cannot complete verification\n");
		ret = 0;
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

  @return       Number of bytes encrypted into out, 0 otherwise
*/
size_t pkEncrypt(unsigned char *in, size_t inLen, unsigned char **out, EVP_PKEY *pkey) {

	EVP_PKEY_CTX 	*ctx;
	size_t 		outLen;
	int		outAllocated;

	outLen = 0;
	outAllocated = 0;

	// create public key context
	if ( ! (ctx = EVP_PKEY_CTX_new(pkey, NULL)) ) {
		fprintf(fpErr, "pkEncrypt: Cannot create P_KEY context\n");
		goto err;
	}

	// initialize context
	if ( EVP_PKEY_encrypt_init(ctx) != 1) {
		fprintf(fpErr, "pkEncrypt: Cannot initialize P_KEY context\n");
		goto err;
	}

	// determine number of bytes to store encrypted message
	if ( EVP_PKEY_encrypt(ctx, NULL, &outLen, in, inLen) != 1 ) {
		fprintf(fpErr, "pkEncrypt: Cannot determine encrypted length\n");
		goto err;
	}

	*out = new unsigned char[outLen];
	if (*out == NULL) {
		fprintf(fpErr, "pkEncrypt: Cannot allocate buffer\n");
		outLen = 0;
		goto err;
	}
	memset(*out, '\0', outLen);
	outAllocated = 1;

	// send encrypted bytes to the out buffer
	if ( EVP_PKEY_encrypt(ctx, *out, &outLen, in, inLen) != 1 ) {
		fprintf(fpErr, "pkEncrypt: Cannot encrypt\n");
		outLen = 0;
		goto err;
	}
err:
	ERR_print_errors_fp(fpErr);

	// clean up
	if (outLen == 0 && outAllocated == 1)
		delete[] *out;

	if (ctx)
		EVP_PKEY_CTX_free(ctx);

	return outLen;
}

/**

  pkDecrypt

  Performs a public-key decryption of a message

  @param in      Ciphertext
  @param inLen   Length of the ciphertext
  @param out     Pointer to decrypted output
  @param pkey    Private key

  @return        1 if successful, 0 otherwise

*/
size_t pkDecrypt(unsigned char *in, size_t inLen, unsigned char **out, EVP_PKEY *pkey) {

	EVP_PKEY_CTX 	*ctx;
	size_t		outLen;
	int		outAllocated;

	outLen = 0;
	outAllocated = 0;

	// create public key context
	if ( ! (ctx = EVP_PKEY_CTX_new(pkey, NULL)) ) {
		fprintf(fpErr, "pkDecrypt: Cannot create P_KEY context\n");
		goto err;
	}

	// initalize context
	if ( EVP_PKEY_decrypt_init(ctx) != 1) {
		fprintf(fpErr, "pkDecrypt: Cannot initialize P_KEY context\n");
		goto err;
	}

	// determine number of bytes needed to store decrypted message
	if ( EVP_PKEY_decrypt(ctx, NULL, &outLen, in, inLen) != 1 ) {
		fprintf(fpErr, "pkDecrypt: Cannot determine decrypted length\n");
		goto err;
	}

	*out = new unsigned char[outLen];
	if (*out == NULL) {
		fprintf(fpErr, "pkDecrypt: Cannot allocate buffer\n");
		outLen = 0;
		goto err;
	}
	memset(*out, '\0', outLen);
	outAllocated = 1;

	// send the decrypted bytes to the out buffer
	if ( EVP_PKEY_decrypt(ctx, *out, &outLen, in, inLen) != 1 ) {
		fprintf(fpErr, "pkDecrypt: Cannot decrypt\n");
		outLen = 0;
		goto err;
	}

err:
	ERR_print_errors_fp(fpErr);

	if (outLen == 0 && outAllocated == 1)
		delete[] *out;

	// clean up
	if (ctx)
		EVP_PKEY_CTX_free(ctx);

	return outLen;
}

/**

  symEncrypt

  Performs a symmetric encryption of a message. The
  cipher, mode and key length used are specified in
  the header file and can be changed accordingly

  @param in      Plaintext
  @param inLen   Length of the plaintext
  @param out     Encrypted buffer (size should be >= inLen + 1 block size)
  @param key     Key (Refer to header file for recommended length)

  @return        Number of bytes encrypted into out, 0 otherwise
*/
size_t symEncrypt(unsigned char *in, size_t inLen, unsigned char **out, unsigned char *key) {

	EVP_CIPHER_CTX *ctx;
	int		tmpLen;
	size_t 		outLen;
	size_t 		maxLen;

	outLen = 0;
	maxLen = inLen + SYM_BLK_SIZE - 1;

	*out = new unsigned char[maxLen];
	memset(*out, '\0', maxLen);

	// create and initalize context
	if ( ! (ctx = EVP_CIPHER_CTX_new()) ){
		fprintf(fpErr, "symEncrypt: Cannot create EVP_CIPHER context\n");
		goto err;
	}

	// initialize encryption operation (not using an IV)
	if ( EVP_EncryptInit_ex(ctx, SYM_ALGO, NULL, key, NULL) != 1 ) {
		fprintf(fpErr, "symEncrypt: Cannot init encryption\n");
		goto err;
	}

	// send encrypted bytes to out buffer
	if ( EVP_EncryptUpdate(ctx, *out, &tmpLen, in, inLen) != 1 ) {
		fprintf(fpErr, "symEncrypt: Cannot encrypt\n");
		outLen = 0;
		goto err;
	}
	outLen = (size_t) tmpLen;

	// finalize encryption
	if ( EVP_EncryptFinal_ex(ctx, *out + tmpLen, &tmpLen) != 1 ) {
		fprintf(fpErr, "symEncrypt: Cannot complete encryption\n");
		outLen = 0;
		goto err;
	}
	outLen += tmpLen;

err:
	ERR_print_errors_fp(fpErr);

	// clean up
	if (outLen == 0)
		delete[] *out;

	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	return outLen;
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

  @return        Number of bytes dencrypted into out, 0 otherwise

*/
size_t symDecrypt(unsigned char *in, size_t inLen, unsigned char **out, unsigned char *key) {

	EVP_CIPHER_CTX *ctx;
	int tmpLen;
	size_t outLen;
	size_t maxLen;

	outLen = 0;
	maxLen = inLen + SYM_BLK_SIZE;

	*out = new unsigned char[maxLen];
	memset(*out, '\0', maxLen);

	// create and initalize context
	if ( ! (ctx = EVP_CIPHER_CTX_new()) ){
		fprintf(fpErr, "symDecrypt: Cannot create EVP_CIPHER context\n");
		goto err;
	}

	// initialize decryption operation (not using an IV)
	if ( EVP_DecryptInit_ex(ctx, SYM_ALGO, NULL, key, NULL) != 1 ) {
		fprintf(fpErr, "symDecrypt: Cannot init decryption\n");
		goto err;
	}

	// send decrypted bytes to out buffer
	if ( EVP_DecryptUpdate(ctx, *out, &tmpLen, in, inLen) != 1 ) {
		fprintf(fpErr, "symDecrypt: Cannot decrypt\n");
		outLen = 0;
		goto err;
	}
	outLen = tmpLen;

	// finalize decryption
	if ( EVP_DecryptFinal_ex(ctx, *out + tmpLen, &tmpLen) != 1 ) {
		fprintf(fpErr, "symDecrypt: Cannot complete decryption\n");
		outLen = 0;
		goto err;
	}
	outLen += tmpLen;

err:
	ERR_print_errors_fp(fpErr);

	// clean up
	if (outLen == 0)
		delete[] *out;

	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	return outLen;
}

/**

  calcMD 

  Calculates a message digest sepecified by MD_ALGO.
  Length of digest output is specified by MD_BYTES.
  
  @param in      input
  @param inLen   length of input
  @param out     pointer to message digest buffer

  @return        1 for success, 0 otherwise

*/
int calcMD(unsigned char *in, size_t inLen, unsigned char **out)
{
	EVP_MD_CTX *mdctx;
	int ret;
	unsigned int outLen;
	
	ret = 1;
	*out = new unsigned char[MD_BYTES];
	if (*out == NULL) { 
		fprintf(fpErr,"Error: Cannot allocate buffer\n");
		ret = 0;
		goto err;
	}
	memset(*out, '\0', MD_BYTES);

	if ( ( mdctx = EVP_MD_CTX_create() ) == NULL) {
		fprintf(fpErr, "Error: Cannot create EVP_MD context\n");
		ret = 0;
		goto err;
	}

	if ( EVP_DigestInit_ex(mdctx, MD_ALGO, NULL) != 1 ) {
		fprintf(fpErr, "Error: Cannot init EVP_MD context\n");
		ret = 0;
		goto err;
	}

	if ( EVP_DigestUpdate(mdctx, in, inLen) != 1) {
		fprintf(fpErr, "Error: Cannot update message digest\n");
		ret = 0;
		goto err;
	}

	if ( EVP_DigestFinal_ex(mdctx, *out, &outLen) != 1 ) {
		fprintf(fpErr, "Error: Cannot finalize message digest\n");
		ret = 0;
		goto err;
	}

err:
	ERR_print_errors_fp(fpErr);

	// clean up
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);

	if (ret == 0 && *out != NULL)
		delete[] *out;

	return ret;
}

/**

  calcHMAC 

  Calculates a message digest sepecified by HMAC_MD_ALGO
  and the key. Length of digest output is specified by HMAC_BYTES.
  
  @param in      input
  @param inLen   length of input
  @param out     pointer to HMAC buffer
  @param key	 key to be used for HMAC
  @param keyLen  key length

  @return        1 for success, 0 otherwise

*/
int calcHMAC(unsigned char *in, size_t inLen, unsigned char **out, unsigned char *key, size_t keyLen) {

    HMAC_CTX *hctx = HMAC_CTX_new();
	int ret;
	unsigned int outLen;

	ret = 1;

	*out = new unsigned char[HMAC_BYTES];
	if (*out == NULL) {
		ret = 0;
		fprintf(fpErr, "Error: Failed to allocate buffer\n");
		goto err;
	}
	memset(*out, '\0', HMAC_BYTES);

	if ( HMAC_Init_ex(hctx, key, keyLen, HMAC_MD_ALGO, NULL) != 1) {
		ret = 0;
		fprintf(fpErr, "Error: Failed to init HMAC context\n");
		goto err;
	}

	if ( HMAC_Update(hctx, in, inLen) != 1) {
		ret = 0;
		fprintf(fpErr, "Error: Failed to update HMAC\n");
		goto err;
	}

	if ( HMAC_Final(hctx, *out, &outLen) != 1) {
		ret = 0;
		fprintf(fpErr, "Error: Failed to finalize HMAC\n");
		goto err;

	}

err:
	ERR_print_errors_fp(fpErr);

	// clean up
	HMAC_CTX_free(hctx);
	
	if (ret == 0 && *out != NULL)
		delete[] *out;

	return ret;
}

/**

  genRandBytes

  Generates random bytes up to a specified length

  @param id     random byte buffer
  @param len	number of random bytes to generate
  @return       1 if successful, 0 otherwise

*/
int genRandBytes(unsigned char *in, size_t len) {
 
	if ( ! RAND_bytes(in, len) ) {
 		fprintf(fpErr, "Error: Failed to generate random bytes\n");
		 return 0;
 	}
	return 1;
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

