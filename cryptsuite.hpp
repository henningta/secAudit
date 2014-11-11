#ifndef __CRYPTSUITE_HPP__
#define __CRYPTSUITE_HPP__

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <sys/time.h>

// ID strings of servers
#define T_ID			"Trusted_Server"
#define U_ID			"Untrusted_Server"

// locations of keys and certs
#define TRUSTED_PRIV		"keys/trusted.priv"
#define TRUSTED_PUB		"keys/trusted.pub"
#define TRUSTED_CERT		"keys/trusted.cert"
#define UNTRUSTED_PRIV		"keys/untrusted.priv"
#define UNTRUSTED_PUB		"keys/untrusted.pub"
#define UNTRUSTED_CERT  	"keys/untrusted.cert"

// message digest algorithm for hashing. MD_BYTES
// is tied to the algorithm used. Changes made to
// MD_ALGO must also be made to MD_BYTES
#define MD_ALGO			EVP_sha256()
#define MD_BYTES		32

// HMAC constants
// only EVP_sha1 and EVP_ripemd160 are allowed
#define HMAC_MD_ALGO		EVP_sha1()
#define HMAC_BYTES		20

// signature constants.
// chosen message digest algorithm and length (2048-bit key)
// algorithm can be changed, but SIG_BYTES must remain
// the same because of our 2048-bit key
#define SIG_MD_ALGO		EVP_sha512()
#define SIG_BYTES		256

// encrypted output for public-key encryption
// value will always be the same as SIG_BYTES
#define PK_ENC_BYTES		256

// chosen symmetric cipher and mode
// all 3 constants need to be updated if there is any change in the cipher
// or mode
#define SYM_ALGO		EVP_aes_128_cbc()
#define SYM_KEY_LEN		16
#define SYM_BLK_SIZE		16

// sizes for initialization
#define SESSION_KEY_LEN		16		// k0 and k1
#define AUTH_KEY_LEN		32		// must be the same as MD_BYTES
#define LOG_ID_LEN		17		// includes space for \0
#define MAX_WAIT		5		// seconds before timeout
#define TSTMP_LEN		10		// timestamp len as a string

#define	ERR_FILE		"err_log"

namespace cryptsuite {

// public key functions
int loadRSAPublicKey(const char *keyPath, EVP_PKEY **pkey);
int loadRSAPrivateKey(const char *keyPath, EVP_PKEY **pkey);
size_t pkEncrypt(unsigned char *in, size_t inLen, unsigned char **out, EVP_PKEY *pkey);
size_t pkDecrypt(unsigned char *in, size_t inLen, unsigned char **out, EVP_PKEY *pkey);

// X509 certificate functions
int loadX509Cert(const char *certPath, X509 **cert);
size_t x509ToDer(X509 *crt, unsigned char **dst);
X509* derToX509(unsigned char *der, size_t derLen);

// signature functions
int createSignature(unsigned char *in, size_t inLen, unsigned char **sig, EVP_PKEY *pkey);
int verifySignature(unsigned char *in, size_t inLen, unsigned char *sig, EVP_PKEY *pkey);

// symmetric encryption functions
size_t symEncrypt(unsigned char *in, size_t inLen, unsigned char **out, unsigned char *key);
size_t symDecrypt(unsigned char *in, size_t inLen, unsigned char **out, unsigned char *key);

// hash and MAC functions
int calcMD(unsigned char *in, size_t inLen, unsigned char **out);
int calcHMAC(unsigned char *in, size_t inLen, unsigned char **out, unsigned char *key, size_t keyLen);

// utilities
int genRandBytes(unsigned char *in, size_t len);

// in this namespace for now
int genLogID(unsigned char *id);
long int getCurrentTimeStamp(void);

}

#endif // __CRYPTSUITE_HPP__

