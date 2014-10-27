#include "cryptsuite.hpp"

using namespace cryptsuite;

//FILE *fpErr = fopen(ERR_FILE, "a+");
FILE *fpErr = stderr;

int main(int argc, char** argv) {

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	// symmetric key
		
	unsigned char symKey[] = { 0x00, 0x01, 0x02, 0x03,
				   0xFF, 0xEE, 0xDD, 0xCC,
				   0xFF, 0xEE, 0xDD, 0xCC,
				   0xFF, 0xEE, 0xDD, 0xCC };

	// or unsigned char symKey[SYM_KEY_LEN];

	// pointer to buffers
	unsigned char *enc = NULL;
	unsigned char *dec = NULL;

	size_t enc_len = 0;
	size_t dec_len = 0;

	// loop index (buffer lengths are of size_t, do not use int)
	size_t i = 0;

	unsigned char plain[] = { 0xAA, 0xBB, 0xCC, 0xDD, 
				  0xEE, 0xFF, 0x01, 0x02 };
	// symmetric encryption
	enc_len = symEncrypt(plain, sizeof(plain), &enc, symKey); 

	printf("Encrypted:\n");
	for (i = 0; i < enc_len; i++) printf("0x%02X ", enc[i]);
	printf("\n\n");

	// symmetric decryption
	dec_len = symDecrypt(enc, enc_len, &dec, symKey);

	printf("Decrypted:\n");
	for (i = 0; i < dec_len; i++) printf("0x%02X ", dec[i]);
	printf("\n\n");

	// don't forget to free
	delete[] dec;
	delete[] enc;

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();


	// close error file
	fclose(fpErr);
	
	return 0;
}

