// gcc decrypt.c -lssl -lcrypto -o decrypt

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

void printhex(unsigned char *buf, size_t len) {
	size_t i;

	for (i = 0; i < len; ++i) {
		printf("%02X", buf[i]);
	}
}

void *base64_decode(void *param_1,size_t *param_2)
{
	const BIO_METHOD *type = BIO_f_base64();
	BIO *b;
	BIO *append;
	void *__s;
	int iVar1;
	size_t *local_10 [2];

	b = BIO_new(type);
	BIO_set_flags(b,0x100);
	append = BIO_new_mem_buf(param_1,-1);
	b = BIO_push(b,append);
	BIO_ctrl(b,0x73,0,local_10);
	__s = calloc(1,*local_10[0] + 1);

	memset(__s,0,*local_10[0]);
	*param_2 = *local_10[0];
	BIO_read(b,__s,*local_10[0]);
	BIO_free_all(b);

	return __s;
}



int main(int argc, char *argv[]) {
	if (argc != 2) {
		return 1;
	}

	char password[] = "ROOT_PASS_HERE";
	int pwlen = strlen(password);

	uint8_t salt[8] = {0x00,0x00,0x30,0x39,0x00,0x00,0xd4,0x31};

	uint8_t key[36];
	uint8_t iv[36];
	uint8_t plaintext[512];
	uint8_t rounds = 5;

	// Zero stuff
	memset(plaintext, '\x00', 512);
	memset(key, '\x00', 32);
	memset(iv, '\x00', 32);

	char *ciphertext_b64 = argv[1];
	
	// printf("ciphertext (b64): %s\n", ciphertext_b64);

	uint8_t *ciphertext;
	size_t ciphertextlen;

	ciphertext = base64_decode(ciphertext_b64, &ciphertextlen);

	// printf("ciphertext: ");
	// printhex(ciphertext, ciphertextlen);

	

	const EVP_CIPHER *type;
	const EVP_MD *md;

	// aes_init()
	type = EVP_aes_256_cbc();
	md = EVP_sha1();

	int res = EVP_BytesToKey(type,md,salt,password,pwlen,rounds,key,iv);

	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	EVP_DecryptInit_ex(ctx,type,(ENGINE *)0x0,key,iv);
	// ----

	// aes_decrypt()
	int plaintextlen = ciphertextlen;
	int len2;
	EVP_DecryptInit_ex(ctx,(EVP_CIPHER *)0x0,(ENGINE *)0x0,(void *)0x0,(void *)0x0);
	EVP_DecryptUpdate(ctx, plaintext, &plaintextlen, ciphertext, ciphertextlen);
	EVP_DecryptFinal_ex(ctx, plaintext + plaintextlen, &len2);
	ciphertextlen = plaintextlen + len2;

	// printf("\nplaintextlen : %d", plaintextlen);
	// printf("\nciphertextlen: %d", ciphertextlen);
	// printf("\nlen2:           %d", len2);

	printf("plaintext: %s", plaintext);

}
