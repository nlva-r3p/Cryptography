#include <openssl/evp.h>
#include <openssl/provider.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <stdexcept>

static const unsigned char cbc_key[] = {
    0xce, 0xb0, 0x09, 0xae, 0xa4, 0x45, 0x44, 0x51, 0xfe, 0xad, 0xf0, 0xe6,
    0xb3, 0x6f, 0x45, 0x55, 0x5d, 0xd0, 0x47, 0x23, 0xba, 0xa4, 0x48, 0xe8
};

/* Unique initialisation vector */
static const unsigned char cbc_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84,
    0x99, 0xaa, 0x3e, 0x68,
};

/* Example plaintext to encrypt */
static const unsigned char cbc_pt[] = {
    0xc8, 0xd2, 0x75, 0xf9, 0x19, 0xe1, 0x7d, 0x7f, 0xe6, 0x9c, 0x2a, 0x1f,
    0x58, 0x93, 0x9d, 0xfe, 0x4d, 0x40, 0x37, 0x91, 0xb5, 0xdf, 0x13, 0x10
};

/* Expected ciphertext value */
static const unsigned char cbc_ct[] = {
    0x7F, 0x5D, 0xCE, 0xE6, 0x08, 0xDA, 0x1A, 0xD5, 0xBE, 0x3A, 0x22, 0x0B, 
    0xAB, 0xCB, 0xA2, 0x92, 0x86, 0xA4, 0x35, 0x69, 0x37, 0x8A, 0x5C, 0xEB, 
    0xF8, 0x29, 0xDF, 0x65, 0x78, 0x60, 0xE9, 0x3C

};

static OSSL_LIB_CTX *libctx = NULL;
static const char *propq = NULL;

int encrypt() {
    int outlen, tmplen;
    unsigned char outbuf[1024];

    // create a context for encrypt operation
    EVP_CIPHER_CTX* ctx;
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        return 0;
    }

    // fetch a block cipher & mode implementation
    EVP_CIPHER* cipher = NULL;
    if ((cipher = EVP_CIPHER_fetch(libctx, "ARIA-192-CBC", propq)) == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // init an encrypt operation w/ the cipher, key, and IV
    if (!EVP_EncryptInit_ex2(ctx, cipher, cbc_key, cbc_iv, /*params*/ NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // encrypt plaintext
    if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, cbc_pt, sizeof(cbc_pt))) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // finalize check -- possible padding
    if (!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    outlen += tmplen;

    printf("Ciphertext (outlen:%d):\n", outlen);
    BIO_dump_fp(stdout, outbuf, outlen);

    if (sizeof(cbc_ct) == outlen && !CRYPTO_memcmp(outbuf, cbc_ct, outlen))
        printf("Final ciphertext matches expected ciphertext\n");
    else
        printf("Final ciphertext differs from expected ciphertext\n");

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return 1;
}

int decrypt(void) {
    int outlen, tmplen;
    unsigned char outbuf[1024];

    printf("\n\nAES CBC Decrypt:\n");
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, cbc_ct, sizeof(cbc_ct));

    EVP_CIPHER_CTX* ctx;
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        return 0;
    }

    EVP_CIPHER* cipher = NULL;
    if ((cipher = EVP_CIPHER_fetch(libctx, "ARIA-192-CBC", propq)) == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (!EVP_DecryptInit_ex2(ctx, cipher, cbc_key, cbc_iv, /*params*/ NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    
    if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, cbc_ct, sizeof(cbc_ct))) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (!EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    outlen += tmplen;

    printf("\n\nPlaintext (outlen:%d):\n", outlen);
    BIO_dump_fp(stdout, outbuf, outlen);

    if (sizeof(cbc_pt) == outlen && !CRYPTO_memcmp(outbuf, cbc_pt, outlen))
        printf("Final plaintext matches original plaintext\n");
    else
        printf("Final plaintext differs from original plaintext\n");
    
    return 1;
}

int main() {
    if (!encrypt()) {
        return EXIT_FAILURE;
    }

    if (!decrypt()) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
