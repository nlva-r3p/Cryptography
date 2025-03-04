#ifndef RSA_COMMON_H
#define RSA_COMMON_H

#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include <openssl/core_names.h>

EVP_PKEY *get_key(OSSL_LIB_CTX *libctx, const char *propq, int is_public);
void set_optional_params(OSSL_PARAM *p, const char *propq);

#endif // RSA_COMMON_H