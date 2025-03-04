#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>
#include "rsa_decrypt.h"
#include "rsa_common.h"

int do_decrypt(OSSL_LIB_CTX *libctx, const unsigned char *in, size_t in_len,
    unsigned char **out, size_t *out_len) 
{
    int ret = 0, public = 0;
    size_t buf_len = 0;
    unsigned char *buf = NULL;
    const char *propq = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *priv_key = NULL;
    OSSL_PARAM params[5];

    /* Get private key */
    priv_key = get_key(libctx, propq, public);
    if (priv_key == NULL) {
        fprintf(stderr, "Get private key failed.\n");
        goto cleanup;
    }
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, priv_key, propq);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed.\n");
        goto cleanup;
    }

    /* The parameters used for encryption must also be used for decryption */
    set_optional_params(params, propq);
    /* If no optional parameters are required then NULL can be passed */
    if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
        fprintf(stderr, "EVP_PKEY_decrypt_init_ex() failed.\n");
        goto cleanup;
    }
    /* Calculate the size required to hold the decrypted data */
    if (EVP_PKEY_decrypt(ctx, NULL, &buf_len, in, in_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_decrypt() failed.\n");
        goto cleanup;
    }
    buf = OPENSSL_zalloc(buf_len);
    if (buf == NULL) {
        fprintf(stderr, "Malloc failed.\n");
        goto cleanup;
    }
    if (EVP_PKEY_decrypt(ctx, buf, &buf_len, in, in_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_decrypt() failed.\n");
        goto cleanup;
    }
    *out_len = buf_len;
    *out = buf;
    fprintf(stdout, "Decrypted:\n");
    BIO_dump_indent_fp(stdout, buf, buf_len, 2);
    fprintf(stdout, "\n");
    ret = 1;

cleanup:
    if (!ret)
        OPENSSL_free(buf);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}