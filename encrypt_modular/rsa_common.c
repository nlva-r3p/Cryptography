#ifdef CLIENT_BUILD
#include "rsa_pub_key.h"
#elif defined(SERVER_BUILD)
#include "rsa_priv_key.h"
#include "rsa_pub_key.h"
#else
#error "Define either CLIENT_BUILD or SERVER_BUILD"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>
#include "rsa_common.h"

EVP_PKEY *get_key(OSSL_LIB_CTX *libctx, const char *propq, int is_public)
{
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;
    int selection;
    const unsigned char *data;
    size_t data_len;

    if (is_public) {
        selection = EVP_PKEY_PUBLIC_KEY;
        data = public_der;
        data_len = sizeof(public_der);
    } else {
#ifdef SERVER_BUILD
        selection = EVP_PKEY_KEYPAIR;
        data = private_der;
        data_len = sizeof(private_der);
#else
        fprintf(stderr, "Private key not available in CLIENT build.\n");
        return NULL;
#endif
    }
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, "RSA",
                                         selection, libctx, propq);
    (void)OSSL_DECODER_from_data(dctx, &data, &data_len);
    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

void set_optional_params(OSSL_PARAM *p, const char *propq)
{
    static unsigned char label[] = "label";

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                            OSSL_PKEY_RSA_PAD_MODE_OAEP, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
                                             label, sizeof(label));
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                            "SHA256", 0);
    if (propq != NULL)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS,
                                                (char *)propq, 0);
    *p = OSSL_PARAM_construct_end();
}