#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "rsa_encrypt.h"
#include "net_utils.h"

#define SERVER_PORT 12345
#define SERVER_HOST "127.0.0.1"

static const unsigned char msg[] =
    "To be, or not to be, that is the question,\n"
    "Whether 'tis nobler in the mind to suffer\n"
    "The slings and arrows of outrageous fortune,\n"
    "Or to take arms against a sea of troubles";

int main(void)
{
    OSSL_LIB_CTX *libctx = NULL;  // using the default context (NULL)
    unsigned char *encrypted = NULL;
    size_t encrypted_len = 0;
    int sockfd = -1;
    int ret = EXIT_FAILURE;

    if (!do_encrypt(libctx, msg, sizeof(msg) - 1, &encrypted, &encrypted_len)) {
        fprintf(stderr, "Encryption failed.\n");
        goto cleanup;
    }

    sockfd = connect_to_server(SERVER_HOST, SERVER_PORT);
    if (sockfd < 0) {
        fprintf(stderr, "Failed to connect to server.\n");
        goto cleanup;
    }

    /* Send the encrypted message length first (in network byte order) */
    uint32_t net_len = htonl(encrypted_len);
    if (send_all(sockfd, &net_len, sizeof(net_len)) != sizeof(net_len)) {
        fprintf(stderr, "Failed to send message length.\n");
        goto cleanup;
    }
    /* Then send the encrypted data */
    if (send_all(sockfd, encrypted, encrypted_len) != (ssize_t)encrypted_len) {
        fprintf(stderr, "Failed to send encrypted data.\n");
        goto cleanup;
    }
    printf("Client: Sent encrypted message to server.\n");
    ret = EXIT_SUCCESS;

cleanup:
    if (sockfd >= 0)
        close(sockfd);
    if (encrypted)
        OPENSSL_free(encrypted);
    return ret;
}
