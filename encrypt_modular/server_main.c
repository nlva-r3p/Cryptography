#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "rsa_decrypt.h"
#include "net_utils.h"

#define SERVER_PORT 12345

int main(void)
{
    OSSL_LIB_CTX *libctx = NULL;  // using the default context (NULL)
    int server_sock = -1, client_sock = -1;
    unsigned char *encrypted = NULL;
    size_t encrypted_len = 0;
    unsigned char *decrypted = NULL;
    size_t decrypted_len = 0;
    int ret = EXIT_FAILURE;

    server_sock = create_server_socket(SERVER_PORT);
    if (server_sock < 0) {
        fprintf(stderr, "Server: Failed to create socket.\n");
        goto cleanup;
    }

    printf("Server: Waiting for connection on port %d...\n", SERVER_PORT);
    client_sock = accept_client(server_sock);
    if (client_sock < 0) {
        fprintf(stderr, "Server: Failed to accept client connection.\n");
        goto cleanup;
    }

    /* First, receive the encrypted message length */
    uint32_t net_len = 0;
    if (recv_all(client_sock, &net_len, sizeof(net_len)) != sizeof(net_len)) {
        fprintf(stderr, "Server: Failed to receive message length.\n");
        goto cleanup;
    }
    encrypted_len = ntohl(net_len);

    encrypted = OPENSSL_zalloc(encrypted_len);
    if (encrypted == NULL) {
        fprintf(stderr, "Server: Memory allocation failed.\n");
        goto cleanup;
    }
    if (recv_all(client_sock, encrypted, encrypted_len) != (ssize_t)encrypted_len) {
        fprintf(stderr, "Server: Failed to receive encrypted data.\n");
        goto cleanup;
    }

    if (!do_decrypt(libctx, encrypted, encrypted_len, &decrypted, &decrypted_len)) {
        fprintf(stderr, "Server: Decryption failed.\n");
        goto cleanup;
    }

    printf("Server: Decrypted message:\n%.*s\n", (int)decrypted_len, decrypted);
    ret = EXIT_SUCCESS;

cleanup:
    if (client_sock >= 0)
        close(client_sock);
    if (server_sock >= 0)
        close(server_sock);
    if (encrypted)
        OPENSSL_free(encrypted);
    if (decrypted)
        OPENSSL_free(decrypted);
    return ret;
}
