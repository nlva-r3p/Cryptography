#include "net_utils.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

int create_server_socket(int port)
{
    int sockfd;
    struct sockaddr_in addr;
    int opt = 1;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sockfd);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }
    if (listen(sockfd, 5) < 0) {
        perror("listen");
        close(sockfd);
        return -1;
    }
    return sockfd;
}

int accept_client(int server_socket)
{
    int client_socket;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);
    if (client_socket < 0) {
        perror("accept");
        return -1;
    }
    return client_socket;
}

int connect_to_server(const char *hostname, int port)
{
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;

    if ((server = gethostbyname(hostname)) == NULL) {
        fprintf(stderr, "Error: no such host %s\n", hostname);
        return -1;
    }
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    server_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }
    return sockfd;
}

ssize_t send_all(int sockfd, const void *buf, size_t len)
{
    size_t total = 0;
    const char *p = buf;
    while (total < len) {
        ssize_t sent = send(sockfd, p + total, len - total, 0);
        if (sent <= 0) {
            perror("send");
            return -1;
        }
        total += sent;
    }
    return total;
}

ssize_t recv_all(int sockfd, void *buf, size_t len)
{
    size_t total = 0;
    char *p = buf;
    while (total < len) {
        ssize_t received = recv(sockfd, p + total, len - total, 0);
        if (received <= 0) {
            if (received < 0)
                perror("recv");
            return -1;
        }
        total += received;
    }
    return total;
}
