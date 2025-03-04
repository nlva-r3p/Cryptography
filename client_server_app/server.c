#include <netinet/in.h>
#include <math.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h> 
#include <stdint.h>

// performs modulo and exponent
uint64_t moduloPow(uint64_t base, uint64_t exponent, uint64_t modulus) {
    double result = pow((double)base, (double)exponent);
    return (uint64_t)result % modulus;
}

uint64_t main(int argc, char const* argv[]) 
{ 
    // socket
    uint64_t servSockD = socket(AF_INET, SOCK_STREAM, 0); 

    // server address
    struct sockaddr_in servAddr; 
    servAddr.sin_family = AF_INET; 
    servAddr.sin_port = htons(9001); 
    servAddr.sin_addr.s_addr = INADDR_ANY; // look into what INADDR_ANY means

    // bind port + ip
    if (bind(servSockD, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
        printf("Failed to bind.");
        return 1;
    } 
    

    // listens for incoming connection
    listen(servSockD, 1); // max 1

    // accepts a client connection
    uint64_t clientSocket = accept(servSockD, NULL, NULL); 

    // your Secret
    uint64_t a = 11;

    // you picked p and g and sent it to them
    uint64_t publicPG[2] = {23, 5};
    uint64_t p = publicPG[0];
    uint64_t g = publicPG[1];
    send(clientSocket, publicPG, sizeof(publicPG), 0);

    // you send your public value
    uint64_t A;
    A = moduloPow(g, a, p);
    send(clientSocket, &A, sizeof(A), 0); 
    
    // you receive your their public value
    uint64_t B;
    recv(clientSocket, &B, sizeof(B), 0);

    uint64_t sharedSecret;
    sharedSecret = moduloPow(B, a, p);

    printf("p: %d, g: %d\n", p, g);
    printf("Your Secret (a): %d\n", a);
    printf("Your Public Value (A): %d\n", A);
    printf("Their Public Value (B): %d\n", B);
    printf("Shared Secret: %d\n", sharedSecret);

    close(clientSocket);
    close(servSockD);

    return 0; 
}
