#include <netinet/in.h> // structure for storing address information 
#include <stdio.h> 
#include <stdlib.h>
#include <math.h>
#include <sys/socket.h> // for socket APIs 
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
    uint64_t sockD = socket(AF_INET, SOCK_STREAM, 0); 

    struct sockaddr_in servAddr; 

    servAddr.sin_family = AF_INET; 
    servAddr.sin_port = htons(9001); // use an unused port number 
    servAddr.sin_addr.s_addr = INADDR_ANY; 

    uint64_t connectStatus = connect(sockD, (struct sockaddr*)&servAddr, sizeof(servAddr)); 
    if (connectStatus == -1) { 
        printf("Error connecting to the server...\n"); 
        return 1;
    } 
    
    else { 
        uint64_t publicPG[2];
        uint64_t p, g;
        recv(sockD, publicPG, sizeof(publicPG), 0);
        p = publicPG[0];
        g = publicPG[1];

        uint64_t A;
        recv(sockD, &A, sizeof(A), 0);

        uint64_t b = 5;

        uint64_t B;
        B = moduloPow(g, b, p);
        send(sockD, &B, sizeof(B), 0);

        uint64_t sharedSecret;
        sharedSecret = moduloPow(A, b, p);

        printf("p: %d, g: %d\n", p, g);
        printf("Your Secret (b): %d\n", b);
        printf("Your Public Value (B): %d\n", B);
        printf("Their Public Value (A): %d\n", A);
        printf("Shared Secret: %d\n", sharedSecret);
    } 

    close(sockD);

    return 0; 
}
