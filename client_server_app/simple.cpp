#include <iostream>
#include <cmath>
#include <stdint.h>

// program implemementation of symmetric encryption using Diffie-Hellman algorithm. // Source: https://deeprnd.medium.com/cryptographic-key-exchange-5eb9e926edb0 

// performs modulo and exponent
uint64_t moduloPow(uint64_t base, uint64_t exponent, uint64_t modulus) {
    uint64_t result = std::pow(base, exponent);
    return result % modulus;
}

// for an integer [a mod m], to find its inverse, we must find a number x s.t. [ (a * x) mod m = 1 ], so we are finding an integer x that works the same way as 1/a.
uint64_t moduloInverse(uint64_t a, uint64_t m) {
    for (uint64_t x = 1; x < m; x++) {
        if ((a * x) % m == 1)
            return x;
    }
    return -1; // indicates that there were no inverse found
}

uint64_t main() {
    uint64_t p = 23; // public (prime modulus)
    uint64_t g = 5;  // public (prime base)

    // only you know
    uint64_t yourSecret = 6;
    std::cout << "Secret: " << yourSecret << "\n";

    // your public value made using yourSecret
    uint64_t yourPublicValue = moduloPow(g, yourSecret, p);
    std::cout << "Your Public Value: " << yourPublicValue << "\n";

    // your friend's public value made using theirSecret
    uint64_t theirPublicValue = 15;
    std::cout << "Their Secret: " << theirPublicValue << "\n";

    // both of your sharedSecret used to encrypt and decrypt
    uint64_t sharedSecret = moduloPow(theirPublicValue, yourSecret, p);
    std::cout << "Shared Secret: " << sharedSecret << "\n";

    // encryption via shared secret
    // unlike assymetric encryption, where only you with your secret key can decrypt an encrypted message, encrypted via your public key,
    // symmetric encryption allows both you and your friend to decrypt an encrypted message, encrypted by either of your public keys
    uint64_t message = 7; // Original message (should be less than p)
    uint64_t encryptedMessage = (message * sharedSecret) % p; 
    // so, mathematically, (Message * SharedSecret) % p
    std::cout << "Original Message: " << message << "\n";
    std::cout << "Encrypted Message: " << encryptedMessage << "\n";

    // decryption using shared secret
    uint64_t inverseSharedSecret = moduloInverse(sharedSecret, p);
    // so, mathematically, (SharedSecret * SharedSecret^-1) % p = 1
    // thus, inverseSharedSecret = SharedSecret^-1
    if (inverseSharedSecret != 1) {
        std::cerr << "No Inverse Found.\n"; 
        return 1;
    }

    // encryptedMessage = (Message * SharedSecret) % p
    uint64_t decryptedMessage = (encryptedMessage * inverseSharedSecret) % p;
    // decryptedMessage = [((Message * SharedSecret) % p) * SharedSecret^-1]
    // decryptedMessage = [(Message * SharedSecret * SharedSecret^-1) % p]
    // decryptedMessage = Message % p
    std::cout << "Decrypted Message: " << decryptedMessage << "\n";

    return 0;
}
