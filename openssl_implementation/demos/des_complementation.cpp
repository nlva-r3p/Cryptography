#include <openssl/evp.h>
#include <openssl/provider.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <stdexcept>

// Function to complement bits of an array
void complement_bits(const unsigned char* input, unsigned char* output, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        output[i] = ~input[i];
    }
}

// Function to encrypt plaintext using DES with EVP
void des_encrypt(const unsigned char* key, const unsigned char* plaintext, unsigned char* ciphertext, size_t& ciphertext_len) {
    // Load the legacy provider for DES support in OpenSSL 3
    if (OSSL_PROVIDER_load(nullptr, "legacy") == nullptr) {
        throw std::runtime_error("Failed to load OpenSSL legacy provider");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    // Initialize the encryption operation with DES ECB mode
    const EVP_CIPHER* cipher = EVP_des_ecb();
    if (!cipher) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to load DES cipher");
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize DES encryption");
    }

    int len = 0;

    // Encrypt the plaintext (assuming a block size of 8 bytes for DES)
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, 8) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt plaintext");
    }
    ciphertext_len = len;

    // Finalize the encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    try {
        // Input key and plaintext
        unsigned char key[8] = {'1', '2', '3', '4', '5', '6', '7', '8'}; // 8-byte DES key
        unsigned char plaintext[8] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'}; // 8-byte plaintext

        // Output buffers
        unsigned char ciphertext[16];
        unsigned char complemented_key[8];
        unsigned char complemented_plaintext[8];
        unsigned char complemented_ciphertext[16];
        size_t ciphertext_len = 0;
        size_t complemented_ciphertext_len = 0;

        // Encrypt plaintext with the original key
        des_encrypt(key, plaintext, ciphertext, ciphertext_len);

        // Compute complemented key and plaintext
        complement_bits(key, complemented_key, 8);
        complement_bits(plaintext, complemented_plaintext, 8);

        // Encrypt complemented plaintext with complemented key
        des_encrypt(complemented_key, complemented_plaintext, complemented_ciphertext, complemented_ciphertext_len);

        // Verify complementation property: ciphertext should complement correctly
        unsigned char expected_complemented_ciphertext[8];
        complement_bits(ciphertext, expected_complemented_ciphertext, 8);

        bool property_holds = memcmp(complemented_ciphertext, expected_complemented_ciphertext, 8) == 0;

        // Output results
        std::cout << "Original Key:           ";
        for (unsigned char b : key)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        std::cout << "\nComplemented Key:       ";
        for (unsigned char b : complemented_key)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;

        std::cout << "\nOriginal Plaintext:     ";
        for (unsigned char b : plaintext)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        std::cout << "\nComplemented Plaintext: ";
        for (unsigned char b : complemented_plaintext)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;

        std::cout << "\nCiphertext:             ";
        for (size_t i = 0; i < ciphertext_len; ++i)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)ciphertext[i];
        std::cout << "\nComplemented Ciphertext:";
        for (size_t i = 0; i < complemented_ciphertext_len; ++i)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)complemented_ciphertext[i];

        std::cout << "\nComplementation Property: " << (property_holds ? "Holds" : "Failed") << "\n";

    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
