#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#define ALPHABET_SIZE 26
#define CAESAR_SHIFT_KEY 7
#define MESSAGE_LENGTH_MAX 64
#define RSA_KEY_BIT_COUNT 2048
#define RSA_KEY_BYTE_COUNT (RSA_KEY_BIT_COUNT / 8)

// `key` should be in the range [-ALPHABET_SIZE, ALPHABET_SIZE]
void caesar_shift(char *text, int key);
unsigned sha256_hash(const char *input, unsigned char *output);

int main(void) {
    char message[MESSAGE_LENGTH_MAX];

    fputs("Enter a message: ", stdout);

    fgets(message, sizeof message / sizeof *message, stdin);
    message[strcspn(message, "\n")] = '\0';


    // Encrypt and decrypt the message with a caesar cipher

    caesar_shift(message, CAESAR_SHIFT_KEY);

    printf("Encrypted message: %s\n", message);

    caesar_shift(message, -CAESAR_SHIFT_KEY);

    printf("Decrypted message: %s\n", message);


    // Create a SHA256 hash for the message

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned hash_length = sha256_hash(message, hash);

    fputs("SHA256 hash: ", stdout);

    for (size_t i = 0; i < hash_length; ++i)
        printf("%02x", hash[i]);

    putchar('\n');


    // Create a signature for the hash

    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);

    if (RSA_generate_key_ex(rsa, RSA_KEY_BIT_COUNT, e, NULL) == 0) {
        fputs("Couldn't generate RSA key.\n", stderr);
        return EXIT_FAILURE;
    }

    BN_free(e);

    unsigned char signature[RSA_KEY_BYTE_COUNT];
    unsigned signature_length;

    if (RSA_sign(NID_sha256, hash, hash_length, signature, &signature_length, rsa) == 1) {
        puts("Signed successfully.");
    } else {
        fputs("Failed to sign.\n", stderr);
        return EXIT_FAILURE;
    }

    fputs("Signature is: ", stdout);

    for (size_t i = 0; i < signature_length; ++i)
        printf("%02x", signature[i]);
    
    putchar('\n');

    // Verify the signature

    if (RSA_verify(NID_sha256, hash, hash_length, signature, signature_length, rsa) == 1) {
        puts("Signature is valid.");
    } else {
        puts("Signature is invalid.");
    }
    
    return EXIT_SUCCESS;
}

void caesar_shift(char *text, int key) {
    // Ensure key is positive
    key += ALPHABET_SIZE;

    for (size_t i = 0; text[i] != '\0'; ++i) {
        // Don't encrypt non-alphabet characters
        if (!isalpha(text[i]))
            continue;
        
        const char base = islower(text[i]) ? 'a' : 'A';

        text[i] = (text[i] - base + key) % ALPHABET_SIZE + base;
    }
}

unsigned sha256_hash(const char *input, unsigned char *output) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned length;

    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, input, strlen(input));
    EVP_DigestFinal_ex(md_ctx, output, &length);

    EVP_MD_CTX_free(md_ctx);

    return length;
}
