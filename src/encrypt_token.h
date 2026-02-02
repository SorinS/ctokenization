#ifndef ENCRYPT_TOKEN_H
#define ENCRYPT_TOKEN_H

#include <stdint.h>
#include <stddef.h>

// EncryptTokenProcessor - AES-128-CTR encryption (non-deterministic, random IV)
typedef struct {
    uint8_t key[16];
} EncryptTokenProcessor;

void encrypt_token_init(EncryptTokenProcessor *proc, const uint8_t key[32]);

// Tokenize (returns base64(IV + ciphertext), caller must free)
char *encrypt_token_tokenize(EncryptTokenProcessor *proc, const char *data, size_t len, size_t *out_len);

// Detokenize (returns plaintext, caller must free)
char *encrypt_token_detokenize(EncryptTokenProcessor *proc, const char *data, size_t len, size_t *out_len);

#endif // ENCRYPT_TOKEN_H
