#ifndef LONGDATA_TOKEN_H
#define LONGDATA_TOKEN_H

#include <stdint.h>
#include <stddef.h>

// LongDataTokenProcessor - AES-128-CBC encryption (deterministic, fixed IV)
typedef struct {
    uint8_t key[16]; // AES-128 key (first 16 bytes of 32-byte key)
} LongDataTokenProcessor;

void longdata_token_init(LongDataTokenProcessor *proc, const uint8_t key[32]);

// Tokenize (returns base64-encoded ciphertext, caller must free)
char *longdata_token_tokenize(LongDataTokenProcessor *proc, const char *data, size_t len, size_t *out_len);

// Detokenize (returns plaintext, caller must free)
char *longdata_token_detokenize(LongDataTokenProcessor *proc, const char *data, size_t len, size_t *out_len);

#endif // LONGDATA_TOKEN_H
