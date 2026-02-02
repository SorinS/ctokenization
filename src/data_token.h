#ifndef DATA_TOKEN_H
#define DATA_TOKEN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define DATA_TOKEN_ROUNDS 31
#define DATA_TOKEN_BLOCK_SIZE 128
#define DATA_TOKEN_MAX_HALF_SIZE 64

// DataTokenProcessor - 31-round Feistel cipher for format-preserving tokenization
typedef struct {
    uint8_t round_keys[DATA_TOKEN_ROUNDS][32];
    uint8_t round_keys_reversed[DATA_TOKEN_ROUNDS][32];
    // Pre-computed HMAC inner/outer pads (major optimization)
    uint8_t hmac_ipads[DATA_TOKEN_ROUNDS][128];
    uint8_t hmac_opads[DATA_TOKEN_ROUNDS][128];
    uint8_t hmac_ipads_rev[DATA_TOKEN_ROUNDS][128];
    uint8_t hmac_opads_rev[DATA_TOKEN_ROUNDS][128];
    // Alphabet and lookup tables
    const char *alphabet;
    size_t alphabet_len;
    uint8_t ascii_alphabet[256];
    uint8_t char_to_index[256];
    // Pre-computed compression table with modulo baked in
    uint8_t comp_table[256];
    uint8_t alphabet_size;
    bool is_ascii_only;
} DataTokenProcessor;

// Standard alphabets
extern const char *DATA_TOKEN_JAVA_ALPHABET;
extern const char *DATA_TOKEN_LOWERCASE_ALPHABET;

// Initialize with default Java alphabet (118 chars)
void data_token_init(DataTokenProcessor *proc, const uint8_t key[32]);

// Initialize with lowercase alphabet (26 chars)
void data_token_init_lowercase(DataTokenProcessor *proc, const uint8_t key[32]);

// Initialize with custom alphabet
void data_token_init_with_alphabet(DataTokenProcessor *proc, const uint8_t key[32],
                                    const char *alphabet);

// Tokenize data (caller must free result)
// Returns allocated buffer, sets *out_len to length
char *data_token_tokenize(DataTokenProcessor *proc, const char *data, size_t len, size_t *out_len);

// Detokenize data (caller must free result)
char *data_token_detokenize(DataTokenProcessor *proc, const char *data, size_t len, size_t *out_len);

// Cleanup (no-op for now, but good practice)
void data_token_deinit(DataTokenProcessor *proc);

#endif // DATA_TOKEN_H
