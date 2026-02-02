#ifndef NUMBER_TOKEN_H
#define NUMBER_TOKEN_H

#include <stdint.h>
#include <stddef.h>

// NumberTokenProcessor - Format-preserving tokenization for numeric strings
// Uses the same Feistel cipher as DataToken but with digit alphabet
typedef struct {
    uint8_t round_keys[31][32];
    uint8_t round_keys_reversed[31][32];
    uint8_t hmac_ipads[31][128];
    uint8_t hmac_opads[31][128];
    uint8_t hmac_ipads_rev[31][128];
    uint8_t hmac_opads_rev[31][128];
    uint8_t comp_table[256];
} NumberTokenProcessor;

// Initialize number token processor
void number_token_init(NumberTokenProcessor *proc, const uint8_t key[32]);

// Tokenize numeric string (caller must free result)
char *number_token_tokenize(NumberTokenProcessor *proc, const char *data, size_t len, size_t *out_len);

// Detokenize numeric string (caller must free result)
char *number_token_detokenize(NumberTokenProcessor *proc, const char *data, size_t len, size_t *out_len);

#endif // NUMBER_TOKEN_H
