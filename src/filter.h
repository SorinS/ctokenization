#ifndef FILTER_H
#define FILTER_H

#include <stddef.h>
#include <stdint.h>

// Filter for selective tokenization based on approved alphabet
typedef struct {
    uint8_t approved[256];  // Lookup table: 1 if char is in alphabet
    char *alphabet;         // The filter alphabet
    size_t alphabet_len;
} Filter;

// Initialize filter with alphabet
void filter_init(Filter *f, const char *alphabet);

// Free filter resources
void filter_free(Filter *f);

// Check if character is in approved alphabet
int filter_is_approved(Filter *f, unsigned char c);

// Forward declaration
#include "data_token.h"

// Tokenize string, only tokenizing approved characters
// Returns malloc'd string (caller must free)
// Uses DataTokenProcessor for tokenization
char *filter_tokenize(Filter *f, DataTokenProcessor *proc,
                      const char *data, size_t len, size_t *out_len);

// Detokenize string, only detokenizing approved characters
char *filter_detokenize(Filter *f, DataTokenProcessor *proc,
                        const char *data, size_t len, size_t *out_len);

#endif // FILTER_H
