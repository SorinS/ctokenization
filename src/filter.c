#include "filter.h"
#include "data_token.h"
#include "number_token.h"
#include <stdlib.h>
#include <string.h>

void filter_init(Filter *f, const char *alphabet) {
    memset(f->approved, 0, sizeof(f->approved));
    f->alphabet_len = strlen(alphabet);
    f->alphabet = strdup(alphabet);

    for (size_t i = 0; i < f->alphabet_len; i++) {
        f->approved[(unsigned char)alphabet[i]] = 1;
    }
}

void filter_free(Filter *f) {
    free(f->alphabet);
    f->alphabet = NULL;
    f->alphabet_len = 0;
}

int filter_is_approved(Filter *f, unsigned char c) {
    return f->approved[c];
}

char *filter_tokenize(Filter *f, DataTokenProcessor *proc,
                      const char *data, size_t len, size_t *out_len) {
    if (len == 0) {
        char *r = malloc(1);
        if (r) r[0] = '\0';
        *out_len = 0;
        return r;
    }

    // Extract approved characters and their positions
    size_t *positions = malloc(len * sizeof(size_t));
    char *approved_chars = malloc(len + 1);
    size_t approved_count = 0;

    for (size_t i = 0; i < len; i++) {
        if (filter_is_approved(f, (unsigned char)data[i])) {
            positions[approved_count] = i;
            approved_chars[approved_count] = data[i];
            approved_count++;
        }
    }
    approved_chars[approved_count] = '\0';

    // Tokenize approved characters
    size_t token_len;
    char *tokenized = NULL;
    if (approved_count > 0) {
        tokenized = data_token_tokenize(proc, approved_chars, approved_count, &token_len);
    }

    // Build result: copy original, replace approved positions with tokenized
    char *result = malloc(len + 1);
    memcpy(result, data, len);
    result[len] = '\0';

    if (tokenized && token_len == approved_count) {
        for (size_t i = 0; i < approved_count; i++) {
            result[positions[i]] = tokenized[i];
        }
    }

    free(positions);
    free(approved_chars);
    free(tokenized);

    *out_len = len;
    return result;
}

char *filter_detokenize(Filter *f, DataTokenProcessor *proc,
                        const char *data, size_t len, size_t *out_len) {
    if (len == 0) {
        char *r = malloc(1);
        if (r) r[0] = '\0';
        *out_len = 0;
        return r;
    }

    // Extract approved characters and their positions
    size_t *positions = malloc(len * sizeof(size_t));
    char *approved_chars = malloc(len + 1);
    size_t approved_count = 0;

    for (size_t i = 0; i < len; i++) {
        if (filter_is_approved(f, (unsigned char)data[i])) {
            positions[approved_count] = i;
            approved_chars[approved_count] = data[i];
            approved_count++;
        }
    }
    approved_chars[approved_count] = '\0';

    // Detokenize approved characters
    size_t detok_len;
    char *detokenized = NULL;
    if (approved_count > 0) {
        detokenized = data_token_detokenize(proc, approved_chars, approved_count, &detok_len);
    }

    // Build result: copy original, replace approved positions with detokenized
    char *result = malloc(len + 1);
    memcpy(result, data, len);
    result[len] = '\0';

    if (detokenized && detok_len == approved_count) {
        for (size_t i = 0; i < approved_count; i++) {
            result[positions[i]] = detokenized[i];
        }
    }

    free(positions);
    free(approved_chars);
    free(detokenized);

    *out_len = len;
    return result;
}

char *filter_tokenize_number(Filter *f, NumberTokenProcessor *proc,
                             const char *data, size_t len, size_t *out_len) {
    if (len == 0) {
        char *r = malloc(1);
        if (r) r[0] = '\0';
        *out_len = 0;
        return r;
    }

    // Extract approved characters and their positions
    size_t *positions = malloc(len * sizeof(size_t));
    char *approved_chars = malloc(len + 1);
    size_t approved_count = 0;

    for (size_t i = 0; i < len; i++) {
        if (filter_is_approved(f, (unsigned char)data[i])) {
            positions[approved_count] = i;
            approved_chars[approved_count] = data[i];
            approved_count++;
        }
    }
    approved_chars[approved_count] = '\0';

    // Tokenize approved characters
    size_t token_len;
    char *tokenized = NULL;
    if (approved_count > 0) {
        tokenized = number_token_tokenize(proc, approved_chars, approved_count, &token_len);
    }

    // Build result: copy original, replace approved positions with tokenized
    char *result = malloc(len + 1);
    memcpy(result, data, len);
    result[len] = '\0';

    if (tokenized && token_len == approved_count) {
        for (size_t i = 0; i < approved_count; i++) {
            result[positions[i]] = tokenized[i];
        }
    }

    free(positions);
    free(approved_chars);
    free(tokenized);

    *out_len = len;
    return result;
}

char *filter_detokenize_number(Filter *f, NumberTokenProcessor *proc,
                               const char *data, size_t len, size_t *out_len) {
    if (len == 0) {
        char *r = malloc(1);
        if (r) r[0] = '\0';
        *out_len = 0;
        return r;
    }

    // Extract approved characters and their positions
    size_t *positions = malloc(len * sizeof(size_t));
    char *approved_chars = malloc(len + 1);
    size_t approved_count = 0;

    for (size_t i = 0; i < len; i++) {
        if (filter_is_approved(f, (unsigned char)data[i])) {
            positions[approved_count] = i;
            approved_chars[approved_count] = data[i];
            approved_count++;
        }
    }
    approved_chars[approved_count] = '\0';

    // Detokenize approved characters
    size_t detok_len;
    char *detokenized = NULL;
    if (approved_count > 0) {
        detokenized = number_token_detokenize(proc, approved_chars, approved_count, &detok_len);
    }

    // Build result: copy original, replace approved positions with detokenized
    char *result = malloc(len + 1);
    memcpy(result, data, len);
    result[len] = '\0';

    if (detokenized && detok_len == approved_count) {
        for (size_t i = 0; i < approved_count; i++) {
            result[positions[i]] = detokenized[i];
        }
    }

    free(positions);
    free(approved_chars);
    free(detokenized);

    *out_len = len;
    return result;
}
