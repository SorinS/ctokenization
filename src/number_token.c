#include "number_token.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define ROUNDS 31
#define BLOCK_SIZE 128
#define MAX_HALF_SIZE 64
#define ALPHABET_SIZE 10

static const uint8_t COMPRESSION_BOX[256] = {
    15, 46, 13, 44, 11, 42,  9, 40,  7, 38,  5, 36,  3, 34,  1, 32,
    63, 30, 61, 28, 59, 26, 57, 24, 55, 22, 53, 20, 51, 18, 49, 16,
    47, 14, 45, 12, 43, 10, 41,  8, 39,  6, 37,  4, 35,  2, 33,  0,
    31, 62, 29, 60, 27, 58, 25, 56, 23, 54, 21, 52, 19, 50, 17, 48,
    15, 46, 13, 44, 11, 42,  9, 40,  7, 38,  5, 36,  3, 34,  1, 32,
    63, 30, 61, 28, 59, 26, 57, 24, 55, 22, 53, 20, 51, 18, 49, 16,
    47, 14, 45, 12, 43, 10, 41,  8, 39,  6, 37,  4, 35,  2, 33,  0,
    31, 62, 29, 60, 27, 58, 25, 56, 23, 54, 21, 52, 19, 50, 17, 48,
    15, 46, 13, 44, 11, 42,  9, 40,  7, 38,  5, 36,  3, 34,  1, 32,
    63, 30, 61, 28, 59, 26, 57, 24, 55, 22, 53, 20, 51, 18, 49, 16,
    47, 14, 45, 12, 43, 10, 41,  8, 39,  6, 37,  4, 35,  2, 33,  0,
    31, 62, 29, 60, 27, 58, 25, 56, 23, 54, 21, 52, 19, 50, 17, 48,
    15, 46, 13, 44, 11, 42,  9, 40,  7, 38,  5, 36,  3, 34,  1, 32,
    63, 30, 61, 28, 59, 26, 57, 24, 55, 22, 53, 20, 51, 18, 49, 16,
    47, 14, 45, 12, 43, 10, 41,  8, 39,  6, 37,  4, 35,  2, 33,  0,
    31, 62, 29, 60, 27, 58, 25, 56, 23, 54, 21, 52, 19, 50, 17, 48,
};

static const uint8_t INDEX_TABLE[256] = {
      0,  16,   1,  17,   2,  18,   3,  19,   4,  20,   5,  21,   6,  22,   7,  23,
      8,  24,   9,  25,  10,  26,  11,  27,  12,  28,  13,  29,  14,  30,  15,  31,
     32,  48,  33,  49,  34,  50,  35,  51,  36,  52,  37,  53,  38,  54,  39,  55,
     40,  56,  41,  57,  42,  58,  43,  59,  44,  60,  45,  61,  46,  62,  47,  63,
     64,  80,  65,  81,  66,  82,  67,  83,  68,  84,  69,  85,  70,  86,  71,  87,
     72,  88,  73,  89,  74,  90,  75,  91,  76,  92,  77,  93,  78,  94,  79,  95,
     96, 112,  97, 113,  98, 114,  99, 115, 100, 116, 101, 117, 102, 118, 103, 119,
    104, 120, 105, 121, 106, 122, 107, 123, 108, 124, 109, 125, 110, 126, 111, 127,
    128, 144, 129, 145, 130, 146, 131, 147, 132, 148, 133, 149, 134, 150, 135, 151,
    136, 152, 137, 153, 138, 154, 139, 155, 140, 156, 141, 157, 142, 158, 143, 159,
    160, 176, 161, 177, 162, 178, 163, 179, 164, 180, 165, 181, 166, 182, 167, 183,
    168, 184, 169, 185, 170, 186, 171, 187, 172, 188, 173, 189, 174, 190, 175, 191,
    192, 208, 193, 209, 194, 210, 195, 211, 196, 212, 197, 213, 198, 214, 199, 215,
    200, 216, 201, 217, 202, 218, 203, 219, 204, 220, 205, 221, 206, 222, 207, 223,
    224, 240, 225, 241, 226, 242, 227, 243, 228, 244, 229, 245, 230, 246, 231, 247,
    232, 248, 233, 249, 234, 250, 235, 251, 236, 252, 237, 253, 238, 254, 239, 255,
};

static void precompute_hmac_pads(const uint8_t key[32], uint8_t ipad[128], uint8_t opad[128]) {
    for (int i = 0; i < 128; i++) {
        uint8_t k = (i < 32) ? key[i] : 0;
        ipad[i] = k ^ 0x36;
        opad[i] = k ^ 0x5c;
    }
}

static void hmac_sha512_with_pads(const uint8_t ipad[128], const uint8_t opad[128],
                                   const uint8_t *data1, size_t len1,
                                   const uint8_t *data2, size_t len2,
                                   uint8_t out[64]) {
    uint8_t inner_hash[64];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, ipad, 128);
    EVP_DigestUpdate(ctx, data1, len1);
    EVP_DigestUpdate(ctx, data2, len2);
    EVP_DigestFinal_ex(ctx, inner_hash, NULL);

    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, opad, 128);
    EVP_DigestUpdate(ctx, inner_hash, 64);
    EVP_DigestFinal_ex(ctx, out, NULL);

    EVP_MD_CTX_free(ctx);
}

void number_token_init(NumberTokenProcessor *proc, const uint8_t key[32]) {
    // Pre-compute compression table with modulo 10 baked in
    for (int i = 0; i < 256; i++) {
        uint8_t idx = INDEX_TABLE[i];
        proc->comp_table[i] = COMPRESSION_BOX[idx] % ALPHABET_SIZE;
    }

    // Generate round keys
    SHA256(key, 32, proc->round_keys[0]);
    for (int i = 1; i < ROUNDS; i++) {
        SHA256(proc->round_keys[i-1], 32, proc->round_keys[i]);
    }

    // Reversed keys
    for (int i = 0; i < ROUNDS; i++) {
        memcpy(proc->round_keys_reversed[i], proc->round_keys[ROUNDS - 1 - i], 32);
    }

    // HMAC pads
    for (int i = 0; i < ROUNDS; i++) {
        precompute_hmac_pads(proc->round_keys[i], proc->hmac_ipads[i], proc->hmac_opads[i]);
        precompute_hmac_pads(proc->round_keys_reversed[i], proc->hmac_ipads_rev[i], proc->hmac_opads_rev[i]);
    }
}

static void process_block(NumberTokenProcessor *proc,
                          const uint8_t *block, size_t block_len,
                          uint8_t *output,
                          int32_t total_blocks, int32_t msg_block,
                          int is_tokenize,
                          const uint8_t ipads[ROUNDS][128],
                          const uint8_t opads[ROUNDS][128]) {
    if (block_len == 0) return;

    uint8_t buf_a[MAX_HALF_SIZE], buf_b[MAX_HALF_SIZE], new_data[MAX_HALF_SIZE];

    size_t half_size = (block_len + 1) / 2;
    size_t right_size = block_len - half_size;

    // Encode digits to indices (0-9)
    for (size_t i = 0; i < half_size; i++) {
        buf_a[i] = block[i] - '0';
    }
    for (size_t i = 0; i < right_size; i++) {
        buf_b[i] = block[half_size + i] - '0';
    }

    uint8_t *left_ptr = buf_a, *right_ptr = buf_b;
    size_t left_len = half_size, right_len = right_size;

    uint8_t metadata[8] = {
        (total_blocks >> 24) & 0xff, (total_blocks >> 16) & 0xff,
        (total_blocks >> 8) & 0xff, total_blocks & 0xff,
        (msg_block >> 24) & 0xff, (msg_block >> 16) & 0xff,
        (msg_block >> 8) & 0xff, msg_block & 0xff
    };

    for (int round = 0; round < ROUNDS; round++) {
        uint8_t hash_out[64];
        hmac_sha512_with_pads(ipads[round], opads[round],
                              right_ptr, right_len, metadata, 8, hash_out);

        if (is_tokenize) {
            for (size_t i = 0; i < left_len; i++) {
                uint8_t hv = proc->comp_table[hash_out[i]];
                new_data[i] = ((uint16_t)left_ptr[i] + hv) % ALPHABET_SIZE;
            }
        } else {
            for (size_t i = 0; i < left_len; i++) {
                uint8_t hv = proc->comp_table[hash_out[i]];
                new_data[i] = ((uint16_t)left_ptr[i] + ALPHABET_SIZE - hv) % ALPHABET_SIZE;
            }
        }

        if (round == ROUNDS - 1) {
            memcpy(left_ptr, new_data, left_len);
        } else {
            uint8_t *tp = left_ptr; size_t tl = left_len;
            left_ptr = right_ptr; left_len = right_len;
            right_ptr = tp; right_len = tl;
            memcpy(right_ptr, new_data, right_len);
        }
    }

    // Decode to digits
    for (size_t i = 0; i < left_len; i++) output[i] = '0' + left_ptr[i];
    for (size_t i = 0; i < right_len; i++) output[left_len + i] = '0' + right_ptr[i];
}

static char *process_data(NumberTokenProcessor *proc, const char *data, size_t len,
                          size_t *out_len, int is_tokenize) {
    if (len == 0) {
        char *r = malloc(1); if (r) r[0] = '\0'; *out_len = 0; return r;
    }

    char *result = malloc(len + 1);
    if (!result) { *out_len = 0; return NULL; }

    int32_t total_blocks = (int32_t)((len + BLOCK_SIZE - 1) / BLOCK_SIZE);
    const uint8_t (*ipads)[128] = is_tokenize ?
        (const uint8_t (*)[128])proc->hmac_ipads : (const uint8_t (*)[128])proc->hmac_ipads_rev;
    const uint8_t (*opads)[128] = is_tokenize ?
        (const uint8_t (*)[128])proc->hmac_opads : (const uint8_t (*)[128])proc->hmac_opads_rev;

    for (size_t offset = 0; offset < len; offset += BLOCK_SIZE) {
        size_t end = offset + BLOCK_SIZE > len ? len : offset + BLOCK_SIZE;
        int32_t msg_block = (offset < len - (len % BLOCK_SIZE)) ?
            (int32_t)(len / BLOCK_SIZE) - (int32_t)(offset / BLOCK_SIZE) : 0;
        process_block(proc, (const uint8_t *)(data + offset), end - offset,
                     (uint8_t *)(result + offset), total_blocks, msg_block, is_tokenize, ipads, opads);
    }

    result[len] = '\0';
    *out_len = len;
    return result;
}

char *number_token_tokenize(NumberTokenProcessor *proc, const char *data, size_t len, size_t *out_len) {
    return process_data(proc, data, len, out_len, 1);
}

char *number_token_detokenize(NumberTokenProcessor *proc, const char *data, size_t len, size_t *out_len) {
    return process_data(proc, data, len, out_len, 0);
}
