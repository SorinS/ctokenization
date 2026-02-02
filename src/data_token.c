#include "data_token.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

// Java's 118-character alphabet
const char *DATA_TOKEN_JAVA_ALPHABET =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "{|}~ !\"#$%&'()*+,-./:;<=>?@[\\]^_`"
    "\xA1\xA2\xA3\xA4\xA5\xA6\xC7\xA8\xA9\xAA"
    "\xAB\xAC\xAE\xAF\xB0\xB1\xB2\xB3\xB4\xB5"
    "\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"
    "\xC0\xC1\xC2";

const char *DATA_TOKEN_LOWERCASE_ALPHABET = "abcdefghijklmnopqrstuvwxyz";

// Compression box matching Java: (31 * i + 15) % 64
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

// Pre-computed index table
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

// Pre-compute HMAC pads for a key
static void precompute_hmac_pads(const uint8_t key[32], uint8_t ipad[128], uint8_t opad[128]) {
    for (int i = 0; i < 128; i++) {
        uint8_t k = (i < 32) ? key[i] : 0;
        ipad[i] = k ^ 0x36;
        opad[i] = k ^ 0x5c;
    }
}

// HMAC-SHA512 using pre-computed pads
static void hmac_sha512_with_pads(const uint8_t ipad[128], const uint8_t opad[128],
                                   const uint8_t *data1, size_t len1,
                                   const uint8_t *data2, size_t len2,
                                   uint8_t out[64]) {
    uint8_t inner_hash[64];

    // Inner hash: SHA512(ipad || data1 || data2)
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, ipad, 128);
    EVP_DigestUpdate(ctx, data1, len1);
    EVP_DigestUpdate(ctx, data2, len2);
    EVP_DigestFinal_ex(ctx, inner_hash, NULL);

    // Outer hash: SHA512(opad || inner_hash)
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, opad, 128);
    EVP_DigestUpdate(ctx, inner_hash, 64);
    EVP_DigestFinal_ex(ctx, out, NULL);

    EVP_MD_CTX_free(ctx);
}

void data_token_init_with_alphabet(DataTokenProcessor *proc, const uint8_t key[32],
                                    const char *alphabet) {
    proc->alphabet = alphabet;
    proc->alphabet_len = strlen(alphabet);
    proc->alphabet_size = (uint8_t)proc->alphabet_len;
    proc->is_ascii_only = true;

    // Initialize lookup tables
    memset(proc->char_to_index, 0, 256);
    memset(proc->ascii_alphabet, 0, 256);

    for (size_t i = 0; i < proc->alphabet_len; i++) {
        uint8_t c = (uint8_t)alphabet[i];
        proc->char_to_index[c] = (uint8_t)i;
        proc->ascii_alphabet[i] = c;
        if (c >= 128) {
            proc->is_ascii_only = false;
        }
    }

    // Pre-compute compression table with modulo baked in
    for (int i = 0; i < 256; i++) {
        uint8_t idx = INDEX_TABLE[i];
        proc->comp_table[i] = COMPRESSION_BOX[idx] % proc->alphabet_size;
    }

    // Generate round keys: K[0] = SHA256(key), K[i] = SHA256(K[i-1])
    SHA256(key, 32, proc->round_keys[0]);
    for (int i = 1; i < DATA_TOKEN_ROUNDS; i++) {
        SHA256(proc->round_keys[i-1], 32, proc->round_keys[i]);
    }

    // Pre-compute reversed round keys
    for (int i = 0; i < DATA_TOKEN_ROUNDS; i++) {
        memcpy(proc->round_keys_reversed[i],
               proc->round_keys[DATA_TOKEN_ROUNDS - 1 - i], 32);
    }

    // Pre-compute HMAC pads for all round keys
    for (int i = 0; i < DATA_TOKEN_ROUNDS; i++) {
        precompute_hmac_pads(proc->round_keys[i],
                            proc->hmac_ipads[i], proc->hmac_opads[i]);
        precompute_hmac_pads(proc->round_keys_reversed[i],
                            proc->hmac_ipads_rev[i], proc->hmac_opads_rev[i]);
    }
}

void data_token_init(DataTokenProcessor *proc, const uint8_t key[32]) {
    data_token_init_with_alphabet(proc, key, DATA_TOKEN_JAVA_ALPHABET);
}

void data_token_init_lowercase(DataTokenProcessor *proc, const uint8_t key[32]) {
    data_token_init_with_alphabet(proc, key, DATA_TOKEN_LOWERCASE_ALPHABET);
}

void data_token_deinit(DataTokenProcessor *proc) {
    (void)proc; // Nothing to free
}

// Process a single block
static void process_block(DataTokenProcessor *proc,
                          const uint8_t *block, size_t block_len,
                          uint8_t *output,
                          int32_t total_blocks, int32_t msg_block,
                          bool is_tokenize,
                          const uint8_t ipads[DATA_TOKEN_ROUNDS][128],
                          const uint8_t opads[DATA_TOKEN_ROUNDS][128]) {
    if (block_len == 0) return;

    uint8_t buf_a[DATA_TOKEN_MAX_HALF_SIZE];
    uint8_t buf_b[DATA_TOKEN_MAX_HALF_SIZE];
    uint8_t new_data[DATA_TOKEN_MAX_HALF_SIZE];

    size_t half_size = (block_len + 1) / 2;
    size_t right_size = block_len - half_size;

    // Encode and split
    for (size_t i = 0; i < half_size; i++) {
        buf_a[i] = proc->char_to_index[block[i]];
    }
    for (size_t i = 0; i < right_size; i++) {
        buf_b[i] = proc->char_to_index[block[half_size + i]];
    }

    uint8_t *left_ptr = buf_a;
    uint8_t *right_ptr = buf_b;
    size_t left_len = half_size;
    size_t right_len = right_size;

    // Metadata (big-endian)
    uint8_t metadata[8];
    metadata[0] = (total_blocks >> 24) & 0xff;
    metadata[1] = (total_blocks >> 16) & 0xff;
    metadata[2] = (total_blocks >> 8) & 0xff;
    metadata[3] = total_blocks & 0xff;
    metadata[4] = (msg_block >> 24) & 0xff;
    metadata[5] = (msg_block >> 16) & 0xff;
    metadata[6] = (msg_block >> 8) & 0xff;
    metadata[7] = msg_block & 0xff;

    uint8_t alphabet_size = proc->alphabet_size;
    const uint8_t *comp_table = proc->comp_table;

    // Feistel rounds
    for (int round = 0; round < DATA_TOKEN_ROUNDS; round++) {
        uint8_t hash_out[64];
        hmac_sha512_with_pads(ipads[round], opads[round],
                              right_ptr, right_len,
                              metadata, 8,
                              hash_out);

        // Calculate new data
        if (is_tokenize) {
            for (size_t i = 0; i < left_len; i++) {
                uint8_t hash_val = comp_table[hash_out[i]];
                new_data[i] = ((uint16_t)left_ptr[i] + hash_val) % alphabet_size;
            }
        } else {
            for (size_t i = 0; i < left_len; i++) {
                uint8_t hash_val = comp_table[hash_out[i]];
                new_data[i] = ((uint16_t)left_ptr[i] + alphabet_size - hash_val) % alphabet_size;
            }
        }

        if (round == DATA_TOKEN_ROUNDS - 1) {
            // Last round: update left in place
            memcpy(left_ptr, new_data, left_len);
        } else {
            // Swap pointers
            uint8_t *temp_ptr = left_ptr;
            size_t temp_len = left_len;

            left_ptr = right_ptr;
            left_len = right_len;

            right_ptr = temp_ptr;
            right_len = temp_len;

            memcpy(right_ptr, new_data, right_len);
        }
    }

    // Decode to output
    const uint8_t *ascii_alphabet = proc->ascii_alphabet;
    for (size_t i = 0; i < left_len; i++) {
        output[i] = ascii_alphabet[left_ptr[i]];
    }
    for (size_t i = 0; i < right_len; i++) {
        output[left_len + i] = ascii_alphabet[right_ptr[i]];
    }
}

static char *process_data(DataTokenProcessor *proc, const char *data, size_t len,
                          size_t *out_len, bool is_tokenize) {
    if (len == 0) {
        char *result = malloc(1);
        if (result) result[0] = '\0';
        *out_len = 0;
        return result;
    }

    char *result = malloc(len + 1);
    if (!result) {
        *out_len = 0;
        return NULL;
    }

    int32_t total_blocks = (int32_t)((len + DATA_TOKEN_BLOCK_SIZE - 1) / DATA_TOKEN_BLOCK_SIZE);

    const uint8_t (*ipads)[128] = is_tokenize ?
        (const uint8_t (*)[128])proc->hmac_ipads :
        (const uint8_t (*)[128])proc->hmac_ipads_rev;
    const uint8_t (*opads)[128] = is_tokenize ?
        (const uint8_t (*)[128])proc->hmac_opads :
        (const uint8_t (*)[128])proc->hmac_opads_rev;

    size_t offset = 0;
    while (offset < len) {
        size_t end = offset + DATA_TOKEN_BLOCK_SIZE;
        if (end > len) end = len;
        size_t block_len = end - offset;

        int32_t msg_block;
        if (offset < len - (len % DATA_TOKEN_BLOCK_SIZE)) {
            msg_block = (int32_t)(len / DATA_TOKEN_BLOCK_SIZE) - (int32_t)(offset / DATA_TOKEN_BLOCK_SIZE);
        } else {
            msg_block = 0;
        }

        process_block(proc, (const uint8_t *)(data + offset), block_len,
                     (uint8_t *)(result + offset),
                     total_blocks, msg_block, is_tokenize, ipads, opads);

        offset += DATA_TOKEN_BLOCK_SIZE;
    }

    result[len] = '\0';
    *out_len = len;
    return result;
}

char *data_token_tokenize(DataTokenProcessor *proc, const char *data, size_t len, size_t *out_len) {
    return process_data(proc, data, len, out_len, true);
}

char *data_token_detokenize(DataTokenProcessor *proc, const char *data, size_t len, size_t *out_len) {
    return process_data(proc, data, len, out_len, false);
}
