#include "longdata_token.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

// Base64 encoding/decoding
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64_encode(const uint8_t *in, size_t len, char *out) {
    size_t i, j;
    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        uint32_t v = in[i] << 16;
        if (i + 1 < len) v |= in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];

        out[j] = b64_table[(v >> 18) & 0x3f];
        out[j + 1] = b64_table[(v >> 12) & 0x3f];
        out[j + 2] = (i + 1 < len) ? b64_table[(v >> 6) & 0x3f] : '=';
        out[j + 3] = (i + 2 < len) ? b64_table[v & 0x3f] : '=';
    }
    return j;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t base64_decode(const char *in, size_t len, uint8_t *out) {
    size_t i, j;
    for (i = 0, j = 0; i < len; i += 4) {
        int v0 = b64_val(in[i]);
        int v1 = b64_val(in[i + 1]);
        int v2 = (i + 2 < len && in[i + 2] != '=') ? b64_val(in[i + 2]) : 0;
        int v3 = (i + 3 < len && in[i + 3] != '=') ? b64_val(in[i + 3]) : 0;

        if (v0 < 0 || v1 < 0) break;

        out[j++] = (v0 << 2) | (v1 >> 4);
        if (i + 2 < len && in[i + 2] != '=') out[j++] = (v1 << 4) | (v2 >> 2);
        if (i + 3 < len && in[i + 3] != '=') out[j++] = (v2 << 6) | v3;
    }
    return j;
}

void longdata_token_init(LongDataTokenProcessor *proc, const uint8_t key[32]) {
    memcpy(proc->key, key, 16); // Use first 16 bytes for AES-128
}

char *longdata_token_tokenize(LongDataTokenProcessor *proc, const char *data, size_t len, size_t *out_len) {
    // PKCS7 padding
    size_t padded_len = ((len / 16) + 1) * 16;
    uint8_t *padded = malloc(padded_len);
    if (!padded) { *out_len = 0; return NULL; }

    memcpy(padded, data, len);
    uint8_t pad_val = (uint8_t)(padded_len - len);
    memset(padded + len, pad_val, pad_val);

    // Fixed IV (all zeros for deterministic encryption)
    uint8_t iv[16] = {0};

    // Encrypt
    uint8_t *ciphertext = malloc(padded_len);
    if (!ciphertext) { free(padded); *out_len = 0; return NULL; }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, proc->key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // We handle padding ourselves

    int outlen;
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, padded, (int)padded_len);
    EVP_CIPHER_CTX_free(ctx);
    free(padded);

    // Base64 encode
    size_t b64_len = ((padded_len + 2) / 3) * 4;
    char *result = malloc(b64_len + 1);
    if (!result) { free(ciphertext); *out_len = 0; return NULL; }

    *out_len = base64_encode(ciphertext, padded_len, result);
    result[*out_len] = '\0';
    free(ciphertext);

    return result;
}

char *longdata_token_detokenize(LongDataTokenProcessor *proc, const char *data, size_t len, size_t *out_len) {
    // Base64 decode
    size_t max_decoded = (len / 4) * 3;
    uint8_t *ciphertext = malloc(max_decoded);
    if (!ciphertext) { *out_len = 0; return NULL; }

    size_t cipher_len = base64_decode(data, len, ciphertext);

    // Fixed IV
    uint8_t iv[16] = {0};

    // Decrypt
    uint8_t *plaintext = malloc(cipher_len);
    if (!plaintext) { free(ciphertext); *out_len = 0; return NULL; }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, proc->key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int outlen;
    EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, (int)cipher_len);
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    // Remove PKCS7 padding
    if (outlen > 0) {
        uint8_t pad_val = plaintext[outlen - 1];
        if (pad_val > 0 && pad_val <= 16) {
            outlen -= pad_val;
        }
    }

    char *result = malloc(outlen + 1);
    if (!result) { free(plaintext); *out_len = 0; return NULL; }

    memcpy(result, plaintext, outlen);
    result[outlen] = '\0';
    *out_len = outlen;

    free(plaintext);
    return result;
}
