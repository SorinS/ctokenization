#include "encrypt_token.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Base64 functions (same as longdata_token.c)
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

void encrypt_token_init(EncryptTokenProcessor *proc, const uint8_t key[32]) {
    memcpy(proc->key, key, 16);
}

char *encrypt_token_tokenize(EncryptTokenProcessor *proc, const char *data, size_t len, size_t *out_len) {
    // Generate random IV
    uint8_t iv[16];
    RAND_bytes(iv, 16);

    // Allocate output: IV + ciphertext (same size as plaintext for CTR mode)
    size_t total_len = 16 + len;
    uint8_t *output = malloc(total_len);
    if (!output) { *out_len = 0; return NULL; }

    // Copy IV to output
    memcpy(output, iv, 16);

    // Encrypt using AES-CTR
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, proc->key, iv);

    int outlen;
    EVP_EncryptUpdate(ctx, output + 16, &outlen, (const uint8_t *)data, (int)len);
    EVP_CIPHER_CTX_free(ctx);

    // Base64 encode
    size_t b64_len = ((total_len + 2) / 3) * 4;
    char *result = malloc(b64_len + 1);
    if (!result) { free(output); *out_len = 0; return NULL; }

    *out_len = base64_encode(output, total_len, result);
    result[*out_len] = '\0';
    free(output);

    return result;
}

char *encrypt_token_detokenize(EncryptTokenProcessor *proc, const char *data, size_t len, size_t *out_len) {
    // Base64 decode
    size_t max_decoded = (len / 4) * 3;
    uint8_t *decoded = malloc(max_decoded);
    if (!decoded) { *out_len = 0; return NULL; }

    size_t decoded_len = base64_decode(data, len, decoded);
    if (decoded_len < 16) {
        free(decoded);
        *out_len = 0;
        return NULL;
    }

    // Extract IV and ciphertext
    uint8_t iv[16];
    memcpy(iv, decoded, 16);
    size_t cipher_len = decoded_len - 16;

    // Decrypt
    char *plaintext = malloc(cipher_len + 1);
    if (!plaintext) { free(decoded); *out_len = 0; return NULL; }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, proc->key, iv);

    int outlen;
    EVP_DecryptUpdate(ctx, (uint8_t *)plaintext, &outlen, decoded + 16, (int)cipher_len);
    EVP_CIPHER_CTX_free(ctx);
    free(decoded);

    plaintext[outlen] = '\0';
    *out_len = outlen;
    return plaintext;
}
