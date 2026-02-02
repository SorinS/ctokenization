#include "kms_wrapper.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#define KMS_ITERATIONS 1200000

static const uint8_t KMS_SALT[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

static const char *DEFAULT_PASSWORD = "this is a BCAG stand-in";

void kms_init_with_key(KMSWrapper *kms, const char *password) {
    // PBKDF2-HMAC-SHA256 to derive master key
    PKCS5_PBKDF2_HMAC(password, strlen(password),
                      KMS_SALT, 16,
                      KMS_ITERATIONS,
                      EVP_sha256(),
                      32, kms->master_key);
}

void kms_init(KMSWrapper *kms) {
    kms_init_with_key(kms, DEFAULT_PASSWORD);
}

void kms_get_key(KMSWrapper *kms, const char *policy_name, uint8_t out_key[32]) {
    // SHA256 hash of policy name
    uint8_t name_hash[32];
    SHA256((const uint8_t *)policy_name, strlen(policy_name), name_hash);

    // AES-256-ECB encrypt the hash with master key
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, kms->master_key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // No padding

    int out_len;
    // Encrypt first 16 bytes
    EVP_EncryptUpdate(ctx, out_key, &out_len, name_hash, 16);
    // Encrypt second 16 bytes
    EVP_EncryptUpdate(ctx, out_key + 16, &out_len, name_hash + 16, 16);

    EVP_CIPHER_CTX_free(ctx);
}
