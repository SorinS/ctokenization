#ifndef KMS_WRAPPER_H
#define KMS_WRAPPER_H

#include <stdint.h>

// KMS Wrapper for policy-based key derivation
// Uses PBKDF2-HMAC-SHA256 for master key + AES-ECB for policy key derivation
typedef struct {
    uint8_t master_key[32];
} KMSWrapper;

// Initialize with default password
void kms_init(KMSWrapper *kms);

// Initialize with custom password
void kms_init_with_key(KMSWrapper *kms, const char *password);

// Get policy-specific key
void kms_get_key(KMSWrapper *kms, const char *policy_name, uint8_t out_key[32]);

#endif // KMS_WRAPPER_H
