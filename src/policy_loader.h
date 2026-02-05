#ifndef POLICY_LOADER_H
#define POLICY_LOADER_H

#include <stddef.h>
#include <stdint.h>

// Token types
typedef enum {
    TOKEN_TYPE_DATA,
    TOKEN_TYPE_NUMBER,
    TOKEN_TYPE_LONGDATA,
    TOKEN_TYPE_ENCRYPT
} TokenType;

// Policy structure - supports both new single-policy format and legacy array format
typedef struct {
    int id;
    char *name;
    char *description;
    char *function;          // "data", "number", "longdata", "encrypt"
    int enabled;             // boolean, default 1
    int is_active;           // boolean, default 1
    int left_offset;
    int right_offset;
    char *key_value;         // Hex-encoded key string
    uint8_t key_bytes[32];   // Decoded key bytes
    int key_len;             // Length of decoded key (16 or 32)
    char *symbol_table;      // Custom alphabet for filtering
    char **allowed_operations;
    int num_allowed_operations;
    char *validation_failure;
    // Legacy fields
    TokenType type;
    char *filter_alphabet;   // NULL if not specified
} Policy;

// PolicyLoader structure
typedef struct {
    Policy *policies;
    size_t count;
    size_t capacity;
} PolicyLoader;

// Initialize policy loader
void policy_loader_init(PolicyLoader *loader);

// Free policy loader
void policy_loader_free(PolicyLoader *loader);

// Load policies from JSON file (auto-detects format)
int policy_loader_load_file(PolicyLoader *loader, const char *path);

// Load policies from JSON string (auto-detects format)
int policy_loader_load_string(PolicyLoader *loader, const char *json);

// Get policy by name (returns NULL if not found)
Policy *policy_loader_get_policy(PolicyLoader *loader, const char *name);

// Get first policy (for single-policy files)
Policy *policy_loader_get_first(PolicyLoader *loader);

// Print all policies (for debugging)
void policy_loader_print(PolicyLoader *loader);

// Check if an operation is allowed by a policy
int policy_is_operation_allowed(Policy *policy, const char *operation);

// Convert hex string to bytes, returns number of bytes written
int policy_hex_to_bytes(const char *hex, uint8_t *out, int max_len);

#endif // POLICY_LOADER_H
