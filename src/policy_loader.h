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

// Policy structure
typedef struct {
    char *name;
    TokenType type;
    char *filter_alphabet;  // NULL if not specified
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

// Load policies from JSON file
int policy_loader_load_file(PolicyLoader *loader, const char *path);

// Load policies from JSON string
int policy_loader_load_string(PolicyLoader *loader, const char *json);

// Get policy by name (returns NULL if not found)
Policy *policy_loader_get_policy(PolicyLoader *loader, const char *name);

// Print all policies (for debugging)
void policy_loader_print(PolicyLoader *loader);

#endif // POLICY_LOADER_H
