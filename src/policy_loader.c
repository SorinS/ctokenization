#include "policy_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void policy_loader_init(PolicyLoader *loader) {
    loader->policies = NULL;
    loader->count = 0;
    loader->capacity = 0;
}

static void policy_free_fields(Policy *p) {
    free(p->name);
    free(p->description);
    free(p->function);
    free(p->key_value);
    free(p->symbol_table);
    free(p->validation_failure);
    free(p->filter_alphabet);
    if (p->allowed_operations) {
        for (int i = 0; i < p->num_allowed_operations; i++) {
            free(p->allowed_operations[i]);
        }
        free(p->allowed_operations);
    }
}

void policy_loader_free(PolicyLoader *loader) {
    for (size_t i = 0; i < loader->count; i++) {
        policy_free_fields(&loader->policies[i]);
    }
    free(loader->policies);
    loader->policies = NULL;
    loader->count = 0;
    loader->capacity = 0;
}

static void ensure_capacity(PolicyLoader *loader) {
    if (loader->count >= loader->capacity) {
        size_t new_cap = loader->capacity == 0 ? 8 : loader->capacity * 2;
        loader->policies = realloc(loader->policies, new_cap * sizeof(Policy));
        loader->capacity = new_cap;
    }
}

static void policy_init_defaults(Policy *p) {
    memset(p, 0, sizeof(Policy));
    p->enabled = 1;
    p->is_active = 1;
    p->type = TOKEN_TYPE_DATA;
}

// Simple JSON helpers
static const char *skip_whitespace(const char *p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static int find_closing_quote(const char *json, int start) {
    for (int i = start; json[i]; i++) {
        if (json[i] == '\\' && json[i + 1]) {
            i++;  // Skip escaped character
        } else if (json[i] == '"') {
            return i;
        }
    }
    return -1;
}

static int find_matching_bracket(const char *json, int start, char open, char close) {
    int depth = 0;
    int in_string = 0;
    for (int i = start; json[i]; i++) {
        if (json[i] == '\\' && in_string && json[i + 1]) {
            i++;
            continue;
        }
        if (json[i] == '"') {
            in_string = !in_string;
        } else if (!in_string) {
            if (json[i] == open) depth++;
            else if (json[i] == close) {
                depth--;
                if (depth == 0) return i;
            }
        }
    }
    return -1;
}

// Unescape a JSON string in-place, returning new length
static char *unescape_json_string(const char *src, size_t src_len) {
    char *result = malloc(src_len + 1);
    if (!result) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < src_len; i++) {
        if (src[i] == '\\' && i + 1 < src_len) {
            char next = src[i + 1];
            switch (next) {
                case '"':  result[j++] = '"'; i++; break;
                case '\\': result[j++] = '\\'; i++; break;
                case '/':  result[j++] = '/'; i++; break;
                case 'n':  result[j++] = '\n'; i++; break;
                case 'r':  result[j++] = '\r'; i++; break;
                case 't':  result[j++] = '\t'; i++; break;
                case 'b':  result[j++] = '\b'; i++; break;
                case 'f':  result[j++] = '\f'; i++; break;
                case 'u':
                    if (i + 5 < src_len) {
                        char hex[5] = {src[i+2], src[i+3], src[i+4], src[i+5], 0};
                        unsigned int codepoint = (unsigned int)strtoul(hex, NULL, 16);
                        if (codepoint < 0x80) {
                            result[j++] = (char)codepoint;
                        } else if (codepoint < 0x800) {
                            result[j++] = (char)(0xC0 | (codepoint >> 6));
                            result[j++] = (char)(0x80 | (codepoint & 0x3F));
                        } else {
                            result[j++] = (char)(0xE0 | (codepoint >> 12));
                            result[j++] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
                            result[j++] = (char)(0x80 | (codepoint & 0x3F));
                        }
                        i += 5;
                    } else {
                        result[j++] = src[i];
                    }
                    break;
                default:
                    result[j++] = src[i];
            }
        } else {
            result[j++] = src[i];
        }
    }
    result[j] = '\0';
    return result;
}

static char *extract_string_value(const char *json, const char *key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char *key_pos = strstr(json, search);
    if (!key_pos) return NULL;

    // Find colon after key
    const char *colon = strchr(key_pos + strlen(search), ':');
    if (!colon) return NULL;

    // Skip whitespace
    const char *val_start = skip_whitespace(colon + 1);
    if (*val_start != '"') return NULL;

    val_start++; // Skip opening quote

    // Find closing quote (handle escaped quotes)
    int close_idx = find_closing_quote(val_start, 0);
    if (close_idx < 0) return NULL;

    return unescape_json_string(val_start, (size_t)close_idx);
}

static int extract_int_value(const char *json, const char *key, int *out) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char *key_pos = strstr(json, search);
    if (!key_pos) return 0;

    const char *colon = strchr(key_pos + strlen(search), ':');
    if (!colon) return 0;

    const char *val_start = skip_whitespace(colon + 1);

    char *end;
    long val = strtol(val_start, &end, 10);
    if (end == val_start) return 0;

    *out = (int)val;
    return 1;
}

static int extract_bool_value(const char *json, const char *key, int *out) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char *key_pos = strstr(json, search);
    if (!key_pos) return 0;

    const char *colon = strchr(key_pos + strlen(search), ':');
    if (!colon) return 0;

    const char *val_start = skip_whitespace(colon + 1);

    if (strncmp(val_start, "true", 4) == 0) {
        *out = 1;
        return 1;
    } else if (strncmp(val_start, "false", 5) == 0) {
        *out = 0;
        return 1;
    }
    return 0;
}

static int extract_string_array(const char *json, const char *key, char ***out, int *count) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char *key_pos = strstr(json, search);
    if (!key_pos) return 0;

    const char *colon = strchr(key_pos + strlen(search), ':');
    if (!colon) return 0;

    const char *arr_start_p = skip_whitespace(colon + 1);
    if (*arr_start_p != '[') return 0;

    int arr_start = (int)(arr_start_p - json);
    int arr_end = find_matching_bracket(json, arr_start, '[', ']');
    if (arr_end < 0) return 0;

    // Count and extract strings
    int capacity = 8;
    char **result = malloc(capacity * sizeof(char *));
    int n = 0;

    for (int i = arr_start + 1; i < arr_end; i++) {
        if (json[i] == '"') {
            int close = find_closing_quote(json, i + 1);
            if (close < 0) break;

            if (n >= capacity) {
                capacity *= 2;
                result = realloc(result, capacity * sizeof(char *));
            }
            result[n] = unescape_json_string(json + i + 1, (size_t)(close - i - 1));
            n++;
            i = close;
        }
    }

    *out = result;
    *count = n;
    return 1;
}

static TokenType parse_type(const char *type_str) {
    if (!type_str) return TOKEN_TYPE_DATA;
    if (strcasecmp(type_str, "DATA") == 0 || strcasecmp(type_str, "data") == 0) return TOKEN_TYPE_DATA;
    if (strcasecmp(type_str, "NUMBER") == 0 || strcasecmp(type_str, "number") == 0) return TOKEN_TYPE_NUMBER;
    if (strcasecmp(type_str, "LONGDATA") == 0 || strcasecmp(type_str, "longdata") == 0) return TOKEN_TYPE_LONGDATA;
    if (strcasecmp(type_str, "ENCRYPT") == 0 || strcasecmp(type_str, "encrypt") == 0) return TOKEN_TYPE_ENCRYPT;
    return TOKEN_TYPE_DATA;
}

int policy_hex_to_bytes(const char *hex, uint8_t *out, int max_len) {
    if (!hex) return 0;
    int hex_len = (int)strlen(hex);
    int byte_len = hex_len / 2;
    if (byte_len > max_len) byte_len = max_len;

    for (int i = 0; i < byte_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return i;
        out[i] = (uint8_t)byte;
    }
    return byte_len;
}

int policy_is_operation_allowed(Policy *policy, const char *operation) {
    if (!policy || !operation) return 0;
    if (policy->num_allowed_operations == 0) return 1;  // No restrictions

    for (int i = 0; i < policy->num_allowed_operations; i++) {
        if (strcasecmp(policy->allowed_operations[i], operation) == 0) {
            return 1;
        }
    }
    return 0;
}

// Parse new single-policy format
static int parse_new_format_policy(PolicyLoader *loader, const char *json) {
    ensure_capacity(loader);
    Policy *p = &loader->policies[loader->count];
    policy_init_defaults(p);

    // Parse top-level fields
    p->name = extract_string_value(json, "name");
    if (!p->name) return -1;

    p->description = extract_string_value(json, "description");
    extract_int_value(json, "id", &p->id);
    extract_bool_value(json, "is_active", &p->is_active);

    p->key_value = extract_string_value(json, "key_value");
    if (p->key_value) {
        p->key_len = policy_hex_to_bytes(p->key_value, p->key_bytes, 32);
    }

    p->symbol_table = extract_string_value(json, "symbol_table");
    if (p->symbol_table) {
        p->filter_alphabet = strdup(p->symbol_table);
    }

    p->validation_failure = extract_string_value(json, "validation_failure");

    extract_int_value(json, "left_offset", &p->left_offset);
    extract_int_value(json, "right_offset", &p->right_offset);

    // Parse parameters sub-object
    const char *params_key = strstr(json, "\"parameters\"");
    if (params_key) {
        const char *obj_start_p = strchr(params_key, '{');
        if (obj_start_p) {
            int obj_start = (int)(obj_start_p - json);
            int obj_end = find_matching_bracket(json, obj_start, '{', '}');
            if (obj_end > 0) {
                // Extract parameters sub-string
                size_t params_len = (size_t)(obj_end - obj_start + 1);
                char *params_json = malloc(params_len + 1);
                memcpy(params_json, json + obj_start, params_len);
                params_json[params_len] = '\0';

                extract_bool_value(params_json, "enabled", &p->enabled);

                p->function = extract_string_value(params_json, "function");
                if (p->function) {
                    p->type = parse_type(p->function);
                }

                extract_string_array(params_json, "allowed_operations",
                                     &p->allowed_operations, &p->num_allowed_operations);

                free(params_json);
            }
        }
    }

    // If function not in parameters, try top-level
    if (!p->function) {
        p->function = extract_string_value(json, "function");
        if (p->function) {
            p->type = parse_type(p->function);
        }
    }

    loader->count++;
    return 0;
}

// Parse legacy array format
static int parse_legacy_format(PolicyLoader *loader, const char *json) {
    const char *policies_key = strstr(json, "\"policies\"");
    if (!policies_key) return -1;

    const char *array_start_p = strchr(policies_key, '[');
    if (!array_start_p) return -1;

    int array_start = (int)(array_start_p - json);
    int array_end = find_matching_bracket(json, array_start, '[', ']');
    if (array_end < 0) return -1;

    // Parse each policy object
    int pos = array_start + 1;
    while (pos < array_end) {
        while (pos < array_end && json[pos] != '{') pos++;
        if (pos >= array_end) break;

        int obj_end = find_matching_bracket(json, pos, '{', '}');
        if (obj_end < 0) break;

        // Extract object content as string
        size_t obj_len = (size_t)(obj_end - pos + 1);
        char *obj = malloc(obj_len + 1);
        memcpy(obj, json + pos, obj_len);
        obj[obj_len] = '\0';

        char *name = extract_string_value(obj, "name");
        char *type_str = extract_string_value(obj, "type");
        char *filter = extract_string_value(obj, "filterAlphabet");

        if (name && type_str) {
            ensure_capacity(loader);
            Policy *p = &loader->policies[loader->count];
            policy_init_defaults(p);
            p->name = name;
            p->type = parse_type(type_str);
            p->function = strdup(type_str);
            // Lowercase the function
            for (char *c = p->function; *c; c++) *c = tolower((unsigned char)*c);
            p->filter_alphabet = filter;
            if (filter) p->symbol_table = strdup(filter);
            loader->count++;
        } else {
            free(name);
            free(filter);
        }
        free(type_str);
        free(obj);
        pos = obj_end + 1;
    }

    return 0;
}

int policy_loader_load_string(PolicyLoader *loader, const char *json) {
    // Auto-detect format: if contains "policies" key -> legacy array format
    if (strstr(json, "\"policies\"")) {
        return parse_legacy_format(loader, json);
    }
    // Otherwise new single-policy format
    return parse_new_format_policy(loader, json);
}

int policy_loader_load_file(PolicyLoader *loader, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = malloc(size + 1);
    if (!content) {
        fclose(f);
        return -1;
    }

    size_t read = fread(content, 1, size, f);
    content[read] = '\0';
    fclose(f);

    int result = policy_loader_load_string(loader, content);
    free(content);
    return result;
}

Policy *policy_loader_get_policy(PolicyLoader *loader, const char *name) {
    for (size_t i = 0; i < loader->count; i++) {
        if (strcmp(loader->policies[i].name, name) == 0) {
            return &loader->policies[i];
        }
    }
    return NULL;
}

Policy *policy_loader_get_first(PolicyLoader *loader) {
    if (loader->count > 0) return &loader->policies[0];
    return NULL;
}

void policy_loader_print(PolicyLoader *loader) {
    printf("Loaded %zu policies:\n", loader->count);
    for (size_t i = 0; i < loader->count; i++) {
        Policy *p = &loader->policies[i];
        const char *func = p->function ? p->function : "data";
        printf("  - %s (function=%s", p->name, func);
        if (p->symbol_table) {
            printf(", symbol_table=%zu chars", strlen(p->symbol_table));
        }
        if (p->left_offset > 0 || p->right_offset > 0) {
            printf(", offsets=[%d,%d]", p->left_offset, p->right_offset);
        }
        if (p->num_allowed_operations > 0) {
            printf(", ops=[");
            for (int j = 0; j < p->num_allowed_operations; j++) {
                if (j > 0) printf(",");
                printf("%s", p->allowed_operations[j]);
            }
            printf("]");
        }
        if (p->key_value) {
            printf(", key=%d bytes", p->key_len);
        }
        printf(")\n");
    }
}
