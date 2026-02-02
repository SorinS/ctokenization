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

void policy_loader_free(PolicyLoader *loader) {
    for (size_t i = 0; i < loader->count; i++) {
        free(loader->policies[i].name);
        free(loader->policies[i].filter_alphabet);
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

// Simple JSON helpers
static const char *skip_whitespace(const char *p) {
    while (*p && isspace(*p)) p++;
    return p;
}

static const char *find_char(const char *p, char c) {
    int depth = 0;
    int in_string = 0;
    while (*p) {
        if (*p == '\\' && in_string) {
            p++;
            if (*p) p++;
            continue;
        }
        if (*p == '"') {
            in_string = !in_string;
        } else if (!in_string) {
            if (*p == '{' || *p == '[') depth++;
            else if (*p == '}' || *p == ']') depth--;
            else if (*p == c && depth == 0) return p;
        }
        p++;
    }
    return NULL;
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
    const char *val_end = val_start;
    while (*val_end && *val_end != '"') {
        if (*val_end == '\\' && *(val_end + 1)) {
            val_end += 2;
        } else {
            val_end++;
        }
    }

    if (!*val_end) return NULL;

    size_t len = val_end - val_start;
    char *result = malloc(len + 1);
    if (result) {
        memcpy(result, val_start, len);
        result[len] = '\0';
    }
    return result;
}

static TokenType parse_type(const char *type_str) {
    if (strcmp(type_str, "DATA") == 0) return TOKEN_TYPE_DATA;
    if (strcmp(type_str, "NUMBER") == 0) return TOKEN_TYPE_NUMBER;
    if (strcmp(type_str, "LONGDATA") == 0) return TOKEN_TYPE_LONGDATA;
    if (strcmp(type_str, "ENCRYPT") == 0) return TOKEN_TYPE_ENCRYPT;
    return TOKEN_TYPE_DATA; // Default
}

static int parse_policy_object(PolicyLoader *loader, const char *obj_start, const char *obj_end) {
    size_t obj_len = obj_end - obj_start;
    char *obj = malloc(obj_len + 1);
    if (!obj) return -1;
    memcpy(obj, obj_start, obj_len);
    obj[obj_len] = '\0';

    char *name = extract_string_value(obj, "name");
    char *type_str = extract_string_value(obj, "type");
    char *filter = extract_string_value(obj, "filterAlphabet");

    if (!name || !type_str) {
        free(name);
        free(type_str);
        free(filter);
        free(obj);
        return -1;
    }

    ensure_capacity(loader);
    Policy *p = &loader->policies[loader->count++];
    p->name = name;
    p->type = parse_type(type_str);
    p->filter_alphabet = filter;

    free(type_str);
    free(obj);
    return 0;
}

int policy_loader_load_string(PolicyLoader *loader, const char *json) {
    // Find "policies" array
    const char *policies_key = strstr(json, "\"policies\"");
    if (!policies_key) return -1;

    // Find array start
    const char *array_start = strchr(policies_key, '[');
    if (!array_start) return -1;

    // Find array end
    int depth = 1;
    const char *p = array_start + 1;
    const char *array_end = NULL;
    int in_string = 0;

    while (*p && depth > 0) {
        if (*p == '\\' && in_string) {
            p++;
            if (*p) p++;
            continue;
        }
        if (*p == '"') {
            in_string = !in_string;
        } else if (!in_string) {
            if (*p == '[') depth++;
            else if (*p == ']') {
                depth--;
                if (depth == 0) array_end = p;
            }
        }
        p++;
    }

    if (!array_end) return -1;

    // Parse each policy object
    p = array_start + 1;
    while (p < array_end) {
        p = skip_whitespace(p);
        if (*p != '{') {
            p++;
            continue;
        }

        const char *obj_start = p;
        depth = 1;
        p++;
        in_string = 0;

        while (*p && depth > 0) {
            if (*p == '\\' && in_string) {
                p++;
                if (*p) p++;
                continue;
            }
            if (*p == '"') {
                in_string = !in_string;
            } else if (!in_string) {
                if (*p == '{') depth++;
                else if (*p == '}') depth--;
            }
            p++;
        }

        if (parse_policy_object(loader, obj_start, p) != 0) {
            // Skip invalid policy
        }
    }

    return 0;
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

void policy_loader_print(PolicyLoader *loader) {
    printf("Loaded %zu policies:\n", loader->count);
    for (size_t i = 0; i < loader->count; i++) {
        Policy *p = &loader->policies[i];
        const char *type_str = "DATA";
        switch (p->type) {
            case TOKEN_TYPE_NUMBER: type_str = "NUMBER"; break;
            case TOKEN_TYPE_LONGDATA: type_str = "LONGDATA"; break;
            case TOKEN_TYPE_ENCRYPT: type_str = "ENCRYPT"; break;
            default: break;
        }
        printf("  - %s (type=%s", p->name, type_str);
        if (p->filter_alphabet) {
            printf(", filter=%zu chars", strlen(p->filter_alphabet));
        }
        printf(")\n");
    }
}
