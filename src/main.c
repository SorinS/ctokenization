#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "data_token.h"
#include "number_token.h"
#include "longdata_token.h"
#include "encrypt_token.h"
#include "policy_loader.h"
#include "filter.h"

typedef enum { OP_TOKENIZE, OP_DETOKENIZE, OP_ROUNDTRIP } Operation;
typedef enum { OUT_FILE, OUT_CONSOLE, OUT_NULL } OutputMode;

// Demo key (hex-encoded 32-byte key)
static const char *DEMO_KEY_HEX = "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";

static void print_usage(const char *prog) {
    printf("Tokenization Tool (C)\n\n");
    printf("Usage: %s -p <policy.json> -i <input> [options]\n\n", prog);
    printf("Required:\n");
    printf("  -p, --policy <file>     Policy JSON file (must contain key_value field)\n");
    printf("  -i, --input <file>      Input file\n\n");
    printf("Options:\n");
    printf("  -o, --output <file>     Output file (enables FILE output mode)\n");
    printf("  -m, --mode <mode>       Operation: TOKENIZE, DETOKENIZE, ROUNDTRIP [default: ROUNDTRIP]\n");
    printf("  --policy-name <name>    Policy name (required if file contains multiple policies)\n");
    printf("  -b, --buffer <size>     Buffer size (e.g., 10M, 100K) [default: 10M]\n");
    printf("  -c, --console           Output to console\n");
    printf("  -n, --null              Discard output (benchmark mode) [default]\n");
    printf("  --demo                  Run demo mode\n");
    printf("  -h, --help              Show this help\n\n");
    printf("Policy Format:\n");
    printf("  - key_value: Hex-encoded 32-byte encryption key (required)\n");
    printf("  - function: Tokenizer type (data, number, longdata, encrypt)\n");
    printf("  - left_offset/right_offset: Preserve prefix/suffix characters\n");
    printf("  - symbol_table: Custom alphabet for format-preserving tokenization\n");
    printf("  - allowed_operations: Restrict which operations can be performed\n\n");
    printf("Examples:\n");
    printf("  # Run demo\n");
    printf("  %s --demo\n\n", prog);
    printf("  # Tokenize a file\n");
    printf("  %s -p policy.json -i data.txt -m TOKENIZE -o tokens.txt\n\n", prog);
    printf("  # Round-trip test (benchmark mode)\n");
    printf("  %s -p policy.json -i data.txt -m ROUNDTRIP -n\n\n", prog);
}

static char *str_upper(char *s) {
    for (char *p = s; *p; p++) *p = toupper((unsigned char)*p);
    return s;
}

static size_t parse_size(const char *s) {
    size_t val = 0;
    size_t multiplier = 1;
    char *end;
    val = strtoul(s, &end, 10);
    if (*end == 'K' || *end == 'k') multiplier = 1024;
    else if (*end == 'M' || *end == 'm') multiplier = 1024 * 1024;
    else if (*end == 'G' || *end == 'g') multiplier = 1024 * 1024 * 1024;
    return val * multiplier;
}

static const char *format_size(size_t bytes, char *buf, size_t buf_size) {
    if (bytes >= 1024 * 1024 * 1024) {
        snprintf(buf, buf_size, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    } else if (bytes >= 1024 * 1024) {
        snprintf(buf, buf_size, "%.2f MB", bytes / (1024.0 * 1024.0));
    } else if (bytes >= 1024) {
        snprintf(buf, buf_size, "%.2f KB", bytes / 1024.0);
    } else {
        snprintf(buf, buf_size, "%zu bytes", bytes);
    }
    return buf;
}

// Create a demo policy with embedded key
static Policy create_demo_policy(const char *name, const char *function) {
    Policy p;
    memset(&p, 0, sizeof(Policy));
    p.name = strdup(name);
    p.function = strdup(function);
    p.key_value = strdup(DEMO_KEY_HEX);
    p.key_len = policy_hex_to_bytes(p.key_value, p.key_bytes, 32);
    p.enabled = 1;
    p.is_active = 1;
    p.type = TOKEN_TYPE_DATA;
    if (strcasecmp(function, "number") == 0) p.type = TOKEN_TYPE_NUMBER;
    else if (strcasecmp(function, "longdata") == 0) p.type = TOKEN_TYPE_LONGDATA;
    else if (strcasecmp(function, "encrypt") == 0) p.type = TOKEN_TYPE_ENCRYPT;
    return p;
}

static void free_demo_policy(Policy *p) {
    free(p->name);
    free(p->function);
    free(p->key_value);
    free(p->symbol_table);
    free(p->filter_alphabet);
}

static void run_demo(void) {
    printf("=== Tokenization Demo ===\n\n");
    size_t out_len;

    // Demo 1: DataToken
    printf("1. DataToken (Feistel cipher, deterministic):\n");
    Policy data_pol = create_demo_policy("customer_email", "data");
    DataTokenProcessor data_proc;
    data_token_init(&data_proc, data_pol.key_bytes);
    const char *data_input = "George@acme.com";
    char *data_token = data_token_tokenize(&data_proc, data_input, strlen(data_input), &out_len);
    char *data_detok = data_token_detokenize(&data_proc, data_token, out_len, &out_len);
    printf("   Policy:      %s\n", data_pol.name);
    printf("   Input:       %s\n", data_input);
    printf("   Token:       %s\n", data_token);
    printf("   Detokenized: %s\n", data_detok);
    printf("   Match: %s\n\n", strcmp(data_input, data_detok) == 0 ? "true" : "false");
    free(data_token); free(data_detok);
    free_demo_policy(&data_pol);

    // Demo 2: NumberToken
    printf("2. NumberToken (Format-preserving, deterministic):\n");
    Policy num_pol = create_demo_policy("customer_phone", "number");
    NumberTokenProcessor num_proc;
    number_token_init(&num_proc, num_pol.key_bytes);
    const char *num_input = "0123456789";
    char *num_token = number_token_tokenize(&num_proc, num_input, strlen(num_input), &out_len);
    char *num_detok = number_token_detokenize(&num_proc, num_token, out_len, &out_len);
    printf("   Policy:      %s\n", num_pol.name);
    printf("   Input:       %s\n", num_input);
    printf("   Token:       %s\n", num_token);
    printf("   Detokenized: %s\n", num_detok);
    printf("   Match: %s\n\n", strcmp(num_input, num_detok) == 0 ? "true" : "false");
    free(num_token); free(num_detok);
    free_demo_policy(&num_pol);

    // Demo 3: LongDataToken
    printf("3. LongDataToken (AES-CBC, deterministic):\n");
    Policy long_pol = create_demo_policy("customer_comments", "longdata");
    LongDataTokenProcessor long_proc;
    longdata_token_init(&long_proc, long_pol.key_bytes);
    const char *long_input = "This is a very very long comment field....";
    char *long_token = longdata_token_tokenize(&long_proc, long_input, strlen(long_input), &out_len);
    char *long_detok = longdata_token_detokenize(&long_proc, long_token, out_len, &out_len);
    printf("   Policy:      %s\n", long_pol.name);
    printf("   Input:       %s\n", long_input);
    printf("   Token:       %s\n", long_token);
    printf("   Detokenized: %s\n", long_detok);
    printf("   Match: %s\n\n", strcmp(long_input, long_detok) == 0 ? "true" : "false");
    free(long_token); free(long_detok);
    free_demo_policy(&long_pol);

    // Demo 4: EncryptToken
    printf("4. EncryptToken (AES-CTR with random IV, non-deterministic):\n");
    Policy enc_pol = create_demo_policy("encrypt_comments", "encrypt");
    EncryptTokenProcessor enc_proc;
    encrypt_token_init(&enc_proc, enc_pol.key_bytes);
    const char *enc_input = "This is a very very long comment field....";
    char *enc_token1 = encrypt_token_tokenize(&enc_proc, enc_input, strlen(enc_input), &out_len);
    char *enc_token2 = encrypt_token_tokenize(&enc_proc, enc_input, strlen(enc_input), &out_len);
    char *enc_detok = encrypt_token_detokenize(&enc_proc, enc_token1, strlen(enc_token1), &out_len);
    printf("   Policy:       %s\n", enc_pol.name);
    printf("   Input:        %s\n", enc_input);
    printf("   Token 1:      %s\n", enc_token1);
    printf("   Token 2:      %s\n", enc_token2);
    printf("   (Note: Different tokens for same input due to random IV)\n");
    printf("   Detokenized:  %s\n", enc_detok);
    printf("   Match: %s\n\n", strcmp(enc_input, enc_detok) == 0 ? "true" : "false");
    free(enc_token1); free(enc_token2); free(enc_detok);
    free_demo_policy(&enc_pol);

    // Demo 5: Filter (lowercase only)
    printf("5. Format-Preserving (lowercase alphabet via symbol_table):\n");
    Policy filter_pol = create_demo_policy("lowercase_text", "data");
    filter_pol.symbol_table = strdup("abcdefghijklmnopqrstuvwxyz");
    filter_pol.filter_alphabet = strdup("abcdefghijklmnopqrstuvwxyz");
    DataTokenProcessor filter_proc;
    data_token_init_with_alphabet(&filter_proc, filter_pol.key_bytes, filter_pol.symbol_table);
    Filter filter;
    filter_init(&filter, filter_pol.symbol_table);
    const char *filter_input = "Hello World 123";
    char *filter_token = filter_tokenize(&filter, &filter_proc, filter_input, strlen(filter_input), &out_len);
    char *filter_detok = filter_detokenize(&filter, &filter_proc, filter_token, out_len, &out_len);
    printf("   Policy:      %s\n", filter_pol.name);
    printf("   Alphabet:    a-z (26 chars)\n");
    printf("   Input:       %s\n", filter_input);
    printf("   Token:       %s\n", filter_token);
    printf("   Detokenized: %s\n", filter_detok);
    printf("   Match: %s\n\n", strcmp(filter_input, filter_detok) == 0 ? "true" : "false");
    free(filter_token); free(filter_detok);
    filter_free(&filter);
    free_demo_policy(&filter_pol);

    // Demo 6: Offset tokenization
    printf("6. Offset Tokenization (preserve first 2 and last 3 chars):\n");
    Policy offset_pol = create_demo_policy("partial_mask", "data");
    offset_pol.left_offset = 2;
    offset_pol.right_offset = 3;
    DataTokenProcessor offset_proc;
    data_token_init(&offset_proc, offset_pol.key_bytes);
    const char *offset_input = "ABCDEFGHIJKLM";
    size_t offset_len = strlen(offset_input);
    // Tokenize middle portion only
    const char *middle = offset_input + offset_pol.left_offset;
    size_t middle_len = offset_len - offset_pol.left_offset - offset_pol.right_offset;
    char *middle_token = data_token_tokenize(&offset_proc, middle, middle_len, &out_len);
    // Reconstruct
    char *offset_result = malloc(offset_len + 1);
    memcpy(offset_result, offset_input, offset_pol.left_offset);
    memcpy(offset_result + offset_pol.left_offset, middle_token, out_len);
    memcpy(offset_result + offset_pol.left_offset + out_len, offset_input + offset_len - offset_pol.right_offset, offset_pol.right_offset);
    offset_result[offset_len] = '\0';
    // Detokenize
    const char *det_middle = offset_result + offset_pol.left_offset;
    char *det_result_mid = data_token_detokenize(&offset_proc, det_middle, middle_len, &out_len);
    char *offset_detok = malloc(offset_len + 1);
    memcpy(offset_detok, offset_input, offset_pol.left_offset);
    memcpy(offset_detok + offset_pol.left_offset, det_result_mid, out_len);
    memcpy(offset_detok + offset_pol.left_offset + out_len, offset_result + offset_len - offset_pol.right_offset, offset_pol.right_offset);
    offset_detok[offset_len] = '\0';

    printf("   Policy:      %s (left_offset=%d, right_offset=%d)\n",
           offset_pol.name, offset_pol.left_offset, offset_pol.right_offset);
    printf("   Input:       %s\n", offset_input);
    printf("   Token:       %s\n", offset_result);
    printf("   Detokenized: %s\n", offset_detok);
    printf("   Preserved:   prefix='%.2s', suffix='%s'\n",
           offset_input, offset_input + offset_len - 3);
    printf("   Match: %s\n", strcmp(offset_input, offset_detok) == 0 ? "true" : "false");
    free(middle_token); free(offset_result); free(det_result_mid); free(offset_detok);
    free_demo_policy(&offset_pol);
}

// Tokenizer context for policy-based processing
typedef struct {
    TokenType type;
    DataTokenProcessor data_proc;
    NumberTokenProcessor num_proc;
    LongDataTokenProcessor long_proc;
    EncryptTokenProcessor enc_proc;
    Filter *filter;
    int has_filter;
    int left_offset;
    int right_offset;
} TokenizerContext;

static void init_tokenizer_from_policy(TokenizerContext *ctx, Policy *policy) {
    ctx->type = policy->type;
    ctx->filter = NULL;
    ctx->has_filter = 0;
    ctx->left_offset = policy->left_offset;
    ctx->right_offset = policy->right_offset;

    switch (policy->type) {
        case TOKEN_TYPE_DATA:
            if (policy->symbol_table) {
                data_token_init_with_alphabet(&ctx->data_proc, policy->key_bytes, policy->symbol_table);
                ctx->filter = malloc(sizeof(Filter));
                filter_init(ctx->filter, policy->symbol_table);
                ctx->has_filter = 1;
            } else {
                data_token_init(&ctx->data_proc, policy->key_bytes);
            }
            break;
        case TOKEN_TYPE_NUMBER:
            number_token_init(&ctx->num_proc, policy->key_bytes);
            if (policy->symbol_table) {
                ctx->filter = malloc(sizeof(Filter));
                filter_init(ctx->filter, policy->symbol_table);
                ctx->has_filter = 1;
            }
            break;
        case TOKEN_TYPE_LONGDATA:
            longdata_token_init(&ctx->long_proc, policy->key_bytes);
            break;
        case TOKEN_TYPE_ENCRYPT:
            encrypt_token_init(&ctx->enc_proc, policy->key_bytes);
            break;
    }
}

static void free_tokenizer_context(TokenizerContext *ctx) {
    if (ctx->has_filter && ctx->filter) {
        filter_free(ctx->filter);
        free(ctx->filter);
    }
}

static char *tokenize_base(TokenizerContext *ctx, const char *data, size_t len, size_t *out_len) {
    if (ctx->has_filter) {
        switch (ctx->type) {
            case TOKEN_TYPE_DATA:
                return filter_tokenize(ctx->filter, &ctx->data_proc, data, len, out_len);
            case TOKEN_TYPE_NUMBER:
                return filter_tokenize_number(ctx->filter, &ctx->num_proc, data, len, out_len);
            default:
                break;
        }
    }
    switch (ctx->type) {
        case TOKEN_TYPE_DATA:
            return data_token_tokenize(&ctx->data_proc, data, len, out_len);
        case TOKEN_TYPE_NUMBER:
            return number_token_tokenize(&ctx->num_proc, data, len, out_len);
        case TOKEN_TYPE_LONGDATA:
            return longdata_token_tokenize(&ctx->long_proc, data, len, out_len);
        case TOKEN_TYPE_ENCRYPT:
            return encrypt_token_tokenize(&ctx->enc_proc, data, len, out_len);
    }
    return NULL;
}

static char *detokenize_base(TokenizerContext *ctx, const char *data, size_t len, size_t *out_len) {
    if (ctx->has_filter) {
        switch (ctx->type) {
            case TOKEN_TYPE_DATA:
                return filter_detokenize(ctx->filter, &ctx->data_proc, data, len, out_len);
            case TOKEN_TYPE_NUMBER:
                return filter_detokenize_number(ctx->filter, &ctx->num_proc, data, len, out_len);
            default:
                break;
        }
    }
    switch (ctx->type) {
        case TOKEN_TYPE_DATA:
            return data_token_detokenize(&ctx->data_proc, data, len, out_len);
        case TOKEN_TYPE_NUMBER:
            return number_token_detokenize(&ctx->num_proc, data, len, out_len);
        case TOKEN_TYPE_LONGDATA:
            return longdata_token_detokenize(&ctx->long_proc, data, len, out_len);
        case TOKEN_TYPE_ENCRYPT:
            return encrypt_token_detokenize(&ctx->enc_proc, data, len, out_len);
    }
    return NULL;
}

// Tokenize with offset support
static char *tokenize_with_context(TokenizerContext *ctx, const char *data, size_t len, size_t *out_len) {
    if (ctx->left_offset <= 0 && ctx->right_offset <= 0) {
        return tokenize_base(ctx, data, len, out_len);
    }

    // Offset handling
    int left = ctx->left_offset;
    int right = ctx->right_offset;

    if ((size_t)(left + right) >= len) {
        // Nothing to tokenize - return copy
        char *copy = malloc(len + 1);
        memcpy(copy, data, len);
        copy[len] = '\0';
        *out_len = len;
        return copy;
    }

    const char *middle = data + left;
    size_t middle_len = len - left - right;
    size_t mid_out_len;
    char *mid_result = tokenize_base(ctx, middle, middle_len, &mid_out_len);
    if (!mid_result) return NULL;

    // Reconstruct: prefix + tokenized_middle + suffix
    size_t total = left + mid_out_len + right;
    char *result = malloc(total + 1);
    if (left > 0) memcpy(result, data, left);
    memcpy(result + left, mid_result, mid_out_len);
    if (right > 0) memcpy(result + left + mid_out_len, data + len - right, right);
    result[total] = '\0';
    *out_len = total;

    free(mid_result);
    return result;
}

// Detokenize with offset support
static char *detokenize_with_context(TokenizerContext *ctx, const char *data, size_t len, size_t *out_len) {
    if (ctx->left_offset <= 0 && ctx->right_offset <= 0) {
        return detokenize_base(ctx, data, len, out_len);
    }

    int left = ctx->left_offset;
    int right = ctx->right_offset;

    if ((size_t)(left + right) >= len) {
        char *copy = malloc(len + 1);
        memcpy(copy, data, len);
        copy[len] = '\0';
        *out_len = len;
        return copy;
    }

    const char *middle = data + left;
    size_t middle_len = len - left - right;
    size_t mid_out_len;
    char *mid_result = detokenize_base(ctx, middle, middle_len, &mid_out_len);
    if (!mid_result) return NULL;

    size_t total = left + mid_out_len + right;
    char *result = malloc(total + 1);
    if (left > 0) memcpy(result, data, left);
    memcpy(result + left, mid_result, mid_out_len);
    if (right > 0) memcpy(result + left + mid_out_len, data + len - right, right);
    result[total] = '\0';
    *out_len = total;

    free(mid_result);
    return result;
}

int main(int argc, char *argv[]) {
    // Defaults
    char *input_file = NULL;
    char *output_file = NULL;
    char *policy_file = NULL;
    char *policy_name = NULL;
    Operation operation = OP_ROUNDTRIP;
    OutputMode output_mode = OUT_NULL;
    size_t buffer_size = 10 * 1024 * 1024;
    int run_demo_mode = 0;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--demo") == 0) {
            run_demo_mode = 1;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--input") == 0) {
            if (++i < argc) input_file = argv[i];
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (++i < argc) { output_file = argv[i]; output_mode = OUT_FILE; }
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--policy") == 0 || strcmp(argv[i], "--policy-file") == 0) {
            if (++i < argc) policy_file = argv[i];
        } else if (strcmp(argv[i], "--policy-name") == 0) {
            if (++i < argc) policy_name = argv[i];
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--mode") == 0 || strcmp(argv[i], "--operation") == 0) {
            if (++i < argc) {
                char mode_buf[32];
                strncpy(mode_buf, argv[i], sizeof(mode_buf) - 1);
                mode_buf[sizeof(mode_buf) - 1] = '\0';
                str_upper(mode_buf);
                if (strcmp(mode_buf, "TOKENIZE") == 0) operation = OP_TOKENIZE;
                else if (strcmp(mode_buf, "DETOKENIZE") == 0) operation = OP_DETOKENIZE;
                else if (strcmp(mode_buf, "ROUNDTRIP") == 0) operation = OP_ROUNDTRIP;
            }
        } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--buffer") == 0) {
            if (++i < argc) buffer_size = parse_size(argv[i]);
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--console") == 0) {
            output_mode = OUT_CONSOLE;
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--null") == 0) {
            output_mode = OUT_NULL;
        } else if (argv[i][0] != '-') {
            if (input_file == NULL) input_file = argv[i];
        }
    }

    // Run demo if requested or no input file
    if (run_demo_mode || input_file == NULL) {
        run_demo();
        return 0;
    }

    // Policy file is required
    if (policy_file == NULL) {
        fprintf(stderr, "Error: Policy file is required (-p <file>)\n");
        fprintf(stderr, "       Policy must contain key_value field with the encryption key\n");
        return 2;
    }

    // Validate input file
    FILE *f = fopen(input_file, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot read input file '%s'\n", input_file);
        return 2;
    }

    // Load policy
    PolicyLoader loader;
    policy_loader_init(&loader);

    if (policy_loader_load_file(&loader, policy_file) != 0) {
        fprintf(stderr, "Error: Cannot load policy file '%s'\n", policy_file);
        fclose(f);
        return 2;
    }

    if (loader.count == 0) {
        fprintf(stderr, "Error: No policies found in policy file\n");
        policy_loader_free(&loader);
        fclose(f);
        return 2;
    }

    // Select policy
    Policy *policy;
    if (policy_name == NULL) {
        if (loader.count == 1) {
            policy = policy_loader_get_first(&loader);
            policy_name = policy->name;
        } else {
            fprintf(stderr, "Error: --policy-name is required when policy file contains multiple policies\n");
            policy_loader_free(&loader);
            fclose(f);
            return 2;
        }
    } else {
        policy = policy_loader_get_policy(&loader, policy_name);
        if (!policy) {
            fprintf(stderr, "Error: Policy '%s' not found in policy file\n", policy_name);
            policy_loader_free(&loader);
            fclose(f);
            return 2;
        }
    }

    // Validate operation is allowed by policy
    int allowed;
    if (operation == OP_ROUNDTRIP) {
        allowed = policy_is_operation_allowed(policy, "tokenize") &&
                  policy_is_operation_allowed(policy, "detokenize");
    } else {
        const char *op_names[] = {"tokenize", "detokenize"};
        allowed = policy_is_operation_allowed(policy, op_names[operation]);
    }
    if (!allowed) {
        fprintf(stderr, "Error: Operation not allowed by policy '%s'\n", policy_name);
        policy_loader_free(&loader);
        fclose(f);
        return 2;
    }

    // Check enabled and active
    if (!policy->enabled) {
        fprintf(stderr, "Error: Policy '%s' is not enabled\n", policy_name);
        policy_loader_free(&loader);
        fclose(f);
        return 2;
    }
    if (!policy->is_active) {
        fprintf(stderr, "Error: Policy '%s' is not active\n", policy_name);
        policy_loader_free(&loader);
        fclose(f);
        return 2;
    }

    // Verify policy has embedded key
    if (!policy->key_value || policy->key_len == 0) {
        fprintf(stderr, "Error: Policy '%s' has no embedded key (key_value field is required)\n", policy_name);
        policy_loader_free(&loader);
        fclose(f);
        return 2;
    }

    // Initialize tokenizer context from policy
    TokenizerContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    init_tokenizer_from_policy(&ctx, policy);

    // Print info
    printf("Policy:    %s (from %s)\n", policy_name, policy_file);
    if (policy->left_offset > 0 || policy->right_offset > 0) {
        printf("Offsets:   left=%d, right=%d\n", policy->left_offset, policy->right_offset);
    }
    if (policy->symbol_table) {
        printf("Alphabet:  %zu chars\n", strlen(policy->symbol_table));
    }

    const char *type_strs[] = {"DATA", "NUMBER", "LONGDATA", "ENCRYPT"};
    const char *op_strs[] = {"TOKENIZE", "DETOKENIZE", "ROUNDTRIP"};
    char size_buf[32];

    printf("\n");
    printf("Input:     %s\n", input_file);
    printf("Type:      %s\n", type_strs[policy->type]);
    printf("Operation: %s\n", op_strs[operation]);
    printf("Output:    %s\n", output_mode == OUT_FILE ? output_file : (output_mode == OUT_CONSOLE ? "CONSOLE" : "NULL"));
    printf("Buffer:    %s\n", format_size(buffer_size, size_buf, sizeof(size_buf)));
    printf("\n");

    // Read all lines
    char **lines = NULL;
    size_t num_lines = 0;
    size_t capacity = 1024;
    size_t input_bytes = 0;
    lines = malloc(capacity * sizeof(char *));

    char *line = NULL;
    size_t line_cap = 0;
    ssize_t line_len;
    while ((line_len = getline(&line, &line_cap, f)) != -1) {
        if (line_len > 0 && line[line_len - 1] == '\n') {
            line[--line_len] = '\0';
        }
        if (num_lines >= capacity) {
            capacity *= 2;
            lines = realloc(lines, capacity * sizeof(char *));
        }
        lines[num_lines] = strdup(line);
        input_bytes += line_len;
        num_lines++;
    }
    free(line);
    fclose(f);

    printf("Lines:     %zu\n", num_lines);
    printf("Input:     %s\n", format_size(input_bytes, size_buf, sizeof(size_buf)));
    printf("\n");

    // Open output file if needed
    FILE *out = NULL;
    if (output_mode == OUT_FILE) {
        out = fopen(output_file, "w");
        if (!out) {
            fprintf(stderr, "Error: Cannot open output file '%s'\n", output_file);
            return 2;
        }
    } else if (output_mode == OUT_CONSOLE) {
        out = stdout;
    }

    // Process
    clock_t start = clock();
    size_t output_bytes = 0;
    int errors = 0;

    for (size_t i = 0; i < num_lines; i++) {
        size_t len = strlen(lines[i]);
        size_t out_len;
        char *result = NULL;
        char *token = NULL;

        switch (operation) {
            case OP_TOKENIZE:
                result = tokenize_with_context(&ctx, lines[i], len, &out_len);
                break;

            case OP_DETOKENIZE:
                result = detokenize_with_context(&ctx, lines[i], len, &out_len);
                break;

            case OP_ROUNDTRIP:
                token = tokenize_with_context(&ctx, lines[i], len, &out_len);
                if (token) {
                    result = detokenize_with_context(&ctx, token, strlen(token), &out_len);
                }
                if (result && strcmp(lines[i], result) != 0) {
                    errors++;
                    if (errors <= 3) {
                        fprintf(stderr, "Round-trip error: '%s' != '%s'\n", lines[i], result);
                    }
                }
                free(token);
                break;
        }

        if (out && result) {
            fprintf(out, "%s\n", result);
        }
        if (result) {
            output_bytes += strlen(result);
            free(result);
        }
    }

    clock_t end = clock();
    double elapsed_sec = (double)(end - start) / CLOCKS_PER_SEC;
    double elapsed_ms = elapsed_sec * 1000.0;

    if (out && output_mode == OUT_FILE) {
        fclose(out);
    }

    // Results
    double lines_per_sec = num_lines / elapsed_sec;
    double mb_per_sec = (input_bytes / (1024.0 * 1024.0)) / elapsed_sec;

    printf("=== Results ===\n");
    printf("Time:      %.2f ms (%.3f sec)\n", elapsed_ms, elapsed_sec);
    printf("Speed:     %.0f lines/sec\n", lines_per_sec);
    printf("Speed:     %.2f MB/sec\n", mb_per_sec);
    if (operation == OP_ROUNDTRIP) {
        printf("Errors:    %d\n", errors);
    }
    if (output_mode == OUT_FILE) {
        printf("Output:    %s (%s)\n", output_file, format_size(output_bytes, size_buf, sizeof(size_buf)));
    }

    // Cleanup
    free_tokenizer_context(&ctx);
    for (size_t i = 0; i < num_lines; i++) {
        free(lines[i]);
    }
    free(lines);
    policy_loader_free(&loader);

    return errors > 0 ? 1 : 0;
}
