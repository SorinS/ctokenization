#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "kms_wrapper.h"
#include "data_token.h"
#include "number_token.h"
#include "longdata_token.h"
#include "encrypt_token.h"
#include "policy_loader.h"
#include "filter.h"

typedef enum { OP_TOKENIZE, OP_DETOKENIZE, OP_ROUNDTRIP } Operation;
typedef enum { OUT_FILE, OUT_CONSOLE, OUT_NULL } OutputMode;

static void print_usage(const char *prog) {
    printf("Tokenization Tool (C)\n\n");
    printf("Usage: %s [options] [input_file]\n\n", prog);
    printf("Options:\n");
    printf("  -i, --input <file>      Input file\n");
    printf("  -o, --output <file>     Output file (enables FILE output mode)\n");
    printf("  -t, --type <type>       Token type: DATA, NUMBER, LONGDATA, ENCRYPT\n");
    printf("  -m, --mode <mode>       Operation: TOKENIZE, DETOKENIZE, ROUNDTRIP\n");
    printf("  -p, --policy <file>     Policy JSON file\n");
    printf("  --policy-name <name>    Policy name to use (required with --policy)\n");
    printf("  -k, --key <key>         Master key for key derivation\n");
    printf("  -b, --buffer <size>     Buffer size (e.g., 10M, 100K) [default: 10M]\n");
    printf("  -c, --console           Output to console\n");
    printf("  -n, --null              Discard output (benchmark mode)\n");
    printf("  --demo                  Run demo mode\n");
    printf("  -h, --help              Show this help\n\n");
    printf("Examples:\n");
    printf("  # Run demo\n");
    printf("  %s --demo\n\n", prog);
    printf("  # Tokenize words and output to file\n");
    printf("  %s -i words.txt -o tokens.txt -t DATA -m TOKENIZE\n\n", prog);
    printf("  # Benchmark round-trip (discard output)\n");
    printf("  %s -i words.txt -t DATA -m ROUNDTRIP -n\n\n", prog);
    printf("  # Use policy-based tokenization\n");
    printf("  %s -i data.txt -p policy.json --policy-name customer_email -m TOKENIZE\n\n", prog);
}

static char *str_upper(char *s) {
    for (char *p = s; *p; p++) *p = toupper(*p);
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

static void run_demo(KMSWrapper *kms) {
    printf("=== Tokenization Demo ===\n\n");

    // Demo: DataToken
    printf("1. DataToken (Feistel cipher, deterministic):\n");
    uint8_t data_key[32];
    kms_get_key(kms, "customer_name", data_key);
    DataTokenProcessor data_proc;
    data_token_init(&data_proc, data_key);
    const char *data_input = "George@acme.com";
    size_t out_len;
    char *data_token = data_token_tokenize(&data_proc, data_input, strlen(data_input), &out_len);
    char *data_detok = data_token_detokenize(&data_proc, data_token, out_len, &out_len);
    printf("   Input:       %s\n", data_input);
    printf("   Token:       %s\n", data_token);
    printf("   Detokenized: %s\n", data_detok);
    printf("   Match: %s\n\n", strcmp(data_input, data_detok) == 0 ? "true" : "false");
    free(data_token);
    free(data_detok);

    // Demo: NumberToken
    printf("2. NumberToken (Format-preserving, deterministic):\n");
    uint8_t num_key[32];
    kms_get_key(kms, "customer_phone", num_key);
    NumberTokenProcessor num_proc;
    number_token_init(&num_proc, num_key);
    const char *num_input = "0123456789";
    char *num_token = number_token_tokenize(&num_proc, num_input, strlen(num_input), &out_len);
    char *num_detok = number_token_detokenize(&num_proc, num_token, out_len, &out_len);
    printf("   Input:       %s\n", num_input);
    printf("   Token:       %s\n", num_token);
    printf("   Detokenized: %s\n", num_detok);
    printf("   Match: %s\n\n", strcmp(num_input, num_detok) == 0 ? "true" : "false");
    free(num_token);
    free(num_detok);

    // Demo: LongDataToken
    printf("3. LongDataToken (AES-CBC, deterministic):\n");
    uint8_t long_key[32];
    kms_get_key(kms, "customer_comments", long_key);
    LongDataTokenProcessor long_proc;
    longdata_token_init(&long_proc, long_key);
    const char *long_input = "This is a very very long comment field....";
    char *long_token = longdata_token_tokenize(&long_proc, long_input, strlen(long_input), &out_len);
    char *long_detok = longdata_token_detokenize(&long_proc, long_token, out_len, &out_len);
    printf("   Input:       %s\n", long_input);
    printf("   Token:       %s\n", long_token);
    printf("   Detokenized: %s\n", long_detok);
    printf("   Match: %s\n\n", strcmp(long_input, long_detok) == 0 ? "true" : "false");
    free(long_token);
    free(long_detok);

    // Demo: EncryptToken
    printf("4. EncryptToken (AES-CTR with random IV, non-deterministic):\n");
    uint8_t enc_key[32];
    kms_get_key(kms, "encrypt_comments", enc_key);
    EncryptTokenProcessor enc_proc;
    encrypt_token_init(&enc_proc, enc_key);
    const char *enc_input = "This is a very very long comment field....";
    char *enc_token1 = encrypt_token_tokenize(&enc_proc, enc_input, strlen(enc_input), &out_len);
    char *enc_token2 = encrypt_token_tokenize(&enc_proc, enc_input, strlen(enc_input), &out_len);
    char *enc_detok = encrypt_token_detokenize(&enc_proc, enc_token1, strlen(enc_token1), &out_len);
    printf("   Input:        %s\n", enc_input);
    printf("   Token 1:      %s\n", enc_token1);
    printf("   Token 2:      %s\n", enc_token2);
    printf("   (Note: Different tokens for same input due to random IV)\n");
    printf("   Detokenized:  %s\n", enc_detok);
    printf("   Match: %s\n\n", strcmp(enc_input, enc_detok) == 0 ? "true" : "false");
    free(enc_token1);
    free(enc_token2);
    free(enc_detok);

    // Demo: Filter (format-preserving with alphabet)
    printf("5. Filter (lowercase only):\n");
    uint8_t filter_key[32];
    kms_get_key(kms, "filter_test", filter_key);
    DataTokenProcessor filter_proc;
    data_token_init(&filter_proc, filter_key);
    Filter filter;
    filter_init(&filter, "abcdefghijklmnopqrstuvwxyz");
    const char *filter_input = "Hello World 123";
    char *filter_token = filter_tokenize(&filter, &filter_proc, filter_input, strlen(filter_input), &out_len);
    char *filter_detok = filter_detokenize(&filter, &filter_proc, filter_token, out_len, &out_len);
    printf("   Alphabet:    a-z (26 chars)\n");
    printf("   Input:       %s\n", filter_input);
    printf("   Token:       %s\n", filter_token);
    printf("   Detokenized: %s\n", filter_detok);
    printf("   Match: %s\n", strcmp(filter_input, filter_detok) == 0 ? "true" : "false");
    free(filter_token);
    free(filter_detok);
    filter_free(&filter);
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
} TokenizerContext;

static void init_tokenizer_from_policy(TokenizerContext *ctx, Policy *policy, KMSWrapper *kms) {
    uint8_t key[32];
    kms_get_key(kms, policy->name, key);

    ctx->type = policy->type;
    ctx->filter = NULL;
    ctx->has_filter = 0;

    switch (policy->type) {
        case TOKEN_TYPE_DATA:
            data_token_init(&ctx->data_proc, key);
            if (policy->filter_alphabet) {
                ctx->filter = malloc(sizeof(Filter));
                filter_init(ctx->filter, policy->filter_alphabet);
                ctx->has_filter = 1;
            }
            break;
        case TOKEN_TYPE_NUMBER:
            number_token_init(&ctx->num_proc, key);
            break;
        case TOKEN_TYPE_LONGDATA:
            longdata_token_init(&ctx->long_proc, key);
            break;
        case TOKEN_TYPE_ENCRYPT:
            encrypt_token_init(&ctx->enc_proc, key);
            break;
    }
}

static void free_tokenizer_context(TokenizerContext *ctx) {
    if (ctx->has_filter && ctx->filter) {
        filter_free(ctx->filter);
        free(ctx->filter);
    }
}

static char *tokenize_with_context(TokenizerContext *ctx, const char *data, size_t len, size_t *out_len) {
    if (ctx->has_filter && ctx->type == TOKEN_TYPE_DATA) {
        return filter_tokenize(ctx->filter, &ctx->data_proc, data, len, out_len);
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

static char *detokenize_with_context(TokenizerContext *ctx, const char *data, size_t len, size_t *out_len) {
    if (ctx->has_filter && ctx->type == TOKEN_TYPE_DATA) {
        return filter_detokenize(ctx->filter, &ctx->data_proc, data, len, out_len);
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

int main(int argc, char *argv[]) {
    // Defaults
    char *input_file = NULL;
    char *output_file = NULL;
    char *master_key = NULL;
    char *policy_file = NULL;
    char *policy_name = NULL;
    TokenType token_type = TOKEN_TYPE_DATA;
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
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--type") == 0) {
            if (++i < argc) {
                char type_buf[32];
                strncpy(type_buf, argv[i], sizeof(type_buf) - 1);
                type_buf[sizeof(type_buf) - 1] = '\0';
                str_upper(type_buf);
                if (strcmp(type_buf, "DATA") == 0) token_type = TOKEN_TYPE_DATA;
                else if (strcmp(type_buf, "NUMBER") == 0) token_type = TOKEN_TYPE_NUMBER;
                else if (strcmp(type_buf, "LONGDATA") == 0) token_type = TOKEN_TYPE_LONGDATA;
                else if (strcmp(type_buf, "ENCRYPT") == 0) token_type = TOKEN_TYPE_ENCRYPT;
            }
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
        } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) {
            if (++i < argc) master_key = argv[i];
        } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--buffer") == 0) {
            if (++i < argc) buffer_size = parse_size(argv[i]);
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--console") == 0) {
            output_mode = OUT_CONSOLE;
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--null") == 0) {
            output_mode = OUT_NULL;
        } else if (argv[i][0] != '-') {
            // Positional argument - treat as input file
            if (input_file == NULL) input_file = argv[i];
        }
    }

    // Validate policy options
    if (policy_file && !policy_name) {
        fprintf(stderr, "Error: --policy-name is required when using --policy\n");
        return 2;
    }

    // Initialize KMS
    KMSWrapper kms;
    if (master_key) {
        kms_init_with_key(&kms, master_key);
    } else {
        kms_init(&kms);
    }

    // Run demo if requested or no input file
    if (run_demo_mode || input_file == NULL) {
        run_demo(&kms);
        return 0;
    }

    // Validate input file
    FILE *f = fopen(input_file, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot read input file '%s'\n", input_file);
        return 2;
    }

    // Initialize tokenizer context
    TokenizerContext ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (policy_file) {
        // Load policy
        PolicyLoader loader;
        policy_loader_init(&loader);

        if (policy_loader_load_file(&loader, policy_file) != 0) {
            fprintf(stderr, "Error: Cannot load policy file '%s'\n", policy_file);
            fclose(f);
            return 2;
        }

        Policy *policy = policy_loader_get_policy(&loader, policy_name);
        if (!policy) {
            fprintf(stderr, "Error: Policy '%s' not found in '%s'\n", policy_name, policy_file);
            policy_loader_free(&loader);
            fclose(f);
            return 2;
        }

        printf("Policy:    %s (from %s)\n", policy_name, policy_file);
        init_tokenizer_from_policy(&ctx, policy, &kms);
        token_type = policy->type;

        policy_loader_free(&loader);
    } else {
        // Direct tokenizer initialization
        uint8_t key[32];
        const char *type_names[] = {"data", "number", "longdata", "encrypt"};
        kms_get_key(&kms, type_names[token_type], key);

        ctx.type = token_type;
        ctx.has_filter = 0;
        ctx.filter = NULL;

        switch (token_type) {
            case TOKEN_TYPE_DATA: data_token_init(&ctx.data_proc, key); break;
            case TOKEN_TYPE_NUMBER: number_token_init(&ctx.num_proc, key); break;
            case TOKEN_TYPE_LONGDATA: longdata_token_init(&ctx.long_proc, key); break;
            case TOKEN_TYPE_ENCRYPT: encrypt_token_init(&ctx.enc_proc, key); break;
        }
    }

    // Print info
    const char *type_strs[] = {"DATA", "NUMBER", "LONGDATA", "ENCRYPT"};
    const char *op_strs[] = {"TOKENIZE", "DETOKENIZE", "ROUNDTRIP"};
    const char *out_strs[] = {"FILE", "CONSOLE", "NULL"};
    char size_buf[32];

    printf("\n");
    printf("Input:     %s\n", input_file);
    printf("Type:      %s\n", type_strs[token_type]);
    printf("Operation: %s\n", op_strs[operation]);
    printf("Output:    %s\n", output_mode == OUT_FILE ? output_file : out_strs[output_mode]);
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
        // Remove trailing newline
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

    return errors > 0 ? 1 : 0;
}
