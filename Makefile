# C Tokenization Library Makefile
# Requires OpenSSL for crypto operations

CC := clang
CFLAGS := -Wall -Wextra -O3 -std=c11

# OpenSSL paths (Homebrew on macOS ARM64)
OPENSSL_PREFIX := /opt/homebrew/opt/openssl@3
CFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS := -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto

SRC_DIR := src
BIN_DIR := bin
OUT := $(BIN_DIR)/ctokenization

SRCS := $(SRC_DIR)/main.c \
        $(SRC_DIR)/kms_wrapper.c \
        $(SRC_DIR)/data_token.c \
        $(SRC_DIR)/number_token.c \
        $(SRC_DIR)/longdata_token.c \
        $(SRC_DIR)/encrypt_token.c \
        $(SRC_DIR)/policy_loader.c \
        $(SRC_DIR)/filter.c

OBJS := $(SRCS:.c=.o)

.PHONY: all build clean run benchmark

all: build

build: $(BIN_DIR) $(OUT)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OUT): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(OUT)
	rm -rf $(BIN_DIR)

# Test commands
run: build
	$(OUT) tokenize data test_policy "Hello World"

benchmark: build
	$(OUT) benchmark data test_policy $(BIN_DIR)/words_alpha.txt

# Dependencies
$(SRC_DIR)/main.o: $(SRC_DIR)/kms_wrapper.h $(SRC_DIR)/data_token.h $(SRC_DIR)/number_token.h $(SRC_DIR)/longdata_token.h $(SRC_DIR)/encrypt_token.h
$(SRC_DIR)/data_token.o: $(SRC_DIR)/data_token.h
$(SRC_DIR)/number_token.o: $(SRC_DIR)/number_token.h
$(SRC_DIR)/longdata_token.o: $(SRC_DIR)/longdata_token.h
$(SRC_DIR)/encrypt_token.o: $(SRC_DIR)/encrypt_token.h
$(SRC_DIR)/kms_wrapper.o: $(SRC_DIR)/kms_wrapper.h
