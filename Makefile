CC ?= cc
AR ?= ar
CPPFLAGS ?= -Iinclude
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic
LDFLAGS ?=
OPENSSL_LIBS ?= -lcrypto
MATH_LIBS ?= -lm
BIN_DIR ?= bin

CRYPTO_SOURCES := \
	src/bch.c \
	src/fuzzy_extractor.c \
	src/secr2r_ecc_elgamal.c \
	src/secr2r_ecies.c \
	src/secr2r_hash.c \
	src/secr2r_protocol_crypto.c \
	src/secure_random.c
CRYPTO_OBJECTS := $(patsubst src/%.c,$(BIN_DIR)/obj/%.o,$(CRYPTO_SOURCES))
HEADERS := $(wildcard include/*.h)
CRYPTO_LIBRARY := $(BIN_DIR)/libsecr2r.a
PROGRAMS := \
	$(BIN_DIR)/registration \
	$(BIN_DIR)/authentication \
	$(BIN_DIR)/entropy_analysis \
	$(BIN_DIR)/xlsx_export

.PHONY: all clean

all: $(PROGRAMS) $(CRYPTO_LIBRARY)

$(BIN_DIR) $(BIN_DIR)/obj:
	mkdir -p $@

$(BIN_DIR)/obj/%.o: src/%.c $(HEADERS) | $(BIN_DIR)/obj
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(CRYPTO_LIBRARY): $(CRYPTO_OBJECTS) | $(BIN_DIR)
	$(AR) rcs $@ $^

$(BIN_DIR)/registration: src/registration.c $(CRYPTO_LIBRARY) | $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< $(CRYPTO_LIBRARY) $(OPENSSL_LIBS) -o $@

$(BIN_DIR)/authentication: src/authentication.c $(CRYPTO_LIBRARY) | $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< $(CRYPTO_LIBRARY) $(OPENSSL_LIBS) -o $@

$(BIN_DIR)/entropy_analysis: src/entropy_analysis.c | $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< $(MATH_LIBS) -o $@

$(BIN_DIR)/xlsx_export: src/xlsx_export.c | $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	rm -f $(PROGRAMS) $(CRYPTO_LIBRARY) $(CRYPTO_OBJECTS)
