#ifndef SECR2R_HASH_H
#define SECR2R_HASH_H
#include <stddef.h>
#include <stdint.h>
#define SECR2R_HASH_BYTES 32u
/* The only protocol hash function h: SHA-256, 256-bit output. */
int secr2r_h(const uint8_t *input, size_t input_len, uint8_t output[SECR2R_HASH_BYTES]);
#endif
