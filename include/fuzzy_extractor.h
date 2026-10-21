#ifndef FUZZY_EXTRACTOR_H
#define FUZZY_EXTRACTOR_H
#include <stdint.h>
#include "bch_fe.h"
#define FE_BLOCKS 2u
#define FE_INPUT_BITS 510u
#define FE_OUT_BITS 128u
#define FE_SEED_BITS 637u
#define FE_SEED_BYTES 80u
#define FE_SECRET_BYTES 16u
#define FE_HELPER_BYTES (2u * BCH_HELPER_SYMBOLS + FE_SEED_BYTES)
typedef struct {
    uint8_t block_helper[FE_BLOCKS][BCH_HELPER_SYMBOLS];
    uint8_t toeplitz_seed[FE_SEED_BYTES]; /* packed MSB-first */
} fe_helper_t;
/* response/seed bits are arrays of bytes containing only 0 or 1.
   Caller supplies a uniformly random, independent 637-bit seed. */
int fe_gen(const uint8_t response[FE_INPUT_BITS],
           const uint8_t seed_bits[FE_SEED_BITS],
           fe_helper_t *helper, uint8_t secret[FE_SECRET_BYTES]);
int fe_rep(const uint8_t noisy[FE_INPUT_BITS], const fe_helper_t *helper,
           uint8_t secret[FE_SECRET_BYTES], unsigned corrected[FE_BLOCKS]);
int fe_helper_serialize(const fe_helper_t *helper, uint8_t out[FE_HELPER_BYTES]);
int fe_helper_deserialize(const uint8_t in[FE_HELPER_BYTES], fe_helper_t *helper);
#endif
