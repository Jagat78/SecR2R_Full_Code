#include "fuzzy_extractor.h"
#include <string.h>

static uint8_t packed_get(const uint8_t *p, unsigned i) {
    return (uint8_t)((p[i / 8u] >> (7u - (i % 8u))) & 1u);
}
static void packed_set(uint8_t *p, unsigned i, uint8_t b) {
    uint8_t mask = (uint8_t)(1u << (7u - (i % 8u)));
    if (b) p[i / 8u] |= mask; else p[i / 8u] &= (uint8_t)~mask;
}
static void toeplitz(const uint8_t input[FE_INPUT_BITS],
                     const uint8_t seed[FE_SEED_BYTES],
                     uint8_t output[FE_SECRET_BYTES]) {
    memset(output, 0, FE_SECRET_BYTES);
    /* T[i,j] = seed[i+j], output and seed bit order are MSB-first. */
    for (unsigned i = 0; i < FE_OUT_BITS; ++i) {
        uint8_t v = 0;
        for (unsigned j = 0; j < FE_INPUT_BITS; ++j)
            v ^= (uint8_t)((input[j] & 1u) & packed_get(seed, i + j));
        packed_set(output, i, v);
    }
}
int fe_gen(const uint8_t response[FE_INPUT_BITS], const uint8_t seed_bits[FE_SEED_BITS],
           fe_helper_t *helper, uint8_t secret[FE_SECRET_BYTES]) {
    if (!response || !seed_bits || !helper || !secret) return 0;
    for (unsigned i=0;i<FE_INPUT_BITS;i++) if (response[i] > 1u) return 0;
    for (unsigned i=0;i<FE_SEED_BITS;i++) if (seed_bits[i] > 1u) return 0;
    memset(helper, 0, sizeof(*helper));
    for (unsigned i=0;i<FE_SEED_BITS;i++) packed_set(helper->toeplitz_seed, i, seed_bits[i]);
    bch_secure_sketch_enroll(response, helper->block_helper[0]);
    bch_secure_sketch_enroll(response + BCH_N, helper->block_helper[1]);
    toeplitz(response, helper->toeplitz_seed, secret);
    return 1;
}
int fe_rep(const uint8_t noisy[FE_INPUT_BITS], const fe_helper_t *helper,
           uint8_t secret[FE_SECRET_BYTES], unsigned corrected[FE_BLOCKS]) {
    if (!noisy || !helper || !secret) return 0;
    uint8_t recovered[FE_INPUT_BITS];
    for (unsigned b=0;b<FE_BLOCKS;b++) {
        unsigned n=0;
        int ok=bch_secure_sketch_reconstruct(noisy+b*BCH_N, helper->block_helper[b],
                                             recovered+b*BCH_N, &n);
        if (corrected) corrected[b]=n;
        if (!ok) { memset(secret,0,FE_SECRET_BYTES); return 0; }
    }
    toeplitz(recovered, helper->toeplitz_seed, secret);
    return 1;
}
int fe_helper_serialize(const fe_helper_t *helper, uint8_t out[FE_HELPER_BYTES]) {
    if (!helper || !out) return 0;
    memcpy(out, helper->block_helper[0], BCH_HELPER_SYMBOLS);
    memcpy(out+BCH_HELPER_SYMBOLS, helper->block_helper[1], BCH_HELPER_SYMBOLS);
    memcpy(out+2u*BCH_HELPER_SYMBOLS, helper->toeplitz_seed, FE_SEED_BYTES);
    return 1;
}
int fe_helper_deserialize(const uint8_t in[FE_HELPER_BYTES], fe_helper_t *helper) {
    if (!in || !helper) return 0;
    memcpy(helper->block_helper[0], in, BCH_HELPER_SYMBOLS);
    memcpy(helper->block_helper[1], in+BCH_HELPER_SYMBOLS, BCH_HELPER_SYMBOLS);
    memcpy(helper->toeplitz_seed, in+2u*BCH_HELPER_SYMBOLS, FE_SEED_BYTES);
    /* 637 bits occupy 80 bytes; low 3 unused bits must be zero. */
    return (helper->toeplitz_seed[FE_SEED_BYTES-1u] & 0x07u) == 0u;
}
