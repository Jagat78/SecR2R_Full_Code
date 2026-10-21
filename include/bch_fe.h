#ifndef BCH_FE_H
#define BCH_FE_H

#include <stdint.h>
#include <stddef.h>

#define BCH_N 255
#define BCH_T 15
#define BCH_HELPER_SYMBOLS 15
#define PUF_BITS 510
#define TOEPLITZ_OUT_BITS 128
#define TOEPLITZ_SEED_BITS (PUF_BITS + TOEPLITZ_OUT_BITS - 1)

/* helper stores S1,S3,...,S29 as 15 GF(256) symbols */
void bch_fe_init(void);
void bch_secure_sketch_enroll(const uint8_t bits[BCH_N],
                              uint8_t helper[BCH_HELPER_SYMBOLS]);
int bch_secure_sketch_reconstruct(const uint8_t noisy[BCH_N],
                                  const uint8_t helper[BCH_HELPER_SYMBOLS],
                                  uint8_t corrected[BCH_N],
                                  unsigned *num_corrected);

/* Bits are packed as 0/1 bytes. seed[i+j] is Toeplitz matrix entry T[i,j]. */
void toeplitz_extract_128(const uint8_t input[PUF_BITS],
                          const uint8_t seed[TOEPLITZ_SEED_BITS],
                          uint8_t output[TOEPLITZ_OUT_BITS]);

#endif
