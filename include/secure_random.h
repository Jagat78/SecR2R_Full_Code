#ifndef SECR2R_SECURE_RANDOM_H
#define SECR2R_SECURE_RANDOM_H
#include <stddef.h>
#include <stdint.h>
#include "fuzzy_extractor.h"

/* Returns 1 only if all requested bytes came from the platform CSPRNG. */
int secr2r_random_bytes(uint8_t *out, size_t length);
/* Uses the OS CSPRNG to create the public Toeplitz seed during enrollment. */
int fe_gen_csprng(const uint8_t response[FE_INPUT_BITS],
                  fe_helper_t *helper, uint8_t secret[FE_SECRET_BYTES]);
#endif
