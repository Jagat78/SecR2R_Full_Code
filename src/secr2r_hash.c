#include "secr2r_hash.h"
#include <openssl/evp.h>
int secr2r_h(const uint8_t *input, size_t input_len, uint8_t output[SECR2R_HASH_BYTES]) {
    unsigned int out_len = 0;
    if ((!input && input_len != 0) || !output) return 0;
    if (EVP_Digest(input, input_len, output, &out_len, EVP_sha256(), NULL) != 1 || out_len != SECR2R_HASH_BYTES) return 0;
    return 1;
}
