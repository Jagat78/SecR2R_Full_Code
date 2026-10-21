#ifndef SECR2R_PROTOCOL_CRYPTO_H
#define SECR2R_PROTOCOL_CRYPTO_H
#include <stddef.h>
#include <stdint.h>
/* SecR2R protocol encryption adapters using NIST P-256 / secp256r1.
 * Public key is 65-byte uncompressed SEC1 point; private scalar is 32 bytes.
 * Wire format is version(1)||plaintext_len(4, big-endian)||repeated C1(65)||C2(65),
 * with plaintext chunks of up to 16 bytes. This EC-ElGamal construction is
 * malleable and provides no ciphertext integrity by itself. */
#define SECR2R_PROTOCOL_PUB_BYTES 65u
#define SECR2R_PROTOCOL_PRIV_BYTES 32u
int secr2r_enc_lc(const uint8_t server_pub[SECR2R_PROTOCOL_PUB_BYTES],
                  const uint8_t *lc_bytes, size_t lc_len,
                  uint8_t *elc_bytes, size_t elc_capacity, size_t *elc_len);
int secr2r_dec_lc(const uint8_t server_priv[SECR2R_PROTOCOL_PRIV_BYTES],
                  const uint8_t *elc_bytes, size_t elc_len,
                  uint8_t *lc_bytes, size_t lc_capacity, size_t *lc_len);
int secr2r_enc_c5_payload(const uint8_t server_pub[SECR2R_PROTOCOL_PUB_BYTES],
                          const uint8_t *serialized_bj_y_c4, size_t payload_len,
                          uint8_t *c5_bytes, size_t c5_capacity, size_t *c5_len);
int secr2r_dec_c5_payload(const uint8_t server_priv[SECR2R_PROTOCOL_PRIV_BYTES],
                          const uint8_t *c5_bytes, size_t c5_len,
                          uint8_t *serialized_bj_y_c4, size_t payload_capacity,
                          size_t *payload_len);
#endif
