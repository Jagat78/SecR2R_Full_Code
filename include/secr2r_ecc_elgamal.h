#ifndef SECR2R_ECC_ELGAMAL_H
#define SECR2R_ECC_ELGAMAL_H
#include <stddef.h>
#include <stdint.h>

/* Textbook ECC ElGamal over NIST P-521 (secp521r1). This is NOT CCA-secure and does not
 * provide ciphertext integrity. Do not use on an adversarial channel without
 * a separately specified authentication mechanism.
 * Public key: Pub=[s]P, 133-byte uncompressed SEC1 point.
 * Private scalar: 66-byte big-endian (valid scalar 1..n-1).
 * Wire format: version(1) || plaintext_len(4, big-endian) || for each
 * 24-byte plaintext chunk: C1(133-byte point) || C2(133-byte point).
 * Message encoding: chunk M (1..24 bytes, zero-padded on final chunk) is
 * embedded as an even-y secp521r1 point with x = integer(chunk || counter_byte),
 * searching counter_byte 0..255. Decryption recovers chunk=floor(x/256).
 * Ciphertext size = 5 + ceil(plaintext_len/24)*266 bytes.
 */
#define SECR2R_EG_VERSION 1u
#define SECR2R_EG_PUB_BYTES 133u
#define SECR2R_EG_POINT_BYTES 133u
#define SECR2R_EG_CHUNK_BYTES 24u
#define SECR2R_EG_OVERHEAD 5u
int secr2r_eg_keygen(uint8_t private_key[66], uint8_t public_key[133]);
int secr2r_eg_encrypt(const uint8_t recipient_public_key[133],
                      const uint8_t *plaintext, size_t plaintext_len,
                      uint8_t *ciphertext, size_t ciphertext_capacity,
                      size_t *ciphertext_len);
int secr2r_eg_decrypt(const uint8_t recipient_private_key[66],
                      const uint8_t *ciphertext, size_t ciphertext_len,
                      uint8_t *plaintext, size_t plaintext_capacity,
                      size_t *plaintext_len);
#endif
