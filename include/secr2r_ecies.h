#ifndef SECR2R_ECIES_H
#define SECR2R_ECIES_H
#include <stddef.h>
#include <stdint.h>

/* SecR2R ECIES profile v1 (OpenSSL desktop implementation):
 * curve: NIST P-256 / prime256v1; public keys: 65-byte uncompressed SEC1;
 * KDF: HKDF-SHA-256; AEAD: AES-256-GCM; nonce: 12 bytes; tag: 16 bytes.
 * Wire format: version(1) || ephemeral_pubkey(65) || nonce(12) ||
 *              ciphertext(plaintext_len) || tag(16).
 * The fixed header (version || ephemeral public key || nonce) is AEAD AAD.
 * Public-key APIs use raw SEC1 point bytes. Output buffer capacity must be
 * sufficient. Return 1 on success and 0 on any failure; decryption fails closed.
 * This is a concrete ECIES-style profile chosen at the user's request; it must
 * be stated as a protocol parameter in the paper and interoperably specified.
 */
#define SECR2R_ECIES_VERSION 1u
#define SECR2R_ECIES_PUBLIC_KEY_BYTES 65u
#define SECR2R_ECIES_NONCE_BYTES 12u
#define SECR2R_ECIES_TAG_BYTES 16u
#define SECR2R_ECIES_HEADER_BYTES (1u + SECR2R_ECIES_PUBLIC_KEY_BYTES + SECR2R_ECIES_NONCE_BYTES)
#define SECR2R_ECIES_OVERHEAD (SECR2R_ECIES_HEADER_BYTES + SECR2R_ECIES_TAG_BYTES)

/* Generate a P-256 key pair. Private scalar is 32-byte big-endian; public is SEC1. */
int secr2r_ecies_keygen(uint8_t private_key[32],
                        uint8_t public_key[SECR2R_ECIES_PUBLIC_KEY_BYTES]);

/* Encrypt to recipient public key. *ciphertext_len receives required/written length. */
int secr2r_ecies_encrypt(const uint8_t recipient_public_key[SECR2R_ECIES_PUBLIC_KEY_BYTES],
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *ciphertext, size_t ciphertext_capacity,
                         size_t *ciphertext_len);

/* Decrypt using recipient private scalar. *plaintext_len receives written length. */
int secr2r_ecies_decrypt(const uint8_t recipient_private_key[32],
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         uint8_t *plaintext, size_t plaintext_capacity,
                         size_t *plaintext_len);
#endif
