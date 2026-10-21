#include "secr2r_ecies.h"
#include <limits.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#define ECIES_INFO "SecR2R-ECIES-v1|P-256|HKDF-SHA-256|AES-256-GCM"

static EC_KEY *key_from_private(const uint8_t priv[32]) {
    EC_KEY *key = NULL; BIGNUM *d = NULL; EC_POINT *q = NULL;
    const EC_GROUP *group;
    if (!priv) return NULL;
    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) return NULL;
    group = EC_KEY_get0_group(key);
    d = BN_bin2bn(priv, 32, NULL);
    if (!d || BN_is_zero(d) || BN_is_negative(d) ||
        BN_cmp(d, EC_GROUP_get0_order(group)) >= 0) goto err;
    q = EC_POINT_new(group);
    if (!q || EC_POINT_mul(group, q, d, NULL, NULL, NULL) != 1 ||
        EC_KEY_set_private_key(key, d) != 1 || EC_KEY_set_public_key(key, q) != 1 ||
        EC_KEY_check_key(key) != 1) goto err;
    BN_clear_free(d); EC_POINT_free(q); return key;
err:
    BN_clear_free(d); EC_POINT_free(q); EC_KEY_free(key); return NULL;
}

static int parse_public(const uint8_t pub[65], EC_KEY **out) {
    EC_KEY *key = NULL; EC_POINT *point = NULL; const EC_GROUP *group;
    if (!pub || !out || pub[0] != 0x04) return 0;
    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) return 0;
    group = EC_KEY_get0_group(key); point = EC_POINT_new(group);
    if (!point || EC_POINT_oct2point(group, point, pub, 65, NULL) != 1 ||
        EC_POINT_is_at_infinity(group, point) == 1 ||
        EC_POINT_is_on_curve(group, point, NULL) != 1 ||
        EC_KEY_set_public_key(key, point) != 1 || EC_KEY_check_key(key) != 1) {
        EC_POINT_free(point); EC_KEY_free(key); return 0;
    }
    EC_POINT_free(point); *out = key; return 1;
}

static int serialize_public(const EC_KEY *key, uint8_t out[65]) {
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *point = EC_KEY_get0_public_key(key);
    return EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                              out, 65, NULL) == 65;
}

static int derive_key(const EC_KEY *own, const EC_KEY *peer,
                      const uint8_t *salt, size_t salt_len, uint8_t out[32]) {
    uint8_t shared[32]; int shared_len; EVP_PKEY_CTX *ctx = NULL;
    int ok = 0;
    shared_len = ECDH_compute_key(shared, sizeof(shared), EC_KEY_get0_public_key(peer),
                                  (EC_KEY *)own, NULL);
    if (shared_len <= 0 || shared_len > (int)sizeof(shared)) goto done;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)salt_len) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, shared, shared_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, (const unsigned char *)ECIES_INFO,
                                    (int)(sizeof(ECIES_INFO)-1)) <= 0) goto done;
    size_t out_len = 32;
    if (EVP_PKEY_derive(ctx, out, &out_len) <= 0 || out_len != 32) goto done;
    ok = 1;
done:
    OPENSSL_cleanse(shared, sizeof(shared)); EVP_PKEY_CTX_free(ctx);
    return ok;
}

int secr2r_ecies_keygen(uint8_t priv[32], uint8_t pub[65]) {
    EC_KEY *key = NULL; const BIGNUM *d; int ok = 0;
    if (!priv || !pub) return 0;
    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key || EC_KEY_generate_key(key) != 1) goto done;
    d = EC_KEY_get0_private_key(key);
    if (BN_bn2binpad(d, priv, 32) != 32 || !serialize_public(key, pub)) goto done;
    ok = 1;
done:
    if (!ok) { OPENSSL_cleanse(priv, 32); OPENSSL_cleanse(pub, 65); }
    EC_KEY_free(key); return ok;
}

int secr2r_ecies_encrypt(const uint8_t recipient_pub[65], const uint8_t *pt,
                         size_t pt_len, uint8_t *ct, size_t cap, size_t *ct_len) {
    EC_KEY *recipient = NULL, *ephemeral = NULL; EVP_CIPHER_CTX *cctx = NULL;
    uint8_t keybytes[32]; int n = 0, total = 0, ok = 0; size_t need;
    if (ct_len) *ct_len = 0;
    if (!recipient_pub || (!pt && pt_len) || !ct || !ct_len || pt_len > INT_MAX) return 0;
    if (pt_len > SIZE_MAX - SECR2R_ECIES_OVERHEAD) return 0;
    need = pt_len + SECR2R_ECIES_OVERHEAD;
    if (cap < need) { *ct_len = need; return 0; }
    if (!parse_public(recipient_pub, &recipient)) goto done;
    ephemeral = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ephemeral || EC_KEY_generate_key(ephemeral) != 1) goto done;
    ct[0] = SECR2R_ECIES_VERSION;
    if (!serialize_public(ephemeral, ct + 1) ||
        RAND_bytes(ct + 1 + 65, SECR2R_ECIES_NONCE_BYTES) != 1 ||
        !derive_key(ephemeral, recipient, ct + 1 + 65, SECR2R_ECIES_NONCE_BYTES, keybytes)) goto done;
    cctx = EVP_CIPHER_CTX_new(); if (!cctx) goto done;
    if (EVP_EncryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_EncryptInit_ex(cctx, NULL, NULL, keybytes, ct + 1 + 65) != 1 ||
        EVP_EncryptUpdate(cctx, NULL, &n, ct, (int)SECR2R_ECIES_HEADER_BYTES) != 1) goto done;
    if (pt_len && EVP_EncryptUpdate(cctx, ct + SECR2R_ECIES_HEADER_BYTES, &n, pt, (int)pt_len) != 1) goto done;
    total = n;
    if (EVP_EncryptFinal_ex(cctx, ct + SECR2R_ECIES_HEADER_BYTES + total, &n) != 1) goto done;
    total += n;
    if ((size_t)total != pt_len || EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, 16,
         ct + SECR2R_ECIES_HEADER_BYTES + pt_len) != 1) goto done;
    *ct_len = need; ok = 1;
done:
    if (!ok && ct && cap) OPENSSL_cleanse(ct, cap < need ? cap : need);
    OPENSSL_cleanse(keybytes, sizeof(keybytes)); EVP_CIPHER_CTX_free(cctx);
    EC_KEY_free(ephemeral); EC_KEY_free(recipient); return ok;
}

int secr2r_ecies_decrypt(const uint8_t priv[32], const uint8_t *ct, size_t ct_len,
                         uint8_t *pt, size_t cap, size_t *pt_len) {
    EC_KEY *recipient = NULL, *ephemeral = NULL; EVP_CIPHER_CTX *cctx = NULL;
    uint8_t keybytes[32]; size_t plen; int n = 0, total = 0, ok = 0;
    if (pt_len) *pt_len = 0;
    if (!priv || !ct || !pt_len || ct_len < SECR2R_ECIES_OVERHEAD ||
        (!pt && ct_len > SECR2R_ECIES_OVERHEAD)) return 0;
    if (ct[0] != SECR2R_ECIES_VERSION) return 0;
    plen = ct_len - SECR2R_ECIES_OVERHEAD;
    if (plen > INT_MAX || cap < plen || (!pt && plen)) return 0;
    recipient = key_from_private(priv); if (!recipient) goto done;
    if (!parse_public(ct + 1, &ephemeral) ||
        !derive_key(recipient, ephemeral, ct + 1 + 65, 12, keybytes)) goto done;
    cctx = EVP_CIPHER_CTX_new(); if (!cctx) goto done;
    if (EVP_DecryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(cctx, NULL, NULL, keybytes, ct + 1 + 65) != 1 ||
        EVP_DecryptUpdate(cctx, NULL, &n, ct, (int)SECR2R_ECIES_HEADER_BYTES) != 1) goto done;
    if (plen && EVP_DecryptUpdate(cctx, pt, &n, ct + SECR2R_ECIES_HEADER_BYTES, (int)plen) != 1) goto done;
    total = n;
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG, 16,
        (void *)(ct + SECR2R_ECIES_HEADER_BYTES + plen)) != 1 ||
        EVP_DecryptFinal_ex(cctx, pt ? pt + total : NULL, &n) != 1) goto done;
    total += n; if ((size_t)total != plen) goto done;
    *pt_len = plen; ok = 1;
done:
    if (!ok && pt && cap) OPENSSL_cleanse(pt, cap);
    OPENSSL_cleanse(keybytes, sizeof(keybytes)); EVP_CIPHER_CTX_free(cctx);
    EC_KEY_free(ephemeral); EC_KEY_free(recipient); return ok;
}
