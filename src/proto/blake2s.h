/*
 * BLAKE2s (RFC 7693) — vmsguard
 *
 * Implemented here rather than taken from OpenSSL deliberately. WireGuard
 * needs BLAKE2s in three shapes: unkeyed with 32-byte output, keyed with
 * 16-byte output (mac1/mac2), and as the digest inside HMAC. OpenSSL 3.0
 * exposes keyed and variable-length BLAKE2 only through EVP_MAC
 * ("BLAKE2SMAC"), which vendor builds sometimes omit — and this port
 * targets a platform where the crypto surface is not fully known.
 *
 * At ~150 lines with published test vectors, owning it removes that risk
 * entirely. X25519 and ChaCha20-Poly1305 stay on OpenSSL, where the
 * constant-time and side-channel engineering matters far more.
 *
 * C99, no allocation, no platform dependencies.
 */

#ifndef VMSGUARD_BLAKE2S_H
#define VMSGUARD_BLAKE2S_H

#include <stddef.h>
#include <stdint.h>

#define BLAKE2S_BLOCK_LEN 64
#define BLAKE2S_HASH_LEN  32
#define BLAKE2S_KEY_MAX   32

struct blake2s_state {
    uint32_t h[8];
    uint8_t  buf[BLAKE2S_BLOCK_LEN];
    uint64_t t;        /* bytes compressed so far */
    size_t   buflen;   /* bytes currently in buf */
    size_t   outlen;
};

/*
 * outlen must be 1..32. key may be NULL with keylen 0; keylen must be
 * 0..32. Behaviour is undefined outside those ranges.
 */
void blake2s_init(struct blake2s_state *s, size_t outlen,
                  const uint8_t *key, size_t keylen);
void blake2s_update(struct blake2s_state *s, const uint8_t *in, size_t inlen);
void blake2s_final(struct blake2s_state *s, uint8_t *out);

/* One-shot convenience wrapper. */
void blake2s(uint8_t *out, size_t outlen,
             const uint8_t *key, size_t keylen,
             const uint8_t *in, size_t inlen);

#endif /* VMSGUARD_BLAKE2S_H */
