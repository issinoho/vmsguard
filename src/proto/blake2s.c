/*
 * BLAKE2s (RFC 7693) — vmsguard
 *
 * Straightforward reference-style implementation. Speed is deliberately
 * not a goal: BLAKE2s is used only in the WireGuard handshake, on inputs
 * of a few dozen bytes. Transport data never touches it.
 */

#include <string.h>

#include "blake2s.h"

static const uint32_t blake2s_iv[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t blake2s_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

/* Explicit little-endian access: never rely on host byte order. */

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) |
           ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) (v & 0xFF);
    p[1] = (uint8_t) ((v >> 8) & 0xFF);
    p[2] = (uint8_t) ((v >> 16) & 0xFF);
    p[3] = (uint8_t) ((v >> 24) & 0xFF);
}

static uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

#define G(a, b, c, d, x, y)                     \
    do {                                        \
        v[a] = v[a] + v[b] + (x);               \
        v[d] = rotr32(v[d] ^ v[a], 16);         \
        v[c] = v[c] + v[d];                     \
        v[b] = rotr32(v[b] ^ v[c], 12);         \
        v[a] = v[a] + v[b] + (y);               \
        v[d] = rotr32(v[d] ^ v[a], 8);          \
        v[c] = v[c] + v[d];                     \
        v[b] = rotr32(v[b] ^ v[c], 7);          \
    } while (0)

static void blake2s_compress(struct blake2s_state *s, const uint8_t block[64],
                             int last)
{
    uint32_t v[16], m[16];
    int i;

    for (i = 0; i < 16; i++)
        m[i] = load32_le(block + 4 * i);

    for (i = 0; i < 8; i++)
        v[i] = s->h[i];
    for (i = 0; i < 8; i++)
        v[8 + i] = blake2s_iv[i];

    v[12] ^= (uint32_t) (s->t & 0xFFFFFFFFUL);
    v[13] ^= (uint32_t) ((s->t >> 32) & 0xFFFFFFFFUL);
    if (last)
        v[14] = ~v[14];

    for (i = 0; i < 10; i++) {
        const uint8_t *sig = blake2s_sigma[i];
        G(0, 4,  8, 12, m[sig[0]],  m[sig[1]]);
        G(1, 5,  9, 13, m[sig[2]],  m[sig[3]]);
        G(2, 6, 10, 14, m[sig[4]],  m[sig[5]]);
        G(3, 7, 11, 15, m[sig[6]],  m[sig[7]]);
        G(0, 5, 10, 15, m[sig[8]],  m[sig[9]]);
        G(1, 6, 11, 12, m[sig[10]], m[sig[11]]);
        G(2, 7,  8, 13, m[sig[12]], m[sig[13]]);
        G(3, 4,  9, 14, m[sig[14]], m[sig[15]]);
    }

    for (i = 0; i < 8; i++)
        s->h[i] ^= v[i] ^ v[8 + i];
}

void blake2s_init(struct blake2s_state *s, size_t outlen,
                  const uint8_t *key, size_t keylen)
{
    int i;

    memset(s, 0, sizeof *s);
    for (i = 0; i < 8; i++)
        s->h[i] = blake2s_iv[i];

    /* Parameter block, digest_length / key_length / fanout / depth. */
    s->h[0] ^= 0x01010000UL ^ ((uint32_t) keylen << 8) ^ (uint32_t) outlen;
    s->outlen = outlen;

    if (keylen > 0) {
        /* The key occupies a full first block, zero padded. */
        uint8_t block[BLAKE2S_BLOCK_LEN];
        memset(block, 0, sizeof block);
        memcpy(block, key, keylen);
        blake2s_update(s, block, sizeof block);
        memset(block, 0, sizeof block);
    }
}

void blake2s_update(struct blake2s_state *s, const uint8_t *in, size_t inlen)
{
    size_t i;

    for (i = 0; i < inlen; i++) {
        /* Compress only once we know more data follows: BLAKE2 finalises
           the last block differently, so it must never be compressed
           eagerly. */
        if (s->buflen == BLAKE2S_BLOCK_LEN) {
            s->t += BLAKE2S_BLOCK_LEN;
            blake2s_compress(s, s->buf, 0);
            s->buflen = 0;
        }
        s->buf[s->buflen++] = in[i];
    }
}

void blake2s_final(struct blake2s_state *s, uint8_t *out)
{
    uint8_t buf[BLAKE2S_HASH_LEN];
    size_t i;

    s->t += s->buflen;
    while (s->buflen < BLAKE2S_BLOCK_LEN)
        s->buf[s->buflen++] = 0;
    blake2s_compress(s, s->buf, 1);

    for (i = 0; i < 8; i++)
        store32_le(buf + 4 * i, s->h[i]);
    memcpy(out, buf, s->outlen);

    memset(buf, 0, sizeof buf);
    memset(s, 0, sizeof *s);
}

void blake2s(uint8_t *out, size_t outlen,
             const uint8_t *key, size_t keylen,
             const uint8_t *in, size_t inlen)
{
    struct blake2s_state s;

    blake2s_init(&s, outlen, key, keylen);
    blake2s_update(&s, in, inlen);
    blake2s_final(&s, out);
}
