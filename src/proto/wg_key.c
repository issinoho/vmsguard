/*
 * WireGuard key encoding — vmsguard
 *
 * Hand-rolled base64 rather than OpenSSL's EVP_EncodeBlock, which
 * inserts newlines and has awkward buffer semantics. 40 lines here is
 * cheaper than working around that, and keeps the OpenVMS build's
 * dependency surface smaller.
 */

#include <string.h>

#include "wg_key.h"

static const char b64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void wg_key_to_base64(char out[WG_KEY_B64_LEN],
                      const uint8_t key[WG_KEY_LEN])
{
    size_t i, o = 0;

    /* 32 bytes is not a multiple of 3, so the last group is handled
       separately: 30 bytes encode cleanly, then 2 bytes remain. */
    for (i = 0; i + 2 < WG_KEY_LEN; i += 3) {
        uint32_t v = ((uint32_t) key[i] << 16) |
                     ((uint32_t) key[i + 1] << 8) |
                     (uint32_t) key[i + 2];
        out[o++] = b64_chars[(v >> 18) & 0x3F];
        out[o++] = b64_chars[(v >> 12) & 0x3F];
        out[o++] = b64_chars[(v >> 6) & 0x3F];
        out[o++] = b64_chars[v & 0x3F];
    }

    /* Two bytes left: 16 bits become three characters plus one '='. */
    {
        uint32_t v = ((uint32_t) key[i] << 16) |
                     ((uint32_t) key[i + 1] << 8);
        out[o++] = b64_chars[(v >> 18) & 0x3F];
        out[o++] = b64_chars[(v >> 12) & 0x3F];
        out[o++] = b64_chars[(v >> 6) & 0x3F];
        out[o++] = '=';
    }

    out[o] = '\0';
}

static int b64_value(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

int wg_key_from_base64(uint8_t key[WG_KEY_LEN], const char *in)
{
    uint8_t out[WG_KEY_LEN];
    size_t i, o = 0;

    if (in == NULL || strlen(in) != 44 || in[43] != '=')
        return -1;

    for (i = 0; i < 40; i += 4) {
        int a = b64_value(in[i]);
        int b = b64_value(in[i + 1]);
        int c = b64_value(in[i + 2]);
        int d = b64_value(in[i + 3]);
        uint32_t v;

        if (a < 0 || b < 0 || c < 0 || d < 0)
            return -1;
        v = ((uint32_t) a << 18) | ((uint32_t) b << 12) |
            ((uint32_t) c << 6) | (uint32_t) d;
        out[o++] = (uint8_t) ((v >> 16) & 0xFF);
        out[o++] = (uint8_t) ((v >> 8) & 0xFF);
        out[o++] = (uint8_t) (v & 0xFF);
    }

    /* Final group: three characters carry the last two bytes. */
    {
        int a = b64_value(in[40]);
        int b = b64_value(in[41]);
        int c = b64_value(in[42]);
        uint32_t v;

        if (a < 0 || b < 0 || c < 0)
            return -1;
        v = ((uint32_t) a << 18) | ((uint32_t) b << 12) | ((uint32_t) c << 6);
        out[o++] = (uint8_t) ((v >> 16) & 0xFF);
        out[o++] = (uint8_t) ((v >> 8) & 0xFF);

        /* The unused low bits must be zero, or this is not a canonical
           encoding of a 32-byte key. */
        if ((v & 0xFF) != 0)
            return -1;
    }

    memcpy(key, out, WG_KEY_LEN);
    return 0;
}
