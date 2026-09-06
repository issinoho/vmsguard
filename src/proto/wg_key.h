/*
 * WireGuard key encoding — vmsguard
 *
 * WireGuard represents keys as standard base64 of the raw 32 bytes,
 * which comes to 44 characters ending in '='. This is the format used
 * by wg(8), wg-quick configuration files, and everything a user will
 * copy and paste, so it needs to round-trip exactly.
 */

#ifndef VMSGUARD_WG_KEY_H
#define VMSGUARD_WG_KEY_H

#include <stddef.h>
#include <stdint.h>

#include "wg_crypto.h"

/* 44 base64 characters plus a NUL. */
#define WG_KEY_B64_LEN 45

/*
 * Encode a 32-byte key as base64. out must be at least WG_KEY_B64_LEN
 * bytes and is NUL-terminated.
 */
void wg_key_to_base64(char out[WG_KEY_B64_LEN],
                      const uint8_t key[WG_KEY_LEN]);

/*
 * Decode a base64 key. Accepts exactly 44 characters of valid base64
 * with correct padding; anything else is rejected rather than
 * partially decoded, since a silently truncated key would be a
 * security problem.
 *
 * Returns 0 on success, -1 on failure.
 */
int wg_key_from_base64(uint8_t key[WG_KEY_LEN], const char *in);

#endif /* VMSGUARD_WG_KEY_H */
