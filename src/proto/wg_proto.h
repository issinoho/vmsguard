/*
 * WireGuard wire format — vmsguard
 *
 * Message layouts are expressed as explicit offsets rather than packed
 * structs. Struct packing is compiler-specific and this code has to build
 * under VSI C on OpenVMS as well as GCC/Clang; explicit offsets and
 * memcpy are portable by construction and cost nothing here.
 *
 * All multi-byte integers on the wire are little-endian.
 *
 * Layouts follow the WireGuard whitepaper, section 5.4.
 */

#ifndef VMSGUARD_WG_PROTO_H
#define VMSGUARD_WG_PROTO_H

#include <stddef.h>
#include <stdint.h>

/* Message types (first byte, followed by 3 reserved zero bytes). */
#define WG_MSG_HANDSHAKE_INIT   1
#define WG_MSG_HANDSHAKE_RESP   2
#define WG_MSG_COOKIE_REPLY     3
#define WG_MSG_TRANSPORT_DATA   4

/* Domain separation strings. Neither is NUL-terminated on the wire. */
#define WG_CONSTRUCTION "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
#define WG_IDENTIFIER   "WireGuard v1 zx2c4 Jason@zx2c4.com"
#define WG_LABEL_MAC1   "mac1----"
#define WG_LABEL_COOKIE "cookie--"

/* ---- handshake initiation, 148 bytes -------------------------------- */

#define WG_INIT_LEN            148
#define WG_INIT_OFF_TYPE         0   /* 1 byte type + 3 reserved         */
#define WG_INIT_OFF_SENDER       4   /* u32 le                           */
#define WG_INIT_OFF_EPHEMERAL    8   /* 32                               */
#define WG_INIT_OFF_STATIC      40   /* 32 + 16 tag = 48                 */
#define WG_INIT_OFF_TIMESTAMP   88   /* 12 + 16 tag = 28                 */
#define WG_INIT_OFF_MAC1       116   /* 16                               */
#define WG_INIT_OFF_MAC2       132   /* 16                               */

/* ---- handshake response, 92 bytes ----------------------------------- */

#define WG_RESP_LEN             92
#define WG_RESP_OFF_TYPE         0   /* 1 byte type + 3 reserved         */
#define WG_RESP_OFF_SENDER       4   /* u32 le                           */
#define WG_RESP_OFF_RECEIVER     8   /* u32 le                           */
#define WG_RESP_OFF_EPHEMERAL   12   /* 32                               */
#define WG_RESP_OFF_EMPTY       44   /* 0 + 16 tag = 16                  */
#define WG_RESP_OFF_MAC1        60   /* 16                               */
#define WG_RESP_OFF_MAC2        76   /* 16                               */

/* ---- transport data: 16-byte header, then ciphertext ---------------- */

#define WG_DATA_HDR_LEN         16
#define WG_DATA_OFF_TYPE         0   /* 1 byte type + 3 reserved         */
#define WG_DATA_OFF_RECEIVER     4   /* u32 le                           */
#define WG_DATA_OFF_COUNTER      8   /* u64 le                           */

/* ---- cookie reply, 64 bytes ----------------------------------------- */

#define WG_COOKIE_LEN           64

/* ---- other sizes ---------------------------------------------------- */

#define WG_TIMESTAMP_LEN        12   /* TAI64N */

/* ---- little-endian accessors ---------------------------------------- */

/* Defined in wg_proto.c rather than as static inline in this header:
   C99 inline semantics are one of the areas where an older compiler is
   most likely to differ, and the cost here is trivial next to ChaCha20. */

void     wg_put32(uint8_t *p, uint32_t v);
uint32_t wg_get32(const uint8_t *p);
void     wg_put64(uint8_t *p, uint64_t v);
uint64_t wg_get64(const uint8_t *p);

#endif /* VMSGUARD_WG_PROTO_H */
