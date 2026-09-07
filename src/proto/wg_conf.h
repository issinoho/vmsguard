/*
 * WireGuard configuration file parsing — vmsguard
 *
 * The format wg-quick(8) reads: INI-ish sections, `Key = Value` lines,
 * `#` or `;` comments. A provider hands you one of these and every
 * value the gateway needs is already in it, so transcribing them into
 * command-line flags by hand is both tedious and a way to get a key
 * subtly wrong.
 *
 * Pure text in, struct out. No allocation, no I/O, no platform
 * dependency — the caller reads the file, which keeps this side
 * testable and leaves it able to compile on OpenVMS unchanged, like the
 * rest of src/proto. It sits here rather than in a directory of its own
 * for the same reason wg_key.c does: it is about WireGuard's own
 * encodings, and it needs that file's base64.
 *
 * Only the keys vmsguard can act on are interpreted. wg-quick's own
 * directives — PostUp, Table, SaveConfig and the like — are recognised
 * as none of our business and ignored rather than treated as errors,
 * because a provider's file will contain them and refusing to read it
 * would help nobody.
 */

#ifndef VMSGUARD_WG_CONF_H
#define VMSGUARD_WG_CONF_H

#include <stddef.h>
#include <stdint.h>

#include "wg_key.h"

/* Enough for any provider config seen; more are reported, not ignored. */
#define WG_CONF_MAX_ALLOWED   8
#define WG_CONF_CIDR_LEN     64
#define WG_CONF_ENDPOINT_LEN 128

/* Enough for a site with several remote networks. */
#define WG_CONF_MAX_PEERS 8

/*
 * One [Peer] section.
 *
 * A config may hold several. They are not variants of one peer: each is
 * a separate tunnel with its own keys, its own endpoint and its own
 * AllowedIPs, and it is AllowedIPs that decides which of them a given
 * packet belongs to.
 */
struct wg_conf_peer {
    uint8_t public_key[WG_KEY_LEN];
    uint8_t preshared_key[WG_KEY_LEN];
    int     have_public_key;
    int     have_preshared_key;

    /* "host:port", exactly as written; resolving is the caller's job. */
    char    endpoint[WG_CONF_ENDPOINT_LEN];
    int     have_endpoint;

    char    allowed[WG_CONF_MAX_ALLOWED][WG_CONF_CIDR_LEN];
    int     n_allowed;

    int     keepalive;      /* seconds, 0 if unset or disabled */
};

struct wg_conf {
    uint8_t private_key[WG_KEY_LEN];
    int     have_private_key;

    /* The first Address entry, with its prefix length stripped: this is
       the address the provider assigned us, which is what source NAT
       rewrites to. */
    char    address[WG_CONF_CIDR_LEN];
    int     have_address;

    struct wg_conf_peer peers[WG_CONF_MAX_PEERS];
    int     n_peers;

    int     mtu;            /* 0 if unset. The inner MTU, so it is what
                               --tunnel-mtu wants directly. */
    int     listen_port;    /* 0 if unset */

    /* Set when a line was understood but names something vmsguard
       cannot act on, so the caller can say so rather than appearing to
       have honoured it. DNS is the one that matters in practice. */
    int     saw_dns;

    char    error[192];
};

/*
 * Parse `text` (need not be NUL-terminated; `len` governs) into conf.
 * Returns 0 on success, -1 with conf->error set on failure.
 *
 * A missing value is not an error here — the caller decides which of
 * them it actually needs, since a gateway and a client want different
 * subsets.
 *
 * Several [Peer] sections are allowed. Anything the caller can only do
 * for one peer, such as source NAT, is the caller's business to refuse.
 */
int wg_conf_parse(struct wg_conf *conf, const char *text, size_t len);

#endif /* VMSGUARD_WG_CONF_H */
