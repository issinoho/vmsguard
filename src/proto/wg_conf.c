/*
 * WireGuard configuration file parsing — vmsguard
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "wg_conf.h"

/* ---- small text helpers ---------------------------------------------- */

/*
 * Case-insensitive compare. strcasecmp is POSIX rather than C99 and is
 * not guaranteed by VSI C, so it is written out; the cast through
 * unsigned char is what keeps tolower defined for bytes above 127.
 */
static int ci_equal(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        if (tolower((unsigned char) *a) != tolower((unsigned char) *b))
            return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static int is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* Trim in place, returning the start. */
static char *trim(char *s)
{
    char *end;

    while (*s != '\0' && is_space(*s))
        s++;
    if (*s == '\0')
        return s;
    end = s + strlen(s) - 1;
    while (end > s && is_space(*end))
        *end-- = '\0';
    return s;
}

static int copy_into(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);

    if (n + 1 > cap)
        return -1;
    memcpy(dst, src, n + 1);
    return 0;
}

static int parse_uint(const char *s, int *out)
{
    long v = 0;
    int digits = 0;

    if (*s == '\0')
        return -1;
    for (; *s != '\0'; s++) {
        if (*s < '0' || *s > '9')
            return -1;
        v = v * 10 + (*s - '0');
        if (v > 2147483647L)
            return -1;
        digits++;
    }
    *out = (int) v;
    return digits > 0 ? 0 : -1;
}

/* ---- parsing --------------------------------------------------------- */

#define SECT_NONE      0
#define SECT_INTERFACE 1
#define SECT_PEER      2

static void fail(struct wg_conf *conf, int lineno, const char *what)
{
    /* The line number is the whole point of the message: a provider
       config is a wall of base64 and "bad key" alone locates nothing. */
    snprintf(conf->error, sizeof conf->error, "line %d: %s", lineno, what);
}

/*
 * As fail, but quoting the line it choked on.
 *
 * Worth the trouble: a config that lost its leading '#' in transit
 * reported only "line 1: expected 'Key = Value'", which is true and
 * says nothing about the cause. Showing the text makes it obvious.
 *
 * Truncated hard, because this prints and a config file is mostly
 * secret. Only reached for a line containing no '=' at all, which a
 * pasted key line always has, so what is shown should be a stray word
 * rather than key material; the cap is there for when that reasoning
 * turns out to be wrong.
 */
static void fail_quoting(struct wg_conf *conf, int lineno, const char *what,
                         const char *text)
{
    snprintf(conf->error, sizeof conf->error, "line %d: %s: \"%.24s%s\"",
             lineno, what, text, strlen(text) > 24 ? "..." : "");
}

/*
 * Split a comma-separated value into conf->allowed. Entries beyond the
 * table are an error rather than a silent truncation: quietly dropping
 * half of AllowedIPs would route traffic somewhere the operator did not
 * ask for.
 */
static int add_allowed(struct wg_conf *conf, char *value, int lineno)
{
    char *p = value;

    while (*p != '\0') {
        char *comma = strchr(p, ',');
        char *item;

        if (comma != NULL)
            *comma = '\0';
        item = trim(p);

        if (*item != '\0') {
            if (conf->n_allowed >= WG_CONF_MAX_ALLOWED) {
                fail(conf, lineno, "too many AllowedIPs entries");
                return -1;
            }
            if (copy_into(conf->allowed[conf->n_allowed],
                          WG_CONF_CIDR_LEN, item) != 0) {
                fail(conf, lineno, "AllowedIPs entry is too long");
                return -1;
            }
            conf->n_allowed++;
        }

        if (comma == NULL)
            break;
        p = comma + 1;
    }
    return 0;
}

/* Address is given as CIDR; the prefix belongs to the interface, not to
   the address the peer knows us by, so it is dropped here. */
static int set_address(struct wg_conf *conf, char *value, int lineno)
{
    char *comma = strchr(value, ',');
    char *slash;
    char *first;

    if (comma != NULL)
        *comma = '\0';       /* only the first: we hold one address */
    first = trim(value);
    slash = strchr(first, '/');
    if (slash != NULL)
        *slash = '\0';
    first = trim(first);

    if (copy_into(conf->address, sizeof conf->address, first) != 0) {
        fail(conf, lineno, "Address is too long");
        return -1;
    }
    conf->have_address = 1;
    return 0;
}

static int set_key(struct wg_conf *conf, uint8_t out[WG_KEY_LEN], int *flag,
                   const char *value, const char *what, int lineno)
{
    if (wg_key_from_base64(out, value) != 0) {
        char msg[96];
        snprintf(msg, sizeof msg, "%s is not a valid base64 key", what);
        fail(conf, lineno, msg);
        return -1;
    }
    *flag = 1;
    return 0;
}

static int set_int(struct wg_conf *conf, int *out, const char *value,
                   const char *what, int lineno)
{
    if (parse_uint(value, out) != 0) {
        char msg[96];
        snprintf(msg, sizeof msg, "%s is not a number", what);
        fail(conf, lineno, msg);
        return -1;
    }
    return 0;
}

int wg_conf_parse(struct wg_conf *conf, const char *text, size_t len)
{
    char line[512];
    size_t pos = 0;
    int section = SECT_NONE;
    int seen_peer = 0;
    int lineno = 0;

    memset(conf, 0, sizeof *conf);

    while (pos <= len) {
        size_t start = pos;
        size_t n;
        char *s, *eq, *key, *value;
        size_t i;

        /* One line, however it is terminated. A file whose last line
           has no newline is still a line. */
        while (pos < len && text[pos] != '\n')
            pos++;
        n = pos - start;
        pos++;                       /* step over the newline */
        lineno++;

        if (start >= len && n == 0)
            break;

        if (n + 1 > sizeof line) {
            fail(conf, lineno, "line is too long");
            return -1;
        }
        memcpy(line, text + start, n);
        line[n] = '\0';

        /* Comments run to end of line. Neither character can appear in
           base64, a dotted address or a section name, so this is safe
           to do before anything else. */
        for (i = 0; line[i] != '\0'; i++) {
            if (line[i] == '#' || line[i] == ';') {
                line[i] = '\0';
                break;
            }
        }

        s = trim(line);
        if (*s == '\0')
            continue;

        if (*s == '[') {
            char *close = strchr(s, ']');

            if (close == NULL) {
                fail(conf, lineno, "section header has no closing bracket");
                return -1;
            }
            *close = '\0';
            s = trim(s + 1);

            if (ci_equal(s, "Interface")) {
                section = SECT_INTERFACE;
            } else if (ci_equal(s, "Peer")) {
                if (seen_peer) {
                    /*
                     * A multi-peer config is a meaningfully different
                     * thing, not a slightly bigger one: vmsguard holds
                     * a single peer and would silently use whichever
                     * happened to be last.
                     */
                    fail(conf, lineno,
                         "more than one [Peer]; vmsguard supports one");
                    return -1;
                }
                seen_peer = 1;
                section = SECT_PEER;
            } else {
                fail_quoting(conf, lineno, "unknown section", s);
                return -1;
            }
            continue;
        }

        eq = strchr(s, '=');
        if (eq == NULL) {
            /*
             * Most often a comment whose '#' did not survive being
             * moved onto the machine, which is why the text is shown.
             */
            fail_quoting(conf, lineno, "expected 'Key = Value'", s);
            return -1;
        }
        *eq = '\0';
        key = trim(s);
        value = trim(eq + 1);

        if (section == SECT_NONE) {
            fail(conf, lineno, "setting outside any section");
            return -1;
        }

        if (section == SECT_INTERFACE) {
            if (ci_equal(key, "PrivateKey")) {
                if (set_key(conf, conf->private_key, &conf->have_private_key,
                            value, "PrivateKey", lineno) != 0)
                    return -1;
            } else if (ci_equal(key, "Address")) {
                if (set_address(conf, value, lineno) != 0)
                    return -1;
            } else if (ci_equal(key, "MTU")) {
                if (set_int(conf, &conf->mtu, value, "MTU", lineno) != 0)
                    return -1;
            } else if (ci_equal(key, "ListenPort")) {
                if (set_int(conf, &conf->listen_port, value, "ListenPort",
                            lineno) != 0)
                    return -1;
            } else if (ci_equal(key, "DNS")) {
                /* Recorded so the caller can say it is being ignored.
                   The gateway forwards for other machines and does not
                   own their resolver configuration. */
                conf->saw_dns = 1;
            }
            /* Anything else in [Interface] is wg-quick's business. */
            continue;
        }

        /* [Peer] */
        if (ci_equal(key, "PublicKey")) {
            if (set_key(conf, conf->public_key, &conf->have_public_key,
                        value, "PublicKey", lineno) != 0)
                return -1;
        } else if (ci_equal(key, "PresharedKey")) {
            if (set_key(conf, conf->preshared_key,
                        &conf->have_preshared_key, value,
                        "PresharedKey", lineno) != 0)
                return -1;
        } else if (ci_equal(key, "Endpoint")) {
            if (copy_into(conf->endpoint, sizeof conf->endpoint,
                          value) != 0) {
                fail(conf, lineno, "Endpoint is too long");
                return -1;
            }
            conf->have_endpoint = 1;
        } else if (ci_equal(key, "AllowedIPs")) {
            if (add_allowed(conf, value, lineno) != 0)
                return -1;
        } else if (ci_equal(key, "PersistentKeepalive")) {
            if (set_int(conf, &conf->keepalive, value,
                        "PersistentKeepalive", lineno) != 0)
                return -1;
        }

        if (start + n >= len)
            break;
    }

    return 0;
}
