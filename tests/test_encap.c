/*
 * IP-in-IP encapsulation tests — vmsguard
 *
 * The header this builds is read by the OpenVMS stack, which decides
 * from it whether the packet belongs to a configured tunnel. A field in
 * the wrong place does not fail loudly: the packet is discarded and the
 * tunnel simply appears not to work, which is the same symptom as the
 * whole mechanism being unavailable. So every field is checked, and the
 * checksum against an independent computation.
 */

#include <stdio.h>
#include <string.h>

#include "encap.h"

static int failures;
static int checks;

static void check(int cond, const char *what)
{
    checks++;
    if (cond) {
        printf("  ok    %s\n", what);
    } else {
        printf("  FAIL  %s\n", what);
        failures++;
    }
}

/* Written out separately from the one under test, so agreement means
   something. */
static unsigned recompute_checksum(const unsigned char *h)
{
    unsigned long sum = 0;
    int i;

    for (i = 0; i < 20; i += 2) {
        if (i == 10)
            continue;               /* the checksum field itself */
        sum += (unsigned long) ((h[i] << 8) | h[i + 1]);
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (~sum) & 0xFFFF;
}

#define REMOTE 0xC0000201UL         /* 192.0.2.1, the tunnel's far end */
#define LOCAL  0xC0A80050UL         /* 192.168.0.80, this machine      */

static void test_header(void)
{
    uint8_t inner[64], out[256];
    size_t n;
    size_t i;

    printf("\nthe outer header\n");

    for (i = 0; i < sizeof inner; i++)
        inner[i] = (uint8_t) (i + 1);

    n = ip4_encap(out, sizeof out, REMOTE, LOCAL, ENCAP_PROTO_IPV6,
                  0x1234, inner, sizeof inner);
    check(n == 20 + sizeof inner, "the length is header plus payload");

    check(out[0] == 0x45, "version 4, five-word header");
    check(((size_t) out[2] << 8 | out[3]) == n,
          "total length counts the header too");
    check(out[4] == 0x12 && out[5] == 0x34, "the identification is carried");
    check(out[6] == 0 && out[7] == 0,
          "no DF: the packet goes no further than our own input path");
    check(out[8] == 64, "a normal TTL");
    check(out[9] == 41, "protocol 41 says IPv6 is inside");

    check(out[12] == 192 && out[13] == 0 && out[14] == 2 && out[15] == 1,
          "sourced from the tunnel's remote end, which is what the stack"
          " matches");
    check(out[16] == 192 && out[17] == 168 && out[18] == 0 && out[19] == 80,
          "and addressed to this machine");

    check(((unsigned) out[10] << 8 | out[11]) == recompute_checksum(out),
          "the header checksum agrees with an independent computation");

    check(memcmp(out + 20, inner, sizeof inner) == 0,
          "and the inner packet is copied unchanged");
}

static void test_refusals(void)
{
    uint8_t inner[2048], out[2048];

    printf("\nwhat it refuses\n");

    memset(inner, 0x5A, sizeof inner);

    check(ip4_encap(out, 20, REMOTE, LOCAL, ENCAP_PROTO_IPV6, 1,
                    inner, 64) == 0,
          "an output buffer with no room for the payload");
    check(ip4_encap(out, 83, REMOTE, LOCAL, ENCAP_PROTO_IPV6, 1,
                    inner, 64) == 0,
          "and one a single byte short");
    check(ip4_encap(out, 84, REMOTE, LOCAL, ENCAP_PROTO_IPV6, 1,
                    inner, 64) == 84,
          "but exactly enough is enough");

    check(ip4_encap(out, sizeof out, REMOTE, LOCAL, ENCAP_PROTO_IPV6, 1,
                    inner, 0) == 0,
          "an empty inner packet");
    check(ip4_encap(out, sizeof out, REMOTE, LOCAL, ENCAP_PROTO_IPV6, 1,
                    inner, 1481) == 0,
          "an inner packet that would need the outer one fragmented");
    check(ip4_encap(out, sizeof out, REMOTE, LOCAL, ENCAP_PROTO_IPV6, 1,
                    inner, 1480) == 1500,
          "and one that just fits");
}

static void test_protocols(void)
{
    uint8_t inner[40], out[128];

    printf("\nboth protocols\n");
    memset(inner, 0, sizeof inner);

    check(ip4_encap(out, sizeof out, REMOTE, LOCAL, ENCAP_PROTO_IPV4,
                    1, inner, sizeof inner) > 0 && out[9] == 4,
          "protocol 4 for IPv4 inside");
    check(ip4_encap(out, sizeof out, REMOTE, LOCAL, ENCAP_PROTO_IPV6,
                    1, inner, sizeof inner) > 0 && out[9] == 41,
          "protocol 41 for IPv6");

    /*
     * Two packets differing only in identification must differ only
     * there and in the checksum -- anything else varying would mean
     * state leaking between calls.
     */
    {
        uint8_t a[128], b[128];
        size_t na, nb;

        na = ip4_encap(a, sizeof a, REMOTE, LOCAL, ENCAP_PROTO_IPV6,
                       0x0001, inner, sizeof inner);
        nb = ip4_encap(b, sizeof b, REMOTE, LOCAL, ENCAP_PROTO_IPV6,
                       0x0002, inner, sizeof inner);
        check(na == nb && memcmp(a, b, 4) == 0 &&
              memcmp(a + 6, b + 6, 4) == 0 &&
              memcmp(a + 12, b + 12, na - 12) == 0,
              "successive packets differ only in id and checksum");
        check(memcmp(a + 10, b + 10, 2) != 0,
              "and the checksum does change with the id");
    }
}

int main(void)
{
    printf("vmsguard encapsulation tests\n");

    test_header();
    test_refusals();
    test_protocols();

    printf("\n%s — %d checks, %d failure%s\n",
           failures == 0 ? "PASS" : "FAIL",
           checks, failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
