/*
 * ICMP error generation tests — vmsguard
 *
 * A malformed ICMP error is worse than none: the sender ignores it and
 * the transfer still hangs, but now there is traffic suggesting the
 * problem was handled. So the checksums and the quoted original are
 * checked against independent recomputation, and the next-hop MTU is
 * checked to be where RFC 1191 says a sender will look for it.
 */

#include <stdio.h>
#include <string.h>

#include "ethip.h"
#include "icmp.h"

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

static uint16_t sum16(const uint8_t *d, size_t n)
{
    uint32_t s = 0;
    size_t i;

    for (i = 0; i + 1 < n; i += 2)
        s += ((uint32_t) d[i] << 8) | d[i + 1];
    if (i < n)
        s += (uint32_t) d[i] << 8;
    while (s >> 16)
        s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t) (~s & 0xFFFF);
}

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t) (v >> 8);
    p[1] = (uint8_t) (v & 0xFF);
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) v;
}

#define GW_ADDR   0xC0A80050UL   /* 192.168.0.80  */
#define CLIENT    0xC0A800DAUL   /* 192.168.0.218 */
#define FAR       0x01010101UL   /* 1.1.1.1       */

/* A large TCP packet with DF set, as a client doing PMTUD would send. */
static size_t build_big_tcp(uint8_t *p, size_t payload, int df)
{
    size_t total = 20 + 20 + payload;
    size_t i;
    uint8_t hdr[20];

    memset(p, 0, total);
    p[0] = 0x45;
    put16(p + 2, (uint16_t) total);
    put16(p + 4, 0xBEEF);                       /* identification */
    put16(p + 6, df ? IPV4_FLAG_DF : 0);
    p[8] = 64;
    p[9] = 6;                                   /* TCP */
    put32(p + 12, CLIENT);
    put32(p + 16, FAR);
    memcpy(hdr, p, 20);
    hdr[10] = 0;
    hdr[11] = 0;
    put16(p + 10, sum16(hdr, 20));

    put16(p + 20, 54321);                       /* source port */
    put16(p + 22, 443);                         /* dest port   */
    put32(p + 24, 0x11223344);                  /* sequence    */

    for (i = 0; i < payload; i++)
        p[40 + i] = (uint8_t) i;
    return total;
}

static void test_construction(void)
{
    uint8_t orig[1600], err[128], tmp[128];
    size_t olen, elen;

    printf("\nconstruction\n");

    olen = build_big_tcp(orig, 1460, 1);
    check(olen == 1500, "built a 1500-byte original");
    check(ipv4_dont_fragment(orig, olen) == 1, "DF is set on it");

    elen = icmp_frag_needed(err, sizeof err, GW_ADDR, orig, olen, 1420);
    check(elen > 0, "an ICMP error was produced");
    check(elen == 20 + 8 + 20 + 8,
          "length is IP + ICMP + quoted header + 8 bytes");

    check(ipv4_src(err) == GW_ADDR, "sourced from the gateway");
    check(ipv4_dst(err) == CLIENT, "addressed back to the sender");
    check(err[9] == 1, "protocol is ICMP");

    check(err[20] == ICMP_TYPE_DEST_UNREACH && err[21] == ICMP_CODE_FRAG_NEEDED,
          "type 3 code 4, fragmentation needed");
    check(get16(err + 26) == 1420,
          "next-hop MTU is where RFC 1191 says to look");
    check(get16(err + 24) == 0, "the preceding two bytes are left unused");

    /* Checksums, recomputed independently. */
    memcpy(tmp, err, 20);
    tmp[10] = 0;
    tmp[11] = 0;
    check(get16(err + 10) == sum16(tmp, 20), "IP header checksum is correct");

    memcpy(tmp, err + 20, elen - 20);
    tmp[2] = 0;
    tmp[3] = 0;
    check(get16(err + 22) == sum16(tmp, elen - 20),
          "ICMP checksum is correct");
}

static void test_quoted_original(void)
{
    uint8_t orig[1600], err[128];
    size_t olen, elen;

    printf("\nquoted original\n");

    olen = build_big_tcp(orig, 1460, 1);
    elen = icmp_frag_needed(err, sizeof err, GW_ADDR, orig, olen, 1420);

    check(memcmp(err + 28, orig, 20) == 0,
          "the original IP header is quoted verbatim");
    check(get16(err + 28 + 20) == 54321 && get16(err + 28 + 22) == 443,
          "and the first 8 bytes, so both ports are visible");
    check(get16(err + 28 + 4) == 0xBEEF,
          "including the identification field");
    (void) elen;
}

static void test_rejections(void)
{
    uint8_t orig[1600], err[128];
    size_t olen;

    printf("\nrejections\n");

    olen = build_big_tcp(orig, 1460, 0);
    check(ipv4_dont_fragment(orig, olen) == 0,
          "DF clear is reported as such");

    check(icmp_frag_needed(err, 20, GW_ADDR, orig, olen, 1420) == 0,
          "refuses when the output buffer is too small");
    check(icmp_frag_needed(err, sizeof err, GW_ADDR, orig, 10, 1420) == 0,
          "refuses a truncated original");

    orig[0] = 0x65;   /* version 6 */
    check(icmp_frag_needed(err, sizeof err, GW_ADDR, orig, olen, 1420) == 0,
          "refuses a non-IPv4 original");
}

static void test_short_original(void)
{
    uint8_t orig[64], err[128];
    size_t olen, elen;

    printf("\nshort original\n");

    /* An original with fewer than 8 bytes after its header must not be
       read past the end of. */
    olen = build_big_tcp(orig, 0, 1);
    olen = 24;                    /* pretend only 4 bytes of TCP arrived */
    elen = icmp_frag_needed(err, sizeof err, GW_ADDR, orig, olen, 1420);
    check(elen == 20 + 8 + 24, "quotes only what was actually present");
}

int main(void)
{
    printf("vmsguard ICMP error tests\n");

    test_construction();
    test_quoted_original();
    test_rejections();
    test_short_original();

    printf("\n%s — %d checks, %d failure%s\n",
           failures == 0 ? "PASS" : "FAIL",
           checks, failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
