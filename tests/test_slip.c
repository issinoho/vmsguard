/*
 * SLIP framing tests — vmsguard
 *
 * The framing is testable on any platform; only the pseudo-terminal
 * plumbing around it is OpenVMS-specific. Worth having solid before
 * that spike, so that a failure there is unambiguously about PTD$ and
 * SLIP attachment rather than about the framing.
 */

#include <stdio.h>
#include <string.h>

#include "slip.h"

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

/* Feed a whole buffer to the decoder, collecting the first packet. */
static int decode_all(struct slip_decoder *d, const uint8_t *in, size_t inlen,
                      uint8_t *out, size_t *outlen)
{
    size_t i;

    for (i = 0; i < inlen; i++) {
        if (slip_decode_byte(d, in[i])) {
            memcpy(out, d->buf, d->len);
            *outlen = d->len;
            return 1;
        }
    }
    return 0;
}

static void test_roundtrip(void)
{
    struct slip_decoder d;
    uint8_t pkt[64], enc[256], dec[SLIP_MTU];
    size_t enclen, declen = 0;
    size_t i;

    printf("\nround trip\n");

    for (i = 0; i < sizeof pkt; i++)
        pkt[i] = (uint8_t) i;

    enclen = slip_encode(enc, sizeof enc, pkt, sizeof pkt);
    check(enclen == sizeof pkt + 2,
          "plain payload encodes to length + 2 framing bytes");
    check(enc[0] == SLIP_END && enc[enclen - 1] == SLIP_END,
          "frame begins and ends with END");

    slip_decoder_init(&d);
    check(decode_all(&d, enc, enclen, dec, &declen) == 1 &&
          declen == sizeof pkt && memcmp(dec, pkt, sizeof pkt) == 0,
          "decodes back to the original payload");
}

static void test_escaping(void)
{
    struct slip_decoder d;
    uint8_t pkt[4];
    uint8_t enc[64], dec[SLIP_MTU];
    size_t enclen, declen = 0;

    printf("\nescaping\n");

    /* Every byte that needs escaping, plus two that do not. */
    pkt[0] = SLIP_END;
    pkt[1] = 0x41;
    pkt[2] = SLIP_ESC;
    pkt[3] = 0x42;

    enclen = slip_encode(enc, sizeof enc, pkt, sizeof pkt);
    check(enclen == 2 + 2 + 1 + 2 + 1,
          "END and ESC each expand to two bytes");
    check(enc[1] == SLIP_ESC && enc[2] == SLIP_ESC_END,
          "END encodes as ESC ESC_END");
    check(enc[4] == SLIP_ESC && enc[5] == SLIP_ESC_ESC,
          "ESC encodes as ESC ESC_ESC");

    slip_decoder_init(&d);
    check(decode_all(&d, enc, enclen, dec, &declen) == 1 &&
          declen == sizeof pkt && memcmp(dec, pkt, sizeof pkt) == 0,
          "escaped payload round-trips");

    /* A payload that is nothing but escapable bytes doubles in size. */
    {
        uint8_t all_end[32], big[128];
        size_t n;

        memset(all_end, SLIP_END, sizeof all_end);
        n = slip_encode(big, sizeof big, all_end, sizeof all_end);
        check(n == 2 * sizeof all_end + 2,
              "worst-case payload doubles, as the buffer sizing assumes");
    }
}

static void test_streaming(void)
{
    struct slip_decoder d;
    uint8_t pkt[100], enc[256], dec[SLIP_MTU];
    size_t enclen, declen = 0;
    size_t i, got = 0;

    printf("\nstreaming\n");

    for (i = 0; i < sizeof pkt; i++)
        pkt[i] = (uint8_t) (i * 7);
    /* Force escapes to straddle whatever chunk boundary we pick. */
    pkt[9] = SLIP_ESC;
    pkt[10] = SLIP_END;

    enclen = slip_encode(enc, sizeof enc, pkt, sizeof pkt);

    /* One byte at a time is the pathological case: every escape
       sequence is split across two calls. */
    slip_decoder_init(&d);
    for (i = 0; i < enclen; i++) {
        if (slip_decode_byte(&d, enc[i])) {
            memcpy(dec, d.buf, d.len);
            declen = d.len;
            got++;
        }
    }
    check(got == 1 && declen == sizeof pkt &&
          memcmp(dec, pkt, sizeof pkt) == 0,
          "decodes correctly fed one byte at a time");

    /* Two datagrams back to back, sharing framing bytes. */
    {
        uint8_t two[512];
        size_t n1, n2, total;

        n1 = slip_encode(two, sizeof two, pkt, 10);
        n2 = slip_encode(two + n1, sizeof two - n1, pkt, 20);
        total = n1 + n2;

        got = 0;
        slip_decoder_init(&d);
        for (i = 0; i < total; i++) {
            if (slip_decode_byte(&d, two[i]))
                got++;
        }
        check(got == 2, "two back-to-back datagrams both decode");
    }
}

static void test_robustness(void)
{
    struct slip_decoder d;
    uint8_t dec[SLIP_MTU];
    uint8_t buf[8];
    size_t declen = 0;
    size_t i;
    int got;

    printf("\nrobustness\n");

    /* Leading noise: a run of ENDs should produce no packets. */
    slip_decoder_init(&d);
    got = 0;
    for (i = 0; i < 8; i++) {
        if (slip_decode_byte(&d, SLIP_END))
            got++;
    }
    check(got == 0, "a run of ENDs yields no empty packets");

    /* A real packet after the noise still decodes. */
    buf[0] = 0x45;
    buf[1] = 0x00;
    if (slip_decode_byte(&d, buf[0]) || slip_decode_byte(&d, buf[1]))
        check(0, "unexpected early packet");
    check(slip_decode_byte(&d, SLIP_END) == 1 && d.len == 2,
          "a packet following leading ENDs decodes");

    /* Oversized frames are dropped whole, not truncated. */
    slip_decoder_init(&d);
    got = 0;
    for (i = 0; i < SLIP_MTU + 50; i++) {
        if (slip_decode_byte(&d, 0x5A))
            got++;
    }
    if (slip_decode_byte(&d, SLIP_END))
        got++;
    check(got == 0, "a frame larger than the MTU is dropped, not truncated");

    /* The decoder recovers: the next frame is fine. */
    slip_decode_byte(&d, 0x11);
    slip_decode_byte(&d, 0x22);
    check(slip_decode_byte(&d, SLIP_END) == 1 && d.len == 2,
          "decoder recovers after an oversized frame");

    /* Encoding refuses to overflow rather than writing a partial frame. */
    {
        uint8_t small[4];
        uint8_t src[8];
        memset(src, 0, sizeof src);
        check(slip_encode(small, sizeof small, src, sizeof src) == 0,
              "encode refuses when the output buffer is too small");
    }

    (void) dec;
    (void) declen;
}

int main(void)
{
    printf("vmsguard SLIP framing tests\n");

    test_roundtrip();
    test_escaping();
    test_streaming();
    test_robustness();

    printf("\n%s — %d checks, %d failure%s\n",
           failures == 0 ? "PASS" : "FAIL",
           checks, failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
