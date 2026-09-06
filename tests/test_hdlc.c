/*
 * PPP HDLC framing tests — vmsguard
 *
 * The FCS is the part worth testing hardest: a wrong CRC produces a
 * link that looks alive and silently discards every frame, which is a
 * miserable thing to debug over a pseudoterminal on another machine.
 */

#include <stdio.h>
#include <string.h>

#include "hdlc.h"

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

static void test_fcs(void)
{
    static const uint8_t abc[3] = { 'a', 'b', 'c' };
    uint16_t fcs;

    printf("\nFCS-16\n");

    /* The empty message: the initial value, complemented. */
    fcs = hdlc_fcs(0xFFFF, NULL, 0) ^ 0xFFFF;
    check(fcs == 0x0000, "FCS of no data is 0x0000");

    /* Cross-checked against an independent bitwise implementation of
       CRC-16/X-25: init 0xFFFF, reversed polynomial 0x8408, final
       complement. This table-driven version and that one agree. */
    fcs = hdlc_fcs(0xFFFF, abc, sizeof abc) ^ 0xFFFF;
    check(fcs == 0x9E25, "FCS(\"abc\") matches CRC-16/X-25");

    /* A whole LCP configure-request body, likewise cross-checked. */
    {
        static const uint8_t lcp[8] = {
            0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04
        };
        fcs = hdlc_fcs(0xFFFF, lcp, sizeof lcp) ^ 0xFFFF;
        check(fcs == 0xB5D1, "FCS of an LCP configure-request body");
    }
}

static void test_roundtrip(void)
{
    struct hdlc_decoder d;
    uint8_t payload[64], frame[512];
    size_t framelen;
    size_t i;
    int got = 0;

    printf("\nround trip\n");

    for (i = 0; i < sizeof payload; i++)
        payload[i] = (uint8_t) (i * 3);

    framelen = hdlc_encode(frame, sizeof frame, PPP_PROTO_IP,
                           payload, sizeof payload);
    check(framelen > 0, "encodes a frame");
    check(frame[0] == HDLC_FLAG && frame[framelen - 1] == HDLC_FLAG,
          "frame is flag-delimited");
    check(frame[1] == HDLC_ADDRESS && frame[2] == HDLC_CONTROL,
          "address and control are FF 03");
    check(frame[3] == 0x00 && frame[4] == 0x21,
          "protocol field is 0x0021 for IP");

    hdlc_decoder_init(&d);
    for (i = 0; i < framelen; i++) {
        if (hdlc_decode_byte(&d, frame[i]))
            got++;
    }
    check(got == 1, "exactly one frame decodes");
    check(d.protocol == PPP_PROTO_IP, "protocol survives the round trip");
    check(d.payload_len == sizeof payload &&
          memcmp(d.buf + d.payload_off, payload, sizeof payload) == 0,
          "payload survives the round trip");
}

static void test_escaping(void)
{
    struct hdlc_decoder d;
    uint8_t payload[4];
    uint8_t frame[128];
    size_t framelen, i;
    int got = 0;

    printf("\nescaping\n");

    payload[0] = HDLC_FLAG;   /* 0x7E must be escaped */
    payload[1] = 0x41;
    payload[2] = HDLC_ESC;    /* 0x7D must be escaped */
    payload[3] = 0x42;

    framelen = hdlc_encode(frame, sizeof frame, PPP_PROTO_LCP,
                           payload, sizeof payload);
    check(framelen > 0, "encodes a payload needing escapes");

    /* Only the delimiters may be bare 0x7E. */
    got = 0;
    for (i = 1; i + 1 < framelen; i++) {
        if (frame[i] == HDLC_FLAG)
            got++;
    }
    check(got == 0, "no bare flag bytes inside the frame");

    hdlc_decoder_init(&d);
    got = 0;
    for (i = 0; i < framelen; i++) {
        if (hdlc_decode_byte(&d, frame[i]))
            got++;
    }
    check(got == 1 && d.payload_len == sizeof payload &&
          memcmp(d.buf + d.payload_off, payload, sizeof payload) == 0,
          "escaped payload round-trips");
}

static void test_corruption(void)
{
    struct hdlc_decoder d;
    uint8_t payload[16], frame[128];
    size_t framelen, i;
    int got;

    printf("\ncorruption\n");

    memset(payload, 0x5A, sizeof payload);
    framelen = hdlc_encode(frame, sizeof frame, PPP_PROTO_IP,
                           payload, sizeof payload);

    /* Flip a payload bit: the FCS must reject the frame. */
    frame[8] ^= 0x01;
    hdlc_decoder_init(&d);
    got = 0;
    for (i = 0; i < framelen; i++) {
        if (hdlc_decode_byte(&d, frame[i]))
            got++;
    }
    check(got == 0, "a corrupted frame fails the FCS check");
    frame[8] ^= 0x01;

    /* The decoder recovers and accepts the next good frame. */
    got = 0;
    for (i = 0; i < framelen; i++) {
        if (hdlc_decode_byte(&d, frame[i]))
            got++;
    }
    check(got == 1, "decoder recovers after a bad frame");

    /* Runt frames carrying no room for header and FCS are ignored. */
    hdlc_decoder_init(&d);
    got = 0;
    hdlc_decode_byte(&d, HDLC_FLAG);
    hdlc_decode_byte(&d, 0xFF);
    hdlc_decode_byte(&d, 0x03);
    if (hdlc_decode_byte(&d, HDLC_FLAG))
        got++;
    check(got == 0, "a runt frame is ignored");
}

static void test_streaming(void)
{
    struct hdlc_decoder d;
    uint8_t payload[100], frame[512], two[1024];
    size_t framelen, n1, n2, i;
    int got;

    printf("\nstreaming\n");

    for (i = 0; i < sizeof payload; i++)
        payload[i] = (uint8_t) i;
    payload[7] = HDLC_ESC;
    payload[8] = HDLC_FLAG;

    framelen = hdlc_encode(frame, sizeof frame, PPP_PROTO_IPCP,
                           payload, sizeof payload);

    hdlc_decoder_init(&d);
    got = 0;
    for (i = 0; i < framelen; i++) {
        if (hdlc_decode_byte(&d, frame[i]))
            got++;
    }
    check(got == 1 && d.protocol == PPP_PROTO_IPCP,
          "decodes byte at a time with escapes split across calls");

    /* Two frames back to back. */
    n1 = hdlc_encode(two, sizeof two, PPP_PROTO_LCP, payload, 10);
    n2 = hdlc_encode(two + n1, sizeof two - n1, PPP_PROTO_IP, payload, 20);

    hdlc_decoder_init(&d);
    got = 0;
    for (i = 0; i < n1 + n2; i++) {
        if (hdlc_decode_byte(&d, two[i]))
            got++;
    }
    check(got == 2, "two back-to-back frames both decode");
}

static void test_lcp_shape(void)
{
    uint8_t req[4];
    uint8_t frame[64];
    size_t framelen, i;

    printf("\nLCP configure-request\n");

    /* Code 1 (Configure-Request), identifier 1, length 4, no options. */
    req[0] = 0x01;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x04;

    framelen = hdlc_encode(frame, sizeof frame, PPP_PROTO_LCP,
                           req, sizeof req);
    check(framelen > 0, "encodes an LCP configure-request");
    check(frame[3] == 0xC0 && frame[4] == 0x21,
          "protocol field is 0xC021 for LCP");

    printf("  note  on the wire:");
    for (i = 0; i < framelen; i++)
        printf(" %02x", frame[i]);
    printf("\n");
}

int main(void)
{
    printf("vmsguard HDLC framing tests\n");

    test_fcs();
    test_roundtrip();
    test_escaping();
    test_corruption();
    test_streaming();
    test_lcp_shape();

    printf("\n%s — %d checks, %d failure%s\n",
           failures == 0 ? "PASS" : "FAIL",
           checks, failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
