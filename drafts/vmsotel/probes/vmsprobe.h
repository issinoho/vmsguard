/*
 * vmsotel probes: shared helpers for the system-service probes.
 *
 * Every probe here asks one question about one system service and
 * prints enough that the answer can be read from a pasted transcript
 * without a second round trip: which items the headers declare, which
 * ones the service accepts, what came back, and how big it was.
 *
 * Items are queried one at a time. A single bad item code fails a
 * whole item list with SS$_BADPARAM, which would hide every good item
 * behind the one bad one.
 *
 * C99. The helpers live in vmsprobe.c, linked into every probe.
 */

#ifndef VMSPROBE_H
#define VMSPROBE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <descrip.h>
#include <efndef.h>
#include <ssdef.h>
#include <starlet.h>

/*
 * Item list entry, item_list_3 layout: word length, word code, then a
 * 32-bit buffer address and a 32-bit return-length address.
 *
 * Declared here rather than taken from <iledef.h> so the probes rest on
 * one fewer header whose spelling is unconfirmed on these machines. The
 * layout is only right with 32-bit pointers, which is VSI C's default
 * and what build_probes.com asks for; probe_check_ile() refuses to run
 * otherwise, because a wrong layout is not a compile error, it is a
 * service writing through a garbage address.
 */
typedef struct {
    unsigned short len;
    unsigned short code;
    void *buf;
    unsigned short *retlen;
} probe_ile3;

/* How a returned buffer is printed. */
#define PK_LONG 1   /* unsigned, up to 64 bits, little-endian */
#define PK_TEXT 2   /* fixed-length text, trimmed at retlen */
#define PK_TIME 3   /* VMS quadword time, 100 ns since 17-NOV-1858 */

/* An item the headers do not declare. Codes are never negative. */
#define PROBE_UNDECLARED (-1)

typedef struct {
    const char *name;
    int code;
    unsigned short size;
    int kind;
} probe_item;

/*
 * Offset between the VMS and Unix epochs in 100 ns units:
 * 40587 days (the Modified Julian Day of 1970-01-01) x 86400 s x 10^7.
 */
#define PROBE_VMS_TO_UNIX 35067168000000000ULL

extern int probe_failures;

void probe_ok(const char *what);
void probe_fail(const char *what);
const char *probe_msg(unsigned int status);
unsigned long long probe_le(const unsigned char *b, unsigned n);
void probe_print_value(const probe_item *it, const unsigned char *buf,
                       unsigned short retlen);
int probe_check_ile(void);
void probe_banner(const char *name);
int probe_summary(void);

/*
 * Declare an item table entry. Each must be spelled out under its own
 * #ifdef by the caller -- the preprocessor cannot test inside a macro
 * -- so this only saves the typing of the entry itself.
 */
#define PROBE_ITEM(nm, sz, kd)      { #nm, nm, sz, kd }
#define PROBE_MISSING(nm, sz, kd)   { #nm, PROBE_UNDECLARED, sz, kd }

#endif
