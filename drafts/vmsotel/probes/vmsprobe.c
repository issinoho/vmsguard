/*
 * vmsotel probes: helpers shared by the system-service probes.
 * See vmsprobe.h.
 */

#include "vmsprobe.h"

int probe_failures = 0;

void probe_ok(const char *what)
{
    printf("  ok    %s\n", what);
}

void probe_fail(const char *what)
{
    printf("  FAIL  %s\n", what);
    probe_failures++;
}

/* Status code to message text, e.g. "%SYSTEM-F-NOPRIV, ...". */
const char *probe_msg(unsigned int status)
{
    static char text[257];
    unsigned short len = 0;
    struct dsc$descriptor_s d;

    d.dsc$w_length = (unsigned short) (sizeof text - 1);
    d.dsc$b_dtype = DSC$K_DTYPE_T;
    d.dsc$b_class = DSC$K_CLASS_S;
    d.dsc$a_pointer = text;

    if (!(sys$getmsg(status, &len, (void *) &d, 15, 0) & 1)) {
        sprintf(text, "%%X%08X", status);
        return text;
    }
    text[len] = '\0';
    return text;
}

/* Little-endian read of up to 8 bytes; VMS is little-endian on every
   architecture it has run on, but say so rather than cast. */
unsigned long long probe_le(const unsigned char *b, unsigned n)
{
    unsigned long long v = 0;
    unsigned i;

    if (n > 8)
        n = 8;
    for (i = n; i > 0; i--)
        v = (v << 8) | b[i - 1];
    return v;
}

void probe_print_value(const probe_item *it,
                              const unsigned char *buf,
                              unsigned short retlen)
{
    unsigned n = retlen ? retlen : it->size;

    switch (it->kind) {
    case PK_TEXT: {
        char s[256];
        unsigned i;

        if (n > sizeof s - 1)
            n = sizeof s - 1;
        for (i = 0; i < n; i++)
            s[i] = (buf[i] >= 32 && buf[i] < 127) ? (char) buf[i] : '.';
        /* Fixed-length VMS strings are blank-padded. */
        while (n > 0 && s[n - 1] == ' ')
            n--;
        s[n] = '\0';
        printf("\"%s\"", s);
        break;
    }
    case PK_TIME: {
        unsigned long long t = probe_le(buf, 8);

        printf("%llu", t);
        if (t > PROBE_VMS_TO_UNIX) {
            time_t u = (time_t) ((t - PROBE_VMS_TO_UNIX) / 10000000ULL);
            struct tm *tm = gmtime(&u);   /* local wall time, shown raw */

            if (tm != NULL)
                printf(" (%04d-%02d-%02d %02d:%02d:%02d as written)",
                       tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                       tm->tm_hour, tm->tm_min, tm->tm_sec);
        }
        break;
    }
    default:
        printf("%llu", probe_le(buf, n));
        break;
    }
    printf("  [%u bytes]", (unsigned) retlen);
}

int probe_check_ile(void)
{
    printf("item list entry: %u bytes, pointers %u bytes\n",
           (unsigned) sizeof(probe_ile3), (unsigned) sizeof(void *));
#ifdef __VMS
    if (sizeof(probe_ile3) != 12) {
        probe_fail("item list layout is not item_list_3; "
                   "build with /POINTER_SIZE=32 or none");
        return 0;
    }
#endif
    return 1;
}

void probe_banner(const char *name)
{
    printf("vmsotel %s\n", name);
    /* Nothing in vmsguard has printed a long long on VMS yet. If this
       line does not read 12345678901, every 64-bit value below is
       suspect too. */
    printf("printf %%llu check: %llu\n", 12345678901ULL);
#ifdef __VMS
    printf("built with __VMS");
#  ifdef __ia64
    printf(", __ia64");
#  endif
#  ifdef __x86_64
    printf(", __x86_64");
#  endif
#  ifdef __DECC_VER
    printf(", __DECC_VER %d", (int) __DECC_VER);
#  endif
    printf("\n");
#else
    printf("built WITHOUT __VMS: this is the Linux stub, values are fake\n");
#endif
}

int probe_summary(void)
{
    printf("\n%s: %d failure%s\n",
           probe_failures ? "FAILURES" : "PASS",
           probe_failures, probe_failures == 1 ? "" : "s");
    /* The C RTL maps these to a DCL status of the right severity. */
    return probe_failures ? EXIT_FAILURE : EXIT_SUCCESS;
}

