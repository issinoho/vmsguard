/*
 * vmsotel probe: $GETSYI identity items, and the clock
 *
 * Answers:
 *   1. Which $GETSYI items exist on this OS version, and what they
 *      return -- these become the OpenTelemetry resource attributes
 *      (host.name, os.version, host.arch) and the memory limit.
 *   2. Whether the C RTL's time() is UTC. OTLP timestamps are Unix
 *      nanoseconds in UTC, and VMS system time is local. If time() is
 *      off by the timezone differential, every point lands hours away
 *      from where a collector expects it and is silently mis-graphed.
 *   3. Uptime from SYI$_BOOTTIME, which is the start time every
 *      cumulative system counter needs.
 *
 * No privilege needed.
 */

#include "vmsprobe.h"

#include <syidef.h>
#include <stdlib.h>

#include "items_syi.h"

static unsigned long long boottime = 0;

static void query_items(void)
{
    size_t i;

    printf("\n$GETSYIW, one item at a time\n");
    for (i = 0; i < SYI_ITEMS_COUNT; i++) {
        const probe_item *it = &syi_items[i];
        unsigned char buf[256];
        unsigned short retlen = 0;
        unsigned short iosb[4] = { 0, 0, 0, 0 };
        probe_ile3 ile[2];
        unsigned int st;

        if (it->code == PROBE_UNDECLARED) {
            printf("  --    %-22s not declared in <syidef.h>\n", it->name);
            continue;
        }
        memset(buf, 0, sizeof buf);
        memset(ile, 0, sizeof ile);
        ile[0].len = it->size;
        ile[0].code = (unsigned short) it->code;
        ile[0].buf = buf;
        ile[0].retlen = &retlen;

        st = sys$getsyiw(EFN$C_ENF, 0, 0, (void *) ile, (void *) iosb, 0, 0);
        if ((st & 1) && !(iosb[0] & 1))
            st = iosb[0];
        if (!(st & 1)) {
            /* Declared but refused is information, not a probe failure. */
            printf("  no    %-22s %s\n", it->name, probe_msg(st));
            continue;
        }
        printf("  ok    %-22s ", it->name);
        probe_print_value(it, buf, retlen);
        printf("\n");

        if (strcmp(it->name, "SYI$_BOOTTIME") == 0)
            boottime = probe_le(buf, 8);
    }
}

static void show_utc(const char *label, long long unix_seconds)
{
    time_t t = (time_t) unix_seconds;
    struct tm *tm = gmtime(&t);

    if (tm == NULL) {
        printf("  %-34s %lld (gmtime failed)\n", label, unix_seconds);
        return;
    }
    printf("  %-34s %lld  %04d-%02d-%02dT%02d:%02d:%02dZ\n", label,
           unix_seconds, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
           tm->tm_hour, tm->tm_min, tm->tm_sec);
}

static void check_clock(void)
{
    unsigned long long now = 0;
    long long from_time, local_secs, tdf = 0;
    const char *tdf_s = getenv("SYS$TIMEZONE_DIFFERENTIAL");
    const char *tz_name = getenv("SYS$TIMEZONE_NAME");
    const char *tz_rule = getenv("TZ");
    int have_tdf = 0;

    printf("\nClock\n");
    printf("  SYS$TIMEZONE_DIFFERENTIAL  %s\n", tdf_s ? tdf_s : "(undefined)");
    printf("  SYS$TIMEZONE_NAME          %s\n", tz_name ? tz_name : "(undefined)");
    printf("  TZ                         %s\n", tz_rule ? tz_rule : "(undefined)");
    if (tdf_s != NULL) {
        tdf = strtol(tdf_s, NULL, 10);
        have_tdf = 1;
    }

    from_time = (long long) time(NULL);
    if (!(sys$gettim((void *) &now) & 1)) {
        probe_fail("$GETTIM");
        return;
    }
    local_secs = (long long) ((now - PROBE_VMS_TO_UNIX) / 10000000ULL);

    show_utc("time()", from_time);
    show_utc("$GETTIM read as if UTC", local_secs);
    if (have_tdf)
        show_utc("$GETTIM minus differential", local_secs - tdf);

    /*
     * time() should agree with $GETTIM corrected by the differential.
     * If it instead agrees with raw $GETTIM while the differential is
     * nonzero, time() is local, not UTC, and the agent must correct it.
     */
    if (have_tdf) {
        long long d = from_time - (local_secs - tdf);

        if (d < -2 || d > 2) {
            printf("  time() differs from local-minus-differential by %lld s\n", d);
            probe_fail("time() is not UTC as the differential describes it");
        } else {
            probe_ok("time() is UTC, consistent with SYS$TIMEZONE_DIFFERENTIAL");
        }
    } else {
        printf("  no differential to check against; compare time() with "
               "`date -u` on the laptop\n");
    }

    if (boottime != 0 && now > boottime) {
        unsigned long long up = (now - boottime) / 10000000ULL;

        printf("  uptime                             %llu s (%llu d %02llu:%02llu)\n",
               up, up / 86400, (up % 86400) / 3600, (up % 3600) / 60);
        if (have_tdf)
            show_utc("boot time, UTC",
                     (long long) ((boottime - PROBE_VMS_TO_UNIX) / 10000000ULL) - tdf);
        probe_ok("uptime from SYI$_BOOTTIME");
    }
}

int main(void)
{
    probe_banner("probe_syi");
    if (!probe_check_ile())
        return probe_summary();
    query_items();
    check_clock();
    return probe_summary();
}
