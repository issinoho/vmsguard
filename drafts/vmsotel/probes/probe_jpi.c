/*
 * vmsotel probe: per-process metrics through a $GETJPI wildcard scan
 *
 * Answers:
 *   1. Which JPI$_ items exist and are accepted.
 *   2. How many processes an unprivileged scan sees, compared with
 *      SHOW SYSTEM. Without WORLD a wildcard $GETJPI returns only the
 *      caller's group; the agent's privilege requirement follows from
 *      that number.
 *   3. What a full scan costs, since the agent repeats it every
 *      interval.
 *   4. The unit of JPI$_PPGCNT and JPI$_GPGCNT: pages or pagelets.
 *      The probe prints its top processes by memory with their PIDs;
 *      compare the "pages" column against Ph.Mem in SHOW SYSTEM, which
 *      is in pagelets. Equal means pagelets.
 *
 * Processes that disappear or are suspended mid-scan are expected and
 * counted, not treated as failures.
 */

#include "vmsprobe.h"

#include <jpidef.h>

#include "items_jpi.h"

#define MAX_PROCS 4096
#define TOP_N 8

typedef struct {
    unsigned int pid;
    char name[16];
    char user[13];
    unsigned long long cputim, pages, state;
} proc_row;

static proc_row rows[MAX_PROCS];
static size_t nrows = 0;

/* Item support, decided on the caller's own process. */
static int item_ok[JPI_ITEMS_COUNT];

static int find_item(const char *name)
{
    size_t i;

    for (i = 0; i < JPI_ITEMS_COUNT; i++)
        if (strcmp(jpi_items[i].name, name) == 0)
            return item_ok[i] ? (int) i : -1;
    return -1;
}

static void check_items(void)
{
    size_t i;

    printf("\n$GETJPIW on this process, one item at a time\n");
    for (i = 0; i < JPI_ITEMS_COUNT; i++) {
        const probe_item *it = &jpi_items[i];
        unsigned char buf[256];
        unsigned short retlen = 0;
        unsigned short iosb[4] = { 0, 0, 0, 0 };
        probe_ile3 ile[2];
        unsigned int st;

        if (it->code == PROBE_UNDECLARED) {
            printf("  --    %-16s not declared in <jpidef.h>\n", it->name);
            continue;
        }
        memset(buf, 0, sizeof buf);
        memset(ile, 0, sizeof ile);
        ile[0].len = it->size;
        ile[0].code = (unsigned short) it->code;
        ile[0].buf = buf;
        ile[0].retlen = &retlen;

        st = sys$getjpiw(EFN$C_ENF, 0, 0, (void *) ile, (void *) iosb, 0, 0);
        if ((st & 1) && !(iosb[0] & 1))
            st = iosb[0];
        if (!(st & 1)) {
            printf("  no    %-16s %s\n", it->name, probe_msg(st));
            continue;
        }
        item_ok[i] = 1;
        printf("  ok    %-16s ", it->name);
        probe_print_value(it, buf, retlen);
        printf("\n");
    }
}

static void copy_text(char *dst, size_t cap, const unsigned char *src,
                      unsigned short len)
{
    size_t n = len < cap - 1 ? len : cap - 1;

    memcpy(dst, src, n);
    while (n > 0 && dst[n - 1] == ' ')
        n--;
    dst[n] = '\0';
}

static void scan(void)
{
    /* Slots: one per item the scan wants, each with its own buffer. */
    static const char *const wanted[] = {
        "JPI$_PID", "JPI$_PRCNAM", "JPI$_USERNAME", "JPI$_CPUTIM",
        "JPI$_PPGCNT", "JPI$_GPGCNT", "JPI$_STATE"
    };
    enum { NW = sizeof wanted / sizeof wanted[0] };
    unsigned char bufs[NW][64];
    unsigned short lens[NW];
    probe_ile3 ile[NW + 1];
    int slot_of[NW];
    unsigned int pid = 0xFFFFFFFFu;   /* -1: start a wildcard scan */
    unsigned long long t0 = 0, t1 = 0;
    unsigned long seen = 0, nopriv = 0, suspended = 0, gone = 0, other = 0;
    size_t i, n = 0;

    for (i = 0; i < NW; i++) {
        int k = find_item(wanted[i]);

        slot_of[i] = -1;
        if (k < 0)
            continue;
        ile[n].len = jpi_items[k].size;
        ile[n].code = (unsigned short) jpi_items[k].code;
        ile[n].buf = bufs[i];
        ile[n].retlen = &lens[i];
        slot_of[i] = (int) n++;
    }
    memset(&ile[n], 0, sizeof ile[n]);

    if (slot_of[0] < 0) {
        probe_fail("JPI$_PID unavailable; cannot scan");
        return;
    }

    printf("\nwildcard scan\n");
    sys$gettim((void *) &t0);
    for (;;) {
        unsigned short iosb[4] = { 0, 0, 0, 0 };
        unsigned int st;

        memset(bufs, 0, sizeof bufs);
        memset(lens, 0, sizeof lens);
        st = sys$getjpiw(EFN$C_ENF, &pid, 0, (void *) ile, (void *) iosb, 0, 0);
        if ((st & 1) && !(iosb[0] & 1))
            st = iosb[0];
        if (st == SS$_NOMOREPROC)
            break;
        if (st == SS$_NOPRIV) { nopriv++; continue; }
        if (st == SS$_SUSPENDED) { suspended++; continue; }
        if (st == SS$_NONEXPR) { gone++; continue; }
        if (!(st & 1)) {
            other++;
            printf("  scan error %s\n", probe_msg(st));
            if (other > 20) {
                probe_fail("too many scan errors; stopping");
                break;
            }
            continue;
        }
        seen++;
        if (nrows < MAX_PROCS) {
            proc_row *r = &rows[nrows++];

            memset(r, 0, sizeof *r);
            r->pid = (unsigned int) probe_le(bufs[0], 4);
            if (slot_of[1] >= 0) copy_text(r->name, sizeof r->name, bufs[1], lens[1]);
            if (slot_of[2] >= 0) copy_text(r->user, sizeof r->user, bufs[2], lens[2]);
            if (slot_of[3] >= 0) r->cputim = probe_le(bufs[3], 4);
            if (slot_of[4] >= 0) r->pages += probe_le(bufs[4], 4);
            if (slot_of[5] >= 0) r->pages += probe_le(bufs[5], 4);
            if (slot_of[6] >= 0) r->state = probe_le(bufs[6], 4);
        }
    }
    sys$gettim((void *) &t1);

    printf("  processes returned  %lu\n", seen);
    printf("  NOPRIV              %lu\n", nopriv);
    printf("  SUSPENDED           %lu\n", suspended);
    printf("  gone mid-scan       %lu\n", gone);
    printf("  other errors        %lu\n", other);
    printf("  scan took           %.1f ms\n", (double) (t1 - t0) / 1e4);
    if (seen > 0)
        probe_ok("wildcard $GETJPIW scan completes");
    else
        probe_fail("wildcard scan returned no processes");
}

static void top_by_memory(void)
{
    size_t i, j, shown;

    /* Selection of the top few; nrows is small and this runs once. */
    printf("\ntop %d by JPI$_PPGCNT + JPI$_GPGCNT -- compare with "
           "Ph.Mem in SHOW SYSTEM\n", TOP_N);
    printf("  %-8s %-15s %-12s %10s %12s %6s\n",
           "PID", "name", "user", "pages", "CPU (10ms)", "state");
    for (shown = 0; shown < TOP_N && shown < nrows; shown++) {
        size_t best = shown;
        proc_row tmp;

        for (j = shown + 1; j < nrows; j++)
            if (rows[j].pages > rows[best].pages)
                best = j;
        tmp = rows[shown];
        rows[shown] = rows[best];
        rows[best] = tmp;
    }
    for (i = 0; i < shown; i++)
        printf("  %08X %-15s %-12s %10llu %12llu %6llu\n", rows[i].pid,
               rows[i].name, rows[i].user, rows[i].pages, rows[i].cputim,
               rows[i].state);
}

int main(void)
{
    probe_banner("probe_jpi");
    if (!probe_check_ile())
        return probe_summary();
    check_items();
    scan();
    top_by_memory();
    return probe_summary();
}
