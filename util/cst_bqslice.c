/*
 * Guest-insn slice bounding -- see include/qemu/cst_bqslice.h for the
 * design.  PRODUCT under the event-agency discipline; the env form
 * overrides the documented default quantum.
 *
 * Copyright (C) 2026, Maccoy Merrell
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/cst_bqslice.h"

bool cst_bq_on;
uint16_t cst_bq_quantum;

static uint64_t bq_seeds;
static uint64_t bq_breakouts;
static uint64_t bq_wp_reloads;
static uint64_t bq_exc_saves;
static uint64_t bq_exc_restores;
static uint64_t bq_nonspec;
static uint64_t bq_overruns;
static uint64_t bq_max_slice;

static void cst_bq_final(void)
{
    uint64_t mx = qatomic_read(&bq_max_slice);
    uint64_t ov = qatomic_read(&bq_overruns);
    bool sane = (mx <= cst_bq_quantum) && (ov == 0);

    if (sane) {
        /* healthy runs stay silent -- the tripwire-report pattern */
        return;
    }
    fprintf(stderr,
            "[CSTBQ] tripwire quantum=%u seeds=%" PRIu64 " breakouts=%" PRIu64
            " max_slice=%" PRIu64 " overruns=%" PRIu64 " wp_reloads=%" PRIu64
            " exc_saves=%" PRIu64 " exc_restores=%" PRIu64
            " nonspec_dispatch=%" PRIu64 " sane=%s\n",
            cst_bq_quantum, qatomic_read(&bq_seeds),
            qatomic_read(&bq_breakouts), mx, ov,
            qatomic_read(&bq_wp_reloads), qatomic_read(&bq_exc_saves),
            qatomic_read(&bq_exc_restores), qatomic_read(&bq_nonspec),
            sane ? "yes" : "NO");
    fflush(stderr);
}

/* Runs before main(); getenv is safe there and the gates in translator.c /
 * cpu-exec.c never observe a half-parsed value. */
static void __attribute__((constructor)) cst_bq_parse(void)
{
    const char *env = getenv("CST_BUDGET_QUANTUM");
    char *end = NULL;
    long v;

    if (!env || !env[0]) {
        return;
    }
    v = strtol(env, &end, 10);
    if (!end || *end || v < 512 || v > 65535) {
        fprintf(stderr,
                "[CSTBQ] FATAL: CST_BUDGET_QUANTUM='%s' invalid (want an"
                " integer in [512, 65535]; 512=TCG_MAX_INSNS floor,"
                " 65535=icount's own u16 cadence cap); refusing to run a"
                " configuration different from its label\n", env);
        abort();
    }
    cst_bq_quantum = (uint16_t)v;
    cst_bq_on = true;
    atexit(cst_bq_final);
    fprintf(stderr,
            "[CSTBQ] quantum override armed: %u guest insns per slice"
            " (event-agency delivery bound; default 65535)\n",
            cst_bq_quantum);
    fflush(stderr);
}

/*
 * Product arming edge -- see the header.  Runs at plugin install,
 * before any vCPU thread exists (the loader precedes machine start),
 * so the plain stores need no ordering against translation or the
 * exec loop.  The env override, if armed, already parsed in the
 * constructor and wins: the product edge only fills the default.
 */
void cst_bq_product_arm(void)
{
    if (cst_bq_on) {
        /* the env override already armed (and already bannered itself);
         * its quantum wins */
        return;
    }
    cst_bq_quantum = 65535;
    cst_bq_on = true;
    atexit(cst_bq_final);
}

void cst_bq_note_seed(void)
{
    qatomic_inc(&bq_seeds);
}

void cst_bq_note_breakout(uint16_t remaining)
{
    if (remaining > cst_bq_quantum) {
        /* u16.low above the quantum: some path raised the budget without
         * billing rights (wrap, or an unmirrored writer).  The invariant
         * broke; say so rather than folding it into max_slice. */
        qatomic_inc(&bq_overruns);
    } else {
        uint64_t consumed = (uint64_t)cst_bq_quantum - remaining;
        uint64_t mx = qatomic_read(&bq_max_slice);

        while (consumed > mx) {
            uint64_t seen = qatomic_cmpxchg(&bq_max_slice, mx, consumed);
            if (seen == mx) {
                break;
            }
            mx = seen;
        }
    }
    qatomic_inc(&bq_breakouts);
}

void cst_bq_note_wp_reload(void)
{
    qatomic_inc(&bq_wp_reloads);
}

void cst_bq_note_exc_save(void)
{
    qatomic_inc(&bq_exc_saves);
}

void cst_bq_note_exc_restore(void)
{
    qatomic_inc(&bq_exc_restores);
}

void cst_bq_note_nonspec_dispatch(void)
{
    qatomic_inc(&bq_nonspec);
}
