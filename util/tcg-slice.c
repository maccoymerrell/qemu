/*
 * TCG guest-instruction slice.  The model is in include/qemu/vclock-agency.h
 * (mechanism 1), the interface in include/qemu/tcg-slice.h.
 *
 * Copyright (C) 2026, Maccoy Merrell
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/tcg-slice.h"

bool tcg_slice_armed;
uint16_t tcg_slice_quantum;

static uint64_t slice_seeds;
static uint64_t slice_breakouts;
static uint64_t slice_wp_reloads;
static uint64_t slice_exc_saves;
static uint64_t slice_exc_restores;
static uint64_t slice_nonspec;
static uint64_t slice_overruns;
static uint64_t slice_max;

static void tcg_slice_final(void)
{
    uint64_t mx = qatomic_read(&slice_max);
    uint64_t ov = qatomic_read(&slice_overruns);
    bool sane = (mx <= tcg_slice_quantum) && (ov == 0);

    if (sane) {
        /* healthy runs stay silent -- the tripwire-report pattern */
        return;
    }
    fprintf(stderr,
            "[CSTBQ] tripwire quantum=%u seeds=%" PRIu64 " breakouts=%" PRIu64
            " max_slice=%" PRIu64 " overruns=%" PRIu64 " wp_reloads=%" PRIu64
            " exc_saves=%" PRIu64 " exc_restores=%" PRIu64
            " nonspec_dispatch=%" PRIu64 " sane=%s\n",
            tcg_slice_quantum, qatomic_read(&slice_seeds),
            qatomic_read(&slice_breakouts), mx, ov,
            qatomic_read(&slice_wp_reloads), qatomic_read(&slice_exc_saves),
            qatomic_read(&slice_exc_restores), qatomic_read(&slice_nonspec),
            sane ? "yes" : "NO");
    fflush(stderr);
}

/* Runs before main(); getenv is safe there and the gates in translator.c /
 * cpu-exec.c never observe a half-parsed value. */
static void __attribute__((constructor)) tcg_slice_parse(void)
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
    tcg_slice_quantum = (uint16_t)v;
    tcg_slice_armed = true;
    atexit(tcg_slice_final);
    fprintf(stderr,
            "[CSTBQ] quantum override armed: %u guest insns per slice"
            " (event-agency delivery bound; default 65535)\n",
            tcg_slice_quantum);
    fflush(stderr);
}

/*
 * Runs at plugin install, before any vCPU thread exists (the loader
 * precedes machine start), so the plain stores need no ordering against
 * translation or the exec loop.  The env override, if armed, already
 * parsed in the constructor and wins: this only fills the default.
 */
void tcg_slice_arm(void)
{
    if (tcg_slice_armed) {
        /* the env override already armed (and already bannered itself);
         * its quantum wins */
        return;
    }
    tcg_slice_quantum = 65535;
    tcg_slice_armed = true;
    atexit(tcg_slice_final);
}

void tcg_slice_note_seed(void)
{
    qatomic_inc(&slice_seeds);
}

void tcg_slice_note_breakout(uint16_t remaining)
{
    if (remaining > tcg_slice_quantum) {
        /* u16.low above the quantum: some path raised the budget without
         * billing rights (wrap, or an unmirrored writer).  The invariant
         * broke; say so rather than folding it into max_slice. */
        qatomic_inc(&slice_overruns);
    } else {
        uint64_t consumed = (uint64_t)tcg_slice_quantum - remaining;
        uint64_t mx = qatomic_read(&slice_max);

        while (consumed > mx) {
            uint64_t seen = qatomic_cmpxchg(&slice_max, mx, consumed);
            if (seen == mx) {
                break;
            }
            mx = seen;
        }
    }
    qatomic_inc(&slice_breakouts);
}

void tcg_slice_note_wp_reload(void)
{
    qatomic_inc(&slice_wp_reloads);
}

void tcg_slice_note_exc_save(void)
{
    qatomic_inc(&slice_exc_saves);
}

void tcg_slice_note_exc_restore(void)
{
    qatomic_inc(&slice_exc_restores);
}

void tcg_slice_note_nonspec_dispatch(void)
{
    qatomic_inc(&slice_nonspec);
}
