/*
 * [cstwit] — target-side address-space witness for MIPS system mode.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Author: Maccoy Merrell
 *
 * THIS FILE IS DELIBERATELY SELF-CONTAINED.  It exists to witness, from
 * outside the tracer, that an experiment's condition actually occurred --
 * and an experiment that compares two ownership rules can only be believed
 * if its witness is provably the same code in both arms.  Keeping every
 * witness function in one file that neither arm's diff touches makes that
 * checkable with a single sha256, which is exactly what the harness does
 * before it will run a wave.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "internal.h"

/*
 * [cstwit] — the target-side address-space witness.
 *
 * WHY THIS IS TARGET CODE AND NOT A PLUGIN COUNTER.  An experiment that
 * compares two ownership rules needs a witness that the condition it claims
 * to have created actually occurred, and that witness cannot come from
 * either rule's own bookkeeping: a plugin-side counter is not arm-invariant,
 * and one of the arms legitimately does not have the mechanism the other
 * counts.  Worse, the counters previously quoted for this purpose are
 * useless in the exact regime they were quoted in — "distinct raw ASID names
 * committed since the pin" runs off a 1024-bit set (ASID_SWEEP_BITS), but
 * this guest's EntryHi.ASID field is 8 bits, so once the kernel has reissued
 * all 256 names the reading is pinned at 256 on every cell and carries no
 * information about whether the PINNED mm was renumbered.
 *
 * So the witness is here, in the target, where it is byte-identical
 * whichever ownership rule the plugin was built with, and it records the
 * physical event rather than a census:
 *
 *   bind   at ERET-to-user, the (asid, pwbase) pair that describes the mm
 *          about to run.  Both registers are settled at that instant, so
 *          there is no write-ordering ambiguity between the two halves of a
 *          switch_mm.  De-duplicated per CPU on the pair.
 *   asidw  at the committed EntryHi.ASID change.
 *   pwbw   at the committed CP0_PWBase change.
 *   mark   at syscall entry, when the guest issues close(-MAGIC).  This is
 *          how the workload timestamps its own phases onto the same clock.
 *
 * cpu_mips_get_count() is the shared guest-architectural clock; the monotone
 * seq lets the offline reader unwrap its 32-bit rollover.  PWBase is
 * normalised kseg0/kseg1 -> physical so the number printed here is the same
 * number an ownership rule keyed on the page-table root would compare.
 *
 * Gated on CST_ASIDWITNESS being set, so a build carrying it behaves exactly
 * as before when the variable is absent.
 */
#define CST_WIT_MAXCPU 16

static FILE *cst_wit_file(void)
{
    static FILE *f;
    static bool tried;

    if (!tried) {
        const char *p = getenv("CST_ASIDWITNESS");
        tried = true;
        if (p && *p) {
            f = fopen(p, "w");
            if (f) {
                setvbuf(f, NULL, _IOLBF, 0);
            }
        }
    }
    return f;
}

static uint64_t cst_wit_seq;

/* kseg0/kseg1 -> physical, so both arms compare the same number. */
static uint64_t cst_wit_norm(uint64_t v)
{
    if ((v & 0xE0000000ull) == 0x80000000ull ||
        (v & 0xE0000000ull) == 0xA0000000ull) {
        return v & 0x1FFFFFFFull;
    }
    return v;
}

static void cst_wit_line(CPUMIPSState *env, const char *kind, const char *tail)
{
    FILE *f = cst_wit_file();

    if (!f) {
        return;
    }
    fprintf(f, "[cstwit] %-5s seq=%" PRIu64 " cpu=%d count=%u %s\n",
            kind, cst_wit_seq++, env_cpu(env)->cpu_index,
            cpu_mips_get_count(env), tail);
}

/* ERET back to user mode: the (asid, pwbase) binding of the mm about to run.
 * De-duplicated on the pair, so a busy guest writes one line per real
 * address-space change and not one per exception. */
void cst_wit_bind(CPUMIPSState *env)
{
    static uint64_t last_asid[CST_WIT_MAXCPU];
    static uint64_t last_pw[CST_WIT_MAXCPU];
    static bool seen[CST_WIT_MAXCPU];
    unsigned idx = env_cpu(env)->cpu_index;
    uint64_t asid, pw;
    char tail[96];

    if (!cst_wit_file() || idx >= CST_WIT_MAXCPU) {
        return;
    }
    if (!(env->hflags & MIPS_HFLAG_UM)) {
        return;                 /* not returning to user */
    }
    asid = env->CP0_EntryHi & env->CP0_EntryHi_ASID_mask;
    pw = cst_wit_norm(env->CP0_PWBase);
    if (seen[idx] && last_asid[idx] == asid && last_pw[idx] == pw) {
        return;
    }
    seen[idx] = true;
    last_asid[idx] = asid;
    last_pw[idx] = pw;
    snprintf(tail, sizeof(tail), "asid=0x%02" PRIx64 " pwbase=0x%08" PRIx64,
             asid, pw);
    cst_wit_line(env, "bind", tail);
}

void cst_wit_asidw(CPUMIPSState *env, uint64_t old, uint64_t nw)
{
    char tail[128];

    if (!cst_wit_file()) {
        return;
    }
    snprintf(tail, sizeof(tail),
             "old=0x%02" PRIx64 " new=0x%02" PRIx64 " pwbase=0x%08" PRIx64,
             old, nw, cst_wit_norm(env->CP0_PWBase));
    cst_wit_line(env, "asidw", tail);
}

void cst_wit_pwbw(CPUMIPSState *env, uint64_t old, uint64_t nw)
{
    char tail[128];

    if (!cst_wit_file()) {
        return;
    }
    snprintf(tail, sizeof(tail),
             "old=0x%08" PRIx64 " new=0x%08" PRIx64 " asid=0x%02" PRIx64,
             cst_wit_norm(old), cst_wit_norm(nw),
             (uint64_t)(env->CP0_EntryHi & env->CP0_EntryHi_ASID_mask));
    cst_wit_line(env, "pwbw", tail);
}

/* Syscall entry.  The workload timestamps its own phases by issuing
 * close(-MAGIC), which is a no-op returning EBADF and therefore cannot
 * perturb anything it is measuring. */
void cst_wit_syscall(CPUMIPSState *env)
{
    static const struct { int32_t magic; const char *tag; } tags[] = {
        { -0xC57A, "start" }, { -0xC57B, "sweep0" }, { -0xC57C, "churn" },
        { -0xC57D, "sweep1" }, { -0xC57E, "end" },
    };
    int32_t a0;
    char tail[128];
    unsigned i;

    if (!cst_wit_file()) {
        return;
    }
    if ((uint32_t)env->active_tc.gpr[2] != 4006u) {       /* o32 __NR_close */
        return;
    }
    a0 = (int32_t)env->active_tc.gpr[4];
    for (i = 0; i < ARRAY_SIZE(tags); i++) {
        if (tags[i].magic != a0) {
            continue;
        }
        snprintf(tail, sizeof(tail),
                 "tag=%s asid=0x%02" PRIx64 " pwbase=0x%08" PRIx64
                 " epc=0x%08" PRIx64,
                 tags[i].tag,
                 (uint64_t)(env->CP0_EntryHi & env->CP0_EntryHi_ASID_mask),
                 cst_wit_norm(env->CP0_PWBase),
                 (uint64_t)env->active_tc.PC);
        cst_wit_line(env, "mark", tail);
        return;
    }
}

