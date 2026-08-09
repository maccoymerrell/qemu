/*
 * Behavioural oracle -- derive an instruction's architectural write set from
 * QEMU's own emulation.
 *
 * The premise: if QEMU executes a program correctly then it already knows, to
 * the byte, what every instruction does.  Rather than asking a disassembler
 * what an instruction *should* write, we snapshot CPUArchState, let QEMU run
 * the instruction, and diff.  What changed is the write set -- including the
 * effects that never appear in TCG IR because they happen inside a helper.
 *
 * Two choke points carry the whole design:
 *
 *   CP1  tcg_gen_callN() in tcg/tcg.c.  Every helper call on every target is
 *        emitted through that one function, so bracketing it with probes
 *        instruments all 818 ARM / 1179 RISC-V / 356 MIPS / 180 x86 helpers
 *        with no per-helper code.
 *
 *   CP3  the TCG globals table.  Each target registers its architectural
 *        registers as TCG globals carrying a name and an offset into
 *        CPUArchState, so the offset->register map is derived from QEMU's own
 *        tables instead of being hand-authored (and silently drifting).
 *
 * A third call site, in translator_loop(), delimits instructions so a delta
 * can be attributed to the instruction that produced it.
 *
 * Driving it
 * ----------
 * Configure a separate build with --enable-oracle; the option is off by
 * default and every call site is inside #ifdef CONFIG_ORACLE, so a normal
 * build is byte-identical.  At run time:
 *
 *   QEMU_ORACLE=<path>          write the report here; unset means inert
 *   QEMU_ORACLE_PC_LO/_PC_HI    only observe instructions in this pc range
 *   QEMU_ORACLE_MAX=<n>         stop after n records
 *   QEMU_ORACLE_HELPERS=0       skip the per-helper probes
 *   QEMU_ORACLE_INSN_MARKS=0    skip the 'I' lines
 *   QEMU_ORACLE_TB_SLACK=<n>    how far before PC_LO a TB may still be armed
 *   QEMU_ORACLE_POISON=<spec>   spoil state before an instruction; see below
 *   QEMU_ORACLE_POISON_NTH=<n>  only the n'th execution of the target pc
 *   QEMU_ORACLE_POISON_ONCE=1   only the first
 *   QEMU_ORACLE_POISON_SEED=<n> seed for the 'r' mode, so runs repeat
 *
 * The report
 * ----------
 *   T ...                       target, sizeof(CPUArchState), counts
 *   G <off> <size> <name>       one per TCG global: the offset -> register map
 *   S ...                       a global the map could not use, and why
 *   Q poison ...                a poison spec that was accepted
 *   I <pc>                      an instruction is about to execute
 *   W <pc> reg=<name> ...       <pc> changed a named register
 *   W <pc> raw off=<n> ...      <pc> changed bytes no global names
 *   H <pc> helper=<h> ...       the change happened inside helper <h>
 *       ... via=retval          ... but it is the helper's return value,
 *                               which the caller bound to that global
 *   X <pc> helper=<h> NO_WG_VIOLATION ...
 *                               a helper declared not to write globals wrote
 *                               one anyway, and it is not its return value
 *   P <pc> off=... poison=...   state spoiled before <pc>
 *   R <pc> off=... written=0|1  and whether <pc> overwrote it
 *   E lines=<n>                 end of report
 *
 * Cost, and why gating is at translation time
 * -------------------------------------------
 * An armed instruction costs a snapshot of CPUArchState and a diff against the
 * previous one, which is hundreds of nanoseconds however tight the loop is.
 * The only way to make that affordable on a real workload is to not do it, so
 * a TB outside the window is translated with no probes in it at all: the pc
 * window is turned into a TB cflag, CF_ORACLE, at lookup time.  Because the
 * decision is a pure function of the pc, an armed and an unarmed TB for one pc
 * can never both be in the cache.
 *
 * What a differ cannot see
 * ------------------------
 * A write whose value equals what was already there leaves no trace.  That
 * hides the zero written by a successful RISC-V sc.d, the high half of a
 * MIPS mult whose product fits in 32 bits, the flag words an AArch64 fcmp
 * clears that were clear already, and every set of an already-set sticky FP
 * exception flag -- which after the first set is invisible for the rest of the
 * run.
 *
 * QEMU_ORACLE_POISON is the answer: put a value in the destination that the
 * instruction cannot produce, and the write reappears.  What it is not is
 * free.  Spoiling state an instruction *reads* changes what the program
 * computes, and nothing here knows what an instruction reads -- that is read
 * detection, which does not exist yet.  So a poisoned run is a hypothesis, and
 * tests/oracle/check-poison.py is what turns it back into a measurement: it
 * runs the program clean and poisoned and refuses to believe the second unless
 * it behaved like the first everywhere the poison was not aimed.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "cpu.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op-common.h"
#include "tcg/tcg-internal.h"
#include "tcg/helper-info.h"
#include "exec/helper-head.h.inc"
#include "exec/translation-block.h"
#include "exec/target_page.h"
#include "exec/oracle.h"

#define ORACLE_HELPER_DEPTH 8
#define ORACLE_RAW_DUMP_MAX 64

typedef struct OracleGlobal {
    intptr_t off;
    uint32_t size;
    const char *name;
    /* First and last 8-byte word of env this global occupies. */
    uint32_t wlo, whi;
} OracleGlobal;

/* Process-wide, immutable after oracle_init(). */
static bool oracle_on;
static FILE *oracle_out;
static QemuMutex oracle_lock;
static size_t oracle_env_size;
static OracleGlobal *oracle_globals;
static unsigned oracle_nglobals;
/* Bit per env byte: set when the byte belongs to some TCG global. */
static unsigned long *oracle_cover;
static uint64_t oracle_pc_lo;
static uint64_t oracle_pc_hi = UINT64_MAX;
static uint64_t oracle_max_lines = 2000000;
static uint64_t oracle_lines;
static bool oracle_do_helpers = true;
static bool oracle_do_insn_marks = true;
/*
 * How far before oracle_pc_lo a TB may start and still reach into the window.
 * A TB never spans more than two guest pages, so two pages is exact; it is
 * settable only because a wrong value here is the one way gating can lose a
 * record, and being able to widen it without a rebuild makes that testable.
 */
static uint64_t oracle_tb_slack;
/* Number of 8-byte words in env, and longs in a per-word change bitmap. */
static size_t oracle_env_words;
static size_t oracle_chg_longs;

/*
 * State randomisation.  A differ cannot see a write whose value equals what
 * was already there, so the mitigation is to make sure it does not: put a
 * value in the destination that the instruction cannot produce, and the write
 * reappears.  Each spec names a byte range and how to spoil it.
 *
 *   'z'  set to zero
 *   'r'  set to a fresh pseudo-random value
 *   'c'  set to a given constant
 *   'o'  set to zero, and OR the old value back afterwards
 *
 * After the instruction, a range that still holds the poison was not written
 * and is put back; a range that does not was written and is left alone.  So a
 * poison the instruction ignores costs the program nothing.  A poison the
 * instruction *reads* is a different matter -- see oracle_poison_apply().
 *
 * 'o' is for a field that accumulates rather than being assigned -- an FP
 * sticky exception flag word.  Zeroing it makes the bits *this* instruction
 * raises visible even when they were already set, and OR-ing the old value
 * back reconstructs the accumulation.  That reconstruction is a model of the
 * field, not a fact about it, and the model is wrong wherever a target clears
 * a bit: RISC-V's fround does exactly that, restoring the caller's inexact
 * bit by assignment.  Which is why a poisoned run has to be checked.
 */
typedef struct OraclePoisonSpec {
    size_t off;
    uint32_t size;
    char mode;
    uint64_t cval;
    uint64_t pc;                        /* only at this pc, if has_pc */
    bool has_pc;
} OraclePoisonSpec;

static OraclePoisonSpec *oracle_poisons;
static unsigned oracle_npoisons;
static uint64_t oracle_poison_nth;      /* 0 = every execution */
static bool oracle_poison_once;
static uint64_t oracle_poison_seed = 0x9e3779b97f4a7c15ULL;

/* Per-guest-thread execution state. */
typedef struct OracleThread {
    uint8_t *snap;                                  /* env at last boundary */
    uint8_t *hsnap[ORACLE_HELPER_DEPTH];            /* env at helper entry */
    const TCGHelperInfo *hinfo[ORACLE_HELPER_DEPTH];
    unsigned long *chg;             /* scratch: changed 8-byte words of env */
    uint8_t *pre;                   /* env before poisoning, to put back */
    uint64_t rng;
    uint64_t nexec;                 /* executions of the poison target pc */
    int hdepth;
    uint64_t cur_pc;
    bool snapped;
    bool poisoned;
} OracleThread;

static __thread OracleThread *oracle_tls;

/* CP5, below: take down a protection window a helper left armed. */
static void oracle_hr_reset(void);

/* ------------------------------------------------------------------ */
/* Output                                                              */
/* ------------------------------------------------------------------ */

static bool oracle_budget(void)
{
    if (oracle_lines >= oracle_max_lines) {
        return false;
    }
    oracle_lines++;
    return true;
}

static void oracle_val(char *buf, size_t buflen, const uint8_t *p, uint32_t size)
{
    uint64_t v = 0;

    switch (size) {
    case 1: case 2: case 4: case 8:
        memcpy(&v, p, size);
        snprintf(buf, buflen, "0x%0*" PRIx64, (int)(size * 2), v);
        return;
    default:
        break;
    }

    /* Wide field: hexdump, most-significant byte first for readability. */
    {
        size_t n = MIN(size, ORACLE_RAW_DUMP_MAX);
        size_t o = 0;
        o += snprintf(buf + o, buflen - o, "0x");
        for (size_t i = 0; i < n && o + 3 < buflen; i++) {
            o += snprintf(buf + o, buflen - o, "%02x", p[size - 1 - i]);
        }
        if (n < size && o + 4 < buflen) {
            snprintf(buf + o, buflen - o, "...");
        }
    }
}

/* ------------------------------------------------------------------ */
/* CP3: the offset -> register map, taken from TCG's own globals table  */
/* ------------------------------------------------------------------ */

#define ORACLE_NAME_MAX 48

static const char *oracle_clean_name(const char *name)
{
    char buf[ORACLE_NAME_MAX + 1];
    size_t n = 0;

    if (name == NULL) {
        return "<unnamed>";
    }
    while (n < ORACLE_NAME_MAX && name[n] != '\0') {
        char c = name[n];
        buf[n] = (c > 0x20 && c < 0x7f) ? c : '?';
        n++;
    }
    buf[n] = '\0';
    return g_strdup(buf);
}

static void oracle_capture_globals(void)
{
    TCGContext *s = tcg_ctx;
    TCGTemp *env_ts = tcgv_ptr_temp(tcg_env);
    unsigned n = 0;

    oracle_globals = g_new0(OracleGlobal, s->nb_globals);

    for (int i = 0; i < s->nb_globals; i++) {
        TCGTemp *ts = &s->temps[i];
        uint32_t size;

        if (ts->kind != TEMP_GLOBAL) {
            continue;
        }
        /*
         * Only env-relative globals are part of the architectural state we
         * can diff.  A global based on anything else (some targets build
         * indirect globals off a second base) is reported and skipped rather
         * than guessed at.
         */
        if (ts->mem_base != env_ts) {
            fprintf(oracle_out, "S skipped-global name=%s reason=non-env-base\n",
                    ts->name ? ts->name : "?");
            continue;
        }
        if (ts->temp_subindex != 0) {
            /* 64-bit global split over two 32-bit temps (32-bit hosts). */
            continue;
        }
        size = tcg_type_size(ts->base_type);
        if (ts->mem_offset < 0 ||
            (size_t)ts->mem_offset + size > oracle_env_size) {
            fprintf(oracle_out, "S skipped-global name=%s off=%td size=%u "
                    "reason=outside-env\n",
                    ts->name ? ts->name : "?", ts->mem_offset, size);
            continue;
        }

        oracle_globals[n].off = ts->mem_offset;
        oracle_globals[n].size = size;
        oracle_globals[n].wlo = (uint32_t)(ts->mem_offset >> 3);
        oracle_globals[n].whi = (uint32_t)((ts->mem_offset + size - 1) >> 3);
        /*
         * Copy the name defensively.  It comes straight out of a target's
         * static table and a table sized exactly to its longest entry leaves
         * the string unterminated -- target/mips had one.  Bound the length
         * and drop anything unprintable so a malformed table can only produce
         * an odd-looking name, never a runaway report.
         */
        oracle_globals[n].name = oracle_clean_name(ts->name);
        n++;
    }
    oracle_nglobals = n;

    oracle_cover = bitmap_new(oracle_env_size);
    for (unsigned i = 0; i < n; i++) {
        bitmap_set(oracle_cover, oracle_globals[i].off, oracle_globals[i].size);
    }

    for (unsigned i = 0; i < n; i++) {
        fprintf(oracle_out, "G %6td %2u %s\n", oracle_globals[i].off,
                oracle_globals[i].size, oracle_globals[i].name);
    }
}

/* ------------------------------------------------------------------ */
/* Diff engine                                                         */
/* ------------------------------------------------------------------ */

/*
 * Reduce two env images to the set of 8-byte words that differ, and say
 * whether any did.
 *
 * Everything downstream consults this first.  Diffing 99 registers with 99
 * memcmp()s and then walking every byte of env looking for uncovered runs is
 * what made an armed instruction cost hundreds of nanoseconds; one linear
 * pass the compiler can vectorise, followed by bit tests, is most of the
 * difference.  The early "nothing changed at all" answer is worth having on
 * its own: it is the whole cost of an instruction that writes only memory.
 */
#define ORACLE_CHUNK 512

static bool oracle_changed_words(unsigned long *chg,
                                 const uint8_t *a, const uint8_t *b)
{
    bool any = false;

    memset(chg, 0, oracle_chg_longs * sizeof(unsigned long));

    /*
     * Coarse pass then fine pass.  A word-at-a-time loop that sets a bit as
     * it goes cannot be vectorised -- the store to the bitmap serialises it --
     * and profiling put 70% of an armed instruction's cost in exactly that
     * loop.  Almost all of env is untouched by any one instruction, so ask
     * memcmp about a chunk at a time first: an unchanged chunk is dismissed at
     * the width of the host's vector unit, and only a chunk that really did
     * change pays for the word-by-word breakdown.
     */
    for (size_t c = 0; c < oracle_env_size; c += ORACLE_CHUNK) {
        size_t len = MIN(ORACLE_CHUNK, oracle_env_size - c);

        if (!memcmp(a + c, b + c, len)) {
            continue;
        }
        any = true;
        for (size_t i = c; i < c + len; i += 8) {
            size_t n = MIN(8, oracle_env_size - i);

            if (n == 8) {
                uint64_t x, y;

                /*
                 * memcpy rather than a cast: env is a CPUArchState and these
                 * buffers are uint8_t, so a uint64_t load through either is an
                 * aliasing violation.  Every compiler we build with turns this
                 * into the load it looks like.
                 */
                memcpy(&x, a + i, 8);
                memcpy(&y, b + i, 8);
                if (x != y) {
                    set_bit(i >> 3, chg);
                }
            } else if (memcmp(a + i, b + i, n)) {
                set_bit(i >> 3, chg);
            }
        }
    }
    return any;
}

static bool oracle_words_changed(const unsigned long *chg,
                                 uint32_t wlo, uint32_t whi)
{
    for (uint32_t w = wlo; w <= whi; w++) {
        if (test_bit(w, chg)) {
            return true;
        }
    }
    return false;
}

/*
 * Report every difference between two env images.  Registers named by the
 * TCG globals table are reported by name; everything else is reported as a
 * raw offset run, which is exactly the state the interpretation layer has to
 * resolve.
 *
 * @chg must already describe the differing words.  The caller holds
 * oracle_lock.
 *
 * Returns the number of differing byte ranges reported.
 */
static unsigned oracle_diff(char tag, uint64_t pc, const TCGHelperInfo *info,
                            int64_t retoff, const unsigned long *chg,
                            const uint8_t *before, const uint8_t *after)
{
    char ob[192], nb[192];
    unsigned hits = 0;
    const char *hname = info ? info->name : NULL;
    unsigned hflags = info ? info->flags : 0;
    /*
     * tcg.h documents NO_READ_GLOBALS as implying NO_WRITE_GLOBALS, so both
     * bits mean "this helper does not touch a global".
     */
    bool declared_no_wg = (hflags & (TCG_CALL_NO_WRITE_GLOBALS |
                                     TCG_CALL_NO_READ_GLOBALS)) != 0;

    /* 1. Named registers. */
    for (unsigned i = 0; i < oracle_nglobals; i++) {
        const OracleGlobal *g = &oracle_globals[i];
        bool is_retval = hname && (int64_t)g->off == retoff;

        if (!oracle_words_changed(chg, g->wlo, g->whi)) {
            continue;
        }
        if (!memcmp(before + g->off, after + g->off, g->size)) {
            continue;
        }
        hits++;
        if (!oracle_budget()) {
            return hits;
        }
        oracle_val(ob, sizeof(ob), before + g->off, g->size);
        oracle_val(nb, sizeof(nb), after + g->off, g->size);
        if (hname) {
            fprintf(oracle_out,
                    "%c 0x%" PRIx64 " helper=%s flags=0x%x reg=%s off=%td "
                    "size=%u old=%s new=%s%s\n",
                    tag, pc, hname, hflags, g->name, g->off, g->size, ob, nb,
                    is_retval ? " via=retval" : "");
            /*
             * A helper that TCG believes writes no globals, writing a global.
             * Either the declaration is wrong (TCG may then discard the write)
             * or the field is aliased.  Both are worth shouting about.
             *
             * The helper's own return value does not count: the caller bound
             * it to a global, so the store is emitted by the register
             * allocator between the call and this probe.  Attributing that to
             * the helper's interior would be a false positive.
             */
            if (declared_no_wg && !is_retval) {
                if (oracle_budget()) {
                    fprintf(oracle_out,
                            "X 0x%" PRIx64 " helper=%s NO_WG_VIOLATION reg=%s "
                            "off=%td\n", pc, hname, g->name, g->off);
                }
            }
        } else {
            fprintf(oracle_out,
                    "%c 0x%" PRIx64 " reg=%s off=%td size=%u old=%s new=%s\n",
                    tag, pc, g->name, g->off, g->size, ob, nb);
        }
    }

    /* 2. Everything else, as raw runs over the bytes no global covers. */
    for (size_t i = 0; i < oracle_env_size; ) {
        size_t j;

        /* Skip eight bytes at a time over words nothing touched. */
        if (!test_bit(i >> 3, chg)) {
            i = ((i >> 3) + 1) << 3;
            continue;
        }
        if (before[i] == after[i] || test_bit(i, oracle_cover)) {
            i++;
            continue;
        }
        j = i;
        while (j < oracle_env_size && !test_bit(j, oracle_cover) &&
               before[j] != after[j]) {
            j++;
        }
        hits++;
        if (!oracle_budget()) {
            return hits;
        }
        oracle_val(ob, sizeof(ob), before + i, j - i);
        oracle_val(nb, sizeof(nb), after + i, j - i);
        if (hname) {
            fprintf(oracle_out,
                    "%c 0x%" PRIx64 " helper=%s flags=0x%x raw off=%zu size=%zu "
                    "old=%s new=%s\n",
                    tag, pc, hname, hflags, i, j - i, ob, nb);
        } else {
            fprintf(oracle_out,
                    "%c 0x%" PRIx64 " raw off=%zu size=%zu old=%s new=%s\n",
                    tag, pc, i, j - i, ob, nb);
        }
        i = j;
    }
    return hits;
}

/* ------------------------------------------------------------------ */
/* Runtime probes (called from generated code)                         */
/* ------------------------------------------------------------------ */

static OracleThread *oracle_thread(void)
{
    OracleThread *t = oracle_tls;

    if (unlikely(t == NULL)) {
        t = g_new0(OracleThread, 1);
        t->snap = g_malloc(oracle_env_size);
        for (int i = 0; i < ORACLE_HELPER_DEPTH; i++) {
            t->hsnap[i] = g_malloc(oracle_env_size);
        }
        t->chg = bitmap_new(oracle_env_words);
        if (oracle_npoisons) {
            t->pre = g_malloc(oracle_env_size);
        }
        t->rng = oracle_poison_seed;
        oracle_tls = t;
    }
    return t;
}

/* ------------------------------------------------------------------ */
/* State randomisation                                                 */
/* ------------------------------------------------------------------ */

static uint64_t oracle_rand(OracleThread *t)
{
    /* splitmix64: small, seedable, and reproducible across runs. */
    uint64_t z = (t->rng += 0x9e3779b97f4a7c15ULL);

    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static bool oracle_poison_here(const OraclePoisonSpec *p, uint64_t pc)
{
    return !p->has_pc || p->pc == pc;
}

/*
 * Spoil every destination named for this pc, having first saved what was
 * there.  The snapshot the caller takes afterwards is of the *poisoned* env,
 * so the next boundary's diff is against the poison and a write of a value
 * that happened to match the original state is no longer invisible.
 *
 * What this may legally do is bounded, and the bound is not "state the ISA
 * calls sticky".  QEMU reads accumulated FP exception flags in at least two
 * places where the read changes what happens: can_use_fpu() takes the
 * hardfloat path only when inexact is *already* set, and RISC-V's fround
 * family reads the old inexact bit in order to put it back afterwards.  So
 * poisoning is not proved safe by the architecture, and the oracle does not
 * claim it is: a poisoned run is only trustworthy if it is checked against an
 * unpoisoned one, which is what tests/oracle/check-poison.py does.
 */
static void oracle_poison_apply(OracleThread *t, uint8_t *env, uint64_t pc)
{
    bool any = false;

    for (unsigned i = 0; i < oracle_npoisons; i++) {
        const OraclePoisonSpec *p = &oracle_poisons[i];

        if (!oracle_poison_here(p, pc)) {
            continue;
        }
        if (!any) {
            memcpy(t->pre, env, oracle_env_size);
            any = true;
        }
        switch (p->mode) {
        case 'z':
        case 'o':
            memset(env + p->off, 0, p->size);
            break;
        case 'c':
            for (uint32_t b = 0; b < p->size; b++) {
                env[p->off + b] = (uint8_t)(p->cval >> ((b & 7) * 8));
            }
            break;
        default:
            for (uint32_t b = 0; b < p->size; b += 8) {
                uint64_t r = oracle_rand(t);
                uint32_t n = MIN(8, p->size - b);
                memcpy(env + p->off + b, &r, n);
            }
            break;
        }
        if (oracle_budget()) {
            char ob[192], nb[192];

            oracle_val(ob, sizeof(ob), t->pre + p->off, p->size);
            oracle_val(nb, sizeof(nb), env + p->off, p->size);
            fprintf(oracle_out, "P 0x%" PRIx64 " off=%zu size=%u mode=%c "
                    "was=%s poison=%s\n", pc, p->off, p->size, p->mode, ob, nb);
        }
    }
    t->poisoned = any;
}

/*
 * Undo the poison now the instruction has been diffed.  A range still holding
 * the poison -- which is what t->snap recorded -- was not written, so put the
 * original back and the guest never knows.  A range that changed was written,
 * so the instruction's own value stands.
 */
static void oracle_poison_restore(OracleThread *t, uint8_t *env, uint64_t pc)
{
    for (unsigned i = 0; i < oracle_npoisons; i++) {
        const OraclePoisonSpec *p = &oracle_poisons[i];
        bool kept;

        if (!oracle_poison_here(p, pc)) {
            continue;
        }
        kept = memcmp(env + p->off, t->snap + p->off, p->size) != 0;
        if (p->mode == 'o') {
            /* Accumulator: what the instruction raised, plus what was there. */
            for (uint32_t b = 0; b < p->size; b++) {
                env[p->off + b] |= t->pre[p->off + b];
            }
        } else if (!kept) {
            memcpy(env + p->off, t->pre + p->off, p->size);
        }
        if (oracle_budget()) {
            fprintf(oracle_out, "R 0x%" PRIx64 " off=%zu size=%u written=%d\n",
                    pc, p->off, p->size, kept);
        }
    }
    t->poisoned = false;
}

/*
 * Does anything want poisoning before the instruction at @pc?  Counting
 * executions here rather than in the apply path keeps -NTH honest when the
 * same pc is reached many times.
 */
static bool oracle_poison_due(OracleThread *t, uint64_t pc)
{
    bool match = false;

    if (oracle_npoisons == 0) {
        return false;
    }
    for (unsigned i = 0; i < oracle_npoisons; i++) {
        if (oracle_poison_here(&oracle_poisons[i], pc)) {
            match = true;
            break;
        }
    }
    if (!match) {
        return false;
    }
    t->nexec++;
    if (oracle_poison_nth && t->nexec != oracle_poison_nth) {
        return false;
    }
    if (oracle_poison_once && oracle_poison_nth == 0 && t->nexec > 1) {
        return false;
    }
    return true;
}

/*
 * Close out the pending instruction: report what changed since its boundary
 * snapshot.  The comparison runs unlocked -- both images belong to this
 * thread -- and the lock is taken only if there is something to say.
 */
static void oracle_flush(OracleThread *t, const uint8_t *env)
{
    if (!oracle_changed_words(t->chg, t->snap, env)) {
        return;
    }
    qemu_mutex_lock(&oracle_lock);
    oracle_diff('W', t->cur_pc, NULL, -1, t->chg, t->snap, env);
    qemu_mutex_unlock(&oracle_lock);
}

void oracle_insn_boundary(void *envp, uint64_t pc);
void oracle_insn_boundary(void *envp, uint64_t pc)
{
    /*
     * A helper that leaves through cpu_loop_exit() never reaches its post
     * probe, so the protection it armed is still up.  Execution only gets
     * back here by faulting its way through, which is correct but ruinous,
     * so the boundary is where it gets taken down.
     */
    oracle_hr_reset();
    OracleThread *t = oracle_thread();
    uint8_t *env = envp;
    bool want = pc >= oracle_pc_lo && pc <= oracle_pc_hi;

    /*
     * Any helper frame still open here belongs to an instruction that left
     * via longjmp (an exception or a syscall).  Drop it; the boundary diff
     * still covers the net effect.
     */
    t->hdepth = 0;

    if (t->snapped) {
        oracle_flush(t, env);
    }
    if (unlikely(t->poisoned)) {
        qemu_mutex_lock(&oracle_lock);
        oracle_poison_restore(t, env, t->cur_pc);
        qemu_mutex_unlock(&oracle_lock);
    }

    if (want) {
        qemu_mutex_lock(&oracle_lock);
        if (oracle_do_insn_marks && oracle_budget()) {
            fprintf(oracle_out, "I 0x%" PRIx64 "\n", pc);
        }
        if (unlikely(oracle_poison_due(t, pc))) {
            oracle_poison_apply(t, env, pc);
        }
        qemu_mutex_unlock(&oracle_lock);
        memcpy(t->snap, env, oracle_env_size);
    }
    t->snapped = want;
    t->cur_pc = pc;
}

void oracle_tb_exit(void *envp)
{
    OracleThread *t = oracle_tls;

    if (t == NULL || !t->snapped) {
        return;
    }
    /*
     * Reached the end of an armed TB.  The last instruction in it has no
     * following boundary probe, so this is where its writes are read off.
     * Taking the reading here rather than at the next instruction is also
     * what keeps the delta attributable: with gating on, the next boundary
     * probe may be an unbounded distance away.
     *
     * env at this point has already been through the TB epilogue, so a
     * branch's write to pc is included -- which is the same window the
     * ungated build measured, when the next TB's first probe closed it.
     */
    t->hdepth = 0;
    oracle_flush(t, envp);
    if (unlikely(t->poisoned)) {
        qemu_mutex_lock(&oracle_lock);
        oracle_poison_restore(t, envp, t->cur_pc);
        qemu_mutex_unlock(&oracle_lock);
    }
    t->snapped = false;
}

/* ------------------------------------------------------------------ */
/* CP5: inside the helper                                              */
/* ------------------------------------------------------------------ */

/*
 * A helper call is one TCG op, so the IR walk can say who was handed what and
 * nothing about what was done with it.  The differ closes half of that: it can
 * see what the helper changed.  It cannot see what the helper *read*, and a
 * dependency model needs both.
 *
 * The declared flags are not an answer.  TCG_CALL_NO_READ_GLOBALS is a
 * promise a helper makes to the register allocator, and most helpers make no
 * promise at all -- helper_divq_EAX is declared flags=0x0, which says only
 * that it may touch anything.  A superset that large is the thing this phase
 * exists to stop relying on.
 *
 * So: go inside.  Not by interposing a frame -- Phase 1 established that a
 * DEF_HELPER_FLAGS_N wrapper breaks GETPC(), and silently -- but by making
 * the state itself untouchable for the duration of the call.  Before the
 * helper runs, the pages CPUArchState lives in go PROT_NONE; each access the
 * helper makes then traps, and the handler records the offset and the
 * direction, unprotects, single-steps the one instruction, and protects
 * again.  The helper's own frame is never disturbed, so GETPC() is exactly as
 * valid as it was.
 *
 * What it costs is two signals per access, which is roughly four orders of
 * magnitude.  That is why it is off unless asked for.
 *
 * What it cannot do:
 *   - It sees the first byte of an access, not its width: after the unprotect
 *     the whole access completes.  Naming the register is the layout map's
 *     job and a byte is enough for that; the width is not recovered.
 *   - CPUArchState does not begin on a page boundary, so the protected range
 *     covers some of its neighbours in ArchCPU.  A fault outside env is
 *     stepped like any other and recorded as nothing: it costs time, not
 *     accuracy.
 *   - Host x86-64 Linux only.  Reading the direction out of the fault and
 *     setting the trap flag are both host ABI.
 */

#if defined(__x86_64__) && defined(__linux__)
#define ORACLE_HELPER_READS 1
#endif

#ifdef ORACLE_HELPER_READS
#include <ucontext.h>

static bool oracle_hr_on;
static uintptr_t oracle_hr_lo, oracle_hr_hi;    /* page-aligned protection */
static uintptr_t oracle_hr_env;                 /* env base, for offsets */
static struct sigaction oracle_hr_old_segv, oracle_hr_old_trap;
static bool oracle_hr_installed;
/* Per pc, what has already been reported; keeps a hot loop from flooding. */
static GHashTable *oracle_hr_seen;

static __thread bool oracle_hr_armed;
static __thread bool oracle_hr_stepping;
static __thread unsigned long *oracle_hr_rd;
static __thread unsigned long *oracle_hr_wr;
static __thread uint64_t oracle_hr_faults;

static void oracle_hr_protect(int prot)
{
    mprotect((void *)oracle_hr_lo, oracle_hr_hi - oracle_hr_lo, prot);
}

static void oracle_hr_chain(struct sigaction *old, int sig, siginfo_t *si,
                            void *uc)
{
    if (old->sa_flags & SA_SIGINFO) {
        old->sa_sigaction(sig, si, uc);
    } else if (old->sa_handler != SIG_IGN && old->sa_handler != SIG_DFL) {
        old->sa_handler(sig);
    } else {
        signal(sig, SIG_DFL);
        raise(sig);
    }
}

static void oracle_hr_segv(int sig, siginfo_t *si, void *ucp)
{
    ucontext_t *uc = ucp;
    uintptr_t a = (uintptr_t)si->si_addr;
    bool write;

    if (!oracle_hr_armed || a < oracle_hr_lo || a >= oracle_hr_hi) {
        oracle_hr_chain(&oracle_hr_old_segv, sig, si, ucp);
        return;
    }
    /* Bit 1 of the page-fault error code is set for a write. */
    write = (uc->uc_mcontext.gregs[REG_ERR] & 2) != 0;
    oracle_hr_faults++;
    if (a >= oracle_hr_env && a - oracle_hr_env < oracle_env_size) {
        set_bit(a - oracle_hr_env, write ? oracle_hr_wr : oracle_hr_rd);
    }
    oracle_hr_protect(PROT_READ | PROT_WRITE);
    oracle_hr_stepping = true;
    uc->uc_mcontext.gregs[REG_EFL] |= 0x100;            /* TF */
}

static void oracle_hr_trap(int sig, siginfo_t *si, void *ucp)
{
    ucontext_t *uc = ucp;

    if (!oracle_hr_stepping) {
        oracle_hr_chain(&oracle_hr_old_trap, sig, si, ucp);
        return;
    }
    uc->uc_mcontext.gregs[REG_EFL] &= ~0x100L;
    oracle_hr_stepping = false;
    if (oracle_hr_armed) {
        oracle_hr_protect(PROT_NONE);
    }
}

static void oracle_hr_init(void)
{
    struct sigaction sa;
    size_t ps = qemu_real_host_page_size();

    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = oracle_hr_segv;
    sigaction(SIGSEGV, &sa, &oracle_hr_old_segv);
    sa.sa_sigaction = oracle_hr_trap;
    sigaction(SIGTRAP, &sa, &oracle_hr_old_trap);

    oracle_hr_lo = oracle_hr_env & ~(uintptr_t)(ps - 1);
    oracle_hr_hi = (oracle_hr_env + oracle_env_size + ps - 1) &
                   ~(uintptr_t)(ps - 1);
    oracle_hr_seen = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                           g_free, g_free);
    oracle_hr_installed = true;
    fprintf(oracle_out, "T helper_reads=1 env=0x%zx protect=[0x%zx,0x%zx)\n",
            (size_t)oracle_hr_env, (size_t)oracle_hr_lo, (size_t)oracle_hr_hi);
}

/*
 * Arm for one helper call, at the outermost depth only: a nested call would
 * have to save and restore the protection, and the outer window already
 * covers everything the inner one does.
 */
static void oracle_hr_arm(void *envp, int depth)
{
    if (!oracle_hr_on || depth != 0) {
        return;
    }
    if (!oracle_hr_installed) {
        oracle_hr_env = (uintptr_t)envp;
        oracle_hr_init();
    }
    if ((uintptr_t)envp != oracle_hr_env) {
        return;                     /* another vCPU: one window is enough */
    }
    if (oracle_hr_rd == NULL) {
        oracle_hr_rd = bitmap_new(oracle_env_size);
        oracle_hr_wr = bitmap_new(oracle_env_size);
    }
    bitmap_zero(oracle_hr_rd, oracle_env_size);
    bitmap_zero(oracle_hr_wr, oracle_env_size);
    oracle_hr_faults = 0;
    oracle_hr_armed = true;
    oracle_hr_protect(PROT_NONE);
}

static void oracle_hr_reset(void)
{
    if (oracle_hr_armed) {
        oracle_hr_armed = false;
        oracle_hr_stepping = false;
        oracle_hr_protect(PROT_READ | PROT_WRITE);
    }
}

/*
 * Report the bytes this helper touched that no earlier execution of the same
 * pc reported already.  A data-dependent helper touches different fields on
 * different executions, so the union grows; one that does the same thing
 * every time reports once.
 */
static void oracle_hr_disarm(uint64_t pc, const TCGHelperInfo *info, int depth)
{
    unsigned long *seen;
    uint64_t key = pc;

    if (!oracle_hr_armed || depth != 0) {
        return;
    }
    oracle_hr_armed = false;
    oracle_hr_stepping = false;
    oracle_hr_protect(PROT_READ | PROT_WRITE);

    qemu_mutex_lock(&oracle_lock);
    seen = g_hash_table_lookup(oracle_hr_seen, &key);
    if (seen == NULL) {
        seen = bitmap_new(2 * oracle_env_size);
        g_hash_table_insert(oracle_hr_seen, g_memdup2(&key, 8), seen);
    }
    for (int w = 0; w < 2; w++) {
        const unsigned long *bm = w ? oracle_hr_wr : oracle_hr_rd;

        for (size_t i = 0; i < oracle_env_size; i++) {
            if (!test_bit(i, bm) || test_bit(w * oracle_env_size + i, seen)) {
                continue;
            }
            set_bit(w * oracle_env_size + i, seen);
            if (!oracle_budget()) {
                break;
            }
            fprintf(oracle_out, "Y 0x%" PRIx64 " %c off=%zu size=1 helper=%s "
                    "faults=%" PRIu64 "\n", pc, w ? 'w' : 'r', i,
                    info && info->name ? info->name : "?", oracle_hr_faults);
        }
    }
    qemu_mutex_unlock(&oracle_lock);
}
#else
static void oracle_hr_arm(void *envp, int depth) { }
static void oracle_hr_disarm(uint64_t pc, const TCGHelperInfo *i, int d) { }
static void oracle_hr_reset(void) { }
#endif /* ORACLE_HELPER_READS */

void oracle_helper_pre(void *envp, void *infop);
void oracle_helper_pre(void *envp, void *infop)
{
    OracleThread *t = oracle_thread();

    if (!t->snapped || t->hdepth >= ORACLE_HELPER_DEPTH) {
        /* Still push a frame so pre/post stay balanced. */
        if (t->hdepth < ORACLE_HELPER_DEPTH) {
            t->hinfo[t->hdepth] = NULL;
        }
        t->hdepth++;
        return;
    }
    t->hinfo[t->hdepth] = infop;
    memcpy(t->hsnap[t->hdepth], envp, oracle_env_size);
    /* After the snapshot: taking it is not one of the helper's accesses. */
    oracle_hr_arm(envp, t->hdepth);
    t->hdepth++;
}

void oracle_helper_post(void *envp, void *infop, int64_t retoff);
void oracle_helper_post(void *envp, void *infop, int64_t retoff)
{
    OracleThread *t = oracle_thread();
    int d;

    if (t->hdepth <= 0) {
        return;
    }
    d = --t->hdepth;
    /* Before anything else reads env, and before the early returns. */
    oracle_hr_disarm(t->cur_pc, infop, d);
    if (d >= ORACLE_HELPER_DEPTH || t->hinfo[d] == NULL) {
        return;
    }
    if (t->hinfo[d] != infop) {
        return;                      /* unbalanced; nothing trustworthy here */
    }
    if (!oracle_changed_words(t->chg, t->hsnap[d], envp)) {
        return;
    }
    qemu_mutex_lock(&oracle_lock);
    oracle_diff('H', t->cur_pc, infop, retoff, t->chg, t->hsnap[d], envp);
    qemu_mutex_unlock(&oracle_lock);
}

/* ------------------------------------------------------------------ */
/* Code generation                                                     */
/* ------------------------------------------------------------------ */

/*
 * The boundary probe must see a coherent env, so it may not carry
 * TCG_CALL_NO_READ_GLOBALS: TCG spills every global it is holding in a host
 * register before a call that reads globals, which is precisely the sync we
 * need.  It writes nothing, hence NO_WG.
 */
static TCGHelperInfo oracle_info_boundary = {
    .func = oracle_insn_boundary,
    .name = "oracle_insn_boundary",
    .flags = TCG_CALL_NO_WG,
    .typemask = dh_typemask(void, 0) | dh_typemask(ptr, 1) | dh_typemask(i64, 2),
};

/*
 * The same probe, declared to write globals as well as read them, for when
 * poisoning is on.
 *
 * NO_WG says the callee does not touch env, which lets TCG go on using the
 * copies of guest registers it is holding in host registers after the call
 * returns.  That is free when the probe only looks.  It is not free when the
 * probe *writes*: the poison lands in env and the instruction reads the host
 * register, so the poison silently does nothing -- and a poison that does
 * nothing reads exactly like an instruction that does not write the register.
 *
 * Dropping the flag makes TCG reload the globals after the call.  The spill
 * *before* the call is what makes the boundary delta exact, and that is
 * unaffected: a call that writes globals still has to have them written out
 * first.  So this costs register allocation quality inside armed TBs and
 * nothing else.
 */
static TCGHelperInfo oracle_info_boundary_rw = {
    .func = oracle_insn_boundary,
    .name = "oracle_insn_boundary_rw",
    .flags = 0,
    .typemask = dh_typemask(void, 0) | dh_typemask(ptr, 1) | dh_typemask(i64, 2),
};

/* Same reasoning for the pre-probe. */
static TCGHelperInfo oracle_info_pre = {
    .func = oracle_helper_pre,
    .name = "oracle_helper_pre",
    .flags = TCG_CALL_NO_WG,
    .typemask = dh_typemask(void, 0) | dh_typemask(ptr, 1) | dh_typemask(ptr, 2),
};

/*
 * The post-probe is the opposite: it must observe env exactly as the helper
 * left it.  If it read globals, TCG would write back its own register copies
 * first and could paper over a helper that wrote a global it had declared it
 * would not touch -- the one bug class this probe exists to catch.
 *
 * The third argument is the env offset of the global the call's return value
 * is bound to, or -1.  Inserting this probe is itself what forces the
 * register allocator to spill that value, so without the offset the helper's
 * own result reads back as an interior side effect.
 */
static TCGHelperInfo oracle_info_post = {
    .func = oracle_helper_post,
    .name = "oracle_helper_post",
    .flags = TCG_CALL_NO_RWG,
    .typemask = dh_typemask(void, 0) | dh_typemask(ptr, 1) |
                dh_typemask(ptr, 2) | dh_typemask(i64, 3),
};

static __thread bool oracle_in_gen;
/* Translation-scoped: was the previous instruction of this TB in the window? */
static __thread bool oracle_gen_prev_in_window;
/* Translation-scoped: is the instruction being translated now in the window? */
static __thread bool oracle_gen_insn_in_window;

/* CP4, below: the IR walk needs the pc of every instruction of an armed TB. */
static void oracle_ir_note_insn(uint64_t pc, bool first_insn, bool in_window);

/* Is the TB currently being translated one the oracle asked to be armed? */
static bool oracle_gen_armed(void)
{
    const TranslationBlock *tb = tcg_ctx->gen_tb;

    return tb != NULL && (tb->cflags & CF_ORACLE) != 0;
}

uint32_t oracle_tb_cflags(uint64_t pc)
{
    if (!oracle_on) {
        return 0;
    }
    if (pc > oracle_pc_hi) {
        return 0;
    }
    /*
     * A TB starting below the window can still reach into it.  Its extent is
     * not known until it has been translated and the cflags have to be fixed
     * before that, so arm anything close enough to reach: a TB spans at most
     * two guest pages.  Over-arming costs nothing, because which instructions
     * actually carry a probe is decided per instruction below.
     */
    if (pc < oracle_pc_lo && oracle_pc_lo - pc > oracle_tb_slack) {
        return 0;
    }
    return CF_ORACLE;
}

/*
 * May a jump from @from be patched to land directly in @to?
 *
 * Only if the oracle would still get to close out @from's last instruction.
 * An armed TB reports an instruction's writes at the *next* boundary probe;
 * jumping into a TB that has no probes leaves that reading untaken.  Refusing
 * the patch sends control back to the execution loop, where oracle_tb_exit()
 * takes it.
 *
 * Armed-to-armed chaining is left alone -- the destination's first
 * instruction always carries a probe -- which is what keeps a hot loop inside
 * the window running at chained speed.
 */
bool oracle_tb_chain_ok(const void *fromp, const void *top)
{
    const TranslationBlock *from = fromp, *to = top;

    if (!oracle_on) {
        return true;
    }
    return !(from->cflags & CF_ORACLE) || (to->cflags & CF_ORACLE);
}

/*
 * The same question for goto_ptr, which is resolved afresh on every execution
 * and so can be answered from live state rather than from cflags: only divert
 * back to the execution loop if there is actually a reading outstanding.
 */
bool oracle_must_exit_before(const void *top)
{
    const TranslationBlock *to = top;
    const OracleThread *t = oracle_tls;

    return oracle_on && t != NULL && t->snapped && !(to->cflags & CF_ORACLE);
}

bool oracle_gen_helper_probe_wanted(const TCGHelperInfo *info)
{
    if (!oracle_on || !oracle_do_helpers || oracle_in_gen) {
        return false;
    }
    /*
     * Helper probes belong to the instruction being translated, so they follow
     * the same window test the boundary probe just applied -- an armed TB's
     * out-of-window instructions get their helpers left alone.
     */
    if (!oracle_gen_insn_in_window || !oracle_gen_armed()) {
        return false;
    }
    if (info == &oracle_info_boundary || info == &oracle_info_boundary_rw ||
        info == &oracle_info_pre || info == &oracle_info_post) {
        return false;
    }
    /* Plugin trampolines are QEMU's own machinery, not guest behaviour. */
    if (info->name && !strncmp(info->name, "plugin_", 7)) {
        return false;
    }
    return true;
}

void oracle_gen_helper_probe(const TCGHelperInfo *info, bool pre, TCGTemp *ret)
{
    int64_t retoff = -1;

    oracle_in_gen = true;
    if (pre) {
        tcg_gen_call2(oracle_info_pre.func, &oracle_info_pre, NULL,
                      tcgv_ptr_temp(tcg_env),
                      tcgv_ptr_temp(tcg_constant_ptr(info)));
    } else {
        if (ret != NULL && ret->kind == TEMP_GLOBAL &&
            ret->mem_base == tcgv_ptr_temp(tcg_env) && ret->temp_subindex == 0) {
            retoff = ret->mem_offset;
        }
        tcg_gen_call3(oracle_info_post.func, &oracle_info_post, NULL,
                      tcgv_ptr_temp(tcg_env),
                      tcgv_ptr_temp(tcg_constant_ptr(info)),
                      tcgv_i64_temp(tcg_constant_i64(retoff)));
    }
    oracle_in_gen = false;
}

/*
 * Which instructions of an armed TB carry a boundary probe.
 *
 * An instruction's writes are read off at the *following* probe, so a probe
 * is needed on an instruction in the window (to open it), on the first
 * instruction after the window (to close the last one), and on the first
 * instruction of the TB (to close whatever the previous TB left open, when it
 * chained straight here without passing through the execution loop).
 *
 * Everything else in an armed TB -- and every instruction of an unarmed one
 * -- gets nothing, which is the point: an armed TB reached only because it
 * starts within a page or two of the window emits no probes at all.
 */
void oracle_gen_insn_boundary(uint64_t pc, bool first_insn)
{
    bool in;

    oracle_gen_insn_in_window = false;
    if (!oracle_on || !oracle_gen_armed()) {
        return;
    }

    in = pc >= oracle_pc_lo && pc <= oracle_pc_hi;
    oracle_gen_insn_in_window = in;
    /*
     * The IR walk needs a pc for every instruction of an armed TB, not just
     * the ones that carry a runtime probe, because it matches them
     * positionally against the insn_start ops in the stream.
     */
    oracle_ir_note_insn(pc, first_insn, in);
    if (!in && !first_insn && !oracle_gen_prev_in_window) {
        oracle_gen_prev_in_window = false;
        return;
    }
    oracle_gen_prev_in_window = in;

    oracle_in_gen = true;
    {
        TCGHelperInfo *info = oracle_npoisons ? &oracle_info_boundary_rw
                                              : &oracle_info_boundary;

        tcg_gen_call2(info->func, info, NULL, tcgv_ptr_temp(tcg_env),
                      tcgv_i64_temp(tcg_constant_i64(pc)));
    }
    oracle_in_gen = false;
}

/* ------------------------------------------------------------------ */
/* CP4: read and write sets from the IR, before it has been optimised  */
/* ------------------------------------------------------------------ */

/*
 * The differ answers "what changed".  It cannot answer "what was read", and
 * it cannot see a write whose value was already there.  Both of those are
 * answered exactly one level up, in the IR the target's translator emitted:
 * every TCG op declares how many of its arguments are outputs and how many
 * are inputs, and a temp that is TEMP_GLOBAL based on tcg_env is a guest
 * register at a known offset.  So the read and write sets are readable
 * straight off the machine's own translation of the instruction.
 *
 * Three properties this has and the differ does not:
 *
 *   - Reads.  An input argument is a read whether or not it changes anything.
 *
 *   - Inert writes.  tcg_gen_movcond_* names its destination as a plain
 *     output, so a conditional write is in the IR whether or not the
 *     condition made it a no-op.  A consumer modelling speculative register
 *     release needs to know the write happened; a differ structurally cannot
 *     tell it.
 *
 *   - Value independence.  Nothing here looks at a value, so an instruction
 *     that writes what was already there is indistinguishable from one that
 *     did not -- which is the correct answer, and the one poisoning had to
 *     be invented to approximate.
 *
 * Why before tcg_optimize()
 * -------------------------
 * Dead-store elimination removes architecturally real writes that nothing
 * downstream consumes.  x86 is the extreme case: the whole lazy-flags scheme
 * exists so that flag writes can be dropped when the next instruction does
 * not look at them.  The translator's raw output is the truth, so the walk
 * runs at the top of tcg_gen_code(), before any pass has touched the ops.
 *
 * What the walk cannot see
 * ------------------------
 * A helper call is one op.  Its argument list is what crosses the boundary,
 * not what the helper does inside, so a call is reported as a call, with the
 * env regions its pointer arguments name (see below) -- the interior is the
 * runtime probes' job.
 *
 * Env accessed by pointer rather than by global is recoverable: gvec goes
 * through tcg_gen_addi_ptr(tmp, tcg_env, offset_of_a_vector_register), so a
 * temp whose value is tcg_env plus a constant carries a register number.  The
 * walk tracks those temps and reports the offset a call was handed, which the
 * layout map turns back into the field it names.
 */

#define ORACLE_IR_MAX_INSNS 1024

typedef struct OracleIRInsn {
    uint64_t pc;
    bool in_window;
} OracleIRInsn;

/*
 * Translation-scoped.  translator_loop() is not re-entrant on a thread, so
 * one buffer per thread is enough and none of it needs the lock.
 */
static __thread OracleIRInsn oracle_ir_insns[ORACLE_IR_MAX_INSNS];
static __thread unsigned oracle_ir_ninsns;
static __thread int64_t oracle_ir_envoff[TCG_MAX_TEMPS];

/*
 * Where each temp's value came from.
 *
 * A bit per TCG global, propagated forward through the ops: a temp carries
 * the set of guest registers its value was computed from.  Reporting that set
 * alongside a write is what makes the difference between a redefinition and
 * an update, and on x86 it is what separates a flag write from a change of
 * flag representation.  gen_compute_eflags() stores into cc_src a value it
 * computed *from* cc_op/cc_src/cc_dst, so a conditional branch looks exactly
 * like a flag write unless the provenance is there to say the value came from
 * the flags themselves and nowhere else.
 */
#define ORACLE_IR_PROV_WORDS 4                  /* up to 256 globals */
static __thread uint64_t oracle_ir_prov[TCG_MAX_TEMPS][ORACLE_IR_PROV_WORDS];

static bool oracle_do_ir = true;
/* pc -> hash of the set last reported for it; see the divergence check. */
static GHashTable *oracle_ir_seen;
static uint64_t oracle_ir_ninsn_reported;
static uint64_t oracle_ir_ndiverged;
static uint64_t oracle_ir_nchurned;

#define ORACLE_IR_NOT_ENV INT64_MIN

/* Record the pc of each instruction of an armed TB, in translation order. */
static void oracle_ir_note_insn(uint64_t pc, bool first_insn, bool in_window)
{
    if (first_insn) {
        oracle_ir_ninsns = 0;
    }
    if (oracle_ir_ninsns < ORACLE_IR_MAX_INSNS) {
        oracle_ir_insns[oracle_ir_ninsns].pc = pc;
        oracle_ir_insns[oracle_ir_ninsns].in_window = in_window;
    }
    oracle_ir_ninsns++;
}

/*
 * Name an env byte range.  An exact hit on a global is the common case; a
 * range inside one is a sub-register access.  Anything else is unnamed here
 * and left as an offset for the layout map to resolve, which is the same
 * contract the differ's raw runs have.
 */
static const char *oracle_ir_name_off(int64_t off, uint32_t size,
                                      int64_t *base)
{
    for (unsigned i = 0; i < oracle_nglobals; i++) {
        const OracleGlobal *g = &oracle_globals[i];

        if (g->off == off && g->size == size) {
            *base = g->off;
            return g->name;
        }
    }
    for (unsigned i = 0; i < oracle_nglobals; i++) {
        const OracleGlobal *g = &oracle_globals[i];

        if (off >= g->off && off + (int64_t)size <= g->off + (int64_t)g->size) {
            *base = g->off;
            return g->name;
        }
    }
    return NULL;
}

/* Index of the global covering @off, or -1.  The provenance bit number. */
static int oracle_ir_gidx(int64_t off)
{
    for (unsigned i = 0; i < oracle_nglobals; i++) {
        const OracleGlobal *g = &oracle_globals[i];

        if (off >= g->off && off < g->off + (int64_t)g->size) {
            return i < ORACLE_IR_PROV_WORDS * 64 ? (int)i : -1;
        }
    }
    return -1;
}

static void oracle_ir_prov_or(uint64_t *dst, const uint64_t *src)
{
    for (int i = 0; i < ORACLE_IR_PROV_WORDS; i++) {
        dst[i] |= src[i];
    }
}

static void oracle_ir_prov_set(uint64_t *p, int bit)
{
    if (bit >= 0) {
        p[bit / 64] |= 1ULL << (bit % 64);
    }
}

/* Render a provenance set as the register names it names. */
static void oracle_ir_prov_str(GString *out, const uint64_t *p)
{
    unsigned n = 0;

    for (unsigned i = 0; i < oracle_nglobals &&
         i < ORACLE_IR_PROV_WORDS * 64; i++) {
        if (!(p[i / 64] & (1ULL << (i % 64)))) {
            continue;
        }
        if (n == 8) {
            g_string_append(out, ",+");
            break;
        }
        g_string_append_printf(out, "%s%s", n ? "," : "",
                               oracle_globals[i].name);
        n++;
    }
    if (n == 0) {
        g_string_append_c(out, '-');
    }
}

/* Is @ts a guest register: a TCG global living at a fixed offset in env? */
static bool oracle_ir_global(const TCGTemp *ts, int64_t *off, uint32_t *size)
{
    if (ts->kind != TEMP_GLOBAL) {
        return false;
    }
    if (ts->mem_base != tcgv_ptr_temp(tcg_env)) {
        return false;
    }
    if (ts->mem_offset < 0 ||
        (size_t)ts->mem_offset + tcg_type_size(ts->base_type) >
        oracle_env_size) {
        return false;
    }
    *off = ts->mem_offset;
    *size = tcg_type_size(ts->base_type);
    return true;
}

/*
 * Direct env access: is @c a load or a store, and of how many bytes?  These
 * are how a target reaches the state it did not register as a global -- x86's
 * vector file and x87 stack, ARM's V registers, every FP status word.
 */
static bool oracle_ir_ldst(const TCGOp *op, bool *store, uint32_t *size)
{
    switch (op->opc) {
    case INDEX_op_ld8u_i32: case INDEX_op_ld8s_i32:
    case INDEX_op_ld8u_i64: case INDEX_op_ld8s_i64:
        *store = false; *size = 1; return true;
    case INDEX_op_ld16u_i32: case INDEX_op_ld16s_i32:
    case INDEX_op_ld16u_i64: case INDEX_op_ld16s_i64:
        *store = false; *size = 2; return true;
    case INDEX_op_ld_i32:
    case INDEX_op_ld32u_i64: case INDEX_op_ld32s_i64:
        *store = false; *size = 4; return true;
    case INDEX_op_ld_i64:
        *store = false; *size = 8; return true;
    case INDEX_op_ld_vec:
        *store = false; *size = tcg_type_size(TCGOP_TYPE(op)); return true;
    case INDEX_op_st8_i32: case INDEX_op_st8_i64:
        *store = true; *size = 1; return true;
    case INDEX_op_st16_i32: case INDEX_op_st16_i64:
        *store = true; *size = 2; return true;
    case INDEX_op_st_i32: case INDEX_op_st32_i64:
        *store = true; *size = 4; return true;
    case INDEX_op_st_i64:
        *store = true; *size = 8; return true;
    case INDEX_op_st_vec:
        *store = true; *size = tcg_type_size(TCGOP_TYPE(op)); return true;
    default:
        return false;
    }
}

/*
 * A call the walk cannot see inside is still worth a line: the helper's name,
 * the flags TCG believes about it, and how many arguments crossed.
 */
static bool oracle_ir_own_probe(const TCGHelperInfo *info)
{
    return info == &oracle_info_boundary || info == &oracle_info_boundary_rw ||
           info == &oracle_info_pre || info == &oracle_info_post;
}

/*
 * Report one access.  @buf gets the full record; @set gets a reduced form
 * naming only the direction and the bytes, which is what the retranslation
 * check compares -- an op that moved without the access moving is not a
 * change in the instruction's set.  A killed value is not an access and is
 * deliberately absent from @set.
 */
static void oracle_ir_arg(GString *buf, GString *set, uint64_t pc, char rw,
                          TCGTemp *ts, const char *opname, unsigned argno,
                          const uint64_t *prov)
{
    int64_t off, base;
    uint32_t size;
    const char *name;

    if (!oracle_ir_global(ts, &off, &size)) {
        return;
    }
    name = oracle_ir_name_off(off, size, &base);
    g_string_append_printf(buf, "D 0x%" PRIx64 " %c reg=%s off=%" PRId64
                           " size=%u via=arg op=%s argno=%u",
                           pc, rw, name ? name : "?", off, size, opname, argno);
    if (rw == 'w' && prov != NULL) {
        g_string_append(buf, " from=");
        oracle_ir_prov_str(buf, prov);
    }
    g_string_append_c(buf, '\n');
    if (rw != 'k') {
        g_string_append_printf(set, "%c%" PRId64 ".%u;", rw, off, size);
    }
}

/*
 * Commit one instruction's derived set.
 *
 * One pc has one instruction, so it has one read/write set, and the second
 * translation of a pc must produce the same one.  That is not free: the x86
 * translator elides a store to cc_op when the preceding instruction already
 * left it right, so the raw op stream for one pc genuinely depends on its
 * neighbour.  Reporting a pc once and checking every later translation
 * against it is what turns that from an unnoticed inconsistency into a
 * measurement -- and, once the lazy-flag fields are mapped onto the
 * architectural register they stand for, into a demonstration that the
 * mapped set does not depend on context even though the ops do.
 */
static void oracle_ir_commit(uint64_t pc, GString *buf, guint hset)
{
    /*
     * Two hashes, because there are two questions.  hraw covers everything
     * reported, including the ops that named each access and the ones that
     * killed a value; hset covers only the reads and writes.  A pc whose raw
     * stream moves but whose set does not is the expected case on x86 and
     * exactly what the lazy-flag mapping is there to absorb; a pc whose set
     * moves is a problem, and the two must not be reported as one thing.
     */
    guint hraw = g_str_hash(buf->str);
    uint64_t key = pc;
    gpointer old;

    qemu_mutex_lock(&oracle_lock);
    if (oracle_ir_seen == NULL) {
        oracle_ir_seen = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                               g_free, NULL);
    }
    if (g_hash_table_lookup_extended(oracle_ir_seen, &key, NULL, &old)) {
        guint prev_raw = GPOINTER_TO_UINT(old) >> 16;
        guint prev_set = GPOINTER_TO_UINT(old) & 0xffff;

        if (prev_raw != (hraw & 0xffff) || prev_set != (hset & 0xffff)) {
            bool set_changed = prev_set != (hset & 0xffff);

            oracle_ir_nchurned++;
            if (set_changed) {
                oracle_ir_ndiverged++;
            }
            g_hash_table_insert(oracle_ir_seen, g_memdup2(&key, 8),
                                GUINT_TO_POINTER(((hraw & 0xffff) << 16) |
                                                 (hset & 0xffff)));
            if (oracle_budget()) {
                fprintf(oracle_out, "Z 0x%" PRIx64 " ir-retranslated "
                        "set_changed=%d oldraw=0x%x newraw=0x%x oldset=0x%x "
                        "newset=0x%x\n", pc, set_changed, prev_raw,
                        hraw & 0xffff, prev_set, hset & 0xffff);
                fputs(buf->str, oracle_out);
            }
        }
    } else {
        g_hash_table_insert(oracle_ir_seen, g_memdup2(&key, 8),
                            GUINT_TO_POINTER(((hraw & 0xffff) << 16) |
                                             (hset & 0xffff)));
        oracle_ir_ninsn_reported++;
        if (oracle_budget()) {
            fputs(buf->str, oracle_out);
        }
    }
    qemu_mutex_unlock(&oracle_lock);
}

/*
 * Walk one instruction's ops.  @first is the op after its insn_start, @end is
 * the op that terminates it (the next insn_start, or NULL at the end of the
 * TB).
 */
static void oracle_ir_insn(GString *buf, GString *set, uint64_t pc,
                           TCGOp *first, TCGOp *end)
{
    unsigned nops = 0, ncalls = 0, nopaque = 0;
    uint64_t prov[ORACLE_IR_PROV_WORDS];

    g_string_truncate(buf, 0);
    g_string_truncate(set, 0);

    for (TCGOp *op = first; op != end; op = QTAILQ_NEXT(op, link)) {
        const TCGOpDef *def = &tcg_op_defs[op->opc];
        const char *opname = def->name;
        unsigned nb_oargs, nb_iargs;
        bool store;
        uint32_t size;

        if (op->opc == INDEX_op_call) {
            const TCGHelperInfo *info = tcg_call_info(op);

            if (oracle_ir_own_probe(info)) {
                continue;
            }
            nb_oargs = TCGOP_CALLO(op);
            nb_iargs = TCGOP_CALLI(op);
            nops++;
            ncalls++;

            /*
             * A helper's outputs derive from everything handed to it, and
             * from whatever it read out of env on its own.  The union of the
             * arguments is the most that can be said from here; the interior
             * probes are what narrow it.
             */
            memset(prov, 0, sizeof(prov));
            for (unsigned i = 0; i < nb_iargs; i++) {
                TCGTemp *its = arg_temp(op->args[nb_oargs + i]);
                int64_t ioff;
                uint32_t isz;

                oracle_ir_prov_or(prov,
                                  oracle_ir_prov[its - tcg_ctx->temps]);
                if (oracle_ir_global(its, &ioff, &isz)) {
                    oracle_ir_prov_set(prov, oracle_ir_gidx(ioff));
                }
            }
            for (unsigned i = 0; i < nb_oargs; i++) {
                TCGTemp *ots = arg_temp(op->args[i]);

                oracle_ir_arg(buf, set, pc, 'w', ots, "call", i, prov);
                oracle_ir_prov_or(oracle_ir_prov[ots - tcg_ctx->temps], prov);
            }
            for (unsigned i = 0; i < nb_iargs; i++) {
                TCGArg a = op->args[nb_oargs + i];
                TCGTemp *ts = arg_temp(a);
                int64_t eo;

                oracle_ir_arg(buf, set, pc, 'r', ts, "call", i, NULL);
                /*
                 * A pointer into env: the argument does not say whether the
                 * helper reads or writes through it, so it is reported as a
                 * reference and left for the interior probes to split.  This
                 * is how a vector register reaches a gvec helper.
                 *
                 * tcg_env itself does not count.  It is the first argument of
                 * nearly every helper there is, and reporting it as a
                 * reference to whatever register happens to sit at offset
                 * zero would put a register on almost every helper call --
                 * a number that would look plausible and mean nothing.
                 */
                eo = ts == tcgv_ptr_temp(tcg_env)
                     ? ORACLE_IR_NOT_ENV
                     : oracle_ir_envoff[ts - tcg_ctx->temps];
                if (eo != ORACLE_IR_NOT_ENV && eo >= 0 &&
                    (uint64_t)eo < oracle_env_size) {
                    int64_t base;
                    const char *name = oracle_ir_name_off(eo, 1, &base);

                    g_string_append_printf(buf,
                            "D 0x%" PRIx64 " p reg=%s off=%" PRId64
                            " size=0 via=envptr op=call helper=%s argno=%u\n",
                            pc, name ? name : "?", eo,
                            info->name ? info->name : "?", i);
                    g_string_append_printf(set, "p%" PRId64 ";", eo);
                }
            }
            g_string_append_printf(buf,
                    "C 0x%" PRIx64 " helper=%s flags=0x%x callo=%u calli=%u\n",
                    pc, info->name ? info->name : "?", info->flags,
                    nb_oargs, nb_iargs);
            g_string_append_printf(set, "h%s;", info->name ? info->name : "?");
            nopaque++;
            continue;
        }

        if (op->opc == INDEX_op_insn_start) {
            continue;
        }

        nb_oargs = def->nb_oargs;
        nb_iargs = def->nb_iargs;
        nops++;

        /* Direct env access by base + constant offset. */
        if (oracle_ir_ldst(op, &store, &size)) {
            TCGTemp *bts = arg_temp(op->args[1]);
            int64_t bo = oracle_ir_envoff[bts - tcg_ctx->temps];
            int64_t off = (int64_t)op->args[2];

            if (bo != ORACLE_IR_NOT_ENV) {
                int64_t eo = bo + off;

                if (eo >= 0 && (uint64_t)eo + size <= oracle_env_size) {
                    int64_t base;
                    const char *name = oracle_ir_name_off(eo, size, &base);

                    g_string_append_printf(buf,
                            "D 0x%" PRIx64 " %c reg=%s off=%" PRId64
                            " size=%u via=%s op=%s argno=0",
                            pc, store ? 'w' : 'r', name ? name : "?", eo,
                            size, store ? "st" : "ld", opname);
                    if (store) {
                        TCGTemp *vts = arg_temp(op->args[0]);

                        g_string_append(buf, " from=");
                        oracle_ir_prov_str(buf,
                                oracle_ir_prov[vts - tcg_ctx->temps]);
                    } else {
                        TCGTemp *dts = arg_temp(op->args[0]);

                        memset(oracle_ir_prov[dts - tcg_ctx->temps], 0,
                               sizeof(prov));
                        oracle_ir_prov_set(
                                oracle_ir_prov[dts - tcg_ctx->temps],
                                oracle_ir_gidx(eo));
                    }
                    g_string_append_c(buf, '\n');
                    g_string_append_printf(set, "%c%" PRId64 ".%u;",
                                           store ? 'w' : 'r', eo, size);
                }
            }
            /* The value moved and the base pointer are still plain args. */
        }

        /* Guest memory, for completeness: the tracer models this already. */
        if (op->opc == INDEX_op_qemu_ld_i32 || op->opc == INDEX_op_qemu_ld_i64 ||
            op->opc == INDEX_op_qemu_ld_i128) {
            g_string_append_printf(buf, "D 0x%" PRIx64 " r mem op=%s\n",
                                   pc, opname);
            g_string_append(set, "mr;");
        } else if (op->opc == INDEX_op_qemu_st_i32 ||
                   op->opc == INDEX_op_qemu_st_i64 ||
                   op->opc == INDEX_op_qemu_st8_i32 ||
                   op->opc == INDEX_op_qemu_st_i128) {
            g_string_append_printf(buf, "D 0x%" PRIx64 " w mem op=%s\n",
                                   pc, opname);
            g_string_append(set, "mw;");
        }

        /*
         * discard names its argument as an output but is not a write: it is
         * TCG being told the temp's value is dead, which on x86 is how the
         * flag fields an instruction does not define are retired.  Counting
         * it as a write would put cc_src2 in the write set of every add.  It
         * is still worth a line of its own -- a value that has been killed is
         * a fact a consumer can use -- so it is reported as 'k'.
         */
        if (op->opc == INDEX_op_discard) {
            TCGTemp *dts = arg_temp(op->args[0]);

            oracle_ir_arg(buf, set, pc, 'k', dts, opname, 0, NULL);
            oracle_ir_envoff[dts - tcg_ctx->temps] = ORACLE_IR_NOT_ENV;
            continue;
        }

        memset(prov, 0, sizeof(prov));
        for (unsigned i = 0; i < nb_iargs; i++) {
            TCGTemp *its = arg_temp(op->args[nb_oargs + i]);
            int64_t ioff;
            uint32_t isz;

            oracle_ir_prov_or(prov, oracle_ir_prov[its - tcg_ctx->temps]);
            if (oracle_ir_global(its, &ioff, &isz)) {
                oracle_ir_prov_set(prov, oracle_ir_gidx(ioff));
            }
        }
        for (unsigned i = 0; i < nb_oargs; i++) {
            TCGTemp *ots = arg_temp(op->args[i]);

            oracle_ir_arg(buf, set, pc, 'w', ots, opname, i, prov);
            memcpy(oracle_ir_prov[ots - tcg_ctx->temps], prov, sizeof(prov));
        }
        for (unsigned i = 0; i < nb_iargs; i++) {
            oracle_ir_arg(buf, set, pc, 'r', arg_temp(op->args[nb_oargs + i]),
                          opname, i, NULL);
        }

        /*
         * Track temps whose value is tcg_env plus a constant.  Only mov and
         * add-of-a-constant can produce one; anything else that writes a
         * tracked temp stops tracking it, so the map never outlives the fact.
         */
        if (nb_oargs == 1) {
            TCGTemp *dts = arg_temp(op->args[0]);
            size_t di = dts - tcg_ctx->temps;
            int64_t v = ORACLE_IR_NOT_ENV;

            if (op->opc == INDEX_op_mov_i64 || op->opc == INDEX_op_mov_i32) {
                v = oracle_ir_envoff[arg_temp(op->args[1]) - tcg_ctx->temps];
            } else if (op->opc == INDEX_op_add_i64 ||
                       op->opc == INDEX_op_add_i32) {
                TCGTemp *a = arg_temp(op->args[1]);
                TCGTemp *b = arg_temp(op->args[2]);
                int64_t ao = oracle_ir_envoff[a - tcg_ctx->temps];
                int64_t bo = oracle_ir_envoff[b - tcg_ctx->temps];

                if (ao != ORACLE_IR_NOT_ENV && b->kind == TEMP_CONST) {
                    v = ao + b->val;
                } else if (bo != ORACLE_IR_NOT_ENV && a->kind == TEMP_CONST) {
                    v = bo + a->val;
                }
            }
            if (di < TCG_MAX_TEMPS) {
                oracle_ir_envoff[di] = v;
            }
        }
    }

    g_string_append_printf(buf, "A 0x%" PRIx64 " ops=%u calls=%u opaque=%u\n",
                           pc, nops, ncalls, nopaque);
    oracle_ir_commit(pc, buf, g_str_hash(set->str));
}

/*
 * Walk the whole TB.  Called at the top of tcg_gen_code(), so the ops are
 * exactly what the target's translator emitted.
 */
void oracle_ir_translate(const void *tbp)
{
    const TranslationBlock *tb = tbp;
    TCGContext *s = tcg_ctx;
    TCGOp *op, *insn_first = NULL;
    unsigned idx = 0, nstart = 0, resync = 0, unmatched = 0;
    uint64_t pc = 0;
    bool want = false;
    GString *buf, *set;

    if (!oracle_on || !oracle_do_ir || tb == NULL ||
        !(tb->cflags & CF_ORACLE)) {
        return;
    }

    for (size_t i = 0; i < TCG_MAX_TEMPS; i++) {
        oracle_ir_envoff[i] = ORACLE_IR_NOT_ENV;
    }
    memset(oracle_ir_prov, 0, sizeof(oracle_ir_prov));
    oracle_ir_envoff[tcgv_ptr_temp(tcg_env) - s->temps] = 0;

    buf = g_string_new(NULL);
    set = g_string_new(NULL);

    QTAILQ_FOREACH(op, &s->ops, link) {
        uint64_t opc_pc;

        if (op->opc != INDEX_op_insn_start) {
            continue;
        }
        if (want && insn_first != NULL) {
            oracle_ir_insn(buf, set, pc, insn_first, op);
        }
        want = false;

        /*
         * Match this insn_start to the pc the boundary hook recorded for it.
         *
         * Position alone is not enough to go on.  x86 rolls an instruction
         * back when decoding it runs off the end of a page --
         * i386_tr_translate_insn()'s tcg_remove_ops_after(prev_insn_end) --
         * which deletes the instruction's ops *including its insn_start*, so
         * the op stream can hold fewer instructions than the hook saw.  The
         * insn_start op carries the pc itself, so the two can be checked
         * against each other rather than assumed to line up, and a stream
         * that has lost an instruction is resynchronised instead of
         * silently shifting every attribution after it.
         */
        opc_pc = tcg_get_insn_start_param(op, 0);
        while (idx < oracle_ir_ninsns && idx < ORACLE_IR_MAX_INSNS &&
               oracle_ir_insns[idx].pc != opc_pc) {
            idx++;
            resync++;
        }
        if (idx < oracle_ir_ninsns && idx < ORACLE_IR_MAX_INSNS) {
            pc = oracle_ir_insns[idx].pc;
            want = oracle_ir_insns[idx].in_window;
            idx++;
        } else {
            unmatched++;
        }
        nstart++;
        insn_first = QTAILQ_NEXT(op, link);
    }
    if (want && insn_first != NULL) {
        oracle_ir_insn(buf, set, pc, insn_first, NULL);
    }

    if (unmatched || resync) {
        qemu_mutex_lock(&oracle_lock);
        if (oracle_budget()) {
            fprintf(oracle_out, "V 0x%" PRIx64 " ir insn_start=%u "
                    "boundaries=%u resync=%u unmatched=%u\n",
                    tb->pc, nstart, oracle_ir_ninsns, resync, unmatched);
        }
        qemu_mutex_unlock(&oracle_lock);
    }
    g_string_free(buf, TRUE);
    g_string_free(set, TRUE);
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

bool oracle_active(void)
{
    return oracle_on;
}

/*
 * QEMU_ORACLE_POISON is a comma-separated list of
 *
 *     <off>:<size>:<mode>[@<pc>]         mode is z, r, or c<hex>
 *
 * plus one shorthand, "globals", which expands to a random poison over every
 * register the TCG globals table names.  That is the strongest form -- after
 * it, any register the instruction leaves alone still holds its poison, so
 * what changed is the write set outright, with no dependence on the values
 * involved -- and also the most destructive, since an instruction reading a
 * poisoned source computes from garbage.  Pair it with @pc and _ONCE.
 */
static void oracle_parse_poison(const char *spec)
{
    char **items;
    unsigned cap;

    if (spec == NULL || *spec == '\0') {
        return;
    }

    items = g_strsplit(spec, ",", 0);
    cap = g_strv_length(items) + oracle_nglobals;
    oracle_poisons = g_new0(OraclePoisonSpec, cap);

    for (char **it = items; *it; it++) {
        char *item = g_strstrip(*it);
        OraclePoisonSpec p = { .mode = 'r' };
        char *at, *f1, *f2, *f3;
        char **fields;

        if (*item == '\0') {
            continue;
        }
        at = strchr(item, '@');
        if (at) {
            *at = '\0';
            p.pc = strtoull(at + 1, NULL, 0);
            p.has_pc = true;
        }

        if (oracle_npoisons >= cap) {
            fprintf(stderr, "oracle: too many poison specs, dropping '%s'\n",
                    item);
            continue;
        }
        if (!strcmp(item, "globals")) {
            for (unsigned i = 0; i < oracle_nglobals &&
                                 oracle_npoisons < cap; i++) {
                oracle_poisons[oracle_npoisons] = p;
                oracle_poisons[oracle_npoisons].off = oracle_globals[i].off;
                oracle_poisons[oracle_npoisons].size = oracle_globals[i].size;
                oracle_npoisons++;
            }
            continue;
        }

        fields = g_strsplit(item, ":", 3);
        f1 = fields[0];
        f2 = f1 ? fields[1] : NULL;
        f3 = f2 ? fields[2] : NULL;
        if (f1 == NULL || f2 == NULL) {
            fprintf(stderr, "oracle: bad poison spec '%s'\n", item);
            g_strfreev(fields);
            continue;
        }
        p.off = strtoull(f1, NULL, 0);
        p.size = strtoul(f2, NULL, 0);
        if (f3 && *f3) {
            p.mode = *f3;
            if (p.mode == 'c') {
                p.cval = strtoull(f3 + 1, NULL, 16);
            }
        }
        g_strfreev(fields);

        if (p.size == 0 || p.off + p.size > oracle_env_size) {
            fprintf(stderr, "oracle: poison %zu+%u is outside env\n",
                    p.off, p.size);
            continue;
        }
        oracle_poisons[oracle_npoisons++] = p;
    }
    g_strfreev(items);

    for (unsigned i = 0; i < oracle_npoisons; i++) {
        fprintf(oracle_out, "Q poison off=%zu size=%u mode=%c pc=0x%" PRIx64
                "%s\n", oracle_poisons[i].off, oracle_poisons[i].size,
                oracle_poisons[i].mode, oracle_poisons[i].pc,
                oracle_poisons[i].has_pc ? "" : " (any)");
    }
}

static void oracle_close(void)
{
    if (oracle_out) {
        fprintf(oracle_out, "E lines=%" PRIu64 " ir_pcs=%" PRIu64
                " ir_diverged=%" PRIu64 " ir_churn=%" PRIu64 "%s\n", oracle_lines,
                oracle_ir_ninsn_reported, oracle_ir_ndiverged,
                oracle_ir_nchurned,
                oracle_lines >= oracle_max_lines ? " truncated=1" : "");
        fflush(oracle_out);
    }
}

void oracle_init(size_t env_size, const char *target_name)
{
    const char *path = getenv("QEMU_ORACLE");
    const char *s;
    char *expanded = NULL;

    if (oracle_on || path == NULL || *path == '\0') {
        return;
    }

    if (strstr(path, "%p")) {
        GString *g = g_string_new(NULL);
        for (const char *p = path; *p; p++) {
            if (p[0] == '%' && p[1] == 'p') {
                g_string_append_printf(g, "%d", (int)getpid());
                p++;
            } else {
                g_string_append_c(g, *p);
            }
        }
        expanded = g_string_free(g, FALSE);
        path = expanded;
    }

    oracle_out = fopen(path, "w");
    if (oracle_out == NULL) {
        fprintf(stderr, "oracle: cannot open %s: %s\n", path, strerror(errno));
        g_free(expanded);
        return;
    }
    g_free(expanded);
    /*
     * linux-user services the guest's exit syscall with _exit(), so atexit
     * handlers never run and a full stdio buffer would be lost.  Line
     * buffering costs throughput we do not care about here and guarantees
     * the report survives however the guest chooses to die.
     */
    setvbuf(oracle_out, NULL, _IOLBF, 0);

    s = getenv("QEMU_ORACLE_PC_LO");
    if (s) {
        oracle_pc_lo = strtoull(s, NULL, 0);
    }
    s = getenv("QEMU_ORACLE_PC_HI");
    if (s) {
        oracle_pc_hi = strtoull(s, NULL, 0);
    }
    s = getenv("QEMU_ORACLE_MAX");
    if (s) {
        oracle_max_lines = strtoull(s, NULL, 0);
    }
    s = getenv("QEMU_ORACLE_HELPERS");
    if (s) {
        oracle_do_helpers = atoi(s) != 0;
    }
    s = getenv("QEMU_ORACLE_INSN_MARKS");
    if (s) {
        oracle_do_insn_marks = atoi(s) != 0;
    }
    s = getenv("QEMU_ORACLE_IR");
    if (s) {
        oracle_do_ir = atoi(s) != 0;
    }
#ifdef ORACLE_HELPER_READS
    s = getenv("QEMU_ORACLE_HELPER_READS");
    if (s) {
        oracle_hr_on = atoi(s) != 0;
    }
#endif

    /* A TB spans at most two guest pages, so two pages is an exact bound. */
    oracle_tb_slack = 2 * qemu_target_page_size();
    s = getenv("QEMU_ORACLE_TB_SLACK");
    if (s) {
        oracle_tb_slack = strtoull(s, NULL, 0);
    }

    s = getenv("QEMU_ORACLE_POISON_NTH");
    if (s) {
        oracle_poison_nth = strtoull(s, NULL, 0);
    }
    s = getenv("QEMU_ORACLE_POISON_ONCE");
    if (s) {
        oracle_poison_once = atoi(s) != 0;
    }
    s = getenv("QEMU_ORACLE_POISON_SEED");
    if (s) {
        oracle_poison_seed = strtoull(s, NULL, 0);
    }

    qemu_mutex_init(&oracle_lock);
    oracle_env_size = env_size;
    oracle_env_words = (env_size + 7) / 8;
    oracle_chg_longs = BITS_TO_LONGS(oracle_env_words);

    fprintf(oracle_out, "# qemu behavioural oracle\n");
    fprintf(oracle_out, "T target=%s env_size=%zu nb_tcg_globals=%d\n",
            target_name, env_size, tcg_ctx->nb_globals);
    oracle_capture_globals();
    oracle_parse_poison(getenv("QEMU_ORACLE_POISON"));
    fprintf(oracle_out, "T mapped_globals=%u pc_lo=0x%" PRIx64
            " pc_hi=0x%" PRIx64 " helpers=%d tb_slack=%" PRIu64
            " poisons=%u seed=0x%" PRIx64 "\n",
            oracle_nglobals, oracle_pc_lo, oracle_pc_hi, oracle_do_helpers,
            oracle_tb_slack, oracle_npoisons, oracle_poison_seed);
    fflush(oracle_out);

    atexit(oracle_close);
    oracle_on = true;
}
