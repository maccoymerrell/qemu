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
        fprintf(oracle_out, "E lines=%" PRIu64 "%s\n", oracle_lines,
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
