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
 *   QEMU_ORACLE_PC_LO/_PC_HI    only diff instructions in this pc range
 *   QEMU_ORACLE_MAX=<n>         stop after n records
 *   QEMU_ORACLE_HELPERS=0       skip the per-helper probes
 *   QEMU_ORACLE_INSN_MARKS=0    skip the 'I' lines
 *
 * The report
 * ----------
 *   T ...                       target, sizeof(CPUArchState), counts
 *   G <off> <size> <name>       one per TCG global: the offset -> register map
 *   S ...                       a global the map could not use, and why
 *   I <pc>                      an instruction is about to execute
 *   W <pc> reg=<name> ...       <pc> changed a named register
 *   W <pc> raw off=<n> ...      <pc> changed bytes no global names
 *   H <pc> helper=<h> ...       the change happened inside helper <h>
 *       ... via=retval          ... but it is the helper's return value,
 *                               which the caller bound to that global
 *   X <pc> helper=<h> NO_WG_VIOLATION ...
 *                               a helper declared not to write globals wrote
 *                               one anyway, and it is not its return value
 *   E lines=<n>                 end of report
 *
 * What a differ cannot see
 * ------------------------
 * A write whose value equals what was already there leaves no trace.  That
 * hides the zero written by a successful RISC-V sc.d, the high half of a
 * MIPS mult whose product fits in 32 bits, and every set of an already-set
 * sticky FP exception flag.  tests/oracle/probe_riscv64_poisoned.S shows the
 * mitigation: pre-load the destinations with a value the instruction will not
 * produce.  Doing that in general -- randomising the machine state before
 * each instruction -- is interpretation-layer work.
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
#include "exec/oracle.h"

#define ORACLE_HELPER_DEPTH 8
#define ORACLE_RAW_DUMP_MAX 64

typedef struct OracleGlobal {
    intptr_t off;
    uint32_t size;
    const char *name;
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

/* Per-guest-thread execution state. */
typedef struct OracleThread {
    uint8_t *snap;                                  /* env at last boundary */
    uint8_t *hsnap[ORACLE_HELPER_DEPTH];            /* env at helper entry */
    const TCGHelperInfo *hinfo[ORACLE_HELPER_DEPTH];
    int hdepth;
    uint64_t cur_pc;
    bool snapped;
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
 * Report every difference between two env images.  Registers named by the
 * TCG globals table are reported by name; everything else is reported as a
 * raw offset run, which is exactly the state Phase 2 has to interpret.
 *
 * Returns the number of differing byte ranges reported.
 */
static unsigned oracle_diff(char tag, uint64_t pc, const TCGHelperInfo *info,
                            int64_t retoff,
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
        oracle_tls = t;
    }
    return t;
}

void oracle_insn_boundary(void *envp, uint64_t pc);
void oracle_insn_boundary(void *envp, uint64_t pc)
{
    OracleThread *t = oracle_thread();
    const uint8_t *env = envp;
    bool want = pc >= oracle_pc_lo && pc <= oracle_pc_hi;

    /*
     * Any helper frame still open here belongs to an instruction that left
     * via longjmp (an exception or a syscall).  Drop it; the boundary diff
     * still covers the net effect.
     */
    t->hdepth = 0;

    if (t->snapped) {
        qemu_mutex_lock(&oracle_lock);
        oracle_diff('W', t->cur_pc, NULL, -1, t->snap, env);
        qemu_mutex_unlock(&oracle_lock);
    }

    if (want) {
        if (oracle_do_insn_marks) {
            qemu_mutex_lock(&oracle_lock);
            if (oracle_budget()) {
                fprintf(oracle_out, "I 0x%" PRIx64 "\n", pc);
            }
            qemu_mutex_unlock(&oracle_lock);
        }
        memcpy(t->snap, env, oracle_env_size);
    }
    t->snapped = want;
    t->cur_pc = pc;
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
    qemu_mutex_lock(&oracle_lock);
    oracle_diff('H', t->cur_pc, infop, retoff, t->hsnap[d], envp);
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

bool oracle_gen_helper_probe_wanted(const TCGHelperInfo *info)
{
    if (!oracle_on || !oracle_do_helpers || oracle_in_gen) {
        return false;
    }
    if (info == &oracle_info_boundary || info == &oracle_info_pre ||
        info == &oracle_info_post) {
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

void oracle_gen_insn_boundary(uint64_t pc)
{
    if (!oracle_on) {
        return;
    }
    oracle_in_gen = true;
    tcg_gen_call2(oracle_info_boundary.func, &oracle_info_boundary, NULL,
                  tcgv_ptr_temp(tcg_env),
                  tcgv_i64_temp(tcg_constant_i64(pc)));
    oracle_in_gen = false;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

bool oracle_active(void)
{
    return oracle_on;
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

    qemu_mutex_init(&oracle_lock);
    oracle_env_size = env_size;

    fprintf(oracle_out, "# qemu behavioural oracle, phase 1\n");
    fprintf(oracle_out, "T target=%s env_size=%zu nb_tcg_globals=%d\n",
            target_name, env_size, tcg_ctx->nb_globals);
    oracle_capture_globals();
    fprintf(oracle_out, "T mapped_globals=%u pc_lo=0x%" PRIx64
            " pc_hi=0x%" PRIx64 " helpers=%d\n",
            oracle_nglobals, oracle_pc_lo, oracle_pc_hi, oracle_do_helpers);
    fflush(oracle_out);

    atexit(oracle_close);
    oracle_on = true;
}
