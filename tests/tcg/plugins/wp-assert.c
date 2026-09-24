/*
 * wp-assert: QEMU-side tests of the wrong-path (speculative) engine.
 *
 * The plugin drives wrong-path excursions through the public plugin API
 * (qemu_plugin_cpu_state_save/restore, qemu_plugin_spec_mode_begin/end,
 * qemu_plugin_set_pc, qemu_plugin_exec_tb, qemu_plugin_spec_clear_exception)
 * at a marker instruction in the companion guest programs
 * tests/tcg/{x86_64,aarch64,riscv64,mipsel}/wp-victim.c, and asserts the
 * engine's contract:
 *
 *   T1 store containment   wrong-path stores never reach guest memory
 *   T2 state restore       the register file is identical after an excursion
 *   T3 fault containment   wrong-path faults end the excursion cleanly and
 *                          never reach the guest
 *   T4 budget              every exec_tb runs exactly one block; an excursion
 *                          into an endless loop ends at the plugin's budget
 *   T5 repeatability       one excursion run twice from one state is
 *                          bit-identical (the runner also compares guest
 *                          output with and without the plugin)
 *
 * On any violation the plugin prints "[wp-assert] FAIL <test>: ..." and
 * aborts.  Every assertion has a control, selected with control=<name>,
 * that perturbs the drive so the assertion MUST fail; a control run that
 * does not fail is itself a test failure (the runner checks that).
 *
 * Arguments:
 *   mode=on|off       off: load, recognise markers, drive nothing
 *   budget=N          T4 block budget (default 1000)
 *   control=NAME      T1 T2 T2G T3 T3N T3UD T3DIV0 T3PRIV T3INT3
 *                     T3SYSCALL T3SYSCALLN T4 T4C T5 T5X (see WP_TESTS.md)
 *   require=on        fail at exit unless every test ran (without it, a
 *                     run that never reaches a marker is silently inert,
 *                     so the generic check-tcg plugin loop may load it)
 *   verbose=on        print every excursion's statistics
 *   keepgoing=on      a failed check is recorded and the run continues,
 *                     so every test gets a verdict; the run still aborts
 *                     at exit
 *   dumpregs=on       list the registers the target exposes, then run
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* Keep in sync with tests/tcg/<isa>/wp-victim.c (all four) */
enum {
    T1_STORE = 1, T1_RO, T2_REGS, T3_FETCH_UNMAPPED, T3_STRADDLE, T3_UD,
    T3_DIV0, T3_PRIV, T3_INT3, T3_LOAD_UNMAPPED, T3_SYSCALL, T4_LOOP,
    T4_REP, T5_REPEAT, T_LAST
};

static const char *const test_names[T_LAST] = {
    [T1_STORE] = "T1_STORE", [T1_RO] = "T1_RO", [T2_REGS] = "T2_REGS",
    [T3_FETCH_UNMAPPED] = "T3_FETCH_UNMAPPED", [T3_STRADDLE] = "T3_STRADDLE",
    [T3_UD] = "T3_UD", [T3_DIV0] = "T3_DIV0", [T3_PRIV] = "T3_PRIV",
    [T3_INT3] = "T3_INT3", [T3_LOAD_UNMAPPED] = "T3_LOAD_UNMAPPED",
    [T3_SYSCALL] = "T3_SYSCALL", [T4_LOOP] = "T4_LOOP", [T4_REP] = "T4_REP",
    [T5_REPEAT] = "T5_REPEAT",
};

/*
 * Per-ISA facts.  The marker is an instruction the guest trigger executes
 * once per test and no other code contains; the plugin matches its bytes at
 * translation time.  The argument registers carry (test, target, buf, len).
 */
typedef struct {
    const char *target;               /* info->target_name */
    uint8_t marker[10];
    size_t marker_len;
    const char *arg[4];
    const char *const *t2_subjects;   /* registers wp_clobber must change */
    const char *t2g_reg;              /* control T2G perturbs this one */
    /*
     * Registers the plugin never samples (not read, not compared, not
     * fingerprinted), each for a reason stated at its table below: its
     * value moves with no guest instruction executing, or reading it has
     * a side effect on the guest.  NULL-terminated.
     */
    const char *const *volatile_regs;
    bool div0_traps;                  /* integer divide by zero raises */
    const char *rep_skip;             /* T4_REP not applicable: why */
    bool rep_is_mops;                 /* T4_REP is SETP/SETM/SETE */
} Isa;

static const char *const x86_t2[] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8",
    "r11", "r15", "rip", "eflags", "xmm0", "xmm15", "mxcsr", "fctrl", NULL
};
static const char *const a64_t2[] = {
    "x0", "x1", "x2", "x3", "x4", "x8", "x16", "x17", "x18", "x19",
    "x28", "x29", "x30", "sp", "pc", "cpsr", "z0", "z31", "fpcr", NULL
};
static const char *const rv_t2[] = {
    "ra", "sp", "gp", "tp", "t0", "fp", "s1", "a0", "a1", "a2", "a3",
    "a7", "s11", "t6", "pc", "ft0", "fs11", "ft11", "frm", NULL
};
static const char *const mips_t2[] = {
    "at", "v0", "a0", "a1", "a2", "a3", "t0", "s0", "s7", "t9", "k0",
    "k1", "gp", "sp", "s8", "ra", "lo", "hi", "pc", "f0", "f31", "fcr31",
    NULL
};
static const char *const no_volatile[] = { NULL };
/*
 * linux-user riscv: cycle, time and instret all return
 * cpu_get_host_ticks() (target/riscv/csr.c, the CONFIG_USER_ONLY
 * counters), so they advance with no guest instruction executing; and a
 * read of seed calls qemu_guest_getrandom(), consuming the guest's
 * entropy stream, so a snapshot that read it would itself perturb the
 * correct path.
 */
static const char *const rv_volatile[] = {
    "cycle", "time", "instret", "seed", NULL
};

static const Isa isas[] = {
    {
        .target = "x86_64",
        /* movabs $0x5750415353455254, %r11 */
        .marker = { 0x49, 0xbb, 0x54, 0x52, 0x45, 0x53, 0x53, 0x41, 0x50,
                    0x57 },
        .marker_len = 10,
        .arg = { "rdi", "rsi", "rdx", "rcx" },
        .t2_subjects = x86_t2, .t2g_reg = "r12",
        .volatile_regs = no_volatile,
        .div0_traps = true,
    },
    {
        .target = "aarch64",
        /* hint #0x7f: an unallocated hint, architecturally a NOP */
        .marker = { 0xff, 0x2f, 0x03, 0xd5 }, .marker_len = 4,
        .arg = { "x0", "x1", "x2", "x3" },
        .t2_subjects = a64_t2, .t2g_reg = "x19",
        .volatile_regs = no_volatile,
        .div0_traps = false,          /* udiv/sdiv by 0 yield 0 */
        .rep_is_mops = true,
    },
    {
        .target = "riscv64",
        /* slti x0, x0, 0x575: a HINT encoding (rd = x0), a NOP */
        .marker = { 0x13, 0x20, 0x50, 0x57 }, .marker_len = 4,
        .arg = { "a0", "a1", "a2", "a3" },
        .t2_subjects = rv_t2, .t2g_reg = "s1",
        .volatile_regs = rv_volatile,
        .div0_traps = false,          /* div by 0 yields all-ones */
        .rep_skip = "RISC-V has no repeat-string or bulk-memory "
                    "instruction (every store is one instruction)",
    },
    {
        .target = "mipsel",
        /* ori $zero, $zero, 0x5750: writes $zero, a NOP */
        .marker = { 0x50, 0x57, 0x00, 0x34 }, .marker_len = 4,
        .arg = { "a0", "a1", "a2", "a3" },
        .t2_subjects = mips_t2, .t2g_reg = "s0",
        .volatile_regs = no_volatile,
        .div0_traps = true,           /* via teq $divisor, $zero, 7 */
        .rep_skip = "MIPS32 has no repeat-string or bulk-memory "
                    "instruction (every store is one instruction)",
    },
};

static const Isa *isa;            /* NULL: unsupported target, inert */

#define WP_SHORT_BUDGET 64

static bool enabled = true;
static bool verbose;
static int t4_budget = 1000;
static const char *control = "";
static int tests_run[T_LAST];
static int checks_passed[T_LAST];
static int checks_failed[T_LAST];
static bool keep_going;
static bool dump_regs;
static bool dump_inside;          /* print T5's in-excursion registers */
static bool require_all;
static bool merge_calls;          /* control T4C */

/* ---------------------------------------------------------------- regs */

typedef struct {
    struct qemu_plugin_register *h;
    const char *name;
} Reg;

static GArray *regs;              /* Reg */

static Reg *reg_by_name(const char *name)
{
    for (guint i = 0; i < regs->len; i++) {
        Reg *r = &g_array_index(regs, Reg, i);
        if (strcmp(r->name, name) == 0) {
            return r;
        }
    }
    return NULL;
}

static uint64_t read_reg64(const char *name)
{
    Reg *r = reg_by_name(name);
    g_autoptr(GByteArray) b = g_byte_array_new();
    uint64_t v = 0;
    if (!r) {
        fprintf(stderr, "[wp-assert] FAIL setup: register %s not exposed\n",
                name);
        abort();
    }
    int n = qemu_plugin_read_register(r->h, b);
    memcpy(&v, b->data, MIN(n, 8));
    return v;
}

/* Add @delta to a register, keeping its width (4 or 8 bytes). */
static void perturb_reg(const char *name, uint64_t delta)
{
    Reg *r = reg_by_name(name);
    g_autoptr(GByteArray) b = g_byte_array_new();
    int n = qemu_plugin_read_register(r->h, b);
    uint64_t v = 0;
    memcpy(&v, b->data, MIN(n, 8));
    v += delta;
    g_byte_array_set_size(b, 0);
    g_byte_array_append(b, (uint8_t *)&v, MIN(n, 8));
    qemu_plugin_write_register(r->h, b);
}

static bool reg_is_volatile(const char *name)
{
    for (const char *const *v = isa->volatile_regs; *v; v++) {
        if (strcmp(*v, name) == 0) {
            return true;
        }
    }
    return false;
}

/*
 * Every register the gdbstub exposes, as one blob with a per-reg index.
 * The ISA's unsampled registers are recorded as unreadable (length 0).
 */
typedef struct {
    GByteArray *bytes;
    GArray *off;                  /* int, start of reg i; -1 if unreadable */
    GArray *len;
} RegSnap;

static RegSnap snap_regs(void)
{
    RegSnap s = { g_byte_array_new(), g_array_new(false, false, sizeof(int)),
                  g_array_new(false, false, sizeof(int)) };
    g_autoptr(GByteArray) b = g_byte_array_new();
    for (guint i = 0; i < regs->len; i++) {
        Reg *r = &g_array_index(regs, Reg, i);
        g_byte_array_set_size(b, 0);
        int n = reg_is_volatile(r->name) ? 0
                : qemu_plugin_read_register(r->h, b);
        int off = n > 0 ? (int)s.bytes->len : -1;
        if (n > 0) {
            g_byte_array_append(s.bytes, b->data, n);
        }
        g_array_append_val(s.off, off);
        g_array_append_val(s.len, n);
    }
    return s;
}

static void free_snap(RegSnap *s)
{
    g_byte_array_free(s->bytes, true);
    g_array_free(s->off, true);
    g_array_free(s->len, true);
}

static bool reg_differs(RegSnap *a, RegSnap *b, guint i)
{
    int la = g_array_index(a->len, int, i), lb = g_array_index(b->len, int, i);
    if (la != lb) {
        return true;
    }
    if (la <= 0) {
        return false;
    }
    return memcmp(a->bytes->data + g_array_index(a->off, int, i),
                  b->bytes->data + g_array_index(b->off, int, i), la) != 0;
}

/* Name of the first differing register, or NULL when identical. */
static const char *snap_diff(RegSnap *a, RegSnap *b)
{
    for (guint i = 0; i < regs->len; i++) {
        if (reg_is_volatile(g_array_index(regs, Reg, i).name)) {
            continue;
        }
        if (reg_differs(a, b, i)) {
            return g_array_index(regs, Reg, i).name;
        }
    }
    return NULL;
}

/* A register's value (low 8 bytes) from a snapshot. */
static uint64_t snap_u64(RegSnap *s, const char *name)
{
    for (guint i = 0; i < regs->len; i++) {
        if (strcmp(g_array_index(regs, Reg, i).name, name) == 0) {
            int n = g_array_index(s->len, int, i);
            uint64_t v = 0;
            if (n > 0) {
                memcpy(&v, s->bytes->data + g_array_index(s->off, int, i),
                       MIN(n, 8));
            }
            return v;
        }
    }
    fprintf(stderr, "[wp-assert] FAIL setup: register %s not exposed\n", name);
    abort();
}

static bool snap_reg_differs(RegSnap *a, RegSnap *b, const char *name)
{
    for (guint i = 0; i < regs->len; i++) {
        if (strcmp(g_array_index(regs, Reg, i).name, name) == 0) {
            return reg_differs(a, b, i);
        }
    }
    fprintf(stderr, "[wp-assert] FAIL setup: register %s not exposed\n", name);
    abort();
}

/* ------------------------------------------------------------- helpers */

static int cur_test;

/*
 * A failed assertion aborts at once, unless keepgoing=on: then it is
 * recorded, the remaining tests still run (so each gets its own verdict),
 * and the run aborts at exit instead.  FATAL always aborts: it guards
 * states the plugin cannot continue from.
 */
#define FATAL(...) do { \
        fprintf(stderr, "[wp-assert] FAIL %s: ", test_names[cur_test]); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
        fflush(stderr); \
        abort(); \
    } while (0)

#define FAIL(...) do { \
        fprintf(stderr, "[wp-assert] FAIL %s: ", test_names[cur_test]); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
        fflush(stderr); \
        if (!keep_going) { \
            abort(); \
        } \
        checks_failed[cur_test]++; \
    } while (0)

#define CHECK(cond, ...) do { \
        if (!(cond)) { \
            FAIL(__VA_ARGS__); \
        } else { \
            checks_passed[cur_test]++; \
        } \
    } while (0)

static bool control_is(const char *c)
{
    return strcmp(control, c) == 0;
}

static uint64_t fnv_add(uint64_t h, const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) {
        h = (h ^ b[i]) * 0x100000001b3ull;
    }
    return h;
}

#define FNV0 0xcbf29ce484222325ull

/* Checksum real guest memory (outside spec mode: no sandbox overlay). */
static uint64_t mem_sum(uint64_t addr, uint64_t len)
{
    g_autoptr(GByteArray) b = g_byte_array_new();
    if (!qemu_plugin_read_memory_vaddr(addr, b, len)) {
        FATAL("cannot read guest memory at 0x%" PRIx64, addr);
    }
    return fnv_add(FNV0, b->data, b->len);
}

static uint64_t mem_u64(uint64_t addr)
{
    g_autoptr(GByteArray) b = g_byte_array_new();
    uint64_t v = 0;
    if (!qemu_plugin_read_memory_vaddr(addr, b, 8)) {
        FATAL("cannot read guest memory at 0x%" PRIx64, addr);
    }
    memcpy(&v, b->data, 8);
    return v;
}

/* ----------------------------------------------------------- excursion */

typedef enum { END_BUDGET, END_FAULT, END_OVERFLOW } EndReason;
static const char *const end_names[] = { "BUDGET", "FAULT", "OVERFLOW" };

typedef struct {
    /* inputs */
    uint64_t target, buf, len;
    int budget;
    bool spec, restore, clear;
    /* observed through the ordinary callbacks while recording */
    uint64_t calls, calls_ok, tbs, insns, loads, stores;
    uint64_t stores_in_buf, faulted_memops, tbs_not_spec;
    uint64_t max_tbs_per_call, max_insn_excess, max_stores_per_call;
    uint64_t store_bytes, max_store_bytes_per_call;
    uint64_t fp;                  /* fingerprint of everything observed */
    EndReason end;
    RegSnap inside;               /* registers at the end, before restore */
    uint64_t inside_buf0, inside_buf8; /* spec-view reads of buf */
} Exc;

static Exc *rec;                   /* recording target, NULL when idle */
static uint64_t call_tbs, call_insns, call_stores, call_tb_len;
static uint64_t call_store_bytes;

typedef struct {
    uint64_t vaddr;
    uint64_t n_insns;
} TBInfo;

static void vcpu_tb_exec(unsigned int vcpu, void *udata)
{
    TBInfo *ti = udata;
    if (!rec) {
        return;
    }
    rec->tbs++;
    call_tbs++;
    call_tb_len = ti->n_insns;
    if (!qemu_plugin_in_spec_mode()) {
        rec->tbs_not_spec++;
    }
    rec->fp = fnv_add(rec->fp, &ti->vaddr, sizeof(ti->vaddr));
}

static void vcpu_insn_exec(unsigned int vcpu, void *udata)
{
    if (rec) {
        rec->insns++;
        call_insns++;
    }
}

static void vcpu_mem(unsigned int vcpu, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, void *udata)
{
    if (!rec) {
        return;
    }
    bool st = qemu_plugin_mem_is_store(info);
    qemu_plugin_mem_value v = qemu_plugin_mem_get_value(info);
    uint64_t lo = 0, hi = 0;
    switch (v.type) {
    case QEMU_PLUGIN_MEM_VALUE_U8:   lo = v.data.u8; break;
    case QEMU_PLUGIN_MEM_VALUE_U16:  lo = v.data.u16; break;
    case QEMU_PLUGIN_MEM_VALUE_U32:  lo = v.data.u32; break;
    case QEMU_PLUGIN_MEM_VALUE_U64:  lo = v.data.u64; break;
    case QEMU_PLUGIN_MEM_VALUE_U128:
        lo = v.data.u128.low;
        hi = v.data.u128.high;
        break;
    default: break;
    }
    if (qemu_plugin_spec_mem_faulted_take()) {
        rec->faulted_memops++;
    }
    if (st) {
        rec->stores++;
        call_stores++;
        rec->store_bytes += 1u << qemu_plugin_mem_size_shift(info);
        call_store_bytes += 1u << qemu_plugin_mem_size_shift(info);
        if (rec->buf && vaddr >= rec->buf && vaddr < rec->buf + rec->len) {
            rec->stores_in_buf++;
        }
    } else {
        rec->loads++;
    }
    uint64_t ev[4] = { vaddr, st, lo, hi };
    rec->fp = fnv_add(rec->fp, ev, sizeof(ev));
}

static void excursion(Exc *e)
{
    struct qemu_plugin_cpu_state *saved = qemu_plugin_cpu_state_save();
    if (!saved) {
        FATAL("qemu_plugin_cpu_state_save returned NULL");
    }
    if (qemu_plugin_in_spec_mode()) {
        FATAL("vCPU already in spec mode before the excursion");
    }
    e->fp = FNV0;
    e->end = END_BUDGET;
    if (e->spec) {
        qemu_plugin_spec_mode_begin(saved);
        if (!qemu_plugin_in_spec_mode()) {
            FATAL("qemu_plugin_in_spec_mode() false after spec_mode_begin");
        }
    }
    qemu_plugin_set_pc(e->target);
    rec = e;
    for (int i = 0; i < e->budget; i++) {
        call_tbs = call_insns = call_stores = call_tb_len = 0;
        call_store_bytes = 0;
        e->calls++;
        bool ok = qemu_plugin_exec_tb();
        if (ok && merge_calls) {
            /* control T4C: two exec_tb in one accounting window */
            ok = qemu_plugin_exec_tb();
        }
        e->max_tbs_per_call = MAX(e->max_tbs_per_call, call_tbs);
        e->max_stores_per_call = MAX(e->max_stores_per_call, call_stores);
        e->max_store_bytes_per_call = MAX(e->max_store_bytes_per_call,
                                          call_store_bytes);
        if (call_insns > call_tb_len) {
            e->max_insn_excess = MAX(e->max_insn_excess,
                                     call_insns - call_tb_len);
        }
        if (!ok) {
            e->end = END_FAULT;
            if (e->clear) {
                qemu_plugin_spec_clear_exception();
            }
            break;
        }
        e->calls_ok++;
        if (e->spec && qemu_plugin_spec_store_overflowed()) {
            e->end = END_OVERFLOW;
            break;
        }
    }
    rec = NULL;
    e->fp = fnv_add(e->fp, &e->end, sizeof(e->end));
    e->fp = fnv_add(e->fp, &e->calls_ok, sizeof(e->calls_ok));
    e->inside = snap_regs();
    e->fp = fnv_add(e->fp, e->inside.bytes->data, e->inside.bytes->len);
    if (e->buf && e->len >= 16) {
        /* while still in spec mode: the plugin API overlays the sandbox */
        e->inside_buf0 = mem_u64(e->buf);
        e->inside_buf8 = mem_u64(e->buf + 8);
    }
    if (e->spec) {
        qemu_plugin_spec_mode_end();
    }
    if (qemu_plugin_in_spec_mode()) {
        FATAL("qemu_plugin_in_spec_mode() true after spec_mode_end");
    }
    if (e->restore) {
        if (!qemu_plugin_cpu_state_restore(saved)) {
            FATAL("qemu_plugin_cpu_state_restore returned false");
        }
    }
    qemu_plugin_cpu_state_free(saved);
    if (verbose) {
        fprintf(stderr, "[wp-assert] exc %s target=0x%" PRIx64 " end=%s "
                "calls=%" PRIu64 "/%" PRIu64 " tbs=%" PRIu64 " insns=%" PRIu64
                " ld=%" PRIu64 " st=%" PRIu64 " st_in_buf=%" PRIu64
                " faulted=%" PRIu64 " st_bytes=%" PRIu64 " max_st_bytes/call=%"
                PRIu64 " fp=%016" PRIx64 "\n",
                test_names[cur_test], e->target, end_names[e->end],
                e->calls_ok, e->calls, e->tbs, e->insns, e->loads, e->stores,
                e->stores_in_buf, e->faulted_memops, e->store_bytes,
                e->max_store_bytes_per_call, e->fp);
    }
}

/*
 * The invariants every excursion must satisfy regardless of test: the
 * register file and the named buffer are unchanged, every block that ran
 * was a speculative one, and no exec_tb ran more than one block.
 */
static void check_common(Exc *e, RegSnap *pre, uint64_t pre_sum)
{
    RegSnap post = snap_regs();
    const char *d = snap_diff(pre, &post);
    CHECK(d == NULL, "T2 register %s differs after the excursion", d);
    free_snap(&post);
    if (e->buf) {
        uint64_t s = mem_sum(e->buf, e->len);
        CHECK(s == pre_sum, "T1 guest memory [0x%" PRIx64 ",+%" PRIu64
              ") changed across the excursion (sum %016" PRIx64 " -> %016"
              PRIx64 ")", e->buf, e->len, pre_sum, s);
    }
    CHECK(e->spec ? e->tbs_not_spec == 0 : true,
          "%" PRIu64 " blocks executed with spec mode off", e->tbs_not_spec);
    CHECK(e->max_tbs_per_call <= 1,
          "T4 one exec_tb ran %" PRIu64 " blocks", e->max_tbs_per_call);
    CHECK(e->max_insn_excess == 0,
          "T4 one exec_tb ran %" PRIu64 " insns beyond its block",
          e->max_insn_excess);
}

/* --------------------------------------------------------------- tests */

/*
 * T3 controls, one per fault kind: control=T3<KIND> (T3UD, T3DIV0, T3PRIV,
 * T3INT3, T3SYSCALL) skips the exception clear and the state restore after
 * that excursion's fault, so the pending exception -- and whatever the
 * wrong path did to the registers -- reaches the correct path.  The guest
 * must then observe it: a signal, or for SYSCALL the wrong path's write().
 * (control=T3 is the same for T3_STRADDLE, handled in its case.)
 */
static bool t3_leak_control(int test, Exc *e)
{
    const char *kind = test_names[test] + 3;       /* "T3_UD" -> "UD" */
    g_autofree char *name = g_strdup_printf("T3%s", kind);
    g_autofree char *name_n = g_strdup_printf("T3%sN", kind);
    if (test == T3_SYSCALL && control_is(name_n)) {
        /*
         * The spec-OFF form of T3SYSCALL.  Whether the spec-ON form leaks
         * is target-dependent (aarch64 contains a wrong-path svc at
         * source, x86/riscv64/mipsel do not -- see WP_TESTS.md), so the
         * control that must go red on every target runs spec mode off.
         */
        fprintf(stderr, "[wp-assert] CONTROL %s: spec mode off, no "
                "exception clear, no state restore; the host must see the "
                "wrong path's write()\n", name_n);
        e->restore = false;
        e->clear = false;
        e->spec = false;
        return true;
    }
    if (!control_is(name)) {
        return false;
    }
    fprintf(stderr, "[wp-assert] CONTROL %s: no exception clear, no state "
            "restore after the fault; the guest must observe it\n", name);
    e->restore = false;
    e->clear = false;
    if (test != T3_SYSCALL) {
        /*
         * x86 execution faults raised in spec mode never latch at all:
         * raise_interrupt2() leaves through cpu_loop_exit_restore()
         * before writing exception_index, so with spec mode on there is
         * nothing to leak (observed: the spec-on form of this control
         * stays green).  Drop spec mode too, so the fault latches and
         * the guest-side detector has something to catch.
         */
        e->spec = false;
    }
    return true;
}

static void run_test(int test, uint64_t target, uint64_t buf, uint64_t len)
{
    Exc e = { .target = target, .buf = buf, .len = len,
              .budget = WP_SHORT_BUDGET, .spec = true, .restore = true,
              .clear = true };
    RegSnap pre = snap_regs();
    uint64_t pre_sum = buf ? mem_sum(buf, len) : 0;

    cur_test = test;
    tests_run[test]++;

    switch (test) {
    case T1_STORE:
        if (control_is("T1")) {
            fprintf(stderr, "[wp-assert] CONTROL T1: excursion WITHOUT "
                    "spec mode; stores reach memory, T1 must FAIL\n");
            e.spec = false;
        }
        if (control_is("T5X")) {
            /* runner-level control: corrupt the correct path, silence
             * the in-plugin memory check, let the runner see it */
            fprintf(stderr, "[wp-assert] CONTROL T5X: excursion WITHOUT "
                    "spec mode, in-plugin T1 suppressed; the RUNNER's "
                    "output comparison must FAIL\n");
            e.spec = false;
        }
        excursion(&e);
        /* subject: the wrong path really stored into the buffer ... */
        CHECK(e.stores_in_buf >= 5, "only %" PRIu64 " wrong-path stores hit "
              "the buffer (subject absent)", e.stores_in_buf);
        /* ... and the sandbox holds them and forwards them to loads */
        CHECK(e.inside_buf0 == 0x1122334455667788ull,
              "spec view of buf[0] is %016" PRIx64 ", not the wrong-path "
              "store", e.inside_buf0);
        CHECK(e.inside_buf8 == 0x1122334455667788ull,
              "store-to-load forwarding: buf[8] is %016" PRIx64,
              e.inside_buf8);
        if (control_is("T5X")) {
            e.buf = 0;             /* suppress the memory half */
        }
        check_common(&e, &pre, pre_sum);
        break;

    case T1_RO:
        excursion(&e);
        CHECK(e.stores >= 3, "only %" PRIu64 " wrong-path stores", e.stores);
        CHECK(e.faulted_memops >= 3, "stores to read-only data/code not "
              "flagged synthetic (%" PRIu64 ")", e.faulted_memops);
        CHECK(e.inside_buf0 == UINT64_MAX, "spec view of read-only data is "
              "%016" PRIx64 ", not the sandboxed store", e.inside_buf0);
        check_common(&e, &pre, pre_sum);
        break;

    case T2_REGS: {
        const char *const *subjects = isa->t2_subjects;
        if (control_is("T2")) {
            fprintf(stderr, "[wp-assert] CONTROL T2: skipping "
                    "qemu_plugin_cpu_state_restore, T2 must FAIL\n");
            e.restore = false;
        }
        excursion(&e);
        for (unsigned i = 0; subjects[i]; i++) {
            CHECK(snap_reg_differs(&pre, &e.inside, subjects[i]),
                  "wrong path did not change %s (subject absent)",
                  subjects[i]);
        }
        check_common(&e, &pre, pre_sum);
        if (control_is("T2G")) {
            /* guest-side control: the trigger's own register check */
            fprintf(stderr, "[wp-assert] CONTROL T2G: perturbing %s after "
                    "the checks; the GUEST must report it in its regmask\n",
                    isa->t2g_reg);
            perturb_reg(isa->t2g_reg, 1);
        }
        break;
    }

    case T3_FETCH_UNMAPPED:
        excursion(&e);
        CHECK(e.end == END_FAULT && e.calls_ok == 0 && e.tbs == 0,
              "fetch from an unmapped page: end=%s ok=%" PRIu64 " tbs=%"
              PRIu64, end_names[e.end], e.calls_ok, e.tbs);
        check_common(&e, &pre, pre_sum);
        break;

    case T3_STRADDLE:
        if (control_is("T3") || control_is("T3N")) {
            /* The nop sled changes no register, so skipping the restore
             * and the exception clear leaks exactly one thing: the
             * pending fault.  The guest must then observe SIGSEGV.
             * T3 keeps spec mode on, which leaks on x86 only (a fetch
             * fault in spec mode latches nothing on the other targets);
             * T3N runs spec mode off so the fault latches on every
             * target. */
            fprintf(stderr, "[wp-assert] CONTROL %s: no exception clear, "
                    "no state restore after the fault; the guest must "
                    "observe SIGSEGV\n", control);
            e.restore = false;
            e.clear = false;
            e.spec = !control_is("T3N");
        }
        excursion(&e);
        CHECK(e.end == END_FAULT && e.calls_ok >= 1 && e.insns >= 16,
              "translation fault in a PROT_NONE page: end=%s ok=%" PRIu64
              " insns=%" PRIu64, end_names[e.end], e.calls_ok, e.insns);
        if (!control_is("T3") && !control_is("T3N")) {
            check_common(&e, &pre, pre_sum);
        }
        break;

    case T3_DIV0:
        if (!isa->div0_traps) {
            /*
             * The ISA defines integer division by zero (no exception), so
             * the architectural contract is the opposite of a fault: the
             * wrong path divides, continues, and runs its full budget.
             */
            if (control_is("T3DIV0")) {
                fprintf(stderr, "[wp-assert] CONTROL T3DIV0: not applicable "
                        "on %s (division by zero does not trap)\n",
                        isa->target);
            }
            excursion(&e);
            CHECK(e.end == END_BUDGET && e.calls_ok == (uint64_t)e.budget,
                  "a non-trapping divide by zero ended the excursion (end=%s "
                  "ok=%" PRIu64 ")", end_names[e.end], e.calls_ok);
            CHECK(e.stores_in_buf >= 1, "the quotient store after the "
                  "divide was not observed (subject absent)");
            check_common(&e, &pre, pre_sum);
            break;
        }
        /* fall through */
    case T3_UD:
    case T3_PRIV:
    case T3_INT3:
        if (t3_leak_control(test, &e)) {
            excursion(&e);
            break;
        }
        excursion(&e);
        CHECK(e.end == END_FAULT, "execution fault did not end the "
              "excursion (end=%s)", end_names[e.end]);
        check_common(&e, &pre, pre_sum);
        break;

    case T3_LOAD_UNMAPPED:
        /* NOT a fault: a wrong-path load never retires; it reads a
         * synthetic placeholder, is flagged, and the walk continues */
        excursion(&e);
        CHECK(e.end == END_BUDGET && e.calls_ok == (uint64_t)e.budget,
              "load from an unmapped page ended the excursion (end=%s ok=%"
              PRIu64 ")", end_names[e.end], e.calls_ok);
        CHECK(e.faulted_memops >= 1, "synthetic load not flagged (subject "
              "absent)");
        CHECK(e.stores_in_buf >= 1, "placeholder store not observed");
        check_common(&e, &pre, pre_sum);
        break;

    case T3_SYSCALL: {
        uint64_t blocked0 = qemu_plugin_spec_syscall_blocked_count();
        if (t3_leak_control(test, &e)) {
            excursion(&e);
            break;
        }
        excursion(&e);
        CHECK(e.end == END_FAULT, "a wrong-path syscall did not end the "
              "block walk (end=%s)", end_names[e.end]);
        CHECK(qemu_plugin_spec_syscall_blocked_count() == blocked0,
              "a wrong-path syscall reached the syscall dispatcher");
        check_common(&e, &pre, pre_sum);
        break;
    }

    case T4_LOOP:
    case T4_REP: {
        int expect = t4_budget;
        e.budget = t4_budget;
        if (control_is("T4")) {
            fprintf(stderr, "[wp-assert] CONTROL T4: expecting budget+1 "
                    "blocks, T4 must FAIL\n");
            expect = t4_budget + 1;
        }
        if (control_is("T4C") && test == T4_LOOP) {
            fprintf(stderr, "[wp-assert] CONTROL T4C: two exec_tb per "
                    "accounting window; the one-block-per-call check must "
                    "FAIL\n");
            merge_calls = true;
        }
        excursion(&e);
        merge_calls = false;
        CHECK(e.max_tbs_per_call == 1, "T4 one exec_tb ran %" PRIu64
              " blocks", e.max_tbs_per_call);
        CHECK(e.end == END_BUDGET && e.calls_ok == (uint64_t)e.budget,
              "endless-loop excursion did not end at its budget (end=%s ok=%"
              PRIu64 ")", end_names[e.end], e.calls_ok);
        CHECK(e.tbs == (uint64_t)expect, "%" PRIu64 " blocks executed for a "
              "budget of %d", e.tbs, expect);
        if (test == T4_REP && isa->rep_is_mops) {
            /*
             * SETP/SETM/SETE with Xn = 16 MiB.  A MOPS set is one helper
             * call that loops a page at a time, so the per-call bound is
             * the bytes stored, not a store count: no exec_tb may set more
             * than one page, and the 16 MiB may never complete inside the
             * budget.  (The engine's MOPS_SPEC_MAX_BYTES clamp is recorded
             * in WP_TESTS.md as it measures.)
             */
            CHECK(e.store_bytes > 0, "the wrong-path set stored nothing "
                  "(subject absent)");
            CHECK(e.max_store_bytes_per_call <= 4096, "one exec_tb set %"
                  PRIu64 " bytes", e.max_store_bytes_per_call);
            CHECK(e.store_bytes < 0x1000000, "the 16 MiB set completed "
                  "inside the budget (%" PRIu64 " bytes)", e.store_bytes);
            /*
             * What the wrong path's own registers say about the set.  A
             * completed set (Xn = 0) has Xd = dest + size under either
             * MOPS option, and has stored all of it; a bounded walk may
             * stop part-way, but the state it leaves must be one the
             * architecture can reach.
             */
            uint64_t x4 = snap_u64(&e.inside, "x4") - e.buf;
            uint64_t x5 = snap_u64(&e.inside, "x5");
            fprintf(stderr, "[wp-assert] T4_REP mops: %" PRIu64 " bytes "
                    "stored; after the triple x4=buf+%" PRId64 " x5=%" PRId64
                    "\n", e.store_bytes, (int64_t)x4, (int64_t)x5);
            CHECK(x5 != 0 || (x4 == 0x1000000 && e.store_bytes == 0x1000000),
                  "the wrong-path set reports completion (x5=0) after %" PRIu64
                  " of 16777216 bytes with x4=buf+%" PRIu64 ": a register "
                  "state the architecture cannot reach", e.store_bytes, x4);
        } else {
            if (test == T4_REP) {
                /* one REP iteration per block; the walk must not plough
                 * through RCX = 16 MiB inside one exec_tb */
                CHECK(e.max_stores_per_call <= 1, "one exec_tb performed %"
                      PRIu64 " REP iterations", e.max_stores_per_call);
            }
            /* one store per block: one increment per loop trip, one
             * stosb per REP iteration -- the walk did what the budget
             * says, no more */
            CHECK(e.stores == (uint64_t)e.budget,
                  "%" PRIu64 " wrong-path stores for %d blocks", e.stores,
                  e.budget);
        }
        check_common(&e, &pre, pre_sum);
        break;
    }

    case T5_REPEAT: {
        Exc e2 = e;
        excursion(&e);
        check_common(&e, &pre, pre_sum);
        if (control_is("T5")) {
            fprintf(stderr, "[wp-assert] CONTROL T5: perturbing %s "
                    "between the two runs, T5 must FAIL\n", isa->arg[2]);
            perturb_reg(isa->arg[2], 8);
        }
        excursion(&e2);
        CHECK(e.tbs > 0 && e.stores > 0, "empty excursion (subject absent)");
        CHECK(e.fp == e2.fp, "same excursion from the same state diverged: "
              "fp %016" PRIx64 " vs %016" PRIx64 " (tbs %" PRIu64 "/%" PRIu64
              " st %" PRIu64 "/%" PRIu64 ")", e.fp, e2.fp, e.tbs, e2.tbs,
              e.stores, e2.stores);
        CHECK(snap_diff(&e.inside, &e2.inside) == NULL,
              "in-excursion register %s diverged between identical runs",
              snap_diff(&e.inside, &e2.inside));
        fprintf(stderr, "[wp-assert] FP T5 %016" PRIx64 "\n", e.fp);
        if (dump_inside) {
            for (guint i = 0; i < regs->len; i++) {
                int n = g_array_index(e.inside.len, int, i);
                int off = g_array_index(e.inside.off, int, i);
                fprintf(stderr, "[wp-assert] inside %s =",
                        g_array_index(regs, Reg, i).name);
                for (int k = 0; k < n; k++) {
                    fprintf(stderr, "%02x", e.inside.bytes->data[off + k]);
                }
                fprintf(stderr, "\n");
            }
        }
        free_snap(&e2.inside);
        break;
    }

    default:
        FATAL("unknown test id %d", test);
    }

    free_snap(&e.inside);
    free_snap(&pre);
}

static void marker_exec(unsigned int vcpu, void *udata)
{
    if (qemu_plugin_in_spec_mode()) {
        return;                   /* a wrong path ran the marker: ignore */
    }
    uint64_t test = read_reg64(isa->arg[0]);
    uint64_t target = read_reg64(isa->arg[1]);
    uint64_t buf = read_reg64(isa->arg[2]);
    uint64_t len = read_reg64(isa->arg[3]);
    if (test == 0 || test >= T_LAST) {
        cur_test = 0;
        fprintf(stderr, "[wp-assert] FAIL marker: bad test id %" PRIu64 "\n",
                test);
        abort();
    }
    if (test == T4_REP && isa->rep_skip) {
        cur_test = T4_REP;
        FATAL("the guest ran T4_REP on %s, which has no subject for it",
             isa->target);
    }
    if (!enabled) {
        tests_run[test]++;
        return;
    }
    run_test((int)test, target, buf, len);
    /*
     * Force the vCPU back through the exception check at the next block
     * boundary.  On linux-user a fault does not queue a signal at the
     * fault site: record_sigsegv sets exception_index and longjmps, and
     * cpu_loop raises the signal only if the index survives to
     * cpu_handle_exception.  Left alone, the guest's next syscall
     * overwrites a leaked index and the leak is invisible to the guest.
     * The deferred flush kicks the vCPU (exit_request), which preserves a
     * pending index and delivers it -- so a leaked wrong-path fault
     * becomes a guest signal the victim reports.
     */
    qemu_plugin_request_tb_flush();
    if (verbose) {
        fprintf(stderr, "[wp-assert] %s ok (%d checks)\n", test_names[test],
                checks_passed[test]);
    }
}

/* ------------------------------------------------------------ plumbing */

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    TBInfo *ti = g_new0(TBInfo, 1);      /* lives as long as the TB may */
    ti->vaddr = qemu_plugin_tb_vaddr(tb);
    ti->n_insns = n;
    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS, ti);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint8_t data[16];
        size_t sz = qemu_plugin_insn_data(insn, data, sizeof(data));
        if (isa && sz == isa->marker_len &&
            memcmp(data, isa->marker, isa->marker_len) == 0) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, marker_exec,
                                                   QEMU_PLUGIN_CB_RW_REGS,
                                                   NULL);
        }
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                               QEMU_PLUGIN_CB_NO_REGS, NULL);
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, NULL);
    }
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu)
{
    if (regs) {
        return;
    }
    g_autoptr(GArray) descs = qemu_plugin_get_registers();
    regs = g_array_new(false, false, sizeof(Reg));
    for (guint i = 0; i < descs->len; i++) {
        qemu_plugin_reg_descriptor *d =
            &g_array_index(descs, qemu_plugin_reg_descriptor, i);
        Reg r = { d->handle, g_strdup(d->name) };
        g_array_append_val(regs, r);
        if (dump_regs) {
            g_autoptr(GByteArray) b = g_byte_array_new();
            int n = qemu_plugin_read_register(d->handle, b);
            fprintf(stderr, "[wp-assert] reg %3u %-12s %2d bytes feature=%s\n",
                    i, d->name, n, d->feature ? d->feature : "?");
        }
    }
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    int missing = 0, seen = 0;
    for (int t = 1; t < T_LAST; t++) {
        seen += tests_run[t];
    }
    if (!isa || (!seen && !require_all)) {
        /* loaded by the generic check-tcg plugin loop: nothing to do */
        return;
    }
    for (int t = 1; t < T_LAST; t++) {
        if (t == T4_REP && isa->rep_skip) {
            fprintf(stderr, "[wp-assert] SKIP %-18s on %s: %s\n",
                    test_names[t], isa->target, isa->rep_skip);
            continue;
        }
        if (!tests_run[t]) {
            fprintf(stderr, "[wp-assert] FAIL %s: never ran (subject "
                    "absent: marker not reached)\n", test_names[t]);
            missing++;
        } else if (checks_failed[t]) {
            fprintf(stderr, "[wp-assert] FAIL %-18s %3d checks failed, %d "
                    "passed\n", test_names[t], checks_failed[t],
                    checks_passed[t]);
            missing++;
        } else if (enabled) {
            fprintf(stderr, "[wp-assert] PASS %-18s %3d checks\n",
                    test_names[t], checks_passed[t]);
        }
    }
    uint64_t blocked = qemu_plugin_spec_syscall_blocked_count();
    if (blocked) {
        fprintf(stderr, "[wp-assert] FAIL T3_SYSCALL: %" PRIu64 " wrong-path "
                "syscalls reached the dispatcher\n", blocked);
        missing++;
    }
    fprintf(stderr, "[wp-assert] spec_reserve_exhausted=%" PRIu64
            " spec_reserve_opens=%" PRIu64 "\n",
            qemu_plugin_spec_reserve_exhausted(),
            qemu_plugin_spec_reserve_opens());
    if (missing) {
        fflush(stderr);
        abort();
    }
    fprintf(stderr, "[wp-assert] %s\n",
            enabled ? "ALL PASS" : "mode=off: markers seen, nothing driven");
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        g_auto(GStrv) kv = g_strsplit(argv[i], "=", 2);
        if (!kv[0] || !kv[1]) {
            fprintf(stderr, "wp-assert: bad option %s\n", argv[i]);
            return -1;
        }
        if (g_strcmp0(kv[0], "mode") == 0) {
            enabled = g_strcmp0(kv[1], "off") != 0;
        } else if (g_strcmp0(kv[0], "budget") == 0) {
            t4_budget = atoi(kv[1]);
        } else if (g_strcmp0(kv[0], "control") == 0) {
            control = g_strdup(kv[1]);
        } else if (g_strcmp0(kv[0], "require") == 0) {
            require_all = g_strcmp0(kv[1], "on") == 0;
        } else if (g_strcmp0(kv[0], "verbose") == 0) {
            verbose = g_strcmp0(kv[1], "on") == 0;
        } else if (g_strcmp0(kv[0], "dumpinside") == 0) {
            dump_inside = g_strcmp0(kv[1], "on") == 0;
        } else if (g_strcmp0(kv[0], "keepgoing") == 0) {
            keep_going = g_strcmp0(kv[1], "on") == 0;
        } else if (g_strcmp0(kv[0], "dumpregs") == 0) {
            dump_regs = g_strcmp0(kv[1], "on") == 0;
        } else {
            fprintf(stderr, "wp-assert: unknown option %s\n", argv[i]);
            return -1;
        }
    }
    if (t4_budget < 16 || t4_budget > 4000) {
        fprintf(stderr, "wp-assert: budget must be in [16,4000]\n");
        return -1;
    }
    for (unsigned i = 0; i < G_N_ELEMENTS(isas); i++) {
        if (strcmp(info->target_name, isas[i].target) == 0) {
            isa = &isas[i];
        }
    }
    if (*control) {
        fprintf(stderr, "[wp-assert] control=%s armed\n", control);
    }
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
