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
 * Under system emulation (qemu-system-x86_64 with the bare-metal kernel
 * tests/tcg/x86_64/system/wp-victim-sys.c) T1-T5 re-run with the real MMU,
 * every excursion is bracketed by qemu_plugin_spec_vtime_pause/_resume
 * outside spec_mode_begin/_end, the plugin's own checks run inside
 * qemu_plugin_vclock_pause/_resume windows, and the phase-2 families run:
 *
 *   P2-A clock freeze      the virtual clock does not see a host delay
 *                          injected inside the excursion (A1), nor does a
 *                          wrong-path rdtsc pair (A3); the guest's own view
 *                          (A2) and liveness are judged by the runner
 *   P2-B interrupt window  no interrupt delivery on the wrong path (B1);
 *                          delivery, counts and positions are the guest's
 *                          and the runner's (B2-B4)
 *   P2-C containment       MMIO/port I/O (C1), TLB (C2), CPL0 faults in an
 *                          IDT-less window (C3), page walks through MMIO (C4)
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
 *   delay_us=N        system: host busy-wait inside every P2A_CLOCK
 *                     excursion, between its first and second exec_tb
 *                     (default 50000; 0 = the no-delay calibration arm)
 *   bdelay_us=N       system: the same inside every P2B_TIMER excursion
 *                     (default 1000, longer than the guest's deadline)
 *   control=P2A P2A2 P2A2X P2B P2B1 P2B1E P2B1L P2B1I C1N C1NS C1NF C2N
 *                     C3N C4N
 *                     (system; see
 *                     WP_TESTS.md "Softmmu phase 2")
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
    T4_REP, T5_REPEAT,
    /* system emulation only: tests/tcg/x86_64/system/wp-victim-sys.c */
    P2A_CLOCK, P2B_TIMER, P2B_PEND, P2B_ISR, C1_MMIO, C2_TLB, C3_GP,
    C3_PF, C3_UD, C4_PTW,
    T_LAST,
    T_USER_LAST = P2A_CLOCK,    /* linux-user runs T1..T5 only */
    P2_INFO = 31,               /* not a test: the guest's layout */
};

static const char *const test_names[T_LAST] = {
    [T1_STORE] = "T1_STORE", [T1_RO] = "T1_RO", [T2_REGS] = "T2_REGS",
    [T3_FETCH_UNMAPPED] = "T3_FETCH_UNMAPPED", [T3_STRADDLE] = "T3_STRADDLE",
    [T3_UD] = "T3_UD", [T3_DIV0] = "T3_DIV0", [T3_PRIV] = "T3_PRIV",
    [T3_INT3] = "T3_INT3", [T3_LOAD_UNMAPPED] = "T3_LOAD_UNMAPPED",
    [T3_SYSCALL] = "T3_SYSCALL", [T4_LOOP] = "T4_LOOP", [T4_REP] = "T4_REP",
    [T5_REPEAT] = "T5_REPEAT", [P2A_CLOCK] = "P2A_CLOCK",
    [P2B_TIMER] = "P2B_TIMER", [P2B_PEND] = "P2B_PEND",
    [P2B_ISR] = "P2B_ISR", [C1_MMIO] = "C1_MMIO", [C2_TLB] = "C2_TLB",
    [C3_GP] = "C3_GP", [C3_PF] = "C3_PF", [C3_UD] = "C3_UD",
    [C4_PTW] = "C4_PTW",
};

/*
 * The fixed layout of the system victim (keep in sync with
 * tests/tcg/x86_64/system/wp-victim-sys.c).
 */
#define SYS_RB          0x400000ull    /* C2's pages */
#define SYS_C2_PAGES    600
#define SYS_PROBE       0x205000ull    /* not present */
#define SYS_C4_VA       0x818000ull    /* PTE in e1000 ICR */
#define SYS_E1K_ICS     0xc8

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
static bool is_system;            /* qemu-system: the phase-2 suite */
static int n_tests = T_USER_LAST; /* tests require=on insists on */
static long delay_us = 50000;     /* P2A_CLOCK in-excursion host delay */
static long bdelay_us = 1000;     /* P2B_TIMER in-excursion host delay */
/* P2_INFO: the guest's layout and TSC rate */
static uint64_t wp_lo, wp_hi, tsc_per_ms;
static bool have_info;
/* control P2B: the vtime resume owed to the next correct-path block */
static bool resume_owed;
/* control P2A2X: re-assert the un-resumed pause at every correct-path block */
static bool repause;
/* B1, the event half: ASYNC_ENTER departures, over the whole run */
static uint64_t ev_async_enter, ev_async_in_wp, ev_async_in_window;
static uint64_t ev_drains;
static bool in_window;            /* between an excursion's two drains */
static uint64_t resets;           /* vm_reset callbacks seen (C3) */

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
    /* system emulation */
    bool vtime;                   /* bracket with spec_vtime_pause/_resume */
    bool skip_pause, skip_resume, defer_resume;   /* P2A / P2A2 / P2B */
    long delay_us;                /* host busy-wait after the first exec_tb */
    int64_t vclk0, vclk1;         /* qemu_plugin_vclock_ns() outside it */
    uint32_t fdepth0, fdepth1;    /* qemu_plugin_fault_depth() around it */
    uint64_t async_blocks;        /* spec blocks with in_async_int true */
    uint64_t probe_addr, probe_hits, probe_faulted;
    bool c2;                      /* count C2's distinct pages */
    uint8_t c2_seen[SYS_C2_PAGES];
    uint64_t c2_pages;
    /* controls C1NS/C1NF (F12 witness): log every exec_tb call's PC in and
     * out; persist = keep calling after a false return */
    bool trace, persist;
    uint64_t pc_in[8], pc_out[8];
    bool call_ok[8];
    uint64_t call_insns_at[8], call_stores_at[8];
} Exc;

/* F12 witness: report the first correct-path translation after it */
static bool f12_watch;

static Exc *rec;                   /* recording target, NULL when idle */
static uint64_t call_tbs, call_insns, call_stores, call_tb_len;
static uint64_t call_store_bytes;

typedef struct {
    uint64_t vaddr;
    uint64_t n_insns;
} TBInfo;

/*
 * The system-mode event queue (qemu_plugin_cpu_events_set), drained at
 * every correct-path block and at both ends of every excursion.  B1's event
 * half: an ASYNC_ENTER whose departure PC lies in the guest's
 * wrong-path-only code is an interrupt delivered on a wrong path, and one
 * drained at the end of an excursion was stamped inside its window.
 */
static void drain_events(unsigned int vcpu)
{
    const struct qemu_plugin_cpu_event *evs;
    size_t n = qemu_plugin_drain_cpu_events(vcpu, &evs);
    ev_drains++;
    for (size_t i = 0; i < n; i++) {
        if (evs[i].kind != QEMU_PLUGIN_CPU_EV_ASYNC_ENTER) {
            continue;
        }
        ev_async_enter++;
        if (in_window) {
            ev_async_in_window++;
            fprintf(stderr, "[wp-assert] FAIL B1: ASYNC_ENTER (departure pc "
                    "0x%" PRIx64 ") stamped inside an excursion window\n",
                    evs[i].pc);
        }
        if (have_info && evs[i].pc >= wp_lo && evs[i].pc < wp_hi) {
            ev_async_in_wp++;
            fprintf(stderr, "[wp-assert] FAIL B1: ASYNC_ENTER departure pc "
                    "0x%" PRIx64 " is wrong-path-only code\n", evs[i].pc);
            fflush(stderr);
        }
    }
}

static void vcpu_tb_exec(unsigned int vcpu, void *udata)
{
    TBInfo *ti = udata;
    if (is_system && !qemu_plugin_in_spec_mode()) {
        drain_events(vcpu);
        if (repause && !rec) {
            /* control P2A2X: cpu_exec_longjmp_cleanup closes a leaked
             * excursion at the next longjmp; keep re-opening it */
            qemu_plugin_spec_vtime_pause();
        }
        if (resume_owed && !rec) {
            /* control P2B: the resume the excursion withheld, one
             * correct-path boundary late */
            resume_owed = false;
            qemu_plugin_spec_vtime_resume();
        }
    }
    if (!rec) {
        return;
    }
    rec->tbs++;
    call_tbs++;
    call_tb_len = ti->n_insns;
    if (!qemu_plugin_in_spec_mode()) {
        rec->tbs_not_spec++;
    } else if (qemu_plugin_in_async_int()) {
        rec->async_blocks++;
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
    bool faulted = qemu_plugin_spec_mem_faulted_take();
    if (faulted) {
        rec->faulted_memops++;
    }
    if (rec->probe_addr && vaddr == rec->probe_addr) {
        rec->probe_hits++;
        rec->probe_faulted += faulted;
    }
    if (rec->c2 && !st && vaddr >= SYS_RB &&
        vaddr < SYS_RB + SYS_C2_PAGES * 0x1000ull) {
        uint64_t pg = (vaddr - SYS_RB) >> 12;
        if (!rec->c2_seen[pg]) {
            rec->c2_seen[pg] = 1;
            rec->c2_pages++;
        }
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

static void busy_wait_us(long us)
{
    gint64 end = g_get_monotonic_time() + us;
    while (g_get_monotonic_time() < end) {
        /* host time passes; the guest's must not */
    }
}

static void excursion(Exc *e)
{
    if (e->vtime) {
        /*
         * The phase-2 bracket: the marker callback's own work runs inside a
         * qemu_plugin_vclock_pause window (marker_exec); leave it, read the
         * guest clock, and freeze it for the excursion.
         */
        qemu_plugin_vclock_resume();
        drain_events(qemu_plugin_current_vcpu_index());
        in_window = true;
        e->vclk0 = qemu_plugin_vclock_ns();
        if (!e->skip_pause) {
            qemu_plugin_spec_vtime_pause();
        }
    }
    e->fdepth0 = qemu_plugin_fault_depth();
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
        uint64_t pc_in = e->trace && i < 8 ? read_reg64("rip") : 0;
        bool ok = qemu_plugin_exec_tb();
        if (e->trace && i < 8) {
            uint64_t pc_out = read_reg64("rip");
            e->pc_in[i] = pc_in;
            e->pc_out[i] = pc_out;
            e->call_ok[i] = ok;
            e->call_insns_at[i] = call_insns;
            e->call_stores_at[i] = call_stores;
            fprintf(stderr, "[wp-assert] %s call %d spec=%d pc_in=0x%" PRIx64
                    " ok=%d pc_out=0x%" PRIx64 " tbs=%" PRIu64 " insns=%"
                    PRIu64 " stores=%" PRIu64 "\n", test_names[cur_test],
                    i + 1, e->spec, pc_in, ok, pc_out, call_tbs, call_insns,
                    call_stores);
        }
        if (ok && merge_calls) {
            /* control T4C: two exec_tb in one accounting window */
            ok = qemu_plugin_exec_tb();
        }
        e->max_tbs_per_call = MAX(e->max_tbs_per_call, call_tbs);
        e->max_stores_per_call = MAX(e->max_stores_per_call, call_stores);
        e->max_store_bytes_per_call = MAX(e->max_store_bytes_per_call,
                                          call_store_bytes);
        if (i == 0 && e->delay_us > 0) {
            busy_wait_us(e->delay_us);
        }
        if (call_insns > call_tb_len) {
            e->max_insn_excess = MAX(e->max_insn_excess,
                                     call_insns - call_tb_len);
        }
        if (!ok) {
            e->end = END_FAULT;
            if (e->clear) {
                qemu_plugin_spec_clear_exception();
            }
            if (e->persist) {
                continue;
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
    e->fdepth1 = qemu_plugin_fault_depth();
    if (e->vtime) {
        if (e->defer_resume) {
            resume_owed = true;
        } else if (!e->skip_resume) {
            qemu_plugin_spec_vtime_resume();
        }
        e->vclk1 = qemu_plugin_vclock_ns();
        drain_events(qemu_plugin_current_vcpu_index());
        in_window = false;
        qemu_plugin_vclock_pause();
    }
    if (verbose) {
        fprintf(stderr, "[wp-assert] exc %s target=0x%" PRIx64 " end=%s "
                "calls=%" PRIu64 "/%" PRIu64 " tbs=%" PRIu64 " insns=%" PRIu64
                " ld=%" PRIu64 " st=%" PRIu64 " st_in_buf=%" PRIu64
                " faulted=%" PRIu64 " st_bytes=%" PRIu64 " max_st_bytes/call=%"
                PRIu64 " fp=%016" PRIx64 " spec=%d not_spec_tbs=%" PRIu64
                " probe=%" PRIu64 "/%" PRIu64 "\n",
                test_names[cur_test], e->target, end_names[e->end],
                e->calls_ok, e->calls, e->tbs, e->insns, e->loads, e->stores,
                e->stores_in_buf, e->faulted_memops, e->store_bytes,
                e->max_store_bytes_per_call, e->fp, e->spec, e->tbs_not_spec,
                e->probe_hits, e->probe_faulted);
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
    if (e->buf && e->len) {
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
    uint64_t pre_sum = buf && len ? mem_sum(buf, len) : 0;

    cur_test = test;
    tests_run[test]++;
    e.vtime = is_system;

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

    case P2A_CLOCK: {
        /*
         * A1: the guest clock read just outside the vtime bracket does not
         * see the host delay injected inside it.  A3: the wrong path's own
         * rdtsc pair, read back from the sandbox while still in spec mode,
         * straddles that delay and must not show it either.
         */
        e.delay_us = delay_us;
        if (control_is("P2A")) {
            fprintf(stderr, "[wp-assert] CONTROL P2A: no "
                    "qemu_plugin_spec_vtime_pause; A1 and A2 must FAIL by "
                    "about the %ld us delay\n", delay_us);
            e.skip_pause = true;
        }
        if (control_is("P2A2") || control_is("P2A2X")) {
            static bool said;
            if (!said) {
                said = true;
                fprintf(stderr, "[wp-assert] CONTROL %s: "
                        "qemu_plugin_spec_vtime_pause without the resume%s; "
                        "the runner's liveness check must FAIL\n", control,
                        control_is("P2A2X") ? ", re-paused at every "
                        "correct-path block" : "");
            }
            e.skip_resume = true;
            repause = control_is("P2A2X");
        }
        excursion(&e);
        check_common(&e, &pre, pre_sum);
        int64_t dv = e.vclk1 - e.vclk0;
        if (e.vclk0 == 0 && e.vclk1 == 0) {
            FAIL("A1 SUBJECT ABSENT: qemu_plugin_vclock_ns() reads 0 on both "
                 "sides of the bracket (it returns 0 under -icount), so the "
                 "clock A1 is about cannot be read through the plugin API");
        } else {
            fprintf(stderr, "[wp-assert] A1 vclock_delta_ns=%" PRId64
                    " delay_us=%ld\n", dv, delay_us);
            if (delay_us > 0) {
                CHECK(dv < delay_us * 1000 / 2, "A1 the guest clock advanced "
                      "%" PRId64 " ns across an excursion holding a %ld us "
                      "host delay", dv, delay_us);
            }
        }
        CHECK(e.calls_ok >= 2, "A3 subject absent: the rdtsc pair did not "
              "both run (ok=%" PRIu64 ")", e.calls_ok);
        CHECK(e.inside_buf0 != 0 && e.inside_buf8 >= e.inside_buf0,
              "A3 subject absent: wrong-path rdtsc pair %" PRIx64 " / %"
              PRIx64, e.inside_buf0, e.inside_buf8);
        uint64_t wtsc = e.inside_buf8 - e.inside_buf0;
        fprintf(stderr, "[wp-assert] A3 wrong_path_tsc_delta=%" PRIu64
                " tsc_per_ms=%" PRIu64 "\n", wtsc, tsc_per_ms);
        if (delay_us > 0) {
            CHECK(have_info && tsc_per_ms > 0, "A3: no TSC rate from P2_INFO");
            uint64_t d_ticks = (uint64_t)delay_us * tsc_per_ms / 1000;
            CHECK(wtsc < d_ticks / 2, "A3 the wrong path's rdtsc pair jumped "
                  "%" PRIu64 " ticks across a %" PRIu64 "-tick host delay",
                  wtsc, d_ticks);
        }
        break;
    }

    case P2B_TIMER:
    case P2B_PEND:
    case P2B_ISR:
        if (test == P2B_TIMER) {
            e.delay_us = bdelay_us;
            if (control_is("P2B")) {
                /* withhold the resume -- and with it the kick re-arm --
                 * until the next correct-path block */
                static bool said;
                if (!said) {
                    said = true;
                    fprintf(stderr, "[wp-assert] CONTROL P2B: every "
                            "P2B_TIMER excursion's vtime resume (and its "
                            "deferred-kick re-arm) withheld to the next "
                            "correct-path block; B2/B3 must FAIL\n");
                }
                e.defer_resume = true;
            }
        }
        if (test == P2B_PEND && control_is("P2B1L")) {
            /*
             * The design's literal P2B1: spec mode off, clear and restore
             * kept.  exec_tb has no interrupt-delivery path of its own, so
             * this is expected NOT to go red; the runner records it as
             * evidence of that, and P2B1 below is the firing control.
             */
            fprintf(stderr, "[wp-assert] CONTROL P2B1L: the pending-interrupt "
                    "excursion with spec mode off (clear and restore kept)\n");
            e.spec = false;
        }
        if (test == P2B_PEND && control_is("P2B1E")) {
            /*
             * The event half's own control: the P2B1 leak below delivers
             * the pending interrupt on correct-path kernel code, which the
             * wrong-path-only range excludes.  Widen the range over the
             * whole kernel text so that real departure must be caught.
             */
            fprintf(stderr, "[wp-assert] CONTROL P2B1E: P2B1's leak with the "
                    "B1 event range widened to [0x100000,0x200000)\n");
            wp_lo = 0x100000;
            wp_hi = 0x200000;
        }
        if (test == P2B_PEND &&
            (control_is("P2B1") || control_is("P2B1E"))) {
            /*
             * The wrong path's sti really runs and nothing restores
             * EFLAGS.IF, so the pending interrupt is taken inside the
             * guest's trigger window -- its IDT-counter detector must see
             * it.  (The correct path does not resume INSIDE the wrong-path
             * code: the marker's block continues from its own host code,
             * whatever env->eip says.)
             */
            fprintf(stderr, "[wp-assert] CONTROL %s: the pending-interrupt "
                    "excursion with spec mode off, no clear, no restore; the "
                    "leaked IF lets the interrupt in inside the trigger "
                    "window and B1 must FAIL\n", control);
            e.spec = false;
            e.clear = false;
            e.restore = false;
            excursion(&e);
            break;
        }
        excursion(&e);
        check_common(&e, &pre, pre_sum);
        CHECK(e.tbs > 0, "B subject absent: the wrong path ran no block");
        if (test == P2B_ISR && !control_is("P2B1I")) {
            /* the instrument's positive witness: inside the ISR the async
             * window is open, and spec blocks see it */
            CHECK(e.async_blocks == e.tbs, "P2B_ISR: %" PRIu64 " of %" PRIu64
                  " spec blocks inside the timer ISR read "
                  "qemu_plugin_in_async_int() true", e.async_blocks, e.tbs);
        } else {
            if (test == P2B_ISR) {
                fprintf(stderr, "[wp-assert] CONTROL P2B1I: B1's "
                        "in_async_int assertion applied to an excursion "
                        "launched from inside the timer ISR; it must FAIL\n");
            }
            CHECK(e.async_blocks == 0, "B1 %" PRIu64 " of %" PRIu64 " spec "
                  "blocks ran with qemu_plugin_in_async_int() true",
                  e.async_blocks, e.tbs);
        }
        break;

    case C1_MMIO:
        e.probe_addr = buf + SYS_E1K_ICS;
        if (control_is("C1N")) {
            fprintf(stderr, "[wp-assert] CONTROL C1N: the device excursion "
                    "with spec mode off; the device, the serial port and "
                    "debug-exit must see it\n");
            e.spec = false;
        }
        if (control_is("C1NS")) {
            /* three blocks: the serial write (x86 ends a block after
             * port I/O), the jump, and the page-final device store --
             * stopping short of debug-exit so the guest lives to read ICR */
            fprintf(stderr, "[wp-assert] CONTROL C1NS: the device excursion "
                    "with spec mode off, cut after its first three blocks; "
                    "the guest's ICR detector must see the store\n");
            e.spec = false;
            e.budget = 3;
            e.trace = true;
        }
        if (control_is("C1NF")) {
            fprintf(stderr, "[wp-assert] CONTROL C1NF: F12 witness -- the "
                    "C1 excursion (spec on, traced) locates the page-final "
                    "store; then the same device store placed NOT "
                    "block-final (wp_mmio_mid) runs under a spec-OFF "
                    "exec_tb\n");
            e.trace = true;
        }
        excursion(&e);
        CHECK(e.probe_hits >= 1, "C1 subject absent: no wrong-path store to "
              "the device register");
        check_common(&e, &pre, pre_sum);
        if (control_is("C1NS")) {
            f12_watch = true;
        }
        if (control_is("C1NF")) {
            /*
             * wp_mmio_mid sits at wp_mmio_st's page + 0x800
             * (wp-victim-sys.c): nop; movl $0x20,0xc8(%rdi); nop; jmp.
             * The stub addresses the device through rdi, so rdi is set to
             * the BAR for this excursion and put back after it.  A
             * spec-off exec_tb performs an MMIO access only as a block's
             * last instruction (can_do_io); here the store is neither
             * the first nor the last, so io_prepare -> cpu_io_recompile
             * must unwind every call, each time at the store's PC.
             */
            uint64_t st = e.pc_in[2];
            uint64_t mid = (st & ~0xfffull) + 0x800;
            g_autoptr(GByteArray) b = g_byte_array_new();
            static const uint8_t stub[] = { 0x90, 0xc7, 0x87, 0xc8, 0x00,
                                            0x00, 0x00, 0x20, 0x00, 0x00,
                                            0x00, 0x90 };
            bool have = (st & 0xfff) == 0xff6 &&
                qemu_plugin_read_memory_vaddr(mid, b, sizeof(stub)) &&
                b->len == sizeof(stub) &&
                memcmp(b->data, stub, sizeof(stub)) == 0;
            if (!have) {
                FAIL("C1NF subject absent: block-final store pc 0x%" PRIx64
                     " (expected page offset 0xff6), stub at 0x%" PRIx64
                     " not found", st, mid);
                break;
            }
            Exc w = { .target = mid, .budget = 3, .spec = false,
                      .restore = true, .clear = true, .vtime = true,
                      .trace = true, .persist = true,
                      .probe_addr = buf + SYS_E1K_ICS };
            struct qemu_plugin_cpu_state *s0 = qemu_plugin_cpu_state_save();
            perturb_reg("rdi", buf - read_reg64("rdi"));
            excursion(&w);
            if (!qemu_plugin_cpu_state_restore(s0)) {
                FATAL("qemu_plugin_cpu_state_restore returned false");
            }
            qemu_plugin_cpu_state_free(s0);
            int ok = 0, at_store = 0;
            for (int i = 0; i < 3; i++) {
                ok += w.call_ok[i];
                at_store += w.pc_in[i] == mid + 1;
            }
            fprintf(stderr, "[wp-assert] F12 WITNESS non-final: target=0x%"
                    PRIx64 " store_pc=0x%" PRIx64 " calls=3 ok=%d/3 "
                    "entries_at_store_pc=%d store_insn_started=%d "
                    "store_memcb=%" PRIu64 "\n",
                    mid, mid + 1, ok, at_store,
                    w.call_insns_at[1] >= 1 && w.pc_in[1] == mid + 1,
                    w.probe_hits);
            f12_watch = true;
        }
        break;

    case C2_TLB:
        e.budget = SYS_C2_PAGES + 64;
        e.c2 = true;
        e.probe_addr = SYS_PROBE;
        if (control_is("C2N")) {
            fprintf(stderr, "[wp-assert] CONTROL C2N: the %d-page excursion "
                    "with spec mode off; its translations persist and the "
                    "guest's page-fault count must FAIL\n", SYS_C2_PAGES);
            e.spec = false;
        }
        excursion(&e);
        CHECK(e.c2_pages == SYS_C2_PAGES, "C2 subject: the wrong path loaded "
              "%" PRIu64 " of %d fresh pages", e.c2_pages, SYS_C2_PAGES);
        CHECK(e.probe_hits >= 1, "C2 subject absent: no wrong-path load of "
              "the not-present probe page");
        if (e.spec) {
            CHECK(e.probe_faulted >= 1, "C2 the not-present probe load was "
                  "not flagged synthetic");
        }
        check_common(&e, &pre, pre_sum);
        break;

    case C3_GP:
    case C3_PF:
    case C3_UD:
        if (test == C3_GP && control_is("C3N")) {
            fprintf(stderr, "[wp-assert] CONTROL C3N: the CPL0 #GP with spec "
                    "mode off, no clear, no restore, in the guest's IDT-less "
                    "window; the reset callback must fire\n");
            e.spec = false;
            e.clear = false;
            e.restore = false;
            excursion(&e);
            break;
        }
        excursion(&e);
        CHECK(e.end == END_FAULT, "C3 a CPL0 wrong-path fault did not end the "
              "excursion (end=%s)", end_names[e.end]);
        CHECK(e.fdepth0 == e.fdepth1, "C3 qemu_plugin_fault_depth() moved "
              "across the excursion: %u -> %u", e.fdepth0, e.fdepth1);
        /* the reading is live: C2's correct-path #PFs (whose handler skips
         * the load, so no iret pops them) leave it well above zero here */
        fprintf(stderr, "[wp-assert] %s fault_depth %u -> %u\n",
                test_names[test], e.fdepth0, e.fdepth1);
        CHECK(resets == 0, "C3 %" PRIu64 " machine resets requested", resets);
        check_common(&e, &pre, pre_sum);
        break;

    case C4_PTW:
        e.probe_addr = SYS_C4_VA;
        if (control_is("C4N")) {
            fprintf(stderr, "[wp-assert] CONTROL C4N: the MMIO-PTE walk with "
                    "spec mode off; the device read must reach the e1000\n");
            e.spec = false;
        }
        excursion(&e);
        CHECK(e.probe_hits >= 1, "C4 subject absent: no wrong-path access at "
              "the MMIO-PTE address");
        if (e.spec) {
            CHECK(e.probe_faulted >= 1, "C4 the access through the MMIO PTE "
                  "was not flagged synthetic");
        }
        check_common(&e, &pre, pre_sum);
        break;

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
    if (test == P2_INFO && is_system) {
        /* the guest's wrong-path-only code range and its TSC rate */
        wp_lo = target;
        wp_hi = buf;
        tsc_per_ms = len;
        have_info = true;
        fprintf(stderr, "[wp-assert] P2_INFO wp=[0x%" PRIx64 ",0x%" PRIx64
                ") tsc_per_ms=%" PRIu64 "\n", wp_lo, wp_hi, tsc_per_ms);
        return;
    }
    if (test == 0 || test >= (uint64_t)n_tests) {
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
    if (is_system) {
        /*
         * The plugin's own work (register snapshots, checksums, checks)
         * is instrumentation, not guest execution: keep it off the guest
         * clock.  excursion() leaves this window around its vtime bracket
         * and re-enters it after.
         */
        qemu_plugin_vclock_pause();
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
    if (!is_system || test < P2A_CLOCK || test > P2B_ISR) {
        /*
         * (Not after the P2-A/P2-B triggers: the flush's exit and
         * retranslation are correct-path work outside every freeze, which
         * the mode=off arm those tests are compared with never does.)
         */
        qemu_plugin_request_tb_flush();
    }
    if (is_system) {
        qemu_plugin_vclock_resume();
    }
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
    if (f12_watch && !qemu_plugin_in_spec_mode()) {
        /* controls C1NS/C1NF: what the correct path translates first
         * after a spec-off device excursion */
        f12_watch = false;
        fprintf(stderr, "[wp-assert] F12 first CP translation after the "
                "witness: vaddr=0x%" PRIx64 " n_insns=%zu\n", ti->vaddr, n);
    }
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
    if (is_system) {
        /* B1's event half and qemu_plugin_in_async_int() both need the
         * per-vCPU event queue (cpu_plugin_async_enter latches the async
         * window only while it is enabled) */
        qemu_plugin_cpu_events_set(vcpu, true);
    }
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

/*
 * C3: a wrong-path fault that escalated (double fault -> triple fault) ends
 * in a machine reset request.  No test in the suite may ever cause one.
 */
static void vm_reset(qemu_plugin_id_t id, int vcpu_index, bool in_guest_insn)
{
    resets++;
    fprintf(stderr, "[wp-assert] FAIL C3: machine reset requested (vcpu %d, "
            "in_guest_insn %d)\n", vcpu_index, in_guest_insn);
    fflush(stderr);
    abort();
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    int missing = 0, seen = 0;
    for (int t = 1; t < n_tests; t++) {
        seen += tests_run[t];
    }
    if (!isa || (!seen && !require_all)) {
        /* loaded by the generic check-tcg plugin loop: nothing to do */
        return;
    }
    if (is_system) {
        fprintf(stderr, "[wp-assert] B1 events: drains=%" PRIu64
                " async_enter=%" PRIu64 " in_window=%" PRIu64
                " in_wp_code=%" PRIu64 " resets=%" PRIu64 "\n", ev_drains,
                ev_async_enter, ev_async_in_window, ev_async_in_wp, resets);
        if (enabled && tests_run[P2B_TIMER] && ev_async_enter == 0) {
            fprintf(stderr, "[wp-assert] FAIL B1: no ASYNC_ENTER was ever "
                    "drained (subject absent: the event instrument is "
                    "blind)\n");
            missing++;
        }
        if (ev_async_in_window || ev_async_in_wp) {
            fprintf(stderr, "[wp-assert] FAIL B1: %" PRIu64 " interrupts "
                    "stamped inside a window, %" PRIu64 " departing "
                    "wrong-path code\n", ev_async_in_window, ev_async_in_wp);
            missing++;
        }
    }
    for (int t = 1; t < n_tests; t++) {
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
        } else if (g_strcmp0(kv[0], "delay_us") == 0) {
            delay_us = atol(kv[1]);
        } else if (g_strcmp0(kv[0], "bdelay_us") == 0) {
            bdelay_us = atol(kv[1]);
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
    if (info->system_emulation) {
        if (!isa || strcmp(isa->target, "x86_64") != 0) {
            isa = NULL;           /* only the x86_64 system victim exists */
        } else {
            is_system = true;
            n_tests = T_LAST;
            qemu_plugin_register_vm_reset_cb(id, vm_reset);
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
