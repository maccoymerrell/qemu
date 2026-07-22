/*
 * Wrong-Path Tracing Plugin for QEMU
 *
 * Main translation unit: plugin install/lifecycle, tracing-window
 * management (windows + simpoints), the tb_trans/tb_exec/tb_flush
 * and memory-access callbacks, and exit-time statistics.  Peer TUs:
 * champsim_tracer_decode.cc, champsim_tracer_wp.cc,
 * champsim_tracer_output.cc.  Output: packed binary (.cst).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <algorithm>
#include <cstddef>
#include <execinfo.h>
#include <malloc.h>
#include <memory>
#include <new>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "champsim_tracer.h"
#include "champsim_marker.h"
#include "champsim_tracer_bb_chain_assembler.h"
#include "champsim_tracer_bb_template_cache.h"
#include "champsim_tracer_branch_history.h"
#include "champsim_tracer_marker_detect.h"
#include "champsim_tracer_mem_access_recorder.h"
#include "champsim_tracer_path_builder.h"
#include "champsim_tracer_plugin_config.h"
#include "champsim_tracer_reg_handle_cache.h"
#include "champsim_tracer_reg_snap_collector.h"
#include "champsim_tracer_scoreboard.h"
#include "champsim_tracer_simpoint_manager.h"
#include "champsim_tracer_stats.h"
#include "champsim_tracer_stats_report.h"
#include "champsim_tracer_trace_segment_manager.h"
#include "champsim_tracer_wp_thread_state.h"
#include "champsim_tracer_writer.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* ========================= Configuration ========================= */

int max_wrong_path_depth = 64;
int g_wp_prune = 0;          /* wpprune level: 0 none, 1 cold, 2 monotone */
bool enable_wrong_path = true;

/* ---- #77 diagnostic ring buffer (gated on CST_RING) -------------------
 * Records recent correct-path BB starts ('C') and wrong-path instruction
 * PCs ('W') into an in-memory ring (no I/O on the hot path).  A periodic
 * overwrite dump to /tmp/rv_ring.txt means the last dump before QEMU is
 * killed shows the steady-state CP loop + the WP running through it.  A
 * one-shot dump to /tmp/rv_ring_onset.txt fires the first time a sustained
 * near-PC CP run is seen, capturing the WP that ran BEFORE the loop formed. */
namespace {
struct CstRingEvt { char tag; uint64_t pc; };
constexpr uint32_t CST_RING_SZ = 32768;
CstRingEvt g_cst_ring[CST_RING_SZ];
uint64_t   g_cst_ring_head = 0;
int        g_cst_ring_on = -1;
uint64_t   g_cst_last_cp_pc = 0;
uint64_t   g_cst_loop_run = 0;
bool       g_cst_onset_dumped = false;

void cst_ring_dump_to(const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        return;
    }
    uint64_t n = g_cst_ring_head < CST_RING_SZ ? g_cst_ring_head : CST_RING_SZ;
    uint64_t start = g_cst_ring_head < CST_RING_SZ ? 0 : g_cst_ring_head;
    for (uint64_t i = 0; i < n; i++) {
        const CstRingEvt &e = g_cst_ring[(start + i) & (CST_RING_SZ - 1)];
        fprintf(f, "%c 0x%" PRIx64 "\n", e.tag, e.pc);
    }
    fclose(f);
}
} /* namespace */

void cst_ring_push(char tag, uint64_t pc)
{
    if (g_cst_ring_on < 0) {
        g_cst_ring_on = getenv("CST_RING") ? 1 : 0;
    }
    if (!g_cst_ring_on) {
        return;
    }
    g_cst_ring[g_cst_ring_head & (CST_RING_SZ - 1)] = { tag, pc };
    g_cst_ring_head++;

    /* Periodic overwrite dump on TOTAL event count (C or W), so a
     * wrong-path-dominated stream (runaway WP excursion) still dumps. */
    if ((g_cst_ring_head % 200000) == 0) {
        cst_ring_dump_to("/tmp/rv_ring.txt");
    }

    if (tag != 'C') {
        return;
    }
    /* Loop-onset detector: a sustained run of CP BBs within a 64 KiB window
     * (same function/region) => we have entered a tight CP loop.  Dump once. */
    uint64_t d = pc > g_cst_last_cp_pc ? pc - g_cst_last_cp_pc
                                       : g_cst_last_cp_pc - pc;
    g_cst_last_cp_pc = pc;
    if (d < 0x10000) {
        g_cst_loop_run++;
    } else {
        g_cst_loop_run = 0;
    }
    if (!g_cst_onset_dumped && g_cst_loop_run > 12000) {
        cst_ring_dump_to("/tmp/rv_ring_onset.txt");
        g_cst_onset_dumped = true;
    }
}
static char *unknown_warn_path = nullptr;
/* File for the final stats / icount report.  Opened at install time
 * so it has a valid fd even after QEMU closes stderr during the
 * guest's exit-syscall path (which would otherwise turn our
 * qemu_plugin_outs writes into EBADF).  Flushed and closed in
 * plugin_exit. */
static char *stats_path = nullptr;
static FILE *stats_file = nullptr;
static char *program_name = nullptr;
const char *target_name;
FILE *unknown_warn_file;
GMutex unknown_warn_lock;

char *qemu_command_line = nullptr;
char *trace_comment = nullptr;
TraceFeatures g_features;
uint64_t warmup_insns = 0;
uint64_t simulation_insns = 0;

/* Executable code region of the main binary, captured at plugin install
 * from qemu_plugin_start_code() / qemu_plugin_end_code().  Used to gate
 * fragment-template creation and WP speculation: a PC outside this range
 * is dynamic memory (stack/heap/data) whose contents are not stable
 * "instructions", and any "BB" the tracer would build there is
 * non-deterministic (the bytes change as the program runs).  CP never
 * leaves the executable range (that would crash the guest), so the gate
 * only ever rejects WP wrong-path divergences.  Statically-linked
 * binaries have all real code inside [start, end); for
 * dynamically-linked binaries this would need extending to track loaded
 * library text segments (TODO). */
uint64_t g_code_start = 0;
uint64_t g_code_end   = 0;

/* First-seen 4-byte instruction word per VA.  Populated at every
 * vcpu_tb_trans and consulted at subsequent translations to detect
 * bytes-changed-since-last-time at the same VA — a sure sign that the
 * "code" being translated is actually dynamic memory (stack / heap /
 * data the program is writing to) and not real instructions.  Stored
 * as plain uint32 to avoid endianness ambiguity; we only compare for
 * equality, never decode.
 *
 * Immortalized (never-destructed heap object): exit(0) at a segment
 * close runs static destructors while OTHER vCPU threads may still be
 * inside vcpu_tb_trans consulting this map — on an SMP guest the
 * closing vCPU races the survivors, and a destructed map under a live
 * reader is a straight SIGSEGV.  The process is exiting; reclaiming
 * these containers buys nothing (same policy as VCPUScoreboard). */
std::unordered_map<uint64_t, uint32_t> &g_first_insn_word =
    *new std::unordered_map<uint64_t, uint32_t>();

/* TB start_pcs that have been detected as carrying non-stable
 * instruction bytes (decode failure OR byte change since first
 * sighting).  WP speculation refuses to enter these; subsequent
 * translation re-attempts at the same start_pc skip fragment
 * materialization.  Persistent across WP simulations; cleared with
 * tb_flush. */
/* pc -> hash of the TB's full canonical byte image when the poison verdict
 * was made.  The stored content is the staleness discriminator: every VA is
 * reused across address spaces (static binaries map at the same base), so a
 * poison earned by one process's bytes must not refuse another process's
 * wrong-path target at the same VA.  A refusal only holds while the bytes
 * still match; a mismatch proves different content now lives there and
 * self-clears the entry (same principle as the merge content guard).
 * Handles exec()-time ASID reuse too, which ASID-keying would miss.  A
 * whole-TB hash rather than the first word: x86 prologues make first-word
 * collisions across unrelated binaries routine.
 * Immortalized — see g_first_insn_word. */
std::unordered_map<uint64_t, uint64_t> &g_poisoned_pcs =
    *new std::unordered_map<uint64_t, uint64_t>();

/* FNV-1a over the canonical per-insn byte image (fixed MAX_INSN_BYTES
 * stride, zero-padded, so equal content implies equal hash input). */
static uint64_t tb_bytes_hash(const uint8_t *insn_bytes, uint32_t n_insns)
{
    uint64_t h = 0xcbf29ce484222325ull;
    size_t len = (size_t)n_insns * MAX_INSN_BYTES;
    for (size_t i = 0; i < len; i++) {
        h = (h ^ insn_bytes[i]) * 0x100000001b3ull;
    }
    return h;
}

/* Both maps above are accessed from vcpu_tb_trans (translation time,
 * no lock currently held) and from the WP walker (under exec_lock).
 * Protected by data_lock — already held by vcpu_tb_trans's
 * fragment-creation critical section and acquired here briefly for
 * lookups during translation. */
thread_local SpecRefusal g_last_spec_refusal = SpecRefusal::NONE;

bool cst_pc_is_poisoned(uint64_t pc)
{
    g_mutex_lock(&data_lock);
    bool poisoned = g_poisoned_pcs.count(pc) > 0;
    g_mutex_unlock(&data_lock);
    return poisoned;
}

/*
 * Recursive: a TCG code-buffer flush during wrong-path simulation runs
 * vcpu_tb_flush() synchronously (tb_gen_code -> qemu_plugin_flush_cb)
 * while this same thread is already inside vcpu_tb_exec holding
 * exec_lock.  A non-recursive mutex self-deadlocks there (seen on
 * large-footprint workloads like gcc that fill the buffer mid-WP).
 * exec_lock is never paired with a GCond, so recursion is safe.
 *
 * Defined up here (rather than beside data_lock) so the ASID-write hook
 * — which runs off the per-TB path but ahead of this file's bulk — can
 * take it to read the owned-ASID set (see g_owned / asid_write_track_cb).
 */
static GRecMutex exec_lock;

/*
 * Address-space pin (marker mode).  When the marker fires we capture the
 * executing vCPU's ASID (x86 CR3 etc., via qemu_plugin_get_addr_space_id)
 * — the marker runs as one of the target's own instructions, so that ASID
 * IS the target's.  Thereafter vcpu_tb_exec traces only TBs whose current
 * ASID matches the pin, so a preempt into another process (a different CR3)
 * is filtered out.  In user mode the ASID is always 0, so the pin matches
 * every TB and is a no-op.  CST_ASID_UNPINNED means "not pinned" — every
 * non-marker window mode leaves it so and pays only one atomic load per TB.
 */
static const uint64_t CST_ASID_UNPINNED = UINT64_MAX;
static std::atomic<uint64_t> g_pinned_asid{CST_ASID_UNPINNED};

/*
 * Owned-ASID set (multi-ASID Stage B, wide-register targets).  The set of
 * page-table roots (x86 CR3 / AArch64 TTBR / RISC-V SATP values, as
 * reported by qemu_plugin_get_addr_space_id) currently INSIDE tracer
 * vision — each process that ran the START marker and has not yet run its
 * END marker.  A single-process trace is a set of one, so every legacy
 * consumer behaves exactly as it did against the single pin.
 *
 * Generalizes the single g_pinned_asid gate: `g_pinned_asid` is retained
 * as the FIRST/representative owned root (so the narrow-ASID MIPS path,
 * pin_effective_asid, cst_pinned_asid_root/sig and the "marker mode armed"
 * predicate keep working single-process), while the actual foreign-drop
 * predicate (pin_user_tb_owned, wide-register) and the coarse-FF
 * asid_match flag consult SET MEMBERSHIP here.
 *
 * Mutated only at marker START/END, under exec_lock (the marker callbacks
 * already hold it around the segment open/close).  Read under exec_lock in
 * pin_user_tb_owned (the caller holds it) and, off the per-TB path, in the
 * ASID-write hook (which takes exec_lock for the read).  Kept consistent
 * with the Stage-A index map: every root added here is also assigned a
 * compact asid index + stored identity {root_phys, sig}.  The narrow-ASID
 * (MIPS, g_pin_reuse_guard) path does NOT use this set — it keeps its
 * dwell/verify machinery (Stage B3), so g_owned stays empty there.
 */
static std::unordered_set<uint64_t> &g_owned =
    *new std::unordered_set<uint64_t>();

/* Caller holds exec_lock.  Is @root a currently-owned address space? */
static inline bool owned_contains_locked(uint64_t root)
{
    return g_owned.count(root) != 0;
}

/* Marker-window multi-process policy (PluginConfig::MarkerPolicy), set at
 * install from trace_window=marker:policy=.  latch (default) is Stage B1;
 * trace-all is Stage B2. */
static int g_marker_policy = 0;   /* PluginConfig::MARKER_LATCH */

/*
 * Trace-all gating (Stage B2).  The FIRST marker emission opens the segment
 * and begins tracing EVERY context/ASID — no foreign-drop, no ownership
 * filter — until that first process runs its END marker (or the icount
 * budget is met).  Only the CAPTURE gate widens: the clock and END detection
 * keep riding the single marker-process pin (g_owned stays the set-of-one
 * clock pin), exactly as the latch/single-pin machinery already does.  All
 * ISAs: the widening is identical; the narrow-ASID (MIPS) dwell machinery
 * still serves the clock, its capture-side verification is simply bypassed. */
static inline bool marker_trace_all(void)
{
    return g_marker_policy == PluginConfig::MARKER_TRACE_ALL;
}

/*
 * Dead-latch detector (marker latch mode).  A latched process that exits
 * WITHOUT running its END marker would otherwise leave its window open
 * forever — "all windows closed" never fires and only the icount budget
 * closes the segment.  On Linux a process's death tears down its mm, so its
 * page-table root (the owned ASID) is never loaded again: a stale
 * last-schedule-in is a death signal.  We stamp each owned root's last
 * schedule-in wall time and, off the hot path (the ASID-write hook), close
 * any window idle past g_latch_timeout_ms exactly as its END marker would;
 * when the last window closes this way the segment shuts down (the backstop
 * for an all-died SIGKILL).  0 (default) disables it: the wall-clock idle
 * signal cannot tell a dead process from a merely long-idle live one, so
 * the detector is opt-in via latch_timeout=<ms> (see PluginConfig). */
static uint64_t g_latch_timeout_ms = 0;

/* Per-owned-root last schedule-in (wall ms), wide-register path.  The
 * narrow-ASID (MIPS) path carries the equivalent as OwnedProc.last_sched_ms.
 * Guarded by exec_lock, like g_owned; immortal. */
static std::unordered_map<uint64_t, uint64_t> &g_owned_last_sched =
    *new std::unordered_map<uint64_t, uint64_t>();

/* Monotonic wall-clock milliseconds.  Unlike g_user_icount (which freezes
 * when no owned process runs, so an all-died set could never age out), this
 * keeps advancing regardless of guest scheduling.  Read only off the hot
 * path (owner creation, dwell re-confirm, the ASID-write hook). */
static inline uint64_t deadlatch_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Off-hot-path staleness sweep, driven from the synchronous ASID-write
 * hook — defined after finish_trace_segment / data_lock are in scope. */
static void deadlatch_on_asid_write(unsigned int vcpu_index,
                                    uint64_t new_asid);

/* Progress-driven peer sweep cadence: while an owned process runs, check
 * for dead PEER windows every this many of its user-instructions (the
 * design's "segment-budget threshold crossing" trigger).  This makes a
 * live dominant process age out a dead peer through its OWN progress —
 * independent of how often the guest happens to write the address-space
 * register — and refreshes the running window's own stamp so it is never
 * itself false-aged.  Reset per segment (user_count_reset). */
static constexpr uint64_t DEADLATCH_UIC_STRIDE = 8192;
static uint64_t g_deadlatch_checked_uic = 0;
static void deadlatch_clock_check(unsigned int cpu_index, uint64_t live_asid);

/*
 * Translation-bypassing privilege level (see champsim_tracer.h).  The pin
 * identifies a process by the value of the target's address-space register,
 * which presumes execution actually translates through that register.  On
 * RISC-V the highest privilege level breaks that presumption: M-mode
 * fetches and loads/stores bypass satp entirely (the privileged spec makes
 * M-mode accesses untranslated regardless of satp.MODE), so firmware
 * handling a synchronous SBI ecall executes while the pinned process's
 * satp sits untouched in the register.  Without a gate those TBs read as
 * "pinned + kernel" and the trace absorbs OpenSBI as the process's kernel
 * work.  No other supported target has an equivalent level: x86 ring 0 and
 * Arm EL1 translate through the reported register, and MIPS kernel mode —
 * though it fetches through unmapped kseg segments — IS the level the OS
 * serves the process's syscalls and faults at, i.e. exactly the kernel
 * work the trace wants, where RISC-V M-mode is firmware a level above the
 * OS kernel.
 */
int g_xlate_bypass_priv = -1;

/*
 * User-space instruction count for the pinned process (the count set).
 * The raw insn_count inline-add stays unconditional (fast), counting every
 * TB.  When pinned, vcpu_tb_exec derives each TB's instruction count as the
 * delta of consecutive insn_count reads and folds it into g_user_icount
 * ONLY for counted TBs — pinned ASID at user privilege.  Kernel calls of the
 * pinned process (priv != 0, same ASID) are traced but NOT counted, and
 * other processes (different ASID) are neither.  So the window budget tracks
 * the same user-space instructions a user-mode run would, while the trace
 * still captures the interleaved kernel.  Reset at each segment open via
 * user_count_reset(); only touched when pinned, so user mode is unaffected.
 */
static uint64_t g_user_icount = 0;       /* counted user-space insns so far */

/* Set when the segment is closed by the guest's end marker (the workload
 * finished under budget by design) so the finish printout reports END
 * rather than an UNDER underrun. */
static bool g_seg_end_marker_close = false;

/* CST_MARKER_DIAG: trace every correct-path invocation of the marker exec
 * callbacks (plus WP-gated / step-bail counters) to stderr.  Diagnostic
 * only — no effect on the trace. */
static inline bool marker_diag(void)
{
    static std::atomic<int> v{-1};
    int x = v.load(std::memory_order_relaxed);
    if (x < 0) {
        x = getenv("CST_MARKER_DIAG") ? 1 : 0;
        v.store(x, std::memory_order_relaxed);
    }
    return x != 0;
}
static thread_local uint64_t tls_mkdiag_end_wp_gated = 0;
static thread_local uint64_t tls_mkdiag_start_wp_gated = 0;
/* Step-bail counters for pinned user-privilege TBs (diag): a stall of the
 * user clock while the guest keeps running shows up here. */
static thread_local uint64_t tls_mkdiag_susp_user = 0;
static thread_local uint64_t tls_mkdiag_foreign_user = 0;

/*
 * Reset the user clock at a pin/segment boundary.  The per-vCPU seen
 * cursors (scoreboard user_seen; each vCPU's fold computes its delta
 * against its OWN insn_count slot) start over: the calling vCPU's cursor
 * is seated exactly at @insn_count_now — its own count, already including
 * the marker TB — so the very next TB's insns are the clock's first
 * contribution; every other vCPU's cursor goes to the unprimed sentinel
 * and self-seats, contributing 0, at that vCPU's first fold (its
 * pre-reset insns must not leak into the fresh clock).
 */
static inline void user_count_reset(unsigned int cpu_index,
                                    uint64_t insn_count_now)
{
    g_user_icount = 0;
    g_deadlatch_checked_uic = 0;
    for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; i++) {
        qemu_plugin_u64_set(g_scoreboard.user_seen, (unsigned)i,
                            (unsigned)i == cpu_index
                                ? insn_count_now : USER_SEEN_UNPRIMED);
    }
}

/* One vCPU-local tick of the user clock's delta source: this vCPU's
 * insn_count advance since its last fold.  Self-seats on the first fold
 * after a reset (delta 0).  Caller decides whether the delta is COUNTED
 * (pinned ASID at user privilege) — the cursor advances either way. */
static inline uint64_t user_seen_advance(unsigned int cpu_index,
                                         uint64_t insn_count_now)
{
    uint64_t seen = qemu_plugin_u64_get(g_scoreboard.user_seen, cpu_index);
    qemu_plugin_u64_set(g_scoreboard.user_seen, cpu_index, insn_count_now);
    return seen == USER_SEEN_UNPRIMED ? 0 : insn_count_now - seen;
}

/*
 * Coarse fast-forward (pinned-simpoint positioning).  The exact
 * positioning path — is_active=1 so vcpu_tb_exec dispatches per TB —
 * costs a register-synced callback plus two state-hook calls per TB,
 * which caps fast-forward well below plain emulation speed.  Over the
 * hundreds of billions of instructions between the pin and a simpoint,
 * that dominates wall time.
 *
 * While g_ff_coarse is set, the per-vCPU budget slot is repurposed as a
 * countdown of USER-MODE instructions: the JIT-inlined decrement and its
 * crossing detector are registered only on TBs translated at priv==0
 * (privilege is part of the TB context key, so a TB translated in user
 * context only ever executes in user context), and is_active stays 0 so
 * no callback dispatches at all.  The countdown target is set
 * FF_COARSE_MARGIN short of the simpoint's effective start;
 * vcpu_tb_check_budget hands the final stretch to the exact path.
 *
 * Exactness: a JIT inline op cannot test the live ASID, so the raw
 * decrement counts every process's user instructions.  The correction
 * rides the scoreboard asid_match flag — maintained by the synchronous
 * ASID-write hook at the architectural commit points, so it is exact at
 * every user TB with zero per-TB maintenance — via a compensating
 * cond_cb registered between the decrement and the crossing detector:
 * when asid_match == 0 (a foreign process's user TB), a trivial
 * callback adds the decrement back and tallies the foreign count.  The
 * countdown therefore counts exactly the PINNED process's user
 * instructions; concurrent user workloads (e.g. a duplicate of the
 * traced program) cost only the tiny add-back call on their own TBs,
 * never positioning error.  The pinned process's TBs pay one untaken
 * JIT compare.
 *
 * The only uncompensated sliver is the handful of TBs between the pin
 * and the pin-time flush landing (pre-pin TBs carry the unconditional
 * decrement); it is bounded by a few TBs' worth of instructions and
 * fires the crossing EARLY, never late.  Multi-vCPU guests skip the
 * coarse leg entirely: the budget slots are per-vCPU but the user
 * clock is global.
 */
static std::atomic<bool> g_ff_coarse{false};
static uint64_t g_ff_coarse_target = 0;   /* user insns from pin to handoff */
static uint64_t g_ff_foreign_insns = 0;   /* compensated foreign user insns */
static constexpr uint64_t FF_COARSE_MARGIN = 200000000;   /* 200M-insn exact tail */

/* Compensation callback for the coarse countdown: fires (via cond_cb
 * on asid_match == 0) only on user TBs executed by a process other
 * than the pinned one; adds the TB's unconditional decrement back so
 * the countdown nets to pinned-process user instructions only.  udata
 * carries the TB's raw insn count.  Post-handoff stale firings (before
 * the handoff flush lands) add to the sentinel-parked budget —
 * harmless headroom. */
static void vcpu_tb_ff_foreign(unsigned int cpu_index, void *udata)
{
    uint64_t n = (uint64_t)(uintptr_t)udata;
    qemu_plugin_u64_add(g_scoreboard.budget, cpu_index, n);
    g_ff_foreign_insns += n;
}

/*
 * Pinned-ASID reuse detector (narrow-ASID targets; currently MIPS).
 *
 * The MIPS pin is a bare EntryHi.ASID value from an architecturally
 * 8-bit field (10 bits with Config4.AE) — a space small enough that the
 * OS must recycle values.  Linux does so by generations: on rollover
 * every live process is silently handed a fresh ASID, so the pinned
 * VALUE can be re-assigned to a different process and the raw-equality
 * pin follows the wrong one from then on.  The rollover itself is
 * invisible in the register stream, but its footprint is not: the
 * committed ASID-write stream (this hook) shows the pinned value going
 * absent while a large share of the whole space is written with OTHER
 * values.  Seeing >= PIN_REUSE_THRESHOLD distinct other values between
 * two writes of the pinned value implies the space wrapped, so the
 * pinned value's return is suspect.  Detection only — one stderr
 * warning per pin plus the pin_asid_reuse_suspected stat; whether to
 * unpin is a policy decision deliberately not taken here.
 *
 * Not armed on the wide-register targets (CR3 / TTBR0 / SATP carry a
 * page-table base): distinct-value counts there measure how many
 * processes ran, not how much of an exhaustible ID space burned, so the
 * same signal would false-fire on any busy guest.
 *
 * Cost: one bounded scan per committed ASID change (a context-switch-
 * rate event), only while pinned.  Fixed POD state — no ctor/dtor
 * ordering against plugin_exit to manage.
 */
static bool g_pin_reuse_guard = false;   /* armed at install (narrow space) */
static constexpr uint32_t PIN_REUSE_THRESHOLD = 200;
static GMutex pin_reuse_lock;
static uint64_t g_pin_reuse_vals[PIN_REUSE_THRESHOLD];
static uint32_t g_pin_reuse_nvals = 0;   /* distinct non-pinned values since
                                          * the pinned value's last write;
                                          * saturates at the threshold */
static bool g_pin_reuse_warned = false;  /* one warning per pin */

static void pin_reuse_reset(void)
{
    g_mutex_lock(&pin_reuse_lock);
    g_pin_reuse_nvals = 0;
    g_pin_reuse_warned = false;
    g_mutex_unlock(&pin_reuse_lock);
}

static void pin_reuse_track(uint64_t new_asid, uint64_t pinned_asid)
{
    g_mutex_lock(&pin_reuse_lock);
    if (new_asid == pinned_asid) {
        if (g_pin_reuse_nvals >= PIN_REUSE_THRESHOLD) {
            g_stats.pin_asid_reuse_suspected++;
            if (!g_pin_reuse_warned) {
                g_pin_reuse_warned = true;
                fprintf(stderr, "champsim_tracer: pinned ASID value 0x%"
                        PRIx64 " re-assigned after apparent rollover (%u "
                        "distinct other ASID values since its last write) "
                        "— trace may follow a different process\n",
                        pinned_asid, g_pin_reuse_nvals);
            }
        }
        g_pin_reuse_nvals = 0;          /* a fresh absence window opens */
    } else if (g_pin_reuse_nvals < PIN_REUSE_THRESHOLD) {
        bool seen = false;
        for (uint32_t i = 0; i < g_pin_reuse_nvals; i++) {
            if (g_pin_reuse_vals[i] == new_asid) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            g_pin_reuse_vals[g_pin_reuse_nvals++] = new_asid;
        }
    }
    g_mutex_unlock(&pin_reuse_lock);
}

/*
 * Physical-page process identity (narrow-ASID targets; currently MIPS).
 *
 * The wide-register targets pin a page-table base (CR3 / TTBR0 / SATP):
 * equality is stable per process and distinct across processes for the
 * whole run.  MIPS exposes no such register — the CP0 audit recorded in
 * mips_get_plugin_state (target/mips/cpu.c) found Context.PTEBase is a
 * per-CPU constant on a 32-bit Linux guest and KScratch / MemoryMapID
 * absent from the 24K/34K-class models — so the bare EntryHi.ASID pin
 * inherits every weakness of an 8-bit, per-CPU, generation-recycled
 * space: a rollover hands the pinned VALUE to a foreign process (whose
 * user code then traces as if pinned), hands the pinned PROCESS a new
 * value (its execution stops matching), and a migration lands the
 * process on a vCPU where its per-CPU ASID differs from the pin.
 *
 * The identity that survives all three is the user code itself: the
 * pinned process's code pages carry the same BYTES no matter which
 * ASID value or vCPU it currently holds, while a foreign process
 * aliasing the same virtual addresses runs different bytes (a distinct
 * binary at that VA) — and byte-identical code shared from the page
 * cache is the same content, which the trace records identically
 * either way.  So on narrow-ASID targets the pin's AUTHORITY is a map
 * of executed user-code pages (virtual page -> {physical page, content
 * signature}), seeded at the marker and grown by every verified user
 * TB; the per-vCPU ASID value is a dwell tag:
 *
 *   - an ASID write ends the vCPU's dwell (confirmed=false; the value
 *     may have been handed to anyone);
 *   - the first user TB of a dwell must probe the map: a hit-match
 *     confirms the dwell (one probe per context switch, not per TB); a
 *     content MISMATCH on a mapped page is a foreign process and the
 *     TB is dropped; an unmapped page stays unverified and the TB is
 *     dropped (the genuine process resumes on a page it has executed,
 *     so it confirms immediately; a foreign process that never touches
 *     mapped pages parks unverified forever — traced never);
 *   - a user TB probing hit-match under a DIFFERENT ASID value
 *     re-acquires the process: the vCPU's dwell tag re-pins to the live
 *     value (rollover re-numbering and cross-vCPU migration both land
 *     here, one-TB lossy).
 *
 * The physical frame is the FAST path, not the authority: a frame match
 * confirms without touching guest memory, but a frame mismatch is not
 * proof of a foreign process — the guest evicts a clean file-backed
 * code page under memory pressure and re-faults it to a DIFFERENT frame
 * with identical bytes (observed reliably across the churn test's sleep
 * window: 512 MiB guest, hundreds of short-lived processes).  Anchoring
 * on the frame alone stalled there — the marker page, the map's only
 * seed, re-faulted while the pinned process slept, so every revisit
 * mismatched and the process (its entire hot region unmapped, having
 * run only post-rollover) never re-acquired.  Content is the true
 * invariant: on a frame mismatch the probe reads the page's bytes and
 * compares their signature, so a re-faulted page reads as a hit (and
 * refreshes its frame) while a genuinely foreign page reads as a
 * mismatch.  Reading guest memory is confined to that mismatch path —
 * the frame fast-path and the confirmed-dwell hot path never touch it.
 *
 * Verification runs only on narrow-ASID targets (g_pin_reuse_guard) in
 * the CP step glue under exec_lock — the map needs no lock of its own;
 * the marker's seed takes exec_lock around it.  The map is immortal
 * (see "Immortal process-wide aggregates" in docs/architecture.rst) and
 * reset at each marker fire.  Known residual, accepted: two live
 * instances of the SAME binary share byte-identical text, so a
 * re-acquisition cannot tell them apart (their user code is identical;
 * data capture may interleave) — the duplicate-binary discriminator
 * would need private (written) page anchors, deliberately not spent
 * here.
 */
static constexpr unsigned CST_PIN_MAX_VCPUS = 1024;
struct PinVcpuState {
    /* The ASID value the pinned process most recently held on this
     * vCPU (dwell tag), CST_ASID_UNPINNED until first acquisition. */
    std::atomic<uint64_t> asid{CST_ASID_UNPINNED};
    /* Current dwell verified by a map hit.  Cleared by every committed
     * ASID write on this vCPU; set by the step glue's probe. */
    std::atomic<bool> confirmed{false};
    /* Which owned process this vCPU's confirmed dwell belongs to — an
     * index into g_owned_procs (multi-ASID Stage B3, narrow-ASID targets).
     * -1 until first acquisition; also retained across an unconfirmed span
     * as the O(1) re-probe hint (the value recycled but the process usually
     * resumes as the same owner).  Single-owner (legacy / wide) leaves it
     * 0 / unused. */
    std::atomic<int> owner{-1};
};
static PinVcpuState g_pin_vcpu[CST_PIN_MAX_VCPUS];
/* One learned code page.  @ppage is the fast-path frame identity (last
 * seen); @sig is the content signature, the authority that survives a
 * re-fault to a new frame. */
struct PinPage {
    uint64_t ppage;
    uint64_t sig;
};
static constexpr uint64_t PIN_PAGE_MASK = ~(uint64_t)0xFFF;

/*
 * One owned process on a narrow-ASID target (MIPS), multi-ASID Stage B3.
 *
 * Generalizes the single g_pin_page_map: each process that ran a START
 * marker (and has not run its END marker) is one OwnedProc with its OWN
 * learned-code-page map — because an 8-bit EntryHi.ASID cannot name a
 * process by value, the page map itself IS the process's identity.  A
 * vCPU's dwell confirms against WHICHEVER owned process's map matches the
 * executing user code (pin_map_probe_owners), and capture attributes to
 * that owner.
 *
 * The stable wire handle is @root_phys — the marker code page's PHYSICAL
 * address (a real, stable physical anchor; MIPS exposes no readable pgd
 * root, so this deviates from multiasid_plan §2's "pgd root", see
 * marker_anchor()).  @root_phys + @marker_sig ride the BODY_TAG_ASID_SWITCH
 * first-sighting identity and, mapped through asid_root_to_index, give the
 * owner a compact wire asid_index that is STABLE across an EntryHi.ASID
 * rollover (the raw value is never the wire key).  A single owner reduces to
 * the former single-pin behaviour; user mode (asid 0) uses root_phys/sig
 * (0,0) so user traces stay byte-identical.
 *
 * @active is cleared (not erased) when the process runs its END marker, so
 * PinVcpuState.owner indices stay valid for the segment; the vector is
 * reset only at a marker-driven re-seed (pin_owned_reset_single).  Immortal
 * (see docs/architecture.rst "Immortal process-wide aggregates"); guarded
 * by exec_lock, like the map it replaces.
 */
struct OwnedProc {
    std::unordered_map<uint64_t, PinPage> pages;   /* vpage -> {ppage, sig} */
    uint64_t root_phys = 0;          /* stable wire anchor (marker page phys) */
    uint64_t marker_sig = 0;         /* content signature companioning it */
    uint64_t repr_vpage = UINT64_MAX;/* lowest learned code vpage (text start) */
    bool     active = false;         /* false after this process's END marker */
    uint64_t last_sched_ms = 0;      /* wall time of last confirmed dwell —
                                      * dead-latch liveness (see deadlatch_*) */
};
/* The owned-process set (narrow-ASID Stage B3).  Immortal; guarded by
 * exec_lock.  Empty on wide-register targets (they use g_owned + the
 * live-root equality gate); populated only on g_pin_reuse_guard targets. */
static std::vector<OwnedProc> *g_owned_procs;
/* Count of ACTIVE owners (windows currently open) — the narrow-ASID sibling
 * of g_owned.size(); drives the last-window-close decision at END. */
static int g_owned_procs_active = 0;
/* Bytes hashed for a page's content signature.  Page-bounded (< 4 KiB)
 * so the read never straddles into an unmapped successor page; 256
 * bytes of code discriminates any two distinct binaries at a shared
 * virtual page. */
static constexpr size_t PIN_SIG_BYTES = 256;

/*
 * Representative content signature of the pinned address space (Phase 2
 * ASID identity — see multiasid_plan.md §2).  It disambiguates a
 * page-table root physical address reused after a process dies, and rides
 * the BODY_TAG_ASID_SWITCH record's first-sighting identity next to the
 * root.
 *
 * Snapshotted at pin time from the MARKER instruction's own code page, so
 * it is non-zero for EVERY pinned target — including the wide-register
 * pins (x86 CR3 / AArch64 TTBR / RISC-V SATP) that never populate the
 * per-owner page maps (those, and their per-owner "text start" anchors,
 * exist only on the narrow-ASID MIPS reuse-guard path — see OwnedProc).
 * On the narrow-ASID path each OwnedProc carries its OWN marker-page
 * signature; this global representative serves the wide pins and the
 * single-owner legacy path.  It is a fixed, deterministic FNV-1a of a
 * real code page.
 *
 * Written only under exec_lock (the pin-fire seed and pin_map_learn);
 * @g_pin_repr_sig is atomic so cst_pinned_asid_sig() can read it O(1) on
 * the emit hot path (it is evaluated on every body entry, though the wire
 * consumes it only at the ASID index's first sighting) without asserting
 * the lock.  0 when unpinned (user mode / no marker) — keeping user
 * traces byte-identical. */
static std::atomic<uint64_t> g_pin_repr_sig{0};
static uint64_t g_pin_repr_vpage = UINT64_MAX;   /* lowest learned code vpage */

/*
 * Phase-2 ASID identity accessors for the body-stream emit path
 * (body_stream_write_entry, output.cc), which runs under exec_lock as does
 * every writer of these values.
 */
uint64_t cst_pinned_asid_root(void)
{
    /* g_pinned_asid caches qemu_plugin_get_addr_space_id() = the
     * page-table root physical address (x86 CR3 with PCID/NOFLUSH already
     * masked, AArch64 TTBR base, RISC-V SATP PPN, MIPS pgd).  Unpinned
     * (user mode / no marker) → 0, the single-user-address-space id. */
    uint64_t a = g_pinned_asid.load(std::memory_order_relaxed);
    return a == CST_ASID_UNPINNED ? 0 : a;
}

uint64_t cst_pinned_asid_sig(void)
{
    /* A signature companions a REAL (non-zero) page-table root — i.e. a
     * system-mode pin.  User mode (and unpinned) reports root 0, so the
     * signature is 0 too, keeping those traces byte-identical: a user-mode
     * marker trace pins the address-space register's user value (0 in
     * linux-user), which is a valid pin but NOT a real page-table root. */
    if (cst_pinned_asid_root() == 0) {
        return 0;
    }
    return g_pin_repr_sig.load(std::memory_order_relaxed);
}

/*
 * Guest-thread identity for a system-mode pin.
 *
 * The wire's thread_id names a GUEST thread, not the vCPU it happens to
 * run on: a thread that migrates across vCPUs keeps one identity, and two
 * threads time-slicing one vCPU are two identities.  The vCPU index (the
 * QEMU cpu_index) is a scheduling slot and never reaches the wire.
 *
 * The kernel-maintained per-thread pointer register (x86 FS/GS.base,
 * AArch64 TPIDR_EL0, RISC-V tp, MIPS CP0 UserLocal — qemu_plugin_get_
 * thread_ptr) is that identity: every mainstream kernel context-switches
 * it per software thread.  A per-SEGMENT map assigns each distinct value a
 * compact tid in first-sighting order (0, 1, 2, …), so a single-threaded
 * pinned process is always tid 0 regardless of vCPU, and the field width
 * (small ints) is never stressed.  The map is meaningful only at USER
 * privilege for the pinned process; it is populated exactly where the pin
 * machinery already confirms that context (a user-owned priv-0 TB).
 *
 * g_vcpu_cur_tid[c] tracks the tid of the most recent user TB on vCPU c;
 * kernel TBs of the pinned process carry it unchanged (they inherit the
 * thread that entered the kernel), and it is advanced AFTER the deferred-
 * prev seal so an emitted BB is attributed to the thread that executed it,
 * not the one about to run next.  Both structures are guarded by exec_lock
 * (every sample and every emit runs under it) and reset per segment.
 *
 * Degradation, documented: a target/model whose thread pointer is never
 * written (no MIPS Config3.ULRI, a guest that sets no TLS) reports 0 for
 * every thread, so all threads collapse to tid 0 — honest indistinctness,
 * not fabricated identity.
 */
static std::unordered_map<uint64_t, uint32_t> *g_thread_tid_map;
static uint32_t g_thread_tid_next = 0;
static uint32_t g_vcpu_cur_tid[CST_PIN_MAX_VCPUS];

/* g_vcpu_cur_asid_index[c] is the address-space sibling of g_vcpu_cur_tid:
 * the compact asid index of the most recent USER TB on vCPU c.  A kernel
 * excursion of the pinned process inherits it unchanged, so the thread's
 * regfile/FieldState CONTEXT stays keyed on the ENTERING process's user CR3
 * across user<->kernel (option a: the context asid is the process asid,
 * decoupled from the per-entry MEMORY asid, which keeps the live kernel CR3
 * tag on the wire).  Reset / seeded / advanced in lockstep with
 * g_vcpu_cur_tid; guarded by exec_lock and reset per segment. */
static uint32_t g_vcpu_cur_asid_index[CST_PIN_MAX_VCPUS];

/*
 * Pinned-process migration-detect guard (system-mode pin, SMP guests).
 *
 * The wire is single-address-space by construction: a marker-mode trace
 * pins ONE process, every VA is that process's, and thread_id distinguishes
 * the software threads WITHIN it (see docs/architecture.rst, "Single
 * address space").  Clean per-thread attribution therefore relies on the
 * pinned process NOT migrating across vCPUs — kernel code carries no
 * architecturally-reliable per-thread identity (the thread pointer is a
 * USER register; no ISA exposes a kernel-privilege one), so a thread the
 * guest scheduler moves between vCPUs leaves the kernel work on the vCPU it
 * left with no clean owner.  cst_attach pins the target to a single guest
 * CPU by default, keeping it inside the clean-attribution envelope; this
 * guard makes the misuse loud rather than silent when it is not pinned.
 *
 * g_pin_user_vcpu_mask records, per segment, which vCPUs the pinned process
 * ran USER code on (one bit per cpu_index).  When its population first
 * exceeds one the process is migrating: emit ONE stderr warning and bump a
 * stat.  The vCPU index is architectural (known to the plugin) and stays
 * OFF the wire — this is a diagnostic, not trace content.  Reset per
 * segment; guarded by exec_lock.
 */
static uint64_t g_pin_user_vcpu_mask = 0;
static bool g_pin_multivcpu_warned = false;
/* Per-vCPU cache of the last thread-pointer value mapped, so the hot path
 * re-maps only when the value actually changes (a thread's pointer is
 * constant while it runs).  CST_TP_UNSEEN is a non-canonical sentinel no
 * real thread pointer takes, forcing a re-map on the first TB of a
 * segment. */
static constexpr uint64_t CST_TP_UNSEEN = UINT64_MAX;
static uint64_t g_vcpu_last_tp[CST_PIN_MAX_VCPUS];

/* CST_TIDDIAG: emit (thread_ptr -> tid) and (vcpu <-> tid) bindings to
 * stderr so an offline check can confirm the wire's tid is decoupled from
 * the vCPU (one tid spanning vCPUs = migration; two tids on one vCPU =
 * time-slice).  vCPU never reaches the wire; this is a stderr-only aid. */
static bool tiddiag_on(void)
{
    static int flag = -1;
    if (flag < 0) {
        flag = getenv("CST_TIDDIAG") ? 1 : 0;
    }
    return flag != 0;
}

/* Log the first sighting of each distinct (vCPU, tid) pair.  A set-based
 * record (not a per-vCPU transition) is what captures a migrating thread
 * whose tid happens to equal a fresh vCPU's initial tid — the exact case a
 * transition edge misses.  Caller holds exec_lock. */
static void tiddiag_note_binding(unsigned int cpu_index, uint32_t tid)
{
    static std::unordered_set<uint64_t> *seen;
    if (!seen) {
        seen = new std::unordered_set<uint64_t>();
    }
    uint64_t key = ((uint64_t)cpu_index << 32) | tid;
    if (seen->insert(key).second) {
        fprintf(stderr, "champsim_tracer: [tiddiag] binding vcpu=%u tid=%u\n",
                cpu_index, tid);
    }
}

/* Map a guest thread-pointer value to its compact per-segment tid
 * (first-sighting order).  Caller holds exec_lock and has established the
 * value was sampled at user privilege for the pinned process. */
static uint32_t thread_ptr_to_tid(uint64_t tp)
{
    if (!g_thread_tid_map) {
        g_thread_tid_map = new std::unordered_map<uint64_t, uint32_t>();
    }
    auto it = g_thread_tid_map->find(tp);
    if (it != g_thread_tid_map->end()) {
        return it->second;
    }
    uint32_t tid = g_thread_tid_next++;
    g_thread_tid_map->emplace(tp, tid);
    if (tiddiag_on()) {
        fprintf(stderr, "champsim_tracer: [tiddiag] new guest thread: "
                "thread_ptr=0x%" PRIx64 " -> tid=%u\n", tp, tid);
    }
    return tid;
}

/* Note that the pinned process ran USER code on vCPU @cpu_index, and fire
 * the migration-detect guard the FIRST time in a segment that it is seen on
 * more than one vCPU.  Caller holds exec_lock, at a user-owned priv-0 TB of
 * the pinned process.  Architectural (vCPU index) diagnostic — off the wire. */
static void pin_user_vcpu_observe(unsigned int cpu_index)
{
    if (cpu_index >= 64) {
        return;
    }
    uint64_t before = g_pin_user_vcpu_mask;
    g_pin_user_vcpu_mask |= (uint64_t)1 << cpu_index;
    if (before != 0 && g_pin_user_vcpu_mask != before &&
        !g_pin_multivcpu_warned) {
        g_pin_multivcpu_warned = true;
        g_stats.pin_multivcpu_observed++;
        fprintf(stderr,
            "champsim_tracer: pinned process ran user code on multiple vCPUs "
            "in one segment — pin it to a core (cst_attach does this by "
            "default; or use taskset/isolcpus) for clean per-thread "
            "attribution.  A migrating pinned process is outside the "
            "single-address-space tracer's clean-attribution envelope: its "
            "user-code thread_id still follows the thread, but kernel code it "
            "leaves on a vacated vCPU has no architecturally-clean owner.\n");
    }
}

/* Reset the per-segment guest-thread identity map and every vCPU's current
 * tid.  Caller holds exec_lock (via reset_segment_local_state). */
static void thread_identity_reset(void)
{
    if (g_thread_tid_map) {
        g_thread_tid_map->clear();
    }
    g_thread_tid_next = 0;
    for (unsigned i = 0; i < CST_PIN_MAX_VCPUS; i++) {
        g_vcpu_cur_tid[i] = 0;
        g_vcpu_cur_asid_index[i] = 0;
        g_vcpu_last_tp[i] = CST_TP_UNSEEN;
    }
    g_pin_user_vcpu_mask = 0;
    g_pin_multivcpu_warned = false;
}

/* The thread_id stamped on an emitted body entry.  System-mode pin: the
 * guest-thread identity (stable across vCPU migration).  User mode and any
 * unpinned run: the vCPU index verbatim, exactly as before this mapping
 * existed, so those traces stay byte-identical. */
static inline uint32_t resolve_thread_id(unsigned int cpu_index)
{
    if (g_pinned_asid.load(std::memory_order_relaxed) != CST_ASID_UNPINNED &&
        cpu_index < CST_PIN_MAX_VCPUS) {
        return g_vcpu_cur_tid[cpu_index];
    }
    return (uint32_t)cpu_index;
}

/*
 * Compact per-entry ASID index — the address-space sibling of the
 * guest-thread tid above, built the same way.  The wire's asid_index
 * names an ADDRESS SPACE (a page-table root), not the vCPU running in it:
 * a per-SEGMENT map assigns each distinct root physical address a compact
 * index in first-sighting order (0, 1, 2, …), so a single-address-space
 * trace is always index 0 (user mode's root is 0 → index 0 too) and the
 * field width is never stressed.  A parallel identity store records each
 * index's identity — its page-table root physical address and a content
 * signature — so the body-stream emit can carry that identity inline on
 * the index's first sighting (mirroring the register-file snapshot).
 *
 * Both structures are guarded by exec_lock (every sample and every emit
 * runs under it) and reset per segment, exactly like the tid map.  In
 * Stage A there is a single address space, so every entry resolves to
 * index 0 and the output stays byte-identical to the single-thread wire;
 * Stage B (multi-process gating) is what activates further indices.
 */
struct AsidIdentity {
    uint64_t root_phys;   /* page-table root physical address (0 = user) */
    uint64_t sig;         /* content signature companioning a real root */
};
static std::unordered_map<uint64_t, uint32_t> *g_asid_index_map;
static std::vector<AsidIdentity> *g_asid_identity_store;
static uint32_t g_asid_index_next = 0;

/* Map a page-table root physical address to its compact per-segment asid
 * index (first-sighting order), recording the index's identity on first
 * sighting.  Caller holds exec_lock, exactly like thread_ptr_to_tid. */
static uint32_t asid_root_to_index(uint64_t root_phys, uint64_t sig)
{
    if (!g_asid_index_map) {
        g_asid_index_map = new std::unordered_map<uint64_t, uint32_t>();
        g_asid_identity_store = new std::vector<AsidIdentity>();
    }
    auto it = g_asid_index_map->find(root_phys);
    if (it != g_asid_index_map->end()) {
        return it->second;
    }
    uint32_t index = g_asid_index_next++;
    g_asid_index_map->emplace(root_phys, index);
    g_asid_identity_store->push_back(AsidIdentity{root_phys, sig});
    return index;
}

/* Per-process content fingerprint (Bug-C support): page-table root -> FNV of
 * that process's own USER code page.  Populated the first time a non-
 * representative root runs a user TB (or fires its marker), independent of
 * the racy marker-callback read and of when the root's identity is first
 * emitted.  The representative is deliberately absent — it keeps the
 * representative marker-page signature so single-process traces stay
 * byte-identical.  Reset per segment alongside the identity map. */
static std::unordered_map<uint64_t, uint64_t> *g_cr3_user_sig;

/* Record @root's own-code content signature @sig (from a user-code page).
 * First writer wins (stable across the segment).  If @root already has a
 * compact index whose identity carries a provisional (representative)
 * signature, refresh it in place — harmless once the wire has emitted it,
 * and correcting when it has not.  Skips the representative (byte-identity)
 * and root 0.  Caller holds exec_lock. */
static void asid_set_user_sig(uint64_t root, uint64_t sig)
{
    if (root == 0 ||
        root == g_pinned_asid.load(std::memory_order_relaxed)) {
        return;
    }
    if (!g_cr3_user_sig) {
        g_cr3_user_sig = new std::unordered_map<uint64_t, uint64_t>();
    }
    if (!g_cr3_user_sig->emplace(root, sig).second) {
        return;                              /* already fingerprinted */
    }
    if (g_asid_index_map) {
        auto it = g_asid_index_map->find(root);
        if (it != g_asid_index_map->end() && g_asid_identity_store &&
            it->second < g_asid_identity_store->size()) {
            (*g_asid_identity_store)[it->second].sig = sig;
        }
    }
}

/* Signature to record when a root is FIRST sighted: the representative (and
 * root 0) keep the representative signature (single-process byte-identity);
 * any other process uses its own-code fingerprint if one has been captured,
 * else the representative as a provisional value (later refreshed by
 * asid_set_user_sig once the process runs user code / marks).  Caller holds
 * exec_lock. */
static uint64_t asid_first_sight_sig(uint64_t root)
{
    if (root != 0 &&
        root != g_pinned_asid.load(std::memory_order_relaxed) &&
        g_cr3_user_sig) {
        auto it = g_cr3_user_sig->find(root);
        if (it != g_cr3_user_sig->end()) {
            return it->second;
        }
    }
    return cst_pinned_asid_sig();
}


/* Reset the per-segment asid identity map and index store.  Caller holds
 * exec_lock (via reset_segment_local_state), mirroring
 * thread_identity_reset. */
static void asid_identity_reset(void)
{
    if (g_asid_index_map) {
        g_asid_index_map->clear();
    }
    if (g_asid_identity_store) {
        g_asid_identity_store->clear();
    }
    if (g_cr3_user_sig) {
        g_cr3_user_sig->clear();
    }
    g_asid_index_next = 0;
}

/* The compact asid index stamped on an emitted body entry: the LIVE
 * address space's page-table root, first-sighting-mapped.  Root 0 (user
 * mode / a single address space) → index 0, keeping those traces byte-
 * identical.  cpu_index is retained for symmetry with resolve_thread_id
 * (Stage B derives the per-process signature from the running context);
 * called from a vCPU context, so qemu_plugin_get_addr_space_id() and
 * cst_pinned_asid_sig() are valid.  Caller holds exec_lock.
 *
 * On a root's first sighting the identity records asid_first_sight_sig(root):
 * the representative's marker-page signature for the representative (single-
 * process byte-identity), each other process's own-code fingerprint. */
static inline uint32_t resolve_asid_index(unsigned int cpu_index)
{
    /* Narrow-ASID latch (MIPS, g_pin_reuse_guard, not trace-all): the live
     * EntryHi.ASID is an 8-bit recycled value, so the per-entry memory asid
     * must be the OWNER's stable index (held in g_vcpu_cur_asid_index across
     * a kernel excursion), not asid_root_to_index(live value) — which would
     * mint a spurious new index the moment the OS rolls the process's ASID
     * over.  User mode (asid 0, owner 0's anchor is (0,0)) and single-pin
     * (owner 0 -> index 0) stay byte-identical.  Wide targets, trace-all
     * (every context by its live root, Stage B2), and unpinned runs keep the
     * live-root mapping unchanged. */
    if (g_pin_reuse_guard && !marker_trace_all() &&
        g_pinned_asid.load(std::memory_order_relaxed) != CST_ASID_UNPINNED &&
        cpu_index < CST_PIN_MAX_VCPUS) {
        return g_vcpu_cur_asid_index[cpu_index];
    }
    uint64_t root = qemu_plugin_get_addr_space_id();
    return asid_root_to_index(root, asid_first_sight_sig(root));
}

/* The CONTEXT asid index used ONLY to key the per-(asid,thread) regfile /
 * FieldState tables — the PROCESS asid, decoupled from the per-entry memory
 * asid (entry->asid_index, which stays the live page-table root).  Pinned:
 * the entering process's user CR3 index (g_vcpu_cur_asid_index, held stable
 * across a kernel excursion), so a thread keeps ONE register-file context
 * across user<->kernel even under KPTI's distinct kernel CR3.  User mode /
 * unpinned: the live index, where live == process anyway, so the key (and
 * hence the whole trace) stays byte-identical.  Mirrors resolve_thread_id;
 * caller holds exec_lock. */
static inline uint32_t resolve_ctx_asid_index(unsigned int cpu_index)
{
    if (g_pinned_asid.load(std::memory_order_relaxed) != CST_ASID_UNPINNED &&
        cpu_index < CST_PIN_MAX_VCPUS) {
        return g_vcpu_cur_asid_index[cpu_index];
    }
    return resolve_asid_index(cpu_index);
}

/* Look up the stored identity (page-table root physical address + content
 * signature) of a compact asid index for the body-stream emit path.
 * Returns false for an index never assigned (leaving the outputs
 * untouched).  Caller holds exec_lock, as does every writer of the store,
 * so the read needs no additional locking — the same contract as
 * cst_pinned_asid_root/sig. */
bool cst_asid_identity(uint32_t index, uint64_t *root, uint64_t *sig)
{
    if (!g_asid_identity_store || index >= g_asid_identity_store->size()) {
        return false;
    }
    const AsidIdentity &id = (*g_asid_identity_store)[index];
    if (root) {
        *root = id.root_phys;
    }
    if (sig) {
        *sig = id.sig;
    }
    return true;
}

/* Content signature of the guest code page based at @vpage in the
 * CURRENT address space: FNV-1a over PIN_SIG_BYTES from the page base
 * (the read is page-bounded, so it never straddles into an unmapped
 * successor).  Returns false when the page cannot be read (no live
 * mapping); caller holds exec_lock, so the single scratch buffer needs
 * no lock. */
static bool pin_page_sig(uint64_t vpage, uint64_t *sig_out)
{
    static GByteArray *buf;
    if (!buf) {
        buf = g_byte_array_new();
    }
    if (!qemu_plugin_read_memory_vaddr(vpage, buf, PIN_SIG_BYTES)) {
        return false;
    }
    uint64_t h = 1469598103934665603ULL;          /* FNV-1a offset basis */
    for (guint i = 0; i < buf->len; i++) {
        h ^= buf->data[i];
        h *= 1099511628211ULL;                     /* FNV-1a prime */
    }
    *sig_out = h;
    return true;
}


/* Seed/refine the pinned space's representative content signature from the
 * code page based at @pc in the CURRENT address space, adopting it only
 * when its vpage is the lowest seen so far (so the representative converges
 * on the text-segment start page — deterministic and stable).  Used for
 * the wide-register pins that learn no per-owner page map; the narrow-ASID
 * path seeds each OwnedProc's own signature at its marker instead.
 * Caller holds exec_lock (pin_page_sig's scratch buffer needs it). */
static void pin_repr_seed(uint64_t pc)
{
    uint64_t vp = pc & PIN_PAGE_MASK;
    if (vp >= g_pin_repr_vpage) {
        return;
    }
    uint64_t sig;
    if (!pin_page_sig(vp, &sig)) {
        return;                 /* page unreadable now: seed on a later TB */
    }
    g_pin_repr_vpage = vp;
    g_pin_repr_sig.store(sig, std::memory_order_relaxed);
}

/* Compute a marker firing's stable wire anchor: @root_phys = the marker
 * code page's PHYSICAL page (a real, stable physical anchor that virtual
 * aliasing cannot forge and an EntryHi.ASID rollover cannot move — MIPS has
 * no readable pgd root, so this deviates from multiasid_plan §2), @sig = the
 * FNV of the marker page.  User mode / no real address space (@asid 0) →
 * (0,0) so user-mode marker traces stay byte-identical.  @pc is the marker
 * instruction's own address (from its udata; the env PC is stale mid-TB).
 * Caller holds exec_lock (pin_page_sig's scratch buffer). */
static void marker_anchor(uint64_t pc, uint64_t asid,
                          uint64_t *root_phys, uint64_t *sig, uint64_t *vpage)
{
    uint64_t vp = pc & PIN_PAGE_MASK;
    *vpage = vp;
    if (asid == 0) {
        *root_phys = 0;
        *sig = 0;
        return;
    }
    uint64_t s = 0;
    pin_page_sig(vp, &s);
    *sig = s;
    uint64_t pa;
    if (qemu_plugin_vaddr_to_paddr(pc, &pa)) {
        *root_phys = pa & PIN_PAGE_MASK;
    } else {
        /* The marker page just executed, so this should not happen; a
         * synthetic high-bit anchor keeps identity distinct if it ever
         * does (a real physical page never has bit 63 set). */
        *root_phys = (1ULL << 63) | vp;
    }
}

/* Reset the owned-process set to a SINGLE owner and seat @cpu_index's dwell
 * onto it (the legacy single-pin re-seed: simpoint, user-mode marker, and
 * the FIRST system marker).  Every vCPU's dwell is cleared; the marker vCPU
 * is confirmed as owner 0.  @root_phys/@sig/@vpage are the owner's anchor
 * (marker_anchor()).  Caller holds exec_lock. */
static void pin_owned_reset_single(uint64_t marker_asid, unsigned int cpu_index,
                                   uint64_t root_phys, uint64_t sig,
                                   uint64_t vpage)
{
    if (!g_owned_procs) {
        g_owned_procs = new std::vector<OwnedProc>();
    }
    g_owned_procs->clear();
    OwnedProc op;
    op.root_phys = root_phys;
    op.marker_sig = sig;
    op.repr_vpage = vpage;
    op.active = true;
    op.last_sched_ms = deadlatch_now_ms();
    g_owned_procs->push_back(std::move(op));
    g_owned_procs_active = 1;
    for (unsigned i = 0; i < CST_PIN_MAX_VCPUS; i++) {
        g_pin_vcpu[i].asid.store(CST_ASID_UNPINNED, std::memory_order_relaxed);
        g_pin_vcpu[i].confirmed.store(false, std::memory_order_relaxed);
        g_pin_vcpu[i].owner.store(-1, std::memory_order_relaxed);
    }
    if (cpu_index < CST_PIN_MAX_VCPUS) {
        g_pin_vcpu[cpu_index].asid.store(marker_asid,
                                         std::memory_order_relaxed);
        g_pin_vcpu[cpu_index].owner.store(0, std::memory_order_relaxed);
        g_pin_vcpu[cpu_index].confirmed.store(true, std::memory_order_relaxed);
    }
}

/* Append a NEW owned process (an additional system marker while the segment
 * is already open) and seat @cpu_index's dwell onto it.  Returns the new
 * owner index.  Caller holds exec_lock. */
static int pin_owned_append(uint64_t marker_asid, unsigned int cpu_index,
                            uint64_t root_phys, uint64_t sig, uint64_t vpage)
{
    if (!g_owned_procs) {
        g_owned_procs = new std::vector<OwnedProc>();
    }
    OwnedProc op;
    op.root_phys = root_phys;
    op.marker_sig = sig;
    op.repr_vpage = vpage;
    op.active = true;
    op.last_sched_ms = deadlatch_now_ms();
    int idx = (int)g_owned_procs->size();
    g_owned_procs->push_back(std::move(op));
    g_owned_procs_active++;
    if (cpu_index < CST_PIN_MAX_VCPUS) {
        g_pin_vcpu[cpu_index].asid.store(marker_asid,
                                         std::memory_order_relaxed);
        g_pin_vcpu[cpu_index].owner.store(idx, std::memory_order_relaxed);
        g_pin_vcpu[cpu_index].confirmed.store(true, std::memory_order_relaxed);
    }
    return idx;
}

/* Learn the current translation of @pc into owner @oi's page map (no-op when
 * already mapped, so the confirmed-dwell hot path is one hash lookup; the
 * translation and content signature are taken only on insert).  Caller holds
 * exec_lock and has established the executing context is owner @oi at user
 * privilege. */
static void pin_map_learn(int oi, uint64_t pc)
{
    if (!g_owned_procs || oi < 0 || oi >= (int)g_owned_procs->size()) {
        return;
    }
    OwnedProc &op = (*g_owned_procs)[oi];
    uint64_t vp = pc & PIN_PAGE_MASK;
    auto it = op.pages.find(vp);
    if (it != op.pages.end()) {
        return;
    }
    uint64_t pa;
    if (!qemu_plugin_vaddr_to_paddr(pc, &pa)) {
        return;                 /* no live translation: learn later */
    }
    uint64_t sig;
    if (!pin_page_sig(vp, &sig)) {
        return;                 /* page unreadable right now: learn later */
    }
    op.pages.emplace(vp, PinPage{pa & PIN_PAGE_MASK, sig});
    op.repr_vpage = vp < op.repr_vpage ? vp : op.repr_vpage;
    g_stats.pin_pages_mapped++;
}

/* Probe @pc against EVERY active owned process's page map (multi-ASID
 * Stage B3).  Returns the matching owner index on a hit, or -1.  @hint (a
 * vCPU's last-confirmed owner) is tried first for the O(1) common case.  On
 * no hit, *@mismatch is set when SOME owner had this vpage mapped with
 * differing bytes (a foreign process at a shared VA), cleared when the vpage
 * was simply unmapped in every owner (unknown).  Physical frame is the fast
 * path; on a frame mismatch the page's byte signature is the authority — a
 * re-faulted page (identical bytes, new frame) reads as a hit and its frame
 * is refreshed.  Caller holds exec_lock. */
static int pin_map_probe_owners(uint64_t pc, int hint, bool *mismatch)
{
    *mismatch = false;
    if (!g_owned_procs || g_owned_procs->empty()) {
        return -1;
    }
    uint64_t vp = pc & PIN_PAGE_MASK;
    uint64_t pa;
    if (!qemu_plugin_vaddr_to_paddr(pc, &pa)) {
        return -1;              /* no live translation: unknown */
    }
    pa &= PIN_PAGE_MASK;
    uint64_t sig = 0;
    bool have_sig = false;
    bool any_mapped = false;
    auto test = [&](int oi) -> bool {
        OwnedProc &op = (*g_owned_procs)[oi];
        if (!op.active) {
            return false;
        }
        auto it = op.pages.find(vp);
        if (it == op.pages.end()) {
            return false;       /* not this owner's code page */
        }
        if (pa == it->second.ppage) {
            return true;        /* frame fast-path: no re-fault */
        }
        any_mapped = true;      /* mapped here but a different frame */
        if (!have_sig) {
            if (!pin_page_sig(vp, &sig)) {
                return false;   /* cannot read to adjudicate */
            }
            have_sig = true;
        }
        if (sig == it->second.sig) {
            it->second.ppage = pa;      /* re-faulted: refresh */
            g_stats.pin_refault_repaired++;
            return true;
        }
        return false;           /* different bytes here — try other owners */
    };
    int n = (int)g_owned_procs->size();
    if (hint >= 0 && hint < n && test(hint)) {
        return hint;
    }
    for (int oi = 0; oi < n; oi++) {
        if (oi == hint) {
            continue;
        }
        if (test(oi)) {
            return oi;
        }
    }
    /* No owner claimed this page.  A mapped-but-mismatched vpage means a
     * foreign process is running different code at a shared VA; an unmapped
     * vpage everywhere is merely unknown (not yet learned). */
    *mismatch = any_mapped && have_sig;
    return -1;
}

/*
 * Ownership of a user-privilege TB under an armed pin — the ONE rule
 * every consumer (user clock, foreign gate, kexc ownership seed,
 * stuck-window recovery, end marker) shares.  Wide-register targets:
 * the exact legacy equality against the marker-time value.  Narrow
 * targets: the dwell/verify/re-pin machinery above.  Caller holds
 * exec_lock; @pc is the executing TB's start.
 */
static bool pin_user_tb_owned(unsigned int cpu_index, uint64_t live_asid,
                              uint64_t pinned_asid, uint64_t pc)
{
    if (!g_pin_reuse_guard) {
        /* Wide-register (x86 CR3 / AArch64 TTBR / RISC-V SATP): owned iff
         * the live root is a member of the owned set.  Single-process is a
         * set of one { pinned_asid }, so this is byte-identical to the
         * former `live_asid == pinned_asid`; multi-process (Stage B1) traces
         * every process whose window is open.  Caller holds exec_lock, which
         * every mutation of g_owned also holds. */
        (void)pinned_asid;
        return owned_contains_locked(live_asid);
    }
    if (cpu_index >= CST_PIN_MAX_VCPUS) {
        return false;
    }
    PinVcpuState &ps = g_pin_vcpu[cpu_index];
    int ow = ps.owner.load(std::memory_order_relaxed);
    if (ps.confirmed.load(std::memory_order_relaxed) && ow >= 0 &&
        live_asid == ps.asid.load(std::memory_order_relaxed)) {
        pin_map_learn(ow, pc);          /* grow the CONFIRMED owner's map */
        return true;
    }
    /* Unconfirmed dwell: probe the executing code against EVERY owned
     * process's map (last-confirmed owner first).  A hit confirms the dwell
     * for THAT owner and attributes capture to it (Stage B3). */
    bool mismatch = false;
    int hit = pin_map_probe_owners(pc, ow, &mismatch);
    if (hit >= 0) {
        ps.owner.store(hit, std::memory_order_relaxed);
        /* Dead-latch liveness: a re-confirmed dwell is this owner being
         * scheduled in.  Stamped here (off the per-TB fast path, which
         * short-circuits above on an already-confirmed dwell) so a live
         * owner stays fresh while a dead one ages out. */
        if (g_latch_timeout_ms && hit < (int)g_owned_procs->size()) {
            (*g_owned_procs)[hit].last_sched_ms = deadlatch_now_ms();
        }
        if (live_asid != ps.asid.load(std::memory_order_relaxed)) {
            ps.asid.store(live_asid, std::memory_order_relaxed);
            qemu_plugin_u64_set(g_scoreboard.asid_match, cpu_index, 1);
            g_stats.pin_repins++;
        }
        ps.confirmed.store(true, std::memory_order_relaxed);
        return true;
    }
    if (mismatch) {
        g_stats.pin_phys_mismatch_dropped++;
    } else {
        g_stats.pin_unverified_dropped++;
    }
    return false;
}

/* The per-vCPU effective pin value: what kernel-TB attribution and the
 * asid_match flag compare against.  Narrow targets follow the vCPU's
 * dwell tag; wide targets use the marker-time value. */
static inline uint64_t pin_effective_asid(unsigned int cpu_index,
                                          uint64_t pinned_asid)
{
    if (g_pin_reuse_guard && cpu_index < CST_PIN_MAX_VCPUS) {
        return g_pin_vcpu[cpu_index].asid.load(std::memory_order_relaxed);
    }
    return pinned_asid;
}

/*
 * Recompute this vCPU's context gates (trace_this_ctx / pin_probe) from
 * the live segment-active flag and the pin-ownership state, and stamp
 * them into the scoreboard.  This is the single event-driven maintainer
 * — called at every is_active edge, at each committed ASID write, and on
 * a light-probe re-acquisition — so the heavy per-TB callback is gated
 * by ONE JIT-testable slot instead of the runtime foreign-drop decision.
 *
 * Divergence from a bare is_active mirror happens ONLY for a narrow-ASID
 * (MIPS) system pin: there a recycled EntryHi.ASID cannot distinguish
 * processes, so only a physical-page-confirmed dwell (g_pin_vcpu
 * .confirmed) is traced and every other context runs the light probe.
 * User mode, unpinned system, and the wide-register pins (CR3 / TTBR0 /
 * SATP — a reliable per-process id, foreign-dropped in the heavy step as
 * before) keep trace_this_ctx == is_active and never arm the probe, so
 * their traces are byte-identical to the pre-gating path.
 */
static inline void refresh_ctx_gates(unsigned int cpu_index)
{
    bool active = qemu_plugin_u64_get(g_scoreboard.is_active, cpu_index) != 0;
    /* Trace-all captures EVERY context, so the heavy callback must dispatch
     * for all in-segment TBs on all ISAs — trace_this_ctx == is_active, no
     * narrow-ASID divergence (the dwell probe would otherwise gate out
     * unconfirmed contexts we intend to trace).  The clock still rides the
     * marker pin via pin_user_tb_owned in the heavy step. */
    bool diverge = g_pin_reuse_guard && !marker_trace_all() &&
        g_pinned_asid.load(std::memory_order_relaxed) != CST_ASID_UNPINNED;
    if (!diverge) {
        qemu_plugin_u64_set(g_scoreboard.trace_this_ctx, cpu_index,
                            active ? 1 : 0);
        qemu_plugin_u64_set(g_scoreboard.pin_probe, cpu_index, 0);
        return;
    }
    bool conf = cpu_index < CST_PIN_MAX_VCPUS &&
        g_pin_vcpu[cpu_index].confirmed.load(std::memory_order_relaxed);
    qemu_plugin_u64_set(g_scoreboard.trace_this_ctx, cpu_index,
                        (active && conf) ? 1 : 0);
    qemu_plugin_u64_set(g_scoreboard.pin_probe, cpu_index,
                        (active && !conf) ? 1 : 0);
}

/* Synchronous ASID-write hook: keep the per-vCPU asid_match flag in
 * step with the live address space.  Fires at the same architectural
 * commit points that produce ASID_WRITE path events (and with the same
 * wrong-path suppression), including while the event queue is disabled
 * — which is the whole point: the coarse fast-forward runs with no
 * dispatching callbacks at all.  Kernel-side transient values (PTI
 * overlays, TLB maintenance) flip the flag while no user TB can
 * execute; the exit write restores it before user code resumes.  Also
 * feeds the pinned-ASID reuse detector above — this hook is the one
 * place every committed ASID change is visible — and, on narrow-ASID
 * targets, ends the vCPU's verified dwell: the written value may have
 * been handed to anyone, so the next user TB must re-probe the
 * physical-page map. */
static void asid_write_track_cb(unsigned int vcpu_index, uint64_t new_asid)
{
    uint64_t pinned = g_pinned_asid.load(std::memory_order_relaxed);
    uint64_t match;
    if (g_pin_reuse_guard) {
        /* Narrow-ASID (MIPS): the recycled EntryHi.ASID is compared against
         * the vCPU's effective dwell tag, exactly as before (Stage B3 owns
         * the narrow-ASID set generalization). */
        match = new_asid == pin_effective_asid(vcpu_index, pinned) ? 1 : 0;
    } else {
        /* Wide-register: membership in the owned-ASID set.  Single-process
         * is a set of one, so this is byte-identical to the former
         * representative compare.  Off the per-TB hot path (fires per
         * page-table-root write = per context switch), so taking exec_lock
         * — the guard g_owned's mutations hold — is cheap and race-free. */
        g_rec_mutex_lock(&exec_lock);
        match = owned_contains_locked(new_asid) ? 1 : 0;
        g_rec_mutex_unlock(&exec_lock);
    }
    qemu_plugin_u64_set(g_scoreboard.asid_match, vcpu_index, match);
    if (g_pin_reuse_guard && pinned != CST_ASID_UNPINNED) {
        if (vcpu_index < CST_PIN_MAX_VCPUS) {
            /* A committed ASID write ends the vCPU's verified dwell: the
             * written value may have been handed to anyone, so the next
             * user TB must re-probe the physical-page map before this
             * context is traced again.  Dropping trace_this_ctx (and
             * arming the probe) HERE, off the per-TB path, is exactly
             * how the foreign span stops dispatching the heavy callback. */
            g_pin_vcpu[vcpu_index].confirmed.store(
                false, std::memory_order_relaxed);
            refresh_ctx_gates(vcpu_index);
        }
        pin_reuse_track(new_asid, pinned);
    }
    /* Dead-latch detector: this hook is the one place every committed root
     * write is visible, so a live process's root passes through here at each
     * schedule-in.  Sweep the owned roots for one that has gone stale (its
     * process died without an END marker).  Off the per-TB hot path.  The
     * mode/policy gate lives inside (g_window_mode is declared below). */
    if (g_latch_timeout_ms) {
        deadlatch_on_asid_write(vcpu_index, new_asid);
    }
}

/* Block-device (disk) I/O tracing: emit DEVIO_START/STOP records.  Set
 * from the devio= option (default on in system mode); the block hook is
 * only registered when this is true and g_system_mode. */
static bool g_devio_enabled = true;

/*
 * Devio doorbell hook (qemu_plugin_register_devio_cb): the guest kicked
 * a block device's virtqueue on vCPU @vcpu_index.  This runs in vCPU
 * context (the transport's MMIO/PIO write handler), correct path only (a
 * speculative doorbell store is sandboxed before it reaches the device),
 * BEFORE the request processing runs — possibly on the main loop.  It is
 * the one point where the issuing vCPU is known, so capture that vCPU's
 * current owning (thread_id, asid) and queue it on a per-device FIFO
 * keyed by @dev_token for the later note_start to attribute exactly.
 *
 * resolve_thread_id / resolve_ctx_asid_index read g_vcpu_cur_{tid,asid}
 * for this vCPU — written only by this same vCPU's vcpu_tb_exec (same
 * thread, so lock-free here) — which hold the process/thread that
 * entered the kernel to issue the syscall (kernel code inherits the
 * entering thread's identity).  Gate on an active segment, matching the
 * start hook; a doorbell for an inactive segment is not captured and the
 * request falls back to positional (and is itself gated out).
 */
static void devio_doorbell_cb(int vcpu_index, uint64_t dev_token)
{
    if (!g_devio_enabled || vcpu_index < 0 ||
        !g_trace_segments.is_active_atomic()) {
        return;
    }
    unsigned c = (unsigned)vcpu_index;
    devio_note_doorbell(vcpu_index, dev_token,
                        resolve_thread_id(c), resolve_ctx_asid_index(c));
}

/*
 * Devio issue hook (qemu_plugin_register_devio_cb): the block backend
 * calls this from blk_aio_prwv when a disk request is issued.  Correct
 * path only (a speculative doorbell store is sandboxed and never
 * reaches the block layer).
 *
 * Attribution: EXACT when this request was issued on the vCPU thread
 * whose most recent kick was to this same device (@dev_token) — under
 * the canonical ioeventfd=off config the kick and blk_aio_prwv run back
 * to back on that vCPU, so note_start reads the owner the kick captured
 * and stamps it on the record.  POSITIONAL fallback when the issue is
 * off any vCPU thread, or its device does not match the vCPU's last kick
 * (non-virtio, IDE/AHCI, or kernel-internal I/O): the record carries no
 * owner and the consumer uses its stream-position context, as before.
 *
 * Gate: an active trace segment.  In marker mode that window is the
 * pinned workload's, so disk I/O issued while it is open is a traced
 * process's.  Boot-time and inter-window I/O (segment inactive) is
 * dropped.  Returns the request id, or 0 to leave the request untracked
 * (no paired completion notification is then delivered).
 */
static uint64_t devio_start_cb(int vcpu_index, int dir,
                               uint64_t offset, uint64_t bytes,
                               uint64_t dev_token)
{
    if (!g_devio_enabled || !g_trace_segments.is_active_atomic()) {
        return 0;
    }
    return devio_note_start(vcpu_index, dir, offset, bytes, dev_token);
}

/* Devio completion hook: the request the start hook tracked has
 * finished (block backend completion chokepoint, main-loop thread
 * under the no-iothread config).  Queue the paired DEVIO_STOP; it is
 * drained into the body stream at the next body entry. */
static void devio_stop_cb(uint64_t request_id)
{
    devio_note_stop(request_id);
}

/* Emit-time fault-depth trailer register (system mode): the exception-
 * nesting depth the deferred prev TB ran at, stamped by the PathBuilder
 * seal phase (which carries the depth pipeline) and read by
 * emit_body_entry into the entry's fault trailer.  0 = normal code,
 * >=1 = fault-handler code at that nesting. */
thread_local uint32_t g_emit_fault_depth CST_TLS_HOT = 0;

/* Fault depth of the LAST body entry emitted on this thread; the unwind-flush
 * anchor guard (PathBuilder::flush_frame_unwound) reads it to keep a merged
 * faulting BB from landing at a depth its predecessor doesn't strictly exceed. */
thread_local uint32_t g_last_emit_fault_depth = 0;

/* CST diag correlation: the seq_num of the most recent body entry emitted on
 * this thread, so the per-step depth diag can be tied to a wire position. */
thread_local uint64_t g_dbg_last_emit_seq = 0;

/* Anchors (faulting-insn indices) for the whole-BB merge emit currently in
 * flight; read by emit_body_entry into the entry's fault trailer. */
thread_local std::vector<uint32_t> g_emit_fault_anchors CST_TLS_HOT;

/* See champsim_tracer.h: threads holding cross-flush BBTemplate*
 * references (in-flight wrong-path simulation).  Gates drain_pending_flush
 * so a tb_flush mid-WP defers template reclamation until the WP unwinds. */
/* See champsim_tracer.h: monotonic tb_flush event count, read by the WP
 * loop to retry a flush-interrupted spec-mode exec_tb. */
std::atomic<uint64_t> g_tb_flush_count{0};

/* Window-stop is reached optimistically at TB-start (icount_prev >=
 * window_stop), but the in-flight chain may still hold fragments
 * waiting for a branch terminator — exiting immediately would drop
 * those insns from the trace and put the recorded count *under* the
 * requested stop.  The design guarantee is "trace covers AT LEAST
 * the requested window," so on first crossing we set this flag and
 * defer the actual exit; vcpu_tb_exec checks it after the per-iter
 * chain commits and only finalizes once the chain assembler reports
 * no active in-flight chain. */
thread_local bool g_icount_shutdown_pending = false;

/* Simpoint analogue of g_icount_shutdown_pending: tw_manage_window
 * detects icount_prev >= window_stop optimistically (counter bumped
 * by the current TB), but the chain assembler may still hold
 * fragments waiting for a branch terminator.  Closing here would
 * truncate the trace below the requested simulation_insns; defer
 * the actual finish_trace_segment / g_simpoints.advance to a
 * vcpu_tb_exec tail when has_active_chain() is false (= at a true-BB
 * boundary).  Each bumped insn then either makes it into the trace
 * or never triggered the bump in the first place. */
thread_local bool g_simpoint_close_pending = false;

/* Next icount threshold above which vcpu_tb_exec MUST take the slow
 * path (acquire exec_lock and call tw_manage_window).  Below this
 * threshold the callback is allowed to just bump the per-vCPU icount
 * slot and return — no mutex, no tw_manage_window, no scoreboard
 * contention.
 *
 * Meaning by phase:
 *   - inter-segment: the next eff_start (next simpoint open icount,
 *     or window_start in icount mode).  Set to UINT64_MAX when no
 *     more opens are possible (= drained simpoint list).
 *   - in-segment: 0, so the slow path always runs (chain emit, BB
 *     emit, WP, close detect).
 *
 * Updated from start_trace_segment / finish_trace_segment under
 * exec_lock; the fast path reads relaxed because a one-TB lag is
 * harmless (next slow-path TB will see the new value and act on it).
 * This is the hot-path optimisation for the inter-segment gap, where
 * profiling (perf record) showed g_mutex_lock + g_mutex_unlock
 * accounting for >20% of CPU. */
std::atomic<uint64_t> g_next_threshold{UINT64_MAX};

/* Host-side mirror of the per-vCPU icount accumulator.  The scoreboard
 * slot (g_scoreboard.insn_count) is the source of truth at runtime,
 * but QEMU tears down the scoreboard storage in qemu_plugin_user_exit
 * before our plugin_exit callback fires — so by the time we want to
 * print the final icount, that slot reads back as freed memory.  This
 * thread_local mirror is bumped at the same point as the scoreboard
 * slot inside vcpu_tb_exec; it stays valid through plugin_exit. */
thread_local uint64_t g_host_icount CST_TLS_HOT = 0;

/* Total sub-entries emitted by REP fan-out (sum of (n_iter - 1)
 * across every emit_body_entry call that fanned out).  Each
 * sub-entry uses the 1-insn rep_subtmpl, so this counter is the
 * architectural insns the trace contains BEYOND the per-TB-exec
 * inline_add count, scoped to in-segment because emit_body_entry
 * only runs when a trace stream is open. */
std::atomic<uint64_t> g_rep_fanout_extra_insns{0};

/* Sum of per-segment `covered` (icount[finish] - icount[start])
 * accumulated at finish_trace_segment.  Matches the BBV-equivalent
 * TB-exec insn count for the portion of execution that landed in
 * trace files. */
std::atomic<uint64_t> g_traced_icount{0};

/* Sum of per-segment g_seg_arch_insns accumulated at finish.
 * Matches cst_audit's "CP insns (total)" summed across all
 * segments — the actual architectural insn count the body
 * streams carry, including REP fan-out sub-entries and the
 * BB-end-deferral drain. */
std::atomic<uint64_t> g_total_arch_insns{0};

/* Defined later after g_window_mode / warmup_insns are in scope. */
static void recompute_next_threshold(void);
/* Set the per-vCPU `budget` scoreboard slot so the JIT-emitted
 * INLINE_ADD_U64(-n_insns) per TB will hit < 1 exactly when the next
 * eff_start is reached, firing vcpu_tb_check_budget once.  In-segment
 * we set a sentinel that won't be crossed during a single segment
 * window. */
static void recompute_budget(unsigned int cpu_index);
/* Sentinel for the budget slot while in-segment.  Large enough that
 * even billion-instruction segments don't decrement it past zero. */
#define BUDGET_INACTIVE_SENTINEL ((int64_t)1ULL << 62)
static void vcpu_tb_check_budget(unsigned int cpu_index, void *udata);

/* Symbol-trigger state (trace_window=symbol:...).  start_symbol_match
 * _count counts TBs whose template names start_symbol; on reaching
 * start_symbol_occurrence we open a segment of simulation_insns. */
static char     *start_symbol            = nullptr;
static uint64_t  start_symbol_occurrence = 1;
static uint64_t  start_symbol_match_count = 0;
static int       g_window_mode           = 0; /* PluginConfig::WIN_AUTO */
static bool g_system_mode;                 /* full-system emulation (set at install) */
static inline bool pinned_simpoint_mode(void);

/* Recompute g_next_threshold given the current segments / simpoint
 * state.  Caller holds exec_lock OR is on the install-time path
 * before any vCPU thread has fired. */
static void recompute_next_threshold(void)
{
    if (g_trace_segments.is_active()) {
        g_next_threshold.store(0, std::memory_order_relaxed);
        return;
    }
    if (g_window_mode == PluginConfig::WIN_ICOUNT) {
        g_next_threshold.store(g_trace_segments.window_start(),
                               std::memory_order_relaxed);
        return;
    }
    if (g_window_mode == PluginConfig::WIN_SIMPOINT &&
        !pinned_simpoint_mode()) {
        if (const SimPointEntry *sp = g_simpoints.current()) {
            uint64_t eff_start = (sp->start_insn > warmup_insns)
                ? sp->start_insn - warmup_insns : 0;
            g_next_threshold.store(eff_start,
                                   std::memory_order_relaxed);
        } else {
            g_next_threshold.store(UINT64_MAX,
                                   std::memory_order_relaxed);
        }
        return;
    }
    if (pinned_simpoint_mode()) {
        /* Pinned-simpoint positioning needs no icount threshold at all:
         * the marker insn callback pins, the coarse countdown (armed at
         * pin) fires the handoff, and the exact fast-path opens the
         * window on the user clock.  Park the budget at the sentinel so
         * vcpu_tb_check_budget never dispatches during boot or FF. */
        g_next_threshold.store(UINT64_MAX, std::memory_order_relaxed);
        return;
    }
    /* Symbol / marker open on an executed instruction (symbol name, or
     * the marker that arms the window), not on an icount threshold;
     * every TB must take the slow path. */
    g_next_threshold.store(0, std::memory_order_relaxed);
}

/* Companion to recompute_next_threshold for the per-vCPU budget slot.
 * In-segment: sentinel large positive so vcpu_tb_check_budget never
 * fires.  Inter-segment: countdown from now to next eff_start, so a
 * sequence of INLINE_ADD_U64(-n_insns) per TB walks the slot down to
 * zero exactly when icount reaches the threshold. */
static void recompute_budget(unsigned int cpu_index)
{
    int64_t target;
    if (g_trace_segments.is_active()) {
        target = BUDGET_INACTIVE_SENTINEL;
    } else {
        uint64_t threshold = g_next_threshold.load(
            std::memory_order_relaxed);
        if (threshold == UINT64_MAX) {
            target = BUDGET_INACTIVE_SENTINEL;
        } else {
            uint64_t icount_now = qemu_plugin_u64_get(
                g_scoreboard.insn_count, cpu_index);
            target = (int64_t)threshold - (int64_t)icount_now;
            if (target < 1) {
                /* Already past the threshold; still need the cb to
                 * fire once to handle it. */
                target = 0;
            }
        }
    }
    qemu_plugin_u64_set(g_scoreboard.budget, cpu_index, (uint64_t)target);
}

/* ========================= Thread ID assignment =========================
 *
 * thread_id on the wire IS the guest vCPU index, verbatim (stable for
 * the whole run, no remapping).  Each segment's body opens with an
 * explicit BODY_TAG_THREAD_SWITCH naming the starting thread.
 */

/* ========================= SimPoints ========================= */

static char *simpoints_file_path = nullptr;
static uint64_t simpoint_interval_insns = 100000000ULL;

/* ========================= Decode / ISA ========================= */

TraceISA trace_isa = TRACE_ISA_UNKNOWN;
int cst_cap_arch = -1;
unsigned int cst_cap_mode;
bool target_big_endian = false;

static_assert(TRACE_ISA_MIPS < 256,
              "TraceISA no longer fits in u8");
static_assert(GEN_OP_COUNT <= 256,
              "GenericOpcode no longer fits in u8");
static_assert(BRANCH_TYPE_COUNT <= 256,
              "BranchType no longer fits in u8");
static_assert(MAX_SRC_REGS <= 255,
              "MAX_SRC_REGS no longer fits in u8");
static_assert(MAX_DST_REGS <= 255,
              "MAX_DST_REGS no longer fits in u8");

const InsnClassification *active_insn_table;
unsigned active_insn_table_size;
const RegClassification *active_reg_table;
unsigned active_reg_table_size;

static void vcpu_init_cb(qemu_plugin_id_t id, unsigned int cpu_index)
{
    (void)id;

    /*
     * Resolve cap_mode lazily on first vCPU init: the per-ISA mode
     * resolvers may call qemu_plugin_path_to_binary(), which needs a
     * live vCPU context.
     */
    if (cst_cap_arch >= 0 && cst_cap_mode == 0
            && trace_isa != TRACE_ISA_UNKNOWN) {
        const IsaProperties *p = &isa_properties[trace_isa];
        if (p->cap_mode_for_target) {
            cst_cap_mode = p->cap_mode_for_target(target_name);
        }
    }

    if (g_features.reg_data) {
        g_reg_handle_cache.ensure_initialized(cpu_index);
    }

    /* If the trace_window opened a segment at install time (icount
     * start=0), the scoreboard is_active slot couldn't be set then
     * because no vCPU existed.  Back-fill it now so the per-insn
     * cond_cb gates fire for this vCPU.  Initialize the budget slot
     * too — either the in-segment sentinel or the inter-segment
     * countdown to the first eff_start, depending on state. */
    if (g_trace_segments.is_active_atomic()) {
        qemu_plugin_u64_set(g_scoreboard.is_active, cpu_index, 1);
    }
    refresh_ctx_gates(cpu_index);
    recompute_budget(cpu_index);

    /* Snapshot the main binary's text-segment range on first vCPU
     * init.  qemu_plugin_start_code() / end_code() dereference the
     * TaskState, which is not initialized at plugin_install time but
     * is by the first vcpu_init.  The bytes-change / decode-failure
     * detector in vcpu_tb_trans uses this range to decide whether to
     * warn (in-text → SMC suspect) vs silent-kill (out-of-text → WP
     * wrong-path into data). */
    if (g_code_start == 0 && g_code_end == 0) {
        g_code_start = qemu_plugin_start_code();
        g_code_end   = qemu_plugin_end_code();
        fprintf(stderr,
                "champsim_tracer: text segment [0x%" PRIx64
                " .. 0x%" PRIx64 ") (%" PRIu64 " bytes)\n",
                g_code_start, g_code_end,
                g_code_end - g_code_start);
    }
}

/* ========================= Global state ========================= */

GMutex data_lock;


/*
 * Pending dst register snapshots for the currently-executing BB.
 * Each insn appends its dst snaps in dst_regs[] order, captured
 * POST-execution (the cb is on the next canonical insn's pre-exec
 * hook).  Last canonical insn of a TB is captured at the NEXT TB's
 * vcpu_tb_exec ("Tail-insn dst snap").  Drained into
 * BodyEntry.reg_snaps at finalize, discarded on flush.  Active only
 * when g_features.reg_data.  Non-static (extern in
 * champsim_tracer_path_builder.h) so the PathBuilder's fault frames can
 * stash and re-inject it. */
thread_local std::vector<RegSnap> pending_reg_snaps CST_TLS_HOT;

/* WP-side counterpart to pending_reg_snaps.  See the docstring on the
 * extern declaration in champsim_tracer.h for the contract.  Non-static
 * so champsim_tracer_wp.cc can drain it after each WP exec_tb. */
thread_local std::vector<RegSnap> wp_pending_reg_snaps CST_TLS_HOT;

/* ========================= Reg-data snapshot capture =========================
 *
 * Snap mechanics live in RegSnapCollector; this file owns only the
 * per-insn callback that feeds pending_reg_snaps (CP context) or
 * wp_pending_reg_snaps (WP context).
 */

typedef struct {
    BBTemplate *tb_tmpl;
    uint32_t    insn_index;
} RegSnapInsnRef;

/*
 * Per-insn destination snap callback.  Registered on the first raw
 * insn of canonical (ci+1), so when it fires pre-exec, canonical ci
 * has just finished and its dst registers hold post-exec values.
 * The TB's last canonical insn is captured at the NEXT TB's
 * vcpu_tb_exec ("Tail-insn dst snap") for CP; the WP fragment walk
 * does a live post-fragment read for its trailing insn (no successor
 * pre-exec inside a WP fragment can capture it).
 *
 * Routes by execution context:
 *  - CP: append to pending_reg_snaps; drained by the next
 *    vcpu_tb_exec.
 *  - WP (g_wp_state.in_progress): append to wp_pending_reg_snaps;
 *    drained by the fragment walk after the in-flight exec_tb
 *    returns.  Skipped when g_features.wp_reg_data is off.
 */
static void vcpu_insn_reg_snap_cb(unsigned int cpu_index, void *udata)
{
    if (!g_features.reg_data && !g_features.wp_reg_data) {
        return;
    }
    if (!g_trace_segments.is_active_atomic()) {
        return;
    }
    /* Async-interrupt exclusion: same rationale as the memop recorder.  A
     * suppressed async handler's per-insn dst snaps must not leak into the
     * interrupted user BB's pending_reg_snaps — they would attach to the
     * wrong instruction and surface kernel register values on a user insn
     * (e.g. a user `add` whose dst snap is a kernel stack pointer).  Sync
     * faults stay traced, so this does not affect them. */
    if (g_capture_mute) {
        return;
    }
    std::vector<RegSnap> *sink;
    if (g_wp_state.in_progress) {
        if (!g_features.wp_reg_data) {
            return;
        }
        sink = &wp_pending_reg_snaps;
    } else {
        if (!g_features.reg_data) {
            return;
        }
        sink = &pending_reg_snaps;
    }
    const RegSnapInsnRef *ref = (const RegSnapInsnRef *)udata;
    if (!ref || !ref->tb_tmpl ||
        ref->insn_index >= ref->tb_tmpl->n_insns ||
        !ref->tb_tmpl->insn_reg_names) {
        return;
    }
    const InsnFields *f = &ref->tb_tmpl->insn_fields[ref->insn_index];
    const InsnRegNames *names = &ref->tb_tmpl->insn_reg_names[ref->insn_index];

    for (uint8_t i = 0; i < f->n_dst_regs; i++) {
        RegSnap s;
        g_reg_snaps.read_into_snap(cpu_index,
                                   names->dst_qemu_reg_keys[i], &s);
        sink->push_back(s);
    }
}

/* ========================= Memory access callback ========================= */

static void vcpu_mem_cb(unsigned int cpu_index,
                        qemu_plugin_meminfo_t info,
                        uint64_t vaddr,
                        void *udata)
{
    (void)cpu_index;
    g_mem_recorder.record(info, vaddr, (uint64_t)(uintptr_t)udata);
}

/* ========================= Synthetic-EA callback =========================
 *
 * Per-insn callback for prefetch / cache-flush / TLB-flush insns
 * whose canonical TCG translation emits no memop.  Computes
 * ea = base + scaled/shifted index + disp and routes it through
 * MemAccessRecorder into the BodyEntry's load slots.  CP-path only
 * (spec-mode CF_MEMI_ONLY suppresses per-insn cbs); fine, since these
 * generate no architectural memops on either path anyway.
 */

typedef struct {
    BBTemplate *tb_tmpl;
    uint32_t    insn_index;
} SynthEAInsnRef;

static inline uint64_t read_reg_u64(unsigned int cpu_index,
                                    const QemuRegKey *key,
                                    GByteArray *scratch)
{
    if (!key || !key->name) {
        return 0;
    }
    struct qemu_plugin_register *handle =
        g_reg_handle_cache.lookup(cpu_index, key);
    if (!handle) {
        return 0;
    }
    g_byte_array_set_size(scratch, 0);
    int n = qemu_plugin_read_register(handle, scratch);
    if (n <= 0) {
        return 0;
    }
    cst_normalize_reg_bytes_to_le(scratch->data, (size_t)n);
    uint64_t val = 0;
    size_t copy = (size_t)n < sizeof(val) ? (size_t)n : sizeof(val);
    memcpy(&val, scratch->data, copy);
    return val;
}

static void vcpu_insn_synth_ea_cb(unsigned int cpu_index, void *udata)
{
    if (g_wp_state.in_progress) {
        return;
    }
    if (!g_trace_segments.is_active_atomic()) {
        return;
    }
    /* Async-interrupt exclusion: drop synthetic-EA loads issued by a
     * suppressed async handler (see the memop recorder rationale). */
    if (g_capture_mute) {
        return;
    }
    const SynthEAInsnRef *ref = (const SynthEAInsnRef *)udata;
    if (!ref || !ref->tb_tmpl ||
        ref->insn_index >= ref->tb_tmpl->n_insns ||
        !ref->tb_tmpl->insn_synthetic_ea) {
        return;
    }
    const SyntheticEAInfo *sea =
        &ref->tb_tmpl->insn_synthetic_ea[ref->insn_index];
    if (!sea->has_addr) {
        return;
    }

    static thread_local GByteArray *tls_scratch = nullptr;
    if (!tls_scratch) {
        tls_scratch = g_byte_array_sized_new(16);
    }

    uint64_t base = read_reg_u64(cpu_index, sea->base_key, tls_scratch);
    uint64_t index = read_reg_u64(cpu_index, sea->index_key, tls_scratch);

    /* AArch64 reg-form shifts the index; x86 SIB scales it.  Mutually
     * exclusive: x86 fill always sets shift_amount==0, arm64 fill
     * always sets scale==1. */
    if (sea->shift_amount && sea->shift_type) {
        index <<= sea->shift_amount;
    } else if (sea->scale > 1) {
        index *= sea->scale;
    }

    uint64_t ea = base + index + (uint64_t)sea->disp;
    g_mem_recorder.record_synthetic_load(ea,
                                         ref->tb_tmpl->insn_pcs[ref->insn_index]);
}

/* ========================= Trace state management ========================= */

/* Heartbeat state: progress_step is 1/10 of the segment span
 * (clamped >=1); progress_next is the next icount to print at. */
static uint64_t progress_step = 0;
static uint64_t progress_next = 0;

/* Stats snapshot at segment start; finish prints
 * (g_stats - segment_start_stats) while g_stats keeps accumulating
 * for the cumulative print at plugin_exit. */
static Stats segment_start_stats;
static char *segment_label = nullptr;  /* g_strdup'd, freed at finish */

/* Histogram state.  --histogram=N gives each segment N Stats buckets
 * (one per equal icount interval) mirroring g_stats bumps, walked at
 * finish for per-interval breakdowns.
 *
 * g_current_hist_bucket points into g_hist.buckets, refreshed at
 * the top of vcpu_tb_exec; null when inactive/disabled so attribution
 * sites collapse to one nullable check. */
struct HistogramState {
    unsigned int intervals = 0;      /* configured interval count (0 == off) */
    std::vector<Stats> buckets;      /* one Stats per interval, per segment */
    uint64_t interval_size = 0;      /* insns per interval */
    uint64_t segment_start = 0;      /* icount at segment open */
};
static HistogramState g_hist;
Stats *g_current_hist_bucket = nullptr;  /* extern in stats.h */

/* append_stats_summary / append_histogram now live in
 * champsim_tracer_stats_report.cc (declared in its header). */

/*
 * Drop plugin-side state that could leak across a segment boundary so
 * each .cst is standalone-decodable.  Called at segment start, after
 * the prior finish_trace_segment drained pending CP body entries.
 *
 *   - bb_map_ (true-BB template dictionary source): cleared so each
 *     segment's dictionary covers only post-reset BBs.  tb_map_
 *     fragments are preserved — QEMU fires vcpu_tb_trans only on
 *     first translation, so dropping them would orphan the chain
 *     assembler (true-BBs are re-assembled from fragments anyway).
 *   - Per-template IFRAME cadence (BBTemplate.emit_count): without
 *     reset a mid-cadence segment would emit IFRAMEs at positions a
 *     standalone run wouldn't.
 *   - In-flight g_cp_chain / g_mem_recorder.cp: a partial chain
 *     spanning the boundary would splice before+after fragments.  WP
 *     is transient (drained per WP sim).
 *   - pending_reg_snaps: would otherwise attach to the new segment's
 *     first body entry.
 *
 * The per-segment guest-thread identity map (thread-pointer -> tid) is
 * reset here via thread_identity_reset(), so tids are numbered in
 * first-sighting order within each segment.  Persistent FieldStateTable
 * overlays are already fresh per segment (new BodyStreamState per open).
 */
static void reset_segment_local_state(void)
{
    if (getenv("CST_SEGDIAG")) {
        fprintf(stderr, "champsim_tracer: [segdiag] reset_segment_local_state"
                " bb_map=%zu active=%d\n",
                g_template_store.bb_count(),
                (int)g_trace_segments.is_active());
    }
    g_mutex_lock(&data_lock);
    /* Clearing bb_map_ drops the old BBTemplates and their
     * accumulated emit_count; the next commit_true_bb rebuilds each
     * zero-initialized, so the IFRAME cadence resets implicitly. */
    g_template_store.clear_bb_map();
    g_mutex_unlock(&data_lock);

    /* Per-segment guest-thread identity: tids are assigned in first-
     * sighting order WITHIN a segment, so the map (and every vCPU's
     * current tid) starts fresh here.  The opener's tid is re-seeded to 0
     * by start_trace_segment below. */
    thread_identity_reset();

    /* Per-segment address-space identity: asid indices are likewise
     * assigned in first-sighting order WITHIN a segment, so the root->index
     * map and its identity store start fresh here (mirroring the tid map). */
    asid_identity_reset();

    /*
     * Other threads' TLS state (cp_chain, tls_cp_mem_accesses,
     * pending_reg_snaps) can't be touched directly.  Bumping
     * g_segment_generation makes each thread self-drop its stale
     * chain on its next append_fragment; the other two drain every
     * BB / body emit, and each thread's PathBuilder runs its own
     * on_segment_open (frames, pending-seal slot, retained events)
     * as it observes the bumped generation in vcpu_tb_exec.
     */
    g_segment_generation.fetch_add(1, std::memory_order_release);

    /* Our own thread's TLS state (we're called from vcpu_tb_exec).  The
     * PathBuilder's frames and cursors are dropped by its own
     * on_segment_open (each thread runs it as it crosses the segment
     * generation, this one included). */
    g_cp_chain.reset();
    g_mem_recorder.clear_cp();
    pending_reg_snaps.clear();

    /* Per-segment disk-I/O record state: request ids are compact and
     * monotonic WITHIN a segment, so the counter, the pending queues,
     * and the live-id set all reset here (a request straddling the
     * boundary yields no cross-segment orphan). */
    devio_reset_segment();
}

/* Snapshot of g_rep_fanout_extra_insns at segment open, so
 * finish_trace_segment can diff and report per-segment fan-out. */
static uint64_t g_seg_fanout_start = 0;

/* Segment-local architectural CP-insn counter.  Bumped by parent
 * BB template n_insns (and +1 per REP sub-iteration) inside
 * emit_body_entry so it tracks exactly what cst_audit counts off
 * the body stream.  At the warmup→simulation transition (host
 * icount reaches window_start + warmup_insns) we snapshot this
 * into g_seg_warmup_end_arch_insns, which finish_trace_segment
 * then writes into the header (§2.13). */
static uint64_t g_seg_arch_insns = 0;
/* UINT64_MAX sentinel = warmup boundary has not been crossed
 * (segment cut short, or warmup_insns==0 and no entry emitted
 * yet).  0 is a legitimate value (warmup_insns==0 → captured at
 * the very first entry). */
static uint64_t g_seg_warmup_end_arch_insns = UINT64_MAX;

static void start_trace_segment(const char *label,
                                uint64_t start, uint64_t stop,
                                uint64_t warmup,
                                uint64_t total_target,
                                unsigned int cpu_index,
                                double simpoint_weight)
{
    reset_segment_local_state();
    g_seg_fanout_start = g_rep_fanout_extra_insns.load(
        std::memory_order_relaxed);
    g_seg_arch_insns = 0;
    g_seg_warmup_end_arch_insns = UINT64_MAX;

    /* Capture the architectural register file so consumers can prime
     * register state without replaying a prior segment's dst-write
     * deltas.  cpu_index == (unsigned)-1 (install-time start=0, no
     * vCPU yet) → empty snapshot; dst-write stream is then the only
     * state source. */
    std::vector<InitialRegSnap> regfile;
    capture_initial_regfile(cpu_index, &regfile);

    /* Seed thread id: the opener's guest-thread identity.  The map was
     * just reset (reset_segment_local_state), so the first user-privilege
     * thread pointer sampled here takes tid 0 — a single-threaded pinned
     * process is thread 0 on any vCPU, and single-thread system goldens
     * stay byte-stable (cpu_index 0 and first-sighting 0 coincide).  A
     * non-pinned (user-mode / plain-icount) open keeps the vCPU index as
     * the seed, preserving byte-identical output.  When the open lands on
     * a kernel TB (no meaningful thread pointer yet) the seed is thread 0
     * and the first user TB establishes the mapping. */
    uint32_t seed_thread_id = (uint32_t)cpu_index;
    if (g_pinned_asid.load(std::memory_order_relaxed) != CST_ASID_UNPINNED &&
        cpu_index < CST_PIN_MAX_VCPUS) {
        seed_thread_id = 0;
        uint32_t seed_asid_index = 0;
        if (qemu_plugin_get_priv_level() == 0) {
            uint64_t tp = qemu_plugin_get_thread_ptr();
            seed_thread_id = thread_ptr_to_tid(tp);
            g_vcpu_last_tp[cpu_index] = tp;
            /* Opener sampled at user privilege: seed the migration-detect
             * guard's per-segment vCPU set with this vCPU. */
            pin_user_vcpu_observe(cpu_index);
            if (tiddiag_on()) {
                tiddiag_note_binding(cpu_index, seed_thread_id);
            }
            /* The live user root at priv 0 IS the process's user CR3, so
             * seed the context asid to it (the tables' process key).  A
             * kernel excursion before the first user TB then folds to the
             * entering process rather than the KPTI kernel CR3.  Just after
             * asid_identity_reset, so this first-sighting maps to index 0 —
             * single-address-space stays byte-identical.
             *
             * Narrow-ASID latch (MIPS): the opener is owner 0, whose stable
             * anchor (marker_anchor, not the recycled EntryHi.ASID) is the
             * process key; derive index 0 from it so the seed matches every
             * later user-TB attribution (seal path below). */
            int ow = g_pin_reuse_guard ? g_pin_vcpu[cpu_index].owner.load(
                                             std::memory_order_relaxed) : -1;
            if (ow >= 0 && g_owned_procs && ow < (int)g_owned_procs->size() &&
                (*g_owned_procs)[ow].active) {
                const OwnedProc &op = (*g_owned_procs)[ow];
                seed_asid_index = asid_root_to_index(op.root_phys,
                                                     op.marker_sig);
            } else {
                uint64_t seed_root = qemu_plugin_get_addr_space_id();
                seed_asid_index = asid_root_to_index(
                    seed_root, asid_first_sight_sig(seed_root));
            }
        }
        g_vcpu_cur_tid[cpu_index] = seed_thread_id;
        g_vcpu_cur_asid_index[cpu_index] = seed_asid_index;
    }

    g_trace_segments.start(label, start, stop, warmup, total_target,
                           seed_thread_id, simpoint_weight, &regfile);

    /* Segment is active now → next-threshold becomes 0 so the
     * fast-path bail never fires in-segment (every TB takes the slow
     * path for chain emit + close-detect). */
    recompute_next_threshold();

    /* Mirror is_active into EVERY existing vCPU's scoreboard slot so the
     * per-TB exec dispatch and the per-insn heavy callbacks (registered
     * with QEMU_PLUGIN_COND_GE 1) fire machine-wide, and park each
     * budget slot at the sentinel so vcpu_tb_check_budget does not fire
     * during the segment.  A mid-run segment open (marker fire, icount
     * threshold) executes on ONE vCPU, but on an SMP guest the pinned
     * process's threads run wherever the guest scheduler put them — a
     * slot left inactive would leave that entire vCPU untraced (and its
     * pinned-user instructions uncounted) for the whole segment, exactly
     * what the pinned-simpoint positioning path already guards against
     * with the same loop.  The install-time call (cpu_index == -1, no
     * vCPU yet) loops over zero vCPUs; vcpu_init_cb back-fills any vCPU
     * created after the open. */
    for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; i++) {
        qemu_plugin_u64_set(g_scoreboard.is_active, (unsigned)i, 1);
        qemu_plugin_u64_set(g_scoreboard.budget, (unsigned)i,
                            (uint64_t)BUDGET_INACTIVE_SENTINEL);
        refresh_ctx_gates((unsigned)i);
    }
    if (getenv("CST_SMP_DIAG")) {
        fprintf(stderr, "champsim_tracer: [smpdiag] segment open on cpu %d: "
                "num_vcpus=%d\n", (int)cpu_index, qemu_plugin_num_vcpus());
    }

    uint64_t span = stop > start ? stop - start : 0;
    progress_step = span >= 10 ? span / 10 : 1;
    progress_next = start + progress_step;
    g_seg_end_marker_close = false;

    /* Snapshot cumulative stats for finish_trace_segment's diff.
     * stats_snapshot() folds every thread's slot plus the exited-
     * thread graveyard, so the diff is a true global delta on
     * multi-vCPU runs. */
    segment_start_stats = stats_snapshot();
    g_free(segment_label);
    segment_label = g_strdup(label ? label : "trace");

    /* One Stats per interval, zero-init.  Interval size rounds up so
     * the last bucket absorbs the remainder; lookup clamps so a late
     * icount past stop still maps into it. */
    if (g_hist.intervals > 0 && span > 0) {
        g_hist.buckets.assign(g_hist.intervals, Stats{});
        g_hist.interval_size =
            (span + g_hist.intervals - 1) / g_hist.intervals;
        if (g_hist.interval_size == 0) {
            g_hist.interval_size = 1;
        }
        g_hist.segment_start = start;
    } else {
        g_hist.buckets.clear();
        g_hist.interval_size = 0;
    }
    g_current_hist_bucket = nullptr;

    if (stop == UINT64_MAX) {
        fprintf(stderr,
                "champsim_tracer: starting segment '%s' "
                "[icount %" PRIu64 " .. unbounded]\n",
                label ? label : "trace", start);
    } else {
        fprintf(stderr,
                "champsim_tracer: starting segment '%s' "
                "[icount %" PRIu64 " .. %" PRIu64 "]\n",
                label ? label : "trace", start, stop);
    }

    /* CST_MEMSTATS: snapshot at segment OPEN, paired with the close-time
     * print — the observed multi-GiB RSS (and the ulimit bad_alloc
     * aborts) materialise in the open/first-steps window, not as
     * gradual template growth. */
    if (getenv("CST_MEMSTATS")) {
        struct mallinfo2 mi = mallinfo2();
        fprintf(stderr, "[memstats] at segment open: arena=%.2f GiB "
                "(in-use=%.2f GiB) mmap=%.2f GiB\n",
                mi.arena / 1073741824.0, mi.uordblks / 1073741824.0,
                mi.hblkhd / 1073741824.0);
    }
}

/* Pick the bucket matching @icount; null when histograms are disabled
 * or no segment is active.  Caller holds exec_lock. */
static Stats *select_histogram_bucket(uint64_t icount)
{
    if (g_hist.buckets.empty() || g_hist.interval_size == 0) {
        return nullptr;
    }
    uint64_t off = icount > g_hist.segment_start
        ? icount - g_hist.segment_start : 0;
    size_t idx = (size_t)(off / g_hist.interval_size);
    if (idx >= g_hist.buckets.size()) {
        idx = g_hist.buckets.size() - 1;
    }
    return &g_hist.buckets[idx];
}

/* True when the window budget runs on the pinned process's user-space
 * instruction count (g_user_icount) instead of raw icount: marker mode
 * with a live ASID pin.  Window open/close, the progress heartbeat, and
 * the finish printout must all read the same clock. */
/*
 * Pinned-simpoint mode: full-system WIN_SIMPOINT.  The guest marker (a
 * self-emitting workload or the cst_attach ptrace injector) PINS the
 * target's address space and zeroes the user-instruction clock; the
 * SimPoint offsets — computed from a user-mode run that counts exactly
 * the same user-space instruction stream — then position the window on
 * that clock.  Kernel work is traced (and attributed by the excursion
 * ownership rules) but never advances the clock, which is what makes the
 * user-mode SimPoints valid here.  One simpoint per run: the window
 * close exits like marker mode.
 */
static inline bool pinned_simpoint_mode(void)
{
    return g_window_mode == PluginConfig::WIN_SIMPOINT && g_system_mode;
}

static inline bool marker_scan_enabled(void)
{
    return g_window_mode == PluginConfig::WIN_MARKER ||
           pinned_simpoint_mode();
}

static inline bool marker_user_clock(void)
{
    return (g_window_mode == PluginConfig::WIN_MARKER ||
            pinned_simpoint_mode()) &&
           g_pinned_asid.load(std::memory_order_relaxed) != CST_ASID_UNPINNED;
}

static void heartbeat_progress(uint64_t icount)
{
    /* On the user-instruction clock, progress is g_user_icount through
     * the span; rebase it onto the raw window bounds so the
     * progress_next/progress_step pacing (initialised from the span,
     * which in marker mode IS the user-insn budget) works unchanged. */
    bool user_clock = marker_user_clock();
    uint64_t clock = user_clock
        ? g_trace_segments.window_start() + g_user_icount : icount;
    if (!g_trace_segments.is_active() || clock < progress_next) {
        return;
    }
    uint64_t start = g_trace_segments.window_start();
    uint64_t stop  = g_trace_segments.window_stop();
    uint64_t span  = stop > start ? stop - start : 1;
    uint64_t pct   = ((clock - start) * 100) / span;
    if (user_clock) {
        fprintf(stderr,
                "champsim_tracer: progress %" PRIu64 "/%" PRIu64
                " user insns (%" PRIu64 "%%)\n",
                g_user_icount, span, pct);
    } else {
        fprintf(stderr,
                "champsim_tracer: progress %" PRIu64 "/%" PRIu64
                " insns (%" PRIu64 "%%)\n",
                clock, stop, pct);
    }
    progress_next += progress_step;
}

/*
 * Build a BodyEntry from the calling thread's CP memop/reg-snap
 * accumulators (draining them) and write it to @out_stream.
 * @wp_entries is moved in.  Caller holds exec_lock; data_lock is NOT
 * held — the per-thread accumulators are unsynchronised by design.
 * Non-static (declared in champsim_tracer_path_builder.h): also the
 * emission primitive of PathBuilder::flush_final.
 */
void emit_body_entry(BodyStreamState *out_stream,
                     BBTemplate *bb_tmpl,
                     unsigned int cpu_index,
                     std::vector<WPBBEntry> wp_entries,
                     bool wp_first_tb_unavail,
                     uint64_t branch_successor_pc,
                     bool branch_successor_known)
{
    /* warmup→simulation boundary capture.  This BB is the first
     * emitted at host_icount >= window_start + warmup_insns, so
     * the consumer reads the simulation phase as "after this many
     * in-trace architectural insns".  Snapshot g_seg_arch_insns
     * BEFORE this entry's insns get added so the value points at
     * the first sim-phase entry, not past it. */
    if (g_seg_warmup_end_arch_insns == UINT64_MAX &&
        g_trace_segments.is_active()) {
        uint64_t simpoint_start =
            g_trace_segments.window_start() + warmup_insns;
        if (g_host_icount >= simpoint_start) {
            g_seg_warmup_end_arch_insns = g_seg_arch_insns;
        }
    }

    BodyEntry entry;
    entry.seq_num = g_trace_segments.next_seq_num();
    g_dbg_last_emit_seq = entry.seq_num;
    entry.template_id = bb_tmpl ? bb_tmpl->template_id : 0;
    entry.dyn_params.reserve(g_mem_recorder.cp_count());
    entry.wp_entries = std::move(wp_entries);
    entry.wp_first_tb_unavail = wp_first_tb_unavail;
    entry.tmpl = bb_tmpl;
    entry.fault_depth = g_emit_fault_depth;
    /* Record this thread's last-emitted depth for the unwind-flush anchor
     * guard.  A REP fan-out below emits its sub-entries at this same depth
     * (they inherit entry.fault_depth), so the parent stamp is the last
     * emitted level regardless. */
    g_last_emit_fault_depth = g_emit_fault_depth;
    entry.fault_anchors = g_emit_fault_anchors;
    /* Guest-thread identity on the wire (system-mode pin); the raw vCPU
     * index otherwise.  cpu_index is retained for live register reads only
     * (regfile capture, WP lane gates) and never reaches the stream. */
    entry.thread_id = resolve_thread_id(cpu_index);
    /* Context asid (regfile / FieldState table key ONLY): the process asid,
     * held stable across a kernel excursion.  Equals asid_index in user
     * mode / unpinned, so the key is unchanged there. */
    entry.ctx_asid_index = resolve_ctx_asid_index(cpu_index);
    /* Address-space identity on the wire: the compact index of the live
     * page-table root (index 0 in user mode / a single address space, so
     * those traces stay byte-identical).  Resolved here alongside
     * thread_id and frozen onto the entry, so a deferred emit carries the
     * index captured at execution time.
     *
     * Bug 3 (non-compact wire indices): a KERNEL block is TAGGED on the wire
     * with the owning process (ctx_asid_index), never the live page-table
     * root — which mid-excursion is a TRANSIENT FOREIGN CR3, the scheduler's
     * next process caught while the kernel still runs under this excursion.
     * Resolving asid_index from that live root would MINT a fresh compact
     * wire index for an address space that never emits an entry of its own
     * (the wire uses ctx_asid_index for every kernel block), burning index
     * numbers on foreign roots and leaving the OWNED processes' wire indices
     * non-compact (the trial saw owned indices 0 and 5, not 0 and 1).  So
     * carry the ctx index for kernel blocks: only a root that actually
     * reaches the wire — an owned process, at user privilege, where the live
     * root IS that already-minted process — mints an index, giving compact
     * first-emission order.  Trace-all keeps the live-root mapping (every
     * context is emitted by its own root there, so the mint is real and the
     * order must not change).  User mode / a single address space:
     * is_system is 0 and ctx == live == 0, so those traces stay
     * byte-identical. */
    if (bb_tmpl && bb_tmpl->is_system && !marker_trace_all()) {
        entry.asid_index = entry.ctx_asid_index;
    } else {
        entry.asid_index = resolve_asid_index(cpu_index);
    }
    entry.cpu_index = cpu_index;
    /* Terminal-branch outcome for the CST_FID_BRANCH_* singletons.  The
     * successor is the deferred-seal landing PC (collect_finalized_bbs'
     * frag_current_pc, threaded through emit_finalized_bb); unknown only for
     * the segment-final flush.  Stamped verbatim; direction/target are
     * derived from it at wire-emit time. */
    entry.branch_successor_pc    = branch_successor_pc;
    entry.branch_successor_known = branch_successor_known;

    g_mem_recorder.drain_cp_into_dyn_params(entry.dyn_params, bb_tmpl);
    /* Backstop for the positional reg-snap invariant.  The wire attributes
     * reg_snaps POSITIONALLY: build_entry_view prefix-sums each insn's
     * n_dst_regs, and the DST_REG / METAFLAGS stages index reg_snaps at that
     * running offset.  So pending_reg_snaps MUST hold exactly Σ n_dst_regs
     * for this template — otherwise every later insn's dst value and
     * metaflags slide onto the wrong slot, landing code addresses on ALU
     * dsts.  After the eager-tail / foreign-drop / segment-boundary fixes
     * this holds by construction on the fault-free path (silent, so user-mode
     * output stays byte-identical), so a residual mismatch is one of two
     * shapes:
     *
     *   SURPLUS — a chain the assembler abandoned on a TB discontinuity in a
     *     sync-fault storm dropped its fragments but left its already-captured
     *     dst snaps at the FRONT of pending, ahead of this BB's own snaps.
     *     This BB's snaps are intact and correct at the back, so trim the
     *     leaked prefix and emit the recovered reg-data (the dataflow oracle
     *     validates it).  Counted separately as a recovered leak, not a drop.
     *
     *   SHORTFALL — a tail snap the capture could not reach (the END-marker
     *     exit block whose later insns never ran).  Nothing to recover; drop
     *     this entry's reg-data rather than emit a mis-sliced stream.  The
     *     END-marker terminator is expected and not counted; any other
     *     shortfall is a real capture bug, counted loudly. */
    if (g_features.reg_data && bb_tmpl) {
        uint64_t expected_snaps = 0;
        for (uint32_t i = 0; i < bb_tmpl->n_insns; i++) {
            expected_snaps += bb_tmpl->insn_fields[i].n_dst_regs;
        }
        /* A merged fault entry carries its verified frame prefix at the FRONT
         * of pending (complete_merge already trimmed its suffix's leak before
         * prepending), so a residual surplus there must NOT front-trim the
         * frame — drop it.  A plain seal (no fault anchors) has any leaked
         * prefix genuinely at the front. */
        bool is_merge_emit = !g_emit_fault_anchors.empty();
        if (pending_reg_snaps.size() > expected_snaps && !is_merge_emit) {
            size_t excess = pending_reg_snaps.size() - (size_t)expected_snaps;
            if (getenv("CST_SNAP_DIAG")) {
                fprintf(stderr, "champsim_tracer: [snapdiag] reg-snap SURPLUS "
                        "BB start=0x%" PRIx64 " n_insns=%u pending=%zu "
                        "expected=%" PRIu64 " fdepth=%u fanchors=%zu is_sys=%d "
                        "— trimming %zu leaked prefix\n",
                        bb_tmpl->start_pc, bb_tmpl->n_insns,
                        pending_reg_snaps.size(), expected_snaps,
                        g_emit_fault_depth, g_emit_fault_anchors.size(),
                        (int)bb_tmpl->is_system, excess);
            }
            pending_reg_snaps.erase(pending_reg_snaps.begin(),
                                    pending_reg_snaps.begin() + (ptrdiff_t)excess);
            g_stats.reg_snap_leak_trimmed++;
        } else if (pending_reg_snaps.size() != expected_snaps) {
            if (!g_seg_end_marker_close) {
                g_stats.reg_snap_slice_dropped++;
            }
            if (getenv("CST_SNAP_DIAG")) {
                fprintf(stderr, "champsim_tracer: [snapdiag] reg-snap "
                        "%s BB start=0x%" PRIx64 " n_insns=%u pending=%zu"
                        " expected=%" PRIu64 " end_marker=%d fdepth=%u "
                        "fanchors=%zu is_sys=%d — dropping reg_snaps\n",
                        pending_reg_snaps.size() < expected_snaps
                            ? "SHORTFALL" : "MERGE-SURPLUS",
                        bb_tmpl->start_pc, bb_tmpl->n_insns,
                        pending_reg_snaps.size(), expected_snaps,
                        (int)g_seg_end_marker_close, g_emit_fault_depth,
                        g_emit_fault_anchors.size(),
                        (int)bb_tmpl->is_system);
            }
            pending_reg_snaps.clear();
        }
    }
    if (g_features.reg_data && !pending_reg_snaps.empty()) {
        entry.reg_snaps = std::move(pending_reg_snaps);
        pending_reg_snaps.clear();
        /* Restore a typical-BB capacity after the move stole the
         * allocation.  Otherwise every BB starts at cap=0 and the
         * first few push_backs pay realloc overhead — perf showed
         * std::vector<RegSnap>::_M_realloc_insert at 0.84% of total
         * runtime on mcf with regdata=1.  64 slots = 16 insns × 4
         * dst regs, well above mcf's 5-insn/2-dst-reg per BB. */
        pending_reg_snaps.reserve(64);
    }

    /*
     * REP fan-out: split a single REP TB-exec's memop stream into N
     * iteration entries (iter 1 on @entry, iter 2..N on rep_subtmpl).
     * Memops arrive in execution order under the REP PC, mpi per
     * iteration (1 for LODS/STOS/SCAS/INS/OUTS, 2 for MOVS/CMPS), so
     * the partition is a direct slice.  WP entries and reg_snaps stay
     * on iter 1: the WP simulator sees REP as one architectural
     * branch, and per-iter RSI/RDI/RCX deltas ride the field-delta
     * stream like any repeated BB visit.
     */
    BBTemplate *rep_sub = bb_tmpl
        ? g_template_store.seg_deref(bb_tmpl->rep_subtmpl)
        : nullptr;
    if (rep_sub && bb_tmpl->n_insns > 0) {
        uint32_t last = bb_tmpl->n_insns - 1;
        const InsnFields *lf = &bb_tmpl->insn_fields[last];
        unsigned mpi = (unsigned)lf->rep_loads_per_iter
                     + (unsigned)lf->rep_stores_per_iter;
        if (mpi > 0) {
            /* Split REP-attributed memops out, preserving order. */
            std::vector<DynParam> rep_dps;
            std::vector<DynParam> other_dps;
            rep_dps.reserve(entry.dyn_params.size());
            other_dps.reserve(entry.dyn_params.size());
            for (const DynParam &dp : entry.dyn_params) {
                if (dp.insn_index == last) {
                    rep_dps.push_back(dp);
                } else {
                    other_dps.push_back(dp);
                }
            }
            size_t n_iter = rep_dps.size() / mpi;
            if (n_iter > 1) {
                /* Track sub-entries (iters 2..N) that this fan-out
                 * will emit beyond the single TB-exec icount bump.
                 * Each sub-entry contributes 1 architectural insn
                 * via the 1-insn rep_subtmpl, so the increment is
                 * (n_iter - 1).  Cumulative at exit lets us verify
                 *   trace_insns == g_host_icount + this_counter. */
                g_rep_fanout_extra_insns.fetch_add(
                    (uint64_t)(n_iter - 1),
                    std::memory_order_relaxed);
                /* Branch-outcome for the fanned-out REP iterations.  The REP
                 * prefix is a self-loop "branch": iterations 1..N-1 loop back
                 * to the REP insn (taken, target = the rep_subtmpl's start_pc
                 * = the REP PC), and the final iteration exits to the BB's
                 * real successor.  Preserve that real successor (stamped on
                 * @entry from the seal) before overriding the parent to the
                 * self-loop target, so the emitted per-iteration direction/
                 * target matches the stream's successor sequence (each entry's
                 * start_pc is the REP PC until the last iter falls through). */
                uint64_t rep_exit_pc     = entry.branch_successor_pc;
                bool     rep_exit_known  = entry.branch_successor_known;
                uint64_t rep_loop_pc     = rep_sub->start_pc;

                /* Iter 1: parent BB template + non-REP memops +
                 * first mpi REP memops. */
                entry.dyn_params = std::move(other_dps);
                entry.dyn_params.reserve(entry.dyn_params.size() + mpi);
                for (unsigned j = 0; j < mpi; j++) {
                    entry.dyn_params.push_back(rep_dps[j]);
                }
                /* n_iter > 1 here, so iter 1 always loops. */
                entry.branch_successor_pc    = rep_loop_pc;
                entry.branch_successor_known = rep_exit_known;
                if (out_stream) {
                    body_stream_write_entry(out_stream, &entry);
                }
                /* Parent + (n_iter-1) rep_subtmpl entries, each
                 * counted as 1 arch insn for the warmup boundary
                 * tracker. */
                g_seg_arch_insns +=
                    (bb_tmpl ? bb_tmpl->n_insns : 0)
                    + (uint64_t)(n_iter - 1);
                /* Iter 2..N: rep_subtmpl, mpi memops each, insn_index
                 * remapped to 0 (sub has exactly one insn).  One reused
                 * BodyEntry across iterations keeps the per-sub dyn_params /
                 * reg_snaps buffers allocated once (a hot path on
                 * memset/memcpy-heavy kernels) instead of per iteration. */
                BodyEntry sub_e;
                sub_e.template_id = rep_sub->template_id;
                sub_e.tmpl        = rep_sub;
                sub_e.thread_id   = entry.thread_id;
                sub_e.asid_index  = entry.asid_index;
                sub_e.ctx_asid_index = entry.ctx_asid_index;
                sub_e.cpu_index   = entry.cpu_index;
                /* The system-mode fault-nesting depth is a property of the
                 * excursion the whole REP instruction runs inside, so every
                 * fanned-out iteration inherits iter 1's depth.  Without this
                 * the sub-entries default to depth 0: a REP string op (a
                 * kernel memset/memcpy) executed inside a fault handler then
                 * emits depth-0 iterations amid its depth-D neighbours,
                 * fabricating a D->0->D step that the syscall_fault_nesting
                 * oracle flags whenever D>1 (the residual 2->0/0->2 kernel
                 * "spin loop" — actually a rep stosq — under churn, where a
                 * leaked handler frame has inflated the excursion to depth 2).
                 * fault_anchors stay iter-1 only (they mark the faulting insn
                 * indices of the merged faulting BB, not a per-iteration
                 * property). */
                sub_e.fault_depth = entry.fault_depth;
                sub_e.branch_successor_known = rep_exit_known;
                sub_e.dyn_params.reserve(mpi);
                /* Dedup case: a 1-insn REP BB (its start_pc IS the REP PC)
                 * is its own rep_subtmpl (commit_true_bb deduped sub against
                 * parent by start_pc), so the parent iter-1 entry and these
                 * sub-entries share ONE template — and thus ONE persistent
                 * (asid,thread) field-state block.  The parent iter-1 wrote
                 * the REP insn's destination-register snapshots (e.g. RDI/RSI
                 * /RCX) into that block; a sub-entry that omits them leaves
                 * the block holding those values, so a later ENTRY decode
                 * materialises them while an IFRAME triggered on a sub-entry
                 * (re-encoded from the sub's empty reg_snaps against fresh
                 * scratch) reproduces only template-defaults — tripping the
                 * decoder's IFRAME self-validation (cp reg_snaps mismatch).
                 * Carry the parent's REP-insn reg snaps so the sub-entry's
                 * field-state and its IFRAME re-encode stay consistent; since
                 * the values are already resident, the ENTRY delta is zero and
                 * the wire ENTRY bytes are unchanged.  Skipped in the non-dedup
                 * case (multi-insn parent -> distinct sub template, distinct
                 * block, nothing to leak).  Positionally sound: a dedup parent
                 * is provably 1-insn, so its reg_snaps are exactly insn 0's
                 * destination slots, matching the 1-insn sub template. */
                if (rep_sub == bb_tmpl && !entry.reg_snaps.empty()) {
                    sub_e.reg_snaps = entry.reg_snaps;
                }
                for (size_t k = 1; k < n_iter; k++) {
                    sub_e.seq_num = g_trace_segments.next_seq_num();
                    sub_e.dyn_params.clear();
                    for (unsigned j = 0; j < mpi; j++) {
                        DynParam dp = rep_dps[k * mpi + j];
                        dp.insn_index = 0;
                        sub_e.dyn_params.push_back(dp);
                    }
                    /* Iters 2..N-1 loop back to the REP PC; the final iter
                     * (k == n_iter-1) exits to the BB's real successor. */
                    sub_e.branch_successor_pc =
                        (k + 1 < n_iter) ? rep_loop_pc : rep_exit_pc;
                    if (out_stream) {
                        body_stream_write_entry(out_stream, &sub_e);
                    }
                }
                return;
            }
        }
    }

    if (out_stream) {
        body_stream_write_entry(out_stream, &entry);
    }
    g_seg_arch_insns += bb_tmpl ? bb_tmpl->n_insns : 0;
}

/* Append a CP fragment to the true-BB chain (per-exec seal walk). */
static inline void cp_chain_append(BBTemplate *frag)
{
    g_cp_chain.append_fragment(frag->start_pc, frag,
                               frag->fall_through_pc,
                               (TbTerminus)frag->terminus);
}

/* Finalize and reset the CP chain if it now forms a complete true BB.
 * Returns the finalized template (the caller emits/records it) or
 * nullptr if the BB is not yet complete.  Resetting immediately lets a
 * subsequent fragment in the same walk start a fresh chain at its own
 * entry_pc instead of being appended onto the just-committed BB. */
static inline BBTemplate *cp_chain_finalize_if_complete(void)
{
    if (g_cp_chain.bb_complete() && g_cp_chain.has_active_chain()) {
        BBTemplate *bb_tmpl = g_cp_chain.finalize();
        g_cp_chain.reset();
        return bb_tmpl;
    }
    return nullptr;
}

/*
 * Finalize and write the current trace segment.  Must be called with
 * exec_lock held.
 */
static void finish_trace_segment(void)
{
    uint64_t lo = g_trace_segments.window_start();
    uint64_t hi = g_trace_segments.window_stop();

    /* Hand the warmup→simulation arch-insn boundary to the body
     * stream so body_stream_finish writes it into the header
     * (§2.13 in docs/format.rst). */
    if (BodyStreamState *bs = g_trace_segments.body_stream()) {
        body_stream_set_warmup_end_arch_insns(
            bs, g_seg_warmup_end_arch_insns);
    }
    /* Drain any chain still in flight.  This may call emit_body_entry
     * one or more times, which bumps g_seg_arch_insns — so we print
     * the per-segment stats AFTER finish() returns so the counter
     * reflects the entire segment, including the trailing chain. */
    g_trace_segments.finish(path_builder_flush_final);

    /* Actual icount at finish — must be >= window_stop for the
     * trace to be at-least-budget.  Underrun means we stopped
     * tracing before the configured stop (guest exit, or worse,
     * a bug in close-pending plumbing). */
    if (hi == UINT64_MAX) {
        fprintf(stderr,
                "champsim_tracer: finished segment [icount %"
                PRIu64 " .. unbounded]  actual_icount=%"
                PRIu64 "\n", lo, g_host_icount);
    } else {
        uint64_t budget = hi - lo;
        /* On the user-instruction clock the budget is measured in the
         * pinned process's user-space insns, so coverage is too; raw
         * icount would count the (traced-but-uncounted) kernel insns
         * and overstate progress.  actual_icount stays raw — it is the
         * real guest icount at close. */
        bool user_clock = marker_user_clock();
        uint64_t covered = user_clock ? g_user_icount
            : (g_host_icount > lo ? g_host_icount - lo : 0);
        /* An end-marker close is the workload finishing under budget by
         * design ("budget or program end"), not an underrun. */
        const char *flag = covered >= budget ? "OK"
            : (g_seg_end_marker_close ? "END" : "UNDER");
        /* Per-segment rep_fanout: diff against the snapshot taken
         * at start_trace_segment.  Makes "architectural CP insns
         * in this trace > covered" visible (the trace fans REP
         * out N-way while the BBV-style inline_add only bumps by
         * 1 per REP TB-exec). */
        uint64_t fanout_now = g_rep_fanout_extra_insns.load(
            std::memory_order_relaxed);
        uint64_t seg_fanout = fanout_now - g_seg_fanout_start;
        /* trace_arch_insns is the truth: summed inside
         * emit_body_entry from each entry's template->n_insns
         * (plus +1 per REP sub-iteration), so it equals exactly
         * what cst_audit will report as "CP insns (total)".  We
         * still print rep_fanout for visibility into where the
         * arch-vs-BBV divergence comes from. */
        fprintf(stderr,
                "champsim_tracer: finished segment [icount %"
                PRIu64 " .. %" PRIu64 "]  actual_icount=%"
                PRIu64 "  %scovered=%" PRIu64
                "  %sbudget=%" PRIu64 "  rep_fanout=%" PRIu64
                "  trace_arch_insns=%" PRIu64 "  %s\n",
                lo, hi, g_host_icount,
                user_clock ? "user_" : "", covered,
                user_clock ? "user_" : "", budget,
                seg_fanout, g_seg_arch_insns, flag);
        g_traced_icount.fetch_add(covered,
                                  std::memory_order_relaxed);
        g_total_arch_insns.fetch_add(g_seg_arch_insns,
                                     std::memory_order_relaxed);
    }

    /* Template-cache census (kernel-bucket duplication investigation): dump
     * the per-bucket breakdown of the templates just serialised (finish()
     * above wrote the templates section), before the segment's bb_map_ is
     * cleared at the next open.  Diagnostic only, gated by env. */
    if (getenv("CST_TMPL_CENSUS")) {
        g_mutex_lock(&data_lock);
        g_template_store.census(stderr);
        g_mutex_unlock(&data_lock);
    }

    /* CST_MEMSTATS (#91): template-store footprint breakdown at segment
     * close — attributes the multi-GiB heap baseline to its owners. */
    if (getenv("CST_MEMSTATS")) {
        g_mutex_lock(&data_lock);
        g_template_store.mem_stats(stderr);
        g_mutex_unlock(&data_lock);
        fprintf(stderr, "[memstats] first_insn_word=%zu poisoned=%zu\n",
                g_first_insn_word.size(), g_poisoned_pcs.size());
        fprintf(stderr, "[memstats] branch_history: %zu records "
                "(~%.2f GiB est)\n",
                g_branch_history.size(),
                g_branch_history.size() *
                    (sizeof(BranchRecord) + 48.0) / 1073741824.0);
    }

    /* Mirror is_active=0 into every vCPU's scoreboard slot so the
     * per-insn heavy callbacks stop firing across the inter-segment
     * gap.  Setting the manager's atomic above already gates the C
     * early-bail; this slot gates the JIT cond_cb.  The budget slot
     * is re-armed in the caller (close handler) AFTER it advances
     * simpoint state and calls recompute_next_threshold, so the
     * countdown targets the post-advance next eff_start. */
    for (int i = 0; i < qemu_plugin_num_vcpus(); i++) {
        qemu_plugin_u64_set(g_scoreboard.is_active, i, 0);
        refresh_ctx_gates((unsigned)i);
    }

    /* Per-segment stats: diff against the segment-start snapshot. */
    Stats seg_stats;
    Stats now = stats_snapshot();
    stats_diff(&seg_stats, now, segment_start_stats);
    g_autoptr(GString) report = g_string_new("");
    g_autofree char *label = g_strdup_printf("Segment '%s'",
                                             segment_label ? segment_label
                                                           : "trace");
    append_stats_summary(report, label, seg_stats);
    if (!g_hist.buckets.empty()) {
        append_histogram(report, label,
                         g_hist.buckets,
                         g_hist.segment_start,
                         g_hist.interval_size);
    }
    qemu_plugin_outs(report->str);
}

/* True when the dead-latch detector is armed: marker mode, per-process
 * latch policy (trace-all pins a single clock process by design), and a
 * non-zero timeout. */
static inline bool deadlatch_enabled(void)
{
    return g_latch_timeout_ms != 0 &&
           g_window_mode == PluginConfig::WIN_MARKER &&
           !marker_trace_all();
}

/* Close the segment when a dead-latch sweep empties the owned set — the
 * whole-set backstop.  Mirrors the END marker's last-window close so the
 * trace finalises identically (audit rolls up to 100%).  Caller holds
 * exec_lock; returns true if the caller should exit(0). */
static bool deadlatch_close_segment(uint64_t now)
{
    if (!g_trace_segments.is_active() ||
        g_trace_segments.is_shutting_down()) {
        return false;
    }
    fprintf(stderr,
            "champsim_tracer: dead-latch close — closing after %" PRIu64
            " user insns (last window; wall %" PRIu64 " ms)\n",
            g_user_icount, now);
    /* A dead process is a process that ended, so report a clean close
     * ("END") rather than an under-budget underrun. */
    g_seg_end_marker_close = true;
    finish_trace_segment();
    g_trace_segments.set_shutting_down();
    return true;
}

/*
 * Wide-register staleness sweep (x86 CR3 / AArch64 TTBR / RISC-V SATP).
 * Close every owned root idle past the timeout — its process died without
 * running its END marker — exactly as the END handler drops a window, then
 * close the segment if that was the last one.  Caller holds exec_lock;
 * returns true if the caller should exit(0).
 */
static bool deadlatch_sweep_wide(uint64_t now)
{
    if (g_owned.empty()) {
        return false;
    }
    std::vector<std::pair<uint64_t, uint64_t>> dead;   /* {root, idle_ms} */
    for (uint64_t root : g_owned) {
        auto it = g_owned_last_sched.find(root);
        if (it == g_owned_last_sched.end()) {
            g_owned_last_sched[root] = now;     /* first sighting: not stale */
            continue;
        }
        uint64_t idle = now - it->second;
        if (idle >= g_latch_timeout_ms) {
            dead.emplace_back(root, idle);
        }
    }
    for (const auto &d : dead) {
        uint64_t root = d.first;
        g_owned.erase(root);
        g_owned_last_sched.erase(root);
        /* Drop the closed process's asid-keyed dedup-index footprint (its
         * true-BB templates stay until the templates section is written),
         * as the END handler does. */
        g_mutex_lock(&data_lock);
        uint64_t dropped = g_template_store.reclaim_asid(root);
        g_mutex_unlock(&data_lock);
        /* If the dead root was the representative, repoint it to a
         * still-owned root so pin_effective_asid / cst_pinned_asid_root
         * stay valid. */
        if (g_pinned_asid.load(std::memory_order_relaxed) == root &&
            !g_owned.empty()) {
            g_pinned_asid.store(*g_owned.begin(), std::memory_order_relaxed);
        }
        fprintf(stderr,
                "champsim_tracer: dead-latch close asid=0x%" PRIx64
                " idle=%" PRIu64 " ms (%zu still tracing, dropped %" PRIu64
                " dedup buckets)\n", root, d.second, g_owned.size(), dropped);
    }
    if (!dead.empty() && g_owned.empty()) {
        return deadlatch_close_segment(now);
    }
    return false;
}

/*
 * Narrow-ASID staleness sweep (MIPS system mode).  An owner's liveness is
 * its last confirmed physical-page dwell (stamped in pin_user_tb_owned) —
 * an EntryHi.ASID value cannot name a process.  An owner currently
 * confirmed on some vCPU is running now, so refresh it and never close it;
 * otherwise close it if its last dwell is older than the timeout.  Caller
 * holds exec_lock; returns true if the caller should exit(0).
 */
static bool deadlatch_sweep_narrow(uint64_t now)
{
    if (!g_owned_procs || g_owned_procs_active <= 0) {
        return false;
    }
    int n = (int)g_owned_procs->size();
    for (int oi = 0; oi < n; oi++) {
        OwnedProc &op = (*g_owned_procs)[oi];
        if (!op.active) {
            continue;
        }
        /* A vCPU whose confirmed dwell is this owner is executing it right
         * now (covers a long-running owner on an SMP peer while another
         * vCPU's writes drive this sweep). */
        bool live_now = false;
        unsigned nv = (unsigned)qemu_plugin_num_vcpus();
        if (nv > CST_PIN_MAX_VCPUS) {
            nv = CST_PIN_MAX_VCPUS;
        }
        for (unsigned v = 0; v < nv; v++) {
            if (g_pin_vcpu[v].confirmed.load(std::memory_order_relaxed) &&
                g_pin_vcpu[v].owner.load(std::memory_order_relaxed) == oi) {
                live_now = true;
                break;
            }
        }
        if (live_now) {
            op.last_sched_ms = now;
            continue;
        }
        uint64_t idle = now - op.last_sched_ms;
        if (idle < g_latch_timeout_ms) {
            continue;
        }
        op.active = false;
        op.pages.clear();               /* free — never probed again */
        g_owned_procs_active--;
        fprintf(stderr,
                "champsim_tracer: dead-latch close narrow owner %d "
                "root_phys=0x%" PRIx64 " idle=%" PRIu64 " ms (%d still "
                "tracing)\n", oi, op.root_phys, idle, g_owned_procs_active);
    }
    if (g_owned_procs_active == 0) {
        return deadlatch_close_segment(now);
    }
    return false;
}

/*
 * Dead-latch entry point, called from the synchronous ASID-write hook on
 * every committed root write (per context switch — off the per-TB path).
 * On the wide path a schedule-in of an owned root refreshes its stamp
 * before the sweep; on the narrow path the dwell machinery does the
 * stamping and this only sweeps.  A stale window is closed like an END
 * fire; if that empties the set the segment shuts down.
 */
static void deadlatch_on_asid_write(unsigned int vcpu_index, uint64_t new_asid)
{
    (void)vcpu_index;
    if (!deadlatch_enabled()) {
        return;
    }
    /* Wrong-path fence: never mutate the owned set or close a window from a
     * speculative context (asid writes are wrong-path-suppressed upstream;
     * this hard-enforces it, mirroring the marker callbacks). */
    if (qemu_plugin_in_spec_mode() || g_wp_state.in_progress) {
        return;
    }
    g_rec_mutex_lock(&exec_lock);
    bool do_exit = false;
    if (g_trace_segments.is_active() &&
        !g_trace_segments.is_shutting_down()) {
        uint64_t now = deadlatch_now_ms();
        if (g_pin_reuse_guard) {
            do_exit = deadlatch_sweep_narrow(now);
        } else {
            if (owned_contains_locked(new_asid)) {
                g_owned_last_sched[new_asid] = now;   /* live: schedule-in */
            }
            do_exit = deadlatch_sweep_wide(now);
        }
    }
    g_rec_mutex_unlock(&exec_lock);
    if (do_exit) {
        exit(0);
    }
}

/*
 * Progress-driven peer sweep, called off the owned user clock (throttled to
 * once per DEADLATCH_UIC_STRIDE user insns — see the constant).  The vCPU
 * is executing an OWNED user TB right now, so ITS window is alive: refresh
 * it, and close any OTHER owned window idle past the timeout (a dead peer
 * whose process died mid-window without an END marker).  The running window
 * is never closed here, so the owned set cannot empty on this path — the
 * whole-set/last-window backstop lives on the ASID-write path.  Caller
 * holds exec_lock; @live_asid is the executing root (wide targets),
 * @cpu_index identifies the confirmed owner (narrow targets).
 */
static void deadlatch_clock_check(unsigned int cpu_index, uint64_t live_asid)
{
    if (!deadlatch_enabled()) {
        return;
    }
    uint64_t now = deadlatch_now_ms();
    if (g_pin_reuse_guard) {
        if (!g_owned_procs) {
            return;
        }
        int cur = (cpu_index < CST_PIN_MAX_VCPUS)
            ? g_pin_vcpu[cpu_index].owner.load(std::memory_order_relaxed) : -1;
        int n = (int)g_owned_procs->size();
        if (cur >= 0 && cur < n) {
            (*g_owned_procs)[cur].last_sched_ms = now;   /* running: fresh */
        }
        unsigned nv = (unsigned)qemu_plugin_num_vcpus();
        if (nv > CST_PIN_MAX_VCPUS) {
            nv = CST_PIN_MAX_VCPUS;
        }
        for (int oi = 0; oi < n; oi++) {
            if (oi == cur) {
                continue;
            }
            OwnedProc &op = (*g_owned_procs)[oi];
            if (!op.active) {
                continue;
            }
            bool live_now = false;
            for (unsigned v = 0; v < nv; v++) {
                if (g_pin_vcpu[v].confirmed.load(std::memory_order_relaxed) &&
                    g_pin_vcpu[v].owner.load(std::memory_order_relaxed) == oi) {
                    live_now = true;
                    break;
                }
            }
            if (live_now) {
                op.last_sched_ms = now;
                continue;
            }
            uint64_t idle = now - op.last_sched_ms;
            if (idle < g_latch_timeout_ms) {
                continue;
            }
            op.active = false;
            op.pages.clear();
            g_owned_procs_active--;
            fprintf(stderr,
                    "champsim_tracer: dead-latch close narrow owner %d "
                    "root_phys=0x%" PRIx64 " idle=%" PRIu64 " ms (%d still "
                    "tracing)\n", oi, op.root_phys, idle, g_owned_procs_active);
        }
        return;
    }
    if (owned_contains_locked(live_asid)) {
        g_owned_last_sched[live_asid] = now;             /* running: fresh */
    }
    std::vector<std::pair<uint64_t, uint64_t>> dead;
    for (uint64_t root : g_owned) {
        if (root == live_asid) {
            continue;
        }
        auto it = g_owned_last_sched.find(root);
        if (it == g_owned_last_sched.end()) {
            g_owned_last_sched[root] = now;
            continue;
        }
        uint64_t idle = now - it->second;
        if (idle >= g_latch_timeout_ms) {
            dead.emplace_back(root, idle);
        }
    }
    for (const auto &d : dead) {
        uint64_t root = d.first;
        g_owned.erase(root);
        g_owned_last_sched.erase(root);
        g_mutex_lock(&data_lock);
        uint64_t dropped = g_template_store.reclaim_asid(root);
        g_mutex_unlock(&data_lock);
        if (g_pinned_asid.load(std::memory_order_relaxed) == root &&
            !g_owned.empty()) {
            g_pinned_asid.store(*g_owned.begin(), std::memory_order_relaxed);
        }
        fprintf(stderr,
                "champsim_tracer: dead-latch close asid=0x%" PRIx64
                " idle=%" PRIu64 " ms (%zu still tracing, dropped %" PRIu64
                " dedup buckets)\n", root, d.second, g_owned.size(), dropped);
    }
}

/* ========================= Execution callback ========================= */

/*
 * Update per-branch transition stats and history for a just-completed
 * true BB's terminating branch.  @branch_pc is that branch's PC (from
 * the finalized true-BB template), @bb_fall_through the BB's
 * architectural fall-through.  Returns the BranchRecord.  Called only
 * when a true BB finalized; caller holds data_lock.
 */
static BranchRecord *observe_branch_transition(BBTemplate *bb_tmpl,
                                               bool branch_taken,
                                               uint64_t branch_pc,
                                               uint64_t bb_fall_through)
{
    Stats &s = thread_stats_get();
    s.branches_observed++;
    if (branch_taken) {
        s.branches_taken++;
    } else {
        s.branches_not_taken++;
    }
    if (Stats *h = g_current_hist_bucket) {
        h->branches_observed++;
        if (branch_taken) {
            h->branches_taken++;
        } else {
            h->branches_not_taken++;
        }
    }
    /* Fast path: BBTemplate caches the BranchRecord*.  First fire does
     * the hash lookup; subsequent fires of the same template skip
     * straight to the cached pointer.  Valid because we never erase
     * BranchHistory entries and std::unordered_map preserves pointer
     * stability across rehashes. */
    BranchRecord *br = bb_tmpl ? bb_tmpl->cached_branch_record : nullptr;
    if (!br) {
        br = g_branch_history.get_or_create(branch_pc, bb_fall_through);
        if (bb_tmpl) {
            bb_tmpl->cached_branch_record = br;
        }
    }
    if (br) {
        br->fall_through = bb_fall_through;
        /* CP direction history for the wpprune cold-branch filter. */
        if (branch_taken) {
            br->taken_count++;
        } else {
            br->nottaken_count++;
        }
    }
    return br;
}

/*
 * Resolve the wrong-path target for a just-finalized true BB whose
 * terminating branch is the last insn of @bb_tmpl.  Returns 0 when no
 * plausible WP target exists.  Caller holds data_lock.
 *
 * @taken_out receives the TAKEN-edge target, derived from the same
 * observations the resolver uses — never the raw (often PC-relative)
 * immediate.  It is current_pc (where CP transferred) in every case
 * except "CP fell through a resolvable direct conditional", where it
 * is the side CP did NOT run (the same value used for the wrong
 * path).  0 only when the BB has no branch.
 */
static uint64_t resolve_wrong_target(const BBTemplate *bb_tmpl,
                                     BranchRecord *br,
                                     bool branch_taken,
                                     uint64_t current_pc,
                                     uint64_t prev_ft,
                                     uint64_t *taken_out)
{
    *taken_out = 0;
    int br_idx = TemplateStore::template_branch_index(bb_tmpl);
    const InsnFields *bf = (br_idx >= 0)
        ? &bb_tmpl->insn_fields[br_idx] : nullptr;
    if (!bf) {
        return 0;
    }

    bool is_indirect = bf->branch_type == BRANCH_INDIRECT_JUMP ||
                       bf->branch_type == BRANCH_RETURN ||
                       bf->branch_type == BRANCH_INDIRECT_CALL;
    bool direct_cond = bf->branch_type == BRANCH_COND_DIRECT ||
                       (bf->branch_type == BRANCH_DIRECT_JUMP &&
                        bf->branch_conditional);

    if (is_indirect) {
        /*
         * The observed-target pool drives indirect_wrong_target, so
         * it MUST stay correct-path-only: folding a speculative target
         * back in would poison the very decision that picks the next
         * speculative target.  vcpu_tb_exec already early-returns when
         * g_wp_state.in_progress; the explicit guard hard-enforces the
         * invariant for any future caller.
         */
        if (branch_taken && !g_wp_state.in_progress) {
            BranchHistory::note_target(br, current_pc);
        }
        /* Indirect/return: CP transferred to current_pc — that IS
         * the observed taken edge. */
        *taken_out = current_pc;
        return BranchHistory::indirect_wrong_target(br, current_pc, prev_ft);
    }
    if (branch_taken) {
        /* CP took the branch → taken edge = where it went;
         * WP = the fall-through. */
        *taken_out = current_pc;
        return prev_ft;
    }
    if (direct_cond && bf->taken_target_pc != 0 &&
        bf->taken_target_pc != prev_ft) {
        /*
         * CP fell through a direct conditional → the taken edge is
         * the side CP did NOT run, which the resolver also uses as
         * the wrong path.  taken_target_pc comes from QEMU's
         * translator (the same value handed to gen_goto_tb), NOT
         * Capstone's immediate — per-ISA encoding (PC-relative vs
         * absolute, sign extension, MIPS delay-slot accounting, ARM
         * Thumb interworking) is already correctly resolved there.
         */
        *taken_out = bf->taken_target_pc;
        return bf->taken_target_pc;
    }
    /* Unconditional jump whose sole direction is its fall-through
     * (current_pc == prev_ft, e.g. `jmp .+2`), or an unresolved
     * terminator: CP still transferred to current_pc — that is the
     * taken edge.  No distinct wrong path. */
    *taken_out = current_pc;
    return 0;
}

/*
 * wpprune cold-branch filter: should the wrong path for this just-resolved
 * branch be skipped?  Off when g_wp_prune == 0.  Uses the branch's
 * correct-path history (BranchRecord), which already includes the current
 * execution (observe_branch_transition runs first):
 *
 *   level 1 — drop WP for a branch never seen taken; for an indirect
 *             (incl. return) drop when it is monomorphic (< 2 distinct
 *             observed targets), i.e. no alternative target to speculate to.
 *   level 2 — additionally drop WP for a conditional seen going only one
 *             way (not both taken and not-taken).
 *
 * Pruning only suppresses the speculative walk; the correct-path taken edge
 * and all CP recording are untouched.
 */
static bool wp_branch_pruned(const BBTemplate *bb_tmpl, const BranchRecord *br)
{
    if (g_wp_prune <= 0 || !br) {
        return false;
    }
    int br_idx = TemplateStore::template_branch_index(bb_tmpl);
    const InsnFields *bf = (br_idx >= 0)
        ? &bb_tmpl->insn_fields[br_idx] : nullptr;
    if (!bf) {
        return false;
    }
    bool is_indirect = bf->branch_type == BRANCH_INDIRECT_JUMP ||
                       bf->branch_type == BRANCH_RETURN ||
                       bf->branch_type == BRANCH_INDIRECT_CALL;
    if (is_indirect) {
        return br->n_targets < 2;
    }
    bool conditional = bf->branch_conditional ||
                       bf->branch_type == BRANCH_COND_DIRECT;
    if (conditional) {
        if (g_wp_prune >= 2) {
            return br->taken_count == 0 || br->nottaken_count == 0;
        }
        return br->taken_count == 0;
    }
    /* Unconditional direct jump/call: resolve_wrong_target returns 0
     * (no wrong path) anyway, so nothing to prune. */
    return false;
}

/*
 * Run the WP simulator (if applicable), then emit the just-finalized
 * BB's BodyEntry.  Caller holds exec_lock; cp_chain is thread_local.
 */
void emit_finalized_bb(BodyStreamState *out_stream,
                       BBTemplate *bb_tmpl,
                       uint64_t prev_last,
                       uint64_t current_pc,
                       uint64_t wrong_target,
                       unsigned int cpu_index)
{
    g_cp_chain.reset();

    std::vector<WPBBEntry> wp_entries;
    /* Genuine first-fetch failure from the accepted (non-flush-
     * interrupted) walker run: the excursion was kicked but its first
     * wrong-path target could not be fetched/translated, so wp_entries
     * is empty.  Carried onto the BodyEntry so the writer emits the
     * chain-level CST_WP_EVENT_TRANSLATION_UNAVAIL event (§4.4). */
    bool wp_first_tb_unavail = false;
    /*
     * Wrong-path speculation relies on the guest MMU to fault on fetches
     * into non-code (a speculative branch into data then page-faults, which
     * aborts the walk).  With paging/MMU disabled — e.g. x86 early boot
     * before CR0.PG — there is no such bound: a speculative branch into a
     * zero/data page decodes as an endless run of no-branch instructions
     * ("NOP sled to infinity"), folding into a true-BB that never seals and
     * exhausting memory.  Don't speculate when the MMU is off.  Always true
     * in linux-user (a process has a valid address space), so user-mode WP
     * is unaffected; this only gates the system-mode pre-paging window,
     * which is not a trace target anyway (the real target is a user process
     * with paging on).
     */
    if (enable_wrong_path && wrong_target != 0 && qemu_plugin_paging_enabled()) {
        /* A tb_flush that unwinds a spec-mode exec_tb mid-walk truncates
         * the chain at that point — the walk cannot be RESUMED (the flush
         * dropped its spec translations; continuing would run wrong-path
         * code outside the sandbox).  A fresh RE-RUN is safe and is the
         * walker's designed contract: the bail epilogue fully restored CP
         * state, the flush has completed, and the re-run re-translates in
         * the fresh cache.  Discard the truncated chain and take the
         * re-run's complete one (exact-or-longer: a flush-shortened chain
         * is indistinguishable from a silent bug on the wire).  Bounded:
         * back-to-back flushes landing inside consecutive re-runs are
         * vanishingly rare; two attempts cover the observed class. */
        for (int attempt = 0; attempt < 3; attempt++) {
            bool flush_interrupted = false;
            wp_entries = simulate_wrong_path_ext(
                prev_last, current_pc, wrong_target, cpu_index,
                &flush_interrupted, &wp_first_tb_unavail);
            if (!flush_interrupted) {
                break;
            }
            thread_stats_get().wp_flush_reruns++;
            if (Stats *h = g_current_hist_bucket) {
                h->wp_flush_reruns++;
            }
        }
    } else if (wrong_target == 0) {
        thread_stats_get().wp_skipped++;
        if (Stats *h = g_current_hist_bucket) {
            h->wp_skipped++;
        }
    }

    /* @current_pc is the resolved architectural successor of this BB's
     * terminating branch (collect_finalized_bbs' frag_current_pc / the seal
     * point) — the PC the next emitted entry starts at.  Pass it so the
     * CST_FID_BRANCH_* singletons record the true direction/target.  Marked
     * known: every emit_finalized_bb caller resolved a successor. */
    emit_body_entry(out_stream, bb_tmpl, cpu_index, std::move(wp_entries),
                    wp_first_tb_unavail, current_pc, /*known=*/true);
}

/*
 * Capture post-exec dst-register values of the just-finished TB's
 * last instruction.  The per-insn cb chain captures only insn[0..n-2]
 * (each on insn[i+1]'s pre-exec hook); insn[n-1] would need a hook on
 * the next TB's first insn, unknowable at translation.  Capturing
 * here at the next TB's vcpu_tb_exec is equivalent: registers still
 * hold prev_tb's last insn's post-exec values (this TB's body hasn't
 * run yet).  The one exception is the branch's PC dst, which a goto_tb
 * chain leaves stale in env->eip; it is taken from @current_pc (the
 * known successor) instead of the live read — see the loop body.
 */
static void snap_prev_tail_dsts(unsigned int cpu_index,
                                const BBTemplate *tmpl,
                                uint64_t current_pc)
{
    if (g_features.reg_data && tmpl->insn_reg_names &&
        tmpl->n_insns > 0 &&
        g_trace_segments.is_active_atomic()) {
        /* Capture the tail insn(s) whose dsts the per-insn hooks could
         * not reach.  Templates are in true execution order, so the
         * last insn is the delay slot on a delay-slot tail
         * [branch@n-2, delay@n-1]; otherwise it is the branch itself.
         *
         * On a delay-slot tail the branch's snap was deferred here (see
         * tb_arm_new_template_cbs) so its REG_IP (PC) dst can take the
         * goto_tb successor override.  Capture the branch (n-2) first,
         * then the delay slot (n-1) — matching execution and template
         * order.  The override fires only on the branch's REG_IP dst,
         * so applying it in both passes is correct on every ISA. */
        uint32_t last = tmpl->n_insns - 1;
        bool delay_slot_tail = tmpl->n_insns >= 2 &&
            tmpl->insn_fields[last - 1].branch_type != BRANCH_NONE &&
            tmpl->insn_fields[last].branch_type == BRANCH_NONE;
        auto capture_tail = [&](uint32_t idx) {
            const InsnFields *fl = &tmpl->insn_fields[idx];
            const InsnRegNames *nl = &tmpl->insn_reg_names[idx];
            for (uint8_t i = 0; i < fl->n_dst_regs; i++) {
                RegSnap s;
                g_reg_snaps.read_into_snap(
                    cpu_index, nl->dst_qemu_reg_keys[i], &s);
                if (fl->dst_regs[i] == REG_IP) {
                    /* The BB-terminating branch's PC dst.  Correct-path
                     * TBs chain via goto_tb, which SKIPS the env->eip
                     * write at the boundary, so the live read is stale
                     * (the chain's entry, not this branch's target).
                     * The post-branch PC is exactly the successor, held
                     * reliably as @current_pc.  Keep the architectural
                     * width; override the value.  (WP TBs are
                     * CF_NO_GOTO_TB so their eip is always synced.) */
                    s.value = cst_wide_from_u64(current_pc);
                }
                pending_reg_snaps.push_back(s);
            }
        };
        if (delay_slot_tail) {
            capture_tail(last - 1);   /* branch (deferred) */
        }
        capture_tail(last);           /* delay slot, or branch on non-delay ISAs */
    }
}

/*
 * Per-CP attribution: bump opcode / branch_type / src / dst counters
 * per insn of the just-committed CP fragment.  Cache thread_stats_get()
 * once — the g_stats macro re-resolves the TLS slot via __tls_get_addr
 * each expansion, and this loop bumps it up to 4×n_insns.
 */
static void attribute_cp_insns(const BBTemplate *tmpl)
{
    Stats &s = thread_stats_get();
    Stats *h = g_current_hist_bucket;
    for (uint32_t i = 0; i < tmpl->n_insns; i++) {
        const InsnFields *f = &tmpl->insn_fields[i];
        s.cp_insns_by_opcode[f->opcode]++;
        if (h) h->cp_insns_by_opcode[f->opcode]++;
        if (f->branch_type != BRANCH_NONE) {
            s.cp_branches_by_type[f->branch_type]++;
            if (h) h->cp_branches_by_type[f->branch_type]++;
        }
        for (uint8_t k = 0; k < f->n_src_regs; k++) {
            s.cp_src_reg_uses[f->src_regs[k]]++;
            if (h) h->cp_src_reg_uses[f->src_regs[k]]++;
        }
        for (uint8_t d = 0; d < f->n_dst_regs; d++) {
            s.cp_dst_reg_writes[f->dst_regs[d]]++;
            if (h) h->cp_dst_reg_writes[f->dst_regs[d]]++;
        }
    }
}

/*
 * Tracing-window management.  May start/stop trace segments and
 * exit() the process.  Must release exec_lock before exit() so
 * plugin_exit can re-acquire.  All early-out paths are exit(0)
 * (process death); on a normal return the caller still holds
 * exec_lock and proceeds to the body-stream check.  Checks key off
 * icount_prev so the trace covers AT LEAST the requested window.
 */
/* Open the pinned-simpoint trace window at the current TB.  Called from
 * the fast-forward fast-path (vcpu_tb_exec) the moment the pinned
 * process's user clock reaches the simpoint's effective start; the first
 * traced TB is this one.  user_count_reset(lo) zeroes the clock so the
 * window budget (warmup + simulation) is measured from here. */
static void open_pinned_simpoint_window(unsigned int cpu_index,
                                        uint64_t icount_prev)
{
    const SimPointEntry *sp = g_simpoints.current();
    if (!sp) {
        return;
    }
    uint64_t sim = simulation_insns ? simulation_insns
                                    : simpoint_interval_insns;
    uint64_t span = warmup_insns + sim;
    uint64_t lo = icount_prev;
    uint64_t hi = lo + span;
    uint64_t reached_at = g_user_icount;
    g_trace_segments.set_window(lo, hi);
    user_count_reset(cpu_index, lo);
    g_autofree char *label = g_strdup_printf("simpoint_%d", sp->cluster_id);
    fprintf(stderr, "champsim_tracer: pinned simpoint %d reached (user clock %"
            PRIu64 ") — tracing %" PRIu64 " user insns (%" PRIu64
            " warmup)\n", sp->cluster_id, reached_at, span, warmup_insns);
    start_trace_segment(label, lo, hi, warmup_insns, span, cpu_index,
                        sp->weight);
}

static void tw_manage_window(unsigned int cpu_index,
                             uint64_t icount_prev,
                             BBTemplate *cur_tb_tmpl)
{
    if (g_window_mode == PluginConfig::WIN_SYMBOL ||
        g_window_mode == PluginConfig::WIN_MARKER ||
        pinned_simpoint_mode()) {
        /* Pinned-simpoint takes this branch even before the marker pins:
         * its open (below, gated on marker_pinned) waits for the pin, and
         * falling through to the icount else-branch would wrongly open a
         * window at icount 0 during boot. */
        /* Stop once the post-trigger simulation_insns budget is spent
         * (window_stop set when the symbol fired, or when the guest
         * marker fired — see vcpu_marker_cb, which is what opens the
         * segment in WIN_MARKER mode; only the close runs here).
         *
         * In WIN_MARKER the budget is measured in the pinned process's
         * USER-SPACE instructions (g_user_icount), not raw icount: the
         * marker pins one address space, and its kernel calls are traced
         * but must not count toward the window — so the window covers the
         * same user-space instructions a user-mode run would.  WIN_SYMBOL
         * (user mode) has no pin and uses raw icount as before. */
        bool marker_pinned = marker_user_clock();
        /* window_start/stop stay in raw icount (the header's start_insn is
         * the real icount at the marker).  In marker mode g_user_icount
         * counts user-space insns from 0, so compare it against the span
         * (stop - start), not the absolute stop. */
        uint64_t budget_now = marker_pinned ? g_user_icount : icount_prev;
        uint64_t budget_stop = marker_pinned
            ? g_trace_segments.window_stop() - g_trace_segments.window_start()
            : g_trace_segments.window_stop();
        if (g_trace_segments.is_active() && budget_now >= budget_stop) {
            /* Budget reached — but this runs MID-STEP: step_events has
             * already promoted the current TB into the pending-seal slot,
             * while the previous TB (the slot's old occupant) is still
             * waiting for step_seal.  Closing here would emit the current
             * TB twice (once by the segment-final flush, once as the seal
             * walk's already-swapped prev) and lose the previous TB's
             * entry outright — the [body, head, head] duplicate-final-
             * entry corruption.  Defer to the same sealed-step tail the
             * icount window-stop uses: the seal phase first emits the
             * deferred prev normally, then the tail's segment-final flush
             * drains the pending-seal slot (the budget-crossing TB whose
             * insns the clock already counted) exactly once. */
            g_icount_shutdown_pending = true;
        }
        if (g_window_mode == PluginConfig::WIN_SYMBOL &&
            !g_trace_segments.is_active() && start_symbol) {
            /* cur_tb_tmpl IS the executing TB's head-fragment template (its
             * per-TB udata); no start_pc lookup needed.  Pre-segment this is
             * delivered by vcpu_tb_check_budget (the heavy vcpu_tb_exec cb is
             * gated off until a segment is active), so the occurrence counter
             * advances here on the budget slow path — once open, the same
             * pointer arrives via events_path_step, but is_active() is then
             * true and this branch is skipped. */
            BBTemplate *cur_tmpl = cur_tb_tmpl;
            if (cur_tmpl && cur_tmpl->symbol_name &&
                cst_str_eq(cur_tmpl->symbol_name, start_symbol)) {
                start_symbol_match_count++;
                if (start_symbol_match_count >= start_symbol_occurrence) {
                    /* Open at the matching TB's icount; run for
                     * simulation_insns more (0 = unbounded, ends at
                     * process exit). */
                    uint64_t lo = icount_prev;
                    uint64_t hi = simulation_insns
                        ? icount_prev + simulation_insns : UINT64_MAX;
                    g_trace_segments.set_window(lo, hi);
                    uint64_t total_target =
                        (hi == UINT64_MAX) ? 0 : hi - lo;
                    g_autofree char *label = g_strdup_printf(
                        "sym_%s_%" PRIu64,
                        start_symbol, start_symbol_occurrence);
                    start_trace_segment(label, lo, hi,
                                        /* warmup= */ 0, total_target,
                                        cpu_index,
                                        /* simpoint_weight= */ 0.0);
                }
            }
        }
    } else if (g_simpoints.is_active() && !pinned_simpoint_mode()) {
        if (g_trace_segments.is_active() &&
            icount_prev >= g_trace_segments.window_stop()) {
            /* icount has optimistically crossed window_stop but the
             * chain assembler may still have in-flight fragments
             * awaiting a branch terminator.  Defer the actual
             * finish + advance to a BB boundary at the tail of
             * vcpu_tb_exec (symmetric to the icount-shutdown path
             * just above).  Until then we stay is_active so pending
             * fragments emit normally and the trace covers the full
             * simulation_insns window. */
            g_simpoint_close_pending = true;
            return;
        }
        if (!g_trace_segments.is_active()) {
            if (const SimPointEntry *sp = g_simpoints.current()) {
                /* Effective window: warmup before the simpoint,
                 * simulation_insns at-and-after (0 → legacy
                 * sp->stop_insn).  warmup underflow clamps to 0. */
                uint64_t eff_start = (sp->start_insn > warmup_insns)
                    ? sp->start_insn - warmup_insns : 0;
                uint64_t eff_stop = simulation_insns
                    ? sp->start_insn + simulation_insns
                    : sp->stop_insn;
                if (icount_prev >= eff_start &&
                    icount_prev <  eff_stop) {
                    g_trace_segments.set_window(eff_start, eff_stop);
                    /* Name the segment by simpoint position in
                     * billions of insns (workload-NNNB convention) so
                     * it maps back to the simpoints/weights line.
                     * Integer arithmetic, not a double: scientific
                     * notation's 'e-05' minus would corrupt the
                     * '-'-separated filename.  Fractional billions use
                     * '_' ("73_4B") so the only '.' is the .cst ext. */
                    uint64_t pos   = sp->start_insn;
                    uint64_t whole = pos / 1000000000ULL;
                    uint64_t frac  = pos % 1000000000ULL;
                    g_autofree char *label = nullptr;
                    if (frac == 0) {
                        label = g_strdup_printf("%" PRIu64 "B", whole);
                    } else {
                        char fbuf[10];
                        g_snprintf(fbuf, sizeof(fbuf),
                                   "%09" PRIu64, frac);
                        int fn = 9;
                        while (fn > 1 && fbuf[fn - 1] == '0') {
                            fn--;
                        }
                        fbuf[fn] = '\0';
                        label = g_strdup_printf("%" PRIu64 "_%sB",
                                                whole, fbuf);
                    }
                    /* Report actual pre-simpoint insns traced, not
                     * the configured warmup budget. */
                    uint64_t hdr_warmup = sp->start_insn > eff_start
                        ? sp->start_insn - eff_start : 0;
                    start_trace_segment(label, eff_start, eff_stop,
                                        hdr_warmup,
                                        /* total_target= */ eff_stop - eff_start,
                                        cpu_index, sp->weight);
                }
            } else {
                g_trace_segments.set_shutting_down();
                g_rec_mutex_unlock(&exec_lock);
                exit(0);
            }
        }
    } else {
        if (!g_trace_segments.is_active() &&
            icount_prev >= g_trace_segments.window_start() &&
            icount_prev <  g_trace_segments.window_stop()) {
            uint64_t lo = g_trace_segments.window_start();
            uint64_t hi = g_trace_segments.window_stop();
            /* Header total: (stop - start), or 0 (unbounded) when
             * stop defaulted to UINT64_MAX. */
            uint64_t total_target = (hi == UINT64_MAX) ? 0 : hi - lo;
            start_trace_segment("trace", lo, hi,
                                /* warmup= */ 0, total_target, cpu_index,
                                /* simpoint_weight= */ 0.0);
        }
        if (g_trace_segments.is_active() &&
            icount_prev >= g_trace_segments.window_stop()) {
            /* Stop is reached optimistically (bumped count past
             * window_stop), but the CP chain assembler may still
             * have in-flight fragments awaiting a branch terminator.
             * Defer the actual finalize+exit until vcpu_tb_exec
             * observes the chain has no active in-flight; that way
             * every bumped insn either ends up committed to a BB in
             * the trace or never triggered the bump in the first
             * place. */
            g_icount_shutdown_pending = true;
        }
    }
}

/* Threshold-crossing handler registered as a cond_cb on the budget
 * scoreboard slot (COND_GE (1<<63) on the u64 storage — see the
 * registration site for the signed-negative-via-unsigned trick).
 * Fires when the per-TB INLINE_ADD_U64(-n_insns) decrements the
 * budget into the signed-negative range — i.e., when icount has
 * reached the next eff_start.  Open the segment via tw_manage_window
 * and reset the budget so the cond becomes false again.  During WP
 * simulation we bail without touching the budget since spec-mode TBs
 * decrement it too; finish_wp restores the pre-WP budget value,
 * which re-triggers this cb cleanly post-WP. */
static void vcpu_tb_check_budget(unsigned int cpu_index, void *udata)
{
    if (g_wp_state.in_progress) {
        /* No-op inside WP; spec-mode TB inline_adds will keep firing
         * this cb on every spec TB until WP restores the saved
         * budget.  The cost is one C call + return per spec TB. */
        return;
    }
    g_rec_mutex_lock(&exec_lock);
    if (g_trace_segments.is_shutting_down()) {
        g_rec_mutex_unlock(&exec_lock);
        return;
    }
    uint64_t icount_now = qemu_plugin_u64_get(
        g_scoreboard.insn_count, cpu_index);
    if (g_ff_coarse.load(std::memory_order_relaxed)) {
        /* Coarse fast-forward handoff: the pinned-user countdown armed
         * at pin time crossed zero, FF_COARSE_MARGIN short of the
         * simpoint's effective start.  The compensation cond_cb nets
         * foreign user TBs out of the countdown, so the fold into the
         * user clock is exact (see g_ff_coarse; the only slack is the
         * few pre-pin-flush TBs, which land early, never late).  Switch
         * the final stretch to the exact per-TB path, which counts
         * against the live ASID and opens the window on the precise
         * threshold.  The flush retires coarse-instrumented TBs so
         * later translations regain the unconditional budget decrement
         * for post-window inter-segment logic. */
        g_ff_coarse.store(false, std::memory_order_relaxed);
        g_user_icount = g_ff_coarse_target;
        qemu_plugin_u64_set(g_scoreboard.user_seen, cpu_index, icount_now);
        for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; i++) {
            qemu_plugin_u64_set(g_scoreboard.is_active, (unsigned)i, 1);
            qemu_plugin_u64_set(g_scoreboard.budget, (unsigned)i,
                                (uint64_t)BUDGET_INACTIVE_SENTINEL);
            refresh_ctx_gates((unsigned)i);
        }
        qemu_plugin_request_tb_flush();
        fprintf(stderr, "champsim_tracer: coarse fast-forward handoff at "
                "user clock %" PRIu64 " (raw icount %" PRIu64 ", foreign "
                "user insns compensated %" PRIu64 ") — exact positioning "
                "for the final %" PRIu64 " insns\n",
                g_user_icount, icount_now, g_ff_foreign_insns,
                FF_COARSE_MARGIN);
        g_rec_mutex_unlock(&exec_lock);
        return;
    }
    g_host_icount = icount_now;
    /* tw_manage_window handles icount-, simpoint-, symbol- and marker-mode
     * open/close logic.  Passing icount_now (post-inline-add value) matches
     * BBV's "count past threshold" semantics.
     *
     * udata is the executing TB's head fragment (baked into this cond_cb's
     * registration, same pointer the vcpu_tb_exec cond_cb gets).  It is
     * load-bearing for WIN_SYMBOL: pre-segment the heavy vcpu_tb_exec cb is
     * gated OFF (trace_this_ctx==0), so this budget cb — armed for every TB
     * once recompute_next_threshold parks the symbol/marker threshold at 0
     * ("every TB must take the slow path") — is the ONLY path that can see
     * the executing TB's resolved symbol name and advance the start-symbol
     * occurrence counter before a segment opens.  Other modes ignore it. */
    tw_manage_window(cpu_index, icount_now, (BBTemplate *)udata);
    /* Re-arm the budget for the next event.  In-segment: sentinel
     * (won't fire while is_active=1 dispatches to vcpu_tb_exec for
     * close detection).  Inter-segment: countdown to next eff_start. */
    recompute_budget(cpu_index);
    g_rec_mutex_unlock(&exec_lock);
}

/* PendingEmit is declared in champsim_tracer_path_builder.h: the events
 * path shares the walk below and the emission entry points verbatim. */

/*
 * Walk the previous TB's fragment list up to the LAST EXECUTED fragment
 * (identified by the scoreboard's @prev_start), fold each executed
 * fragment into the CP true-BB chain, and collect every completed BB as a
 * PendingEmit -- resolving its terminal-branch direction and wrong-path
 * target here.  Intermediate fragments fell through by definition (a later
 * fragment in the same TB ran), so their "next PC" is the successor
 * fragment's start_pc; the last-executed fragment uses the scoreboard's
 * @current_pc.  A trap mid-TB stops later fragments' stores from firing, so
 * the walk naturally truncates at the trapping fragment.  Returns true if
 * any BB finalized.  Caller holds exec_lock; this takes data_lock for the
 * chain/cache mutations.
 */
bool collect_finalized_bbs(unsigned int cpu_index,
                           BBTemplate *prev_tb_head,
                           uint64_t prev_start, uint64_t current_pc,
                           std::vector<PendingEmit> &pending_emits)
{
    g_mutex_lock(&data_lock);
    bool any_finalize = false;

    /* Identify the last-executed fragment.  The scoreboard's @prev_start
     * normally pinpoints it (a mid-TB trap prevents later fragments' first-
     * insn stores from firing).  But an async interrupt or a foreign-ASID
     * span BETWEEN prev's execution and this delayed seal overwrites
     * @prev_start: the intervening TBs' per-fragment inline stores fire on
     * their own execution, regardless of the capture mute (the mute gates
     * only the C callbacks).  When no fragment matches, prev ran to
     * completion — an interrupt / foreign TB is taken at a TB boundary, so
     * the deferred prev finished — and its last-executed fragment is simply
     * its LAST fragment.  Without this fallback, is_last_executed never
     * fires at the resume seal, snap_prev_tail_dsts is skipped, and the tail
     * insn's dst snaps go missing — sliding every later insn's POSITIONAL
     * reg-snap attribution (build_entry_view prefix-sums n_dst_regs), which
     * lands a code address on an ALU dst and reads metaflags from the wrong
     * slot.  A clobbered @prev_start that coincidentally matches a fragment
     * of prev is astronomically unlikely (disjoint code regions) and, if it
     * ever happened, is caught by the emit-time reg-snap backstop. */
    BBTemplate *last_frag = nullptr;
    bool prev_start_matches = false;
    for (BBTemplate *frag = prev_tb_head; frag != nullptr;
         frag = frag->next_tb_fragment) {
        last_frag = frag;
        if (frag->start_pc == prev_start) {
            prev_start_matches = true;
        }
    }

    for (BBTemplate *frag = prev_tb_head; frag != nullptr;
         frag = frag->next_tb_fragment) {
        bool is_last_executed = prev_start_matches
            ? (frag->start_pc == prev_start)
            : (frag == last_frag);

        uint64_t frag_current_pc;
        uint64_t frag_prev_ft = frag->fall_through_pc;
        if (is_last_executed) {
            frag_current_pc = current_pc;
        } else if (frag->next_tb_fragment) {
            frag_current_pc = frag->next_tb_fragment->start_pc;
        } else {
            /* No successor but not the last-executed: only the first TB of
             * the trace (untouched scoreboard).  Use the scoreboard value. */
            frag_current_pc = current_pc;
        }
        bool frag_branch_taken = (frag_current_pc != frag_prev_ft);

        if (is_last_executed) {
            snap_prev_tail_dsts(cpu_index, frag, frag_current_pc);
        }
        cp_chain_append(frag);
        attribute_cp_insns(frag);

        if (BBTemplate *bb_tmpl = cp_chain_finalize_if_complete()) {
            PendingEmit pe = {bb_tmpl, 0, frag_current_pc, 0};
            int br_idx = TemplateStore::template_branch_index(bb_tmpl);
            if (br_idx >= 0) {
                pe.branch_pc = bb_tmpl->insn_pcs[br_idx];
                BranchRecord *br = observe_branch_transition(
                    bb_tmpl, frag_branch_taken, pe.branch_pc,
                    frag_prev_ft);
                uint64_t taken_target = 0;
                pe.wrong_target = resolve_wrong_target(
                    bb_tmpl, br, frag_branch_taken,
                    frag_current_pc, frag_prev_ft, &taken_target);
                if (taken_target != 0) {
                    bb_tmpl->taken_pc = taken_target;
                }
                /* wpprune: skip the wrong path for a cold branch.  The
                 * taken edge above is already recorded; only the
                 * speculative walk is suppressed. */
                if (pe.wrong_target != 0 && wp_branch_pruned(bb_tmpl, br)) {
                    pe.wrong_target = 0;
                }
            }
            pending_emits.push_back(pe);
            any_finalize = true;
        }

        if (is_last_executed) {
            break;
        }
    }

    g_mutex_unlock(&data_lock);
    return any_finalize;
}

/*
 * RAII freeze of the guest virtual clock across a plugin instrumentation
 * window (per-TB emission in vcpu_tb_exec, translation work in
 * vcpu_tb_trans).  Instrumentation runs on the vCPU thread but is not guest
 * execution, so its host wall-clock cost must not be charged to guest time:
 * left unfrozen, a heavily traced guest timer-tick handler can cost more
 * guest time than one tick period, and the guest collapses into a
 * self-sustaining tick/scheduler storm (context-switch storm, RCU-kthread
 * starvation, zero foreground progress — the x86 system-mode livelock).
 * Nestable and composes with the wrong-path vtime pause; no-op in user mode.
 */
struct VClockPauseGuard {
    VClockPauseGuard() { qemu_plugin_vclock_pause(); }
    ~VClockPauseGuard() { qemu_plugin_vclock_resume(); }
    VClockPauseGuard(const VClockPauseGuard &) = delete;
    VClockPauseGuard &operator=(const VClockPauseGuard &) = delete;
};

/* Set by the spec-budget trip in vcpu_tb_trans (mid-excursion); consumed
 * at the end of the CP step in vcpu_tb_exec, where no wrong-path walk is
 * in flight and the translation that tripped has completed. */
static std::atomic<bool> g_spec_flush_latched{false};

/*
 * Deferred icount / simpoint window closes.  The crossing is detected
 * optimistically at TB-start while the chain assembler may still hold
 * fragments awaiting a terminator; closing is deferred to a step tail
 * with no active in-flight chain, so every inline-add-counted insn is
 * either committed to an emitted BB or never bumped ("trace covers AT
 * LEAST the requested window").  Caller holds exec_lock; the close paths
 * unlock it themselves before exit(0).  @pb is the calling thread's
 * builder (its pending-seal slot must be cleared on the simpoint close).
 */
static void run_deferred_window_closes(PathBuilder &pb)
{
    /* Deferred-exit on icount window-stop.  The trigger was set in
     * tw_manage_window when icount first crossed window_stop. */
    if (g_icount_shutdown_pending &&
        !g_cp_chain.has_active_chain() &&
        g_trace_segments.is_active()) {
        finish_trace_segment();
        g_trace_segments.set_shutting_down();
        g_icount_shutdown_pending = false;
        /* No need to recompute_budget: we're exiting immediately and
         * the budget slot will be torn down with the scoreboard. */
        g_rec_mutex_unlock(&exec_lock);
        exit(0);
    }

    /* Simpoint analogue: finalize only after the chain has drained to a
     * BB boundary so the trace covers AT LEAST eff_stop - eff_start
     * (warmup + simulation) insns. */
    if (g_simpoint_close_pending &&
        !g_cp_chain.has_active_chain() &&
        g_trace_segments.is_active()) {
        finish_trace_segment();
        g_simpoints.advance();
        g_simpoint_close_pending = false;
        pb.clear_prev();
        pb.events_queue_disable();
        if (!g_simpoints.current()) {
            g_trace_segments.set_shutting_down();
            g_rec_mutex_unlock(&exec_lock);
            exit(0);
        }
        recompute_next_threshold();
        /* Re-arm budget so the per-TB inline_add countdown lands at
         * zero when icount reaches the now-current eff_start. */
        for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; i++) {
            recompute_budget((unsigned)i);
        }
    }
}

/*
 * The CP step, driven by the ordered per-vCPU event queue.  The shared
 * prologue of vcpu_tb_exec — WP early-out, chain promotion,
 * capture-mute latch, blkwatch, vclock guard, icount read — has already
 * run.  This glue keeps the SHARED machinery at the step level (window
 * management, segment boundary, heartbeat/histogram, scoreboard reads,
 * deferred closes, spec-flush latch) and hands everything path-shaped to
 * the PathBuilder: the drained events, the async/foreign arrows, the
 * pending-seal slot, the fault frames, and emission.  The gate ORDER is
 * load-bearing on both sides of the window management: step_events
 * (async gate, foreign-ASID drop, prev swap) runs before it — an
 * async-suspended TB must not drive window decisions, and the marker
 * close's segment-final flush walks the just-swapped prev — while
 * step_seal (depth pipeline, fault classification, seal walk, emits)
 * runs after the boundary gates so events during bailed steps accumulate
 * to the next surviving step.
 */
static void events_path_step(unsigned int cpu_index, BBTemplate *cur_tb_tmpl,
                             uint64_t icount_prev, uint64_t watch_pc)
{
    PathBuilder &pb = path_builder_tls();

    /* Enable this vCPU's event queue lazily on its first CP exec (clears
     * any boot-time backlog).  Must run on the owning vCPU thread, which
     * a tb_exec callback guarantees. */
    if (!pb.events_queue_enabled()) {
        qemu_plugin_cpu_events_set(cpu_index, true);
        pb.mark_events_queue_enabled(cpu_index);
    }

    g_rec_mutex_lock(&exec_lock);

    /* Address-space pin + count set (marker mode only — pinned !=
     * UNPINNED).  The inline-add counts every TB; here we fold this TB's
     * instruction count (the delta of consecutive insn_count reads) into
     * g_user_icount ONLY when the pinned process runs at user privilege,
     * so the window budget tracks the same user-space instructions a
     * user-mode run would.  The executing fragment's privilege is stamped
     * from the LIVE correct-path context (authoritative — the shared
     * true-BB cache can be seeded first by a wrong-path session that
     * spec-translated this PC at the kernel's CPL; see
     * BBTemplate::is_system).  Runs under exec_lock — g_user_icount is a
     * plain static, racy if mutated pre-lock on multi-vCPU guests (the
     * seen cursor itself is per-vCPU).  It must run before tw_manage_window
     * (the marker budget clock includes this TB) and before the
     * async/foreign arrows (every TB — including ones about to be
     * dropped — advances the seen cursor and carries the CP ground-truth
     * privilege stamp). */
    uint64_t pinned_asid = g_pinned_asid.load(std::memory_order_relaxed);
    uint64_t live_asid = 0;
    int live_priv = -1;
    /* user_owned  == CLOCK ownership: the marker (pinned) process's user
     *                TBs, which advance g_user_icount and the END window.
     *                Narrow (pin_user_tb_owned) in every mode.
     * capture_owned == CAPTURE ownership: which user TBs reach the trace.
     *                In latch it equals user_owned; in trace-all it widens
     *                to EVERY user TB (foreign processes are captured too),
     *                so the foreign-ASID boundary in step_events lets them
     *                through and kernel work folds to whichever process
     *                last ran user code. */
    bool user_owned = false;
    bool capture_owned = false;
    if (pinned_asid != CST_ASID_UNPINNED) {
        uint64_t delta = user_seen_advance(cpu_index, icount_prev);
        live_asid = qemu_plugin_get_addr_space_id();
        live_priv = qemu_plugin_get_priv_level();
        /* Ownership of a user TB: legacy ASID equality on the
         * wide-register targets, the physical-page identity machinery
         * on narrow-ASID ones (see pin_user_tb_owned).  Counted and
         * traced are the same set by construction — an unverified TB
         * neither advances the user clock nor reaches the trace. */
        if (live_priv == 0 && cur_tb_tmpl) {
            user_owned = pin_user_tb_owned(cpu_index, live_asid,
                                           pinned_asid,
                                           cur_tb_tmpl->start_pc);
            /* Fingerprint this process from its OWN user code (Bug C):
             * the identity that reaches the wire must be a real per-process
             * content hash, not the global representative one.  Capture the
             * first time each non-representative root runs a user TB —
             * reliable (live CR3 IS this root, its code page resident) and
             * independent of the racy marker-callback read.  Bounded: one
             * page hash per distinct root (skipped once known). */
            if (live_asid != 0 && live_asid != pinned_asid &&
                (!g_cr3_user_sig || !g_cr3_user_sig->count(live_asid))) {
                uint64_t usig;
                if (pin_page_sig(cur_tb_tmpl->start_pc & PIN_PAGE_MASK,
                                 &usig)) {
                    asid_set_user_sig(live_asid, usig);
                }
            }
            /* Capture widens to every user context in trace-all; the clock
             * (user_owned) stays the marker process. */
            capture_owned = marker_trace_all() ? true : user_owned;
        }
        if (user_owned) {
            g_user_icount += delta;
            /* Progress-driven dead-latch peer sweep (throttled).  A live
             * owned process ages out a dead peer through its own user-clock
             * progress, so a straggler window closes even when the guest is
             * not context-switching (the ASID-write trigger's blind spot).
             * Off the hot path: one compare per owned TB, the sweep only at
             * a stride crossing. */
            if (g_latch_timeout_ms &&
                g_user_icount - g_deadlatch_checked_uic >=
                    DEADLATCH_UIC_STRIDE) {
                g_deadlatch_checked_uic = g_user_icount;
                deadlatch_clock_check(cpu_index, live_asid);
            }
        }
        if (cur_tb_tmpl) {
            cur_tb_tmpl->is_system = live_priv != 0;
            cur_tb_tmpl->is_system_cp_confirmed = true;
        }
    }

    if (cur_tb_tmpl) {
        cst_ring_push('C', cur_tb_tmpl->start_pc);  /* #77 ring (gated) */
    }

    /* Drain the ordered path events.  step_events copies them out
     * immediately (the queue's internal buffer is only valid until the
     * next push) and retains fault events across bailed steps, so no
     * event is ever lost to an early return below. */
    PathBuilder::StepIn in;
    in.cur = cur_tb_tmpl;
    in.prev_start = 0;      /* scoreboard fields read after window mgmt */
    in.prev_ft = 0;
    in.current_pc = 0;
    in.pinned = pinned_asid != CST_ASID_UNPINNED;
    /* Kernel-TB attribution and event matching compare against the
     * vCPU's EFFECTIVE pin: the dwell tag on narrow-ASID targets (which
     * re-pins across rollover/migration), the marker-time value on the
     * wide-register ones. */
    in.pinned_asid = pin_effective_asid(cpu_index, pinned_asid);
    in.live_asid = live_asid;
    in.live_priv = live_priv;
    /* CAPTURE ownership drives the foreign-ASID drop, the kernel-excursion
     * fold, and the (asid,thread) context refresh — widened to every user
     * context in trace-all.  The CLOCK stays user_owned (folded above). */
    in.user_owned = capture_owned;
    in.evs = nullptr;
    in.n_evs = qemu_plugin_drain_cpu_events(cpu_index, &in.evs);
    in.cpu_index = cpu_index;
    in.watch_pc = watch_pc;

    /* Pre-window phase: async-window arrows, foreign-ASID boundary, prev
     * swap — in that order, before any window decision. */
    PathBuilder::StepStatus st = pb.step_events(in);
    if (st != PathBuilder::StepStatus::CONTINUE) {
        if (in.pinned && user_owned) {
            /* CST_MARKER_DIAG stall canaries: pinned user TBs bailing
             * here means the user clock advances but nothing traces. */
            if (st == PathBuilder::StepStatus::SUSPENDED) {
                tls_mkdiag_susp_user++;
            } else if (st == PathBuilder::StepStatus::SUSPENDED_FOREIGN) {
                tls_mkdiag_foreign_user++;
            }
        }
        g_rec_mutex_unlock(&exec_lock);
        return;
    }

    if (g_trace_segments.is_shutting_down()) {
        g_rec_mutex_unlock(&exec_lock);
        return;
    }

    uint32_t seg_gen_before = g_segment_generation.load(
        std::memory_order_relaxed);
    tw_manage_window(cpu_index, icount_prev, cur_tb_tmpl);
    bool segment_just_opened =
        g_segment_generation.load(std::memory_order_relaxed) != seg_gen_before;

    BodyStreamState *out_stream = g_trace_segments.body_stream();
    if (!g_trace_segments.is_active() || !out_stream) {
        g_rec_mutex_unlock(&exec_lock);
        return;
    }

    if (segment_just_opened) {
        /* PER-THREAD segment-open boundary (one-TB lossy):
         * reset_segment_local_state runs once on the OPENER thread
         * (global caches + its own TLS); every vCPU thread crosses into
         * the new segment HERE, via the generation check, and must reset
         * its own builder (frames, pending seal, retained events, mute
         * window, depth pipeline — lazily re-primed), clear any
         * pre-marker async state, and re-enable the queue, which discards
         * the queue-side backlog straddling the boundary (pre-segment
         * events are baselined out by the lazy re-prime). */
        pb.on_segment_open();
        qemu_plugin_async_int_reset();
        g_capture_mute = false;
        qemu_plugin_cpu_events_set(cpu_index, true);
        g_rec_mutex_unlock(&exec_lock);
        return;
    }

    heartbeat_progress(icount_prev);
    g_current_hist_bucket = select_histogram_bucket(icount_prev);

    in.current_pc = qemu_plugin_u64_get(g_scoreboard.current_pc, cpu_index);
    in.prev_start = qemu_plugin_u64_get(g_scoreboard.prev_start_pc,
                                        cpu_index);
    in.prev_ft    = qemu_plugin_u64_get(g_scoreboard.prev_fall_through,
                                        cpu_index);

    st = pb.step_seal(in, out_stream);

    /* Advance this vCPU's guest-thread identity AFTER the deferred-prev
     * seal above: the just-emitted BB belongs to the thread that executed
     * it (the previous user TB), so this refresh takes effect only for the
     * NEXT emit.  A user-owned priv-0 TB re-reads the thread pointer (which
     * survives vCPU migration); a kernel TB leaves it, inheriting the
     * thread that entered the kernel.  Under exec_lock — thread_ptr_to_tid
     * mutates the per-segment map. */
    if (in.pinned && in.user_owned && in.live_priv == 0 &&
        cpu_index < CST_PIN_MAX_VCPUS) {
        uint64_t tp = qemu_plugin_get_thread_ptr();
        if (tp != g_vcpu_last_tp[cpu_index]) {
            g_vcpu_last_tp[cpu_index] = tp;
            uint32_t new_tid = thread_ptr_to_tid(tp);
            g_vcpu_cur_tid[cpu_index] = new_tid;
            if (tiddiag_on()) {
                tiddiag_note_binding(cpu_index, new_tid);
            }
        }
        /* Context-asid sibling of the tid refresh: the live user root at
         * priv 0 IS the process's user CR3.  Record it (idempotent — same
         * root maps to the same index) so a subsequent kernel excursion
         * folds this thread's regfile/FieldState CONTEXT to the entering
         * process, not the KPTI kernel CR3.  Set every user TB (not only on
         * a tid change) so it holds the entering asid at the excursion.
         *
         * Narrow-ASID latch (MIPS, not trace-all): key on the CONFIRMED
         * owner's stable anchor rather than the recycled EntryHi.ASID, so a
         * rollover of the process's value never mints a spurious index and
         * the memory/context asid stays pinned to the owning process across
         * its whole run.  Trace-all keeps the live-root mapping (Stage B2:
         * every context by its own root). */
        int ow = (g_pin_reuse_guard && !marker_trace_all())
            ? g_pin_vcpu[cpu_index].owner.load(std::memory_order_relaxed) : -1;
        if (ow >= 0 && g_owned_procs && ow < (int)g_owned_procs->size() &&
            (*g_owned_procs)[ow].active) {
            const OwnedProc &op = (*g_owned_procs)[ow];
            g_vcpu_cur_asid_index[cpu_index] =
                asid_root_to_index(op.root_phys, op.marker_sig);
        } else {
            uint64_t live_root = qemu_plugin_get_addr_space_id();
            g_vcpu_cur_asid_index[cpu_index] =
                asid_root_to_index(live_root, asid_first_sight_sig(live_root));
        }
        /* Migration-detect guard: record this vCPU in the pinned process's
         * per-segment user-vCPU set (every user TB, not only on a tid
         * change), firing one warning if the process spans vCPUs. */
        pin_user_vcpu_observe(cpu_index);
    }

    /* Only a normally-sealed step evaluates the deferred closes and
     * consumes the spec-flush latch — the stash / merge / no-seal
     * outcomes skip both (a pending close waits for the next normal
     * step). */
    if (st != PathBuilder::StepStatus::SEALED) {
        g_rec_mutex_unlock(&exec_lock);
        return;
    }

    run_deferred_window_closes(pb);
    g_rec_mutex_unlock(&exec_lock);

    if (g_spec_flush_latched.exchange(false, std::memory_order_relaxed)) {
        qemu_plugin_request_tb_flush();
    }
}

/*
 * Light per-TB probe for the unowned / unconfirmed context under a
 * narrow-ASID system pin.  Registered (only when g_pin_reuse_guard)
 * BEFORE the heavy vcpu_tb_exec and gated on the pin_probe scoreboard
 * slot, so it dispatches ONLY while a segment is active and this vCPU's
 * dwell is not a confirmed-owned pinned context — never for user mode,
 * unpinned system, or a wide-register pin.  It is the whole per-foreign-
 * TB budget: no VClockPauseGuard, no PathBuilder step, and exec_lock is
 * taken only on the user-TB probe path.  Everything the heavy callback's
 * foreign-ASID arm used to do for a foreign span (mute the per-insn
 * capture callbacks, set the deferred prev aside so nothing seals across
 * the gap, tick the user-clock cursor) is done here instead — cheaply — and
 * on the TB that re-acquires the pinned process it flips trace_this_ctx
 * to 1 so the heavy callback's re-loaded brcond fires for that same TB.
 */
static void vcpu_pin_probe(unsigned int cpu_index, void *udata)
{
    /* Wrong-path simulation re-dispatches the TB's callbacks on the same
     * thread that already owns the CP step; it touches no pin state. */
    if (g_wp_state.in_progress) {
        return;
    }
    BBTemplate *cur_tb_tmpl = (BBTemplate *)udata;
    uint64_t icount = qemu_plugin_u64_get(g_scoreboard.insn_count, cpu_index);

    /* Physical-page re-acquisition (user TBs only; a kernel TB carries no
     * user-code PC to match against the map, and the switch-return kernel
     * path is charged to the excursion owner by kexc regardless).  One
     * probe per unconfirmed user TB — the exact per-TB semantics the
     * heavy path had, minus its cost — until a hit confirms the dwell. */
    if (cur_tb_tmpl && cpu_index < CST_PIN_MAX_VCPUS &&
        !g_pin_vcpu[cpu_index].confirmed.load(std::memory_order_relaxed) &&
        qemu_plugin_get_priv_level() == 0) {
        uint64_t live_asid = qemu_plugin_get_addr_space_id();
        g_rec_mutex_lock(&exec_lock);
        PinVcpuState &ps = g_pin_vcpu[cpu_index];
        bool mismatch = false;
        int hit = pin_map_probe_owners(cur_tb_tmpl->start_pc,
                                       ps.owner.load(std::memory_order_relaxed),
                                       &mismatch);
        if (hit >= 0) {
            ps.owner.store(hit, std::memory_order_relaxed);
            if (live_asid != ps.asid.load(std::memory_order_relaxed)) {
                /* Re-acquired under a different ASID value — a generation
                 * rollover re-numbered the process or it migrated onto a
                 * vCPU whose per-CPU ASID differs.  Re-pin the dwell tag. */
                ps.asid.store(live_asid, std::memory_order_relaxed);
                qemu_plugin_u64_set(g_scoreboard.asid_match, cpu_index, 1);
                g_stats.pin_repins++;
            }
            ps.confirmed.store(true, std::memory_order_relaxed);
            refresh_ctx_gates(cpu_index);   /* trace_this_ctx=1, pin_probe=0 */
            g_rec_mutex_unlock(&exec_lock);
            /* Do NOT advance the user cursor here: the heavy callback
             * fires for this very TB (its brcond re-loads trace_this_ctx)
             * and folds this TB's delta into the user clock itself. */
            return;
        }
        if (mismatch) {
            g_stats.pin_phys_mismatch_dropped++;
        } else {
            g_stats.pin_unverified_dropped++;
        }
        g_rec_mutex_unlock(&exec_lock);
    }

    /* Unowned this TB.  Mute the per-insn capture callbacks (still gated
     * on is_active, they self-drop on g_capture_mute) so the foreign
     * span's registers/memops never pile into the pinned process's
     * pending state.
     *
     * Dropping the deferred prev, though, is a USER-TB decision only.  The
     * physical-page map adjudicates USER-CODE identity; a kernel TB carries
     * no user-code PC to probe (see the priv==0 guard above), so a kernel
     * TB reaching here is a synchronous excursion — a fault/exception
     * handler — whose ownership the heavy path decides with the kexc
     * machinery, not the dwell.  The pinned process's own fault handler
     * routes through this light probe whenever a transient foreign ASID
     * write (a brief kernel overlay, e.g. a MIPS EntryHi ASID scratch) has
     * un-confirmed the dwell an instant before the exception; destroying
     * the interrupted user block's pending seal HERE drops that block
     * outright (silent CP corruption — the resume then seals a later block
     * against the handler's fetch, and the interrupted block never emits).
     * Leave prev intact for kernel TBs: the pinned process resumes at the
     * faulting instruction and seals the interrupted block against its real
     * successor (the case-(c) fault path), exactly as the heavy+kexc path
     * would have; a genuinely foreign span still drops prev when its own
     * USER code resumes and mismatches the physical-page map (the priv==0
     * probe above).  INSIDE an async window prev is likewise preserved
     * (the SUSPENDED contract — the resume seals the interrupted branch
     * against its real target). */
    g_capture_mute = true;
    if (!qemu_plugin_in_async_int() && qemu_plugin_get_priv_level() == 0) {
        g_mem_recorder.clear_cp();
        path_builder_tls().clear_prev();
    }
    /* User-clock cursor tick: advance this vCPU's seen cursor so the
     * foreign span's instructions never fold into the pinned process's
     * user clock when it resumes (the delta is measured from HERE). */
    user_seen_advance(cpu_index, icount);
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    /* This callback is registered via register_vcpu_tb_exec_cond_cb
     * gated on the trace_this_ctx scoreboard slot (is_active folded with
     * pinned-context ownership), so the JIT only dispatches it in-segment
     * for a context this trace owns.  Inter-segment dispatch is handled
     * solely by inline_add (icount/budget) and vcpu_tb_check_budget; a
     * foreign / unowned in-segment TB is handled by the light
     * vcpu_pin_probe instead (narrow-ASID pins) or never diverges at all.
     *
     * udata = the head fragment of this TB's per-translation fragment
     * list, set when the translation was armed in vcpu_tb_trans.
     * Both CP-mode and WP-mode (qemu_plugin_exec_tb) invocations
     * deliver the executing TB through the same pointer. */
    BBTemplate *cur_tb_tmpl = (BBTemplate *)udata;

    /* WP-mode early-out runs BEFORE exec_lock acquisition.  The CP
     * thread that triggered this WP simulation already holds
     * exec_lock from emit_finalized_bb's caller; vcpu_tb_exec fires
     * synchronously inside qemu_plugin_exec_tb on the same thread, so
     * the WP branch must not re-acquire it (exec_lock is a GRecMutex,
     * so a nested acquire would recurse rather than deadlock — but the
     * nested step would then run the full CP machinery against WP
     * state).  The WP-mode branch only touches thread-local state, so
     * it skips the lock cleanly. */
    if (g_wp_state.in_progress) {
        g_wp_state.last_executed_tb = cur_tb_tmpl;
        return;
    }

    /* Fast-forward fast-path (pinned-simpoint, system mode).  Between the
     * pin and the window opening, the ONLY work needed per TB is to
     * advance the pinned process's user-instruction clock and watch for
     * the simpoint's effective start.  Placed ahead of the whole per-TB
     * prologue (promote, capture-mute latch, the vclock pause/resume) so
     * the hundreds of billions of fast-forward instructions skip all of
     * it.  On the TB that crosses the threshold we open the window and
     * fall through into the full path so this same TB is the first one
     * traced. */
    if (pinned_simpoint_mode() &&
        g_pinned_asid.load(std::memory_order_relaxed) != CST_ASID_UNPINNED &&
        !g_trace_segments.is_active()) {
        uint64_t icount_ff = qemu_plugin_u64_get(g_scoreboard.insn_count,
                                                 cpu_index);
        uint64_t delta = user_seen_advance(cpu_index, icount_ff);
        /* Positioning accuracy only, lock-free: compare against the
         * vCPU's effective pin (dwell tag on narrow-ASID targets) but
         * without the map probe — a rollover during a long fast-forward
         * can drift the count until the process's next verified dwell;
         * the traced window itself is always probe-verified. */
        if (qemu_plugin_get_addr_space_id() ==
                pin_effective_asid(cpu_index,
                                   g_pinned_asid.load(
                                       std::memory_order_relaxed)) &&
            qemu_plugin_get_priv_level() == 0) {
            g_user_icount += delta;
        }
        const SimPointEntry *sp = g_simpoints.current();
        uint64_t eff_start = (sp && sp->start_insn > warmup_insns)
            ? sp->start_insn - warmup_insns : 0;
        if (sp && g_user_icount >= eff_start) {
            g_rec_mutex_lock(&exec_lock);
            if (!g_trace_segments.is_active() &&
                !g_trace_segments.is_shutting_down()) {
                open_pinned_simpoint_window(cpu_index, icount_ff);
            }
            g_rec_mutex_unlock(&exec_lock);
        }
        /* Fast-forward is per-TB accounting only; the first traced TB is
         * handled by the full path on the NEXT dispatch (segment now
         * active).  Always return here. */
        return;
    }

    /* Correct-path execution promotes this TB's whole fragment chain to
     * the CODE lifetime class and moves its dedup visibility to the
     * CODE index — protection from the SPEC reclaim at tb_flush (#91)
     * for chains the wrong path minted first, in one transition (see
     * TemplateStore::promote).  CODE-born chains are indexed at
     * registration, so the pre-lock gate on chain_indexed keeps the
     * steady state lock-free; promote() rechecks under data_lock. */
    if (cur_tb_tmpl && !cur_tb_tmpl->chain_indexed) {
        g_mutex_lock(&data_lock);
        g_template_store.promote(cur_tb_tmpl);
        g_mutex_unlock(&data_lock);
    }

    /* Latch the async-exclusion decision for this TB's body callbacks
     * (see g_capture_mute) before any early return below — the dropped
     * boundary TBs still fire their per-insn capture callbacks. */
    g_capture_mute = qemu_plugin_in_async_int();

    /* CST_BLKWATCH=<hex pc> (#90 diagnostic): one-line report every time a
     * watched TB's exec callback fires, with the gate states that could
     * suppress its emission.  A single integer compare per call; prints only
     * for the watched PC, so the timing perturbation is negligible. */
    static uint64_t watch_pc = getenv("CST_BLKWATCH")
        ? strtoull(getenv("CST_BLKWATCH"), nullptr, 16) : 0;
    if (watch_pc && cur_tb_tmpl && cur_tb_tmpl->start_pc == watch_pc) {
        BBTemplate *watch_prev = path_builder_tls().prev();
        fprintf(stderr, "[blkwatch] exec pc=0x%" PRIx64 " async=%d fdepth=%u "
                "prev=0x%" PRIx64 "\n",
                cur_tb_tmpl->start_pc, (int)qemu_plugin_in_async_int(),
                qemu_plugin_fault_depth(),
                watch_prev ? watch_prev->start_pc : 0);
    }

    /* Everything below is instrumentation cost, not guest execution:
     * keep it off the guest clock (see VClockPauseGuard). */
    VClockPauseGuard vclock_guard;


    /* Read the running instruction count.  The per-TB insn_count inline-add
     * is injected BEFORE this callback (plugin-gen emits a TB's cbs in
     * registration order, and the add is registered first in vcpu_tb_trans),
     * so insn_count already includes this TB.  tw_manage_window consumes it
     * as the running icount. */
    uint64_t icount_prev = qemu_plugin_u64_get(
        g_scoreboard.insn_count, cpu_index);
    g_host_icount = icount_prev;

    /* CST_SMP_DIAG: one line at each vCPU's first in-segment dispatch —
     * SMP coverage triage (a vCPU missing from this set traced nothing). */
    static const bool smp_diag = getenv("CST_SMP_DIAG") != nullptr;
    if (smp_diag) {
        static thread_local bool announced;
        if (!announced) {
            announced = true;
            fprintf(stderr, "champsim_tracer: [smpdiag] first exec dispatch "
                    "on cpu %u\n", cpu_index);
        }
    }

    /* The PathBuilder consumes the ordered per-vCPU event queue and runs
     * the CP step from here on.  Everything above this line is the shared
     * per-TB prologue. */
    events_path_step(cpu_index, cur_tb_tmpl, icount_prev, watch_pc);
}

/* ========================= Translation callback ========================= */

/*
 * Arm the per-insn dynamic callbacks for a freshly created template:
 * post-exec dst-register snapshots and synthetic-EA capture for
 * memory-hint opcodes.  See the inline comments for the
 * canonical-first / ci-1 timing rationale.
 */
/*
 * Post-exec dst-register capture.  Register the snap cb on raw insn i
 * (canonical_first && ci > 0) pointing at ci-1: firing pre-exec of ci means
 * ci-1 just completed, so its dst registers hold post-exec values.  The
 * TB's last canonical insn is captured at the next TB's vcpu_tb_exec
 * ("Tail-insn dst snap").
 *
 * Delay-slot tail: on MIPS (and similar ISAs) a true BB ends with a
 * [branch, delay-slot] pair kept in true execution order — branch at
 * canonical[n-2], delay slot at canonical[n-1].  The branch's PC-dst
 * (REG_IP) needs the goto_tb override that only snap_prev_tail_dsts can
 * supply (it knows the successor PC), so DEFER the branch's snap to the
 * next TB rather than capturing it here at the delay slot's pre-exec hook.
 * Detect the pair by branch_type and skip the cb whose ci-1 is the branch
 * (ci == n-1); snap_prev_tail_dsts then captures both canonical[n-2]
 * (branch, with REG_IP override) and canonical[n-1] (delay slot) at the
 * right time.
 */
static void arm_reg_snap_cbs(struct qemu_plugin_tb *tb, BBTemplate *new_tmpl,
                             size_t raw_n_insns,
                             const uint32_t *canonical_index,
                             const bool *canonical_first,
                             uint32_t canonical_n_insns)
{
    if (!((g_features.reg_data || g_features.wp_reg_data) && new_tmpl &&
          new_tmpl->insn_reg_names)) {
        return;
    }
    /* The RegSnapInsnRef udata array lives in the (persistent) template and
     * is allocated once; on a dedup reuse it already exists and we only
     * re-register the QEMU callbacks below against it (a re-translation must
     * re-arm the JIT-level callbacks even though the udata is unchanged). */
    if (!new_tmpl->insn_snap_refs) {
        RegSnapInsnRef *refs = g_new0(RegSnapInsnRef, canonical_n_insns);
        new_tmpl->insn_snap_refs = refs;
        for (uint32_t i = 0; i < canonical_n_insns; i++) {
            refs[i].tb_tmpl = new_tmpl;
            refs[i].insn_index = i;
        }
    }
    RegSnapInsnRef *refs = (RegSnapInsnRef *)new_tmpl->insn_snap_refs;
    bool delay_slot_tail = canonical_n_insns >= 2
        && new_tmpl->insn_fields[canonical_n_insns - 2].branch_type
             != BRANCH_NONE
        && new_tmpl->insn_fields[canonical_n_insns - 1].branch_type
             == BRANCH_NONE;
    for (size_t i = 0; i < raw_n_insns; i++) {
        if (!canonical_first[i]) {
            continue;
        }
        uint32_t ci = canonical_index[i];
        if (ci == 0) {
            continue;  /* no predecessor canonical insn in this TB */
        }
        if (delay_slot_tail && ci == canonical_n_insns - 1) {
            /* The cb HERE would capture canonical[n-2] (the branch); defer
             * it to snap_prev_tail_dsts so the branch's REG_IP dst gets the
             * goto_tb successor override. */
            continue;
        }
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        /* Gate on the is_active scoreboard slot so the callback skips
         * entirely between segments via a JIT-emitted check — no
         * plugin-side tb_flush needed at segment boundaries.  Translations
         * cached from any prior segment continue to fire harmlessly: the
         * cond_cb predicate is false outside segments and the JIT skips the
         * callback. */
        qemu_plugin_register_vcpu_insn_exec_cond_cb(
            insn, vcpu_insn_reg_snap_cb,
            QEMU_PLUGIN_CB_R_REGS,
            QEMU_PLUGIN_COND_GE, g_scoreboard.is_active, 1,
            &refs[ci - 1]);
    }
}

/*
 * Synthetic-EA capture for memory-hint opcodes (prefetch / cache-flush /
 * tlb-flush) whose effective address QEMU does not surface as a memop.
 * Decode the EA per canonical insn, then arm a register-reading cb on each
 * raw insn whose canonical insn resolved an address.
 */
static void arm_synth_ea_cbs(struct qemu_plugin_tb *tb, BBTemplate *new_tmpl,
                             const qemu_plugin_insn_info *insn_info,
                             size_t raw_n_insns,
                             const uint32_t *canonical_index,
                             const bool *canonical_first,
                             uint32_t canonical_n_insns)
{
    if (!new_tmpl) {
        return;
    }
    for (uint32_t i = 0; i < canonical_n_insns; i++) {
        uint8_t op = new_tmpl->insn_fields[i].opcode;
        if (op != GEN_OP_PREFETCH &&
            op != GEN_OP_CACHE_FLUSH &&
            op != GEN_OP_TLB_FLUSH) {
            continue;
        }
        if (!new_tmpl->insn_synthetic_ea) {
            new_tmpl->insn_synthetic_ea =
                g_new0(SyntheticEAInfo, canonical_n_insns);
        }
        decode_synthetic_ea(&insn_info[i], op,
                            new_tmpl->insn_pcs[i],
                            new_tmpl->insn_sizes[i],
                            &new_tmpl->insn_synthetic_ea[i]);
    }
    if (!new_tmpl->insn_synthetic_ea) {
        return;
    }
    /* Allocate the udata once (persistent template); on a dedup reuse
     * re-register the callbacks against the existing refs. */
    if (!new_tmpl->insn_synth_ea_refs) {
        SynthEAInsnRef *synth_refs = g_new0(SynthEAInsnRef, canonical_n_insns);
        new_tmpl->insn_synth_ea_refs = synth_refs;
        for (uint32_t i = 0; i < canonical_n_insns; i++) {
            synth_refs[i].tb_tmpl = new_tmpl;
            synth_refs[i].insn_index = i;
        }
    }
    SynthEAInsnRef *synth_refs = (SynthEAInsnRef *)new_tmpl->insn_synth_ea_refs;
    for (size_t i = 0; i < raw_n_insns; i++) {
        if (!canonical_first[i]) {
            continue;
        }
        uint32_t ci = canonical_index[i];
        if (!new_tmpl->insn_synthetic_ea[ci].has_addr) {
            continue;
        }
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        qemu_plugin_register_vcpu_insn_exec_cond_cb(
            insn, vcpu_insn_synth_ea_cb,
            QEMU_PLUGIN_CB_R_REGS,
            QEMU_PLUGIN_COND_GE, g_scoreboard.is_active, 1,
            &synth_refs[ci]);
    }
}

static void tb_arm_new_template_cbs(struct qemu_plugin_tb *tb,
                                    BBTemplate *new_tmpl,
                                    const qemu_plugin_insn_info *insn_info,
                                    size_t raw_n_insns,
                                    const uint32_t *canonical_index,
                                    const bool *canonical_first,
                                    uint32_t canonical_n_insns)
{
    arm_reg_snap_cbs(tb, new_tmpl, raw_n_insns, canonical_index,
                     canonical_first, canonical_n_insns);
    arm_synth_ea_cbs(tb, new_tmpl, insn_info, raw_n_insns, canonical_index,
                     canonical_first, canonical_n_insns);
}

/*
 * One per-fragment record produced by split_tb_into_fragments.  The
 * fragment covers canonical insns [start, start + n_insns) of the
 * source QEMU TB.
 */
struct TbFragmentSpec {
    uint32_t   start_canonical;
    uint32_t   n_insns;
    TbTerminus terminus;
};

/*
 * Split a QEMU TB's canonical insn stream at any non-final branch
 * terminator.  A TB may contain multiple control-flow terminators
 * (e.g. a conditional trap mid-TB followed by code TCG kept
 * translating past), and each one ends a true BB at that point.  This
 * walker emits one TbFragmentSpec per resulting fragment; the chain
 * assembler then folds fragments into true BBs.
 *
 * - On every branch-classified insn @i < n - 1, emit a fragment
 *   [prev_start..i] (or [prev_start..i+1] for delay-slot ISA branches
 *   whose slot is at i+1 in this TB) terminating in COMPLETE.
 * - A delay-slot ISA branch as the literal last insn yields a
 *   trailing BARE_BRANCH fragment (the slot lands in the next TB).
 * - Trailing insns after the last branch (or a TB with no branches
 *   at all) form a final NONE fragment that continues into the next
 *   TB via the chain assembler.
 *
 * The tracer makes no assertion that a QEMU TB ends in a branch or
 * that branches only appear at the end — TCG and Capstone can
 * disagree about which insns terminate control flow (e.g. MIPS
 * conditional traps), and the splitter is what reconciles that
 * disagreement at the true-BB layer.
 */
static void split_tb_into_fragments(const qemu_plugin_insn_info *insn_info,
                                    uint32_t n_insns,
                                    std::vector<TbFragmentSpec> &out)
{
    out.clear();
    if (!insn_info || n_insns == 0) {
        return;
    }
    auto insn_branch_type = [](const qemu_plugin_insn_info *info) -> uint8_t {
        if (!info->mnemonic[0]) {
            return BRANCH_NONE;
        }
        /* Full-size scratch backing: the decode contract requires wired
         * spans (the dep/lane refiners write through them even though
         * only branch_type is consumed here). */
        InsnFieldsScratch s;
        insn_fields_scratch_reset(&s);
        decode_detail_to_generic(0, info, &s.f, nullptr);
        return s.f.branch_type;
    };
    /*
     * Branch families that carry an architectural delay slot — the
     * insn right after the branch always executes (MIPS j / jal /
     * jr / b*).  syscall- and trap-type "branches" do NOT have a
     * delay slot and so end their fragment on the branch insn itself.
     *
     * The exception-return family (MIPS eret / eretnc / deret) is
     * classified BRANCH_RETURN — semantically right for consumers —
     * but unlike `jr $ra` it has NO delay slot.  QEMU always ends the
     * TB at an eret, so without this exclusion the splitter marks the
     * eret fragment BARE_BRANCH and the chain assembler absorbs the
     * next executed TB (the exception-return TARGET — usually user
     * code) as its "delay slot", welding kernel and user code into one
     * true-BB and desyncing the whole system-mode fault machinery.
     */
    auto is_no_delay_slot_mnemonic = [](const char *m) -> bool {
        return m[0] == 'e' ? (!strcmp(m, "eret") || !strcmp(m, "eretnc"))
                           : !strcmp(m, "deret");
    };
    auto has_delay_slot = [&](uint8_t bt,
                              const qemu_plugin_insn_info *info) -> bool {
        if (bt != BRANCH_DIRECT_JUMP && bt != BRANCH_INDIRECT_JUMP &&
            bt != BRANCH_RETURN && bt != BRANCH_COND_DIRECT &&
            bt != BRANCH_DIRECT_CALL && bt != BRANCH_INDIRECT_CALL) {
            return false;
        }
        return !is_no_delay_slot_mnemonic(info->mnemonic);
    };
    bool delay_isa = isa_properties[trace_isa].branch_delay_slots > 0;

    uint32_t frag_start = 0;
    uint32_t i = 0;
    while (i < n_insns) {
        uint8_t bt = insn_branch_type(&insn_info[i]);
        if (bt == BRANCH_NONE) {
            i++;
            continue;
        }
        if (delay_isa && has_delay_slot(bt, &insn_info[i])) {
            if (i + 1 < n_insns) {
                /* Branch + delay slot both in this TB: fragment runs
                 * through the delay slot (canonical index i+1). */
                out.push_back({frag_start, (i + 2) - frag_start,
                               TB_TERMINUS_COMPLETE});
                frag_start = i + 2;
                i = i + 2;
            } else {
                /* Bare branch as the literal last insn: delay slot
                 * lives in the next QEMU TB. */
                out.push_back({frag_start, (i + 1) - frag_start,
                               TB_TERMINUS_BARE_BRANCH});
                frag_start = i + 1;
                i = i + 1;
            }
        } else {
            /* Non-delay-slot branch (syscall / trap / non-delay-slot
             * ISA conditional or unconditional branch): fragment ends
             * on the branch insn itself. */
            out.push_back({frag_start, (i + 1) - frag_start,
                           TB_TERMINUS_COMPLETE});
            frag_start = i + 1;
            i = i + 1;
        }
    }

    /* Trailing tail with no terminator: continues into the next
     * QEMU TB via the chain assembler. */
    if (frag_start < n_insns) {
        out.push_back({frag_start, n_insns - frag_start,
                       TB_TERMINUS_NONE});
    }
}

/*
 * Guest-issued trace marker (WIN_MARKER, x86 only for now).
 *
 * The marker is a sequence of CST_MARKER_SEQ_LEN identical
 * `mov $CST_MARKER_MAGIC, %eax` instructions back to back.  The plugin
 * spots that exact byte run at translation time and arms a one-shot exec
 * callback on the last one; when it executes, a trace segment opens and
 * the window pins to the executing address space (see vcpu_marker_cb).
 * It needs no ELF symbol table, no host icount, and no modification to the
 * target or the guest kernel, so it is the mechanism for system-mode
 * tracing of a chosen process (paging on, where wrong-path speculation is
 * bounded).
 *
 * Why a repeated sequence and not a single mov: a lone `mov $imm, %eax`
 * can collide with ordinary code that happens to load that constant.
 * Three identical immediate-loads to the same register in a row are
 * provably-dead redundant work (the 2nd and 3rd rewrite %eax with a value
 * it already holds) — no compiler emits that and a human only would
 * deliberately, so the marker cannot occur in real code by accident.  The
 * sequence must sit within one TB (straight-line, no branch, not straddling
 * a page); the injector that emits it (cst_attach / synthetic workload)
 * places it so.
 *
 * The magic must execute INSIDE the target's address space.  A launcher
 * that runs it then execve's the target does NOT work: execve replaces the
 * address space, so the marker's CR3 is the launcher's, not the target's.
 * The marker therefore originates in the post-execve image — compiled into
 * a synthetic workload, or injected at the entry point by cst_attach.
 */
/* Marker magic / sequence length / per-arch encodings: champsim_marker.h
 * (the contract shared with the cst_attach injector). */
static std::atomic<bool> g_marker_fired{false};

/* Per-thread execution-time marker runs (START / END).  The MarkerRunSet
 * type and the detection primitives (marker_seq_init / marker_word_match /
 * marker_exec_step / marker_run_peek / the udata pack-unpack) live in
 * champsim_tracer_marker_detect.{h,cc}; these per-thread run sets and the
 * one-shot fired flag above are touched only by the marker callbacks, so
 * they stay here. */
static thread_local MarkerRunSet tls_marker_run;
static thread_local MarkerRunSet tls_marker_end_run;

/* Open the marker trace window on @cpu_index.  The three WIN_MARKER
 * first-open paths — wide-register, narrow-ASID, and legacy single-pin —
 * share this exact body: guard against a redundant open, then window +
 * user-clock reset + segment start.  @root_phys is logged only on the
 * narrow-ASID path (@have_root_phys); the trace-affecting statements are
 * identical across all three callers.  The caller holds exec_lock. */
static void marker_open_trace_window(unsigned int cpu_index, uint64_t asid,
                                     bool have_root_phys, uint64_t root_phys)
{
    if (g_trace_segments.is_active() || g_trace_segments.is_shutting_down()) {
        return;
    }
    uint64_t lo = qemu_plugin_u64_get(g_scoreboard.insn_count, cpu_index);
    uint64_t span = simulation_insns ? simulation_insns : 1000000;
    uint64_t hi = lo + span;
    g_trace_segments.set_window(lo, hi);
    /* The window budget counts the pinned process's user-space insns from 0
     * (kernel calls are traced but not counted); start the counter here at
     * the marker's icount. */
    user_count_reset(cpu_index, lo);
    if (have_root_phys) {
        fprintf(stderr,
                "champsim_tracer: marker fired at icount %" PRIu64
                ", asid 0x%" PRIx64 " priv=%d (0=user,3=kernel) "
                "pc=0x%" PRIx64 " root_phys=0x%" PRIx64
                " — tracing %" PRIu64 " insns\n",
                lo, asid, qemu_plugin_get_priv_level(),
                qemu_plugin_get_pc(), root_phys, span);
    } else {
        fprintf(stderr, "champsim_tracer: marker fired at icount %" PRIu64
                ", asid 0x%" PRIx64 " priv=%d (0=user,3=kernel) pc=0x%" PRIx64
                " — tracing %" PRIu64 " insns\n",
                lo, asid, qemu_plugin_get_priv_level(),
                qemu_plugin_get_pc(), span);
    }
    start_trace_segment("marker", lo, hi, /* warmup= */ 0, span,
                        cpu_index, /* simpoint_weight= */ 0.0);
}

/* All-windows-closed stop shared by the END-marker paths.  The caller holds
 * exec_lock; when a segment is live this latches the end-marker close, closes
 * it, and exit(0)s (never returns); otherwise it releases exec_lock and
 * returns.  @last_window selects the multi-process "(last window)" diagnostic
 * over the legacy single-pin one. */
static void marker_close_and_exit(bool last_window)
{
    if (g_trace_segments.is_active() && !g_trace_segments.is_shutting_down()) {
        if (last_window) {
            fprintf(stderr,
                    "champsim_tracer: end marker — closing after %" PRIu64
                    " user insns (last window)\n", g_user_icount);
        } else {
            fprintf(stderr, "champsim_tracer: end marker — closing after %"
                    PRIu64 " user insns\n", g_user_icount);
        }
        g_seg_end_marker_close = true;
        finish_trace_segment();
        g_trace_segments.set_shutting_down();
        g_rec_mutex_unlock(&exec_lock);
        exit(0);
    }
    g_rec_mutex_unlock(&exec_lock);
}

static void vcpu_marker_cb(unsigned int cpu_index, void *udata)
{
    /* Wrong-path fence, two independent gates: the QEMU-side per-vCPU
     * spec-mode flag is the ground truth for *this execution* (a
     * speculative invocation observes it regardless of which thread's
     * TLS the callback happens to read), and the per-thread session
     * flag covers the walker's bracketing on the owning thread.
     * Marker detection is a correct-path fact — speculation routinely
     * runs the marker bytes (the wrong path of a spin-wait branch
     * falls straight into the END sequence), so a leak past this
     * fence opens/closes windows from wrong-path execution (observed:
     * a 2 M-insn SMP window closed "END" after 385 k user insns,
     * mid-loop, end-marker template exec_cp=0 / exec_wp=98722). */
    if (qemu_plugin_in_spec_mode() || g_wp_state.in_progress) {
        tls_mkdiag_start_wp_gated++;
        return;
    }
    uint64_t pc;
    uint8_t size;
    marker_udata_unpack(udata, &pc, &size);
    if (!marker_exec_step(&tls_marker_run, pc, size)) {
        return;                              /* run not complete yet */
    }
    /* The marker is one of the target's own instructions, so the current
     * ASID is the target's page-table root. */
    uint64_t asid = qemu_plugin_get_addr_space_id();

    /*
     * Multi-process latch (Stage B1): wide-register WIN_MARKER.  Each
     * process that runs the START marker OPENS ITS WINDOW — joins the
     * owned set — and is traced concurrently; the first open starts the
     * segment, later opens just widen the set.  Excludes the narrow-ASID
     * (MIPS) path — its single-process dwell machinery is retained
     * verbatim (Stage B3) — and the simpoint positioning path (single
     * program by design); both keep the legacy one-shot below.
     */
    if (g_window_mode == PluginConfig::WIN_MARKER && !g_pin_reuse_guard) {
        g_rec_mutex_lock(&exec_lock);
        if (owned_contains_locked(asid)) {
            /* This process already has an open window: the START marker is
             * idempotent per address space (a re-run does not re-open). */
            g_rec_mutex_unlock(&exec_lock);
            return;
        }
        if (marker_trace_all() && !g_owned.empty()) {
            /* Trace-all: the FIRST marker already opened the whole-system
             * window and everything is being captured.  A later marker —
             * from this process or any other — must NOT join the owned set:
             * the clock and END detection stay pinned to that first process
             * (decision #4), and every context is already traced anyway. */
            g_rec_mutex_unlock(&exec_lock);
            return;
        }
        bool first_open = g_owned.empty();
        g_owned.insert(asid);
        g_owned_last_sched[asid] = deadlatch_now_ms();
        if (first_open) {
            /* First window: pin the representative root, seed its identity
             * signature from the marker's own code page (@pc is this
             * callback's own instruction address from udata, NOT
             * qemu_plugin_get_pc() — the env PC is stale mid-TB), and open
             * the segment exactly as the single-process path did. */
            g_pinned_asid.store(asid, std::memory_order_relaxed);
            pin_reuse_reset();
            g_pin_repr_vpage = UINT64_MAX;
            g_pin_repr_sig.store(0, std::memory_order_relaxed);
            if (asid != 0) {
                pin_repr_seed(pc);
            }
            /* This is the whole-system open under policy=trace-all too: the
             * segment machinery is identical (pin the first process for the
             * clock + END), and the widened CAPTURE gate lives in the heavy
             * step (marker_trace_all() in events_path_step / refresh_ctx_gates),
             * so every context is traced from here without touching the owned
             * set — which stays this single clock pin (see the guard above). */
            marker_open_trace_window(cpu_index, asid,
                                     /* have_root_phys= */ false, 0);
            /* Assign this root's compact asid index (index 0) with its own
             * marker-page signature.  Runs AFTER start_trace_segment (which
             * resets the per-segment identity map) so the pre-registration
             * survives; cst_pinned_asid_sig() is the repr sig just seeded
             * from THIS process's marker page, so this is byte-identical to
             * letting the first emit assign it. */
            asid_root_to_index(asid, cst_pinned_asid_sig());
        } else {
            /* Additional window while the segment is already open: no new
             * segment.  Register this root's identity with ITS OWN
             * marker-page signature (a per-process sig, not the
             * representative's), and recompute this vCPU's gates so its TBs
             * begin dispatching the heavy callback (pin_user_tb_owned now
             * sees the live root as owned).  Other vCPUs running this root
             * pick it up at their next ASID write via asid_write_track_cb. */
            uint64_t sig = 0;
            if (asid != 0) {
                uint64_t s;
                if (pin_page_sig(pc & PIN_PAGE_MASK, &s)) {
                    sig = s;
                }
            }
            /* Fingerprint this additional process from its own marker page
             * (Bug C), refreshing the identity if a hot-path first-sighter
             * already provisionally stamped the representative signature.
             * The per-user-TB capture usually beats the marker to it; this
             * covers a process whose first user TB has not run yet. */
            if (sig) {
                asid_set_user_sig(asid, sig);
            }
            asid_root_to_index(asid, asid_first_sight_sig(asid));
            qemu_plugin_u64_set(g_scoreboard.asid_match, cpu_index, 1);
            refresh_ctx_gates(cpu_index);
            fprintf(stderr,
                    "champsim_tracer: marker opened additional window for "
                    "asid 0x%" PRIx64 " (%zu owned)\n", asid, g_owned.size());
        }
        g_rec_mutex_unlock(&exec_lock);
        return;
    }

    /*
     * Multi-process latch (Stage B3): narrow-ASID WIN_MARKER (MIPS system
     * mode).  An 8-bit EntryHi.ASID cannot name a process by value, so each
     * owned process is an OwnedProc keyed by physical-page identity: the
     * first START marker seeds owner 0 and opens the segment, later START
     * markers append owners and widen the traced set, each with its own
     * marker-seeded page map and stable (marker-page-phys, sig) wire anchor.
     * Excludes trace-all (Stage B2: the first marker opens a whole-system
     * window; the legacy single-pin path below serves its clock/END) and
     * user mode (asid 0, single address space — also the legacy path, kept
     * byte-identical).
     */
    if (g_window_mode == PluginConfig::WIN_MARKER && g_pin_reuse_guard &&
        asid != 0 && !marker_trace_all()) {
        g_rec_mutex_lock(&exec_lock);
        PinVcpuState &ps = g_pin_vcpu[cpu_index];
        /* Idempotent per process: a re-run of the START marker whose code
         * already belongs to an active owner just re-seats the dwell. */
        bool mm = false;
        int existing = pin_map_probe_owners(
            pc, ps.owner.load(std::memory_order_relaxed), &mm);
        if (existing >= 0 && g_owned_procs &&
            (*g_owned_procs)[existing].active) {
            ps.owner.store(existing, std::memory_order_relaxed);
            ps.asid.store(asid, std::memory_order_relaxed);
            ps.confirmed.store(true, std::memory_order_relaxed);
            qemu_plugin_u64_set(g_scoreboard.asid_match, cpu_index, 1);
            refresh_ctx_gates(cpu_index);
            g_rec_mutex_unlock(&exec_lock);
            return;
        }
        uint64_t root_phys, sig, vpage;
        marker_anchor(pc, asid, &root_phys, &sig, &vpage);
        bool first_open = !g_owned_procs || g_owned_procs->empty();
        if (first_open) {
            /* First window: pin the representative (owner 0), seed its
             * page map + identity from the marker's own code page, and open
             * the segment exactly as the single-process narrow path did. */
            g_pinned_asid.store(asid, std::memory_order_relaxed);
            pin_reuse_reset();
            g_pin_repr_vpage = vpage;
            g_pin_repr_sig.store(sig, std::memory_order_relaxed);
            pin_owned_reset_single(asid, cpu_index, root_phys, sig, vpage);
            pin_map_learn(0, pc);
            marker_open_trace_window(cpu_index, asid,
                                     /* have_root_phys= */ true, root_phys);
            /* Pre-register owner 0's compact index (index 0) with its own
             * marker-page anchor, AFTER start_trace_segment reset the
             * per-segment identity map (mirrors the wide path). */
            asid_root_to_index(root_phys, sig);
        } else {
            /* Additional window: append owner k, seed its map, register its
             * identity, and recompute this vCPU's gates so its confirmed
             * dwell begins dispatching the heavy callback. */
            int idx = pin_owned_append(asid, cpu_index, root_phys, sig, vpage);
            pin_map_learn(idx, pc);
            asid_root_to_index(root_phys, sig);
            qemu_plugin_u64_set(g_scoreboard.asid_match, cpu_index, 1);
            refresh_ctx_gates(cpu_index);
            fprintf(stderr,
                    "champsim_tracer: marker opened additional window for "
                    "narrow owner %d root_phys=0x%" PRIx64 " (%d owned)\n",
                    idx, root_phys, g_owned_procs_active);
        }
        g_rec_mutex_unlock(&exec_lock);
        return;
    }

    /*
     * Legacy single-pin path: pinned-simpoint positioning and the
     * narrow-ASID (MIPS) marker window.  One process, one marker, one
     * shot — byte-identical to the pre-Stage-B behavior.
     */
    bool expected = false;
    if (!g_marker_fired.compare_exchange_strong(expected, true)) {
        return;                              /* one-shot */
    }
    /* Pin to the target's address space.  The marker is one of the
     * target's own instructions, so the current ASID is the target's; every
     * later TB in a different address space is filtered in vcpu_tb_exec. */
    g_pinned_asid.store(asid, std::memory_order_relaxed);
    pin_reuse_reset();
    /* Snapshot this pin's ASID identity (Phase 2): the root physical
     * address is @asid itself (cached above); the representative content
     * signature is seeded from the marker's own code page.  @pc is this
     * callback's own instruction address (from its udata), NOT
     * qemu_plugin_get_pc(): the env PC is only synced at TB
     * boundaries/exceptions, so a mid-TB read is stale and would hash a
     * bogus page.  exec_lock guards the shared scratch buffer / page map
     * against concurrent step-glue probes on other vCPUs. */
    if (g_pin_reuse_guard) {
        /* Narrow-ASID (MIPS) single owner: user-mode marker (asid 0, one
         * address space), pinned-simpoint positioning, and MIPS trace-all
         * (whose clock/END ride this single pin while capture widens in the
         * heavy step).  Seat owner 0's dwell and seed its page map from the
         * marker's own live-translated page; the stable anchor is (0,0) in
         * user mode so those traces stay byte-identical, the marker-page
         * physical address in system mode. */
        g_rec_mutex_lock(&exec_lock);
        uint64_t root_phys, sig, vpage;
        marker_anchor(pc, asid, &root_phys, &sig, &vpage);
        g_pin_repr_vpage = vpage;
        g_pin_repr_sig.store(sig, std::memory_order_relaxed);
        pin_owned_reset_single(asid, cpu_index, root_phys, sig, vpage);
        pin_map_learn(0, pc);
        g_rec_mutex_unlock(&exec_lock);
    } else if (asid != 0) {
        /* Wide-register SYSTEM pin (x86 CR3 / AArch64 TTBR / RISC-V SATP):
         * no page map is learned, so seed the representative directly from
         * the marker's own code page.  Gated on a real (non-zero) root:
         * user-mode pins report asid 0 and need no signature, so this path
         * — and its lock / guest read — never runs in user mode, leaving
         * user traces byte-identical. */
        g_rec_mutex_lock(&exec_lock);
        g_pin_repr_vpage = UINT64_MAX;
        g_pin_repr_sig.store(0, std::memory_order_relaxed);
        pin_repr_seed(pc);
        g_rec_mutex_unlock(&exec_lock);
    }
    /* Record the representative root in the owned set too, so the
     * wide-register asid_match set-membership (asid_write_track_cb) is
     * correct for a wide-register pinned simpoint (single-owned).  MIPS
     * keeps its own dwell path and never reads the set. */
    if (!g_pin_reuse_guard) {
        g_rec_mutex_lock(&exec_lock);
        g_owned.insert(asid);
        g_owned_last_sched[asid] = deadlatch_now_ms();
        g_rec_mutex_unlock(&exec_lock);
    }

    if (pinned_simpoint_mode()) {
        /* Pin only: zero the user clock at the target's first instruction
         * and start positioning toward the simpoint's effective start. */
        uint64_t lo = qemu_plugin_u64_get(g_scoreboard.insn_count, cpu_index);
        user_count_reset(cpu_index, lo);
        const SimPointEntry *sp = g_simpoints.current();
        uint64_t eff_start = (sp && sp->start_insn > warmup_insns)
            ? sp->start_insn - warmup_insns : 0;
        if (qemu_plugin_num_vcpus() == 1 &&
            eff_start > 2 * FF_COARSE_MARGIN) {
            /* Distant simpoint: coarse leg first (see g_ff_coarse).
             * is_active stays 0 — nothing dispatches per TB; the
             * pinned-user budget countdown fires the handoff
             * FF_COARSE_MARGIN short of the target.  The marker
             * executes in the pinned process, so asid_match seeds to 1
             * here; the ASID-write hook maintains it from now on.
             * Flush so TBs translated before the pin — whose budget
             * decrements are unconditional, kernel included — are
             * retired before the countdown accumulates. */
            g_ff_coarse_target = eff_start - FF_COARSE_MARGIN;
            g_ff_foreign_insns = 0;
            qemu_plugin_u64_set(g_scoreboard.asid_match, cpu_index, 1);
            g_ff_coarse.store(true, std::memory_order_relaxed);
            qemu_plugin_u64_set(g_scoreboard.budget, cpu_index,
                                g_ff_coarse_target);
            qemu_plugin_request_tb_flush();
            fprintf(stderr, "champsim_tracer: marker pinned asid 0x%" PRIx64
                    " at icount %" PRIu64 " — coarse fast-forward %" PRIu64
                    " user insns toward simpoint start %" PRIu64
                    " (warmup %" PRIu64 ")\n",
                    asid, lo, g_ff_coarse_target,
                    sp ? sp->start_insn : 0, warmup_insns);
            return;
        }
        /* Near simpoint (or SMP guest): exact path from the pin — turn
         * on the per-TB callback so the clock advances (the budget slot
         * parks at the sentinel; the capture callbacks all bail while no
         * segment is active).  The vcpu_tb_exec fast-path opens the
         * window when the clock reaches the effective start. */
        for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; i++) {
            qemu_plugin_u64_set(g_scoreboard.is_active, (unsigned)i, 1);
            qemu_plugin_u64_set(g_scoreboard.budget, (unsigned)i,
                                (uint64_t)BUDGET_INACTIVE_SENTINEL);
            refresh_ctx_gates((unsigned)i);
        }
        fprintf(stderr, "champsim_tracer: marker pinned asid 0x%" PRIx64
                " at icount %" PRIu64 " — positioning to simpoint start %"
                PRIu64 " user insns (warmup %" PRIu64 ")\n",
                asid, lo, sp ? sp->start_insn : 0, warmup_insns);
        return;
    }

    g_rec_mutex_lock(&exec_lock);
    marker_open_trace_window(cpu_index, asid, /* have_root_phys= */ false, 0);
    g_rec_mutex_unlock(&exec_lock);
}

/*
 * End-of-program marker (WIN_MARKER).  The workload emits the END-marker
 * sequence just before it exits; when it executes in the pinned process's
 * address space, close the trace window here.  This is the "or the program
 * ends" stop: a workload shorter than the icount/simpoint budget ends
 * cleanly instead of running past process exit, where the freed address
 * space (ASID/CR3) may be reused by another process and re-match the pin.
 * Ignored if unpinned, if not the pinned process, or during WP.
 */
static void vcpu_marker_end_cb(unsigned int cpu_index, void *udata)
{
    /* Wrong-path fence — see vcpu_marker_cb. */
    if (qemu_plugin_in_spec_mode() || g_wp_state.in_progress) {
        tls_mkdiag_end_wp_gated++;
        return;
    }
    uint64_t pc;
    uint8_t size;
    marker_udata_unpack(udata, &pc, &size);
    if (marker_diag()) {
        const MarkerExecRun *er =
            marker_run_peek(&tls_marker_end_run,
                            qemu_plugin_get_addr_space_id());
        fprintf(stderr, "[mkdiag] end-cb CP cpu=%u pc=0x%" PRIx64
                " sz=%u priv=%d asid=0x%" PRIx64 " pinned=0x%" PRIx64
                " run=%u next=0x%" PRIx64 " user=%" PRIu64
                " wp_gated=%" PRIu64 " susp_u=%" PRIu64
                " foreign_u=%" PRIu64 "\n",
                cpu_index, pc, size, qemu_plugin_get_priv_level(),
                qemu_plugin_get_addr_space_id(),
                g_pinned_asid.load(std::memory_order_relaxed),
                er ? er->run : 0, er ? er->next_pc : 0,
                g_user_icount, tls_mkdiag_end_wp_gated,
                tls_mkdiag_susp_user, tls_mkdiag_foreign_user);
    }
    if (!marker_exec_step(&tls_marker_end_run, pc, size)) {
        return;
    }
    uint64_t asid = qemu_plugin_get_addr_space_id();

    /*
     * Multi-process latch (Stage B1): wide-register WIN_MARKER.  The END
     * marker CLOSES the emitting process's window (leaves the owned set).
     * The segment closes only when the LAST window closes (the owned set
     * empties); while other processes are still tracing, the ending
     * process is dropped and the segment keeps running.  Symmetric with
     * the START handler; excludes the narrow-ASID (MIPS) and simpoint
     * paths, which keep the single-process exit below.
     */
    if (g_window_mode == PluginConfig::WIN_MARKER && !g_pin_reuse_guard) {
        g_rec_mutex_lock(&exec_lock);
        if (!owned_contains_locked(asid)) {
            /* END from a process that never opened a window (or already
             * closed it): not ours to act on. */
            g_rec_mutex_unlock(&exec_lock);
            return;
        }
        g_owned.erase(asid);
        g_owned_last_sched.erase(asid);
        if (!g_owned.empty()) {
            /* Other windows remain open — do NOT close the segment.  Drop
             * only this root: recompute the emitting vCPU's gates/flag so
             * its TBs stop being owned (pin_user_tb_owned now sees the live
             * root as foreign); other vCPUs that were running this root
             * self-correct at their next ASID write.  If this root was the
             * representative, repoint it to a still-owned root so
             * pin_effective_asid / cst_pinned_asid_root stay valid. */
            if (g_pinned_asid.load(std::memory_order_relaxed) == asid) {
                g_pinned_asid.store(*g_owned.begin(),
                                    std::memory_order_relaxed);
            }
            /* Drop the closed process's asid-keyed dedup-index footprint so
             * it does not accumulate across disparate ASIDs (single shared
             * tracer with asid-keyed caches, not one tracer per ASID).  The
             * process's true-BB templates stay until the segment's templates
             * section is written (see reclaim_asid).  data_lock guards the
             * store against a concurrent translation on another vCPU. */
            g_mutex_lock(&data_lock);
            uint64_t dropped = g_template_store.reclaim_asid(asid);
            g_mutex_unlock(&data_lock);
            if (dropped) {
                fprintf(stderr, "champsim_tracer: dropped %" PRIu64
                        " dedup buckets for closed asid 0x%" PRIx64 "\n",
                        dropped, asid);
            }
            qemu_plugin_u64_set(g_scoreboard.asid_match, cpu_index, 0);
            refresh_ctx_gates(cpu_index);
            fprintf(stderr,
                    "champsim_tracer: end marker — closed window for asid "
                    "0x%" PRIx64 " (%zu still tracing)\n",
                    asid, g_owned.size());
            g_rec_mutex_unlock(&exec_lock);
            return;
        }
        /* Last window closed: all-windows-closed stop (peer of the
         * icount/budget stop — whichever fires first wins). */
        marker_close_and_exit(/* last_window= */ true);
        return;
    }

    /*
     * Multi-process latch (Stage B3): narrow-ASID WIN_MARKER (MIPS system).
     * The END marker executes as the ending process's OWN user code, so the
     * emitting vCPU's confirmed dwell owner IS the ender.  Close that owner's
     * window (mark it inactive, free its page map); the segment closes only
     * when the LAST active owner ends.  Symmetric with the narrow-ASID START
     * handler; excludes trace-all / user / simpoint (the legacy exit below).
     */
    if (g_window_mode == PluginConfig::WIN_MARKER && g_pin_reuse_guard &&
        asid != 0 && !marker_trace_all()) {
        g_rec_mutex_lock(&exec_lock);
        PinVcpuState &ps = g_pin_vcpu[cpu_index];
        int ow = ps.owner.load(std::memory_order_relaxed);
        bool ok = ps.confirmed.load(std::memory_order_relaxed) && ow >= 0 &&
                  g_owned_procs && ow < (int)g_owned_procs->size() &&
                  (*g_owned_procs)[ow].active;
        if (!ok) {
            /* Dwell not currently confirmed (a kernel overlay may have
             * un-confirmed it an instant before this insn): identify the
             * ender by probing its own code against the owned maps. */
            bool mm = false;
            ow = pin_map_probe_owners(pc, ow, &mm);
        }
        if (ow < 0 || !g_owned_procs || ow >= (int)g_owned_procs->size() ||
            !(*g_owned_procs)[ow].active) {
            /* END from a process that never opened a window (or already
             * closed it): not ours to act on. */
            g_rec_mutex_unlock(&exec_lock);
            return;
        }
        (*g_owned_procs)[ow].active = false;
        (*g_owned_procs)[ow].pages.clear();   /* free — never probed again */
        g_owned_procs_active--;
        /* The ending vCPU has left the owned set: un-confirm its dwell so its
         * remaining TBs re-probe (and, finding no active owner, drop). */
        ps.confirmed.store(false, std::memory_order_relaxed);
        qemu_plugin_u64_set(g_scoreboard.asid_match, cpu_index, 0);
        refresh_ctx_gates(cpu_index);
        if (g_owned_procs_active > 0) {
            /* Other windows remain open — do NOT close the segment.  The
             * closed owner's true-BB templates stay until the segment's
             * templates section is written; its live-ASID-keyed dedup index
             * is byte-checked and bounded, so no cross-process reclaim is
             * needed (a concurrently-owned process holds a distinct ASID
             * value). */
            fprintf(stderr,
                    "champsim_tracer: end marker — closed narrow owner %d "
                    "(%d still tracing)\n", ow, g_owned_procs_active);
            g_rec_mutex_unlock(&exec_lock);
            return;
        }
        /* Last window closed: all-windows-closed stop. */
        marker_close_and_exit(/* last_window= */ true);
        return;
    }

    /* Legacy single-pin path: pinned-simpoint / narrow-ASID (MIPS). */
    uint64_t pinned = g_pinned_asid.load(std::memory_order_relaxed);
    if (pinned == CST_ASID_UNPINNED) {
        return;
    }
    /* The end marker must be the pinned process's own: compare against
     * the executing vCPU's effective pin (on a narrow-ASID target the
     * process may hold a re-pinned value by now; its dwell was verified
     * by the step glue before this insn callback fired). */
    if (asid != pin_effective_asid(cpu_index, pinned)) {
        return;
    }
    g_rec_mutex_lock(&exec_lock);
    marker_close_and_exit(/* last_window= */ false);
}

/* Outcome of the pre-commit instruction-memory stability check. */
struct TbPoison {
    bool        poisoned = false;
    uint64_t    pc = 0;
    const char *reason = nullptr;
    bool        is_smc_signal = false;
};

/*
 * Detect non-stable "instruction" memory before committing this TB as a
 * fragment.  Two independent signals:
 *
 *   1. Capstone decode failure on any canonical insn (empty mnemonic): the
 *      bytes don't parse as a valid instruction of this ISA.  Cannot be
 *      real code.
 *
 *   2. Byte change since the first sighting of this VA: the same address
 *      now reads different bytes than the last time the tracer saw it.
 *      Real code does not change (no self-modification in this workload);
 *      writable memory (stack, heap, .bss) does.
 *
 * Either signal poisons the TB's start_pc — the WP walker bails before
 * re-entering, and subsequent translations short-circuit fragment creation.
 * Only the byte-change signal points specifically at self-modifying code;
 * Capstone decode failure also fires on perfectly stable .rodata that the
 * R-E LOAD segment happens to cover (static binaries place .text and
 * .rodata in the same R-E LOAD, so start_code/end_code spans both) — that
 * is WP wrong-pathing into data, not SMC.  Records the first-sighting word
 * of every new canonical PC.  Takes data_lock.
 */
static TbPoison detect_tb_poison(uint64_t pc, const uint64_t *insn_pcs,
                                 const uint8_t *insn_bytes,
                                 const qemu_plugin_insn_info *insn_info,
                                 uint32_t canonical_n_insns)
{
    TbPoison p;

    /* A wrong-path (spec-mode) translation must never MUTATE the persistent
     * SMC state.  In system mode a spec excursion routinely reads a VA whose
     * softmmu page is mid-refill (garbage bytes) or belongs to another address
     * space (ASID reuse at the same VA).  If such a read seeds the first-
     * sighting word, the subsequent real correct-path translation reads the
     * true bytes, looks "self-modifying", and the whole basic block is dropped
     * from the trace; if it persists into g_poisoned_pcs, that PC is blocked
     * from CP tracing forever.  Spec mode therefore only READS this state (so
     * a genuinely-bad spec TB still yields poisoned=true and gets no fragment);
     * the WP walker tracks its own transient poison in a local set. */
    const bool spec = g_wp_state.in_progress;

    g_mutex_lock(&data_lock);
    uint64_t bytes_hash = tb_bytes_hash(insn_bytes, canonical_n_insns);
    auto poison_it = g_poisoned_pcs.find(pc);
    if (poison_it != g_poisoned_pcs.end() && spec &&
        poison_it->second != bytes_hash) {
        /* Different bytes than when the verdict was made: the VA has been
         * reused by another context since (process exit, exec, page reuse).
         * The old verdict says nothing about THIS content — clear it and
         * evaluate normally below. */
        g_poisoned_pcs.erase(poison_it);
        poison_it = g_poisoned_pcs.end();
    }
    if (poison_it != g_poisoned_pcs.end() && spec) {
        p.poisoned = true;
        p.pc = pc;
        p.reason = "previously poisoned";
        g_last_spec_refusal = SpecRefusal::POISON;
    } else {
        /* Correct-path execution reaching a poisoned PC is proof the poison was
         * wrong: the CPU is really executing this code in the current address
         * space, so a prior verdict (spec contamination, or a stale/cross-ASID
         * byte-change) no longer holds.  Unpoison and re-validate against the
         * CP bytes — the same "correct path is ground truth" rule the byte-
         * change refresh below follows.  Without this, one bad spec/boot
         * sighting permanently blocks both CP tracing AND every WP excursion
         * that targets this PC (the 0-block wrong_path_chains truncation).
         *
         * Erase per CANONICAL VA, not just this TB's start_pc: a poison entry is
         * keyed by the start_pc of whatever TB first tripped it, which can be a
         * WP-target VA that the correct path only ever reaches MID-TB (never as
         * a TB start).  Erasing only @pc would then never clear it, leaving that
         * WP target refused forever.  The per-VA erase below (in the canonical
         * loop) clears it the first time the correct path executes through it. */
        if (!spec) {
            g_poisoned_pcs.erase(pc);
        }
        for (uint32_t ci = 0; ci < canonical_n_insns && !p.poisoned; ci++) {
            uint64_t ipc = insn_pcs[ci];
            if (!spec) {
                g_poisoned_pcs.erase(ipc);
            }
            uint32_t word = 0;
            memcpy(&word, &insn_bytes[(size_t)ci * MAX_INSN_BYTES],
                   sizeof(word));
            auto it = g_first_insn_word.find(ipc);
            if (it != g_first_insn_word.end()) {
                if (it->second != word) {
                    if (spec) {
                        /* Spec read differs from the CP-recorded first word.
                         * The presence of that word means the correct path
                         * already confirmed this VA is real code, so the differ
                         * is real code in another context (ASID reuse) or a
                         * resident page the CP first saw mid-refill — NOT data.
                         * Do not poison: let the fragment form so the wrong path
                         * can speculate through it (genuine WP-into-data is
                         * still caught by the Capstone-decode check below).
                         * Stay read-only: never mutate the CP first word. */
                    } else {
                        /* Correct-path execution is ground truth: the CPU is
                         * really executing these bytes.  In system mode the
                         * same VA legitimately reads different bytes across CP
                         * translations (demand paging, an earlier read racing
                         * page-in, ASID reuse).  Poisoning here dropped whole
                         * executed basic blocks from the trace.  Refresh the
                         * cache to the CP-observed word instead of poisoning. */
                        it->second = word;
                    }
                }
            } else if (!spec) {
                g_first_insn_word.emplace(ipc, word);
            }
            if (!p.poisoned &&
                cst_cap_arch >= 0 && !insn_info[ci].mnemonic[0]) {
                p.poisoned = true;
                p.pc = ipc;
                p.reason = "Capstone decode failure";
            }
        }
        if (p.poisoned && !spec) {
            g_poisoned_pcs[pc] = bytes_hash;
        }
    }
    g_mutex_unlock(&data_lock);
    return p;
}

/*
 * Owning per-TB scratch for vcpu_tb_trans: the parallel canonical-insn
 * arrays plus the reused per-fragment local mapping.  RAII via unique_ptr,
 * so every exit path frees the whole set automatically — previously each of
 * the three returns had to g_free them by hand, a leak waiting for the next
 * array to be added.  make_unique<T[]> value-initialises (zeroes), matching
 * the old g_new0.
 */
struct TbScratch {
    std::unique_ptr<uint64_t[]>              insn_pcs;
    std::unique_ptr<qemu_plugin_insn_info[]> insn_info;
    std::unique_ptr<uint64_t[]>              insn_branch_target_pcs;
    std::unique_ptr<uint8_t[]>               insn_sizes;
    std::unique_ptr<uint8_t[]>               insn_bytes;   /* n * MAX_INSN_BYTES */
    std::unique_ptr<uint32_t[]>              canonical_index;
    std::unique_ptr<bool[]>                  canonical_first;
    /* Per-fragment local canonical mapping, reused across fragments. */
    std::unique_ptr<uint32_t[]>              local_canonical_index;
    std::unique_ptr<bool[]>                  local_canonical_first;

    explicit TbScratch(size_t n)
        : insn_pcs(std::make_unique<uint64_t[]>(n)),
          insn_info(std::make_unique<qemu_plugin_insn_info[]>(n)),
          insn_branch_target_pcs(std::make_unique<uint64_t[]>(n)),
          insn_sizes(std::make_unique<uint8_t[]>(n)),
          insn_bytes(std::make_unique<uint8_t[]>(n * MAX_INSN_BYTES)),
          canonical_index(std::make_unique<uint32_t[]>(n)),
          canonical_first(std::make_unique<bool[]>(n)),
          local_canonical_index(std::make_unique<uint32_t[]>(n)),
          local_canonical_first(std::make_unique<bool[]>(n)) {}
};

/*
 * Decode the TB's raw instruction stream into the canonical (de-duplicated)
 * arrays in @scratch, and arm the per-insn memop callback (plus, in marker
 * window mode, the one-shot trace-open callback on the x86 launch magic).
 * A QEMU TB can repeat an instruction (e.g. REP string ops): consecutive
 * byte-identical insns at the same PC fold to one canonical entry, with
 * canonical_index[] mapping each raw insn to its canonical slot and
 * canonical_first[] marking the first raw occurrence.  Returns the canonical
 * insn count.  insn_branch_target_pcs holds the translator-resolved static
 * branch target per canonical insn (0 on non-branch / indirect).
 */
static uint32_t build_canonical_insns(struct qemu_plugin_tb *tb,
                                      size_t raw_n_insns, TbScratch &scratch)
{
    uint64_t *insn_pcs                 = scratch.insn_pcs.get();
    qemu_plugin_insn_info *insn_info   = scratch.insn_info.get();
    uint64_t *insn_branch_target_pcs   = scratch.insn_branch_target_pcs.get();
    uint8_t *insn_sizes                = scratch.insn_sizes.get();
    uint8_t *insn_bytes                = scratch.insn_bytes.get();
    uint32_t *canonical_index          = scratch.canonical_index.get();
    bool *canonical_first              = scratch.canonical_first.get();
    uint32_t canonical_n_insns = 0;

    for (size_t i = 0; i < raw_n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t raw_pc = qemu_plugin_insn_vaddr(insn);
        uint8_t raw_size =
            (uint8_t)MIN(qemu_plugin_insn_size(insn), MAX_INSN_BYTES);
        uint8_t raw_bytes[MAX_INSN_BYTES] = {0};

        qemu_plugin_insn_data(insn, raw_bytes, raw_size);

        /* WIN_MARKER: detect the marker sequence (per-ISA bytes, see
         * MarkerSeq) and arm the trace-open (START) or trace-close (END)
         * callback on its LAST instruction.  Each counter tracks the
         * sequence position reached in this TB's straight-line stream;
         * arming on the final insn means that when it executes, the whole
         * sequence ran before it.  Registered at every translation —
         * wrong-path (spec-born) ones included — so the marker is caught
         * wherever the process runs; the wrong-path fence lives in the
         * callbacks (see vcpu_marker_cb), which drop every speculative
         * invocation on the QEMU-side spec-mode flag before touching the
         * adjacency run.  Suppressing the registration on spec-born
         * translations instead is NOT equivalent: it changes the WP
         * translations' instrumentation shape, and an A/B pair on the
         * SMP thread_test showed that variant livelocking the guest
         * right after segment open (one vCPU pinned in a userspace spin
         * below every plugin callback) while this registration-
         * preserving build completes — a QEMU-base interaction
         * preserved under mkclose_bug1/ab for follow-up. */
        if (marker_scan_enabled() && g_marker_seq.valid) {
            /* Arm the exec callback on every insn whose bytes belong to a
             * marker sequence; the callback judges consecutivity in the
             * user-space stream by PC adjacency, so detection is
             * independent of TB slicing (see marker_exec_step). */
            if (marker_word_match(g_marker_seq.start, raw_bytes, raw_size)) {
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, vcpu_marker_cb, QEMU_PLUGIN_CB_NO_REGS,
                    marker_udata_pack(raw_pc, raw_size));
            }
            if (marker_word_match(g_marker_seq.end, raw_bytes, raw_size)) {
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, vcpu_marker_end_cb, QEMU_PLUGIN_CB_NO_REGS,
                    marker_udata_pack(raw_pc, raw_size));
            }
        }

        bool duplicate = false;
        if (canonical_n_insns > 0) {
            uint32_t prev = canonical_n_insns - 1;
            duplicate = insn_pcs[prev] == raw_pc &&
                        insn_sizes[prev] == raw_size &&
                        memcmp(&insn_bytes[(size_t)prev * MAX_INSN_BYTES],
                               raw_bytes, MAX_INSN_BYTES) == 0;
        }

        if (duplicate) {
            canonical_index[i] = canonical_n_insns - 1;
        } else {
            uint32_t out = canonical_n_insns++;
            canonical_index[i] = out;
            canonical_first[i] = true;
            insn_pcs[out] = raw_pc;
            insn_sizes[out] = raw_size;
            insn_branch_target_pcs[out] =
                qemu_plugin_insn_branch_target_pc(insn);
            memcpy(&insn_bytes[(size_t)out * MAX_INSN_BYTES],
                   raw_bytes, MAX_INSN_BYTES);

            if (cst_cap_arch >= 0) {
                qemu_plugin_cap_decode(cst_cap_arch, cst_cap_mode,
                                       &insn_bytes[(size_t)out *
                                                   MAX_INSN_BYTES],
                                       insn_sizes[out],
                                       insn_pcs[out],
                                       &insn_info[out]);
            }
        }

        /* Per-memop callback fires unconditionally; the cb body
         * does its own is_active check before doing real work.
         *
         * Why NOT cond_cb: a JIT-emitted brcond at memop sites would
         * introduce a TCG label mid-instruction.  Helpers like x86
         * cmpxchg expand into a load + movcond + store sequence
         * sharing TEMP_EBB temps across the memops; inserting a
         * set_label between the qemu_ld/qemu_st pair breaks the
         * containing EBB and the post-memop ops read dead temps.
         * Aborts with "tcg.c:temp_load: code should not be reached".
         * Keep the per-memop overhead in C and bail fast there.
         *
         * Coarse fast-forward is the exception: a C call per guest
         * memory access is the dominant positioning cost, and nothing
         * consumes memops until a window opens.  TBs translated during
         * the coarse phase skip the callback entirely; the pin-time
         * and handoff-time flushes guarantee none of them survives
         * into a phase that records (see g_ff_coarse). */
        if (!g_ff_coarse.load(std::memory_order_relaxed)) {
            qemu_plugin_register_vcpu_mem_cb(
                insn, vcpu_mem_cb, QEMU_PLUGIN_CB_NO_REGS,
                QEMU_PLUGIN_MEM_RW,
                (void *)(uintptr_t)raw_pc);
        }
    }
    return canonical_n_insns;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t raw_n_insns = qemu_plugin_tb_n_insns(tb);
    if (raw_n_insns == 0) {
        return;
    }

    /* Shutdown gate: a segment close on another vCPU thread sets the
     * shutting-down flag and calls exit(0), whose teardown races any
     * still-running vCPU (translation is not is_active-gated — new code
     * translates whenever a vCPU meets it).  Once the flag is up the
     * trace is finished; skip the template work entirely so surviving
     * vCPUs stop touching the process-wide stores while the process
     * dies.  (The stores themselves are also immortalized — this gate
     * closes the window, the immortalization removes the cliff.) */
    if (g_trace_segments.is_shutting_down()) {
        return;
    }

    /* Translation-time template building (Capstone decode, fragment split,
     * callback arming) is instrumentation cost, not guest execution: keep it
     * off the guest clock (see VClockPauseGuard at vcpu_tb_exec). */
    VClockPauseGuard vclock_guard;

    /* Lifetime-class selection (#91): templates built for a wrong-path
     * translation are born SPEC — reclaimable at tb_flush unless the
     * correct path executes them first (see TmplLife). */
    g_template_store.set_creating_spec(g_wp_state.in_progress);

    /*
     * Every TB gets the full heavy translation, regardless of segment
     * state.  Per-insn callbacks are gated via cond_cb on the
     * scoreboard `is_active` slot so inter-segment execution skips
     * them via a JIT-emitted check, with no plugin-side flush
     * required at segment boundaries.  This avoids the user-mode
     * `tb_flush` hazard where a chained TB jumps to JIT-region bytes
     * that subsequent translations have overwritten.
     */
    struct qemu_plugin_insn *first_insn = qemu_plugin_tb_get_insn(tb, 0);

    /* RAII-owned scratch; raw aliases below keep the loop body unchanged.
     * insn_branch_target_pcs is the per-canonical-insn static branch target
     * the translator resolved (qemu_plugin_insn_branch_target_pc()), parallel
     * to insn_info[]/insn_pcs[]; zero on non-branches and indirect branches
     * (which fall back to BranchHistory). */
    TbScratch scratch(raw_n_insns);
    uint64_t *insn_pcs                 = scratch.insn_pcs.get();
    qemu_plugin_insn_info *insn_info   = scratch.insn_info.get();
    uint64_t *insn_branch_target_pcs   = scratch.insn_branch_target_pcs.get();
    uint8_t *insn_sizes                = scratch.insn_sizes.get();
    uint8_t *insn_bytes                = scratch.insn_bytes.get();
    uint32_t *canonical_index          = scratch.canonical_index.get();
    bool *canonical_first              = scratch.canonical_first.get();

    uint32_t canonical_n_insns =
        build_canonical_insns(tb, raw_n_insns, scratch);

    /* Pre-commit instruction-memory stability check.  If the poisoning
     * fires inside the main binary's text segment, warn once: that is a
     * real SMC suspect, not WP wrong-pathing into data. */
    TbPoison poison = detect_tb_poison(pc, insn_pcs, insn_bytes, insn_info,
                                       canonical_n_insns);
    if (poison.poisoned) {
        if (poison.is_smc_signal && cst_pc_in_code(poison.pc)) {
            static std::atomic<int> warned{0};
            int expected = 0;
            if (warned.compare_exchange_strong(expected, 1)) {
                fprintf(stderr,
                    "champsim_tracer: WARNING in-text-segment "
                    "instruction at 0x%" PRIx64 " %s — possible "
                    "self-modifying code; suppressing fragment "
                    "creation for TB at 0x%" PRIx64 ".  "
                    "(Further occurrences suppressed.)\n",
                    poison.pc, poison.reason, pc);
            }
        }
        /* Do not create fragments, do not arm callbacks.  vcpu_tb_exec gets
         * no udata for this TB; scratch is freed by TbScratch on return. */
        return;
    }

    /* Partition the TB's canonical insn stream at every non-final
     * branch terminator.  TCG and Capstone don't always agree on
     * which insns end control flow (e.g. MIPS conditional traps:
     * TCG keeps translating past, Capstone classifies as a branch);
     * the splitter is what reconciles that at the true-BB layer.
     * Singleton TBs (no mid-TB branch) produce one spec, matching
     * the pre-splitter behavior. */
    std::vector<TbFragmentSpec> fragment_specs;
    split_tb_into_fragments(insn_info, canonical_n_insns, fragment_specs);

    /* Per-raw-insn local mapping into the current fragment's canonical
     * index space.  Allocated once and reused per fragment.  For raw
     * insns not in the current fragment, local_canonical_first is set
     * to false so tb_arm_new_template_cbs skips them. */
    uint32_t *local_canonical_index = scratch.local_canonical_index.get();
    bool     *local_canonical_first = scratch.local_canonical_first.get();

    const char *tb_symbol_name = qemu_plugin_insn_symbol(first_insn);

    /* Persistent-template dedup: a tb_flush re-translates the same code,
     * so reuse the already-built fragment chain for this (start_pc,
     * canonical-insn-count, canonical bytes) instead of allocating a
     * duplicate.  Byte identity is verified inside the lookup — the
     * poison gate above refreshes its first-sighting cache on CP byte
     * changes rather than invalidating chains, so guest code patching
     * (x86 kernel alternatives) at an already-templated VA must miss
     * here and mint a fresh chain.  On a hit the chain's shape and
     * decoded contents are identical; we only need to re-arm the
     * JIT-level per-insn callbacks and scoreboard stores below (done
     * every translation regardless of reuse). */
    /* Whole-TB canonical view; each fragment passes a slice to
     * create_tb_template (groups the six parallel per-insn arrays). */
    TbInsnView tb_view = {
        canonical_n_insns, insn_pcs, insn_info, insn_branch_target_pcs,
        insn_sizes, insn_bytes,
    };

    uint64_t tb_start_pc = insn_pcs[0];
    g_mutex_lock(&data_lock);
    BBTemplate *reuse_head =
        g_template_store.lookup_tb_chain(tb_start_pc, canonical_n_insns,
                                         insn_sizes, insn_bytes);
    g_mutex_unlock(&data_lock);
    const bool reuse = (reuse_head != nullptr);

    BBTemplate *head_fragment = reuse_head;
    BBTemplate *prev_fragment = nullptr;
    BBTemplate *reuse_cursor  = reuse_head;

    for (size_t f = 0; f < fragment_specs.size(); f++) {
        const TbFragmentSpec &spec = fragment_specs[f];
        uint32_t f_first_ci = spec.start_canonical;
        uint32_t f_last_ci  = spec.start_canonical + spec.n_insns - 1;
        uint64_t f_start_pc = insn_pcs[f_first_ci];
        uint64_t f_fall_through =
            insn_pcs[f_last_ci] + insn_sizes[f_last_ci];

        /* Symbol-trigger matching keys off symbol_name on the head
         * fragment only (matches the pre-splitter point of comparison
         * against a TB start_pc). */
        const char *frag_symbol =
            (f == 0) ? tb_symbol_name : nullptr;

        /* Reuse the existing per-fragment template on a dedup hit; else
         * build a fresh one.  The template is attached to the QEMU TB via
         * udata so vcpu_tb_exec walks the chain and feeds the assembler
         * only the fragments that actually executed (CP and WP paths). */
        BBTemplate *frag_tmpl;
        if (reuse) {
            frag_tmpl = reuse_cursor;
            if (reuse_cursor) {
                reuse_cursor = reuse_cursor->next_tb_fragment;
            }
        } else {
            g_mutex_lock(&data_lock);
            frag_tmpl = g_template_store.create_tb_template(
                                f_start_pc,
                                tb_view.slice(f_first_ci, spec.n_insns),
                                frag_symbol,
                                f_fall_through);
            frag_tmpl->terminus = (uint8_t)spec.terminus;
            g_mutex_unlock(&data_lock);

            if (!head_fragment) {
                head_fragment = frag_tmpl;
            }
            if (prev_fragment) {
                prev_fragment->next_tb_fragment = frag_tmpl;
            }
            prev_fragment = frag_tmpl;
        }

        /* Build the fragment-local canonical_index/first mask: raw
         * insns inside [f_first_ci, f_last_ci] map to local canonical
         * (ci - f_first_ci); raw insns outside have canonical_first
         * cleared so tb_arm_new_template_cbs skips them entirely. */
        size_t frag_first_raw = SIZE_MAX;
        for (size_t i = 0; i < raw_n_insns; i++) {
            uint32_t ci = canonical_index[i];
            if (ci >= f_first_ci && ci <= f_last_ci) {
                local_canonical_index[i] = ci - f_first_ci;
                local_canonical_first[i] = canonical_first[i];
                if (canonical_first[i] && ci == f_first_ci &&
                    frag_first_raw == SIZE_MAX) {
                    frag_first_raw = i;
                }
            } else {
                local_canonical_index[i] = 0;
                local_canonical_first[i] = false;
            }
        }

        tb_arm_new_template_cbs(tb, frag_tmpl, &insn_info[f_first_ci],
                                raw_n_insns, local_canonical_index,
                                local_canonical_first, spec.n_insns);

        /* Per-fragment scoreboard inline stores at the fragment's
         * first raw insn.  The LAST fragment whose store fires before
         * the next QEMU TB's vcpu_tb_exec wins — that is exactly the
         * last-executed fragment, since a trap mid-TB prevents later
         * fragments' first-insn stores from firing. */
        if (frag_first_raw != SIZE_MAX) {
            struct qemu_plugin_insn *frag_first_insn =
                qemu_plugin_tb_get_insn(tb, frag_first_raw);
            qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
                frag_first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
                g_scoreboard.prev_start_pc, f_start_pc);
            qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
                frag_first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
                g_scoreboard.prev_fall_through, f_fall_through);
        }
    }

    /* Record a freshly built chain for future reuse in its lifetime
     * class's index (a tb_flush will re-translate the same code and
     * reuse it instead of duplicating; a CP translation adopts a chain
     * the wrong path minted first).  SPEC chains go to the separate
     * SPEC index so the reclaim can drop them wholesale — no per-chain
     * index surgery (see register_tb_chain / promote). */
    if (!reuse && head_fragment) {
        g_mutex_lock(&data_lock);
        g_template_store.register_tb_chain(tb_start_pc, head_fragment);
        g_mutex_unlock(&data_lock);
    }

    /* Instrument the block for execution tracking.  current_pc is set
     * per-TB-exec to the TB's start_pc (== head fragment's start_pc).
     * udata = head fragment; vcpu_tb_exec walks the list. */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_STORE_U64, g_scoreboard.current_pc, pc);

    /* icount bump as a JIT-emitted ADD on the scoreboard slot — same
     * pattern as the BBV plugin.  This eliminates the
     * qemu_plugin_u64_get/set function calls the C cb used to do per
     * TB exec.  Per-TB raw_n_insns matches the value BBV's inline ADD
     * uses, so the icount counter stays byte-identical to BBV. */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_ADD_U64,
        g_scoreboard.insn_count, raw_n_insns);
    /* Mirror the bump into the budget slot but negated — it counts
     * DOWN by n_insns per TB exec.  When budget < 1 the cond_cb
     * below fires once, handles the threshold crossing, and resets
     * budget.  Same inline pattern; no C call on the hot path.
     *
     * During coarse fast-forward the budget slot is a USER-insn
     * countdown: kernel-context translations skip both the decrement
     * and the crossing detector (see g_ff_coarse).  The pin-time and
     * handoff-time flushes bound each phase's TBs to its own
     * registration shape. */
    bool ff_coarse = g_ff_coarse.load(std::memory_order_relaxed);
    bool ff_coarse_kernel_tb = ff_coarse &&
        qemu_plugin_get_priv_level() != 0;
    if (!ff_coarse_kernel_tb) {
        qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
            tb, QEMU_PLUGIN_INLINE_ADD_U64,
            g_scoreboard.budget, (uint64_t)(int64_t)(-(int64_t)raw_n_insns));
    }
    if (ff_coarse && !ff_coarse_kernel_tb) {
        /* Coarse-countdown compensation: registered between the
         * unconditional decrement above and the crossing detector
         * below (per-TB callbacks execute in registration order), so a
         * foreign-process user TB nets to zero before the crossing is
         * evaluated.  asid_match == 0 exactly when the live address
         * space is not the pinned one. */
        qemu_plugin_register_vcpu_tb_exec_cond_cb(
            tb, vcpu_tb_ff_foreign, QEMU_PLUGIN_CB_NO_REGS,
            QEMU_PLUGIN_COND_EQ, g_scoreboard.asid_match, 0,
            (void *)(uintptr_t)raw_n_insns);
    }

    /* Threshold-crossing detector: fires once when the budget slot
     * crosses zero (i.e. icount reached the next eff_start).  The
     * scoreboard slot is u64 storage; plugin-gen emits an UNSIGNED
     * comparison (TCG_COND_GEU), so testing budget < 1 in unsigned
     * arithmetic only catches budget == 0 exactly.  We want to fire
     * for any signed-negative budget too (per-TB inline_add can
     * overshoot zero by up to one TB's n_insns).  Trick: a signed
     * int64 is negative iff its u64 representation is >= 2^63, so
     * COND_GE with imm = (1ULL << 63) gives the signed-negative test
     * we actually want.
     *
     * IMPORTANT: this cond_cb is registered BEFORE the vcpu_tb_exec
     * cond_cb below.  At the crossing TB that opens a segment, the
     * budget cb fires first and tw_manage_window sets is_active=1.
     * The vcpu_tb_exec brcond then re-loads is_active from the
     * scoreboard and fires for the crossing TB too — so its body
     * entry lands in the trace instead of being lost as a BBV-count
     * deficit.  Symmetric at close: budget cb only sets
     * g_simpoint_close_pending and never clears is_active here, so
     * vcpu_tb_exec still fires and emits the closing TB's entry. */
    if (!ff_coarse_kernel_tb) {
        /* udata = this TB's head fragment.  In WIN_SYMBOL the threshold is
         * parked at 0 so this cb fires for every pre-segment TB; it forwards
         * the head fragment to tw_manage_window, which reads its resolved
         * symbol_name to advance the start-symbol occurrence counter (the
         * heavy vcpu_tb_exec cb that used to do this is gated off until a
         * segment is active).  Other modes ignore the udata. */
        qemu_plugin_register_vcpu_tb_exec_cond_cb(
            tb, vcpu_tb_check_budget, QEMU_PLUGIN_CB_NO_REGS,
            QEMU_PLUGIN_COND_GE, g_scoreboard.budget, (1ULL << 63),
            (void *)head_fragment);
    }
    /* Light re-acquisition probe (narrow-ASID system pins only).  Gated
     * on pin_probe and registered BEFORE the heavy callback so that on
     * the TB re-acquiring the pinned process it flips trace_this_ctx to
     * 1, and the heavy callback's brcond — re-loaded from the scoreboard
     * — fires for that same TB (the identical ordering trick the budget
     * cb uses above).  Not registered for user mode or wide-register
     * pins, so those paths carry no extra per-TB brcond. */
    if (g_pin_reuse_guard) {
        qemu_plugin_register_vcpu_tb_exec_cond_cb(
            tb, vcpu_pin_probe, QEMU_PLUGIN_CB_NO_REGS,
            QEMU_PLUGIN_COND_GE, g_scoreboard.pin_probe, 1,
            (void *)head_fragment);
    }
    /* Heavy callback: chain assembler, WP simulator, body-entry
     * emission.  Gated via cond_cb on trace_this_ctx (is_active folded
     * with pinned-context ownership) so it is NOT dispatched at all
     * inter-segment OR for a foreign / unowned context — the JIT emits a
     * brcond and skips the call, sparing the vclock pause and the drop
     * decision the dropped foreign TB used to pay.  For user mode,
     * unpinned system, and wide-register pins trace_this_ctx mirrors
     * is_active exactly, so the cb fires per TB just as it did before. */
    qemu_plugin_register_vcpu_tb_exec_cond_cb(
        tb, vcpu_tb_exec, QEMU_PLUGIN_CB_RW_REGS,
        QEMU_PLUGIN_COND_GE, g_scoreboard.trace_this_ctx, 1,
        (void *)head_fragment);

    /* Proactive spec-template reclaim (#91): when the wrong path has minted
     * more than a budget of reclaimable templates since the last flush —
     * speculative fetch wandering mutable data that happens to decode —
     * request a tb_flush.  The flush callback then frees every template
     * still in the SPEC lifetime class, bounding the growth that
     * previously ran to tens of GiB (one-insn templates at millions of
     * fresh PCs, or ~1.7 MB 512-insn nop-slide templates from zeroed
     * pages).  Deferred-flush machinery makes the request safe here. */
    {
        /* Budget recalibrated for the InsnFields/RegNames span diet
         * (~450 B per one-insn spec template vs ~3.5 KB before): 256 MB
         * of reclaimable spec templates ≈ half a million wander
         * templates — far above any healthy run (~1-2 MB), reached only
         * by a genuine runaway.  CST_SPEC_FLUSH_BUDGET overrides (bytes;
         * also the reclaim live-fire test knob). */
        static uint64_t budget;
        if (budget == 0) {
            const char *e = getenv("CST_SPEC_FLUSH_BUDGET");
            budget = (e && *e) ? strtoull(e, nullptr, 0) : (256ull << 20);
        }
        if (g_wp_state.in_progress &&
            g_template_store.spec_pending_bytes() > budget) {
            if (getenv("CST_MEMSTATS")) {
                fprintf(stderr, "[memstats] spec budget tripped: pending=%"
                        PRIu64 " > %" PRIu64 " -- flush latched\n",
                        g_template_store.spec_pending_bytes(), budget);
            }
            /* LATCH ONLY.  Requesting here — mid-excursion, inside a WP
             * translation — kicks the vCPU (async-safe work) and the
             * nested WP executor bails, truncating the current chain
             * (exact-or-longer violation).  The CP step boundary issues
             * the request once no excursion is in flight. */
            g_spec_flush_latched.store(true, std::memory_order_relaxed);
        }
    }
}

/* ========================= Flush callback ========================= */

/*
 * TB-cache flush callback.  During WP execution tb_gen_code() may
 * tb_flush() on a full code buffer, longjmping past
 * simulate_wrong_path_ext()'s cleanup; reset wp_* state here so
 * vcpu_tb_exec isn't permanently suppressed.
 */
static void vcpu_tb_flush(qemu_plugin_id_t id)
{
    /* A tb_flush is QEMU JIT housekeeping — the code cache filled and
     * every TB is being re-translated — NOT a guest-execution event, so
     * the trace must be identical with or without it.  Templates for code
     * the CORRECT PATH has executed are PERSISTENT and deduped: a
     * re-translation reuses its existing chain (see lookup_tb_chain), so
     * for real code a flush frees nothing and perturbs no walk state —
     * flush-invariant by construction, no flush-time use-after-free.
     *
     * SPEC-lifetime templates (never promoted by a correct-path
     * execution) are the exception (#91): they are wrong-path fetch
     * residue (speculation wandering mutable data that happens to
     * decode), unbounded across a run, and nothing references them once
     * the flush drops their owning QEMU TBs — the deferred-flush
     * machinery guarantees no wrong-path walk is in flight when this
     * callback fires.  Reclaim them here; a proactive flush is requested
     * from vcpu_tb_trans when their footprint crosses the budget.
     *
     * We do NOT clear the bytes/poison caches (g_first_insn_word /
     * g_poisoned_pcs): they persist so SMC detection survives a flush,
     * and a legitimate flush+retranslate of unchanged code re-matches its
     * first sighting (no false poison) and reuses its template.
     *
     * The flush counter is read by the wrong-path loop to detect (and
     * retry) a spec-mode exec_tb that a flush unwound before the guest
     * insn ran. */
    g_tb_flush_count.fetch_add(1, std::memory_order_acq_rel);
    g_wp_state.last_executed_tb = nullptr;   /* may point at a reclaimee */
    g_mutex_lock(&data_lock);
    uint64_t freed = g_template_store.reclaim_spec_templates();
    g_mutex_unlock(&data_lock);
    if (getenv("CST_MEMSTATS")) {
        /* Unconditional: freed==0 vs flush-never-ran must be
         * distinguishable when proving the request->flush->reclaim
         * chain end-to-end. */
        fprintf(stderr, "[memstats] tb_flush reclaimed %" PRIu64
                " spec templates\n", freed);
    }
}

/* ========================= Exit / statistics ========================= */

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_trace_segments.set_shutting_down();

    g_rec_mutex_lock(&exec_lock);

    if (g_trace_segments.is_active()) {
        finish_trace_segment();
    }

    g_autoptr(GString) report = g_string_new("");

    /* Three counters with distinct meaning:
     *
     *   host_icount     — last per-vCPU TB-exec icount seen by this
     *                     thread.  Read from g_host_icount (the
     *                     scoreboard storage is torn down before
     *                     plugin_exit fires).  Matches the BBV
     *                     plugin's count for the same run.
     *
     *   traced_icount   — sum of per-segment `covered` (in-segment
     *                     architectural insns).  Should match the
     *                     number of CP body entries in the trace
     *                     files, BEFORE REP fan-out expansion.
     *
     *   rep_fanout      — total sub-entries emitted by REP fan-out
     *                     inside emit_body_entry, in-segment only.
     *
     * Identity the trace files satisfy:
     *   sum of cst_audit "CP insns (total)" across segments
     *     == g_total_arch_insns
     *
     * (traced_icount + rep_fanout under-counts by a handful of
     * insns per segment from chain-assembly edge cases — the BB-end
     * deferral and mid-TB-branch fragments don't always preserve
     * the "covered + fanout = audit" identity, but g_total_arch_insns
     * is summed directly from what emit_body_entry actually wrote.)
     *
     * host_icount (full-run BBV-style count) is reported separately
     * so it can be cross-checked against the BBV plugin run. */
    uint64_t fanout = g_rep_fanout_extra_insns.load(
        std::memory_order_relaxed);
    uint64_t traced = g_traced_icount.load(std::memory_order_relaxed);
    uint64_t arch   = g_total_arch_insns.load(
        std::memory_order_relaxed);
    g_string_append_printf(report,
        "champsim_tracer: host_icount=%" PRIu64
        " traced_icount=%" PRIu64
        " rep_fanout=%" PRIu64
        " trace_arch_insns=%" PRIu64 "\n",
        g_host_icount, traced, fanout, arch);

    g_mutex_lock(&data_lock);
    append_stats_summary(report, "Cumulative", stats_snapshot());
    if (g_simpoints.is_active()) {
        g_string_append_printf(report,
            "SimPoints loaded/traced: %zu / %zu\n\n",
            g_simpoints.size(), g_simpoints.current_index());
    }
    g_mutex_unlock(&data_lock);

    qemu_plugin_outs(report->str);

    /* qemu_plugin_outs goes via qemu_log, whose target (stderr by
     * default) may have been closed by the time we run — the guest's
     * exit syscall reaches us through preexit_cleanup AFTER QEMU has
     * torn its log fd down.  Mirror to a side file so the icount /
     * fanout / cumulative report is always recoverable. */
    if (stats_file) {
        fputs(report->str, stats_file);
        fclose(stats_file);
        stats_file = nullptr;
    }
    g_free(stats_path);
    stats_path = nullptr;

    if (unknown_warn_file) {
        fclose(unknown_warn_file);
    }
    g_free(unknown_warn_path);
    g_free(segment_label);

    MemAccessRecorder::cleanup_current_thread();
    RegSnapCollector::cleanup_current_thread();

    g_free(program_name);
    g_free(simpoints_file_path);
}

/* ========================= Plugin installation ========================= */

/* CST_MEMSTATS one-shot allocation-failure reporter: name the caller of
 * the C++ allocation that tripped the ulimit (the intermittent
 * segment-open bad_alloc aborts), then clear the handler so the retry
 * throws bad_alloc on the normal path.  Best effort — backtrace() may
 * itself fail under a hard address-space limit. */
static void memstats_new_failure_handler()
{
    std::set_new_handler(nullptr);
    struct mallinfo2 mi = mallinfo2();
    fprintf(stderr, "[memstats] C++ allocation FAILED: arena=%.2f GiB "
            "(in-use=%.2f GiB) mmap=%.2f GiB — backtrace:\n",
            mi.arena / 1073741824.0, mi.uordblks / 1073741824.0,
            mi.hblkhd / 1073741824.0);
    void *bt[64];
    int n = backtrace(bt, 64);
    backtrace_symbols_fd(bt, n, fileno(stderr));
    fflush(stderr);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    target_name = info->target_name;

    if (getenv("CST_MEMSTATS")) {
        std::set_new_handler(memstats_new_failure_handler);
    }

    /* Resolve ISA from target_name via the per-ISA prefix tables. */
    trace_isa = TRACE_ISA_UNKNOWN;
    for (unsigned isa_i = TRACE_ISA_X86;
         isa_i < G_N_ELEMENTS(isa_properties); isa_i++) {
        TraceISA isa = (TraceISA)isa_i;
        const char *const *prefixes = isa_properties[isa].target_prefixes;
        if (!prefixes) {
            continue;
        }
        for (; *prefixes; prefixes++) {
            if (g_str_has_prefix(target_name, *prefixes)) {
                trace_isa = isa;
                break;
            }
        }
        if (trace_isa != TRACE_ISA_UNKNOWN) {
            break;
        }
    }
    if (trace_isa == TRACE_ISA_UNKNOWN) {
        fprintf(stderr, "champsim_tracer: warning: unsupported ISA '%s', "
                "instruction decode will be limited\n", target_name);
    }

    /* RISC-V M-mode (normalized priv 3, the raw PRV_M the target hook
     * reports) executes with satp bypassed, so pinned attribution must
     * exclude it — see g_xlate_bypass_priv at the pin machinery. */
    if (trace_isa == TRACE_ISA_RISCV) {
        g_xlate_bypass_priv = 3;
    }

    /* MIPS pins a bare EntryHi.ASID value from an 8-bit (10 with
     * Config4.AE) space the OS must recycle, so arm the reuse detector —
     * see pin_reuse_track.  The wide-register targets stay unarmed. */
    if (trace_isa == TRACE_ISA_MIPS) {
        g_pin_reuse_guard = true;
    }

    /* Target byte order.  The four currently-supported ISAs (x86, AArch64,
     * RISC-V, MIPS) are LE in every QEMU configuration we ship except the
     * MIPS BE variants (qemu-mips, qemu-mips64), distinguished by the
     * lack of an "el" suffix on the target_name. */
    target_big_endian = (trace_isa == TRACE_ISA_MIPS &&
                         !g_str_has_suffix(target_name, "el"));

    /* Build the per-ISA marker byte sequences (WIN_MARKER detection).
     * The MIPS encoding is little-endian — mipsel only, matching the
     * supported targets. */
    marker_seq_init();

    /*
     * Map ISA to Capstone arch/mode.  arch is determined by
     * target_name and set here; the mode resolver may introspect the
     * guest binary via qemu_plugin_path_to_binary() (live-vCPU only),
     * so cap_mode is deferred to the first vcpu_init_cb.
     */
    if (trace_isa != TRACE_ISA_UNKNOWN) {
        const IsaProperties *p = &isa_properties[trace_isa];
        cst_cap_arch = p->cap_arch;
        cst_cap_mode = 0;  /* deferred — resolved in vcpu_init_cb */
    } else {
        cst_cap_arch = -1;
        cst_cap_mode = 0;
    }

    /* Best-effort capture of the full QEMU command line. */
    {
        FILE *cmdline_f = fopen("/proc/self/cmdline", "r");
        if (cmdline_f) {
            char buf[4096];
            size_t n = fread(buf, 1, sizeof(buf) - 1, cmdline_f);
            fclose(cmdline_f);
            if (n > 0) {
                for (size_t i = 0; i < n - 1; i++) {
                    if (buf[i] == '\0') {
                        buf[i] = ' ';
                    }
                }
                buf[n] = '\0';
                qemu_command_line = g_strdup(buf);
            }
        }
    }

    PluginConfig cfg;
    if (!parse_plugin_options(&cfg, argc, argv)) {
        plugin_config_free(&cfg);
        return -1;
    }

    /* Apply parsed config.  Long-lived string fields transfer out of
     * cfg (ownership moved); the rest are freed by
     * plugin_config_free below. */
    max_wrong_path_depth = cfg.wp_depth;
    g_wp_prune           = cfg.wp_prune;
    enable_wrong_path    = cfg.enable_wp;
    /*
     * Wrong-path speculation freezes the guest virtual clock for the excursion
     * via cpu_disable_ticks (host wall-clock).  Under -icount the virtual clock
     * is driven by the instruction count, which that freeze does NOT stop, so a
     * speculative excursion's instructions leak into guest time.  WP still runs
     * under icount (the trace is still valid); warn once that guest timing may
     * be perturbed.
     */
    if (enable_wrong_path && qemu_plugin_icount_enabled()) {
        fprintf(stderr, "champsim_tracer: warning: -icount is active; "
                "wrong-path speculation advances guest instruction-count time "
                "(the vtime freeze only covers wall-clock). Trace is valid but "
                "guest timing may be perturbed.\n");
    }
    g_devio_enabled          = cfg.devio != 0;
    g_features.mem_data      = cfg.enable_mem_data;
    g_features.reg_data      = cfg.enable_reg_data;
    /* Per-path toggles default to their CP siblings when unset (-1). */
    g_features.wp_mem_data   = (cfg.wp_mem_data < 0)
        ? g_features.mem_data : (cfg.wp_mem_data != 0);
    g_features.wp_reg_data   = (cfg.wp_reg_data < 0)
        ? g_features.reg_data : (cfg.wp_reg_data != 0);
    g_hist.intervals = cfg.histogram_intervals > 0
        ? (unsigned int)cfg.histogram_intervals : 0;
    g_features.iframe_rate         = cfg.iframe_rate;
    simpoint_interval_insns = cfg.simpoint_interval;
    warmup_insns        = cfg.warmup_insns;
    simulation_insns    = cfg.simulation_insns;

    program_name        = cfg.program_name;    cfg.program_name = nullptr;
    trace_comment       = cfg.comment;         cfg.comment = nullptr;
    simpoints_file_path = cfg.simpoints_file;  cfg.simpoints_file = nullptr;
    start_symbol        = cfg.start_symbol;    cfg.start_symbol   = nullptr;
    start_symbol_occurrence = cfg.start_symbol_occurrence;
    g_window_mode       = cfg.window_mode;
    g_marker_policy     = cfg.marker_policy;
    g_latch_timeout_ms  = cfg.latch_timeout_ms;

    /*
     * Two decoupled fault concerns, split from the former single flag:
     *
     *  (a) The system-only sync-fault DEPTH TRAILER + kernel-handler merge.
     *      Marker mode is the system-mode entrypoint (the validator's
     *      --system implies --marker, pinning a real guest ASID); a pinned
     *      simpoint qualifies too.  The per-entry trailer depth-tags handler
     *      code there; user-mode windows leave it off and emit no trailer.
     *
     *  (b) The wrong-path SYNTHETIC-FAULT marking policy.  A speculative
     *      memory access to an absent/unreadable page runs on a deterministic
     *      placeholder value and CONTINUES (a mispredicted-path fault is never
     *      taken by a real core); when set, the faulting insn's WP BB entry is
     *      marked CST_WP_EVENT_FAULT.  It must run whenever wrong-path
     *      simulation runs — system AND user mode alike.
     *
     * CST_NO_FAULT disables BOTH for A/B measurement (accesses still run on
     * garbage, but the synthetic fault is not marked).
     */
    g_system_mode = info->system_emulation;
    const bool fault_env_ok = getenv("CST_NO_FAULT") == nullptr;
    g_features.fault_depth_trailer =
        (g_window_mode == PluginConfig::WIN_MARKER ||
         pinned_simpoint_mode()) &&
        fault_env_ok;
    g_features.wp_synthetic_marking = enable_wrong_path && fault_env_ok;

    /* Kernel-excursion ownership rides the marker-mode ASID pin (the
     * ownership rule replaces the live-ASID test for kernel TBs of the
     * PINNED run only); outside marker mode the flag is inert, so keep
     * it wired verbatim rather than mode-gated. */
    g_features.kexc = cfg.kexc != 0;

    /* Physical-page capture is SYSTEM-MODE ONLY: qemu_plugin_get_hwaddr
     * returns NULL for linux-user, so there is no translation to record.
     * Forcing it off in user mode keeps user-mode traces byte-identical
     * regardless of the requested option. */
    g_features.physaddr = (cfg.physaddr != 0) && g_system_mode;
    if (cfg.physaddr != 0 && !g_system_mode) {
        fprintf(stderr, "champsim_tracer: physaddr=1 ignored in user mode "
                "(no virtual-to-physical translation exists)\n");
    }

    if (!cfg.output_path) {
        cfg.output_path = g_strdup("champsim_tracer_out");
    }
    g_trace_segments.set_output_path(cfg.output_path);
    g_trace_segments.set_compress_cmd(cfg.compress_cmd);

    unknown_warn_path = g_strdup_printf("%s.unknown_warnings.log",
                                        cfg.output_path);
    unknown_warn_file = fopen(unknown_warn_path, "w");
    if (!unknown_warn_file) {
        fprintf(stderr, "champsim_tracer: cannot open unknown-warning output: %s\n",
                unknown_warn_path);
    } else {
        fprintf(unknown_warn_file, "# champsim_tracer unknown instruction warnings\n");
        fflush(unknown_warn_file);
    }

    stats_path = g_strdup_printf("%s.stats.log", cfg.output_path);
    stats_file = fopen(stats_path, "w");
    if (!stats_file) {
        fprintf(stderr, "champsim_tracer: cannot open stats output: %s\n",
                stats_path);
    }

    uint64_t trace_start_insn = cfg.trace_start_insn;
    uint64_t trace_stop_insn  = cfg.trace_stop_insn;
    if (simpoints_file_path) {
        if (!g_simpoints.load(simpoints_file_path, simpoint_interval_insns)) {
            fprintf(stderr, "champsim_tracer: no valid simpoints in: %s\n",
                    simpoints_file_path);
            plugin_config_free(&cfg);
            return -1;
        }
        fprintf(stderr, "champsim_tracer: loaded %zu simpoints from %s\n",
                g_simpoints.size(), simpoints_file_path);
        trace_start_insn = 0;
        trace_stop_insn  = UINT64_MAX;
    }
    g_trace_segments.set_window(trace_start_insn, trace_stop_insn);
    plugin_config_free(&cfg);

    g_mutex_init(&data_lock);
    g_rec_mutex_init(&exec_lock);
    g_mutex_init(&unknown_warn_lock);

    active_insn_table = isa_insn_class[trace_isa];
    active_insn_table_size = isa_insn_class_size[trace_isa];
    active_reg_table = isa_reg_class[trace_isa];
    active_reg_table_size = isa_reg_class_size[trace_isa];

    /* Build the GenericRegId → QemuRegKey reverse index (needs the
     * per-ISA reg table).  The multi-reg path (RISC-V V*M* tuples,
     * future register groups) uses it to cover every constituent
     * generic id, not just the leading one. */
    build_qemu_reg_reverse_index();

    /* Pre-size the per-thread stats registry now, on the main thread,
     * before any vCPU runs.  This pins its backing buffer in the main
     * malloc arena so a teardown-time push_back (body_stream_finish on the
     * main thread) never reallocates/frees a buffer owned by a vCPU
     * thread's arena — the system-mode cross-arena teardown crash.  The
     * bound covers any realistic vCPU + service-thread count; exceeding it
     * merely falls back to the original lazy-growth path. */
    stats_registry_reserve(1024);

    if (g_window_mode == PluginConfig::WIN_SYMBOL) {
        if (!start_symbol) {
            fprintf(stderr,
                    "champsim_tracer: trace_window=symbol requires name=...\n");
            return -1;
        }
        /* No segment opens until the named symbol is seen
         * start_symbol_occurrence times in vcpu_tb_exec. */
    } else if (g_window_mode == PluginConfig::WIN_MARKER) {
        if (!g_marker_seq.valid) {
            fprintf(stderr, "champsim_tracer: trace_window=marker has no "
                    "marker encoding for this ISA\n");
            return -1;
        }
        if (marker_trace_all()) {
            /* Stage B2: trace-all.  The first marker opens the segment and
             * captures every context/ASID; the clock and the closing END
             * stay pinned to that first process (decision #4). */
            fprintf(stderr, "champsim_tracer: marker window policy=trace-all "
                    "(whole-system from the first marker; every context "
                    "captured; clock and END ride the first marker process; "
                    "segment closes at its END marker or the icount budget)\n");
        } else {
            fprintf(stderr, "champsim_tracer: marker window policy=latch "
                    "(per-process opt-in; segment closes when the last window "
                    "ends or the icount budget is met)\n");
        }
        /* No segment opens until the guest launch wrapper's magic
         * marker instruction executes (see vcpu_marker_cb). */
    } else if (!g_simpoints.is_active() && trace_start_insn == 0) {
        /* No vCPU at install time: empty initial regfile (id→name
         * still pinned, no live values).  Header total 0 = unbounded
         * when no explicit stop. */
        uint64_t total_target =
            (trace_stop_insn == UINT64_MAX) ? 0 : trace_stop_insn;
        start_trace_segment("trace", 0, trace_stop_insn,
                            /* warmup= */ 0, total_target,
                            /* cpu_index= */ (unsigned int)-1,
                            /* simpoint_weight= */ 0.0);
    }

    /* Prime the fast-path threshold with the first event icount so
     * pre-segment TBs lockless-bail until they get close. */
    recompute_next_threshold();


    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_flush_cb(id, vcpu_tb_flush);
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit, nullptr);
    if (g_system_mode) {
        /* Keep the per-vCPU asid_match flag current from the
         * architectural ASID-write commit points (fires even while the
         * path-event queue is disabled; wrong-path writes suppressed).
         * Backs the coarse fast-forward compensation — see
         * asid_write_track_cb. */
        qemu_plugin_register_asid_write_cb(id, asid_write_track_cb);
        /* Block-device I/O records: bracket disk requests in the body
         * stream (DEVIO_START at the doorbell, DEVIO_STOP at completion).
         * System mode only — the block backend does not exist in user
         * mode.  A no-op without disk traffic (no blk_aio_* fires), so
         * device-free system traces are byte-identical. */
        if (g_devio_enabled) {
            qemu_plugin_register_devio_cb(id, devio_doorbell_cb,
                                          devio_start_cb, devio_stop_cb);
            /* Advertise the DEVIO_* body-tag names in the header map only
             * now (device-free / user-mode traces omit them and stay
             * byte-identical). */
            devio_set_map_active(true);
        }
    }

    return 0;
}
