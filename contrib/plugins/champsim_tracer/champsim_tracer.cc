/*
 * Wrong-Path Tracing Plugin for QEMU
 *
 * Main translation unit: plugin install/lifecycle, tracing-window
 * management (windows + simpoints), the tb_trans/tb_exec/tb_flush
 * and memory-access callbacks, and exit-time statistics.  Every other
 * subsystem (decode, WP, output, and the headers included below) is
 * its own champsim_tracer_<name>.{h,cc} peer TU.  Output: packed
 * binary (.cst).
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
#include "champsim_tracer_delay.h"
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
uint32_t g_smc_revision_cap = 1024;   /* SMC per-PC revision cap (smc_plan §5-A) */

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
 * instruction bytes (Capstone decode failure — see detect_tb_poison).
 * WP speculation refuses to enter these; subsequent translation
 * re-attempts at the same start_pc skip fragment materialization.
 * Persistent across WP simulations AND tb_flush (see vcpu_tb_flush). */
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
 * The REPRESENTATIVE owned address space, as QEMU's opaque process id
 * (qemu_plugin_get_process_id).  g_pinned_asid above is the raw
 * architectural value the marker fired under and stays that: it names the
 * window on the WIRE and arms the "marker mode" predicate.  This is the
 * OWNERSHIP key — the thing set membership is tested on — and the two are
 * kept apart because on a narrow-ASID target the raw value is recycled
 * under live processes while the identity is not.  0 when unpinned.
 */
static std::atomic<uint64_t> g_pinned_pid{0};

/*
 * Owned-ASID set (multi-ASID Stage B, wide-register targets).  The set of
 * page-table roots (x86 CR3 / AArch64 TTBR / RISC-V SATP values, as
 * reported by qemu_plugin_get_addr_space_id) currently INSIDE tracer
 * vision — each process that ran the START marker and has not yet run its
 * END marker.  A single-process trace is a set of one, so every legacy
 * consumer behaves exactly as it did against the single pin.
 *
 * Generalizes the single g_pinned_asid gate: `g_pinned_asid` is retained
 * as the FIRST/representative owned root (so cst_pinned_asid_root/sig and
 * the "marker mode armed" predicate keep working single-process), while
 * the actual foreign-drop
 * predicate (pin_user_tb_owned, wide-register) and the coarse-FF
 * asid_match flag consult SET MEMBERSHIP here.
 *
 * Mutated only at marker START/END, under exec_lock (the marker callbacks
 * already hold it around the segment open/close).  Read under exec_lock in
 * pin_user_tb_owned (the caller holds it) and, off the per-TB path, in the
 * ASID-write hook (which takes exec_lock for the read).  Kept consistent
 * with the Stage-A index map: every root added here is also assigned a
 * compact asid index + stored identity {root_phys, sig}.  Every supported
 * target populates it, MIPS included: the key is the page-table root the
 * hardware walks from, so there is no target left that needs a dwell/verify
 * substitute for one.
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

/*
 * Instruction-denominated dead latch (latch_idle_insns=<N>): the same
 * detector as g_latch_timeout_ms, on a denominator the host cannot move.
 * Wall-clock idleness rides on host load, so a wall-clock latch closes the
 * same window at two different points of the guest's own execution on a
 * quiet host and a loaded one; trace validity and hang prevention must
 * never depend on host load.  Counted in GLOBAL guest architectural
 * instructions (every context, every vCPU) so it keeps advancing exactly
 * when the wall clock's advantage matters — while the owned process is not
 * running at all.  0 (default) disables it; the two detectors are
 * independent and a root is dead when EITHER threshold is crossed.  See
 * PluginConfig::latch_idle_insns for how this differs from stall_ceiling.
 */
static uint64_t g_latch_idle_insns = 0;

/* Per-owned-root global architectural instruction count at last
 * schedule-in — the instruction-clock twin of g_owned_last_sched, kept in
 * lockstep with it at every stamp and every erase (the narrow-ASID path
 * carries the equivalent as OwnedProc.last_sched_insns).  Guarded by
 * exec_lock; immortal. */
static std::unordered_map<uint64_t, uint64_t> &g_owned_last_sched_insns =
    *new std::unordered_map<uint64_t, uint64_t>();

/* Either denominator configured.  The cheap pre-check the detector's call
 * sites use before entering it; the mode/policy gate lives inside
 * deadlatch_enabled(). */
static inline bool deadlatch_configured(void)
{
    return g_latch_timeout_ms != 0 || g_latch_idle_insns != 0;
}

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

/*
 * Global guest architectural instruction count: the sum of every vCPU's
 * insn_count slot, which the unconditional per-TB inline add maintains from
 * the TB's own instruction count.  This is architectural state — it counts
 * what the guest retired, in any context, and nothing the host scheduler
 * does can move it — which is the entire point of the instruction latch.
 *
 * NOT g_total_arch_insns: that accumulator is fetch_add'ed only inside
 * finish_trace_segment, so it holds 0 for the whole life of the segment a
 * live detector has to run in and an idle computed against it would be
 * identically zero.  Read only off the hot path, like deadlatch_now_ms().
 */
static inline uint64_t deadlatch_now_insns(void)
{
    return qemu_plugin_u64_sum(g_scoreboard.insn_count);
}

/*
 * Was this root idle long enough to be dead?  Each denominator is
 * independently opt-in, and either alone is sufficient.  @by_insns reports
 * that the INSTRUCTION denominator is what crossed (and the wall clock did
 * not), so the close can name which detector fired.  With latch_idle_insns
 * unset the second term is dead: the set of roots a sweep reaps is exactly
 * what the wall-clock detector alone reaps today.
 */
static inline bool deadlatch_root_is_dead(uint64_t idle_ms,
                                          uint64_t idle_insns,
                                          bool *by_insns)
{
    bool ms_crossed  = g_latch_timeout_ms && idle_ms    >= g_latch_timeout_ms;
    bool ins_crossed = g_latch_idle_insns && idle_insns >= g_latch_idle_insns;
    *by_insns = ins_crossed && !ms_crossed;
    return ms_crossed || ins_crossed;
}

/* Off-hot-path staleness sweep, driven from the synchronous ASID-write
 * hook — defined after finish_trace_segment / data_lock are in scope. */
static void deadlatch_on_asid_write(unsigned int vcpu_index,
                                    uint64_t new_asid);

/* Retirement-driven sweep cadence: one sweep per this many globally
 * retired guest instructions (deadlatch_beat, driven from the per-TB
 * correct-path step — any context, any privilege).  Riding the global
 * retirement clock is what makes the instruction-denominated latch's
 * trigger inseparable from its threshold's denominator: the sweep runs
 * exactly while idle_insns can grow, independent of how often the guest
 * writes the address-space register or schedules the owned process. */
static constexpr uint64_t DEADLATCH_UIC_STRIDE = 8192;
static void deadlatch_beat(unsigned int cpu_index);

/*
 * Does this CPU model name a thread architecturally at all?  Set false at
 * pin time when the target reports thread id 0 for a real address space —
 * a MIPS model with Config3.ULRI clear implements no UserLocal register,
 * so there is no per-thread value to compare.  Without one the ONE re-bind
 * rule cannot fire, which matters on exactly the targets whose
 * address-space NAME is recycled under live processes.
 */

/* Retire the pinned window because its architectural address-space NAME was
 * handed out again and this CPU model gives nothing to re-bind against.
 * Defined beside the dead-latch closes, which it reuses. */

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

/*
 * THE PIN-ABSOLUTE USER CLOCK.
 *
 * g_user_icount is an EPOCH counter: user_count_reset zeroes it at the pin
 * and again at every segment open, so a window's budget reads "user insns
 * since this window opened".  A pinned-simpoint SCHEDULE positions on a
 * different clock.  Its cluster offsets are absolute from the pin — they
 * come from a user-mode SimPoint run that counted the same user-space
 * instruction stream from the program's start — and they stay meaningful
 * only against a clock that never restarts.  Comparing them against the
 * epoch counter places the first cluster correctly and mis-places every
 * cluster after it, silently: the capture is a valid region, just not the
 * region the schedule named.
 *
 * g_user_icount_pin_base carries the user instructions retired by all
 * CLOSED epochs, so pin_user_clock() == base + epoch is monotone from the
 * pin across any number of segments.  Positioning reads pin_user_clock();
 * window budgets keep reading g_user_icount.  The base is zeroed at the
 * pin and advanced by exactly the epoch it retires at each segment open,
 * so the two clocks agree at every boundary.
 *
 * User mode never touches it.  There is no pin and no schedule there, the
 * base is therefore never assigned anything but its 0 initialiser, and
 * pin_user_clock() reduces to g_user_icount identically.
 */
static uint64_t g_user_icount_pin_base = 0;

/* Trace segments finalised to a file so far (see finish_trace_segment). */
static size_t g_segments_written = 0;

static inline uint64_t pin_user_clock(void)
{
    return g_user_icount_pin_base + g_user_icount;
}

/*
 * USER-CLOCK STALL CEILING (stall_ceiling=<arch insns>; see PluginConfig).
 * The marker window's budget runs on g_user_icount, which advances only
 * while the pinned process executes user-space code.  A process that is
 * alive and on-CPU but never returns to user space therefore freezes the
 * budget AND can never execute its END marker: nothing closes the segment
 * and the run is unbounded.  These counters bound it architecturally —
 * instructions retired in an owned context since the pinned user clock
 * last moved, per vCPU (a generation stamp reseats every vCPU's base when
 * any of them advances the clock).  Owned contexts only: a foreign
 * process running while the pin idles is not a stall.  All of it is
 * touched under exec_lock, from the correct-path step.
 */
static uint64_t g_stall_ceiling = CST_STALL_CEILING_DEFAULT;
static uint64_t g_stall_last_uic = 0;
static uint64_t g_stall_gen = 0;
static uint64_t g_stall_seen_gen[CST_PIN_MAX_VCPUS];
static uint64_t g_stall_base[CST_PIN_MAX_VCPUS];
static bool     g_stall_ceiling_fired = false;
static bool     g_stall_warned = false;

/*
 * ANY-CONTEXT STALL CEILING (stall_ceiling_any=<arch insns>).
 *
 * The ceiling above only accumulates while the TRACED process is running,
 * so it cannot bound the case where the traced process is not running at
 * all: killed after its window opened, or blocked in a syscall it never
 * leaves, while the rest of the guest stays busy.  There the user clock is
 * frozen, the END marker can never execute, no owned instruction is ever
 * retired — and nothing ends the run.  These counters bound THAT: guest
 * instructions retired in ANY context since the pinned user clock last
 * advanced.  Sampled at the top of the correct-path step, which every
 * dispatched TB reaches while a segment is open — including the foreign
 * and async ones that are dropped a few lines later, and which are all a
 * guest with a dead traced process ever executes.
 */
static uint64_t g_stall_any_ceiling = CST_STALL_ANY_CEILING_DEFAULT;
static uint64_t g_stall_any_last_uic = 0;
static uint64_t g_stall_any_gen = 0;
static uint64_t g_stall_any_seen_gen[CST_PIN_MAX_VCPUS];
static uint64_t g_stall_any_base[CST_PIN_MAX_VCPUS];
static bool     g_stall_any_fired = false;
static bool     g_stall_any_warned = false;

static inline void user_clock_stall_reset(void)
{
    g_stall_last_uic = 0;
    g_stall_gen++;
    g_stall_ceiling_fired = false;
    g_stall_warned = false;
    g_stall_any_last_uic = 0;
    g_stall_any_gen++;
    g_stall_any_fired = false;
    g_stall_any_warned = false;
    for (unsigned i = 0; i < CST_PIN_MAX_VCPUS; i++) {
        g_stall_seen_gen[i] = 0;
        g_stall_any_seen_gen[i] = 0;
    }
}

/* Set when the segment is closed by the guest's end marker (the workload
 * finished under budget by design) so the finish printout reports END
 * rather than an UNDER underrun. */
static bool g_seg_end_marker_close = false;

/*
 * A close the ordinary OK / END / UNDER rendering cannot name, because it
 * was forced rather than reached: the any-context termination ceiling
 * (CEILING) or the machine going down under an open window (SHUTDOWN).
 * Both truncate the capture, and a truncation a reader cannot tell from a
 * short-but-complete run is exactly the kind of quiet result this tracer
 * must not produce — so the flag on the segment's own close line names it,
 * the statistics report counts it, and the trace's own coverage numbers
 * (covered vs budget) sit next to it.  nullptr = ordinary rendering.
 */
static const char *g_seg_close_reason = nullptr;

/* Deferred end-of-run for the machine-RESET close route: set by
 * vcpu_vm_reset_cb after it finalises the segment (possibly under the
 * BQL, inside the resetting device write), consumed at the top of
 * vcpu_tb_trans, where the exit runs on a vCPU thread outside any
 * device dispatch.  See the reset-route comment block ahead of
 * vcpu_vm_reset_cb. */
static std::atomic<bool> g_reset_exit_pending{false};

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
/* Step-bail counter for pinned user-privilege TBs (diag): a stall of the
 * user clock while the guest keeps running shows up here. */
static thread_local uint64_t tls_mkdiag_susp_user = 0;

/*
 * FENCE LANE INSTRUMENTATION (diagnostic only; every hook is off unless its
 * environment variable is set, and none of them changes a byte of the trace).
 *
 * CST_FENCE_DIAG=<seconds>  heartbeat: print the window state, the pinned
 *   process's user clock, the retired-instruction clock, the three wrong-path
 *   fence flags and the END-marker callback census every <seconds> of host
 *   time.  A window that never closes then leaves a durable record even when
 *   the cell is killed at its cap.
 * CST_FENCE_FORCE_END=1     defect simulator: force EVERY end-marker
 *   invocation down the fence's drop path while a segment is open — a leaked
 *   fence flag, reproduced on demand, so the signature of a suppressed
 *   correct-path END can be compared against the real non-closing cells.
 *   It is also the POSITIVE CONTROL for `marker END with no close`: the
 *   suppression it forces is a correct-path END that closes nothing, and
 *   the tripwire is tested ahead of the drop precisely so it sees it (see
 *   vcpu_marker_end_cb).
 * CST_FENCE_FORCE_SESSION=<n>  the other leak shape: leave the per-vCPU
 *   wrong-path session bracket SET when the n-th excursion ends, so the
 *   correct path runs flagged as speculative.  Positive control for
 *   `WP session flag on correct path` and `marker fence session-only`.
 *   Implemented in champsim_tracer_wp.cc, where the bracket is closed.
 */
static inline int64_t fence_diag_period_ns(void)
{
    static std::atomic<long long> v{-1};
    long long x = v.load(std::memory_order_relaxed);
    if (x < 0) {
        const char *e = getenv("CST_FENCE_DIAG");
        double s = (e && *e) ? strtod(e, nullptr) : 0.0;
        x = (long long)(s * 1e9);
        if (e && *e && x <= 0) {
            x = 5000000000LL;                /* bare CST_FENCE_DIAG=1 -> 5 s */
        }
        v.store(x, std::memory_order_relaxed);
    }
    return (int64_t)x;
}
static inline bool fence_diag(void)
{
    return fence_diag_period_ns() > 0;
}
static inline bool fence_force_end(void)
{
    static std::atomic<int> v{-1};
    int x = v.load(std::memory_order_relaxed);
    if (x < 0) {
        x = getenv("CST_FENCE_FORCE_END") ? 1 : 0;
        v.store(x, std::memory_order_relaxed);
    }
    return x != 0;
}

/* One END-marker callback invocation, recorded BEFORE the fence decides. */
struct FenceEndRec {
    uint64_t pc = 0;
    uint64_t asid = 0;
    uint64_t uic = 0;             /* pinned user clock at the invocation */
    uint64_t ms = 0;              /* monotonic host ms */
    int      priv = -1;
    uint8_t  flags = 0;           /* 1 spec | 2 wp | 4 sess | 8 forced */
    uint8_t  run_after = 0;       /* adjacency run after the step (CP only) */
    bool     fenced = false;
};
static constexpr unsigned FDIAG_RING = 256;
static FenceEndRec g_fdiag_end_ring[FDIAG_RING];
static unsigned g_fdiag_end_head = 0;
static uint64_t g_fdiag_end_total = 0;
static uint64_t g_fdiag_end_fenced = 0;
static uint64_t g_fdiag_end_fenced_user = 0;   /* fenced at USER privilege */
static uint64_t g_fdiag_end_cp = 0;            /* reached the run machine */
static uint64_t g_fdiag_start_total = 0;
static uint64_t g_fdiag_start_fenced = 0;
static uint64_t g_fdiag_end_printed = 0;       /* ring entries already shown */
/* Completed correct-path runs.  ATOMIC: the marker callbacks run on the
 * executing vCPU's own thread with no lock held, and the marker stress
 * judges the invariant by EXACT EQUALITY against a count the guest prints,
 * so a lost increment on an SMP guest would read as a missed sequence. */
static std::atomic<uint64_t> g_fdiag_start_runs{0};
static std::atomic<uint64_t> g_fdiag_end_runs{0};

static inline void fence_note_end(uint64_t pc, uint64_t asid, int priv,
                                  uint8_t flags, bool fenced,
                                  uint8_t run_after)
{
    g_fdiag_end_total++;
    if (fenced) {
        g_fdiag_end_fenced++;
        if (priv == 0) {
            g_fdiag_end_fenced_user++;
        }
    } else {
        g_fdiag_end_cp++;
    }
    FenceEndRec &r = g_fdiag_end_ring[g_fdiag_end_head % FDIAG_RING];
    r.pc = pc;
    r.asid = asid;
    r.uic = g_user_icount;
    r.ms = deadlatch_now_ms();
    r.priv = priv;
    r.flags = flags;
    r.fenced = fenced;
    r.run_after = run_after;
    g_fdiag_end_head++;
}

/* Print every END-marker invocation the census has not shown yet: the direct
 * answer to "did the end marker execute, on which path, at what user clock,
 * and did the fence drop it".  Flushed on the heartbeat, at the close, and
 * at plugin exit. */
static void fence_flush_end_ring(void)
{
    if (!fence_diag()) {
        return;
    }
    uint64_t first = g_fdiag_end_head > FDIAG_RING
                     ? g_fdiag_end_head - FDIAG_RING : 0;
    if (g_fdiag_end_printed < first) {
        fprintf(stderr, "[fence]   (%" PRIu64 " END records lost from the "
                "ring)\n", first - g_fdiag_end_printed);
        g_fdiag_end_printed = first;
    }
    while (g_fdiag_end_printed < g_fdiag_end_head) {
        const FenceEndRec &r =
            g_fdiag_end_ring[g_fdiag_end_printed % FDIAG_RING];
        fprintf(stderr, "[fence]   END#%" PRIu64 " ms=%" PRIu64
                " pc=0x%" PRIx64 " priv=%d asid=0x%" PRIx64 " uic=%" PRIu64
                " %s flags=0x%x run_after=%u\n",
                g_fdiag_end_printed, r.ms, r.pc, r.priv, r.asid, r.uic,
                r.fenced ? "FENCED" : "CP", r.flags, r.run_after);
        g_fdiag_end_printed++;
    }
    fflush(stderr);
}

/*
 * RETIRED-INSTRUCTION CURSOR — the architectural twin of user_seen.
 *
 * user_seen advances against insn_count, whose per-TB inline add credits a
 * TB's whole instruction count the moment the TB is ENTERED.  These
 * advance against insn_started, whose add is the instruction's own, so the
 * delta between two dispatches is the number of instructions that really
 * ran between them — not the number the dispatched TBs would have run had
 * nothing interrupted them.
 *
 * The attribution is LAGGED BY ONE DISPATCH and it has to be: the
 * instructions counted at dispatch N are the ones the TB dispatched at N-1
 * executed.  @g_retired_owner_owned remembers whether that earlier
 * dispatch was the owned process's, and @g_retired_tb_base is the cursor
 * value at the CURRENT dispatch, which the segment close uses to learn how
 * far into the in-flight block execution actually got.
 */
static uint64_t g_retired_seen[CST_PIN_MAX_VCPUS];
static bool     g_retired_seen_primed[CST_PIN_MAX_VCPUS];
static bool     g_retired_owner_owned[CST_PIN_MAX_VCPUS];
static uint64_t g_retired_tb_base[CST_PIN_MAX_VCPUS];
/* Which TB head @g_retired_tb_base belongs to, and the same pair for the
 * dispatch before it.  A close can land on either side of the promote that
 * makes the current TB the pending seal (PathBuilder::set_prev), so the
 * closing walk asks by TB head rather than assuming which one it holds. */
static const BBTemplate *g_retired_tb_head[CST_PIN_MAX_VCPUS];
static const BBTemplate *g_retired_prev_head[CST_PIN_MAX_VCPUS];
static uint64_t g_retired_prev_executed[CST_PIN_MAX_VCPUS];
/* Was the delta folded at THIS dispatch actually billed to the window
 * clock?  Read by the fault re-credit, which runs later in the same step,
 * after g_retired_owner_owned has been re-armed for the current dispatch. */
static bool     g_retired_prev_billed[CST_PIN_MAX_VCPUS];

static inline unsigned retired_slot(unsigned int cpu_index)
{
    return cpu_index < CST_PIN_MAX_VCPUS ? cpu_index : CST_PIN_MAX_VCPUS - 1;
}

/* Architectural instruction count of a whole dispatched TB (all fragments). */
static inline uint32_t tb_head_insns(const BBTemplate *head)
{
    uint32_t n = 0;
    for (const BBTemplate *f = head; f; f = f->next_tb_fragment) {
        n += f->n_insns;
    }
    return n;
}

/*
 * The PC of the @idx'th instruction of a whole dispatched TB, walking its
 * fragment list in execution order.  0 when @idx is past the TB's end.
 *
 * Used to ask the one question the retired cursor cannot answer on its own:
 * insn_started counts instructions BEGUN, so a TB the guest abandoned
 * part-way has already counted the instruction it abandoned.  Control
 * standing on insn[started-1] means QEMU rewound to that instruction and is
 * re-running it in an ORDINARY instrumented TB, whose own add is about to
 * count it a second time — so it did not retire in this dispatch.  (The
 * device-MMIO re-run is the exception and needs no correction: it happens in
 * a CF_MEMI_ONLY TB, whose non-memory instrumentation plugins/api.c
 * suppresses, so it neither re-adds nor moves current_pc.)
 */
static inline uint64_t tb_head_insn_pc_at(const BBTemplate *head, uint32_t idx)
{
    for (const BBTemplate *f = head; f; f = f->next_tb_fragment) {
        if (idx < f->n_insns) {
            return f->insn_pcs ? f->insn_pcs[idx] : 0;
        }
        idx -= f->n_insns;
    }
    return 0;
}

/* Index of @pc among the instructions of the dispatched TB @head, or
 * UINT32_MAX when @pc is not one of them. */
uint32_t tb_head_insn_index(const BBTemplate *head, uint64_t pc)
{
    uint32_t base = 0;
    for (const BBTemplate *f = head; f; f = f->next_tb_fragment) {
        for (uint32_t i = 0; i < f->n_insns; i++) {
            if (f->insn_pcs && f->insn_pcs[i] == pc) {
                return base + i;
            }
        }
        base += f->n_insns;
    }
    return UINT32_MAX;
}

/* Instructions this vCPU has completed, live. */
static inline uint64_t retired_now(unsigned int cpu_index)
{
    return qemu_plugin_u64_get(g_scoreboard.insn_started, cpu_index);
}

/* Instructions completed inside the TB currently in flight on @cpu_index.
 * Read from a pre-instruction callback (the marker close) it is exactly
 * the number of the in-flight block's instructions that executed. */
static inline uint64_t retired_in_flight(unsigned int cpu_index)
{
    unsigned s = retired_slot(cpu_index);
    uint64_t now = retired_now(cpu_index);
    return now >= g_retired_tb_base[s] ? now - g_retired_tb_base[s] : 0;
}

static inline uint64_t retired_advance(unsigned int cpu_index,
                                       const BBTemplate *cur)
{
    unsigned s = retired_slot(cpu_index);
    uint64_t now = retired_now(cpu_index);
    uint64_t delta = g_retired_seen_primed[s] && now >= g_retired_seen[s]
        ? now - g_retired_seen[s] : 0;
    g_retired_prev_head[s] = g_retired_tb_head[s];
    g_retired_prev_executed[s] = delta;
    g_retired_tb_head[s] = cur;
    g_retired_seen[s] = now;
    g_retired_tb_base[s] = now;
    g_retired_seen_primed[s] = true;
    return delta;
}

static inline void retired_reset(unsigned int cpu_index)
{
    for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; i++) {
        unsigned s = retired_slot((unsigned)i);
        g_retired_owner_owned[s] = false;
        g_retired_tb_head[s] = nullptr;
        g_retired_prev_head[s] = nullptr;
        g_retired_prev_executed[s] = 0;
        if ((unsigned)i == cpu_index) {
            g_retired_seen[s] = retired_now((unsigned)i);
            g_retired_tb_base[s] = g_retired_seen[s];
            g_retired_seen_primed[s] = true;
        } else {
            g_retired_seen_primed[s] = false;
        }
    }
}

/*
 * How many instructions of the dispatched TB @head actually executed.
 *
 * The segment-close walk needs this and cannot infer it: the scoreboard's
 * prev_start_pc resolves to the last-executed FRAGMENT, which says nothing
 * about how far into that fragment the guest got before the ceiling, a
 * machine teardown or the guest's own death stopped it.  (Not the END
 * marker: its close is deferred to the end of the marker's own true BB,
 * so it lands at a block boundary with nothing part-way — see
 * marker_close_and_exit.)  Two dispatch positions can hold @head — the one
 * whose base is live (a close from inside an instruction callback) and the
 * one before it (a close taken at the top of a dispatch, before the promote) —
 * and both answers are exact, so the caller does not have to know which
 * side of the promote it is on.  Clamped to the TB's own extent: the
 * lagged delta counts everything that ran between two dispatches, and a
 * TB whose successor was never dispatched (a foreign context the gate
 * skips) would otherwise read above its own length.
 *
 * Returns false when @head is neither — no answer is better than a wrong
 * truncation, and the caller counts the case (see close_walk_extent_unknown).
 */
/*
 * THE IN-FLIGHT EXTENT A CLOSE READS MUST BE SAMPLED WHILE THE CAPTURE IS
 * STILL RECORDING.
 *
 * retired_in_flight() reads insn_started, which is an UNGATED inline add
 * (one per instruction, registered last among an instruction's ops), while
 * every observation sink is gated on the is_active scoreboard slot:
 * vcpu_insn_reg_snap_cb, vcpu_mem_cb and vcpu_insn_synth_ea_cb all bail
 * when the segment is not active.  TraceSegmentManager::finish() clears
 * active_ BEFORE it runs the close's flush hook, and a close quiesces
 * nobody: it holds exec_lock, so a PEER vCPU stops only when it reaches
 * its next vcpu_tb_exec callback, and until then it runs out the rest of
 * the TB it is standing in with every sink shut.  A live read taken inside
 * the flush hook therefore counts instructions nothing recorded -- up to
 * the whole TB, since retired_executed_of clamps to its length -- and the
 * flush publishes them from the template with their fields inherited from
 * an earlier execution's delta-persist slots.  That is the fabrication
 * class of the branch-outcome and close-drained-register defects, reached
 * through the extent instead of through a field.
 *
 * So the extent is sampled ONCE per close, on the closing thread, before
 * the capture stops recording, and every close-path reader is answered
 * from that snapshot.  The sample is honest by the op order the inline add
 * documents: insn_started is registered AFTER the per-insn reg-snap
 * callback, so a value of c proves instruction c's whole prologue ran --
 * including the capture of instruction c-1's destinations -- and therefore
 * that instructions 1..c-1 completed with their observations recorded.
 * c-1 is exactly what the flush's stop rule publishes.  A peer that runs
 * further between the sample and the drain only appends past the prefix
 * being published; it cannot un-record what is already in the sink, and it
 * cannot emit, because emission needs the exec_lock the closing thread
 * holds.
 */
static const BBTemplate *g_close_extent_head[CST_PIN_MAX_VCPUS];
static uint64_t g_close_extent_insns[CST_PIN_MAX_VCPUS];
static bool     g_close_extent_armed;

static void retired_close_extent_arm(void)
{
    const unsigned int n = (unsigned int)qemu_plugin_num_vcpus();
    for (unsigned int i = 0; i < CST_PIN_MAX_VCPUS; i++) {
        if (i < n) {
            g_close_extent_head[i] = g_retired_tb_head[i];
            g_close_extent_insns[i] = retired_in_flight(i);
        } else {
            g_close_extent_head[i] = nullptr;
            g_close_extent_insns[i] = 0;
        }
    }
    g_close_extent_armed = true;
}

static void retired_close_extent_disarm(void)
{
    g_close_extent_armed = false;
    for (unsigned int i = 0; i < CST_PIN_MAX_VCPUS; i++) {
        g_close_extent_head[i] = nullptr;
        g_close_extent_insns[i] = 0;
    }
}

bool retired_executed_of(unsigned int cpu_index, const BBTemplate *head,
                         uint64_t *out)
{
    if (!head) {
        return false;
    }
    unsigned s = retired_slot(cpu_index);
    uint64_t n;
    if (head == g_retired_tb_head[s]) {
        /* The in-flight arm.  Inside a close this comes from the sample
         * taken before recording stopped; outside one the reader is the
         * vCPU's own thread and the counter is not moving under it. */
        n = (g_close_extent_armed && g_close_extent_head[s] == head)
            ? g_close_extent_insns[s]
            : retired_in_flight(cpu_index);
    } else if (head == g_retired_prev_head[s]) {
        n = g_retired_prev_executed[s];
    } else {
        return false;
    }
    uint32_t cap = tb_head_insns(head);
    *out = n > cap ? cap : n;
    return true;
}

/*
 * IS @head THE BLOCK THE GUEST IS STANDING IN ON @cpu_index?
 *
 * There is exactly one dispatch position at which that can be true: the
 * CURRENT one.  retired_executed_of also answers for the PREVIOUS dispatch,
 * and PathBuilder::prev_extent answers from a measurement taken at the first
 * dispatch AFTER prev — both of which are positions a successor block has
 * already been dispatched from, so the block they describe provably ran to
 * its end.
 *
 * The distinction matters to exactly one caller: the machine-shutdown
 * close, which is told by QEMU whether the vCPU is inside a guest
 * instruction (qemu_plugin_vm_shutdown_cb's in_guest_insn) and subtracts
 * that begun-but-unretired instruction from the slot's retired prefix.
 * That fact is about the vCPU's CURRENT instruction; the pending-seal slot
 * holds the last block of the PINNED process, which on a system guest is
 * almost never the process performing the poweroff.  Applying the
 * subtraction to a slot the cursor can no longer name drops an instruction
 * that retired.
 */
bool retired_is_in_flight(unsigned int cpu_index, const BBTemplate *head)
{
    return head && head == g_retired_tb_head[retired_slot(cpu_index)];
}

/*
 * The same question asked SPECIFICALLY of the previous dispatch.
 *
 * retired_executed_of accepts either dispatch position because a segment
 * close can land on either side of the promote.  A per-execution reader
 * cannot: a TB that BRANCHES TO ITSELF — every tight single-block loop — is
 * the previous dispatch AND the current one, the same BBTemplate pointer in
 * both slots, and the "current" arm answers with the in-flight count of the
 * dispatch that has only just begun, which is zero.  A seal walk that
 * believed that would emit nothing for the loop body and leave its captured
 * dst snaps in the positional sink as the next block's leaked prefix.
 * Returns false unless @head really is the previous dispatch's TB.
 */
bool retired_executed_prev(unsigned int cpu_index, const BBTemplate *head,
                           uint64_t *out)
{
    unsigned s = retired_slot(cpu_index);
    if (!head || head != g_retired_prev_head[s]) {
        return false;
    }
    uint64_t n = g_retired_prev_executed[s];
    uint32_t cap = tb_head_insns(head);
    *out = n > cap ? cap : n;
    return true;
}

/*
 * THE WINDOW CLOCK MUST NOT BILL A FAULT'S ABORTED ATTEMPT.
 *
 * QEMU pushes a FAULT_ENTER only for a RE-EXECUTING fault (see
 * cpu_plugin_fault_push, include/hw/core/cpu.h: "Every pushed fault
 * re-executes its faulting instruction").  insn_started counts instructions
 * BEGUN, so the aborted attempt's instructions are already in the delta the
 * previous dispatch folded, and they are counted AGAIN when the handler
 * returns and they re-execute — while the merge puts the faulting block on
 * the wire exactly once, whole.  The clock therefore over-reads by exactly
 * the instructions RE-ATTEMPTED: one for an ordinary data fault, and two on
 * a MIPS branch-delay-slot fault (EPC names the branch, Cause.BD=1, so the
 * branch AND its delay slot re-execute).
 *
 * This is the correction VCPUScoreBoard::insn_started's own contract has
 * named since the slot was minted and that was never written.  It is applied
 * where the fault is OBSERVED — the amount is (instructions started in the
 * aborted attempt) minus (the index the handler resumes at), and both
 * operands are only in hand there.
 *
 * @insns is that amount.  It is subtracted from the clock only when the
 * aborted attempt was actually billed; a saturating subtract keeps a clock
 * that a reset has already zeroed from wrapping.
 */
void user_clock_fault_recredit(unsigned int cpu_index, uint64_t insns)
{
    if (insns == 0 || !g_retired_prev_billed[retired_slot(cpu_index)]) {
        return;
    }
    if (insns > g_user_icount) {
        insns = g_user_icount;
    }
    g_user_icount -= insns;
    if (g_stats.user_clock_retired_insns >= insns) {
        g_stats.user_clock_retired_insns -= insns;
    }
    g_stats.user_clock_fault_recredits++;
    g_stats.user_clock_fault_recredit_insns += insns;
}

/*
 * BILLING AT EMIT, AT THE CLOSE: the clock advances by exactly the
 * PUBLISHED user range of the one holder whose dispatch-time fold never
 * came — the pending-seal slot of a vCPU with no dispatch after it.
 *
 * Every other close emission is already billed: the mid-step walk snapshot
 * and the in-flight chain were folded at their following dispatches, and a
 * slot that HAS seen a later dispatch was folded by it (retired_advance
 * runs on every dispatch, owned or not).  Only the never-dispatched-after
 * slot — the closing vCPU's own block at an END/ceiling close, and a peer
 * slot the pinned thread migrated off and nothing ran on since — carries
 * retired work no fold has billed.  Crediting it with the extent the flush
 * PUBLISHES (not the extent the retired cursor measured) is what makes
 * BILLED == PUBLISHED an identity at every close: the boundary instruction
 * a close leaves unobserved — the END-firing instruction mid-callback, the
 * un-snapped tail — is outside the published range, therefore unbilled.
 *
 * Called by PathBuilder::flush_final with the stop it is about to emit.
 * The two gates are positional: @head still standing at the CURRENT
 * dispatch cursor slot means no fold has run for it, and the ownership
 * flag armed at that same dispatch says whether its fold WOULD have
 * billed (kernel and foreign blocks never bill).
 */
void user_clock_close_credit(unsigned int cpu_index, const BBTemplate *head,
                             uint64_t published)
{
    if (published == 0 || head == nullptr || head->is_system) {
        return;
    }
    unsigned s = retired_slot(cpu_index);
    if (head != g_retired_tb_head[s] || !g_retired_owner_owned[s]) {
        return;      /* folded at a later dispatch, or not clock-owned */
    }
    g_user_icount += published;
    g_stats.user_clock_retired_insns += published;
    g_stats.user_clock_close_credits++;
    g_stats.user_clock_close_credit_insns += published;
}

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
    user_clock_stall_reset();
    for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; i++) {
        qemu_plugin_u64_set(g_scoreboard.user_seen, (unsigned)i,
                            (unsigned)i == cpu_index
                                ? insn_count_now : USER_SEEN_UNPRIMED);
        /* A pre-reset REP continuation must not withhold a tick from the
         * fresh clock. */
        rep_state((unsigned)i).prev_tb_counted = false;
        rep_state((unsigned)i).prev_tb_rep_n = 0;
    }
    retired_reset(cpu_index);
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

/* REP compensation for the coarse countdown — the window-clock rule
 * (count what the bbv plugin counts under the canonical loop translation)
 * applied where no per-TB callback exists.  Registered during coarse
 * fast-forward ONLY on user TBs whose first instruction is a fan-out
 * instruction: every execution that must lose its count is a re-entering
 * one, and a re-entering execution is by definition followed by an entry
 * to this very TB, so this callback observes each of them exactly once,
 * one entry later.  When the previous execution of this instruction left
 * by re-entering OFF a canonical chunk boundary (a per-iteration
 * translation pass under -icount — the canonical translation bbv counted
 * makes no such entry), add its unconditional decrement back.  Ownership:
 * a re-entry chain is synchronous within one process, so the live
 * asid_match stands in for the previous execution's; a foreign process's
 * REP (same shared-code TB) is skipped here because vcpu_tb_ff_foreign
 * already added its whole decrement back.  udata = the REP's PC, keying
 * the facts to this instruction.  Off the fast-forward hot path by
 * construction: non-REP TBs never register it. */
static void vcpu_tb_ff_rep(unsigned int cpu_index, void *udata)
{
    if (qemu_plugin_rep_pc() == (uint64_t)(uintptr_t)udata &&
        qemu_plugin_rep_reenter() && !qemu_plugin_rep_chunk_boundary() &&
        qemu_plugin_u64_get(g_scoreboard.asid_match, cpu_index) != 0) {
        qemu_plugin_u64_add(g_scoreboard.budget, cpu_index, 1);
        g_stats.rep_ff_ticks_withheld++;
    }
}

/*
 * The `-cpu` argument this QEMU was started with, for the install refusal's
 * diagnosis only.  QEMU does not expose the RESOLVED model name to a plugin,
 * so this reports what the operator typed; a model that was defaulted by the
 * board says so instead of naming a value that might be wrong.  Never used
 * for a decision — the decision is qemu_plugin_identity_caps(), which asks
 * the resolved class itself.
 */
static const char *cmdline_cpu_option(void)
{
    static char model[64];
    static bool done = false;
    if (done) {
        return model[0] ? model : "(defaulted by the machine)";
    }
    done = true;
    FILE *f = fopen("/proc/self/cmdline", "r");
    if (f) {
        char buf[4096];
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        for (size_t i = 0; i + 1 < n; i++) {
            if (buf[i] != '\0' && (i == 0 || buf[i - 1] == '\0') &&
                strcmp(&buf[i], "-cpu") == 0) {
                const char *v = &buf[i + 5];
                if (v < buf + n && *v) {
                    snprintf(model, sizeof(model), "%s", v);
                }
                break;
            }
        }
    }
    return model[0] ? model : "(defaulted by the machine)";
}

/*
 * ASID-SWEEP WITNESS (the guest side of the rollover question).
 *
 * Ownership does NOT depend on this and never reads it.  A window is owned
 * by its PAGE-TABLE ROOT (x86 CR3, AArch64 TTBR0, RISC-V SATP, MIPS CP0
 * PWBase), which an operating system cannot re-point at a second LIVE
 * address space, so a narrow-ASID rollover is a non-event for attribution:
 * nothing re-binds, nothing is quarantined, nothing is dropped pending a
 * witness, and no instruction of the traced process is ever refused.
 *
 * What remains worth counting is whether a test that CLAIMS to have driven
 * the guest through an ASID rollover actually did.  That is a property of
 * the guest, not of the tracer, so it is measured on the guest's own
 * committed EntryHi.ASID write stream -- deliberately the RAW architectural
 * value and NOT the ownership key, so the witness stays independent of the
 * thing it corroborates.  Seeing every value of the space means the kernel
 * reissued every name; a cell that cannot show that has not exercised a
 * rollover and must FAIL as vacuous rather than pass quietly.
 *
 * A 1024-bit set (16 words, 128 bytes) covers the whole 10-bit Config4.AE
 * ASID space exactly, so the result is a true distinct-value count with no
 * threshold, no absence window and no saturation.  Maintained from the
 * committed-write hook, a context-switch-rate event off the per-TB path.
 */
static constexpr uint32_t ASID_SWEEP_BITS = 1024;
static std::atomic<uint64_t> g_asid_sweep_bits[ASID_SWEEP_BITS / 64];
static std::atomic<uint32_t> g_asid_sweep_count{0};

static void asid_sweep_reset(void)
{
    for (auto &w : g_asid_sweep_bits) {
        w.store(0, std::memory_order_relaxed);
    }
    g_asid_sweep_count.store(0, std::memory_order_relaxed);
    g_stats.asid_names_committed_since_pin = 0;
}

/* Note that the guest committed raw EntryHi.ASID value @raw.  A value wider
 * than the bitmap (which the architecture does not produce) folds, so the
 * count can only ever UNDER-report: a witness that cannot inflate.
 *
 * Relaxed atomics rather than a lock, because every vCPU's committed-write
 * hook reaches here and none of them holds exec_lock: the set-once
 * fetch_or/increment pair needs no ordering against anything else, and the
 * counter is only ever read for a report.  No new lock, and no race that
 * could double-count -- the bit decides. */
static void asid_sweep_note(uint64_t raw)
{
    uint32_t idx = (uint32_t)(raw % ASID_SWEEP_BITS);
    uint64_t bit = 1ULL << (idx & 63);
    uint64_t prev = g_asid_sweep_bits[idx >> 6].fetch_or(
        bit, std::memory_order_relaxed);
    if (prev & bit) {
        return;
    }
    g_stats.asid_names_committed_since_pin =
        g_asid_sweep_count.fetch_add(1, std::memory_order_relaxed) + 1;
}

static constexpr uint64_t PIN_PAGE_MASK = ~(uint64_t)0xFFF;

/*
 * PER-OWNED-ADDRESS-SPACE RECORD.
 *
 * Ownership keys on the ADDRESS SPACE — never on a thread, and never on the
 * code a process happens to be running.  g_owned holds QEMU process ids
 * (qemu_plugin_get_process_id), and this side table carries what an owned
 * space needs beyond bare membership:
 *
 *   @root_phys/@sig  the STABLE WIRE NAME of the space, kept deliberately
 *                    separate from the ownership key.  The wire names an
 *                    address space by a physical anchor plus a content
 *                    signature (marker_anchor / asid_root_to_index) so a
 *                    target whose architectural address-space value is 8
 *                    bits wide cannot churn the wire's asid index when the
 *                    OS renumbers it.
 *   @raw_asid        the architectural address-space value the window was
 *                    opened under — what the asid-keyed dedup index is
 *                    reclaimed by, and what stderr reports.
 *   @raw_asid_last   the last raw EntryHi.ASID value this space was seen
 *                    executing user code under, and @raw_asid_names how many
 *                    DISTINCT such values there have been.  Pure
 *                    instrumentation: an anti-vacuity witness for the
 *                    rollover tests, measured on the owned execution path,
 *                    consulted by no decision anywhere (see
 *                    owned_asid_names_seen).
 *
 * NO THREAD SET.  Ownership keys on the address space and nothing else, so
 * no ownership decision anywhere in the tracer reads a thread name.  That is
 * what closes the fork-forgery class by construction: fork() copies the
 * thread pointer verbatim, so a thread id can be forged by a child, but a
 * child gets a new mm and therefore a new page-table root, which cannot be.
 *
 * Guarded by exec_lock, like g_owned; immortal (see "Immortal process-wide
 * aggregates" in docs/architecture.rst).
 */
struct OwnedSpace {
    uint64_t root_phys = 0;
    uint64_t sig = 0;
    uint64_t raw_asid = 0;
    uint64_t raw_asid_last = 0;
    uint32_t raw_asid_names = 0;
    /*
     * The marker instruction's own code page — virtual page and the
     * physical page it translated to when the marker executed — kept as
     * the window's PROOF-OF-LIFE anchor for the dead-latch detector.
     *
     * The latch's design premise ("a dead process's page-table root is
     * never loaded again") is false on a real guest: Linux hands the
     * freed root page to the next fork, and QEMU's identity layer
     * interns the raw root VALUE, so the successor process reads as the
     * owned space and every schedule-in / owned-execution event it
     * produces is forged in the dead window's name.  Measured (cell
     * e1_idle_diag): the recycled root was re-stamped thousands of times
     * over 190 s while the pinned process was provably dead, holding the
     * idle below any threshold forever.
     *
     * What a successor CANNOT forge is this mapping: only the process
     * that executed the marker maps @marker_vpage to @marker_pphys (a
     * different binary maps other physical pages there or nothing at
     * all; the page itself outlives the process in the page cache, so
     * the compare stays meaningful).  A stamp refresh must present this
     * proof (deadlatch_live_probe).  Known accepted residual, shared
     * with the narrow-ASID dwell machinery: a second instance of the
     * SAME binary maps the same file page and passes.  0/0 (user mode,
     * or no usable physical anchor) disables the probe and keeps the
     * bare-membership refresh.
     */
    uint64_t marker_vpage = 0;
    uint64_t marker_pphys = 0;
};
static std::unordered_map<uint64_t, OwnedSpace> &g_owned_info =
    *new std::unordered_map<uint64_t, OwnedSpace>();

/* Record whether this target names a thread architecturally, once a real
 * address space has been pinned; see the definition below. */
static void pin_note_thread_naming(uint64_t asid, uint64_t tid);

/* The live ownership key and strand label for the executing vCPU.  Both are
 * opaque monotonic integers QEMU mints from the target's own architectural
 * registers; the plugin only ever compares them. */
static inline uint64_t live_process_id(void)
{
    return qemu_plugin_get_process_id();
}
static inline uint64_t live_thread_id(void)
{
    return qemu_plugin_get_thread_id();
}

/* A zero thread id for a REAL address space means strands inside the window
 * cannot be told apart by name.  Say so once, loudly, because a silently
 * coarse strand label is worse than a stated one.
 *
 * TWO DIFFERENT CAUSES, AND THE MESSAGE MUST NOT CONFLATE THEM.  A zero can
 * mean the CPU MODEL implements no thread-pointer register at all (a MIPS
 * model with Config3.ULRI clear), in which case no process on this guest will
 * ever be named; or it can mean THIS PROCESS has no TLS base installed —
 * every -nostdlib guest binary the validator generates is in that state, on
 * targets (arm, riscv, i386) whose models do implement the register.  Only
 * qemu_plugin_identity_caps() can tell them apart, and printing the model
 * diagnosis for the process case names a MIPS condition on an ARM guest and
 * sends a reader looking for a -cpu they cannot change.
 *
 * IT IS NOT AN OWNERSHIP PROBLEM AND NOTHING IS RETIRED, either way.
 * Ownership is the page-table root and never consults a thread name, so a
 * window with no thread identity traces exactly the same instructions as one
 * with it; only the per-strand labelling is coarser.  Caller holds
 * exec_lock. */
static void pin_note_thread_naming(uint64_t asid, uint64_t tid)
{
    static bool warned = false;
    if (asid == 0 || tid != 0) {
        return;                 /* user mode, or a real thread identity */
    }
    if (!warned) {
        warned = true;
        g_stats.pin_thread_identity_absent++;
        if (qemu_plugin_identity_caps() & QEMU_PLUGIN_IDENT_NAMES_THREAD) {
            fprintf(stderr,
                    "champsim_tracer: the pinned process has no thread "
                    "pointer installed (the CPU model implements one; this "
                    "process left it zero — a -nostdlib binary with no TLS, "
                    "or a kernel thread), so strands inside the window share "
                    "one label; ownership is unaffected — it keys on the "
                    "page-table root, not on a thread\n");
        } else {
            fprintf(stderr,
                    "champsim_tracer: this CPU model names no thread "
                    "architecturally (no thread-pointer register — a MIPS "
                    "model with Config3.ULRI clear), so strands inside the "
                    "window share one label; ownership is unaffected — it "
                    "keys on the page-table root, not on a thread\n");
        }
    }
}

/* The raw architectural address-space value @pid was opened under, for
 * human- and validator-readable reporting; 0 if unknown.  Caller holds
 * exec_lock. */
static inline uint64_t owned_raw_asid_locked(uint64_t pid)
{
    auto it = g_owned_info.find(pid);
    return it == g_owned_info.end() ? 0 : it->second.raw_asid;
}

/* @pid's record, or nullptr when it is not owned.  Caller holds exec_lock. */
static inline const OwnedSpace *owned_info_locked(uint64_t pid)
{
    auto it = g_owned_info.find(pid);
    return it == g_owned_info.end() ? nullptr : &it->second;
}

/* Note the raw architectural ASID value @raw the owned space @pid is
 * executing under.  INSTRUMENTATION ONLY — no ownership decision reads it.
 * A second distinct value means the guest renamed a live address space and
 * the trace kept following it, which is the independent witness the
 * rollover cells assert on.  Caller holds exec_lock. */
static inline void owned_note_raw_asid(uint64_t pid, uint64_t raw)
{
    auto it = g_owned_info.find(pid);
    if (it == g_owned_info.end() || it->second.raw_asid_last == raw) {
        return;
    }
    it->second.raw_asid_last = raw;
    if (++it->second.raw_asid_names >= 2 &&
        it->second.raw_asid_names > g_stats.owned_asid_names_seen) {
        g_stats.owned_asid_names_seen = it->second.raw_asid_names;
    }
}

/*
 * THERE IS NO RE-BIND RULE.
 *
 * The rule that used to live here followed the pin when a thread of an
 * owned address space reappeared under a name the trace did not own.  It
 * existed only because MIPS named an address space by an 8-bit
 * EntryHi.ASID, which Linux re-points at a DIFFERENT LIVE process on
 * rollover, so ownership had to be transferable.  It was measured unsound
 * and is now unnecessary, in that order:
 *
 *   unsound   — it rested on a thread pointer naming one thread of one
 *               address space, and fork() copies that pointer verbatim, so
 *               a forked child presents as "a thread of an owned space
 *               under an unowned name" and the pin walks onto it.  Caught
 *               in the act on the mipsel smp=4 migfault cell: the window
 *               crossed four address-space names and the owned user clock
 *               reached 146 M instructions for a 34 k workload.
 *   unnecessary — ownership now keys on the PAGE-TABLE ROOT (CP0 PWBase on
 *               MIPS, as CR3/TTBR0/SATP elsewhere), which an operating
 *               system cannot hand to a second live address space.  A
 *               rollover renames nothing the tracer looks at, so there is
 *               nothing to follow, nothing to transfer, and no evidence to
 *               forge.
 *
 * Everything it needed is gone with it: the thread set on OwnedSpace, the
 * claim/conviction machinery, the deferred verdicts and the quarantine.
 * Because no verdict is ever deferred, no TB of the traced process is ever
 * held back or dropped waiting for a witness, and an END marker can never
 * be swallowed by a suspended span.
 */

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

/* Full-system emulation (qemu_info_t::system_emulation, latched at
 * install).  Declared here because the guest-thread identity below is what
 * distinguishes the two emulation modes: system mode has one CPUState per
 * vCPU and must derive the thread from guest state, user mode has one per
 * guest thread and gets it for free. */
static bool g_system_mode;

/*
 * Guest-thread identity.
 *
 * The wire's thread_id names a GUEST thread, not the vCPU it happens to
 * run on: a thread that migrates across vCPUs keeps one identity, and two
 * threads time-slicing one vCPU are two identities.  The vCPU index (the
 * QEMU cpu_index) is a scheduling slot and never reaches the wire.
 *
 * In USER mode the two coincide by construction and nothing below runs:
 * qemu-user gives every guest thread its own CPUState (clone's CLONE_VM
 * path calls cpu_copy(), which cpu_create()s a vCPU and cpu_list_add()
 * hands it the next free index), so a "vCPU" there IS a guest thread and
 * cpu_index is a per-thread identifier, stable for that thread's whole
 * lifetime.  See resolve_thread_id() for the one boundary on that
 * equivalence.
 *
 * SYSTEM mode has to derive the identity, because one vCPU hosts every
 * thread the guest scheduler puts on it.  The kernel-maintained per-thread
 * pointer register (x86-64 FS.base, AArch64 TPIDR_EL0, MIPS CP0
 * UserLocal, and on RISC-V the kernel's current-task pointer, sscratch/tp
 * per the trap-entry swap — qemu_plugin_get_thread_ptr) is that identity:
 * every mainstream kernel reloads it from the incoming task at each context
 * switch.  A per-SEGMENT map assigns each distinct value a compact tid in
 * first-sighting order (0, 1, 2, …), so a single-threaded traced process is
 * always tid 0 regardless of vCPU, and the field width (small ints) is
 * never stressed.
 *
 * g_vcpu_cur_tid[c] tracks the identity of the task vCPU c is CURRENTLY
 * executing, sampled per TB and advanced AFTER the deferred-prev seal so an
 * emitted BB is attributed to the thread that executed it, not the one
 * about to run next.  Where the target reports
 * qemu_plugin_thread_ptr_tracks_current() the sample is taken at every
 * privilege level, which is what lets a task switch that happens entirely
 * inside the kernel be followed: a freshly cloned child finishing its
 * ret_from_fork before it has ever run a user instruction, a kernel thread
 * scheduled in on a borrowed mm, or a handler running after the scheduler
 * moved on.  Since plugin API v14 that includes RISC-V at S privilege (the
 * target reports the current-task pointer, one value space across U/S);
 * the answer is per-STATE, so it is re-asked at each privileged sample —
 * M-mode firmware and H-extension virtualization stay untrusted, and
 * kernel code there inherits the thread that entered on that vCPU — see
 * the KERNEL-STRAND note in docs/limitations.rst.  Both structures are guarded by
 * exec_lock (every sample and every emit runs under it) and reset per
 * segment.
 *
 * Degradation, documented: a target/model whose thread pointer is never
 * written (no MIPS Config3.ULRI, a guest that sets no TLS) reports 0 for
 * every thread, so all threads collapse to tid 0 — honest indistinctness,
 * not fabricated identity.  Kernel threads, which carry no TLS pointer,
 * likewise share the tid minted for the value 0.
 */
static std::unordered_map<uint64_t, uint32_t> *g_thread_tid_map;
static uint32_t g_thread_tid_next = 0;
static uint32_t g_vcpu_cur_tid[CST_PIN_MAX_VCPUS];

/* Per-vCPU self-loop accounting (see RepSelfLoopState).  The clamp mirrors
 * the rest of this family: an implausibly high vCPU index folds onto the last
 * slot rather than running off the array. */
RepSelfLoopState g_rep_state[CST_PIN_MAX_VCPUS];
RepSelfLoopState &rep_state(unsigned int cpu_index)
{
    return g_rep_state[cpu_index < CST_PIN_MAX_VCPUS
                       ? cpu_index : CST_PIN_MAX_VCPUS - 1];
}

/* Per-vCPU wrong-path session bracket (see champsim_tracer_wp_thread_state.h;
 * written by wp_enter/wp_end_spec_session in champsim_tracer_wp.cc). */
std::atomic<bool> g_wp_session_vcpu[CST_PIN_MAX_VCPUS];

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
 * thread_id distinguishes the software threads WITHIN an owned process
 * (see docs/architecture.rst, "Address-space scope and per-thread
 * attribution").  Clean per-thread attribution therefore relies on the
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

/* The step's identity sample, taken BEFORE the seal and applied AFTER it.
 *
 * The seal needs both halves of the boundary at once: it EMITS the deferred
 * prev, which belongs to the thread the vCPU was running before this TB
 * (g_vcpu_cur_tid, still the committed value), and it STAMPS the executing
 * TB's fault depth, which belongs to the thread running now.  Sampling once
 * into these slots gives the seal the incoming identity without disturbing
 * the outgoing one; thread_identity_commit then advances g_vcpu_cur_tid at
 * exactly the point the refresh always happened.  Byte-inert: the mapping
 * (thread_ptr_to_tid, first-sighting order) is unchanged and nothing between
 * the sample and the commit reads the map. */
static uint64_t g_vcpu_pending_tp[CST_PIN_MAX_VCPUS];
static uint32_t g_vcpu_pending_tid[CST_PIN_MAX_VCPUS];
static bool     g_vcpu_pending_tid_valid[CST_PIN_MAX_VCPUS];

/*
 * Kernel-entry identity alias (the thread-identity ruling, part a).
 *
 * The maintainer's model: a context is a THREAD — kernel code running on a
 * separate task (kswapd, ksoftirqd, a per-CPU idle) is a separate thread
 * with its own id, and kernel code that takes over a thread keeps that
 * thread's id.  The identity registers deliver the first half directly on
 * targets whose kernel keeps a per-task pointer readable in kernel mode
 * (RISC-V tp/sscratch, arm64 SP_EL0, MIPS $28): distinct tasks yield
 * distinct values, so kernel threads mint distinct tids.  The second half
 * needs this arrow for the one identity the registers CANNOT join: a
 * TLS-less user thread reads thread-pointer 0 at user privilege but its
 * task pointer in the kernel, two different raw values for ONE program
 * path.  The join is provable exactly at the exception edge: a
 * user->kernel transition on one vCPU can only be an exception taken by
 * the running thread, so the first task value the kernel run resolves
 * names the ENTERING thread — alias it to that thread's tid instead of
 * minting, and the thread's kernel excursions keep its id.
 *
 * pending is armed at every user-privilege sample and consumed by the
 * first RESOLVED kernel sample; unresolvable kernel samples (the
 * entry-window TBs before the kernel installs its task pointer) pass
 * through with a bounded budget, so on a target with no kernel task
 * source at all (x86-64, which reaches `current` only through a
 * link-time percpu offset) the arm expires instead of aliasing some
 * later excursion's first value.  Hazard, documented: the guest
 * recycling a task_struct/stack does not re-key the per-segment map, so
 * a recycled task address inherits the dead thread's tid until the next
 * segment or its own re-alias (last-writer-wins).
 */
static bool     g_vcpu_alias_pending[CST_PIN_MAX_VCPUS];
static uint8_t  g_vcpu_alias_budget[CST_PIN_MAX_VCPUS];
static constexpr uint8_t CST_ALIAS_KSAMPLE_BUDGET = 8;

/* CST_TIDDIAG accounting for the kernel-privilege sample's effect on the
 * wire.  g_vcpu_user_tid[c] is what vCPU c's identity WOULD be if only
 * user-privilege samples were trusted — the attribution rule before the
 * kernel-strand sample, and still the live rule on a target that reports
 * no qemu_plugin_thread_ptr_tracks_current().  Comparing it against the
 * emitted thread_id per entry says exactly which entries the kernel sample
 * re-attributed, and at which privilege, in ONE run: a full-system boot is
 * not reproducible across processes, so a two-run decode diff cannot
 * isolate the change.  Diagnostic only; never consulted by the wire. */
static uint32_t g_vcpu_user_tid[CST_PIN_MAX_VCPUS];
static uint64_t g_tiddiag_kern_retagged;
static uint64_t g_tiddiag_user_retagged;
static uint64_t g_tiddiag_kern_entries;
static uint64_t g_tiddiag_user_entries;

/* CST_TIDDIAG: stderr-only thread-identity diagnostics, never wire content.
 *
 *   1  the (thread_ptr -> tid) and (vcpu <-> tid) bindings, so an offline
 *      check can confirm the wire's tid is decoupled from the vCPU (one tid
 *      spanning vCPUs = migration; two tids on one vCPU = time-slice), plus
 *      the end-of-run kernel-strand re-attribution tally.
 *   2  additionally every transition of the thread-pointer register as seen
 *      on each vCPU, at whatever privilege — the bring-up probe for "does
 *      this target's register discriminate KERNEL strands?".
 */
static int tiddiag_level(void)
{
    static int lvl = -1;
    if (lvl < 0) {
        const char *s = getenv("CST_TIDDIAG");
        lvl = s ? (s[0] >= '1' && s[0] <= '9' ? s[0] - '0' : 1) : 0;
    }
    return lvl;
}

static bool tiddiag_on(void)
{
    return tiddiag_level() > 0;
}

/* CST_TID2_DIAG: stderr-only condition instrument for the SMP async-owner
 * work — which vCPU mints identities when, and which vCPU receives async
 * interrupts in whose context.  Never wire content. */
static bool tid2diag_on(void)
{
    static const bool v = getenv("CST_TID2_DIAG") != nullptr;
    return v;
}

/* CST_TIDDIAG=2: trace every transition of the thread-pointer register as
 * sampled on THIS vCPU, at whatever privilege the TB runs at, so an offline
 * check can answer whether the register discriminates KERNEL strands (a
 * kthread, a handler running after an in-kernel switch) from the user thread
 * that entered.  Diagnostic only — nothing here reaches the wire, and the
 * attribution path still samples at user privilege. */
static void tiddiag_probe_ktp(unsigned int cpu_index, int priv, uint64_t pc)
{
    static uint64_t last[CST_PIN_MAX_VCPUS];
    static bool primed[CST_PIN_MAX_VCPUS];
    static unsigned budget = 3000;      /* a wandering guest can switch a lot */
    if (cpu_index >= CST_PIN_MAX_VCPUS) {
        return;
    }
    uint64_t tp = qemu_plugin_get_thread_ptr();
    if (primed[cpu_index] && last[cpu_index] == tp) {
        return;
    }
    primed[cpu_index] = true;
    last[cpu_index] = tp;
    if (budget-- == 0) {
        return;
    }
    fprintf(stderr, "champsim_tracer: [tiddiag] ktp vcpu=%u priv=%d "
            "tp=0x%" PRIx64 " pc=0x%" PRIx64 "\n", cpu_index, priv, tp, pc);
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

/* Whether the thread pointer still names the executing software thread in
 * the vCPU's CURRENT state.  Deliberately NOT latched: since plugin API v14
 * the answer is a property of the sampling context, not of the target —
 * RISC-V reports true at U/S privilege (where the reported value is the
 * kernel's current-task pointer) but false in M-mode firmware and under
 * H-extension virtualization.  Called only on privileged samples (user
 * privilege short-circuits in thread_ptr_sample), from a vCPU context. */
static bool thread_ptr_tracks_current(void)
{
    return qemu_plugin_thread_ptr_tracks_current();
}

/* Read the guest-thread pointer for the vCPU running at @live_priv, into
 * @tp.  Returns false when the register cannot be trusted at that
 * privilege — i.e. above user privilege on a target whose kernel entry
 * repurposes it — in which case the caller must leave the vCPU's current
 * identity alone and let kernel code inherit the entering thread. */
static bool thread_ptr_sample(int live_priv, uint64_t *tp)
{
    if (live_priv != 0 && !thread_ptr_tracks_current()) {
        return false;
    }
    *tp = qemu_plugin_get_thread_ptr();
    return true;
}

/* Map a guest thread-pointer value to its compact per-segment tid
 * (first-sighting order).  Caller holds exec_lock and has established the
 * value was sampled at a privilege where it names the current task
 * (thread_ptr_sample). */
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
    if (tid2diag_on() && g_pin_user_vcpu_mask != before) {
        fprintf(stderr, "champsim_tracer: [tid2] PINUSER vcpu=%u\n",
                cpu_index);
    }
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
        g_vcpu_user_tid[i] = 0;
        g_vcpu_cur_asid_index[i] = 0;
        g_vcpu_last_tp[i] = CST_TP_UNSEEN;
        g_vcpu_pending_tid_valid[i] = false;
        g_vcpu_alias_pending[i] = false;
        g_vcpu_alias_budget[i] = 0;
    }
    g_pin_user_vcpu_mask = 0;
    g_pin_multivcpu_warned = false;
}

/* The thread_id stamped on an emitted body entry — always a guest-thread
 * identifier, never a vCPU index.
 *
 * SYSTEM mode (pinned or not) resolves the identity the guest-thread map
 * minted for the task the vCPU is currently executing.  It is deliberately
 * NOT conditioned on the pin: an unpinned system trace (trace-all, or a
 * plain icount window with no marker) runs many threads on each vCPU, so
 * returning cpu_index there would stamp every thread on vCPU N with the
 * same id and hand the consumer the scheduling slot the format promises it
 * will never see.
 *
 * USER mode returns cpu_index, and that value already satisfies the
 * contract rather than escaping it: qemu-user creates a CPUState per guest
 * thread (clone/CLONE_VM -> cpu_copy -> cpu_create -> cpu_list_add), so the
 * index is a per-guest-thread tag, held for the thread's entire lifetime,
 * with no scheduler multiplexing behind it.  One boundary, and it is the
 * only one: cpu_list_remove() releases the index when a thread exits and
 * cpu_get_free_index() may hand the same number to a thread created later,
 * so ids are unique among threads that are alive together (which is what a
 * consumer keying per-thread state needs) but may be reused across a
 * thread's death.  The guest-thread map is not used here because the
 * identity is already exact and because minting fresh values would change
 * every user-mode trace byte-for-byte for no gain in meaning. */
static inline uint32_t resolve_thread_id(unsigned int cpu_index)
{
    if (g_system_mode && cpu_index < CST_PIN_MAX_VCPUS) {
        return g_vcpu_cur_tid[cpu_index];
    }
    return (uint32_t)cpu_index;
}

/*
 * Sample the guest-thread identity of the TB executing NOW and return it,
 * holding the advance in the pending slot for thread_identity_commit.
 *
 * The seal phase needs this value to attribute fault frames per guest thread:
 * a fault frame belongs to the thread that was inside the handler, and the
 * depth stamped on the executing TB counts only ITS OWN thread's frames.
 * resolve_thread_id cannot supply it — the committed identity is still the
 * previous TB's, deliberately, so the block the seal emits carries the thread
 * that ran it.  Caller holds exec_lock (the map mint below mutates it).
 */
static uint32_t thread_identity_sample(unsigned int cpu_index, int live_priv)
{
    if (!g_system_mode || cpu_index >= CST_PIN_MAX_VCPUS) {
        /* User mode: qemu-user gives every guest thread its own CPUState, so
         * the index IS the thread (see resolve_thread_id). */
        return (uint32_t)cpu_index;
    }
    g_vcpu_pending_tid_valid[cpu_index] = false;
    uint64_t tp;
    bool resolved = thread_ptr_sample(live_priv, &tp);
    /* Kernel-entry alias arming (see the declaration): every user sample
     * (re)arms; the first resolved kernel sample consumes; an unresolvable
     * kernel sample burns budget so a target with no kernel task source
     * expires the arm instead of aliasing a later excursion's first
     * value. */
    if (live_priv == 0 && resolved) {
        g_vcpu_alias_pending[cpu_index] = true;
        g_vcpu_alias_budget[cpu_index] = CST_ALIAS_KSAMPLE_BUDGET;
    } else if (live_priv != 0 && !resolved &&
               g_vcpu_alias_pending[cpu_index]) {
        if (g_vcpu_alias_budget[cpu_index] == 0 ||
            --g_vcpu_alias_budget[cpu_index] == 0) {
            g_vcpu_alias_pending[cpu_index] = false;
            g_stats.tid_alias_expired++;
        }
    }
    if (resolved && tp != g_vcpu_last_tp[cpu_index]) {
        uint32_t tid;
        uint32_t next_before = g_thread_tid_next;
        if (live_priv != 0 && g_vcpu_alias_pending[cpu_index] &&
            (!g_thread_tid_map || g_thread_tid_map->count(tp) == 0)) {
            /* First task value resolved by a user-entered kernel run, never
             * seen before: it names the ENTERING thread (the exception was
             * taken by the thread that was running), so it aliases to that
             * thread's tid rather than minting — kernel-on-behalf keeps the
             * thread's id even where the raw register value changes at the
             * privilege boundary (a TLS-less thread: 0 in user, the task
             * pointer in kernel). */
            if (!g_thread_tid_map) {
                g_thread_tid_map =
                    new std::unordered_map<uint64_t, uint32_t>();
            }
            tid = g_vcpu_cur_tid[cpu_index];
            g_thread_tid_map->emplace(tp, tid);
            g_stats.tid_task_aliased++;
            if (tiddiag_on() || tid2diag_on()) {
                fprintf(stderr, "champsim_tracer: [tiddiag] entry-alias: "
                        "task=0x%" PRIx64 " -> tid=%u (vcpu=%u)\n",
                        tp, tid, cpu_index);
            }
        } else {
            tid = thread_ptr_to_tid(tp);
            if (live_priv != 0 && g_thread_tid_next != next_before) {
                /* A kernel-resolved task value minting fresh: a task with
                 * no user identity to join — a kernel thread's own strand. */
                g_stats.tid_kernel_task_minted++;
            }
        }
        if (tid2diag_on() && g_thread_tid_next != next_before) {
            fprintf(stderr, "champsim_tracer: [tid2] MINT vcpu=%u priv=%d "
                    "tp=0x%" PRIx64 " tid=%u\n",
                    cpu_index, live_priv, tp, tid);
        }
        if (live_priv != 0) {
            g_vcpu_alias_pending[cpu_index] = false;   /* consumed */
        }
        g_vcpu_pending_tp[cpu_index] = tp;
        g_vcpu_pending_tid[cpu_index] = tid;
        g_vcpu_pending_tid_valid[cpu_index] = true;
        return tid;
    }
    if (resolved && live_priv != 0) {
        /* Resolved and unchanged (a TLS-ful thread whose kernel identity is
         * its user value): the join is already the identity map's, and the
         * arm is consumed. */
        g_vcpu_alias_pending[cpu_index] = false;
    }
    /* Unchanged, or a privilege where the register does not name the current
     * task (RISC-V M-mode, an unresolvable entry window): the strand keeps
     * the entering thread. */
    return g_vcpu_cur_tid[cpu_index];
}

/*
 * Read-only twin of thread_identity_sample: the guest-thread identity of the
 * TB executing NOW, resolved WITHOUT minting a map entry and WITHOUT touching
 * the pending slot.
 *
 * The PRE-WINDOW phase needs a usable thread id.  PathBuilder::step_events
 * applies the async-window arrows there, and the depth level a captured
 * window contributes belongs to the thread the interrupt was delivered in
 * (format.rst §4.2a) — a fact only that step knows, because the step carrying
 * the ASYNC_ENTER is routinely dropped or suspended long before any seal runs.
 *
 * thread_identity_sample cannot be moved that early.  It MINTS: thread_ptr_to_
 * tid bumps g_thread_tid_next on a first sighting, and the pre-window phase
 * runs on steps that bail (foreign ASID, async suspension, segment open), so
 * minting there would allocate ids for threads the trace never emits and
 * renumber every thread_id on the wire.  This twin only LOOKS UP, so it is
 * byte-inert; an unsighted thread pointer resolves to CST_TID_UNSEEN rather
 * than to a fresh id, which keeps an unattributable async level dormant
 * instead of letting the next thread borrow it.  Every other case returns
 * exactly what thread_identity_sample would.  Caller holds exec_lock.
 */
static uint32_t thread_identity_peek(unsigned int cpu_index, int live_priv)
{
    if (!g_system_mode || cpu_index >= CST_PIN_MAX_VCPUS) {
        return (uint32_t)cpu_index;
    }
    uint64_t tp;
    if (!thread_ptr_sample(live_priv, &tp) ||
        tp == g_vcpu_last_tp[cpu_index]) {
        return g_vcpu_cur_tid[cpu_index];
    }
    if (g_thread_tid_map) {
        auto it = g_thread_tid_map->find(tp);
        if (it != g_thread_tid_map->end()) {
            return it->second;
        }
    }
    return PathBuilder::CST_TID_UNSEEN;
}

/* Apply the pending sample: this vCPU's identity advances AFTER the deferred
 * prev has been sealed, so the just-emitted BB is attributed to the thread
 * that executed it and the refresh takes effect for the NEXT emit.  Caller
 * holds exec_lock. */
static void thread_identity_commit(unsigned int cpu_index, int live_priv)
{
    if (!g_system_mode || cpu_index >= CST_PIN_MAX_VCPUS) {
        return;
    }
    if (g_vcpu_pending_tid_valid[cpu_index]) {
        g_vcpu_pending_tid_valid[cpu_index] = false;
        g_vcpu_last_tp[cpu_index] = g_vcpu_pending_tp[cpu_index];
        g_vcpu_cur_tid[cpu_index] = g_vcpu_pending_tid[cpu_index];
        if (tiddiag_on()) {
            tiddiag_note_binding(cpu_index, g_vcpu_cur_tid[cpu_index]);
        }
    }
    if (tiddiag_on() && live_priv == 0) {
        g_vcpu_user_tid[cpu_index] = g_vcpu_cur_tid[cpu_index];
    }
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
    (void)cpu_index;
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

/*
 * DYNAMIC PRECONDITION: the guest must have PROGRAMMED the root register.
 *
 * The install refusal proved the CPU MODEL implements a page-table-root
 * register; this proves the GUEST filled it in.  A MIPS kernel booted with
 * "nohtw", built CONFIG_MIPS_HTW=n, or one that declined the walker after
 * checking PTEI (dmesg: "Unsupported PTEI field value ... HTW will not be
 * enabled") leaves CP0 PWBase at 0, and QEMU's identity layer refuses to
 * intern 0 into an id — 0 is an ABSENCE, not a name.  Opening a window on it
 * would silently pool every address space in the guest under one id.
 *
 * This REFUSES TO OPEN.  It runs at the first START marker, before the space
 * joins the owned set and before a segment exists, so no byte has been
 * written and no window is being retired mid-capture.  Terminates non-zero
 * through _exit() so nothing half-written is flushed behind it.
 * Caller holds exec_lock.
 */
static void marker_refuse_no_root(void)
{
    fprintf(stderr,
        "champsim_tracer: refusing to open the trace window — the guest has "
        "not\nprogrammed CP0 PWBase.  The hardware page-table walker is off "
        "(\"nohtw\" on\nthe kernel command line, CONFIG_MIPS_HTW=n, or the "
        "kernel declined it;\ncheck dmesg for \"Hardware Page Table Walker "
        "enabled\").  Without it there\nis no architectural name for this "
        "address space.  No trace is written.\n");
    fflush(stderr);
    _exit(CST_NO_ROOT_EXIT);
}

/*
 * Ownership of a user-privilege TB under an armed pin — the ONE rule every
 * consumer (user clock, foreign gate, kexc ownership seed, stuck-window
 * recovery, end marker) shares.
 *
 * WE PIN ON A MARKER WITHIN AN ADDRESS SPACE, NOT A THREAD.  @live_pid is
 * QEMU's opaque id for the address space this vCPU is translating through —
 * interned from the PAGE-TABLE ROOT the hardware walks — and the TB is ours
 * exactly when that space is in the owned set.  So EVERY THREAD INSIDE AN
 * OWNED ADDRESS SPACE IS TRACED, including one the trace has never seen
 * before, and NOTHING ELSE IS.  @live_tid only labels the strand; no
 * ownership decision reads it, which is what makes the rule immune to
 * fork()'s verbatim copy of the thread pointer.
 *
 * The verdict is final at the instant it is taken: there is no re-bind, no
 * deferral, no quarantine and no pending witness, so an owned TB is never
 * withheld and a foreign TB is never provisionally admitted.  That is why
 * pin_unverified_dropped can be quoted as-is — every count is a genuinely
 * foreign user TB, not the traced process's own work awaiting confirmation.
 * Caller holds exec_lock.
 */
static bool pin_user_tb_owned(unsigned int cpu_index, uint64_t live_pid,
                              uint64_t live_tid)
{
    (void)cpu_index;
    (void)live_tid;
    bool owned = owned_contains_locked(live_pid);
    if (!owned) {
        /* Not an address space this trace owns.  This counter IS the drop
         * path: a zero over a run with foreign execution in it means the
         * check never ran. */
        g_stats.pin_unverified_dropped++;
        return false;
    }
    /* Anti-vacuity witness, instrumentation only (see owned_note_raw_asid):
     * the exhaustible TLB tag the owned space is executing under RIGHT NOW.
     * Read here, on the owned execution path, and after the verdict, so it
     * depends on no ownership decision and cannot be a sub-event of the
     * thing it is claimed to witness. */
    owned_note_raw_asid(live_pid, qemu_plugin_get_narrow_asid());
    return true;
}


/*
 * Recompute this vCPU's context gate (trace_this_ctx) from the live
 * segment-active flag and stamp it into the scoreboard.  This is the
 * single event-driven maintainer — called at every is_active edge and at
 * each committed address-space write — so the heavy per-TB callback is
 * gated by ONE JIT-testable slot instead of a runtime decision.
 *
 * The gate is a bare is_active mirror on every supported target: an
 * address space is named by its page-table root (x86 CR3, AArch64 TTBR0,
 * RISC-V SATP, MIPS CP0 PWBase), a reliable per-process id, so ownership
 * is decided by set membership inside the heavy step and no context has
 * to be gated out of dispatch to keep the attribution honest.
 */
static inline void refresh_ctx_gates(unsigned int cpu_index)
{
    bool active = qemu_plugin_u64_get(g_scoreboard.is_active, cpu_index) != 0;
    qemu_plugin_u64_set(g_scoreboard.trace_this_ctx, cpu_index,
                        active ? 1 : 0);
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
    /*
     * Leaked-fence tripwire, SECOND test point — see the first in
     * events_path_step.  That one runs on the correct-path STEP, which the
     * JIT dispatches only for a context this trace owns while a segment is
     * active (vcpu_tb_exec is a cond_cb gated on trace_this_ctx, and the
     * pinned-simpoint fast-forward returns ahead of it).  A bracket leaked
     * on a vCPU that then stops running owned code would therefore go
     * unseen there while it silently fenced every marker callback on that
     * vCPU — which is how a window stays open forever.
     *
     * A committed address-space write is the one correct-path event that
     * fires REGARDLESS of ownership, of the window, and of the
     * fast-forward, so testing it here makes the counter's claim — the
     * session flag was set while this vCPU ran the correct path — true of
     * the whole class rather than of the traced window only.  One relaxed
     * load per context switch.  The wrong path is excluded by the same two
     * gates the marker fence trusts: QEMU's own spec-mode flag, and this
     * host thread's walker flag (the walker is synchronous).
     */
    if (!qemu_plugin_in_spec_mode() && !g_wp_in_progress &&
        wp_session_active(vcpu_index)) {
        g_stats.wp_session_on_cp++;
    }
    uint64_t pinned = g_pinned_asid.load(std::memory_order_relaxed);
    /*
     * The address space this vCPU has just switched into, as QEMU's opaque
     * process id.  The core samples the identity at this same commit point
     * before calling us, so the id is already the NEW space.  Ownership is
     * set membership and nothing else: off the per-TB hot path (this fires
     * once per context switch), so taking exec_lock — the guard every
     * mutation of g_owned holds — is cheap and race-free.
     */
    g_rec_mutex_lock(&exec_lock);
    uint64_t pid = live_process_id();
    uint64_t match = owned_contains_locked(pid) ? 1 : 0;
    g_rec_mutex_unlock(&exec_lock);
    qemu_plugin_u64_set(g_scoreboard.asid_match, vcpu_index, match);
    if (pinned != CST_ASID_UNPINNED && vcpu_index < CST_PIN_MAX_VCPUS) {
        /* A committed address-space write is exactly when the JIT-visible
         * context gate can change, so it is settled HERE, off the per-TB
         * path. */
        refresh_ctx_gates(vcpu_index);
    }

    /* Guest-side sweep witness, instrumentation only.  Deliberately the RAW
     * exhaustible TLB tag, NOT @new_asid (which is the page-table root the
     * ownership key is interned from): the witness has to be independent of
     * the key it corroborates, or a test that "proves" a rollover is only
     * restating its own premise.  Nothing here can change what is traced. */
    asid_sweep_note(qemu_plugin_get_narrow_asid());

    /* Dead-latch detector: this hook is the one place every committed root
     * write is visible, so a live process's root passes through here at each
     * schedule-in.  Sweep the owned roots for one that has gone stale (its
     * process died without an END marker).  Off the per-TB hot path.  The
     * mode/policy gate lives inside (g_window_mode is declared below). */
    if (deadlatch_configured()) {
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
 * current owning (thread_id, asid) and push it onto @vcpu_index's own
 * bounded kick FIFO (keyed by the KICKING vCPU, one producer per FIFO)
 * for a later note_start — on any thread, matched by @dev_token in kick
 * order — to attribute exactly.  See the DEVIO comment block in
 * champsim_tracer_output.cc for why a per-vCPU FIFO, not a per-device
 * one or a single per-vCPU slot.
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
 * Attribution: EXACT when @vcpu_index's own kick FIFO still holds a
 * queued kick to this same device (@dev_token) — note_start matches the
 * oldest such entry in THAT vCPU's FIFO (the vCPU actually draining its
 * virtqueue right now, which disambiguates two vCPUs' separate queues
 * sharing one device token; only widened to every FIFO when @vcpu_index
 * itself is unknown) and stamps that kick's owner on the record.
 * POSITIONAL fallback when no matching kick is found (non-virtio,
 * IDE/AHCI, kernel-internal I/O, or a kick dropped by the FIFO's
 * overflow guard): the record carries no owner and the consumer uses
 * its stream-position context, as before.
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

/* CST diag correlation: the seq_num of the most recent body entry emitted
 * process-wide, so the per-step depth diag can be tied to a wire position.
 * Plain static like the other g_dbg_* mirrors: every writer runs under
 * exec_lock, which orders it exactly as the body stream it describes. */
uint64_t g_dbg_last_emit_seq = 0;

/* ---- SMP attribution-pair instrument (Stats::smp_*) --------------------
 *
 * Emit-site provenance for the per-thread claim ledger in emit_body_entry:
 * every emission call site names itself so a duplicate claim's report says
 * WHICH two mechanisms produced the two claims (the ordinary seal, a cut,
 * a fault prefix, a continuation, a close-time flush, a departure).  A
 * plain global, not TLS (the static-TLS budget is spent — see the
 * CST_JUMP_DIAG block above); every writer runs under exec_lock. */
const char *g_cst_emit_site = "seal";
/* The vCPU a segment close is executing on while its flush hook runs, or
 * UINT32_MAX outside a close.  Read by PathBuilder::flush_final to
 * classify PEER-slot extents (stash vs live cursor). */
unsigned int g_cst_closing_cpu = UINT32_MAX;

bool cst_smp_diag(void)
{
    static const bool v = getenv("CST_SMP_DIAG") != nullptr;
    return v;
}

/* CST_JUMP_DIAG mirrors (see champsim_tracer_path_builder.h): the depth
 * pipeline's provenance, published so the online step-discipline assertion
 * in emit_body_entry can name the code path that stamped the depth. */
uint8_t  g_dbg_depth_src = CST_DSRC_NONE;
uint8_t  g_dbg_prev_depth_src = CST_PDSRC_NONE;
uint8_t  g_dbg_walk_depth_src = CST_PDSRC_NONE;
uint32_t g_dbg_raw_depth = 0;
uint32_t g_dbg_inflight = 0;
uint32_t g_dbg_async_captured = 0;
uint32_t g_dbg_depth_next = 0;
uint32_t g_dbg_prev_depth = 0;
uint32_t g_dbg_walk_depth = 0;
size_t   g_dbg_frames = 0;

/* Anchors (faulting-insn indices) for the whole-BB merge emit currently in
 * flight; read by emit_body_entry into the entry's fault trailer. */

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
 * no active in-flight chain.
 *
 * The three deferred-close flags below are PER-vCPU (one struct array,
 * accessor-clamped like every per-vCPU array here): the arm is raised
 * by the vCPU whose budget crossed and must be consumed at that SAME
 * vCPU's next steps — its chain, its pending-seal slot.  They were
 * thread_local, which round-robin TCG breaks: the next dispatch on the
 * one host thread may belong to a different vCPU, which would run the
 * close against the wrong chain. */
struct VcpuDeferredClose {
    bool icount_shutdown_pending = false;
    bool simpoint_close_pending = false;
    bool window_close_armed = false;
    /* The END marker fired on this vCPU and the capture is running out
     * the marker's own true BB before it closes (see
     * marker_close_and_exit).  Unlike the two above this needs no second
     * armed step: the marker's block has already executed when the arm is
     * raised, so the first boundary the arm survives to IS the end of the
     * END-marker BB, and one step more would put a block PAST the END on
     * the wire. */
    bool end_close_pending = false;
};
static VcpuDeferredClose g_deferred_close[CST_PIN_MAX_VCPUS];

/*
 * Has an END marker already claimed the close?  The arm above is per-vCPU
 * because the block it runs out is on the marker's own vCPU; this is the
 * process-wide "the END has been seen" latch, and it is what makes the
 * close non-re-entrant — a second END sequence, or the same one re-reached
 * through the unowned-END path, finds the stop already owned and adds
 * nothing.
 *
 * The DEFERRAL is what makes it load-bearing.  A synchronous close cannot
 * be re-entered (the first caller never returns), so under that design the
 * latch guarded nothing; here the guest keeps executing between the arm and
 * the block boundary the take waits for, and every END path reachable in
 * that gap has to find the stop owned.  Its second reader — the simpoint
 * take — is the same window seen from a peer vCPU.
 *
 * Both accesses are made with exec_lock held, so the atomicity is
 * belt-and-braces rather than load-bearing today; it is spelled as an
 * atomic so the claim cannot be split if a later reader takes it off the
 * lock.  (An earlier comment here named a marker-fence diagnostic as such
 * a reader.  There is none — the fence census counts callback invocations
 * and never consults this latch — so the claim is stated as it is.)
 */
static std::atomic<bool> g_end_close_claimed{false};

static VcpuDeferredClose &deferred_close(unsigned int cpu_index)
{
    return g_deferred_close[cpu_index < CST_PIN_MAX_VCPUS
                            ? cpu_index : CST_PIN_MAX_VCPUS - 1];
}

/* Simpoint analogue of g_icount_shutdown_pending: tw_manage_window
 * detects icount_prev >= window_stop optimistically (counter bumped
 * by the current TB), but the chain assembler may still hold
 * fragments waiting for a branch terminator.  Closing here would
 * truncate the trace below the requested simulation_insns; defer
 * the actual finish_trace_segment / g_simpoints.advance to a
 * vcpu_tb_exec tail when has_active_chain() is false (= at a true-BB
 * boundary).  Each bumped insn then either makes it into the trace
 * or never triggered the bump in the first place. */

/* One-step arm shared by both deferred window closes.  The crossing is
 * detected at TB-START with the dispatching TB's instructions already
 * folded into icount, so that TB must be emitted for the trace to cover
 * the requested window — but at the tail of the step that detects the
 * crossing it has not RUN yet: step_events has only just promoted it into
 * the pending-seal slot, its memory callbacks have not fired, and its dst
 * registers have not been snapped.  Closing there emitted it through
 * flush_final against empty accumulators, which is how the segment's last
 * body entry came to carry no memop records and no register deltas at all
 * (the "CP reg-snap slice dropped" counter reads 1 per segment).
 *
 * So the first satisfied visit only arms; the close runs at the tail of
 * the NEXT step, by which time that TB has executed and the ordinary seal
 * walk has emitted it exactly like every other entry — memops, register
 * deltas, resolved terminal branch, wrong path.  The now-pending slot at
 * that point is the next dispatching TB, which flush_final must not walk
 * (path_builder_flush_final_chain_only).  Cleared at segment open and
 * whenever the pending condition lapses. */

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

/* Total sub-entries emitted by self-loop fan-out (sum of (n_iter - 1)
 * across every emit_body_entry call that fanned out) — x86 REP string
 * ops and AArch64 FEAT_MOPS bulk copy/set alike.  Each sub-entry uses
 * the 1-insn rep_subtmpl, so this counter is the architectural insns
 * the trace contains BEYOND the per-TB-exec inline_add count, scoped
 * to in-segment because emit_body_entry only runs when a trace stream
 * is open.
 *
 * Its scale is per FAN-OUT UNIT, which is per family: an x86 iteration
 * is an architectural element, a MOPS iteration is one memory access.
 * A megabyte memcpy on a FEAT_MOPS guest therefore contributes ~65K
 * here off a single instruction, which is what the trace genuinely
 * contains and what any icount-derived quantity must be read against. */
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

/* ================== Guest realtime factor: instrument + gate ==============
 *
 * WHAT IT MEASURES.  qemu_plugin_vclock_ns() reads the clock the GUEST reads:
 * host wall time minus every interval the tracer had it frozen.  Two ratios
 * come out of it, answering different questions:
 *
 *   factor = d(guest ns) / d(host ns)
 *       how much guest time the guest is charged per second of host time.
 *
 *   R_g    = d(arch insns) / d(guest seconds)
 *       how many instructions the guest gets to retire per guest-second.
 *       Reported as insn_per_guest_s, and paired with the exact retired
 *       count (segment_insns) so a consumer never has to invert the rate.
 *
 * WHAT R_g DOES NOT TELL YOU.  It is a rate, and no rate has ever been shown
 * to select the system-mode stall this tracer can enter (the traced process
 * alive in the kernel, retiring tens of millions of instructions without one
 * user-space instruction).  Measured over the 3,838-cell wrong-path-necessity
 * corpus, R_g in stalled captures is not depressed but slightly ELEVATED —
 * p50 2.897M against 2.819M in healthy wrong-path captures (AUC 0.600), and
 * higher again than the 2.404M of captures taken with the wrong path off
 * (AUC 0.762).  A reader who expects the stalled cell to be the slow one by
 * this number will not find it.  Use worst_user_stall, which counts
 * architectural instructions and selects the condition exactly.
 *
 * WHY THIS IS NOT A CORRECTNESS KNOB.  Measurement is unconditional and
 * changes nothing the tracer emits.  The GATE is opt-in (CST_RT_GATE) and its
 * only power is to abort loudly — it can turn a silent multi-hour stall into
 * an immediate diagnosable failure, and it can never quietly capture less.
 */
struct RtFactorGate {
    /* Config, read once at install. */
    double   floor       = 0.0;   /* CST_RT_GATE; 0 disables the abort */
    unsigned streak_need = 8;     /* consecutive sub-floor sample windows */
    int64_t  sample_ns   = 250 * 1000 * 1000;  /* host span per sample */

    /* State. */
    bool     supported   = true;  /* vclock readable: system mode, no icount */
    bool     armed       = false; /* inside a capture segment */
    int64_t  seg_host0   = 0, seg_vc0 = 0;
    uint64_t seg_icnt0   = 0;
    int64_t  win_host0   = 0, win_vc0 = 0;
    uint32_t divider     = 0;
    unsigned streak      = 0;
    int64_t  last_host   = 0, last_vc = 0;   /* most recent sampled pair */

    /* Accumulated across segments, for the exit report. */
    int64_t  tot_host_ns = 0, tot_vc_ns = 0;
    uint64_t tot_icnt    = 0;
    uint32_t samples     = 0;
    double   worst_factor = 0.0;
    bool     have_worst  = false;
    bool     trace_samples = false;   /* CST_RT_TRACE: dump every sample */

    static int64_t host_ns(void)
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    }

    /*
     * TICK TAX.  Instructions retired inside an asynchronous interrupt (the
     * periodic timer tick, and everything the scheduler does on the way out
     * of it) versus instructions retired in total, attributed per TB from
     * the already-latched async decision, so it costs one compare and one
     * add.  It answers one question — how much of what the guest retired
     * was interrupt work — and it is a composition measure, not a health
     * one.
     *
     * IT DOES NOT DETECT THE STALL, AND MUST NOT BE READ AS IF IT DID.  The
     * saturation reading of this ratio — that the guest returns from a tick
     * with the next already pending, the ratio reaches 1, and forward
     * progress stops — is not what the corpus shows.  Over 3,838 marker
     * cells the ratio never exceeded 0.794 in any cell of any arm, and in
     * the stalled cells it sits at p50 0.689 against 0.703 in the healthy
     * wrong-path cells: LOWER in the condition (AUC 0.215), because a
     * stalled traced process is not in interrupt context at all, it is on
     * the scheduler's context-switch path.  Two thirds of everything this
     * fixture retires is interrupt work in EVERY cell of both arms, stalled
     * or healthy, which is a property of a mostly-idle guest and not a
     * symptom.  A sub-1 tick tax is therefore not evidence of health, and
     * no threshold on it separates the two populations.  worst_user_stall
     * is the field that does.
     */
    uint64_t async_insns = 0;
    uint64_t last_icnt   = 0;
    uint64_t seg_async0  = 0;
    uint64_t tot_async   = 0;

    /*
     * WORKLOAD-PROGRESS STALL — the load-invariant half of the detector.
     * Both terms are architectural counts: instructions retired by the guest,
     * and g_user_icount, the pinned process's user-space instruction clock.
     * Neither contains host time, so this fires identically on an idle
     * machine and on a saturated one; contention cannot manufacture it and
     * cannot mask it.  A healthy capture never lets the guest retire more
     * than a few hundred thousand instructions between two workload
     * instructions; a wedge retires tens of millions and never comes back.
     *
     * The detector refuses to trust a subject it has not seen move: it arms
     * only after g_user_icount has advanced at least once inside this
     * segment, and reports itself INERT otherwise rather than passing
     * silently on a counter that a future mode leaves frozen.
     */
    uint64_t stall_limit   = 8ull * 1000 * 1000;
    uint64_t last_user     = 0;
    uint64_t stall_icnt0   = 0;
    uint64_t worst_stall   = 0;
    bool     user_moved    = false;
    bool     armed_stall   = false;

    void note_tb(bool async, uint64_t icount_now)
    {
        if (icount_now > last_icnt) {
            if (async) {
                async_insns += icount_now - last_icnt;
            }
            last_icnt = icount_now;
        }
    }

    /*
     * Retired-instruction clock for the R_g denominator.  g_host_icount is
     * thread_local (one per vCPU), so take a high-water mark across vCPUs:
     * for a detector whose subject is "no vCPU is making forward progress",
     * the leading vCPU is the correct and conservative reading.
     */
    static uint64_t icount_hwm(void)
    {
        static uint64_t hwm;          /* only ever read/written under exec_lock */
        if (g_host_icount > hwm) {
            hwm = g_host_icount;
        }
        return hwm;
    }

    void install(void)
    {
        const char *e = getenv("CST_RT_GATE");
        if (e && *e) {
            floor = strtod(e, nullptr);
        }
        const char *s = getenv("CST_RT_GATE_STREAK");
        if (s && *s) {
            unsigned long v = strtoul(s, nullptr, 0);
            if (v) {
                streak_need = (unsigned)v;
            }
        }
        /*
         * CST_RT_STALL ARMS THE ARM IT CONFIGURES.
         *
         * It used to only set the budget while CST_RT_GATE alone did the
         * arming, so an operator who set CST_RT_STALL=<n> and nothing else
         * configured a detector that could not fire and got no word of it
         * beyond a "live-unarmed" token in the exit report.  A knob whose
         * only effect is on a tripwire it does not arm is the same defect
         * as the tripwire that cannot fire: it reads as protection and is
         * not.  Either variable now arms the workload-progress stall; the
         * guest-realtime FLOOR arm stays separately gated on a non-zero
         * CST_RT_GATE (floor <= 0 disables it), so CST_RT_GATE=0 still
         * means "the architectural arm only".
         */
        const char *st = getenv("CST_RT_STALL");
        armed_stall = getenv("CST_RT_GATE") != nullptr || st != nullptr;
        if (st && *st) {
            unsigned long long v = strtoull(st, nullptr, 0);
            if (v) {
                stall_limit = (uint64_t)v;
            }
        }
        trace_samples = getenv("CST_RT_TRACE") != nullptr;
        const char *w = getenv("CST_RT_GATE_WINDOW_MS");
        if (w && *w) {
            unsigned long v = strtoul(w, nullptr, 0);
            if (v) {
                sample_ns = (int64_t)v * 1000000LL;
            }
        }
    }

    /*
     * Close out the open segment using the LAST SAMPLED clock pair, never a
     * fresh read.  close_segment() is reachable from plugin_exit, where the
     * vCPU thread is gone and the timer subsystem may already be torn down;
     * reading the guest clock there loses the whole exit report (the report
     * is one GString emitted after every contributor has appended to it) and
     * can take the process with it.  Observed once as a system-golden cell
     * that finished its segment, exited 1, and wrote no summary at all.
     * The cost of using the last sample is at most one sample window of
     * unattributed time at the very end of a segment.
     */
    void close_segment(void)
    {
        if (!armed) {
            return;
        }
        armed = false;
        int64_t h = last_host - seg_host0;
        int64_t v = last_vc - seg_vc0;
        if (h > 0 && v >= 0) {
            tot_host_ns += h;
            tot_vc_ns   += v;
            tot_icnt    += icount_hwm() - seg_icnt0;
            tot_async   += async_insns - seg_async0;
        }
    }

    /*
     * Called from the per-TB correct-path step, inside the vclock-paused
     * region.  The clock reads are amortised 1-in-1024 TBs, so the instrument
     * costs well under a microsecond per sample window.
     */
    void tick(bool seg_active)
    {
        if (!supported) {
            return;
        }
        if (!seg_active) {
            close_segment();
            return;
        }
        if ((++divider & 1023u) != 0) {
            return;
        }
        int64_t vc = qemu_plugin_vclock_ns();
        if (vc == 0) {
            /* User mode, or icount owns the clock: nothing to measure. */
            supported = false;
            return;
        }
        int64_t h = host_ns();
        if (!armed) {
            armed = true;
            seg_host0 = win_host0 = last_host = h;
            seg_vc0   = win_vc0   = last_vc  = vc;
            seg_icnt0 = icount_hwm();
            seg_async0 = async_insns;
            last_user = g_user_icount;
            stall_icnt0 = seg_icnt0;
            user_moved = false;
            streak = 0;
            return;
        }
        last_host = h;
        last_vc   = vc;
        int64_t dh = h - win_host0;
        if (dh < sample_ns) {
            return;
        }
        double f = (double)(vc - win_vc0) / (double)dh;
        uint64_t ic = icount_hwm();
        win_host0 = h;
        win_vc0   = vc;
        samples++;
        uint64_t di = ic - seg_icnt0;
        uint64_t da = async_insns - seg_async0;
        if (trace_samples) {
            fprintf(stderr, "[rtsample] t=%.3f f=%.4f insn=%" PRIu64
                    " ticktax=%.3f stall=%" PRIu64 "\n",
                    (double)(h - seg_host0) / 1e9, f, di,
                    di ? (double)da / (double)di : 0.0,
                    ic - stall_icnt0);
        }
        if (!have_worst || f < worst_factor) {
            worst_factor = f;
            have_worst = true;
        }
        /* Workload-progress stall: architectural, load-invariant. */
        uint64_t u = g_user_icount;
        if (u != last_user) {
            last_user = u;
            stall_icnt0 = ic;
            user_moved = true;
        }
        uint64_t stall = ic - stall_icnt0;
        if (stall > worst_stall) {
            worst_stall = stall;
        }
        if (armed_stall && user_moved && stall > stall_limit) {
            fprintf(stderr,
                "\nchampsim_tracer: *** WORKLOAD PROGRESS STALLED ***\n"
                "  the guest retired %" PRIu64 " instructions without the "
                "traced process\n"
                "  executing a single user-space instruction (limit %"
                PRIu64 ").  Tick tax %.3f.\n"
                "  Both terms are architectural counts, so this verdict does "
                "not depend on\n"
                "  host load: the guest is WEDGED, not slow.  Abandoning the "
                "capture now (#61)\n"
                "  rather than letting it finish a trace that passes every "
                "content check while\n"
                "  carrying tens of times the healthy instruction count.\n"
                "  No .cst is assembled — an abandoned capture must not look "
                "like a delivered\n"
                "  one.  The partial body member (*.body_tmp*) is left on "
                "disk for postmortem;\n"
                "  it is this abandonment's signature, not a salvageable "
                "trace (the header\n"
                "  member only exists at a real close).  Exit status %d.\n\n",
                stall, stall_limit,
                di ? (double)da / (double)di : 0.0, CST_RT_GATE_EXIT);
            fflush(stderr);
            _exit(CST_RT_GATE_EXIT);
        }

        if (floor <= 0.0) {
            return;
        }
        if (f >= floor) {
            streak = 0;
            return;
        }
        if (++streak < streak_need) {
            return;
        }
        double secs = (double)(h - seg_host0) / 1e9;
        fprintf(stderr,
            "\nchampsim_tracer: *** GUEST REALTIME GATE TRIPPED ***\n"
            "  guest realtime factor %.4f < floor %.4f for %u consecutive "
            "%.0f ms windows\n"
            "  (segment open %.1f host-seconds).  The guest is being charged "
            "more timer-tick\n"
            "  work than it can retire: it is WEDGED, not merely slow.\n"
            "  This is the #61 detector, not a timeout — the capture is "
            "abandoned now so the\n"
            "  run fails loudly instead of finishing a trace that passes "
            "every content check\n"
            "  while carrying tens of times the healthy architectural insn "
            "count.\n"
            "  No .cst is assembled — an abandoned capture must not look "
            "like a delivered\n"
            "  one.  The partial body member (*.body_tmp*) is left on disk "
            "for postmortem;\n"
            "  it is this abandonment's signature, not a salvageable trace "
            "(the header\n"
            "  member only exists at a real close).  Exit status %d.\n\n",
            f, floor, streak, (double)sample_ns / 1e6, secs,
            CST_RT_GATE_EXIT);
        fflush(stderr);
        _exit(CST_RT_GATE_EXIT);
    }

    void report(GString *out)
    {
        close_segment();
        if (!supported || tot_host_ns <= 0) {
            g_string_append_printf(out,
                "champsim_tracer: guest_realtime factor=n/a "
                "(no guest clock: user mode, icount, or no segment opened)\n");
            return;
        }
        double f = (double)tot_vc_ns / (double)tot_host_ns;
        double gsec = (double)tot_vc_ns / 1e9;
        double rg = gsec > 0 ? (double)tot_icnt / gsec : 0.0;
        /*
         * segment_insns is tot_icnt VERBATIM, and it is the field a consumer
         * must divide worst_user_stall by.  It is printed because the rate
         * beside it cannot be inverted: a reader that reconstructs the count
         * as insn_per_guest_s x guest_s divides by a guest clock rounded to
         * three decimals, and this clock is FROZEN across every excursion, so
         * a whole marker window can close inside a few milliseconds of it.
         * At guest_s=0.003 those three decimals are a 17% quantisation on the
         * denominator; the reconstruction then exceeded the run's own retired
         * count by 3.2x and drove the validator's stall gate to a "fraction"
         * of 1.050 on a cell whose arch/user was 1.2.  The count is exact and
         * costs one field, so the round trip through a rate is removed rather
         * than bounded.
         */
        g_string_append_printf(out,
            "champsim_tracer: guest_realtime factor=%.4f worst_sample=%.4f "
            "samples=%u in_segment_host_s=%.2f guest_s=%.3f "
            "insn_per_guest_s=%.3fM segment_insns=%" PRIu64 " ticktax=%.4f "
            "worst_user_stall=%" PRIu64 " stall_detector=%s\n",
            f, have_worst ? worst_factor : f, samples,
            (double)tot_host_ns / 1e9, gsec, rg / 1e6, tot_icnt,
            tot_icnt ? (double)tot_async / (double)tot_icnt : 0.0,
            worst_stall,
            user_moved ? (armed_stall ? "live" : "live-unarmed") : "INERT");
    }
};

static RtFactorGate g_rt_gate;

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
/* g_system_mode (full-system emulation, set at install) is declared with the
 * guest-thread identity block above, which is what turns on it. */
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
    if (g_window_mode == PluginConfig::WIN_MARKER) {
        /* Marker mode opens on an executed instruction, and that
         * instruction has its own exec callback: the marker bytes are
         * detected at translation time and vcpu_marker_cb is armed on
         * them directly, so no per-TB polling can ever be what opens
         * the window.  Everything the budget slow path does between
         * segments here is a no-op — tw_manage_window's marker branch
         * only acts when a segment is active, and the segment open
         * itself runs under exec_lock in vcpu_marker_cb — so park the
         * threshold and let the whole boot/fast-forward take the same
         * lock-free inline path the inter-segment icount gap takes.
         * (Measured on the canonical system devio cell: the per-TB
         * slow path — exec_lock pair, scoreboard u64 get/set, the
         * no-op tw_manage_window walk — was ~24% of all host cycles.)
         * The g_host_icount mirror this path refreshed is re-anchored
         * at every segment open (marker_open_trace_window) and
         * maintained in-segment by the heavy step, so the printed
         * "last seen" icount stays truthful at every segment
         * boundary; between the final close and process exit it no
         * longer advances, which is the documented "last per-vCPU
         * TB-exec icount seen" contract. */
        g_next_threshold.store(UINT64_MAX, std::memory_order_relaxed);
        return;
    }
    /* Symbol mode opens on an executed instruction too, but the symbol
     * is matched by TEMPLATE NAME, not by an armed insn callback: the
     * pre-segment occurrence counter advances inside tw_manage_window
     * off the budget slow path (see the WIN_SYMBOL branch there), so
     * every TB must keep taking it. */
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
 * thread_id on the wire is resolve_thread_id()'s result, and it always
 * names a GUEST THREAD — never the vCPU, which is a host scheduling slot
 * the format keeps off the wire entirely.  In system mode that is the
 * identity minted for the task the vCPU is currently running (see the
 * guest-thread identity block near thread_ptr_to_tid); in user mode it is
 * cpu_index, which qemu-user already allocates one-per-guest-thread.  Each
 * segment's body opens with an explicit BODY_TAG_THREAD_SWITCH naming the
 * starting thread.
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
 * when g_features.reg_data.  Accessor is declared in
 * champsim_tracer_path_builder.h so the PathBuilder's fault frames can
 * stash and re-inject it.  Per-vCPU because the capture-to-drain
 * lifetime crosses CP steps (see the header comment). */
static std::vector<RegSnap> g_pending_reg_snaps[CST_PIN_MAX_VCPUS];

std::vector<RegSnap> &pending_reg_snaps(unsigned int cpu_index)
{
    return g_pending_reg_snaps[cpu_index < CST_PIN_MAX_VCPUS
                               ? cpu_index : CST_PIN_MAX_VCPUS - 1];
}

/* WP-side counterpart to pending_reg_snaps.  See the docstring on the
 * extern declaration in champsim_tracer.h for the contract.  Non-static
 * so champsim_tracer_wp.cc can drain it after each WP exec_tb.  Still
 * thread_local (unlike the CP sink): its whole capture-to-drain
 * lifetime sits inside one wrong-path walk, which runs synchronously
 * within a single exec_lock'd CP step — no vCPU switch can interleave,
 * under either threading model. */
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
 *  - WP (g_wp_in_progress): append to wp_pending_reg_snaps;
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
    if (g_wp_in_progress) {
        if (!g_features.wp_reg_data) {
            return;
        }
        sink = &wp_pending_reg_snaps;
    } else {
        if (!g_features.reg_data) {
            return;
        }
        sink = &pending_reg_snaps(cpu_index);
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
    g_mem_recorder.record(cpu_index, info, vaddr, (uint64_t)(uintptr_t)udata);
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
    if (g_wp_in_progress) {
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
    g_mem_recorder.record_synthetic_load(cpu_index, ea,
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
static void reset_segment_local_state(unsigned int cpu_index)
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
     * Other vCPUs' accumulators (cp_chain, the CP memop buffer,
     * pending_reg_snaps) are reset lazily: bumping
     * g_segment_generation makes each vCPU self-drop its stale chain
     * on its next append_fragment; the other two drain every BB /
     * body emit, and each vCPU's PathBuilder runs its own
     * on_segment_open (frames, pending-seal slot, retained events)
     * as it observes the bumped generation in vcpu_tb_exec.
     */
    g_segment_generation.fetch_add(1, std::memory_order_release);

    /* The opening vCPU's own accumulators (we're called from
     * vcpu_tb_exec).  Its PathBuilder's frames and cursors are dropped
     * by its own on_segment_open (each vCPU runs it as it crosses the
     * segment generation, this one included). */
    cp_chain(cpu_index).reset();
    g_mem_recorder.clear_cp(cpu_index);
    pending_reg_snaps(cpu_index).clear();
    cp_chain_snap_mark(cpu_index) = 0;
    /* A fresh window is never mid-close (the arm self-clears the moment
     * no close is pending, so this is belt-and-braces).  The END arm is
     * cleared with it: an END terminates the run, so a segment opening
     * after one is not a state this can reach — and if it ever were, the
     * new window would inherit a close it never earned. */
    deferred_close(cpu_index).window_close_armed = false;
    deferred_close(cpu_index).end_close_pending = false;

    /* Per-segment disk-I/O record state: request ids are compact and
     * monotonic WITHIN a segment, so the counter, the pending queues,
     * and the live-id set all reset here (a request straddling the
     * boundary yields no cross-segment orphan). */
    devio_reset_segment();
}

/* Snapshot of g_rep_fanout_extra_insns at segment open, so
 * finish_trace_segment can diff and report per-segment fan-out. */
static uint64_t g_seg_fanout_start = 0;

/* Snapshot of wire_user_rep_extra_insns at segment open.  The diff is the
 * segment's USER self-loop fan-out surplus — the one legitimate way the
 * wire outruns the clock (see the counter's increment sites) — and
 * finish_trace_segment folds it into the printed clock_minus_wire, so a
 * fan-out-bearing segment whose accounting is exact reads 0 there instead
 * of -(surplus).  The surplus stays a NAMED term (its own stats row), and
 * folding it at the print never touches `covered` or the un-bill
 * machinery. */
static uint64_t g_seg_rep_surplus_start = 0;

/* Segment-local TRACE-instruction counter (trace position).  Bumped by
 * parent BB template n_insns (and +1 per REP sub-iteration) inside
 * emit_body_entry so it tracks exactly what cst_audit counts off
 * the body stream — which, through fan-out, runs AHEAD of the window
 * clock (the bbv-equivalent count the budgets are configured in).  At
 * the warmup→simulation transition (the window clock reaches the
 * warmup budget) we snapshot this into g_seg_warmup_end_trace_insns,
 * which finish_trace_segment writes into the header (§2.13): the
 * trace-position index aligning to the bbv-counted warmup boundary. */
static uint64_t g_seg_arch_insns = 0;
/* The USER (non-system) part of g_seg_arch_insns — the plugin-side twin of
 * the OWNED_CP figure this arc reconstructs from the wire.  Printed on the
 * segment's finish line beside user_covered so the clock-vs-wire residual is
 * a number the run reports, not one a reader has to subtract. */
static uint64_t g_seg_arch_user_insns = 0;
/* User-mode (raw-clock) instructions of THIS segment that the inline
 * icount counted at dispatch but that no published range claims — the
 * exact-budget cut/suppression past a finite user window's stop, and each
 * close-flushed pending-seal slot's unpublished tail (S18: the boundary
 * instruction dies mid-callback / never ran; outside the range, therefore
 * unbilled).  finish_trace_segment subtracts it from the raw `covered` so
 * BILLED == PUBLISHED holds at the user exit and budget closes exactly as
 * user_clock_close_credit makes it hold on the marker clock.  Mutated
 * under exec_lock (emissions and closes both hold it). */
static uint64_t g_seg_user_unbilled = 0;
/* User-mode (raw-clock) instructions of THIS segment that are PUBLISHED
 * but whose inline-add bill landed BEFORE window_start: a mid-run window
 * open fires at the dispatch whose per-TB add carried the clock past the
 * start, and that crossing TB is deliberately traced whole (the budget
 * cond_cb opens the segment, the vcpu_tb_exec brcond re-loads is_active
 * and fires for the same TB — see the registration-order comment in
 * vcpu_tb_trans), so its head insns are on the wire while
 * `g_host_icount - lo` never bills them.  finish_trace_segment adds this
 * to the raw `covered` — the open-boundary twin of g_seg_user_unbilled,
 * with the opposite sign.  Mutated under exec_lock. */
static uint64_t g_seg_user_prebilled = 0;

/*
 * The user-mode (raw-clock) twin of user_clock_close_credit, with the
 * opposite sign.  In user mode the window clock is the inline per-TB
 * icount, which counts a TB's full translated length the moment the TB is
 * ENTERED — so an instruction the close leaves unpublished (the exit
 * syscall dying mid-callback, the un-run TB a deferred budget close
 * skips, the exact-budget cut/suppression past a finite window's stop)
 * has already been counted and must be UN-billed for BILLED == PUBLISHED
 * to hold at the close.  Accumulated per segment; finish_trace_segment
 * subtracts it from the raw `covered`.  A no-op in system mode, whose
 * window clocks bill by retirement folds and settle through
 * user_clock_close_credit.
 */
void user_raw_clock_unbilled(uint64_t insns)
{
    if (g_system_mode || insns == 0) {
        return;
    }
    g_seg_user_unbilled += insns;
    g_stats.user_raw_unbilled_insns += insns;
}

/*
 * The OPEN-boundary correction the close-side un-bill above cannot see.
 * A mid-run window open lands on a TB boundary: the crossing TB — the one
 * whose inline per-TB add carried the raw clock from below window_start
 * to at-or-past it — executes fully traced (its body entry lands in the
 * trace by design, keeping the wire aligned with the BBV count that
 * positioned the window; see the budget-cb registration-order comment in
 * vcpu_tb_trans), but the coverage settle bills the segment from
 * window_start, so the head insns of that TB dispatched below the start
 * are published-but-never-billed and every such open reads
 * clock_minus_wire = -(head) while the accounting is in fact exact.
 * Called at each raw-clock segment-open site with the opening dispatch's
 * post-add clock and the crossing TB's head fragment; credits exactly the
 * straddle.  A boundary-aligned open (dispatch began at-or-past the
 * start, e.g. the very first TB of a lo=0 window) credits nothing and
 * leaves single-segment runs byte-identical.  No-op in system mode, whose
 * window clocks bill by retirement folds.
 *
 * CST_SEG_OPEN_CREDIT_OFF=1 severs the credit (falsifier lever, the
 * CST_REP_FACTS_OFF precedent): it reproduces the published-but-unbilled
 * open-boundary shape on demand so the validator's per-segment
 * clock_minus_wire gate can be proven able to fire.  Never set it on a
 * production run.
 */
static void user_raw_clock_open_credit(uint64_t lo, uint64_t icount_now,
                                       const BBTemplate *cross_head)
{
    if (g_system_mode || !cross_head) {
        return;
    }
    static const bool credit_off =
        getenv("CST_SEG_OPEN_CREDIT_OFF") != nullptr;
    if (credit_off) {
        return;
    }
    uint64_t tb_len = 0;
    for (const BBTemplate *f = cross_head; f; f = f->next_tb_fragment) {
        tb_len += f->n_insns;
    }
    uint64_t dispatch_start = icount_now > tb_len ? icount_now - tb_len : 0;
    if (dispatch_start >= lo) {
        return;             /* opened on a TB boundary: nothing straddles */
    }
    uint64_t credit = lo - dispatch_start;
    if (credit > tb_len) {
        credit = tb_len;    /* whole TB billed below the start (symbol open) */
    }
    g_seg_user_prebilled += credit;
    g_stats.user_raw_open_prebilled_insns += credit;
}

/* UINT64_MAX sentinel = warmup boundary has not been crossed
 * (segment cut short, or warmup_insns==0 and no entry emitted
 * yet).  0 is a legitimate value (warmup_insns==0 → captured at
 * the very first entry). */
static uint64_t g_seg_warmup_end_trace_insns = UINT64_MAX;

/* Ceiling on the deferred window close's fan-out hold, in consecutive
 * close evaluations.  Large enough that no legitimate hold reaches it
 * (an instruction's remaining REP_MAX chunks plus its own page-fault
 * service), small enough that a hold that never releases costs a
 * bounded overrun instead of a trace that never finishes.  The §2.13
 * warmup-boundary hold deliberately does NOT share it: the boundary is
 * a header field, not a liveness event, and a ceiling there would
 * re-introduce the mid-instruction split (see emit_body_entry). */
static const uint64_t CST_FANOUT_HOLD_MAX = 65536;
/* Dispatch-time warmup crossing latch: set in tw_manage_window when the
 * window clock (user clock in pinned modes, raw inline counter
 * otherwise) reaches the warmup budget.  The §2.13 capture in
 * emit_body_entry keys off this flag, never off a live clock read —
 * emissions lag execution, and a live read would move the boundary
 * with translation-dependent emission timing. */
static bool g_seg_warmup_crossed = false;
/* Records this segment's §2.13 placement has deferred past under the
 * fan-out hold.  Distinguishes, at segment finish, a boundary the hold
 * was still deferring (crossed, sentinel, deferrals > 0 — counted as
 * warmup_boundary_unplaced_at_finish) from the pre-existing sentinel
 * meanings (segment cut short before the crossing, or no emission
 * after it), whose header bytes stay untouched. */
static uint64_t g_seg_wm_deferred_records = 0;

/* ============================================================
 * Opportunistic branch-alternate minting (static_templates=1, both modes).
 *
 * The never-executed fetch/decode space a trace-inferred wrong-path consumer
 * fetches is, block by block, the UNTAKEN side of a branch.  Rather than
 * enumerate the whole executable footprint up front, the plugin mints that
 * side exactly when a branch is evaluated: at every branch the correct path
 * or a wrong-path excursion resolves, the UNTAKEN side's true BB is decoded
 * (through the same Capstone -> decode_detail_to_generic -> fragment-splitter
 * machinery the dynamic path uses) and minted as an ordinary never-executed
 * dictionary template — unless it is already covered.  Coverage is therefore
 * CONVERGENT (the dictionary fills as branches are seen) and mode-independent
 * (it needs no region enumeration at all, so it covers system mode too).
 *
 * With static_depth>0, each freshly-minted block's own statically-known
 * successors are followed recursively — the architectural fall-through
 * always, and a direct branch's decoded target too (both edges of a
 * direct terminator are statically known; an indirect terminator has no
 * static target, so that edge ends the chain).  This deepens coverage from
 * just the immediate untaken side toward the whole reachable never-executed
 * region a mispredict-driven consumer wanders into.
 *
 * This fills the two gaps a wrong path alone leaves: branches INSIDE
 * wrong-path blocks (which follow their resolved direction, so their
 * alternates are never walked) and branches whose wrong-path fork never
 * launched (wpprune, budget, translation-unavail, wp=0).
 *
 * Off the hot path by construction: the presence test is one hash lookup per
 * evaluated branch (the walker already does lookups); the decode + successor
 * walk fire only on a miss, which trends to ~0 after warmup.  Guest bytes are
 * read with the same probing read the wrong path uses (mapped page -> decode;
 * unmapped -> skipped, counted), so enumeration never demand-pages or
 * perturbs the guest.
 * ============================================================ */

/* Defensive per-BB length cap: a branch-free region (or data decoding as
 * straight-line insns) cannot mint one unbounded template. */
static constexpr uint32_t CST_ALT_BB_MAX_INSNS = 4096;

/* True iff @bt is a control-transfer that carries an architectural delay
 * slot on this ISA (mirrors split_tb_into_fragments::has_delay_slot).  The
 * exception-return family (eret/eretnc/deret) is BRANCH_RETURN but has no
 * slot; QEMU ends the TB there, so exclude it. */
static bool alt_has_delay_slot(uint8_t bt, const char *mnem)
{
    if (bt != BRANCH_DIRECT_JUMP && bt != BRANCH_INDIRECT_JUMP &&
        bt != BRANCH_RETURN && bt != BRANCH_COND_DIRECT &&
        bt != BRANCH_DIRECT_CALL && bt != BRANCH_INDIRECT_CALL) {
        return false;
    }
    if (mnem[0] == 'e') {
        return !(!strcmp(mnem, "eret") || !strcmp(mnem, "eretnc"));
    }
    return strcmp(mnem, "deret") != 0;
}

struct AltMintStats {
    uint64_t checks         = 0;  /* PCs whose coverage was tested            */
    uint64_t mints          = 0;  /* never-executed alternates minted         */
    uint64_t depth_mints    = 0;  /* subset of mints from the depth>0 walk     */
    uint64_t skips_unmapped = 0;  /* target unmapped/undecodable              */
    uint64_t budget_hits    = 0;  /* mints skipped for the per-segment budget */
};
static AltMintStats g_alt_mint;

/* Per-segment mint budget: bounds the DECODE+MINT work (the presence test is
 * always allowed).  Ample for a code footprint's distinct never-executed
 * blocks; a runaway (data-in-text minting garbage alternates) is capped.
 * Reset at every segment open. */
static constexpr uint64_t CST_ALT_MINT_BUDGET = 1u << 20;   /* 1,048,576 */
static uint64_t g_alt_mint_budget_used = 0;

/*
 * Decode ONE true BB starting at @pc into the supplied scratch arrays,
 * stopping at the first branch terminator (folding a delay slot on
 * delay-slot ISAs) or CST_ALT_BB_MAX_INSNS.  Guest bytes are read in one
 * page-bounded window via the probing qemu_plugin_read_memory_vaddr (unmapped
 * -> read fails).  Returns the instruction count (0 iff the very first insn
 * could not be read/decoded — unmapped or undecodable), sets *out_ft to the
 * architectural fall-through (post-terminator PC, or the next linear PC for
 * an unterminated cap/edge stop) and *out_taken to the terminal
 * direct-branch's decoded target (0 if none).  Takes NO lock (pure guest
 * read + decode).
 *
 * @fscratch / @nscratch are the CALLER-OWNED per-instruction decode backing.
 * InsnFields is a struct of SPANS (champsim_tracer_mnemonics.h) — its
 * register arrays and every dep/lane mask live in the InsnFieldsScratch that
 * produced them — so one scratch per instruction is required (a shared one
 * leaves all N entries pointing at the last instruction decoded), and it must
 * outlive commit_alt_bb's pack, which is what deep-copies out of it.  Held by
 * unique_ptr so growing the pool cannot move an already-wired element: the
 * scratch types are self-referential and must never be relocated.
 */
static uint32_t alt_decode_one_bb(uint64_t pc,
                                  std::vector<uint64_t> &pcs,
                                  std::vector<InsnFields> &fields,
                                  std::vector<InsnRegNames> &regnames,
                                  std::vector<uint8_t> &sizes,
                                  std::vector<uint8_t> &bytes,
                                  std::vector<std::unique_ptr<
                                      InsnFieldsScratch>> &fscratch,
                                  std::vector<std::unique_ptr<
                                      InsnRegNamesScratch>> &nscratch,
                                  bool with_names,
                                  uint64_t *out_ft,
                                  uint64_t *out_taken)
{
    const bool delay_isa = isa_properties[trace_isa].branch_delay_slots > 0;
    *out_ft = 0;
    *out_taken = 0;

    /* One page-bounded read window (a true BB never spans far); refilled if a
     * folded delay slot crosses the initial window. */
    GByteArray *win = g_byte_array_new();
    uint64_t win_base = 0, win_len = 0;
    bool     win_ok = false;
    auto window_at = [&](uint64_t at, const uint8_t **out,
                         uint64_t *avail) -> bool {
        if (!win_ok || at < win_base || at >= win_base + win_len) {
            if (!qemu_plugin_read_memory_vaddr(at, win, 4096)) {
                win_ok = false;
                return false;
            }
            win_base = at;
            win_len  = win->len;
            win_ok   = true;
        }
        *out   = win->data + (at - win_base);
        *avail = win_base + win_len - at;
        return *avail > 0;
    };

    /* Decode the insn at @at into slot @i; returns bytes consumed (0 on
     * failure) and reports the branch type in @out_bt. */
    auto decode_one = [&](uint64_t at, uint32_t i, uint8_t *out_bt,
                          bool *out_dslot) -> uint8_t {
        const uint8_t *p = nullptr;
        uint64_t avail = 0;
        if (!window_at(at, &p, &avail)) {
            return 0;
        }
        qemu_plugin_insn_info info;
        if (!qemu_plugin_cap_decode(cst_cap_arch, cst_cap_mode, p,
                                    (size_t)avail, at, &info)) {
            return 0;
        }
        uint8_t sz = info.insn_size;
        if (sz == 0 || sz > MAX_INSN_BYTES || sz > avail) {
            return 0;
        }
        /* Grow the caller's pool to cover slot @i.  Growth appends
         * unique_ptrs, so no already-decoded element moves. */
        while (fscratch.size() <= i) {
            fscratch.push_back(std::make_unique<InsnFieldsScratch>());
        }
        InsnFieldsScratch &fs = *fscratch[i];
        insn_fields_scratch_reset(&fs);
        InsnRegNamesScratch *ns = nullptr;
        if (with_names) {
            while (nscratch.size() <= i) {
                nscratch.push_back(std::make_unique<InsnRegNamesScratch>());
            }
            ns = nscratch[i].get();
            insn_reg_names_scratch_reset(ns);
        }
        decode_detail_to_generic(at, &info, &fs.f, ns ? &ns->rn : nullptr);
        uint8_t bt = fs.f.branch_type;
        pcs[i]   = at;
        sizes[i] = sz;
        memcpy(&bytes[(size_t)i * MAX_INSN_BYTES], p, sz);
        if (sz < MAX_INSN_BYTES) {
            memset(&bytes[(size_t)i * MAX_INSN_BYTES + sz], 0,
                   MAX_INSN_BYTES - sz);
        }
        /* Shallow copy of the descriptor: its spans stay pointed at
         * fscratch[i] / nscratch[i], which the caller keeps alive across
         * commit_alt_bb. */
        fields[i] = fs.f;
        if (with_names) {
            regnames[i] = ns->rn;
        }
        *out_bt = bt;
        *out_dslot = (delay_isa && bt != BRANCH_NONE &&
                      alt_has_delay_slot(bt, info.mnemonic));
        return sz;
    };

    uint64_t cur = pc;
    uint32_t n = 0;
    bool sealed = false;
    while (n < CST_ALT_BB_MAX_INSNS) {
        uint8_t bt = BRANCH_NONE;
        bool dslot = false;
        uint8_t sz = decode_one(cur, n, &bt, &dslot);
        if (sz == 0) {
            break;      /* undecodable (or unmapped at n==0) */
        }
        uint32_t branch_idx = n;
        n++;
        cur += sz;
        if (bt == BRANCH_NONE) {
            continue;
        }
        /* Fold the delay slot, then seal. */
        if (dslot && n < CST_ALT_BB_MAX_INSNS) {
            uint8_t sbt = BRANCH_NONE;
            bool sd = false;
            uint8_t ssz = decode_one(cur, n, &sbt, &sd);
            if (ssz != 0) {
                n++;
                cur += ssz;
            }
        }
        if ((bt == BRANCH_COND_DIRECT || bt == BRANCH_DIRECT_JUMP ||
             bt == BRANCH_DIRECT_CALL) &&
            fields[branch_idx].has_immediate) {
            *out_taken = (uint64_t)fields[branch_idx].immediate;
            /* The executed path stamps this from the per-ISA translator
             * (create_tb_template); a never-executed block has no
             * translation, so the decoded immediate IS its static target.
             * Leaving it zero is what made a minted branch's declared
             * target readable only at template level. */
            fields[branch_idx].taken_target_pc = *out_taken;
        }
        sealed = true;
        break;
    }

    g_byte_array_free(win, TRUE);
    if (n == 0) {
        return 0;
    }
    *out_ft = sealed ? cur : pcs[n - 1] + sizes[n - 1];
    return n;
}

/*
 * Mint ONE never-executed alternate at @pc into alt_map_, unless it is
 * already covered (executed / previously-minted), the mint budget is
 * exhausted, or its page is unmapped/undecodable.  On a successful mint,
 * reports the block's statically-known successors: *out_ft is the
 * architectural fall-through (always defined) and *out_taken the terminal
 * direct-branch's decoded target (0 for an indirect / non-branch terminator).
 * Returns true iff a fresh template was committed (the only case the caller
 * recurses on).  Takes data_lock internally, releasing it around the guest
 * read; caller must hold exec_lock and NOT data_lock.
 */
static bool altmint_one(uint64_t pc, uint64_t *out_ft, uint64_t *out_taken)
{
    *out_ft = 0;
    *out_taken = 0;
    g_alt_mint.checks++;

    /* One hash lookup: already carried by an executed or previously-minted
     * template?  Existing wins (find_existing_true_bb / alt_map_ dedup
     * semantics) — nothing to do. */
    g_mutex_lock(&data_lock);
    bool covered = g_template_store.alt_or_bb_covered(pc);
    g_mutex_unlock(&data_lock);
    if (covered) {
        return false;
    }

    if (g_alt_mint_budget_used >= CST_ALT_MINT_BUDGET) {
        g_alt_mint.budget_hits++;
        return false;
    }
    if (cst_cap_arch < 0) {
        return false;   /* no Capstone arch for this ISA — cannot decode */
    }

    const bool with_names = g_features.reg_data || g_features.wp_reg_data;

    /* Per-BB descriptor arrays (plain locals; a mint is rare after warmup —
     * misses trend to zero — so a fresh allocation here keeps these buffers
     * out of the plugin's static TLS block). */
    std::vector<uint64_t>      pcs(CST_ALT_BB_MAX_INSNS);
    std::vector<InsnFields>    fields(CST_ALT_BB_MAX_INSNS);
    std::vector<InsnRegNames>  regnames(CST_ALT_BB_MAX_INSNS);
    std::vector<uint8_t>       sizes(CST_ALT_BB_MAX_INSNS);
    std::vector<uint8_t>       bytes((size_t)CST_ALT_BB_MAX_INSNS *
                                     MAX_INSN_BYTES);

    /* Per-INSTRUCTION decode backing, one scratch per slot.  It is the
     * register identities and every dep/lane mask — an InsnFields carries
     * those as spans into the scratch that built them (SPAN MEMBERS,
     * champsim_tracer_mnemonics.h), so the descriptors above are only as
     * good as the scratch they point at.  Grown on demand and reused
     * across mints rather than sized to CST_ALT_BB_MAX_INSNS: a full-cap
     * preallocation would be tens of MB zeroed per mint, and a true BB is
     * a few instructions long.  Held by unique_ptr because the scratch
     * types are self-referential and must never be relocated; kept alive
     * until after commit_alt_bb, which is where the pack deep-copies.
     *
     * Plain locals, deliberately NOT thread_local: the plugin is dlopen'd
     * and its static TLS block is already within ~80 bytes of glibc's
     * static-TLS surplus, so even an empty thread_local vector here makes
     * every guest refuse to load the plugin ("cannot allocate memory in
     * static TLS block").  A mint is rare after warmup and this function
     * already allocates its descriptor arrays per call. */
    std::vector<std::unique_ptr<InsnFieldsScratch>>   fscratch;
    std::vector<std::unique_ptr<InsnRegNamesScratch>> nscratch;

    uint64_t ft = 0, taken = 0;
    /* The guest read + decode runs WITHOUT data_lock: the probing read takes
     * the mmap_lock (user) / walks the page table (system), and the
     * translation path holds mmap_lock before data_lock — holding data_lock
     * across the read would invert that order. */
    uint32_t n = alt_decode_one_bb(pc, pcs, fields, regnames, sizes,
                                   bytes, fscratch, nscratch,
                                   with_names, &ft, &taken);
    if (n == 0) {
        g_alt_mint.skips_unmapped++;   /* unmapped page or undecodable head */
        return false;
    }

    g_mutex_lock(&data_lock);
    BBTemplate *t = g_template_store.commit_alt_bb(
        pc, n, pcs.data(), fields.data(), sizes.data(), bytes.data(),
        with_names ? regnames.data() : nullptr,
        /* symbol_name= */ nullptr, ft);
    if (t && taken != 0 && t->taken_pc == 0) {
        /* A never-executed direct branch's declared taken edge is its
         * decoded target (BTB coverage of the never-executed destination). */
        t->taken_pc = taken;
    }
    g_mutex_unlock(&data_lock);

    g_alt_mint.mints++;
    g_alt_mint_budget_used++;
    *out_ft = ft;
    *out_taken = taken;
    return true;
}

void altmint_pc(uint64_t alt_pc)
{
    if (!g_features.alt_mint || alt_pc == 0) {
        return;
    }

    /* Depth-0 (static_depth==0): mint just the immediate untaken side.  The
     * fast common case skips the worklist machinery entirely. */
    uint64_t ft = 0, taken = 0;
    bool minted = altmint_one(alt_pc, &ft, &taken);
    if (!minted || g_features.alt_depth == 0) {
        return;
    }

    /*
     * Depth-N: from each freshly-minted block, follow its statically-known
     * successors — the fall-through always, and a direct branch's decoded
     * target too (an indirect terminator reports taken==0, ending that
     * chain).  DFS worklist of (pc, depth); recurse only on blocks this call
     * actually minted, so dedup (alt_or_bb_covered) + the per-segment budget
     * bound the walk and a cycle can never spin (a re-visited PC is already
     * covered and stops).  A local seen-set keeps the worklist from ballooning
     * with duplicate pending PCs.  All off the hot path: this runs only when
     * a miss was minted, which trends to zero after warmup.
     */
    std::vector<std::pair<uint64_t, uint32_t>> work;
    std::unordered_set<uint64_t> seen;
    auto enqueue = [&](uint64_t pc, uint32_t depth) {
        if (pc != 0 && seen.insert(pc).second) {
            work.emplace_back(pc, depth);
        }
    };
    seen.insert(alt_pc);
    enqueue(ft, 1);
    enqueue(taken, 1);
    while (!work.empty()) {
        auto [pc, depth] = work.back();
        work.pop_back();
        uint64_t s_ft = 0, s_taken = 0;
        if (!altmint_one(pc, &s_ft, &s_taken)) {
            continue;   /* covered / unmapped / budget — chain ends here */
        }
        g_alt_mint.depth_mints++;
        if (depth < g_features.alt_depth) {
            enqueue(s_ft, depth + 1);
            enqueue(s_taken, depth + 1);
        }
    }
}

void altmint_conditional_alternate(const InsnFields *terminal,
                                   uint64_t fall_through,
                                   uint64_t followed_pc)
{
    if (!g_features.alt_mint || !terminal) {
        return;
    }
    /* Only a conditional DIRECT branch has a statically-known untaken side
     * (both edges architecturally reachable): its taken target is the decoded
     * immediate, its not-taken edge the fall-through.  Unconditional /
     * indirect terminators have no decodable alternate here. */
    bool direct_cond = terminal->branch_type == BRANCH_COND_DIRECT ||
                       (terminal->branch_type == BRANCH_DIRECT_JUMP &&
                        terminal->branch_conditional);
    if (!direct_cond || !terminal->has_immediate) {
        return;
    }
    uint64_t taken = (uint64_t)terminal->immediate;

    uint64_t alt;
    if (followed_pc == fall_through) {
        alt = taken;              /* walk fell through -> taken is untaken */
    } else if (followed_pc == taken) {
        alt = fall_through;       /* walk took -> fall-through is untaken */
    } else {
        return;                   /* neither edge (fault redirect): ambiguous */
    }
    altmint_pc(alt);
}

static void start_trace_segment(const char *label,
                                uint64_t start, uint64_t stop,
                                uint64_t warmup,
                                uint64_t total_target,
                                unsigned int cpu_index,
                                double simpoint_weight)
{
    reset_segment_local_state(cpu_index);
    g_seg_fanout_start = g_rep_fanout_extra_insns.load(
        std::memory_order_relaxed);
    g_seg_rep_surplus_start = g_stats.wire_user_rep_extra_insns;
    g_seg_arch_insns = 0;
    g_seg_arch_user_insns = 0;
    g_seg_user_unbilled = 0;
    g_seg_user_prebilled = 0;
    g_seg_warmup_end_trace_insns = UINT64_MAX;
    g_seg_warmup_crossed = false;
    g_seg_wm_deferred_records = 0;
    /* A fan-out instruction left architecturally in flight by a previous
     * segment must not hold the fresh segment's warmup boundary. */
    for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; i++) {
        rep_state((unsigned)i).warmup_hold_reset();
    }

    /* Capture the architectural register file so consumers can prime
     * register state without replaying a prior segment's dst-write
     * deltas.  cpu_index == (unsigned)-1 (install-time start=0, no
     * vCPU yet) → empty snapshot; dst-write stream is then the only
     * state source. */
    std::vector<InitialRegSnap> regfile;
    capture_initial_regfile(cpu_index, &regfile);

    /* Seed thread id: the opener's guest-thread identity.  The map was just
     * reset (reset_segment_local_state), so the thread pointer sampled here
     * takes tid 0 — a single-threaded traced process is thread 0 on any
     * vCPU, and single-thread system goldens stay byte-stable (cpu_index 0
     * and first-sighting 0 coincide).  User mode keeps cpu_index, which is
     * already the guest thread there (see resolve_thread_id).  When the
     * open lands on a kernel TB of a target whose thread pointer is not
     * readable at that privilege, the seed is thread 0 and the first user
     * TB establishes the mapping. */
    uint32_t seed_thread_id = (uint32_t)cpu_index;
    if (g_system_mode && cpu_index < CST_PIN_MAX_VCPUS) {
        int seed_priv = qemu_plugin_get_priv_level();
        uint64_t seed_tp;
        seed_thread_id = 0;
        if (thread_ptr_sample(seed_priv, &seed_tp)) {
            seed_thread_id = thread_ptr_to_tid(seed_tp);
            g_vcpu_last_tp[cpu_index] = seed_tp;
            if (tiddiag_on()) {
                tiddiag_note_binding(cpu_index, seed_thread_id);
            }
            if (seed_priv == 0) {
                /* The seed IS a user sample of the opener (the marker's
                 * own user context), so it must arm the kernel-entry
                 * alias exactly as a user thread_identity_sample does:
                 * a segment whose FIRST body steps are already inside a
                 * kernel excursion of the opener (marker directly
                 * followed by a syscall/interrupt) otherwise MINTS a
                 * fresh strand for the opener's own task value — the
                 * opener's kernel work then splits from its user id,
                 * violating rule (a) from the first exit edge.  The
                 * alias arm makes that first resolved kernel value join
                 * the opener's tid, on the same exception-edge evidence
                 * as every later entry (the excursion the window opened
                 * into was entered by the thread that ran the marker). */
                g_vcpu_alias_pending[cpu_index] = true;
                g_vcpu_alias_budget[cpu_index] = CST_ALIAS_KSAMPLE_BUDGET;
            }
        }
        g_vcpu_cur_tid[cpu_index] = seed_thread_id;
    }
    if (g_pinned_asid.load(std::memory_order_relaxed) != CST_ASID_UNPINNED &&
        cpu_index < CST_PIN_MAX_VCPUS) {
        uint32_t seed_asid_index = 0;
        if (qemu_plugin_get_priv_level() == 0) {
            /* Opener sampled at user privilege: seed the migration-detect
             * guard's per-segment vCPU set with this vCPU. */
            pin_user_vcpu_observe(cpu_index);
            /* The live user root at priv 0 IS the process's user CR3, so
             * seed the context asid to it (the tables' process key).  A
             * kernel excursion before the first user TB then folds to the
             * entering process rather than the KPTI kernel CR3.  Just after
             * asid_identity_reset, so this first-sighting maps to index 0 —
             * single-address-space stays byte-identical. */
            uint64_t seed_root = qemu_plugin_get_addr_space_id();
            seed_asid_index = asid_root_to_index(
                seed_root, asid_first_sight_sig(seed_root));
        }
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
    g_seg_close_reason = nullptr;

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

    /* Opportunistic branch-alternate minting is segment-scoped (alt_map_ is
     * dropped at clear_bb_map); re-arm its per-segment mint budget. */
    g_alt_mint_budget_used = 0;
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

/* ---- SMP attribution-pair claim ledger (Stats::smp_dup_*) --------------
 *
 * THE CONDITION, INSTRUMENTED AT THE CHOKE POINT.  Every body entry claims
 * a range of one template's instructions for one guest thread; an
 * instruction claimed twice is the trace-invalidating duplicate pair
 * (mid-stream re-emission / duplicate final entry at the budget close).
 * The ledger keeps, per thread, the last two USER claims and fires the
 * moment a new claim re-covers one of them at a position the previous
 * entry's own resolved DIRECT terminal makes unreachable — so a genuine
 * self-loop (taken edge to its own start), an indirect branch, a REP
 * fan-out and a disjoint fault-split continuation all stay silent, and a
 * fire names the two emit sites, vCPUs and seqs of the double claim.
 *
 * Everything runs under exec_lock (every emission does); the map is
 * process-lifetime by the stats.cc immortalization rule.
 */
struct SmpClaim {
    const BBTemplate *tmpl = nullptr;
    uint32_t bb_start = 0;
    uint32_t bb_stop = 0;
    uint64_t seq = 0;
    unsigned vcpu = 0;
    const char *site = "";
    size_t seg = 0;            /* g_segments_written stamp */
    uint32_t depth = 0;
    bool valid = false;
};
struct SmpTidLedger {
    SmpClaim last[2];          /* [0] = most recent */
};
static std::unordered_map<uint32_t, SmpTidLedger> &g_smp_claims =
    *new std::unordered_map<uint32_t, SmpTidLedger>();

/* Can @p's terminal successor set DEFINITIVELY exclude a next entry at
 * @pc?  Only a full-range claim whose terminal is a resolved DIRECT
 * branch (or a branchless page-split block, whose one successor is its
 * fall-through) can answer yes; everything else answers no and the
 * checker stays silent. */
static bool smp_succ_excludes(const SmpClaim &p, uint64_t pc)
{
    const BBTemplate *t = p.tmpl;
    if (!t || t->n_insns == 0 || !t->insn_fields ||
        p.bb_stop != t->n_insns) {
        return false;
    }
    int bi = TemplateStore::template_branch_index(t);
    if (bi < 0) {
        /* No terminal branch: the block was split by the translator and
         * its only successor is the fall-through. */
        return t->fall_through_pc != 0 && pc != t->fall_through_pc;
    }
    switch (t->insn_fields[bi].branch_type) {
    case BRANCH_DIRECT_JUMP:
    case BRANCH_DIRECT_CALL:
        return t->taken_pc != 0 && pc != t->taken_pc;
    case BRANCH_COND_DIRECT:
        return t->taken_pc != 0 && t->fall_through_pc != 0 &&
               pc != t->taken_pc && pc != t->fall_through_pc;
    default:
        return false;              /* indirect / return / syscall / REP */
    }
}

static inline uint64_t smp_claim_start_pc(const SmpClaim &c)
{
    return (c.tmpl && c.tmpl->insn_pcs && c.bb_start < c.tmpl->n_insns)
        ? c.tmpl->insn_pcs[c.bb_start] : (c.tmpl ? c.tmpl->start_pc : 0);
}

static inline bool smp_claims_overlap(const SmpClaim &a, const SmpClaim &b)
{
    return a.tmpl == b.tmpl &&
           a.bb_start < b.bb_stop && b.bb_start < a.bb_stop;
}

static void smp_claim_report(const char *what, const SmpClaim &cur,
                             const SmpClaim &dup, const SmpClaim &between)
{
    fprintf(stderr, "champsim_tracer: [smpdiag] %s: tid-claim seq=%" PRIu64
            " pc=0x%" PRIx64 " [%u,%u) vcpu=%u site=%s RE-CLAIMS seq=%"
            PRIu64 " vcpu=%u site=%s%s%s (between: seq=%" PRIu64
            " pc=0x%" PRIx64 " site=%s)\n",
            what, cur.seq, smp_claim_start_pc(cur), cur.bb_start,
            cur.bb_stop, cur.vcpu, cur.site, dup.seq, dup.vcpu, dup.site,
            cur.vcpu != dup.vcpu ? " CROSS-VCPU" : "",
            strcmp(cur.site, dup.site) != 0 ? " CROSS-SITE" : "",
            between.valid ? between.seq : 0,
            between.valid ? smp_claim_start_pc(between) : 0,
            between.valid ? between.site : "-");
}

/* One check per emitted entry; @tid ledger updated afterwards.  Fires
 * Stats::smp_dup_adjacent_claims / smp_dup_wrongpc_reemit; the falsifier
 * arm (CST_SMP_DUP_FALSIFY) replays the previous claim through the same
 * predicates once per run so the plumbing is provably able to fire. */
static void smp_claim_check(uint32_t tid, const BBTemplate *t,
                            uint32_t lo, uint32_t hi, uint64_t seq,
                            unsigned int cpu_index, uint32_t depth)
{
    SmpTidLedger &L = g_smp_claims[tid];
    if (t->is_system) {
        /* A kernel entry breaks user-flow adjacency for this thread
         * (signal delivery, excursions): forget the claims rather than
         * reasoning across it. */
        L.last[0].valid = L.last[1].valid = false;
        return;
    }
    if (hi <= lo) {
        return;                     /* empty range: claims nothing */
    }
    g_stats.smp_dup_ledger_checks++;
    const SmpClaim cur{ t, lo, hi, seq, cpu_index, g_cst_emit_site,
                        g_segments_written, depth, true };
    const SmpClaim p1 = L.last[0];
    const SmpClaim p2 = L.last[1];
    const uint64_t cur_pc = smp_claim_start_pc(cur);
    auto live = [&](const SmpClaim &c) {
        return c.valid && c.seg == cur.seg && c.depth == cur.depth;
    };
    if (live(p1) && smp_claims_overlap(cur, p1) &&
        smp_succ_excludes(p1, cur_pc)) {
        /* Shape (B): the immediately preceding entry's instructions are
         * claimed again although its own resolved terminal cannot lead
         * here. */
        g_stats.smp_dup_adjacent_claims++;
        smp_claim_report("DUPLICATE adjacent claim", cur, p1, SmpClaim{});
    } else if (live(p1) && live(p2) && smp_claims_overlap(cur, p2) &&
               cur.bb_start == p2.bb_start && cur.bb_stop == p2.bb_stop &&
               smp_succ_excludes(p1, cur_pc)) {
        /* Shape (A): the block emitted two entries ago is re-emitted at a
         * position the intervening entry's resolved terminal makes
         * unreachable. */
        g_stats.smp_dup_wrongpc_reemit++;
        smp_claim_report("DUPLICATE re-emission one entry later", cur, p2,
                         p1);
    }
    /* Falsifier: prove the predicate + counter + report path can fire on
     * this run's own data (a synthetic re-claim of p1 behind itself —
     * never written to the wire). */
    static const bool falsify = getenv("CST_SMP_DUP_FALSIFY") != nullptr;
    static bool falsified = false;
    if (falsify && !falsified && live(p1) &&
        smp_claims_overlap(p1, p1) &&
        smp_succ_excludes(p1, smp_claim_start_pc(p1))) {
        falsified = true;
        g_stats.smp_dup_falsifier_fires++;
        smp_claim_report("FALSIFIER synthetic re-claim", p1, p1, SmpClaim{});
    }
    L.last[1] = p1;
    L.last[0] = cur;
}

/*
 * The close's THREAD_END pre-pass predicted whether a flush would emit;
 * @emitted is what it actually did.  A disagreement means the stamp may
 * sit one flush early or a context's close-final may be unstamped, so it
 * is counted (Stats::smp_close_stamp_mispredict) rather than left silent
 * — the validator's thread_end oracle remains the enforcement.
 *
 * A must-be-0 row that has never been SEEN to fire is not evidence of
 * anything: of the 70 instrumented SMP cells that reported this row
 * before the arm below existed, all 70 read 0 — equally consistent with
 * a correct prediction and with a detector wired to nothing.  CST_SMP_
 * STAMP_FALSIFY resolves that ambiguity by inverting the prediction once
 * per run at a flush that really ran, so the comparison, the counter and
 * the report are exercised on the run's own data.  It perturbs the copy
 * the COMPARISON reads — @predicted is taken by value, after the flush
 * has already run, and is read nowhere else — never the smp_last_emitter
 * map that decides the stamp, so no emission changes, exactly as CST_SMP_
 * DUP_FALSIFY's synthetic re-claim is never written to the wire.
 *
 * That is measured, not merely argued: a fixed user-mode program traced
 * armed and unarmed produces a byte-identical .cst while this row moves
 * 0 -> 1.  Reaching that measurement took three corrections worth
 * recording, because each first produced a confident wrong answer.  The
 * comparison needs a same-arm control (two unarmed runs differed, so the
 * first "the wire changed" verdict was measuring nothing); the outfile
 * path and the environment block both sit on the guest stack, so the arms
 * must share one output path and the control must set a DECOY variable of
 * equal length that the plugin never reads; and one 8-byte register field
 * holding a guest stack pointer varies between two runs of the SAME arm
 * and has to be masked before any cross-arm claim.  Under those controls
 * every arm hashes alike.  See validator-side ab_stamp.sh in the arc's
 * run directory.
 */
static void smp_stamp_mispredict_note(bool emitted, bool predicted)
{
    static const bool falsify = getenv("CST_SMP_STAMP_FALSIFY") != nullptr;
    static bool falsified = false;
    if (falsify && !falsified) {
        falsified = true;
        predicted = !predicted;
        if (cst_smp_diag()) {
            fprintf(stderr, "champsim_tracer: [smpdiag] FALSIFIER stamp "
                    "prediction inverted at a flush that %s\n",
                    emitted ? "emitted" : "emitted nothing");
        }
    }
    if (emitted != predicted) {
        g_stats.smp_close_stamp_mispredict++;
        if (cst_smp_diag()) {
            fprintf(stderr, "champsim_tracer: [smpdiag] close stamp "
                    "MISPREDICT: predicted %s, flush %s\n",
                    predicted ? "emit" : "no-emit",
                    emitted ? "emitted" : "emitted nothing");
        }
    }
}

/*
 * WHERE A PEER vCPU'S HELD SLOT GOT ITS EXTENT AT A CLOSE.
 *
 * Called once per peer-slot flush (PathBuilder::flush_final), with the
 * three facts already read off the machine: whether the note_prev_extent
 * STASH holds a measurement for the slot, whether the vCPU's retired
 * CURSOR can still name it, and whether the slot is that vCPU's CURRENT
 * in-flight head.  The classification is a strict priority — the stash was
 * taken at the first dispatch after prev and is therefore definitively
 * past, so it wins whenever it exists; the cursor belongs to a vCPU whose
 * thread may still be executing, and a slot that is the cursor's in-flight
 * head is a block the close is reading MID-FLIGHT.  Counters only: nothing
 * here is read by tracer logic, and flush_final re-derives the extent it
 * actually publishes from its own lookups.
 *
 * THE TWO ARMS.  Of the 400 instrumented x86_64 and mipsel cells that had
 * reported these rows, 76 saw the stash arm fire and NOT ONE ever saw the
 * live-cursor arm or the in-flight arm at anything but 0.  A row seen only
 * at 0 cannot distinguish "the stash answers for every slot a close finds"
 * from "the branch is unreachable and the row means nothing", which is the
 * same silent-false-success cad149f5be named for this pair's two siblings.
 * It turned out to be neither: a 160-cell aarch64+riscv64 system wave with
 * no arm anywhere classified 98 peer slots as 77 stash and 21 live cursor,
 * over 21 cells.  The old zero was an ISA blind spot.
 *
 * Both rows are classification outcomes rather than claims that work went
 * unpublished, so both arms are SYNTHETIC, in the CST_SMP_STAMP_FALSIFY
 * family: they perturb the copies of the three facts that the
 * CLASSIFICATION reads, once per run, and never the machine state those
 * facts were read from.  CST_SMP_PEER_LIVE_FALSIFY drives one real peer
 * close down the live-cursor arm; CST_SMP_PEER_INFLIGHT_FALSIFY drives one
 * down the in-flight arm inside it.  Each still requires a genuine peer
 * close with a genuine held slot to reach this function at all, so the arm
 * proves the predicate chain, the counters and the report lines are wired
 * to a reachable site rather than merely quiet.
 *
 * What the arm fabricates it also PRINTS: the diagnostic names the real
 * (stash, cursor, in-flight) triple beside the forced one, so an armed
 * run's record says what the machine actually reported.  Neither arm is on
 * by default and neither is read by tracer logic; being counters-only,
 * neither can change a byte of the wire.
 */
void smp_close_peer_extent_note(unsigned int cpu_index,
                                const BBTemplate *slot,
                                bool from_stash, bool from_cursor,
                                bool in_flight, uint64_t extent)
{
    static const bool falsify_live =
        getenv("CST_SMP_PEER_LIVE_FALSIFY") != nullptr;
    static const bool falsify_inflight =
        getenv("CST_SMP_PEER_INFLIGHT_FALSIFY") != nullptr;
    static bool falsified = false;

    if ((falsify_live || falsify_inflight) && !falsified) {
        falsified = true;
        if (cst_smp_diag()) {
            fprintf(stderr, "champsim_tracer: [smpdiag] FALSIFIER peer-slot "
                    "extent classification forced to %s at pc=0x%" PRIx64
                    " (real: stash=%d cursor=%d inflight=%d ran=%" PRIu64
                    ")\n",
                    falsify_inflight ? "IN-FLIGHT head" : "LIVE cursor",
                    slot ? slot->start_pc : 0,
                    (int)from_stash, (int)from_cursor, (int)in_flight,
                    extent);
        }
        from_stash = false;
        from_cursor = true;
        if (falsify_inflight) {
            in_flight = true;
        }
    }

    if (from_stash) {
        g_stats.smp_close_peer_stash_extent++;
        return;
    }
    if (!from_cursor) {
        return;
    }
    g_stats.smp_close_peer_live_cursor++;
    if (!in_flight) {
        return;
    }
    g_stats.smp_close_peer_inflight_head++;
    /*
     * THE DRIFT THE SNAPSHOT REMOVES, MEASURED RATHER THAN ASSERTED.
     *
     * @extent came from the close-time sample, taken before
     * TraceSegmentManager::finish() shut the observation sinks.  Read the
     * counter AGAIN here, live, at the moment the flush would have read
     * it: the difference is the number of instructions this peer executed
     * with nothing recording them, which is exactly what a live-cursor
     * extent would have published from the template with inherited field
     * values.  Zero on a peer that has not moved; positive says the fix
     * was load-bearing on this cell and by how much.  Read-only — it
     * changes no extent and reaches no wire.
     */
    if (slot) {
        const uint64_t cap = tb_head_insns(slot);
        uint64_t live = retired_in_flight(cpu_index);
        if (live > cap) {
            live = cap;
        }
        if (live > extent) {
            g_stats.smp_close_peer_inflight_drift++;
            g_stats.smp_close_peer_inflight_drift_insns += live - extent;
        }
        if (cst_smp_diag()) {
            fprintf(stderr, "[smpdiag] close peer slot is vCPU %u's "
                    "IN-FLIGHT head: pc=0x%" PRIx64 " ran=%" PRIu64
                    " live_at_flush=%" PRIu64 " closing_cpu=%u\n",
                    cpu_index, slot->start_pc, extent, live,
                    g_cst_closing_cpu);
        }
    }
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
                     bool branch_successor_known,
                     uint32_t bb_start,
                     uint32_t bb_stop,
                     bool thread_end)
{
    /*
     * USER-MODE EXACT-BUDGET WINDOW (S18 clean break at the budget).
     *
     * A finite user-mode icount/simpoint window bills EXACTLY its
     * budget: billing advances at emit by each entry's range width, so
     * the emission that would carry the wire past the remaining budget
     * is published as the partial range [start, start + remainder) — the
     * partial-entry rule of §4.2a — and any emission
     * after the budget is exhausted is outside the window and not
     * emitted at all.  The excluded instructions RAN (the deferred close
     * lets the crossing block execute and seal so the published prefix
     * is fully observed); they are outside every published range, so
     * they are un-billed from the raw clock (user_raw_clock_unbilled)
     * and the covered == wire identity holds at the budget close.
     *
     * The cut entry's terminating branch sits outside its range: the
     * successor is not this entry's to publish (branch_successor_known
     * false — the fault-split prefix precedent), and a wrong-path chain
     * hangs off a resolved branch, so it is dropped with it.  The entry
     * that exhausts the budget is by construction the segment's last
     * published entry of its context and carries CST_BB_FLAG_THREAD_END
     * whether or not the seal-stamp choreography saw the close coming.
     *
     * A REP fan-out parent is exempt (its iterations are indivisible on
     * the wire; the fan-out site counts the overrun instead), and the
     * whole block is skipped in system mode, where the marker clock
     * bills by retirement folds and budget closes may overshoot by
     * design.
     */
    if (!g_system_mode && bb_tmpl && !bb_tmpl->is_system &&
        g_trace_segments.is_active() &&
        g_trace_segments.window_stop() != UINT64_MAX) {
        const uint64_t budget = g_trace_segments.window_stop() -
                                g_trace_segments.window_start();
        const uint64_t done = g_seg_arch_user_insns;
        const uint64_t remaining = budget > done ? budget - done : 0;
        const uint32_t n = bb_tmpl->n_insns;
        uint32_t stop_c = bb_stop > n ? n : bb_stop;
        uint32_t start_c = bb_start > stop_c ? stop_c : bb_start;
        const uint32_t width = stop_c - start_c;
        const bool rep_parent = n > 0 && stop_c == n &&
            bb_tmpl->insn_fields[n - 1].rep_memops_per_iter > 0 &&
            g_template_store.seg_deref(bb_tmpl->rep_subtmpl) != nullptr;
        if (width > 0) {
            if (remaining == 0) {
                /* Past the budget: outside the window, not emitted (a
                 * REP parent too — suppressing it WHOLE splits no
                 * iteration, so the fan-out exemption does not apply
                 * here).  The block's observations are of instructions
                 * no published range claims — discard them so they
                 * cannot leak onto a later emission's positional
                 * sinks. */
                g_stats.user_budget_entries_suppressed++;
                g_stats.user_budget_insns_suppressed += width;
                user_raw_clock_unbilled(width);
                g_mem_recorder.clear_cp(cpu_index);
                pending_reg_snaps(cpu_index).clear();
                cp_chain_snap_mark(cpu_index) = 0;
                return;
            }
            if (width > remaining && !rep_parent) {
                const uint32_t new_stop = start_c + (uint32_t)remaining;
                /* Drop the tail's dst snaps BEFORE the positional
                 * backstop below sizes against the cut range — the
                 * surplus is provably the excluded tail's, at the BACK
                 * of the sink, so trim there (the backstop's front-trim
                 * arm exists for leaked prefixes, a different shape).
                 * Only when the sink holds exactly the full range's
                 * snaps; any other occupancy is left for the backstop to
                 * name. */
                if (g_features.reg_data) {
                    uint64_t exp_full = 0, exp_cut = 0;
                    for (uint32_t i = start_c; i < stop_c; i++) {
                        exp_full += bb_tmpl->insn_fields[i].n_dst_regs;
                        if (i < new_stop) {
                            exp_cut += bb_tmpl->insn_fields[i].n_dst_regs;
                        }
                    }
                    std::vector<RegSnap> &pend = pending_reg_snaps(cpu_index);
                    if (pend.size() == exp_full && exp_cut < exp_full) {
                        pend.resize(exp_cut);
                    }
                }
                g_stats.user_budget_final_partial++;
                g_stats.user_budget_final_cut_insns += width - remaining;
                user_raw_clock_unbilled(width - remaining);
                wp_entries.clear();
                wp_first_tb_unavail = false;
                branch_successor_known = false;
                bb_stop = new_stop;
                bb_start = start_c;
                thread_end = true;
            } else if (width == remaining && !rep_parent) {
                /* This entry exhausts the budget exactly at a block
                 * boundary: it is the last published entry.  (A REP
                 * parent is not stamped — its fan-out sub-entries follow
                 * in the same context, and a THREAD_END that is not the
                 * context's last entry is the lie the oracle rejects;
                 * the fan-out site's overrun row names the excess.) */
                thread_end = true;
            }
        }
    }

    /* warmup→simulation boundary capture (header §2.13,
     * warmup_end_trace_insn_idx): the trace-instruction index of the
     * first simulation-phase record.  Snapshot g_seg_arch_insns BEFORE
     * this entry's insns get added so the value points at the first
     * sim-phase record, not past it.
     *
     * The crossing itself (g_seg_warmup_crossed) is latched at DISPATCH
     * time on the window clock in tw_manage_window — not read live here
     * — because emissions lag execution (pending seal, fault deferral),
     * and a live read would move the boundary with emission timing:
     * observably, per-iteration translation (-icount) emits mid-REP
     * where chunk translation emits after the fault resolves, landing
     * the boundary at different records for identical guest execution.
     * The dispatch-time latch is on the corrected (translation-
     * invariant, bbv-coherent) clock, so the crossing names the same
     * architectural point in every arm.
     *
     * Boundary atomicity: the boundary never splits one architectural
     * instruction's records across the warmup/measure line (a fan-out
     * instruction — x86 REP, and MOPS when its facts land — renders one
     * record per iteration, across several emissions when QEMU chunks
     * or single-steps the loop, with fault/interrupt excursion records
     * interleaved).  While a fan-out instruction is architecturally in
     * flight on this vCPU (warmup_hold: begun, not retired — a
     * predicate that survives mid-instruction faults, unlike reenter),
     * the capture DEFERS past its remaining records, past excursion
     * records emitted between its chunks, and past PEER guest threads'
     * user records interleaved on this vCPU; the boundary then points
     * at the first record of the next architectural instruction.
     *
     * The release is per-slot and thread-aware, the same predicate as
     * the deferred-close hold below (which this boundary predated): a
     * peer thread's user record on this vCPU proves nothing about the
     * holder's instruction — the historical pc-or-kernel release let a
     * kernel REP completing between a user REP's chunks stand in for
     * the user instruction's retirement, and a peer's user record
     * placed the boundary mid-instruction (the cross-thread silent
     * split measured on the close side, probes/threadrep.S,
     * cst_runs/x86s2 item B).  Only a record from the HOLDER's own
     * thread at a different user pc proves the instruction
     * architecturally past (or the hold stale — a signal diverted it);
     * an ownerless dispatch arm (no emission yet) keeps the historical
     * structural release.
     *
     * Unlike the deferred window close, the boundary needs NO numeric
     * ceiling: it is a header field chosen from the record stream, not
     * a liveness event — deferring costs nothing but a later index,
     * and a capped placement would re-introduce the very
     * mid-instruction split the hold exists to prevent.  The one
     * unbounded case is a holder that never emits again (a thread
     * killed mid-instruction): its records have all been emitted, so
     * no placement can split it, and the segment finish names the
     * still-deferred boundary (warmup_boundary_unplaced_at_finish)
     * instead of inventing one; a placement with a structurally
     * released slot still active is counted too
     * (warmup_boundary_in_fanout), never silent. */
    if (g_seg_warmup_end_trace_insns == UINT64_MAX &&
        g_seg_warmup_crossed && g_trace_segments.is_active()) {
        /* CST_WMHOLD_OFF: measurement kill switch (behaviour gated,
         * condition census on both arms)
         * — restores the historical thread-blind pc-or-kernel
         * release so a paired probe wave measures the same condition
         * under both behaviours.  The census counters and the placement
         * tripwire run on both arms; only the peer-thread defer arrow is
         * gated. */
        static int wm_hold_off = -1;
        if (wm_hold_off < 0) {
            wm_hold_off = getenv("CST_WMHOLD_OFF") ? 1 : 0;
        }
        const RepSelfLoopState &rs_wh = rep_state(cpu_index);
        bool wm_defer = false;
        if (rs_wh.warmup_hold_any() && bb_tmpl) {
            const uint32_t rec_tid = resolve_thread_id(cpu_index);
            for (unsigned i = 0; i < RepSelfLoopState::REP_CLK_PCS; i++) {
                const RepBoundaryHold &h = rs_wh.warmup_hold[i];
                if (!h.active) {
                    continue;
                }
                if (bb_tmpl->start_pc == h.pc || bb_tmpl->is_system ||
                    (!wm_hold_off &&
                     h.tid != RepBoundaryHold::CST_HOLD_TID_UNKNOWN &&
                     h.tid != rec_tid)) {
                    wm_defer = true;
                }
                /* Ownerless slot, or the holder's own thread at a
                 * different user pc: the structural bound — this record
                 * does not defer on that slot.  Slot lifecycle stays
                 * with its owners (the emission-side update and the
                 * close-eval release); the placement tripwire below
                 * names any slot still active. */
            }
        }
        if (wm_defer) {
            g_stats.warmup_boundary_hold_defers++;
            g_seg_wm_deferred_records++;
        } else {
            if (rs_wh.warmup_hold_any()) {
                /* Placed with a hold slot still active: the ceiling
                 * forced it, or every live slot was structurally
                 * released (ownerless arm / holder-identity at another
                 * pc, which includes the indistinguishable no-SETTLS
                 * peer).  Names the possible split instead of reading
                 * a false zero. */
                g_stats.warmup_boundary_in_fanout++;
            }
            g_seg_warmup_end_trace_insns = g_seg_arch_insns;
        }
    }

    BodyEntry entry;
    entry.seq_num = g_trace_segments.next_seq_num();
    g_dbg_last_emit_seq = entry.seq_num;
    entry.template_id = bb_tmpl ? bb_tmpl->template_id : 0;
    entry.dyn_params.reserve(g_mem_recorder.cp_count(cpu_index));
    entry.wp_entries = std::move(wp_entries);
    entry.wp_first_tb_unavail = wp_first_tb_unavail;
    entry.tmpl = bb_tmpl;
    /* Executed range: caller-declared [bb_start, bb_stop), clamped to the
     * template (§4.2a).  Every call site states its range explicitly; the
     * range is not optional wire state and no site may leave it unset. */
    {
        uint32_t n = bb_tmpl ? bb_tmpl->n_insns : 0;
        if (bb_stop > n) {
            bb_stop = n;
        }
        if (bb_start > bb_stop) {
            bb_start = bb_stop;
        }
        entry.bb_start = bb_start;
        entry.bb_stop = bb_stop;
    }
    entry.thread_end = thread_end;
    entry.fault_depth = g_emit_fault_depth;
    /* Guest-thread identity on the wire.  cpu_index is a lookup key for the
     * per-vCPU identity (and for live register reads — regfile capture, WP
     * lane gates); the index itself never reaches the stream. */
    entry.thread_id = resolve_thread_id(cpu_index);
    if (tiddiag_on() && g_system_mode && cpu_index < CST_PIN_MAX_VCPUS) {
        bool sys = bb_tmpl && bb_tmpl->is_system;
        (sys ? g_tiddiag_kern_entries : g_tiddiag_user_entries)++;
        if (entry.thread_id != g_vcpu_user_tid[cpu_index]) {
            (sys ? g_tiddiag_kern_retagged : g_tiddiag_user_retagged)++;
        }
    }
    /* SMP attribution-pair claim ledger: one check per emitted entry, at
     * the entry's FINAL range and identity (see smp_claim_check above). */
    if (bb_tmpl) {
        smp_claim_check(entry.thread_id, bb_tmpl, entry.bb_start,
                        entry.bb_stop, entry.seq_num, cpu_index,
                        entry.fault_depth);
    }
    /* Context asid (regfile / FieldState table key ONLY): the process asid,
     * held stable across a kernel excursion.  Equals asid_index in user
     * mode / unpinned, so the key is unchanged there. */
    entry.ctx_asid_index = resolve_ctx_asid_index(cpu_index);
    /* Address-space identity on the wire: the compact index of the address
     * space THE BLOCK EXECUTED IN (index 0 in user mode / a single address
     * space, so those traces stay byte-identical).
     *
     * Not the live page-table root at the emit.  Emissions lag execution —
     * the deferred seal emits a block one TB later, and every close flush
     * emits blocks that ran arbitrarily earlier — so a live read names
     * whatever address space happens to be current when the writer runs.
     * At a SHUTDOWN close that is the process performing the poweroff: the
     * traced process's last block was stamped with a freshly minted index
     * for an address space that never executed a traced instruction, in a
     * pinned trace that format.rst says never switches the asid dimension
     * at all (measured: x86_64 poweroff cell, one entry of 9850863 carrying
     * asid=1, the closing walk's).  g_vcpu_cur_asid_index — the index of
     * the most recent USER TB on this vCPU, advanced AFTER the seal step —
     * names the block being emitted rather than the TB running now, and is
     * what resolve_ctx_asid_index returns under a pin.  Trace-all keeps the
     * live-root mapping (Stage B2: every context is emitted by its own
     * root, and no ctx latch is maintained there).
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
    if (marker_trace_all()) {
        entry.asid_index = resolve_asid_index(cpu_index);
    } else if (bb_tmpl && bb_tmpl->is_system) {
        entry.asid_index = entry.ctx_asid_index;
    } else {
        /* CST_ASID_LIVE: measurement kill switch (the CST_WMHOLD_OFF
         * pattern) — restores the historical live-root read so a paired
         * run measures the same close under both behaviours.  The
         * mismatch counter runs on both arms. */
        static int asid_live = -1;
        if (asid_live < 0) {
            asid_live = getenv("CST_ASID_LIVE") ? 1 : 0;
        }
        const uint32_t live_idx = resolve_asid_index(cpu_index);
        if (live_idx != entry.ctx_asid_index) {
            /* A USER block emitted while a foreign address space is live:
             * the emitting context is not the one the block ran in.  This
             * is also the exact set of entries whose wire tag the carry
             * changes, so a zero here proves a trace is byte-identical to
             * what the live read produced. */
            g_stats.emit_asid_foreign_context++;
        }
        entry.asid_index = asid_live ? live_idx : entry.ctx_asid_index;
    }
    entry.cpu_index = cpu_index;
    /* Terminal-branch outcome for the CST_FID_BRANCH_* singletons.  The
     * successor is the deferred-seal landing PC (collect_finalized_bbs'
     * frag_current_pc, threaded through emit_finalized_bb); unknown only for
     * the segment-final flush.  Stamped verbatim; direction/target are
     * derived from it at wire-emit time. */
    entry.branch_successor_pc    = branch_successor_pc;
    entry.branch_successor_known = branch_successor_known;

    /* CST_JUMP_DIAG: raise the syscall_fault_nesting step/anchor discipline
     * ONLINE, at the emit, with the depth pipeline's live state attached. */
    cst_jump_diag_emit(entry.seq_num, entry.thread_id,
                       bb_tmpl ? bb_tmpl->start_pc : 0, entry.fault_depth,
                       bb_tmpl && bb_tmpl->is_system ? 1 : 0, 0);

    g_mem_recorder.drain_cp_into_dyn_params(cpu_index, entry.dyn_params,
                                            bb_tmpl, entry.bb_start,
                                            entry.bb_stop);
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
     *   SHORTFALL — a tail snap the capture could not reach (a block the
     *     close stopped inside, whose later insns never ran).  Nothing to
     *     recover; drop this entry's reg-data rather than emit a mis-sliced
     *     stream.  Every shortfall is counted, and the ones emitted by a
     *     closing flush that an END marker routed are ALSO bucketed
     *     separately: the END close is deferred to its block's boundary and
     *     so is not itself a producer, but the bucket is what proves that
     *     rather than assuming it, and a run that always closes on the END
     *     marker is exactly the run that must not report a false zero. */
    if (g_features.reg_data && bb_tmpl) {
        /* Sum over the entry's DECLARED range, not the whole template: a
         * partial entry ([bb_start, bb_stop)) observes destination snaps
         * for exactly the instructions inside its range (§4.2a), and the
         * wire attributes positionally from bb_start.  Whole-block
         * entries make the two sums identical. */
        uint64_t expected_snaps = 0;
        for (uint32_t i = entry.bb_start; i < entry.bb_stop; i++) {
            expected_snaps += bb_tmpl->insn_fields[i].n_dst_regs;
        }
        if (pending_reg_snaps(cpu_index).size() > expected_snaps) {
            size_t excess = pending_reg_snaps(cpu_index).size() - (size_t)expected_snaps;
            if (getenv("CST_SNAP_DIAG")) {
                fprintf(stderr, "champsim_tracer: [snapdiag] reg-snap SURPLUS "
                        "BB start=0x%" PRIx64 " n_insns=%u pending=%zu "
                        "expected=%" PRIu64 " fdepth=%u is_sys=%d "
                        "— trimming %zu leaked prefix\n",
                        bb_tmpl->start_pc, bb_tmpl->n_insns,
                        pending_reg_snaps(cpu_index).size(), expected_snaps,
                        g_emit_fault_depth,
                        (int)bb_tmpl->is_system, excess);
            }
            pending_reg_snaps(cpu_index).erase(pending_reg_snaps(cpu_index).begin(),
                                    pending_reg_snaps(cpu_index).begin() + (ptrdiff_t)excess);
            g_stats.reg_snap_leak_trimmed++;
        } else if (pending_reg_snaps(cpu_index).size() != expected_snaps) {
            /*
             * COUNT IT ALWAYS.
             *
             * The bump used to sit behind `if (!g_seg_end_marker_close)`
             * while the clear() below ran unconditionally.  On a
             * marker-window trace the segment ALWAYS closes on the END
             * marker, so the flag was set for every entry emitted by the
             * closing flush and the counter could not observe the drop that
             * happens on every run — it reported 0 while a slice was
             * destroyed each time.  The carve-out also silenced two cases it
             * was never argued for: the MERGE-SURPLUS arm (a surplus on a
             * merged fault entry, which has nothing to do with an
             * END-truncated tail) and any unrelated shortfall that happens
             * to land in the same closing flush.  A global segment-close
             * flag cannot say whether THIS entry is the truncated block.
             *
             * The end-marker-close case is still separable — it goes in its
             * own bucket below — but it is no longer separable by being
             * invisible, and the magnitude of what was thrown away is
             * recorded next to the event.
             */
            const size_t n_discarded = pending_reg_snaps(cpu_index).size();
            g_stats.reg_snap_slice_dropped++;
            if (g_seg_end_marker_close) {
                g_stats.reg_snap_slice_dropped_end_close++;
            }
            g_stats.reg_snap_slice_drop_discarded += n_discarded;
            if (getenv("CST_SNAP_DIAG")) {
                fprintf(stderr, "champsim_tracer: [snapdiag] reg-snap "
                        "%s BB start=0x%" PRIx64 " n_insns=%u pending=%zu"
                        " expected=%" PRIu64 " end_marker=%d fdepth=%u "
                        "is_sys=%d — dropping reg_snaps\n",
                        pending_reg_snaps(cpu_index).size() < expected_snaps
                            ? "SHORTFALL" : "SURPLUS",
                        bb_tmpl->start_pc, bb_tmpl->n_insns,
                        pending_reg_snaps(cpu_index).size(), expected_snaps,
                        (int)g_seg_end_marker_close, g_emit_fault_depth,
                        (int)bb_tmpl->is_system);
                /*
                 * Name what is being thrown away.  The sink is POSITIONAL,
                 * so the k-th pending snap belongs to the k-th dst slot in
                 * the template's prefix-sum order — the same walk
                 * build_entry_view does.  Printing insn pc + register name +
                 * value turns "4 register deltas were discarded" from a
                 * count into an identified loss.
                 */
                const std::vector<RegSnap> &pv = pending_reg_snaps(cpu_index);
                size_t slot = 0;
                for (uint32_t i = 0; i < bb_tmpl->n_insns && slot < pv.size();
                     i++) {
                    const InsnFields *fi = &bb_tmpl->insn_fields[i];
                    for (uint8_t d = 0; d < fi->n_dst_regs &&
                                        slot < pv.size(); d++, slot++) {
                        const char *rn = "?";
                        if (bb_tmpl->insn_reg_names &&
                            bb_tmpl->insn_reg_names[i].dst_qemu_reg_keys &&
                            bb_tmpl->insn_reg_names[i].dst_qemu_reg_keys[d] &&
                            bb_tmpl->insn_reg_names[i]
                                .dst_qemu_reg_keys[d]->name) {
                            rn = bb_tmpl->insn_reg_names[i]
                                     .dst_qemu_reg_keys[d]->name;
                        }
                        fprintf(stderr, "champsim_tracer: [snapdiag]   "
                                "discarded slot %zu: insn[%u] pc=0x%" PRIx64
                                " dst[%u]=%s width=%u value=0x%016" PRIx64
                                "\n", slot, i,
                                bb_tmpl->insn_pcs ? bb_tmpl->insn_pcs[i] : 0,
                                d, rn, (unsigned)pv[slot].width_bytes,
                                pv[slot].value.limb[0]);
                    }
                }
                for (; slot < pv.size(); slot++) {
                    fprintf(stderr, "champsim_tracer: [snapdiag]   "
                            "discarded slot %zu: BEYOND the template's dst "
                            "slots width=%u value=0x%016" PRIx64 "\n",
                            slot, (unsigned)pv[slot].width_bytes,
                            pv[slot].value.limb[0]);
                }
            }
            pending_reg_snaps(cpu_index).clear();
        }
    }
    if (g_features.reg_data && !pending_reg_snaps(cpu_index).empty()) {
        entry.reg_snaps = std::move(pending_reg_snaps(cpu_index));
        pending_reg_snaps(cpu_index).clear();
        /* Restore a typical-BB capacity after the move stole the
         * allocation.  Otherwise every BB starts at cap=0 and the
         * first few push_backs pay realloc overhead — perf showed
         * std::vector<RegSnap>::_M_realloc_insert at 0.84% of total
         * runtime on mcf with regdata=1.  64 slots = 16 insns × 4
         * dst regs, well above mcf's 5-insn/2-dst-reg per BB. */
        pending_reg_snaps(cpu_index).reserve(64);
    }

    /*
     * Self-loop fan-out: split a single fan-out insn's TB-exec memop
     * stream into N iteration entries (iter 1 on @entry, iter 2..N on
     * rep_subtmpl).  Memops arrive in execution order under the insn's
     * PC, mpi per iteration, so the partition is a direct slice.
     *
     * mpi is the family's fan-out unit (see rep_memops_per_iter): one
     * architectural element for an x86 REP string op (1 for
     * LODS/STOS/SCAS/INS/OUTS, 2 for MOVS/CMPS), one memory access for
     * an AArch64 FEAT_MOPS bulk copy/set, whose transfer has no
     * architectural iteration and whose loads and stores arrive in
     * per-step runs rather than pairs.  The unit is what keeps the
     * unbounded issuers off the CST_FID_SLOT_COUNT clamp — a MOPS
     * memcpy of a megabyte reaches the wire as ~65K one-memop entries
     * instead of one entry with 65K memops of which 512 survive.
     *
     * WP entries and reg_snaps stay on iter 1: the WP simulator sees
     * the whole instruction as one architectural branch, and per-iter
     * register deltas (x86 RSI/RDI/RCX, MOPS Xd/Xs/Xn) ride the
     * field-delta stream like any repeated BB visit.
     */
    BBTemplate *rep_sub = bb_tmpl
        ? g_template_store.seg_deref(bb_tmpl->rep_subtmpl)
        : nullptr;
    /* The fan-out renders the template's LAST insn; a declared range that
     * excludes it (a split-emission prefix cut before the self-loop) has
     * nothing to fan.  A range that INCLUDES it (whole block, a fault
     * continuation, a rep-split piece [K, K+1)) fans normally. */
    if (rep_sub && bb_tmpl->n_insns > 0 &&
        entry.bb_stop == bb_tmpl->n_insns &&
        entry.bb_start < entry.bb_stop) {
        uint32_t last = bb_tmpl->n_insns - 1;
        const InsnFields *lf = &bb_tmpl->insn_fields[last];
        unsigned mpi = (unsigned)lf->rep_memops_per_iter;
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
            /*
             * Iteration count.  Prefer QEMU's architectural number, which
             * comes from the instruction's own loop-counter decrement and is
             * therefore the same whether do_gen_rep translated the whole
             * loop or a single iteration, and whether or not an exception
             * split the repetition.  The memop stream only says how many
             * callbacks were delivered, which the translation shape and a
             * mid-iteration fault both move.
             *
             * The fallback (memops / mpi) still covers the families QEMU has
             * no architectural iteration for: the AArch64 FEAT_MOPS bulk
             * copy/set, whose fan-out unit is one memory access rather than
             * an architectural element, never publishes a count, so its PC
             * never matches and it keeps the delivery-derived number.
             */
            RepSelfLoopState &rs = rep_state(cpu_index);
            /* Consume the emission handoff (see RepSelfLoopState::
             * emit_facts): the PathBuilder froze these facts WITH the
             * block being emitted, so a fault-deferred or suspended
             * emission reads the execution it describes, not whatever
             * the per-callback latch holds by now.  Consume-once: clear
             * before use so a path that failed to set it falls back and
             * is counted rather than silently reading a stale value. */
            RepArchFacts efacts = rs.emit_facts;
            bool evalid = rs.emit_facts_valid;
            uint64_t pre_iters  = rs.emit_pre_iters;
            uint64_t pre_memops = rs.emit_pre_memops;
            std::vector<std::pair<uint64_t, uint64_t>> pre_pieces =
                std::move(rs.emit_pre_pieces);
            rs.emit_facts_valid = false;
            rs.emit_pre_iters = 0;
            rs.emit_pre_memops = 0;
            rs.emit_pre_pieces.clear();

            bool     arch_known = (evalid && efacts.pc != 0 &&
                                   efacts.pc == bb_tmpl->insn_pcs[last]);
            size_t   n_iter;
            bool     rep_retired;
            /* Fault-split prefix (whole-BB merge): iterations retired and
             * REP memops delivered before the fault.  pre_i partitions the
             * merged memop stream; the surplus beyond pre_i*mpi is the
             * faulted iteration's aborted attempt, paired onto the
             * iteration that re-executed it. */
            size_t pre_i = 0, pre_m = 0;
            if (arch_known) {
                pre_i = (size_t)pre_iters;
                pre_m = (size_t)pre_memops;
                if (pre_m < pre_i * mpi) {
                    /* Degenerate prefix (suppressed capture): keep the
                     * count, drop the pairing offset. */
                    pre_m = pre_i * mpi;
                }
                n_iter      = pre_i + (size_t)efacts.iters;
                rep_retired = efacts.complete;
                g_stats.rep_iters_architectural++;
                size_t expected = n_iter * mpi + (pre_m - pre_i * mpi);
                if (rep_dps.size() != expected) {
                    /* Delivered memops disagree with the architectural
                     * count — capture was suppressed for part of the
                     * stream.  A COMPLETENESS check only: a multi-piece
                     * fault split delivers exactly this total too (each
                     * piece contributes iters*mpi + its aborted attempt),
                     * so pairing is carried by the piece table, never by
                     * this counter.  Recorded rather than silently
                     * absorbed by the old integer division. */
                    g_stats.rep_iters_memop_mismatch++;
                }
            } else {
                n_iter      = rep_dps.size() / mpi;
                rep_retired = true;
                g_stats.rep_iters_inferred++;
            }

            /*
             * Trailing pass over an instruction QEMU has already finished.
             * A single-iteration translation re-enters the REP once more
             * after its last iteration and takes the zero-count exit, doing
             * no architectural work.  Emitting it would add an instruction
             * the guest never executed — and add it only under the settings
             * that clear can_loop, which is exactly the setting-dependent
             * trace shape this accounting exists to remove.  A REP entered
             * with a zero counter is a different thing entirely: nothing was
             * in flight, so it falls through and emits its one entry below.
             */
            bool continuation = rs.cp_in_flight.in_progress &&
                                rs.cp_in_flight.pc == bb_tmpl->insn_pcs[last];
            if (arch_known) {
                rs.cp_in_flight.pc = bb_tmpl->insn_pcs[last];
                /* In flight for as long as QEMU keeps coming back to the
                 * instruction — which it does once more after the iteration
                 * that retired the repetition, hence reenter rather than
                 * !complete.  A REP_MAX chunk boundary sets both. */
                rs.cp_in_flight.in_progress = efacts.reenter;
                /* Warmup-boundary / deferred-close hold update: the
                 * ARCHITECTURAL predicate (a mid-instruction fault
                 * publishes reenter=false while the instruction is
                 * unfinished, and both consumers must keep deferring
                 * across it).  The table is pc-keyed, so an emission only
                 * ever updates ITS OWN instruction's slot — the hazard
                 * the old depth-0 user-only gate was added for
                 * (clear_page's rep stosq retiring between two user
                 * chunks releasing the USER hold) cannot recur, and the
                 * gate itself was a hole: a KERNEL fan-out in flight
                 * (chunked copy_to_user, a fault-split clear/copy) never
                 * armed, so a deferred window close could take inside it
                 * — the privilege gap the `window close in fan-out`
                 * tripwire counts.  Privilege-agnostic now; the entry's
                 * guest thread stamps the holder for the close's
                 * thread-aware release. */
                rs.warmup_hold_update(bb_tmpl->insn_pcs[last],
                                      !rep_retired, entry.thread_id);
            }
            if (arch_known && n_iter == 0 && continuation) {
                g_stats.rep_trailing_pass_dropped++;
                return;
            }

            /*
             * Leading pass of an instruction that has not yet done
             * anything.  A FEAT_MOPS bulk op whose very first byte
             * faults executes once for zero accesses and zero bytes,
             * takes the fault, and re-executes after the handler; the
             * re-execution delivers the whole instruction.  Emitting the
             * empty first pass would bill an extra architectural
             * instruction exactly when a demand fault (a clean
             * destination page) happens to land on the op — the
             * measured 256-vs-257 split.  Same principle as the
             * trailing pass, mirrored: nothing retired, nothing was
             * delivered, and the instruction's single wire rendering
             * comes from the execution that does the work.  Guarded to
             * the 1-insn re-entry shape so a multi-insn block's other
             * instructions can never lose their memops or accounting;
             * any other shape is kept and counted for visibility.
             */
            if (arch_known && n_iter == 0 && !rep_retired && !continuation) {
                if (bb_tmpl->n_insns == 1 && rep_dps.empty() &&
                    other_dps.empty()) {
                    g_stats.rep_unretired_pass_dropped++;
                    return;
                }
                g_stats.rep_unretired_pass_kept++;
            }

            /*
             * FEAT_MOPS byte anchor (counts from architectural state):
             * the fan-out unit for a bulk op is one memory access, so
             * the entry count is the delivered access count — but the
             * helpers publish the instruction's own size-register
             * progress (qemu_plugin_rep_bytes), and on a cleanly
             * completed single-execution instance the delivered access
             * sizes must sum to exactly that.  Checked here, where both
             * sides describe the same execution; fault-split and
             * continuation renderings are excluded (their bytes and
             * their deliveries legitimately land in different
             * executions of the same instruction).  x86 REP publishes
             * no bytes and is never checked.
             */
            if (arch_known && efacts.bytes != 0 && rep_retired &&
                !continuation && pre_i == 0 && pre_m == 0) {
                /* Per direction: a SET delivers one store per byte moved;
                 * a CPY delivers one load AND one store per byte moved. */
                uint64_t ld_bytes = 0, st_bytes = 0;
                bool sizes_known = true;
                for (const DynParam &dp : rep_dps) {
                    if (dp.data_size == 0) {
                        sizes_known = false;
                        break;
                    }
                    if (dp.type == DYN_LOAD_ADDR) {
                        ld_bytes += dp.data_size;
                    } else {
                        st_bytes += dp.data_size;
                    }
                }
                if (!sizes_known) {
                    g_stats.mops_bytes_unchecked++;
                } else if (st_bytes == efacts.bytes &&
                           (ld_bytes == 0 || ld_bytes == efacts.bytes)) {
                    g_stats.mops_bytes_checked++;
                } else {
                    g_stats.mops_bytes_mismatch++;
                }
            }

            /*
             * Terminal successor.  When a single-iteration translation
             * retires the instruction it still jumps back to the REP's own
             * PC before taking the zero-count exit, so the observed
             * successor is the self-loop even though architecturally the
             * instruction fell through.  Recover the architectural edge, so
             * the emitted direction/target sequence matches the one a
             * looping translation produces.
             */
            if (arch_known && rep_retired && n_iter >= 1 &&
                entry.branch_successor_pc == bb_tmpl->insn_pcs[last]) {
                entry.branch_successor_pc = bb_tmpl->fall_through_pc;
                g_stats.rep_exit_edge_recovered++;
            }

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

                /* Iteration k's slice of the REP memop stream.  Plain
                 * k*mpi normally; across a fault-split whole-BB merge the
                 * stream is one run per fault PIECE — [piece j's retired
                 * iterations][piece j's aborted attempt] — followed by the
                 * re-delivered rest, and each piece's aborted-attempt
                 * surplus belongs to the iteration that faulted at THAT
                 * piece's end, rendered as [aborted memops][re-executed
                 * mpi] — the same shape the single-iteration translation's
                 * merge gives the same fault.  The piece table places every
                 * middle surplus; the totals alone cannot (they shifted
                 * every slice after the first fault of a multi-piece
                 * split).  Bounded by what was actually delivered: with an
                 * architectural count the two can differ, and the
                 * iteration count stays architectural while the memops
                 * stay whatever really happened. */
                struct RepSeg {
                    size_t start, n, off, sb;   /* iters [start,start+n) at
                                                 * stream offset off; first
                                                 * iteration re-executes sb
                                                 * aborted memops */
                };
                std::vector<RepSeg> rep_segs;
                bool segs_ok = false;
                /* Only an architectural count partitions the stream by
                 * piece: without it n_iter came from the delivered memops
                 * themselves and pre_i/pre_m were never read, so the table
                 * describes a prefix this emission is not rendering. */
                if (arch_known && !pre_pieces.empty()) {
                    /* Two tests, and they are not the same test.
                     *
                     * No piece may deliver fewer REP memops than its own
                     * retired iterations require: that piece had capture
                     * suppressed part-way, its boundary is not where the
                     * table says, and every slice after it would shift.
                     * This is the detector.
                     *
                     * The sums are a construction invariant — collect_piece
                     * appends the pair in the same statement that adds it
                     * to the totals, so they can only disagree if those two
                     * seams drift apart in a later edit.  Kept as a
                     * tripwire, compared against the RAW handoff scalars
                     * because pre_m above may already have been clamped up
                     * to pre_i*mpi by exactly the suppressed-capture case
                     * the first test catches.
                     *
                     * A table failing either is unusable: fall back to the
                     * total-based split and COUNT it rather than mis-place
                     * slices. */
                    uint64_t sum_i = 0, sum_m = 0;
                    bool bad = false;
                    for (const auto &p : pre_pieces) {
                        if (p.second < p.first * mpi) {
                            bad = true;
                        }
                        sum_i += p.first;
                        sum_m += p.second;
                    }
                    if (bad || sum_i != pre_iters || sum_m != pre_memops) {
                        g_stats.rep_piece_table_degenerate++;
                        /* Never observed (see the counter's comment in
                         * stats.h): every capture-suppression mechanism is
                         * structurally disjoint from the retired
                         * iterations of a piece-carrying instruction, so a
                         * firing means a capture-gating edit broke that
                         * disjointness and the totals split below is
                         * MIS-PAIRING slices.  A trace shaped by this must
                         * name itself — a counter alone is a silent
                         * success. */
                        if (unknown_warn_file) {
                            g_mutex_lock(&unknown_warn_lock);
                            fprintf(unknown_warn_file,
                                    "rep_piece_table_degenerate: pc=0x%"
                                    PRIx64 " pieces=%zu sum_i=%" PRIu64
                                    "/%" PRIu64 " sum_m=%" PRIu64 "/%"
                                    PRIu64 " bad_piece=%d — falling back "
                                    "to the totals split; per-iteration "
                                    "pairing of this emission is NOT "
                                    "trustworthy\n",
                                    bb_tmpl->insn_pcs[last],
                                    pre_pieces.size(), sum_i, pre_iters,
                                    sum_m, pre_memops, (int)bad);
                            fflush(unknown_warn_file);
                            g_mutex_unlock(&unknown_warn_lock);
                        }
                    } else {
                        size_t cum = 0, off = 0, pend = 0;
                        for (const auto &p : pre_pieces) {
                            if (p.first > 0) {
                                rep_segs.push_back({cum, (size_t)p.first,
                                                    off, pend});
                                pend = 0;
                            }
                            cum += (size_t)p.first;
                            off += (size_t)p.second;
                            pend += (size_t)(p.second - p.first * mpi);
                        }
                        /* Resume-suffix segment (empty on a suffix-less
                         * unwind flush: its start clamps the loop below
                         * and the dangling last surplus is never read). */
                        rep_segs.push_back({cum, n_iter - cum, off, pend});
                        segs_ok = true;
                    }
                }
                auto rep_slice = [&](size_t k, size_t &lo, size_t &hi) {
                    if (segs_ok) {
                        lo = hi = rep_dps.size();
                        for (const RepSeg &s : rep_segs) {
                            if (k >= s.start && k < s.start + s.n) {
                                lo = s.off + (k - s.start) * mpi;
                                hi = lo + mpi;
                                if (k == s.start) {
                                    lo -= std::min(s.sb, lo);
                                }
                                break;
                            }
                        }
                    } else if (pre_m == 0 || k < pre_i) {
                        lo = k * mpi;
                        hi = lo + mpi;
                    } else if (k == pre_i) {
                        lo = pre_i * mpi;
                        hi = pre_m + mpi;
                    } else {
                        lo = pre_m + (k - pre_i) * mpi;
                        hi = lo + mpi;
                    }
                    lo = std::min(lo, rep_dps.size());
                    hi = std::min(hi, rep_dps.size());
                };

                /* Iter 1: parent BB template + non-REP memops + iteration
                 * 0's slice. */
                entry.dyn_params = std::move(other_dps);
                size_t s0, e0;
                rep_slice(0, s0, e0);
                entry.dyn_params.reserve(entry.dyn_params.size() + (e0 - s0));
                for (size_t j = s0; j < e0; j++) {
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
                    (uint64_t)(entry.bb_stop - entry.bb_start)
                    + (uint64_t)(n_iter - 1);
                /* Wire-side twin of OWNED_CP: the same sum a reader
                 * reconstructs with cst_decode --templates-only, computed
                 * here so the clock-vs-wire residual needs no decoder. */
                if (bb_tmpl && !bb_tmpl->is_system) {
                    g_stats.wire_user_arch_insns +=
                        (uint64_t)(entry.bb_stop - entry.bb_start) +
                        (uint64_t)(n_iter - 1);
                    g_seg_arch_user_insns +=
                        (uint64_t)(entry.bb_stop - entry.bb_start) +
                        (uint64_t)(n_iter - 1);
                    /* THE ONE LEGITIMATE WAY THE WIRE OUTRUNS THE RETIRED
                     * CURSOR.  A self-looping instruction is fanned out to
                     * one entry per iteration on purpose, but the guest
                     * BEGAN it once, so insn_started — and therefore
                     * user_clock_retired_insns — counts 1 where the wire
                     * carries n_iter.  Counting the surplus at its source
                     * turns the retired-vs-wire falsifier from "these two
                     * numbers differ" into an identity that has to hold
                     * exactly: retired + this == wire.  Anything the fan-out
                     * does not account for is then a real over-claim and
                     * says so, instead of hiding inside a slack term.
                     *
                     * A FAULT-CUT PIECE'S PARENT ENTRY IS SURPLUS TOO.  A
                     * rep-split piece (§4.2a overlap) renders the retired
                     * iterations of an execution neither clock keeps a
                     * count for: the piece ends in the fault
                     * (reenter=false, complete=false), so its start was
                     * re-credited (raw clock) / its retirement fold never
                     * happened (window clock), and the one count the
                     * instruction keeps lands on the completing
                     * execution's piece.  The cut piece's parent range
                     * therefore adds wire with nothing billed behind it —
                     * one more surplus, on exactly the fault-ended shape.
                     * Re-enter exits stay at n_iter - 1: a chunk boundary
                     * is billed on both clocks, and the off-boundary
                     * single-iteration pass is billed on the raw clock
                     * (its window-clock withhold is a pre-existing
                     * comparator residual of the -icount regime, named by
                     * rep_clock_ticks_withheld, not folded here). */
                    {
                        uint64_t fan_surplus = (uint64_t)(n_iter - 1);
                        if (arch_known && !rep_retired && !efacts.reenter) {
                            fan_surplus += 1;
                        }
                        g_stats.wire_user_rep_extra_insns += fan_surplus;
                    }
                    /* Exact-budget tripwire: a fan-out parent is exempt
                     * from the S18 budget cut (its iterations are
                     * indivisible on the wire), so a finite user window
                     * whose budget lands inside a REP overruns here.
                     * Named, never silent. */
                    if (!g_system_mode &&
                        g_trace_segments.window_stop() != UINT64_MAX) {
                        uint64_t bud = g_trace_segments.window_stop() -
                                       g_trace_segments.window_start();
                        if (g_seg_arch_user_insns > bud) {
                            uint64_t over = g_seg_arch_user_insns - bud;
                            if (over > g_stats.user_budget_rep_overrun_insns) {
                                g_stats.user_budget_rep_overrun_insns = over;
                            }
                        }
                    }
                }
                /* Iter 2..N: rep_subtmpl, mpi memops each, insn_index
                 * remapped to 0 (sub has exactly one insn).  One reused
                 * BodyEntry across iterations keeps the per-sub dyn_params /
                 * reg_snaps buffers allocated once (a hot path on
                 * memset/memcpy-heavy kernels) instead of per iteration. */
                BodyEntry sub_e;
                sub_e.template_id = rep_sub->template_id;
                sub_e.tmpl        = rep_sub;
                sub_e.bb_start    = 0;
                sub_e.bb_stop     = rep_sub->n_insns;
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
                 */
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
                    size_t sk, ek;
                    rep_slice(k, sk, ek);
                    for (size_t j = sk; j < ek; j++) {
                        DynParam dp = rep_dps[j];
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
            /* n_iter <= 1 falls through to the single-entry emission
             * below.  A fault-cut piece that retired exactly ONE
             * iteration is the degenerate fan-out: its parent range
             * still adds the instruction's width with nothing billed
             * behind it (the count lands on the completing execution),
             * so it carries the same one-entry surplus. */
            if (bb_tmpl && !bb_tmpl->is_system && arch_known &&
                n_iter == 1 && !rep_retired && !efacts.reenter) {
                g_stats.wire_user_rep_extra_insns += 1;
            }
        }
    }

    if (out_stream) {
        body_stream_write_entry(out_stream, &entry);
    }
    /* BILLING AT EMIT: covered advances by the EMITTED RANGE's width, never
     * the template's — an entry that declares [start, stop) claims exactly
     * that many architectural instructions (§4.2a). */
    g_seg_arch_insns += (uint64_t)(entry.bb_stop - entry.bb_start);
    if (bb_tmpl && !bb_tmpl->is_system) {
        g_stats.wire_user_arch_insns +=
            (uint64_t)(entry.bb_stop - entry.bb_start);
        g_seg_arch_user_insns +=
            (uint64_t)(entry.bb_stop - entry.bb_start);
    }
}

/*
 * Snaps at the FRONT of pending_reg_snaps that belong to the in-flight CP
 * chain — i.e. to fragments already appended but not yet finalized into an
 * emitted true BB.  Maintained only here and by the suspend/resume arrows;
 * see cp_chain_append for why it exists.
 */
static size_t g_cp_chain_snap_mark[CST_PIN_MAX_VCPUS];

size_t &cp_chain_snap_mark(unsigned int cpu_index)
{
    return g_cp_chain_snap_mark[cpu_index < CST_PIN_MAX_VCPUS
                                ? cpu_index : CST_PIN_MAX_VCPUS - 1];
}

/*
 * Append a CP fragment to the true-BB chain (per-exec seal walk).
 *
 * The reg-snap sink is POSITIONAL, so it has to follow the chain exactly.
 * When append_fragment discards an in-flight chain — the interrupted-BB
 * case: our kernel block runs half a true BB, an async window swallows the
 * rest, and control comes back at an unrelated PC — those fragments will
 * never be emitted, but their per-insn dst snaps were already captured and
 * sit at the front of the sink.  Left there they become the next block's
 * "leaked prefix": the emit-time backstop saw pending=3 against expected=1
 * and trimmed 2, which recovers the COUNT while silently attributing the
 * wrong values (the recovered stream passes the dataflow oracle only
 * because the trim happens to leave this block's own snaps intact).  Drop
 * them with the fragments that own them, and count the condition.
 */
static inline void cp_chain_append(unsigned int cpu_index, BBTemplate *frag)
{
    uint32_t dropped_insns = 0;
    /* What is about to be discarded, named before it is gone. */
    const bool will_discard = cp_chain(cpu_index).would_discard(frag->start_pc);
    const bool dropped_system = will_discard &&
                                cp_chain(cpu_index).in_flight_is_system();
    if (will_discard && getenv("CST_CHAINDROP_DIAG")) {
        cp_chain(cpu_index).describe_in_flight(stderr, frag->start_pc);
    }
    const bool dropped_chain =
        cp_chain(cpu_index).append_fragment(frag->start_pc, frag,
                                            frag->fall_through_pc,
                                            (TbTerminus)frag->terminus,
                                            &dropped_insns);
    /* The chain is dropped whether or not reg-data capture is on, so the
     * chain counter is bumped before the reg-data early-out.  Behind it,
     * "CP chains dropped on discontinuity" read 0 on every regdata=0 run
     * and meant "not measured", not "did not happen". */
    if (dropped_chain) {
        g_stats.reg_snap_chain_drops++;
        g_stats.reg_snap_chain_drop_insns += dropped_insns;
        /* Split by privilege.  A kernel block lost here and a USER block
         * lost here are the same defect but not the same number: only the
         * user one is inside the quantity the window clock counts, so a
         * single total cannot say whether a clock-vs-wire residual is
         * explained by these drops or is a second mechanism. */
        if (dropped_system) {
            g_stats.reg_snap_chain_drop_sys_insns += dropped_insns;
        } else {
            g_stats.reg_snap_chain_drop_user_insns += dropped_insns;
        }
    }
    if (!g_features.reg_data) {
        return;
    }
    std::vector<RegSnap> &pend = pending_reg_snaps(cpu_index);
    size_t &mark = cp_chain_snap_mark(cpu_index);
    if (dropped_chain) {
        /* min(): the mark can outlive its snaps (an emit or a segment
         * reset empties the sink without a chain event), and an
         * over-erase would corrupt the very stream this protects. */
        const size_t n = mark < pend.size() ? mark : pend.size();
        if (n) {
            pend.erase(pend.begin(), pend.begin() + (ptrdiff_t)n);
            g_stats.reg_snap_chain_drop_discarded += n;
        }
    }
    /* Everything now pending belongs to the chain this fragment is in:
     * earlier entries are earlier fragments of the same chain, and the
     * fragment just appended pushed the rest. */
    mark = pend.size();
}

/* Finalize and reset the CP chain if it now forms a complete true BB.
 * Returns the finalized template (the caller emits/records it) or
 * nullptr if the BB is not yet complete.  Resetting immediately lets a
 * subsequent fragment in the same walk start a fresh chain at its own
 * entry_pc instead of being appended onto the just-committed BB. */
static inline BBTemplate *cp_chain_finalize_if_complete(unsigned int cpu_index)
{
    if (cp_chain(cpu_index).bb_complete() && cp_chain(cpu_index).has_active_chain()) {
        BBTemplate *bb_tmpl = cp_chain(cpu_index).finalize();
        cp_chain(cpu_index).reset();
        return bb_tmpl;
    }
    return nullptr;
}

/*
 * CST_NO_PEER_FLUSH: the falsifier arm for the peer pending-seal flush.
 * With it set the close reverts to flushing only the closing vCPU's slot,
 * which is what the peer flush exists to fix -- so a run pair with and
 * without it measures the drop the fix removes, instead of asserting it.
 * A falsifier arm, not a capture.
 */
/*
 * CST_NO_PEER_HOLDERS: the falsifier arm for the peer gate itself.  The loop
 * used to ask `if (!b || !b->prev()) continue;` -- the pending-seal SLOT and
 * nothing else -- so a peer vCPU holding an in-flight chain or a captured
 * reg-snap sink behind an EMPTY slot was skipped whole, and with it the
 * flush's chain arm, which no other path reaches.  With this set the gate
 * reverts to the slot-only question, so a run pair measures what the wider
 * gate recovers.  A falsifier arm, not a capture.
 */
static bool peer_holders_falsifier(void)
{
    static const bool v = []() {
        if (getenv("CST_NO_PEER_HOLDERS") == nullptr) {
            return false;
        }
        fprintf(stderr, "champsim_tracer: CST_NO_PEER_HOLDERS — a peer vCPU "
                "whose pending-seal slot is empty is skipped at the close "
                "even when it holds fault frames, suspensions or a chain.  "
                "This trace is missing instructions the guest executed; it "
                "is a falsifier arm, not a capture.\n");
        return true;
    }();
    return v;
}

static bool peer_flush_falsifier(void)
{
    static const bool v = []() {
        if (getenv("CST_NO_PEER_FLUSH") == nullptr) {
            return false;
        }
        fprintf(stderr, "champsim_tracer: CST_NO_PEER_FLUSH — peer vCPU "
                "pending-seal slots are DROPPED at the close.  This trace "
                "is missing instructions the guest executed; it is a "
                "falsifier arm, not a capture.\n");
        return true;
    }();
    return v;
}

/*
 * CST_NO_CLOSE_ORDER: the falsifier arm for the close's flush ORDER.  With
 * it set the close reverts to flushing its own vCPU first and the peers
 * after it in ascending vCPU order — appending blocks the guest ran EARLIER
 * behind blocks it ran later, which is what breaks strand sequentiality on
 * the wire.  A falsifier arm, not a capture.
 */
static bool close_order_falsifier(void)
{
    static const bool v = []() {
        if (getenv("CST_NO_CLOSE_ORDER") == nullptr) {
            return false;
        }
        fprintf(stderr, "champsim_tracer: CST_NO_CLOSE_ORDER — the close "
                "flushes its own vCPU before every peer regardless of when "
                "their blocks ran, so a (thread_id, asid) context can carry "
                "an earlier block behind a later one.  This trace's body is "
                "out of program order; it is a falsifier arm, not a "
                "capture.\n");
        return true;
    }();
    return v;
}

/*
 * Finalize and write the current trace segment.  Must be called with
 * exec_lock held.
 *
 * @prev_executed says whether the calling thread's pending-seal slot
 * holds a TB that has run (see PathBuilder::flush_final).  A close that
 * fires where the guest happens to be — process exit, the dead-latch
 * sweep, the stall ceiling — closes on a TB that executed and walks it.
 * The closes DEFERRED to a true-BB boundary do not: the icount and
 * simpoint window closes and the END-marker close all take at a step
 * tail whose slot holds the next, freshly promoted TB, so they pass
 * prev_executed=false and the block they were waiting for has already
 * been emitted by that step's ordinary seal.
 */
static void finish_trace_segment(bool prev_executed = true,
                                 unsigned int closing_cpu = UINT32_MAX,
                                 bool prev_in_flight = false)
{
    /* SMP condition census: name the closing vCPU for the duration of the
     * close so flush_final can classify PEER-slot drains (see
     * g_cst_closing_cpu).  UINT32_MAX (the plugin-exit route) means every
     * builder is a peerless flush and the peer counters stay silent. */
    g_cst_closing_cpu = closing_cpu;

    /* Sample every vCPU's in-flight retired extent NOW, while the capture
     * is still recording, so the census and the flush hook below both read
     * a stable number instead of a counter a peer is still advancing with
     * its observation sinks already shut (see retired_close_extent_arm).
     * This is the first statement of the close for that reason: everything
     * after it — the pre census, finish()'s active_ clear, the peer flush
     * order — must see the same extents. */
    retired_close_extent_arm();

    /* Segments actually finalised to a file.  The SimPoint report counts
     * captures with THIS, not with the schedule iterator's index: the
     * iterator only advances on a budget close, so a schedule ended by an
     * END marker — which terminates without advancing, by ruling — would
     * otherwise report the segment it DID write as untraced, which reads
     * exactly like the schedule never having run at all. */
    g_segments_written++;

    /* The lagged retired attribution of the in-flight block is closed out
     * by user_clock_close_credit, called from each builder's flush_final
     * with the extent that flush PUBLISHES.  It used to be folded here
     * from the retired cursor directly — which counts the END-firing
     * instruction (begun, mid-callback, unobserved) and the un-snapped
     * tail that the flush's stop rule excludes, so every END/ceiling
     * close billed exactly the boundary instructions the wire honestly
     * refused to claim (clock_minus_wire=+1 on every marker cell), and
     * it covered only the closing vCPU, so a peer slot flushed at an SMP
     * close was published but never billed (clock_minus_wire=-N). */

    uint64_t lo = g_trace_segments.window_start();
    uint64_t hi = g_trace_segments.window_stop();

    /* Hand the warmup→simulation arch-insn boundary to the body
     * stream so body_stream_finish writes it into the header
     * (§2.13 in docs/format.rst). */
    if (BodyStreamState *bs = g_trace_segments.body_stream()) {
        body_stream_set_warmup_end_trace_insn_idx(
            bs, g_seg_warmup_end_trace_insns);
    }
    /* A crossed boundary the fan-out hold was still deferring when the
     * segment closed goes to the header as the sentinel (the honest
     * value: no placement exists that provably avoids splitting the
     * held instruction the consumer cannot see the end of) — but never
     * silently: the counter and the line below name it. */
    if (g_seg_warmup_crossed &&
        g_seg_warmup_end_trace_insns == UINT64_MAX &&
        g_seg_wm_deferred_records > 0) {
        g_stats.warmup_boundary_unplaced_at_finish++;
        fprintf(stderr, "champsim_tracer: warmup boundary still held by an "
                "in-flight fan-out instruction at segment finish (%" PRIu64
                " records deferred) — header keeps the sentinel\n",
                g_seg_wm_deferred_records);
    }
    /*
     * ---- THE CLOSE CENSUS ----
     *
     * Every structure that can hold instructions the guest RETIRED and the
     * tracer has not put on the wire, read at this close: the pending-seal
     * slots (this vCPU's and every peer's), the cross-phase walk snapshot,
     * the in-flight true-BB chains, the open fault frames, the suspended
     * prevs and their four frozen sinks, the positional reg-snap sink and
     * its chain mark, the CP memop buffer and its straggler carry, the
     * retained fault events, the self-loop fan-out facts, the warmup hold,
     * an open wrong-path session, and the queued device-I/O records.
     *
     * Taken TWICE.  "pre" is what the close inherited; "post" is what
     * survived the flush hook, and the post pass is the one that feeds the
     * held_at_close ledger — so a holder with a working drain reads
     * non-zero pre and zero post, and a holder with no drain reads the
     * same both times.  That difference is the whole instrument: five
     * previous rounds each closed one holder and asserted the rest were
     * empty, and none of them could show it.
     */
    static const bool census_print = getenv("CST_CLOSEDROP") != nullptr;
    /* Name the close ROUTE, not just the flush mode: "exec"/"deferred"
     * lumped the END marker, the dead latch and the plugin_exit teardown
     * into one string, and a census whose rows cannot be grouped by close
     * reason cannot answer "which holders are occupied at which kind of
     * close". */
    const char *census_why =
        g_seg_close_reason ? g_seg_close_reason
        : (closing_cpu == UINT32_MAX ? "EXIT"
           : (g_seg_end_marker_close ? "END"
              : (prev_executed ? "exec" : "BUDGET")));
    g_stats.census_closes++;
    /*
     * OPEN THE UNSEALED-AT-CLOSE WINDOW.
     *
     * Everything the close's flush hook seals without a terminating branch
     * is attributed to THIS close and to the route named above, so the
     * per-close peak has a close to be per, and every unsealed block can
     * name what stopped it.  Closed after the flush hook returns; the
     * ledger ignores any seal taken outside the window (the departure and
     * migration drains, which are not stopping points).
     */
    close_unsealed_begin(census_why);
    /*
     * MIRRORED TO THE STATS FILE, NOT ONLY TO stderr.  In user mode the
     * guest's exit syscall reaches plugin_exit through preexit_cleanup
     * AFTER QEMU has torn its log fd down (see the note beside
     * qemu_plugin_outs in plugin_exit), so a close taken there writes its
     * census into a closed stderr and the run reports nothing.  A census
     * whose output can silently vanish on one whole mode is not evidence.
     */
    path_builder_close_state_report(stderr, census_why, closing_cpu,
                                    "pre", census_print, /* ledger= */ false);
    if (census_print && stats_file) {
        path_builder_close_state_report(stats_file, census_why, closing_cpu,
                                        "pre", true, /* ledger= */ false);
    }

    /* Drain any chain still in flight.  This may call emit_body_entry
     * one or more times, which bumps g_seg_arch_insns — so we print
     * the per-segment stats AFTER finish() returns so the counter
     * reflects the entire segment, including the trailing chain. */
    g_trace_segments.finish([&]() {
        if (closing_cpu != UINT32_MAX) {
            /*
             * PEERS, AND THE ORDER THEY GO ON THE WIRE IN.
             *
             * A close happens on ONE vCPU's dispatch, but on an SMP guest
             * the pinned process may have run on others and left each of
             * them holding a pending-seal slot: a TB that EXECUTED and
             * whose emission was waiting for a next owned dispatch that
             * never came, because the process migrated away.  Those slots
             * used to be dropped, and the instructions in them with it --
             * measured on aarch64 -smp 4 as clock_minus_wire = +6..+16 in
             * exactly the runs where the migration guard fired, and zero in
             * every run where it did not.  Retired-but-never-emitted is a
             * DROP, so the peers are flushed here too.
             *
             * They cannot be flushed in ANY order, though, and flushing the
             * closing vCPU first was the wrong one.  A block a peer is still
             * holding is by construction one the pinned thread ran BEFORE it
             * left that vCPU, so appending it behind the closing vCPU's own
             * final block puts earlier work behind later work in the same
             * (asid, thread_id) context -- and docs/format.rst promises a
             * consumer strand sequentiality: filtered to one context the
             * entries read as a single instruction stream in order, with
             * breaks only at nesting boundaries the format makes visible
             * (fault_depth changes, privilege-domain gaps).  A tail append
             * at the same depth and the same privilege is none of those.
             * Measured on an x86_64 -smp 4 churn cell: the segment's last
             * user entry was vCPU 1's held block at 0x401478, which does not
             * continue the block vCPU 0 emitted before it, and the
             * validator's thread_chain check reports it as an orphan.
             *
             * So the flushes are ordered by the shared dispatch clock
             * (g_promote_seq), ascending: the vCPU the thread left earliest
             * empties first and the closing vCPU -- which promoted at this
             * very dispatch -- empties last.  Ties (a builder that never
             * promoted) fall back to vCPU index, so the order is
             * deterministic.  Each peer's extent still comes from the
             * measurement taken at the first dispatch after its prev
             * (note_prev_extent), because the retired cursor on a vacated
             * vCPU has long since rolled past.
             */
            const bool no_peers = peer_flush_falsifier();
            const bool slot_only_gate = peer_holders_falsifier();
            const bool no_order = close_order_falsifier();

            struct CloseFlush { uint64_t seq; unsigned int cpu; };
            std::vector<CloseFlush> flush_order;
            for (unsigned int i = 0; i < CST_PIN_MAX_VCPUS; i++) {
                PathBuilder *b = path_builder_if_created(i);
                if (i == closing_cpu) {
                    /* Always flushed, builder or not: flush_final on a
                     * builder that does not exist yet creates an empty one
                     * and emits nothing, which is what it did before. */
                    flush_order.push_back({ b ? b->prev_seq() : UINT64_MAX,
                                            i });
                    continue;
                }
                /*
                 * THE GATE IS "DOES IT HOLD ANYTHING", NOT "DOES IT HOLD A
                 * SLOT".  Asking only about prev() skipped a peer whose
                 * pending-seal slot was empty while it still held work (in
                 * the pre-0x1E model: open fault frames and suspensions;
                 * today: an in-flight chain or a captured reg-snap sink) --
                 * and those drains are reachable ONLY through flush_final,
                 * so the skip took them with it.  Measured then: sd_smp4
                 * vCPUs 2 and 3 and ceil2 vCPUs 1 and 2 each held work
                 * behind prev=0x0, and read flushed=0 in the post-flush
                 * census while vCPU 0's identical frame drained in the same
                 * close.
                 */
                if (!b || !b->holds_close_work()) {
                    continue;
                }
                if (no_peers || (slot_only_gate && !b->prev())) {
                    /* Held work and was not flushed: the drop the falsifier
                     * arm exists to produce, counted so the arm is visible
                     * in the run's own stats rather than asserted. */
                    g_stats.close_peer_holders_skipped++;
                    continue;
                }
                flush_order.push_back({ b->prev_seq(), i });
            }
            if (closing_cpu >= CST_PIN_MAX_VCPUS) {
                /* Past the per-vCPU array bound (path_builder_if_created
                 * clamps, this loop cannot).  The closing vCPU is flushed
                 * whatever else happens -- it was flushed unconditionally
                 * before this ordering existed and must stay that way. */
                flush_order.push_back({ UINT64_MAX, closing_cpu });
            }
            std::stable_sort(flush_order.begin(), flush_order.end(),
                             [](const CloseFlush &a, const CloseFlush &b) {
                                 return a.seq != b.seq ? a.seq < b.seq
                                                       : a.cpu < b.cpu;
                             });
            if (no_order) {
                /* The falsifier arm: the pre-fix order, closing vCPU first
                 * and peers after it in ascending vCPU index. */
                std::stable_sort(flush_order.begin(), flush_order.end(),
                                 [&](const CloseFlush &a, const CloseFlush &b) {
                                     bool ac = a.cpu == closing_cpu;
                                     bool bc = b.cpu == closing_cpu;
                                     return ac != bc ? ac : a.cpu < b.cpu;
                                 });
            }
            /* How many builders the dispatch clock moved AHEAD of the
             * closing vCPU -- precisely the blocks the old order appended
             * behind it.  Counted so a run says for itself whether its
             * close was one where the ordering mattered: a close that found
             * no peer holding work reads zero and is evidence of nothing.
             * Zero by construction under CST_NO_CLOSE_ORDER. */
            unsigned int moved_ahead = 0;
            for (const CloseFlush &cf : flush_order) {
                if (cf.cpu == closing_cpu) {
                    break;
                }
                moved_ahead++;
            }
            if (moved_ahead) {
                g_stats.close_flush_reordered++;
                g_stats.close_flush_reordered_builders += moved_ahead;
            }

            /*
             * THE CONTEXT'S FINAL, NOT THE BUILDER'S.  Several builders
             * can drain for ONE context at one close — the closing vCPU's
             * own flush plus a peer holding the same thread's kernel
             * excursion sliver is the measured shape — and a flush that
             * stamped CST_BB_FLAG_THREAD_END on "its" last entry declared
             * an end mid-context (the thread_end oracle's stamp lie).
             * The flush order is already fixed, so decide finality by
             * thread BEFORE flushing: for each context, only the LAST
             * flush in the order that will EMIT may stamp.  A wrong
             * emission prediction is counted (never silent); the oracle
             * remains the enforcement.
             */
            std::unordered_map<uint32_t, size_t> smp_last_emitter;
            std::vector<uint8_t> smp_will_emit(flush_order.size(), 0);
            for (size_t fi = 0; fi < flush_order.size(); fi++) {
                unsigned int fcpu = flush_order[fi].cpu;
                PathBuilder *fb = path_builder_if_created(fcpu);
                const bool will = fb && fb->close_flush_will_emit();
                smp_will_emit[fi] = will ? 1 : 0;
                if (will) {
                    smp_last_emitter[resolve_thread_id(fcpu)] = fi;
                }
            }
            auto smp_stamp_here = [&](size_t fi) {
                unsigned int fcpu = flush_order[fi].cpu;
                auto it = smp_last_emitter.find(resolve_thread_id(fcpu));
                return it != smp_last_emitter.end() && it->second == fi;
            };

            for (size_t fi = 0; fi < flush_order.size(); fi++) {
                const CloseFlush &cf = flush_order[fi];
                if (cf.cpu == closing_cpu) {
                    /* The closing vCPU's own pending final entry. */
                    const uint64_t cb = g_seg_arch_insns;
                    if (prev_executed) {
                        path_builder_flush_final(closing_cpu,
                                                 smp_stamp_here(fi));
                    } else {
                        path_builder_flush_final_chain_only(closing_cpu,
                                                            prev_in_flight,
                                                            smp_stamp_here(fi));
                    }
                    smp_stamp_mispredict_note(g_seg_arch_insns != cb,
                                              smp_will_emit[fi] != 0);
                    continue;
                }
                unsigned int i = cf.cpu;
                PathBuilder *b = path_builder_if_created(i);
                if (!b) {
                    continue;
                }
                const bool had_slot = b->prev() != nullptr;
                /*
                 * COUNT WHAT THE FLUSH EMITTED, NOT WHAT THE SLOT HELD.
                 *
                 * This used to add tb_head_insns(prev) BEFORE calling
                 * flush_final and never look at whether the flush emitted
                 * anything — a number that reports success without
                 * verifying it.  It read "1 peer slot flushed / 3 insns
                 * recovered" in 24 of 24 single-core cells where nothing
                 * was at risk and nothing reached the wire, and it counted
                 * the slot's FULL translated length even where the flush
                 * correctly truncated to what ran.  Measure the wire
                 * instead: the delta in emitted arch instructions across
                 * the flush is exactly what was recovered.  (The pre-0x1E
                 * frame and suspension drains, whose shares this once
                 * subtracted, are gone: fault frames are ledger entries
                 * whose prefixes are already on the wire, and the flush's
                 * emissions are all the flush emits.)
                 */
                const uint64_t arch_before = g_seg_arch_insns;
                const uint64_t user_before = g_stats.wire_user_arch_insns;
                /*
                 * prev_in_flight STAYS FALSE, INCLUDING FOR A SLOT THAT IS
                 * THE PEER'S CURRENT HEAD.
                 *
                 * The extra subtraction that flag controls is not a second
                 * safety margin, it is a second copy of the first one.
                 * insn_started's add is registered LAST among an
                 * instruction's ops, so a cursor reading c always means
                 * instruction c's prologue has run and instructions
                 * 1..c-1 completed with their observations recorded --
                 * whether the vCPU is mid-body of c or sitting between
                 * instructions.  The stop rule's unconditional
                 * `executed--` publishes exactly those c-1, so the
                 * begun-but-unretired instruction is already outside the
                 * extent and taking one more would drop an instruction
                 * that ran and was fully observed.  What the peer case
                 * actually needed was a STABLE c, which the close-time
                 * snapshot now supplies.
                 */
                b->flush_final(/* walk_prev= */ true,
                               /* prev_in_flight= */ false,
                               smp_stamp_here(fi));
                const uint64_t got_all = g_seg_arch_insns - arch_before;
                uint64_t got = got_all;
                uint64_t got_user = g_stats.wire_user_arch_insns - user_before;
                smp_stamp_mispredict_note(got_all != 0,
                                          smp_will_emit[fi] != 0);
                if (had_slot) {
                    g_stats.close_peer_slots_flushed++;
                    if (got == 0) {
                        /* The slot held a block but the flush put nothing on
                         * the wire — nothing was recovered, and saying so is
                         * the whole point of measuring instead of
                         * asserting. */
                        g_stats.close_peer_slots_emitted_nothing++;
                    } else {
                        g_stats.close_peer_insns_recovered += got;
                        g_stats.close_peer_user_insns_recovered += got_user;
                    }
                } else {
                    /* A peer with an EMPTY slot that held work anyway — the
                     * population the old gate skipped.  Its recovery is
                     * whatever the flush put on the wire, drains included:
                     * there was no slot to attribute it to. */
                    g_stats.close_peer_holder_flushes++;
                    g_stats.close_peer_holder_insns_recovered += got_all;
                }
            }
        } else {
            /* plugin_exit with a segment still active (abnormal end: the
             * guest died without a close).  No dispatch context exists,
             * so flush every builder that ever ran -- in the order the
             * guest dispatched on them (g_promote_seq, ascending), for the
             * same strand-sequentiality reason the ordinary close route
             * has, and deterministically.  The old thread-keyed builder
             * made this flush a silent no-op (plugin_exit runs on a thread
             * that never dispatched, so its builder was empty). */
            struct CloseFlush { uint64_t seq; unsigned int cpu; };
            std::vector<CloseFlush> exit_order;
            for (unsigned int i = 0; i < CST_PIN_MAX_VCPUS; i++) {
                if (PathBuilder *b = path_builder_if_created(i)) {
                    exit_order.push_back({ b->prev_seq(), i });
                }
            }
            std::stable_sort(exit_order.begin(), exit_order.end(),
                             [](const CloseFlush &a, const CloseFlush &b) {
                                 return a.seq != b.seq ? a.seq < b.seq
                                                       : a.cpu < b.cpu;
                             });
            /* Thread-keyed finality, same rule as the ordinary close:
             * only a context's LAST emitting flush stamps THREAD_END. */
            std::unordered_map<uint32_t, size_t> smp_last_emitter;
            std::vector<uint8_t> smp_will_emit(exit_order.size(), 0);
            for (size_t fi = 0; fi < exit_order.size(); fi++) {
                PathBuilder *fb = path_builder_if_created(exit_order[fi].cpu);
                const bool will = fb && fb->close_flush_will_emit();
                smp_will_emit[fi] = will ? 1 : 0;
                if (will) {
                    smp_last_emitter[
                        resolve_thread_id(exit_order[fi].cpu)] = fi;
                }
            }
            for (size_t fi = 0; fi < exit_order.size(); fi++) {
                const CloseFlush &cf = exit_order[fi];
                if (PathBuilder *b = path_builder_if_created(cf.cpu)) {
                    auto it = smp_last_emitter.find(
                        resolve_thread_id(cf.cpu));
                    const uint64_t cb = g_seg_arch_insns;
                    b->flush_final(/* walk_prev= */ true,
                                   /* prev_in_flight= */ false,
                                   it != smp_last_emitter.end() &&
                                   it->second == fi);
                    smp_stamp_mispredict_note(g_seg_arch_insns != cb,
                                              smp_will_emit[fi] != 0);
                }
            }
        }
    });

    /* The flush hook has run: fold this close's unsealed-block tally into
     * the peak and the run totals before anything else reads them. */
    close_unsealed_end();

    /* POST pass: what survived every drain the close performs.  This is
     * the drop, and it is where the held_at_close ledger is taken. */
    const uint64_t held_frames_before = g_stats.census_frames_held_at_close;
    path_builder_close_state_report(stderr, census_why, closing_cpu,
                                    "post", census_print, /* ledger= */ true);
    if (census_print && stats_file) {
        path_builder_close_state_report(stats_file, census_why, closing_cpu,
                                        "post", true, /* ledger= */ false);
    }
    /*
     * THE FATE IDENTITY.
     *
     * Every occupant of a holder either left it through a named fate or is
     * still in it.  Checked cumulatively at each close, so a fate this
     * census cannot name shows up as a broken identity rather than as a
     * verifier's discovery three rounds later.  Reported, never enforced —
     * the instrument's job is to say what happened.
     */
    {
        /*
         * OVER THE AGGREGATE, NOT THE CLOSING THREAD'S SLICE.
         *
         * Stats is per-thread (g_stats is thread_stats_get()) and under
         * MTTCG a holder is FILLED on its own vCPU's thread while the
         * close runs on whichever vCPU crossed the budget.  Reading
         * g_stats here made a suspension pushed on vCPU 1 and held at a
         * close taken on vCPU 3 report "pushed=0 fated=0 held=1" — the
         * identity broken by the instrument's own bookkeeping rather than
         * by the tracer.  The occupancy delta below is still this thread's
         * (the post pass ran on it, and only on it).
         */
        const Stats s = stats_snapshot();
        const uint64_t frames_fated =
            s.census_frames_merged + s.census_frames_unwound_dropped +
            s.census_frames_orphan_dropped;
        const uint64_t frames_live =
            g_stats.census_frames_held_at_close - held_frames_before;
        const bool frames_ok =
            s.census_frames_opened == frames_fated + frames_live;
        if (!frames_ok) {
            g_stats.census_balance_broken++;
        }
        for (FILE *cf : { stderr, stats_file }) {
            if (!census_print || !cf) {
                continue;
            }
            fprintf(cf,
                    "[censusfate] why=%s frames: opened=%" PRIu64
                    " fated=%" PRIu64 " held=%" PRIu64 " %s"
                    " | prev: promoted=%" PRIu64 " close_walked=%" PRIu64
                    " close_dropped=%" PRIu64 "(insns=%" PRIu64 ")\n",
                    census_why, s.census_frames_opened, frames_fated,
                    frames_live, frames_ok ? "BALANCE-ok" : "BALANCE-BROKEN",
                    s.census_prev_promoted, s.census_prev_close_walked,
                    s.census_prev_close_dropped,
                    s.census_prev_close_dropped_insns);
        }
    }

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
        /* User (raw-clock) mode: BILLED == PUBLISHED at the close.  The
         * inline per-TB add counts instructions at dispatch, including
         * ones no published range claims — the exit syscall dying
         * mid-callback in this very close, the not-yet-run TB a deferred
         * budget close skips, the exact-budget cut past a finite
         * window's stop.  Those were un-billed where the exclusion
         * happened (user_raw_clock_unbilled); settle the bill here so
         * clock_minus_wire reads the identity, not the S18 exclusions.
         * The OPEN boundary has the opposite face: a mid-run open's
         * crossing TB is published whole while its pre-start head was
         * billed below `lo`, outside `covered` — that head is credited
         * where the open happened (user_raw_clock_open_credit) and
         * folded in here, so the identity holds at both edges of the
         * window. */
        if (!user_clock) {
            covered += g_seg_user_prebilled;
            covered = covered > g_seg_user_unbilled
                ? covered - g_seg_user_unbilled : 0;
        }
        /* An end-marker close is the workload finishing under budget by
         * design ("budget or program end"), not an underrun. */
        const char *flag = g_seg_close_reason ? g_seg_close_reason
            : (covered >= budget ? "OK"
               : (g_seg_end_marker_close ? "END" : "UNDER"));
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
        /* wire_user_insns / clock_minus_wire: the OWNED_CP-vs-user_covered
         * comparison, computed by the run that produced both numbers.  A
         * nonzero residual is instructions the window clock billed to the
         * owned process that no user template carries — the clock's bill is
         * a delta of insn_count reads, so anything retired between two owned
         * dispatches lands in the next owned TB's bill.  The per-bill split
         * is in the stats report (user_clock_bill_*).
         *
         * The segment's user self-loop fan-out surplus is folded into the
         * comparison on the clock side: the fan-out writes one entry per
         * iteration where every clock counts the instruction once, and the
         * surplus is measured at its source as exactly that difference
         * (wire_user_rep_extra_insns — a named term, never slack), so
         * covered + surplus == wire is the identity an exact segment
         * satisfies and 0 here is what it prints.  On a segment with no
         * user fan-out the term is 0 and the line is unchanged. */
        uint64_t seg_rep_surplus = g_stats.wire_user_rep_extra_insns -
                                   g_seg_rep_surplus_start;
        fprintf(stderr,
                "champsim_tracer: finished segment [icount %"
                PRIu64 " .. %" PRIu64 "]  actual_icount=%"
                PRIu64 "  %scovered=%" PRIu64
                "  %sbudget=%" PRIu64 "  rep_fanout=%" PRIu64
                "  trace_arch_insns=%" PRIu64
                "  wire_user_insns=%" PRIu64
                "  clock_minus_wire=%" PRId64 "  %s\n",
                lo, hi, g_host_icount,
                user_clock ? "user_" : "", covered,
                user_clock ? "user_" : "", budget,
                seg_fanout, g_seg_arch_insns, g_seg_arch_user_insns,
                (int64_t)(covered + seg_rep_surplus) -
                    (int64_t)g_seg_arch_user_insns, flag);
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

    /* The close is over: peer classification in any later flush (a next
     * segment's, the teardown's) must not inherit this close's vCPU, and
     * the in-flight extent snapshot must not answer for a vCPU that has
     * since run on. */
    g_cst_closing_cpu = UINT32_MAX;
    retired_close_extent_disarm();
}

/* True when the dead-latch detector is armed: marker mode, per-process
 * latch policy (trace-all pins a single clock process by design), and at
 * least one of the two denominators (wall-clock timeout, idle instructions)
 * given a non-zero threshold. */
static inline bool deadlatch_enabled(void)
{
    return deadlatch_configured() &&
           g_window_mode == PluginConfig::WIN_MARKER &&
           !marker_trace_all();
}

/*
 * Close the segment when a dead-latch sweep empties the owned set — the
 * whole-set backstop.  Mirrors the END marker's last-window close so the
 * trace finalises identically (audit rolls up to 100%).
 *
 * @by_insns says the closing sweep reaped at least one window on the
 * INSTRUCTION denominator.  That close is then flagged IDLE rather than
 * rendered as END: an idle close is a guess that a process is gone, and a
 * reader must never mistake it for the process's own END marker actually
 * having run.  "At least one", not "the last one", deliberately: g_owned is
 * unordered, so which reap is last is arbitrary, and a close's reported
 * reason must not depend on a container's iteration order.  (END always
 * wins: this path is only ever reached with the owned set already empty,
 * and the END handler drops its root before the sweep can see it.)
 *
 * Caller holds exec_lock; returns true if the caller should exit(0).
 */
static bool deadlatch_close_segment(uint64_t now, unsigned int cpu_index,
                                    const char *why = "dead-latch",
                                    bool by_insns = false)
{
    if (!g_trace_segments.is_active() ||
        g_trace_segments.is_shutting_down()) {
        return false;
    }
    fprintf(stderr,
            "champsim_tracer: %s close — closing after %" PRIu64
            " user insns (last window; wall %" PRIu64 " ms)\n",
            why, g_user_icount, now);
    /* A dead process is a process that ended, so report a clean close
     * ("END") rather than an under-budget underrun. */
    g_seg_end_marker_close = true;
    if (by_insns) {
        g_seg_close_reason = "IDLE";
    }
    finish_trace_segment(/* prev_executed= */ true, cpu_index);
    g_trace_segments.set_shutting_down();
    return true;
}

/* One root a sweep decided is dead, with both idle readings and which
 * denominator crossed — carried out of the scan loop so the reaping
 * (which mutates g_owned) does not run while g_owned is being iterated. */
struct DeadRoot {
    uint64_t root;
    uint64_t idle_ms;
    uint64_t idle_insns;
    bool     by_insns;
};

/* Instructions the guest has retired globally since @root was last
 * scheduled in.  A root with no instruction stamp yet (only reachable if
 * the two maps ever fell out of lockstep) reads as zero idle — never as
 * dead, which is the safe direction: a missing stamp must not reap a
 * window.  Caller holds exec_lock. */
static inline uint64_t deadlatch_idle_insns(uint64_t root, uint64_t now_insns)
{
    auto it = g_owned_last_sched_insns.find(root);
    if (it == g_owned_last_sched_insns.end()) {
        g_owned_last_sched_insns[root] = now_insns;
        return 0;
    }
    return now_insns >= it->second ? now_insns - it->second : 0;
}
/*
 * Proof of life for a dead-latch stamp refresh.
 *
 * The refresh events the latch used to trust — a schedule-in of the owned
 * root, an owned user TB executing — are all FORGEABLE: Linux recycles a
 * dead process's page-table root page into the next fork, QEMU's identity
 * layer interns the raw root value, and the successor process then
 * produces every one of those events in the dead window's name (measured:
 * cell e1_idle_diag re-stamped a dead window's root ~5700 times over
 * 190 s and held its idle below every threshold — the exposure whose
 * DOCUMENTED mitigation is this very latch).  What a successor cannot
 * forge is the pinned space's own mapping of the marker page: translate
 * the marker instruction's virtual page through the CURRENT address space
 * and demand the physical page the marker actually executed from.  A
 * recycled root maps something else there, or nothing.
 *
 * Runs on the vCPU thread whose event is being credited (both refresh
 * sites qualify), so the debug walk goes through that vCPU's live root.
 * Fails CLOSED: an unmapped / re-mapped marker page refuses the refresh,
 * which at worst closes a live window early — the documented hazard
 * direction of an opt-in idleness detector, tuned by raising the
 * threshold, never by trusting a forgeable signal.  No usable anchor
 * (user mode, or a synthetic bit-63 anchor) keeps bare-membership
 * refresh, i.e. the probe never LOOSENS the old behaviour.  Caller holds
 * exec_lock.
 */
static bool deadlatch_live_probe(uint64_t pid)
{
    auto it = g_owned_info.find(pid);
    if (it == g_owned_info.end()) {
        return false;
    }
    const OwnedSpace &os = it->second;
    if (!os.marker_pphys || (os.marker_pphys & (1ULL << 63))) {
        return true;             /* no usable anchor: refresh as before */
    }
    uint64_t pa;
    if (!qemu_plugin_vaddr_to_paddr(os.marker_vpage, &pa)) {
        g_stats.dead_latch_refresh_refused++;
        return false;
    }
    if ((pa & PIN_PAGE_MASK) != os.marker_pphys) {
        g_stats.dead_latch_refresh_refused++;
        return false;
    }
    return true;
}

/* CST_DEADLATCH_DIAG: prove the detector's CONDITION, not its outcome.
 * One rate-limited line per second from the two sweep drivers, under
 * exec_lock: the owned set, each root's two idle readings, and how many
 * times each driver refreshed a stamp.  A latch that never fires either
 * never sweeps (the line never prints) or keeps being refreshed (the
 * refresh counters climb while the process is dead) — the two inertness
 * mechanisms this distinguishes.  Instrumentation only. */
static uint64_t g_dl_diag_refresh_asid = 0;   /* stamp refreshes, asid hook */
static uint64_t g_dl_diag_refresh_clock = 0;  /* stamp refreshes, user clock */
static void deadlatch_diag(const char *site, uint64_t now, uint64_t now_insns)
{
    static int on = -1;
    if (on < 0) {
        on = getenv("CST_DEADLATCH_DIAG") != nullptr;
    }
    if (!on) {
        return;
    }
    static uint64_t last_print_ms;
    if (now - last_print_ms < 1000) {
        return;
    }
    last_print_ms = now;
    GString *s = g_string_new(nullptr);
    g_string_append_printf(s,
        "[dldiag] site=%s owned=%zu refr_asid=%" PRIu64
        " refr_clock=%" PRIu64 " arch=%" PRIu64 " user=%" PRIu64,
        site, g_owned.size(), g_dl_diag_refresh_asid,
        g_dl_diag_refresh_clock, now_insns, g_user_icount);
    for (uint64_t root : g_owned) {
        auto it = g_owned_last_sched.find(root);
        uint64_t idle_ms = it == g_owned_last_sched.end()
            ? 0 : now - it->second;
        g_string_append_printf(s, " root=0x%" PRIx64 " idle_ms=%" PRIu64
                               " idle_insns=%" PRIu64,
                               owned_raw_asid_locked(root), idle_ms,
                               deadlatch_idle_insns(root, now_insns));
    }
    fprintf(stderr, "%s\n", s->str);
    g_string_free(s, TRUE);
}

/* Count a reaped window against the denominator that reaped it, so the
 * statistics report distinguishes a wall-clock close from an idle-insn
 * one without anyone having to read stderr. */
static inline void deadlatch_count_close(bool by_insns)
{
    if (by_insns) {
        g_stats.dead_latch_closes_insns++;
    } else {
        g_stats.dead_latch_closes_ms++;
    }
}

/*
 * One reaped root's report line.  The "dead-latch close asid=0x..." prefix
 * is the detector's public signature (the validator's causal subcheck
 * matches on it and nothing else); what follows names WHICH denominator
 * crossed and by how much, so an idle close is never mistaken for an END.
 * The wall-clock rendering is byte-for-byte what it has always been.
 */
static void deadlatch_report_root(uint64_t root, uint64_t idle_ms,
                                  uint64_t idle_insns, bool by_insns,
                                  size_t still_tracing, uint64_t dropped)
{
    if (by_insns) {
        fprintf(stderr,
                "champsim_tracer: dead-latch close asid=0x%" PRIx64
                " idle=%" PRIu64 " insns (latch_idle_insns=%" PRIu64
                ", at arch_insns=%" PRIu64 ", wall idle %" PRIu64 " ms)"
                " (%zu still tracing, dropped %" PRIu64 " dedup buckets)\n",
                root, idle_insns, g_latch_idle_insns,
                deadlatch_now_insns(), idle_ms, still_tracing, dropped);
    } else {
        fprintf(stderr,
                "champsim_tracer: dead-latch close asid=0x%" PRIx64
                " idle=%" PRIu64 " ms (%zu still tracing, dropped %" PRIu64
                " dedup buckets)\n",
                root, idle_ms, still_tracing, dropped);
    }
}

/* Retire one owned root exactly as its END marker would: drop it from the
 * owned set, drop its asid-keyed dedup-index footprint (its true-BB
 * templates stay until the templates section is written), forget its
 * anchors, and repoint the representative if this was it.  Returns the
 * number of dedup buckets dropped.  Caller holds exec_lock. */
static uint64_t owned_retire_root_locked(uint64_t root)
{
    g_owned.erase(root);
    g_owned_last_sched.erase(root);
    g_owned_last_sched_insns.erase(root);
    uint64_t raw = root;
    auto oit = g_owned_info.find(root);
    if (oit != g_owned_info.end()) {
        raw = oit->second.raw_asid;
        g_owned_info.erase(oit);
    }
    g_mutex_lock(&data_lock);
    uint64_t dropped = g_template_store.reclaim_asid(raw);
    g_mutex_unlock(&data_lock);
    /* If the retired space was the representative, repoint it to a
     * still-owned one so cst_pinned_asid_root and the effective-pin
     * compare stay valid. */
    if (g_pinned_pid.load(std::memory_order_relaxed) == root &&
        !g_owned.empty()) {
        uint64_t heir = *g_owned.begin();
        g_pinned_pid.store(heir, std::memory_order_relaxed);
        auto hit = g_owned_info.find(heir);
        if (hit != g_owned_info.end()) {
            g_pinned_asid.store(hit->second.raw_asid,
                                std::memory_order_relaxed);
        }
    }
    return dropped;
}

/*
 * Wide-register staleness sweep (x86 CR3 / AArch64 TTBR / RISC-V SATP).
 * Close every owned root idle past the timeout — its process died without
 * running its END marker — exactly as the END handler drops a window, then
 * close the segment if that was the last one.  Caller holds exec_lock;
 * returns true if the caller should exit(0).
 */
static bool deadlatch_sweep_wide(uint64_t now, uint64_t now_insns,
                                 unsigned int cpu_index)
{
    if (g_owned.empty()) {
        return false;
    }
    /* {root, idle_ms, idle_insns, crossed on the instruction denominator} */
    std::vector<DeadRoot> dead;
    for (uint64_t root : g_owned) {
        auto it = g_owned_last_sched.find(root);
        if (it == g_owned_last_sched.end()) {
            g_owned_last_sched[root] = now;     /* first sighting: not stale */
            g_owned_last_sched_insns[root] = now_insns;
            continue;
        }
        uint64_t idle = now - it->second;
        uint64_t idle_insns = deadlatch_idle_insns(root, now_insns);
        bool by_insns = false;
        if (deadlatch_root_is_dead(idle, idle_insns, &by_insns)) {
            dead.push_back({root, idle, idle_insns, by_insns});
        }
    }
    bool any_by_insns = false;
    for (const auto &d : dead) {
        uint64_t raw = owned_raw_asid_locked(d.root);
        uint64_t dropped = owned_retire_root_locked(d.root);
        deadlatch_report_root(raw, d.idle_ms, d.idle_insns, d.by_insns,
                              g_owned.size(), dropped);
        deadlatch_count_close(d.by_insns);
        any_by_insns |= d.by_insns;
    }
    if (!dead.empty() && g_owned.empty()) {
        return deadlatch_close_segment(now, cpu_index, "dead-latch",
                                       any_by_insns);
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
    if (!deadlatch_enabled()) {
        return;
    }
    /* Wrong-path fence: never mutate the owned set or close a window from a
     * speculative context (asid writes are wrong-path-suppressed upstream;
     * this hard-enforces it, mirroring the marker callbacks). */
    if (qemu_plugin_in_spec_mode() || g_wp_in_progress) {
        return;
    }
    g_rec_mutex_lock(&exec_lock);
    bool do_exit = false;
    if (g_trace_segments.is_active() &&
        !g_trace_segments.is_shutting_down()) {
        uint64_t now = deadlatch_now_ms();
        uint64_t now_insns = deadlatch_now_insns();
        uint64_t pid = live_process_id();
        /* A schedule-in refreshes the stamp only with PROOF the space is
         * still the pinned process's (deadlatch_live_probe): the bare
         * root-value match is exactly what a recycled root forges. */
        if (owned_contains_locked(pid) && deadlatch_live_probe(pid)) {
            g_owned_last_sched[pid] = now;            /* live: schedule-in */
            g_owned_last_sched_insns[pid] = now_insns;
            g_dl_diag_refresh_asid++;
        }
        deadlatch_diag("asid", now, now_insns);
        do_exit = deadlatch_sweep_wide(now, now_insns, vcpu_index);
    }
    g_rec_mutex_unlock(&exec_lock);
    if (do_exit) {
        exit(0);
    }
}

/*
 * Retirement-driven sweep beat, called from the correct-path step glue
 * (events_path_step) BEFORE the foreign/async gates and throttled to one
 * sweep per DEADLATCH_UIC_STRIDE globally-retired instructions (sampled
 * 1-in-256 dispatched TBs, so the steady-state cost is one branch).
 *
 * This replaces the owned-user-clock peer sweep, whose trigger had the
 * detector's own blind spot built in: it ran only while an OWNED user TB
 * executed, and the ASID-write trigger runs only when the guest writes
 * the root register — so a guest whose one traced process died and which
 * then never context-switched swept NOTHING while retiring hundreds of
 * millions of instructions (task #9 hole 1, measured at 250 M).  The
 * instruction-denominated latch's subject is "the guest retired N insns
 * while the window showed no life", so its sweep must ride the same
 * clock the threshold is denominated in: any correct-path TB, any
 * context.  When no instruction retires at all, idle_insns cannot cross
 * either — the beat stopping WITH the denominator is the correct
 * behaviour, not a hole (the wall-clock arm alone cannot age a fully
 * halted guest; that residual stands documented in PluginConfig).
 *
 * Unlike the old peer sweep this one may close the WHOLE set: the
 * running context need not be owned, and a dead last window must not
 * survive on the technicality of which trigger sees it.  Refresh of the
 * live context demands the same proof of life as every other refresh.
 * Caller holds exec_lock; on a whole-set close the segment is finalised
 * (the pending seal slot holds the PREVIOUS, fully-executed TB — the
 * ceiling close's position) and the process exits like the END marker's
 * last-window close.
 */
static void deadlatch_beat(unsigned int cpu_index)
{
    static uint64_t divider;                    /* exec_lock-guarded */
    static uint64_t last_sweep_insns;
    if (!deadlatch_enabled() || (++divider & 255u) != 0) {
        return;
    }
    if (!g_trace_segments.is_active() ||
        g_trace_segments.is_shutting_down()) {
        return;
    }
    uint64_t now_insns = deadlatch_now_insns();
    if (now_insns - last_sweep_insns < DEADLATCH_UIC_STRIDE) {
        return;
    }
    last_sweep_insns = now_insns;
    uint64_t now = deadlatch_now_ms();
    uint64_t pid = live_process_id();
    if (owned_contains_locked(pid) && deadlatch_live_probe(pid)) {
        g_owned_last_sched[pid] = now;                /* running: fresh */
        g_owned_last_sched_insns[pid] = now_insns;
        g_dl_diag_refresh_clock++;
    }
    deadlatch_diag("beat", now, now_insns);
    if (deadlatch_sweep_wide(now, now_insns, cpu_index)) {
        /* The segment is finalised and shutting down; leave the step's
         * lock and end the run the way the END marker's close does. */
        g_rec_mutex_unlock(&exec_lock);
        exit(0);
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
         * g_wp_in_progress; the explicit guard hard-enforces the
         * invariant for any future caller.
         */
        if (branch_taken && !g_wp_in_progress) {
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
                       unsigned int cpu_index,
                       uint32_t bb_start,
                       bool thread_end)
{
    cp_chain(cpu_index).reset();

    std::vector<WPBBEntry> wp_entries;
    /* Genuine first-fetch failure from the accepted (non-flush-
     * interrupted) walker run: the excursion was kicked but its first
     * wrong-path target could not be fetched/translated, so wp_entries
     * is empty.  Carried onto the BodyEntry so the writer raises
     * CST_BB_FLAG_WP_FIRST_TARGET_UNAVAIL on the CP block record (§4.4). */
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

    /*
     * Opportunistic branch-alternate minting (static_templates=1),
     * translation-unavail case: the wrong-path fork launched but its FIRST
     * target could not be fetched/translated, so the wrong path covered
     * nothing.  The collect-time CP mint deferred this branch to the fork
     * (it was going to launch), so nothing has covered the untaken side —
     * mint it here through the probing read (a mapped page a spec-mode fetch
     * quirk skipped is decoded; a genuinely unmapped one is skip-counted).
     * No-op unless the feature is on; data_lock is NOT held here.
     */
    if (wp_first_tb_unavail) {
        altmint_pc(wrong_target);
    }

    /* @current_pc is the resolved architectural successor of this BB's
     * terminating branch (collect_finalized_bbs' frag_current_pc / the seal
     * point) — the PC the next emitted entry starts at.  Pass it so the
     * CST_FID_BRANCH_* singletons record the true direction/target.  Marked
     * known: every emit_finalized_bb caller resolved a successor. */
    emit_body_entry(out_stream, bb_tmpl, cpu_index, std::move(wp_entries),
                    wp_first_tb_unavail, current_pc, /*known=*/true,
                    bb_start, bb_tmpl ? bb_tmpl->n_insns : 0,
                    thread_end);
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
 *
 * @ran is how many of the fragment's instructions RETIRED (its whole
 * n_insns on the ordinary path).  @aborted_tail says the instruction
 * AFTER the cut started — its own pre-exec callback already captured
 * insn[ran-1], so nothing is missing and this must capture nothing.  The
 * capture is always one behind: with S instructions started, the per-insn
 * hooks have covered insn[0..S-2], so the range still owed is
 * [S-1, ran-1] — a single instruction when the tail retired, and empty
 * when it was abandoned mid-flight and will be re-executed.
 *
 * @at_close marks the ONE caller that is the segment's own closing flush
 * (close_seal_at_terminator) rather than a dispatch, and two things follow
 * from it.  The active-segment test below belongs to the dispatch-time
 * callers — it keeps the hot path from capturing outside a window — and
 * the close runs with that flag already cleared
 * (TraceSegmentManager::finish drops it before it calls the flush hook),
 * so a close that went through it would capture nothing and hand the emit
 * a short register slice, which the emit then discards WHOLE.  And there
 * is no successor to put in the terminating branch's REG_IP dst, nor any
 * goto_tb staleness to repair: a block that left TCG through an exception
 * synced its PC on the way out, so the live read is the value.
 */
static void snap_prev_tail_dsts(unsigned int cpu_index,
                                const BBTemplate *tmpl,
                                uint64_t current_pc,
                                uint32_t ran,
                                bool aborted_tail,
                                bool at_close = false)
{
    if (aborted_tail || ran == 0) {
        return;
    }
    if (g_features.reg_data && tmpl->insn_reg_names &&
        tmpl->n_insns > 0 &&
        (at_close || g_trace_segments.is_active_atomic())) {
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
         * so applying it in both passes is correct on every ISA.
         *
         * A TRUNCATED fragment stops before that tail, so the deferred
         * branch snap cannot be owed here: every instruction below the cut
         * had its snap taken by its successor's callback and only
         * insn[ran-1] is missing. */
        uint32_t last = ran - 1;
        bool delay_slot_tail = ran == tmpl->n_insns && ran >= 2 &&
            tmpl->insn_fields[last - 1].branch_type != BRANCH_NONE &&
            tmpl->insn_fields[last].branch_type == BRANCH_NONE;
        auto capture_tail = [&](uint32_t idx) {
            const InsnFields *fl = &tmpl->insn_fields[idx];
            const InsnRegNames *nl = &tmpl->insn_reg_names[idx];
            for (uint8_t i = 0; i < fl->n_dst_regs; i++) {
                RegSnap s;
                g_reg_snaps.read_into_snap(
                    cpu_index, nl->dst_qemu_reg_keys[i], &s);
                if (!at_close && fl->dst_regs[i] == REG_IP) {
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
                pending_reg_snaps(cpu_index).push_back(s);
            }
        };
        if (delay_slot_tail) {
            capture_tail(last - 1);   /* branch (deferred) */
        }
        capture_tail(last);           /* delay slot, or branch on non-delay ISAs */
    }
}

/*
 * THE TERMINATOR IS THE SEAL POINT, NOT THE NEXT DISPATCH.
 *
 * A close finds the pending-seal slot holding a block no later dispatch
 * ever measured, and the flush's stop rule then drops its last instruction:
 * that instruction's dst snaps are taken by its SUCCESSOR's pre-exec
 * callback, and no successor began.  For a block the guest merely stopped
 * inside, dropping it is right — the instruction is not architecturally
 * past.  For a block that ran to its own TERMINATOR it is not: a syscall IS
 * a block terminator, so the exit syscall's block is complete the moment
 * the syscall retires, and waiting for a dispatch that can never come cut
 * every user-mode run's last block one instruction short of the syscall
 * that ended the program (measured: the unsealed-at-close ledger read peak
 * 1, route EXIT, `mov %edx,%eax` at 0x4112c9 with `syscall` missing).
 *
 * So ask the architectural question instead.  Returns true — and captures
 * the terminator's own dst snaps, so the block's register slice is whole —
 * when all four hold:
 *
 *   - every instruction of the slot's fragment chain retired (@executed
 *     covers the chain), so the terminator is not still in flight;
 *   - the chain's last fragment ends at a terminating branch
 *     (TB_TERMINUS_COMPLETE — a bare branch still owes its delay slot, a
 *     NONE tail still owes the rest of its true BB);
 *   - @head is this vCPU's CURRENT dispatch, which together with the
 *     first condition places the vCPU at the end of that TB.  Its next
 *     dispatch enters vcpu_tb_exec and blocks on the exec_lock this close
 *     holds, so the registers cannot move under the read;
 *   - the caller is on the direct-cursor path, i.e. no later dispatch
 *     stashed an extent — one that did also took the tail snaps, and this
 *     would duplicate them.
 *
 * The live read is the terminator's post-exec state for the same reason
 * the dispatch-time capture's is: nothing has executed since.  It is taken
 * with @at_close set, which both lets the capture past the active-segment
 * guard the closing flush has already cleared and leaves the terminating
 * branch's REG_IP dst on its live read — there is no successor PC to
 * substitute, and the exception that ended the block synced the PC.
 */
bool close_seal_at_terminator(unsigned int cpu_index,
                              const BBTemplate *head,
                              uint64_t executed)
{
    const BBTemplate *last = nullptr;
    uint64_t total = 0;
    for (const BBTemplate *f = head; f; f = f->next_tb_fragment) {
        total += f->n_insns;
        last = f;
    }
    if (!last || total == 0 || executed != total) {
        return false;
    }
    if (last->terminus != (uint8_t)TB_TERMINUS_COMPLETE) {
        return false;
    }
    if (!retired_is_in_flight(cpu_index, head)) {
        return false;
    }
    snap_prev_tail_dsts(cpu_index, last, /* current_pc= */ 0,
                        last->n_insns, /* aborted_tail= */ false,
                        /* at_close= */ true);
    return true;
}

/*
 * Rewrite the REG_IP destination values among the tail dst snaps the glue
 * prologue captured for @tmpl (see snap_prev_tail_dsts): the prologue
 * stamps the DISPATCHED next PC, and a seal that resolves a different
 * architectural successor (fault case (c) resume PC, async departure PC)
 * corrects it here, before the emit publishes the value.  The captured
 * tail snaps are the sink's LAST entries; their per-insn layout is
 * deterministic from the template, so the positions are recomputed rather
 * than stored.  Mirrors snap_prev_tail_dsts' selection exactly.
 */
static void patch_tail_ip_snaps(unsigned int cpu_index,
                                const BBTemplate *tmpl,
                                uint64_t current_pc,
                                uint32_t ran,
                                bool aborted_tail)
{
    if (aborted_tail || ran == 0) {
        return;
    }
    if (!g_features.reg_data || !tmpl->insn_reg_names || tmpl->n_insns == 0) {
        return;
    }
    uint32_t last = ran - 1;
    bool delay_slot_tail = ran == tmpl->n_insns && ran >= 2 &&
        tmpl->insn_fields[last - 1].branch_type != BRANCH_NONE &&
        tmpl->insn_fields[last].branch_type == BRANCH_NONE;
    uint32_t idxs[2];
    unsigned n_idx = 0;
    if (delay_slot_tail) {
        idxs[n_idx++] = last - 1;
    }
    idxs[n_idx++] = last;
    unsigned total = 0;
    for (unsigned k = 0; k < n_idx; k++) {
        total += tmpl->insn_fields[idxs[k]].n_dst_regs;
    }
    std::vector<RegSnap> &sink = pending_reg_snaps(cpu_index);
    if (total == 0 || sink.size() < total) {
        return;                 /* prologue capture did not run / was reset */
    }
    size_t base = sink.size() - total;
    size_t pos = 0;
    for (unsigned k = 0; k < n_idx; k++) {
        const InsnFields *fl = &tmpl->insn_fields[idxs[k]];
        for (uint8_t i = 0; i < fl->n_dst_regs; i++, pos++) {
            if (fl->dst_regs[i] == REG_IP) {
                sink[base + pos].value = cst_wide_from_u64(current_pc);
            }
        }
    }
}

/*
 * Per-CP attribution: bump opcode / branch_type / src / dst counters
 * per insn of the just-committed CP fragment.  Cache thread_stats_get()
 * once — the g_stats macro re-resolves the TLS slot via __tls_get_addr
 * each expansion, and this loop bumps it up to 4×n_insns.
 */
static void attribute_cp_insns(const BBTemplate *tmpl, uint32_t ran)
{
    Stats &s = thread_stats_get();
    Stats *h = g_current_hist_bucket;
    if (ran > tmpl->n_insns) {
        ran = tmpl->n_insns;
    }
    /* Third point in the window-clock accounting chain (see the Stats block
     * on user_clock_billed_insns): what the SEAL WALK saw, between what the
     * clock billed at dispatch and what emission put on the wire.  Two gaps
     * instead of one residual — a fragment lost before the seal walk and an
     * assembled block lost between the seal and the emit are different
     * defects and were previously indistinguishable.  @ran is the extent
     * that RETIRED, so a fragment the guest abandoned part-way attributes
     * only the instructions it ran. */
    if (!tmpl->is_system) {
        s.cp_user_seal_insns += ran;
    }
    for (uint32_t i = 0; i < ran; i++) {
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
    uint64_t reached_at = pin_user_clock();
    g_trace_segments.set_window(lo, hi);
    /* Retire this positioning epoch into the pin-absolute clock BEFORE
     * user_count_reset zeroes it: the window budget restarts at 0, the
     * schedule's clock does not.  On the first cluster the base is still
     * 0, so this is exactly what the single-cluster path always
     * computed. */
    g_user_icount_pin_base = reached_at;
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
    /* Warmup crossing (header §2.13), latched here at dispatch
     * granularity on the same clock the window budget runs on: the
     * pinned user clock when marker_user_clock(), the raw inline
     * counter against window_start otherwise.  Runs before this step's
     * seal-phase emissions, so the first record emitted at-or-after the
     * crossing is capturable by emit_body_entry.  warmup_insns is 0
     * outside simpoint windows, making the flag true from the first
     * in-segment step there (boundary index 0 = no warmup, as before). */
    if (g_trace_segments.is_active() && !g_seg_warmup_crossed) {
        bool wm_crossed = marker_user_clock()
            ? g_user_icount >= warmup_insns
            : icount_prev >=
                  g_trace_segments.window_start() + warmup_insns;
        if (wm_crossed) {
            g_seg_warmup_crossed = true;
        }
    }

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
        /*
         * Termination bound.  While a marker window is open on the user
         * clock, watch how far the guest gets in an owned context without
         * the pinned process retiring a single user instruction.  Crossing
         * the ceiling closes the segment exactly as the budget would (the
         * same deferred, sealed-step path), so the trace is finalised and
         * the run ends — instead of recording an alive-but-never-returning
         * process forever.  Diagnostic max is kept even when the ceiling
         * is disabled, so a capture can be judged after the fact.
         */
        if (marker_pinned && g_trace_segments.is_active() &&
            cpu_index < CST_PIN_MAX_VCPUS) {
            uint64_t u = g_user_icount;
            if (u != g_stall_last_uic) {
                g_stall_last_uic = u;
                g_stall_gen++;
            }
            if (g_stall_seen_gen[cpu_index] != g_stall_gen) {
                g_stall_seen_gen[cpu_index] = g_stall_gen;
                g_stall_base[cpu_index] = icount_prev;
            }
            uint64_t stall = icount_prev >= g_stall_base[cpu_index]
                ? icount_prev - g_stall_base[cpu_index] : 0;
            if (stall > g_stats.user_clock_worst_stall) {
                g_stats.user_clock_worst_stall = stall;
            }
            if (stall >= CST_STALL_WARN_DEFAULT && !g_stall_warned &&
                (!g_stall_ceiling || stall < g_stall_ceiling)) {
                g_stall_warned = true;
                fprintf(stderr,
                    "champsim_tracer: the traced process has not executed a "
                    "user-space instruction\n  for %" PRIu64 " retired "
                    "instructions of its own context — it is alive and in "
                    "the\n  kernel, and its user-clock budget cannot "
                    "advance while this lasts (ceiling %" PRIu64 ").\n",
                    stall, g_stall_ceiling);
                fflush(stderr);
            }
            if (g_stall_ceiling && stall >= g_stall_ceiling &&
                !g_stall_ceiling_fired) {
                g_stall_ceiling_fired = true;
                g_stats.stall_ceiling_closes++;
                fprintf(stderr,
                    "\nchampsim_tracer: *** USER-CLOCK STALL CEILING ***\n"
                    "  the guest retired %" PRIu64 " instructions in this "
                    "trace's own context without\n"
                    "  the traced process executing ONE user-space "
                    "instruction (ceiling %" PRIu64 ").\n"
                    "  Its END marker cannot execute and its user-clock "
                    "budget cannot advance, so\n"
                    "  nothing else would ever close this window.  Closing "
                    "the segment here: the\n"
                    "  trace is finalised and TRUNCATED at %" PRIu64
                    " of %" PRIu64 " user instructions.\n"
                    "  (stall_ceiling=<insns> tunes this; 0 disables it.)\n\n",
                    stall, g_stall_ceiling, budget_now, budget_stop);
                fflush(stderr);
                deferred_close(cpu_index).icount_shutdown_pending = true;
            }
        }
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
             * deferred prev normally, and the close then waits one step
             * more so the budget-crossing TB — whose insns the clock
             * already counted, but which has not run at the tail that
             * detects the crossing — executes and seals normally too,
             * carrying its memops and register deltas (see
             * g_window_close_armed). */
            /*
             * WHICH close.  A budget-reached close in pinned-simpoint mode
             * is the end of ONE CLUSTER, not the end of the run: the
             * schedule may still name regions the caller asked for, and
             * tracing several regions over a single run is the contract in
             * both modes.  Route it to the SAME simpoint close the
             * user-mode schedule uses, which finalises the segment,
             * advances the iterator, and exits only once the schedule is
             * exhausted.
             *
             * This is the BUDGET close only.  Every other close reachable
             * here stays terminal by design: the END marker
             * (marker_close_and_exit), the user-clock stall ceiling just
             * above, and the dead-latch close all end the run with
             * clusters possibly outstanding — an END in particular kills
             * the tracer regardless of simpoints, exactly as a program
             * ending does in user mode.
             */
            if (pinned_simpoint_mode() && g_simpoints.is_active()) {
                deferred_close(cpu_index).simpoint_close_pending = true;
            } else {
                deferred_close(cpu_index).icount_shutdown_pending = true;
            }
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
                    /* The matching TB is traced whole while `lo` sits at
                     * its post-add clock: its full length is the
                     * published-below-the-start head. */
                    user_raw_clock_open_credit(lo, icount_prev, cur_tmpl);
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
            deferred_close(cpu_index).simpoint_close_pending = true;
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
                    /* A non-first cluster opens mid-run: the crossing
                     * TB's head insns were billed below eff_start but
                     * are published — credit the straddle. */
                    user_raw_clock_open_credit(eff_start, icount_prev,
                                               cur_tb_tmpl);
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
            /* An icount window with start > 0 opens mid-run exactly like
             * a non-first simpoint cluster; a lo=0 window's first TB
             * begins at clock 0 and the credit computes to nothing. */
            user_raw_clock_open_credit(lo, icount_prev, cur_tb_tmpl);
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
            deferred_close(cpu_index).icount_shutdown_pending = true;
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
    if (g_wp_in_progress) {
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
                           std::vector<PendingEmit> &pending_emits,
                           std::vector<CutEmit> &cut_emits)
{
    g_mutex_lock(&data_lock);
    bool any_finalize = false;

    /* Opportunistic branch-alternate mint targets collected under data_lock
     * (PC only — no decode), minted after the lock is released: altmint_pc
     * takes data_lock itself, so it cannot run inside this region. */
    std::vector<uint64_t> alt_pcs;

    /*
     * HOW MUCH OF THE DISPATCHED TB ACTUALLY RAN.
     *
     * A dispatched TB is not a promise that its instructions execute.  QEMU
     * abandons one mid-flight with NO exception whenever an instruction that
     * is not the TB's last needs to be re-run on its own: a device-MMIO
     * access (translator.c clears can_do_io for every instruction of a
     * multi-instruction TB except the last, so io_prepare() takes
     * cpu_io_recompile() -> cpu_restore_state_from_tb() +
     * cpu_loop_exit_noexc()), an atomic that needs serial execution
     * (cpu_loop_exit_atomic), a MOPS / REP re-entry.  The already-executed
     * prefix is architecturally retired, the abandoned instruction is
     * rewound and re-executed, and control continues in a fresh TB.  There
     * is no exception, so no fault or async event exists and the fault
     * machinery cannot see it.
     *
     * @prev_start resolves the last-executed FRAGMENT and says NOTHING about
     * how far into it the guest got, so this walk used to fold the fragment
     * at its full TRANSLATED length.  Two losses followed from the one
     * omission: the entry claimed instructions this dispatch never ran (and
     * the following block re-covered them, so the wire DUPLICATED them), and
     * the positional reg-snap sink held only the prefix that ran plus one or
     * two BOGUS tail snaps read for instructions that never executed —
     * pending != Sum(n_dst_regs), which made the emit-time backstop discard
     * the entry's WHOLE register slice.
     *
     * The segment-close walk already asks this question
     * (PathBuilder::flush_final); the per-execution seal never did.  It is
     * the same instrument and the same answer.
     *
     * insn_started counts instructions BEGUN, so the abandoned instruction
     * is already in @started.  Whether it RETIRED depends on how QEMU re-runs
     * it, and the guest itself says which case this is.
     *
     *   DEVICE MMIO.  The re-run is a one-instruction CF_MEMI_ONLY TB, and
     *   plugins/api.c refuses every non-memory instrumentation request on
     *   such a TB (tb_is_mem_only): no tb-exec callback, no current_pc
     *   store, no insn_started add — only the memory callback, which is
     *   always planted.  So the add fired exactly once, for an instruction
     *   that really does complete, and @started is already the retired
     *   count.  @current_pc is the TB after the re-run, i.e. the
     *   instruction's true successor, and the block is exact at @started.
     *
     *   EVERY OTHER MID-FLIGHT ABANDON (cpu_loop_exit_atomic's serial
     *   re-run, a MOPS / REP re-entry, a case-(c) fault whose resume PC
     *   substitutes for the successor).  The re-run is an ordinary
     *   instrumented TB entered AT the abandoned instruction, so the guest
     *   is standing on insn[started-1] and its add is about to fire a second
     *   time.  That instruction did NOT retire here: drop it, and let the
     *   re-run's own block carry it.
     */
    uint64_t started = 0;
    const bool falsify = false;     /* falsifier arms retired with the model */
    bool have_extent =
        retired_executed_prev(cpu_index, prev_tb_head, &started);
    /*
     * A DEFERRED SEAL'S EXTENT IS NOT ACTUALLY UNKNOWN.
     *
     * The retired cursor answers only for the previous dispatch, so a seal
     * deferred past its own dispatch used to get no answer and fold prev at
     * its FULL translated length -- on the argument that a prev still
     * pending later was left at a TB boundary and ran to its end.
     * a07df2d053's comment names the door that leaves open, and
     * seal_walk_extent_unknown_interior watches it: on aarch64 it fired,
     * one latch cell in 33, folding 21 instructions the dispatch never ran
     * so the block resuming at current_pc re-covered them and the wire
     * DUPLICATED them.  The number was measured at the first dispatch after
     * prev -- the very step whose seal was deferred -- and set_prev carries
     * it across the swap.  Ask for it before declaring the extent unknown.
     */
    if (!have_extent &&
        path_builder(cpu_index).seal_prev_extent(prev_tb_head, &started)) {
        have_extent = true;
        g_stats.seal_walk_extent_from_stash++;
    }
    const uint32_t tb_total = tb_head_insns(prev_tb_head);
    uint64_t executed = started;
    bool aborted_tail = false;
    if (!falsify && !have_extent && prev_tb_head != nullptr &&
        seal_extent_diag()) {
        PathBuilder &pbd = path_builder(cpu_index);
        unsigned miss = pbd.seal_extent_miss(prev_tb_head);
        fprintf(stderr, "[sealext] UNANSWERED prev=0x%" PRIx64 " n=%u "
                "cur=0x%" PRIx64 " at=%u miss=%u(%s%s) seal_prev=0x%" PRIx64
                " live_valid=%d susp=%zu\n",
                prev_tb_head ? prev_tb_head->start_pc : 0, tb_total,
                current_pc, tb_head_insn_index(prev_tb_head, current_pc),
                miss, (miss & 1u) ? "no-measurement " : "",
                (miss & 2u) ? "other-block" : "",
                pbd.seal_prev_block() ? pbd.seal_prev_block()->start_pc : 0,
                (int)pbd.live_prev_extent_valid(), (size_t)0);
    }
    if (falsify) {
        /* The extent question was never asked, so this is not an unknown
         * extent — it is the pre-a07df2d053 walk, which had no such
         * question.  Leaving the counter alone keeps the falsified arm
         * comparable to the healthy one everywhere the switch is not the
         * variable. */
    } else if (!have_extent && prev_tb_head != nullptr) {
        g_stats.seal_walk_extent_unknown++;
        /*
         * ASK THE JUSTIFICATION'S OWN QUESTION.
         *
         * An unknown extent is not by itself a defect: a seal DEFERRED past
         * its own dispatch has no retired delta to read, and the walk then
         * folds prev at its FULL translated length on the argument that an
         * interrupt or a foreign span is taken at a TB boundary, so a prev
         * still pending at a later dispatch ran to its end.
         *
         * That argument has a falsifier and, until now, no instrument that
         * could state it: if prev really was abandoned mid-flight, the guest
         * is standing INSIDE prev, and @current_pc is one of prev's own
         * instructions at a position past its first.  Then the full-extent
         * fold claims instructions this dispatch never ran and the block
         * that resumes at @current_pc re-covers them — defect B's signature,
         * arriving through the one door a07df2d053 left open.
         *
         * Index 0 is deliberately NOT counted: a TB that branches to itself
         * legitimately leaves the guest standing on its first instruction
         * having run the whole block, so that reading proves nothing either
         * way.  What is counted is unambiguous.
         */
        uint32_t at = tb_head_insn_index(prev_tb_head, current_pc);
        if (at != UINT32_MAX && at > 0 && at < tb_total) {
            g_stats.seal_walk_extent_unknown_interior++;
            g_stats.seal_walk_extent_unknown_interior_insns += tb_total - at;
        }
    } else if (started > 0 && started < tb_total &&
               tb_head_insn_pc_at(prev_tb_head,
                                  (uint32_t)(started - 1)) == current_pc) {
        aborted_tail = true;
        executed = started - 1;
        /*
         * PROOF-OF-FIRE for the probe above.  This arm is the same question
         * asked where the answer is already known: the retired cursor says
         * the guest abandoned prev at @started, and the probe is asked to
         * find the very instruction it is standing on.  A non-zero reading
         * here is what makes the unknown-extent arm's zero worth quoting —
         * the same lookup, on the same kind of TB, demonstrably firing.
         */
        if (tb_head_insn_index(prev_tb_head, current_pc)
                == (uint32_t)(started - 1) && started >= 2) {
            g_stats.seal_walk_interior_probe_hits++;
        }
    }

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

    uint32_t walked = 0;
    for (BBTemplate *frag = prev_tb_head; frag != nullptr;
         frag = frag->next_tb_fragment) {
        /* Instructions of THIS fragment that retired. */
        uint32_t ran = frag->n_insns;
        if (have_extent) {
            if (walked >= executed) {
                break;                 /* fragment never entered */
            }
            uint64_t left = executed - walked;
            if (left < frag->n_insns) {
                ran = (uint32_t)left;
            }
        }
        const bool truncated = ran < frag->n_insns;
        /* A truncated fragment IS the last one that executed, whatever
         * @prev_start says. */
        bool is_last_executed = truncated ||
            (prev_start_matches ? (frag->start_pc == prev_start)
                                : (frag == last_frag));

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
            /* The tail insn's dst snaps were captured by this dispatch's
             * glue prologue (the note_prev_extent site), which stamped the
             * DISPATCHED next PC into the branch's REG_IP dst.  A seal
             * override (a case-(c) fault's resume PC, an async departure)
             * resolves a different architectural successor — patch those
             * positions with the resolved value. */
            patch_tail_ip_snaps(cpu_index, frag, frag_current_pc, ran,
                                truncated && aborted_tail);
        }
        /*
         * CONTROL LEFT THE IN-FLIGHT BLOCK.  This fragment does not continue
         * the chain (an async window swallowed the rest of a true BB and
         * control came back somewhere else, a segment generation bumped, a
         * foreign span intervened), so that chain will never reach a
         * terminating branch and append_fragment is about to throw it away —
         * along with the per-instruction destination snaps it already
         * captured, which the sink's positional discipline then forces out
         * too.  Those instructions EXECUTED.  Seal the chain at the extent
         * that ran and hand it to the caller to emit ahead of this walk's
         * own blocks, in program order.
         *
         * The snaps go with it: [snap_lo, snap_hi) of the sink is exactly
         * this chain's, and leaving them behind is what made them the next
         * block's "leaked prefix".
         */
        if (cp_chain(cpu_index).would_discard(frag->start_pc)) {
            size_t lo = cut_emits.empty() ? 0 : cut_emits.back().snap_hi;
            size_t hi = cp_chain_snap_mark(cpu_index);
            if (hi < lo) {
                hi = lo;
            }
            if (BBTemplate *cut =
                    cp_chain(cpu_index).finalize_truncated(nullptr, 0)) {
                cut_emits.push_back(CutEmit{cut, lo, hi});
                g_stats.cut_blocks_sealed++;
                g_stats.cut_block_insns += cut->n_insns;
                if (cut->is_system) {
                    g_stats.cut_block_sys_insns += cut->n_insns;
                } else {
                    g_stats.cut_block_user_insns += cut->n_insns;
                }
            }
            cp_chain(cpu_index).reset();
        }

        /*
         * THE GUEST DID NOT FINISH THIS FRAGMENT.  Seal the block at the
         * extent that RAN.  The clipped fragment is NOT appended to the
         * chain: the chain's fragment list feeds the complete-block cache,
         * and a clipped fragment must never become part of a cached complete
         * block (commit_partial_bb mints its own extent-keyed template and
         * leaves parent_true_bb alone for exactly that reason).
         *
         * It goes on @pending_emits, not @cut_emits, so it keeps its
         * position in program order behind any block an earlier fragment of
         * this same TB completed; cut blocks are emitted ahead of the walk.
         * The successor is @frag_current_pc — where the guest actually is —
         * and there is no terminating branch to resolve, so no wrong path is
         * forked from a block that never reached one.
         */
        if (truncated) {
            attribute_cp_insns(frag, ran);
            if (BBTemplate *bb_tmpl =
                    cp_chain(cpu_index).finalize_truncated(frag, ran)) {
                pending_emits.push_back(
                    PendingEmit{bb_tmpl, 0, frag_current_pc, 0});
                any_finalize = true;
            }
            cp_chain(cpu_index).reset();
            g_stats.seal_walk_blocks_truncated++;
            g_stats.seal_walk_insns_not_executed += frag->n_insns - ran;
            if (aborted_tail) {
                g_stats.seal_walk_aborted_tails++;
            }
            break;
        }

        cp_chain_append(cpu_index, frag);
        attribute_cp_insns(frag, ran);
        walked += ran;

        if (BBTemplate *bb_tmpl = cp_chain_finalize_if_complete(cpu_index)) {
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
                uint64_t raw_wrong = pe.wrong_target;
                if (taken_target != 0) {
                    bb_tmpl->taken_pc = taken_target;
                }
                /* wpprune: skip the wrong path for a cold branch.  The
                 * taken edge above is already recorded; only the
                 * speculative walk is suppressed. */
                bool pruned =
                    (pe.wrong_target != 0 && wp_branch_pruned(bb_tmpl, br));
                if (pruned) {
                    pe.wrong_target = 0;
                }
                /*
                 * Opportunistic branch-alternate minting (static_templates=1):
                 * when this branch's wrong-path fork will NOT launch — pruned,
                 * wrong-path disabled, or paging off — nothing will decode its
                 * untaken side, so mint it here as a never-executed template.
                 * When the fork DOES launch, the wrong path itself covers the
                 * untaken block (and its inner branches feed the WP-side mint),
                 * so we leave it.  Queued; minted after the data_lock release.
                 *
                 * bb_tmpl->alt_checked_cp latches this to ONCE per block (the
                 * cheap flag read gates the paging_enabled() call and the
                 * lookup): the executed side is always covered by execution,
                 * and the first visit's alternate covers the not-executed
                 * side, so a single latch suffices even as the branch flips
                 * direction across visits.
                 */
                if (g_features.alt_mint && raw_wrong != 0 &&
                    !bb_tmpl->alt_checked_cp) {
                    bb_tmpl->alt_checked_cp = true;
                    bool wp_will_launch = enable_wrong_path && !pruned &&
                                          qemu_plugin_paging_enabled();
                    if (!wp_will_launch) {
                        alt_pcs.push_back(raw_wrong);
                    }
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

    /* Mint the branch alternates queued above, now that data_lock is
     * released (altmint_pc reacquires it, releasing around the guest read).
     * Empty unless static_templates=1 and a fork-less branch was sealed. */
    for (uint64_t alt : alt_pcs) {
        altmint_pc(alt);
    }
    return any_finalize;
}

/*
 * RAII freeze of the guest virtual clock across a plugin instrumentation
 * window (per-TB emission in vcpu_tb_exec, translation work in
 * vcpu_tb_trans).  Instrumentation runs on the vCPU thread but is not guest
 * execution, so its host wall-clock cost must not be charged to guest time:
 * left unfrozen, a heavily traced guest timer-tick handler can cost more
 * guest time than one tick period, and the guest collapses into a
 * self-sustaining tick/scheduler storm — the mechanism this guard was
 * written to close, and it is closed.
 *
 * It is not a general account of guest stalls, and must not be read as one.
 * The freeze is in force in every capture taken since, including every
 * capture that has shown the system-mode stall condition, so a stall
 * observed with this guard in place is a DIFFERENT mechanism and its cause
 * is elsewhere.  Reasoning that begins "the tracer is expensive, therefore
 * the guest stalls" does not survive that fact.
 *
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
 *
 * The close also waits one step past the first boundary it could take, so
 * the TB whose instruction count carried icount over window_stop is EMITTED
 * BY THE ORDINARY SEAL — with its memops, its register deltas and its
 * terminal branch — instead of being flushed out of the pending-seal slot
 * before it has run (see g_window_close_armed).  The pending slot at the
 * close therefore holds a TB that has not executed, and the flush skips it.
 */
/* CST_CLOSE_DIAG: one line per deferred-close evaluation.  Reports the
 * three predicates that decide whether this step takes the close, so a
 * window that closed at the wrong point can be read back to the step that
 * armed it.  Diagnostic only — no effect on the trace. */
static inline bool close_diag(void)
{
    static std::atomic<int> v{-1};
    int x = v.load(std::memory_order_relaxed);
    if (x < 0) {
        x = getenv("CST_CLOSE_DIAG") ? 1 : 0;
        v.store(x, std::memory_order_relaxed);
    }
    return x != 0;
}

/*
 * Will the deferred window close try to take at this step's end, with this
 * seal's final emission standing as the closing context's segment-final
 * entry?  Read by PathBuilder::step_seal so that entry can carry
 * CST_BB_FLAG_THREAD_END — a budget/simpoint close itself emits nothing
 * for the closing vCPU (the slot holds the TB dispatching now, extent 0),
 * so the flag has to ride the seal.  Pending and armed are both settled
 * before step_seal runs (tw_manage_window sets pending between step_events
 * and the seal; only the take mutates armed), so this read is stable
 * across the seal-to-take window.
 *
 * A peer builder holding close work will have its flush emit AFTER the
 * seal's entry — which un-finals it only when the peer's emissions carry
 * the SAME (thread, asid) context; that peer's own flush then stamps the
 * context's true final (thread_end_last), and a seal stamp here would be
 * the lie the oracle rejects.  A different context's later entries leave
 * the closing context's final exactly where the seal put it, so only the
 * same-context peer suppresses.  Identity read from the same per-vCPU
 * carries the flush's own emission resolves against, under the same
 * exec_lock, so the comparison and the eventual emission cannot disagree.
 */
bool deferred_close_take_pending(unsigned int cpu_index)
{
    /* The END arm has no second armed step (see VcpuDeferredClose): its
     * take fires at the first boundary the arm survives to, and the seal's
     * own empty-chain / fan-out tests are that boundary, so asking for
     * `armed` here would suppress the stamp on the one step the take
     * actually happens. */
    const bool end_pend = deferred_close(cpu_index).end_close_pending;
    if (!((end_pend ||
           ((deferred_close(cpu_index).icount_shutdown_pending ||
             deferred_close(cpu_index).simpoint_close_pending) &&
            deferred_close(cpu_index).window_close_armed)) &&
          g_trace_segments.is_active())) {
        return false;
    }
    const uint32_t tid = resolve_thread_id(cpu_index);
    const uint32_t asid = resolve_ctx_asid_index(cpu_index);
    for (unsigned int i = 0; i < CST_PIN_MAX_VCPUS; i++) {
        if (i == cpu_index) {
            continue;
        }
        PathBuilder *b = path_builder_if_created(i);
        if (b && b->holds_close_work() &&
            resolve_thread_id(i) == tid &&
            resolve_ctx_asid_index(i) == asid) {
            return false;
        }
    }
    return true;
}

static void run_deferred_window_closes(PathBuilder &pb, unsigned int cpu_index,
                                       const BBTemplate *cur_tb_tmpl)
{
    if (!deferred_close(cpu_index).icount_shutdown_pending &&
        !deferred_close(cpu_index).simpoint_close_pending &&
        !deferred_close(cpu_index).end_close_pending) {
        deferred_close(cpu_index).window_close_armed = false;
        return;
    }
    RepSelfLoopState &rs_cd = rep_state(cpu_index);
    /* Privilege-agnostic, thread-aware in-flight hold.  A slot holds the
     * close while execution is still AT the held instruction (a REP chunk
     * re-enters at the instruction's own pc, so the resume BB's start_pc
     * matches), inside ANY kernel service (the holder's fault service, or
     * the scheduler on its way to a peer), or on a user TB of a DIFFERENT
     * guest thread — a peer's user code on this vCPU proves nothing about
     * the holder's instruction (measured: a budget crossing detected on a
     * spinner thread split the peer's 50M-iteration REP at 651390
     * iterations, probes/threadrep.S).  Only the HOLDER's own thread at a
     * different user pc proves the instruction architecturally past (or
     * the hold stale, e.g. a signal diverted it) — that slot is then
     * CLEARED, not just bypassed, so a stale hold cannot re-defer every
     * later close.  An unknown-holder slot (armed at dispatch, no
     * emission yet) keeps the historical pc-or-kernel release: with no
     * owner to test, any user TB elsewhere releases it.  The numeric
     * ceiling below still bounds the whole hold — a close that never
     * fires is a trace that never finishes. */
    bool fanout_hold = false;
    if (cur_tb_tmpl) {
        const uint32_t cur_tid = resolve_thread_id(cpu_index);
        for (unsigned i = 0; i < RepSelfLoopState::REP_CLK_PCS; i++) {
            RepBoundaryHold &h = rs_cd.warmup_hold[i];
            if (!h.active) {
                continue;
            }
            if (cur_tb_tmpl->start_pc == h.pc || cur_tb_tmpl->is_system ||
                (h.tid != RepBoundaryHold::CST_HOLD_TID_UNKNOWN &&
                 h.tid != cur_tid)) {
                fanout_hold = true;
            } else if (h.tid == RepBoundaryHold::CST_HOLD_TID_UNKNOWN) {
                /* An ownerless dispatch arm (no emission yet) at a
                 * different user BB: the old structural release. */
                h.active = false;
            } else {
                /* The HOLDER's identity at a different user BB.  Either
                 * the instruction is architecturally past without its
                 * retirement emission (a signal diverted it), or this is
                 * a peer thread the guest never gave its own thread
                 * pointer — indistinguishable from the holder by the
                 * wire's identity model (a no-SETTLS raw clone; measured:
                 * with shared fs the spinner cleared the hold and the
                 * split went unnamed).  Do NOT hold (no hang), but KEEP
                 * the slot: if the close takes now, the tripwire below
                 * still names the possible split instead of reading a
                 * false zero. */
            }
        }
    }
    if (close_diag()) {
        fprintf(stderr, "[closediag] eval clock=%" PRIu64
                " chain=%d armed=%d fanout_hold=%d(any=%d) icount_pend=%d "
                "sp_pend=%d pc=0x%" PRIx64 "\n",
                g_user_icount, (int)cp_chain(cpu_index).has_active_chain(),
                (int)deferred_close(cpu_index).window_close_armed, (int)fanout_hold,
                (int)rs_cd.warmup_hold_any(),
                (int)deferred_close(cpu_index).icount_shutdown_pending, (int)deferred_close(cpu_index).simpoint_close_pending,
                cur_tb_tmpl ? cur_tb_tmpl->start_pc : 0);
    }
    /* Not at a BB boundary yet (or the segment already closed under us):
     * hold the arm and let a later step take the close. */
    if (cp_chain(cpu_index).has_active_chain() || !g_trace_segments.is_active()) {
        return;
    }
    /*
     * Fan-out atomicity.  A true BB seals at the REP itself — it is a
     * branch terminator — so between two REP_MAX chunks of ONE
     * architectural instruction the chain is empty and the two tests above
     * both pass.  Taking the close there ends the trace in the middle of an
     * instruction: the wire gets a partial iteration count and a self-loop
     * terminal edge, and the iterations QEMU had already billed to the
     * window clock are never emitted — the opposite of this function's
     * contract that every counted insn is committed to an emitted BB.
     *
     * So hold the close while a fan-out instruction is architecturally in
     * flight, the same predicate (begun, not retired) the §2.13
     * warmup boundary already defers on.
     *
     * Measured (cst_runs/x86close, probes/bigrep3.S — a 140000-iteration
     * REP STOSB, three REP_MAX chunks): without this, budgets 1..5 all
     * closed between chunk 1 and chunk 2 and put 74463 of 140000
     * iterations on the wire.  A two-chunk REP never showed it — the close
     * needs one armed step and one taking step, and two chunks do not
     * leave room between them, which is why the reasoned D3/D6 case went
     * unconstructed until a three-chunk probe.
     *
     * The hold is bounded twice over, because a close that never fires is a
     * trace that never finishes.  Structurally: the HOLDER's own thread at
     * a different user pc clears its slot (a peer's user TB does not — see
     * the release loop above).  Numerically: a hold that outlives
     * CST_FANOUT_HOLD_MAX consecutive evaluations is abandoned and counted,
     * which converts both "the guest stayed in the kernel with a stale
     * hold" and "the holder never got rescheduled" (a peer spinning
     * through the whole ceiling, probes/threadrep.S) from a hang into a
     * bounded overrun with a number attached.  The legitimate
     * single-thread span is the instruction's remaining chunks plus its
     * own fault service — thousands of steps at the outside; the
     * cross-thread span is a scheduling quantum and MAY exceed the
     * ceiling, in which case the capped counter and the tripwire below
     * both name the split.
     */
    static uint64_t held_steps;          /* exec_lock serialises this */
    if (fanout_hold) {
        if (++held_steps <= CST_FANOUT_HOLD_MAX) {
            return;
        }
        g_stats.window_close_fanout_hold_capped++;
    }
    held_steps = 0;
    /*
     * END-MARKER TAKE.  Both gates above have passed, so this step's tail
     * is a true-BB boundary with no fan-out instruction in flight — and
     * because the arm was raised from inside the marker instruction's own
     * execution, the nearest such boundary is the end of the END-marker's
     * own block.  The seal that just ran emitted it whole.
     *
     * FIRST, and without the second armed step the budget close takes.
     * First, because an END outranks every other stop: a budget crossing
     * that armed on the same step must not close the window a route ahead
     * of the one the workload chose.  Without the extra step, because the
     * arm is raised AFTER the marker's block executed rather than before —
     * the budget close waits a step for the crossing TB to run, and here
     * that step has already happened, so one more would put a block PAST
     * the END marker on the wire.
     */
    if (deferred_close(cpu_index).end_close_pending) {
        deferred_close(cpu_index).end_close_pending = false;
        deferred_close(cpu_index).window_close_armed = false;
        if (!pb.seal_stamped_thread_end()) {
            /* Same accounting as the icount take: this close emits nothing
             * for the closing context, so the seal owned the THREAD_END
             * stamp and did not take it.  Named, never silent. */
            g_stats.close_thread_end_missed++;
        }
        finish_trace_segment(/* prev_executed= */ false, cpu_index);
        g_trace_segments.set_shutting_down();
        g_rec_mutex_unlock(&exec_lock);
        exit(0);
    }
    if (!deferred_close(cpu_index).window_close_armed) {
        deferred_close(cpu_index).window_close_armed = true;
        return;
    }
    deferred_close(cpu_index).window_close_armed = false;
    /* Tripwire: a take with any hold slot still active is a close inside
     * an architecturally in-flight fan-out instruction — reachable only
     * through the numeric ceiling now that the hold is privilege-agnostic
     * and thread-aware.  Counted from the hold TABLE (pc-keyed, one slot
     * per in-flight instruction), NOT from cp_in_flight: that scalar is
     * last-writer-wins, and any interleaved completing REP (a kernel
     * clear_page between a user REP's chunks) overwrites it — measured
     * reading 0 while the wire carried a 651390-of-50000000 split
     * (probes/threadrep.S), which is why the original tripwire's
     * ~12-opportunity zero was never evidence. */
    if (rs_cd.warmup_hold_any()) {
        g_stats.window_close_in_fanout++;
    }
    if (close_diag()) {
        fprintf(stderr, "[closediag] TAKE clock=%" PRIu64 "\n",
                g_user_icount);
    }

    /* Deferred-exit on icount window-stop.  The trigger was set in
     * tw_manage_window when icount first crossed window_stop. */
    if (deferred_close(cpu_index).icount_shutdown_pending) {
        if (!pb.seal_stamped_thread_end()) {
            /* This close emits nothing for the closing context, and the
             * seal that produced its final entry did not stamp THREAD_END
             * (merge-path seal, fan-out template, or a peer holding close
             * work).  Named, never silent. */
            g_stats.close_thread_end_missed++;
        }
        finish_trace_segment(/* prev_executed= */ false, cpu_index);
        g_trace_segments.set_shutting_down();
        deferred_close(cpu_index).icount_shutdown_pending = false;
        /* No need to recompute_budget: we're exiting immediately and
         * the budget slot will be torn down with the scoreboard. */
        g_rec_mutex_unlock(&exec_lock);
        exit(0);
    }

    /* Simpoint analogue: finalize only after the chain has drained to a
     * BB boundary so the trace covers AT LEAST eff_stop - eff_start
     * (warmup + simulation) insns. */
    if (deferred_close(cpu_index).simpoint_close_pending) {
        if (!pb.seal_stamped_thread_end()) {
            g_stats.close_thread_end_missed++;   /* see the icount take */
        }
        finish_trace_segment(/* prev_executed= */ false, cpu_index);
        if (g_end_close_claimed.load(std::memory_order_relaxed)) {
            /*
             * AN END OUTRANKS THE SCHEDULE, WHICHEVER vCPU CLOSES.
             *
             * The END take above cannot be beaten on the marker's own
             * vCPU — it is tested first and needs no second armed step —
             * but on an SMP guest a PEER's budget crossing can reach its
             * take between the END's arm and the END's own boundary.  The
             * simpoint close is the one route here that would survive it,
             * advancing to the next cluster on a workload that has
             * already ended, so a claimed END terminates the run instead
             * (see marker_close_and_exit: the ruling is about the END,
             * not about which vCPU happened to close).
             */
            g_trace_segments.set_shutting_down();
            g_rec_mutex_unlock(&exec_lock);
            exit(0);
        }
        g_simpoints.advance();
        deferred_close(cpu_index).simpoint_close_pending = false;
        pb.clear_prev();
        pb.events_queue_disable();
        if (!g_simpoints.current()) {
            g_trace_segments.set_shutting_down();
            g_rec_mutex_unlock(&exec_lock);
            exit(0);
        }
        recompute_next_threshold();
        if (pinned_simpoint_mode()) {
            /*
             * Re-enter pinned positioning for the next cluster.  The pin
             * survives the segment close (the marker fired once and owns
             * the address space for the whole run) and pin_user_clock()
             * is monotone across the close, so the next cluster's
             * start_insn — an offset from the pin — needs no rebasing.
             *
             * What DOES have to be restored is the per-TB dispatch the
             * fast-forward fast-path rides on: finish_trace_segment
             * mirrored is_active=0 into every vCPU slot to stop the
             * in-segment callbacks.  Put it back and park the budget slot
             * at the sentinel, exactly as the pin-time path does — in
             * pinned mode the budget countdown positions nothing
             * (recompute_next_threshold parks the threshold at the
             * sentinel); the user clock does.
             */
            for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; i++) {
                qemu_plugin_u64_set(g_scoreboard.is_active, (unsigned)i, 1);
                qemu_plugin_u64_set(g_scoreboard.budget, (unsigned)i,
                                    (uint64_t)BUDGET_INACTIVE_SENTINEL);
                refresh_ctx_gates((unsigned)i);
            }
            const SimPointEntry *nsp = g_simpoints.current();
            uint64_t neff = (nsp->start_insn > warmup_insns)
                ? nsp->start_insn - warmup_insns : 0;
            fprintf(stderr,
                    "champsim_tracer: simpoint segment closed at user clock %"
                    PRIu64 " — positioning to simpoint %d start %" PRIu64
                    " user insns (warmup %" PRIu64 ")\n",
                    pin_user_clock(), nsp->cluster_id, nsp->start_insn,
                    warmup_insns);
            if (pin_user_clock() >= neff) {
                /* The schedule asked for a region the run has already
                 * passed (overlapping clusters, or a warmup wide enough
                 * to reach back before the previous window's end).  The
                 * window opens on the very next TB, so the capture is a
                 * valid region — but it is NOT the region requested, and
                 * a silently mispositioned segment is worse than a loud
                 * one. */
                fprintf(stderr,
                        "champsim_tracer: WARNING simpoint %d effective "
                        "start %" PRIu64 " is already behind the pinned "
                        "user clock %" PRIu64 " — its window opens "
                        "immediately and the segment is NOT positioned "
                        "where the schedule asked\n",
                        nsp->cluster_id, neff, pin_user_clock());
            }
            fflush(stderr);
        } else {
            /* Re-arm budget so the per-TB inline_add countdown lands at
             * zero when icount reaches the now-current eff_start. */
            for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; i++) {
                recompute_budget((unsigned)i);
            }
        }
    }
}

/* Live queue-length high-water across every vCPU, read from QEMU.  Used by
 * the heartbeat so the bound is observable DURING a run — a cell killed by a
 * timeout never reaches plugin_exit, and an invariant that can only be read
 * from a clean shutdown is unobservable exactly where it matters. */
static inline uint64_t fence_evq_qmax(void)
{
    uint64_t peak = 0;
    for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; i++) {
        uint64_t ml = 0;
        qemu_plugin_cpu_events_stats((unsigned)i, &ml, nullptr, nullptr);
        if (ml > peak) {
            peak = ml;
        }
    }
    return peak;
}

/*
 * Fence-lane heartbeat (CST_FENCE_DIAG only).  Runs on the correct-path TB
 * step, so it observes exactly the state a real END-marker execution would:
 * the window, the pinned process's user clock, the retired-instruction
 * clock, the three fence flags at rest, and the END-callback census.  All
 * reads; the trace is untouched.
 */
static void fence_diag_tick(unsigned int cpu_index, uint64_t icount_prev,
                            uint64_t watch_pc, bool seg_active)
{
    static uint64_t divider = 0;
    static int64_t last_ms = 0;
    static uint64_t last_icnt = 0;
    static uint64_t last_uic = 0;
    if (!fence_diag()) {
        return;
    }
    if ((++divider & 255u) != 0) {
        return;
    }
    int64_t ms = (int64_t)deadlatch_now_ms();
    if (last_ms == 0) {
        last_ms = ms;
        return;
    }
    if ((ms - last_ms) * 1000000LL < fence_diag_period_ns()) {
        return;
    }
    double dt = (double)(ms - last_ms) / 1000.0;
    last_ms = ms;
    bool f_spec = qemu_plugin_in_spec_mode();
    bool f_wp   = g_wp_in_progress;
    bool f_sess = wp_session_active(cpu_index);
    uint64_t icnt = icount_prev;
    uint64_t uic  = g_user_icount;
    fprintf(stderr,
            "[fence] ms=%" PRId64 " seg=%d uic=%" PRIu64 " d_uic=%" PRIu64
            " icnt=%" PRIu64 " d_icnt=%" PRIu64 " rate=%.2fM/s pc=0x%" PRIx64
            " priv=%d asid=0x%" PRIx64 " pin=0x%" PRIx64
            " | end_cb=%" PRIu64 " cp=%" PRIu64 " fenced=%" PRIu64
            " fenced_user=%" PRIu64 " start_cb=%" PRIu64 "/%" PRIu64
            " | flags spec=%d wp=%d sess=%d"
            " | susp_u=%" PRIu64
            " | evq qmax=%" PRIu64 " batch=%" PRIu64 " gap=%" PRIu64
            " big=%" PRIu64 " absorb=%" PRIu64 "/%" PRIu64
            " drains=%" PRIu64 "\n",
            ms, seg_active ? 1 : 0, uic, uic - last_uic, icnt,
            icnt - last_icnt,
            dt > 0 ? (double)(icnt - last_icnt) / dt / 1e6 : 0.0,
            watch_pc, qemu_plugin_get_priv_level(),
            qemu_plugin_get_addr_space_id(),
            g_pinned_asid.load(std::memory_order_relaxed),
            g_fdiag_end_total, g_fdiag_end_cp, g_fdiag_end_fenced,
            g_fdiag_end_fenced_user, g_fdiag_start_fenced,
            g_fdiag_start_total,
            f_spec ? 1 : 0, f_wp ? 1 : 0, f_sess ? 1 : 0,
            tls_mkdiag_susp_user,
            fence_evq_qmax(), g_stats.evq_batch_peak, g_stats.evq_gap_peak,
            g_stats.evq_bigdrains, g_stats.evq_absorb_calls,
            g_stats.evq_absorb_events, g_stats.evq_drain_calls);
    fence_flush_end_ring();
    last_icnt = icnt;
    last_uic = uic;
}

/*
 * Any-context termination bound.  Runs at the top of every correct-path
 * step while a marker window is open, before the gates that drop foreign
 * and async TBs — because a guest whose traced process is dead or blocked
 * executes nothing BUT those.  Caller holds exec_lock and never returns if
 * the ceiling fires (the process exits, exactly as the END marker's close
 * does).
 */
static void user_clock_stall_any_check(unsigned int cpu_index,
                                       uint64_t icount_prev)
{
    if (!marker_user_clock() || !g_trace_segments.is_active() ||
        g_trace_segments.is_shutting_down() ||
        cpu_index >= CST_PIN_MAX_VCPUS) {
        return;
    }
    uint64_t u = g_user_icount;
    if (u != g_stall_any_last_uic) {
        g_stall_any_last_uic = u;
        g_stall_any_gen++;
    }
    if (g_stall_any_seen_gen[cpu_index] != g_stall_any_gen) {
        g_stall_any_seen_gen[cpu_index] = g_stall_any_gen;
        g_stall_any_base[cpu_index] = icount_prev;
    }
    uint64_t stall = icount_prev >= g_stall_any_base[cpu_index]
        ? icount_prev - g_stall_any_base[cpu_index] : 0;
    if (stall > g_stats.user_clock_worst_stall_any) {
        g_stats.user_clock_worst_stall_any = stall;
    }
    if (stall >= CST_STALL_ANY_WARN_DEFAULT && !g_stall_any_warned &&
        (!g_stall_any_ceiling || stall < g_stall_any_ceiling)) {
        g_stall_any_warned = true;
        fprintf(stderr,
            "champsim_tracer: the traced process has not executed a "
            "user-space instruction\n  for %" PRIu64 " instructions the "
            "guest retired in ANY context — it may be blocked,\n  starved, "
            "or gone.  Nothing but its END marker or a ceiling can close "
            "this\n  window (any-context ceiling %" PRIu64 ").\n",
            stall, g_stall_any_ceiling);
        fflush(stderr);
    }
    if (!g_stall_any_ceiling || stall < g_stall_any_ceiling ||
        g_stall_any_fired) {
        return;
    }
    g_stall_any_fired = true;
    g_stats.stall_any_closes++;
    fprintf(stderr,
        "\nchampsim_tracer: *** PINNED PROCESS NOT RUNNING ***\n"
        "  the guest retired %" PRIu64 " instructions without the traced "
        "process executing\n  ONE user-space instruction in ANY context "
        "(ceiling %" PRIu64 ").  It is blocked,\n  starved or gone: its END "
        "marker cannot execute and its user-clock budget\n  cannot advance, "
        "so nothing would ever close this window.  Closing the\n  segment "
        "here — the trace is finalised and TRUNCATED at %" PRIu64
        " user instructions.\n"
        "  (stall_ceiling_any=<insns> tunes this; 0 disables it.)\n\n",
        stall, g_stall_any_ceiling, g_user_icount);
    fflush(stderr);
    /* Closes where the guest stands, not at a block boundary: the calling
     * thread's pending seal slot holds the PREVIOUS TB, which has executed,
     * so it is emitted normally and the segment is finalised (audit rolls
     * up to 100%).  Unlike the END marker's close this cannot be deferred
     * — there is no boundary coming, which is the condition it fires on. */
    g_seg_end_marker_close = false;
    g_seg_close_reason = "CEILING";
    finish_trace_segment(/* prev_executed= */ true, cpu_index);
    g_trace_segments.set_shutting_down();
    g_rec_mutex_unlock(&exec_lock);
    exit(0);
}

/*
 * Drain instrument, shared by BOTH drain sites.  Records the batch size and
 * the guest-instruction distance from the previous drain call on this vCPU,
 * and shouts if a single drain ever exceeds one translation block's worth of
 * events -- the "BIGDRAIN" condition, which is the work-per-guest-instruction
 * invariant being violated: every event in an oversized batch is O(n) work
 * charged to the one guest instruction whose TB happened to dispatch.
 *
 * Caller holds no lock; the arrays are per-vCPU and touched only by their own
 * vCPU thread, and the g_stats fields are monotone maxima whose worst case
 * under a benign SMP race is a lost update of a smaller value.
 */
static inline void evq_note_drain(unsigned int cpu_index, size_t n_evs,
                                  uint64_t icount)
{
    static uint64_t last_ic[CST_PIN_MAX_VCPUS];
    unsigned sl = cpu_index < CST_PIN_MAX_VCPUS ? cpu_index : 0;
    uint64_t gap = icount - last_ic[sl];
    last_ic[sl] = icount;

    g_stats.evq_drain_calls++;
    g_stats.evq_drain_events += n_evs;
    if (n_evs) {
        /* Latch the QUEUE-SIDE high-water mark here, and only here.
         *
         * Reading it once at plugin_exit is not good enough and silently
         * reads ZERO in system mode: the exit callback runs from atexit(3),
         * after qemu_cleanup() has torn the machine down, where
         * qemu_get_cpu() no longer resolves — a witness that reports 0
         * because it could not find its subject is a false success, not a
         * bound.  A SIGKILLed run never reaches an exit hook at all.
         *
         * Sampling on every NON-EMPTY drain is exact, and it is exact
         * because of the fix itself: q->max_len can only rise at a push,
         * every push sets the pending flag, and the pending flag makes the
         * very next TB entry drain a non-empty queue.  So no increase can
         * escape between two consecutive samples.  Empty drains — the
         * overwhelming majority — pay nothing. */
        uint64_t ml = 0, np = 0, nd = 0;
        qemu_plugin_cpu_events_stats(cpu_index, &ml, &np, &nd);
        if (ml > g_stats.evq_qmax_len) {
            g_stats.evq_qmax_len = ml;
        }
    }
    if (n_evs > g_stats.evq_batch_peak) {
        g_stats.evq_batch_peak = n_evs;
    }
    if (gap > g_stats.evq_gap_peak) {
        g_stats.evq_gap_peak = gap;
    }
    if (n_evs > CST_EVQ_TB_EVENT_MAX) {
        g_stats.evq_bigdrains++;
        fprintf(stderr, "champsim_tracer: [evq] BIGDRAIN cpu=%u n=%zu "
                "icount=%" PRIu64 " (+%" PRIu64 ") -- a single drain larger "
                "than one TB can produce means a TB entry did not drain; the "
                "work-per-instruction bound is broken\n",
                cpu_index, n_evs, icount, gap);
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
    PathBuilder &pb = path_builder(cpu_index);

    /* Enable this vCPU's event queue lazily on its first CP exec (clears
     * any boot-time backlog).  Must run on the owning vCPU thread, which
     * a tb_exec callback guarantees. */
    if (!pb.events_queue_enabled()) {
        qemu_plugin_cpu_events_set(cpu_index, true);
        pb.mark_events_queue_enabled(cpu_index);
    }

    /* Delay instrument (CST_DELAY_DIAG, off by default): bracket the
     * acquisition, not the hold.  simulate_wrong_path_ext runs under this
     * lock, so on a multi-vCPU guest a peer's excursion is what a vCPU waits
     * behind here — and without this bracket that wait was billed to the
     * waiter's undifferentiated gap term, where it was indistinguishable from
     * guest execution.  The gate is a relaxed int load when disarmed. */
    const bool delay_lock_timed = cst_delay_armed();
    if (delay_lock_timed) {
        cst_delay_lock_wait_begin(cpu_index);
    }
    g_rec_mutex_lock(&exec_lock);
    if (delay_lock_timed) {
        cst_delay_lock_wait_end(cpu_index);
    }

    /* Guest-realtime instrument (#61).  Sampled here — one point that runs
     * once per correct-path TB, with the guest clock already frozen (the
     * caller's VClockPauseGuard is in scope) and UNDER exec_lock: the gate
     * is one process-wide aggregate, and on an SMP guest every vCPU thread
     * walks this step, so pre-lock sampling would race its counters (the
     * same cross-vCPU class the cpu_index-array conversion just retired).
     * Amortised 1-in-1024 internally; g_user_icount, which the stall
     * detector reads, is likewise exec_lock-owned. */
    g_rt_gate.note_tb(g_capture_mute, icount_prev);
    g_rt_gate.tick(g_trace_segments.is_active_atomic());
    /*
     * Leaked-fence tripwire, always armed.  This step IS the correct path
     * (the wrong-path early-out fires above it), so the wrong-path session
     * bracket must be closed here.  If it is not, the bracket leaked — and
     * a leaked bracket silently drops every marker callback on this vCPU,
     * which is exactly how a window could stay open forever with no
     * counter to show for it.  One relaxed load per step.
     */
    if (wp_session_active(cpu_index)) {
        g_stats.wp_session_on_cp++;
    }
    fence_diag_tick(cpu_index, icount_prev, watch_pc,
                    g_trace_segments.is_active_atomic());

    /* Termination bound of last resort — see g_stall_any_ceiling.  This
     * point is BEFORE step_events, which is where a foreign or async TB
     * leaves the step: a guest whose traced process has died or blocked
     * executes nothing else, so any bound placed after that gate cannot
     * see it.  Closing here walks the pending seal slot, which holds the
     * previous, fully executed TB, so the trace is finalised rather than
     * abandoned — the position a close takes when no block boundary is
     * coming, which is exactly the condition this ceiling names. */
    user_clock_stall_any_check(cpu_index, icount_prev);

    /* Dead-latch sweep beat, at the same point for the same reason: its
     * subject is precisely a window whose owner no longer executes, so
     * the sweep must ride TBs that are not the owner's.  Throttled to
     * one sweep per DEADLATCH_UIC_STRIDE retired instructions; may
     * finalise the segment and exit like the END marker's close. */
    deadlatch_beat(cpu_index);

    /*
     * Architectural retired-instruction cursor.  Advanced on EVERY dispatch
     * in EVERY mode, not only under a pin: the segment-close walk uses it to
     * learn how much of the in-flight block actually executed, and a block
     * the guest entered and did not finish is emitted at its full translated
     * length in user mode exactly as it is in system mode.  The lagged
     * delta belongs to the PREVIOUS dispatch (see retired_advance).
     */
    uint64_t delta_retired = retired_advance(cpu_index, cur_tb_tmpl);
    const bool prev_dispatch_owned =
        g_retired_owner_owned[retired_slot(cpu_index)];

    /*
     * AN ABORTED ATTEMPT IS NOT A RETIREMENT.
     *
     * insn_started is a per-instruction add emitted at the TOP of the
     * instruction's translated code, so it counts instructions BEGUN.  Every
     * mid-TB abandonment QEMU takes without an exception rewinds to the
     * abandoned instruction and RE-EXECUTES it — cpu_loop_exit_atomic's
     * serial re-run, a MOPS / REP re-entry — so its add fires twice while
     * the instruction retires once.  The guest says so by where it is
     * standing: control on insn[delta-1] of the TB just abandoned means that
     * instruction did not retire here.  Take it back before the fold, not
     * after, so the window clock counts retirements and nothing downstream
     * has to know the slot is approximate.
     *
     * The device-MMIO rewind is deliberately NOT in this set: its re-run is
     * a CF_MEMI_ONLY TB whose non-memory instrumentation plugins/api.c
     * suppresses, so the add fires once, current_pc never names the rewound
     * instruction, and the predicate below correctly stays silent.
     */
    bool prev_tail_aborted = false;
    {
        const BBTemplate *prev_head =
            g_retired_prev_head[retired_slot(cpu_index)];
        uint32_t prev_total = tb_head_insns(prev_head);
        if (delta_retired > 0 && delta_retired < prev_total && cur_tb_tmpl &&
            tb_head_insn_pc_at(prev_head, (uint32_t)(delta_retired - 1)) ==
                cur_tb_tmpl->start_pc) {
            delta_retired--;
            prev_tail_aborted = true;
            g_stats.user_clock_abort_recredits++;
            g_stats.user_clock_abort_recredit_insns++;
        }
    }
    /*
     * Record the pending prev's extent while it is still measurable — and
     * CAPTURE ITS TAIL INSN'S DST SNAPS (T5).
     *
     * This dispatch's lagged delta belongs to the dispatch before it.  When
     * that earlier dispatch is the TB still sitting in the pending-seal
     * slot, the delta IS how much of it ran, and this is the last moment
     * anyone can say so on this vCPU: if the pinned process is migrating
     * away, every later dispatch here belongs to somebody else and rolls
     * the cursor past prev for good.  Placed before every gate that can
     * bail the step (a bailed step is exactly the case this exists for) and
     * AFTER the abort re-credit above, so the recorded extent counts only
     * retirements.  Recorded once per prev (note_prev_extent's guard).
     *
     * The tail capture rides the same site, OWNED OR NOT: the registers
     * still hold prev's last retired instruction's post-exec values (this
     * TB's body has not run), and this may be the only dispatch that can
     * still observe them — which is precisely what makes a measured extent
     * FULLY OBSERVED (§4.2a).  The branch's REG_IP dst is stamped with the
     * dispatched next PC; a seal that resolves a different successor
     * patches it (patch_tail_ip_snaps).
     */
    if (BBTemplate *pending = pb.prev()) {
        if (pending == g_retired_prev_head[retired_slot(cpu_index)] &&
            !pb.live_prev_extent_valid()) {
            uint32_t cap = tb_head_insns(pending);
            uint64_t ext = delta_retired > cap ? cap : delta_retired;
            pb.note_prev_extent(ext);
            /* Locate the last-executed fragment and its executed count. */
            uint64_t left = ext;
            const bool tail_aborted = prev_tail_aborted;
            for (BBTemplate *pf = pending; pf && left > 0;
                 pf = pf->next_tb_fragment) {
                if (left <= pf->n_insns) {
                    snap_prev_tail_dsts(cpu_index, pf,
                                        cur_tb_tmpl ? cur_tb_tmpl->start_pc
                                                    : 0,
                                        (uint32_t)left, tail_aborted);
                    break;
                }
                left -= pf->n_insns;
            }
        }
    }

    /* Whether the delta folded at THIS dispatch was billed to the window
     * clock.  The fault observation, which runs later in this same step,
     * needs it: g_retired_owner_owned is re-armed for the CURRENT dispatch
     * below, and a re-credit against a bill that was never taken would run
     * the clock backwards. */
    g_retired_prev_billed[retired_slot(cpu_index)] = false;

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
        /* Ownership of a user TB: is the ADDRESS SPACE it is executing in
         * one this trace owns?  That is the whole rule — every thread
         * inside an owned space is traced (see pin_user_tb_owned).
         * Counted and traced are the same set by construction: a TB the
         * trace does not own neither advances the user clock nor reaches
         * the trace. */
        if (live_priv == 0 && cur_tb_tmpl) {
            uint64_t live_pid = live_process_id();
            user_owned = pin_user_tb_owned(cpu_index, live_pid,
                                           live_thread_id());
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
        /* Window-clock ruling (maintainer, 2026-07-29; refined 2026-07-30
         * to the bbv rule): the window clock counts what the BBV plugin
         * counts in the simpoint-generation regime — user mode, canonical
         * loop translation — because SimPoint offsets are selected from
         * bbv counts and any other rule misaligns every simpoint-anchored
         * window.  Measured on bbv itself: a REP bills one count per TB
         * entry the loop translation makes (1 + floor((N-2)/65536) for an
         * N-iteration counter-terminated REP).  So when the PREVIOUS
         * counted TB ended with a REP and that execution left by
         * re-entering the instruction (reenter=true), its tick is
         * withheld here, one dispatch later — UNLESS the re-entry sits on
         * a canonical chunk boundary (chunk=true), which the reference
         * regime also bills; the completing execution (reenter=false: the
         * looping translation's final chunk, a flag-break, a zero-count
         * REP, or the trailing pass) always ticks.  Under canonical
         * translation the correction nets to zero; under icount /
         * single-step / TF it reproduces the canonical count from
         * architectural state.  The canonical-chunk carve-out is x86-REP-
         * only BY CONSTRUCTION: chunk is published solely by do_gen_rep,
         * so an AArch64 MOPS re-entry (a cpu_loop_exit_requested split or
         * a mid-instruction fault — timing artifacts the user-mode bbv
         * reference regime never bills, unlike REP_MAX chunks, which are
         * deterministic in the count register) always withholds — the
         * landed MOPS rule, unchanged.  Keyed on the remembered fan-out
         * pcs (membership, one per fragment terminator) so a foreign REP
         * executed between two owned dispatches cannot trigger it.  The
         * raw latch (cp_facts) describes exactly the TB that finished
         * before this dispatch. */
        {
            RepSelfLoopState &rs_clk = rep_state(cpu_index);
            if (rs_clk.prev_tb_counted && rs_clk.cp_facts.reenter &&
                !rs_clk.cp_facts.chunk &&
                rs_clk.prev_tb_rep_contains(rs_clk.cp_facts.pc)) {
                if (g_user_icount > 0) {
                    g_user_icount--;
                }
                g_stats.rep_clock_ticks_withheld++;
            }
            rs_clk.prev_tb_counted = user_owned;
            rs_clk.prev_tb_rep_n = 0;
            if (user_owned && cur_tb_tmpl) {
                /* Every fragment's last insn: the splitter seals a
                 * fragment at each self-loop terminator, so this collects
                 * each fan-out insn in the TB.  x86 ends the TB at a REP
                 * (one hop); an AArch64 SETP/SETM/SETE trio contributes
                 * three, and a cpu_loop_exit_requested split re-enters at
                 * the SPLIT insn's own pc — which is why membership, not
                 * the TB-terminating pc, keys the withhold. */
                for (BBTemplate *lf = cur_tb_tmpl; lf;
                     lf = lf->next_tb_fragment) {
                    if (lf->n_insns > 0 &&
                        lf->insn_fields[lf->n_insns - 1].rep_memops_per_iter
                            > 0 &&
                        rs_clk.prev_tb_rep_n <
                            RepSelfLoopState::REP_CLK_PCS) {
                        rs_clk.prev_tb_rep_pcs[rs_clk.prev_tb_rep_n++] =
                            lf->insn_pcs[lf->n_insns - 1];
                    }
                }
            }
        }
        /*
         * THE WINDOW CLOCK COUNTS WHAT EXECUTED.
         *
         * It used to count @delta — the advance of insn_count, whose per-TB
         * inline add credits a TB's whole instruction count at TB ENTRY.  A
         * block the guest entered and did not run to the end was therefore
         * billed in full: the marker window's clock read above the trace's
         * own instruction count on every run with a fault in it, and by
         * exactly the same amount at zero doses, where the END block's
         * unexecuted tail was billed by the clock AND claimed by the wire so
         * the two agreed while both were wrong.
         *
         * @delta_retired is the instruction's own count (see
         * retired_advance).  It is LAGGED: the instructions observed at this
         * dispatch are the ones the PREVIOUS dispatch's TB executed, so it
         * folds against that dispatch's ownership.  The segment close folds
         * the in-flight block's own executed prefix, so nothing is left
         * uncounted at the end.
         *
         * @delta and the bill-site counters below are KEPT, as the
         * instrument they became: user_clock_billed_insns minus
         * user_clock_retired_insns is the phantom bill this replaces, and it
         * stays visible instead of disappearing with the defect.
         */
        if (prev_dispatch_owned) {
            g_user_icount += delta_retired;
            g_stats.user_clock_retired_insns += delta_retired;
            g_retired_prev_billed[retired_slot(cpu_index)] = true;
            /* The retired delta has the same exposure @delta has: anything
             * that executes between two dispatches WITHOUT being dispatched
             * itself (a context the trace_this_ctx gate skips) lands in it.
             * Bound it by the TB it is attributed to and name the excess. */
            uint32_t prev_cap =
                tb_head_insns(g_retired_prev_head[retired_slot(cpu_index)]);
            if (delta_retired > prev_cap) {
                g_stats.user_clock_retired_over_tb++;
                g_stats.user_clock_retired_over_insns +=
                    delta_retired - prev_cap;
            }
        }
        if (user_owned) {
            /*
             * BILL-SITE ACCOUNTING (see the Stats block on
             * user_clock_billed_insns).  What the window clock bills is a
             * DELTA of consecutive insn_count reads, not this TB's own
             * instruction count.  Whenever those differ, the owned process
             * is being billed for instructions that some other dispatch
             * retired — a fork child's user code, most visibly — and the
             * only previous way to see it was to decode the trace back out
             * and subtract OWNED_CP from user_covered, which shows a
             * residual and names nothing.  Compare the two here, where both
             * are in hand.
             */
            g_stats.user_clock_billed_tbs++;
            g_stats.user_clock_billed_insns += delta;
            if (!cur_tb_tmpl) {
                /* No template: this TB cannot reach the wire at all, so
                 * everything billed on it is billed-but-never-traced. */
                g_stats.user_clock_bill_no_template++;
            } else {
                uint64_t tb_insns = 0;
                for (BBTemplate *bf = cur_tb_tmpl; bf;
                     bf = bf->next_tb_fragment) {
                    tb_insns += bf->n_insns;
                }
                if (delta != tb_insns) {
                    g_stats.user_clock_bill_mismatch_tbs++;
                    if (delta > tb_insns) {
                        g_stats.user_clock_bill_excess_insns +=
                            delta - tb_insns;
                    }
                }
            }
        }
        if (cur_tb_tmpl) {
            cur_tb_tmpl->is_system = live_priv != 0;
            cur_tb_tmpl->is_system_cp_confirmed = true;
        }
        /* Arm the lagged attribution for the NEXT dispatch: the
         * instructions counted there are the ones this TB executes. */
        g_retired_owner_owned[retired_slot(cpu_index)] = user_owned;
    }

    /* §2.13 warmup-boundary hold, armed at DISPATCH: when a counted TB
     * ending in a fan-out instruction executes, that instruction is
     * architecturally in flight from now until the emission that retires
     * it releases the hold (fan-out block in emit_body_entry).  Arming at
     * dispatch — not at the instruction's first emission — is what keeps
     * the boundary arm-invariant: a chunk translation's first record
     * emits after the crossing (whole-BB fault deferral), when an
     * emission-armed hold would not yet exist.  Only live while an
     * active segment's boundary is still uncaptured, so the per-TB cost
     * exists only during a simpoint window's warmup phase; in pinned
     * modes only the owned (counted) user TBs arm it. */
    if (g_trace_segments.is_active() &&
        g_seg_warmup_end_trace_insns == UINT64_MAX && cur_tb_tmpl &&
        (pinned_asid == CST_ASID_UNPINNED || user_owned)) {
        /* One arm per fragment terminator — a MOPS trio is three mid-TB
         * fan-out terminators, each independently able to straddle the
         * crossing (same walk as the clock's prev_tb_rep_pcs collection). */
        RepSelfLoopState &rs_wh = rep_state(cpu_index);
        for (BBTemplate *lf_wh = cur_tb_tmpl; lf_wh;
             lf_wh = lf_wh->next_tb_fragment) {
            if (lf_wh->n_insns > 0 &&
                lf_wh->insn_fields[lf_wh->n_insns - 1].rep_memops_per_iter
                    > 0) {
                rs_wh.warmup_hold_update(
                    lf_wh->insn_pcs[lf_wh->n_insns - 1], true);
            }
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
    in.pinned_asid = pinned_asid;
    in.live_asid = live_asid;
    in.live_priv = live_priv;
    /* CAPTURE ownership drives the foreign-ASID drop, the kernel-excursion
     * fold, and the (asid,thread) context refresh — widened to every user
     * context in trace-all.  The CLOCK stays user_owned (folded above). */
    in.user_owned = capture_owned;
    in.evs = nullptr;
    in.n_evs = qemu_plugin_drain_cpu_events(cpu_index, &in.evs);
    evq_note_drain(cpu_index, in.n_evs, icount_prev);
    in.cpu_index = cpu_index;
    in.watch_pc = watch_pc;
    /* Guest thread of the TB executing NOW, for the PRE-WINDOW phase: the
     * async-window arrows record which thread an interrupt was delivered in,
     * and that is knowable only on the ENTER's own step.  The read-only peek
     * is used here because this phase runs on steps that bail and the minting
     * sample would renumber the wire (see thread_identity_peek);
     * in.cur_tid is overwritten with the minting sample below, before the
     * seal phase, which is what frame ownership and the depth stamp count
     * against. */
    in.cur_tid = thread_identity_peek(cpu_index, live_priv);
    /* The step's RAW thread pointer, for the async-owner predicate (see
     * StepIn::cur_tp).  Where the register cannot be trusted at this
     * privilege the step inherits the vCPU's last COMMITTED pointer — the
     * entering thread — mirroring cur_tid's inheritance; before any commit
     * on this vCPU nothing is known and the flag stays false.  cur_tp_strict
     * records which branch ran: only a FRESH sample feeds the kexc
     * task-identity rule (an inherited value is exactly the stale evidence
     * that rule overrules). */
    if (g_system_mode && cpu_index < CST_PIN_MAX_VCPUS) {
        uint64_t step_tp;
        if (thread_ptr_sample(live_priv, &step_tp)) {
            in.cur_tp = step_tp;
            in.cur_tp_ok = true;
            in.cur_tp_strict = true;
        } else if (g_vcpu_last_tp[cpu_index] != CST_TP_UNSEEN) {
            in.cur_tp = g_vcpu_last_tp[cpu_index];
            in.cur_tp_ok = true;
        }
    }
    /* Every supported target names an address space by a page-table root,
     * which is a per-process identity. */
    in.asid_is_identity = true;
    /* Does the trace CAPTURE the address space this block is executing in?
     * The kernel keep rule refuses a block whose live root is nobody's the
     * trace owns (see kexc_kernel_kept_foreign_root); asking here keeps the
     * capture policy — the pin, Stage B1's owned set, trace-all's
     * everything — in the one place that already knows it.  Kernel TBs on a
     * wide-register target only, and the common case (the pin itself)
     * short-circuits ahead of the set lookup; caller holds exec_lock, which
     * every mutation of g_owned also holds. */
    if (in.pinned && in.asid_is_identity && live_priv > 0) {
        in.live_root_owned = marker_trace_all() ||
                             owned_contains_locked(live_process_id());
    }

    /* CST_TID2_DIAG: the delivery-condition instrument for the SMP async
     * ownership work.  For every async edge drained this step, print the
     * step's vCPU, the event's own privilege/pc/asid, the LIVE thread
     * pointer at the drain step (raw, plus whether the current privilege
     * makes it trustworthy), the identity map's verdict on it, and the
     * step's gates — which vCPU mints when, and which vCPU receives
     * interrupts in whose context, in one joinable stream.  stderr only;
     * no behavioural change. */
    if (tid2diag_on() && g_system_mode) {
        for (size_t di = 0; di < in.n_evs; di++) {
            const struct qemu_plugin_cpu_event &dev = in.evs[di];
            if (dev.kind != QEMU_PLUGIN_CPU_EV_ASYNC_ENTER &&
                dev.kind != QEMU_PLUGIN_CPU_EV_ASYNC_RETURN) {
                continue;
            }
            uint64_t dtp = qemu_plugin_get_thread_ptr();
            bool dtrust = live_priv == 0 || thread_ptr_tracks_current();
            bool dhit = g_thread_tid_map &&
                        g_thread_tid_map->count(dtp) != 0;
            fprintf(stderr, "champsim_tracer: [tid2] %s vcpu=%u evpriv=%d "
                    "evpc=0x%" PRIx64 " evasid=0x%" PRIx64
                    " evtp=0x%" PRIx64 " evtpok=%d live_priv=%d "
                    "tp=0x%" PRIx64 " trust=%d maphit=%d peek=%u uown=%d "
                    "mapsz=%zu\n",
                    dev.kind == QEMU_PLUGIN_CPU_EV_ASYNC_ENTER ? "ENTER"
                                                               : "RETURN",
                    cpu_index, (int)dev.priv, dev.pc, dev.asid,
                    dev.tp, (int)dev.tp_ok, live_priv,
                    dtp, (int)dtrust, (int)dhit, in.cur_tid,
                    (int)in.user_owned,
                    g_thread_tid_map ? g_thread_tid_map->size() : 0);
        }
    }

    /* Pre-window phase: async-window arrows, foreign-ASID boundary, prev
     * swap — in that order, before any window decision. */
    PathBuilder::StepStatus st = pb.step_events(in);
    if (st != PathBuilder::StepStatus::CONTINUE) {
        if (in.pinned && user_owned) {
            /* CST_MARKER_DIAG stall canaries: pinned user TBs bailing
             * here means the user clock advances but nothing traces. */
            if (st == PathBuilder::StepStatus::SUSPENDED) {
                tls_mkdiag_susp_user++;
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

    /* Guest-thread identity across the seal boundary.  walk_tid is the
     * committed identity — the thread that ran the deferred prev this seal
     * emits, and the thread that owns a fault frame the seal opens for it.
     * cur_tid is this step's sample: the thread the TB executing NOW belongs
     * to, which is what the depth stamp counts frames for.  They differ
     * exactly on the step where the guest scheduler switched tasks on this
     * vCPU, and that step is where a peer thread would otherwise inherit the
     * descheduled thread's fault nesting. */
    in.walk_tid = resolve_thread_id(cpu_index);
    in.cur_tid = thread_identity_sample(cpu_index, live_priv);

    st = pb.step_seal(in, out_stream);

    if (tiddiag_level() >= 2 && g_system_mode) {
        tiddiag_probe_ktp(cpu_index, in.live_priv,
                          in.cur ? in.cur->start_pc : 0);
    }

    /* Advance this vCPU's guest-thread identity AFTER the deferred-prev
     * seal above: the just-emitted BB belongs to the thread that executed
     * it, so this refresh takes effect only for the NEXT emit.  Under
     * exec_lock — thread_ptr_to_tid mutates the per-segment map.
     *
     * The sample itself was taken just before the seal (thread_identity_
     * sample, which the seal's per-thread frame ownership needs); this is
     * where it lands.  It is taken at whatever privilege this TB runs at, so
     * long as the target's register still names the current task there
     * (thread_ptr_sample).  That is what makes a strand's identity follow
     * the guest scheduler rather than the vCPU: a task switch performed
     * entirely inside the kernel — the tail of a clone handing the child
     * its first run, a kernel thread scheduled in on a borrowed mm, an
     * interrupt handler running after the scheduler moved on — retags the
     * vCPU here instead of leaving every later kernel block credited to
     * whichever thread last returned to user on it.  Where the register is
     * only trustworthy at user privilege the sample is skipped and kernel
     * code inherits the entering thread, as before. */
    thread_identity_commit(cpu_index, in.live_priv);
    if (in.pinned && in.user_owned && in.live_priv == 0 &&
        cpu_index < CST_PIN_MAX_VCPUS) {
        /* Context-asid sibling of the tid refresh: the live user root at
         * priv 0 IS the process's user CR3.  Record it (idempotent — same
         * root maps to the same index) so a subsequent kernel excursion
         * folds this thread's regfile/FieldState CONTEXT to the entering
         * process, not the KPTI kernel CR3.  Set every user TB (not only on
         * a tid change) so it holds the entering asid at the excursion. */
        uint64_t live_root = qemu_plugin_get_addr_space_id();
        g_vcpu_cur_asid_index[cpu_index] =
            asid_root_to_index(live_root, asid_first_sight_sig(live_root));
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

    run_deferred_window_closes(pb, cpu_index, cur_tb_tmpl);
    g_rec_mutex_unlock(&exec_lock);

    if (g_spec_flush_latched.exchange(false, std::memory_order_relaxed)) {
        qemu_plugin_request_tb_flush();
    }
}

/*
 * ---------------------------------------------------------------------------
 * The event-queue absorber: the per-TB drain point.
 * ---------------------------------------------------------------------------
 *
 * QEMU's per-vCPU path-event queue is grow-only and never drops.  Its only
 * consumer used to be events_path_step, reached only from the heavy
 * vcpu_tb_exec, which the JIT dispatches only when trace_this_ctx says this
 * context is both in-segment AND owned.  Every window where that gate is
 * shut is a window where the queue has NO consumer at all:
 *
 *   W1 a foreign / unconfirmed context under the narrow-ASID pin, where
 *      trace_this_ctx diverged from is_active — the window this absence
 *      was first caught in.  That path is gone: the gate mirrors is_active
 *      on every target, so an in-segment foreign TB now dispatches the
 *      heavy callback (which drops it) and drains on the way;
 *   W2 inter-segment (is_active == 0 zeroes trace_this_ctx on every ISA,
 *      so the heavy callback does not dispatch);
 *   W3 after the marker window closes -- W2's code path, mirrored to every
 *      vCPU;
 *   W4 pre-first-segment once the queue has been enabled, between simpoint
 *      clusters, and the coarse fast-forward stretch;
 *   W6 an SMP peer vCPU that dispatched once and never again.
 *
 * In all of them the queue's length was exactly "events produced by untraced
 * execution", i.e. unbounded, and the whole backlog then landed in ONE
 * tb_exec callback -- 83,532 events after 119.8 million guest instructions,
 * measured on a mipsel churn cell, three O(n) passes charged to a single
 * guest instruction.
 *
 * This callback closes all of them the same way.  It is registered for EVERY
 * translated TB with no ownership, privilege or segment condition, and gated
 * on the ONE scoreboard slot no attribution decision feeds: evq_pending,
 * which QEMU sets on push and clears on drain.  So every TB entry is a drain
 * point, and the queue can only ever hold what one in-flight TB plus the
 * exception edges around it produced.
 *
 * REGISTERED LAST, after vcpu_tb_exec.  Each cond_cb re-loads its slot when
 * it runs (the same ordering the budget cb already relies on), so
 * on a TB where the heavy callback dispatched, its own drain has already
 * zeroed evq_pending and this callback's brcond is false: the light path runs
 * on exactly the TBs where nothing else drained, and the traced path pays one
 * load and one brcond.
 *
 * It NEVER EMITS.  It folds state (absorb_events) and nothing else; the seal,
 * the merges and every byte written to the body stream stay in step_seal,
 * which only an owned, dispatching step reaches.  A record therefore cannot
 * originate from a context the heavy callback would not have dispatched for.
 */
static void vcpu_evq_absorb(unsigned int cpu_index, void *udata)
{
    (void)udata;
    /* Wrong-path simulation: pushes are spec-suppressed at source, so the
     * queue cannot grow during an excursion.  The flag survives to the next
     * correct-path TB, which absorbs -- bounded by wpdepth.  Also keeps this
     * off the nested WP dispatch path entirely, exactly as the heavy
     * callback and the pin probe do. */
    if (g_wp_in_progress) {
        return;
    }

    /* Drain first, unlocked: the queue is single-producer/single-consumer
     * and both are this vCPU thread.  A zero-length drain means the heavy
     * callback beat us to it on this TB (a stale slot), and costs nothing
     * further. */
    const struct qemu_plugin_cpu_event *evs = nullptr;
    size_t n_evs = qemu_plugin_drain_cpu_events(cpu_index, &evs);
    evq_note_drain(cpu_index, n_evs,
                   qemu_plugin_u64_get(g_scoreboard.insn_count, cpu_index));
    if (n_evs == 0) {
        return;
    }

    /* Absorbing is instrumentation, not guest execution.  Unpaused, its
     * host cost on a long foreign span is charged to guest time -- the exact
     * mechanism behind the x86 tick/scheduler storm.  The guard is nestable
     * and composes with the heavy path's. */
    VClockPauseGuard vclock_guard;

    g_rec_mutex_lock(&exec_lock);

    PathBuilder &pb = path_builder(cpu_index);
    PathBuilder::StepIn in;
    in.cpu_index = cpu_index;
    in.evs = evs;
    in.n_evs = n_evs;

    /* Exactly the fields absorb_events reads.  Every one of them is a
     * plugin-side or event-side datum -- no TB, no template, no successor:
     * the absorber has no block to attribute and never asks for one. */
    uint64_t pinned = g_pinned_asid.load(std::memory_order_relaxed);
    in.pinned = pinned != CST_ASID_UNPINNED;
    in.pinned_asid = pinned;
    in.asid_is_identity = true;
    in.live_priv = qemu_plugin_get_priv_level();
    in.live_asid = qemu_plugin_get_addr_space_id();
    /* Read-only peek, never the minting sample: minting a thread id here
     * would renumber the wire from a context the trace does not emit. */
    in.cur_tid = thread_identity_peek(cpu_index, in.live_priv);
    /* The async-owner predicate's raw thread pointer, sampled the same way
     * the step samples it (fresh where the privilege allows, otherwise this
     * vCPU's last committed value). */
    if (g_system_mode && cpu_index < CST_PIN_MAX_VCPUS) {
        uint64_t step_tp;
        if (thread_ptr_sample(in.live_priv, &step_tp)) {
            in.cur_tp = step_tp;
            in.cur_tp_ok = true;
            in.cur_tp_strict = true;
        } else if (g_vcpu_last_tp[cpu_index] != CST_TP_UNSEEN) {
            in.cur_tp = g_vcpu_last_tp[cpu_index];
            in.cur_tp_ok = true;
        }
    }

    pb.absorb_events(in);

    g_stats.evq_absorb_calls++;
    g_stats.evq_absorb_events += n_evs;
    if (n_evs > g_stats.evq_absorb_batch_peak) {
        g_stats.evq_absorb_batch_peak = n_evs;
    }

    g_rec_mutex_unlock(&exec_lock);
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    /* This callback is registered via register_vcpu_tb_exec_cond_cb
     * gated on the trace_this_ctx scoreboard slot (is_active folded with
     * pinned-context ownership), so the JIT only dispatches it in-segment
     * for a context this trace owns.  Inter-segment dispatch is handled
     * solely by inline_add (icount/budget) and vcpu_tb_check_budget; a
     * foreign / unowned in-segment TB dispatches like any other and the
     * step drops it, so the gate never diverges from is_active.
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
    if (g_wp_in_progress) {
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
        /* Positioning accuracy only, lock-free: the live page-table root
         * against the representative pin, with no lock taken. */
        bool ff_counted =
            qemu_plugin_get_addr_space_id() ==
                g_pinned_asid.load(std::memory_order_relaxed) &&
            qemu_plugin_get_priv_level() == 0;
        /* The positioning clock follows the same window-clock rule as the
         * traced fold in events_path_step (which this fast path bypasses):
         * a counted REP execution that left by re-entering the
         * instruction OFF a canonical chunk boundary would not exist
         * under the canonical loop translation the SimPoint offsets were
         * counted with (user-mode bbv), so its tick is withheld one
         * dispatch later.  Same prev-TB protocol, same per-vCPU state;
         * facts are only consulted when the previous counted TB actually
         * ended in a fan-out instruction, keeping the common fast-forward
         * TB at zero extra API calls.  Without this, an -icount
         * fast-forward opens the window early by every REP's re-execution
         * count. */
        {
            RepSelfLoopState &rs_ff = rep_state(cpu_index);
            if (rs_ff.prev_tb_counted && rs_ff.prev_tb_rep_n != 0 &&
                qemu_plugin_rep_reenter() &&
                !qemu_plugin_rep_chunk_boundary() &&
                rs_ff.prev_tb_rep_contains(qemu_plugin_rep_pc())) {
                if (g_user_icount > 0) {
                    g_user_icount--;
                }
                g_stats.rep_ff_ticks_withheld++;
            }
            rs_ff.prev_tb_counted = ff_counted;
            rs_ff.prev_tb_rep_n = 0;
            if (ff_counted && cur_tb_tmpl) {
                /* Same membership collection as the traced fold: one pc
                 * per fragment terminator (an AArch64 MOPS trio is three
                 * mid-TB terminators; x86 ends the TB at the REP). */
                for (BBTemplate *lf_ff = cur_tb_tmpl; lf_ff;
                     lf_ff = lf_ff->next_tb_fragment) {
                    if (lf_ff->n_insns > 0 &&
                        lf_ff->insn_fields[lf_ff->n_insns - 1]
                                .rep_memops_per_iter > 0 &&
                        rs_ff.prev_tb_rep_n <
                            RepSelfLoopState::REP_CLK_PCS) {
                        rs_ff.prev_tb_rep_pcs[rs_ff.prev_tb_rep_n++] =
                            lf_ff->insn_pcs[lf_ff->n_insns - 1];
                    }
                }
            }
        }
        if (ff_counted) {
            g_user_icount += delta;
        }
        const SimPointEntry *sp = g_simpoints.current();
        uint64_t eff_start = (sp && sp->start_insn > warmup_insns)
            ? sp->start_insn - warmup_insns : 0;
        /* Positioning is against the PIN-ABSOLUTE clock: the schedule's
         * offsets are all measured from the pin, and once cluster N's
         * window has closed the epoch counter has restarted while the
         * schedule has not.  On the first cluster the base is 0 and this
         * is the g_user_icount comparison it replaces. */
        if (sp && pin_user_clock() >= eff_start) {
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

    /* Latch the just-finished TB's architectural self-loop accounting.
     * Must happen here, before the correct-path step: QEMU's fields are
     * overwritten by any later REP — a wrong-path excursion's, a kernel
     * fault path's — so this dispatch's raw copy is the only valid source.
     * Consumers: the PathBuilder absorbs it into the pending-seal prev's
     * travelling facts at step_events (deferral-safe; see
     * RepSelfLoopState::emit_facts), and the window-clock correction in
     * events_path_step reads it directly (it acts exactly one dispatch
     * behind, which is where the latch points). */
    rep_state(cpu_index).cp_facts.pc       = qemu_plugin_rep_pc();
    rep_state(cpu_index).cp_facts.iters    = qemu_plugin_rep_iterations();
    rep_state(cpu_index).cp_facts.bytes    = qemu_plugin_rep_bytes();
    rep_state(cpu_index).cp_facts.complete = qemu_plugin_rep_complete();
    rep_state(cpu_index).cp_facts.reenter  = qemu_plugin_rep_reenter();
    rep_state(cpu_index).cp_facts.chunk    = qemu_plugin_rep_chunk_boundary();

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
        BBTemplate *watch_prev = path_builder(cpu_index).prev();
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
        /* Per-vCPU, not per-thread: under round-robin TCG one thread
         * dispatches every vCPU and a thread-keyed latch would announce
         * only the first. */
        static bool announced[CST_PIN_MAX_VCPUS];
        bool &a = announced[cpu_index < CST_PIN_MAX_VCPUS
                            ? cpu_index : CST_PIN_MAX_VCPUS - 1];
        if (!a) {
            a = true;
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

/*
 * MARKER DETECTION IS A BYTE MATCH, MADE AT TRANSLATION TIME.
 *
 * A marker is CST_MARKER_SEQ_LEN identical immediate-loads in a row, and
 * that is a property of the bytes, not of an execution order.  The
 * translator finds every instruction that IS the terminating instruction of
 * a marker sequence, compares the CST_MARKER_SEQ_LEN-1 instruction slots
 * immediately before it against the rest of that sequence, and — when they
 * match — arms ONE execution callback on it.  That callback firing is the
 * marker.  See champsim_tracer_marker_detect.h for why this is the
 * mechanism: a fault, an interrupt, a migration, a page straddle,
 * single-stepping, -icount or any TB slicing between the marker's
 * instructions cannot change bytes, so none of them can lose a marker.
 *
 * The helpers below are the whole of it: read the preceding slots, and
 * decide.  All run on a vCPU thread with current_cpu set (translation and
 * execution both do), so the guest read walks the live address space — the
 * one whose instruction stream this is.
 */

/* Read @len guest bytes at @addr into @out.  Thread-local scratch: called
 * from translation and from marker callbacks, both on vCPU threads, with no
 * lock held. */
static bool marker_read_guest(uint64_t addr, uint8_t *out, size_t len)
{
    static thread_local GByteArray *buf;
    if (!buf) {
        buf = g_byte_array_new();
    }
    if (!qemu_plugin_read_memory_vaddr(addr, buf, len)) {
        return false;
    }
    if (buf->len < len) {
        return false;
    }
    memcpy(out, buf->data, len);
    return true;
}

/*
 * Fill @prefix with the g_marker_seq.prefix_bytes guest bytes immediately
 * before @pc — the CST_MARKER_SEQ_LEN-1 instruction slots preceding the
 * instruction at @pc, at known fixed-width offsets.
 *
 * Preferred source is THIS TB's own translated instruction stream when it
 * reaches back far enough (@i is @pc's index in it): those are exactly the
 * bytes QEMU translated, and no guest read is needed.  A TB that starts
 * mid-sequence — a page split, a branch landing inside it, one-insn-per-TB
 * under -icount or a single-stepping injector — falls back to reading guest
 * memory.  Returns false only when neither source can produce the bytes.
 */
static bool marker_gather_prefix_tb(struct qemu_plugin_tb *tb, size_t i,
                                    uint64_t pc, uint8_t *prefix)
{
    const MarkerSeq &m = g_marker_seq;
    uint32_t need = (uint32_t)m.n_insns - 1u;
    uint64_t base = pc - m.prefix_bytes;

    if (i < need) {
        return false;
    }
    for (uint32_t k = 0; k < need; k++) {
        struct qemu_plugin_insn *p = qemu_plugin_tb_get_insn(tb, i - need + k);
        if (!p ||
            qemu_plugin_insn_vaddr(p) != base + (uint64_t)k * m.insn_bytes ||
            qemu_plugin_insn_size(p) != m.insn_bytes) {
            return false;
        }
        qemu_plugin_insn_data(p, prefix + (size_t)k * m.insn_bytes,
                              m.insn_bytes);
    }
    return true;
}

static bool marker_gather_prefix(struct qemu_plugin_tb *tb, size_t i,
                                 uint64_t pc, uint8_t *prefix)
{
    const MarkerSeq &m = g_marker_seq;
    if (marker_gather_prefix_tb(tb, i, pc, prefix)) {
        return true;
    }
    return marker_read_guest(pc - m.prefix_bytes, prefix, m.prefix_bytes);
}

/* The physical page an instruction's page-aligned base sits at, or false. */
static bool marker_page_paddr(uint64_t vaddr, uint64_t *paddr)
{
    uint64_t pa;
    if (!qemu_plugin_vaddr_to_paddr(vaddr, &pa)) {
        return false;
    }
    *paddr = pa;
    return true;
}

/*
 * The PREDECESSOR side of a straddling sequence.
 *
 * If this TB's TRAILING instructions are the LEADING slots of a marker
 * sequence whose remaining slots lie past the end of the page it ends on,
 * remember them: this is the only moment they are knowable.  The page is
 * resident right now — QEMU has just translated code out of it — and on a
 * software-managed TLB it need not still be when the sequence's terminating
 * instruction executes, one or two instructions later, on the far side of a
 * fault or a preemption (see champsim_tracer_marker_detect.h).
 *
 * What is recorded is the verdict-so-far (which sequence the leading slots
 * belong to, and how many of them there were) together with the PHYSICAL
 * address those slots sat at — the first half of the pair the tail's own
 * translation completes.  Nothing here arms a callback: the terminating
 * instruction is still the one and only instruction that fires.
 */
/* Straddle tracing: names every witness taken and every straddle decision,
 * so a sequence that goes undecided can be attributed to the source that was
 * missing rather than guessed at.  Off unless CST_STRADDLE_DIAG is set. */
static inline bool marker_straddle_diag(void)
{
    static const bool on = getenv("CST_STRADDLE_DIAG") != nullptr;
    return on;
}

static void marker_witness_straddle(struct qemu_plugin_tb *tb,
                                    size_t raw_n_insns)
{
    const MarkerSeq &m = g_marker_seq;
    if (!m.valid || raw_n_insns == 0 || m.n_insns < 2) {
        return;
    }
    const uint64_t page = 4096;
    struct qemu_plugin_insn *last =
        qemu_plugin_tb_get_insn(tb, raw_n_insns - 1);
    if (!last || qemu_plugin_insn_size(last) != m.insn_bytes) {
        return;
    }
    uint64_t last_pc = qemu_plugin_insn_vaddr(last);

    /* @j leading slots end at the TB's last instruction.  Longest first: the
     * more slots seen on this side, the less is left to the other. */
    uint32_t jmax = (uint32_t)m.n_insns - 1u;
    if ((uint64_t)jmax > raw_n_insns) {
        jmax = (uint32_t)raw_n_insns;
    }
    uint8_t head[CST_MARKER_PAIR_SEQ_BYTES];
    for (uint32_t j = jmax; j >= 1; j--) {
        uint64_t base = last_pc - (uint64_t)(j - 1) * m.insn_bytes;
        uint64_t tail_vaddr = base + m.prefix_bytes;
        /* Straddling means the terminating instruction is on a LATER page
         * than the last slot seen here. */
        if ((tail_vaddr / page) == (last_pc / page)) {
            continue;
        }
        size_t at = raw_n_insns - j;
        bool ok = true;
        for (uint32_t k = 0; k < j; k++) {
            struct qemu_plugin_insn *p = qemu_plugin_tb_get_insn(tb, at + k);
            if (!p ||
                qemu_plugin_insn_vaddr(p) !=
                    base + (uint64_t)k * m.insn_bytes ||
                qemu_plugin_insn_size(p) != m.insn_bytes) {
                ok = false;
                break;
            }
            qemu_plugin_insn_data(p, head + (size_t)k * m.insn_bytes,
                                  m.insn_bytes);
        }
        if (!ok) {
            continue;
        }
        size_t nb = (size_t)j * m.insn_bytes;
        MarkerStraddleWitness w;
        w.match_start = memcmp(head, m.start, nb) == 0;
        w.match_end   = memcmp(head, m.end,   nb) == 0;
        if (!w.match_start && !w.match_end) {
            continue;
        }
        w.head_slots = (uint8_t)j;
        if (!marker_page_paddr(base, &w.prefix_paddr)) {
            continue;       /* resident enough to translate, not to resolve */
        }
        /* Every head length that matches gets its own witness: each names a
         * DIFFERENT terminating instruction, so they cannot displace one
         * another, and taking only the longest would drop the real one where
         * two sequences sit back to back (cell adjacent). */
        marker_straddle_witness_note(tail_vaddr, w);
        if (marker_straddle_diag()) {
            fprintf(stderr, "[straddle] witness tail=0x%" PRIx64 " head=%u "
                    "start=%d end=%d prefix_pa=0x%" PRIx64 " last_pc=0x%"
                    PRIx64 " n=%zu\n", tail_vaddr, (unsigned)j,
                    (int)w.match_start, (int)w.match_end, w.prefix_paddr,
                    last_pc, raw_n_insns);
        }
    }
}

/*
 * The TAIL side of a straddling sequence: rebuild the slots before @pc from
 * the predecessor page's WITNESS plus the tail page's own bytes.
 *
 * The witness says which sequence the leading @head_slots slots were and
 * that they matched it, so those bytes are the sequence's own; the slots
 * between them and the terminating instruction are on the tail's page,
 * which this translation is reading out of.  The assembled prefix is still
 * put through marker_whole_match by the caller, so a witness that does not
 * agree with what is actually on this page decides nothing.
 *
 * @prefix_paddr comes back with the PHYSICAL address the witness recorded
 * for the predecessor page.  It has to: by the time this side runs, that
 * page's translation can be gone — that is the whole reason the witness
 * exists — so re-resolving it HERE is exactly the read that fails, and the
 * pair would go unrecorded on precisely the runs that need it.
 */
static bool marker_straddle_prefix_from_witness(uint64_t pc, uint8_t *prefix,
                                                uint64_t *prefix_paddr)
{
    const MarkerSeq &m = g_marker_seq;
    MarkerStraddleWitness w;
    if (!marker_straddle_witness_get(pc, &w) ||
        (!w.match_start && !w.match_end) || w.head_slots == 0 ||
        w.head_slots >= m.n_insns) {
        return false;
    }
    /* When the head matched BOTH, the two sequences' bytes are equal over
     * it — that is what "both" means — so either is the same source. */
    const uint8_t *seq = w.match_start ? m.start : m.end;
    size_t head = (size_t)w.head_slots * m.insn_bytes;
    memcpy(prefix, seq, head);
    if (head < m.prefix_bytes &&
        !marker_read_guest(pc - m.prefix_bytes + head, prefix + head,
                           m.prefix_bytes - head)) {
        return false;
    }
    *prefix_paddr = w.prefix_paddr;
    return true;
}

/*
 * Re-decide the marker from guest memory when the instruction EXECUTES.
 *
 * Reached only for an instruction whose terminating-word match was made at
 * translation time but whose preceding slots could not be read then (the
 * page before it was not resident at that moment), or whose sequence
 * straddles a page boundary and this TB does not cover both of its pages.
 *
 * The guest read is the PREFERRED source and is asked first: it is the
 * address space that is actually running the instruction, so its answer is
 * exact, and it needs no table.  It is NOT a reliable one.  On a target with
 * a software-managed TLB the page holding the preceding slots can have lost
 * its TLB entry between the two halves of the sequence — a fault handler or
 * a preemption is enough — and QEMU's debug read has no hardware walker to
 * fall back on, so it fails for a page that is still perfectly mapped.  That
 * is not a proof that the slots did not execute; treating it as one lost 4
 * of 200,000 START sequences and a whole END marker (see
 * champsim_tracer_marker_detect.h).
 *
 * So when the read cannot be serviced, the straddle's verdict is taken from
 * its PHYSICAL PAGE PAIR, decided at translation time while both pages were
 * resident.  The tail's own physical address always resolves — this CPU is
 * executing out of that page — and it is allowed to decide only while it
 * DETERMINES the pair: a second, different predecessor page recorded behind
 * it marks the entry conflicting and the shortcut refuses.  A straddle with
 * no witnessed pair and no serviceable read is neither claimed nor guessed:
 * it is counted in marker_straddle_undecided(), whose one benign shape is a
 * LONE marker-shaped instruction at a page start — no sequence ran, no
 * witness was ever taken, and claiming nothing is the right answer.
 */
static MarkerWhich marker_verify_at_exec(uint64_t pc)
{
    const MarkerSeq &m = g_marker_seq;
    uint8_t seq[CST_MARKER_PAIR_SEQ_BYTES];
    if (!m.valid) {
        return MARKER_WHICH_NONE;
    }
    const uint64_t page = 4096;
    bool straddles = ((pc - m.prefix_bytes) / page) != (pc / page);
    /*
     * POSITIVE CONTROL (CST_STRADDLE_FORCE_UNREADABLE).  Whether the
     * backward read can be serviced is a property of the guest's TLB at one
     * instant, so on a lucky run the fallback below never runs and a suite
     * that only ever saw lucky runs would prove nothing about it.  With this
     * set, every STRADDLING sequence's read is treated as unserviceable and
     * the physical page pair has to carry the whole suite on its own.  It
     * makes the rare case the only case; it cannot make a marker appear.
     */
    static const bool force_unreadable =
        getenv("CST_STRADDLE_FORCE_UNREADABLE") != nullptr;
    if (!(straddles && force_unreadable) &&
        marker_read_guest(pc - m.prefix_bytes, seq, m.seq_bytes)) {
        return marker_whole_match(seq + m.prefix_bytes, m.insn_bytes, seq);
    }
    marker_prefix_unreadable_note();
    if (!straddles) {
        /* Not a straddle: the slots are on the tail's own page, which this
         * CPU is executing out of.  A read that fails there is the
         * execute-only case, not a lost translation, and there is no
         * second page and so no pair to consult. */
        return MARKER_WHICH_NONE;
    }
    uint64_t tail_paddr;
    MarkerWhich which = MARKER_WHICH_NONE;
    if (marker_page_paddr(pc, &tail_paddr)) {
        /* Ask the RUNNING address space for the predecessor page too.  It
         * usually cannot answer — a page whose bytes will not read is
         * normally a page with no translation to consult, which is the whole
         * reason this fallback exists — but when it CAN, the recorded pair
         * is checked in full and a different predecessor page refuses
         * outright.  Cheap, and it turns part of the reuse hazard from
         * "guarded against" into "detected". */
        uint64_t live_prefix = 0;
        uint64_t lp;
        if (marker_page_paddr(pc - m.prefix_bytes, &lp)) {
            live_prefix = lp & ~(page - 1);
        }
        which = marker_straddle_pair_lookup(tail_paddr, live_prefix);
    }
    if (which == MARKER_WHICH_NONE) {
        marker_straddle_undecided_note();
    }
    return which;
}

/*
 * The marker callback's own gate, shared by START and END.  Returns true
 * when this invocation is a real, correct-path marker of @which.
 *
 * A marker is a USER-SPACE event: the sequence is the target's own code.
 * The wrong-path fence is applied by the callers before this (a speculative
 * execution routinely runs the marker bytes).
 */
static bool marker_claim(void *udata, MarkerWhich which, uint64_t *pc_out)
{
    uint64_t pc;
    uint8_t  size;
    bool     recheck;
    marker_udata_unpack(udata, &pc, &size, &recheck);
    *pc_out = pc;
    if (qemu_plugin_get_priv_level() != 0) {
        return false;
    }
    if (recheck && marker_verify_at_exec(pc) != which) {
        return false;
    }
    return true;
}

/* Open the marker trace window on @cpu_index.  Both WIN_MARKER first-open
 * paths — wide-register and legacy single-pin — share this exact body:
 * guard against a redundant open, then window + user-clock reset + segment
 * start.  The caller holds exec_lock. */
static void marker_open_trace_window(unsigned int cpu_index, uint64_t asid)
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
    fprintf(stderr, "champsim_tracer: marker fired at icount %" PRIu64
            ", asid 0x%" PRIx64 " priv=%d (0=user,3=kernel) pc=0x%" PRIx64
            " — tracing %" PRIu64 " insns\n",
            lo, asid, qemu_plugin_get_priv_level(),
            qemu_plugin_get_pc(), span);
    start_trace_segment("marker", lo, hi, /* warmup= */ 0, span,
                        cpu_index, /* simpoint_weight= */ 0.0);
}

/* All-windows-closed stop shared by the END-marker paths.  The caller holds
 * exec_lock; when a segment is live this CLAIMS the close for the END marker
 * and arms it to run at the end of the marker's own true BB, then releases
 * exec_lock and returns; the pinned-simpoint positioning arm still exits
 * here.  @last_window selects the multi-process "(last window)" diagnostic
 * over the legacy single-pin one. */
static void marker_close_and_exit(bool last_window, unsigned int cpu_index)
{
    if (g_trace_segments.is_active() && !g_trace_segments.is_shutting_down()) {
        /*
         * THE END MARKER CLOSES AT A BLOCK BOUNDARY, NOT MID-BLOCK.
         *
         * This runs from inside the marker instruction's own execution
         * callback, so the block the marker sits in has not finished: the
         * TB is in the pending-seal slot with its later instructions still
         * to run, its memory callbacks unfired and its dst registers
         * unsnapped.  Closing here published that block sealed at whatever
         * had retired — one instruction on x86_64, four on the ISAs whose
         * marker sequence is four instructions long — and the
         * unsealed-at-close ledger read exactly that: peak 1, route END,
         * the first instruction of the END sequence.
         *
         * Blocks are always closed out where it is in our power, and here
         * it is: raise the arm and let the guest run out the marker's own
         * true BB.  The close then runs from run_deferred_window_closes at
         * the first step tail with no in-flight chain — the BB's own
         * boundary — by which time the ordinary seal walk has already
         * emitted the whole block with its memops, its register deltas and
         * its resolved terminal branch, exactly like every other entry.
         * Where the BB spans several TBs (a page split) or ends in a
         * mid-TB branch, "no in-flight chain" is still the same boundary:
         * the chain assembler is what decides it, not the TB edge.
         *
         * END-ALWAYS-WINS IS UNTOUCHED.  g_seg_end_marker_close is
         * latched HERE, at the marker, so the route this run closes by is
         * decided the moment the END executes and every close from now on
         * reports END; the arm below is only where in the instruction
         * stream that close lands.  The claim latch makes it
         * non-re-entrant: a second END sequence, or the same one arriving
         * again through the unowned-END path, finds the stop already owned
         * and adds nothing.
         */
        if (g_end_close_claimed.exchange(true, std::memory_order_relaxed)) {
            g_rec_mutex_unlock(&exec_lock);
            return;
        }
        if (last_window) {
            fprintf(stderr,
                    "champsim_tracer: end marker — closing after %" PRIu64
                    " user insns (last window)\n", g_user_icount);
        } else {
            fprintf(stderr, "champsim_tracer: end marker — closing after %"
                    PRIu64 " user insns\n", g_user_icount);
        }
        g_seg_end_marker_close = true;
        deferred_close(cpu_index).end_close_pending = true;
        g_rec_mutex_unlock(&exec_lock);
        return;
    }
    /*
     * END with NO window open.  In a pinned-simpoint run this is the
     * schedule POSITIONING between clusters (or before the first one):
     * the workload just ended, so every remaining cluster is an offset on
     * a clock that will never advance again, and continuing would leave
     * the tracer positioning forever toward a region that cannot arrive.
     *
     * The ruling that an END kills the tracer regardless of simpoints is
     * about the END, not about whether a window happened to be open when
     * it fired.  Terminate here: the segments already written are
     * complete and finalised, and the outstanding clusters are
     * unreachable BY DESIGN, named on the way out rather than waited on.
     *
     * Scoped to pinned-simpoint mode — plain WIN_MARKER has no schedule
     * to strand, and its no-window END keeps the historical return (the
     * unowned-END diagnostics own that case).
     */
    if (pinned_simpoint_mode() && !g_trace_segments.is_shutting_down()) {
        size_t left = g_simpoints.size() > g_simpoints.current_index()
            ? g_simpoints.size() - g_simpoints.current_index() : 0;
        fprintf(stderr,
                "champsim_tracer: end marker between simpoint windows at "
                "user clock %" PRIu64 " — the workload ended, so the run "
                "ends here with %zu of %zu scheduled simpoint(s) never "
                "reached (%zu segment(s) written)\n",
                pin_user_clock(), left, g_simpoints.size(),
                g_segments_written);
        fflush(stderr);
        g_trace_segments.set_shutting_down();
        g_rec_mutex_unlock(&exec_lock);
        exit(0);
    }
    g_rec_mutex_unlock(&exec_lock);
}

/*
 * A correct-path END marker that could not be attributed to any owner.
 *
 * MAINTAINER RULING (2026-08-02): "END kills the tracer, regardless of
 * simpoints, just like a program ending in user mode would do."  So this is
 * not a condition to note and walk past.  A detected correct-path END
 * FINALISES AND TERMINATES: it never advances a simpoint iterator, never
 * waits for a budget, and never leaves the window open.
 *
 * The case it exists for is the narrow-ASID (MIPS) pin, whose owner identity
 * is a set of LEARNED PHYSICAL CODE PAGES seeded from the START marker's own
 * page — MIPS exposes no readable page-table root, so the wide-register root
 * identity is unavailable (see marker_anchor / OwnedProc).  An END executed
 * on a page the process mmap'd after its START is a page no owner's map
 * contains, so ownership cannot name the ender.  What ownership CANNOT do is
 * make the workload still be running: the END executed, at user privilege,
 * on the correct path, out of the traced binary's own bytes.  Closing here
 * is the only outcome that keeps the trace ending where its workload does.
 *
 * Counted separately (marker_end_forced_close) precisely so that "ownership
 * could not name the ender" stays visible as its own defect rather than
 * being absorbed by the close.  Caller holds exec_lock; does not return when
 * a segment is live.
 */
static void marker_end_no_close_warn(unsigned int cpu_index, uint64_t pc,
                                     const char *cause);

static void marker_end_force_close(unsigned int cpu_index, uint64_t pc,
                                   const char *cause)
{
    if (!g_trace_segments.is_active() || g_trace_segments.is_shutting_down()) {
        g_rec_mutex_unlock(&exec_lock);
        return;
    }
    g_stats.marker_end_no_close++;
    g_stats.marker_end_forced_close++;
    marker_end_no_close_warn(cpu_index, pc, cause);
    fprintf(stderr,
            "champsim_tracer: the END marker owns the stop — closing the "
            "capture here.\n  An END that closed nothing would run the "
            "capture past the end of its workload,\n  which is a trace that "
            "cannot be used.  Ownership could not name the ender;\n  the "
            "workload ended all the same.\n");
    fflush(stderr);
    marker_close_and_exit(/* last_window= */ true, cpu_index);
}

static void vcpu_marker_cb(unsigned int cpu_index, void *udata)
{
    /* Wrong-path fence, three independent gates: the QEMU-side per-vCPU
     * spec-mode flag is the ground truth for *this execution* (a
     * speculative invocation observes it regardless of which thread's
     * TLS the callback happens to read), the per-thread session flag
     * covers the walker's bracketing on the owning thread, and the
     * per-vCPU session bracket (g_wp_session_vcpu) covers the spec-mode
     * flag's teardown windows (fault-skip end->restore->begin, longjmp
     * cleanup) keyed by the one identity a speculative invocation
     * cannot misreport — the executing vCPU.  Marker detection is a
     * correct-path fact — speculation routinely runs the marker bytes
     * (the wrong path of a spin-wait branch falls straight into the END
     * sequence), so a leak past this fence opens/closes windows from
     * wrong-path execution (observed pre-fence: a 2 M-insn SMP window
     * closed "END" after 385 k user insns, mid-loop, end-marker
     * template exec_cp=0 / exec_wp=98722).  A drop only the third gate
     * catches is counted separately (must be 0): it would be a
     * speculative invocation past BOTH original flags — the leak shape
     * the pre-fence close implied but could not name. */
    {
        bool f_spec = qemu_plugin_in_spec_mode();
        bool f_wp   = g_wp_in_progress;
        bool f_sess = wp_session_active(cpu_index);
        if (fence_diag()) {
            g_fdiag_start_total++;
            if (f_spec || f_wp || f_sess) {
                g_fdiag_start_fenced++;
            }
        }
        if (f_spec || f_wp || f_sess) {
            tls_mkdiag_start_wp_gated++;
            g_stats.marker_wp_fenced_start++;
            if (f_sess && !f_spec && !f_wp) {
                g_stats.marker_fence_session_only++;
            }
            return;
        }
    }
    uint64_t pc;
    if (!marker_claim(udata, MARKER_WHICH_START, &pc)) {
        return;
    }
    g_fdiag_start_runs.fetch_add(1, std::memory_order_relaxed);
    /* The marker is one of the target's own instructions, so the current
     * ASID is the target's page-table root. */
    uint64_t asid = qemu_plugin_get_addr_space_id();
    /* The ownership key and the strand label: QEMU's opaque ids for this
     * vCPU's address space and thread.  The marker is one of the target's
     * own instructions, so both are the target's. */
    uint64_t pid = live_process_id();
    uint64_t tid = live_thread_id();

    /*
     * Marker window open, every target.  Each process that runs the START
     * marker OPENS ITS WINDOW — its ADDRESS SPACE joins the owned set — and
     * is traced concurrently with the others; the first open starts the
     * segment, later opens just widen the set.  Ownership keys on the
     * address space, so EVERY THREAD INSIDE AN OWNED SPACE IS TRACED and
     * nothing here depends on what code a process happens to run.  Excludes
     * the simpoint positioning path (single program by design), which keeps
     * the legacy one-shot below.
     */
    if (g_window_mode == PluginConfig::WIN_MARKER) {
        g_rec_mutex_lock(&exec_lock);
        if (owned_contains_locked(pid)) {
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
        if (!pid && g_system_mode) {
            /* No architectural name for this address space (see
             * marker_refuse_no_root).  Refuse to OPEN — never retire.
             * System mode only: qemu-user reports 0 because a QEMU process
             * IS the one address space, which is an answer, not an
             * absence. */
            marker_refuse_no_root();
        }
        bool first_open = g_owned.empty();
        /* The window's STABLE WIRE NAME, from the marker's own code page.
         * Separate from the ownership key by design — see the legacy path
         * below for why the wire cannot be named by the architectural
         * address-space value on a narrow-ASID target. */
        uint64_t root_phys, sig, vpage;
        marker_anchor(pc, asid, &root_phys, &sig, &vpage);
        g_owned.insert(pid);
        g_owned_last_sched[pid] = deadlatch_now_ms();
        g_owned_last_sched_insns[pid] = deadlatch_now_insns();
        OwnedSpace &os = g_owned_info[pid];
        /* The wire's stable name for this window IS the page-table root
         * (QEMU reports it on every supported target), so the anchor and
         * the ownership key agree by construction. */
        os.root_phys = asid;
        os.sig = sig;
        os.raw_asid = asid;
        os.raw_asid_last = qemu_plugin_get_narrow_asid();
        /* Proof-of-life anchor for the dead latch: the marker's own code
         * page, virtual and physical (see the OwnedSpace field comment). */
        os.marker_vpage = vpage;
        os.marker_pphys = root_phys;
        pin_note_thread_naming(asid, tid);
        if (first_open) {
            /* First window: pin the representative, seed its identity
             * signature from the marker's own code page, and open the
             * segment exactly as the single-process path did. */
            g_pinned_asid.store(asid, std::memory_order_relaxed);
            g_pinned_pid.store(pid, std::memory_order_relaxed);
            asid_sweep_reset();
            g_pin_repr_sig.store(sig, std::memory_order_relaxed);
            marker_open_trace_window(cpu_index, asid);
            /* Assign this window's compact asid index (index 0) with its own
             * marker-page signature.  Runs AFTER start_trace_segment (which
             * resets the per-segment identity map) so the pre-registration
             * survives. */
            asid_root_to_index(os.root_phys, sig);
        } else {
            /* Additional window while the segment is already open: no new
             * segment.  Register this window's identity with ITS OWN
             * marker-page signature (a per-process sig, not the
             * representative's), and recompute this vCPU's gates so its TBs
             * begin dispatching the heavy callback.  Other vCPUs running
             * this space pick it up at their next address-space write. */
            if (sig) {
                asid_set_user_sig(asid, sig);
            }
            asid_root_to_index(os.root_phys, asid_first_sight_sig(asid));
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
    asid_sweep_reset();
    /* Snapshot this pin's ASID identity (Phase 2): the root physical
     * address is @asid itself (cached above); the representative content
     * signature is seeded from the marker's own code page.  @pc is this
     * callback's own instruction address (from its udata), NOT
     * qemu_plugin_get_pc(): the env PC is only synced at TB
     * boundaries/exceptions, so a mid-TB read is stale and would hash a
     * bogus page.  exec_lock guards the shared scratch buffer / page map
     * against concurrent step-glue probes on other vCPUs. */
    g_rec_mutex_lock(&exec_lock);
    {
        /* The window's STABLE WIRE NAME (marker_anchor) and its OWNERSHIP
         * KEY (@pid) are separate things, deliberately: the wire names an
         * address space by a physical anchor plus a content signature so a
         * narrow architectural ASID value cannot churn the wire's asid
         * index, while ownership compares QEMU's opaque process id.  @pc is
         * this callback's own instruction address (from its udata), NOT
         * qemu_plugin_get_pc(): the env PC is only synced at TB
         * boundaries/exceptions, so a mid-TB read would hash a bogus page.
         * User mode / no real address space anchors at (0,0), keeping those
         * traces byte-identical. */
        uint64_t root_phys, sig, vpage;
        marker_anchor(pc, asid, &root_phys, &sig, &vpage);
        if (!pid && g_system_mode) {
            marker_refuse_no_root();
        }
        g_pin_repr_sig.store(sig, std::memory_order_relaxed);
        g_pinned_pid.store(pid, std::memory_order_relaxed);
        g_owned.insert(pid);
        g_owned_last_sched[pid] = deadlatch_now_ms();
        g_owned_last_sched_insns[pid] = deadlatch_now_insns();
        OwnedSpace &os = g_owned_info[pid];
        /* The wire's stable name for this window IS the page-table root
         * (QEMU reports it on every supported target), so the anchor and
         * the ownership key agree by construction. */
        os.root_phys = asid;
        os.sig = sig;
        os.raw_asid = asid;
        os.raw_asid_last = qemu_plugin_get_narrow_asid();
        /* Proof-of-life anchor for the dead latch: the marker's own code
         * page, virtual and physical (see the OwnedSpace field comment). */
        os.marker_vpage = vpage;
        os.marker_pphys = root_phys;
        pin_note_thread_naming(asid, tid);
    }
    g_rec_mutex_unlock(&exec_lock);

    if (pinned_simpoint_mode()) {
        /* Pin only: zero the user clock at the target's first instruction
         * and start positioning toward the simpoint's effective start.
         * The pin is the schedule's ORIGIN, so the pin-absolute clock
         * starts here too — base 0, i.e. the first epoch IS the absolute
         * clock. */
        uint64_t lo = qemu_plugin_u64_get(g_scoreboard.insn_count, cpu_index);
        g_user_icount_pin_base = 0;
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
    marker_open_trace_window(cpu_index, asid);
    g_rec_mutex_unlock(&exec_lock);
}

/*
 * An END marker executed on the correct path and closed no window — either
 * because the fence suppressed its words, or because the run completed in an
 * address space this trace does not own.  Loud ONCE, at the moment it
 * happens, not only as a counter at exit.
 */
static void marker_end_no_close_warn(unsigned int cpu_index, uint64_t pc,
                                     const char *cause)
{
    static std::atomic<bool> said{false};
    bool expected = false;
    if (!said.compare_exchange_strong(expected, true,
                                      std::memory_order_relaxed)) {
        return;
    }
    fprintf(stderr,
            "champsim_tracer: *** END MARKER CLOSED NO WINDOW ***\n"
            "  cpu=%u pc=0x%" PRIx64 " asid=0x%" PRIx64
            " user_insns=%" PRIu64 " cause=%s\n"
            "  See 'marker END in an unowned address space' in the report.\n",
            cpu_index, pc, qemu_plugin_get_addr_space_id(), g_user_icount,
            cause);
    fflush(stderr);
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
    /* Wrong-path fence, three gates — see vcpu_marker_cb. */
    {
        bool f_spec = qemu_plugin_in_spec_mode();
        bool f_wp   = g_wp_in_progress;
        bool f_sess = wp_session_active(cpu_index);
        /* Fence-lane instrumentation: every invocation is censused before
         * the fence decides, so a suppressed CORRECT-PATH end marker is
         * visible as a drop at user privilege in the pinned address space
         * (see fence_note_end).  Off unless CST_FENCE_DIAG is set. */
        bool f_forced = fence_force_end() &&
                        g_trace_segments.is_active_atomic();
        if (f_spec || f_wp || f_sess || f_forced) {
            if (fence_diag()) {
                uint64_t fpc;
                uint8_t fsz;
                bool frc;
                marker_udata_unpack(udata, &fpc, &fsz, &frc);
                fence_note_end(fpc, qemu_plugin_get_addr_space_id(),
                               qemu_plugin_get_priv_level(),
                               (uint8_t)((f_spec ? 1 : 0) | (f_wp ? 2 : 0) |
                                         (f_sess ? 4 : 0) | (f_forced ? 8 : 0)),
                               /* fenced= */ true, 0);
            }
            /*
             * INVARIANT 1's TEST POINT, and why it is HERE and not below.
             *
             * The claim "marker END with no close" makes is about an END
             * marker that executed on the CORRECT PATH.  The owned-set test
             * further down can only speak about a COMPLETED run — and a word
             * the fence drops never reaches the run machine, so no run
             * completes, so that test is structurally blind to the very case
             * this counter exists to name.  Measured, before this moved: with
             * CST_FENCE_FORCE_END a correct-path END was suppressed 54 times,
             * the window never closed, and the counter still read 0.  A
             * tripwire that cannot fire converts a violated invariant into a
             * clean-looking run.
             *
             * "On the correct path" is decided by the two gates a speculative
             * execution cannot be missing: QEMU's own per-vCPU spec-mode flag,
             * and the walker's per-THREAD in-progress flag — the walker is
             * synchronous, so every block it runs fires its callbacks on this
             * host thread with g_wp_in_progress set.  What remains — the
             * per-vCPU session bracket, and the forced control — can be set on
             * a correct-path step only by a LEAK, which is the defect.  So
             * this costs nothing on a healthy run (the 37.9 M speculative END
             * invocations measured by the fence lane all carry f_spec) and
             * cannot fire without the defect being present.
             */
            if (!f_spec && !f_wp && qemu_plugin_get_priv_level() == 0 &&
                g_trace_segments.is_active_atomic()) {
                uint64_t spc;
                uint8_t ssz;
                bool src;
                marker_udata_unpack(udata, &spc, &ssz, &src);
                g_stats.marker_end_suppressed++;
                marker_end_no_close_warn(cpu_index, spc,
                        f_forced ? "suppressed by the fence, forced "
                                   "(CST_FENCE_FORCE_END)"
                                 : "suppressed by the fence — a leaked "
                                   "wrong-path session bracket");
            }
            if (f_spec || f_wp || f_sess) {
                tls_mkdiag_end_wp_gated++;
                g_stats.marker_wp_fenced_end++;
                if (f_sess && !f_spec && !f_wp) {
                    g_stats.marker_fence_session_only++;
                }
            }
            return;
        }
    }
    uint64_t pc;
    if (!marker_claim(udata, MARKER_WHICH_END, &pc)) {
        return;
    }
    if (marker_diag()) {
        fprintf(stderr, "[mkdiag] end-cb CP cpu=%u pc=0x%" PRIx64
                " priv=%d asid=0x%" PRIx64 " pinned=0x%" PRIx64
                " user=%" PRIu64 " wp_gated=%" PRIu64 " susp_u=%" PRIu64
                "\n",
                cpu_index, pc, qemu_plugin_get_priv_level(),
                qemu_plugin_get_addr_space_id(),
                g_pinned_asid.load(std::memory_order_relaxed),
                g_user_icount, tls_mkdiag_end_wp_gated,
                tls_mkdiag_susp_user);
    }
    if (fence_diag()) {
        fence_note_end(pc, qemu_plugin_get_addr_space_id(),
                       qemu_plugin_get_priv_level(), 0, /* fenced= */ false,
                       (uint8_t)g_marker_seq.n_insns);
    }
    g_fdiag_end_runs.fetch_add(1, std::memory_order_relaxed);
    fence_flush_end_ring();
    uint64_t asid = qemu_plugin_get_addr_space_id();
    /* The ownership key: QEMU's opaque id for the address space this
     * marker executed in (the marker is one of the target's own
     * instructions, so it is the target's). */
    uint64_t pid = live_process_id();

    /*
     * Marker window close, every target.  The END marker CLOSES the
     * emitting process's window: its ADDRESS SPACE leaves the owned set.
     * The segment closes only when the LAST window closes; while other
     * processes are still tracing, the ending one is dropped and the
     * segment keeps running.  Symmetric with the START handler; the
     * simpoint positioning path keeps the single-process exit below.
     */
    if (g_window_mode == PluginConfig::WIN_MARKER) {
        g_rec_mutex_lock(&exec_lock);
        if (!owned_contains_locked(pid)) {
            /* END from a process that never opened a window (or already
             * closed it).  A completed correct-path END that closes nothing
             * is how a pin that drifted off its process looks — and it is
             * still an END, so it stops the capture (see
             * marker_end_force_close; does not return under a live
             * segment). */
            marker_end_force_close(cpu_index, pc,
                    "the run completed in an address space this trace "
                    "does not own");
            return;
        }
        /* From here the close is unconditional: the run completed on the
         * correct path in an address space this trace owns.  Anything that
         * returned before this point without closing is counted at the
         * call site (see marker_end_no_close). */
        /*
         * THE LAST WINDOW KEEPS ITS OWNERSHIP UNTIL THE CLOSE TAKES.
         *
         * Dropping the ending space from the owned set is how a
         * multi-process capture stops tracing one participant while the
         * others run on — but when this END is the last window, the close
         * it raises now runs at the end of the marker's own block
         * (marker_close_and_exit), and the tracer has to still own the
         * address space to get there: an unowned dispatch is a foreign
         * span, which mutes capture, sets the deferred prev aside and
         * would leave the very block this close exists to finish
         * unemitted.  So the last window's bookkeeping is left standing
         * and the segment close tears it down.
         */
        if (g_owned.size() > 1) {
            uint64_t raw = asid;
            auto oit = g_owned_info.find(pid);
            if (oit != g_owned_info.end()) {
                raw = oit->second.raw_asid;
                g_owned_info.erase(oit);
            }
            g_owned.erase(pid);
            g_owned_last_sched.erase(pid);
            g_owned_last_sched_insns.erase(pid);
            /* Other windows remain open — do NOT close the segment.  Drop
             * only this space: recompute the emitting vCPU's gates/flag so
             * its TBs stop being owned; other vCPUs that were running it
             * self-correct at their next address-space write.  If this was
             * the representative, repoint so cst_pinned_asid_root and the
             * effective-pin compare stay valid. */
            if (g_pinned_pid.load(std::memory_order_relaxed) == pid) {
                uint64_t heir = *g_owned.begin();
                g_pinned_pid.store(heir, std::memory_order_relaxed);
                auto hit = g_owned_info.find(heir);
                if (hit != g_owned_info.end()) {
                    g_pinned_asid.store(hit->second.raw_asid,
                                        std::memory_order_relaxed);
                }
            }
            /* Drop the closed process's asid-keyed dedup-index footprint so
             * it does not accumulate across disparate ASIDs (single shared
             * tracer with asid-keyed caches, not one tracer per ASID).  The
             * process's true-BB templates stay until the segment's templates
             * section is written (see reclaim_asid).  data_lock guards the
             * store against a concurrent translation on another vCPU. */
            g_mutex_lock(&data_lock);
            uint64_t dropped = g_template_store.reclaim_asid(raw);
            g_mutex_unlock(&data_lock);
            if (dropped) {
                fprintf(stderr, "champsim_tracer: dropped %" PRIu64
                        " dedup buckets for closed asid 0x%" PRIx64 "\n",
                        dropped, raw);
            }
            qemu_plugin_u64_set(g_scoreboard.asid_match, cpu_index, 0);
            refresh_ctx_gates(cpu_index);
            fprintf(stderr,
                    "champsim_tracer: end marker — closed window for asid "
                    "0x%" PRIx64 " (%zu still tracing)\n",
                    raw, g_owned.size());
            g_rec_mutex_unlock(&exec_lock);
            return;
        }
        /* The last window: all-windows-closed stop (peer of the
         * icount/budget stop — whichever fires first wins).  Its owned-set
         * entry stands until the close takes; see the note above. */
        marker_close_and_exit(/* last_window= */ true, cpu_index);
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
     * by the step glue before this insn callback fired).  A mismatch is
     * still a correct-path END while a window is open, so it closes — the
     * pinned-simpoint iterator does not outrank a workload that ended
     * (maintainer ruling, see marker_end_force_close). */
    g_rec_mutex_lock(&exec_lock);
    if (!owned_contains_locked(pid)) {
        marker_end_force_close(cpu_index, pc,
                "the run completed under an address space value that is not "
                "this vCPU's effective pin");
        return;
    }
    marker_close_and_exit(/* last_window= */ false, cpu_index);
}

/* Outcome of the pre-commit instruction-memory stability check. */
struct TbPoison {
    bool        poisoned = false;
    uint64_t    pc = 0;
    const char *reason = nullptr;
};

/*
 * Detect non-stable "instruction" memory before committing this TB as a
 * fragment.  Only one signal poisons: Capstone decode failure on any
 * canonical insn (empty mnemonic) — the bytes don't parse as a valid
 * instruction of this ISA, so they cannot be real code.  Poisoning the
 * TB's start_pc makes the WP walker bail before re-entering it, and
 * short-circuits fragment creation on subsequent translations.  Decode
 * failure also fires on perfectly stable .rodata that the R-E LOAD
 * segment happens to cover (static binaries place .text and .rodata in
 * the same R-E LOAD, so start_code/end_code spans both) — that is WP
 * wrong-pathing into data, not self-modifying code.
 *
 * A byte change since the first sighting of this VA is tracked
 * separately (see g_first_insn_word) but does NOT poison by itself:
 * self-modifying code is handled by BB template revisioning (see
 * champsim_tracer_bb_template_cache.{cc,h}), not refusal, so the
 * correct path just refreshes the cached first word to the new bytes,
 * and a wrong-path read that differs is assumed to be another address
 * space's real code (ASID reuse) rather than SMC, so the fragment still
 * forms.  Records the first-sighting word of every new canonical PC.
 * Takes data_lock.
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
    const bool spec = g_wp_in_progress;

    g_mutex_lock(&data_lock);
    uint64_t bytes_hash = tb_bytes_hash(insn_bytes, canonical_n_insns);
    auto poison_it = g_poisoned_pcs.find(pc);
    if (poison_it != g_poisoned_pcs.end() && spec &&
        poison_it->second != bytes_hash) {
        /* Different bytes than when the verdict was made: the VA has been
         * reused by another context since (process exit, exec, page reuse).
         * The old verdict says nothing about THIS content — ignore it HERE
         * and evaluate normally below.
         *
         * Ignore, never erase.  The paragraph above states the rule this
         * function is built on: a spec-mode translation only READS this
         * state.  Erasing was the one place that broke it, and it broke it
         * in the direction that matters — a wrong-path read of a VA whose
         * page is mid-refill or belongs to a reused ASID sees a different
         * hash by construction, so the entry a correct-path sighting placed
         * was dropped by exactly the garbage read the poison exists to
         * refuse.  Nothing is stranded by keeping it: the correct path
         * clears its own stale entries unconditionally in the arm below
         * (per start_pc and per canonical VA), which is the ground-truth
         * rule this cache follows everywhere else. */
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

    /* WIN_MARKER: the predecessor half of a straddling sequence, taken while
     * the page it sits on is still resident (see marker_witness_straddle).
     *
     * Correct-path translations only.  The witness table is persistent and
     * the correct path PREFERS it over its own guest read (the
     * `from_witness || marker_read_guest` below), so a wrong-path entry is
     * not a spare copy of the same answer — it is the answer.  A spec-mode
     * translation reaches this point with a real TB of real guest bytes,
     * but not necessarily the same EXTENT: "freshest translation wins" in
     * marker_straddle_witness_note lets a wrong-path TB carrying fewer head
     * slots overwrite a correct-path witness, after which the prefix
     * reconstruction fails, marker_whole_match yields MARKER_WHICH_NONE and
     * the terminating instruction is never armed.  A missed END is
     * trace-invalidating, so the wrong path does not get a vote here.
     *
     * The gate is on the NOTE, not on the arming: spec translations keep
     * byte-for-byte the instrumentation shape they have today. */
    if (marker_scan_enabled() && g_marker_seq.valid && !g_wp_in_progress) {
        marker_witness_straddle(tb, raw_n_insns);
    }

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
        if (marker_scan_enabled() && g_marker_seq.valid &&
            marker_tail_word_match(raw_bytes, raw_size)) {
            /*
             * Decided here, in the bytes, on ONE instruction.  The cheap
             * filter above is "is this instruction, byte for byte, the
             * TERMINATING instruction of a marker sequence".  When it is,
             * the CST_MARKER_SEQ_LEN-1 instruction slots immediately before
             * it are compared against the rest of the sequence — from this
             * TB's own translated stream when it reaches back that far,
             * otherwise from guest memory.  A whole-sequence match arms
             * exactly one execution callback, and that callback firing IS
             * the marker: no run to advance, nothing to hand off between
             * vCPUs, and nothing a fault, a migration, a page straddle,
             * single-stepping or -icount can interrupt.  START and END are
             * compared whole, immediates included, so the word the two
             * magics share on every fixed-width target cannot confuse them.
             */
            uint8_t prefix[CST_MARKER_PAIR_SEQ_BYTES];
            /*
             * A sequence that STRADDLES A PAGE BOUNDARY needs more than
             * "read the bytes before it", because the bytes before it are
             * another page's and QEMU keys a translation block by the
             * physical pages it covers: a block may legitimately be reused
             * by another address space that maps the SAME tail page behind
             * a DIFFERENT predecessor page, and the slots before the
             * sequence would then be that other program's.  So a straddle
             * is decided by its PHYSICAL PAGE PAIR, never by its tail
             * alone.  Three sources, in order of how strongly they key it:
             *
             *   1. THIS TB covers the whole sequence.  Then QEMU's own key
             *      IS the pair — tb_lookup_cmp compares tb_page_addr0 AND
             *      tb_page_addr1 — so the decision is final here and needs
             *      no execution-time recheck at all.
             *   2. The predecessor page was witnessed at ITS translation
             *      (marker_witness_straddle), which is the only moment a
             *      software-walked target can be relied on to produce those
             *      bytes.  The remaining slots are on the tail's own page,
             *      which this translation is reading out of.
             *   3. A plain guest read reaches back over the boundary.
             *
             * 2 and 3 record the pair and still arm the execution-time
             * recheck, which prefers the running address space's own read
             * and falls back to the pair only when that read cannot be
             * serviced.  CST_MARKER_PAIR_SEQ_BYTES is far below a page, so
             * a straddle is the rare case, and the smallest page any
             * supported target uses is the conservative boundary.
             */
            const uint64_t page = 4096;
            uint64_t seq_base = raw_pc - g_marker_seq.prefix_bytes;
            bool straddles = (seq_base / page) != (raw_pc / page);
            bool have = false;
            bool pair_keyed = false;      /* source 1: QEMU's own TB key */
            bool from_witness = false;
            uint64_t witness_pa = 0;
            if (!straddles) {
                have = marker_gather_prefix(tb, i, raw_pc, prefix);
                pair_keyed = have;        /* one page: the tail page IS the key */
            } else {
                have = marker_gather_prefix_tb(tb, i, raw_pc, prefix);
                pair_keyed = have;
                if (!have) {
                    from_witness = marker_straddle_prefix_from_witness(
                        raw_pc, prefix, &witness_pa);
                    have = from_witness ||
                           marker_read_guest(seq_base, prefix,
                                             g_marker_seq.prefix_bytes);
                }
            }
            MarkerWhich which = have
                ? marker_whole_match(raw_bytes, raw_size, prefix)
                : MARKER_WHICH_NONE;
            if (straddles && which != MARKER_WHICH_NONE) {
                /* Record the pair whatever the source: even source 1's
                 * entry is worth having, because a later TB that starts on
                 * the tail's page will need it.  The predecessor's physical
                 * address comes from the WITNESS when the witness is what
                 * decided this — re-resolving it here is the very read that
                 * is not serviceable on the runs this exists for. */
                uint64_t pp = 0, tp = 0;
                bool have_pp = from_witness
                    ? (witness_pa != 0 && (pp = witness_pa, true))
                    : marker_page_paddr(seq_base, &pp);
                /* Correct-path translations only, for the same reason the
                 * witness note is gated: the pair table is persistent, and
                 * a second DIFFERENT predecessor page behind one tail page
                 * latches `conflicting` permanently, after which
                 * marker_straddle_pair_lookup refuses that tail forever.  A
                 * wrong-path translation reaching a straddling tail through
                 * a reused or mid-refill page is precisely how a second
                 * predecessor appears, so letting it vote can make a
                 * straddling END permanently undecidable. */
                if (have_pp && marker_page_paddr(raw_pc, &tp) &&
                    !g_wp_in_progress) {
                    marker_straddle_pair_note(tp, pp & ~(page - 1), which);
                } else {
                    pair_keyed = false;     /* unrecorded: keep the recheck */
                }
            }
            if (straddles && marker_straddle_diag()) {
                fprintf(stderr, "[straddle] tail=0x%" PRIx64 " i=%zu have=%d "
                        "pair_keyed=%d which=%d\n", raw_pc, i, (int)have,
                        (int)pair_keyed, (int)which);
            }
            if (straddles && !pair_keyed) {
                /* Decided, but by a source QEMU's TB key does not carry.
                 * Arm the recheck so the running address space answers for
                 * itself whenever it can, and the pair only when it cannot. */
                have = false;
                which = MARKER_WHICH_NONE;
            }
            if (have) {
                if (which == MARKER_WHICH_START) {
                    qemu_plugin_register_vcpu_insn_exec_cb(
                        insn, vcpu_marker_cb, QEMU_PLUGIN_CB_NO_REGS,
                        marker_udata_pack(raw_pc, raw_size,
                                          /* recheck= */ false));
                } else if (which == MARKER_WHICH_END) {
                    qemu_plugin_register_vcpu_insn_exec_cb(
                        insn, vcpu_marker_end_cb, QEMU_PLUGIN_CB_NO_REGS,
                        marker_udata_pack(raw_pc, raw_size,
                                          /* recheck= */ false));
                }
            } else {
                /* Undecided here: either the sequence straddles a page
                 * (above), or the slots before this instruction are not
                 * readable at THIS moment because the page holding them is
                 * not resident while we translate.  Either way, arm both
                 * and re-read when the instruction executes: by then this
                 * same CPU has fetched and retired those slots one or two
                 * instructions ago, in the address space whose answer
                 * counts.  See marker_verify_at_exec. */
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, vcpu_marker_cb, QEMU_PLUGIN_CB_NO_REGS,
                    marker_udata_pack(raw_pc, raw_size, /* recheck= */ true));
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, vcpu_marker_end_cb, QEMU_PLUGIN_CB_NO_REGS,
                    marker_udata_pack(raw_pc, raw_size, /* recheck= */ true));
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

    /* Deferred end-of-run for the RESET close (see vcpu_vm_reset_cb): the
     * close ran at the reset request, possibly under the BQL; the exit is
     * taken here, on a vCPU thread outside any device write — the same
     * context the dead-latch and ceiling closes exit from.  The rebooted
     * machine retranslates everything, so this fires within milliseconds
     * of the new world starting. */
    if (g_reset_exit_pending.load(std::memory_order_acquire)) {
        exit(0);
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
     * correct path executes them first (see TmplLife).  The label lasts
     * exactly as long as this translation (TemplateStore::TranslationScope):
     * templates minted at execution time belong to a cache the reclaim never
     * touches, and must not answer to a translation's flag. */
    TemplateStore::TranslationScope spec_class_scope(g_wp_in_progress);

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

    /* Pre-commit instruction-memory stability check: bail without creating
     * fragments/callbacks for a TB whose bytes don't parse as valid code
     * (see detect_tb_poison). */
    TbPoison poison = detect_tb_poison(pc, insn_pcs, insn_bytes, insn_info,
                                       canonical_n_insns);
    if (poison.poisoned) {
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
    /*
     * Architectural instruction clock: one ADD(+1) per instruction (see
     * VCPUScoreBoard::insn_started).  The TB-entry add above credits a TB
     * that is abandoned part-way for instructions that never ran; this one
     * cannot, because it is the instruction's own op.
     *
     * REGISTERED HERE, after the per-insn marker / reg-snap / synth-EA
     * callbacks armed earlier in this function, ON PURPOSE.  Plugin ops on
     * one instruction fire in registration order, so being last makes the
     * slot read "instructions COMPLETED" from inside any pre-instruction
     * callback — which is what lets the segment close truncate the
     * in-flight block to the instructions that actually executed.  Move it
     * earlier and every such reader silently gains one phantom
     * instruction.
     */
    for (size_t i = 0; i < raw_n_insns; i++) {
        qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
            qemu_plugin_tb_get_insn(tb, i), QEMU_PLUGIN_INLINE_ADD_U64,
            g_scoreboard.insn_started, 1);
    }
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
        /* REP window-clock compensation (see vcpu_tb_ff_rep): only on TBs
         * that BEGIN with a fan-out instruction — the TB every re-entering
         * execution of that instruction is followed by — so the coarse
         * countdown, like the traced window clock, counts REPs the way the
         * bbv run behind the SimPoint offsets did.  Also ahead of the
         * crossing detector, so a withheld tick nets out before the
         * crossing is evaluated. */
        if (head_fragment && head_fragment->n_insns > 0 &&
            head_fragment->insn_fields[0].rep_memops_per_iter > 0) {
            qemu_plugin_register_vcpu_tb_exec_cb(
                tb, vcpu_tb_ff_rep, QEMU_PLUGIN_CB_NO_REGS,
                (void *)(uintptr_t)head_fragment->insn_pcs[0]);
        }
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
    /* Heavy callback: chain assembler, WP simulator, body-entry
     * emission.  Gated via cond_cb on trace_this_ctx (is_active folded
     * with pinned-context ownership) so it is NOT dispatched at all
     * inter-segment OR for a foreign / unowned context — the JIT emits a
     * brcond and skips the call, sparing the vclock pause and the drop
     * decision the dropped foreign TB used to pay.  For user mode,
     * unpinned system, and every system pin trace_this_ctx mirrors
     * is_active exactly, so the cb fires per TB just as it did before. */
    qemu_plugin_register_vcpu_tb_exec_cond_cb(
        tb, vcpu_tb_exec, QEMU_PLUGIN_CB_RW_REGS,
        QEMU_PLUGIN_COND_GE, g_scoreboard.trace_this_ctx, 1,
        (void *)head_fragment);

    /* Event-queue absorber: the per-TB drain point (see vcpu_evq_absorb).
     * UNCONDITIONAL — every translated TB on every target carries it, with
     * no ownership, privilege or segment condition — because the windows it
     * exists for are precisely the ones where every such condition is
     * false.  Registering it under an ownership or target condition would
     * cover one target and one of the five windows; that was round 3's
     * mistake and it is not repeated here.
     *
     * REGISTERED LAST.  Per-TB callbacks run in registration order and each
     * cond_cb re-loads its slot, so on any TB where the heavy vcpu_tb_exec
     * above dispatched, its drain has already stored 0 into evq_pending and
     * this brcond is false.  The light path runs on exactly the TBs where
     * nothing else drained.  Getting the order wrong silently converts every
     * owned dispatch into the absorb path and changes the traced wire. */
    qemu_plugin_register_vcpu_tb_exec_cond_cb(
        tb, vcpu_evq_absorb, QEMU_PLUGIN_CB_RW_REGS,
        QEMU_PLUGIN_COND_GE, g_scoreboard.evq_pending, 1,
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
        if (g_wp_in_progress &&
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
    /* The straddle tables ARE translation-derived: every entry is a fact
     * about code QEMU is about to re-translate, and every one of them is
     * re-established by that re-translation before the sequence can run
     * again.  Dropping them here bounds how stale a recorded physical page
     * pair can be — the one thing a physical key cannot notice on its own is
     * the guest rewriting the predecessor page underneath it. */
    marker_straddle_reset();
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

/* ================== Machine shutdown: close, don't abandon ==================
 *
 * THE TERMINATION PATH THAT NEEDS NO GUEST COOPERATION.
 *
 * A system-mode window is normally ended by the guest: the workload's END
 * marker executes, or the user-instruction budget is met.  Both require the
 * traced process to RUN.  When it does not — killed after its window opened,
 * blocked in a syscall it never leaves, never scheduled — neither can
 * happen, and the run has nothing to end it.  The operator's answer to that
 * is a script that runs the workload and then shuts the guest down:
 *
 *     /workload ; poweroff
 *
 * and this callback is what makes that answer WORK.  It fires from the
 * shutdown request itself (qemu_plugin_register_vm_shutdown_cb), before the
 * main loop leaves and before qemu_cleanup() stops the vCPUs, on a vCPU
 * thread — so an open segment is closed exactly the way the END marker
 * closes one, with the machine still assembled and its state readable.
 * Whatever the workload did or failed to do, the trace is finalised.
 *
 * It also removes a real crash.  Before it existed, a window still open at
 * guest poweroff was closed from plugin_exit, which QEMU runs from atexit(3)
 * on a thread that is not a vCPU thread: the emit path then asked for the
 * privilege level / address space / paging state, every one of which
 * resolves through current_cpu, and QEMU aborted
 * (plugins/api.c: "plugin_cpu_state: assertion failed: (current_cpu)").
 * Closing here means plugin_exit finds nothing left to close.
 */
static void vcpu_vm_shutdown_cb(qemu_plugin_id_t id, int vcpu_index,
                                bool in_guest_insn)
{
    if (!g_system_mode) {
        return;                      /* *-user exits on a guest thread */
    }
    g_rec_mutex_lock(&exec_lock);
    if (!g_trace_segments.is_active() ||
        g_trace_segments.is_shutting_down()) {
        g_rec_mutex_unlock(&exec_lock);
        return;                      /* nothing open — the normal case */
    }
    g_stats.vm_shutdown_closes++;
    uint64_t covered = marker_user_clock() ? g_user_icount : g_host_icount;
    fprintf(stderr,
        "\nchampsim_tracer: *** MACHINE SHUTDOWN WITH THE WINDOW OPEN ***\n"
        "  the guest is powering off while a capture is still running, so "
        "no END\n  marker and no budget can ever close it.  Closing the "
        "segment here — the\n  trace is finalised and TRUNCATED at %" PRIu64
        " %sinstructions.\n"
        "  (a workload that ends on its own closes at its END marker "
        "instead; this\n   is the shutdown backstop, and it is always "
        "armed.)\n\n",
        covered, marker_user_clock() ? "user " : "");
    fflush(stderr);
    g_seg_end_marker_close = false;
    g_seg_close_reason = "SHUTDOWN";
    if (vcpu_index >= 0 && (unsigned)vcpu_index < CST_PIN_MAX_VCPUS) {
        /*
         * prev_executed = FALSE, and this is the one thing about this
         * close that is not like the others.  The ceiling and the
         * budget close from the TOP of a correct-path step, where the
         * pending seal slot holds the PREVIOUS block — fully executed,
         * so it is emitted.  This close can arrive MID-INSTRUCTION: the
         * pending slot then holds a block that is still running, and
         * emitting it writes an execution whose memory operations were
         * only partly observed.  Caught by cst_audit's memop-bimodality
         * oracle — "1/841 CP executions realised zero memops" — on a
         * first version of this that used true.  So an in-flight block
         * is dropped and only the completed chain is flushed.
         */
        /*
         * DROPPED WHOLE, THOUGH, IS TOO MUCH.  Everything AHEAD of the
         * instruction performing the device write retired, memory
         * operations and all; only that instruction is incomplete.
         * prev_in_flight says so, and the drain walks the slot's retired
         * prefix and subtracts exactly the one begun-but-unretired
         * instruction (insn_started is added at the TOP of an instruction,
         * so it is already counted).
         *
         * A guest poweroff used to be the mid-instruction case — the
         * dispatch ran inside the device write that performs it.  QEMU
         * now queues that route to the writing vCPU's next TB boundary
         * (the write's BQL must not be held into the plugin's lock: the
         * AB/BA against a peer's wrong-path excursion, measured on
         * riscv64 -smp 4 poweroff), so it arrives with the vCPU named,
         * in_guest_insn FALSE, and the block that performed the write
         * fully retired.  The trim keys off the flag, not the route, so
         * it fires exactly when something is in flight.
         */
        finish_trace_segment(/* prev_executed= */ false,
                             (unsigned int)vcpu_index,
                             /* prev_in_flight= */ in_guest_insn);
    } else {
        /* No vCPU could be named.  Flush every builder that ever ran;
         * reachable only if the machine goes down without having run. */
        finish_trace_segment();
    }
    g_trace_segments.set_shutting_down();
    g_rec_mutex_unlock(&exec_lock);
}

/* ==================== Machine reset: a close route too ====================
 *
 * A guest RESET is the teardown the shutdown route never sees: the machine
 * is torn down and booted again inside the same QEMU process, so neither
 * the shutdown callback nor atexit fires, and a capture left open would
 * outlive the machine that ran its process.  The reboot is a fresh world —
 * new kernel, every address-space name recycled — and the recycled names
 * mean its execution would be recorded INTO the stale window under the
 * dead pin (per docs/format.rst and the marker contract, trace-invalidating:
 * the window must contain exactly the marker process).  Measured before
 * this route existed: a marker window survived a guest `reboot -f` and
 * 2.04e9 post-marker instructions, ended only by the any-context ceiling.
 *
 * So a reset with a window open is a named close route, RESET: the segment
 * is closed at the reset REQUEST, while the machine being recorded still
 * exists, with the shutdown route's discipline (the request arrives inside
 * the device write / triple fault that performs it, so the in-flight
 * instruction is trimmed the same way).  Delivery paths all funnel through
 * qemu_system_reset_request — x86 port 92h / PIIX RCR / i8042 pulse /
 * triple fault, Arm PSCI SYSTEM_RESET, the RISC-V sifive_test finisher,
 * the Malta SOFTRES register, the watchdog's reset action, monitor/QMP
 * system_reset — and a reset that -no-reboot converts into a shutdown
 * takes the shutdown route instead, never both.
 *
 * After the close the run ENDS (the END marker's own discipline: a capture
 * whose process is gone has nothing left to record, and the rebooted world
 * must not be).  The exit is DEFERRED to the next translation rather than
 * taken here: this callback can run inside a device write with the BQL
 * held, and ending the process under the BQL re-creates the lock-order
 * exposure the marshalled shutdown dispatch had to drop the BQL to avoid.
 * The reboot retranslates everything, so the deferral is milliseconds.
 * A reset with NO window open closes nothing and the run continues — a
 * boot-chain reset before the workload runs is legitimate, and a marker
 * in the booted world may still open its window.
 */
static void vcpu_vm_reset_cb(qemu_plugin_id_t id, int vcpu_index,
                             bool in_guest_insn)
{
    if (!g_system_mode) {
        return;
    }
    g_rec_mutex_lock(&exec_lock);
    if (!g_trace_segments.is_active() ||
        g_trace_segments.is_shutting_down()) {
        g_rec_mutex_unlock(&exec_lock);
        return;                      /* nothing open — reboot untraced */
    }
    g_stats.vm_reset_closes++;
    uint64_t covered = marker_user_clock() ? g_user_icount : g_host_icount;
    fprintf(stderr,
        "\nchampsim_tracer: *** MACHINE RESET WITH THE WINDOW OPEN ***\n"
        "  the guest is resetting while a capture is still running.  The "
        "machine that\n  ran the traced process is being torn down; the "
        "world that boots next is a\n  different one whose recycled "
        "address-space names must not land in this\n  window.  Closing the "
        "segment here — the trace is finalised and TRUNCATED at\n  %" PRIu64
        " %sinstructions — and the run ends at the next translation.\n\n",
        covered, marker_user_clock() ? "user " : "");
    fflush(stderr);
    g_seg_end_marker_close = false;
    g_seg_close_reason = "RESET";
    if (vcpu_index >= 0 && (unsigned)vcpu_index < CST_PIN_MAX_VCPUS) {
        /* Same in-flight discipline as the shutdown close: the request
         * arrives from inside the instruction performing it, so the
         * retired prefix is drained and the begun-but-unretired
         * instruction subtracted (see vcpu_vm_shutdown_cb). */
        finish_trace_segment(/* prev_executed= */ false,
                             (unsigned int)vcpu_index,
                             /* prev_in_flight= */ in_guest_insn);
    } else {
        finish_trace_segment();
    }
    g_trace_segments.set_shutting_down();
    g_reset_exit_pending.store(true, std::memory_order_release);
    g_rec_mutex_unlock(&exec_lock);
}

/* ========================= Exit / statistics ========================= */

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_trace_segments.set_shutting_down();

    /* Totals from the QUEUE SIDE, produced by the event producer upstream
     * of every plugin attribution gate.  Best-effort HERE and nowhere else
     * critical: in system mode this hook runs from atexit(3), after
     * qemu_cleanup() has stopped the vCPUs and torn the machine down, so
     * qemu_get_cpu() may resolve nothing and these read 0.  The number that
     * matters — the queue-length high-water mark — is therefore latched
     * continuously at every non-empty drain (evq_note_drain) and is already
     * correct before this runs; only the push/drain totals depend on the
     * machine still being assembled, and evq_note_drain's own counts stand
     * in for them when it is not. */
    for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; i++) {
        uint64_t ml = 0, np = 0, nd = 0;
        qemu_plugin_cpu_events_stats((unsigned)i, &ml, &np, &nd);
        if (ml > g_stats.evq_qmax_len) {
            g_stats.evq_qmax_len = ml;
        }
        g_stats.evq_q_pushes += np;
        g_stats.evq_q_drains += nd;
    }

    g_rec_mutex_lock(&exec_lock);

    if (g_trace_segments.is_active()) {
        finish_trace_segment();
    }

    if (tiddiag_on() && g_system_mode) {
        /* One-run accounting of what the kernel-privilege thread-pointer
         * sample changed on the wire (see g_vcpu_user_tid). */
        fprintf(stderr, "champsim_tracer: [tiddiag] kernel-strand "
                "re-attribution: %" PRIu64 "/%" PRIu64 " kernel entries and "
                "%" PRIu64 "/%" PRIu64 " user entries carry a thread_id "
                "other than the last user-privilege thread on their vCPU\n",
                g_tiddiag_kern_retagged, g_tiddiag_kern_entries,
                g_tiddiag_user_retagged, g_tiddiag_user_entries);
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
     *                     files, BEFORE self-loop fan-out expansion.
     *
     *   rep_fanout      — total sub-entries emitted by self-loop
     *                     fan-out (x86 REP string ops, AArch64
     *                     FEAT_MOPS bulk copy/set) inside
     *                     emit_body_entry, in-segment only.
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

    /* Guest-realtime summary (#61): factor and the guest instruction rate the
     * cliff model is expressed in.  Always reported, never gating unless
     * CST_RT_GATE armed it. */
    fence_flush_end_ring();
    /*
     * THE INVARIANT REPORT, and why it does not go through `g_stats`.
     *
     * `g_stats` is a THREAD-LOCAL slot registered in a process-wide
     * registry, and plugin_exit runs from inside exit(3) — which calls the
     * calling thread's thread_local destructors BEFORE it runs atexit
     * handlers.  By the time this code executes, that thread's Stats slot
     * has already been folded into the graveyard, erased from the registry
     * and freed: writing a counter here writes freed memory that no
     * snapshot can see, and READING one here reads a dead slot that never
     * accumulated what the vCPU threads counted.  Measured: a run with 87
     * broken marker runs printed 87 in this banner (the dangling write read
     * straight back) and 0 in the statistics table (the aggregate), while
     * `WP session flag on CP step` — accumulated during the run by the vCPU
     * threads — read 0 HERE and its true value in the table.  Either way a
     * tripwire could report a clean run over a violated invariant.
     *
     * So the aggregate is snapshotted once, the process-wide detector
     * counters are folded into that copy, and BOTH the banner and the table
     * are rendered from it.  Nothing at exit touches the thread-local.
     */
    Stats final_stats = stats_snapshot();
    /* The marker is decided in the bytes, so there is no run state to leave
     * behind and nothing to report at exit about a sequence that
     * half-happened.  The one count worth carrying is how often a
     * marker-shaped instruction was ruled out because the slots before it
     * were unreadable — see Stats::marker_prefix_unreadable. */
    final_stats.marker_prefix_unreadable = marker_prefix_unreadable();
    /* ... and, for every one of those, whether the sequence's physical page
     * pair could still answer.  marker_straddle_undecided is the number that
     * must be 0: a straddling sequence with neither source. */
    final_stats.marker_straddle_pair_resolved = marker_straddle_pair_resolved();
    final_stats.marker_straddle_conflicts = marker_straddle_conflicts();
    final_stats.marker_straddle_undecided = marker_straddle_undecided();
    /* The tripwires that SURVIVE byte-decided detection.  Each still names
     * a way a correct-path marker can be lost, and none of them depends on
     * a run: a leaked wrong-path session bracket silently drops every
     * marker callback on its vCPU, and an END suppressed by the fence on a
     * demonstrably non-speculative execution is a window that should have
     * closed and did not. */
    if (final_stats.marker_end_suppressed ||
        final_stats.wp_session_on_cp ||
        final_stats.marker_fence_session_only) {
        fprintf(stderr,
            "\nchampsim_tracer: *** MARKER INVARIANT TRIPWIRE ***\n"
            "  marker END suppressed by fence %" PRIu64 " (must be 0)\n"
            "  WP session flag on CP step   %" PRIu64 " (must be 0)\n"
            "  marker fence session-only    %" PRIu64 " (must be 0)\n"
            "  A correct-path marker may have been dropped: the window that "
            "should have\n  closed at it did not.\n\n",
            final_stats.marker_end_suppressed,
            final_stats.wp_session_on_cp,
            final_stats.marker_fence_session_only);
        fflush(stderr);
    }
    if (getenv("CST_STATSDBG")) {
        /* Positive control for the paragraph above: the thread-local read
         * and the aggregate, side by side, at the same instant. */
        fprintf(stderr, "[statsdbg] tls.end_supp=%" PRIu64
                " agg.end_supp=%" PRIu64
                " tls.wp_sess=%" PRIu64 " agg.wp_sess=%" PRIu64 "\n",
                g_stats.marker_end_suppressed, final_stats.marker_end_suppressed,
                g_stats.wp_session_on_cp, final_stats.wp_session_on_cp);
        fflush(stderr);
    }
    if (fence_diag()) {
        fprintf(stderr, "[fence] FINAL start_runs=%" PRIu64 " end_runs=%" PRIu64
                " start_cb=%" PRIu64 " start_fenced=%" PRIu64
                " end_cb=%" PRIu64 " end_cp=%" PRIu64 " end_fenced=%" PRIu64
                "\n", g_fdiag_start_runs.load(std::memory_order_relaxed),
                g_fdiag_end_runs.load(std::memory_order_relaxed),
                g_fdiag_start_total, g_fdiag_start_fenced,
                g_fdiag_end_total, g_fdiag_end_cp, g_fdiag_end_fenced);
        fflush(stderr);
    }
    g_rt_gate.report(report);

    g_mutex_lock(&data_lock);
    append_stats_summary(report, "Cumulative", final_stats);
    if (g_simpoints.is_active()) {
        g_string_append_printf(report,
            "SimPoints loaded/traced: %zu / %zu\n\n",
            g_simpoints.size(), g_segments_written);
    }
    g_mutex_unlock(&data_lock);

    /* Opportunistic branch-alternate minting accounting (static_templates=1,
     * both modes).  mints/checks is the post-warmup miss rate; depth_mints is
     * the subset minted by the static_depth successor walk; skips_unmapped are
     * targets whose page was not mapped (probing read failed). */
    if (g_features.alt_mint) {
        g_string_append_printf(report,
            "Branch-alternate minting: checks=%" PRIu64 " mints=%" PRIu64
            " depth_mints=%" PRIu64 " (depth=%u) skips_unmapped=%" PRIu64
            " budget_hits=%" PRIu64 "\n",
            g_alt_mint.checks, g_alt_mint.mints, g_alt_mint.depth_mints,
            g_features.alt_depth, g_alt_mint.skips_unmapped,
            g_alt_mint.budget_hits);
    }

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

    g_rt_gate.install();

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

    /*
     * Per-ISA init-time flags are sourced from the ISA property table so
     * the whole port surface lives in one declarative place
     * (isa_properties[] in champsim_tracer_mnemonics.h), not as scattered
     * trace_isa special cases here:
     *   - xlate_bypass_priv: the privilege level that runs with the
     *     paging register bypassed, excluded from pinned attribution
     *     (RISC-V M-mode is priv 3; -1 = none) — see the pin machinery.
     *   - has_be_variant: the ISA ships a big-endian QEMU target, taken
     *     unless the target_name carries the little-endian "el" suffix
     *     (qemu-mips / qemu-mips64 are BE; mipsel / mips64el are LE).
     */
    const IsaProperties *ip = &isa_properties[trace_isa];
    g_xlate_bypass_priv = ip->xlate_bypass_priv;
    target_big_endian   = ip->has_be_variant &&
                          !g_str_has_suffix(target_name, "el");

    /*
     * A SYSTEM CAPTURE NAMES ITS PROCESS BY THE PAGE-TABLE ROOT, OR IT DOES
     * NOT RUN.
     *
     * Every supported target identifies an address space by the root its own
     * hardware translates from — x86-64 CR3, AArch64 TTBR0, RISC-V SATP,
     * MIPS CP0 PWBase — and two LIVE address spaces can never share one.
     * A CPU model that supplies no root leaves only a narrow tag over the
     * TLB, and on MIPS that is an 8-bit EntryHi.ASID over a 16-entry TLB
     * which a Linux guest re-points at a DIFFERENT LIVE PROCESS whenever the
     * space wraps.  That is the normal case on a busy guest, not an edge
     * case, and following the traced process across it would mean guessing
     * from a thread pointer that fork() copies verbatim — forgeable
     * evidence, so it is not done.
     *
     * Refused UNCONDITIONALLY in system mode, on every ISA: there is no
     * plugin argument that makes a rootless model safe, and a refusal that
     * could be argued away is exactly the mid-capture window death it exists
     * to prevent.  QEMU exits non-zero from here, before
     * machine_run_board_init(), so no vCPU is created, no TB is translated,
     * no marker byte is read and no trace file is opened.
     *
     * User mode is exempt by construction: qemu-user is one address space
     * per process and the pin is not used.
     */
    if (info->system_emulation &&
        !(qemu_plugin_identity_caps() & QEMU_PLUGIN_IDENT_SPACE_IS_ROOT)) {
        if (!(qemu_plugin_identity_caps() &
              QEMU_PLUGIN_IDENT_MODEL_KNOWN)) {
            fprintf(stderr,
                "champsim_tracer: refusing to install — no CPU model.\n"
                "  The machine has no cpu_type (-M none), so the capture "
                "cannot be validated\n  before the first vCPU exists, and "
                "there is no address space to name.\n");
            return -1;
        }
        fprintf(stderr,
            "champsim_tracer: refusing to install — this CPU model names no "
            "address space.\n"
            "  target : %s\n"
            "  -cpu   : %s              <- resolved model, whether given or "
            "defaulted\n"
            "  missing: Config3.PW / CP0 PWBase, the hardware page-table "
            "walker's\n           page-table base register\n"
            "\n"
            "  A system-mode capture identifies its process by the page-table "
            "root the\n  architecture itself walks from: x86 CR3, AArch64 "
            "TTBR0, RISC-V SATP,\n  MIPS CP0 PWBase.  With no such register "
            "MIPS names an address space only\n  by an 8-bit EntryHi.ASID "
            "over the TLB, and a Linux guest reassigns that\n  value to a "
            "DIFFERENT live process on rollover -- the normal case, not an\n"
            "  edge case.  Following the traced process across that "
            "reassignment would\n  mean guessing from CP0 UserLocal, which "
            "fork() copies verbatim; that is\n  forgeable, so it is not "
            "done.  The capture is refused now rather than\n  "
            "mis-attributed, or retired in the middle of a window.\n"
            "\n"
            "  Re-run with the MIPS model that implements the walker:\n"
            "      -cpu P5600            (MIPS32r5, malta; Config3.PW and "
            "Config3.ULRI)\n"
            "  and a guest kernel that enables it: CONFIG_MIPS_HTW=y, no "
            "\"nohtw\" on the\n  kernel command line -- dmesg must print "
            "\"Hardware Page Table Walker\n  enabled\".  For -smp > 1 the "
            "kernel also needs CONFIG_MIPS_CPS=y; P5600\n  has no MT ASE.\n"
            "  (hw/mips/malta.c defaults to 24Kf on MIPS32 and 20Kc on "
            "MIPS64; neither\n   implements the walker, so -cpu is REQUIRED "
            "for a system-mode capture.)\n",
            target_name, cmdline_cpu_option());
        return -1;
    }

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
     * A wrong-path excursion is transparent to guest time under -icount as
     * well as without it: the excursion freezes the wall-clock source
     * (cpu_disable_ticks) and checkpoints the instruction counter
     * (icount_plugin_freeze), so speculation consumes neither.  Nothing to
     * warn about — the guest sees the same tick count with wrong-path
     * speculation on as with it off.
     */
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
    /* SMC per-PC revision cap (smc_plan.md §5-A).  The plugin option sets it;
     * CST_SMC_REVISION_CAP overrides for testability (the validator's cap-
     * overflow workload drives it far below the 1024 default). */
    g_smc_revision_cap = cfg.smc_revisions;
    if (const char *env = getenv("CST_SMC_REVISION_CAP")) {
        long long n = g_ascii_strtoll(env, nullptr, 10);
        if (n >= 0 && n <= UINT32_MAX) {
            g_smc_revision_cap = (uint32_t)n;
        }
    }
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
    g_latch_idle_insns  = cfg.latch_idle_insns;
    g_stall_ceiling     = cfg.stall_ceiling;
    g_stall_any_ceiling = cfg.stall_ceiling_any;
    /* marker_scan_enabled() below reads g_system_mode; seat it before the
     * admission test rather than at its later assignment. */
    g_system_mode = info->system_emulation;

    /*
     * IN SYSTEM MODE, THE WINDOW MUST LATCH TO A PROCESS VIA A MARKER.
     *
     * A full-system guest runs many processes through one instruction
     * stream.  A trace of a program is only a trace of that program if every
     * instruction in it belongs to that program, and the ONLY thing that
     * states which address space that is, is the START marker the program
     * itself executes.  A window that merely names a position on a clock
     * cannot say WHOSE instructions it is counting, so what it captures in
     * system mode is not a trace of anything.
     *
     * THE TEST IS THE PROPERTY, NOT A LIST OF MODE NAMES.  marker_scan_
     * enabled() is exactly "this window arms marker detection and therefore
     * latches to the address space that ran the START marker".  It is true
     * for trace_window=marker AND for a system-mode trace_window=simpoint,
     * which is a MARKER window with a simpoint schedule inside it: the
     * marker pins the process and zeroes the user clock, and the SimPoint
     * offsets then position the capture on that clock (see
     * pinned_simpoint_mode).  Naming modes here instead would refuse the
     * canonical marker+simpoint configuration, and a hand-listed set is
     * exactly how that mistake gets made.
     *
     * User mode is unaffected — qemu-user emulates one program, so the
     * window modes that only position a clock are exactly as meaningful
     * there as they have always been.
     */
    if (info->system_emulation && !marker_scan_enabled()) {
        const char *named =
            cfg.window_mode == PluginConfig::WIN_ICOUNT ? "icount" :
            cfg.window_mode == PluginConfig::WIN_SYMBOL ? "symbol" :
                                                          "the default";
        fprintf(stderr,
            "champsim_tracer: refusing to start — %s is not a valid window "
            "in system mode.\n"
            "  A full-system guest runs many processes through one "
            "instruction stream, and\n  a %s window is a position on a "
            "clock: it cannot say whose instructions\n  it is counting, so "
            "what it captures is not a trace of any one program.\n"
            "  A system-mode window must LATCH to a process, which means the "
            "program must\n  execute a START marker in its own address "
            "space.  Use either\n"
            "      trace_window=marker:simulation=<insns>+policy="
            "latch|trace-all\n"
            "  or, to capture SimPoint intervals inside that marked region,\n"
            "      trace_window=simpoint:file=<f>+interval=<n>+warmup=<n>"
            "+simulation=<n>\n"
            "  (the marker pins the process; the simpoint schedule chooses "
            "the intervals).\n"
            "  Give the workload its markers — compile them in, or inject "
            "them with\n  cst_attach.\n",
            named, named);
        return -1;
    }

    /*
     * BOUNDED BY CONSTRUCTION, OR REFUSED.
     *
     * A system-mode capture on the USER-INSTRUCTION clock (marker windows,
     * pinned simpoints) advances its budget only while the traced process
     * runs, and is ended only by that process's own END marker.  A process
     * that is killed, blocked forever, or never scheduled satisfies
     * neither, and the run then has no terminator at all.  Three things can
     * end it without the traced process's cooperation:
     *
     *   1. the machine going down (vcpu_vm_shutdown_cb) — always armed,
     *      but it needs the guest, or the operator, to shut down;
     *   2. the any-context instruction ceiling (stall_ceiling_any) — an
     *      architectural bound that holds whatever the guest is doing, as
     *      long as it executes ANYTHING;
     *   3. the dead latch (latch_timeout on the host's wall clock, or
     *      latch_idle_insns on the guest's own instruction stream) —
     *      opt-in, because its signal cannot tell a dead process from an
     *      idle one.  Either denominator alone bounds the run.
     *
     * Only (2) and (3) bound a guest that keeps running and never shuts
     * down.  Turning (2) off with no (3) leaves the run unbounded, so it is
     * not started at all: an operator who wants a capture with no bound
     * must say so by giving a dead latch, not by disabling the default.
     * Refused here rather than warned about, because the failure it
     * prevents is a run that never ends and a trace that is never written.
     */
    /*
     * A pinned system-mode capture needs the kernel-excursion ownership
     * model.  Without it there is no trustworthy answer to "whose work is
     * this?" at kernel privilege — the live address-space register is
     * exactly the read the excursion model exists to replace — and the
     * event-retention gate would have to fall back to retaining every
     * kernel-privilege fault event, i.e. precisely the unbounded behaviour
     * it removes.  Refused rather than run in a partial form.
     */
    if (info->system_emulation && !cfg.kexc &&
        (cfg.window_mode == PluginConfig::WIN_MARKER ||
         cfg.window_mode == PluginConfig::WIN_SIMPOINT)) {
        fprintf(stderr,
            "champsim_tracer: refusing to start — kexc=0 with a pinned "
            "system-mode window.\n"
            "  Kernel-privilege attribution then rests on the live "
            "address-space register,\n  which the kernel itself rewrites "
            "(entry switches, TLB-maintenance probes), so\n  neither the "
            "block gate nor the event-retention gate can say whose work a "
            "kernel\n  fault is.  Use kexc=1 (the default), or a non-pinned "
            "window.\n");
        return -1;
    }

    if (info->system_emulation && !cfg.stall_ceiling_any &&
        !cfg.latch_timeout_ms && !cfg.latch_idle_insns &&
        (cfg.window_mode == PluginConfig::WIN_MARKER ||
         cfg.window_mode == PluginConfig::WIN_SIMPOINT)) {
        fprintf(stderr,
            "champsim_tracer: refusing to start — this capture has no way "
            "to terminate.\n"
            "  A system-mode %s window advances its budget only while the "
            "traced\n  process runs, and closes only at that process's own "
            "END marker.  If the\n  process is killed, blocks forever, or "
            "is never scheduled, neither can\n  happen.  stall_ceiling_any="
            "0 disables the architectural bound that\n  covers exactly "
            "that case, and no dead latch was given, so nothing would\n"
            "  end this run.\n"
            "  Give stall_ceiling_any=<arch insns> (default %llu), or "
            "latch_idle_insns=<arch insns>\n  for a per-window bound on the "
            "same architectural clock, or latch_timeout=<ms>\n  if you want "
            "a wall-clock bound instead.\n",
            cfg.window_mode == PluginConfig::WIN_MARKER ? "marker"
                                                        : "simpoint",
            (unsigned long long)CST_STALL_ANY_CEILING_DEFAULT);
        return -1;
    }

    /*
     * Two decoupled fault concerns, split from the former single flag:
     *
     *  (a) The system-only sync-fault DEPTH (CST_FID_BB_FAULT_DEPTH block
     *      records) + kernel-handler merge.  Marker mode is the system-mode
     *      entrypoint (the validator's --system implies --marker, pinning a
     *      real guest ASID); a pinned simpoint qualifies too.  The block-level
     *      depth record tags handler code there; user-mode windows leave the
     *      feature off and every depth cell stays at its default 0.
     *
     *  (b) The wrong-path SYNTHETIC-FAULT marking policy.  A speculative
     *      memory access to an absent/unreadable page runs on a deterministic
     *      placeholder value and CONTINUES (a mispredicted-path fault is never
     *      taken by a real core); when set, the faulting insn's WP BB entry is
     *      marked CST_BB_FLAG_SYNTHETIC_FAULT.  It must run whenever
     *      wrong-path simulation runs — system AND user mode alike.
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

    /* Independent synchronous-fault / asynchronous-interrupt handler tracing.
     * Both are system-mode concepts: faults ride the depth-trailer machinery
     * (fault_depth_trailer) and interrupts ride the async-window machinery,
     * neither of which exists in user mode.  trace_faults defaults on (today's
     * behavior); trace_interrupts defaults off and is forced off in user mode
     * so a user-mode trace is byte-identical regardless of the requested
     * value. */
    g_features.trace_faults = cfg.faults != 0;
    g_features.trace_interrupts = (cfg.interrupts != 0) && g_system_mode;
    if (cfg.interrupts != 0 && !g_system_mode) {
        fprintf(stderr, "champsim_tracer: interrupts=1 ignored in user mode "
                "(no asynchronous-interrupt delivery exists)\n");
    }

    /* Per-image current-task offset (curtask_off=0x...).  Declared to
     * QEMU, whose x86-64 target resolves kernel-privilege thread
     * identity by reading the kernel's per-CPU current-task pointer at
     * this offset through the live kernel GS base — the same
     * "current, iff the identity register holds a kernel VA" contract
     * AArch64 (SP_EL0) and MIPS ($28) answer from a register, which
     * x86-64 architecturally cannot (the offset is decided at kernel
     * link time).  Absent, kernel identity keeps the register-only
     * contract byte-for-byte: every TLS-less task shares the identity
     * minted for 0.  The declaration itself is target-agnostic; warn
     * where nothing consumes it so a mis-aimed option is loud. */
    if (cfg.curtask_off_set) {
        qemu_plugin_set_current_task_offset(cfg.curtask_off);
        if (!g_system_mode) {
            fprintf(stderr, "champsim_tracer: curtask_off ignored in user "
                    "mode (no guest kernel runs)\n");
        } else if (trace_isa != TRACE_ISA_X86) {
            fprintf(stderr, "champsim_tracer: curtask_off declared but only "
                    "the x86-64 target consumes it (this target's kernel "
                    "keeps its task pointer in a register)\n");
        } else {
            fprintf(stderr, "champsim_tracer: kernel current-task pointer at "
                    "per-CPU offset 0x%" PRIx64 " (per-image; derive from "
                    "the running kernel build)\n", cfg.curtask_off);
        }
    }

    /* Physical-page capture is SYSTEM-MODE ONLY: qemu_plugin_get_hwaddr
     * returns NULL for linux-user, so there is no translation to record.
     * Forcing it off in user mode keeps user-mode traces byte-identical
     * regardless of the requested option. */
    g_features.physaddr = (cfg.physaddr != 0) && g_system_mode;
    if (cfg.physaddr != 0 && !g_system_mode) {
        fprintf(stderr, "champsim_tracer: physaddr=1 ignored in user mode "
                "(no virtual-to-physical translation exists)\n");
    }

    /* static_templates=1 turns on opportunistic branch-alternate MINTING —
     * mode-INDEPENDENT (it reads guest bytes at a branch's untaken target
     * through the same probing read the wrong path uses), so it covers the
     * never-executed fetch/decode space in user AND system mode alike.
     * static_depth=N (default) deepens that coverage from just the immediate
     * untaken side to its statically-known successors, N levels out. */
    g_features.alt_mint = (cfg.static_templates != 0);
    g_features.alt_depth = cfg.static_depth;

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


    /* Publish the "a path-event drain is owed" slot BEFORE any TB is
     * translated.  QEMU writes it on every queue push and clears it on
     * every drain; the per-TB absorber registered in vcpu_tb_trans is
     * conditional on it.  Without it the absorber's brcond is never true
     * and the queue reverts to growing with untraced execution.
     *
     * CST_EVQ_NOABSORB=1 withholds the registration.  It is the A/B arm —
     * the SAME binary, the same instrument, the same everything, minus the
     * mechanism — so the before/after numbers are not confounded by a
     * different build.  It is a diagnostic, never a supported mode: QEMU's
     * structural tripwire is likewise only armed when the slot is
     * published, because the ceiling is a claim about what a per-TB drain
     * point makes impossible.  Announced on stderr so a run that has it set
     * can never be mistaken for a shipping one. */
    if (getenv("CST_EVQ_NOABSORB")) {
        fprintf(stderr, "champsim_tracer: *** CST_EVQ_NOABSORB: the per-TB "
                "event-queue drain point is DISABLED (A/B arm).  The queue "
                "is unbounded in this run and the producer tripwire is not "
                "armed.  Never a shipping configuration. ***\n");
    } else {
        qemu_plugin_cpu_events_pending_slot(g_scoreboard.evq_pending);
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_flush_cb(id, vcpu_tb_flush);
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit, nullptr);
    if (g_system_mode) {
        /* Close, don't abandon: the machine going down is the one
         * termination path that needs no cooperation from the traced
         * process (see vcpu_vm_shutdown_cb).  Always registered — a
         * backstop that is opt-in is not a backstop. */
        qemu_plugin_register_vm_shutdown_cb(id, vcpu_vm_shutdown_cb);
        /* And the teardown the shutdown route never sees: a machine
         * RESET boots a new world in the same process, which must not
         * be recorded into the old world's window (vcpu_vm_reset_cb). */
        qemu_plugin_register_vm_reset_cb(id, vcpu_vm_reset_cb);
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
