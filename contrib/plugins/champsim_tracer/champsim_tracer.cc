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
#include "champsim_tracer_bb_chain_assembler.h"
#include "champsim_tracer_bb_template_cache.h"
#include "champsim_tracer_branch_history.h"
#include "champsim_tracer_mem_access_recorder.h"
#include "champsim_tracer_plugin_config.h"
#include "champsim_tracer_reg_handle_cache.h"
#include "champsim_tracer_reg_snap_collector.h"
#include "champsim_tracer_scoreboard.h"
#include "champsim_tracer_simpoint_manager.h"
#include "champsim_tracer_stats.h"
#include "champsim_tracer_trace_segment_manager.h"
#include "champsim_tracer_wp_thread_state.h"
#include "champsim_tracer_writer.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* ========================= Configuration ========================= */

int max_wrong_path_depth = 64;
bool enable_wrong_path = true;
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
bool enable_mem_data = false;
bool enable_reg_data = false;
bool enable_wp_mem_data = false;
bool enable_wp_reg_data = false;
uint32_t iframe_rate = 0;
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
 * equality, never decode. */
std::unordered_map<uint64_t, uint32_t> g_first_insn_word;

/* TB start_pcs that have been detected as carrying non-stable
 * instruction bytes (decode failure OR byte change since first
 * sighting).  WP speculation refuses to enter these; subsequent
 * translation re-attempts at the same start_pc skip fragment
 * materialization.  Persistent across WP simulations; cleared with
 * tb_flush. */
std::unordered_set<uint64_t> g_poisoned_pcs;

/* Both maps above are accessed from vcpu_tb_trans (translation time,
 * no lock currently held) and from the WP walker (under exec_lock).
 * Protected by data_lock — already held by vcpu_tb_trans's
 * fragment-creation critical section and acquired here briefly for
 * lookups during translation. */
bool cst_pc_is_poisoned(uint64_t pc)
{
    g_mutex_lock(&data_lock);
    bool poisoned = g_poisoned_pcs.count(pc) > 0;
    g_mutex_unlock(&data_lock);
    return poisoned;
}

/* Thread-local cursor of the last CP TB this vCPU executed, set by
 * vcpu_tb_exec from its own per-TB udata.  The CP chain assembler
 * folds this snapshot at the next exec — an exact-shape pointer that
 * cannot collide with a sibling translation (CP vs WP) of the same
 * start_pc, and that needs no start_pc lookup. */
thread_local BBTemplate *g_cp_prev_tb_template CST_TLS_HOT = nullptr;

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
    if (g_window_mode == PluginConfig::WIN_SIMPOINT) {
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
    /* Symbol mode opens on TB template symbol name, not on an icount
     * threshold; every TB must take the slow path. */
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

    if (enable_reg_data) {
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
 * Recursive: a TCG code-buffer flush during wrong-path simulation runs
 * vcpu_tb_flush() synchronously (tb_gen_code -> qemu_plugin_flush_cb)
 * while this same thread is already inside vcpu_tb_exec holding
 * exec_lock.  A non-recursive mutex self-deadlocks there (seen on
 * large-footprint workloads like gcc that fill the buffer mid-WP).
 * exec_lock is never paired with a GCond, so recursion is safe.
 */
static GRecMutex exec_lock;


/*
 * Pending dst register snapshots for the currently-executing BB.
 * Each insn appends its dst snaps in dst_regs[] order, captured
 * POST-execution (the cb is on the next canonical insn's pre-exec
 * hook).  Last canonical insn of a TB is captured at the NEXT TB's
 * vcpu_tb_exec ("Tail-insn dst snap").  Drained into
 * BodyEntry.reg_snaps at finalize, discarded on flush.  Active only
 * when enable_reg_data.
 */
static thread_local std::vector<RegSnap> pending_reg_snaps CST_TLS_HOT;

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
 *    returns.  Skipped when enable_wp_reg_data is off.
 */
static void vcpu_insn_reg_snap_cb(unsigned int cpu_index, void *udata)
{
    if (!enable_reg_data && !enable_wp_reg_data) {
        return;
    }
    if (!g_trace_segments.is_active_atomic()) {
        return;
    }
    std::vector<RegSnap> *sink;
    if (g_wp_state.in_progress) {
        if (!enable_wp_reg_data) {
            return;
        }
        sink = &wp_pending_reg_snaps;
    } else {
        if (!enable_reg_data) {
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
 * g_current_hist_bucket points into g_histogram_buckets, refreshed at
 * the top of vcpu_tb_exec; null when inactive/disabled so attribution
 * sites collapse to one nullable check. */
static unsigned int g_histogram_intervals = 0;
static std::vector<Stats> g_histogram_buckets;
static uint64_t g_histogram_interval_size = 0;
static uint64_t g_histogram_segment_start = 0;
Stats *g_current_hist_bucket = nullptr;  /* extern in stats.h */

/* Appends a formatted summary of @stats to @report. */
static void append_stats_summary(GString *report, const char *label,
                                 const Stats &stats);

/* Appends a per-interval breakdown of @buckets to @report.  No-op
 * when @buckets is empty. */
static void append_histogram(GString *report, const char *segment_label,
                             const std::vector<Stats> &buckets,
                             uint64_t segment_start,
                             uint64_t interval_size);

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
 * No per-segment thread state (thread_id == vCPU index).  Persistent
 * FieldStateTable overlays are already fresh per segment (new
 * BodyStreamState per open).
 */
static void reset_segment_local_state(void)
{
    g_mutex_lock(&data_lock);
    /* Clearing bb_map_ drops the old BBTemplates and their
     * accumulated emit_count; the next commit_true_bb rebuilds each
     * zero-initialized, so the IFRAME cadence resets implicitly. */
    g_bb_template_cache.clear_bb_map();
    g_mutex_unlock(&data_lock);

    /*
     * Other threads' TLS state (cp_chain, tls_cp_mem_accesses,
     * pending_reg_snaps) can't be touched directly.  Bumping
     * g_segment_generation makes each thread self-drop its stale
     * chain on its next append_fragment; the other two drain every
     * BB / body emit, and any stale BBTemplate* they hold was just
     * invalidated by clear_bb_map (vcpu_tb_exec re-validates
     * prev_tb_tmpl via find_tb_template, now returning nullptr).
     */
    g_segment_generation.fetch_add(1, std::memory_order_release);

    /* Our own thread's TLS state (we're called from vcpu_tb_exec). */
    g_cp_chain.reset();
    g_mem_recorder.clear_cp();
    pending_reg_snaps.clear();
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

    g_trace_segments.start(label, start, stop, warmup, total_target,
                           (uint32_t)cpu_index, simpoint_weight, &regfile);

    /* Segment is active now → next-threshold becomes 0 so the
     * fast-path bail never fires in-segment (every TB takes the slow
     * path for chain emit + close-detect). */
    recompute_next_threshold();

    /* Mirror is_active into the per-vCPU scoreboard so the per-insn
     * heavy callbacks (registered with QEMU_PLUGIN_COND_GE 1) fire.
     * Also park the budget slot at the sentinel so
     * vcpu_tb_check_budget does not fire during the segment.  Skip
     * the slot writes on the install-time call (cpu_index == -1, no
     * vCPU yet); vcpu_init_cb back-fills both when a vCPU actually
     * appears with the manager already in "active" state. */
    if (cpu_index != (unsigned)-1) {
        qemu_plugin_u64_set(g_scoreboard.is_active, cpu_index, 1);
        qemu_plugin_u64_set(g_scoreboard.budget, cpu_index,
                            (uint64_t)BUDGET_INACTIVE_SENTINEL);
    }

    uint64_t span = stop > start ? stop - start : 0;
    progress_step = span >= 10 ? span / 10 : 1;
    progress_next = start + progress_step;

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
    if (g_histogram_intervals > 0 && span > 0) {
        g_histogram_buckets.assign(g_histogram_intervals, Stats{});
        g_histogram_interval_size =
            (span + g_histogram_intervals - 1) / g_histogram_intervals;
        if (g_histogram_interval_size == 0) {
            g_histogram_interval_size = 1;
        }
        g_histogram_segment_start = start;
    } else {
        g_histogram_buckets.clear();
        g_histogram_interval_size = 0;
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
}

/* Pick the bucket matching @icount; null when histograms are disabled
 * or no segment is active.  Caller holds exec_lock. */
static Stats *select_histogram_bucket(uint64_t icount)
{
    if (g_histogram_buckets.empty() || g_histogram_interval_size == 0) {
        return nullptr;
    }
    uint64_t off = icount > g_histogram_segment_start
        ? icount - g_histogram_segment_start : 0;
    size_t idx = (size_t)(off / g_histogram_interval_size);
    if (idx >= g_histogram_buckets.size()) {
        idx = g_histogram_buckets.size() - 1;
    }
    return &g_histogram_buckets[idx];
}

static void heartbeat_progress(uint64_t icount)
{
    if (!g_trace_segments.is_active() || icount < progress_next) {
        return;
    }
    uint64_t start = g_trace_segments.window_start();
    uint64_t stop  = g_trace_segments.window_stop();
    uint64_t span  = stop > start ? stop - start : 1;
    uint64_t pct   = ((icount - start) * 100) / span;
    fprintf(stderr,
            "champsim_tracer: progress %" PRIu64 "/%" PRIu64
            " insns (%" PRIu64 "%%)\n",
            icount, stop, pct);
    progress_next += progress_step;
}

/*
 * Build a BodyEntry from the calling thread's CP memop/reg-snap
 * accumulators (draining them) and write it to @out_stream.
 * @wp_entries is moved in.  Caller holds exec_lock; data_lock is NOT
 * held — the per-thread accumulators are unsynchronised by design.
 */
static void emit_body_entry(BodyStreamState *out_stream,
                            BBTemplate *bb_tmpl,
                            unsigned int cpu_index,
                            std::vector<WPBBEntry> wp_entries)
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
    entry.template_id = bb_tmpl ? bb_tmpl->template_id : 0;
    entry.dyn_params.reserve(g_mem_recorder.cp_count());
    entry.wp_entries = std::move(wp_entries);
    entry.tmpl = bb_tmpl;
    entry.thread_id = (uint32_t)cpu_index;
    entry.cpu_index = cpu_index;

    g_mem_recorder.drain_cp_into_dyn_params(entry.dyn_params, bb_tmpl);
    if (enable_reg_data && !pending_reg_snaps.empty()) {
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
    BBTemplate *rep_sub = bb_tmpl ? bb_tmpl->rep_subtmpl : nullptr;
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
                /* Iter 1: parent BB template + non-REP memops +
                 * first mpi REP memops. */
                entry.dyn_params = std::move(other_dps);
                entry.dyn_params.reserve(entry.dyn_params.size() + mpi);
                for (unsigned j = 0; j < mpi; j++) {
                    entry.dyn_params.push_back(rep_dps[j]);
                }
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
                 * remapped to 0 (sub has exactly one insn). */
                for (size_t k = 1; k < n_iter; k++) {
                    BodyEntry sub_e;
                    sub_e.seq_num     = g_trace_segments.next_seq_num();
                    sub_e.template_id = rep_sub->template_id;
                    sub_e.tmpl        = rep_sub;
                    sub_e.thread_id   = entry.thread_id;
                    sub_e.cpu_index   = entry.cpu_index;
                    sub_e.dyn_params.reserve(mpi);
                    for (unsigned j = 0; j < mpi; j++) {
                        DynParam dp = rep_dps[k * mpi + j];
                        dp.insn_index = 0;
                        sub_e.dyn_params.push_back(dp);
                    }
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

/* Append a CP fragment to the true-BB chain (shared by the per-exec walk
 * in vcpu_tb_exec and the segment-final flush below). */
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
 * Flush the pending final-TB body entry before a segment finishes.
 * BodyEntries are emitted lazily: vcpu_tb_exec emits the *previous*
 * TB's entry once its branch direction is known.  A TB ended by a
 * process-exiting syscall has no "next" TB, so without this its
 * memops would vanish.  No wrong-path (WP undefined after exit).
 * Caller holds exec_lock.
 */
static void flush_pending_final_body_entry(void)
{
    BodyStreamState *out_stream = g_trace_segments.body_stream();
    unsigned int cpu_index = 0;
    uint64_t prev_start =
        qemu_plugin_u64_get(g_scoreboard.prev_start_pc, cpu_index);

    std::vector<BBTemplate *> finalized;
    if (out_stream && prev_start != 0) {
        g_mutex_lock(&data_lock);
        /* Head fragment of the segment-final QEMU TB.  Walk its
         * fragment list up to the last-executed one (matched by
         * scoreboard's @prev_start), same as the per-exec walk in
         * vcpu_tb_exec.  No later vcpu_tb_exec will fire after
         * shutdown so this is the only chance to flush the trailing
         * chain. */
        BBTemplate *prev_tb_head = g_cp_prev_tb_template;
        for (BBTemplate *frag = prev_tb_head; frag != nullptr;
             frag = frag->next_tb_fragment) {
            bool is_last_executed = (frag->start_pc == prev_start);

            if (is_last_executed) {
                /* Tail-insn dst snap (see snap_prev_tail_dsts): the
                 * last-executed fragment's tail registers still hold
                 * post-exec values.  On a delay-slot tail [branch@n-2,
                 * delay@n-1] the branch's snap was deferred and there is
                 * no next TB to catch it (segment end), so capture both
                 * the branch (n-2) and the delay slot (n-1) here. */
                if (enable_reg_data && frag->insn_reg_names &&
                    frag->n_insns > 0) {
                    uint32_t last = frag->n_insns - 1;
                    bool ds_tail = frag->n_insns >= 2 &&
                        frag->insn_fields[last - 1].branch_type
                            != BRANCH_NONE &&
                        frag->insn_fields[last].branch_type
                            == BRANCH_NONE;
                    auto snap_tail = [&](uint32_t idx) {
                        const InsnFields *fl = &frag->insn_fields[idx];
                        const InsnRegNames *nl = &frag->insn_reg_names[idx];
                        for (uint8_t i = 0; i < fl->n_dst_regs; i++) {
                            RegSnap s;
                            g_reg_snaps.read_into_snap(
                                cpu_index, nl->dst_qemu_reg_keys[i], &s);
                            pending_reg_snaps.push_back(s);
                        }
                    };
                    if (ds_tail) {
                        snap_tail(last - 1);  /* branch */
                    }
                    snap_tail(last);          /* delay slot, or branch */
                }
            }

            cp_chain_append(frag);
            if (BBTemplate *bb_tmpl = cp_chain_finalize_if_complete()) {
                finalized.push_back(bb_tmpl);
            }

            if (is_last_executed) {
                break;
            }
        }
        g_mutex_unlock(&data_lock);
    }

    for (BBTemplate *bb_tmpl : finalized) {
        emit_body_entry(out_stream, bb_tmpl, cpu_index, {});
    }

    /* cp_chain and tls_cp_mem_accesses are thread_local; no lock. */
    g_cp_chain.reset();
    g_mem_recorder.clear_cp();

    qemu_plugin_u64_set(g_scoreboard.prev_start_pc, 0, 0);
    qemu_plugin_u64_set(g_scoreboard.prev_fall_through, 0, 0);
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
     * (§2.13 in champsim_tracer_format.md). */
    if (BodyStreamState *bs = g_trace_segments.body_stream()) {
        body_stream_set_warmup_end_arch_insns(
            bs, g_seg_warmup_end_arch_insns);
    }
    /* Drain any chain still in flight.  This may call emit_body_entry
     * one or more times, which bumps g_seg_arch_insns — so we print
     * the per-segment stats AFTER finish() returns so the counter
     * reflects the entire segment, including the trailing chain. */
    g_trace_segments.finish(flush_pending_final_body_entry);

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
        uint64_t covered = g_host_icount > lo
            ? g_host_icount - lo : 0;
        const char *flag = covered >= budget ? "OK" : "UNDER";
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
                PRIu64 "  covered=%" PRIu64
                "  budget=%" PRIu64 "  rep_fanout=%" PRIu64
                "  trace_arch_insns=%" PRIu64 "  %s\n",
                lo, hi, g_host_icount, covered, budget,
                seg_fanout, g_seg_arch_insns, flag);
        g_traced_icount.fetch_add(covered,
                                  std::memory_order_relaxed);
        g_total_arch_insns.fetch_add(g_seg_arch_insns,
                                     std::memory_order_relaxed);
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
    if (!g_histogram_buckets.empty()) {
        append_histogram(report, label,
                         g_histogram_buckets,
                         g_histogram_segment_start,
                         g_histogram_interval_size);
    }
    qemu_plugin_outs(report->str);
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
    int br_idx = BBTemplateCache::template_branch_index(bb_tmpl);
    const InsnFields *bf = (br_idx >= 0)
        ? &bb_tmpl->insn_fields[br_idx] : nullptr;
    if (!bf) {
        return 0;
    }

    bool is_indirect = bf->branch_type == BRANCH_INDIRECT_JUMP ||
                       bf->branch_type == BRANCH_RETURN;
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
 * Run the WP simulator (if applicable), then emit the just-finalized
 * BB's BodyEntry.  Caller holds exec_lock; cp_chain is thread_local.
 */
static void emit_finalized_bb(BodyStreamState *out_stream,
                              BBTemplate *bb_tmpl,
                              uint64_t prev_last,
                              uint64_t current_pc,
                              uint64_t wrong_target,
                              unsigned int cpu_index)
{
    g_cp_chain.reset();

    std::vector<WPBBEntry> wp_entries;
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
        /* If a tb_flush unwinds a spec-mode exec_tb mid-WP, the chain is
         * truncated at that point: the WP simulation cannot be safely
         * resumed OR re-run across the flush (QEMU's flush + spec-mode
         * interaction faults if wrong-path execution continues), so we
         * accept the truncated (still-valid, shorter) chain.  Only bites
         * under heavy flushing (rare except a tiny code cache). */
        bool flush_interrupted = false;
        wp_entries = simulate_wrong_path_ext(
            prev_last, current_pc, wrong_target, cpu_index,
            &flush_interrupted);
    } else if (wrong_target == 0) {
        thread_stats_get().wp_skipped++;
        if (Stats *h = g_current_hist_bucket) {
            h->wp_skipped++;
        }
    }

    emit_body_entry(out_stream, bb_tmpl, cpu_index, std::move(wp_entries));
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
    if (enable_reg_data && tmpl->insn_reg_names &&
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
static void tw_manage_window(unsigned int cpu_index,
                             uint64_t icount_prev,
                             BBTemplate *cur_tb_tmpl)
{
    if (g_window_mode == PluginConfig::WIN_SYMBOL ||
        g_window_mode == PluginConfig::WIN_MARKER) {
        /* Stop once the post-trigger simulation_insns budget is spent
         * (window_stop set when the symbol fired, or when the guest
         * marker fired — see vcpu_marker_cb, which is what opens the
         * segment in WIN_MARKER mode; only the close runs here). */
        if (g_trace_segments.is_active() &&
            icount_prev >= g_trace_segments.window_stop()) {
            finish_trace_segment();
            g_trace_segments.set_shutting_down();
            g_rec_mutex_unlock(&exec_lock);
            exit(0);
        }
        if (g_window_mode == PluginConfig::WIN_SYMBOL &&
            !g_trace_segments.is_active() && start_symbol) {
            /* cur_tb_tmpl IS the executing TB's template (passed
             * straight from the caller's per-TB udata); no start_pc
             * lookup needed. */
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
    } else if (g_simpoints.is_active()) {
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
    (void)udata;
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
    g_host_icount = icount_now;
    /* tw_manage_window handles both icount-mode and simpoint-mode
     * open/close logic.  Passing icount_now (post-inline-add value)
     * matches BBV's "count past threshold" semantics. */
    tw_manage_window(cpu_index, icount_now, nullptr);
    /* Re-arm the budget for the next event.  In-segment: sentinel
     * (won't fire while is_active=1 dispatches to vcpu_tb_exec for
     * close detection).  Inter-segment: countdown to next eff_start. */
    recompute_budget(cpu_index);
    g_rec_mutex_unlock(&exec_lock);
}

/* A finalized true BB awaiting emission, with its terminal-branch
 * classification already resolved.  Collected under data_lock; the actual
 * emit happens later under exec_lock only. */
struct PendingEmit {
    BBTemplate *bb_tmpl;
    uint64_t    branch_pc;
    uint64_t    emit_current_pc;
    uint64_t    wrong_target;
};

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
static bool collect_finalized_bbs(unsigned int cpu_index,
                                  BBTemplate *prev_tb_head,
                                  uint64_t prev_start, uint64_t current_pc,
                                  std::vector<PendingEmit> &pending_emits)
{
    g_mutex_lock(&data_lock);
    bool any_finalize = false;

    for (BBTemplate *frag = prev_tb_head; frag != nullptr;
         frag = frag->next_tb_fragment) {
        bool is_last_executed = (frag->start_pc == prev_start);

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
            int br_idx = BBTemplateCache::template_branch_index(bb_tmpl);
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

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    /* This callback is registered via register_vcpu_tb_exec_cond_cb
     * with COND_GE on is_active, so the JIT only dispatches it when
     * we're in-segment.  Inter-segment dispatch is handled solely by
     * inline_add (icount/budget) and vcpu_tb_check_budget.
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
     * acquiring exec_lock here would self-deadlock (it is a
     * non-recursive GMutex).  The WP-mode branch only touches
     * thread-local state, so it can skip the lock cleanly. */
    if (g_wp_state.in_progress) {
        g_wp_state.last_executed_tb = cur_tb_tmpl;
        return;
    }

    /* icount bump is now an inline_add registered AFTER this cb in
     * vcpu_tb_trans, so the scoreboard slot still holds the pre-TB
     * value at this point — matches the old icount_prev semantics
     * that tw_manage_window expects. */
    uint64_t icount_prev = qemu_plugin_u64_get(
        g_scoreboard.insn_count, cpu_index);
    g_host_icount = icount_prev;

    /* Snapshot the previous-TB cursor BEFORE updating it.  The chain
     * emit below walks this fragment list as "the TB that ran just
     * before this one", so it must capture the value g_cp_prev_tb_template
     * held on entry — NOT the value we are about to write. */
    BBTemplate *prev_cp_tb_tmpl = g_cp_prev_tb_template;
    g_cp_prev_tb_template = cur_tb_tmpl;

    g_rec_mutex_lock(&exec_lock);

    if (g_trace_segments.is_shutting_down()) {
        g_rec_mutex_unlock(&exec_lock);
        return;
    }

    /* Snapshot the segment generation before tw_manage_window so we
     * can detect a segment-open that happened inside it.  Each
     * segment is an independent trace: when a new segment opens
     * here, the local prev_cp_tb_tmpl and cur_tb_tmpl point at
     * fragments from the previous segment / inter-segment gap.
     * Walking them would bridge stale fragments into the new
     * segment's trace AND run WP against PCs unrelated to the new
     * segment's execution stream.  Drop this TB as a one-TB lossy
     * boundary; the next TB starts a fresh chain at its own
     * entry_pc.  No tb_flush is needed: per-insn callbacks for
     * already-translated TBs are gated via cond_cb on
     * `g_scoreboard.is_active`, so cached translations just fire
     * the cond_cb predicate (false outside segments) and skip the
     * callbacks at JIT-level. */
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
        g_cp_prev_tb_template = nullptr;
        g_rec_mutex_unlock(&exec_lock);
        return;
    }

    heartbeat_progress(icount_prev);

    /* Refresh the histogram bucket for this TB exec.  WP runs
     * synchronously below under exec_lock so its bumps land here too.
     * Selection uses icount_prev so stats land in the slice the TB
     * actually ran in. */
    g_current_hist_bucket = select_histogram_bucket(icount_prev);

    /* Snapshot the previous-TB scoreboard fields.  @prev_start is the
     * last-executed fragment's start_pc — set by that fragment's
     * first-raw-insn inline store; @prev_ft is its fall_through.  The
     * per-TB terminus is no longer read from the scoreboard: each
     * fragment's terminus is stored on its BBTemplate and consumed by
     * the per-fragment walk below. */
    uint64_t current_pc = qemu_plugin_u64_get(g_scoreboard.current_pc, cpu_index);
    uint64_t prev_start = qemu_plugin_u64_get(g_scoreboard.prev_start_pc, cpu_index);
    uint64_t prev_ft    = qemu_plugin_u64_get(g_scoreboard.prev_fall_through, cpu_index);

    /* Skip initial block (no previous context). */
    if (prev_ft == 0) {
        g_rec_mutex_unlock(&exec_lock);
        return;
    }

    /*
     * Walk the previous TB's fragment list up to the LAST EXECUTED
     * fragment.  The scoreboard's @prev_start identifies that
     * fragment (each fragment's first raw insn fires an inline store
     * with its own start_pc; a trap mid-TB stops later fragments'
     * stores from firing).  For each fragment that ran:
     *
     *   - intermediate fragments: by definition their branch did NOT
     *     take (a later fragment in the same TB executed), so their
     *     "next PC" is the next fragment's start_pc.
     *   - last-executed fragment: its current_pc / prev_ft come from
     *     the scoreboard (= where execution went after the entire
     *     prev TB ran).
     *
     * The chain assembler folds fragments into true BBs; each
     * completion is finalized + emitted independently.  Trap-fires
     * cases naturally truncate the walk at the trapping fragment, so
     * post-trap fragments never enter the chain.
     */
    std::vector<PendingEmit> pending_emits;
    bool any_finalize = collect_finalized_bbs(cpu_index, prev_cp_tb_tmpl,
                                              prev_start, current_pc,
                                              pending_emits);

    if (!any_finalize) {
        g_rec_mutex_unlock(&exec_lock);
        return;
    }

    for (const PendingEmit &pe : pending_emits) {
        emit_finalized_bb(out_stream, pe.bb_tmpl, pe.branch_pc,
                          pe.emit_current_pc, pe.wrong_target, cpu_index);
    }

    /* Deferred-exit on icount window-stop.  The trigger was set in
     * tw_manage_window when icount_prev first crossed window_stop;
     * exiting then would have left in-flight chain fragments
     * uncommitted (= recorded count below the requested stop, which
     * violates the "trace covers AT LEAST the requested window"
     * guarantee).  Wait until a vcpu_tb_exec ends with no active
     * in-flight chain — i.e. at a true-BB boundary — so every bumped
     * insn has either been committed to a BB in the trace or never
     * triggered the bump in the first place. */
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

    /* Simpoint analogue: tw_manage_window set close_pending when
     * icount_prev crossed window_stop.  Finalize only after the chain
     * has drained to a BB boundary so the trace covers AT LEAST
     * eff_stop - eff_start (warmup + simulation) insns. */
    if (g_simpoint_close_pending &&
        !g_cp_chain.has_active_chain() &&
        g_trace_segments.is_active()) {
        finish_trace_segment();
        g_simpoints.advance();
        g_simpoint_close_pending = false;
        g_cp_prev_tb_template = nullptr;
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

    g_rec_mutex_unlock(&exec_lock);
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
    if (!((enable_reg_data || enable_wp_reg_data) && new_tmpl &&
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
        InsnFields f;
        decode_detail_to_generic(0, info, &f, nullptr);
        return f.branch_type;
    };
    /*
     * Branch families that carry an architectural delay slot — the
     * insn right after the branch always executes (MIPS j / jal /
     * jr / b*).  syscall- and trap-type "branches" do NOT have a
     * delay slot and so end their fragment on the branch insn itself.
     */
    auto has_delay_slot = [](uint8_t bt) -> bool {
        return bt == BRANCH_DIRECT_JUMP || bt == BRANCH_INDIRECT_JUMP ||
               bt == BRANCH_RETURN || bt == BRANCH_COND_DIRECT;
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
        if (delay_isa && has_delay_slot(bt)) {
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
 * A generic launch wrapper executes `mov $CST_MARKER_MAGIC, %eax` just
 * before execve-ing the unmodified target.  The plugin spots that exact
 * encoding (B8 imm32) at translation time and arms a one-shot exec
 * callback; when it runs, a trace segment opens here and covers the
 * next `simulation` instructions of the launched process.  This is the
 * only window source that needs no ELF symbol table, no host icount,
 * and no modification to the target or the guest kernel — so it is the
 * mechanism for system-mode tracing of a chosen process (paging on,
 * where wrong-path speculation is bounded).
 *
 * NOTE (quick first cut): the window is `simulation` total instructions
 * from the marker, not yet user-space-only counted or pinned to the
 * target's address space.  The brief wrapper tail before execve is
 * negligible; SimPoint-grade user-space-instruction alignment and ASID
 * pinning are the planned refinement.
 */
static const uint32_t CST_MARKER_MAGIC = 0x43535401u;   /* mov: B8 01 54 53 43 */
static std::atomic<bool> g_marker_fired{false};

static void vcpu_marker_cb(unsigned int cpu_index, void *udata)
{
    (void)udata;
    if (g_wp_state.in_progress) {
        return;
    }
    bool expected = false;
    if (!g_marker_fired.compare_exchange_strong(expected, true)) {
        return;                              /* one-shot */
    }
    g_rec_mutex_lock(&exec_lock);
    if (!g_trace_segments.is_active() && !g_trace_segments.is_shutting_down()) {
        uint64_t lo = qemu_plugin_u64_get(g_scoreboard.insn_count, cpu_index);
        uint64_t span = simulation_insns ? simulation_insns : 1000000;
        uint64_t hi = lo + span;
        g_trace_segments.set_window(lo, hi);
        fprintf(stderr, "champsim_tracer: marker fired at icount %" PRIu64
                " — tracing %" PRIu64 " insns\n", lo, span);
        start_trace_segment("marker", lo, hi, /* warmup= */ 0, span,
                            cpu_index, /* simpoint_weight= */ 0.0);
    }
    g_rec_mutex_unlock(&exec_lock);
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

    g_mutex_lock(&data_lock);
    if (g_poisoned_pcs.count(pc)) {
        p.poisoned = true;
        p.pc = pc;
        p.reason = "previously poisoned";
    } else {
        for (uint32_t ci = 0; ci < canonical_n_insns && !p.poisoned; ci++) {
            uint64_t ipc = insn_pcs[ci];
            uint32_t word = 0;
            memcpy(&word, &insn_bytes[(size_t)ci * MAX_INSN_BYTES],
                   sizeof(word));
            auto it = g_first_insn_word.find(ipc);
            if (it != g_first_insn_word.end()) {
                if (it->second != word) {
                    p.poisoned = true;
                    p.pc = ipc;
                    p.reason = "bytes changed since first sighting";
                    p.is_smc_signal = true;
                }
            } else {
                g_first_insn_word.emplace(ipc, word);
            }
            if (!p.poisoned &&
                cst_cap_arch >= 0 && !insn_info[ci].mnemonic[0]) {
                p.poisoned = true;
                p.pc = ipc;
                p.reason = "Capstone decode failure";
            }
        }
        if (p.poisoned) {
            g_poisoned_pcs.insert(pc);
        }
    }
    g_mutex_unlock(&data_lock);
    return p;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t raw_n_insns = qemu_plugin_tb_n_insns(tb);
    if (raw_n_insns == 0) {
        return;
    }

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

    uint64_t *insn_pcs = g_new0(uint64_t, raw_n_insns);
    qemu_plugin_insn_info *insn_info =
        g_new0(qemu_plugin_insn_info, raw_n_insns);
    /*
     * Per-canonical-insn static branch target the translator resolved
     * for this instruction (via qemu_plugin_insn_branch_target_pc()).
     * Parallel to insn_info[] / insn_pcs[].  Zero on non-branches and
     * on indirect branches (which fall back to BranchHistory).
     */
    uint64_t *insn_branch_target_pcs = g_new0(uint64_t, raw_n_insns);
    uint8_t *insn_sizes = g_new0(uint8_t, raw_n_insns);
    uint8_t *insn_bytes = g_new0(uint8_t,
                                 raw_n_insns * MAX_INSN_BYTES);
    uint32_t *canonical_index = g_new0(uint32_t, raw_n_insns);
    bool *canonical_first = g_new0(bool, raw_n_insns);
    uint32_t canonical_n_insns = 0;

    for (size_t i = 0; i < raw_n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t raw_pc = qemu_plugin_insn_vaddr(insn);
        uint8_t raw_size =
            (uint8_t)MIN(qemu_plugin_insn_size(insn), MAX_INSN_BYTES);
        uint8_t raw_bytes[MAX_INSN_BYTES] = {0};

        qemu_plugin_insn_data(insn, raw_bytes, raw_size);

        /* WIN_MARKER (x86): arm the one-shot trace-open callback on the
         * launch wrapper's magic `mov $CST_MARKER_MAGIC, %eax`
         * (B8 imm32, little-endian).  Registered at every translation so
         * the marker is caught whenever and wherever the process runs;
         * the callback itself is one-shot. */
        if (g_window_mode == PluginConfig::WIN_MARKER &&
            trace_isa == TRACE_ISA_X86 && raw_size >= 5 &&
            raw_bytes[0] == 0xB8 &&
            raw_bytes[1] == (uint8_t)(CST_MARKER_MAGIC) &&
            raw_bytes[2] == (uint8_t)(CST_MARKER_MAGIC >> 8) &&
            raw_bytes[3] == (uint8_t)(CST_MARKER_MAGIC >> 16) &&
            raw_bytes[4] == (uint8_t)(CST_MARKER_MAGIC >> 24)) {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, vcpu_marker_cb, QEMU_PLUGIN_CB_NO_REGS, nullptr);
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
         * Keep the per-memop overhead in C and bail fast there. */
        qemu_plugin_register_vcpu_mem_cb(
            insn, vcpu_mem_cb, QEMU_PLUGIN_CB_NO_REGS,
            QEMU_PLUGIN_MEM_RW,
            (void *)(uintptr_t)raw_pc);
    }

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
        /* Drop all per-TB scratch; do not create fragments, do not arm
         * callbacks.  vcpu_tb_exec gets no udata for this TB. */
        g_free(insn_pcs);
        g_free(insn_info);
        g_free(insn_branch_target_pcs);
        g_free(insn_sizes);
        g_free(insn_bytes);
        g_free(canonical_index);
        g_free(canonical_first);
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
    uint32_t *local_canonical_index = g_new0(uint32_t, raw_n_insns);
    bool     *local_canonical_first = g_new0(bool, raw_n_insns);

    const char *tb_symbol_name = qemu_plugin_insn_symbol(first_insn);

    /* Persistent-template dedup: a tb_flush re-translates the same code,
     * so reuse the already-built fragment chain for this (start_pc,
     * canonical-insn-count) instead of allocating a duplicate.  Byte
     * identity is guaranteed by the bytes-changed/poison gate above (a TB
     * reaching here matches its first sighting), so the chain's shape and
     * decoded contents are identical; we only need to re-arm the JIT-level
     * per-insn callbacks and scoreboard stores below (done every
     * translation regardless of reuse). */
    /* Whole-TB canonical view; each fragment passes a slice to
     * create_tb_template (groups the six parallel per-insn arrays). */
    TbInsnView tb_view = {
        canonical_n_insns, insn_pcs, insn_info, insn_branch_target_pcs,
        insn_sizes, insn_bytes,
    };

    uint64_t tb_start_pc = insn_pcs[0];
    g_mutex_lock(&data_lock);
    BBTemplate *reuse_head =
        g_bb_template_cache.lookup_tb_chain(tb_start_pc, canonical_n_insns);
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
            frag_tmpl = g_bb_template_cache.create_tb_template(
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
            qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
                frag_first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
                g_scoreboard.prev_bb_terminus,
                (uint64_t)spec.terminus);
        }
    }

    /* Record a freshly built chain for future reuse (a tb_flush will
     * re-translate the same code and reuse it instead of duplicating). */
    if (!reuse && head_fragment) {
        g_mutex_lock(&data_lock);
        g_bb_template_cache.register_tb_chain(tb_start_pc, head_fragment);
        g_mutex_unlock(&data_lock);
    }

    g_free(local_canonical_index);
    g_free(local_canonical_first);

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
     * budget.  Same inline pattern; no C call on the hot path. */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_ADD_U64,
        g_scoreboard.budget, (uint64_t)(int64_t)(-(int64_t)raw_n_insns));

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
    qemu_plugin_register_vcpu_tb_exec_cond_cb(
        tb, vcpu_tb_check_budget, QEMU_PLUGIN_CB_NO_REGS,
        QEMU_PLUGIN_COND_GE, g_scoreboard.budget, (1ULL << 63),
        nullptr);
    /* Heavy callback: chain assembler, WP simulator, body-entry
     * emission.  Gated via cond_cb on is_active so it is NOT
     * dispatched at all during inter-segment — the JIT emits a
     * brcond and skips the call.  In-segment, is_active=1 and the
     * cb fires per TB just like before. */
    qemu_plugin_register_vcpu_tb_exec_cond_cb(
        tb, vcpu_tb_exec, QEMU_PLUGIN_CB_RW_REGS,
        QEMU_PLUGIN_COND_GE, g_scoreboard.is_active, 1,
        (void *)head_fragment);

    g_free(insn_pcs);
    g_free(insn_info);
    g_free(insn_branch_target_pcs);
    g_free(insn_sizes);
    g_free(insn_bytes);
    g_free(canonical_index);
    g_free(canonical_first);
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
     * the trace must be identical with or without it.  The plugin's
     * per-translation templates (tb_templates_) are PERSISTENT and
     * deduped: a re-translation reuses its existing chain (see
     * lookup_tb_chain), so a flush frees nothing and perturbs no walk
     * state.  That makes the trace flush-invariant by construction and
     * removes the whole class of flush-time use-after-free.
     *
     * We do NOT clear the bytes/poison caches (g_first_insn_word /
     * g_poisoned_pcs): they persist so SMC detection survives a flush,
     * and a legitimate flush+retranslate of unchanged code re-matches its
     * first sighting (no false poison) and reuses its template.
     *
     * The only state a flush touches is the flush counter, which the
     * wrong-path loop reads to detect (and retry) a spec-mode exec_tb
     * that a flush unwound before the guest insn ran. */
    g_tb_flush_count.fetch_add(1, std::memory_order_acq_rel);
}

/* ========================= Exit / statistics ========================= */

/* Render a Stats snapshot to @report (per-segment diff or cumulative
 * total). */
/* Per-branch-type breakdown, CP and WP side-by-side. */
static void append_branch_breakdown(GString *report, const Stats &stats)
{
    uint64_t cp_total = 0, wp_total = 0;
    for (size_t i = 0; i < BRANCH_TYPE_COUNT; i++) {
        if (i == BRANCH_NONE) continue;
        cp_total += stats.cp_branches_by_type[i];
        wp_total += stats.wp_branches_by_type[i];
    }
    if (cp_total == 0 && wp_total == 0) return;
    g_string_append_printf(report,
        "Branch type breakdown:\n"
        "  %-22s %14s %8s   %14s %8s\n",
        "type", "CP count", "%CP", "WP count", "%WP");
    for (size_t i = 0; i < BRANCH_TYPE_COUNT; i++) {
        if (i == BRANCH_NONE) continue;
        uint64_t cv = stats.cp_branches_by_type[i];
        uint64_t wv = stats.wp_branches_by_type[i];
        if (cv == 0 && wv == 0) continue;
        double cp_pct = cp_total
            ? 100.0 * (double)cv / (double)cp_total : 0.0;
        double wp_pct = wp_total
            ? 100.0 * (double)wv / (double)wp_total : 0.0;
        g_string_append_printf(report,
            "  %-22s %14" PRIu64 " %7.2f%%   %14" PRIu64 " %7.2f%%\n",
            branch_type_name_or_unknown((unsigned)i),
            cv, cp_pct, wv, wp_pct);
    }
}

/* Generic opcode breakdown, CP and WP side-by-side.  Sorted by
 * (CP+WP) total so the busiest opcodes come first regardless of
 * which path drives them. */
static void append_opcode_breakdown(GString *report, const Stats &stats)
{
    uint64_t cp_total = 0, wp_total = 0;
    for (size_t i = 0; i < GEN_OP_COUNT; i++) {
        cp_total += stats.cp_insns_by_opcode[i];
        wp_total += stats.wp_insns_by_opcode[i];
    }
    if (cp_total == 0 && wp_total == 0) return;
    std::vector<std::tuple<uint64_t, uint8_t>> rows;
    for (size_t i = 0; i < GEN_OP_COUNT; i++) {
        uint64_t s = stats.cp_insns_by_opcode[i] +
                     stats.wp_insns_by_opcode[i];
        if (s) rows.emplace_back(s, (uint8_t)i);
    }
    std::sort(rows.begin(), rows.end(),
              std::greater<std::tuple<uint64_t, uint8_t>>());
    g_string_append_printf(report,
        "Generic opcode breakdown (%zu non-zero):\n"
        "  %-20s %14s %8s   %14s %8s\n",
        rows.size(), "opcode", "CP count", "%CP", "WP count", "%WP");
    for (const auto &r : rows) {
        uint8_t op = std::get<1>(r);
        uint64_t cv = stats.cp_insns_by_opcode[op];
        uint64_t wv = stats.wp_insns_by_opcode[op];
        double cp_pct = cp_total
            ? 100.0 * (double)cv / (double)cp_total : 0.0;
        double wp_pct = wp_total
            ? 100.0 * (double)wv / (double)wp_total : 0.0;
        g_string_append_printf(report,
            "  %-20s %14" PRIu64 " %7.2f%%   %14" PRIu64 " %7.2f%%\n",
            generic_opcode_name_or_unknown((unsigned)op),
            cv, cp_pct, wv, wp_pct);
    }
}

static void append_stats_summary(GString *report, const char *label,
                                 const Stats &stats)
{
    const struct { const char *name; uint64_t value; } counters[] = {
        { "Branch transitions observed",         stats.branches_observed },
        { "  Taken",                             stats.branches_taken },
        { "  Not-taken",                         stats.branches_not_taken },
        { "CP total memory accesses",            stats.cp_total_mem_accesses },
        { "WP simulations performed",            stats.wp_simulations },
        { "WP simulations skipped",              stats.wp_skipped },
        { "WP total instructions",               stats.wp_total_insns },
        { "WP total memory accesses",            stats.wp_total_mem_accesses },
        { "WP early exits (fault)",              stats.wp_early_exits },
        { "Unknown-instruction warnings",        stats.unknown_insn_warnings },
    };
    const struct { const char *name; uint64_t value; } bin_counters[] = {
        { "  Header bits",        stats.bin_header_bits },
        { "  Body bits",          stats.bin_body_bits },
        { "  Dyn CP bits",        stats.bin_dyn_cp_bits },
        { "  Dyn WP bits",        stats.bin_dyn_wp_bits },
        { "  WP exception bits",  stats.bin_wp_exception_bits },
    };

    g_string_append_printf(report,
        "\n=== Wrong-Path Trace Plugin Statistics: %s ===\n"
        "Target architecture: %s\n"
        "Max wrong-path depth: %d instructions\n"
        "TB fragments translated: %" PRIu64 "\n"
        "BB templates created: %" PRIu64 "\n"
        "Unique branch PCs: %" PRIu64 "\n",
        label,
        target_name ? target_name : "unknown",
        max_wrong_path_depth,
        stats.tb_templates_created,
        stats.bb_templates_created,
        stats.unique_branch_pcs);

    for (size_t i = 0; i < G_N_ELEMENTS(counters); i++) {
        g_string_append_printf(report, "%-40s %" PRIu64 "\n",
                               counters[i].name, counters[i].value);
    }

    if (stats.wp_simulations > 0) {
        g_string_append_printf(report,
            "Average wrong-path length: %.1f instructions\n",
            (double)stats.wp_total_insns / stats.wp_simulations);
    }

    if (stats.bin_total_bits > 0) {
        g_string_append_printf(report,
            "Total binary bits: %" PRIu64 " (%.2f MiB)\n",
            stats.bin_total_bits,
            (double)stats.bin_total_bits / 8.0 / (1024.0 * 1024.0));
        for (size_t i = 0; i < G_N_ELEMENTS(bin_counters); i++) {
            g_string_append_printf(report,
                "%-40s %" PRIu64 " (%.2f%%)\n",
                bin_counters[i].name, bin_counters[i].value,
                100.0 * (double)bin_counters[i].value /
                       (double)stats.bin_total_bits);
        }
    }

    append_branch_breakdown(report, stats);
    append_opcode_breakdown(report, stats);

    /* Per-register attribution, CP and WP side-by-side, src and dst
     * separately. */
    auto print_reg_table = [&](const char *table_label,
                               const uint64_t *cp_arr,
                               const uint64_t *wp_arr) {
        uint64_t cp_total = 0, wp_total = 0;
        for (size_t i = 0; i < REG_ID_COUNT; i++) {
            cp_total += cp_arr[i];
            wp_total += wp_arr[i];
        }
        if (cp_total == 0 && wp_total == 0) return;
        std::vector<std::tuple<uint64_t, uint8_t>> rows;
        for (size_t i = 0; i < REG_ID_COUNT; i++) {
            uint64_t s = cp_arr[i] + wp_arr[i];
            if (s) rows.emplace_back(s, (uint8_t)i);
        }
        std::sort(rows.begin(), rows.end(),
                  std::greater<std::tuple<uint64_t, uint8_t>>());
        g_string_append_printf(report,
            "%s (%zu non-zero):\n"
            "  %-12s %14s %8s   %14s %8s\n",
            table_label, rows.size(),
            "register", "CP count", "%CP", "WP count", "%WP");
        for (const auto &r : rows) {
            uint8_t reg = std::get<1>(r);
            uint64_t cv = cp_arr[reg];
            uint64_t wv = wp_arr[reg];
            double cp_pct = cp_total
                ? 100.0 * (double)cv / (double)cp_total : 0.0;
            double wp_pct = wp_total
                ? 100.0 * (double)wv / (double)wp_total : 0.0;
            g_string_append_printf(report,
                "  %-12s %14" PRIu64 " %7.2f%%   %14" PRIu64 " %7.2f%%\n",
                generic_reg_name_or_unknown((unsigned)reg),
                cv, cp_pct, wv, wp_pct);
        }
    };
    print_reg_table("Src register attribution",
                    stats.cp_src_reg_uses, stats.wp_src_reg_uses);
    print_reg_table("Dst register attribution",
                    stats.cp_dst_reg_writes, stats.wp_dst_reg_writes);

    g_string_append_printf(report,
        "==========================================\n");
}

/* Per-interval breakdown: a headline table (CP/WP insns+memops,
 * branches per interval) then transposed top-K tables for opcode /
 * branch type / src reg / dst reg.  @buckets is partitioned by
 * interval and sums to the segment totals; per-interval insn counts
 * are approximated by summing *_insns_by_opcode. */
static void append_histogram(GString *report, const char *segment_label,
                             const std::vector<Stats> &buckets,
                             uint64_t segment_start,
                             uint64_t interval_size)
{
    if (buckets.empty()) {
        return;
    }
    size_t n = buckets.size();

    /* Per-bucket array sum, for the headline CP/WP insn columns. */
    auto sum_arr = [](const uint64_t *arr, size_t len) {
        uint64_t s = 0;
        for (size_t i = 0; i < len; i++) s += arr[i];
        return s;
    };

    g_string_append_printf(report,
        "\n--- Histogram: %s (%zu intervals of %" PRIu64 " insns) ---\n"
        "  %-4s %-22s %14s %14s %14s %14s %14s\n",
        segment_label, n, interval_size,
        "iv", "icount range",
        "CP insns", "CP memops", "WP insns", "WP memops", "branches");
    for (size_t i = 0; i < n; i++) {
        const Stats &b = buckets[i];
        uint64_t lo = segment_start + i * interval_size;
        uint64_t hi = lo + interval_size;
        g_autofree char *range =
            g_strdup_printf("%" PRIu64 "..%" PRIu64, lo, hi);
        uint64_t cp_ins = sum_arr(b.cp_insns_by_opcode, GEN_OP_COUNT);
        uint64_t wp_ins = sum_arr(b.wp_insns_by_opcode, GEN_OP_COUNT);
        g_string_append_printf(report,
            "  %-4zu %-22s %14" PRIu64 " %14" PRIu64
            " %14" PRIu64 " %14" PRIu64 " %14" PRIu64 "\n",
            i, range, cp_ins, b.cp_total_mem_accesses,
            wp_ins, b.wp_total_mem_accesses, b.branches_observed);
    }

    /* Transposed top-K: rows = top items by total CP+WP activity
     * across all intervals, columns = intervals.  cp_off/wp_off pick
     * the Stats arrays; CP+WP summed for ranking and printed combined. */
    auto print_top_k = [&](const char *table_label, unsigned id_count,
                           const char *(*name_of)(unsigned),
                           size_t cp_off, size_t wp_off,
                           unsigned k) {
        std::vector<std::tuple<uint64_t, unsigned>> rows;
        for (unsigned id = 0; id < id_count; id++) {
            uint64_t s = 0;
            for (size_t i = 0; i < n; i++) {
                const uint64_t *cp_arr =
                    (const uint64_t *)((const uint8_t *)&buckets[i] + cp_off);
                const uint64_t *wp_arr =
                    (const uint64_t *)((const uint8_t *)&buckets[i] + wp_off);
                s += cp_arr[id] + wp_arr[id];
            }
            if (s) rows.emplace_back(s, id);
        }
        if (rows.empty()) {
            return;
        }
        std::sort(rows.begin(), rows.end(),
                  std::greater<std::tuple<uint64_t, unsigned>>());
        if (rows.size() > k) {
            rows.resize(k);
        }
        g_string_append_printf(report,
            "\n  %s (top %zu, CP+WP per interval):\n    %-20s",
            table_label, rows.size(), "id");
        for (size_t i = 0; i < n; i++) {
            g_string_append_printf(report, " %12zu", i);
        }
        g_string_append_c(report, '\n');
        for (const auto &r : rows) {
            unsigned id = std::get<1>(r);
            const char *name = name_of(id);
            g_string_append_printf(report, "    %-20s",
                                   name ? name : "?");
            for (size_t i = 0; i < n; i++) {
                const uint64_t *cp_arr =
                    (const uint64_t *)((const uint8_t *)&buckets[i] + cp_off);
                const uint64_t *wp_arr =
                    (const uint64_t *)((const uint8_t *)&buckets[i] + wp_off);
                g_string_append_printf(report, " %12" PRIu64,
                                       cp_arr[id] + wp_arr[id]);
            }
            g_string_append_c(report, '\n');
        }
    };

    print_top_k("Opcode", GEN_OP_COUNT, generic_opcode_name_or_unknown,
                offsetof(Stats, cp_insns_by_opcode),
                offsetof(Stats, wp_insns_by_opcode), 10);
    print_top_k("Branch type", BRANCH_TYPE_COUNT, branch_type_name_or_unknown,
                offsetof(Stats, cp_branches_by_type),
                offsetof(Stats, wp_branches_by_type), BRANCH_TYPE_COUNT);
    print_top_k("Src register", REG_ID_COUNT, generic_reg_name_or_unknown,
                offsetof(Stats, cp_src_reg_uses),
                offsetof(Stats, wp_src_reg_uses), 12);
    print_top_k("Dst register", REG_ID_COUNT, generic_reg_name_or_unknown,
                offsetof(Stats, cp_dst_reg_writes),
                offsetof(Stats, wp_dst_reg_writes), 12);

    g_string_append_printf(report,
        "------------------------------------------\n");
}

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

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    target_name = info->target_name;

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

    /* Target byte order.  The four currently-supported ISAs (x86, AArch64,
     * RISC-V, MIPS) are LE in every QEMU configuration we ship except the
     * MIPS BE variants (qemu-mips, qemu-mips64), distinguished by the
     * lack of an "el" suffix on the target_name. */
    target_big_endian = (trace_isa == TRACE_ISA_MIPS &&
                         !g_str_has_suffix(target_name, "el"));

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
    enable_wrong_path    = cfg.enable_wp;
    enable_mem_data      = cfg.enable_mem_data;
    enable_reg_data      = cfg.enable_reg_data;
    /* Per-path toggles default to their CP siblings when unset (-1). */
    enable_wp_mem_data   = (cfg.wp_mem_data < 0)
        ? enable_mem_data : (cfg.wp_mem_data != 0);
    enable_wp_reg_data   = (cfg.wp_reg_data < 0)
        ? enable_reg_data : (cfg.wp_reg_data != 0);
    g_histogram_intervals = cfg.histogram_intervals > 0
        ? (unsigned int)cfg.histogram_intervals : 0;
    iframe_rate         = cfg.iframe_rate;
    simpoint_interval_insns = cfg.simpoint_interval;
    warmup_insns        = cfg.warmup_insns;
    simulation_insns    = cfg.simulation_insns;

    program_name        = cfg.program_name;    cfg.program_name = nullptr;
    trace_comment       = cfg.comment;         cfg.comment = nullptr;
    simpoints_file_path = cfg.simpoints_file;  cfg.simpoints_file = nullptr;
    start_symbol        = cfg.start_symbol;    cfg.start_symbol   = nullptr;
    start_symbol_occurrence = cfg.start_symbol_occurrence;
    g_window_mode       = cfg.window_mode;

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
        if (trace_isa != TRACE_ISA_X86) {
            fprintf(stderr, "champsim_tracer: trace_window=marker is "
                    "x86-only for now\n");
            return -1;
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

    return 0;
}
