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

/* Symbol-trigger state (trace_window=symbol:...).  start_symbol_match
 * _count counts TBs whose template names start_symbol; on reaching
 * start_symbol_occurrence we open a segment of simulation_insns. */
static char     *start_symbol            = nullptr;
static uint64_t  start_symbol_occurrence = 1;
static uint64_t  start_symbol_match_count = 0;
static int       g_window_mode           = 0; /* PluginConfig::WIN_AUTO */

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
}

/* ========================= Global state ========================= */

GMutex data_lock;
static GMutex exec_lock;

/*
 * Pending dst register snapshots for the currently-executing BB.
 * Each insn appends its dst snaps in dst_regs[] order, captured
 * POST-execution (the cb is on the next canonical insn's pre-exec
 * hook).  Last canonical insn of a TB is captured at the NEXT TB's
 * vcpu_tb_exec ("Tail-insn dst snap").  Drained into
 * BodyEntry.reg_snaps at finalize, discarded on flush.  Active only
 * when enable_reg_data.
 */
static thread_local std::vector<RegSnap> pending_reg_snaps;

/* ========================= Reg-data snapshot capture =========================
 *
 * Snap mechanics live in RegSnapCollector; this file owns only the
 * per-insn correct-path callback feeding pending_reg_snaps.
 */

typedef struct {
    BBTemplate *tb_tmpl;
    uint32_t    insn_index;
} RegSnapInsnRef;

/*
 * Per-insn destination snap callback.  Registered on the first raw
 * insn of canonical (ci+1), so when it fires pre-exec, canonical ci
 * has just finished and its dst registers hold post-exec values;
 * appends them to pending_reg_snaps.  The TB's last canonical insn
 * is captured at the NEXT TB's vcpu_tb_exec ("Tail-insn dst snap").
 */
static void vcpu_insn_reg_snap_cb(unsigned int cpu_index, void *udata)
{
    if (!enable_reg_data || g_wp_state.in_progress) {
        return;
    }
    if (!g_trace_segments.is_active_atomic()) {
        return;
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
        pending_reg_snaps.push_back(s);
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

static void start_trace_segment(const char *label,
                                uint64_t start, uint64_t stop,
                                uint64_t warmup,
                                uint64_t total_target,
                                unsigned int cpu_index,
                                double simpoint_weight)
{
    reset_segment_local_state();

    /* Capture the architectural register file so consumers can prime
     * register state without replaying a prior segment's dst-write
     * deltas.  cpu_index == (unsigned)-1 (install-time start=0, no
     * vCPU yet) → empty snapshot; dst-write stream is then the only
     * state source. */
    std::vector<InitialRegSnap> regfile;
    capture_initial_regfile(cpu_index, &regfile);

    g_trace_segments.start(label, start, stop, warmup, total_target,
                           (uint32_t)cpu_index, simpoint_weight, &regfile);

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
    uint64_t prev_ft =
        qemu_plugin_u64_get(g_scoreboard.prev_fall_through, cpu_index);
    uint64_t prev_is_branch =
        qemu_plugin_u64_get(g_scoreboard.prev_bb_ends_in_branch, cpu_index);

    BBTemplate *bb_tmpl = nullptr;
    if (out_stream && prev_start != 0) {
        g_mutex_lock(&data_lock);
        BBTemplate *prev_tb_tmpl =
            g_bb_template_cache.find_tb_template(prev_start);
        if (prev_tb_tmpl) {
            /* Tail-insn dst snap (see vcpu_tb_exec): no later
             * vcpu_tb_exec fires after shutdown, so capture the
             * segment-final TB's last insn's dst values here. */
            if (enable_reg_data && prev_tb_tmpl->insn_reg_names &&
                prev_tb_tmpl->n_insns > 0) {
                uint32_t last = prev_tb_tmpl->n_insns - 1;
                const InsnFields *fl = &prev_tb_tmpl->insn_fields[last];
                const InsnRegNames *nl =
                    &prev_tb_tmpl->insn_reg_names[last];
                for (uint8_t i = 0; i < fl->n_dst_regs; i++) {
                    RegSnap s;
                    g_reg_snaps.read_into_snap(
                        cpu_index, nl->dst_qemu_reg_keys[i], &s);
                    pending_reg_snaps.push_back(s);
                }
            }
            g_cp_chain.append_fragment(prev_start, prev_tb_tmpl, prev_ft);
        }
        if (prev_is_branch && prev_tb_tmpl &&
            g_cp_chain.has_active_chain()) {
            bb_tmpl = g_cp_chain.finalize();
        }
        g_mutex_unlock(&data_lock);
    }

    if (bb_tmpl) {
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
    {
        uint64_t lo = g_trace_segments.window_start();
        uint64_t hi = g_trace_segments.window_stop();
        if (hi == UINT64_MAX) {
            fprintf(stderr,
                    "champsim_tracer: finished segment [icount %"
                    PRIu64 " .. unbounded]\n", lo);
        } else {
            fprintf(stderr,
                    "champsim_tracer: finished segment [icount %"
                    PRIu64 " .. %" PRIu64 "]\n", lo, hi);
        }
    }
    g_trace_segments.finish(flush_pending_final_body_entry);

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
 * Update per-branch transition stats and history for the observed
 * transition.  Returns the BranchRecord (null if the previous TB
 * wasn't branch-terminated).  Caller holds data_lock.
 */
static BranchRecord *observe_branch_transition(bool prev_is_branch,
                                               bool branch_taken,
                                               uint64_t prev_last,
                                               uint64_t prev_ft)
{
    if (prev_is_branch) {
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
    }
    BranchRecord *br = prev_is_branch
        ? g_branch_history.get_or_create(prev_last, prev_ft)
        : g_branch_history.find(prev_last);
    if (br) {
        br->fall_through = prev_ft;
    }
    return br;
}

/*
 * Resolve the wrong-path target for a just-finalized BB whose
 * terminating branch lives in @prev_tb_tmpl.  Returns 0 when no
 * plausible WP target exists.  Caller holds data_lock.
 *
 * @taken_out receives the TAKEN-edge target, derived from the same
 * observations the resolver uses — never the raw (often PC-relative)
 * immediate.  It is current_pc (where CP transferred) in every case
 * except "CP fell through a resolvable direct conditional", where it
 * is the side CP did NOT run (the same value used for the wrong
 * path).  0 only when the BB has no branch.
 */
static uint64_t resolve_wrong_target(const BBTemplate *prev_tb_tmpl,
                                     BranchRecord *br,
                                     bool branch_taken,
                                     uint64_t current_pc,
                                     uint64_t prev_ft,
                                     uint64_t *taken_out)
{
    *taken_out = 0;
    int br_idx = BBTemplateCache::template_branch_index(prev_tb_tmpl);
    const InsnFields *bf = (br_idx >= 0)
        ? &prev_tb_tmpl->insn_fields[br_idx] : nullptr;
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
    if (direct_cond && bf->has_immediate &&
        (uint64_t)bf->immediate != prev_ft) {
        /* CP fell through a direct conditional → the taken edge is
         * the side CP did NOT run, which the resolver also uses as
         * the wrong path. */
        *taken_out = (uint64_t)bf->immediate;
        return (uint64_t)bf->immediate;
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
    if (enable_wrong_path && wrong_target != 0) {
        wp_entries = simulate_wrong_path_ext(
            prev_last, current_pc, wrong_target, cpu_index);
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
 * run yet).
 */
static void snap_prev_tail_dsts(unsigned int cpu_index,
                                const BBTemplate *tmpl)
{
    if (enable_reg_data && tmpl->insn_reg_names &&
        tmpl->n_insns > 0 &&
        g_trace_segments.is_active_atomic()) {
        uint32_t last = tmpl->n_insns - 1;
        const InsnFields *fl = &tmpl->insn_fields[last];
        const InsnRegNames *nl = &tmpl->insn_reg_names[last];
        for (uint8_t i = 0; i < fl->n_dst_regs; i++) {
            RegSnap s;
            g_reg_snaps.read_into_snap(
                cpu_index, nl->dst_qemu_reg_keys[i], &s);
            pending_reg_snaps.push_back(s);
        }
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
                             uint64_t icount_prev)
{
    if (g_window_mode == PluginConfig::WIN_SYMBOL) {
        /* Stop once the post-trigger simulation_insns budget is
         * spent (window_stop set when the symbol fired). */
        if (g_trace_segments.is_active() &&
            icount_prev >= g_trace_segments.window_stop()) {
            finish_trace_segment();
            g_trace_segments.set_shutting_down();
            g_mutex_unlock(&exec_lock);
            exit(0);
        }
        if (!g_trace_segments.is_active() && start_symbol) {
            uint64_t cur_pc = qemu_plugin_u64_get(g_scoreboard.current_pc,
                                                  cpu_index);
            BBTemplate *cur_tmpl = nullptr;
            g_mutex_lock(&data_lock);
            cur_tmpl = g_bb_template_cache.find_tb_template(cur_pc);
            g_mutex_unlock(&data_lock);
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
            finish_trace_segment();
            g_simpoints.advance();
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
                g_mutex_unlock(&exec_lock);
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
            finish_trace_segment();
            g_trace_segments.set_shutting_down();
            g_mutex_unlock(&exec_lock);
            exit(0);
        }
    }
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    uint64_t n_insns = (uint64_t)(uintptr_t)udata;

    g_mutex_lock(&exec_lock);

    if (g_trace_segments.is_shutting_down()) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    /* Update the per-vCPU instruction counter (CP path only).
     *
     * QEMU emits x86 REP string ops as a single-insn TB re-executed
     * once per REP iteration, each re-exec firing vcpu_tb_exec with
     * the same start_pc.  Skipping the increment when n_insns == 1 &&
     * start_pc == last_counted suppresses that drift; a normal tight
     * loop is a multi-insn TB so its per-iteration count is kept. */
    uint64_t cur_start_pc = qemu_plugin_u64_get(g_scoreboard.prev_start_pc,
                                                cpu_index);
    /*
     * icount_prev = architectural insns actually executed (TBs
     * 1..N-1); THIS TB has NOT run yet (vcpu_tb_exec fires at TB
     * start).  All trigger logic keys off icount_prev so conditions
     * track completed work — using the post-bump count would
     * undershoot by this TB on threshold-crossing exits.
     */
    uint64_t icount_prev = qemu_plugin_u64_get(g_scoreboard.insn_count,
                                               cpu_index);
    /* Cache the WP-progress flag: g_wp_state is thread_local and the
     * dlopen'd plugin's general-dynamic TLS model emits
     * __tls_get_addr per access (~10 ns each on every TB exec). */
    bool wp_in_progress = g_wp_state.in_progress;
    if (!wp_in_progress) {
        uint64_t last_counted = qemu_plugin_u64_get(
            g_scoreboard.last_counted_start_pc, cpu_index);
        bool is_rep_reentry = (n_insns == 1 && cur_start_pc == last_counted);
        if (!is_rep_reentry) {
            qemu_plugin_u64_set(g_scoreboard.insn_count, cpu_index,
                                icount_prev + n_insns);
            qemu_plugin_u64_set(g_scoreboard.last_counted_start_pc,
                                cpu_index, cur_start_pc);
        }
    }

    if (wp_in_progress) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    tw_manage_window(cpu_index, icount_prev);

    BodyStreamState *out_stream = g_trace_segments.body_stream();
    if (!g_trace_segments.is_active() || !out_stream) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    heartbeat_progress(icount_prev);

    /* Refresh the histogram bucket for this TB exec.  WP runs
     * synchronously below under exec_lock so its bumps land here too.
     * Selection uses icount_prev so stats land in the slice the TB
     * actually ran in. */
    g_current_hist_bucket = select_histogram_bucket(icount_prev);

    /* Snapshot the previous-TB scoreboard fields. */
    uint64_t current_pc = qemu_plugin_u64_get(g_scoreboard.current_pc, cpu_index);
    uint64_t prev_start = qemu_plugin_u64_get(g_scoreboard.prev_start_pc, cpu_index);
    uint64_t prev_last  = qemu_plugin_u64_get(g_scoreboard.prev_last_pc, cpu_index);
    uint64_t prev_ft    = qemu_plugin_u64_get(g_scoreboard.prev_fall_through, cpu_index);
    bool prev_is_branch = qemu_plugin_u64_get(g_scoreboard.prev_bb_ends_in_branch,
                                              cpu_index);

    /* Skip initial block (no previous context). */
    if (prev_ft == 0) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    bool branch_taken = (current_pc != prev_ft);

    /* --- Branch observation, chain assembly, and WP target resolution
     *     all run under data_lock. */
    g_mutex_lock(&data_lock);

    BranchRecord *br = observe_branch_transition(
        prev_is_branch, branch_taken, prev_last, prev_ft);

    BBTemplate *prev_tb_tmpl = g_bb_template_cache.find_tb_template(prev_start);
    if (prev_tb_tmpl) {
        snap_prev_tail_dsts(cpu_index, prev_tb_tmpl);
        g_cp_chain.append_fragment(prev_start, prev_tb_tmpl, prev_ft);
        attribute_cp_insns(prev_tb_tmpl);
    }

    bool finalize = prev_is_branch && prev_tb_tmpl != nullptr;
    uint64_t taken_target = 0;
    uint64_t wrong_target = finalize
        ? resolve_wrong_target(prev_tb_tmpl, br, branch_taken,
                               current_pc, prev_ft, &taken_target)
        : 0;
    BBTemplate *bb_tmpl = (finalize && g_cp_chain.has_active_chain())
        ? g_cp_chain.finalize() : nullptr;

    /*
     * Record the terminal-branch taken-edge target (derived by
     * resolve_wrong_target; see its @taken_out contract).
     */
    if (bb_tmpl && taken_target != 0) {
        bb_tmpl->taken_pc = taken_target;
    }

    g_mutex_unlock(&data_lock);

    if (!finalize) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    emit_finalized_bb(out_stream, bb_tmpl, prev_last, current_pc,
                      wrong_target, cpu_index);

    g_mutex_unlock(&exec_lock);
}

/* ========================= Translation callback ========================= */

/*
 * Arm the per-insn dynamic callbacks for a freshly created template:
 * post-exec dst-register snapshots and synthetic-EA capture for
 * memory-hint opcodes.  See the inline comments for the
 * canonical-first / ci-1 timing rationale.
 */
static void tb_arm_new_template_cbs(struct qemu_plugin_tb *tb,
                                    BBTemplate *new_tmpl,
                                    const qemu_plugin_insn_info *insn_info,
                                    size_t raw_n_insns,
                                    const uint32_t *canonical_index,
                                    const bool *canonical_first,
                                    uint32_t canonical_n_insns)
{
    if (enable_reg_data && new_tmpl && new_tmpl->insn_reg_names) {
        RegSnapInsnRef *refs = g_new0(RegSnapInsnRef,
                                      canonical_n_insns);
        new_tmpl->insn_snap_refs = refs;
        for (uint32_t i = 0; i < canonical_n_insns; i++) {
            refs[i].tb_tmpl = new_tmpl;
            refs[i].insn_index = i;
        }
        /*
         * Post-exec dst capture: register the snap cb on raw insn
         * i (canonical_first && ci > 0) pointing at ci-1.  Firing
         * pre-exec of ci means ci-1 just completed, so its dst
         * registers hold post-exec values.  The TB's last
         * canonical insn is captured at the next TB's
         * vcpu_tb_exec ("Tail-insn dst snap").
         */
        for (size_t i = 0; i < raw_n_insns; i++) {
            if (!canonical_first[i]) {
                continue;
            }
            uint32_t ci = canonical_index[i];
            if (ci == 0) {
                continue;  /* no predecessor canonical insn in this TB */
            }
            struct qemu_plugin_insn *insn =
                qemu_plugin_tb_get_insn(tb, i);
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, vcpu_insn_reg_snap_cb,
                QEMU_PLUGIN_CB_R_REGS,
                &refs[ci - 1]);
        }
    }

    if (new_tmpl) {
        SynthEAInsnRef *synth_refs = nullptr;
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
        if (new_tmpl->insn_synthetic_ea) {
            synth_refs = g_new0(SynthEAInsnRef, canonical_n_insns);
            new_tmpl->insn_synth_ea_refs = synth_refs;
            for (uint32_t i = 0; i < canonical_n_insns; i++) {
                synth_refs[i].tb_tmpl = new_tmpl;
                synth_refs[i].insn_index = i;
            }
            for (size_t i = 0; i < raw_n_insns; i++) {
                if (!canonical_first[i]) {
                    continue;
                }
                uint32_t ci = canonical_index[i];
                if (!new_tmpl->insn_synthetic_ea[ci].has_addr) {
                    continue;
                }
                struct qemu_plugin_insn *insn =
                    qemu_plugin_tb_get_insn(tb, i);
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, vcpu_insn_synth_ea_cb,
                    QEMU_PLUGIN_CB_R_REGS,
                    &synth_refs[ci]);
            }
        }
    }
}

/*
 * Re-translation of a known BB: re-arm the same per-insn dynamic
 * callbacks against the cached template's existing ref arrays.
 */
static void tb_rearm_known_template_cbs(struct qemu_plugin_tb *tb,
                                        BBTemplate *existing_tmpl,
                                        size_t raw_n_insns,
                                        const uint32_t *canonical_index,
                                        const bool *canonical_first)
{
    RegSnapInsnRef *refs =
        (RegSnapInsnRef *)existing_tmpl->insn_snap_refs;
    SynthEAInsnRef *synth_refs =
        (SynthEAInsnRef *)existing_tmpl->insn_synth_ea_refs;
    for (size_t i = 0; i < raw_n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

        if (enable_reg_data && refs && canonical_first[i] &&
            canonical_index[i] > 0 &&
            canonical_index[i] - 1 < existing_tmpl->n_insns) {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, vcpu_insn_reg_snap_cb,
                QEMU_PLUGIN_CB_R_REGS,
                &refs[canonical_index[i] - 1]);
        }

        if (synth_refs && canonical_first[i] &&
            canonical_index[i] < existing_tmpl->n_insns &&
            existing_tmpl->insn_synthetic_ea &&
            existing_tmpl->insn_synthetic_ea[canonical_index[i]].has_addr) {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, vcpu_insn_synth_ea_cb,
                QEMU_PLUGIN_CB_R_REGS,
                &synth_refs[canonical_index[i]]);
        }
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t raw_n_insns = qemu_plugin_tb_n_insns(tb);
    if (raw_n_insns == 0) {
        return;
    }
    struct qemu_plugin_insn *first_insn = qemu_plugin_tb_get_insn(tb, 0);
    struct qemu_plugin_insn *last_insn = qemu_plugin_tb_get_insn(tb,
                                                                  raw_n_insns - 1);
    uint64_t last_insn_pc = qemu_plugin_insn_vaddr(last_insn);
    size_t last_insn_size = qemu_plugin_insn_size(last_insn);
    uint64_t fall_through = last_insn_pc + last_insn_size;
    uint64_t bb_ends_in_branch = 0;
    uint64_t effective_last_pc = last_insn_pc;
    BBTemplate *existing_tmpl;

    uint64_t *insn_pcs = g_new0(uint64_t, raw_n_insns);
    qemu_plugin_insn_info *insn_info =
        g_new0(qemu_plugin_insn_info, raw_n_insns);
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

        qemu_plugin_register_vcpu_mem_cb(
            insn, vcpu_mem_cb, QEMU_PLUGIN_CB_NO_REGS,
            QEMU_PLUGIN_MEM_RW, (void *)(uintptr_t)raw_pc);
    }

    g_mutex_lock(&data_lock);
    existing_tmpl = g_bb_template_cache.find_tb_template(pc);
    /*
     * Only honour the cached template's branch index when the cached
     * template actually represents THIS TB's content.  QEMU can
     * translate two distinct TBs at the same start_pc (e.g. a small
     * chaining fragment alongside a full-block translation) and the
     * cache key is start_pc alone, so the first to land sticks.  If
     * the executing TB is the smaller fragment, reading effective_
     * last_pc from the cached larger template hands the scoreboard a
     * branch PC this TB doesn't actually contain — and the next
     * vcpu_tb_exec then thinks a branch just finalised and
     * resolve_wrong_target emits a bogus WP that mirrors CP.
     * fall_through_pc is the cheapest unique-enough fingerprint
     * (start_pc + architectural end past the delay slot).
     */
    bool cached_matches_tb =
        existing_tmpl && existing_tmpl->n_insns > 0 &&
        existing_tmpl->fall_through_pc == fall_through &&
        existing_tmpl->n_insns == canonical_n_insns;
    if (cached_matches_tb) {
        int br_idx = BBTemplateCache::template_branch_index(existing_tmpl);
        bb_ends_in_branch = (br_idx >= 0) ? 1 : 0;
        if (br_idx >= 0) {
            effective_last_pc = existing_tmpl->insn_pcs[br_idx];
        }
    }
    g_mutex_unlock(&data_lock);

    if (!existing_tmpl) {
        const char *symbol_name = qemu_plugin_insn_symbol(first_insn);

        g_mutex_lock(&data_lock);
        BBTemplate *new_tmpl = g_bb_template_cache.get_or_create_tb_template(
                                          pc,
                                          canonical_n_insns,
                                          insn_pcs,
                                          insn_info,
                                          insn_sizes,
                                          insn_bytes,
                                          symbol_name, fall_through);
        if (new_tmpl && new_tmpl->n_insns > 0) {
            int br_idx = BBTemplateCache::template_branch_index(new_tmpl);
            bb_ends_in_branch = (br_idx >= 0) ? 1 : 0;
            if (br_idx >= 0) {
                effective_last_pc = new_tmpl->insn_pcs[br_idx];
            }
        }
        g_mutex_unlock(&data_lock);

        tb_arm_new_template_cbs(tb, new_tmpl, insn_info, raw_n_insns,
                                canonical_index, canonical_first,
                                canonical_n_insns);
    } else if (cached_matches_tb) {
        tb_rearm_known_template_cbs(tb, existing_tmpl, raw_n_insns,
                                    canonical_index, canonical_first);
    } else {
        /*
         * Cached template's content doesn't match this TB (different
         * fragment at the same start_pc) — rearm the per-insn cbs
         * using the cached template as a structural skeleton so the
         * exec callbacks still fire, but DON'T claim this TB ends in
         * the cached template's branch.  bb_ends_in_branch and
         * effective_last_pc stay at their pre-template defaults
         * (no-branch, QEMU's raw last_insn_pc).
         */
        tb_rearm_known_template_cbs(tb, existing_tmpl, raw_n_insns,
                                    canonical_index, canonical_first);
    }

    /* Instrument the block for execution tracking. */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_STORE_U64, g_scoreboard.current_pc, pc);

    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, vcpu_tb_exec, QEMU_PLUGIN_CB_RW_REGS,
        (void *)(uintptr_t)canonical_n_insns);

    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        g_scoreboard.prev_start_pc, pc);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        g_scoreboard.prev_last_pc, effective_last_pc);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        g_scoreboard.prev_fall_through, fall_through);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        g_scoreboard.prev_bb_ends_in_branch, bb_ends_in_branch);

    g_free(insn_pcs);
    g_free(insn_info);
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
    g_mutex_lock(&exec_lock);

    if (g_wp_state.in_progress) {
        g_wp_state.in_progress = false;
        qemu_plugin_u64_set(g_scoreboard.insn_count, g_wp_state.saved_cpu_index,
                            g_wp_state.saved_insn_count);
        qemu_plugin_u64_set(g_scoreboard.prev_start_pc, g_wp_state.saved_cpu_index,
                            g_wp_state.saved_prev_start_pc);
        qemu_plugin_u64_set(g_scoreboard.prev_last_pc, g_wp_state.saved_cpu_index,
                            g_wp_state.saved_prev_last_pc);
        qemu_plugin_u64_set(g_scoreboard.prev_fall_through, g_wp_state.saved_cpu_index,
                            g_wp_state.saved_prev_fall_through);
        qemu_plugin_u64_set(g_scoreboard.prev_bb_ends_in_branch, g_wp_state.saved_cpu_index,
                            g_wp_state.saved_prev_bb_ends_in_branch);
        g_wp_state.mem_accesses.clear();
    }

    /* Drop the partial BB: preserving it across a flush would risk
     * splicing pre- and post-flush fragments. */
    g_mutex_lock(&data_lock);
    g_cp_chain.reset();
    g_mem_recorder.clear_cp();
    pending_reg_snaps.clear();
    g_mutex_unlock(&data_lock);

    g_mutex_unlock(&exec_lock);
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

    g_mutex_lock(&exec_lock);

    if (g_trace_segments.is_active()) {
        finish_trace_segment();
    }

    g_autoptr(GString) report = g_string_new("");

    g_mutex_lock(&data_lock);
    append_stats_summary(report, "Cumulative", stats_snapshot());
    if (g_simpoints.is_active()) {
        g_string_append_printf(report,
            "SimPoints loaded/traced: %zu / %zu\n\n",
            g_simpoints.size(), g_simpoints.current_index());
    }
    g_mutex_unlock(&data_lock);

    qemu_plugin_outs(report->str);

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
    g_mutex_init(&exec_lock);
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

    if (g_window_mode == PluginConfig::WIN_SYMBOL) {
        if (!start_symbol) {
            fprintf(stderr,
                    "champsim_tracer: trace_window=symbol requires name=...\n");
            return -1;
        }
        /* No segment opens until the named symbol is seen
         * start_symbol_occurrence times in vcpu_tb_exec. */
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


    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_flush_cb(id, vcpu_tb_flush);
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit, nullptr);

    return 0;
}
