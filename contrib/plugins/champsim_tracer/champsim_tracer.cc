/*
 * Wrong-Path Tracing Plugin for QEMU
 *
 * Main translation unit.  Responsibilities:
 *   - Plugin install, option parsing, lifecycle
 *   - Tracing window management (start/stop + simpoints)
 *   - BB template creation (delegated to BBTemplateCache)
 *   - vcpu_tb_trans / vcpu_tb_exec / vcpu_tb_flush callbacks
 *   - Memory-access callback (correct-path + wrong-path collection)
 *   - Exit-time statistics
 *
 * Peer TUs:
 *   - champsim_tracer_decode.cc  (Capstone → InsnFields)
 *   - champsim_tracer_wp.cc      (wrong-path simulator)
 *   - champsim_tracer_output.cc  (binary format v1.0 writer)
 *
 * Output: packed binary (.cst).  A reference Python decoder
 * (champsim_tracer_decode.py) produces human-readable text.
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
static bool enable_wrong_path = true;
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

/* ========================= Thread ID assignment ========================= */

static std::unordered_map<unsigned int, uint32_t> cpu_to_thread_id;
static uint32_t next_thread_id = 0;

static uint32_t get_or_assign_thread_id(unsigned int cpu_index)
{
    auto [it, inserted] = cpu_to_thread_id.try_emplace(cpu_index,
                                                       next_thread_id);
    if (inserted) {
        next_thread_id++;
    }
    return it->second;
}

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
static_assert(SYNC_ATOMIC < 16,
              "SyncEventType no longer fits in 4 bits of flags byte");

const InsnClassification *active_insn_table;
unsigned active_insn_table_size;
const RegClassification *active_reg_table;
unsigned active_reg_table_size;

static void vcpu_init_cb(qemu_plugin_id_t id, unsigned int cpu_index)
{
    (void)id;

    /*
     * Resolve cap_mode lazily on the first vCPU init.  The per-ISA
     * mode resolvers may call qemu_plugin_path_to_binary(), which
     * requires a live vCPU context (it dereferences current_cpu).
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
 * Pending register snapshots produced by the per-insn reg-snap
 * callback for the currently-executing BB.  Each insn appends its src
 * snaps in InsnFields.src_regs[] order.  The buffer is drained into
 * BodyEntry.reg_snaps at BB-finalize time, and discarded on flush.
 * Active only when enable_reg_data is true.
 */
static thread_local std::vector<RegSnap> pending_reg_snaps;

/* ========================= Reg-data snapshot capture =========================
 *
 * Reg-snap mechanics live in RegSnapCollector (see
 * champsim_tracer_reg_snap_collector.h).  This file owns only the
 * per-insn correct-path callback, which collects snaps into
 * pending_reg_snaps so the body emitter can fold them into BodyEntry
 * at finalize time.
 */

typedef struct {
    BBTemplate *tb_tmpl;
    uint32_t    insn_index;
} RegSnapInsnRef;

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

    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        RegSnap s;
        g_reg_snaps.read_into_snap(cpu_index, &names->src_qemu_reg_keys[i], &s);
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

/* ========================= Trace state management ========================= */

/* Heartbeat state for the active segment.  progress_step is one tenth
 * of the segment's instruction span (clamped to >=1).  progress_next is
 * the next icount value at which we'll print a progress line. */
static uint64_t progress_step = 0;
static uint64_t progress_next = 0;

/* Stats snapshot taken at segment start.  At segment finish we compute
 * (g_stats - segment_start_stats) and print that as the per-segment
 * summary, while g_stats keeps accumulating across segments for the
 * final cumulative print at plugin_exit. */
static Stats segment_start_stats;
static char *segment_label = nullptr;  /* g_strdup'd, freed at finish */

/* Histogram state.  When --histogram=N is set, every active segment
 * gets a parallel array of N Stats buckets — one per equal-sized
 * icount interval — that mirror the bumps made to g_stats during the
 * segment.  At finish_trace_segment we walk the buckets to print
 * per-interval breakdowns of the same attribution tables.
 *
 * g_current_hist_bucket is a pointer into g_histogram_buckets,
 * refreshed at the top of vcpu_tb_exec from the current icount.  CP
 * and WP attribution sites bump it when non-null.  Set to null when
 * the segment is inactive or histograms are disabled, so the bump
 * sites collapse to a single nullable check + branch. */
static unsigned int g_histogram_intervals = 0;
static std::vector<Stats> g_histogram_buckets;
static uint64_t g_histogram_interval_size = 0;
static uint64_t g_histogram_segment_start = 0;
Stats *g_current_hist_bucket = nullptr;  /* extern in stats.h */

/* Forward decl: appends a formatted summary of @stats to @report.
 * Called from finish_trace_segment with the per-segment diff and from
 * plugin_exit with the cumulative total. */
static void append_stats_summary(GString *report, const char *label,
                                 const Stats &stats);

/* Forward decl: appends a per-interval breakdown of @buckets to
 * @report.  Called from finish_trace_segment after the segment-wide
 * summary when --histogram=N is set.  No-op when @buckets is empty. */
static void append_histogram(GString *report, const char *segment_label,
                             const std::vector<Stats> &buckets,
                             uint64_t segment_start,
                             uint64_t interval_size);

static void start_trace_segment(const char *label,
                                uint64_t start, uint64_t stop)
{
    g_trace_segments.start(label, start, stop);
    cpu_to_thread_id.clear();
    next_thread_id = 0;

    uint64_t span = stop > start ? stop - start : 0;
    progress_step = span >= 10 ? span / 10 : 1;
    progress_next = start + progress_step;

    /* Snapshot the cumulative stats so the matching finish_trace_segment
     * can compute "this segment's contribution" via stats_diff(). */
    segment_start_stats = g_stats;
    g_free(segment_label);
    segment_label = g_strdup(label ? label : "trace");

    /* Histogram buckets: one Stats per interval, zero-init.  Interval
     * size rounds up so the last bucket absorbs any remainder; bucket
     * lookup clamps the index so a late icount past stop still maps
     * into the last bucket. */
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

    fprintf(stderr,
            "champsim_tracer: starting segment '%s' "
            "[icount %" PRIu64 " .. %" PRIu64 "]\n",
            label ? label : "trace", start, stop);
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
 * Build a BodyEntry from the calling thread's CP memop and reg-snap
 * accumulators and write it to @out_stream.  Drains the accumulators
 * as a side effect.  @wp_entries is moved into the entry.
 *
 * Caller must hold exec_lock.  data_lock is not held; the per-thread
 * accumulators are unsynchronised by design.
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
    entry.thread_id = get_or_assign_thread_id(cpu_index);

    g_mem_recorder.drain_cp_into_dyn_params(entry.dyn_params, bb_tmpl);
    if (enable_reg_data && !pending_reg_snaps.empty()) {
        entry.reg_snaps = std::move(pending_reg_snaps);
        pending_reg_snaps.clear();
    }

    if (out_stream) {
        body_stream_write_entry(out_stream, &entry);
    }
}

/*
 * Flush the pending final-TB body entry before a segment is finished.
 *
 * BodyEntries are emitted lazily from vcpu_tb_exec(): when a TB starts,
 * we emit the entry for the *previous* TB because only then do we know
 * whether that TB's branch was taken.  A TB terminated by a
 * process-exiting syscall never has a "next" TB to trigger the flush,
 * so its memops would silently disappear.  This helper emits that
 * pending entry (no wrong-path: WP is undefined after process exit).
 * Must be called with exec_lock held.
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

    g_mutex_lock(&data_lock);
    g_cp_chain.reset();
    g_mem_recorder.clear_cp();
    g_mutex_unlock(&data_lock);

    qemu_plugin_u64_set(g_scoreboard.prev_start_pc, 0, 0);
    qemu_plugin_u64_set(g_scoreboard.prev_fall_through, 0, 0);
}

/*
 * Finalize and write the current trace segment.  Must be called with
 * exec_lock held.
 */
static void finish_trace_segment(void)
{
    fprintf(stderr,
            "champsim_tracer: finished segment [icount %" PRIu64
            " .. %" PRIu64 "]\n",
            g_trace_segments.window_start(),
            g_trace_segments.window_stop());
    g_trace_segments.finish(flush_pending_final_body_entry);

    /* Per-segment stats: diff against the snapshot taken at segment
     * start, format with the segment label, hand to the plugin
     * diagnostic stream. */
    Stats seg_stats;
    stats_diff(&seg_stats, g_stats, segment_start_stats);
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
 * Update per-branch transition stats and the per-branch history record
 * for the just-observed transition.  Returns the BranchRecord so the
 * caller can hand it to the wrong-target resolver; null when the
 * previous TB did not end in a branch.  Caller holds data_lock.
 */
static BranchRecord *observe_branch_transition(bool prev_is_branch,
                                               bool branch_taken,
                                               uint64_t prev_last,
                                               uint64_t prev_ft)
{
    if (prev_is_branch) {
        g_stats.branches_observed++;
        if (branch_taken) {
            g_stats.branches_taken++;
        } else {
            g_stats.branches_not_taken++;
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
 * Resolve the wrong-path target for a just-finalized basic block whose
 * terminating branch lives in @prev_tb_tmpl.  Returns 0 when no
 * plausible WP target exists (unconditional jump that took its sole
 * direction; not a branch at all).  Caller holds data_lock.
 */
static uint64_t resolve_wrong_target(const BBTemplate *prev_tb_tmpl,
                                     BranchRecord *br,
                                     bool branch_taken,
                                     uint64_t current_pc,
                                     uint64_t prev_ft)
{
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
        if (branch_taken) {
            BranchHistory::note_target(br, current_pc);
        }
        return BranchHistory::indirect_wrong_target(br, current_pc, prev_ft);
    }
    if (branch_taken) {
        /* CP took a direct branch → WP is the fall-through. */
        return prev_ft;
    }
    if (direct_cond && bf->has_immediate &&
        (uint64_t)bf->immediate != prev_ft) {
        /* CP fell through a direct conditional → WP is the
         * statically-resolved taken target. */
        return (uint64_t)bf->immediate;
    }
    return 0;
}

/*
 * Run the WP simulator (if applicable), then build and emit the
 * BodyEntry for the just-finalized BB via emit_body_entry().  Caller
 * holds exec_lock; data_lock must be unheld (this function takes
 * data_lock around the cp_chain reset).
 */
static void emit_finalized_bb(BodyStreamState *out_stream,
                              BBTemplate *bb_tmpl,
                              uint64_t prev_last,
                              uint64_t current_pc,
                              uint64_t wrong_target,
                              unsigned int cpu_index)
{
    g_mutex_lock(&data_lock);
    g_cp_chain.reset();
    g_mutex_unlock(&data_lock);

    std::vector<WPBBEntry> wp_entries;
    if (enable_wrong_path && wrong_target != 0) {
        wp_entries = simulate_wrong_path_ext(
            prev_last, current_pc, wrong_target, cpu_index);
    } else if (wrong_target == 0) {
        g_stats.wp_skipped++;
        if (g_current_hist_bucket) {
            g_current_hist_bucket->wp_skipped++;
        }
    }

    emit_body_entry(out_stream, bb_tmpl, cpu_index, std::move(wp_entries));
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    uint64_t n_insns = (uint64_t)(uintptr_t)udata;

    g_mutex_lock(&exec_lock);

    if (g_trace_segments.is_shutting_down()) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    /* Update the per-vCPU instruction counter (only on CP path; WP
     * fragments are not counted). */
    if (!g_wp_state.in_progress) {
        uint64_t icount_prev = qemu_plugin_u64_get(g_scoreboard.insn_count, cpu_index);
        qemu_plugin_u64_set(g_scoreboard.insn_count, cpu_index, icount_prev + n_insns);
    }
    uint64_t icount = qemu_plugin_u64_get(g_scoreboard.insn_count, cpu_index);

    if (g_wp_state.in_progress) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    /* --- Tracing window management.  May start/stop segments and
     *     terminate the process on simpoint exhaustion or non-simpoint
     *     stop.  Inline because the exit path holds exec_lock and we
     *     must release it before exit() so plugin_exit can re-acquire. */
    if (g_simpoints.is_active()) {
        if (g_trace_segments.is_active() &&
            icount >= g_trace_segments.window_stop()) {
            finish_trace_segment();
            g_simpoints.advance();
        }
        if (!g_trace_segments.is_active()) {
            if (const SimPointEntry *sp = g_simpoints.current()) {
                if (icount >= sp->start_insn && icount < sp->stop_insn) {
                    g_trace_segments.set_window(sp->start_insn, sp->stop_insn);
                    g_autofree char *label = g_strdup_printf(
                        "sp%zu", g_simpoints.current_index());
                    start_trace_segment(label, sp->start_insn, sp->stop_insn);
                }
            } else {
                g_trace_segments.set_shutting_down();
                g_mutex_unlock(&exec_lock);
                exit(0);
            }
        }
    } else {
        if (!g_trace_segments.is_active() &&
            icount >= g_trace_segments.window_start() &&
            icount <  g_trace_segments.window_stop()) {
            start_trace_segment("trace",
                                g_trace_segments.window_start(),
                                g_trace_segments.window_stop());
        }
        if (g_trace_segments.is_active() &&
            icount >= g_trace_segments.window_stop()) {
            finish_trace_segment();
            g_trace_segments.set_shutting_down();
            g_mutex_unlock(&exec_lock);
            exit(0);
        }
    }

    BodyStreamState *out_stream = g_trace_segments.body_stream();
    if (!g_trace_segments.is_active() || !out_stream) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    heartbeat_progress(icount);

    /* Refresh the histogram bucket pointer for this TB exec.  WP code
     * runs synchronously below while exec_lock is still held, so its
     * bumps land in the correct bucket too. */
    g_current_hist_bucket = select_histogram_bucket(icount);

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
        g_cp_chain.append_fragment(prev_start, prev_tb_tmpl, prev_ft);

        /* Per-CP-execution attribution: walk the just-executed TB's
         * insns and bump opcode / branch_type / src-reg / dst-reg
         * counters.  Cheap: <=20 insns per TB on average, all hot in
         * cache from the surrounding work. */
        Stats *h = g_current_hist_bucket;
        for (uint32_t i = 0; i < prev_tb_tmpl->n_insns; i++) {
            const InsnFields *f = &prev_tb_tmpl->insn_fields[i];
            g_stats.cp_insns_by_opcode[f->opcode]++;
            if (h) h->cp_insns_by_opcode[f->opcode]++;
            if (f->branch_type != BRANCH_NONE) {
                g_stats.cp_branches_by_type[f->branch_type]++;
                if (h) h->cp_branches_by_type[f->branch_type]++;
            }
            for (uint8_t s = 0; s < f->n_src_regs; s++) {
                g_stats.cp_src_reg_uses[f->src_regs[s]]++;
                if (h) h->cp_src_reg_uses[f->src_regs[s]]++;
            }
            for (uint8_t d = 0; d < f->n_dst_regs; d++) {
                g_stats.cp_dst_reg_writes[f->dst_regs[d]]++;
                if (h) h->cp_dst_reg_writes[f->dst_regs[d]]++;
            }
        }
    }

    bool finalize = prev_is_branch && prev_tb_tmpl != nullptr;
    uint64_t wrong_target = finalize
        ? resolve_wrong_target(prev_tb_tmpl, br, branch_taken,
                               current_pc, prev_ft)
        : 0;
    BBTemplate *bb_tmpl = (finalize && g_cp_chain.has_active_chain())
        ? g_cp_chain.finalize() : nullptr;

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
    if (existing_tmpl && existing_tmpl->n_insns > 0) {
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
        BBTemplate *new_tmpl = nullptr;
        {
            new_tmpl = g_bb_template_cache.get_or_create_tb_template(pc,
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
        }
        g_mutex_unlock(&data_lock);

        if (enable_reg_data && new_tmpl && new_tmpl->insn_reg_names) {
            RegSnapInsnRef *refs = g_new0(RegSnapInsnRef,
                                          canonical_n_insns);
            new_tmpl->insn_snap_refs = refs;
            for (uint32_t i = 0; i < canonical_n_insns; i++) {
                refs[i].tb_tmpl = new_tmpl;
                refs[i].insn_index = i;
            }
            for (size_t i = 0; i < raw_n_insns; i++) {
                if (!canonical_first[i]) {
                    continue;
                }
                struct qemu_plugin_insn *insn =
                    qemu_plugin_tb_get_insn(tb, i);
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, vcpu_insn_reg_snap_cb,
                    QEMU_PLUGIN_CB_R_REGS,
                    &refs[canonical_index[i]]);
            }
        }
    } else {
        /* Re-translation of known BB: re-arm dynamic callbacks. */
        RegSnapInsnRef *refs =
            (RegSnapInsnRef *)existing_tmpl->insn_snap_refs;
        for (size_t i = 0; i < raw_n_insns; i++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

            if (enable_reg_data && refs && canonical_first[i] &&
                canonical_index[i] < existing_tmpl->n_insns) {
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, vcpu_insn_reg_snap_cb,
                    QEMU_PLUGIN_CB_R_REGS,
                    &refs[canonical_index[i]]);
            }
        }
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
 * Called when the TB cache is flushed.
 *
 * During wrong-path execution, tb_gen_code() may trigger tb_flush() when
 * the code buffer is full, longjmping past simulate_wrong_path_ext()'s
 * cleanup code.  Reset wp_* state here so vcpu_tb_exec is not
 * permanently suppressed.
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

    /* Drop partial BB being assembled — we can't know whether the flushed
     * TB will resume, so preserving partial state would risk splicing
     * fragments from before and after the flush. */
    g_mutex_lock(&data_lock);
    g_cp_chain.reset();
    g_mem_recorder.clear_cp();
    pending_reg_snaps.clear();
    g_mutex_unlock(&data_lock);

    g_mutex_unlock(&exec_lock);
}

/* ========================= Exit / statistics ========================= */

/* Render a Stats snapshot to @report.  Used for both the per-segment
 * summary (called from finish_trace_segment with a diff Stats) and
 * the cumulative final summary (called from plugin_exit with the
 * accumulated g_stats). */
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

    /* Per-branch-type breakdown, CP and WP side-by-side. */
    {
        uint64_t cp_total = 0, wp_total = 0;
        for (size_t i = 0; i < BRANCH_TYPE_COUNT; i++) {
            if (i == BRANCH_NONE) continue;
            cp_total += stats.cp_branches_by_type[i];
            wp_total += stats.wp_branches_by_type[i];
        }
        if (cp_total > 0 || wp_total > 0) {
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
    }

    /* Generic opcode breakdown, CP and WP side-by-side.  Sorted by
     * (CP+WP) total so the busiest opcodes come first regardless of
     * which path drives them. */
    {
        uint64_t cp_total = 0, wp_total = 0;
        for (size_t i = 0; i < GEN_OP_COUNT; i++) {
            cp_total += stats.cp_insns_by_opcode[i];
            wp_total += stats.wp_insns_by_opcode[i];
        }
        if (cp_total > 0 || wp_total > 0) {
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
    }

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

/* Per-interval breakdown of a segment's activity.  Emits:
 *   1. A headline table — one row per interval, with totals for CP
 *      insns / CP memops / WP insns / WP memops / branches.  Lets the
 *      reader spot phase boundaries at a glance.
 *   2. Transposed top-K tables for the four attribution dimensions
 *      (opcode, branch type, src reg, dst reg).  Rows are the K most-
 *      active items globally across the segment; columns are the
 *      intervals.  This format makes it trivial to see "where does
 *      RAX usage spike?" or "do branches concentrate in interval 7?"
 *
 * Counts in @buckets are partitioned by interval, so they sum to the
 * segment-wide totals already printed above.  CP insn count per
 * interval is approximated by summing cp_insns_by_opcode (which is
 * what the bumps actually counted); same for WP. */
static void append_histogram(GString *report, const char *segment_label,
                             const std::vector<Stats> &buckets,
                             uint64_t segment_start,
                             uint64_t interval_size)
{
    if (buckets.empty()) {
        return;
    }
    size_t n = buckets.size();

    /* Row totals helper: accumulate a per-bucket scalar so the headline
     * table can show CP/WP insns without the caller having to walk the
     * opcode array twice.  Inline to keep the table loop tight. */
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

    /* Transposed top-K table: one row per top item (chosen by total
     * activity across all intervals and both CP+WP), one column per
     * interval.  Caller-supplied accessors decide which Stats arrays
     * feed the totals — same closure pattern as print_reg_table above
     * so both CP and WP are summed for ranking but printed combined. */
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
    append_stats_summary(report, "Cumulative", g_stats);
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
     * Map ISA to Capstone arch/mode for qemu_plugin_cap_decode().  The
     * arch is fully determined by target_name and is set here.  The
     * mode resolver may need to introspect the guest binary (for
     * example to read .riscv.attributes or MIPS EF_* flags) which in
     * turn calls qemu_plugin_path_to_binary() — that helper requires
     * a live vCPU context, so the actual cap_mode_for_target() call is
     * deferred to the first vcpu_init_cb (see vcpu_init_cb).
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

    /* Apply parsed config to plugin globals + subsystem instances.
     * String fields with long-term lifetime (program_name, comment,
     * simpoints file) transfer out of cfg; the remaining strings are
     * freed by plugin_config_free below. */
    max_wrong_path_depth = cfg.depth;
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
    simpoint_interval_insns = cfg.simpoint_interval;

    program_name        = cfg.program_name;    cfg.program_name = nullptr;
    trace_comment       = cfg.comment;         cfg.comment = nullptr;
    simpoints_file_path = cfg.simpoints_file;  cfg.simpoints_file = nullptr;

    if (!cfg.output_path) {
        cfg.output_path = g_strdup("champsim_tracer_out");
    }
    g_trace_segments.set_output_path(cfg.output_path);
    g_trace_segments.set_output_pipe(cfg.output_pipe);

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

    if (!g_simpoints.is_active() && trace_start_insn == 0) {
        start_trace_segment("trace", 0, trace_stop_insn);
    }


    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_flush_cb(id, vcpu_tb_flush);
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit, nullptr);

    return 0;
}
