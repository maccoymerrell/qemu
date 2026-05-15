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
uint32_t iframe_rate = 0;
uint64_t warmup_insns = 0;
uint64_t simulation_insns = 0;

/* Symbol-trigger state (trace_window=symbol:...).  Owned strings live
 * for the lifetime of the plugin; symbol_match_count is the running
 * count of TBs we've seen whose owning template names the configured
 * start_symbol — once it reaches start_symbol_occurrence we open a
 * trace segment of simulation_insns architectural insns. */
static char     *start_symbol            = nullptr;
static uint64_t  start_symbol_occurrence = 1;
static uint64_t  start_symbol_match_count = 0;
static int       g_window_mode           = 0; /* PluginConfig::WIN_AUTO */

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
static_assert(SYNC_EVENT_COUNT <= 4,
              "SyncEventType no longer fits in 2 bits of CST_INSN_FLAG_SYNC_MASK");

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
 * callback for the currently-executing BB.  Each insn appends its dst
 * snaps in InsnFields.dst_regs[] order, captured POST-execution: the
 * cb is registered on the next canonical insn's pre-exec hook, so it
 * fires AFTER the previous insn's body completed but BEFORE the next
 * begins.  The last canonical insn of every TB is captured at the
 * NEXT TB's vcpu_tb_exec instead (see "Tail-insn dst snap" there).
 * The buffer is drained into BodyEntry.reg_snaps at BB-finalize time
 * and discarded on flush.  Active only when enable_reg_data is true.
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

/*
 * Per-insn destination snap callback.  Registered on the FIRST raw
 * insn of canonical insn (ci+1) in this TB, so when it fires
 * pre-execution of that insn, canonical ci has just finished and its
 * destination registers carry post-execution values.  Reads each of
 * canonical ci's destination registers and appends the values to the
 * thread-local pending_reg_snaps buffer, which the body emitter folds
 * into BodyEntry.reg_snaps at finalize time.
 *
 * The LAST canonical insn of every TB is captured separately at the
 * NEXT TB's vcpu_tb_exec — see the "Tail-insn dst snap" block there.
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
 * Per-insn callback for prefetch / cache-flush / TLB-flush instructions
 * whose canonical TCG translation does not emit a memop.  Reads the
 * base/index register values, applies scale (x86) or shift (AArch64) to
 * the index, adds the displacement, and routes the resulting EA through
 * MemAccessRecorder so it shows up in the BodyEntry's load slots.
 *
 * Spec-mode WP execution (CF_MEMI_ONLY + CF_SINGLE_STEP) suppresses
 * post-translation per-insn callbacks, so this fires only on the CP
 * path.  That's expected: prefetch hints generate no architectural
 * memops on either path, and the WP simulator already ignores
 * non-memop control-flow effects.
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

    /* AArch64 register-form: index gets the shift modifier first;
     * x86 SIB: index gets multiplied by scale.  The two are mutually
     * exclusive (cap_fill_x86_operands always sets shift_amount == 0,
     * cap_fill_arm64_operands always sets scale == 1). */
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

/*
 * Drop every piece of plugin-side state that could leak across a
 * segment boundary, so each per-simpoint .cst file is standalone-
 * decodable without depending on values established in a prior
 * segment.  Called at segment start, after the prior segment's
 * finish_trace_segment has already drained pending CP body entries.
 *
 * What we reset and why:
 *   - True-BB template cache (g_bb_template_cache.bb_map_): the
 *     per-segment template dictionary is built from this map, so
 *     clearing it gives each segment a clean dictionary covering
 *     only the BBs reached after the reset.  Per-TB fragments
 *     (tb_map_) are intentionally preserved: QEMU only fires
 *     vcpu_tb_trans on a TB's first translation, so dropping
 *     fragments would orphan the chain assembler the next time a
 *     previously-translated TB executes.  True-BBs are re-assembled
 *     at runtime by BBChainAssembler from those fragments anyway.
 *   - Per-template IFRAME cadence (BBTemplate.emit_count) on the
 *     surviving tb_map_ entries: drives the iframe_rate-th emission
 *     trigger.  Without the reset a segment that begins mid-cadence
 *     would emit IFRAMEs at positions a standalone run wouldn't.
 *   - In-flight CP basic-block assembly (g_cp_chain): a partial
 *     chain started before the segment boundary and finalized after
 *     would splice fragments from before+after together.
 *   - In-flight memops (g_mem_recorder.cp): same rationale; WP is
 *     transient and always drained at the end of each WP simulation.
 *   - Thread-local pending dst register snaps: captured by the per-
 *     insn callback for the next BB; if the prior segment didn't
 *     flush them (e.g. the segment ended on a snap-capturing TB),
 *     they'd attach to the new segment's first body entry.
 *   - Per-vCPU thread-id assignment counter: thread_id 0 is the
 *     first vCPU observed in this segment, regardless of which one
 *     the prior segment last saw.
 *
 * The persistent FieldStateTable overlays inside BodyStreamState are
 * already fresh per segment (a new BodyStreamState is created in
 * body_stream_new on every open), so delta values in segment N are
 * encoded against a "nothing observed" baseline regardless of N-1.
 */
static void reset_segment_local_state(void)
{
    g_mutex_lock(&data_lock);
    /* Clearing bb_map_ also drops the old BBTemplates carrying their
     * accumulated emit_count; the next commit_true_bb rebuilds each
     * one zero-initialized (g_new0), so the IFRAME cadence implicitly
     * resets without a separate emit_count walk. */
    g_bb_template_cache.clear_bb_map();
    g_mutex_unlock(&data_lock);

    /*
     * Per-vCPU thread_local state (cp_chain, tls_cp_mem_accesses,
     * pending_reg_snaps) belongs to threads other than us.  We can't
     * touch those directly.  Bumping g_segment_generation lets each
     * thread self-drop its stale chain on its next append_fragment;
     * tls_cp_mem_accesses naturally drains every BB and pending_reg_
     * snaps drains every body emit, so they don't need a generation
     * check (their stale contents are at most one in-flight BB old,
     * and that BB's BBTemplate * pointers were just invalidated by
     * clear_bb_map — but vcpu_tb_exec re-validates the prev_tb_tmpl
     * via find_tb_template before using it, returning nullptr now
     * that bb_map_ is empty).
     */
    g_segment_generation.fetch_add(1, std::memory_order_release);

    /* Our own thread's TLS state (we're called from vcpu_tb_exec). */
    g_cp_chain.reset();
    g_mem_recorder.clear_cp();
    pending_reg_snaps.clear();

    cpu_to_thread_id.clear();
    next_thread_id = 0;
}

static void start_trace_segment(const char *label,
                                uint64_t start, uint64_t stop,
                                uint64_t warmup,
                                uint64_t total_target,
                                unsigned int cpu_index)
{
    reset_segment_local_state();

    /* Capture the architectural register file at segment start so the
     * header's "reg" encoding-map carries each generic ID's initial
     * value.  Lets consumers prime register state without depending
     * on a prior segment's final dst-write deltas to reveal values.
     * cpu_index == (unsigned)-1 means "no vCPU context yet" (the
     * install-time start=0 path); the snapshot is empty in that case
     * and the dst-write stream is the only state source. */
    std::vector<InitialRegSnap> regfile;
    capture_initial_regfile(cpu_index, &regfile);

    g_trace_segments.start(label, start, stop, warmup, total_target, &regfile);

    uint64_t span = stop > start ? stop - start : 0;
    progress_step = span >= 10 ? span / 10 : 1;
    progress_next = start + progress_step;

    /* Snapshot the cumulative stats so the matching finish_trace_segment
     * can compute "this segment's contribution" via stats_diff().
     * stats_snapshot() folds every thread's per-thread slot plus the
     * graveyard from any thread that has exited, so the diff is a
     * true global delta even on multi-vCPU runs. */
    segment_start_stats = stats_snapshot();
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
    entry.cpu_index = cpu_index;

    g_mem_recorder.drain_cp_into_dyn_params(entry.dyn_params, bb_tmpl);
    if (enable_reg_data && !pending_reg_snaps.empty()) {
        entry.reg_snaps = std::move(pending_reg_snaps);
        pending_reg_snaps.clear();
    }

    /*
     * REP fan-out: if the BB's terminator is a REP-prefixed string op
     * and its TB template carries a rep_subtmpl, split a single TB-
     * exec's memop stream into N iteration entries.  Iter 1 stays on
     * @entry (so the BB that *first* enters the REP loop ends with
     * the first REP, exactly like an ordinary branch terminator);
     * iter 2..N each emit a fresh 1-insn BodyEntry on rep_subtmpl
     * with a slice of the memops.
     *
     * Memops arrive in execution order under the REP insn's PC, so
     * the partition is direct: load/store callbacks fire mpi times
     * per iteration (1 for LODS/STOS/SCAS/INS/OUTS, 2 for MOVS/CMPS),
     * the first mpi belong to iter 1, the next mpi to iter 2, etc.
     * WP entries (if any) stay on iter 1 — the WP simulator already
     * sees REP as a single architectural branch, so the speculative
     * window applies once at the loop boundary, not per iteration.
     * reg_snaps similarly stay on iter 1; per-iteration RSI/RDI/RCX
     * deltas ride the field-delta stream like any other repeated
     * BB visit.
     */
    BBTemplate *rep_sub = bb_tmpl ? bb_tmpl->rep_subtmpl : nullptr;
    if (rep_sub && bb_tmpl->n_insns > 0) {
        uint32_t last = bb_tmpl->n_insns - 1;
        const InsnFields *lf = &bb_tmpl->insn_fields[last];
        unsigned mpi = (unsigned)lf->rep_loads_per_iter
                     + (unsigned)lf->rep_stores_per_iter;
        if (mpi > 0) {
            /* Separate REP-attributed memops from the rest while
             * preserving arrival order. */
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
            /* Tail-insn dst snap: same rationale as the equivalent
             * block in vcpu_tb_exec.  Without this we'd lose the
             * destination values of the segment-final TB's last
             * canonical insn, since no subsequent vcpu_tb_exec will
             * fire after segment shutdown. */
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

    /* Per-segment stats: diff against the snapshot taken at segment
     * start, format with the segment label, hand to the plugin
     * diagnostic stream. */
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
 * holds exec_lock.  cp_chain is thread_local; reset needs no lock.
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

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    uint64_t n_insns = (uint64_t)(uintptr_t)udata;

    g_mutex_lock(&exec_lock);

    if (g_trace_segments.is_shutting_down()) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    /* Update the per-vCPU instruction counter (only on CP path; WP
     * fragments are not counted).
     *
     * REP-family dispatcher re-entry doesn't move the architectural
     * instruction count.  QEMU's translator emits x86 REP-prefixed
     * string ops (MOVSB, STOSB, CMPSB, ...) as a *single-insn* TB
     * that the dispatcher re-executes once per architectural REP
     * iteration: each re-execution fires vcpu_tb_exec with the same
     * start_pc and adds 1 again, drifting our icount past the "one
     * count per architectural insn" semantics that PIN-style tracers
     * use.  Skip the increment exactly when n_insns == 1 AND
     * start_pc matches the last counted — that signature catches
     * REP-class single-insn dispatcher loops and nothing else.  A
     * normal tight loop is a multi-insn TB (the loop body plus the
     * conditional branch), so its per-iteration count is preserved. */
    uint64_t cur_start_pc = qemu_plugin_u64_get(g_scoreboard.prev_start_pc,
                                                cpu_index);
    /*
     * icount_prev is the count of architectural instructions that have
     * actually executed (TBs 1..N-1).  icount (read after the bump
     * below) reflects TBs 1..N — i.e. it includes THIS TB which has
     * NOT yet run since vcpu_tb_exec fires at TB start, before the
     * body.  Trigger logic (start/stop windows, histogram bucket
     * selection, progress prints) uses icount_prev so the conditions
     * key off completed work; if we used icount instead, exiting on
     * the threshold-crossing call would leave the trace short by
     * THIS TB's worth of insns (the canonical undershoot the user
     * reported on `start=0,stop=N` runs).
     */
    uint64_t icount_prev = qemu_plugin_u64_get(g_scoreboard.insn_count,
                                               cpu_index);
    /* Cache the WP-progress flag.  g_wp_state is thread_local, so the
     * compiler emits __tls_get_addr per access in the dlopen'd
     * plugin's general-dynamic TLS model; reading it twice in this
     * critical section costs ~10 ns extra on every TB exec. */
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

    /* --- Tracing window management.  May start/stop segments and
     *     terminate the process on simpoint exhaustion or non-simpoint
     *     stop.  Inline because the exit path holds exec_lock and we
     *     must release it before exit() so plugin_exit can re-acquire.
     *     All checks key off icount_prev (architectural insns
     *     completed) so the trace covers AT LEAST the requested
     *     window — overshooting by at most one TB rather than
     *     undershooting by the threshold-crossing TB. */
    if (g_window_mode == PluginConfig::WIN_SYMBOL) {
        /* Stop when the simulation_insns budget after the trigger has
         * been spent.  set_window stamped trace_start when the symbol
         * fired; we inherit the stop check from window_stop(). */
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
                    /* Open segment at the architectural insn count of
                     * the matching TB's start.  Simulation runs for
                     * simulation_insns more architectural insns; when
                     * unset (==0) the segment is unbounded and ends
                     * at process exit. */
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
                                        cpu_index);
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
                /* Effective window: warmup before the simpoint position,
                 * simulation_insns at-and-after.  When simulation_insns
                 * is zero the legacy sp->stop_insn (start + interval) is
                 * preserved for backwards-compatible runs.  warmup_insns
                 * underflow at the head of the trace is clamped to 0. */
                uint64_t eff_start = (sp->start_insn > warmup_insns)
                    ? sp->start_insn - warmup_insns : 0;
                uint64_t eff_stop = simulation_insns
                    ? sp->start_insn + simulation_insns
                    : sp->stop_insn;
                if (icount_prev >= eff_start &&
                    icount_prev <  eff_stop) {
                    g_trace_segments.set_window(eff_start, eff_stop);
                    g_autofree char *label = g_strdup_printf(
                        "sp%zu", g_simpoints.current_index());
                    /* warmup_insns saturates against eff_start so the
                     * header reports the actual number of pre-simpoint
                     * insns we'll trace, not the configured budget. */
                    uint64_t hdr_warmup = sp->start_insn > eff_start
                        ? sp->start_insn - eff_start : 0;
                    start_trace_segment(label, eff_start, eff_stop,
                                        hdr_warmup,
                                        /* total_target= */ eff_stop - eff_start,
                                        cpu_index);
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
            /* Non-simpoint mode: header total is the configured
             * (stop - start) when stop was specified, or 0 ("unbounded
             * — runs until process exit") when stop defaulted to
             * UINT64_MAX. */
            uint64_t total_target = (hi == UINT64_MAX) ? 0 : hi - lo;
            start_trace_segment("trace", lo, hi,
                                /* warmup= */ 0, total_target, cpu_index);
        }
        if (g_trace_segments.is_active() &&
            icount_prev >= g_trace_segments.window_stop()) {
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

    heartbeat_progress(icount_prev);

    /* Refresh the histogram bucket pointer for this TB exec.  WP code
     * runs synchronously below while exec_lock is still held, so its
     * bumps land in the correct bucket too.  Bucket selection uses
     * icount_prev so the just-executed TB's stats land in the bucket
     * for the architectural slice it actually ran in, not the slice
     * the next-to-run TB belongs to. */
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
        /*
         * Tail-insn dst snap for the TB that just finished.  The
         * per-insn cb chain only captures insn[0..n-2] of each TB
         * (each registered on insn[i+1]'s pre-exec hook); insn[n-1]'s
         * destinations would need a hook on the *next* TB's first
         * insn, which we can't pre-register because the branch target
         * is unknown at translation time.  Catching it here at the
         * next TB's vcpu_tb_exec is equivalent — registers still hold
         * prev_tb_tmpl's last insn's post-exec values (the next TB's
         * body has not yet run).
         */
        if (enable_reg_data && prev_tb_tmpl->insn_reg_names &&
            prev_tb_tmpl->n_insns > 0 &&
            g_trace_segments.is_active_atomic()) {
            uint32_t last = prev_tb_tmpl->n_insns - 1;
            const InsnFields *fl = &prev_tb_tmpl->insn_fields[last];
            const InsnRegNames *nl = &prev_tb_tmpl->insn_reg_names[last];
            for (uint8_t i = 0; i < fl->n_dst_regs; i++) {
                RegSnap s;
                g_reg_snaps.read_into_snap(
                    cpu_index, nl->dst_qemu_reg_keys[i], &s);
                pending_reg_snaps.push_back(s);
            }
        }

        g_cp_chain.append_fragment(prev_start, prev_tb_tmpl, prev_ft);

        /* Per-CP-execution attribution: walk the just-executed TB's
         * insns and bump opcode / branch_type / src-reg / dst-reg
         * counters.  Cheap: <=20 insns per TB on average, all hot in
         * cache from the surrounding work.
         *
         * Cache thread_stats_get() once before the loop — the g_stats
         * macro re-resolves the TLS slot via __tls_get_addr on every
         * expansion, and this loop bumps it 4×n_insns times in the
         * worst case. */
        Stats &s = thread_stats_get();
        Stats *h = g_current_hist_bucket;
        for (uint32_t i = 0; i < prev_tb_tmpl->n_insns; i++) {
            const InsnFields *f = &prev_tb_tmpl->insn_fields[i];
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
            /*
             * Post-exec destination capture: register the snap cb on
             * raw insn i (where canonical_first[i] && canonical_index
             * > 0), pointing at canonical_index-1.  When the cb fires
             * (PRE-execution of raw insn i, which is the first raw
             * occurrence of canonical insn ci), canonical insn ci-1
             * has just completed — its destination registers carry
             * post-execution values.  The LAST canonical insn of the
             * TB has no successor raw insn here; its destinations are
             * captured at the NEXT TB's vcpu_tb_exec via the
             * prev_tb_tmpl path (see "Tail-insn dst snap" below).
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
    } else {
        /* Re-translation of known BB: re-arm dynamic callbacks. */
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

    /* Build the GenericRegId → QemuRegKey reverse index now that the
     * per-ISA reg table is wired up.  The multi-reg classification
     * path (RISC-V V*M* tuples and any future register-group rows)
     * uses this to recover a QemuRegKey for each constituent generic
     * id so reg-data captures cover the whole tuple, not just its
     * leading element. */
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
        /* No vCPU context yet at install-time; capture an empty
         * initial regfile.  The (id->name) mapping is still pinned
         * in the header, just without live values.  Header total is
         * 0 (unbounded) when no explicit stop was given. */
        uint64_t total_target =
            (trace_stop_insn == UINT64_MAX) ? 0 : trace_stop_insn;
        start_trace_segment("trace", 0, trace_stop_insn,
                            /* warmup= */ 0, total_target,
                            /* cpu_index= */ (unsigned int)-1);
    }


    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_flush_cb(id, vcpu_tb_flush);
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit, nullptr);

    return 0;
}
