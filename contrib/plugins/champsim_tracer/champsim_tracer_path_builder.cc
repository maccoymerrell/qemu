/*
 * ChampSim Tracer — PathBuilder implementation (events-path CP step).
 *
 * See champsim_tracer_path_builder.h for the model and the two-phase
 * split around the shared window management.  The ordering invariant
 * underneath both phases: an event's effects belong to the first TB
 * executed after it — the drained events of step N happened after prev's
 * execution and before cur's, so they classify PREV (which executed
 * before them) and set the depth/mute context CUR runs under.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <utility>

#include "champsim_tracer_path_builder.h"
#include "champsim_tracer_bb_chain_assembler.h"
#include "champsim_tracer_mem_access_recorder.h"
#include "champsim_tracer_reg_snap_collector.h"
#include "champsim_tracer_scoreboard.h"
#include "champsim_tracer_stats.h"
#include "champsim_tracer_trace_segment_manager.h"
#include "champsim_tracer_wp_thread_state.h"

/* A/B env toggles for the fault machinery: CST_NO_FAULT kills the
 * feature upstream (g_features.fault_depth_trailer and wp_synthetic_marking),
 * CST_NO_FAULT_MERGE keeps depth stamping but disables classification/
 * stash/completion, and CST_NO_FAULT_WP zeroes only the merged emit's
 * wrong-path target. */
static bool pb_no_merge()
{
    static const bool v = getenv("CST_NO_FAULT_MERGE") != nullptr;
    return v;
}

static bool pb_no_fault_wp()
{
    static const bool v = getenv("CST_NO_FAULT_WP") != nullptr;
    return v;
}

static bool pb_diag()
{
    static const bool v = getenv("CST_FAULT_DIAG") != nullptr;
    return v;
}

/* Suspend-stack push/pop/displacement diagnostics (env-gated), for the
 * contention-run evidence the acceptance gate asks for. */
static bool pb_susp_diag()
{
    static const bool v = getenv("CST_SUSP_DIAG") != nullptr;
    return v;
}

static bool pb_depth_diag()
{
    static const bool v = getenv("CST_DEPTH_DIAG") != nullptr;
    return v;
}

/* Kernel-excursion ownership diagnostics: the entry-ASID restore arrow and
 * the kernel TBs an excursion admits or refuses after one.  Prints each
 * distinct block PC once (the interesting population is the set of blocks,
 * not the dynamic count, and a kernel excursion re-executes the same handler
 * text millions of times). */
static bool kexc_diag()
{
    static const bool v = getenv("CST_KEXC_DIAG") != nullptr;
    return v;
}

/* First-sighting filter for the kexc PC dumps.  Written only under
 * kexc_diag(), and every writer holds exec_lock (kexc runs inside the CP
 * step), so one process-wide set records the true interleave.  Immortal,
 * like the jump-diag rings: a teardown racing a late step must not touch
 * freed storage. */
static bool kexc_pc_first_sighting(const char *bucket, uint64_t pc)
{
    static std::set<std::pair<const char *, uint64_t>> *seen = nullptr;
    if (!seen) {
        seen = new std::set<std::pair<const char *, uint64_t>>();
    }
    return seen->insert({bucket, pc}).second;
}

/* Captured-async-window edge log (ENTER / RETURN / in-window ASID write /
 * close) with the window's identity, the guest thread at each edge and the
 * per-window ownership condition counters.  Measurement instrument only —
 * nothing in the tracer's logic reads it. */
static bool pb_async_diag()
{
    static const bool v = getenv("CST_ASYNC_DIAG") != nullptr;
    return v;
}

/*
 * Per-window measurement of the ownership CONDITION (not of its outcome): the
 * open window's id, where it opened in the body stream, how many depth stamps
 * it served for its OWNER vs for a PEER thread, and how many address-space
 * switches committed inside it.  A window with peer stamps and NO ASID write
 * is a context change no address-space-keyed rule could ever have seen.
 *
 * Process-wide, deliberately NOT members of the thread_local PathBuilder: the
 * plugin's static TLS block has almost no head room (see async_owner_tid_),
 * and a measurement instrument must not be the thing that pushes the .so past
 * dlopen.  Every writer runs under exec_lock, so the counters are race-free
 * and the ids globally monotonic; on a multi-vCPU guest they describe the
 * interleaved stream of windows rather than one vCPU's, which is a diagnostic
 * caveat only — the LEVEL's ownership (async_owner_tid_) stays per-vCPU.
 */
static uint64_t g_async_win_seq = 0;
static uint64_t g_async_win_id = 0;
static uint64_t g_async_win_enter_seq = 0;
static uint32_t g_async_win_asidw = 0;
static uint32_t g_async_win_own_stamps = 0;
static uint32_t g_async_win_peer_stamps = 0;

void PathBuilder::async_win_close(const char *kind, uint32_t tid)
{
    /* Tallied once per window, against the async_captures denominator. */
    if (g_async_win_peer_stamps) {
        if (g_async_win_asidw) {
            g_stats.async_win_peer_with_asidw++;
        } else {
            g_stats.async_win_peer_no_asidw++;
        }
    }
    if (pb_async_diag()) {
        fprintf(stderr, "[asyncdiag] CLOSE win=%" PRIu64 " kind=%s tid=%u "
                "owner=%u seq=%" PRIu64 " spanned=%" PRId64 " asidw=%u "
                "own_stamps=%u peer_stamps=%u\n",
                g_async_win_id, kind, tid, async_owner_tid_,
                g_dbg_last_emit_seq,
                (int64_t)(g_dbg_last_emit_seq - g_async_win_enter_seq),
                g_async_win_asidw, g_async_win_own_stamps,
                g_async_win_peer_stamps);
    }
    g_async_win_id = 0;
    g_async_win_enter_seq = 0;
    g_async_win_asidw = 0;
    g_async_win_own_stamps = 0;
    g_async_win_peer_stamps = 0;
}

/*
 * ---- CST_JUMP_DIAG: the syscall_fault_nesting oracle, raised ONLINE ----
 *
 * The offline oracle names a violating seq number long after the machinery
 * state that produced it is gone.  Under the gate every emit is checked
 * against the same rule (consecutive same-tid entries at the same privilege
 * step by <= 1) at the instant of the emit, and a violation prints the depth
 * pipeline's live state plus a ring of the preceding emits and seal steps —
 * naming the code path that stamped the depth.  Off the gate the only cost
 * is the mirror stores, which are plain thread-local writes on paths that
 * already run.
 */
bool cst_jump_diag(void)
{
    static const bool v = getenv("CST_JUMP_DIAG") != nullptr;
    return v;
}

static const char *dsrc_name(uint8_t s)
{
    switch (s) {
    case CST_DSRC_PIPELINE:    return "pipeline";
    case CST_DSRC_MERGE:       return "merge";
    case CST_DSRC_MERGE_PLAIN: return "merge-plain";
    case CST_DSRC_MERGE_ZERO:  return "merge-zero";
    case CST_DSRC_UNWIND:      return "unwind-flush";
    case CST_DSRC_FLUSH_FINAL: return "flush-final";
    default:                   return "none";
    }
}

static const char *pdsrc_name(uint8_t s)
{
    switch (s) {
    case CST_PDSRC_SEAL:   return "seal";
    case CST_PDSRC_RESUME: return "resume";
    default:               return "none";
    }
}

namespace {

struct JumpEmitRec {
    uint64_t seq, pc;
    uint32_t tid, depth;
    uint8_t  src, is_sys;
    uint16_t n_anchors;
};
struct JumpStepRec {
    uint64_t cur_pc, prev_pc;
    uint32_t raw, inflight, async_cap, depth_next, prev_depth, walk_depth;
    uint16_t frames, susp;
    uint8_t  priv, pinned, pdsrc, wdsrc;
    const char *tag;
};
constexpr size_t JD_RING = 32;

}  /* namespace */

/* Process-wide rings on the HEAP: the plugin is dlopen'd and the tracer's
 * TLS block already all but fills glibc's static-TLS surplus, so a
 * thread_local ring would fail the plugin load.  Every writer runs under
 * exec_lock (which serialises the whole CP step), so one shared ring records
 * the true global interleave — better evidence than per-thread rings.
 * Deliberately never freed (immortal, like the tracer's other process-wide
 * aggregates) so a teardown racing a late emit cannot touch freed storage. */
static JumpEmitRec *g_jd_emits = nullptr;
static size_t       g_jd_emit_n = 0;
static JumpStepRec *g_jd_steps = nullptr;
static size_t       g_jd_step_n = 0;
/* Last emit per guest thread id, so the online check mirrors the oracle's
 * per-tid (not per-vCPU) adjacency.  emit_body_entry runs under exec_lock,
 * so a plain process-wide map is safe; immortal for the same reason. */
static std::map<uint32_t, std::pair<uint32_t, int>> *g_jd_last_by_tid = nullptr;

void cst_jump_diag_step(uint64_t cur_pc, uint64_t prev_pc, int priv,
                        int pinned, const char *tag)
{
    if (!cst_jump_diag()) {
        return;
    }
    if (!g_jd_steps) {
        g_jd_steps = new JumpStepRec[JD_RING]();
    }
    JumpStepRec &r = g_jd_steps[g_jd_step_n % JD_RING];
    g_jd_step_n++;
    r.cur_pc = cur_pc;
    r.prev_pc = prev_pc;
    r.raw = g_dbg_raw_depth;
    r.inflight = g_dbg_inflight;
    r.async_cap = g_dbg_async_captured;
    r.depth_next = g_dbg_depth_next;
    r.prev_depth = g_dbg_prev_depth;
    r.walk_depth = g_dbg_walk_depth;
    r.frames = (uint16_t)g_dbg_frames;
    r.susp = (uint16_t)g_dbg_susp;
    r.priv = (uint8_t)priv;
    r.pinned = (uint8_t)pinned;
    r.pdsrc = g_dbg_prev_depth_src;
    r.wdsrc = g_dbg_walk_depth_src;
    r.tag = tag;
}

void cst_jump_diag_emit(uint64_t seq, uint32_t tid, uint64_t pc,
                        uint32_t depth, int is_sys, size_t n_anchors)
{
    if (!cst_jump_diag()) {
        return;
    }
    if (!g_jd_emits) {
        g_jd_emits = new JumpEmitRec[JD_RING]();
    }
    if (!g_jd_last_by_tid) {
        g_jd_last_by_tid = new std::map<uint32_t, std::pair<uint32_t, int>>();
    }
    auto it = g_jd_last_by_tid->find(tid);
    bool viol = false;
    const char *kind = "";
    uint32_t pd = 0;
    if (it != g_jd_last_by_tid->end()) {
        pd = it->second.first;
        const bool same_priv = (it->second.second == is_sys);
        if (same_priv &&
            (depth > pd ? depth - pd : pd - depth) > 1) {
            viol = true;
            kind = "JUMP";
        }
        if (n_anchors && pd <= depth) {
            viol = true;
            kind = kind[0] ? "JUMP+ANCHOR" : "ANCHOR";
        }
    }
    JumpEmitRec &e = g_jd_emits[g_jd_emit_n % JD_RING];
    g_jd_emit_n++;
    e.seq = seq;
    e.pc = pc;
    e.tid = tid;
    e.depth = depth;
    e.src = g_dbg_depth_src;
    e.is_sys = (uint8_t)is_sys;
    e.n_anchors = (uint16_t)n_anchors;
    (*g_jd_last_by_tid)[tid] = {depth, is_sys};

    if (!viol) {
        return;
    }
    fprintf(stderr,
            "\n[jumpdiag] *** %s seq=%" PRIu64 " tid=%u pc=0x%" PRIx64
            " sys=%d depth %u -> %u src=%s nanchor=%zu\n"
            "[jumpdiag]     live: raw=%u inflight=%u async=%u depth_next=%u"
            " prev_depth=%u(%s) walk_depth=%u(%s) frames=%zu susp=%zu\n",
            kind, seq, tid, pc, is_sys, pd, depth,
            dsrc_name(g_dbg_depth_src), n_anchors,
            g_dbg_raw_depth, g_dbg_inflight, g_dbg_async_captured,
            g_dbg_depth_next, g_dbg_prev_depth,
            pdsrc_name(g_dbg_prev_depth_src), g_dbg_walk_depth,
            pdsrc_name(g_dbg_walk_depth_src), g_dbg_frames, g_dbg_susp);
    size_t n = g_jd_emit_n < JD_RING ? g_jd_emit_n : JD_RING;
    for (size_t i = 0; i < n; i++) {
        const JumpEmitRec &r =
            g_jd_emits[(g_jd_emit_n - n + i) % JD_RING];
        fprintf(stderr, "[jumpdiag]   emit[-%02zu] seq=%" PRIu64 " tid=%u "
                "d=%u sys=%u anch=%u pc=0x%" PRIx64 " src=%s\n",
                n - 1 - i, r.seq, r.tid, r.depth, r.is_sys, r.n_anchors,
                r.pc, dsrc_name(r.src));
    }
    size_t m = g_jd_step_n < JD_RING ? g_jd_step_n : JD_RING;
    for (size_t i = 0; i < m; i++) {
        const JumpStepRec &r =
            g_jd_steps[(g_jd_step_n - m + i) % JD_RING];
        fprintf(stderr, "[jumpdiag]   step[-%02zu] %-16s cur=0x%" PRIx64
                " prev=0x%" PRIx64 " priv=%u pin=%u raw=%u infl=%u async=%u "
                "next=%u prev_d=%u(%s) walk_d=%u(%s) frames=%u susp=%u\n",
                m - 1 - i, r.tag ? r.tag : "?", r.cur_pc, r.prev_pc,
                r.priv, r.pinned, r.raw, r.inflight, r.async_cap,
                r.depth_next, r.prev_depth, pdsrc_name(r.pdsrc),
                r.walk_depth, pdsrc_name(r.wdsrc), r.frames, r.susp);
    }
    fflush(stderr);
}

PathBuilder &path_builder_tls()
{
    /* Heap-allocated and deliberately never freed: keeps the thread_local
     * itself an 8-byte pointer instead of a 400-byte object, so the
     * plugin's initial-exec TLS block stays well inside glibc's dlopen
     * static-TLS surplus (1664 B in qemu-system-x86_64). */
    static thread_local PathBuilder *builder = new PathBuilder();
    return *builder;
}

/* Does @t's instruction list contain @pc?  The frame invariant is
 * resume_pc ∈ full_tmpl — the faulting instruction lives in the faulting BB —
 * so a candidate 'prev' that fails this is a stale deferred TB, not the real
 * faulting block, and must not seed a frame. */
static bool tmpl_contains_pc(const BBTemplate *t, uint64_t pc)
{
    if (!t || !t->insn_pcs) {
        return false;
    }
    for (uint32_t i = 0; i < t->n_insns; i++) {
        if (t->insn_pcs[i] == pc) {
            return true;
        }
    }
    return false;
}

/* Is @piece's instruction run contained in @full at @piece->start_pc's
 * position — same PCs, sizes, AND BYTES?  Returns the position via @pos_out
 * (or UINT32_MAX).  Byte identity is the load-bearing discriminator: user
 * binaries share load addresses (every process maps code at the same low
 * VAs), so on a fixed-width ISA two processes' code at the same VA yields
 * identical PC and size runs — only the bytes tell them apart. */
static uint32_t tmpl_subrun_pos(const BBTemplate *full, const BBTemplate *piece)
{
    if (!full || !piece || !full->insn_pcs || !piece->insn_pcs) {
        return UINT32_MAX;
    }
    uint32_t i = 0;
    while (i < full->n_insns && full->insn_pcs[i] != piece->start_pc) {
        i++;
    }
    if (i == full->n_insns) {
        return UINT32_MAX;
    }
    /* Compare the OVERLAP only: @piece may legitimately extend past @full's
     * end (a force-committed incomplete head-fragment template whose resume
     * suffix runs on to the block's real branch), and may be shorter (a
     * re-fault attempt cut by a page boundary).  Foreign code fails on the
     * first byte-mismatched overlap insn regardless. */
    uint32_t overlap = full->n_insns - i < piece->n_insns
        ? full->n_insns - i : piece->n_insns;
    for (uint32_t k = 0; k < overlap; k++) {
        if (full->insn_pcs[i + k] != piece->insn_pcs[k]) {
            return UINT32_MAX;
        }
        if (full->insn_sizes && piece->insn_sizes &&
            full->insn_sizes[i + k] != piece->insn_sizes[k]) {
            return UINT32_MAX;
        }
        if (full->insn_bytes && piece->insn_bytes && full->insn_sizes &&
            memcmp(&full->insn_bytes[(size_t)(i + k) * MAX_INSN_BYTES],
                   &piece->insn_bytes[(size_t)k * MAX_INSN_BYTES],
                   full->insn_sizes[i + k]) != 0) {
            return UINT32_MAX;
        }
    }
    return i;
}

/* Is @suffix content-consistent with being @full's resume suffix — same
 * instruction PCs, sizes, and BYTES across their overlap from suffix->start?
 * This is the CONTENT check that makes resume-PC frame matching safe: user
 * binaries share load addresses (every process maps code at the same low
 * VAs), so a frame stashed by ANOTHER address space's fault at the same VA —
 * reachable through same-VA reuse across ASID generations — must not consume
 * an innocent block's seal and emit a foreign template in its place
 * (observed: another process's pending frame at resume 0x4003f0 swallowed
 * the workload's just-sealed block starting there, silently dropping it from
 * the trace).  A genuine resume suffix is byte-identical to the stashed
 * template at the resume position, so this costs nothing for real
 * completions. */
static bool merge_suffix_matches(const BBTemplate *full,
                                 const BBTemplate *suffix)
{
    return tmpl_subrun_pos(full, suffix) != UINT32_MAX;
}

void PathBuilder::on_segment_open()
{
    /* Orphan drop: every frame's full_tmpl points into the bb_map_ the
     * opener just cleared, so an excursion straddling the boundary loses
     * its accumulated prefix by design (acceptable; the segment is a
     * fresh trace).  The accumulators the frames absorbed are gone with
     * them. */
    if (pb_diag() && !frames_.empty()) {
        for (const CtxFrame &f : frames_) {
            fprintf(stderr, "[pathbuilder] ORPHAN frame full=0x%" PRIx64
                    " resume=0x%" PRIx64 " depth=%u nmem=%zu\n",
                    f.full_tmpl ? f.full_tmpl->start_pc : 0,
                    f.resume_pc, f.depth, f.mem.size());
        }
    }
    /* Orphan-drop the suspension stack too (Stage 3, Decision A): each
     * entry's prev + frozen chain point into the bb_map_ the opener cleared,
     * so a suspension straddling the boundary is discarded with no emit — the
     * same rule frames_ follows (the segment is a fresh trace). */
    if ((pb_diag() || pb_susp_diag()) && !susp_stack_.empty()) {
        fprintf(stderr, "[pathbuilder] SUSP-ORPHAN dropping %zu suspension(s) "
                "at segment open\n", susp_stack_.size());
    }
    g_stats.susp_orphan_dropped += susp_stack_.size();
    susp_stack_.clear();
    frames_.clear();
    pending_evs_.clear();
    clear_prev();
    walk_prev_ = nullptr;
    walk_depth_ = 0;
    prev_depth_ = 0;
    prev_owner_asid_ = 0;
    prev_owner_live_ = 0;
    /* Reg-snap hygiene at the window-mode segment boundary (Case C): drop any
     * pre-segment / opener snaps now, sync the generation stamp so the
     * step_events check doesn't redundantly re-clear, and arm the one-shot
     * follow-up — the opening block's OWN per-insn snaps are captured AFTER
     * this reset (its insns run once this callback returns) and must be
     * dropped before the first real block seals. */
    pending_reg_snaps.clear();
    seg_gen_seen_ = g_segment_generation.load(std::memory_order_relaxed);
    drop_open_leak_pending_ = true;
    depth_next_ = 0;
    raw_depth_ = 0;
    async_excluding_ = false;
    async_departure_pc_ = 0;
    async_captured_ = 0;
    async_owner_tid_ = CST_TID_UNSEEN;
    g_async_win_id = 0;
    g_async_win_enter_seq = 0;
    g_async_win_asidw = 0;
    g_async_win_own_stamps = 0;
    g_async_win_peer_stamps = 0;
    prev_in_sync_ = false;
    walk_in_sync_ = false;
    seal_pc_override_ = 0;
    /* Kernel-excursion ownership starts the segment unowned: the pin was
     * just captured at user privilege, so the first user TB re-seeds
     * last_user_asid_; kernel TBs before it have no owner and drop
     * (conservative, and a window of at most the marker's own tail). */
    kexc_reset();
    kexc_have_user_ = false;
    kexc_last_user_asid_ = 0;
    kexc_user_owned_ = false;
    /* Re-prime lazily at the next seal: a fault in flight across
     * segment-open is baselined out so the window starts at depth 0
     * rather than inheriting a pre-trace excursion. */
    primed_ = false;
    /* The emit-side trailer registers are shared with emit_body_entry;
     * zero them so nothing leaks into the new segment's first entry.  The
     * last-emitted-depth guard likewise resets so the new segment's first
     * unwind flush compares against a clean baseline, not a stale prior
     * segment's depth. */
    g_emit_fault_depth = 0;
    g_last_emit_fault_depth = 0;
    g_emit_fault_anchors.clear();
}

/*
 * Flush the pending final-TB body entry before a segment finishes (see
 * the declaration).  Walks the pending-seal slot's fragment list up to
 * the last-executed fragment (matched by the scoreboard's @prev_start),
 * same as the per-exec seal walk; no later CP step will fire after
 * shutdown, so this is the only chance to flush the trailing chain.
 * @walk_prev is false on the deferred window close, whose slot holds the
 * TB about to dispatch rather than one that has run (see the
 * declaration); the in-flight chain is finalized either way.
 */
void PathBuilder::flush_final(bool walk_prev)
{
    BodyStreamState *out_stream = g_trace_segments.body_stream();
    /* This builder's own vCPU (recorded at the lazy event-queue enable;
     * a builder that never stepped holds 0 and has no pending prev
     * anyway).  The scoreboard slots and the emitted entry's thread_id
     * must be THIS vCPU's — a hardcoded slot 0 read the wrong cursor
     * and mislabeled the segment's final entry whenever the closing
     * thread wasn't vCPU 0. */
    unsigned int cpu_index = cpu_index_;
    uint64_t prev_start =
        qemu_plugin_u64_get(g_scoreboard.prev_start_pc, cpu_index);

    std::vector<BBTemplate *> finalized;
    if (out_stream && prev_start != 0) {
        g_mutex_lock(&data_lock);
        for (BBTemplate *frag = walk_prev ? prev_tb_ : nullptr;
             frag != nullptr;
             frag = frag->next_tb_fragment) {
            bool is_last_executed = (frag->start_pc == prev_start);

            if (is_last_executed) {
                /* Tail-insn dst snap (see snap_prev_tail_dsts): the
                 * last-executed fragment's tail registers still hold
                 * post-exec values.  On a delay-slot tail [branch@n-2,
                 * delay@n-1] the branch's snap was deferred and there is
                 * no next TB to catch it (segment end), so capture both
                 * the branch (n-2) and the delay slot (n-1) here. */
                if (g_features.reg_data && frag->insn_reg_names &&
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

            g_cp_chain.append_fragment(frag->start_pc, frag,
                                       frag->fall_through_pc,
                                       (TbTerminus)frag->terminus);
            if (g_cp_chain.bb_complete() && g_cp_chain.has_active_chain()) {
                BBTemplate *bb_tmpl = g_cp_chain.finalize();
                g_cp_chain.reset();
                finalized.push_back(bb_tmpl);
            }

            if (is_last_executed) {
                break;
            }
        }
        /* The walk can end with the chain mid-BB and no sealing branch
         * ever coming — the segment is closing.  This is the pending
         * TB whose true BB a page boundary split (TB_TERMINUS_NONE
         * tail): its instructions are already counted in the window's
         * coverage (the per-TB inline-add ran at TB entry), so
         * discarding the chain here would break covered == emitted —
         * observed as the end-marker close dropping the workload's
         * final block whenever the END sequence completed inside the
         * first sub-TB of a page-straddling exit block.  Finalize the
         * partial BB as-is; like every entry this flush emits, its
         * terminal branch is simply unresolved. */
        if (g_cp_chain.has_active_chain()) {
            if (BBTemplate *bb_tmpl = g_cp_chain.finalize()) {
                finalized.push_back(bb_tmpl);
            }
        }
        g_mutex_unlock(&data_lock);
    }

    for (BBTemplate *bb_tmpl : finalized) {
        emit_body_entry(out_stream, bb_tmpl, cpu_index, {});
    }

    /* cp_chain and the CP memop buffer are thread_local; no lock. */
    g_cp_chain.reset();
    g_mem_recorder.clear_cp();

    qemu_plugin_u64_set(g_scoreboard.prev_start_pc, cpu_index, 0);
    qemu_plugin_u64_set(g_scoreboard.prev_fall_through, cpu_index, 0);
}

void path_builder_flush_final()
{
    path_builder_tls().flush_final();
}

void path_builder_flush_final_chain_only()
{
    path_builder_tls().flush_final(/* walk_prev= */ false);
}

/*
 * First seal of a segment (or of the builder's life): the priming swallow.
 * Events retained up to this point may predate the segment and reflect a
 * pre-trace excursion, so the caller discards the whole retained batch
 * (entries before the first surviving step of a segment never stash and
 * never count).  depth_next_ opens at 0; the pinned nesting depth then
 * accrues purely from frames_ (empty at segment open), so a fault in flight
 * across the boundary is baselined out for free.  raw_depth_ is sampled
 * from the live per-vCPU stack for the diagnostic only.
 */
void PathBuilder::prime_from_live()
{
    raw_depth_ = qemu_plugin_fault_depth();
    depth_next_ = 0;
    primed_ = true;
}

/*
 * ---- Kernel-excursion ownership (kexc=1) ----
 * The model and the full rule table live at the state declarations in
 * champsim_tracer_path_builder.h; these are its four arrows.
 */

/* Close any open excursion; the next kernel TB fires a fresh entry
 * edge.  last_user_asid_ deliberately survives (it is TB-history, not
 * excursion state). */
void PathBuilder::kexc_reset()
{
    kexc_in_kernel_ = false;
    kexc_have_overlay_ = false;
    kexc_overlay_ = 0;
    kexc_cut_ = false;
    kexc_restored_after_cut_ = false;
    kexc_nvals_ = 0;
    kexc_stormed_ = false;
}

/* One ASID_WRITE path event (@new_asid = the committed NEW value).
 * Applied exactly once, at the step that drained it, before any gate —
 * including steps the async window suspends: the window's TBs are
 * excluded regardless, but the ownership state must track the writes so
 * post-window attribution is right.  Only meaningful while an excursion
 * is open; a write draining outside one (e.g. the segment's very first
 * steps) has no owner to classify against and is consumed. */
void PathBuilder::kexc_apply_asid_write(uint64_t new_asid)
{
    g_stats.kexc_asid_writes++;
    if (!kexc_in_kernel_) {
        return;
    }

    /* Storm detection (detection only; pin-invalidation policy is a
     * later decision): distinct new-values this excursion. */
    if (!kexc_stormed_) {
        bool seen = false;
        for (uint32_t i = 0; i < kexc_nvals_; i++) {
            if (kexc_vals_[i] == new_asid) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            kexc_vals_[kexc_nvals_++] = new_asid;
            if (kexc_nvals_ >= KEXC_STORM_THRESHOLD) {
                kexc_stormed_ = true;
                g_stats.kexc_write_storm++;
                /* One stderr warning per segment (any thread). */
                static std::atomic<uint32_t> warned_gen{UINT32_MAX};
                uint32_t gen = g_segment_generation.load(
                    std::memory_order_relaxed);
                uint32_t prev = warned_gen.exchange(
                    gen, std::memory_order_relaxed);
                if (prev != gen) {
                    fprintf(stderr, "champsim_tracer: kexc: ASID-write "
                            "storm (>= %u distinct values in one kernel "
                            "excursion, entry ASID 0x%" PRIx64 ") — "
                            "possible ASID rollover; ownership stays "
                            "conservative (cut)\n",
                            KEXC_STORM_THRESHOLD, kexc_exc_entry_);
                }
            }
        }
    }

    if (new_asid == kexc_exc_entry_) {
        /* Restore: the address space the excursion was ENTERED from is
         * loaded again, so the excursion's own kernel work resumes here —
         * which means retiring a standing cut.  A cut records that the
         * address space MOVED to a third distinct value; once the entry
         * value is written back, that statement no longer describes the
         * machine, and leaving the flag set would refuse the entering
         * process's own post-switch-back kernel path all the way to its
         * next user TB.  Only the cut clears: the overlay is kept, so a
         * further third value cuts again, and kexc_entry_owned_ is not
         * touched — it was latched from kexc_user_owned_, which cannot
         * change while an excursion is open (kexc_user_tb closes one), so
         * re-latching it here would provably be a no-op. */
        g_stats.kexc_entry_restores++;
        if (kexc_cut_) {
            kexc_cut_ = false;
            g_stats.kexc_cut_retired_by_restore++;
            kexc_restored_after_cut_ = true;
            if (kexc_diag()) {
                fprintf(stderr, "[kexcdiag] RESTORE-AFTER-CUT entry=0x%"
                        PRIx64 " overlay=0x%" PRIx64 " owned=%d\n",
                        kexc_exc_entry_, kexc_overlay_,
                        (int)kexc_entry_owned_);
            }
        }
        return;                     /* restore; ownership continues */
    }
    if (!kexc_have_overlay_) {
        kexc_have_overlay_ = true;  /* the excursion's kernel overlay —
                                     * a PTI-style entry switch or a
                                     * TLB-maintenance save/probe; NOT a
                                     * committed switch */
        kexc_overlay_ = new_asid;
        g_stats.kexc_overlays++;
        return;
    }
    if (new_asid == kexc_overlay_) {
        return;
    }
    if (!kexc_cut_) {
        kexc_cut_ = true;           /* third distinct value = committed
                                     * context switch; sticky until the
                                     * next user TB */
        g_stats.kexc_cuts++;
    }
}

/* Every priv==0 TB: the excursion (if any) is over, live ASID is
 * authoritative again, and this address space is the owner of the next
 * kernel entry.  Foreign user TBs update ownership too — after a
 * committed switch, the next process's kernel work must charge to ITS
 * user ASID, not linger on the pin.  @owned is the step glue's
 * pin_user_tb_owned verdict: on narrow-ASID targets a raw value match
 * is not proof of identity (a rollover can hand the pinned value to a
 * foreign process), so the ownership seed carries the verified bit
 * rather than re-deriving it from ASID equality. */
void PathBuilder::kexc_user_tb(uint64_t live_asid, bool owned)
{
    kexc_reset();
    kexc_last_user_asid_ = live_asid;
    kexc_have_user_ = true;
    kexc_user_owned_ = owned;
}

/* Every non-suspended priv!=0 TB: latch the entry edge once at the
 * outermost user->kernel transition (nested faults inside an open
 * excursion never re-fire it — the single-edge model), then answer the
 * ownership question.  Replaces the live-ASID foreign-drop test for
 * kernel TBs only. */
bool PathBuilder::kexc_kernel_tb_keep(const StepIn &in)
{
    uint64_t start_pc = in.cur ? in.cur->start_pc : 0;
    uint32_t n_insns = in.cur ? in.cur->n_insns : 0;
    if (!kexc_in_kernel_) {
        kexc_reset();
        kexc_in_kernel_ = true;
        kexc_exc_entry_ = kexc_last_user_asid_;
        kexc_entry_owned_ = kexc_user_owned_;
    }
    /* @ours: the excursion was entered from a verified-owned user TB, so
     * every block of it belongs to the pinned process unless a committed
     * switch has since moved the address space elsewhere. */
    bool ours = kexc_have_user_ && kexc_entry_owned_;
    bool keep = ours && !kexc_cut_;
    if (keep) {
        g_stats.kexc_kernel_kept++;
        /* Post-restore recovery census: the blocks the restore arrow puts
         * back in the trace.  A cut is monotone within an excursion unless a
         * restore retires it, so a block admitted after one is exactly a
         * block a sticky cut would have refused.  Its own tripwire is the
         * live address space: the arrow may only re-admit blocks running
         * under the excursion's entry value, or under the kernel overlay the
         * excursion already accepted as benign (an idle / kthread borrow) —
         * anything else would be foreign work entering the trace. */
        if (kexc_restored_after_cut_) {
            g_stats.kexc_post_restore_kept_tbs++;
            g_stats.kexc_post_restore_kept_insns += n_insns;
            bool own_space = in.live_asid == kexc_exc_entry_ ||
                             (kexc_have_overlay_ &&
                              in.live_asid == kexc_overlay_);
            if (!own_space) {
                g_stats.kexc_post_restore_kept_foreign_live++;
            }
            if (kexc_diag() &&
                (!own_space ||
                 kexc_pc_first_sighting("recovered", start_pc))) {
                fprintf(stderr, "[kexcdiag] RECOVERED%s pc=0x%" PRIx64
                        " ninsns=%u entry=0x%" PRIx64 " overlay=0x%" PRIx64
                        " live=0x%" PRIx64 " pin=0x%" PRIx64 "\n",
                        own_space ? "" : "/OFF-SPACE", start_pc, n_insns,
                        kexc_exc_entry_, kexc_overlay_, in.live_asid,
                        in.pinned_asid);
            }
        }
    } else {
        g_stats.kexc_kernel_dropped++;
        /* Decline-reason census.  Exactly one arm fires per refused block. */
        if (!kexc_have_user_) {
            g_stats.kexc_decl_no_user++;
        } else if (!kexc_entry_owned_) {
            g_stats.kexc_decl_not_owned++;
            /* The excursion was latched to a foreign entry, yet the address
             * space in force is the pinned one: a re-entry with no
             * intervening user TB.  A separate attribution question from the
             * cut; recorded, not adjudicated. */
            if (in.live_asid == in.pinned_asid) {
                g_stats.kexc_decl_not_owned_live_pinned++;
            }
        } else {
            g_stats.kexc_decl_cut++;
            /* THE TRIPWIRE.  A cut asserts the address space moved away; the
             * live register says it is the excursion's own entry value.  Both
             * cannot hold, so a non-zero count is a cut outliving the switch
             * it describes — the sticky-cut defect. */
            if (in.live_asid == kexc_exc_entry_) {
                g_stats.kexc_cut_declined_at_entry_asid++;
                if (kexc_diag() &&
                    kexc_pc_first_sighting("stalecut", start_pc)) {
                    fprintf(stderr, "[kexcdiag] STALE-CUT-DECLINE pc=0x%"
                            PRIx64 " ninsns=%u entry=0x%" PRIx64
                            " overlay=0x%" PRIx64 " restored=%d\n",
                            start_pc, n_insns, kexc_exc_entry_,
                            kexc_overlay_, (int)kexc_restored_after_cut_);
                }
            }
        }
    }
    return keep;
}

/* Frame lookup by the FAULT event's identity: resume PC plus the ASID
 * stamped at the event instant.  Both the frame's ENTER and a later
 * re-fault/return of the same instruction are stamped while the faulting
 * process is current, so the pair matches exactly — a handler rewriting the MMU context
 * register mid-excursion cannot drift the key at match time.  Top-down so nesting (LIFO position) is respected when
 * duplicate resume PCs exist. */
ptrdiff_t PathBuilder::frame_idx_for_resume(uint64_t resume_pc,
                                            uint64_t asid) const
{
    for (size_t i = frames_.size(); i-- > 0; ) {
        if (frames_[i].resume_pc == resume_pc && frames_[i].asid == asid) {
            return (ptrdiff_t)i;
        }
    }
    return -1;
}

/* Frame lookup by block identity: the frame whose stashed full template
 * CONTAINS the faulting TB (@piece is a byte-identical subrun of
 * full_tmpl) and covers @resume.  This is the join key for a SECOND
 * fault inside an already-pending block: the resume suffix re-executing
 * after the first fault is a subrun of the frame's own template, so a
 * fresh fault it takes on a LATER instruction belongs to the same
 * pending block — not to a new frame keyed at the suffix's start, which
 * would drop every instruction ahead of the first resume from the
 * merged emission.  Same ASID and byte-content guards as the resume
 * match; top-down so nesting is respected. */
ptrdiff_t PathBuilder::frame_idx_for_block(const BBTemplate *piece,
                                           uint64_t resume,
                                           uint64_t asid) const
{
    for (size_t i = frames_.size(); i-- > 0; ) {
        const CtxFrame &f = frames_[i];
        if (f.asid == asid &&
            tmpl_contains_pc(f.full_tmpl, resume) &&
            tmpl_subrun_pos(f.full_tmpl, piece) != UINT32_MAX) {
            return (ptrdiff_t)i;
        }
    }
    return -1;
}

/*
 * Completion candidate for a just-sealed BB claiming to be some frame's
 * resume suffix.  Keyed on the completing seal's (thread,asid): the thread
 * is implicit (PathBuilder is per-vCPU-thread TLS), and @seal_asid — the
 * pinned process's effective asid at the seal (StepIn::pinned_asid) — is the
 * second half of the key.
 *
 * USER frames match on the hard key (f.asid == seal_asid).  That makes the
 * cross-ASID swallow the byte guard was added to catch (a same-VA frame from
 * ANOTHER process consuming an innocent seal, e.g. resume 0x4003f0 — owned
 * processes all map code at the same low VAs) IMPOSSIBLE BY CONSTRUCTION,
 * and a user fault's event stamp is reliably the faulting process's own
 * asid, so the key never misses a genuine completion.  merge_suffix_matches
 * is demoted to a pure diagnostic on this arm (Decision C).
 *
 * KERNEL-code frames (full_tmpl->is_system, CP-authoritative) additionally
 * complete on the byte-content path when the asid key misses: a kernel
 * fault's event stamp is whatever mm is loaded at the fault instant — under
 * multi-process churn routinely another task's (live ASID is not ownership
 * for kernel code; the reason kexc ownership exists) — so the hard key alone
 * strands the pinned process's own kernel-handler frames un-completable,
 * leaving stale frames to perturb the fault-storm interleave.  The content
 * guard is not process-ambiguous here the way it is for user VAs: kernel
 * text is one shared image, frames_ only ever holds the pinned process's
 * excursions (a foreign TB's prev is dropped before classification can
 * stash one), and the completing suffix is a kexc-kept kernel block of the
 * pinned process.  The stamp drift is reported as a diagnostic.
 *
 * Preferred match: a frame whose FAULT_RETURN was already observed (event
 * identity).  Fallback: QEMU's fault-stack pop is strict LIFO, so a non-LIFO
 * guest exception return — a context switch inside a blocking fault resuming
 * the OUTER task first — produces NO FAULT_RETURN event even though the
 * suffix genuinely resumes; complete those on the same keys.
 */
bool PathBuilder::frame_matches_completion(const CtxFrame &f,
                                           const BBTemplate *suffix,
                                           uint64_t seal_asid)
{
    if (f.resume_pc != suffix->start_pc) {
        return false;
    }
    if (f.asid == seal_asid) {
        /* Byte guard demoted to a pure diagnostic on the asid-keyed arm:
         * a mismatch here is a bug to REPORT (self-modified code, a decode
         * drift), not a reason to reject a same-address-space completion. */
        if (pb_diag() && !merge_suffix_matches(f.full_tmpl, suffix)) {
            fprintf(stderr, "[pathbuilder] DIAG completion byte mismatch "
                    "(non-behavioral; asid-keyed): frame full=0x%" PRIx64
                    " resume=0x%" PRIx64 " asid=0x%" PRIx64 " vs suffix=0x%"
                    PRIx64 "\n",
                    f.full_tmpl ? f.full_tmpl->start_pc : 0,
                    f.resume_pc, f.asid, suffix->start_pc);
        }
        return true;
    }
    if (f.full_tmpl && f.full_tmpl->is_system &&
        merge_suffix_matches(f.full_tmpl, suffix)) {
        if (pb_diag()) {
            fprintf(stderr, "[pathbuilder] DIAG kernel-frame completion via "
                    "content (asid stamp drift): frame full=0x%" PRIx64
                    " resume=0x%" PRIx64 " asid=0x%" PRIx64 " vs seal asid=0x%"
                    PRIx64 "\n",
                    f.full_tmpl->start_pc, f.resume_pc, f.asid, seal_asid);
        }
        return true;
    }
    return false;
}

ptrdiff_t PathBuilder::frame_idx_for_completion(const BBTemplate *suffix,
                                                uint64_t seal_asid) const
{
    if (!suffix) {
        return -1;
    }
    for (size_t i = frames_.size(); i-- > 0; ) {
        const CtxFrame &f = frames_[i];
        if (f.returned && frame_matches_completion(f, suffix, seal_asid)) {
            return (ptrdiff_t)i;
        }
    }
    for (size_t i = frames_.size(); i-- > 0; ) {
        const CtxFrame &f = frames_[i];
        if (frame_matches_completion(f, suffix, seal_asid)) {
            return (ptrdiff_t)i;
        }
    }
    return -1;
}

/* Move the deferred prev's committed accumulators into @f (the handler's
 * subsequent memops then land in fresh buffers), and record the faulting
 * instruction's index — once, even when the same insn faults repeatedly
 * (TLB refill then demand fault is ONE faulting instruction). */
void PathBuilder::collect_piece(CtxFrame &f, uint64_t resume_pc)
{
    std::vector<WPMemAccess> piece_mem;
    g_mem_recorder.take_cp(piece_mem);
    f.mem.insert(f.mem.end(), piece_mem.begin(), piece_mem.end());
    if (!pending_reg_snaps.empty()) {
        f.snaps.insert(f.snaps.end(), pending_reg_snaps.begin(),
                       pending_reg_snaps.end());
        pending_reg_snaps.clear();
    }
    if (f.full_tmpl && f.full_tmpl->insn_pcs) {
        for (uint32_t i = 0; i < f.full_tmpl->n_insns; i++) {
            if (f.full_tmpl->insn_pcs[i] == resume_pc) {
                if (std::find(f.anchors.begin(), f.anchors.end(), i) ==
                    f.anchors.end()) {
                    f.anchors.push_back(i);
                }
                break;
            }
        }
    }
    f.resume_pc = resume_pc;
    if (pb_diag()) {
        fprintf(stderr, "[pathbuilder] STASH full=0x%" PRIx64 " resume=0x%"
                PRIx64 " depth=%u nsnaps=%zu nmem=%zu nanchor=%zu frames=%zu\n",
                f.full_tmpl ? f.full_tmpl->start_pc : 0, resume_pc, f.depth,
                f.snaps.size(),
                f.mem.size(), f.anchors.size(), frames_.size());
    }
}

/*
 * Case (b) fold: serialise the faulting prev into a decoder-visible
 * true-BB template.  Drop any in-flight chain prefix (case (b) destroys,
 * it does not suspend — earlier TBs of a multi-TB true BB vanish from
 * the merged template while their memops ride along in the stash), fold
 * prev's HEAD fragment, and if the head has no terminating branch force-commit
 * the incomplete chain so the emit references a template the decoder
 * will actually see.
 */
BBTemplate *PathBuilder::fold_prev_full_bb(BBTemplate *prev)
{
    g_mutex_lock(&data_lock);
    g_cp_chain.reset();
    g_cp_chain.append_fragment(prev->start_pc, prev, prev->fall_through_pc,
                               (TbTerminus)prev->terminus);
    BBTemplate *full_bb = nullptr;
    if (g_cp_chain.bb_complete() && g_cp_chain.has_active_chain()) {
        full_bb = g_cp_chain.finalize();
        g_cp_chain.reset();
    }
    bool fell_back = false;
    if (!full_bb) {
        full_bb = g_cp_chain.finalize();   /* force-commit incomplete head */
        fell_back = true;
        if (!full_bb) {
            full_bb = prev;                /* empty-chain guard */
        }
    }
    g_cp_chain.reset();
    if (pb_diag()) {
        fprintf(stderr, "[pathbuilder] PUSH prev=0x%" PRIx64 " n=%u term=%d "
                "-> full=0x%" PRIx64 " n=%u incomplete=%d tid=%u\n",
                prev->start_pc, prev->n_insns, (int)prev->terminus,
                full_bb->start_pc, full_bb->n_insns, (int)fell_back,
                full_bb->template_id);
    }
    g_mutex_unlock(&data_lock);
    return full_bb;
}

/*
 * One FAULT_ENTER: QEMU reports the faulting instruction as the event's
 * pc (where the handler's exception-return lands).  Three cases, told
 * apart by where that resume PC lives:
 *
 *  (a) an in-flight frame's resume PC — the same instruction re-faulted;
 *      append the new prefix piece to that frame.  The content guard on
 *      the deferred prev stays a MATCHER, not an assertion: a resume
 *      suffix that fetch-faults before its exec callback leaves prev
 *      pointing at the handler's last TB, whose committed memops belong
 *      to the handler and must NOT be absorbed into the frame — the
 *      guard demotes exactly that case to (c).
 *
 *  (a2) a LATER instruction of an already-pending block — the frame's
 *      resume suffix (walk_prev_, a byte-identical subrun of some
 *      frame's full template) took a fresh fault at a NEW resume PC
 *      still inside that template (the aarch64 archetype: the ldr's
 *      demand-zero fault, then the str's CoW fault, in one BB).  The
 *      new fault JOINS the frame: the suffix's committed pieces and the
 *      new anchor accumulate, and the frame re-keys to the new resume
 *      PC so the eventual completion matches the final suffix.  Without
 *      the join, case (b) would mint a second frame keyed at the FIRST
 *      resume PC — the merged emission would start there, silently
 *      dropping every instruction ahead of it, and the original frame
 *      would leak.
 *
 *  (b) inside the deferred prev — prev IS the faulting BB and its
 *      terminating branch never ran; fold it into a serialisable
 *      template and push a fresh frame.
 *
 *  (c) neither — prev did not fault (an instruction-fetch miss on a
 *      block whose exec callback never ran); consume the event with no
 *      action so prev seals normally.
 *
 * Handling each drained ENTER individually (instead of the tracker's
 * collapse to the LAST entry per step) is one of the two sanctioned
 * improvements: under a dense storm the outer user fault's case-(b)
 * stash is no longer lost behind a nested handler fault's entry.
 */
void PathBuilder::classify_fault_enter(const struct qemu_plugin_cpu_event &ev,
                                       bool *prev_stashed, uint32_t owner_tid)
{
    /* Gated on a non-null deferred prev: post-drop or post-boundary
     * entries are consumed with no action. */
    if (!walk_prev_) {
        return;
    }
    const uint64_t resume = ev.pc;
    ptrdiff_t cont = frame_idx_for_resume(resume, ev.asid);
    if (cont >= 0 &&
        tmpl_subrun_pos(frames_[(size_t)cont].full_tmpl, walk_prev_)
            == UINT32_MAX) {
        cont = -1;
    }
    if (cont < 0) {                                        /* case (a2) */
        /* Same guards as (a) minus the resume-PC identity: the faulting
         * TB must be a byte-identical subrun of the frame's template
         * and the NEW resume PC must lie inside it (a suffix extending
         * past a force-committed head keeps the old (b) path, so the
         * frame key never leaves its template).  collect_piece re-keys
         * the frame and records the new anchor. */
        cont = frame_idx_for_block(walk_prev_, resume, ev.asid);
    }
    if (cont >= 0) {                                  /* case (a) / (a2) */
        g_mutex_lock(&data_lock);
        g_cp_chain.reset();
        g_mutex_unlock(&data_lock);
        cst_jump_diag_step(resume, walk_prev_->start_pc, (int)ev.priv, 1,
                           "fault-enter(a)");
        collect_piece(frames_[(size_t)cont], resume);
        frames_[(size_t)cont].returned = false;   /* back in flight */
        *prev_stashed = true;
        return;
    }
    if (!*prev_stashed && tmpl_contains_pc(walk_prev_, resume)) { /* (b) */
        BBTemplate *full_bb = fold_prev_full_bb(walk_prev_);
        frames_.emplace_back();
        CtxFrame &f = frames_.back();
        f.full_tmpl = full_bb;
        f.asid = ev.asid;
        /* The depth the faulting BB ran at: prev's promote-time stamp
         * (NOT this event's depth_after, which is post-entry). */
        f.depth = walk_depth_;
        /* The excursion belongs to the thread that ran the faulting BB —
         * @owner_tid is exactly the identity that block is emitted with, so
         * the frame and its interrupted block agree by construction.  This is
         * what keeps a peer thread scheduled onto this vCPU during the
         * excursion at its OWN nesting depth. */
        f.tid = owner_tid;
        cst_jump_diag_step(resume, walk_prev_->start_pc, (int)ev.priv, 1,
                           "fault-enter(b)");
        collect_piece(f, resume);
        *prev_stashed = true;
        return;
    }
    /* case (c): consumed, no action. */
}

/* One FAULT_RETURN: the handler's exception return landed back on a
 * faulting instruction.  Mark the matching frame returnable — emission
 * still rides the resume suffix's SEAL, one or more TB steps later.
 * Returns for faults that never stashed (case (c), pre-prime, foreign)
 * match no frame and are consumed silently. */
void PathBuilder::apply_fault_return(const struct qemu_plugin_cpu_event &ev)
{
    ptrdiff_t idx = frame_idx_for_resume(ev.pc, ev.asid);
    if (idx >= 0) {
        frames_[(size_t)idx].returned = true;
    }
    cst_jump_diag_step(ev.pc, 0, (int)ev.priv, (int)(idx >= 0),
                       idx >= 0 ? "fault-return" : "fault-return/nomatch");
    if (pb_diag()) {
        fprintf(stderr, "[pathbuilder] RET resume=0x%" PRIx64 " depth=%u "
                "frame=%td\n", ev.pc, ev.depth_after, idx);
    }
}

PathBuilder::StepStatus PathBuilder::step_events(const StepIn &in)
{
    /* The seal-successor override is strictly one-step state: a
     * recovery step always survives to its own seal (recovery implies
     * pinned-user, which passes the foreign-ASID gate), and any
     * harder bail between the phases also drops the walk prev the
     * override was meant for. */
    seal_pc_override_ = 0;

    /* One-step hold-off for the resume arrow (Stage 4).  The abandoned-async
     * no-departure arm suspends the deferred prev and then FALLS THROUGH to
     * the promote (unlike the foreign-ASID arrow, which returns early).  If
     * the resume arrow ran on this same step it would immediately re-arm and
     * seal that just-suspended prev against cur — but the abandoned window
     * means cur is the OTHER guest thread the scheduler handed this vCPU
     * (a proper resume would have refetched the departure PC), not prev's
     * successor, so that seal is the cross-thread taken-edge poisoning the
     * departure-PC override exists to prevent.  Holding the resume off this
     * one step lets cur promote fresh and defers the suspended prev to its
     * TRUE successor's later resume (or the retire-at-return backstop).  Only
     * the abandoned arm sets it; off the async-recovery path it stays false
     * and the resume arrow is unchanged (byte-identical). */
    bool hold_resume_this_step = false;

    /* Segment-boundary reg-snap hygiene (Case C).  A change in the segment
     * generation since this thread's last step means the segment just opened
     * under it.  In marker mode the opener's own vcpu_tb_exec is JIT-gated
     * off before the START marker fires, so on_segment_open never runs and
     * THIS is the first dispatch after the open — with the marker block's
     * post-open per-insn snaps (the 0x43535401 magic write among them) still
     * pooled in pending_reg_snaps.  Drop them so the segment's first real
     * block starts positionally clean.  In window mode on_segment_open ran
     * last step and armed the one-shot follow-up so the opener block's own
     * post-open leak is dropped the step after. */
    uint32_t cur_gen = g_segment_generation.load(std::memory_order_relaxed);
    if (seg_gen_seen_ != cur_gen) {
        seg_gen_seen_ = cur_gen;
        drop_open_leak_pending_ = false;
        pending_reg_snaps.clear();
    } else if (drop_open_leak_pending_) {
        drop_open_leak_pending_ = false;
        pending_reg_snaps.clear();
    }

    /* Retain this step's drain: the queue's internal buffer is only
     * valid until the next push, and fault events may have to survive
     * bailed steps until a seal consumes them. */
    if (in.n_evs) {
        pending_evs_.insert(pending_evs_.end(), in.evs, in.evs + in.n_evs);
    }

    /* Kernel-excursion ownership: apply this step's FRESH drain of
     * ASID_WRITE events exactly once, before any gate — the retained-
     * event rescans below must never see them twice, and a step the
     * async window suspends (or any later gate bails) still updates
     * ownership so post-window state is right.  The event's asid field
     * carries the committed NEW value for this kind.  With kexc off the
     * events are consumed-and-ignored (the async and fault scans below
     * skip kind 4 by construction), keeping legacy behavior
     * byte-for-byte. */
    if (g_features.kexc && in.pinned) {
        for (size_t i = 0; i < in.n_evs; i++) {
            if (in.evs[i].kind == QEMU_PLUGIN_CPU_EV_ASID_WRITE) {
                kexc_apply_asid_write(in.evs[i].asid);
            }
        }
    }

    /* Captured-async OWNERSHIP, from this step's FRESH drain — each event seen
     * exactly once, like the kexc pass above and unlike the retained-event
     * rescan below, which deliberately replays.  The level a window
     * contributes belongs to the thread the interrupt was DELIVERED in
     * (format.rst §4.2a), and only this pass runs in that thread's step: the
     * rescan would re-derive the owner from whatever context is running when
     * the step finally survives a gate, which in the foreign-delivery case is
     * the pinned process — precisely the misattribution being fixed.
     *
     * Recording ownership here rather than at the first seal is load-bearing
     * for the same reason.  An interrupt delivered in a foreign address space
     * runs its handler on dropped/suspended TBs; no seal happens until the
     * handler reschedules the pinned process, so a seal-time capture would
     * name the pinned thread as the owner and reproduce the bug verbatim.
     *
     * in.cur_tid is the glue's read-only PEEK here (see StepIn): a thread
     * whose pointer the identity map has not minted yet resolves to
     * CST_TID_UNSEEN, which async_level() can never match, so an
     * unattributable level stays dormant instead of being borrowed. */
    if (g_features.trace_interrupts) {
        for (size_t i = 0; i < in.n_evs; i++) {
            const struct qemu_plugin_cpu_event &ev = in.evs[i];
            if (ev.kind == QEMU_PLUGIN_CPU_EV_ASYNC_ENTER) {
                if (g_async_win_id) {
                    g_stats.async_captures_reopened++;
                    async_win_close("REOPEN", in.cur_tid);
                }
                async_owner_tid_ = in.cur_tid;
                g_async_win_id = ++g_async_win_seq;
                g_async_win_enter_seq = g_dbg_last_emit_seq;
                g_stats.async_captures++;
                if (in.cur_tid == CST_TID_UNSEEN) {
                    g_stats.async_capture_owner_unseen++;
                }
                if (pb_async_diag()) {
                    fprintf(stderr, "[asyncdiag] ENTER win=%" PRIu64
                            " pc=0x%" PRIx64 " tid=%u priv=%d asid=0x%" PRIx64
                            " seq=%" PRIu64 " pinned=%d primed=%d\n",
                            g_async_win_id, ev.pc, in.cur_tid, (int)ev.priv,
                            ev.asid, g_dbg_last_emit_seq, (int)in.pinned,
                            (int)primed_);
                }
            } else if (ev.kind == QEMU_PLUGIN_CPU_EV_ASYNC_RETURN) {
                if (g_async_win_id) {
                    g_stats.async_closed_by_return++;
                    if (in.cur_tid != async_owner_tid_) {
                        /* The producer's test is a bare PC equality on a
                         * per-vCPU departure PC (accel/tcg/cpu-exec.c), with
                         * no thread and no address-space check, so a peer
                         * executing the same VA can close the window early.
                         * Counted, not suppressed: the window's LIFETIME is
                         * QEMU's per-vCPU state and the plugin must not
                         * desynchronise from it — a nonzero count here is an
                         * upstream defect to report, not one to paper over. */
                        g_stats.async_return_peer_ctx++;
                    }
                    async_win_close("RETURN", in.cur_tid);
                }
                async_owner_tid_ = CST_TID_UNSEEN;
                if (pb_async_diag()) {
                    fprintf(stderr, "[asyncdiag] RETURN pc=0x%" PRIx64
                            " tid=%u priv=%d seq=%" PRIu64 "\n",
                            ev.pc, in.cur_tid, (int)ev.priv,
                            g_dbg_last_emit_seq);
                }
            } else if (ev.kind == QEMU_PLUGIN_CPU_EV_ASID_WRITE &&
                       g_async_win_id) {
                /* Measurement only.  An address-space switch inside an open
                 * window says nothing about the level's ownership: the
                 * capture context routinely leaves and comes back before the
                 * window closes, and a same-mm thread switch commits no such
                 * event at all. */
                g_async_win_asidw++;
                g_stats.async_asid_write_in_window++;
                if (pb_async_diag()) {
                    fprintf(stderr, "[asyncdiag] ASIDW win=%" PRIu64
                            " new_asid=0x%" PRIx64 " priv=%d seq=%" PRIu64
                            " owner=%u cur_tid=%u\n",
                            g_async_win_id, ev.asid, (int)ev.priv,
                            g_dbg_last_emit_seq, async_owner_tid_,
                            in.cur_tid);
                }
            }
        }
    }

    /* Async mute window.  Until the first seal-phase prime the live flag
     * is authoritative (it already reflects every retained event); after
     * that the ordered edges drive it.  Assignment semantics make the
     * rescan of retained events across a bailed step idempotent.  An
     * ASYNC_RETURN drained this step unmutes the resume TB's body
     * callbacks (the event precedes the resume TB's execution). */
    bool async_enter_this_batch = false;
    if (!primed_) {
        /* interrupts=1 never mutes; a pre-prime window carries no departure
         * PC, so it is neither muted nor captured — the segment just opened at
         * a clean user marker and the first well-formed ASYNC_ENTER after the
         * prime drives the capture. */
        async_excluding_ = qemu_plugin_in_async_int() &&
                           !g_features.trace_interrupts;
        async_departure_pc_ = 0;    /* pre-prime windows carry no pc */
        async_captured_ = 0;
        /* Nothing is owed before the prime, so no owner is owed either (the
         * fresh pass above may have just recorded one for a pre-prime ENTER
         * that step_seal's priming swallow will discard). */
        if (g_async_win_id) {
            async_owner_tid_ = CST_TID_UNSEEN;
            async_win_close("PREPRIME", in.cur_tid);
        }
    } else {
        for (const struct qemu_plugin_cpu_event &ev : pending_evs_) {
            if (ev.kind == QEMU_PLUGIN_CPU_EV_ASYNC_ENTER) {
                if (g_features.trace_interrupts) {
                    /* Capture: contribute one depth level and remember the
                     * batch opened a window, so the interrupted prev seals
                     * against the departure PC below. */
                    async_captured_ = 1;
                    async_enter_this_batch = true;
                } else {
                    async_excluding_ = true;
                }
                async_departure_pc_ = ev.pc;
            } else if (ev.kind == QEMU_PLUGIN_CPU_EV_ASYNC_RETURN) {
                if (g_features.trace_interrupts) {
                    async_captured_ = 0;
                } else {
                    async_excluding_ = false;
                }
                async_departure_pc_ = 0;
            }
            /* ASID_WRITE (kind 4) is window-neutral: consumed by the
             * kexc ownership pass at drain time above, explicitly
             * ignored here on the legacy (kexc=0) rule. */
        }
    }
    g_capture_mute = async_excluding_;

    /* interrupts=1: a freshly-opened capture window means the deferred prev is
     * the interrupted block and cur is the handler entry.  Seal prev against
     * the async departure PC — where the interrupted flow architecturally
     * resumes — so no phantom edge runs through the handler entry (the same
     * successor substitution the abandoned-window recovery makes).  Only on
     * the batch that opened the window; subsequent handler steps seal against
     * each other normally, and the handler's tail seals against the resume TB
     * (which re-executes the departure PC). */
    if (g_features.trace_interrupts && async_enter_this_batch &&
        async_departure_pc_) {
        seal_pc_override_ = async_departure_pc_;
    }

    if (async_excluding_) {
        if (in.pinned && in.user_owned) {
            /* Stuck-window recovery: the pinned process at user privilege
             * is definitionally not handler content, so force-close an
             * abandoned window here.  The reset produces NO ASYNC_RETURN
             * event (the departure PC may never be hit again), so the
             * window is closed locally too; a later fresh ASYNC_ENTER
             * opens a well-formed new window.
             *
             * An abandoned window is precisely a guest-thread switch the
             * exclusion hid: a proper resume refetches the departure PC
             * (closing the window with an ASYNC_RETURN before this TB
             * dispatches), so reaching here means the scheduler handed
             * this vCPU to ANOTHER thread of the pinned process (or a
             * signal rewrote the resume point).  The TB executing now is
             * therefore NOT the deferred prev's successor, and sealing
             * prev against it would fabricate a cross-thread taken edge —
             * observed as a loop branch whose profile targets the other
             * thread's resume PC (and, through the template's last-write
             * taken_pc, relabels every prior taken count with it).  Seal
             * prev against the window's departure PC instead: that is
             * where the interrupted flow architecturally continues, making
             * this seal identical to the one a proper resume would have
             * produced.  When no departure PC is known (window predates
             * the segment prime), that seal target is unavailable, so
             * prev is suspended like the foreign-ASID boundary suspends
             * it (below). */
            qemu_plugin_async_int_reset();
            async_excluding_ = false;
            g_capture_mute = false;
            if (async_departure_pc_) {
                seal_pc_override_ = async_departure_pc_;
                async_departure_pc_ = 0;
            } else if (prev_tb_) {
                /* SUSPEND-OR-SEAL, abandoned-async arrow (plan §1.2,
                 * Stage 4).  Freeze the deferred prev + its four sinks
                 * onto the suspension stack, so an inner fault-handler
                 * level interrupted by an abandoned window seals at ITS
                 * OWN depth when the pinned context returns, rather than
                 * being lost.  The abandoned arm falls THROUGH to promote
                 * cur (the force-closed window's block, which the
                 * recovery keeps traced — g_capture_mute stayed false),
                 * so the resume arrow is held off this one step
                 * (hold_resume_this_step): cur is the other thread, not
                 * prev's successor, and an immediate resume would seal
                 * prev against it — exactly the cross-thread taken edge
                 * the departure-PC seal exists to avoid.  The suspension
                 * defers to prev's true later resume, or to the
                 * retire-at-return backstop if it never returns. */
                suspend_prev(prev_owner_asid_, prev_owner_live_,
                             in.cpu_index);
                g_stats.susp_abandoned++;
                clear_prev();
                hold_resume_this_step = true;
                if (pb_diag() || pb_susp_diag()) {
                    fprintf(stderr, "[pathbuilder] ABANDONED-SUSPEND "
                            "cur=0x%" PRIx64 " (no departure pc; prev "
                            "deferred to later resume)\n",
                            in.cur ? in.cur->start_pc : 0);
                }
            }
            if (pb_diag()) {
                fprintf(stderr, "[pathbuilder] ABANDONED-WINDOW recovery "
                        "prev=0x%" PRIx64 " cur=0x%" PRIx64 " seal_pc=0x%"
                        PRIx64 "\n",
                        prev_tb_ ? prev_tb_->start_pc : 0,
                        in.cur ? in.cur->start_pc : 0, seal_pc_override_);
            }
        } else {
            /* Suspend: the handler (and anything it context-switches
             * through, foreign address spaces included) never appears in
             * the trace.  Critically prev is untouched, so the resume TB
             * seals the interrupted branch against its REAL target.
             * Runs BEFORE the foreign-ASID arrow and BEFORE window
             * management — that order is load-bearing: an async excursion
             * routinely context-switches through OTHER address spaces,
             * and those TBs must take THIS bail (which preserves the
             * deferred prev for the resume), not the ASID drop. */
            return StepStatus::SUSPENDED;
        }
    }

    /* Foreign-ASID boundary (non-async; the async case bailed above,
     * preserving prev).  With kexc on, kernel (priv!=0) TBs are gated by
     * the excursion-ownership rule INSTEAD of the live ASID — the live
     * register is not trustworthy inside the kernel (PTI entry
     * switches, TLB-maintenance save/probe writes) — while user
     * (priv==0) TBs keep the live-ASID rule verbatim, additionally
     * driving the ownership edges (reset + owner tracking).  Suspended
     * TBs never reach this point, so excluded async-window content
     * drives no ownership edge. */
    if (in.pinned) {
        bool drop;
        if (in.live_priv > 0 && in.live_priv == g_xlate_bypass_priv) {
            /* Translation-bypassing privilege level (RISC-V M-mode; see
             * g_xlate_bypass_priv in champsim_tracer.cc).  Execution here
             * never translates through the pinned register — the live
             * satp is a stale bystander, and matching it (or owning the
             * excursion under kexc) says nothing about whose work this
             * is.  It is firmware above the OS kernel, not the pinned
             * process's kernel work, so it drops on BOTH attribution
             * rules.  Deliberately ahead of the kexc arrows: a dropped
             * M-mode TB neither opens nor cuts an excursion, so an
             * S-mode excursion interrupted by a sync SBI call resumes
             * with its ownership intact. */
            g_stats.kexc_mmode_dropped++;
            drop = true;
        } else if (!g_features.kexc) {
            drop = in.live_priv == 0 ? !in.user_owned
                                     : in.live_asid != in.pinned_asid;
        } else if (in.live_priv == 0) {
            kexc_user_tb(in.live_asid, in.user_owned);
            drop = !in.user_owned;
        } else {
            drop = !kexc_kernel_tb_keep(in);
        }
        if (drop) {
            /* SUSPEND-OR-SEAL (plan §1.2).  Freeze the deferred prev + its
             * four sinks onto the suspension stack instead of dropping
             * them, so the pinned process's resume seals the interrupted
             * (fault-handler) block at ITS OWN DEPTH — closing the
             * syscall_fault_nesting manifestations where the intermediate
             * level was lost to a DROP (2->1->0 / 0->1->2 instead of 2->0 /
             * 0->2).  Do NOT retire-at-return here: the frame stays in flight
             * and completes normally when the suspension resumes; the
             * retire-at-return backstop covers only the un-resumable tail
             * (displacement / orphan / stale sweep).  When prev is null there
             * is nothing to suspend (a second foreign TB in the same span,
             * prev already cleared) — just clear the accumulators.  Mute the
             * foreign TB's accesses either way (the step recomputes
             * g_capture_mute at every dispatch, so the mute self-clears with
             * the span). */
            if (prev_tb_) {
                suspend_prev(prev_owner_asid_, prev_owner_live_, in.cpu_index);
            } else {
                g_mem_recorder.clear_cp();
                pending_reg_snaps.clear();
            }
            g_capture_mute = true;
            clear_prev();
            return StepStatus::SUSPENDED_FOREIGN;
        }
    }

    /* Resume arrow (plan §1.3): the pinned process is back at an owned,
     * non-excluded TB (every gate above passed, so this step will CONTINUE).
     * Pop the suspension whose (asid, live) matches this resuming context —
     * restoring the deferred prev + its four frozen sinks — so the promote
     * below walks the SUSPENDED prev and the seal emits the intermediate
     * handler level at its own depth.  Off the contention path the stack is
     * empty and this is a no-op (byte-identical).
     *
     * hold_resume_this_step suppresses the pop for the one step where the
     * abandoned-async arrow just suspended prev and fell through (Stage 4):
     * cur is the force-closed window's OTHER thread, so resuming prev against
     * it here would fabricate the cross-thread edge the arm suspended to
     * avoid — the suspension waits for prev's true successor instead. */
    if (!susp_stack_.empty() && !hold_resume_this_step) {
        resume_suspension(in.pinned_asid, in.live_asid);
    }

    /* Promote: cur becomes the pending seal; the seal phase walks the
     * OLD prev with the depth stamped when it executed.  Cur's own stamp
     * is written by the seal phase after the fault events apply (on a
     * step bailing between the phases the stamp stays stale until the
     * next surviving seal). */
    walk_prev_ = prev_tb_;
    walk_depth_ = prev_depth_;
    g_dbg_walk_depth = walk_depth_;
    g_dbg_walk_depth_src = g_dbg_prev_depth_src;
    walk_in_sync_ = prev_in_sync_;
    set_prev(in.cur);
    /* Record cur's owning (thread,asid) so a later foreign span that
     * suspends this now-deferred prev freezes the RIGHT owner (Stage 3): the
     * pinned effective asid is the frame-identity key, the live asid the
     * wide-register per-process discriminator.  A kernel TB under KPTI-off
     * shares its process's CR3, so live is the owning process there too. */
    prev_owner_asid_ = in.pinned_asid;
    prev_owner_live_ = in.live_asid;
    return StepStatus::CONTINUE;
}

/*
 * Merge completion: the frame's accumulated prefix is re-injected in
 * front of the suffix's own accumulators (drain attribution walks the
 * full template's insn_pcs in forward monotonic lockstep, so order is
 * load-bearing), the suffix's resolved branch metadata drives the emit
 * on the FULL template, and the frame is retired BEFORE the emit — the
 * synchronous WP walk it kicks must not observe the BB still pending.
 * Trailing seals of the same step keep the frame's depth and empty
 * anchors.
 */
PathBuilder::StepStatus
PathBuilder::complete_merge(size_t idx,
                            const std::vector<PendingEmit> &pending_emits,
                            BodyStreamState *out_stream,
                            unsigned int cpu_index)
{
    /* faults=0: the synchronous-fault handler excursion is excluded, but the
     * merge still runs so a fault-split interrupted block reassembles whole.
     * A frame at depth >= 1 is a NESTED fault's interrupted HANDLER block —
     * excluded like the handler's other blocks; drop it (its prefix was
     * capture-muted, so its buffers are empty) and discard the resume suffix's
     * accumulators.  A depth-0 frame is the top-level interrupted block: emit
     * it whole, its pre-fault prefix re-injected ahead of the resume suffix,
     * but with NO fault anchors and depth clamped to 0 — a faults=0 trace
     * carries no depth>0 entries.  Wrong-path stays on: it is ordinary
     * correct-path code.  (The faults=1 machinery below — deeper-frame flush,
     * anchor guard — is bypassed entirely, so it stays byte-identical.) */
    if (!g_features.trace_faults) {
        CtxFrame &f0 = frames_[idx];
        if (f0.depth >= 1) {
            frames_.erase(frames_.begin() + (ptrdiff_t)idx);
            g_mem_recorder.clear_cp();
            pending_reg_snaps.clear();
            return StepStatus::MERGED;
        }
        const PendingEmit &pe0 = pending_emits.front();
        if (g_features.reg_data && f0.full_tmpl) {
            uint64_t expected = 0;
            for (uint32_t i = 0; i < f0.full_tmpl->n_insns; i++) {
                expected += f0.full_tmpl->insn_fields[i].n_dst_regs;
            }
            size_t have = f0.snaps.size() + pending_reg_snaps.size();
            if (have > expected && f0.snaps.size() <= expected) {
                size_t excess = have - expected;
                if (excess <= pending_reg_snaps.size()) {
                    pending_reg_snaps.erase(
                        pending_reg_snaps.begin(),
                        pending_reg_snaps.begin() + (ptrdiff_t)excess);
                }
            }
        }
        g_mem_recorder.prepend_cp(f0.mem);
        if (!f0.snaps.empty()) {
            pending_reg_snaps.insert(pending_reg_snaps.begin(),
                                     f0.snaps.begin(), f0.snaps.end());
        }
        if (pe0.bb_tmpl && f0.full_tmpl && pe0.bb_tmpl->taken_pc) {
            g_mutex_lock(&data_lock);
            f0.full_tmpl->taken_pc = pe0.bb_tmpl->taken_pc;
            g_mutex_unlock(&data_lock);
        }
        g_emit_fault_depth = 0;
        g_dbg_depth_src = CST_DSRC_MERGE_ZERO;
        g_emit_fault_anchors.clear();
        BBTemplate *merged0 = f0.full_tmpl;
        uint64_t merge_wrong0 = pb_no_fault_wp() ? 0 : pe0.wrong_target;
        frames_.erase(frames_.begin() + (ptrdiff_t)idx);
        emit_finalized_bb(out_stream, merged0, pe0.branch_pc,
                          pe0.emit_current_pc, merge_wrong0, cpu_index);
        for (size_t i = 1; i < pending_emits.size(); i++) {
            const PendingEmit &pe2 = pending_emits[i];
            emit_finalized_bb(out_stream, pe2.bb_tmpl, pe2.branch_pc,
                              pe2.emit_current_pc, pe2.wrong_target, cpu_index);
        }
        return StepStatus::MERGED;
    }

    /* Retire-at-return backstop (deferred from Stage 0, landed now that
     * completion is (thread,asid)-scoped — Stage 2).  @idx was picked by
     * frame_idx_for_completion under the asid key, so it is unambiguously
     * THIS process's completing frame — and that scoped pick is what makes
     * the flush below safe (the Stage-0 hazard was an ambiguous @idx: flushing
     * deeper than a mis-picked foreign frame could erase another process's
     * live excursion).  Any frame still in flight that nests DEEPER (a higher
     * stack index; frames_ is push / fault-nesting order) has leaked: inner
     * faults unwind before their outer under strict LIFO, so a deeper frame
     * surviving to this completion means its own resume suffix was lost /
     * never sealed under contention.  Emit each inner (depth >= 1) frame's
     * level now, deepest-first, BEFORE the outer frame's merged BB, so the
     * unwind steps down one level at a time (2->1->0) instead of collapsing
     * straight to the outer's depth (2->0 — the syscall_fault_nesting jump
     * retire_prev_frame cannot reach, because the leaked frame's suffix never
     * passed through a suspension).  Depth >= 1 mirrors retire_prev_frame:
     * a depth-0 (user) frame is the unwind floor and never anchors a >1 jump,
     * and emitting user code standalone would degrade an entry the content
     * oracle validates.
     *
     * The deeper frames are NOT filtered on CtxFrame::asid equality: frames_
     * only ever holds the pinned process's own excursions (a foreign TB's
     * prev is dropped before classification can stash it), but a KERNEL
     * fault's event-stamped asid is whatever mm happens to be loaded at the
     * fault instant — under multi-process churn routinely another task's
     * (the same reason kexc ownership exists: live ASID is not ownership for
     * kernel code).  An equality filter here would skip exactly the pinned
     * process's own leaked handler frames (observed: the depth-1 kernel frame
     * stamped with a churn CR3, its level then lost to a 2->0 jump).  A stamp
     * mismatch is reported as a diagnostic, same demotion as the completion
     * byte guard.  flush_frame_unwound erases index i > idx, which never
     * shifts @idx, so the reference below stays valid; its own anchor guard
     * drops any level it cannot place without an anchor-at-unwind
     * violation. */
    if (out_stream) {
        const uint64_t complete_asid = frames_[idx].asid;
        const uint32_t complete_tid = frames_[idx].tid;
        for (size_t i = frames_.size(); i-- > idx + 1; ) {
            if (frames_[i].depth < 1) {
                continue;
            }
            /* Ownership IS filtered, unlike the asid stamp below: "deeper on
             * the stack" only means "nested inside" within ONE guest thread.
             * A peer thread's frame sitting above this one on the shared
             * per-vCPU ledger is a concurrent excursion, not an inner one —
             * flushing it here would emit that thread's level into the
             * completing thread's stream, fabricating the very depth jump the
             * flush exists to prevent.  It stays for its own unwind. */
            if (frames_[i].tid != complete_tid) {
                g_stats.depth_tid_deeper_spared++;
                continue;
            }
            if (pb_diag() && frames_[i].asid != complete_asid) {
                fprintf(stderr, "[pathbuilder] DIAG deeper-flush asid stamp "
                        "drift (non-behavioral): frame full=0x%" PRIx64
                        " depth=%u asid=0x%" PRIx64 " vs completing asid=0x%"
                        PRIx64 "\n",
                        frames_[i].full_tmpl ? frames_[i].full_tmpl->start_pc
                                             : 0,
                        frames_[i].depth, frames_[i].asid, complete_asid);
            }
            flush_frame_unwound(i, out_stream, cpu_index);
        }
    }
    CtxFrame &f = frames_[idx];
    const PendingEmit &pe = pending_emits.front();
    if (pb_diag()) {
        fprintf(stderr, "[pathbuilder] EMIT full=0x%" PRIx64 " fsnaps=%zu "
                "suffsnaps=%zu nmem=%zu "
                "branch_pc=0x%" PRIx64 " cur=0x%" PRIx64 " wrong=0x%" PRIx64
                " frames=%zu\n",
                f.full_tmpl ? f.full_tmpl->start_pc : 0, f.snaps.size(),
                pending_reg_snaps.size(), f.mem.size(),
                pe.branch_pc, pe.emit_current_pc, pe.wrong_target,
                frames_.size());
    }
    /* Discard any leaked prefix in the resume suffix's pending snaps before
     * prepending the frame.  When a sync-fault handler abandons a chain on a
     * TB discontinuity, the chain assembler drops its fragments but its
     * already-captured dst snaps stay in pending_reg_snaps (no async-suspend
     * or segment-edge clear runs on the sync-fault path), landing at the
     * FRONT of pending — ahead of this resume suffix's own snaps.  The frame
     * prefix (f.snaps, captured at stash and equal to the faulting BB's
     * pre-fault dsts) is authoritative, so any excess over the merged
     * template's Σ n_dst_regs is exactly that leaked front; trim it, keeping
     * the suffix's real snaps.  Without this the merged entry over-counts and
     * the emit-time backstop drops the whole entry's reg-data — this recovers
     * the correct positional attribution instead. */
    if (g_features.reg_data && f.full_tmpl) {
        uint64_t expected = 0;
        for (uint32_t i = 0; i < f.full_tmpl->n_insns; i++) {
            expected += f.full_tmpl->insn_fields[i].n_dst_regs;
        }
        size_t have = f.snaps.size() + pending_reg_snaps.size();
        if (have > expected && f.snaps.size() <= expected) {
            size_t excess = have - expected;
            if (excess <= pending_reg_snaps.size()) {
                pending_reg_snaps.erase(
                    pending_reg_snaps.begin(),
                    pending_reg_snaps.begin() + (ptrdiff_t)excess);
            }
        }
    }
    g_mem_recorder.prepend_cp(f.mem);
    if (!f.snaps.empty()) {
        pending_reg_snaps.insert(pending_reg_snaps.begin(),
                                 f.snaps.begin(), f.snaps.end());
    }
    /* The faulting BB and its resuming suffix share the terminal branch,
     * so they share its resolved static target. */
    if (pe.bb_tmpl && f.full_tmpl && pe.bb_tmpl->taken_pc) {
        g_mutex_lock(&data_lock);
        f.full_tmpl->taken_pc = pe.bb_tmpl->taken_pc;
        g_mutex_unlock(&data_lock);
    }
    /* Anchor guard on the merge emit (mirrors flush_frame_unwound's guard,
     * plan §1.4 — the safety net against a depth-JUMP / anchor-at-unwind
     * trade).  A merged (fault-anchored) entry must land at its excursion's
     * unwind — its same-tid predecessor strictly DEEPER.  Under multi-process
     * kernel-fault interleave a frame can be created off the pinned process's
     * shared-kernel deferred prev by ANOTHER task's fault (a kernel event's
     * asid stamp is not ownership — the Stage-2 finding) and then completed by
     * the pinned process via the kernel-content path, with the excursion's
     * deeper handler blocks never traced in the pinned stream
     * (g_last_emit_fault_depth <= f.depth).  Emitting it anchored at f.depth
     * then fabricates the residual depth-0 merge (anch=[0] at depth 0 whose
     * predecessor is also depth 0) or a >1 depth JUMP.  When the deeper
     * predecessor is absent, emit the faulting BB as a PLAIN block clamped to
     * the predecessor's depth (no anchor, no jump) — the honest
     * representation of a fault whose excursion the pinned stream did not see.
     * Byte-inert off the contention path: a genuine nested fault's handler
     * emits deeper first, so the guard never triggers (g_last_emit > f.depth).
     * The deeper-frame flush above may have just emitted the true deeper
     * predecessor, in which case g_last_emit is deep and the anchor stays. */
    if (g_last_emit_fault_depth > f.depth) {
        g_emit_fault_depth = f.depth;
        g_dbg_depth_src = CST_DSRC_MERGE;
        g_emit_fault_anchors = f.anchors;
    } else {
        g_emit_fault_depth = g_last_emit_fault_depth;
        g_dbg_depth_src = CST_DSRC_MERGE_PLAIN;
        g_emit_fault_anchors.clear();
        if (pb_diag() || pb_susp_diag()) {
            fprintf(stderr, "[pathbuilder] MERGE-DEANCHOR full=0x%" PRIx64
                    " f.depth=%u last_emit=%u nanchor=%zu (no deeper "
                    "predecessor; emit plain)\n",
                    f.full_tmpl ? f.full_tmpl->start_pc : 0, f.depth,
                    g_last_emit_fault_depth, f.anchors.size());
        }
    }
    BBTemplate *merged = f.full_tmpl;
    uint64_t merge_wrong = pb_no_fault_wp() ? 0 : pe.wrong_target;
    frames_.erase(frames_.begin() + idx);
    emit_finalized_bb(out_stream, merged, pe.branch_pc,
                      pe.emit_current_pc, merge_wrong, cpu_index);
    g_emit_fault_anchors.clear();
    for (size_t i = 1; i < pending_emits.size(); i++) {
        const PendingEmit &pe2 = pending_emits[i];
        emit_finalized_bb(out_stream, pe2.bb_tmpl, pe2.branch_pc,
                          pe2.emit_current_pc, pe2.wrong_target, cpu_index);
    }
    return StepStatus::MERGED;
}

/*
 * Unwind flush (see the header): retire an inner fault frame AT ITS RETURN by
 * emitting its merged faulting BB standalone — the frame's own template, at
 * its own fault depth + anchors, from its OWN accumulated memop / reg-snap
 * buffers — then erasing it.  Used when the frame's resume suffix (the block
 * whose seal would complete the merge) is DROPPED or never seals under host
 * contention, so its depth level is emitted at the unwind rather than lost
 * and collapsed into a >1 depth jump.  No wrong-path, and the terminal branch
 * is left unresolved (the suffix that resolves it is gone), like the
 * segment-final flush.
 *
 * The current CP memop / pending reg-snap accumulators hold the block being
 * sealed THIS step (the outer frame's resume suffix, still pending), so they
 * are set aside and restored around the frame's own emit.
 *
 * Anchor-at-unwind guard: an anchored (merged) entry must follow a strictly
 * DEEPER one (syscall_fault_nesting).  If this thread's last-emitted depth is
 * not strictly greater than the frame's, emitting here would fabricate that
 * violation (the unwind already stepped past this level, or the predecessor
 * is not this frame's handler) — so the frame is dropped WITHOUT emit.  Its
 * merged BB is lost, but no anchor/step violation is introduced: depth is
 * already at or below this level, so no >1 jump opens either.
 */
void PathBuilder::flush_frame_unwound(size_t idx, BodyStreamState *out_stream,
                                      unsigned int cpu_index)
{
    CtxFrame f = std::move(frames_[idx]);
    frames_.erase(frames_.begin() + (ptrdiff_t)idx);

    if (!out_stream || !f.full_tmpl) {
        return;
    }
    if (!(g_last_emit_fault_depth > f.depth)) {
        if (pb_diag()) {
            fprintf(stderr, "[pathbuilder] UNWIND-FLUSH-SKIP full=0x%" PRIx64
                    " depth=%u last_emit_depth=%u (anchor guard)\n",
                    f.full_tmpl->start_pc, f.depth, g_last_emit_fault_depth);
        }
        return;
    }

    /* Set the current block's accumulators aside; emit from the frame's own. */
    std::vector<WPMemAccess> cur_mem;
    g_mem_recorder.take_cp(cur_mem);
    std::vector<RegSnap> cur_snaps = std::move(pending_reg_snaps);
    pending_reg_snaps.clear();

    g_mem_recorder.prepend_cp(f.mem);
    pending_reg_snaps = f.snaps;
    g_emit_fault_depth = f.depth;
    g_dbg_depth_src = CST_DSRC_UNWIND;
    g_emit_fault_anchors = f.anchors;

    if (pb_diag() || pb_depth_diag()) {
        fprintf(stderr, "[pathbuilder] UNWIND-FLUSH full=0x%" PRIx64 " depth=%u "
                "nanchor=%zu nmem=%zu pred_depth=%u frames_left=%zu\n",
                f.full_tmpl->start_pc, f.depth, f.anchors.size(),
                f.mem.size(), g_last_emit_fault_depth, frames_.size());
    }

    emit_body_entry(out_stream, f.full_tmpl, cpu_index, {});

    g_emit_fault_anchors.clear();
    g_emit_fault_depth = 0;

    /* Restore the current block's accumulators (emit drained them). */
    g_mem_recorder.clear_cp();
    g_mem_recorder.prepend_cp(cur_mem);
    pending_reg_snaps = std::move(cur_snaps);
}

/*
 * A deferred prev is about to be discarded without resuming (the
 * retire-at-return tail: an over-cap displacement or a stale sweep past its
 * owner's return).  If that prev is an in-flight INNER fault frame's resume
 * suffix, its seal would have completed the merge — retiring that frame at
 * its return.  Discarding it silently is exactly what leaks the frame under
 * contention (it lingers un-returned, inflating every later fault's depth
 * until a coarse sweep collapses it: the residual 2->0 / kernel 2->0->2
 * depth jump).  Retire it now instead, emitting its depth level at the
 * unwind.  Only inner (depth>=1, kernel-handler) frames flush: a depth-0
 * (user) frame is the unwind floor — it can never anchor a >1 jump — and
 * emitting user code standalone would degrade a user entry the content
 * oracle validates.
 */
void PathBuilder::retire_prev_frame(BBTemplate *prev, uint64_t seal_asid,
                                    unsigned int cpu_index)
{
    if (!g_features.fault_depth_trailer || pb_no_merge() ||
        !prev || frames_.empty()) {
        return;
    }
    BodyStreamState *out_stream =
        g_trace_segments.is_active() ? g_trace_segments.body_stream() : nullptr;
    if (!out_stream) {
        return;
    }
    /* The retired prev is the pinned process's OWN block, so it is matched
     * within its (thread,asid): seal_asid is the pinned effective asid. */
    ptrdiff_t ci = frame_idx_for_completion(prev, seal_asid);
    if (ci >= 0 && frames_[(size_t)ci].depth >= 1) {
        flush_frame_unwound((size_t)ci, out_stream, cpu_index);
    }
}

/*
 * Suspend-or-seal (Stage 3, plan §1.2).  Freeze the deferred prev and its
 * four thread-local sinks (committed CP memops, per-insn dst snaps, the
 * in-flight chain prefix, and the depth stamp) onto susp_stack_, keyed on
 * the OWNING (asid, live) captured at the block's promote.  The caller
 * guarantees prev_tb_ != nullptr.  Over the SUSP_STACK_CAP bound the OLDEST
 * suspension falls back to retire-at-return (Decision A): flush its fault
 * level now and evict it to make room, so the stack stays bounded and no
 * depth level is silently lost to displacement.
 */
void PathBuilder::suspend_prev(uint64_t owner_asid, uint64_t owner_live,
                               unsigned int cpu_index)
{
    if (susp_stack_.size() >= SUSP_STACK_CAP) {
        retire_suspension(0, cpu_index);        /* oldest -> retire-at-return */
        susp_stack_.erase(susp_stack_.begin());
        g_stats.susp_displaced++;
    }
    susp_stack_.emplace_back();
    SuspendedPrev &s = susp_stack_.back();
    s.prev = prev_tb_;
    s.depth = prev_depth_;
    s.asid = owner_asid;
    s.owner_live = owner_live;
    g_mem_recorder.take_cp(s.mem);              /* drains the CP buffer */
    s.snaps = std::move(pending_reg_snaps);
    pending_reg_snaps.clear();
    s.chain = g_cp_chain.detach_state();
    g_stats.susp_pushed++;
    g_dbg_susp = susp_stack_.size();
    cst_jump_diag_step(0, s.prev ? s.prev->start_pc : 0, -1, 1, "SUSPEND");
    if (pb_diag() || pb_susp_diag()) {
        fprintf(stderr, "[pathbuilder] SUSPEND prev=0x%" PRIx64 " depth=%u "
                "asid=0x%" PRIx64 " live=0x%" PRIx64 " nmem=%zu nsnaps=%zu "
                "stack=%zu\n",
                s.prev ? s.prev->start_pc : 0, s.depth, s.asid, s.owner_live,
                s.mem.size(), s.snaps.size(), susp_stack_.size());
    }
}

/*
 * The resume arrow (plan §1.3).  The pinned process is back at an owned,
 * non-excluded TB (all gates passed).  Pop the top-most suspension whose
 * owning asid matches the resuming context's pinned effective asid and
 * re-arm the four sinks so the promote below walks the suspended prev and
 * the seal emits the intermediate handler block AT ITS OWN DEPTH.
 *
 * The match keys ONLY on the pinned effective asid (StepIn::pinned_asid, the
 * dwell tag on narrow-ASID targets) — the load-bearing Stage-2 finding: a
 * kept KERNEL block's LIVE asid is whatever mm is loaded (a PTI overlay, a
 * TLB-maintenance scratch), NOT ownership, so gating the resume on live asid
 * strands the pinned process's own kernel-handler suspensions un-resumable
 * (observed: a kept kernel block promoted under a 0x...d2000 overlay never
 * matches the pinned 0x...c4000).  Cross-process safety in trace-all is the
 * COMPLETION path's job (frame_matches_completion keys user frames on the
 * hard asid and kernel frames on content), not the resume re-arm's.  Returns
 * true iff a suspension was restored.
 */
bool PathBuilder::resume_suspension(uint64_t resume_asid, uint64_t resume_live)
{
    (void)resume_live;                           /* diagnostic only; see above */
    for (size_t i = susp_stack_.size(); i-- > 0; ) {
        SuspendedPrev &s = susp_stack_[i];
        if (s.asid != resume_asid) {
            continue;
        }
        prev_tb_ = s.prev;                       /* re-arm the pending seal */
        prev_depth_ = s.depth;
        g_dbg_prev_depth_src = CST_PDSRC_RESUME;
        g_dbg_prev_depth = prev_depth_;
        prev_owner_asid_ = s.asid;
        prev_owner_live_ = s.owner_live;
        g_mem_recorder.prepend_cp(s.mem);        /* restore committed memops */
        if (!s.snaps.empty()) {                  /* restore per-insn snaps */
            pending_reg_snaps.insert(pending_reg_snaps.begin(),
                                     s.snaps.begin(), s.snaps.end());
        }
        g_cp_chain.attach_state(std::move(s.chain));
        cst_jump_diag_step(0, prev_tb_ ? prev_tb_->start_pc : 0, -1, 1,
                           "RESUME");
        if (pb_diag() || pb_susp_diag()) {
            fprintf(stderr, "[pathbuilder] RESUME prev=0x%" PRIx64 " depth=%u "
                    "asid=0x%" PRIx64 " live=0x%" PRIx64 " stack=%zu\n",
                    prev_tb_ ? prev_tb_->start_pc : 0, prev_depth_,
                    resume_asid, resume_live, susp_stack_.size() - 1);
        }
        susp_stack_.erase(susp_stack_.begin() + (ptrdiff_t)i);
        g_stats.susp_resumed++;
        return true;
    }
    return false;
}

/*
 * Retire a held suspension without resuming it — the "suspend couldn't cover
 * this" tail (over-cap displacement; a stale sweep past its owner's return).
 * Emit its fault level via retire_prev_frame (keyed on its own owning asid,
 * anchor-guarded so it can never trade a depth-JUMP for an anchor-at-unwind
 * violation), draining the frozen accumulators back so the flush emits from
 * them, then leave the entry for the caller to erase.
 */
void PathBuilder::retire_suspension(size_t idx, unsigned int cpu_index)
{
    SuspendedPrev &s = susp_stack_[idx];
    /* retire_prev_frame -> flush_frame_unwound emits from the FRAME's own
     * buffers and save/restores the LIVE accumulators around its emit, so the
     * suspension's frozen mem/snaps need not be re-injected; only prev + its
     * owning asid drive the frame match. */
    retire_prev_frame(s.prev, s.asid, cpu_index);
    if (pb_diag() || pb_susp_diag()) {
        fprintf(stderr, "[pathbuilder] SUSP-RETIRE prev=0x%" PRIx64 " depth=%u "
                "asid=0x%" PRIx64 " stack=%zu\n",
                s.prev ? s.prev->start_pc : 0, s.depth, s.asid,
                susp_stack_.size());
    }
}

/*
 * Stamp the depth cur (already promoted by step_events) runs at, and with it
 * the synchronous-fault-span flag the faults=0 handler suppression reads.
 *
 * The depth is the count of un-returned merge frames that CUR'S OWN GUEST
 * THREAD entered.  frames_ is per-vCPU and a vCPU multiplexes guest threads,
 * so ownership is what separates them: a thread descheduled across a peer's
 * excursion would otherwise inherit the peer's nesting and step back down to
 * its own when rescheduled (the single-sided `2 -> 0` the oracle reports).
 * StepIn::cur_tid names the executing TB's thread and is sampled before the
 * seal for exactly this reason — the committed identity is still the previous
 * block's, so counting against it would be one step late.
 *
 * The count is a function of frames_ AT THE MOMENT OF THE STAMP — and
 * step_seal moves frames_ twice: the event drain at its head pushes/returns
 * frames, and the seal walk at its tail RETIRES them (complete_merge erases
 * the completing frame and flushes any deeper ones).  Both movements bracket
 * cur, so the stamp is taken at the head AND re-taken after the walk.
 *
 * The re-stamp is the fix for the residual syscall_fault_nesting depth-JUMP.
 * A completion proves the excursion is over: the resume suffix only executes
 * after the exception return, so the block that follows the reassembled
 * faulting BB is at the POST-unwind depth.  Stamping it only at the head gave
 * it the PRE-completion count, and whenever a frame's FAULT_RETURN had been
 * suppressed (QEMU's strict-LIFO cpu_plugin_fault_pop drops a pinned frame's
 * return when a foreign churn frame sits above it on the shared per-vCPU
 * stack, so the frame is still flagged un-returned when its merge completes)
 * that count was too high — by one per suppressed frame.  With two such
 * frames (a nested fault: the copy_user BB, then a fault inside its handler)
 * the single block after the merge emitted at depth 2 between depth-0
 * neighbours: the observed 0 -> 2 -> 0 spike.
 *
 * Byte-inert wherever the returns are observed: apply_fault_return has
 * already cleared `returned` for the completing frames, so they were never
 * counted and the re-stamp reproduces the head's value exactly.  Only the
 * suppressed-return case, which is the bug, changes.
 */
void PathBuilder::stamp_cur_depth(const StepIn &in, bool post_merge)
{
    const uint32_t was = prev_depth_;
    uint32_t pinned_inflight = 0;
    uint32_t foreign_inflight = 0;
    for (const CtxFrame &f : frames_) {
        if (f.returned) {
            continue;
        }
        if (f.tid == in.cur_tid) {
            pinned_inflight++;
        } else {
            foreign_inflight++;
        }
    }
    if (foreign_inflight) {
        /* The Class-B condition, counted directly: another guest thread's
         * excursion was in flight while THIS thread's block executed.  Every
         * one of these was inherited before frames carried an owner. */
        g_stats.depth_tid_foreign_inflight += foreign_inflight;
        g_stats.depth_tid_stamps_corrected++;
        if (foreign_inflight > g_stats.depth_tid_max_foreign) {
            g_stats.depth_tid_max_foreign = foreign_inflight;
        }
        if (pb_diag() || pb_depth_diag() || cst_jump_diag()) {
            fprintf(stderr, "[pathbuilder] TID-DISOWN cur=0x%" PRIx64
                    " tid=%u own=%u foreign=%u frames=%zu\n",
                    in.cur ? in.cur->start_pc : 0, in.cur_tid,
                    pinned_inflight, foreign_inflight, frames_.size());
        }
    }
    /* The captured async level is ownership-filtered exactly as the frame
     * count above is: format.rst §4.2a's nesting is a property of the entry's
     * own thread, and an interrupt delivered in one thread is not the next
     * thread's nesting.  Dormant off-context, live again on return — a
     * predicate, not a latch. */
    const uint32_t async_lvl = async_level(in);
    depth_next_ = pinned_inflight + async_lvl;
    /* User-privilege TBs stamp depth 0 regardless of the vCPU's raw
     * fault-stack depth: user code is never fault-handler content, but a
     * preemptible kernel can context-switch INSIDE a blocking fault handler
     * (cond_resched in the fault path) and resume another guest thread's user
     * code while the interrupted task's fault frames are still live on this
     * vCPU's stack — without the clamp those user entries would carry the
     * interrupted excursion's depth (observed: depth-4 user loop blocks under
     * a two-thread yield workload).  That peer thread's KERNEL work is
     * covered by frame ownership, not by this clamp: the count above skips
     * frames another thread entered, so the peer's kernel blocks stand at
     * their own nesting depth, which is what format.rst §4.2a defines
     * fault_depth to be. */
    prev_depth_ = (in.pinned && in.live_priv == 0) ? 0 : depth_next_;
    /* Synchronous-fault-span stamp (faults=0 handler suppression): true when
     * cur runs while an un-returned synchronous-fault frame OF CUR'S OWN
     * THREAD is in flight and cur is not user code.  A peer thread's block is
     * not this excursion's handler content — same ownership rule as the depth
     * — and a user TB is never handler content at all, so it stamps false,
     * mirroring the depth clamp above. */
    prev_in_sync_ = (in.pinned && in.live_priv == 0)
                        ? false
                        : (depth_next_ - async_lvl) > 0;
    g_dbg_prev_depth_src = CST_PDSRC_SEAL;
    g_dbg_prev_depth = prev_depth_;
    g_dbg_inflight = pinned_inflight;
    g_dbg_depth_next = depth_next_;
    g_dbg_frames = frames_.size();
    /* Measure the correction the second stamp makes; see the counters. */
    if (post_merge && prev_depth_ != was) {
        uint32_t delta = was > prev_depth_ ? was - prev_depth_
                                           : prev_depth_ - was;
        g_stats.depth_restamp_corrections++;
        if (delta >= 2) {
            g_stats.depth_restamp_jumps++;
        }
        if (delta > g_stats.depth_restamp_max_delta) {
            g_stats.depth_restamp_max_delta = delta;
        }
        if (pb_diag() || pb_depth_diag() || cst_jump_diag()) {
            fprintf(stderr, "[pathbuilder] RESTAMP cur=0x%" PRIx64
                    " %u -> %u (delta %u) frames=%zu\n",
                    in.cur ? in.cur->start_pc : 0, was, prev_depth_, delta,
                    frames_.size());
        }
    }
}

PathBuilder::StepStatus PathBuilder::step_seal(const StepIn &in,
                                               BodyStreamState *out_stream)
{
    /* The depth-pipeline + kernel-handler fault merge is the system-only
     * DEPTH TRAILER machinery (fault_depth_trailer); it is orthogonal to the
     * wrong-path synthetic-fault marking policy (wp_synthetic_marking), which
     * lives in the WP walker and runs in user mode too. */
    const bool fault_on = g_features.fault_depth_trailer;

    /* No previous context (first TB after install / after the segment-
     * final flush zeroed the scoreboard): nothing to seal, and the
     * retained fault events carry to the next surviving step. */
    if (in.prev_ft == 0) {
        return StepStatus::NO_SEAL;
    }

    /* Depth pipeline + fault-entry classification: only steps that
     * survive every gate consume the retained events. */
    bool prev_stashed = false;
    /* Architectural-successor override for a synchronous fault that
     * interposed between prev and cur.  A FAULT_ENTER whose resume PC
     * lies outside the deferred prev is case (c): the fetch of prev's
     * successor missed (or a resume suffix's refetch re-faulted before
     * its exec callback), so the TB executing now is the fault HANDLER
     * — not where prev's control flow architecturally went.  Sealing
     * prev against the scoreboard's current_pc would then attribute
     * the branch edge to the handler's entry PC: a taken conditional's
     * template taken_pc records the handler (breaking the decoder's
     * chain walk at the real target), a fall-through fetch-miss
     * flips the recorded direction to "taken", and a handler-tail
     * ERET whose refetch re-faults records the next excursion's
     * handler entry as its own target.  The event's resume PC IS the
     * successor — the PC the CPU attempted after prev and re-executes
     * after the excursion — so the first FAULT_ENTER taken OUTSIDE an
     * async window supplies the seal's successor.  In-window entries
     * are excluded content interposed by an interrupt, not prev's
     * edge; the async machinery already seals prev against the
     * window's departure PC. */
    uint64_t fault_resume_pc = 0;
    if (!primed_) {
        prime_from_live();
        pending_evs_.clear();   /* priming swallow */
    } else {
        /* Async-window state at the head of the retained batch: the
         * step survived to the seal phase, so any window the batch
         * opened is closed again by its end; a batch whose FIRST async
         * edge is a RETURN was inside a window from the start (its
         * earlier events are in-window). */
        bool ev_in_async = false;
        for (const struct qemu_plugin_cpu_event &ev : pending_evs_) {
            if (ev.kind == QEMU_PLUGIN_CPU_EV_ASYNC_RETURN) {
                ev_in_async = true;
                break;
            }
            if (ev.kind == QEMU_PLUGIN_CPU_EV_ASYNC_ENTER) {
                break;
            }
        }
        for (const struct qemu_plugin_cpu_event &ev : pending_evs_) {
            if (ev.kind == QEMU_PLUGIN_CPU_EV_ASYNC_ENTER) {
                ev_in_async = true;
            } else if (ev.kind == QEMU_PLUGIN_CPU_EV_ASYNC_RETURN) {
                ev_in_async = false;
            }
            if (ev.kind == QEMU_PLUGIN_CPU_EV_FAULT_ENTER) {
                raw_depth_ = ev.depth_after;
                if (fault_on && !ev_in_async && fault_resume_pc == 0) {
                    fault_resume_pc = ev.pc;
                }
                if (pb_diag()) {
                    fprintf(stderr, "[pathbuilder] ENTRY resume=0x%" PRIx64
                            " depth=%u asid=0x%" PRIx64 " priv=%u\n",
                            ev.pc, ev.depth_after, ev.asid, ev.priv);
                }
                if (fault_on && !pb_no_merge()) {
                    classify_fault_enter(ev, &prev_stashed, in.walk_tid);
                }
            } else if (ev.kind == QEMU_PLUGIN_CPU_EV_FAULT_RETURN) {
                raw_depth_ = ev.depth_after;
                if (fault_on && !pb_no_merge()) {
                    apply_fault_return(ev);
                }
            }
            /* async kinds were applied by step_events.  ASID_WRITE (kind
             * 4) is consumed at drain time for kexc ownership (step_events);
             * the fault-depth trailer no longer reads it.  Depth is the
             * pinned process's OWN un-returned fault count (below), which the
             * context switch an ASID_WRITE marks cannot perturb. */
        }
        pending_evs_.clear();
        /*
         * Fault-trailer depth = the pinned process's OWN synchronous-fault
         * nesting: the number of its un-returned merge frames.  It is
         * deliberately NOT derived from the per-vCPU plugin_fault_depth
         * (raw_depth_, tracked above only for the diag).  That stack is a
         * SINGLE object SHARED by every guest process, and under
         * multi-process churn it interleaves the pinned process's frames
         * with a busy boot's leaked frames (observed raw 62-65, at the
         * 64-slot cap) and the churn tasks' transient ones.  No single
         * per-vCPU baseline scalar can partition those: a foreign frame
         * popping re-floored the old baseline down and a later foreign push
         * then OVER-counted the pinned depth, while a context switch through
         * the pinned handler and back UNDER-counted it — the two churn
         * signatures (a merged faulting BB stamped at its own handler's
         * depth, and a handler depth jumping 0<->2 across a kernel spin
         * loop).  frames_ holds exactly the pinned process's in-flight
         * faults: foreign (dropped) and async (suspended) excursions never
         * reach the merge, so they never seed a frame, and the boot's leaked
         * frames predate frames_, which on_segment_open clears.  Counting
         * its un-returned frames therefore gives the pinned nesting depth
         * directly — ISA-agnostic, immune to the shared stack's pollution,
         * and 0 on the fault-free user path (frames_ empty) so output stays
         * byte-identical there.  A returned frame's handler has already
         * unwound (its FAULT_RETURN was observed), so it does not count.
         *
         * Stale-frame retirement.  A pinned TB at USER privilege proves the
         * process is at fault-nesting depth 0 — user code never runs inside
         * its own fault handler.  Any frame still flagged un-returned when a
         * pinned user TB executes is therefore a LEAK: its handler's
         * exception-return was non-LIFO on the shared per-vCPU stack (a
         * foreign churn frame sat on top of it, so QEMU's strict-LIFO
         * cpu_plugin_fault_pop matched the top and suppressed this frame's
         * FAULT_RETURN), so the plugin never saw the return and the frame
         * lingered — inflating every subsequent pinned fault's depth (the
         * residual 0<->2 churn jump).  Retire such frames: mark them
         * returned so they drop out of the depth count, but do NOT erase
         * them — their merge completion stays possible if the resume suffix
         * still seals.
         *
         * The proof is per guest THREAD, so the sweep is too: this user TB
         * says THIS thread is at depth 0 and says nothing about a peer whose
         * handler is still live on the same vCPU.  Sweeping a peer's frames
         * here is the mirror image of counting them — it would drop that
         * thread's nesting the moment any other thread touched user code, and
         * its next kernel block would step down without an unwind. */
        if (fault_on && in.pinned && in.live_priv == 0) {
            uint32_t leaked = 0;
            for (CtxFrame &f : frames_) {
                if (f.tid != in.cur_tid) {
                    if (!f.returned) {
                        g_stats.depth_tid_sweep_spared++;
                    }
                    continue;                  /* a peer thread's excursion */
                }
                if (!f.returned) {
                    leaked++;
                    cst_jump_diag_step(in.cur ? in.cur->start_pc : 0,
                                       f.full_tmpl ? f.full_tmpl->start_pc : 0,
                                       0, 1, "RETIRE-LEAK");
                    if (pb_diag()) {
                        fprintf(stderr, "[pathbuilder] RETIRE-LEAK user_tb=0x%"
                                PRIx64 " frame full=0x%" PRIx64 " resume=0x%"
                                PRIx64 " frame_depth=%u\n",
                                in.cur ? in.cur->start_pc : 0,
                                f.full_tmpl ? f.full_tmpl->start_pc : 0,
                                f.resume_pc, f.depth);
                    }
                }
                f.returned = true;
            }
            /* One-line summary: a user TB retiring >1 un-returned frame at
             * once is exactly the residual 2->0 leak-drain discontinuity. */
            if ((pb_diag() || pb_depth_diag()) && leaked > 1) {
                fprintf(stderr, "[pathbuilder] RETIRE-LEAK-BURST user_tb=0x%"
                        PRIx64 " count=%u (inflight drops %u->0)\n",
                        in.cur ? in.cur->start_pc : 0, leaked, leaked);
            }
            /* Suspension stale sweep (Stage 3, Decision A "stale-sweep retire
             * while held").  This pinned USER TB proves the process is at
             * fault-nesting depth 0, and the resume arrow already ran in
             * step_events — so any suspension STILL held for THIS process's
             * (asid, live) reached user privilege without resuming (its owner
             * took a different path than the suspended continuation).  It can
             * no longer reseal; retire it at its depth (anchor-guarded) so its
             * level is not silently lost, then drop it.  Only this process's
             * suspensions are touched — a peer process's held suspension stays
             * for its own resume. */
            for (size_t i = susp_stack_.size(); i-- > 0; ) {
                if (susp_stack_[i].asid == in.pinned_asid) {
                    retire_suspension(i, in.cpu_index);
                    susp_stack_.erase(susp_stack_.begin() + (ptrdiff_t)i);
                    g_stats.susp_stale_retired++;
                }
            }
        }
        /* interrupts=1 abandoned-window recovery: a pinned USER TB proves the
         * process is at async-nesting depth 0 (user code never runs inside its
         * own async handler), so a still-open captured window whose departure
         * PC was never re-fetched (an SMP guest-thread switch the capture
         * spanned, or a killed task) is stale.  Reset it — and the QEMU-side
         * flag, so a fresh ASYNC_ENTER opens a well-formed new window — exactly
         * as the interrupts=0 abandoned-window arrow force-closes the mute.
         * The interrupts=0 path never reaches here with a live window (it
         * SUSPENDS at step_events instead), so this is capture-only. */
        if (g_features.trace_interrupts && in.pinned && in.live_priv == 0 &&
            async_captured_) {
            /* QEMU's window flag is a per-vCPU fact and a pinned USER TB
             * disproves it for the whole vCPU: reaching user privilege means
             * every exception level has been returned from.  Reset it
             * unconditionally — every producer is edge-gated on
             * !plugin_in_async_int, so a stale flag would black out every
             * later capture on this vCPU. */
            qemu_plugin_async_int_reset();
            /* The LEVEL is per thread, so its release is per thread too.
             * This TB proves THIS thread is at async-nesting depth 0; it
             * proves nothing about a peer descheduled inside its own handler,
             * which is the same distinction the stale-frame sweep above draws
             * (`f.tid != in.cur_tid` -> spared, not retired).  Releasing a
             * peer's level here would destroy it while its owner is still
             * inside the handler and it can never be restored; holding it
             * costs nothing, because async_level() already keeps it off every
             * entry that is not the owner's.  It is released when the owner
             * itself reaches user privilege, or replaced by the next
             * ASYNC_ENTER. */
            if (in.cur_tid == async_owner_tid_ ||
                async_owner_tid_ == CST_TID_UNSEEN) {
                async_captured_ = 0;
                async_departure_pc_ = 0;
                async_owner_tid_ = CST_TID_UNSEEN;
                g_stats.async_abandon_owner++;
                async_win_close("ABANDON", in.cur_tid);
                if (pb_diag()) {
                    fprintf(stderr, "[pathbuilder] ASYNC-ABANDON reset at "
                            "pinned user tb=0x%" PRIx64 "\n",
                            in.cur ? in.cur->start_pc : 0);
                }
            } else {
                g_stats.async_abandon_peer_spared++;
                if (pb_diag()) {
                    fprintf(stderr, "[pathbuilder] ASYNC-ABANDON spared "
                            "(peer tid=%u, owner=%u) tb=0x%" PRIx64 "\n",
                            in.cur_tid, async_owner_tid_,
                            in.cur ? in.cur->start_pc : 0);
                }
            }
        }
        uint32_t pinned_inflight = 0;
        for (const CtxFrame &f : frames_) {
            if (!f.returned && f.tid == in.cur_tid) {
                pinned_inflight++;
            }
        }
        /* Emitted fault-trailer depth = synchronous-fault frame nesting +
         * the OWNER's captured async level.  async_level() is 0 with
         * interrupts=0 (the window is never captured), so the trailer is
         * byte-identical to today there. */
        const uint32_t seal_async_lvl = async_level(in);
        depth_next_ = pinned_inflight + seal_async_lvl;
        /* Ownership condition, once per surviving step: whose stamp did the
         * open window just serve?  Denominator for every rate below. */
        if (async_captured_) {
            if (seal_async_lvl) {
                g_async_win_own_stamps++;
                g_stats.async_level_own_stamps++;
            } else {
                g_async_win_peer_stamps++;
                g_stats.async_level_peer_stamps++;
            }
        }
        g_dbg_raw_depth = raw_depth_;
        g_dbg_inflight = pinned_inflight;
        g_dbg_async_captured = seal_async_lvl;
        g_dbg_depth_next = depth_next_;
        g_dbg_frames = frames_.size();
        g_dbg_susp = susp_stack_.size();
        /* Skip the pure user/steady-state (depth 0, no frames, prev depth 0)
         * UNLESS the current TB is a REP string op (rep_subtmpl), whose
         * fanned-out emit is the residual jump's locus: keep every step that
         * carries excursion context or a REP so the per-step log stays small
         * yet captures the interleave.  g_dbg_last_emit_seq ties the step to
         * the wire position. */
        bool cur_is_rep = in.cur && in.cur->rep_subtmpl.ptr != nullptr;
        if (pb_depth_diag() &&
            (cur_is_rep ||
             !(depth_next_ == 0 && walk_depth_ == 0 && prev_depth_ == 0 &&
               frames_.empty()))) {
            fprintf(stderr, "[depthdiag] seq~%" PRIu64 " cur=0x%" PRIx64
                    " walk_prev=0x%" PRIx64 " priv=%d rep=%d raw=%u inflight=%u "
                    "depth_next=%u prev_depth=%u walk_depth=%u frames=%zu\n",
                    g_dbg_last_emit_seq,
                    in.cur ? in.cur->start_pc : 0,
                    walk_prev_ ? walk_prev_->start_pc : 0, in.live_priv,
                    (int)cur_is_rep, raw_depth_, pinned_inflight, depth_next_,
                    prev_depth_, walk_depth_, frames_.size());
        }
    }

    /* Stamp cur (already promoted by step_events) with the depth it runs at,
     * from the ledger as the event drain above left it.  The seal walk below
     * may retire frames, and takes the stamp again when it does. */
    stamp_cur_depth(in);
    /* faults=0: suspend capture across the synchronous-fault handler exactly
     * as the async mute does — the handler's memops / reg snaps never pool
     * into the interrupted block's slots, and its BB is dropped at the seal
     * (walk_in_sync_).  The merge is untouched, so the interrupted block still
     * reassembles whole from its pre-fault prefix and its post-return suffix.
     * Never fires with faults=1 (byte-identical). */
    if (!g_features.trace_faults && (depth_next_ - async_level(in)) > 0) {
        g_capture_mute = true;
    }
    if (fault_on) {
        g_emit_fault_depth = walk_depth_;
        g_dbg_depth_src = CST_DSRC_PIPELINE;
    }
    cst_jump_diag_step(in.cur ? in.cur->start_pc : 0,
                       walk_prev_ ? walk_prev_->start_pc : 0,
                       in.live_priv, (int)in.pinned,
                       prev_stashed ? "seal/STASHED" : "seal");

    if (prev_stashed) {
        /* prev was folded into a fault frame: nothing seals, and the
         * step skips the deferred window closes. */
        return StepStatus::STASHED;
    }

    /* ---- process_tb: the shared seal walk ---- */
    /* The stuck-window recovery substitutes the abandoned window's
     * departure PC for the scoreboard's current_pc: the TB executing
     * now belongs to another guest thread, and prev's successor is
     * where its own interrupted flow would have resumed.  With no
     * recovery in play, a case-(c) fault entry substitutes its resume
     * PC the same way: the TB executing now is the fault handler, and
     * prev's successor is the PC whose fetch faulted (see the
     * fault_resume_pc derivation above).  Reaching the walk with
     * fault_resume_pc set implies every entry this step classified as
     * case (c) — the stash cases returned STASHED just above. */
    uint64_t seal_current_pc = seal_pc_override_ ? seal_pc_override_
                             : fault_resume_pc  ? fault_resume_pc
                                                : in.current_pc;
    seal_pc_override_ = 0;
    std::vector<PendingEmit> pending_emits;
    bool any_finalize = collect_finalized_bbs(in.cpu_index, walk_prev_,
                                              in.prev_start, seal_current_pc,
                                              pending_emits);

    if (in.watch_pc && walk_prev_ && walk_prev_->start_pc == in.watch_pc) {
        fprintf(stderr, "[blkwatch] seal prev=0x%" PRIx64 " prev_start_sb=0x%"
                PRIx64 " cur=0x%" PRIx64 " any_fin=%d npend=%zu pend0=0x%"
                PRIx64 " fdep=%u (events)\n",
                walk_prev_->start_pc, in.prev_start,
                in.cur ? in.cur->start_pc : 0,
                (int)any_finalize, pending_emits.size(),
                pending_emits.empty() ? 0
                    : pending_emits.front().bb_tmpl->start_pc,
                g_emit_fault_depth);
    }

    /* ---- merge completion (front seal only) ---- */
    /* The seal runs on the pinned process's live context; its effective asid
     * (in.pinned_asid) is the (thread,asid) key completion matches on. */
    ptrdiff_t mtop = -1;
    if (fault_on && !pb_no_merge() && any_finalize && !pending_emits.empty()) {
        mtop = frame_idx_for_completion(pending_emits.front().bb_tmpl,
                                        in.pinned_asid);
    }
    if (in.watch_pc && walk_prev_ && walk_prev_->start_pc == in.watch_pc) {
        fprintf(stderr, "[blkwatch] mtop=%td frames=%zu (events)\n",
                mtop, frames_.size());
    }
    if (mtop >= 0) {
        StepStatus st = complete_merge((size_t)mtop, pending_emits, out_stream,
                                       in.cpu_index);
        /* The merge just RETIRED this excursion's frames.  cur is the block
         * the pinned process runs AFTER the faulting BB reassembled, so it
         * is at the post-unwind depth — re-stamp it (see stamp_cur_depth). */
        stamp_cur_depth(in, /*post_merge=*/true);
        return st;
    }

    if (!any_finalize) {
        return StepStatus::NO_SEAL;
    }

    /* faults=0: a block that executed inside a synchronous-fault handler
     * (walk_in_sync_) is excluded.  Its capture was already muted at the
     * depth stamp above, so dropping its emission leaves nothing behind — the
     * accumulators clear is defensive.  A nested-fault resume suffix that
     * completes a merge took the complete_merge return above (which drops the
     * inner handler content on the same rule); this path is the handler's own
     * standalone BBs.  The interrupted (depth-0) block still reassembles
     * whole via the merge. */
    if (!g_features.trace_faults && walk_in_sync_) {
        g_mem_recorder.clear_cp();
        pending_reg_snaps.clear();
        return StepStatus::NO_SEAL;
    }

    for (const PendingEmit &pe : pending_emits) {
        emit_finalized_bb(out_stream, pe.bb_tmpl, pe.branch_pc,
                          pe.emit_current_pc, pe.wrong_target, in.cpu_index);
    }
    return StepStatus::SEALED;
}
