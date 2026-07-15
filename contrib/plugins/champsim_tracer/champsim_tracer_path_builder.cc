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

PathBuilder &path_builder_tls()
{
    static thread_local PathBuilder builder;
    return builder;
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
    frames_.clear();
    pending_evs_.clear();
    clear_prev();
    walk_prev_ = nullptr;
    walk_depth_ = 0;
    prev_depth_ = 0;
    depth_next_ = 0;
    raw_depth_ = 0;
    base_depth_ = 0;
    async_excluding_ = false;
    async_departure_pc_ = 0;
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
     * zero them so nothing leaks into the new segment's first entry. */
    g_emit_fault_depth = 0;
    g_emit_fault_anchors.clear();
}

/*
 * Flush the pending final-TB body entry before a segment finishes (see
 * the declaration).  Walks the pending-seal slot's fragment list up to
 * the last-executed fragment (matched by the scoreboard's @prev_start),
 * same as the per-exec seal walk; no later CP step will fire after
 * shutdown, so this is the only chance to flush the trailing chain.
 */
void PathBuilder::flush_final()
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
        for (BBTemplate *frag = prev_tb_; frag != nullptr;
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

/*
 * First seal of a segment (or of the builder's life): baseline from LIVE
 * state instead of events.  Events retained up to this point may predate
 * the baseline; the live fault depth reflects all of them, so the whole
 * retained batch is swallowed by the caller (the priming swallow:
 * entries before the first surviving step of a segment never stash and
 * never count).
 */
void PathBuilder::prime_from_live()
{
    raw_depth_ = qemu_plugin_fault_depth();
    base_depth_ = raw_depth_;
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
bool PathBuilder::kexc_kernel_tb_keep(void)
{
    if (!kexc_in_kernel_) {
        kexc_reset();
        kexc_in_kernel_ = true;
        kexc_exc_entry_ = kexc_last_user_asid_;
        kexc_entry_owned_ = kexc_user_owned_;
    }
    bool keep = kexc_have_user_ && kexc_entry_owned_ && !kexc_cut_;
    if (keep) {
        g_stats.kexc_kernel_kept++;
    } else {
        g_stats.kexc_kernel_dropped++;
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
 * resume suffix.  Preferred match: a frame whose FAULT_RETURN was already
 * observed (event identity; the byte-content check is demoted to a
 * diagnostic there).  Fallback: QEMU's fault-stack pop is strict LIFO, so
 * a non-LIFO guest exception return — a context switch inside a blocking
 * fault resuming the OUTER task first — produces NO FAULT_RETURN event
 * even though the suffix genuinely resumes; complete those on the
 * byte-content check alone (the content match is what keeps a same-VA
 * frame from another address space from swallowing an innocent seal).
 */
ptrdiff_t PathBuilder::frame_idx_for_completion(const BBTemplate *suffix) const
{
    if (!suffix) {
        return -1;
    }
    for (size_t i = frames_.size(); i-- > 0; ) {
        const CtxFrame &f = frames_[i];
        if (!(f.returned && f.resume_pc == suffix->start_pc)) {
            continue;
        }
        /* Content guard — the SAME check the fallback loop below uses, and
         * the fix for the cross-ASID completion hazard the header comment
         * names.  A returned frame's resume PC matching the seal is NOT
         * proof of same-address-space identity: owned processes share load
         * VAs, so a frame stashed by ANOTHER process's fault at this VA can
         * carry the matching resume_pc while its template is foreign code.
         * merge_suffix_matches must therefore be a HARD condition, not the
         * old assert: under NDEBUG the assert compiles out, which let a
         * cross-ASID frame silently complete and emit a foreign template in
         * the innocent seal's place.  A genuine resume suffix is
         * byte-identical to the stashed template at the resume position, so
         * this rejects nothing real and leaves single-process output
         * byte-identical (the check always held where the old assert did). */
        if (merge_suffix_matches(f.full_tmpl, suffix)) {
            return (ptrdiff_t)i;
        }
        if (pb_diag()) {
            fprintf(stderr, "[pathbuilder] WARN completion content "
                    "mismatch (cross-ASID guard): frame full=0x%" PRIx64
                    " resume=0x%" PRIx64 " vs suffix=0x%" PRIx64 "\n",
                    f.full_tmpl ? f.full_tmpl->start_pc : 0,
                    f.resume_pc, suffix->start_pc);
        }
    }
    for (size_t i = frames_.size(); i-- > 0; ) {
        const CtxFrame &f = frames_[i];
        if (f.resume_pc == suffix->start_pc &&
            merge_suffix_matches(f.full_tmpl, suffix)) {
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
                PRIx64 " depth=%u nmem=%zu nanchor=%zu frames=%zu\n",
                f.full_tmpl ? f.full_tmpl->start_pc : 0, resume_pc, f.depth,
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
                                       bool *prev_stashed)
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

    /* Async mute window.  Until the first seal-phase prime the live flag
     * is authoritative (it already reflects every retained event); after
     * that the ordered edges drive it.  Assignment semantics make the
     * rescan of retained events across a bailed step idempotent.  An
     * ASYNC_RETURN drained this step unmutes the resume TB's body
     * callbacks (the event precedes the resume TB's execution). */
    if (!primed_) {
        async_excluding_ = qemu_plugin_in_async_int();
        async_departure_pc_ = 0;    /* pre-prime windows carry no pc */
    } else {
        for (const struct qemu_plugin_cpu_event &ev : pending_evs_) {
            if (ev.kind == QEMU_PLUGIN_CPU_EV_ASYNC_ENTER) {
                async_excluding_ = true;
                async_departure_pc_ = ev.pc;
            } else if (ev.kind == QEMU_PLUGIN_CPU_EV_ASYNC_RETURN) {
                async_excluding_ = false;
                async_departure_pc_ = 0;
            }
            /* ASID_WRITE (kind 4) is window-neutral: consumed by the
             * kexc ownership pass at drain time above, explicitly
             * ignored here on the legacy (kexc=0) rule. */
        }
    }
    g_capture_mute = async_excluding_;

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
             * the segment prime), drop prev like the foreign-ASID
             * boundary does — prev's accumulated memops die with it, or
             * they would collapse onto the next entry's slots. */
            qemu_plugin_async_int_reset();
            async_excluding_ = false;
            g_capture_mute = false;
            if (async_departure_pc_) {
                seal_pc_override_ = async_departure_pc_;
                async_departure_pc_ = 0;
            } else if (prev_tb_) {
                g_mem_recorder.clear_cp();
                pending_reg_snaps.clear();
                clear_prev();
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
            drop = !kexc_kernel_tb_keep();
        }
        if (drop) {
            /* rearch: suspend-or-seal candidate.  For now the deferred
             * prev is DROPPED — the one-TB lossy boundary — rather than
             * suspended, so its fragments never bridge across the
             * gap.
             *
             * Prev's memops die with it: they are still sitting in the
             * CP accumulator (drained only at prev's emit, which now
             * never happens) and would otherwise be attributed to the
             * NEXT emitted entry — whose template contains none of
             * their PCs, collapsing them onto insn 0 as a phantom blob
             * and displacing that entry's own memops in the drain's
             * monotonic walk.  The TB being dispatched right now is
             * equally unemitted, so mute its upcoming accesses too;
             * the step recomputes g_capture_mute at every dispatch, so
             * the mute self-clears with the foreign span. */
            g_mem_recorder.clear_cp();
            g_capture_mute = true;
            clear_prev();
            return StepStatus::DROPPED_FOREIGN;
        }
    }

    /* Promote: cur becomes the pending seal; the seal phase walks the
     * OLD prev with the depth stamped when it executed.  Cur's own stamp
     * is written by the seal phase after the fault events apply (on a
     * step bailing between the phases the stamp stays stale until the
     * next surviving seal). */
    walk_prev_ = prev_tb_;
    walk_depth_ = prev_depth_;
    set_prev(in.cur);
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
    CtxFrame &f = frames_[idx];
    const PendingEmit &pe = pending_emits.front();
    if (pb_diag()) {
        fprintf(stderr, "[pathbuilder] EMIT full=0x%" PRIx64 " nmem=%zu "
                "branch_pc=0x%" PRIx64 " cur=0x%" PRIx64 " wrong=0x%" PRIx64
                " frames=%zu\n",
                f.full_tmpl ? f.full_tmpl->start_pc : 0, f.mem.size(),
                pe.branch_pc, pe.emit_current_pc, pe.wrong_target,
                frames_.size());
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
    g_emit_fault_depth = f.depth;
    g_emit_fault_anchors = f.anchors;
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
                    classify_fault_enter(ev, &prev_stashed);
                }
            } else if (ev.kind == QEMU_PLUGIN_CPU_EV_FAULT_RETURN) {
                raw_depth_ = ev.depth_after;
                if (fault_on && !pb_no_merge()) {
                    apply_fault_return(ev);
                }
            } else if (fault_on && ev.kind == QEMU_PLUGIN_CPU_EV_ASID_WRITE) {
                /* Guest context switch — the reported address-space
                 * register genuinely changed (a TLB-maintenance write
                 * that leaves the masked field alone emits nothing).
                 * Any fault frames still live on the per-vCPU stack were
                 * pushed by the OUTGOING context; the incoming process is
                 * unrelated to them and establishes its own nesting from
                 * here.  Re-floor the segment baseline to the switch-
                 * instant depth so the incoming context's handlers are
                 * measured against ITS zero, not the stale frames a
                 * non-LIFO switch left behind: a page fault whose handler
                 * the scheduler preempts (an async tick landing inside
                 * the handler, then a switch to another task) never
                 * returns to pop its frame, and without this re-baseline
                 * every later fault under the reused ASID stamps one
                 * level too deep — the intermittent 0->2+ jump the churn
                 * battery's syscall_fault_nesting check flags.  This is
                 * the inflate-side twin of the raw < base re-floor below
                 * (which handles a stale frame finally popping); the
                 * ASID_WRITE event's depth_after carries the live
                 * plugin_fault_depth at the write. */
                base_depth_ = ev.depth_after;
            }
            /* async kinds were applied by step_events.  ASID_WRITE (kind
             * 4) was also consumed at drain time for kexc ownership; here
             * it additionally re-floors the depth baseline across the
             * context switch (above).  On the legacy (fault-off) path it
             * is ignored, as before. */
        }
        pending_evs_.clear();
        /* Baselined, 0-clamped depth the CURRENT TB runs at.  Raw can
         * drop below the segment baseline when a pre-segment fault
         * returns inside the segment; when it does, the baseline
         * RE-FLOORS to the new raw depth rather than clamping forever.
         * The distinction matters because the pre-segment frames under
         * the baseline are not all live excursions: a non-LIFO guest
         * return (a context switch inside a blocking fault resuming the
         * outer task first) never pops its frame, so a busy boot leaves
         * STALE frames on the per-vCPU stack and the prime baselines
         * them in.  When an unrelated in-segment exception return later
         * matches such a frame's resume PC, the pop drops raw below
         * base permanently — without the re-floor, every later
         * excursion's depth clamps to 0 for the rest of the segment
         * (observed: depth-0 TLB-refill handler entries followed by a
         * merged faulting BB whose anchors then violate the depth-
         * nesting invariant). */
        if (raw_depth_ < base_depth_) {
            base_depth_ = raw_depth_;
        }
        depth_next_ = raw_depth_ > base_depth_ ? raw_depth_ - base_depth_ : 0;
    }

    /* Stamp cur (already promoted by step_events) with the depth it runs
     * at, and expose prev's execute-time depth for this step's emits.
     *
     * User-privilege TBs stamp depth 0 regardless of the vCPU's raw
     * fault-stack depth: user code is never fault-handler content, but a
     * preemptible kernel can context-switch INSIDE a blocking fault
     * handler (cond_resched in the fault path) and resume another guest
     * thread's user code while the interrupted task's fault frames are
     * still live on this vCPU's stack — without the clamp those user
     * entries would carry the interrupted excursion's depth (observed:
     * depth-4 user loop blocks under a two-thread yield workload).  The
     * other thread's KERNEL work keeps the raw-baselined depth — the
     * per-vCPU stack cannot attribute frames per guest thread, an
     * accepted approximation. */
    prev_depth_ = (in.pinned && in.live_priv == 0) ? 0 : depth_next_;
    if (fault_on) {
        g_emit_fault_depth = walk_depth_;
    }

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
    ptrdiff_t mtop = -1;
    if (fault_on && !pb_no_merge() && any_finalize && !pending_emits.empty()) {
        mtop = frame_idx_for_completion(pending_emits.front().bb_tmpl);
    }
    if (in.watch_pc && walk_prev_ && walk_prev_->start_pc == in.watch_pc) {
        fprintf(stderr, "[blkwatch] mtop=%td frames=%zu (events)\n",
                mtop, frames_.size());
    }
    if (mtop >= 0) {
        return complete_merge((size_t)mtop, pending_emits, out_stream,
                              in.cpu_index);
    }

    if (!any_finalize) {
        return StepStatus::NO_SEAL;
    }

    for (const PendingEmit &pe : pending_emits) {
        emit_finalized_bb(out_stream, pe.bb_tmpl, pe.branch_pc,
                          pe.emit_current_pc, pe.wrong_target, in.cpu_index);
    }
    return StepStatus::SEALED;
}
