/*
 * ChampSim Tracer — PathBuilder (events-path CP step).
 *
 * One per-vCPU-thread state machine that consumes the ordered per-vCPU
 * path-event queue (qemu_plugin_drain_cpu_events) and performs the
 * correct-path TB-step work: async-window exclusion, foreign-ASID
 * boundary, the deferred-prev pending-seal slot, fault-excursion frames
 * (the whole-BB merge), and emission.
 *
 * The event stream carries the path causality (fault entries/returns,
 * async-window edges); the seal and emission machinery is shared: the
 * seal phase calls the collect_finalized_bbs fragment walk and
 * emit_finalized_bb owned by champsim_tracer.cc.  Each drained event is
 * handled individually — one FAULT_ENTER per fault, FAULT_RETURN marking
 * a frame returnable by event identity — so dense fault storms cannot
 * collapse multiple entries into one observation.
 *
 * The step is split in two around the SHARED window management, because
 * the gate order is load-bearing on both sides of it: the async /
 * foreign-ASID gates and the prev swap run BEFORE tw_manage_window (an
 * async-suspended TB must not drive window decisions, and the marker
 * close's segment-final flush walks the swapped prev), while the fault
 * depth pipeline and entry classification run AFTER the segment-boundary
 * and initial-block gates (entries during bailed steps accumulate to the
 * next surviving step; entries before a segment's first surviving step
 * are swallowed by the depth re-prime).  A single step() would have to
 * own window management itself to keep that order.
 *
 *   glue:  drain -> step_events() -> [shutdown gate, tw_manage_window,
 *          active gate, segment boundary, heartbeat, scoreboard reads]
 *          -> step_seal() -> deferred closes (SEALED only)
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_PATH_BUILDER_H
#define CHAMPSIM_TRACER_PATH_BUILDER_H

#include <cstddef>
#include <vector>

#include "champsim_tracer.h"

/*
 * ---- Shared CP-step machinery owned by champsim_tracer.cc ----
 *
 * The seal walk and emission entry points live in champsim_tracer.cc
 * (they bind to the thread's chain assembler, scoreboard, branch history
 * and stats); PathBuilder calls them, never reimplements them.
 */

/* A finalized true BB awaiting emission, with its terminal-branch
 * classification already resolved.  Collected under data_lock; the actual
 * emit happens later under exec_lock only. */
struct PendingEmit {
    BBTemplate *bb_tmpl;
    uint64_t    branch_pc;
    uint64_t    emit_current_pc;
    uint64_t    wrong_target;
};

/* The fragment walk over the deferred prev TB: folds executed fragments
 * into the CP true-BB chain and collects every completed BB as a
 * PendingEmit.  Caller holds exec_lock; takes data_lock internally. */
bool collect_finalized_bbs(unsigned int cpu_index,
                           BBTemplate *prev_tb_head,
                           uint64_t prev_start, uint64_t current_pc,
                           std::vector<PendingEmit> &pending_emits);

/* Run the WP simulator (if armed) and emit one finalized BB's BodyEntry.
 * Caller holds exec_lock; must NOT hold data_lock. */
void emit_finalized_bb(BodyStreamState *out_stream,
                       BBTemplate *bb_tmpl,
                       uint64_t prev_last,
                       uint64_t current_pc,
                       uint64_t wrong_target,
                       unsigned int cpu_index);

/* Build a BodyEntry from the calling thread's CP memop/reg-snap
 * accumulators (draining them) and write it to @out_stream.  @wp_entries
 * is moved in.  @wp_first_tb_unavail marks a kicked excursion whose
 * first wrong-path target could not be fetched/translated (so
 * @wp_entries is empty); the writer emits it as a chain-level
 * CST_WP_EVENT_TRANSLATION_UNAVAIL event (champsim_tracer_format.md
 * §4.4).  Caller holds exec_lock; data_lock is NOT held.  Used by
 * PathBuilder::flush_final, which emits without branch resolution or WP
 * (unlike emit_finalized_bb above). */
void emit_body_entry(BodyStreamState *out_stream,
                     BBTemplate *bb_tmpl,
                     unsigned int cpu_index,
                     std::vector<WPBBEntry> wp_entries,
                     bool wp_first_tb_unavail = false);

/* Thread-local CP-step accumulators owned by champsim_tracer.cc.
 * PathBuilder moves them into / out of its frames (the stash and the
 * merge re-injection) and stamps the emit-time fault trailer values
 * emit_body_entry reads. */
extern thread_local uint32_t g_emit_fault_depth CST_TLS_HOT;
extern thread_local std::vector<uint32_t> g_emit_fault_anchors CST_TLS_HOT;
extern thread_local std::vector<RegSnap> pending_reg_snaps CST_TLS_HOT;

/*
 * ---- PathBuilder proper ----
 */

/* One in-flight fault excursion: the faulting BB whose pieces are being
 * set aside until its resume suffix seals.  Frame identity comes from
 * the FAULT_ENTER event ({resume_pc, asid} stamped at the fault
 * instant — so a page-fault handler rewriting the MMU context register
 * mid-excursion cannot drift the key), and @returned records the frame's
 * FAULT_RETURN event — the completion is still fired by the resume
 * suffix's SEAL, one or more TB steps later.  (The plan's
 * susp_prev/susp_chain suspend fields arrive with the foreign-ASID
 * suspend-or-seal arrow; until then the foreign-ASID boundary DROPS the
 * deferred prev, so a frame never freezes chain state.) */
struct CtxFrame {
    BBTemplate *full_tmpl = nullptr;   /* the faulting BB's full template */
    uint64_t asid = 0;                 /* event-stamped owning address space */
    uint64_t resume_pc = 0;            /* faulting insn = where ERET lands */
    uint32_t depth = 0;                /* depth the faulting BB ran at */
    bool returned = false;             /* FAULT_RETURN observed, seal pending */
    std::vector<WPMemAccess> mem;      /* accumulated memops (insn_pc-keyed) */
    std::vector<RegSnap> snaps;        /* accumulated reg snaps (insn order) */
    std::vector<uint32_t> anchors;     /* faulting-insn indices in full_tmpl */
};

class PathBuilder {
public:
    /* Everything one CP step needs, sampled by the glue in vcpu_tb_exec
     * under exec_lock: the executing TB, the scoreboard's previous-TB
     * fields, the live pin/ASID/privilege reads (the user-clock fold and
     * is_system stamp already happened in the glue prologue), and this
     * step's drained events.  The same object is passed to both phases;
     * the scoreboard fields are only read by the seal phase. */
    struct StepIn {
        BBTemplate *cur;          /* head fragment of the executing TB */
        uint64_t prev_start;      /* scoreboard prev_start_pc */
        uint64_t prev_ft;         /* scoreboard prev_fall_through */
        uint64_t current_pc;      /* scoreboard current_pc */
        bool pinned;              /* marker-mode ASID pin armed */
        uint64_t pinned_asid;     /* valid iff pinned */
        uint64_t live_asid;       /* live read at TB exec (0 unpinned) */
        int live_priv;            /* live read at TB exec (-1 unpinned) */
        const struct qemu_plugin_cpu_event *evs;
        size_t n_evs;
        unsigned int cpu_index;
        uint64_t watch_pc;        /* CST_BLKWATCH, 0 when unset */
    };

    /* What the step did, so the glue can pick the right continuation:
     * after step_events, only CONTINUE proceeds to window management;
     * after step_seal, only SEALED runs the deferred window closes and
     * consumes the spec-flush latch (the suspend / drop / stash / merge /
     * no-seal outcomes all skip them — a pending close waits for the
     * next normally-sealed step). */
    enum class StepStatus {
        CONTINUE,         /* step_events: proceed to window mgmt + seal */
        SUSPENDED,        /* async window open: prev untouched, TB dropped */
        DROPPED_FOREIGN,  /* foreign ASID: prev dropped (one-TB lossy) */
        STASHED,          /* prev folded into a fault frame; nothing seals */
        NO_SEAL,          /* no previous context / no BB completed */
        MERGED,           /* a fault frame completed and emitted */
        SEALED,           /* normal seal + emit path ran to completion */
    };

    /* Pre-window phase: absorb this step's drained events, apply the
     * async-window edges, refine the capture mute, run the async-suspend
     * / stuck-recovery and foreign-ASID arrows, and on CONTINUE promote
     * cur into the pending-seal slot (snapshotting the old prev + its
     * depth stamp for the seal phase).  Fault events are retained,
     * unapplied, until the seal phase — or across the whole step when a
     * gate bails, so events during bailed steps accumulate to the next
     * surviving step.  Caller holds exec_lock. */
    StepStatus step_events(const StepIn &in);

    /* Post-window phase: initial-block gate, depth pipeline + per-event
     * fault entry classification against the snapshotted prev, the
     * shared seal walk, merge completion, emission.  Caller holds
     * exec_lock and has passed the shutdown / active / segment-boundary
     * gates. */
    StepStatus step_seal(const StepIn &in, BodyStreamState *out_stream);

    /* Per-thread segment-open boundary: drop all frames (orphan drop —
     * their full_tmpl dangles into the cleared bb_map_), clear the
     * pending-seal slot, close any async mute window, discard retained
     * events, zero the depth pipeline and re-prime lazily at the next
     * seal.  The caller also re-enables the event queue, discarding the
     * queue-side backlog that straddles the boundary. */
    void on_segment_open();

    /* Pending-seal slot writes. */
    void set_prev(BBTemplate *tb) { prev_tb_ = tb; }
    void clear_prev() { set_prev(nullptr); }

    /* The pending-seal slot (the deferred prev TB); read by the blkwatch
     * exec print in vcpu_tb_exec's shared prologue. */
    BBTemplate *prev() const { return prev_tb_; }

    /* Flush the pending final-TB body entry before a segment finishes.
     * BodyEntries are emitted lazily — the seal phase emits the
     * *previous* TB's entry once its branch direction is known — so a TB
     * ended by a process-exiting syscall has no "next" TB and its memops
     * would vanish without this.  No wrong-path (WP undefined after
     * exit).  Caller holds exec_lock. */
    void flush_final();

    /* Lazy per-vCPU event-queue enable, done by the glue on this thread's
     * first CP exec (must run on the owning vCPU thread). */
    bool events_queue_enabled() const { return evq_enabled_; }
    void mark_events_queue_enabled(unsigned int cpu_index)
    {
        evq_enabled_ = true;
        cpu_index_ = cpu_index;
    }
    /* Disable across an inter-segment gap: the exec callback (the only
     * consumer) stops firing while the scoreboard is inactive, so a long
     * gap's faults and interrupts would grow the queue unboundedly.
     * The lazy enable at the next active step re-arms it. */
    void events_queue_disable()
    {
        if (evq_enabled_) {
            qemu_plugin_cpu_events_set(cpu_index_, false);
            evq_enabled_ = false;
        }
    }

private:
    void prime_from_live();
    void kexc_apply_asid_write(uint64_t new_asid);
    void kexc_user_tb(uint64_t live_asid);
    bool kexc_kernel_tb_keep(uint64_t pinned_asid);
    void kexc_reset();
    void classify_fault_enter(const struct qemu_plugin_cpu_event &ev,
                              bool *prev_stashed);
    void apply_fault_return(const struct qemu_plugin_cpu_event &ev);
    ptrdiff_t frame_idx_for_resume(uint64_t resume_pc, uint64_t asid) const;
    ptrdiff_t frame_idx_for_completion(const BBTemplate *suffix) const;
    void collect_piece(CtxFrame &f, uint64_t resume_pc);
    BBTemplate *fold_prev_full_bb(BBTemplate *prev);
    StepStatus complete_merge(size_t idx,
                              const std::vector<PendingEmit> &pending_emits,
                              BodyStreamState *out_stream,
                              unsigned int cpu_index);

    /* In-flight fault excursions, fault-nesting order (completion may
     * retire a mid-stack frame; see frame_idx_for_completion). */
    std::vector<CtxFrame> frames_;

    /* Drained-but-unapplied events.  Copied out of the queue's internal
     * buffer at drain time (that buffer is only valid until the next
     * push); async edges are applied by step_events each step (assignment
     * semantics, so re-scanning retained events is idempotent), fault
     * events exactly once by the first step_seal that consumes them. */
    std::vector<struct qemu_plugin_cpu_event> pending_evs_;

    /* The single pending-seal slot: the deferred prev TB, plus the fault
     * depth stamped when it EXECUTED.  Stamping at promote time (not at
     * seal time) is required — the fault stack may pop between a TB's
     * execution and its BBs' emission one step later, and reading depth
     * at seal would lose the handler's level. */
    BBTemplate *prev_tb_ = nullptr;
    uint32_t prev_depth_ = 0;

    /* Cross-phase snapshot: the prev the seal phase walks (and its
     * promote-time depth stamp), captured by step_events before the
     * swap. */
    BBTemplate *walk_prev_ = nullptr;
    uint32_t walk_depth_ = 0;

    /* Depth pipeline: raw_depth_ tracks depth_after of the last fault
     * event; base_depth_ is the segment baseline (a fault in flight
     * across segment-open is baselined out); depth_next_ is the
     * baselined, 0-clamped depth the CURRENT TB runs at (a pre-segment
     * fault returning mid-segment can take raw below base). */
    uint32_t depth_next_ = 0;
    uint32_t raw_depth_ = 0;
    uint32_t base_depth_ = 0;

    /* Async-interrupt mute window, driven by ASYNC_ENTER/ASYNC_RETURN
     * events plus the two local reset arrows that produce NO event
     * (stuck-window recovery, segment open).  Latched from the live flag
     * until the first seal-phase prime. */
    bool async_excluding_ = false;

    /* Lazy per-segment baseline; see prime_from_live(). */
    bool primed_ = false;

    /*
     * ---- Kernel-excursion ownership (kexc=1) ----
     *
     * Who owns a kernel TB?  The user address space the kernel was
     * entered FROM — not whatever the live ASID register happens to
     * hold, because a kernel is free to run under a private address
     * space (PTI-style entry switches) or to scribble save/probe values
     * into the ASID register for TLB maintenance.  All of it is
     * observable architecturally: privilege transitions delimit the
     * excursion and ASID_WRITE path events expose every committed swap.
     *
     *   user TB (priv==0)   ownership resets; live ASID is authoritative
     *                       (the exact legacy rule) and is recorded as
     *                       kexc_last_user_asid_.
     *   kernel-entry edge   the first priv!=0 TB after a priv==0 TB —
     *                       once per excursion, at the OUTERMOST
     *                       user->kernel transition (nested faults
     *                       inside a syscall do not re-fire it):
     *                       exc_entry_ = last_user_asid_, overlay
     *                       cleared, cut cleared.
     *   ASID_WRITE (new V)  only meaningful while in kernel:
     *                         V == exc_entry_   nothing (restore;
     *                                           ownership continues)
     *                         no overlay yet    overlay_ = V (the
     *                                           excursion's kernel
     *                                           overlay — a PTI entry
     *                                           switch or a TLB-
     *                                           maintenance save/probe;
     *                                           NOT a committed switch)
     *                         V == overlay_     nothing
     *                         else              cut_ = true (a third
     *                                           distinct value is a
     *                                           committed context
     *                                           switch; sticky until
     *                                           the next user TB)
     *   kernel TB           keep for the trace iff
     *                       exc_entry_ == pinned && !cut_ (the async
     *                       exclusion has already run).  This REPLACES
     *                       the live-ASID foreign-drop test for priv!=0
     *                       TBs only.
     *
     * Conservative by construction: a TLB-maintenance loop writing two
     * DIFFERENT probe values fakes a cut and under-attributes until the
     * next user TB (counted in kexc_cuts); kernel TBs before a
     * segment's first user TB have no owner and drop.  An ASID_WRITE
     * inside an async window still updates this state (the window's TBs
     * are excluded regardless) so post-window ownership is right.
     * Storm detection only counts distinct values (>= threshold warns
     * once per segment + kexc_write_storm); pin invalidation on ASID
     * rollover is a later policy decision.
     */
    bool     kexc_in_kernel_ = false;   /* excursion open (edge latched) */
    bool     kexc_have_user_ = false;   /* last_user_asid_ is valid */
    uint64_t kexc_last_user_asid_ = 0;
    uint64_t kexc_exc_entry_ = 0;       /* owning ASID at the entry edge */
    bool     kexc_have_overlay_ = false;
    uint64_t kexc_overlay_ = 0;
    bool     kexc_cut_ = false;
    /* Distinct new-values this excursion (storm detection).  Bounded
     * scan is fine: the set never grows past the storm threshold. */
    static constexpr uint32_t KEXC_STORM_THRESHOLD = 16;
    uint64_t kexc_vals_[KEXC_STORM_THRESHOLD];
    uint32_t kexc_nvals_ = 0;
    bool     kexc_stormed_ = false;     /* this excursion already counted */

    bool evq_enabled_ = false;
    unsigned int cpu_index_ = 0;
};

/* The calling vCPU thread's PathBuilder (per-thread by construction:
 * frames, chain, recorder buffer and reg-snap accumulators are all
 * thread-local, and TLS cursors can only be reset from their own
 * thread). */
PathBuilder &path_builder_tls();

/* Free-function trampoline for the segment-finish flush hook
 * (TraceSegmentManager::finish takes a plain callback): flush the
 * calling thread's pending final body entry. */
void path_builder_flush_final();

#endif /* CHAMPSIM_TRACER_PATH_BUILDER_H */
