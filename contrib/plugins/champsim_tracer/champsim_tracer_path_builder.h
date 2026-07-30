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
#include "champsim_tracer_bb_chain_assembler.h"

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
 * CST_WP_EVENT_TRANSLATION_UNAVAIL event (docs/format.rst
 * §4.4).  Caller holds exec_lock; data_lock is NOT held.  Used by
 * PathBuilder::flush_final, which emits without branch resolution or WP
 * (unlike emit_finalized_bb above). */
void emit_body_entry(BodyStreamState *out_stream,
                     BBTemplate *bb_tmpl,
                     unsigned int cpu_index,
                     std::vector<WPBBEntry> wp_entries,
                     bool wp_first_tb_unavail = false,
                     uint64_t branch_successor_pc = 0,
                     bool branch_successor_known = false);

/* Thread-local CP-step accumulators owned by champsim_tracer.cc.
 * PathBuilder moves them into / out of its frames (the stash and the
 * merge re-injection) and stamps the emit-time fault trailer values
 * emit_body_entry reads. */
extern thread_local uint32_t g_emit_fault_depth CST_TLS_HOT;
/* Fault depth stamped on the MOST RECENTLY emitted body entry of this
 * thread (set by emit_body_entry).  Read by the unwind-flush anchor guard
 * so a leaked inner frame is only emitted at the unwind when its depth is
 * strictly shallower than its predecessor (an anchored entry must follow a
 * deeper one); never write it elsewhere. */
extern thread_local uint32_t g_last_emit_fault_depth;
extern thread_local uint64_t g_dbg_last_emit_seq;

/* ---- CST_JUMP_DIAG: online depth-step violation detector (diagnostic) ----
 *
 * The syscall_fault_nesting oracle is an OFFLINE check over the finished
 * wire, so a violation names a seq number with no view of the machinery
 * state that produced it.  These mirrors let emit_body_entry raise the same
 * assertion ONLINE, at the instant of the emit, with the pipeline state and
 * a ring of the preceding steps attached.  Every write is a plain store on
 * a path that already runs; the reads happen only under the env gate.
 * Control-flow inert: nothing here is consulted by the tracer's logic. */
enum CstDepthSrc : uint8_t {
    CST_DSRC_NONE = 0,
    CST_DSRC_PIPELINE,       /* step_seal: g_emit_fault_depth = walk_depth_ */
    CST_DSRC_MERGE,          /* complete_merge, anchored at f.depth         */
    CST_DSRC_MERGE_PLAIN,    /* complete_merge, de-anchored to last_emit    */
    CST_DSRC_MERGE_ZERO,     /* complete_merge deeper-frame flush at 0      */
    CST_DSRC_UNWIND,         /* flush_frame_unwound at f.depth              */
    CST_DSRC_FLUSH_FINAL,    /* segment-final flush                         */
};
/* Provenance of prev_depth_ / walk_depth_, so a restored suspension's frozen
 * stamp is distinguishable from a freshly computed one. */
enum CstPrevDepthSrc : uint8_t {
    CST_PDSRC_NONE = 0,
    CST_PDSRC_SEAL,          /* computed from frames_ at this step's seal   */
    CST_PDSRC_RESUME,        /* restored from a SuspendedPrev's frozen stamp*/
};
/* PROCESS-WIDE, deliberately NOT thread_local.  The plugin is dlopen'd, so
 * its whole TLS block comes out of glibc's static-TLS surplus (1664 B); the
 * tracer already sits at ~1640 B, so ANY new thread_local fails the plugin
 * load outright ("cannot allocate memory in static TLS block").  Correctness
 * is unaffected: every writer runs inside vcpu_tb_exec under exec_lock, which
 * serialises the CP step (including nested WP), so these are ordered exactly
 * as the body stream they describe. */
extern uint8_t  g_dbg_depth_src;
extern uint8_t  g_dbg_prev_depth_src;
extern uint8_t  g_dbg_walk_depth_src;
extern uint32_t g_dbg_raw_depth;
extern uint32_t g_dbg_inflight;
extern uint32_t g_dbg_async_captured;
extern uint32_t g_dbg_depth_next;
extern uint32_t g_dbg_prev_depth;
extern uint32_t g_dbg_walk_depth;
extern size_t   g_dbg_frames;
extern size_t   g_dbg_susp;

bool cst_jump_diag(void);
/* Record one seal-phase step into the ring (no-op unless gated). */
void cst_jump_diag_step(uint64_t cur_pc, uint64_t prev_pc, int priv,
                        int pinned, const char *tag);
/* Raise the online assertion for an emit at @depth (no-op unless gated). */
void cst_jump_diag_emit(uint64_t seq, uint32_t tid, uint64_t pc,
                        uint32_t depth, int is_sys, size_t n_anchors);
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
 * suffix's SEAL, one or more TB steps later.  (The foreign-ASID
 * suspend-or-seal arrow freezes the deferred prev in a SuspendedPrev
 * instead of dropping it, so a frame never loses chain state.
 * SuspendedPrev keys on this SAME (thread,asid): susp_.asid =
 * StepIn::pinned_asid at suspend time, and a resume requires the resuming
 * TB's effective asid to match — the identical key frame_idx_for_completion
 * uses, so a suspension cannot be resumed cross-process.) */
/* One suspended deferred-prev: the four thread-local sinks the seal phase
 * consumes, frozen atomically across a foreign-ASID span (plan §1.1) so the
 * pinned process's resume seals the interrupted block at its own depth
 * instead of the block being DROPPED and its fault level lost (the
 * manifestation-2/3 fix).  Keyed on the OWNING (thread,asid): @asid is the
 * pinned effective asid (StepIn::pinned_asid) sampled at the block's promote
 * — the Stage-2 frame-identity key (the dwell tag on narrow-ASID targets) —
 * and @owner_live is the live asid the block executed under (a wide-register
 * per-process discriminator: a constant marker pin cannot tell two owned
 * x86 processes apart, but their CR3s can).  A resume requires BOTH to
 * match, so a suspension can never be restored into a foreign context. */
struct SuspendedPrev {
    BBTemplate *prev = nullptr;         /* the deferred prev block; its seal
                                         * emits the intermediate level */
    uint32_t depth = 0;                 /* prev's promote-time depth stamp */
    uint64_t asid = 0;                  /* owning pinned effective asid */
    uint64_t owner_live = 0;            /* owning live asid (wide discriminator) */
    std::vector<WPMemAccess> mem;       /* prev's committed CP memops */
    std::vector<RegSnap> snaps;         /* prev's per-insn dst snaps */
    BBChainAssembler::ChainState chain; /* in-flight chain prefix (page-split BB) */
};

struct CtxFrame {
    BBTemplate *full_tmpl = nullptr;   /* the faulting BB's full template */
    uint64_t asid = 0;                 /* event-stamped owning address space;
                                        * the (thread,asid) match key for
                                        * resume / block / completion — and,
                                        * Stage 3, suspend/resume */
    uint64_t resume_pc = 0;            /* faulting insn = where ERET lands */
    uint32_t depth = 0;                /* depth the faulting BB ran at */
    uint32_t tid = 0;                  /* OWNING guest thread: the identity
                                        * the faulting BB is emitted with.
                                        * frames_ is per-vCPU, but a vCPU
                                        * multiplexes guest threads, so an
                                        * excursion belongs to the thread that
                                        * entered it — a peer thread scheduled
                                        * on the same vCPU is at its own
                                        * nesting depth (format.rst §4.2a:
                                        * fault_depth is the depth THIS basic
                                        * block executed at) */
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
        uint64_t pinned_asid;     /* the vCPU's EFFECTIVE pin (dwell tag
                                   * on narrow-ASID targets, marker-time
                                   * value on wide ones); valid iff
                                   * pinned */
        uint64_t live_asid;       /* live read at TB exec (0 unpinned) */
        int live_priv;            /* live read at TB exec (-1 unpinned) */
        bool user_owned;          /* priv==0 TB owned by the pinned
                                   * process (pin_user_tb_owned: legacy
                                   * ASID equality on wide targets,
                                   * physical-page verification on
                                   * narrow ones); false for kernel TBs
                                   * and when unpinned */
        const struct qemu_plugin_cpu_event *evs;
        size_t n_evs;
        unsigned int cpu_index;
        uint64_t watch_pc;        /* CST_BLKWATCH, 0 when unset */
        /* Guest-thread identities across the seal boundary (seal phase
         * only; the glue fills them just before step_seal).  @walk_tid is
         * the COMMITTED identity — the thread that ran the deferred prev
         * this seal emits, hence the owner of any fault frame the seal
         * opens for it.  @cur_tid is the thread the TB executing NOW
         * belongs to, hence whose frames the depth stamp counts.  Equal
         * except on the step where the guest scheduler switched tasks on
         * this vCPU; in user mode both are cpu_index. */
        uint32_t walk_tid = 0;
        uint32_t cur_tid = 0;
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
        SUSPENDED_FOREIGN,/* foreign ASID: prev SUSPENDED onto the stack for
                           * the pinned process's resume */
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
     * exit).  Caller holds exec_lock.
     *
     * @walk_prev says whether the pending-seal slot holds a TB that has
     * RUN.  It does on every close the guest's own progress raises —
     * process exit, the END marker, the dead-latch sweep — which is the
     * case this flush exists for: the slot's TB executed (wholly, or up
     * to the scoreboard's last-executed fragment) and its memops and dst
     * snaps sit in this thread's accumulators awaiting a successor step
     * that will never come.  It does NOT on the deferred icount /
     * simpoint window close, which fires at the tail of a step that has
     * just promoted the *currently dispatching* TB into the slot: walking
     * it there emits instructions before they execute, against empty
     * accumulators (see run_deferred_window_closes).  The in-flight chain
     * is finalized either way. */
    void flush_final(bool walk_prev = true);

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
    void kexc_user_tb(uint64_t live_asid, bool owned);
    /* @in supplies the executing fragment (block PC + instruction count) and
     * the live / pinned ASIDs, all of which feed only the ownership-census
     * instrumentation; the keep rule itself reads excursion state alone. */
    bool kexc_kernel_tb_keep(const StepIn &in);
    void kexc_reset();
    /* @owner_tid is StepIn::walk_tid: a frame opened here is the deferred
     * prev's excursion, so the thread that ran that block owns it. */
    void classify_fault_enter(const struct qemu_plugin_cpu_event &ev,
                              bool *prev_stashed, uint32_t owner_tid);
    void apply_fault_return(const struct qemu_plugin_cpu_event &ev);
    ptrdiff_t frame_idx_for_resume(uint64_t resume_pc, uint64_t asid) const;
    ptrdiff_t frame_idx_for_block(const BBTemplate *piece, uint64_t resume,
                                  uint64_t asid) const;
    /* Completion candidate for a just-sealed BB claiming to be some frame's
     * resume suffix.  @seal_asid is the pinned process's effective asid at
     * the seal (StepIn::pinned_asid = pin_effective_asid): a frame can only
     * complete against a suffix sealed in ITS OWN (thread,asid) — the thread
     * dimension is implicit (PathBuilder is per-vCPU-thread TLS), and this
     * asid is the second half of the (thread,asid) key.  USER frames match
     * the hard asid key (merge_suffix_matches is a PURE DIAGNOSTIC there —
     * Decision C); KERNEL-code frames (is_system) also complete on the
     * byte-content path when the key misses, because kernel fault events
     * stamp the loaded mm, not ownership (see the .cc comment). */
    static bool frame_matches_completion(const CtxFrame &f,
                                         const BBTemplate *suffix,
                                         uint64_t seal_asid);
    ptrdiff_t frame_idx_for_completion(const BBTemplate *suffix,
                                       uint64_t seal_asid) const;
    void collect_piece(CtxFrame &f, uint64_t resume_pc);
    BBTemplate *fold_prev_full_bb(BBTemplate *prev);
    StepStatus complete_merge(size_t idx,
                              const std::vector<PendingEmit> &pending_emits,
                              BodyStreamState *out_stream,
                              unsigned int cpu_index);
    /* Unwind flush: emit frames_[idx]'s merged faulting BB at its own
     * fault depth + anchors, using the frame's OWN accumulated buffers
     * (the current CP / reg-snap accumulators are saved and restored), no
     * wrong-path, unresolved terminal branch — then erase the frame.  This
     * retires an inner fault frame AT ITS RETURN when its resume suffix was
     * dropped / never sealed under host contention, so its depth level is
     * emitted (the interrupted BB carries the depth it ran at) instead of
     * being collaterally lost and collapsed into a >1 depth jump.  Guarded
     * against an anchor-at-unwind violation via g_last_emit_fault_depth.
     * Caller holds exec_lock; data_lock is NOT held. */
    void flush_frame_unwound(size_t idx, BodyStreamState *out_stream,
                             unsigned int cpu_index);
    /* Retire-at-return on the block @prev (the pinned process's own deferred
     * prev, matched within its (thread,asid)): if @prev is an inner fault
     * frame's resume suffix, flush that frame at its depth via
     * flush_frame_unwound so its level is not lost.  Fetches the active body
     * stream itself (no-op when no segment is active).  Used for a
     * suspension retired without resuming (over-cap displacement / stale
     * sweep).  @seal_asid is the owning effective asid, so the retired frame
     * is matched within one (thread,asid) — same key as completion. */
    void retire_prev_frame(BBTemplate *prev, uint64_t seal_asid,
                           unsigned int cpu_index);

    /* Suspend-or-seal arrows (Stage 3, plan §1.2/§1.3).  suspend_prev freezes
     * the deferred prev + its four sinks onto susp_stack_ (over-cap: retire
     * the oldest via retire_prev_frame and evict it); resume_suspension pops
     * the entry whose (asid, owner_live) matches the resuming context and
     * restores the four sinks so the seal walks the suspended prev; the
     * @cpu_index is only needed for the over-cap retire. */
    void suspend_prev(uint64_t owner_asid, uint64_t owner_live,
                      unsigned int cpu_index);
    bool resume_suspension(uint64_t resume_asid, uint64_t resume_live);
    /* Emit a held suspension's fault level via retire_prev_frame, then drop
     * it from the stack (the "suspend couldn't cover this" tail). */
    void retire_suspension(size_t idx, unsigned int cpu_index);

    /* In-flight fault excursions, fault-nesting order (completion may
     * retire a mid-stack frame; see frame_idx_for_completion). */
    std::vector<CtxFrame> frames_;

    /* Suspended deferred-prev blocks (Stage 3).  A bounded stack — nested
     * foreign/async spans across different (thread,asid) owners each push an
     * entry, and a resume pops the matching one (Decision A); over-cap the
     * oldest falls back to retire-at-return.  Orphan-dropped at
     * on_segment_open (like frames_).  Empty off the contention path. */
    std::vector<SuspendedPrev> susp_stack_;
    static constexpr size_t SUSP_STACK_CAP = 8;

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

    /* Owner identity of the current pending-seal prev, sampled at its promote
     * (Stage 3): the (thread,asid) the block executed under, frozen into a
     * suspension so a resume matches the SAME owned process.  prev_owner_asid_
     * is the pinned effective asid (dwell tag on narrow targets); prev_owner_
     * live_ is the live asid (the wide-register per-process discriminator).
     * Both restored from a suspension on resume so a re-suspension re-freezes
     * the right owner. */
    uint64_t prev_owner_asid_ = 0;
    uint64_t prev_owner_live_ = 0;

    /* Cross-phase snapshot: the prev the seal phase walks (and its
     * promote-time depth stamp), captured by step_events before the
     * swap. */
    BBTemplate *walk_prev_ = nullptr;
    uint32_t walk_depth_ = 0;

    /* Depth pipeline.  depth_next_ is the fault-nesting depth the CURRENT
     * TB runs at; it is the count of the pinned process's OWN un-returned
     * merge frames (see step_seal), NOT a function of the per-vCPU
     * plugin_fault_depth.  The raw stack is a single object shared by every
     * guest process and, under multi-process churn, mixes the pinned
     * process's frames with a busy boot's leaked frames and the churn
     * tasks' transient ones — no per-vCPU baseline scalar can partition it,
     * so the trailer counts our own frames instead.  raw_depth_ tracks
     * depth_after of the last fault event for the CST_DEPTH_DIAG log only. */
    uint32_t depth_next_ = 0;

    /* Stamp cur's fault depth (and the faults=0 sync-span flag) from the
     * CURRENT frame ledger, counting only the frames StepIn::cur_tid owns.
     * Called twice per seal — after the event drain and again after the seal
     * walk's merge completions retire frames — so a block following a
     * reassembled faulting BB carries the post-unwind depth.  See the
     * definition for why the second call is load-bearing. */
    void stamp_cur_depth(const StepIn &in, bool post_merge = false);
    uint32_t raw_depth_ = 0;

    /* Captured asynchronous-interrupt depth (interrupts=1 only).  QEMU emits
     * one ASYNC_ENTER at the outermost async delivery and one ASYNC_RETURN at
     * the outermost return, so a captured window contributes exactly one
     * level: 0 outside a window, 1 while an async handler is being traced.
     * Added to the synchronous-fault frame count to form the emitted depth
     * trailer, so an async handler taking a sync fault nests one level deeper.
     * Assignment (not increment) keeps the retained-event rescan idempotent.
     * Always 0 with interrupts=0 (the window is muted, never captured), so the
     * depth trailer stays byte-identical to today. */
    uint32_t async_captured_ = 0;

    /* Synchronous-fault-span markers for faults=0 handler suppression.  A
     * block that executed while this thread had an un-returned synchronous
     * fault frame in flight is handler content — excluded when trace_faults is
     * off.  prev_in_sync_ is stamped for the pending-seal prev at the seal (a
     * user-privilege TB is never handler content, so it stamps false, mirroring
     * the depth clamp); walk_in_sync_ captures it at the promote, so the seal
     * phase suppresses the emit of a handler block by the same
     * stamp-at-execution rule the depth uses.  Untouched (and unread) with
     * faults=1, so the default path is byte-identical. */
    bool prev_in_sync_ = false;
    bool walk_in_sync_ = false;

    /* Async-interrupt mute window, driven by ASYNC_ENTER/ASYNC_RETURN
     * events plus the two local reset arrows that produce NO event
     * (stuck-window recovery, segment open).  Latched from the live flag
     * until the first seal-phase prime. */
    bool async_excluding_ = false;

    /* Departure PC of the open async window: the pc of the outermost
     * ASYNC_ENTER (QEMU emits the event only at the outermost entry, so
     * the last un-returned ENTER's pc is exactly where the interrupted
     * flow would resume — the deferred prev's true successor).  Tracked
     * by the same assignment-semantics event sweep as the mute flag;
     * 0 when no window is open or the window predates the segment
     * prime (the live-flag latch carries no pc). */
    uint64_t async_departure_pc_ = 0;

    /* One-step seal-successor override, set by the stuck-window
     * recovery: the abandoned window means execution resumed in ANOTHER
     * guest thread (a proper resume refetches the departure PC and
     * closes the window with an ASYNC_RETURN instead), so the TB
     * executing now is not the deferred prev's successor.  The seal
     * phase substitutes this PC — the window's departure PC — for the
     * scoreboard's current_pc, making the abandoned-window seal
     * byte-identical to a proper resume's: same-flow adjacency only,
     * never the other thread's PC (the cross-thread taken-edge
     * poisoning).  Cleared at every step_events entry (a recovery step
     * always survives to its own seal). */
    uint64_t seal_pc_override_ = 0;

    /* Lazy per-segment baseline; see prime_from_live(). */
    bool primed_ = false;

    /* Segment-boundary reg-snap hygiene (Case C: marker-block leak).  The
     * block that OPENS a segment captures its own per-insn dst snaps AFTER
     * the open — the START marker's magic-value write among them — but its
     * seal is skipped (marker mode: its own vcpu_tb_exec was JIT-gated off
     * pre-open; window mode: on_segment_open drops it as one-TB-lossy), so
     * those snaps would prepend to the first REAL block's positional reg-snap
     * stream.  seg_gen_seen_ detects the first step in a new segment (marker
     * mode, where on_segment_open never runs); drop_open_leak_pending_ is the
     * one-shot follow-up clear for the window-mode opener whose leak lands
     * the step AFTER its own on_segment_open. */
    uint32_t seg_gen_seen_ = 0;
    bool drop_open_leak_pending_ = false;

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
     *   user TB (priv==0)   ownership resets; the step glue's
     *                       pin_user_tb_owned verdict is recorded as
     *                       kexc_user_owned_ (on wide-register targets
     *                       that is the exact legacy live-ASID
     *                       equality; on narrow-ASID targets it is the
     *                       physical-page verification — a raw value
     *                       match after a rollover is not identity),
     *                       and the live ASID as kexc_last_user_asid_.
     *   kernel-entry edge   the first priv!=0 TB after a priv==0 TB —
     *                       once per excursion, at the OUTERMOST
     *                       user->kernel transition (nested faults
     *                       inside a syscall do not re-fire it):
     *                       exc_entry_ = last_user_asid_, entry_owned_
     *                       = user_owned_, overlay cleared, cut
     *                       cleared.
     *   ASID_WRITE (new V)  only meaningful while in kernel:
     *                         V == exc_entry_   restore: the entering
     *                                           address space is loaded
     *                                           again, so ownership
     *                                           continues — which means
     *                                           retiring any standing cut
     *                                           (it described an address
     *                                           space that is no longer in
     *                                           force).  The overlay is
     *                                           kept, so a further third
     *                                           value cuts again.
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
     *                       entry_owned_ && !cut_ (the async
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
    bool     kexc_user_owned_ = false;  /* last user TB's ownership
                                         * verdict (TB-history: survives
                                         * kexc_reset with last_user) */
    uint64_t kexc_exc_entry_ = 0;       /* owning ASID at the entry edge */
    bool     kexc_entry_owned_ = false; /* ownership latched at the edge */
    bool     kexc_have_overlay_ = false;
    uint64_t kexc_overlay_ = 0;
    bool     kexc_cut_ = false;
    /* This excursion has seen an entry-ASID restore that retired a standing
     * cut.  Instrumentation only (it partitions the kernel TBs that the
     * sticky-cut defect used to refuse); never consulted by the keep rule. */
    bool     kexc_restored_after_cut_ = false;
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

/* Free-function trampolines for the segment-finish flush hook
 * (TraceSegmentManager::finish takes a plain callback): flush the
 * calling thread's pending final body entry.  The _chain_only variant
 * is PathBuilder::flush_final(false) — the deferred window close, whose
 * pending-seal slot holds a TB that has not run yet. */
void path_builder_flush_final();
void path_builder_flush_final_chain_only();

#endif /* CHAMPSIM_TRACER_PATH_BUILDER_H */
