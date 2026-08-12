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

#include "champsim_tracer_wp_thread_state.h"
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
/*
 * A block SEALED BECAUSE CONTROL LEFT IT: the walk found the next fragment
 * does not continue the in-flight chain, so that chain will never reach a
 * terminating branch.  Its instructions executed, so it is emitted at the
 * extent that ran instead of being discarded.  @snap_lo / @snap_hi are the
 * half-open range of the positional reg-snap sink that belongs to it — the
 * sink is a FIFO shared with the blocks this walk goes on to emit, so the
 * cut block takes its own prefix and leaves the rest.
 */
struct CutEmit {
    BBTemplate *bb_tmpl;
    size_t      snap_lo;
    size_t      snap_hi;
};

bool collect_finalized_bbs(unsigned int cpu_index,
                           BBTemplate *prev_tb_head,
                           uint64_t prev_start, uint64_t current_pc,
                           std::vector<PendingEmit> &pending_emits,
                           std::vector<CutEmit> &cut_emits);

/* Run the WP simulator (if armed) and emit one finalized BB's BodyEntry.
 * @bb_start is the entry's declared range start: 0 for an ordinary seal,
 * the resume index for a fault continuation (same template, bb_start =
 * index(resume_pc); §4.2a).  The range always runs to the template's end
 * — a seal resolves the terminating branch, which is the last insn.
 * Caller holds exec_lock; must NOT hold data_lock. */
void emit_finalized_bb(BodyStreamState *out_stream,
                       BBTemplate *bb_tmpl,
                       uint64_t prev_last,
                       uint64_t current_pc,
                       uint64_t wrong_target,
                       unsigned int cpu_index,
                       uint32_t bb_start = 0);

/* Build a BodyEntry from the calling thread's CP memop/reg-snap
 * accumulators (draining them FOR THE DECLARED RANGE) and write it to
 * @out_stream.  @wp_entries is moved in.  @wp_first_tb_unavail marks a
 * kicked excursion whose first wrong-path target could not be
 * fetched/translated (so @wp_entries is empty); the writer raises
 * CST_BB_FLAG_WP_FIRST_TARGET_UNAVAIL on the CP block record
 * (docs/format.rst §4.4).
 *
 * @bb_start / @bb_stop declare the executed range [bb_start, bb_stop) of
 * @bb_tmpl's instructions this entry FULLY OBSERVED (§4.2a) — REQUIRED,
 * no default: every call site states its range, [0, n_insns) for a
 * whole-block run.  The CP memop drain takes only memops attributed
 * inside the range and leaves the rest for the continuation entry;
 * billing (covered / wire arch-insn counters) advances by the range's
 * width, never the template's.  @thread_end marks the context's final
 * entry of the segment (CST_BB_FLAG_THREAD_END).
 *
 * Caller holds exec_lock; data_lock is NOT held. */
void emit_body_entry(BodyStreamState *out_stream,
                     BBTemplate *bb_tmpl,
                     unsigned int cpu_index,
                     std::vector<WPBBEntry> wp_entries,
                     bool wp_first_tb_unavail,
                     uint64_t branch_successor_pc,
                     bool branch_successor_known,
                     uint32_t bb_start,
                     uint32_t bb_stop,
                     bool thread_end = false);

/* CP-step accumulators owned by champsim_tracer.cc.  PathBuilder moves
 * them into / out of its frames (the stash and the merge re-injection)
 * and stamps the emit-time fault trailer values emit_body_entry reads.
 *
 * g_emit_fault_depth is a TRANSFER REGISTER: written by the seal phase
 * and consumed by emit_body_entry within the same exec_lock'd CP step,
 * never across steps — so thread_local is safe under BOTH threading
 * models (MTTCG: one thread per vCPU; round-robin: one thread total,
 * and a step cannot be preempted mid-dispatch). */
extern thread_local uint32_t g_emit_fault_depth CST_TLS_HOT;
/* Fault depth stamped on the MOST RECENTLY emitted body entry of a
 * vCPU's stream (set by emit_body_entry).  Read by the unwind-flush
 * anchor guard so a leaked inner frame is only emitted at the unwind
 * when its depth is strictly shallower than its predecessor (an
 * anchored entry must follow a deeper one); never write it elsewhere.
 * Per-vCPU (NOT thread-keyed): it carries meaning across CP steps, and
 * under round-robin TCG consecutive steps on the one host thread
 * belong to different vCPUs. */
uint32_t &last_emit_fault_depth(unsigned int cpu_index);
/* CST diag correlation: seq_num of the most recent body entry emitted
 * process-wide.  A wire-position cursor for the gap/jump diagnostics;
 * plain static like the g_dbg_* mirrors below (every writer runs under
 * exec_lock). */
extern uint64_t g_dbg_last_emit_seq;

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
/* Provenance of prev_depth_ / walk_depth_. */
enum CstPrevDepthSrc : uint8_t {
    CST_PDSRC_NONE = 0,
    CST_PDSRC_SEAL,          /* computed from frames_ at this step's seal   */
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

bool cst_jump_diag(void);
/* Record one seal-phase step into the ring (no-op unless gated). */
void cst_jump_diag_step(uint64_t cur_pc, uint64_t prev_pc, int priv,
                        int pinned, const char *tag);
/* Raise the online assertion for an emit at @depth (no-op unless gated). */
void cst_jump_diag_emit(uint64_t seq, uint32_t tid, uint64_t pc,
                        uint32_t depth, int is_sys, size_t n_anchors);
/* Tail-insn dst snaps awaiting their BB's emission.  Captured during a
 * TB's body, drained at that vCPU's NEXT CP step — a lifetime that
 * crosses dispatches, so it must be keyed by vCPU, not by host thread
 * (under round-robin TCG the next dispatch on the thread may belong to
 * the other vCPU). */
std::vector<RegSnap> &pending_reg_snaps(unsigned int cpu_index);

/* How many of those, counted from the front, belong to the CP chain still
 * in flight (fragments appended, true BB not yet finalized).  Owned by
 * cp_chain_append; a departure emit resets it with the sink it clears. */
size_t &cp_chain_snap_mark(unsigned int cpu_index);

/* How many instructions of the dispatched TB whose head is @head actually
 * executed on @cpu_index.  False when the retired cursor cannot answer for
 * that TB — see the definition in champsim_tracer.cc. */
bool retired_executed_of(unsigned int cpu_index, const BBTemplate *head,
                         uint64_t *out);

/* The same, asked specifically of the PREVIOUS dispatch — the only sound
 * question for a per-execution reader, because a self-branching TB occupies
 * both dispatch slots at once.  See the definition in champsim_tracer.cc. */
bool retired_executed_prev(unsigned int cpu_index, const BBTemplate *head,
                           uint64_t *out);

/* Is @head the block the guest is standing IN on @cpu_index — the current
 * dispatch, and only that?  The one question a mid-instruction fact may be
 * applied to.  See the definition in champsim_tracer.cc. */
bool retired_is_in_flight(unsigned int cpu_index, const BBTemplate *head);

/* Close census: one pending-seal slot promote.  Out of line because the
 * g_stats macro is not in scope in this header (stats.h is included after
 * it in every TU). */
void census_note_prev_promote(void);

/*
 * THE DISPATCH CLOCK EVERY BUILDER SHARES.
 *
 * Bumped once per pending-seal promote, in PathBuilder::set_prev, which
 * runs only inside step_events under exec_lock — so it is a total order
 * over the dispatches of every vCPU, and comparing two builders' stamps
 * answers "which of these blocks ran first" across vCPUs.  Nothing else
 * on the tracer can: the retired cursor is per-vCPU and the window clock
 * counts instructions, not order.
 *
 * The close needs exactly that.  A close happens on ONE vCPU while peers
 * may each be holding a block that EXECUTED and was waiting for a next
 * owned dispatch that never came; emitting them after the closing vCPU's
 * own final block appends work the guest ran EARLIER behind work it ran
 * later, and a consumer reading one (asid, thread_id) context as a single
 * instruction stream — the guarantee docs/format.rst calls strand
 * sequentiality — sees a break the format does not document.
 */
extern uint64_t g_promote_seq;

/* CST_SEALEXT: per-seal diagnostic print for unanswered extent questions. */
bool seal_extent_diag(void);

/* Index of @pc among the instructions of the dispatched TB whose head is
 * @head (fragments walked in execution order), or UINT32_MAX. */
uint32_t tb_head_insn_index(const BBTemplate *head, uint64_t pc);

/* Take @insns back off the window clock: a re-executing fault's aborted
 * attempt was billed by insn_started and the instructions it aborted are
 * about to run again.  See the definition in champsim_tracer.cc. */
void user_clock_fault_recredit(unsigned int cpu_index, uint64_t insns);

/*
 * ---- PathBuilder proper ----
 */

/* One in-flight fault excursion — an IDENTITY AND DEPTH LEDGER ENTRY,
 * nothing more.  Under split emission the interrupted block's executed
 * prefix went on the wire AT THE FAULT (classify_fault_enter emits
 * [0, k) the moment the FAULT_ENTER classifies), so a frame holds no
 * memops, no reg snaps, no piece tables: it records only WHICH block is
 * awaiting its continuation and at what depth, so the resumed suffix can
 * be emitted as the SAME template with bb_start = index(resume_pc), and
 * so the depth pipeline can count the thread's un-returned excursions.
 * Frame identity comes from the FAULT_ENTER event ({resume_pc, asid}
 * stamped at the fault instant); @returned records the FAULT_RETURN —
 * the continuation is still fired by the resume suffix's SEAL, one or
 * more TB steps later. */
struct CtxFrame {
    BBTemplate *full_tmpl = nullptr;   /* the faulting BB's full template */
    uint64_t asid = 0;                 /* event-stamped owning address space;
                                        * the (thread,asid) completion key */
    uint64_t resume_pc = 0;            /* faulting insn = where ERET lands */
    uint32_t depth = 0;                /* depth the faulting BB ran at */
    uint8_t async_in_depth = 0;        /* the captured-async component (0/1)
                                        * frozen inside @depth at the stamp;
                                        * the continuation emits at the
                                        * frame's SYNCHRONOUS depth plus the
                                        * owner's async level AT COMPLETION */
    /* The OWNING thread's raw thread pointer at the frame's FAULT_ENTER
     * (the event's own delivery-instant stamp) — the async-level
     * re-derivation compares this against the window owner. */
    uint64_t owner_tp = 0;
    bool owner_tp_ok = false;
    uint32_t tid = 0;                  /* OWNING guest thread (format.rst
                                        * §4.2a: fault_depth is per-thread) */
    bool returned = false;             /* FAULT_RETURN observed */
    /* How many instructions of @full_tmpl this excursion has already put
     * on the wire — the next continuation's bb_start.  Starts at the
     * first fault's prefix length; a case-(a2) later fault advances it
     * past the mid-suffix continuation it emits. */
    uint32_t emitted_to = 0;
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
        bool live_root_owned = true;
                                  /* whether the LIVE address-space root is
                                   * one the trace CAPTURES: the pin,
                                   * another open window's root (Stage B1),
                                   * or — under trace-all — any root at all.
                                   * The glue fills it for kernel TBs on
                                   * wide-register targets, where the root
                                   * IS the process; everywhere else it
                                   * stays true and the kernel keep rule's
                                   * foreign-root refusal is inert */
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
        /* @cur_tid is filled TWICE.  Before step_events the glue writes the
         * read-only peek (thread_identity_peek): the pre-window phase applies
         * the async-window arrows and must know whose context the interrupt
         * was delivered in, but it also runs on steps that later bail, so it
         * cannot mint a fresh id there without renumbering the wire.  Before
         * step_seal the glue overwrites it with the minting sample
         * (thread_identity_sample), which is what the frame ownership and the
         * depth stamp count against.  The two agree except for a thread whose
         * pointer has never been sighted, where the peek yields
         * CST_TID_UNSEEN. */
        uint32_t cur_tid = 0;
        /* The RAW thread-pointer sample for this step, and whether it names
         * the executing thread (user privilege, or a privileged context the
         * target vouches for via qemu_plugin_thread_ptr_tracks_current —
         * re-asked per step, since RISC-V's answer varies with privilege).
         * When the register cannot be trusted here the glue substitutes the
         * vCPU's last COMMITTED thread pointer — the entering thread —
         * mirroring cur_tid's inheritance; cur_tp_ok=false means not even
         * that is known.  The async-window ownership compares these raw
         * values instead of minted tids: a raw value needs no identity-map
         * entry, so ownership stays resolvable in contexts the trace never
         * emits (an interrupt delivered into a foreign process on a peer
         * vCPU), where the minted-tid peek could only say UNSEEN. */
        uint64_t cur_tp = 0;
        bool cur_tp_ok = false;
        /* STRICT flavour of the same sample, for the kexc task-identity
         * ownership rule: true only when the register itself named the
         * CURRENT task at this step's privilege (a fresh thread_ptr_sample
         * success) — never the inherited last-committed value, which is
         * exactly the stale evidence that rule exists to overrule.  The raw
         * value is never minted into a tid, so a kernel keep decision cannot
         * renumber the wire. */
        bool cur_tp_strict = false;
        /* Is the live address-space root a per-process IDENTITY on this
         * target?  True for the wide-register roots (x86 CR3, AArch64
         * TTBR0_EL1, RISC-V SATP): the value is a page-table base, unique
         * per process for the life of the process, so "the pinned root is
         * installed" names the pinned process and nothing else.  False on a
         * narrow-ASID target (MIPS EntryHi.ASID), where the OS recycles the
         * value and equality is a coincidence of bits — there the root-owned
         * recovery below must not fire.  Filled from the pin's reuse-guard
         * arming, so it is a property of the target, not of the workload. */
        bool asid_is_identity = false;
    };

    /* A guest thread the identity map has not minted an id for yet.  Never
     * equal to any real tid (those are minted from 0 upwards), so an async
     * level whose owner resolves to this is dormant everywhere rather than
     * borrowed by whoever runs next. */
    static constexpr uint32_t CST_TID_UNSEEN = UINT32_MAX;

    /* What the step did, so the glue can pick the right continuation:
     * after step_events, only CONTINUE proceeds to window management;
     * after step_seal, only SEALED runs the deferred window closes and
     * consumes the spec-flush latch (the suspended / no-seal outcomes
     * skip them — a pending close waits for the next normally-sealed
     * step). */
    enum class StepStatus {
        CONTINUE,         /* step_events: proceed to window mgmt + seal */
        SUSPENDED,        /* async mute window open / foreign ASID: the
                           * TB is not traced.  A held prev was either
                           * kept (async: the resume seals it against its
                           * real target) or emitted at its measured
                           * extent (foreign: emit-at-departure). */
        NO_SEAL,          /* no previous context / no BB completed */
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
    /* Fold one drained batch of ordered path events into the persistent
     * builder state: the kexc ownership pass, the retention pass (which
     * moves the async window cursor) and the captured-async ownership
     * pass, in event order.  NEVER emits — every write to the body stream
     * lives in step_seal — so it is safe to run on a TB the heavy capture
     * callback was deliberately not dispatched for.
     *
     * step_events calls this; so does the light per-TB absorber
     * (vcpu_evq_absorb), which is what gives the event queue a consumer in
     * the windows where every attribution gate is closed.  Only these
     * StepIn fields are read: pinned, pinned_asid, asid_is_identity,
     * live_asid (diagnostics), cur_tp/cur_tp_ok, cur_tid, cpu_index,
     * evs/n_evs. */
    void absorb_events(const StepIn &in);

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

    /* Pending-seal slot writes.  A new prev invalidates the stranded
     * extent recorded for the old one. */
    void set_prev(BBTemplate *tb)
    {
        /*
         * A SELF-BRANCHING TB STILL SWAPS.
         *
         * The carry used to be conditional on tb != prev_tb_, which is
         * false for every tight single-block loop: cur IS prev, nothing was
         * carried, and the seal walk then asked seal_prev_extent() about the
         * block it was folding while the answer sat under the PREVIOUS
         * block's name — @head rejected it and the walk declared the extent
         * unknown and folded at full translated length on no evidence.
         * Measured on riscv64 as the one surviving "seal walks with an
         * unknown extent" per cell (prev=0x...bc44 seal_prev=0x...bc40,
         * miss=other-block, with the live measurement valid).
         *
         * Carrying on the equal case also re-arms prev_extent_valid_, so the
         * next dispatch measures the loop's NEXT iteration instead of the
         * walk reading a measurement taken several iterations earlier.
         * Only a null-to-null write is skipped: a repeated clear_prev() has
         * nothing to carry and must not overwrite a live carry with a stale
         * one.
         */
        if (tb != nullptr || prev_tb_ != nullptr) {
            /* The outgoing prev is what the seal walk in THIS step is about
             * to fold, and the measurement recorded for it is the only
             * answer that survives the swap.  Carry it across; see
             * seal_prev_extent(). */
            seal_prev_ = prev_tb_;
            seal_prev_extent_ = prev_extent_;
            seal_prev_extent_valid_ = prev_extent_valid_;
            prev_extent_valid_ = false;
        }
        if (tb != nullptr) {
            census_note_prev_promote();
            /* WHEN THIS BUILDER LAST RAN, on a clock every builder shares.
             * Promotes happen only in step_events, under exec_lock, so the
             * counter is a total order over dispatches across every vCPU —
             * which is exactly what a close needs to put the builders'
             * held blocks on the wire in the order the guest executed
             * them (see the flush order in finish_trace_segment). */
            prev_seq_ = ++g_promote_seq;
        }
        prev_tb_ = tb;
    }

    /* The shared-clock stamp of this builder's most recent promote; 0 for a
     * builder that has never held a block.  A vCPU the pinned thread left
     * earlier reads a SMALLER stamp than the vCPU it is running on now. */
    uint64_t prev_seq() const { return prev_seq_; }
    void clear_prev() { set_prev(nullptr); }

    /*
     * THE EXTENT OF A PREV THIS vCPU WILL NEVER SEAL.
     *
     * The pending-seal slot is normally consumed by the NEXT owned
     * dispatch on the same vCPU, which is where the retired cursor still
     * answers "how much of prev ran".  A vCPU the pinned process LEAVES
     * has no next owned dispatch: it goes on dispatching foreign and
     * kernel TBs, the cursor rolls forward past prev, and by the time the
     * segment closes retired_executed_of can no longer name it.  Its
     * instructions are then either dropped (they were, until this) or
     * folded at full translated length on no evidence.
     *
     * So the extent is recorded at the ONE dispatch that can still measure
     * it: the first dispatch after prev on that vCPU, owned or not.  Its
     * lagged delta IS prev's executed count, and events_path_step computes
     * it before any gate can bail the step.  Recorded once per prev — the
     * guard is set_prev's invalidation above, so a later dispatch cannot
     * overwrite a measurement with its own unrelated delta.
     */
    void note_prev_extent(uint64_t executed)
    {
        if (!prev_extent_valid_) {
            prev_extent_ = executed;
            prev_extent_valid_ = true;
        }
    }
    bool prev_extent(uint64_t *out) const
    {
        if (!prev_extent_valid_) {
            return false;
        }
        *out = prev_extent_;
        return true;
    }

    /*
     * THE SAME MEASUREMENT, FOR THE SEAL WALK.
     *
     * A seal DEFERRED past its own dispatch cannot ask the retired cursor
     * how much of prev ran — the cursor has moved on — and the walk then
     * folds prev at its FULL translated length, on the argument that a
     * prev still pending at a later dispatch was left at a TB boundary and
     * therefore ran to its end.  a07df2d053's own comment names the door
     * that argument leaves open, and seal_walk_extent_unknown_interior is
     * the instrument that watches it: measured firing on aarch64, one
     * latch cell in 33, folding 21 instructions the dispatch never ran
     * (the block resuming at current_pc then re-covers them, so the wire
     * DUPLICATES them).
     *
     * The extent is not actually unknown.  It was measured at the first
     * dispatch after prev (note_prev_extent), which is exactly the step
     * whose seal was deferred, and set_prev carries it here as prev is
     * swapped out.  @head guards it: the answer is only offered for the
     * very block it was measured for.
     */
    bool seal_prev_extent(const BBTemplate *head, uint64_t *out) const
    {
        if (!seal_prev_extent_valid_ || head == nullptr ||
            head != seal_prev_) {
            return false;
        }
        *out = seal_prev_extent_;
        return true;
    }

    /* Diagnostic only (CST_SEALEXT): WHY seal_prev_extent could not answer
     * for @head.  Bit 0 — no measurement was carried across the swap at all;
     * bit 1 — one was carried but it belongs to a DIFFERENT block.  The two
     * misses have different causes and only the report distinguishes them. */
    unsigned seal_extent_miss(const BBTemplate *head) const
    {
        return (seal_prev_extent_valid_ ? 0u : 1u) |
               (head == seal_prev_ ? 0u : 2u);
    }
    const BBTemplate *seal_prev_block() const { return seal_prev_; }
    bool live_prev_extent_valid() const { return prev_extent_valid_; }

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
     * is finalized either way.
     *
     * @prev_in_flight says the slot holds a block the guest is STANDING IN
     * — the machine-shutdown close arrives from a device write part-way
     * through the block that performs it.  The retired prefix of such a
     * block is real and is emitted; the instruction the close interrupted
     * is not, because insn_started is added at the top of an instruction
     * and an instruction that has not completed has not delivered all its
     * memory operations.  Only meaningful with @walk_prev false (the
     * deferred route); ignored otherwise. */
    void flush_final(bool walk_prev = true, bool prev_in_flight = false);

    /* Does this builder hold anything a close would have to drain — a
     * pending-seal slot with retired instructions, an in-flight chain, or
     * per-vCPU accumulator content? */
    bool holds_close_work() const;

    /* Is a close landing BETWEEN step_events and step_seal, i.e. with the
     * cross-phase walk snapshot (walk_prev_) still live rather than already
     * sealed?  Every close route that exists today lands outside that
     * window; nothing asserted it, and inside it walk_prev_ is a holder of
     * retired work with no drain.  Read by the close census. */
    bool mid_step() const { return mid_step_; }

    /* Which vCPU this builder belongs to.  Stamped once by
     * path_builder() at creation; every internal reference to the
     * per-vCPU accumulators (pending_reg_snaps, cp_chain, the memory
     * recorder's CP buffer, the anchor guard) keys off it. */
    void set_cpu_index(unsigned int cpu_index) { cpu_index_ = cpu_index; }

    /* Lazy per-vCPU event-queue enable, done by the glue on this vCPU's
     * first CP exec (must run on the owning vCPU). */
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

    /* THE CLOSE CENSUS: EVERY HOLDER, EVERY CLOSE.
     *
     * The close flushes the pending-seal slot (and, on a peer, its own);
     * fault frames are ledger entries whose prefixes are already on the
     * wire.  Everything else this builder can be holding at that instant
     * — the in-flight chain, the positional reg-snap sink, the CP memop
     * buffer and its straggler carry, the retained fault events, the
     * pending self-loop facts — leaves with no drain and no counter, so
     * a clock-vs-wire residual at a close has no site to name.
     *
     * This walks all of them and prints one [census] line per builder,
     * TWICE per close: @phase "pre" before anything is flushed (what the
     * close inherited) and "post" after the flush hook has run (what
     * survived it, which is the drop).  The post pass is also where the
     * held_at_close ledger rows in Stats are accumulated, so the fate
     * identity "entered == fated + held" is checkable over a whole run.
     *
     * Printing is behind CST_CLOSEDROP; the ledger accumulation is not
     * (a counter that only exists when a diagnostic is enabled cannot be
     * quoted as evidence for a run that did not enable it). */
    void close_state_report(FILE *f, const char *why,
                            unsigned int closing_cpu,
                            const char *phase, bool print,
                            bool ledger) const;

private:
    void prime_from_live();
    void kexc_apply_asid_write(uint64_t new_asid);
    /* True while this excursion's stored raw ASID values are still in the
     * namespace generation they were recorded in — the single gate every
     * stored-value comparison passes through (see g_asid_identity_gen). */
    bool kexc_values_current() const;
    /* @tp/@tp_valid: the step's raw thread-pointer sample (StepIn::cur_tp),
     * seeding the owned-thread identity map when the TB is owned. */
    void kexc_user_tb(uint64_t live_asid, bool owned,
                      uint64_t tp, bool tp_valid);
    /* @in supplies the executing fragment (block PC + instruction count) and
     * the live / pinned ASIDs, all of which feed only the ownership-census
     * instrumentation; the keep rule itself reads excursion state alone. */
    bool kexc_kernel_tb_keep(const StepIn &in);
    void kexc_reset();
    /* @owner_tid is StepIn::walk_tid: a frame opened here is the deferred
     * prev's excursion, so the thread that ran that block owns it.  Under
     * split emission this EMITS the interrupted block's executed prefix
     * (or a mid-excursion continuation) to @out_stream the moment the
     * event classifies, and keeps only a ledger frame. */
    void classify_fault_enter(const struct qemu_plugin_cpu_event &ev,
                              bool *prev_emitted, uint32_t owner_tid,
                              BodyStreamState *out_stream,
                              const StepIn &in);
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
    BBTemplate *fold_prev_full_bb(BBTemplate *prev);
    /* Completion: the just-sealed suffix matched frames_[idx].  Emit it as
     * a CONTINUATION of the frame's full template — SAME template_id,
     * bb_start = the frame's emitted_to cursor — with the seal's resolved
     * branch, then erase the frame.  The trailing pending_emits follow
     * unchanged. */
    StepStatus complete_continuation(size_t idx,
                                     const std::vector<PendingEmit> &pending_emits,
                                     BodyStreamState *out_stream,
                                     unsigned int cpu_index);


    /* The one close-time walk-and-emit.  Folds @a.head's fragment list into
     * the in-flight chain up to the retired extent, finalizes whatever
     * seals (including a chain the close leaves mid-BB), and emits each
     * block from the accumulators the caller has installed.  Shared by
     * every close-time / departure-time emission so a truncation rule has
     * exactly one copy. */
    struct CloseWalk {
        BBTemplate *head = nullptr;     /* fragment list to walk (may be null:
                                         * the chain is still finalized) */
        bool have_extent = false;       /* is @executed a measurement? */
        uint64_t executed = 0;          /* instructions of @head that RETIRED */
        uint64_t prev_start = 0;        /* scoreboard's last-executed fragment,
                                         * 0 when the caller has no such
                                         * marker */
        bool set_depth = false;         /* stamp g_emit_fault_depth per block */
        uint32_t depth = 0;
        uint8_t async_in_depth = 0;
        const RepArchFacts *facts = nullptr;
        /* Mark the LAST block this walk emits as its context's final entry
         * (CST_BB_FLAG_THREAD_END).  Set by the close-time flush only. */
        bool thread_end_last = false;
        /* Filled by the walk: the template extent that reached the wire,
         * split by privilege.  Measured from the blocks emitted, not from
         * what the slot held — the difference is the whole of 81239d89cd. */
        uint64_t insns_emitted = 0;
        uint64_t user_insns_emitted = 0;
    };
    uint32_t close_walk_emit(BodyStreamState *out_stream,
                             unsigned int cpu_index, CloseWalk &a);
    /* Emit-at-departure: the pending-seal slot's block is leaving this
     * vCPU's traced flow (foreign-ASID dispatch; abandoned async window).
     * Emit it NOW at its measured extent with the terminating branch
     * honestly unresolved, and drop everything past the range.  Caller
     * clears the slot afterwards. */
    void emit_prev_at_departure(const StepIn &in);

    /* In-flight fault excursions, fault-nesting order (completion may
     * retire a mid-stack frame; see frame_idx_for_completion).  Identity
     * and depth ledger entries only — see CtxFrame. */
    std::vector<CtxFrame> frames_;

    /* A retained event, with the async-window state that held AT ITS OWN
     * POSITION in the drain.  The stamp is taken once, in event order, from
     * the persistent window flag — never reconstructed later from a batch's
     * shape, which cannot see a window opened on an earlier bailed step. */
    struct RetainedEv {
        struct qemu_plugin_cpu_event ev;
        bool in_async;
        bool ours;          /* the attribution verdict at drain */
    };

    /* Drained-but-unapplied events.  RETENTION IS AN ATTRIBUTION DECISION:
     * an event is kept only when the SAME ownership predicate that admits a
     * TB admits the event (event_is_ours), evaluated on the event's own
     * recorded (asid, priv, tp) at its own position in the drain.  So this
     * holds exactly the traced context's own FAULT_ENTER/FAULT_RETURN,
     * surviving its bailed steps until a seal consumes them; execution the
     * trace refuses contributes nothing, and the structure cannot grow with
     * untraced execution.
     *
     * Async edges are NOT retained: their whole effect is assignment into
     * persistent members, done once at drain (O(1)), plus the per-event
     * in_async stamp above.  ASID_WRITE is consumed once at drain by the
     * kexc ownership pass and read by nobody afterwards.
     *
     * Under CST_RETAIN_ALL=1 the ownership guard on the append is bypassed
     * (and nothing else changes) so the discriminating experiment can run
     * the unbounded arm in the same binary. */
    std::vector<RetainedEv> pending_evs_;

    /* One batch-local fact the seal needs but cannot recompute: a capture
     * window OPENED somewhere in the events folded since the last step.
     * Set by absorb_events, read-and-cleared by step_events.  Carried in a
     * member rather than returned, because the batch that opened the window
     * may have been absorbed one or more TBs before the step that seals
     * against its departure PC — which is exactly the case the light
     * absorber creates and the old lump-at-next-dispatch behaviour hid. */
    bool absorbed_opened_window_ = false;

    /* True between step_events returning CONTINUE and step_seal running:
     * the window tw_manage_window occupies, and the ONE window in which
     * walk_prev_ holds a block that has executed and has not been sealed.
     * Set and cleared by the two step phases; read only by the census, so
     * nothing in the tracer's logic depends on it. */
    bool mid_step_ = false;

    /* Async-window state AT THE DRAIN CURSOR: persistent across dispatches,
     * so a window opened on a step that later bailed is still open when the
     * next step's events are stamped.  Distinct from async_excluding_ /
     * async_captured_, which are the mode-dependent consequences. */
    bool drain_async_open_ = false;

    /* The architectural-successor override derived at drain instead of by a
     * seal-time rescan: the resume PC of the first retained non-in-async
     * FAULT_ENTER since the last seal. */
    uint64_t retained_first_enter_pc_ = 0;

    /* Ownership predicate for ONE event, from the event's own recorded
     * state — the same rule the TB gates apply, re-asked at the event's
     * position in the drain.  See champsim_tracer_path_builder.cc. */
    bool event_is_ours(const struct qemu_plugin_cpu_event &ev,
                       const StepIn &in, bool in_async, size_t idx) const;

    /* Is @ev INTERIOR to the outstanding async window, as opposed to merely
     * concurrent with it?  The single spelling of that question — the
     * retention gate, the seal's fault classifier and the seal's successor
     * override all ask it here, so they cannot drift apart.  Static: it
     * reads only the event and the cursor stamp.  See the .cc for why user
     * privilege settles it. */
    static bool async_window_interior(const struct qemu_plugin_cpu_event &ev,
                                      bool in_async);

    /* Per-event snapshot of the kernel-excursion ownership edge, indexed by
     * position in the current drain (filled by the kexc pass, read by
     * event_is_ours). */
    std::vector<uint8_t> drain_kexc_own_;

    /* The pin, sampled at the last drain, so a consumer that does not
     * receive the StepIn (classify_fault_enter) can still ask the
     * address-space identity question. */
    uint64_t pin_asid_cur_ = 0;
    bool     pin_armed_cur_ = false;
    bool     pin_identity_cur_ = false;

    /* True when @asid demonstrably names an address space other than the
     * traced one.  Conservative: false whenever the question cannot be
     * answered (unpinned, or a narrow-ASID target where equality of the raw
     * bits is not identity). */
    bool ctx_asid_foreign(uint64_t asid) const
    {
        return pin_armed_cur_ && pin_identity_cur_ && asid != pin_asid_cur_;
    }

    /* CST_RETAIN_CHECK only: the OLD unconditional retention, kept verbatim
     * alongside the new one so every seal can compare the two derivations.
     * Unbounded by construction — never a default, never a shipping path. */
    std::vector<RetainedEv> ref_evs_;
    void retain_check_compare(uint64_t new_resume_pc);

    /* The single pending-seal slot: the deferred prev TB, plus the fault
     * depth stamped when it EXECUTED.  Stamping at promote time (not at
     * seal time) is required — the fault stack may pop between a TB's
     * execution and its BBs' emission one step later, and reading depth
     * at seal would lose the handler's level. */
    BBTemplate *prev_tb_ = nullptr;
    /* See note_prev_extent: prev's executed count, measured at the first
     * dispatch after it, for the close walk on a vCPU the process left. */
    uint64_t prev_extent_ = 0;
    bool     prev_extent_valid_ = false;
    /* The shared dispatch clock at this builder's most recent promote (see
     * g_promote_seq).  The close orders the builders' flushes by it. */
    uint64_t prev_seq_ = 0;
    /* The outgoing prev and its measurement, carried across the swap for
     * the seal walk of the same step (see seal_prev_extent). */
    const BBTemplate *seal_prev_ = nullptr;
    uint64_t seal_prev_extent_ = 0;
    bool     seal_prev_extent_valid_ = false;
    uint32_t prev_depth_ = 0;
    
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

    /* OWNER of the captured level.  format.rst §4.2a defines fault_depth as
     * the nesting THIS basic block executed at and makes the nesting a
     * property of the entry's own thread_id, so the level a window
     * contributes belongs to the context the interrupt was DELIVERED in and
     * to no other.  async_captured_ alone is the vCPU's window lifetime (QEMU
     * owns it: one flag, opened at the outermost delivery, closed when the
     * departure PC is re-executed); this pair is the attribution.
     *
     * The owner is the DELIVERY-INSTANT thread pointer the ASYNC_ENTER event
     * itself carries (ev.tp/ev.tp_ok, stamped by the producer before any
     * handler instruction runs).  A raw register value, not a minted tid:
     * the delivering context routinely belongs to a thread the trace never
     * emits (a foreign process on a peer vCPU, a kernel thread), which the
     * identity map has never minted and never will — a tid-keyed owner was
     * unresolvable exactly where SMP interrupts land.  The event-carried
     * value also survives the drain latency: the event is consumed at the
     * next executed TB, by which point the vCPU is already inside the
     * handler (today that TB is the handler's first, but nothing pins the
     * drain that close — an inter-segment gap batches events for later).
     *
     * Read only through async_level(), which makes the contribution a
     * PREDICATE re-evaluated per entry — dormant while a peer thread runs,
     * live again when the owner is rescheduled — exactly as
     * stamp_cur_depth's `f.tid == in.cur_tid` already does for synchronous
     * frames.  A latch on "something changed since the capture" cannot come
     * back, and the address space is the wrong key besides: a same-mm thread
     * switch, a kernel thread on a borrowed mm and a recycled narrow ASID all
     * change context while committing no ASID write at all.
     *
     * async_owner_ok_ false (the producer could not vouch for the delivery
     * context's register — e.g. an interrupt into M-mode firmware) leaves
     * the level dormant everywhere rather than borrowed by whoever runs
     * next.  Thread-pointer collisions (two threads whose register holds
     * the same value — a no-TLS workload and a kernel thread both at 0)
     * merge under this key exactly as they merged under the minted-tid key:
     * the map was value-keyed too, so the predicate is no coarser than it
     * was.  PathBuilder lives on the heap behind per-vCPU pointers
     * (path_builder(cpu_index)), so these members cost no static TLS. */
    uint64_t async_owner_tp_ = 0;
    bool async_owner_ok_ = false;

    /* Per-vCPU window measurement + id (formerly process-wide statics in
     * the .cc).  Under SMP a peer vCPU's pre-prime step or fresh ENTER
     * must not close or clobber THIS vCPU's open window record: the kexc
     * async re-latch gate reads the id, so the cross-vCPU clobber was
     * wire-visible (a skipped re-latch drops the post-window kernel tail),
     * and the per-window own/peer/asidw tallies were interleaved noise.
     * The id values stay globally unique via g_async_win_seq (exec_lock).
     * Heap-resident like everything else here: no static-TLS cost. */
    uint64_t win_id_ = 0;
    uint64_t win_enter_seq_ = 0;
    uint32_t win_asidw_ = 0;
    uint32_t win_own_stamps_ = 0;
    uint32_t win_peer_stamps_ = 0;

    /* Publish the closing window's condition counters and clear them. */
    void async_win_close(const char *kind, uint32_t tid);

    /* The +1 an open capture window contributes to the depth of the block
     * described by @in: present iff the window is open AND @in names the
     * thread the interrupt was delivered in.  The single point where the
     * async level is read. */
    uint32_t async_level(const StepIn &in) const
    {
        return (async_captured_ && async_owner_ok_ && in.cur_tp_ok &&
                in.cur_tp == async_owner_tp_) ? 1u : 0u;
    }

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
    /* The raw-value namespace generation @kexc_exc_entry_ was latched under
     * (g_asid_identity_gen).  A narrow-ASID space recycles, so the entry
     * VALUE returning is proof of identity only while the generation has
     * not moved; once it has, the same bits may name any process and every
     * arrow that compares against @kexc_exc_entry_ must stand down. */
    uint32_t kexc_exc_entry_gen_ = 0;
    bool     kexc_entry_owned_ = false; /* ownership latched at the edge */
    bool     kexc_have_overlay_ = false;
    uint64_t kexc_overlay_ = 0;
    bool     kexc_cut_ = false;
    /* Which decline-census arm refused the last dropped kernel TB
     * (0 none, 1 no_user, 2 not_owned, 3 cut, 4 task-identity) — read by
     * the CST_JUMP_DIAG gap-condition recorder only; no behavioral
     * reader. */
    uint8_t  kexc_last_decline_ = 0;
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

    /* Async re-latch (interrupts=1 only).  A captured window's content —
     * the handler and everything the guest scheduler runs before the
     * departure PC is re-fetched — routinely includes foreign user TBs,
     * which reset the excursion state above and re-latch the entry edge to
     * a FOREIGN owner.  The interrupted excursion's own post-window kernel
     * tail then refuses on not_owned all the way to user privilege, which
     * silently deletes its depth level from the wire (the residual 2->0).
     * The ASYNC_RETURN producer fires only when the departure PC is
     * re-fetched with the departure thread pointer, so the return is proof
     * the machine is back in the state the window interrupted: snapshot
     * the ownership block at ASYNC_ENTER and restore it on the owner's
     * genuine return.  A window that never returns (abandon, pre-prime,
     * segment boundary) invalidates the snapshot instead. */
    struct KexcSnap {
        bool     valid = false;
        bool     in_kernel;
        bool     have_user, user_owned;
        uint64_t last_user_asid;
        uint64_t exc_entry;
        uint32_t exc_entry_gen;
        bool     entry_owned;
        bool     have_overlay;
        uint64_t overlay;
        bool     cut, restored_after_cut;
        uint64_t vals[KEXC_STORM_THRESHOLD];
        uint32_t nvals;
        bool     stormed;
    } kexc_snap_;
    /* Census flag (mirrors kexc_restored_after_cut_): this excursion's
     * ownership was re-latched from an async-return snapshot; cleared by
     * kexc_reset.  Never consulted by the keep rule. */
    bool kexc_relatched_ = false;
    void kexc_async_snapshot();
    void kexc_async_restore();

    bool evq_enabled_ = false;
    unsigned int cpu_index_ = 0;

    /* CLOSE CENSUS ONLY.  flush_final consumes the pending-seal slot but
     * does not null prev_tb_, so the post-flush census cannot tell a slot
     * the close EMITTED from one it dropped by reading the slot alone.
     * This stamps the close (Stats::census_closes) whose flush walked this
     * builder and how: 1 = walked prev, 2 = chain-only (prev dropped),
     * 3 = chain-only but the slot's RETIRED PREFIX was walked (the
     * machine-shutdown drain).  Written by flush_final, read by
     * close_state_report, consulted by nothing else. */
    mutable uint64_t census_flush_seq_ = 0;
    mutable uint8_t  census_flush_kind_ = 0;
    /* And how much RETIRED work of the slot that flush left unemitted.
     * The census cannot recompute it after the fact: the retired cursor is
     * read the same way by both, but only the flush knows whether the close
     * landed mid-instruction (the device-write shutdown), where the
     * in-flight instruction has BEGUN and has not retired. */
    mutable uint64_t census_prev_undrained_ = 0;
};

/* @cpu_index's PathBuilder (lazily heap-allocated, immortal).  One
 * builder per vCPU: frames, chain, recorder buffer and reg-snap
 * accumulators are per-vCPU streams.  Keyed by cpu_index rather than by
 * host thread because round-robin TCG runs every vCPU on one thread;
 * under MTTCG the two keyings coincide. */
PathBuilder &path_builder(unsigned int cpu_index);
/* @cpu_index's PathBuilder if it has ever been created, else nullptr —
 * for teardown sweeps that must not mint builders. */
PathBuilder *path_builder_if_created(unsigned int cpu_index);

/* Segment-finish flush: flush @cpu_index's pending final body entry.
 * The _chain_only variant is PathBuilder::flush_final(false) — the
 * deferred window close, whose pending-seal slot holds a TB that has
 * not run yet. */
void path_builder_flush_final(unsigned int cpu_index);
void path_builder_flush_final_chain_only(unsigned int cpu_index,
                                         bool prev_in_flight = false);

/* The close census: one pass per segment close over every builder that
 * ever ran, naming everything still held (see
 * PathBuilder::close_state_report).  Called twice per close — @phase
 * "pre" before the flush hook, "post" after it.  @print is the
 * CST_CLOSEDROP gate; the ledger accumulation in the "post" pass runs
 * regardless. */
void path_builder_close_state_report(FILE *f, const char *why,
                                     unsigned int closing_cpu,
                                     const char *phase, bool print,
                                     bool ledger);

/*
 * ---- Narrow-ASID identity generation ----
 *
 * A raw ASID value names a process only for as long as the OS has not
 * recycled it.  On a narrow-ASID target (MIPS: an architecturally 8-bit
 * EntryHi.ASID) the OS MUST recycle, and when it does every value the
 * tracer stored silently starts naming somebody else.  This counter is the
 * generation of the raw-value namespace: each piece of evidence that the
 * space wrapped bumps it, and a stored value stamped with an older
 * generation is no longer identity — only a coincidence of bits.  Bumped
 * from the committed-ASID-write hook's rollover detector and from a dwell
 * re-pin; read by the kexc excursion arrows, which stamp the generation
 * beside every raw value they keep.
 *
 * Monotone and process-wide, never reset: a reset would make two different
 * namespaces compare equal, which is the very defect it exists to prevent.
 * Wide-register targets (CR3 / TTBR0 / SATP) never bump it, so their
 * comparisons are byte-identical to before.
 */
extern std::atomic<uint32_t> g_asid_identity_gen;
void asid_identity_gen_bump(const char *why);

/* Invalidate the kexc owned-thread identity map (rollover-scale evidence:
 * an ASID-write storm, a narrow-ASID dwell re-pin, a foreign user TB carrying
 * the pinned ASID value).  A stale (thread-pointer, asid) pair must never
 * satisfy the task-identity kernel ownership rule after the raw asid value
 * may have been handed to another process.  Caller holds exec_lock. */
void kexc_owned_tp_invalidate(const char *why);




#endif /* CHAMPSIM_TRACER_PATH_BUILDER_H */
