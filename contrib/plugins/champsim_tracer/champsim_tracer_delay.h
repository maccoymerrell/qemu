/*
 * Wrong-Path Tracing Plugin — wrong-path excursion delay attribution.
 *
 * A DIAGNOSTIC instrument, armed by CST_DELAY_DIAG and inert otherwise.  It
 * is not a watchdog and not a product guard: it changes nothing the tracer
 * emits, takes no decision, and ends no run.  Its only job is to make one
 * quantity visible while it is happening.
 *
 * WHAT IT MEASURES: TRACER COST, AND NOTHING ELSE.
 *
 * The subject is how much of a vCPU THREAD's host wall clock the tracer
 * consumed, and where inside the tracer it went.  That is a cost figure.  It
 * is not, and must never be read as, a statement about the guest.
 *
 * THE GUEST CANNOT SEE ANY OF THIS.  An excursion runs with the guest's
 * virtual clock frozen (cpu_plugin_spec_vtime_pause), and the resume
 * DISCARDS the interval the excursion consumed, so the guest's architected
 * counters read the same value after an excursion as before it — the clock
 * is returned to where it stood when the excursion started (see
 * qemu_plugin_spec_vtime_pause / _resume in qemu-plugin.h).  Correct-path
 * instrumentation runs under the same freeze via VClockPauseGuard.  No
 * quantity this file reports is therefore guest-visible time, and no number
 * printed here may be offered as a mechanism by which a guest stopped making
 * progress.  A guest that stops progressing under wp=1 and does not under
 * wp=0 has a wrong-path RESTORE defect — state the excursion changed and
 * did not put back — and the place to hunt is the restore, not the cost.
 * These figures bound the cost of a capture: how long it takes and how it
 * scales, so a run can be sized.
 *
 * THE DECOMPOSITION.  Each vCPU's timeline between two consecutive excursion
 * ends is partitioned with no residue and no modelling:
 *
 *   span = excursion wall + exec_lock wait wall + remaining gap wall
 *
 * where "excursion" is the whole of simulate_wrong_path_ext (snapshot,
 * spec-mode walk, restore); "exec_lock wait" is the interval a vCPU spent
 * blocked acquiring exec_lock before its correct-path step could run; and
 * the remaining gap is correct-path instrumentation, guest execution, and
 * any interval the host scheduler had the thread off-CPU.  All three are
 * measured at their own boundaries.
 *
 * WHY THE LOCK TERM IS SEPARATE.  simulate_wrong_path_ext runs under
 * exec_lock, so on a multi-vCPU guest the vCPU holding an excursion and the
 * vCPUs waiting behind it are in completely different states — and before
 * this term existed they were indistinguishable, because a waiter's blocked
 * interval fell into its own undifferentiated gap alongside guest execution.
 * Worse, a vCPU that never ran an excursion of its own was never reported at
 * all: the sampler only printed slots that had been touched by an excursion
 * boundary, so the machine's waiters were silently absent from the output.
 * A lock wait now marks the slot seen and is reported on its own, whether or
 * not that vCPU ever speculates.
 *
 * SEPARATING TRACER COST FROM HOST CONTENTION.  Wall time alone cannot tell
 * "the tracer is consuming this vCPU" from "the host is not scheduling this
 * vCPU", and a load-dependent reading is not evidence (a busy host depresses
 * every wall-clock ratio).  Both clocks are therefore sampled at every
 * excursion boundary: CLOCK_MONOTONIC and CLOCK_THREAD_CPUTIME_ID for the
 * vCPU thread itself.  sched = span_cpu / span_wall is the fraction of the
 * span the thread was actually on-CPU, so cost measured under host
 * contention is distinguishable from cost that is really the tracer's.
 *
 * WHAT IT DOES NOT MEASURE.  The remaining gap is not decomposed further:
 * this instrument brackets the lock acquisition but not the correct-path
 * step's body, so it cannot separate correct-path instrumentation from guest
 * execution inside what is left.  RtFactorGate's guest-realtime factor
 * supplies that complementary split by design, and the two are meant to be
 * read together on one run (CST_RT_TRACE=1 CST_DELAY_DIAG=1).
 *
 * SAMPLED FROM A SEPARATE THREAD, ON PURPOSE.  An in-callback sampler can
 * only observe at the moments the tracer hands control back, so it is blind
 * for exactly as long as any single excursion runs — the interval most worth
 * seeing.  A standalone sampler reads the counters on its own clock and
 * reports an excursion that is still open, with its current age, while the
 * vCPU is still inside it.  That is what "in the act" requires.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_DELAY_H
#define CHAMPSIM_TRACER_DELAY_H

#include <stdint.h>

/*
 * Tri-state arm cache: -1 not yet probed, 0 disarmed, 1 armed.  Exposed so
 * the gate on the hot path is a relaxed load of an int and a predictable
 * branch, with no call and no getenv, when the instrument is off — which is
 * always, unless an operator armed it.
 */
extern int g_cst_delay_armed;

/* Resolve the environment gate once and publish it.  Out of line; reached at
 * most once per process from the inline probe below. */
bool cst_delay_arm_probe(void);

static inline bool cst_delay_armed(void)
{
    int v = __atomic_load_n(&g_cst_delay_armed, __ATOMIC_RELAXED);
    if (v < 0) {
        return cst_delay_arm_probe();
    }
    return v != 0;
}

/* Excursion boundaries.  Both are no-ops unless armed; the caller's gate
 * keeps them off the disarmed path entirely. */
void cst_delay_excursion_begin(unsigned int cpu_index, uint64_t wrong_target);
void cst_delay_excursion_end(unsigned int cpu_index, uint64_t sim_insns,
                             bool early_exit);

/* One speculative exec_tb completed inside the current excursion.  The caller
 * gates on cst_delay_armed(): this sits in the walker's innermost loop, and
 * an unconditional call would resolve a thread-local on every speculative
 * dispatch of every run, armed or not. */
void cst_delay_note_spec_tb(void);

/*
 * exec_lock acquisition boundaries, bracketing the blocking call itself:
 *
 *   cst_delay_lock_wait_begin(cpu_index);
 *   g_rec_mutex_lock(&exec_lock);
 *   cst_delay_lock_wait_end(cpu_index);
 *
 * Both are no-ops unless armed, and every caller gates on cst_delay_armed()
 * so the disarmed cost is a relaxed int load and a predictable branch — this
 * sits on the correct-path step, once per traced TB.  Only WALL time is
 * sampled here: a thread blocked on a mutex accrues no thread CPU time, so
 * the second clock would report nothing while doubling a hot-path cost.
 *
 * The pair is depth-guarded like the excursion bracket.  exec_lock is a
 * GRecMutex and the correct-path step is reached from more than one hook, so
 * a re-entrant acquire must not clobber the outer wait's start timestamp.
 */
void cst_delay_lock_wait_begin(unsigned int cpu_index);
void cst_delay_lock_wait_end(unsigned int cpu_index);

/*
 * RAII bracket for one excursion.  Scoped over the whole of
 * simulate_wrong_path_ext including its early returns, so the snapshot
 * failure path is billed the wall time it really costs rather than
 * disappearing from the accounting.
 */
class CstDelayExcursion {
public:
    CstDelayExcursion(unsigned int cpu_index, uint64_t wrong_target)
        : cpu_index_(cpu_index), armed_(cst_delay_armed())
    {
        if (armed_) {
            cst_delay_excursion_begin(cpu_index, wrong_target);
        }
    }

    ~CstDelayExcursion()
    {
        if (armed_) {
            cst_delay_excursion_end(cpu_index_, insns_, early_exit_);
        }
    }

    /* Called just before the excursion returns, when its outcome is known. */
    void result(uint64_t insns, bool early_exit)
    {
        insns_ = insns;
        early_exit_ = early_exit;
    }

    CstDelayExcursion(const CstDelayExcursion &) = delete;
    CstDelayExcursion &operator=(const CstDelayExcursion &) = delete;

private:
    unsigned int cpu_index_;
    bool         armed_;
    uint64_t     insns_      = 0;
    bool         early_exit_ = false;
};

#endif /* CHAMPSIM_TRACER_DELAY_H */
