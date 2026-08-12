/*
 * Wrong-Path Tracing Plugin — wrong-path excursion delay attribution.
 *
 * A DIAGNOSTIC instrument, armed by CST_DELAY_DIAG and inert otherwise.  It
 * is not a watchdog and not a product guard: it changes nothing the tracer
 * emits, takes no decision, and ends no run.  Its only job is to make one
 * quantity visible while it is happening.
 *
 * WHAT IT MEASURES, AND WHY THAT IS A DIFFERENT QUESTION FROM THE ONE THE
 * OTHER INSTRUMENTS ANSWER.
 *
 * Every existing wrong-path instrument measures DAMAGE: interrupts lost or
 * gained across an excursion, timer counters that failed to be restored,
 * device state a speculative access moved, register state that leaked past
 * the rollback.  Those all answer "did the excursion corrupt something?".
 *
 * There is a failure shape they are all blind to by construction.  The guest
 * stops making architectural progress, every corruption instrument reads
 * zero, and nothing is wrong with any state the excursion touched — because
 * nothing is corrupt.  The vCPU thread is simply not executing guest
 * instructions: it is inside the tracer.  A count of excursions cannot
 * separate that case from a healthy one (cheap excursions and expensive
 * excursions count the same), and a corruption instrument cannot see it at
 * all (there is no corruption).  What is needed is an instrument whose
 * subject is DELAY: how much of a vCPU's wall time the tracer consumed, and
 * where inside the tracer it went.
 *
 * THE DECOMPOSITION.  Each vCPU's timeline between two consecutive excursion
 * ends is partitioned exactly two ways, with no residue and no modelling:
 *
 *   span = excursion wall time + gap wall time
 *
 * where "excursion" is the whole of simulate_wrong_path_ext (snapshot,
 * spec-mode walk, restore) and "gap" is everything between one excursion
 * ending and the next beginning — correct-path instrumentation, guest
 * execution, and any interval the host scheduler had the thread off-CPU.
 * The headline number is the excursion OCCUPANCY, exc_wall / span: the
 * fraction of the vCPU's own wall clock that the wrong-path walker held.
 *
 * SEPARATING TRACER COST FROM HOST CONTENTION.  Wall time alone cannot tell
 * "the tracer is consuming this vCPU" from "the host is not scheduling this
 * vCPU", and a load-dependent reading is not evidence (a busy host depresses
 * every wall-clock ratio).  Both clocks are therefore sampled at every
 * boundary: CLOCK_MONOTONIC and CLOCK_THREAD_CPUTIME_ID for the vCPU thread
 * itself.  sched = span_cpu / span_wall is the fraction of the span the
 * thread was actually on-CPU, so a delay caused by host contention
 * (sched well below 1) is distinguishable from a delay caused by tracer work
 * (sched near 1, occ near 1) rather than confounded with it.
 *
 * WHAT IT DOES NOT MEASURE.  The gap term is not decomposed: this instrument
 * cannot separate correct-path instrumentation from guest execution inside
 * it, because it holds no correct-path hook.  RtFactorGate's guest-realtime
 * factor supplies that complementary split, and the two are designed to be
 * read together on one run (CST_RT_TRACE=1 CST_DELAY_DIAG=1).  It also does
 * not observe exec_lock: a vCPU blocked waiting on a peer's excursion spends
 * that time in its own gap term, indistinguishable there from guest
 * execution.  Both are stated limits, not silences.
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
