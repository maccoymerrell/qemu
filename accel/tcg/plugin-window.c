/*
 * The wrong-path excursion window: the register-state restore and the
 * open/close pair around one excursion (clock freeze, icount and slice
 * budget save/restore, per-target clock resync, kick re-arm), plus the
 * nestable correct-path instrumentation clock freeze.
 *
 * Vocabulary: an excursion is one wrong-path run, bracketed by
 * cpu_plugin_excursion_open() and cpu_plugin_excursion_close(); spec mode
 * (plugin_spec_mode) is set only inside it.
 *
 * Copyright (C) 2026, Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "accel/tcg/cpu-ops.h"
#include "exec/cpu-common.h"
#include "tcg/tcg.h"
#include "qemu/atomic.h"
#include "qemu/main-loop.h"
#include "exec/cpu-all.h"
#include "exec/exec-all.h"
#include "system/cpu-timers.h"
#include "qemu/qemu-plugin.h"
#include "qemu/tcg-slice.h"
#include "internal-common.h"
#include "internal-target.h"
#include "exec/cputlb.h"
#include "plugin-diag.h"

size_t cpu_plugin_arch_state_size(void)
{
    /*
     * Only save execution state up to end_reset_fields.  Fields beyond
     * that boundary are static configuration (CPUID, features) or
     * externally-managed pointers (KVM/HVF buffers, Xen timers, mutexes)
     * that must not be rolled back by speculative execution.
     */
    return offsetof(CPUArchState, end_reset_fields);
}

void cpu_plugin_arch_state_restore(void *saved, size_t size)
{
    CPUArchState *env = cpu_env(current_cpu);

    /*
     * Preserve debug breakpoint/watchpoint pointers across restore.
     * These are managed by the GDB debug subsystem and must not be
     * rolled back during speculative execution.
     */
#if defined(TARGET_I386)
    typeof(env->cpu_breakpoint) bp_save;
    memcpy(bp_save, env->cpu_breakpoint, sizeof(bp_save));
    memcpy(env, saved, size);
    memcpy(env->cpu_breakpoint, bp_save, sizeof(bp_save));
#elif defined(TARGET_ARM)
    typeof(env->cpu_breakpoint) bp_save;
    typeof(env->cpu_watchpoint) wp_save;
    memcpy(bp_save, env->cpu_breakpoint, sizeof(bp_save));
    memcpy(wp_save, env->cpu_watchpoint, sizeof(wp_save));
#if !defined(CONFIG_USER_ONLY)
    /*
     * The generic timer's host QEMUTimers live OUTSIDE this register snapshot.
     * If the restore rolls back any timer's ctl/cval -- most importantly the
     * ISTATUS bit, which an expiry processed during the excursion can
     * advance to 1 -- the architected registers revert but the host
     * QEMUTimer does not, leaving it parked (e.g. at INT64_MAX) and never
     * firing again, and the guest's timer subsystem livelocks.  Nothing is
     * detected here: arm_cpu_plugin_resync_timers re-runs gt_recalc_timer
     * over every present timer at excursion exit, unconditionally, so this
     * restore only has to avoid damaging the registers that reconcile reads
     * from.
     */
    /*
     * env->irq_line_state is the level of the six inbound interrupt lines,
     * driven by the GIC through arm_cpu_set_irq() from the iothread.  It is
     * DEVICE state that merely happens to live inside CPUARMState: guest
     * instructions never write it, so a discarded speculative path has
     * nothing to roll back, while a GIC level change that lands during the
     * excursion is real and must survive.  Rewinding it desyncs it from the
     * CPU_INTERRUPT_* bits in CPUState (which the memcpy does not touch) and
     * poisons every later arm_cpu_update_virq/vfiq/vinmi recomputation, which
     * reads it.  Carry the live value forward, exactly as the breakpoint and
     * watchpoint pointers below are carried, and let the excursion-exit
     * resync re-derive the interrupt-request word from it.
     */
    uint32_t irq_line_save = env->irq_line_state;
#endif
    memcpy(env, saved, size);
    memcpy(env->cpu_breakpoint, bp_save, sizeof(bp_save));
    memcpy(env->cpu_watchpoint, wp_save, sizeof(wp_save));
#if !defined(CONFIG_USER_ONLY)
    env->irq_line_state = irq_line_save;
#endif
    /* Clock resync runs in cpu_plugin_excursion_close, not here. */
#elif defined(TARGET_RISCV)
#if !defined(CONFIG_USER_ONLY)
    /*
     * The Sstc supervisor/VS host timers (env->stimer/vstimer) and the ACLINT
     * machine timer live outside this register snapshot, so a rolled-back
     * stimecmp/vstimecmp, or an expiry the excursion suppressed, can leave a
     * host QEMUTimer armed for a deadline the architected registers no longer
     * ask for (the storm class: architected timer register desynced from the
     * host timer).  The excursion-exit resync re-derives every deadline and
     * level from the compare registers unconditionally, so this restore no
     * longer has to detect which of those happened -- it just has to not
     * damage the compare registers, and it does not (mtimecmp is device
     * state; stimecmp/vstimecmp revert to their correct-path values).
     */
    {
        const CPURISCVState *s = (const CPURISCVState *)saved;
        /* Diagnostic (CST_ILL_DIAG): report a restore that turns mstatus.VS
         * from On to Off, i.e. one that would clobber a correct-path
         * vector-enable with a stale snapshot. */
        if (getenv("CST_ILL_DIAG") &&
            (env->mstatus & MSTATUS_VS) && !(s->mstatus & MSTATUS_VS)) {
            fprintf(stderr, "[vsclobber] restore VS 1->0 spec=%d FS:%d->%d\n",
                    (int)current_cpu->plugin_spec_mode,
                    (int)!!(env->mstatus & MSTATUS_FS),
                    (int)!!(s->mstatus & MSTATUS_FS));
        }
    }
    /*
     * Rollback with EXTERNAL REPLAY.  env->mip is architectural register
     * state, so a speculative CSR write to sip/mip is reverted with everything
     * else -- interrupts remain untouched and unhandled by the wrong path.
     * But env->mip is also where the machine's interrupt controllers park
     * their pending bits, and a device assertion that lands inside the
     * excursion window is not speculative: rewinding it silently drops a real
     * interrupt.  Only the TIMER bits had a recovery path (the exit reconcile
     * re-derives them from the architected compare registers); the PLIC's
     * SEIP/MEIP, the ACLINT software interrupt's MSIP/SSIP, SGEIP and LCOFIP
     * had none, and were simply lost.
     *
     * riscv_cpu_update_mip separates the two cases at the source -- it logs
     * the externally-caused delta and ignores the guest's own writes -- so the
     * replay here is exact: revert everything, then re-apply the external
     * delta.  Timer bits are excluded from that delta: the reconcile owns
     * them, and carrying them here as well would give interrupt delivery a
     * second, competing opinion.
     */
    {
        /*
         * Rewind, read the record and re-apply it as ONE step with respect to
         * riscv_cpu_update_mip.  That function is the record's only writer and
         * env->mip's only external writer, and it holds the BQL for both, so
         * taking the BQL here is what makes the replay exact.  Without it a
         * raise landing between the read and the memcpy is written into a
         * record that the trailing reset then zeroes unread -- the bit is
         * neither kept in env->mip (the memcpy rewound it) nor replayed, and a
         * lost MIP_MSIP deadlocks the guest, since the ACLINT holds no latch of
         * its own to re-assert from.
         *
         * The lock is taken once per excursion (the two callers are the
         * plugin's normal qemu_plugin_cpu_state_restore and the abnormal
         * cpu_exec_longjmp_cleanup, both excursion exits), and the ordering -- plugin walk lock, then BQL -- is the one
         * cpu_plugin_excursion_open already establishes on the same thread.
         */
        bool need_bql = !bql_locked();
        uint64_t replay_set, replay_clear, live_dev;

        if (need_bql) {
            bql_lock();
        }
        replay_set = env->plugin_irq_delta.set;
        replay_clear = env->plugin_irq_delta.clear;
        /*
         * MSIP, MEIP and SGEIP are device state that merely lives in an
         * architectural register: they are absent from csr.c's delegable_ints,
         * so rmw_mip64 masks every guest write to them out and no instruction
         * -- speculative or not -- can change them.  A speculative excursion
         * therefore has nothing to roll back there, and carrying the live
         * value forward makes the erasure structurally impossible rather than
         * merely raced-free.  This is the same treatment ARM's irq_line_state
         * gets above, and it agrees with the replay whenever the replay is
         * right, so it perturbs nothing.
         *
         * MTIP is guest-unwritable too but stays out of this: the
         * excursion-exit reconcile re-derives it from the architected compare
         * registers, and a second opinion held here would compete with it.
         * It is excluded from the replay mask for exactly that reason.
         */
        live_dev = env->mip & RISCV_MIP_DEVICE_OWNED;

        cst_miperase_check(env, (const CPURISCVState *)saved,
                           replay_set, replay_clear);
        memcpy(env, saved, size);
        env->mip = (((env->mip | replay_set) & ~replay_clear)
                    & ~(uint64_t)RISCV_MIP_DEVICE_OWNED) | live_dev;
        env->plugin_irq_delta.set = 0;
        env->plugin_irq_delta.clear = 0;
        if (need_bql) {
            bql_unlock();
        }
    }
    /* Timer resync runs in cpu_plugin_excursion_close, not here. */
#else
    memcpy(env, saved, size);
#endif
#elif defined(TARGET_MIPS)
#if !defined(CONFIG_USER_ONLY)
    /*
     * The R4K host timer (env->timer) lives outside this register snapshot.
     * A restore that rolls CP0_Count/Compare back is reconciled by
     * mips_cpu_plugin_resync_timers, which re-arms from the restored compare
     * on every excursion exit whether or not anything here noticed the
     * rollback.  Nothing is recorded for the TIMER before the memcpy,
     * because the live env cannot gain a Cause.TI the snapshot lacks.  The
     * excursion window opens BEFORE the snapshot is taken and under the BQL,
     * so every caller of cpu_mips_timer_expire sees the flags: mips_timer_cb
     * runs from the main loop holding that same BQL, and the other two run
     * on this vCPU thread.  The gate therefore always returns, and a
     * speculative MTC0 can only CLEAR Cause.TI, never set it.
     *
     * Rollback with EXTERNAL REPLAY (the riscv mip pattern above, adapted).
     * Cause.IP1..IP0 are guest-written architectural state and Cause.TI is
     * owed by the timer machinery, so rewinding those with the snapshot is
     * exactly right.  But IP7..IP2 are read-only to the guest --
     * cpu_mips_store_cause's write mask excludes them -- so every in-window
     * writer of those bits is an external device (i8259/CBUS UART lines,
     * GIC, IPIs) whose raise is real, and unlike the timer bit there is no
     * compare register to re-derive it from: rewinding it silently drops the
     * interrupt.  cpu_mips_irq_request records the externally-caused delta;
     * replay it over the rewound Cause.
     *
     * Read the record, rewind, re-apply and zero as ONE BQL bracket.
     * cpu_mips_irq_request is the record's only writer and holds the BQL, so
     * the bracket is what orders the replay against a concurrent iothread
     * raise: without it a raise landing between the mask read and the reset
     * below is zeroed unread -- neither kept in Cause (the memcpy rewound
     * its qatomic_or) nor replayed.  The lock is taken once per excursion
     * (the two callers are the plugin's normal qemu_plugin_cpu_state_restore
     * and the abnormal cpu_exec_longjmp_cleanup, mutually exclusive excursion
     * exits; nothing restores mid-excursion), and the ordering -- plugin walk lock, then
     * BQL -- is the one cpu_plugin_excursion_open already establishes on
     * this thread.  The masks live after end_reset_fields, outside the
     * snapshot, so the memcpy cannot roll the record itself back.  Zeroing
     * them here is the consume-once step; the reset at window open
     * (cpu_plugin_excursion_open) clears anything recorded after this
     * consume, so the NEXT excursion cannot replay a raise the guest may
     * have acknowledged in between.  The exit reconcile
     * (mips_cpu_plugin_resync_timers -> mips_cpu_plugin_reconcile_irq) then
     * recomputes CPU_INTERRUPT_HARD from the now-correct Cause, so a
     * replayed raise produces its kick edge through the reconcile.
     */
    {
        bool need_bql = !bql_locked();
        uint32_t replay_set, replay_clear;

        if (need_bql) {
            bql_lock();
        }
        replay_set = env->plugin_irq_delta.set;
        replay_clear = env->plugin_irq_delta.clear;
        memcpy(env, saved, size);
        /* Atomic for the same reason as cpu_mips_irq_request's own update:
         * a peer VPE's mttc0 read-modify-write of this whole word runs on
         * its vCPU thread without the BQL. */
        qatomic_or(&env->CP0_Cause, replay_set);
        qatomic_and(&env->CP0_Cause, ~replay_clear);
        env->plugin_irq_delta.set = 0;
        env->plugin_irq_delta.clear = 0;
        if (need_bql) {
            bql_unlock();
        }
    }
    /* Timer resync runs in cpu_plugin_excursion_close, not here. */
#else
    memcpy(env, saved, size);
#endif
#else
    memcpy(env, saved, size);
#endif
}

#if !defined(CONFIG_USER_ONLY)
/*
 * x86 only, and not a diagnostic: set when cpu_plugin_excursion_open kept
 * the BQL for the excursion, so cpu_plugin_excursion_close releases it.
 * Per-EXCURSION, therefore per-vCPU (__thread, like every other
 * per-excursion datum here): the pause that sets it and the resume that
 * consumes it are two halves of one vCPU's excursion.  Shared, two vCPUs
 * would cross: A's pause sets it and keeps the BQL, B's resume reads A's
 * flag as its own and reaches bql_unlock() without holding the lock, while
 * A's own resume then sees it false and never unlocks.
 */
static __thread bool g_excursion_holds_bql;     /* x86: open kept the BQL */

/*
 * Instruction-counter position captured at wrong-path excursion entry and put
 * back at exit, so the excursion consumes zero icount just as the tick freeze
 * makes it consume zero wall-clock guest time.  Thread-local rather than
 * per-CPU because the pause/resume pair always runs on the vCPU's own thread,
 * and the pair is made non-reentrant by plugin_excursion_active.
 */
static __thread IcountFreeze g_excursion_icount;

/* Guest-insn slice bounding: the CORRECT PATH's remaining slice budget,
 * saved at excursion open and restored at excursion close (see
 * cpu_plugin_excursion_open/_close). */
static __thread uint16_t g_tcg_slice_exc_low;
static __thread bool g_tcg_slice_exc_low_active;

/*
 * The per-target clock resynchronisation hook (TCGCPUOps::plugin_clock_resync).
 * Every guest-observable clock and every armed host QEMUTimer is reconciled
 * to the FROZEN virtual time by the target, at the end of both plugin clock
 * freezes.  The generic code owns the freeze/thaw and the ordering; the
 * target owns the knowledge of what its clocks are.  See the hook's contract
 * in include/accel/tcg/cpu-ops.h.
 */
static void cpu_plugin_clock_resync(CPUState *cpu,
                                    CPUPluginClockResyncReason why)
{
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;

    if (tcg_ops && tcg_ops->plugin_clock_resync) {
        tcg_ops->plugin_clock_resync(cpu, why);
    }
}
#endif

/*
 * The excursion and clock-window helpers below have softmmu-only side
 * effects.  Compiled per-target so CONFIG_USER_ONLY selects the no-op forms;
 * the common plugins/api.c calls these rather than referencing
 * cpu_disable_ticks directly (which is not linked into user-mode binaries).
 * Their callers are plugins/api.c and cpu_exec_longjmp_cleanup(), and this
 * file is built only with plugins enabled.
 */
void cpu_plugin_excursion_open(CPUState *cpu)
{
#ifndef CONFIG_USER_ONLY
    /*
     * Freeze the guest virtual clock across a whole wrong-path excursion so
     * the speculative run's host wall-clock time does not advance the guest's
     * architected timer counters (CNTVCT / TSC / time / Count) -- WP is outside
     * guest time.  Idempotent + balanced via plugin_excursion_active: a
     * second pause before the matching resume is a no-op.
     */
    if (cpu->plugin_excursion_active) {
        return;
    }
    bool need_bql = !bql_locked();
    if (need_bql) {
        bql_lock();
    }
    cst_clkprobe(false);              /* CST_CLKPROBE skew sample (gated) */
    /* CST_NOFREEZE lever: keep the excursion window and the resync, but
     * leave the guest virtual clock running. */
    if (!cst_nofreeze()) {
        /*
         * The SPECULATIVE freeze: the clock's value stops, and so does its
         * processing.  This is the only bracket that stops processing, and
         * the reason is that this is the only bracket inside which the guest
         * is not between two of its own instructions -- there is no legal
         * position here for an event derived from guest time.  The
         * correct-path instrumentation window below
         * (cpu_plugin_cb_window_open) keeps the value-only freeze: it brackets
         * a callback that runs beside real guest execution, where every
         * guest-time event still has a position and only the callback's host
         * cost must be kept out of the clock.
         */
        cpu_plugin_spec_clock_freeze(cpu->cpu_index);
        /* The other half of the freeze: under -icount the guest clock is
         * driven by retired instructions, which cpu_disable_ticks() does not
         * touch.  See icount_freeze(). */
        icount_freeze(cpu, &g_excursion_icount);
    }
    /*
     * Guest-insn slice bounding: the default-clock mirror of
     * icount_freeze's u16.low capture (that call is a no-op off
     * icount).  Save the CORRECT PATH's remaining budget here, at the
     * true excursion open; every spec-mode dispatch runs on its own
     * full quantum (cpu_plugin_exec_tb/_inline), and
     * cpu_plugin_excursion_close puts this value back, so WP depth
     * cannot drain the CP slice.  Deliberately OUTSIDE the
     * cst_nofreeze() gate above: the budget rule must not silently
     * change under that lever.
     */
    if (unlikely(tcg_slice_armed)) {
        g_tcg_slice_exc_low = cpu->neg.icount_decr.u16.low;
        g_tcg_slice_exc_low_active = true;
        tcg_slice_note_exc_save();
    }
    cst_clkaudit_note_pause();       /* every root a guest clock derives from */
#if defined(TARGET_RISCV)
    /*
     * Start the excursion's pending-interrupt record empty, and do it under
     * the same BQL hold that opens the window, so riscv_cpu_update_mip (which
     * takes the BQL for its update) cannot have a raise recorded and then
     * wiped by this reset.
     *
     * The record is only consumed by cpu_plugin_arch_state_restore, which
     * fires at excursion exit while the window is still open: a raise landing
     * after that consume and before cpu_plugin_excursion_close closes the
     * window is recorded but never replayed -- correctly, because nothing
     * rewinds env->mip after the restore, so the bit is already live.  Left in
     * place it would be replayed by the NEXT excursion's restore, resurrecting
     * an interrupt the guest may have acknowledged in between.  Clearing here
     * makes each excursion's replay describe only that excursion.
     */
    {
        CPURISCVState *renv = cpu_env(cpu);
        renv->plugin_irq_delta.set = 0;
        renv->plugin_irq_delta.clear = 0;
    }
#endif
#if defined(TARGET_MIPS)
    /*
     * Same rule for the mips external Cause.IP record: start it empty, under
     * the same BQL hold that opens the window (cpu_mips_irq_request, the
     * record's only writer, takes the BQL for its update).  The consume-then-
     * reset argument is the riscv comment above, verbatim: a raise recorded
     * after the restore's consume and before this window closes is already
     * live in CP0_Cause (nothing rewinds it after the restore), and clearing
     * the residue here keeps the NEXT excursion's replay from resurrecting
     * an interrupt the guest may have acknowledged in between.
     */
    {
        CPUMIPSState *menv = cpu_env(cpu);
        menv->plugin_irq_delta.set = 0;
        menv->plugin_irq_delta.clear = 0;
    }
#endif
    cpu->plugin_excursion_active = true;
    if (wprot_ready()) {           /* CST_WPROTECT: write-protect guest RAM */
        wprot_setprot(PROT_READ);
        g_wprot_active = true;
    }
    sdiff_snapshot(cpu);           /* CST_STATEDIFF: snapshot CPU state */
    tlbsave_snapshot(cpu);         /* CST_TLB_SAVE: snapshot full TLB */
    /*
     * x86 only: keep the BQL across the whole wrong-path excursion, so the
     * main loop (iothread) cannot interleave with it; the close releases it
     * (g_excursion_holds_bql).  x86 alone, because on the other targets
     * wrong-path execution legitimately takes the BQL for a sandboxed device
     * access and holding it here would self-deadlock (bql_lock asserts
     * !bql_locked()).
     * The excursion's lock order is plugin lock, then BQL, on every target:
     * any seam that dispatches a plugin callback with the BQL already held
     * must drop it first, as the shutdown dispatch in plugins/system.c does.
     * CST_NO_BQLHOLD disables the hold, for A/B comparison.
     */
#if defined(TARGET_I386)
    {
        static int no_hold = -1;   /* CST_NO_BQLHOLD: A/B the BQL-hold */
        if (no_hold < 0) {
            no_hold = getenv("CST_NO_BQLHOLD") != NULL;
        }
        if (need_bql && !no_hold) {
            g_excursion_holds_bql = true;
            return;                /* keep BQL; resume releases it */
        }
    }
#endif
    if (need_bql) {
        bql_unlock();
    }
#endif
}

void cpu_plugin_excursion_close(CPUState *cpu)
{
#ifndef CONFIG_USER_ONLY
    if (!cpu->plugin_excursion_active) {
        return;
    }
    bool we_hold_from_pause = g_excursion_holds_bql; /* x86: open kept BQL */
    g_excursion_holds_bql = false;
    bool need_bql = !bql_locked();
    if (need_bql) {
        bql_lock();
    }
    /*
     * Give back the freeze this excursion took.  cpu_plugin_clock_thaw() owns
     * both the arbitration and the vm_stop deference: the clock restarts only
     * when the LAST outstanding plugin freeze closes -- this excursion's, the
     * correct-path instrumentation window nested around it on this vCPU, and
     * any window a PEER vCPU has open, all of which drive the one global
     * cpu_ticks_enabled -- and never while a vm_stop owns the stopped clock.
     */
    int64_t clkaudit_pre_thaw[CST_CLKROOT__COUNT] = { 0 };
    if (cst_clkaudit_on()) {
        /* Sampled here, inside the still-open window: this is what the guest
         * would have read had it executed one more instruction before the
         * excursion closed, and it is the only place the "did the freeze hold
         * for the WHOLE window" half of the question can be answered. */
        cst_clkaudit_sample(clkaudit_pre_thaw);
    }
    /* CST_NOFREEZE lever: the pause never froze, so there is nothing to
     * thaw. */
    if (!cst_nofreeze()) {
        /* Value back first, then processing -- see the pair's contract. */
        cpu_plugin_spec_clock_thaw(cpu->cpu_index);
    }
    /*
     * The icount position belongs to the excursion that captured it, not to
     * whichever freeze happens to be last out: restore it here unconditionally
     * (a no-op when icount is off or the record was never armed).
     */
    icount_thaw(cpu, &g_excursion_icount);
    /*
     * Guest-insn slice bounding: the matching CP budget restore.  This
     * function runs on BOTH excursion exits (the plugin's normal
     * qemu_plugin_spec_vtime_resume and the abnormal
     * cpu_exec_longjmp_cleanup), same as the thaw above, so the CP slice
     * resumes with exactly the budget it entered with regardless of what
     * the wrong path spent.
     */
    if (g_tcg_slice_exc_low_active) {
        cpu->neg.icount_decr.u16.low = g_tcg_slice_exc_low;
        g_tcg_slice_exc_low_active = false;
        tcg_slice_note_exc_restore();
    }
    cpu->plugin_excursion_active = false;
    cst_clkprobe(true);            /* CST_CLKPROBE skew sample (gated) */
    if (g_wprot_active) {          /* CST_WPROTECT: guest RAM read-write again */
        wprot_setprot(PROT_READ | PROT_WRITE);
        g_wprot_active = false;
    }
    tlbsave_restore(cpu);         /* CST_TLB_SAVE: revert full TLB */
    /*
     * Resync every guest clock to the frozen virtual time HERE, once per
     * excursion.  The register restore runs exactly once per excursion, at
     * its exit (the plugin's qemu_plugin_spec_mode_end +
     * qemu_plugin_cpu_state_restore, or cpu_exec_longjmp_cleanup), and the
     * resync must follow it: after the thaw, and with spec mode already
     * ended, so it reconciles the clocks against the final state.
     *
     * Unconditional and per-target: every registered target reconciles all
     * of its clocks here, whether or not this particular excursion is known
     * to have perturbed one, so no clock source can drift for want of a
     * flag.
     */
    cpu_plugin_clock_resync(cpu, CPU_PLUGIN_CLOCK_EXCURSION_END);
    /*
     * The excursion's defining requirement, checked where it must hold: every
     * guest clock root now reads what it read when the excursion began.
     * Sampled after the thaw and after the per-target resync, so it sees the
     * value the guest will see.
     */
    cst_clkaudit_check(cpu, clkaudit_pre_thaw);
    /*
     * The leak diff belongs after the LAST step of the restore, for the same
     * reason: a comparison taken before the restore finishes reports the work
     * the restore has not done yet as work it will never do.
     */
    sdiff_compare(cpu);            /* CST_STATEDIFF: un-restored state leak */
    /*
     * Kick re-arm, the other half of the wrong-path kick deferral in
     * cpu_plugin_exec_tb.  Edge semantics: reconstruct the kick iff this
     * excursion actually cleared one (plugin_spec_kick_deferred, set by the
     * WP dispatch that consumed it), or one is in the register right now
     * (landed after the last dispatch).  The request flags are NOT
     * consulted: interrupt_request holds level bits that stay set while a
     * line is pending (e.g. a masked IRQ), so reconstructing from them would
     * fabricate a kick nobody posted, every excursion, for as long as the
     * line stays high.
     */
    if (cpu->plugin_spec_kick_deferred ||
        qatomic_read(&cpu->neg.icount_decr.u16.high)) {
        qatomic_set(&cpu->neg.icount_decr.u16.high, -1);
    }
    /*
     * The deferral flag must not outlive its excursion: this resume runs on
     * BOTH exit paths (the plugin's normal resume and the abnormal
     * cpu_exec_longjmp_cleanup), so clearing it here -- outside the branch
     * above -- is what keeps a deferred kick from leaking into the next
     * excursion's re-arm decision.
     */
    cpu->plugin_spec_kick_deferred = false;
    if (need_bql || we_hold_from_pause) {
        bql_unlock();
    }
#endif
}

/*
 * Nestable guest-virtual-clock freeze for plugin instrumentation windows
 * (translation-time decoding, per-TB trace emission).  Same transparency
 * principle as the wrong-path vtime pause above -- plugin work is outside
 * guest execution, so its host wall-clock cost must not advance guest time --
 * but for the CORRECT-path instrumentation cost.  Without this, a heavily
 * instrumented guest tick handler can cost more guest time than one tick
 * period, leaving the next tick already pending on return: the guest
 * collapses into a self-sustaining tick/scheduler storm (context-switch
 * storm, RCU-kthread starvation, zero foreground progress).
 *
 * Nesting (plugin_cb_window_depth) counts this vCPU's own windows, so callers
 * can wrap arbitrary regions without coordinating.  Composition with the WP
 * pause, and with a window open on a DIFFERENT vCPU, is not this counter's
 * job: each vCPU's outermost window takes one reference on the machine-wide
 * freeze (cpu_plugin_clock_freeze), and the clock restarts only when the last
 * reference anywhere goes away -- a translation callback on one vCPU may
 * run inside another vCPU's wrong-path excursion, and closing its window
 * must not restart the clock underneath that excursion.  The vm_stop guard
 * lives in cpu_plugin_clock_thaw(): never re-enable a clock a vm_stop owns.
 *
 * VALUE ONLY, and that is the difference from the wrong-path pause.  This
 * window brackets a callback that runs beside guest execution the guest
 * really performed: the guest sits between two of its own instructions, so
 * every event derived from guest time still has a legal position and the only
 * requirement is that the callback's host cost stays out of the clock.
 * Suspending the clock's PROCESSING here as well would stop the guest's
 * timers from being evaluated once per translation block.  The processing
 * stall belongs to cpu_plugin_spec_clock_freeze() and to nothing else.
 */
void cpu_plugin_cb_window_open(CPUState *cpu)
{
#ifndef CONFIG_USER_ONLY
    if (cpu->plugin_cb_window_depth++ > 0) {
        return;                    /* already frozen by an outer window */
    }
    if (cst_nofreeze()) {
        return;
    }
    bool need_bql = !bql_locked();
    if (need_bql) {
        bql_lock();
    }
    cpu_plugin_clock_freeze(cpu->cpu_index);
    if (need_bql) {
        bql_unlock();
    }
#endif
}

void cpu_plugin_cb_window_close(CPUState *cpu)
{
#ifndef CONFIG_USER_ONLY
    g_assert(cpu->plugin_cb_window_depth > 0);
    if (--cpu->plugin_cb_window_depth > 0) {
        return;                    /* still frozen by an outer window */
    }
    if (cst_nofreeze()) {
        return;
    }
    bool need_bql = !bql_locked();
    if (need_bql) {
        bql_lock();
    }
    if (cpu_plugin_clock_thaw(cpu->cpu_index)) {
        /*
         * The clock actually restarted here: no guest state moved, but each
         * target still has to reconcile the clocks it owns to the frozen
         * time -- an armed host QEMUTimer whose deadline was computed against
         * the pre-freeze virtual clock, above all.  The x86 TSC needs no
         * re-pinning: cpu_get_ticks() derives from cpu_get_clock() while a
         * plugin is installed (plugin_tsc_from_clock, system/cpu-timers.c),
         * so x86's hook has nothing to do past its one-shot arming.
         */
        cpu_plugin_clock_resync(cpu, CPU_PLUGIN_CLOCK_CB_WINDOW_END);
    }
    if (need_bql) {
        bql_unlock();
    }
#endif
}
