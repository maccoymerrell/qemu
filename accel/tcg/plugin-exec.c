/*
 * Plugin entry points that run guest code from a plugin callback:
 * execute one instruction or one block at the current PC, translate a
 * block without executing it, and the wrong-path TLB containment and
 * capability query that bracket those runs.
 *
 * Copyright (C) 2026, Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "exec/cpu-common.h"
#include "exec/translation-block.h"
#include "tcg/tcg.h"
#include "qemu/atomic.h"
#include "qemu/main-loop.h"
#include "exec/cpu-all.h"
#include "exec/exec-all.h"
#include "qemu/qemu-plugin.h"
#include "tb-internal.h"
#include "qemu/tcg-slice.h"
#include "internal-common.h"
#include "internal-target.h"
#include "exec/cputlb.h"

/*
 * Execute one instruction at the current PC from a plugin callback.
 * Returns true on success, false on failure (e.g. unmapped PC).
 */
bool cpu_plugin_exec_inline(CPUState *cpu)
{
    CPUArchState *env = cpu_env(cpu);
    TranslationBlock *tb;
    vaddr pc;
    uint64_t cs_base;
    uint32_t flags, cflags;
    int tb_exit;
    bool saved_running;

    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

    cflags = curr_cflags(cpu);
    /* Execute in serial context, exactly 1 instruction, no chaining.
     * CF_SINGLE_STEP prevents rep-prefixed instructions from looping. */
    cflags &= ~CF_PARALLEL;
    cflags |= CF_NO_GOTO_TB | CF_NO_GOTO_PTR | CF_MEMI_ONLY
            | CF_SINGLE_STEP | 1;

    /* Force slow-path memory ops so the spec store buffer can intercept */
    if (cpu->plugin_spec_mode) {
        cflags |= CF_FORCE_SLOW;
    }

    /* Verify the PC page is mapped before translation */
    void *host;
    int pflags = probe_access_flags(env, pc, 1, MMU_INST_FETCH,
                                    cpu_mmu_index(cpu, true),
                                    true, &host, 0);
    if (pflags & TLB_INVALID_MASK) {
        return false;
    }

    /*
     * Save and restore cpu->running to avoid assertion failures
     * when called from a plugin callback context.
     */
    saved_running = cpu->running;
    /* Restored by the landing pad: see cpu_plugin_exec_tb. */
    uint32_t saved_cflags_next_tb = cpu->cflags_next_tb;

    /*
     * Set up a local exception landing pad so faults during wrong-path
     * execution longjmp back here instead of the outer cpu_exec loop.
     *
     * TRANSLATION IS INSIDE THE PAD, NOT BEFORE IT.  tb_gen_code() can raise:
     * translator_ld() reading the second page of a block that straddles a page
     * boundary siglongjmps through cpu->jmp_env from inside the translator.
     * With the codegen ahead of the sigsetjmp that fault unwound PAST this
     * function to whatever pad the caller had installed -- and this function's
     * caller is a plugin callback, which that pad does not know how to
     * resume: it would continue the interrupted guest execution with the
     * plugin's own stack frame abandoned.  Under the pad the same fault lands
     * below, cpu->jmp_env is put back, and the caller gets false.
     */
    sigjmp_buf saved_jmp_env;
    memcpy(&saved_jmp_env, &cpu->jmp_env, sizeof(sigjmp_buf));

    if (sigsetjmp(cpu->jmp_env, 0) == 0) {
        tb = tb_lookup(cpu, pc, cs_base, flags, cflags);
        if (tb == NULL) {
            mmap_lock();
            tb = tb_gen_code(cpu, pc, cs_base, flags, cflags);
            mmap_unlock();
            if (tb == NULL) {
                cpu->running = saved_running;
                memcpy(&cpu->jmp_env, &saved_jmp_env, sizeof(sigjmp_buf));
                return false;
            }
        }

#ifndef CONFIG_USER_ONLY
        /* Guest-insn slice bounding: same spec-dispatch quantum rule as
         * cpu_plugin_exec_tb -- see the comment there. */
        if (unlikely(tcg_slice_armed)) {
            if (cpu->plugin_spec_mode) {
                cpu->neg.icount_decr.u16.low = tcg_slice_quantum;
                tcg_slice_note_wp_reload();
            } else {
                tcg_slice_note_nonspec_dispatch();
            }
        }
#endif
        cpu_tb_exec(cpu, tb, &tb_exit);
        cpu->running = saved_running;
        memcpy(&cpu->jmp_env, &saved_jmp_env, sizeof(sigjmp_buf));
        return true;
    } else {
        /* Exception during wrong-path execution; clean up and report */
        cpu->neg.can_do_io = true;
        qemu_plugin_disable_mem_helpers(cpu);
#ifdef CONFIG_USER_ONLY
        clear_helper_retaddr();
#endif
        /*
         * The translation above is inside this pad, so this pad owns what
         * tb_gen_code was holding when it unwound: the TB's PageDesc locks
         * under softmmu, the memory lock in user mode, and the in-flight
         * pointer in both.  The live siblings release exactly this, for
         * exactly this reason, and this one could not before because its
         * codegen ran outside.
         */
        tcg_ctx_drop_gen_tb();
        cpu->cflags_next_tb = saved_cflags_next_tb;
        cpu->running = saved_running;
        memcpy(&cpu->jmp_env, &saved_jmp_env, sizeof(sigjmp_buf));
        /* A yield is a block that ran: see cpu_plugin_exec_tb. */
        if (cpu->plugin_spec_mode && cpu->exception_index == EXCP_YIELD) {
            cpu->exception_index = -1;
            return true;
        }
        return false;
    }
}

/*
 * Execute one full translation block at the current PC from a plugin
 * callback.  All plugin callbacks fire -- tb_exec, insn_exec, inline ops,
 * and mem -- so the plugin sees the speculative TB the same way it sees a
 * normal CP TB and can deliver its instructions through the per-TB
 * exec-cb udata.  The plugin is responsible for keeping its own state
 * separated (e.g. early-out for spec-mode invocations of CP-only state
 * mutations, and saving/restoring scoreboard slots clobbered by inline
 * stores around spec-mode entry).  Returns true on success, false on
 * failure (e.g. unmapped PC, exception).
 *
 * The block must hand control back after bounded work, so it is built
 * unchained (CF_NO_GOTO_TB | CF_NO_GOTO_PTR: the TB exits to this caller
 * instead of jumping to its successor) and with CF_SINGLE_ITER, which
 * makes a self-looping instruction (x86 REP) retire one iteration per
 * block instead of ploughing through its whole count inside one TB.
 * Nothing else about the translation changes: in particular it is NOT
 * CF_SINGLE_STEP, which means "gdb is single-stepping" and which a
 * translator may honour by relaxing rules the correct path obeys (MIPS
 * lets such a block run on past a page boundary to keep a branch with its
 * delay slot).  A wrong-path block ends where the correct path's would.
 */
bool cpu_plugin_exec_tb(CPUState *cpu)
{
    CPUArchState *env = cpu_env(cpu);
    TranslationBlock *tb;
    vaddr pc;
    uint64_t cs_base;
    uint32_t flags, cflags;
    int tb_exit;
    bool saved_running;

    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

    cflags = curr_cflags(cpu);
    cflags &= ~CF_PARALLEL;
    cflags |= CF_NO_GOTO_TB | CF_NO_GOTO_PTR | CF_SINGLE_ITER;

    if (cpu->plugin_spec_mode) {
        cflags |= CF_FORCE_SLOW;
    }

    void *host;
    int pflags = probe_access_flags(env, pc, 1, MMU_INST_FETCH,
                                    cpu_mmu_index(cpu, true),
                                    true, &host, 0);
    if (pflags & TLB_INVALID_MASK) {
#if !defined(CONFIG_USER_ONLY)
        /*
         * Wrong-path fetch-gate reject classifier (CST_FETCHGATE_DIAG).  The
         * probe above already ran the target walker with probe=true, which
         * walks EXISTING PTEs without demand-paging: a present, executable,
         * privilege-OK but merely iTLB-cold page WALKS + FILLS + succeeds (it
         * never lands here).  Landing here therefore means a real instruction
         * fetch at the speculating context would FAULT -- which is exactly the
         * "translation-unavailable" terminate the wrong path takes.  The side
         * effect-free debug walk plus a MMU_DATA_LOAD probe classify WHY:
         *   phys==-1                -> absent (no PTE): a demand-page would be
         *                             required; correctly declined.
         *   phys!=-1, dload INVALID -> present but access-denied at this
         *                             privilege (SMEP/SMAP/US/cross-domain).
         *   phys!=-1, dload valid   -> present + readable but NON-executable
         *                             (NX): a data region, not code.
         * All three are legitimate terminates; the classifier only exists so
         * a future WP-fetch question can be reconciled from runtime evidence
         * without a rebuild (it never changes control flow).
         */
        if (unlikely(getenv("CST_FETCHGATE_DIAG"))) {
            hwaddr phys = cpu_get_phys_page_debug(cpu, pc & TARGET_PAGE_MASK);
            void *dhost;
            int dflags = probe_access_flags(env, pc, 1, MMU_DATA_LOAD,
                                            cpu_mmu_index(cpu, false),
                                            true, &dhost, 0);
            const char *verdict =
                phys == (hwaddr)-1        ? "absent-no-PTE"
                : (dflags & TLB_INVALID_MASK) ? "present-access-denied"
                                          : "present-non-executable-NX";
            fprintf(stderr, "[fetchgate] reject pc=0x%" PRIx64
                    " ifetch_pflags=0x%x dload_pflags=0x%x ifidx=%d didx=%d"
                    " phys=0x%" PRIx64 " verdict=%s (correct-terminate)\n",
                    (uint64_t)pc, pflags, dflags,
                    cpu_mmu_index(cpu, true), cpu_mmu_index(cpu, false),
                    (uint64_t)phys, verdict);
        }
#endif
        return false;
    }

    saved_running = cpu->running;
    /*
     * An unwind out of the block can mint cflags for the NEXT translation
     * on its way out: cpu_io_recompile (a device access that is not the
     * block's last instruction), a stop-after-access watchpoint, precise
     * SMC.  Each names the instruction it unwound at, and the main loop
     * consumes it at its next tb_find -- but an unwind out of this call
     * lands in the pad below, not the main loop, and the caller does not
     * resume at that instruction.  The correct path resumes from the
     * plugin callback's own block, and a value left behind would be spent
     * on whatever block the correct path translates next (a count-limited
     * CF_MEMI_ONLY | CF_NOIRQ block after cpu_io_recompile).  The pad puts
     * back the value the call found, so nothing minted inside the call
     * outlives it.
     */
    uint32_t saved_cflags_next_tb = cpu->cflags_next_tb;

    /*
     * Install our sigsetjmp guard *before* tb_gen_code(): translation can
     * itself fault (e.g. translator_ld() crossing into an unmapped page
     * during plugin speculative execution), and that path siglongjmps
     * through cpu->jmp_env via cpu_loop_exit_sigsegv().  If we set the
     * guard only around cpu_tb_exec(), a translation-time fault would
     * unwind all the way out to cpu_exec_setjmp(), abandoning the plugin
     * callback frame above us with locks/state held -> deadlock on the
     * next callback.
     */
    sigjmp_buf saved_jmp_env;
    memcpy(&saved_jmp_env, &cpu->jmp_env, sizeof(sigjmp_buf));

    if (sigsetjmp(cpu->jmp_env, 0) == 0) {
        tb = tb_lookup(cpu, pc, cs_base, flags, cflags);
        if (tb == NULL) {
            mmap_lock();
            tb = tb_gen_code(cpu, pc, cs_base, flags, cflags);
            mmap_unlock();
            if (tb == NULL) {
                cpu->running = saved_running;
                memcpy(&cpu->jmp_env, &saved_jmp_env, sizeof(sigjmp_buf));
                return false;
            }
        }
#if !defined(CONFIG_USER_ONLY)
        /*
         * Wrong-path kick deferral.  A cpu_exit() kick that lands during a
         * speculative excursion (iothread IRQ raise, another vCPU's exclusive
         * request, vm_stop) sets icount_decr.u16.high, which makes every TB --
         * including this wrong-path TB -- exit at its prologue without
         * retiring an instruction.  A plugin that stops an excursion on zero
         * forward progress would then truncate it, so the wrong path's
         * content would depend on host IRQ timing.  Clear the exit-request
         * half for the speculative exec (the .low half is icount budget and
         * is not touched).  The resume re-arms the kick iff this excursion
         * consumed one (plugin_spec_kick_deferred) or one is pending now --
         * see cpu_plugin_excursion_close -- so the correct path observes
         * delivery exactly as if the excursion had taken zero host time.
         */
        if (cpu->plugin_spec_mode) {
            if (qatomic_xchg(&cpu->neg.icount_decr.u16.high, 0)) {
                cpu->plugin_spec_kick_deferred = true;
            }
        }
        /*
         * Guest-insn slice bounding: spec TBs inherit the budget
         * prologue (the arming edge precedes any translation --
         * mirroring icount's effect on WP blocks), and this dispatch's
         * .low half must never present an exhausted budget to a
         * wrong-path TB (the prologue would refuse to execute it and
         * the caller would see a block that never ran).  Give each SPEC-MODE
         * dispatch its own full quantum; the CP value was saved at
         * excursion open and is restored by
         * cpu_plugin_excursion_close.  A dispatch with spec mode
         * CLEAR is only counted (tripwire): it is not entitled to free
         * budget.
         */
        if (unlikely(tcg_slice_armed)) {
            if (cpu->plugin_spec_mode) {
                cpu->neg.icount_decr.u16.low = tcg_slice_quantum;
                tcg_slice_note_wp_reload();
            } else {
                tcg_slice_note_nonspec_dispatch();
            }
        }
#endif
        cpu_tb_exec(cpu, tb, &tb_exit);
        cpu->running = saved_running;
        memcpy(&cpu->jmp_env, &saved_jmp_env, sizeof(sigjmp_buf));
        return true;
    } else {
        cpu->neg.can_do_io = true;
        qemu_plugin_disable_mem_helpers(cpu);
#ifdef CONFIG_USER_ONLY
        clear_helper_retaddr();
#endif
        /*
         * A translation-time fault lands here from INSIDE tb_gen_code: a
         * wrong-path translator_ld() crossing into an absent page unwinds
         * via cpu_loop_exit_restore (the spec_real_access abort in
         * cputlb.c's tlb_fill_align) while tb_gen_code still holds the TB's
         * PageDesc lock(s) under softmmu, the memory lock in user mode, and
         * tcg_ctx->gen_tb in both.  The outer loop's landing pad releases
         * those (cpu_exec_longjmp_cleanup); this pad must do the same, or
         * the page spinlock leaks permanently and the next tb_gen_code
         * touching that page spins forever below every plugin callback -- a
         * 100%-utime vCPU freeze.  The pointer belongs to whichever pad
         * catches the unwind, and this pad catches the wrong path's.
         */
        tcg_ctx_drop_gen_tb();
        cpu->cflags_next_tb = saved_cflags_next_tb;
        cpu->running = saved_running;
        memcpy(&cpu->jmp_env, &saved_jmp_env, sizeof(sigjmp_buf));
        /*
         * EXCP_YIELD is not a fault: the instruction gave the CPU back with
         * its architectural state consistent at the PC it restored, and
         * there is nothing to deliver -- in the main loop it only ends the
         * slice.  A restartable instruction bounding its own wrong-path
         * work leaves this way (the FEAT_MOPS Main forms, see
         * mops_spec_yield() in target/arm/tcg/helper-a64.c), so the block
         * counts as executed and the caller continues from that PC, which
         * re-executes the instruction.  Consume the index so nothing
         * outlives the block.
         */
        if (cpu->plugin_spec_mode && cpu->exception_index == EXCP_YIELD) {
            cpu->exception_index = -1;
            return true;
        }
        return false;
    }
}

/*
 * Translate the block at @pc without executing it, so a plugin is told what
 * QEMU makes of code the guest has not reached.
 *
 * Every translation-time callback fires -- vcpu_tb_trans with the whole
 * qemu_plugin_tb, and with it the per-instruction identity and the control
 * notes -- because this is a real translation and translator_loop() emits
 * them.  That is the whole reason the facility exists: what the plugin
 * derives about a block it derives from QEMU's own translation of it, and
 * the qemu_plugin_tb handle that carries that translation is readable only
 * inside the translation callback, so the only way to have QEMU's answer
 * about a block is to have QEMU translate it.  A decoder run beside QEMU can
 * supply a length and a name; it cannot supply what QEMU's translator made
 * of the instruction.
 *
 * The block is KEPT rather than discarded.  A caller asks about a PC because
 * it thinks the guest may reach it; if it does, the cached TB is a hit,
 * vcpu_tb_trans does not fire again, and what the plugin was shown is what
 * executes.
 *
 * Structure follows cpu_plugin_exec_tb() above and stops before
 * cpu_tb_exec(): the non-faulting instruction-fetch probe that declines an
 * unmapped, non-executable or privilege-denied page without demand-paging;
 * the sigsetjmp guard installed BEFORE tb_gen_code, because translation can
 * itself fault (translator_ld() reading the second page of a straddling
 * block) and the caller is a plugin callback the outer pad cannot resume; the
 * memory lock tb_gen_code asserts; and a landing pad that releases what the
 * unwind skipped.
 *
 * cflags are curr_cflags(cpu) verbatim, with nothing added.  The TB produced
 * here has to be the TB the executor would produce at this PC, or keeping it
 * warms nothing and the plugin is shown a translation the guest can never
 * take.  CF_FORCE_SLOW in particular is deliberately absent: it changes
 * cflags, which changes the TB hash key.
 *
 * The translation CONTEXT (cs_base/flags) is the current vCPU state, which is
 * right by construction for a fall-through or a same-mode branch target and
 * wrong for a target in another mode.  Deciding that belongs to the caller,
 * which knows which PC it asked about and why.
 *
 * Returns true iff a TB now exists at @pc.  False means declined -- an
 * unreachable page, a translation-time fault, or a full code buffer -- and
 * nothing was mutated.
 */
bool cpu_plugin_translate_tb(CPUState *cpu, vaddr pc)
{
    CPUArchState *env = cpu_env(cpu);
    TranslationBlock *tb;
    vaddr cur_pc;
    uint64_t cs_base;
    uint32_t flags, cflags;
    bool saved_running;
    bool ok;

    /*
     * A translate-on-demand runs from a vCPU EXEC callback, never from a
     * translation callback and never off the vCPU thread.  Re-entering
     * tb_gen_code from inside a translation corrupts tcg_ctx->gen_tb, which
     * names the translation in flight.  Asserted rather than commented,
     * because the failure is silent.
     *
     * WHOSE translation gen_tb names differs by mode -- see
     * tcg_ctx_drop_gen_tb().  Under softmmu it is this thread's and can be
     * read here.  In user mode every guest thread shares one TCGContext, so
     * reading it here, outside mmap_lock, would be reading whichever peer
     * thread happens to be translating right now; the assert therefore moves
     * to the one point where it is this thread's to read, inside the lock
     * just before tb_gen_code.
     */
    g_assert(cpu == current_cpu);
#ifndef CONFIG_USER_ONLY
    g_assert(tcg_ctx->gen_tb == NULL);
#endif

    cpu_get_tb_cpu_state(env, &cur_pc, &cs_base, &flags);
    cflags = curr_cflags(cpu);

    void *host;
    int pflags = probe_access_flags(env, pc, 1, MMU_INST_FETCH,
                                    cpu_mmu_index(cpu, true),
                                    true, &host, 0);
    if (pflags & TLB_INVALID_MASK) {
        return false;
    }

    saved_running = cpu->running;

    sigjmp_buf saved_jmp_env;
    memcpy(&saved_jmp_env, &cpu->jmp_env, sizeof(sigjmp_buf));

    cpu->plugin_decode_only = true;
    if (sigsetjmp(cpu->jmp_env, 0) == 0) {
        tb = tb_lookup(cpu, pc, cs_base, flags, cflags);
        if (tb == NULL) {
            mmap_lock();
            /* Serialised now, so gen_tb is ours to read in either mode. */
            g_assert(tcg_ctx->gen_tb == NULL);
            tb = tb_gen_code(cpu, pc, cs_base, flags, cflags);
            mmap_unlock();
        }
        ok = (tb != NULL);
    } else {
        /*
         * A translation-time fault landed here from inside tb_gen_code.
         * Release what the unwind skipped, exactly as the two pads above do:
         * the TB's PageDesc locks under softmmu, which leak permanently
         * otherwise, and the in-flight pointer in both modes -- a stale one
         * makes the NEXT translation on this thread look like a re-entry and
         * trips the assert above.
         */
        cpu->neg.can_do_io = true;
        qemu_plugin_disable_mem_helpers(cpu);
#ifdef CONFIG_USER_ONLY
        clear_helper_retaddr();
#endif
        tcg_ctx_drop_gen_tb();
        ok = false;
    }
    cpu->plugin_decode_only = false;
    cpu->running = saved_running;
    memcpy(&cpu->jmp_env, &saved_jmp_env, sizeof(sigjmp_buf));
    return ok;
}

void cpu_plugin_spec_tlb_flush(CPUState *cpu)
{
#ifndef CONFIG_USER_ONLY
    /*
     * CF_FORCE_SLOW routes spec-mode memory through the slow do_ld/do_st
     * helpers, which run tlb_fill on a miss and install TLB entries.  Those
     * entries are not guaranteed valid for the correct-path regime we roll back
     * to (a wrong path can flip EL via `eret`), and the register snapshot can't
     * undo them (the softmmu TLB lives in CPUState, outside the snapshot).
     *
     * A full tlb_flush() here is correct but ruinously expensive: it drops the
     * entire correct-path TLB and jump cache on every excursion, and WP runs
     * constantly.  Instead, tlb_set_page_full logged exactly the pages this
     * excursion installed; invalidate only those (keyed by their install
     * mmu_idx, which encodes the regime).  An excursion that only HIT existing
     * entries logged nothing, so the common case costs zero.  A large-page
     * install or log overflow falls back to the full flush.
     */
    if (cpu->plugin_spec_tlb_log_overflow) {
        tlb_flush(cpu);
    } else {
        cpu_plugin_spec_tlb_flush_logged(cpu);
    }
    cpu->plugin_spec_tlb_log_n = 0;
    cpu->plugin_spec_tlb_log_overflow = false;
#endif
}

/*
 * Spec-mode entry TLB flush -- the portable (host-independent) half of the
 * wrong-path store sandbox.
 *
 * On a host TCG backend that does NOT honor CF_FORCE_SLOW, spec-mode routing
 * to the sandboxed do_ld/do_st helpers relies on TLB_FORCE_SLOW being set on
 * every TLB entry the excursion uses; tlb_set_page_full stamps it on each
 * entry the excursion installs.  Correct-path entries already resident when
 * the excursion begins predate that stamp and lack the flag, so an inline
 * TLB-hit speculative store would reach real guest RAM.  Flush here so those entries refill --
 * with the flag -- inside the excursion, closing the window for pre-existing
 * correct-path entries.
 *
 * Compiled to a no-op on hosts whose backend honors CF_FORCE_SLOW (x86: the
 * inline fast-path bypass already keeps spec-mode data ops off the fast path,
 * so the flag and this flush are unnecessary and would only cost a full TLB
 * reload per excursion), and in user mode (no softmmu TLB).
 */
void cpu_plugin_spec_tlb_flush_enter(CPUState *cpu)
{
#if !defined(CONFIG_USER_ONLY) && !TCG_TARGET_HAS_SPEC_FORCE_SLOW
    tlb_flush(cpu);
#else
    (void)cpu;
#endif
#ifndef CONFIG_USER_ONLY
    cpu_plugin_spec_tlb_note(cpu);
#endif
}

/*
 * Whether a wrong-path (speculative) excursion can be contained on this build,
 * so the plugin can refuse loudly rather than corrupt guest memory.
 *
 * Safe when the host backend honors CF_FORCE_SLOW (its inline qemu_ld/qemu_st
 * bypass routes speculative memory ops to the slow-path helpers in both user
 * and system mode), OR in system mode, where the portable TLB_FORCE_SLOW path
 * (cpu_plugin_spec_tlb_flush_enter + the tlb_set_page_full stamp) contains
 * speculative stores on ANY host backend -- every backend's inline fast-path
 * compare already treats a TLB_FORCE_SLOW entry as a miss.  The only remaining
 * unsupported case is user mode on a backend without CF_FORCE_SLOW: there is
 * no softmmu TLB to carry the flag and stores go straight to the guest image.
 */
bool cpu_plugin_spec_mode_supported(void)
{
#if TCG_TARGET_HAS_SPEC_FORCE_SLOW || !defined(CONFIG_USER_ONLY)
    return true;
#else
    return false;
#endif
}
