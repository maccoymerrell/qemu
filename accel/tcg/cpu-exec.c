/*
 *  emulator main execution loop
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/qemu-print.h"
#include "qapi/error.h"
#include "qapi/type-helpers.h"
#include "hw/core/cpu.h"
#include "accel/tcg/cpu-ops.h"
#include "trace.h"
#include "disas/disas.h"
#include "exec/cpu-common.h"
#include "exec/page-protection.h"
#include "exec/translation-block.h"
#include "exec/tb-flush.h"
#include "tcg/tcg.h"
#include "qemu/atomic.h"
#include "qemu/rcu.h"
#include "exec/log.h"
#include "qemu/main-loop.h"
#include "exec/cpu-all.h"
#include "exec/exec-all.h"
#include "system/cpu-timers.h"
#include "system/runstate.h"
#ifndef CONFIG_USER_ONLY
#include "system/system.h"      /* rtc_clock, for the excursion clock audit */
#endif
#include "exec/replay-core.h"
#include "system/tcg.h"
#include "exec/helper-proto-common.h"
#include "exec/oracle.h"
#include "qemu/qemu-plugin.h"
#include "tb-jmp-cache.h"
#include "tb-hash.h"
#include "tb-context.h"
#include "tb-internal.h"
#include "qemu/cst_bqslice.h"
#include "qemu/vclock-agency.h"
#include "internal-common.h"
#include "internal-target.h"
#include "exec/cputlb.h"

/* -icount align implementation. */

typedef struct SyncClocks {
    int64_t diff_clk;
    int64_t last_cpu_icount;
    int64_t realtime_clock;
} SyncClocks;

#if !defined(CONFIG_USER_ONLY)
/* Allow the guest to have a max 3ms advance.
 * The difference between the 2 clocks could therefore
 * oscillate around 0.
 */
#define VM_CLOCK_ADVANCE 3000000
#define THRESHOLD_REDUCE 1.5
#define MAX_DELAY_PRINT_RATE 2000000000LL
#define MAX_NB_PRINTS 100

int64_t max_delay;
int64_t max_advance;

static void align_clocks(SyncClocks *sc, CPUState *cpu)
{
    int64_t cpu_icount;

    if (!icount_align_option) {
        return;
    }

    cpu_icount = cpu->icount_extra + cpu->neg.icount_decr.u16.low;
    sc->diff_clk += icount_to_ns(sc->last_cpu_icount - cpu_icount);
    sc->last_cpu_icount = cpu_icount;

    if (sc->diff_clk > VM_CLOCK_ADVANCE) {
#ifndef _WIN32
        struct timespec sleep_delay, rem_delay;
        sleep_delay.tv_sec = sc->diff_clk / 1000000000LL;
        sleep_delay.tv_nsec = sc->diff_clk % 1000000000LL;
        if (nanosleep(&sleep_delay, &rem_delay) < 0) {
            sc->diff_clk = rem_delay.tv_sec * 1000000000LL + rem_delay.tv_nsec;
        } else {
            sc->diff_clk = 0;
        }
#else
        Sleep(sc->diff_clk / SCALE_MS);
        sc->diff_clk = 0;
#endif
    }
}

static void print_delay(const SyncClocks *sc)
{
    static float threshold_delay;
    static int64_t last_realtime_clock;
    static int nb_prints;

    if (icount_align_option &&
        sc->realtime_clock - last_realtime_clock >= MAX_DELAY_PRINT_RATE &&
        nb_prints < MAX_NB_PRINTS) {
        if ((-sc->diff_clk / (float)1000000000LL > threshold_delay) ||
            (-sc->diff_clk / (float)1000000000LL <
             (threshold_delay - THRESHOLD_REDUCE))) {
            threshold_delay = (-sc->diff_clk / 1000000000LL) + 1;
            qemu_printf("Warning: The guest is now late by %.1f to %.1f seconds\n",
                        threshold_delay - 1,
                        threshold_delay);
            nb_prints++;
            last_realtime_clock = sc->realtime_clock;
        }
    }
}

static void init_delay_params(SyncClocks *sc, CPUState *cpu)
{
    if (!icount_align_option) {
        return;
    }
    sc->realtime_clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_RT);
    sc->diff_clk = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - sc->realtime_clock;
    sc->last_cpu_icount
        = cpu->icount_extra + cpu->neg.icount_decr.u16.low;
    if (sc->diff_clk < max_delay) {
        max_delay = sc->diff_clk;
    }
    if (sc->diff_clk > max_advance) {
        max_advance = sc->diff_clk;
    }

    /* Print every 2s max if the guest is late. We limit the number
       of printed messages to NB_PRINT_MAX(currently 100) */
    print_delay(sc);
}
#else
static void align_clocks(SyncClocks *sc, const CPUState *cpu)
{
}

static void init_delay_params(SyncClocks *sc, const CPUState *cpu)
{
}
#endif /* CONFIG USER ONLY */

struct tb_desc {
    vaddr pc;
    uint64_t cs_base;
    CPUArchState *env;
    tb_page_addr_t page_addr0;
    uint32_t flags;
    uint32_t cflags;
};

static bool tb_lookup_cmp(const void *p, const void *d)
{
    const TranslationBlock *tb = p;
    const struct tb_desc *desc = d;

    if ((tb_cflags(tb) & CF_PCREL || tb->pc == desc->pc) &&
        tb_page_addr0(tb) == desc->page_addr0 &&
        tb->cs_base == desc->cs_base &&
        tb->flags == desc->flags &&
        tb_cflags(tb) == desc->cflags) {
        /* check next page if needed */
        tb_page_addr_t tb_phys_page1 = tb_page_addr1(tb);
        if (tb_phys_page1 == -1) {
            return true;
        } else {
            tb_page_addr_t phys_page1;
            vaddr virt_page1;

            /*
             * We know that the first page matched, and an otherwise valid TB
             * encountered an incomplete instruction at the end of that page,
             * therefore we know that generating a new TB from the current PC
             * must also require reading from the next page -- even if the
             * second pages do not match, and therefore the resulting insn
             * is different for the new TB.  Therefore any exception raised
             * here by the faulting lookup is not premature.
             */
            virt_page1 = TARGET_PAGE_ALIGN(desc->pc);
            phys_page1 = get_page_addr_code(desc->env, virt_page1);
            if (tb_phys_page1 == phys_page1) {
                return true;
            }
        }
    }
    return false;
}

static TranslationBlock *tb_htable_lookup(CPUState *cpu, vaddr pc,
                                          uint64_t cs_base, uint32_t flags,
                                          uint32_t cflags)
{
    tb_page_addr_t phys_pc;
    struct tb_desc desc;
    uint32_t h;

    desc.env = cpu_env(cpu);
    desc.cs_base = cs_base;
    desc.flags = flags;
    desc.cflags = cflags;
    desc.pc = pc;
    phys_pc = get_page_addr_code(desc.env, pc);
    if (phys_pc == -1) {
        return NULL;
    }
    desc.page_addr0 = phys_pc;
    h = tb_hash_func(phys_pc, (cflags & CF_PCREL ? 0 : pc),
                     flags, cs_base, cflags);
    return qht_lookup_custom(&tb_ctx.htable, &desc, h, tb_lookup_cmp);
}

/**
 * tb_lookup:
 * @cpu: CPU that will execute the returned translation block
 * @pc: guest PC
 * @cs_base: arch-specific value associated with translation block
 * @flags: arch-specific translation block flags
 * @cflags: CF_* flags
 *
 * Look up a translation block inside the QHT using @pc, @cs_base, @flags and
 * @cflags. Uses @cpu's tb_jmp_cache. Might cause an exception, so have a
 * longjmp destination ready.
 *
 * Returns: an existing translation block or NULL.
 */
static inline TranslationBlock *tb_lookup(CPUState *cpu, vaddr pc,
                                          uint64_t cs_base, uint32_t flags,
                                          uint32_t cflags)
{
    TranslationBlock *tb;
    CPUJumpCache *jc;
    uint32_t hash;

    /* we should never be trying to look up an INVALID tb */
    tcg_debug_assert(!(cflags & CF_INVALID));

    hash = tb_jmp_cache_hash_func(pc);
    jc = cpu->tb_jmp_cache;

    tb = qatomic_read(&jc->array[hash].tb);
    if (likely(tb &&
               jc->array[hash].pc == pc &&
               tb->cs_base == cs_base &&
               tb->flags == flags &&
               tb_cflags(tb) == cflags)) {
        goto hit;
    }

    tb = tb_htable_lookup(cpu, pc, cs_base, flags, cflags);
    if (tb == NULL) {
        return NULL;
    }

    jc->array[hash].pc = pc;
    qatomic_set(&jc->array[hash].tb, tb);

hit:
    /*
     * As long as tb is not NULL, the contents are consistent.  Therefore,
     * the virtual PC has to match for non-CF_PCREL translations.
     */
    assert((tb_cflags(tb) & CF_PCREL) || tb->pc == pc);
    return tb;
}

static void log_cpu_exec(vaddr pc, CPUState *cpu,
                         const TranslationBlock *tb)
{
    if (qemu_log_in_addr_range(pc)) {
        qemu_log_mask(CPU_LOG_EXEC,
                      "Trace %d: %p [%08" PRIx64
                      "/%016" VADDR_PRIx "/%08x/%08x] %s\n",
                      cpu->cpu_index, tb->tc.ptr, tb->cs_base, pc,
                      tb->flags, tb->cflags, lookup_symbol(pc));

        if (qemu_loglevel_mask(CPU_LOG_TB_CPU)) {
            FILE *logfile = qemu_log_trylock();
            if (logfile) {
                int flags = 0;

                if (qemu_loglevel_mask(CPU_LOG_TB_FPU)) {
                    flags |= CPU_DUMP_FPU;
                }
#if defined(TARGET_I386)
                flags |= CPU_DUMP_CCOP;
#endif
                if (qemu_loglevel_mask(CPU_LOG_TB_VPU)) {
                    flags |= CPU_DUMP_VPU;
                }
                cpu_dump_state(cpu, logfile, flags);
                qemu_log_unlock(logfile);
            }
        }
    }
}

static bool check_for_breakpoints_slow(CPUState *cpu, vaddr pc,
                                       uint32_t *cflags)
{
    CPUBreakpoint *bp;
    bool match_page = false;

    /*
     * Singlestep overrides breakpoints.
     * This requirement is visible in the record-replay tests, where
     * we would fail to make forward progress in reverse-continue.
     *
     * TODO: gdb singlestep should only override gdb breakpoints,
     * so that one could (gdb) singlestep into the guest kernel's
     * architectural breakpoint handler.
     */
    if (cpu->singlestep_enabled) {
        return false;
    }

    QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
        /*
         * If we have an exact pc match, trigger the breakpoint.
         * Otherwise, note matches within the page.
         */
        if (pc == bp->pc) {
            bool match_bp = false;

            if (bp->flags & BP_GDB) {
                match_bp = true;
            } else if (bp->flags & BP_CPU) {
#ifdef CONFIG_USER_ONLY
                g_assert_not_reached();
#else
                const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;
                assert(tcg_ops->debug_check_breakpoint);
                match_bp = tcg_ops->debug_check_breakpoint(cpu);
#endif
            }

            if (match_bp) {
                cpu->exception_index = EXCP_DEBUG;
                return true;
            }
        } else if (((pc ^ bp->pc) & TARGET_PAGE_MASK) == 0) {
            match_page = true;
        }
    }

    /*
     * Within the same page as a breakpoint, single-step,
     * returning to helper_lookup_tb_ptr after each insn looking
     * for the actual breakpoint.
     *
     * TODO: Perhaps better to record all of the TBs associated
     * with a given virtual page that contains a breakpoint, and
     * then invalidate them when a new overlapping breakpoint is
     * set on the page.  Non-overlapping TBs would not be
     * invalidated, nor would any TB need to be invalidated as
     * breakpoints are removed.
     */
    if (match_page) {
        *cflags = (*cflags & ~CF_COUNT_MASK) | CF_NO_GOTO_TB | CF_BP_PAGE | 1;
    }
    return false;
}

static inline bool check_for_breakpoints(CPUState *cpu, vaddr pc,
                                         uint32_t *cflags)
{
    return unlikely(!QTAILQ_EMPTY(&cpu->breakpoints)) &&
        check_for_breakpoints_slow(cpu, pc, cflags);
}

/**
 * helper_lookup_tb_ptr: quick check for next tb
 * @env: current cpu state
 *
 * Look for an existing TB matching the current cpu state.
 * If found, return the code pointer.  If not found, return
 * the tcg epilogue so that we return into cpu_tb_exec.
 */
const void *HELPER(lookup_tb_ptr)(CPUArchState *env)
{
    CPUState *cpu = env_cpu(env);
    TranslationBlock *tb;
    vaddr pc;
    uint64_t cs_base;
    uint32_t flags, cflags;

    /*
     * By definition we've just finished a TB, so I/O is OK.
     * Avoid the possibility of calling cpu_io_recompile() if
     * a page table walk triggered by tb_lookup() calling
     * probe_access_internal() happens to touch an MMIO device.
     * The next TB, if we chain to it, will clear the flag again.
     */
    cpu->neg.can_do_io = true;
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

    cflags = curr_cflags(cpu);
#ifdef CONFIG_ORACLE
    cflags |= oracle_tb_cflags(pc);
#endif
    if (check_for_breakpoints(cpu, pc, &cflags)) {
        cpu_loop_exit(cpu);
    }

    tb = tb_lookup(cpu, pc, cs_base, flags, cflags);
    if (tb == NULL) {
        return tcg_code_gen_epilogue;
    }
#ifdef CONFIG_ORACLE
    /*
     * goto_ptr would jump straight into a TB carrying no probes, leaving the
     * instruction that just executed unreported.  Go back to the execution
     * loop instead, where oracle_tb_exit() reads it off.
     */
    if (unlikely(oracle_must_exit_before(tb))) {
        return tcg_code_gen_epilogue;
    }
#endif

    if (qemu_loglevel_mask(CPU_LOG_TB_CPU | CPU_LOG_EXEC)) {
        log_cpu_exec(pc, cpu, tb);
    }

    return tb->tc.ptr;
}

/* Return the current PC from CPU, which may be cached in TB. */
static vaddr log_pc(CPUState *cpu, const TranslationBlock *tb)
{
    if (tb_cflags(tb) & CF_PCREL) {
        return cpu->cc->get_pc(cpu);
    } else {
        return tb->pc;
    }
}

/* Execute a TB, and fix up the CPU state afterwards if necessary */
/*
 * Disable CFI checks.
 * TCG creates binary blobs at runtime, with the transformed code.
 * A TB is a blob of binary code, created at runtime and called with an
 * indirect function call. Since such function did not exist at compile time,
 * the CFI runtime has no way to verify its signature and would fail.
 * TCG is not considered a security-sensitive part of QEMU so this does not
 * affect the impact of CFI in environment with high security requirements
 */
static inline TranslationBlock * QEMU_DISABLE_CFI
cpu_tb_exec(CPUState *cpu, TranslationBlock *itb, int *tb_exit)
{
    uintptr_t ret;
    TranslationBlock *last_tb;
    const void *tb_ptr = itb->tc.ptr;

    if (qemu_loglevel_mask(CPU_LOG_TB_CPU | CPU_LOG_EXEC)) {
        log_cpu_exec(log_pc(cpu, itb), cpu, itb);
    }

    qemu_thread_jit_execute();
    ret = tcg_qemu_tb_exec(cpu_env(cpu), tb_ptr);
#ifdef CONFIG_ORACLE
    /*
     * The last instruction of an armed TB has no following boundary probe, so
     * its delta is still unreported when control arrives back here.  An armed
     * TB is only ever allowed to chain onwards into another armed TB, whose
     * first instruction always carries a probe, so this and that probe between
     * them cover every way out.
     */
    oracle_tb_exit(cpu_env(cpu));
#endif
    cpu->neg.can_do_io = true;
    qemu_plugin_disable_mem_helpers(cpu);
    /*
     * TODO: Delay swapping back to the read-write region of the TB
     * until we actually need to modify the TB.  The read-only copy,
     * coming from the rx region, shares the same host TLB entry as
     * the code that executed the exit_tb opcode that arrived here.
     * If we insist on touching both the RX and the RW pages, we
     * double the host TLB pressure.
     */
    last_tb = tcg_splitwx_to_rw((void *)(ret & ~TB_EXIT_MASK));
    *tb_exit = ret & TB_EXIT_MASK;

    trace_exec_tb_exit(last_tb, *tb_exit);

    if (*tb_exit > TB_EXIT_IDX1) {
        /* We didn't start executing this TB (eg because the instruction
         * counter hit zero); we must restore the guest PC to the address
         * of the start of the TB.
         */
        CPUClass *cc = cpu->cc;
        const TCGCPUOps *tcg_ops = cc->tcg_ops;

        if (tcg_ops->synchronize_from_tb) {
            tcg_ops->synchronize_from_tb(cpu, last_tb);
        } else {
            tcg_debug_assert(!(tb_cflags(last_tb) & CF_PCREL));
            assert(cc->set_pc);
            cc->set_pc(cpu, last_tb->pc);
        }
        if (qemu_loglevel_mask(CPU_LOG_EXEC)) {
            vaddr pc = log_pc(cpu, last_tb);
            if (qemu_log_in_addr_range(pc)) {
                qemu_log("Stopped execution of TB chain before %p [%016"
                         VADDR_PRIx "] %s\n",
                         last_tb->tc.ptr, pc, lookup_symbol(pc));
            }
        }
    }

    /*
     * If gdb single-step, and we haven't raised another exception,
     * raise a debug exception.  Single-step with another exception
     * is handled in cpu_handle_exception.
     */
    if (unlikely(cpu->singlestep_enabled) && cpu->exception_index == -1) {
        cpu->exception_index = EXCP_DEBUG;
        cpu_loop_exit(cpu);
    }

    return last_tb;
}


static void cpu_exec_enter(CPUState *cpu)
{
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;

    if (tcg_ops->cpu_exec_enter) {
        tcg_ops->cpu_exec_enter(cpu);
    }
}

static void cpu_exec_exit(CPUState *cpu)
{
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;

    if (tcg_ops->cpu_exec_exit) {
        tcg_ops->cpu_exec_exit(cpu);
    }
}

static void cpu_exec_longjmp_cleanup(CPUState *cpu)
{
    /* Non-buggy compilers preserve this; assert the correct value. */
    g_assert(cpu == current_cpu);

#ifdef CONFIG_PLUGIN
    /*
     * Clean up speculative state after an exception during wrong-path
     * execution.  Save the pointer before spec_mode_end() clears it.
     *
     * This is the ABNORMAL counterpart of wp_end_spec_session(): when a
     * speculative exception/longjmp escapes the wrong-path walk it lands here
     * instead of the normal wp_end path, so it must undo EVERYTHING that
     * wp_enter_spec_session() set up — including resuming the guest virtual
     * clock paused for the excursion.  Omitting the vtime resume leaves
     * cpu_disable_ticks() in effect: QEMU_CLOCK_VIRTUAL (hence the guest's
     * CNTVCT/TSC/time/Count) freezes for good, and the guest's timer
     * subsystem livelocks — the self-sustaining aarch64 system-mode storm.
     * vtime_resume is idempotent (per-CPU paused flag), so this is safe even
     * if wp_end later runs too.
     */
    if (cpu->plugin_spec_mode || cpu->plugin_spec_vtime_paused) {
        struct qemu_plugin_cpu_state *saved =
            cpu->plugin_spec_saved_state;
        qemu_plugin_spec_mode_end();
        if (saved) {
            qemu_plugin_cpu_state_restore(saved);
            qemu_plugin_cpu_state_free(saved);
        }
        cpu_plugin_spec_vtime_resume(cpu);
    }

    /*
     * Symmetric to the wrong-path vtime reconcile above, but for the
     * CORRECT-path instrumentation freeze.  The plugin brackets its
     * correct-path callbacks (translation-time decoding, per-TB emission)
     * with a nestable cpu_plugin_vclock_pause/_resume pair tracked by
     * plugin_vclock_depth (the RAII VClockPauseGuard in the ChampSim Tracer
     * plugin).  A cpu_loop_exit that longjmps out of a callback -- e.g. a
     * tlb_fill fault taken while re-translating inside an instrumented
     * region -- unwinds past the guard's scope without running its
     * destructor, so the paired _resume is never issued and the depth is
     * leaked > 0.  With the depth stuck above zero, cpu_disable_ticks()
     * stays in effect and QEMU_CLOCK_VIRTUAL never re-enables: the guest
     * clock freezes for good and its timer subsystem livelocks -- the same
     * permanent-freeze class the spec-mode reconcile above guards against
     * on the wrong path.  Drain the leaked depth here so the invariant
     * "an unbalanced longjmp still leaves the clock running" holds on both
     * paths.  A no-op when the guard was balanced (depth already 0, the
     * normal case) and in user-mode (pause/resume never touch the depth),
     * and idempotent with a later balanced _resume via the depth guard.
     */
    while (cpu->plugin_vclock_depth > 0) {
        cpu_plugin_vclock_resume(cpu);
    }
#endif

#ifdef CONFIG_USER_ONLY
    clear_helper_retaddr();
    if (have_mmap_lock()) {
        mmap_unlock();
    }
#else
    /*
     * For softmmu, a tlb_fill fault during translation will land here,
     * and we need to release any page locks held.  In system mode we
     * have one tcg_ctx per thread, so we know it was this cpu doing
     * the translation.
     *
     * Alternative 1: Install a cleanup to be called via an exception
     * handling safe longjmp.  It seems plausible that all our hosts
     * support such a thing.  We'd have to properly register unwind info
     * for the JIT for EH, rather that just for GDB.
     *
     * Alternative 2: Set and restore cpu->jmp_env in tb_gen_code to
     * capture the cpu_loop_exit longjmp, perform the cleanup, and
     * jump again to arrive here.
     */
    if (tcg_ctx->gen_tb) {
        tb_unlock_pages(tcg_ctx->gen_tb);
        tcg_ctx->gen_tb = NULL;
    }
#endif
    if (bql_locked()) {
        bql_unlock();
    }
    assert_no_pages_locked();
}

void cpu_exec_step_atomic(CPUState *cpu)
{
    CPUArchState *env = cpu_env(cpu);
    TranslationBlock *tb;
    vaddr pc;
    uint64_t cs_base;
    uint32_t flags, cflags;
    int tb_exit;

    if (sigsetjmp(cpu->jmp_env, 0) == 0) {
        start_exclusive();
        g_assert(cpu == current_cpu);
        g_assert(!cpu->running);
        cpu->running = true;

        cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

        cflags = curr_cflags(cpu);
        /* Execute in a serial context. */
        cflags &= ~CF_PARALLEL;
        /* After 1 insn, return and release the exclusive lock. */
        cflags |= CF_NO_GOTO_TB | CF_NO_GOTO_PTR | 1;
#ifdef CONFIG_ORACLE
        cflags |= oracle_tb_cflags(pc);
#endif
        /*
         * No need to check_for_breakpoints here.
         * We only arrive in cpu_exec_step_atomic after beginning execution
         * of an insn that includes an atomic operation we can't handle.
         * Any breakpoint for this insn will have been recognized earlier.
         */

        tb = tb_lookup(cpu, pc, cs_base, flags, cflags);
        if (tb == NULL) {
            mmap_lock();
            tb = tb_gen_code(cpu, pc, cs_base, flags, cflags);
            mmap_unlock();
        }

        cpu_exec_enter(cpu);
        /* execute the generated code */
        trace_exec_tb(tb, pc);
        cpu_tb_exec(cpu, tb, &tb_exit);
        cpu_exec_exit(cpu);
    } else {
        cpu_exec_longjmp_cleanup(cpu);
    }

    /*
     * As we start the exclusive region before codegen we must still
     * be in the region if we longjump out of either the codegen or
     * the execution.
     */
    g_assert(cpu_in_exclusive_context(cpu));
    cpu->running = false;
    end_exclusive();
}

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

    tb = tb_lookup(cpu, pc, cs_base, flags, cflags);
    if (tb == NULL) {
        mmap_lock();
        tb = tb_gen_code(cpu, pc, cs_base, flags, cflags);
        mmap_unlock();
        if (tb == NULL) {
            return false;
        }
    }

    /*
     * Save and restore cpu->running to avoid assertion failures
     * when called from a plugin callback context.
     */
    saved_running = cpu->running;

    /*
     * Set up a local exception landing pad so faults during wrong-path
     * execution longjmp back here instead of the outer cpu_exec loop.
     */
    sigjmp_buf saved_jmp_env;
    memcpy(&saved_jmp_env, &cpu->jmp_env, sizeof(sigjmp_buf));

    if (sigsetjmp(cpu->jmp_env, 0) == 0) {
#ifndef CONFIG_USER_ONLY
        /* Guest-insn slice bounding: same spec-dispatch quantum rule as
         * cpu_plugin_exec_tb -- see the comment there. */
        if (unlikely(cst_bq_on)) {
            if (cpu->plugin_spec_mode) {
                cpu->neg.icount_decr.u16.low = cst_bq_quantum;
                cst_bq_note_wp_reload();
            } else {
                cst_bq_note_nonspec_dispatch();
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
        if (have_mmap_lock()) {
            mmap_unlock();
        }
#endif
        cpu->running = saved_running;
        memcpy(&cpu->jmp_env, &saved_jmp_env, sizeof(sigjmp_buf));
        return false;
    }
}

/*
 * Execute one full translation block at the current PC from a plugin
 * callback.  All plugin callbacks fire — tb_exec, insn_exec, inline ops,
 * and mem — so the plugin sees the speculative TB the same way it sees a
 * normal CP TB and can deliver its instructions through the per-TB
 * exec-cb udata.  The plugin is responsible for keeping its own state
 * separated (e.g. early-out for spec-mode invocations of CP-only state
 * mutations, and saving/restoring scoreboard slots clobbered by inline
 * stores around spec-mode entry).  CF_SINGLE_STEP prevents rep-prefixed
 * instructions from looping internally.  Returns true on success, false
 * on failure (e.g. unmapped PC, exception).
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
    cflags |= CF_NO_GOTO_TB | CF_NO_GOTO_PTR | CF_SINGLE_STEP;

    if (cpu->plugin_spec_mode) {
        cflags |= CF_FORCE_SLOW;
    }

    void *host;
    int pflags = probe_access_flags(env, pc, 1, MMU_INST_FETCH,
                                    cpu_mmu_index(cpu, true),
                                    true, &host, 0);
    if (pflags & TLB_INVALID_MASK) {
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
        /*
         * Wrong-path fetch-gate reject classifier (CST_FETCHGATE_DIAG).  The
         * probe above already ran the target walker with probe=true, which
         * walks EXISTING PTEs without demand-paging: a present, executable,
         * privilege-OK but merely iTLB-cold page WALKS + FILLS + succeeds (it
         * never lands here).  Landing here therefore means a real instruction
         * fetch at the speculating context would FAULT — which is exactly the
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
         * request, vm_stop) sets icount_decr.u16.high, which makes every TB —
         * including this wrong-path TB — exit at its prologue without
         * retiring an instruction.  The walker's no-forward-progress guard
         * then truncates the excursion, so WRONG-PATH TRACE CONTENT would
         * depend on host IRQ timing — a load-dependence the trace contract
         * forbids.  Clear the exit-request half for the speculative exec (the
         * .low half is icount budget and is not touched); every kick source
         * first sets cpu->exit_request or cpu->interrupt_request, both of
         * which survive, and cpu_plugin_spec_vtime_resume re-arms the kick at
         * the true excursion exit, so the correct path observes delivery
         * exactly as if the excursion had taken zero host time.
         */
        if (cpu->plugin_spec_mode) {
            if (qatomic_xchg(&cpu->neg.icount_decr.u16.high, 0)) {
                cpu->plugin_spec_kick_deferred = true;
            }
        }
#endif
#ifndef CONFIG_USER_ONLY
        /*
         * Guest-insn slice bounding: spec TBs inherit the budget
         * prologue (the arming edge precedes any translation --
         * mirroring icount's effect on WP blocks), and this dispatch's
         * .low half must never present an exhausted budget to a
         * wrong-path TB (the prologue would refuse to execute it and
         * the walker would see a false bail).  Give each SPEC-MODE
         * dispatch its own full quantum; the CP value was saved at
         * excursion open and is restored by
         * cpu_plugin_spec_vtime_resume.  A dispatch with spec mode
         * CLEAR is only counted (tripwire): it is not entitled to free
         * budget.
         */
        if (unlikely(cst_bq_on)) {
            if (cpu->plugin_spec_mode) {
                cpu->neg.icount_decr.u16.low = cst_bq_quantum;
                cst_bq_note_wp_reload();
            } else {
                cst_bq_note_nonspec_dispatch();
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
        if (have_mmap_lock()) {
            mmap_unlock();
        }
#else
        /*
         * A translation-time fault lands here from INSIDE tb_gen_code: a
         * wrong-path translator_ld() crossing into an absent page unwinds
         * via cpu_loop_exit_restore (the spec_real_access abort in
         * cputlb.c's tlb_fill_align) while tb_gen_code still holds the TB's
         * PageDesc lock(s) and tcg_ctx->gen_tb.  The outer loop's landing
         * pad releases those (cpu_exec_longjmp_cleanup); this pad must do
         * the same, or the page spinlock leaks permanently and the next
         * tb_gen_code touching that page spins forever below every plugin
         * callback — a 100%-utime vCPU freeze (observed as the x86 -smp 2
         * marker-window stall at segment open, where cold-branch wrong
         * paths translate heavily and fault often).
         */
        if (tcg_ctx->gen_tb) {
            tb_unlock_pages(tcg_ctx->gen_tb);
            tcg_ctx->gen_tb = NULL;
        }
#endif
        cpu->running = saved_running;
        memcpy(&cpu->jmp_env, &saved_jmp_env, sizeof(sigjmp_buf));
        return false;
    }
}

#if defined(TARGET_RISCV) && defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
/*
 * The mip bits a DEVICE owns outright: absent from csr.c's delegable_ints, so
 * no guest write can reach them, and their only writer is an interrupt
 * controller going through riscv_cpu_update_mip.  A speculative excursion has
 * nothing to roll back in them.  MTIP is deliberately not here -- see the
 * restore below.
 */
#define CST_MIP_DEVICE_OWNED ((uint64_t)(MIP_MSIP | MIP_MEIP | MIP_SGEIP))

/*
 * Render @bits into the CALLER's buffer.  Not a shared static: the one line
 * below names two different masks, and a single buffer makes both names show
 * whichever call the compiler happened to evaluate last -- a diagnostic that
 * quietly reports the wrong thing is worse than none.
 */
static const char *cst_mip_bit_names(uint64_t bits, char *buf, size_t buflen)
{
    static const struct { uint64_t bit; const char *name; } tab[] = {
        { MIP_MSIP,   " MIP_MSIP"   }, { MIP_SSIP,   " MIP_SSIP"   },
        { MIP_MEIP,   " MIP_MEIP"   }, { MIP_SEIP,   " MIP_SEIP"   },
        { MIP_SGEIP,  " MIP_SGEIP"  }, { MIP_LCOFIP, " MIP_LCOFIP" },
        { MIP_VSSIP,  " MIP_VSSIP"  }, { MIP_VSEIP,  " MIP_VSEIP"  },
    };
    size_t n = 0;
    buf[0] = '\0';
    for (size_t i = 0; i < ARRAY_SIZE(tab); i++) {
        if (bits & tab[i].bit) {
            n += snprintf(buf + n, buflen - n, "%s", tab[i].name);
            if (n >= buflen) {
                break;
            }
        }
    }
    return buf;
}

/*
 * CST_MIPERASE=<n> -- pending-interrupt erasure detector (diagnostic, off by
 * default; <n> caps the printed detail lines, default 64.  The counters keep
 * running past the cap and a TOTALS line is printed at every power-of-two
 * event, so a run killed by a watchdog while wedged still reports its totals).
 *
 * Runs immediately before the wrong-path restore's memcpy and reports two
 * different things, because the condition and the outcome can be closed
 * separately and only measuring the outcome would hide a regression:
 *
 *   UNRECORDED -- a bit that is live-set in env->mip, absent from the
 *      snapshot, and absent from the replay record.  That is the RACE
 *      signature: a device raise the excursion neither snapshotted nor logged,
 *      i.e. one that landed in a window where the excursion was not yet (or no
 *      longer) recording.  It is what the entry/exit ordering fixes close, and
 *      it is measurable independently of what the restore then decides to do
 *      with the bit.
 *
 *   ERASED -- a bit that is live-set now and will be zero after the restore
 *      writes env->mip.  That is the outcome the guest actually suffers.
 *      Computed from the same expression the restore uses, device carry-forward
 *      included, so it stays honest as that expression changes.
 *
 * Timer bits are excluded from both: the excursion-exit reconcile re-derives
 * them from the architected compare registers.  Every other bit in mip is
 * parked there by a device (the ACLINT's MSIP/SSIP, the PLIC's MEIP/SEIP,
 * hgeip's SGEIP, the PMU's LCOFIP) with no second source to recover from -- an
 * erasure there is an interrupt the guest never sees and a device that waits
 * forever for an acknowledgement.
 */
static void cst_miperase_check(const CPURISCVState *env,
                               const CPURISCVState *saved,
                               uint64_t replay_set, uint64_t replay_clear)
{
    static int lim = -1;
    static uint64_t n_events, n_unrec, n_lost, n_msip_unrec, n_msip_lost;
    const uint64_t timer = MIP_MTIP | MIP_STIP | MIP_VSTIP;
    uint64_t post, lost, unrec, ev;
    char unrec_names[96], lost_names[96];

    if (unlikely(lim < 0)) {
        const char *e = getenv("CST_MIPERASE");
        int v = e ? atoi(e) : 0;
        qatomic_set(&lim, e ? (v > 0 ? v : 64) : 0);
    }
    if (likely(!lim)) {
        return;
    }

    /* Exactly the value the restore is about to write. */
    post = (((saved->mip | replay_set) & ~replay_clear)
            & ~CST_MIP_DEVICE_OWNED) | (env->mip & CST_MIP_DEVICE_OWNED);

    lost  = (env->mip & ~post) & ~timer;
    unrec = (env->mip & ~saved->mip & ~replay_set) & ~timer;
    if (likely(!lost && !unrec)) {
        return;
    }

    ev = qatomic_fetch_inc(&n_events) + 1;
    if (unrec) {
        qatomic_inc(&n_unrec);
        if (unrec & MIP_MSIP) {
            qatomic_inc(&n_msip_unrec);
        }
    }
    if (lost) {
        qatomic_inc(&n_lost);
        if (lost & MIP_MSIP) {
            qatomic_inc(&n_msip_lost);
        }
    }

    if (ev <= (uint64_t)lim) {
        fprintf(stderr, "[miperase] cpu%d unrecorded=0x%" PRIx64 "%s"
                " erased=0x%" PRIx64 "%s live=0x%" PRIx64 " saved=0x%" PRIx64
                " set=0x%" PRIx64 " clr=0x%" PRIx64 " pc=0x%" PRIx64
                " spec=%d vtp=%d gw=%d\n",
                current_cpu->cpu_index,
                unrec, cst_mip_bit_names(unrec, unrec_names,
                                         sizeof(unrec_names)),
                lost, cst_mip_bit_names(lost, lost_names,
                                        sizeof(lost_names)),
                env->mip, saved->mip, replay_set, replay_clear,
                (uint64_t)env->pc,
                (int)current_cpu->plugin_spec_mode,
                (int)current_cpu->plugin_spec_vtime_paused,
                (int)env->plugin_mip_guest_write);
    }
    if ((ev & (ev - 1)) == 0) {
        fprintf(stderr, "[miperase] TOTALS events=%" PRIu64
                " unrecorded=%" PRIu64 " (msip=%" PRIu64 ")"
                " erased=%" PRIu64 " (msip=%" PRIu64 ")\n",
                ev, qatomic_read(&n_unrec), qatomic_read(&n_msip_unrec),
                qatomic_read(&n_lost), qatomic_read(&n_msip_lost));
    }
}
#endif

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
    void *bp_save[4];
    memcpy(bp_save, env->cpu_breakpoint, sizeof(bp_save));
    memcpy(env, saved, size);
    memcpy(env->cpu_breakpoint, bp_save, sizeof(bp_save));
#elif defined(TARGET_ARM)
    void *bp_save[16], *wp_save[16];
    memcpy(bp_save, env->cpu_breakpoint, sizeof(bp_save));
    memcpy(wp_save, env->cpu_watchpoint, sizeof(wp_save));
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
    /*
     * The generic timer's host QEMUTimers live OUTSIDE this register snapshot.
     * If the restore rolls back any timer's ctl/cval — most importantly the
     * ISTATUS bit, which the timer can advance to 1 when it expires (its
     * iothread callback running while spec mode is briefly open in a fault-skip
     * gap) during the excursion's host wall-clock window — the architected
     * registers revert but the host QEMUTimer does not, leaving it parked
     * (e.g. at INT64_MAX) and never firing again.  The guest's timer subsystem
     * then livelocks: the aarch64 system-mode storm.  Nothing is detected
     * here: arm_cpu_plugin_resync_timers re-runs gt_recalc_timer over every
     * present timer at excursion exit, unconditionally, so this restore only
     * has to avoid damaging the registers that reconcile reads from.  That
     * also covers the desync a detection here could never have caught: a
     * gt_recalc_timer that ran with spec mode closed, in the fault-skip gap.
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
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
    env->irq_line_state = irq_line_save;
#endif
    /*
     * Clock resync deferred to cpu_plugin_spec_vtime_resume (true excursion
     * exit) -- see the riscv branch / #77.  Running it at this restore would
     * fire at an intermediate fault-skip restore too.
     */
#elif defined(TARGET_RISCV)
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
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
#ifdef CONFIG_PLUGIN
        /* #77 (i)-vs-(ii) probe: does a WP restore knock mstatus.VS On->Off,
         * i.e. clobber a real correct-path vector-enable with a stale snapshot? */
        if (getenv("CST_ILL_DIAG") &&
            (env->mstatus & MSTATUS_VS) && !(s->mstatus & MSTATUS_VS)) {
            fprintf(stderr, "[vsclobber] restore VS 1->0 spec=%d FS:%d->%d\n",
                    (int)current_cpu->plugin_spec_mode,
                    (int)!!(env->mstatus & MSTATUS_FS),
                    (int)!!(s->mstatus & MSTATUS_FS));
        }
#else
        (void)s;
#endif
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
     * delta.  Timer bits are excluded from that delta (the reconcile owns
     * them; carrying them here as well perturbed interrupt-delivery timing
     * across the merge, #77).
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
         * The lock is taken once per excursion (the two callers are the normal
         * wp_end restore and the abnormal longjmp cleanup, both excursion
         * exits), and the ordering -- plugin walk lock, then BQL -- is the one
         * cpu_plugin_spec_vtime_pause already establishes on the same thread.
         */
        bool need_bql = !bql_locked();
        uint64_t replay_set, replay_clear, live_dev;

        if (need_bql) {
            bql_lock();
        }
        replay_set = env->plugin_spec_mip_set;
        replay_clear = env->plugin_spec_mip_clear;
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
         * registers, and holding a second opinion here perturbed
         * interrupt-delivery timing across the wrong-path merge (#77).  It is
         * excluded from the replay mask for exactly that reason.
         */
        live_dev = env->mip & CST_MIP_DEVICE_OWNED;

        cst_miperase_check(env, (const CPURISCVState *)saved,
                           replay_set, replay_clear);
        memcpy(env, saved, size);
        env->mip = (((env->mip | replay_set) & ~replay_clear)
                    & ~(uint64_t)CST_MIP_DEVICE_OWNED) | live_dev;
        env->plugin_spec_mip_set = 0;
        env->plugin_spec_mip_clear = 0;
        if (need_bql) {
            bql_unlock();
        }
    }
    /*
     * Timer resync is deferred to cpu_plugin_spec_vtime_resume (the true
     * excursion-exit boundary).  Running it here would fire at an intermediate
     * wrong-path fault-skip restore (spec_mode_end -> restore -> spec_mode_begin),
     * synthesising STIP that the FINAL wp_end restore then clobbers with the
     * stale snapshot -- losing the timer IRQ and livelocking the guest (#77).
     */
#else
    memcpy(env, saved, size);
#endif
#elif defined(TARGET_MIPS)
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
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
     * (the two callers are the normal wp_end restore and the abnormal
     * longjmp cleanup, mutually exclusive excursion exits; fault-skip does
     * not restore mid-excursion), and the ordering -- plugin walk lock, then
     * BQL -- is the one cpu_plugin_spec_vtime_pause already establishes on
     * this thread.  The masks live after end_reset_fields, outside the
     * snapshot, so the memcpy cannot roll the record itself back.  Zeroing
     * them here is the consume-once step; the reset at window open
     * (cpu_plugin_spec_vtime_pause) clears anything recorded after this
     * consume, so the NEXT excursion cannot replay a raise the guest may
     * have acknowledged in between.  The exit reconcile
     * (mips_cpu_plugin_resync_timers -> cpu_mips_plugin_reconcile_irq) then
     * recomputes CPU_INTERRUPT_HARD from the now-correct Cause, so a
     * replayed raise produces its kick edge through the reconcile.
     */
    {
        bool need_bql = !bql_locked();
        uint32_t replay_set, replay_clear;

        if (need_bql) {
            bql_lock();
        }
        replay_set = env->plugin_ext_ip_set;
        replay_clear = env->plugin_ext_ip_clear;
        memcpy(env, saved, size);
        /* Atomic for the same reason as cpu_mips_irq_request's own update:
         * a peer VPE's mttc0 read-modify-write of this whole word runs on
         * its vCPU thread without the BQL. */
        qatomic_or(&env->CP0_Cause, replay_set);
        qatomic_and(&env->CP0_Cause, ~replay_clear);
        env->plugin_ext_ip_set = 0;
        env->plugin_ext_ip_clear = 0;
        if (need_bql) {
            bql_unlock();
        }
    }
    /* Timer resync deferred to cpu_plugin_spec_vtime_resume -- see #77. */
#else
    memcpy(env, saved, size);
#endif
#else
    memcpy(env, saved, size);
#endif
}

#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
/*
 * #77 UNBIASED wrong-path write-leak detector (gated on CST_WPROTECT=<delay_s>).
 * Host-MMU based: write-protect ALL guest RAM for the duration of each wrong-
 * path excursion.  Reads and sandboxed (buffered) stores never touch real RAM,
 * so they don't fault; ANY real write -- from ANY code path, known or not --
 * traps in wprot_handler, which prints the leaking guest-physical address and
 * the wrong-path PC of the instruction that did it, then aborts.  No guessing
 * where to place a probe.  Armed only after a delay (default 15s) so the boot +
 * workload phase isn't slowed; the teardown livelock happens later.
 */
#include <sys/mman.h>
typedef struct { void *host; size_t len; uint64_t off; } WProtBlk;
static WProtBlk g_wprot_blk[16];
static int      g_wprot_nblk = 0;
static bool     g_wprot_collected = false;
static bool     g_wprot_installed = false;
static bool     g_wprot_active = false;
/*
 * Per-EXCURSION, therefore per-vCPU: the pause that sets it and the resume
 * that consumes it are two halves of one vCPU's excursion.  File scope was
 * the wrong storage class for that datum and every other per-excursion
 * static in this file is already __thread (g_spec_icount_freeze,
 * g_clkeq_pause, g_clkaudit_pause, the clkprobe accumulators, the sdiff
 * buffers).  Shared, two vCPUs cross: A's pause sets it and keeps the BQL,
 * B's resume reads A's flag as its own and reaches bql_unlock() without
 * holding the lock, while A's own resume then sees it false and never
 * unlocks -- the BQL held by a vCPU forever.  Unlike the diagnostics around
 * it this path is not env-gated, so that is product behaviour.
 */
static __thread bool g_wp_bql_held;     /* #77 test: BQL held across excursion */
static int      g_wprot_enabled = -1;
static long     g_wprot_delay = 15;
static time_t   g_wprot_start = 0;
static long     g_wprot_pgsz = 4096;
static struct sigaction g_wprot_old_sa;

static int wprot_collect_cb(RAMBlock *rb, void *opaque)
{
    void *h = qemu_ram_get_host_addr(rb);
    if (h && g_wprot_nblk < 16) {
        g_wprot_blk[g_wprot_nblk].host = h;
        g_wprot_blk[g_wprot_nblk].len  = qemu_ram_get_used_length(rb);
        g_wprot_blk[g_wprot_nblk].off  = qemu_ram_get_offset(rb);
        g_wprot_nblk++;
    }
    return 0;
}

static void wprot_handler(int sig, siginfo_t *si, void *uc)
{
    char *a = (char *)si->si_addr;
    for (int i = 0; i < g_wprot_nblk; i++) {
        char *base = (char *)g_wprot_blk[i].host;
        if (a >= base && a < base + g_wprot_blk[i].len) {
            bool spec = current_cpu && current_cpu->plugin_spec_mode;
            bool vtp  = current_cpu && current_cpu->plugin_spec_vtime_paused;
            if (spec || vtp) {
                uint64_t phys = g_wprot_blk[i].off + (uint64_t)(a - base);
                uint64_t pc = current_cpu ? current_cpu->cc->get_pc(current_cpu)
                                          : 0;
                fprintf(stderr, "[wpleak] WP wrote guest RAM phys=0x%" PRIx64
                        " host=%p wp_pc=0x%" PRIx64 " spec=%d vtp=%d\n",
                        phys, (void *)a, pc, (int)spec, (int)vtp);
                fflush(stderr);
                abort();
            }
            /* concurrent non-WP write (iothread/DMA): unprotect + continue */
            void *pg = (void *)((uintptr_t)a & ~(uintptr_t)(g_wprot_pgsz - 1));
            mprotect(pg, g_wprot_pgsz, PROT_READ | PROT_WRITE);
            return;
        }
    }
    /* Not guest RAM: chain to QEMU's previous SIGSEGV handler. */
    if (g_wprot_old_sa.sa_flags & SA_SIGINFO) {
        if (g_wprot_old_sa.sa_sigaction) {
            g_wprot_old_sa.sa_sigaction(sig, si, uc);
            return;
        }
    } else if (g_wprot_old_sa.sa_handler &&
               g_wprot_old_sa.sa_handler != SIG_DFL &&
               g_wprot_old_sa.sa_handler != SIG_IGN) {
        g_wprot_old_sa.sa_handler(sig);
        return;
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

static void wprot_setprot(int prot)
{
    for (int i = 0; i < g_wprot_nblk; i++) {
        mprotect(g_wprot_blk[i].host, g_wprot_blk[i].len, prot);
    }
}

static bool wprot_ready(void)
{
    if (g_wprot_enabled < 0) {
        const char *e = getenv("CST_WPROTECT");
        g_wprot_enabled = e ? 1 : 0;
        /* delay in seconds before arming; default 0 = arm on the first WP
         * excursion (in marker mode WP only runs post-marker, so there is no
         * boot phase to skip). */
        g_wprot_delay = (e && *e) ? atol(e) : 0;
        g_wprot_pgsz = qemu_real_host_page_size();
    }
    if (!g_wprot_enabled) {
        return false;
    }
    if (g_wprot_start == 0) {
        g_wprot_start = time(NULL);
    }
    if (time(NULL) - g_wprot_start < g_wprot_delay) {
        return false;
    }
    if (!g_wprot_collected) {
        qemu_ram_foreach_block(wprot_collect_cb, NULL);
        g_wprot_collected = true;
    }
    if (!g_wprot_installed) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = wprot_handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, &g_wprot_old_sa);
        g_wprot_installed = true;
        fprintf(stderr, "[wpleak] armed: %d RAM block(s) write-protected "
                "during WP\n", g_wprot_nblk);
    }
    return g_wprot_nblk > 0;
}
#endif /* CONFIG_PLUGIN && !CONFIG_USER_ONLY */

#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
/*
 * #77 UNBIASED CPU-state leak detector (gated on CST_STATEDIFF).  The WP
 * snapshot saves/restores only CPUArchState[0..end_reset_fields] + halted +
 * exception_index.  ANY other CPUState/env byte a wrong-path excursion mutates
 * persists into the correct path.  This snapshots CPUState[0..neg] (all scalar
 * fields, excludes the huge TLB) and the un-restored env tail at excursion
 * start, compares after the restore, and logs each distinct changed-and-not-
 * restored byte once -- revealing the leaked field with no guessing.
 */
#define SDIFF_CPU_SZ  sizeof(CPUState)   /* now INCLUDES neg.tlb descriptors */
#define SDIFF_ENV_OFF offsetof(CPUArchState, end_reset_fields)
#define SDIFF_ENV_SZ  (sizeof(CPUArchState) - offsetof(CPUArchState, end_reset_fields))
/*
 * The snapshot buffers are per-vCPU-thread.  They hold one specific CPUState's
 * bytes, and the pair that produces a verdict is a snapshot on one thread and
 * the compare that follows it on that same thread; a process-wide buffer makes
 * that pair depend on no peer vCPU opening an excursion in between, which is
 * not a property this file can assert -- the serialisation that would grant it
 * belongs to a plugin's lock, not to QEMU.  Shared, a peer's snapshot would be
 * compared against this vCPU's registers and every byte where the two vCPUs
 * legitimately differ would be reported as a leak.  The `seen` filters stay
 * per-thread with them, so first-occurrence reporting is per-vCPU too.
 */
static __thread uint8_t g_sdiff_cpu[SDIFF_CPU_SZ];
static __thread uint8_t g_sdiff_env[SDIFF_ENV_SZ];
static __thread uint8_t g_sdiff_cpu_seen[SDIFF_CPU_SZ];
static __thread uint8_t g_sdiff_env_seen[SDIFF_ENV_SZ];
static __thread bool    g_sdiff_have = false;
static int     g_sdiff_on = -1;
static long    g_sdiff_delay = 0;
static time_t  g_sdiff_start = 0;
static bool    g_sdiff_printed_off = false;

static bool sdiff_enabled(void)
{
    if (g_sdiff_on < 0) {
        const char *e = getenv("CST_STATEDIFF");
        g_sdiff_on = e ? 1 : 0;
        g_sdiff_delay = (e && *e) ? atol(e) : 0;
    }
    if (g_sdiff_on <= 0) {
        return false;
    }
    if (g_sdiff_start == 0) {
        g_sdiff_start = time(NULL);
    }
    if (time(NULL) - g_sdiff_start < g_sdiff_delay) {
        return false;
    }
    if (!g_sdiff_printed_off) {
        g_sdiff_printed_off = true;
        fprintf(stderr, "[statediff] armed. offsetof: interrupt_request=%zu "
                "neg=%zu plugin_spec_tlb_log=%zu sizeof(CPUState)=%zu\n",
                offsetof(CPUState, interrupt_request),
                offsetof(CPUState, neg),
                offsetof(CPUState, plugin_spec_tlb_log),
                sizeof(CPUState));
        fflush(stderr);
    }
    return true;
}

/*
 * Name every byte that differs across an excursion BY CONSTRUCTION, so an
 * un-named offset is the finding.  Left unnamed, these bury a real leak: they
 * are reported on essentially every excursion, and the reader who has learned
 * to scroll past them scrolls past the one line that matters.
 *
 * Four groups, and none of them is an un-restored wrong-path mutation:
 *
 *  - ASYNC SIGNALLING (exit_request, interrupt_request, work_list).  These are
 *    written by OTHER threads -- the iothread's device models raise an
 *    interrupt line, cpu_exit() sets the kick, async_run_on_cpu() queues an
 *    item -- while this vCPU sits in the excursion.  They MUST survive it:
 *    restoring them would discard a device interrupt the guest is owed, which
 *    is the failure the RISC-V mip and MIPS CP0_Cause work exists to prevent.
 *    On x86 the excursion holds the BQL end to end, so the iothread cannot
 *    interleave and this group does not appear; on the other targets it does.
 *
 *  - THE PER-EXECUTION REPORT'S LAZILY ALLOCATED ACCUMULATOR
 *    (plugin_mops_report).  A pointer to per-vCPU storage the FEAT_MOPS byte
 *    fallbacks allocate on first use and keep for the vCPU's lifetime, so it
 *    goes NULL -> heap on the first excursion that needs it.  What it HOLDS is
 *    already path-separated inside the allocation (the accumulator carries a
 *    correct-path and a wrong-path context and selects on plugin_spec_mode),
 *    so the surviving pointer carries no wrong-path value into the correct
 *    path.
 *
 *    The scalar report beside it -- the plugin_rep_* block -- is NOT in this
 *    group and must not be added to it.  It is a publication channel read one
 *    dispatch after the execution that wrote it, which is across the boundary
 *    an excursion is kicked from, and its only identity is an address; a
 *    speculative re-entry of the same instruction is therefore indis-
 *    tinguishable from the correct-path execution it displaced.  It is saved
 *    and restored with the rest of the rollback (qemu_plugin_cpu_state_save /
 *    _restore) and so does not differ here.  If it ever appears in this
 *    detector's output again, that is the finding.
 *
 *  - THE WRONG-PATH STORE SANDBOX (plugin_spec_store_buf, _pool, _pool_used,
 *    _pool_cap, _atomic_scratch, _store_overflow).  The sandbox that holds the
 *    excursion's speculative stores is an allocator, and its buffer is kept
 *    across excursions on purpose: qemu_plugin_spec_mode_end empties the line
 *    index and resets the high-water mark but does NOT free the pool, so the
 *    next excursion reuses it.  The pointers therefore go NULL -> heap on the
 *    first excursion that stores, and the cap grows when a wider one needs
 *    more lines.  What the sandbox HOLDS is discarded at excursion exit --
 *    that is the sandbox's whole purpose -- so the surviving allocation
 *    carries no wrong-path value into the correct path.
 *
 *  - EXCURSION BOOKKEEPING (plugin_spec_vtime_paused, plugin_spec_tlb_log and
 *    its siblings).  plugin_spec_vtime_paused is this detector's own bracket:
 *    set before the snapshot, cleared before the compare, so it differs on
 *    every excursion ever measured.
 *
 * The rest of the plugin block is DELIBERATELY left unnamed -- the fault stack
 * and its depth, the event queue, plugin_spec_saved_state, the identity memo.
 * A change there across an excursion is exactly the finding this detector is
 * for, and naming the block wholesale to quieten the sandbox lines would hide
 * it.
 */
static const char *sdiff_cpu_field(size_t off)
{
    if (off == offsetof(CPUState, interrupt_request)) {
        return "interrupt_request (async: raised by another thread - must survive)";
    }
    if (off == offsetof(CPUState, exit_request)) {
        return "exit_request (async: kick from another thread - must survive)";
    }
    if (off >= offsetof(CPUState, work_list) &&
        off <  offsetof(CPUState, work_list) + sizeof(((CPUState *)0)->work_list)) {
        return "work_list (async: queued by another thread - must survive)";
    }
    if (off == offsetof(CPUState, cflags_next_tb))     return "cflags_next_tb";
    /*
     * plugin_mops_report AND NOTHING BEFORE IT.  This range used to start at
     * plugin_rep_iters, which silenced the entire self-loop publication
     * channel -- the six fields a wrong-path fan-out instruction overwrites
     * and the correct path reads at its next dispatch.  Those are restored
     * now, so they do not differ; naming them would re-hide the leak the
     * restore exists to prevent.
     */
    if (off >= offsetof(CPUState, plugin_mops_report) &&
        off <  offsetof(CPUState, plugin_mops_report) + sizeof(void *)) {
        return "(FEAT_MOPS report accumulator - lazily allocated, vCPU "
               "lifetime; its contents are path-separated internally)";
    }
    if (off >= offsetof(CPUState, plugin_spec_store_buf) &&
        off <  offsetof(CPUState, plugin_spec_store_overflow) +
               sizeof(((CPUState *)0)->plugin_spec_store_overflow)) {
        return "(wrong-path store sandbox - a pool DELIBERATELY reused across "
               "excursions: qemu_plugin_spec_mode_end clears the line index "
               "and resets pool_used, and keeps the buffer)";
    }
    if (off == offsetof(CPUState, plugin_spec_vtime_paused)) {
        return "plugin_spec_vtime_paused (this detector's own bracket)";
    }
    /*
     * The TLB log AND NOTHING PAST IT.  This range used to run to
     * offsetof(CPUState, neg), which is not the plugin block: past the log's
     * own overflow flag it swallowed plugin_spec_absent,
     * plugin_spec_mem_faulted, cpu_index, tcg_cflags, halted,
     * exception_index and iommu_notifiers, and printed every one of them
     * with the word "intentional" beside it.  tcg_cflags is the reason this
     * matters: curr_cflags() reads it and it selects the TB the correct path
     * looks up, so a perturbation there is a retranslate-forever shape that
     * this detector was reporting as expected noise.  A name is a claim that
     * a difference is understood; it must cover only what it names.
     */
    if (off >= offsetof(CPUState, plugin_spec_tlb_log) &&
        off <= offsetof(CPUState, plugin_spec_tlb_log_overflow)) {
        return "(plugin_spec_tlb_log - intentional)";
    }
    if (off >= offsetof(CPUState, neg)) {
        return "(neg/TLB)";
    }
    return NULL;
}

static void sdiff_snapshot(CPUState *cpu)
{
    if (!sdiff_enabled()) {
        return;
    }
    memcpy(g_sdiff_cpu, cpu, SDIFF_CPU_SZ);
    memcpy(g_sdiff_env, (uint8_t *)cpu_env(cpu) + SDIFF_ENV_OFF, SDIFF_ENV_SZ);
    g_sdiff_have = true;
}

static void sdiff_compare(CPUState *cpu)
{
    if (!sdiff_enabled() || !g_sdiff_have) {
        return;
    }
    const uint8_t *now = (const uint8_t *)cpu;
    for (size_t i = 0; i < SDIFF_CPU_SZ; i++) {
        if (now[i] != g_sdiff_cpu[i] && !g_sdiff_cpu_seen[i]) {
            g_sdiff_cpu_seen[i] = 1;
            const char *f = sdiff_cpu_field(i);
            fprintf(stderr, "[statediff] CPUState off=%zu%s%s changed across WP "
                    "(0x%02x->0x%02x) NOT restored\n", i,
                    f ? " field=" : "", f ? f : "",
                    g_sdiff_cpu[i], now[i]);
            fflush(stderr);
        }
    }
    const uint8_t *enow = (const uint8_t *)cpu_env(cpu) + SDIFF_ENV_OFF;
    /*
     * "!=" rather than "<": on targets whose CPUArchState ends at
     * end_reset_fields (alpha, avr, microblaze, tricore, xtensa)
     * SDIFF_ENV_SZ is compile-time 0 and an unsigned "< 0" trips
     * -Wtype-limits under -Werror.
     */
    for (size_t i = 0; i != SDIFF_ENV_SZ; i++) {
        if (enow[i] != g_sdiff_env[i] && !g_sdiff_env_seen[i]) {
            g_sdiff_env_seen[i] = 1;
            fprintf(stderr, "[statediff] env tail off=%zu (env+%zu) changed "
                    "across WP (0x%02x->0x%02x) NOT restored\n",
                    i, SDIFF_ENV_OFF + i, g_sdiff_env[i], enow[i]);
            fflush(stderr);
        }
    }
}

/*
 * #77 causation test: snapshot the ENTIRE softmmu TLB at wrong-path entry and
 * fully restore it at exit -- descriptors, the inline victim tables, AND the
 * heap fast-table / fulltlb arrays (which sdiff cannot see, being behind
 * pointers).  If forcing the TLB byte-identical across every excursion makes
 * the riscv64 livelock vanish, the TLB is conclusively the leak channel.
 * Heavy (per-excursion memcpy of the tables); diagnostic only, gated
 * CST_TLB_SAVE.
 */
static int  g_tlbsave_on = -1;
static bool g_tlbsave_have = false;
static CPUTLBDesc      g_tlbsave_d[NB_MMU_MODES];
static uintptr_t       g_tlbsave_mask[NB_MMU_MODES];
static size_t          g_tlbsave_nent[NB_MMU_MODES];
static CPUTLBEntry    *g_tlbsave_table[NB_MMU_MODES];
static CPUTLBEntryFull *g_tlbsave_fulltlb[NB_MMU_MODES];
static uint16_t        g_tlbsave_dirty;
static size_t          g_tlbsave_ffc, g_tlbsave_pfc, g_tlbsave_efc;

static bool tlbsave_enabled(void)
{
    if (g_tlbsave_on < 0) {
        g_tlbsave_on = getenv("CST_TLB_SAVE") ? 1 : 0;
    }
    return g_tlbsave_on > 0;
}

static void tlbsave_snapshot(CPUState *cpu)
{
    if (!tlbsave_enabled()) {
        return;
    }
    CPUTLB *tlb = &cpu->neg.tlb;
    qemu_spin_lock(&tlb->c.lock);
    g_tlbsave_dirty = tlb->c.dirty;
    g_tlbsave_ffc = tlb->c.full_flush_count;
    g_tlbsave_pfc = tlb->c.part_flush_count;
    g_tlbsave_efc = tlb->c.elide_flush_count;
    for (int i = 0; i < NB_MMU_MODES; i++) {
        size_t nent = (tlb->f[i].mask >> CPU_TLB_ENTRY_BITS) + 1;
        g_tlbsave_d[i] = tlb->d[i];
        g_tlbsave_mask[i] = tlb->f[i].mask;
        g_tlbsave_nent[i] = nent;
        g_tlbsave_table[i] = g_realloc(g_tlbsave_table[i],
                                       nent * sizeof(CPUTLBEntry));
        memcpy(g_tlbsave_table[i], tlb->f[i].table,
               nent * sizeof(CPUTLBEntry));
        g_tlbsave_fulltlb[i] = g_realloc(g_tlbsave_fulltlb[i],
                                         nent * sizeof(CPUTLBEntryFull));
        memcpy(g_tlbsave_fulltlb[i], tlb->d[i].fulltlb,
               nent * sizeof(CPUTLBEntryFull));
    }
    qemu_spin_unlock(&tlb->c.lock);
    g_tlbsave_have = true;
}

static void tlbsave_restore(CPUState *cpu)
{
    if (!tlbsave_enabled() || !g_tlbsave_have) {
        return;
    }
    CPUTLB *tlb = &cpu->neg.tlb;
    qemu_spin_lock(&tlb->c.lock);
    tlb->c.dirty = g_tlbsave_dirty;
    tlb->c.full_flush_count = g_tlbsave_ffc;
    tlb->c.part_flush_count = g_tlbsave_pfc;
    tlb->c.elide_flush_count = g_tlbsave_efc;
    for (int i = 0; i < NB_MMU_MODES; i++) {
        size_t saved_nent = g_tlbsave_nent[i];
        size_t cur_nent = (tlb->f[i].mask >> CPU_TLB_ENTRY_BITS) + 1;
        CPUTLBEntry *table = tlb->f[i].table;
        CPUTLBEntryFull *fulltlb = tlb->d[i].fulltlb;
        if (cur_nent != saved_nent) {
            /* WP resized this mmu_idx: the saved heap pointers were freed.
             * Reallocate the live buffers back to the saved geometry. */
            g_free(table);
            g_free(fulltlb);
            table = g_new(CPUTLBEntry, saved_nent);
            fulltlb = g_new(CPUTLBEntryFull, saved_nent);
        }
        memcpy(table, g_tlbsave_table[i], saved_nent * sizeof(CPUTLBEntry));
        memcpy(fulltlb, g_tlbsave_fulltlb[i],
               saved_nent * sizeof(CPUTLBEntryFull));
        tlb->d[i] = g_tlbsave_d[i];        /* restores inline victim + scalars */
        tlb->d[i].fulltlb = fulltlb;       /* but keep the LIVE heap pointer */
        tlb->f[i].mask = g_tlbsave_mask[i];
        tlb->f[i].table = table;
    }
    qemu_spin_unlock(&tlb->c.lock);
    g_tlbsave_have = false;
}
#endif /* CONFIG_PLUGIN && !CONFIG_USER_ONLY */

#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
/*
 * Run excursions WITHOUT freezing the guest virtual clock (#77 arm).  Both
 * spellings select it: CST_NOFREEZE, and CST_NO_VTPAUSE, which used to be a
 * separate and much blunter switch -- it returned out of
 * cpu_plugin_spec_vtime_pause() before plugin_spec_vtime_paused was set, so it
 * did not merely leave the clock running, it left the excursion WINDOW closed.
 * That flag is what the RISC-V external-mip record, the RISC-V/MIPS/Arm timer
 * expiry gates, the interrupt-line suppression, the wrong-path kick re-arm and
 * the excursion-exit clock resync all key on, so the arm silently disabled
 * every one of them and manufactured the leaks it was meant to discriminate
 * against.  Its own comment claimed it kept "the excursion flag + resync";
 * that claim was false.  One meaning now, and it is the documented one.
 *
 * Cached: called on every excursion.
 */
static bool cst_nofreeze(void)
{
    static int v = -1;
    if (v < 0) {
        v = getenv("CST_NOFREEZE") != NULL || getenv("CST_NO_VTPAUSE") != NULL;
    }
    return v;
}

/*
 * CST_CLKEQ (#77 falsifier): the excursion's defining requirement, measured.
 * On return from a wrong path the guest virtual clock must read what it read
 * when the excursion began -- not merely have been unfrozen, but be back at
 * the pause-point value.  Sample it three times and name which half failed:
 *
 *   ADVANCED   the clock moved while the excursion was open: the freeze was
 *              not in effect for the whole window (a peer vCPU's plugin
 *              window restarting the global clock is how that happens).
 *   NOTRESTORED  the clock did not come back to the pause-point value across
 *              the thaw and the per-target resync.
 *
 * Positive control: CST_NOFREEZE / CST_NO_VTPAUSE deliberately skip the
 * freeze, so every excursion must report ADVANCED under them.  A run with the
 * instrument armed and that arm set which reports nothing has a broken
 * instrument, not a clean clock.
 */
static __thread int64_t g_clkeq_pause;
static bool cst_clkeq_on(void)
{
    static int on = -1;
    if (on < 0) {
        on = getenv("CST_CLKEQ") != NULL;
    }
    return on > 0;
}
static void cst_clkeq_note_pause(void)
{
    if (cst_clkeq_on()) {
        g_clkeq_pause = cpu_get_clock();
    }
}
static void cst_clkeq_check(CPUState *cpu, int64_t pre_thaw)
{
    if (!cst_clkeq_on()) {
        return;
    }
    int64_t post = cpu_get_clock();
    static __thread uint64_t n_adv, n_not;
    if (pre_thaw != g_clkeq_pause) {
        n_adv++;
        if ((n_adv & (n_adv - 1)) == 0) {   /* powers of two: bound the spam */
            fprintf(stderr, "[clkeq] cpu%d ADVANCED field=QEMU_CLOCK_VIRTUAL "
                    "pause=%" PRId64 " in_excursion=%" PRId64 " delta=%" PRId64
                    "ns n=%" PRIu64 "\n", cpu->cpu_index, g_clkeq_pause,
                    pre_thaw, pre_thaw - g_clkeq_pause, n_adv);
            fflush(stderr);
        }
    }
    if (post != g_clkeq_pause) {
        n_not++;
        if ((n_not & (n_not - 1)) == 0) {
            fprintf(stderr, "[clkeq] cpu%d NOTRESTORED field=QEMU_CLOCK_VIRTUAL "
                    "pause=%" PRId64 " resume=%" PRId64 " delta=%" PRId64
                    "ns n=%" PRIu64 "\n", cpu->cpu_index, g_clkeq_pause, post,
                    post - g_clkeq_pause, n_not);
            fflush(stderr);
        }
    }
    /*
     * The CONDITION, reported next to the outcome: how many plugin freezes so
     * far ended with every remaining freeze held by a DIFFERENT vCPU.  Each is
     * an occasion on which a per-vCPU thaw would have restarted the guest clock
     * inside a peer's window, so a large figure alongside zero ADVANCED lines
     * is the measurement that the machine-wide reference count is what holds
     * the requirement, not luck.
     *
     * The count that gates this line is per-vCPU-thread, so the period has to
     * be chosen against the excursions ONE vCPU takes, not the machine's total.
     * A fixed 20000 silently reports nothing on exactly the cells the peer
     * figure exists for: an x86_64 -smp 4 marker cell taking 20587 excursions
     * spread over four vCPUs printed no line at all, so peer_only_thaws -- the
     * only readout of the condition -- was unavailable on an SMP run, which is
     * where the condition lives.  CST_CLKEQ_EVERY sets the period; at 500 the
     * same cell reports it, and reads 528694.
     *
     * A period that cannot be used is SAID, not swapped in silence.  An
     * operator who asks for a period and is given a different one without
     * being told reads the resulting lines as answering the question they
     * set, which is the same misreading the fixed 20000 produced.  The
     * period is per-vCPU-thread like the count it gates, so a thread reads
     * the environment once and the refusal is announced once per process.
     */
#define CST_CLKEQ_EVERY_DEFAULT 20000
    static __thread uint64_t n_excursions;
    static __thread int every = -1;
    if (every < 0) {
        const char *s = getenv("CST_CLKEQ_EVERY");
        every = s ? atoi(s) : CST_CLKEQ_EVERY_DEFAULT;
        if (every <= 0) {
            static int refusal_announced;
            if (qatomic_xchg(&refusal_announced, 1) == 0) {
                fprintf(stderr, "[clkeq] CST_CLKEQ_EVERY=\"%s\" is not a "
                        "positive period; refused, reporting every %d "
                        "excursions per vcpu instead\n",
                        s ? s : "", CST_CLKEQ_EVERY_DEFAULT);
                fflush(stderr);
            }
            every = CST_CLKEQ_EVERY_DEFAULT;
        }
    }
    if ((++n_excursions % (unsigned)every) == 0) {
        fprintf(stderr, "[clkeq] cpu%d excursions=%" PRIu64 " advanced=%" PRIu64
                " notrestored=%" PRIu64 " peer_only_thaws=%" PRIu64 "\n",
                cpu->cpu_index, n_excursions, n_adv, n_not,
                cpu_plugin_ticks_peer_only_thaws());
        fflush(stderr);
    }
}

/*
 * CST_CLKAUDIT: can a guest observe ANY time discontinuity across a wrong-path
 * excursion?  Answered by enumerating the sources rather than by checking the
 * ones we thought of.
 *
 * cst_clkeq above samples ONE field, QEMU_CLOCK_VIRTUAL.  A zero from it is a
 * statement about that field and nothing else, and a guest has more than one
 * clock: on x86 alone the kernel reads the TSC, the HPET, the ACPI PM timer,
 * the LAPIC current-count, the PIT and the CMOS RTC, and its clocksource
 * watchdog exists precisely to cross-check one against another.  A per-field
 * instrument can only ever report on the fields someone listed.
 *
 * The enumeration is made complete by taking it one level below the guest's
 * clocks, at their ROOTS.  Every guest-visible timebase in QEMU is computed on
 * demand, at the moment the guest reads it, from one of six host-side
 * quantities.  Sampling those six therefore covers every derived source --
 * including sources in devices this file has never heard of, and ones not yet
 * written -- provided the derivation set really is closed.  That is a source
 * property, so it is established mechanically rather than asserted:
 *
 *     grep -rn 'qemu_clock_get_\(ns\|ms\|us\)(' --include=*.c hw/ target/ system/
 *     grep -rn 'cpu_get_host_ticks()\|cpu_get_ticks()\|cpus_get_elapsed_ticks()'
 *
 * Every hit resolves to a literal QEMU_CLOCK_* or to the one global selector
 * rtc_clock (which is itself one of QEMU_CLOCK_HOST / _REALTIME / _VIRTUAL).
 * Re-run those two greps when adding a device or a target: a new root is a new
 * row here, and a hit that bottoms out in neither list is a hole in this
 * instrument, not a clean result.
 *
 * The rows, and what each is allowed to do across an excursion:
 *
 *   VIRTUAL     cpus_get_virtual_clock()   HPET, ACPI PM, PIT, LAPIC timer,
 *                                          Arm CNTVCT/CNTPCT, MIPS CP0 Count,
 *                                          RISC-V ACLINT mtime.  MUST NOT MOVE.
 *   VMTICKS     cpu_get_ticks()            x86 TSC (cpus_get_elapsed_ticks),
 *                                          RISC-V mcycle/minstret.  MUST NOT
 *                                          MOVE -- x86 additionally re-pins it
 *                                          to the virtual clock at every thaw,
 *                                          so this row also checks that pin.
 *   VIRTUAL_RT  cpu_get_clock()            QEMU_CLOCK_VIRTUAL_RT.  MUST NOT
 *                                          MOVE (same gate as the above).
 *   HOST        get_clock_realtime()       host wall time.  Guest-visible ONLY
 *                                          through an RTC model, and only when
 *                                          rtc_clock names it -- so the
 *                                          exemption is COMPUTED from
 *                                          rtc_clock, never assumed.
 *   REALTIME    get_clock()                host monotonic.  Same rule.
 *   HOSTTICKS   cpu_get_host_ticks()       raw host cycle counter.  No target
 *                                          reads it in system mode; the row
 *                                          exists so that claim is measured
 *                                          rather than believed, and is
 *                                          reported as an unconditional
 *                                          exemption.  RISC-V's
 *                                          mcycle/minstret DID read it, which
 *                                          is why the row is not simply absent.
 *
 * A row that must not move and moved is named, with its delta, in both halves:
 * ADVANCED (it moved while the window was open -- the freeze did not hold) and
 * NOTRESTORED (it did not come back across the thaw and the per-target
 * resync).  Exempt rows are still sampled and still reported, once, with the
 * reason -- an exemption an operator cannot see is an exemption nobody
 * checked.
 *
 * Positive control: CST_NOFREEZE skips the freeze, so under it every
 * must-not-move row must report ADVANCED.  A run with CST_CLKAUDIT and
 * CST_NOFREEZE both set that reports nothing has a broken instrument.
 */
typedef enum {
    CST_CLKROOT_VIRTUAL,
    CST_CLKROOT_VMTICKS,
    CST_CLKROOT_VIRTUAL_RT,
    CST_CLKROOT_HOST,
    CST_CLKROOT_REALTIME,
    CST_CLKROOT_HOSTTICKS,
    CST_CLKROOT__COUNT
} CstClkRoot;

static const char * const cst_clkroot_name[CST_CLKROOT__COUNT] = {
    [CST_CLKROOT_VIRTUAL]    = "QEMU_CLOCK_VIRTUAL",
    [CST_CLKROOT_VMTICKS]    = "VM_TICKS",
    [CST_CLKROOT_VIRTUAL_RT] = "QEMU_CLOCK_VIRTUAL_RT",
    [CST_CLKROOT_HOST]       = "QEMU_CLOCK_HOST",
    [CST_CLKROOT_REALTIME]   = "QEMU_CLOCK_REALTIME",
    [CST_CLKROOT_HOSTTICKS]  = "HOST_TICKS",
};

static bool cst_clkaudit_on(void)
{
    static int on = -1;
    if (on < 0) {
        on = getenv("CST_CLKAUDIT") != NULL;
    }
    return on > 0;
}

/*
 * Whether a moving root is a guest-visible discontinuity.  For the three
 * gated roots the answer is fixed.  For the two host clocks it depends on
 * whether an RTC model is currently pointed at them, which is what rtc_clock
 * says -- so the exemption is derived from live configuration, and an
 * operator who passes -rtc clock=host (or runs without a plugin, so the
 * adoption in rtc_adopt_vm_clock_for_plugin() does not fire) gets the row
 * enforced instead of excused.
 */
static bool cst_clkroot_must_hold(CstClkRoot r, const char **why)
{
    switch (r) {
    case CST_CLKROOT_VIRTUAL:
    case CST_CLKROOT_VMTICKS:
    case CST_CLKROOT_VIRTUAL_RT:
        *why = "guest-visible";
        return true;
    case CST_CLKROOT_HOST:
        if (rtc_clock == QEMU_CLOCK_HOST) {
            *why = "guest-visible: rtc_clock == QEMU_CLOCK_HOST";
            return true;
        }
        *why = "host-only: no RTC points at it";
        return false;
    case CST_CLKROOT_REALTIME:
        if (rtc_clock == QEMU_CLOCK_REALTIME) {
            *why = "guest-visible: rtc_clock == QEMU_CLOCK_REALTIME";
            return true;
        }
        *why = "host-only: no RTC points at it";
        return false;
    case CST_CLKROOT_HOSTTICKS:
    default:
        *why = "host-only: no system-mode target reads the raw host counter";
        return false;
    }
}

static void cst_clkaudit_sample(int64_t v[CST_CLKROOT__COUNT])
{
    v[CST_CLKROOT_VIRTUAL]    = cpus_get_virtual_clock();
    v[CST_CLKROOT_VMTICKS]    = cpu_get_ticks();
    v[CST_CLKROOT_VIRTUAL_RT] = cpu_get_clock();
    /*
     * The two host clocks are read through their raw accessors rather than
     * qemu_clock_get_ns(), which wraps them in REPLAY_CLOCK: an instrument
     * must not consume a replay event.
     */
    v[CST_CLKROOT_HOST]       = get_clock_realtime();
    v[CST_CLKROOT_REALTIME]   = get_clock();
    v[CST_CLKROOT_HOSTTICKS]  = cpu_get_host_ticks();
}

static __thread int64_t g_clkaudit_pause[CST_CLKROOT__COUNT];

static void cst_clkaudit_note_pause(void)
{
    if (cst_clkaudit_on()) {
        cst_clkaudit_sample(g_clkaudit_pause);
    }
}

static void cst_clkaudit_check(CPUState *cpu,
                               const int64_t pre_thaw[CST_CLKROOT__COUNT])
{
    if (!cst_clkaudit_on()) {
        return;
    }
    int64_t post[CST_CLKROOT__COUNT];
    static __thread uint64_t n_adv[CST_CLKROOT__COUNT];
    static __thread uint64_t n_not[CST_CLKROOT__COUNT];
    static __thread bool exempt_said[CST_CLKROOT__COUNT];

    cst_clkaudit_sample(post);

    for (int r = 0; r < CST_CLKROOT__COUNT; r++) {
        const char *why = NULL;
        bool must = cst_clkroot_must_hold(r, &why);
        int64_t d_in  = pre_thaw[r] - g_clkaudit_pause[r];
        int64_t d_out = post[r]     - g_clkaudit_pause[r];

        if (!must) {
            /* Said once per row per thread, with the movement it was excused
             * for, so the exemption is visible and its size is on the record. */
            if (!exempt_said[r]) {
                exempt_said[r] = true;
                fprintf(stderr, "[clkaudit] cpu%d EXEMPT root=%s reason=\"%s\" "
                        "in_excursion_delta=%" PRId64 "\n", cpu->cpu_index,
                        cst_clkroot_name[r], why, d_in);
                fflush(stderr);
            }
            continue;
        }
        if (d_in != 0) {
            n_adv[r]++;
            if ((n_adv[r] & (n_adv[r] - 1)) == 0) {
                fprintf(stderr, "[clkaudit] cpu%d ADVANCED root=%s (%s) "
                        "pause=%" PRId64 " in_excursion=%" PRId64
                        " delta=%" PRId64 " n=%" PRIu64 "\n", cpu->cpu_index,
                        cst_clkroot_name[r], why, g_clkaudit_pause[r],
                        pre_thaw[r], d_in, n_adv[r]);
                fflush(stderr);
            }
        }
        if (d_out != 0) {
            n_not[r]++;
            if ((n_not[r] & (n_not[r] - 1)) == 0) {
                fprintf(stderr, "[clkaudit] cpu%d NOTRESTORED root=%s (%s) "
                        "pause=%" PRId64 " resume=%" PRId64
                        " delta=%" PRId64 " n=%" PRIu64 "\n", cpu->cpu_index,
                        cst_clkroot_name[r], why, g_clkaudit_pause[r],
                        post[r], d_out, n_not[r]);
                fflush(stderr);
            }
        }
    }
}
/*
 * CST_CLKPROBE (#80 diagnostic): measure the guest-visible TSC-vs-monotonic
 * skew the WP time-freeze accumulates.  Every excursion the freeze excludes a
 * host-TSC interval (cpu_get_host_ticks = rdtsc) from the guest TSC and a
 * host-monotonic interval (get_clock) from the guest HPET clock; if those two
 * host clocks drift, the guest's clocksource watchdog eventually marks the TSC
 * unstable.  tsc_hz is self-calibrated from the correct-path intervals between
 * excursions (both host clocks measured over the same real interval), so
 * "SKEW" is exactly the divergence the guest sees.  Off unless CST_CLKPROBE.
 */
static __thread int64_t  g_clkp_ht_pause, g_clkp_hm_pause;
static __thread int64_t  g_clkp_ht_resume, g_clkp_hm_resume;
static __thread int64_t  g_clkp_cp_tsc, g_clkp_cp_ns;
static __thread int64_t  g_clkp_excl_tsc, g_clkp_excl_ns;
static __thread int64_t  g_clkp_gt_pause, g_clkp_gc_pause;   /* GUEST tsc/clock */
static __thread int64_t  g_clkp_gleak_tsc, g_clkp_gleak_ns;  /* guest-visible leak */
static __thread uint64_t g_clkp_n;
static void cst_clkprobe(bool resume)
{
    static int on = -1;
    if (on < 0) {
        on = getenv("CST_CLKPROBE") != NULL;
    }
    if (!on) {
        return;
    }
    int64_t ht = cpu_get_host_ticks();
    int64_t hm = get_clock();
    int64_t gt = cpu_get_ticks();      /* guest TSC source */
    int64_t gc = cpu_get_clock();      /* guest QEMU_CLOCK_VIRTUAL source */
    if (!resume) {
        if (g_clkp_ht_resume) {          /* correct-path interval for calibration */
            g_clkp_cp_tsc += ht - g_clkp_ht_resume;
            g_clkp_cp_ns  += hm - g_clkp_hm_resume;
        }
        g_clkp_ht_pause = ht;
        g_clkp_hm_pause = hm;
        g_clkp_gt_pause = gt;
        g_clkp_gc_pause = gc;
        return;
    }
    g_clkp_excl_tsc += ht - g_clkp_ht_pause;   /* frozen (excluded) this excursion */
    g_clkp_excl_ns  += hm - g_clkp_hm_pause;
    g_clkp_gleak_tsc += gt - g_clkp_gt_pause;  /* guest TSC that LEAKED across WP */
    g_clkp_gleak_ns  += gc - g_clkp_gc_pause;  /* guest clock that LEAKED across WP */
    g_clkp_ht_resume = ht;
    g_clkp_hm_resume = hm;
    if (++g_clkp_n % 20000 == 0 && g_clkp_cp_ns > 0) {
        double tsc_hz = (double)g_clkp_cp_tsc / (double)g_clkp_cp_ns * 1e9;
        double excl_tsc_s  = (double)g_clkp_excl_tsc / tsc_hz;
        double excl_mono_s = (double)g_clkp_excl_ns / 1e9;
        double gleak_tsc_s = (double)g_clkp_gleak_tsc / tsc_hz;
        double gleak_ns_s  = (double)g_clkp_gleak_ns / 1e9;
        fprintf(stderr, "[clkprobe] n=%llu tsc=%.3fGHz host_skew=%.4fms "
                "GUEST_leak_tsc=%.4fms GUEST_leak_clk=%.4fms GUEST_skew=%.4fms\n",
                (unsigned long long)g_clkp_n, tsc_hz / 1e9,
                (excl_tsc_s - excl_mono_s) * 1e3,
                gleak_tsc_s * 1e3, gleak_ns_s * 1e3,
                (gleak_tsc_s - gleak_ns_s) * 1e3);
    }
}
#endif

#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
/*
 * Instruction-counter position captured at wrong-path excursion entry and put
 * back at exit, so the excursion consumes zero icount just as the tick freeze
 * makes it consume zero wall-clock guest time.  Thread-local rather than
 * per-CPU because the pause/resume pair always runs on the vCPU's own thread,
 * and the pair is made non-reentrant by plugin_spec_vtime_paused.
 */
static __thread IcountFreeze g_spec_icount_freeze;

/* Guest-insn slice bounding: the CORRECT PATH's remaining slice budget,
 * saved at excursion open and restored at excursion close (see
 * cpu_plugin_spec_vtime_pause/_resume). */
static __thread uint16_t g_cst_bq_exc_low;
static __thread bool g_cst_bq_exc_low_active;

/*
 * The per-target clock resynchronisation hook (TCGCPUOps::spec_clock_resync).
 * Every guest-observable clock and every armed host QEMUTimer is reconciled
 * to the FROZEN virtual time by the target, at the end of both plugin clock
 * freezes.  The generic code owns the freeze/thaw and the ordering; the
 * target owns the knowledge of what its clocks are.  See the hook's contract
 * in include/accel/tcg/cpu-ops.h.
 */
static void cpu_plugin_clock_resync(CPUState *cpu, SpecClockResyncReason why)
{
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;

    if (tcg_ops && tcg_ops->spec_clock_resync) {
        tcg_ops->spec_clock_resync(cpu, why);
    }
}
#endif

/*
 * Wrong-path containment helpers with softmmu-only side effects.  Compiled
 * per-target so CONFIG_USER_ONLY selects the no-op forms; the common
 * plugins/api.c calls these rather than referencing tlb_flush /
 * cpu_disable_ticks directly (which are not linked into user-mode binaries).
 *
 * The whole family is CONFIG_PLUGIN-only: plugins/api.c is its sole caller,
 * and the CPUState fields it manipulates live inside the same guard.
 */
#ifdef CONFIG_PLUGIN
void cpu_plugin_spec_vtime_pause(CPUState *cpu)
{
#ifndef CONFIG_USER_ONLY
    /*
     * Freeze the guest virtual clock across a whole wrong-path excursion so
     * the speculative run's host wall-clock time does not advance the guest's
     * architected timer counters (CNTVCT / TSC / time / Count) — WP is outside
     * guest time.  Idempotent + balanced via plugin_spec_vtime_paused so a
     * fault-skip's spec_mode teardown/re-entry does not leak ticks.
     */
    if (cpu->plugin_spec_vtime_paused) {
        return;
    }
    bool need_bql = !bql_locked();
    if (need_bql) {
        bql_lock();
    }
#ifdef CONFIG_PLUGIN
    cst_clkprobe(false);              /* #80: skew measurement (gated) */
    /* #77 arm: keep the excursion window + resync, but DON'T freeze the guest
     * virtual clock during WP (lets the stimer deadline still be reached in a
     * WP-saturated spin).  Distinguishes timer-freeze starvation from a leak. */
    if (!cst_nofreeze())
#endif
    {
        /*
         * The SPECULATIVE freeze: the clock's value stops, and so does its
         * processing.  This is the only bracket that stops processing, and
         * the reason is that this is the only bracket inside which the guest
         * is not between two of its own instructions -- there is no legal
         * position here for an event derived from guest time.  The
         * correct-path instrumentation window below
         * (cpu_plugin_vclock_pause) keeps the value-only freeze: it brackets
         * a callback that runs beside real guest execution, where every
         * guest-time event still has a position and only the callback's host
         * cost must be kept out of the clock.
         */
        cpu_plugin_spec_ticks_freeze(cpu->cpu_index);
#ifdef CONFIG_PLUGIN
        /* The other half of the freeze: under -icount the guest clock is
         * driven by retired instructions, which cpu_disable_ticks() does not
         * touch.  See icount_plugin_freeze(). */
        icount_plugin_freeze(cpu, &g_spec_icount_freeze);
#endif
    }
#ifdef CONFIG_PLUGIN
    /*
     * Guest-insn slice bounding: the default-clock mirror of
     * icount_plugin_freeze's u16.low capture (that call is a no-op off
     * icount).  Save the CORRECT PATH's remaining budget here, at the
     * true excursion open; every spec-mode dispatch runs on its own
     * full quantum (cpu_plugin_exec_tb/_inline), and
     * cpu_plugin_spec_vtime_resume puts this value back, so WP depth
     * cannot drain the CP slice.  Deliberately OUTSIDE the
     * cst_nofreeze() gate above: the budget rule must not silently
     * change under that lever.
     */
    if (unlikely(cst_bq_on)) {
        g_cst_bq_exc_low = cpu->neg.icount_decr.u16.low;
        g_cst_bq_exc_low_active = true;
        cst_bq_note_exc_save();
    }
#endif
#ifdef CONFIG_PLUGIN
    cst_clkeq_note_pause();           /* #77 falsifier: excursion clock equality */
    cst_clkaudit_note_pause();        /* every root a guest clock derives from */
#endif
#if defined(TARGET_RISCV) && defined(CONFIG_PLUGIN)
    /*
     * Start the excursion's pending-interrupt record empty, and do it under
     * the same BQL hold that opens the window, so riscv_cpu_update_mip (which
     * takes the BQL for its update) cannot have a raise recorded and then
     * wiped by this reset.
     *
     * The record is only consumed by cpu_plugin_arch_state_restore, which
     * fires at excursion exit while the window is still open: a raise landing
     * after that consume and before cpu_plugin_spec_vtime_resume closes the
     * window is recorded but never replayed -- correctly, because nothing
     * rewinds env->mip after the restore, so the bit is already live.  Left in
     * place it would be replayed by the NEXT excursion's restore, resurrecting
     * an interrupt the guest may have acknowledged in between.  Clearing here
     * makes each excursion's replay describe only that excursion.
     */
    {
        CPURISCVState *renv = cpu_env(cpu);
        renv->plugin_spec_mip_set = 0;
        renv->plugin_spec_mip_clear = 0;
    }
#endif
#if defined(TARGET_MIPS) && defined(CONFIG_PLUGIN)
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
        menv->plugin_ext_ip_set = 0;
        menv->plugin_ext_ip_clear = 0;
    }
#endif
    cpu->plugin_spec_vtime_paused = true;
#ifdef CONFIG_PLUGIN
    if (wprot_ready()) {           /* #77: write-protect guest RAM for the WP */
        wprot_setprot(PROT_READ);
        g_wprot_active = true;
    }
    sdiff_snapshot(cpu);           /* #77: snapshot CPU state for leak diff */
    tlbsave_snapshot(cpu);         /* #77: snapshot full TLB (causation test) */
    /*
     * x86 only: hold the BQL across the whole wrong-path excursion so the main
     * loop (iothread) cannot interleave mid-WP.  The excursion freezes the
     * guest virtual clock (cpu_plugin_ticks_freeze above); the underlying
     * cpu_ticks_enabled is a VM-global boolean, not per-vCPU, and x86 delivers
     * speculative page faults extremely often, so the abnormal-longjmp /
     * fault-skip spec_mode re-entry cycling runs far more than on other ISAs.
     * Before the reference count that boolean had two independent owners and
     * the disable/enable could be left unbalanced, desyncing cpu_clock_offset
     * from cpu_ticks_offset.  The guest's TSC-vs-HPET clocksource watchdog then
     * marks the TSC unstable and wedges timekeeping/RCU — a system-mode
     * livelock (the vCPU spins in WP while jiffies drift and the scheduler
     * starves; confirmed: holding the BQL, or booting tsc=reliable, both clear
     * it).  Serialising the excursion against the iothread — as -icount does —
     * keeps guest time consistent.  This is x86's analogue of the per-target
     * timer resync arm/riscv/mips run at excursion exit (cpu_plugin_spec_vtime
     * _resume); x86 has no env-backed timer to resync, so it holds the BQL
     * instead.  It is x86-ONLY because other ISAs' WP execution legitimately
     * takes the BQL for a sandboxed device access, and holding it here would
     * recursively self-lock (bql_lock asserts !bql_locked()).  Bounded by
     * wpdepth.
     *
     * It does NOT follow that the excursion cannot deadlock, and this comment
     * used to end by saying it could not.  An excursion BLOCKS on the BQL
     * every time it takes one: at the bql_lock above, on every target; at
     * cpu_plugin_spec_vtime_resume's, on the targets that do not hold it
     * through; and at cpu_plugin_arch_state_restore's on RISC-V.  It does so
     * while still holding whatever lock the plugin took before calling in, so
     * the excursion's lock order is plugin-lock then BQL.  Any seam that
     * dispatches a plugin callback with the BQL ALREADY held and then blocks
     * on that same plugin lock runs the order the other way and closes an
     * AB/BA cycle.  process_queued_cpu_work() is such a seam — it runs a
     * non-exclusive work item with the BQL held — and the machine-shutdown
     * callback is placed through it.  Measured on riscv64, -smp 4, wp=1, a
     * marker window open, SIGTERM: four cells of eight stopped dead with the
     * shutdown callback waiting on the plugin's lock, that lock's holder
     * waiting here for the BQL the callback's own vCPU holds, and every
     * thread in futex_wait at zero CPU.  aarch64 with the same arms closed
     * in both cells it was run in, which bounds how often it happens there
     * and not whether it can: the pause and the resume block on the BQL on
     * every target, and only the third acquisition — the RISC-V replay in
     * cpu_plugin_arch_state_restore — is target-specific.  The cure belongs
     * at the dispatching seam, which must not hold the BQL across a plugin
     * callback; nothing about the hold below makes an excursion safe.
     *
     * WHAT THE HOLD IS FOR NOW, which is not what it was added for.  Both of
     * the reasons above have been paid off elsewhere.  The unbalanced
     * disable/enable is gone: cpu_plugin_ticks_freeze() arbitrates the one
     * cpu_ticks_enabled through a reference count, so the pair cannot be left
     * astray by a peer.  The oscillator split is gone too -- c1657092ce made
     * cpu_get_ticks() a fixed affine function of cpu_get_clock(), so the TSC
     * and QEMU_CLOCK_VIRTUAL stop and restart together by construction and
     * the guest's TSC-vs-HPET watchdog has nothing left to find.  And the
     * AB/BA cycle the paragraph above describes is closed at its seam, by the
     * BQL drop around the shutdown dispatch in plugins/system.c.
     *
     * The third property the hold was found to be carrying -- that on x86 it
     * was the only thing keeping a guest-visible timer callback out of an
     * excursion window -- is the one this comment used to end on, and it is
     * the one that has now moved.  A plugin freeze used to stop the clock's
     * VALUE and leave its PROCESSING running, so an iothread free to take a
     * virtual timerlist pass mid-excursion evaluated deadlines against a
     * clock that was not moving and entered the callbacks it found due,
     * inside the window, on the wrong path's watch.  Measured on the x86_64
     * system marker cell with --devio-probe 256, counting callbacks ENTERED
     * while an excursion was open: none at all with the hold, in 24 of 24
     * boots; 27 to 73 per boot without it, in 24 of 24, every one of them on
     * a thread other than the excursion's own -- over 5.97M and 5.99M
     * excursions respectively, so the arms were matched and the zero was the
     * hold's doing rather than an arm that did not run.
     *
     * cpu_plugin_spec_ticks_freeze() above now denies that pass directly, on
     * every target, without taking a lock: the excursion suspends the
     * guest-visible clock's processing for its own duration, so the pass
     * reports no deadline and enters no callback whether or not anyone holds
     * the BQL.  On x86 that makes the hold redundant for THIS purpose, and it
     * means the exclusion no longer stops at x86.
     *
     * The hold nonetheless stays for now, and deliberately: it was introduced
     * against a measured livelock, its removal is a lock-order change on the
     * one target where the excursion runs longest, and it gets its own commit
     * and its own A/B rather than being deleted as a side effect of this one.
     * What has changed is the argument for keeping it, which is no longer
     * "removing it admits the event class the wrong-path boundary exists to
     * exclude".
     */
#if defined(TARGET_I386)
    {
        static int no_hold = -1;   /* CST_NO_BQLHOLD: A/B the BQL-hold */
        if (no_hold < 0) {
            no_hold = getenv("CST_NO_BQLHOLD") != NULL;
        }
        if (need_bql && !no_hold) {
            g_wp_bql_held = true;
            return;                /* keep BQL; resume releases it */
        }
    }
#endif
#endif
    if (need_bql) {
        bql_unlock();
    }
#endif
}

void cpu_plugin_spec_vtime_resume(CPUState *cpu)
{
#ifndef CONFIG_USER_ONLY
    if (!cpu->plugin_spec_vtime_paused) {
        return;
    }
    bool we_hold_from_pause = false;
#ifdef CONFIG_PLUGIN
    we_hold_from_pause = g_wp_bql_held;   /* #77 test: pause kept BQL held */
    g_wp_bql_held = false;
#endif
    bool need_bql = !bql_locked();
    if (need_bql) {
        bql_lock();
    }
    /*
     * Give back the freeze this excursion took.  cpu_plugin_ticks_thaw() owns
     * both the arbitration and the vm_stop deference: the clock restarts only
     * when the LAST outstanding plugin freeze closes -- this excursion's, the
     * correct-path instrumentation window nested around it on this vCPU, and
     * any window a PEER vCPU has open, all of which drive the one global
     * cpu_ticks_enabled -- and never while a vm_stop owns the stopped clock.
     * The predecessor of that call was a bare cpu_enable_ticks() conditioned
     * on this vCPU's own plugin_vclock_depth, which can say nothing about a
     * peer: a peer's translation callback closing its window mid-excursion
     * restarted the clock underneath this excursion, and this thaw then found
     * ticks already enabled and left them so.
     */
    int64_t clkeq_pre_thaw = 0;
    int64_t clkaudit_pre_thaw[CST_CLKROOT__COUNT] = { 0 };
#ifdef CONFIG_PLUGIN
    if (cst_clkeq_on()) {
        clkeq_pre_thaw = cpu_get_clock();   /* before the thaw: did it move? */
    }
    if (cst_clkaudit_on()) {
        /* Sampled here, inside the still-open window: this is what the guest
         * would have read had it executed one more instruction before the
         * excursion closed, and it is the only place the "did the freeze hold
         * for the WHOLE window" half of the question can be answered. */
        cst_clkaudit_sample(clkaudit_pre_thaw);
    }
    if (!cst_nofreeze())   /* #77 arm: never disabled ticks; don't re-enable */
#endif
    {
        /* Value back first, then processing -- see the pair's contract. */
        cpu_plugin_spec_ticks_thaw(cpu->cpu_index);
    }
#ifdef CONFIG_PLUGIN
    /*
     * The icount position belongs to the excursion that captured it, not to
     * whichever freeze happens to be last out: restore it here unconditionally
     * (a no-op when icount is off or the record was never armed).
     */
    icount_plugin_thaw(cpu, &g_spec_icount_freeze);
    /*
     * Guest-insn slice bounding: the matching CP budget restore.  This
     * function runs on BOTH excursion exits (normal wp_end and the
     * abnormal longjmp cleanup), same as the thaw above, so the CP
     * slice resumes with exactly the budget it entered with regardless
     * of what the wrong path spent.
     */
    if (g_cst_bq_exc_low_active) {
        cpu->neg.icount_decr.u16.low = g_cst_bq_exc_low;
        g_cst_bq_exc_low_active = false;
        cst_bq_note_exc_restore();
    }
#endif
    cpu->plugin_spec_vtime_paused = false;
#ifdef CONFIG_PLUGIN
    cst_clkprobe(true);            /* #80: skew measurement (gated) */
    if (g_wprot_active) {          /* #77: restore guest RAM to read-write */
        wprot_setprot(PROT_READ | PROT_WRITE);
        g_wprot_active = false;
    }
    tlbsave_restore(cpu);         /* #77: revert full TLB (causation test) */
#endif
    /*
     * Resync every guest clock to the frozen virtual time HERE -- the true
     * excursion-exit boundary -- not inside cpu_plugin_arch_state_restore.  A
     * wrong-path fault-skip does an intermediate cpu_state_restore mid-excursion
     * (spec_mode_end -> restore -> spec_mode_begin) without resuming vtime; doing
     * the resync at every restore would consume the deferred-expiry record there
     * and synthesise a pending timer IRQ (e.g. riscv STIP) that the FINAL wp_end
     * restore then clobbers with the stale snapshot, losing the timer event and
     * livelocking the guest (#77).  Deferring to vtime_resume lets the deferral
     * survive intermediate restores so the resync runs once against the final
     * state, after ticks are re-enabled and with spec mode already ended.
     *
     * Unconditional and per-target: every registered target reconciles all of
     * its clocks here, whether or not this particular excursion is known to
     * have perturbed one.  The predecessor of this call was three unrelated
     * per-ISA point patches behind an event-driven "dirty" gate, and every
     * clock source no patch happened to cover -- or that desynced without
     * setting the flag -- silently drifted.
     */
#if defined(CONFIG_PLUGIN)
    cpu_plugin_clock_resync(cpu, SPEC_CLOCK_EXCURSION_END);
#ifdef CONFIG_PLUGIN
    /* #77 test: the WP-saturated vCPU starves the main loop's QEMU_CLOCK_VIRTUAL
     * timer processing, so the guest stimer never fires -> tick death.  Process
     * expired virtual timers in-thread here (as -icount does at insn boundaries)
     * under the BQL we already hold, so the deferred tick is delivered. */
    if (getenv("CST_RUNTIMERS")) {
        qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL);
    }
    /*
     * The excursion's defining requirement, checked where it must hold: the
     * guest virtual clock now reads what it read when the excursion began.
     * Sampled after the thaw and after the per-target resync, so it sees the
     * value the guest will see.
     */
    cst_clkeq_check(cpu, clkeq_pre_thaw);
    cst_clkaudit_check(cpu, clkaudit_pre_thaw);
    /*
     * The leak diff belongs after the LAST step of the restore, for the same
     * reason: a comparison taken before the restore finishes reports the work
     * the restore has not done yet as work it will never do.  Its predecessor
     * sat before cpu_plugin_clock_resync(), so every byte that call restores
     * was reported as an un-restored leak by the statement that was about to
     * restore it.
     */
    sdiff_compare(cpu);            /* #77: un-restored CPU-state leak */
#endif
#endif
    /*
     * Kick re-arm — the other half of the wrong-path kick deferral in
     * cpu_plugin_exec_tb.  The speculative exec clears icount_decr.u16.high
     * so a mid-excursion cpu_exit() kick cannot truncate the wrong-path walk;
     * here, at the true excursion exit (this function runs on BOTH the normal
     * wp_end path and the abnormal longjmp-cleanup path), the kick is
     * reconstructed from the request flags every kick source sets first.  Net
     * effect: the correct path breaks out of its TB loop at the first
     * boundary after the excursion — the same point it would have reached had
     * the excursion taken zero host time.  Delivery latency added by an
     * excursion is thereby bounded by that one excursion, by construction,
     * and wrong-path content is independent of host IRQ timing.
     */
    /*
     * Edge semantics: reconstruct the kick iff this excursion actually
     * cleared one (plugin_spec_kick_deferred, set by the WP dispatch
     * that consumed it), or one is in the register right now (landed
     * after the last dispatch).  The request flags are NOT consulted:
     * interrupt_request holds level bits that stay set while a line is
     * pending (e.g. a masked IRQ), so reconstructing from them would
     * fabricate a kick nobody posted, every excursion, for as long as
     * the line stays high.
     */
    if (cpu->plugin_spec_kick_deferred ||
        qatomic_read(&cpu->neg.icount_decr.u16.high)) {
        qatomic_set(&cpu->neg.icount_decr.u16.high, -1);
    }
    /*
     * The deferral flag must not outlive its excursion: this resume runs on
     * BOTH exit paths (the walker's normal wp_end and the abnormal
     * longjmp cleanup), so clearing it here — outside the branch above —
     * is what keeps a deferred kick from leaking into the next excursion's
     * re-arm decision.
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
 * principle as the wrong-path vtime pause above — plugin work is outside
 * guest execution, so its host wall-clock cost must not advance guest time —
 * but for the CORRECT-path instrumentation cost.  Without this, a heavily
 * instrumented guest tick handler can cost more guest time than one tick
 * period, leaving the next tick already pending on return: the guest
 * collapses into a self-sustaining tick/scheduler storm (context-switch
 * storm, RCU-kthread starvation, zero foreground progress).
 *
 * Nesting (plugin_vclock_depth) counts this vCPU's own windows, so callers
 * can wrap arbitrary regions without coordinating.  Composition with the WP
 * pause, and with a window open on a DIFFERENT vCPU, is not this counter's
 * job: each vCPU's outermost window takes one reference on the machine-wide
 * freeze (cpu_plugin_ticks_freeze), and the clock restarts only when the last
 * reference anywhere goes away.  It used to be this counter's job, via a
 * short-circuit on this vCPU's plugin_spec_vtime_paused, which is blind to a
 * peer: a translation callback on vCPU 1 takes no exec lock and so runs
 * freely inside vCPU 0's wrong-path excursion, and its window closing called
 * cpu_enable_ticks() and restarted the guest clock in the middle of that
 * excursion.  The vm_stop guard lives in cpu_plugin_ticks_thaw(): never
 * re-enable a clock a vm_stop owns.
 *
 * VALUE ONLY, and that is the difference from the wrong-path pause.  This
 * window brackets a callback that runs beside guest execution the guest
 * really performed: the guest sits between two of its own instructions, so
 * every event derived from guest time still has a legal position and the only
 * requirement is that the callback's host cost stays out of the clock.
 * Suspending the clock's PROCESSING here as well was tried and measured red
 * -- once per translation block the guest's timers stop being evaluated, and
 * on the x86 system marker cell 5 cells in 12 stalled with a 24.2-24.4k
 * instruction cluster that had not existed before.  The processing stall
 * belongs to cpu_plugin_spec_ticks_freeze() and to nothing else.
 */
void cpu_plugin_vclock_pause(CPUState *cpu)
{
#ifndef CONFIG_USER_ONLY
    if (cpu->plugin_vclock_depth++ > 0) {
        return;                    /* already frozen by an outer window */
    }
#ifdef CONFIG_PLUGIN
    if (cst_nofreeze()) {
        return;
    }
#endif
    bool need_bql = !bql_locked();
    if (need_bql) {
        bql_lock();
    }
    cpu_plugin_ticks_freeze(cpu->cpu_index);
    if (need_bql) {
        bql_unlock();
    }
#endif
}

void cpu_plugin_vclock_resume(CPUState *cpu)
{
#ifndef CONFIG_USER_ONLY
    g_assert(cpu->plugin_vclock_depth > 0);
    if (--cpu->plugin_vclock_depth > 0) {
        return;                    /* still frozen by an outer window */
    }
#ifdef CONFIG_PLUGIN
    if (cst_nofreeze()) {
        return;
    }
#endif
    bool need_bql = !bql_locked();
    if (need_bql) {
        bql_lock();
    }
    if (cpu_plugin_ticks_thaw(cpu->cpu_index)) {
#if defined(CONFIG_PLUGIN)
        /*
         * The clock actually restarted here: no guest state moved, but each
         * target still has to reconcile the clocks it owns to the frozen
         * time -- an armed host QEMUTimer whose deadline was computed against
         * the pre-freeze virtual clock, above all.
         *
         * This used to say the resync was here to re-pin a counter derived
         * from a different host oscillator than the virtual clock.  That was
         * the x86 TSC, and c1657092ce removed the second oscillator instead
         * of reconciling it, so x86's hook now has nothing to do past its
         * one-shot arming.  The call stays because arm, mips and riscv all
         * register the hook for the timer reason above.
         */
        cpu_plugin_clock_resync(cpu, SPEC_CLOCK_THAW);
#endif
    }
    if (need_bql) {
        bql_unlock();
    }
#endif
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
#ifdef CONFIG_PLUGIN
    /* #77 diagnostic toggle: CST_WP_FULLFLUSH forces a full TLB flush on every
     * WP exit instead of the selective per-logged-page flush, to test whether a
     * WP-installed TLB entry leaking into the correct path causes the teardown
     * livelock. */
    if (cpu->plugin_spec_tlb_log_overflow || getenv("CST_WP_FULLFLUSH")) {
        tlb_flush(cpu);
    } else {
        cpu_plugin_spec_tlb_flush_logged(cpu);
    }
    cpu->plugin_spec_tlb_log_n = 0;
    cpu->plugin_spec_tlb_log_overflow = false;
#else
    tlb_flush(cpu);
#endif
#endif
}

/*
 * Spec-mode entry TLB flush — the portable (host-independent) half of the
 * wrong-path store sandbox.
 *
 * On a host TCG backend that does NOT honor CF_FORCE_SLOW, spec-mode routing
 * to the sandboxed do_ld/do_st helpers relies on TLB_FORCE_SLOW being set on
 * every TLB entry the excursion uses; tlb_set_page_full stamps it on each
 * entry the excursion installs.  Correct-path entries already resident when
 * the excursion begins predate that stamp and lack the flag, so an inline
 * TLB-hit speculative store would reach real guest RAM (the storm this fixed:
 * see the i386 CF_FORCE_SLOW commit).  Flush here so those entries refill —
 * with the flag — inside the excursion, closing the window for pre-existing
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
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
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
 * speculative stores on ANY host backend — every backend's inline fast-path
 * compare already treats a TLB_FORCE_SLOW entry as a miss.  The only remaining
 * unsupported case is user mode on a backend without CF_FORCE_SLOW: there is
 * no softmmu TLB to carry the flag and stores go straight to the guest image.
 */
bool cpu_plugin_spec_mode_supported(void)
{
#if TCG_TARGET_HAS_SPEC_FORCE_SLOW
    return true;
#elif !defined(CONFIG_USER_ONLY)
    return true;
#else
    return false;
#endif
}
#endif /* CONFIG_PLUGIN */

void tb_set_jmp_target(TranslationBlock *tb, int n, uintptr_t addr)
{
    /*
     * Get the rx view of the structure, from which we find the
     * executable code address, and tb_target_set_jmp_target can
     * produce a pc-relative displacement to jmp_target_addr[n].
     */
    const TranslationBlock *c_tb = tcg_splitwx_to_rx(tb);
    uintptr_t offset = tb->jmp_insn_offset[n];
    uintptr_t jmp_rx = (uintptr_t)tb->tc.ptr + offset;
    uintptr_t jmp_rw = jmp_rx - tcg_splitwx_diff;

    tb->jmp_target_addr[n] = addr;
    tb_target_set_jmp_target(c_tb, n, jmp_rx, jmp_rw);
}

static inline void tb_add_jump(TranslationBlock *tb, int n,
                               TranslationBlock *tb_next)
{
    uintptr_t old;

    qemu_thread_jit_write();
    assert(n < ARRAY_SIZE(tb->jmp_list_next));
    qemu_spin_lock(&tb_next->jmp_lock);

    /* make sure the destination TB is valid */
    if (tb_next->cflags & CF_INVALID) {
        goto out_unlock_next;
    }
    /* Atomically claim the jump destination slot only if it was NULL */
    old = qatomic_cmpxchg(&tb->jmp_dest[n], (uintptr_t)NULL,
                          (uintptr_t)tb_next);
    if (old) {
        goto out_unlock_next;
    }

    /* patch the native jump address */
    tb_set_jmp_target(tb, n, (uintptr_t)tb_next->tc.ptr);

    /* add in TB jmp list */
    tb->jmp_list_next[n] = tb_next->jmp_list_head;
    tb_next->jmp_list_head = (uintptr_t)tb | n;

    qemu_spin_unlock(&tb_next->jmp_lock);

    qemu_log_mask(CPU_LOG_EXEC, "Linking TBs %p index %d -> %p\n",
                  tb->tc.ptr, n, tb_next->tc.ptr);
    return;

 out_unlock_next:
    qemu_spin_unlock(&tb_next->jmp_lock);
    return;
}

static inline bool cpu_handle_halt(CPUState *cpu)
{
#ifndef CONFIG_USER_ONLY
    if (cpu->halted) {
        const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;
        bool leave_halt = tcg_ops->cpu_exec_halt(cpu);

        if (!leave_halt) {
            return true;
        }

        cpu->halted = 0;
    }
#endif /* !CONFIG_USER_ONLY */

    return false;
}

static inline void cpu_handle_debug_exception(CPUState *cpu)
{
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;
    CPUWatchpoint *wp;

    if (!cpu->watchpoint_hit) {
        QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }

    if (tcg_ops->debug_excp_handler) {
        tcg_ops->debug_excp_handler(cpu);
    }
}

static inline bool cpu_handle_exception(CPUState *cpu, int *ret)
{
    if (cpu->exception_index < 0) {
#ifndef CONFIG_USER_ONLY
        if (replay_has_exception()
            && cpu->neg.icount_decr.u16.low + cpu->icount_extra == 0) {
            /* Execute just one insn to trigger exception pending in the log */
            cpu->cflags_next_tb = (curr_cflags(cpu) & ~CF_USE_ICOUNT)
                | CF_NOIRQ | 1;
        }
#endif
        return false;
    }

    if (cpu->exception_index >= EXCP_INTERRUPT) {
        /* exit request from the cpu execution loop */
        *ret = cpu->exception_index;
        if (*ret == EXCP_DEBUG) {
            cpu_handle_debug_exception(cpu);
        }
        cpu->exception_index = -1;
        return true;
    }

#if defined(CONFIG_USER_ONLY)
    /*
     * If user mode only, we simulate a fake exception which will be
     * handled outside the cpu execution loop.
     */
#if defined(TARGET_I386)
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;
    tcg_ops->fake_user_interrupt(cpu);
#endif /* TARGET_I386 */
    *ret = cpu->exception_index;
    cpu->exception_index = -1;
    return true;
#else
    if (replay_exception()) {
        const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;

        bql_lock();
        tcg_ops->do_interrupt(cpu);
        bql_unlock();
        cpu->exception_index = -1;

        if (unlikely(cpu->singlestep_enabled)) {
            /*
             * After processing the exception, ensure an EXCP_DEBUG is
             * raised when single-stepping so that GDB doesn't miss the
             * next instruction.
             */
            *ret = EXCP_DEBUG;
            cpu_handle_debug_exception(cpu);
            return true;
        }
    } else if (!replay_has_interrupt()) {
        /* give a chance to iothread in replay mode */
        *ret = EXCP_INTERRUPT;
        return true;
    }
#endif

    return false;
}

static inline bool icount_exit_request(CPUState *cpu)
{
    if (!icount_enabled()) {
        return false;
    }
    if (cpu->cflags_next_tb != -1 && !(cpu->cflags_next_tb & CF_USE_ICOUNT)) {
        return false;
    }
    return cpu->neg.icount_decr.u16.low + cpu->icount_extra == 0;
}

static inline bool cpu_handle_interrupt(CPUState *cpu,
                                        TranslationBlock **last_tb)
{
    /*
     * If we have requested custom cflags with CF_NOIRQ we should
     * skip checking here. Any pending interrupts will get picked up
     * by the next TB we execute under normal cflags.
     */
    if (cpu->cflags_next_tb != -1 && cpu->cflags_next_tb & CF_NOIRQ) {
        return false;
    }

    /* Clear the interrupt flag now since we're processing
     * cpu->interrupt_request and cpu->exit_request.
     * Ensure zeroing happens before reading cpu->exit_request or
     * cpu->interrupt_request (see also smp_wmb in cpu_exit())
     */
    qatomic_set_mb(&cpu->neg.icount_decr.u16.high, 0);

    if (unlikely(qatomic_read(&cpu->interrupt_request))) {
        int interrupt_request;
        bql_lock();
        interrupt_request = cpu->interrupt_request;
        if (unlikely(cpu->singlestep_enabled & SSTEP_NOIRQ)) {
            /* Mask out external interrupts for this step. */
            interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
        }
        if (interrupt_request & CPU_INTERRUPT_DEBUG) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
            cpu->exception_index = EXCP_DEBUG;
            bql_unlock();
            return true;
        }
#if !defined(CONFIG_USER_ONLY)
        if (replay_mode == REPLAY_MODE_PLAY && !replay_has_interrupt()) {
            /* Do nothing */
        } else if (interrupt_request & CPU_INTERRUPT_HALT) {
            replay_interrupt();
            cpu->interrupt_request &= ~CPU_INTERRUPT_HALT;
            cpu->halted = 1;
            cpu->exception_index = EXCP_HLT;
            bql_unlock();
            return true;
        }
#if defined(TARGET_I386)
        else if (interrupt_request & CPU_INTERRUPT_INIT) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            CPUArchState *env = &x86_cpu->env;
            replay_interrupt();
            cpu_svm_check_intercept_param(env, SVM_EXIT_INIT, 0, 0);
            do_cpu_init(x86_cpu);
            cpu->exception_index = EXCP_HALTED;
            bql_unlock();
            return true;
        }
#else
        else if (interrupt_request & CPU_INTERRUPT_RESET) {
            replay_interrupt();
            cpu_reset(cpu);
            bql_unlock();
            return true;
        }
#endif /* !TARGET_I386 */
        /* The target hook has 3 exit conditions:
           False when the interrupt isn't processed,
           True when it is, and we should restart on a new TB,
           and via longjmp via cpu_loop_exit.  */
        else {
            const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;
#ifdef CONFIG_PLUGIN
            /* CST_IRQSTORM (#80 diagnostic): detect an interrupt storm —
             * repeated async delivery with the INTERRUPTED guest PC (sampled
             * before the vector redirect) never advancing: each IRQ pass
             * consumed more virtual time than the guest needed to retire one
             * instruction, so the same insn is re-interrupted forever. */
            static int storm_diag = -1;
            if (storm_diag < 0) {
                storm_diag = getenv("CST_IRQSTORM") != NULL;
            }
            uint64_t storm_pre_pc = storm_diag ? cpu->cc->get_pc(cpu) : 0;
#endif

            if (tcg_ops->cpu_exec_interrupt(cpu, interrupt_request)) {
#ifdef CONFIG_PLUGIN
                if (storm_diag) {
                    static uint64_t last_pc, storm_len, reported;
                    if (storm_pre_pc == last_pc) {
                        storm_len++;
                        if (storm_len >= 1000 && storm_len >= reported * 10) {
                            fprintf(stderr, "[irqstorm] pc=0x%" PRIx64
                                    " consecutive_irqs=%" PRIu64 "\n",
                                    storm_pre_pc, storm_len);
                            reported = storm_len;
                        }
                    } else {
                        last_pc = storm_pre_pc;
                        storm_len = 1;
                        reported = 0;
                    }
                }
#endif
                if (!tcg_ops->need_replay_interrupt ||
                    tcg_ops->need_replay_interrupt(interrupt_request)) {
                    replay_interrupt();
                }
                /*
                 * After processing the interrupt, ensure an EXCP_DEBUG is
                 * raised when single-stepping so that GDB doesn't miss the
                 * next instruction.
                 */
                if (unlikely(cpu->singlestep_enabled)) {
                    cpu->exception_index = EXCP_DEBUG;
                    bql_unlock();
                    return true;
                }
                cpu->exception_index = -1;
                *last_tb = NULL;
            }
            /* The target hook may have updated the 'cpu->interrupt_request';
             * reload the 'interrupt_request' value */
            interrupt_request = cpu->interrupt_request;
        }
#endif /* !CONFIG_USER_ONLY */
        if (interrupt_request & CPU_INTERRUPT_EXITTB) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
            /* ensure that no TB jump will be modified as
               the program flow was changed */
            *last_tb = NULL;
        }

        /* If we exit via cpu_loop_exit/longjmp it is reset in cpu_exec */
        bql_unlock();
    }

    /* Finally, check if we need to exit to the main loop.  */
    if (unlikely(qatomic_read(&cpu->exit_request)) || icount_exit_request(cpu)) {
        qatomic_set(&cpu->exit_request, 0);
        if (cpu->exception_index == -1) {
            cpu->exception_index = EXCP_INTERRUPT;
        }
        return true;
    }

    return false;
}

static inline void cpu_loop_exec_tb(CPUState *cpu, TranslationBlock *tb,
                                    vaddr pc, TranslationBlock **last_tb,
                                    int *tb_exit)
{
    trace_exec_tb(tb, pc);
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
    /*
     * Diagnostic (#77): the main loop only runs REAL TBs; speculative wrong-path
     * TBs run via cpu_plugin_exec_tb/_inline.  If plugin_spec_mode is set here,
     * a WP excursion leaked spec mode into real execution (would make riscv
     * stimecmp writes bail -> timer death) -- a spec-mode escape.
     */
    if (unlikely(cpu->plugin_spec_mode) && getenv("CST_SPEC_ESCAPE_DIAG")) {
        fprintf(stderr, "[specescape] REAL tb exec with plugin_spec_mode=1 "
                "pc=0x%" PRIx64 "\n", (uint64_t)pc);
    }
#endif
    tb = cpu_tb_exec(cpu, tb, tb_exit);
    if (*tb_exit != TB_EXIT_REQUESTED) {
        *last_tb = tb;
        return;
    }

    *last_tb = NULL;
    if (cpu_loop_exit_requested(cpu)) {
        /* Something asked us to stop executing chained TBs; just
         * continue round the main loop. Whatever requested the exit
         * will also have set something else (eg exit_request or
         * interrupt_request) which will be handled by
         * cpu_handle_interrupt.  cpu_handle_interrupt will also
         * clear cpu->icount_decr.u16.high.
         */
        return;
    }

    /* Instruction counter expired.  */
    if (unlikely(cst_bq_on) && !icount_enabled()) {
        /*
         * Guest-insn slice bounding (event-agency discipline): the
         * mid-slice refill, mirroring the icount refill below MINUS all
         * timekeeping: no icount_update (no VIRTUAL-clock credit), no
         * icount_extra (the whole budget fits the u16), no deadline.
         * The chain is already broken (*last_tb = NULL above), and the
         * loop takes the normal cpu_handle_interrupt pass next
         * iteration -- the icount execution shape exactly.  icount's
         * shortened-TB regeneration (insns_left < tb->icount) is
         * structurally unreachable here: quantum >= 512 = TCG_MAX_INSNS
         * >= tb->icount, asserted.
         */
        cst_bq_note_breakout(cpu->neg.icount_decr.u16.low);
        g_assert(tb->icount <= cst_bq_quantum);
#if !defined(CONFIG_USER_ONLY)
        /*
         * Event-agency consumption (PRODUCT; see qemu/vclock-agency.h):
         * THE product consumption site -- every consumption happens at
         * a guest-insn slice breakout.  Predicate is the
         * intervention-proven one: a FRESH qemu_clock_deadline_ns_all(
         * VIRTUAL, ATTR_ALL) == 0 read (icount_handle_deadline's own
         * test), NOT a cached compare.  Site+predicate were proven by
         * the archival LX geometry (wave/locus 0/6) and replicated on
         * this lineage by the trigger-site wave (wave/proddr PTB 0/6,
         * VLX 0/6, vs dispatch-top P 6/6 and disarmed VOFF 6/6); the
         * dispatch-top site and its VIRTUAL_RT nudge are the disproven
         * geometry and were never landed.  The spec-mode skip lives
         * inside vclock_agency_consume.  Delivery lag is bounded in
         * GUEST-INSTRUCTION time by the slice quantum -- the quantum IS
         * the discipline's delivery bound, which is why the slice
         * bounding arms on the same plugin-install edge as the
         * discipline itself.  A per-excursion consumption site was
         * considered and rejected: it would run device callbacks from
         * inside the plugin's emit path (exec_lock held, fragment walk
         * in flight), where a callback-driven tb_flush is
         * reentrancy-unsafe.
         */
        if (vclock_agency_engaged() &&
            qemu_clock_deadline_ns_all(QEMU_CLOCK_VIRTUAL,
                                       QEMU_TIMER_ATTR_ALL) == 0) {
            vclock_agency_consume(cpu, true);
        }
#endif
        cpu->neg.icount_decr.u16.low = cst_bq_quantum;
        return;
    }
    assert(icount_enabled());
#ifndef CONFIG_USER_ONLY
    /* Ensure global icount has gone forward */
    icount_update(cpu);
    /* Refill decrementer and continue execution.  */
    int32_t insns_left = MIN(0xffff, cpu->icount_budget);
    cpu->neg.icount_decr.u16.low = insns_left;
    cpu->icount_extra = cpu->icount_budget - insns_left;

    /*
     * If the next tb has more instructions than we have left to
     * execute we need to ensure we find/generate a TB with exactly
     * insns_left instructions in it.
     */
    if (insns_left > 0 && insns_left < tb->icount)  {
        assert(insns_left <= CF_COUNT_MASK);
        assert(cpu->icount_extra == 0);
        cpu->cflags_next_tb = (tb->cflags & ~CF_COUNT_MASK) | insns_left;
    }
#endif
}

/* main execution loop */

/*
 * Guest-insn slice bounding posture guard, one-time.  Armed together
 * with -icount, two disciplines would write icount_decr.u16.low (and
 * the slice refill would shadow the real icount refill); armed in a
 * user-mode binary, the WP save/restore bracket (softmmu-only
 * cpu_plugin_spec_vtime_pause/_resume) does not exist.  The product
 * arming edge (plugins/system.c) can produce neither state -- it
 * declines under icount and is softmmu-only -- so this guard polices
 * the CST_BUDGET_QUANTUM override, and the invariant if the arming
 * edge ever changes.
 */
static void cst_bq_posture_check(void)
{
    static bool cst_bq_checked;

    if (cst_bq_checked) {
        return;
    }
    cst_bq_checked = true;
#ifdef CONFIG_USER_ONLY
    fprintf(stderr, "[CSTBQ] FATAL: guest-insn slice bounding is"
            " system-mode only (the WP excursion budget bracket is"
            " softmmu-only); refusing\n");
    abort();
#else
    if (icount_enabled()) {
        fprintf(stderr, "[CSTBQ] FATAL: guest-insn slice bounding and"
                " -icount are both armed; two writers of"
                " icount_decr.u16.low; refusing\n");
        abort();
    }
#endif
}

static int __attribute__((noinline))
cpu_exec_loop(CPUState *cpu, SyncClocks *sc)
{
    int ret;

    /*
     * Guest-insn slice bounding: the initial budget load, mirroring the
     * outer u16.low load icount does in icount_prepare_for_run
     * (tcg-accel-ops-icount.c) -- MINUS the deadline derivation (no
     * clock coupling, no deadline read).  Nothing else writes u16.low
     * on the default clock, so low==0 means "never seeded, or consumed
     * to exactly zero"; both want a fresh quantum.  Mid-slice
     * exhaustion reloads in cpu_loop_exec_tb, exactly where icount
     * refills.
     */
    if (unlikely(cst_bq_on)) {
        cst_bq_posture_check();
        if (cpu->neg.icount_decr.u16.low == 0) {
            cpu->neg.icount_decr.u16.low = cst_bq_quantum;
            cst_bq_note_seed();
        }
    }
#ifndef CONFIG_USER_ONLY
    /*
     * Event-agency posture (PRODUCT): an engaged exclusion whose
     * consumer is unreachable is a livelock shape, not a lookalike to
     * tolerate.  The product consumes ONLY at slice breakouts, so an
     * active discipline REQUIRES the slice bounding armed -- the
     * arming edge (plugins/system.c) arms both or neither, and this
     * guard is the invariant's tripwire, not a second decision point.
     */
    if (unlikely(qatomic_read(&vclock_agency_active)) && !cst_bq_on) {
        fprintf(stderr, "qemu: vclock-agency: FATAL: discipline active"
                " with guest-insn slice bounding unarmed -- the"
                " consumption site cannot be reached; the arming edge"
                " is broken\n");
        abort();
    }
#endif

    /* if an exception is pending, we execute it here */
    while (!cpu_handle_exception(cpu, &ret)) {
        TranslationBlock *last_tb = NULL;
        int tb_exit = 0;

        while (!cpu_handle_interrupt(cpu, &last_tb)) {
            TranslationBlock *tb;
            vaddr pc;
            uint64_t cs_base;
            uint32_t flags, cflags;

#ifdef CONFIG_PLUGIN
            /*
             * A code-buffer overflow during a plugin wrong-path walk deferred
             * its flush (see tb_gen_code): the walk has now unwound and its
             * host correct-path TB has finished executing, so we are at a safe
             * point with no TB in flight.  Honor the flush before translating
             * anything new, exactly as the in-line overflow path would.
             */
            if (unlikely(cpu->plugin_flush_pending)) {
                cpu->plugin_flush_pending = false;
                tb_flush(cpu);
                cpu->exception_index = EXCP_INTERRUPT;
                cpu_loop_exit(cpu);
            }
#endif

            cpu_get_tb_cpu_state(cpu_env(cpu), &pc, &cs_base, &flags);

#ifdef CONFIG_PLUGIN
            /*
             * End an asynchronous-interrupt excursion when execution returns
             * to the departure PC recorded on async entry (the interrupted
             * instruction) IN THE DEPARTED CONTEXT.  This generic resume
             * point is target-independent and robust to the scheduler
             * context-switching away during the handler and to nested
             * exceptions: the departure PC is not executed inside the
             * handler, only when its exception return lands back there.
             * Entry is flagged per-target in each <arch>_cpu_do_interrupt
             * via cpu_plugin_async_enter(); see cpu.h.
             *
             * The context test is the guest thread-pointer register, the
             * same register a tracer derives guest-thread identity from
             * (format.rst §4.2a keys the window's level on the delivering
             * THREAD).  Under SMP a PEER thread scheduled onto this vCPU
             * inside the window can execute the same VA; a bare PC equality
             * closed the window early then (measured: async_return_peer_ctx
             * = 2 in 1,919 windows).  A genuine resume cannot mismatch: the
             * departed thread executes NOTHING between departure and its
             * resume (the resume IS its next instruction), so its thread
             * pointer — context-switched state the kernel restores before
             * the exception return — compares equal exactly there.  When
             * the hook is absent both sides read 0 and this is the
             * historical bare PC equality.  A mismatch leaves the window
             * open for the owner's later return; if the owner never
             * returns, the tracer's abandoned-window recovery reaps the
             * flag at the next pinned user TB (both mute and capture
             * modes), exactly as it already does for a window whose
             * departure PC is never re-fetched at all.
             */
            if (unlikely(cpu->plugin_in_async_int) &&
                pc == cpu->plugin_async_departure_pc) {
                const TCGCPUOps *aret_ops = cpu->cc->tcg_ops;
                uint64_t cur_tp =
                    (aret_ops && aret_ops->get_plugin_thread_ptr)
                    ? aret_ops->get_plugin_thread_ptr(cpu)
                    : cpu->plugin_async_departure_tp;

                if (cur_tp == cpu->plugin_async_departure_tp) {
                    cpu_plugin_async_probe(cpu, "CLOSE", 0, false);
                    cpu->plugin_in_async_int = false;
                    cpu_plugin_evq_push(cpu,
                                        QEMU_PLUGIN_CPU_EVENT_ASYNC_RETURN,
                                        pc, cpu->plugin_fault_depth);
                } else {
                    cpu_plugin_async_probe(cpu, "PEERPC", 0, false);
                    /* Condition instrument (CST_ASYNCRET_DIAG): a peer
                     * context hit the departure PC and the close was
                     * withheld — the case the discriminator exists for. */
                    static int aret_diag = -1;
                    if (aret_diag < 0) {
                        aret_diag = getenv("CST_ASYNCRET_DIAG") != NULL;
                    }
                    if (aret_diag) {
                        fprintf(stderr, "[asyncret] peer-context hit "
                                "suppressed pc=0x%" PRIx64 " dep_tp=0x%"
                                PRIx64 " cur_tp=0x%" PRIx64 "\n",
                                (uint64_t)pc,
                                cpu->plugin_async_departure_tp, cur_tp);
                    }
                }
            }
#endif

            /*
             * When requested, use an exact setting for cflags for the next
             * execution.  This is used for icount, precise smc, and stop-
             * after-access watchpoints.  Since this request should never
             * have CF_INVALID set, -1 is a convenient invalid value that
             * does not require tcg headers for cpu_common_reset.
             */
            cflags = cpu->cflags_next_tb;
            if (cflags == -1) {
                cflags = curr_cflags(cpu);
            } else {
                cpu->cflags_next_tb = -1;
            }

#ifdef CONFIG_ORACLE
            cflags |= oracle_tb_cflags(pc);
#endif
            if (check_for_breakpoints(cpu, pc, &cflags)) {
                break;
            }

            tb = tb_lookup(cpu, pc, cs_base, flags, cflags);
            if (tb == NULL) {
                CPUJumpCache *jc;
                uint32_t h;

                mmap_lock();
                tb = tb_gen_code(cpu, pc, cs_base, flags, cflags);
                mmap_unlock();

                /*
                 * We add the TB in the virtual pc hash table
                 * for the fast lookup
                 */
                h = tb_jmp_cache_hash_func(pc);
                jc = cpu->tb_jmp_cache;
                jc->array[h].pc = pc;
                qatomic_set(&jc->array[h].tb, tb);
            }

#ifndef CONFIG_USER_ONLY
            /*
             * We don't take care of direct jumps when address mapping
             * changes in system emulation.  So it's not safe to make a
             * direct jump to a TB spanning two pages because the mapping
             * for the second page can change.
             */
            if (tb_page_addr1(tb) != -1) {
                last_tb = NULL;
            }
#endif
            /* See if we can patch the calling TB. */
#ifdef CONFIG_ORACLE
            if (last_tb && !oracle_tb_chain_ok(last_tb, tb)) {
                last_tb = NULL;
            }
#endif
            if (last_tb) {
                tb_add_jump(last_tb, tb_exit, tb);
            }

            cpu_loop_exec_tb(cpu, tb, pc, &last_tb, &tb_exit);

            /* Try to align the host and virtual clocks
               if the guest is in advance */
            align_clocks(sc, cpu);
        }
    }
    return ret;
}

static int cpu_exec_setjmp(CPUState *cpu, SyncClocks *sc)
{
    /* Prepare setjmp context for exception handling. */
    if (unlikely(sigsetjmp(cpu->jmp_env, 0) != 0)) {
        cpu_exec_longjmp_cleanup(cpu);
    }

    return cpu_exec_loop(cpu, sc);
}

int cpu_exec(CPUState *cpu)
{
    int ret;
    SyncClocks sc = { 0 };

    /* replay_interrupt may need current_cpu */
    current_cpu = cpu;

    if (cpu_handle_halt(cpu)) {
        return EXCP_HALTED;
    }

    RCU_READ_LOCK_GUARD();
    cpu_exec_enter(cpu);

    /*
     * Calculate difference between guest clock and host clock.
     * This delay includes the delay of the last cycle, so
     * what we have to do is sleep until it is 0. As for the
     * advance/delay we gain here, we try to fix it next time.
     */
    init_delay_params(&sc, cpu);

    ret = cpu_exec_setjmp(cpu, &sc);

    cpu_exec_exit(cpu);
    return ret;
}

bool tcg_exec_realizefn(CPUState *cpu, Error **errp)
{
    static bool tcg_target_initialized;

    if (!tcg_target_initialized) {
        /* Check mandatory TCGCPUOps handlers */
        const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;
#ifndef CONFIG_USER_ONLY
        assert(tcg_ops->cpu_exec_halt);
        assert(tcg_ops->cpu_exec_interrupt);
#endif /* !CONFIG_USER_ONLY */
        assert(tcg_ops->translate_code);
        tcg_ops->initialize();
        tcg_target_initialized = true;
#ifdef CONFIG_ORACLE
        /*
         * The target has just registered its architectural registers as TCG
         * globals, so this is the first moment the offset -> register map
         * exists.  sizeof(CPUArchState) is only real in per-target code,
         * which this file is.
         */
        oracle_init(sizeof(CPUArchState), TARGET_NAME);
#endif
    }

    cpu->tb_jmp_cache = g_new0(CPUJumpCache, 1);
    tlb_init(cpu);
#ifndef CONFIG_USER_ONLY
    tcg_iommu_init_notifier_list(cpu);
#endif /* !CONFIG_USER_ONLY */
    /* qemu_plugin_vcpu_init_hook delayed until cpu_index assigned. */

    return true;
}

/* undo the initializations in reverse order */
void tcg_exec_unrealizefn(CPUState *cpu)
{
#ifndef CONFIG_USER_ONLY
    tcg_iommu_free_notifier_list(cpu);
#endif /* !CONFIG_USER_ONLY */

    tlb_destroy(cpu);
    g_free_rcu(cpu->tb_jmp_cache, rcu);
}
