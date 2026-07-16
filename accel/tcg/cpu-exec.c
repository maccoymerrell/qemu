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
#include "exec/replay-core.h"
#include "system/tcg.h"
#include "exec/helper-proto-common.h"
#include "qemu/qemu-plugin.h"
#include "tb-jmp-cache.h"
#include "tb-hash.h"
#include "tb-context.h"
#include "tb-internal.h"
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
    if (check_for_breakpoints(cpu, pc, &cflags)) {
        cpu_loop_exit(cpu);
    }

    tb = tb_lookup(cpu, pc, cs_base, flags, cflags);
    if (tb == NULL) {
        return tcg_code_gen_epilogue;
    }

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
     * then livelocks: the aarch64 system-mode storm.  Detect any such rollback
     * here and flag a resync (below) to re-arm the host timer to match the
     * restored registers.  This is NOT covered by the spec-gate dirty flag,
     * because the desyncing gt_recalc_timer ran with spec mode closed.
     */
    {
        const CPUARMState *s = (const CPUARMState *)saved;
        for (int i = 0; i < NUM_GTIMERS; i++) {
            if (env->cp15.c14_timer[i].ctl != s->cp15.c14_timer[i].ctl ||
                env->cp15.c14_timer[i].cval != s->cp15.c14_timer[i].cval) {
                current_cpu->plugin_spec_timer_dirty = true;
                break;
            }
        }
    }
#endif
    memcpy(env, saved, size);
    memcpy(env->cpu_breakpoint, bp_save, sizeof(bp_save));
    memcpy(env->cpu_watchpoint, wp_save, sizeof(wp_save));
    /*
     * Timer resync deferred to cpu_plugin_spec_vtime_resume (true excursion
     * exit) -- see the riscv branch / #77.  Running it at this restore would
     * fire at an intermediate fault-skip restore too.
     */
#elif defined(TARGET_RISCV)
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
    /*
     * The Sstc supervisor/VS host timers (env->stimer/vstimer) live outside
     * this register snapshot.  If the restore rolls back the architected
     * compare register (stimecmp/vstimecmp), the host QEMUTimer is left armed
     * for the speculative deadline while the register says otherwise -- re-sync
     * so a rolled-back compare can't leave the host timer stale (the ARM storm
     * class: architected timer register desynced from the host timer).
     *
     * Only compare fields that are actually inside the snapshot (i.e. before
     * end_reset_fields): stimecmp/vstimecmp qualify.  vstime_irq, stimer and
     * vstimer all sit AFTER end_reset_fields, so they are neither saved nor
     * rolled back -- reading them through `s` would index past the saved
     * buffer.
     */
    {
        const CPURISCVState *s = (const CPURISCVState *)saved;
        if (env->stimecmp != s->stimecmp || env->vstimecmp != s->vstimecmp) {
            current_cpu->plugin_spec_timer_dirty = true;
        }
        /*
         * A timer-pending bit that materialised in the LIVE env->mip after
         * the snapshot was taken is about to be erased by the memcpy below.
         * This happens when a host timer cb (ACLINT mtimer -> MTIP, Sstc
         * stimer/vstimer -> STIP/VSTIP; iothread, under BQL) fires in the
         * race window at excursion ENTRY: the snapshot is already taken but
         * the spec/vtime flags are not yet visible to the cb's thread, so
         * the cb-side deferral gates cannot catch it (the freezing fire
         * observably logs spec=0 vtp=0).  The one-shot host timer has
         * already fired and will not re-arm itself, so the erased raise
         * would be lost forever — the machine-timer park that freezes an
         * SBI-timer (sstc=false) guest at its next nanosleep tick.  Flag
         * the excursion dirty; the exit resync re-derives the level + host
         * deadline from the compare registers, which this restore does not
         * damage (mtimecmp is device state; stimecmp/vstimecmp revert to
         * their correct-path values).
         */
        if ((env->mip & ~s->mip) & (MIP_MTIP | MIP_STIP | MIP_VSTIP)) {
            current_cpu->plugin_spec_timer_dirty = true;
        }
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
#endif
    }
    /*
     * Pure rollback: WP is fully transparent to the correct path, so env->mip
     * (interrupt-pending) is reverted to its pre-excursion value -- interrupts
     * remain untouched and unhandled by WP.  A timer that fired during the
     * excursion is deferred by the timer-cb gate (plugin_spec_timer_dirty) and
     * re-asserted by riscv_cpu_plugin_resync_timers at vtime_resume; it is not
     * carried forward here (that force-carry perturbed interrupt-delivery
     * timing across the merge, #77).
     */
    memcpy(env, saved, size);
    /*
     * Timer resync is deferred to cpu_plugin_spec_vtime_resume (the true
     * excursion-exit boundary).  Running it here would fire at an intermediate
     * wrong-path fault-skip restore (spec_mode_end -> restore -> spec_mode_begin),
     * consuming plugin_spec_timer_dirty and synthesising STIP that the FINAL
     * wp_end restore then clobbers with the stale snapshot -- losing the timer
     * IRQ and livelocking the guest (#77).
     */
#else
    memcpy(env, saved, size);
#endif
#elif defined(TARGET_MIPS)
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
    /*
     * The R4K host timer (env->timer) lives outside this register snapshot.
     * If the restore rolls back CP0_Count/Compare, re-arm it so a rolled-back
     * compare can't leave it stale (the ARM storm class).
     */
    {
        const CPUMIPSState *s = (const CPUMIPSState *)saved;
        if (env->CP0_Count != s->CP0_Count ||
            env->CP0_Compare != s->CP0_Compare) {
            current_cpu->plugin_spec_timer_dirty = true;
        }
        /*
         * Cause.TI materialised in the LIVE env after the snapshot was
         * taken: the R4K timer expired in the race window at excursion
         * ENTRY (snapshot taken, spec/vtime flags not yet visible to the
         * iothread), so the gate in cpu_mips_timer_expire could not defer
         * it.  The memcpy below erases the pending TI/IP while the host
         * QEMUTimer has already been re-armed a full Count wrap out — the
         * tick would be lost.  Mark it as a deferred expiry so
         * mips_cpu_plugin_resync_timers re-delivers it at excursion exit
         * (mirror of the riscv mip-rollback detection).  Pre-R2 CPUs have
         * no Cause.TI to key on; only the in-excursion cb gate covers them.
         */
        if ((env->insn_flags & ISA_MIPS_R2) &&
            ((env->CP0_Cause & ~s->CP0_Cause) & (1 << CP0Ca_TI))) {
            current_cpu->plugin_spec_timer_dirty = true;
            env->plugin_spec_timer_expired = true;
        }
    }
    memcpy(env, saved, size);
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
static bool     g_wp_bql_held = false;  /* #77 test: BQL held across excursion */
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
static uint8_t g_sdiff_cpu[SDIFF_CPU_SZ];
static uint8_t g_sdiff_env[SDIFF_ENV_SZ];
static uint8_t g_sdiff_cpu_seen[SDIFF_CPU_SZ];
static uint8_t g_sdiff_env_seen[SDIFF_ENV_SZ];
static bool    g_sdiff_have = false;
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

static const char *sdiff_cpu_field(size_t off)
{
    if (off == offsetof(CPUState, interrupt_request)) return "interrupt_request";
    if (off == offsetof(CPUState, cflags_next_tb))     return "cflags_next_tb";
    if (off == offsetof(CPUState, exit_request))       return "exit_request";
    if (off >= offsetof(CPUState, plugin_spec_tlb_log) &&
        off <  offsetof(CPUState, neg)) {
        return "(plugin_spec_tlb_log/plugin block - intentional)";
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
static bool cst_nofreeze(void)   /* cached: called on every excursion */
{
    static int v = -1;
    if (v < 0) {
        v = getenv("CST_NOFREEZE") != NULL;
    }
    return v;
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

#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY) && defined(TARGET_I386)
/*
 * Re-lock the guest TSC to QEMU_CLOCK_VIRTUAL after every wrong-path excursion.
 *
 * The guest TSC is derived from the host rdtsc (cpu_get_host_ticks) and the
 * guest HPET/LAPIC clock from host CLOCK_MONOTONIC (get_clock).  Those two host
 * oscillators do not keep a constant ratio across the excursion windows vs the
 * correct-path windows (TSC read jitter across host-core migration, P-state
 * effects), so however balanced the per-excursion freeze is, the guest TSC and
 * guest HPET diverge by a growing skew (measured ~38ns/excursion -> hundreds of
 * ms) and the guest's clocksource watchdog marks the TSC unstable, wedging
 * timekeeping/RCU (the x86 system-mode livelock).
 *
 * Fix: force guest_TSC == ref_tsc + tsc_hz * (guest_clock - ref_clock) at each
 * resume, so the two guest clocksources are locked by construction and cannot
 * skew — regardless of the host clocks' relationship.  tsc_hz is self-
 * calibrated once from the host rdtsc/monotonic ratio over the first stretch of
 * correct-path execution (both host clocks measured over the SAME real
 * intervals), then frozen so the lock slope never moves.  x86-only: other ISAs
 * read one guest clock family (arm CNTVCT, riscv time, mips Count) reconciled by
 * their per-target timer resync, so they have no two-clock split to lock.
 */
static __thread int64_t g_pin_cp_tsc, g_pin_cp_ns;      /* CP calibration sums */
static __thread int64_t g_pin_last_ht, g_pin_last_hm;   /* host tsc/mono @ resume */
static __thread double  g_pin_tsc_hz;                   /* frozen once calibrated */
static __thread int64_t g_pin_ref_tsc, g_pin_ref_clk;   /* lock reference point */
static __thread bool    g_pin_ready;

static void cst_pin_note_pause(void)
{
    int64_t ht = cpu_get_host_ticks();
    int64_t hm = get_clock();
    if (g_pin_last_hm) {                 /* accumulate the correct-path interval */
        g_pin_cp_tsc += ht - g_pin_last_ht;
        g_pin_cp_ns  += hm - g_pin_last_hm;
    }
}

static void cst_pin_tsc_to_clock(void)
{
    if (!g_pin_ready) {
        /* Calibrate over ~0.2s of correct-path host time, then freeze the
         * ratio and anchor the lock at the current (still-unskewed) values. */
        if (g_pin_cp_ns >= 200 * 1000 * 1000) {
            g_pin_tsc_hz  = (double)g_pin_cp_tsc / (double)g_pin_cp_ns * 1e9;
            g_pin_ref_tsc = cpu_get_ticks();
            g_pin_ref_clk = cpu_get_clock();
            g_pin_ready   = true;
        }
    } else {
        int64_t target = g_pin_ref_tsc +
            (int64_t)(g_pin_tsc_hz * (double)(cpu_get_clock() - g_pin_ref_clk)
                      / 1e9);
        cpu_plugin_pin_tsc(target);
    }
    g_pin_last_ht = cpu_get_host_ticks();
    g_pin_last_hm = get_clock();
}
#endif

/*
 * Wrong-path containment helpers with softmmu-only side effects.  Compiled
 * per-target so CONFIG_USER_ONLY selects the no-op forms; the common
 * plugins/api.c calls these rather than referencing tlb_flush /
 * cpu_disable_ticks directly (which are not linked into user-mode binaries).
 */
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
#ifdef CONFIG_PLUGIN
    static int no_vtpause = -1;    /* cache: getenv per excursion is a hot path */
    if (no_vtpause < 0) {
        no_vtpause = getenv("CST_NO_VTPAUSE") != NULL;
    }
    if (no_vtpause) {                 /* #77 test: don't freeze guest clock in WP */
        return;
    }
#endif
    bool need_bql = !bql_locked();
    if (need_bql) {
        bql_lock();
    }
#ifdef CONFIG_PLUGIN
    cst_clkprobe(false);              /* #80: skew measurement (gated) */
#if defined(TARGET_I386)
    cst_pin_note_pause();             /* #80: accumulate correct-path calibration */
#endif
    /* #77 test: keep the excursion flag + resync, but DON'T freeze the guest
     * virtual clock during WP (lets the stimer deadline still be reached in a
     * WP-saturated spin).  Distinguishes timer-freeze starvation from a leak. */
    if (!cst_nofreeze())
#endif
    cpu_disable_ticks();
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
     * guest virtual clock (cpu_disable_ticks above), but that freeze is a
     * VM-global boolean+offset, not per-vCPU: x86 delivers speculative page
     * faults extremely often, so the abnormal-longjmp / fault-skip spec_mode
     * re-entry cycling runs far more than on other ISAs and can leave the
     * disable/enable unbalanced, desyncing cpu_clock_offset from
     * cpu_ticks_offset.  The guest's TSC-vs-HPET clocksource watchdog then
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
     * wpdepth; the excursion never blocks on the iothread, so no deadlock.
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
     * Re-enable ticks only if the VM is still running.  do_vm_stop() calls
     * cpu_disable_ticks() BEFORE pausing vcpus (system/cpus.c), so a QMP
     * vm_stop landing during this excursion leaves ticks disabled and owns
     * that state; blindly re-enabling here would advance the guest clock while
     * the VM is meant to be stopped.  vm_start()'s cpu_enable_ticks() restores
     * ticks when the VM resumes.  (cpu_disable_ticks/enable_ticks is a single
     * global boolean, not a refcount, so the plugin pause must not fight the
     * vm_stop owner.)
     */
    if (runstate_is_running()
#ifdef CONFIG_PLUGIN
        && !cst_nofreeze()   /* #77 test: never disabled ticks; don't re-enable */
#endif
        && cpu->plugin_vclock_depth == 0  /* callback freeze still active */
        ) {
        cpu_enable_ticks();
#if defined(CONFIG_PLUGIN) && defined(TARGET_I386)
        cst_pin_tsc_to_clock();   /* #80: re-lock guest TSC to QEMU_CLOCK_VIRTUAL */
#endif
    }
    cpu->plugin_spec_vtime_paused = false;
#ifdef CONFIG_PLUGIN
    cst_clkprobe(true);            /* #80: skew measurement (gated) */
    if (g_wprot_active) {          /* #77: restore guest RAM to read-write */
        wprot_setprot(PROT_READ | PROT_WRITE);
        g_wprot_active = false;
    }
    tlbsave_restore(cpu);         /* #77: revert full TLB (causation test) */
    sdiff_compare(cpu);           /* #77: detect un-restored CPU-state leak */
#endif
    /*
     * Reconcile the host QEMUTimers with the restored registers HERE -- the true
     * excursion-exit boundary -- not inside cpu_plugin_arch_state_restore.  A
     * wrong-path fault-skip does an intermediate cpu_state_restore mid-excursion
     * (spec_mode_end -> restore -> spec_mode_begin) without resuming vtime; doing
     * the resync at every restore would consume plugin_spec_timer_dirty there and
     * synthesise a pending timer IRQ (e.g. riscv STIP) that the FINAL wp_end
     * restore then clobbers with the stale snapshot, losing the timer event and
     * livelocking the guest (#77).  Deferring to vtime_resume lets the dirty flag
     * survive intermediate restores so the resync runs once against the final
     * state, after ticks are re-enabled and with spec mode already ended.
     */
#if defined(CONFIG_PLUGIN)
#if defined(TARGET_RISCV)
    riscv_cpu_plugin_resync_timers(cpu);
#elif defined(TARGET_ARM)
    arm_cpu_plugin_resync_timers(cpu);
#elif defined(TARGET_MIPS)
    mips_cpu_plugin_resync_timers(cpu);
#endif
#ifdef CONFIG_PLUGIN
    /* #77 test: the WP-saturated vCPU starves the main loop's QEMU_CLOCK_VIRTUAL
     * timer processing, so the guest stimer never fires -> tick death.  Process
     * expired virtual timers in-thread here (as -icount does at insn boundaries)
     * under the BQL we already hold, so the deferred tick is delivered. */
    if (getenv("CST_RUNTIMERS")) {
        qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL);
    }
#endif
#endif
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
 * Nesting (plugin_vclock_depth) lets callers wrap arbitrary regions without
 * coordinating; composition with the WP pause is by "ticks re-enable only
 * when both mechanisms have fully resumed".  The vm_stop guard mirrors
 * cpu_plugin_spec_vtime_resume: never re-enable a clock a vm_stop owns.
 */
void cpu_plugin_vclock_pause(CPUState *cpu)
{
#ifndef CONFIG_USER_ONLY
    if (cpu->plugin_vclock_depth++ > 0 || cpu->plugin_spec_vtime_paused) {
        return;                    /* already frozen */
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
    cpu_disable_ticks();
    if (need_bql) {
        bql_unlock();
    }
#endif
}

void cpu_plugin_vclock_resume(CPUState *cpu)
{
#ifndef CONFIG_USER_ONLY
    g_assert(cpu->plugin_vclock_depth > 0);
    if (--cpu->plugin_vclock_depth > 0 || cpu->plugin_spec_vtime_paused) {
        return;                    /* still frozen by an outer window / WP */
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
    if (runstate_is_running()) {
        cpu_enable_ticks();
#if defined(CONFIG_PLUGIN) && defined(TARGET_I386)
        cst_pin_tsc_to_clock();   /* #80: re-lock guest TSC to the virtual clock */
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
        for (uint16_t i = 0; i < cpu->plugin_spec_tlb_log_n; i++) {
            tlb_flush_page_by_mmuidx(cpu, cpu->plugin_spec_tlb_log[i].page,
                                     1 << cpu->plugin_spec_tlb_log[i].mmu_idx);
        }
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

static int __attribute__((noinline))
cpu_exec_loop(CPUState *cpu, SyncClocks *sc)
{
    int ret;

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
             * instruction).  This generic resume point is target-independent
             * and robust to the scheduler context-switching away during the
             * handler and to nested exceptions: the departure PC is not
             * executed inside the handler, only when its exception return
             * lands back there.  Entry is flagged per-target in each
             * <arch>_cpu_do_interrupt; see cpu.h.
             */
            if (unlikely(cpu->plugin_in_async_int) &&
                pc == cpu->plugin_async_departure_pc) {
                cpu->plugin_in_async_int = false;
                cpu_plugin_evq_push(cpu, QEMU_PLUGIN_CPU_EVENT_ASYNC_RETURN,
                                    pc, cpu->plugin_fault_depth);
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
