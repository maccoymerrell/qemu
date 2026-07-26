/*
 * TCG CPU-specific operations
 *
 * Copyright 2021 SUSE LLC
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef TCG_CPU_OPS_H
#define TCG_CPU_OPS_H

#include "exec/breakpoint.h"
#include "exec/cpu-common.h"
#include "exec/hwaddr.h"
#include "exec/memattrs.h"
#include "exec/memop.h"
#include "exec/mmu-access-type.h"
#include "exec/vaddr.h"

struct TCGCPUOps {
    /**
     * @initialize: Initialize TCG state
     *
     * Called when the first CPU is realized.
     */
    void (*initialize)(void);
    /**
     * @translate_code: Translate guest instructions to TCGOps
     * @cpu: cpu context
     * @tb: translation block
     * @max_insns: max number of instructions to translate
     * @pc: guest virtual program counter address
     * @host_pc: host physical program counter address
     *
     * This function must be provided by the target, which should create
     * the target-specific DisasContext, and then invoke translator_loop.
     */
    void (*translate_code)(CPUState *cpu, TranslationBlock *tb,
                           int *max_insns, vaddr pc, void *host_pc);
    /**
     * @synchronize_from_tb: Synchronize state from a TCG #TranslationBlock
     *
     * This is called when we abandon execution of a TB before starting it,
     * and must set all parts of the CPU state which the previous TB in the
     * chain may not have updated.
     * By default, when this is NULL, a call is made to @set_pc(tb->pc).
     *
     * If more state needs to be restored, the target must implement a
     * function to restore all the state, and register it here.
     */
    void (*synchronize_from_tb)(CPUState *cpu, const TranslationBlock *tb);
    /**
     * @restore_state_to_opc: Synchronize state from INDEX_op_start_insn
     *
     * This is called when we unwind state in the middle of a TB,
     * usually before raising an exception.  Set all part of the CPU
     * state which are tracked insn-by-insn in the target-specific
     * arguments to start_insn, passed as @data.
     */
    void (*restore_state_to_opc)(CPUState *cpu, const TranslationBlock *tb,
                                 const uint64_t *data);

    /** @cpu_exec_enter: Callback for cpu_exec preparation */
    void (*cpu_exec_enter)(CPUState *cpu);
    /** @cpu_exec_exit: Callback for cpu_exec cleanup */
    void (*cpu_exec_exit)(CPUState *cpu);
    /** @debug_excp_handler: Callback for handling debug exceptions */
    void (*debug_excp_handler)(CPUState *cpu);

#ifdef CONFIG_PLUGIN
    /**
     * @get_plugin_state: report current privilege + address space to plugins
     *
     * Optional.  Fills @priv with a normalized privilege ordinal
     * (0 = user / least privileged, larger = more privileged) and @asid with
     * the current address-space identifier (x86 CR3, RISC-V SATP, Arm TTBR,
     * MIPS ASID).  Lets a plugin filter by process / privilege in system
     * mode (and read priv=0 in user mode); see qemu_plugin_get_priv_level()
     * and qemu_plugin_get_addr_space_id().
     *
     * Also fills @mmu_on with whether the guest's MMU / paging is currently
     * enabled (x86 CR0.PG, Arm SCTLR.M, RISC-V SATP!=Bare; MIPS always has a
     * TLB so reports true).  A plugin's speculative (wrong-path) execution
     * relies on the MMU to fault on fetches into non-code; with paging off
     * there is no such bound, so the plugin must not speculate.  See
     * qemu_plugin_paging_enabled().
     */
    void (*get_plugin_state)(CPUState *cpu, int *priv, uint64_t *asid,
                             bool *mmu_on);

    /**
     * @get_plugin_thread_ptr: report the guest thread-pointer register
     *
     * Optional.  Returns the architectural per-thread pointer the
     * guest kernel context-switches per software thread (x86_64
     * FS.base — GS.base for a 32-bit compat task — AArch64 TPIDR_EL0,
     * RISC-V tp/x4, MIPS CP0 UserLocal).  Meaningful when sampled at
     * user privilege; see qemu_plugin_get_thread_ptr().
     */
    uint64_t (*get_plugin_thread_ptr)(CPUState *cpu);

    /**
     * @plugin_thread_ptr_tracks_current: the thread pointer also names the
     * current task at privileged level
     *
     * Set when the register @get_plugin_thread_ptr reports keeps naming the
     * software thread the vCPU is executing even above user privilege, so a
     * sample taken inside the kernel identifies the task that is CURRENT
     * rather than the one that last ran in user mode.  True where the
     * register is architecturally separate from anything the kernel needs
     * for its own use and every mainstream kernel therefore reloads it from
     * the incoming task at each context switch, leaving it untouched in
     * between (MIPS CP0 UserLocal, AArch64 TPIDR_EL0, x86-64 FS.base).
     * False where the kernel repurposes the register for itself on entry —
     * RISC-V swaps tp with sscratch so it holds the kernel's own per-task
     * pointer, a different value space from the user thread pointer, which
     * would split one thread's user and kernel code across two identities.
     *
     * Only meaningful alongside @get_plugin_thread_ptr; see
     * qemu_plugin_thread_ptr_tracks_current().
     */
    bool plugin_thread_ptr_tracks_current;

    /**
     * @vaddr_is_kernel: classify a code virtual address's privilege domain
     *
     * Optional.  Returns true when @vaddr lies in the guest's KERNEL
     * (privileged/supervisor) code region, false when it lies in the USER
     * region, as determined by the target's own MMU / segment logic — the
     * canonical/TTBR/sign-extension range the walker selects on, or the
     * fixed-segment map (MIPS kuseg vs kseg).  This is a pure architectural
     * range/bit test on the address; it does no page-table walk and cannot
     * fault, so a plugin can call it on a speculatively-fetched wrong-path
     * address safely.  Kernel and user virtual-address ranges are
     * architecturally disjoint, so the classification does not depend on the
     * current privilege level (which a wrong-path walk can mis-observe).
     * Lets a plugin partition kernel from user code, seed a kernel/user bit
     * without trusting a speculated privilege level, and detect a
     * privilege-domain crossing on a control transfer.  Read priv=0 targets
     * (user-mode QEMU) do not register this hook, so the API reports "user".
     */
    bool (*vaddr_is_kernel)(CPUState *cpu, uint64_t vaddr);

    /**
     * @spec_clock_resync: reconcile every guest clock with the frozen time
     *
     * Optional; system-mode targets only.  Called at the end of a plugin
     * clock freeze, once the virtual clock has been thawed and (for a
     * wrong-path excursion) the speculative register state has been rolled
     * back.  @reason says which of the two freezes ended.
     *
     * The contract is a single sentence: ON RETURN, EVERY ARCHITECTURAL
     * CLOCK OR COUNTER THE GUEST CAN OBSERVE, AND EVERY ARMED HOST
     * QEMUTimer BACKING ONE, MUST BE CONSISTENT WITH THE FROZEN VIRTUAL
     * TIME -- as if the freeze had consumed exactly zero guest time.  The
     * frozen clock is authoritative: an implementation resyncs the SOURCES
     * to it, never the other way round.  Concretely, for each time source
     * the target exposes, an implementation must
     *
     *   - re-derive the architectural counter (Arm CNTVCT/CNTPCT, x86 TSC,
     *     RISC-V time, MIPS CP0_Count) from the frozen virtual clock, so a
     *     counter that free-runs off a different host source cannot drift
     *     across the freeze;
     *   - re-arm every host QEMUTimer from the (restored) architectural
     *     compare register, so a compare rolled back by the excursion, or a
     *     one-shot host timer that fired and was suppressed during it,
     *     cannot leave the timer parked and never firing again;
     *   - re-deliver any interrupt whose raise the excursion suppressed, and
     *     re-derive the CPU interrupt-request line from the restored
     *     architectural pending state (Arm irq_line_state, RISC-V mip, MIPS
     *     CP0_Cause.IP), so line and register cannot disagree.
     *
     * Called with the BQL held and with plugin spec mode already ended, so
     * an implementation may drive IRQ lines directly.  It must be
     * idempotent: it runs on every excursion exit, including ones that
     * perturbed nothing.
     *
     * Registering this hook is how a system-mode target opts in to
     * wrong-path (speculative) plugin execution being time-transparent.  A
     * target that does not register it will silently accumulate clock skew
     * across excursions; see docs/devel/tcg-plugins.rst.
     */
    void (*spec_clock_resync)(CPUState *cpu, SpecClockResyncReason reason);
#endif

#ifdef CONFIG_USER_ONLY
    /**
     * @fake_user_interrupt: Callback for 'fake exception' handling.
     *
     * Simulate 'fake exception' which will be handled outside the
     * cpu execution loop (hack for x86 user mode).
     */
    void (*fake_user_interrupt)(CPUState *cpu);

    /**
     * record_sigsegv:
     * @cpu: cpu context
     * @addr: faulting guest address
     * @access_type: access was read/write/execute
     * @maperr: true for invalid page, false for permission fault
     * @ra: host pc for unwinding
     *
     * We are about to raise SIGSEGV with si_code set for @maperr,
     * and si_addr set for @addr.  Record anything further needed
     * for the signal ucontext_t.
     *
     * If the emulated kernel does not provide anything to the signal
     * handler with anything besides the user context registers, and
     * the siginfo_t, then this hook need do nothing and may be omitted.
     * Otherwise, record the data and return; the caller will raise
     * the signal, unwind the cpu state, and return to the main loop.
     *
     * If it is simpler to re-use the sysemu tlb_fill code, @ra is provided
     * so that a "normal" cpu exception can be raised.  In this case,
     * the signal must be raised by the architecture cpu_loop.
     */
    void (*record_sigsegv)(CPUState *cpu, vaddr addr,
                           MMUAccessType access_type,
                           bool maperr, uintptr_t ra);
    /**
     * record_sigbus:
     * @cpu: cpu context
     * @addr: misaligned guest address
     * @access_type: access was read/write/execute
     * @ra: host pc for unwinding
     *
     * We are about to raise SIGBUS with si_code BUS_ADRALN,
     * and si_addr set for @addr.  Record anything further needed
     * for the signal ucontext_t.
     *
     * If the emulated kernel does not provide the signal handler with
     * anything besides the user context registers, and the siginfo_t,
     * then this hook need do nothing and may be omitted.
     * Otherwise, record the data and return; the caller will raise
     * the signal, unwind the cpu state, and return to the main loop.
     *
     * If it is simpler to re-use the sysemu do_unaligned_access code,
     * @ra is provided so that a "normal" cpu exception can be raised.
     * In this case, the signal must be raised by the architecture cpu_loop.
     */
    void (*record_sigbus)(CPUState *cpu, vaddr addr,
                          MMUAccessType access_type, uintptr_t ra);
#else
    /** @do_interrupt: Callback for interrupt handling.  */
    void (*do_interrupt)(CPUState *cpu);
    /** @cpu_exec_interrupt: Callback for processing interrupts in cpu_exec */
    bool (*cpu_exec_interrupt)(CPUState *cpu, int interrupt_request);
    /**
     * @cpu_exec_halt: Callback for handling halt in cpu_exec.
     *
     * The target CPU should do any special processing here that it needs
     * to do when the CPU is in the halted state.
     *
     * Return true to indicate that the CPU should now leave halt, false
     * if it should remain in the halted state. (This should generally
     * be the same value that cpu_has_work() would return.)
     *
     * This method must be provided. If the target does not need to
     * do anything special for halt, the same function used for its
     * SysemuCPUOps::has_work method can be used here, as they have the
     * same function signature.
     */
    bool (*cpu_exec_halt)(CPUState *cpu);
    /**
     * @tlb_fill_align: Handle a softmmu tlb miss
     * @cpu: cpu context
     * @out: output page properties
     * @addr: virtual address
     * @access_type: read, write or execute
     * @mmu_idx: mmu context
     * @memop: memory operation for the access
     * @size: memory access size, or 0 for whole page
     * @probe: test only, no fault
     * @ra: host return address for exception unwind
     *
     * If the access is valid, fill in @out and return true.
     * Otherwise if probe is true, return false.
     * Otherwise raise an exception and do not return.
     *
     * The alignment check for the access is deferred to this hook,
     * so that the target can determine the priority of any alignment
     * fault with respect to other potential faults from paging.
     * Zero may be passed for @memop to skip any alignment check
     * for non-memory-access operations such as probing.
     */
    bool (*tlb_fill_align)(CPUState *cpu, CPUTLBEntryFull *out, vaddr addr,
                           MMUAccessType access_type, int mmu_idx,
                           MemOp memop, int size, bool probe, uintptr_t ra);
    /**
     * @tlb_fill: Handle a softmmu tlb miss
     *
     * If the access is valid, call tlb_set_page and return true;
     * if the access is invalid and probe is true, return false;
     * otherwise raise an exception and do not return.
     */
    bool (*tlb_fill)(CPUState *cpu, vaddr address, int size,
                     MMUAccessType access_type, int mmu_idx,
                     bool probe, uintptr_t retaddr);
    /**
     * @do_transaction_failed: Callback for handling failed memory transactions
     * (ie bus faults or external aborts; not MMU faults)
     */
    void (*do_transaction_failed)(CPUState *cpu, hwaddr physaddr, vaddr addr,
                                  unsigned size, MMUAccessType access_type,
                                  int mmu_idx, MemTxAttrs attrs,
                                  MemTxResult response, uintptr_t retaddr);
    /**
     * @do_unaligned_access: Callback for unaligned access handling
     * The callback must exit via raising an exception.
     */
    G_NORETURN void (*do_unaligned_access)(CPUState *cpu, vaddr addr,
                                           MMUAccessType access_type,
                                           int mmu_idx, uintptr_t retaddr);

    /**
     * @adjust_watchpoint_address: hack for cpu_check_watchpoint used by ARM
     */
    vaddr (*adjust_watchpoint_address)(CPUState *cpu, vaddr addr, int len);

    /**
     * @debug_check_watchpoint: return true if the architectural
     * watchpoint whose address has matched should really fire, used by ARM
     * and RISC-V
     */
    bool (*debug_check_watchpoint)(CPUState *cpu, CPUWatchpoint *wp);

    /**
     * @debug_check_breakpoint: return true if the architectural
     * breakpoint whose PC has matched should really fire.
     */
    bool (*debug_check_breakpoint)(CPUState *cpu);

    /**
     * @io_recompile_replay_branch: Callback for cpu_io_recompile.
     *
     * The cpu has been stopped, and cpu_restore_state_from_tb has been
     * called.  If the faulting instruction is in a delay slot, and the
     * target architecture requires re-execution of the branch, then
     * adjust the cpu state as required and return true.
     */
    bool (*io_recompile_replay_branch)(CPUState *cpu,
                                       const TranslationBlock *tb);
    /**
     * @need_replay_interrupt: Return %true if @interrupt_request
     * needs to be recorded for replay purposes.
     */
    bool (*need_replay_interrupt)(int interrupt_request);
#endif /* !CONFIG_USER_ONLY */
};

#if defined(CONFIG_USER_ONLY)

static inline void cpu_check_watchpoint(CPUState *cpu, vaddr addr, vaddr len,
                                        MemTxAttrs atr, int fl, uintptr_t ra)
{
}

static inline int cpu_watchpoint_address_matches(CPUState *cpu,
                                                 vaddr addr, vaddr len)
{
    return 0;
}

#else

/**
 * cpu_check_watchpoint:
 * @cpu: cpu context
 * @addr: guest virtual address
 * @len: access length
 * @attrs: memory access attributes
 * @flags: watchpoint access type
 * @ra: unwind return address
 *
 * Check for a watchpoint hit in [addr, addr+len) of the type
 * specified by @flags.  Exit via exception with a hit.
 */
void cpu_check_watchpoint(CPUState *cpu, vaddr addr, vaddr len,
                          MemTxAttrs attrs, int flags, uintptr_t ra);

/**
 * cpu_watchpoint_address_matches:
 * @cpu: cpu context
 * @addr: guest virtual address
 * @len: access length
 *
 * Return the watchpoint flags that apply to [addr, addr+len).
 * If no watchpoint is registered for the range, the result is 0.
 */
int cpu_watchpoint_address_matches(CPUState *cpu, vaddr addr, vaddr len);

#endif

#endif /* TCG_CPU_OPS_H */
