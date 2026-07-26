QEMU base modifications
=======================

The ChampSim Tracer plugin is more than a self-contained ``.so``: it
relies on additions to QEMU's plugin API and on a handful of changes
to the TCG memory path so that the wrong-path simulator can mutate
guest registers and route guest stores through a per-vCPU speculative
buffer without corrupting the correct path.  This page enumerates
every modification the plugin's QEMU base carries relative to upstream
QEMU, why each is needed, and where consumers should look for the
matching code.

Plugin API additions
--------------------

``include/qemu/qemu-plugin.h`` (``QEMU_PLUGIN_VERSION = 12``)

   * ``qemu_plugin_insn_detail`` — Capstone-detail accessor that
     returns a structured ``qemu_plugin_insn_info`` for an
     in-flight ``qemu_plugin_insn`` (operands with type/access/size,
     implicit register reads/writes, instruction groups, x86
     prefix bits).  The plugin uses this in ``vcpu_tb_trans`` to
     classify each instruction without parsing disassembly strings.
   * ``qemu_plugin_cap_decode`` — same shape, but accepts a raw
     instruction byte buffer plus an explicit Capstone
     ``cs_arch`` / ``cs_mode`` pair.  Used for re-decoding the
     instructions of speculative basic blocks, which need the
     same Capstone view of bytes that the in-flight TCG translator
     does not otherwise expose.
   * ``qemu_plugin_insn_branch_target_pc`` — returns the static
     control-transfer target the per-ISA translator resolved for a
     branch instruction, or 0 for a non-branch or an indirect
     branch (whose target is not statically knowable).  This is the
     authoritative branch target: Capstone's branch-immediate
     operand is *not* a safe substitute, because per-ISA encoding
     (PC-relative vs. absolute, sign extension, MIPS delay-slot
     accounting, the ARM Thumb interworking bit, RISC-V immediate
     splits) is already resolved inside the translator, which must
     produce the value anyway to chain translation blocks.  The
     wrong-path simulator consumes this so a not-taken branch's
     alternate edge can be traced even when the program never
     executes it.
   * ``qemu_plugin_request_tb_flush`` — drops QEMU's entire TB
     cache from a plugin callback so every subsequent execution
     re-translates through ``vcpu_tb_trans``.  ChampSim Tracer uses
     it to honor the SPEC-template reclaim budget (the flush
     callback is where wrong-path-minted templates are freed).
     Plugin callbacks run inside a translation or an executing TB —
     contexts where a synchronous flush would reset the code region
     under an in-flight ``tb_gen_code`` — so the entry point always
     defers through ``tb_flush_deferred``
     (``include/exec/tb-flush.h``): the flush is queued as
     async-safe work, ``do_tb_flush`` runs at the vCPU thread-loop
     safe point after any plugin excursion has unwound, and any
     plugin ``flush_cb`` registered via
     ``qemu_plugin_register_flush_cb`` fires before the next TB
     executes.
   * ``qemu_plugin_cpu_events_set`` / ``qemu_plugin_drain_cpu_events``
     — enable and drain the ordered per-vCPU path-event queue (see
     *Path-event delivery*, below).  Draining hands out the queue's
     internal buffer — valid until the next push, which cannot happen
     before the consuming ``tb_exec`` callback returns — and resets
     its length; both producer and consumer are the owning vCPU
     thread, so the API is lock-free by construction.
   * ``qemu_plugin_register_asid_write_cb`` — synchronous
     notification each time the guest commits a changed value to the
     register ``qemu_plugin_get_addr_space_id()`` reports, fired from
     the same per-target commit points that produce
     ``QEMU_PLUGIN_CPU_EVENT_ASID_WRITE`` path events and with the
     same wrong-path suppression.  Unlike the queued event it fires
     even while the event queue is disabled, which is its purpose:
     the coarse fast-forward phase runs with no dispatching
     callbacks at all, yet must know whether the live address space
     is the pinned process's so the JIT-inlined user-instruction
     countdown can be compensated for foreign-process execution.
     The callback runs on the owning vCPU thread.
   * ``qemu_plugin_fault_depth`` — the live synchronous-fault
     nesting depth from QEMU's fault stack (see *Path-event
     delivery*).  The plugin baselines per-segment depth reporting
     from it.
   * ``qemu_plugin_in_async_int`` / ``qemu_plugin_async_int_reset``
     — read and force-clear the asynchronous-interrupt exclusion
     window flag.  The reset exists for abandoned windows (the
     departure PC is never fetched again); the plugin invokes it only
     when the pinned process is observed at user privilege, which is
     definitionally outside any handler.
   * ``qemu_plugin_in_spec_mode`` — the executing vCPU's speculative
     (wrong-path) mode flag, read from the vCPU itself.  The marker
     open/close callbacks gate on it so an invocation fired by a
     speculative execution is dropped on the QEMU-side ground truth,
     independent of any plugin thread-local session state.
   * ``qemu_plugin_vclock_pause`` / ``qemu_plugin_vclock_resume`` —
     nestable guest-virtual-clock freeze for plugin instrumentation
     windows (see *Guest-time transparency*, below).
   * ``qemu_plugin_icount_enabled`` — whether ``-icount`` drives the
     virtual clock; the plugin warns at install that wrong-path
     instructions advance instruction-count time (the vclock freeze
     covers wall-clock-driven time only).
   * The wrong-path session surface:
     ``qemu_plugin_cpu_state_save`` / ``_restore`` / ``_free``
     (architectural-register snapshot and rollback, sized per target
     by the ``end_reset_fields`` marker),
     ``qemu_plugin_spec_mode_begin`` / ``_end`` (enter/leave the
     side-effect-suppressed execution mode; ``_end`` also flushes the
     spec store sandbox and invalidates any wrong-path-installed TLB
     entries), ``qemu_plugin_set_pc`` / ``qemu_plugin_get_pc``
     (redirect and observe the speculative PC),
     ``qemu_plugin_exec_tb`` (run one TB at the current PC with the
     full plugin-callback surface),
     ``qemu_plugin_spec_vtime_pause`` / ``_resume``
     (whole-excursion guest-time freeze), and
     ``qemu_plugin_spec_store_overflowed`` (the sandbox's
     soft-budget flag — a wrong-path store footprint past the soft
     budget marks the excursion as diverged into nonsense so the
     walker can terminate it before the hard cap drops stores).
   * ``qemu_plugin_get_priv_level`` / ``qemu_plugin_get_addr_space_id``
     / ``qemu_plugin_paging_enabled`` — system-mode introspection backed
     by the per-target ``TCGCPUOps::get_plugin_state`` hook (below).
     They report the executing vCPU's privilege ordinal (0 = user,
     larger = more privileged), its address-space identifier (the
     page-table base / ASID register: x86 ``CR3``, RISC-V ``SATP``, Arm
     ``TTBR0_EL1``, MIPS ASID), and whether the guest MMU / paging is
     currently enabled.  They let a system-mode plugin pin tracing to a
     single process address space and, critically for the wrong-path
     simulator, decline to speculate when there is no paging to bound a
     speculative fetch (see *No speculation without paging*, below).  All
     three return their user-mode defaults — privilege 0, ASID 0, paging
     on — in ``*-linux-user``, where a process always has one valid
     address space.
   * ``qemu_plugin_vaddr_to_paddr`` — debug-walks the executing vCPU's
     current translation to return the physical address a virtual
     address maps to (0 when unmapped).  It supplies the physical-page
     identity a narrow ASID cannot distinguish — two processes that
     alias the same short MIPS ASID still occupy distinct physical
     pages — and backs the ``physaddr=1`` per-memop physical-page
     records.
   * ``qemu_plugin_get_thread_ptr`` — the kernel-maintained per-thread
     pointer register for the running thread, giving guest-thread
     identity independent of the vCPU a thread happens to be scheduled
     on.  The plugin keys ``thread_id`` off it rather than the vCPU
     index.
   * ``qemu_plugin_thread_ptr_tracks_current`` — whether that register
     still names the executing software thread when sampled *above* user
     privilege.  It is a per-target property: MIPS ``UserLocal``,
     AArch64 ``TPIDR_EL0`` and x86-64 ``FS.base`` are the kernel's to
     reload and nobody else's, so a kernel-privilege read names the
     current task; RISC-V swaps ``tp`` with ``sscratch`` on trap entry,
     so its in-kernel value is a different quantity entirely.  Where the
     answer is yes the plugin samples at every privilege level, which is
     what lets a guest context switch performed entirely inside the
     kernel retag the strand instead of leaving the work credited to
     whichever thread last returned to user on that vCPU.
   * ``qemu_plugin_vaddr_is_kernel`` — classifies a code virtual
     address's privilege domain through the target's own MMU / segment
     logic: a kernel-vs-user split that needs no page-table walk and is
     safe to consult on a speculative (wrong-path) address.  The plugin
     uses it to fold shared kernel code to a single template rather than
     re-minting one per process.
   * ``qemu_plugin_register_devio_cb`` — registers block-device I/O
     issue and completion notifications from the block backend, plus a
     doorbell hook.  The guest's virtqueue-notify (kick) executes in
     vCPU context, so the doorbell callback captures the kicking vCPU's
     owning (thread, asid) into a small bounded FIFO scoped to that same
     vCPU; the backend's later issue notification matches the oldest
     queued kick in that vCPU's FIFO by device token (mirroring a
     device's own in-order queue service) and stamps its owner on the
     request, giving the ``devio=1`` disk-I/O records their exact owner
     attribution instead of a positional guess.  A per-vCPU FIFO, rather
     than a single slot, is needed because one vCPU can ring the
     doorbell more than once before the backend drains the first
     request; scoping the match to the issuing vCPU's own FIFO, rather
     than searching every vCPU's, keeps two vCPUs' separate virtqueues
     from being confused when they share one device token.
   * ``QEMU_PLUGIN_VERSION = 12`` advertises these entry
     points to plugin loaders.

``include/accel/tcg/cpu-ops.h`` and per-target
``TCGCPUOps::get_plugin_state``

   A new optional ``TCGCPUOps`` callback,
   ``get_plugin_state(cpu, *priv, *asid, *mmu_on)``, is the single
   per-target source for the three introspection accessors above.  Each
   softmmu target fills it from architectural state: x86 from ``CPL`` /
   ``CR3`` / ``CR0.PG`` (``target/i386/tcg/tcg-cpu.c``; the reported
   ``CR3`` masks bit 63, the PCID no-flush command bit that is never
   part of the stored register, and the ``ASID_WRITE`` producer in
   ``cpu_x86_update_cr3`` compares under the same mask — PCID bits
   [11:0] pass through, since with ``CR4.PCIDE`` they are a real
   component of the address-space identity), Arm from the
   current EL / ``TTBR0_EL1`` / ``SCTLR.M``
   (``target/arm/cpu.c``), RISC-V from ``priv`` / ``SATP`` /
   (``SATP != 0 && priv != M``) (``target/riscv/tcg/tcg-cpu.c``), and
   MIPS from ``KSU`` / ``EntryHi.ASID`` / always-true (the MIPS TLB has
   no global enable) (``target/mips/cpu.c``).  ``plugins/api.c`` calls
   the hook when present and otherwise returns the user-mode defaults.
   The hook is gated ``CONFIG_PLUGIN && !CONFIG_USER_ONLY``; porting a
   new ISA to system-mode tracing means implementing it (see
   :doc:`extending`).

``plugins/api.c`` and ``disas/disas-target.c``

   The dispatch layer between the plugin API and the disassemblers.
   ``qemu_plugin_insn_detail`` forwards to a new
   ``plugin_disas_detail()`` which delegates to
   ``cap_disas_plugin_detail()`` when Capstone is available for the
   target ISA, and falls back to the builtin disassembler with a
   ``mnemonic / op_str`` split otherwise (so RISC-V and MIPS still
   produce something the plugin's MNEM-table classifier can use).

``disas/capstone.c`` and ``include/disas/dis-asm.h``

   Two new entry points: ``cap_disas_plugin_detail`` (uses an
   in-flight ``disassemble_info`` and a known PC/size) and
   ``cap_disas_raw_detail`` (opens a fresh Capstone handle from
   ``cs_arch`` / ``cs_mode`` arguments).  Both fill the
   ``qemu_plugin_insn_info`` structure declared in
   ``qemu-plugin.h``.  The implementation maps Capstone's generic
   group enum to ``QEMU_PLUGIN_GRP_*`` bits, copies operand and
   register-name strings into the public buffers, and recovers x86
   ``LOCK`` / ``REP`` prefix flags from the Capstone detail block.

   ``qemu_plugin_operand`` also carries ``segment_id``: the Capstone
   register ID of an x86 segment override on a ``MEM`` operand
   (``X86_REG_FS`` / ``X86_REG_GS`` / ...), 0 when the access uses
   the default segment and for every non-x86 ISA.  The segment
   register is a genuine address input — the linear address is
   ``seg.base + base + index * scale + disp`` — and Capstone exposes
   it *only* on the operand: x86 segment overrides do not appear in
   the implicit ``regs_read[]`` list.  Without the field a plugin
   walking operands cannot see it at all, so ``%fs:``-prefixed TLS
   and stack-protector accesses look address-input-less.

Static branch-target plumbing
-----------------------------

``qemu_plugin_insn_branch_target_pc`` (above) reports a value that
originates inside the per-ISA TCG translators.  Surfacing it requires
a small recording path plus a call at every direct-branch decode
site, since the translator otherwise discards the resolved target
once it has emitted the block-chaining code.

``include/qemu/plugin.h`` — ``struct qemu_plugin_insn``

   Carries a ``uint64_t branch_target_pc`` field.  ``plugin_gen_
   insn_start`` clears it for every instruction (the insn structs
   are pooled and reused across translations, so a stale target
   must never leak onto a later insn).

``include/exec/plugin-gen.h`` and ``accel/tcg/plugin-gen.c`` —
``plugin_gen_record_branch_target``

   The translator-facing entry point.  A per-ISA translator calls
   it while decoding a direct branch, passing the resolved absolute
   target; the implementation writes that into the current
   instruction's ``branch_target_pc``.  It is a no-op inline stub
   when ``CONFIG_PLUGIN`` is unset, so the per-target call sites add
   nothing to a non-plugin build.

``plugins/api.c`` — ``qemu_plugin_insn_branch_target_pc``

   Reads the field back out for plugins.

Per-ISA translator call sites
   Each translator calls ``plugin_gen_record_branch_target`` at its
   direct-branch decode sites, with the same target value it feeds
   to ``gen_goto_tb`` (or the architecture's equivalent).  Indirect
   and register-form branches deliberately do not call it — their
   target is not statically known — so ``branch_target_pc`` stays 0
   and consumers fall back to observed-target history.

   * ``target/arm/tcg/translate-a64.c`` — ``trans_B``, ``trans_BL``,
     ``trans_CBZ``, ``trans_TBZ``, ``trans_B_cond``
     (``s->pc_curr + a->imm``).
   * ``target/i386/tcg/translate.c`` and
     ``target/i386/tcg/emit.c.inc`` —
     ``gen_conditional_jump_labels`` (the ``Jcc`` / ``JCXZ`` /
     ``LOOPcc`` family) and ``gen_JMP`` (which ``gen_CALL`` reuses),
     using ``s->pc + immediate``.
   * ``target/mips/tcg/translate.c``,
     ``target/mips/tcg/nanomips_translate.c.inc``,
     ``target/mips/tcg/msa_translate.c``,
     ``target/mips/tcg/octeon_translate.c`` — paired with each
     static ``ctx->btarget`` assignment.  The general branch
     decoder's ``btgt = -1`` sentinel keeps the indirect
     ``JR`` / ``JALR`` forms out, leaving their
     ``branch_target_pc`` at 0.
   * ``target/riscv/translate.c`` and
     ``target/riscv/insn_trans/trans_rvi.c.inc`` — ``gen_jal``
     (the unconditional ``JAL``) and ``gen_branch`` (the B-type
     conditionals), using ``ctx->base.pc_next + imm``.  ``JALR``
     (indirect) is unaffected.

Path-event delivery
-------------------

System-mode path causality — which faults and interrupts detoured
execution, and exactly where — is observed by QEMU at its own
chokepoints and delivered to the plugin as ordered events plus two
pieces of live state.  All of it lives in ``include/hw/core/cpu.h``
(the ``CPUState`` plugin fields) with the API in ``plugins/api.c``.

``CPUState::plugin_fault_stack`` / ``plugin_fault_depth`` —
synchronous-fault resume stack

   QEMU owns the resume-PC stack directly because it observes every
   fault entry and every exception return synchronously and in
   strict LIFO order.  ``cpu_plugin_fault_push`` is called from each
   target's fault-delivery path for a *re-executing* fault only
   (TLB refill, lazy-enable trap — not syscalls or advance-past
   exceptions), pushing the resume PC: ``target/arm/helper.c``,
   ``target/i386/tcg/seg_helper.c``, ``target/riscv/cpu_helper.c``,
   ``target/mips/tcg/system/tlb_helper.c``.
   ``cpu_plugin_fault_pop`` is called from each target's
   exception-return path and pops only when the return target equals
   the top frame's resume PC — an exact match, since a pushed fault
   always re-executes its faulting instruction — so syscall and
   async returns, which never pushed, leave the stack untouched.
   Both are no-ops on the wrong path (``plugin_spec_mode``).

``CPUState::plugin_in_async_int`` / ``plugin_async_departure_pc`` —
async-interrupt window

   The target's exception-delivery path sets the flag on an
   *asynchronous* entry (timer / device IRQ / FIQ / SError) and
   records the interrupted guest PC — the departure point.  The
   fetch loop in ``accel/tcg/cpu-exec.c`` clears the flag when
   execution returns to exactly that PC, which is robust to the
   scheduler context-switching away mid-handler and to nesting (the
   outermost departure PC is kept).  The four delivery sites mirror
   the fault-push sites above.  Set only on the correct path.

``CPUState::plugin_evq`` — the ordered per-vCPU path-event queue

   Each fault push/pop and async-window edge appends one event
   (``FAULT_ENTER`` / ``FAULT_RETURN`` / ``ASYNC_ENTER`` /
   ``ASYNC_RETURN``) carrying the resume/departure PC, the
   depth-after, and the address-space ID and privilege level
   **stamped at the event instant** via the per-target
   ``get_plugin_state`` hook (``cpu_plugin_evq_push``,
   ``plugins/core.c``).  The queue is single-producer,
   single-consumer (both the owning vCPU thread), grow-only — it
   never drops an event, so a dense fault storm delivers one event
   per entry — spec-mode-suppressed at source, and disabled (and
   empty) until a plugin opts in per vCPU.  This is the channel the
   tracer's PathBuilder consumes; ``plugin_fault_depth`` remains the
   authoritative live depth.

Guest-time transparency
-----------------------

Plugin instrumentation runs on the vCPU thread but is not guest
execution; these mechanisms keep its host wall-clock cost out of
the guest's clocks.  A traced guest whose timer-tick handler costs
more than a tick period otherwise collapses into a self-sustaining
tick/scheduler storm.

``CPUState::plugin_vclock_depth`` + ``cpu_plugin_vclock_pause`` /
``_resume`` (``accel/tcg/cpu-exec.c``)

   Nesting-depth freeze of the guest virtual clock for correct-path
   instrumentation windows (per-TB emission, translation-time
   decoding).  Composes with the wrong-path excursion freeze below:
   ticks re-enable only when both say so.  No-op in user mode, and
   never re-enables a clock that ``vm_stop`` owns.

``CPUState::plugin_spec_vtime_paused`` +
``cpu_plugin_spec_vtime_pause`` / ``_resume``

   Whole-excursion guest-clock freeze for wrong-path simulation,
   idempotent and balanced so a fault-skip's spec-mode
   teardown/re-entry cannot leak ticks.  The resume side is also
   the excursion-exit boundary where every guest clock is
   resynchronised (below).  The BQL is additionally held across each
   wrong-path excursion on x86 only (other targets' wrong path
   legitimately takes the BQL for sandboxed device accesses) so the
   iothread cannot interleave mid-excursion.

``IcountFreeze`` + ``icount_plugin_freeze`` / ``_thaw``
(``accel/tcg/icount-common.c``)

   ``cpu_disable_ticks()`` stops the host-wall-clock source of
   ``QEMU_CLOCK_VIRTUAL``.  Under ``-icount`` that is not the source:
   guest time is a pure function of retired instructions, so a
   wrong-path excursion would advance guest time in proportion to its
   speculation depth.  The excursion checkpoints the instruction
   counter — both the per-vCPU in-flight counters and the global
   accumulator, since anything that reads the clock inside the window
   folds one into the other — and restores it on exit, so the
   excursion consumes zero icount as well as zero wall-clock guest
   time.

``TCGCPUOps::spec_clock_resync`` (``include/accel/tcg/cpu-ops.h``)

   The per-target clock resynchronisation hook, called for every
   target at the end of both plugin clock freezes.  Its contract: on
   return, every architectural clock or counter the guest can observe,
   and every armed host ``QEMUTimer`` backing one, is consistent with
   the FROZEN virtual time — as if the freeze had consumed exactly
   zero guest time.  The frozen clock is authoritative, so an
   implementation resynchronises the sources to it rather than the
   reverse.  Three obligations: re-derive each architectural counter
   from the frozen clock (x86's TSC free-runs off the host rdtsc and
   is re-pinned; Arm, RISC-V and MIPS counters are already functions
   of the virtual clock); re-arm every host timer from its restored
   compare register and re-deliver any expiry the excursion
   suppressed; and re-derive the CPU interrupt-request line from the
   restored architectural pending state.  Called with the BQL held and
   spec mode already ended, so an implementation may drive IRQ lines
   directly, and required to be idempotent — it runs on every
   excursion exit, including ones that disturbed nothing.

   Registered by all four system-mode targets.  A target that does not
   register it silently accumulates clock skew across excursions.

   Reconciling unconditionally rather than on an event flag is
   deliberate.  The predecessor of this hook was three per-ISA point
   patches behind a ``plugin_spec_timer_dirty`` gate that only fired
   when a desync had been *observed*; every clock source no patch
   covered, and every desync the register rollback produced on its
   own, drifted silently.  ``CPUState::plugin_spec_timer_dirty`` and
   ``plugin_spec_irq_dirty`` survive only as the record of *which*
   deferred expiry has to be re-delivered, not as the gate on whether
   to reconcile.

Interrupt replay across the wrong-path rollback

   Arm's ``env->irq_line_state`` and RISC-V's ``env->mip`` are inside
   ``CPUArchState``, so the excursion-exit register restore rewinds
   them.  For guest-caused changes that is correct; for changes an
   interrupt controller made while the excursion was in flight it is
   not — the assertion is real, and rewinding it drops the interrupt
   for good.  Arm carries ``irq_line_state`` across the restore
   wholesale (guest instructions never write it).  RISC-V separates
   the two cases at ``riscv_cpu_update_mip``, the single point every
   ``mip`` change passes through: the externally-caused delta is
   logged and replayed over the rewound register, while the guest's
   own ``mip``/``sip`` CSR write flags itself and is discarded with the
   rest of the speculative state.  Timer bits stay out of the replay —
   the resync re-derives them from the architected compare registers.

Speculative-execution support
-----------------------------

The wrong-path simulator drives QEMU's TCG to execute speculatively-
chosen translations whose architectural side effects must be
discarded at the end of each WP chain.  That requires three things
that stock TCG does not provide: faults during translation must
unwind cleanly, stores must route through a per-vCPU buffer instead
of touching guest memory, and translation faults must not deliver a
signal to the guest.  The hooks below cooperate with the plugin's
``cpu->plugin_spec_mode`` flag to give the WP simulator a usable
speculative path.

``accel/tcg/cpu-exec.c`` — ``cpu_plugin_exec_tb``

   The ``sigsetjmp(cpu->jmp_env, 0)`` guard wraps both
   ``tb_lookup`` and ``tb_gen_code``, not just ``cpu_tb_exec``.
   Translating a TB during plugin speculative execution can fault
   (e.g. ``translator_ld()`` crossing into an unmapped page), and
   that path siglongjmps through ``cpu->jmp_env``.  If the guard
   did not cover translation, the longjmp would unwind past the
   plugin callback frame and deadlock on the next call.

``accel/tcg/translate-all.c`` — ``tb_gen_code``,
``accel/tcg/cpu-exec.c`` — ``cpu_exec_loop``,
``tcg/region.c`` — spec reserve

   A wrong-path walk runs nested inside the ``vcpu_tb_exec`` callback
   of an executing correct-path TB, so that TB's host code must stay
   intact until the walk unwinds and the TB finishes.  A code-buffer
   overflow during ordinary translation resolves with ``tb_flush`` +
   ``cpu_loop_exit``, which resets the buffer and re-dispatches — but
   taken mid-walk that resets the buffer *under* the correct-path TB
   the walk is nested inside, clobbering the host code control returns
   into (a JIT ``SIGSEGV``).

   Two cooperating mechanisms keep wrong-path translation
   flush-invariant instead.  Each region holds back a small reserve at
   the top: ``tcg_region_assign`` lowers ``code_gen_highwater`` by up
   to 2 MiB.  When ``tb_gen_code`` overflows while
   ``cpu->plugin_spec_mode`` is set, it opens that reserve
   (``tcg_region_open_spec_reserve``) so the in-flight walk translates
   to its natural end — wrong-path is a series of independent true BBs,
   and the emitted chain is identical with or without the flush, never
   truncated — and records the owed flush in
   ``cpu->plugin_flush_pending`` rather than flushing in place.
   ``cpu_exec_loop`` honors that flag with the real ``tb_flush`` at its
   next safe point, after the walk has unwound and the correct-path TB
   has finished, so the flush recycles the whole buffer (reserve
   included) with no TB in flight.  At the default buffer size the
   reserve is never reached and neither path runs; it is a
   wrong-path-only safety valve, and the correct path is byte-for-byte
   and speed-for-speed unaffected.

``accel/tcg/cputlb.c`` and ``accel/tcg/user-exec.c`` —
``probe_access``

   When ``cpu_plugin_spec_active(env_cpu(env))`` is true, both
   probes return ``NULL`` so that callers fall back to the slow-
   path ``cpu_ld``/``cpu_st`` helpers.  Those helpers invoke the
   plugin's spec store buffer / load overlay; a successful direct
   host-pointer return would bypass the buffer and let speculative
   stores leak into guest memory.

``linux-user/signal.c`` — ``cpu_loop_exit_sigsegv`` /
``cpu_loop_exit_sigbus``

   When ``cpu->plugin_spec_mode`` is set, both helpers ``longjmp``
   out via ``cpu_loop_exit_restore()`` instead of queuing a guest
   signal via ``force_sig_fault()``.  A queued ``SIGSEGV`` would
   later be delivered on the correct path and kill the guest; the
   plugin observes the speculative fault via the ``tb_ok=false``
   return from ``cpu_plugin_exec_tb`` instead.

``target/arm/tcg/helper-a64.c``, ``target/i386/tcg/access.c``,
``target/ppc/mem_helper.c``

   Per-target store helpers (``DC ZVA``, x86 ``access_prepare_mmu``,
   PPC ``dcbz``).  A host fast-path memset taken when
   ``tlb_vaddr_to_host`` returns a usable pointer would bypass the
   plugin's spec store buffer.  These helpers have no
   ``CONFIG_USER_ONLY`` gate around the ``cpu_st*`` slow path, so
   user-mode + speculative execution always routes through the
   buffer; non-speculative user-mode runs hit the slow path
   exactly when the host pointer is unavailable, the same as
   system mode.

``include/exec/cpu_ldst.h`` — user-mode ``tlb_vaddr_to_host``

   In ``linux-user`` there is no softmmu TLB, so
   ``tlb_vaddr_to_host`` is ``guest_base + addr`` with no mapping
   check.  Under ``plugin_spec_mode`` it returns ``NULL`` for every
   access type, so all targets' bulk / host-pointer helpers fall
   back to the slow ``cpu_{ld,st}*_mmuidx_ra`` path: speculative
   stores route through the spec store buffer and speculative loads
   fault as guest exceptions the wrong-path simulator handles.
   Gating only stores would leave a wrong-path load of a garbage
   address dereferencing an unmapped host pointer — a host
   ``SIGSEGV`` instead of a guest fault.  This is the ISA-generic
   counterpart to the per-target store-helper changes above and
   also covers reads (ARM FEAT_MOPS, x86 string ops, vector
   gather/scatter).

``target/arm/tcg/helper-a64.c`` — FEAT_MOPS bulk set/copy

   ``SETP/SETM/SETE`` and ``CPYP/CPYM/CPYE`` perform a
   register-sized memory set/copy whose loop runs entirely inside a
   single TCG helper.  x86 ``REP`` is single-stepped, so the
   plugin's between-``exec_tb`` forward-progress / depth guards
   bound it; a MOPS helper does not return to the plugin
   mid-operation, so a wrong-path speculative-garbage size register
   drives billions of byte iterations.  ``do_setp/do_setm/do_sete``
   and ``do_cpyp/do_cpym/do_cpye`` clamp the operation size to a
   sub-page bound (``MOPS_SPEC_MAX_BYTES`` = 256) under
   ``plugin_spec_mode``.  Wrong-path memory state is discarded on
   rollback, so a bounded set/copy is indistinguishable to any
   consumer; the sub-page bound also preserves the architectural
   ``< page`` epilogue invariant of ``do_sete`` / ``do_cpye``.  The
   correct path is unaffected.  This bounds the iteration count
   only — per-byte sandboxing is handled by the generic
   ``tlb_vaddr_to_host`` behaviour above.  It is MOPS-specific
   because no other ISA has a single instruction looping a 64-bit
   register-sized memory operation.

``include/exec/plugin-spec.h`` and ``accel/tcg/internal-common.h`` —
spec store buffer

   The per-vCPU spec store buffer is a ``g_hash_table`` keyed by
   64-byte cache line (``PluginSpecLine``: a ``valid_mask`` bitmap
   plus a ``bytes[64]`` payload, declared in ``plugin-spec.h``).
   Both the store and the store-to-load-forwarding load resolve a
   whole access **per cache line, not per byte**: a naturally-aligned
   access stays within one line, so the common case is a single hash
   lookup, and a load whose line holds no speculative bytes falls
   straight through to a bulk read from guest memory.

   * ``spec_store_bytes`` (``internal-common.h``) chunks a store by
     line, ``memcpy``-ing each chunk into the line payload and OR-ing
     the covered bits into ``valid_mask``.
   * ``spec_load_bytes_user`` (``accel/tcg/user-exec.c``, linux-user)
     and ``spec_load_bytes`` (``accel/tcg/cputlb.c``, softmmu) are the
     two mirror-image forwarding loads; both chunk by line and only
     fall to per-byte selection when a line is partially speculative.

   ``spec_line_get_or_alloc`` bounds the table at
   ``PLUGIN_SPEC_STORE_LINE_MAX`` lines: beyond the cap no new lines
   are added, but existing lines still update so store-to-load
   forwarding stays correct for the tracked working set and excess
   speculative stores are simply not forwarded.  The bound, and the
   buffer itself, are ISA-generic — they apply to every target that
   routes stores through the buffer.  A *soft* budget sits below the
   hard cap: when a single excursion's store footprint crosses it,
   ``cpu->plugin_spec_store_overflow`` is set (readable via
   ``qemu_plugin_spec_store_overflowed()``) so the wrong-path walker
   can terminate a wild excursion — a garbage-size memop that a real
   CPU's wrong path would fault on — before the hard cap starts
   dropping stores.

   ``PluginSpecLine`` places its ``bytes[64]`` payload first and is
   ``QEMU_ALIGNED(16)`` so a naturally-aligned guest atomic (size ≤ 16,
   never crossing a 64-byte line) yields a correspondingly-aligned
   pointer into the payload — the redirect for speculative atomics
   (below) depends on this, because the host atomic primitives (x86
   ``cmpxchg16b``, AArch64 128-bit ``LDXP``/``STXP``) fault on a
   misaligned operand.

``accel/tcg/cputlb.c`` and ``accel/tcg/user-exec.c`` —
``atomic_mmu_lookup``

   The atomic read-modify-write helpers (``atomic_template.h``:
   ``cmpxchg``, ``xchg``, ``fetch_*``, ``*_fetch``) obtain a raw host
   pointer from ``atomic_mmu_lookup`` and mutate it in place with real
   host atomics.  Left unsandboxed that writes real guest memory on the
   discarded wrong path — kernel spinlocks, refcounts and page-table
   cmpxchg in system mode, and ``lock``-prefixed RMW / futex words in
   user mode alike — because the spec store buffer only intercepts the
   plain load/store helpers.  Under ``cpu_plugin_spec_active`` both
   copies of ``atomic_mmu_lookup`` redirect the returned pointer into
   the spec store buffer via ``spec_atomic_shadow``
   (``internal-common.h``): it pre-fills the accessed bytes from real
   memory wherever they are not already speculatively dirty (so the RMW
   reads the correct store-to-load-forwarded baseline), marks them
   valid, and returns a pointer into the line.  The in-place RMW then
   mutates the shadow, later speculative loads forward from it, and the
   line is discarded at walk end.  The softmmu copy also returns before
   the real-memory ``notdirty_write`` / watchpoint side effects.

   When the line pool is at ``PLUGIN_SPEC_STORE_LINE_MAX`` and no
   shadow line can be allocated, both copies discard the RMW into a
   per-thread scratch line seeded from the real bytes.  No path falls
   back to the real host pointer: a wrong-path atomic cannot mutate
   guest memory even under sandbox exhaustion.  The cost is
   store-to-load forwarding for that one line — the same degradation
   the plain store path takes when a capped pool drops a store.

   As with the store buffer this is ISA-generic and fixes user-mode
   wrong-path atomics too.

Bounding wrong-path: no speculation without paging
--------------------------------------------------

   A real processor's wrong-path fetch still goes through the MMU: a
   speculative branch into a non-code page faults on the
   instruction-fetch translation, which is what stops it.  The
   wrong-path simulator relies on exactly that — a speculative branch
   into data takes a guest instruction-fetch fault, which unwinds via
   ``cpu_plugin_exec_tb`` and ends the walk.  With the guest MMU
   *disabled* (x86 real-mode / early boot before ``CR0.PG``) there is no
   such fault: a branch into a zero/data page decodes as an unbounded
   run of no-branch instructions — a "NOP sled to infinity" — that folds
   into a true basic block which never seals, exhausting host memory.

   The plugin therefore consults ``qemu_plugin_paging_enabled()`` before
   launching a wrong-path walk and does not speculate when the MMU is
   off.  This is system-mode-only by construction: ``*-linux-user``
   reports paging on (a process address space always bounds fetches),
   so user-mode wrong-path is unchanged.  It also matches the intended
   use — system-mode tracing targets a user process and its (mapped)
   kernel invocations, which run with paging on, not the pre-paging
   boot path.

Suppressing device and global side effects
------------------------------------------

   Wrong-path execution may run privileged instructions whose effect is
   neither a register write (rolled back with ``CPUArchState``) nor a
   guest-memory store (caught by the spec store buffer) but a poke at an
   emulated *device* or at *global* CPU state — an interrupt-controller
   register, a timer, the interrupt-request line.  Those escape the
   discarded path.  Each target suppresses them under
   ``plugin_spec_mode`` while still applying any architectural-register
   part (which is restored at walk end anyway):

   * **x86** (``target/i386/tcg/system/misc_helper.c``): port I/O
     (``in``/``out``) returns without touching ``address_space_io``;
     ``mov cr8`` applies the ``V_TPR`` shadow but skips
     ``cpu_set_apic_tpr`` and the ``VIRQ`` ``cpu_interrupt``; ``wrmsr``
     skips ``cpu_set_apic_base`` and the x2APIC ``apic_msr_write``.
   * **Arm** (``target/arm/tcg/op_helper.c``): ``set_cp_reg`` /
     ``set_cp_reg64`` skip the ``writefn`` for ``ARM_CP_IO`` registers —
     the architecture's own marker for system registers with device
     side effects (GIC ``ICC_*``, the generic timer).
   * **RISC-V**: ``riscv_cpu_interrupt`` (``cpu_helper.c``) leaves the
     real interrupt line alone (a speculative ``mip``/``sip`` write
     still updates ``env->mip``, restored at walk end);
     ``riscv_timer_write_timecmp`` (``time_helper.c``) skips the timer
     reprogram.
   * **MIPS** (``target/mips/tcg/system/cp0_helper.c``):
     ``mtc0 Count`` / ``Compare`` skip the timer reprogram; the
     VPE wake/sleep paths skip ``cpu_interrupt`` / ``halted``.

   Guest-memory device escapes (MMIO) need no separate gate: an MMIO
   store is unreachable because the softmmu store helpers route to the
   spec buffer before the device dispatch, and an MMIO load returns
   zero.  Page-table accessed/dirty-bit writeback is likewise suppressed
   per target (``target/i386/tcg/system/excp_helper.c`` ``ptw_setl``,
   ``target/arm/ptw.c`` ``arm_casq_ptw``, ``target/riscv/cpu_helper.c``).

   A gated timer expiry (Arm generic timer, RISC-V ``timecmp``, MIPS
   ``Count`` / ``Compare``) additionally records that its delivery was
   deferred, so the excursion-exit resync (see *Guest-time
   transparency*) knows to re-deliver it rather than merely re-arm.
   The re-arm itself is unconditional and needs no such record.

``accel/tcg/cputlb.c`` — wrong-path TLB-install log

   Speculative accesses still run ``tlb_fill`` on a miss and install
   softmmu TLB entries.  Rather than a full ``tlb_flush`` on every
   excursion exit — which would drop the entire correct-path TLB and
   jump cache, ruinously expensive at wrong-path frequency — the
   pages an excursion installs are logged (with their ``mmu_idx``,
   which also covers a wrong-path privilege change) in
   ``cpu->plugin_spec_tlb_log`` at ``tlb_set_page_full``, and only
   those pages are invalidated at spec-mode exit.  An excursion that
   only hits existing entries — the common case — leaves the log
   empty and flushes nothing; a large-page install or log overflow
   falls back to a full flush.

Aborting unsandboxable instructions
-----------------------------------

   A few instructions change state too sweepingly to sandbox: they halt
   the vCPU, write to guest *physical* memory through paths that bypass
   the softmmu helpers, or perform a complete mode switch.  On the wrong
   path the simulator simply stops there — a real wrong path would not
   retire deep past one of these either.  Each calls ``cpu_loop_exit``
   under ``plugin_spec_mode`` (caught by ``cpu_plugin_exec_tb``'s guard,
   ending the walk), exactly like the existing ``hlt`` gate:

   * **Halt family** — x86 ``mwait``
     (``misc_helper.c``), Arm ``wfi`` / ``wfit`` (``op_helper.c``),
     RISC-V ``wfi`` (``op_helper.c``), MIPS ``wait`` (``exception.c``):
     setting ``cs->halted`` on the discarded path would stall the VM.
   * **x86 SVM** ``vmrun`` / ``vmload`` / ``vmsave`` and **SMM**
     ``rsm`` (``svm_helper.c`` / ``smm_helper.c``): these write host
     save-state to guest physical memory (``x86_st*_phys``, outside the
     sandbox) and switch virtualization / SMM mode.
   * **Exceptions**: ``raise_interrupt2`` (``excp_helper.c``) aborts the
     walk rather than delivering a guest fault, so a speculative
     ``#GP`` / ``#UD`` / ``#PF`` does not vector into a handler (whose
     side effects would pollute the correct path) nor escalate to a
     triple fault.

Wrong-path syscalls: fetched, never performed
---------------------------------------------

   The wrong path walks *past* a syscall at its architectural
   fall-through rather than stopping there (see :doc:`architecture`),
   which makes it load-bearing that the call is never carried out.  On a
   discarded path a syscall would otherwise write files, send packets or
   exit the process in ``*-linux-user``, and run the guest's real kernel
   entry in system mode.

   In ``*-linux-user`` the suppression is structural.  Every target's
   syscall instruction leaves TCG through a guest exception, and under
   ``plugin_spec_mode`` that exception unwinds into
   ``cpu_plugin_exec_tb``'s own ``sigsetjmp`` landing pad instead of
   returning to ``cpu_loop()`` — and ``do_syscall()`` is only ever
   reached from ``cpu_loop()``.  ``linux-user/syscall.c`` carries a
   barrier at the top of ``do_syscall()`` that makes this a checked
   invariant rather than an argument: reaching it on a wrong path
   refuses the call, returns ``-ENOSYS`` to the discarded path, and
   increments ``qemu_plugin_spec_syscall_blocked``.  A plugin reads that
   through ``qemu_plugin_spec_syscall_blocked_count()``; the tracer
   prints it as ``WP host syscalls blocked`` and it reads 0 on a healthy
   run, so a non-zero value means the unwind grew a hole and the trace
   ran with real side effects on it.

   System-mode x86 is the one target that does not raise: ``SYSCALL``
   and ``SYSENTER`` perform the privilege escalation inline in
   ``helper_syscall`` / ``helper_sysenter``, loading CS/SS and
   redirecting EIP to LSTAR.  Both now call ``cpu_loop_exit_restore``
   under ``plugin_spec_mode`` — the same shape ``raise_interrupt2`` uses
   for a speculative exception — so the wrong path resumes at the
   fall-through there too, and RCX/R11 keep their pre-syscall values as
   the deterministic placeholder the walker already applies to a skipped
   instruction's destinations.

x86 lazy-flags resolution for plugin reads
------------------------------------------

QEMU's i386 target keeps the arithmetic-flag bits (CF / PF / AF / ZF /
SF / OF) in a lazy ``CC_OP / CC_SRC / CC_DST`` shadow rather than in
``env->eflags``, and only materialises them into ``env->eflags`` at
specific sync points (helper calls that read flags, TB exit, signals).
A plugin that reads ``eflags`` mid-TB via the gdbstub register path
sees stale arithmetic-flag bits — typically the values left over from
``cpu_exec_enter`` (CC_OP_EFLAGS plus whatever IF / reserved bits the
prior TB ended with).

Two cooperating mechanisms make plugin reads of EFLAGS
correct.  Both are scoped narrowly so non-plugin builds and
non-plugin TB execution are unchanged.

``target/i386/gdbstub.c`` — ``IDX_FLAGS_REG`` read path

   The ``x86_cpu_gdb_read_register`` case for ``IDX_FLAGS_REG``
   returns ``cpu_compute_eflags(env)`` instead of raw ``env->eflags``.
   ``cpu_compute_eflags`` dispatches on the current ``cc_op`` and
   resolves the lazy CC bits via ``cpu_cc_compute_all(env)`` before
   OR-ing them into the returned value.  Otherwise the gdbstub
   path (which is what ``qemu_plugin_read_register`` ultimately
   reaches) would emit only the non-lazy bits in ``env->eflags`` —
   useless for tracing.

``target/i386/tcg/translate.c`` — ``i386_tr_insn_start``

   The gdbstub read path is necessary but not sufficient.  ``cc_op``
   itself is a TCG global written *lazily* by the translator via
   ``gen_update_cc_op()`` only when ``s->cc_op_dirty`` is true at a
   known sync point (helper call, branch, TB exit).  Plugin
   ``QEMU_PLUGIN_CB_R_REGS`` callbacks are target-agnostic, so the
   plugin infrastructure cannot know to flush ``cc_op`` for x86 —
   meaning the global gets flushed to ``env->cc_op`` with whatever
   value was last emitted as ``tcg_gen_movi_i32(cpu_cc_op, …)``,
   typically the ``CC_OP_EFLAGS`` left over from TB entry.
   ``cpu_compute_eflags`` then sees ``cc_op = CC_OP_EFLAGS`` and
   ``cc_src = <last ALU op's source operand>``, interprets
   ``cc_src`` as if it were a resolved-flags value, and returns
   garbage.

   ``i386_tr_insn_start`` calls ``gen_update_cc_op(dc)`` at its very
   top when ``dcbase->plugin_enabled`` is set.
   That guarantees every insn boundary materialises the prior insn's
   ``cc_op`` into the TCG global before the next insn's plugin
   ``PLUGIN_GEN_FROM_INSN`` placeholder is emitted — so the R_REGS
   helper sees ``cc_op`` matching what the previous ALU op actually
   set.  Cost is one ``movi`` per insn boundary, gated on plugin
   active.

   The same problem in principle exists for any target that defers
   sync-point writes of shadow state across insns; i386 is the only
   target affected (AArch64 NZCV is updated eagerly).

The :doc:`validator`'s ``metaflags`` check is what surfaces this
class of bug:  it predicts the canonical Z / N / P bits from the
post-execution dst-register snap and asserts they match the
FID_METAFLAGS byte the writer derived from ``REG_FLAGS``.  Without
the two mechanisms above, every flag-writing x86
arithmetic insn miscompares.

Disassembly and target metadata
-------------------------------

``disas/capstone.c``

   In addition to the plugin entry points above, this file carries a
   per-arch register-ID map.  Capstone's auto-generated
   ``getRegisterName()`` asserts on out-of-range IDs in
   ``CAPSTONE_DEBUG`` builds (the meson default).  Each
   ``cs_reg_name()`` call is wrapped with a per-arch upper bound
   (e.g. ``X86_REG_ENDING``) so the plugin can probe register IDs
   that appear in operand metadata without tripping the assert when
   Capstone exposes a sparse range.

``disas/capstone.c`` — Capstone-6.0.0 decode-bug workarounds

   The operand metadata feeding ``qemu_plugin_insn_info`` is only as
   sound as Capstone's structured detail.  Capstone 6.0.0 mis-decodes
   a handful of instruction shapes; ``cap_fill_*_operands`` correct
   each at the boundary, so the rest of QEMU and every plugin see a
   consistent operand view.  Each is scoped to the exact mis-decoded
   shape and is keyed to revisit when Capstone is bumped past 6.0.0.

   * AArch64 ``LSL`` / ``LSR`` / ``ASR`` / ``ROR`` by immediate.
     These are alias mnemonics of ``UBFM`` / ``SBFM`` / ``EXTR``;
     Capstone prints the shift count in ``op_str`` but drops the
     immediate from the structured operand array, so the immediate
     would be invisible to the plugin.  The shift count is still
     parked in ``operands[1].shift``, and
     ``cap_fill_arm64_operands`` synthesises the missing ``IMM``
     operand from it (see ``cap_aarch64_is_buggy_shift_imm_alias``).
   * AArch64 memory access flags.  The register-offset /
     extended-register load-store forms (``ldr w3, [x1, x2]``,
     ``str w3, [x1, w2, uxtw #2]``, and kin with a GPR destination)
     and the LSE ``SWP`` family report their memory operand with
     ``access == 0`` — Capstone's generated operand table carries no
     access for those rows, and its own per-instruction repair table
     (``mem_acc``) is equally unpopulated in 6.0.0-Alpha7.
     Immediate-offset, pre/post-index, exclusive, ``CAS`` /
     ``LD<op>`` atomic, SVE, and vector-structure forms all report
     correctly.  ``cap_fill_arm64_operands`` infers the missing
     access from the mnemonic class (``swp`` / ``cas`` / atomic
     ``ld<op>`` / ``st<op>`` → ``READ|WRITE``, other ``ld*`` →
     ``READ``, other ``st*`` → ``WRITE``; see
     ``cap_aarch64_infer_mem_access``) and applies the inference
     only when Capstone reported ``access == 0``, so a Capstone
     version that starts populating these rows wins automatically.
     Upstream fixed the register-offset rows in 6.0.0-Alpha8
     (``e5c6e09``, capstone-engine/capstone#2802); the ``SWP`` rows
     remain unfixed upstream.
   * x86 store-form extract (``PEXTR`` / ``EXTRACTPS`` family).
     Capstone marks the ``r/m`` destination ``READ``-only;
     ``cap_fill_x86_operands`` forces ``WRITE`` on the memory
     operand.
   * x86 store-form data moves (``VMOVDQA`` / ``MOVUPS`` /
     ``VMOVUPS`` and kin writing memory).  Capstone marks the
     memory destination ``READ``-only; the same filler forces
     ``WRITE``.
   * x86 ``TEST``.  ``TEST`` ANDs its operands, discards the result
     and writes ``EFLAGS`` only — it never writes an operand.
     Capstone breaks that in both directions: some register-source
     encodings report every operand with ``access == 0`` (a lost
     ``READ``, so a memory operand mints no load slot), and opcode
     ``A9`` **at 32-bit operand size only** reports its accumulator
     operand ``READ|WRITE`` (a phantom destination register — false
     WAW/RAW edges and a wasted ChampSim destination slot).  The
     8-bit ``A8``, 16-bit ``66 A9``, 64-bit ``REX.W A9`` and every
     ModRM form (``F6``/``F7 /0``, ``84``, ``85``) are correct.
     ``cap_fill_x86_operands`` forces plain ``READ`` on every
     ``TEST`` operand, which is what the architecture says and so
     cannot disturb the correctly-reported encodings.
   * x86 string family (``MOVS`` / ``CMPS`` / ``SCAS`` / ``LODS`` /
     ``STOS`` / ``INS`` / ``OUTS``).  These address memory only through
     ``(%rSI)`` and ``(%rDI)``, and which of the two each reads and
     writes is fixed by the architecture, so
     ``cap_x86_string_mem_access`` derives the access from the
     (mnemonic, base register) pair and sets it for the whole family.
     Three distinct defects make that necessary.  ``STOS`` reports its
     ``ES:[rDI]`` destination ``READ`` — *inverted* — at every operand
     size and with or without a ``REP`` prefix, so the walker mints a
     load slot where a store belongs and the REP per-iteration split
     counts it as ``rep_loads_per_iter``.  ``CMPS`` **at 32-bit operand
     size only** (opcode ``A7`` with neither ``66`` nor ``REX.W``)
     reports *both* memory operands ``access == 0``, while ``cmpsb`` /
     ``cmpsw`` / ``cmpsq`` are correct — the same one-operand-size shape
     as the ``TEST A9`` defect above.  ``INS`` and ``OUTS`` report their
     memory operand ``access == 0`` at *every* size, and their 32-bit
     forms additionally drop the ``READ`` on the ``%dx`` port operand.

     The lost-flag cases do the most damage, because a REP-prefixed
     string op derives its per-iteration memop count from exactly these
     flags: a zero count disables the fan-out entirely, so a
     ``rep cmpsl`` over *N* dwords collapses from *N* body entries of two
     loads each into a single entry carrying all 2*N* memops, none of
     which its template says the instruction can perform.  (The memop
     records themselves come from QEMU's memory callbacks, not from
     Capstone, and were always correct — PIN and the tracer agree 100 %
     on string-op memop counts and addresses.  Only the operand, lane
     and fan-out model was wrong.)  Note Capstone folds the repeat
     prefix into the mnemonic string (``"rep stosq"``), which
     ``cap_x86_skip_rep`` steps over.
   * x86 scalar ``ROUNDSS`` / ``ROUNDSD``.  Their memory-source form
     reports the memory operand ``access == 0``, while the packed
     ``ROUNDPS`` / ``ROUNDPD`` and the register form of the very same
     instructions are correct.  Because the destination operand does
     carry an access, the walker sees "access info present" and simply
     drops the source: a real 4- or 8-byte load gets no load lane, no
     address dependency, and any memop observed on it is an impossible
     attribution.  ``cap_x86_is_scalar_round`` forces ``READ``; these
     instructions never write memory, so that is exact.
   * x86 ``WRSS`` / ``WRUSS``.  The CET shadow-stack writes report
     *both* operands ``access == 0``, so a genuine store is modelled
     with no store lane.  ``cap_x86_is_shadow_stack_store`` sets
     ``READ`` on the register data source and ``WRITE`` on the memory
     target.
   * x86 multi-byte ``NOP`` (``0F 1F``).  This is the opposite
     direction — a *phantom* access rather than a lost one.  The
     instruction takes a ModRM and so names a memory operand, but it
     performs no memory access whatsoever (Intel SDM); Capstone reports
     that operand ``READ`` at the sizes a compiler actually emits for
     alignment padding, and ``access == 0`` (correct) only for the
     ``REX.W`` form.  Left alone it mints a load lane and an address
     dependency on the base and index registers for a load that can
     never occur, on one of the most frequent instructions in any
     optimised binary.  ``cap_x86_mem_is_never_accessed`` clears it.
     This is deliberately **not** applied to the cache-hint
     instructions (``PREFETCH*``, ``CLFLUSH``, ``CLWB``, ``CLDEMOTE``),
     whose memory operand Capstone also reports ``READ``: those do name
     a real address a memory-system consumer wants, and the tracer
     routes them through its synthetic-EA path precisely because their
     TCG translation emits no memop.
   * x86 ``PUSH %fs`` / ``%gs``.  The segment-register forms report
     their operand ``access == 0``, while the general-register form and
     every ``POP`` are correct, so the pushed segment register is
     dropped from the dependency model.  ``cap_x86_is_push`` sets
     ``READ``; a ``PUSH`` operand is a read in every encoding.

     Three further encodings whose operands report ``access == 0`` are
     deliberately left alone, because ``0`` is either right or
     unknowable: ``CLDEMOTE`` (a cache hint that reads and writes no
     data), ``BSWAPW`` (``66``-prefixed ``BSWAP`` is an undefined
     encoding), and ``FFREEP`` (an undocumented x87 opcode that touches
     no memory).  Immediate operands also report ``access == 0``; that
     is correct and universal, and the walker never derives a lane from
     one.

   * MIPS memory access flags.  MSA vector loads/stores and the
     unaligned scalar family (``LWL`` / ``LWR`` / ``LDL`` / ``LDR``
     / ``SWL`` / ``SWR`` / ``SDL`` / ``SDR``) report their memory
     operand with ``access == 0``.  MIPS has no address-only
     memory-operand form, so a zero-access MIPS memory operand is
     always this defect; ``cap_fill_generic_operands`` infers the
     direction from the data register operand (a written data
     register implies a load, a read one implies a store).
   * MIPS unaligned-load register merge.  ``LWL`` / ``LWR`` (and the
     64-bit ``LDL`` / ``LDR``) merge selected bytes of the loaded
     word into the destination register, preserving the rest — the
     old register value is architecturally an input.  Capstone marks
     the register ``WRITE``-only; ``cap_fill_generic_operands``
     promotes it to ``READ|WRITE`` so the partial write's dependency
     on the previous value survives.

``target/mips/cpu.c`` and ``configs/targets/mips*.mak`` plus
``gdb-xml/mips-cpu.xml`` / ``mips64-cpu.xml``

   Wires the MIPS GDB stub XML files into the build so the plugin's
   register-handle cache can resolve MIPS register names via
   ``qemu_plugin_get_registers()``.  Without these the cache returns
   empty for MIPS targets and ``regdata=1`` traces would have no
   register snapshots.

``target/riscv/cpu.h``

   Inserts the ``end_reset_fields`` boundary marker into
   ``CPUArchState``, immediately after the architectural register
   state and CSRs (``gpr``, ``fpr``, ``vreg``, ``pc``, ``vl`` /
   ``vtype`` and the rest) and before the externally-managed pointers
   and timers (S/VS-mode interrupt timers, KVM/HVF state).  The marker
   delimits the rollback-eligible region: ``cpu_plugin_arch_state_size()``
   returns ``offsetof(CPUArchState, end_reset_fields)`` as the byte
   count the wrong-path simulator's ``qemu_plugin_cpu_state_save`` /
   ``qemu_plugin_cpu_state_restore`` snapshot copies.  RISC-V's
   ``CPUArchState`` had no such marker upstream, so
   ``cpu_plugin_arch_state_size()`` does not compile for the RISC-V
   target without it.  The placement matters for ``regdata=1`` on
   RISC-V: every architectural register the plugin reads back through
   ``qemu_plugin_read_register`` for destination-register snapshots
   falls before the marker, so the WP simulator's speculative writes
   to those registers are rolled back on restore.  A marker placed
   before any register field would leave that field on the preserved
   side, and the post-WP correct-path snapshot would observe a
   speculatively-corrupted value instead of the architectural one.

``target/alpha/cpu.h``, ``target/avr/cpu.h``,
``target/hexagon/cpu.h``, ``target/loongarch/cpu.h``,
``target/ppc/cpu.h``, ``target/tricore/cpu.h``,
``target/xtensa/cpu.h``

   Same ``end_reset_fields`` insertion as RISC-V, but placed at the
   end of each ``CPUArchState`` so the boundary covers the whole
   struct.  The marker is required for these targets because the
   plugin-API surface (``qemu_plugin_cpu_state_save`` and friends)
   is built once per ``target/`` and resolves
   ``offsetof(CPUArchState, end_reset_fields)`` per-target; without
   the field the whole tree fails to compile.  ChampSim Tracer does
   not exercise wrong-path simulation on these ISAs, so the
   conservative whole-struct placement is correct (anything a future
   spec-mode user might write to is captured for rollback) and the
   placement is easy to refine downstream if speculative execution
   is ever lit up for one of them.

Speculative-execution slow-path routing
---------------------------------------

``qemu_plugin_spec_mode_begin`` / ``qemu_plugin_spec_mode_end`` set
and clear ``cpu->plugin_spec_mode`` without flushing the TLB.  Slow-
path memory routing during spec mode is enforced by ``CF_FORCE_SLOW``
on the cflags passed through ``cpu_plugin_exec_inline`` and
``cpu_plugin_exec_tb`` (``accel/tcg/cpu-exec.c``): spec-mode TBs
hash to a distinct ``tb_lookup`` key whose ``tb_gen_code`` emits the
slow-path memory helpers directly, with no dependence on TLB state.
A TLB flush at entry would be redundant (in CONFIG_USER_ONLY the
helper is the empty stub from ``include/exec/cputlb.h``, and in
system mode the spec-mode translation already bypasses the softmmu
TLB), and at exit it would be unnecessary because spec-mode TBs do
not populate the normal-mode TLB they bypass.

``tcg/i386/tcg-target.c.inc`` — ``prepare_host_addr``

   ``CF_FORCE_SLOW`` takes effect at code-generation time, in the TCG
   backend's guest-memory address preparation.  For a spec-mode TB the
   backend emits an unconditional jump to the slow-path helper call in
   place of the usual fast path, in both configurations: under softmmu
   this replaces the inline TLB lookup-and-compare — whose TLB-hit
   store would otherwise write real guest memory through the TLB
   entry's addend, bypassing the sandbox entirely — and in user mode
   it replaces the direct guest-base access.  Every wrong-path load
   and store therefore reaches the ``do_ld*`` / ``do_st*`` helpers,
   which is where the spec store buffer redirect and load overlay
   live.  Correct-path translation is untouched: the branch is keyed
   on the TB's cflags, and only spec-mode TBs carry the flag.

   ``CF_FORCE_SLOW`` is implemented in the i386 backend (which serves
   both x86 and x86-64 **hosts** — guest ISA coverage is unaffected),
   advertised by ``TCG_TARGET_HAS_SPEC_FORCE_SLOW`` in
   ``tcg/i386/tcg-target.h``.  A backend that does not honor the flag
   emits its normal fast path, whose TLB-hit store would otherwise
   write real guest memory.  For those hosts a second,
   backend-independent containment path applies in **system mode**:
   ``tlb_set_page_full`` (``accel/tcg/cputlb.c``, compiled in only
   where the backend lacks ``CF_FORCE_SLOW``) stamps ``TLB_FORCE_SLOW``
   on the data-load and data-store comparators of every TLB entry a
   speculative excursion installs, and ``cpu_plugin_spec_tlb_flush_enter``
   flushes any correct-path entries resident when the excursion begins
   so they refill carrying the flag.  Every backend's inline fast-path
   compare already treats a ``TLB_FORCE_SLOW`` entry as a miss, so
   speculative loads and stores route to the ``do_ld*`` / ``do_st*``
   helpers — and the spec store sandbox — on any host.

   ``cpu_plugin_spec_mode_supported`` (``accel/tcg/cpu-exec.c``) is the
   resulting capability gate: wrong-path containment holds when the host
   backend honors ``CF_FORCE_SLOW`` **or** the build is system-mode.
   The one uncontained configuration is user-mode tracing on a backend
   without ``CF_FORCE_SLOW`` — no softmmu TLB exists there to carry
   ``TLB_FORCE_SLOW``, so an inline store would commit to the guest
   image.  ``qemu_plugin_spec_mode_begin`` (``plugins/api.c``) guards
   against it: at the first speculative excursion it consults the gate
   and, when containment is unavailable, calls ``error_report`` and
   ``_exit(1)`` — refusing loudly rather than corrupting the guest image
   or silently disabling wrong-path tracing.  On x86 the capability is a
   compile-time constant, so the guard collapses to a no-op.  Porting
   fast-path containment to another host starts at that backend's
   address-preparation routine (``tcg/<host>/tcg-target.c.inc``); its
   softmmu paths are already covered by the portable ``TLB_FORCE_SLOW``
   path.

``include/elf.h``

   Adds the generic build-attributes section type
   ``SHT_ARM_ATTRIBUTES`` / ``SHT_RISCV_ATTRIBUTES`` and matching
   ``Tag_*`` enumerations, consumed by
   ``contrib/plugins/champsim_tracer/champsim_tracer_elf_attrs.h``
   to detect RVC, RVV, and TSO from the guest ELF rather than
   guessing.

``linux-user/plugin-api.c``

   One-line: pulls in ``loader.h`` so the plugin can call
   ``qemu_plugin_path_to_binary()`` from ``vcpu_init_cb`` to find
   the guest ELF for the build-attributes parse.

Bulk-memory instrumentation
---------------------------

A handful of AArch64 instructions move memory in bulk from inside a TCG
helper rather than through ``qemu_ld`` / ``qemu_st`` ops: the ARMv8.8
FEAT_MOPS families ``SETP`` / ``SETM`` / ``SETE`` and ``CPYP`` /
``CPYM`` / ``CPYE``, whose three-instruction triples implement a whole
``memset`` or ``memcpy``, and ``DC ZVA``, which zeroes a
cache-block-sized run.
Each helper takes a trapless ``tlb_vaddr_to_host()`` lookup and, on
success, transfers the page-bounded chunk with a host ``memset()`` or
``memmove()``.  Plugin memory instrumentation is emitted by ``accel/tcg``
around the *TCG* memory ops, so a bulk transfer that hits the
host-pointer fast path is invisible: the instruction reports no memory
access at all.  Only the byte-at-a-time fallbacks — taken for I/O,
watchpoints, unmapped pages and, in this fork, speculative execution —
are instrumented, which is why the wrong path records this traffic and
the correct path does not.

This matters far beyond exotic code.  glibc's AArch64 ``memcpy`` /
``memmove`` / ``memset`` dispatch to the FEAT_MOPS implementations
whenever ``HWCAP2_MOPS`` is set, which is the case on a ``-cpu max``
guest, so on the correct path an unfixed base hides essentially all of a
program's bulk memory traffic.

``target/arm/tcg/helper-a64.c`` — ``arm_plugin_bulk_mem_cb``

   Reports the transfer to the plugin layer explicitly.  The range is
   decomposed into naturally aligned power-of-two accesses of at most 16
   bytes and one ``qemu_plugin_vcpu_mem_cb`` is emitted per piece, so
   every access carries a real address, a real size and the right
   direction.  The 16-byte ceiling is the widest size the plugin memory
   API can describe (``qemu_plugin_mem_get_value()`` asserts above
   ``MO_128``), and AArch64 already issues 16-byte accesses for ``LDP`` /
   ``STP`` of Q registers and for the LSE 128-bit atomics, so a consumer
   sees no access shape it could not see already.  The whole body is
   gated on ``cpu->neg.plugin_mem_cbs``: with no plugin attached the cost
   is one load and one branch per page-sized chunk.

   The call sites are the four FEAT_MOPS step helpers ``set_step``,
   ``set_step_tags``, ``copy_step`` and ``copy_step_rev``.  A copy
   reports its load before the host ``memmove`` and its store after, so
   an overlapping ``memmove`` records the value each access actually saw.
   The copy helpers' *mixed* slow path — where only one of the source and
   destination resolved to a host pointer — is covered too: there the
   instrumented ``cpu_ldub`` / ``cpu_stb`` handles one side while the
   other is a bare host access, which would otherwise leave the copy
   reporting a store with no load or a load with no store.

   ``HELPER(dc_zva)`` is **not** a call site, though its bulk ``memset``
   has the identical defect.  Capstone decodes ``DC ZVA`` as the generic
   ``AARCH64_INS_SYS``, which the plugin's AArch64 mnemonic table
   classifies ``GEN_OP_VEC_LOGIC`` with no memory operand, so reported
   stores would land on a slot the trace declares incapable of touching
   memory and every trace containing a ``DC ZVA`` — the Linux
   ``clear_page``, for one — would fail the impossible-attribution lint.
   Reporting it needs that ``SYS`` classification fixed first, which in
   turn needs a decision on whether ``DC ZVA`` models as cache
   maintenance (whose ``GEN_OP_CACHE_FLUSH`` path synthesises a competing
   effective address) or as the block store it performs.  Until then a
   correct-path ``DC ZVA`` still records no memory access.

   The alternative fix is to make ``tlb_vaddr_to_host()`` honour
   ``cpu_plugin_mem_cbs_enabled()`` the way ``probe_access_flags()``
   already does, so these helpers fall back to their instrumented slow
   paths — which is how SVE contiguous loads, RISC-V vector and s390x
   already behave.  It is rejected here because those MOPS fallbacks
   transfer **one byte per iteration**: a 4 KiB page-sized step would
   surface as 4096 one-byte accesses instead of 256 sixteen-byte ones,
   exhausting the wire's 512 memop slots inside the first 512 bytes and
   turning every ``memcpy`` in the guest into a per-byte softmmu loop.

   The one instruction class this leaves bounded is the ``M`` member of
   each triple.  ``SETM`` and ``CPYM`` transfer every whole page of the
   operation in a single execution, so one instruction can issue
   arbitrarily many accesses — 3840 stores for a 64 KiB ``memset``.  The
   wire addresses at most ``CST_FID_SLOT_COUNT`` = 512 per direction per
   instruction; see :doc:`limitations` for what the trace carries past
   that point.

Build wiring
------------

``contrib/plugins/meson.build``

   Adds the C++ language requirement and lists every
   ``champsim_tracer/*.cc`` source so that meson builds the plugin
   as a single ``.so`` with the right Capstone dependency.  Also
   handles the Windows shared-module form by linking against the
   import library.

``meson.build`` and ``linux-user/meson.build``

   Threads the plugin sources through the top-level project so
   ``ninja contrib/plugins/libchampsim_tracer.so`` is enough to
   build the plugin from a configured QEMU build directory.
