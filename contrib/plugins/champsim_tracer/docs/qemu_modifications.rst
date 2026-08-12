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
   * ``qemu_plugin_cpu_events_pending_slot`` — publish a per-vCPU
     scoreboard entry QEMU sets to 1 on every queue push and clears to
     0 on every drain.  It makes "is a drain owed on this vCPU"
     JIT-testable, which is what lets the tracer put a drain point at
     **every** translation-block entry for the price of one load and
     one brcond.  That is what bounds the queue: without it the queue's
     only consumer is the heavy ``vcpu_tb_exec`` callback, which is
     conditional on ownership and on a segment being active, so any
     window where those are false — a foreign address space, between
     segments, after the marker window closes — is a window where the
     grow-only queue has no consumer at all and its length becomes a
     function of untraced execution.  ``qemu_plugin_cpu_events_set``
     correspondingly no longer discards a pending backlog: a non-empty
     queue at that call is reported and aborts, because a silent
     discard there is a dropped event by another name.
   * ``qemu_plugin_cpu_events_stats`` — the queue's own high-water
     length and push/drain counts.  Produced by the producer, upstream
     of every plugin attribution decision, so a plugin gate that
     refuses a context cannot suppress it; ``CPU_PLUGIN_EVQ_STRUCTURAL_
     MAX`` in ``include/hw/core/cpu.h`` documents the ceiling the
     producer asserts (it aborts, it never caps or drops).
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
   * ``qemu_plugin_rep_iterations`` / ``qemu_plugin_rep_complete`` /
     ``qemu_plugin_rep_reenter`` / ``qemu_plugin_rep_chunk_boundary`` /
     ``qemu_plugin_rep_pc`` — the architectural self-loop accounting
     of the fan-out instruction the executing vCPU most recently ran.
     ``do_gen_rep`` (``target/i386/tcg/translate.c``) publishes the
     iteration count from the count register's own decrement, whether
     the repetition ended (the counter reached zero or a REPZ/REPNZ
     condition broke it), whether QEMU is about to re-enter the same
     instruction, whether that re-entry sits on a canonical chunk
     boundary (the exit the looping translation itself takes every
     65536 iterations — written-back counter ``65536*m + 1``; a
     looping translation's re-entries always do, a single-iteration
     translation computes it from the written-back counter), and
     which instruction the facts describe.  The chunk-boundary flag
     is what lets the window clock reproduce, under any translation,
     the per-TB-execution count the BBV plugin observes under the
     canonical translation: keep re-entries on a boundary, withhold
     the rest.

     They exist because a REP is not always translated as a loop:
     ``can_loop`` is false whenever ``CF_USE_ICOUNT`` or
     ``CF_SINGLE_STEP`` is set on the block or ``EFLAGS.TF`` or the
     interrupt shadow is live, and QEMU then generates one iteration
     and jumps back to the instruction's own address — including once
     after the iteration that exhausted the counter, a pass that does
     no architectural work.  An iteration count inferred from
     delivered memory-op callbacks inherits all of that, so the fan-out
     would gain an entry, and lose its architectural exit edge, purely
     because of a setting.  Reading the count register instead makes
     the emitted shape identical under ``-icount`` and without it, and
     on the wrong path — which ``cpu_plugin_exec_tb`` always
     single-steps — as on the correct path.  The accounting is written
     only when the block carries plugin instrumentation
     (``DisasContextBase::plugin_enabled``), so an uninstrumented QEMU
     pays nothing; targets with no fan-out instruction never write it,
     which is also how the plugin recognises that no architectural
     count is available.

     The AArch64 FEAT_MOPS bulk copy/set family publishes through the
     same four fields — ``do_SET``/``do_CPY``
     (``target/arm/tcg/translate-a64.c``) store the instruction's
     address at translation time, and the ``do_setX``/``do_cpyX``
     helpers (``target/arm/tcg/helper-a64.c``) publish per execution —
     with one semantic shift: MOPS has no architectural iteration, its
     fan-out unit is one memory access, so ``qemu_plugin_rep_iterations``
     counts the accesses that execution reported and
     ``qemu_plugin_rep_bytes`` anchors them in architectural state (the
     bytes moved, accumulated from the step helpers' returns — the size
     register's own decrement — so the delivered access sizes must sum
     to it).  ``reenter`` is true only at the helpers'
     ``cpu_loop_exit_requested`` splits, QEMU's implementation artifact;
     a guest-architectural fault leaves it false, as on x86.

     The MOPS helpers' byte-at-a-time fallbacks (watchpoints, clean
     pages, speculation) no longer report per byte: they accumulate
     into per-vCPU runs (``CPUState::plugin_mops_report``) and flush
     through the same naturally-aligned <=16-byte decomposition the
     host-pointer fast path reports, at the same page-bounded chunk
     boundaries — pending runs surviving fault and interrupt splits of
     the instruction, so the reported shape is split-invariant.
     Genuine device memory is the deliberate exception: a device
     observes byte accesses individually, so MMIO operands keep their
     per-byte reports (classified with ``tlb_vaddr_lookup_flags``, a
     side-effect-free raw-TLB-flag probe added to ``accel/tcg/cputlb.c``
     for exactly this distinction).  How the bytes are moved is
     unchanged everywhere; only the report is normalized.
   * ``qemu_plugin_in_spec_mode`` — the executing vCPU's speculative
     (wrong-path) mode flag, read from the vCPU itself.  The marker
     open/close callbacks gate on it so an invocation fired by a
     speculative execution is dropped on the QEMU-side ground truth,
     independent of any plugin thread-local session state.
   * ``qemu_plugin_vclock_pause`` / ``qemu_plugin_vclock_resume`` —
     nestable guest-virtual-clock freeze for plugin instrumentation
     windows (see *Guest-time transparency*, below).
   * ``qemu_plugin_vclock_ns`` — the read side of that clock, in
     nanoseconds: host wall time minus every interval a freeze was in
     effect, i.e. the time the *guest* believes has elapsed.  Ratioed
     against host wall time it is the guest realtime factor; ratioed
     against retired instructions it is the guest's instruction rate
     per guest-second, which is what decides how much periodic-tick
     work the guest is charged per unit of forward progress.  Returns
     0 in user mode (no guest clock) and under ``-icount`` (icount owns
     the virtual clock, and reading it from a vCPU callback with
     ``cpu->running && !can_do_io`` aborts with *Bad icount read*).
     Read-only, no BQL.
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
   * ``qemu_plugin_current_vcpu_index`` — the vCPU whose thread the
     calling code is on, or ``QEMU_PLUGIN_VCPU_NONE`` outside vCPU
     context.  That vCPU is the subject of every state API above that
     takes no vCPU argument, all of which assert on ``current_cpu``
     rather than answering when there is none; this lets a plugin ask
     instead of finding out by aborting.  It exists for the events QEMU
     MARSHALS onto a vCPU thread of its own choosing — the machine
     shutdown, below — where the vCPU carrying the callback and the vCPU
     the callback is about are different questions with different
     answers.
   * ``qemu_plugin_vaddr_to_paddr`` — debug-walks the executing vCPU's
     current translation to return the physical address a virtual
     address maps to (0 when unmapped).  It supplies the physical-page
     identity a narrow ASID cannot distinguish — two processes that
     alias the same short MIPS ASID still occupy distinct physical
     pages — and backs the ``physaddr=1`` per-memop physical-page
     records.
   * ``qemu_plugin_get_thread_ptr`` — the kernel-maintained per-thread
     pointer state for the running thread, giving guest-thread identity
     independent of the vCPU a thread happens to be scheduled on: x86-64
     ``FS.base``, AArch64 ``TPIDR_EL0``, MIPS CP0 ``UserLocal``, and on
     RISC-V the kernel's current-task pointer (whichever of ``tp`` /
     ``sscratch`` holds a kernel address — the trap entry swaps them, so
     neither register alone spans both privileges).  A TLS-less task
     leaves the TLS register 0, so at kernel privilege each target falls
     back to the guest kernel's own per-task contract for ``current``:
     AArch64 reports ``SP_EL0`` and MIPS ``$28`` **iff the value is a
     kernel VA** (the registers Linux keeps ``current`` /
     ``current_thread_info`` in while in-kernel), and x86-64 — whose
     kernel keeps no per-task pointer in a register — reads the per-CPU
     ``current_task`` pointer through the kernel GS base at the
     plugin-declared per-image offset (see
     ``qemu_plugin_set_current_task_offset`` below).  The plugin keys
     ``thread_id`` off it rather than the vCPU index.
   * ``qemu_plugin_thread_ptr_tracks_current`` — whether the value the
     hook above reports still names the executing software thread when
     sampled *above* user privilege.  It is a property of the sampling
     **context**, not a flat per-target answer, and the plugin re-asks it
     at every privileged sample rather than latching one verdict per run.
     MIPS ``UserLocal``, AArch64 ``TPIDR_EL0`` and x86-64 ``FS.base`` are
     the kernel's to reload and nobody else's, so a non-zero read answers
     yes at any privilege.  RISC-V answers yes at U and S privilege —
     where the reported value is the kernel's current-task pointer,
     selected from the ``tp``/``sscratch`` pair by which one holds a
     kernel address — and no in M-mode firmware and under H-extension
     virtualization.  The kernel-privilege fallbacks answer for
     themselves per sample: an AArch64/MIPS early-entry window (the
     interrupted user's value still in the register, not yet a kernel
     VA) and an x86-64 SWAPGS window (user GS base still live) or failed
     per-CPU read all answer no, and the consumer inherits the entering
     thread — which in every such window *is* the current task.  Where
     the answer is yes the plugin samples at that privilege level,
     which is what lets a guest context switch performed entirely inside
     the kernel retag the strand instead of leaving the work credited to
     whichever thread last returned to user on that vCPU.
   * ``qemu_plugin_set_current_task_offset`` — declares the per-image
     byte offset of the guest kernel's current-task pointer within its
     per-CPU region, for targets whose kernels keep no per-task pointer
     in a register at kernel privilege.  Linux/x86-64 reaches
     ``current`` through the swapped-in kernel GS base at the per-CPU
     offset of ``current_task`` (``pcpu_hot + 0`` on
     ``6.2 <= v < 6.14``) — a link-time constant unrecoverable from
     architectural state, so the tracer derives it per kernel build
     (symbol table, ``System.map``, or the guest's own
     ``/proc/kallsyms``; the validator's ``derive_curtask`` module
     automates all three) and passes it as the ``curtask_off=`` plugin
     option.  Undeclared, the target keeps its register-only contract
     unchanged: TLS-less tasks share the identity minted for 0 — honest
     indistinctness rather than a fabricated identity.
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
   MIPS from ``KSU`` / ``CP0 PWBase`` (``EntryHi.ASID`` on a model
   without ``Config3.PW``) / always-true (the MIPS TLB has no global
   enable) (``target/mips/cpu.c``).  ``plugins/api.c`` calls
   the hook when present and otherwise returns the user-mode defaults.
   The hook is gated ``CONFIG_PLUGIN && !CONFIG_USER_ONLY``; porting a
   new ISA to system-mode tracing means implementing it (see
   :doc:`extending`).

``include/accel/tcg/cpu-ops.h``, ``plugins/core.c`` and per-target
``TCGCPUOps::get_plugin_identity``

   Base QEMU keys its TLB on the translation regime (``mmu_idx``) and
   maintains no notion of WHICH address space a vCPU is in, so this is a
   new primitive rather than a re-export of an existing one.  A second
   optional ``TCGCPUOps`` callback,
   ``get_plugin_identity(cpu, *space_key, *thread_key)``, reports the
   RAW architectural identity keys; ``plugins/core.c`` interns each
   distinct key into a monotonically increasing id and caches the pair
   per vCPU (``CPUState::plugin_process_id`` /
   ``plugin_thread_id``), refreshing it at the address-space commit
   point (beside the ``ASID_WRITE`` push) and on demand from the API.
   Plugins receive only the ids, through
   ``qemu_plugin_get_process_id()`` and ``qemu_plugin_get_thread_id()``
   (``QEMU_PLUGIN_VERSION = 19``), so nothing a plugin does can come to
   depend on a target's register width, layout or reuse behaviour.

   Each target composes its keys only where the architecture itself
   splits the name across fields, and reads nothing but registers — no
   guest memory, no test of a value's *content*, no operating-system
   layout:

   * x86-64 — ``CR3``, with the PCID kept when ``CR4.PCIDE`` is set and
     the architecturally-ignored low 12 bits masked when it is not, and
     the NOFLUSH command bit (never stored state) always masked;
     ``FS.base``, or ``GS.base`` for a non-long-mode task.
   * AArch64 — ``TTBR0_EL1``'s table base recombined with the
     architectural ASID, which ``TCR_EL1.A1`` places in ``TTBR0_EL1`` or
     ``TTBR1_EL1``; ``TPIDR_EL0``.
   * RISC-V — ``SATP`` (already ``{MODE, ASID, PPN}``), or ``VSATP``
     under H-extension virtualization; ``tp`` (``x4``).
   * MIPS — ``CP0 PWBase``, the hardware page-table walker's base
     register, on a model implementing the walker (``Config3.PW``),
     normalised to a physical address when the kernel names it through
     kseg0/kseg1.  This makes MIPS the same kind of target as the other
     three: the key is the root the hardware translates from, per-``mm``,
     identical on every vCPU running that ``mm``, and distinct for a
     ``fork`` child from its first instruction.  Zero is **not** a
     fallback — a guest that never programmed the register (``nohtw``,
     ``CONFIG_MIPS_HTW=n``) reports an absence, and substituting the
     narrow tag there would silently restore the reuse hazard on exactly
     the boots where it is invisible.  A model without ``Config3.PW``
     reports ``EntryHi.ASID`` under the CPU's ASID mask, with
     ``CP0 MemoryMapID`` above it when ``Config5.MI`` makes MemoryMapID
     the TLB tag.  Thread key: ``CP0 UserLocal``.

   A key of 0 means "the architecture names nothing in this state" and
   is never interned, so id 0 is an *absence*, not an identity: a target
   with no hook (user-mode emulation, where a QEMU process is one
   address space) and a CPU model that implements no thread-pointer
   register (a MIPS model with ``Config3.ULRI`` clear) both report it,
   and a consumer must treat it as unknown rather than as a match.

   Registers that live in TCG globals (the x86 segment bases, RISC-V
   ``tp``) are only guaranteed spilled to the CPU state in a callback
   registered ``QEMU_PLUGIN_CB_R_REGS`` or ``QEMU_PLUGIN_CB_RW_REGS``;
   the per-vCPU memo makes a sample taken elsewhere self-correcting at
   the next coherent one rather than sticky.

``include/hw/core/cpu.h``, ``plugins/api-system.c`` and per-target
``CPUClass::plugin_identity_caps``

   A CLASS method — ``plugin_identity_caps(ObjectClass *oc)`` — reporting
   which identity keys the RESOLVED CPU MODEL can supply, exported to
   plugins as ``qemu_plugin_identity_caps()``.  It takes the class, not a
   ``CPUState``, because the question it answers has to be answerable
   from ``qemu_plugin_install()``: ``system/vl.c`` resolves
   ``current_machine->cpu_type`` from the board default and then from
   ``-cpu`` well before ``qmp_x_exit_preconfig()`` reaches
   ``qemu_init_board()``, which loads plugins and only then calls
   ``machine_run_board_init()``.  A plugin whose output would be invalid
   without a page-table root can therefore refuse the run before the
   first vCPU exists.

   It is installed from each target's own ``class_init`` (i386 and
   RISC-V in ``target/*/cpu.c``, not their ``tcg-cpu.c``): the
   accelerator's ``init_accel_cpu`` hook runs from
   ``accel_init_interfaces()``, which is called *inside*
   ``machine_run_board_init()`` — a caps method installed there would
   read NULL at exactly the moment it is asked for.

   x86-64, AArch64 and RISC-V answer ``SPACE_IS_ROOT | NAMES_THREAD``
   unconditionally.  MIPS reads its model definition's ``CP0_Config3``
   for ``PW`` (bit 24) and ``ULRI`` (bit 13); today only ``P5600``
   sets ``PW``.  ``-M none``, an unresolvable ``cpu_type`` and a target
   without the method all report an empty mask, so the safe answer is
   the default rather than an assumption.

``include/accel/tcg/cpu-ops.h`` and
``TCGCPUOps::get_plugin_narrow_asid``

   ``get_plugin_narrow_asid(cpu)``, exported as
   ``qemu_plugin_get_narrow_asid()``, reports the target's exhaustible
   TLB TAG where that is a different value from the page-table root —
   MIPS ``EntryHi.ASID`` (with ``MemoryMapID``).  NULL, hence 0, on
   x86-64, AArch64 and RISC-V, whose TLB tag is a field of the root
   register itself.

   It is explicitly **not** an identity, and the API documentation says
   so: an operating system re-points these tags at different live
   address spaces.  It exists so that a consumer can WITNESS that
   recycling with a value independent of the identity key it
   corroborates — a rollover test that measured the guest's ASID sweep
   through the ownership key would only be restating its own premise.

``target/mips/tcg/translate.c``, ``target/mips/tcg/system_helper.h.inc``
and ``target/mips/tcg/system/cp0_helper.c``

   ``mtc0``/``dmtc0`` to ``CP0 PWBase`` were inline TCG stores; they are
   now ``helper_mtc0_pwbase`` / ``helper_dmtc0_pwbase``.  The write is
   the MIPS ADDRESS-SPACE COMMIT POINT — Linux reaches it from
   ``htw_set_pwbase()`` inside ``TLBMISS_HANDLER_SETUP_PGD()``, i.e. at
   every ``switch_mm``/``activate_mm`` — so the plugin identity has to be
   resampled exactly there.  The helper stores the value and, only when
   it changed, pushes ``QEMU_PLUGIN_CPU_EVENT_ASID_WRITE``; there is no
   ``tlb_flush``, because PWBase says where the walker starts and
   invalidates no existing translation.  ``cpu_plugin_evq_push`` is inert
   on the wrong path and compiled out under ``--disable-plugins``,
   leaving one helper call per context switch.

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

   ``qemu_plugin_operand`` also carries ``sysreg_class``, the
   architectural role of a ``QEMU_PLUGIN_OP_SYSREG`` operand
   (``QEMU_PLUGIN_SYSREG_FLAGS`` / ``_FPCTRL`` / ``_VECCTRL`` /
   ``_THREADPTR`` / ``_OTHER``).  Capstone models system registers
   outside its register enum *and* has ids for almost none of them —
   two of the 1214 entries in ``aarch64_sysreg`` — so there is no
   register id to hand over and ``reg_id`` cannot be used to classify
   them.  ``cap_aarch64_sysreg_class`` and ``cap_riscv_csr_class``
   resolve the role here, beside the other Capstone workarounds,
   which keeps the per-ISA knowledge on the side of the boundary that
   already holds the rest of it; ``reg_id`` still carries the raw
   architectural encoding for identification.  The field occupies a
   pre-existing padding byte, so the structure's size is unchanged.

   The same operands need their ``access`` synthesised, because
   Capstone leaves the AArch64 system operand's access bits empty and
   reports every RISC-V CSR operand as read-modify-write:
   ``sysop.sub_type`` says whether an ``mrs`` reads or an ``msr``
   writes, and ``cap_riscv_csr_access`` applies Zicsr's rd/rs1
   suppression rules.

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

``qemu_plugin_vclock_ns`` (``plugins/api.c``)

   Read side of the freeze above, so a plugin that excludes its own
   cost from guest time can also observe what it left the guest
   believing.  The two ratios it supports are the guest realtime
   factor (guest ns per host ns) and the guest instruction rate per
   guest-second; the second is the denominator of the tick-tax
   relation ``HZ * N_tick / R_g``, whose value at 1 is the
   tick/scheduler storm described above.  The ChampSim Tracer's
   guest-progress detector is built on it.

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

A device timer may not re-arm itself at the current time
(``gic_vptimer_update``, ``hw/timer/mips_gictimer.c``)

   The freeze above makes ``QEMU_CLOCK_VIRTUAL`` stand still, and that
   turns a latent rule about ``QEMUTimer`` callbacks into a hard one:
   *a callback must never re-arm its own timer at a time that is not
   strictly later than the time it fired at.*

   ``timerlist_run_timers`` samples ``current_time`` **once**, before
   its callback loop, and ``timer_expired_ns`` counts
   ``expire_time <= current_time`` as expired.  A callback that re-arms
   at exactly ``now`` therefore has its timer popped straight back out
   of the list, and the loop — which the iothread runs holding the BQL
   — never ends.  Every vCPU starves behind the BQL and the guest stops
   dead while the process burns 100% of a core.

   With the clock running the hazard self-limits: ``now`` advances a
   nanosecond and the loop exits.  With the clock frozen it does not.

   The MIPS GIC per-VP timer computed ``wait = compare - count`` and
   re-armed at ``now + wait * TIMER_PERIOD`` with no clamp, so a guest
   that programs ``compare`` equal to the current count wedges the
   machine.  It is now clamped to a full counter wrap, which is also
   the architectural meaning of the equality match, and which is what
   the R4K CP0 timer next door (``cpu_mips_timer_update``,
   ``target/mips/system/cp0_timer.c``) already did for the identical
   arithmetic.

   This is an upstream QEMU defect, not a tracer limitation: the guest
   programming that triggers it is legal, and nothing about the tracer
   is required to reach it beyond a virtual clock that stops.  Any
   other device model with the same shape has the same obligation.

``timerlist_run_timers`` cannot loop on a timer callback (``util/qemu-timer.c``)

   The backstop for the rule above, because a rule enforced only in the
   one device known to have broken it is not enforced.  Two bounds sit
   in the callback loop.

   The first asks whether the DEADLINE MOVED FORWARD.  Every timer the
   pass runs is stamped with the pass number and the deadline it ran
   for; if the head of the list is a timer this pass already ran, is
   expired against the pass's sampled ``current_time``, and is now armed
   at a deadline no later than the one it ran for, it is deferred to the
   next pass and the devices involved are named — once per
   (armer, deferred) pair, so a second offending device is still heard
   and no one victim can consume the report for every device that arms
   it.

   The report names two callbacks, because two are involved and they are
   not always the same one: the callback of the timer being deferred,
   and the callback that ARMED that timer.  They coincide for a device
   re-arming its own timer and differ for a cycle of devices arming each
   other, where naming only the deferred timer points at the victim and
   leaves the offender unnamed.  The armer is read from the timer's own
   ``armed_by`` stamp, written by the arming itself, and not inferred
   from where the run loop happens to be standing.  The loop reaches the
   no-progress test once per callback and only sees an armed timer when
   it surfaces at the HEAD of the list, so any other timer due in the
   same pass is popped in between — two timers on one list sharing a
   deadline are enough, since a re-armed timer sorts behind the one
   already there.  "Whatever ran last" is therefore a bystander as often
   as it is the offender.  ``armed_by`` is ``NULL`` when the timer was
   armed from outside any timer callback, and the report says so rather
   than naming a device model it cannot identify.

   Testing the deadline rather than the timer's identity is what makes
   the bound both sound and quiet.  Quiet, because a timer coming back
   is the NORMAL terminating shape: a periodic device that fell behind
   re-arms at *fired-for + period*, strictly greater every time, so it
   catches up in a bounded number of iterations and the loop ends by
   itself.  ``pit_irq_timer`` (``hw/timer/i8254.c``) does exactly that on
   every x86 and malta boot, and an earlier version of this bound, which
   tested only "back at the head and expired", stopped it and consumed
   the one warning the process printed — so a device with the real
   defect would then have wedged the machine in silence.  Sound, because
   a cycle of devices arming EACH OTHER hits the same test: whichever
   one comes round first is being re-run for a deadline it already ran
   for.

   The second bound is a ceiling on callbacks per pass.  The first rests
   on a property of the device — "the deadline moved forward" — and a
   device that advances its deadline by a nanosecond against a backlog
   of seconds satisfies it while still running for hours inside one
   pass, holding the BQL.  The ceiling rests on nothing but arithmetic.

   Deferring drops nothing and drops the BQL in between, so the rest of
   the process runs: the iothread, the monitor, and — where the vCPU is
   not budget-gated — the vCPUs, which is how a frozen clock gets
   unfrozen and the deadline comes good.

   What deferral cannot do is make a device ask for a later deadline.
   A callback that re-arms at an ABSOLUTE time already behind the clock
   asks for the same past deadline on every pass, and under ``-icount``
   the guest then stops for good: ``qemu_clock_deadline_ns_all`` clamps
   an expired deadline to 0, ``icount_get_limit`` rounds that to a
   budget of 0, and ``rr_cpu_thread_fn`` answers a zero deadline
   through ``icount_handle_deadline`` by calling
   ``qemu_clock_run_timers`` itself — so the pass the bound ends is
   re-entered from the vCPU thread with the vCPU having retired nothing
   in between.  **What is bounded is the pass, not the machine.**  On
   the RISC-V trigger below as it stood before its repair, with the
   bound in, the offender is named and the monitor still answers while
   the guest is parked: ``icount_get_raw()`` reads 19 after five
   thousand callbacks and the PC never leaves the instruction after the
   arming ``csrw``.  With both bounds compiled out the same build
   prints no warning at all and the monitor cannot be reached, because
   the callback loop never returns and so never drops the BQL.
   Deferral buys the diagnosis and the management plane; only repairing
   the device buys the guest, which is why the entry below is a device
   fix and not a note about a backstop that covers it.

   ``tests/unit/test-timer-rearm-bound.c`` exercises all four shapes —
   self re-arm, mutual re-arm, a creeping deadline, and a healthy
   catch-up that must NOT be throttled — and the first three hang
   without these bounds.  Two further cases assert WHO the report names,
   in a subprocess, off the warning text: a self re-armer with an
   unrelated bystander timer due in the same pass must still read
   "re-armed its own timer", and a mutual pair must read "armed the
   timer of callback".  They read opposite values out of the same
   assertion, so neither is an unfalsifiable pass.

The RISC-V instruction-count trigger (``target/riscv/debug.c``)

   The first device the bound above named, and the reason this base
   carries the RISC-V trigger module in a working state rather than the
   state upstream ships it in.  A ``tdata1`` of type 3 arms a counter
   that falls by one for every instruction the guest retires at a
   privilege level the trigger is enabled for; the guest reads what is
   left of it back out of ``tdata1``.  Four properties make that true
   here, and each was false before.

   *Its deadline is a time.*  ``env->itrigger_timer[]`` is a
   ``timer_new_ns(QEMU_CLOCK_VIRTUAL)`` timer, and that clock reads
   ``qemu_icount_bias + icount_to_ns(icount)``.  Both arming sites —
   ``riscv_itrigger_update_count`` and ``itrigger_reg_write`` — arm at
   ``qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + icount_to_ns(count)``.  A
   raw instruction count is neither the bias nor the shifted count, so
   passing one directly is a deadline already in the past, and the
   callback's re-arming branch then asks for that same past deadline
   from inside its own callback: the vCPU never runs again.  That is the
   shape the no-progress bound catches, and catching it is how the
   deadline was identified.

   *A privilege level selects a bit.*  ``tdata1`` holds one enable bit
   per level, laid out so that the level's own encoding indexes them —
   ``ITRIGGER_U`` at bit 6 for ``PRV_U`` = 0, ``ITRIGGER_S`` at bit 7 for
   ``PRV_S`` = 1, ``ITRIGGER_M`` at bit 9 for ``PRV_M`` = 3, and the same
   shape one field along under virtualisation with ``ITRIGGER_VU`` at bit
   25 and ``ITRIGGER_VS`` at bit 26.  ``check_itrigger_priv`` selects the
   bit the current level names.  Comparing a one-bit field against a
   two-bit level instead is not a near miss but a different function
   entirely: it can never be true in M mode, and in U mode it is true of
   a level whose bit is CLEAR, so an M-only trigger counts the guest's
   user code and counts none of its own.  This is the same selection
   ``trigger_priv_match`` makes for the same trigger type, and the two
   have to agree — that one decides whether the trigger fires, this one
   decides which instructions it counted on the way there.

   *The count that is stored falls.*  When ``-icount`` is off the count
   is kept by ``helper_itrigger_match``, one decrement per instruction,
   and what it writes back is the decremented value.  Storing the value
   it already had leaves the whole non-icount path inert: the trigger
   counts for ever and never reaches zero.

   *The count that is read falls too.*  Under ``-icount`` the stored
   count is only brought up to date at a privilege change or a timer
   expiry, so a read has to account for the instructions retired since
   ``env->last_icount``.  Those instructions have been counted, so they
   come off — ``itrigger_get_adjust_count`` subtracts them.  Adding them
   makes the remaining count rise as the guest runs, which no reader can
   interpret.

   ``riscv_itrigger_enabled`` answers only whether any instruction-count
   trigger is armed, with no privilege test of its own.  Its answer gates
   ``gen_helper_itrigger_match`` and is cached in
   ``env->itrigger_enabled``, recomputed when ``tdata1`` is written and
   when a trigger reaches zero but never on a privilege change — so a
   privilege-dependent answer would be stale from the first ``mret``, and
   a trigger armed for U mode is always armed from M mode, where
   ``tdata1`` is writable.  The helper is what filters by level, in
   ``trigger_common_match``.

   ``tests/tcg/riscv64/itrigger-priv.S`` is the bare-metal proof, run
   both ways — ``run-itrigger-priv`` without ``-icount`` and
   ``run-itrigger-priv-icount`` with it, since the two paths keep the
   count by different means.  It arms one enable bit at a time, executes
   a loop of known length at M, S, U, VS and VU in turn, and reads the
   remaining count back: eighteen cells assert that the count falls by
   the loop's length at an enabled level and does not move at any other,
   including that a virtualised level consults only VS and VU and a
   non-virtualised one only U, S and M.  Five further cells repeat the
   measurement at two loop lengths and assert the difference, which
   cancels the fixed cost of arming, switching privilege and reading
   back, so what is asserted is the loop's instructions and nothing else.

   These are upstream QEMU defects rather than tracer limitations.  The
   programming that reaches them is a legal use of an architected
   debug facility, no part of the tracer is required to get there, and
   the hang the first one causes is reachable by any guest that arms an
   instruction-count trigger under ``-icount``.

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

   Two cooperating mechanisms hold the flush off until the walk has
   unwound.  Each region holds back a small reserve at the top:
   ``tcg_region_assign`` lowers ``code_gen_highwater`` by up to 2 MiB.
   When ``tb_gen_code`` overflows while ``cpu->plugin_spec_mode`` is
   set, it opens that reserve (``tcg_region_open_spec_reserve``) so the
   in-flight walk keeps translating, and records the owed flush in
   ``cpu->plugin_flush_pending`` rather than flushing in place.
   ``cpu_exec_loop`` honors that flag with the real ``tb_flush`` at its
   next safe point, after the walk has unwound and the correct-path TB
   has finished, so the flush recycles the whole buffer (reserve
   included) with no TB in flight.

   The reserve is finite, and both of its limits are reachable, so both
   are counted rather than described.
   ``qemu_plugin_spec_reserve_opens()`` is how many walks filled the
   buffer and were handed the reserve; each of those costs a full
   ``tb_flush`` the moment it unwinds, so the whole correct-path cache
   is retranslated for one excursion.
   ``qemu_plugin_spec_reserve_exhausted()`` is how many walks the
   reserve could not hold either: ``tb_gen_code`` returns ``NULL`` and
   the chain is cut at a depth set by how full the buffer happened to
   be.  That cut is HOST state, not guest state, so a wrong-path chain
   is only flush-invariant while this counter is zero — which is why
   the tracer reports it as ``WP chain cut by code-buffer (must be 0)``
   and does not charge it to ``WP first-TB unavailable``, the counter
   that means the guest could not supply the code.

   Measured, on a workload built so the wrong path (and only the wrong
   path) walks 20,000 never-executed basic blocks: at the default
   buffer size neither limit is reached at any ``wpdepth`` up to 65536.
   At ``-accel tcg,tb-size=8`` and ``wpdepth`` 16384 the reserve opens
   (21-26 times per run, no exhaustion).  At ``tb-size=4`` and
   ``wpdepth`` 65536 it opens 122 times and is exhausted 103 times in a
   single x86_64 run, which before the split showed up as 107 "first-TB
   unavailable" — a host code-buffer squeeze reported as absent guest
   code.  No configuration wedged; the cost is a translation storm
   (about 17x wall time), and cost is not the same thing as a hang.

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

``linux-user/signal.c`` — ``host_sigbus_handler``

   A host ``SIGBUS`` raised while QEMU is reading guest *code* is a
   fault the guest is entitled to take, not a QEMU bug.
   ``adjust_signal_pc()`` reports ``MMU_INST_FETCH`` for the
   ``cpu_ld*_code()`` case, ``helper_retaddr == 1``, and clears the pc,
   which is how it says the unwinder must not run because the guest pc
   already names the right instruction.  A cleared pc is never inside
   the code gen buffer, so the "not on behalf of the guest, therefore a
   host bug" test that guards ``die_from_signal()`` is asked only for
   the other access types — the exemption ``host_sigsegv_handler`` next
   door already carries.  The code read whose address a guest chooses
   outright is RISC-V Zcmt's ``cm.jalt``, which fetches its
   jump-vector-table entry through ``cpu_ldq_code()`` at an address the
   unprivileged ``jvt`` CSR names: aimed at a page of a file mapping
   lying past the end of that file, it raises ``BUS_ADRERR`` on the
   host, and the guest's own ``SIGBUS`` handler is what must run.
   ``tests/tcg/riscv64/test-sigbus-code-fetch.c`` is that guest.

   Every ``si_code`` other than ``BUS_ADRALN`` returns to
   ``host_signal_handler``, which queues a guest signal, and a
   wrong-path excursion may not leave one queued: the excursion is
   discarded, the signal is not, and it is delivered afterwards on the
   correct path, where nothing ever faulted.  Under
   ``plugin_spec_mode`` the handler therefore leaves by the route
   ``cpu_loop_exit_sigbus()`` takes for ``BUS_ADRALN``, and the
   wrong-path simulator sees an excursion that ended rather than a
   fault the guest took.
   ``tests/tcg/riscv64/test-sigbus-code-fetch-wp.c`` puts the same
   ``cm.jalt`` on the not-taken side of a taken branch, where only the
   wrong path reaches it.

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
   shadow line can be allocated, ``spec_atomic_shadow`` points the RMW
   at the per-vCPU scratch line
   ``CPUState::plugin_spec_atomic_scratch``, seeded with the same
   baseline bytes, and the result is discarded.  It never returns the
   real host pointer and offers its callers no way to obtain one, so a
   wrong-path atomic cannot mutate guest memory even under sandbox
   exhaustion.  The cost is store-to-load forwarding for that one
   access — the same degradation the plain store path takes when a
   capped pool drops a store.

   The distinction is worth stating plainly, because the two
   degradations sound interchangeable and are not.  A dropped
   speculative *store* writes nothing.  An atomic handed the real
   pointer would perform a real read-modify-write on real guest memory
   from the wrong path — architectural mutation that no rollback
   undoes.  "Drop the atomic" means discard it, never execute it
   somewhere real.

   As with the store buffer this is ISA-generic and covers user-mode
   wrong-path atomics too — and matters most there, since user mode has
   no softmmu TLB and therefore no ``TLB_FORCE_SLOW`` routing
   underneath the decision.

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
     VPE wake/sleep paths skip ``cpu_interrupt`` / ``halted``;
     ``mtc0 MVPControl`` and the ``DVPE`` / ``EVPE`` pair skip the
     shared ``env->mvp`` context, which every VPE points at and no
     single vCPU's snapshot covers.  ``cpu_mips_get_random`` answers a
     speculative ``mfc0 $Random`` without advancing its generator: the
     LCG's ``seed`` and ``prev_idx`` are file-scope statics, so they
     cannot be in the snapshot at all, and the sequence is not
     decorative — it chooses which entry the correct path's next
     ``TLBWR`` replaces, so an advance charged to the wrong path would
     change the correct path's TLB replacement pattern and with it the
     miss stream the trace exists to record.  ``TLBWR`` itself never
     arrives speculatively (``tcg/system/tlb_helper.c`` gates the whole
     TLB-write family, whose array likewise sits past the marker), so
     the ``mfc0`` read is the only speculative caller.

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

   The second escape route is architectural state the snapshot does not
   reach.  A register whose write is neither a device poke nor a
   guest-memory store still escapes if the register lives past
   ``end_reset_fields``, because that offset is precisely what
   ``cpu_plugin_arch_state_size()`` copies.  Two register files are in
   that position by necessity rather than oversight, and both are gated
   at their writers:

   * **x86 MTRRs and machine-check banks**
     (``target/i386/tcg/system/misc_helper.c``).  ``mtrr_fixed``,
     ``mtrr_deftype``, ``mtrr_var``, ``mcg_ctl`` and ``mce_banks`` are
     preserved across a CPU reset and so sit past the marker; a
     discarded ring-0 ``wrmsr`` would permanently rewrite the guest's
     memory-type and machine-check configuration.  ``mcg_status`` is
     deliberately left writable: it precedes the marker, is rolled back
     with the rest of the register file, and letting the wrong path
     write it keeps that path self-consistent with its own ``rdmsr``.
     Every other ``wrmsr`` destination in that helper — ``pat``,
     ``vm_hsave``, ``tsc_aux``, ``msr_ia32_misc_enable``,
     ``msr_bndcfgs``, ``pkrs``, ``msr_smi_count``, the ``SYSENTER`` and
     ``SYSCALL`` bases, ``efer`` — precedes the marker and is restored.

   * **Arm MPU and SAU** (``target/arm/helper.c``,
     ``arm_pmsa_write_discarded``).  ``pmsav7``, ``pmsav8`` and ``sau``
     hold their region descriptors in heap arrays the struct reaches
     through a pointer, and the pointers must survive a CPU reset, so
     the whole family sits past the marker.  A discarded write to
     ``PRBAR`` / ``PRLAR`` / ``PRSELR`` / ``HPRBAR`` / ``HPRLAR`` /
     ``HPRSELR`` / ``HPRENR`` / ``DRBAR`` / ``DRSR`` / ``DRACR`` /
     ``RGNR`` would permanently reprogram the guest's memory
     protection, with the ``tlb_flush()`` those writers perform already
     applied against it.  The reads are untouched: a wrong path is
     entitled to read architectural state and act on what it finds.
     ``ARM_CP_IO`` — the generic gate in ``target/arm/tcg/op_helper.c``
     — does not cover these, because a PMSA region register has no
     device side effect; it is ordinary CPU state that merely happens to
     live outside the snapshot.  The M-profile CPUs reach the same state
     through NVIC MMIO instead, which the spec store buffer already
     contains.

     ``target/arm/cpu.c`` carries the premise as three
     ``QEMU_BUILD_BUG_ON`` offset checks rather than as prose.  If the
     marker is ever moved to cover this state the rollback becomes
     automatic, the assertions fire, and the guard should go with them.

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

   * AArch64 ``SYS`` alias space (``DC`` / ``IC`` / ``AT`` / ``TLBI``).
     Not an access-flag bug but a modelling gap with the same effect.
     Capstone decodes every one of these to
     ``insn->id == AARCH64_INS_SYS`` and, for ``DC ZVA`` — which is not
     maintenance at all but a store of zeros over a whole
     ``DCZID_EL0``-sized block — provides no memory operand of any kind,
     only the ``Xt`` address register described as a plain read.  A
     consumer therefore mints no store lane, and every store the
     instruction performs is an attribution to an instruction that
     cannot perform one.  The structured detail *does* identify the
     operation exactly (``operands[0].type == AARCH64_OP_SYSALIAS``,
     ``sysop.sub_type == AARCH64_OP_DC``,
     ``sysop.alias.dc == AARCH64_DC_ZVA``), so
     ``cap_aarch64_is_block_zero_sysop`` uses it to recognise ``DC ZVA``
     and ``DC GZVA`` and present their ``Xt`` operand as the written
     memory operand it is.  Every other ``DC`` operation, and all of
     ``IC`` / ``AT`` / ``TLBI``, moves no architectural data and gets no
     memory operand.
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

A handful of instructions move memory in bulk from inside a TCG helper
rather than through ``qemu_ld`` / ``qemu_st`` ops.  On AArch64 these are
the ARMv8.8 FEAT_MOPS families ``SETP`` / ``SETM`` / ``SETE`` and
``CPYP`` / ``CPYM`` / ``CPYE``, whose three-instruction triples
implement a whole ``memset`` or ``memcpy``, and ``DC ZVA``, which zeroes
a cache-block-sized run; on PowerPC it is ``DCBZ``.
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

   ``HELPER(dc_zva)`` is a call site too.  ``DC ZVA, Xt`` zeroes a
   naturally aligned block whose size comes from ``DCZID_EL0.BS``,
   through the same bare host ``memset`` behind a trapless
   ``tlb_vaddr_to_host()``.  Linux's ``clear_page`` is built on it, so on
   a system-mode trace it carries a large share of all store traffic.
   The call passes the already block-aligned ``vaddr`` and the CPU's own
   ``blocklen``, so the decomposition is exact rather than assuming a
   block size — which matters, because the size is a property of the CPU
   model and not a constant: the same tracer sees 512-byte blocks under
   ``qemu-aarch64`` and 64-byte blocks under ``qemu-system-aarch64 -cpu
   max``, where ``clear_page`` accordingly loops 64 times to cover a
   4 KiB page.  The helper's two other exits zero the block with
   ``cpu_stb_mmuidx_ra()`` and are instrumented already.

   Reporting it also required the instruction to be *classifiable* as a
   memory instruction, which it was not.  Capstone folds the whole
   ``DC`` / ``IC`` / ``AT`` / ``TLBI`` alias space into
   ``AARCH64_INS_SYS`` and gives ``DC ZVA`` no memory operand at all, so
   the plugin classified it ``GEN_OP_VEC_LOGIC`` and any store reported
   against it was an impossible attribution — which is why an earlier
   attempt at this call site had to be withdrawn.  ``disas/capstone.c``
   (``cap_aarch64_is_block_zero_sysop``) now recognises the block-zeroing
   operations from Capstone's structured sysop detail
   (``sysop.sub_type == AARCH64_OP_DC`` with
   ``sysop.alias.dc == AARCH64_DC_ZVA`` or ``_GZVA``) and presents their
   ``Xt`` operand as the written memory operand it really is; the
   plugin's ``refine_arm64_sysop`` then classifies them ``GEN_OP_STORE``
   and leaves the rest of the ``SYS`` space as maintenance.  The block
   size is deliberately not encoded at the disassembly boundary — it is a
   runtime CPU property, not a property of the encoding — so the sizes on
   the wire come from the helper.

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

``target/ppc/mem_helper.c`` — ``ppc_plugin_block_zero_cb``

   PowerPC's ``DCBZ`` is the same instruction shape and had the same
   defect.  ``dcbz_common()`` clears a whole d-cache block, and in user
   mode its ``tlb_vaddr_to_host()`` lookup is a bare ``g2h()`` that
   always succeeds on a mapped page, so the host ``memset()`` behind it
   is the *only* path a correct-path ``DCBZ`` ever takes and the whole
   block clear is invisible to a plugin.  System mode was already
   correct by accident of using ``probe_write()``, which passes
   ``check_mem_cbs=true`` and so hands back NULL while a plugin has
   memory callbacks registered, sending the clear down the instrumented
   quadword loop.

   The reporter is the ppc twin of the AArch64 one: same 16-byte
   naturally aligned decomposition, same ``cpu->neg.plugin_mem_cbs``
   gate, and the stored value is zero by construction.  ``@addr`` is
   already aligned down to the block and the size is the CPU's own
   ``dcache_line_size``, so the decomposition is exact.  The slow path
   above it needs no such call — its ``cpu_stq_mmuidx_ra()`` stores are
   instrumented already.  The rest of the file's bulk helpers
   (``lmw`` / ``stmw`` / ``lsw`` / ``stsw``) reach their host pointer
   through ``probe_access()`` and therefore fall back correctly on their
   own.

   ``tests/tcg/ppc64/dcbz-instrumentation.c`` holds the invariant.  Every
   access it makes to its test region is a ``DCBZ``; it prints the region
   bounds and the number of accesses that amounts to, and the existing
   ``validate-memory-counts.py`` compares that against what the ``mem``
   plugin saw.  Against a target that does not report, the plugin sees no
   accesses to the region at all and the check fails.

Machine-shutdown notification
-----------------------------

``include/qemu/qemu-plugin.h``, ``plugins/core.c``, ``plugins/system.c``,
``include/qemu/plugin.h``, ``system/runstate.c``

   Adds ``qemu_plugin_register_vm_shutdown_cb()`` (plugin API version
   16): the machine is going down, close what you have open.

   The callback's CONTRACT has moved twice.  ``in_guest_insn`` was
   added below, and it was added while the version constant still read
   19 — so 19 names both the two-argument and the three-argument
   callback and cannot be honoured either way.  Version 21 then changed
   what ``vcpu_index`` means without touching the argument list at all:
   the same three arguments now carry the vCPU the shutdown CAME FROM
   where they used to carry the vCPU the callback was PLACED on.  That
   second move leaves no trace a compiler or a linker can find, so the
   version number is the only thing that can separate the two readings.

   ``QEMU_PLUGIN_MIN_VERSION`` is 2 and deliberately stays there, since
   raising it to cover one API would reject every unrelated old plugin
   as well.  The gate is instead at the entry point:
   ``qemu_plugin_register_vm_shutdown_cb()`` refuses a plugin declaring
   below version 21 and says to rebuild.  A plugin built at 20 would
   read ``QEMU_PLUGIN_VCPU_UNNAMED`` as the old "no vCPU exists" and
   close its capture without ever looking at the machine, on a route
   where the machine is right there and readable.

   Two earlier entry points changed signature the same silent way and
   are gated the same way: ``qemu_plugin_spec_mode_begin()`` gained
   ``saved_state`` inside version 5 and requires 6, and
   ``qemu_plugin_register_devio_cb()`` gained ``doorbell_cb`` inside
   version 12 and requires 13.  The devio one is the dangerous shape —
   the argument was INSERTED, not appended, so a version-12 caller's
   callbacks land one slot over and the stop slot is filled from a
   register that caller never wrote.

   The existing ``qemu_plugin_register_atexit_cb()`` cannot serve this
   purpose in system emulation.  It fires from libc's ``atexit(3)``,
   which runs *after* ``qemu_cleanup()`` has stopped every vCPU and torn
   the machine down, on a thread that is not a vCPU thread — so
   ``current_cpu`` is ``NULL`` and every plugin API that resolves through
   it (guest memory, registers, privilege level, address space) is
   unusable.  A plugin that must *close* something rather than merely
   free it therefore cannot close it there.  Before this hook, a marker
   window still open at guest poweroff took the tracer's emit path down
   that road and QEMU aborted in
   ``plugins/api.c: plugin_cpu_state: assertion failed: (current_cpu)``.

   The dispatch is placed to be both EARLY and ON A vCPU:

   * ``qemu_system_shutdown_request()`` — the guest poweroff / reset /
     monitor / QMP path.  A guest that powers itself off reaches this
     from its own instruction stream, so it arrives on that vCPU's own
     thread with its state live — and with the BQL held, because the
     CONDUIT belongs to the machine and not to this interface: an x86-64
     guest writes the ACPI sleep register and the request comes out of
     the store (``do_st_mmio_leN`` took the lock); an ``-M virt``
     aarch64 guest executes ``hvc #0`` and QEMU answers it itself as
     PSCI ``SYSTEM_OFF`` (``target/arm/tcg/psci.c``, reached from
     ``arm_cpu_do_interrupt()`` — exception delivery, with no device
     write anywhere in it, and the lock held just the same).  The
     dispatch therefore does not run inside the write: a synchronous
     callback here would hold the BQL against a plugin lock a peer vCPU
     can hold across a wrong-path excursion that needs the BQL — the
     same AB/BA the marshalled route below cures by dropping the lock,
     measured live on this route as a riscv64 -smp 4 guest poweroff
     standing in the shutdown callback beneath the syscon store while a
     peer's excursion waited on the BQL.  This lock is the device
     write's own and cannot be dropped mid-handler, so the work is
     QUEUED on the requesting vCPU instead and delivered at its next
     translation-block boundary, where the runner drops the BQL around
     the callback and forwards the origin index.  The request path does
     not wait; the second dispatch point below runs before teardown and
     waits for the delivery.
   * ``qemu_system_shutdown()`` in the main loop — the only path a HOST
     SIGNAL reaches, because ``qemu_system_killed()`` runs in a signal
     handler and sets ``shutdown_requested`` directly.  Here there is no
     ``current_cpu``, so the callback is marshalled onto a vCPU thread:
     the work is offered to every live vCPU with ``async_run_on_cpu()``
     and the first one to drain its work queue delivers it, at a
     translation-block boundary — outside any plugin callback, so the
     plugin's own locks are free.

   WHICH vCPU the marshalled callback lands on is decided by that race,
   and the callback says so rather than presenting the winner as a
   finding.  ``vcpu_index`` names the vCPU the shutdown CAME FROM: a
   real index on the guest-poweroff route, ``QEMU_PLUGIN_VCPU_UNNAMED``
   on the marshalled one, ``QEMU_PLUGIN_VCPU_NONE`` where no vCPU could
   be reached at all.  A plugin that needs to know whose registers it is
   about to read — the vCPU the no-argument state APIs resolve through —
   asks ``qemu_plugin_current_vcpu_index()``, and the two answers are
   deliberately separate calls because they are separate facts.  Under
   round-robin TCG they are not even the same vCPU: one vCPU's work
   queue is drained without ``current_cpu`` being pointed at it.

   Offering the work to every vCPU rather than to ``first_cpu`` is what
   makes the placement robust as well as honest.  ``first_cpu`` has no
   better claim than any other to be reachable; it may be halted, it may
   be stopped, and — the case that matters for this tracer — it may be
   the vCPU parked behind a plugin lock that another vCPU is holding.
   The offer to every vCPU means the callback runs as soon as ANY of
   them drains its work queue, and the lock-order inversion that could
   park the callback itself — arriving with the BQL held and then
   blocking on a plugin lock whose holder needs the BQL — is fixed at
   its source: the dispatch drops the BQL around the callback.

   The requester then waits, without bound, until some vCPU has
   delivered the callback.  Nothing times the wait and nothing steps
   around it: with the placement offered to every vCPU and the
   lock-order fixed, a wait that does not end is a vCPU that is
   genuinely not making progress, and that is a defect to be fixed
   where it lives rather than detected here.  The offer goes to every
   vCPU, so more than one can arrive; the one-shot claim is an atomic
   exchange rather than a plain flag, and a late arrival finds the hook
   already fired and does nothing.  ``QEMU_PLUGIN_VCPU_NONE`` is
   dispatched immediately — no wait — on the routes where no vCPU can
   be reached at all: none exists, none is live, or the requester does
   not hold the BQL that placing work requires.

   ``in_guest_insn`` reports POSITION, and it is a separate statement
   from ``vcpu_index``'s statement of ORIGIN.  It is true only where the
   callback really runs inside the instruction that caused the shutdown
   — a vCPU-context request that arrives without the BQL, which no
   ordinary route produces.  Everywhere a delivery runs at a
   translation-block boundary — the marshalled routes, and the
   guest-poweroff route whose dispatch is queued past the BQL-holding
   write — the last dispatched block completed and the flag is false; on
   the poweroff route the instruction that asked has retired by the time
   the callback runs, which is exactly what false reports.  A plugin
   closing a capture would otherwise have to guess, and either guess
   costs it: claiming an in-flight instruction publishes a block whose
   memops are incomplete (cst_audit's memop-bimodality oracle catches
   it), while discarding an instruction that did retire is a dropped
   instruction.  The tracer walks the slot's retired prefix and
   subtracts exactly the in-flight instruction when this flag says there
   is one, and the machinery keys off the flag rather than the route.

   WHICH instruction asked follows the conduit — ``outw %ax, %dx`` on
   x86-64 (the ACPI store), ``hvc #0`` on aarch64 ``-M virt`` — and the
   queued delivery is why the callback no longer stands inside it.  When
   the dispatch still ran inside the write, a probe plugin recording the
   last instruction to reach an execution callback read exactly those
   instructions at the callback, their memory operations only partly
   observed, and the tracer's drain subtracted the in-flight one on each
   ISA (``close_deferred_prev_inflight_trimmed`` read 1, and an aarch64
   final entry was the two-instruction PSCI stub ``bti c ; hvc #0``
   published as one instruction — measurements of the synchronous
   dispatch this seam has since replaced).  At the queued delivery the
   asking instruction has retired and its block is complete, so nothing
   is subtracted and the block is published whole; the trim machinery
   stays, driven by the flag, for any delivery that really is
   mid-instruction.

   The flag is INFERRED from ``current_cpu`` and the BQL at the request,
   which are facts about the thread rather than about the guest.  The
   two coincide wherever a shutdown request reaches
   ``qemu_system_shutdown_request()`` from inside ``cpu_exec()``, which
   is every route the guest itself can take to it — a device write and a
   trapped instruction alike, and every one of them holds the BQL, so
   every one of them takes the queued delivery and reports false.  The
   inference hazard this paragraph used to name — under ``-icount`` with
   round-robin TCG, ``icount_handle_deadline()`` runs
   ``QEMU_CLOCK_VIRTUAL`` timer callbacks on the vCPU thread with
   ``current_cpu`` still pointing at the vCPU of the previous loop
   iteration (``accel/tcg/tcg-accel-ops-icount.c``,
   ``accel/tcg/tcg-accel-ops-rr.c``), which the synchronous dispatch
   would have reported as in-guest while the last dispatched block was
   in fact complete — is confined by the same queueing: those timer
   callbacks run under the BQL, so a shutdown requested from one is
   queued and delivered at a boundary, false and correct.  What remains
   of the inference is only the no-BQL vCPU-context branch, which no
   route in this tree produces; the discriminator that would make the
   flag a fact rather than an inference there is ``cpu_exec()``'s own
   ``CPUState::running``, and it is still not applied, for the standing
   reason: a predicate whose failing arm cannot be made to fire is not
   a fix that can be shown to work.

   The contract is exercised by ``tests/plugin-shutdown/check.sh``,
   which builds a probe plugin and takes an x86-64 guest to a shutdown
   four ways: a guest poweroff must name the vCPU that performed the
   write and that vCPU must be the one whose state is live; a SIGTERM
   must name none and still run in vCPU context; a run whose first vCPU
   is stalled inside an instrumentation callback must still shut down
   promptly, on some other vCPU; and a run whose only vCPU is stalled
   must shut down on the bound, with the diagnostic.  All four cells are
   x86-64, so the check covers one of the two conduits: the trapped-call
   form an aarch64 ``-M virt`` guest uses is exercised by the cells
   described above and not by this script.

   Both run before ``qemu_cleanup()``, and the dispatch is idempotent:
   whichever fires first wins.  The hook lives in ``plugins/core.c``
   (registration + one-shot delivery) with the vCPU placement in
   ``plugins/system.c``, because ``run_on_cpu()`` is system-only.  With
   no plugin registered it is two predictable branches on a path taken
   once per run.

   The tracer uses it to close an open segment exactly the way an end
   marker closes one, which makes ``run target ; poweroff`` a capture
   that terminates by construction whatever the target does.  See
   :doc:`quickstart`.

Machine-reset notification
--------------------------

``include/qemu/qemu-plugin.h``, ``plugins/core.c``, ``plugins/system.c``,
``include/qemu/plugin.h``, ``system/runstate.c``

   Adds ``qemu_plugin_register_vm_reset_cb()`` (plugin API version 22):
   the machine is about to be torn down and booted again *inside the
   same process*.

   A guest RESET is the teardown the shutdown seam never sees.  With
   rebooting enabled (no ``-no-reboot``), ``qemu_system_reset_request()``
   sets ``reset_requested`` and the main loop pauses the vCPUs, resets
   the machine, and resumes it — no shutdown request, no
   ``qemu_cleanup()``, no atexit, so neither the shutdown callback nor
   the exit callback ever fires.  Everything a plugin has been recording
   stops being true at that boundary: the new world's kernel reallocates
   page tables, and every guest-derived identity (for this tracer, the
   pinned page-table root) is up for recycling by processes that have
   nothing to do with the traced one.  Measured before the seam existed:
   a marker window survived a guest ``reboot -f`` and 2.04e9 post-marker
   instructions, ended only by the any-context ceiling.

   The dispatch point is ``qemu_system_reset_request()`` itself, on the
   branch that will really reset — every delivery path funnels through
   it: the guest's reset device writes (x86 port 92h, the PIIX RCR and
   ICH9 RCR, the i8042 pulse, ACPI GED reset; Arm PSCI ``SYSTEM_RESET``;
   the RISC-V ``sifive_test`` finisher; the Malta ``SOFTRES`` register),
   the x86 triple fault (``target/i386/tcg/excp_helper.c``), a
   watchdog's reset action (``hw/watchdog/watchdog.c``), and a
   monitor/QMP ``system_reset``.  A request that ``-no-reboot`` (or
   non-resettable vCPUs) converts into a shutdown takes the shutdown
   dispatch in ``qemu_system_shutdown()`` instead — a reset is never
   reported as both.  Boot-time and wakeup resets call
   ``qemu_system_reset()`` directly, not the request, and are not
   events: nothing a plugin recorded predates the machine's first
   reset.

   Placement mirrors the shutdown seam, including the BQL discipline
   that seam measured and A/B-proved.  A guest-initiated request
   arrives on the responsible vCPU's own thread holding the BQL from
   the device write, so the dispatch is queued to that vCPU's next
   translation-block boundary (where the work runner drops the BQL
   around the callback, carrying the origin index); the reset
   performance in the main loop then waits, at
   ``qemu_plugin_vm_reset_wait_placed()``, for that delivery before the
   machine it must report on is torn down.  Monitor/QMP/watchdog
   requests are offered to every live vCPU, exactly like the marshalled
   shutdown.  Unlike the shutdown hook this one can fire more than once
   per run — each teardown is its own event, and only concurrent
   duplicates of the same event are folded.

   The tracer registers it always (system mode) and treats a reset with
   a window open as a named close route: the segment is finalised at
   the request, while the pre-reset machine still exists, with the
   close reason ``RESET`` and the ``closed by machine reset``
   statistics row, and the run then ends at the rebooted world's first
   translation — recording across the teardown would attribute the new
   world's execution, under recycled address-space names, to the dead
   pin.  A reset with no window open closes nothing and the run
   continues (a boot-chain reset before the workload is legitimate).
   See :doc:`quickstart`.

Guest threads in user mode
--------------------------

``do_fork`` (``linux-user/syscall.c``)

   A guest thread is a host thread, and ``do_fork()`` asks for it with
   an explicit ``NEW_STACK_SIZE`` of 256 KiB rather than the host C
   library's default, because a guest thread's host stack holds only
   QEMU's own interpreter frames.  That economy is conditional on
   something QEMU does not control: glibc places a thread's **static
   TLS block inside the stack allocation the attribute names**, and
   refuses ``pthread_create`` with ``EINVAL`` when what is left over
   falls below its minimum.  A QEMU binary whose static TLS approaches
   256 KiB therefore fails to create *any* guest thread, and fails the
   same way for every thread the guest will ever ask for — the guest
   sees a ``clone`` that cannot succeed.

   The condition is not hypothetical here: it was for a time the normal
   state of this tree, whose static TLS reached 0x63bc8 bytes when the
   per-translation dataflow scratch of ``accel/tcg/insn-dataflow.c``
   lived there (``df_out`` alone was 0x5e000), and every multithreaded
   guest program in ``*-linux-user`` failed on its first ``clone``.  That
   storage has since moved off static TLS — see the
   ``TCGContext::insn_df`` entry below, and the guard that keeps it off —
   and the emulators' static TLS is now 0x2c0 bytes.  The fallback here
   is not thereby redundant: it is what makes QEMU correct for whatever
   the number becomes, in a place where the failure is otherwise total
   and silent.

   The size is therefore a preference, not a requirement.  A refusal
   with ``EINVAL`` — the only error the two attributes QEMU sets can
   produce — drops the explicit size, warns once naming the reason, and
   creates the thread on the library's default stack, which is sized by
   the library that has to fit inside it.  The latch is process-wide
   and read under ``clone_lock``: nothing about the answer is
   per-thread, so the failed attempt is paid once.

   Sizing the request instead would mean knowing the static TLS
   requirement, which glibc exposes only as a ``GLIBC_PRIVATE`` symbol,
   so asking and being told no is the portable form of the question.

``insn_df`` (``include/tcg/tcg.h``, ``accel/tcg/insn-dataflow.c``)

   The dataflow extractor's per-translation scratch — the provenance
   table, the env-offset table, the interned field slots and the
   ``InsnDataflow`` result array, 376 KiB in total — hangs off the
   ``TCGContext``, allocated on that context's first translation and
   reused for every later one.  It sits beside ``plugin_tb`` in the same
   struct and on the same terms: allocated lazily, cleared but not freed
   per translation, never returned.

   The translation context is the object whose lifetime and exclusion
   this scratch actually needs.  In system mode there is one per
   translating vCPU, so the arrays are per-vCPU exactly as the
   extractor's non-reentrancy requires, and the total is bounded by
   ``tcg_max_ctxs`` rather than by how many threads the process happens
   to create.  In user mode every guest thread shares ``tcg_init_ctx``
   and translates only while holding the translation lock
   (``tb_gen_code()`` asserts it), so one scratch for all of them is
   both correct and cheaper than one apiece.  Keying on the context also
   agrees with the accessor guard in ``plugins/api.c``, which decides
   whether a result is still readable by comparing a plugin's ``tb``
   against ``tcg_ctx->plugin_tb``: guard and data are now fields of the
   same object.

   What it must not be is a thread-local.  Static TLS is allocated for
   every thread the process creates — vCPU, iothread, RCU, each guest
   thread — whether or not that thread ever translates anything, and
   glibc places it inside the stack allocation ``pthread_create`` is
   given, which is what broke guest-thread creation outright (see
   ``do_fork`` above).  A file-scope ``__thread`` pointer caches the
   binding so the per-op accessors cost a load; ``insn_dataflow_get()``
   and its two siblings treat a null one as "nothing extracted", which
   is the answer a caller arriving before any translation must get.

   ``tests/check-emulator-static-tls.sh``, attached by ``meson.build`` to
   every emulator as a build step, holds the invariant: a ``PT_TLS``
   MemSiz over 64 KiB fails the build and prints the offending TLS
   symbols.  The ceiling is a tripwire against growth tied to the failure
   it prevents — it leaves the great majority of a 256 KiB guest-thread
   stack for the stack — and raising it is a deliberate act that belongs
   with a re-measured multithreaded guest run.

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
