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

``include/qemu/qemu-plugin.h`` (``QEMU_PLUGIN_VERSION = 8``)

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
     re-translates through ``vcpu_tb_trans``.  ChampSim Tracer
     uses it at trace-segment boundaries: ``vcpu_tb_trans`` gates
     its expensive instrumentation work (Capstone decode, BBTemplate
     creation, per-insn memory callbacks) on
     ``g_trace_segments.is_active_atomic()``, so a cached
     translation taken on the inactive side of a window has none of
     the segment-time hooks.  Flushing on window-open forces a
     fresh translation pass while ``is_active`` is true, and the
     next TB exec arrives with full instrumentation in place.  The
     entry point is async-safe — QEMU schedules ``do_tb_flush`` to
     run between TBs (or synchronously when already in serial
     context), and any plugin ``flush_cb`` registered via
     ``qemu_plugin_register_flush_cb`` fires before the next TB
     executes.
   * ``QEMU_PLUGIN_VERSION = 8`` advertises these entry
     points to plugin loaders.

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

``accel/tcg/internal-common.h`` — ``spec_store_byte``

   The per-vCPU spec store buffer holds one ``g_hash_table`` node
   per speculative byte, so an unbounded wrong-path bulk store
   would exhaust memory and crash inside glib.  ``spec_store_byte``
   bounds the table at ``PLUGIN_SPEC_STORE_BUF_MAX`` (64 MiB of byte
   entries): beyond the limit no new keys are added, but existing
   keys still update so store-to-load forwarding stays correct for
   the tracked working set, and excess speculative stores are not
   forwarded.  The bound is ISA-generic — it applies to every target
   that routes stores through the buffer.

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
   * x86 store-form extract (``PEXTR`` / ``EXTRACTPS`` family).
     Capstone marks the ``r/m`` destination ``READ``-only;
     ``cap_fill_x86_operands`` forces ``WRITE`` on the memory
     operand.
   * x86 store-form data moves (``VMOVDQA`` / ``MOVUPS`` /
     ``VMOVUPS`` and kin writing memory).  Capstone marks the
     memory destination ``READ``-only; the same filler forces
     ``WRITE``.
   * MIPS memory access flags.  MSA vector loads/stores and the
     unaligned scalar family (``LWL`` / ``LWR`` / ``LDL`` / ``LDR``
     / ``SWL`` / ``SWR`` / ``SDL`` / ``SDR``) report their memory
     operand with ``access == 0``.  MIPS has no address-only
     memory-operand form, so a zero-access MIPS memory operand is
     always this defect; ``cap_fill_generic_operands`` infers the
     direction from the data register operand (a written data
     register implies a load, a read one implies a store).

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
