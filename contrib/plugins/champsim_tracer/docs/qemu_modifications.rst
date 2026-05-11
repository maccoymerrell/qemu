QEMU base modifications
=======================

The ChampSim Tracer plugin is more than a self-contained ``.so``: it
relies on additions to QEMU's plugin API and on a handful of changes
to the TCG memory path so that the wrong-path simulator can mutate
guest registers and route guest stores through a per-vCPU speculative
buffer without corrupting the correct path.  This page enumerates
every patch we carry on top of upstream QEMU, why each is needed, and
where consumers should look for the matching code.

Plugin API additions
--------------------

``include/qemu/qemu-plugin.h`` (version bumped from 5 to 6)

   * ``qemu_plugin_insn_detail`` — Capstone-detail accessor that
     returns a structured ``qemu_plugin_insn_info`` for an
     in-flight ``qemu_plugin_insn`` (operands with type/access/size,
     implicit register reads/writes, instruction groups, x86
     prefix bits).  The plugin uses this in ``vcpu_tb_trans`` to
     classify each instruction without parsing disassembly strings.
   * ``qemu_plugin_cap_decode`` — same shape, but accepts a raw
     instruction byte buffer plus an explicit Capstone
     ``cs_arch`` / ``cs_mode`` pair.  Used for re-decoding the
     instructions of speculative basic blocks where we need the
     same Capstone view of bytes that the in-flight TCG translator
     wouldn't otherwise expose.
   * Bumped ``QEMU_PLUGIN_VERSION = 6`` to advertise the new entry
     points to plugin loaders.

``plugins/api.c`` and ``disas/disas-target.c``

   Glue.  ``qemu_plugin_insn_detail`` forwards to a new
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

Speculative-execution support
-----------------------------

The wrong-path simulator drives QEMU's TCG to execute speculatively-
chosen translations whose architectural side effects must be
discarded at the end of each WP chain.  That requires three things
that stock TCG doesn't provide: faults during translation must
unwind cleanly, stores must route through a per-vCPU buffer instead
of touching guest memory, and translation faults must not deliver a
signal to the guest.  The hooks below cooperate with the plugin's
``cpu->plugin_spec_mode`` flag (added in the same plugin commit
series) to give the WP simulator a usable speculative path.

``accel/tcg/cpu-exec.c`` — ``cpu_plugin_exec_tb``

   The ``sigsetjmp(cpu->jmp_env, 0)`` guard now wraps both
   ``tb_lookup`` and ``tb_gen_code``, not just ``cpu_tb_exec``.
   Translating a TB during plugin speculative execution can fault
   (e.g. ``translator_ld()`` crossing into an unmapped page), and
   that path siglongjmps through ``cpu->jmp_env``.  Without the
   guard moved up, the longjmp would unwind past the plugin
   callback frame and deadlock on the next call.

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
   PPC ``dcbz``).  These previously used a host fast-path memset
   when ``tlb_vaddr_to_host`` returned a usable pointer, bypassing
   the plugin's spec store buffer.  The patches drop the
   ``CONFIG_USER_ONLY`` gate around the ``cpu_st*`` slow path so
   that user-mode + speculative execution always routes through
   the buffer; non-speculative user-mode runs hit the slow path
   exactly when the host pointer is unavailable, the same as
   system mode.

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

Two cooperating patches are needed for plugin reads of EFLAGS to be
correct.  Both are scoped narrowly so non-plugin builds and
non-plugin TB execution are unchanged.

``target/i386/gdbstub.c`` — ``IDX_FLAGS_REG`` read path

   The ``x86_cpu_gdb_read_register`` case for ``IDX_FLAGS_REG`` now
   returns ``cpu_compute_eflags(env)`` instead of raw ``env->eflags``.
   ``cpu_compute_eflags`` dispatches on the current ``cc_op`` and
   resolves the lazy CC bits via ``cpu_cc_compute_all(env)`` before
   OR-ing them into the returned value.  Without this, the gdbstub
   path (which is what ``qemu_plugin_read_register`` ultimately
   reaches) emits only the non-lazy bits in ``env->eflags`` — useless
   for tracing.

``target/i386/tcg/translate.c`` — ``i386_tr_insn_start``

   The patch above is necessary but not sufficient.  ``cc_op`` itself
   is a TCG global written *lazily* by the translator via
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

   The fix calls ``gen_update_cc_op(dc)`` at the very top of
   ``i386_tr_insn_start`` when ``dcbase->plugin_enabled`` is set.
   That guarantees every insn boundary materialises the prior insn's
   ``cc_op`` into the TCG global before the next insn's plugin
   ``PLUGIN_GEN_FROM_INSN`` placeholder is emitted — so the R_REGS
   helper sees ``cc_op`` matching what the previous ALU op actually
   set.  Cost is one ``movi`` per insn boundary, gated on plugin
   active.

   The same problem in principle exists for any target that defers
   sync-point writes of shadow state across insns; the i386 patch
   here is the only target currently affected (AArch64 NZCV is
   updated eagerly).  A more general fix would be a per-arch
   "flush translator state before R_REGS callbacks" hook in
   ``accel/tcg/plugin-gen.c``; the localised i386 patch is the
   minimal version that catches the bug today.

The :doc:`validator`'s ``metaflags`` check is what surfaces this
class of bug:  it predicts the canonical Z / N / P bits from the
post-execution dst-register snap and asserts they match the
FID_METAFLAGS byte the writer derived from ``REG_FLAGS``.  Before
the two patches above were in place, every flag-writing x86
arithmetic insn miscompared.

Disassembly and target metadata
-------------------------------

``disas/capstone.c`` (the larger half of the diff)

   In addition to the plugin entry points above, this file gains a
   per-arch register-ID map.  Capstone's auto-generated
   ``getRegisterName()`` asserts on out-of-range IDs in
   ``CAPSTONE_DEBUG`` builds (the meson default).  We wrap each
   ``cs_reg_name()`` call with a per-arch upper bound (e.g.
   ``X86_REG_ENDING``) so the plugin can probe register IDs that
   appear in operand metadata without tripping the assert when
   Capstone exposes a sparse range.

``target/mips/cpu.c`` and ``configs/targets/mips*.mak`` plus
``gdb-xml/mips-cpu.xml`` / ``mips64-cpu.xml``

   Wires the MIPS GDB stub XML files into the build so the plugin's
   register-handle cache can resolve MIPS register names via
   ``qemu_plugin_get_registers()``.  Without these the cache returns
   empty for MIPS targets and ``regdata=1`` traces would have no
   register snapshots.

``target/riscv/cpu.h``

   Inserts the ``end_reset_fields`` marker into ``CPUArchState`` so
   ``cpu_reset()`` clears the right region.  Required for
   ``regdata=1`` on RISC-V where the previous boundary left the
   plugin's snapshot scratch in undefined state across reset.

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
