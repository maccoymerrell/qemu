Reference: the classification vocabularies
==========================================

The two sections below are carried verbatim, as sanctioned contract text,
from the original tree's ``docs/reference.rst`` (``champsim-trace`` at
``02d2e16c44``, sections "Generic opcodes" and "Branch types"): they are
the canonical ``GenericOpcode`` and ``BranchType`` name sets and their
meanings, the vocabulary the ``opcode`` and ``branch_type`` encoding maps
publish (:doc:`format`, Step 3).  Only the names and their meanings are
contract.  Statements in the carried text about how the original tree
produced a class (its Capstone-driven classifier and refiners, the
``champsim_tracer_generic_ids.h`` header, ``Stats`` arrays, and the
per-type wrong-path target rules) describe that implementation, not this
writer's: here QEMU's decode sites state a generic word per instruction
(``qemu_plugin_insn_decode()``), and the plugin's one vocabulary table
(``vocab.h``) maps each word to a ``GenericOpcode`` / ``BranchType`` pair
and refuses a word it has no row for; its wrong-path launch policy does not
read ``branch_type``.

.. _generic-opcodes:

Generic opcodes (``GenericOpcode``)
-----------------------------------

ISA-agnostic instruction classes.  Source of truth:
``champsim_tracer_generic_ids.h``.  Wire payload is a ``u8`` per
instruction in the templates section and (when an instance differs
from the template) inside ``CST_FID_INSN_OPCODE`` field-delta
records.

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Name
     - Notes
   * - ``GEN_OP_UNKNOWN``
     - Default for instructions the per-ISA classifier didn't recognize.
       A non-zero count in the exit-time summary's "Generic opcode
       breakdown" suggests the ``insn_classification`` table needs a row.
   * - ``GEN_OP_INT_ADD``
     - Integer addition.
   * - ``GEN_OP_INT_SUB``
     - Integer subtraction.
   * - ``GEN_OP_INT_MUL``
     - Integer multiplication.
   * - ``GEN_OP_INT_DIV``
     - Integer division / modulus.
   * - ``GEN_OP_AND``
     - Bitwise AND (integer).
   * - ``GEN_OP_OR``
     - Bitwise OR.
   * - ``GEN_OP_XOR``
     - Bitwise XOR. ``xor reg,reg`` is an idiomatic zero-clear and still
       classifies as XOR; the destination value is whatever semantic the
       consumer chooses.
   * - ``GEN_OP_NOT``
     - Bitwise complement.
   * - ``GEN_OP_SHL``
     - Logical shift left.
   * - ``GEN_OP_SHR``
     - Logical shift right. Arithmetic shift right (SAR) folds here — the
       sign behaviour is a value distinction, not a latency / dataflow
       one the consumer models.
   * - ``GEN_OP_ROL``
     - Rotate left.
   * - ``GEN_OP_ROR``
     - Rotate right.
   * - ``GEN_OP_BITMANIP``
     - Scalar bit-field / bit-count manipulation: BMI/BMI2 (``bextr``,
       ``blsi`` / ``blsmsk`` / ``blsr``, ``bzhi``, ``pdep``, ``pext``),
       ``popcnt``, ``lzcnt`` / ``tzcnt``, ``bsf`` / ``bsr``. Distinct
       from the boolean ``GEN_OP_AND`` / ``OR`` / ... class: these
       rearrange / extract / count bits and on real cores occupy a
       separate port with multi-cycle latency.
   * - ``GEN_OP_MOV``
     - Data movement. The classifier maps a mnemonic to ``MOV`` *as a
       whole* — operand inspection does not split memory-form and
       register-form variants. On x86 this means ``mov`` is always
       ``GEN_OP_MOV`` whether the operands are reg-reg, reg-mem, mem-reg,
       or mem-imm; the resulting trace records memory addresses for the
       mem-form executions via ``CST_FID_LOAD_ADDR*`` /
       ``CST_FID_STORE_ADDR*`` and the opcode stays ``MOV``. On AArch64 /
       RISC-V / MIPS where load and store have distinct mnemonics,
       ``MOV`` covers only the register-transfer family.
   * - ``GEN_OP_LOAD``
     - Memory read. Fall-through classification: used when nothing *else*
       happens beyond fetching data. Heavy on AArch64 (``ldr``/``ld1``
       families), RISC-V (``lw``, ``ld``, ``fld``), and MIPS. On x86,
       common ``mov`` from memory is ``GEN_OP_MOV`` instead; ``LOAD`` is
       reserved for specialized forms — FPU control-word loads
       (``fldcw``, ``fldenv``), state-restore (``xrstor``, ``fxrstor``),
       gather (``vgather*``, ``vpgather*``), MPX (``bndldx``), and
       segment / system loads (``lds``, ``lgdt``, ``ltr``). Pairs with
       ``CST_FID_LOAD_ADDR*`` / ``CST_FID_LOAD_DATA*``.

       Exclusive-monitor primitives — MIPS ``ll`` / ``lld`` / ``lle`` /
       ``llwp``, RISC-V ``lr.{w,d}.*``, AArch64 ``ldxr`` / ``ldaxr`` /
       ``ldxp`` / ``ldaxp`` and their byte / halfword variants — are
       individually just tagged loads, so they classify as ``LOAD``
       *with* ``MF_ATOMIC``. Load-acquire (AArch64 ``ldar`` / ``ldapr`` /
       ``ldlar``, RISC-V ``.aq`` hints) are memory-ordered single loads
       and stay plain ``LOAD`` without ``MF_ATOMIC``.

       x86 gather (``vgather*`` / ``vpgather*``) classifies as
       ``GEN_OP_VEC_LOAD`` (SIMD-indexed load), not plain ``LOAD``.
   * - ``GEN_OP_STORE``
     - Memory write. Fall-through classification; mirror of ``LOAD``.
       Dominant on AArch64 (``str``/``st1``), RISC-V (``sw``, ``sd``,
       ``fsd``), and MIPS, marginal on x86 where ``mov`` to memory is
       ``GEN_OP_MOV``. x86 ``STORE`` covers FPU state-save (``fxsave``,
       ``xsave*``, ``fnstcw``, ``fnstenv``), scatter (``vscatter*``,
       ``maskmov*``), MPX (``bndstx``), system register stores (``sgdt``,
       ``stmxcsr``), and shadow-stack ops (``clrssbsy``, ``clzero``).
       Pairs with ``CST_FID_STORE_ADDR*`` / ``CST_FID_STORE_DATA*``.

       Exclusive-monitor primitives — MIPS ``sc`` / ``scd`` / ``sce`` /
       ``scwp``, RISC-V ``sc.{w,d}.*``, AArch64 ``stxr`` / ``stlxr`` /
       ``stxp`` / ``stlxp`` and their byte / halfword variants — are
       individually just tagged stores, so they classify as ``STORE``
       *with* ``MF_ATOMIC``. Store- release (AArch64 ``stlr`` /
       ``stllr``, RISC-V ``.rl`` hints) are memory-ordered single stores
       and stay plain ``STORE`` without ``MF_ATOMIC``.

       x86 string ops with implicit pointer arithmetic (``lodsb/w/d/q``,
       ``stosb/w/d/q``, ``insb/w/d``, ``outsb/w/d``) are *not* classified
       as ``LOAD`` / ``STORE`` — the implicit ``RSI`` / ``RDI ± op_size``
       advance is more specific than the data motion, so those
       instructions classify as ``GEN_OP_INT_ADD``. AArch64 ``ldr`` /
       ``str`` / ``ldp`` / ``stp`` with writeback addressing modes
       (``[Xn]!`` / ``[Xn], #imm``) take the same path: the runtime
       refiner detects the implicit base-register write and reclassifies
       to ``INT_ADD``.

       x86 scatter (``vscatter*`` / ``vpscatter*``) classifies as
       ``GEN_OP_VEC_STORE``; ``maskmov*`` stays ``STORE``.
   * - ``GEN_OP_PUSH``
     - Stack push (memory write + SP update). Almost exclusively x86
       (``push``, ``pusha*``, ``pushf*``, ``enter``); a few AArch64 /
       RISC-V mnemonics for shadow-stack and zcmp compressed-instruction
       families.
   * - ``GEN_OP_POP``
     - Stack pop. Same distribution as ``GEN_OP_PUSH``.
   * - ``GEN_OP_LEA``
     - Address computation: the instruction computes an
       address-shaped value into a register and performs no memory
       access. x86 ``lea``, AArch64 ``adr`` / ``adrp``, RISC-V
       ``auipc`` / ``la`` / ``sh{1,2,3}add``, MIPS ``aluipc`` /
       ``auipc`` / ``la`` / ``dla``.
   * - ``GEN_OP_MOVSX``
     - Sign-extending move.
   * - ``GEN_OP_MOVZX``
     - Zero-extending move.
   * - ``GEN_OP_XCHG``
     - Exchange. Reserved for instructions whose semantic IS a swap
       (register ↔ memory). Every classifier row that maps to ``XCHG``
       also sets ``MF_ATOMIC`` so the resulting insn sets the
       ``CST_INSN_FLAG_ATOMIC`` bit. Examples: x86 ``xchg`` /
       ``cmpxchg`` / ``cmpxchg8b`` / ``cmpxchg16b``; AArch64 ``cas{p}`` /
       ``swp`` / ``ldsmax`` / ``ldsmin`` / ``ldumax`` / ``ldumin``;
       RISC-V ``amoswap`` / ``amocas`` / ``amomax{u}`` / ``amomin{u}``;
       MIPS ``saa`` / ``saad``.

       Atomic RMW with a *specific* arithmetic op on the loaded data
       (AArch64 ``ldadd`` / ``ldclr`` / ``ldeor`` / ``ldset``, RISC-V
       ``amoadd`` / ``amoand`` / ``amoor`` / ``amoxor``, x86 ``xadd``)
       classifies as the arithmetic op with ``MF_ATOMIC``, *not* as
       ``XCHG`` — the swap is incidental to the modify.
   * - ``GEN_OP_CMP``
     - Compare (subtract-and-discard, sets flags). Examples: x86 ``cmp``
       and MPX bound-check (``bndcl`` / ``bndcu``); AArch64 ``ccmp`` /
       ``ccmn``; RISC-V CV-extension ``cv_cmp*``.
   * - ``GEN_OP_TEST``
     - Bitwise test (and-and-discard, sets flags). x86 ``test`` and
       bit-test family ``bt`` / ``btc`` / ``btr`` / ``bts``; AArch64
       ``tst*``; uncommon on RISC-V / MIPS where the compare op is fused
       into the branch.
   * - ``GEN_OP_BRANCH``
     - Control flow. Direction (taken / not-taken / fall-through) lives
       at runtime; the static branch flavour lives in ``branch_type``.
       Jumps, conditional jumps, and calls all share this opcode; the
       flavour split (``BRANCH_DIRECT_JUMP`` / ``BRANCH_INDIRECT_JUMP`` /
       ``BRANCH_DIRECT_CALL`` / ``BRANCH_INDIRECT_CALL`` /
       ``BRANCH_COND_DIRECT`` / ``BRANCH_RETURN``) is in ``branch_type``.
       Calls are kept distinct from jumps so a consumer can drive a
       return-address stack (see the branch-type table below).
   * - ``GEN_OP_RET``
     - Return from call. Always paired with ``branch_type =
       BRANCH_RETURN``. x86 ``ret`` / ``retf*`` / ``iret*`` get this;
       AArch64 ``ret`` gets this; RISC-V ``cm.popret*`` / ``dret`` and
       MIPS exception-return ``eret`` / ``deret`` get this.  Plain RISC-V
       ``ret`` (``jalr x0, ra, 0``) is recognized too — Capstone prints
       the ``ret`` alias and the decoder maps it to ``BRANCH_RETURN`` —
       but MIPS ``jr $ra`` is **not**: Capstone prints it as ``jr`` (no
       return alias) and the classifier does not inspect the ``ra``
       operand, so a MIPS function return is classified as a general
       ``BRANCH_INDIRECT_JUMP``.
   * - ``GEN_OP_FP_ADD``
     - Floating-point add.
   * - ``GEN_OP_FP_SUB``
     - Floating-point sub.
   * - ``GEN_OP_FP_MUL``
     - Floating-point mul.
   * - ``GEN_OP_FP_DIV``
     - Floating-point divide.
   * - ``GEN_OP_FP_SQRT``
     - Floating-point square root.
   * - ``GEN_OP_FP_MOV``
     - Floating-point move.
   * - ``GEN_OP_FP_CVT``
     - Floating-point conversion (between FP formats or to/from integer).
   * - ``GEN_OP_FP_CMP``
     - Floating-point compare.
   * - ``GEN_OP_VEC_ADD``
     - SIMD / vector add.
   * - ``GEN_OP_VEC_SUB``
     - SIMD / vector sub.
   * - ``GEN_OP_VEC_MUL``
     - SIMD / vector multiply.
   * - ``GEN_OP_VEC_DIV``
     - Packed FP / integer divide and reciprocal approximation
       (``rcpps``, ``vrcp14p*``, ``vrcp28*``).
   * - ``GEN_OP_VEC_SQRT``
     - Packed square root and reciprocal-sqrt approximation (``sqrtps``,
       ``rsqrtps``, ``vrsqrt14p*``).
   * - ``GEN_OP_VEC_MOV``
     - SIMD / vector move, incl. vector loads/stores (``vmovdqa`` /
       ``vmovups``, AArch64 NEON/SVE ``ld1``/``ld2``/``ld3``/``ld4`` and
       ``st1``..``st4`` structure loads/stores).

       A pure SIMD-width load/store with no compute may instead be
       ``GEN_OP_VEC_LOAD`` / ``GEN_OP_VEC_STORE`` (currently x86
       gather/scatter; the AArch64/RISC-V/MIPS vector-memory families
       still map here).
   * - ``GEN_OP_VEC_LOAD``
     - SIMD-width or SIMD-indexed (gather) load with no substantial
       compute — worth distinguishing from scalar ``GEN_OP_LOAD``. Per
       the load/store-yield rule, an instruction doing real compute is
       classified by that compute instead. x86 ``vgather*`` /
       ``vpgather*``.
   * - ``GEN_OP_VEC_STORE``
     - SIMD-width or SIMD-indexed (scatter) store; vector-store
       counterpart of ``GEN_OP_VEC_LOAD``. x86 ``vscatter*`` /
       ``vpscatter*``.
   * - ``GEN_OP_VEC_SHUF``
     - SIMD permute / shuffle / blend, incl. element insert/extract
       (``pinsr*`` / ``pextr*`` / ``insertps`` / ``extractps``).
   * - ``GEN_OP_VEC_LOGIC``
     - Bitwise operations on vector registers.
   * - ``GEN_OP_NOP``
     - No-op (architectural or padding).
   * - ``GEN_OP_SYSCALL``
     - System call, software interrupt or unconditional trap. Pairs with
       ``branch_type = BRANCH_SYSCALL_TYPE``. In WP simulation the chain
       continues past it at the fall-through; the call is suppressed. A
       *conditional* trap (MIPS ``teq`` family, x86 ``into`` / ``bound``)
       is not in this class — it carries no target, so it is a
       ``GEN_OP_CMP`` that may except.
   * - ``GEN_OP_FENCE``
     - Memory / instruction barrier. Every classifier row that maps to
       ``FENCE`` has ``MF_ATOMIC``, so the resulting insn always sets
       the ``CST_INSN_FLAG_ATOMIC`` bit. Examples: x86 ``mfence`` /
       ``lfence`` / ``sfence``, cache-wide ops without an address
       (``invd``, ``wbinvd``, ``serialize``); AArch64 ``dmb`` / ``dsb`` /
       ``isb`` / ``clrex``; RISC-V ``fence`` / ``fence.i``. Cache- and
       TLB-management opcodes that *carry an address operand* map to
       ``GEN_OP_CACHE_FLUSH`` / ``GEN_OP_TLB_FLUSH`` /
       ``GEN_OP_PREFETCH`` instead — see those rows below.
   * - ``GEN_OP_CMOV``
     - Conditional move.
   * - ``GEN_OP_SETCC``
     - Set-on-condition (writes 0 or 1 to a destination register).
   * - ``GEN_OP_NEG``
     - Two's-complement negate.
   * - ``GEN_OP_INC``
     - Integer increment-by-one (idiomatic ``inc reg``).
   * - ``GEN_OP_DEC``
     - Integer decrement-by-one.
   * - ``GEN_OP_INT_MADD``
     - Integer multiply-and-add.
   * - ``GEN_OP_INT_MSUB``
     - Integer multiply-and-sub.
   * - ``GEN_OP_FP_MADD``
     - Floating-point fused multiply-add.
   * - ``GEN_OP_FP_MSUB``
     - Floating-point fused multiply-sub.
   * - ``GEN_OP_VEC_MADD``
     - Vector fused multiply-add.
   * - ``GEN_OP_VEC_MSUB``
     - Vector fused multiply-sub.
   * - ``GEN_OP_PREFETCH``
     - Software prefetch hint. QEMU's TCG translates these to no-ops, so
       no real memop is emitted; the tracer synthesises a load memop
       carrying the computed effective address by reading base / index
       registers at exec time and applying ``ea = base + (index <<
       shift_amount) * scale + disp`` from the Capstone operand metadata.
       Examples: x86 ``prefetch*``, AArch64 ``prfm`` / ``prfum`` /
       ``pli``, RISC-V ``prefetch.{i,r,w}``, MIPS ``pref`` / ``prefe`` /
       ``prefx``.
   * - ``GEN_OP_CACHE_FLUSH``
     - Cache-line clean / flush / invalidate addressed at a specific
       line. Same synthetic-EA capture as ``GEN_OP_PREFETCH``. Always
       sets the ``CST_INSN_FLAG_ATOMIC`` bit. Examples: x86
       ``clflush*`` / ``clwb`` / ``cldemote``, AArch64 ``dc.*`` /
       ``ic.*``, RISC-V ``cbo.{clean,flush,inval}``, MIPS ``cache`` /
       ``cachee``. Cache-wide forms with no address (``invd``,
       ``wbinvd``) stay under ``GEN_OP_FENCE``.
   * - ``GEN_OP_TLB_FLUSH``
     - TLB-entry invalidation addressed at a specific page. Same
       synthetic-EA capture. Always sets the
       ``CST_INSN_FLAG_ATOMIC`` bit. Examples: x86 ``invlpg`` /
       ``invlpga``, AArch64 ``tlbi``, RISC-V ``sfence.vma`` /
       ``hfence.{g,v}vma`` / ``hinval.{g,v}vma`` / ``sinval.vma``, MIPS
       ``tlbp`` / ``tlbr`` / ``tlbwi`` / ``tlbwr`` / ``ginv*`` /
       ``tlbg*`` / ``tlbinv*``.
   * - ``GEN_OP_VEC_PREFETCH``
     - SIMD / gather-prefetch hint — one or more SIMD-indexed cache-line
       warms (x86 ``vgatherpf*`` / ``vscatterpf*``). Same synthetic-EA
       capture as ``GEN_OP_PREFETCH``; the address(es) ride the
       load-memop slot.
   * - ``GEN_OP_INT_ALU_SHORT``
     - *Reserved fallback.* Coarse "single-cycle integer ALU op" bucket
       for external trace writers that lack ISA-specific opcode metadata.
       Never emitted by the in-tree tracer. Consumers should accept it so
       foreign traces decode.
   * - ``GEN_OP_INT_ALU_LONG``
     - *Reserved fallback.* Coarse "long-latency integer op" bucket
       (multi-cycle multiplier, divider, etc.). Never emitted by the
       in-tree tracer.
   * - ``GEN_OP_FP_ALU_SHORT``
     - *Reserved fallback.* Single-cycle floating-point op bucket. Never
       emitted by the in-tree tracer.
   * - ``GEN_OP_FP_ALU_LONG``
     - *Reserved fallback.* Long-latency floating-point op bucket (FDIV,
       FSQRT, transcendentals, etc.). Never emitted by the in-tree
       tracer.
   * - ``GEN_OP_VEC_ALU_SHORT``
     - *Reserved fallback.* Single-cycle vector / SIMD op bucket. Never
       emitted by the in-tree tracer.
   * - ``GEN_OP_VEC_ALU_LONG``
     - *Reserved fallback.* Long-latency vector / SIMD op bucket. Never
       emitted by the in-tree tracer.

       ``GEN_OP_COUNT`` is the in-tree enum sentinel; per-CP and
       per-WP attribution arrays in ``Stats`` are sized by it so
       adding a new opcode automatically extends the histograms.

Numeric IDs are the current in-tree enum assignment, **not** a wire
contract: every trace embeds an opcode encoding map (Step 3 of
:doc:`format`) and consumers resolve names through it.  ``GEN_OP_COUNT``
is the enum sentinel; the per-CP / per-WP attribution arrays in
``Stats`` are sized by it so adding an opcode extends the
histograms automatically.

.. _branch-types:

Branch types (``BranchType``)
-----------------------------

``u8`` field on every template instruction; sparse-recorded via
``CST_FID_INSN_BRANCH_TYPE`` when an instance overrides the template.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Name
     - Notes
   * - ``BRANCH_NONE``
     - Not a branch.  Templates default to this for all but the
       last instruction (after delay-slot normalization, where
       applicable).
   * - ``BRANCH_DIRECT_JUMP``
     - Plain jump with a direct target encoded in the instruction
       (``jmp imm``), plus — when the per-ISA classifier flagged the
       row ``MF_CONDITIONAL`` *but* the table left it ``DIRECT_JUMP``
       — conditional direct branches that didn't get the dedicated
       ``COND_DIRECT`` classification.  Calls have their own types
       (below).  WP-target resolution treats a taken instance as
       fall-through; if the instance was *also* conditional and fell
       through, the WP target is the translator-resolved static
       target reported by ``qemu_plugin_insn_branch_target_pc`` (not
       Capstone's branch immediate, whose encoding is ISA-specific).
   * - ``BRANCH_INDIRECT_JUMP``
     - Plain jump to a computed (register/memory) target.  WP-target
       picking: with ≥2 distinct historic targets observed, return
       the most-frequent target other than this execution's actual
       one; with one observed target, fall back to the fall-through
       PC (so single-target indirect jumps in trampolines don't
       produce all-CP WP slices).
   * - ``BRANCH_DIRECT_CALL``
     - Call with a static (immediate/relative) target — links the
       return address.  aarch64 ``bl``, mips ``jal``/``bal``, x86
       ``call imm``, riscv ``jal`` (rd != x0).  An unconditional
       direct call has a single target, so it produces no wrong
       path.  Pairs ~1:1 with ``BRANCH_RETURN`` (modulo tail calls /
       PIC thunks / setjmp).
   * - ``BRANCH_INDIRECT_CALL``
     - Call to a computed (register/memory) target.  aarch64
       ``blr``, mips ``jalr``/``jialc``, x86 ``call reg``/``call mem``
       (the per-row refine rewrites ``DIRECT_CALL`` to this when the
       target operand isn't an immediate), riscv ``jalr`` (rd != x0).
       WP-target picking is the indirect rule (grouped with
       ``BRANCH_INDIRECT_JUMP`` / ``BRANCH_RETURN``).
   * - ``BRANCH_RETURN``
     - Indirect via return address.  Grouped with
       ``BRANCH_INDIRECT_JUMP`` in WP-target picking — same rule.
   * - ``BRANCH_SYSCALL_TYPE``
     - System-call-style transfer: a syscall (``syscall``, ``svc``,
       ``ecall``), a software interrupt (``int``) or an unconditional
       trap (``ud2``, ``brk``, ``ebreak``, ``break``) — anything that
       always transfers to a vector.  Its taken side is a privilege
       escalation the speculative model cannot follow, so on the wrong
       path it behaves as an unfollowable taken edge: the block is
       sealed there and the excursion continues on the NOT-taken side,
       the architectural fall-through, exactly as for any other branch.
       The instruction raises (that is how it leaves speculative
       execution) so the block carries ``CST_BB_FLAG_SYNTHETIC_FAULT``
       with ``CST_FID_BB_FAULT_INSN`` at it, and
       the call is never performed — the syscall's result registers hold
       the deterministic placeholder.  A *conditional* trap has no
       target and does not belong here; see ``GEN_OP_CMP``.
   * - ``BRANCH_COND_DIRECT``
     - PC-relative conditional.  WP target is the *not-taken*
       static target when CP took the branch (i.e., the
       fall-through PC), and the static taken target — the
       translator-resolved value from
       ``qemu_plugin_insn_branch_target_pc``, not the raw encoded
       immediate — when CP fell through.
   * - ``BRANCH_REP``
     - Self-loop terminator for an instruction whose memory fan-out
       is bounded only by a register value: an x86 REP / REPNZ
       string op (MOVS / STOS / LODS / CMPS / SCAS / INS / OUTS) or
       an AArch64 FEAT_MOPS bulk copy/set (CPYP / CPYM / CPYE,
       CPYFP / CPYFM / CPYFE, SETP / SETM / SETE, SETGP / SETGM /
       SETGE and their option-suffixed variants).  Conditional
       self-loop: target = the instruction's own PC, fall-through =
       the next PC.  The tracer fans each iteration of the loop into
       its own true-BB visit; iter 1 stays on the BB that *enters*
       the loop, iter 2..N each emit on a 1-insn self-loop
       sub-template at the instruction's PC carrying that
       iteration's memops.  One iteration is one architectural
       element on x86 (1 load + 1 store for MOVS, 2 loads for CMPS,
       etc.) and one memory access on MOPS, which has no
       architectural iteration to count.  Distinguished from
       ``BRANCH_COND_DIRECT`` so simulators that model branch
       behaviour can skip target-diversity tracking here (target is
       always self-PC) and so the fan-out shape is obvious at
       template-parse time.


.. _dependency-blocks:

Dependency blocks: what this writer states
------------------------------------------

An instruction's dependency sub-block (:doc:`format`, Step 4.5) is only
ever a refinement of the all-to-all default, and the writer emits one only
where a mask is strictly smaller than that default.  Every mask is computed
from what QEMU states at translation -- the register list
(``qemu_plugin_insn_reg_list()``), the decode word
(``qemu_plugin_insn_decode()``) and the access statement
(``qemu_plugin_insn_access_list()``): per memory callback the translation
emits, the registers its decode site composed the address from (or that
the address is a constant the encoding fixes: absolute, or pc-relative and
folded), and, where the emission states it, the register the access moves.
Nothing is read from the instruction bytes and nothing is inferred from the
ops.

An access list is trusted for a direction only when it is complete there:
no helper that could access memory runs, or every execution delivered
exactly the listed count and no op branches over a listed access.  Slot
``k`` is taken to be the ``k``-th listed access only when no op branches
over one and every execution delivered the listed count; otherwise a
direction's slots share the union of its compositions.  A bulk (fan-out)
instruction, and one whose retranslation stated a different list, carries
no block.

The families, each named in ``<outfile>.deps.tsv`` per encoding with the
reason when none applies:

``address``
   ``HAS_ADDR`` only: each load and store address names the registers its
   composition reads.  Models address generation apart from data: a load
   issues when its address operands are ready, a store splits into its
   address and data halves.  A consumer reads a source that only address
   masks name as reaching the sinks through the memop (:doc:`format`,
   lane-granularity resolution, rule 2), which a saturated ``dst_dep`` /
   ``store_data_dep`` does through a load but not through a store: where a
   store's address names a source no load's address does and a register
   mask is saturated -- the stack pointer a ``call`` both addresses and
   moves -- the block states no address masks (``none:store-address`` in
   ``<outfile>.deps.tsv``).
``passthrough``
   By decode word (``mem.load``, ``mem.store``, ``int.mov``, ``int.movzx``,
   ``int.movsx``, ``fp.mov``, ``vec.load``, ``vec.store``, ``vec.mov``,
   the broadcasts ``vec.load.dup`` / ``vec.mov.dup``, and the written-back
   ``mem.load.wb`` / ``mem.store.wb``): a loaded value feeds the register
   the access names -- itself too, and the address
   registers, when that register is also a source (a merge such as MIPS
   ``lwl``); a data register no access names takes every load and the
   sources no load's address reads.  A store's datum is the register its
   access names, or nothing but the immediate for a constant.  A
   written-back base depends on itself and the sources the accesses do not
   move.  Models load-to-use wakeup on the load alone, store-data
   forwarding, and writeback address updates off the data path.
``vec-struct``
   ``passthrough`` whose loads name two or more vector registers (AArch64
   ``ld2``-``ld4``, ``ld1`` multiple): each register depends on its own
   structure elements.  Models per-register wakeup of de-interleaving
   structure loads.
``stack``
   ``mem.push`` / ``mem.pop``: the stack pointer depends only on itself
   (and the immediate), a pushed datum on the sources less the stack
   pointer and a load's address, a popped register on the loads.  Models a
   stack engine: pointer updates off the data path.

Absent from the families by design: an address computed into a register
(``int.lea``) keeps the default, which is already exact -- the registers
it reads are the ones its composition names; an atomic read-modify-write
keeps the default (the registers its accesses move are not stated); and a
register statement QEMU marked incomplete never gets ``HAS_REG``.

.. _lane-masks:

Lane masks: what this writer states
-----------------------------------

The four lane-mask families (:doc:`format`, "Vector lane masks") are body
fields: every execution of a ``CST_INSN_FLAG_VEC`` instruction publishes
its masks as deltas against the last ones, like every other slotted
field.  What they are computed from is QEMU's vector statement
(``qemu_plugin_insn_vector_shape()``), made where the emission holds the facts --
the element size, the bytes of each register operated on, whether the
active count is the encoding's or the ``vl`` register's, the element a
single-element form selects, whether the operation is element-wise, and
the registers a RISC-V V operand spans:

- the generic vector expanders state an element-wise operation of one
  element size over whole registers; an expander working on part of a
  register, or several of different shapes in one instruction, makes the
  statement MIXED, which carries no masks;
- AArch64: the multiple- and single-structure loads and stores (``ld1``-
  ``ld4``, ``st1``-``st4``, one lane), the replicating loads (``ld1r``-
  ``ld4r``) and the three-register vector floating-point funnel;
- x86: the packed SSE/AVX floating-point funnels, ``pinsr*`` /
  ``pextr*`` and the broadcasts (``vpbroadcast*``, ``vbroadcastss``,
  ``vbroadcasti128``), from memory or a register's element 0;
- RISC-V V: the single-width checks (``vv``/``vx``/``vi``/unary FP) and the
  unit-stride and strided loads and stores, unmasked and one field, the
  active count ``vl`` read at every execution;
- MIPS MSA: the I8, I5, BIT, 2R, 2RF, 3R and 3RF families (less the
  widening and narrowing members), ``ld.df`` / ``st.df``, ``insert`` /
  ``copy_*`` and ``fill``.

Every other vector encoding states no shape and carries no masks:
out-of-line helpers whose element size the emission does not hold
(``addp``, ``haddps``), widening and narrowing
forms, masked (predicated) RISC-V V forms -- their active elements are
``v0``'s to say -- segment accesses, SVE loads and stores.
``<outfile>.deps.tsv`` names each executed vector encoding ``masked``
(``masked-parallel``) or ``refused-<why>`` with its opcode family, and the
side log counts them.

Per execution, a vector register slot's mask is the shape's lanes -- for
an RVV one those below ``vl``, the members of a register group holding the
elements after its base's -- or the one element a single-element form
selects; a source that is also the destination (a merge, a pass-through)
is read whole, less a selected element.  Memop masks follow the rank rule
through the dependency block's association: the register a memop moves is
the one ``dst_dep`` / ``store_data_dep`` name for its slot (the access
statement's per-slot register where the block is per slot, else every
register, whose masks are the same), and the memops of a register take its
active lanes in slot order, each as many as its size spans in elements.
A group's elements past its base register take none.  A broadcast -- the
decode word ``vec.load.dup`` / ``vec.mov.dup``, one element replicated to
every lane -- is where the rank reading does not apply: every active lane
of the register takes its value from the one load, so that load's mask is
all of them (:doc:`format`: bit ``j`` iff lane ``j`` takes its value from
the load).

``CST_INSN_FLAG_LANE_PARALLEL`` is set from the ruled family list --
``VEC_ADD``, ``VEC_SUB``, ``VEC_MUL``, ``VEC_DIV``, ``VEC_SQRT``,
``VEC_MADD``, ``VEC_MSUB``, ``VEC_LOGIC`` -- for an instruction whose
emission QEMU states element-wise on every element; a pairwise, crypto or
reduction member of those families (stated no shape, or not
element-wise) keeps it clear.
