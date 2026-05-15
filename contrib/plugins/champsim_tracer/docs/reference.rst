Reference: symbolic IDs
=======================

The wire format encodes opcodes, branch types, register IDs, and
field IDs as ``u8`` integers.  The trace's encoding-maps section
(see :doc:`/format`) carries the canonical name for each value
inside the file itself, so a decoder reading a fresh trace never
needs to consult these tables.  This page exists for two cases:

* Decoding a trace produced by an older plugin build whose
  encoding maps are missing or stale.
* Producing a ``.cst`` trace from a non-QEMU source: a static
  binary translator, a different simulator, an ISA the QEMU plugin
  doesn't yet support.

Anyone in the second camp should treat the table below as the
authoritative list of *generally supported* IDs.  Producers may emit
values outside this set, but consumers (most importantly ChampSim's
decoder) do not have to handle them.

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
   :widths: 6 25 69

   * - ID
     - Name
     - Notes
   * - 0
     - ``GEN_OP_UNKNOWN``
     - Default for instructions the per-ISA classifier didn't
       recognize.  A non-zero count in the exit-time summary's
       "Generic opcode breakdown" suggests the
       ``insn_classification`` table needs a row.
   * - 1
     - ``GEN_OP_INT_ADD``
     - Integer addition.
   * - 2
     - ``GEN_OP_INT_SUB``
     - Integer subtraction.
   * - 3
     - ``GEN_OP_INT_MUL``
     - Integer multiplication.
   * - 4
     - ``GEN_OP_INT_DIV``
     - Integer division / modulus.
   * - 5
     - ``GEN_OP_AND``
     - Bitwise AND (integer).
   * - 6
     - ``GEN_OP_OR``
     - Bitwise OR.
   * - 7
     - ``GEN_OP_XOR``
     - Bitwise XOR.  ``xor reg,reg`` is an idiomatic zero-clear and
       still classifies as XOR; the destination value is whatever
       semantic the consumer chooses.
   * - 8
     - ``GEN_OP_NOT``
     - Bitwise complement.
   * - 9
     - ``GEN_OP_SHL``
     - Logical shift left.
   * - 10
     - ``GEN_OP_SHR``
     - Logical shift right.
   * - 11
     - ``GEN_OP_SAR``
     - Arithmetic shift right.
   * - 12
     - ``GEN_OP_ROL``
     - Rotate left.
   * - 13
     - ``GEN_OP_ROR``
     - Rotate right.
   * - 14
     - ``GEN_OP_MOV``
     - Data movement.  The classifier maps a mnemonic to ``MOV``
       *as a whole* — operand inspection does not split memory-form
       and register-form variants.  On x86 this means ``mov`` is
       always ``GEN_OP_MOV`` whether the operands are reg-reg,
       reg-mem, mem-reg, or mem-imm; the resulting trace records
       memory addresses for the mem-form executions via
       ``CST_FID_LOAD_ADDR*`` / ``CST_FID_STORE_ADDR*`` and the
       opcode stays ``MOV``.  On AArch64 / RISC-V / MIPS where load
       and store have distinct mnemonics, ``MOV`` covers only the
       register-transfer family.
   * - 15
     - ``GEN_OP_LOAD``
     - Memory read.  Fall-through classification: used when nothing
       *else* happens beyond fetching data.  Heavy on AArch64
       (``ldr``/``ld1`` families), RISC-V (``lw``, ``ld``, ``fld``),
       and MIPS.  On x86, common ``mov`` from memory is
       ``GEN_OP_MOV`` instead; ``LOAD`` is reserved for specialized
       forms — FPU control-word loads (``fldcw``, ``fldenv``),
       state-restore (``xrstor``, ``fxrstor``), gather
       (``vgather*``, ``vpgather*``), MPX (``bndldx``), and segment /
       system loads (``lds``, ``lgdt``, ``ltr``).  Pairs with
       ``CST_FID_LOAD_ADDR*`` / ``CST_FID_LOAD_DATA*``.

       Exclusive-monitor primitives — MIPS ``ll`` / ``lld`` /
       ``lle`` / ``llwp``, RISC-V ``lr.{w,d}.*``, AArch64 ``ldxr``
       / ``ldaxr`` / ``ldxp`` / ``ldaxp`` and their byte / halfword
       variants — are individually just tagged loads, so they
       classify as ``LOAD`` *with* ``MF_ATOMIC``.  Load-acquire
       (AArch64 ``ldar`` / ``ldapr`` / ``ldlar``, RISC-V ``.aq``
       hints) are memory-ordered single loads and stay plain
       ``LOAD`` without ``MF_ATOMIC``.
   * - 16
     - ``GEN_OP_STORE``
     - Memory write.  Fall-through classification; mirror of
       ``LOAD``.  Dominant on AArch64 (``str``/``st1``), RISC-V
       (``sw``, ``sd``, ``fsd``), and MIPS, marginal on x86 where
       ``mov`` to memory is ``GEN_OP_MOV``.  x86 ``STORE`` covers
       FPU state-save (``fxsave``, ``xsave*``, ``fnstcw``,
       ``fnstenv``), scatter (``vscatter*``, ``maskmov*``), MPX
       (``bndstx``), system register stores (``sgdt``,
       ``stmxcsr``), and shadow-stack ops (``clrssbsy``,
       ``clzero``).  Pairs with ``CST_FID_STORE_ADDR*`` /
       ``CST_FID_STORE_DATA*``.

       Exclusive-monitor primitives — MIPS ``sc`` / ``scd`` /
       ``sce`` / ``scwp``, RISC-V ``sc.{w,d}.*``, AArch64 ``stxr``
       / ``stlxr`` / ``stxp`` / ``stlxp`` and their byte /
       halfword variants — are individually just tagged stores, so
       they classify as ``STORE`` *with* ``MF_ATOMIC``.  Store-
       release (AArch64 ``stlr`` / ``stllr``, RISC-V ``.rl``
       hints) are memory-ordered single stores and stay plain
       ``STORE`` without ``MF_ATOMIC``.

       x86 string ops with implicit pointer arithmetic
       (``lodsb/w/d/q``, ``stosb/w/d/q``, ``insb/w/d``,
       ``outsb/w/d``) are *not* classified as ``LOAD`` / ``STORE``
       — the implicit ``RSI`` / ``RDI ± op_size`` advance is more
       specific than the data motion, so those instructions
       classify as ``GEN_OP_INT_ADD``.  AArch64 ``ldr`` / ``str``
       / ``ldp`` / ``stp`` with writeback addressing modes
       (``[Xn]!`` / ``[Xn], #imm``) take the same path: the
       runtime refiner detects the implicit base-register write
       and reclassifies to ``INT_ADD``.
   * - 17
     - ``GEN_OP_PUSH``
     - Stack push (memory write + SP update).  Almost exclusively
       x86 (``push``, ``pusha*``, ``pushf*``, ``enter``); a few
       AArch64 / RISC-V mnemonics for shadow-stack and zcmp
       compressed-instruction families.
   * - 18
     - ``GEN_OP_POP``
     - Stack pop.  Same distribution as ``GEN_OP_PUSH``.
   * - 19
     - ``GEN_OP_LEA``
     - Effective-address compute, no memory access despite the
       memory-style operand.  x86 ``lea``, AArch64 ``adr`` /
       ``adrp``, RISC-V ``auipc``, MIPS ``aluipc`` and similar
       PC-relative-offset-into-register operations.
   * - 20
     - ``GEN_OP_MOVSX``
     - Sign-extending move.
   * - 21
     - ``GEN_OP_MOVZX``
     - Zero-extending move.
   * - 22
     - ``GEN_OP_XCHG``
     - Exchange.  Reserved for instructions whose semantic IS a
       swap (register ↔ memory).  Every classifier row that maps to
       ``XCHG`` also sets ``MF_ATOMIC`` so the resulting insn
       carries ``the ``CST_INSN_FLAG_ATOMIC`` bit``.  Examples: x86 ``xchg``
       / ``cmpxchg`` / ``cmpxchg8b`` / ``cmpxchg16b``; AArch64
       ``cas{p}`` / ``swp`` / ``ldsmax`` / ``ldsmin`` / ``ldumax``
       / ``ldumin``; RISC-V ``amoswap`` / ``amocas`` /
       ``amomax{u}`` / ``amomin{u}``; MIPS ``saa`` / ``saad``.

       Atomic RMW with a *specific* arithmetic op on the loaded
       data (AArch64 ``ldadd`` / ``ldclr`` / ``ldeor`` / ``ldset``,
       RISC-V ``amoadd`` / ``amoand`` / ``amoor`` / ``amoxor``,
       x86 ``xadd``) classifies as the arithmetic op with
       ``MF_ATOMIC``, *not* as ``XCHG`` — the swap is incidental to
       the modify.
   * - 23
     - ``GEN_OP_CMP``
     - Compare (subtract-and-discard, sets flags).  Examples: x86
       ``cmp`` and MPX bound-check (``bndcl`` / ``bndcu``);
       AArch64 ``ccmp`` / ``ccmn``; RISC-V CV-extension
       ``cv_cmp*``.
   * - 24
     - ``GEN_OP_TEST``
     - Bitwise test (and-and-discard, sets flags).  x86 ``test``
       and bit-test family ``bt`` / ``btc`` / ``btr`` / ``bts``;
       AArch64 ``tst*``; uncommon on RISC-V / MIPS where the
       compare op is fused into the branch.
   * - 25
     - ``GEN_OP_BRANCH``
     - Control flow.  Direction (taken / not-taken / fall-through)
       lives at runtime; the static branch flavour lives in
       ``branch_type``.  Direct jumps, indirect jumps, conditional
       jumps, and direct/indirect ``call`` all collapse into this
       opcode — the ``call`` vs ``jmp`` split is in ``branch_type``
       (direct ``call`` looks like ``BRANCH_DIRECT_JUMP``; indirect
       ``call`` is refined to ``BRANCH_INDIRECT_JUMP`` based on
       operand kind).
   * - 26
     - *(reserved)*
     - Skipped intentionally.  An older revision used 26 for
       call-shaped control flow before everything collapsed into
       ``GEN_OP_BRANCH``; left unused so ID stability across
       revisions is exact.
   * - 27
     - ``GEN_OP_RET``
     - Return from call.  Always paired with
       ``branch_type = BRANCH_RETURN``.  x86 ``ret`` / ``retf*`` /
       ``iret*`` get this; AArch64 ``ret`` gets this; RISC-V
       ``cm.popret*`` / ``dret`` and MIPS exception-return
       ``eret`` / ``deret`` get this.  *Plain* RISC-V ``ret`` (the
       ``jalr x0, ra, 0`` pseudo) and MIPS ``jr $ra`` are
       classified by their canonical Capstone insn-id as
       ``GEN_OP_BRANCH`` with ``branch_type =
       BRANCH_INDIRECT_JUMP`` because the classifier does not
       inspect the ``ra`` register operand to recognize them as
       returns.  This is a deliberate trade-off: keeps the
       classification table operand-agnostic at the cost of
       conflating RISC-V/MIPS returns with general indirect jumps
       in the trace.
   * - 28
     - ``GEN_OP_FP_ADD``
     - Floating-point add.
   * - 29
     - ``GEN_OP_FP_SUB``
     - Floating-point sub.
   * - 30
     - ``GEN_OP_FP_MUL``
     - Floating-point mul.
   * - 31
     - ``GEN_OP_FP_DIV``
     - Floating-point divide.
   * - 32
     - ``GEN_OP_FP_SQRT``
     - Floating-point square root.
   * - 33
     - ``GEN_OP_FP_MOV``
     - Floating-point move.
   * - 34
     - ``GEN_OP_FP_CVT``
     - Floating-point conversion (between FP formats or to/from
       integer).
   * - 35
     - ``GEN_OP_FP_CMP``
     - Floating-point compare.
   * - 36
     - ``GEN_OP_VEC_ADD``
     - SIMD / vector add.
   * - 37
     - ``GEN_OP_VEC_SUB``
     - SIMD / vector sub.
   * - 38
     - ``GEN_OP_VEC_MUL``
     - SIMD / vector multiply.
   * - 39
     - ``GEN_OP_VEC_MOV``
     - SIMD / vector move (also covers ``vmovdqa`` / ``vmovups``).
   * - 40
     - ``GEN_OP_VEC_SHUF``
     - SIMD permute / shuffle / blend.
   * - 41
     - ``GEN_OP_VEC_LOGIC``
     - Bitwise operations on vector registers.
   * - 42
     - ``GEN_OP_NOP``
     - No-op (architectural or padding).
   * - 43
     - ``GEN_OP_SYSCALL``
     - System call.  Pairs with
       ``branch_type = BRANCH_SYSCALL_TYPE``.  In WP simulation, a
       syscall ends the speculative chain.
   * - 44
     - ``GEN_OP_FENCE``
     - Memory / instruction barrier.  Every classifier row that
       maps to ``FENCE`` has ``MF_ATOMIC``, so the resulting
       insn always carries ``the ``CST_INSN_FLAG_ATOMIC`` bit``.
       Examples: x86 ``mfence`` / ``lfence`` / ``sfence``,
       cache-wide ops without an address (``invd``, ``wbinvd``,
       ``serialize``); AArch64 ``dmb`` / ``dsb`` / ``isb`` /
       ``clrex``; RISC-V ``fence`` / ``fence.i``.  Cache- and
       TLB-management opcodes that *carry an address operand* now
       map to ``GEN_OP_CACHE_FLUSH`` / ``GEN_OP_TLB_FLUSH`` /
       ``GEN_OP_PREFETCH`` instead — see those rows below.
   * - 45
     - ``GEN_OP_CMOV``
     - Conditional move.
   * - 46
     - ``GEN_OP_SETCC``
     - Set-on-condition (writes 0 or 1 to a destination register).
   * - 47
     - ``GEN_OP_INT_ADC``
     - Integer add-with-carry.
   * - 48
     - ``GEN_OP_INT_SBB``
     - Integer subtract-with-borrow.
   * - 49
     - ``GEN_OP_NEG``
     - Two's-complement negate.
   * - 50
     - ``GEN_OP_INC``
     - Integer increment-by-one (idiomatic ``inc reg``).
   * - 51
     - ``GEN_OP_DEC``
     - Integer decrement-by-one.
   * - 52
     - ``GEN_OP_INT_MADD``
     - Integer multiply-and-add.
   * - 53
     - ``GEN_OP_INT_MSUB``
     - Integer multiply-and-sub.
   * - 54
     - ``GEN_OP_FP_MADD``
     - Floating-point fused multiply-add.
   * - 55
     - ``GEN_OP_FP_MSUB``
     - Floating-point fused multiply-sub.
   * - 56
     - ``GEN_OP_VEC_MADD``
     - Vector fused multiply-add.
   * - 57
     - ``GEN_OP_VEC_MSUB``
     - Vector fused multiply-sub.
   * - 58
     - ``GEN_OP_PREFETCH``
     - Software prefetch hint.  QEMU's TCG translates these to
       no-ops, so no real memop is emitted; the tracer synthesises
       a load memop carrying the computed effective address by
       reading base / index registers at exec time and applying
       ``ea = base + (index << shift_amount) * scale + disp`` from
       the Capstone operand metadata.  Examples: x86 ``prefetch*``,
       AArch64 ``prfm`` / ``prfum`` / ``pli``, RISC-V
       ``prefetch.{i,r,w}``, MIPS ``pref`` / ``prefe`` / ``prefx``.
   * - 59
     - ``GEN_OP_CACHE_FLUSH``
     - Cache-line clean / flush / invalidate addressed at a
       specific line.  Same synthetic-EA capture as
       ``GEN_OP_PREFETCH``.  Always carries
       ``the ``CST_INSN_FLAG_ATOMIC`` bit``.  Examples: x86 ``clflush*`` /
       ``clwb`` / ``cldemote``, AArch64 ``dc.*`` / ``ic.*``,
       RISC-V ``cbo.{clean,flush,inval}``, MIPS ``cache`` /
       ``cachee``.  Cache-wide forms with no address (``invd``,
       ``wbinvd``) stay under ``GEN_OP_FENCE``.
   * - 60
     - ``GEN_OP_TLB_FLUSH``
     - TLB-entry invalidation addressed at a specific page.  Same
       synthetic-EA capture.  Always carries
       ``the ``CST_INSN_FLAG_ATOMIC`` bit``.  Examples: x86 ``invlpg`` /
       ``invlpga``, AArch64 ``tlbi``, RISC-V ``sfence.vma`` /
       ``hfence.{g,v}vma`` / ``hinval.{g,v}vma`` /
       ``sinval.vma``, MIPS ``tlbp`` / ``tlbr`` / ``tlbwi`` /
       ``tlbwr`` / ``ginv*`` / ``tlbg*`` / ``tlbinv*``.
   * - 61
     - ``GEN_OP_INT_ALU_SHORT``
     - *Reserved fallback.*  Coarse "single-cycle integer ALU op"
       bucket for external trace writers that lack ISA-specific
       opcode metadata.  Never emitted by the in-tree tracer.
       Consumers should accept it so foreign traces decode.
   * - 62
     - ``GEN_OP_INT_ALU_LONG``
     - *Reserved fallback.*  Coarse "long-latency integer op"
       bucket (multi-cycle multiplier, divider, etc.).  Never
       emitted by the in-tree tracer.
   * - 63
     - ``GEN_OP_FP_ALU_SHORT``
     - *Reserved fallback.*  Single-cycle floating-point op
       bucket.  Never emitted by the in-tree tracer.
   * - 64
     - ``GEN_OP_FP_ALU_LONG``
     - *Reserved fallback.*  Long-latency floating-point op
       bucket (FDIV, FSQRT, transcendentals, etc.).  Never
       emitted by the in-tree tracer.
   * - 65
     - ``GEN_OP_VEC_ALU_SHORT``
     - *Reserved fallback.*  Single-cycle vector / SIMD op
       bucket.  Never emitted by the in-tree tracer.
   * - 66
     - ``GEN_OP_VEC_ALU_LONG``
     - *Reserved fallback.*  Long-latency vector / SIMD op
       bucket.  Never emitted by the in-tree tracer.

IDs 67..255 are unallocated.  ``GEN_OP_COUNT`` is the
sentinel; per-CP and per-WP attribution arrays in ``Stats`` are sized
by it so adding a new opcode automatically extends the histograms.

.. _branch-types:

Branch types (``BranchType``)
-----------------------------

``u8`` field on every template instruction; sparse-recorded via
``CST_FID_INSN_BRANCH_TYPE`` when an instance overrides the template.

.. list-table::
   :header-rows: 1
   :widths: 6 28 66

   * - ID
     - Name
     - Notes
   * - 0
     - ``BRANCH_NONE``
     - Not a branch.  Templates default to this for all but the
       last instruction (after delay-slot normalization, where
       applicable).
   * - 1
     - ``BRANCH_DIRECT_JUMP``
     - Direct target encoded in the instruction.  Covers
       unconditional direct jumps (``jmp imm``), direct ``call``
       (which is also a control-transfer-with-immediate-target),
       and — when the per-ISA classifier flagged the row with
       ``MF_CONDITIONAL`` *but* the table classified the branch as
       ``DIRECT_JUMP`` — conditional direct branches that didn't
       get the dedicated ``COND_DIRECT`` classification.  WP-target
       resolution treats a taken instance as fall-through; if the
       instance was *also* conditional and fell through, the WP
       target becomes the static immediate.
   * - 2
     - ``BRANCH_INDIRECT_JUMP``
     - Computed target.  Covers indirect jumps and indirect
       ``call`` (the x86 refine callback rewrites the table's
       default ``DIRECT_JUMP`` to ``INDIRECT_JUMP`` when the call's
       first operand isn't an immediate).  WP-target picking: with
       ≥2 distinct historic targets observed, return the most-
       frequent target other than this execution's actual one;
       with one observed target, fall back to the fall-through PC
       (so single-target indirect calls in shared-library trampolines
       don't produce all-CP WP slices).
   * - 3
     - ``BRANCH_RETURN``
     - Indirect via return address.  Grouped with
       ``BRANCH_INDIRECT_JUMP`` in WP-target picking — same rule.
   * - 4
     - ``BRANCH_SYSCALL_TYPE``
     - System-call-style transfer (``syscall``, ``svc``,
       ``ecall``).  WP simulation continues *into* the syscall as
       any other branch, but if the syscall's TB raises a fault
       (the architectural common case in spec mode) the natural
       ``ends_in_branch`` test commits the BB and the post-PC
       poisoning then breaks out of the WP chain.  Speculative
       state past the syscall is not modeled.
   * - 5
     - ``BRANCH_COND_DIRECT``
     - PC-relative conditional.  WP target is the *not-taken*
       static target when CP took the branch (i.e., the
       fall-through PC), and the static taken target (the encoded
       immediate) when CP fell through.
   * - 6
     - ``BRANCH_REP``
     - x86 REP / REPNZ self-loop terminator (string ops MOVS /
       STOS / LODS / CMPS / SCAS / INS / OUTS with a REP prefix).
       Conditional self-loop: target = the REP's own PC,
       fall-through = the next PC.  The tracer fans each
       architectural iteration of the REP loop into its own true-BB
       visit; iter 1 stays on the BB that *enters* the REP loop,
       iter 2..N each emit on a 1-insn self-loop sub-template at
       the REP's PC carrying that iteration's memops (1 load + 1
       store for MOVS, 2 loads for CMPS, etc.).  Distinguished
       from ``BRANCH_COND_DIRECT`` so simulators that model branch
       behaviour can skip target-diversity tracking on REP (target
       is always self-PC) and so the fan-out shape is obvious at
       template-parse time.

.. _registers:

Register IDs (``GenericRegId``)
-------------------------------

Each architectural register the per-ISA classification table maps to
a generic-domain ID.  IDs 0..254 are valid; ``REG_ID_COUNT = 255``
is the sentinel.  Wire-format encoding is a single ``u8``.

The dense banks below number from a base value with each subsequent
register one greater.  Use the per-bank base as the entry-point.

.. list-table::
   :header-rows: 1
   :widths: 18 18 64

   * - Range
     - Class
     - Notes
   * - 0
     - ``REG_NONE``
     - Sentinel returned by the per-ISA register classifier when
       it can't map a Capstone register ID to a generic-domain
       slot.  ``decode.cc::add_src_reg`` / ``add_dst_reg`` *skip*
       any classification that yields ``REG_NONE``, so this ID is
       never written into a template's ``src_regs`` / ``dst_regs``
       and consumers will not see it on the wire.  The decoder
       reserves the name purely as a debugging fallback.
   * - 1..64
     - ``REG_GPR0`` .. ``REG_GPR63``
     - General-purpose integer registers.
   * - 65..128
     - ``REG_FPR0`` .. ``REG_FPR63``
     - Scalar floating-point registers.
   * - 129..192
     - ``REG_VEC0`` .. ``REG_VEC63``
     - Vector / SIMD registers.  The full width is whatever the
       guest ISA exposes (XMM, YMM, ZMM on x86; Q on aarch64;
       V on RISC-V).  Snapshot capture truncates to 512 bits.
   * - 193..224
     - ``REG_PRED0`` .. ``REG_PRED31``
     - Predicate / mask registers (SVE, AVX-512 ``k`` regs,
       RVV mask).
   * - 225..230
     - ``REG_SEG0`` .. ``REG_SEG5``
     - x86 segment registers (``cs`` / ``ds`` / ... ).  Other ISAs
       leave this range empty.
   * - 231
     - ``REG_CTRL``
     - Architectural control register family (CR0..N on x86,
       SCTLR on aarch64).
   * - 232
     - ``REG_DEBUG``
     - Debug-control register family (DR0..N, MDSCR).
   * - 233..236
     - ``REG_BOUND0`` .. ``REG_BOUND3``
     - x86 MPX bound registers.
   * - 237..240
     - ``REG_ACC0`` .. ``REG_ACC3``
     - Accumulator-style architectural registers (MIPS HI/LO,
       AArch64 SME accumulators).
   * - 241
     - ``REG_ZERO``
     - Hardwired-zero register (RISC-V ``x0``, MIPS ``$zero``,
       aarch64 ``xzr``).
   * - 242
     - ``REG_MATRIX``
     - Tile/matrix register family (AMX TMM, SME ZA).
   * - 243
     - ``REG_SYS``
     - Generic system register (per-arch MSR / MRS / CSR space).
   * - 244
     - ``REG_FCSR``
     - Floating-point control / status register.
   * - 245
     - ``REG_VCTRL``
     - Vector control register (RVV ``vtype`` / ``vl``,
       SVE ``ZCR``).
   * - 246..249
     - *(unallocated)*
     - Available for future singleton additions.
   * - 250
     - ``REG_SP``
     - Stack pointer.
   * - 251
     - ``REG_FLAGS``
     - Flags / condition-code register (RFLAGS, NZCV, ``mstatus``).
   * - 252
     - ``REG_IP``
     - Instruction / program counter.
   * - 253
     - ``REG_LR``
     - Link register (return address) on architectures that have
       one architecturally.
   * - 254
     - ``REG_FP_REG``
     - Frame pointer (rbp / x29 / ``s0``).

.. _atomic-flag:

Atomic flag (``CST_INSN_FLAG_ATOMIC``)
--------------------------------------

Single bit in the per-instruction template flags byte.  Set in
``decode.cc::decode_detail_to_generic`` when either (a) Capstone
reports the x86 ``LOCK`` prefix on this instruction
(``info->has_lock``), or (b) the per-ISA classifier row has the
``MF_ATOMIC`` flag.  In practice this fires on every
``GEN_OP_XCHG`` (the ``cmpxchg`` / ``xadd`` / ``xchg`` / AArch64
``cas`` / RISC-V ``amo*`` / MIPS ``ll`` family) and on every
``GEN_OP_CACHE_FLUSH`` / ``GEN_OP_TLB_FLUSH`` row (``clflush``,
``clwb``, ``invlpg``, ``cbo.*``, ``tlbi``, ``sfence.vma``, ...).
Thread switches are recorded out-of-band via
``BODY_TAG_THREAD_SWITCH`` body records, not as a per-insn flag.

.. _field-ids:

Field-ID space (``CST_FID_*``)
------------------------------

Per-instruction dynamic observations the body stream encodes as
deltas against template defaults.  Detailed semantics are in
:doc:`/format`; the table below is the at-a-glance mapping.

.. list-table::
   :header-rows: 1
   :widths: 18 28 54

   * - ID
     - Name
     - Payload
   * - 0x00
     - ``CST_FID_N_LOADS``
     - SLEB delta — current valid load slot count.
   * - 0x01..0x10
     - ``CST_FID_LOAD_ADDR0`` .. ``CST_FID_LOAD_ADDR15``
     - SLEB delta of the access vaddr modulo 2^512.
   * - 0x11..0x20
     - ``CST_FID_STORE_ADDR0`` .. ``CST_FID_STORE_ADDR15``
     - SLEB delta of the store vaddr.
   * - 0x21..0x30
     - ``CST_FID_LOAD_DATA0`` .. ``CST_FID_LOAD_DATA15``
     - SLEB delta of the loaded value (gated by
       ``CST_FLAG_MEM_DATA``).
   * - 0x31..0x40
     - ``CST_FID_STORE_DATA0`` .. ``CST_FID_STORE_DATA15``
     - SLEB delta of the stored value (gated by
       ``CST_FLAG_MEM_DATA``).
   * - 0x41..0x50
     - *(reserved)*
     - Future source-register-value extension.  Not currently emitted;
       the writer captures destination values post-execution
       (see 0x51..0x60).
   * - 0x51..0x60
     - ``CST_FID_DST_REG0`` .. ``CST_FID_DST_REG15``
     - SLEB delta of the destination-register post-execution snapshot
       (gated by ``CST_FLAG_REG_DATA``).
   * - 0x61
     - ``CST_FID_N_STORES``
     - SLEB delta — current valid store slot count.
   * - 0x62
     - ``CST_FID_EXTRA_LOAD_ADDR``
     - Raw ULEB vector — load addresses for slots 16+.
   * - 0x63
     - ``CST_FID_EXTRA_STORE_ADDR``
     - Raw ULEB vector — store addresses for slots 16+.
   * - 0x64
     - ``CST_FID_EXTRA_LOAD_DATA``
     - Raw ULEB vector — load values for slots 16+.
   * - 0x65
     - ``CST_FID_EXTRA_STORE_DATA``
     - Raw ULEB vector — store values for slots 16+.
   * - 0x66..0x6F
     - *(reserved)*
     - Future memop metadata.
   * - 0x70
     - ``CST_FID_INSN_BYTES_LO``
     - SLEB delta — low 8 bytes of instruction encoding.
   * - 0x71
     - ``CST_FID_INSN_BYTES_HI``
     - SLEB delta — high 8 bytes (only x86 / wide encodings).
   * - 0x72
     - ``CST_FID_INSN_OPCODE``
     - SLEB delta — generic opcode override.
   * - 0x73
     - ``CST_FID_INSN_BRANCH_TYPE``
     - SLEB delta — branch-type override.
   * - 0x74
     - ``CST_FID_INSN_FLAGS``
     - SLEB delta — per-insn flag byte (cond + has_imm + sync).
   * - 0x75
     - ``CST_FID_INSN_IMMEDIATE``
     - SLEB delta — signed immediate.
   * - 0x76
     - ``CST_FID_INSN_SIZE``
     - SLEB delta — instruction byte length.
   * - 0x77
     - ``CST_FID_METAFLAGS``
     - SLEB delta — canonical Z/N/C/V/P byte for ALU insns that
       write the ISA's integer-flags register
       (see :ref:`metaflags`).  Gated by ``CST_FLAG_REG_DATA``;
       emitted only when the insn's template sets
       ``writes_int_flags`` (i.e., its dst maps to a
       ``RegClassification`` row with ``.is_int_flags = true``).
   * - 0x78..0xFE
     - *(reserved)*
     - Available for future scalar field-ID assignments.
   * - 0xFF
     - ``CST_FID_EXTENDED``
     - Reserved escape; not currently used.

.. _metaflags:

Canonical integer-flags byte (``CST_METAFLAGS_*``)
--------------------------------------------------

Different ISAs spell their condition-code bits differently — x86
``EFLAGS`` carries CF / PF / AF / ZF / SF / OF at scattered bit
positions, AArch64 packs N / Z / C / V into the top nibble of NZCV,
RISC-V and MIPS have no integer-flags register at all.  Consumers
that compute on flag semantics (branch-predictor models, value
predictors, mis-speculation analyses) need a stable ISA-agnostic
shape.

The tracer emits one canonical byte per flag-writing instruction
under the side-channel field ID ``CST_FID_METAFLAGS`` (``0x77``).
The plugin derives this byte from the architectural flags-register
snap by applying the per-ISA bit-shuffle mapper at capture time;
consumers don't need to know the source ISA's flag-bit layout.

Bit layout (``include/champsim_tracer_generic_ids.h``):

.. list-table::
   :header-rows: 1
   :widths: 8 18 74

   * - Bit
     - Name
     - Meaning
   * - 0
     - ``CST_METAFLAGS_Z``
     - Zero / equal (result == 0).
   * - 1
     - ``CST_METAFLAGS_N``
     - Negative / sign (high bit of result).
   * - 2
     - ``CST_METAFLAGS_C``
     - Unsigned carry / borrow.
   * - 3
     - ``CST_METAFLAGS_V``
     - Signed overflow.
   * - 4
     - ``CST_METAFLAGS_P``
     - Parity of the low byte (x86 only; always 0 on other ISAs).
   * - 5..7
     - *(reserved)*
     - Written as 0; readers should mask before comparing.

Per-ISA EFLAGS → metaflags mapping:

.. list-table::
   :header-rows: 1
   :widths: 14 86

   * - ISA
     - Mapping
   * - x86_64
     - ``CF→C`` (bit 0), ``PF→P`` (bit 2), ``ZF→Z`` (bit 6),
       ``SF→N`` (bit 7), ``OF→V`` (bit 11).  AF and the system
       bits (IF / DF / TF / IOPL / NT / …) are dropped.
   * - aarch64
     - NZCV top nibble of CPSR: ``N→N`` (bit 31), ``Z→Z`` (bit 30),
       ``C→C`` (bit 29), ``V→V`` (bit 28).  No parity bit.
   * - riscv64
     - No architectural integer-flags register; the FID is never
       emitted.  No insn classification row has
       ``is_int_flags = true``.
   * - mipsel
     - No architectural integer-flags register; the FID is never
       emitted.  Conditional branches read GPRs directly.

The "canonical byte rides a side-channel field-ID, not a synthetic
dst-register slot" design lets consumers reason about architectural
register sets without filtering a phantom slot, and lets
``writes_int_flags`` be a *static template* property rather than a
runtime classification — the writer decides at template-build time
(via the per-ISA ``RegClassification.is_int_flags`` marker on each
Capstone-decoded dst register) whether to emit the FID.

The encoding map carries the bit-name table under the
``metaflags`` map (one entry per ``CST_METAFLAGS_*`` bit), so a
consumer reading the trace can resolve ``0x05`` to ``Z|C`` without
hard-coding the bit positions.  ``REG_FLAGS`` (generic id 251) is
the *architectural* register name a consumer compares against to
decide whether an insn writes flags; the metaflags byte under FID
0x77 is the canonical-shape value.

.. _isa-ids:

ISA identifiers (``TraceISA``)
------------------------------

``u8`` recorded in the trace header so the consumer knows how to
interpret the ``insn_bytes`` payload of each template.

ISA coverage in detail
~~~~~~~~~~~~~~~~~~~~~~

Each ISA has a per-ISA classification table in
``contrib/plugins/champsim_tracer/champsim_tracer_mnemonics_<isa>.h``
sized to the upstream Capstone ``<ISA>_INS_ENDING`` constant.
Every Capstone-defined mnemonic gets a designated-initializer row
in the table, so a build of the plugin against the in-tree
Capstone version covers Capstone's full mnemonic surface for that
ISA.  The practical limits on coverage are:

* Capstone itself doesn't model every architectural extension at
  the mnemonic level (notably anything that requires runtime
  state or hard-to-statically-decode operands).
* The per-row generic-opcode mapping was filled in pass-by-pass;
  niche / recent extensions may be classified as ``GEN_OP_UNKNOWN``
  if they were added after the last classification pass.  The
  ``GEN_OP_UNKNOWN`` line of the exit-time summary plus the
  ``.unknown_warnings.log`` sidecar is the authoritative answer
  for any specific workload.

.. list-table::
   :header-rows: 1
   :widths: 14 86

   * - ISA
     - Notes
   * - x86_64
     - Capstone's full x86 mnemonic surface in 64-bit mode.
       ``LOCK`` / ``REP`` prefixes are observed and surface as
       ``the ``CST_INSN_FLAG_ATOMIC`` bit``.  Vector register snapshots are
       512-bit-truncated; full ZMM is captured.
   * - aarch64
     - Capstone's full AArch64 mnemonic surface.  SVE
       instructions appear in the mnemonic table; SVE register
       snapshots are truncated to 512 bits, so VLEN > 512
       configurations capture only the low 64 bytes per Z register.
   * - riscv64
     - Capstone's full RV64 mnemonic surface, including RVV
       (vector extension) at the mnemonic level.  rv32 isn't
       currently produced (no ``riscv32-linux-user`` build target
       wired up).
   * - mipsel
     - Capstone's 32-bit little-endian MIPS surface.  MIPS
       big-endian, mips64, and MIPS16e are not currently
       supported.

ISA enumeration on the wire
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 6 18 76

   * - ID
     - Name
     - Notes
   * - 0
     - ``TRACE_ISA_UNKNOWN``
     - Unrecognized ISA.  Decoders should still be able to read
       opcodes / branch types / register IDs since those are
       generic; only Capstone-disassembling the raw insn_bytes
       requires knowing the ISA.
   * - 1
     - ``TRACE_ISA_X86``
     - x86_64.
   * - 2
     - ``TRACE_ISA_AARCH64``
     - ARMv8 / aarch64.
   * - 3
     - ``TRACE_ISA_RISCV``
     - RISC-V (rv64gc; rv32 not currently produced).
   * - 4
     - ``TRACE_ISA_MIPS``
     - MIPS (32-bit little-endian; mipsel).
