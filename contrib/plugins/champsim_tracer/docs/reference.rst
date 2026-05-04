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
       recognise.  A non-zero count in the exit-time summary's
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
     - Register-to-register move (no memory access).
   * - 15
     - ``GEN_OP_LOAD``
     - Memory read.  Pairs with ``CST_FID_LOAD_ADDR*`` /
       ``CST_FID_LOAD_DATA*``.
   * - 16
     - ``GEN_OP_STORE``
     - Memory write.  Pairs with ``CST_FID_STORE_ADDR*`` /
       ``CST_FID_STORE_DATA*``.
   * - 17
     - ``GEN_OP_PUSH``
     - Stack push (memory write + SP update).
   * - 18
     - ``GEN_OP_POP``
     - Stack pop.
   * - 19
     - ``GEN_OP_LEA``
     - Effective-address compute, no memory access (x86 ``lea``,
       aarch64 ``adrp``).
   * - 20
     - ``GEN_OP_MOVSX``
     - Sign-extending move.
   * - 21
     - ``GEN_OP_MOVZX``
     - Zero-extending move.
   * - 22
     - ``GEN_OP_XCHG``
     - Atomic or non-atomic exchange.  Atomic flavour also sets
       ``sync_hint = SYNC_ATOMIC``.
   * - 23
     - ``GEN_OP_CMP``
     - Compare (subtract-and-discard, sets flags).
   * - 24
     - ``GEN_OP_TEST``
     - Bitwise test (and-and-discard, sets flags).
   * - 25
     - ``GEN_OP_BRANCH``
     - Control flow.  Specific flavour lives in ``branch_type``;
       ``call``, conditional/unconditional jump, and direct jump
       all collapse into this opcode.
   * - 26
     - *(reserved)*
     - Skipped intentionally.  An older revision used 26 for
       call-shaped control flow before everything collapsed into
       ``GEN_OP_BRANCH``; left unused so ID stability across
       revisions is exact.
   * - 27
     - ``GEN_OP_RET``
     - Return from call.  ``branch_type`` is ``BRANCH_RETURN``.
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
     - Memory / instruction barrier.  Pairs with whichever
       ``sync_hint`` value applies (atomic, thread-switch, or
       neither).
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

IDs 58..255 are unallocated.  ``GEN_OP_COUNT`` is the
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
       last instruction (after delay-slot normalisation, where
       applicable).
   * - 1
     - ``BRANCH_DIRECT_JUMP``
     - Static, PC-relative, unconditional.  WP target is the
       fall-through.
   * - 2
     - ``BRANCH_INDIRECT_JUMP``
     - Computed target.  WP target is chosen from the per-branch
       indirect-target history, picking the most-frequent target
       that isn't this execution's actual target.
   * - 3
     - ``BRANCH_RETURN``
     - Indirect via return address.  WP targets are picked the
       same way as ``BRANCH_INDIRECT_JUMP``.
   * - 4
     - ``BRANCH_SYSCALL_TYPE``
     - System-call-style transfer (``syscall``, ``svc``,
       ``ecall``).  WP simulation ends after seeing one because
       speculative state past the syscall is not modelled.
   * - 5
     - ``BRANCH_COND_DIRECT``
     - PC-relative conditional.  WP target is the *not-taken*
       static target when CP took the branch, and the static taken
       target when CP fell through.

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
     - Sentinel for "no register" — used in template src/dst slots
       that are not architectural registers (e.g., immediates).
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

.. _sync-events:

Sync events (``SyncEventType``)
-------------------------------

4-bit field embedded in the per-instruction template flags byte
(``CST_INSN_FLAG_SYNC_*``).  Marks instructions whose semantics
involve thread-level synchronisation.

.. list-table::
   :header-rows: 1
   :widths: 6 28 66

   * - ID
     - Name
     - Notes
   * - 0
     - ``SYNC_NONE``
     - No synchronisation.  Default.
   * - 1..3
     - *(reserved)*
     - Not currently used.  ID 0 → 4 jump leaves space for future
       weakly-ordered hints without bit-shifting.
   * - 4
     - ``SYNC_THREAD_SWITCH``
     - Hint: this instruction's execution may yield the vCPU.
       Currently used only as a hint to the writer to emit a
       ``BODY_TAG_THREAD_SWITCH`` record.
   * - 5
     - ``SYNC_ATOMIC``
     - Atomic read-modify-write or fence with memory ordering.
       Pairs with ``GEN_OP_XCHG``, ``GEN_OP_FENCE``, or any
       ``LOCK``-prefixed x86 RMW.

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
     - ``CST_FID_SRC_REG0`` .. ``CST_FID_SRC_REG15``
     - SLEB delta of the source-register pre-execution snapshot
       (gated by ``CST_FLAG_REG_DATA``).
   * - 0x51..0x60
     - *(reserved)*
     - Future destination-register-value extension.
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
   * - 0x77..0xFE
     - *(reserved)*
     - Available for future scalar field-ID assignments.
   * - 0xFF
     - ``CST_FID_EXTENDED``
     - Reserved escape; not used in v1.9.

.. _isa-ids:

ISA identifiers (``TraceISA``)
------------------------------

``u8`` recorded in the trace header so the consumer knows how to
interpret the ``insn_bytes`` payload of each template.

.. list-table::
   :header-rows: 1
   :widths: 6 18 76

   * - ID
     - Name
     - Notes
   * - 0
     - ``TRACE_ISA_UNKNOWN``
     - Unrecognised ISA.  Decoders should still be able to read
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
