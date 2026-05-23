"""Assembly-only code block library for champsim_tracer_genval.

Each generated block maps to one machine-level basic block. Straight-line
blocks end in an unconditional branch, and 2-way blocks end in one
conditional branch whose fallthrough path is the other successor.
"""

from __future__ import annotations

import dataclasses
import random
import re
from typing import ClassVar


@dataclasses.dataclass
class ExpectedMemOp:
    kind: str
    arena_u64_index: int
    size: int
    data: int
    optional: bool = False


@dataclasses.dataclass
class BlockPlan:
    block_id: int
    name: str
    memops: list[ExpectedMemOp]
    ordered_memops: bool = False
    # Aggregate memop dyn_params from *every* body entry of every
    # template in the block's bipartite component, not just each
    # template's first entry.  Needed for blocks that emit REP-
    # prefixed string ops: the tracer fans the iterations out into
    # one entry per iteration on a 1-insn self-loop sub-template, so
    # iter 2..N memops live on subsequent entries of the same
    # template_id and would be missed by the default first-entry
    # aggregation (which exists to suppress normal-loop double-
    # counting).
    aggregate_fanout: bool = False
    # Per-execution expected memops: if set, the validator checks that the
    # k-th CP entry on this block's template has the k-th sub-list as its
    # dyn_params (in the same multiset sense as `memops`).  Used for
    # known-deterministic loop bodies whose data varies across iterations
    # (e.g. LoopHead: counter decrements each iter) so the per-execution
    # data check can catch stale/wrong delta regressions that the
    # first-execution-only `_check_cp_memops` misses.
    per_iteration_memops: list[list["ExpectedMemOp"]] = \
        dataclasses.field(default_factory=list)
    reg_value_assertions: list[dict] = dataclasses.field(default_factory=list)
    memop_count_assertions: list[dict] = dataclasses.field(default_factory=list)
    indirect_wp_assertions: list[dict] = dataclasses.field(default_factory=list)
    coarse_opcodes: dict[str, int] = dataclasses.field(default_factory=dict)
    successors: list[int] = dataclasses.field(default_factory=list)
    branch_pred: bool | None = None
    terminal: bool = False
    asserted_branch_types: list[str] = dataclasses.field(default_factory=list)
    asserted_opcodes: list[str] = dataclasses.field(default_factory=list)
    asserted_cond_uncond_branch: bool = False
    # Author-declared per-instruction register sets, parallel to the
    # asm body.  Each entry is {"src": [...], "dst": [...]} naming
    # GenericRegId values (e.g. "REG_GPR0", "REG_IP") OR a per-ISA
    # canonical Capstone name we resolve at validation time.  Optional;
    # the validator's _check_static_reg_sets already covers per-insn
    # src/dst correctness against Capstone disassembly, so this is for
    # author-intent vs. emitted-asm divergence — a probe whose
    # declared sets don't match what Capstone says about the asm we
    # actually wrote indicates a bug (typo, unintended encoding, etc.).
    expected_reg_sets: list[dict] = dataclasses.field(default_factory=list)
    # Author-declared dep-refiner bucket names exercised by this block
    # (e.g. "DEP_LEA", "DEP_PASSTHROUGH", "DEP_X86_STACK_PUSH").  The
    # validator's _check_dep_refine_coverage uses this to flag probes
    # whose stated dep-bucket coverage never actually shows up in the
    # trace (typo in spec, classifier change, or instruction selection
    # bug).  Names come from validator.py's _DEP_REFINE_BUCKETS tuple.
    asserted_dep_refines: list[str] = dataclasses.field(default_factory=list)
    # Author-declared per-instruction EXACT check vectors, parallel to
    # the asm body (same indexing as expected_reg_sets).  Each entry is
    # a dict with any subset of the following keys; missing keys aren't
    # checked, so authors fill in only what they want exact-matched:
    #
    #   "src":      list[str] of GenericRegId names — same as
    #               expected_reg_sets["src"].
    #   "dst":      list[str] of GenericRegId names.
    #   "opcode":   GEN_OP_* name (the trace's generic opcode).
    #   "branch_type": BRANCH_* name.
    #   "insn_flags": list of CST_INSN_FLAG_* names that MUST be set
    #               (the per-insn flag byte).  Names not listed need
    #               not be clear — extra flags are tolerated unless
    #               also listed in "insn_flags_clear".
    #   "insn_flags_clear": list of CST_INSN_FLAG_* names that MUST be
    #               clear.
    #   "dst_deps":   list parallel to dst[]; each entry is a list of
    #               input-name strings selecting bits of dst_dep_mask.
    #               Input names: "src_reg[i]" (i in 0..n_src-1),
    #               "load_data[k]" (k in 0..max_dep_loads-1), "imm".
    #   "store_data_deps": list parallel to the insn's store-data slots;
    #               same shape as dst_deps.
    #   "load_addr_deps":  list parallel to the insn's load slots; each
    #               entry uses input-name strings (src_reg[i] and imm).
    #   "store_addr_deps": same shape for store-address dep masks.
    #   "src_lane_masks":  list[int] parallel to src_regs[]; each int is
    #               the per-(insn,src-slot) lane bitmap.  Bit j set iff
    #               lane j participates as input.
    #   "dst_lane_masks":  list[int] parallel to dst_regs[].
    #   "load_data_lane_masks":  list[int] parallel to the insn's load
    #               slots — per-memop lane bitmap (which lane(s) of the
    #               consuming dst register THIS memop fills).
    #   "store_data_lane_masks": same shape for stores.
    #
    # The validator's `_check_expected_insns` resolves the symbolic
    # references against the trace's per-template insn data (which
    # carries dst_dep_mask / store_data_dep_mask / load_addr_dep_mask /
    # store_addr_dep_mask exactly) and the per-entry observation
    # records (which carry lane masks as runtime FID deltas).  An
    # absent dep-mask family on the wire (no HAS_REG sub-block) maps
    # to the implicit all-to-all approximation — authors who want to
    # assert that absence write the field as an empty list.
    expected_insns: list[dict] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class EmitCtx:
    block_id: int
    isa: str
    branch_slot: int | None
    scratch_slots: list[int]
    arena_u64: int
    successor_labels: list[str]
    rng: random.Random
    branch_outcome: bool | None = None
    loop_iterations: int = 0


_REGISTRY: dict[str, type["CodeBlock"]] = {}


def register(cls: type["CodeBlock"]) -> type["CodeBlock"]:
    _REGISTRY[cls.name] = cls
    return cls


def get_block(name: str) -> type["CodeBlock"]:
    return _REGISTRY[name]


def all_blocks() -> list[type["CodeBlock"]]:
    return list(_REGISTRY.values())


def symbol_name(block_id: int) -> str:
    return f"blk_{block_id}"


def coverage_probes_for_isa(isa: str) -> list[str]:
    out: list[str] = []
    for cls in all_blocks():
        if (isa in cls.supported_isas and cls.coverage_probe
                and cls.num_successors == 1 and not cls.terminal):
            out.append(cls.name)
    return out


def emit_data_u64(isa: str, value: int) -> list[str]:
    value &= (1 << 64) - 1
    if isa.startswith("mips"):
        lo = value & 0xFFFFFFFF
        hi = (value >> 32) & 0xFFFFFFFF
        return [f"  .word 0x{lo:08x}, 0x{hi:08x}"]
    return [f"  .quad 0x{value:016x}"]


def emit_entry_jump(isa: str, entry_symbol: str) -> list[str]:
    if isa == "x86_64":
        return [f"  jmp {entry_symbol}"]
    if isa == "aarch64":
        return [f"  b {entry_symbol}"]
    if isa == "riscv64":
        return [f"  j {entry_symbol}"]
    if isa.startswith("mips"):
        return [f"  j {entry_symbol}", "  nop"]
    raise ValueError(f"unsupported ISA: {isa}")


def emit_helper_symbols(isa: str) -> list[str]:
    """Emit helper leaf symbols used by call-coverage blocks."""
    lines = [
        ".globl wptgen_leaf",
        ".type wptgen_leaf, @function",
        "wptgen_leaf:",
    ]
    if isa == "x86_64":
        lines += [
            "  movabs $0xA5A5A5A5A5A5A5A5, %rcx",
            "  xorq %rcx, %rax",
            "  ret",
        ]
    elif isa == "aarch64":
        lines += [
            "  movz x9, #0xa5a5",
            "  movk x9, #0xa5a5, lsl #16",
            "  movk x9, #0xa5a5, lsl #32",
            "  movk x9, #0xa5a5, lsl #48",
            "  eor x0, x0, x9",
            "  ret",
        ]
    elif isa == "riscv64":
        lines += [
            "  li t1, 0xA5A5A5A5A5A5A5A5",
            "  xor a0, a0, t1",
            "  ret",
        ]
    elif isa.startswith("mips"):
        lines += [
            "  lui $t0, 0xA5A5",
            "  ori $t0, $t0, 0xA5A5",
            "  xor $v0, $a0, $t0",
            "  jr $ra",
            "  nop",
        ]
    else:
        raise ValueError(f"unsupported ISA: {isa}")
    return lines


class CodeBlock:
    name: ClassVar[str] = "__abstract__"
    num_successors: ClassVar[int] = 1
    scratch_slots: ClassVar[int] = 0
    supported_isas: ClassVar[tuple[str, ...]] = (
        "x86_64", "aarch64", "riscv64", "mipsel"
    )
    needs_branch_slot: ClassVar[bool] = False
    randomizable: ClassVar[bool] = True
    coverage_probe: ClassVar[bool] = True
    terminal: ClassVar[bool] = False

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        raise NotImplementedError

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        raise NotImplementedError


def _insn(opcode: str, *,
          src: list[str] | None = None,
          dst: list[str] | None = None,
          branch_type: str | None = None,
          insn_flags: list[str] | None = None,
          insn_flags_clear: list[str] | None = None,
          dst_deps: list[list[str]] | None = None,
          store_data_deps: list[list[str]] | None = None,
          load_addr_deps: list[list[str]] | None = None,
          store_addr_deps: list[list[str]] | None = None,
          src_lane_masks: list[int] | None = None,
          dst_lane_masks: list[int] | None = None,
          load_data_lane_masks: list[int] | None = None,
          store_data_lane_masks: list[int] | None = None,
          ) -> dict:
    """Author helper for a single entry of BlockPlan.expected_insns.

    Only the fields actually provided are filled into the dict, so the
    validator's per-field "missing key = don't check" behavior
    extends to every check vector — authors can spec just the opcode
    and reg sets on cold paths and add deps / lane masks where
    precision matters."""
    d: dict = {"opcode": opcode}
    if src is not None:                    d["src"] = src
    if dst is not None:                    d["dst"] = dst
    if branch_type is not None:            d["branch_type"] = branch_type
    if insn_flags is not None:             d["insn_flags"] = insn_flags
    if insn_flags_clear is not None:       d["insn_flags_clear"] = insn_flags_clear
    if dst_deps is not None:               d["dst_deps"] = dst_deps
    if store_data_deps is not None:        d["store_data_deps"] = store_data_deps
    if load_addr_deps is not None:         d["load_addr_deps"] = load_addr_deps
    if store_addr_deps is not None:        d["store_addr_deps"] = store_addr_deps
    if src_lane_masks is not None:         d["src_lane_masks"] = src_lane_masks
    if dst_lane_masks is not None:         d["dst_lane_masks"] = dst_lane_masks
    if load_data_lane_masks is not None:   d["load_data_lane_masks"] = load_data_lane_masks
    if store_data_lane_masks is not None:  d["store_data_lane_masks"] = store_data_lane_masks
    return d


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _mask_bytes(value: int, size: int) -> int:
    if size >= 64:
        return value & ((1 << 512) - 1)
    return value & ((1 << (size * 8)) - 1)


def _byte_pattern(seed: int, size: int) -> int:
    value = 0
    for i in range(size):
        value |= ((seed + i * 17) & 0xFF) << (8 * i)
    return value


def _prologue(block_id: int) -> list[str]:
    sym = symbol_name(block_id)
    return [f".globl {sym}", f".type {sym}, @function", f"{sym}:"]


def _jump(isa: str, target: str) -> list[str]:
    if isa == "x86_64":
        return [f"  jmp {target}"]
    if isa == "aarch64":
        return [f"  b {target}"]
    if isa == "riscv64":
        return [f"  j {target}"]
    if isa.startswith("mips"):
        return [f"  j {target}", "  nop"]
    raise ValueError(f"unsupported ISA: {isa}")


def _load_base(isa: str) -> list[str]:
    if isa == "x86_64":
        return ["  leaq arena(%rip), %r15"]
    if isa == "aarch64":
        return ["  adrp x20, arena", "  add x20, x20, :lo12:arena"]
    if isa == "riscv64":
        return ["  lla t6, arena"]
    if isa.startswith("mips"):
        return ["  lui $t8, %hi(arena)", "  addiu $t8, $t8, %lo(arena)"]
    raise ValueError(f"unsupported ISA: {isa}")


def _load_slot(isa: str, slot: int, reg: str, aux: str | None = None) -> list[str]:
    off = slot * 8
    if isa == "x86_64":
        return [f"  movq {off}(%r15), {reg}"]
    if isa == "aarch64":
        return [f"  ldr {reg}, [x20, #{off}]"]
    if isa == "riscv64":
        if -2048 <= off <= 2047:
            return [f"  ld {reg}, {off}(t6)"]
        return [
            f"  li t5, {off}",
            "  .option push",
            "  .option norvc",
            "  add t5, t6, t5",
            "  .option pop",
            f"  ld {reg}, 0(t5)",
        ]
    if isa.startswith("mips"):
        hi = aux or "$t7"
        return [f"  lw {reg}, {off}($t8)", f"  lw {hi}, {off + 4}($t8)"]
    raise ValueError(f"unsupported ISA: {isa}")


def _store_slot(isa: str, slot: int, reg: str) -> list[str]:
    off = slot * 8
    if isa == "x86_64":
        return [f"  movq {reg}, {off}(%r15)"]
    if isa == "aarch64":
        return [f"  str {reg}, [x20, #{off}]"]
    if isa == "riscv64":
        if -2048 <= off <= 2047:
            return [f"  sd {reg}, {off}(t6)"]
        return [
            f"  li t5, {off}",
            "  .option push",
            "  .option norvc",
            "  add t5, t6, t5",
            "  .option pop",
            f"  sd {reg}, 0(t5)",
        ]
    if isa.startswith("mips"):
        return [f"  sw {reg}, {off}($t8)", f"  sw $zero, {off + 4}($t8)"]
    raise ValueError(f"unsupported ISA: {isa}")


def _branch_zero_to(isa: str, reg: str, target: str) -> list[str]:
    if isa == "x86_64":
        return [f"  testq {reg}, {reg}", f"  je {target}"]
    if isa == "aarch64":
        return [f"  cbz {reg}, {target}"]
    if isa == "riscv64":
        return [f"  beqz {reg}, {target}"]
    if isa.startswith("mips"):
        return [f"  beq {reg}, $zero, {target}", "  nop"]
    raise ValueError(f"unsupported ISA: {isa}")


@register
class IntAdd(CodeBlock):
    name = "asm_int_add"
    scratch_slots = 3

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        s0, s1, s2 = ctx.scratch_slots
        a = ctx.rng.randrange(1, 1 << 15)
        b = ctx.rng.randrange(1, 1 << 15)
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, a),
                ExpectedMemOp("load", s1, 8, b),
                ExpectedMemOp("store", s2, 8, _u32(a + b)),
            ],
            coarse_opcodes={"LOAD": 2, "INT_ADD": 1, "STORE": 1},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1, s2 = (m.arena_u64_index for m in plan.memops)
        lines = _prologue(ctx.block_id) + _load_base(ctx.isa)
        if ctx.isa == "x86_64":
            lines += _load_slot(ctx.isa, s0, "%r8")
            lines += _load_slot(ctx.isa, s1, "%r9")
            lines += ["  addq %r9, %r8"]
            lines += _store_slot(ctx.isa, s2, "%r8")
        elif ctx.isa == "aarch64":
            lines += _load_slot(ctx.isa, s0, "x9")
            lines += _load_slot(ctx.isa, s1, "x10")
            # Use ADDS (flag-writing) so the trace exercises NZCV
            # capture / FID_METAFLAGS emission.  Result is identical
            # to ADD; the only difference is that NZCV gets updated.
            lines += ["  adds x9, x9, x10"]
            lines += _store_slot(ctx.isa, s2, "x9")
        elif ctx.isa == "riscv64":
            lines += _load_slot(ctx.isa, s0, "t0")
            lines += _load_slot(ctx.isa, s1, "t1")
            lines += ["  add t0, t0, t1"]
            lines += _store_slot(ctx.isa, s2, "t0")
        else:
            lines += _load_slot(ctx.isa, s0, "$t0")
            lines += _load_slot(ctx.isa, s1, "$t1")
            lines += ["  addu $t0, $t0, $t1"]
            lines += _store_slot(ctx.isa, s2, "$t0")
        lines += _jump(ctx.isa, ctx.successor_labels[0])
        return "\n".join(lines) + "\n"


@register
class XorMix(CodeBlock):
    name = "asm_xor_mix"
    scratch_slots = 4

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        s0, s1, s2, s3 = ctx.scratch_slots
        a = ctx.rng.randrange(1, 1 << 15)
        b = ctx.rng.randrange(1, 1 << 15)
        v1 = _u32((a ^ b) + 0x55AA)
        v2 = _u32(v1 ^ b)
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, a),
                ExpectedMemOp("load", s1, 8, b),
                ExpectedMemOp("store", s2, 8, v1),
                ExpectedMemOp("store", s3, 8, v2),
            ],
            coarse_opcodes={"LOAD": 2, "XOR": 2, "INT_ADD": 1, "STORE": 2},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1, s2, s3 = (m.arena_u64_index for m in plan.memops)
        lines = _prologue(ctx.block_id) + _load_base(ctx.isa)
        if ctx.isa == "x86_64":
            lines += _load_slot(ctx.isa, s0, "%r8")
            lines += _load_slot(ctx.isa, s1, "%r9")
            lines += ["  xorq %r9, %r8", "  addq $21930, %r8"]
            lines += _store_slot(ctx.isa, s2, "%r8")
            lines += ["  xorq %r8, %r9"]
            lines += _store_slot(ctx.isa, s3, "%r9")
        elif ctx.isa == "aarch64":
            lines += _load_slot(ctx.isa, s0, "x9")
            lines += _load_slot(ctx.isa, s1, "x10")
            lines += ["  eor x9, x9, x10", "  movz x11, #21930", "  add x9, x9, x11"]
            lines += _store_slot(ctx.isa, s2, "x9")
            lines += ["  eor x10, x9, x10"]
            lines += _store_slot(ctx.isa, s3, "x10")
        elif ctx.isa == "riscv64":
            lines += _load_slot(ctx.isa, s0, "t0")
            lines += _load_slot(ctx.isa, s1, "t1")
            lines += ["  xor t0, t0, t1", "  li t2, 21930", "  add t0, t0, t2"]
            lines += _store_slot(ctx.isa, s2, "t0")
            lines += ["  xor t1, t0, t1"]
            lines += _store_slot(ctx.isa, s3, "t1")
        else:
            lines += _load_slot(ctx.isa, s0, "$t0")
            lines += _load_slot(ctx.isa, s1, "$t1")
            lines += ["  xor $t0, $t0, $t1", "  addiu $t0, $t0, 21930"]
            lines += _store_slot(ctx.isa, s2, "$t0")
            lines += ["  xor $t1, $t0, $t1"]
            lines += _store_slot(ctx.isa, s3, "$t1")
        lines += _jump(ctx.isa, ctx.successor_labels[0])
        return "\n".join(lines) + "\n"


@register
class LoadBurst(CodeBlock):
    name = "asm_load_burst"
    scratch_slots = 4

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        slots = ctx.scratch_slots
        vals = [ctx.rng.randrange(1, 1 << 14) for _ in slots[:-1]]
        acc = _u32(sum(vals))
        memops = [ExpectedMemOp("load", slots[i], 8, vals[i]) for i in range(3)]
        memops.append(ExpectedMemOp("store", slots[3], 8, acc))
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=memops,
            coarse_opcodes={"LOAD": 3, "INT_ADD": 2, "STORE": 1},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        slots = [m.arena_u64_index for m in plan.memops]
        lines = _prologue(ctx.block_id) + _load_base(ctx.isa)
        if ctx.isa == "x86_64":
            lines += _load_slot(ctx.isa, slots[0], "%r8")
            lines += _load_slot(ctx.isa, slots[1], "%r9")
            lines += _load_slot(ctx.isa, slots[2], "%r10")
            lines += ["  addq %r9, %r8", "  addq %r10, %r8"]
            lines += _store_slot(ctx.isa, slots[3], "%r8")
        elif ctx.isa == "aarch64":
            lines += _load_slot(ctx.isa, slots[0], "x9")
            lines += _load_slot(ctx.isa, slots[1], "x10")
            lines += _load_slot(ctx.isa, slots[2], "x11")
            lines += ["  add x9, x9, x10", "  add x9, x9, x11"]
            lines += _store_slot(ctx.isa, slots[3], "x9")
        elif ctx.isa == "riscv64":
            lines += _load_slot(ctx.isa, slots[0], "t0")
            lines += _load_slot(ctx.isa, slots[1], "t1")
            lines += _load_slot(ctx.isa, slots[2], "t2")
            lines += ["  add t0, t0, t1", "  add t0, t0, t2"]
            lines += _store_slot(ctx.isa, slots[3], "t0")
        else:
            lines += _load_slot(ctx.isa, slots[0], "$t0")
            lines += _load_slot(ctx.isa, slots[1], "$t1")
            lines += _load_slot(ctx.isa, slots[2], "$t2")
            lines += ["  addu $t0, $t0, $t1", "  addu $t0, $t0, $t2"]
            lines += _store_slot(ctx.isa, slots[3], "$t0")
        lines += _jump(ctx.isa, ctx.successor_labels[0])
        return "\n".join(lines) + "\n"


@register
class StoreBurst(CodeBlock):
    name = "asm_store_burst"
    scratch_slots = 3

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        vals = [ctx.rng.randrange(1, 1 << 16) for _ in ctx.scratch_slots]
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[
                ExpectedMemOp("store", slot, 8, val)
                for slot, val in zip(ctx.scratch_slots, vals)
            ],
            coarse_opcodes={"STORE": 3},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        lines = _prologue(ctx.block_id) + _load_base(ctx.isa)
        slots = [m.arena_u64_index for m in plan.memops]
        vals = [m.data for m in plan.memops]
        if ctx.isa == "x86_64":
            regs = ["%r8d", "%r9d", "%r10d"]
            outs = ["%r8", "%r9", "%r10"]
            for reg, out_reg, val, slot in zip(regs, outs, vals, slots):
                lines += [f"  movl ${val}, {reg}"]
                lines += _store_slot(ctx.isa, slot, out_reg)
        elif ctx.isa == "aarch64":
            regs = ["x9", "x10", "x11"]
            for reg, val, slot in zip(regs, vals, slots):
                lines += [f"  movz {reg}, #{val}"]
                lines += _store_slot(ctx.isa, slot, reg)
        elif ctx.isa == "riscv64":
            regs = ["t0", "t1", "t2"]
            for reg, val, slot in zip(regs, vals, slots):
                lines += [f"  li {reg}, {val}"]
                lines += _store_slot(ctx.isa, slot, reg)
        else:
            regs = ["$t0", "$t1", "$t2"]
            for reg, val, slot in zip(regs, vals, slots):
                lines += [f"  li {reg}, {val}"]
                lines += _store_slot(ctx.isa, slot, reg)
        lines += _jump(ctx.isa, ctx.successor_labels[0])
        return "\n".join(lines) + "\n"


@register
class CondBranch(CodeBlock):
    name = "cond_branch"
    num_successors = 2
    scratch_slots = 2
    needs_branch_slot = True
    randomizable = False
    coverage_probe = False

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        assert ctx.branch_slot is not None
        assert ctx.branch_outcome is not None
        s0, s1 = ctx.scratch_slots
        a = ctx.rng.randrange(1, 1 << 15)
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[
                ExpectedMemOp("load", ctx.branch_slot, 8,
                              1 if ctx.branch_outcome else 0),
                ExpectedMemOp("load", s0, 8, a),
                ExpectedMemOp("store", s1, 8, _u32(a ^ 0xA5A5)),
            ],
            coarse_opcodes={"LOAD": 2, "XOR": 1, "STORE": 1, "BRANCH": 1},
            branch_pred=ctx.branch_outcome,
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        assert ctx.branch_slot is not None
        s0 = plan.memops[1].arena_u64_index
        s1 = plan.memops[2].arena_u64_index
        branch_target = ctx.successor_labels[1]
        lines = _prologue(ctx.block_id) + _load_base(ctx.isa)
        if ctx.isa == "x86_64":
            lines += _load_slot(ctx.isa, ctx.branch_slot, "%r8")
            lines += _load_slot(ctx.isa, s0, "%r9")
            lines += ["  xorq $42405, %r9"]
            lines += _store_slot(ctx.isa, s1, "%r9")
            lines += _branch_zero_to(ctx.isa, "%r8", branch_target)
        elif ctx.isa == "aarch64":
            lines += _load_slot(ctx.isa, ctx.branch_slot, "x9")
            lines += _load_slot(ctx.isa, s0, "x10")
            lines += ["  movz x11, #0xa5a5", "  eor x10, x10, x11"]
            lines += _store_slot(ctx.isa, s1, "x10")
            lines += _branch_zero_to(ctx.isa, "x9", branch_target)
        elif ctx.isa == "riscv64":
            lines += _load_slot(ctx.isa, ctx.branch_slot, "t0")
            lines += _load_slot(ctx.isa, s0, "t1")
            lines += ["  li t2, 42405", "  xor t1, t1, t2"]
            lines += _store_slot(ctx.isa, s1, "t1")
            lines += _branch_zero_to(ctx.isa, "t0", branch_target)
        else:
            lines += _load_slot(ctx.isa, ctx.branch_slot, "$t0")
            lines += _load_slot(ctx.isa, s0, "$t1")
            lines += ["  xori $t1, $t1, 0xa5a5"]
            lines += _store_slot(ctx.isa, s1, "$t1")
            lines += _branch_zero_to(ctx.isa, "$t0", branch_target)
        return "\n".join(lines) + "\n"


@register
class LoopHead(CodeBlock):
    name = "loop_head"
    num_successors = 2
    scratch_slots = 1
    randomizable = False
    coverage_probe = False

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        counter = max(1, int(ctx.loop_iterations)) + 1
        slot = ctx.scratch_slots[0]
        # Per-iteration memops: counter decrements from `counter` to 1
        # across this block's CP executions (the iter that produces
        # store=0 takes the exit branch and ends the loop).  This is the
        # data trajectory the encoder must reproduce on every execution
        # of this template; a regression that fails to refresh
        # load_data/store_data on subsequent iterations would show up as
        # stale (counter, counter-1) values on iter 2+.
        per_iter: list[list[ExpectedMemOp]] = []
        for c in range(counter, 0, -1):
            per_iter.append([
                ExpectedMemOp("load", slot, 8, c),
                ExpectedMemOp("store", slot, 8, c - 1),
            ])
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[
                ExpectedMemOp("load", slot, 8, counter),
                ExpectedMemOp("store", slot, 8, counter - 1),
            ],
            per_iteration_memops=per_iter,
            coarse_opcodes={"LOAD": 1, "STORE": 1, "INT_SUB": 1, "BRANCH": 1},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        slot = plan.memops[0].arena_u64_index
        exit_target = ctx.successor_labels[1]
        lines = _prologue(ctx.block_id) + _load_base(ctx.isa)
        if ctx.isa == "x86_64":
            lines += _load_slot(ctx.isa, slot, "%r8")
            lines += ["  xorl %r9d, %r9d", "  testq %r8, %r8", "  setne %r9b",
                      "  subq %r9, %r8"]
            lines += _store_slot(ctx.isa, slot, "%r8")
            lines += _branch_zero_to(ctx.isa, "%r8", exit_target)
        elif ctx.isa == "aarch64":
            lines += _load_slot(ctx.isa, slot, "x9")
            lines += ["  cmp x9, #0", "  cset x10, ne", "  sub x9, x9, x10"]
            lines += _store_slot(ctx.isa, slot, "x9")
            lines += _branch_zero_to(ctx.isa, "x9", exit_target)
        elif ctx.isa == "riscv64":
            lines += _load_slot(ctx.isa, slot, "t0")
            lines += ["  sltiu t1, t0, 1", "  xori t1, t1, 1",
                      "  sub t0, t0, t1"]
            lines += _store_slot(ctx.isa, slot, "t0")
            lines += _branch_zero_to(ctx.isa, "t0", exit_target)
        else:
            lines += _load_slot(ctx.isa, slot, "$t0")
            lines += ["  sltu $t1, $zero, $t0", "  subu $t0, $t0, $t1"]
            lines += _store_slot(ctx.isa, slot, "$t0")
            lines += _branch_zero_to(ctx.isa, "$t0", exit_target)
        return "\n".join(lines) + "\n"


@register
class LoopBody(CodeBlock):
    name = "loop_body"
    scratch_slots = 2
    randomizable = False
    coverage_probe = False

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        s0, s1 = ctx.scratch_slots
        seed = ctx.rng.randrange(1, 1 << 15)
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, seed),
                ExpectedMemOp("store", s1, 8, _u32(seed + 7)),
            ],
            coarse_opcodes={"LOAD": 1, "INT_ADD": 1, "STORE": 1, "BRANCH": 1},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1 = (m.arena_u64_index for m in plan.memops)
        lines = _prologue(ctx.block_id) + _load_base(ctx.isa)
        if ctx.isa == "x86_64":
            lines += _load_slot(ctx.isa, s0, "%r8")
            lines += ["  addq $7, %r8"]
            lines += _store_slot(ctx.isa, s1, "%r8")
        elif ctx.isa == "aarch64":
            lines += _load_slot(ctx.isa, s0, "x9")
            lines += ["  add x9, x9, #7"]
            lines += _store_slot(ctx.isa, s1, "x9")
        elif ctx.isa == "riscv64":
            lines += _load_slot(ctx.isa, s0, "t0")
            lines += ["  addi t0, t0, 7"]
            lines += _store_slot(ctx.isa, s1, "t0")
        else:
            lines += _load_slot(ctx.isa, s0, "$t0")
            lines += ["  addiu $t0, $t0, 7"]
            lines += _store_slot(ctx.isa, s1, "$t0")
        lines += _jump(ctx.isa, ctx.successor_labels[0])
        return "\n".join(lines) + "\n"


@register
class LoopExit(CodeBlock):
    name = "loop_exit"
    scratch_slots = 2
    randomizable = False
    coverage_probe = False

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        s0, s1 = ctx.scratch_slots
        a = ctx.rng.randrange(1, 1 << 14)
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, a),
                ExpectedMemOp("store", s1, 8, _u32(a ^ 0x33)),
            ],
            coarse_opcodes={"LOAD": 1, "XOR": 1, "STORE": 1, "BRANCH": 1},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1 = (m.arena_u64_index for m in plan.memops)
        lines = _prologue(ctx.block_id) + _load_base(ctx.isa)
        if ctx.isa == "x86_64":
            lines += _load_slot(ctx.isa, s0, "%r8")
            lines += ["  xorq $51, %r8"]
            lines += _store_slot(ctx.isa, s1, "%r8")
        elif ctx.isa == "aarch64":
            lines += _load_slot(ctx.isa, s0, "x9")
            lines += ["  mov x10, #0x33", "  eor x9, x9, x10"]
            lines += _store_slot(ctx.isa, s1, "x9")
        elif ctx.isa == "riscv64":
            lines += _load_slot(ctx.isa, s0, "t0")
            lines += ["  xori t0, t0, 51"]
            lines += _store_slot(ctx.isa, s1, "t0")
        else:
            lines += _load_slot(ctx.isa, s0, "$t0")
            lines += ["  xori $t0, $t0, 51"]
            lines += _store_slot(ctx.isa, s1, "$t0")
        lines += _jump(ctx.isa, ctx.successor_labels[0])
        return "\n".join(lines) + "\n"


@register
class StrideLoopHead(CodeBlock):
    """CFG self-looping block that varies the LOAD/STORE address every
    iteration of the same template — stresses the state-delta encoder's
    per-execution address path that no other deterministic-asm probe
    touches.

    On every execution this template runs ONE iteration's worth of asm:
    load counter, strided load at slot[counter], add, strided store
    back, decrement counter, store counter back, branch.  The CFG wires
    successors[0] = self (back-edge) and successors[1] = exit, with the
    branch test choosing.  Branch step semantics mirror LoopHead's
    loop_remaining machinery (added to _branch_step / _initial_state in
    generator.py).

    Same template runs `loop_iterations` times; load_addr/store_addr
    differ across executions because the base register varies.  Per-iter
    expected memops are declared so the per-execution data check
    surfaces any stale-address or stale-data delta as a multiset
    mismatch on the diverging iteration.
    """
    name = "stride_loop_head"
    num_successors = 2
    # 1 counter slot + STRIDE_DEPTH stride slots.  The generator pins
    # loop_iterations to STRIDE_DEPTH at most; smaller loop_iterations
    # uses a prefix of the stride table.
    STRIDE_DEPTH: ClassVar[int] = 16
    scratch_slots = 17
    supported_isas = ("x86_64",)
    randomizable = False
    coverage_probe = False

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        n_iters = max(1, int(ctx.loop_iterations))
        if len(ctx.scratch_slots) < n_iters + 1:
            raise ValueError(
                f"StrideLoopHead needs scratch_slots = loop_iterations+1; "
                f"got {len(ctx.scratch_slots)} for n_iters={n_iters}"
            )
        ctr_slot = ctx.scratch_slots[0]
        stride_slots = ctx.scratch_slots[1:1 + n_iters]
        # Counter starts at n_iters and decrements to 0; the branch
        # exits when counter reaches 0.  On iter j (1-indexed, j=1
        # being the first execution), the counter loaded is
        # n_iters - j + 1, the strided slot is stride_slots[counter-1].
        # We declare the per-iter expected memops in execution order.
        per_iter: list[list[ExpectedMemOp]] = []
        for j in range(1, n_iters + 1):
            counter_pre = n_iters - j + 1
            slot = stride_slots[counter_pre - 1]
            seed = 0x100 * counter_pre
            iter_ops = [
                ExpectedMemOp("load", ctr_slot, 8, counter_pre),
                ExpectedMemOp("load", slot, 8, seed),
                ExpectedMemOp("store", slot, 8, seed + 7),
                ExpectedMemOp("store", ctr_slot, 8, counter_pre - 1),
            ]
            per_iter.append(iter_ops)
        # `memops` lists iter-1's pair (used by the first-exec check);
        # init_values takes the load .data on each, which pre-populates
        # ctr_slot to n_iters and stride_slots[k] to 0x100*(k+1).
        memops = list(per_iter[0])
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=memops,
            per_iteration_memops=per_iter,
            coarse_opcodes={"LOAD": 2, "STORE": 2, "INT_SUB": 1, "BRANCH": 1},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        n_iters = max(1, int(ctx.loop_iterations))
        ctr_slot = ctx.scratch_slots[0]
        stride_base = ctx.scratch_slots[1]
        for k in range(n_iters):
            if ctx.scratch_slots[1 + k] != stride_base + k:
                raise ValueError(
                    "StrideLoopHead requires contiguous stride scratch slots"
                )
        # successor[0] = self (back-edge); successor[1] = exit.  Both
        # are emitted as explicit jumps so this block's layout is
        # independent of physical adjacency.
        back_target = ctx.successor_labels[0]
        exit_target = ctx.successor_labels[1]
        stride_off = (stride_base - 1) * 8  # so (r15, r8, 8) hits slot[counter-1]
        lines = _prologue(ctx.block_id) + _load_base(ctx.isa) + [
            f"  movq {ctr_slot * 8}(%r15), %r8",
            f"  movq {stride_off}(%r15, %r8, 8), %r9",
            "  addq $7, %r9",
            f"  movq %r9, {stride_off}(%r15, %r8, 8)",
            "  subq $1, %r8",
            f"  movq %r8, {ctr_slot * 8}(%r15)",
            "  testq %r8, %r8",
            f"  je {exit_target}",
            f"  jmp {back_target}",
        ]
        return "\n".join(lines) + "\n"


@register
class ExitBlock(CodeBlock):
    name = "exit"
    num_successors = 0
    scratch_slots = 0
    randomizable = False
    coverage_probe = False
    terminal = True

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[],
            coarse_opcodes={"SYSCALL": 1},
            terminal=True,
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        lines = _prologue(ctx.block_id)
        if ctx.isa == "x86_64":
            lines += ["  mov $60, %rax", "  xor %rdi, %rdi", "  syscall"]
        elif ctx.isa == "aarch64":
            lines += ["  mov x8, #93", "  mov x0, #0", "  svc #0"]
        elif ctx.isa == "riscv64":
            lines += ["  li a7, 93", "  li a0, 0", "  ecall"]
        else:
            lines += ["  li $v0, 4001", "  move $a0, $zero", "  syscall"]
        return "\n".join(lines) + "\n"


@register
class DirectCall(CodeBlock):
    name = "direct_call"
    scratch_slots = 0
    randomizable = False

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[],
            asserted_branch_types=["BRANCH_DIRECT_JUMP"],
            asserted_opcodes=["BRANCH"],
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        lines = _prologue(ctx.block_id)
        if ctx.isa == "x86_64":
            lines += ["  xor %edi, %edi", "  call wptgen_leaf"]
        elif ctx.isa == "aarch64":
            lines += ["  mov x0, #0", "  bl wptgen_leaf"]
        elif ctx.isa == "riscv64":
            lines += ["  li a0, 0", "  jal ra, wptgen_leaf"]
        else:
            # Keep mipsel self-contained: direct local call + return.
            lines += [
                "  jal 1f",
                "  nop",
                "  b 2f",
                "  nop",
                "1:",
                "  jr $ra",
                "  nop",
                "2:",
            ]
        lines += _jump(ctx.isa, ctx.successor_labels[0])
        return "\n".join(lines) + "\n"


@register
class IndirectCall(CodeBlock):
    name = "indirect_call"
    scratch_slots = 0
    randomizable = False

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[],
            asserted_branch_types=["BRANCH_INDIRECT_JUMP"],
            asserted_opcodes=["BRANCH"],
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        lines = _prologue(ctx.block_id)
        if ctx.isa == "x86_64":
            lines += [
                "  xor %edi, %edi",
                "  leaq wptgen_leaf(%rip), %rax",
                "  call *%rax",
            ]
        elif ctx.isa == "aarch64":
            lines += [
                "  mov x0, #0",
                "  adrp x9, wptgen_leaf",
                "  add x9, x9, :lo12:wptgen_leaf",
                "  blr x9",
            ]
        elif ctx.isa == "riscv64":
            lines += ["  li a0, 0", "  la t0, wptgen_leaf", "  jalr ra, 0(t0)"]
        else:
            # Keep mipsel self-contained: indirect local call + return.
            lines += [
                "  lui $t9, %hi(1f)",
                "  addiu $t9, $t9, %lo(1f)",
                "  jalr $t9",
                "  nop",
                "  b 2f",
                "  nop",
                "1:",
                "  jr $ra",
                "  nop",
                "2:",
            ]
        lines += _jump(ctx.isa, ctx.successor_labels[0])
        return "\n".join(lines) + "\n"


@register
class IndirectJump(CodeBlock):
    name = "indirect_jump"
    scratch_slots = 0
    randomizable = False

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[],
            asserted_branch_types=["BRANCH_INDIRECT_JUMP"],
            asserted_opcodes=["BRANCH"],
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        target = ctx.successor_labels[0]
        lines = _prologue(ctx.block_id)
        if ctx.isa == "x86_64":
            lines += [f"  leaq {target}(%rip), %rax", "  jmp *%rax"]
        elif ctx.isa == "aarch64":
            lines += [
                f"  adrp x9, {target}",
                f"  add x9, x9, :lo12:{target}",
                "  br x9",
            ]
        elif ctx.isa == "riscv64":
            lines += [f"  la t0, {target}", "  jr t0"]
        else:
            lines += [
                f"  lui $t9, %hi({target})",
                f"  addiu $t9, $t9, %lo({target})",
                "  jr $t9",
                "  nop",
            ]
        return "\n".join(lines) + "\n"


@register
class NarrowMemData(CodeBlock):
    name = "narrow_mem_data"
    scratch_slots = 8
    randomizable = False
    coverage_probe = True

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        load_slots = ctx.scratch_slots[:4]
        store_slots = ctx.scratch_slots[4:8]
        sizes = [1, 2, 4]
        if ctx.isa != "mipsel":
            sizes.append(8)
        values = {
            1: 0x7B,
            2: 0x55AA,
            4: 0x89ABCDEF,
            8: 0x0123456789ABCDEF,
        }
        memops: list[ExpectedMemOp] = []
        reg_names = {
            "x86_64": ["REG_GPR6", "REG_GPR7", "REG_GPR8", "REG_GPR9"],
            "aarch64": ["REG_GPR9", "REG_GPR10", "REG_GPR11", "REG_GPR12"],
            "riscv64": ["REG_GPR5", "REG_GPR6", "REG_GPR7", "REG_GPR28"],
            "mipsel": ["REG_GPR8", "REG_GPR9", "REG_GPR10"],
        }[ctx.isa]
        reg_asserts: list[dict] = []
        for i, size in enumerate(sizes):
            data = _mask_bytes(values[size], size)
            memops.append(ExpectedMemOp("load", load_slots[i], size, data))
            memops.append(ExpectedMemOp("store", store_slots[i], size, data))
            reg_asserts.append({
                "reg": reg_names[i],
                "bits": size * 8,
                "value": data,
            })
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=memops,
            reg_value_assertions=reg_asserts,
            coarse_opcodes={"LOAD": len(sizes), "STORE": len(sizes)},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        loads = [m for m in plan.memops if m.kind == "load"]
        stores = [m for m in plan.memops if m.kind == "store"]
        lines = _prologue(ctx.block_id) + _load_base(ctx.isa)
        if ctx.isa == "x86_64":
            for m, dst in zip(loads, ("%r8", "%r9", "%r10", "%r11")):
                off = m.arena_u64_index * 8
                if m.size == 1:
                    lines.append(f"  movzbq {off}(%r15), {dst}")
                elif m.size == 2:
                    lines.append(f"  movzwq {off}(%r15), {dst}")
                elif m.size == 4:
                    lines.append(f"  movl {off}(%r15), {dst}d")
                else:
                    lines.append(f"  movq {off}(%r15), {dst}")
            for m, src in zip(stores, ("%r8", "%r9", "%r10", "%r11")):
                off = m.arena_u64_index * 8
                if m.size == 1:
                    lines.append(f"  movb {src}b, {off}(%r15)")
                elif m.size == 2:
                    lines.append(f"  movw {src}w, {off}(%r15)")
                elif m.size == 4:
                    lines.append(f"  movl {src}d, {off}(%r15)")
                else:
                    lines.append(f"  movq {src}, {off}(%r15)")
        elif ctx.isa == "aarch64":
            regs = ["w9", "w10", "w11", "x12"]
            for m, reg in zip(loads, regs):
                off = m.arena_u64_index * 8
                if m.size == 1:
                    lines.append(f"  ldrb {reg}, [x20, #{off}]")
                elif m.size == 2:
                    lines.append(f"  ldrh {reg}, [x20, #{off}]")
                elif m.size == 4:
                    lines.append(f"  ldr {reg}, [x20, #{off}]")
                else:
                    lines.append(f"  ldr {reg}, [x20, #{off}]")
            for m, reg in zip(stores, regs):
                off = m.arena_u64_index * 8
                if m.size == 1:
                    lines.append(f"  strb {reg}, [x20, #{off}]")
                elif m.size == 2:
                    lines.append(f"  strh {reg}, [x20, #{off}]")
                elif m.size == 4:
                    lines.append(f"  str {reg}, [x20, #{off}]")
                else:
                    lines.append(f"  str {reg}, [x20, #{off}]")
        elif ctx.isa == "riscv64":
            regs = ["t0", "t1", "t2", "t3"]
            for m, reg in zip(loads, regs):
                off = m.arena_u64_index * 8
                op = {1: "lbu", 2: "lhu", 4: "lwu", 8: "ld"}[m.size]
                lines.append(f"  {op} {reg}, {off}(t6)")
            for m, reg in zip(stores, regs):
                off = m.arena_u64_index * 8
                op = {1: "sb", 2: "sh", 4: "sw", 8: "sd"}[m.size]
                lines.append(f"  {op} {reg}, {off}(t6)")
        else:
            regs = ["$t0", "$t1", "$t2"]
            for m, reg in zip(loads, regs):
                off = m.arena_u64_index * 8
                op = {1: "lbu", 2: "lhu", 4: "lw"}[m.size]
                lines.append(f"  {op} {reg}, {off}($t8)")
            for m, reg in zip(stores, regs):
                off = m.arena_u64_index * 8
                op = {1: "sb", 2: "sh", 4: "sw"}[m.size]
                lines.append(f"  {op} {reg}, {off}($t8)")
        lines += _jump(ctx.isa, ctx.successor_labels[0])
        return "\n".join(lines) + "\n"


@register
class WideMemDataAarch64(CodeBlock):
    name = "wide_mem_data_aarch64"
    scratch_slots = 4
    supported_isas = ("aarch64",)
    randomizable = False
    coverage_probe = True

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        load_slot, store_slot = ctx.scratch_slots[0], ctx.scratch_slots[2]
        data = _byte_pattern(0x31, 16)
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[
                ExpectedMemOp("load", load_slot, 16, data),
                ExpectedMemOp("store", store_slot, 16, data),
            ],
            reg_value_assertions=[
                {"reg": "REG_VEC0", "bits": 128, "value": data},
            ],
            coarse_opcodes={"LOAD": 1, "STORE": 1, "VEC_MOV": 2},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        src = plan.memops[0].arena_u64_index * 8
        dst = plan.memops[1].arena_u64_index * 8
        lines = _prologue(ctx.block_id) + _load_base(ctx.isa) + [
            f"  add x9, x20, #{src}",
            "  ldr q0, [x9]",
            "  orr v1.16b, v0.16b, v0.16b",
            f"  add x9, x20, #{dst}",
            "  str q0, [x9]",
        ]
        lines += _jump(ctx.isa, ctx.successor_labels[0])
        return "\n".join(lines) + "\n"


@register
class WideMemDataX86(CodeBlock):
    name = "wide_mem_data_x86"
    scratch_slots = 12
    supported_isas = ("x86_64",)
    randomizable = False
    coverage_probe = True

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        s = ctx.scratch_slots
        data16 = _byte_pattern(0x41, 16)
        data32 = _byte_pattern(0x58, 32)
        data32_lo = data32 & ((1 << 128) - 1)
        data32_hi = data32 >> 128
        memops: list[ExpectedMemOp] = []
        memops.extend([
            ExpectedMemOp("load", s[0], 16, data16),
            ExpectedMemOp("store", s[2], 16, data16),
            ExpectedMemOp("load", s[4], 16, data32_lo),
            ExpectedMemOp("load", s[6], 16, data32_hi),
            ExpectedMemOp("store", s[8], 16, data32_lo),
            ExpectedMemOp("store", s[10], 16, data32_hi),
        ])
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=memops,
            reg_value_assertions=[
                {"reg": "REG_VEC0", "bits": 128, "value": data16},
            ],
            coarse_opcodes={"LOAD": 3, "STORE": 3, "VEC_MOV": 4},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        load16 = plan.memops[0]
        store16 = plan.memops[1]
        load32 = plan.memops[2]
        store32 = plan.memops[4]
        lines = _prologue(ctx.block_id) + _load_base(ctx.isa)
        lines += [
            f"  movdqu {load16.arena_u64_index * 8}(%r15), %xmm0",
            "  pxor %xmm0, %xmm1",
            f"  movdqu %xmm0, {store16.arena_u64_index * 8}(%r15)",
        ]
        lines += [
            f"  vmovdqu {load32.arena_u64_index * 8}(%r15), %ymm1",
            "  vpxor %ymm1, %ymm1, %ymm2",
            f"  vmovdqu %ymm1, {store32.arena_u64_index * 8}(%r15)",
        ]
        lines += _jump(ctx.isa, ctx.successor_labels[0])
        return "\n".join(lines) + "\n"


@register
class X86RepIterationFanout(CodeBlock):
    """
    Exercises the tracer's REP-iteration fan-out path.  Each REP MOVSQ
    iteration is its own 1-insn self-loop true-BB in the body stream:
    iter 1 stays on the entering BB (terminated by the REP branch),
    iter 2..N each emit a separate body entry on the 1-insn REP
    sub-template with exactly one (load, store) pair.  This block
    asserts via memop_count_assertions that we see (loads=1, stores=1)
    entries — never the pre-fan-out (loads=8, stores=8) or
    (loads=20, stores=20) buckets.

    Per-memop validation via the `memops` list is intentionally
    skipped: the existing _check_cp_memops walker aggregates dyn_params
    on the *first* body entry of each template, but with fan-out the
    iter 2..N memops live on subsequent entries of the REP sub-
    template.  The per-iteration count assertion below catches the
    same regressions (any single entry having loads>1 or stores>1 on
    a REP insn would fail), and the coarse-opcode assertion on
    `INT_ADD: 28` catches the REP being mis-emitted as a single
    aggregate entry (which would produce a single INT_ADD count, not
    28).

    Uses two REP MOVSQ calls (ECX=8 and ECX=20) so the assertion still
    catches a regression where the fan-out only fires for one count.
    """
    name = "x86_rep_iteration_fanout"
    scratch_slots = 56
    supported_isas = ("x86_64",)
    randomizable = False
    coverage_probe = True

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        s = ctx.scratch_slots
        # Real correctness check: the fan-out must place EVERY one of
        # the 56 expected memops (8 src/dst pairs for MOVSQ#1 +
        # 20 src/dst pairs for MOVSQ#2) into the trace, each on its
        # own body entry.  aggregate_fanout=True tells the cp_memops
        # walker to scan every body entry across the bipartite
        # component, not just each template's first entry.  A
        # regression where the fan-out drops iterations, mis-orders
        # the pointer advance, or aggregates memops onto a single
        # entry will surface here as missing / extra memops.
        memops: list[ExpectedMemOp] = []
        for count, src_base, dst_base, seed in ((8,  s[0],  s[8],  0x1111),
                                               (20, s[16], s[36], 0x2222)):
            for i in range(count):
                data = (seed + i * 0x101010101010101) & ((1 << 64) - 1)
                memops.append(ExpectedMemOp("load",  src_base + i, 8, data))
                memops.append(ExpectedMemOp("store", dst_base + i, 8, data))
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=memops,
            ordered_memops=False,
            aggregate_fanout=True,
            memop_count_assertions=[
                # Independent shape check: every body entry that
                # touches the REP insn must carry exactly one load
                # and one store (the per-iteration fan-out shape).
                # A regression where the fan-out fails to fire would
                # show up as a single entry with loads=8 or 20.
                {"loads": 1, "stores": 1, "overflow": False},
            ],
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s = ctx.scratch_slots
        lines = _prologue(ctx.block_id) + _load_base(ctx.isa) + [
            "  cld",
            f"  leaq {s[0] * 8}(%r15), %rsi",
            f"  leaq {s[8] * 8}(%r15), %rdi",
            "  mov $8, %ecx",
            "  rep movsq",
            f"  leaq {s[16] * 8}(%r15), %rsi",
            f"  leaq {s[36] * 8}(%r15), %rdi",
            "  mov $20, %ecx",
            "  rep movsq",
        ]
        lines += _jump(ctx.isa, ctx.successor_labels[0])
        return "\n".join(lines) + "\n"


@register
class IndirectOneTargetWP(CodeBlock):
    name = "indirect_wp_one_target"
    scratch_slots = 0
    randomizable = False
    coverage_probe = True

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[],
            asserted_branch_types=["BRANCH_INDIRECT_JUMP"],
            asserted_opcodes=["BRANCH"],
            indirect_wp_assertions=[{"mode": "one_target_fallthrough"}],
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        p = f".Liwp_one_{ctx.block_id}"
        target = ctx.successor_labels[0]
        lines = _prologue(ctx.block_id)
        if ctx.isa == "x86_64":
            lines += [
                "  mov $0, %r8d",
                f"{p}_dispatch:",
                f"  leaq {p}_target(%rip), %rax",
                f"{p}_branch:",
                "  jmp *%rax",
                f"{p}_fallthrough:",
                f"  jmp {p}_done",
                f"{p}_target:",
                "  inc %r8d",
                "  cmp $2, %r8d",
                f"  jl {p}_dispatch",
                f"{p}_done:",
            ]
        elif ctx.isa == "aarch64":
            lines += [
                "  mov x9, #0",
                f"{p}_dispatch:",
                f"  adr x10, {p}_target",
                f"{p}_branch:",
                "  br x10",
                f"{p}_fallthrough:",
                f"  b {p}_done",
                f"{p}_target:",
                "  add x9, x9, #1",
                "  cmp x9, #2",
                f"  b.lt {p}_dispatch",
                f"{p}_done:",
            ]
        elif ctx.isa == "riscv64":
            lines += [
                "  li t0, 0",
                f"{p}_dispatch:",
                f"  lla t1, {p}_target",
                f"{p}_branch:",
                "  jr t1",
                f"{p}_fallthrough:",
                f"  j {p}_done",
                f"{p}_target:",
                "  addi t0, t0, 1",
                "  li t2, 2",
                f"  blt t0, t2, {p}_dispatch",
                f"{p}_done:",
            ]
        else:
            lines += [
                "  li $t0, 0",
                f"{p}_dispatch:",
                f"  lui $t9, %hi({p}_target)",
                f"  addiu $t9, $t9, %lo({p}_target)",
                f"{p}_branch:",
                "  jr $t9",
                "  nop",
                f"{p}_fallthrough:",
                f"  b {p}_done",
                "  nop",
                f"{p}_target:",
                "  addiu $t0, $t0, 1",
                "  slti $t2, $t0, 2",
                f"  bne $t2, $zero, {p}_dispatch",
                "  nop",
                f"{p}_done:",
            ]
        lines += _jump(ctx.isa, target)
        return "\n".join(lines) + "\n"


@register
class IndirectMultiTargetWP(CodeBlock):
    name = "indirect_wp_multi_target"
    scratch_slots = 0
    randomizable = False
    coverage_probe = True

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[],
            asserted_branch_types=["BRANCH_INDIRECT_JUMP"],
            asserted_opcodes=["BRANCH"],
            indirect_wp_assertions=[{"mode": "multi_target_most_frequent"}],
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        p = f".Liwp_multi_{ctx.block_id}"
        target = ctx.successor_labels[0]
        lines = _prologue(ctx.block_id)
        if ctx.isa == "x86_64":
            lines += [
                "  mov $0, %r8d",
                f"{p}_dispatch:",
                "  cmp $2, %r8d",
                f"  jl {p}_choose_a",
                f"  leaq {p}_target_b(%rip), %rax",
                f"  jmp {p}_branch",
                f"{p}_choose_a:",
                f"  leaq {p}_target_a(%rip), %rax",
                f"{p}_branch:",
                "  jmp *%rax",
                f"{p}_fallthrough:",
                f"  jmp {p}_done",
                f"{p}_target_a:",
                "  inc %r8d",
                f"  jmp {p}_dispatch",
                f"{p}_target_b:",
                "  inc %r8d",
                f"{p}_done:",
            ]
        elif ctx.isa == "aarch64":
            lines += [
                "  mov x9, #0",
                f"{p}_dispatch:",
                "  cmp x9, #2",
                f"  b.lt {p}_choose_a",
                f"  adr x10, {p}_target_b",
                f"  b {p}_branch",
                f"{p}_choose_a:",
                f"  adr x10, {p}_target_a",
                f"{p}_branch:",
                "  br x10",
                f"{p}_fallthrough:",
                f"  b {p}_done",
                f"{p}_target_a:",
                "  add x9, x9, #1",
                f"  b {p}_dispatch",
                f"{p}_target_b:",
                "  add x9, x9, #1",
                f"{p}_done:",
            ]
        elif ctx.isa == "riscv64":
            lines += [
                "  li t0, 0",
                f"{p}_dispatch:",
                "  li t2, 2",
                f"  blt t0, t2, {p}_choose_a",
                f"  lla t1, {p}_target_b",
                f"  j {p}_branch",
                f"{p}_choose_a:",
                f"  lla t1, {p}_target_a",
                f"{p}_branch:",
                "  jr t1",
                f"{p}_fallthrough:",
                f"  j {p}_done",
                f"{p}_target_a:",
                "  addi t0, t0, 1",
                f"  j {p}_dispatch",
                f"{p}_target_b:",
                "  addi t0, t0, 1",
                f"{p}_done:",
            ]
        else:
            lines += [
                "  li $t0, 0",
                f"{p}_dispatch:",
                "  slti $t2, $t0, 2",
                f"  bne $t2, $zero, {p}_choose_a",
                "  nop",
                f"  lui $t9, %hi({p}_target_b)",
                f"  addiu $t9, $t9, %lo({p}_target_b)",
                f"  b {p}_branch",
                "  nop",
                f"{p}_choose_a:",
                f"  lui $t9, %hi({p}_target_a)",
                f"  addiu $t9, $t9, %lo({p}_target_a)",
                f"{p}_branch:",
                "  jr $t9",
                "  nop",
                f"{p}_fallthrough:",
                f"  b {p}_done",
                "  nop",
                f"{p}_target_a:",
                "  addiu $t0, $t0, 1",
                f"  b {p}_dispatch",
                "  nop",
                f"{p}_target_b:",
                "  addiu $t0, $t0, 1",
                f"{p}_done:",
            ]
        lines += _jump(ctx.isa, target)
        return "\n".join(lines) + "\n"


@register
class RegIdSweep(CodeBlock):
    name = "regid_sweep"
    scratch_slots = 0
    randomizable = False
    coverage_probe = True

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        return BlockPlan(block_id=ctx.block_id, name=cls.name, memops=[])

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        lines = _prologue(ctx.block_id)
        if ctx.isa == "x86_64":
            gprs = [
                "%rax", "%rcx", "%rdx", "%rbx", "%rsi", "%rdi",
                "%r8", "%r9", "%r10", "%r11", "%r12", "%r13",
                "%r14", "%r15",
            ]
            for reg in gprs:
                lines.append(f"  mov {reg}, {reg}")
            lines += [
                "  mov %rsp, %rax",
                "  mov %rbp, %rax",
                "  leaq 0(%rip), %rax",
                "  cmp %rax, %rax",
                "  mov %cs, %ax",
                "  mov %ds, %ax",
                "  mov %es, %ax",
                "  mov %ss, %ax",
                "  mov %fs, %ax",
                "  mov %gs, %ax",
            ]
            for i in range(16):
                lines.append(f"  pxor %xmm{i}, %xmm{i}")
            lines += [
                "  fldz", "  fld1", "  fldpi", "  fldln2",
                "  fldl2e", "  fldl2t", "  fldlg2", "  fldz",
                "  fxch %st(7)", "  fxch %st(6)", "  fxch %st(5)",
                "  fxch %st(4)", "  fxch %st(3)", "  fxch %st(2)",
                "  fxch %st(1)", "  fstp %st(0)", "  fstp %st(0)",
                "  fstp %st(0)", "  fstp %st(0)", "  fstp %st(0)",
                "  fstp %st(0)", "  fstp %st(0)", "  fstp %st(0)",
            ]
        elif ctx.isa == "aarch64":
            for i in range(29):
                lines.append(f"  mov x{i}, x{i}")
            lines += [
                "  mov x0, x29",
                "  mov x0, x30",
                "  mov w0, w29",
                "  mov w0, w30",
                "  mov x0, sp",
                "  mov x0, xzr",
                "  cmp x0, x0",
            ]
            for i in range(32):
                lines.append(f"  orr v{i}.16b, v{i}.16b, v{i}.16b")
            lines += [
                "  mrs x0, fpcr",
                "  mrs x1, fpsr",
            ]
        elif ctx.isa == "riscv64":
            regs = [
                "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
                "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
                "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
                "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
            ]
            for reg in regs:
                lines.append(f"  addi {reg}, {reg}, 0")
            for i in range(32):
                lines.append(f"  fsgnj.d f{i}, f{i}, f{i}")
            lines += [
                "  frcsr t0",
                "  fscsr t0, t0",
                "  .option push",
                "  .option arch, +v",
                "  vsetvli t0, zero, e64, m1, ta, ma",
            ]
            for i in range(32):
                lines.append(f"  vmv.v.v v{i}, v{i}")
            lines.append("  .option pop")
        else:
            lines += ["  .set push", "  .set noat"]
            regs = [
                "$zero", "$1", "$v0", "$v1", "$a0", "$a1", "$a2",
                "$a3", "$t0", "$t1", "$t2", "$t3", "$t4", "$t5",
                "$t6", "$t7", "$s0", "$s1", "$s2", "$s3", "$s4",
                "$s5", "$s6", "$s7", "$t8", "$t9", "$k0", "$k1",
                "$gp", "$sp", "$fp", "$ra",
            ]
            for reg in regs:
                lines.append(f"  addu {reg}, {reg}, $zero")
            lines += ["  .set fp=32", "  .set oddspreg"]
            for i in range(32):
                lines.append(f"  mov.s $f{i}, $f{i}")
            lines += [
                "  cfc1 $t0, $31",
                "  mfhi $t0",
                "  mflo $t1",
                "  .set pop",
            ]
        lines += _jump(ctx.isa, ctx.successor_labels[0])
        return "\n".join(lines) + "\n"


def _decode_c_asm_string(c_text: str) -> list[str]:
    """Convert a C inline-asm literal block to plain assembly lines."""
    parts = re.findall(r'"(?:[^"\\]|\\.)*"', c_text)
    if not parts:
        return []
    decoded = ""
    for p in parts:
        decoded += bytes(p[1:-1], "utf-8").decode("unicode_escape")
    decoded = decoded.replace("%%", "%")
    return [ln.strip() for ln in decoded.splitlines() if ln.strip()]


def _register_probe(name: str, per_isa: dict[str, dict]) -> None:
    class _Probe(CodeBlock):
        pass

    _Probe.name = name
    _Probe.num_successors = 1
    _Probe.scratch_slots = 0
    _Probe.randomizable = False
    _Probe.coverage_probe = True
    _Probe.supported_isas = tuple(sorted(per_isa.keys()))

    asm_lines = {
        isa: _decode_c_asm_string(spec.get("asm", ""))
        for isa, spec in per_isa.items()
    }

    @classmethod
    def _plan(cls, ctx: EmitCtx) -> BlockPlan:
        spec = per_isa[ctx.isa]
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=list(spec.get("memops", [])),
            asserted_opcodes=list(spec.get("opcodes", [])),
            asserted_branch_types=list(spec.get("branch_types", [])),
            reg_value_assertions=list(spec.get("reg_value_assertions", [])),
            expected_reg_sets=list(spec.get("reg_sets", [])),
            asserted_dep_refines=list(spec.get("dep_refines", [])),
            # Optional per-insn EXACT check vectors (opcode + branch +
            # insn_flags + per-(dst/store/load_addr/store_addr) dep
            # masks + per-operand-slot lane masks).  See
            # `BlockPlan.expected_insns` for the field layout and the
            # `_insn()` helper for spec authoring.  Resolved against
            # the decoded trace by `_check_expected_insns`.
            expected_insns=list(spec.get("insns", [])),
        )

    @classmethod
    def _emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        lines = _prologue(ctx.block_id)
        for insn in asm_lines[ctx.isa]:
            lines.append(f"  {insn}")
        lines += _jump(ctx.isa, ctx.successor_labels[0])
        return "\n".join(lines) + "\n"

    _Probe.plan = _plan
    _Probe.emit = _emit
    _Probe.__name__ = f"Probe_{name}"
    register(_Probe)


# Inline-asm coverage probes live in `_probe_specs` as a flat data file:
# 89 single-instruction or short-sequence probes, one per uniquely-classified
# GenericOpcode / BranchType combination across the four ISAs.  Importing
# here registers them via _register_probe.  The split keeps this file as the
# active CodeBlock library and the spec file as a pure data table that can
# be regenerated mechanically when probes are added or retuned.
from . import _probe_specs as _probe_specs  # noqa: F401