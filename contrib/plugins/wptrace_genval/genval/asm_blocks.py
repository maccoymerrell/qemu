"""Assembly-only code block library for champsim_tracer_genval.

Each generated block maps to one machine-level basic block. Straight-line
blocks end in an unconditional branch, and 2-way blocks end in one
conditional branch whose fallthrough path is the other successor.
"""

from __future__ import annotations

import dataclasses
import random
from typing import ClassVar


@dataclasses.dataclass
class ExpectedMemOp:
    kind: str
    arena_u64_index: int
    size: int
    data: int


@dataclasses.dataclass
class BlockPlan:
    block_id: int
    name: str
    memops: list[ExpectedMemOp]
    ordered_memops: bool = False
    coarse_opcodes: dict[str, int] = dataclasses.field(default_factory=dict)
    successors: list[int] = dataclasses.field(default_factory=list)
    branch_pred: bool | None = None
    terminal: bool = False
    asserted_branch_types: list[str] = dataclasses.field(default_factory=list)
    asserted_opcodes: list[str] = dataclasses.field(default_factory=list)
    asserted_cond_uncond_branch: bool = False


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
        return [f"  b {entry_symbol}", "  nop"]
    raise ValueError(f"unsupported ISA: {isa}")


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


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


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
        return [f"  b {target}", "  nop"]
    raise ValueError(f"unsupported ISA: {isa}")


def _load_base(isa: str) -> list[str]:
    if isa == "x86_64":
        return ["  leaq arena(%rip), %r15"]
    if isa == "aarch64":
        return ["  adrp x20, arena", "  add x20, x20, :lo12:arena"]
    if isa == "riscv64":
        return ["  la t6, arena"]
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
        return [f"  li t5, {off}", "  add t5, t6, t5", f"  ld {reg}, 0(t5)"]
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
        return [f"  li t5, {off}", "  add t5, t6, t5", f"  sd {reg}, 0(t5)"]
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
            lines += ["  add x9, x9, x10"]
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
        counter = max(1, int(ctx.loop_iterations))
        slot = ctx.scratch_slots[0]
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=[
                ExpectedMemOp("load", slot, 8, counter),
                ExpectedMemOp("store", slot, 8, counter - 1),
            ],
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
            lines += ["  snez t1, t0", "  sub t0, t0, t1"]
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
            lines += ["  eor x9, x9, #0x33"]
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