"""Code block library.

A `CodeBlock` describes a chunk of C++ source that will be emitted as
the body of a labelled basic block in the generated program.

Design contract
---------------
Every block is emitted inside a single function `run()` as a
statement-expression prefixed by a globally-visible assembly label.
The label becomes an ELF symbol that the wptrace plugin records in each
template's `sym_name`.  This lets the validator map trace entries back
to generator block IDs.

A block's body may:
  * read/write the `arena` buffer (load/store with predictable offsets
    and data);
  * perform arithmetic / logic / fp ops that the compiler lowers to
    predictable `GenericOpcode` classes;
  * end in exactly one of:
      - an unconditional `goto next_label;`   (1 successor)
      - `if (pred) goto T; else goto F;`      (2 successors)
      - an exit syscall                        (0 successors, terminal).

Every read of a driver value goes through a `*(volatile uint64_t*)&arena[i]`
cast so the compiler is forbidden from constant-folding the load away.
Every driver slot is written **once** at program start (in `init_arena`)
and never again, so wrong-path stores cannot corrupt CP control flow.

Arena layout
------------

```
offset (uint64_t indices):
  [0 ... N_BRANCH_SLOTS-1]    — branch driver slots, one per branching block
  [N_BRANCH_SLOTS ... B_END]  — load/store scratch, partitioned per block
```

Per-block scratch slots are assigned by the generator and passed in via
`EmitCtx.block_slots`.

Block API
---------

Each block subclass defines:
  * `name: str`                       — registry key (also used as label)
  * `num_successors: int`             — 0, 1, or 2
  * `plan(rng, ctx) -> BlockPlan`     — compute memory accesses and
                                        expected opcode classes for this
                                        instance
  * `emit(plan, ctx) -> str`          — emit the C++ body.  The emitted
                                        code must end with the correct
                                        `goto`/syscall form.
"""

from __future__ import annotations

import dataclasses
import random
import struct
from typing import Callable, ClassVar


# ---------------------------------------------------------------------------
# Expectations — what the validator will check against each block instance
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class ExpectedMemOp:
    """A single expected load/store inside a block instance."""
    kind: str              # "load" | "store"
    arena_u64_index: int   # offset into arena[] in uint64_t units
    size: int              # bytes
    # Expected data for loads (value the CPU will see on the bus) and for
    # stores (value the CPU will write).  Match against the `data_lo`
    # field in the trace's DynParam.
    data: int


@dataclasses.dataclass
class BlockPlan:
    """Per-execution metadata for one block."""
    block_id: int
    name: str              # block class name
    # Memory operations the block is *intended* to emit, in program order.
    # The validator checks that the set of accesses matches; ordering
    # within one BB is compiler-dependent for the wptrace trace, since
    # the plugin records all BB memops together and the order within
    # one BB is the architectural memory-access order chosen by the
    # backend.  We keep order here as a hint but compare as multisets
    # unless `ordered=True`.
    memops: list[ExpectedMemOp]
    ordered_memops: bool = False
    # Coarse expected opcode-class contribution.  Used only for smoke
    # checks; the authoritative opcode ground truth comes from
    # disassembling the compiled binary.
    coarse_opcodes: dict[str, int] = dataclasses.field(default_factory=dict)
    # Successors: for 0-succ blocks empty; for 1-succ [next_id]; for
    # 2-succ [taken_id, fallthrough_id] with `branch_pred` being the
    # compile-time-known outcome (True = goto taken_id).
    successors: list[int] = dataclasses.field(default_factory=list)
    branch_pred: bool | None = None
    terminal: bool = False


@dataclasses.dataclass
class EmitCtx:
    """Context passed to a block during planning/emission."""
    block_id: int
    isa: str
    # Absolute uint64-index of the branch slot assigned to this block
    # (only valid if num_successors == 2).
    branch_slot: int | None
    # Absolute uint64-indices of the scratch slots this block may
    # read/write.  Enough slots for the block's needs, determined by
    # `scratch_slots` class attribute.
    scratch_slots: list[int]
    # Arena total size in uint64 units (for sanity checks).
    arena_u64: int
    # Label name to branch to for each successor (filled in by the
    # generator after all IDs are assigned).
    successor_labels: list[str]
    # RNG to consume when planning this block (seeded from
    # (global_seed, block_id, "plan")).
    rng: random.Random
    # If this block is branching, the branch outcome chosen by the
    # generator (True = taken_id, False = fallthrough_id).  Used to
    # plant the correct value into the branch slot at init time.
    branch_outcome: bool | None = None


# ---------------------------------------------------------------------------
# Block registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, type["CodeBlock"]] = {}


def register(cls: type["CodeBlock"]) -> type["CodeBlock"]:
    _REGISTRY[cls.name] = cls
    return cls


def get_block(name: str) -> type["CodeBlock"]:
    return _REGISTRY[name]


def all_blocks() -> list[type["CodeBlock"]]:
    return list(_REGISTRY.values())


# ---------------------------------------------------------------------------
# CodeBlock base class
# ---------------------------------------------------------------------------

class CodeBlock:
    name: ClassVar[str] = "__abstract__"
    # Number of successors: 0 = terminal, 1 = straight-line, 2 = cond branch.
    num_successors: ClassVar[int] = 1
    # How many arena scratch slots (uint64_t) this block needs.
    scratch_slots: ClassVar[int] = 0
    # Supported ISAs.  Blocks that use portable C++ list all four.
    supported_isas: ClassVar[tuple[str, ...]] = (
        "x86_64", "aarch64", "riscv64", "mipsel"
    )

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        raise NotImplementedError

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _label(block_id: int) -> str:
    return f"L_blk_{block_id}"


def _emit_label(block_id: int) -> str:
    """Emit a globally-visible label that also serves as a C goto target.

    The `.globl` directive exposes the label in the ELF symbol table so
    the wptrace plugin records it in the template's `sym_name` field.
    """
    sym = f"blk_{block_id}"
    # Landing C label MUST come before the inline asm, otherwise the
    # asm block sits between the incoming `goto L_blk_N;` and its
    # target and gets eliminated as dead code, taking our `.globl`
    # directive with it.
    return (
        f'{_label(block_id)}: (void)0;\n'
        f'asm volatile(".globl {sym}\\n\\t"\n'
        f'             "{sym}:\\n" ::: "memory");\n'
    )


def _volatile_load_u64(slot: int) -> str:
    return f"(*(volatile uint64_t*)&arena[{slot}])"


def _volatile_store_u64(slot: int, value_expr: str) -> str:
    return f"(*(volatile uint64_t*)&arena[{slot}]) = {value_expr};"


def _goto_successor(ctx: EmitCtx, idx: int) -> str:
    return f"goto {ctx.successor_labels[idx]};"


def _emit_cond_branch(ctx: EmitCtx, cond_expr: str) -> str:
    """Emit a 2-way goto using the planted branch outcome."""
    # branch_outcome was planted in arena[branch_slot] at init time.
    # The predicate here reads that slot (volatile) so GCC produces a
    # real conditional branch rather than constant-folding.
    taken = ctx.successor_labels[0]
    fall = ctx.successor_labels[1]
    return (
        f"if ({cond_expr}) {{ goto {taken}; }} "
        f"else {{ goto {fall}; }}\n"
    )


# ---------------------------------------------------------------------------
# Block: INT_ARITH — an integer-heavy straight-line block
# ---------------------------------------------------------------------------

@register
class IntArith(CodeBlock):
    name = "int_arith"
    num_successors = 1
    scratch_slots = 4

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        # Two loads from distinct scratch slots, some arithmetic, one store.
        r = ctx.rng
        s0, s1, s2, s3 = ctx.scratch_slots
        a = r.randrange(0, 1 << 48)
        b = r.randrange(0, 1 << 48)
        result = (a + b) & ((1 << 64) - 1)
        memops = [
            ExpectedMemOp("load", s0, 8, a),
            ExpectedMemOp("load", s1, 8, b),
            ExpectedMemOp("store", s2, 8, result),
        ]
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=memops,
            ordered_memops=False,
            coarse_opcodes={"INT_ADD": 1, "LOAD": 2, "STORE": 1},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0 = plan.memops[0].arena_u64_index
        s1 = plan.memops[1].arena_u64_index
        s2 = plan.memops[2].arena_u64_index
        body = (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t a = {_volatile_load_u64(s0)};\n"
            f"  uint64_t b = {_volatile_load_u64(s1)};\n"
            f"  uint64_t r = a + b;\n"
            f"  {_volatile_store_u64(s2, 'r')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )
        return body


# ---------------------------------------------------------------------------
# Block: INT_MIX — multi-op integer block (sub, mul, xor, shl)
# ---------------------------------------------------------------------------

@register
class IntMix(CodeBlock):
    name = "int_mix"
    num_successors = 1
    scratch_slots = 5

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        s0, s1, s2, s3, _s4 = ctx.scratch_slots
        a = r.randrange(0, 1 << 32)
        b = r.randrange(1, 1 << 16)
        v1 = (a - b) & ((1 << 64) - 1)
        v2 = (a * b) & ((1 << 64) - 1)
        v3 = (v1 ^ v2) & ((1 << 64) - 1)
        v4 = (v3 ^ v2) & ((1 << 64) - 1)
        memops = [
            ExpectedMemOp("load", s0, 8, a),
            ExpectedMemOp("load", s1, 8, b),
            ExpectedMemOp("store", s2, 8, v3),
            ExpectedMemOp("store", s3, 8, v4),
        ]
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=memops,
            coarse_opcodes={
                "INT_SUB": 1, "INT_MUL": 1, "XOR": 2,
                "LOAD": 2, "STORE": 2,
            },
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1, s2, s3 = (plan.memops[i].arena_u64_index for i in range(4))
        body = (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t a = {_volatile_load_u64(s0)};\n"
            f"  uint64_t b = {_volatile_load_u64(s1)};\n"
            f"  uint64_t v1 = a - b;\n"
            f"  uint64_t v2 = a * b;\n"
            f"  uint64_t v3 = v1 ^ v2;\n"
            f"  {_volatile_store_u64(s2, 'v3')}\n"
            f"  {_volatile_store_u64(s3, 'v3 ^ v2')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )
        return body


# ---------------------------------------------------------------------------
# Block: LOAD_BURST — many loads, one store
# ---------------------------------------------------------------------------

@register
class LoadBurst(CodeBlock):
    name = "load_burst"
    num_successors = 1
    scratch_slots = 8

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        slots = ctx.scratch_slots
        vals = [r.randrange(0, 1 << 48) for _ in slots[:-1]]
        acc = 0
        for v in vals:
            acc = (acc + v) & ((1 << 64) - 1)
        memops = [
            ExpectedMemOp("load", slots[i], 8, vals[i]) for i in range(len(vals))
        ]
        memops.append(ExpectedMemOp("store", slots[-1], 8, acc))
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=memops,
            coarse_opcodes={"LOAD": len(vals), "STORE": 1, "INT_ADD": len(vals)-1},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        loads = [m for m in plan.memops if m.kind == "load"]
        store = next(m for m in plan.memops if m.kind == "store")
        lines = [_emit_label(ctx.block_id), "{"]
        lines.append("  uint64_t acc = 0;")
        for i, m in enumerate(loads):
            lines.append(
                f"  acc += {_volatile_load_u64(m.arena_u64_index)};"
            )
        lines.append(f"  {_volatile_store_u64(store.arena_u64_index, 'acc')}")
        lines.append(f"  {_goto_successor(ctx, 0)}")
        lines.append("}")
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Block: STORE_BURST — many stores of distinct immediates
# ---------------------------------------------------------------------------

@register
class StoreBurst(CodeBlock):
    name = "store_burst"
    num_successors = 1
    scratch_slots = 6

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        slots = ctx.scratch_slots
        vals = [r.randrange(0, 1 << 48) | 1 for _ in slots]
        memops = [
            ExpectedMemOp("store", slots[i], 8, vals[i])
            for i in range(len(slots))
        ]
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=memops,
            ordered_memops=False,
            coarse_opcodes={"STORE": len(slots), "MOV": len(slots)},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        lines = [_emit_label(ctx.block_id), "{"]
        for m in plan.memops:
            lines.append(
                f"  (*(volatile uint64_t*)&arena[{m.arena_u64_index}]) "
                f"= 0x{m.data:016x}ULL;"
            )
        lines.append(f"  {_goto_successor(ctx, 0)}")
        lines.append("}")
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Block: COND_BRANCH — ends in a deterministic conditional branch
# ---------------------------------------------------------------------------

@register
class CondBranch(CodeBlock):
    """2-way branching block.

    Reads arena[branch_slot] (volatile, planted at init time) and compares
    it against a fixed immediate.  The outcome is chosen by the generator
    and planted such that the branch takes the edge specified by
    ``branch_outcome``.

    The plugin will simulate the *other* edge naturally for up to
    `max_wrong_path_depth` BBs — which is also a valid, reachable path
    in our CFG.
    """
    name = "cond_branch"
    num_successors = 2
    scratch_slots = 2

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        assert ctx.branch_slot is not None
        assert ctx.branch_outcome is not None
        r = ctx.rng
        s0, s1 = ctx.scratch_slots
        a = r.randrange(0, 1 << 32)
        # Load + compare gives LOAD + CMP + BRANCH in most ISAs.
        memops = [
            ExpectedMemOp("load", ctx.branch_slot, 8,
                          1 if ctx.branch_outcome else 0),
            ExpectedMemOp("load", s0, 8, a),
            ExpectedMemOp("store", s1, 8, a ^ 0xA5A5A5A5),
        ]
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=memops,
            coarse_opcodes={
                "LOAD": 2, "STORE": 1, "XOR": 1, "CMP": 1, "BRANCH": 1,
            },
            successors=[],           # filled in by generator
            branch_pred=ctx.branch_outcome,
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        assert ctx.branch_slot is not None
        s0 = plan.memops[1].arena_u64_index
        s1 = plan.memops[2].arena_u64_index
        body = (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t drv = {_volatile_load_u64(ctx.branch_slot)};\n"
            f"  uint64_t a = {_volatile_load_u64(s0)};\n"
            f"  {_volatile_store_u64(s1, 'a ^ 0xA5A5A5A5ULL')}\n"
            f"  {_emit_cond_branch(ctx, 'drv != 0')}"
            f"}}\n"
        )
        return body


# ---------------------------------------------------------------------------
# Block: FP_ARITH — double-precision floating-point workload
# ---------------------------------------------------------------------------

@register
class FpArith(CodeBlock):
    name = "fp_arith"
    num_successors = 1
    scratch_slots = 4

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        import struct
        r = ctx.rng
        s0, s1, s2, s3 = ctx.scratch_slots

        def as_u64(d: float) -> int:
            return struct.unpack("<Q", struct.pack("<d", d))[0]

        a = r.uniform(1.0, 1e6)
        b = r.uniform(1.0, 1e6)
        result = a * b + a
        memops = [
            ExpectedMemOp("load", s0, 8, as_u64(a)),
            ExpectedMemOp("load", s1, 8, as_u64(b)),
            ExpectedMemOp("store", s2, 8, as_u64(result)),
        ]
        return BlockPlan(
            block_id=ctx.block_id,
            name=cls.name,
            memops=memops,
            coarse_opcodes={"FP_MUL": 1, "FP_ADD": 1, "LOAD": 2, "STORE": 1},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0 = plan.memops[0].arena_u64_index
        s1 = plan.memops[1].arena_u64_index
        s2 = plan.memops[2].arena_u64_index
        body = (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  double a, b, r;\n"
            f"  uint64_t ua = {_volatile_load_u64(s0)};\n"
            f"  uint64_t ub = {_volatile_load_u64(s1)};\n"
            f"  __builtin_memcpy(&a, &ua, sizeof(a));\n"
            f"  __builtin_memcpy(&b, &ub, sizeof(b));\n"
            f"  r = a * b + a;\n"
            f"  uint64_t ur;\n"
            f"  __builtin_memcpy(&ur, &r, sizeof(ur));\n"
            f"  {_volatile_store_u64(s2, 'ur')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )
        return body


# ---------------------------------------------------------------------------
# Block: EXIT — terminal block, performs a direct exit(0) syscall
# ---------------------------------------------------------------------------

@register
class ExitBlock(CodeBlock):
    name = "exit"
    num_successors = 0
    scratch_slots = 0

    # Per-ISA exit-syscall thunks.  We emit raw inline asm because the
    # generated binary is `-nostdlib`.
    _EXIT_ASM = {
        "x86_64": (
            '"mov $60, %%rax\\n"\n'
            '"xor %%rdi, %%rdi\\n"\n'
            '"syscall\\n"\n'
            ':: : "rax","rdi","memory"'
        ),
        "aarch64": (
            '"mov x8, #93\\n"\n'
            '"mov x0, #0\\n"\n'
            '"svc #0\\n"\n'
            ':: : "x0","x8","memory"'
        ),
        "riscv64": (
            '"li a7, 93\\n"\n'
            '"li a0, 0\\n"\n'
            '"ecall\\n"\n'
            ':: : "a0","a7","memory"'
        ),
        "mipsel": (
            '"li $v0, 4001\\n"\n'  # Linux mipsel __NR_exit
            '"li $a0, 0\\n"\n'
            '"syscall\\n"\n'
            ':: : "$v0","$a0","memory"'
        ),
    }

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
        asm = cls._EXIT_ASM[ctx.isa]
        body = (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  asm volatile(\n"
            f"  {asm});\n"
            f"  __builtin_unreachable();\n"
            f"}}\n"
        )
        return body


# ---------------------------------------------------------------------------
# Expanded block library
#
# Each block below follows the same contract:
#
#   * `plan()` computes the exact sequence of memory operations the
#     block will perform, including the *data* value observed on
#     every load/store.  The validator uses this (via the analyzer's
#     `ground_truth` PC spans and the trace's `dyn_params`) to check
#     both addresses and values.
#
#   * `emit()` produces C++ that, when compiled, performs exactly the
#     same sequence of loads/stores with the same data values.  The
#     Python-side computation in `plan()` IS the oracle: any
#     divergence between Python arithmetic and compiled code will
#     surface in `cp_memops`.
#
# All blocks assume 64-bit load/store granularity so the stored values
# are trivially comparable to `DynParam.data_lo`.
# ---------------------------------------------------------------------------


def _u64(x: int) -> int:
    return x & ((1 << 64) - 1)


def _s64(x: int) -> int:
    x &= (1 << 64) - 1
    return x - (1 << 64) if x >= (1 << 63) else x


# ---------------------------------------------------------------------------
# Block: INT_SUB_MUL — integer subtract + multiply chain
# ---------------------------------------------------------------------------

@register
class IntSubMul(CodeBlock):
    name = "int_sub_mul"
    num_successors = 1
    scratch_slots = 3

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        s0, s1, s2 = ctx.scratch_slots
        a = r.randrange(1 << 20, 1 << 32)
        b = r.randrange(1, 1 << 16)
        r_val = _u64((a - b) * b)
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, a),
                ExpectedMemOp("load", s1, 8, b),
                ExpectedMemOp("store", s2, 8, r_val),
            ],
            coarse_opcodes={"INT_SUB": 1, "INT_MUL": 1,
                            "LOAD": 2, "STORE": 1},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1, s2 = (m.arena_u64_index for m in plan.memops)
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t a = {_volatile_load_u64(s0)};\n"
            f"  uint64_t b = {_volatile_load_u64(s1)};\n"
            f"  uint64_t r = (a - b) * b;\n"
            f"  {_volatile_store_u64(s2, 'r')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )


# ---------------------------------------------------------------------------
# Block: INT_DIV_MOD — integer divide + remainder
# ---------------------------------------------------------------------------

@register
class IntDivMod(CodeBlock):
    name = "int_div_mod"
    num_successors = 1
    scratch_slots = 4

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        s0, s1, s2, s3 = ctx.scratch_slots
        a = r.randrange(1 << 32, 1 << 48)
        b = r.randrange(3, 1 << 20)
        q = a // b
        m = a % b
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, a),
                ExpectedMemOp("load", s1, 8, b),
                ExpectedMemOp("store", s2, 8, q),
                ExpectedMemOp("store", s3, 8, m),
            ],
            coarse_opcodes={"INT_DIV": 1, "LOAD": 2, "STORE": 2},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1, s2, s3 = (m.arena_u64_index for m in plan.memops)
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t a = {_volatile_load_u64(s0)};\n"
            f"  uint64_t b = {_volatile_load_u64(s1)};\n"
            f"  uint64_t q = a / b;\n"
            f"  uint64_t m = a % b;\n"
            f"  {_volatile_store_u64(s2, 'q')}\n"
            f"  {_volatile_store_u64(s3, 'm')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )


# ---------------------------------------------------------------------------
# Block: LOGIC — bitwise AND/OR/XOR/NOT chain
# ---------------------------------------------------------------------------

@register
class LogicChain(CodeBlock):
    name = "logic_chain"
    num_successors = 1
    scratch_slots = 5

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        s0, s1, s2, s3, s4 = ctx.scratch_slots
        a = r.randrange(0, 1 << 48)
        b = r.randrange(0, 1 << 48)
        v_and = a & b
        v_or = a | b
        v_xor = a ^ b
        v_not = _u64(~(a & b))
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, a),
                ExpectedMemOp("load", s1, 8, b),
                ExpectedMemOp("store", s2, 8, v_and),
                ExpectedMemOp("store", s3, 8, v_or ^ v_xor),
                ExpectedMemOp("store", s4, 8, v_not),
            ],
            coarse_opcodes={"AND": 2, "OR": 1, "XOR": 2, "NOT": 1,
                            "LOAD": 2, "STORE": 3},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1, s2, s3, s4 = (m.arena_u64_index for m in plan.memops)
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t a = {_volatile_load_u64(s0)};\n"
            f"  uint64_t b = {_volatile_load_u64(s1)};\n"
            f"  uint64_t a_and_b = a & b;\n"
            f"  uint64_t a_or_b  = a | b;\n"
            f"  uint64_t a_xor_b = a ^ b;\n"
            f"  uint64_t inv = ~a_and_b;\n"
            f"  {_volatile_store_u64(s2, 'a_and_b')}\n"
            f"  {_volatile_store_u64(s3, 'a_or_b ^ a_xor_b')}\n"
            f"  {_volatile_store_u64(s4, 'inv')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )


# ---------------------------------------------------------------------------
# Block: SHIFT_ROTATE — SHL/SHR/SAR and synthesised rotate
# ---------------------------------------------------------------------------

@register
class ShiftRotate(CodeBlock):
    name = "shift_rotate"
    num_successors = 1
    scratch_slots = 4

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        s0, s1, s2, s3 = ctx.scratch_slots
        a = r.randrange(1 << 32, 1 << 63)
        sh = r.randrange(1, 32)
        v_shl = _u64(a << sh)
        v_shr = a >> sh
        v_sar = _u64(_s64(a) >> sh)
        v_rot = _u64((a << sh) | (a >> (64 - sh)))
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, a),
                ExpectedMemOp("store", s1, 8, v_shl ^ v_shr),
                ExpectedMemOp("store", s2, 8, v_sar),
                ExpectedMemOp("store", s3, 8, v_rot),
            ],
            coarse_opcodes={"SHL": 2, "SHR": 1, "SAR": 1, "OR": 1,
                            "XOR": 1, "LOAD": 1, "STORE": 3},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1, s2, s3 = (m.arena_u64_index for m in plan.memops)
        # Recover shift amount by inverting plan's computation.  We
        # instead store it inline from the RNG path via seed-state
        # determinism: we re-seed a twin RNG with the same key used
        # in plan().  Simpler: compute shift from (load/store) deltas.
        # Here we emit the shift as a literal by re-deriving from the
        # plan's deterministic sub-seed.  But `plan` already chose sh,
        # so we reconstruct by running the same random sequence.
        r = random.Random(ctx.rng.getstate() if False else 0)
        # Fallback: derive sh from plan's stored values.
        a = plan.memops[0].data
        v_rot = plan.memops[3].data
        # Brute-force find shift that matches v_rot; 1..63
        sh = next(
            k for k in range(1, 64)
            if _u64((a << k) | (a >> (64 - k))) == v_rot
        )
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t a = {_volatile_load_u64(s0)};\n"
            f"  uint64_t v_shl = a << {sh};\n"
            f"  uint64_t v_shr = a >> {sh};\n"
            f"  int64_t  sa    = (int64_t)a;\n"
            f"  uint64_t v_sar = (uint64_t)(sa >> {sh});\n"
            f"  uint64_t v_rot = (a << {sh}) | (a >> (64 - {sh}));\n"
            f"  {_volatile_store_u64(s1, 'v_shl ^ v_shr')}\n"
            f"  {_volatile_store_u64(s2, 'v_sar')}\n"
            f"  {_volatile_store_u64(s3, 'v_rot')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )


# ---------------------------------------------------------------------------
# Block: COMPARE_SELECT — CMP + CMOV/SETCC
# ---------------------------------------------------------------------------

@register
class CompareSelect(CodeBlock):
    name = "compare_select"
    num_successors = 1
    scratch_slots = 4

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        s0, s1, s2, s3 = ctx.scratch_slots
        a = r.randrange(0, 1 << 48)
        b = r.randrange(0, 1 << 48)
        v_max = max(a, b)
        v_eq = 1 if a == b else 0
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, a),
                ExpectedMemOp("load", s1, 8, b),
                ExpectedMemOp("store", s2, 8, v_max),
                ExpectedMemOp("store", s3, 8, v_eq),
            ],
            coarse_opcodes={"CMP": 2, "CMOV": 1, "SETCC": 1,
                            "LOAD": 2, "STORE": 2},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1, s2, s3 = (m.arena_u64_index for m in plan.memops)
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t a = {_volatile_load_u64(s0)};\n"
            f"  uint64_t b = {_volatile_load_u64(s1)};\n"
            f"  uint64_t mx = (a > b) ? a : b;\n"
            f"  uint64_t eq = (a == b) ? 1 : 0;\n"
            f"  {_volatile_store_u64(s2, 'mx')}\n"
            f"  {_volatile_store_u64(s3, 'eq')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )


# ---------------------------------------------------------------------------
# Block: NEG_INCDEC — NEG, INC, DEC
# ---------------------------------------------------------------------------

@register
class NegIncDec(CodeBlock):
    name = "neg_inc_dec"
    num_successors = 1
    scratch_slots = 4

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        s0, s1, s2, s3 = ctx.scratch_slots
        a = r.randrange(1, 1 << 40)
        v_neg = _u64(-a)
        v_inc = _u64(a + 1)
        v_dec = _u64(a - 1)
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, a),
                ExpectedMemOp("store", s1, 8, v_neg),
                ExpectedMemOp("store", s2, 8, v_inc),
                ExpectedMemOp("store", s3, 8, v_dec),
            ],
            coarse_opcodes={"NEG": 1, "INC": 1, "DEC": 1,
                            "LOAD": 1, "STORE": 3},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1, s2, s3 = (m.arena_u64_index for m in plan.memops)
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t a = {_volatile_load_u64(s0)};\n"
            f"  uint64_t n = (uint64_t)(-(int64_t)a);\n"
            f"  uint64_t up = a + 1;\n"
            f"  uint64_t dn = a - 1;\n"
            f"  {_volatile_store_u64(s1, 'n')}\n"
            f"  {_volatile_store_u64(s2, 'up')}\n"
            f"  {_volatile_store_u64(s3, 'dn')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )


# ---------------------------------------------------------------------------
# Block: MOV_EXTEND — zero-extend / sign-extend sequences (MOVZX / MOVSX)
# ---------------------------------------------------------------------------

@register
class MovExtend(CodeBlock):
    name = "mov_extend"
    num_successors = 1
    scratch_slots = 4

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        s0, s1, s2, s3 = ctx.scratch_slots
        # Set high bit of the low byte to exercise sign-extend difference.
        a = r.randrange(0x80, 0x100) | (r.randrange(0, 1 << 40) << 8)
        lo8 = a & 0xff
        v_zx = lo8
        v_sx = _u64(lo8 - 0x100) if lo8 & 0x80 else lo8
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, a),
                ExpectedMemOp("store", s1, 8, v_zx),
                ExpectedMemOp("store", s2, 8, v_sx),
                ExpectedMemOp("store", s3, 8, a),
            ],
            coarse_opcodes={"MOVZX": 1, "MOVSX": 1, "MOV": 1,
                            "LOAD": 1, "STORE": 3},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1, s2, s3 = (m.arena_u64_index for m in plan.memops)
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t a = {_volatile_load_u64(s0)};\n"
            f"  uint8_t  b = (uint8_t)a;\n"
            f"  int8_t   sb = (int8_t)b;\n"
            f"  uint64_t zx = (uint64_t)b;\n"
            f"  uint64_t sx = (uint64_t)(int64_t)sb;\n"
            f"  {_volatile_store_u64(s1, 'zx')}\n"
            f"  {_volatile_store_u64(s2, 'sx')}\n"
            f"  {_volatile_store_u64(s3, 'a')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )


# ---------------------------------------------------------------------------
# Block: FP_DIV_SQRT — floating-point DIV + SQRT
# ---------------------------------------------------------------------------

@register
class FpDivSqrt(CodeBlock):
    name = "fp_div_sqrt"
    num_successors = 1
    scratch_slots = 4

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        s0, s1, s2, s3 = ctx.scratch_slots

        def as_u64(d: float) -> int:
            return struct.unpack("<Q", struct.pack("<d", d))[0]

        a = r.uniform(100.0, 1e8)
        b = r.uniform(1.0, 1e3)
        q = a / b
        # Use a * a instead of sqrt(a) to avoid libm dependency under
        # -nostdlib.  "fp mul+div" still exercises FP_MUL + FP_DIV.
        sq = a * a
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, as_u64(a)),
                ExpectedMemOp("load", s1, 8, as_u64(b)),
                ExpectedMemOp("store", s2, 8, as_u64(q)),
                ExpectedMemOp("store", s3, 8, as_u64(sq)),
            ],
            coarse_opcodes={"FP_DIV": 1, "FP_MUL": 1,
                            "LOAD": 2, "STORE": 2},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1, s2, s3 = (m.arena_u64_index for m in plan.memops)
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  double a, b, q, sq;\n"
            f"  uint64_t ua = {_volatile_load_u64(s0)};\n"
            f"  uint64_t ub = {_volatile_load_u64(s1)};\n"
            f"  __builtin_memcpy(&a, &ua, sizeof(a));\n"
            f"  __builtin_memcpy(&b, &ub, sizeof(b));\n"
            f"  q  = a / b;\n"
            f"  sq = a * a;\n"
            f"  uint64_t uq, usq;\n"
            f"  __builtin_memcpy(&uq,  &q,  sizeof(uq));\n"
            f"  __builtin_memcpy(&usq, &sq, sizeof(usq));\n"
            f"  {_volatile_store_u64(s2, 'uq')}\n"
            f"  {_volatile_store_u64(s3, 'usq')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )


# ---------------------------------------------------------------------------
# Block: FP_CONVERT — double<->int round-trip (FP_CVT)
# ---------------------------------------------------------------------------

@register
class FpConvert(CodeBlock):
    name = "fp_convert"
    num_successors = 1
    scratch_slots = 3

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        s0, s1, s2 = ctx.scratch_slots

        def as_u64(d: float) -> int:
            return struct.unpack("<Q", struct.pack("<d", d))[0]

        i = r.randrange(1, 1 << 40)
        d = float(i) + 0.5
        back = int(d)
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, i),
                ExpectedMemOp("store", s1, 8, as_u64(d)),
                ExpectedMemOp("store", s2, 8, back),
            ],
            coarse_opcodes={"FP_CVT": 2, "FP_ADD": 1,
                            "LOAD": 1, "STORE": 2},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1, s2 = (m.arena_u64_index for m in plan.memops)
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t ui = {_volatile_load_u64(s0)};\n"
            f"  int64_t  si = (int64_t)ui;\n"
            f"  double d = (double)si + 0.5;\n"
            f"  uint64_t back = (uint64_t)(int64_t)d;\n"
            f"  uint64_t ud;\n"
            f"  __builtin_memcpy(&ud, &d, sizeof(ud));\n"
            f"  {_volatile_store_u64(s1, 'ud')}\n"
            f"  {_volatile_store_u64(s2, 'back')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )


# ---------------------------------------------------------------------------
# Block: MEMCOPY — chain of loads fanning into stores (LEA-friendly)
# ---------------------------------------------------------------------------

@register
class MemCopy(CodeBlock):
    name = "memcopy"
    num_successors = 1
    scratch_slots = 6

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        slots = ctx.scratch_slots
        n = len(slots) // 2
        src = slots[:n]
        dst = slots[n:]
        vals = [r.randrange(0, 1 << 48) | 1 for _ in range(n)]
        memops: list[ExpectedMemOp] = []
        for i in range(n):
            memops.append(ExpectedMemOp("load", src[i], 8, vals[i]))
        for i in range(n):
            memops.append(ExpectedMemOp("store", dst[i], 8, vals[i]))
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=memops,
            coarse_opcodes={"LOAD": n, "STORE": n, "MOV": n},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        n = len(plan.memops) // 2
        lines = [_emit_label(ctx.block_id), "{"]
        for i in range(n):
            src_slot = plan.memops[i].arena_u64_index
            lines.append(
                f"  uint64_t t{i} = {_volatile_load_u64(src_slot)};"
            )
        for i in range(n):
            dst_slot = plan.memops[n + i].arena_u64_index
            lines.append(f"  {_volatile_store_u64(dst_slot, f't{i}')}")
        lines.append(f"  {_goto_successor(ctx, 0)}")
        lines.append("}")
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Block: RUNNING_HASH — polynomial accumulator (MUL + ADD + XOR + ROL-ish)
# ---------------------------------------------------------------------------

@register
class RunningHash(CodeBlock):
    name = "running_hash"
    num_successors = 1
    scratch_slots = 6

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        slots = ctx.scratch_slots
        loads = [r.randrange(1, 1 << 40) for _ in slots[:-1]]
        h = 0x9E3779B97F4A7C15
        for v in loads:
            h = _u64(h ^ v)
            h = _u64(h * 0xBF58476D1CE4E5B9)
            h = _u64((h << 13) | (h >> 51))
            h = _u64(h + v)
        memops = [
            ExpectedMemOp("load", slots[i], 8, loads[i])
            for i in range(len(loads))
        ]
        memops.append(ExpectedMemOp("store", slots[-1], 8, h))
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=memops,
            coarse_opcodes={
                "LOAD": len(loads), "STORE": 1,
                "XOR": len(loads), "INT_MUL": len(loads),
                "SHL": len(loads), "SHR": len(loads),
                "OR": len(loads), "INT_ADD": len(loads),
            },
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        loads = [m for m in plan.memops if m.kind == "load"]
        store = next(m for m in plan.memops if m.kind == "store")
        lines = [_emit_label(ctx.block_id), "{"]
        lines.append("  uint64_t h = 0x9E3779B97F4A7C15ULL;")
        for m in loads:
            lines.append(
                f"  {{ uint64_t v = {_volatile_load_u64(m.arena_u64_index)};"
                f" h ^= v; h *= 0xBF58476D1CE4E5B9ULL;"
                f" h = (h << 13) | (h >> 51); h += v; }}"
            )
        lines.append(f"  {_volatile_store_u64(store.arena_u64_index, 'h')}")
        lines.append(f"  {_goto_successor(ctx, 0)}")
        lines.append("}")
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Block: MIXED_WIDTH — interleaved 8/16/32/64-bit accesses
#
# Most ISAs lower these to distinct load/store opcodes (e.g. x86 MOV vs
# MOVZX/MOVSX).  We normalise by storing the final assembled value as
# u64 so validator comparison works uniformly.
# ---------------------------------------------------------------------------

@register
class MixedWidth(CodeBlock):
    name = "mixed_width"
    num_successors = 1
    scratch_slots = 5

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        s0, s1, s2, s3, s4 = ctx.scratch_slots
        a = r.randrange(0, 1 << 56) | (1 << 7)
        b = a ^ 0x00FF00FF
        c = _u64(a + b)
        d = a & 0xFFFFFFFF
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, a),
                ExpectedMemOp("load", s1, 8, b),
                ExpectedMemOp("store", s2, 8, c),
                ExpectedMemOp("store", s3, 8, d),
                ExpectedMemOp("store", s4, 8, a ^ b),
            ],
            coarse_opcodes={"LOAD": 2, "STORE": 3,
                            "INT_ADD": 1, "XOR": 1, "AND": 1},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0, s1, s2, s3, s4 = (m.arena_u64_index for m in plan.memops)
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t a = {_volatile_load_u64(s0)};\n"
            f"  uint64_t b = {_volatile_load_u64(s1)};\n"
            f"  uint64_t c = a + b;\n"
            f"  uint64_t d = a & 0xFFFFFFFFULL;\n"
            f"  uint64_t x = a ^ b;\n"
            f"  {_volatile_store_u64(s2, 'c')}\n"
            f"  {_volatile_store_u64(s3, 'd')}\n"
            f"  {_volatile_store_u64(s4, 'x')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )


# ---------------------------------------------------------------------------
# Block: NOP_SLED — NOPs mixed with a single load/store (tests the
# plugin's handling of long instruction runs that don't touch memory).
# ---------------------------------------------------------------------------

@register
class NopSled(CodeBlock):
    name = "nop_sled"
    num_successors = 1
    scratch_slots = 2

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        r = ctx.rng
        s0, s1 = ctx.scratch_slots
        a = r.randrange(1, 1 << 40)
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, a),
                ExpectedMemOp("store", s1, 8, _u64(a + 1)),
            ],
            coarse_opcodes={"NOP": 16, "LOAD": 1, "STORE": 1, "INT_ADD": 1},
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0 = plan.memops[0].arena_u64_index
        s1 = plan.memops[1].arena_u64_index
        nop_insn = {
            "x86_64":  '"nop\\n"',
            "aarch64": '"nop\\n"',
            "riscv64": '"nop\\n"',
            "mipsel":  '"nop\\n"',
        }[ctx.isa]
        nops = "\n".join(f"  asm volatile({nop_insn});" for _ in range(16))
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t a = {_volatile_load_u64(s0)};\n"
            f"{nops}\n"
            f"  uint64_t r = a + 1;\n"
            f"  {_volatile_store_u64(s1, 'r')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )
