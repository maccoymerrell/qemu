"""Code block library.

A `CodeBlock` describes a chunk of C++ source that will be emitted as
the body of a labelled basic block in the generated program.

Design contract
---------------
Every block is emitted inside a single function `run()` as a
statement-expression prefixed by a globally-visible assembly label.
The label becomes an ELF symbol that the champsim_tracer plugin records in each
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
    # within one BB is compiler-dependent for the champsim_tracer trace, since
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
    # Asserted branch-type classifications we expect to observe somewhere
    # in the disassembled instructions for this block instance.  Each
    # entry is a BranchType name (e.g. "BRANCH_DIRECT_JUMP").  Used by
    # the validator to verify coverage of uncommon branch kinds.
    asserted_branch_types: list[str] = dataclasses.field(default_factory=list)
    # Asserted generic-opcode classifications: same idea, but for
    # GenericOpcode names ("INT_MUL", "SYSCALL", ...).
    asserted_opcodes: list[str] = dataclasses.field(default_factory=list)
    # Optional: if set, assert the block contains at least one
    # instruction whose classified branch_type is "DIRECT_JUMP" *and*
    # whose branch_conditional bit is set.  This exists specifically
    # to validate the x86 conditional-unconditional encoding family
    # (LOOP / LOOPE / LOOPNE / JCXZ / JECXZ / JRCXZ).
    asserted_cond_uncond_branch: bool = False


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
    the champsim_tracer plugin records it in the template's `sym_name` field.
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
# Block: HOT_LOOP — counted register-only loop that re-executes its body
# many times.  Used to drive long-running traces ("trace a large program
# in its entirety") from a small CFG.
#
# Layout produced by the C++ compiler at -O1:
#
#     <prologue>            ; load n  (s0)  and acc  (s1)
#     <loop body>:          ; pure-register multiply-add, no memops
#         acc = acc * M + A
#         n  -= 1
#         bnez n, <loop body>
#     <epilogue>            ; store acc (s2)
#
# The plugin observes (typically) one TB for the loop body that
# re-executes `iters` times — a single template with `iters` runtime
# entries.  All loads/stores live outside the loop body so the validator
# `cp_memops` multiset (1 load(n) + 1 load(seed) + 1 store(acc))
# matches independently of how many iterations the loop ran.
#
# The iteration count is read from arena[s0] (planted at init), not a
# compile-time constant, which prevents the compiler from unrolling or
# constant-folding the loop.  An additional `asm volatile` clobber on
# `acc` inside the loop body forbids vectorization / loop-invariant
# motion.
# ---------------------------------------------------------------------------

@register
class HotLoop(CodeBlock):
    name = "hot_loop"
    num_successors = 1
    scratch_slots = 4

    # Iteration count.  Set by the generator (via the CLI's --hot-iters
    # flag) before planning so plan() can compute the deterministic
    # final accumulator value.  Default is conservative so accidental
    # inclusion in a small trace doesn't blow past --stop.
    iters: ClassVar[int] = 64

    # Loop-body constants.  Chosen so the recurrence is bijective and
    # produces a non-trivial value spectrum across iterations.
    _MULT: ClassVar[int] = 0x100000001B3        # FNV-1a 64-bit prime
    _ADD:  ClassVar[int] = 0x9E3779B97F4A7C15   # 2^64 / phi

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        s0, s1, s2, _s3 = ctx.scratch_slots
        n = int(cls.iters)
        if n <= 0:
            n = 1
        seed = ctx.rng.randrange(1, 1 << 48) | 1
        # Closed-form for the linear recurrence acc_{i+1} = M*acc_i + A
        # (mod 2^64). Computes (M^n, sum_{i<n} M^i) by fast doubling in
        # O(log n) instead of O(n) — necessary at hot_iters in the
        # tens of millions.
        MASK = (1 << 64) - 1
        M = cls._MULT
        A = cls._ADD
        def power_and_sum(k: int) -> tuple[int, int]:
            if k == 0:
                return (1, 0)
            if k == 1:
                return (M & MASK, 1)
            half, rem = divmod(k, 2)
            ph, sh = power_and_sum(half)
            p_full = (ph * ph) & MASK
            s_full = (sh * (1 + ph)) & MASK
            if rem:
                p_full = (p_full * M) & MASK
                s_full = (1 + M * s_full) & MASK
            return (p_full, s_full)
        Mn, Sn = power_and_sum(n)
        acc = ((Mn * seed) + (A * Sn)) & MASK
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[
                ExpectedMemOp("load", s0, 8, n),
                ExpectedMemOp("load", s1, 8, seed),
                ExpectedMemOp("store", s2, 8, acc),
            ],
            coarse_opcodes={
                "LOAD": 1, "STORE": 1,
                "INT_MUL": 1, "INT_ADD": 1, "INT_SUB": 1,
                "BRANCH": 1,
            },
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0 = plan.memops[0].arena_u64_index   # iteration count
        s1 = plan.memops[1].arena_u64_index   # accumulator seed
        s2 = plan.memops[2].arena_u64_index   # final accumulator
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t n   = {_volatile_load_u64(s0)};\n"
            f"  uint64_t acc = {_volatile_load_u64(s1)};\n"
            f"  do {{\n"
            f"    acc = acc * 0x{cls._MULT:X}ULL + 0x{cls._ADD:X}ULL;\n"
            f"    asm volatile(\"\" : \"+r\"(acc) : : \"memory\");\n"
            f"    n -= 1;\n"
            f"  }} while (n != 0);\n"
            f"  {_volatile_store_u64(s2, 'acc')}\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )


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


# ===========================================================================
# Declarative block factory
#
# Most blocks boil down to: (a) issue N volatile loads from arena slots,
# (b) compute some outputs in both Python and C++, (c) issue M volatile
# stores back to arena.  The `simple_compute_block` factory collapses that
# entire pattern to a single specification:
#
#   @simple_compute_block(
#       name="int_sub_add",
#       scratch=3,
#       coarse={"INT_SUB": 1, "INT_ADD": 1, "LOAD": 2, "STORE": 1},
#   )
#   def _int_sub_add(rng, slots):
#       s0, s1, s2 = slots
#       a = rng.randrange(0, 1 << 40)
#       b = rng.randrange(1, 1 << 20)
#       r = _u64(a - b + 1)
#       loads  = [(s0, a), (s1, b)]
#       stores = [(s2, r, "a - b + 1")]
#       body = (
#           f"  uint64_t a = {_volatile_load_u64(s0)};\n"
#           f"  uint64_t b = {_volatile_load_u64(s1)};\n"
#       )
#       return loads, stores, body
#
# The factory registers a real `CodeBlock` subclass under the given name
# and wires plan()/emit() automatically.  Adding a new coverage block is
# a single decorated function.
# ===========================================================================

def simple_compute_block(
    *,
    name: str,
    scratch: int,
    coarse: dict[str, int] | None = None,
    supported_isas: tuple[str, ...] = (
        "x86_64", "aarch64", "riscv64", "mipsel"
    ),
    asserted_opcodes: list[str] | None = None,
    asserted_opcodes_per_isa: dict[str, list[str]] | None = None,
    asserted_branch_types: list[str] | None = None,
    asserted_cond_uncond_branch: bool = False,
):
    """Decorator turning a `build(rng, slots)` callable into a `CodeBlock`.

    `build` must return `(loads, stores, body_lines)` where:

      * `loads`  = list of `(slot, python_value)` — emitted as an
                   `ExpectedMemOp("load", ...)` and turned into a
                   `uint64_t NAME = *volatile(&arena[slot]);` line.
      * `stores` = list of `(slot, python_value, cpp_value_expr)` —
                   an `ExpectedMemOp("store", ...)` plus a line
                   storing `cpp_value_expr` to the slot.
      * `body_lines` = free-form C++ to splice between loads and stores.
                       Should reference load-named variables as `a`,
                       `b`, `c`, ... (positional).  You typically
                       perform the computation here.

    The factory emits the load variables as `a`, `b`, `c` ... (so
    `body_lines` may reference them) and writes stores at the end.
    """
    coarse_d = dict(coarse or {})
    branch_asserts = list(asserted_branch_types or [])
    opcode_asserts = list(asserted_opcodes or [])
    opcode_asserts_per_isa = dict(asserted_opcodes_per_isa or {})

    def deco(build_fn):
        class _Simple(CodeBlock):
            pass

        _Simple.name = name
        _Simple.num_successors = 1
        _Simple.scratch_slots = scratch
        _Simple.supported_isas = supported_isas

        @classmethod  # type: ignore[misc]
        def _plan(cls, ctx: EmitCtx) -> BlockPlan:
            loads, stores, _body = build_fn(ctx.rng, list(ctx.scratch_slots))
            memops: list[ExpectedMemOp] = []
            for slot, val in loads:
                memops.append(ExpectedMemOp("load", slot, 8, _u64(val)))
            for slot, val, _expr in stores:
                memops.append(ExpectedMemOp("store", slot, 8, _u64(val)))
            return BlockPlan(
                block_id=ctx.block_id, name=cls.name,
                memops=memops,
                coarse_opcodes=coarse_d,
                asserted_branch_types=list(branch_asserts),
                asserted_opcodes=list(
                    opcode_asserts_per_isa.get(ctx.isa, opcode_asserts)
                ),
                asserted_cond_uncond_branch=asserted_cond_uncond_branch,
            )

        @classmethod  # type: ignore[misc]
        def _emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
            # Reconstruct a matching build() invocation with the same RNG
            # sequence: EmitCtx at emit-time uses a fresh Random(0), so we
            # cannot re-invoke build_fn deterministically.  Instead we
            # reconstruct (loads, stores, body) from the stored plan by
            # deriving a trivial build invocation at emit time as well.
            # The plan already contains slots + values — emit directly.
            loads = [(m.arena_u64_index, m.data)
                     for m in plan.memops if m.kind == "load"]
            stores = [(m.arena_u64_index, m.data)
                      for m in plan.memops if m.kind == "store"]

            # Re-invoke build_fn with a disposable RNG just to get the
            # body_lines text (the load/store slots are already pinned
            # in the plan, so any discrepancy inside build_fn is
            # harmless).  We feed it the *actual* slots so the variable
            # references in body match up.
            _dummy_rng = random.Random(0)
            _lo, _st, body_lines = build_fn(_dummy_rng, list(ctx.scratch_slots))

            load_lines = []
            for i, (slot, _val) in enumerate(loads):
                var = chr(ord('a') + i)
                load_lines.append(
                    f"  uint64_t {var} = {_volatile_load_u64(slot)};"
                )
            store_lines = []
            for i, (slot, _val) in enumerate(stores):
                # Match the build_fn's declared store expression.
                # build_fn's `stores` uses `(slot, value, cpp_expr)` —
                # we re-fetch cpp_expr from the invocation above.
                cpp_expr = _st[i][2]
                store_lines.append(
                    f"  {_volatile_store_u64(slot, cpp_expr)}"
                )
            return (
                f"{_emit_label(ctx.block_id)}"
                f"{{\n"
                + "\n".join(load_lines)
                + ("\n" if load_lines else "")
                + body_lines
                + ("\n" if body_lines and not body_lines.endswith("\n") else "")
                + "\n".join(store_lines)
                + "\n"
                + f"  {_goto_successor(ctx, 0)}\n"
                + f"}}\n"
            )

        _Simple.plan = _plan
        _Simple.emit = _emit
        _Simple.__name__ = f"Simple_{name}"
        register(_Simple)
        return _Simple
    return deco


# ---------------------------------------------------------------------------
# Example uses of the factory.  Each one is a few lines and contributes
# a new GenericOpcode/BranchType the validator will see and classify.
# ---------------------------------------------------------------------------

@simple_compute_block(
    name="int_adc_sbb",
    scratch=4,
    coarse={"INT_ADC": 1, "INT_SBB": 1, "LOAD": 2, "STORE": 2},
    # `a + b + 1` is commonly folded into LEA on x86, so we only assert
    # the subtract side which stays INT_SUB across supported ISAs.
    asserted_opcodes=["INT_SUB"],
)
def _int_adc_sbb(rng, slots):
    s0, s1, s2, s3 = slots
    a = rng.randrange(1 << 40, (1 << 63) - 1)
    b = rng.randrange(1, 1 << 40)
    s = _u64(a + b + 1)
    d = _u64(a - b - 1)
    loads = [(s0, a), (s1, b)]
    stores = [(s2, s, "a + b + 1"), (s3, d, "a - b - 1")]
    return loads, stores, ""


@simple_compute_block(
    name="test_cmp_eq",
    scratch=3,
    coarse={"CMP": 1, "TEST": 1, "LOAD": 2, "STORE": 1},
    # On x86/aarch64/riscv the compiler emits a discrete compare insn
    # (cmp / slt / etc.) that maps to GEN_OP_CMP.  On MIPS, GCC under
    # -O1 frequently fuses the equality test into a `beq`/`bne`
    # conditional branch (the comparison happens *as part of* the
    # branch encoding), so no GEN_OP_CMP instruction appears in the
    # trace.  Skip the CMP assertion on mipsel.
    asserted_opcodes_per_isa={
        "x86_64":  ["CMP"],
        "aarch64": ["CMP"],
        "riscv64": ["CMP"],
        "mipsel":  [],
    },
)
def _test_cmp_eq(rng, slots):
    s0, s1, s2 = slots
    a = rng.randrange(0, 1 << 32)
    b = a  # guarantee eq branch on CMP
    loads = [(s0, a), (s1, b)]
    r = 1 if a == b else 0
    stores = [(s2, r, "(a == b) ? 1ULL : 0ULL")]
    return loads, stores, ""


@simple_compute_block(
    name="xchg_pair",
    scratch=4,
    coarse={"XCHG": 1, "LOAD": 2, "STORE": 2},
    # x86 classifies memory MOVs as GEN_OP_MOV rather than LOAD/STORE,
    # so we don't assert a specific opcode name here -- the memop count
    # check in the validator already covers the load/store traffic.
    asserted_opcodes=[],
)
def _xchg_pair(rng, slots):
    s0, s1, s2, s3 = slots
    a = rng.randrange(1, 1 << 40)
    b = rng.randrange(1, 1 << 40)
    loads = [(s0, a), (s1, b)]
    # Emitted as two mutually-swapping stores (portable "xchg").
    stores = [(s2, b, "b"), (s3, a, "a")]
    return loads, stores, ""


# ---------------------------------------------------------------------------
# Branch-type coverage blocks
#
# Each of these introduces one or more uncommon branch-type instructions
# INSIDE a straight-line block (num_successors=1).  From the generator's
# CFG point of view they look identical to any other straight-line block,
# but the plugin's trace will show branch / RET / indirect-JMP instructions
# inside the template's insn list.  The validator uses
# `asserted_branch_types` to check coverage.
# ---------------------------------------------------------------------------

# Name of the shared helper leaf function emitted once in the preamble.
HELPER_LEAF_NAME = "wptgen_leaf"


@register
class DirectCallBlock(CodeBlock):
    """Calls a no-op leaf function defined at file scope.  Emits a
    BRANCH_DIRECT_JUMP at the call site and a BRANCH_RETURN inside
    the leaf — both observable in the plugin's trace templates."""
    name = "direct_call"
    num_successors = 1
    scratch_slots = 0

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        # No arena memops: a CALL ends a TB, so the load-before /
        # store-after pair would straddle two templates and confuse the
        # single-template memop multiset check.  We rely entirely on the
        # disassembly-level branch-type assertion.
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[],
            coarse_opcodes={"BRANCH": 1, "RET": 1},
            asserted_opcodes=["BRANCH"],
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  (void){HELPER_LEAF_NAME}(0);\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )


@register
class IndirectCallBlock(CodeBlock):
    """Calls the leaf function via a function-pointer variable.  On
    every ISA this forces the compiler to materialise the address and
    emit a register/memory-indirect call (BRANCH_INDIRECT_JUMP)."""
    name = "indirect_call"
    num_successors = 1
    scratch_slots = 0

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        # See DirectCallBlock for why memops is empty.
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[],
            coarse_opcodes={"BRANCH": 1, "RET": 1},
            asserted_branch_types=["BRANCH_INDIRECT_JUMP"],
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t (* volatile fp)(uint64_t) = &{HELPER_LEAF_NAME};\n"
            f"  (void)fp(0);\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )


@register
class IndirectJumpBlock(CodeBlock):
    """Uses GCC's labels-as-values (`&&label`) combined with inline
    `asm goto` so the compiler emits a true indirect jump
    (BRANCH_INDIRECT_JUMP).  Target is always the block's successor,
    so CFG behaviour is unchanged.  x86-only because the asm uses
    `jmp *%0`; the block is simply skipped on other ISAs.
    """
    name = "indirect_jump"
    supported_isas = ("x86_64",)
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
            coarse_opcodes={"LOAD": 1, "STORE": 1, "INT_ADD": 1},
            asserted_branch_types=["BRANCH_INDIRECT_JUMP"],
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        s0 = plan.memops[0].arena_u64_index
        s1 = plan.memops[1].arena_u64_index
        succ = ctx.successor_labels[0]
        # The successor C label (L_blk_N) and the successor's `.globl`
        # asm symbol (blk_N) are NOT guaranteed to live at the same PC
        # after GCC's block reordering -- the C label floats with the
        # statements around it, while the inline asm `.globl` directive
        # stays pinned to where the assembler encounters it.  We load
        # the asm symbol's address via a RIP-relative LEA so the jump
        # target is exactly `blk_N`, which is what the analyzer sees in
        # the ELF symbol table.
        succ_sym = succ.removeprefix("L_") if succ.startswith("L_") else succ
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  uint64_t a = {_volatile_load_u64(s0)};\n"
            f"  uint64_t r = a + 1;\n"
            f"  {_volatile_store_u64(s1, 'r')}\n"
            # asm goto with a label clobber so GCC knows control may
            # exit to `succ`; the asm body ignores the label operand
            # and jumps directly to the pinned `.globl` symbol.
            f"  asm goto (\"leaq {succ_sym}(%%rip), %%rax\\n\\t\"\n"
            f"            \"jmp *%%rax\"\n"
            f"            : : : \"rax\",\"memory\" : {succ});\n"
            f"}}\n"
        )


@register
class X86CondUncondBlock(CodeBlock):
    """x86-only: emits a JECXZ instruction via inline asm.

    JECXZ (and the LOOP* family) are the classic "conditional
    unconditional" branches — Capstone classifies them with the
    unconditional JUMP group, but they only transfer control when
    ECX == 0.  The champsim_tracer plugin's canonical behaviour is to report
    ``branch_type == BRANCH_DIRECT_JUMP`` *together with*
    ``branch_conditional == true``.  Blocks of this class assert that
    pairing exists somewhere in their disassembly.
    """
    name = "x86_cond_uncond"
    num_successors = 1
    scratch_slots = 0
    supported_isas = ("x86_64",)

    @classmethod
    def plan(cls, ctx: EmitCtx) -> BlockPlan:
        # JECXZ terminates a TB, so any load-before / store-after pair
        # would straddle two templates.  We keep the block memop-free
        # and rely on the cond-uncond branch assertion below.
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[],
            coarse_opcodes={"BRANCH": 1},
            asserted_cond_uncond_branch=True,
        )

    @classmethod
    def emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        # Emit a guaranteed-not-taken JECXZ: set %ecx = 1, then JECXZ
        # (branch if ECX == 0) falls through to the rest of the block.
        # The key point is that the instruction EXISTS in the template
        # so the validator can inspect its classification.
        body_asm = (
            '"mov $1, %%ecx\\n\\t"\n'
            '"jecxz 1f\\n\\t"\n'
            '"1:\\n\\t"\n'
            ':: : "ecx","memory"'
        )
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  asm volatile(\n  {body_asm});\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )


# ===========================================================================
# Inline-asm opcode probes
#
# Many GenericOpcode values can only be emitted reliably with inline asm
# (PUSH/POP/LEA/XCHG/CMOV/SETCC/FENCE/rotates/vector insns/...).  The
# `asm_probe_block` factory collapses that pattern to a single per-ISA
# specification:
#
#   asm_probe_block(
#       name="probe_x86_lea",
#       per_isa={
#           "x86_64": {
#               "asm":      '"leaq 1(%%rax,%%rax,1), %%rax"',
#               "clobbers": '"rax"',
#               "opcodes":  ["LEA"],
#           },
#       },
#   )
#
# The factory produces a straight-line (1-successor) block that emits
# exactly the given inline asm.  It has zero memops, so the validator's
# memop check is trivially satisfied, and the block's
# `asserted_opcodes` is populated per-ISA at plan time from the per-ISA
# specification.
#
# Using raw register clobbers avoids the generator having to reason
# about operand numbering; each probe is a minimal, self-contained
# instruction sequence that survives compiler optimisation because it
# lives inside `asm volatile`.
# ===========================================================================


def asm_probe_block(
    *,
    name: str,
    per_isa: dict[str, dict],
):
    """Register a CodeBlock whose body is exactly an inline-asm probe.

    `per_isa[isa]` must supply:
      * "asm":      GCC inline-asm body (a single C string literal, with
                    \\n\\t separators if multiple instructions).
      * "opcodes":  list of GenericOpcode names that are guaranteed to
                    appear in the disassembled asm.  Wired into the
                    plan's `asserted_opcodes`.
      * "clobbers": optional clobber list (as the raw C string that
                    follows `:::`).  Defaults to `"memory"`.
      * "branch_types":  optional list of BranchType names to assert.
    """
    supported = tuple(per_isa.keys())

    class _AsmProbe(CodeBlock):
        pass

    _AsmProbe.name = name
    _AsmProbe.num_successors = 1
    _AsmProbe.scratch_slots = 0
    _AsmProbe.supported_isas = supported

    @classmethod  # type: ignore[misc]
    def _plan(cls, ctx: EmitCtx) -> BlockPlan:
        spec = per_isa[ctx.isa]
        return BlockPlan(
            block_id=ctx.block_id, name=cls.name,
            memops=[],
            coarse_opcodes={},
            asserted_opcodes=list(spec.get("opcodes", [])),
            asserted_branch_types=list(spec.get("branch_types", [])),
        )

    @classmethod  # type: ignore[misc]
    def _emit(cls, plan: BlockPlan, ctx: EmitCtx) -> str:
        spec = per_isa[ctx.isa]
        asm_body = spec["asm"]
        clobbers = spec.get("clobbers", '"memory"')
        return (
            f"{_emit_label(ctx.block_id)}"
            f"{{\n"
            f"  asm volatile(\n"
            f"    {asm_body}\n"
            f"    :: : {clobbers});\n"
            f"  {_goto_successor(ctx, 0)}\n"
            f"}}\n"
        )

    _AsmProbe.plan = _plan
    _AsmProbe.emit = _emit
    _AsmProbe.__name__ = f"AsmProbe_{name}"
    register(_AsmProbe)
    return _AsmProbe


# ---------------------------------------------------------------------------
# x86_64 probes — one block per uniquely-classified GenericOpcode.
# Every probe uses caller-clobbered GPRs (rax/rbx/rcx/rdx) or XMM0/XMM1
# so no callee-save ABI machinery is disturbed.
# ---------------------------------------------------------------------------

asm_probe_block(
    name="probe_x86_lea",
    per_isa={
        "x86_64": {
            "asm":      '"leaq 3(%%rax,%%rax,4), %%rax"',
            "clobbers": '"rax"',
            "opcodes":  ["LEA"],
        },
    },
)

asm_probe_block(
    name="probe_x86_push_pop",
    per_isa={
        "x86_64": {
            # Round-trip: pushq imm ; popq reg — a minimal pairing that
            # leaves the stack pointer unchanged across the block.
            "asm":      '"pushq $0x1234\\n\\t"\n    "popq %%rax"',
            "clobbers": '"rax","cc"',
            "opcodes":  ["PUSH", "POP"],
        },
    },
)

asm_probe_block(
    name="probe_x86_movsx_movzx",
    per_isa={
        "x86_64": {
            "asm":      (
                '"movb $-1, %%al\\n\\t"\n'
                '    "movsx %%al, %%ebx\\n\\t"\n'
                '    "movzx %%al, %%ecx"'
            ),
            "clobbers": '"rax","rbx","rcx"',
            "opcodes":  ["MOVSX", "MOVZX"],
        },
    },
)

asm_probe_block(
    name="probe_x86_xchg",
    per_isa={
        "x86_64": {
            "asm":      '"xchg %%rax, %%rbx"',
            "clobbers": '"rax","rbx"',
            "opcodes":  ["XCHG"],
        },
    },
)

asm_probe_block(
    name="probe_x86_cmov",
    per_isa={
        "x86_64": {
            # CMP+CMOV: rax ← (rbx < rcx ? rdx : rax).
            "asm":      (
                '"cmp %%rcx, %%rbx\\n\\t"\n'
                '    "cmovl %%rdx, %%rax"'
            ),
            "clobbers": '"rax","cc"',
            "opcodes":  ["CMOV", "CMP"],
        },
    },
)

asm_probe_block(
    name="probe_x86_setcc",
    per_isa={
        "x86_64": {
            "asm":      (
                '"xor %%eax, %%eax\\n\\t"\n'
                '    "cmp %%rcx, %%rbx\\n\\t"\n'
                '    "sete %%al"'
            ),
            "clobbers": '"rax","cc"',
            "opcodes":  ["SETCC"],
        },
    },
)

asm_probe_block(
    name="probe_x86_fence",
    per_isa={
        "x86_64": {
            "asm":      '"mfence"',
            "clobbers": '"memory"',
            "opcodes":  ["FENCE"],
        },
    },
)

asm_probe_block(
    name="probe_x86_rotate",
    per_isa={
        "x86_64": {
            "asm":      (
                '"rol $5, %%rax\\n\\t"\n'
                '    "ror $3, %%rbx"'
            ),
            "clobbers": '"rax","rbx","cc"',
            "opcodes":  ["ROL", "ROR"],
        },
    },
)

asm_probe_block(
    name="probe_x86_inc_dec",
    per_isa={
        "x86_64": {
            "asm":      (
                '"inc %%rax\\n\\t"\n'
                '    "dec %%rbx"'
            ),
            "clobbers": '"rax","rbx","cc"',
            "opcodes":  ["INC", "DEC"],
        },
    },
)

asm_probe_block(
    name="probe_x86_neg_not",
    per_isa={
        "x86_64": {
            "asm":      (
                '"neg %%rax\\n\\t"\n'
                '    "not %%rbx"'
            ),
            "clobbers": '"rax","rbx","cc"',
            "opcodes":  ["NEG", "NOT"],
        },
    },
)

asm_probe_block(
    name="probe_x86_test",
    per_isa={
        "x86_64": {
            "asm":      '"test %%rax, %%rbx"',
            "clobbers": '"cc"',
            "opcodes":  ["TEST"],
        },
    },
)

asm_probe_block(
    name="probe_x86_shift",
    per_isa={
        "x86_64": {
            "asm":      (
                '"shl $3, %%rax\\n\\t"\n'
                '    "shr $2, %%rbx\\n\\t"\n'
                '    "sar $1, %%rcx"'
            ),
            "clobbers": '"rax","rbx","rcx","cc"',
            "opcodes":  ["SHL", "SHR", "SAR"],
        },
    },
)

asm_probe_block(
    name="probe_x86_int_mul",
    per_isa={
        "x86_64": {
            "asm":      '"imul %%rbx, %%rax"',
            "clobbers": '"rax","cc"',
            "opcodes":  ["INT_MUL"],
        },
    },
)

asm_probe_block(
    name="probe_x86_int_div",
    per_isa={
        "x86_64": {
            # Clear %rdx for unsigned DIV so we don't trigger #DE on a
            # non-zero high half.  Divisor in %rbx is a fixed small
            # constant so the sequence is hermetic.
            "asm":      (
                '"xor %%edx, %%edx\\n\\t"\n'
                '    "mov $7, %%rbx\\n\\t"\n'
                '    "mov $1000, %%rax\\n\\t"\n'
                '    "div %%rbx"'
            ),
            "clobbers": '"rax","rbx","rdx","cc"',
            "opcodes":  ["INT_DIV"],
        },
    },
)

asm_probe_block(
    name="probe_x86_int_adc_sbb",
    per_isa={
        "x86_64": {
            "asm":      (
                '"clc\\n\\t"\n'
                '    "adc %%rbx, %%rax\\n\\t"\n'
                '    "sbb %%rdx, %%rcx"'
            ),
            "clobbers": '"rax","rcx","cc"',
            "opcodes":  ["INT_ADC", "INT_SBB"],
        },
    },
)

asm_probe_block(
    name="probe_x86_logic",
    per_isa={
        "x86_64": {
            "asm":      (
                '"and %%rbx, %%rax\\n\\t"\n'
                '    "or %%rdx, %%rcx\\n\\t"\n'
                '    "xor %%rsi, %%rdi"'
            ),
            "clobbers": '"rax","rcx","rdi","cc"',
            "opcodes":  ["AND", "OR", "XOR"],
        },
    },
)

asm_probe_block(
    name="probe_x86_int_add_sub",
    per_isa={
        "x86_64": {
            "asm":      (
                '"add %%rbx, %%rax\\n\\t"\n'
                '    "sub %%rdx, %%rcx"'
            ),
            "clobbers": '"rax","rcx","cc"',
            "opcodes":  ["INT_ADD", "INT_SUB"],
        },
    },
)

asm_probe_block(
    name="probe_x86_load_store",
    per_isa={
        "x86_64": {
            # FNSTCW/LDMXCSR are the x86 insns classified as GEN_OP_LOAD
            # / GEN_OP_STORE in champsim_tracer_mnemonics_x86.h (ordinary MOVs
            # map to GEN_OP_MOV).  Use an on-stack slot so we don't
            # touch the arena.
            "asm":      (
                '"subq $8, %%rsp\\n\\t"\n'
                '    "fnstcw (%%rsp)\\n\\t"\n'
                '    "stmxcsr (%%rsp)\\n\\t"\n'
                '    "ldmxcsr (%%rsp)\\n\\t"\n'
                '    "fldcw (%%rsp)\\n\\t"\n'
                '    "addq $8, %%rsp"'
            ),
            "clobbers": '"memory"',
            "opcodes":  ["LOAD", "STORE"],
        },
    },
)

asm_probe_block(
    name="probe_x86_vec_arith",
    per_isa={
        "x86_64": {
            "asm":      (
                '"paddq %%xmm1, %%xmm0\\n\\t"\n'
                '    "psubq %%xmm1, %%xmm2\\n\\t"\n'
                '    "pmullw %%xmm1, %%xmm3"'
            ),
            "clobbers": '"xmm0","xmm2","xmm3"',
            "opcodes":  ["VEC_ADD", "VEC_SUB", "VEC_MUL"],
        },
    },
)

asm_probe_block(
    name="probe_x86_vec_move",
    per_isa={
        "x86_64": {
            "asm":      (
                '"movdqa %%xmm0, %%xmm1\\n\\t"\n'
                '    "pshufd $0x1B, %%xmm0, %%xmm2"'
            ),
            "clobbers": '"xmm1","xmm2"',
            "opcodes":  ["VEC_MOV", "VEC_SHUF"],
        },
    },
)

asm_probe_block(
    name="probe_x86_vec_logic",
    per_isa={
        "x86_64": {
            "asm":      (
                '"pand %%xmm1, %%xmm0\\n\\t"\n'
                '    "por %%xmm1, %%xmm2\\n\\t"\n'
                '    "pxor %%xmm1, %%xmm3"'
            ),
            "clobbers": '"xmm0","xmm2","xmm3"',
            "opcodes":  ["VEC_LOGIC"],
        },
    },
)

asm_probe_block(
    name="probe_x86_fp_arith",
    per_isa={
        "x86_64": {
            "asm":      (
                '"addsd %%xmm1, %%xmm0\\n\\t"\n'
                '    "subsd %%xmm1, %%xmm2\\n\\t"\n'
                '    "mulsd %%xmm1, %%xmm3\\n\\t"\n'
                '    "divsd %%xmm1, %%xmm4"'
            ),
            "clobbers": '"xmm0","xmm2","xmm3","xmm4"',
            "opcodes":  ["FP_ADD", "FP_SUB", "FP_MUL", "FP_DIV"],
        },
    },
)

asm_probe_block(
    name="probe_x86_fp_sqrt_cmp",
    per_isa={
        "x86_64": {
            "asm":      (
                '"sqrtsd %%xmm1, %%xmm0\\n\\t"\n'
                '    "ucomisd %%xmm1, %%xmm0"'
            ),
            "clobbers": '"xmm0","cc"',
            "opcodes":  ["FP_SQRT", "FP_CMP"],
        },
    },
)

asm_probe_block(
    name="probe_x86_fp_mov_cvt",
    per_isa={
        "x86_64": {
            "asm":      (
                '"movsd %%xmm1, %%xmm0\\n\\t"\n'
                '    "cvtsi2sd %%rax, %%xmm2"'
            ),
            "clobbers": '"xmm0","xmm2"',
            "opcodes":  ["FP_MOV", "FP_CVT"],
        },
    },
)

asm_probe_block(
    name="probe_x86_fma",
    per_isa={
        "x86_64": {
            "asm":      (
                '"vfmadd132sd %%xmm1, %%xmm2, %%xmm0\\n\\t"\n'
                '    "vfmsub132sd %%xmm4, %%xmm5, %%xmm3"'
            ),
            "clobbers": '"xmm0","xmm3"',
            "opcodes":  ["FP_MADD", "FP_MSUB"],
        },
    },
)

asm_probe_block(
    name="probe_x86_vec_madd",
    per_isa={
        "x86_64": {
            "asm":      '"pmaddwd %%xmm1, %%xmm0"',
            "clobbers": '"xmm0"',
            "opcodes":  ["VEC_MADD"],
        },
    },
)

asm_probe_block(
    name="probe_x86_nop",
    per_isa={
        "x86_64": {
            # Three-byte NOP — a single multi-byte NOP encoding that
            # Capstone classifies distinctly from a bare `nop`.
            "asm":      '".byte 0x0f, 0x1f, 0x00"',
            "clobbers": '"memory"',
            "opcodes":  ["NOP"],
        },
    },
)


# ---------------------------------------------------------------------------
# aarch64 probes — exercise the core GenericOpcode classes using
# caller-clobbered GPRs (x0-x7) and SIMD regs (v0-v3).
# Requires g++-aarch64-linux-gnu + qemu-aarch64.
# ---------------------------------------------------------------------------

asm_probe_block(
    name="probe_arm_int_add_sub",
    per_isa={
        "aarch64": {
            "asm":      (
                '"add x0, x1, x2\\n\\t"\n'
                '    "sub x3, x4, x5"'
            ),
            "clobbers": '"x0","x3","cc"',
            "opcodes":  ["INT_ADD", "INT_SUB"],
        },
    },
)

asm_probe_block(
    name="probe_arm_int_mul_div",
    per_isa={
        "aarch64": {
            # AArch64 `mul` is an alias of MADD with XZR as the addend;
            # keep that explicit and add UMULH as a true INT_MUL-class
            # instruction so this probe exercises both families.
            "asm":      (
                '"mov x1, #1000\\n\\t"\n'
                '    "mov x2, #7\\n\\t"\n'
                '    "mul  x0, x1, x2\\n\\t"\n'
                '    "umulh x4, x1, x2\\n\\t"\n'
                '    "udiv x3, x1, x2"'
            ),
            "clobbers": '"x0","x1","x2","x3","x4"',
            "opcodes":  ["INT_MADD", "INT_MUL", "INT_DIV"],
        },
    },
)

asm_probe_block(
    name="probe_arm_logic",
    per_isa={
        "aarch64": {
            "asm":      (
                '"and x0, x1, x2\\n\\t"\n'
                '    "orr x3, x4, x5\\n\\t"\n'
                '    "eor x6, x7, x0"'
            ),
            "clobbers": '"x0","x3","x6"',
            "opcodes":  ["AND", "OR", "XOR"],
        },
    },
)

asm_probe_block(
    name="probe_arm_shift",
    per_isa={
        "aarch64": {
            # Register-form shifts have dedicated AArch64 opcodes
            # (LSLV/LSRV/ASRV, mnemonics LSL/LSR/ASR with reg operand).
            # Immediate-form shifts encode as UBFM/SBFM and are
            # exercised by probe_arm_sxt_uxt instead.
            "asm":      (
                '"lsl x0, x1, x2\\n\\t"\n'
                '    "lsr x3, x4, x5\\n\\t"\n'
                '    "asr x6, x7, x0"'
            ),
            "clobbers": '"x0","x3","x6"',
            "opcodes":  ["SHL", "SHR", "SAR"],
        },
    },
)

asm_probe_block(
    name="probe_arm_sxt_uxt",
    per_isa={
        "aarch64": {
            "asm":      (
                '"sxtb x0, w1\\n\\t"\n'
                '    "uxtb x2, w3\\n\\t"\n'
                '    "sxth x4, w5\\n\\t"\n'
                '    "uxth x6, w7"'
            ),
            "clobbers": '"x0","x2","x4","x6"',
            "opcodes":  ["MOVSX", "MOVZX"],
        },
    },
)

asm_probe_block(
    name="probe_arm_adc_sbc",
    per_isa={
        "aarch64": {
            "asm":      (
                '"cmp x0, x0\\n\\t"     /* clear carry to known state */\n'
                '    "adc x1, x2, x3\\n\\t"\n'
                '    "sbc x4, x5, x6"'
            ),
            "clobbers": '"x1","x4","cc"',
            "opcodes":  ["INT_ADC", "INT_SBB"],
        },
    },
)

asm_probe_block(
    name="probe_arm_load_store",
    per_isa={
        "aarch64": {
            # Round-trip via the stack: store then load an x-reg pair.
            "asm":      (
                '"sub sp, sp, #16\\n\\t"\n'
                '    "stp x0, x1, [sp]\\n\\t"\n'
                '    "ldp x2, x3, [sp]\\n\\t"\n'
                '    "add sp, sp, #16"'
            ),
            "clobbers": '"x2","x3","memory"',
            "opcodes":  ["LOAD", "STORE"],
        },
    },
)

asm_probe_block(
    name="probe_arm_vec_arith",
    per_isa={
        "aarch64": {
            # Use instructions whose insn_id is exclusively vector:
            # ADDP (pairwise add), SABD (signed abs diff), PMUL
            # (polynomial multiply), and MLA (multiply-accumulate).
            "asm":      (
                '"addp v0.16b, v1.16b, v2.16b\\n\\t"\n'
                '    "sabd v3.16b, v4.16b, v5.16b\\n\\t"\n'
                '    "pmul v6.16b, v7.16b, v1.16b\\n\\t"\n'
                '    "mla  v0.16b, v7.16b, v1.16b"'
            ),
            "clobbers": '"v0","v3","v6"',
            "opcodes":  ["VEC_ADD", "VEC_SUB", "VEC_MUL", "VEC_MADD"],
        },
    },
)

asm_probe_block(
    name="probe_arm_vec_logic",
    per_isa={
        "aarch64": {
            # Use vector-exclusive mnemonics: BIT (bitwise insert if
            # true), BSL (bitwise select), CMEQ (vector compare-equal).
            # These all map to GEN_OP_VEC_LOGIC and have no scalar
            # form sharing the same insn_id.
            "asm":      (
                '"bit  v0.16b, v1.16b, v2.16b\\n\\t"\n'
                '    "bsl  v3.16b, v4.16b, v5.16b\\n\\t"\n'
                '    "cmeq v6.16b, v7.16b, v1.16b"'
            ),
            "clobbers": '"v0","v3","v6"',
            "opcodes":  ["VEC_LOGIC"],
        },
    },
)

asm_probe_block(
    name="probe_arm_fp_arith",
    per_isa={
        "aarch64": {
            "asm":      (
                '"fadd d0, d1, d2\\n\\t"\n'
                '    "fsub d3, d4, d5\\n\\t"\n'
                '    "fmul d6, d7, d1\\n\\t"\n'
                '    "fdiv d0, d2, d3"'
            ),
            "clobbers": '"d0","d3","d6"',
            "opcodes":  ["FP_ADD", "FP_SUB", "FP_MUL", "FP_DIV"],
        },
    },
)

asm_probe_block(
    name="probe_arm_fp_sqrt_cmp",
    per_isa={
        "aarch64": {
            "asm":      (
                '"fsqrt d0, d1\\n\\t"\n'
                '    "fcmp d0, d1"'
            ),
            "clobbers": '"d0","cc"',
            "opcodes":  ["FP_SQRT", "FP_CMP"],
        },
    },
)

asm_probe_block(
    name="probe_arm_fp_mov_cvt",
    per_isa={
        "aarch64": {
            "asm":      (
                '"fmov d0, d1\\n\\t"\n'
                '    "scvtf d2, x0"'
            ),
            "clobbers": '"d0","d2"',
            "opcodes":  ["FP_MOV", "FP_CVT"],
        },
    },
)

asm_probe_block(
    name="probe_arm_nop",
    per_isa={
        "aarch64": {
            "asm":      '"nop\\n\\t"\n    "nop"',
            "clobbers": '"memory"',
            "opcodes":  ["NOP"],
        },
    },
)


# ---------------------------------------------------------------------------
# riscv64 probes — use caller-saved t0-t6/a0-a7 GPRs and ft0-ft7 FPRs.
# Requires g++-riscv64-linux-gnu + qemu-riscv64.
# ---------------------------------------------------------------------------

asm_probe_block(
    name="probe_rv_int_add_sub",
    per_isa={
        "riscv64": {
            "asm":      (
                '"add t0, t1, t2\\n\\t"\n'
                '    "sub t3, t4, t5"'
            ),
            "clobbers": '"t0","t3"',
            "opcodes":  ["INT_ADD", "INT_SUB"],
        },
    },
)

asm_probe_block(
    name="probe_rv_int_mul_div",
    per_isa={
        "riscv64": {
            "asm":      (
                '"li t1, 1000\\n\\t"\n'
                '    "li t2, 7\\n\\t"\n'
                '    "mul  t0, t1, t2\\n\\t"\n'
                '    "divu t3, t1, t2"'
            ),
            "clobbers": '"t0","t1","t2","t3"',
            "opcodes":  ["INT_MUL", "INT_DIV"],
        },
    },
)

asm_probe_block(
    name="probe_rv_logic",
    per_isa={
        "riscv64": {
            "asm":      (
                '"and t0, t1, t2\\n\\t"\n'
                '    "or  t3, t4, t5\\n\\t"\n'
                '    "xor t6, a0, a1"'
            ),
            "clobbers": '"t0","t3","t6"',
            "opcodes":  ["AND", "OR", "XOR"],
        },
    },
)

asm_probe_block(
    name="probe_rv_shift",
    per_isa={
        "riscv64": {
            "asm":      (
                '"slli t0, t1, 3\\n\\t"\n'
                '    "srli t2, t3, 2\\n\\t"\n'
                '    "srai t4, t5, 1"'
            ),
            "clobbers": '"t0","t2","t4"',
            "opcodes":  ["SHL", "SHR", "SAR"],
        },
    },
)

asm_probe_block(
    name="probe_rv_sxt_uxt",
    per_isa={
        "riscv64": {
            # RV has no dedicated sign/zero-extend mnemonics; the canonical
            # idioms are `sext.w` (an alias for ADDIW rd,rs,0) and
            # `andi r, r, 0xff` for zero-extend.  Capstone reports these
            # as RISCV_INS_ADDIW and RISCV_INS_ANDI respectively, which
            # the per-insn-id mnemonic table maps to INT_ADD and AND.
            "asm":      (
                '"sext.w t0, t1\\n\\t"\n'
                '    "andi  t2, t3, 0xff"'
            ),
            "clobbers": '"t0","t2"',
            "opcodes":  ["INT_ADD", "AND"],
        },
    },
)

asm_probe_block(
    name="probe_rv_load_store",
    per_isa={
        "riscv64": {
            "asm":      (
                '"addi sp, sp, -16\\n\\t"\n'
                '    "sd t0, 0(sp)\\n\\t"\n'
                '    "sd t1, 8(sp)\\n\\t"\n'
                '    "ld t2, 0(sp)\\n\\t"\n'
                '    "ld t3, 8(sp)\\n\\t"\n'
                '    "addi sp, sp, 16"'
            ),
            "clobbers": '"t2","t3","memory"',
            "opcodes":  ["LOAD", "STORE"],
        },
    },
)

asm_probe_block(
    name="probe_rv_fp_arith",
    per_isa={
        "riscv64": {
            "asm":      (
                '"fadd.d ft0, ft1, ft2\\n\\t"\n'
                '    "fsub.d ft3, ft4, ft5\\n\\t"\n'
                '    "fmul.d ft6, ft7, ft1\\n\\t"\n'
                '    "fdiv.d ft0, ft2, ft3"'
            ),
            "clobbers": '"ft0","ft3","ft6"',
            "opcodes":  ["FP_ADD", "FP_SUB", "FP_MUL", "FP_DIV"],
        },
    },
)

asm_probe_block(
    name="probe_rv_fp_sqrt_cmp",
    per_isa={
        "riscv64": {
            "asm":      (
                '"fsqrt.d ft0, ft1\\n\\t"\n'
                '    "feq.d  t0, ft0, ft1"'
            ),
            "clobbers": '"ft0","t0"',
            "opcodes":  ["FP_SQRT", "FP_CMP"],
        },
    },
)

asm_probe_block(
    name="probe_rv_fp_mov_cvt",
    per_isa={
        "riscv64": {
            "asm":      (
                '"fmv.d    ft0, ft1\\n\\t"\n'
                '    "fcvt.d.l ft2, t0"'
            ),
            "clobbers": '"ft0","ft2"',
            "opcodes":  ["FP_MOV", "FP_CVT"],
        },
    },
)

asm_probe_block(
    name="probe_rv_nop",
    per_isa={
        "riscv64": {
            # `nop` on RV is an alias for `addi x0, x0, 0`.
            "asm":      '"nop\\n\\t"\n    "nop"',
            "clobbers": '"memory"',
            "opcodes":  ["NOP"],
        },
    },
)


# ---------------------------------------------------------------------------
# mipsel probes — MIPS32r2 little-endian.  Use caller-clobbered t0-t9.
# Requires g++-mipsel-linux-gnu + qemu-mipsel.
# ---------------------------------------------------------------------------

asm_probe_block(
    name="probe_mips_int_add_sub",
    per_isa={
        "mipsel": {
            "asm":      (
                '"addu $t0, $t1, $t2\\n\\t"\n'
                '    "subu $t3, $t4, $t5"'
            ),
            "clobbers": '"$t0","$t3"',
            "opcodes":  ["INT_ADD", "INT_SUB"],
        },
    },
)

asm_probe_block(
    name="probe_mips_int_mul_div",
    per_isa={
        "mipsel": {
            "asm":      (
                '"li   $t1, 1000\\n\\t"\n'
                '    "li   $t2, 7\\n\\t"\n'
                '    "mul  $t0, $t1, $t2\\n\\t"\n'
                '    "divu $t1, $t2\\n\\t"\n'
                '    "mflo $t3"'
            ),
            "clobbers": '"$t0","$t1","$t2","$t3","hi","lo"',
            "opcodes":  ["INT_MUL", "INT_DIV"],
        },
    },
)

asm_probe_block(
    name="probe_mips_logic",
    per_isa={
        "mipsel": {
            "asm":      (
                '"and $t0, $t1, $t2\\n\\t"\n'
                '    "or  $t3, $t4, $t5\\n\\t"\n'
                '    "xor $t6, $t7, $t8"'
            ),
            "clobbers": '"$t0","$t3","$t6"',
            "opcodes":  ["AND", "OR", "XOR"],
        },
    },
)

asm_probe_block(
    name="probe_mips_shift",
    per_isa={
        "mipsel": {
            "asm":      (
                '"sll $t0, $t1, 3\\n\\t"\n'
                '    "srl $t2, $t3, 2\\n\\t"\n'
                '    "sra $t4, $t5, 1"'
            ),
            "clobbers": '"$t0","$t2","$t4"',
            "opcodes":  ["SHL", "SHR", "SAR"],
        },
    },
)

asm_probe_block(
    name="probe_mips_sxt_uxt",
    per_isa={
        "mipsel": {
            # `seb`/`seh` are real MIPS32r2 sign-extend insns -> MOVSX.
            # `andi rd, rs, 0xff` is the canonical zero-extend idiom but
            # Capstone reports it as MIPS_INS_ANDI which the mnemonic
            # table maps to AND (MIPS has no MOVZX-class insn id).
            "asm":      (
                '"seb  $t0, $t1\\n\\t"\n'
                '    "seh  $t2, $t3\\n\\t"\n'
                '    "andi $t4, $t5, 0xff"'
            ),
            "clobbers": '"$t0","$t2","$t4"',
            "opcodes":  ["MOVSX", "AND"],
        },
    },
)

asm_probe_block(
    name="probe_mips_load_store",
    per_isa={
        "mipsel": {
            "asm":      (
                '"addiu $sp, $sp, -8\\n\\t"\n'
                '    "sw    $t0, 0($sp)\\n\\t"\n'
                '    "sw    $t1, 4($sp)\\n\\t"\n'
                '    "lw    $t2, 0($sp)\\n\\t"\n'
                '    "lw    $t3, 4($sp)\\n\\t"\n'
                '    "addiu $sp, $sp, 8"'
            ),
            "clobbers": '"$t2","$t3","memory"',
            "opcodes":  ["LOAD", "STORE"],
        },
    },
)

asm_probe_block(
    name="probe_mips_fp_arith",
    per_isa={
        "mipsel": {
            # Capstone 6 emits distinct FP instruction IDs for `add.d`/`sub.d`/
            # `mul.d`/`div.d` (MIPS_INS_ADD_D, SUB_D, MUL_D, DIV_D), which the
            # mips classification table maps to FP_ADD/FP_SUB/FP_MUL/FP_DIV.
            # (Capstone 5 emitted the integer-form IDs and we asserted INT_*
            # here as a workaround — no longer needed under cs6.)
            "asm":      (
                '"add.d $f0, $f2, $f4\\n\\t"\n'
                '    "sub.d $f6, $f8, $f10\\n\\t"\n'
                '    "mul.d $f12, $f14, $f2\\n\\t"\n'
                '    "div.d $f0, $f4, $f6"'
            ),
            "clobbers": '"$f0","$f6","$f12"',
            "opcodes":  ["FP_ADD", "FP_SUB", "FP_MUL", "FP_DIV"],
        },
    },
)

asm_probe_block(
    name="probe_mips_fp_sqrt_cmp",
    per_isa={
        "mipsel": {
            "asm":      (
                '"sqrt.d $f0, $f2\\n\\t"\n'
                '    "c.eq.d $f0, $f2"'
            ),
            "clobbers": '"$f0"',
            "opcodes":  ["FP_SQRT", "FP_CMP"],
        },
    },
)

asm_probe_block(
    name="probe_mips_fp_mov_cvt",
    per_isa={
        "mipsel": {
            "asm":      (
                '"mov.d    $f0, $f2\\n\\t"\n'
                '    "cvt.d.w  $f4, $f6"'
            ),
            "clobbers": '"$f0","$f4"',
            "opcodes":  ["FP_MOV", "FP_CVT"],
        },
    },
)

asm_probe_block(
    name="probe_mips_nop",
    per_isa={
        "mipsel": {
            # `nop` on MIPS is an alias for `sll $zero, $zero, 0`.
            # Capstone 6 reports MIPS_INS_SLL (mapped to GEN_OP_SHL),
            # not a synthetic MIPS_INS_NOP.
            "asm":      '"nop\\n\\t"\n    "nop"',
            "clobbers": '"memory"',
            "opcodes":  ["SHL"],
        },
    },
)


# ===========================================================================
# Coverage-completion probes
#
# The probes above predate this section and were added incrementally as
# specific opcodes were noticed missing.  Everything below is the result
# of a per-ISA audit against the GenericOpcode classifications in
# `champsim_tracer_mnemonics_<isa>.h`: for every classification that is
# reachable on a given ISA, there is at least one probe block that emits
# an instruction guaranteed to receive that classification.  Combined
# with the `--coverage` mode (see generator.py), this gives 100% generic
# opcode coverage per ISA.
# ===========================================================================

# ---------------------------------------------------------------------------
# x86_64 — completion
# ---------------------------------------------------------------------------

asm_probe_block(
    name="probe_x86_mov",
    per_isa={
        "x86_64": {
            # Plain register-to-register MOV, classified as GEN_OP_MOV
            # (distinct from MOVSX/MOVZX/CMOV/etc.).
            "asm":      '"mov %%rbx, %%rax"',
            "clobbers": '"rax"',
            "opcodes":  ["MOV"],
        },
    },
)


# ---------------------------------------------------------------------------
# aarch64 — completion
# ---------------------------------------------------------------------------

asm_probe_block(
    name="probe_arm_mov_not_neg",
    per_isa={
        "aarch64": {
            # On AArch64 these are not distinct opcodes in silicon:
            #   mov xn, xm   -> ORR  xn, xzr, xm     (GEN_OP_OR)
            #   mvn xn, xm   -> ORN  xn, xzr, xm     (GEN_OP_OR)
            #   neg xn, xm   -> SUB  xn, xzr, xm     (GEN_OP_INT_SUB)
            # Capstone 6 emits the underlying ORR/ORN/SUB ids.
            "asm":      (
                '"mov x0, x1\\n\\t"\n'
                '    "mvn x2, x3\\n\\t"\n'
                '    "neg x4, x5"'
            ),
            "clobbers": '"x0","x2","x4"',
            "opcodes":  ["OR", "INT_SUB"],
        },
    },
)

asm_probe_block(
    name="probe_arm_cmp_test",
    per_isa={
        "aarch64": {
            # AArch64 has no dedicated CMP/TEST opcode.
            #   cmp xn, xm  -> SUBS xzr, xn, xm  (GEN_OP_INT_SUB, writes NZCV)
            #   tst xn, xm  -> ANDS xzr, xn, xm  (GEN_OP_AND,     writes NZCV)
            "asm":      (
                '"cmp x0, x1\\n\\t"\n'
                '    "tst x2, x3"'
            ),
            "clobbers": '"cc"',
            "opcodes":  ["INT_SUB", "AND"],
        },
    },
)

asm_probe_block(
    name="probe_arm_cmov_setcc",
    per_isa={
        "aarch64": {
            # AArch64 has no SETCC opcode.  cset xd, cond is encoded as
            # csinc xd, xzr, xzr, !cond, so it classifies as GEN_OP_CMOV
            # (the same family as CSEL/CSINC/CSINV/CSNEG).
            #   cmp   -> SUBS  (GEN_OP_INT_SUB, writes NZCV)
            #   csel  -> CSEL  (GEN_OP_CMOV)
            #   cset  -> CSINC (GEN_OP_CMOV)
            #   csinc -> CSINC (GEN_OP_CMOV)
            "asm":      (
                '"cmp x0, x1\\n\\t"\n'
                '    "csel x2, x3, x4, eq\\n\\t"\n'
                '    "cset x5, ne\\n\\t"\n'
                '    "csinc x6, x7, x0, gt"'
            ),
            "clobbers": '"x2","x5","x6","cc"',
            "opcodes":  ["CMOV", "INT_SUB"],
        },
    },
)

asm_probe_block(
    name="probe_arm_fence",
    per_isa={
        "aarch64": {
            # DMB / DSB / ISB all → GEN_OP_FENCE.  Use ISH domain (the
            # smallest legal "real" barrier) for DMB/DSB.
            "asm":      (
                '"dmb ish\\n\\t"\n'
                '    "dsb ish\\n\\t"\n'
                '    "isb"'
            ),
            "clobbers": '"memory"',
            "opcodes":  ["FENCE"],
        },
    },
)

asm_probe_block(
    name="probe_arm_lea",
    per_isa={
        "aarch64": {
            # ADR xd, label  → GEN_OP_LEA (PC-relative address calc).
            # ADRP loads the page address; ADR loads byte address.
            # The `1:` label sits just before the asm body so ADR's
            # +/-1MiB range is trivially satisfied.
            "asm":      (
                '"1:\\n\\t"\n'
                '    "adr  x0, 1b\\n\\t"\n'
                '    "adrp x1, 1b"'
            ),
            "clobbers": '"x0","x1"',
            "opcodes":  ["LEA"],
        },
    },
)

asm_probe_block(
    name="probe_arm_xchg",
    per_isa={
        "aarch64": {
            # SWP rs, rt, [rn]  → GEN_OP_XCHG (LSE atomic).  Requires
            # ARMv8.1-A LSE; switch the assembler arch locally so the
            # default v8.0-a baseline binary still assembles.  Operates
            # on a stack slot to avoid touching the arena.
            "asm":      (
                '".arch armv8.1-a\\n\\t"\n'
                '    "sub sp, sp, #16\\n\\t"\n'
                '    "mov x0, sp\\n\\t"\n'
                '    "mov x1, #0\\n\\t"\n'
                '    "swp x2, x1, [x0]\\n\\t"\n'
                '    "add sp, sp, #16\\n\\t"\n'
                '    ".arch armv8-a"'
            ),
            "clobbers": '"x0","x1","x2","memory"',
            "opcodes":  ["XCHG"],
        },
    },
)

asm_probe_block(
    name="probe_arm_rotate",
    per_isa={
        "aarch64": {
            # ROR xd, xn, #imm           → GEN_OP_ROR
            # EXTR xd, xn, xm, #imm      → GEN_OP_ROR (funnel-shift,
            #                              implements rotate when xn==xm)
            "asm":      (
                '"ror  x0, x1, #5\\n\\t"\n'
                '    "extr x2, x3, x3, #7"'
            ),
            "clobbers": '"x0","x2"',
            "opcodes":  ["ROR"],
        },
    },
)

asm_probe_block(
    name="probe_arm_vec_mov",
    per_isa={
        "aarch64": {
            # DUP / INS / MOVI all → GEN_OP_VEC_MOV.  The plain `mov`
            # vector form (`mov v0.16b, v1.16b`) is an alias for ORR and
            # classifies as GEN_OP_VEC_LOGIC, so we use the explicit
            # broadcast/insert/immediate-move forms instead.
            "asm":      (
                '"dup  v0.16b, w1\\n\\t"\n'
                '    "ins  v2.b[0], w3\\n\\t"\n'
                '    "movi v4.16b, #0xAA"'
            ),
            "clobbers": '"v0","v2","v4"',
            "opcodes":  ["VEC_MOV"],
        },
    },
)

asm_probe_block(
    name="probe_arm_vec_shuf",
    per_isa={
        "aarch64": {
            # ZIP1 / UZP1 / TRN1 / EXT / TBL all → GEN_OP_VEC_SHUF.
            "asm":      (
                '"zip1 v0.16b, v1.16b, v2.16b\\n\\t"\n'
                '    "uzp1 v3.16b, v4.16b, v5.16b\\n\\t"\n'
                '    "trn1 v6.16b, v7.16b, v1.16b\\n\\t"\n'
                '    "ext  v0.16b, v1.16b, v2.16b, #4\\n\\t"\n'
                '    "tbl  v3.16b, {v4.16b}, v5.16b"'
            ),
            "clobbers": '"v0","v3","v6"',
            "opcodes":  ["VEC_SHUF"],
        },
    },
)

asm_probe_block(
    name="probe_arm_msub_cmp_neg_not",
    per_isa={
        "aarch64": {
            "asm":      (
                '"ccmp x0, x1, #0, eq\\n\\t"\n'
                '    "msub x2, x3, x4, x5\\n\\t"\n'
                '    "abs  v0.16b, v1.16b\\n\\t"\n'
                '    "not  v2.16b, v3.16b"'
            ),
            "clobbers": '"x2","v0","v2","cc"',
            "opcodes":  ["CMP", "INT_MSUB", "NEG", "NOT"],
        },
    },
)

asm_probe_block(
    name="probe_arm_fp_madd_msub",
    per_isa={
        "aarch64": {
            "asm":      (
                '"fmadd d0, d1, d2, d3\\n\\t"\n'
                '    "fmsub d4, d5, d6, d7"'
            ),
            "clobbers": '"d0","d4"',
            "opcodes":  ["FP_MADD", "FP_MSUB"],
        },
    },
)

asm_probe_block(
    name="probe_arm_vec_msub",
    per_isa={
        "aarch64": {
            "asm":      '"mls v0.16b, v1.16b, v2.16b"',
            "clobbers": '"v0"',
            "opcodes":  ["VEC_MSUB"],
        },
    },
)


# ---------------------------------------------------------------------------
# riscv64 — completion
# ---------------------------------------------------------------------------

asm_probe_block(
    name="probe_rv_mov",
    per_isa={
        "riscv64": {
            # `mv rd, rs` is an assembler alias for `addi rd, rs, 0`.
            # Capstone exposes a dedicated RISCV_INS_MV id for it,
            # which the mnemonic table maps to GEN_OP_MOV (not
            # GEN_OP_INT_ADD).  Asserting MOV documents the
            # alias-vs-canonical-form distinction explicitly.
            "asm":      '"mv t0, t1"',
            "clobbers": '"t0"',
            "opcodes":  ["MOV"],
        },
    },
)

asm_probe_block(
    name="probe_rv_lea",
    per_isa={
        "riscv64": {
            # AUIPC rd, imm  → GEN_OP_LEA (PC-relative address calc).
            "asm":      '"auipc t0, 1"',
            "clobbers": '"t0"',
            "opcodes":  ["LEA"],
        },
    },
)

asm_probe_block(
    name="probe_rv_fence",
    per_isa={
        "riscv64": {
            # FENCE rw, rw → GEN_OP_FENCE.  FENCE.I requires the Zifencei
            # extension which rv64gc includes; it's not strictly needed
            # for opcode coverage here, so we stick with plain FENCE.
            "asm":      '"fence rw, rw"',
            "clobbers": '"memory"',
            "opcodes":  ["FENCE"],
        },
    },
)

asm_probe_block(
    name="probe_rv_xchg",
    per_isa={
        "riscv64": {
            # AMOSWAP.D rd, rs2, (rs1) → GEN_OP_XCHG.  Targets a fresh
            # stack slot so we do not perturb the arena.  rv64gc
            # includes the A extension so amoswap is always available.
            "asm":      (
                '"addi sp, sp, -16\\n\\t"\n'
                '    "li t1, 0xCAFE\\n\\t"\n'
                '    "amoswap.d t0, t1, (sp)\\n\\t"\n'
                '    "addi sp, sp, 16"'
            ),
            "clobbers": '"t0","t1","memory"',
            "opcodes":  ["XCHG"],
        },
    },
)

asm_probe_block(
    name="probe_rv_cmp",
    per_isa={
        "riscv64": {
            # SLT / SLTU / SLTI all → GEN_OP_CMP in the riscv mnemonic
            # table (RISC-V has no dedicated compare instruction; the
            # set-less-than family fills that role).
            "asm":      (
                '"slt   t0, t1, t2\\n\\t"\n'
                '    "sltu  t3, t4, t5\\n\\t"\n'
                '    "slti  a0, a1, 5"'
            ),
            "clobbers": '"t0","t3","a0"',
            "opcodes":  ["CMP"],
        },
    },
)

asm_probe_block(
    name="probe_rv_fp_madd_msub",
    per_isa={
        "riscv64": {
            "asm":      (
                '"fmadd.d ft0, ft1, ft2, ft3\\n\\t"\n'
                '    "fmsub.d ft4, ft5, ft6, ft7"'
            ),
            "clobbers": '"ft0","ft4"',
            "opcodes":  ["FP_MADD", "FP_MSUB"],
        },
    },
)

asm_probe_block(
    name="probe_rv_vec_arith",
    per_isa={
        "riscv64": {
            "asm":      (
                '".option push\\n\\t"\n'
                '    ".option arch, +v\\n\\t"\n'
                '    "vsetvli t0, zero, e64, m1, ta, ma\\n\\t"\n'
                '    "vadd.vv  v0,  v1,  v2\\n\\t"\n'
                '    "vsub.vv  v3,  v4,  v5\\n\\t"\n'
                '    "vmul.vv  v6,  v7,  v8\\n\\t"\n'
                '    "vfmadd.vv v9, v10, v11\\n\\t"\n'
                '    "vfmsub.vv v12, v13, v14\\n\\t"\n'
                '    ".option pop"'
            ),
            "clobbers": '"t0","memory"',
            "opcodes":  ["VEC_ADD", "VEC_SUB", "VEC_MUL", "VEC_MADD", "VEC_MSUB"],
        },
    },
)


# ---------------------------------------------------------------------------
# mipsel — completion
# ---------------------------------------------------------------------------

asm_probe_block(
    name="probe_mips_mov",
    per_isa={
        "mipsel": {
            # MIPS has no dedicated reg-to-reg MOV instruction.  The
            # canonical idiom `move $rd, $rs` assembles to either
            # `addu $rd, $zero, $rs` or `or $rd, $zero, $rs`.  Capstone 6
            # reports the underlying real opcode (MIPS_INS_OR for the
            # GAS default) rather than a synthetic MIPS_INS_MOVE pseudo,
            # so the hardware-honest expectation here is OR.
            "asm":      '"move $t0, $t1"',
            "clobbers": '"$t0"',
            "opcodes":  ["OR"],
        },
    },
)

asm_probe_block(
    name="probe_mips_neg_not",
    per_isa={
        "mipsel": {
            # NEGU is the GAS alias for `subu $rd, $zero, $rs`, NOT for
            # `nor $rd, $zero, $rs`.  Capstone 6 reports the underlying
            # real opcodes (MIPS_INS_SUBU and MIPS_INS_NOR) rather than
            # MIPS_INS_NEGU/MIPS_INS_NOT pseudos.  NOR with $zero is the
            # real encoding of NOT, so assert NOT rather than OR.
            "asm":      (
                '"negu $t0, $t1\\n\\t"\n'
                '    "not  $t2, $t3"'
            ),
            "clobbers": '"$t0","$t2"',
            "opcodes":  ["INT_SUB", "NOT"],
        },
    },
)

asm_probe_block(
    name="probe_mips_cmov",
    per_isa={
        "mipsel": {
            # MOVZ / MOVN → GEN_OP_CMOV.  Set $t1=0 first so MOVZ takes
            # the move side without disturbing observable state.
            "asm":      (
                '"li   $t1, 0\\n\\t"\n'
                '    "movz $t0, $t2, $t1\\n\\t"\n'
                '    "movn $t3, $t4, $t5"'
            ),
            "clobbers": '"$t0","$t1","$t3"',
            "opcodes":  ["CMOV"],
        },
    },
)

asm_probe_block(
    name="probe_mips_rotate",
    per_isa={
        "mipsel": {
            # ROTR / ROTRV → GEN_OP_ROR (MIPS32r2+).  No left-rotate;
            # MIPS doesn't define one as a separate insn id.
            "asm":      (
                '"rotr  $t0, $t1, 5\\n\\t"\n'
                '    "rotrv $t2, $t3, $t4"'
            ),
            "clobbers": '"$t0","$t2"',
            "opcodes":  ["ROR"],
        },
    },
)

asm_probe_block(
    name="probe_mips_fence",
    per_isa={
        "mipsel": {
            # SYNC → GEN_OP_FENCE.
            "asm":      '"sync"',
            "clobbers": '"memory"',
            "opcodes":  ["FENCE"],
        },
    },
)

asm_probe_block(
    name="probe_mips_cmp",
    per_isa={
        "mipsel": {
            # SLT / SLTU / SLTI → GEN_OP_CMP (same rationale as RISC-V).
            "asm":      (
                '"slt   $t0, $t1, $t2\\n\\t"\n'
                '    "sltu  $t3, $t4, $t5\\n\\t"\n'
                '    "slti  $t6, $t7, 5"'
            ),
            "clobbers": '"$t0","$t3","$t6"',
            "opcodes":  ["CMP"],
        },
    },
)

asm_probe_block(
    name="probe_mips_madd_msub",
    per_isa={
        "mipsel": {
            "asm":      (
                '"li    $t0, 3\\n\\t"\n'
                '    "li    $t1, 5\\n\\t"\n'
                '    "madd  $t0, $t1\\n\\t"\n'
                '    "msub  $t0, $t1"'
            ),
            "clobbers": '"$t0","$t1","hi","lo"',
            "opcodes":  ["INT_MADD", "INT_MSUB"],
        },
    },
)

asm_probe_block(
    name="probe_mips_fp_madd_msub",
    per_isa={
        "mipsel": {
            "asm":      (
                '"madd.d $f0, $f2, $f4, $f6\\n\\t"\n'
                '    "msub.d $f8, $f10, $f12, $f14"'
            ),
            "clobbers": '"$f0","$f8"',
            "opcodes":  ["FP_MADD", "FP_MSUB"],
        },
    },
)

asm_probe_block(
    name="probe_mips_xchg_nop_neg",
    per_isa={
        "mipsel": {
            "asm":      (
                '"addiu $sp, $sp, -8\\n\\t"\n'
                '    "sw    $zero, 0($sp)\\n\\t"\n'
                '    "li    $t1, 1\\n\\t"\n'
                '    "ll    $t0, 0($sp)\\n\\t"\n'
                '    "sc    $t1, 0($sp)\\n\\t"\n'
                '    "addiu $sp, $sp, 8\\n\\t"\n'
                '    "ssnop\\n\\t"\n'
                '    "abs   $t2, $t3"'
            ),
            "clobbers": '"$t0","$t1","$t2","memory"',
            "opcodes":  ["XCHG", "NOP", "INT_SUB"],
        },
    },
)

# probe_mips_lea: intentionally omitted.
#
# GenericOpcode LEA on MIPS is reachable only via the MIPS32r6/MIPS64r6
# AUIPC / ADDIUPC / ALUIPC instructions.  The default `mipsel-linux-gnu`
# toolchain targets mips32r2 (pre-r6), where these mnemonics do not
# assemble, so LEA is genuinely unreachable in this configuration.
# `lui` is the natural MIPS32r2 "address-builder upper-half" instruction
# but the mnemonic table classifies it as GEN_OP_MOV (covered by
# probe_mips_mov).  Promoting the build target to mips32r6 would unlock
# a LEA probe but breaks ABI compatibility with the qemu-user mipsel
# binary, so we accept this gap on this ISA.


# ===========================================================================
# Coverage probe registry
#
# `coverage_probes_for_isa(isa)` returns the list of registered probe
# block class names whose `supported_isas` includes `isa`.  The
# generator's `--coverage` mode uses this to ensure every probe gets
# scheduled at least once into the CFG.
# ===========================================================================

def coverage_probes_for_isa(isa: str) -> list[str]:
    """Return the names of every probe-style block (asm-only, zero
    memops, single successor) that supports `isa`.  Used by the
    generator's coverage mode to guarantee one of each runs.

    In addition to the auto-registered AsmProbe subclasses, we include
    a hand-picked set of "essential coverage" CodeBlocks whose
    classifications cannot be reproduced by inline-asm probes alone
    (e.g. helper-call branches, returns, and indirect jumps), so a single
    coverage trace also exercises those branch types.
    """
    out: list[str] = []
    for name, cls in _REGISTRY.items():
        # Probes are the auto-registered AsmProbe subclasses.  We
        # recognise them structurally rather than by name pattern so a
        # later rename of any probe doesn't silently exclude it.
        if cls.__name__.startswith("AsmProbe_") and isa in cls.supported_isas:
            out.append(name)

    # Hand-picked helper-call/RET/indirect-branch coverage.  These rely on the
    # compiler so they live as full CodeBlocks, not asm probes.
    extras = ["direct_call", "indirect_call", "indirect_jump"]
    for nm in extras:
        cls = _REGISTRY.get(nm)
        if cls is not None and isa in cls.supported_isas and nm not in out:
            out.append(nm)
    return sorted(out)


# ---------------------------------------------------------------------------
# File-scope helpers that must appear before `run()` in generated C++.
# The generator calls `collect_preamble_helpers(isa)` and splices the
# result into the preamble.  Keeping this in blocks.py means new helper
# code co-locates with the blocks that depend on it.
# ---------------------------------------------------------------------------

def collect_preamble_helpers(isa: str) -> str:
    """Return C++ source that must be emitted at file scope before
    the definition of ``run()``.  Every helper is unconditional so
    unused ones simply compile to nothing if the linker DCEs them; the
    marginal cost is negligible and keeps the generator simple."""
    helpers = []
    # `noinline` alone is not enough: at -O1 GCC's pure/const IPA pass
    # infers wptgen_leaf is a pure function of its argument and elides
    # the call when the result is unused.  `noipa` disables interprocedural
    # analysis entirely so every call site is preserved.
    helpers.append(
        f"extern \"C\" __attribute__((noinline, noipa))\n"
        f"uint64_t {HELPER_LEAF_NAME}(uint64_t x) {{\n"
        f"    return x ^ 0xA5A5A5A5A5A5A5A5ULL;\n"
        f"}}\n"
    )
    return "\n".join(helpers)
