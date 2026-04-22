"""CFG generator + C++ emitter + metadata writer.

Generates a program as a chain of diamonds:

    entry → D0 → join0 → D1 → join1 → ... → exit

Each diamond is:

            root (CondBranch)
           /     \\
         T-chain  F-chain
           \\     /
            join

The root's outcome is baked into `arena[branch_slot]` at init time, so
each execution is fully deterministic.  The *other* side of the branch
is still a valid, reachable sequence of BBs — which is exactly the
wrong-path chain the plugin will emit.

Block IDs are dense integers; block 0 is the entry; the last block is
`exit`.  Labels in the emitted source are `L_blk_N` and ELF symbols are
`blk_N`.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import random
import struct
from pathlib import Path
from typing import Any

from . import blocks as B


# ---------------------------------------------------------------------------
# Graph IR
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class Node:
    block_id: int
    cls_name: str           # CodeBlock registry name
    successors: list[int]   # ordered; [taken, fallthrough] for 2-way
    branch_outcome: bool | None = None   # for 2-way only
    scratch_slots: list[int] = dataclasses.field(default_factory=list)
    branch_slot: int | None = None


@dataclasses.dataclass
class CFG:
    nodes: list[Node]
    entry: int
    exit: int


# ---------------------------------------------------------------------------
# Diamond generator
# ---------------------------------------------------------------------------

def _build_diamond_cfg(seed: int, num_diamonds: int,
                       side_len_range: tuple[int, int]) -> CFG:
    """Build a chain of `num_diamonds` diamonds plus entry and exit.

    Block layout inside each diamond:
      root   (CondBranch)
      T_0..T_{k-1}   (straight-line, various classes)
      F_0..F_{l-1}   (straight-line, various classes)
      join   (straight-line)
    """
    r = random.Random(hashlib.sha256(f"{seed}:cfg".encode()).digest())

    # Straight-line block menu (no terminal, no branching)
    straight_menu = [
        cls for cls in B.all_blocks()
        if cls.num_successors == 1 and cls.name != "exit"
    ]

    nodes: list[Node] = []

    def add(cls_name: str) -> int:
        bid = len(nodes)
        nodes.append(Node(block_id=bid, cls_name=cls_name, successors=[]))
        return bid

    # Entry block: a simple straight-line block to anchor symbol 0.
    entry_id = add(r.choice(straight_menu).name)

    prev_join = entry_id

    for _ in range(num_diamonds):
        root_id = add(B.CondBranch.name)
        nodes[prev_join].successors = [root_id]

        t_len = r.randint(*side_len_range)
        f_len = r.randint(*side_len_range)
        t_ids = [add(r.choice(straight_menu).name) for _ in range(t_len)]
        f_ids = [add(r.choice(straight_menu).name) for _ in range(f_len)]
        join_id = add(r.choice(straight_menu).name)

        # Wire T-chain
        for i, bid in enumerate(t_ids):
            nxt = t_ids[i + 1] if i + 1 < t_len else join_id
            nodes[bid].successors = [nxt]
        # Wire F-chain
        for i, bid in enumerate(f_ids):
            nxt = f_ids[i + 1] if i + 1 < f_len else join_id
            nodes[bid].successors = [nxt]

        # Wire root: [taken=T-chain head, fallthrough=F-chain head]
        t_head = t_ids[0] if t_ids else join_id
        f_head = f_ids[0] if f_ids else join_id
        nodes[root_id].successors = [t_head, f_head]
        nodes[root_id].branch_outcome = bool(r.getrandbits(1))

        prev_join = join_id

    exit_id = add(B.ExitBlock.name)
    nodes[prev_join].successors = [exit_id]
    nodes[exit_id].successors = []

    return CFG(nodes=nodes, entry=entry_id, exit=exit_id)


# ---------------------------------------------------------------------------
# Arena slot assignment
# ---------------------------------------------------------------------------

_BRANCH_REGION_PAD = 4   # leading guard slots
_ARENA_ALIGN_U64 = 64    # pad to this boundary


def _assign_slots(cfg: CFG) -> int:
    """Assign every node its branch slot (if 2-way) and scratch slots.

    Slots are disjoint across the whole program so wrong-path stores
    from one BB cannot corrupt the driver state of another.

    Returns total arena size in uint64_t units.
    """
    cursor = _BRANCH_REGION_PAD

    # Pass 1: branch slots for every 2-way block.
    for n in cfg.nodes:
        cls = B.get_block(n.cls_name)
        if cls.num_successors == 2:
            n.branch_slot = cursor
            cursor += 1

    # Pass 2: scratch slots per block.
    # Add a 2-slot gap between blocks so small off-by-one bugs on our
    # end produce loud failures rather than silent clobber.
    for n in cfg.nodes:
        cls = B.get_block(n.cls_name)
        if cls.scratch_slots == 0:
            continue
        cursor += 2
        n.scratch_slots = list(range(cursor, cursor + cls.scratch_slots))
        cursor += cls.scratch_slots

    # Round up to alignment
    rem = cursor % _ARENA_ALIGN_U64
    if rem:
        cursor += _ARENA_ALIGN_U64 - rem
    return cursor


# ---------------------------------------------------------------------------
# Planning: walk every node, produce BlockPlan, collect memops & init values
# ---------------------------------------------------------------------------

def _plan_nodes(cfg: CFG, seed: int, isa: str
                ) -> tuple[list[B.BlockPlan], dict[int, int]]:
    """Return (plans_by_id, init_values_u64)."""
    plans: list[B.BlockPlan | None] = [None] * len(cfg.nodes)
    init_values: dict[int, int] = {}

    for n in cfg.nodes:
        cls = B.get_block(n.cls_name)
        # Per-block deterministic sub-seed.
        sub = hashlib.sha256(
            f"{seed}:{n.block_id}:plan".encode()
        ).digest()
        rng = random.Random(sub)

        # Successor labels are placeholder strings the emitter will
        # turn into goto targets.
        succ_labels = [B._label(s) for s in n.successors]

        ctx = B.EmitCtx(
            block_id=n.block_id,
            isa=isa,
            branch_slot=n.branch_slot,
            scratch_slots=n.scratch_slots,
            arena_u64=0,    # not needed at plan time
            successor_labels=succ_labels,
            rng=rng,
            branch_outcome=n.branch_outcome,
        )
        plan = cls.plan(ctx)
        plan.successors = list(n.successors)
        plan.branch_pred = n.branch_outcome
        plans[n.block_id] = plan

        # For every `load` memop, plant that value at the corresponding
        # arena slot at init time.  Stores don't need pre-planted values,
        # but we plant a recognisable pattern to make debugging easier.
        for m in plan.memops:
            if m.kind == "load":
                init_values.setdefault(m.arena_u64_index, m.data)
            else:
                init_values.setdefault(m.arena_u64_index,
                                        0xDEADBEEFCAFEBABE)

    return [p for p in plans if p is not None], init_values


# ---------------------------------------------------------------------------
# C++ source emission
# ---------------------------------------------------------------------------

_CPP_PREAMBLE = r"""/* GENERATED by wptrace_genval.  Do not edit by hand. */
/* seed={seed:#x}  isa={isa}  num_blocks={num_blocks}  num_diamonds={num_diamonds} */

typedef unsigned long long uint64_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef signed long long int64_t;
typedef signed int int32_t;
typedef signed short int16_t;
typedef signed char int8_t;
typedef unsigned long  size_t;

#define ARENA_U64 {arena_u64}

extern "C" uint64_t arena[ARENA_U64];
__attribute__((aligned(64)))
uint64_t arena[ARENA_U64];

static __attribute__((noinline))
void init_arena(void) {{
    /* Zero the entire arena, then plant the seeded values in-place.
       Explicit per-slot stores avoid memcpy() (we're -nostdlib) and
       C++'s refusal to accept sparse designated-initializer arrays. */
    for (size_t i = 0; i < ARENA_U64; i++) {{
        (*(volatile uint64_t*)&arena[i]) = 0;
    }}
{arena_init_body}
}}

static __attribute__((noinline, noreturn))
void run(void);

extern "C" __attribute__((noreturn))
void _start(void) {{
    init_arena();
    run();
    __builtin_unreachable();
}}

__attribute__((noinline, noreturn))
void run(void) {{
    goto {entry_label};
"""

_CPP_POSTAMBLE = "}\n"


def _format_init_array(init_values: dict[int, int], arena_u64: int) -> str:
    """Produce per-slot assignment statements for init_arena().

    Emitted inside init_arena() after the zero-fill loop.
    """
    lines = []
    for slot in sorted(init_values):
        val = init_values[slot]
        lines.append(
            f"    (*(volatile uint64_t*)&arena[{slot}]) "
            f"= 0x{val:016x}ULL;"
        )
    if not lines:
        lines.append("    (void)0;")
    return "\n".join(lines)


def emit_cpp(cfg: CFG, plans: list[B.BlockPlan],
             init_values: dict[int, int], arena_u64: int,
             seed: int, isa: str, num_diamonds: int) -> str:
    chunks: list[str] = []
    chunks.append(_CPP_PREAMBLE.format(
        seed=seed, isa=isa,
        num_blocks=len(cfg.nodes),
        num_diamonds=num_diamonds,
        arena_u64=arena_u64,
        arena_init_body=_format_init_array(init_values, arena_u64),
        entry_label=B._label(cfg.entry),
    ))

    plan_by_id = {p.block_id: p for p in plans}

    for n in cfg.nodes:
        cls = B.get_block(n.cls_name)
        plan = plan_by_id[n.block_id]
        succ_labels = [B._label(s) for s in n.successors]
        ctx = B.EmitCtx(
            block_id=n.block_id,
            isa=isa,
            branch_slot=n.branch_slot,
            scratch_slots=n.scratch_slots,
            arena_u64=arena_u64,
            successor_labels=succ_labels,
            rng=random.Random(0),   # unused at emit time
            branch_outcome=n.branch_outcome,
        )
        chunks.append(cls.emit(plan, ctx))

    chunks.append(_CPP_POSTAMBLE)
    return "".join(chunks)


# ---------------------------------------------------------------------------
# Metadata emission
# ---------------------------------------------------------------------------

def _compute_correct_path(cfg: CFG, max_steps: int = 100_000) -> list[int]:
    """Walk the CFG starting from entry, following the planted branch
    outcome at every 2-way block, until we hit the exit block.
    """
    path: list[int] = []
    cur = cfg.entry
    for _ in range(max_steps):
        path.append(cur)
        n = cfg.nodes[cur]
        cls = B.get_block(n.cls_name)
        if cls.num_successors == 0:
            return path
        if cls.num_successors == 1:
            cur = n.successors[0]
        else:
            # branch_outcome == True -> taken -> successors[0]
            cur = n.successors[0 if n.branch_outcome else 1]
    raise RuntimeError("CP walk did not terminate")


def _compute_wrong_path(cfg: CFG, cp_block: int, max_depth: int = 64
                        ) -> list[int]:
    """For a 2-way `cp_block`, compute the WP chain the plugin would
    naturally emit: start at the *un-taken* successor and follow edges
    naturally (using the same deterministic branch outcomes our runtime
    uses) for up to `max_depth` blocks, or until we hit the exit.
    """
    n = cfg.nodes[cp_block]
    if B.get_block(n.cls_name).num_successors != 2:
        return []
    # Opposite of the CP-chosen successor
    wp_start = n.successors[1 if n.branch_outcome else 0]
    chain = []
    cur = wp_start
    for _ in range(max_depth):
        chain.append(cur)
        nn = cfg.nodes[cur]
        cls = B.get_block(nn.cls_name)
        if cls.num_successors == 0:
            # Exit block — plugin stops WP here (syscall).
            break
        if cls.num_successors == 1:
            cur = nn.successors[0]
        else:
            cur = nn.successors[0 if nn.branch_outcome else 1]
    return chain


def build_metadata(cfg: CFG, plans: list[B.BlockPlan],
                   init_values: dict[int, int], arena_u64: int,
                   seed: int, isa: str) -> dict:
    plan_by_id = {p.block_id: p for p in plans}
    correct_path = _compute_correct_path(cfg)

    wrong_paths: dict[int, dict[str, Any]] = {}
    for exec_idx, bid in enumerate(correct_path):
        n = cfg.nodes[bid]
        cls = B.get_block(n.cls_name)
        if cls.num_successors == 2:
            wp_chain = _compute_wrong_path(cfg, bid)
            wrong_paths[exec_idx] = {
                "cp_block_id": bid,
                "cp_exec_index": exec_idx,
                "wp_start_block": wp_chain[0] if wp_chain else None,
                "wp_chain": wp_chain,
                "branch_outcome": n.branch_outcome,
            }

    nodes_out = []
    for n in cfg.nodes:
        plan = plan_by_id[n.block_id]
        nodes_out.append({
            "block_id": n.block_id,
            "class": n.cls_name,
            "successors": n.successors,
            "branch_slot": n.branch_slot,
            "branch_outcome": n.branch_outcome,
            "scratch_slots": n.scratch_slots,
            "sym_name": f"blk_{n.block_id}",
            "memops": [dataclasses.asdict(m) for m in plan.memops],
            "ordered_memops": plan.ordered_memops,
            "coarse_opcodes": plan.coarse_opcodes,
            "terminal": plan.terminal,
        })

    return {
        "format_version": 1,
        "generator": "wptrace_genval",
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "seed": seed,
        "isa": isa,
        "arena": {
            "symbol": "arena",
            "u64_count": arena_u64,
            "byte_size": arena_u64 * 8,
        },
        "entry_block": cfg.entry,
        "exit_block": cfg.exit,
        "correct_path": correct_path,
        "wrong_paths": wrong_paths,
        "blocks": nodes_out,
        # Per-slot planted init values (for reference; the values also
        # appear in the memops themselves).
        "arena_init": {str(k): v for k, v in sorted(init_values.items())},
    }


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class GenerateParams:
    seed: int
    isa: str
    num_diamonds: int = 8
    side_len_min: int = 2
    side_len_max: int = 4


def generate(params: GenerateParams, out_dir: Path, prog_name: str
             ) -> tuple[Path, Path]:
    """Generate a .cpp source and a .meta.json file.

    Returns (cpp_path, meta_path).
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    cfg = _build_diamond_cfg(
        params.seed, params.num_diamonds,
        (params.side_len_min, params.side_len_max),
    )
    arena_u64 = _assign_slots(cfg)
    plans, init_values = _plan_nodes(cfg, params.seed, params.isa)
    source = emit_cpp(cfg, plans, init_values, arena_u64,
                      params.seed, params.isa, params.num_diamonds)
    meta = build_metadata(cfg, plans, init_values, arena_u64,
                          params.seed, params.isa)

    cpp_path = out_dir / f"{prog_name}.cpp"
    meta_path = out_dir / f"{prog_name}.meta.json"
    cpp_path.write_text(source)
    meta_path.write_text(json.dumps(meta, indent=2))
    return cpp_path, meta_path
