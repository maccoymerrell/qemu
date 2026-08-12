"""CFG generator + assembly emitter + metadata writer.

Generates a program as a chain of diamonds:

    entry -> D0 -> join0 -> D1 -> join1 -> ... -> exit

Each diamond is:

            root (CondBranch)
           /     \
         T-chain  F-chain
           \     /
            join

Optional loop regions are explicit CFG cycles:

    loop_head -> loop_body -> loop_head
         \
          -> loop_exit -> next

This keeps one generated code block aligned with one guest basic block.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import random
from pathlib import Path
from typing import Any

from . import asm_blocks as B


@dataclasses.dataclass
class Node:
    block_id: int
    cls_name: str
    successors: list[int]
    branch_outcome: bool | None = None
    scratch_slots: list[int] = dataclasses.field(default_factory=list)
    branch_slot: int | None = None
    loop_iterations: int = 0


@dataclasses.dataclass
class CFG:
    nodes: list[Node]
    entry: int
    exit: int


def _build_diamond_cfg(seed: int, num_diamonds: int,
                       side_len_range: tuple[int, int],
                       isa: str = "x86_64",
                       coverage: bool = False,
                       hot_iters: int = 0,
                       stride_loops: bool = False) -> CFG:
    r = random.Random(hashlib.sha256(f"{seed}:cfg".encode()).digest())

    # StrideLoopHead is x86_64-only; ignore the request on other ISAs.
    use_stride = stride_loops and isa in B.StrideLoopHead.supported_isas

    straight_menu = [
        cls for cls in B.all_blocks()
        if cls.randomizable and isa in cls.supported_isas
    ]
    nodes: list[Node] = []

    def add(cls_name: str) -> int:
        bid = len(nodes)
        nodes.append(Node(block_id=bid, cls_name=cls_name, successors=[]))
        return bid

    def side_descriptors(length: int) -> list[str]:
        names = [r.choice(straight_menu).name for _ in range(length)]
        if hot_iters > 0 and names:
            names[length // 2] = "__loop_region__"
        return names

    # Stride-loop mode: dedicated minimal CFG so the StrideLoopHead's
    # two-successor self-loop doesn't tangle with the diamond chaining.
    if use_stride:
        entry_id = add(B.StrideLoopHead.name)
        # Pin loop_iterations to the static stride table depth.
        nodes[entry_id].loop_iterations = max(
            1, min(int(hot_iters), B.StrideLoopHead.STRIDE_DEPTH))
        exit_id = add(B.ExitBlock.name)
        nodes[entry_id].successors = [entry_id, exit_id]
        return CFG(nodes=nodes, entry=entry_id, exit=exit_id)

    def expand_side(descs: list[str]) -> tuple[int | None, int | None]:
        first_id: int | None = None
        tail_id: int | None = None
        for desc in descs:
            if desc == "__loop_region__":
                head_id = add(B.LoopHead.name)
                nodes[head_id].loop_iterations = max(1, int(hot_iters))
                body_id = add(B.LoopBody.name)
                exit_id = add(B.LoopExit.name)
                nodes[head_id].successors = [body_id, exit_id]
                nodes[body_id].successors = [head_id]
                seg_first = head_id
                seg_tail = exit_id
            else:
                seg_first = add(desc)
                seg_tail = seg_first
            if first_id is None:
                first_id = seg_first
            if tail_id is not None:
                nodes[tail_id].successors = [seg_first]
            tail_id = seg_tail
        return first_id, tail_id

    entry_id = add(r.choice(straight_menu).name)
    prev_join = entry_id

    if coverage:
        for pname in B.coverage_probes_for_isa(isa):
            new_id = add(pname)
            nodes[prev_join].successors = [new_id]
            prev_join = new_id

    for _ in range(num_diamonds):
        root_id = add(B.CondBranch.name)
        nodes[prev_join].successors = [root_id]

        t_first, t_tail = expand_side(side_descriptors(r.randint(*side_len_range)))
        f_first, f_tail = expand_side(side_descriptors(r.randint(*side_len_range)))
        join_id = add(r.choice(straight_menu).name)

        if t_tail is not None:
            nodes[t_tail].successors = [join_id]
        if f_tail is not None:
            nodes[f_tail].successors = [join_id]

        nodes[root_id].successors = [t_first or join_id, f_first or join_id]
        nodes[root_id].branch_outcome = bool(r.getrandbits(1))
        prev_join = join_id

    exit_id = add(B.ExitBlock.name)
    nodes[prev_join].successors = [exit_id]
    return CFG(nodes=nodes, entry=entry_id, exit=exit_id)


_BRANCH_REGION_PAD = 4
_ARENA_ALIGN_U64 = 64


def _assign_slots(cfg: CFG) -> int:
    cursor = _BRANCH_REGION_PAD

    for n in cfg.nodes:
        cls = B.get_block(n.cls_name)
        if cls.needs_branch_slot:
            n.branch_slot = cursor
            cursor += 1

    for n in cfg.nodes:
        cls = B.get_block(n.cls_name)
        if cls.scratch_slots == 0:
            continue
        cursor += 2
        n.scratch_slots = list(range(cursor, cursor + cls.scratch_slots))
        cursor += cls.scratch_slots

    rem = cursor % _ARENA_ALIGN_U64
    if rem:
        cursor += _ARENA_ALIGN_U64 - rem
    return cursor


def _plan_nodes(cfg: CFG, seed: int, isa: str
                ) -> tuple[list[B.BlockPlan], dict[int, int]]:
    plans: list[B.BlockPlan | None] = [None] * len(cfg.nodes)
    init_values: dict[int, int] = {}

    for n in cfg.nodes:
        cls = B.get_block(n.cls_name)
        rng = random.Random(hashlib.sha256(
            f"{seed}:{n.block_id}:plan".encode()
        ).digest())
        ctx = B.EmitCtx(
            block_id=n.block_id,
            isa=isa,
            branch_slot=n.branch_slot,
            scratch_slots=n.scratch_slots,
            arena_u64=0,
            successor_labels=[B.symbol_name(s) for s in n.successors],
            rng=rng,
            branch_outcome=n.branch_outcome,
            loop_iterations=n.loop_iterations,
        )
        plan = cls.plan(ctx)
        plan.successors = list(n.successors)
        plan.branch_pred = n.branch_outcome
        plans[n.block_id] = plan

        # Initialize arena slots from `memops` (the first-iter view)
        # and from every iteration of `per_iteration_memops` if set —
        # the latter is what stride probes use to populate slots that
        # are only read on later iterations.
        memop_iter = list(plan.memops)
        for iter_ops in plan.per_iteration_memops:
            memop_iter.extend(iter_ops)
        for m in memop_iter:
            span = max(1, (int(m.size) + 7) // 8)
            if m.kind == "load":
                for i in range(span):
                    init_values.setdefault(
                        m.arena_u64_index + i,
                        (int(m.data) >> (64 * i)) & ((1 << 64) - 1),
                    )
            else:
                for i in range(span):
                    init_values.setdefault(m.arena_u64_index + i, 0)

    return [p for p in plans if p is not None], init_values


def emit_source(cfg: CFG, plans: list[B.BlockPlan],
                init_values: dict[int, int], arena_u64: int,
                seed: int, isa: str, num_diamonds: int,
                marker: bool = False, sleep_probe: int = 0,
                start_marker: bool = True, end_marker: bool = True,
                devio_probe: int = 0) -> str:
    lines = [
        f"# GENERATED by champsim_tracer_genval; seed=0x{seed:x} isa={isa}",
        f"# num_blocks={len(cfg.nodes)} num_diamonds={num_diamonds}",
        ".section .data",
        ".balign 64",
        ".globl arena",
        ".type arena, @object",
        "arena:",
    ]
    for slot in range(arena_u64):
        lines.extend(B.emit_data_u64(isa, init_values.get(slot, 0)))
    lines.append(f".size arena, {arena_u64 * 8}")
    lines.append(".text")
    if isa.startswith("mips"):
        lines.append(".set noreorder")
    lines.extend(B.emit_helper_symbols(isa))
    lines.extend([
        ".globl _start",
        ".type _start, @function",
        "_start:",
    ])
    if marker:
        if start_marker:
            # Trace marker first thing in _start, so it executes in this
            # workload's own address space — the plugin opens + ASID-pins
            # the window here (trace_window=marker).  Lets the same
            # generated workload drive user- and system-mode runs.
            #
            # Omitted when the window is opened by INJECTION instead
            # (cst_attach pokes the same sequence into _start over ptrace,
            # which is how an unmodified binary is traced).  Leaving it out
            # is what makes such a run a real test of the injector: with no
            # marker in the image, nothing else can open the window.  The
            # probes below and the END marker are unaffected — they run
            # in-window either way.
            lines.extend(B.emit_trace_marker(isa))
        # One returning syscall in-window so the system-mode validator can
        # check the user->kernel->fall-through round trip.  No-op in user
        # mode (kernel not traced); harmless before the workload starts.
        lines.extend(B.emit_trace_syscall_probe(isa))
        # One syscall whose kernel path faults (sysinfo into a demand-zero
        # page) so a system-mode trace is guaranteed a fault excursion
        # nested inside a syscall excursion (syscall_fault_nesting check).
        lines.extend(B.emit_trace_fault_probe(isa))
        if devio_probe > 0:
            # Make the traced process drive a real device from inside its own
            # kernel path, so the seal walk's mid-flight-abandon case can
            # occur INSIDE the marker window (see emit_trace_devio_probe).
            lines.extend(B.emit_trace_devio_probe(isa, devio_probe))
        if sleep_probe > 0:
            # Hold the pinned window open on a frozen user clock while
            # the guest churns (see emit_trace_sleep_probe).
            lines.extend(B.emit_trace_sleep_probe(isa, sleep_probe))
    lines.extend(B.emit_entry_jump(isa, B.symbol_name(cfg.entry)))

    plan_by_id = {p.block_id: p for p in plans}
    for n in cfg.nodes:
        cls = B.get_block(n.cls_name)
        plan = plan_by_id[n.block_id]
        ctx = B.EmitCtx(
            block_id=n.block_id,
            isa=isa,
            branch_slot=n.branch_slot,
            scratch_slots=n.scratch_slots,
            arena_u64=arena_u64,
            successor_labels=[B.symbol_name(s) for s in n.successors],
            rng=random.Random(0),
            branch_outcome=n.branch_outcome,
            loop_iterations=n.loop_iterations,
        )
        body = cls.emit(plan, ctx).rstrip()
        # Pin each expected memop to the instruction(s) that perform it
        # (asm_blocks.annotate_memop_insn_seq): the .meta.json then
        # carries per-memop insn_seq ordinals, which the validator's
        # cp_memops check resolves to instruction PCs so the match is
        # strict on (kind, insn, value) instead of value-only.
        B.annotate_memop_insn_seq(plan, body, isa)
        if marker and end_marker and n.block_id == cfg.exit:
            # End marker right after the exit block's label (before the exit
            # syscall) so the plugin closes the trace window as the process
            # ends — the "or the program ends" stop for sub-budget runs.
            # end_marker=False builds the workload the dead-latch backstop
            # exists for: it opens its window, runs, and exits WITHOUT the
            # closing sequence, leaving the window for the latch to reap.
            blines = body.split("\n")
            label = f"{B.symbol_name(n.block_id)}:"
            if label in blines:
                idx = blines.index(label)
                blines[idx + 1:idx + 1] = B.emit_trace_marker_end(isa)
                body = "\n".join(blines)
        # Append `.size sym, .-sym` so the symbol's st_size is non-zero
        # in the linked ELF.  QEMU user-mode's lookup_symbolxx() does
        # bsearch using `addr >= st_value && addr < st_value+st_size`,
        # so a zero-sized symbol is invisible to qemu_plugin_insn_symbol
        # — and therefore to plugin features that rely on it (e.g.,
        # trace_window=symbol:name=...).
        sym = B.symbol_name(n.block_id)
        body = f"{body}\n.size {sym}, .-{sym}"
        lines.append(body)
    if isa.startswith("mips"):
        lines.append(".set reorder")
    return "\n".join(lines) + "\n"


@dataclasses.dataclass
class _SimState:
    loop_remaining: dict[int, int]

    def copy(self) -> "_SimState":
        return _SimState(dict(self.loop_remaining))


_LOOP_HEAD_CLASS_NAMES = (B.LoopHead.name, B.StrideLoopHead.name)


def _initial_state(cfg: CFG) -> _SimState:
    init: dict[int, int] = {}
    for n in cfg.nodes:
        if n.cls_name not in _LOOP_HEAD_CLASS_NAMES:
            continue
        # StrideLoopHead exits when its counter reaches 0 (== fires the
        # `je exit` branch on the iter that decrements the counter from
        # 1 to 0).  Without LoopBody as a separate node, the head runs
        # exactly loop_iterations times, so loop_remaining starts at
        # loop_iterations (no +1).  Plain LoopHead uses +1 because the
        # head fires once more than the body executes.
        bump = 0 if n.cls_name == B.StrideLoopHead.name else 1
        init[n.block_id] = n.loop_iterations + bump
    return _SimState(init)


def _branch_step(n: Node, state: _SimState) -> tuple[int, int, _SimState]:
    post = state.copy()
    if n.cls_name == B.CondBranch.name:
        cp_idx = 0 if n.branch_outcome else 1
        return cp_idx, 1 - cp_idx, post
    if n.cls_name in _LOOP_HEAD_CLASS_NAMES:
        # StrideLoopHead does its full body+counter+branch in ONE
        # execution per iter, so its loop_iterations matches the
        # number of times the template fires (no +1 needed for an
        # entering setup iter).  LoopHead uses +1 because its loop
        # body lives in a separate LoopBody block.
        bump = 0 if n.cls_name == B.StrideLoopHead.name else 1
        remaining = post.loop_remaining.get(
            n.block_id, n.loop_iterations + bump)
        if remaining > 1:
            post.loop_remaining[n.block_id] = remaining - 1
            return 0, 1, post
        if remaining > 0:
            post.loop_remaining[n.block_id] = remaining - 1
        return 1, 0, post
    raise RuntimeError(f"branch step requested for non-branch block {n.cls_name}")


def _walk_correct_path(cfg: CFG, max_steps: int = 100_000
                       ) -> tuple[list[int], list[dict[str, Any]]]:
    path: list[int] = []
    branches: list[dict[str, Any]] = []
    cur = cfg.entry
    state = _initial_state(cfg)
    for _ in range(max_steps):
        path.append(cur)
        n = cfg.nodes[cur]
        cls = B.get_block(n.cls_name)
        if cls.num_successors == 0:
            return path, branches
        if cls.num_successors == 1:
            cur = n.successors[0]
            continue
        cp_idx, wp_idx, post = _branch_step(n, state)
        # CFG-level self-loop branches (CP target == source block) have
        # no observable WP from the validator's POV: cp_pos in the
        # wp_chains check only advances when the block_id changes,
        # never within a run of the same block.  Skip emitting a
        # wrong_paths entry for these so the check can't fire on a
        # cp_pos that never reaches the corresponding cp_exec_index.
        if n.successors[cp_idx] != cur:
            branches.append({
                "cp_exec_index": len(path) - 1,
                "cp_block_id": cur,
                "wp_start_block": n.successors[wp_idx],
                "branch_outcome": (cp_idx == 0),
                "post_state": post.copy(),
            })
        cur = n.successors[cp_idx]
        state = post
    raise RuntimeError("CP walk did not terminate")


def _compute_wrong_path(cfg: CFG, start_block: int, state: _SimState,
                        max_blocks: int = 256) -> list[int]:
    chain: list[int] = []
    cur = start_block
    sim = state.copy()
    for _ in range(max_blocks):
        chain.append(cur)
        n = cfg.nodes[cur]
        cls = B.get_block(n.cls_name)
        if cls.num_successors == 0:
            break
        if cls.num_successors == 1:
            cur = n.successors[0]
            continue
        cp_idx, _wp_idx, post = _branch_step(n, sim)
        cur = n.successors[cp_idx]
        sim = post
    return chain


def build_metadata(cfg: CFG, plans: list[B.BlockPlan],
                   init_values: dict[int, int], arena_u64: int,
                   seed: int, isa: str,
                   hot_iters: int = 0) -> dict:
    plan_by_id = {p.block_id: p for p in plans}
    correct_path, branch_execs = _walk_correct_path(cfg)

    wrong_paths: dict[int, dict[str, Any]] = {}
    for branch in branch_execs:
        wp_chain = _compute_wrong_path(
            cfg,
            branch["wp_start_block"],
            branch["post_state"],
        )
        wrong_paths[branch["cp_exec_index"]] = {
            "cp_block_id": branch["cp_block_id"],
            "cp_exec_index": branch["cp_exec_index"],
            "wp_start_block": branch["wp_start_block"],
            "wp_chain": wp_chain,
            "branch_outcome": branch["branch_outcome"],
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
            "loop_iterations": n.loop_iterations,
            "scratch_slots": n.scratch_slots,
            "sym_name": B.symbol_name(n.block_id),
            "memops": [dataclasses.asdict(m) for m in plan.memops],
            "ordered_memops": plan.ordered_memops,
            "aggregate_fanout": plan.aggregate_fanout,
            "per_iteration_memops": [
                [dataclasses.asdict(m) for m in iter_ops]
                for iter_ops in plan.per_iteration_memops
            ],
            "reg_value_assertions": list(plan.reg_value_assertions),
            "memop_count_assertions": list(plan.memop_count_assertions),
            "indirect_wp_assertions": list(plan.indirect_wp_assertions),
            "coarse_opcodes": plan.coarse_opcodes,
            "terminal": plan.terminal,
            "asserted_branch_types": list(plan.asserted_branch_types),
            "asserted_opcodes": list(plan.asserted_opcodes),
            "asserted_cond_uncond_branch": plan.asserted_cond_uncond_branch,
            "expected_reg_sets": list(plan.expected_reg_sets),
            "asserted_dep_refines": list(plan.asserted_dep_refines),
            "expected_insns": list(plan.expected_insns),
        })

    return {
        "format_version": 1,
        "generator": "champsim_tracer_genval",
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
        "hot_iters": int(hot_iters),
        "blocks": nodes_out,
        "arena_init": {str(k): v for k, v in sorted(init_values.items())},
    }


@dataclasses.dataclass
class GenerateParams:
    seed: int
    isa: str
    num_diamonds: int = 8
    side_len_min: int = 2
    side_len_max: int = 4
    coverage: bool = False
    hot_iters: int = 0
    stride_loops: bool = False
    marker: bool = False
    # Emit the START marker itself.  False keeps the in-window probes and
    # the END marker but omits the opening sequence, for runs where
    # cst_attach injects it into the entry point over ptrace instead.
    start_marker: bool = True
    # Emit the END marker.  False builds a workload that opens its window
    # and exits without ever closing it — the deadlatch_test's subject.
    end_marker: bool = True
    # Seconds of nanosleep emitted right after the marker probes (0 =
    # none).  Marker-mode only; the churn test uses it to hold the
    # pinned window open while the guest's init rolls the ASID space.
    sleep_probe: int = 0
    # Number of write(1, ...) console writes emitted right after the fault
    # probe (0 = none).  Opt-in: it drives a real device from inside the
    # traced process's kernel path, which is the only way the per-execution
    # seal walk's mid-flight-abandon case can arise inside a marker window.
    devio_probe: int = 0


def generate(params: GenerateParams, out_dir: Path, prog_name: str
             ) -> tuple[Path, Path]:
    """Generate a .S source and a .meta.json file."""
    out_dir.mkdir(parents=True, exist_ok=True)
    if params.side_len_min < 1:
        raise ValueError("side_len_min must be >= 1 for assembly BB layout")

    cfg = _build_diamond_cfg(
        params.seed, params.num_diamonds,
        (params.side_len_min, params.side_len_max),
        isa=params.isa,
        coverage=params.coverage,
        hot_iters=params.hot_iters,
        stride_loops=params.stride_loops,
    )
    arena_u64 = _assign_slots(cfg)
    plans, init_values = _plan_nodes(cfg, params.seed, params.isa)
    source = emit_source(cfg, plans, init_values, arena_u64,
                         params.seed, params.isa, params.num_diamonds,
                         marker=params.marker,
                         sleep_probe=params.sleep_probe,
                         start_marker=params.start_marker,
                         end_marker=params.end_marker,
                         devio_probe=params.devio_probe)
    meta = build_metadata(cfg, plans, init_values, arena_u64,
                          params.seed, params.isa,
                          hot_iters=params.hot_iters)

    src_path = out_dir / f"{prog_name}.S"
    meta_path = out_dir / f"{prog_name}.meta.json"
    src_path.write_text(source)
    meta_path.write_text(json.dumps(meta, indent=2))
    return src_path, meta_path
