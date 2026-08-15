"""Analyzer: disassemble a compiled binary and annotate the metadata
with the ground-truth opcode sequence for every generator block.

This is what turns loose expectations ("INT_ADD count ~= 1") into exact
assertions ("instruction 3 of template blk_7 is INT_ADD; its raw bytes
are 48 01 d8; the opcode in the trace's template must match").

Workflow:
  1. Parse the ELF with LIEF; locate the symbol `blk_N` for every
     generator block (the generator's `_emit_label` inlined a `.globl
     blk_N` directive).
  2. For each block symbol, find the next symbol in address order — the
     block's bytes span `[addr, next_addr)`.
  3. Disassemble that byte range with Capstone.
  4. Classify every instruction via `classify.Classifier`.
  5. Write the result back into the metadata as
     `blocks[N]["ground_truth"]`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path

from .classify import get_classifier
from . import asm_blocks as _B


_HEX_TARGET_RE = None


def _detect_loop_body_n_insns(insns: list, isa: str = "") -> tuple[int, int]:
    """Return ``(body_n, through_loop_n)`` for the inner loop of a
    block, or ``(0, 0)`` if no backedge is present.

    * ``body_n``: insns from the loop target index through the
      backedge inclusive — one iteration's body.
    * ``through_loop_n``: insns from block start through the backedge
      inclusive.  Insns AFTER the backedge in the same block (e.g.
      a post-loop store) are *not* part of any loop iteration.  The
      QEMU plugin attributes those tail insns to a fresh TB starting
      at the post-loop PC, which extends into the next block, so the
      validator credits the post-loop tail to the *next* block in
      the chain rather than to the loop block itself.

    On MIPS the conditional branch has a one-insn delay slot which
    is executed every iteration — including on the iteration that
    falls through to the post-loop tail.  The plugin's per-BB
    counting attributes the delay-slot insn to the loop iteration's
    BB, so body and through are extended by one when the ISA is a
    MIPS variant and a delay-slot insn is present.
    """
    import re
    global _HEX_TARGET_RE
    if _HEX_TARGET_RE is None:
        _HEX_TARGET_RE = re.compile(r"0x[0-9a-fA-F]+")

    has_delay_slot = isa.startswith("mips")
    pc_to_idx = {ins.pc: i for i, ins in enumerate(insns)}
    for j, ins in enumerate(insns):
        if ins.branch_type not in ("BRANCH_DIRECT_JUMP",
                                    "BRANCH_COND_DIRECT"):
            continue
        matches = _HEX_TARGET_RE.findall(ins.op_str)
        if not matches:
            continue
        try:
            target = int(matches[-1], 16)
        except ValueError:
            continue
        if target >= ins.pc:
            continue
        k = pc_to_idx.get(target)
        if k is None or k > j:
            continue
        body = j - k + 1
        through = j + 1
        if has_delay_slot and j + 1 < len(insns):
            body += 1
            through += 1
        return body, through
    return 0, 0


@dataclass
class InsnGT:
    pc: int
    size: int
    mnemonic: str
    op_str: str
    gen_op: str
    branch_type: str
    flags: str
    raw_bytes_hex: str


@dataclass
class BlockGT:
    block_id: int
    sym_name: str
    start_pc: int
    end_pc: int
    n_insns: int
    insns: list[InsnGT]


# ---------------------------------------------------------------------------
# Symbol table helpers
# ---------------------------------------------------------------------------

def _collect_block_symbols(binary,
                           wanted: "set[str] | None" = None
                           ) -> dict[str, tuple[int, int]]:
    """Return { sym_name: (address, size) } for the generator's block
    symbols.

    @wanted names the exact symbols to collect — the metadata's own
    ``sym_name`` set.  That is what lets a namespaced image (the
    multi-thread oracle links N bodies whose symbols carry a ``tK_``
    prefix) be analyzed with the same code path: the meta already knows
    which names are its own.  Without it the collector falls back to the
    single-thread convention, every ``blk_*`` symbol in the image.

    LIEF's Symbol.size is often 0 for labels placed via inline asm; we
    treat size 0 as "span up to next block symbol".
    """
    out: dict[str, tuple[int, int]] = {}
    for sym in binary.symbols:
        name = sym.name
        if not name:
            continue
        if wanted is not None:
            if name not in wanted:
                continue
        elif not name.startswith("blk_"):
            continue
        out[name] = (int(sym.value), int(sym.size))
    return out


def _section_for_pc(binary, pc: int):
    import lief
    if hasattr(lief.ELF, "SECTION_FLAGS"):
        exec_flag = int(lief.ELF.SECTION_FLAGS.EXECINSTR)
    else:
        exec_flag = int(lief.ELF.Section.FLAGS.EXECINSTR)
    for sec in binary.sections:
        base = int(sec.virtual_address)
        size = int(sec.size)
        if base <= pc < base + size and (int(sec.flags) & exec_flag):
            return sec
    return None


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze(binary_path: Path, meta_path: Path) -> Path:
    """Disassemble `binary_path`, annotate `meta_path` with ground
    truth, and write it back in place.  Returns `meta_path`.

    A metadata file that carries ``mt_sym_prefix`` describes one thread of
    a multi-thread stitched image: its block and helper symbols were
    namespaced at link time, so the lookups below are driven by the
    metadata's own names rather than the bare single-thread convention.
    """
    meta = json.loads(meta_path.read_text())
    classifier = get_classifier()
    binary, md, _ = classifier.make_capstone(binary_path)
    isa = meta["isa"]
    sym_prefix = str(meta.get("mt_sym_prefix", "") or "")

    wanted = {b["sym_name"] for b in meta["blocks"] if b.get("sym_name")}
    syms = _collect_block_symbols(binary, wanted or None)

    # For computing each block's end_pc we need the *next address that
    # belongs to a different function/symbol*, not just the next blk_
    # label.  Otherwise, when a libgcc helper (e.g. __floatdidf,
    # __fixdfdi, __mulsf3) is laid out between two blk_ symbols, its
    # PCs would be misattributed to the preceding block — which then
    # corrupts the PcMap and produces spurious cp_execution_order
    # errors when the trace executes that helper.
    all_addrs: list[int] = []
    for sym in binary.symbols:
        if not sym.name:
            continue
        # Skip ELF "mapping symbols" — `$a`, `$t`, `$d` on AArch64
        # mark instruction/data boundaries; `$x...` on RISC-V marks
        # arch-switch points emitted by GAS for `.option arch, +ext`
        # constructs.  Mapping symbols are not real function/data
        # symbols and would shorten our block spans incorrectly
        # (e.g. a `$xrv64..._zicbop...` symbol planted at the end of
        # a Zicbop probe would cut the trailer branch out of the
        # block's pc range).
        if sym.name.startswith("$"):
            continue
        a = int(sym.value)
        if a > 0:
            all_addrs.append(a)
    all_addrs = sorted(set(all_addrs))

    import bisect as _bisect
    def _next_addr_after(addr: int, sec_end: int) -> int:
        i = _bisect.bisect_right(all_addrs, addr)
        return all_addrs[i] if i < len(all_addrs) and all_addrs[i] < sec_end else sec_end

    next_addr: dict[str, int] = {}
    for name, (addr, _sz) in syms.items():
        sec = _section_for_pc(binary, addr)
        if sec is None:
            raise RuntimeError(
                f"symbol {name} @0x{addr:x} not in an exec section"
            )
        sec_end = int(sec.virtual_address) + int(sec.size)
        next_addr[name] = _next_addr_after(addr, sec_end)

    # Annotate each block in metadata
    for node in meta["blocks"]:
        sym = node["sym_name"]
        if sym not in syms:
            # Might happen for blocks whose label was stripped.  We
            # report and continue; the validator will flag the miss.
            node["ground_truth"] = None
            continue
        start, _ = syms[sym]
        end = next_addr[sym]

        sec = _section_for_pc(binary, start)
        if sec is None:
            node["ground_truth"] = None
            continue
        sec_base = int(sec.virtual_address)
        data = bytes(sec.content)
        slice_ = data[start - sec_base: end - sec_base]

        insns: list[InsnGT] = []
        for ins in md.disasm(slice_, start):
            cls_tup = classifier.classify(isa, ins.id)
            gen_op, branch, flags = (
                cls_tup if cls_tup is not None
                else ("UNKNOWN", "BRANCH_NONE", "MF_NONE")
            )
            insns.append(InsnGT(
                pc=ins.address,
                size=ins.size,
                mnemonic=ins.mnemonic,
                op_str=ins.op_str,
                gen_op=gen_op,
                branch_type=branch,
                flags=flags,
                raw_bytes_hex=bytes(ins.bytes).hex(),
            ))
            # Exit blocks end at the syscall/hlt — the linker may place
            # padding/unrelated stubs after them that we must not count
            # as part of this block's disassembly.
            if (not node.get("successors")
                    and ins.mnemonic in ("syscall", "hlt", "ud2")):
                end = ins.address + ins.size
                break

        gt = BlockGT(
            block_id=node["block_id"],
            sym_name=sym,
            start_pc=start,
            end_pc=end,
            n_insns=len(insns),
            insns=insns,
        )
        gt_dict = {
            "start_pc": gt.start_pc,
            "end_pc": gt.end_pc,
            "n_insns": gt.n_insns,
            "insns": [asdict(i) for i in gt.insns],
        }
        # Detect inner loop span via the first backward-targeting
        # branch within this block.  Used by the WP-chain validator
        # to compute the runtime-expanded instruction cost of blocks
        # that contain loops (e.g. hot_loop), since the plugin's
        # WP instruction budget counts each iteration's body
        # separately while the static disassembly counts it once.
        loop_body_n_insns, loop_through_n_insns = (
            _detect_loop_body_n_insns(insns, isa=isa))
        if loop_body_n_insns > 0:
            gt_dict["loop_body_n_insns"] = loop_body_n_insns
            gt_dict["loop_through_n_insns"] = loop_through_n_insns
        node["ground_truth"] = gt_dict

        # Dense author-intent annotation: for single-true-BB block classes
        # that opt in (`auto_annotate`), record the generator's intended
        # GenericOpcode / BranchType for every emitted machine instruction.
        # Applied here — not at generate time — because the exact
        # machine-instruction sequence (pseudo expansions resolved by the
        # assembler) is only known once the binary is disassembled.  Hand-
        # authored coverage probes already carry `expected_insns` and are
        # left untouched.
        try:
            cls = _B.get_block(node.get("class", ""))
        except KeyError:
            cls = None
        if cls is not None and getattr(cls, "auto_annotate", False):
            _B.annotate_expected_insns(node, isa)

    # Record the leaf-helper insn count for ``direct_call`` /
    # ``indirect_call`` blocks.  The DirectCall/IndirectCall block
    # classes emit ``call wptgen_leaf`` (a small XOR/return stub
    # defined at file scope).  The leaf's instructions are executed
    # by QEMU and counted toward the plugin's WP instruction budget,
    # but since the leaf has no ``blk_*`` label it would otherwise be
    # invisible to the validator.  Recording its insn count here lets
    # the validator add ``helper_leaf_n_insns`` to the runtime cost
    # of each direct_call / indirect_call visit when computing the
    # WP-budget trim point.
    leaf_n = 0
    leaf_name = f"{sym_prefix}wptgen_leaf"
    for sym in binary.symbols:
        if sym.name == leaf_name:
            leaf_addr = int(sym.value)
            leaf_size = int(sym.size)
            sec = _section_for_pc(binary, leaf_addr)
            if sec is None:
                break
            sec_end = int(sec.virtual_address) + int(sec.size)
            if leaf_size <= 0:
                leaf_size = _next_addr_after(leaf_addr, sec_end) - leaf_addr
            sec_offset = leaf_addr - int(sec.virtual_address)
            sec_bytes = bytes(sec.content)[sec_offset:sec_offset + leaf_size]
            leaf_n = sum(1 for _ in md.disasm(sec_bytes, leaf_addr))
            break
    if leaf_n > 0:
        meta["helper_leaf_n_insns"] = leaf_n

    meta_path.write_text(json.dumps(meta, indent=2))
    return meta_path
