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

def _collect_block_symbols(binary) -> dict[str, tuple[int, int]]:
    """Return { sym_name: (address, size) } for all `blk_*` symbols.

    LIEF's Symbol.size is often 0 for labels placed via inline asm; we
    treat size 0 as "span up to next block symbol".
    """
    out: dict[str, tuple[int, int]] = {}
    for sym in binary.symbols:
        name = sym.name
        if not name or not name.startswith("blk_"):
            continue
        out[name] = (int(sym.value), int(sym.size))
    return out


def _section_for_pc(binary, pc: int):
    import lief
    for sec in binary.sections:
        base = int(sec.virtual_address)
        size = int(sec.size)
        if base <= pc < base + size and (
            int(sec.flags) & int(lief.ELF.SECTION_FLAGS.EXECINSTR)
        ):
            return sec
    return None


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze(binary_path: Path, meta_path: Path) -> Path:
    """Disassemble `binary_path`, annotate `meta_path` with ground
    truth, and write it back in place.  Returns `meta_path`.
    """
    meta = json.loads(meta_path.read_text())
    classifier = get_classifier()
    binary, md, _ = classifier.make_capstone(binary_path)
    isa = meta["isa"]

    syms = _collect_block_symbols(binary)

    # Order blocks by start address so we can derive "end" from next.
    by_addr = sorted(syms.items(), key=lambda kv: kv[1][0])

    # Build a quick "next symbol address" lookup for every blk_ sym.
    next_addr: dict[str, int] = {}
    for i, (name, (addr, _)) in enumerate(by_addr):
        if i + 1 < len(by_addr):
            next_addr[name] = by_addr[i + 1][1][0]
        else:
            # Last block: span to end of containing section
            sec = _section_for_pc(binary, addr)
            if sec is None:
                raise RuntimeError(
                    f"symbol {name} @0x{addr:x} not in an exec section"
                )
            next_addr[name] = int(sec.virtual_address) + int(sec.size)

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

        gt = BlockGT(
            block_id=node["block_id"],
            sym_name=sym,
            start_pc=start,
            end_pc=end,
            n_insns=len(insns),
            insns=insns,
        )
        node["ground_truth"] = {
            "start_pc": gt.start_pc,
            "end_pc": gt.end_pc,
            "n_insns": gt.n_insns,
            "insns": [asdict(i) for i in gt.insns],
        }

    meta_path.write_text(json.dumps(meta, indent=2))
    return meta_path
