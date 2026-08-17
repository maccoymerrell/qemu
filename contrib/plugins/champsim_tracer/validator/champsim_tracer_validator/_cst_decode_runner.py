"""Compat shim that wraps the C++ ``cst_decode`` binary.

The validator was originally written against an in-process
``champsim_tracer_decode`` Python module:
``decode_champsim_tracer(path)`` returned ``(meta, templates,
entries)`` with rich Python objects.  After the C++ port the Python
decoder is gone — the source of truth is the ``cst_decode`` binary,
with its ``--format=legacy`` mode emitting the byte-identical text
that the Python renderer used to produce.

This module subprocess-runs ``cst_decode --format=legacy`` and parses
its stdout back into the same Python shapes the validator expects.
The text format is stable (covered by the byte-identical regression
test in the C++ tooling), so the parser only needs to handle the
fixed prose grammar of the META / ENCODINGS / TEMPLATES / BODY
sections.

Public surface (matches the old ``champsim_tracer_decode``):

    decode_champsim_tracer(path) -> (meta, templates, entries)
    iter_decode_champsim_tracer(path) -> (meta, templates, iterator)
    DynParam dataclass with .type_name, .value, .data_lo, .data_hi,
        .data, .data_size, .insn_index
    OPCODE_NAMES, BRANCH_NAMES, REG_NAMES_DEFAULT
    build_reg_names()

Locating the binary: a checked-in ``CST_DECODE`` env var, a peer in
``$PATH``, or ``../../build/contrib/plugins/cst_decode`` relative to
this file (the canonical in-tree build location).
"""

from __future__ import annotations

import bisect
import dataclasses
import os
import pickle
import random
import re
import shutil
import subprocess
import sys
import tempfile
import types
import weakref
from array import array
from collections.abc import Sequence
from pathlib import Path
from typing import Iterator

_HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Validator-side id -> name vocabulary.  NOT a decode fallback: a
# trace is self-describing and _parse_full reads its embedded
# encoding maps unconditionally.  These tables are only the
# validator's own knowledge of the id space, used to phrase report
# strings / build expected sets when no trace is in hand.  They must
# mirror enum GenericOpcode / BranchType in
# champsim_tracer_generic_ids.h (GEN_OP_/BRANCH_ prefix stripped).
# ---------------------------------------------------------------------------

OPCODE_NAMES = {
    0: "UNKNOWN", 1: "INT_ADD", 2: "INT_SUB", 3: "INT_MUL", 4: "INT_DIV",
    5: "AND", 6: "OR", 7: "XOR", 8: "NOT",
    9: "SHL", 10: "SHR", 11: "ROL", 12: "ROR", 13: "BITMANIP",
    14: "MOV", 15: "LOAD", 16: "STORE", 17: "PUSH", 18: "POP",
    19: "LEA", 20: "MOVSX", 21: "MOVZX", 22: "XCHG",
    23: "CMP", 24: "TEST", 25: "BRANCH", 26: "RET",
    27: "FP_ADD", 28: "FP_SUB", 29: "FP_MUL", 30: "FP_DIV", 31: "FP_SQRT",
    32: "FP_MOV", 33: "FP_CVT", 34: "FP_CMP",
    35: "VEC_ADD", 36: "VEC_SUB", 37: "VEC_MUL", 38: "VEC_DIV",
    39: "VEC_SQRT", 40: "VEC_MOV", 41: "VEC_LOAD", 42: "VEC_STORE",
    43: "VEC_SHUF", 44: "VEC_LOGIC",
    45: "NOP", 46: "SYSCALL", 47: "FENCE",
    48: "CMOV", 49: "SETCC", 50: "NEG", 51: "INC", 52: "DEC",
    53: "INT_MADD", 54: "INT_MSUB",
    55: "FP_MADD", 56: "FP_MSUB",
    57: "VEC_MADD", 58: "VEC_MSUB",
    59: "PREFETCH", 60: "CACHE_FLUSH", 61: "TLB_FLUSH",
    62: "VEC_PREFETCH",
    63: "INT_ALU_SHORT", 64: "INT_ALU_LONG", 65: "FP_ALU_SHORT",
    66: "FP_ALU_LONG", 67: "VEC_ALU_SHORT", 68: "VEC_ALU_LONG",
}

BRANCH_NAMES = {
    0: "NONE",
    1: "DIRECT_JUMP", 2: "INDIRECT_JUMP",
    3: "RETURN", 4: "SYSCALL", 5: "COND_DIRECT",
    6: "REP", 7: "DIRECT_CALL", 8: "INDIRECT_CALL",
}

# No field-ID table lives here.  This module reads the textual output of
# `cst_decode --format=legacy`, which has already resolved every field by
# NAME through the trace's own field_id encoding map; a numeric mirror of
# champsim_tracer.h would be a second, silently-diverging source of truth.
# (One used to sit here, still describing a 16-slot layout with EXTRA_*
# overflow escapes that the format has not had for a long time.)


def build_reg_names() -> dict[int, str]:
    """Minimal fallback reg-id → name table.

    The authoritative GenericRegId → name mapping for any given trace
    lives in that trace's ENCODINGS section (parsed into
    `meta["encoding_maps"]["reg"]`).  Validator code should pull names
    from there, not from this fallback — see the static-reg-set check
    in `validator.py`.  This dict is kept solely so legacy call sites
    that pre-date the per-trace encoding-map plumbing have something
    to return; new code should reach for the trace's own map.
    """
    return {0: "REG_NONE"}


REG_NAMES_DEFAULT = build_reg_names()


# ---------------------------------------------------------------------------
# DynParam — same shape the deleted decoder exposed.
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class DynParam:
    type_name: str
    value: int
    data: int = 0
    data_lo: int = 0
    data_hi: int = 0
    data_size: int = 0
    insn_index: int = -1


# ---------------------------------------------------------------------------
# Locating cst_decode.
# ---------------------------------------------------------------------------

def _find_cst_decode() -> Path:
    explicit = os.environ.get("CST_DECODE")
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return p
        raise FileNotFoundError(
            f"CST_DECODE={explicit!r} does not exist")
    on_path = shutil.which("cst_decode")
    if on_path:
        return Path(on_path)
    # _HERE = .../contrib/plugins/champsim_tracer/validator/champsim_tracer_validator
    # Walk five parents up to reach the QEMU source root, then descend
    # into the conventional build directory.
    in_tree = (_HERE.parent.parent.parent.parent.parent
               / "build" / "contrib" / "plugins" / "cst_decode")
    if in_tree.is_file():
        return in_tree.resolve()
    raise FileNotFoundError(
        "cst_decode binary not found; build it with "
        "`ninja contrib/plugins/cst_decode` from the QEMU build "
        "directory, or set CST_DECODE to its path.")


# ---------------------------------------------------------------------------
# Legacy-text parser.  Mirrors render_legacy() in cst_decode_main.cc.
# ---------------------------------------------------------------------------

_BB_HEAD_RE  = re.compile(
    r"^BB(\d+) \[pc=0x([0-9a-f]+), insns=(\d+), fall_through=0x([0-9a-f]+)"
    r"(, system)?\]$"
)
# Run-aggregated profile block (format §6), emitted as part of each BB.
_PROF_EXEC_RE = re.compile(
    r"^  profile: exec_cp=(\d+) exec_wp=(\d+)$"
)
_PROF_TGT_RE = re.compile(
    r"^  target\[(\d+)\]: pc=0x([0-9a-f]+) taken_cp=(\d+) nottaken_cp=(\d+) "
    r"taken_wp=(\d+) nottaken_wp=(\d+)$"
)
_PROF_INSN_RE = re.compile(r"^  insn\[(\d+)\] prof: (.*)$")
_INSN_RE = re.compile(
    r"^  \[(\d+)\] 0x([0-9a-f]+): op=(\S+)"
    r"(?: br=(\S+) cond=(\d))?"
    r" src=\[([^\]]*)\] dst=\[([^\]]*)\]"
    r"(?: imm=(-?\d+))?"
    r"( atomic)?"
    r"( lane_parallel)?"
    r"(?: bytes=([0-9a-f]*))?"
    r"(?:  prof: (.*))?$"
)
_ENTRY_HEAD_RE = re.compile(
    r"^ENTRY (\d+) thread=(\d+)(?: asid=(\d+))?(?: switch=(\d))?"
    # Executed range (epoch 0x1E, format spec 4.2a): present only on a
    # PARTIAL entry; the whole-block common line stays byte-identical.
    r"(?: fault_depth=(\d+))?(?: range=(\d+)\.\.(\d+))? template=BB(\d+)"
    # Terminal-branch direction/target (CST_FID_BRANCH_*), decoded directly
    # per branch-terminated entry.  ABSENT when the entry's range does not
    # reach the branch, when the writer flagged CST_BB_FLAG_BRANCH_UNRESOLVED,
    # or when the slot was never observed — absence IS "no outcome", never a
    # value to be defaulted.
    r"(?: branch=(taken|not-taken) target=0x([0-9a-f]+))?"
    # CST_BB_FLAG_THREAD_END: this entry is its (thread, asid) context's
    # final one — stamped by every close route (spec §4.2a/§5.6).
    r"( thread_end=1)?$"
)
_WP_HEAD_RE = re.compile(
    r"^  wp\[(\d+)\] template=BB(\d+) n_insns=(\d+)"
    # Executed range of the speculative block itself (spec 4.3): present
    # only when partial; groups 4/5.
    r"(?: range=(\d+)\.\.(\d+))?"
    # Terminal-branch direction/target (CST_FID_BRANCH_*), carried on WP
    # blocks too.  Non-capturing so group indices 1..5 are unchanged.
    r"(?: branch=(?:taken|not-taken) target=0x[0-9a-f]+)?$"
)
_LOAD_RE  = re.compile(
    r"^( +)insn\[(\d+)\] load=0x([0-9a-f]+)"
    r"(?::data=0x([0-9a-f]+):size=(\d+))?$"
)
_STORE_RE = re.compile(
    r"^( +)insn\[(\d+)\] store=0x([0-9a-f]+)"
    r"(?::data=0x([0-9a-f]+):size=(\d+))?$"
)
_REG_RE = re.compile(
    r"^( +)insn\[(\d+)\] (dst|src)\[(\d+)\] (\S+)=0x([0-9a-f]+)(?::w=(\d+))?$"
)
_MFLAGS_RE = re.compile(
    r"^( +)insn\[(\d+)\] 0x([0-9a-fA-F]+) \[([A-Z\-]+)\]$"
)
_LANE_RE = re.compile(
    r"^( +)insn\[(\d+)\] (src|dst|load|store)\[(\d+)\] 0x([0-9a-fA-F]+)$"
)
# Per-insn dep-mask continuation line under each template insn entry.
# Each "dst=" / "sd=" / "la=" / "sa=" group is independently optional.
_DEP_FAMILY_RE = re.compile(
    r"\b(dst|sd|la|sa)=((?:0x[0-9a-fA-F]+(?:,0x[0-9a-fA-F]+)*))"
)


def _make_dyn(type_name: str, value: int, insn_index: int,
              data_hex: str | None, size: str | None = None) -> DynParam:
    dp = DynParam(type_name=type_name, value=value, insn_index=insn_index)
    if data_hex:
        d = int(data_hex, 16)
        dp.data = d
        dp.data_lo = d & ((1 << 64) - 1)
        dp.data_hi = (d >> 64) & ((1 << 64) - 1)
        # Prefer the trace's captured access width (CST_FID_*_SIZE); fall
        # back to the value-magnitude estimate only for older traces whose
        # legacy output carries no ``:size=``.
        dp.data_size = int(size) if size is not None \
            else (d.bit_length() + 7) // 8
    return dp


def _make_reg_snap(insn_index: int, kind: str, operand_index: int,
                   reg_id: int, hexv: str, width: str | None = None) -> dict:
    v = int(hexv, 16)
    return {
        "insn_index": insn_index,
        "kind":       kind,
        "operand_index": operand_index,
        "reg_id":     reg_id,
        "value":      v,
        "lo":         v & ((1 << 64) - 1),
        "hi":         (v >> 64) & ((1 << 64) - 1),
        # Captured write byte width (CST_FID_DST_REG_WIDTH); None for
        # older traces whose legacy output carries no ``:w=``.
        "width_bytes": int(width) if width is not None else None,
    }


def _parse_meta_section(lines: list[str]) -> dict:
    meta: dict = {
        "encoding_maps": {},
        "stop_reason_names": {},
        "exception_names": {},
    }
    i = 0
    if lines[0] != "META" or lines[1] != "----":
        raise ValueError("expected META section header")
    i = 2
    while i < len(lines) and lines[i] != "":
        line = lines[i]
        if line.startswith("VERSION "):
            meta["magic"] = int(line[len("VERSION "):], 16)
        elif line.startswith("ISA "):
            meta["target_name"] = line[len("ISA "):]
        elif line.startswith("COMMAND "):
            meta["command"] = line[len("COMMAND "):]
        elif line == "COMMAND":
            meta["command"] = ""
        elif line.startswith("DATETIME "):
            meta["datetime"] = line[len("DATETIME "):]
        elif line == "DATETIME":
            meta["datetime"] = ""
        elif line.startswith("COMMENT "):
            meta["comment"] = line[len("COMMENT "):]
        elif line == "COMMENT":
            meta["comment"] = ""
        elif line.startswith("FLAGS"):
            tokens = line.split()[1:]
            meta["has_mem_data"] = "MEM_DATA" in tokens
            meta["has_reg_data"] = "REG_DATA" in tokens
            meta["flags"] = ((0x1 if meta["has_mem_data"] else 0) |
                             (0x2 if meta["has_reg_data"] else 0))
        elif line.startswith("START_INSN "):
            meta["start_insn"] = int(line[len("START_INSN "):])
        elif line.startswith("WARMUP_INSNS "):
            meta["warmup_insns"] = int(line[len("WARMUP_INSNS "):])
        elif line.startswith("TOTAL_TARGET_INSNS "):
            payload = line[len("TOTAL_TARGET_INSNS "):]
            meta["total_target_insns"] = int(payload.split()[0])
        i += 1
    return meta, i


def _parse_encodings(lines: list[str], i: int,
                     meta: dict) -> tuple[dict[str, dict[int, str]], int]:
    if lines[i] != "" or lines[i + 1] != "ENCODINGS" or lines[i + 2] != "---------":
        raise ValueError("expected ENCODINGS section header")
    i += 3
    encoding_maps: dict[str, dict[int, str]] = {}
    while i < len(lines) and lines[i] != "":
        head = lines[i]
        sp = head.find(" ")
        name = head[:sp]
        n = int(head[sp + 1:])
        i += 1
        m: dict[int, str] = {}
        for _ in range(n):
            parts = lines[i].strip().split(" ", 1)
            m[int(parts[0])] = parts[1] if len(parts) > 1 else ""
            i += 1
        if name == "WP_STOP_REASONS":
            meta["stop_reason_names"] = m
        elif name == "EXCEPTIONS":
            meta["exception_names"] = m
        else:
            encoding_maps[name] = m
    return encoding_maps, i


def _parse_templates(lines: list[str], i: int,
                     reg_name_to_id: dict[str, int],
                     opcode_to_id: dict[str, int],
                     branch_to_id: dict[str, int]) -> tuple[list[dict], int]:
    while i < len(lines) and lines[i] == "":
        i += 1
    if lines[i] != "TEMPLATES" or lines[i + 1] != "---------":
        raise ValueError("expected TEMPLATES section header")
    i += 2
    templates: list[dict] = []
    while i < len(lines) and lines[i] != "BODY":
        if lines[i] == "":
            i += 1
            continue
        m = _BB_HEAD_RE.match(lines[i])
        if not m:
            raise ValueError(f"bad template header: {lines[i]!r}")
        tid = int(m.group(1))
        start_pc = int(m.group(2), 16)
        n_insns = int(m.group(3))
        ft_pc = int(m.group(4), 16)
        is_system = m.group(5) is not None
        i += 1
        # Optional terminal-branch target list (header): "  targets:
        # 0x.. 0x..".  n_targets is implicit in the count of pcs.
        target_pcs: list[int] = []
        if i < len(lines) and lines[i].startswith("  targets:"):
            target_pcs = [int(x, 16)
                          for x in lines[i].split("targets:", 1)[1].split()]
            i += 1
        symbol = ""
        if i < len(lines) and lines[i].startswith("  symbol="):
            symbol = lines[i][len("  symbol="):]
            i += 1
        # Run-aggregated template profile block (format §6), emitted
        # as part of this BB.  Parse it so the validator can assert
        # the stats against the metadata (overlapping coverage).
        profile = {"exec_cp": 0, "exec_wp": 0,
                   "targets": [], "insns": {}}
        while i < len(lines):
            pe = _PROF_EXEC_RE.match(lines[i])
            if pe:
                profile["exec_cp"] = int(pe.group(1))
                profile["exec_wp"] = int(pe.group(2))
                i += 1
                continue
            pt = _PROF_TGT_RE.match(lines[i])
            if pt:
                profile["targets"].append({
                    "pc":          int(pt.group(2), 16),
                    "taken_cp":    int(pt.group(3)),
                    "nottaken_cp": int(pt.group(4)),
                    "taken_wp":    int(pt.group(5)),
                    "nottaken_wp": int(pt.group(6)),
                })
                i += 1
                continue
            pi = _PROF_INSN_RE.match(lines[i])
            if pi:
                fields: dict = {}
                for tok in pi.group(2).split():
                    if "=" in tok:
                        k, v = tok.split("=", 1)
                        fields[k] = v
                profile["insns"][int(pi.group(1))] = fields
                i += 1
                continue
            break
        insns: list[dict] = []
        for _insn_idx in range(n_insns):
            mm = _INSN_RE.match(lines[i])
            if not mm:
                raise ValueError(f"bad insn line: {lines[i]!r}")
            br_name = mm.group(4)
            cond_str = mm.group(5)
            # Inline per-instruction profile (format §6) now rides on
            # the instruction's own line as `  prof: k=v k=v ...`.
            if mm.group(12):
                pf: dict = {}
                for tok in mm.group(12).split():
                    if "=" in tok:
                        k, v = tok.split("=", 1)
                        pf[k] = v
                profile["insns"][_insn_idx] = pf
            insn = {
                "pc": int(mm.group(2), 16),
                "opcode": opcode_to_id.get(mm.group(3), 0),
                "branch_type": branch_to_id.get(br_name, 0) if br_name else 0,
                "branch_conditional": (cond_str == "1") if cond_str else False,
                "src_regs": [reg_name_to_id.get(r, 0)
                             for r in mm.group(6).split(",") if r],
                "dst_regs": [reg_name_to_id.get(r, 0)
                             for r in mm.group(7).split(",") if r],
                "imm": int(mm.group(8)) if mm.group(8) is not None else None,
                "is_atomic": mm.group(9) is not None,
                "lane_parallel": mm.group(10) is not None,
                "n_loads": 0,
                "n_stores": 0,
                "raw_bytes": bytes.fromhex(mm.group(11) or ""),
                "dst_dep_mask": [],
                "store_data_dep_mask": [],
                "load_addr_dep_mask": [],
                "store_addr_dep_mask": [],
            }
            insns.append(insn)
            i += 1
            # Optional dep-mask continuation line.  Lives at the
            # next index; only consume it when the prefix matches.
            # n_loads / n_stores aren't carried on the legacy
            # template line — derive them from the address-mask
            # vector lengths (load_addr_dep_mask sized by
            # max_dep_loads, store_*_dep_mask by max_dep_stores).
            if (i < len(lines)
                    and lines[i].lstrip().startswith("deps:")):
                body = lines[i].split("deps:", 1)[1]
                fams = {"dst": "dst_dep_mask",
                        "sd":  "store_data_dep_mask",
                        "la":  "load_addr_dep_mask",
                        "sa":  "store_addr_dep_mask"}
                for key, vals in _DEP_FAMILY_RE.findall(body):
                    insn[fams[key]] = [int(v, 16) for v in vals.split(",")]
                insn["n_loads"]  = len(insn["load_addr_dep_mask"])
                insn["n_stores"] = max(len(insn["store_addr_dep_mask"]),
                                       len(insn["store_data_dep_mask"]))
                i += 1
        templates.append({
            "template_id": tid,
            "start_pc": start_pc,
            "n_insns": n_insns,
            "fall_through_pc": ft_pc,
            "is_system": is_system,
            "target_pcs": target_pcs,
            "symbol_name": symbol,
            "insns": insns,
            "profile": profile,
        })
    return templates, i


def _parse_observations(lines: list[str], i: int,
                        reg_name_to_id: dict[str, int]
                        ) -> tuple[list[DynParam], list[dict],
                                   list[dict], list[dict], int]:
    """Parse a CP or WP `cp:` / sub-block observation block.

    Returns (dyn_params, reg_snaps, metaflags, lane_masks, next_i).
    `lane_masks` is a list of
    ``{insn_index, family, slot_index, mask}`` dicts surfaced from
    the legacy decoder's `lanes:` section (per-execution lane FIDs).
    """
    dyn: list[DynParam] = []
    snaps: list[dict] = []
    mflags: list[dict] = []
    lanes: list[dict] = []
    if i >= len(lines):
        return dyn, snaps, mflags, lanes, i
    # `unchanged` sentinel: caller already consumed the prefix line.
    line = lines[i].strip()
    if line == "unchanged":
        return dyn, snaps, mflags, lanes, i + 1
    while i < len(lines):
        line = lines[i]
        if line == "memops:":
            i += 1
            while i < len(lines):
                ml = _LOAD_RE.match(lines[i])
                if ml:
                    dyn.append(_make_dyn("load", int(ml.group(3), 16),
                                          int(ml.group(2)), ml.group(4),
                                          ml.group(5)))
                    i += 1
                    continue
                ms = _STORE_RE.match(lines[i])
                if ms:
                    dyn.append(_make_dyn("store", int(ms.group(3), 16),
                                          int(ms.group(2)), ms.group(4),
                                          ms.group(5)))
                    i += 1
                    continue
                break
            continue
        if line == "regs:":
            i += 1
            while i < len(lines):
                mr = _REG_RE.match(lines[i])
                if not mr:
                    break
                snaps.append(_make_reg_snap(
                    int(mr.group(2)), mr.group(3),
                    int(mr.group(4)),
                    reg_name_to_id.get(mr.group(5), 0),
                    mr.group(6), mr.group(7)))
                i += 1
            continue
        if line == "metaflags:":
            i += 1
            while i < len(lines):
                mf = _MFLAGS_RE.match(lines[i])
                if not mf:
                    break
                mflags.append({
                    "insn_index": int(mf.group(2)),
                    "byte":       int(mf.group(3), 16),
                    "bits":       mf.group(4),
                })
                i += 1
            continue
        if line == "lanes:":
            i += 1
            while i < len(lines):
                ml = _LANE_RE.match(lines[i])
                if not ml:
                    break
                lanes.append({
                    "insn_index": int(ml.group(2)),
                    "family":     ml.group(3),
                    "slot_index": int(ml.group(4)),
                    "mask":       int(ml.group(5), 16),
                })
                i += 1
            continue
        break
    return dyn, snaps, mflags, lanes, i


def _body_start(lines, i: int) -> int:
    """Index of the first line after the ``BODY`` section header, or -1 when
    the decode has no body section at all."""
    while i < len(lines) and lines[i] == "":
        i += 1
    if i >= len(lines):
        return -1
    if lines[i] != "BODY" or lines[i + 1] != "----":
        raise ValueError("expected BODY section header")
    return i + 2


def _parse_entry_at(lines, i: int,
                    reg_name_to_id: dict[str, int]) -> tuple[dict, int]:
    """Parse the one ENTRY record whose head line sits at @i.

    Returns ``(entry, next_i)``.  An entry is self-contained -- it begins at
    its own ``ENTRY`` head and stops at the first line that is neither its
    ``cp:`` block, one of its ``wp[k]`` blocks, nor its chain-level wp note --
    so this can be called at any indexed head without replaying the stream.
    That property is what makes :class:`_EntrySeq` possible.
    """
    m = _ENTRY_HEAD_RE.match(lines[i])
    if not m:
        raise ValueError(f"not an ENTRY head at line {i}: {lines[i]!r}")
    seq_num = int(m.group(1))
    thread_id = int(m.group(2))
    asid_index = int(m.group(3)) if m.group(3) is not None else 0
    thread_switched = m.group(4) == "1"
    fault_depth = int(m.group(5)) if m.group(5) is not None else 0
    # Executed range [bb_start, bb_stop) — printed only when partial,
    # so None here means "whole block" (resolved after the template
    # is known by consumers that need the absolute stop).
    bb_start = int(m.group(6)) if m.group(6) is not None else 0
    bb_stop = int(m.group(7)) if m.group(7) is not None else None
    template_id = int(m.group(8))
    branch_taken = (None if m.group(9) is None
                    else m.group(9) == "taken")
    branch_target = (None if m.group(10) is None
                     else int(m.group(10), 16))
    thread_end = m.group(11) is not None
    i += 1
    n_lines = len(lines)
    # CP block: indented "cp:" header followed by observations.
    cp_dyn: list[DynParam] = []
    cp_snaps: list[dict] = []
    cp_mflags: list[dict] = []
    cp_lanes: list[dict] = []
    wp_entries: list[dict] = []
    if i < n_lines and lines[i] == "  cp:":
        i += 1
        # Strip leading 4 spaces from observation lines so the
        # generic parser reads them.
        obs_lines: list[str] = []
        while i < n_lines and lines[i].startswith("    "):
            obs_lines.append(lines[i][4:])
            i += 1
        j = 0
        cp_dyn, cp_snaps, cp_mflags, cp_lanes, _ = _parse_observations(
            obs_lines, j, reg_name_to_id)
    while i < n_lines:
        mw = _WP_HEAD_RE.match(lines[i])
        if not mw:
            break
        i += 1
        wp = {
            "index": int(mw.group(1)),
            "template_id": int(mw.group(2)),
            "n_insns": int(mw.group(3)),
            "bb_start": (int(mw.group(4))
                         if mw.group(4) is not None else 0),
            "bb_stop": (int(mw.group(5))
                        if mw.group(5) is not None else None),
            "dyn_params": [],
            "reg_snaps": [],
            "metaflags": [],
            "lane_masks": [],
            "fault": False,
            "translation_unavailable": False,
            "fault_insn_index": None,
        }
        if i < n_lines and lines[i].startswith("    status:"):
            tokens = lines[i][len("    status: "):].split()
            for t in tokens:
                if t == "FAULT":
                    wp["fault"] = True
                elif t.startswith("FAULT@insn"):
                    wp["fault"] = True
                    wp["fault_insn_index"] = int(t[len("FAULT@insn"):])
                elif t == "TRANSLATION_UNAVAILABLE":
                    wp["translation_unavailable"] = True
            i += 1
        obs_lines = []
        while i < n_lines and lines[i].startswith("    "):
            obs_lines.append(lines[i][4:])
            i += 1
        j = 0
        (wp["dyn_params"], wp["reg_snaps"],
         wp["metaflags"], wp["lane_masks"], _) = _parse_observations(
            obs_lines, j, reg_name_to_id)
        wp_entries.append(wp)
    # Chain-level TRANSLATION_UNAVAIL event (format spec §4.4): the
    # excursion was kicked but its first target could not be
    # fetched, so the entry has no wp[k] blocks and the decoder
    # prints this line instead.
    wp_first_fetch_unavailable = False
    if i < n_lines and lines[i] == "  wp: none (first fetch unavailable)":
        wp_first_fetch_unavailable = True
        i += 1
    return {
        "seq_num": seq_num,
        "template_id": template_id,
        "thread_id": thread_id,
        "asid_index": asid_index,
        "thread_switched": thread_switched,
        "branch_taken": branch_taken,
        "branch_target": branch_target,
        "thread_end": thread_end,
        "fault_depth": fault_depth,
        "bb_start": bb_start,
        "bb_stop": bb_stop,
        "dyn_params": cp_dyn,
        "reg_snaps": cp_snaps,
        "metaflags": cp_mflags,
        "lane_masks": cp_lanes,
        "wp_entries": wp_entries,
        "wp_first_fetch_unavailable": wp_first_fetch_unavailable,
    }, i


def _iter_body(lines, i: int,
               reg_name_to_id: dict[str, int]) -> Iterator[dict]:
    """Yield every body ENTRY in stream order, retaining none of them."""
    i = _body_start(lines, i)
    if i < 0:
        return
    n_lines = len(lines)
    while i < n_lines:
        line = lines[i]
        if line == "" or not _ENTRY_HEAD_RE.match(line):
            i += 1
            continue
        entry, i = _parse_entry_at(lines, i, reg_name_to_id)
        yield entry


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class _LineFile:
    """A positionally-indexable sequence of lines backed by a file on disk.

    Drop-in for the ``list[str]`` the parsers below expect: it supports
    ``len()``, scalar ``[i]``, negative indices, the one bounded slice
    (``lines[-8:]``), iteration and ``enumerate``.  Nothing else is used.

    WHY THIS EXISTS.  ``cst_decode --format=legacy`` emits roughly 27 lines
    per guest instruction, so a 20 M-instruction trace is ~540 M lines and
    tens of gigabytes of text.  Reading that with ``capture_output=True``
    held the whole thing as one ``str``, and ``text.splitlines()`` then made
    a second copy as hundreds of millions of ``str`` objects (each carrying
    ~49 bytes of object overhead on top of its payload), and three later
    passes re-scanned it.  That pattern exhausted 487 GiB of host RAM and
    took the machine down for two days.

    Here the text stays on disk and the only resident structure is an
    8-bytes-per-line offset index, with no change to how the parsers address
    it.  Bytes are pulled through ``os.pread`` into one bounded window rather
    than through a whole-file mmap: a mapping's resident pages are charged to
    this process's RSS, so streaming a 1.5 GB decode through one would report
    (and hold) 1.5 GB of page cache as if it were the parser's own heap.
    ``pread`` leaves those pages in the kernel's cache where they belong and
    the window costs :data:`_WINDOW` bytes no matter how long the trace is.

    ``mark_prefixes`` records, during the single index-building pass, the line
    numbers of every line beginning with one of the given prefixes.  That is
    what lets the readers above find the ENTRY / REGFILE / BODY_STATS records
    without re-walking tens of millions of lines per question asked.
    """

    __slots__ = ("_path", "_fh", "_fd", "_off", "_n", "_own", "_size",
                 "_buf", "_buf_lo", "_buf_hi", "marks")

    @property
    def path(self) -> str:
        return self._path

    # One read window.  Big enough that sequential line access costs one
    # syscall per few thousand lines; small enough to be irrelevant to RSS.
    _WINDOW = 1 << 22          # 4 MiB

    def __init__(self, path: str | os.PathLike, *, own: bool = False,
                 mark_prefixes: tuple[bytes, ...] = ()):
        self._path = str(path)
        self._own = own
        self._fh = open(self._path, "rb", buffering=1 << 20)
        self._fd = self._fh.fileno()
        if own:
            # Unlink NOW, while the fd holds the data alive.  A scratch file
            # that only disappears in close() survives a kill -9 and fills
            # the array; this one cannot outlive the process by construction.
            try:
                os.unlink(self._path)
            except OSError:
                pass
            self._own = False
        self._size = os.fstat(self._fd).st_size
        self._buf = b""
        self._buf_lo = 0
        self._buf_hi = 0
        self.marks: dict[bytes, "array[int]"] = {
            p: array("q") for p in mark_prefixes}
        self._off = array("q")
        self._n = 0
        if self._size:
            self._build_index(mark_prefixes)

    def _build_index(self, mark_prefixes: tuple[bytes, ...]) -> None:
        """One pass: line-start offsets, plus the line numbers of every
        marked prefix.  Consumes the buffered handle opened in __init__ (the
        scratch file is already unlinked by then, so it cannot be reopened by
        name); every later read goes through ``os.pread`` on the same fd,
        which is position-independent and leaves the file's pages in the
        kernel page cache rather than in this process's RSS."""
        off = self._off
        append = off.append
        # (first byte, prefix, len, sink) -- the byte test rejects almost
        # every line without slicing it.
        probes = [(p[0], p, len(p), self.marks[p]) for p in mark_prefixes]
        pos = 0
        idx = 0
        for raw in self._fh:
            append(pos)
            if probes and raw:
                b0 = raw[0]
                for first, pre, plen, sink in probes:
                    if b0 == first and raw[:plen] == pre:
                        sink.append(idx)
                        break
            pos += len(raw)
            idx += 1
        self._n = idx

    def __len__(self) -> int:
        return self._n

    def _read(self, start: int, end: int) -> bytes:
        """Bytes [start, end) via the sliding window."""
        if self._fd < 0:
            # A lazy view (_EntrySeq / _BodyOrderSeq) outlived the decode it
            # addresses.  Say so.  Reading on regardless is worse than an
            # error: the fd number this object used has been released, so a
            # pread through it lands on whatever file the process opened
            # next and returns that file's bytes, silently.
            raise ValueError(
                f"_LineFile({self._path!r}) is closed -- a lazy view over "
                f"this decode outlived it.  Views hold a reference to keep "
                f"the decode alive; something closed it explicitly, or the "
                f"view was built over a decode owned by a `with` block.")
        if start >= self._buf_lo and end <= self._buf_hi:
            return self._buf[start - self._buf_lo:end - self._buf_lo]
        want = max(self._WINDOW, end - start)
        buf = os.pread(self._fd, want, start)
        if len(buf) < end - start:          # short read at EOF
            end = start + len(buf)
        self._buf = buf
        self._buf_lo = start
        self._buf_hi = start + len(buf)
        return buf[:end - start]

    def _line(self, i: int) -> str:
        start = self._off[i]
        end = self._off[i + 1] if i + 1 < self._n else self._size
        raw = self._read(start, end)
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        return raw.decode("utf-8", "replace")

    def __getitem__(self, key):
        if isinstance(key, slice):
            # Only a small tail slice is used (`lines[-8:]`); materialising a
            # bounded window is fine, materialising an unbounded one is not.
            idx = range(*key.indices(self._n))
            if len(idx) > 4096:
                raise MemoryError(
                    "_LineFile: refusing to materialise a slice of "
                    f"{len(idx)} lines; iterate instead")
            return [self._line(i) for i in idx]
        if key < 0:
            key += self._n
        if not 0 <= key < self._n:
            raise IndexError(key)
        return self._line(key)

    def __iter__(self) -> Iterator[str]:
        for i in range(self._n):
            yield self._line(i)

    def close(self) -> None:
        self._buf = b""
        # Retire the window as well as its contents: leaving _buf_lo/_buf_hi
        # behind lets a post-close read whose range falls inside the old
        # window be served from the emptied buffer, which returns empty
        # strings with no error at all.
        self._buf_lo = 0
        self._buf_hi = 0
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        # And retire the fd NUMBER.  Once released it can be handed to the
        # next file this process opens, and _read() addresses it directly:
        # a stale _fd is how a use-after-close reads another file's bytes
        # instead of failing.  -1 makes _read say what happened.
        self._fd = -1
        if self._own:
            try:
                os.unlink(self._path)
            except OSError:
                pass

    def __del__(self):
        try:
            self.close()
        except Exception:                                   # noqa: BLE001
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def __deepcopy__(self, memo):
        # Reached only if some new path deepcopies a structure that still
        # points at the open decode.  Say so, instead of dying six frames
        # down on "cannot pickle '_io.BufferedReader'".
        raise TypeError(
            "_LineFile is an open decode, not data: it cannot be deepcopied. "
            "The lazy views over it (_EntrySeq, _BodyOrderSeq) each define "
            "__deepcopy__ and hand back plain, independent Python objects -- "
            "copy those, or iterate.")


_ENTRY_MARK = b"ENTRY "
_REGFILE_MARK = b"REGFILE "
_STATS_MARK = b"BODY_STATS"
_BODY_MARKS = (_ENTRY_MARK, _REGFILE_MARK, _STATS_MARK)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# How much memory the parsed entries may occupy, in MiB.  A BUDGET, not a
# count: the thing that has to stay under control is bytes, and entries are
# not interchangeable units of it (measured across four ISAs, one entry is
# 18 KB on a system cell and 49 KB on a user cell).
#
# WHY THE DEFAULT IS 10 GiB.  The first bound counted entries -- 4096 of
# them, about 74 MB -- which is two orders of magnitude below what a lane is
# allowed to hold, and the gap was paid for in time: every one of
# `validate()`'s ~22 passes over a 632,121-entry body missed the cache almost
# entirely and unpickled the whole body back off the spill, turning 3:46 into
# ~20 minutes.  The ruling:
#
#     "It is okay to use ~150 GiB of RAM, but your rebalance is killing
#      performance to keep runs below 20.  Too aggressive."
#
# so the working set is sized to the machine rather than to the smallest
# number that still technically bounds.  A cell whose parsed body fits in the
# budget now runs at eager speed; only a genuinely oversized one degrades to
# parse-on-access.  The arithmetic is in `_CachePool`.
#
# WHY 11 GiB AND NOT 10.  10240 was tried first and lands just under the
# cliff on the very cell this exists for.  The 3 M riscv64 system cell's
# parsed body charges 10.44 GiB, so a 10 GiB budget holds 95.8% of it and
# evicts 180,274 times; the 4.2% that does not fit costs a re-parse on every
# pass.  Measured, same cell, same code, four passes each:
#
#     budget 10 GiB   95.8% resident   hit rate 91.4%   pass 5.3 s   RSS 10.43 GiB
#     budget 12 GiB    100% resident   hit rate  100%   pass 0.5 s   RSS 10.51 GiB
#
# Ten times the per-pass cost for 0.08 GiB of resident memory -- the last few
# percent of a body is worth far more than it weighs, because a miss is a
# re-parse and a hit is free.  11 GiB is the largest default that keeps the
# worst case inside both limits: a body too big for it fills the cache and
# peaks near 12.3 GiB against the standing 16 GiB `ulimit -v` (3.7 GiB of
# margin), and twelve lanes at that is ~148 GiB, inside the ~150 GiB the
# machine is allowed to give up.  12288 would hold more bodies whole but puts
# twelve lanes at ~159 GiB, over the line.
_CACHE_MB_DEFAULT = 11264

# One dict slot, one victim-pool slot and the (entry, charge) tuple that records
# what was charged.  Small next to an entry, but 10 GiB of 18 KB entries is
# ~580 k slots, so it is not nothing and it is not free to ignore.
_SLOT_OVERHEAD_BYTES = 256

# Charging every admission its true recursive size costs more than the
# unpickle it rides on (160 us against 45 us on a system cell, 370 us against
# a ~100 us parse on a user cell), so the size of one entry in N is measured
# and the rest are scaled from their pickled length.  Measured across seven
# cells and four ISAs, live-bytes-per-pickled-byte is 7.32-8.89 BETWEEN cells
# but flat to two decimal places WITHIN one (7.32 / 7.32, 8.88 / 8.89), which
# is exactly the shape a per-decode calibration handles and a compiled-in
# constant does not.
_CACHE_SAMPLE_EVERY = 256

# Only ever consulted before the first sample lands, and the first admission
# IS a sample -- so this is a defensive floor, not a working default.  Set
# above the largest per-entry size measured anywhere (49,089 B, x86_64 user).
_ENTRY_BYTES_SEED = 64 * 1024
_ENTRY_RATIO_SEED = 9.0

# Above this many entries, .materialize() refuses.  The mutation matrix and
# the multi-thread provers legitimately need a real mutable list, and their
# substrates are proof-sized (a 120 k-instruction trace, a few thousand
# entries).  A 3 M-instruction system cell is ~576 k entries at ~18 KB each --
# the 10.3 GiB that took the host down.  Nothing may cross that line silently.
_MATERIALIZE_MAX_DEFAULT = 100_000

# The body-record-order view is two machine words per record, not a whole
# entry, so its ceiling sits far higher -- but it is still a ceiling, so a
# trace nobody sized for cannot quietly become hundreds of MB of tuples.
_ORDER_MATERIALIZE_MAX_DEFAULT = 2_000_000

# Below this many entries the whole body parses in well under a second, so
# the parsed-entry spill would cost a scratch file to save nothing.
_SPILL_MIN_ENTRIES = 20_000


def _spill_enabled() -> bool:
    return os.environ.get("CST_DECODE_PARSED_SPILL", "1") != "0"


def _spill_dir(lines: "_LineFile") -> str:
    """Alongside the decode itself -- on the array, never /tmp (the OS SSD
    on this host, which a multi-GB spill would fill)."""
    env = os.environ.get("CST_DECODE_SCRATCH")
    if env:
        return env
    d = os.path.dirname(lines.path)
    return d if d and os.access(d, os.W_OK) else str(Path.cwd())


class _ParsedSpill:
    """Write-through store of PARSED entries, keyed by entry index.

    ``validate()`` walks the body around forty times -- one pass per check.
    Reading them lazily off the legacy text means each pass re-runs the
    regex parse, which turns a bounded decode into a slow one.  So the
    first read of an entry parses it and writes the parsed form here; every
    later read is an unpickle, which costs a fraction of the parse and
    still holds nothing resident.

    Append-only, unlinked at creation, addressed by ``pread``/``pwrite`` --
    the resident cost is two machine words per entry regardless of how big
    the body is.
    """

    __slots__ = ("_fh", "_fd", "_off", "_len", "_end")

    def __init__(self, n: int, scratch_dir: str):
        fd, path = tempfile.mkstemp(prefix=".cstparsed-", suffix=".bin",
                                    dir=scratch_dir)
        self._fh = os.fdopen(fd, "r+b")
        self._fd = self._fh.fileno()
        try:
            os.unlink(path)
        except OSError:
            pass
        # len == 0 means "not written yet"; a pickled entry is never empty.
        self._off = array("q", bytes(8 * n))
        self._len = array("q", bytes(8 * n))
        self._end = 0

    def get(self, k: int):
        ln = self._len[k]
        if not ln:
            return None
        return pickle.loads(os.pread(self._fd, ln, self._off[k]))

    def size(self, k: int) -> int:
        """Pickled length of entry @k, or 0 if it has never been written.

        This is what the cache's byte budget scales from: an exact,
        already-computed per-entry number that tracks how big each entry
        really is, where a flat per-entry average would not.
        """
        return self._len[k]

    def put(self, k: int, entry: dict) -> None:
        blob = pickle.dumps(entry, protocol=pickle.HIGHEST_PROTOCOL)
        off = self._end
        os.pwrite(self._fd, blob, off)
        self._end = off + len(blob)
        self._off[k] = off
        self._len[k] = len(blob)

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None

    def __del__(self):
        try:
            self.close()
        except Exception:                                   # noqa: BLE001
            pass


_SIZEOF_ATOMIC = (str, bytes, bytearray, int, float, complex, bool,
                  type(None))
_SIZEOF_OPAQUE = (type, types.ModuleType, types.FunctionType,
                  types.BuiltinFunctionType, types.MethodType)


def _deep_sizeof(obj) -> int:
    """Recursive size of one decoded entry, in bytes.

    Follows dicts, sequences AND instance ``__dict__`` / ``__slots__``: a
    body entry's ``dyn_params`` are :class:`DynParam` dataclasses, whose
    seven-field ``__dict__`` is several times the 48-byte instance header.
    A sizer that stops at the header under-counts an entry by about half,
    and for a memory budget an under-count is the direction that hurts --
    it over-admits.

    Shared objects (interned strings, small ints) are counted once per
    entry rather than once per process, so the number is an upper bound on
    the entry's marginal cost.  Validated against RSS: summed over 8,000
    held entries it lands within 3% of the resident growth they cause.
    """
    seen: set[int] = set()
    total = 0
    stack = [obj]
    gso = sys.getsizeof
    while stack:
        o = stack.pop()
        i = id(o)
        if i in seen:
            continue
        seen.add(i)
        total += gso(o)
        if isinstance(o, _SIZEOF_ATOMIC):
            continue
        if isinstance(o, dict):
            stack.extend(o.keys())
            stack.extend(o.values())
            continue
        if isinstance(o, (list, tuple, set, frozenset)):
            stack.extend(o)
            continue
        if isinstance(o, _SIZEOF_OPAQUE):
            # A class or a module reached from an entry would drag the
            # interpreter in behind it.  Nothing in a decoded entry does;
            # this makes that structural, not a hope.
            continue
        d = getattr(o, "__dict__", None)
        if isinstance(d, dict):
            stack.append(d)
        for cls in type(o).__mro__:
            for name in getattr(cls, "__slots__", ()) or ():
                try:
                    stack.append(getattr(o, name))
                except AttributeError:
                    pass
    return total


class _CachePool:
    """The process-wide ceiling on parsed-entry cache bytes.

    The budget belongs to the PROCESS, not to one decode.  Decodes do
    coexist -- ``_diff_entries`` walks a pair side by side, the
    cross-segment check opens one per segment -- and if each were entitled
    to the whole budget the ceiling would be a per-decode number wearing a
    process-wide name, which is how a 10 GiB bound quietly becomes 30.

    THE ARITHMETIC, against the standing ``ulimit -v 16777216`` cell shape.
    Measured on the largest cell here -- the 3 M riscv64 system cell,
    632,121 entries / 31,514,301 lines, whose parsed body charges 10.44 GiB
    and so fits inside the 11 GiB default -- running the full ``validate()``:

        parsed entries, charged                     10.44 GiB
        line index, entry / record-order / spill
          indices, interpreter, templates,
          encoding maps, and the checks' own
          working sets (measured as the residue)     1.26 GiB
        ------------------------------------------- --------
        total, measured                             ~11.7 GiB

    against a 16 GiB cap.  A body too large for the budget fills it instead
    and peaks near 12.3 GiB, which is the worst case and still leaves
    3.7 GiB.  Both sit within a factor of the 11.07 GiB the pre-fix eager
    decode reached on this same cell under this same cap without hitting it,
    so the default is bounded by a residency already demonstrated to fit
    rather than by an estimate.  Twelve lanes at the worst case is ~148 GiB,
    inside the ~150 GiB the machine is allowed to give up.

    When the total goes over, the pool takes from the LARGEST live cache
    rather than from whoever happened to be growing, so a second decode
    starting against a first that has already filled up is throttled fairly
    instead of being starved down to one entry.
    """

    __slots__ = ("budget", "_caches")

    def __init__(self, budget: int):
        self.budget = budget
        self._caches: list[weakref.ref] = []

    def register(self, cache: "_ByteCache") -> None:
        self._caches = [r for r in self._caches if r() is not None]
        self._caches.append(weakref.ref(cache))

    def live(self) -> list["_ByteCache"]:
        out = []
        keep = []
        for r in self._caches:
            c = r()
            if c is not None:
                keep.append(r)
                out.append(c)
        self._caches = keep
        return out

    def total(self) -> int:
        # Deliberately does not rebuild the registry: this runs on every
        # cache admission, which on a large cell is millions of calls, and
        # the sweep only earns its keep when something has actually died.
        t = 0
        dead = False
        for r in self._caches:
            c = r()
            if c is None:
                dead = True
            else:
                t += c.bytes
        if dead:
            self._caches = [r for r in self._caches if r() is not None]
        return t

    def enforce(self, keeper: "_ByteCache", protect: int) -> None:
        """Evict until the process total is inside the budget.

        @keeper is the cache that just admitted and @protect the key it
        admitted; that one entry is never the victim, so a budget below the
        size of a single entry still hands back the entry the caller asked
        for instead of looping forever.
        """
        total = self.total()
        if total <= self.budget:
            return
        caches = self.live()
        while total > self.budget:
            victim = None
            best = 0
            for c in caches:
                floor = 1 if c is keeper else 0
                if len(c) > floor and c.bytes > best:
                    victim, best = c, c.bytes
            if victim is None:
                return          # nothing left that may be given up
            freed = victim.evict_one(protect if victim is keeper else None)
            if freed <= 0:
                return          # the victim could not give anything up
            total -= freed


_POOL: _CachePool | None = None


def _pool() -> _CachePool:
    """The pool, built on first use so the budget reflects the environment
    the process was started with (every measurement path spawns a child with
    ``CST_DECODE_CACHE_MB`` already set)."""
    global _POOL
    if _POOL is None:
        mb = _env_int("CST_DECODE_CACHE_MB", _CACHE_MB_DEFAULT)
        _POOL = _CachePool(max(0, mb) * 1024 * 1024)
    return _POOL


class _ByteCache:
    """Cache of parsed entries bounded by BYTES, with RANDOM replacement.

    Each admission is charged what the entry actually costs resident.  The
    charge is recorded alongside the entry and refunded verbatim on
    eviction, so a calibration that moves mid-decode cannot make the
    accounting drift -- what went in is what comes out.

    WHY NOT LRU.  ``validate()`` reads the body as ~22 full forward passes.
    That is the exact access pattern least-recently-used is worst at: on a
    cyclic scan of a body slightly larger than the cache, the least-recently
    used entry is always the one the next pass is about to ask for, so every
    access misses.  Measured, on an x86_64 user cell whose body is 0.12 GiB,
    with an LRU holding 1,551 of its 3,371 entries -- 46% of the body
    resident:

        hits 0        misses 3,371        hit rate 0.0%

    A cache holding nearly half the body and returning nothing is not a
    tuning problem, it is the wrong policy.  Random replacement has no such
    blind spot: no entry is systematically evicted just before it is needed,
    so the hit rate tracks the resident fraction instead of collapsing to
    zero, and a body that overflows the budget degrades in proportion rather
    than falling off a cliff.  It is also why the budget can be sized for
    the machine and left alone -- a cell too big for it gets slower by the
    fraction that does not fit, not by a factor.

    Eviction picks a uniformly random resident entry and swap-removes it,
    which is O(1); recency is deliberately not tracked, because tracking it
    is what produced the zero above.
    """

    # __weakref__ is required, not incidental: the pool tracks live caches
    # by weak reference so a dropped decode leaves the process-wide total
    # on its own, with nothing to remember to un-account.
    __slots__ = ("_map", "_keys", "_pos", "_rng", "_bytes", "_peak", "_adm",
                 "_deep_sum", "_pick_sum", "_mean_sum", "_mean_n",
                 "_evictions", "_hits", "_misses", "_misaccount",
                 "__weakref__")

    def __init__(self):
        self._map: dict[int, tuple] = {}
        # Victim pool: _keys[_pos[k]] == k for every resident k, so a random
        # victim is one randrange and one swap-remove.
        self._keys: list[int] = []
        self._pos: dict[int, int] = {}
        # Its own stream, seeded fixed: the cache must not perturb anyone
        # else's use of `random`, and two runs of the same cell should evict
        # the same way so a timing measurement is repeatable.
        self._rng = random.Random(0xC57CACE)
        self._hits = 0
        self._misses = 0
        self._bytes = 0
        self._peak = 0
        self._adm = 0
        self._deep_sum = 0          # sampled true sizes ...
        self._pick_sum = 0          # ... against their pickled lengths
        self._mean_sum = 0
        self._mean_n = 0
        self._evictions = 0
        # TEST LEVER, and the only thing that may ever set it is the
        # residency tripwire, which needs a deliberately mis-accounted
        # charge to prove its budget arm can go red.  Any other use makes
        # the cache hold N times what it says it holds.
        self._misaccount = max(1, _env_int("CST_DECODE_CACHE_MISACCOUNT", 1))
        _pool().register(self)

    def __len__(self) -> int:
        return len(self._map)

    @property
    def bytes(self) -> int:
        return self._bytes

    @property
    def peak_bytes(self) -> int:
        return self._peak

    @property
    def evictions(self) -> int:
        return self._evictions

    @property
    def hit_rate(self) -> float:
        """Fraction of reads served from memory.

        The number that says whether the budget is buying anything: an
        eviction policy can hold most of a body and still return none of
        it, and without this that failure is invisible from outside.
        """
        total = self._hits + self._misses
        return self._hits / total if total else 0.0

    @property
    def ratio(self) -> float:
        """Measured live bytes per pickled byte, or the seed if unsampled."""
        if self._pick_sum:
            return self._deep_sum / self._pick_sum
        return _ENTRY_RATIO_SEED

    def _charge(self, entry: dict, pickled_len: int) -> int:
        """What to bill @entry, and the calibration it feeds."""
        self._adm += 1
        if self._adm % _CACHE_SAMPLE_EVERY == 1:
            deep = _deep_sizeof(entry)
            self._mean_sum += deep
            self._mean_n += 1
            if pickled_len:
                self._deep_sum += deep
                self._pick_sum += pickled_len
            cost = deep
        elif pickled_len and self._pick_sum:
            cost = pickled_len * self._deep_sum // self._pick_sum
        elif self._mean_n:
            cost = self._mean_sum // self._mean_n
        else:
            cost = _ENTRY_BYTES_SEED
        return (cost + _SLOT_OVERHEAD_BYTES) // self._misaccount

    def get(self, k: int):
        hit = self._map.get(k)
        if hit is None:
            self._misses += 1
            return None
        self._hits += 1
        return hit[0]

    def put(self, k: int, entry: dict, pickled_len: int) -> None:
        cost = self._charge(entry, pickled_len)
        old = self._map.get(k)
        if old is not None:
            self._bytes -= old[1]
        else:
            self._pos[k] = len(self._keys)
            self._keys.append(k)
        self._map[k] = (entry, cost)
        self._bytes += cost
        _pool().enforce(self, protect=k)
        # AFTER enforcement.  An entry has to exist before it can be
        # charged, so between those two lines the cache is over budget by
        # one entry -- unavoidable in any cache, and not what "peak
        # residency" is asking about.  Sampling here reports the level the
        # cache actually settles at, which is the number the budget is a
        # promise about.
        if self._bytes > self._peak:
            self._peak = self._bytes

    def evict_one(self, protect: int | None = None) -> int:
        """Drop a uniformly random resident entry; returns bytes refunded.

        @protect is the key just admitted, which is never the victim -- the
        caller asked for it, and evicting it would let a budget smaller than
        one entry loop forever without ever handing anything back.
        """
        keys = self._keys
        n = len(keys)
        if n == 0:
            return 0
        i = self._rng.randrange(n)
        if keys[i] == protect:
            if n == 1:
                return 0
            i = (i + 1) % n
        return self._drop_at(i)

    def _drop_at(self, i: int) -> int:
        keys = self._keys
        k = keys[i]
        last = keys.pop()
        if last != k:
            keys[i] = last
            self._pos[last] = i
        del self._pos[k]
        _entry, cost = self._map.pop(k)
        self._bytes -= cost
        self._evictions += 1
        return cost

    def clear(self) -> None:
        self._map.clear()
        self._keys.clear()
        self._pos.clear()
        self._bytes = 0


class _EntrySeq(Sequence):
    """The body entries of a decode, as a lazy disk-backed sequence.

    Indistinguishable from ``list[dict]`` for every read the validator does --
    ``len()``, ``seq[i]``, negative indices, slicing, iteration, ``reversed``,
    ``enumerate``, ``zip`` -- but what it holds is capped in BYTES rather than
    growing with the trace.  ``seq[i]`` parses the record at its indexed line
    offset on demand and a byte-budgeted cache (:class:`_ByteCache`, against the
    process-wide :class:`_CachePool`) absorbs the checks' locality; iteration
    walks the same path.  Resident cost is the line index, the entry index and
    that budget, none of which grow with how much the trace executed.

    The budget is deliberately large -- 10 GiB by default, sized to the
    machine rather than to the smallest number that still bounds -- so a body
    that fits in it is cached whole and the validator's ~22 passes run at the
    speed of the eager list they replaced.  A body that does not fit degrades
    to parse-on-access, which is the case the bound exists for.

    WHY THIS EXISTS.  ``decode_champsim_tracer`` used to return
    ``list(_iter_body(...))``.  On a ``--stop 3000000`` system-marker cell
    that is ~576 k entry dicts at ~18 KB apiece -- 10.3 GiB measured, per
    cell.  Twelve to fifteen concurrent validator lanes reached ~190 GiB and
    made the host unresponsive.  The eager list was never a requirement of
    any caller; it was the shape the API happened to have.

    Entries handed out by ``seq[i]`` are the cached objects, so a consumer
    that MUTATES one would see its edit persist until eviction and then
    vanish.  No read-only consumer does (audited).  The consumers that do
    mutate -- the mutation matrix, the multi-thread provers -- take a
    ``copy.deepcopy`` of the whole triple first, which lands on
    :meth:`materialize` and gives them a genuine, independent ``list``.
    """

    __slots__ = ("_lines", "_rid", "_idx", "_lo", "_hi", "_cache",
                 "_root", "_spill")

    def __init__(self, lines: _LineFile, body_start: int,
                 reg_name_to_id: dict[str, int], *,
                 idx=None, lo: int = 0, hi: int | None = None,
                 cache=None, root: "_EntrySeq | None" = None,
                 spill: "_ParsedSpill | None" = None):
        self._lines = lines
        self._rid = reg_name_to_id
        if idx is None:
            marks = lines.marks.get(_ENTRY_MARK, array("q"))
            # ENTRY heads only ever occur in the body; clip anyway so a
            # header that ever grew one cannot be read as a record.
            first = bisect.bisect_left(marks, body_start) if body_start > 0 else 0
            idx = marks[first:] if first else marks
        self._idx = idx
        self._lo = lo
        self._hi = len(idx) if hi is None else hi
        # A slice shares the parent's cache: same entries, same budget, one
        # set of books.  Its own budget would be a second entitlement to the
        # process-wide ceiling.
        self._cache = _ByteCache() if cache is None else cache
        # A view keeps its parent (and so the open decode) alive.
        self._root = root
        if spill is not None:
            self._spill = spill
        elif root is None and _spill_enabled() and len(idx) > _SPILL_MIN_ENTRIES:
            self._spill = _ParsedSpill(len(idx), _spill_dir(lines))
        else:
            self._spill = None

    # -- sequence protocol -------------------------------------------------

    def __len__(self) -> int:
        return self._hi - self._lo

    def _parse(self, k: int) -> dict:
        entry, _ = _parse_entry_at(self._lines, self._idx[k], self._rid)
        return entry

    def _fresh_sized(self, k: int) -> tuple[dict, int]:
        """A newly-built entry at index @k, with its pickled length.

        The length is what the byte budget bills against -- it is already
        known exactly wherever the parsed spill is in play, so the common
        case costs nothing to measure.  0 means "no spill here", and the
        cache falls back to its running mean.
        """
        spill = self._spill
        if spill is not None:
            got = spill.get(k)
            if got is not None:
                return got, spill.size(k)
            entry = self._parse(k)
            spill.put(k, entry)
            return entry, spill.size(k)
        return self._parse(k), 0

    def _fresh(self, k: int) -> dict:
        """A newly-built entry at absolute index @k, shared with nobody."""
        return self._fresh_sized(k)[0]

    def _at(self, k: int) -> dict:
        """Entry at absolute index @k, through the byte-budgeted LRU."""
        cache = self._cache
        hit = cache.get(k)
        if hit is not None:
            return hit
        entry, plen = self._fresh_sized(k)
        cache.put(k, entry, plen)
        return entry

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.indices(len(self))
            if step == 1:
                return _EntrySeq(self._lines, 0, self._rid,
                                 idx=self._idx,
                                 lo=self._lo + start,
                                 hi=self._lo + max(start, stop),
                                 cache=self._cache,
                                 root=self._root or self,
                                 spill=self._spill)
            # Non-unit step is not on any path today; parse the (small)
            # window rather than growing a second lazy shape for it.
            return [self._at(self._lo + k)
                    for k in range(start, stop, step)]
        n = len(self)
        if key < 0:
            key += n
        if not 0 <= key < n:
            raise IndexError(key)
        return self._at(self._lo + key)

    def __iter__(self) -> Iterator[dict]:
        at = self._at
        for k in range(self._lo, self._hi):
            yield at(k)

    def __eq__(self, other) -> bool:
        # The container this replaced was a list, and callers compare two
        # decodes with `==` (the decoder smoke test does exactly that).
        # Without this, that comparison silently degrades to identity and
        # reports every pair of equal decodes as different.
        if other is self:
            return True
        if isinstance(other, (str, bytes, bytearray)):
            return NotImplemented
        if not isinstance(other, Sequence):
            return NotImplemented
        if len(self) != len(other):
            return False
        return all(a == b for a, b in zip(self, other))

    __hash__ = None         # same as list: equal-by-content, so unhashable

    # -- explicit materialisation -----------------------------------------

    def materialize(self, limit: int | None = None) -> list[dict]:
        """A real, independent ``list[dict]`` -- guarded by size.

        Every entry is parsed fresh (the LRU is bypassed), so the result
        shares nothing with this sequence and is safe to mutate.  Above
        @limit entries this REFUSES rather than quietly reproducing the
        residency that took the host down; a consumer that genuinely needs
        the whole body of a large trace is a defect to convert to streaming,
        not a case to widen the limit for.
        """
        if limit is None:
            limit = _env_int("CST_DECODE_MATERIALIZE_MAX",
                             _MATERIALIZE_MAX_DEFAULT)
        n = len(self)
        if n > limit:
            raise MemoryError(
                f"refusing to materialise {n} decoded body entries "
                f"(limit {limit}).  The eager list is what put ~10 GiB per "
                f"cell on the host; iterate the sequence, or raise "
                f"CST_DECODE_MATERIALIZE_MAX deliberately if this really is "
                f"a proof-sized trace.")
        return [self._fresh(k) for k in range(self._lo, self._hi)]

    def __deepcopy__(self, memo) -> list[dict]:
        # copy.deepcopy(triple) is how the mutation matrix and the
        # multi-thread provers get something they can damage.  Give them a
        # genuine list -- already freshly parsed, so nothing is shared.
        return self.materialize()

    # -- lifetime ----------------------------------------------------------

    def close(self) -> None:
        # A view shares the root's cache and its open decode; closing one
        # must not pull either out from under the sequence it was sliced from.
        if self._root is None:
            self._cache.clear()
            if self._spill is not None:
                self._spill.close()
                self._spill = None
            self._lines.close()

    def __repr__(self) -> str:
        return f"<_EntrySeq {len(self)} entries (lazy)>"


class _BodyOrderSeq(Sequence):
    """``meta["body_record_order"]`` as a lazy sequence.

    One ``("regfile" | "entry", thread_id)`` tuple per body record, in stream
    order -- the positional view the record-cadence checks need (a thread's
    REGFILE must precede its first ENTRY).  Materialising it eagerly costs one
    tuple per record, which grows with the trace exactly like the entry list
    did; here the record's line number is already known from the decode's
    index pass and the tuple is rebuilt on access.
    """

    __slots__ = ("_lines", "_idx")

    def __init__(self, lines: _LineFile, body_start: int):
        self._lines = lines
        # Interleave line number and kind in one flat array: two machine
        # words per record, never a tuple object per record -- not even
        # transiently, which is why the two sorted mark arrays are merged
        # rather than concatenated and sorted.
        flat = array("q")
        append = flat.append
        cuts = []
        for mark in (_REGFILE_MARK, _ENTRY_MARK):
            marks = lines.marks.get(mark, array("q"))
            first = (bisect.bisect_left(marks, body_start)
                     if body_start > 0 else 0)
            cuts.append((marks, first, len(marks)))
        (ra, ai, an), (ea, ei, en) = cuts
        while ai < an and ei < en:
            if ra[ai] < ea[ei]:
                append(ra[ai]); append(0); ai += 1
            else:
                append(ea[ei]); append(1); ei += 1
        while ai < an:
            append(ra[ai]); append(0); ai += 1
        while ei < en:
            append(ea[ei]); append(1); ei += 1
        self._idx = flat

    def __len__(self) -> int:
        return len(self._idx) // 2

    def __getitem__(self, key):
        if isinstance(key, slice):
            return [self[k] for k in range(*key.indices(len(self)))]
        n = len(self)
        if key < 0:
            key += n
        if not 0 <= key < n:
            raise IndexError(key)
        line_no = self._idx[2 * key]
        kind = self._idx[2 * key + 1]
        line = self._lines[line_no]
        if kind:
            m = _ENTRY_HEAD_RE.match(line)
            return ("entry", int(m.group(2)))
        m = _REGFILE_HEAD_RE.match(line)
        return ("regfile", int(m.group(1)))

    def __iter__(self):
        for k in range(len(self)):
            yield self[k]

    def __eq__(self, other) -> bool:
        if other is self:
            return True
        if isinstance(other, (str, bytes, bytearray)):
            return NotImplemented
        if not isinstance(other, Sequence):
            return NotImplemented
        if len(self) != len(other):
            return False
        return all(a == b for a, b in zip(self, other))

    __hash__ = None

    def materialize(self, limit: int | None = None) -> list[tuple[str, int]]:
        if limit is None:
            limit = _env_int("CST_DECODE_ORDER_MATERIALIZE_MAX",
                             _ORDER_MATERIALIZE_MAX_DEFAULT)
        n = len(self)
        if n > limit:
            raise MemoryError(
                f"refusing to materialise {n} body-record-order tuples "
                f"(limit {limit}); iterate the sequence instead")
        return [self[k] for k in range(n)]

    def __deepcopy__(self, memo) -> list[tuple[str, int]]:
        # meta rides inside the (meta, templates, entries) triple that the
        # mutation matrix and the multi-thread provers deepcopy.  Without
        # this, deepcopy walks into the open decode behind this view and
        # dies on its file handle -- which is exactly what it did.
        return self.materialize()


def _decode_scratch_dir(path: str | os.PathLike) -> str:
    """Where to spill the decode.  Never /tmp -- that is the OS SSD on this
    host and a large decode would fill it.  Sit next to the trace, which is
    on the array, unless the caller overrides."""
    env = os.environ.get("CST_DECODE_SCRATCH")
    if env:
        return env
    parent = Path(path).resolve().parent
    return str(parent if os.access(parent, os.W_OK) else Path.cwd())


def _run_cst_decode_to_file(path: str | os.PathLike) -> str:
    """Run cst_decode with its stdout going straight to disk.

    Returns the scratch file path; the caller owns it.  stdout is NEVER
    buffered in this process -- see _LineFile for why.
    """
    binary = _find_cst_decode()
    fd, out = tempfile.mkstemp(prefix=".cstdecode-", suffix=".legacy",
                               dir=_decode_scratch_dir(path))
    try:
        with os.fdopen(fd, "wb") as sink:
            proc = subprocess.run(
                [str(binary), "--format=legacy", str(path)],
                check=False, stdout=sink, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            err = (proc.stderr or b"").decode("utf-8", "replace")
            tail = " | ".join(err.strip().splitlines()[-6:])
            raise subprocess.CalledProcessError(
                proc.returncode, [str(binary), "--format=legacy", str(path)],
                stderr=tail)
    except BaseException:
        try:
            os.unlink(out)
        except OSError:
            pass
        raise
    return out


def _run_cst_decode(path: str | os.PathLike) -> str:
    """Back-compat: return the decode as one string.

    DEPRECATED and dangerous on anything but a small trace -- it is the
    pattern that took the host down.  Kept only for callers that predate
    _LineFile; new code must use _run_cst_decode_to_file + _LineFile.
    """
    out = _run_cst_decode_to_file(path)
    try:
        with open(out, "r", errors="replace") as fh:
            return fh.read()
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass


def _parse_header(lines) -> tuple[dict, list[dict], int, dict]:
    """Parse everything before the body: meta, encoding maps, templates.

    All of it is bounded by the trace's template count rather than by its
    length, so this is safe to do eagerly on any size of trace.  Returns
    (meta, templates, body_start_index, rid_by_name).
    """
    meta, i = _parse_meta_section(lines)
    encoding_maps, i = _parse_encodings(lines, i, meta)
    meta["encoding_maps"] = encoding_maps
    # The trace is self-describing: every map is embedded in the
    # header by the plugin.  No built-in fallback -- a missing map is
    # a corrupt/truncated trace, not a compatibility case.
    for need in ("reg", "opcode", "branch_type"):
        if need not in encoding_maps:
            raise ValueError(
                f"trace header missing '{need}' encoding map "
                f"(corrupt or truncated .cst)")
    rid_by_name = {n: r for r, n in encoding_maps["reg"].items()}
    op_to_id = {n: r for r, n in encoding_maps["opcode"].items()}
    br_to_id = {n: r for r, n in encoding_maps["branch_type"].items()}
    meta["reg_names"] = encoding_maps["reg"]
    meta["opcode_names"] = encoding_maps["opcode"]
    meta["branch_names"] = encoding_maps["branch_type"]

    templates, i = _parse_templates(
        lines, i, rid_by_name, op_to_id, br_to_id)
    return meta, templates, i, rid_by_name


def _parse_full(text) -> tuple[dict, list[dict], Sequence]:
    # Accepts either a str (small inputs, tests) or an already-open
    # _LineFile / list[str].  A str is split here exactly as before; a
    # _LineFile is addressed in place so the text never enters RAM.
    lines = text.splitlines() if isinstance(text, str) else text

    meta, templates, i, rid_by_name = _parse_header(lines)
    if isinstance(lines, _LineFile):
        # The disk-backed path: entries and the record-order view are lazy
        # sequences over the decode's own index, so neither grows with how
        # much the trace executed.
        body_start = _body_start(lines, i)
        entries: Sequence = _EntrySeq(lines, max(body_start, 0), rid_by_name)
        order: Sequence = _BodyOrderSeq(lines, max(body_start, 0))
    else:
        # In-memory input (a str, or a plain list of lines in the tests).
        # It is already fully resident by construction, so there is nothing
        # for laziness to save here.
        entries = list(_iter_body(lines, i, rid_by_name))
        order = _scan_body_order(lines)
    # Trailing BODY_STATS section.  Emitted unconditionally by the
    # legacy renderer; we scan the full output for it rather than
    # tracking position because the body iterator above leaves `i`
    # mid-stream when it short-circuits.
    meta["body_stats"] = _parse_body_stats(lines)
    meta["impossible_attributions"] = _parse_impossible_attributions(lines)
    meta["body_record_order"] = order
    return meta, templates, entries


_REGFILE_HEAD_RE = re.compile(r"^REGFILE thread=(\d+) n=\d+$")


def _scan_body_order(lines) -> Sequence:
    """Ordered body-record stream: ("regfile", thread_id) and
    ("entry", thread_id) tuples in the order the records appear in the
    body section.  ``_iter_body`` deliberately skips REGFILE blocks (they
    carry no per-entry payload the validator's entry checks consume), so
    record *ordering* invariants — a thread's REGFILE preceding its first
    ENTRY — need this positional view.

    On a disk-backed decode this returns the lazy :class:`_BodyOrderSeq` --
    same reads, but two machine words per record instead of a tuple object,
    and no whole-file re-scan to build it."""
    if isinstance(lines, _LineFile) and _ENTRY_MARK in lines.marks:
        i = 0
        n = len(lines)
        while i < n and lines[i] != "BODY":
            i += 1
        body_start = i + 2 if i < n else 0
        return _BodyOrderSeq(lines, body_start)
    order: list[tuple[str, int]] = []
    in_body = False
    for i, line in enumerate(lines):
        if not in_body:
            if line == "BODY" and i + 1 < len(lines) and lines[i + 1] == "----":
                in_body = True
            continue
        m = _REGFILE_HEAD_RE.match(line)
        if m:
            order.append(("regfile", int(m.group(1))))
            continue
        m = _ENTRY_HEAD_RE.match(line)
        if m:
            order.append(("entry", int(m.group(2))))
    return order


_IMPOSSIBLE_RE = re.compile(
    r"^; impossible attributions: (\d+) memop \((\d+) distinct insns\), "
    r"(\d+) regdata \((\d+) distinct insns\)$"
)


def _parse_impossible_attributions(lines: list[str]) -> dict:
    """Pick up cst_decode's trailing impossible-attribution summary
    (emitted only when the lint counted violations — a clean trace has
    no such line, keeping the legacy text byte-stable).  Surfaced in
    meta so the validator can fail the trace on its own terms."""
    out = {"memop": 0, "memop_insns": 0, "regdata": 0, "regdata_insns": 0}
    for line in reversed(lines[-8:]):
        m = _IMPOSSIBLE_RE.match(line)
        if m:
            out = {"memop": int(m.group(1)),
                   "memop_insns": int(m.group(2)),
                   "regdata": int(m.group(3)),
                   "regdata_insns": int(m.group(4))}
            break
    return out


def _parse_body_stats(lines) -> dict:
    """Scan for the BODY_STATS section emitted at end of legacy output."""
    stats: dict = {
        "cp_entries": 0,
        "wp_entries": 0,
        "iframe_count": 0,
        "regfile_count": 0,
        "thread_switch_count": 0,
        "fault_count": 0,
        "translation_unavail_count": 0,
        "atomic_count": 0,
    }
    if isinstance(lines, _LineFile) and _STATS_MARK in lines.marks:
        # The section header's line number was recorded by the decode's one
        # index pass; walking tens of millions of lines to rediscover it is
        # the kind of whole-file re-scan this reader exists to avoid.
        hits = lines.marks[_STATS_MARK]
        i = next((h for h in hits if lines[h] == "BODY_STATS"), None)
        if i is None:
            return stats
    else:
        i = 0
        while i < len(lines) and lines[i] != "BODY_STATS":
            i += 1
    if i >= len(lines):
        return stats
    if i + 1 >= len(lines) or lines[i + 1] != "----------":
        return stats
    i += 2
    while i < len(lines) and lines[i] != "":
        line = lines[i]
        for key in ("cp_entries", "wp_entries", "iframe_count",
                    "regfile_count", "thread_switch_count",
                    "fault_count", "translation_unavail_count",
                    "atomic_count"):
            if line.startswith(key + " "):
                stats[key] = int(line[len(key) + 1:])
                break
        i += 1
    return stats


def decode_champsim_tracer(bin_path):
    """Decode a trace.  Returns ``(meta, templates, entries)``.

    ``entries`` is a LAZY, disk-backed :class:`_EntrySeq`, not a list: it
    reads like ``list[dict]`` for every access the validator makes, and its
    residency does not grow with how much the trace executed.  The decode
    itself is spilled to disk and addressed through :class:`_LineFile`, so
    the legacy text is never resident either.

    This function used to return ``list(_iter_body(...))``.  A ``--stop
    3000000`` system-marker cell decodes to ~576 k entries at ~18 KB apiece:
    10.3 GiB, measured, for one cell, before validate() had checked anything.
    Concurrent lanes multiplied that until the host stopped responding.  The
    lazy sequence is the same read surface at a bounded cost, so no call site
    had to change to get the bound.

    The returned sequence owns the open decode.  Drop it (or call
    ``.close()``) when done; the scratch file is unlinked at open, so it can
    never outlive the process regardless.
    """
    out = _run_cst_decode_to_file(bin_path)
    lines = _LineFile(out, own=True, mark_prefixes=_BODY_MARKS)
    try:
        meta, templates, entries = _parse_full(lines)
    except BaseException:
        lines.close()
        raise
    if os.environ.get(FORCE_EAGER_ENV) == "1":
        # TEST LEVER, and the only thing that may ever set it is the
        # residency tripwire (`decode_bound`), which needs the pre-fix shape
        # to prove it can go red.  This reinstates exactly the unbounded
        # materialisation that put ~10 GiB per cell on the host.
        entries = list(entries)
        meta["body_record_order"] = list(meta.get("body_record_order") or [])
    return meta, templates, entries


# Set to "1" ONLY by the residency tripwire, to prove it fires.  Any other
# use reinstates the defect this module exists to prevent.
FORCE_EAGER_ENV = "CST_DECODE_FORCE_EAGER_UNBOUNDED"


def decode_residency_facts(entries) -> dict:
    """What the residency tripwire needs to know about a decode.

    Whether the container is the lazy sequence at all, how many entries it
    presents, how many lines of legacy text back it, and the cache's own
    books: the byte budget it was given, the high-water mark it actually
    charged, how many entries that was and how many it had to evict.
    Reported rather than assumed, so the bound the tripwire checks against
    is derived from the decode in front of it -- and so "the budget was
    honoured" can be distinguished from "nothing was ever cached", which
    would satisfy any ceiling and prove nothing.
    """
    if isinstance(entries, _EntrySeq):
        cache = entries._cache
        return {"lazy": True,
                "entries": len(entries),
                "lines": len(entries._lines),
                "cache_budget": _pool().budget,
                "cache_peak_bytes": cache.peak_bytes,
                "cache_bytes": cache.bytes,
                "cache_entries": len(cache),
                "cache_evictions": cache.evictions,
                "cache_hit_rate": round(cache.hit_rate, 4),
                "cache_ratio": round(cache.ratio, 3)}
    return {"lazy": False, "entries": len(entries), "lines": 0,
            "cache_budget": _pool().budget, "cache_peak_bytes": 0,
            "cache_bytes": 0, "cache_entries": 0, "cache_evictions": 0,
            "cache_hit_rate": 0.0, "cache_ratio": 0.0}


def decode_champsim_tracer_header(bin_path):
    """Return (meta, templates) only, holding nothing else.

    For the several callers that want templates and throw the body away
    (`_m, templates, _e = decode_champsim_tracer(...)`).  Materialising
    millions of entry dicts to discard them is pure waste, and on a large
    trace it is the difference between working and exhausting the host.
    Everything is released before returning -- no iterator to forget to
    consume, no scratch file left behind.
    """
    out = _run_cst_decode_to_file(bin_path)
    with _LineFile(out, own=True, mark_prefixes=_BODY_MARKS) as lines:
        meta, templates, _i, _rid = _parse_header(lines)
        meta["body_stats"] = _parse_body_stats(lines)
        meta["impossible_attributions"] = _parse_impossible_attributions(lines)
        return meta, templates


def iter_decode_champsim_tracer(bin_path, *, body_record_order: bool = False):
    """Streaming decoder.  Returns (meta, templates, entries_iterator).

    The header, the encoding maps and the templates are parsed up front (all
    bounded by the trace's template count, not its length), and body entries
    are then YIELDED one at a time.  Resident cost is the _LineFile line index
    plus one entry.

    This is the single-pass, forward-only form.  :func:`decode_champsim_tracer`
    is bounded too -- it returns a lazy random-access sequence over the same
    decode -- so prefer that when the consumer needs ``len()``, indexing or
    more than one pass, and this when it genuinely just walks the body once.

    `meta["body_stats"]` and `meta["impossible_attributions"]` are computed
    (both are bounded summaries).  `meta["body_record_order"]` is NOT, by
    default: pass body_record_order=True if you need it; otherwise the key is
    absent, and absent is honest -- it is not silently empty.
    """
    out = _run_cst_decode_to_file(bin_path)
    lines = _LineFile(out, own=True, mark_prefixes=_BODY_MARKS)
    try:
        meta, templates, i, rid_by_name = _parse_header(lines)
        meta["body_stats"] = _parse_body_stats(lines)
        meta["impossible_attributions"] = _parse_impossible_attributions(lines)
        if body_record_order:
            meta["body_record_order"] = _scan_body_order(lines)
    except BaseException:
        lines.close()
        raise

    def _entries():
        try:
            yield from _iter_body(lines, i, rid_by_name)
        finally:
            # When body_record_order was asked for, meta holds a lazy view
            # over THIS decode, and the caller may read it after the walk --
            # it was a plain list of tuples before the views existed, and
            # nothing in the API says it stops being readable.  Closing here
            # would leave them holding a view over a closed file.  The view
            # owns a reference, so dropping both releases the decode; the
            # fd is not leaked, only handed over.
            if not body_record_order:
                lines.close()

    return meta, templates, _entries()
