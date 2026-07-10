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

import dataclasses
import os
import re
import shutil
import subprocess
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

# Field IDs mirror champsim_tracer.h.
FID_SLOT_COUNT       = 16
FID_N_LOADS          = 0x00
FID_LOAD_ADDR_BASE   = 0x01
FID_STORE_ADDR_BASE  = 0x11
FID_LOAD_DATA_BASE   = 0x21
FID_STORE_DATA_BASE  = 0x31
FID_DST_REG_BASE     = 0x51
FID_N_STORES         = 0x61
FID_EXTRA_LOAD_ADDR  = 0x62
FID_EXTRA_STORE_ADDR = 0x63
FID_EXTRA_LOAD_DATA  = 0x64
FID_EXTRA_STORE_DATA = 0x65
FID_INSN_BYTES_LO    = 0x70
FID_INSN_BYTES_HI    = 0x71
FID_INSN_OPCODE      = 0x72
FID_INSN_BRANCH_TYPE = 0x73
FID_INSN_FLAGS       = 0x74
FID_INSN_IMMEDIATE   = 0x75
FID_INSN_SIZE        = 0x76
FID_EXTENDED         = 0xFF


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
    r"^ENTRY (\d+) thread=(\d+)(?: switch=(\d))?"
    r"(?: fault_depth=(\d+))?(?: fault_at=([\d,]+))? template=BB(\d+)$"
)
_WP_HEAD_RE = re.compile(
    r"^  wp\[(\d+)\] template=BB(\d+) n_insns=(\d+)$"
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


def _iter_body(lines: list[str], i: int,
               reg_name_to_id: dict[str, int]) -> Iterator[dict]:
    while i < len(lines) and lines[i] == "":
        i += 1
    if i >= len(lines):
        return
    if lines[i] != "BODY" or lines[i + 1] != "----":
        raise ValueError("expected BODY section header")
    i += 2
    while i < len(lines):
        line = lines[i]
        if line == "":
            i += 1
            continue
        m = _ENTRY_HEAD_RE.match(line)
        if not m:
            i += 1
            continue
        seq_num = int(m.group(1))
        thread_id = int(m.group(2))
        thread_switched = m.group(3) == "1"
        fault_depth = int(m.group(4)) if m.group(4) is not None else 0
        fault_anchors = ([int(x) for x in m.group(5).split(",")]
                         if m.group(5) else [])
        template_id = int(m.group(6))
        i += 1
        # CP block: indented "cp:" header followed by observations.
        cp_dyn: list[DynParam] = []
        cp_snaps: list[dict] = []
        cp_mflags: list[dict] = []
        cp_lanes: list[dict] = []
        wp_entries: list[dict] = []
        if i < len(lines) and lines[i] == "  cp:":
            i += 1
            # Strip leading 4 spaces from observation lines so the
            # generic parser reads them.
            obs_lines: list[str] = []
            while i < len(lines) and lines[i].startswith("    "):
                obs_lines.append(lines[i][4:])
                i += 1
            j = 0
            cp_dyn, cp_snaps, cp_mflags, cp_lanes, _ = _parse_observations(
                obs_lines, j, reg_name_to_id)
        while i < len(lines):
            mw = _WP_HEAD_RE.match(lines[i])
            if not mw:
                break
            i += 1
            wp = {
                "index": int(mw.group(1)),
                "template_id": int(mw.group(2)),
                "n_insns": int(mw.group(3)),
                "dyn_params": [],
                "reg_snaps": [],
                "metaflags": [],
                "lane_masks": [],
                "fault": False,
                "translation_unavailable": False,
                "dep_branch_kill": False,
                "fault_insn_index": None,
            }
            if i < len(lines) and lines[i].startswith("    status:"):
                tokens = lines[i][len("    status: "):].split()
                for t in tokens:
                    if t == "FAULT":
                        wp["fault"] = True
                    elif t.startswith("FAULT@insn"):
                        wp["fault"] = True
                        wp["fault_insn_index"] = int(t[len("FAULT@insn"):])
                    elif t == "TRANSLATION_UNAVAILABLE":
                        wp["translation_unavailable"] = True
                    elif t == "DEP_BRANCH_KILL":
                        # Chain terminator: the excursion died at this
                        # block because its terminating branch depends
                        # on a faulted wrong-path insn (format §4.4).
                        wp["dep_branch_kill"] = True
                i += 1
            obs_lines = []
            while i < len(lines) and lines[i].startswith("    "):
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
        if i < len(lines) and lines[i] == "  wp: none (first fetch unavailable)":
            wp_first_fetch_unavailable = True
            i += 1
        yield {
            "seq_num": seq_num,
            "template_id": template_id,
            "thread_id": thread_id,
            "thread_switched": thread_switched,
            "fault_depth": fault_depth,
            "fault_anchors": fault_anchors,
            "dyn_params": cp_dyn,
            "reg_snaps": cp_snaps,
            "metaflags": cp_mflags,
            "lane_masks": cp_lanes,
            "wp_entries": wp_entries,
            "wp_first_fetch_unavailable": wp_first_fetch_unavailable,
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _run_cst_decode(path: str | os.PathLike) -> str:
    binary = _find_cst_decode()
    proc = subprocess.run(
        [str(binary), "--format=legacy", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout


def _parse_full(text: str) -> tuple[dict, list[dict], list[dict]]:
    lines = text.splitlines()

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
    entries = list(_iter_body(lines, i, rid_by_name))
    # Trailing BODY_STATS section.  Emitted unconditionally by the
    # legacy renderer; we scan the full output for it rather than
    # tracking position because the body iterator above leaves `i`
    # mid-stream when it short-circuits.
    meta["body_stats"] = _parse_body_stats(lines)
    meta["impossible_attributions"] = _parse_impossible_attributions(lines)
    meta["body_record_order"] = _scan_body_order(lines)
    return meta, templates, entries


_REGFILE_HEAD_RE = re.compile(r"^REGFILE thread=(\d+) n=\d+$")


def _scan_body_order(lines: list[str]) -> list[tuple[str, int]]:
    """Ordered body-record stream: ("regfile", thread_id) and
    ("entry", thread_id) tuples in the order the records appear in the
    body section.  ``_iter_body`` deliberately skips REGFILE blocks (they
    carry no per-entry payload the validator's entry checks consume), so
    record *ordering* invariants — a thread's REGFILE preceding its first
    ENTRY — need this positional view."""
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


def _parse_body_stats(lines: list[str]) -> dict:
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
    """Eager decoder.  Returns (meta, templates, entries)."""
    text = _run_cst_decode(bin_path)
    return _parse_full(text)


def iter_decode_champsim_tracer(bin_path):
    """Streaming form.  cst_decode buffers the legacy output to stdout in
    full so this implementation eagerly collects entries; callers that
    require true streaming should iterate the C++ binary's stdout
    directly via subprocess.Popen and the line-grammar above.
    """
    meta, templates, entries = decode_champsim_tracer(bin_path)
    return meta, templates, iter(entries)
