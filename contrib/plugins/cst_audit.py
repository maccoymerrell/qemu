#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
cst_audit.py - byte-composition audit of a .cst trace.

Streams a .cst file (mmap'd, so multi-GB OK) and reports a
single-screen breakdown of where the bytes go. Categories mirror the
writer's logical regions so the report directly identifies shrinkage
targets.

Usage:
  python3 cst_audit.py path/to/trace.cst
  xz -dc trace.cst.xz > /tmp/trace.cst && python3 cst_audit.py /tmp/trace.cst

Compressed input is not supported directly: the trailer is read by
seek-from-end.  Decompress first.
"""
from __future__ import annotations

import argparse
import dataclasses
import mmap
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import champsim_tracer_decode as dec  # noqa: E402

# Per-insn template flag bits (subset we need to parse the body).
_INSN_FLAG_HAS_IMM           = 0x02
_INSN_FLAG_VARIABLE_MEMOP    = 0x40


# ---------------------------------------------------------------------------
# mmap-backed cursor with ULEB/SLEB helpers.
# ---------------------------------------------------------------------------

class _R:
    __slots__ = ("m", "p", "end")

    def __init__(self, m, p: int = 0, end: int | None = None):
        self.m = m
        self.p = p
        self.end = len(m) if end is None else end

    def u8(self) -> int:
        v = self.m[self.p]
        self.p += 1
        return v

    def u32_le(self) -> int:
        v = int.from_bytes(self.m[self.p:self.p + 4], "little")
        self.p += 4
        return v

    def u64_le(self) -> int:
        v = int.from_bytes(self.m[self.p:self.p + 8], "little")
        self.p += 8
        return v

    def uleb(self) -> int:
        result, shift = 0, 0
        while True:
            b = self.m[self.p]
            self.p += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return result
            shift += 7

    def sleb(self) -> int:
        result, shift = 0, 0
        while True:
            b = self.m[self.p]
            self.p += 1
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                if (b & 0x40) and shift < 64:
                    result |= -(1 << shift)
                return result

    def skip(self, n: int) -> None:
        self.p += n

    def slice(self, n: int) -> "_R":
        sub = _R(self.m, self.p, self.p + n)
        self.p += n
        return sub

    def string_len(self) -> int:
        st = self.p
        n = self.uleb()
        self.skip(n)
        return self.p - st


# ---------------------------------------------------------------------------
# Stat buckets.
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class _Bucket:
    bytes: int = 0
    count: int = 0

    def add(self, n: int) -> None:
        self.bytes += n
        self.count += 1


@dataclasses.dataclass
class _Stats:
    file_size: int = 0
    header: int = 0
    templates_section: int = 0
    templates_count: int = 0
    trailer: int = 0
    body_total: int = 0
    body_terminator: int = 0
    cp_entries: int = 0
    wp_entries_total: int = 0
    cp_total_insns: int = 0
    wp_total_insns: int = 0

    cp_entry_framing: _Bucket = dataclasses.field(default_factory=_Bucket)
    cp_dyn_memop_preamble: _Bucket = dataclasses.field(default_factory=_Bucket)
    cp_dyn_patch: _Bucket = dataclasses.field(default_factory=_Bucket)
    cp_mem_data: _Bucket = dataclasses.field(default_factory=_Bucket)
    cp_reg_data: _Bucket = dataclasses.field(default_factory=_Bucket)

    wp_chain_envelope: _Bucket = dataclasses.field(default_factory=_Bucket)
    wp_entry_framing: _Bucket = dataclasses.field(default_factory=_Bucket)
    wp_dyn_memop_preamble: _Bucket = dataclasses.field(default_factory=_Bucket)
    wp_dyn_patch: _Bucket = dataclasses.field(default_factory=_Bucket)
    wp_mem_data: _Bucket = dataclasses.field(default_factory=_Bucket)
    wp_reg_data: _Bucket = dataclasses.field(default_factory=_Bucket)

    wp_events: _Bucket = dataclasses.field(default_factory=_Bucket)


# ---------------------------------------------------------------------------
# Audit walker.
# ---------------------------------------------------------------------------

def _walk_templates(r: _R, expected: int) -> tuple[int, dict[int, dict]]:
    start = r.p
    n = r.uleb()
    if n != expected:
        raise ValueError(f"template count mismatch: header={n} "
                         f"trailer={expected}")
    tinfo: dict[int, dict] = {}
    for _ in range(n):
        tlen = r.uleb()
        tend = r.p + tlen
        tid = r.uleb()
        r.uleb()                     # start_pc
        n_insns = r.uleb()
        r.uleb()                     # fall_through
        sname = r.uleb()
        r.skip(sname)
        n_dyn = 0
        for _i in range(n_insns):
            r.uleb()                 # pc_delta
            r.u8()                   # opcode
            r.u8()                   # branch_type
            iflags = r.u8()
            n_src = r.u8()
            n_dst = r.u8()
            r.skip(n_src + n_dst)
            n_loads = r.u8()
            n_stores = r.u8()
            if iflags & _INSN_FLAG_HAS_IMM:
                r.sleb()
            isize = r.u8()
            r.skip(isize)
            if iflags & _INSN_FLAG_VARIABLE_MEMOP:
                n_dyn += 1
        if r.p != tend:
            raise ValueError(f"template {tid}: declared len {tlen} "
                             f"!= actual {r.p - (tend - tlen)}")
        tinfo[tid] = {"n_insns": n_insns, "n_dyn_insns": n_dyn}
    return r.p - start, tinfo


def _memop_preamble_bytes(rr: _R, info: dict | None) -> int:
    if info is None or info["n_dyn_insns"] == 0:
        return 0
    st = rr.p
    for _ in range(info["n_dyn_insns"]):
        rr.uleb()
        rr.uleb()
    return rr.p - st


def _dyn_patch_bytes(rr: _R) -> int:
    st = rr.p
    flags = rr.u8()
    if flags & dec.CST_DYN_FLAG_UNCHANGED:
        return rr.p - st
    rr.uleb()                         # new_len
    num_changed = rr.uleb()
    for _ in range(num_changed):
        rr.uleb()
        rr.sleb()
    return rr.p - st


def _read_lp_sub(rr: _R) -> tuple[_R, int]:
    st = rr.p
    n = rr.uleb()
    prefix = rr.p - st
    sub = rr.slice(n)
    return sub, prefix + n


def audit(path: Path) -> _Stats:
    fd = os.open(path, os.O_RDONLY)
    try:
        m = mmap.mmap(fd, 0, prot=mmap.PROT_READ)
    finally:
        os.close(fd)

    s = _Stats()
    s.file_size = len(m)

    # Trailer
    if len(m) < dec.CST_TRAILER_SIZE:
        raise ValueError("file too small for trailer")
    tr = _R(m, len(m) - dec.CST_TRAILER_SIZE)
    templates_off   = tr.u64_le()
    templates_count = tr.u64_le()
    body_off        = tr.u64_le()
    body_byte_count = tr.u64_le()
    trailer_magic   = tr.u64_le()
    if trailer_magic != dec.CST_TRAILER_MAGIC:
        raise ValueError(f"bad trailer magic 0x{trailer_magic:016x}")
    s.trailer = dec.CST_TRAILER_SIZE
    s.body_total = body_byte_count

    # Header
    hr = _R(m, 0)
    if hr.u32_le() != dec.CST_MAGIC:
        raise ValueError("bad header magic")
    hr.u8()                  # isa
    flags = hr.u8()
    hr.string_len()          # command
    hr.string_len()          # datetime
    hr.string_len()          # comment
    hr.string_len()          # target_name
    hr.uleb()                # thread_id
    s.header = hr.p
    has_mem_data = bool(flags & dec.CST_FLAG_MEM_DATA)
    has_reg_data = bool(flags & dec.CST_FLAG_REG_DATA)

    # Templates
    tr2 = _R(m, templates_off)
    s.templates_section, tinfo = _walk_templates(tr2, templates_count)
    s.templates_count = templates_count

    # Body
    br = _R(m, body_off, body_off + body_byte_count)
    prev_cp_tid = 0
    while True:
        tag_pos = br.p
        tag = br.u8()
        if tag == dec.BODY_TAG_END:
            br.uleb()
            s.body_terminator = br.p - tag_pos
            break
        if tag != dec.BODY_TAG_ENTRY:
            raise ValueError(f"unknown body tag {tag} at offset {tag_pos}")

        # CP framing = tag byte + template_id SLEB
        prev_cp_tid += br.sleb()
        s.cp_entry_framing.add(br.p - tag_pos)
        s.cp_entries += 1
        cp_info = tinfo.get(prev_cp_tid)
        if cp_info:
            s.cp_total_insns += cp_info["n_insns"]

        n = _memop_preamble_bytes(br, cp_info)
        if n:
            s.cp_dyn_memop_preamble.add(n)

        s.cp_dyn_patch.add(_dyn_patch_bytes(br))

        if has_mem_data:
            _sub, used = _read_lp_sub(br)
            s.cp_mem_data.add(used)
        if has_reg_data:
            _sub, used = _read_lp_sub(br)
            s.cp_reg_data.add(used)

        # WP chain
        wp_sub, wp_used = _read_lp_sub(br)
        s.wp_chain_envelope.add(wp_used)
        num_wp = wp_sub.uleb()
        prev_wp_tid = 0
        for _w in range(num_wp):
            wfs = wp_sub.p
            prev_wp_tid += wp_sub.sleb()
            s.wp_entry_framing.add(wp_sub.p - wfs)
            wp_info = tinfo.get(prev_wp_tid)
            if wp_info:
                s.wp_total_insns += wp_info["n_insns"]
            n = _memop_preamble_bytes(wp_sub, wp_info)
            if n:
                s.wp_dyn_memop_preamble.add(n)
            s.wp_dyn_patch.add(_dyn_patch_bytes(wp_sub))
            if has_mem_data:
                _sub, used = _read_lp_sub(wp_sub)
                s.wp_mem_data.add(used)
            if has_reg_data:
                _sub, used = _read_lp_sub(wp_sub)
                s.wp_reg_data.add(used)
        s.wp_entries_total += num_wp

        _ev_sub, ev_used = _read_lp_sub(br)
        s.wp_events.add(ev_used)

    return s


# ---------------------------------------------------------------------------
# Reporting.
# ---------------------------------------------------------------------------

def _human(n: float) -> str:
    if n < 1024:
        return f"{int(n)} B"
    for u in ("KiB", "MiB", "GiB", "TiB", "PiB"):
        n /= 1024
        if n < 1024:
            return f"{n:.2f} {u}"
    return f"{n:.2f} PiB"


def _row(label: str, b: int, total: int,
         count: int | None = None, per: str | None = None) -> str:
    pct = (100.0 * b / total) if total else 0.0
    extra = ""
    if count:
        extra = f"  [{count:>10,} {per or 'evt'}, avg {b / count:6.1f} B]"
    return f"  {label:<34} {_human(b):>14}  {pct:6.2f}%{extra}"


def report(s: _Stats) -> str:
    lines: list[str] = []
    out = lines.append
    total = s.file_size

    out(f"FILE                                {_human(total):>14}  100.00%")
    out("")
    out("=== TOP-LEVEL SECTIONS ===")
    out(_row("HEADER", s.header, total))
    out(_row("TEMPLATES", s.templates_section, total,
             count=s.templates_count, per="tmpl"))
    out(_row("BODY", s.body_total, total))
    out(_row("TRAILER", s.trailer, total))

    body = s.body_total
    out("")
    out(f"=== BODY BREAKDOWN ({_human(body)}) ===")
    out(_row("CP entry framing",
             s.cp_entry_framing.bytes, body,
             count=s.cp_entries, per="entry"))
    if s.cp_dyn_memop_preamble.count:
        out(_row("CP dyn-memop preamble",
                 s.cp_dyn_memop_preamble.bytes, body,
                 count=s.cp_dyn_memop_preamble.count, per="entry"))
    out(_row("CP dyn-patch",
             s.cp_dyn_patch.bytes, body,
             count=s.cp_entries, per="entry"))
    if s.cp_mem_data.count:
        out(_row("CP mem-data",
                 s.cp_mem_data.bytes, body,
                 count=s.cp_mem_data.count, per="entry"))
    if s.cp_reg_data.count:
        out(_row("CP reg-data",
                 s.cp_reg_data.bytes, body,
                 count=s.cp_reg_data.count, per="entry"))

    out(_row("WP chain envelope (incl. inner)",
             s.wp_chain_envelope.bytes, body,
             count=s.cp_entries, per="entry"))
    out("    expanded:")
    out(_row("    WP entry framing",
             s.wp_entry_framing.bytes, body,
             count=s.wp_entry_framing.count, per="WP"))
    if s.wp_dyn_memop_preamble.count:
        out(_row("    WP dyn-memop preamble",
                 s.wp_dyn_memop_preamble.bytes, body,
                 count=s.wp_dyn_memop_preamble.count, per="WP"))
    out(_row("    WP dyn-patch",
             s.wp_dyn_patch.bytes, body,
             count=s.wp_entries_total, per="WP"))
    if s.wp_mem_data.count:
        out(_row("    WP mem-data",
                 s.wp_mem_data.bytes, body,
                 count=s.wp_mem_data.count, per="WP"))
    if s.wp_reg_data.count:
        out(_row("    WP reg-data",
                 s.wp_reg_data.bytes, body,
                 count=s.wp_reg_data.count, per="WP"))

    out(_row("WP events", s.wp_events.bytes, body,
             count=s.cp_entries, per="entry"))
    out(_row("BODY terminator", s.body_terminator, body))

    out("")
    out("=== ENTRIES & INSNS ===")
    out(f"  CP entries           {s.cp_entries:>14,}")
    out(f"  WP entries (total)   {s.wp_entries_total:>14,}")
    out(f"  CP insns (total)     {s.cp_total_insns:>14,}")
    out(f"  WP insns (total)     {s.wp_total_insns:>14,}")
    if s.cp_total_insns:
        out(f"  bytes / CP insn      {body / s.cp_total_insns:>14.2f}")
    all_insns = s.cp_total_insns + s.wp_total_insns
    if all_insns:
        out(f"  bytes / any insn     {body / all_insns:>14.2f}")
    if s.cp_entries:
        out(f"  WPs / CP entry       "
            f"{s.wp_entries_total / s.cp_entries:>14.2f}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Audit byte composition of an (uncompressed) .cst trace.")
    ap.add_argument("trace", type=Path,
                    help="Path to a decompressed .cst file.")
    args = ap.parse_args()
    s = audit(args.trace)
    print(report(s))
    return 0


if __name__ == "__main__":
    sys.exit(main())
