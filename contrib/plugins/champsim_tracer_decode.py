#!/usr/bin/env python3
"""
Reference decoder for the champsim_tracer binary trace format v1.2.

Format v1.2 is byte-aligned throughout: every record and sub-record
starts on a byte boundary, and most fields are plain u8 / u32 / u64
or ULEB128/SLEB128.  See champsim_tracer_format.md for the full spec.
"""

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


# --- Format constants ------------------------------------------------

# 'C','S','T',0x11 little-endian
CST_MAGIC = 0x12545343
CST_TRAILER_MAGIC = 0x12545343FFFFFFFF
CST_TRAILER_SIZE = 64

CST_FLAG_MEM_DATA      = 1 << 0
CST_FLAG_REG_DATA      = 1 << 1

# Body entry tags (u8)
BODY_TAG_END      = 0
BODY_TAG_ENTRY    = 1

# Per-insn template flags (u8)
CST_INSN_FLAG_BRANCH_COND    = 1 << 0
CST_INSN_FLAG_HAS_IMM        = 1 << 1
CST_INSN_FLAG_SYNC_SHIFT     = 2
CST_INSN_FLAG_SYNC_MASK      = 0x3C
CST_INSN_FLAG_DYNAMIC_MEMOP  = 1 << 6

# WP event flags (u8)
CST_WP_EVENT_TRANSLATION_UNAVAIL = 1 << 0
CST_WP_EVENT_FAULT               = 1 << 1

# Dyn-patch flags (u8)
CST_DYN_FLAG_UNCHANGED = 1 << 0

# Generic opcodes (subset needed by decoder to classify load/store)
GEN_OP_LOAD  = 15
GEN_OP_STORE = 16

BRANCH_NONE = 0

# ISA enum (must match TraceISA in champsim_tracer_mnemonics.h)
ISA_NAMES = {
    0: "unknown",
    1: "x86_64",
    2: "aarch64",
    3: "riscv64",
    4: "mipsel",
}

# Sync hints
SYNC_NONE          = 0
SYNC_THREAD_SWITCH = 4
SYNC_ATOMIC        = 5
SYNC_HINT_NAMES = {0: "NONE", 4: "THREAD_SWITCH", 5: "ATOMIC"}

OPCODE_NAMES = {
    0: "UNKNOWN", 1: "INT_ADD", 2: "INT_SUB", 3: "INT_MUL", 4: "INT_DIV",
    5: "AND", 6: "OR", 7: "XOR", 8: "NOT",
    9: "SHL", 10: "SHR", 11: "SAR", 12: "ROL", 13: "ROR",
    14: "MOV", 15: "LOAD", 16: "STORE", 17: "PUSH", 18: "POP",
    19: "LEA", 20: "MOVSX", 21: "MOVZX", 22: "XCHG",
    23: "CMP", 24: "TEST", 25: "BRANCH", 26: "CALL", 27: "RET",
    28: "FP_ADD", 29: "FP_SUB", 30: "FP_MUL", 31: "FP_DIV", 32: "FP_SQRT",
    33: "FP_MOV", 34: "FP_CVT", 35: "FP_CMP",
    36: "VEC_ADD", 37: "VEC_SUB", 38: "VEC_MUL", 39: "VEC_MOV",
    40: "VEC_SHUF", 41: "VEC_LOGIC",
    42: "NOP", 43: "SYSCALL", 44: "FENCE",
    45: "CMOV", 46: "SETCC",
    47: "INT_ADC", 48: "INT_SBB", 49: "NEG", 50: "INC", 51: "DEC",
}

BRANCH_NAMES = {
    0: "NONE",
    1: "DIRECT_JUMP", 2: "INDIRECT_JUMP",
    3: "DIRECT_CALL", 4: "INDIRECT_CALL",
    5: "RETURN", 6: "SYSCALL", 7: "COND_DIRECT",
}

EXCEPTION_NAMES_DEFAULT = {
    0: "NONE", 1: "UNKNOWN",
    2: "INT_DIVIDE_BY_ZERO", 3: "FP_DIVIDE_BY_ZERO",
    4: "MEMORY_ACCESS",
}

WP_STOP_REASON_NAMES = {0: "NONE", 1: "SYSCALL_USERMODE"}

# Byte sizes for 3-bit mem-data size codes
_MEM_DATA_SIZE_TABLE = [1, 2, 4, 8, 16, 1, 1, 1]


def build_reg_names() -> dict[int, str]:
    names: dict[int, str] = {0: "NONE"}
    for i in range(64):
        names[1 + i]   = f"GPR{i}"
        names[65 + i]  = f"FPR{i}"
        names[129 + i] = f"VEC{i}"
    names[250] = "SP"
    names[251] = "FLAGS"
    names[252] = "IP"
    names[253] = "LR"
    names[254] = "FP"
    return names


REG_NAMES_DEFAULT = build_reg_names()


def reg_name(reg_id: int) -> str:
    return REG_NAMES_DEFAULT.get(reg_id, f"R{reg_id}")


@dataclass
class DynParam:
    type_name: str         # "load" or "store"
    value: int
    data_size: int = 0
    data_lo: int = 0
    data_hi: int = 0
    insn_index: int = -1


# --- Byte reader -----------------------------------------------------

class ByteReader:
    """Stateful byte-stream reader over an in-memory buffer."""

    __slots__ = ("data", "pos", "end")

    def __init__(self, data: bytes, pos: int = 0, end: int | None = None):
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else end

    def eof(self) -> bool:
        return self.pos >= self.end

    def u8(self) -> int:
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u32_le(self) -> int:
        v = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return v

    def u64_le(self) -> int:
        v = struct.unpack_from("<Q", self.data, self.pos)[0]
        self.pos += 8
        return v

    def raw(self, n: int) -> bytes:
        b = bytes(self.data[self.pos:self.pos + n])
        self.pos += n
        return b

    def uleb(self) -> int:
        out = 0
        shift = 0
        while True:
            b = self.u8()
            out |= (b & 0x7F) << shift
            if not (b & 0x80):
                return out
            shift += 7
            if shift > 70:
                raise ValueError("ULEB128 too large")

    def sleb(self) -> int:
        out = 0
        shift = 0
        while True:
            b = self.u8()
            out |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                if b & 0x40 and shift < 64:
                    out |= -(1 << shift)
                return out
            if shift > 70:
                raise ValueError("SLEB128 too large")

    def string(self) -> str:
        n = self.uleb()
        if n == 0:
            return ""
        return self.raw(n).decode("utf-8", errors="replace")

    def sub(self) -> "ByteReader":
        """Read a ULEB128 length + that many bytes, return a ByteReader
        scoped to that slice.  Advances the outer cursor past it."""
        n = self.uleb()
        start = self.pos
        self.pos += n
        return ByteReader(self.data, start, start + n)


def _add_delta_u64(base: int, delta: int) -> int:
    return (base + delta) & ((1 << 64) - 1)


# --- Template decoding ----------------------------------------------

def _decode_template_record(br: ByteReader) -> dict:
    template_id     = br.uleb()
    start_pc        = br.uleb()
    n_insns         = br.uleb()
    fall_through_pc = br.uleb()
    symbol_name     = br.string()

    insns: list[dict] = []
    prev_pc = start_pc
    for _ in range(n_insns):
        delta = br.uleb()
        pc = _add_delta_u64(prev_pc, delta)
        prev_pc = pc

        opcode      = br.u8()
        branch_type = br.u8()
        flags       = br.u8()
        n_src       = br.u8()
        n_dst       = br.u8()
        src_regs = [br.u8() for _ in range(n_src)]
        dst_regs = [br.u8() for _ in range(n_dst)]
        n_loads  = br.u8()
        n_stores = br.u8()

        branch_conditional = bool(flags & CST_INSN_FLAG_BRANCH_COND)
        has_imm            = bool(flags & CST_INSN_FLAG_HAS_IMM)
        sync_hint          = (flags & CST_INSN_FLAG_SYNC_MASK) \
                             >> CST_INSN_FLAG_SYNC_SHIFT
        dynamic_memop      = bool(flags & CST_INSN_FLAG_DYNAMIC_MEMOP)

        imm = br.sleb() if has_imm else None
        insn_size = br.u8()
        raw_bytes = br.raw(insn_size)

        insns.append({
            "pc": pc,
            "opcode": opcode,
            "branch_type": branch_type,
            "branch_conditional": branch_conditional,
            "src_regs": src_regs,
            "dst_regs": dst_regs,
            "imm": imm,
            "sync_hint": sync_hint,
            "n_loads": n_loads,
            "n_stores": n_stores,
            "dynamic_memop": dynamic_memop,
            "raw_bytes": raw_bytes,
        })

    return {
        "template_id": template_id,
        "start_pc": start_pc,
        "n_insns": n_insns,
        "fall_through_pc": fall_through_pc,
        "symbol_name": symbol_name,
        "insns": insns,
    }


def _decode_templates_section(br: ByteReader,
                              count: int
                              ) -> tuple[list[dict], dict[int, dict]]:
    templates: list[dict] = []
    template_by_id: dict[int, dict] = {}
    for _ in range(count):
        sub = br.sub()
        tmpl = _decode_template_record(sub)
        templates.append(tmpl)
        template_by_id[tmpl["template_id"]] = tmpl
    return templates, template_by_id


# --- Body decoding ---------------------------------------------------

def _classify_dyn_params_by_schema(
        dps: list[DynParam],
        tmpl: dict | None,
        actual_counts: list[tuple[int, int]]) -> None:
    """Assign (type_name, insn_index) to each param by walking the
    template's per-insn (n_loads, n_stores) schema.  For insns with
    the DYNAMIC_MEMOP flag, use actual_counts (list of (n_l, n_s)
    tuples in template-insn order of dynamic insns)."""
    if not tmpl:
        for dp in dps:
            dp.type_name = "load"
            dp.insn_index = -1
        return
    dyn_iter = iter(actual_counts)
    pos = 0
    for i, insn in enumerate(tmpl["insns"]):
        if insn.get("dynamic_memop"):
            try:
                n_l, n_s = next(dyn_iter)
            except StopIteration:
                n_l, n_s = insn.get("n_loads", 0), insn.get("n_stores", 0)
        else:
            n_l = insn.get("n_loads", 0)
            n_s = insn.get("n_stores", 0)
        for _ in range(n_l):
            if pos >= len(dps):
                return
            dps[pos].type_name = "load"
            dps[pos].insn_index = i
            pos += 1
        for _ in range(n_s):
            if pos >= len(dps):
                return
            dps[pos].type_name = "store"
            dps[pos].insn_index = i
            pos += 1


def _read_dynamic_memop_preamble(br: ByteReader,
                                 tmpl: dict | None
                                 ) -> list[tuple[int, int]]:
    """Read per-entry (n_loads, n_stores) pairs for each template insn
    flagged DYNAMIC_MEMOP, in template-insn order."""
    if not tmpl:
        return []
    out = []
    for insn in tmpl["insns"]:
        if insn.get("dynamic_memop"):
            n_l = br.uleb()
            n_s = br.uleb()
            out.append((n_l, n_s))
    return out


def _decode_dyn_patch(br: ByteReader,
                      prev_dyn: list[DynParam]
                      ) -> tuple[bool, list[DynParam]]:
    """Returns (unchanged, new_dyn).  When unchanged, caller reuses
    the prior state verbatim."""
    flags = br.u8()
    if flags & CST_DYN_FLAG_UNCHANGED:
        return True, []

    new_len     = br.uleb()
    num_changed = br.uleb()

    out: list[DynParam] = []
    for i in range(new_len):
        if i < len(prev_dyn):
            p = prev_dyn[i]
            out.append(DynParam(type_name=p.type_name, value=p.value))
        else:
            out.append(DynParam(type_name="load", value=0))

    prev_pos = -1
    for _ in range(num_changed):
        pos_gap = br.uleb()
        pos = prev_pos + 1 + pos_gap
        if pos >= new_len:
            raise ValueError("Patch position out of range")
        delta = br.sleb()
        base = prev_dyn[pos].value if pos < len(prev_dyn) else 0
        out[pos] = DynParam(type_name="load",
                            value=_add_delta_u64(base, delta))
        prev_pos = pos
    return False, out


def _read_mem_data_values(br: ByteReader, params: list[DynParam]) -> None:
    for dp in params:
        code = br.u8()
        sz = _MEM_DATA_SIZE_TABLE[code]
        dp.data_size = sz
        lo = 0
        for b in range(min(sz, 8)):
            lo |= br.u8() << (b * 8)
        dp.data_lo = lo
        hi = 0
        if sz > 8:
            for b in range(sz - 8):
                hi |= br.u8() << (b * 8)
        dp.data_hi = hi


_REG_NONE = 0


def _read_reg_data_section(
    br: "ByteReader",
    cp_tmpl: dict | None,
    state_lo: list[int],
    state_hi: list[int],
) -> list[dict]:
    """Read \u00a75.2 reg-data section: per-insn src then dst snapshots,
    each {size_code:u8, delta_lo:SLEB, [delta_hi:SLEB if 16B]}.

    Updates `state_lo`/`state_hi` (indexed by GenericRegId 0..255) so
    subsequent entries can recover absolute values.  Returns a list
    of {"insn_index", "kind"("src"|"dst"), "operand_index",
    "reg_id", "size_code", "lo", "hi"} dicts in stream order.
    """
    snaps: list[dict] = []
    if cp_tmpl is None:
        return snaps
    insns = cp_tmpl.get("insns", [])
    for i, insn in enumerate(insns):
        for kind, regs in (("src", insn.get("src_regs", [])),
                           ("dst", insn.get("dst_regs", []))):
            for op_i, reg_id in enumerate(regs):
                code = br.u8()
                if code > 2:
                    raise ValueError(f"bad reg-data size_code: {code}")
                delta_lo = br.sleb()
                if reg_id != _REG_NONE:
                    state_lo[reg_id] = (state_lo[reg_id] + delta_lo) & ((1 << 64) - 1)
                    lo = state_lo[reg_id]
                else:
                    lo = delta_lo & ((1 << 64) - 1)
                hi = 0
                if code == 2:
                    delta_hi = br.sleb()
                    if reg_id != _REG_NONE:
                        state_hi[reg_id] = (state_hi[reg_id] + delta_hi) & ((1 << 64) - 1)
                        hi = state_hi[reg_id]
                    else:
                        hi = delta_hi & ((1 << 64) - 1)
                snaps.append({
                    "insn_index": i,
                    "kind": kind,
                    "operand_index": op_i,
                    "reg_id": reg_id,
                    "size_code": code,
                    "lo": lo,
                    "hi": hi,
                })
    return snaps


def decode_champsim_tracer(bin_path: Path
                           ) -> tuple[dict, list[dict], list[dict]]:
    """Decode a v1.2 trace file.  Returns (meta, templates, entries).
    Public API; stable across minor revisions of the decoder."""
    data = bin_path.read_bytes()
    if len(data) < CST_TRAILER_SIZE:
        raise ValueError("Trace file too small to contain a trailer")

    # --- Read trailer from end of file ---
    trailer = ByteReader(data, len(data) - CST_TRAILER_SIZE)
    templates_off   = trailer.u64_le()
    templates_count = trailer.u64_le()
    body_off        = trailer.u64_le()
    body_byte_count = trailer.u64_le()
    trailer_magic   = trailer.u64_le()
    if trailer_magic != CST_TRAILER_MAGIC:
        raise ValueError(
            f"Bad trailer magic 0x{trailer_magic:016x}, "
            f"expected 0x{CST_TRAILER_MAGIC:016x}"
        )

    # --- Read header ---
    br = ByteReader(data)
    magic = br.u32_le()
    if magic != CST_MAGIC:
        raise ValueError(
            f"Bad magic 0x{magic:08x}, expected 0x{CST_MAGIC:08x}"
        )
    isa          = br.u8()
    flags        = br.u8()
    command      = br.string()
    datetime_str = br.string()
    comment      = br.string()
    target_name  = br.string()
    thread_id    = br.uleb()

    has_mem_data = bool(flags & CST_FLAG_MEM_DATA)
    has_reg_data = bool(flags & CST_FLAG_REG_DATA)

    # --- Read templates first (always present since v1.1) ---
    templates: list[dict] = []
    template_by_id: dict[int, dict] = {}
    if templates_count > 0:
        tbr = ByteReader(data, templates_off)
        n = tbr.uleb()
        if n != templates_count:
            raise ValueError(
                f"template count mismatch: header={n} trailer={templates_count}"
            )
        templates, template_by_id = _decode_templates_section(tbr, n)

    # --- Read body ---
    body = ByteReader(data, body_off, body_off + body_byte_count)

    entries: list[dict] = []
    prev_entry_template = 0
    cp_dyn_state: dict[int, list[DynParam]] = {}
    wp_dyn_state: dict[int, list[DynParam]] = {}
    # Per-GenericRegId last-value state for \u00a75.2 reg-data SLEB deltas
    # (CP only in v1).  Indexed 0..255; reset to zero at body start.
    cp_reg_state_lo: list[int] = [0] * 256
    cp_reg_state_hi: list[int] = [0] * 256
    footer_num_entries: int | None = None

    while True:
        tag = body.u8()

        if tag == BODY_TAG_END:
            footer_num_entries = body.uleb()
            break

        if tag != BODY_TAG_ENTRY:
            raise ValueError(f"Unknown body tag: {tag}")

        entry_tmpl = prev_entry_template + body.sleb()
        prev_entry_template = entry_tmpl

        cp_tmpl = template_by_id.get(entry_tmpl)
        cp_dynamic_counts = _read_dynamic_memop_preamble(body, cp_tmpl)

        # CP dyn-patch
        prev_cp = cp_dyn_state.get(entry_tmpl, [])
        unchanged, cp_dyn = _decode_dyn_patch(body, prev_cp)
        if unchanged:
            if entry_tmpl not in cp_dyn_state:
                raise ValueError("cp dyn_unchanged without prior state")
            cp_dyn = [DynParam(type_name=d.type_name,
                               value=d.value,
                               insn_index=d.insn_index)
                      for d in cp_dyn_state[entry_tmpl]]
        else:
            _classify_dyn_params_by_schema(cp_dyn, cp_tmpl, cp_dynamic_counts)
            cp_dyn_state[entry_tmpl] = [
                DynParam(type_name=d.type_name,
                         value=d.value,
                         insn_index=d.insn_index)
                for d in cp_dyn]

        # CP mem_data sub-section
        if has_mem_data:
            mdb = body.sub()
            _read_mem_data_values(mdb, cp_dyn)

        # CP reg_data sub-section
        cp_reg_snaps: list[dict] = []
        if has_reg_data:
            rdb = body.sub()
            cp_reg_snaps = _read_reg_data_section(
                rdb, cp_tmpl, cp_reg_state_lo, cp_reg_state_hi)

        # WP chain sub-section
        wp_entries: list[dict] = []
        wpb = body.sub()
        num_wp = wpb.uleb()
        prev_wp_tmpl = 0
        # Seed WP reg-state from the current CP reg-state.  Wrong-path
        # execution begins at the CP architectural state and is rolled
        # back at chain end, so cross-chain accumulation would be wrong.
        wp_reg_state_lo = list(cp_reg_state_lo)
        wp_reg_state_hi = list(cp_reg_state_hi)
        for w in range(num_wp):
            wp_tmpl = prev_wp_tmpl + wpb.sleb()
            prev_wp_tmpl = wp_tmpl

            wp_tmpl_dict = template_by_id.get(wp_tmpl)
            wp_dynamic_counts = _read_dynamic_memop_preamble(wpb, wp_tmpl_dict)

            prev_wp = wp_dyn_state.get(wp_tmpl, [])
            wunchanged, wp_dyn = _decode_dyn_patch(wpb, prev_wp)
            if wunchanged:
                if wp_tmpl not in wp_dyn_state:
                    raise ValueError("wp dyn_unchanged without prior state")
                wp_dyn = [DynParam(type_name=d.type_name,
                                   value=d.value,
                                   insn_index=d.insn_index)
                          for d in wp_dyn_state[wp_tmpl]]
            else:
                _classify_dyn_params_by_schema(wp_dyn, wp_tmpl_dict,
                                               wp_dynamic_counts)
                wp_dyn_state[wp_tmpl] = [
                    DynParam(type_name=d.type_name,
                             value=d.value,
                             insn_index=d.insn_index)
                    for d in wp_dyn]

            if has_mem_data:
                wmdb = wpb.sub()
                _read_mem_data_values(wmdb, wp_dyn)

            if has_reg_data:
                wrdb = wpb.sub()
                wp_reg_snaps = _read_reg_data_section(
                    wrdb, wp_tmpl_dict, wp_reg_state_lo, wp_reg_state_hi)
            else:
                wp_reg_snaps = []

            wp_entries.append({
                "index": w,
                "template_id": wp_tmpl,
                "dyn_params": wp_dyn,
                "reg_snaps": wp_reg_snaps,
                "fault": False,
                "translation_unavailable": False,
                "fault_insn_index": None,
                "n_insns": template_by_id.get(wp_tmpl, {}).get("n_insns", 0),
            })

        # WP events sub-section
        evb = body.sub()
        num_events = evb.uleb()
        prev_evt_idx = -1
        for _ in range(num_events):
            gap = evb.uleb()
            idx = prev_evt_idx + 1 + gap
            if idx >= num_wp:
                raise ValueError("wp event index out of range")
            evf = evb.u8()
            wp_entries[idx]["translation_unavailable"] = bool(
                evf & CST_WP_EVENT_TRANSLATION_UNAVAIL)
            is_fault = bool(evf & CST_WP_EVENT_FAULT)
            wp_entries[idx]["fault"] = is_fault
            if is_fault:
                # v1.2: chain-relative index of the faulting insn.
                wp_entries[idx]["fault_insn_index"] = evb.uleb()
            prev_evt_idx = idx

        entries.append({
            "seq_num": len(entries) + 1,
            "template_id": entry_tmpl,
            "dyn_params": cp_dyn,
            "reg_snaps": cp_reg_snaps,
            "wp_entries": wp_entries,
        })

    if footer_num_entries is not None and footer_num_entries != len(entries):
        raise ValueError(
            f"Footer entry count mismatch: "
            f"{footer_num_entries} != {len(entries)}"
        )

    meta = {
        "magic": magic,
        "isa": isa,
        "target_name": target_name,
        "flags": flags,
        "command": command,
        "datetime": datetime_str,
        "comment": comment,
        "has_mem_data": has_mem_data,
        "has_reg_data": has_reg_data,
        "thread_id": thread_id,
        "templates_off": templates_off,
        "templates_count": templates_count,
        "body_off": body_off,
        "body_byte_count": body_byte_count,
        "opcode_names": dict(OPCODE_NAMES),
        "branch_names": dict(BRANCH_NAMES),
        "stop_reason_names": dict(WP_STOP_REASON_NAMES),
        "exception_names": dict(EXCEPTION_NAMES_DEFAULT),
        "reg_names": dict(REG_NAMES_DEFAULT),
    }
    return meta, templates, entries


# --- Text renderer ---------------------------------------------------

def _format_dyn(dp: DynParam, show_data: bool) -> str:
    s = f"{dp.type_name}=0x{dp.value:x}"
    if show_data and dp.data_size > 0:
        if dp.data_size <= 8:
            s += f":data=0x{dp.data_lo:x}"
        else:
            s += f":data=0x{dp.data_hi:x}{dp.data_lo:016x}"
    return s


def render_text(meta: dict, templates: list[dict], entries: list[dict]) -> str:
    out: list[str] = []
    opcode_names = meta.get("opcode_names", OPCODE_NAMES)
    branch_names = meta.get("branch_names", BRANCH_NAMES)
    stop_reason_names = meta.get("stop_reason_names", WP_STOP_REASON_NAMES)
    exception_names = meta.get("exception_names", EXCEPTION_NAMES_DEFAULT)
    reg_names = meta.get("reg_names", REG_NAMES_DEFAULT)
    has_mem_data = meta.get("has_mem_data", False)

    def rfmt(r: int) -> str:
        return reg_names.get(r, reg_name(r))

    out.append("META")
    out.append("----")
    out.append(f"VERSION 0x{meta.get('magic', CST_MAGIC):08X}")
    isa_name = meta.get("target_name") or ISA_NAMES.get(meta.get("isa", 0),
                                                        "unknown")
    out.append(f"ISA {isa_name}")
    out.append(f"COMMAND {meta.get('command', '')}")
    out.append(f"DATETIME {meta.get('datetime', '')}")
    out.append(f"COMMENT {meta.get('comment', '')}")
    out.append(f"THREAD {meta.get('thread_id', 0)}")
    flags_str = ""
    if has_mem_data:
        flags_str += " MEM_DATA"
    out.append(f"FLAGS{flags_str}")
    out.append("")

    out.append("ENUMS")
    out.append("-----")
    out.append(f"OPCODES {len(opcode_names)}")
    for k in sorted(opcode_names):
        out.append(f"O {k} {opcode_names[k]}")
    out.append(f"BRANCHES {len(branch_names)}")
    for k in sorted(branch_names):
        out.append(f"B {k} {branch_names[k]}")
    out.append(f"WP_STOP_REASONS {len(stop_reason_names)}")
    for k in sorted(stop_reason_names):
        out.append(f"S {k} {stop_reason_names[k]}")
    out.append(f"EXCEPTIONS {len(exception_names)}")
    for k in sorted(exception_names):
        out.append(f"E {k} {exception_names[k]}")
    out.append(f"REGS {len(reg_names)}")
    for k in sorted(reg_names):
        out.append(f"R {k} {reg_names[k]}")
    out.append("")

    out.append("HEADER")
    out.append("------")
    for tmpl in templates:
        out.append(
            f"BB{tmpl['template_id']} [pc=0x{tmpl['start_pc']:x}, "
            f"insns={tmpl['n_insns']}, "
            f"fall_through=0x{tmpl['fall_through_pc']:x}]"
        )
        if tmpl.get("symbol_name"):
            out.append(f"  symbol={tmpl['symbol_name']}")
        for i, insn in enumerate(tmpl["insns"]):
            line = (f"  [{i}] 0x{insn['pc']:x}: "
                    f"op={opcode_names.get(insn['opcode'], 'UNKNOWN')}")
            if insn["branch_type"] != BRANCH_NONE:
                line += (f" br={branch_names.get(insn['branch_type'], 'UNKNOWN')}"
                         f" cond={1 if insn['branch_conditional'] else 0}")
            src = ",".join(rfmt(r) for r in insn["src_regs"])
            dst = ",".join(rfmt(r) for r in insn["dst_regs"])
            line += f" src=[{src}] dst=[{dst}]"
            if insn["imm"] is not None:
                line += f" imm={insn['imm']}"
            if insn.get("sync_hint", 0) != 0:
                line += f" sync={SYNC_HINT_NAMES.get(insn['sync_hint'], 'UNKNOWN')}"
            if insn.get("raw_bytes") is not None:
                line += f" bytes={insn['raw_bytes'].hex()}"
            out.append(line)
        out.append("")

    out.append("BODY")
    out.append("----")
    for entry_idx, entry in enumerate(entries):
        dyn_str = " ".join(_format_dyn(dp, has_mem_data)
                           for dp in entry["dyn_params"])
        line = f"{entry['seq_num']:04d} BB{entry['template_id']} [{dyn_str}]"
        for wp in entry["wp_entries"]:
            line += f" [wp{wp['index']}=BB{wp['template_id']}"
            for dp in wp["dyn_params"]:
                line += f" {_format_dyn(dp, has_mem_data)}"
            if wp["fault"]:
                fi = wp.get("fault_insn_index")
                if fi is not None:
                    line += f" FAULT@insn{fi}"
                else:
                    line += " FAULT"
            if wp.get("translation_unavailable"):
                line += " TRANSLATION_UNAVAILABLE"
            line += f" n_insns={wp['n_insns']}]"
        out.append(line)
        _ = exception_names, stop_reason_names  # referenced for API parity

    return "\n".join(out) + "\n"


def _first_diff_line(a: str, b: str) -> tuple[int, str, str] | None:
    al, bl = a.splitlines(), b.splitlines()
    for i in range(max(len(al), len(bl))):
        left  = al[i] if i < len(al) else "<EOF>"
        right = bl[i] if i < len(bl) else "<EOF>"
        if left != right:
            return i + 1, left, right
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode champsim_tracer binary (.wpt, v1.2) to text")
    parser.add_argument("bin", type=Path)
    parser.add_argument("-o", "--out", type=Path)
    parser.add_argument("--expect", type=Path)
    args = parser.parse_args()

    meta, templates, entries = decode_champsim_tracer(args.bin)
    text = render_text(meta, templates, entries)
    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)

    if args.expect:
        expected = args.expect.read_text()
        if text == expected:
            print("VERIFY: OK")
            return 0
        diff = _first_diff_line(text, expected)
        if diff:
            ln, got, exp = diff
            print(f"VERIFY: FAIL at line {ln}")
            print(f"  got: {got}")
            print(f"  exp: {exp}")
        else:
            print("VERIFY: FAIL (content differs)")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
