#!/usr/bin/env python3
"""
Reference decoder for the champsim_tracer binary trace format v1.7.

The body uses one unified field-typed delta stream per CP or WP basic
block.  Each BB entry carries:

    n_records : ULEB
    { ins_pos_gap : ULEB,  field_id : u8,  delta : SLEB128 } *

Records are sorted in non-descending (ins_pos, field_id) order; an
absent (template_id, ins_pos, field_id) triple means "field unchanged
since last correct-path emission, or equal to template default if
never observed".  The delta is `(cur128 − baseline128) mod 2**128`.

Field IDs are dispatched through ``FIELD_DESCRIPTORS`` below — adding
a new dynamic field is one entry there, mirroring the FieldDescriptor
table in champsim_tracer_output.cc.
"""

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


# --- Format constants ------------------------------------------------

# 'C','S','T',0x17 little-endian
CST_MAGIC = 0x17545343
CST_TRAILER_MAGIC = 0x17545343FFFFFFFF
CST_TRAILER_SIZE = 64

CST_FLAG_MEM_DATA      = 1 << 0
CST_FLAG_REG_DATA      = 1 << 1
CST_FLAG_RESERVED_2    = 1 << 2

# Body entry tags (u8)
BODY_TAG_END             = 0
BODY_TAG_ENTRY           = 1
BODY_TAG_THREAD_SWITCH   = 2

# Per-insn template flags (u8)
CST_INSN_FLAG_BRANCH_COND    = 1 << 0
CST_INSN_FLAG_HAS_IMM        = 1 << 1
CST_INSN_FLAG_SYNC_SHIFT     = 2
CST_INSN_FLAG_SYNC_MASK      = 0x3C

# WP event flags (u8)
CST_WP_EVENT_TRANSLATION_UNAVAIL = 1 << 0
CST_WP_EVENT_FAULT               = 1 << 1

# Field-ID space (mirrors champsim_tracer.h CST_FID_*)
FID_SLOT_COUNT       = 16
FID_N_LOADS          = 0x00
FID_LOAD_ADDR_BASE   = 0x01
FID_STORE_ADDR_BASE  = 0x11
FID_LOAD_DATA_BASE   = 0x21
FID_STORE_DATA_BASE  = 0x31
FID_SRC_REG_BASE     = 0x41
FID_N_STORES         = 0x61
FID_INSN_BYTES_LO    = 0x70
FID_INSN_BYTES_HI    = 0x71
FID_INSN_OPCODE      = 0x72
FID_INSN_BRANCH_TYPE = 0x73
FID_INSN_FLAGS       = 0x74
FID_INSN_IMMEDIATE   = 0x75
FID_INSN_SIZE        = 0x76
FID_EXTENDED         = 0xFF

MASK128 = (1 << 128) - 1
MASK64  = (1 << 64) - 1

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
SYNC_HINT_NAMES = {0: "SYNC_NONE", 4: "SYNC_THREAD_SWITCH", 5: "SYNC_ATOMIC"}

OPCODE_NAMES = {
    0: "UNKNOWN", 1: "INT_ADD", 2: "INT_SUB", 3: "INT_MUL", 4: "INT_DIV",
    5: "AND", 6: "OR", 7: "XOR", 8: "NOT",
    9: "SHL", 10: "SHR", 11: "SAR", 12: "ROL", 13: "ROR",
    14: "MOV", 15: "LOAD", 16: "STORE", 17: "PUSH", 18: "POP",
    19: "LEA", 20: "MOVSX", 21: "MOVZX", 22: "XCHG",
    23: "CMP", 24: "TEST", 25: "BRANCH", 27: "RET",
    28: "FP_ADD", 29: "FP_SUB", 30: "FP_MUL", 31: "FP_DIV", 32: "FP_SQRT",
    33: "FP_MOV", 34: "FP_CVT", 35: "FP_CMP",
    36: "VEC_ADD", 37: "VEC_SUB", 38: "VEC_MUL", 39: "VEC_MOV",
    40: "VEC_SHUF", 41: "VEC_LOGIC",
    42: "NOP", 43: "SYSCALL", 44: "FENCE",
    45: "CMOV", 46: "SETCC",
    47: "INT_ADC", 48: "INT_SBB", 49: "NEG", 50: "INC", 51: "DEC",
    52: "INT_MADD", 53: "INT_MSUB",
    54: "FP_MADD", 55: "FP_MSUB",
    56: "VEC_MADD", 57: "VEC_MSUB",
}

BRANCH_NAMES = {
    0: "NONE",
    1: "DIRECT_JUMP", 2: "INDIRECT_JUMP",
    3: "RETURN", 4: "SYSCALL", 5: "COND_DIRECT",
}

EXCEPTION_NAMES_DEFAULT = {
    0: "NONE", 1: "UNKNOWN",
    2: "INT_DIVIDE_BY_ZERO", 3: "FP_DIVIDE_BY_ZERO",
    4: "MEMORY_ACCESS",
}

WP_STOP_REASON_NAMES = {0: "NONE", 1: "SYSCALL_USERMODE"}

# Byte sizes for 3-bit mem-data size codes


def build_reg_names() -> dict[int, str]:
    names: dict[int, str] = {0: "REG_NONE"}
    for i in range(64):
        names[1 + i]   = f"REG_GPR{i}"
        names[65 + i]  = f"REG_FPR{i}"
        names[129 + i] = f"REG_VEC{i}"
    for i in range(32):
        names[193 + i] = f"REG_PRED{i}"
    for i in range(6):
        names[225 + i] = f"REG_SEG{i}"
    names[231] = "REG_CTRL"
    names[232] = "REG_DEBUG"
    for i in range(4):
        names[233 + i] = f"REG_BOUND{i}"
        names[237 + i] = f"REG_ACC{i}"
    names[241] = "REG_ZERO"
    names[242] = "REG_MATRIX"
    names[243] = "REG_SYS"
    names[244] = "REG_FCSR"
    names[245] = "REG_VCTRL"
    names[250] = "REG_SP"
    names[251] = "REG_FLAGS"
    names[252] = "REG_IP"
    names[253] = "REG_LR"
    names[254] = "REG_FP_REG"
    return names


REG_NAMES_DEFAULT = build_reg_names()


def build_field_id_names() -> dict[int, str]:
    names: dict[int, str] = {FID_N_LOADS: "CST_FID_N_LOADS"}
    for i in range(FID_SLOT_COUNT):
        names[FID_LOAD_ADDR_BASE + i] = f"CST_FID_LOAD_ADDR{i}"
        names[FID_STORE_ADDR_BASE + i] = f"CST_FID_STORE_ADDR{i}"
        names[FID_LOAD_DATA_BASE + i] = f"CST_FID_LOAD_DATA{i}"
        names[FID_STORE_DATA_BASE + i] = f"CST_FID_STORE_DATA{i}"
        names[FID_SRC_REG_BASE + i] = f"CST_FID_SRC_REG{i}"
    names[FID_N_STORES] = "CST_FID_N_STORES"
    names[FID_INSN_BYTES_LO] = "CST_FID_INSN_BYTES_LO"
    names[FID_INSN_BYTES_HI] = "CST_FID_INSN_BYTES_HI"
    names[FID_INSN_OPCODE] = "CST_FID_INSN_OPCODE"
    names[FID_INSN_BRANCH_TYPE] = "CST_FID_INSN_BRANCH_TYPE"
    names[FID_INSN_FLAGS] = "CST_FID_INSN_FLAGS"
    names[FID_INSN_IMMEDIATE] = "CST_FID_INSN_IMMEDIATE"
    names[FID_INSN_SIZE] = "CST_FID_INSN_SIZE"
    names[FID_EXTENDED] = "CST_FID_EXTENDED"
    return names


FIELD_ID_NAMES_DEFAULT = build_field_id_names()


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
                if b & 0x40 and shift < 128:
                    out |= -(1 << shift)
                return out
            if shift > 140:
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


def _decode_encoding_maps(br: ByteReader) -> dict[str, dict[int, str]]:
    maps: dict[str, dict[int, str]] = {}
    n_maps = br.uleb()
    for _ in range(n_maps):
        map_name = br.string()
        n_entries = br.uleb()
        entries: dict[int, str] = {}
        for _ in range(n_entries):
            value = br.uleb()
            entries[value] = br.string()
        maps[map_name] = entries
    return maps


def _merge_encoding_map(defaults: dict[int, str],
                        parsed: dict[str, dict[int, str]],
                        name: str) -> dict[int, str]:
    merged = dict(defaults)
    merged.update(parsed.get(name, {}))
    return merged


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


# --- Body decoding (v1.7 unified field-typed delta stream) ----------

def _template_default(tmpl: dict | None, ipos: int, fid: int) -> int:
    """Return the per-(template, insn-position, field-id) baseline used
    when a (template_id, ins_pos, field_id) triple is observed for the
    first time.  Mirrors deflt_* callbacks in champsim_tracer_output.cc:
    runtime fields default to zero, encoding fields default to the
    template's static value so that an emit-equal-to-template produces
    no record on the wire."""
    if tmpl is None:
        return 0
    insns = tmpl.get("insns", [])
    if ipos >= len(insns):
        return 0
    insn = insns[ipos]
    if fid == FID_N_LOADS:
        return 0
    if fid == FID_N_STORES:
        return 0
    if FID_INSN_BYTES_LO <= fid <= FID_INSN_SIZE:
        rb = insn.get("raw_bytes") or b""
        rb_int = int.from_bytes(rb, "little") if rb else 0
        if fid == FID_INSN_BYTES_LO:
            return rb_int & MASK64
        if fid == FID_INSN_BYTES_HI:
            return (rb_int >> 64) & MASK64
        if fid == FID_INSN_OPCODE:
            return insn.get("opcode", 0) & 0xFF
        if fid == FID_INSN_BRANCH_TYPE:
            return insn.get("branch_type", 0) & 0xFF
        if fid == FID_INSN_FLAGS:
            f = 0
            if insn.get("branch_conditional"):
                f |= CST_INSN_FLAG_BRANCH_COND
            if insn.get("imm") is not None:
                f |= CST_INSN_FLAG_HAS_IMM
            f |= ((insn.get("sync_hint", 0) << CST_INSN_FLAG_SYNC_SHIFT)
                  & CST_INSN_FLAG_SYNC_MASK)
            return f & 0xFF
        if fid == FID_INSN_IMMEDIATE:
            imm = insn.get("imm")
            return (imm or 0) & MASK64
        if fid == FID_INSN_SIZE:
            return len(insn.get("raw_bytes") or b"") & 0xFF
    return 0


def _decode_field_delta_section(
        br: ByteReader,
        template_id: int,
        tmpl: dict | None,
        state: dict[tuple[int, int, int], int],
        flags: int,
        ) -> tuple[list[DynParam], list[dict]]:
    """Read one length-prefixed delta_section, apply records to the
    per-(template_id, ins_pos, field_id) state map, and reconstruct
    the consumer-facing (dyn_params, reg_snaps) shape the validator API
    expects.  Records are stored as ``(pos_gap, field_id, sleb_delta)``
    triples; ins_pos is reconstructed by accumulating gaps."""
    sec = br.sub()
    n_records = sec.uleb()

    # First pass: walk records, applying deltas to state.
    pos = 0
    for _ in range(n_records):
        gap = sec.uleb()
        pos += gap
        fid = sec.u8()
        delta = sec.sleb()
        if fid == FID_EXTENDED:
            # Reserved escape: payload = ULEB(ext_field_id), SLEB(delta).
            # No extended fields defined yet; skip silently after consuming.
            _ext_id = sec.uleb()
            continue
        key = (template_id, pos, fid)
        base = state.get(key)
        if base is None:
            base = _template_default(tmpl, pos, fid)
        cur = (base + delta) & MASK128
        state[key] = cur

    # Second pass: rebuild dyn_params and reg_snaps by walking the
    # template schema and reading current state for every relevant
    # (ins_pos, field_id).  This preserves the consumer-facing shape:
    # dyn_params is a flat list ordered by (insn_index, load-before-store,
    # slot), reg_snaps is per-insn source operands in operand order.
    dyn_params: list[DynParam] = []
    reg_snaps: list[dict] = []

    if tmpl is None:
        return dyn_params, reg_snaps

    has_mem = bool(flags & CST_FLAG_MEM_DATA)

    def _state_or_default(ipos: int, fid: int) -> int:
        v = state.get((template_id, ipos, fid))
        if v is None:
            v = _template_default(tmpl, ipos, fid)
        return v

    for i, insn in enumerate(tmpl["insns"]):
        n_loads = _state_or_default(i, FID_N_LOADS) & 0xFF
        n_stores = _state_or_default(i, FID_N_STORES) & 0xFF

        for slot in range(n_loads):
            v = _state_or_default(i, FID_LOAD_ADDR_BASE + slot) & MASK64
            dp = DynParam(type_name="load", value=v, insn_index=i)
            if has_mem:
                d128 = _state_or_default(i, FID_LOAD_DATA_BASE + slot)
                dp.data_lo = d128 & MASK64
                dp.data_hi = (d128 >> 64) & MASK64
            dyn_params.append(dp)

        for slot in range(n_stores):
            v = _state_or_default(i, FID_STORE_ADDR_BASE + slot) & MASK64
            dp = DynParam(type_name="store", value=v, insn_index=i)
            if has_mem:
                d128 = _state_or_default(i, FID_STORE_DATA_BASE + slot)
                dp.data_lo = d128 & MASK64
                dp.data_hi = (d128 >> 64) & MASK64
            dyn_params.append(dp)

        # Register snapshots: source operands only. Destination register
        # identities remain in the template, but dynamic destination values
        # are not emitted by the writer's pre-execution capture path.
        # Skip if the REG_DATA flag is clear (no records will exist).
        if flags & CST_FLAG_REG_DATA:
            for op_i, reg_id in enumerate(insn.get("src_regs", [])):
                v = _state_or_default(i, FID_SRC_REG_BASE + op_i)
                reg_snaps.append({
                    "insn_index": i,
                    "kind": "src",
                    "operand_index": op_i,
                    "reg_id": reg_id,
                    "lo": v & MASK64,
                    "hi": (v >> 64) & MASK64,
                })

    return dyn_params, reg_snaps


def decode_champsim_tracer(bin_path: Path
                           ) -> tuple[dict, list[dict], list[dict]]:
    """Decode a v1.7 trace file.  Returns (meta, templates, entries).
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

    encoding_maps: dict[str, dict[int, str]] = {}
    if br.pos < body_off:
        maps_br = br.sub()
        encoding_maps = _decode_encoding_maps(maps_br)
        if not maps_br.eof():
            raise ValueError("encoding map section has trailing bytes")
    if br.pos != body_off:
        raise ValueError(
            f"header/body offset mismatch: parsed={br.pos} trailer={body_off}"
        )

    has_mem_data = bool(flags & CST_FLAG_MEM_DATA)
    has_reg_data = bool(flags & CST_FLAG_REG_DATA)

    # --- Read templates ---
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
    current_thread = 0
    pending_thread_switch = False
    cp_field_state: dict[tuple[int, int, int], int] = {}
    wp_field_state: dict[tuple[int, int, int], int] = {}
    footer_num_entries: int | None = None

    while True:
        tag = body.u8()

        if tag == BODY_TAG_END:
            footer_num_entries = body.uleb()
            break

        if tag == BODY_TAG_THREAD_SWITCH:
            current_thread += body.sleb()
            pending_thread_switch = True
            continue

        if tag != BODY_TAG_ENTRY:
            raise ValueError(f"Unknown body tag: {tag}")

        entry_tmpl = prev_entry_template + body.sleb()
        prev_entry_template = entry_tmpl

        cp_tmpl = template_by_id.get(entry_tmpl)
        cp_dyn, cp_reg_snaps = _decode_field_delta_section(
            body, entry_tmpl, cp_tmpl, cp_field_state, flags)

        # WP chain sub-section
        wp_entries: list[dict] = []
        wpb = body.sub()
        num_wp = wpb.uleb()
        prev_wp_tmpl = 0
        if num_wp > 0:
            # Fork CP→WP state at chain start; discarded at chain end
            # (overwritten on the next chain).  Speculative execution
            # begins at the CP architectural state.
            wp_field_state = dict(cp_field_state)
        for w in range(num_wp):
            wp_tmpl = prev_wp_tmpl + wpb.sleb()
            prev_wp_tmpl = wp_tmpl
            wp_tmpl_dict = template_by_id.get(wp_tmpl)
            wp_dyn, wp_reg_snaps = _decode_field_delta_section(
                wpb, wp_tmpl, wp_tmpl_dict, wp_field_state, flags)
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
                wp_entries[idx]["fault_insn_index"] = evb.uleb()
            prev_evt_idx = idx

        entries.append({
            "seq_num": len(entries) + 1,
            "template_id": entry_tmpl,
            "thread_id": current_thread,
            "thread_switched": pending_thread_switch,
            "dyn_params": cp_dyn,
            "reg_snaps": cp_reg_snaps,
            "wp_entries": wp_entries,
        })
        pending_thread_switch = False

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
        "templates_off": templates_off,
        "templates_count": templates_count,
        "body_off": body_off,
        "body_byte_count": body_byte_count,
        "encoding_maps": encoding_maps,
        "opcode_names": _merge_encoding_map(OPCODE_NAMES, encoding_maps,
                                             "opcode"),
        "branch_names": _merge_encoding_map(BRANCH_NAMES, encoding_maps,
                                             "branch_type"),
        "sync_hint_names": _merge_encoding_map(SYNC_HINT_NAMES,
                                               encoding_maps, "sync_hint"),
        "field_id_names": _merge_encoding_map(FIELD_ID_NAMES_DEFAULT,
                                              encoding_maps, "field_id"),
        "stop_reason_names": dict(WP_STOP_REASON_NAMES),
        "exception_names": dict(EXCEPTION_NAMES_DEFAULT),
        "reg_names": _merge_encoding_map(REG_NAMES_DEFAULT, encoding_maps,
                                          "reg"),
    }
    return meta, templates, entries


# --- Text renderer ---------------------------------------------------

def _format_dyn(dp: DynParam, show_data: bool) -> str:
    s = f"{dp.type_name}=0x{dp.value:x}"
    if show_data and (dp.data_lo or dp.data_hi):
        if dp.data_hi:
            s += f":data=0x{dp.data_hi:x}{dp.data_lo:016x}"
        else:
            s += f":data=0x{dp.data_lo:x}"
    return s


def render_text(meta: dict, templates: list[dict], entries: list[dict]) -> str:
    out: list[str] = []
    opcode_names = meta.get("opcode_names", OPCODE_NAMES)
    branch_names = meta.get("branch_names", BRANCH_NAMES)
    sync_hint_names = meta.get("sync_hint_names", SYNC_HINT_NAMES)
    stop_reason_names = meta.get("stop_reason_names", WP_STOP_REASON_NAMES)
    exception_names = meta.get("exception_names", EXCEPTION_NAMES_DEFAULT)
    reg_names = meta.get("reg_names", REG_NAMES_DEFAULT)
    encoding_maps = meta.get("encoding_maps", {})
    has_mem_data = meta.get("has_mem_data", False)
    has_reg_data = meta.get("has_reg_data", False)

    def rfmt(r: int) -> str:
        return reg_names.get(r, reg_name(r))

    def enum_name(names: dict[int, str], value: int, fallback: str) -> str:
        return names.get(value, f"{fallback}_{value}")

    def snap_value(snap: dict) -> str:
        hi = snap.get("hi", 0)
        lo = snap.get("lo", 0)
        if hi:
            return f"0x{hi:x}{lo:016x}"
        return f"0x{lo:x}"

    def emit_observations(prefix: str,
                          dyn_params: list[DynParam],
                          reg_snaps: list[dict]) -> None:
        if not dyn_params and not reg_snaps:
            out.append(f"{prefix}unchanged")
            return
        if dyn_params:
            out.append(f"{prefix}memops:")
            for dp in dyn_params:
                out.append(
                    f"{prefix}  insn[{dp.insn_index}] "
                    f"{_format_dyn(dp, has_mem_data)}"
                )
        if reg_snaps:
            out.append(f"{prefix}regs:")
            for snap in reg_snaps:
                out.append(
                    f"{prefix}  insn[{snap['insn_index']}] "
                    f"{snap['kind']}[{snap['operand_index']}] "
                    f"{rfmt(snap['reg_id'])}={snap_value(snap)}"
                )

    out.append("META")
    out.append("----")
    out.append(f"VERSION 0x{meta.get('magic', CST_MAGIC):08X}")
    isa_name = meta.get("target_name") or ISA_NAMES.get(meta.get("isa", 0),
                                                        "unknown")
    out.append(f"ISA {isa_name}")
    out.append(f"COMMAND {meta.get('command', '')}")
    out.append(f"DATETIME {meta.get('datetime', '')}")
    out.append(f"COMMENT {meta.get('comment', '')}")
    flags_str = ""
    if has_mem_data:
        flags_str += " MEM_DATA"
    if has_reg_data:
        flags_str += " REG_DATA"
    out.append(f"FLAGS{flags_str}")
    out.append("")

    out.append("ENCODINGS")
    out.append("---------")
    if encoding_maps:
        for map_name in sorted(encoding_maps):
            map_entries = encoding_maps[map_name]
            out.append(f"{map_name} {len(map_entries)}")
            for k in sorted(map_entries):
                out.append(f"  {k} {map_entries[k]}")
    else:
        out.append(f"opcode {len(opcode_names)}")
        for k in sorted(opcode_names):
            out.append(f"  {k} {opcode_names[k]}")
        out.append(f"branch_type {len(branch_names)}")
        for k in sorted(branch_names):
            out.append(f"  {k} {branch_names[k]}")
        out.append(f"reg {len(reg_names)}")
        for k in sorted(reg_names):
            out.append(f"  {k} {reg_names[k]}")
    out.append(f"WP_STOP_REASONS {len(stop_reason_names)}")
    for k in sorted(stop_reason_names):
        out.append(f"  {k} {stop_reason_names[k]}")
    out.append(f"EXCEPTIONS {len(exception_names)}")
    for k in sorted(exception_names):
        out.append(f"  {k} {exception_names[k]}")
    out.append("")

    out.append("TEMPLATES")
    out.append("---------")
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
                    f"op={enum_name(opcode_names, insn['opcode'], 'OP')}")
            if insn["branch_type"] != BRANCH_NONE:
                line += (f" br={enum_name(branch_names, insn['branch_type'], 'BR')}"
                         f" cond={1 if insn['branch_conditional'] else 0}")
            src = ",".join(rfmt(r) for r in insn["src_regs"])
            dst = ",".join(rfmt(r) for r in insn["dst_regs"])
            line += f" src=[{src}] dst=[{dst}]"
            if insn["imm"] is not None:
                line += f" imm={insn['imm']}"
            if insn.get("sync_hint", 0) != 0:
                line += f" sync={enum_name(sync_hint_names, insn['sync_hint'], 'SYNC')}"
            if insn.get("raw_bytes") is not None:
                line += f" bytes={insn['raw_bytes'].hex()}"
            out.append(line)
        out.append("")

    out.append("BODY")
    out.append("----")
    for entry_idx, entry in enumerate(entries):
        switch = " switch=1" if entry.get("thread_switched") else ""
        out.append(
            f"ENTRY {entry['seq_num']:04d} "
            f"thread={entry.get('thread_id', 0)}{switch} "
            f"template=BB{entry['template_id']}"
        )
        out.append("  cp:")
        emit_observations("    ", entry["dyn_params"],
                          entry.get("reg_snaps", []))
        for wp in entry["wp_entries"]:
            out.append(
                f"  wp[{wp['index']}] template=BB{wp['template_id']} "
                f"n_insns={wp['n_insns']}"
            )
            statuses: list[str] = []
            if wp["fault"]:
                fi = wp.get("fault_insn_index")
                if fi is not None:
                    statuses.append(f"FAULT@insn{fi}")
                else:
                    statuses.append("FAULT")
            if wp.get("translation_unavailable"):
                statuses.append("TRANSLATION_UNAVAILABLE")
            if statuses:
                out.append(f"    status: {' '.join(statuses)}")
            emit_observations("    ", wp["dyn_params"],
                              wp.get("reg_snaps", []))
        out.append("")
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
        description="Decode champsim_tracer binary (.cst, v1.7) to text")
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
