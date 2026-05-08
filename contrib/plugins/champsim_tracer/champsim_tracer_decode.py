#!/usr/bin/env python3
"""
Reference decoder for the champsim_tracer binary trace format v1.8.

The body uses one unified field-typed delta stream per CP or WP basic
block.  Each BB entry carries:

    n_records : ULEB
    { ins_pos_gap : ULEB,  field_id : u8,  payload } *

Records are sorted in non-descending (ins_pos, field_id) order; an
absent (template_id, ins_pos, field_id) triple means "field unchanged
since last correct-path emission, or equal to template default if
never observed".  Scalar payloads are SLEB deltas computed as
`(cur512 - baseline512) mod 2**512`.  EXTRA_* memop fields carry raw
ULEB vectors for slots beyond the first 16 and do not persist in state.

Field IDs are dispatched through ``FIELD_DESCRIPTORS`` below — adding
a new dynamic field is one entry there, mirroring the FieldDescriptor
table in champsim_tracer_output.cc.
"""

import argparse
import mmap
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, TextIO


# --- Format constants ------------------------------------------------

# 'C','S','T',version little-endian
CST_MAGIC_V17 = 0x17545343
CST_MAGIC_V18 = 0x18545343
CST_MAGIC_V19 = 0x19545343
CST_MAGIC = CST_MAGIC_V19
CST_TRAILER_MAGIC_V17 = 0x17545343FFFFFFFF
CST_TRAILER_MAGIC_V18 = 0x18545343FFFFFFFF
CST_TRAILER_MAGIC_V19 = 0x19545343FFFFFFFF
CST_TRAILER_MAGIC = CST_TRAILER_MAGIC_V19
CST_TRAILER_SIZE = 64

CST_FLAG_MEM_DATA      = 1 << 0
CST_FLAG_REG_DATA      = 1 << 1
CST_FLAG_RESERVED_2    = 1 << 2

# Body entry tags (u8)
BODY_TAG_END             = 0
BODY_TAG_ENTRY           = 1
BODY_TAG_THREAD_SWITCH   = 2
BODY_TAG_IFRAME          = 3

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
# 0x41..0x50 reserved for pre-exec source register values (not currently
# emitted; the writer captures destination values post-execution).
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

MASK512 = (1 << 512) - 1
MASK128 = (1 << 128) - 1
MASK64  = (1 << 64) - 1
EXTRA_VECTOR_FIDS = {
    FID_EXTRA_LOAD_ADDR,
    FID_EXTRA_STORE_ADDR,
    FID_EXTRA_LOAD_DATA,
    FID_EXTRA_STORE_DATA,
}

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
    58: "PREFETCH", 59: "CACHE_FLUSH", 60: "TLB_FLUSH",
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
        names[FID_DST_REG_BASE + i] = f"CST_FID_DST_REG{i}"
    names[FID_N_STORES] = "CST_FID_N_STORES"
    names[FID_EXTRA_LOAD_ADDR] = "CST_FID_EXTRA_LOAD_ADDR"
    names[FID_EXTRA_STORE_ADDR] = "CST_FID_EXTRA_STORE_ADDR"
    names[FID_EXTRA_LOAD_DATA] = "CST_FID_EXTRA_LOAD_DATA"
    names[FID_EXTRA_STORE_DATA] = "CST_FID_EXTRA_STORE_DATA"
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
    data: int = 0
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
            if shift > 600:
                raise ValueError("ULEB128 too large")

    def sleb(self) -> int:
        out = 0
        shift = 0
        while True:
            b = self.u8()
            out |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                if b & 0x40:
                    out |= -(1 << shift)
                return out
            if shift > 600:
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


def _decode_encoding_maps(
    br: ByteReader,
) -> tuple[dict[str, dict[int, str]], dict[int, bytes]]:
    """Read all encoding maps from the header.

    The "reg" map carries an extra (width_bytes, raw_bytes) suffix per
    entry: the architectural register's value at segment start, sourced
    from the live vCPU at body_stream_new() time.  width_bytes == 0
    means "no live snapshot" (unresolved register or pre-vCPU install-
    time start).  Non-reg maps keep the legacy (id, name) layout.
    Returns (maps, initial_regfile) where initial_regfile is keyed by
    GenericRegId and maps to little-endian raw bytes.
    """
    maps: dict[str, dict[int, str]] = {}
    initial_regfile: dict[int, bytes] = {}
    n_maps = br.uleb()
    for _ in range(n_maps):
        map_name = br.string()
        n_entries = br.uleb()
        entries: dict[int, str] = {}
        for _ in range(n_entries):
            value = br.uleb()
            entries[value] = br.string()
            if map_name == "reg":
                width = br.u8()
                if width:
                    initial_regfile[value] = br.raw(width)
        maps[map_name] = entries
    return maps, initial_regfile


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


# --- Body decoding (v1.7-v1.9 unified field-typed delta stream) -----

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


def _dp_key(dp) -> tuple:
    """Comparable key for a DynParam.  Captures everything the wire
    format actually carries, so an absolute-encoded IFRAME view can be
    compared against the delta-encoded ENTRY view for the same entry.
    """
    return (dp.insn_index, dp.type_name, dp.value, dp.data, dp.data_size)


def _validate_iframe(template_id: int,
                     where: str,
                     entry_dyn: list,
                     entry_reg_snaps: list,
                     iframe_dyn: list,
                     iframe_reg_snaps: list) -> None:
    """Compare an absolute-encoded IFRAME against the delta-decoded
    regular ENTRY for the same observation point.  A mismatch indicates
    either a writer bug or a decoder bug; raise so it surfaces in
    consumers that decode strictly.  (cst_audit.py and similar wrap the
    decode call and downgrade to a warning if the strictness isn't
    desired.)
    """
    e_keys = sorted(_dp_key(dp) for dp in entry_dyn)
    i_keys = sorted(_dp_key(dp) for dp in iframe_dyn)
    if e_keys != i_keys:
        raise ValueError(
            f"IFRAME {where} dyn_params mismatch for template {template_id}: "
            f"entry={e_keys!r} iframe={i_keys!r}"
        )
    if len(entry_reg_snaps) != len(iframe_reg_snaps):
        raise ValueError(
            f"IFRAME {where} reg_snap count mismatch for template "
            f"{template_id}: entry={len(entry_reg_snaps)} "
            f"iframe={len(iframe_reg_snaps)}"
        )
    for i, (a, b) in enumerate(zip(entry_reg_snaps, iframe_reg_snaps)):
        if a.get("value") != b.get("value"):
            raise ValueError(
                f"IFRAME {where} reg_snap[{i}] mismatch for template "
                f"{template_id}: entry={a.get('value')!r} "
                f"iframe={b.get('value')!r}"
            )


def _decode_field_delta_section(
        br: ByteReader,
        template_id: int,
        tmpl: dict | None,
        state: dict[int, int],
        flags: int,
        scalar_mask: int,
        base_state: dict[int, int] | None = None
        ) -> tuple[list[DynParam], list[dict]]:
    """Read one length-prefixed delta_section, apply records to the
    per-(template_id, ins_pos, field_id) state map, and reconstruct
    the consumer-facing (dyn_params, reg_snaps) shape the validator API
    expects.  Scalar records update persistent state; EXTRA_* records
    provide raw overflow memop vectors for this entry only.

    If @base_state is provided (v1.9 WP path), keys not yet present in
    @state fall back to it before fall through to the template default.
    Updates always go to @state (the writable overlay).

    Hot path; aggressively localized.  State is keyed by a 32-bit
    composite int (``template_id<<24 | ipos<<8 | fid``) rather than a
    tuple to skip per-record tuple allocation.  Pass 2 inlines what
    used to be ``_state_or_default`` / ``_template_default``: the
    reader fids touched there (FID_N_LOADS, FID_N_STORES, the
    LOAD/STORE/DST_REG slot ranges) all have a template default of
    zero, so a missed lookup just falls through to ``0`` — no need to
    consult ``tmpl`` at all in pass 2.
    """
    sec = br.sub()
    n_records = sec.uleb()

    tid_base = template_id << 24

    # Local-bind hot attribute lookups.
    sec_uleb = sec.uleb
    sec_sleb = sec.sleb
    sec_u8   = sec.u8
    state_get = state.get
    base_get  = base_state.get if base_state is not None else None

    # --- First pass: apply record deltas to state. ---
    pos = 0
    extra_vectors: dict[tuple[int, int], list[int]] = {}
    extra_set = EXTRA_VECTOR_FIDS

    for _ in range(n_records):
        pos += sec_uleb()
        fid = sec_u8()
        if fid in extra_set:
            n_values = sec_uleb()
            extra_vectors[(pos, fid)] = [sec_uleb() for _ in range(n_values)]
            continue
        delta = sec_sleb()
        if fid == FID_EXTENDED:
            # Reserved escape: payload = ULEB(ext_field_id), SLEB(delta).
            # No extended fields defined yet; skip silently after consuming.
            sec_uleb()
            continue
        key = tid_base | (pos << 8) | fid
        base = state_get(key)
        if base is None:
            if base_get is not None:
                base = base_get(key)
            if base is None:
                # Most fids default to 0; only the FID_INSN_* range
                # carries a template-derived baseline.  Skip the
                # function-call overhead for the common case.
                if FID_INSN_BYTES_LO <= fid <= FID_INSN_SIZE:
                    base = _template_default(tmpl, pos, fid)
                else:
                    base = 0
        state[key] = (base + delta) & scalar_mask

    # --- Second pass: materialize dyn_params and reg_snaps. ---
    dyn_params: list[DynParam] = []
    reg_snaps: list[dict] = []

    if tmpl is None:
        return dyn_params, reg_snaps

    has_mem = bool(flags & CST_FLAG_MEM_DATA)
    has_reg = bool(flags & CST_FLAG_REG_DATA)
    insns = tmpl["insns"]

    # Pass 2 only reads fids whose template_default is 0.  A missed
    # lookup on either overlay just yields 0.
    if base_get is None:
        def _lookup(k: int) -> int:
            v = state_get(k)
            return 0 if v is None else v
    else:
        def _lookup(k: int) -> int:
            v = state_get(k)
            if v is None:
                v = base_get(k)
                if v is None:
                    return 0
            return v

    extra_get = extra_vectors.get

    def _require_extra(ipos: int, fid: int, count: int) -> list[int]:
        values = extra_get((ipos, fid), [])
        if len(values) != count:
            name = FIELD_ID_NAMES_DEFAULT.get(fid, f"FID_{fid:#x}")
            raise ValueError(
                f"{name} count mismatch at template={template_id} "
                f"insn={ipos}: expected {count}, got {len(values)}"
            )
        return values

    for i, insn in enumerate(insns):
        ipos_key = tid_base | (i << 8)
        n_loads  = _lookup(ipos_key | FID_N_LOADS)
        n_stores = _lookup(ipos_key | FID_N_STORES)

        if n_loads or n_stores:
            fixed_loads  = n_loads  if n_loads  < FID_SLOT_COUNT else FID_SLOT_COUNT
            fixed_stores = n_stores if n_stores < FID_SLOT_COUNT else FID_SLOT_COUNT

            for slot in range(fixed_loads):
                addr = _lookup(ipos_key | (FID_LOAD_ADDR_BASE + slot)) & MASK64
                dp = DynParam(type_name="load", value=addr, insn_index=i)
                if has_mem:
                    data = _lookup(ipos_key | (FID_LOAD_DATA_BASE + slot)) & scalar_mask
                    dp.data = data
                    dp.data_lo = data & MASK64
                    dp.data_hi = (data >> 64) & MASK64
                dyn_params.append(dp)

            extra_load_count = n_loads - FID_SLOT_COUNT
            if extra_load_count > 0:
                extra_addrs = _require_extra(i, FID_EXTRA_LOAD_ADDR,
                                             extra_load_count)
                extra_data = _require_extra(i, FID_EXTRA_LOAD_DATA,
                                            extra_load_count) if has_mem else []
                for j, v in enumerate(extra_addrs):
                    dp = DynParam(type_name="load", value=v & MASK64,
                                  insn_index=i)
                    if has_mem:
                        d = extra_data[j] & scalar_mask
                        dp.data = d
                        dp.data_lo = d & MASK64
                        dp.data_hi = (d >> 64) & MASK64
                    dyn_params.append(dp)

            for slot in range(fixed_stores):
                addr = _lookup(ipos_key | (FID_STORE_ADDR_BASE + slot)) & MASK64
                dp = DynParam(type_name="store", value=addr, insn_index=i)
                if has_mem:
                    data = _lookup(ipos_key | (FID_STORE_DATA_BASE + slot)) & scalar_mask
                    dp.data = data
                    dp.data_lo = data & MASK64
                    dp.data_hi = (data >> 64) & MASK64
                dyn_params.append(dp)

            extra_store_count = n_stores - FID_SLOT_COUNT
            if extra_store_count > 0:
                extra_addrs = _require_extra(i, FID_EXTRA_STORE_ADDR,
                                             extra_store_count)
                extra_data = _require_extra(i, FID_EXTRA_STORE_DATA,
                                            extra_store_count) if has_mem else []
                for j, v in enumerate(extra_addrs):
                    dp = DynParam(type_name="store", value=v & MASK64,
                                  insn_index=i)
                    if has_mem:
                        d = extra_data[j] & scalar_mask
                        dp.data = d
                        dp.data_lo = d & MASK64
                        dp.data_hi = (d >> 64) & MASK64
                    dyn_params.append(dp)

        # Register snapshots: destination operands only, captured
        # post-execution.  Source register identities remain in the
        # template; source values are not emitted on the wire (the
        # writer's capture path is dst-only — consumers can derive any
        # register's value at any point from the most recent post-exec
        # destination observation).  Skip if the REG_DATA flag is
        # clear (no records will exist).
        if has_reg:
            dst_regs = insn.get("dst_regs")
            if dst_regs:
                for op_i, reg_id in enumerate(dst_regs):
                    v = _lookup(ipos_key | (FID_DST_REG_BASE + op_i))
                    reg_snaps.append({
                        "insn_index": i,
                        "kind": "dst",
                        "operand_index": op_i,
                        "reg_id": reg_id,
                        "value": v & scalar_mask,
                        "lo": v & MASK64,
                        "hi": (v >> 64) & MASK64,
                    })

    return dyn_params, reg_snaps


def _open_trace(bin_path: Path):
    """Open a trace file as a read-only mmap.  Returns the mmap object;
    caller is responsible for releasing it (typically by letting it go
    out of scope, or by holding it alive as long as a body iterator
    derived from it is in use).
    """
    fd = os.open(bin_path, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        if size == 0:
            raise ValueError("Trace file is empty")
        return mmap.mmap(fd, 0, prot=mmap.PROT_READ)
    finally:
        os.close(fd)


def _parse_header_and_templates(data) -> tuple[dict, list[dict],
                                               dict[int, dict],
                                               int, int, int, int, bool]:
    """Parse the trailer, header, and templates section.  Returns
    ``(meta, templates, template_by_id, body_off, body_end, flags,
    scalar_mask, wp_persistent)`` — everything the body walker needs to
    start producing entries.
    """
    if len(data) < CST_TRAILER_SIZE:
        raise ValueError("Trace file too small to contain a trailer")

    # --- Read trailer from end of file ---
    trailer = ByteReader(data, len(data) - CST_TRAILER_SIZE)
    templates_off   = trailer.u64_le()
    templates_count = trailer.u64_le()
    body_off        = trailer.u64_le()
    body_byte_count = trailer.u64_le()
    trailer_magic   = trailer.u64_le()
    if trailer_magic not in (CST_TRAILER_MAGIC_V17, CST_TRAILER_MAGIC_V18,
                             CST_TRAILER_MAGIC_V19):
        raise ValueError(
            f"Bad trailer magic 0x{trailer_magic:016x}, "
            f"expected 0x{CST_TRAILER_MAGIC_V17:016x}, "
            f"0x{CST_TRAILER_MAGIC_V18:016x}, or "
            f"0x{CST_TRAILER_MAGIC_V19:016x}"
        )

    # --- Read header ---
    br = ByteReader(data)
    magic = br.u32_le()
    if magic not in (CST_MAGIC_V17, CST_MAGIC_V18, CST_MAGIC_V19):
        raise ValueError(
            f"Bad magic 0x{magic:08x}, expected 0x{CST_MAGIC_V17:08x}, "
            f"0x{CST_MAGIC_V18:08x}, or 0x{CST_MAGIC_V19:08x}"
        )
    expected_trailer = {
        CST_MAGIC_V17: CST_TRAILER_MAGIC_V17,
        CST_MAGIC_V18: CST_TRAILER_MAGIC_V18,
        CST_MAGIC_V19: CST_TRAILER_MAGIC_V19,
    }[magic]
    if trailer_magic != expected_trailer:
        raise ValueError("Header/trailer CST version mismatch")
    isa          = br.u8()
    flags        = br.u8()
    # Per-segment instruction window descriptors.
    #   start_insn         : architectural icount where this segment
    #                        begins (anchors body records to a global
    #                        timeline).
    #   warmup_insns       : insns at the front of this trace meant
    #                        to prime caches/predictors and not be
    #                        evaluated; zero outside simpoint mode.
    #   total_target_insns : configured length of the segment.  Zero
    #                        means "unbounded" (non-simpoint with no
    #                        explicit stop).  This is the targeted
    #                        value, not what was observed.
    start_insn         = br.uleb()
    warmup_insns       = br.uleb()
    total_target_insns = br.uleb()
    command      = br.string()
    datetime_str = br.string()
    comment      = br.string()
    target_name  = br.string()

    encoding_maps: dict[str, dict[int, str]] = {}
    initial_regfile: dict[int, bytes] = {}
    if br.pos < body_off:
        maps_br = br.sub()
        encoding_maps, initial_regfile = _decode_encoding_maps(maps_br)
        if not maps_br.eof():
            raise ValueError("encoding map section has trailing bytes")
    if br.pos != body_off:
        raise ValueError(
            f"header/body offset mismatch: parsed={br.pos} trailer={body_off}"
        )

    has_mem_data = bool(flags & CST_FLAG_MEM_DATA)
    has_reg_data = bool(flags & CST_FLAG_REG_DATA)
    scalar_mask = MASK128 if magic == CST_MAGIC_V17 else MASK512
    wp_persistent = (magic == CST_MAGIC_V19)

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

    meta = {
        "magic": magic,
        "format_version": {
            CST_MAGIC_V17: 0x17,
            CST_MAGIC_V18: 0x18,
            CST_MAGIC_V19: 0x19,
        }[magic],
        "isa": isa,
        "target_name": target_name,
        "flags": flags,
        "start_insn": start_insn,
        "warmup_insns": warmup_insns,
        "total_target_insns": total_target_insns,
        "initial_regfile": initial_regfile,
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
    return (meta, templates, template_by_id, body_off,
            body_off + body_byte_count, flags, scalar_mask, wp_persistent)


_DECODER_DIAG_EVERY = int(os.environ.get("CST_DECODER_DIAG_EVERY", "0"))


def _iter_body_entries(data, body_off: int, body_end: int,
                       template_by_id: dict[int, dict],
                       flags: int, scalar_mask: int,
                       wp_persistent: bool) -> Iterator[dict]:
    """Generator: walk the body section once, yielding one entry dict
    per BODY_TAG_ENTRY.  IFRAME records validate against the
    immediately preceding entry without yielding anything.

    Memory: O(1) in entry count.  The persistent (template_id, ipos,
    fid) state map grows as the trace exercises new (template, slot)
    pairs but is bounded by the template population, not the entry
    count.
    """
    body = ByteReader(data, body_off, body_end)
    prev_entry_template = 0
    current_thread = 0
    pending_thread_switch = False
    cp_field_state: dict[int, int] = {}
    wp_field_state: dict[int, int] = {}
    prev_entry: dict | None = None
    seq = 0
    footer_num_entries: int | None = None

    def _decode_body_record_payload(br, entry_tmpl, cp_state, wp_state):
        """See the eager decoder for the rationale; unchanged logic."""
        cp_tmpl = template_by_id.get(entry_tmpl)
        cp_dyn, cp_reg_snaps = _decode_field_delta_section(
            br, entry_tmpl, cp_tmpl, cp_state, flags, scalar_mask)

        wp_entries_local: list[dict] = []
        wpb = br.sub()
        num_wp = wpb.uleb()
        prev_wp_tmpl = 0
        wp_base = cp_state if wp_persistent else None
        for w in range(num_wp):
            wp_tmpl = prev_wp_tmpl + wpb.sleb()
            prev_wp_tmpl = wp_tmpl
            wp_tmpl_dict = template_by_id.get(wp_tmpl)
            wp_dyn, wp_reg_snaps = _decode_field_delta_section(
                wpb, wp_tmpl, wp_tmpl_dict, wp_state, flags,
                scalar_mask, base_state=wp_base)
            wp_entries_local.append({
                "index": w,
                "template_id": wp_tmpl,
                "dyn_params": wp_dyn,
                "reg_snaps": wp_reg_snaps,
                "fault": False,
                "translation_unavailable": False,
                "fault_insn_index": None,
                "n_insns": template_by_id.get(wp_tmpl, {}).get("n_insns", 0),
            })

        evb = br.sub()
        num_events = evb.uleb()
        prev_evt_idx = -1
        for _ in range(num_events):
            gap = evb.uleb()
            idx = prev_evt_idx + 1 + gap
            if idx >= num_wp:
                raise ValueError("wp event index out of range")
            evf = evb.u8()
            wp_entries_local[idx]["translation_unavailable"] = bool(
                evf & CST_WP_EVENT_TRANSLATION_UNAVAIL)
            is_fault = bool(evf & CST_WP_EVENT_FAULT)
            wp_entries_local[idx]["fault"] = is_fault
            if is_fault:
                wp_entries_local[idx]["fault_insn_index"] = evb.uleb()
            prev_evt_idx = idx

        return cp_dyn, cp_reg_snaps, wp_entries_local

    while True:
        tag = body.u8()

        if tag == BODY_TAG_END:
            footer_num_entries = body.uleb()
            break

        if tag == BODY_TAG_THREAD_SWITCH:
            current_thread += body.sleb()
            pending_thread_switch = True
            continue

        if tag == BODY_TAG_ENTRY:
            entry_tmpl = prev_entry_template + body.sleb()
            prev_entry_template = entry_tmpl

            if not wp_persistent:
                # v1.7/v1.8 forked CP→WP state at chain start.  Carry
                # the latest CP state forward into a fresh WP overlay
                # only when this body record actually starts a chain;
                # the cheaper unconditional clone here matches the
                # writer's pre-chain state.
                wp_field_state = dict(cp_field_state)

            cp_dyn, cp_reg_snaps, wp_entries = _decode_body_record_payload(
                body, entry_tmpl, cp_field_state, wp_field_state)

            seq += 1
            entry = {
                "seq_num": seq,
                "template_id": entry_tmpl,
                "thread_id": current_thread,
                "thread_switched": pending_thread_switch,
                "dyn_params": cp_dyn,
                "reg_snaps": cp_reg_snaps,
                "wp_entries": wp_entries,
            }
            pending_thread_switch = False
            prev_entry = entry
            if _DECODER_DIAG_EVERY and (seq % _DECODER_DIAG_EVERY == 0):
                try:
                    import resource as _res
                    _rss = _res.getrusage(_res.RUSAGE_SELF).ru_maxrss
                except Exception:
                    _rss = -1
                # cp_state and wp_state are kept in sync only when v1.7/v1.8
                # forks; in v1.9 they grow independently. Show both.
                print(
                    f"[diag] seq={seq:>9} cp_state={len(cp_field_state):>8} "
                    f"wp_state={len(wp_field_state):>8} "
                    f"rss={_rss//1024 if _rss > 0 else _rss}MB",
                    file=sys.stderr, flush=True,
                )
            yield entry
            continue

        if tag == BODY_TAG_IFRAME:
            # Validates the immediately-preceding BODY_TAG_ENTRY using
            # fresh empty overlays so every delta resolves against
            # template_default — a pure absolute decode.
            if prev_entry is None:
                raise ValueError("BODY_TAG_IFRAME with no preceding ENTRY")
            iframe_cp_state: dict[int, int] = {}
            iframe_wp_state: dict[int, int] = {}
            i_cp_dyn, i_cp_reg, i_wp_entries = _decode_body_record_payload(
                body, prev_entry["template_id"],
                iframe_cp_state, iframe_wp_state)
            _validate_iframe(prev_entry["template_id"], "CP",
                             prev_entry["dyn_params"],
                             prev_entry["reg_snaps"],
                             i_cp_dyn, i_cp_reg)
            if len(i_wp_entries) != len(prev_entry["wp_entries"]):
                raise ValueError(
                    f"IFRAME WP-chain length mismatch: "
                    f"entry={len(prev_entry['wp_entries'])} "
                    f"iframe={len(i_wp_entries)}"
                )
            for w_idx, (e_wp, i_wp) in enumerate(
                    zip(prev_entry["wp_entries"], i_wp_entries)):
                _validate_iframe(e_wp["template_id"], f"WP[{w_idx}]",
                                 e_wp["dyn_params"], e_wp["reg_snaps"],
                                 i_wp["dyn_params"], i_wp["reg_snaps"])
            continue

        raise ValueError(f"Unknown body tag: {tag}")

    if footer_num_entries is not None and footer_num_entries != seq:
        raise ValueError(
            f"Footer entry count mismatch: "
            f"{footer_num_entries} != {seq}"
        )


def iter_decode_champsim_tracer(bin_path: Path
                                ) -> tuple[dict, list[dict],
                                           Iterator[dict]]:
    """Streaming decoder.  Returns ``(meta, templates, entry_iter)``
    with the same shape as :func:`decode_champsim_tracer`, except the
    third element is a single-pass iterator that yields one entry at a
    time.  Memory usage stays O(1) in entry count, so this is the
    correct API for multi-GB traces.

    The returned iterator captures the underlying mmap; consume it (or
    let it go out of scope) before the trace file is unlinked.
    """
    data = _open_trace(bin_path)
    (meta, templates, template_by_id, body_off, body_end,
     flags, scalar_mask, wp_persistent) = _parse_header_and_templates(data)

    def entries_gen() -> Iterator[dict]:
        # `data` is captured here, keeping the mmap alive for the
        # lifetime of the iterator regardless of what the caller does
        # with the meta / templates references.
        yield from _iter_body_entries(
            data, body_off, body_end, template_by_id,
            flags, scalar_mask, wp_persistent)

    return meta, templates, entries_gen()


def decode_champsim_tracer(bin_path: Path
                           ) -> tuple[dict, list[dict], list[dict]]:
    """Decode a v1.7/v1.8/v1.9 trace file.  Returns
    ``(meta, templates, entries)`` with ``entries`` materialized as a
    list.  Public API; stable across minor revisions of the decoder.

    For multi-GB traces use :func:`iter_decode_champsim_tracer`
    instead — this function holds every decoded entry in memory and
    will OOM on traces of even moderate size.
    """
    meta, templates, it = iter_decode_champsim_tracer(bin_path)
    return meta, templates, list(it)


# --- Text renderer ---------------------------------------------------

def _format_dyn(dp: DynParam, show_data: bool) -> str:
    s = f"{dp.type_name}=0x{dp.value:x}"
    if show_data:
        data = dp.data if dp.data else ((dp.data_hi << 64) | dp.data_lo)
        if data:
            s += f":data=0x{data:x}"
    return s


def render_text_streaming(meta: dict, templates: list[dict],
                          entries: Iterator[dict] | list[dict],
                          out: TextIO) -> int:
    """Stream the text rendering directly to ``out`` (a file-like
    object).  Returns the number of entries rendered.  Output is
    byte-identical to :func:`render_text` for the same input.
    """
    write = out.write
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
            write(f"{prefix}unchanged\n")
            return
        if dyn_params:
            write(f"{prefix}memops:\n")
            for dp in dyn_params:
                write(f"{prefix}  insn[{dp.insn_index}] "
                      f"{_format_dyn(dp, has_mem_data)}\n")
        if reg_snaps:
            write(f"{prefix}regs:\n")
            for snap in reg_snaps:
                write(f"{prefix}  insn[{snap['insn_index']}] "
                      f"{snap['kind']}[{snap['operand_index']}] "
                      f"{rfmt(snap['reg_id'])}={snap_value(snap)}\n")

    write("META\n----\n")
    write(f"VERSION 0x{meta.get('magic', CST_MAGIC):08X}\n")
    isa_name = meta.get("target_name") or ISA_NAMES.get(meta.get("isa", 0),
                                                        "unknown")
    write(f"ISA {isa_name}\n")
    write(f"COMMAND {meta.get('command', '')}\n")
    write(f"DATETIME {meta.get('datetime', '')}\n")
    write(f"COMMENT {meta.get('comment', '')}\n")
    flags_str = ""
    if has_mem_data:
        flags_str += " MEM_DATA"
    if has_reg_data:
        flags_str += " REG_DATA"
    write(f"FLAGS{flags_str}\n")
    write(f"START_INSN {meta.get('start_insn', 0)}\n")
    write(f"WARMUP_INSNS {meta.get('warmup_insns', 0)}\n")
    total_target = meta.get('total_target_insns', 0)
    write(f"TOTAL_TARGET_INSNS {total_target}"
          f"{' (unbounded)' if total_target == 0 else ''}\n")
    initial_regfile = meta.get("initial_regfile", {})
    if initial_regfile:
        write(f"INITIAL_REGFILE {len(initial_regfile)}\n")
        for k in sorted(initial_regfile):
            v = initial_regfile[k]
            write(f"  {rfmt(k)} {v.hex()}\n")
    write("\n")

    write("ENCODINGS\n---------\n")
    if encoding_maps:
        for map_name in sorted(encoding_maps):
            map_entries = encoding_maps[map_name]
            write(f"{map_name} {len(map_entries)}\n")
            for k in sorted(map_entries):
                write(f"  {k} {map_entries[k]}\n")
    else:
        write(f"opcode {len(opcode_names)}\n")
        for k in sorted(opcode_names):
            write(f"  {k} {opcode_names[k]}\n")
        write(f"branch_type {len(branch_names)}\n")
        for k in sorted(branch_names):
            write(f"  {k} {branch_names[k]}\n")
        write(f"reg {len(reg_names)}\n")
        for k in sorted(reg_names):
            write(f"  {k} {reg_names[k]}\n")
    write(f"WP_STOP_REASONS {len(stop_reason_names)}\n")
    for k in sorted(stop_reason_names):
        write(f"  {k} {stop_reason_names[k]}\n")
    write(f"EXCEPTIONS {len(exception_names)}\n")
    for k in sorted(exception_names):
        write(f"  {k} {exception_names[k]}\n")
    write("\n")

    write("TEMPLATES\n---------\n")
    for tmpl in templates:
        write(f"BB{tmpl['template_id']} [pc=0x{tmpl['start_pc']:x}, "
              f"insns={tmpl['n_insns']}, "
              f"fall_through=0x{tmpl['fall_through_pc']:x}]\n")
        if tmpl.get("symbol_name"):
            write(f"  symbol={tmpl['symbol_name']}\n")
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
            write(line + "\n")
        write("\n")

    write("BODY\n----\n")
    n_entries = 0
    for entry in entries:
        n_entries += 1
        switch = " switch=1" if entry.get("thread_switched") else ""
        write(f"ENTRY {entry['seq_num']:04d} "
              f"thread={entry.get('thread_id', 0)}{switch} "
              f"template=BB{entry['template_id']}\n")
        write("  cp:\n")
        emit_observations("    ", entry["dyn_params"],
                          entry.get("reg_snaps", []))
        for wp in entry["wp_entries"]:
            write(f"  wp[{wp['index']}] template=BB{wp['template_id']} "
                  f"n_insns={wp['n_insns']}\n")
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
                write(f"    status: {' '.join(statuses)}\n")
            emit_observations("    ", wp["dyn_params"],
                              wp.get("reg_snaps", []))
        write("\n")
        _ = exception_names, stop_reason_names  # referenced for API parity

    return n_entries


def render_text(meta: dict, templates: list[dict],
                entries: list[dict]) -> str:
    """Render to a single string.  For very large traces use
    :func:`render_text_streaming` directly to avoid the whole-text-in-
    memory cost.
    """
    import io
    buf = io.StringIO()
    render_text_streaming(meta, templates, iter(entries), buf)
    return buf.getvalue()


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
        description="Decode champsim_tracer binary (.cst, v1.7/v1.8/v1.9) to text")
    parser.add_argument("bin", type=Path)
    parser.add_argument("-o", "--out", type=Path)
    parser.add_argument("--expect", type=Path)
    args = parser.parse_args()

    if args.expect:
        # --expect needs the full text in memory for comparison; stay on
        # the eager path (still mmap-backed via iter_decode_champsim_tracer
        # internally, just materialized into a list before render).
        meta, templates, entries = decode_champsim_tracer(args.bin)
        text = render_text(meta, templates, entries)
        if args.out:
            args.out.write_text(text)
        else:
            sys.stdout.write(text)
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

    # Streaming path: decode + render entry-by-entry, no full-trace
    # accumulation in memory.
    meta, templates, entry_iter = iter_decode_champsim_tracer(args.bin)
    if args.out:
        with args.out.open("w") as f:
            render_text_streaming(meta, templates, entry_iter, f)
    else:
        render_text_streaming(meta, templates, entry_iter, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
