#!/usr/bin/env python3

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path


WPT_MAGIC = 0x54505707

WPT_ISA_BITS = 3
WPT_OPCODE_BITS = 8
WPT_BRANCH_BITS = 8
WPT_REG_COUNT_BITS = 3
WPT_REG_BITS = 8
WPT_HEADER_FLAGS_BITS = 8
WPT_MEM_DATA_SIZE_BITS = 3

WPT_FLAG_MEM_DATA  = 1 << 0
WPT_FLAG_REG_DATA  = 1 << 1
WPT_FLAG_MEM_ALLOC = 1 << 2
WPT_FLAG_THREADS   = 1 << 3

# Body entry tags (2-bit)
BODY_TAG_END      = 0
BODY_TAG_ENTRY    = 1
BODY_TAG_MEMALLOC = 2
BODY_TAG_SYNC     = 3

WPT_SYNC_TYPE_BITS = 4
WPT_SYNC_HINT_BITS = 4

# Sync event types (must match SyncEventType enum in wptrace_mnemonics.h)
SYNC_NONE          = 0
SYNC_YIELD         = 1
SYNC_FUTEX_WAIT    = 2
SYNC_FUTEX_WAKE    = 3
SYNC_THREAD_SWITCH = 4
SYNC_ATOMIC        = 5
SYNC_TYPE_NAMES    = {0: "NONE", 1: "YIELD", 2: "FUTEX_WAIT", 3: "FUTEX_WAKE",
                      4: "THREAD_SWITCH", 5: "ATOMIC"}

# MemAlloc event types
MEMALLOC_MAP   = 0
MEMALLOC_UNMAP = 1
MEMALLOC_REMAP = 2
MEMALLOC_TYPE_NAMES = {0: "MAP", 1: "UNMAP", 2: "REMAP"}

# ISA enum values (must match TraceISA in wptrace_mnemonics.h)
ISA_NAMES = {
    0: "unknown",
    1: "x86_64",
    2: "aarch64",
    3: "riscv64",
    4: "mipsel",
}

BRANCH_NONE = 0


OPCODE_NAMES = {
    0: "UNKNOWN",
    1: "INT_ADD",
    2: "INT_SUB",
    3: "INT_MUL",
    4: "INT_DIV",
    5: "AND",
    6: "OR",
    7: "XOR",
    8: "NOT",
    9: "SHL",
    10: "SHR",
    11: "SAR",
    12: "ROL",
    13: "ROR",
    14: "MOV",
    15: "LOAD",
    16: "STORE",
    17: "PUSH",
    18: "POP",
    19: "LEA",
    20: "MOVSX",
    21: "MOVZX",
    22: "XCHG",
    23: "CMP",
    24: "TEST",
    25: "BRANCH",
    26: "CALL",
    27: "RET",
    28: "FP_ADD",
    29: "FP_SUB",
    30: "FP_MUL",
    31: "FP_DIV",
    32: "FP_SQRT",
    33: "FP_MOV",
    34: "FP_CVT",
    35: "FP_CMP",
    36: "VEC_ADD",
    37: "VEC_SUB",
    38: "VEC_MUL",
    39: "VEC_MOV",
    40: "VEC_SHUF",
    41: "VEC_LOGIC",
    42: "NOP",
    43: "SYSCALL",
    44: "FENCE",
    45: "CMOV",
    46: "SETCC",
    47: "INT_ADC",
    48: "INT_SBB",
    49: "NEG",
    50: "INC",
    51: "DEC",
}


BRANCH_NAMES = {
    0: "NONE",
    1: "DIRECT_JUMP",
    2: "INDIRECT_JUMP",
    3: "DIRECT_CALL",
    4: "INDIRECT_CALL",
    5: "RETURN",
    6: "SYSCALL",
    7: "COND_DIRECT",
}

EXCEPTION_NAMES_DEFAULT = {
    0: "NONE",
    1: "UNKNOWN",
    2: "INT_DIVIDE_BY_ZERO",
    3: "FP_DIVIDE_BY_ZERO",
    4: "MEMORY_ACCESS",
}

WP_STOP_REASON_NAMES = {
    0: "NONE",
    1: "SYSCALL_USERMODE",
}


def build_reg_names() -> dict[int, str]:
    names: dict[int, str] = {}
    names[0] = "NONE"
    for i in range(64):
        names[1 + i] = f"GPR{i}"
    for i in range(64):
        names[65 + i] = f"FPR{i}"
    for i in range(64):
        names[129 + i] = f"VEC{i}"
    names[250] = "SP"
    names[251] = "FLAGS"
    names[252] = "IP"
    names[253] = "LR"
    names[254] = "FP"
    return names


REG_NAMES_DEFAULT = build_reg_names()


@dataclass
class DynParam:
    type_name: str
    value: int
    data_size: int = 0
    data_lo: int = 0
    data_hi: int = 0


def add_delta_u64(base: int, delta: int) -> int:
    return (base + delta) & ((1 << 64) - 1)


class BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.cur = 0
        self.used = 8

    def _next_byte(self) -> int:
        if self.pos >= len(self.data):
            raise ValueError("Unexpected EOF")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bits(self, nbits: int) -> int:
        out = 0
        shift = 0
        while nbits > 0:
            if self.used == 8:
                self.cur = self._next_byte()
                self.used = 0

            avail = 8 - self.used
            take = min(avail, nbits)
            mask = (1 << take) - 1
            part = (self.cur >> self.used) & mask

            out |= part << shift
            shift += take
            self.used += take
            nbits -= take

        return out

    def read_uleb128(self) -> int:
        out = 0
        shift = 0
        while True:
            b = self.read_bits(8)
            out |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return out
            shift += 7
            if shift > 70:
                raise ValueError("ULEB128 too large")

    def read_sleb128(self) -> int:
        out = 0
        shift = 0
        while True:
            b = self.read_bits(8)
            out |= (b & 0x7F) << shift
            shift += 7

            if (b & 0x80) == 0:
                if (b & 0x40) and shift < 64:
                    out |= - (1 << shift)
                return out

            if shift > 70:
                raise ValueError("SLEB128 too large")


def read_bytes(br: BitReader, n: int) -> bytes:
    return bytes(br.read_bits(8) for _ in range(n))


def read_string(br: BitReader) -> str:
    n = br.read_uleb128()
    if n == 0:
        return ""
    return read_bytes(br, n).decode("utf-8", errors="replace")


def read_name_table(br: BitReader) -> dict[int, str]:
    count = br.read_uleb128()
    out: dict[int, str] = {}
    for _ in range(count):
        key = br.read_uleb128()
        out[key] = read_string(br)
    return out


def reg_name(reg_id: int) -> str:
    if reg_id == 0:
        return "NONE"
    if 1 <= reg_id <= 64:
        return f"GPR{reg_id - 1}"
    if 65 <= reg_id <= 128:
        return f"FPR{reg_id - 65}"
    if 129 <= reg_id <= 192:
        return f"VEC{reg_id - 129}"
    if reg_id == 250:
        return "SP"
    if reg_id == 251:
        return "FLAGS"
    if reg_id == 252:
        return "IP"
    if reg_id == 253:
        return "LR"
    if reg_id == 254:
        return "FP"
    return f"R{reg_id}"


def decode_dyn_patch(br: BitReader, prev_dyn: list[DynParam]) -> list[DynParam]:
    new_len = br.read_uleb128()
    num_changed = br.read_uleb128()

    out = [DynParam(type_name=d.type_name, value=d.value)
           for d in prev_dyn[:new_len]]

    while len(out) < new_len:
        out.append(DynParam(type_name="load", value=0))

    prev_pos = -1
    for _ in range(num_changed):
        pos_gap = br.read_uleb128()
        pos = prev_pos + 1 + pos_gap
        if pos >= new_len:
            raise ValueError("Patch position out of range")

        type_bit = br.read_bits(1)
        delta = br.read_sleb128()

        base_value = 0
        if pos < len(prev_dyn):
            base_value = prev_dyn[pos].value

        value = add_delta_u64(base_value, delta)
        type_name = "store" if type_bit else "load"
        out[pos] = DynParam(type_name=type_name, value=value)
        prev_pos = pos

    return out


# Byte sizes corresponding to 3-bit size codes used for mem data
_MEM_DATA_SIZE_TABLE = [1, 2, 4, 8, 16, 1, 1, 1]


def read_mem_data_values(br: "BitReader", params: list[DynParam]) -> None:
    """Read and attach data values to each DynParam in-place."""
    for dp in params:
        code = br.read_bits(WPT_MEM_DATA_SIZE_BITS)
        sz = _MEM_DATA_SIZE_TABLE[code]
        dp.data_size = sz
        lo = 0
        for b in range(min(sz, 8)):
            lo |= br.read_bits(8) << (b * 8)
        dp.data_lo = lo
        hi = 0
        if sz > 8:
            for b in range(sz - 8):
                hi |= br.read_bits(8) << (b * 8)
        dp.data_hi = hi


def format_dyn(dp: DynParam, show_data: bool = False) -> str:
    s = f"{dp.type_name}=0x{dp.value:x}"
    if show_data and dp.data_size > 0:
        if dp.data_size <= 8:
            s += f":data=0x{dp.data_lo:x}"
        else:
            s += f":data=0x{dp.data_hi:x}{dp.data_lo:016x}"
    return s


def decode_wptrace(bin_path: Path) -> tuple[dict, list[dict], list[dict]]:
    data = bin_path.read_bytes()
    br = BitReader(data)

    magic = br.read_bits(32)
    if magic != WPT_MAGIC:
        raise ValueError(
            f"Bad magic 0x{magic:08x}, expected 0x{WPT_MAGIC:08x}"
        )

    isa = br.read_bits(WPT_ISA_BITS)

    # v0.6 header: flags, command, datetime, comment, target_name, thread_id
    flags = br.read_bits(WPT_HEADER_FLAGS_BITS)
    command      = read_string(br)
    datetime_str = read_string(br)
    comment      = read_string(br)
    target_name  = read_string(br)
    thread_id    = br.read_uleb128()   # v0.6: always present (0 = single-thread)

    has_mem_data  = bool(flags & WPT_FLAG_MEM_DATA)
    has_mem_alloc = bool(flags & WPT_FLAG_MEM_ALLOC)
    is_threaded   = bool(flags & WPT_FLAG_THREADS)

    opcode_names = dict(OPCODE_NAMES)
    branch_names = dict(BRANCH_NAMES)
    exception_names = dict(EXCEPTION_NAMES_DEFAULT)
    stop_reason_names = dict(WP_STOP_REASON_NAMES)
    reg_names: dict[int, str] = dict(REG_NAMES_DEFAULT)

    entries: list[dict] = []
    memalloc_events: list[dict] = []
    sync_events: list[dict] = []
    templates: list[dict] = []
    template_by_id: dict[int, dict] = {}

    prev_entry_template = 0
    cp_dyn_state: dict[int, list[DynParam]] = {}
    wp_dyn_state: dict[int, list[DynParam]] = {}
    footer_num_entries: int | None = None

    while True:
        tag = br.read_bits(2)

        if tag == BODY_TAG_END:
            footer_num_entries = br.read_uleb128()
            break

        if tag == BODY_TAG_MEMALLOC:
            event_type = br.read_bits(2)
            vaddr = br.read_uleb128()
            size  = br.read_uleb128()
            new_vaddr = 0
            new_size  = 0
            if event_type == MEMALLOC_REMAP:
                new_vaddr = br.read_uleb128()
                new_size  = br.read_uleb128()
            memalloc_events.append({
                "event_type": event_type,
                "type_name": MEMALLOC_TYPE_NAMES.get(event_type, "UNKNOWN"),
                "vaddr": vaddr,
                "size": size,
                "new_vaddr": new_vaddr,
                "new_size": new_size,
                # associate with next body entry
                "before_entry": len(entries),
            })
            continue

        if tag == BODY_TAG_SYNC:
            sync_type = br.read_bits(WPT_SYNC_TYPE_BITS)
            addr = 0
            if sync_type in (SYNC_FUTEX_WAIT, SYNC_FUTEX_WAKE,
                             SYNC_THREAD_SWITCH):
                addr = br.read_uleb128()
            sync_events.append({
                "sync_type": sync_type,
                "type_name": SYNC_TYPE_NAMES.get(sync_type, "UNKNOWN"),
                "addr": addr,
                "before_entry": len(entries),
            })
            continue

        # tag == BODY_TAG_ENTRY
        seq_num = len(entries) + 1
        entry_tmpl = prev_entry_template + br.read_sleb128()
        prev_entry_template = entry_tmpl

        cp_unchanged = br.read_bits(1)
        prev_cp_dyn = cp_dyn_state.get(entry_tmpl, [])

        if cp_unchanged:
            if entry_tmpl not in cp_dyn_state:
                raise ValueError("cp dyn_unchanged set without prior state")
            cp_dyn = [DynParam(type_name=d.type_name, value=d.value)
                      for d in cp_dyn_state[entry_tmpl]]
        else:
            cp_dyn = decode_dyn_patch(br, prev_cp_dyn)
            cp_dyn_state[entry_tmpl] = [DynParam(type_name=d.type_name,
                                                 value=d.value)
                                        for d in cp_dyn]

        if has_mem_data:
            read_mem_data_values(br, cp_dyn)

        num_wp = br.read_uleb128()
        prev_wp_tmpl = 0
        wp_entries: list[dict] = []

        for w in range(num_wp):
            wp_tmpl = prev_wp_tmpl + br.read_sleb128()
            prev_wp_tmpl = wp_tmpl

            wp_unchanged = br.read_bits(1)
            prev_wp_dyn = wp_dyn_state.get(wp_tmpl, [])

            if wp_unchanged:
                if wp_tmpl not in wp_dyn_state:
                    raise ValueError("wp dyn_unchanged set without prior state")
                wp_dyn = [DynParam(type_name=d.type_name, value=d.value)
                          for d in wp_dyn_state[wp_tmpl]]
            else:
                wp_dyn = decode_dyn_patch(br, prev_wp_dyn)
                wp_dyn_state[wp_tmpl] = [DynParam(type_name=d.type_name,
                                                  value=d.value)
                                         for d in wp_dyn]

            if has_mem_data:
                read_mem_data_values(br, wp_dyn)

            wp_n_insns = 0
            if wp_tmpl in template_by_id:
                wp_n_insns = template_by_id[wp_tmpl]["n_insns"]

            wp_entries.append({
                "index": w,
                "template_id": wp_tmpl,
                "dyn_params": wp_dyn,
                "fault": False,
                "translation_unavailable": False,
                "stop_reason": 0,
                "stop_reason_name": None,
                "has_exception_class": False,
                "exception_id": 0,
                "exception_name": None,
                "has_exception_reg": False,
                "exception_reg": None,
                "poison_mask": [],
                "n_insns": wp_n_insns,
            })

        num_wp_events = br.read_uleb128()
        prev_wp_event_idx = -1
        for _ in range(num_wp_events):
            wp_idx_gap = br.read_uleb128()
            wp_idx = prev_wp_event_idx + 1 + wp_idx_gap

            if wp_idx >= num_wp:
                raise ValueError("wp event index out of range")

            translation_unavailable = bool(br.read_bits(1))
            fault = bool(br.read_bits(1))

            target = wp_entries[wp_idx]
            target["translation_unavailable"] = translation_unavailable
            target["fault"] = fault

            if fault:
                stop_reason = br.read_bits(8)
                target["stop_reason"] = stop_reason
                target["stop_reason_name"] = stop_reason_names.get(
                    stop_reason, "UNKNOWN")

                has_exception_class = bool(br.read_bits(1))
                target["has_exception_class"] = has_exception_class

                if has_exception_class:
                    exception_id = br.read_bits(8)
                    target["exception_id"] = exception_id
                    target["exception_name"] = exception_names.get(
                        exception_id, "UNKNOWN")

                    has_exception_reg = bool(br.read_bits(1))
                    target["has_exception_reg"] = has_exception_reg
                    if has_exception_reg:
                        exreg_id = br.read_bits(WPT_REG_BITS)
                        target["exception_reg"] = reg_names.get(
                            exreg_id, reg_name(exreg_id))

                poison_len = br.read_uleb128()
                target["poison_mask"] = [br.read_bits(8)
                                          for _ in range(poison_len)]

            prev_wp_event_idx = wp_idx

        entries.append({
            "seq_num": seq_num,
            "template_id": entry_tmpl,
            "dyn_params": cp_dyn,
            "wp_entries": wp_entries,
        })

    num_templates = br.read_uleb128()
    for _ in range(num_templates):
        template_id = br.read_uleb128()
        start_pc = br.read_uleb128()
        n_insns = br.read_uleb128()
        fall_through_pc = br.read_uleb128()
        sym_len = br.read_uleb128()
        symbol_name = read_bytes(br, sym_len).decode('utf-8', errors='replace') if sym_len else ""

        insns: list[dict] = []
        for _ in range(n_insns):
            pc = br.read_uleb128()
            opcode = br.read_bits(WPT_OPCODE_BITS)
            branch_type = br.read_bits(WPT_BRANCH_BITS)
            branch_conditional = bool(br.read_bits(1))
            n_src = br.read_bits(WPT_REG_COUNT_BITS)
            n_dst = br.read_bits(WPT_REG_COUNT_BITS)
            has_imm = br.read_bits(1)
            sync_hint = br.read_bits(WPT_SYNC_HINT_BITS)
            src_regs = [br.read_bits(WPT_REG_BITS) for _ in range(n_src)]
            dst_regs = [br.read_bits(WPT_REG_BITS) for _ in range(n_dst)]
            imm = br.read_sleb128() if has_imm else None
            insn_size = br.read_uleb128()
            raw_bytes = read_bytes(br, insn_size)

            insns.append({
                "pc": pc,
                "opcode": opcode,
                "branch_type": branch_type,
                "branch_conditional": branch_conditional,
                "src_regs": src_regs,
                "dst_regs": dst_regs,
                "imm": imm,
                "sync_hint": sync_hint,
                "raw_bytes": raw_bytes,
            })

        tmpl = {
            "template_id": template_id,
            "start_pc": start_pc,
            "n_insns": n_insns,
            "fall_through_pc": fall_through_pc,
            "symbol_name": symbol_name,
            "insns": insns,
        }
        templates.append(tmpl)
        template_by_id[template_id] = tmpl

    for entry in entries:
        for wp in entry["wp_entries"]:
            wp_tmpl = wp["template_id"]
            if wp_tmpl in template_by_id:
                wp["n_insns"] = template_by_id[wp_tmpl]["n_insns"]

    if footer_num_entries is not None and footer_num_entries != len(entries):
        raise ValueError(
            f"Footer entry count mismatch: {footer_num_entries} != {len(entries)}"
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
        "has_mem_alloc": has_mem_alloc,
        "is_threaded": is_threaded,
        "thread_id": thread_id,
        "opcode_names": opcode_names,
        "branch_names": branch_names,
        "stop_reason_names": stop_reason_names,
        "exception_names": exception_names,
        "reg_names": reg_names,
        "memalloc_events": memalloc_events,
        "sync_events": sync_events,
    }
    return meta, templates, entries


def render_text(meta: dict, templates: list[dict], entries: list[dict]) -> str:
    out: list[str] = []
    opcode_names: dict[int, str] = meta.get("opcode_names", OPCODE_NAMES)
    branch_names: dict[int, str] = meta.get("branch_names", BRANCH_NAMES)
    stop_reason_names: dict[int, str] = meta.get("stop_reason_names",
                                                  WP_STOP_REASON_NAMES)
    exception_names: dict[int, str] = meta.get("exception_names",
                                               EXCEPTION_NAMES_DEFAULT)
    reg_names: dict[int, str] = meta.get("reg_names", REG_NAMES_DEFAULT)
    has_mem_data = meta.get("has_mem_data", False)
    memalloc_events: list[dict] = meta.get("memalloc_events", [])
    sync_events: list[dict]     = meta.get("sync_events", [])

    def reg_fmt(r: int) -> str:
        return reg_names.get(r, reg_name(r))

    # META section
    out.append("META")
    out.append("----")
    out.append(f"VERSION 0x{meta.get('magic', WPT_MAGIC):08X}")
    isa_val = meta.get('isa', 0)
    isa_name = meta.get('target_name') or ISA_NAMES.get(isa_val, "unknown")
    out.append(f"ISA {isa_name}")
    out.append(f"COMMAND {meta.get('command', '')}")
    out.append(f"DATETIME {meta.get('datetime', '')}")
    out.append(f"COMMENT {meta.get('comment', '')}")
    out.append(f"THREAD {meta.get('thread_id', 0)}")
    flags_str = ""
    if has_mem_data:
        flags_str += " MEM_DATA"
    if meta.get("has_mem_alloc"):
        flags_str += " MEM_ALLOC"
    if meta.get("is_threaded"):
        flags_str += " THREADS"
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
            f"insns={tmpl['n_insns']}, fall_through=0x{tmpl['fall_through_pc']:x}]"
        )
        if tmpl.get("symbol_name"):
            out.append(f"  symbol={tmpl['symbol_name']}")

        for i, insn in enumerate(tmpl["insns"]):
            line = (
                f"  [{i}] 0x{insn['pc']:x}: op="
                f"{opcode_names.get(insn['opcode'], 'UNKNOWN')}"
            )

            if insn["branch_type"] != BRANCH_NONE:
                line += f" br={branch_names.get(insn['branch_type'], 'UNKNOWN')}"
                line += f" cond={1 if insn.get('branch_conditional') else 0}"

            src = ",".join(reg_fmt(r) for r in insn["src_regs"])
            dst = ",".join(reg_fmt(r) for r in insn["dst_regs"])
            line += f" src=[{src}] dst=[{dst}]"

            if insn["imm"] is not None:
                line += f" imm={insn['imm']}"
            if insn.get("sync_hint", 0) != 0:
                line += f" sync={SYNC_TYPE_NAMES.get(insn['sync_hint'], 'UNKNOWN')}"
            if insn.get("raw_bytes") is not None:
                line += f" bytes={insn['raw_bytes'].hex()}"

            out.append(line)

        out.append("")

    out.append("BODY")
    out.append("----")

    next_memalloc_idx = 0
    next_sync_idx = 0
    for entry_idx, entry in enumerate(entries):
        # Emit any sync events that occurred before this entry
        while (next_sync_idx < len(sync_events) and
               sync_events[next_sync_idx]["before_entry"] == entry_idx):
            ev = sync_events[next_sync_idx]
            if ev["sync_type"] in (SYNC_YIELD, SYNC_ATOMIC):
                out.append(f"SYNC type={ev['type_name']}")
            elif ev["sync_type"] == SYNC_THREAD_SWITCH:
                out.append(f"SYNC type=THREAD_SWITCH thread={ev['addr']}")
            else:
                out.append(
                    f"SYNC type={ev['type_name']} addr=0x{ev['addr']:x}"
                )
            next_sync_idx += 1

        # Emit any memalloc events that occurred before this entry
        while (next_memalloc_idx < len(memalloc_events) and
               memalloc_events[next_memalloc_idx]["before_entry"] == entry_idx):
            ev = memalloc_events[next_memalloc_idx]
            line = (
                f"MEMALLOC type={ev['type_name']} "
                f"vaddr=0x{ev['vaddr']:x} size=0x{ev['size']:x}"
            )
            if ev["type_name"] == "REMAP":
                line += (
                    f" new_vaddr=0x{ev['new_vaddr']:x}"
                    f" new_size=0x{ev['new_size']:x}"
                )
            out.append(line)
            next_memalloc_idx += 1

        dyn_str = " ".join(
            format_dyn(dp, show_data=has_mem_data) for dp in entry["dyn_params"]
        )
        line = f"{entry['seq_num']:04d} BB{entry['template_id']} [{dyn_str}]"

        for wp in entry["wp_entries"]:
            line += f" [wp{wp['index']}=BB{wp['template_id']}"
            for dp in wp["dyn_params"]:
                line += f" {format_dyn(dp, show_data=has_mem_data)}"
            if wp["fault"]:
                line += " FAULT"
                if wp.get("stop_reason", 0) != 0 and wp.get("stop_reason_name"):
                    line += f" stop={wp['stop_reason_name']}"
                if wp.get("has_exception_class"):
                    line += f" exid={wp.get('exception_name', 'UNKNOWN')}"
                    if wp.get("has_exception_reg") and wp.get("exception_reg"):
                        line += f" exreg={wp['exception_reg']}"
            if wp.get("translation_unavailable"):
                line += " TRANSLATION_UNAVAILABLE"
            if wp.get("poison_mask"):
                mask = "".join("1" if x else "0" for x in wp["poison_mask"])
                line += f" poison={mask}"
            line += f" n_insns={wp['n_insns']}]"

        out.append(line)

    return "\n".join(out) + "\n"


def first_diff_line(a: str, b: str) -> tuple[int, str, str] | None:
    a_lines = a.splitlines()
    b_lines = b.splitlines()
    max_len = max(len(a_lines), len(b_lines))

    for i in range(max_len):
        left = a_lines[i] if i < len(a_lines) else "<EOF>"
        right = b_lines[i] if i < len(b_lines) else "<EOF>"
        if left != right:
            return i + 1, left, right

    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Decode wptrace binary (.bin, format v0.5) and reconstruct debug text format"
        )
    )
    parser.add_argument("bin", type=Path, help="Input wptrace binary file")
    parser.add_argument(
        "-o",
        "--out",
        type=Path,
        help="Output reconstructed text path (default: stdout)",
    )
    parser.add_argument(
        "--expect",
        type=Path,
        help="Expected debug text file; enables exact comparison check",
    )
    args = parser.parse_args()

    meta, templates, entries = decode_wptrace(args.bin)
    text = render_text(meta, templates, entries)

    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)

    if args.expect:
        expected = args.expect.read_text()
        if text == expected:
            print("VERIFY: OK (reconstructed text matches expected exactly)")
            return 0

        diff = first_diff_line(text, expected)
        if diff:
            line_no, got, exp = diff
            print(f"VERIFY: FAIL at line {line_no}")
            print(f"  got: {got}")
            print(f"  exp: {exp}")
        else:
            print("VERIFY: FAIL (content differs)")
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
