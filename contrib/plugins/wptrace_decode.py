#!/usr/bin/env python3

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path


WPT_MAGIC = 0x54505703

WPT_ISA_BITS = 3
WPT_OPCODE_BITS = 8
WPT_BRANCH_BITS = 8
WPT_REG_COUNT_BITS = 3
WPT_REG_BITS = 8

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
    5: "SYSCALL",
}


@dataclass
class DynParam:
    type_name: str
    value: int


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


def format_dyn(dp: DynParam) -> str:
    return f"{dp.type_name}=0x{dp.value:x}"


def decode_wptrace(bin_path: Path) -> tuple[dict, list[dict], list[dict]]:
    data = bin_path.read_bytes()
    br = BitReader(data)

    magic = br.read_bits(32)
    if magic != WPT_MAGIC:
        raise ValueError(
            f"Bad magic 0x{magic:08x}, expected 0x{WPT_MAGIC:08x}"
        )

    isa = br.read_bits(WPT_ISA_BITS)
    opcode_names = dict(OPCODE_NAMES)
    branch_names = dict(BRANCH_NAMES)
    exception_names = dict(EXCEPTION_NAMES_DEFAULT)
    reg_names: dict[int, str] = {}

    num_templates = br.read_uleb128()

    templates: list[dict] = []
    template_by_id: dict[int, dict] = {}

    for _ in range(num_templates):
        template_id = br.read_uleb128()
        start_pc = br.read_uleb128()
        n_insns = br.read_uleb128()
        fall_through_pc = br.read_uleb128()
        symbol_name = ""

        insns: list[dict] = []
        for _ in range(n_insns):
            pc = br.read_uleb128()
            opcode = br.read_bits(WPT_OPCODE_BITS)
            branch_type = br.read_bits(WPT_BRANCH_BITS)
            branch_conditional = bool(br.read_bits(1))
            n_src = br.read_bits(WPT_REG_COUNT_BITS)
            n_dst = br.read_bits(WPT_REG_COUNT_BITS)
            has_imm = br.read_bits(1)

            src_regs = [br.read_bits(WPT_REG_BITS) for _ in range(n_src)]
            dst_regs = [br.read_bits(WPT_REG_BITS) for _ in range(n_dst)]
            imm = br.read_sleb128() if has_imm else None
            # v0.3 keeps only instruction size in the header (raw bytes removed).
            _insn_size = br.read_uleb128()
            raw_bytes = b""

            insns.append({
                "pc": pc,
                "opcode": opcode,
                "branch_type": branch_type,
                "branch_conditional": branch_conditional,
                "src_regs": src_regs,
                "dst_regs": dst_regs,
                "imm": imm,
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

    num_entries = br.read_uleb128()
    num_wp_chains = br.read_uleb128()
    wp_chains: list[list[int]] = []

    for _ in range(num_wp_chains):
        chain_len = br.read_uleb128()
        prev_tid = 0
        chain: list[int] = []

        for _ in range(chain_len):
            prev_tid = prev_tid + br.read_sleb128()
            chain.append(prev_tid)

        wp_chains.append(chain)

    entries: list[dict] = []

    prev_entry_template = 0
    cp_dyn_state: dict[int, list[DynParam]] = {}
    wp_dyn_state: dict[int, list[DynParam]] = {}

    for seq_num in range(1, num_entries + 1):
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

        chain_id = br.read_uleb128()
        if chain_id >= len(wp_chains):
            raise ValueError("wp chain id out of range")

        chain = wp_chains[chain_id]
        num_wp = len(chain)
        wp_entries: list[dict] = []

        for w in range(num_wp):
            wp_tmpl = chain[w]

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

            translation_unavailable = False
            exception = False
            exception_id = 0
            exception_name = None
            exreg_name = None
            poison_mask: list[int] = []
            wp_n_insns = 0
            if wp_tmpl in template_by_id:
                wp_n_insns = template_by_id[wp_tmpl]["n_insns"]

            wp_entries.append({
                "index": w,
                "template_id": wp_tmpl,
                "dyn_params": wp_dyn,
                "exception": bool(exception),
                "translation_unavailable": translation_unavailable,
                "exception_id": exception_id,
                "exception_name": exception_name,
                "exception_reg": exreg_name,
                "poison_mask": poison_mask,
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
            exception = bool(br.read_bits(1))

            target = wp_entries[wp_idx]
            target["translation_unavailable"] = translation_unavailable
            target["exception"] = exception

            if exception:
                exception_id = br.read_bits(8)
                target["exception_id"] = exception_id
                target["exception_name"] = exception_names.get(exception_id,
                                                                  "UNKNOWN")
                has_exreg = br.read_bits(1)
                if has_exreg:
                    exreg_id = br.read_bits(WPT_REG_BITS)
                    target["exception_reg"] = reg_names.get(exreg_id,
                                                              reg_name(exreg_id))
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

    meta = {
        "magic": magic,
        "isa": isa,
        "opcode_names": opcode_names,
        "branch_names": branch_names,
        "exception_names": exception_names,
        "reg_names": reg_names,
    }
    return meta, templates, entries


def render_text(meta: dict, templates: list[dict], entries: list[dict]) -> str:
    out: list[str] = []
    opcode_names: dict[int, str] = meta.get("opcode_names", OPCODE_NAMES)
    branch_names: dict[int, str] = meta.get("branch_names", BRANCH_NAMES)
    exception_names: dict[int, str] = meta.get("exception_names", EXCEPTION_NAMES_DEFAULT)
    reg_names: dict[int, str] = meta.get("reg_names", {})

    def reg_fmt(r: int) -> str:
        return reg_names.get(r, reg_name(r))

    out.append("ENUMS")
    out.append("-----")
    out.append(f"OPCODES {len(opcode_names)}")
    for k in sorted(opcode_names):
        out.append(f"O {k} {opcode_names[k]}")
    out.append(f"BRANCHES {len(branch_names)}")
    for k in sorted(branch_names):
        out.append(f"B {k} {branch_names[k]}")
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
            if insn.get("raw_bytes") is not None:
                line += f" bytes={insn['raw_bytes'].hex()}"

            out.append(line)

        out.append("")

    out.append("BODY")
    out.append("----")

    for entry in entries:
        dyn_str = " ".join(format_dyn(dp) for dp in entry["dyn_params"])
        line = f"{entry['seq_num']:04d} BB{entry['template_id']} [{dyn_str}]"

        for wp in entry["wp_entries"]:
            line += f" [wp{wp['index']}=BB{wp['template_id']}"
            for dp in wp["dyn_params"]:
                line += f" {format_dyn(dp)}"
            if wp["exception"]:
                line += " EXCEPTION"
                if wp.get("exception_name"):
                    line += f" exid={wp['exception_name']}"
                if wp.get("exception_reg"):
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
            "Decode wptrace binary (.bin, format v0.3) and reconstruct debug text format"
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