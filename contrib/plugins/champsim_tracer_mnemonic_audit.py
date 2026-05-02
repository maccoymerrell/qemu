#!/usr/bin/env python3
"""Audit and regenerate champsim_tracer mnemonic classification tables.

The script intentionally derives mnemonics from the in-tree Capstone C enum
names instead of Capstone's Python id-to-name API.  Some local Capstone Python
bindings can drift from the rebuilt C library, while the plugin compiles
against the C headers.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_DIR = Path(__file__).resolve().parent
CAPSTONE_INCLUDE = ROOT / "subprojects" / "capstone" / "include" / "capstone"
GDB_XML_DIR = ROOT / "gdb-xml"


@dataclass(frozen=True)
class Entry:
    op: str
    branch: str = "BRANCH_NONE"
    flags: str = "MF_NONE"
    refine: str | None = None

    def without_refine(self) -> "Entry":
        return Entry(self.op, self.branch, self.flags)


@dataclass(frozen=True)
class IsaInfo:
    key: str
    prefix: str
    reg_prefix: str
    header: Path
    capstone_header: Path
    table: str
    array_size: str
    reg_table: str
    reg_array_size: str


ISAS = {
    "x86": IsaInfo(
        "x86",
        "X86_INS_",
        "X86_REG_",
        PLUGIN_DIR / "champsim_tracer_mnemonics_x86.h",
        CAPSTONE_INCLUDE / "x86.h",
        "x86_insn_class",
        "X86_INS_ENDING",
        "x86_reg_class",
        "X86_REG_ENDING",
    ),
    "aarch64": IsaInfo(
        "aarch64",
        "AARCH64_INS_",
        "AARCH64_REG_",
        PLUGIN_DIR / "champsim_tracer_mnemonics_aarch64.h",
        CAPSTONE_INCLUDE / "aarch64.h",
        "aarch64_insn_class",
        "AARCH64_INS_ENDING",
        "aarch64_reg_class",
        "AARCH64_REG_ENDING",
    ),
    "riscv": IsaInfo(
        "riscv",
        "RISCV_INS_",
        "RISCV_REG_",
        PLUGIN_DIR / "champsim_tracer_mnemonics_riscv.h",
        CAPSTONE_INCLUDE / "riscv.h",
        "riscv_insn_class",
        "RISCV_INS_ENDING",
        "riscv_reg_class",
        "RISCV_REG_ENDING",
    ),
    "mips": IsaInfo(
        "mips",
        "MIPS_INS_",
        "MIPS_REG_",
        PLUGIN_DIR / "champsim_tracer_mnemonics_mips.h",
        CAPSTONE_INCLUDE / "mips.h",
        "mips_insn_class",
        "MIPS_INS_ENDING",
        "mips_reg_class",
        "MIPS_REG_ENDING",
    ),
}


@dataclass(frozen=True)
class RegEntry:
    primary: str
    aliases: tuple[str, ...] = ()

    @property
    def ignored(self) -> bool:
        return self.primary == "REG_NONE" and not self.aliases


@dataclass(frozen=True)
class QemuRegKey:
    feature: str
    name: str


@dataclass(frozen=True)
class GdbXmlFeature:
    feature_name: str
    regs: dict[str, int]
    names_by_local: tuple[str | None, ...]
    num_regs: int


ENTRY_RE = re.compile(
    r"\[\s*(?P<const>[A-Z0-9_]+)\s*\]\s*=\s*\{\s*"
    r"(?P<op>GEN_OP_[A-Z0-9_]+)\s*,\s*"
    r"(?P<branch>BRANCH_[A-Z0-9_]+)\s*,\s*"
    r"(?P<flags>(?:MF_[A-Z0-9_]+|0)(?:\s*\|\s*MF_[A-Z0-9_]+)*)\s*"
    r"(?:,\s*\.refine\s*=\s*(?P<refine>[A-Za-z_][A-Za-z0-9_]*))?\s*\}",
    re.DOTALL,
)


def norm_flags(flags: str) -> str:
    flags = re.sub(r"\s+", "", flags)
    if flags == "0":
        return "MF_NONE"
    if flags == "MF_NONE|MF_NONE":
        return "MF_NONE"
    return " | ".join(part for part in flags.split("|") if part != "MF_NONE") or "MF_NONE"


def add_flag(flags: str, flag: str) -> str:
    flags = norm_flags(flags)
    if flags == "MF_NONE":
        return flag
    parts = flags.split(" | ")
    if flag not in parts:
        parts.append(flag)
    return " | ".join(parts)


def c_mnemonic(const_name: str, prefix: str) -> str:
    return const_name.removeprefix(prefix).lower()


def enum_constants(info: IsaInfo) -> list[str]:
    text = info.capstone_header.read_text()
    try:
        start = text.index(info.prefix + "INVALID")
        end = text.index(info.prefix + "ENDING", start)
    except ValueError as exc:
        raise SystemExit(f"could not find instruction enum in {info.capstone_header}") from exc
    enum_text = text[start:end]
    seen: set[str] = set()
    names: list[str] = []
    for match in re.finditer(r"\b" + re.escape(info.prefix) + r"[A-Z0-9_]+\b", enum_text):
        name = match.group(0)
        if name.endswith("INVALID") or name.endswith("ENDING") or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def enum_reg_constants(info: IsaInfo) -> list[str]:
    text = info.capstone_header.read_text()
    try:
        start = text.index(info.reg_prefix + "INVALID")
        end = text.index(info.reg_prefix + "ENDING", start)
    except ValueError as exc:
        raise SystemExit(f"could not find register enum in {info.capstone_header}") from exc
    enum_text = text[start:end]
    seen: set[str] = set()
    names: list[str] = []
    for match in re.finditer(r"\b" + re.escape(info.reg_prefix) + r"[A-Z0-9_]+\b", enum_text):
        name = match.group(0)
        if name.endswith("INVALID") or name.endswith("ENDING") or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def parse_existing(info: IsaInfo) -> dict[str, Entry]:
    text = info.header.read_text()
    body = table_body(text, info)
    entries: dict[str, Entry] = {}
    for match in ENTRY_RE.finditer(body):
        entries[match.group("const")] = Entry(
            match.group("op"),
            match.group("branch"),
            norm_flags(match.group("flags")),
            match.group("refine"),
        )
    return entries


def table_body(text: str, info: IsaInfo) -> str:
    pat = re.compile(
        r"\bstatic\s+const\s+InsnClassification\s+"
        + re.escape(info.table)
        + r"\s*\[\s*"
        + re.escape(info.array_size)
        + r"\s*\]\s*=\s*\{",
        re.DOTALL,
    )
    match = pat.search(text)
    if not match:
        raise SystemExit(f"could not find table {info.table} in {info.header}")
    start = match.end()
    depth = 1
    pos = start
    while pos < len(text):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[start:pos]
        pos += 1
    raise SystemExit(f"unterminated table {info.table} in {info.header}")


def replace_table_body(text: str, info: IsaInfo, new_body: str) -> str:
    pat = re.compile(
        r"\bstatic\s+const\s+InsnClassification\s+"
        + re.escape(info.table)
        + r"\s*\[\s*"
        + re.escape(info.array_size)
        + r"\s*\]\s*=\s*\{",
        re.DOTALL,
    )
    match = pat.search(text)
    if not match:
        raise SystemExit(f"could not find table {info.table} in {info.header}")
    start = match.end()
    depth = 1
    pos = start
    while pos < len(text):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[:start] + "\n" + new_body + text[pos:]
        pos += 1
    raise SystemExit(f"unterminated table {info.table} in {info.header}")


def replace_reg_table_body(text: str, info: IsaInfo, new_body: str) -> str:
    pat = re.compile(
        r"\bstatic\s+const\s+RegClassification\s+"
        + re.escape(info.reg_table)
        + r"\s*\[\s*"
        + re.escape(info.reg_array_size)
        + r"\s*\]\s*=\s*\{",
        re.DOTALL,
    )
    match = pat.search(text)
    if not match:
        raise SystemExit(f"could not find table {info.reg_table} in {info.header}")
    start = match.end()
    depth = 1
    pos = start
    while pos < len(text):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[:start] + "\n" + new_body + text[pos:]
        pos += 1
    raise SystemExit(f"unterminated table {info.reg_table} in {info.header}")


def ent(op: str, branch: str = "BRANCH_NONE", flags: str = "MF_NONE") -> Entry:
    return Entry(op, branch, norm_flags(flags))


def reg_ent(primary: str, aliases: list[str] | tuple[str, ...] = ()) -> RegEntry:
    aliases_t = tuple(aliases)
    if aliases_t == (primary,):
        aliases_t = ()
    return RegEntry(primary, aliases_t)


def reg_none() -> RegEntry:
    return RegEntry("REG_NONE")


def numbered(prefix: str, idx: int) -> str:
    return f"{prefix}{idx}"


def first_number(name: str) -> int | None:
    match = re.search(r"\d+", name)
    return int(match.group(0)) if match else None


def all_numbered(name: str, letter: str) -> list[int]:
    return [int(m.group(1)) for m in re.finditer(rf"(?<![A-Z]){letter}(\d+)", name)]


def reg_names_from_tokens(name: str, family: str, out_prefix: str) -> list[str]:
    regs: list[str] = []
    for num in all_numbered(name, family):
        reg = numbered(out_prefix, num)
        if reg not in regs:
            regs.append(reg)
    return regs


def riscv_vector_aliases(name: str) -> list[str]:
    # V0M2/V0M4/V0M8 denote LMUL register groups starting at V0.
    match = re.fullmatch(r"V(\d+)", name)
    if match:
        return [numbered("REG_VEC", int(match.group(1)))]
    match = re.fullmatch(r"V(\d+)M([248])", name)
    if match:
        base = int(match.group(1))
        width = int(match.group(2))
        return [numbered("REG_VEC", base + i) for i in range(width) if base + i < 64]
    regs: list[str] = []
    for token in name.split("_"):
        part = riscv_vector_aliases(token)
        if part:
            for reg in part:
                if reg not in regs:
                    regs.append(reg)
            continue
        match = re.fullmatch(r"V(\d+)", token)
        if match:
            reg = numbered("REG_VEC", int(match.group(1)))
            if reg not in regs:
                regs.append(reg)
    return regs


def classify_x86_reg(name: str) -> RegEntry:
    gpr_aliases = {
        "A": 0, "B": 3, "C": 1, "D": 2,
        "SI": 4, "DI": 5,
        "BP": None, "SP": "REG_SP",
    }
    if name in {"EIZ", "RIZ"}:
        return reg_none()
    if name in {"IP", "EIP", "RIP"}:
        return reg_ent("REG_IP")
    if name in {"EFLAGS", "FPSW"}:
        return reg_ent("REG_FLAGS")
    segs = {"CS": 0, "DS": 1, "ES": 2, "FS": 3, "GS": 4, "SS": 5}
    if name in segs:
        return reg_ent(numbered("REG_SEG", segs[name]))
    if match := re.fullmatch(r"CR(\d+)", name):
        return reg_ent("REG_CTRL")
    if match := re.fullmatch(r"DR(\d+)", name):
        return reg_ent("REG_DEBUG")
    if match := re.fullmatch(r"K(\d+)", name):
        return reg_ent(numbered("REG_PRED", int(match.group(1))))
    if match := re.fullmatch(r"BND(\d+)", name):
        return reg_ent(numbered("REG_BOUND", int(match.group(1))))
    if match := re.fullmatch(r"(?:FP|ST)(\d+)", name):
        return reg_ent(numbered("REG_FPR", int(match.group(1))))
    if match := re.fullmatch(r"MM(\d+)", name):
        return reg_ent(numbered("REG_VEC", int(match.group(1))))
    if match := re.fullmatch(r"[XYZ]MM(\d+)", name):
        return reg_ent(numbered("REG_VEC", int(match.group(1))))
    if match := re.fullmatch(r"R(\d+)(?:[BDW])?", name):
        return reg_ent(numbered("REG_GPR", int(match.group(1)) - 2))
    for base, target in gpr_aliases.items():
        if re.fullmatch(rf"[ER]?{base}[XHL]?|{base}L", name):
            if target == "REG_SP":
                return reg_ent("REG_SP")
            if target is None:
                return reg_ent("REG_FP_REG")
            return reg_ent(numbered("REG_GPR", target))
    return reg_none()


def classify_aarch64_reg(name: str) -> RegEntry:
    if name in {"X_LANE", "Y_LANE"}:
        return reg_none()
    if name in {"WZR", "XZR"}:
        return reg_ent("REG_ZERO")
    if name in {"SP", "WSP"}:
        return reg_ent("REG_SP")
    if name == "LR":
        return reg_ent("REG_LR")
    if name == "LR_XZR":
        return reg_ent("REG_LR", ["REG_LR", "REG_ZERO"])
    if name == "FP":
        return reg_ent("REG_FP_REG")
    if name == "NZCV":
        return reg_ent("REG_FLAGS")
    if name == "FPCR":
        return reg_ent("REG_FCSR")
    if name in {"FFR", "VG"}:
        return reg_ent("REG_VCTRL")
    if name.startswith(("ZA", "ZT")) or name == "Z_MATRIX":
        return reg_ent("REG_MATRIX")
    if re.fullmatch(r"P\d+", name):
        return reg_ent(numbered("REG_PRED", int(name[1:])))
    if re.fullmatch(r"PN\d+", name):
        return reg_ent(numbered("REG_PRED", 16 + int(name[2:])))
    if name.startswith("P") and "_" in name:
        regs = reg_names_from_tokens(name, "P", "REG_PRED")
        return reg_ent(regs[0], regs) if regs else reg_none()
    if re.fullmatch(r"[BHSQDZ]\d+", name):
        return reg_ent(numbered("REG_VEC", first_number(name) or 0))
    if name[0] in "DQZ" and "_" in name:
        regs = reg_names_from_tokens(name, name[0], "REG_VEC")
        return reg_ent(regs[0], regs) if regs else reg_none()
    if re.fullmatch(r"W\d+", name) or re.fullmatch(r"X\d+", name):
        return reg_ent(numbered("REG_GPR", first_number(name) or 0))
    if name.startswith(("W", "X")) and "_" in name:
        regs: list[str] = []
        for token in name.split("_"):
            if token == "FP":
                reg = "REG_FP_REG"
            elif token in {"LR", "XZR", "WZR"}:
                reg = "REG_LR" if token == "LR" else "REG_ZERO"
            elif re.fullmatch(r"[WX]\d+", token):
                reg = numbered("REG_GPR", first_number(token) or 0)
            else:
                reg = None
            if reg and reg not in regs:
                regs.append(reg)
        return reg_ent(regs[0], regs) if regs else reg_none()
    return reg_none()


def classify_riscv_reg(name: str) -> RegEntry:
    if name in {"X0", "X0_PAIR", "DUMMY_REG_PAIR_WITH_X0"}:
        return reg_ent("REG_ZERO")
    if name == "SSP":
        return reg_ent("REG_SP")
    if name in {"FFLAGS", "FRM"}:
        return reg_ent("REG_FCSR")
    if name in {"VL", "VLENB", "VTYPE", "VXRM", "VXSAT"}:
        return reg_ent("REG_VCTRL")
    if re.fullmatch(r"X\d+", name):
        num = first_number(name) or 0
        if num == 1:
            return reg_ent("REG_LR")
        if num == 2:
            return reg_ent("REG_SP")
        if num == 8:
            return reg_ent("REG_FP_REG")
        return reg_ent(numbered("REG_GPR", num))
    if name.startswith("X") and "_" in name:
        regs: list[str] = []
        for num in all_numbered(name, "X"):
            reg = "REG_ZERO" if num == 0 else "REG_LR" if num == 1 else "REG_SP" if num == 2 else "REG_FP_REG" if num == 8 else numbered("REG_GPR", num)
            if reg not in regs:
                regs.append(reg)
        return reg_ent(regs[0], regs) if regs else reg_none()
    if match := re.fullmatch(r"F(\d+)_[DFH]", name):
        return reg_ent(numbered("REG_FPR", int(match.group(1))))
    regs = riscv_vector_aliases(name)
    if regs:
        return reg_ent(regs[0], regs)
    return reg_none()


MIPS_GPR_NUM = {
    "AT": 1, "V0": 2, "V1": 3,
    "A0": 4, "A1": 5, "A2": 6, "A3": 7,
    "A4": 8, "A5": 9, "A6": 10, "A7": 11,
    "T0": 8, "T1": 9, "T2": 10, "T3": 11, "T4": 12, "T5": 13,
    "T6": 14, "T7": 15, "S0": 16, "S1": 17, "S2": 18, "S3": 19,
    "S4": 20, "S5": 21, "S6": 22, "S7": 23, "T8": 24, "T9": 25,
    "K0": 26, "K1": 27, "GP": 28, "SP": 29, "FP": 30, "RA": 31,
}


def classify_mips_reg(name: str) -> RegEntry:
    stem = re.sub(r"(?:_NM|_64)$", "", name)
    if stem == "ZERO":
        return reg_ent("REG_ZERO")
    if stem == "PC":
        return reg_ent("REG_IP")
    if stem == "SP":
        return reg_ent("REG_SP")
    if stem == "FP":
        return reg_ent("REG_FP_REG")
    if stem == "RA":
        return reg_ent("REG_LR")
    if stem in MIPS_GPR_NUM:
        return reg_ent(numbered("REG_GPR", MIPS_GPR_NUM[stem]))
    if match := re.fullmatch(r"F(\d+)", stem):
        return reg_ent(numbered("REG_FPR", int(match.group(1))))
    if match := re.fullmatch(r"D(\d+)", stem):
        return reg_ent(numbered("REG_FPR", int(match.group(1))))
    if match := re.fullmatch(r"F_HI(\d+)", stem):
        return reg_ent(numbered("REG_FPR", int(match.group(1))))
    if match := re.fullmatch(r"W(\d+)", stem):
        return reg_ent(numbered("REG_VEC", int(match.group(1))))
    if match := re.fullmatch(r"(?:MSA|FCC)(\d+)", stem):
        return reg_ent(numbered("REG_PRED", int(match.group(1)) % 32))
    if match := re.fullmatch(r"(?:AC|HI|LO|MPL|P)(\d+)", stem):
        return reg_ent(numbered("REG_ACC", int(match.group(1)) % 4))
    if stem.startswith("FCR"):
        return reg_ent("REG_FCSR")
    if stem.startswith(("HWR", "COP")):
        return reg_ent("REG_SYS")
    if stem.startswith("DSP"):
        return reg_ent("REG_FLAGS" if "COND" in stem or "CARRY" in stem or "OUTFLAG" in stem else "REG_VCTRL")
    if stem.startswith("MSA"):
        return reg_ent("REG_VCTRL")
    return reg_none()


REG_CLASSIFIERS = {
    "x86": classify_x86_reg,
    "aarch64": classify_aarch64_reg,
    "riscv": classify_riscv_reg,
    "mips": classify_mips_reg,
}


def classify_reg(info: IsaInfo, const_name: str) -> RegEntry:
    return REG_CLASSIFIERS[info.key](const_name.removeprefix(info.reg_prefix))


MADD_OPS = {
    "GEN_OP_INT_MADD", "GEN_OP_INT_MSUB",
    "GEN_OP_FP_MADD", "GEN_OP_FP_MSUB",
    "GEN_OP_VEC_MADD", "GEN_OP_VEC_MSUB",
}


def classify_x86(m: str) -> Entry:
    jcc = {
        "ja", "jae", "jb", "jbe", "jc", "je", "jecxz", "jg", "jge",
        "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne",
        "jng", "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz",
        "jo", "jp", "jpe", "jpo", "jrcxz", "js", "jz", "jcxz",
        "loop", "loope", "loopne",
    }
    if m in jcc:
        return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
    if m in {"jmp", "ljmp"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m in {"call", "lcall"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m.startswith("ret") or m.startswith("iret"):
        return ent("GEN_OP_RET", "BRANCH_RETURN")
    if m in {"syscall", "sysenter", "sysexit", "int", "int1", "int3", "into", "vmcall", "vmmcall"}:
        return ent("GEN_OP_SYSCALL", "BRANCH_SYSCALL_TYPE")
    if m in {"ud0", "ud1", "ud2", "hlt", "cpuid", "rdtsc", "rdtscp", "xgetbv", "xsetbv", "endbr32", "endbr64", "wait", "clc", "cld", "cli", "sti", "clac", "stac", "clts", "cmc", "stc", "std", "pause", "rdsspq", "clgi", "getsec", "pconfig", "rsm", "skinit", "stgi", "swapgs", "encls", "enclu", "enclv", "emms", "data16", "lock", "rep", "repne", "rex64", "xacquire", "xrelease"}:
        return ent("GEN_OP_NOP")
    if m.startswith("nop") or m.startswith("prefetch"):
        return ent("GEN_OP_NOP")
    if m.startswith(("lfence", "mfence", "sfence")):
        return ent("GEN_OP_FENCE", flags="MF_ATOMIC")

    if re.match(r"^(lzcnt|tzcnt|popcnt)", m):
        return ent("GEN_OP_AND")
    if m in {"aaa", "aad", "aam", "aas", "daa", "das"}:
        return ent("GEN_OP_INT_ADD")
    if m.startswith("adox"):
        return ent("GEN_OP_INT_ADC")
    if m.startswith(("aes", "sha", "xcrypt", "xsha")):
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith(("gf2p8mul", "pclmul")):
        return ent("GEN_OP_VEC_MUL")
    if m.startswith("gf2p8") or m.startswith("crc32"):
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith("k"):
        if m.startswith("kadd"):
            return ent("GEN_OP_VEC_ADD")
        if m.startswith("kshift"):
            return ent("GEN_OP_VEC_LOGIC")
        if m.startswith(("ktest", "kortest")):
            return ent("GEN_OP_TEST")
        if m.startswith("kmov"):
            return ent("GEN_OP_VEC_MOV")
        if m.startswith("knot"):
            return ent("GEN_OP_NOT")
        if m.startswith("kunpck"):
            return ent("GEN_OP_VEC_SHUF")
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith("push"):
        return ent("GEN_OP_PUSH")
    if m == "enter":
        return ent("GEN_OP_PUSH")
    if m.startswith("pop"):
        return ent("GEN_OP_POP")
    if m == "leave":
        return ent("GEN_OP_POP")
    if m.startswith("clflush") or m.startswith(("cldemote", "clwb", "invd", "invlpg", "invept", "invpcid", "invvpid", "wbinvd", "wbnoinvd", "serialize")):
        return ent("GEN_OP_FENCE", flags="MF_ATOMIC")
    if m.startswith("xsave") or m.startswith("stmxcsr") or m.startswith(("clrssbsy", "clzero", "ptwrite", "sgdt", "sidt", "wrssd", "wrssq", "wrussd", "wrussq", "xstore")) or re.match(r"^out", m):
        return ent("GEN_OP_STORE")
    if m.startswith("xrstor") or m.startswith("ldmxcsr") or m.startswith(("lgdt", "lidt", "lldt", "llwpcb", "lmsw", "ltr", "rdmsr", "rdpmc", "rstorssp", "sldt", "slwpcb", "smsw", "str")) or re.match(r"^in(s|$)", m):
        return ent("GEN_OP_LOAD")
    if m.startswith("maskmov"):
        return ent("GEN_OP_STORE")
    if m.startswith(("bndldx", "lds", "les", "lfs", "lgs", "lss", "xlat")):
        return ent("GEN_OP_LOAD")
    if m.startswith("bndstx"):
        return ent("GEN_OP_STORE")
    if m.startswith(("bndcl", "bndcu", "bndcn", "bound", "arpl")):
        return ent("GEN_OP_CMP")
    if m.startswith(("bndmk", "bndmov", "lar", "lsl", "lahf", "sahf", "lwpins", "lwpval", "rdfsbase", "rdgsbase", "rdrand", "rdseed", "rdpid", "rdpkru", "rdsspd", "saveprevssp", "wrfsbase", "wrgsbase", "wrmsr", "wrpkru")):
        return ent("GEN_OP_MOV")
    if m.startswith(("monitor", "mwait", "umonitor", "umwait", "tpause", "xabort", "xbegin", "xend", "xtest")):
        return ent("GEN_OP_NOP")

    if m.startswith("cmpxchg") or m.startswith("xchg") or m.startswith("xadd"):
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    if m.startswith("cmov") or m.startswith("fcmov"):
        return ent("GEN_OP_CMOV")
    if re.match(r"^set[a-z0-9]+$", m):
        return ent("GEN_OP_SETCC")
    if m == "salc":
        return ent("GEN_OP_SETCC")
    if re.match(r"^movs[bwq]$", m):
        return ent("GEN_OP_MOV")
    if re.match(r"^stos[bwdq]$", m):
        return ent("GEN_OP_STORE")
    if re.match(r"^lods[bwdq]$", m):
        return ent("GEN_OP_LOAD")
    if re.match(r"^scas[bwdq]$", m):
        return ent("GEN_OP_CMP")
    if m.startswith(("movsx", "movsxd", "cbw", "cwde", "cdqe", "cwd", "cdq", "cqo")):
        return ent("GEN_OP_MOVSX")
    if m.startswith("movzx"):
        return ent("GEN_OP_MOVZX")
    if m.startswith("lea"):
        return ent("GEN_OP_LEA")
    if m.startswith("mov") or m in {"bswap"}:
        if re.match(r"^mov[a-z]*(ps|pd|dqa|dqu|hp|lp|nt|dq|ap|up|hl|lh|msk|shdup|sldup)", m):
            return ent("GEN_OP_VEC_MOV")
        if re.match(r"^mov[a-z]*s[sd]$", m):
            return ent("GEN_OP_FP_MOV")
        return ent("GEN_OP_MOV")

    if m in {"comisd", "comiss", "ucomisd", "ucomiss"}:
        return ent("GEN_OP_FP_CMP")
    if re.match(r"^(addsub|add|sub|mul|div|sqrt|max|min|cmp|round|cvt)(pd|ps|sd|ss)", m):
        if m.startswith("add"):
            return ent("GEN_OP_FP_ADD")
        if m.startswith("sub"):
            return ent("GEN_OP_FP_SUB")
        if m.startswith("mul"):
            return ent("GEN_OP_FP_MUL")
        if m.startswith("div"):
            return ent("GEN_OP_FP_DIV")
        if m.startswith("sqrt"):
            return ent("GEN_OP_FP_SQRT")
        if m.startswith(("max", "min", "cmp")):
            return ent("GEN_OP_FP_CMP")
        return ent("GEN_OP_FP_CVT")
    if re.match(r"^(and|andn|or|xor)(pd|ps)$", m):
        return ent("GEN_OP_VEC_LOGIC")

    if m.startswith("adc"):
        return ent("GEN_OP_INT_ADC")
    if m.startswith("sbb"):
        return ent("GEN_OP_INT_SBB")
    if m.startswith("add"):
        return ent("GEN_OP_INT_ADD")
    if m.startswith("sub"):
        return ent("GEN_OP_INT_SUB")
    if m.startswith(("imul", "mul")):
        return ent("GEN_OP_INT_MUL")
    if m.startswith(("idiv", "div")):
        return ent("GEN_OP_INT_DIV")
    if m.startswith(("and", "andn", "bextr", "blc", "bls", "t1mskc", "tzmsk", "bextr", "blsi", "blsmsk", "blsr", "bzhi", "pdep", "pext", "popcnt", "lzcnt", "tzcnt", "bsf", "bsr")):
        return ent("GEN_OP_AND")
    if re.match(r"^or", m):
        return ent("GEN_OP_OR")
    if re.match(r"^xor", m):
        return ent("GEN_OP_XOR")
    if m.startswith("not"):
        return ent("GEN_OP_NOT")
    if m.startswith("neg"):
        return ent("GEN_OP_NEG")
    if m.startswith("inc"):
        return ent("GEN_OP_INC")
    if m.startswith("dec"):
        return ent("GEN_OP_DEC")
    if m.startswith("cmp"):
        return ent("GEN_OP_CMP")
    if m.startswith("test") or re.match(r"^bt[csrt]?$", m):
        return ent("GEN_OP_TEST")
    if m.startswith(("shl", "sal", "shlx")):
        return ent("GEN_OP_SHL")
    if m.startswith(("shr", "shrx")):
        return ent("GEN_OP_SHR")
    if m.startswith(("sar", "sarx")):
        return ent("GEN_OP_SAR")
    if m.startswith(("rol", "rcl")):
        return ent("GEN_OP_ROL")
    if m.startswith(("ror", "rcr")):
        return ent("GEN_OP_ROR")

    if m.startswith("f"):
        if m.startswith(("fnstcw", "fstcw", "fnstsw", "fstsw", "fnstenv", "fstenv", "fnsave", "fsave", "fxsave")):
            return ent("GEN_OP_STORE")
        if m.startswith(("fldcw", "fldenv", "frstor", "fxrstor")):
            return ent("GEN_OP_LOAD")
        if re.match(r"^f(add|iadd)", m):
            return ent("GEN_OP_FP_ADD")
        if re.match(r"^f(sub|isub)", m):
            return ent("GEN_OP_FP_SUB")
        if re.match(r"^f(mul|imul)", m):
            return ent("GEN_OP_FP_MUL")
        if re.match(r"^f(div|idiv)", m):
            return ent("GEN_OP_FP_DIV")
        if m.startswith("fsqrt"):
            return ent("GEN_OP_FP_SQRT")
        if m.startswith(("fcom", "ficom", "ftst", "fucom")):
            return ent("GEN_OP_FP_CMP")
        if m.startswith(("fild", "fist", "fbld", "fbstp")):
            return ent("GEN_OP_FP_CVT")
        return ent("GEN_OP_FP_MOV")

    if m.startswith("v"):
        core = m[1:]
        fma_core = core[1:] if core[:1].isdigit() else core
        if core.startswith("p"):
            p = core[1:]
            if p.startswith("gather"):
                return ent("GEN_OP_LOAD")
            if p.startswith("scatter"):
                return ent("GEN_OP_STORE")
            if p.startswith("add"):
                return ent("GEN_OP_VEC_ADD")
            if p.startswith("sub"):
                return ent("GEN_OP_VEC_SUB")
            if p.startswith("madd"):
                return ent("GEN_OP_VEC_MADD")
            if p.startswith("mul"):
                return ent("GEN_OP_VEC_MUL")
            if p.startswith(("shuf", "blend", "perm", "unpck", "pack", "align", "insert", "extract", "insr", "extr")):
                return ent("GEN_OP_VEC_SHUF")
            if p.startswith(("broadcast", "mov", "load", "store", "maskmov")):
                return ent("GEN_OP_VEC_MOV")
            if p.startswith("test"):
                return ent("GEN_OP_TEST")
            return ent("GEN_OP_VEC_LOGIC")
        if core.startswith(("add", "hadd", "addsub")):
            return ent("GEN_OP_FP_ADD")
        if core.startswith(("sub", "hsub")):
            return ent("GEN_OP_FP_SUB")
        if fma_core.startswith(("fmadd", "fnmadd")) or fma_core.startswith("fmaddsub"):
            return ent("GEN_OP_FP_MADD")
        if fma_core.startswith(("fmsub", "fnmsub")) or fma_core.startswith("fmsubadd"):
            return ent("GEN_OP_FP_MSUB")
        if core.startswith(("mul", "fm", "fnm")):
            return ent("GEN_OP_FP_MUL")
        if core.startswith("div"):
            return ent("GEN_OP_FP_DIV")
        if core.startswith("sqrt"):
            return ent("GEN_OP_FP_SQRT")
        if core.startswith(("cmp", "comi", "ucomi", "max", "min")):
            return ent("GEN_OP_FP_CMP")
        if core.startswith(("cvt", "round")):
            return ent("GEN_OP_FP_CVT")
        if core.startswith(("gatherpf", "scatterpf")):
            return ent("GEN_OP_NOP")
        if core.startswith("gather"):
            return ent("GEN_OP_LOAD")
        if core.startswith("scatter"):
            return ent("GEN_OP_STORE")
        if core.startswith(("mov", "broadcast", "maskmov")):
            return ent("GEN_OP_VEC_MOV")
        if core.startswith(("shuf", "blend", "perm", "unpck", "insert", "extract")):
            return ent("GEN_OP_VEC_SHUF")
        if core.startswith("zero"):
            return ent("GEN_OP_NOP")
        return ent("GEN_OP_VEC_LOGIC")

    if re.match(r"^(addsub|add|sub|mul|div|sqrt|max|min|cmp|round|cvt)[a-z0-9]*[ps][sd]", m):
        if m.startswith("add"):
            return ent("GEN_OP_FP_ADD")
        if m.startswith("sub"):
            return ent("GEN_OP_FP_SUB")
        if m.startswith("mul"):
            return ent("GEN_OP_FP_MUL")
        if m.startswith("div"):
            return ent("GEN_OP_FP_DIV")
        if m.startswith("sqrt"):
            return ent("GEN_OP_FP_SQRT")
        if m.startswith(("max", "min", "cmp")):
            return ent("GEN_OP_FP_CMP")
        return ent("GEN_OP_FP_CVT")
    if m.startswith(("hadd", "padd", "pfacc", "pfadd", "phadd")):
        return ent("GEN_OP_VEC_ADD")
    if m.startswith(("hsub", "pfnacc", "pfpnacc", "pfsub", "psub", "phsub")):
        return ent("GEN_OP_VEC_SUB")
    if m.startswith("pmadd"):
        return ent("GEN_OP_VEC_MADD")
    if m.startswith(("pmul", "montmul", "pfmul")):
        return ent("GEN_OP_VEC_MUL")
    if m.startswith(("blend", "dpp", "extrq", "extract", "insert", "pswap", "pshuf", "pblend", "palign", "punpck", "pack", "pextr", "pinsr", "shuf", "unpck")):
        return ent("GEN_OP_VEC_SHUF")
    if m.startswith(("movap", "movup", "movdq", "movddup", "movshdup", "movsldup", "movhp", "movlp", "lddqu", "pmov")):
        return ent("GEN_OP_VEC_MOV")
    if m.startswith(("pand", "por", "pxor", "pcmp", "pfcm", "pfmax", "pfmin", "phmin", "mpsadbw", "pmin", "pmax", "psad", "pavg", "pabs", "psign", "ptest", "psll", "psrl", "psra")):
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith(("pf2i", "pi2f")):
        return ent("GEN_OP_FP_CVT")
    if m.startswith(("pfrcp", "pfrsq", "rcp", "rsqrt")):
        return ent("GEN_OP_FP_SQRT")
    if m in {"sysexitq", "sysret", "sysretq"}:
        return ent("GEN_OP_RET", "BRANCH_RETURN")
    return ent("GEN_OP_UNKNOWN")


def classify_aarch64(m: str) -> Entry:
    if m in {"b"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m in {"bc", "cbz", "cbnz", "tbz", "tbnz"}:
        return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
    if m == "bl":
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m.startswith("blr"):
        return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_JUMP")
    if m in {"br", "braa", "braaz", "brab", "brabz"}:
        return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_JUMP")
    if m.startswith("ret") or m.startswith("eret"):
        return ent("GEN_OP_RET", "BRANCH_RETURN")
    if m in {"svc", "hvc", "smc", "brk", "hlt", "dcps1", "dcps2", "dcps3"}:
        return ent("GEN_OP_SYSCALL", "BRANCH_SYSCALL_TYPE")
    if m in {"nop", "hint", "wfe", "wfi", "wfet", "wfit", "sev", "sevl", "yield", "xaflag", "axflag", "cfinv", "gmi", "irg", "rmif", "udf"}:
        return ent("GEN_OP_NOP")
    if m in {"dmb", "dsb", "isb", "sb", "csdb", "psb", "tsb", "clrex", "sdsb"} or m.startswith(("dc_", "ic_", "tlbi")):
        return ent("GEN_OP_FENCE", flags="MF_ATOMIC")
    if m.startswith("at_"):
        return ent("GEN_OP_FENCE", flags="MF_ATOMIC")
    if m.startswith("prf") or m.startswith("rprf") or m.startswith("pli"):
        return ent("GEN_OP_NOP")
    if m.startswith(("sysp", "trcit", "wkdmc", "wkdmd", "rdsvl")):
        return ent("GEN_OP_NOP")

    if m in {"ccmn"}:
        return ent("GEN_OP_CMP")
    if m in {
        "setge", "setgen", "setget", "setgetn", "sete", "seten",
        "setet", "setetn", "setgm", "setgmn", "setgmt", "setgmtn",
        "setgp", "setgpn", "setgpt", "setgptn", "setm", "setmn",
        "setmt", "setmtn", "setp", "setpn", "setpt", "setptn",
    }:
        return ent("GEN_OP_STORE")

    if m.startswith(("cas", "casp", "swp")):
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    if m.startswith(("rcwcas", "rcwscas", "rcwswp", "rcwsswp")):
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    if m.startswith(("rcwclr", "rcwsclr")):
        return ent("GEN_OP_AND", flags="MF_ATOMIC")
    if m.startswith(("rcwset", "rcwsset")):
        return ent("GEN_OP_OR", flags="MF_ATOMIC")
    if m.startswith(("ldadd", "stadd")):
        return ent("GEN_OP_INT_ADD", flags="MF_ATOMIC")
    if m.startswith(("ldclr", "stclr")):
        return ent("GEN_OP_AND", flags="MF_ATOMIC")
    if m.startswith(("ldeor", "steor")):
        return ent("GEN_OP_XOR", flags="MF_ATOMIC")
    if m.startswith(("ldset", "stset")):
        return ent("GEN_OP_OR", flags="MF_ATOMIC")
    if m.startswith(("ldsmax", "ldsmin", "ldumax", "ldumin", "stsmax", "stsmin", "stumax", "stumin")):
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    if m.startswith(("ld", "ldap", "ldar")):
        return ent("GEN_OP_LOAD")
    if m.startswith("st"):
        return ent("GEN_OP_STORE")

    if m in {"bfm", "mrrs", "mrs", "msr", "msrr", "pmov", "setf16", "setf8"}:
        return ent("GEN_OP_MOV")
    if m.startswith(("adr", "adrp")):
        return ent("GEN_OP_LEA")
    if m.startswith(("aut", "pac", "xpac")):
        return ent("GEN_OP_MOV")
    if m.startswith(("sxt", "sbfm", "sbfiz", "sbfx")):
        return ent("GEN_OP_MOVSX")
    if m.startswith(("uxt", "ubfm", "ubfiz", "ubfx")):
        return ent("GEN_OP_MOVZX")
    if m.startswith(("dup", "ins", "movi")):
        return ent("GEN_OP_VEC_MOV")
    if m.startswith("extr"):
        return ent("GEN_OP_ROR")
    if m.startswith(("mov", "movi", "movk", "movn", "movz", "dup", "ins", "ext", "cpy")):
        return ent("GEN_OP_MOV")
    if m in {"clr", "ctz", "pext"}:
        return ent("GEN_OP_AND")
    if m.startswith("gcs"):
        if m.startswith("gcspop"):
            return ent("GEN_OP_POP")
        if m.startswith("gcspush"):
            return ent("GEN_OP_PUSH")
        if m.startswith(("gcsstr", "gcssttr")):
            return ent("GEN_OP_STORE")
        return ent("GEN_OP_MOV")
    if m == "abs":
        return ent("GEN_OP_NEG")
    if m.startswith("adc"):
        return ent("GEN_OP_INT_ADC")
    if re.match(r"^(sadd|uadd|addv|addqv|addp|saba|uaba|sabal|uabal)", m):
        return ent("GEN_OP_VEC_ADD")
    if m.startswith(("madd", "smadd", "umadd")):
        return ent("GEN_OP_INT_MADD")
    if m.startswith(("msub", "smsub", "umsub")):
        return ent("GEN_OP_INT_MSUB")
    if m.startswith(("add", "cmn", "neg", "ngc")):
        return ent("GEN_OP_INT_ADD")
    if re.match(r"^(ssub|usub|subv|sabd|uabd)", m):
        return ent("GEN_OP_VEC_SUB")
    if m.startswith("sbc"):
        return ent("GEN_OP_INT_SBB")
    if m.startswith("sub"):
        return ent("GEN_OP_INT_SUB")
    if m.startswith(("mul", "smul", "umul", "mneg")):
        return ent("GEN_OP_INT_MUL")
    if m.startswith(("sdiv", "udiv")):
        return ent("GEN_OP_INT_DIV")
    if re.match(r"^(andqv|andv)", m):
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith(("and", "bic")):
        return ent("GEN_OP_AND")
    if m.startswith(("orr", "orn")):
        return ent("GEN_OP_OR")
    if m.startswith(("eor", "eon")):
        return ent("GEN_OP_XOR")
    if m.startswith(("mvn", "not")):
        return ent("GEN_OP_NOT")
    if m.startswith(("lsl", "lslrv")):
        return ent("GEN_OP_SHL")
    if m.startswith(("lsr", "lsrrv")):
        return ent("GEN_OP_SHR")
    if m.startswith(("asr", "asrrv")):
        return ent("GEN_OP_SAR")
    if m.startswith(("ror", "rorv", "extr")):
        return ent("GEN_OP_ROR")
    if m.startswith(("cmp", "ccmp")):
        return ent("GEN_OP_CMP")
    if m.startswith(("tst", "ands")):
        return ent("GEN_OP_TEST")
    if m.startswith(("csel", "csinc", "csinv", "csneg", "cinc", "cinv", "cneg")):
        return ent("GEN_OP_CMOV")
    if m.startswith(("cset", "csetm")):
        return ent("GEN_OP_SETCC")

    if m.startswith(("fdot", "fvdot", "bfdot", "bfvdot")):
        return ent("GEN_OP_VEC_MADD")
    if m.startswith(("fcvt", "scvt", "ucvt", "fjcvt", "bfcvt", "bf1cvt", "bf2cvt", "f1cvt", "f2cvt", "fround")):
        return ent("GEN_OP_FP_CVT")
    if m.startswith(("famax", "famin", "fclamp", "bfclamp")):
        return ent("GEN_OP_FP_CMP")
    if m == "fcadd":
        return ent("GEN_OP_FP_ADD")
    if m.startswith(("fadd", "bfadd")):
        return ent("GEN_OP_FP_ADD")
    if m.startswith(("fsub", "bfsub")):
        return ent("GEN_OP_FP_SUB")
    if m.startswith(("fcmla", "fmadd", "fnmadd", "fnmad", "fmad", "fma", "fmla", "fnmla", "fmmla", "fmopa", "bfmla", "bfmmla", "bfmlal", "bfmopa")):
        return ent("GEN_OP_FP_MADD")
    if m.startswith(("fmsub", "fnmsub", "fnmsb", "fms", "fmls", "fnmls", "fmops", "bfmls", "bfmops")):
        return ent("GEN_OP_FP_MSUB")
    if m in {"flogb", "fscale", "ftmad", "ftsmul"}:
        return ent("GEN_OP_FP_MUL")
    if m in {"fmsb"}:
        return ent("GEN_OP_VEC_MUL")
    if m.startswith(("fmul", "fnmul", "bfmul")):
        return ent("GEN_OP_FP_MUL")
    if m.startswith("fdiv"):
        return ent("GEN_OP_FP_DIV")
    if m.startswith("fsqrt"):
        return ent("GEN_OP_FP_SQRT")
    if m.startswith(("facge", "facgt", "fccmp", "fccmpe", "fcmp", "fcm", "fmax", "fmin", "bfmax", "bfmin")):
        return ent("GEN_OP_FP_CMP")
    if m.startswith(("fcsel", "fdup", "fexpa", "flogb", "fscale", "ftmad", "ftssel", "ftsmul", "fmov", "fabs", "fneg", "frint", "frsqr", "frecp")):
        return ent("GEN_OP_FP_MOV")

    if re.match(r"^(cadd|raddhn|shadd|suqadd|uhadd|usqadd)", m):
        return ent("GEN_OP_VEC_ADD")
    if re.match(r"^(rsubhn|shsub|uhsub)", m):
        return ent("GEN_OP_VEC_SUB")
    if re.match(r"^(bmopa|cmla|mac16|matfp|matint|mla|smlal|umlal|sqdmlal|sqrdmlah|sqrdcmlah|sdot|udot|usdot|sudot|svdot|uvdot|suvdot|usvdot|sumlall|usmlall|mopa|smopa|sumopa|umopa|usmopa|smmla|ummla|usmmla|bfmopa)", m):
        return ent("GEN_OP_VEC_MADD")
    if re.match(r"^(bmops|mls|smlsl|umlsl|sqdmlsl|sqrdmlsh|mops|smops|sumops|umops|usmops|bfmops)", m):
        return ent("GEN_OP_VEC_MSUB")
    if m == "madpt":
        return ent("GEN_OP_VEC_MADD")
    if re.match(r"^(cdot|mad|msb|sqdmul|sqrdmul|mul|pmul|smull|umull)", m):
        return ent("GEN_OP_VEC_MUL")
    if re.match(r"^(clasta|clastb|lasta|lastb|smov|umov)", m):
        return ent("GEN_OP_VEC_MOV")
    if re.match(r"^(genlut|luti|punpk|tbl|tbx|zip|uzp|trn|rev|splice|compact|unpk|uunpk|sunpk|xtn|sqxt|uqxt|uzp|zip|ext|ins|dup|index)", m):
        return ent("GEN_OP_VEC_SHUF")
    if re.match(r"^(aes|bcax|bdep|bext|bgrp|brb|cm|crc32|cterm|dec|drps|fabd|fcpy|genter|gexit|hist|inc|nand|nbsl|nor|orqv|orv|pfirst|pnext|psel|rax1|rdvl|rshr|sadalp|sclamp|set$|sha|sm3|sm4|srsh|srsra|ssh|ssra|sys$|sysl$|tcancel|tcommit|ttest|uadalp|uclamp|ur|ush|usra|vecfp|vecint|while|ptrue|pfalse|rdffr|wrffr|setffr|brk|sel|match|nmatch|ptest|cnt|cls|clz|cnot|eor|orr|and|bic|bsl|bit|bif|xar|rbit|smax|smin|umax|umin|saba|uaba|sabd|uabd|sq|uq|srh|urh|sri|sli|shl|shr|q|uq|sqr|uqr|sqsh|uqsh|sqadd|uqadd|sqsub|uqsub)", m):
        return ent("GEN_OP_VEC_LOGIC")
    if m in {"zero"}:
        return ent("GEN_OP_VEC_LOGIC")
    return ent("GEN_OP_UNKNOWN")


def classify_riscv(m: str) -> Entry:
    if m in {"beq", "bne", "blt", "bge", "bltu", "bgeu", "c_beqz", "c_bnez"}:
        return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
    if m in {"jal", "c_jal"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m in {"c_j"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m in {"jalr", "c_jalr"}:
        return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_JUMP")
    if m in {"c_jr"}:
        return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_JUMP")
    if m in {"ecall", "ebreak", "c_ebreak"}:
        return ent("GEN_OP_SYSCALL", "BRANCH_SYSCALL_TYPE")
    if m in {"mret", "sret", "uret", "dret"}:
        return ent("GEN_OP_RET", "BRANCH_RETURN")
    if m.startswith(("fence", "sfence", "hfence")):
        return ent("GEN_OP_FENCE", flags="MF_ATOMIC")
    if m in {"wfi", "unimp", "c_unimp", "pause", "c_nop", "sinval_vma"} or m.startswith(("mop_", "cmop_")):
        return ent("GEN_OP_NOP")
    if m in {"call", "tail"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m in {"jump"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m in {"la", "la_tlsdesc", "la_tls_gd", "la_tls_ie", "lla", "lga", "pcrel_hi", "tlsdesc_hi", "tls_gd_hi", "tls_got_hi", "tls_ie_hi", "auipc"}:
        return ent("GEN_OP_LEA")
    if m in {"li"}:
        return ent("GEN_OP_MOV")
    if m.startswith("csrr"):
        return ent("GEN_OP_MOV")
    if m.startswith("amo"):
        if m.startswith("amoadd"):
            return ent("GEN_OP_INT_ADD", flags="MF_ATOMIC")
        if m.startswith("amoand"):
            return ent("GEN_OP_AND", flags="MF_ATOMIC")
        if m.startswith("amoor"):
            return ent("GEN_OP_OR", flags="MF_ATOMIC")
        if m.startswith("amoxor"):
            return ent("GEN_OP_XOR", flags="MF_ATOMIC")
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    if m.startswith(("lr_", "sc_")):
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    if m.startswith("ssamoswap"):
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    if m.startswith("sspush"):
        return ent("GEN_OP_PUSH")
    if m.startswith("sspop"):
        return ent("GEN_OP_POP")
    if m.startswith("ssrdp"):
        return ent("GEN_OP_MOV")
    if m.startswith(("hlv", "hlvx")):
        return ent("GEN_OP_LOAD")
    if m.startswith("hsv"):
        return ent("GEN_OP_STORE")
    if m.startswith(("hinval", "cbo_clean", "cbo_flush", "cbo_inval", "wrs_")):
        return ent("GEN_OP_FENCE", flags="MF_ATOMIC")
    if m.startswith(("cbo_zero", "prefetch_")):
        return ent("GEN_OP_NOP")
    if m.startswith("cm_"):
        if m.startswith("cm_jalt"):
            return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_JUMP")
        if m.startswith("cm_jt"):
            return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_JUMP")
        if m.startswith("cm_push"):
            return ent("GEN_OP_PUSH")
        if m.startswith("cm_popret"):
            return ent("GEN_OP_RET", "BRANCH_RETURN")
        if m.startswith("cm_pop"):
            return ent("GEN_OP_POP")
        return ent("GEN_OP_MOV")
    if m.startswith(("addi", "addiw", "addw", "add", "c_add", "c_addi")):
        return ent("GEN_OP_INT_ADD")
    if m.startswith(("subw", "sub", "c_sub")):
        return ent("GEN_OP_INT_SUB")
    if m.startswith(("sll", "slli", "c_slli", "sh1", "sh2", "sh3")):
        return ent("GEN_OP_SHL")
    if m.startswith(("srl", "srli", "c_srli")):
        return ent("GEN_OP_SHR")
    if m.startswith(("sra", "srai", "c_srai")):
        return ent("GEN_OP_SAR")
    if m.startswith(("lui", "c_li", "c_lui", "c_mv", "mv")):
        return ent("GEN_OP_MOV")
    if m.startswith(("aes", "brev8", "pack", "unzip", "xperm", "zip")):
        return ent("GEN_OP_AND")
    if m.startswith("czero"):
        return ent("GEN_OP_CMOV")
    if m.startswith(("c_lbu", "c_lh", "c_lhu")):
        return ent("GEN_OP_LOAD")
    if m.startswith(("c_not", "c_sext", "c_zext")):
        return ent("GEN_OP_AND")
    if m.startswith("c_sspush"):
        return ent("GEN_OP_PUSH")
    if m.startswith("c_sspop"):
        return ent("GEN_OP_POP")
    if m.startswith("f"):
        if m.startswith(("fadd",)):
            return ent("GEN_OP_FP_ADD")
        if m.startswith(("fsub", "fsgnj")):
            return ent("GEN_OP_FP_SUB") if m.startswith("fsub") else ent("GEN_OP_FP_MOV")
        if m.startswith(("fmadd", "fnmadd")):
            return ent("GEN_OP_FP_MADD")
        if m.startswith(("fmsub", "fnmsub")):
            return ent("GEN_OP_FP_MSUB")
        if m.startswith(("fmul",)):
            return ent("GEN_OP_FP_MUL")
        if m.startswith("fdiv"):
            return ent("GEN_OP_FP_DIV")
        if m.startswith("fsqrt"):
            return ent("GEN_OP_FP_SQRT")
        if m.startswith(("feq", "flt", "fle", "fmin", "fmax", "fclass")):
            return ent("GEN_OP_FP_CMP")
        if m.startswith(("fcvt", "fround")):
            return ent("GEN_OP_FP_CVT")
        if m.startswith("fmv"):
            return ent("GEN_OP_FP_MOV")
        if m.startswith("fli"):
            return ent("GEN_OP_FP_MOV")
        if m.startswith(("fl",)):
            return ent("GEN_OP_LOAD")
        if m.startswith(("fs",)):
            return ent("GEN_OP_STORE")
        return ent("GEN_OP_FP_MOV")
    if m.startswith(("sha", "sm3", "sm4")):
        return ent("GEN_OP_AND")
    if m.startswith(("lb", "lh", "lw", "ld", "lbu", "lhu", "lwu", "fl", "c_lw", "c_ld", "c_lq", "c_fl")):
        return ent("GEN_OP_LOAD")
    if m.startswith(("sb", "sh", "sw", "sd", "fs", "c_sw", "c_sd", "c_sq", "c_fs", "c_sb", "c_sh")):
        return ent("GEN_OP_STORE")
    if m.startswith(("mul", "c_mul")):
        return ent("GEN_OP_INT_MUL")
    if m.startswith(("div", "rem")):
        return ent("GEN_OP_INT_DIV")
    if m.startswith(("and", "andi", "c_and", "bclr", "bext", "binv", "bset", "clmul", "clz", "ctz", "cpop", "orc", "rev", "rol", "ror", "xnor", "sext", "zext")):
        return ent("GEN_OP_AND")
    if m.startswith(("or", "ori", "c_or")):
        return ent("GEN_OP_OR")
    if m.startswith(("xor", "xori", "c_xor")):
        return ent("GEN_OP_XOR")
    if m.startswith(("slt", "sltu", "slti", "sltiu", "min", "max")):
        return ent("GEN_OP_CMP")
    if m.startswith("v"):
        if m.startswith("vl"):
            return ent("GEN_OP_LOAD")
        if m.startswith(("vfcvt", "vfncvt", "vfwcvt")):
            return ent("GEN_OP_FP_CVT")
        if m.startswith(("vset", "vsext")):
            return ent("GEN_OP_VEC_LOGIC")
        if m.startswith(("vadd", "vaadd", "vaaddu", "vadc", "vsadd", "vsaddu", "vwadd", "vfadd", "vfwadd", "vfred", "vwred", "vfwred")):
            return ent("GEN_OP_VEC_ADD")
        if m.startswith(("vsub", "vasub", "vasubu", "vsbc", "vssub", "vssubu", "vwsub", "vfsub", "vfwsub")):
            return ent("GEN_OP_VEC_SUB")
        if m.startswith(("vmacc", "vmadd", "vwmacc", "vfmacc", "vfnmacc", "vfmadd", "vfnmadd", "vfwmacc", "vfwnmacc")):
            return ent("GEN_OP_VEC_MADD")
        if m.startswith(("vmsac", "vnmsac", "vnmsub", "vfmsac", "vfnmsac", "vfmsub", "vfnmsub", "vfwmsac", "vfwnmsac")):
            return ent("GEN_OP_VEC_MSUB")
        if m.startswith(("vmul", "vsmul", "vwmul", "vfmul", "vfwmul")):
            return ent("GEN_OP_VEC_MUL")
        if m.startswith(("vfdiv", "vfrdiv")):
            return ent("GEN_OP_FP_DIV")
        if m.startswith("vfsqrt"):
            return ent("GEN_OP_FP_SQRT")
        if m.startswith(("vmerge", "vmv", "vslide", "vrgather", "vcompress", "vfirst", "viota", "vid", "vfmerge", "vfmv")):
            return ent("GEN_OP_VEC_MOV")
        if re.match(r"^vs(e|se|seg|sseg|ox|oxseg|ux|uxseg|[1248]r|m_)", m):
            return ent("GEN_OP_STORE")
        if m.startswith(("vsha", "vsm3", "vsm4", "vset", "vsext", "vzext", "vsll", "vsra", "vsrl", "vssra", "vssrl", "vcpop", "vms", "vmn", "vmx", "vfmin", "vfmax", "vmseq", "vmsne", "vmslt", "vmsle", "vmsgt", "vmsge", "vmfeq", "vmfne", "vmflt", "vmfle", "vmfgt", "vmfge")):
            return ent("GEN_OP_VEC_LOGIC")
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith("cv_"):
        c = m[3:]
        if c.startswith(("beqimm", "bneimm")):
            return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
        if c.startswith(("lb", "lbu", "lh", "lhu", "lw", "elw")):
            return ent("GEN_OP_LOAD")
        if c.startswith(("sb", "sh", "sw")):
            return ent("GEN_OP_STORE")
        if c.startswith(("mac", "mach", "dot", "sdot")):
            return ent("GEN_OP_VEC_MADD")
        if c.startswith("msu"):
            return ent("GEN_OP_VEC_MSUB")
        if c.startswith(("cplxmul", "mul")):
            return ent("GEN_OP_VEC_MUL")
        if c.startswith(("add", "avg")):
            return ent("GEN_OP_VEC_ADD")
        if c.startswith("sub"):
            return ent("GEN_OP_VEC_SUB")
        if c.startswith(("cmp", "slet", "max", "min")):
            return ent("GEN_OP_CMP")
        if c.startswith("and"):
            return ent("GEN_OP_AND")
        if c.startswith("or"):
            return ent("GEN_OP_OR")
        if c.startswith("xor"):
            return ent("GEN_OP_XOR")
        if c.startswith(("sll", "bset", "bclr")):
            return ent("GEN_OP_SHL")
        if c.startswith("srl"):
            return ent("GEN_OP_SHR")
        if c.startswith("sra"):
            return ent("GEN_OP_SAR")
        if c.startswith("ror"):
            return ent("GEN_OP_ROR")
        if c.startswith(("pack", "shuffle", "insert", "extract")):
            return ent("GEN_OP_VEC_SHUF")
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith("th_"):
        t = m[3:]
        if "cache" in t or t.startswith(("sfence", "sync")):
            return ent("GEN_OP_FENCE", flags="MF_ATOMIC")
        if t.startswith(("lb", "lh", "lw", "ld", "lr", "lur", "fl")):
            return ent("GEN_OP_LOAD")
        if t.startswith(("sb", "sh", "sw", "sd", "sr", "sur", "fs")):
            return ent("GEN_OP_STORE")
        if t.startswith("vmaqa"):
            return ent("GEN_OP_VEC_MADD")
        if t.startswith("mula"):
            return ent("GEN_OP_INT_MADD")
        if t.startswith("muls"):
            return ent("GEN_OP_INT_MSUB")
        if t.startswith("mul"):
            return ent("GEN_OP_INT_MUL")
        if t.startswith("add"):
            return ent("GEN_OP_INT_ADD")
        if t.startswith(("mveqz", "mvnez")):
            return ent("GEN_OP_CMOV")
        if t.startswith("extu"):
            return ent("GEN_OP_MOVZX")
        if t.startswith("ext"):
            return ent("GEN_OP_MOVSX")
        if t.startswith(("ff", "rev", "tst")):
            return ent("GEN_OP_AND")
        return ent("GEN_OP_NOP")
    if m.startswith("sf_"):
        if m.startswith(("sf_vfwmacc", "sf_vqmacc")):
            return ent("GEN_OP_VEC_MADD")
        if m.startswith("sf_vfnrclip"):
            return ent("GEN_OP_FP_CVT")
        return ent("GEN_OP_VEC_MOV")
    return ent("GEN_OP_UNKNOWN")


def classify_mips(m: str) -> Entry:
    if m in {"j", "b", "bc", "b16"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m in {"jr", "jrc", "jic", "jr_hb", "jr16", "jrc16", "jrcaddiusp", "jraddiusp"}:
        return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_JUMP")
    if m in {"jal", "bal", "balc", "jalx", "jals"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m.startswith(("jalr", "jialc")):
        return ent("GEN_OP_BRANCH", "BRANCH_INDIRECT_JUMP")
    if re.match(r"^b(g|l|eq|ne|lt|ge|gt|le|z|nz).*al", m) and m not in {"bal", "balc"}:
        return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
    if m.startswith(("bbit", "bposge", "bteqz", "btnez")):
        return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
    if m.startswith(("beq", "bne", "bge", "bgt", "ble", "blt", "bc1", "bc2", "bnv", "bnz", "bz", "bovc", "bnvc")):
        return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
    if m in {"eret", "eretnc", "deret"}:
        return ent("GEN_OP_RET", "BRANCH_RETURN")
    if m.startswith(("syscall", "break", "hypcall", "sdbbp", "sigrie", "teq", "tge", "tgeu", "tlt", "tltu", "tne")):
        return ent("GEN_OP_SYSCALL", "BRANCH_SYSCALL_TYPE")
    if m.startswith(("sync", "synci", "pause", "wait", "yield")):
        return ent("GEN_OP_FENCE", flags="MF_ATOMIC")
    if m in {"nop", "nop32", "ssnop", "ehb", "cache", "tlbp", "tlbr", "tlbwi", "tlbwr"} or m.startswith(("cachee", "dmt", "dvp", "dvpe", "emt", "evp", "evpe", "ginv", "tlbg", "tlbinv")):
        return ent("GEN_OP_NOP")
    if m.startswith(("movn", "movz")):
        return ent("GEN_OP_CMOV")
    if m.startswith(("ll", "sc")):
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    if re.match(r"^c_.*_(s|d|ps)$", m):
        return ent("GEN_OP_FP_CMP")
    if m in {"li", "li16", "dli"} or m.startswith("li_"):
        return ent("GEN_OP_MOV")
    if m in {"la", "dla"}:
        return ent("GEN_OP_LEA")
    if m.startswith("s_"):
        return ent("GEN_OP_STORE")
    if re.match(r"^(lb|lbu|lh|lhu|lw|lwu|ld|lwc[0-9]*|ldc[0-9]*|lux|lwl|lwr|lld|pref|ulh|ulhu|ulw|ualh|ualw|ualwm)($|[0-9]|_|e|x|pc|r|l|m|p|c|$)", m):
        return ent("GEN_OP_LOAD")
    if re.match(r"^(sb|sbx|sh|shx|sw|swc[0-9]*|sdc[0-9]*|sd|sux|swl|swr|sdl|sdr|ush|usw|uash|uasw|uaswm)($|[0-9]|_|e|x|pc|sp|m|p|c|$)", m):
        return ent("GEN_OP_STORE")
    if m.startswith("insert_"):
        return ent("GEN_OP_VEC_SHUF")
    if m in {"align", "balign", "bitrev", "bitrevw", "byterevw", "cfc1", "cfc2", "cfcmsa", "cftc1", "ctc1", "ctc2", "ctcmsa", "cttc1", "dalign", "di", "ei", "dmfc0", "dmfc2", "dmfgc0", "dmtc0", "dmtc2", "dmtgc0", "mfc0", "mfc2", "mfgc0", "mfhc0", "mfhc1", "mfhc2", "mfhgc0", "mfhi", "mfhi16", "mflo", "mflo16", "mftacx", "mftc0", "mftc1", "mftdsp", "mftgpr", "mfthc1", "mfthi", "mftlo", "mftr", "mtc0", "mtc2", "mtgc0", "mthc0", "mthc1", "mthc2", "mthgc0", "mthi", "mthlip", "mtlo", "mttacx", "mttc0", "mttc1", "mttdsp", "mttgpr", "mtthc1", "mtthi", "mttlo", "mttr", "mtm0", "mtm1", "mtm2", "mtp0", "mtp1", "mtp2", "rdpgpr", "rddsp", "rdhwr", "wrpgpr", "wrdsp"}:
        return ent("GEN_OP_MOV")
    if m.startswith(("move", "dext", "ext", "ins", "dins", "lui")):
        return ent("GEN_OP_MOV")
    if m.startswith(("seb", "seh")):
        return ent("GEN_OP_MOVSX")
    if m.startswith(("clo", "clz", "dclo", "dclz", "cins", "dpop", "pop", "dbitswap")):
        return ent("GEN_OP_AND")
    if re.match(r"^(ceil|floor|round|trunc)_(w|l)_(s|d)$", m) or re.match(r"^f(tint|trunc)_(s|u)_(d|w)$", m) or re.match(r"^rint_(s|d|w|l)$", m) or re.match(r"^cvt_(s|d|w|l|ps|pw)_(s|d|w|l|ps|pl|pu|pw)$", m):
        return ent("GEN_OP_FP_CVT")
    fp = re.match(r"^(f?abs|f?add|ceil|c|class|f?div|floor|fmadd|fmsub|f?trunc|maddf|madd|mfc|mov|msubf|msub|f?mul|mulr|f?neg|nmadd|nmsub|recip|round|rsqrt|f?sqrt|f?sub|trunc)_(s|d|w|l|ps|h)$", m)
    if fp:
        stem = fp.group(1)
        if stem in {"fabs", "fadd", "fdiv", "fmadd", "fmsub", "fmul", "fneg", "fsqrt", "fsub"}:
            stem = stem[1:]
        if stem == "add":
            return ent("GEN_OP_FP_ADD")
        if stem == "sub":
            return ent("GEN_OP_FP_SUB")
        if stem in {"fmadd", "maddf", "madd", "nmadd"}:
            return ent("GEN_OP_FP_MADD")
        if stem in {"fmsub", "msubf", "msub", "nmsub"}:
            return ent("GEN_OP_FP_MSUB")
        if stem in {"mul", "mulr"}:
            return ent("GEN_OP_FP_MUL")
        if stem == "div":
            return ent("GEN_OP_FP_DIV")
        if stem in {"sqrt", "rsqrt", "recip"}:
            return ent("GEN_OP_FP_SQRT")
        if stem in {"c", "class"}:
            return ent("GEN_OP_FP_CMP")
        if stem in {"cvt", "ceil", "floor", "round", "trunc"}:
            return ent("GEN_OP_FP_CVT")
        return ent("GEN_OP_FP_MOV")
    if re.match(r"^cmp_.*_(s|d)$", m):
        return ent("GEN_OP_FP_CMP")
    if re.match(r"^fc(eq|le|lt)_(d|w)$", m):
        return ent("GEN_OP_FP_CMP")
    if m in {"maxa_s", "mina_s"}:
        return ent("GEN_OP_FP_CMP")
    if m in {"dmfc1", "dmtc1", "mfc1", "mfhc1", "mtc1", "mthc1", "sel_s"}:
        return ent("GEN_OP_FP_MOV")
    if m in {"aluipc", "auipc"}:
        return ent("GEN_OP_LEA")
    if m.startswith(("aui", "baddu", "dahi", "dati", "daui", "dlsa", "lsa")):
        return ent("GEN_OP_INT_ADD")
    if m.startswith(("maq", "dpau")):
        return ent("GEN_OP_VEC_MADD")
    if m.startswith("dpsu"):
        return ent("GEN_OP_VEC_MSUB")
    if m.startswith(("preceq", "preceu", "precequ")):
        return ent("GEN_OP_VEC_SHUF")
    if m.startswith(("bmnz", "bmz", "bsel")):
        return ent("GEN_OP_CMOV")
    if re.search(r"_(b|h|w|d|ph|qb|v)$", m) or m.startswith(("v", "msa", "copy_", "insert_", "splati", "splat_", "ldi_")):
        if m.startswith("dpadd"):
            return ent("GEN_OP_VEC_MADD")
        if m.startswith("dpsub"):
            return ent("GEN_OP_VEC_MSUB")
        if m.startswith(("add", "hadd", "aver")):
            return ent("GEN_OP_VEC_ADD")
        if m.startswith(("sub", "hsub", "asub")):
            return ent("GEN_OP_VEC_SUB")
        if m.startswith("shll"):
            return ent("GEN_OP_VEC_LOGIC")
        if m.startswith("shra"):
            return ent("GEN_OP_VEC_LOGIC")
        if m.startswith("shrl"):
            return ent("GEN_OP_VEC_LOGIC")
        if m.startswith(("madd", "dotp", "dpadd")):
            return ent("GEN_OP_VEC_MADD")
        if m.startswith(("msub", "dpsub")):
            return ent("GEN_OP_VEC_MSUB")
        if m.startswith(("mul", "dp")):
            return ent("GEN_OP_VEC_MUL")
        if m.startswith("insert"):
            return ent("GEN_OP_VEC_SHUF")
        if m.startswith(("copy", "ldi", "splat", "splati", "move")):
            return ent("GEN_OP_VEC_MOV")
        if m.startswith(("shf", "ilv", "pck", "sld", "splat", "vshf")):
            return ent("GEN_OP_VEC_SHUF")
        return ent("GEN_OP_VEC_LOGIC")
    if m.startswith(("madd", "maddu")):
        return ent("GEN_OP_INT_MADD")
    if m.startswith(("msub", "msubu")):
        return ent("GEN_OP_INT_MSUB")
    if m.startswith(("add", "addu", "dadd", "daddu", "addi", "addiu", "daddi", "daddiu")):
        return ent("GEN_OP_INT_ADD")
    if m.startswith(("sub", "subu", "dsub", "dsubu")):
        return ent("GEN_OP_INT_SUB")
    if m.startswith(("mul", "muh", "dmul", "dmuh", "mult", "dmult")):
        return ent("GEN_OP_INT_MUL")
    if m.startswith(("div", "ddiv", "rem", "drem", "mod", "dmod")):
        return ent("GEN_OP_INT_DIV")
    if m.startswith(("and", "andi", "bitswap", "crc32", "wsbh", "dsbh", "dshd")):
        return ent("GEN_OP_AND")
    if m.startswith(("append", "prepend", "or", "ori")):
        return ent("GEN_OP_OR")
    if m.startswith(("xor", "xori")):
        return ent("GEN_OP_XOR")
    if m.startswith(("nor", "not")):
        return ent("GEN_OP_NOT")
    if m.startswith(("shilo", "sll", "dsll")):
        return ent("GEN_OP_SHL")
    if m.startswith(("srl", "dsrl")):
        return ent("GEN_OP_SHR")
    if m.startswith(("sra", "dsra")):
        return ent("GEN_OP_SAR")
    if m.startswith(("rol", "ror", "rotr", "drol", "dror", "drotr", "rotx")):
        return ent("GEN_OP_ROR")
    if m.startswith(("movf", "movt", "movn", "movz", "seleqz", "selnez")):
        return ent("GEN_OP_CMOV")
    if m.startswith(("seq", "sge", "sgt", "sle", "sne", "slt", "sltu", "slti", "sltiu")):
        return ent("GEN_OP_CMP")
    if m in {"balrsc"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m in {"brsc"}:
        return ent("GEN_OP_BRANCH", "BRANCH_DIRECT_JUMP")
    if m.startswith(("bbeqzc", "bbnezc")):
        return ent("GEN_OP_BRANCH", "BRANCH_COND_DIRECT")
    if m.startswith("restore_jrc"):
        return ent("GEN_OP_RET", "BRANCH_RETURN")
    if m.startswith("restore"):
        return ent("GEN_OP_LOAD")
    if m.startswith("save"):
        return ent("GEN_OP_STORE")
    if m in {"abs", "neg"}:
        return ent("GEN_OP_NEG")
    if m in {"max_s", "min_s"}:
        return ent("GEN_OP_VEC_LOGIC")
    if m in {"pll_ps", "plu_ps", "pul_ps", "puu_ps"}:
        return ent("GEN_OP_VEC_SHUF")
    if m.startswith("fork"):
        return ent("GEN_OP_NOP")
    if m.startswith(("saa", "saad")):
        return ent("GEN_OP_XCHG", flags="MF_ATOMIC")
    if m == "sov":
        return ent("GEN_OP_CMP")
    if m.startswith("cmp"):
        return ent("GEN_OP_CMP")
    return ent("GEN_OP_UNKNOWN")


CLASSIFIERS = {
    "x86": classify_x86,
    "aarch64": classify_aarch64,
    "riscv": classify_riscv,
    "mips": classify_mips,
}


def classify(info: IsaInfo, const_name: str) -> Entry:
    return CLASSIFIERS[info.key](c_mnemonic(const_name, info.prefix))


def format_entry(const_name: str, entry: Entry) -> str:
    left = f"    [{const_name}]"
    pad1 = " " * max(1, 36 - len(const_name))
    pad2 = " " * max(1, 14 - len(entry.op))
    pad3 = " " * max(1, 22 - len(entry.branch))
    line = f"{left}{pad1}= {{ {entry.op},{pad2}{entry.branch},{pad3}{entry.flags}"
    if entry.refine:
        return line + f",\n                                        .refine = {entry.refine} }},"
    return line + " },"


def xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


@lru_cache(maxsize=None)
def gdb_xml_feature(xml_name: str) -> GdbXmlFeature:
    path = GDB_XML_DIR / xml_name
    try:
        root = ET.parse(path).getroot()
    except FileNotFoundError as exc:
        raise SystemExit(f"could not find GDB XML feature {path}") from exc
    except ET.ParseError as exc:
        raise SystemExit(f"could not parse GDB XML feature {path}: {exc}") from exc

    regnum = 0
    parsed: list[tuple[str, int]] = []
    for child in root:
        if xml_local_name(child.tag) != "reg":
            continue
        if "regnum" in child.attrib:
            regnum = int(child.attrib["regnum"], 0)
        parsed.append((child.attrib["name"], regnum))
        regnum += 1

    if not parsed:
        return GdbXmlFeature(root.attrib["name"], {}, (), 0)

    base_reg = min(regnum for _, regnum in parsed)
    num_regs = max(regnum for _, regnum in parsed) - base_reg + 1
    regs: dict[str, int] = {}
    names_by_local: list[str | None] = [None] * num_regs
    for name, regnum in parsed:
        local_reg = regnum - base_reg
        regs[name] = local_reg
        names_by_local[local_reg] = name
    return GdbXmlFeature(root.attrib["name"], regs, tuple(names_by_local), num_regs)


def gdb_xml_reg_name(xml_name: str, local_reg: int) -> str | None:
    names = gdb_xml_feature(xml_name).names_by_local
    return names[local_reg] if 0 <= local_reg < len(names) else None


def add_qemu_reg_key(regs: dict[str, QemuRegKey], name: str,
                     feature_name: str, qemu_name: str | None = None) -> None:
    regs[name] = QemuRegKey(feature_name, qemu_name or name)


def add_gdb_feature_keys(regs: dict[str, QemuRegKey],
                         feature: GdbXmlFeature) -> None:
    for name in feature.regs:
        add_qemu_reg_key(regs, name, feature.feature_name)


@lru_cache(maxsize=None)
def gdb_xml_reg_key_map(xml_names: tuple[str, ...]) -> dict[str, QemuRegKey]:
    regs: dict[str, QemuRegKey] = {}
    for xml_name in xml_names:
        add_gdb_feature_keys(regs, gdb_xml_feature(xml_name))
    return regs


def add_sequential_qemu_reg_keys(regs: dict[str, QemuRegKey], prefix: str,
                                 count: int, feature_name: str) -> None:
    for num in range(count):
        add_qemu_reg_key(regs, f"{prefix}{num}", feature_name)


@lru_cache(maxsize=None)
def qemu_x86_reg_keys() -> dict[str, QemuRegKey]:
    return gdb_xml_reg_key_map(("i386-64bit.xml",))


@lru_cache(maxsize=None)
def qemu_aarch64_reg_keys() -> dict[str, QemuRegKey]:
    regs = dict(gdb_xml_reg_key_map(("aarch64-core.xml", "aarch64-fpu.xml")))
    sve_feature = "org.gnu.gdb.aarch64.sve"

    add_sequential_qemu_reg_keys(regs, "z", 32, sve_feature)
    add_sequential_qemu_reg_keys(regs, "p", 16, sve_feature)
    add_qemu_reg_key(regs, "ffr", sve_feature)
    add_qemu_reg_key(regs, "vg", sve_feature)
    return regs


@lru_cache(maxsize=None)
def qemu_riscv_reg_keys() -> dict[str, QemuRegKey]:
    regs = dict(gdb_xml_reg_key_map(("riscv-64bit-cpu.xml", "riscv-64bit-fpu.xml")))
    add_sequential_qemu_reg_keys(regs, "v", 32, "org.gnu.gdb.riscv.vector")
    return regs


QEMU_REG_KEYS = {
    "x86": qemu_x86_reg_keys,
    "aarch64": qemu_aarch64_reg_keys,
    "riscv": qemu_riscv_reg_keys,
}


def qemu_reg_key_by_name(isa: str, name: str | None) -> QemuRegKey | None:
    if name is None:
        return None
    return QEMU_REG_KEYS[isa]().get(name)


def qemu_x86_reg_key(name: str) -> QemuRegKey | None:
    gpr_aliases = {
        "A": "rax", "B": "rbx", "C": "rcx", "D": "rdx",
        "SI": "rsi", "DI": "rdi", "BP": "rbp", "SP": "rsp",
    }
    if name in {"EIZ", "RIZ"}:
        return None
    if name in {"IP", "EIP", "RIP"}:
        return qemu_reg_key_by_name("x86", "rip")
    if name == "EFLAGS":
        return qemu_reg_key_by_name("x86", "eflags")
    if name == "FPSW":
        return qemu_reg_key_by_name("x86", "fstat")
    segs = {"CS", "SS", "DS", "ES", "FS", "GS"}
    if name in segs:
        return qemu_reg_key_by_name("x86", name.lower())
    if match := re.fullmatch(r"CR(0|2|3|4|8)", name):
        return qemu_reg_key_by_name("x86", f"cr{match.group(1)}")
    if match := re.fullmatch(r"(?:FP|ST)([0-7])", name):
        return qemu_reg_key_by_name("x86", f"st{match.group(1)}")
    if match := re.fullmatch(r"[XYZ]MM(\d+)", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name("x86", f"xmm{num}") if num < 16 else None
    if name == "MXCSR":
        return qemu_reg_key_by_name("x86", "mxcsr")
    if match := re.fullmatch(r"R(\d+)(?:[BDW])?", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name("x86", f"r{num}") if 8 <= num <= 15 else None
    for base, qemu_name in gpr_aliases.items():
        if re.fullmatch(rf"[ER]?{base}[XHL]?|{base}L", name):
            return qemu_reg_key_by_name("x86", qemu_name)
    return None


def qemu_aarch64_reg_key(name: str) -> QemuRegKey | None:
    if name in {"X_LANE", "Y_LANE", "WZR", "XZR"}:
        return None
    if name in {"SP", "WSP"}:
        return qemu_reg_key_by_name("aarch64", "sp")
    if name == "LR":
        return qemu_reg_key_by_name("aarch64", "x30")
    if name == "FP":
        return qemu_reg_key_by_name("aarch64", "x29")
    if name == "NZCV":
        return qemu_reg_key_by_name("aarch64", "cpsr")
    if name == "FPSR":
        return qemu_reg_key_by_name("aarch64", "fpsr")
    if name == "FPCR":
        return qemu_reg_key_by_name("aarch64", "fpcr")
    if name == "FFR":
        return qemu_reg_key_by_name("aarch64", "ffr")
    if name == "VG":
        return qemu_reg_key_by_name("aarch64", "vg")
    if match := re.fullmatch(r"P(\d+)", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name("aarch64", f"p{num}") if num < 16 else None
    if match := re.fullmatch(r"[BHSDQ](\d+)", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name("aarch64", f"v{num}") if num < 32 else None
    if match := re.fullmatch(r"Z(\d+)", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name("aarch64", f"z{num}") if num < 32 else None
    if match := re.fullmatch(r"[WX](\d+)", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name("aarch64", f"x{num}") if num < 31 else None
    return None


def qemu_riscv_reg_key(name: str) -> QemuRegKey | None:
    if name in {"DUMMY_REG_PAIR_WITH_X0"}:
        return None
    if name == "X0_PAIR":
        return None
    if match := re.fullmatch(r"X(\d+)", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name(
            "riscv", gdb_xml_reg_name("riscv-64bit-cpu.xml", num)) if num < 32 else None
    if match := re.fullmatch(r"F(\d+)_[DFH]", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name(
            "riscv", gdb_xml_reg_name("riscv-64bit-fpu.xml", num)) if num < 32 else None
    if match := re.fullmatch(r"V(\d+)", name):
        num = int(match.group(1))
        return qemu_reg_key_by_name("riscv", f"v{num}") if num < 32 else None
    return None


def qemu_mips_reg_key(name: str) -> QemuRegKey | None:
    feature = "org.gnu.gdb.mips.cpu"
    gpr_names = (
        "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
        "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
        "t8", "t9", "k0", "k1", "gp", "sp", "s8", "ra",
    )
    stem = re.sub(r"(?:_NM|_64)$", "", name)
    if stem == "ZERO":
        return QemuRegKey(feature, "zero")
    if stem == "PC":
        return QemuRegKey(feature, "pc")
    if stem == "LO":
        return QemuRegKey(feature, "lo")
    if stem == "HI":
        return QemuRegKey(feature, "hi")
    if stem in MIPS_GPR_NUM:
        return QemuRegKey(feature, gpr_names[MIPS_GPR_NUM[stem]])
    if match := re.fullmatch(r"[FD](\d+)", stem):
        num = int(match.group(1))
        return QemuRegKey(feature, f"f{num}") if num < 32 else None
    if stem == "FCR31":
        return QemuRegKey(feature, "fcr31")
    if stem == "FCR0":
        return QemuRegKey(feature, "fcr0")
    return None


QEMU_REG_CLASSIFIERS = {
    "x86": qemu_x86_reg_key,
    "aarch64": qemu_aarch64_reg_key,
    "riscv": qemu_riscv_reg_key,
    "mips": qemu_mips_reg_key,
}


def qemu_reg_key(info: IsaInfo, const_name: str) -> QemuRegKey | None:
    name = const_name.removeprefix(info.reg_prefix)
    return QEMU_REG_CLASSIFIERS[info.key](name)


def c_string(value: str) -> str:
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def format_qemu_reg(qemu_reg: QemuRegKey | None) -> str:
    if qemu_reg is None:
        return ""
    return (", .qemu_reg = { .feature = " + c_string(qemu_reg.feature) +
            ", .name = " + c_string(qemu_reg.name) + " }")


def format_reg_entry(const_name: str, entry: RegEntry, comment: str,
                     qemu_reg: QemuRegKey | None) -> str:
    qemu_field = format_qemu_reg(qemu_reg)
    if entry.aliases:
        aliases = ", ".join(entry.aliases)
        return (f"    [{const_name}] = {{ .reg_id = {entry.primary}, "
                f".n_regs = {len(entry.aliases)}, .regs = {{ {aliases} }}"
                f"{qemu_field} }},  /* {comment} */")
    return (f"    [{const_name}] = {{ .reg_id = {entry.primary}"
            f"{qemu_field} }},  /* {comment} */")


def generated_body(info: IsaInfo, constants: list[str], existing: dict[str, Entry]) -> str:
    lines = [f"    /* Auto-generated by {Path(__file__).name}. */"]
    emitted = 0
    for const_name in constants:
        new = classify(info, const_name)
        old = existing.get(const_name)
        if new.op == "GEN_OP_UNKNOWN" and old is None:
            continue
        if new.op == "GEN_OP_UNKNOWN" and old is not None:
            new = old.without_refine()
        if old and old.refine:
            new = Entry(new.op, new.branch, new.flags, old.refine)
        lines.append(format_entry(const_name, new))
        emitted += 1
    lines.insert(1, f"    /* {info.key}: {emitted}/{len(constants) + 1} classified, {len(constants) - emitted} unknown */")
    return "\n".join(lines) + "\n"


def generated_reg_body(info: IsaInfo, constants: list[str]) -> str:
    lines = [f"    /* Auto-generated by {Path(__file__).name}. */"]
    mapped = 0
    ignored = 0
    for const_name in constants:
        entry = classify_reg(info, const_name)
        if entry.ignored:
            ignored += 1
            continue
        mapped += 1
        comment = const_name.removeprefix(info.reg_prefix).lower()
        lines.append(format_reg_entry(const_name, entry, comment,
                                      qemu_reg_key(info, const_name)))
    lines.insert(1, f"    /* {info.key} regs: {mapped}/{len(constants) + 1} mapped, {ignored} intentionally ignored */")
    return "\n".join(lines) + "\n"


def targeted_fix(isa: str, const_name: str, old: Entry, new: Entry) -> bool:
    if new.op == "GEN_OP_UNKNOWN":
        return False
    if new.op in MADD_OPS and old.op != new.op:
        return True
    if new.branch == "BRANCH_COND_DIRECT" and old.without_refine() != new:
        return True
    if old.op == "GEN_OP_NOP" and new.op == "GEN_OP_FENCE":
        return True
    if old.op == "GEN_OP_STORE" and new.op in {"GEN_OP_VEC_LOGIC", "GEN_OP_VEC_SHUF"}:
        return True
    if old.op == "GEN_OP_LOAD" and new.op in {"GEN_OP_VEC_MOV", "GEN_OP_VEC_LOGIC"}:
        return True
    if old.op == "GEN_OP_FP_MOV" and new.op == "GEN_OP_FP_CVT":
        return True
    if old.op == "GEN_OP_VEC_LOGIC" and new.op in {"GEN_OP_FP_DIV", "GEN_OP_FP_SQRT"}:
        return True
    if isa == "x86":
        return const_name in {
            "X86_INS_JCXZ", "X86_INS_JECXZ", "X86_INS_JRCXZ",
            "X86_INS_LOOP", "X86_INS_LOOPE", "X86_INS_LOOPNE",
            "X86_INS_INT3", "X86_INS_MOVSB", "X86_INS_MOVSW",
            "X86_INS_MOVSQ", "X86_INS_MOVSLDUP", "X86_INS_SALC",
        }
    if isa == "aarch64":
        if const_name.startswith(("AARCH64_INS_AUT", "AARCH64_INS_PAC", "AARCH64_INS_XPAC")):
            return True
        if const_name == "AARCH64_INS_UXTW":
            return True
        if const_name.startswith("AARCH64_INS_BFCVT"):
            return True
        return False
    if isa == "mips":
        if const_name.startswith("MIPS_INS_ASUB") or const_name.startswith("MIPS_INS_INSERT_"):
            return True
        return const_name in {
            "MIPS_INS_BGEZAL", "MIPS_INS_BGEZALL", "MIPS_INS_BGEZALS",
            "MIPS_INS_BLTZAL", "MIPS_INS_BLTZALL", "MIPS_INS_BLTZALS",
        }
    return False


def audit_one(info: IsaInfo, *, max_lines: int) -> int:
    constants = enum_constants(info)
    existing = parse_existing(info)
    missing: list[tuple[str, Entry]] = []
    mismatched: list[tuple[str, Entry, Entry]] = []
    stale = [name for name in sorted(existing) if name not in constants]
    unknown_existing: list[str] = []
    for const_name in constants:
        new = classify(info, const_name)
        old = existing.get(const_name)
        if old is None:
            if new.op != "GEN_OP_UNKNOWN":
                missing.append((const_name, new))
            continue
        if new.op == "GEN_OP_UNKNOWN":
            unknown_existing.append(const_name)
            continue
        if old.without_refine() != new:
            mismatched.append((const_name, old, new))

    classified = len({name for name in constants if classify(info, name).op != "GEN_OP_UNKNOWN"})
    print(f"{info.key}: constants={len(constants) + 1} classified_by_rules={classified} existing={len(existing)} missing={len(missing)} mismatched={len(mismatched)} stale={len(stale)}")
    if missing:
        print("  missing:")
        for const_name, new in missing[:max_lines]:
            print(f"    {const_name}: {new.op}, {new.branch}, {new.flags}")
        if len(missing) > max_lines:
            print(f"    ... {len(missing) - max_lines} more")
    if mismatched:
        print("  mismatched:")
        for const_name, old, new in mismatched[:max_lines]:
            print(f"    {const_name}: {old.op}/{old.branch}/{old.flags} -> {new.op}/{new.branch}/{new.flags}")
        if len(mismatched) > max_lines:
            print(f"    ... {len(mismatched) - max_lines} more")
    if stale:
        print("  stale constants not in current Capstone header:")
        for const_name in stale[:max_lines]:
            print(f"    {const_name}")
        if len(stale) > max_lines:
            print(f"    ... {len(stale) - max_lines} more")
    if unknown_existing:
        print(f"  existing entries with no rule coverage: {len(unknown_existing)}")
    return len(missing) + len(mismatched) + len(stale)


def audit_regs_one(info: IsaInfo, *, max_lines: int) -> int:
    constants = enum_reg_constants(info)
    unmapped: list[str] = []
    ignored: list[str] = []
    mapped = 0
    for const_name in constants:
        entry = classify_reg(info, const_name)
        if entry.ignored:
            ignored.append(const_name)
        elif entry.primary == "REG_NONE":
            unmapped.append(const_name)
        else:
            mapped += 1
    print(f"{info.key} regs: constants={len(constants) + 1} mapped={mapped} ignored={len(ignored)} unmapped={len(unmapped)}")
    if unmapped:
        print("  unmapped stateful registers:")
        for const_name in unmapped[:max_lines]:
            print(f"    {const_name}")
        if len(unmapped) > max_lines:
            print(f"    ... {len(unmapped) - max_lines} more")
    if ignored and max_lines > 0:
        print("  intentionally ignored:")
        for const_name in ignored[:max_lines]:
            print(f"    {const_name}")
        if len(ignored) > max_lines:
            print(f"    ... {len(ignored) - max_lines} more")
    return len(unmapped)


def apply_one(info: IsaInfo) -> None:
    constants = enum_constants(info)
    existing = parse_existing(info)
    text = info.header.read_text()
    new_text = replace_table_body(text, info, generated_body(info, constants, existing))
    info.header.write_text(new_text)


def apply_regs_one(info: IsaInfo) -> None:
    constants = enum_reg_constants(info)
    text = info.header.read_text()
    new_text = replace_reg_table_body(text, info, generated_reg_body(info, constants))
    info.header.write_text(new_text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isa", choices=sorted(ISAS), action="append", help="limit to one ISA; repeatable")
    parser.add_argument("--diff", action="store_true", help="print missing/mismatched entries")
    parser.add_argument("--apply", action="store_true", help="rewrite mnemonic tables in place")
    parser.add_argument("--regs", action="store_true", help="audit/rewrite register tables instead of instruction tables")
    parser.add_argument("--max-lines", type=int, default=40, help="maximum diff rows per section")
    args = parser.parse_args()
    if not args.diff and not args.apply:
        parser.error("choose --diff and/or --apply")
    keys = args.isa or sorted(ISAS)
    total = 0
    if args.diff:
        for key in keys:
            if args.regs:
                total += audit_regs_one(ISAS[key], max_lines=args.max_lines)
            else:
                total += audit_one(ISAS[key], max_lines=args.max_lines)
    if args.apply:
        for key in keys:
            if args.regs:
                apply_regs_one(ISAS[key])
            else:
                apply_one(ISAS[key])
            print(f"rewrote {ISAS[key].header}")
    return 1 if args.diff and total else 0


if __name__ == "__main__":
    sys.exit(main())