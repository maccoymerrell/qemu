#!/usr/bin/env python3
"""
wptrace_mnemonic_survey.py — Static mnemonic coverage analyzer.

Parses wptrace_mnemonics.h to build the set of known instruction IDs
for each ISA, then disassembles input ELF binaries with Capstone and
reports any instruction IDs not covered by the tables.

Supports: x86-64, AArch64, RISC-V 64, MIPS 32/64.

Requirements: capstone >= 5.0.7, lief
"""

import argparse
import os
import re
import sys
from collections import defaultdict

import capstone
import capstone.x86_const as x86_const
import capstone.arm64_const as arm64_const
import capstone.riscv_const as riscv_const
import capstone.mips_const as mips_const
import lief


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------

HEADER_REL = os.path.join(os.path.dirname(__file__), "wptrace_mnemonics.h")

# ISA → (table C identifier, Capstone const module, constant prefix)
ISA_TABLE_INFO = {
    "x86":     ("x86_insn_class",     x86_const,     "X86_INS_"),
    "aarch64": ("arm64_insn_class",   arm64_const,   "ARM64_INS_"),
    "riscv":   ("riscv_insn_class",   riscv_const,   "RISCV_INS_"),
    "mips":    ("mips_insn_class",    mips_const,    "MIPS_INS_"),
}


def _build_const_map(mod, prefix):
    """Build name → id and id → name maps for a Capstone const module."""
    name_to_id = {}
    id_to_name = {}
    ending = prefix + "ENDING"
    for attr in dir(mod):
        if attr.startswith(prefix) and attr != ending:
            val = getattr(mod, attr)
            name_to_id[attr] = val
            id_to_name[val] = attr
    return name_to_id, id_to_name


def _read_with_includes(path):
    """Read a header file, inlining any local #include "..." directives."""
    base_dir = os.path.dirname(path)
    lines = []
    with open(path) as f:
        for line in f:
            m = re.match(r'\s*#\s*include\s+"([^"]+)"', line)
            if m:
                inc_path = os.path.join(base_dir, m.group(1))
                if os.path.isfile(inc_path):
                    with open(inc_path) as inc:
                        lines.append(inc.read())
                    continue
            lines.append(line)
    return "".join(lines)


def parse_header(path):
    """Return per-ISA dicts  { isa: (known_ids, id_to_classification) }.

    known_ids: set of int (Capstone instruction IDs with non-zero entries)
    id_to_classification: dict { int: (gen_op, branch_type, flags) }
    """
    text = _read_with_includes(path)

    # Pattern for designated-initializer entries:
    # [X86_INS_FOO] = { GEN_OP_xxx, BRANCH_xxx, MF_xxx },
    re_entry = re.compile(
        r'\[\s*(\w+)\s*\]\s*=\s*\{\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\}'
    )

    tables = {}
    for isa, (tname, mod, prefix) in ISA_TABLE_INFO.items():
        name_to_id, id_to_name = _build_const_map(mod, prefix)

        # Find the array body
        pat = re.compile(
            r'\b' + re.escape(tname) + r'\s*\[.*?\]\s*=\s*\{(.*?)\}\s*;',
            re.DOTALL,
        )
        m = pat.search(text)
        if not m:
            print(f"WARNING: could not find table {tname}", file=sys.stderr)
            tables[isa] = (set(), {}, id_to_name)
            continue

        body = m.group(1)
        known_ids = set()
        id_to_class = {}

        for em in re_entry.finditer(body):
            const_name = em.group(1)
            gen_op = em.group(2)
            branch = em.group(3)
            flags = em.group(4)

            if const_name in name_to_id:
                insn_id = name_to_id[const_name]
                known_ids.add(insn_id)
                id_to_class[insn_id] = (gen_op, branch, flags)
            else:
                print(f"WARNING: {const_name} not found in Capstone",
                      file=sys.stderr)

        tables[isa] = (known_ids, id_to_class, id_to_name)

    return tables


# ---------------------------------------------------------------------------
# ELF → Capstone configuration
# ---------------------------------------------------------------------------

# lief.ELF.ARCH → (capstone_arch, capstone_mode, isa_key)
ARCH_MAP = {
    lief.ELF.ARCH.x86_64:  (capstone.CS_ARCH_X86,   capstone.CS_MODE_64,       "x86"),
    lief.ELF.ARCH.i386:    (capstone.CS_ARCH_X86,   capstone.CS_MODE_32,       "x86"),
    lief.ELF.ARCH.AARCH64: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM,      "aarch64"),
    lief.ELF.ARCH.RISCV:   (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64,  "riscv"),
    lief.ELF.ARCH.MIPS:    (capstone.CS_ARCH_MIPS,  capstone.CS_MODE_MIPS64,   "mips"),
}


def make_disassembler(binary):
    """Create a Capstone disassembler from a LIEF binary object."""
    arch = binary.header.machine_type
    if arch not in ARCH_MAP:
        return None, None
    cs_arch, cs_mode, isa = ARCH_MAP[arch]

    # For MIPS: add big/little endian
    if isa == "mips":
        if binary.header.identity_data == lief.ELF.ELF_DATA.MSB:
            cs_mode |= capstone.CS_MODE_BIG_ENDIAN
        else:
            cs_mode |= capstone.CS_MODE_LITTLE_ENDIAN

    # For RISC-V: detect 32 vs 64 from ELF class
    if isa == "riscv":
        if binary.header.identity_class == lief.ELF.ELF_CLASS.CLASS32:
            cs_mode = capstone.CS_MODE_RISCV32

    md = capstone.Cs(cs_arch, cs_mode)

    # x86: use AT&T syntax for display consistency
    if isa == "x86":
        md.syntax = capstone.CS_OPT_SYNTAX_ATT

    md.skipdata = True
    return md, isa


# ---------------------------------------------------------------------------
# Disassemble and collect instruction IDs
# ---------------------------------------------------------------------------

def collect_insn_ids(binary, md):
    """Disassemble all executable sections.

    Returns insn_ids: { insn_id: [count, first_addr, mnemonic] }
    """
    insn_ids = defaultdict(lambda: [0, 0, ""])  # id → [count, first_addr, mnem]

    for section in binary.sections:
        if not (section.flags & lief.ELF.SECTION_FLAGS.EXECINSTR):
            continue
        data = bytes(section.content)
        base = section.virtual_address
        for insn in md.disasm(data, base):
            entry = insn_ids[insn.id]
            entry[0] += 1
            if entry[0] == 1:
                entry[1] = insn.address
                entry[2] = insn.mnemonic

    return insn_ids


# ---------------------------------------------------------------------------
# Check coverage
# ---------------------------------------------------------------------------

def check_coverage(insn_ids, known_ids):
    """Return list of (insn_id, mnemonic, count, first_addr) for unknown IDs."""
    unknown = []
    for insn_id, (count, addr, mnem) in sorted(insn_ids.items()):
        if insn_id == 0:  # skip invalid
            continue
        if insn_id not in known_ids:
            unknown.append((insn_id, mnem, count, addr))
    return unknown


# ---------------------------------------------------------------------------
# Entry generation — classify unknowns and emit C code
# ---------------------------------------------------------------------------

def _classify_x86(insn_id, mnem, id_to_class, id_to_name):
    """Classify an x86 instruction ID.  Returns (gen_op, branch, flags_str).

    Strategy:
      1. Check if a related instruction is already classified (e.g. VPADDQ
         when VPADDD is known).
      2. Fall back to mnemonic pattern rules.
    """
    m = mnem

    # --- Pattern-based classification ---

    # Misc / system
    if m in ('ud2', 'hlt'):
        return ('GEN_OP_NOP', 'BRANCH_NONE', 'MF_NONE')
    if m == 'leave':
        return ('GEN_OP_POP', 'BRANCH_NONE', 'MF_NONE')
    if m.startswith('prefetch'):
        return ('GEN_OP_NOP', 'BRANCH_NONE', 'MF_NONE')
    if m in ('endbr32', 'endbr64'):
        return ('GEN_OP_NOP', 'BRANCH_NONE', 'MF_NONE')
    if m.startswith('nop'):
        return ('GEN_OP_NOP', 'BRANCH_NONE', 'MF_NONE')

    # Stack
    if m.startswith('push'):
        return ('GEN_OP_PUSH', 'BRANCH_NONE', 'MF_NONE')
    if m.startswith('pop'):
        return ('GEN_OP_POP', 'BRANCH_NONE', 'MF_NONE')

    # Data movement
    if re.match(r'^mov[sz]', m) and not m.startswith('movs '):
        if 'zx' in m or m.startswith('movz'):
            return ('GEN_OP_MOVZX', 'BRANCH_NONE', 'MF_NONE')
        if 'sx' in m or m.startswith('movs'):
            return ('GEN_OP_MOVSX', 'BRANCH_NONE', 'MF_NONE')
    if m.startswith('mov') or m.startswith('bswap'):
        return ('GEN_OP_MOV', 'BRANCH_NONE', 'MF_NONE')
    if m.startswith('lea'):
        return ('GEN_OP_LEA', 'BRANCH_NONE', 'MF_NONE')
    if m.startswith('xchg'):
        return ('GEN_OP_XCHG', 'BRANCH_NONE', 'MF_NONE')
    if m.startswith('cmov'):
        return ('GEN_OP_CMOV', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^set[a-z]+', m):
        return ('GEN_OP_SETCC', 'BRANCH_NONE', 'MF_NONE')

    # Bit test / bit manipulation
    if re.match(r'^bt[scr]?[wlq]?$', m):
        return ('GEN_OP_TEST', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^bs[fr]', m):
        return ('GEN_OP_AND', 'BRANCH_NONE', 'MF_NONE')

    # Integer ALU
    if re.match(r'^add', m):
        return ('GEN_OP_INT_ADD', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^sub', m):
        return ('GEN_OP_INT_SUB', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^i?mul', m):
        return ('GEN_OP_INT_MUL', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^i?div', m):
        return ('GEN_OP_INT_DIV', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^adc', m):
        return ('GEN_OP_INT_ADC', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^sbb', m):
        return ('GEN_OP_INT_SBB', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^and', m):
        return ('GEN_OP_AND', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^or[blwq]?$', m):
        return ('GEN_OP_OR', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^xor', m):
        return ('GEN_OP_XOR', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^not', m):
        return ('GEN_OP_NOT', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^neg', m):
        return ('GEN_OP_NEG', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^inc', m):
        return ('GEN_OP_INC', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^dec', m):
        return ('GEN_OP_DEC', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^cmp', m):
        return ('GEN_OP_CMP', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^test', m):
        return ('GEN_OP_TEST', 'BRANCH_NONE', 'MF_NONE')

    # Shifts / rotates
    if re.match(r'^sh[lr]', m):
        if 'l' in m[2:3]:
            return ('GEN_OP_SHL', 'BRANCH_NONE', 'MF_NONE')
        return ('GEN_OP_SHR', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^sar', m):
        return ('GEN_OP_SAR', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^ro[lr]', m):
        if 'l' in m[2:3]:
            return ('GEN_OP_ROL', 'BRANCH_NONE', 'MF_NONE')
        return ('GEN_OP_ROR', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^rc[lr]', m):
        if 'l' in m[2:3]:
            return ('GEN_OP_ROL', 'BRANCH_NONE', 'MF_NONE')
        return ('GEN_OP_ROR', 'BRANCH_NONE', 'MF_NONE')

    # BMI
    if re.match(r'^(lzcnt|tzcnt|popcnt)', m):
        return ('GEN_OP_AND', 'BRANCH_NONE', 'MF_NONE')
    if m.startswith('rorx'):
        return ('GEN_OP_ROR', 'BRANCH_NONE', 'MF_NONE')
    if m.startswith('shrx'):
        return ('GEN_OP_SHR', 'BRANCH_NONE', 'MF_NONE')
    if m.startswith('shlx'):
        return ('GEN_OP_SHL', 'BRANCH_NONE', 'MF_NONE')
    if m.startswith('sarx'):
        return ('GEN_OP_SAR', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^(andn|blsr|blsi|blsmsk|bzhi)', m):
        return ('GEN_OP_AND', 'BRANCH_NONE', 'MF_NONE')

    # Control flow
    if re.match(r'^j[a-z]+', m) and m != 'jmp':
        return ('GEN_OP_BRANCH', 'BRANCH_COND_DIRECT', 'MF_NONE')
    if m == 'jmp':
        return ('GEN_OP_BRANCH', 'BRANCH_DIRECT_JUMP', 'MF_NONE')
    if m.startswith('call'):
        return ('GEN_OP_CALL', 'BRANCH_DIRECT_CALL', 'MF_NONE')
    if m.startswith('ret'):
        return ('GEN_OP_RET', 'BRANCH_RETURN', 'MF_NONE')
    if m.startswith('loop'):
        return ('GEN_OP_BRANCH', 'BRANCH_COND_DIRECT', 'MF_NONE')
    if m == 'syscall':
        return ('GEN_OP_SYSCALL', 'BRANCH_SYSCALL_TYPE', 'MF_NONE')

    # I/O
    if re.match(r'^(in|out)', m):
        if m.startswith('in'):
            return ('GEN_OP_LOAD', 'BRANCH_NONE', 'MF_NONE')
        return ('GEN_OP_STORE', 'BRANCH_NONE', 'MF_NONE')

    # Fence
    if re.match(r'^[lms]fence', m):
        return ('GEN_OP_FENCE', 'BRANCH_NONE', 'MF_ATOMIC')

    # x87 FP
    if m.startswith('f'):
        if re.match(r'^f(n?)(add|sub|subr)', m):
            kind = 'GEN_OP_FP_ADD' if 'add' in m else 'GEN_OP_FP_SUB'
            return (kind, 'BRANCH_NONE', 'MF_NONE')
        if re.match(r'^f(n?)(mul)', m):
            return ('GEN_OP_FP_MUL', 'BRANCH_NONE', 'MF_NONE')
        if re.match(r'^f(n?)(div|divr)', m):
            return ('GEN_OP_FP_DIV', 'BRANCH_NONE', 'MF_NONE')
        if m.startswith('fild') or m.startswith('fist'):
            return ('GEN_OP_FP_CVT', 'BRANCH_NONE', 'MF_NONE')
        if re.match(r'^f(u?)com', m):
            return ('GEN_OP_FP_CMP', 'BRANCH_NONE', 'MF_NONE')
        if m.startswith('fcmov'):
            return ('GEN_OP_CMOV', 'BRANCH_NONE', 'MF_NONE')
        if m.startswith('fsqrt'):
            return ('GEN_OP_FP_SQRT', 'BRANCH_NONE', 'MF_NONE')
        return ('GEN_OP_FP_MOV', 'BRANCH_NONE', 'MF_NONE')

    # SSE / AVX with 'v' prefix
    if m.startswith('v'):
        if m.startswith('vcmp'):
            return ('GEN_OP_FP_CMP', 'BRANCH_NONE', 'MF_NONE')
        if m in ('vptest', 'vtestps', 'vtestpd'):
            return ('GEN_OP_TEST', 'BRANCH_NONE', 'MF_NONE')

        # vp... packed integer
        if m.startswith('vp'):
            core = m[2:]
            if core.startswith('add'):
                return ('GEN_OP_VEC_ADD', 'BRANCH_NONE', 'MF_NONE')
            if core.startswith('sub'):
                return ('GEN_OP_VEC_SUB', 'BRANCH_NONE', 'MF_NONE')
            if re.match(r'^mul', core):
                return ('GEN_OP_VEC_MUL', 'BRANCH_NONE', 'MF_NONE')
            if re.match(r'^(min|max|avg|abs|cmpgt|cmpeq|cmplt|sadbw|'
                        r'hminposuw|madd)', core):
                return ('GEN_OP_VEC_LOGIC', 'BRANCH_NONE', 'MF_NONE')
            if re.match(r'^(sll|srl|sra)', core):
                return ('GEN_OP_VEC_LOGIC', 'BRANCH_NONE', 'MF_NONE')
            if re.match(r'^(shuf|blend|align|unpck|unpack|pack|perm|'
                        r'insert|extract|insrt|extr)', core):
                return ('GEN_OP_VEC_SHUF', 'BRANCH_NONE', 'MF_NONE')
            if re.match(r'^(broadcast|movm|movsx|movzx)', core):
                return ('GEN_OP_VEC_MOV', 'BRANCH_NONE', 'MF_NONE')
            if re.match(r'^(or$|and|xor)', core):
                return ('GEN_OP_VEC_LOGIC', 'BRANCH_NONE', 'MF_NONE')
            return ('GEN_OP_VEC_LOGIC', 'BRANCH_NONE', 'MF_NONE')

        # v{op} — FP or vector
        vcore = m[1:]
        if re.match(r'^(add|hadd|addsub)', vcore):
            return ('GEN_OP_FP_ADD', 'BRANCH_NONE', 'MF_NONE')
        if re.match(r'^(sub|hsub)', vcore):
            return ('GEN_OP_FP_SUB', 'BRANCH_NONE', 'MF_NONE')
        if vcore.startswith('mul'):
            return ('GEN_OP_FP_MUL', 'BRANCH_NONE', 'MF_NONE')
        if vcore.startswith('div'):
            return ('GEN_OP_FP_DIV', 'BRANCH_NONE', 'MF_NONE')
        if vcore.startswith('sqrt'):
            return ('GEN_OP_FP_SQRT', 'BRANCH_NONE', 'MF_NONE')
        if re.match(r'^(min|max)', vcore):
            return ('GEN_OP_FP_CMP', 'BRANCH_NONE', 'MF_NONE')
        if vcore.startswith('round') or re.match(r'^cvt', vcore):
            return ('GEN_OP_FP_CVT', 'BRANCH_NONE', 'MF_NONE')
        if re.match(r'^(mov|broadcast|gather|scatter|maskmov)', vcore):
            return ('GEN_OP_VEC_MOV', 'BRANCH_NONE', 'MF_NONE')
        if re.match(r'^(shuf|blend|perm|unpck|insert|extract)', vcore):
            return ('GEN_OP_VEC_SHUF', 'BRANCH_NONE', 'MF_NONE')
        if vcore.startswith('zeroupper'):
            return ('GEN_OP_NOP', 'BRANCH_NONE', 'MF_NONE')
        return ('GEN_OP_VEC_LOGIC', 'BRANCH_NONE', 'MF_NONE')

    # SSE without v prefix
    if re.match(r'^(add|sub|mul|div|sqrt|max|min|cmp|round|cvt)(s|p)(s|d)', m):
        op = m.split('s')[0].split('p')[0]
        op_map = {'add': 'GEN_OP_FP_ADD', 'sub': 'GEN_OP_FP_SUB',
                   'mul': 'GEN_OP_FP_MUL', 'div': 'GEN_OP_FP_DIV',
                   'sqrt': 'GEN_OP_FP_SQRT', 'max': 'GEN_OP_FP_CMP',
                   'min': 'GEN_OP_FP_CMP', 'cmp': 'GEN_OP_FP_CMP',
                   'round': 'GEN_OP_FP_CVT', 'cvt': 'GEN_OP_FP_CVT'}
        return (op_map.get(op, 'GEN_OP_FP_MOV'), 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^(movap|movup|movdq|movddup|movshdup|movsldup|movhp|movlp|'
                r'movss|movsd|movnt|lddqu|movhlp|movlhp)', m):
        return ('GEN_OP_VEC_MOV', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^(padd|psub)', m):
        if 'add' in m:
            return ('GEN_OP_VEC_ADD', 'BRANCH_NONE', 'MF_NONE')
        return ('GEN_OP_VEC_SUB', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^pmul', m):
        return ('GEN_OP_VEC_MUL', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^(pand|pandn|por|pxor|pcmp|pmin|pmax|psadbw|phminposuw|'
                r'pmadd|pavg|pabs)', m):
        return ('GEN_OP_VEC_LOGIC', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^(psll|psrl|psra)', m):
        return ('GEN_OP_VEC_LOGIC', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^(pshuf|pblend|palign|punpck|pack[su]|pextr|pinsr)', m):
        return ('GEN_OP_VEC_SHUF', 'BRANCH_NONE', 'MF_NONE')
    if re.match(r'^(movdq2|movq2|pmov[sz]x)', m):
        return ('GEN_OP_VEC_MOV', 'BRANCH_NONE', 'MF_NONE')

    return ('GEN_OP_UNKNOWN', 'BRANCH_NONE', 'MF_NONE')


def classify_insn(insn_id, mnem, isa, id_to_class, id_to_name):
    """Classify an instruction.  Returns (gen_op, branch_type, flags_str)."""
    if isa == 'x86':
        return _classify_x86(insn_id, mnem, id_to_class, id_to_name)
    return ('GEN_OP_UNKNOWN', 'BRANCH_NONE', 'MF_NONE')


# Instruction category for grouping output.
_GEN_OP_CATEGORY = {
    'GEN_OP_INT_ADD': 'int_alu', 'GEN_OP_INT_SUB': 'int_alu',
    'GEN_OP_INT_MUL': 'int_alu', 'GEN_OP_INT_DIV': 'int_alu',
    'GEN_OP_INT_ADC': 'int_alu', 'GEN_OP_INT_SBB': 'int_alu',
    'GEN_OP_AND': 'int_alu', 'GEN_OP_OR': 'int_alu',
    'GEN_OP_XOR': 'int_alu', 'GEN_OP_NOT': 'int_alu',
    'GEN_OP_NEG': 'int_alu', 'GEN_OP_INC': 'int_alu',
    'GEN_OP_DEC': 'int_alu',
    'GEN_OP_SHL': 'shift', 'GEN_OP_SHR': 'shift',
    'GEN_OP_SAR': 'shift', 'GEN_OP_ROL': 'shift', 'GEN_OP_ROR': 'shift',
    'GEN_OP_MOV': 'data_mov', 'GEN_OP_MOVSX': 'data_mov',
    'GEN_OP_MOVZX': 'data_mov', 'GEN_OP_LEA': 'data_mov',
    'GEN_OP_LOAD': 'data_mov', 'GEN_OP_STORE': 'data_mov',
    'GEN_OP_PUSH': 'data_mov', 'GEN_OP_POP': 'data_mov',
    'GEN_OP_XCHG': 'data_mov',
    'GEN_OP_TEST': 'cmp', 'GEN_OP_CMP': 'cmp',
    'GEN_OP_CMOV': 'cond', 'GEN_OP_SETCC': 'cond',
    'GEN_OP_BRANCH': 'ctrl', 'GEN_OP_CALL': 'ctrl',
    'GEN_OP_RET': 'ctrl', 'GEN_OP_NOP': 'misc',
    'GEN_OP_SYSCALL': 'misc', 'GEN_OP_FENCE': 'misc',
    'GEN_OP_FP_ADD': 'fp', 'GEN_OP_FP_SUB': 'fp',
    'GEN_OP_FP_MUL': 'fp', 'GEN_OP_FP_DIV': 'fp',
    'GEN_OP_FP_SQRT': 'fp', 'GEN_OP_FP_MOV': 'fp',
    'GEN_OP_FP_CVT': 'fp', 'GEN_OP_FP_CMP': 'fp',
    'GEN_OP_VEC_ADD': 'vec', 'GEN_OP_VEC_SUB': 'vec',
    'GEN_OP_VEC_MUL': 'vec', 'GEN_OP_VEC_MOV': 'vec',
    'GEN_OP_VEC_SHUF': 'vec', 'GEN_OP_VEC_LOGIC': 'vec',
}

_CATEGORY_LABELS = {
    'fp':       'Scalar / packed FP',
    'vec':      'Vector integer',
    'int_alu':  'Integer ALU / BMI',
    'shift':    'Shifts / rotates',
    'data_mov': 'Data movement',
    'cmp':      'Comparison / test',
    'cond':     'Conditional',
    'ctrl':     'Control flow',
    'misc':     'Misc / NOP / fence',
}


def generate_entries(unknowns, isa, id_to_class, id_to_name):
    """Classify unknowns and print C designated-initializer entries."""
    entries_by_cat = defaultdict(list)
    for insn_id, mnem, count, addr in unknowns:
        const_name = id_to_name.get(insn_id, f"/* UNKNOWN_ID_{insn_id} */")
        gen_op, branch, flags = classify_insn(
            insn_id, mnem, isa, id_to_class, id_to_name
        )
        cat = _GEN_OP_CATEGORY.get(gen_op, 'misc')
        entries_by_cat[cat].append((const_name, gen_op, branch, flags, mnem, count))

    print("\n/* ===== AUTO-GENERATED entries — review before use ===== */")
    total = 0
    for cat in ('fp', 'vec', 'int_alu', 'shift', 'data_mov', 'cmp',
                'cond', 'ctrl', 'misc'):
        entries = entries_by_cat.get(cat)
        if not entries:
            continue
        label = _CATEGORY_LABELS.get(cat, cat)
        print(f"    /* {label} */")
        for const_name, gen_op, branch, flags, mnem, count in entries:
            pad = max(1, 36 - len(const_name))
            line = (f'    [{const_name}]{" " * pad}= '
                    f'{{ {gen_op},{" " * max(1, 14 - len(gen_op))}'
                    f'{branch},{" " * max(1, 22 - len(branch))}'
                    f'{flags} }},  /* {mnem} (count={count}) */')
            print(line)
            total += 1
    print(f"/* ===== END AUTO-GENERATED — {total} entries ===== */")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Survey ELF binaries for instruction IDs missing from wptrace tables."
    )
    parser.add_argument(
        "binaries", nargs="+", metavar="ELF",
        help="ELF binary files to analyze",
    )
    parser.add_argument(
        "--header", default=HEADER_REL,
        help="Path to wptrace_mnemonics.h (default: auto-detect)",
    )
    parser.add_argument(
        "--show-known", action="store_true",
        help="Also print known instruction IDs found in the binary",
    )
    parser.add_argument(
        "-g", "--generate", action="store_true",
        help="Generate C table entries for unknown instruction IDs",
    )
    args = parser.parse_args()

    # Parse the header
    tables = parse_header(args.header)
    for isa, (known_ids, id_to_class, id_to_name) in tables.items():
        print(f"  {isa:10s}: {len(known_ids):4d} instruction IDs classified")
    print()

    total_unknown = 0
    # Aggregate: insn_id → [count, first_file, first_addr, mnem]
    all_unknown = defaultdict(lambda: [0, None, None, ""])
    last_isa = None

    for path in args.binaries:
        binary = lief.parse(path)
        if binary is None:
            print(f"ERROR: could not parse {path}", file=sys.stderr)
            continue

        md, isa = make_disassembler(binary)
        if md is None:
            print(f"ERROR: unsupported architecture in {path}", file=sys.stderr)
            continue

        last_isa = isa
        known_ids, id_to_class, id_to_name = tables[isa]
        insn_ids = collect_insn_ids(binary, md)
        unknown = check_coverage(insn_ids, known_ids)

        n_total = sum(c for c, _, _ in insn_ids.values())
        n_unique = len(insn_ids)

        name = os.path.basename(path)
        print(f"--- {name} ({isa}) ---")
        print(f"  {n_total:,d} instructions, {n_unique} unique IDs")

        if unknown:
            print(f"  {len(unknown)} UNKNOWN instruction IDs:")
            for insn_id, mnem, count, addr in sorted(unknown, key=lambda x: -x[2]):
                cname = id_to_name.get(insn_id, f"ID_{insn_id}")
                print(f"    {cname:40s}  mnem={mnem:16s}  "
                      f"count={count:8d}  first=0x{addr:x}")
                entry = all_unknown[insn_id]
                entry[0] += count
                if entry[1] is None:
                    entry[1] = name
                    entry[2] = addr
                    entry[3] = mnem
        else:
            print("  All instruction IDs covered!")

        if args.show_known:
            known_list = [(iid, c, a, m) for iid, (c, a, m) in insn_ids.items()
                          if iid in known_ids]
            print(f"  {len(known_list)} known instruction IDs:")
            for iid, count, addr, mnem in sorted(known_list, key=lambda x: -x[1]):
                cname = id_to_name.get(iid, f"ID_{iid}")
                print(f"    {cname:40s}  mnem={mnem:16s}  count={count:8d}")

        total_unknown += len(unknown)
        print()

    # Summary across all binaries
    if len(args.binaries) > 1 and all_unknown:
        print("=== AGGREGATE UNKNOWN INSTRUCTION IDs ===")
        for insn_id, (count, first_file, first_addr, mnem) in sorted(
            all_unknown.items(), key=lambda x: -x[1][0]
        ):
            if last_isa:
                _, _, id_to_name = tables[last_isa]
                cname = id_to_name.get(insn_id, f"ID_{insn_id}")
            else:
                cname = f"ID_{insn_id}"
            print(f"  {cname:40s}  mnem={mnem:16s}  "
                  f"total={count:8d}  first in {first_file}")
        print()

    print(f"Total unknown instruction IDs across all files: {total_unknown}")

    # Generate C entries if requested
    if args.generate and all_unknown and last_isa is not None:
        _, id_to_class, id_to_name = tables[last_isa]
        combined_unknowns = [
            (iid, info[3], info[0], info[2] or 0)
            for iid, info in all_unknown.items()
        ]
        generate_entries(combined_unknowns, last_isa, id_to_class, id_to_name)

    return 1 if total_unknown > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
