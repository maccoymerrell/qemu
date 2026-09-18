#!/usr/bin/env python3
"""cst_referee — the external referee: the Capstone side of the tracer's
two-decoder comparison, produced offline from the encodings a QEMU-side
corpus already records.

Author: Maccoy Merrell
SPDX-License-Identifier: GPL-2.0-or-later

WHAT THIS IS FOR
----------------
The tracer's acceptance rests on comparing two decoders per encoding.  The
QEMU column is written by the emulator's own capture; this tool writes the
Capstone column, offline, from the recorded encodings.  It replaces the
retired C++ referee (tools/cst_referee.cc), which compiled Capstone and the
tracer's Capstone operand walk into the tree — the maintainer's ruling is
that the repository carries no Capstone C source at all, and the offline
comparison is produced the way the mnemonic-table generator always was:
through the Python Capstone bindings.

WHAT IT REPRODUCES, EXACTLY
---------------------------
Per (isa, encoding) key this emits the same rows the retired C++ referee
emitted for the corpora the join machinery consumes:

  gen_c_<isa>.tsv   the Capstone walk's register sets, side 'c', one row
                    per direction, spelled in the wire's generic names
                    (consumed by setjoin.py through score_referee.sh)
  opc_<isa>.tsv     mnemonic + generic opcode class
                    (consumed by gapreport.py through score_referee.sh)
  srcenc_<isa>.tsv  mnemonic + source-register list, insertion order
  mech_<isa>.tsv    walked / walked-empty / (unknown rows are absent,
                    exactly as the in-process arm behaved)

The derivation is a line-for-line port of the retired pipeline:

  1. the decode boundary — disas/capstone.c's per-arch operand fill,
     including every access-flag workaround for the pinned Capstone
     (6.0.0-Alpha7) that file carried;
  2. the operand walk — champsim_tracer_decode.cc's
     decode_detail_to_generic(), register-set half (the lane-mask and
     dependency refiners never reached these columns);
  3. the vocabulary — imported from champsim_tracer_mnemonic_audit.py,
     the same classify()/classify_reg() rules that generated the retired
     C tables, so the two cannot drift apart.

VERSION PARITY IS PART OF THE BAR.  The retired referee refused to run
against a Capstone other than the one its headers described, and stamped
the wrap revision into every corpus.  This tool stamps the Python
bindings' distribution version and the runtime cs_version() instead, and
REFUSES if the bindings are not the 6.0.0 line the workaround catalogue
was written against — a comparison against a different Capstone turns
version differences into decoder disagreements.

The corpora carry the INPUT's #so stamp (the build whose encodings are
scored), and a #referee line naming the Capstone that produced the column,
exactly as before.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import capstone

# The vocabulary: the same classification rules that generated the retired
# C tables.  champsim_tracer_mnemonic_audit.py lives one directory up.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import champsim_tracer_mnemonic_audit as vocab  # noqa: E402

# ----------------------------------------------------------------------
# Constants shared with the retired boundary (identical values).
# ----------------------------------------------------------------------

ACC_READ = 1                    # QEMU_PLUGIN_OP_ACC_READ == CS_AC_READ
ACC_WRITE = 2                   # QEMU_PLUGIN_OP_ACC_WRITE == CS_AC_WRITE
MAX_OPS = 16                    # QEMU_PLUGIN_INSN_DETAIL_MAX_OPS
MAX_IREGS = 16                  # QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS
MAX_SRC_REGS = 64
MAX_DST_REGS = 64
SET_NAMES_MAX = 64

# Operand kinds (internal; the wire never sees these).
OP_INVALID, OP_REG, OP_IMM, OP_MEM, OP_SYSREG = range(5)

# Sysreg roles -> the generic register the walk publishes
# (generic_reg_for_sysreg_class in champsim_tracer_mnemonics.h).
SYSREG_FLAGS = "REG_FLAGS"
SYSREG_FPCTRL = "REG_FCSR"
SYSREG_VECCTRL = "REG_VCTRL"
SYSREG_THREADPTR = "REG_TLS"
SYSREG_OTHER = "REG_SYS"

# The decode address every encoding is scored at (keyed on the encoding
# alone, so a pc that moved would leak into pc-relative renderings).
DECODE_PC = 0x100000


class Operand:
    __slots__ = ("kind", "access", "reg_id", "index_id", "segment_id",
                 "imm", "sysreg_gen", "shift_type", "shift_value",
                 "lane_bytes")

    def __init__(self):
        self.kind = OP_INVALID
        self.access = 0
        self.reg_id = 0
        self.index_id = 0
        self.segment_id = 0
        self.imm = 0
        self.sysreg_gen = None      # generic name for SYSREG operands
        self.shift_type = 0
        self.shift_value = 0
        self.lane_bytes = 0         # vector lane width; 0 on scalars


class Info:
    """The subset of qemu_plugin_insn_info the register walk consumed."""
    __slots__ = ("mnemonic", "op_str", "insn_id", "operands",
                 "regs_read_id", "regs_write_id", "has_lock", "has_rep")

    def __init__(self):
        self.mnemonic = ""
        self.op_str = ""
        self.insn_id = 0
        self.operands = []
        self.regs_read_id = []
        self.regs_write_id = []
        self.has_lock = False
        self.has_rep = False


# ----------------------------------------------------------------------
# Per-ISA setup: Capstone arch/mode (the offline defaults the retired
# champsim_tracer_capstone_mode.h fell back to when no guest binary was
# available — which is the referee's situation by construction) and the
# constant tables the fill and the walk key on.
# ----------------------------------------------------------------------

from capstone import x86_const as XC          # noqa: E402
from capstone import mips_const as MC         # noqa: E402
from capstone import riscv_const as RC        # noqa: E402
try:
    from capstone import aarch64_const as AC  # capstone 6 spelling
except ImportError:                            # pragma: no cover
    from capstone import arm64_const as AC


def _const_map(mod, prefix, upper=None, chooser=None):
    """value -> constant-name-suffix.

    The python bindings carry names the pinned C headers did not: the ABI
    aliases of the RISC-V register file (RA beside X1), AArch64's IP0/IP1/
    X29/X30 beside X16/X17/FP/LR, and the *_ALIAS_* instruction-id space
    beyond <ARCH>_INS_ENDING.  The retired C tables were generated over
    the C header's names and indexed below ENDING, so this map must make
    the same choices: @upper drops ids at or beyond ENDING, and @chooser
    picks the header's spelling when one value has several names.
    """
    gathered = {}
    for name in dir(mod):
        if not name.startswith(prefix):
            continue
        suffix = name[len(prefix):]
        if suffix in ("ENDING", "INVALID"):
            continue
        val = getattr(mod, name)
        if not isinstance(val, int):
            continue
        if upper is not None and val >= upper:
            continue
        gathered.setdefault(val, []).append(suffix)
    out = {}
    for val, names in gathered.items():
        if len(names) == 1 or chooser is None:
            out[val] = sorted(names)[0]
        else:
            out[val] = chooser(sorted(names))
    return out


import re as _re


def _riscv_reg_choose(names):
    """The pinned C riscv.h spells registers X<n> / F<n>_* / V<n>*; the
    python bindings add the ABI aliases (RA, SP, A0, FT0, ...).  Prefer
    the header spelling, which is also the one the vocabulary's
    classify_riscv_reg() resolves."""
    for pat in (r"X\d+", r"F\d+_[A-Z0-9]+", r"V\d+.*"):
        for n in names:
            if _re.fullmatch(pat, n):
                return n
    return names[0]


def _aarch64_reg_choose(names):
    """The pinned C aarch64.h has FP/LR/X16/X17; the bindings add
    X29/X30/IP0/IP1 as extra spellings of the same values.  Prefer the
    header's: FP and LR over X29/X30, X<n> over IP<n>."""
    for pref in ("FP", "LR"):
        if pref in names:
            return pref
    for n in names:
        if _re.fullmatch(r"[WX]\d+", n):
            return n
    return names[0]


# The four MIPS register names the 6.0.0a7 python bindings dropped while
# the pinned C mips.h carries them (values read off that header).
_MIPS_REG_PATCH = {401: "COP0SEL_CDMMBASE", 402: "COP0SEL_CMGCRBASE",
                   416: "COP0SEL_EBASE", 440: "COP0SEL_PWBASE"}


class Isa:
    def __init__(self, name):
        self.name = name
        if name == "x86_64":
            self.key = "x86"
            self.arch = capstone.CS_ARCH_X86
            self.mode = capstone.CS_MODE_64
            self.ins = _const_map(XC, "X86_INS_", XC.X86_INS_ENDING)
            self.regs = _const_map(XC, "X86_REG_")
            self.reg_ending = XC.X86_REG_ENDING
        elif name == "aarch64":
            self.key = "aarch64"
            self.arch = capstone.CS_ARCH_AARCH64
            self.mode = capstone.CS_MODE_LITTLE_ENDIAN
            self.ins = _const_map(AC, "AARCH64_INS_",
                                  AC.AARCH64_INS_ENDING)
            self.regs = _const_map(AC, "AARCH64_REG_",
                                   chooser=_aarch64_reg_choose)
            self.reg_ending = AC.AARCH64_REG_ENDING
        elif name == "riscv64":
            self.key = "riscv"
            self.arch = capstone.CS_ARCH_RISCV
            self.mode = (capstone.CS_MODE_RISCV64
                         | capstone.CS_MODE_RISCV_C
                         | capstone.CS_MODE_RISCV_FD
                         | capstone.CS_MODE_RISCV_A
                         | capstone.CS_MODE_RISCV_V
                         | capstone.CS_MODE_RISCV_ZBA
                         | capstone.CS_MODE_RISCV_ZBB
                         | capstone.CS_MODE_RISCV_ZBC
                         | capstone.CS_MODE_RISCV_ZBKB
                         | capstone.CS_MODE_RISCV_ZBKC
                         | capstone.CS_MODE_RISCV_ZBKX
                         | capstone.CS_MODE_RISCV_ZBS)
            self.ins = _const_map(RC, "RISCV_INS_", RC.RISCV_INS_ENDING)
            self.regs = _const_map(RC, "RISCV_REG_",
                                   chooser=_riscv_reg_choose)
            # The 6.0.0a7 python bindings ship no RISCV_REG_ENDING; the
            # bound exists to guard the out-of-range implicit ids the
            # RISC-V decoder emits on vector pseudo-ops, so one past the
            # largest named register is the same bound.
            self.reg_ending = getattr(RC, "RISCV_REG_ENDING",
                                      max(self.regs) + 1)
        elif name == "mipsel":
            self.key = "mips"
            self.arch = capstone.CS_ARCH_MIPS
            self.mode = (capstone.CS_MODE_MIPS32R2
                         | capstone.CS_MODE_LITTLE_ENDIAN)
            self.ins = _const_map(MC, "MIPS_INS_", MC.MIPS_INS_ENDING)
            self.regs = _const_map(MC, "MIPS_REG_")
            self.regs.update(_MIPS_REG_PATCH)
            self.reg_ending = MC.MIPS_REG_ENDING
        else:
            raise KeyError(name)
        self.info = vocab.ISAS[self.key]
        self._cls_cache = {}
        self._reg_cache = {}
        md = capstone.Cs(self.arch, self.mode)
        if self.arch == capstone.CS_ARCH_X86:
            md.syntax = capstone.CS_OPT_SYNTAX_ATT
        md.detail = True
        self.md = md

    def classify_id(self, insn_id):
        """insn_id -> vocab Entry (opcode / branch / flags), or None."""
        e = self._cls_cache.get(insn_id)
        if e is None:
            suffix = self.ins.get(insn_id)
            if suffix is None:
                return None
            e = vocab.classify(self.info, self.info.prefix + suffix)
            self._cls_cache[insn_id] = e
        return e

    def reg_names(self, reg_id):
        """Capstone reg id -> tuple of generic names (the retired
        RegClassification row: alias list when present, else primary,
        REG_NONE rows -> empty)."""
        names = self._reg_cache.get(reg_id)
        if names is None:
            if reg_id == 0 or reg_id >= self.reg_ending:
                names = ()
            else:
                suffix = self.regs.get(reg_id)
                if suffix is None:
                    names = ()
                else:
                    ent = vocab.classify_reg(self.info,
                                             self.info.reg_prefix + suffix)
                    if ent.ignored:
                        names = ()
                    elif ent.aliases:
                        names = tuple(ent.aliases)[:8]  # MAX_REG_ALIASES
                    else:
                        names = (ent.primary,)
                    names = tuple(n for n in names if n != "REG_NONE")
            self._reg_cache[reg_id] = names
        return names


# ----------------------------------------------------------------------
# The x86 workaround catalogue (disas/capstone.c, ported verbatim).
# ----------------------------------------------------------------------

def x86_strip_v(m):
    return m[1:] if m.startswith("v") else m


def cap_x86_is_extract_store(m):
    if not m:
        return False
    m = x86_strip_v(m)
    return m.startswith("pextr") or m.startswith("extract") or m == "cvtps2ph"


_SETCC = {"seta", "setae", "setb", "setbe", "sete", "setg", "setge", "setl",
          "setle", "setne", "setno", "setnp", "setns", "seto", "setp", "sets"}


def cap_x86_is_lost_mem_store(m):
    if not m:
        return False
    if m in ("stmxcsr", "vstmxcsr"):
        return True
    return m in _SETCC


def cap_x86_is_gather(m):
    return m in {"vpgatherdd", "vpgatherdq", "vpgatherqd", "vpgatherqq",
                 "vgatherdps", "vgatherdpd", "vgatherqps", "vgatherqpd"}


_X87_MEM_WRITE = {"fsts", "fstl", "fstps", "fstpl", "fstpt",
                  "fists", "fistl", "fistps", "fistpl", "fistpll",
                  "fisttps", "fisttpl", "fisttpll",
                  "fbstp", "fnstcw", "fnstsw", "fnstenv", "fnsave"}
_X87_MEM_READ = {"frstor", "fldenv"}


def cap_x86_x87_mem_access(m):
    if not m or m[0] != "f":
        return 0
    if m in _X87_MEM_WRITE:
        return ACC_WRITE
    if m in _X87_MEM_READ:
        return ACC_READ
    return 0


def cap_x86_is_erased_mem_load(m):
    return m in ("vbroadcasti128", "vcvtpd2psx")


def cap_x86_is_test(m):
    return bool(m) and m.startswith("test")


def cap_x86_is_mask_arith_dest_last(m):
    return bool(m) and (m.startswith("kadd") or m.startswith("kunpck")
                        or m.startswith("vpermil2"))


def cap_x86_is_ktest(m):
    return bool(m) and m.startswith("ktest")


def cap_x86_is_ssp_read(m):
    return bool(m) and m.startswith("incssp")


def cap_x86_is_x87_tag_only(m):
    return m == "ffreep"


def cap_x86_skip_rep(m):
    for p in ("rep ", "repe ", "repz ", "repne ", "repnz "):
        if m.startswith(p):
            return m.split(" ", 1)[1]
    return m


_STRING_BASES = ("movs", "cmps", "scas", "lods", "stos", "ins", "outs")


def cap_x86_is_string_op(m):
    if not m:
        return False
    m = cap_x86_skip_rep(m)
    for base in _STRING_BASES:
        if len(m) == len(base) + 1 and m.startswith(base) \
                and m[-1] in "bwlq":
            return True
    return False


def cap_x86_string_mem_access(m, base_reg):
    if not m:
        return 0
    m = cap_x86_skip_rep(m)
    via_si = base_reg in (XC.X86_REG_RSI, XC.X86_REG_ESI, XC.X86_REG_SI)
    via_di = base_reg in (XC.X86_REG_RDI, XC.X86_REG_EDI, XC.X86_REG_DI)
    if not via_si and not via_di:
        return 0
    if via_si:
        return ACC_READ
    if m.startswith("cmps") or m.startswith("scas"):
        return ACC_READ
    return ACC_WRITE


def cap_x86_is_scalar_round(m):
    if not m:
        return False
    m = x86_strip_v(m)
    return m in ("roundss", "roundsd")


def cap_x86_is_shadow_stack_store(m):
    return bool(m) and (m.startswith("wrss") or m.startswith("wruss"))


def cap_x86_mem_is_never_accessed(m):
    return bool(m) and m.startswith("nop")


def cap_x86_is_push(m):
    return bool(m) and m.startswith("push")


def cap_x86_is_move_family(m):
    if not m:
        return False
    if m.startswith("kmov"):
        return True
    m = x86_strip_v(m)
    if m.startswith("maskmov") or m.startswith("pmaskmov"):
        return True
    if not m.startswith("mov"):
        return False
    if len(m) == 6 and m[3] in "sz" and m[4] in "bwl" and m[5] in "wlq":
        return False
    return not (m.startswith("movsx") or m.startswith("movzx")
                or m.startswith("movbe") or m.startswith("movmsk"))


def _implicit_add(ids, reg):
    if reg in ids:
        return
    if len(ids) >= MAX_IREGS:
        return
    ids.append(reg)


def fill_x86(isa, insn, out):
    ops = insn.operands[:MAX_OPS]
    m = insn.mnemonic

    extract_store = cap_x86_is_extract_store(m)
    mv_fam = cap_x86_is_move_family(m)
    mv_has_mem = mv_has_reg = mv_any_write = False
    if mv_fam:
        for cop in ops:
            if cop.type == XC.X86_OP_MEM:
                mv_has_mem = True
            elif cop.type == XC.X86_OP_REG:
                mv_has_reg = True
            if cop.access & ACC_WRITE:
                mv_any_write = True
    move_store = mv_fam and mv_has_mem and mv_has_reg and not mv_any_write
    test_read = cap_x86_is_test(m)
    string_op = cap_x86_is_string_op(m)
    scalar_round = cap_x86_is_scalar_round(m)
    shstk_store = cap_x86_is_shadow_stack_store(m)
    mem_unused = cap_x86_mem_is_never_accessed(m)
    push_read = cap_x86_is_push(m)
    erased_load = cap_x86_is_erased_mem_load(m)
    lost_store = cap_x86_is_lost_mem_store(m)
    gather = cap_x86_is_gather(m)
    x87_mem = cap_x86_x87_mem_access(m)
    dest_last = cap_x86_is_mask_arith_dest_last(m)
    ktest_op = cap_x86_is_ktest(m)
    ssp_read = cap_x86_is_ssp_read(m)
    tag_only = cap_x86_is_x87_tag_only(m)

    if ktest_op:
        _implicit_add(out.regs_write_id, XC.X86_REG_EFLAGS)

    n = len(ops)
    for i, cop in enumerate(ops):
        op = Operand()
        op.access = cop.access
        if test_read or ktest_op or ssp_read:
            op.access = ACC_READ
        if dest_last and cop.type != XC.X86_OP_IMM:
            op.access = ACC_WRITE if i == n - 1 else ACC_READ
        if tag_only:
            op.kind = OP_INVALID
            op.access = 0
            out.operands.append(op)
            continue

        if cop.type == XC.X86_OP_REG:
            op.kind = OP_REG
            op.reg_id = cop.reg
            if (string_op or shstk_store or push_read) and op.access == 0:
                op.access = ACC_READ
            if erased_load and op.access == 0:
                op.access = ACC_WRITE
            if gather and i == 0:
                op.access |= ACC_WRITE
        elif cop.type == XC.X86_OP_IMM:
            op.kind = OP_IMM
            op.imm = cop.imm
        elif cop.type == XC.X86_OP_MEM:
            op.kind = OP_MEM
            op.reg_id = cop.mem.base
            op.index_id = cop.mem.index
            op.imm = cop.mem.disp
            op.segment_id = cop.mem.segment
            if extract_store or move_store or lost_store:
                op.access = ACC_WRITE
            if x87_mem:
                op.access = x87_mem
            if string_op:
                a = cap_x86_string_mem_access(m, cop.mem.base)
                if a:
                    op.access = a
            if scalar_round:
                op.access = ACC_READ
            if shstk_store:
                op.access = ACC_WRITE
            if mem_unused:
                op.access = 0
            if erased_load and op.access == 0:
                op.access = ACC_READ
        else:
            op.kind = OP_INVALID
        out.operands.append(op)

    prefix0 = insn.prefix[0] if insn.prefix else 0
    out.has_lock = prefix0 == XC.X86_PREFIX_LOCK
    out.has_rep = (prefix0 in (XC.X86_PREFIX_REP, XC.X86_PREFIX_REPNE)
                   and string_op)


# ----------------------------------------------------------------------
# AArch64 (disas/capstone.c, ported verbatim).
# ----------------------------------------------------------------------

def _ac(name, default=None):
    return getattr(AC, name, default)


_AARCH64LAYOUT_INVALID = _ac("AARCH64LAYOUT_INVALID", 0)
AARCH64_OP_REG = _ac("AARCH64_OP_REG")
AARCH64_OP_IMM = _ac("AARCH64_OP_IMM")
AARCH64_OP_MEM = _ac("AARCH64_OP_MEM")
AARCH64_OP_PRED = _ac("AARCH64_OP_PRED")
AARCH64_OP_SME = _ac("AARCH64_OP_SME")
AARCH64_OP_SYSREG = _ac("AARCH64_OP_SYSREG")
AARCH64_OP_REG_MRS = _ac("AARCH64_OP_REG_MRS")
AARCH64_OP_REG_MSR = _ac("AARCH64_OP_REG_MSR")
AARCH64_OP_SYSALIAS = _ac("AARCH64_OP_SYSALIAS")
AARCH64_OP_DC = _ac("AARCH64_OP_DC")
AARCH64_DC_ZVA = _ac("AARCH64_DC_ZVA")
AARCH64_DC_GZVA = _ac("AARCH64_DC_GZVA")
AARCH64_SFT_INVALID = _ac("AARCH64_SFT_INVALID", 0)
AARCH64_SFT_LSL_REG = _ac("AARCH64_SFT_LSL_REG")
AARCH64_REG_INVALID = _ac("AARCH64_REG_INVALID", 0)
AARCH64_REG_LR = _ac("AARCH64_REG_LR")
AARCH64_REG_FPCR = _ac("AARCH64_REG_FPCR")
AARCH64_INS_RET = _ac("AARCH64_INS_RET")
AARCH64_INS_SEL = _ac("AARCH64_INS_SEL")
AARCH64_SYSREG_NZCV = _ac("AARCH64_SYSREG_NZCV")
AARCH64_SYSREG_FPCR = _ac("AARCH64_SYSREG_FPCR")
AARCH64_SYSREG_FPSR = _ac("AARCH64_SYSREG_FPSR")
AARCH64_SYSREG_FPMR = _ac("AARCH64_SYSREG_FPMR")
AARCH64_SYSREG_TPIDR_EL0 = _ac("AARCH64_SYSREG_TPIDR_EL0")
AARCH64_SYSREG_TPIDRRO_EL0 = _ac("AARCH64_SYSREG_TPIDRRO_EL0")


def cap_aarch64_sysreg_class(sysreg):
    if sysreg == AARCH64_SYSREG_NZCV:
        return SYSREG_FLAGS
    if sysreg in (AARCH64_SYSREG_FPCR, AARCH64_SYSREG_FPSR,
                  AARCH64_SYSREG_FPMR):
        return SYSREG_FPCTRL
    if sysreg in (AARCH64_SYSREG_TPIDR_EL0, AARCH64_SYSREG_TPIDRRO_EL0):
        return SYSREG_THREADPTR
    return SYSREG_OTHER


def cap_aarch64_is_cas(m):
    return m.startswith("cas") or m.startswith("rcwcas") \
        or m.startswith("rcwscas")


def cap_aarch64_is_single_cas(m):
    return m.startswith("cas") and (len(m) < 4 or m[3] != "p")


def cap_aarch64_is_mops_set(m):
    return m.startswith("set") and not m.startswith("setf")


def cap_aarch64_reads_fpcr_unreported(m):
    if m.startswith("fccmp"):
        return True
    if m.startswith("fabs") or m.startswith("fneg"):
        return True
    if m.startswith("fadda"):
        return True
    if len(m) >= 2 and m[0] in "su" and m[1] == "q":
        return True
    return False


def cap_aarch64_is_buggy_shift_imm_alias(m):
    return m in ("lsl", "lsr", "asr", "ror")


_A64_RMW_PREFIXES = ("swp", "cas",
                     "ldadd", "ldclr", "ldeor", "ldset",
                     "ldsmax", "ldsmin", "ldumax", "ldumin",
                     "stadd", "stclr", "steor", "stset",
                     "stsmax", "stsmin", "stumax", "stumin")


def cap_aarch64_infer_mem_access(m):
    if not m:
        return 0
    for p in _A64_RMW_PREFIXES:
        if m.startswith(p):
            return ACC_READ | ACC_WRITE
    if m.startswith("ld"):
        return ACC_READ
    if m.startswith("st"):
        return ACC_WRITE
    return 0


def _a64_block_zero(ops):
    if len(ops) < 2:
        return False
    o = ops[0]
    if o.type != AARCH64_OP_SYSALIAS:
        return False
    sysop = o.sysop
    if sysop.sub_type != AARCH64_OP_DC:
        return False
    return sysop.alias.dc in (AARCH64_DC_ZVA, AARCH64_DC_GZVA)


def _a64_vas_lane_bytes(vas):
    """cap_decode_aarch64_vas() from disas/capstone.c: the vector
    arrangement specifier's lane width in bytes, 0 when the operand
    carries no arrangement (every scalar form)."""
    if not vas or vas == _AARCH64LAYOUT_INVALID:
        return 0
    lane_bits = vas & 0xff
    if lane_bits not in (8, 16, 32, 64, 128):
        return 0
    count = (vas >> 8) & 0xff
    if count == 0:
        count = 1
    lb = lane_bits // 8
    if lb * count > 255:            # SVE matrix tile (COMPLETE)
        return 0
    return lb


def fill_arm64(isa, insn, out):
    ops = insn.operands[:MAX_OPS]
    m = insn.mnemonic
    n = len(ops)

    block_zero = _a64_block_zero(ops)

    for cop in ops:
        op = Operand()
        op.access = cop.access
        op.lane_bytes = _a64_vas_lane_bytes(getattr(cop, "vas", 0))
        shift = getattr(cop, "shift", None)
        if shift is not None:
            op.shift_type = shift.type
            op.shift_value = shift.value

        t = cop.type
        if t == AARCH64_OP_REG:
            op.kind = OP_REG
            op.reg_id = cop.reg
            if block_zero:
                op.kind = OP_MEM
                op.access = ACC_WRITE
                op.imm = 0
        elif t == AARCH64_OP_IMM:
            op.kind = OP_IMM
            op.imm = cop.imm
        elif t == AARCH64_OP_MEM:
            op.kind = OP_MEM
            op.reg_id = cop.mem.base
            op.index_id = cop.mem.index
            op.imm = cop.mem.disp
            if cop.access == 0:
                op.access = cap_aarch64_infer_mem_access(m)
        elif t == AARCH64_OP_PRED:
            op.kind = OP_REG
            # The Python bindings' AArch64Op wrapper exposes reg/imm/fp/mem/
            # imm_range/sme as properties over the operand union but has no
            # `pred` property, so the union member has to be reached directly.
            # (Bindings gap, capstone 6.0.0: capstone/aarch64.py declares
            # AArch64OpValue.pred and then omits the accessor.)
            op.reg_id = cop.value.pred.reg
        elif t == AARCH64_OP_SME:
            op.kind = OP_REG
            op.reg_id = cop.sme.tile
            if cop.sme.slice_reg != AARCH64_REG_INVALID:
                _implicit_add(out.regs_read_id, cop.sme.slice_reg)
        else:
            handled = False
            if t in (AARCH64_OP_SYSREG, AARCH64_OP_REG_MRS,
                     AARCH64_OP_REG_MSR):
                sub = cop.sysop.sub_type
                if sub == AARCH64_OP_REG_MRS:
                    op.kind = OP_SYSREG
                    op.access = ACC_READ
                    op.sysreg_gen = cap_aarch64_sysreg_class(
                        cop.sysop.reg.sysreg)
                    handled = True
                elif sub == AARCH64_OP_REG_MSR:
                    op.kind = OP_SYSREG
                    op.access = ACC_WRITE
                    op.sysreg_gen = cap_aarch64_sysreg_class(
                        cop.sysop.reg.sysreg)
                    handled = True
            if not handled:
                op.kind = OP_INVALID
        out.operands.append(op)

    # SIMD writeback: add the base register to the implicit write list
    # when writeback is claimed and an index amount exists.
    if insn.writeback:
        for op in out.operands:
            if op.kind != OP_MEM or op.reg_id == 0:
                continue
            if op.imm == 0 and op.index_id == 0:
                break
            _implicit_add(out.regs_write_id, op.reg_id)
            break

    # Single-register CAS: restore the RMW on the compare/result register
    # and drop the phantom base write.
    if cap_aarch64_is_cas(m):
        base_reg = 0
        for op in out.operands:
            if op.kind == OP_MEM:
                base_reg = op.reg_id
                break
        if cap_aarch64_is_single_cas(m):
            for op in out.operands:
                if op.kind == OP_REG:
                    op.access |= ACC_READ | ACC_WRITE
                    break
        if base_reg:
            out.regs_write_id = [r for r in out.regs_write_id
                                 if r != base_reg]

    # FEAT_MOPS memset: stores only.
    if cap_aarch64_is_mops_set(m):
        for op in out.operands:
            if op.kind == OP_MEM:
                op.access = ACC_WRITE

    # SVE merging-predicated mov alias of SEL: restore Zd's read.
    if insn.id == AARCH64_INS_SEL and len(out.operands) == 3 \
            and out.operands[0].kind == OP_REG \
            and out.operands[2].kind == OP_REG:
        out.operands[0].access |= ACC_READ

    # FPCR read on the forms whose siblings report it.
    if cap_aarch64_reads_fpcr_unreported(m):
        _implicit_add(out.regs_read_id, AARCH64_REG_FPCR)

    # Aliased RET: restore the x30 read.
    if insn.id == AARCH64_INS_RET and n == 0:
        _implicit_add(out.regs_read_id, AARCH64_REG_LR)

    # LSL/LSR/ASR/ROR alias: synthesise the dropped third operand.
    if len(out.operands) == 2 and len(out.operands) < MAX_OPS \
            and cap_aarch64_is_buggy_shift_imm_alias(m) \
            and len(ops) >= 2 \
            and ops[1].shift.type != AARCH64_SFT_INVALID:
        op = Operand()
        shift_type = ops[1].shift.type
        shift_val = ops[1].shift.value
        if AARCH64_SFT_LSL_REG is not None \
                and shift_type >= AARCH64_SFT_LSL_REG:
            op.kind = OP_REG
            op.access = ACC_READ
            op.reg_id = shift_val
        else:
            op.kind = OP_IMM
            op.imm = shift_val
        out.operands.append(op)


# ----------------------------------------------------------------------
# RISC-V + MIPS (disas/capstone.c cap_fill_generic_operands, ported
# verbatim).
# ----------------------------------------------------------------------

_MIPS_TIED_STEMS = ("ins", "dins", "append", "prepend", "insv", "balign",
                    "precr_sra",
                    "binsl", "binsr", "bmnz", "bmz", "bsel",
                    "insert", "insve", "sld", "vshf",
                    "maddv", "msubv", "madd_q", "maddr_q", "msub_q",
                    "msubr_q", "fmadd", "fmsub", "dpa", "dps",
                    "movn", "movz", "movt", "movf")


def cap_mips_is_tied_dst(m):
    return bool(m) and any(m.startswith(s) for s in _MIPS_TIED_STEMS)


def cap_riscv_is_tied_vd(m):
    if not m or m[0] != "v":
        return False
    if m in ("vmv.s.x", "vfmv.s.f"):
        return True
    return ("macc" in m) or ("madd" in m) or ("msac" in m) or ("msub" in m)


def cap_riscv_reads_v0_mask(m):
    if not m or m[0] != "v":
        return False
    if len(m) < 5 or m[-1] != "m" or m[-3] != "v" or m[-4] != ".":
        return False
    return m[-2] in "vxif"


def cap_riscv_is_mask_dst(m):
    if not m or m[0] != "v":
        return False
    if m == "vlm.v":
        return True
    if m in ("vmmv.m", "vmnot.m", "vmclr.m", "vmset.m"):
        return True
    if m.startswith("vms") or m.startswith("vmf") or m.startswith("vmadc"):
        return True
    return len(m) > 5 and m[1] == "m" and m.endswith(".mm")


def _riscv_word(insn):
    if insn.size != 4:
        return None
    b = insn.bytes
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)


def cap_riscv_reads_dynamic_frm(insn):
    word = _riscv_word(insn)
    if word is None:
        return False
    opcode = word & 0x7f
    if opcode not in (0x43, 0x47, 0x4b, 0x4f, 0x53):
        return False
    return ((word >> 12) & 0x7) == 0x7


def cap_riscv_is_tied_rd(m):
    if not m:
        return False
    if m.startswith("amocas."):
        return True
    if not m.startswith("cv."):
        return False
    return len(m) > 5 and m.endswith("nr")


def cap_riscv_is_vector_encoding(insn):
    word = _riscv_word(insn)
    if word is None:
        return False
    op = word & 0x7f
    if op == 0x57:
        return True
    if op in (0x07, 0x27):
        return ((word >> 12) & 0x7) in (0, 5, 6, 7)
    return False


def cap_riscv_fli_index(insn):
    word = _riscv_word(insn)
    if word is None:
        return None
    if (word & 0x7f) != 0x53:
        return None
    if ((word >> 12) & 0x7) != 0:
        return None
    if ((word >> 20) & 0x1f) != 1:
        return None
    if (word >> 27) != 0x1e:
        return None
    return (word >> 15) & 0x1f


def cap_riscv_csr_class(csr):
    if csr in (0x001, 0x002, 0x003, 0x009, 0x00a, 0x00f):
        return SYSREG_FPCTRL
    if csr in (0x008, 0xc20, 0xc21):
        return SYSREG_VECCTRL
    return SYSREG_OTHER


def cap_riscv_csr_access(insn):
    word = _riscv_word(insn)
    if word is None or (word & 0x7f) != 0x73:
        return ACC_READ | ACC_WRITE
    funct3 = (word >> 12) & 0x7
    rd = (word >> 7) & 0x1f
    rs1 = (word >> 15) & 0x1f
    if funct3 in (1, 5):                      # CSRRW / CSRRWI
        return ACC_WRITE | (ACC_READ if rd else 0)
    if funct3 in (2, 3, 6, 7):                # CSRRS/C[I]
        return ACC_READ | (ACC_WRITE if rs1 else 0)
    return ACC_READ | ACC_WRITE


def cap_mips_is_acc_rmw(m):
    return any(m.startswith(p) for p in
               ("madd", "msub", "dpa", "dps", "maq", "mulsa",
                "shilo", "mthlip"))


def cap_mips_is_acc_reg(reg):
    return (MC.MIPS_REG_AC0 <= reg <= MC.MIPS_REG_AC3) or \
           (MC.MIPS_REG_HI0 <= reg <= MC.MIPS_REG_HI3) or \
           (MC.MIPS_REG_LO0 <= reg <= MC.MIPS_REG_LO3)


RISCV_OP_REG = RC.RISCV_OP_REG
RISCV_OP_IMM = RC.RISCV_OP_IMM
RISCV_OP_MEM = RC.RISCV_OP_MEM
RISCV_OP_CSR = getattr(RC, "RISCV_OP_CSR", None)
RISCV_OP_FP = getattr(RC, "RISCV_OP_FP", None)


def fill_riscv(isa, insn, out):
    ops = insn.operands[:MAX_OPS]
    m = insn.mnemonic

    for cop in ops:
        op = Operand()
        op.access = getattr(cop, "access", 0)
        t = cop.type
        if t == RISCV_OP_REG:
            op.kind = OP_REG
            op.reg_id = cop.reg
        elif t == RISCV_OP_IMM:
            op.kind = OP_IMM
            op.imm = cop.imm
        elif t == RISCV_OP_MEM:
            op.kind = OP_MEM
            op.reg_id = cop.mem.base
            op.imm = cop.mem.disp
        elif RISCV_OP_FP is not None and t == RISCV_OP_FP:
            idx = cap_riscv_fli_index(insn)
            if idx is not None:
                op.kind = OP_IMM
                op.imm = idx
            else:
                op.kind = OP_INVALID
        elif RISCV_OP_CSR is not None and t == RISCV_OP_CSR:
            op.kind = OP_SYSREG
            op.access = cap_riscv_csr_access(insn)
            op.sysreg_gen = cap_riscv_csr_class(cop.csr)
        else:
            op.kind = OP_INVALID
        out.operands.append(op)

    # Zicsr alias forms drop the CSR operand: recover it from the word.
    word = _riscv_word(insn)
    if word is not None:
        funct3 = (word >> 12) & 0x7
        if (word & 0x7f) == 0x73 and funct3 not in (0, 4):
            if not any(o.kind == OP_SYSREG for o in out.operands) \
                    and len(out.operands) < MAX_OPS:
                csr = (word >> 20) & 0xfff
                op = Operand()
                op.kind = OP_SYSREG
                op.access = cap_riscv_csr_access(insn)
                op.sysreg_gen = cap_riscv_csr_class(csr)
                out.operands.append(op)

    n = len(out.operands)

    # A mask destination is read as well as written.
    if cap_riscv_is_mask_dst(m) and n >= 1 \
            and out.operands[0].kind == OP_REG:
        out.operands[0].access |= ACC_READ | ACC_WRITE
    # RVV tied-vd multiply-accumulate.
    if cap_riscv_is_tied_vd(m) and n >= 1 \
            and out.operands[0].kind == OP_REG:
        out.operands[0].access |= ACC_READ | ACC_WRITE
    # Zacas / CORE-V tied-rd.
    if cap_riscv_is_tied_rd(m) and n >= 1 \
            and out.operands[0].kind == OP_REG:
        out.operands[0].access |= ACC_READ | ACC_WRITE

    # Unconditionally-masked carry/merge families read v0.
    if cap_riscv_reads_v0_mask(m):
        has_v0 = RC.RISCV_REG_V0 in out.regs_read_id
        if not has_v0:
            for o in out.operands:
                if o.kind == OP_REG and o.reg_id == RC.RISCV_REG_V0 \
                        and (o.access & ACC_READ):
                    has_v0 = True
                    break
        if not has_v0:
            _implicit_add(out.regs_read_id, RC.RISCV_REG_V0)

    # Dynamic rounding mode reads frm.
    if cap_riscv_reads_dynamic_frm(insn):
        if RC.RISCV_REG_FRM not in out.regs_read_id:
            _implicit_add(out.regs_read_id, RC.RISCV_REG_FRM)

    # Vector instructions read the vl/vtype configuration.
    if m and m[0] == "v" and not m.startswith("vsetvl") \
            and cap_riscv_is_vector_encoding(insn):
        if RC.RISCV_REG_VL not in out.regs_read_id \
                and RC.RISCV_REG_VTYPE not in out.regs_read_id:
            _implicit_add(out.regs_read_id, RC.RISCV_REG_VL)
            _implicit_add(out.regs_read_id, RC.RISCV_REG_VTYPE)


MIPS_OP_REG = MC.MIPS_OP_REG
MIPS_OP_IMM = MC.MIPS_OP_IMM
MIPS_OP_MEM = MC.MIPS_OP_MEM


def fill_mips(isa, insn, out):
    ops = insn.operands[:MAX_OPS]
    m = insn.mnemonic

    for cop in ops:
        op = Operand()
        op.access = getattr(cop, "access", 0)
        t = cop.type
        if t == MIPS_OP_REG:
            op.kind = OP_REG
            op.reg_id = cop.reg
        elif t == MIPS_OP_IMM:
            op.kind = OP_IMM
            op.imm = cop.imm
        elif t == MIPS_OP_MEM:
            op.kind = OP_MEM
            op.reg_id = cop.mem.base
            op.imm = cop.mem.disp
        else:
            op.kind = OP_INVALID
        out.operands.append(op)

    n = len(out.operands)

    # MSA / unaligned MEM access==0: infer from the data register.
    for mem in out.operands:
        if mem.kind != OP_MEM or mem.access != 0:
            continue
        for reg in out.operands:
            if reg.kind != OP_REG or reg.access == 0:
                continue
            mem.access = ACC_READ if (reg.access & ACC_WRITE) \
                else ACC_WRITE
            break

    # Store-conditional success-bit write-back.
    if insn.id in (MC.MIPS_INS_SC, MC.MIPS_INS_SCD,
                   MC.MIPS_INS_SCE, MC.MIPS_INS_SCWP):
        for op in out.operands:
            if op.kind == OP_REG:
                op.access = ACC_READ | ACC_WRITE
                break

    # LWL/LWR/LDL/LDR partial write.
    if insn.id in (MC.MIPS_INS_LWL, MC.MIPS_INS_LWR,
                   MC.MIPS_INS_LDL, MC.MIPS_INS_LDR):
        for op in out.operands:
            if op.kind == OP_REG:
                op.access = ACC_READ | ACC_WRITE
                break

    # Tied-destination family.
    if cap_mips_is_tied_dst(m):
        for op in out.operands:
            if op.kind == OP_REG:
                op.access |= ACC_READ | ACC_WRITE
                break

    # Accumulator RMW on the named-accumulator forms.
    if cap_mips_is_acc_rmw(m):
        for op in out.operands:
            if op.kind == OP_REG and cap_mips_is_acc_reg(op.reg_id):
                op.access |= ACC_READ | ACC_WRITE
                break

    # MTHC1 preserves the low half: the written FP reg is also read.
    if insn.id == MC.MIPS_INS_MTHC1:
        for op in out.operands:
            if op.kind == OP_REG and (op.access & ACC_WRITE):
                op.access |= ACC_READ
                break

    # DSPControl on the four instructions that exist to move it.
    if insn.id == MC.MIPS_INS_RDDSP:
        _implicit_add(out.regs_read_id, MC.MIPS_REG_DSPCCOND)
    elif insn.id == MC.MIPS_INS_WRDSP:
        _implicit_add(out.regs_write_id, MC.MIPS_REG_DSPCCOND)
    elif insn.id in (MC.MIPS_INS_BPOSGE32, MC.MIPS_INS_MTHLIP):
        _implicit_add(out.regs_read_id, MC.MIPS_REG_DSPPOS)

    # CTCMSA writes the MSA control register its first operand names.
    if insn.id == MC.MIPS_INS_CTCMSA and n >= 1 \
            and out.operands[0].kind == OP_REG:
        out.operands[0].access = ACC_WRITE

    # Register-indexed FP / DSP loads: fold the pair into a MEM operand.
    if insn.id in (MC.MIPS_INS_LWXC1, MC.MIPS_INS_LDXC1,
                   MC.MIPS_INS_LUXC1, MC.MIPS_INS_SWXC1,
                   MC.MIPS_INS_SDXC1, MC.MIPS_INS_SUXC1,
                   MC.MIPS_INS_LWX, MC.MIPS_INS_LHX,
                   MC.MIPS_INS_LBUX) \
            and n == 3 \
            and out.operands[0].kind == OP_REG \
            and out.operands[1].kind == OP_REG \
            and out.operands[2].kind == OP_REG:
        index_id = out.operands[1].reg_id
        base_id = out.operands[2].reg_id
        mem = out.operands[1]
        mem.kind = OP_MEM
        mem.access = ACC_READ \
            if (out.operands[0].access & ACC_WRITE) else ACC_WRITE
        mem.reg_id = base_id
        mem.index_id = index_id
        mem.imm = 0
        del out.operands[2]
        n = 2

    # CTC1/CFC1 COP0-bank misnaming -> FCR bank.
    if m in ("ctc1", "cfc1"):
        for op in out.operands:
            if op.kind == OP_REG \
                    and MC.MIPS_REG_COP00 <= op.reg_id <= MC.MIPS_REG_COP09:
                op.reg_id = MC.MIPS_REG_FCR0 \
                    + (op.reg_id - MC.MIPS_REG_COP00)

    # FP compare/branch implicit $fcc0 + phantom $at write.
    is_fp_cmp = m.startswith("c.")
    is_fp_br = insn.id in (MC.MIPS_INS_BC1T, MC.MIPS_INS_BC1F,
                           MC.MIPS_INS_BC1TL, MC.MIPS_INS_BC1FL)
    names_cc = any(o.kind == OP_REG
                   and MC.MIPS_REG_FCC0 <= o.reg_id <= MC.MIPS_REG_FCC7
                   for o in out.operands)
    if is_fp_br:
        out.regs_write_id = [r for r in out.regs_write_id
                             if r != MC.MIPS_REG_AT]
    if (is_fp_cmp or is_fp_br) and not names_cc:
        if is_fp_cmp:
            _implicit_add(out.regs_write_id, MC.MIPS_REG_FCC0)
        else:
            _implicit_add(out.regs_read_id, MC.MIPS_REG_FCC0)


# ----------------------------------------------------------------------
# The boundary driver: cap_disas_raw_detail(), python form.
# ----------------------------------------------------------------------

def raw_detail(isa, data):
    """Decode one encoding.  None => Capstone declined (CAPSTONE-BLANK)."""
    insns = list(isa.md.disasm(data, DECODE_PC, count=1))
    if not insns:
        return None
    insn = insns[0]
    # Whole-buffer keying, as the retired referee: the encoding IS the
    # instruction; trailing bytes mean the corpus key and the decode
    # disagree about instruction length, and the row is still written for
    # the decoded instruction exactly as cs_disasm_iter behaved.
    out = Info()
    out.mnemonic = insn.mnemonic
    out.op_str = insn.op_str
    out.insn_id = insn.id
    try:
        out.regs_read_id = [r for r in insn.regs_read
                            if 0 < r < isa.reg_ending][:MAX_IREGS]
        out.regs_write_id = [r for r in insn.regs_write
                             if 0 < r < isa.reg_ending][:MAX_IREGS]
    except capstone.CsError:
        out.regs_read_id = []
        out.regs_write_id = []

    if isa.arch == capstone.CS_ARCH_X86:
        fill_x86(isa, insn, out)
    elif isa.arch == capstone.CS_ARCH_AARCH64:
        fill_arm64(isa, insn, out)
    elif isa.arch == capstone.CS_ARCH_RISCV:
        fill_riscv(isa, insn, out)
    elif isa.arch == capstone.CS_ARCH_MIPS:
        fill_mips(isa, insn, out)
    return out


# ----------------------------------------------------------------------
# The operand walk: decode_detail_to_generic(), register-set half.
# ----------------------------------------------------------------------

# Opcode classes whose first register operand is NOT the fallback
# destination (champsim_tracer_decode.cc opcode_first_is_dst).
_NOT_FIRST_DST = {"GEN_OP_STORE", "GEN_OP_CMP", "GEN_OP_BRANCH",
                  "GEN_OP_RET", "GEN_OP_SYSCALL", "GEN_OP_NOP",
                  "GEN_OP_TEST"}


class Fields:
    __slots__ = ("opcode", "src", "dst")

    def __init__(self):
        self.opcode = "GEN_OP_UNKNOWN"
        self.src = []               # generic names, insertion order
        self.dst = []


def _add(lst, names, cap):
    for nm in names:
        if nm in lst:
            continue
        if len(lst) >= cap:
            return
        lst.append(nm)


def refine_alias_fields(isa, info, f):
    """The register half of refine_alias_fields(): only the RISC-V arm
    edits the register sets (the aarch64/mips arms move branch fields
    these columns do not carry)."""
    if isa.key != "riscv":
        return
    m = info.mnemonic
    if m in ("c.addi", "c.slli64", "c.srli64", "c.srai64"):
        if not f.dst:
            f.src = []
        return
    aliased_link = False
    is_call = False
    is_ret = False
    if m in ("jal", "c_jal", "call", "tail"):
        aliased_link = True
        is_call = True
    elif m in ("jalr", "c_jalr"):
        aliased_link = True
        is_call = True
    elif m == "ret":
        aliased_link = True
        is_ret = True
    if not aliased_link:
        return
    if is_call and not f.dst:
        _add(f.dst, ("REG_LR",), MAX_DST_REGS)
    elif is_ret and not f.src:
        _add(f.src, ("REG_LR",), MAX_SRC_REGS)


# ----------------------------------------------------------------------
# The AArch64 post-classification .refine hooks.
#
# One Capstone AArch64 instruction id covers several operand encodings,
# so four refiners in champsim_tracer_mnemonics_aarch64.h repaired the
# static class from the decoded operands.  They ran AFTER the operand
# walk and AFTER refine_alias_fields, and they moved the OPCODE these
# corpora publish -- so the referee reproduces them, or its opcode
# column would be the pre-refinement row under a post-refinement name.
#
# The assignment is per instruction id, exactly as the retired table
# named it (a blanket application would be wrong: refine_arm64_cmp_alias
# on a plain `add xzr, ...` would read the zero destination as the CMP
# alias shape, which is why only the flag-setting ids carried it).
# ----------------------------------------------------------------------

_A64_REFINE_LDST_NAMES = (
    "LDARB LDARH LDAR LDNP LDP LDPSW LDRB LDR LDRH LDRSB LDRSH LDRSW "
    "LDTRB LDTRH LDTRSB LDTRSH LDTRSW LDTR LDURB LDUR LDURH LDURSB "
    "LDURSH LDURSW STLRB STLRH STLR STNP STP STRB STR STRH STTRB STTRH "
    "STTR STURB STUR STURH").split()

_A64_REFINE_FPVEC_NAMES = (
    "BFADD BFMLALB BFMLALT BFMLAL BFMLA BFMLSLB BFMLSLT BFMLSL BFMLS "
    "BFMMLA BFMOPA BFMOPS BFMUL BFSUB FABS FADDA FADD FADDP FADDQV "
    "FADDV FCADD FCMLA FCSEL FDIV FDIVR FDUP FEXPA FLOGB FMA16 FMA32 "
    "FMA64 FMADD FMAD FMAX FMAXNM FMAXNMP FMAXNMQV FMAXNMV FMAXP "
    "FMAXQV FMAXV FMLAL2 FMLALB FMLALLBB FMLALLBT FMLALLTB FMLALLTT "
    "FMLALL FMLALT FMLAL FMLA FMLSL2 FMLSLB FMLSLT FMLSL FMLS FMMLA "
    "FMOPA FMOPS FMOV FMS16 FMS32 FMS64 FMSB FMSUB FMUL FMULX FNEG "
    "FNMADD FNMAD FNMLA FNMLS FNMSB FNMSUB FNMUL FRECPE FRECPS FRECPX "
    "FRINT32X FRINT32Z FRINT64X FRINT64Z FRINTA FRINTI FRINTM FRINTN "
    "FRINTP FRINTX FRINTZ FRSQRTE FRSQRTS FSCALE FSQRT FSUB FSUBR "
    "FTMAD FTSMUL FTSSEL").split()

_A64_REFINE_CMP_NAMES = "ADDS ANDS SUBS".split()
_A64_REFINE_SYSOP_NAMES = "SYSL SYS".split()

_FP_VEC_PROMOTE = {
    "GEN_OP_FP_ADD":  "GEN_OP_VEC_ADD",
    "GEN_OP_FP_SUB":  "GEN_OP_VEC_SUB",
    "GEN_OP_FP_MUL":  "GEN_OP_VEC_MUL",
    "GEN_OP_FP_DIV":  "GEN_OP_VEC_DIV",
    "GEN_OP_FP_SQRT": "GEN_OP_VEC_SQRT",
    "GEN_OP_FP_MADD": "GEN_OP_VEC_MADD",
    "GEN_OP_FP_MSUB": "GEN_OP_VEC_MSUB",
    "GEN_OP_FP_MOV":  "GEN_OP_VEC_MOV",
}


def _refine_a64_ldst_access(info, f):
    """A load or store that also writes a register is a writeback form:
    the address update is the substantial operation, so the class is the
    add, not the memory access."""
    if not info.regs_write_id:
        return
    for op in info.operands:
        if op.kind == OP_MEM:
            f.opcode = "GEN_OP_INT_ADD"
            return


def _refine_a64_fp_vec(info, f):
    """One insn id covers the scalar-FP and the packed-vector form; the
    table names the scalar op, and a real vector arrangement promotes it
    to the VEC_* twin."""
    promoted = _FP_VEC_PROMOTE.get(f.opcode)
    if promoted is None:
        return
    for op in info.operands:
        if op.kind == OP_REG and op.lane_bytes != 0:
            f.opcode = promoted
            return


def _refine_a64_cmp_alias(info, f):
    """CMP / CMN / TST are SUBS / ADDS / ANDS writing XZR.  A flag-only
    destination set is the alias; any real register destination is the
    canonical arithmetic form and keeps its class."""
    for d in f.dst:
        if d not in (SYSREG_FLAGS, "REG_ZERO"):
            return
    if f.opcode in ("GEN_OP_INT_SUB", "GEN_OP_INT_ADD"):
        f.opcode = "GEN_OP_CMP"
    elif f.opcode == "GEN_OP_AND":
        f.opcode = "GEN_OP_TEST"
    else:
        return
    f.dst = [d for d in f.dst if d != "REG_ZERO"]


def _refine_a64_sysop(info, f):
    """SYS is one insn id for the whole alias space.  DC ZVA / GZVA is
    the one member that moves architectural data -- the boundary hands
    it a written memory operand, and that is the discriminator.  TLBI is
    TLB maintenance; AT writes PAR_EL1 and orders like a barrier."""
    for op in info.operands:
        if op.kind == OP_MEM and (op.access & ACC_WRITE):
            f.opcode = "GEN_OP_STORE"
            return
    if info.mnemonic == "tlbi":
        f.opcode = "GEN_OP_TLB_FLUSH"
    elif info.mnemonic == "at":
        f.opcode = "GEN_OP_FENCE"


def _build_a64_refine_map():
    m = {}
    for names, fn in ((_A64_REFINE_LDST_NAMES, _refine_a64_ldst_access),
                      (_A64_REFINE_FPVEC_NAMES, _refine_a64_fp_vec),
                      (_A64_REFINE_CMP_NAMES, _refine_a64_cmp_alias),
                      (_A64_REFINE_SYSOP_NAMES, _refine_a64_sysop)):
        for nm in names:
            v = _ac("AARCH64_INS_" + nm)
            if v is not None:
                m[v] = fn
    return m


_A64_REFINE = _build_a64_refine_map()


def walk(isa, info):
    """decode_detail_to_generic(), the part that feeds these corpora.
    None => unknown mnemonic (no rows, as the in-process arm behaved)."""
    if not info.mnemonic:
        return None

    entry = isa.classify_id(info.insn_id)
    opcode = entry.op if entry else "GEN_OP_UNKNOWN"
    if opcode == "GEN_OP_UNKNOWN":
        return None

    f = Fields()
    f.opcode = opcode

    have_access = any(op.access != 0 for op in info.operands)

    dst_reg_idx = None
    if not have_access and opcode not in _NOT_FIRST_DST:
        for i, op in enumerate(info.operands):
            if op.kind != OP_REG:
                continue
            dst_reg_idx = i
            if isa.key != "x86":
                break               # dest-first ISAs: first REG operand
            # AT&T: last REG operand wins — keep scanning.

    for i, op in enumerate(info.operands):
        if op.kind == OP_REG:
            if have_access:
                if op.access & ACC_READ:
                    _add(f.src, isa.reg_names(op.reg_id), MAX_SRC_REGS)
                if op.access & ACC_WRITE:
                    _add(f.dst, isa.reg_names(op.reg_id), MAX_DST_REGS)
            else:
                if i == dst_reg_idx:
                    _add(f.dst, isa.reg_names(op.reg_id), MAX_DST_REGS)
                else:
                    _add(f.src, isa.reg_names(op.reg_id), MAX_SRC_REGS)
        elif op.kind == OP_SYSREG:
            gen = op.sysreg_gen
            if not gen:
                continue
            if op.access & ACC_READ:
                _add(f.src, (gen,), MAX_SRC_REGS)
            if op.access & ACC_WRITE:
                _add(f.dst, (gen,), MAX_DST_REGS)
        elif op.kind == OP_MEM:
            _add(f.src, isa.reg_names(op.reg_id), MAX_SRC_REGS)
            _add(f.src, isa.reg_names(op.index_id), MAX_SRC_REGS)
            _add(f.src, isa.reg_names(op.segment_id), MAX_SRC_REGS)

    # include_implicit_regs is true on all four ISAs.
    for r in info.regs_read_id:
        _add(f.src, isa.reg_names(r), MAX_SRC_REGS)
    for r in info.regs_write_id:
        _add(f.dst, isa.reg_names(r), MAX_DST_REGS)

    refine_alias_fields(isa, info, f)

    if isa.key == "aarch64":
        fn = _A64_REFINE.get(info.insn_id)
        if fn is not None:
            fn(info, f)
    return f


# ----------------------------------------------------------------------
# Corpus writers (the retired capture's emit_gen_set / cst_capture_insn
# row shapes, byte for byte).
# ----------------------------------------------------------------------

def gen_set_row(isa_name, enc, side, dir_, names):
    nraw = len(names)
    labels = sorted(names)[:SET_NAMES_MAX]
    uniq = []
    for nm in labels:
        if not uniq or uniq[-1] != nm:
            uniq.append(nm)
    joined = ",".join(uniq) if uniq else "-"
    more = ",+MORE" if nraw > len(labels) else ""
    return "%s\t%s\t%c\t%c\t%u\t%u\t%s%s\n" % (
        isa_name, enc, side, dir_, nraw, len(uniq), joined, more)


# ----------------------------------------------------------------------
# Input reading (the retired referee's read_input / check_input).
# ----------------------------------------------------------------------

class Input:
    def __init__(self):
        self.stamp = ""
        self.encodings = []
        self.rows = 0
        self.other_isa = 0


def read_input(path, isa_name):
    inp = Input()
    seen = set()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("#so "):
                inp.stamp = line[4:]
                continue
            if line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            if parts[0] != isa_name:
                inp.other_isa += 1
                continue
            inp.rows += 1
            enc = parts[1]
            if enc not in seen:
                seen.add(enc)
                inp.encodings.append(enc)
    return inp


def check_input(inp, path, isa_name):
    if not inp.stamp:
        return ("%s: no #so stamp.  An unstamped corpus cannot say which "
                "build its encodings came from, and a join across builds "
                "is the frozen-arm failure." % path)
    if inp.rows == 0:
        msg = "%s: no data rows for isa %s" % (path, isa_name)
        if inp.other_isa:
            msg += (" (but %d rows for another ISA -- wrong --isa, or "
                    "wrong corpus)" % inp.other_isa)
        return msg
    if not inp.encodings:
        return "%s: rows but no encodings" % path
    return None


def unhex(s):
    if not s or len(s) % 2 or len(s) > 2 * 64:
        return None
    try:
        return bytes.fromhex(s)
    except ValueError:
        return None


# ----------------------------------------------------------------------
# Version parity.
# ----------------------------------------------------------------------

def bindings_version():
    try:
        import importlib.metadata as md
        dist = md.version("capstone")
    except Exception:
        dist = getattr(capstone, "__version__", "unknown")
    major, minor, _combined = capstone.cs_version()
    return dist, major, minor


def check_version():
    dist, major, minor = bindings_version()
    if (major, minor) != (6, 0):
        sys.stderr.write(
            "cst_referee: the python capstone bindings are %s "
            "(cs_version %d.%d), but the workaround catalogue this "
            "referee carries was written against the 6.0.0-Alpha7 line.  "
            "A comparison run against a different Capstone turns version "
            "differences into decoder disagreements; refusing.\n"
            % (dist, major, minor))
        return None
    return dist, major, minor


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------

def run(isa_name, in_path, out_dir):
    ver = check_version()
    if ver is None:
        return 3
    dist, major, minor = ver

    try:
        isa = Isa(isa_name)
    except KeyError:
        sys.stderr.write("cst_referee: no tracer tables for isa %s\n"
                         % isa_name)
        return 4

    try:
        inp = read_input(in_path, isa_name)
    except OSError as e:
        sys.stderr.write("cst_referee: %s: %s\n" % (in_path, e.strerror))
        return 4
    err = check_input(inp, in_path, isa_name)
    if err:
        sys.stderr.write("cst_referee: %s\n" % err)
        return 4

    note = ("#referee capstone_bindings=%s headers=%d.%d runtime=%d.%d "
            "source=%s" % (dist, major, minor, major, minor, in_path))

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {}
    for stem in ("gen_c", "opc", "srcenc", "mech"):
        p = out_dir / ("%s_%s.tsv" % (stem, isa_name))
        f = open(p, "w", encoding="utf-8")
        f.write("#so %s\n%s\n" % (inp.stamp, note))
        files[stem] = f
    files["gen_c"].write("#isa\tencoding\tside\tdir\tnraw\tnuniq\tnames\n")
    files["opc"].write("#isa\tencoding\tmnem\topcode\n")
    files["srcenc"].write("#isa\tencoding\tmnem\tsrc\n")
    files["mech"].write("#isa\tencoding\tmech\n")

    decoded = 0
    boundary_refused = 0
    unhexable = 0
    unclassified = 0
    seen_gen = set()

    for enc in inp.encodings:
        data = unhex(enc)
        if data is None:
            unhexable += 1
            continue
        info = raw_detail(isa, data)
        if info is None:
            boundary_refused += 1
            continue
        f = walk(isa, info)
        if f is None:
            # Unknown mnemonic: the in-process arm wrote no rows here
            # (decode_detail_to_generic returned before the capture
            # call), and neither does this one.
            unclassified += 1
            decoded += 1
            continue
        decoded += 1
        mnem = info.mnemonic if info.mnemonic else "-"
        files["srcenc"].write("%s\t%s\t%s\t%s\n" % (
            isa_name, enc, mnem, ",".join(f.src) if f.src else "-"))
        files["opc"].write("%s\t%s\t%s\t%s\n" % (
            isa_name, enc, mnem, f.opcode))
        for dir_, names in (("r", f.src), ("w", f.dst)):
            row = gen_set_row(isa_name, enc, "c", dir_, names)
            if row not in seen_gen:
                seen_gen.add(row)
                files["gen_c"].write(row)
        files["mech"].write("%s\t%s\t%s\n" % (
            isa_name, enc, "walked" if f.src else "walked-empty"))

    for f in files.values():
        f.close()

    print("cst_referee %s: %d rows -> %d distinct encodings; "
          "decoded %d, capstone-blank %d, unclassified %d, "
          "unparsable keys %d"
          % (isa_name, inp.rows, len(inp.encodings), decoded,
             boundary_refused, unclassified, unhexable))
    print("  %s" % note)
    print("  stamp carried from the input: %s" % inp.stamp)

    if decoded == 0:
        sys.stderr.write(
            "cst_referee: %d encodings and not one decoded.  A Capstone "
            "column with no rows is the failure this tool exists to end; "
            "refusing to call that a result.\n" % len(inp.encodings))
        return 6
    if unhexable:
        sys.stderr.write("cst_referee: %d key(s) were not hex bytes and "
                         "were not scored.\n" % unhexable)
        return 7
    return 0


# ----------------------------------------------------------------------
# Selftest: the retired referee's arms, plus a walk-content arm per ISA.
# ----------------------------------------------------------------------

def run_selftest():
    fail = 0
    ran = 0
    if check_version() is None:
        print("FAIL version parity")
        return 1
    ran += 1
    print("ok   version parity")

    for name in ("x86_64", "aarch64", "riscv64", "mipsel"):
        ran += 1
        try:
            Isa(name)
            print("ok   init %s" % name)
        except Exception as e:                      # noqa: BLE001
            print("FAIL init %s: %s" % (name, e))
            fail += 1

    ran += 1
    try:
        Isa("sparc64")
        print("FAIL an unknown ISA initialised")
        fail += 1
    except KeyError:
        print("ok   unknown isa refused")

    cases = [
        # (isa, enc, decodes, expected mnem or None, expected src or None,
        #  expected dst or None)
        ("x86_64", "4889e5", True, "movq", ["REG_SP"], ["REG_FP_REG"]),
        # The banked in-tree referee's own rows for retq: implicit
        # rsp+ss reads, rip+rsp writes.
        ("x86_64", "c3", True, "retq", ["REG_SP", "REG_SEG5"],
         ["REG_IP", "REG_SP"]),
        ("aarch64", "e00301aa", True, None, ["REG_GPR1"], ["REG_GPR0"]),
        ("riscv64", "93000000", True, None, None, None),
        ("mipsel", "21100000", True, None, ["REG_ZERO"], ["REG_GPR2"]),
        ("aarch64", "00000000", True, "udf", None, None),
        ("riscv64", "ffffffff", False, None, None, None),
        # The aliased RET carries its restored x30 read.
        ("aarch64", "c0035fd6", True, "ret", ["REG_LR"], None),
        # riscv aliased jal writes the hidden link register.
        ("riscv64", "ef000000", True, None, None, ["REG_LR"]),
    ]
    isas = {}
    for isa_name, enc, expect_ok, expect_mnem, expect_src, expect_dst \
            in cases:
        ran += 1
        isa = isas.setdefault(isa_name, Isa(isa_name))
        data = unhex(enc)
        info = raw_detail(isa, data)
        ok = info is not None
        if ok != expect_ok:
            print("FAIL %s %s: boundary %s, expected %s"
                  % (isa_name, enc,
                     "decoded" if ok else "declined",
                     "decoded" if expect_ok else "declined"))
            fail += 1
            continue
        if not ok:
            print("ok   %s %s declined at the boundary" % (isa_name, enc))
            continue
        if expect_mnem and info.mnemonic != expect_mnem:
            print("FAIL %s %s: mnemonic %s, expected %s"
                  % (isa_name, enc, info.mnemonic, expect_mnem))
            fail += 1
            continue
        f = walk(isa, info)
        if f is None:
            print("FAIL %s %s: the walk refused" % (isa_name, enc))
            fail += 1
            continue
        if expect_src is not None and sorted(f.src) != sorted(expect_src):
            print("FAIL %s %s: src %s, expected %s"
                  % (isa_name, enc, f.src, expect_src))
            fail += 1
            continue
        if expect_dst is not None and sorted(f.dst) != sorted(expect_dst):
            print("FAIL %s %s: dst %s, expected %s"
                  % (isa_name, enc, f.dst, expect_dst))
            fail += 1
            continue
        print("ok   %s %s -> %s %s src=%s dst=%s"
              % (isa_name, enc, info.mnemonic, f.opcode,
                 ",".join(f.src) or "-", ",".join(f.dst) or "-"))

    for bad in ("4889e", "zz", ""):
        ran += 1
        if unhex(bad) is not None:
            print("FAIL unhex accepted \"%s\"" % bad)
            fail += 1
        else:
            print("ok   unhex refused \"%s\"" % bad)

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "corpus.tsv"
        p.write_text("#so plugin=aa emulator=bb\n#isa\tencoding\n"
                     "x86_64\t4889e5\tmov\n")
        for isa_name, expect_ok, what in (
                ("x86_64", True, "a matching corpus is accepted"),
                ("mipsel", False, "a corpus for another ISA is refused")):
            ran += 1
            inp = read_input(p, isa_name)
            ok = check_input(inp, str(p), isa_name) is None
            if ok != expect_ok:
                print("FAIL %s" % what)
                fail += 1
            else:
                print("ok   %s" % what)
        p.write_text("#isa\tencoding\nx86_64\t4889e5\n")
        ran += 1
        inp = read_input(p, "x86_64")
        if check_input(inp, str(p), "x86_64") is None:
            print("FAIL an unstamped corpus was accepted")
            fail += 1
        else:
            print("ok   unstamped corpus refused")
        p.write_text("#so plugin=aa emulator=bb\n#isa\tencoding\n")
        ran += 1
        inp = read_input(p, "x86_64")
        if check_input(inp, str(p), "x86_64") is None:
            print("FAIL an empty corpus was accepted")
            fail += 1
        else:
            print("ok   empty corpus refused")

    ran += 1
    try:
        read_input("/nonexistent/cst_referee", "x86_64")
        print("FAIL a missing corpus was accepted")
        fail += 1
    except OSError:
        print("ok   missing corpus refused")

    print("\ncst_referee selftest: %d arms, %d failure(s)" % (ran, fail))
    if ran < 20:
        print("FAIL the selftest itself ran only %d arms" % ran)
        return 1
    return 1 if fail else 0


def main():
    ap = argparse.ArgumentParser(
        description="the external referee: the Capstone side of the "
                    "tracer's two-decoder comparison, produced offline "
                    "through the python capstone bindings")
    ap.add_argument("--isa",
                    choices=["x86_64", "aarch64", "riscv64", "mipsel"])
    ap.add_argument("--in", dest="in_path", metavar="CORPUS",
                    help="a QEMU-side capture corpus; column 1 is the ISA "
                         "and column 2 the encoding")
    ap.add_argument("--out-dir", help="where the Capstone-side corpora "
                                      "are written")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return run_selftest()
    if not args.isa or not args.in_path or not args.out_dir:
        ap.print_usage(sys.stderr)
        return 2
    return run(args.isa, args.in_path, args.out_dir)


if __name__ == "__main__":
    sys.exit(main())
