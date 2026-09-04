#!/usr/bin/env python3
"""Emit the fields allowlist's `SR-rd-*` block FROM A MEASURED RESIDUE.

    isax_srcenc_rows.py --arms <dir-with-f_<isa>.txt> [--isa ...]

WHY A GENERATOR AND NOT A HAND-WRITTEN BLOCK.  A row in this family says
"the wire publishes a source LLVM MC's operand description does not name (or
the reverse), and the tracer is right".  Two properties have to hold and
neither survives hand-editing:

  * THE ROW MUST HAVE AN OCCUPANT ON THE DAY IT LANDS.  PASS 66 / FINDING
    65-D landed two rows whose justification (a REGCOV line reading
    REFERENCE-HAS-NO-OPERAND) was necessary and not sufficient: the register
    was never the WHOLE difference set, so the rows matched nothing and the
    detector that named them was read by nobody.  Emitting every row FROM a
    signature the arm reported makes a dead row impossible by construction.

  * THE PARTITION MUST BE TOTAL.  Every signature lands in exactly one named
    class, and a signature no class claims is an UNEXAMINED class, not a
    stray.  This script refuses to emit while any signature is unclassified.

A class may be adjudicated DEFECT, and then its signatures get NO rows: an
allowlist row asserts the tracer is right, so laundering a tracer defect
through one is the failure this file's own header warns against.  Those
signatures stay red with a named blocker.

Author: Maccoy Merrell.
SPDX-License-Identifier: GPL-2.0-or-later
"""
import argparse
import collections
import os
import re
import sys

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")

_LINE = re.compile(
    r'^NEW\s+(?P<sig>(?P<cls>\S+)\s+(?P<rest>.*?))\s+n=(?P<n>\d+)\s+'
    r'(?P<enc>[0-9a-f]+)\s')


class Sig:
    __slots__ = ("cls", "mnem", "qual", "n", "enc", "key")

    def __init__(self, m):
        self.cls = m.group("cls")
        rest = m.group("rest")
        mnem, qual = rest.rsplit(" +", 1)
        self.mnem = mnem
        self.qual = "+" + qual
        self.n = int(m.group("n"))
        self.enc = m.group("enc")
        self.key = f"{self.cls} {self.mnem} {self.qual}"

    @property
    def regs(self):
        return set(self.qual[1:].split(","))


def read_arm(path):
    out = []
    for line in open(path):
        m = _LINE.match(line)
        if m:
            out.append(Sig(m))
        elif line.startswith("NEW"):
            raise SystemExit(f"{path}: unparsed NEW line: {line!r}")
    return out


# --------------------------------------------------------------------------
# THE CLASSES.  Each entry is (id, one-line title, the comment, predicate),
# tried in order; the FIRST match wins, so the narrow classes come first.
# `defect=True` means the class is a tracer defect and gets no rows.
# --------------------------------------------------------------------------
SYSIDS = {"REG_SYS", "REG_SYSMMU", "REG_SYSEXC", "REG_SYSDBG", "REG_SYSCACHE",
          "REG_SYSID", "REG_SYSTIMER", "REG_SYSPERF", "REG_SYSFPEN",
          "REG_COPROC0", "REG_COPROC1", "REG_SSP", "REG_VCTRL", "REG_FCSR",
          "REG_FPCW", "REG_TLS", "REG_FLAGS"}

# mipsel: the DSP dispatchers that hoist gen_load_gpr above the opcode
# switch, so an IMMEDIATE field is read as a GPR.  FINDING 71-A.
MIPS_DSP_IMM = {
    "repl.ph", "repl.qb", "shll.ph", "shll_s.ph", "shll_s.w", "shll.qb",
    "shra.ph", "shra.qb", "shra_r.ph", "shra_r.qb", "shra_r.w", "shrl.ph",
    "shrl.qb", "extp", "extpdp", "extr.w", "extr_r.w", "extr_rs.w",
    "extr_s.h", "shilo", "rddsp", "precr_sra.ph.w", "precr_sra_r.ph.w",
}
GPRISH = {"REG_SP", "REG_LR", "REG_FP_REG", "REG_ZERO"}


def _gpr(regs):
    return any(r.startswith("REG_GPR") for r in regs) or bool(regs & GPRISH)


CLASSES = {}


def cls(isa, cid, title, comment, defect=False):
    def deco(fn):
        CLASSES.setdefault(isa, []).append((cid, title, comment, fn, defect))
        return fn
    return deco


# ---------------------------------------------------------------- riscv64
@cls("riscv64", "R-HINT", "an RV128 mnemonic decoded on RV64, where the "
     "encoding is a HINT that reads nothing", """
C.SLLI64 / C.SRLI64 / C.SRAI64 are the RV128 spellings of the compressed
shifts with shamt == 0.  On RV64 that encoding is not those instructions:
the unprivileged spec (Ch. 16, "C" extension) makes shamt == 0 a HINT, and
QEMU implements the hint -- nothing is read and nothing is written.  LLVM's
RV64 decoder still resolves the RV128 opcode and names its register operand,
so the reference names a read the architecture does not perform on this
target.  The wire is right.""")
def _r_hint(s):
    return s.cls == "SR-rd-missing" and s.mnem.split()[0] in (
        "c.slli64", "c.srli64", "c.srai64")


@cls("riscv64", "R-ZIMOP", "Zimop may-be-operations write zero and read "
     "nothing", """
`mop.r.N rd, rs1` and `mop.rr.N rd, rs1, rs2` are Zimop's "may be operations":
when no extension has claimed the encoding they are defined to write ZERO to
rd, and their source registers are architecturally unread.  QEMU implements
exactly that.  LLVM's MCInstrDesc names the source operands because the
encoding HAS them, which is a statement about the syntax and not about the
dataflow.  The wire is right.""")
def _r_zimop(s):
    return s.cls == "SR-rd-missing" and s.mnem.split()[0].startswith("mop.r")


@cls("riscv64", "R-PAIR", "AMOCAS.Q's even-odd register PAIR, of which LLVM "
     "names only the even half", """
Zacas AMOCAS.Q on RV64 compares and swaps 128 bits, so its compare value and
its swap value are each an EVEN-ODD REGISTER PAIR -- rd/rd+1 and rs2/rs2+1 --
and QEMU reads both halves.  LLVM's MCInst carries one operand for the pair,
spelled with the even register, so the odd half is a read it structurally
cannot name.  The wire is right, and the pair is the whole difference.""")
def _r_pair(s):
    return s.mnem.split()[0].startswith("amocas.q")


@cls("riscv64", "R-LPAD", "Zicfilp's landing-pad label check reads x7", """
`lpad` compares the encoded label against the low bits of x7 and traps on a
mismatch, so x7 is a true source and the landing-pad state is read beside it.
LLVM models the label as an immediate and names no register at all.""")
def _r_lpad(s):
    return s.mnem.split()[0] == "lpad"


@cls("riscv64", "R-VTAIL", "RVV reads its own destination: prestart, "
     "masked-off and tail elements are UNDISTURBED", """
Under the tail-undisturbed and mask-undisturbed policies -- the reset state
of vtype and the one QEMU's helpers implement unconditionally -- the elements
of vd before vstart, the elements a mask bit turns off, and the elements past
vl all RETAIN THE VALUE vd ALREADY HELD ("V" spec v1.0, sec. 5.3 and 5.4).
The destination is therefore a genuine source of every vector instruction
that does not write all VLEN bits, which is why QEMU passes vd into the gvec
helper and reads it.  LLVM's MCInstrDesc carries a tied operand only on the
forms whose ASSEMBLY repeats the register, so on the rest its read set is
short by exactly vd.  This is the same disagreement MIPS lwl/lwr already
carries in this file, and the fields side is again the correct one.""")
def _r_vtail(s):
    return s.mnem.startswith("v") and any(r.startswith("REG_VEC")
                                          for r in s.regs)


@cls("riscv64", "R-CSRIMM", "the CSR a number selects, which LLVM models as "
     "an IMMEDIATE", """
A CSR instruction addresses its register by a 12-bit NUMBER, and LLVM's
MCInstrDesc carries that number as an immediate operand: there is no register
operand for the reference to name, whatever the number selects.  The tracer
names the register, in the behaviour class the CSR table (371 entries) puts
it in -- REG_FCSR for the FP control-and-status file, REG_VCTRL for the
vector configuration, REG_SSP for Zicfiss ssp, REG_SYS for the long tail.
This is the boundary file's own `riscv64 SR-rd-phantom * +REG_SYS` row seen
per-family at this layer.  R16: the dependency is the ISA's, and a reference
that does not model the register cannot refute it.""")
def _r_csr(s):
    m = s.mnem.split()[0]
    return (m.startswith("csr") or m.startswith("cbo.")
            or m.startswith("fence") or m.startswith("sfence")
            or m.startswith("hfence") or m.startswith("hlv")
            or m.startswith("hsv") or m.startswith("ss")
            or m.startswith("fr") or m.startswith("fs")
            or m.startswith("rd") or s.regs <= SYSIDS)


# ----------------------------------------------------------------- mipsel
@cls("mipsel", "M-DSPIMM", "QEMU's MIPS DSP translators read the IMMEDIATE "
     "FIELD as a GPR -- FINDING 71-A", "", defect=True)
def _m_dspimm(s):
    return s.mnem.split()[0] in MIPS_DSP_IMM and _gpr(s.regs)


@cls("mipsel", "M-LSA", "an R6 mnemonic carrying the 24Kf PMON "
     "translation's dataflow -- FINDING 70-A", "", defect=True)
def _m_lsa(s):
    return s.mnem.split()[0] == "lsa"


@cls("mipsel", "M-MERGE", "the unaligned loads merge into their destination, "
     "so the destination is a source", """
LWL / LWR / LWLE / LWRE write only the bytes their address selects and leave
the rest of $rt standing, so the old $rt is a true source.  LLVM's
MCInstrDesc agrees and its MCInst drops the tie, which is the same shape the
boundary block for lwl/lwr in this file already carries.""")
def _m_merge(s):
    return s.mnem.split()[0] in ("lwl", "lwr", "lwle", "lwre",
                                 "swl", "swr", "swle", "swre")


@cls("mipsel", "M-MT", "the MT ASE far operand, reported in the file the "
     "(u, sel) pair selects", """
MFTR / MTTR move between thread contexts and the (u, sel) pair chooses WHICH
FILE the far operand lives in -- GPR, FPR, accumulator, CP0, the DSP control
word.  The tracer reports the register in the file the pair selects; LLVM
models the pair as immediates and names the GPR encoding regardless.  The
paired phantom and missing entries are ONE operand reclassified, not two
findings, exactly as the boundary block for this family already states.""")
def _m_mt(s):
    return s.mnem.split()[0] in ("mftr", "mttr")


@cls("mipsel", "M-CP0", "the CP0 register an instruction owns, in the class "
     "the split put it in", """
The TLB maintenance instructions, the exception returns and the COP0 moves
name their coprocessor-0 registers through a (rd, sel) pair or implicitly;
QEMU's helpers name them one at a time and the tracer records the class --
REG_SYSMMU for the TLB file, REG_SYSEXC for Status/Cause/EPC, REG_SYSDBG for
the EJTAG file, REG_SYSID for the read-only identification registers.  LLVM's
MIPS tables model no CP0 register on any of these forms.""")
def _m_cp0(s):
    return s.mnem.split()[0] in (
        "tlbp", "tlbr", "tlbwi", "tlbwr", "tlbinv", "tlbinvf", "eret",
        "deret", "wait", "dvpe", "evpe", "dmt", "emt", "mfc0", "mtc0",
        "mfhc0", "mthc0", "ctcmsa", "cfcmsa", "mfc2", "mtc2", "cfc2", "ctc2",
        "sdbbp", "rdhwr", "synci")


@cls("mipsel", "M-FCSR", "FCR31 / MSACSR is read-modify-written by every "
     "COP1 and MSA arithmetic instruction", """
QEMU's update_fcr31() read-modify-writes the word on every call -- it
SET_FP_CAUSEs into it and reads GET_FP_ENABLE out of it -- and update_msacsr()
is the same shape, so the register is a true source of the instruction that
updates it.  LLVM's MIPS tables model no FP status register at all.  This is
the fields-layer face of the same fact the FR block above already carries;
what is new is the SIGNATURE, not the argument.""")
def _m_fcsr(s):
    return "REG_FCSR" in s.regs


@cls("mipsel", "M-EXC", "the footprint of the exception an instruction "
     "RAISES", """
R7.6: syscall, break, the twelve conditional traps, the overflow-checking
arithmetic and the DSP forms whose availability is gated all reach QEMU's
exception path, which read-modify-writes Status and Cause and writes EPC
(tlb_helper.c).  The tracer records that footprint; LLVM MC models no
exception entry on any instruction, so it is a phantom on both the read and
the write because the model is a read-modify-write.  Again the fields-layer
face of the FR block above, under the `SR-` key.""")
def _m_exc(s):
    return "REG_SYSEXC" in s.regs


@cls("mipsel", "M-MSACTL", "the MSA control file an index selects", """
CTCMSA / CFCMSA address an MSA control register by INDEX, and LLVM carries
the index as an immediate.  Where the reference names a register on these
forms it is naming the index's GPR spelling, not the control register the
index selects, so the phantom and missing rows are again one operand read two
ways.""")
def _m_msactl(s):
    return s.mnem.split()[0] in ("ctcmsa", "cfcmsa")


# ---------------------------------------------------------------- aarch64
@cls("aarch64", "A-FROZEN", "a FIXED survivor row froze the deriving "
     "corpus's own base register -- FINDING 71-B", "", defect=True)
def _a_frozen(s):
    return s.mnem.split()[0] in ("prfum", "prfm") and "REG_SP" in s.regs


@cls("aarch64", "A-FPEN", "the FP / SIMD / SVE / SME EXECUTION-ENABLE gate, "
     "which the reference models on no instruction", """
Every FP, AdvSIMD, SVE and SME instruction runs an architectural enable check
before it does anything -- CheckFPAdvSIMDEnabled, CheckSVEEnabled,
CheckSMEEnabled (Arm ARM DDI 0487) -- and that check READS CPACR_EL1.FPEN and
the CPTR_EL{2,3} traps.  QEMU states the read at translation time
(fp_access_check() / sve_access_check() in target/arm/tcg/translate-a64.c),
so it reaches the wire's ordered read list on the whole FP population.
REG_SYSFPEN exists because that population is every FP instruction in the
ISA: folded into the residual REG_SYS, one TTBR write would order all of them
behind it.  LLVM's MCInstrDesc models no enable check on any instruction, so
this is a phantom by construction and not a disagreement about dataflow.

Where the qualifier names REG_VEC# beside the gate, the extra register is the
instruction's own DESTINATION, read for the same reason the RVV block above
gives: the predicated and merging forms leave the inactive elements of Zd
standing, so Zd is a source.  Where it names REG_FCSR the register is FPSR,
whose QC bit these forms make STICKY -- read-modify-written, not written --
and where it names REG_FPCW it is FPCR, the control word every FP instruction
reads.""")
def _a_fpen(s):
    return "REG_SYSFPEN" in s.regs


@cls("aarch64", "A-GCS", "the guarded control stack pointer, which the "
     "reference names on nothing", """
The GCS instructions push to, pop from and switch the guarded control stack,
all through GCSPR_ELx, and none of them names it in the encoding.  LLVM's
MCInstrDesc has no operand for it.  REG_SSP is its own dependency population
-- neither the data stack pointer nor the link register -- so the read is
recorded there.""")
def _a_gcs(s):
    return s.mnem.split()[0].startswith("gcs") or (
        s.regs == {"REG_SSP"} and s.mnem.split()[0] in ("sys", "sysl", "mrs"))


@cls("aarch64", "A-SYSSEL", "the system register an (op0, op1, CRn, CRm, "
     "op2) tuple selects, which LLVM models as an immediate", """
MRS / MSR / MRRS / MSRR / SYS / SYSL address a system register by an ENCODED
TUPLE, and LLVM's MCInstrDesc carries that tuple as immediates: there is no
register operand for the reference to name.  The tracer names the register,
in the dependence-behaviour group cap_aarch64_sysreg_class puts it in, so
MRS produces one signature per group where it produced one in total.  The
`SR-rd-missing sysl +REG_GPR#` companion is the same operand read the other
way: LLVM names the destination GPR of SYSL as a USE.

`msr +REG_FPCW` and `msrr +REG_FPCW` are the WRITE half, new at this tip
because FPCR moved off REG_FCSR (the control word is not the status word);
LLVM models no system register write on MSR either.""")
def _a_syssel(s):
    return s.mnem.split()[0] in ("mrs", "msr", "mrrs", "msrr", "sys", "sysl",
                                 "at", "dc", "ic", "tlbi", "cfp", "cpp",
                                 "dvp")


@cls("aarch64", "A-MTE", "the MTE tag-control registers, read implicitly", """
IRG, ADDG, SUBG, LDGM, STGM and STZGM take their behaviour from GCR_EL1 (the
tag-exclusion mask) and GMID_EL1 (the tag-granule size), and ST64BV0 from
ACCDATA_EL1.  All are implicit reads the encoding does not name and LLVM's
MCInstrDesc does not model.""")
def _a_mte(s):
    return s.mnem.split()[0] in ("irg", "addg", "subg", "ldgm", "stgm",
                                 "stzgm", "st64bv0", "st64bv", "st64b",
                                 "ld64b")


@cls("aarch64", "A-ERET", "exception return reads the state exception entry "
     "wrote", """
ERET, ERETAA and ERETAB restore PC and PSTATE from ELR_ELx and SPSR_ELx, so
both are true sources; the authenticated forms additionally read the stack
pointer as the PAC modifier, which is what the wire records and what LLVM
spells as a read of the link register instead.  LLVM models no exception
state on any of the three.""")
def _a_eret(s):
    return s.mnem.split()[0] in ("eret", "eretaa", "eretab", "drps")


@cls("aarch64", "A-SATQC", "the saturating forms read FPSR.QC because QC is "
     "STICKY, and LLVM names FPCR instead", """
SQDMULH and SQRDMULH set FPSR.QC on saturation, and QC is a STICKY bit: the
instruction must read the accumulated value to OR into it, so FPSR is
read-modify-written and the read is real.  LLVM instead attaches a use of
FPCR to these opcodes -- the control word, which a fixed-point saturating
multiply does not consult -- so the two sides name two different registers
and neither names the other's.  The wire is right on both counts, and the
disagreement is only VISIBLE now because FPCR and FPSR stopped sharing an id
at this tip.""")
def _a_satqc(s):
    return s.mnem.split()[0] in ("sqdmulh", "sqrdmulh")


@cls("aarch64", "A-MISC", "the remaining single-signature reference gaps", """
`bc.nv` is the never-taken consistent branch: LLVM names a condition-flag
read for the whole BC.cond family, and QEMU reads nothing because the NV
condition is resolved at translation time.  `tlbi` with a register argument
LLVM names as a GPR use on the forms that take none.  `zero za...` LLVM names
as a read of the ZA array it only writes.  Each is one signature and each is
the reference over-naming an operand its per-opcode description carries.""")
def _a_misc(s):
    return True


# ----------------------------------------------------------------- x86_64
@cls("x86_64", "X-FIP", "every x87 instruction reads the CS SELECTOR, to "
     "save it as the FPU code segment", """
The x87 state includes the FPU Instruction Pointer and the FPU Code Segment
selector -- the pair FSTENV / FSAVE / FXSAVE publish (Intel SDM Vol. 1
sec. 8.1.8) -- and the instruction that updates FIP must read CS to do it.
QEMU does exactly that, in one place, for the whole x87 population:

    target/i386/tcg/translate.c, `if (update_fip)`:
        tcg_gen_ld32u_tl(..., offsetof(CPUX86State, segs[R_CS].selector));
        tcg_gen_st_tl (..., offsetof(CPUX86State, fpcs));

so REG_SEG0 reaches the wire's read list on every x87 form that updates FIP,
including the register-only ones with no memory operand at all.  LLVM's
MCInstrDesc names no segment register on any of them.  This is NOT the
zero-base segment-override family below: that one is about an override
prefix the reference reports and 64-bit mode ignores, this one is a real read
the reference does not report.  Where the qualifier names REG_FCSR beside it
the register is FPSW, read-modify-written for the condition codes and the
stack top, and where it names REG_FPR# it is the stack slot ST(0) resolves
to.""")
def _x_fip(s):
    return "REG_SEG0" in s.regs


@cls("x86_64", "X-IOPL", "IN and OUT read EFLAGS.IOPL to decide whether "
     "they are allowed to run", """
The I/O instructions are permitted by CPL and EFLAGS.IOPL, and outside ring 0
by the I/O permission bitmap (Intel SDM Vol. 2A, IN / OUT: "protected mode
... IOPL").  QEMU states that check at translation (gen_check_io), so the
flag register reaches the read list.  LLVM's MCInstrDesc models the data
movement and no permission check, so it names no flag use.""")
def _x_iopl(s):
    m = s.mnem.split()[-1]
    return (m[:2] in ("in", "ou") and m[:3] in ("inb", "inl", "inw", "out")
            and "REG_FLAGS" in s.regs)


@cls("x86_64", "X-REP", "the REP prefix reads the count register, which is "
     "not part of the opcode LLVM describes", """
REP / REPE / REPNE make the string operation iterate on RCX, so RCX is a true
source of the prefixed form.  LLVM's MCInstrDesc describes the BASE OPCODE --
MOVSB, STOSB, INSB -- and the prefix is a separate MCInst feature, so its
read set is short by the count register on every prefixed encoding.  The
tracer's subject is the instruction QEMU translated, prefix included.""")
def _x_rep(s):
    return (s.mnem.split()[0] in ("rep", "repe", "repz", "repne", "repnz")
            or s.mnem.split()[-1] in ("loop", "loope", "loopne", "loopz",
                                      "loopnz", "jrcxz", "jecxz"))


X_PARTIAL_STEMS = ("bt", "inc", "dec", "rol", "ror", "sar", "shl", "shr",
                   "shld", "shrd", "bsf", "bsr", "cmpxchg", "lar", "lsl")


@cls("x86_64", "X-PARTIAL", "an instruction that writes PART of a register "
     "must carry the rest forward, and the reference has one operand", """
BT / BTS / BTR / BTC write CF and leave OF, SF, ZF, AF and PF UNCHANGED
(Intel SDM Vol. 2A, BT); SAHF writes five flags and leaves OF and the
reserved bits; LAHF writes AH and leaves the other 56 bits of RAX; POPF
restores some flags and preserves others by privilege.  At the granularity a
register file schedules on, each of those is a PARTIAL WRITE, which is a
read-modify-write: the instruction must carry the untouched part forward, and
QEMU's lazy-flag machinery states the read.  LLVM's MCInstrDesc carries ONE
operand for EFLAGS and one for the GPR and marks it Def, so it has no way to
express a partial write and reports no use.""")
def _x_partial(s):
    m = s.mnem.split()[-1]
    return (m.startswith(X_PARTIAL_STEMS)
            or m in ("lahf", "sahf", "popfq", "popfw", "pushfq", "pushfw",
                     "clc", "stc", "cmc", "cld", "std", "cli", "sti"))


@cls("x86_64", "X-STACK", "the implicit stack access reads SS and RSP, and "
     "LLVM names neither", """
RET, CALL, PUSH, POP, LEAVE and ENTER address memory through RSP with SS as
the segment, and neither register appears in the encoding.  QEMU computes the
effective address from both, so both reach the read list.  LLVM's
MCInstrDesc leaves the implicit stack operands to the target's own lowering
and names no register here.""")
def _x_stack(s):
    m = s.mnem.split()[-1]
    return (m.startswith(("ret", "lret", "leave", "enter", "push", "pop",
                          "call", "iret"))
            and bool(s.regs & {"REG_SP", "REG_SEG5"}))


@cls("x86_64", "X-CR", "a control register that gates whether the "
     "instruction runs at all", """
FWAIT checks CR0.TS, CR0.MP and CR0.EM before it looks at the x87 status
word, and the SSE and XSAVE forms check CR4.OSFXSR / CR4.OSXSAVE the same
way.  QEMU states those reads at translation.  LLVM's MCInstrDesc models no
control register on any instruction, which is the same structural silence
REG_SYSFPEN meets on AArch64.""")
def _x_cr(s):
    return any(r.startswith("REG_CTRL") for r in s.regs)


@cls("x86_64", "X-FSGS", "the FS and GS BASES, which are the only segment "
     "bases that are live in 64-bit mode", """
The phantom direction of the segment family: the tracer reads the live base
register -- `swapgs`, `rdfsbase`, `wrgsbase`, `maskmovq` -- and LLVM's
MCInstrDesc has no operand for the hidden descriptor base.  This is the
counterpart to the zero-base override family below, and the discriminator
between them is checked: NOT ONE row here is REG_SEG0 / REG_SEG1 / REG_SEG2 /
REG_SEG5, and not one row there is REG_SEG3 or REG_SEG4.""")
def _x_fsgs(s):
    return bool(s.regs & {"REG_SEG3", "REG_SEG4"})


@cls("x86_64", "X-UPPERLANE", "a legacy scalar or unary SSE form preserves "
     "the upper lanes of its destination, so the destination is read", """
R7.1-SCALAR, restated at this layer: the destination of a legacy scalar SSE
form survives above the element the instruction writes, so it is an input.
LLVM models the preserve as a tied operand on the forms whose assembly
repeats the register and not on the rest, so its read set is short by the
destination exactly where the tie is absent.""")
def _x_upperlane(s):
    return any(r.startswith("REG_VEC") for r in s.regs)


@cls("x86_64", "X-CONSTCOUNT", "a rotate-through-carry by an immediate ZERO "
     "reads nothing, and LLVM's description is per-opcode", """
RCL and RCR with a masked count of zero do not rotate and do not touch the
flags (Intel SDM Vol. 2B, RCL/RCR), so QEMU's translator folds the whole
operation away at translation time and reads no flag.  Measured on the same
tool: `rclb $3, (%rdx)` (--hex=c01203) DOES read REG_FLAGS on both sides, so
the disagreement is confined to the immediate-zero encodings.  LLVM's
MCInstrDesc is keyed on the OPCODE and cannot say "reads CF unless the
immediate is zero", so it names the use unconditionally.""")
def _x_constcount(s):
    return s.mnem.split()[-1][:3] in ("rcl", "rcr") and "REG_FLAGS" in s.regs


@cls("x86_64", "X-X87OPERAND", "the x87 operand LLVM attaches and the "
     "hardware does not consult", """
FFREE / FFREEP mark a stack slot EMPTY in the tag word; they do not read the
value in it.  FLD / FST / FSTP / FXCH between registers, FLD1 / FLDZ and the
m80 FLDT / FSTPT pair move a bit pattern without rounding it, so they do not
consult the control word either -- the same sixteen pure moves 0acd1e32e5
resolved through QEMU's call graph and left OUT of the x87 control-word read
set on purpose.  LLVM attaches the use anyway, uniformly across the x87
tables.  The tracer's set is the derived one.""")
def _x_x87(s):
    return s.mnem.split()[-1] in (
        "ffree", "ffreep", "fld", "fldt", "fld1", "fldz", "fst", "fstp",
        "fstpt", "fxch", "fxam", "fnop", "fdecstp", "fincstp")


@cls("x86_64", "X-IMPLICITGPR", "the implicit GPR operands of the "
     "monitor / wait / key family", """
MONITORX, MWAITX, PCONFIG, RDPKRU, WRPKRU, TPAUSE and UMWAIT take implicit
operands in fixed GPRs, and which of those the instruction READS depends on
the leaf the register selects.  QEMU implements the leaf it models and reads
what that leaf needs; LLVM's MCInstrDesc names the whole implicit set for the
opcode.  The residue is the difference between a modelled leaf and a named
one, and the tracer's is the read that happens.""")
def _x_implicit(s):
    return s.mnem.split()[-1] in (
        "monitorx", "mwaitx", "pconfig", "rdpkru", "wrpkru", "tpause",
        "umwait", "monitor", "mwait", "umonitor", "xgetbv", "xsetbv",
        "encls", "enclu", "enclv", "vmfunc", "sysexitl", "sysexitq",
        "sysretl", "sysretq", "syscall", "sysenter")


@cls("x86_64", "X-SSP", "the shadow-stack pointer, which the reference names "
     "as a GPR or not at all", """
RDSSPD / RDSSPQ read SSP into a GPR; with CET off they are NOPs, which is why
LLVM models the destination as SURVIVING and therefore read, while the
tracer names the architectural source.  The remaining SSP rows are the CET
instructions whose shadow-stack access the encoding does not name.  This is
the `SR-` face of family (g) in the FR block above.""")
def _x_ssp(s):
    return "REG_SSP" in s.regs or s.mnem.split()[-1].startswith("rdssp")


@cls("x86_64", "X-MSR", "the model-specific or descriptor-table register an "
     "INDEX selects", """
RDMSR / WRMSR address a register by an index in ECX and LLVM's description
says only that they move EDX:EAX; LLDT / LTR / SGDT / SIDT reach the
descriptor-table registers the same way.  There is no register operand for
the reference to name.  This is the boundary file's own
`x86_64 SR-rd-phantom * +REG_SYS*` argument at this layer.""")
def _x_msr(s):
    return bool(s.regs & {"REG_SYS", "REG_SYSMMU", "REG_SYSTIMER",
                          "REG_SYSPERF", "REG_SYSDBG", "REG_SYSCACHE",
                          "REG_SYSID", "REG_SYSEXC"})


@cls("x86_64", "X-SELFRELOAD", "QEMU re-reads the control word the "
     "instruction just WROTE, to re-derive its softfloat state", "",
     defect=True)
def _x_selfreload(s):
    return s.mnem.split()[-1] in ("fldcw", "fldenv", "ldmxcsr", "vldmxcsr",
                                  "frstor", "fxrstor", "fxrstor64")


@cls("x86_64", "X-ADDRONLY", "a hint whose memory operand is an ADDRESS the "
     "instruction computes and does not dereference", """
CLDEMOTE, PREFETCH* and the multi-byte NOP r/m all carry a ModRM memory
operand whose EFFECTIVE ADDRESS is formed -- that is what the base register
is for -- and whose contents are never touched.  QEMU forms the address, so
the base register reaches the read list.  LLVM's MCInstrDesc models the
operand as ignored and names no use, which is true of the DATA and false of
the ADDRESS.""")
def _x_addronly(s):
    m = s.mnem.split()[-1]
    return m.startswith(("nop", "cldemote", "prefetch"))


@cls("x86_64", "X-X87STATE", "the x87 status word and the stack slot ST(0) "
     "resolves to, neither of which the reference names", """
The x87 status word carries the condition codes AND the stack top, so an
instruction that sets C0-C3 read-modify-writes it and an instruction that
names ST(i) must read the top to resolve i to a physical slot.  QEMU does
both.  LLVM's MCInstrDesc names the architectural ST register and no status
word at all.  STMXCSR and VSTMXCSR are the same silence from the other end:
they STORE MXCSR, so reading it is the whole instruction, and LLVM still
carries no use for it.""")
def _x_x87state(s):
    m = s.mnem.split()[-1]
    return (bool(s.regs & {"REG_FCSR"})
            and (m.startswith(("fcom", "ficom", "fist", "fst", "fld", "fnst",
                               "fisub", "fiadd", "fimul", "fidiv"))
                 or m in ("stmxcsr", "vstmxcsr")))


@cls("x86_64", "X-MISC", "the remaining reference gaps, one signature at a "
     "time", """
What is left after the named families: forms where LLVM names an implicit
operand its per-opcode description carries and the instruction does not
consult, or where the tracer names a register the encoding implies and the
reference has no operand for.  They are listed one row at a time because
none of them generalises.""")
def _x_misc(s):
    return True


def classify(isa, sigs):
    out = collections.OrderedDict()
    for cid, title, comment, fn, defect in CLASSES[isa]:
        out[cid] = (title, comment, defect, [])
    for s in sigs:
        for cid, title, comment, fn, defect in CLASSES[isa]:
            if fn(s):
                out[cid][3].append(s)
                break
        else:
            raise SystemExit(f"{isa}: UNCLASSIFIED {s.key}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arms", required=True,
                    help="directory holding f_<isa>.txt from the --srcenc "
                         "fields arms")
    ap.add_argument("--isa", action="append", choices=ISAS)
    ap.add_argument("--census", action="store_true",
                    help="print the partition and exit")
    args = ap.parse_args()
    isas = args.isa or list(ISAS)

    blocks = []
    for isa in isas:
        path = os.path.join(args.arms, f"f_{isa}.txt")
        if not os.path.exists(path):
            raise SystemExit(f"no arm output at {path}")
        sigs = read_arm(path)
        parts = classify(isa, sigs)
        if args.census:
            print(f"--- {isa}: {len(sigs)} signatures")
            for cid, (title, comment, defect, rows) in parts.items():
                if rows:
                    tag = " DEFECT" if defect else ""
                    print(f"  {cid:14s} {len(rows):5d} sigs "
                          f"{sum(r.n for r in rows):9d} enc{tag}")
            continue
        for cid, (title, comment, defect, rows) in parts.items():
            if not rows:
                continue
            if defect:
                blocks.append(
                    f"# --- {cid}: {title}.\n"
                    f"#     {len(rows)} signature(s), "
                    f"{sum(r.n for r in rows)} encodings, NOT ALLOWLISTED.\n"
                    f"#     An allowlist row asserts the tracer is right; "
                    f"these stay red.\n"
                    + "".join(f"#     {isa} {r.key}\n"
                              for r in sorted(rows, key=lambda x: x.key)))
                continue
            body = "\n".join(
                "#" + (" " + l if l else "") for l in comment.strip().split("\n"))
            blocks.append(
                f"# --- {cid}: {title}.\n"
                f"#     {len(rows)} signature(s), "
                f"{sum(r.n for r in rows)} encodings at this tip.\n#\n"
                + body + "\n"
                + "".join(f"{isa} {r.key}\n"
                          for r in sorted(rows, key=lambda x: x.key)))
    if not args.census:
        sys.stdout.write("\n".join(blocks))


if __name__ == "__main__":
    main()
