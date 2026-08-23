"""LLVM MIPS register name -> tracer canonical generic name (R4: full-width)."""
import re

# CP0 is not one register.  The role of each CP0 register NUMBER, read off
# MIPS32 Volume III's coprocessor-0 register table, not off the tracer's
# own table -- if the two ever disagree the comparison must be able to say
# so, which it cannot if this map is derived from the thing it measures.
# The grouping question is "which registers does one event write together",
# because that is the set whose members a consumer must order against each
# other; an edge inside a group is real and an edge across groups is not.
CP0_NUM_GROUP = {
    0:  "REG_SYSMMU",    # Index
    1:  "REG_SYSMMU",    # Random
    2:  "REG_SYSMMU",    # EntryLo0
    3:  "REG_SYSMMU",    # EntryLo1
    4:  "REG_SYSMMU",    # Context / ContextConfig
    5:  "REG_SYSMMU",    # PageMask / PageGrain / SegCtl / PWBase-PWSize
    6:  "REG_SYSMMU",    # Wired / PWCtl
    7:  "REG_SYS",       # HWREna -- a permission mask, not TLB state
    8:  "REG_SYSEXC",    # BadVAddr / BadInstr / BadInstrP / BadInstrX
    9:  "REG_SYSTIMER",  # Count
    10: "REG_SYSMMU",    # EntryHi
    11: "REG_SYSTIMER",  # Compare
    12: "REG_SYSEXC",    # Status / IntCtl / SRSCtl / SRSMap
    13: "REG_SYSEXC",    # Cause
    14: "REG_SYSEXC",    # EPC / NestedEPC
    15: "REG_SYSID",     # PRId (+EBase / CDMMBase / CMGCRBase / BEVVA)
    16: "REG_SYSID",     # Config / Config1-5
    17: "REG_SYS",       # LLAddr
    18: "REG_SYSDBG",    # WatchLo0-15
    19: "REG_SYSDBG",    # WatchHi0-15
    20: "REG_SYSMMU",    # XContext / XContextConfig
    21: "REG_SYS",       # reserved
    22: "REG_SYS",       # implementation-dependent
    23: "REG_SYSDBG",    # Debug / Debug2 / TraceControl / TraceIBPC
    24: "REG_SYSDBG",    # DEPC / TraceControl3 / UserTraceData2
    25: "REG_SYSPERF",   # PerfCtl0-7 / PerfCnt0-7
    26: "REG_SYSCACHE",  # ErrCtl
    27: "REG_SYSCACHE",  # CacheErr
    28: "REG_SYSCACHE",  # ITagLo / IDataLo / DTagLo / DDataLo
    29: "REG_SYSCACHE",  # ITagHi / IDataHi / DTagHi / DDataHi
    30: "REG_SYSEXC",    # ErrorEPC
    31: "REG_SYS",       # DESAVE + KScratch1-6, two unrelated uses
}

# The rdhwr window onto that state, MIPS32 Volume II rdhwr.
HWR_GROUP = {
    0: "REG_SYSID",      # CPUNum
    1: "REG_SYSID",      # SYNCI_Step
    2: "REG_SYSTIMER",   # CC -- the cycle counter, i.e. Count
    3: "REG_SYSID",      # CCRes
    29: "REG_TLS",       # UserLocal, the thread pointer
}

GPR = {"ZERO":"REG_ZERO","AT":"REG_GPR1","V0":"REG_GPR2","V1":"REG_GPR3",
       "A0":"REG_GPR4","A1":"REG_GPR5","A2":"REG_GPR6","A3":"REG_GPR7",
       "T0":"REG_GPR8","T1":"REG_GPR9","T2":"REG_GPR10","T3":"REG_GPR11",
       "T4":"REG_GPR12","T5":"REG_GPR13","T6":"REG_GPR14","T7":"REG_GPR15",
       "S0":"REG_GPR16","S1":"REG_GPR17","S2":"REG_GPR18","S3":"REG_GPR19",
       "S4":"REG_GPR20","S5":"REG_GPR21","S6":"REG_GPR22","S7":"REG_GPR23",
       "T8":"REG_GPR24","T9":"REG_GPR25","K0":"REG_GPR26","K1":"REG_GPR27",
       "GP":"REG_GPR28","SP":"REG_SP","FP":"REG_FP_REG","RA":"REG_LR"}

def canon(name):
    """Map one LLVM MIPS physical register name to the tracer's canonical id.
    Returns None for a name that carries no architectural register."""
    if not name or name == "<noreg>":
        return None
    n = name.upper()
    if n in GPR:
        return GPR[n]
    # 64-bit FP view (FGR64 D<n>_64) aliases FGR32 F<n> exactly under FR=1.
    m = re.fullmatch(r"D(\d+)_64", n)
    if m: return "REG_FPR%d" % int(m.group(1))
    # FR=0 AFGR64 pair D<n> covers F<2n>,F<2n+1>; canonical full-width is the
    # even member (R4: a sub-register difference is not a disagreement).
    m = re.fullmatch(r"D(\d+)", n)
    if m: return "REG_FPR%d" % (2 * int(m.group(1)))
    m = re.fullmatch(r"F(\d+)", n)
    if m: return "REG_FPR%d" % int(m.group(1))
    m = re.fullmatch(r"W(\d+)", n)
    if m: return "REG_VEC%d" % int(m.group(1))
    m = re.fullmatch(r"FCC(\d+)", n)
    if m: return "REG_PRED%d" % int(m.group(1))
    # HI<n> and LO<n> are two architecturally DISTINCT registers -- mfhi
    # and mflo read different hardware -- so they take different ids.  AC<n>
    # is the DSP name for the whole 64-bit accumulator and therefore denotes
    # BOTH; it is a register LIST and only canon_set() can express it.
    m = re.fullmatch(r"HI(\d+)(?:_64)?", n)
    if m: return "REG_ACCHI%d" % int(m.group(1))
    m = re.fullmatch(r"LO(\d+)(?:_64)?", n)
    if m: return "REG_ACC%d" % int(m.group(1))
    m = re.fullmatch(r"AC(\d+)(?:_64)?", n)
    if m: return "REG_ACC%d" % int(m.group(1))   # low half; see canon_set
    if n.startswith("DSP"):
        return "REG_FLAGS"
    # The FP control file is not one register.  FIR (fcr0) is a read-only
    # implementation constant, so a read of it depends on nothing and it
    # must not share an id with the writable status word; FCCR/FEXR/FENR
    # (25/26/28) ARE views of FCSR and stay with it.
    m = re.fullmatch(r"FCR(\d+)", n)
    if m: return "REG_SYSID" if m.group(1) == "0" else "REG_FCSR"
    # Likewise MSA: MSACSR is the status word, MSAIR the read-only id
    # register, and the rest are registers-in-use / virtualisation control
    # that have nothing to do with FP exception state.
    if n == "MSACSR":
        return "REG_FCSR"
    if n == "MSAIR":
        return "REG_SYSID"
    if n in ("MSAMODIFY", "MSAREQUEST", "MSAACCESS", "MSASAVE",
             "MSAUNMAP", "MSAMAP"):
        return "REG_SYS"
    m = re.fullmatch(r"COP0(\d+)", n)
    if m: return CP0_NUM_GROUP.get(int(m.group(1)), "REG_SYS")
    # CP2 and CP3 are implementation-defined coprocessors: the
    # architecture gives their registers no semantics, so there is no
    # role to group by and each file is one id.
    m = re.fullmatch(r"COP2(\d+)", n)
    if m: return "REG_COPROC0"
    m = re.fullmatch(r"COP3(\d+)", n)
    if m: return "REG_COPROC1"
    m = re.fullmatch(r"HWR(\d+)", n)
    if m: return HWR_GROUP.get(int(m.group(1)), "REG_SYS")
    if n == "PC": return "REG_IP"
    return "UNMAPPED:" + name

def canon_set(name):
    """canon(), but for names that denote a register LIST rather than one
    register.  AC<n> is the whole 64-bit DSP accumulator and a consumer must
    order against BOTH halves -- the same shape as the AArch64 D0_D1 forms --
    so it expands.  Every other name yields its single id."""
    n = (name or "").upper()
    m = re.fullmatch(r"AC(\d+)(?:_64)?", n)
    if m:
        i = int(m.group(1))
        return {"REG_ACC%d" % i, "REG_ACCHI%d" % i}
    g = canon(name)
    return set() if g is None else {g}


# R7.3: "REG_ZERO exists, so it should be specified.  We should not be
# dropping reg zero.  We weren't before, we shouldn't be now."  The id is a
# real generic register and a set that names it differs from a set that does
# not, so suppressing it on BOTH sides -- which is what this harness used to
# do -- hides every place the two sides disagree about x0/$zero.  It hid them
# symmetrically, which is why mipsel read 977/977 with the suppression in
# place; a symmetric blindfold is still a blindfold.  aarch64's reference lost
# the same suppression in 7880bf6125 (mra_ref.to_sets did dst.discard('ZERO'))
# and the comparison is only cross-ISA comparable if both lose it.
#
# REG_IP stays.  It is not the zero register and R7.3 does not reach it: the
# program counter is not part of the register file the dependency model
# arbitrates, and every branch would otherwise carry a PC read/write that no
# consumer renames.
DROP = {"REG_IP", "-", "", None}

def drop(s):
    return set(x for x in s if x not in DROP)
