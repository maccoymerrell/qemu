"""LLVM MIPS register name -> tracer canonical generic name (R4: full-width)."""
import re

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
    # HI<n>/LO<n> are the two halves of the 64-bit accumulator AC<n>;
    # R4 canonicalises to the full-width register.
    m = re.fullmatch(r"(?:HI|LO|AC)(\d+)(?:_64)?", n)
    if m: return "REG_ACC%d" % int(m.group(1))
    if n.startswith("DSP"):
        return "REG_FLAGS"
    m = re.fullmatch(r"FCR(\d+)", n)
    if m: return "REG_FCSR"
    if n in ("MSAMODIFY", "MSAREQUEST", "MSACSR", "MSAACCESS", "MSASAVE",
             "MSAIR", "MSAUNMAP", "MSAMAP"):
        return "REG_FCSR"
    m = re.fullmatch(r"COP0(\d+)", n)
    if m: return "REG_SYS"
    m = re.fullmatch(r"COP2(\d+)", n)
    if m: return "REG_SYS"
    m = re.fullmatch(r"HWR(\d+)", n)
    if m:
        return "REG_TLS" if m.group(1) == "29" else "REG_SYS"
    if n == "PC": return "REG_IP"
    return "UNMAPPED:" + name

DROP = {"REG_ZERO", "REG_IP", "-", "", None}

def drop(s):
    return set(x for x in s if x not in DROP)
