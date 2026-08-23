"""
Adjudicate the mipsel reference operand sets and compare against the tracer.

Rank order for mipsel (from the arc brief):
    LLVM MC 18.1.3  >  binutils 2.42 mips-opc.c  >  sail-cheri-mips
plus QEMU's own modelling (R6) for the three classes that have NO static
reference: the trap footprint, FCSR on ordinary FP arithmetic, and DSPControl.

Every departure from the rank-1 answer carries a rule id and a provenance
string; nothing is averaged.
"""
import os, json, re, sys, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from canon import drop

BASE = os.environ.get("CST_ARC3_ATTRIB_DIR", os.getcwd()).rstrip("/") + "/"
rows = json.load(open(BASE + "rows_raw.json"))
fcr31 = set(json.load(open(BASE + "qemu_fcr31_class.json"))["fcr31_class"])
msacsr_h = [l.strip()[len("helper_msa_"):] for l in open(BASE + "qemu_msacsr_helpers.txt") if l.strip()]
msa_fp_bases = set(h[:-3] for h in msacsr_h if h.endswith("_df")) - {"cfcmsa", "ctcmsa"}

TRAP_UNCOND = {"syscall", "break", "sdbbp"}
TRAP_COND = {"teq","tge","tgeu","tlt","tltu","tne",
             "teqi","tgei","tgeiu","tlti","tltiu","tnei"}
ERET = {"eret", "deret"}
TLB_RW  = {"tlbr", "tlbp"}
TLB_R   = {"tlbwi", "tlbwr", "tlbinv", "tlbinvf"}
CP0_RMW = {"di", "ei", "dvpe", "evpe", "dmt", "emt"}
WAIT    = {"wait"}
LL      = {"ll", "lle"}
SC      = {"sc", "sce"}

RULES = {
 "L-AT":     ("LLVM defect: BC1F/BC1T carry Defs=[AT], an assembler branch-expansion "
              "artifact, not an architectural write; binutils names no such write (R2)."),
 "L-DSPCTL": ("LLVM defect: the DSPControl read/write of BPOSGE32 / RDDSP / WRDSP / MTHLIP "
              "is absent from the MCInstrDesc implicit lists; the DSP ASE defines it and "
              "QEMU's dsp_helper models it (R2/R6)."),
 "L-MSACTL": ("LLVM defect: CTCMSA models the MSA control register as a USE operand; the "
              "instruction writes it (R6: helper_msa_ctcmsa assigns env->active_tc.msacsr)."),
 "Q-FCR31":  ("QEMU truth (R6): 108 helpers in target/mips/tcg/fpu_helper.c call "
              "update_fcr31(), which does SET_FP_CAUSE(env->active_fpu.fcr31, ...) "
              "unconditionally and reads GET_FP_ENABLE(fcr31) plus the fcr31 rounding mode. "
              "No static mipsel reference models it."),
 "Q-MSACSR": ("QEMU truth (R6): 50 MSA float helpers in target/mips/tcg/msa_helper.c reach "
              "update_msacsr(), which reads and writes env->active_tc.msacsr."),
 "Q-TRAP":   ("QEMU truth (R6): target/mips/tcg/system/tlb_helper.c set_EPC (:1421-1440) "
              "writes CP0_EPC, CP0_Cause.BD and CP0_Status.EXL and reads CP0_Status; "
              ":1051/:1066 writes CP0_BadInstr. R5: a conditional trap still names the write."),
 "Q-CP0":    ("QEMU truth (R6): the TLB and CP0-control helpers name their CP0 registers "
              "exactly (r4k_helper_tlbr/tlbp/tlbwi, helper_di/ei, helper_dvpe/evpe)."),
 "Q-LLBIT":  ("QEMU truth (R6) + sail-cheri-mips (rank 3, the only static mipsel reference "
              "that models the link bit): LL writes the link state, SC reads and clears it."),
 "B2-MTFILE":("Rank 2 (binutils mips-opc.c) is the only reference that names the register "
              "FILE of each of the 24 MT ASE MFTR/MTTR forms; LLVM, Capstone and the tracer "
              "collapse all 24 into a GPR<->GPR move (C4: never silently reduced)."),
 "R1-TIED":  ("Rank 1 (LLVM MCInstrDesc TIED_TO): the unaligned load merges into its "
              "destination, so the destination is also a source (R5/C4)."),
}

# ---------------------------------------------------------------------------
# MT ASE: MFTR/MTTR carry a (u, sel, h) triple that selects which register FILE
# the far operand lives in.  Capstone, LLVM and the tracer all collapse the 24
# named forms into one GPR<->GPR move; binutils (rank 2) is the only reference
# that names the file per form, and QEMU's own MT modelling agrees with it.
MT_FILE = {
  "mftc0":"SYS",  "mttc0":"SYS",   "mftc2":"SYS",  "mttc2":"SYS",
  "mfthc2":"SYS", "mtthc2":"SYS",  "cftc2":"SYS",  "cttc2":"SYS",
  "cftc1":"FCSR", "cttc1":"FCSR",
  "mftc1":"FPR",  "mttc1":"FPR",   "mfthc1":"FPR", "mtthc1":"FPR",
  "mftgpr":"GPR", "mttgpr":"GPR",
  "mfthi":"ACC",  "mtthi":"ACC",   "mftlo":"ACC",  "mttlo":"ACC",
  "mftacx":"ACC", "mttacx":"ACC",
  "mftdsp":"FLAGS","mttdsp":"FLAGS",
}

def mt_reg(fil, word, from_file):
    """Name the far operand.  Its index is whatever the pattern leaves free in
    the field that carries it: rt[20:16] for MFTR, rd[15:11] for MTTR; the
    accumulator forms pin all but the two-bit ac index."""
    if fil in ("SYS", "FCSR", "FLAGS"):
        return "REG_" + fil
    if fil == "ACC":
        # The accumulator index is rt >> 2, NOT rt & 3.  QEMU's gen_mftr /
        # gen_mttr spell the sixteen values out one at a time and the group
        # of three (lo, hi, acx) advances by four: rt 0/1/2 -> AC0,
        # 4/5/6 -> AC1, 8/9/10 -> AC2, 12/13/14 -> AC3
        # (target/mips/tcg/translate.c:8213).  rt lives at [20:16] for MFTR
        # and rd at [15:11] for MTTR, so the shift is 16+2 / 11+2.
        idx = (word >> 18) & 3 if from_file else (word >> 13) & 3
        return "REG_ACC%d" % idx
    idx = (word >> 16) & 31 if from_file else (word >> 11) & 31
    return "REG_%s%d" % (fil, idx)

def mnem(r):
    """Opcode id -> mnemonic.  Two DSP control opcodes carry a `.<encoding>`
    discriminator because their two operand shapes are distinct decode
    patterns; strip it to get the mnemonic."""
    m = r["id"].replace("mipsel.", "")
    return re.sub(r"\.[0-9a-f]{8}$", "", m)

def main():
    out = []
    for r in rows:
        m = mnem(r)
        src = set(r["ref_src"]); dst = set(r["ref_dst"])
        applied = []

        if m in ("bc1f", "bc1t", "bc1fl", "bc1tl") and "REG_GPR1" in dst:
            dst.discard("REG_GPR1"); applied.append("L-AT")

        if m in ("bposge32", "rddsp"):
            if "REG_FLAGS" not in src: src.add("REG_FLAGS"); applied.append("L-DSPCTL")
        if m == "wrdsp":
            if "REG_FLAGS" not in dst: dst.add("REG_FLAGS"); applied.append("L-DSPCTL")
        if m == "mthlip":
            if "REG_FLAGS" not in src: src.add("REG_FLAGS"); applied.append("L-DSPCTL")

        if m == "ctcmsa":
            src.discard("REG_FCSR"); dst.add("REG_FCSR"); applied.append("L-MSACTL")

        if m in fcr31:
            src.add("REG_FCSR"); dst.add("REG_FCSR"); applied.append("Q-FCR31")
        else:
            mm = re.fullmatch(r"(\w+)\.(b|h|w|d)", m)
            if mm and mm.group(1) in msa_fp_bases:
                src.add("REG_FCSR"); dst.add("REG_FCSR"); applied.append("Q-MSACSR")

        if m in TRAP_UNCOND or m in TRAP_COND:
            src.add("REG_SYS"); dst.add("REG_SYS"); applied.append("Q-TRAP")
        if m in ERET or m in TLB_RW or m in CP0_RMW:
            src.add("REG_SYS"); dst.add("REG_SYS"); applied.append("Q-CP0")
        if m in TLB_R or m in WAIT:
            src.add("REG_SYS"); applied.append("Q-CP0")

        if m in LL:
            dst.add("REG_LLBIT"); applied.append("Q-LLBIT")
        if m in SC:
            src.add("REG_LLBIT"); dst.add("REG_LLBIT"); applied.append("Q-LLBIT")

        # ---- MT ASE mft*/mtt*: the (u, sel) pair selects the register FILE ----
        if m in MT_FILE:
            fil = MT_FILE[m]
            w = int(r["word"], 16)
            if m.startswith(("mft", "cft")):
                other = mt_reg(fil, w, from_file=True)
                src = {other} if other else set()
                dst = set(r["ref_dst"])          # the GPR the rank-1 view already names
            else:
                other = mt_reg(fil, w, from_file=False)
                dst = {other} if other else set()
                src = set(r["ref_src"])
            applied.append("B2-MTFILE")

        if m in ("lwle", "lwre"):
            # rank 1 already carries the tie; recorded so the rule shows in the table
            applied.append("R1-TIED")

        r2 = dict(r)
        r2["adj_src"] = sorted(drop(src)); r2["adj_dst"] = sorted(drop(dst))
        r2["rules"] = applied
        r2["mnem_key"] = m
        out.append(r2)

    json.dump(out, open(BASE + "rows_adj.json", "w"), indent=0)

    def sigof(r):
        rs, rd = set(r["adj_src"]), set(r["adj_dst"])
        ts, td = set(r["tr_src"]), set(r["tr_dst"])
        if rs == ts and rd == td: return None
        def cls(x): return re.sub(r"\d+", "N", x).replace("REG_", "")
        p = []
        if rs - ts: p.append("SRC-miss{%s}" % ",".join(sorted(set(map(cls, rs - ts)))))
        if ts - rs: p.append("SRC-extra{%s}" % ",".join(sorted(set(map(cls, ts - rs)))))
        if rd - td: p.append("DST-miss{%s}" % ",".join(sorted(set(map(cls, rd - td)))))
        if td - rd: p.append("DST-extra{%s}" % ",".join(sorted(set(map(cls, td - rd)))))
        return " ".join(p)

    sig = collections.defaultdict(list)
    agree = 0
    for r in out:
        s = sigof(r)
        if s is None: agree += 1
        else: sig[s].append(r)
    print("attempted=%d agree=%d disagree=%d" % (len(out), agree, len(out) - agree))
    print()
    for k, v in sorted(sig.items(), key=lambda kv: -len(kv[1])):
        rules = collections.Counter(x for r in v for x in r["rules"])
        print("%4d  %-46s rules=%s" % (len(v), k, dict(rules)))
        print("        eg: %s" % ", ".join(x["mnem_key"] for x in v[:10]))
    json.dump({k: [r["id"] for r in v] for k, v in sig.items()},
              open(BASE + "signatures.json", "w"), indent=1)


if __name__ == "__main__":
    main()
