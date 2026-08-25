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
from canon import drop, canon, canon_set


def cp0(n):
    """The generic id of CP0 register NUMBER n, via the shared canonicaliser."""
    return canon("COP0%d" % n)

BASE = os.environ.get("CST_ARC3_ATTRIB_DIR", os.getcwd()).rstrip("/") + "/"
rows = json.load(open(BASE + "rows_raw.json"))
fcr31 = set(json.load(open(BASE + "qemu_fcr31_class.json"))["fcr31_class"])
msacsr_h = [l.strip()[len("helper_msa_"):] for l in open(BASE + "qemu_msacsr_helpers.txt") if l.strip()]
msa_fp_bases = set(h[:-3] for h in msacsr_h if h.endswith("_df")) - {"cfcmsa", "ctcmsa"}

TRAP_UNCOND = {"syscall", "break"}
TRAP_COND = {"teq","tge","tgeu","tlt","tltu","tne",
             "teqi","tgei","tgeiu","tlti","tltiu","tnei"}
# sdbbp is NOT on the general exception path: it raises EXCP_DBp, whose
# footprint is the EJTAG debug file plus the Status/Cause it shares.
TRAP_DEBUG = {"sdbbp"}
ERET = {"eret", "deret"}
TLB_RW  = {"tlbr", "tlbp"}
TLB_R   = {"tlbwi", "tlbwr", "tlbinv", "tlbinvf"}
CP0_RMW = {"di", "ei", "dvpe", "evpe", "dmt", "emt"}
WAIT    = {"wait"}
LL      = {"ll", "lle"}
# The ids an MSA control register can canonicalise to, now that the file is
# split by role: MSACSR (status word), MSAIR (read-only id), and the
# registers-in-use / virtualisation control that fall to the residual.
MSA_CTL_IDS = {"REG_FCSR", "REG_SYSID", "REG_SYS"}
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
 "Q-TRAP":   ("R7.6 + QEMU truth (R6): the state the exception an instruction RAISES "
              "writes is in that instruction's set, because a later mfc0 of EPC/Cause/"
              "Status must wait on the write (R7). target/mips/tcg/system/tlb_helper.c "
              "set_EPC (:1420-1456) reads CP0_Status (the EXL gate on the whole write, "
              "then BEV for the vector) and read-modify-writes it, read-modify-writes "
              "CP0_Cause for BD (:1427-1430) and for the exception code "
              "(mips_cause_set_field, :1456, a cmpxchg loop -- internal.h:172), and "
              "writes CP0_EPC (:1422). Registers 12/13/14 -- REG_SYSEXC, and register 8 "
              "(BadInstr, :1043) is the same id. R4: a conditional trap names the write "
              "as a candidate whether or not it fires."),
 "Q-TRAPD":  ("R7.6 applied to the DEBUG entry path, which is a different footprint. "
              "sdbbp raises EXCP_DBp (translate.c:13049, :13454), not EXCP_TRAP, so it "
              "reaches set_DEPC/enter_debug_mode (tlb_helper.c:1204-1233): CP0_Debug is "
              "read-modify-written (the DBp bit and the DExcCode field), CP0_DEPC takes "
              "the resume PC, and the BD clear is the same Status-gated read-modify-write "
              "of CP0_Cause. So REG_SYSDBG on top of REG_SYSEXC, and NOT EPC."),
 "Q-CP0":    ("QEMU truth (R6): the TLB and CP0-control helpers name their CP0 registers "
              "exactly (r4k_helper_tlbr/tlbp/tlbwi, helper_di/ei, helper_dvpe/evpe). "
              "Since the CP0 split those registers are no longer one id: the TLB file is "
              "REG_SYSMMU (numbers 0/2/3/5/10), Status/EPC is REG_SYSEXC (12/14), "
              "deret's Debug/DEPC is REG_SYSDBG (23/24) and MVPControl/VPEControl is "
              "the residual REG_SYS (0/1 of the MT file)."),
 "R7.7-LL":  ("R7.7: there is NO reservation-state register. The maintainer's ruling is "
              "that reservation state is a product of the INSTRUCTION, not of a register: "
              "ll/lle/sc/sce name their real registers only and the monitor is the "
              "consumer's to model. Consistent with R2 -- we record ARCHITECTURAL "
              "dependencies and a reservation is microarchitectural -- and with the "
              "other two ISAs, where aarch64 stlxr and riscv64 lr.w/sc.w model no "
              "monitor either. The previous reference rule invented REG_LLBIT off "
              "env->lladdr/env->llval, which is QEMU's implementation of the monitor, "
              "not an architectural register. Removed from the reference -- the tracer "
              "was right on all four rows."),
 "B2-MTFILE":("Rank 2 (binutils mips-opc.c) is the only reference that names the register "
              "FILE of each of the 24 MT ASE MFTR/MTTR forms; LLVM, Capstone and the tracer "
              "collapse all 24 into a GPR<->GPR move (C4: never silently reduced)."),
 "R1-TIED":  ("Rank 1 (LLVM MCInstrDesc TIED_TO): the unaligned load merges into its "
              "destination, so the destination is also a source (R5/C4)."),
 "B2-ACCHALF":("Rank 2 decides. LLVM's MFHI_DSP/MFLO_DSP take the accumulator PAIR as "
              "their operand class (ACC64DSP), so rank 1 names both halves; binutils "
              "mips-opc.c names the half explicitly -- RD_HI on mfhi, RD_LO on mflo -- "
              "and QEMU agrees, reading cpu_HI[acc] and cpu_LO[acc] one at a time "
              "(gen_HILO, target/mips/tcg/translate.c:2891-2905). Two references and "
              "the model against one operand class; the tracer is right. The move-TO "
              "forms need no rule: LLVM names the single half it writes there."),
}

# ---------------------------------------------------------------------------
# MT ASE: MFTR/MTTR carry a (u, sel, h) triple that selects which register FILE
# the far operand lives in.  Capstone, LLVM and the tracer all collapse the 24
# named forms into one GPR<->GPR move; binutils (rank 2) is the only reference
# that names the file per form, and QEMU's own MT modelling agrees with it.
# The CP0 and CP2 forms named one file, "SYS", when CP0 was one id.  They
# are two files and always were: a CP0 register is grouped by its number,
# a CP2 register belongs to an implementation-defined coprocessor the
# architecture gives no semantics at all.
MT_FILE = {
  "mftc0":"CP0",  "mttc0":"CP0",   "mftc2":"CP2",  "mttc2":"CP2",
  "mfthc2":"CP2", "mtthc2":"CP2",  "cftc2":"CP2",  "cttc2":"CP2",
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
    if fil in ("FCSR", "FLAGS"):
        return {"REG_" + fil}
    if fil in ("CP0", "CP2"):
        idx = (word >> 16) & 31 if from_file else (word >> 11) & 31
        return {canon("COP%s%d" % ("0" if fil == "CP0" else "2", idx))}
    if fil == "ACC":
        # The accumulator index is rt >> 2, NOT rt & 3.  QEMU's gen_mftr /
        # gen_mttr spell the sixteen values out one at a time and the group
        # of three (lo, hi, acx) advances by four: rt 0/1/2 -> AC0,
        # 4/5/6 -> AC1, 8/9/10 -> AC2, 12/13/14 -> AC3
        # (target/mips/tcg/translate.c:8213).  rt lives at [20:16] for MFTR
        # and rd at [15:11] for MTTR, so the shift is 16+2 / 11+2.
        # mfthi/mftlo/mftacx name ONE half each; mttacx and the DSP forms
        # that carry the whole 64-bit accumulator name both (canon_set).
        idx = (word >> 18) & 3 if from_file else (word >> 13) & 3
        return canon_set("AC%d" % idx)
    idx = (word >> 16) & 31 if from_file else (word >> 11) & 31
    return {"REG_%s%d" % (fil, idx)}

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

        # L-AT -- LLVM declares an implicit def of $at on a MIPS branch
        # because the ASSEMBLER may expand a long branch through it.  The
        # INSTRUCTION writes no general register; `beq $4, $5, 4` is three
        # explicit uses and nothing else, and the impDEF is a fact about
        # llvm-mc's expansion, not about the encoding.
        #
        # SCOPE IS THE CLASS, NOT THE ROW, and this rule learned that the
        # expensive way.  It used to name four mnemonics -- bc1f, bc1t,
        # bc1fl, bc1tl -- while LLVM carries impDEF AT on 27, every one of
        # them a branch and not one naming $1 as an operand.  The other 23
        # were invisible only because the TRACER carried the same phantom $at
        # write and the two agreed on a fact that was false on both sides.
        # When 95a0d89e92 removed the tracer's phantom the reference kept its
        # own and the class surfaced as 23 TRACER-SUBSET rows.
        #
        # So the test is the observed LLVM record, not a name: an implicit
        # def of $at, on a branch, where $1 is not an explicit operand.
        if ("REG_GPR1" in dst and "REG_GPR1" in set(r.get("imp_dst") or ())
                and r.get("isBranch") and not re.search(r"\$1\b", r["asm"])):
            dst.discard("REG_GPR1"); applied.append("L-AT")

        if m in ("bposge32", "rddsp"):
            if "REG_FLAGS" not in src: src.add("REG_FLAGS"); applied.append("L-DSPCTL")
        if m == "wrdsp":
            if "REG_FLAGS" not in dst: dst.add("REG_FLAGS"); applied.append("L-DSPCTL")
        if m == "mthlip":
            if "REG_FLAGS" not in src: src.add("REG_FLAGS"); applied.append("L-DSPCTL")

        if m == "ctcmsa":
            # DIRECTION, not identity: whichever MSA control register the
            # operand names, LLVM models it as a USE and the instruction
            # writes it.  Since the MSA control file was split by role the
            # id is no longer always REG_FCSR, so the rule moves whatever
            # control id is present rather than naming one.
            ctl = src & MSA_CTL_IDS
            src -= ctl; dst |= ctl; applied.append("L-MSACTL")

        # mfhi/mflo read ONE half of the accumulator, and the half is named
        # by the mnemonic, not by the operand.
        if m in ("mfhi", "mflo"):
            half = "REG_ACCHI" if m == "mfhi" else "REG_ACC"
            src = {x for x in src
                   if not re.fullmatch(r"REG_ACC(?:HI)?\d+", x)
                   or x.startswith(half) and not (half == "REG_ACC"
                                                  and x.startswith("REG_ACCHI"))}
            applied.append("B2-ACCHALF")

        if m in fcr31:
            src.add("REG_FCSR"); dst.add("REG_FCSR"); applied.append("Q-FCR31")
        else:
            mm = re.fullmatch(r"(\w+)\.(b|h|w|d)", m)
            if mm and mm.group(1) in msa_fp_bases:
                src.add("REG_FCSR"); dst.add("REG_FCSR"); applied.append("Q-MSACSR")

        # The CP0 numbers each of these instructions names, from QEMU's own
        # helper, then canonicalised -- so the rule states the REGISTER and
        # the generic id is a consequence, exactly as on the tracer side.
        # A number, not a (number, sel) pair, because a number is all the
        # decode carries: Capstone's COP0<n> constants have no select field.
        if m in TRAP_UNCOND or m in TRAP_COND:
            # set_EPC: RMW Status(12) and Cause(13), write EPC(14).
            for cn in (12, 13):
                src.add(cp0(cn)); dst.add(cp0(cn))
            dst.add(cp0(14)); applied.append("Q-TRAP")
        if m in TRAP_DEBUG:
            # enter_debug_mode: RMW Debug(23), write DEPC(24), and the same
            # Status(12)-gated RMW of Cause(13).  No EPC.
            src.add(cp0(23)); dst.add(cp0(23)); dst.add(cp0(24))
            src.add(cp0(12)); src.add(cp0(13)); dst.add(cp0(13))
            applied.append("Q-TRAPD")
        if m == "eret":
            # reads Status(12), EPC(14), ErrorEPC(30); writes Status(12).
            for cn in (12, 14, 30):
                src.add(cp0(cn))
            dst.add(cp0(12)); applied.append("Q-CP0")
        if m == "deret":
            src.add(cp0(24)); dst.add(cp0(23)); applied.append("Q-CP0")
        if m in TLB_RW:
            # tlbr reads Index(0), writes EntryHi(10)/EntryLo(2,3)/PageMask(5);
            # tlbp reads EntryHi(10), writes Index(0).
            src.add(cp0(0 if m == "tlbr" else 10))
            dst.add(cp0(10 if m == "tlbr" else 0)); applied.append("Q-CP0")
        if m in CP0_RMW:
            # di/ei RMW Status(12); dvpe/evpe RMW MVPControl, which is CP0
            # register 0 select 1, and dmt/emt VPEControl, register 1
            # select 1.  Those two are MT thread control and NOT TLB state,
            # but they share their NUMBER with Index and Random, so with no
            # select in the decode they canonicalise onto the TLB id.  That
            # is a genuine number-vs-select collision and it is recorded
            # here rather than hidden behind a hand-picked id.
            cn = 12 if m in ("di", "ei") else (0 if m in ("dvpe", "evpe") else 1)
            src.add(cp0(cn)); dst.add(cp0(cn)); applied.append("Q-CP0")
        if m in TLB_R:
            # tlbwi/tlbwr/tlbinv/tlbinvf read Index(0) and EntryHi(10).
            src.add(cp0(0)); src.add(cp0(10)); applied.append("Q-CP0")
        if m in WAIT:
            src.add(cp0(12)); src.add(cp0(13)); applied.append("Q-CP0")

        # R7.7: no reservation-state register.  ll/lle/sc/sce name their
        # real registers only; the reference's REG_LLBIT is retired.
        if m in LL or m in SC:
            src.discard("REG_LLBIT"); dst.discard("REG_LLBIT")
            applied.append("R7.7-LL")

        # ---- MT ASE mft*/mtt*: the (u, sel) pair selects the register FILE ----
        if m in MT_FILE:
            fil = MT_FILE[m]
            w = int(r["word"], 16)
            if m.startswith(("mft", "cft")):
                src = set(mt_reg(fil, w, from_file=True))
                dst = set(r["ref_dst"])          # the GPR the rank-1 view already names
            else:
                dst = set(mt_reg(fil, w, from_file=False))
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
