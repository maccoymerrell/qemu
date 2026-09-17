#!/usr/bin/env python3
"""Put a THIRD decoder beside the two the referee scores.

setjoin reports (name, encoding) rows where the Capstone arm named a register
and QEMU did not.  Two decoders disagreeing settles nothing -- the contract's
arbitration rule says neither side is trusted -- so this asks LLVM, which
isaxcheck already decodes every encoding with, and reports per REAL-LOST class
which way the third reading falls:

    LLVM-WITH-CAPSTONE   two independent decoders name it; the question is
                         architectural and the merits read has to say why
                         QEMU is right (or that QEMU is wrong and must state it)
    LLVM-WITH-QEMU       the incumbent stands alone; that is a measured
                         refutation of the Capstone arm, not an opinion
    LLVM-SILENT          LLVM did not decode these bytes at all

It samples, and it SAYS it samples: the sample size is printed with every row
and a class whose witnesses all answer alike is reported as unanimous only when
every sampled witness was read.  A class this cannot decode at all is REFUSED
rather than scored, because "the tool could not look" is not "they agree".
"""
import argparse
import collections
import os
import subprocess
import sys

DEF_ISAX = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "..", "..", "..", "build", "contrib", "plugins",
                        "isaxcheck")


def read_gen(path):
    rows = collections.defaultdict(dict)
    with open(path, errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                continue
            p = line.rstrip("\n").split("\t")
            if len(p) < 7 or p[2] not in ("q", "c"):
                continue
            names = {n.strip() for n in p[6].split(",")
                     if n.strip() and n.strip() not in ("-", "+MORE")}
            rows[(p[1], p[3])].setdefault(p[2], set()).update(names)
    return rows


def read_ident(path):
    out = {}
    with open(path, errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                continue
            p = line.rstrip("\n").split("\t")
            if len(p) >= 6:
                out.setdefault(p[1], (p[2], p[3], p[4], p[5]))
    return out


def llvm_batch(isax, isa, encs):
    """{enc: (llvm_ok, llvm_text, set(rd), set(wr), b_rd, b_wr, b_mnem)}"""
    if not encs:
        return {}
    p = subprocess.run([isax, "--isa=" + isa, "--batch", "--layer=fields",
                        "--keep-zero"],
                       input="\n".join(encs) + "\n",
                       capture_output=True, text=True, timeout=1800)
    out = {}
    for line in p.stdout.splitlines():
        f = line.split("\t")
        if len(f) < 26 or f[0] == "hex":
            continue
        def s(x):
            return {t for t in x.split(",") if t and t != "-"}
        out[f[0]] = (f[16] == "1", f[18], s(f[24]), s(f[25]),
                     s(f[14]), s(f[15]), f[3])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--isa", required=True)
    ap.add_argument("--sample", type=int, default=24)
    ap.add_argument("--name")
    ap.add_argument("--witness", type=int, default=0,
                    help="print this many witness lines per class")
    ap.add_argument("--join", required=True,
                    help="directory holding the joined gen_<isa>.tsv setjoin "
                         "scores -- the QEMU side and the Capstone side in "
                         "one file")
    ap.add_argument("--merged", required=True,
                    help="directory holding ident_<isa>.tsv, for the "
                         "mnemonic and rule each witness carries")
    ap.add_argument("--isax", default=None,
                    help="the isaxcheck binary whose LLVM side is the third "
                         "decoder (default: the tree's own build/)")
    a = ap.parse_args()

    isax = a.isax or os.path.normpath(DEF_ISAX)
    if not os.path.exists(isax):
        print("realost_arbitrate: REFUSED -- no isaxcheck at %s.  Without a "
              "third decoder this has nothing to add to what setjoin already "
              "said." % isax, file=sys.stderr)
        return 2

    rows = read_gen(os.path.join(a.join, "gen_%s.tsv" % a.isa))
    ident = read_ident(os.path.join(a.merged, "ident_%s.tsv" % a.isa))

    lost = collections.defaultdict(list)
    for key, v in rows.items():
        if "q" in v and "c" in v:
            for nm in v["c"] - v["q"]:
                lost[(nm, key[1])].append(key[0])
    if not lost:
        print("arbitrate: REFUSED -- no REAL-LOST rows on %s at all.  A class "
              "list with no members cannot be adjudicated." % a.isa,
              file=sys.stderr)
        return 1

    # one isaxcheck pass over every sampled witness
    want = {}
    for (nm, d), encs in lost.items():
        if a.name and nm != a.name:
            continue
        want[(nm, d)] = encs[:a.sample]
    allenc = sorted({e for v in want.values() for e in v})
    llvm = llvm_batch(isax, a.isa, allenc)
    if not llvm:
        print("arbitrate: REFUSED -- isaxcheck decoded none of %d sampled "
              "encodings on %s." % (len(allenc), a.isa), file=sys.stderr)
        return 1

    print("# isa=%s  sampled %d encodings, isaxcheck read %d"
          % (a.isa, len(allenc), len(llvm)))
    print("%-12s %s %7s %6s  %-18s %-18s %-8s %s"
          % ("name", "d", "rows", "sample", "verdict", "mnemonics",
             "unread", "rule/word"))
    for (nm, d), encs in sorted(want.items(),
                                key=lambda x: -len(lost[x[0]])):
        sample = encs
        agree = dis = unread = 0
        unmapped = collections.Counter()
        mn = collections.Counter()
        rw = collections.Counter()
        wit = []
        for e in sample:
            r = llvm.get(e)
            i = ident.get(e, ("?", "?", "?", "?"))
            mn[i[0]] += 1
            rw["%s/%s" % (i[1], i[2])] += 1
            if r is None or not r[0]:
                unread += 1
                continue
            side = r[3] if d == "w" else r[2]
            gen, un = llvm_generic(side, a.isa)
            for u in un:
                unmapped[u] += 1
            if nm in gen:
                agree += 1
            else:
                dis += 1
            if len(wit) < a.witness:
                wit.append("     %-12s %-10s b_rd{%s} b_wr{%s} l_rd{%s} "
                           "l_wr{%s}  %s"
                           % (e, i[0], ",".join(sorted(r[4])),
                              ",".join(sorted(r[5])), ",".join(sorted(r[2])),
                              ",".join(sorted(r[3])), r[1]))
        read = agree + dis
        if read == 0:
            v = "LLVM-SILENT"
        elif dis == 0:
            v = "LLVM-WITH-CAPSTONE"
        elif agree == 0 and unmapped:
            #
            # LLVM named registers this mapper could not spell, so "QEMU is
            # alone" is a statement about the mapper and not about the
            # encoding.  Say so instead of casting the vote.
            #
            v = "UNMAPPED"
        elif agree == 0:
            v = "LLVM-WITH-QEMU"
        else:
            v = "LLVM-SPLIT %d/%d" % (agree, dis)
        print("%-12s %s %7d %6d  %-18s %-18s %-8s %s%s"
              % (nm, d, len(lost[(nm, d)]), len(sample), v,
                 ",".join("%s(%d)" % x for x in mn.most_common(3)),
                 unread, ",".join("%s" % x[0] for x in rw.most_common(2)),
                 ("   unmapped:" + ",".join(x for x, _ in
                                            unmapped.most_common(4)))
                 if unmapped else ""))
        for w in wit:
            print(w)
    return 0


X86_GPR = {
    "rax": 0, "eax": 0, "ax": 0, "al": 0, "ah": 0,
    "rcx": 1, "ecx": 1, "cx": 1, "cl": 1, "ch": 1,
    "rdx": 2, "edx": 2, "dx": 2, "dl": 2, "dh": 2,
    "rbx": 3, "ebx": 3, "bx": 3, "bl": 3, "bh": 3,
    "rsp": 4, "esp": 4, "sp": 4, "spl": 4,
    "rbp": 5, "ebp": 5, "bp": 5, "bpl": 5,
    "rsi": 6, "esi": 6, "si": 6, "sil": 6,
    "rdi": 7, "edi": 7, "di": 7, "dil": 7,
}
for _n in range(8, 16):
    for _s in ("r%d", "r%dd", "r%dw", "r%db"):
        X86_GPR[_s % _n] = _n

X86_SEG = {"es": 0, "cs": 1, "ss": 2, "ds": 3, "fs": 4, "gs": 5}

#
# The integer-register numbers whose generic name is NOT REG_GPR<n>.
# Taken from the plugin's own per-ISA tables so the two sides of the join
# spell one register one way:
#
#   mipsel   $0 zero, $29 sp, $31 ra   champsim_tracer_mnemonics_mips.h
#   riscv64  x0 zero, x2  sp, x1  ra   champsim_tracer_mnemonics_riscv.h
#   aarch64  x30 lr                    champsim_tracer_mnemonics_aarch64.h
#            (x31 is never spelled rN by the reference decoder -- it prints
#             `sp` or `zr` by context, and both already map below)
#
ABI_FIXED_GPR = {
    "mipsel":  {0: "REG_ZERO", 29: "REG_SP", 31: "REG_LR"},
    "riscv64": {0: "REG_ZERO", 1: "REG_LR", 2: "REG_SP"},
    "aarch64": {30: "REG_LR"},
}


def llvm_generic(regs, isa):
    """LLVM's own spellings, mapped to the generic names setjoin uses.

    A SPELLING THIS CANNOT MAP IS NOT AN ABSENCE.  An unmapped name used to
    fall through and read as "LLVM did not name it", which turns every gap in
    this table into a silent vote for QEMU -- the shape this tree calls a
    silent false success.  Unmapped spellings are returned in a second set and
    the caller reports the class as UNMAPPED rather than giving it a verdict.
    """
    out = set()
    unmapped = set()
    for r in regs:
        r = r.strip().lower()
        hit = True
        if r[:1] == "r" and r[1:].isdigit():
            n = int(r[1:])
            #
            # A NUMBER IS NOT A NAME.  LLVM spells every integer register
            # rN; the wire's vocabulary spells the three ABI-fixed ones
            # REG_ZERO / REG_SP / REG_LR, exactly as the plugin's own
            # per-ISA table does (champsim_tracer_mnemonics_mips.h:129-131,
            # _riscv.h:220-221, _aarch64.h:107).  Reading r31 as REG_GPR31
            # on mipsel made the third decoder vote "did not name it" for a
            # register it had just named -- the 220-A shape, one level up:
            # a scorer refuted by its own spelling.  Mapped here, per ISA,
            # from that table and nowhere else.
            #
            special = ABI_FIXED_GPR.get(isa, {}).get(n)
            out.add(special if special else "REG_GPR%d" % n)
        elif r[:1] == "v" and r[1:].isdigit():
            out.add("REG_VEC%s" % r[1:])
            out.add("REG_FPR%s" % r[1:])
        elif isa == "x86_64" and r in X86_GPR:
            out.add("REG_GPR%d" % X86_GPR[r])
        elif isa == "x86_64" and r in X86_SEG:
            out.add("REG_SEG%d" % X86_SEG[r])
        elif isa == "x86_64" and r.startswith("st") and r[2:].strip("()").isdigit():
            out.add("REG_FPR%s" % r[2:].strip("()"))
        elif isa == "x86_64" and r.startswith(("xmm", "ymm", "zmm")) \
                and r[3:].isdigit():
            out.add("REG_VEC%s" % r[3:])
        elif isa == "x86_64" and r.startswith("mm") and r[2:].isdigit():
            out.add("REG_VEC%s" % r[2:])
        elif isa == "mipsel" and r[:3] == "cop" and r[3:].isdigit():
            # Capstone's cop0..cop31 are the coprocessor register files;
            # the plugin's table spells every one of them REG_SYS
            # (champsim_tracer_mnemonics_mips.h:144-163).
            out.add("REG_SYS")
        elif isa == "riscv64" and r in ("vl", "vtype"):
            # champsim_tracer_mnemonics_riscv.h:181,183 -- the vector
            # configuration registers are REG_VCTRL, not an unmappable
            # spelling.  vlenb is REG_SYS and is left to the table below.
            out.add("REG_VCTRL")
        elif isa == "mipsel" and r.startswith(("f", "w")) and r[1:].isdigit():
            out.add("REG_VEC%s" % r[1:])
            out.add("REG_FPR%s" % r[1:])
        elif isa == "mipsel" and r.startswith("fcc") and r[3:].isdigit():
            out.add("REG_PRED%s" % r[3:])
        elif isa in ("riscv64", "aarch64") and r[:1] in ("x", "w") \
                and r[1:].isdigit():
            n = int(r[1:])
            out.add("REG_ZERO" if (n == 0 and isa == "riscv64")
                    else "REG_GPR%d" % n)
        elif isa in ("riscv64", "aarch64") and r[:1] in ("v", "q", "d", "s",
                                                         "z", "h", "b", "f") \
                and r[1:].isdigit():
            out.add("REG_VEC%s" % r[1:])
            out.add("REG_FPR%s" % r[1:])
        elif isa in ("riscv64", "aarch64") and r[:1] == "p" and r[1:].isdigit():
            out.add("REG_PRED%s" % r[1:])
        elif r in ("zero", "wzr", "xzr", "zr"):
            out.add("REG_ZERO")
        elif r[:2] == "ac" and r[2:].isdigit():
            out.add("REG_ACC%s" % r[2:])
        elif r[:3] == "hwr" and r[3:].isdigit():
            out.add("REG_TLS")
        elif r in ("ssp", "shadow_stack_pointer"):
            out.add("REG_SSP")
        elif r in ("ra", "lr", "x30", "w30"):
            out.add("REG_LR")
        elif r in ("sp", "wsp", "x2"):
            out.add("REG_SP")
        elif r in ("pc", "rip", "eip"):
            out.add("REG_IP")
        elif r in ("eflags", "rflags", "flags", "nzcv", "cpsr", "fflags"):
            out.add("REG_FLAGS")
        elif r in ("fcsr", "fpcr", "fpsr", "frm"):
            out.add("REG_FCSR")
        elif r in ("fpsw", "fpcw", "fpstate", "fpstatus"):
            out.add("REG_FPCW")
        elif r in ("-", ""):
            continue
        else:
            hit = False
            unmapped.add(r)
        if hit:
            out.add(r.upper())
    return out, unmapped


if __name__ == "__main__":
    sys.exit(main())
