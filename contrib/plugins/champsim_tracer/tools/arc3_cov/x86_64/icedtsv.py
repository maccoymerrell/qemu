#!/usr/bin/env python3
"""iced-x86 canonical elaborator -- same TSV schema as xl3.  ARC 3.
Canonicalisation follows R1-R5 and R7.1: largest enclosing register (R4); a
CONDITIONAL write implies a preserved-value read (R4 -- a false condition
really does leave the old value in place, so the instruction takes its
destination as a source); but under R7.1-NARROW a sub-width write does NOT
imply a read of the enclosing register, and a partial flag write does NOT
imply an RFLAGS read.  Both are still DETECTED and counted -- see xl3.cc for
the ruling in full and for why an inert rule is a finding."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "pylib"))
from iced_x86 import (Decoder, InstructionInfoFactory, OpAccess, Register,
                      RegisterInfo, RflagsBits, Code, EncodingKind)

REGNAME = {v: k for k, v in vars(Register).items()
           if not k.startswith("_") and isinstance(v, int)}
ALL6 = (RflagsBits.CF | RflagsBits.PF | RflagsBits.AF |
        RflagsBits.ZF | RflagsBits.SF | RflagsBits.OF)

def canon(reg):
    """Largest enclosing register name, plus whether reg was a sub-register
    and whether it is a 32-bit GPR (which zero-extends on write)."""
    try:
        ri = RegisterInfo(reg)
    except Exception:
        return REGNAME.get(reg, str(reg)), False, False
    full = ri.full_register
    name = REGNAME.get(full, str(full))
    sub = (full != reg)
    gpr32 = (ri.size == 4 and RegisterInfo(full).size == 8 and
             RegisterInfo(full).base == RegisterInfo(Register.RAX).base)
    return name, sub, gpr32

VECZ = (EncodingKind.VEX, EncodingKind.EVEX, EncodingKind.MVEX, EncodingKind.XOP)

# R7.1-SCALAR.  iced carries the same conflation XED does: a legacy scalar
# SSE form's destination is reported READ_WRITE whether the read is the
# operation's own operand (ADDSD) or only the surviving upper lanes
# (SQRTSD).  The ten unary iclasses -- derived from the WHOLE 24-iclass
# legacy simd_scalar class in xed-isa.txt, not from the rows that disagreed
# -- take no read.  See xl3.cc for the derivation and the other fourteen.
SCALAR_UNARY = ("CVTSD2SS", "CVTSI2SD", "CVTSI2SS", "CVTSS2SD", "RCPSS",
                "ROUNDSD", "ROUNDSS", "RSQRTSS", "SQRTSD", "SQRTSS")

# R7.1-NARROW: preserve-reads DETECTED and SUPPRESSED.  Reported on stderr.
SUP = {"subwidth": 0, "partialflag": 0, "scalarunary": 0}


def elab(data):
    dec = Decoder(64, data, ip=0x100000)
    if not dec.can_decode:
        return None
    ins = dec.decode()
    if ins.is_invalid:
        return None
    src, dst = set(), set()
    vex = ins.encoding in VECZ
    info = InstructionInfoFactory().info(ins)
    for u in info.used_registers():
        name, sub, gpr32 = canon(u.register)
        a = u.access
        rd = a in (OpAccess.READ, OpAccess.COND_READ, OpAccess.READ_WRITE,
                   OpAccess.READ_COND_WRITE)
        wr = a in (OpAccess.WRITE, OpAccess.COND_WRITE, OpAccess.READ_WRITE,
                   OpAccess.READ_COND_WRITE)
        cw = a in (OpAccess.COND_WRITE, OpAccess.READ_COND_WRITE)
        if rd: src.add(name)
        if wr: dst.add(name)
        if cw: src.add(name)                       # R5 preserved value
        vec = name.startswith("ZMM") or name.startswith("YMM") or name.startswith("XMM")
        # R7.1-NARROW: the enclosing register's surviving bits are not a source.
        if wr and sub and not gpr32 and not (vec and vex): SUP["subwidth"] += 1
    # R7.1-SCALAR: drop the destination's preserve-read, unless the same
    # register is genuinely named again by another operand or by the memory
    # operand's addressing registers.
    if ins.encoding == EncodingKind.LEGACY:
        code_name = CODENAME.get(ins.code, "")
        if code_name.split("_")[0] in SCALAR_UNARY:
            d0 = ins.op0_register
            if d0 != Register.NONE:
                dn = canon(d0)[0]
                others = set()
                for i in range(1, ins.op_count):
                    r = ins.op_register(i)
                    if r != Register.NONE:
                        others.add(canon(r)[0])
                for m in info.used_memory():
                    for r in (m.base, m.index):
                        if r != Register.NONE:
                            others.add(canon(r)[0])
                if dn not in others and dn in src:
                    src.discard(dn)
                    SUP["scalarunary"] += 1
    memparts = []
    for m in info.used_memory():
        for r in (m.base, m.index):
            if r != Register.NONE: src.add(canon(r)[0])
        if m.segment != Register.NONE: src.add(REGNAME.get(m.segment, "?"))
        acc = m.access
        r = "R" if acc in (OpAccess.READ, OpAccess.COND_READ, OpAccess.READ_WRITE,
                           OpAccess.READ_COND_WRITE) else "-"
        w = "W" if acc in (OpAccess.WRITE, OpAccess.COND_WRITE, OpAccess.READ_WRITE,
                           OpAccess.READ_COND_WRITE) else "-"
        memparts.append(f"{r}{w}{ins.memory_size}")
    wrm = ins.rflags_written | ins.rflags_cleared | ins.rflags_set | ins.rflags_undefined
    if ins.rflags_read: src.add("RFLAGS")
    if wrm:
        dst.add("RFLAGS")
        # R7.1-NARROW, flag bank: a partial flag write reads nothing.
        if (wrm & ALL6) != ALL6: SUP["partialflag"] += 1
    return (ins.len, ins.code, sorted(src), sorted(dst), ";".join(memparts) or "-")

CODENAME = {v: k for k, v in vars(Code).items()
            if not k.startswith("_") and isinstance(v, int)}

def main():
    out = sys.stdout
    out.write("hex\ttool\tok\tlen\tmnem\tsrc\tdst\tmem\n")
    with open(sys.argv[1]) as f:
        for line in f:
            h = line.strip()
            if not h:
                continue
            try:
                data = bytes.fromhex(h)
            except ValueError:
                continue
            r = elab(data)
            if r is None:
                out.write(f"{h}\tICED\t0\t0\t-\t-\t-\t-\n")
            else:
                L, code, s, d, m = r
                out.write(f"{h}\tICED\t1\t{L}\t{CODENAME.get(code,code)}\t"
                          f"{','.join(s) or '-'}\t{','.join(d) or '-'}\t{m}\n")
    sys.stderr.write("[R7.1-NARROW suppressed preserve-reads] "
                     f"iced-subwidth={SUP['subwidth']} "
                     f"iced-partialflag={SUP['partialflag']} "
                     f"iced-scalarunary={SUP['scalarunary']}\n")

if __name__ == "__main__":
    main()
