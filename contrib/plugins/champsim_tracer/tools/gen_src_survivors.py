#!/usr/bin/env python3
"""Emit champsim_tracer_src_survivors.h from the plugin's own source census.

WHY A GENERATOR AND NOT A TABLE.  The rows below are a MEASUREMENT: for each
instruction the tracer's per-ISA decode publishes as a source and QEMU's
ordered read list does not justify, which decode rule it belongs to and how
the register is reached.  Hand-copying that measurement into a header is how
the number and the table drift apart, and the mnemonic tables in this
directory are generated for exactly that reason.  The input is the census
block the plugin prints into every stats sidecar; the output is the header
the plugin compiles.

INPUT.  One stats sidecar per ISA, each containing the block headed
"SOURCE SURVIVORS KEYED ON QEMU'S DECODE IDENTITY".  Its rows read

    <count>  <decode_id>  <rule name>  <generic register>  <role>  <mnemonic>

where <role> is SELF when the register the wire publishes as a source is also
a register the wire publishes as a DESTINATION of the same instruction, and
FIXED when it is not.  That distinction is the whole of the classification and
it is read, never guessed:

  FIXED  the register is a property of the RULE -- x86 `ret` reads SS, an
         aarch64 FP instruction reads the FP-enable gate.  The row carries the
         register's generic id, because it is the same register on every
         instruction the rule decodes.
  SELF   the register is a property of the INSTANCE -- `movlpd` merges into
         whichever XMM the encoding names, `mthc1` into whichever FPR.  The
         row carries NO register: it says "this rule's destinations are also
         its sources", and the register is read at translation time from the
         instruction's own destination list.

A rule that shows BOTH roles gets both kinds of row.

A TABLE DERIVED FROM ONE CORPUS IS A SNAPSHOT, NOT A CLOSURE, and this is
measured rather than hoped: the first table this generator emitted was built
from one workload and the plugin's own flip-cost census immediately reported
16 published sources it did not carry on the golden-net workloads -- fourteen
aarch64 FP/SIMD rules the first corpus never executed, one x86 `movsd` and
one mipsel `addu rd,rs,$zero`.  The CLASSES were right; the ROW SET was the
corpus's.  So the generator takes as many sidecars per ISA as the caller has,
and the caller is expected to hand it every corpus the tree gates on.  The
residual it cannot remove is the flip-cost census's `no-table-row` count,
which is what says how much of the population was never scored at all.

Usage:
  gen_src_survivors.py --out <header> <isa>=<stats.log> [<isa>=<stats.log> ...]

An ISA may be repeated; the rows union.
"""
import re
import sys

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")
HDR = "SOURCE SURVIVORS KEYED ON QEMU'S DECODE IDENTITY"
ROW = re.compile(r"^\s*(\d+)\s+([0-9a-f]{8})\s+(\S+)\s+(REG_\S+)\s+(SELF|FIXED)\s+(\S+)\s*$")


def parse(path):
    """Return {(decode_id, kind, reg): (rule, count, mnemonics)} for one ISA."""
    text = open(path, "r", errors="replace").read()
    if HDR not in text:
        sys.exit("FAIL %s: no survivor block -- the census did not run" % path)
    block = text.split(HDR, 1)[1]
    rows = {}
    seen_any = False
    for line in block.splitlines():
        if line.strip() == "(none)":
            return rows, True
        m = ROW.match(line)
        if not m:
            if seen_any and not line.strip():
                break
            continue
        seen_any = True
        cnt, did, rule, reg, role, mnem = m.groups()
        key = (int(did, 16), role, reg if role == "FIXED" else "")
        rule_, c, mn = rows.get(key, (rule, 0, set()))
        rows[key] = (rule, c + int(cnt), mn | {mnem})
    if not seen_any:
        sys.exit("FAIL %s: survivor block present but unparsable" % path)
    return rows, True


def main(argv):
    out = None
    inputs = {}
    i = 0
    while i < len(argv):
        if argv[i] == "--out":
            out = argv[i + 1]
            i += 2
            continue
        isa, _, path = argv[i].partition("=")
        if isa not in ISAS:
            sys.exit("unknown isa %r" % isa)
        inputs.setdefault(isa, []).append(path)
        i += 1
    if not out or sorted(inputs) != sorted(ISAS):
        sys.exit(__doc__)

    per = {}
    for isa in ISAS:
        merged = {}
        for path in inputs[isa]:
            rows, ok = parse(path)
            if not ok:
                sys.exit("FAIL %s: census absent" % path)
            for key, (rule, cnt, mn) in rows.items():
                r0, c0, m0 = merged.get(key, (rule, 0, set()))
                merged[key] = (rule, c0 + cnt, m0 | mn)
        per[isa] = merged

    w = []
    a = w.append
    a("/*")
    a(" * SOURCE SURVIVORS, per decode identity -- GENERATED, DO NOT HAND-EDIT.")
    a(" *")
    a(" * Re-emit with tools/gen_src_survivors.py; see that file for what a row")
    a(" * means and where the measurement comes from.  Every row here is a")
    a(" * register the tracer's per-ISA decode publishes as a source that QEMU's")
    a(" * ordered read list does not state -- the population R12.1 forbids")
    a(" * dropping when the source list stops being the operand walk's.")
    a(" *")
    a(" * Author: Maccoy Merrell.")
    a(" */")
    a("#ifndef CHAMPSIM_TRACER_SRC_SURVIVORS_H")
    a("#define CHAMPSIM_TRACER_SRC_SURVIVORS_H")
    a("")
    a("#include <stdint.h>")
    a("")
    a("#include \"champsim_tracer_generic_ids.h\"")
    a("")
    a("typedef enum {")
    a("    SRC_SURV_FIXED = 0,   /* @reg, the same register on every instance */")
    a("    SRC_SURV_SELF  = 1,   /* the instance's own destination registers   */")
    a("} SrcSurvivorKind;")
    a("")
    a("typedef struct {")
    a("    uint32_t decode_id;")
    a("    uint8_t  kind;        /* SrcSurvivorKind */")
    a("    uint8_t  reg;         /* generic id; REG_NONE for SRC_SURV_SELF */")
    a("    const char *rule;     /* annotation: QEMU's spelling of the rule */")
    a("} SrcSurvivorRow;")
    a("")
    a("typedef struct {")
    a("    const SrcSurvivorRow *rows;")
    a("    unsigned              n;")
    a("} SrcSurvivorTable;")
    a("")
    total = 0
    for isa in ISAS:
        rows = per[isa]
        ents = sum(v[1] for v in rows.values())
        a("/* %s -- %d row%s, %d census entr%s */"
          % (isa, len(rows), "" if len(rows) == 1 else "s",
             ents, "y" if ents == 1 else "ies"))
        if not rows:
            a("/* No array: every published source on this ISA is justified by")
            a(" * QEMU's read list, so the flip has nothing to carry.  An EMPTY")
            a(" * table is a RESULT here and the descriptor below says so with a")
            a(" * null pointer rather than a zero-length array. */")
            a("")
            continue
        a("static const SrcSurvivorRow g_src_survivors_%s[] = {" % isa)
        for (did, role, reg), (rule, cnt, mnems) in sorted(rows.items()):
            kind = "SRC_SURV_FIXED" if role == "FIXED" else "SRC_SURV_SELF"
            r = reg if role == "FIXED" else "REG_NONE"
            a("    { 0x%08xu, %-14s, %-14s, \"%s\" },   /* %s x%d */"
              % (did, kind, r, rule, ",".join(sorted(mnems)), cnt))
        a("};")
        a("")
        total += len(rows)
    a("/* Indexed by TraceISA.  A null row pointer is \"this ISA has no")
    a(" * survivors\", which is a measured answer and not a missing table. */")
    a("static const SrcSurvivorTable g_src_survivor_tables[] = {")
    a("    [TRACE_ISA_UNKNOWN] = { NULL, 0 },")
    for isa, enum in (("x86_64", "TRACE_ISA_X86"), ("aarch64", "TRACE_ISA_AARCH64"),
                      ("riscv64", "TRACE_ISA_RISCV"), ("mipsel", "TRACE_ISA_MIPS")):
        if per[isa]:
            a("    [%-17s] = { g_src_survivors_%s," % (enum, isa))
            a("                            G_N_ELEMENTS(g_src_survivors_%s) }," % isa)
        else:
            a("    [%-17s] = { NULL, 0 }," % enum)
    a("};")
    a("")
    a("/* %d rows over the four ISAs. */" % total)
    a("")
    a("#endif /* CHAMPSIM_TRACER_SRC_SURVIVORS_H */")
    open(out, "w").write("\n".join(w) + "\n")
    print("wrote %s: %d rows" % (out, total))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
