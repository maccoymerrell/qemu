"""Build the rank-1 (LLVM MC) reference operand set, desc-complete."""
import os, json, sys, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from canon import canon, canon_set, drop

BASE = os.environ.get("CST_ARC3_ATTRIB_DIR", os.getcwd()).rstrip("/") + "/"
d = json.load(open(BASE + "parsed.json"))
L, B, T = d["llvm"], d["bu"], d["tracer"]

def llvm_sets(e):
    """Walk MCInstrDesc (not MCInst) so an unmaterialised TIED operand still
    contributes its read edge -- the LWL/MOVF read-modify-write case."""
    ops = {o["i"]: o for o in e["ops"]}
    src, dst = set(), set()
    for ds in e["dsc"]:
        i = ds["i"]
        o = ops.get(i)
        # A tied USE names the register of the DEF it is tied to.
        if ds["tied"] is not None and (o is None or o["kind"] != "reg"):
            o = ops.get(ds["tied"])
        if o is None or o["kind"] != "reg":
            continue
        g = canon_set(o["val"])
        if ds["role"].startswith("DEF"):
            dst |= g
        else:
            src |= g
        if ds["tied"] is not None:
            # RMW: the destination is also a source (R5/C4).
            td = ops.get(ds["tied"])
            if td is not None and td["kind"] == "reg":
                src |= canon_set(td["val"])
    # Variadic operands beyond the descriptor.
    for i, o in ops.items():
        if i >= len(e["dsc"]) and o["kind"] == "reg":
            tgt = dst if e["flags"].get("variadicOpsAreDefs") else src
            tgt |= canon_set(o["val"])
    for r in e["impuse"]: src |= canon_set(r)
    for r in e["impdef"]: dst |= canon_set(r)
    return drop(src), drop(dst)

def canon_set_all(names):
    """Canonicalise a list of LLVM register names into generic ids."""
    out = set()
    for r in names:
        out |= canon_set(r)
    return out


BU_IMPLIED_SRC = {"RD_HI":"HI", "RD_LO":"LO", "RD_$31":"REG_LR", "RD_$29":"REG_SP",
                  "RD_$24":"REG_GPR24", "RD_$16":"REG_GPR16", "RD_CC":"FCC"}
BU_IMPLIED_DST = {"WR_HI":"HI", "WR_LO":"LO", "WR_$31":"REG_LR", "WR_$29":"REG_SP",
                  "WR_$24":"REG_GPR24", "WR_CC":"FCC"}

def bu_flags(e):
    """Union the pinfo of every matching binutils row (the hit and its alts)."""
    f = set()
    for r in e["rows"]:
        f |= set(r["pinfo"]) | set(r["pinfo2"])
    return f

rows = []
for oid in sorted(L):
    e = L[oid]
    src, dst = llvm_sets(e)
    tr = T[oid]
    tsrc, tdst = drop(set(tr["src"])), drop(set(tr["dst"]))
    rows.append(dict(id=oid, word=e["word"], hex=tr["hex"], llvm_opcode=e["opcode"],
                     asm=e["asm"], mnem=tr["mnem"],
                     ref_src=sorted(src), ref_dst=sorted(dst),
                     tr_src=sorted(tsrc), tr_dst=sorted(tdst),
                     bu=sorted(bu_flags(B[oid])),
                     tr_opcode=tr["opcode"], tr_branch=tr["branch"],
                     loads=tr["loads"], stores=tr["stores"],
                     mayLoad=e["flags"].get("mayLoad"), mayStore=e["flags"].get("mayStore"),
                     isCall=e["flags"].get("isCall"), isBranch=e["flags"].get("isBranch"),
                     # The IMPLICIT halves of the LLVM record, kept as their
                     # own fields.  An adjudication about an implicit operand
                     # has to be able to SEE that the operand is implicit;
                     # without this the L-AT rule could only be written as a
                     # list of mnemonics, and a list is how 23 of its 27 rows
                     # went unhandled.
                     imp_src=sorted(canon_set_all(e["impuse"])),
                     imp_dst=sorted(canon_set_all(e["impdef"]))))
json.dump(rows, open(BASE + "rows_raw.json", "w"), indent=0)

unmapped = collections.Counter()
for r in rows:
    for x in r["ref_src"] + r["ref_dst"]:
        if x.startswith("UNMAPPED"): unmapped[x] += 1
print("rows=%d unmapped=%s" % (len(rows), dict(unmapped)))

# raw agreement, before adjudication
agree = sum(1 for r in rows if set(r["ref_src"]) == set(r["tr_src"])
            and set(r["ref_dst"]) == set(r["tr_dst"]))
print("raw LLVM-vs-tracer exact set match: %d / %d" % (agree, len(rows)))
