"""Build the rank-1 (LLVM MC) reference operand set, desc-complete."""
import os, json, sys, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from canon import canon, drop

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
        g = canon(o["val"])
        if ds["role"].startswith("DEF"):
            dst.add(g)
        else:
            src.add(g)
        if ds["tied"] is not None:
            # RMW: the destination is also a source (R5/C4).
            td = ops.get(ds["tied"])
            if td is not None and td["kind"] == "reg":
                src.add(canon(td["val"]))
    # Variadic operands beyond the descriptor.
    for i, o in ops.items():
        if i >= len(e["dsc"]) and o["kind"] == "reg":
            (dst if e["flags"].get("variadicOpsAreDefs") else src).add(canon(o["val"]))
    for r in e["impuse"]: src.add(canon(r))
    for r in e["impdef"]: dst.add(canon(r))
    return drop(src), drop(dst)

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
                     isCall=e["flags"].get("isCall"), isBranch=e["flags"].get("isBranch")))
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
