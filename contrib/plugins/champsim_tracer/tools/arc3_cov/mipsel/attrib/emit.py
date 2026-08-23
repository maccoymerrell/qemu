"""Emit the per-opcode attribution table and the signature summary."""
import os, json, re, collections, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from adjudicate import RULES

W = os.environ.get("CST_ARC3_ATTRIB_DIR", os.getcwd()).rstrip("/") + "/"
BASE = os.path.dirname(W.rstrip("/")) + "/"
rows = json.load(open(W + "rows_adj.json"))

def s(x): return ",".join(sorted(x)) if x else "-"
def cls(x): return re.sub(r"\d+", "N", x).replace("REG_", "")

recs = []
for r in rows:
    rs, rd = set(r["adj_src"]), set(r["adj_dst"])
    ts, td = set(r["tr_src"]), set(r["tr_dst"])
    ok = (rs == ts and rd == td)
    p = []
    if rs - ts: p.append("SRC-miss{%s}" % ",".join(sorted(set(map(cls, rs - ts)))))
    if ts - rs: p.append("SRC-extra{%s}" % ",".join(sorted(set(map(cls, ts - rs)))))
    if rd - td: p.append("DST-miss{%s}" % ",".join(sorted(set(map(cls, rd - td)))))
    if td - rd: p.append("DST-extra{%s}" % ",".join(sorted(set(map(cls, td - rd)))))
    recs.append(dict(r, verdict="AGREE" if ok else "DISAGREE",
                     sig=" ".join(p) if p else "-",
                     ms=s(rs - ts), es=s(ts - rs), md=s(rd - td), ed=s(td - rd)))

cols = ["opcode_id","mnemonic","encoding_hex_le","verdict","signature",
        "ref_src","ref_dst","tracer_src","tracer_dst",
        "missing_src","extra_src","missing_dst","extra_dst",
        "adjudication_rules","llvm_mc_opcode","llvm_mc_asm","binutils_pinfo"]
with open(BASE + "attrib.tsv", "w") as f:
    f.write("#" + "\t".join(cols) + "\n")
    for r in sorted(recs, key=lambda x: x["id"]):
        f.write("\t".join([r["id"], r["mnem_key"], r["hex"], r["verdict"], r["sig"],
                           s(r["adj_src"]), s(r["adj_dst"]), s(r["tr_src"]), s(r["tr_dst"]),
                           r["ms"], r["es"], r["md"], r["ed"],
                           ",".join(r["rules"]) or "-",
                           r["llvm_opcode"], r["asm"], " ".join(r["bu"]) or "-"]) + "\n")

sig = collections.defaultdict(list)
for r in recs:
    if r["verdict"] == "DISAGREE": sig[r["sig"]].append(r)
agree = sum(1 for r in recs if r["verdict"] == "AGREE")

with open(BASE + "attrib_signatures.tsv", "w") as f:
    f.write("#count\tsignature\trules\topcodes\n")
    for k, v in sorted(sig.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        rl = sorted(set(x for r in v for x in r["rules"]))
        f.write("%d\t%s\t%s\t%s\n" % (len(v), k, ",".join(rl) or "-",
                                      " ".join(sorted(r["mnem_key"] for r in v))))
print("attempted=%d agree=%d disagree=%d unprobed=0" % (len(recs), agree, len(recs) - agree))
print("distinct disagreement signatures: %d" % len(sig))
for k, v in sorted(sig.items(), key=lambda kv: -len(kv[1])):
    print("  %4d  %s" % (len(v), k))
