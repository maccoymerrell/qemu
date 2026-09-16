"""Emit the per-opcode attribution table and the signature summary."""
import os, json, re, collections, sys
_D = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _D)
from adjudicate import RULES

# The two-axis taxonomy is shared by all four ISA harnesses.  A harness runs
# from a working copy beside its evidence, so look there first and fall back to
# the tree, which is the source of truth.
_TOOLS = os.environ.get(
    'CST_ARC3_TOOLS',
    '/mnt/md0/QEMU/qemu/contrib/plugins/champsim_tracer/tools/arc3_cov')
for _p in (_D, os.path.dirname(_D), os.path.dirname(os.path.dirname(_D)),
           _TOOLS):
    if os.path.exists(os.path.join(_p, 'arc3_taxonomy.py')):
        if _p not in sys.path:
            sys.path.insert(0, _p)
        break
else:
    sys.exit('arc3_taxonomy.py not found (set CST_ARC3_TOOLS)')
import arc3_taxonomy as tax
import arc3_rules as taxrules

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
    # ---- the two axes.  DIRECTION is measured from the very sets the verdict
    # was taken from, so it cannot drift from it.  adjudicate.RULES build the
    # REFERENCE; they are not disagreement adjudications, so a mipsel
    # disagreement is UNACCOUNTED until a disagreement-adjudication table
    # exists for this ISA (arc3_rules.MIPSEL).
    rel = tax.set_relation(rs, rd, ts, td)
    recs.append(dict(r, verdict="AGREE" if ok else "DISAGREE",
                     sig=" ".join(p) if p else "-", relation=rel,
                     ms=s(rs - ts), es=s(ts - rs), md=s(rd - td), ed=s(td - rd)))

tax_rows, tax_labels = [], collections.Counter()
for r in recs:
    if r["verdict"] != "DISAGREE":
        r["direction"] = r["category"] = "-"
        r["accounted"] = "-"
        continue
    lab = ",".join(r["rules"]) or "-"
    tax_labels[lab] += 1
    t = tax.classify(r["id"], r["mnem_key"], lab, r["relation"],
                     taxrules.mipsel_rule(lab))
    tax_rows.append(t)
    r["direction"], r["category"] = t.direction, t.category
    r["accounted"] = "1" if t.accounted else "0"

cols = ["opcode_id","mnemonic","encoding_hex_le","verdict","signature",
        "ref_src","ref_dst","tracer_src","tracer_dst",
        "missing_src","extra_src","missing_dst","extra_dst",
        "adjudication_rules","llvm_mc_opcode","llvm_mc_asm","binutils_pinfo",
        "set_relation","direction","category","accounted"]
with open(BASE + "attrib.tsv", "w") as f:
    f.write("#" + "\t".join(cols) + "\n")
    for r in sorted(recs, key=lambda x: x["id"]):
        f.write("\t".join([r["id"], r["mnem_key"], r["hex"], r["verdict"], r["sig"],
                           s(r["adj_src"]), s(r["adj_dst"]), s(r["tr_src"]), s(r["tr_dst"]),
                           r["ms"], r["es"], r["md"], r["ed"],
                           ",".join(r["rules"]) or "-",
                           r["llvm_opcode"], r["asm"], " ".join(r["bu"]) or "-",
                           r["relation"], r["direction"], r["category"],
                           r["accounted"]]) + "\n")

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
taxtxt = ["=" * 78,
          "TWO-AXIS CLASSIFICATION OF THE %d DISAGREEING ROWS"
          % (len(recs) - agree), "=" * 78, ""]
for d in tax.DIRECTIONS:
    taxtxt.append("  %-16s %s" % (d, tax.DIRECTION_VERDICT[d]))
taxtxt += ["", tax.render_crosstab(tax_rows,
                                   "CROSS-TABULATION  direction x category"),
           "", tax.render_conflicts(tax_rows), tax.render_unaccounted(tax_rows)]
taxtxt.append("LABELS WITH NO RULE  (an adjudication the taxonomy does not map")
taxtxt.append("is not an explanation; its rows are UNACCOUNTED above)")
_nr = [(k, n) for k, n in tax_labels.most_common()
       if taxrules.mipsel_rule(k) is None]
for k, n in _nr:
    taxtxt.append("  %6d  %s" % (n, k))
if not _nr:
    taxtxt.append("  (none)")
taxtxt.append("")
taxtxt.append("MEMOP ATTRIBUTION  (count / address / data for every load and")
taxtxt.append("store) is HALF the deliverable and this harness measures none of")
taxtxt.append("it.  Reported as a hole, not implied to be covered by the")
taxtxt.append("register numbers below.")
taxtxt = "\n".join(taxtxt) + "\n"
print(taxtxt)
open(BASE + "attrib_taxonomy.txt", "w").write(taxtxt)

print("attempted=%d agree=%d disagree=%d unprobed=0" % (len(recs), agree, len(recs) - agree))
print("distinct disagreement signatures: %d" % len(sig))
for k, v in sorted(sig.items(), key=lambda kv: -len(kv[1])):
    print("  %4d  %s" % (len(v), k))
