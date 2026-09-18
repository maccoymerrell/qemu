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

# ---- THE ATTRIBUTION JOIN, COMPLETED (FINDING 246-C) ------------------------
#
# WHAT WAS WRONG.  The tracer arm answers per encoding with a register set AND
# an `ident` -- `seated`, `refused:<why>` or `unreached` -- and this file used
# to read only the set.  An encoding the sled built no chain for therefore
# arrived as SRC{} DST{}, which is the wire's spelling for "this instruction
# touches no register", and every one of them scored as a DISAGREEMENT with
# the whole reference set missing.  MEASURED at the exec246 tip: 733 of the
# leg's 906 disagreements had two empty tracer sets, so 81% of the headline
# was a silence read as an attribution.  A silence is not an attribution in
# either direction (sled_fields.py says the same thing about the other one).
#
# WHAT DECIDES A ROW NOW, AND IT IS QEMU.  Two facts, both from the capture:
# the ident, and QEMU's own DECODE RULE for the encoding.  Read together they
# name the class without a judgement call:
#
#   rule `#undecoded`  -- QEMU's mipsel decoder matched NO rule.  No QEMU
#       guest executes this encoding as an instruction, so the row is
#       UNPROBED and out of scope: qemu_tcg_reachable=no.  MEASURED: 217.
#
#   rule `OPC_MDMX`    -- the MSA opcode space.  decode_opc() tries
#       `ase_msa_available(env) && decode_ase_msa(...)` FIRST
#       (target/mips/tcg/translate.c:15663) and ase_msa_available() reads
#       CP0_Config3.MSAP (target/mips/cpu.h:1379) -- a CPU-MODEL property.
#       On a model without it the encoding falls through to the legacy
#       switch's `case OPC_MDMX: /* MDMX: Not implemented. */ break;`
#       (translate.c:15608), which emits nothing, so the empty set is the
#       honest answer FOR THAT MACHINE.  QEMU does implement MSA, so a guest
#       on an MSAP model runs these: qemu_tcg_reachable=yes, a real coverage
#       HOLE in this leg and not a tracer loss.  MEASURED: 515 (+1 OPC_PMON).
#       THE CAPTURE CANNOT SIMPLY BE MOVED TO SUCH A MODEL: every MSA-capable
#       mipsel model is 2008-NaN-only and the sled's guest image carries the
#       legacy NaN flag, so linux-user/mips/cpu_loop.c refuses it -- measured
#       here as `ELF binary's NaN mode not supported by CPU` on P5600 and
#       mips32r6-generic.  srcenc_sled.py already has `--nan2008` for exactly
#       this, with its own measured A/B; wiring it through ident_capture.sh is
#       the fix path and it is NOT done here.
#
# Rows the comparison DID reach keep their verdict unchanged; nothing about
# the 173 real disagreements moves.
_TRACER_IDENT, _QEMU_RULE = {}, {}
try:
    _P = json.load(open(W + "parsed.json"))
    _TRACER_IDENT = {k: v.get("ident", "absent")
                     for k, v in _P.get("tracer", {}).items()}
except (IOError, ValueError):
    pass
_CAP = os.environ.get("CST_SLED_CAPTURE", "")
if _CAP:
    try:
        for _l in open(os.path.join(_CAP, "ident_mipsel.tsv")):
            if _l.startswith("#"):
                continue
            _c = _l.rstrip("\n").split("\t")
            if len(_c) >= 4:
                _QEMU_RULE[_c[1].lower()] = _c[3]
    except IOError:
        pass
if not _TRACER_IDENT or not _QEMU_RULE:
    sys.exit("emit: no tracer ident (%d) or QEMU rule (%d) to join on -- "
             "REFUSING.  Without both, a row the sled never reached is "
             "indistinguishable from an instruction that reads no register, "
             "and this table would publish 733 silences as disagreements "
             "again (FINDING 246-C).  parsed.json comes from parse.py and the "
             "rule column from CST_SLED_CAPTURE/ident_mipsel.tsv."
             % (len(_TRACER_IDENT), len(_QEMU_RULE)))

# NON-EMPTY IS NOT THE SAME AS JOINED.  Both sides above are keyed -- the
# ident by the probe row's opcode id, the rule by the encoding -- and a
# dictionary that is full of the WRONG keys answers `absent` / `#undecoded`
# to every lookup, which is exactly the shape that would relabel all 733
# silences as `qemu-no-decode-rule` and report the leg as clean.  So the join
# is checked against the rows it is about to classify, not merely counted.
_UNJOINED_IDENT = [r["id"] for r in rows if r["id"] not in _TRACER_IDENT]
_UNJOINED_RULE = [r["hex"] for r in rows if r["hex"].lower() not in _QEMU_RULE]
if _UNJOINED_IDENT or _UNJOINED_RULE:
    sys.exit("emit: the attribution join does not cover this table -- "
             "REFUSING.\n  %d of %d rows have no tracer ident (first: %s)\n"
             "  %d of %d rows have no QEMU rule (first: %s)\n"
             "  A lookup that misses answers with the same words a genuine "
             "silence uses, so\n  an unjoined table would publish every "
             "empty row as 'QEMU matched no rule'."
             % (len(_UNJOINED_IDENT), len(rows), _UNJOINED_IDENT[:3] or '-',
                len(_UNJOINED_RULE), len(rows), _UNJOINED_RULE[:3] or '-'))
# AND THE IDENT COLUMN HAS TO SAY SOMETHING.  parse.py fills it from the
# `ident=` line sled_fields.py prints; a parser that stopped matching that line
# would hand every row the word `absent`, which reads as a silence the tracer
# never explained.  The default filling the whole column is the failure, so it
# is the condition.
if all(v == "absent" for v in _TRACER_IDENT.values()):
    sys.exit("emit: every one of %d tracer rows carries ident='absent' -- "
             "REFUSING.  That is parse.py's default, not an answer: the "
             "`ident=` line sled_fields.py prints is no longer being read, and "
             "no row below could be told apart from one the sled never "
             "reached." % len(_TRACER_IDENT))


def unprobed_reason(r):
    """-> (mechanism, qemu_tcg_reachable) when the arm reached nothing, else None.

    QEMU'S OWN DECODE RULE DECIDES FIRST, and the tracer's ident only where the
    rule leaves the question open.  Taking them the other way round would let
    an MSA encoding the sled happened not to seat be reported as 'QEMU matched
    no rule' -- a statement about QEMU that QEMU's own identity corpus
    contradicts on the very same row.  MEASURED at this tip the two never
    disagree (515 OPC_MDMX + 1 OPC_PMON all `seated`, 217 #undecoded all
    `unreached`), which is why the order is a correctness choice and not a
    difference in today's numbers.
    """
    ident = _TRACER_IDENT.get(r["id"], "absent")
    rule = _QEMU_RULE.get(r["hex"].lower(), "#undecoded")
    if set(r["tr_src"]) or set(r["tr_dst"]):
        return None                       # the arm answered; score it
    if rule in ("OPC_MDMX", "OPC_PMON"):
        return ("ase-absent-on-capture-cpu", "yes")
    if rule == "#undecoded":
        return ("qemu-no-decode-rule", "no")
    if ident in ("unreached", "absent"):
        return ("sled-never-reached", "yes")
    if ident.startswith("refused:"):
        return ("seating-" + ident, "yes")
    return None                           # a genuinely empty set QEMU stated

def s(x): return ",".join(sorted(x)) if x else "-"
def cls(x): return re.sub(r"\d+", "N", x).replace("REG_", "")

recs = []
for r in rows:
    rs, rd = set(r["adj_src"]), set(r["adj_dst"])
    ts, td = set(r["tr_src"]), set(r["tr_dst"])
    unp = unprobed_reason(r)
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
    recs.append(dict(r, verdict=("UNPROBED" if unp else
                                 ("AGREE" if ok else "DISAGREE")),
                     sig=" ".join(p) if p else "-", relation=rel,
                     mechanism=unp[0] if unp else "-",
                     reachable=unp[1] if unp else "-",
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
        "set_relation","direction","category","accounted",
        "qemu_tcg_reachable","mechanism"]
with open(BASE + "attrib.tsv", "w") as f:
    f.write("#" + "\t".join(cols) + "\n")
    for r in sorted(recs, key=lambda x: x["id"]):
        f.write("\t".join([r["id"], r["mnem_key"], r["hex"], r["verdict"], r["sig"],
                           s(r["adj_src"]), s(r["adj_dst"]), s(r["tr_src"]), s(r["tr_dst"]),
                           r["ms"], r["es"], r["md"], r["ed"],
                           ",".join(r["rules"]) or "-",
                           r["llvm_opcode"], r["asm"], " ".join(r["bu"]) or "-",
                           r["relation"], r["direction"], r["category"],
                           r["accounted"], r["reachable"],
                           r["mechanism"]]) + "\n")

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

unpro = collections.Counter((r["mechanism"], r["reachable"]) for r in recs
                            if r["verdict"] == "UNPROBED")
dis = sum(1 for r in recs if r["verdict"] == "DISAGREE")
print("attempted=%d agree=%d disagree=%d unprobed=%d"
      % (len(recs), agree, dis, sum(unpro.values())))
for (m, reach), n in unpro.most_common():
    print("  UNPROBED %-30s qemu_tcg_reachable=%-3s %d" % (m, reach, n))
print("distinct disagreement signatures: %d" % len(sig))
for k, v in sorted(sig.items(), key=lambda kv: -len(kv[1])):
    print("  %4d  %s" % (len(v), k))
