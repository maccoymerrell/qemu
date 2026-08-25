#!/usr/bin/env python
"""Fold the harvested rank-2 rows to the same C3 granularity the MRA rows use
-- register VALUES (including SP/ZR), immediates, element indices and memory
displacements are generic FIELDS, not shapes -- then append them to
opcodes.tsv as the post-2022-12 tail of the denominator."""
import csv, re, subprocess, collections
ISAX = "/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck"

def batch(hexes):
    p = subprocess.run([ISAX, "--isa=aarch64", "--batch"],
                       input="\n".join(hexes) + "\n", capture_output=True, text=True)
    return {r["hex"]: r for r in csv.DictReader(p.stdout.splitlines(), delimiter="\t")}

REG   = re.compile(r'\b([wxzpvbhsdq])\d+\b')
ZRSP  = re.compile(r'\b(?:sp|wsp|xzr|wzr)\b')
ZA    = re.compile(r'\bza\d*[a-z]*\b')
IMM   = re.compile(r'#-?(?:0x)?[0-9a-fA-F]+(?:\.[0-9]+)?')
BRK   = re.compile(r'\[[^\]]*\]')
SHIFT = re.compile(r',\s*(?:lsl|lsr|asr|ror|msl|uxtb|uxth|uxtw|uxtx|sxtb|sxth|sxtw|sxtx)\b\s*#?')
def shape(t):
    s = t.lower()
    s = BRK.sub('[F]', s)
    s = ZRSP.sub('rN', s)
    s = ZA.sub('za', s)
    s = REG.sub(lambda m: m.group(1) + 'N', s)
    s = IMM.sub('#', s)
    s = SHIFT.sub(', SH', s)
    return re.sub(r'\s+', ' ', s).strip()

raw = list(csv.reader(open('gap_rows.tsv'), delimiter='\t'))
dec = batch([r[2] for r in raw])
best = collections.OrderedDict()
for mn, _sh, hx in raw:
    d = dec.get(hx, {})
    t = (d.get("l_text") or "").strip()
    best.setdefault((mn, shape(t)), (t, hx, d))
print("gap shapes: harvested %d -> C3-folded %d over %d mnemonics"
      % (len(raw), len(best), len({k[0] for k in best})))
nl = sum(1 for _, (_t, _h, d) in best.items() if d.get("l_ok") == "1")
nb = sum(1 for _, (_t, _h, d) in best.items() if d.get("b_ok") == "1")
print("gap rows: %d, LLVM decodes %d, Capstone decodes %d" % (len(best), nl, nb))

rows = list(csv.reader(open('opcodes.tsv'), delimiter='\t'))
head, body = rows[0], [r for r in rows[1:] if not r[3].startswith("LLVM-MC")]
have = {r[2] for r in body}
n, add = collections.Counter(), []
for (mn, sh), (t, hx, d) in best.items():
    if hx in have:
        continue
    n[mn] += 1
    add.append(["LLVM_MC:%s_%d" % (mn.upper(), n[mn]), mn, hx,
                "LLVM-MC-18(+all) rank-2: post-2022-12 architecture addition",
                sh, "post-2022-12", "", "", mn, "",
                "yes" if d.get("l_ok") == "1" else "NO", t,
                d.get("b_mnem") or "", t, ""])
with open('opcodes.tsv', 'w') as f:
    w = csv.writer(f, delimiter='\t', lineterminator='\n')
    w.writerow(head)
    for r in sorted(body + add, key=lambda r: r[0]):
        w.writerow(r)
print("MRA rows %d + rank-2 rows %d = %d" % (len(body), len(add), len(body) + len(add)))
