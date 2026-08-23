"""Rank-2 (LLVM MC) rows for opcodes the 2022-12 MRA release does not name.
One row per distinct OPERAND SHAPE, shape = the disassembly with every
register number and immediate erased -- the same "fields are generic"
rule the MRA rows use, applied to a decoder instead of a spec."""
import sys, re, csv
want = set(open('gap_mnemonics.txt').read().split())
num = re.compile(r'\b([wxzpvbhsdq])\d+\b|#-?(0x)?[0-9a-f.]+|\bza\d+|\[w\d+')
def shape(t):
    t = num.sub(lambda m: (m.group(1) + 'N') if m.group(1) else '#', t)
    return re.sub(r'\s+', ' ', t).strip()
best = {}
r = csv.DictReader(sys.stdin, delimiter='\t')
for row in r:
    if row['l_ok'] != '1':
        continue
    t = row['l_text']
    mn = t.split()[0].lower() if t else ''
    if mn not in want:
        continue
    k = (mn, shape(t))
    if k not in best:
        best[k] = row['hex']
w = csv.writer(open('gap_rows.tsv', 'w'), delimiter='\t', lineterminator='\n')
for (mn, sh), hx in sorted(best.items()):
    w.writerow([mn, sh, hx])
sys.stderr.write("gap shapes %d over %d mnemonics\n" % (len(best), len({k[0] for k in best})))
