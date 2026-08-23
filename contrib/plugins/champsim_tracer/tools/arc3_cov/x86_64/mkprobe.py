#!/usr/bin/env python3
"""Build the per-opcode probe set: the denominator encoding, except that an
EVEX opcode carrying a mask slot is re-probed with aaa=001 so the mask
operand is actually exercised (C3).  A variant is accepted only when XED
still decodes it to the same iform at the same length.  Author: Maccoy Merrell."""
import json, subprocess, os
D = os.path.dirname(os.path.abspath(__file__))
rows = [l.rstrip('\n').split('\t') for l in open(os.path.join(D, '..', 'opcodes.tsv'))][1:]

cand = {}
for opid, mnem, hexs, src in rows:
    b = bytes.fromhex(hexs)
    if len(b) >= 4 and b[0] == 0x62 and 'MASKmskw' in opid and (b[3] & 7) == 0:
        v = bytearray(b); v[3] |= 1
        cand[hexs] = v.hex()

def iforms(hexlist):
    p = subprocess.run([os.path.join(D, 'xediform')],
                       input=''.join(h + '\n' for h in hexlist),
                       capture_output=True, text=True, check=True)
    out = {}
    for line in p.stdout.splitlines()[1:]:
        h, ok, ln, ifm = line.split('\t')
        out[h] = (ok, ln, ifm)
    return out

base, var = list(cand.keys()), list(cand.values())
old, new = iforms(base), iforms(var)
accept = {b: v for b, v in zip(base, var)
          if new.get(v) and old.get(b) and new[v][0] == '1'
          and new[v][1:] == old[b][1:]}
print('EVEX mask-slot opcodes with aaa=000 : %d' % len(cand))
print('variant keeps same iform and length : %d  (rejected %d)'
      % (len(accept), len(cand) - len(accept)))

probe = {opid: accept.get(hexs, hexs) for opid, mnem, hexs, src in rows}
json.dump(probe, open(os.path.join(D, 'probe_map.json'), 'w'))
u = sorted(set(probe.values()))
open(os.path.join(D, 'probe_uniq.hex'), 'w').write(''.join(h + '\n' for h in u))
print('opcodes %d  unique probe encodings %d' % (len(probe), len(u)))
