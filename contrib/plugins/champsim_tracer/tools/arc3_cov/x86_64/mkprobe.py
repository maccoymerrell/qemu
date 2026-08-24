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

# A PROBE ENCODING THE REFERENCE DECODER REFUSES IS NOT A PROBE.  The
# denominator's encoding for XED_IFORM_UD0 is `0fff`, two bytes -- and UD0 is
# 0F FF /r, so the ModRM is missing and XED's own decoder rejects what its own
# tables produced.  The row then reaches the comparison as a "reference decode
# gap", which is not a verdict: it is one opcode with no comparison at all.
# Complete such an encoding with a register-form ModRM and accept the result
# ONLY when XED then decodes it -- to a real iform, at the completed length.
# A row that stays undecodable is left exactly as it was and stays visible.
base_probe = {opid: accept.get(hexs, hexs) for opid, mnem, hexs, src in rows}
allhex = sorted(set(base_probe.values()))
dec = iforms(allhex)
broken = [h for h in allhex if dec.get(h, ('0',))[0] != '1']
fix = {}
if broken:
    cands = [h + 'c0' for h in broken]
    got = iforms(cands)
    for h, c in zip(broken, cands):
        if got.get(c) and got[c][0] == '1' and int(got[c][1]) == len(c) // 2:
            fix[h] = c
print('probe encodings XED refuses          : %d' % len(broken))
print('  completed with a ModRM and accepted: %d  %s'
      % (len(fix), ' '.join('%s->%s' % kv for kv in sorted(fix.items())[:6])))
if len(fix) != len(broken):
    print('  STILL UNDECODABLE                  : %s'
          % ' '.join(h for h in broken if h not in fix))
probe = {opid: fix.get(h, h) for opid, h in base_probe.items()}
json.dump(probe, open(os.path.join(D, 'probe_map.json'), 'w'))
u = sorted(set(probe.values()))
open(os.path.join(D, 'probe_uniq.hex'), 'w').write(''.join(h + '\n' for h in u))
print('opcodes %d  unique probe encodings %d' % (len(probe), len(u)))
