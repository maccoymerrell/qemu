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
        h, ok, ln, immw, ifm = line.split('\t')
        out[h] = (ok, ln, immw, ifm)
    return out

def same_opcode(a, b):
    """Two decodes name the same opcode at the same size: ok, length, iform.
    The immediate WIDTH is deliberately not part of this test -- it is an
    input to choosing a variant, never evidence that the variant is valid."""
    return (b and a and b[0] == '1' and a[0] == '1'
            and b[1] == a[1] and b[3] == a[3])

base, var = list(cand.keys()), list(cand.values())
old, new = iforms(base), iforms(var)
accept = {b: v for b, v in zip(base, var) if same_opcode(old.get(b), new.get(v))}
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

# A PROBE WHOSE IMMEDIATE IS THE ONE VALUE THAT SWITCHES THE OPERATION OFF IS
# NOT A PROBE OF THAT OPERATION.  XED's representative encoding fills every
# immediate with zero, and for the shift/rotate family zero is not a count --
# it is the architectural instruction to do nothing.  The SDM says so four
# times (SAL/SAR/SHL/SHR 4-687, RCL/RCR/ROL/ROR 4-543, SHLD 4-706, SHRD
# 4-709: "If the masked count is 0, the flags are not affected"), and QEMU
# implements exactly that -- gen_shift_count() returns a NULL count on
# (imm & mask) == 0, so no flag write is generated and the tracer states
# none.  XED's iform-level answer carries Defs=[EFLAGS] regardless, because
# an iform has no operand VALUE to condition on.  Comparing the two on this
# encoding is a category error, and it read as 36 x86_64 opcodes UNCOVERED
# and a static headline of 83 against an adjudicated ceiling of 47.
#
# So the count is re-seated to 1 and the SAME acceptance rule the two stages
# above use is applied: the variant is taken only when XED decodes it to the
# same iform at the same length.  This changes the ENCODING probed, never the
# opcode measured.  It is restricted to probes carrying exactly one one-byte
# immediate -- asked of XED, not guessed from the opcode -- so a ModRM byte
# or a displacement that happens to be zero is never touched, and a two-
# immediate form (ENTER) reports width 2 and is excluded by that.
#
# The zero-count encoding is not thereby unmeasured: it is what the whole-
# population sweeps carry, and the boundary and fields gates hold its 54
# reference signatures under a written allowlist entry.  This leg measures
# the opcode; those measure the encoding.
dec2 = iforms(sorted(set(probe.values())))
imm_cand = {}
for h in sorted(set(probe.values())):
    d = dec2.get(h)
    if d and d[0] == '1' and d[2] == '1' and h.endswith('00'):
        imm_cand[h] = h[:-2] + '01'
if imm_cand:
    ib, iv = list(imm_cand.keys()), list(imm_cand.values())
    o2, n2 = iforms(ib), iforms(iv)
    imm_ok = {b: v for b, v in zip(ib, iv) if same_opcode(o2.get(b), n2.get(v))}
    print('probes whose only immediate is a zero byte : %d' % len(imm_cand))
    print('  re-seated to 1, same iform and length    : %d  (rejected %d)'
          % (len(imm_ok), len(imm_cand) - len(imm_ok)))
    probe = {opid: imm_ok.get(h, h) for opid, h in probe.items()}

json.dump(probe, open(os.path.join(D, 'probe_map.json'), 'w'))
u = sorted(set(probe.values()))
open(os.path.join(D, 'probe_uniq.hex'), 'w').write(''.join(h + '\n' for h in u))
print('opcodes %d  unique probe encodings %d' % (len(probe), len(u)))
