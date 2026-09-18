#!/usr/bin/env python3
"""The aarch64 leg's SECOND-DECODER arm, read out of LLVM MC (FINDING 246-C).

    llvm_arm.py [--probe <llvmref>] < hex-encodings-one-per-line > fields_all.txt

WHAT THIS REPLACES AND WHY A FLAG COULD NOT.
--------------------------------------------
compare.py consumes `fields_all.txt`, a four-column cache of LLVM MC's read and
write sets over the denominator.  Until c32824defa that file was produced by
`isaxcheck --isa=aarch64 --batch` -- the retired binary's DEFAULT layer, which
was `boundary`: Capstone beside LLVM MC, both foreign to QEMU.  The binary went
with Capstone, and REPRODUCE.sh kept calling it, so the leg refused.

The successor for the TRACER arm is sled_fields.py, and it REFUSES this call by
name, correctly: answering a boundary request with QEMU's own columns would let
compare.py score QEMU against QEMU on every row the Arm MRA has no entry for
and report the agreement as a cross-check.  So the arm is rebuilt where the
fact actually lives -- in a second decoder, run OFFLINE over recorded bytes,
the same shape as the mipsel leg's llvm_probe and binutils_probe.

WHAT IT IS.  A join over `probes/llvmref`, the LLVM MC 18 operand elaborator
already built beside the aarch64 reference corpus.  Per encoding it emits:

    hex     the encoding, as the denominator spells it (little-endian bytes)
    l_rd    the read set:  explicit USE operands, tied DEFs, implicit_uses
    l_wr    the write set: explicit DEF operands, implicit_defs
    l_ok    1 when LLVM decoded the encoding, 0 when it did not

in the token space compare.py's `llvm_tok` parses -- lowercase, sorted,
comma-separated, `-` for empty.

THE TOKEN MAP IS NOT INVENTED, IT IS FITTED AND CHECKED.  The retired tool's
own output for 3,919 of this leg's 3,920 encodings survives in the working
directory as `batch_all.tsv`, so `--selfcheck <batch_all.tsv>` scores this
module against it row by row and names every difference.  A mapping that agreed
with nothing would otherwise look exactly like a leg that had stopped
disagreeing.

A REGISTER TUPLE IS ITS MEMBERS.  LLVM names `Z4_Z5_Z6_Z7` and `P8_P9` as one
operand; the set the comparison is about is the registers, so a tuple expands.
ZA tiles carry their element size in the name (`ZAS2`, `ZAD6`) and the tile
INDEX is what the tracer's vocabulary has, so the size letter is dropped --
which is what makes `za0`..`za6` the banked spelling rather than `zas0`.

Author: Maccoy Merrell.
"""

import argparse
import csv
import os
import re
import subprocess
import sys

DEFAULT_PROBE = ('/mnt/md0/QEMU/cst_runs/_arc3_refs/aarch64/probes/llvmref')

FIELDS = ('hex', 'l_rd', 'l_wr', 'l_ok')

# The whole-architecture feature string the reference corpus was built with, so
# "LLVM rejects it" means the architecture rejects it and not that this call
# asked for a narrower machine than the banked one did.
MATTR = '+all'

_NAMED = {'NZCV': 'nzcv', 'FPCR': 'fpcr', 'FPSR': 'fpsr', 'FFR': 'ffr',
          'SP': 'sp', 'WSP': 'sp', 'XZR': 'zr', 'WZR': 'zr',
          'LR': 'r30', 'FP': 'r29', 'ZA': 'za'}
_GPR = re.compile(r'^[XW](\d+)$')
_VEC = re.compile(r'^[ZQDSHB](\d+)$')
_PRED = re.compile(r'^PN?(\d+)$')
_ZA = re.compile(r'^ZA[BHSDQ](\d+)$')
_ZT = re.compile(r'^ZT(\d+)$')


def tok(name):
    """-> the token(s) one LLVM register name contributes, or ()."""
    if not name or name == '%noreg':
        return ()
    if '_' in name:                      # a tuple operand IS its members
        out = []
        for part in name.split('_'):
            out.extend(tok(part))
        return tuple(out)
    if name in _NAMED:
        return (_NAMED[name],)
    for rx, fmt in ((_GPR, 'r%s'), (_VEC, 'v%s'), (_ZA, 'za%s'),
                    (_ZT, 'zt%s'), (_PRED, 'p%s')):
        m = rx.match(name)
        if m:
            return (fmt % int(m.group(1)),)
    # NOT SILENTLY DROPPED.  An unmapped name is reported as itself; compare.py
    # passes an unrecognised token through, so it lands in the comparison as a
    # visible difference rather than as a register that reads nothing.
    return (name.lower(),)


def _fmt(s):
    return ','.join(sorted(s)) if s else '-'


_HDR = re.compile(r'^=== ([0-9a-f]{8}) ===$')
_OP = re.compile(r'^  op\[\d+\]\s+:\s+(DEF|USE|USE\(variadic\))\s+'
                 r'(REG|IMM|OTHER)\s*(\S*)(.*)$')


def parse(text):
    """-> {word: (reads, writes, ok)} over one llvmref run's block output."""
    out, cur = {}, None
    rd = wr = None
    iscall = False
    for line in text.splitlines():
        m = _HDR.match(line)
        if m:
            cur, rd, wr = m.group(1), set(), set()
            iscall = False
            out[cur] = (rd, wr, [False])
            continue
        if cur is None:
            continue
        if line.startswith('  DECODE: FAIL'):
            continue
        if line.startswith('  asm      :'):
            out[cur][2][0] = True          # a block that got this far decoded
            continue
        if line.startswith('  flags    :'):
            iscall = 'isCall=1' in line
            continue
        m = _OP.match(line)
        if m:
            role, kind, val, rest = m.groups()
            if kind != 'REG':
                continue
            t = tok(val)
            if role == 'DEF':
                wr.update(t)
                # A TIED DEF IS ALSO A READ.  `TIED_TO op[k]` means the
                # destination carries the operand's prior value in, which is
                # exactly a source.
                if 'TIED_TO' in rest:
                    rd.update(t)
            else:
                rd.update(t)
            continue
        if line.startswith('  impl_use :'):
            for n in line.split(':', 1)[1].split():
                if n == '-':
                    continue
                # ONE REFERENCE-SIDE RULE, AND IT IS NARROW ON PURPOSE.  LLVM
                # lists SP as an implicit USE of every isCall opcode -- its
                # call-lowering convention, so the frame pointer stays live
                # across the call -- and an AArch64 `bl` / `blr` reads no such
                # thing: the ARM ARM's pseudocode reads PC and writes X30.
                # MEASURED over this leg's 3,920 encodings: 16 rows carry an
                # implicit SP use and exactly 6 of them are isCall (bl, blr,
                # blraa/blraaz, blrab/blrabz).  The other 10 -- paciasp,
                # autiasp, retaa, retabsppc, eretaa -- read SP as the pointer
                # authentication modifier, architecturally, and are kept.  So
                # the rule is conditioned on isCall and cannot widen to them.
                if iscall and n in ('SP', 'WSP'):
                    continue
                rd.update(tok(n))
            continue
        if line.startswith('  impl_def :'):
            for n in line.split(':', 1)[1].split():
                if n != '-':
                    wr.update(tok(n))
            continue
    return out


def run(probe, words, chunk=400):
    text = []
    for i in range(0, len(words), chunk):
        p = subprocess.run([probe, '--mattr=' + MATTR] + words[i:i + chunk],
                           capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit('llvm_arm: %s failed rc=%d: %s'
                     % (probe, p.returncode, p.stderr[-2000:]))
        text.append(p.stdout)
    return parse(''.join(text))


def le_to_word(h):
    return '%08x' % int.from_bytes(bytes.fromhex(h), 'little')


def render(probe, hexes):
    words = [le_to_word(h) for h in hexes]
    info = run(probe, words)
    rows = ['\t'.join(FIELDS)]
    miss = [h for h, w in zip(hexes, words) if w not in info]
    if miss:
        sys.exit('llvm_arm: %s returned no block for %d encoding(s), first %s '
                 '-- REFUSING.  A cache that silently omits a row reads '
                 'downstream as "LLVM says nothing" when nothing asked LLVM.'
                 % (probe, len(miss), miss[:4]))
    for h, w in zip(hexes, words):
        rd, wr, ok = info[w]
        rows.append('\t'.join((h, _fmt(rd), _fmt(wr), '1' if ok[0] else '0')))
    return '\n'.join(rows) + '\n'


def selfcheck(probe, banked):
    """Score this module against the RETIRED tool's own banked output."""
    ref = list(csv.DictReader(open(banked), delimiter='\t'))
    if not ref:
        sys.exit('llvm_arm: %s carries no row -- a selfcheck with no subject '
                 'proves nothing.' % banked)
    hexes = [r['hex'] for r in ref]
    got = {}
    for line in render(probe, hexes).splitlines()[1:]:
        c = line.split('\t')
        got[c[0]] = (c[1], c[2], c[3])
    same = 0
    diffs = []
    for r in ref:
        g = got[r['hex']]
        want = (r['l_rd'] or '-', r['l_wr'] or '-', r['l_ok'])
        if g == want:
            same += 1
        else:
            diffs.append((r['hex'], r.get('l_text', ''), want, g))
    print('selfcheck vs %s: %d rows, %d identical, %d differing'
          % (banked, len(ref), same, len(diffs)))
    for d in diffs[:40]:
        print('  %s  %-38s banked rd{%s} wr{%s} ok=%s | here rd{%s} wr{%s} '
              'ok=%s' % (d[0], d[1][:38], d[2][0], d[2][1], d[2][2],
                         d[3][0], d[3][1], d[3][2]))
    if len(diffs) > 40:
        print('  ... %d more' % (len(diffs) - 40))
    return len(diffs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--probe', default=os.environ.get('CST_A64_LLVMREF',
                                                      DEFAULT_PROBE))
    ap.add_argument('--selfcheck', default=None,
                    help='score against a banked isaxcheck --batch table')
    a = ap.parse_args()
    if not os.access(a.probe, os.X_OK):
        sys.exit('llvm_arm: no LLVM MC probe at %s -- REFUSING.  The reference '
                 'side of this leg is a SECOND DECODER; without one there is '
                 'no cross-check, and scoring QEMU against QEMU would report '
                 'agreement.  Build it: see '
                 '/mnt/md0/QEMU/cst_runs/_arc3_refs/aarch64/REPRODUCE.sh'
                 % a.probe)
    if a.selfcheck:
        return 1 if selfcheck(a.probe, a.selfcheck) else 0
    hexes = []
    for line in sys.stdin:
        h = ''.join(c for c in line.strip() if c in '0123456789abcdefABCDEF')
        if h:
            hexes.append(h.lower())
    if not hexes:
        sys.exit('llvm_arm: stdin carried no encoding -- REFUSING')
    sys.stdout.write(render(a.probe, hexes))
    return 0


if __name__ == '__main__':
    sys.exit(main())
