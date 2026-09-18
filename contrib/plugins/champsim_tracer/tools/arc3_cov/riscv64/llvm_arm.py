#!/usr/bin/env python3
"""The riscv64 leg's SECOND-DECODER arm, read out of LLVM MC (FINDING 246-C).

    llvm_arm.py [--probe <bin_llvm_ops>] [--selfcheck <rows.json>]
        < hex-encodings-one-per-line  > boundary.tsv

WHAT THIS REPLACES AND WHY.
---------------------------
emit.py asked the retired `isaxcheck --layer=boundary` for two things at once:
CAPSTONE's decode (`b_ok`, `b_sz`, `b_mnem`, `b_ops`) and LLVM MC's (`l_ok`,
`l_sz`, `l_text`).  That binary linked Capstone and was deleted with it at
c32824defa, so both halves went at once and the leg refused --
`isaxcheck refused the vm re-seat batch rc=1`, plus the same refusal inside
reprobe().

The Capstone half does not come back: Capstone is out of the shipped tracer by
ruling, and its only surviving role is as an OFFLINE referee over recorded
bytes.  The LLVM half does, from the probe binary the riscv64 reference corpus
was built with, and it is enough on its own: this leg's reference is the
Sail-RISCV model, LLVM MC is the decode-boundary cross-check beside it, and the
columns emit.py actually consumes -- decode status, size, mnemonic, operand
shape -- are all things LLVM MC states.

    hex     the encoding, little-endian bytes, as rows.json spells it
    l_ok    1 when LLVM MC decoded it
    l_sz    the decoded length in bytes
    l_text  the disassembly, mnemonic first
    l_rd    the read set, LLVM register names, lowercase and sorted
    l_wr    the write set, likewise

l_rd / l_wr are not consumed by emit.py today.  They are emitted because this
is the leg's reference decoder and the register sets are the fact the arc is
about; a column that exists is a column a later pass can join on, and deriving
it here costs one pass over output already parsed.

THE ARM IS CHECKED AGAINST THE RETIRED TOOL'S OWN READING.  `--selfcheck
rows.json` scores `l_ok` / `l_sz` / `l_text` against the values isaxcheck wrote
into rows.json and names every difference, so a mapping that agreed with
nothing cannot pass for a leg that stopped disagreeing.

Author: Maccoy Merrell.
"""

import argparse
import json
import os
import re
import subprocess
import sys

DEFAULT_PROBE = '/mnt/md0/QEMU/cst_runs/_arc3_refs/riscv64/bin_llvm_ops'

# THE FEATURE STRING IS THE MACHINE THE REFERENCE IS ASKED ABOUT, so it is
# STATED here and not left to the probe's default.  It is every ISA extension
# LLVM 18 names for RISC-V, MINUS four groups, each excluded for a reason:
#
#   zcmp / zcmt / zce / zcf  -- the compressed profiles are ALTERNATIVES to the
#       Zcd that C+D implies, not layers on top of it (zcmp_profile.py carries
#       the measurement and the QEMU citation).  This leg enumerates the
#       rv64gc profile; enabling them here would re-decode the compressed
#       FP-store space and move the denominator under the leg.
#   zdinx / zfinx / zhinx / zhinxmin -- these put floating point in the INTEGER
#       register file, so LLVM's printer names fa0 as a0.  MEASURED: with them
#       on, 85 D-extension rows print integer register names.  QEMU's rv64
#       machine is not an *inx machine and neither is this denominator.
#
# MEASURED against the retired tool's own reading in rows.json: 0 rows differ
# on decode status, 0 on size, and ONE on text -- `pause` (0f000001), which
# the retired arm printed as its `fence w, 0` encoding because it lacked
# +zihintpause.  This arm names the hint, which is what Sail calls it too.
FEATURES = ('+a,' '+c,' '+d,' '+experimental-zacas,' '+experimental-zcmop,'
             '+experimental-zfbfmin,' '+experimental-zicfilp,'
             '+experimental-zicfiss,' '+experimental-zimop,'
             '+experimental-ztso,' '+experimental-zvfbfmin,'
             '+experimental-zvfbfwma,' '+f,' '+h,' '+m,' '+smaia,'
             '+smepmp,' '+ssaia,' '+svinval,' '+svnapot,' '+svpbmt,' '+v,'
             '+za128rs,' '+za64rs,' '+zawrs,' '+zba,' '+zbb,' '+zbc,'
             '+zbkb,' '+zbkc,' '+zbkx,' '+zbs,' '+zca,' '+zcb,' '+zcd,'
             '+zfa,' '+zfh,' '+zfhmin,' '+zic64b,' '+zicbom,' '+zicbop,'
             '+zicboz,' '+ziccamoa,' '+ziccif,' '+zicclsm,' '+ziccrse,'
             '+zicntr,' '+zicond,' '+zicsr,' '+zifencei,' '+zihintntl,'
             '+zihintpause,' '+zihpm,' '+zk,' '+zkn,' '+zknd,' '+zkne,'
             '+zknh,' '+zkr,' '+zks,' '+zksed,' '+zksh,' '+zkt,' '+zmmul,'
             '+zvbb,' '+zvbc,' '+zve32f,' '+zve32x,' '+zve64d,' '+zve64f,'
             '+zve64x,' '+zvfh,' '+zvfhmin,' '+zvkb,' '+zvkg,' '+zvkn,'
             '+zvknc,' '+zvkned,' '+zvkng,' '+zvknha,' '+zvknhb,' '+zvks,'
             '+zvksc,' '+zvksed,' '+zvksg,' '+zvksh,' '+zvkt,' '+zvl64b')

FIELDS = ('hex', 'l_ok', 'l_sz', 'l_text', 'l_rd', 'l_wr')

_HDR = re.compile(r'^=== hex=([0-9a-fA-F]+) ===$')
_OP = re.compile(r'^\s*op\[\d+\]\s+(DEF|USE)\s+(?:reg=(\S+)|imm=\S+)\s+'
                 r'type=(\S+)\s+rc=(\S+)\s+tied_to=(-?\d+)\s*$')
_SZ = re.compile(r'size=(\d+)')


def tok(name):
    """-> the token(s) one LLVM RISC-V register name contributes."""
    if not name or name in ('-', 'noreg'):
        return ()
    if '_' in name:                      # a register tuple IS its members
        out = []
        for part in name.split('_'):
            out.extend(tok(part))
        return tuple(out)
    return (name.lower(),)


def parse(text):
    """-> {hex: dict} over one bin_llvm_ops run."""
    out, cur = {}, None
    for line in text.splitlines():
        m = _HDR.match(line)
        if m:
            cur = m.group(1).lower()
            out[cur] = {'ok': 0, 'sz': 0, 'text': '', 'rd': set(), 'wr': set()}
            continue
        if cur is None:
            continue
        e = out[cur]
        if line.startswith('  DECODE-FAIL'):
            continue
        if line.startswith('  asm      :'):
            e['ok'] = 1
            # ONE SPELLING, SO A JOIN ON IT IS A JOIN.  The printer separates
            # the mnemonic from its operands with a tab; rows.json carries the
            # space form, and emit.py splits the first token off either way.
            e['text'] = ' '.join(line.split(':', 1)[1].split())
            continue
        if line.startswith('  opcode   :'):
            m = _SZ.search(line)
            if m:
                e['sz'] = int(m.group(1))
            continue
        m = _OP.match(line)
        if m:
            role, reg, _kind, _rc, tied = m.groups()
            if not reg:
                continue
            t = tok(reg)
            if role == 'DEF':
                e['wr'].update(t)
                # A TIED DEF CARRIES ITS OWN PRIOR VALUE IN, so it is read too.
                if int(tied) >= 0:
                    e['rd'].update(t)
            else:
                e['rd'].update(t)
            continue
        if line.strip().startswith('implicit_uses:'):
            for n in line.split(':', 1)[1].split():
                if n != '(none)':
                    e['rd'].update(tok(n.strip(',')))
            continue
        if line.strip().startswith('implicit_defs:'):
            for n in line.split(':', 1)[1].split():
                if n != '(none)':
                    e['wr'].update(tok(n.strip(',')))
            continue
    return out


def run(probe, hexes, chunk=400):
    text = []
    for i in range(0, len(hexes), chunk):
        p = subprocess.run([probe, '--features=' + FEATURES] + hexes[i:i + chunk],
                           capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit('llvm_arm: %s failed rc=%d: %s'
                     % (probe, p.returncode, p.stderr[-2000:]))
        text.append(p.stdout)
    return parse(''.join(text))


def render(probe, hexes):
    info = run(probe, hexes)
    miss = [h for h in hexes if h.lower() not in info]
    if miss:
        sys.exit('llvm_arm: %s returned no block for %d encoding(s), first %s '
                 '-- REFUSING.  A row the reference was never asked about is '
                 'not a row the reference declined.' % (probe, len(miss),
                                                        miss[:4]))
    rows = ['\t'.join(FIELDS)]
    for h in hexes:
        e = info[h.lower()]
        rows.append('\t'.join((h, str(e['ok']), str(e['sz']), e['text'],
                               ','.join(sorted(e['rd'])) or '-',
                               ','.join(sorted(e['wr'])) or '-')))
    return '\n'.join(rows) + '\n'


_IMMHEX = re.compile(r'(?<![\w.])0x([0-9a-f]+)\b')


def _norm_imm(text):
    """Immediates in DECIMAL, for comparison only.

    bin_llvm_ops calls setPrintImmHex(true) and the retired arm did not, so
    `c.addi a0, a0, 0x1` and `c.addi a0, a0, 1` are the same decode printed two
    ways.  The EMITTED text keeps the probe's own spelling -- it is what the
    command in the log produced -- and only the comparison normalises, so a
    cosmetic difference cannot be read as a decode difference and a real one
    cannot hide behind the normaliser.
    """
    return _IMMHEX.sub(lambda m: str(int(m.group(1), 16)), text)


def selfcheck(probe, rows_json):
    """Score l_ok / l_sz / l_text against what the retired tool recorded."""
    rows = json.load(open(rows_json))
    if not rows:
        sys.exit('llvm_arm: %s carries no row -- a selfcheck with no subject '
                 'proves nothing.' % rows_json)
    info = run(probe, [r['hex'] for r in rows])
    same = 0
    diffs = []
    for r in rows:
        e = info[r['hex'].lower()]
        want = (1 if r['l_ok'] else 0, int(r['hex_sz'] or 0) if r['l_ok'] else 0,
                r['l_text'])
        got = (e['ok'], e['sz'], _norm_imm(e['text']))
        if got == want:
            same += 1
        else:
            diffs.append((r['node'], r['mnemonic'], r['hex'], want, got))
    print('selfcheck vs %s: %d rows, %d identical, %d differing'
          % (rows_json, len(rows), same, len(diffs)))
    for d in diffs[:40]:
        print('  %-16s %-18s %s  banked ok=%s sz=%s "%s" | here ok=%s sz=%s "%s"'
              % (d[0], d[1], d[2], d[3][0], d[3][1], d[3][2],
                 d[4][0], d[4][1], d[4][2]))
    if len(diffs) > 40:
        print('  ... %d more' % (len(diffs) - 40))
    return len(diffs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--probe', default=os.environ.get('CST_RV_LLVMOPS',
                                                      DEFAULT_PROBE))
    ap.add_argument('--selfcheck', default=None)
    a = ap.parse_args()
    if not os.access(a.probe, os.X_OK):
        sys.exit('llvm_arm: no LLVM MC probe at %s -- REFUSING.  This leg\'s '
                 'decode-boundary cross-check is a SECOND DECODER; without one '
                 'there is nothing to cross-check against.  Build it: see '
                 '/mnt/md0/QEMU/cst_runs/_arc3_refs/riscv64/reproduce.sh'
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
