#!/usr/bin/env python3
"""
THE PROBE DEGENERACY AUDIT for the three fixed-width ISAs.

WHY THIS EXISTS.  `arc3_cov/x86_64/mkprobe.py` carries a rule with three
instances behind it: a probe encoding whose field sits at the value where the
modelled effect DOES NOT HAPPEN is not a probe of that effect.  The third
instance cost a whole R13 leg -- thirty-six x86_64 shift and rotate opcodes
read UNCOVERED because XED's representative encoding fills every immediate
with zero, and a shift by zero writes no flags, so an INSTANCE answer was
being compared against a CLASS answer on the one instance where the class's
answer does not hold.

That rule was an x86 rule applied by an x86 harness.  aarch64, riscv64 and
mipsel build their probe sets elsewhere and their static legs read 0/0 --
which is evidence that no such probe is currently COSTING anything, not
evidence that none exists.  A degenerate probe that happens to agree is
invisible in exactly the way this one was until the wire moved underneath it.
This tool puts the same question to the other three.

THE TEST, AND WHY IT NEEDS NO PER-ISA FIELD TABLE.  On a fixed-width ISA
every field value that could be degenerate is reachable by changing bits of
the probe word, and a field at zero is raised off zero by setting its lowest
bit -- one bit.  So for every probe encoding the audit forms all 32 single-bit
variants and keeps only those the REFERENCE decoder reads as THE SAME
INSTRUCTION: LLVM accepts the variant, prints the same mnemonic, and consumes
the same number of bytes.  That is the acceptance rule mkprobe.py already
uses (`same_opcode`: ok, length, iform), expressed in the terms a fixed-width
ISA has.

A variant that survives that filter differs from the probe ONLY in an operand
value.  If the TRACER'S ANSWER for the variant is a STRICT SUPERSET of its
answer for the probe -- more sources, or more destinations -- then the probe
is sitting at a value at which part of the instruction's dataflow does not
occur, and the leg is measuring the instruction at its quietest point.  That
is the degeneracy, stated as a measurement rather than as ISA lore.

WHAT A HIT IS AND IS NOT.  A hit is a CANDIDATE, not a verdict: a register
field moved into or out of the zero register also enlarges a set, and under
R15/R16 the zero register is expressed rather than elided, so those rows are
real answers and not degeneracies.  The report therefore prints the reference
rendering of both encodings beside the registers gained, so every hit is
adjudicated from what the two instructions ARE.  Nothing is re-seated here.

Author: Maccoy Merrell.
"""
import argparse, csv, os, re, subprocess, sys
from collections import defaultdict

BASE_DEFAULT = os.environ.get('CST_COV_DIR', '/mnt/md0/QEMU/cst_runs/_arc3_cov')
ISAX_DEFAULT = os.environ.get(
    'CST_ISAXCHECK', '/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck')

# opcodes.tsv is one table per ISA and they do not share a column name.
HEXCOL = {
    'aarch64': 'hex',
    'riscv64': 'hex',
    'mipsel':  'representative_encoding_hex_le',
}


def read_probes(base, isa):
    path = os.path.join(base, isa, 'opcodes.tsv')
    if not os.path.exists(path):
        sys.exit('REFUSED: no denominator at %s.  This tool audits a probe '
                 'set; it does not build one.' % path)
    with open(path) as f:
        # mipsel's header is commented; csv wants it uncommented.
        head = f.readline().lstrip('#').rstrip('\n').split('\t')
        col = HEXCOL[isa]
        if col not in head:
            sys.exit('REFUSED: %s has no %r column (has %r)' %
                     (path, col, head))
        i_hex = head.index(col)
        i_id = 0
        rows = []
        for line in f:
            c = line.rstrip('\n').split('\t')
            if len(c) <= i_hex or not c[i_hex]:
                continue
            rows.append((c[i_id], c[i_hex]))
    return rows


def probe(isax, isa, hexes, chunk=200000):
    """One or more isaxcheck --batch calls; returns {hex: row}."""
    out = {}
    for i in range(0, len(hexes), chunk):
        part = hexes[i:i + chunk]
        p = subprocess.run(
            [isax, '--isa=' + isa, '--layer=fields', '--batch'],
            input='\n'.join(part) + '\n', capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit('isaxcheck --batch failed rc=%d: %s'
                     % (p.returncode, p.stderr[-2000:]))
        for r in csv.DictReader(p.stdout.splitlines(), delimiter='\t'):
            out[r['hex']] = r
    return out


def word(h):
    """The probe tables spell a fixed-width instruction as its LITTLE-ENDIAN
    byte string, which is what every decoder here is fed."""
    return int.from_bytes(bytes.fromhex(h), 'little')


def spell(w, nbytes):
    return w.to_bytes(nbytes, 'little').hex()


def regset(s):
    return frozenset(t for t in s.split(',') if t and t != '-')


def mnem(text):
    return text.split(' ')[0].strip() if text else ''


# Register tokens as the four reference printers spell them.  Used only to
# tell "an operand VALUE moved" from "a control field moved"; a token this
# misses lands the row in the more conservative bucket, never a quieter one.
RE_REG = re.compile(r'\b(?:[wx]\d+|[wx]zr|wsp|sp|lr|[vqdshbz]\d+|p\d+|za\d*|'
                    r'zt\d+|[fvax]\d+|s\d+|t\d+|a\d+|ra|gp|tp|fp|'
                    r'\$\w+)\b')


def shape(probe_text, var_text):
    """Name what kind of field the accepted variant moved.

    The four buckets are not equally interesting and the report says which
    is which rather than leaving a reader to infer it:

      mask-enable      the variant turns a MASK or PREDICATION mode on.  This
                       is the class mkprobe.py already re-seats on x86 (an
                       EVEX opcode carrying a mask slot is re-probed with
                       aaa=001 so the mask operand is exercised); a probe
                       sitting at "unmasked" never reads the mask register.
      addressing-mode  the variant turns an offset form into a pre- or
                       post-indexed one.  On aarch64 those are SEPARATE named
                       MRA encodings with their own denominator rows, so the
                       probe is right and the variant belongs to another
                       subject.
      operand-value    a register field changed value.  A probe that seats
                       two operand slots on the SAME register has a smaller
                       set than the instruction has slots -- it cannot
                       discriminate a mis-slotted register -- but its answer
                       is not wrong.
      control-field    everything else: a non-register field whose value
                       changes the dataflow of the SAME subject.  This is the
                       bucket the x86 zero-shift-count defect would land in.
    """
    if 'v0.t' in var_text and 'v0.t' not in probe_text:
        return 'mask-enable'
    if '/m' in var_text and '/z' in probe_text:
        return 'mask-enable'
    if ('!' in var_text and '!' not in probe_text) or \
       (']' in probe_text and var_text.rstrip().endswith(('#0', '#8', '#16'))
        and not probe_text.rstrip().endswith(('#0', '#8', '#16'))):
        return 'addressing-mode'
    if set(RE_REG.findall(probe_text)) != set(RE_REG.findall(var_text)):
        return 'operand-value'
    return 'control-field'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--isa', required=True, choices=sorted(HEXCOL))
    ap.add_argument('--base', default=BASE_DEFAULT)
    ap.add_argument('--isaxcheck', default=ISAX_DEFAULT)
    ap.add_argument('--out', default=None)
    a = ap.parse_args()
    if not os.access(a.isaxcheck, os.X_OK):
        sys.exit('REFUSED: no isaxcheck at %s' % a.isaxcheck)

    rows = read_probes(a.base, a.isa)
    hexes = [h for _, h in rows]
    nb = len(bytes.fromhex(hexes[0]))
    if any(len(bytes.fromhex(h)) != nb for h in hexes):
        # riscv64 carries 16-bit compressed forms beside 32-bit ones.
        pass
    base = probe(a.isaxcheck, a.isa, sorted(set(hexes)))

    # Every single-bit variant of every probe, de-duplicated across probes.
    variants = defaultdict(list)          # probe hex -> [(bit, variant hex)]
    allv = set()
    for _, h in rows:
        n = len(bytes.fromhex(h))
        w = word(h)
        for b in range(n * 8):
            v = spell(w ^ (1 << b), n)
            if v == h:
                continue
            variants[h].append((b, v))
            allv.add(v)
    vres = probe(a.isaxcheck, a.isa, sorted(allv))

    hits, considered, comparable = [], 0, 0
    for oid, h in rows:
        br = base.get(h)
        if not br or br.get('l_ok') != '1' or br.get('f_ok') != '1':
            continue
        considered += 1
        bsrc, bdst = regset(br['f_src']), regset(br['f_dst'])
        bm, bsz = mnem(br['l_text']), br['l_sz']
        for bit, v in variants[h]:
            vr = vres.get(v)
            if not vr or vr.get('l_ok') != '1' or vr.get('f_ok') != '1':
                continue
            # THE REFERENCE'S ACCEPTANCE RULE: same instruction, same length.
            if mnem(vr['l_text']) != bm or vr['l_sz'] != bsz:
                continue
            comparable += 1
            vsrc, vdst = regset(vr['f_src']), regset(vr['f_dst'])
            if vsrc > bsrc or vdst > bdst:
                hits.append((oid, h, bit, v,
                             shape(br['l_text'], vr['l_text']),
                             ','.join(sorted(vsrc - bsrc)) or '-',
                             ','.join(sorted(vdst - bdst)) or '-',
                             br['l_text'], vr['l_text']))

    out = open(a.out, 'w') if a.out else sys.stdout
    print('# probe degeneracy audit  isa=%s  probes=%d  scored=%d  '
          'same-instruction variants=%d  candidate rows=%d  '
          'candidate opcodes=%d'
          % (a.isa, len(rows), considered, comparable, len(hits),
             len({x[0] for x in hits})), file=out)
    byshape = defaultdict(int)
    opshape = defaultdict(set)
    for x in hits:
        byshape[x[4]] += 1
        opshape[x[4]].add(x[0])
    for k in sorted(byshape):
        print('# shape %-16s rows=%-6d opcodes=%d'
              % (k, byshape[k], len(opshape[k])), file=out)
    print('# opcode_id\tprobe\tbit\tvariant\tshape\tsrc_gained\t'
          'dst_gained\tref_probe\tref_variant', file=out)
    for row in hits:
        print('\t'.join(str(x) for x in row), file=out)
    if a.out:
        out.close()
    # A hit is a candidate, so a non-zero count is a REPORT, not a failure.
    return 0


if __name__ == '__main__':
    sys.exit(main())
