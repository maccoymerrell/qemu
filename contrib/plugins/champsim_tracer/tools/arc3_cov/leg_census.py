#!/usr/bin/env python3
"""
ARC 3 -- the OPCODE CENSUS of an execution leg.

WHY THIS EXISTS
===============
Every execution leg in this arc is quoted by its instruction count: 395,474
correct-path pairs on x86_64, 704 declared wrong-path instructions there, 297
on mipsel.  An instruction count is not a size.  A loop inflates it for free,
and a leg that ran one basic block ten thousand times has exercised exactly as
many opcodes as one that ran it once.

The number that bounds what a leg can support is how many DISTINCT things it
ran, and the honest answer needs three vocabularies rather than one:

  * DISTINCT ENCODINGS -- the finest, and the only one with no decoder in it.
  * DISTINCT OPCODES -- the disassembler's mnemonic.  This is the number the
    maintainer asked for, and it is the one to quote.
  * DISTINCT GENERIC CLASSES -- the tracer's own ``GEN_OP_*`` vocabulary, the
    granularity at which the dependency model behaves differently.  A class
    the leg never ran is a class the leg did not validate, whatever its
    agreement count says, so the classes NOT exercised are printed by name.

The last one is the point of the tool.  An axis that never saw an instruction
class has not validated it, and a report that prints only "N of N axes agree"
cannot say which classes were behind the N.

WHERE THE ANSWERS COME FROM, AND WHY NOT FROM THE COMPARATORS
=============================================================
The encodings come from ``cst_decode --format=disasm`` by way of
``wp_trace.census`` -- the trace alone, no image and no simulator, so the
census can be taken of a BANKED trace as well as of a fresh run.  The two
vocabularies come from ``isaxcheck --batch``, which decodes each distinct
encoding through the same Capstone boundary the plugin calls and through the
plugin's own ``InsnFields`` layer, printing both.  Neither number is read off
a table: R8.7 wants an OBSERVED decode, and this is one.

CONTROLS
========
  * an encoding the boundary cannot decode is counted and FAILS the run -- it
    would silently shrink every distinct count below it;
  * an encoding whose fields layer refuses is counted and FAILS the run for
    the same reason;
  * ``--expect-wp N`` asserts the census's own wrong-path total against the
    number the leg's REPORT declared, so a census taken of the wrong traces,
    or of a subset of them, cannot pass as the leg's size.

Author: Maccoy Merrell.
"""
import argparse
import collections
import os
import re
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(_HERE, 'riscv64', 'spike', 'wp')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import wp_trace                                              # noqa: E402

#: where the generic opcode vocabulary is DEFINED.  Read from the tree on
#: every run rather than copied here: a class added to the enum and not to a
#: copy would make "classes not exercised" quietly wrong in the safe
#: direction, which is the failure this arc keeps finding.
_GENERIC_IDS = os.path.abspath(os.path.join(
    _HERE, '..', '..', 'champsim_tracer_generic_ids.h'))
_ENUM_ROW = re.compile(r'^\s*(GEN_OP_[A-Z0-9_]+)\s*=\s*(\d+)\s*,')

#: the four denominators, for context only.  The census does NOT join a
#: mnemonic onto them -- XED spells the x86 rows in a different vocabulary
#: from Capstone's AT&T output and a name join there would invent a coverage
#: fraction nobody measured.  The row count is printed so a reader can size
#: the leg against the denominator without the tool pretending to that join.
_DENOM = {
    'x86_64':  'x86_64/attrib.tsv',
    'aarch64': 'aarch64/attrib.tsv',
    'riscv64': 'riscv64/attrib.tsv',
    'mipsel':  'mipsel/attrib.tsv',
}


def generic_classes():
    """The GEN_OP_* vocabulary, read from the header that defines it."""
    if not os.path.exists(_GENERIC_IDS):
        raise SystemExit('the generic-opcode header moved: %s' % _GENERIC_IDS)
    names = []
    with open(_GENERIC_IDS) as fh:
        for line in fh:
            m = _ENUM_ROW.match(line)
            if m:
                names.append(m.group(1))
    if 'GEN_OP_MOV' not in names or len(names) < 40:
        raise SystemExit('the generic-opcode enum no longer parses out of %s '
                         '(%d names found)' % (_GENERIC_IDS, len(names)))
    return names


def decode_batch(isaxcheck, isa, encodings):
    """{hex: (b_ok, b_mnem, f_ok, f_opcode)} for every encoding, OBSERVED.

    One process for the whole set; ``isaxcheck --batch`` exists so a
    per-opcode sweep does not pay a process start per encoding.
    """
    payload = ''.join(h + '\n' for h in encodings)
    p = subprocess.run([isaxcheck, '--isa=' + isa, '--batch'],
                       input=payload.encode(), stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise SystemExit('isaxcheck --batch exit %d: %s'
                         % (p.returncode,
                            p.stderr.decode('utf-8', 'replace')[-600:]))
    lines = p.stdout.decode('utf-8', 'replace').splitlines()
    if not lines:
        raise SystemExit('isaxcheck --batch printed nothing')
    hdr = lines[0].split('\t')
    col = dict((n, i) for i, n in enumerate(hdr))
    for need in ('hex', 'b_ok', 'b_mnem', 'f_ok', 'f_opcode'):
        if need not in col:
            raise SystemExit('isaxcheck --batch has no %r column; its header '
                             'changed and this census would be reading the '
                             'wrong field' % need)
    out = {}
    for line in lines[1:]:
        f = line.split('\t')
        if len(f) < len(hdr):
            continue
        out[f[col['hex']]] = (f[col['b_ok']] == '1', f[col['b_mnem']],
                              f[col['f_ok']] == '1', f[col['f_opcode']])
    missing = [h for h in encodings if h not in out]
    if missing:
        raise SystemExit('isaxcheck --batch returned no row for %d of %d '
                         'encodings, first %s'
                         % (len(missing), len(encodings), missing[0]))
    return out


def encodings_of(triples):
    """[(pc, bits, nbytes)] -> Counter of lowercase hex encodings."""
    c = collections.Counter()
    for _pc, bits, nb in triples:
        c[bits.to_bytes(nb, 'little').hex()] += 1
    return c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--isa', required=True, choices=sorted(_DENOM))
    ap.add_argument('--decode', required=True, help='cst_decode')
    ap.add_argument('--isaxcheck', required=True)
    ap.add_argument('--cov', default='/mnt/md0/QEMU/cst_runs/_arc3_cov',
                    help='denominator directory, for the row count only')
    ap.add_argument('--label', default='', help='what leg this is')
    ap.add_argument('--tsv', help='per-encoding census output')
    ap.add_argument('--axis-subjects',
                    help="a leg's axis_subjects.tsv; the per-axis distinct "
                         'ENCODING counts it carries are mapped onto opcodes '
                         'and onto generic classes here')
    ap.add_argument('--expect-wp', type=int,
                    help='the wrong-path instruction total the leg REPORT '
                         'declared; a mismatch fails the run')
    ap.add_argument('trace', nargs='+')
    a = ap.parse_args()

    cp, wp = collections.Counter(), collections.Counter()
    per_trace = []
    for t in a.trace:
        c = wp_trace.census(a.decode, t)
        ecp, ewp = encodings_of(c['cp']), encodings_of(c['wp'])
        per_trace.append((os.path.basename(t), sum(ecp.values()),
                          sum(ewp.values()), len(ecp), len(ewp)))
        cp.update(ecp)
        wp.update(ewp)

    allenc = sorted(set(cp) | set(wp))
    if not allenc:
        raise SystemExit('the census found no instructions at all in %d '
                         'traces -- it is measuring nothing' % len(a.trace))
    dec = decode_batch(a.isaxcheck, a.isa, allenc)

    bad_b = [h for h in allenc if not dec[h][0]]
    bad_f = [h for h in allenc if dec[h][0] and not dec[h][2]]

    def vocab(counter, idx):
        s = collections.Counter()
        for h, n in counter.items():
            s[dec[h][idx]] += n
        return s

    w, out = (lambda s: out.append(s)), []
    w('=' * 74)
    w('ARC 3 -- EXECUTION LEG OPCODE CENSUS%s'
      % (('  --  ' + a.label) if a.label else ''))
    w('=' * 74)
    w('')
    w('An instruction COUNT is not a size: a loop inflates it for free.  What')
    w('bounds the claim is how many DISTINCT things the leg ran, and a class')
    w('the leg never ran is a class it did not validate.')
    w('')
    w('isa                 %s' % a.isa)
    w('traces              %d' % len(a.trace))
    w('')
    hdr = '%-28s %14s %14s' % ('', 'CORRECT PATH', 'WRONG PATH')
    w(hdr)
    w('-' * len(hdr))
    w('%-28s %14d %14d' % ('instructions', sum(cp.values()), sum(wp.values())))
    w('%-28s %14d %14d' % ('distinct encodings', len(cp), len(wp)))
    mcp, mwp = vocab(cp, 1), vocab(wp, 1)
    gcp, gwp = vocab(cp, 3), vocab(wp, 3)
    w('%-28s %14d %14d' % ('DISTINCT OPCODES', len(mcp), len(mwp)))
    w('%-28s %14d %14d' % ('distinct generic classes', len(gcp), len(gwp)))
    w('-' * len(hdr))
    w('')
    w('UNION OF BOTH PATHS   encodings %d   opcodes %d   generic classes %d'
      % (len(set(cp) | set(wp)), len(set(mcp) | set(mwp)),
         len(set(gcp) | set(gwp))))
    w('')
    w('THE RATIO A LOOP HIDES.  instructions per distinct opcode:')
    w('  correct path  %8.1f          wrong path  %8.1f'
      % ((sum(cp.values()) / len(mcp)) if mcp else 0.0,
         (sum(wp.values()) / len(mwp)) if mwp else 0.0))
    w('')
    denom = os.path.join(a.cov, _DENOM[a.isa])
    nrows = 0
    if os.path.exists(denom):
        with open(denom) as fh:
            nrows = sum(1 for line in fh if line.strip()) - 1
    w('THE DENOMINATOR, for size only.  %s carries %d opcode rows.  This'
      % (_DENOM[a.isa], nrows))
    w('census does NOT join its mnemonics onto them -- the tables are written')
    w('in a different vocabulary and a name join would invent a coverage')
    w('fraction nobody measured.  What the two numbers together say is that')
    w('an execution leg is a PROBE, not a coverage result, and this is its')
    w('size.')
    w('')
    w('PER TRACE')
    w('%-30s %9s %9s %9s %9s'
      % ('trace', 'cp insns', 'wp insns', 'cp enc', 'wp enc'))
    for name, ncp, nwp, dcp, dwp in per_trace:
        w('%-30s %9d %9d %9d %9d' % (name[:30], ncp, nwp, dcp, dwp))
    w('')
    w('DISTINCT OPCODES ON THE WRONG PATH (%d), with dynamic count' % len(mwp))
    for name, n in sorted(mwp.items(), key=lambda kv: (-kv[1], kv[0])):
        w('  %-24s %8d' % (name, n))
    w('')
    w('DISTINCT OPCODES ON THE CORRECT PATH ONLY (%d)'
      % len(set(mcp) - set(mwp)))
    w('  %s' % (', '.join(sorted(set(mcp) - set(mwp))) or '(none)'))
    w('')
    allcls = generic_classes()
    seen = set(gcp) | set(gwp)
    unseen = [c for c in allcls if c not in seen]
    w('GENERIC CLASSES.  The tracer\'s dependency model behaves per class, so')
    w('a class no instruction in this leg belongs to is a class this leg did')
    w('NOT validate -- on any axis, whatever the agreement count.')
    w('')
    w('  vocabulary (%s)   %d' % (os.path.basename(_GENERIC_IDS), len(allcls)))
    w('  exercised, either path        %d' % len(seen))
    w('  NOT exercised                 %d' % len(unseen))
    w('')
    w('  exercised on the wrong path:')
    for name, n in sorted(gwp.items(), key=lambda kv: (-kv[1], kv[0])):
        w('    %-28s %8d' % (name, n))
    w('')
    w('  NOT EXERCISED ANYWHERE IN THIS LEG, by name:')
    for i in range(0, len(unseen), 3):
        w('    ' + '  '.join('%-24s' % c for c in unseen[i:i + 3]))
    w('')
    if a.axis_subjects:
        w('PER-AXIS SUBJECTS, IN OPCODES.  The comparator counts DISTINCT')
        w('ENCODINGS because counting them needs no decoder; this maps them')
        w('onto opcodes and onto the tracer\'s generic classes, which is the')
        w('granularity at which the dependency model behaves differently.')
        w('An axis is validated only over the classes it actually saw.')
        w('')
        ax = []
        with open(a.axis_subjects) as fh:
            hdr = fh.readline().rstrip('\n').split('\t')
            if hdr[:3] != ['axis', 'facts', 'subjects']:
                raise SystemExit('%s is not an axis_subjects table'
                                 % a.axis_subjects)
            for line in fh:
                f = line.rstrip('\n').split('\t')
                if len(f) < 4:
                    continue
                ax.append((f[0], int(f[1]), int(f[2]),
                           [e for e in f[3].split(',') if e]))
        need = sorted(set(e for _a, _f, _s, es in ax for e in es)
                      - set(allenc))
        if need:
            dec.update(decode_batch(a.isaxcheck, a.isa, need))
        hdr2 = '%-18s %9s %10s %9s %9s' % ('axis', 'facts', 'encodings',
                                           'opcodes', 'classes')
        w(hdr2)
        w('-' * len(hdr2))
        for name, nf, ns, es in ax:
            ops = set(dec[e][1] for e in es if e in dec)
            cls = set(dec[e][3] for e in es if e in dec)
            w('%-18s %9s %10s %9s %9s'
              % (name, 'INERT' if not nf else nf, ns or '-',
                 len(ops) or '-', len(cls) or '-'))
        w('-' * len(hdr2))
        dead = [n for n, nf, _s, _e in ax if not nf]
        w('INERT AXES: %s' % (', '.join(dead) if dead else 'none'))
        w('')

    w('CONTROLS')
    w('  encodings the decode boundary refused   %d' % len(bad_b))
    w('  encodings the fields layer refused      %d' % len(bad_f))
    if bad_b:
        w('  first refused by the boundary          %s' % bad_b[0])
    if bad_f:
        w('  first refused by the fields layer      %s' % bad_f[0])
    if a.expect_wp is not None:
        w('  wrong-path total vs the leg REPORT     %d vs %d  %s'
          % (sum(wp.values()), a.expect_wp,
             'MATCH' if sum(wp.values()) == a.expect_wp else 'MISMATCH'))
    w('')

    txt = '\n'.join(out) + '\n'
    sys.stdout.write(txt)
    if a.tsv:
        with open(a.tsv, 'w') as fh:
            fh.write('hex\tpath\tdynamic\tb_ok\tmnemonic\tf_ok\tgeneric\n')
            for h in allenc:
                b_ok, mnem, f_ok, gen = dec[h]
                fh.write('%s\t%s\t%d\t%d\t%s\t%d\t%s\n'
                         % (h, ('both' if h in cp and h in wp else
                                'cp' if h in cp else 'wp'),
                            cp[h] + wp[h], b_ok, mnem, f_ok, gen))
    rc = 0
    if bad_b or bad_f:
        sys.stderr.write('REFUSING: %d encodings the boundary could not '
                         'decode and %d the fields layer refused; every '
                         'distinct count above is short by an unknown '
                         'amount\n' % (len(bad_b), len(bad_f)))
        rc = 1
    if a.expect_wp is not None and sum(wp.values()) != a.expect_wp:
        sys.stderr.write('REFUSING: the census saw %d wrong-path '
                         'instructions and the leg declared %d -- this census '
                         'is not of that leg\n'
                         % (sum(wp.values()), a.expect_wp))
        rc = 1
    return rc


if __name__ == '__main__':
    sys.exit(main())
