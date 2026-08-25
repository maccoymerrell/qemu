#!/usr/bin/env python3
"""
ARC 3 -- the address-DEPENDENCY facet, scored against a reference.

    compare_addrdep.py --isa ISA --hex FILE [--out FILE] [--falsify=M:MNEM]

For every encoding in the probe set, compare the registers the ChampSim
Tracer says each access computes its address FROM -- the ``HAS_ADDR``
sub-block, reached through ``isaxcheck --batch``'s ``f_laddr`` / ``f_saddr``
columns -- against an independent decoder's account of the same thing.

TWO AXES, AND WHY THE SPLIT ONE IS NOT AVAILABLE EVERYWHERE

  ``addrdep-union``  the union over every access the instruction makes.
                     Granularity-invariant, so a reference that cracks one
                     architectural access into a different number of
                     operations than the tracer records still compares
                     like for like.  All four ISAs.

  ``addrdep-split``  the same sets, role-tagged LOAD versus STORE.  Only
                     where the reference supplies a per-access direction,
                     which today is iced-x86 on x86_64.  The text-based
                     references deliberately do not guess: LLVM's
                     ``mayLoad``/``mayStore`` are instruction-level
                     over-approximations, and promoting one into a
                     per-access claim would put a number on the page that
                     the reference never said.

THE INPUT IS RE-DERIVED, NEVER READ FROM DISK.  A scorer that reads a cached
table is a scorer nobody re-ran: this arc published a verdict off a table
built four hours before the commits it claimed to measure, and re-probing at
the same tip moved 119 of 8,880 rows.  There is no cache here to go stale --
``isaxcheck`` is run, and its exit code is taken from the process.

Author: Maccoy Merrell.
"""
import argparse
import collections
import os
import subprocess
import sys

D = os.path.dirname(os.path.abspath(__file__))
for _p in (D, os.path.dirname(D)):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import addrdep_ref                                       # noqa: E402
from arc3_taxonomy import (side_set, EQUAL, SUBSET, SUPERSET,      # noqa: E402
                           ORTHOGONAL)

ISAXCHECK = os.environ.get(
    'CST_ISAXCHECK',
    '/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck')


def parse_slots(cell):
    """``f_laddr`` / ``f_saddr`` -> the UNION of its per-slot register sets.

    ``-`` is an empty slot and also a direction with no slot at all; the slot
    COUNT is carried by ``f_loads`` / ``f_stores`` and is not re-encoded here.
    ``IMM`` is a displacement, not a register, and this facet is about
    registers -- it is counted separately so the count is not lost.
    """
    regs, imm = set(), 0
    if cell in ('', '-'):
        return regs, imm
    for slot in cell.split(';'):
        if slot == '-':
            continue
        for tok in slot.split(','):
            if tok == 'IMM':
                imm += 1
            elif tok:
                regs.add(tok)
    return regs, imm


def probe(isa, hexfile, falsify, workdir):
    """Run the tracer arm live.  Returns [row dict], newest binary always."""
    if not os.path.exists(ISAXCHECK):
        sys.exit('CANNOT PROBE: no isaxcheck at %s (ninja -j 12 -C build '
                 'contrib-plugins, or set CST_ISAXCHECK)' % ISAXCHECK)
    argv = [ISAXCHECK, '--isa=' + isa, '--layer=fields', '--batch']
    if falsify:
        argv.append('--falsify=' + falsify)
    out = os.path.join(workdir, 'tracer_addrdep.tsv')
    with open(hexfile) as fi, open(out, 'w') as fo:
        rc = subprocess.call(argv, stdin=fi, stdout=fo)
    if rc != 0:
        sys.exit('CANNOT PROBE: %s exited %d' % (' '.join(argv), rc))
    rows = []
    with open(out) as f:
        cols = next(f).rstrip('\n').split('\t')
        need = ('hex', 'f_ok', 'f_laddr', 'f_saddr', 'f_hasaddr',
                'f_loads', 'f_stores', 'l_text', 'b_mnem', 'b_ok')
        missing = [c for c in need if c not in cols]
        if missing:
            sys.exit('isaxcheck --batch has no %s column -- this scorer needs '
                     'the address-dependency columns; rebuild isaxcheck'
                     % ', '.join(missing))
        ix = {c: i for i, c in enumerate(cols)}
        for line in f:
            p = line.rstrip('\n').split('\t')
            if len(p) < len(cols):
                continue
            rows.append({c: p[ix[c]] for c in need})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--isa', required=True,
                    choices=('x86_64', 'aarch64', 'riscv64', 'mipsel'))
    ap.add_argument('--hex', required=True, help='probe set, one hex per line')
    ap.add_argument('--out', default=None)
    ap.add_argument('--workdir', default=None)
    ap.add_argument('--falsify', default=None,
                    help='MODE:MNEM, passed through to isaxcheck')
    ap.add_argument('--maxreport', type=int, default=200)
    A = ap.parse_args()
    work = A.workdir or os.path.dirname(os.path.abspath(A.out or A.hex))
    fh = open(A.out, 'w') if A.out else None

    def say(s=''):
        print(s)
        if fh:
            fh.write(s + '\n')

    ref = addrdep_ref.build(A.isa)
    rows = probe(A.isa, A.hex, A.falsify, work)

    st = collections.Counter()
    #: (relation, axis) -> count, and one sample per disagreeing signature
    sig = collections.defaultdict(collections.Counter)
    sample = {}
    unmapped = collections.Counter()

    for r in rows:
        st['probed'] += 1
        acc = ref.accesses(r['hex'], r['l_text'])
        if acc is None:
            # The reference could not decode these bytes.  Never scored as
            # agreement, and never hidden.
            st['ref_no_decode'] += 1
            continue
        if r['f_ok'] != '1':
            # The tracer's classification stopped before the dependency model
            # ran, which its own sidecar log already reports.  Counted apart:
            # comparing an empty set built by an early return against a
            # reference's real answer would score a decode gap as a
            # dependency defect.
            st['tracer_unclassified'] += 1
            continue
        st['scored'] += 1

        for a in acc:
            for u in a.unmapped:
                unmapped[u] += 1

        ld, ld_imm = parse_slots(r['f_laddr'])
        stq, st_imm = parse_slots(r['f_saddr'])
        st['tracer_imm_bits'] += ld_imm + st_imm

        ref_union = set()
        for a in acc:
            ref_union |= a.regs
        trc_union = ld | stq

        axes = [('addrdep-union', frozenset(ref_union), frozenset(),
                 frozenset(trc_union), frozenset())]
        if ref.has_direction:
            rl, rs = set(), set()
            for a in acc:
                if a.is_load:
                    rl |= a.regs
                if a.is_store:
                    rs |= a.regs
            axes.append(('addrdep-split', frozenset(rl), frozenset(rs),
                         frozenset(ld), frozenset(stq)))

        for axis, rsrc, rdst, tsrc, tdst in axes:
            rset, tset = side_set(rsrc, rdst), side_set(tsrc, tdst)
            if rset == tset:
                st[axis + ':equal'] += 1
                continue
            rel = (SUPERSET if rset < tset else
                   SUBSET if tset < rset else ORTHOGONAL)
            st[axis + ':' + rel] += 1
            key = (axis, r['b_mnem'], rel,
                   'ref=' + (','.join(sorted(x[2:] for x in rset - tset))
                             or '-'),
                   'trc=' + (','.join(sorted(x[2:] for x in tset - rset))
                             or '-'))
            sig[axis][key] += 1
            sample.setdefault(key, (r['hex'], r['l_text']))

    say('=== ARC 3 -- ADDRESS-DEPENDENCY, %s ===' % A.isa)
    say('reference: %s%s' % (ref.name,
                             '' if ref.has_direction else
                             '  (no per-access direction: union axis only)'))
    say('tracer   : isaxcheck --layer=fields --batch  f_laddr / f_saddr'
        '%s' % ('   FALSIFIED ' + A.falsify if A.falsify else ''))
    say('')
    say('  encodings probed                     %8d' % st['probed'])
    say('  reference could not decode           %8d' % st['ref_no_decode'])
    say('  tracer classification did not run    %8d' % st['tracer_unclassified'])
    say('  SCORED                               %8d' % st['scored'])
    say('  displacement bits on the tracer side %8d' % st['tracer_imm_bits'])
    say('')
    for axis in ('addrdep-union', 'addrdep-split'):
        n = sum(st[axis + ':' + k]
                for k in ('equal', SUPERSET, SUBSET, ORTHOGONAL))
        if not n:
            continue
        say('  %-16s EQUAL %6d  TRACER-SUPERSET %5d  TRACER-SUBSET %5d  '
            'ORTHOGONAL %5d   (of %d)'
            % (axis, st[axis + ':equal'], st[axis + ':' + SUPERSET],
               st[axis + ':' + SUBSET], st[axis + ':' + ORTHOGONAL], n))
    say('')
    if unmapped:
        say('  REFERENCE REGISTERS WITH NO ROW IN THE TRACER TABLE '
            '(vocabulary gap, never agreement):')
        for k, v in unmapped.most_common(30):
            say('    %-20s %8d' % (k, v))
        say('')

    for axis in ('addrdep-union', 'addrdep-split'):
        if not sig[axis]:
            continue
        say('=== every disagreeing %s row, with a DIRECTION ===' % axis)
        say('  %-12s %-16s %-28s %-28s %8s  %s'
            % ('MNEMONIC', 'DIRECTION', 'REFERENCE ONLY', 'TRACER ONLY', 'N',
               'SAMPLE'))
        for key, n in sig[axis].most_common(A.maxreport):
            _ax, mnem, rel, ronly, tonly = key
            hexs, text = sample[key]
            say('  %-12s %-16s %-28s %-28s %8d  %s  %s'
                % (mnem[:12], rel, ronly[4:][:28], tonly[4:][:28], n,
                   hexs[:20], text[:44]))
        say('')

    crit = sum(st[a + ':' + k] for a in ('addrdep-union', 'addrdep-split')
               for k in (SUBSET, ORTHOGONAL))
    say('=== ROLL-UP ===')
    say('  TRACER-SUBSET + ORTHOGONAL (the criterion): %d' % crit)
    if fh:
        fh.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
