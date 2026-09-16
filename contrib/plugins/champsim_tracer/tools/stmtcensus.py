#!/usr/bin/env python3
#
# The decoder-only statements, counted per encoding.
#
# Five facts have no op stream to be read off: atomicity, the encoded
# immediate's value, the vector lane shape, the synthetic address of an
# instruction that names one and accesses nothing, and the CPUArchState ranges
# that resolve to a register name.  A decode site states each of them, and this
# is what says whether it did -- per ISA, over a whole guest corpus, one column
# per fact so a zero in one cannot be read as a zero in another.
#
# WHAT MAKES A ZERO READABLE.  An arm that masks one statement must move that
# column and no other; the report prints each column separately for exactly
# that reason, and `--compare` does the subtraction so the two readings are
# joined by the tool rather than by whoever quotes them.
#
# THE INSTRUMENT REFUSES RATHER THAN REPORTS NOTHING.  A corpus file that is
# missing, empty, headerless, or written by a different pair of binaries than
# its siblings is an error and not a zero: a scorer that cannot find its
# subject must fail, or its perfect scores are the instrument's silence.
#
# Author: Maccoy Merrell
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import os
import sys

COLUMNS = ('isa', 'encoding', 'atomic', 'imm', 'vece', 'oprsz', 'memops',
           'fieldregs')


def load(paths):
    """Merge the per-guest corpora by encoding, refusing a skewed set."""
    rows = {}
    stamp = None
    stamp_from = None
    seen_files = 0

    for p in paths:
        if not os.path.exists(p):
            sys.exit('stmtcensus: %s does not exist -- a corpus that was '
                     'asked for and is absent is a refusal, not a zero' % p)
        n_rows = 0
        with open(p) as f:
            for line in f:
                line = line.rstrip('\n')
                if line.startswith('#so '):
                    if stamp is None:
                        stamp, stamp_from = line, p
                    elif line != stamp:
                        sys.exit('stmtcensus: %s was written by a different '
                                 'build than %s\n  %s\n  %s\n'
                                 'joining corpora across builds is the frozen-'
                                 'arm failure and it does not announce itself'
                                 % (p, stamp_from, line, stamp))
                    continue
                if line.startswith('#') or not line:
                    continue
                parts = line.split('\t')
                if len(parts) != len(COLUMNS):
                    sys.exit('stmtcensus: %s: expected %d columns, got %d: %r'
                             % (p, len(COLUMNS), len(parts), line))
                row = dict(zip(COLUMNS, parts))
                key = (row['isa'], row['encoding'])
                prev = rows.get(key)
                if prev is not None and prev != row:
                    # The same bytes decoded twice with different answers is a
                    # real finding, not noise: it means a statement depends on
                    # something outside the encoding.  Keep both and say so.
                    row['_conflict'] = '1'
                rows[key] = row
                n_rows += 1
        if n_rows == 0:
            sys.exit('stmtcensus: %s carries no rows -- an empty corpus is an '
                     'instrument that did not run, not a decoder with nothing '
                     'to say' % p)
        seen_files += 1

    if stamp is None:
        sys.exit('stmtcensus: no #so build stamp in any of %s; an unstamped '
                 'corpus cannot be shown to belong to one build'
                 % ', '.join(paths))
    return rows, stamp, seen_files


def census(rows):
    """One count per fact class, over the merged encodings."""
    c = {
        'encodings': len(rows),
        'atomic': 0,
        'imm_any': 0,
        'imm_operand': 0,
        'imm_disp': 0,
        'vece': 0,
        'memops': 0,
        'fieldreg_named': 0,
        'fieldreg_unnamed': 0,
        'conflict': 0,
    }
    named = {}
    for row in rows.values():
        if row['atomic'] == '1':
            c['atomic'] += 1
        if row['imm'] != '-':
            c['imm_any'] += 1
            if 'imm:' in row['imm']:
                c['imm_operand'] += 1
            if 'disp:' in row['imm']:
                c['imm_disp'] += 1
        if row['vece'] != '-':
            c['vece'] += 1
        if row['memops'] != '0':
            c['memops'] += 1
        if row['fieldregs'] != '-':
            for nm in row['fieldregs'].split(','):
                if nm == '?':
                    c['fieldreg_unnamed'] += 1
                else:
                    c['fieldreg_named'] += 1
                    named[nm] = named.get(nm, 0) + 1
        if row.get('_conflict'):
            c['conflict'] += 1
    return c, named


def report(tag, c, named, stamp, nfiles, show_names):
    print('== %s' % tag)
    print('   %s' % stamp)
    print('   corpora joined       %d' % nfiles)
    print('   encodings            %d' % c['encodings'])
    print('   atomic               %d' % c['atomic'])
    print('   immediates (any)     %d' % c['imm_any'])
    print('     operand role       %d' % c['imm_operand'])
    print('     displacement role  %d' % c['imm_disp'])
    print('   lane shape stated    %d' % c['vece'])
    print('   memop rows           %d' % c['memops'])
    print('   env range NAMED      %d' % c['fieldreg_named'])
    print('   env range unnamed    %d' % c['fieldreg_unnamed'])
    print('   per-encoding conflict %d' % c['conflict'])
    if show_names:
        for nm, n in sorted(named.items(), key=lambda kv: -kv[1]):
            print('     %-12s %d' % (nm, n))


def main():
    ap = argparse.ArgumentParser(
        description='the decoder-only statements, counted per encoding')
    ap.add_argument('corpora', nargs='+', help='stmt.tsv files of one arm')
    ap.add_argument('--compare', nargs='+', default=None,
                    help="the other arm's stmt.tsv files")
    ap.add_argument('--names', action='store_true',
                    help='list the register names the env ranges resolved to')
    ap.add_argument('--require', nargs='*', default=[],
                    help='fact columns that must be non-zero (else exit 1)')
    args = ap.parse_args()

    rows, stamp, nfiles = load(args.corpora)
    c, named = census(rows)
    report('ARM A', c, named, stamp, nfiles, args.names)

    rc = 0
    for k in args.require:
        if k not in c:
            sys.exit('stmtcensus: --require names no such column: %s' % k)
        if c[k] == 0:
            print('RED: %s is 0 and was required to be non-zero' % k)
            rc = 1

    if args.compare:
        rows_b, stamp_b, nfiles_b = load(args.compare)
        cb, named_b = census(rows_b)
        report('ARM B', cb, named_b, stamp_b, nfiles_b, args.names)
        print('== A minus B')
        moved = 0
        for k in sorted(c):
            d = c[k] - cb[k]
            if d:
                moved += 1
            print('   %-22s %+d   (%d -> %d)' % (k, -d, c[k], cb[k]))
        if moved == 0:
            print('RED: nothing moved between the two arms -- either the mask '
                  'did not take or the statement was inert')
            rc = 1
    sys.exit(rc)


if __name__ == '__main__':
    main()
