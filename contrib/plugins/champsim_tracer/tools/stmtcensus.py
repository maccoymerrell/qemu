#!/usr/bin/env python3
#
# The decoder-only statements, counted per encoding.
#
# Six facts have no op stream to be read off: atomicity, the encoded
# immediate's value, the vector lane shape, the synthetic address of an
# instruction that names one and accesses nothing, the CPUArchState ranges
# that resolve to a register name, and the architectural zero register an
# operand accessor folds away before any op sees it.  A decode site states
# each of them, and this is what says whether it did -- per ISA, over a whole
# guest corpus, one column per fact so a zero in one cannot be read as a zero
# in another.
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

COLUMNS = ('isa', 'encoding', 'atomic', 'imm', 'vece', 'oprsz',
           'vkind', 'vlane', 'memops', 'fieldregs', 'zero', 'pcread', 'ea',
           'selfloop', 'nrd', 'nwr')


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
        'lane_uniform': 0,
        'lane_insert': 0,
        'lane_extract': 0,
        'lane_bcast': 0,
        'lane_selected': 0,
        'lane_refused': 0,
        'synth_ea': 0,
        'synth_ea_refused': 0,
        'selfloop_iter': 0,
        'selfloop_access': 0,
        'selfloop_memops': 0,
        'memops': 0,
        'fieldreg_named': 0,
        'fieldreg_unnamed': 0,
        'zero_read': 0,
        'zero_write': 0,
        'pc_read': 0,
        'pc_absent': 0,
        'reg_reads': 0,
        'reg_writes': 0,
        'set_refused': 0,
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
        # The KIND and the SELECTED LANE are counted apart, and a refusal apart
        # from both: a kind with no lane (a packed operation) and a lane the
        # decode site would not state are different claims, and one column
        # could not tell them apart.
        kind_col = {'uniform': 'lane_uniform', 'insert': 'lane_insert',
                    'extract': 'lane_extract', 'bcast': 'lane_bcast'}
        if row['vkind'] in kind_col:
            c[kind_col[row['vkind']]] += 1
        if row['vlane'].startswith('refused:'):
            c['lane_refused'] += 1
        elif row['vlane'] != '-':
            c['lane_selected'] += 1
        if row['ea'] == 'refused':
            c['synth_ea_refused'] += 1
        elif row['ea'] != '-':
            c['synth_ea'] += 1
        # The two fan-out families are counted apart because they are
        # different claims: an ITERATED unit has an architectural iteration
        # count a consumer can ask QEMU for, and an access-unit family has
        # none.  The accesses column sums the stated units so a masked arm
        # that keeps the rows but changes the number still moves something.
        if row['selfloop'] != '-':
            kind, _, n = row['selfloop'].partition(':')
            if kind == 'iter':
                c['selfloop_iter'] += 1
            elif kind == 'access':
                c['selfloop_access'] += 1
            if n.isdigit():
                c['selfloop_memops'] += int(n)
        if row['memops'] != '0':
            c['memops'] += 1
        if row['fieldregs'] != '-':
            for nm in row['fieldregs'].split(','):
                if nm == '?':
                    c['fieldreg_unnamed'] += 1
                else:
                    c['fieldreg_named'] += 1
                    named[nm] = named.get(nm, 0) + 1
        if row['nrd'] == '-':
            c['set_refused'] += 1
        else:
            c['reg_reads'] += int(row['nrd'])
            c['reg_writes'] += int(row['nwr'])
        if 'r' in row['zero']:
            c['zero_read'] += 1
        if 'w' in row['zero']:
            c['zero_write'] += 1
        if row['pcread'] == '-':
            # The target has no program counter in the register namespace, so
            # this column is an ABSENT INSTRUMENT and not a measured zero.
            c['pc_absent'] += 1
        elif row['pcread'] == 'r':
            c['pc_read'] += 1
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
    print('   lane kind UNIFORM    %d' % c['lane_uniform'])
    print('   lane kind INSERT     %d' % c['lane_insert'])
    print('   lane kind EXTRACT    %d' % c['lane_extract'])
    print('   lane kind BROADCAST  %d' % c['lane_bcast'])
    print('   lane SELECTED        %d' % c['lane_selected'])
    print('   lane REFUSED         %d' % c['lane_refused'])
    print('   synthetic EA rows    %d' % c['synth_ea'])
    print('   synthetic EA refused %d' % c['synth_ea_refused'])
    print('   self-loop ITERATED   %d' % c['selfloop_iter'])
    print('   self-loop per-ACCESS %d' % c['selfloop_access'])
    print('   self-loop unit sum   %d' % c['selfloop_memops'])
    print('   memop rows           %d' % c['memops'])
    print('   env range NAMED      %d' % c['fieldreg_named'])
    print('   env range unnamed    %d' % c['fieldreg_unnamed'])
    print('   zero reg READ        %d' % c['zero_read'])
    print('   zero reg WRITTEN     %d' % c['zero_write'])
    print('   folded pc READ       %d' % c['pc_read'])
    print('   pc column ABSENT     %d' % c['pc_absent'])
    print('   register READS       %d' % c['reg_reads'])
    print('   register WRITES      %d' % c['reg_writes'])
    print('   set REFUSED          %d' % c['set_refused'])
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
