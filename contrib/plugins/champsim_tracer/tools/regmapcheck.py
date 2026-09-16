#!/usr/bin/env python3
#
# Score the register map against what QEMU actually named, in both directions.
#
# The build already refuses a map that is short a name the TARGET SOURCE
# registers or that carries a row naming nothing (scripts/cst-regmap.py).  That
# is a static join and it answers for the source.  This tool answers for the
# RUN: the capture writes one row per distinct (direction, QEMU name) an
# instruction's register sets reached, with the generic id the map gave it, and
# this reads the two directions off that corpus.
#
#   DIRECTION 1, the one that can lose a register: every name the corpus
#   carries has a row in the map.  An UNMAPPED name FAILS -- it is a register
#   the wire could not publish, and the two static halves could not have seen
#   it if the emulator names something the source scrape did not reach.
#
#   DIRECTION 2, the one that can hide dead weight: every row in the map was
#   reached.  This REPORTS rather than fails, and the distinction is a
#   measurement and not a softening: which registers a target registers depends
#   on the CPU MODEL (MXU only on 32-bit MIPS, AVX-512 masks only on a machine
#   that has them, SVE predicates only under SVE), so a row no guest reached is
#   coverage this corpus lacks, not a rule that is wrong.  The static join is
#   what makes a genuinely dead row impossible.
#
# A corpus that is absent, empty or written by another build REFUSES: an
# instrument that did not run reports nothing, never a perfect zero.
#
# Author: Maccoy Merrell

import argparse
import os
import sys

COLUMNS = ('isa', 'encoding', 'dir', 'name', 'generic')

ISA_TSV = {
    'x86_64': 'x86_64', 'i386': 'x86_64',
    'aarch64': 'aarch64',
    'riscv64': 'riscv64', 'riscv32': 'riscv64',
    'mipsel': 'mipsel', 'mips': 'mipsel',
}


def load_corpus(paths):
    rows = []
    stamp = None
    stamp_from = None

    for p in paths:
        if not os.path.exists(p):
            sys.exit('regmapcheck: %s does not exist -- a corpus that was '
                     'asked for and is absent is a refusal, not a zero' % p)
        n = 0
        with open(p) as f:
            for line in f:
                line = line.rstrip('\n')
                if line.startswith('#so '):
                    if stamp is None:
                        stamp, stamp_from = line, p
                    elif line != stamp:
                        sys.exit('regmapcheck: %s was written by a different '
                                 'build than %s\n  %s\n  %s'
                                 % (p, stamp_from, stamp, line))
                    continue
                if not line or line.startswith('#'):
                    continue
                parts = line.split('\t')
                if len(parts) != len(COLUMNS):
                    sys.exit('regmapcheck: %s: expected %d columns, got %d: %r'
                             % (p, len(COLUMNS), len(parts), line))
                rows.append(dict(zip(COLUMNS, parts)))
                n += 1
        if n == 0:
            sys.exit('regmapcheck: %s carries no rows -- an empty corpus is an '
                     'instrument that did not run, not a run with no registers'
                     % p)
    if stamp is None:
        sys.exit('regmapcheck: no #so build stamp in any of %s; an unstamped '
                 'corpus cannot be shown to belong to one build'
                 % ', '.join(paths))
    return rows, stamp


def load_map(tsvdir, isa):
    path = os.path.join(tsvdir, '%s.tsv' % isa)
    if not os.path.exists(path):
        sys.exit('regmapcheck: no map at %s' % path)
    out = {}
    with open(path) as f:
        for line in f:
            line = line.rstrip('\n')
            if not line or line.lstrip().startswith('#'):
                continue
            name, reg, _ground = line.split('\t')
            out[name.strip()] = reg.strip()
    if not out:
        sys.exit('regmapcheck: %s carries no rows' % path)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('corpus', nargs='+', help='regmap corpora (CST_REGMAP_DUMP)')
    ap.add_argument('--maps', required=True,
                    help='directory holding <isa>.tsv')
    ap.add_argument('--show-unreached', action='store_true')
    args = ap.parse_args()

    rows, stamp = load_corpus(args.corpus)

    by_isa = {}
    for r in rows:
        by_isa.setdefault(r['isa'], []).append(r)

    print('== register map, both directions')
    print('   %s' % stamp)
    print('   corpora joined       %d' % len(args.corpus))
    rc = 0
    for isa in sorted(by_isa):
        tsv = ISA_TSV.get(isa)
        if tsv is None:
            print('   %-9s UNKNOWN ISA -- no map to score against' % isa)
            rc = 1
            continue
        m = load_map(args.maps, tsv)
        seen = {}
        unmapped = []
        disagree = []
        for r in by_isa[isa]:
            seen.setdefault(r['name'], set()).add(r['generic'])
            if r['generic'] == 'UNMAPPED':
                unmapped.append(r)
            elif m.get(r['name']) != r['generic']:
                # The running plugin and the checked-in table disagreed about
                # a name.  That is a stale generated header, not a decoder
                # gap, and it must not read as a pass.
                disagree.append((r['name'], r['generic'], m.get(r['name'])))
        reached = set(seen)
        unreached = sorted(set(m) - reached)
        print('   %-9s names seen %4d   map rows %4d   reached %4d   '
              'UNMAPPED %d' % (isa, len(reached), len(m), len(reached),
                               len(unmapped)))
        if unmapped:
            rc = 1
            for r in sorted({(x['name'], x['encoding']) for x in unmapped}):
                print('      UNMAPPED %s (first at %s)' % r)
        if disagree:
            rc = 1
            for d in sorted(set(disagree)):
                print('      TABLE SKEW %s: running=%s checked-in=%s' % d)
        print('      map rows this corpus did not reach: %d' % len(unreached))
        if args.show_unreached and unreached:
            print('      %s' % ' '.join(unreached))

    print('   VERDICT %s' % ('PASS' if rc == 0 else 'FAIL'))
    return rc


if __name__ == '__main__':
    sys.exit(main())
