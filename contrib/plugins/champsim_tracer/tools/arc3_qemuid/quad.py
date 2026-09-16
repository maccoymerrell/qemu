#!/usr/bin/env python3
"""The identity reader's four counters, computed offline from idprobe records.

champsim_tracer_qemu_ident.cc counts, per translated instruction:

    read            -- instructions the reader saw
    no-identity     -- the target exported none (id == 0)
    missing-row     -- an id arrived that the generated table has no row for
    name-mismatch   -- a row was found and its name disagrees with QEMU's

Those four are a property of the EXPORT and the TABLE, not of the tracer, so
they can be recomputed from an idprobe TSV plus the generated header.  This
tool exists because the in-tree reader cannot always be run -- it lives in a
plugin, and a plugin has to load.

It refuses an empty input and refuses a table it could not parse: a zero
printed by a reader that found nothing to read is the failure mode this whole
census exists to avoid.

Author: Maccoy Merrell
"""
import argparse
import collections
import re
import sys
from pathlib import Path

ROW = re.compile(r'^\s*\{\s*(0x[0-9a-fA-F]+)u,\s*"([^"]*)"')


def load_table(path):
    rows = {}
    for line in Path(path).read_text().splitlines():
        m = ROW.match(line)
        if m:
            rows[int(m.group(1), 16)] = m.group(2)
    if not rows:
        sys.exit("%s: no rows parsed -- refusing to score against nothing"
                 % path)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--table', required=True)
    ap.add_argument('--label', default='(unlabelled)')
    ap.add_argument('--top', type=int, default=20)
    ap.add_argument('tsv', nargs='+')
    a = ap.parse_args()

    rows = load_table(a.table)
    n = no_id = missing = mismatch = 0
    unident = collections.Counter()
    miss = collections.Counter()
    mism = collections.Counter()
    hit = set()
    for p in a.tsv:
        for line in Path(p).read_text().splitlines():
            f = line.split('\t')
            if len(f) < 5:
                continue
            n += 1
            ident = int(f[1])
            qname = f[2]
            mnem = f[4].split()[0] if f[4].strip() else '?'
            if ident == 0:
                no_id += 1
                unident[mnem] += 1
                continue
            if ident not in rows:
                missing += 1
                miss['id=0x%08x name=%s cap=%s' % (ident, qname, mnem)] += 1
                continue
            hit.add(ident)
            if rows[ident] != qname:
                mismatch += 1
                mism['id=0x%08x qemu=%s table=%s'
                     % (ident, qname, rows[ident])] += 1
    if n == 0:
        sys.exit('no idprobe records read -- refusing to report on nothing')

    print('== identity reader quad: %s ==' % a.label)
    print('table                    : %s (%d rows)' % (a.table, len(rows)))
    print('read                     : %d' % n)
    print('no identity (id == 0)    : %d  (%.3f%%)' % (no_id, 100.0 * no_id / n))
    print('id with NO ROW in table  : %d' % missing)
    print('row found, NAME DISAGREES: %d' % mismatch)
    print('table rows reached       : %d of %d' % (len(hit), len(rows)))
    if unident:
        print('\nunidentified, BY OPCODE (never a bare count):')
        for k, v in unident.most_common():
            print('    %-16s %d' % (k, v))
    for title, c in (('missing rows', miss), ('name mismatches', mism)):
        if c:
            print('\n%s:' % title)
            for k, v in c.most_common(a.top):
                print('    %s  x%d' % (k, v))
    return 0


if __name__ == '__main__':
    sys.exit(main())
