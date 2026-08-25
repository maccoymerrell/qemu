#!/usr/bin/env python3
"""Census of QEMU's own decode-table identity against the disassembler's.

Reads idprobe TSV records -- one per translated instruction, produced by
idprobe.so -- and answers the two questions that decide whether QEMU's
decode identity can stand in for a Capstone-derived one:

  * how much identity does the slot NAME alone lose (the hazard: a name
    test is not an identity test)
  * where is the QEMU slot coarser than the disassembler's mnemonic, and
    where is it finer

Coarser-in-operand-size is GRANULARITY, not disagreement: QEMU resolves
X86_SIZE_v at decode time so one row serves andb/andw/andl/andq, while the
disassembler spells the width into the mnemonic.  The census reports it and
does not score it.

Author: Maccoy Merrell
"""
import argparse
import collections
import sys


def load(paths):
    rows = []
    for p in paths:
        with open(p) as f:
            for line in f:
                fields = line.rstrip('\n').split('\t')
                if len(fields) < 5:
                    continue
                mnem = fields[4].split()[0] if fields[4].strip() else '?'
                rows.append((int(fields[1]), fields[2], fields[3], mnem))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('tsv', nargs='+', help='idprobe output files')
    ap.add_argument('--label', default='(unlabelled)',
                    help='workload description printed in the header')
    ap.add_argument('--top', type=int, default=15)
    args = ap.parse_args()

    rows = load(args.tsv)
    if not rows:
        print('census: no records read -- refusing to report on nothing',
              file=sys.stderr)
        return 2
    n = len(rows)

    slot2mn = collections.defaultdict(collections.Counter)
    mn2slot = collections.defaultdict(collections.Counter)
    name2slot = collections.defaultdict(set)
    slotname = {}
    for sid, name, _, mnem in rows:
        slot2mn[sid][mnem] += 1
        mn2slot[mnem][sid] += 1
        name2slot[name].add(sid)
        slotname[sid] = name

    print('== PER-ROW MAPPING CENSUS: QEMU decode identity vs disassembler ==')
    print('workload: %s' % args.label)
    print('translated-instruction records: %d' % n)
    print()
    unident = sum(1 for r in rows if r[0] == 0)
    print('records with NO QEMU identity (slot 0): %d (%.3f%%)'
          % (unident, 100.0 * unident / n))
    print('QEMU slots exercised         : %d' % len(slot2mn))
    print('QEMU slot NAMES exercised    : %d' % len(name2slot))
    print('disassembler mnemonics       : %d' % len(mn2slot))
    print()

    print('-- A. identity the NAME alone loses --')
    lossy = {k: v for k, v in name2slot.items() if len(v) > 1}
    lost = sum(1 for _, name, _, _ in rows if len(name2slot[name]) > 1)
    print('names covering >1 exercised slot: %d' % len(lossy))
    print('records whose name does not determine the slot: %d (%.1f%%)'
          % (lost, 100.0 * lost / n))
    for name, slots in sorted(lossy.items(), key=lambda x: -len(x[1]))[:args.top]:
        print('    %-14s %2d slots: %s'
              % (name, len(slots), sorted(slots)))
    print()

    print('-- B. slot COARSER than mnemonic (one slot, many mnemonics) --')
    coarse = [(s, c) for s, c in slot2mn.items() if len(c) > 1]
    coarse.sort(key=lambda x: -len(x[1]))
    print('slots covering >1 mnemonic: %d of %d' % (len(coarse), len(slot2mn)))
    for sid, c in coarse[:args.top]:
        print('    slot %-6d %-14s %2d: %s'
              % (sid, slotname[sid], len(c),
                 ', '.join('%s(%d)' % kv for kv in c.most_common(6))))
    print()

    print('-- C. slot FINER than mnemonic (one mnemonic, many slots) --')
    fine = [(m, c) for m, c in mn2slot.items() if len(c) > 1]
    fine.sort(key=lambda x: -len(x[1]))
    print('mnemonics split across >1 slot: %d of %d' % (len(fine), len(mn2slot)))
    for mnem, c in fine[:args.top]:
        print('    %-12s %2d slots: %s'
              % (mnem, len(c),
                 ', '.join('%d/%s(%d)' % (k, slotname[k], v)
                           for k, v in c.most_common(6))))
    print()

    exact = sum(1 for c in slot2mn.values() if len(c) == 1)
    print('-- D. slots mapping to exactly one mnemonic: %d of %d (%.1f%%) --'
          % (exact, len(slot2mn), 100.0 * exact / len(slot2mn)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
