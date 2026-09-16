#!/usr/bin/env python3
"""Static census of the x86 decode table's identity-bearing slots.

Scans target/i386/tcg/decode-new.c.inc for every macro that fills a slot's
identity and checks the one property the exported id depends on: that no two
slots share a source line, because the i386 derivation of the id IS the
source line.  If this ever reports a collision, the export is silently
merging two decode rules and must be fixed before anything reads it.

Author: Maccoy Merrell
"""
import argparse
import collections
import json
import re
import sys

PAT = re.compile(r'\bX86_OP_(ENTRY[0-4rw]{0,2}|GROUP[0-3rw]{0,2}|LEAF|SET_GEN)'
                 r'\s*\(\s*([A-Za-z0-9_]+)\s*(?:,\s*([A-Za-z0-9_]+))?')


def scan(path):
    sites = []
    in_define = False
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip('\n')
            cont = line.endswith('\\')
            if line.lstrip().startswith('#define'):
                in_define = cont
                continue
            if in_define:
                in_define = cont
                continue
            for m in PAT.finditer(line):
                kind = m.group(1)
                name = m.group(3) if kind == 'SET_GEN' else m.group(2)
                sites.append((lineno, kind, name))
    return sites


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('source', help='path to decode-new.c.inc')
    ap.add_argument('--json', help='write the slot table here')
    args = ap.parse_args()

    sites = scan(args.source)
    if not sites:
        print('static_census: found no slots -- the scanner does not match '
              'this source, refusing to report 0', file=sys.stderr)
        return 2

    print('== STATIC CENSUS: x86 decode-table identity slots ==')
    print('source: %s' % args.source)
    print('identity-bearing slots: %d' % len(sites))
    kinds = collections.Counter(
        'ENTRY' if s[1].startswith('ENTRY')
        else 'GROUP' if s[1].startswith('GROUP') else s[1] for s in sites)
    for k in sorted(kinds):
        print('   %-8s %4d' % (k, kinds[k]))

    lines = collections.Counter(s[0] for s in sites)
    collisions = sorted(l for l, c in lines.items() if c > 1)
    print('slot-id (source line) collisions: %d' % len(collisions))

    names = collections.Counter(s[2] for s in sites)
    dup = {n: c for n, c in names.items() if c > 1}
    print('distinct names: %d' % len(names))
    print('names shared by >1 slot: %d, covering %d of %d slots (%.1f%%)'
          % (len(dup), sum(dup.values()), len(sites),
             100.0 * sum(dup.values()) / len(sites)))
    print('worst offenders: %s'
          % sorted(dup.items(), key=lambda x: -x[1])[:12])

    if args.json:
        with open(args.json, 'w') as f:
            json.dump([{'slot': a, 'kind': b, 'name': c} for a, b, c in sites],
                      f, indent=0)

    if collisions:
        print('FAIL: %d source lines carry more than one slot; the exported '
              'id cannot tell them apart: %s' % (len(collisions), collisions),
              file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
