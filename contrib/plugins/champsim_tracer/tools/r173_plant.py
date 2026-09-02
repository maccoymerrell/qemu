#!/usr/bin/env python3
"""Damage ONE source list in an R17.3 raw dump, so the oracle can be seen
to fail.

R17.3's headline is VARIANT=0, and a zero is equally consistent with "the
sets are invocation-invariant" and with "the oracle never reached its
subject".  This picks a (pc) that occurs at least twice with a
multi-register source list, truncates that list to its first register in
ONE of the occurrences, and writes the damaged dump out.  r173_check.py
must then report VARIANT>0.

A control that cannot be armed is a FAILURE and exits 2: it means the dump
holds no instruction reached twice, which is the case in which the clean
run's zero says nothing at all.

Author: Maccoy Merrell.
SPDX-License-Identifier: GPL-2.0-or-later
"""
import collections
import re
import sys

INSN = re.compile(r"insn\[\d+\] pc=(0x[0-9a-f]+)\s")
SRCRE = re.compile(r"^(\s+@\S+\s+[0-9a-f ]*\+?\s*src=\[)(.*?)(\]\s+dst=\[.*?\]\s*)$")


def main():
    if len(sys.argv) != 3:
        sys.exit('usage: r173_plant.py <src.raw> <dst.raw>')
    src, dst = sys.argv[1], sys.argv[2]
    try:
        lines = open(src, errors='replace').read().split('\n')
    except OSError as e:
        sys.exit('PLANT: cannot read %s (%s) -- a control that cannot find '
                 'its subject FAILS' % (src, e))
    seen = collections.Counter()
    idx = []
    pc = None
    for i, ln in enumerate(lines):
        m = INSN.search(ln)
        if m:
            pc = m.group(1)
            continue
        m = SRCRE.match(ln)
        if m and pc:
            seen[pc] += 1
            idx.append((i, pc, m))
    tgt = {p for p, c in seen.items() if c >= 2}
    for i, p, m in idx:
        if p in tgt and ',' in m.group(2):
            new = m.group(2).split(',')[0].strip()
            print('planted at pc=%s (%d occurrences): src [%s] -> [%s]'
                  % (p, seen[p], m.group(2), new))
            lines[i] = m.group(1) + new + m.group(3)
            open(dst, 'w').write('\n'.join(lines))
            return 0
    sys.exit('PLANT: no pc occurs twice with a multi-register source list in '
             '%s -- THE CONTROL COULD NOT BE ARMED, so the clean run\'s '
             'VARIANT=0 is not evidence' % src)


if __name__ == '__main__':
    sys.exit(main())
