#!/usr/bin/env python3
"""The must-be-0 row scanner for a tracer stats sidecar -- BOTH row shapes.

WHY THIS FILE EXISTS AT ALL.  Every acceptance reads the "MUST BE 0" rows out
of the stats sidecar, and every wave until now wrote its own reader inline in
its battery script.  Two of those readers were wrong in the same way and each
was believed for a night:

  * reading only the line that carries the phrase misses the rows whose text
    wraps, so the phrase lands on a continuation line and the count sits on
    the line above it;
  * reading a fixed `grep -B2` window instead picks up the leading integer of
    an UNRELATED row above, which is how a battery reported
    `must0_nonzero_rows=1` on all four ISAs while every real row read 0.

Both shapes are in the same file, so a reader that handles one and not the
other is not a reader.  This is the one location; batteries cite this path.

THE RULE.  A row's count is the leading integer of the line the row's TEXT
begins on -- the phrase line itself when the phrase starts the row, otherwise
the nearest preceding line that starts with an integer, within the height of
one wrapped row.

WHAT IS *NOT* A MUST-BE-0 ROW, stated because two census columns are now
honestly non-zero and reading them as red would be a false alarm:

  NOT-SCORED   published sources on instructions whose read list QEMU
               withheld.  Non-zero by construction since the source census
               was hoisted above apply_dst's write-side refusal return
               (#327/#328) -- before that it printed a zero about a
               population it never looked at.
  ADJ-OWED     published sources held out of MISSING because their deletion
               was landed, measured against the external references and
               REVERTED.  Non-zero means an OPEN maintainer question, and it
               blocks any source-list flip; it does not mean a red gate.

Neither line carries the phrase, so neither is scanned here.  That is the
membership rule and not a special case: a column is a must-be-0 row exactly
when the plugin writes "MUST BE 0" in its own text.

Exit 1 when any row is non-zero, or when a file carries NO must-be-0 row at
all: a scanner that cannot find its subject FAILS.  Exit 2 on a usage or
selftest failure.

Author: Maccoy Merrell.
"""
import argparse
import os
import re
import sys
import tempfile

LEAD = re.compile(r'^\s*(\d+)\s+\S')
WRAP_HEIGHT = 4          # a wrapped row is at most this many lines tall


def scan(path):
    """-> [(count|None, text)] for every must-be-0 row in @path."""
    rows = []
    lines = open(path, errors='replace').read().splitlines()
    for i, ln in enumerate(lines):
        if 'MUST BE 0' not in ln:
            continue
        for j in range(i, max(-1, i - WRAP_HEIGHT), -1):
            m = LEAD.match(lines[j])
            if m:
                rows.append((int(m.group(1)), lines[j].strip()[:70]))
                break
        else:
            rows.append((None, ln.strip()[:70]))
    return rows


def report(paths, quiet=False):
    rc = 0
    for p in paths:
        if not os.path.exists(p):
            print('%s: MISSING -- a scanner that cannot find its subject '
                  'fails' % p)
            rc = 1
            continue
        rows = scan(p)
        if not rows:
            print('%s: NO must-be-0 ROW FOUND -- the scanner has no subject'
                  % p)
            rc = 1
            continue
        bad = [r for r in rows if r[0] != 0]
        print('%s: must-be-0 rows=%d non-zero=%d'
              % (p, len(rows), len(bad)))
        if not quiet:
            for v, t in rows:
                print('     %s  %s' % ('?' if v is None else v, t))
        if bad:
            rc = 1
    return rc


# --------------------------------------------------------------- selftest
# A scanner is only a scanner if it can go red, and if it reads BOTH shapes.
# Each arm below is one way this reader has actually been wrong.
_SHAPE_A = """\
tracer statistics
        12  something unrelated
         0  spec_mode_leak                                (MUST BE 0)
         0  close_in_mid_step                             (MUST BE 0)
"""
_SHAPE_B = """\
tracer statistics
        12  something unrelated
         0  a row whose descriptive text is long enough that the marker
            wraps onto the next line                      (MUST BE 0)
"""
_SHAPE_B_RED = _SHAPE_B.replace('         0  a row', '         7  a row')
_NO_SUBJECT = "tracer statistics\n        12  something unrelated\n"


def selftest():
    d = tempfile.mkdtemp(prefix='must0_selftest.')
    def w(name, text):
        p = os.path.join(d, name)
        open(p, 'w').write(text)
        return p
    ok = True

    a = w('a.log', _SHAPE_A)
    rows = scan(a)
    if [r[0] for r in rows] != [0, 0]:
        print('ARM 1 FAILED: plain shape read %r' % rows); ok = False
    else:
        print('ARM 1 ok: plain rows read 0, 0')

    b = w('b.log', _SHAPE_B)
    rows = scan(b)
    if [r[0] for r in rows] != [0]:
        print('ARM 2 FAILED: WRAPPED shape read %r -- this is the shape a '
              'phrase-line-only reader misses' % rows); ok = False
    else:
        print('ARM 2 ok: wrapped row read 0, not the 12 above it')

    br = w('bred.log', _SHAPE_B_RED)
    if report([br], quiet=True) == 0:
        print('ARM 3 FAILED: a non-zero wrapped row passed'); ok = False
    else:
        print('ARM 3 ok: non-zero wrapped row FAILS')

    n = w('none.log', _NO_SUBJECT)
    if report([n], quiet=True) == 0:
        print('ARM 4 FAILED: a file with no must-be-0 row passed by silence')
        ok = False
    else:
        print('ARM 4 ok: absent subject FAILS')

    if report([os.path.join(d, 'nope.log')], quiet=True) == 0:
        print('ARM 5 FAILED: a missing file passed'); ok = False
    else:
        print('ARM 5 ok: missing file FAILS')

    print('SELFTEST %s -- 5 arms' % ('PASSED' if ok else 'FAILED'))
    return 0 if ok else 2


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('files', nargs='*')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--quiet', action='store_true',
                    help='print the per-file totals without the row list')
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.files:
        ap.error('no files given; a scanner with no subject is not a check')
    return report(a.files, a.quiet)


if __name__ == '__main__':
    sys.exit(main())
