#!/usr/bin/env python3
"""ARC 3 / R13 -- PLANT ONE DISAGREEMENT THE GATE MUST SEE.

WHY THE PLANT IS CHOSEN RATHER THAN NAMED.  The selftest's arm B used to plant
a fixed edit: `TRACER-SUBSET + UNACCOUNTED = 22` -> `23` in
`gem5/rc_aarch64.log`, because that row's ceiling was 22 and the fixture read
22.  That is a plant on a row which, at this tip and on any root measured at
it, ALREADY FAILS at 51.  Two things go wrong at once and neither is visible
from the arm's own output: the `sed` finds nothing, so the plant does not take;
and even if it did, flipping a row that was already FAIL proves nothing about
whether the gate can go red -- it was red before the plant and red after.  An
arm whose subject has silently moved out from under it is the failure mode
this project calls silent false success, and a hard-coded target guarantees it
recurs every time a ceiling or a reading moves.

SO THE TARGET IS DERIVED FROM THE EVIDENCE.  This picks the first manifest row
that

    (1) the root's recorded expectation says is `ok` -- so the flip to FAIL is
        an observable change and not a repaint of an existing red; and
    (2) carries a headline this can damage exactly: a single integer captured
        by that leg's own headline pattern in score.py.  The pattern comes
        from the scorer, so the number this rewrites is by construction the
        number the scorer reads.

and rewrites that integer to CEILING + 1: the smallest value that must fail,
which is also the value that proves the comparison is `>` and not `>=`.

The reference legs (refopc, refsrc and their dead-arbitration siblings) sum
their headline out of several printed lines and are deliberately NOT plantable
here -- a single-number rewrite cannot express a plant on them, and arm G
proves those rows refuse a malformed report by its own fixtures.

Exit codes: 0 planted (details on stdout), 1 nothing plantable.  Nothing is
read through a pipe.

Usage:
    plant.py <root> [--expected FILE] [--pick-only]

Author: Maccoy Merrell.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import score              # noqa: E402  (same directory, no package)
import expected_verdicts  # noqa: E402


def main():
    ap = argparse.ArgumentParser(
        description='plant one above-ceiling disagreement in an evidence root')
    ap.add_argument('root')
    ap.add_argument('--expected', default=None)
    ap.add_argument('--pick-only', action='store_true',
                    help='print the row that would be planted and stop')
    ap.add_argument('--manifest', default=score.MANIFEST)
    a = ap.parse_args()

    exp_path = a.expected or os.path.join(a.root,
                                          expected_verdicts.DEFAULT_NAME)
    if not os.path.isfile(exp_path):
        print('NO RECORDED EXPECTATION at %s, so there is no way to tell '
              'which rows are green and a plant could land on a row that was '
              'already red.  A plant that cannot be shown to have changed '
              'anything proves nothing.' % exp_path, file=sys.stderr)
        return 1
    expected, _order = expected_verdicts.read_expected(exp_path)

    considered = []
    for r in score.read_manifest(a.manifest):
        e = expected.get((r.leg, r.isa))
        if e is None:
            considered.append((r, 'not in the expectation'))
            continue
        if e[0] != 'ok':
            considered.append((r, 'expected %s -- a plant here would repaint '
                                  'an existing red' % e[0]))
            continue
        pat, kind = score.HEADLINE[r.leg]
        if pat is None or kind != 'int':
            considered.append((r, 'headline is not a single captured integer '
                                  '(kind %s)' % kind))
            continue
        path = os.path.join(a.root, r.report)
        if not os.path.isfile(path):
            considered.append((r, 'report absent'))
            continue
        text = open(path, errors='replace').read()
        m = pat.search(text)
        if not m:
            considered.append((r, 'headline pattern does not match the report'))
            continue

        old = m.group(1)
        new = str(r.ceiling + 1)
        print('PLANT TARGET  %s/%s' % (r.leg, r.isa))
        print('  report      %s' % r.report)
        print('  expectation ok (headline %s, ceiling %d)' % (e[1], r.ceiling))
        print('  rewriting   %s -> %s  (ceiling + 1: the smallest value that '
              'must fail)' % (old, new))
        if a.pick_only:
            print('PICKED %s %s %s %s' % (r.leg, r.isa, r.report, new))
            return 0
        s, t = m.span(1)
        open(path, 'w').write(text[:s] + new + text[t:])
        # Prove the plant took by reading it back through the SCORER, not by
        # grepping our own edit: the number that matters is the one score.py
        # parses, and a rewrite that landed in a place the parser does not
        # look would grep clean and score unchanged.
        back = open(path, errors='replace').read()
        m2 = pat.search(back)
        if not m2 or m2.group(1) != new:
            print('PLANT DID NOT TAKE: the scorer still reads %s out of %s.'
                  % (m2.group(1) if m2 else 'nothing', path), file=sys.stderr)
            return 1
        print('PLANTED %s %s %s %s' % (r.leg, r.isa, r.report, new))
        return 0

    print('NOTHING PLANTABLE in %s.  Every manifest row was rejected:'
          % a.root, file=sys.stderr)
    for r, why in considered:
        print('    %-10s %-8s %s' % (r.leg, r.isa, why), file=sys.stderr)
    print('A selftest arm with no subject FAILS rather than passing by '
          'absence.  A fixture needs at least one green row whose headline '
          'is a single integer.', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
