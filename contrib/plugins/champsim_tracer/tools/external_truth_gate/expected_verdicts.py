#!/usr/bin/env python3
"""ARC 3 / R13 -- WHAT THE GATE SHOULD SAY ABOUT ONE EVIDENCE ROOT.

THE PROBLEM THIS SOLVES.  ``external_truth_gate.sh --selftest`` arm A used to
demand that the unmodified reports of its fixture PASS.  That is a stricter
demand than the question the arm exists to ask, and FINDING 245-C measured the
consequence: the two populations that could satisfy the two halves stopped
intersecting.  Every root old enough to have been gate-green is now INCOMPLETE
(eight manifest rows were re-pointed at an offline referee that did not exist
when those roots were written), and every root new enough to be COMPLETE
carries this tip's held reds -- reds standing on written merits, which is to
say reds that must NOT be relaxed to make a selftest convenient.  Arm A
therefore could not run at all, and arms B..G never executed behind it.

WHAT ARM A IS ACTUALLY FOR.  Not "is the project green".  It is "does the gate
read UNMODIFIED reports correctly" -- and that does not require the reports to
be green, it requires the gate's verdict over them to be the EXPECTED one.
So the expectation is written down beside the fixture, once, when the fixture
is adopted, and the arm compares against it.  A root that carries three
adjudicated reds is then a perfectly good fixture: the arm requires exactly
those three, with exactly those headlines, for exactly those reasons.

THIS IS #305's RULE, APPLIED ONE LEVEL UP.  The fixture still moves with the
ceilings; what moves with it now is its recorded expectation rather than a
demand that the reading be clean.

WHAT IS COMPARED, per manifest row:

    verdict    ok / FAIL
    headline   the number the gate parsed out of the report
    scored     the population the gate parsed out of the report
    reason     for a FAIL, the refusal's CLASS (the text before the first
               ':' or '.') -- so a row that fails for a DIFFERENT reason than
               the one recorded is a deviation, not a match

A row's headline and population are part of the expectation deliberately: a
parser that started reading the wrong number out of an unchanged report would
otherwise keep its verdict and pass this arm.

AND THE EXPECTATION MAY NOT BE CONSTANT.  A file whose rows are all `ok`, or
all `FAIL`, would be satisfied by a gate stuck at one answer -- the shape this
whole flow exists to forbid.  Both verdicts must appear, or the check refuses
and says so.  That is not a property of the gate; it is a property of the
FIXTURE, and it is what makes the fixture able to prove anything.

CIRCULARITY, STATED RATHER THAN HIDDEN.  ``--record`` writes the expectation
from a measurement of the very root it describes, so the first check after a
record is trivially satisfied.  That is why recording is a separate, explicit
act performed when a fixture is ADOPTED, and why the file it writes carries
the tip, the date and the root it was taken from: after that moment the file
is a bank, and any later movement in the gate's reading of unchanged reports
is a deviation the arm names.  Arms B and C prove the gate can still go red
from the same fixture, so a gate that degenerated to "always ok" fails there
even if it somehow passed here.

Exit codes: 0 all rows as expected, 1 otherwise.  Nothing is read through a
pipe.

Usage:
    expected_verdicts.py --record <root> [--out FILE] [--note TEXT]
    expected_verdicts.py --check  <root> [--expected FILE]

Author: Maccoy Merrell.
"""
import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import score  # noqa: E402  (same directory, no package)

DEFAULT_NAME = 'EXPECTED_VERDICTS.tsv'


def reason_class(why):
    """The CLASS of a refusal: everything before the first ':' or '.'.

    `UNADJUDICATED DISAGREEMENT: 51 > adjudicated 22.` -> `UNADJUDICATED
    DISAGREEMENT`.  The numbers are compared separately, through the headline
    column; what this column pins is that the row fails for the SAME REASON it
    was recorded failing for.  A row that swapped `REPORT MISSING` for
    `VACUOUS` has changed what the gate is saying about it even though the
    verdict column did not move.
    """
    if not why:
        return '-'
    cut = len(why)
    for ch in (':', '.'):
        i = why.find(ch)
        if i != -1:
            cut = min(cut, i)
    return why[:cut].strip() or '-'


def measure(root, manifest):
    """-> [(row, verdict, headline, scored, reason_class)] in manifest order."""
    out = []
    for r in score.read_manifest(manifest):
        # binary_mtime 0: this arm asks what the gate SAYS about these
        # reports, which is a different question from whether they are fresh.
        # Staleness has its own arm (D) and its own guard in the gate itself.
        ok, headline, scored, why = score.score_one(r, root, 0.0)
        out.append((r, 'ok' if ok else 'FAIL',
                    '-' if headline is None else str(headline),
                    '-' if scored is None else str(scored),
                    '-' if ok else reason_class(why)))
    return out


def read_expected(path):
    """-> {(leg, isa): (verdict, headline, scored, reason)}, in file order."""
    rows = {}
    order = []
    with open(path) as fh:
        for line in fh:
            line = line.rstrip('\n')
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            f = line.split('\t')
            if len(f) != 6:
                sys.exit('EXPECTATION MALFORMED: %r needs 6 tab-separated '
                         'fields, has %d.' % (line, len(f)))
            key = (f[0], f[1])
            if key in rows:
                sys.exit('EXPECTATION NAMES %s/%s TWICE.' % key)
            rows[key] = tuple(f[2:])
            order.append(key)
    if not rows:
        sys.exit('EXPECTATION IS EMPTY: %s.  A check with no subject fails.'
                 % path)
    return rows, order


def cmd_record(a):
    manifest = a.manifest
    out = a.out or os.path.join(a.root, DEFAULT_NAME)
    rows = measure(a.root, manifest)
    verdicts = set(v for _r, v, _h, _s, _w in rows)
    if verdicts != {'ok', 'FAIL'}:
        print('REFUSED: this root produces only %s verdicts.  An expectation '
              'that is constant can be satisfied by a gate stuck at one '
              'answer, which is the shape the whole flow exists to forbid.  '
              'A fixture must carry at least one row of each.'
              % ' and '.join(sorted(verdicts)), file=sys.stderr)
        return 1
    tip = 'unknown'
    try:
        tip = subprocess.check_output(
            ['git', '-C', HERE, 'rev-parse', 'HEAD'],
            stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        pass
    with open(out, 'w') as fh:
        fh.write('# THE GATE\'S EXPECTED VERDICT OVER THIS EVIDENCE ROOT.\n')
        fh.write('#\n')
        fh.write('# Written by expected_verdicts.py --record when this root\n')
        fh.write('# was ADOPTED as the selftest fixture.  Arm A of\n')
        fh.write('# external_truth_gate.sh --selftest compares the gate\'s\n')
        fh.write('# reading of these unmodified reports against these rows;\n')
        fh.write('# a deviation is a failure of the GATE, not of the root.\n')
        fh.write('# A FAIL row here is an adjudicated red standing on the\n')
        fh.write('# merits written in ADJUDICATED.tsv -- it is recorded, not\n')
        fh.write('# excused, and relaxing a ceiling to remove it is exactly\n')
        fh.write('# what this file exists to make unnecessary.\n')
        fh.write('#\n')
        fh.write('# root      : %s\n' % os.path.abspath(a.root))
        fh.write('# recorded  : %s\n' % time.strftime('%Y-%m-%d %H:%M:%S'))
        fh.write('# tree tip  : %s\n' % tip)
        if a.note:
            fh.write('# note      : %s\n' % a.note)
        fh.write('#\n')
        fh.write('# leg\tisa\tverdict\theadline\tscored\treason-class\n')
        for r, v, h, s, w in rows:
            fh.write('%s\t%s\t%s\t%s\t%s\t%s\n' % (r.leg, r.isa, v, h, s, w))
    print('RECORDED %d row(s) to %s' % (len(rows), out))
    for r, v, h, s, w in rows:
        print('    %-10s %-8s %-4s headline=%-8s scored=%-8s %s'
              % (r.leg, r.isa, v, h, s, w))
    return 0


def cmd_check(a):
    exp_path = a.expected or os.path.join(a.root, DEFAULT_NAME)
    if not os.path.isfile(exp_path):
        print('CHECK CANNOT RUN: no recorded expectation at %s.  Arm A '
              'compares the gate\'s reading against what this root was '
              'adopted saying; with no record there is nothing to compare '
              'against, and a check that cannot find its subject FAILS.  '
              'Run expected_verdicts.py --record %s first, and only when '
              'adopting the root.' % (exp_path, a.root), file=sys.stderr)
        return 1
    expected, _order = read_expected(exp_path)
    verdicts = set(e[0] for e in expected.values())
    if verdicts != {'ok', 'FAIL'}:
        print('EXPECTATION IS CONSTANT (%s only): %s.  A gate stuck at one '
              'answer would satisfy it, so it proves nothing.'
              % (' and '.join(sorted(verdicts)), exp_path), file=sys.stderr)
        return 1

    rows = measure(a.root, a.manifest)
    got = dict(((r.leg, r.isa), (v, h, s, w)) for r, v, h, s, w in rows)

    print('R13 EXPECTED-VERDICT CHECK')
    print('root        : %s' % a.root)
    print('expectation : %s' % exp_path)
    print('')
    print('%-10s %-8s %-6s %-10s %-10s  %s'
          % ('leg', 'isa', 'verdict', 'headline', 'scored', 'agreement'))
    print('-' * 78)

    deviations = []
    for r, v, h, s, w in rows:
        key = (r.leg, r.isa)
        e = expected.get(key)
        if e is None:
            note = 'NOT IN THE EXPECTATION'
            deviations.append((key, note))
        elif (v, h, s, w) == e:
            note = 'as recorded'
        else:
            bits = []
            for name, mine, theirs in (('verdict', v, e[0]),
                                       ('headline', h, e[1]),
                                       ('scored', s, e[2]),
                                       ('reason', w, e[3])):
                if mine != theirs:
                    bits.append('%s %s != recorded %s' % (name, mine, theirs))
            note = 'DEVIATES -- ' + '; '.join(bits)
            deviations.append((key, note))
        print('%-10s %-8s %-6s %-10s %-10s  %s' % (r.leg, r.isa, v, h, s, note))

    for key in expected:
        if key not in got:
            deviations.append((key, 'RECORDED BUT THE MANIFEST NO LONGER '
                                    'CARRIES THIS ROW'))
            print('%-10s %-8s %-6s %-10s %-10s  %s'
                  % (key[0], key[1], '-', '-', '-',
                     'RECORDED BUT THE MANIFEST NO LONGER CARRIES THIS ROW'))

    # The aggregation is checked too, and not by re-deriving it here: the gate
    # is run as the process a caller would run, and its exit status must be
    # the one the recorded rows imply.  A scorer that read every row right and
    # then summed them wrong would pass the loop above.
    want_rc = 1 if any(e[0] == 'FAIL' for e in expected.values()) else 0
    proc = subprocess.run([sys.executable, os.path.join(HERE, 'score.py'),
                           a.root, '--manifest', a.manifest],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print('')
    print('gate exit status: %d (expected %d from the recorded rows)'
          % (proc.returncode, want_rc))
    if proc.returncode != want_rc:
        deviations.append((('score.py', 'exit'),
                           'EXIT STATUS %d, the recorded rows imply %d'
                           % (proc.returncode, want_rc)))

    print('')
    if deviations:
        print('CHECK FAILED -- %d deviation(s) from the recorded expectation:'
              % len(deviations))
        for key, note in deviations:
            print('    %s/%s  %s' % (key[0], key[1], note))
        return 1
    print('CHECK PASSED -- %d row(s), every verdict, headline, population and '
          'refusal class exactly as recorded' % len(rows))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="record or check the gate's expected verdict over an "
                    "evidence root")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--record', metavar='ROOT')
    g.add_argument('--check', metavar='ROOT')
    ap.add_argument('--out', default=None,
                    help='where --record writes (default: <root>/%s)'
                         % DEFAULT_NAME)
    ap.add_argument('--expected', default=None,
                    help='what --check reads (default: <root>/%s)'
                         % DEFAULT_NAME)
    ap.add_argument('--note', default=None,
                    help='one line recorded in the file header')
    ap.add_argument('--manifest', default=score.MANIFEST)
    a = ap.parse_args()
    if a.record:
        a.root = a.record
        return cmd_record(a)
    a.root = a.check
    return cmd_check(a)


if __name__ == '__main__':
    sys.exit(main())
