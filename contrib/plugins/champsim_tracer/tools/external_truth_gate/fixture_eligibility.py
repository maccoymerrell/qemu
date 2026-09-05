#!/usr/bin/env python3
"""ARC 3 / R13 -- IS THIS EVIDENCE ROOT ELIGIBLE TO BE THE SELFTEST FIXTURE?

The selftest of ``external_truth_gate.sh`` proves the gate can go both ways:
arm A requires the UNMODIFIED reports of a real evidence root to pass, arm B
requires one planted disagreement to fail.  Which root plays that part is a
choice, and 70f56eff3a wrote the rule the choice has to satisfy:

    an evidence root is fixture-eligible when it is COMPLETE -- it carries
    every report the manifest names -- AND every headline it carries is one
    a live leg reproduces.

That commit stated the rule and then applied it BY NAME, refusing the one root
already known to fail it with a path match on ``*/verify55/*``.  A rule applied
by name is a rule applied from memory: it says nothing about the next root, and
the next root is the one nobody has checked.  THIS is the rule executed.

WHAT REPRODUCTION MEANS HERE, and what it does not.  Re-running gem5, Spike and
PIN takes hours and needs guests this repository does not carry, so this script
does not run the legs -- no more than the gate itself does.  What it can do,
and what the verify55 case was actually decided on, is ask whether any OTHER
independent run reads the same number.  verify55's ``gem5wp/aarch64`` report
carries 30; verify56, verify57 and exec127 each read 0 over 40,798 scored.
Three independent runs, one unreproduced report.  So:

    a headline is REPRODUCED when at least one other evidence root, written
    by a different run, parses to the same value on the same manifest row.

and a candidate carrying a headline that EVERY comparison root contradicts is
REFUSED, with the row, the candidate's value and the contradicting values all
named.

BOTH TESTS ALWAYS RUN, and the second does not stand down because the first
convicted.  An incomplete root that short-circuits here would take the
reproduction test's ONLY real subject off the table -- `verify55/r13/evroot`
is both incomplete AND unreproduced, so a test that stops at the first fault
can never be shown to convict on the second.  A control that cannot fire on
the one case it was written for is not a control.  Rows whose report the
candidate does not carry are skipped by test 2 and counted as skipped.  A row no comparison root carries at all is NOT a refusal and NOT a
pass: it is reported as UNCORROBORATED, because a manifest row younger than
every other root on disk has nothing to be corroborated against yet, and
convicting it would make the newest root permanently ineligible -- which is
the opposite of what the rule is for.  The count of uncorroborated rows is
printed so the choice is made with it in view.

Exit codes: 0 eligible, 1 refused.  Nothing is read through a pipe.

Author: Maccoy Merrell.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import score  # noqa: E402  (same directory, no package)


def headline_of(row, root):
    """-> (headline, note).  headline is None when the report cannot answer."""
    path = os.path.join(root, row.report)
    if not os.path.exists(path):
        return (None, 'absent')
    # binary_mtime 0: eligibility asks whether a number REPRODUCES, which is a
    # different question from whether it is fresh.  Staleness is the gate's own
    # guard and it runs there, against the build, every time the gate runs.
    _ok, headline, _scored, why = score.score_one(row, root, 0.0)
    if headline is None:
        return (None, why.split('.')[0])
    return (headline, '')


def main():
    ap = argparse.ArgumentParser(
        description="execute 70f56eff3a's fixture-eligibility rule against a "
                    "candidate evidence root")
    ap.add_argument('candidate', help='the evidence root being considered')
    ap.add_argument('--against', action='append', default=[],
                    help='an evidence root to corroborate against; repeatable')
    ap.add_argument('--manifest', default=score.MANIFEST)
    a = ap.parse_args()

    rows = score.read_manifest(a.manifest)
    others = [o for o in a.against
              if os.path.abspath(o) != os.path.abspath(a.candidate)]

    print('R13 FIXTURE-ELIGIBILITY TEST (the rule of 70f56eff3a, executed)')
    print('candidate     : %s' % a.candidate)
    for o in others:
        print('corroborator  : %s' % o)
    if not others:
        print('corroborator  : NONE GIVEN')
    print('')

    if not os.path.isdir(a.candidate):
        print('REFUSED: %s is not a directory.  A test with no subject fails.'
              % a.candidate)
        return 1

    # ---------------------------------------------------------- completeness
    absent_rows = [r for r in rows
                   if not os.path.isfile(os.path.join(a.candidate, r.report))]
    print('TEST 1 -- COMPLETE: every report the manifest names')
    if absent_rows:
        seen, missing = set(), []
        for r in absent_rows:
            if r.report not in seen:
                seen.add(r.report)
                missing.append(r.report)
        print('    REFUSED -- %d of %d row(s) name a report that is absent '
              '(%d distinct):' % (len(absent_rows), len(rows), len(missing)))
        for m in missing:
            print('        %s' % m)
    else:
        print('    PASS -- %d of %d present' % (len(rows), len(rows)))
    print('')

    # ----------------------------------------------------------- reproduction
    print('TEST 2 -- REPRODUCED: every headline a value another run also reads')
    print('')
    print('    %-10s %-8s %9s  %s'
          % ('leg', 'isa', 'candidate', 'corroboration'))
    print('    ' + '-' * 72)
    refused, uncorroborated, skipped = [], [], []
    for r in rows:
        mine, note = headline_of(r, a.candidate)
        if mine is None and note == 'absent':
            skipped.append(r)
            print('    %-10s %-8s %9s  skipped -- report absent (test 1)'
                  % (r.leg, r.isa, '-'))
            continue
        agree, differ, silent = [], [], []
        for o in others:
            theirs, _n = headline_of(r, o)
            tag = os.path.basename(os.path.dirname(os.path.dirname(o))) + \
                '/' + os.path.basename(os.path.dirname(o))
            if theirs is None:
                silent.append(tag)
            elif theirs == mine:
                agree.append(tag)
            else:
                differ.append('%s=%s' % (tag, theirs))
        if mine is None:
            verdict = 'UNPARSEABLE (%s)' % note
            refused.append((r, verdict))
        elif agree:
            verdict = 'reproduced by %d (%s)' % (len(agree), ', '.join(agree))
            if differ:
                verdict += '; differs on %s' % ', '.join(differ)
        elif differ:
            verdict = 'NOT REPRODUCED -- every corroborator differs: %s' \
                % ', '.join(differ)
            refused.append((r, verdict))
        else:
            verdict = 'UNCORROBORATED -- no corroborator carries this row'
            uncorroborated.append(r)
        print('    %-10s %-8s %9s  %s'
              % (r.leg, r.isa, '-' if mine is None else mine, verdict))

    print('')
    if skipped:
        print('    (%d row(s) skipped: no report to read -- test 1 named them)'
              % len(skipped))
        print('')
    if refused:
        print('REFUSED -- %d row(s) carry a headline no other run reproduces.'
              % len(refused))
        for r, why in refused:
            print('')
            print('    %s/%s  (%s)' % (r.leg, r.isa, r.report))
            print('        %s' % why)
        print('')
        print('A fixture whose numbers nothing reproduces proves nothing about')
        print('the gate: arm A would go green because the ceiling happens to')
        print('cover an unreproduced number, not because the gate reads')
        print('reports correctly.  The root stays on disk as the record of the')
        print('run that wrote it, which is a different thing from a fixture,')
        print('and the unreproduced number stays OWED as a finding about that')
        print('run.  Retiring the fixture does not close the question.')
        if absent_rows:
            print('')
            print('AND IT IS INCOMPLETE -- test 1 refused it as well.')
        return 1

    if absent_rows:
        print('REFUSED -- incomplete (test 1).  Every headline it DOES carry')
        print('reproduces, but a selftest run over a partial root proves less')
        print('than it claims.')
        return 1

    print('ELIGIBLE -- complete, and every headline it carries is one another')
    print('run reads too (%d row(s) uncorroborated: %s).'
          % (len(uncorroborated),
             ', '.join('%s/%s' % (r.leg, r.isa) for r in uncorroborated)
             or 'none'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
