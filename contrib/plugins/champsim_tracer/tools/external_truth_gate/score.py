#!/usr/bin/env python3
"""ARC 3 / R13 -- score the external-truth flow's leg reports against the
adjudicated ceilings.

R13 makes the multi-static-decode + execution-simulation flow a STANDING GATE.
This is the scorer behind the one entry point (``external_truth_gate.sh``).
It reads each leg's own report, pulls the leg's HEADLINE -- the count of rows
where the tracer drops information a reference states, or where the difference
is not understood -- and compares it to the ceiling a maintainer adjudicated
row by row.

WHAT MAKES IT FAIL, and every one of these is a FAILURE and not a skip:

* a report named in the manifest is missing            (the check cannot find
  its subject, so it must fail -- it may never pass by absence)
* a headline cannot be parsed out of a report          (same reason)
* a headline EXCEEDS its adjudicated ceiling           (a new disagreement)
* a leg's scored population is below its FLOOR         (vacuity: a leg that
  compared nothing reports zero disagreements, which is not a result)
* a report is OLDER than the tracer binaries it is
  supposed to have measured                            (staleness: a green
  taken against a previous build is not a green)

Author: Maccoy Merrell.
"""
import argparse
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import behavior_digest  # noqa: E402  (same directory, no package)

MANIFEST = os.path.join(HERE, 'ADJUDICATED.tsv')

# Each leg's report is written by a different harness, so the headline is
# matched per leg rather than by one hopeful regex over all of them.  A leg
# whose pattern does not match is a FAILURE, never a zero.
HEADLINE = {
    # the eight-arm Capstone-as-external-reference gate: count the arms that
    # did NOT exit 0, so the ceiling of 0 means "every arm passed"
    'isax':    (re.compile(r'^(?:boundary|fields)\s+(\S+)\s+rc=(\d+)', re.M), 'isax'),
    # THE DEAD-ALLOWLIST-RULE FACT, scored on BOTH arm shapes (FINDING
    # 72-F).  `isax` above scores the arms' EXIT CODES, and it can only ever
    # be asked of the bare half: a `--srcenc` arm carries the boundary
    # residue as `unallowed`, so it exits 1 by construction and an exit-code
    # ceiling over it would be a number about the residue, not about the
    # allowlist.  The dead-rule question is different -- every arm answers it
    # for the families IT scores, and the two shapes are partial in
    # COMPLEMENTARY families -- so it gets its own leg, one row per shape,
    # and both reports must be present for the union to cover the allowlist.
    #
    # MEASURED, and this is why the row exists: at PASS 72 one
    # `SR-rd-phantom ffree` row went dead two commits after it landed, the
    # `--srcenc` x86_64 fields arm PRINTED `dead_allow_rules=1`, and the gate
    # passed 17 of 17 -- correctly, because the eight arms it scored were the
    # bare ones and the `SR-` family is exempt from the detector there.  A
    # detector nobody reads is not a detector.
    'isaxdead': (re.compile(r'^# isa=\S+ layer=\S+ .*dead_allow_rules=(\d+)',
                            re.M), 'isaxdead'),
    # the four-ISA cross-tabulation is the ONE static report that carries the
    # headline AND its denominator AND the reachability hole on the same row,
    # so the static leg reads that rather than the per-ISA compare files (two
    # of which carry no denominator at all -- see PASS 11)
    'static':  (None, 'coverage'),
    'gem5cp':  (re.compile(r'the number that matters:\s*TRACER-SUBSET \+ UNACCOUNTED\s*=\s*(\d+)'), 'int'),
    'spikecp': (re.compile(r'HEADLINE\s+TRACER-SUBSET \+ UNACCOUNTED\s*=\s*(\d+)'), 'int'),
    'gem5wp':  (re.compile(r'THE NUMBER THAT MATTERS:\s*WP-DEFECT \+ RECONSTRUCTION-GAP \+\s*\n\s*UNACCOUNTED\s*=\s*(\d+)'), 'int'),
    'spikewp': (re.compile(r'THE NUMBER THAT MATTERS:\s*WP-DEFECT \+ RECONSTRUCTION-GAP \+\s*\n\s*UNACCOUNTED\s*=\s*(\d+)'), 'int'),
    'pin':     (re.compile(r'SUBSET \+ UNACCOUNTED \(the criterion; must be 0\):\s*(\d+)'), 'int'),
    # THE DEPENDENCY MAP, and it is scored in BOTH directions by two rows
    # over the SAME report.  `depmap` is the loss direction -- the map omits
    # an edge gem5 states -- and `depmapprec` is the precision the map
    # discards.  Two rows rather than one sum, because a sum lets a new loss
    # hide behind a retired over-approximation; and both rather than the loss
    # alone, because three of the instrument's five falsifiers land in the
    # precision column, so a gate holding only the loss number could not see
    # the arms that prove the axis convicts.  See score_depmap.py.
    'depmap':     (None, 'depmap'),
    'depmapprec': (None, 'depmapprec'),
}

# The population each leg actually compared.  A leg reporting zero
# disagreements over zero comparisons is survivorship bias, not coverage.
FLOOR = {
    'isax':    re.compile(r'^(?:boundary|fields)\s+\S+\s+rc=\d+', re.M),
    'isaxdead': re.compile(r'^# isa=\S+ layer=\S+ .*dead_allow_rules=\d+',
                           re.M),
    'static':  None,
    'gem5cp':  re.compile(r'^TOTAL\s+(\d+)', re.M),
    'spikecp': re.compile(r'^\s*aligned\s+(\d+)', re.M),
    'gem5wp':  re.compile(r'^TOTAL\s+(\d+)', re.M),
    'spikewp': re.compile(r'^TOTAL\s+(\d+)', re.M),
    'pin':     re.compile(r'lockstep walk:\s*(\d+) byte-identical pairs'),
    # the number of dependency FACTS compared, summed over the four axes
    'depmap':     re.compile(r'^TOTAL FACTS = (\d+)', re.M),
    'depmapprec': re.compile(r'^TOTAL FACTS = (\d+)', re.M),
}


class Row(object):
    __slots__ = ('leg', 'isa', 'report', 'ceiling', 'floor',
                 'retired_by', 'adjudication')


def read_manifest(path):
    rows = []
    with open(path) as fh:
        for line in fh:
            line = line.rstrip('\n')
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            f = line.split('\t')
            if len(f) < 7:
                sys.exit('MANIFEST MALFORMED: %r needs 7 tab-separated fields, '
                         'has %d.  A ceiling without its adjudication is not a '
                         'ceiling.' % (line, len(f)))
            r = Row()
            (r.leg, r.isa, r.report, ceil, flr,
             r.retired_by, r.adjudication) = f[:7]
            r.ceiling, r.floor = int(ceil), int(flr)
            if r.leg not in HEADLINE:
                sys.exit('MANIFEST NAMES AN UNKNOWN LEG: %r.  Add its headline '
                         'pattern to score.py before adding it here -- a leg '
                         'nothing can parse would pass by silence.' % r.leg)
            rows.append(r)
    if not rows:
        sys.exit('MANIFEST IS EMPTY: a gate with no legs passes everything.')
    return rows


# THE STALENESS REFERENCE IS THE WHOLE MEASURED SUBJECT, NOT JUST THE PLUGIN.
#
# It used to be the plugin .so and cst_decode alone, and that is a hole this
# arc walked straight into.  Every execution leg -- gem5, Spike, PIN -- runs a
# QEMU EMULATOR beside the plugin, and the dataflow facts those legs score are
# produced by the emulator: the translator states them and the plugin only
# carries them.  #288's fix (9070200114) lived entirely in
# accel/tcg/insn-dataflow.c and target/i386/tcg/translate.c and touched
# neither of the two files this guard used to watch, so a report taken BEFORE
# that fix would have been called fresh AFTER it.  It was caught only because
# an unrelated relink happened to move cst_decode's mtime in between.
#
# So the reference is the newest of the plugin, the offline decoder and every
# emulator present in the build directory, and the file that set it is named
# in the header so the reader can see which one the reports are being held
# against.
#
# AND THE REFERENCE IS A BEHAVIOUR TIME, NOT A LINK TIME (#292).  Widening the
# reference to all 62 emulators made the guard correct and made it useless in
# the same commit: QEMU rebuilds `qemu-version.h` from `git describe`, so any
# commit at all relinks every emulator and moves every mtime, and every
# execution leg read stale after a comment.  What each binary is now held at
# is the mtime at which its BEHAVIOUR-BEARING BYTES last changed -- see
# behavior_digest.py for what that means and, just as importantly, for the one
# case it refuses to absorb.
def newest_binary(build_dir):
    paths = [
        os.path.join(build_dir, 'contrib/plugins/libchampsim_tracer.so'),
        os.path.join(build_dir, 'contrib/plugins/cst_decode'),
    ]
    # WHICH `qemu-*` FILES ARE EMULATORS IS ASKED OF THE BUILD, NOT OF A LIST.
    # `qemu-img`, `qemu-nbd` and `qemu-bridge-helper` all match any name
    # pattern one would write, and a hand-maintained exclusion list would go
    # stale silently.  Meson emits one `<target>_tls_guard.ok` stamp per
    # EMULATOR and for nothing else -- 62 of them in this build against 208
    # `qemu-*` entries -- so the stamp is the discriminator.
    for name in sorted(os.listdir(build_dir)):
        if not name.endswith('_tls_guard.ok'):
            continue
        emu = os.path.join(build_dir, name[:-len('_tls_guard.ok')])
        if os.path.isfile(emu) and os.access(emu, os.X_OK):
            paths.append(emu)
    return behavior_digest.behaviour_reference(build_dir, paths)


def score_one(row, root, binary_mtime):
    """-> (ok, headline, scored, why)"""
    path = os.path.join(root, row.report)
    if not os.path.exists(path):
        return (False, None, None,
                'REPORT MISSING: %s.  A leg that did not run has not passed.'
                % path)
    if binary_mtime and os.path.getmtime(path) < binary_mtime:
        return (False, None, None,
                'STALE REPORT: %s is older than the tracer binaries it is '
                'supposed to have measured.  A green taken against a previous '
                'build is not a green.' % path)
    text = open(path, errors='replace').read()

    pat, kind = HEADLINE[row.leg]
    if kind == 'coverage':
        # "x86_64    47  (subset 37 + unaccounted 10 + hole 0)"
        hm = re.search(r'^%s\s+(\d+)\s+\(subset (\d+) \+ unaccounted (\d+) '
                       r'\+ hole (\d+)\)' % re.escape(row.isa), text, re.M)
        if not hm:
            return (False, None, None,
                    'HEADLINE NOT FOUND for %s in %s.  The four-ISA '
                    'cross-tabulation did not name this ISA; a leg the report '
                    'does not mention has not passed.' % (row.isa, path))
        headline = int(hm.group(1))
        dm = re.search(r'^%s\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+'
                       r'\d+\s+\d+\s*$' % re.escape(row.isa), text, re.M)
        if not dm:
            return (False, headline, None,
                    'PROBED POPULATION NOT FOUND for %s in %s -- a headline '
                    'with no denominator cannot be believed.'
                    % (row.isa, path))
        scored = int(dm.group(1))
        if int(hm.group(4)) != 0:
            return (False, headline, scored,
                    'REACHABLE-UNPROBED HOLE = %s.  An opcode a QEMU guest '
                    'runs and the tracer never decoded drops the WHOLE '
                    'instruction; it is never folded into a rate.'
                    % hm.group(4))
    elif kind in ('depmap', 'depmapprec'):
        # An INERT axis is checked FIRST and on BOTH rows.  An axis that
        # compared nothing contributes 0 to the loss count and 0 to the
        # precision count, so either number would read like a pass for the
        # one reason that is never a pass -- the probe stopped reaching that
        # family.  The per-axis floor cannot catch it either, because the
        # floor is the SUM over axes.
        im = re.search(r'^INERT AXES = (\d+)', text, re.M)
        if not im:
            return (False, None, None,
                    'INERT-AXIS LINE NOT FOUND in %s.  The report changed '
                    'shape; that is a failure, not a zero.' % path)
        want = (r'^THE NUMBER THAT MATTERS: MISSING-EDGE \+ BOTH = (\d+)'
                if kind == 'depmap' else
                r'^PRECISION-DISCARDED \(STRICTLY-SMALLER\) = (\d+)')
        hm = re.search(want, text, re.M)
        if not hm:
            return (False, None, None,
                    'HEADLINE NOT FOUND in %s.  The report changed shape or '
                    'the leg died before writing it; either way this is a '
                    'failure, not a zero.' % path)
        headline = int(hm.group(1))
        fm = FLOOR[row.leg].search(text)
        if not fm:
            return (False, headline, None,
                    'SCORED POPULATION NOT FOUND in %s -- a headline with no '
                    'denominator cannot be believed.' % path)
        scored = int(fm.group(1))
        if int(im.group(1)) != 0:
            return (False, headline, scored,
                    'INERT AXES = %s.  An axis that compared nothing reports '
                    'no disagreement for the wrong reason; it is a demand for '
                    'a better probe, never a pass.' % im.group(1))
    elif kind == 'isaxdead':
        arms = pat.findall(text)
        if not arms:
            return (False, None, None,
                    'NO ARM SUMMARY LINES PARSED out of %s.  The dead-rule '
                    'fact lives on isaxcheck\'s own `# isa=` line; a report '
                    'without one cannot answer this question and must not '
                    'read as a zero.' % path)
        headline = sum(int(n) for n in arms)
        scored = len(arms)
        if headline:
            dead = [n for n in arms if n != '0']
            return (False, headline, scored,
                    'DEAD ALLOWLIST RULE(S): %d across %d arm(s) (%s).  A '
                    'rule that excuses no signature has outlived the '
                    'disagreement it was written for; the arm names it on a '
                    'DEAD line.  Retire it in the allowlist with the reason '
                    'written next to it.' % (headline, len(dead),
                                             ', '.join(dead)))
    elif kind == 'isax':
        arms = pat.findall(text)
        if not arms:
            return (False, None, None,
                    'NO ARMS PARSED out of %s' % path)
        headline = sum(1 for _isa, rc in arms if rc != '0')
        scored = len(arms)
        bad = [i for i, rc in arms if rc != '0']
        if bad:
            return (False, headline, scored,
                    'ARMS THAT DID NOT EXIT 0: %s' % ', '.join(bad))
    else:
        m = pat.search(text)
        if not m:
            return (False, None, None,
                    "HEADLINE NOT FOUND in %s.  The report changed shape or the "
                    "leg died before writing it; either way this is a failure, "
                    "not a zero." % path)
        headline = int(m.group(1))
        fm = FLOOR[row.leg].search(text)
        if not fm:
            return (False, headline, None,
                    'SCORED POPULATION NOT FOUND in %s -- a headline with no '
                    'denominator cannot be believed.' % path)
        scored = int(next(g for g in fm.groups() if g))

    if scored < row.floor:
        return (False, headline, scored,
                'VACUOUS: scored %d, floor %d.  A leg that compared almost '
                'nothing reports few disagreements for the wrong reason.'
                % (scored, row.floor))
    if headline > row.ceiling:
        return (False, headline, scored,
                'UNADJUDICATED DISAGREEMENT: %d > adjudicated %d.  Every row '
                'above the ceiling needs a per-row adjudication before this '
                'gate can go green again.' % (headline, row.ceiling))
    return (True, headline, scored, '')


def main():
    ap = argparse.ArgumentParser(
        description='score the R13 external-truth legs against their '
                    'adjudicated ceilings')
    ap.add_argument('root', help='evidence root holding the leg reports')
    ap.add_argument('--manifest', default=MANIFEST)
    ap.add_argument('--build-dir', default=None,
                    help='build directory whose tracer binaries the reports '
                         'must be newer than (staleness guard)')
    ap.add_argument('--only', default=None,
                    help='comma-separated leg names to score (the rest are '
                         'reported as NOT RUN and FAIL the gate)')
    a = ap.parse_args()

    rows = read_manifest(a.manifest)
    only = set(a.only.split(',')) if a.only else None

    binary_mtime = 0.0
    ref_rows = []
    if a.build_dir:
        binary_mtime, ref_path, ref_rows = newest_binary(a.build_dir)
        if not binary_mtime:
            sys.exit('BUILD DIRECTORY HAS NO TRACER BINARIES: %s.  The '
                     'staleness guard cannot run, so it may not be skipped.'
                     % a.build_dir)

    print('R13 EXTERNAL-TRUTH GATE')
    print('evidence root : %s' % a.root)
    print('manifest      : %s' % a.manifest)
    if a.build_dir:
        print('staleness ref : %s' % a.build_dir)
        print('  behaviour of  : %s' % ref_path)
        print('  last changed  : %s'
              % time.strftime('%Y-%m-%d %H:%M:%S',
                              time.localtime(binary_mtime)))
        moved = [r for r in ref_rows if r[4] != 'cached']
        recomputed = len(moved)
        changed = [r for r in moved if r[4].startswith('behaviour CHANGED')]
        unreadable = [r for r in ref_rows if r[3] is None]
        print('  %d binaries, %d re-digested, %d changed behaviour, '
              '%d unreadable' % (len(ref_rows), recomputed, len(changed),
                                 len(unreadable)))
        for r in changed + unreadable:
            print('    %-58s %s' % (os.path.basename(r[0]), r[4]))
    else:
        print('staleness ref : NOT CHECKED (no --build-dir)')
    print('')
    print('%-10s %-8s %9s %9s %9s  %s'
          % ('leg', 'isa', 'headline', 'ceiling', 'scored', 'verdict'))
    print('-' * 80)

    failures = []
    for r in rows:
        if only is not None and r.leg not in only:
            print('%-10s %-8s %9s %9d %9s  NOT RUN -- fails the gate'
                  % (r.leg, r.isa, '-', r.ceiling, '-'))
            failures.append((r, 'NOT RUN: this leg was excluded by --only.  '
                                'The flow is a gate, so a leg that did not run '
                                'is a failure, not a skip.'))
            continue
        ok, headline, scored, why = score_one(r, a.root, binary_mtime)
        print('%-10s %-8s %9s %9d %9s  %s'
              % (r.leg, r.isa,
                 '-' if headline is None else headline, r.ceiling,
                 '-' if scored is None else scored,
                 'ok' if ok else 'FAIL'))
        if not ok:
            failures.append((r, why))

    print('')
    if failures:
        print('GATE FAILED -- %d of %d legs' % (len(failures), len(rows)))
        for r, why in failures:
            print('')
            print('  %s/%s  (%s)' % (r.leg, r.isa, r.report))
            print('    %s' % why)
            print('    adjudication on file: %s' % r.adjudication)
            if r.retired_by != '-':
                print('    the ceiling retires with: %s' % r.retired_by)
        return 1
    print('GATE PASSED -- %d legs, every headline at or under its adjudicated '
          'ceiling' % len(rows))
    return 0


if __name__ == '__main__':
    sys.exit(main())
