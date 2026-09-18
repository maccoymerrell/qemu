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
    # ------------------------------------------------------------------
    # THE OFFLINE REFERENCE LEGS.  These five replace the four `static`
    # rows and the four `isax*` rows, which drove `isaxcheck` -- a binary
    # that linked Capstone into the build and was deleted with it.  The
    # FUNCTION those rows served is unchanged and is served here: external
    # static-decode agreement per ISA (`refopc`), the register-name set
    # comparison (`refsrc`), the dead-arbitration tripwire on both
    # (`refopcdead`, `refsrcdead`), and the producer's own arms
    # (`refstage`).  What changed is where the reference runs: OFFLINE,
    # over recorded encodings, never in the traced process.  Each row's
    # manifest entry states what the row it succeeds measured, what this
    # one measures, and where its ceiling came from.
    # ------------------------------------------------------------------
    'refopc':     (None, 'refopc'),
    'refopcdead': (None, 'refopcdead'),
    'refsrc':     (None, 'refsrc'),
    'refsrcdead': (None, 'refsrcdead'),
    'refstage':   (re.compile(r'^stage\s+(\S+)\s+rc=(\d+)', re.M), 'refstage'),
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
    # The five offline reference legs carry their populations INSIDE the
    # report blocks -- encodings joined, keys joined, rulings disposed of,
    # stages run -- so each is read by its own branch in score_one() rather
    # than by one regex here.  They are named anyway, so that a leg with no
    # entry in this table is still a KeyError rather than a silent skip.
    'refopc':     None,
    'refopcdead': None,
    'refsrc':     None,
    'refsrcdead': None,
    'refstage':   None,
    'gem5cp':  re.compile(r'^TOTAL\s+(\d+)', re.M),
    'spikecp': re.compile(r'^\s*aligned\s+(\d+)', re.M),
    'gem5wp':  re.compile(r'^TOTAL\s+(\d+)', re.M),
    'spikewp': re.compile(r'^TOTAL\s+(\d+)', re.M),
    'pin':     re.compile(r'lockstep walk:\s*(\d+) byte-identical pairs'),
    # the number of dependency FACTS compared, summed over the four axes
    'depmap':     re.compile(r'^TOTAL FACTS = (\d+)', re.M),
    'depmapprec': re.compile(r'^TOTAL FACTS = (\d+)', re.M),
}

# THE CONTRACT-SKIP ACCOUNTING IS RETIRED WITH ITS SUBJECT -- FINDING 99-A.
#
# `accounted()` and the `roll-up: ... fields_layer_skipped=` rule lived here
# because `isax_srcenc_gate.sh` ran two LAYERS per ISA and a bare arm skipped
# the fields layer by contract, so a floor of 8 had to count arms ACCOUNTED
# FOR rather than arms scored.  That gate drove `isaxcheck`, which linked
# Capstone into the build and was deleted with it; there are no layers, no arm
# shapes and no roll-up line at this tip, and the four rows that read them are
# re-pointed at the offline referee.
#
# The rule is DELETED rather than left in place, because a check that cannot
# find its subject must fail and a check whose subject cannot exist is worse:
# it can never fire, never be seen to fire, and reads as coverage to anyone
# counting rules.  What the rule stood for -- a population short of its floor
# is a refusal unless the report itself accounts for the shortfall -- is not
# lost: every branch below refuses on a missing block, a truncated detail
# list, or a population under the manifest's floor, and says which.


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


# ---------------------------------------------------------------------------
# THE OFFLINE REFERENCE REPORTS.
#
# Both are written by the same producer and both are per-ISA blocks under a
# `== <isa>` header, so the parsing is one helper with four readings.  The one
# rule that runs before any of them: FOUR blocks or the report is refused.  A
# report carrying three ISAs would give every row it does carry a perfectly
# good number while one ISA silently stopped being compared, and a summed row
# (`refsrc`, `refopcdead`, `refsrcdead`) would read LOWER for it -- the exact
# shape of a green that means the probe stopped reaching.
#
# The second rule is about the DETAIL lists.  Both tools print their UNRULED
# classes at a `--top` limit, and the summed headline is read off those
# printed lines; if the list were truncated the headline would under-count in
# the safe-looking direction.  So the count on the roll-up line is compared
# against the number of lines actually printed, and a shortfall is a refusal
# naming the flag to raise -- never a smaller number.
# ---------------------------------------------------------------------------
ISAS = ('x86_64', 'aarch64', 'riscv64', 'mipsel')

GAP_HEAD = re.compile(r'^== (\S+)\s+(\d+) encodings, (\d+) also in the '
                      r'Capstone corpus\s*$', re.M)
GAP_ARB = re.compile(r'^\s+-- arbitration: (\d+) classes, (\d+) encodings '
                     r'arbitrated \((\d+) on a coverage path\), (\d+) '
                     r'classes UNRULED\s*$', re.M)
GAP_UNRULED = re.compile(r'^\s+UNRULED\s+(\d+)\s+rule ', re.M)
GAP_BUCKET = re.compile(r'^\s+(\S+)\s+(\d+)\s+[\d.]+%\s*$', re.M)
GAP_DEAD = re.compile(r'^gapreport: rulings: (\d+) RESERVED, (\d+) DEAD\s*$',
                      re.M)

SET_HEAD = re.compile(r'^== (\S+)\s+(\d+) \(encoding, direction\) keys in '
                      r'BOTH sides\s*$', re.M)
SET_ARB = re.compile(r'^\s+-- arbitration: (\d+) classes live, .*?; (\d+) '
                     r'UNRULED, (\d+) RESERVED, (\d+) DEAD\s*$', re.M)
SET_UNRULED = re.compile(r'^\s+UNRULED\s+(\d+)\s+\S+ \S+\s*$', re.M)


def isa_blocks(text, head):
    """-> {isa: block text}, in the order the report wrote them."""
    out, marks = {}, list(head.finditer(text))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        out[m.group(1)] = (m, text[m.start():end])
    return out


def score_reference(row, kind, text, path):
    """-> (ok, headline, scored, why) for the four offline-referee legs."""
    head = GAP_HEAD if kind in ('refopc', 'refopcdead') else SET_HEAD
    blocks = isa_blocks(text, head)
    missing = [i for i in ISAS if i not in blocks]
    if missing:
        return (False, None, None,
                'THE REPORT DOES NOT CARRY ALL FOUR ISAs: %s absent from %s.  '
                'An ISA that stopped being compared contributes nothing to a '
                'summed headline and reads as an improvement; the report is '
                'refused rather than scored on what is left.'
                % (', '.join(missing), path))

    def arbitration(isa, pat, what):
        m = pat.search(blocks[isa][1])
        if not m:
            return None, ('ARBITRATION LINE NOT FOUND for %s in %s.  %s prints '
                          'it on every run; without it this row has no '
                          'subject.' % (isa, path, what))
        return m, None

    def unruled_rows(isa, arb_m, line_pat, idx):
        """Sum the printed UNRULED detail lines, refusing a truncated list."""
        want = int(arb_m.group(idx))
        lines = line_pat.findall(blocks[isa][1])
        if len(lines) != want:
            return None, ('UNRULED LIST TRUNCATED for %s in %s: the roll-up '
                          'says %d class(es) and %d detail line(s) were '
                          'printed.  The headline is summed off those lines, '
                          'so a truncated list under-counts in the direction '
                          'that looks like a pass.  Re-run the producer with a '
                          'larger --top.' % (isa, path, want, len(lines)))
        return sum(int(n) for n in lines), None

    if kind == 'refopc':
        m, blk = blocks[row.isa]
        scored = int(m.group(3))            # encodings joined with the reference
        buckets = dict((b, int(n)) for b, n in GAP_BUCKET.findall(blk))
        if 'UNKNOWN-WORD' not in buckets:
            return (False, None, scored,
                    'BUCKET LINES NOT FOUND for %s in %s.  The report changed '
                    'shape; that is a failure, not a zero.' % (row.isa, path))
        arb, why = arbitration(row.isa, GAP_ARB, 'gapreport')
        if why:
            return (False, None, scored, why)
        unruled, why = unruled_rows(row.isa, arb, GAP_UNRULED, 4)
        if why:
            return (False, None, scored, why)
        headline = unruled + int(arb.group(3))
        if buckets['UNKNOWN-WORD']:
            return (False, headline, scored,
                    'UNKNOWN-WORD = %d.  QEMU stated a generic word this '
                    'referee cannot read, which is a mismatched pair of '
                    'binaries and not a decode disagreement: the reading is '
                    'invalid, not merely bad.' % buckets['UNKNOWN-WORD'])
    elif kind == 'refopcdead':
        dm = GAP_DEAD.search(text)
        if not dm:
            return (False, None, None,
                    'RULING-DISPOSITION LINE NOT FOUND in %s.  gapreport '
                    'prints `rulings: N RESERVED, M DEAD` whenever it joins '
                    'the arbitration corpus; without it nothing here has been '
                    'asked the dead-rule question.' % path)
        headline = int(dm.group(2))
        scored = int(dm.group(1)) + headline
        for isa in ISAS:
            arb, why = arbitration(isa, GAP_ARB, 'gapreport')
            if why:
                return (False, headline, None, why)
            scored += int(arb.group(1)) - int(arb.group(4))
        if headline:
            return (False, headline, scored,
                    'DEAD ARBITRATION(S): %d.  A written arbitration naming a '
                    'decode rule this build no longer has excuses nothing and '
                    'has outlived the disagreement it was written for; '
                    'gapreport names each on its own DEAD line.  Retire it '
                    'with the reason written next to it.' % headline)
    else:                                    # refsrc / refsrcdead
        headline = scored = 0
        for isa in ISAS:
            arb, why = arbitration(isa, SET_ARB, 'setjoin')
            if why:
                return (False, None, None, why)
            if kind == 'refsrc':
                n, why = unruled_rows(isa, arb, SET_UNRULED, 2)
                if why:
                    return (False, None, None, why)
                headline += n
                scored += int(blocks[isa][0].group(2))
            else:
                headline += int(arb.group(4))
                scored += (int(arb.group(1)) + int(arb.group(3))
                           + int(arb.group(4)))
        if kind == 'refsrcdead' and headline:
            return (False, headline, scored,
                    'DEAD ARBITRATION(S): %d.  A written arbitration naming a '
                    'register name this build cannot spell at all excuses '
                    'nothing; setjoin names each on its own DEAD line.  Retire '
                    'it with the reason written next to it.' % headline)
    return (True, headline, scored, '')


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
    if kind in ('refopc', 'refopcdead', 'refsrc', 'refsrcdead'):
        ok, headline, scored, why = score_reference(row, kind, text, path)
        if not ok:
            return (False, headline, scored, why)
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
    elif kind == 'refstage':
        stages = pat.findall(text)
        if not stages:
            return (False, None, None,
                    'NO STAGE LINES PARSED out of %s.  The producer writes one '
                    '`stage <name> rc=<n>` line per arm it ran; a report '
                    'without one says the producer did not run, and that is a '
                    'failure rather than a zero.' % path)
        headline = sum(1 for _name, rc in stages if rc != '0')
        scored = len(stages)
        bad = ['%s rc=%s' % (n, rc) for n, rc in stages if rc != '0']
        if bad:
            return (False, headline, scored,
                    'STAGES THAT DID NOT EXIT 0: %s.  The referee\'s own arms '
                    'are scored here and nowhere else; a stage that died did '
                    'not measure what the rows reading its report claim.'
                    % ', '.join(bad))
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
