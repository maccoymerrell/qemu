#!/usr/bin/env python3
"""
ARC 3 -- the four-ISA coverage report, with every disagreement classified.

Reads the four per-ISA attribution tables, which each carry the two-axis
classification their own harness computed (arc3_taxonomy), and prints the
cross-tabulation for all four together.  Nothing is re-derived here: the
columns are the harnesses' own, so this report and the per-ISA reports cannot
disagree.

The headline is NOT the agreement rate.  It is

    TRACER-SUBSET + UNACCOUNTED + REACHABLE-UNPROBED

the rows where the reference records something the tracer drops, plus the rows
where nobody has yet said why the two differ, plus the rows a QEMU guest can
execute and no comparison was ever made for.  A bare disagreement count is
compatible with both the project's goal (we record MORE) and its one
disqualifying failure (we record LESS), so it is not reported without the
direction beside it.

The third term used to sit outside the headline as a total.  It cannot: an
opcode the tracer fails to decode drops EVERYTHING for that instruction, so it
is the most severe form of the defect rather than a footnote to it.  It is
also where a frozen number hid a moving one -- the x86_64 unprobed total read
2713 in three consecutive reports while its composition moved 2479/234 to
2363/349 reachable -- so the out-of-scope and reachable components are always
printed side by side and never summed away.

Usage:
    python coverage_report.py [--cov DIR] [--top N]

Author: Maccoy Merrell.
"""
import os
import sys
import csv
import argparse
import time
import collections

_D = os.path.dirname(os.path.abspath(__file__))
if _D not in sys.path:
    sys.path.insert(0, _D)
import arc3_taxonomy as tax                                   # noqa: E402

DEFAULT_COV = '/mnt/md0/QEMU/cst_runs/_arc3_cov'

# Per ISA: the table, and the column names it uses for the fields this report
# needs.  The four harnesses were written independently and spell their columns
# differently; that is the only thing this map records.
ISAS = [
    # isa,       path,                  verdict col, disagree token, mnemonic
    ('x86_64',  'x86_64/attrib.tsv',   'verdict', 'DISAGREE',  'mnemonic',
     'mechanism'),
    ('aarch64', 'aarch64/attrib.tsv',  'verdict', 'disagree',  'mnemonic',
     'signature'),
    ('riscv64', 'riscv64/attrib.tsv',  'verdict', 'DISAGREE',  'mnemonic',
     'adjudication'),
    ('mipsel',  'mipsel/attrib.tsv',   'verdict', 'DISAGREE',  'mnemonic',
     'adjudication_rules'),
]

#: the execution reference each ISA has, or the absence of one.  A static-only
#: result must never be quoted as if execution had validated it.
EXEC_REFERENCE = {
    'x86_64':  'PIN (execution).  INS_RegR is EXPLICIT-OPERAND ONLY, so PIN\'s '
               'silence proves nothing; only its positive evidence counts.',
    'riscv64': 'Spike (execution), patched to state reads, load data and '
               'load width.  Correct path: riscv64/spike/compare_exec.py.  '
               'WRONG path: riscv64/spike/wp/compare_wp.py -- the only WP '
               'execution reference on any ISA.',
    'aarch64': 'gem5 25.1.0.1 (execution), syscall-emulation, AtomicSimpleCPU, '
               'patched to state every destination value, the bytes a store '
               'moved, the access width and the access direction.  '
               'gem5/compare_exec_gem5.py.  It is a PROBE-SIZED reference '
               '(244 aligned instructions), not a coverage result.',
    'mipsel':  'gem5 25.1.0.1 (execution), same harness and same patch, 147 '
               'aligned instructions.  PROBE-SIZED, not a coverage result.',
}

#: Where a per-ISA harness has MEASURED reachability per encoding and written
#: the evidence onto the row, the three-valued verdict is taken from that file
#: rather than re-derived here.  UNREACHABLE is the one verdict this report
#: must never compute for itself: it is a claim about what a QEMU guest can
#: execute, and the only honest source for it is the run that tried.
REACH_MATRIX = {
    'x86_64': 'x86_64/reach_matrix.tsv',
}


def read(path, verdict_col, disagree, mnem_col, label_col):
    """-> (rows, counts, unprobed_split)

    unprobed_split is {'no': n, 'yes': n}: an opcode with no comparison drops
    EVERYTHING for its instruction, so whether a QEMU guest can execute it is
    the difference between an out-of-scope row and the worst coverage hole in
    the arc.  The two are never summed into one number here.
    """
    with open(path, newline='') as f:
        first = f.readline()
        f.seek(0)
        # two of the four tables comment their header line
        txt = f.read()
    if txt.startswith('#'):
        txt = txt[1:]
    rd = csv.DictReader(txt.splitlines(), delimiter='\t')
    rows, counts = [], collections.Counter()
    unpro = collections.Counter()
    for r in rd:
        counts[r[verdict_col]] += 1
        if r[verdict_col].upper() == 'UNPROBED':
            if 'qemu_tcg_reachable' not in r:
                sys.exit('%s has UNPROBED rows and no qemu_tcg_reachable '
                         'column: an unprobed opcode without a reachability '
                         'verdict cannot be told apart from a coverage hole, '
                         'and this report will not average over the '
                         'difference' % path)
            # THE LAYOUT EXCLUSION IS ITS OWN BUCKET (exec179, 179-C).  HOLE
            # means "an opcode a QEMU guest runs and THE TRACER never decoded",
            # and an encoding the SLED removed from its own population because
            # the slot padding decodes as it was never put to the tracer at
            # all.  Both are UNCOVERED and both are counted; they are not the
            # same finding, and the headline says which is which.  Folding
            # them made the x86_64 leg fail on `ret`, whose 3,502 classified
            # occurrences sit in any real trace.
            if r.get('mechanism') == 'sled-terminator-collision':
                unpro['layout'] += 1
            else:
                unpro[r['qemu_tcg_reachable']] += 1
        if r[verdict_col] != disagree:
            continue
        if 'direction' not in r:
            sys.exit('%s has no direction column: re-run its comparator '
                     '(the taxonomy is computed there, not here)' % path)
        rows.append(tax.Row(
            r.get('opcode_id', '?'), r.get(mnem_col, '?'),
            r.get(label_col, ''), r.get('set_relation', ''),
            r['direction'], r['category'], r['accounted'] == '1', None))
    return rows, counts, unpro


BUILD_DIR = os.environ.get('CST_BUILD', '/mnt/md0/QEMU/qemu/build')

#: The offline reference.  Everything that used to run inside the traced
#: process now runs here, over encodings a capture build recorded, so the
#: file that decides the reference side of every attribution is a Python
#: source and not a binary.  It is a freshness subject for exactly that
#: reason: a change to it changes what "disagree" means.
REFEREE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(
    __file__))), 'cst_referee.py')

#: The tracer side: every binary whose behaviour a coverage table describes.
#:
#: THE PLUGIN AND THE OFFLINE DECODER are the obvious two -- the plugin
#: publishes the wire and cst_decode reads it back.
#:
#: THE FOUR EMULATORS ARE SUBJECTS TOO, and leaving them out was FINDING
#: 247-C.  Since the tracer arm moved into the emulator there is no longer a
#: host-side decoder to hold the register lists: srcenc_fields reads them out
#: of a capture that `qemu-<isa>` produced, because the wire's src_regs[] and
#: dst_regs[] ARE QEMU's own ordered statements, made at translation time by
#: target/<arch> code that only the emulator contains (sled_fields.py's
#: header says this, and srcenc_sled.py launches `build/qemu-<isa>` by name).
#: So a commit that changes ONLY a target's statements -- exactly the shape
#: of every wire change in this arc -- moves what the tables measure while
#: leaving the plugin and cst_decode byte-identical, and with only those two
#: as subjects the freshness reference would not advance and a table written
#: before the change would publish as current.  That is the same false-green
#: this guard exists to prevent, one layer down.
#:
#: WHY ALL FOUR RATHER THAN THE ONE AN ISA'S LEG USES: the reference is a
#: single time over all subjects and the report publishes an ALL-FOUR
#: aggregate, so a per-ISA reference would let an aggregate mix a fresh leg
#: with one whose emulator moved.  Holding every leg to the newest of the
#: four is the conservative direction -- it can cost a re-run, never a lie.
#:
#: The version string is masked by behavior_digest (that is what #292 built
#: it for), so a relink that changes only `qemu-version.h` leaves all four
#: digests unchanged and the reference does not advance.  Without that
#: masking this list could not exist: every commit relinks every emulator.
TRACER_BINARIES = (
    'contrib/plugins/libchampsim_tracer.so',
    'contrib/plugins/cst_decode',
    'qemu-x86_64',
    'qemu-aarch64',
    'qemu-riscv64',
    'qemu-mipsel',
)


def freshness_reference(build_dir):
    """-> (time, what, rows) -- the newest time a SUBJECT's behaviour moved.

    THE SUBJECTS ARE THE THING MEASURED AND THE INSTRUMENT THAT MEASURED IT.
    A table is stale if the tracer changed after it was written (it describes
    a binary that no longer exists) or if the offline referee changed after it
    was written (it was scored against a reference that no longer exists).
    Nothing else qualifies: the capture corpora are INPUTS a leg consumed, and
    a corpus regenerated afterwards does not invalidate a table built from the
    one it had.

    THE TRACER SIDE IS HELD AT A BEHAVIOUR TIME, NOT A LINK TIME.  QEMU
    regenerates `qemu-version.h` from `git describe`, so every commit relinks
    every binary and moves every mtime; a link-time reference would report
    every table stale after a comment-only commit.  behavior_digest.py hashes
    only the bytes that can change behaviour and remembers when each digest
    FIRST appeared, which is what #292 built for the R13 gate and what this
    now shares with it.  The referee is a Python source with no such
    structure, so it is held at its plain mtime.
    """
    sys.path.insert(0, os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'external_truth_gate'))
    import behavior_digest                                   # noqa: E402

    missing = [p for p in
               [os.path.join(build_dir, b) for b in TRACER_BINARIES]
               if not os.path.exists(p)]
    if not os.path.exists(REFEREE):
        missing.append(REFEREE)
    if missing:
        sys.exit('CANNOT CHECK FRESHNESS: no subject at %s.  This report '
                 'scores tables it did not build; without the tracer it '
                 'measures and the referee that measured it, it cannot tell '
                 'a current table from a stale one, and a check that cannot '
                 'find its subject must fail.  Build them, or point --build-'
                 'dir / CST_BUILD at a build that has them.'
                 % ', '.join(missing))

    since, which, rows = behavior_digest.behaviour_reference(
        build_dir, [os.path.join(build_dir, b) for b in TRACER_BINARIES])
    out = [(p, mt, sn, 'behaviour: ' + note) for p, mt, sn, _d, note in rows]
    rt = os.path.getmtime(REFEREE)
    out.append((REFEREE, rt, rt, 'offline referee (mtime: a source file has '
                                 'no behaviour digest)'))
    if rt > since:
        since, which = rt, REFEREE
    return since, which, out


def refuse_if_stale(cov, allow_stale=False, build_dir=None, out=None):
    """Refuse to publish a headline computed before the tracer it scores.

    THE FAILURE THIS EXISTS FOR: `12149 COVERED / 2698 UNREACHABLE / 0
    UNCOVERED` was published and relayed to the maintainer, and at the tip it
    read `12034 / 2698 / 115`.  The table was built four hours before the two
    commits it claimed to measure, the gate was green throughout --
    correctly, it reads a different thing -- and nothing anywhere noticed.
    This report cannot re-derive four heterogeneous legs in process (aarch64
    walks the Arm MRA, riscv64 the Sail model, x86_64 four reachability legs
    under qemu-system), so it does the other half of the maintainer's ruling:
    it REFUSES, by name, when a per-ISA table is older than the apparatus
    whose behaviour it describes.

    WHAT THE SUBJECT IS NOW.  It was `build/contrib/plugins/isaxcheck`, a
    binary that linked Capstone into the build and was deleted with it; this
    report then refused on every run for a reason about the apparatus and not
    about a single table, and the four percentages could not be re-derived at
    any tip after that deletion.  Under the standing external-comparison
    ruling the reference runs OFFLINE, so the subject follows it: the tracer
    binaries the tables describe, and `tools/cst_referee.py`, the referee that
    scored them.  See freshness_reference().

    The per-ISA harnesses hold the stronger check -- x86_64 and aarch64 each
    re-probe and compare byte-for-byte, riscv64 and mipsel re-probe as part of
    their run -- so a green result here means every leg was re-run AND their
    tables post-date the apparatus.

    THIS IS THE LAST LINE, NOT THE FIRST.  Refusing here is correct and it is
    also expensive: by the time this runs, four heterogeneous legs have taken
    hours, and a rebuild anywhere in that window is discovered only once all
    of them have been paid for.  Each REPRODUCE.sh therefore arms
    ../settle_guard.sh before any of its own work -- it refuses to START on a
    tree with pending build work, and hashes the subjects so a rebuild DURING
    a leg is named by the leg it invalidated.  A run that came through those
    guards cannot reach this one with a stale table; a run that did not is
    exactly what this is still here to catch.
    """
    bt, which, rows = freshness_reference(build_dir or BUILD_DIR)
    if out is not None:
        fmt = '%Y-%m-%d %H:%M:%S'
        out.append('FRESHNESS REFERENCE: %s' % which)
        for p, mt, sn, note in rows:
            out.append('  %-58s mtime %s  since %s  %s'
                       % (os.path.basename(p),
                          time.strftime(fmt, time.localtime(mt)),
                          time.strftime(fmt, time.localtime(sn)), note))
        out.append('')
    stale = []
    for isa, rel, _v, _d, _m, _l in ISAS:
        q = os.path.join(cov, rel)
        if os.path.exists(q) and os.path.getmtime(q) < bt:
            stale.append((isa, q, os.path.getmtime(q)))
    if not stale:
        return
    fmt = '%Y-%m-%d %H:%M:%S'
    for isa, q, mt in stale:
        sys.stderr.write('STALE LEG  %-8s %s\n            table     %s\n'
                         '            apparatus %s (%s)\n'
                         % (isa, q, time.strftime(fmt, time.localtime(mt)),
                            time.strftime(fmt, time.localtime(bt)),
                            os.path.basename(which)))
    if allow_stale:
        sys.stderr.write('--allow-stale given: publishing anyway.  The '
                         'numbers below are NOT a measurement at this tip.\n')
        return {}
    #
    # ONE STALE LEG NAMES ITSELF; IT DOES NOT BLANK THE OTHER THREE -- 99-A's
    # sibling, and the shape verify76 measured: `coverage_report.py` exited
    # here, wrote no `coverage_report.txt`, and all FOUR of the R13 gate's
    # `static/<isa>` rows read REPORT MISSING -- for one x86_64 leg that had
    # exited 1.  Three legs that ran, and whose tables are fresh, were
    # reported as not having run at all.
    #
    # A leg is the unit of freshness, so it is the unit of the refusal.  The
    # blocked ISAs are returned, the report is WRITTEN, each blocked ISA gets
    # a `REFUSED` row carrying its own reason, every ALL-FOUR aggregate
    # refuses rather than totalling over a subset, and the process still
    # exits non-zero.  Nothing is published that was not measured, and
    # nothing measured is thrown away with it.
    return {isa: ('table %s predates the apparatus it describes -- %s at %s'
                  % (time.strftime(fmt, time.localtime(mt)),
                     os.path.basename(which),
                     time.strftime(fmt, time.localtime(bt))))
            for isa, _q, mt in stale}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cov', default=DEFAULT_COV)
    ap.add_argument('--top', type=int, default=50)
    ap.add_argument('-o', default=None, help='also write the report here')
    ap.add_argument('--rows', default=None,
                    help='write EVERY unaccounted row here as a TSV, so the '
                         'top-N above never stands in for the full list')
    ap.add_argument('--allow-stale', action='store_true',
                    help='print the table even when a leg predates the '
                         'apparatus, having said so on stderr first.  For '
                         'inspecting a historical run, never for a verdict')
    ap.add_argument('--build-dir', default=BUILD_DIR,
                    help='the build whose tracer binaries the tables '
                         'describe (default $CST_BUILD or %s)' % BUILD_DIR)
    a = ap.parse_args()

    out = []
    w = out.append
    blocked = refuse_if_stale(a.cov, a.allow_stale,
                              build_dir=a.build_dir, out=out) or {}

    per_isa = {}
    missing = []
    for isa, rel, vcol, dtok, mcol, lcol in ISAS:
        p = os.path.join(a.cov, rel)
        if not os.path.exists(p):
            missing.append((isa, p))
            continue
        try:
            per_isa[isa] = read(p, vcol, dtok, mcol, lcol)
        except SystemExit as e:
            # THE SECOND SOURCE OF THE SAME CASCADE.  `read()` refuses a table
            # it cannot interpret -- a riscv64 table with UNPROBED rows and no
            # `qemu_tcg_reachable` column is the live one -- and that refusal
            # is correct and is ALSO about one leg.  Exiting here silenced the
            # other three exactly as the staleness refusal did.  Same unit,
            # same treatment: the leg is blocked, by its own message.
            missing.append((isa, '%s: %s' % (p, e)))

    # A report that cannot find a leg's subject must fail FOR THAT LEG, not
    # quietly average over what it did find -- and not silence the legs that
    # did run.  Same unit as the staleness refusal above.
    for isa, p in missing:
        sys.stderr.write('MISSING %s: %s\n' % (isa, p))
        blocked[isa] = ('unusable table: %s' % p) if ': ' in p else \
                       ('no table at %s -- the leg did not run, or exited '
                        'before writing one' % p)
    if len(blocked) == len(ISAS):
        sys.exit('all %d legs are blocked; there is nothing to report'
                 % len(ISAS))
    #: The line a blocked ISA gets wherever a number would go.  The R13
    #: gate's `coverage` scorer matches it and reports THIS leg's reason.
    def refused_row(isa):
        return '%-9s REFUSED  %s' % (isa, blocked[isa])
    #: An aggregate over a subset is a number about a different population,
    #: so there is no honest total while any leg is blocked.
    def refused_total(what):
        return ('%-9s REFUSED  %d of %d legs blocked (%s); a total over the '
                'rest would be a number about a different population'
                % (what, len(blocked), len(ISAS), ', '.join(sorted(blocked))))

    w('=' * 78)
    w('ARC 3 -- REGISTER ATTRIBUTION COVERAGE, ALL FOUR ISAs')
    w('=' * 78)
    w('')
    w('A disagreement count on its own is not a result.  Every disagreeing row')
    w('carries a DIRECTION, measured from the sets themselves, and a CATEGORY,')
    w('the mechanism.  The headline is the rows where we drop information or do')
    w('not know why we differ -- not the agreement rate.')
    w('')
    for d in tax.DIRECTIONS:
        w('  %-16s %s' % (d, tax.DIRECTION_VERDICT[d]))
    w('  %-16s an opcode a QEMU guest runs and the tracer never decoded: '
      'the whole instruction is missing' % 'REACHABLE-UNPROBED')
    w('')

    # ------------------------------------------------------------- headline
    w('THE NUMBER THAT MATTERS: TRACER-SUBSET + UNACCOUNTED +')
    w('REACHABLE-UNPROBED, per ISA')
    w('')
    hdr = ('%-9s %8s %9s %9s %11s %9s %11s %13s %10s'
           % ('ISA', 'probed', 'agree', 'disagree', 'SUPERSET', 'SUBSET',
              'ORTHOGONAL', 'UNACCOUNTED', 'HOLE'))
    w(hdr)
    w('-' * len(hdr))
    grand = collections.Counter()
    gcounts = collections.Counter()
    for isa, _, vcol, dtok, _, _ in ISAS:
        if isa in blocked:
            w(refused_row(isa)); continue
        rows, counts, _unp = per_isa[isa]
        c = collections.Counter(r.direction for r in rows)
        agree = counts.get('AGREE', 0) + counts.get('agree', 0)
        unpro = counts.get('UNPROBED', 0) + counts.get('unprobed', 0)
        probed = agree + len(rows)
        gcounts['hole'] += _unp['yes']
        gcounts['outofscope'] += _unp['no']
        gcounts['layout'] += _unp['layout']
        for k in tax.DIRECTIONS:
            grand[k] += c[k]
        gcounts['agree'] += agree
        gcounts['probed'] += probed
        gcounts['unprobed'] += unpro
        gcounts['disagree'] += len(rows)
        w('%-9s %8d %9d %9d %11d %9d %11d %13d %10d'
          % (isa, probed, agree, len(rows), c[tax.SUPERSET], c[tax.SUBSET],
             c[tax.ORTHOGONAL], c[tax.UNACCOUNTED], _unp['yes']))
    w('-' * len(hdr))
    w(refused_total('all four') if blocked else
      '%-9s %8d %9d %9d %11d %9d %11d %13d %10d'
      % ('all four', gcounts['probed'], gcounts['agree'], gcounts['disagree'],
         grand[tax.SUPERSET], grand[tax.SUBSET], grand[tax.ORTHOGONAL],
         grand[tax.UNACCOUNTED], gcounts['hole']))
    w('')
    w('HOLE = unprobed AND executable by a QEMU guest.  It is in the headline')
    w('because it is the most severe form of the defect, not a footnote: a row')
    w('the tracer cannot decode drops the ENTIRE instruction, every register')
    w('and every memop, where a SUBSET row drops only part of one.')
    w('')
    w('%-9s %s' % ('ISA', 'TRACER-SUBSET + UNACCOUNTED + REACHABLE-UNPROBED'))
    for isa, _, _, _, _, _ in ISAS:
        if isa in blocked:
            w(refused_row(isa)); continue
        rows, _c2, _unp = per_isa[isa]
        c = collections.Counter(r.direction for r in rows)
        w('%-9s %d  (subset %d + unaccounted %d + hole %d)'
          % (isa, c[tax.SUBSET] + c[tax.UNACCOUNTED] + _unp['yes'],
             c[tax.SUBSET], c[tax.UNACCOUNTED], _unp['yes']))
    w(refused_total('all four') if blocked else
      '%-9s %d  (subset %d + unaccounted %d + hole %d)'
      % ('all four',
         grand[tax.SUBSET] + grand[tax.UNACCOUNTED] + gcounts['hole'],
         grand[tax.SUBSET], grand[tax.UNACCOUNTED], gcounts['hole']))
    w('')
    # The unprobed TOTAL is never printed alone.  It sat frozen at 2713 across
    # three x86_64 reports while its composition moved 2479/234 -> 2363/349
    # reachable; a constant hid a 50% growth in the coverage hole.  Both
    # components travel together, always.
    w('UNPROBED, counted here and nowhere else: %d = %d out-of-scope + %d '
      'sled-layout + %d'
      % (gcounts['unprobed'], gcounts['outofscope'], gcounts['layout'],
         gcounts['hole']))
    w('REACHABLE.  An opcode with no comparison has no direction; it is the')
    w('most complete form of dropped information, not a row that agreed.  The')
    w('out-of-scope component is only out of scope where the per-ISA harness')
    w('charged it to a citation from the QEMU tree -- for x86_64 that is')
    w('qemu_tcg_scope.py, which re-asserts every citation on every run and')
    w('refuses when one goes stale.  The REACHABLE component is the hole.')
    w('The sled-layout component is neither: it is an encoding the SLED could')
    w('not put in a slot because the slot PADDING decodes as it')
    w('(srcenc_sled.terminator_collisions()), so the tracer was never asked.')
    w('UNCOVERED, counted, and NOT a tracer decode gap -- 179-C.')
    w('')

    # ------------------------------------------------ the three-valued split
    # There are three verdicts and no fourth.  A row is COVERED (compared and
    # agreeing, or disagreeing only as TRACER-SUPERSET), UNREACHABLE (shown
    # per row that no configuration of QEMU can execute it), or UNCOVERED --
    # a defect.  "Partial", "out of scope" and "not measured" are not
    # verdicts, so ORTHOGONAL and every unprobed row without a per-row
    # unreachability proof land in UNCOVERED and are named there.
    w('=' * 78)
    w('THE THREE-VALUED SPLIT.  COVERED / UNREACHABLE / UNCOVERED, and no')
    w('fourth value.  UNREACHABLE is only claimable where the per-ISA harness')
    w('carries the proof ON the row; everything else that is not COVERED is a')
    w('defect and is counted as one.')
    w('')
    hdr3 = ('%-9s %10s %13s %11s %11s' %
            ('ISA', 'COVERED', 'UNREACHABLE', 'UNCOVERED', 'total'))
    w(hdr3)
    w('-' * len(hdr3))
    g3 = collections.Counter()
    reach_src = {}
    for isa, _, vcol, dtok, _, _ in ISAS:
        if isa in blocked:
            w(refused_row(isa)); continue
        rows, counts, _unp = per_isa[isa]
        c = collections.Counter(r.direction for r in rows)
        mpath = os.path.join(a.cov, REACH_MATRIX.get(isa, '\0'))
        if isa in REACH_MATRIX and os.path.exists(mpath):
            # The verdict column of a file that carries, per row, the CPL3
            # signal, the count of CPU models the encoding ran under, the
            # all-CPUID-flags signal, the CPL0 vector, where QEMU refused,
            # the gating feature word and whether the decode tables name the
            # mnemonic at all.
            vt = collections.Counter()
            with open(mpath) as f:
                for r in csv.DictReader(f, delimiter='\t'):
                    vt[r['verdict']] += 1
            cov_, unreach, unc = (vt['COVERED'], vt['UNREACHABLE'],
                                  vt['UNCOVERED'])
            reach_src[isa] = mpath
        else:
            agree = counts.get('AGREE', 0) + counts.get('agree', 0)
            cov_ = agree + c[tax.SUPERSET]
            unreach = _unp['no']
            # `layout` is UNCOVERED, not UNREACHABLE: nobody proved the guest
            # cannot run it, the sled simply could not put it in a slot.
            unc = (c[tax.SUBSET] + c[tax.UNACCOUNTED] + c[tax.ORTHOGONAL] +
                   _unp['yes'] + _unp['layout'])
        cov = cov_
        g3['c'] += cov
        g3['u'] += unreach
        g3['x'] += unc
        w('%-9s %10d %13d %11d %11d'
          % (isa, cov, unreach, unc, cov + unreach + unc))
    w('-' * len(hdr3))
    w(refused_total('all four') if blocked else
      '%-9s %10d %13d %11d %11d'
      % ('all four', g3['c'], g3['u'], g3['x'],
         g3['c'] + g3['u'] + g3['x']))
    w('')
    for isa in sorted(reach_src):
        w('')
        w('%s: the verdict above is READ OFF %s, which carries the four'
          % (isa, reach_src[isa]))
        w('reachability legs and the two QEMU-tree citations on EVERY row.  An')
        w('UNREACHABLE row there means: SIGILL at CPL3 under -cpu max, SIGILL')
        w('at CPL3 under every 64-bit-capable CPU model QEMU has, SIGILL with')
        w('every CPUID flag forced on at once, AND #UD at CPL0 in long mode')
        w('under qemu-system.  A row that fails any one of the four is')
        w('UNCOVERED, whether or not a comparison was made for it.')
    w('')
    w('WHERE THE VERDICT IS NOT READ OFF A REACH MATRIX,')
    w('UNCOVERED = TRACER-SUBSET + UNACCOUNTED + ORTHOGONAL + '
      'REACHABLE-UNPROBED.')
    w('ORTHOGONAL is in there deliberately: a different vocabulary for the')
    w('same fact is a NAMED disagreement, not an agreement, and naming it is')
    w('not the same as closing it.')
    w('')

    # ------------------------------------------------- per-ISA cross-tables
    for isa, _, _, _, _, _ in ISAS:
        if isa in blocked:
            w(refused_row(isa)); continue
        rows = per_isa[isa][0]
        w('=' * 78)
        w(tax.render_crosstab(
            rows, '%s -- CROSS-TABULATION  direction x category' % isa))
        w('')
        w('  execution reference: %s' % EXEC_REFERENCE[isa])
        w('')

    # ------------------------------------------------------ combined table
    allrows = [r for isa, _, _, _, _, _ in ISAS if isa not in blocked
               for r in per_isa[isa][0]]
    w('=' * 78)
    w(tax.render_crosstab(
        allrows, 'ALL FOUR ISAs -- CROSS-TABULATION  direction x category'))
    w('')

    # ------------------------------------------------- unaccounted, by ISA
    for isa, _, _, _, _, _ in ISAS:
        if isa in blocked:
            w(refused_row(isa)); continue
        rows = per_isa[isa][0]
        w('=' * 78)
        w('%s -- %s' % (isa, tax.render_unaccounted(rows, a.top).splitlines()[0]))
        w('')
        body = tax.render_unaccounted(rows, a.top).splitlines()[1:]
        w('\n'.join(body))

    # ----------------------------------------------------------- the holes
    w('=' * 78)
    w('WHAT THIS REPORT DOES NOT MEASURE')
    w('=' * 78)
    w('')
    w('MEMOPS.  Count, address and data for every load and store are half the')
    w('deliverable and NO harness IN THIS REPORT compares any of them.  On')
    w('x86_64 the hole is wider than it used to be described: this text said')
    w('the tracer arm "parses f_loads / f_stores and never uses them", and it')
    w('no longer parses them at all -- the arm is sled_fields.py, whose')
    w('columns are hex / f_ok / f_opcode / f_branch / f_src / f_dst /')
    w('f_ident, with no memop counts in them, so there is no tracer-side')
    w('number there to compare.  The aarch64 reference carries mem_r / mem_w')
    w('per subject and its comparison never reads them.  The numbers above')
    w('are register attribution only and must not be quoted as memop')
    w('coverage.')
    w('')
    w('The EXECUTION legs DO compare memops -- count, address, width and data')
    w('-- on all four ISAs, and their numbers live in their own reports, not')
    w('here.  See the R13 gate (tools/external_truth_gate.sh) for the one')
    w('entry point that scores both halves together.')
    w('')
    w('THE WRONG PATH.  Every number above is a CORRECT-PATH number, and no')
    w('row in this table would move if a wrong-path divergence existed.  The')
    w('wrong path has its own harnesses, in their own reports: riscv64 against')
    w('Spike (spike/wp/compare_wp.py) and aarch64 + mipsel against gem5')
    w('(gem5/wp/), each rebuilding the architectural state a trace says holds')
    w('at an excursion and re-executing it in a real simulator.  x86_64 has NO')
    w('wrong-path execution reference; there, a wrong-path divergence is still')
    w('invisible.  Separately, wpcp_equiv scores WP-against-CP dataflow')
    w('equivalence on all four ISAs, which is a self-consistency check and not')
    w('an external reference.')
    w('')
    w('EXECUTION.  Every ISA now has an execution reference.  What each one')
    w('can and cannot state differs, and the difference is the point:')
    for isa, _, _, _, _, _ in ISAS:
        w('  %-9s %s' % (isa, EXEC_REFERENCE[isa]))
    w('')
    txt = '\n'.join(out) + '\n'
    sys.stdout.write(txt)
    if a.o:
        open(a.o, 'w').write(txt)
    if a.rows:
        # The report prints the top N mnemonics; this file is every row, so
        # "more than 50" is never a place information goes missing.
        with open(a.rows, 'w') as f:
            f.write('isa\topcode_id\tmnemonic\tset_relation\tcategory\t'
                    'harness_label\n')
            for isa, _, _, _, _, _ in ISAS:
                if isa in blocked:
                    continue
                for r in per_isa[isa][0]:
                    if r.direction != tax.UNACCOUNTED:
                        continue
                    f.write('\t'.join((isa, r.ident, r.mnemonic, r.relation,
                                        r.category, r.label)) + '\n')
    # THE REPORT IS WRITTEN AND THE RUN STILL FAILS.  Publishing the legs that
    # ran is not the same as passing; the blocked legs carry REFUSED rows that
    # the R13 gate reads as their own failures, and this exit code is what a
    # caller scripting the report sees.
    if blocked:
        sys.exit('%d of %d legs blocked: %s.  Their rows above read REFUSED '
                 'and every all-four total is withheld; the legs that DID run '
                 'are published beside them and are readable.'
                 % (len(blocked), len(ISAS), ', '.join(sorted(blocked))))


if __name__ == '__main__':
    main()
