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


ISAXCHECK = os.environ.get(
    'CST_ISAXCHECK',
    '/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck')


def refuse_if_stale(cov, allow_stale=False):
    """Refuse to publish a headline computed before the tracer it scores.

    THE FAILURE THIS EXISTS FOR: `12149 COVERED / 2698 UNREACHABLE / 0
    UNCOVERED` was published and relayed to the maintainer, and at the tip it
    read `12034 / 2698 / 115`.  The table was built four hours before the two
    commits it claimed to measure, the isaxcheck GATE was green throughout --
    correctly, it reads a different thing -- and nothing anywhere noticed.
    This report cannot re-derive four heterogeneous legs in process (aarch64
    walks the Arm MRA, riscv64 the Sail model, x86_64 four reachability legs
    under qemu-system), so it does the other half of the maintainer's ruling:
    it REFUSES, by name, when a per-ISA table is older than the binary whose
    behaviour it describes.

    The per-ISA harnesses hold the stronger check -- x86_64 and aarch64 each
    re-probe and compare byte-for-byte, riscv64 and mipsel re-probe as part of
    their run -- so a green result here means every leg was re-run AND their
    tables post-date the build.

    THIS IS THE LAST LINE, NOT THE FIRST.  Refusing here is correct and it is
    also expensive: by the time this runs, four heterogeneous legs have taken
    hours, and a relink anywhere in that window is discovered only once all of
    them have been paid for.  Each REPRODUCE.sh therefore arms
    ../settle_guard.sh before any of its own work -- it refuses to START on a
    tree with pending build work, and hashes the subjects so a relink DURING a
    leg is named by the leg it invalidated.  A run that came through those
    guards cannot reach this one with a stale table; a run that did not is
    exactly what this is still here to catch.
    """
    if not os.path.exists(ISAXCHECK):
        sys.exit('CANNOT CHECK FRESHNESS: no isaxcheck at %s.  This report '
                 'scores tables it did not build; without the binary it '
                 'cannot tell a current table from a stale one, and a check '
                 'that cannot find its subject must fail.  Build it or set '
                 'CST_ISAXCHECK.' % ISAXCHECK)
    bt = os.path.getmtime(ISAXCHECK)
    stale = []
    for isa, rel, _v, _d, _m, _l in ISAS:
        q = os.path.join(cov, rel)
        if os.path.exists(q) and os.path.getmtime(q) < bt:
            stale.append((isa, q, os.path.getmtime(q)))
    if not stale:
        return
    fmt = '%Y-%m-%d %H:%M:%S'
    for isa, q, mt in stale:
        sys.stderr.write('STALE LEG  %-8s %s\n            table  %s\n'
                         '            binary %s\n'
                         % (isa, q, time.strftime(fmt, time.localtime(mt)),
                            time.strftime(fmt, time.localtime(bt))))
    if allow_stale:
        sys.stderr.write('--allow-stale given: publishing anyway.  The '
                         'numbers below are NOT a measurement at this tip.\n')
        return
    sys.exit('%d of %d legs were scored before the tracer they describe was '
             'built.  Re-run those legs; do not publish this table.'
             % (len(stale), len(ISAS)))


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
                         'binary, having said so on stderr first.  For '
                         'inspecting a historical run, never for a verdict')
    a = ap.parse_args()

    refuse_if_stale(a.cov, a.allow_stale)

    out = []
    w = out.append
    per_isa = {}
    missing = []
    for isa, rel, vcol, dtok, mcol, lcol in ISAS:
        p = os.path.join(a.cov, rel)
        if not os.path.exists(p):
            missing.append((isa, p))
            continue
        per_isa[isa] = read(p, vcol, dtok, mcol, lcol)

    if missing:
        # A report that cannot find its subject must fail, not quietly average
        # over what it did find.
        for isa, p in missing:
            sys.stderr.write('MISSING %s: %s\n' % (isa, p))
        sys.exit('refusing to report on a partial set of ISAs')

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
        rows, counts, _unp = per_isa[isa]
        c = collections.Counter(r.direction for r in rows)
        agree = counts.get('AGREE', 0) + counts.get('agree', 0)
        unpro = counts.get('UNPROBED', 0) + counts.get('unprobed', 0)
        probed = agree + len(rows)
        gcounts['hole'] += _unp['yes']
        gcounts['outofscope'] += _unp['no']
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
    w('%-9s %8d %9d %9d %11d %9d %11d %13d %10d'
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
        rows, _c2, _unp = per_isa[isa]
        c = collections.Counter(r.direction for r in rows)
        w('%-9s %d  (subset %d + unaccounted %d + hole %d)'
          % (isa, c[tax.SUBSET] + c[tax.UNACCOUNTED] + _unp['yes'],
             c[tax.SUBSET], c[tax.UNACCOUNTED], _unp['yes']))
    w('%-9s %d  (subset %d + unaccounted %d + hole %d)'
      % ('all four',
         grand[tax.SUBSET] + grand[tax.UNACCOUNTED] + gcounts['hole'],
         grand[tax.SUBSET], grand[tax.UNACCOUNTED], gcounts['hole']))
    w('')
    # The unprobed TOTAL is never printed alone.  It sat frozen at 2713 across
    # three x86_64 reports while its composition moved 2479/234 -> 2363/349
    # reachable; a constant hid a 50% growth in the coverage hole.  Both
    # components travel together, always.
    w('UNPROBED, counted here and nowhere else: %d = %d out-of-scope + %d'
      % (gcounts['unprobed'], gcounts['outofscope'], gcounts['hole']))
    w('REACHABLE.  An opcode with no comparison has no direction; it is the')
    w('most complete form of dropped information, not a row that agreed.  The')
    w('out-of-scope component is only out of scope where the per-ISA harness')
    w('charged it to a citation from the QEMU tree -- for x86_64 that is')
    w('qemu_tcg_scope.py, which re-asserts every citation on every run and')
    w('refuses when one goes stale.  The REACHABLE component is the hole.')
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
            unc = (c[tax.SUBSET] + c[tax.UNACCOUNTED] + c[tax.ORTHOGONAL] +
                   _unp['yes'])
        cov = cov_
        g3['c'] += cov
        g3['u'] += unreach
        g3['x'] += unc
        w('%-9s %10d %13d %11d %11d'
          % (isa, cov, unreach, unc, cov + unreach + unc))
    w('-' * len(hdr3))
    w('%-9s %10d %13d %11d %11d'
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
        rows = per_isa[isa][0]
        w('=' * 78)
        w(tax.render_crosstab(
            rows, '%s -- CROSS-TABULATION  direction x category' % isa))
        w('')
        w('  execution reference: %s' % EXEC_REFERENCE[isa])
        w('')

    # ------------------------------------------------------ combined table
    allrows = [r for isa, _, _, _, _, _ in ISAS for r in per_isa[isa][0]]
    w('=' * 78)
    w(tax.render_crosstab(
        allrows, 'ALL FOUR ISAs -- CROSS-TABULATION  direction x category'))
    w('')

    # ------------------------------------------------- unaccounted, by ISA
    for isa, _, _, _, _, _ in ISAS:
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
    w('deliverable and NO harness IN THIS REPORT compares any of them.  The')
    w('x86_64 tracer arm parses f_loads / f_stores and never uses them; the')
    w('aarch64 reference carries mem_r / mem_w per subject and the comparison')
    w('never reads them.  The numbers above are register attribution only and')
    w('must not be quoted as memop coverage.')
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
                for r in per_isa[isa][0]:
                    if r.direction != tax.UNACCOUNTED:
                        continue
                    f.write('\t'.join((isa, r.ident, r.mnemonic, r.relation,
                                        r.category, r.label)) + '\n')


if __name__ == '__main__':
    main()
