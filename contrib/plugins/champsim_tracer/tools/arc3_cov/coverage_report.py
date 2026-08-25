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
    'aarch64': 'NONE.  No execution reference exists for this ISA.',
    'mipsel':  'NONE.  No execution reference exists for this ISA.',
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cov', default=DEFAULT_COV)
    ap.add_argument('--top', type=int, default=50)
    ap.add_argument('-o', default=None, help='also write the report here')
    ap.add_argument('--rows', default=None,
                    help='write EVERY unaccounted row here as a TSV, so the '
                         'top-N above never stands in for the full list')
    a = ap.parse_args()

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
    for isa, _, vcol, dtok, _, _ in ISAS:
        rows, counts, _unp = per_isa[isa]
        c = collections.Counter(r.direction for r in rows)
        agree = counts.get('AGREE', 0) + counts.get('agree', 0)
        cov = agree + c[tax.SUPERSET]
        unreach = _unp['no']
        unc = (c[tax.SUBSET] + c[tax.UNACCOUNTED] + c[tax.ORTHOGONAL] +
               _unp['yes'])
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
    w('deliverable and NO ISA harness compares any of them.  The x86_64 tracer')
    w('arm parses f_loads / f_stores and never uses them; the aarch64 reference')
    w('carries mem_r / mem_w per subject and the comparison never reads them.')
    w('The numbers above are register attribution only and must not be quoted')
    w('as memop coverage.')
    w('')
    w('THE WRONG PATH.  Every number above is a CORRECT-PATH number.  The')
    w('wrong-path arm is scored by exactly one harness on exactly one ISA --')
    w('riscv64/spike/wp/compare_wp.py, which rebuilds the architectural state')
    w('a trace says holds at an excursion and runs a real simulator from it.')
    w('On aarch64, mipsel and x86_64 a wrong-path divergence is still')
    w('invisible, and no row in this table would move if one existed.')
    w('')
    w('EXECUTION.  Three of the four ISAs are scored against a STATIC decoder')
    w('or an executable specification, not against a real run:')
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
