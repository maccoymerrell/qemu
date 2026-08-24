"""
ARC 3 -- the two-axis taxonomy every coverage harness reports through.

A disagreement count on its own says nothing.  "554 disagree" is compatible
with 554 rows where the tracer records MORE than the reference (which is the
project's stated goal) and with 554 rows where it silently drops execution
information (which is the thing that must never ship).  Every disagreeing row
therefore carries two independent answers:

  DIRECTION -- WHICH WAY the two sets differ.  Derived MECHANICALLY from the
               sets themselves, never from a label, because a label is an
               opinion and a set relation is a measurement:

                 TRACER-SUPERSET  the tracer's set strictly CONTAINS the
                                  reference's -- we record something the
                                  reference omits                       OK
                 TRACER-SUBSET    the reference's set strictly contains the
                                  tracer's -- the reference records
                                  something we drop                     DEFECT
                 ORTHOGONAL       neither contains the other            named
                 UNACCOUNTED      no rule explains this row       MUST BE 0

  CATEGORY  -- WHY they differ: the mechanism.  reference-defect,
               capstone-defect, tracer-defect, scope-exclusion,
               vocabulary-gap, ...

The set relation is always computed.  The reported DIRECTION is that relation
only when a rule accounts for the row; otherwise it is UNACCOUNTED, because a
row nobody has interrogated has no direction we are entitled to claim.  The
number that matters is TRACER-SUBSET + UNACCOUNTED: the rows where we drop
information, or do not know why we differ.

A rule that names a mechanism ALSO names, where the mechanism admits only one,
the set relations it is consistent with.  A row whose measured relation is
outside its rule's expectation is not quietly reclassified -- it is reported as
a CONFLICT, i.e. an adjudication that does not fit the row it is charged to.
Rules that state a row count ("42 rows.") are checked against the measured
count, and a mismatch is reported the same way.

Author: Maccoy Merrell.
"""
import re
import collections

# --------------------------------------------------------------- directions
SUPERSET = 'TRACER-SUPERSET'
SUBSET = 'TRACER-SUBSET'
ORTHOGONAL = 'ORTHOGONAL'
UNACCOUNTED = 'UNACCOUNTED'
EQUAL = 'EQUAL'          # not a disagreement; never reported as a direction

DIRECTIONS = (SUPERSET, SUBSET, ORTHOGONAL, UNACCOUNTED)
ANY = frozenset((SUPERSET, SUBSET, ORTHOGONAL))

#: the direction axis, with the verdict each value carries
DIRECTION_VERDICT = {
    SUPERSET:    'OK      we record something the reference omits',
    SUBSET:      'DEFECT  the reference records something we drop',
    ORTHOGONAL:  'NAMED   different vocabulary for the same fact',
    UNACCOUNTED: 'MUST BE 0  not yet interrogated',
}

# --------------------------------------------------------------- categories
# The mechanism axis.  Fixed vocabulary: a harness may not invent a category
# without adding it here, so the cross-tabulation stays comparable across ISAs.
CATEGORIES = (
    'tracer-defect',            # the tracer drops or invents architectural state
    'capstone-defect',          # upstream Capstone gives the tracer no way to see it
    'reference-defect',         # the reference is wrong; the tracer is right
    'reference-gap',            # the reference models this state not at all
    'scope-exclusion',          # an enumerated exclusion, applied on one side only
    'vocabulary-gap',           # no GenericRegId exists for this register
    'vocabulary-difference',    # same fact, different spelling
    'representative-artifact',  # the chosen probe encoding, not the opcode
    'emulation-artefact',       # QEMU's execution differs from the ISA, and
                                # the tracer records what the guest RAN.  Not
                                # a tracer defect and not a reference defect:
                                # both are right about different machines.
                                # The store-conditional lowered onto a
                                # cmpxchg, which really reads, is the case
                                # this exists for (#177, and its riscv64 and
                                # mipsel siblings).
    'needs-ruling',             # mechanism named, verdict awaiting the maintainer
    'unaccounted',              # no rule reaches this row
)

#: categories whose mechanism admits only one set relation.  A row charged to
#: one of these whose measurement lies outside is a CONFLICT, not a row to be
#: re-labelled.
CATEGORY_EXPECT = {
    'reference-gap':  frozenset((SUPERSET,)),   # the reference under-reports, always
    'vocabulary-gap': frozenset((SUBSET,)),     # an unmappable register is dropped
    'unaccounted':    frozenset(),
}


class Rule(object):
    """One adjudication, translated onto the two axes.

    key       the harness's own label, verbatim -- the thing being mapped
    category  the mechanism, from CATEGORIES
    expect    set relations this mechanism is consistent with
    accounts  False for a label that groups rows of more than one mechanism,
              or that merely restates the set relation: such a label cannot
              explain any individual row, so its rows stay UNACCOUNTED
    stated    the row count the rule's own text claims, or None
    note      free text
    """

    __slots__ = ('key', 'category', 'expect', 'accounts', 'stated', 'note')

    def __init__(self, key, category, expect=None, accounts=True,
                 stated=None, note=''):
        assert category in CATEGORIES, category
        self.key = key
        self.category = category
        self.expect = frozenset(expect) if expect is not None else \
            CATEGORY_EXPECT.get(category, ANY)
        self.accounts = accounts
        self.stated = stated
        self.note = note


# ------------------------------------------------------ mechanical direction
def side_set(src, dst):
    """(source set, destination set) -> one role-tagged set.

    Tagging by role is what makes the containment test mean what it says: a
    register the reference calls a source and the tracer calls a destination is
    not agreement, and must not compare as containment in either direction.
    """
    return frozenset(['S:' + x for x in src] + ['D:' + x for x in dst])


def set_relation(ref_src, ref_dst, trc_src, trc_dst):
    """The measurement.  No label is consulted."""
    r = side_set(ref_src, ref_dst)
    t = side_set(trc_src, trc_dst)
    if r == t:
        return EQUAL
    if r < t:
        return SUPERSET          # tracer strictly contains the reference
    if t < r:
        return SUBSET            # reference strictly contains the tracer
    return ORTHOGONAL


# ------------------------------------------------------------- the classifier
Row = collections.namedtuple(
    'Row', 'ident mnemonic label relation direction category accounted conflict')


def classify(ident, mnemonic, label, relation, rule):
    """One disagreeing row -> its place in the cross-tabulation.

    `relation` is the measurement; `rule` is whatever the harness's own
    adjudication table returned for `label` (None when nothing matched).
    """
    assert relation in (SUPERSET, SUBSET, ORTHOGONAL), relation
    if rule is None:
        return Row(ident, mnemonic, label, relation, UNACCOUNTED,
                   'unaccounted', False, None)
    if not rule.accounts:
        # The label exists but cannot explain THIS row -- it groups several
        # mechanisms, or it only restates which way the sets differ.
        return Row(ident, mnemonic, label, relation, UNACCOUNTED,
                   rule.category, False, None)
    if relation not in rule.expect:
        # The adjudication does not fit the row it is charged to.  Reported,
        # never silently corrected.
        return Row(ident, mnemonic, label, relation, UNACCOUNTED,
                   rule.category, False,
                   'adjudication "%s" (%s) expects %s, row measures %s'
                   % (label, rule.category,
                      '/'.join(sorted(rule.expect)) or '(nothing)', relation))
    return Row(ident, mnemonic, label, relation, relation,
               rule.category, True, None)


# --------------------------------------------------------- stated-count check
_STATED = re.compile(r'(\d+)\s+rows?\.')


def stated_rows(text):
    """The row count an adjudication's own prose claims, if it claims one.

    An adjudication that says "42 rows." is making a checkable statement about
    the measurement.  When it stops matching, either the tree moved under the
    adjudication or the adjudication was never right; both are findings.
    """
    m = _STATED.findall(text or '')
    return int(m[-1]) if m else None


def check_stated(rules, measured):
    """[(key, stated, measured)] for every rule whose stated count is wrong."""
    bad = []
    for key, rule in rules.items():
        if rule.stated is None:
            continue
        got = measured.get(key, 0)
        if got != rule.stated:
            bad.append((key, rule.stated, got))
    return sorted(bad)


# ------------------------------------------------------------------ rendering
def crosstab(rows):
    """rows -> {(direction, category): count}"""
    c = collections.Counter()
    for r in rows:
        c[(r.direction, r.category)] += 1
    return c


def render_crosstab(rows, title, width=26):
    """The cross-tabulation, as text.  Directions are columns, categories rows."""
    ct = crosstab(rows)
    cats = [c for c in CATEGORIES
            if any((d, c) in ct for d in DIRECTIONS)]
    out = []
    out.append(title)
    out.append('')
    hdr = '%-*s %16s %14s %11s %12s %8s' % (
        width, 'CATEGORY (mechanism)', SUPERSET, SUBSET, ORTHOGONAL,
        UNACCOUNTED, 'total')
    out.append(hdr)
    out.append('-' * len(hdr))
    tot = collections.Counter()
    for c in cats:
        line = [ct.get((d, c), 0) for d in DIRECTIONS]
        for d, v in zip(DIRECTIONS, line):
            tot[d] += v
        out.append('%-*s %16d %14d %11d %12d %8d'
                   % (width, c, line[0], line[1], line[2], line[3], sum(line)))
    out.append('-' * len(hdr))
    out.append('%-*s %16d %14d %11d %12d %8d'
               % (width, 'TOTAL', tot[SUPERSET], tot[SUBSET], tot[ORTHOGONAL],
                  tot[UNACCOUNTED],
                  sum(tot[d] for d in DIRECTIONS)))
    out.append('')
    out.append('  the number that matters: TRACER-SUBSET + UNACCOUNTED = %d'
               % (tot[SUBSET] + tot[UNACCOUNTED]))
    out.append('  (rows where we drop information, or do not know why we differ)')
    return '\n'.join(out)


def render_conflicts(rows, limit=50):
    """The rows whose existing adjudication does not fit them.  Findings."""
    bad = [r for r in rows if r.conflict]
    if not bad:
        return 'ADJUDICATION CONFLICTS: none\n'
    out = ['ADJUDICATION CONFLICTS -- %d rows whose existing adjudication does '
           'not fit' % len(bad),
           'the row it is charged to.  Reported, NOT reclassified.', '']
    seen = collections.Counter()
    for r in bad:
        seen[r.conflict] += 1
    for msg, n in seen.most_common(limit):
        out.append('%6d  %s' % (n, msg))
        ex = [r for r in bad if r.conflict == msg][:4]
        out.append('        e.g. %s' % ', '.join(
            '%s (%s)' % (r.ident, r.mnemonic) for r in ex))
    return '\n'.join(out) + '\n'


def render_unaccounted(rows, limit=50):
    """Every UNACCOUNTED row, by mnemonic."""
    un = [r for r in rows if r.direction == UNACCOUNTED]
    if not un:
        return 'UNACCOUNTED ROWS: none\n'
    by_mnem = collections.Counter(r.mnemonic for r in un)
    by_class = collections.Counter('%s / %s' % (r.category, r.relation)
                                   for r in un)
    out = ['UNACCOUNTED -- %d rows, %d distinct mnemonics'
           % (len(un), len(by_mnem)), '']
    out.append('  by class (category / measured set relation)')
    for k, n in by_class.most_common():
        out.append('    %6d  %s' % (n, k))
    out.append('')
    if len(by_mnem) > limit:
        out.append('  more than %d distinct mnemonics; full class breakdown '
                   'above, top %d below' % (limit, limit))
    out.append('  by mnemonic')
    for m, n in by_mnem.most_common(limit):
        ex = next(r for r in un if r.mnemonic == m)
        out.append('    %6d  %-24s %-14s %s'
                   % (n, m, ex.relation, ex.label[:60]))
    return '\n'.join(out) + '\n'
