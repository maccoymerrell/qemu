"""
ARC 3 -- the rule tables that map each harness's own adjudication labels onto
the shared two-axis taxonomy (arc3_taxonomy).

One rule per label the four harnesses actually emit.  A label that names a
MECHANISM accounts for its rows.  A label that only restates WHICH WAY the sets
differ ("other missing register", "TRACER-GAP"), or that groups rows of more
than one mechanism ("MIXED -- 10 rank-2 gap, 5 reference defect"), explains no
individual row and therefore accounts for none: those rows report as
UNACCOUNTED, which is what they are.

A label present in the data with no rule here is also UNACCOUNTED, and the
harness prints it under LABELS WITH NO RULE so the gap is never silent.

Author: Maccoy Merrell.
"""
import os
import re
import sys

from arc3_taxonomy import (Rule, ANY, SUPERSET, SUBSET, ORTHOGONAL,
                           stated_rows)


# ===========================================================================
# x86_64 -- compare_attrib.mechanism() charges every disagreement to exactly
# one Mn cause.  The key is the Mn token; the rest of the string is prose.
# ===========================================================================
def x86_key(mech):
    return mech.split(' ', 1)[0] if mech else ''


X86 = {
    # The EVEX mask classes.  Root cause measured in the harness itself:
    # Capstone 6.0-Alpha7 hands the mask operand over with access == 0, so the
    # tracer's operand walker never sees it.  Upstream defect, same family as
    # the PEXTR and MSA access-flag bugs already worked around at the boundary.
    'M1':  Rule('M1', 'capstone-defect', {SUBSET},
                note='EVEX mask not recorded as a source'),
    'M1b': Rule('M1b', 'capstone-defect', ANY,
                note='EVEX mask misplaced or missing, k-destination forms'),
    'M1c': Rule('M1c', 'capstone-defect', {SUBSET, ORTHOGONAL},
                note='EVEX mask source missing alongside another gap'),
    'M2':  Rule('M2', 'capstone-defect', {ORTHOGONAL},
                note='mask lands in DST and the vector destination is lost'),

    # Flags.
    'M3':  Rule('M3', 'tracer-defect', {SUBSET},
                note='a real RFLAGS read the tracer does not name'),
    'M3b': Rule('M3b', 'capstone-defect', ANY,
                note='Capstone access-flag gap: cli/sti write IF and the '
                     'tracer records nothing'),
    'M3c': Rule('M3c', 'tracer-defect', {SUBSET},
                note='R4 source of a conditional flag write (shift by CL)'),

    'M5':  Rule('M5', 'tracer-defect', {SUBSET},
                note='x87 implicit ST(0) / status-word dependency'),
    'M6':  Rule('M6', 'vocabulary-gap', {SUBSET},
                note='no GenericRegId exists for this register'),

    # "the tracer names a register the reference does not (phantom)" asserts
    # the extra register is FALSE.  The harness's own coverage report records
    # that some of these rows are the MPX / NOP identity forms, where the extra
    # register is TRUE and the row is a TRACER-SUPERSET, not a defect.  One
    # label, two mechanisms: it cannot explain an individual row.
    'M7':  Rule('M7', 'tracer-defect', ANY, accounts=False,
                note='groups genuine phantoms with MPX/NOP identity rows; '
                     'the label cannot say which a given row is'),

    # "other missing register" names no mechanism.  It is the residual bucket,
    # i.e. exactly the rows nobody has interrogated.
    'M8':  Rule('M8', 'unaccounted', ANY, accounts=False,
                note='residual bucket; restates the direction, names no cause'),
}


# ===========================================================================
# aarch64 -- adjudicate.ADJ maps a disagreement SIGNATURE to a verdict string
# and a prose reason.  The verdict prefix carries the mechanism; the prose
# carries a row count, which is checked.
# ===========================================================================
_A64_VERDICT = [
    # (regex over the verdict string, category, accounts)
    (r'^MIXED\b',                       'tracer-defect',           False),
    (r'\(\d+ rows?\)\s*/',              'tracer-defect',           False),
    (r'^TRACER DEFECT',                 'tracer-defect',           True),
    (r'^TRACER RIGHT -- REFERENCE DEFECT', 'reference-defect',     True),
    (r'^TRACER RIGHT -- REFERENCE-SIDE',   'reference-defect',     True),
    (r'^REFERENCE GAP',                 'reference-gap',           True),
    (r'^REPRESENTATIVE ARTIFACT',       'representative-artifact', True),
    (r'^NEEDS RULING',                  'needs-ruling',            True),
    # A signature whose adjudication says CLOSED must have no rows left.  If
    # one matches, the close was not a close.
    (r'^CLOSED',                        'tracer-defect',           True),
]


def aarch64_rules(adj):
    """adjudicate.ADJ -> {signature: Rule}."""
    out = {}
    for sig, (verdict, why) in adj.items():
        cat, accounts, expect = None, True, None
        for rx, c, a in _A64_VERDICT:
            if re.search(rx, verdict):
                cat, accounts = c, a
                break
        if cat is None:
            continue                      # no rule -> UNACCOUNTED, reported
        stated = stated_rows(why)
        if verdict.startswith('CLOSED'):
            # A CLOSED adjudication's prose states the count the class had
            # BEFORE it was closed, so that number is history, not a claim
            # about the measurement.  The claim a close makes is that the class
            # is empty, and expect=() enforces exactly that: any surviving row
            # reports as a conflict.
            expect, stated = frozenset(), None
        out[sig] = Rule(sig, cat, expect, accounts=accounts,
                        stated=stated, note=verdict)
    return out


# ===========================================================================
# riscv64 -- compare.ADJUDICATED assigns a kind per signature PART; the row's
# adjudication column is the '+'-joined set of kinds, or one of the derived
# fallbacks.
# ===========================================================================
RISCV = {
    'REF-ARTIFACT':  Rule('REF-ARTIFACT', 'reference-defect', ANY,
                          note='the reference performs a read the ISA does '
                               'not make this encoding depend on'),
    'SCOPE-XLATE':   Rule('SCOPE-XLATE', 'scope-exclusion', {SUBSET},
                          note='address translation / PMP / platform state: '
                               'an enumerated exclusion the tracer applies '
                               'and the reference leaks'),
    'REF-UNDERREAD': Rule('REF-UNDERREAD', 'reference-defect', {SUPERSET},
                          note='Sail writes a sub-range, so the preserve of '
                               'the rest calls no read accessor'),
    # Derived fallbacks.  They restate the set relation and name no cause.
    'TRACER-GAP':    Rule('TRACER-GAP', 'unaccounted', ANY, accounts=False,
                          note='derived fallback: every signature part is a '
                               'miss and none is adjudicated'),
    'TRACER-EXTRA':  Rule('TRACER-EXTRA', 'unaccounted', ANY, accounts=False,
                          note='derived fallback: every part is an extra and '
                               'none is adjudicated'),
    'MIXED':         Rule('MIXED', 'unaccounted', ANY, accounts=False,
                          note='derived fallback: misses and extras, none '
                               'adjudicated'),
}


def riscv_rule(label):
    """A '+'-joined label is only accounted when EVERY part is."""
    if not label:
        return None
    parts = label.split('+')
    rules = [RISCV.get(p) for p in parts]
    if any(r is None for r in rules):
        return None
    if len(rules) == 1:
        return rules[0]
    # A compound label means the row was only PARTLY adjudicated: some
    # signature part matched a rule and the rest fell to a derived fallback.
    # Partly explained is not explained.
    accounts = all(r.accounts for r in rules)
    cats = [r.category for r in rules if r.category != 'unaccounted']
    return Rule(label, cats[0] if len(set(cats)) == 1 else 'unaccounted',
                ANY, accounts=accounts,
                note='compound: ' + ' + '.join(r.note for r in rules))


# ===========================================================================
# mipsel -- adjudicate.RULES are applied to build the REFERENCE, not to
# adjudicate a disagreement, so the adjudication_rules column of a DISAGREE row
# says how the reference was formed, never why the two sides differ.  There is
# no disagreement-adjudication table for this ISA: any mipsel disagreement is
# UNACCOUNTED until one is written.  At HEAD there are none, and this table
# exists so that the first one to appear reports as UNACCOUNTED rather than
# inheriting a reference-construction rule id it has nothing to do with.
# ===========================================================================
MIPSEL = {}


def mipsel_rule(label):
    return MIPSEL.get(label)
