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


# ===========================================================================
# riscv64, EXECUTION leg -- compare_exec.py against spike's commit log.
#
# Separate from RISCV above, which adjudicates the STATIC (Sail) leg.  The two
# legs disagree for different reasons and must not share a rule table: a Sail
# modelling gap says nothing about what spike's logger prints, and vice versa.
#
# Every rule here names a mechanism located in spike's own source, so it can be
# rechecked when spike is bumped rather than believed.
# ===========================================================================
RISCV_EXEC = {
    # riscv/execute.cc, commit_log_print_insn: the loop over log_reg_write
    # begins `if (item.first == 0) continue;`.  item.first is (rd << 4) | kind,
    # so the entry it skips is exactly an integer write to x0.  The reference
    # therefore cannot ever report an x0 write; the tracer's is surplus.
    'REF-X0-DISCARD':   Rule('REF-X0-DISCARD', 'reference-gap', {SUPERSET},
                             note='spike suppresses x0 writes outright '
                                  '(execute.cc); a tracer x0 write has no '
                                  'counterpart to disagree with'),

    # A CSR spike names that the tracer's GenericRegId vocabulary has no id
    # for.  Reported as vocabulary, never as a dropped write, and never
    # silently mapped onto a neighbouring id.
    'REF-CSR-UNMAPPED': Rule('REF-CSR-UNMAPPED', 'vocabulary-gap', {SUBSET},
                             note='the execution reference names a CSR no '
                                  'GenericRegId spells'),

    # riscv/csrs.cc:69 -- spike's CSR log entry is written from inside the CSR
    # WRITE ACCESSOR.  An FP operation that raises no new exception flag never
    # calls it, so the reference reports no fcsr destination at all, while the
    # tracer names the architectural destination whether or not this execution
    # changed it.  The reference under-reports by construction.
    'REF-CSR-ACCESSOR-ONLY':
        Rule('REF-CSR-ACCESSOR-ONLY', 'reference-gap', {SUPERSET},
             note='spike logs a CSR write only when the write accessor ran; '
                  'the tracer names the architectural destination'),

    # riscv/vector_unit.cc:168 -- log_elt_write_if_needed() is ELEMENT
    # triggered.  A fully masked-off vector operation writes no element and so
    # logs no vector destination, though the opcode's destination register is
    # architecturally exactly that register.
    'REF-VEC-ELEMENT-ONLY':
        Rule('REF-VEC-ELEMENT-ONLY', 'reference-gap', {SUPERSET},
             note='spike logs vector ELEMENT writes; a fully masked-off op '
                  'logs no destination at all'),

    # A register both sides name, with different values.  There is no
    # vocabulary reading of this: one of the two is wrong about what the
    # machine did, and it is not the machine.
    'VALUE-MISMATCH':
        Rule('VALUE-MISMATCH', 'tracer-defect', {SUBSET},
             note='both sides name the register; the values differ, so the '
                  'tracer carries a value the run did not produce'),

    # One GenericRegId, several architectural CSR writes in one instruction
    # (vsetvli writes vstart, vl and vtype).  The id cannot carry them, so no
    # value comparison at this granularity would be honest.
    'CSR-FOLD-MULTI':
        Rule('CSR-FOLD-MULTI', 'vocabulary-gap', {SUBSET},
             note='the reference records several CSR writes that the tracer '
                  'folds onto one GenericRegId, which can hold one value'),

    # A CSR the reference writes that the guest's architecture does not have.
    # spike at this revision carries the matrix/Zvt extension and clears its
    # `mtype` (0xC23) inside vectorUnit_t::set_vl (vector_unit.cc:148-152), so
    # every vsetvl logs a write to a register RVV 1.0 vsetvli does not touch.
    # The tracer is right to have no id for it.
    'REF-NONARCH-CSR':
        Rule('REF-NONARCH-CSR', 'reference-defect', {SUBSET},
             note='the reference logs a write to a CSR outside the ISA the '
                  'guest was built for (spike Zvt mtype on every vsetvl)'),

    # target/riscv/insn_trans/trans_rva.c.inc:74 -- QEMU implements SC with
    # tcg_gen_atomic_cmpxchg_tl, which performs a REAL load, and the memop
    # callback delivers it.  Architecturally a store-conditional writes and
    # returns a status bit; it does not read.  DECIDED the way #177 decided
    # the identical AArch64 case: the load is kept, because the trace records
    # what EXECUTED and a delivered access with no slot to land in is worse
    # than a superset the reference explains.  Spike models the architecture
    # and QEMU ran the emulation; neither is wrong, and the row is a named
    # TRACER-SUPERSET rather than an open question.
    'QEMU-SC-CMPXCHG':
        Rule('QEMU-SC-CMPXCHG', 'emulation-artefact', {SUPERSET},
             note='QEMU lowers store-conditional onto tcg_gen_atomic_cmpxchg, '
                  'which really reads the line; the tracer records the access '
                  'the guest performed, which the architecture does not have'),
}


def riscv_exec_rule(label):
    return RISCV_EXEC.get(label) if label else None
