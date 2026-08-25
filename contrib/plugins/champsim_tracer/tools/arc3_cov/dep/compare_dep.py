"""
ARC 3 -- the riscv64 and mipsel INTRA-INSTRUCTION DEPENDENCY leg.

THE SUBJECT
===========
The wire's four dependency-mask families, as a consumer reads them, scored
against a reference that resolves intra-instruction dependencies for itself.
This is the check ``QUEUED_refiner_substitution.md`` names as the one that
matters after the emitter-stated substitution: CP-M and CP-H are QEMU-derived,
so validating them against QEMU proves nothing, and Capstone -- which the
refiners are being moved OFF -- cannot state a dependency at all.

WHAT EACH AXIS CAN CONVICT, AND WHAT IT DELIBERATELY CANNOT
===========================================================
``dep-src-set``
    the architectural registers the instruction READS.  Tracer side: the
    union of every mask, with load slots resolved back through their address
    masks.  Reference side: gem5's external-source set.  Convicts a MISSING
    EDGE (a register gem5 renames as a source and no mask names) and a FALSE
    EDGE (a register a mask names and gem5 never reads).

``dep-dst-set``
    the architectural registers the instruction WRITES.  Present so the
    per-destination axis below cannot quietly skip a destination that only
    one side has -- without it, an invented or dropped destination would be
    unscored and its edges would vanish from both counts.

``dep-dst-closure``
    THE AXIS THIS LEG EXISTS FOR.  Per destination, the set of architectural
    registers that reach it.  On a single-micro-op instruction this is the
    all-to-all relation; on a cracked one it is strictly finer, and it is the
    relation an O3 rename stage acts on.

``dep-dst-discrimination``
    where the reference gives two destinations DIFFERENT closures, does the
    map also give them different sets?  A map that flattens an
    intra-instruction chain agrees on every union and fails only here.

THE SCOPE GUARD IS ENFORCED, NOT MERELY DECLARED
================================================
gem5's micro-op COUNT is never compared and never appears in an axis.  It is
gem5's implementation choice, the same class as the aarch64 memop-count bucket
this arc resolved by scoring bytes instead of counts.  ``uops`` is carried on
the reference record for the report's census and for nothing else.

R7.1 IS ENFORCED ON THE REFERENCE SIDE
======================================
A narrow write does NOT acquire a preserve-read.  Where a reference names the
merged-into register as a source of a partial write, the row is REFERENCE-side
over-naming and is accounted ``REF-OVER-NAMES-PRESERVE-READ``, never charged
to the tracer.  Predication is a different question and is NOT covered by that
rule: a predicated destination really is a source.

EXIT CODES -- taken from the process, never through a pipe
    0  every axis carried facts, and no axis has a TRACER-SUBSET or an
       UNACCOUNTED row
    1  scored, and the headline is non-zero
    2  an axis is INERT (zero facts).  A clean row from an axis that compared
       nothing is survivorship bias; the remedy is a better probe, never a
       pass, so this does not exit 0.
    3  REFUSED -- a prerequisite is absent, or the reference did not run to
       completion.  Nothing was scored.

Author: Maccoy Merrell.
"""
import argparse
import collections
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_COV = os.path.dirname(HERE)
for _d in (HERE, _COV, os.path.join(_COV, 'gem5'),
           os.path.join(_COV, 'riscv64', 'spike')):
    if _d not in sys.path:
        sys.path.insert(0, _d)

import arc3_taxonomy as tax                                     # noqa: E402
import axis_subjects                                            # noqa: E402
import dep_map                                                  # noqa: E402
import dep_ref_gem5                                             # noqa: E402
import gem5_env                                                 # noqa: E402
import gem5_ref                                                 # noqa: E402
import compare_exec_gem5 as cex                                 # noqa: E402

#: riscv64 joins the two tables the execution leg already keys by ISA.  Set
#: with ``setdefault`` so that an entry added there later wins over this one.
cex.QEMU_BIN.setdefault('riscv64', 'qemu-riscv64')
cex.GEM5_BUILD.setdefault('riscv64', 'RISCV')

#: The FP status/control partition, as the wire names it.  Held as a set so
#: the per-row test is a MEASUREMENT on the two operand sets and never a
#: mnemonic lookup.
FP_STATUS = frozenset(('REG_FCSR', 'REG_PRED0', 'REG_FPCW'))

#: The MIPS HI/LO accumulator pair.
ACC_PAIR = frozenset(('REG_ACC0', 'REG_ACCHI0'))

AXES = ('dep-src-set', 'dep-dst-set', 'dep-dst-closure',
        'dep-dst-discrimination', 'dep-mask-coverage')

#: ``dep-mask-coverage`` has NO reference side and says so in the report.  It
#: asks a question about the wire alone: does every source the instruction
#: DECLARES reach at least one sink through the masks?  A source that is
#: declared and routed nowhere is invisible to a dependency-consuming model --
#: it is in the operand list and in no edge -- and that is exactly the shape
#: of the mipsel `lwl`/`lwr` defect this leg found.  It is listed with the
#: scored axes because it carries facts and can fail; it is marked SELF so it
#: can never be read as a reference agreeing with us.
SELF_AXES = frozenset(('dep-mask-coverage',))


# ------------------------------------------------------------ adjudications
#
# Every rule below states a MECHANISM and the set relations that mechanism can
# produce.  A row whose measurement falls outside its rule's expectation is
# reported as a CONFLICT rather than re-labelled -- the adjudication is wrong
# about that row, and hiding it would be the allowlist-false-justification
# class this project has been caught by four times.
RULES = {
    'REF-STOPPED-AT-GUEST-EXIT': tax.Rule(
        'REF-STOPPED-AT-GUEST-EXIT', 'reference-gap',
        note='gem5 SE mode services the exit syscall outside its instruction '
             'trace, so the guest\'s final syscall has no reference record.'),
    'REF-CANNOT-SEPARATE-ADDR-FROM-DATA': tax.Rule(
        'REF-CANNOT-SEPARATE-ADDR-FROM-DATA', 'reference-gap',
        note='a load is one micro-op whose only source is the address '
             'register, so gem5 states that the address reaches the '
             'destination and cannot state that it does so AS an address.  '
             'The tracer states both facts; the closure is what makes them '
             'comparable.'),
    'REF-OVER-NAMES-PRESERVE-READ': tax.Rule(
        'REF-OVER-NAMES-PRESERVE-READ', 'reference-defect',
        expect=(tax.SUBSET,),
        note='R7.1: a NARROW write does not acquire a read of what it '
             'preserves.  A reference naming the merged-into register as a '
             'source of a partial write is over-naming, as XED was.  '
             'PREDICATION is a different question and is not covered here.'),
    'REF-NO-HILO-PROVENANCE': tax.Rule(
        'REF-NO-HILO-PROVENANCE', 'reference-gap',
        note='gem5 MIPS publishes the HI/LO pair in its operand lists but '
             'models no provenance distinction between them.'),
    'VOCAB-UNMAPPED': tax.Rule(
        'VOCAB-UNMAPPED', 'vocabulary-gap',
        note='a reference operand no vocabulary rule reaches.  Counted on '
             'the reference side, never folded into agreement.'),
    'REF-DROPS-REG-ZERO': tax.Rule(
        'REF-DROPS-REG-ZERO', 'reference-defect', expect=(tax.SUPERSET,),
        note='R7.3, BINDING and verbatim: "REG_ZERO exists, so it should be '
             'specified.  We should not be dropping reg zero."  The tracer '
             'is right; the reference elides the constant-zero operand.  The '
             'SAME defect was already adjudicated against the aarch64 '
             'reference, whose mra_ref.py:340 did dst.discard(\'ZERO\').  '
             'It is measured here, not assumed: the reference names REG_ZERO '
             'nowhere in the entire run.'),
    'REF-MODELS-NO-SUCH-STATE': tax.Rule(
        'REF-MODELS-NO-SUCH-STATE', 'reference-gap',
        note='a register the reference names NOWHERE in the whole run, so it '
             'is state the reference does not model rather than state it '
             'disagrees about.  Measured from the run\'s own vocabulary '
             'census, never from a table of expected omissions.'),
    'REF-UNIMPLEMENTED-INSN': tax.Rule(
        'REF-UNIMPLEMENTED-INSN', 'reference-gap',
        note='gem5 retires the instruction with no architectural effects and '
             'says so in its own disassembly.  Read off the reference\'s '
             'output, not off a mnemonic list.'),
    'VOCAB-NO-GENERIC-FOR-REF-MISC': tax.Rule(
        'VOCAB-NO-GENERIC-FOR-REF-MISC', 'vocabulary-gap',
        note='the reference names a register from its own miscellaneous file '
             'for which this leg has no generic id.  Reported as a '
             'vocabulary gap so it cannot be scored as a tracer omission.'),
    'REF-NO-FP-STATUS-ON-ARITH': tax.Rule(
        'REF-NO-FP-STATUS-ON-ARITH', 'reference-gap', expect=(tax.SUPERSET,),
        note='the reference models the FP status/control register on SOME '
             'instructions -- it names it on the compares and on cfc1 -- and '
             'on FP ARITHMETIC it names it nowhere.  Under R7 the edge is '
             'real: a ctc1 that writes the rounding mode must block a later '
             'add.s, so a renaming regfile has to respect it.  The CP leg '
             'recorded the same asymmetry from the other side ("on mipsel '
             'the tracer publishes an FP status destination the reference '
             'does not").  Measured per row: the reference names no FP '
             'status register on THIS instruction.'),
    'REF-SOURCE-IS-NEVER-WRITTEN': tax.Rule(
        'REF-SOURCE-IS-NEVER-WRITTEN', 'reference-defect',
        expect=(tax.SUBSET,),
        note='the reference names a source that it never writes ANYWHERE in '
             'the whole run.  An edge into a register nothing produces can '
             'never be respected by rename, so by the R7 test it is not a '
             'dependency -- the reference is naming the operand FILE rather '
             'than the operand.  Measured from the run\'s own destination '
             'census, not from a claim about which registers are read-only.'),
    'TRACER-SATURATED-DEFAULT': tax.Rule(
        'TRACER-SATURATED-DEFAULT', 'needs-ruling', accounts=False,
        note='the residue, once every register the reference does not model '
             'at all is removed, is the instruction\'s OWN DESTINATION named '
             'as a source, and the mask carrying it is SATURATED -- every '
             'declared source, every load slot and the immediate, which is '
             'the all-to-all default format.rst defines for an absent '
             'dependency block.  So the map is not STATING this edge; it is '
             'declining to narrow.  Whether it should narrow is a live '
             'question and it is NOT decided here: measured on the riscv64 '
             'vector probe, whose own vtype is `ta, ma` (tail-agnostic, '
             'mask-agnostic, read off the probe source and confirmed in the '
             'decode), nothing is preserved and R7.1 says a partial write '
             'acquires no preserve-read -- but the template is STATIC and '
             'must also cover `tu`, where the tail IS preserved and the edge '
             'IS real under R7.  Two binding rulings meet here and the '
             'lane-mask model that would resolve it is out of scope for this '
             'arc by design.  MECHANISM NAMED, VERDICT NOT TAKEN.'),
    'REF-NO-VECTOR-CONTROL-DEP+TRACER-SATURATED-DEFAULT': tax.Rule(
        'REF-NO-VECTOR-CONTROL-DEP+TRACER-SATURATED-DEFAULT', 'needs-ruling',
        accounts=False,
        note='BOTH mechanisms on one row: the reference models no vector '
             'control state (R7.4 says the tracer is right about that half), '
             'and the residue is the saturated all-to-all default naming the '
             'destination as a source.  It does not account, because half of '
             'it is the TRACER-SATURATED-DEFAULT question nobody has ruled '
             'on, and a composite row cannot be closed by the half that is '
             'settled.'),
    'REF-NO-VECTOR-CONTROL-DEP': tax.Rule(
        'REF-NO-VECTOR-CONTROL-DEP', 'reference-gap', expect=(tax.SUPERSET,),
        note='the reference names no vector control state (vl/vtype) on any '
             'vector instruction.  R7.4, BINDING and verbatim: "If a write '
             'to the CSR would block that instruction due to a dependency, '
             'it should be recorded."  A vsetvli must block every vector '
             'operation after it, so the tracer is right and the reference '
             'does not model the edge.'),
    'TRACER-NAMES-ACC-PAIR': tax.Rule(
        'TRACER-NAMES-ACC-PAIR', 'needs-ruling', accounts=False,
        note='the tracer names the HI/LO accumulator pair as destinations '
             'where the reference names only the explicit register.  The '
             'architecture leaves the pair UNPREDICTABLE for this form and '
             'QEMU really writes it, so the two tools are right about '
             'different machines -- which is the emulation-artefact shape.  '
             'MECHANISM NAMED, VERDICT NOT TAKEN: it stays UNACCOUNTED until '
             'the maintainer rules, rather than being absorbed by a category '
             'chosen here.'),
    'ORPHANED-SOURCE-NOT-ROUTED': tax.Rule(
        'ORPHANED-SOURCE-NOT-ROUTED', 'tracer-defect', expect=(tax.SUBSET,),
        note='the wire DECLARES the register as a source of the instruction '
             'and no mask routes it to any sink, so a model reading the '
             'dependency map never sees the edge.  Under R7 the test is '
             'whether a renaming regfile would have to respect it.'),
}


def rule_for(label):
    return RULES.get(label)


# ----------------------------------------------------------------- scoring
Row = collections.namedtuple(
    'Row', 'guest pc mnemonic axis subject ref trc label')


def _fmt(s):
    """Deterministic set rendering.

    ``repr(set)`` follows CPython's per-process hash randomisation, and two
    byte-identical measurements previously produced TSVs differing on 24 of 49
    rows for no reason but ``PYTHONHASHSEED``.  A reference nobody can diff
    against the last run is a reference nobody can check.
    """
    return '{' + ','.join(sorted(s)) + '}'


def score_guest(guest, tinsns, ginsns, subj, rows, notes, ref_vocab,
                ref_dst_vocab):
    """Align the two streams and score every axis.  Returns the identity."""
    name = os.path.basename(guest)
    compared = 0
    gap = collections.Counter()
    no_sink = [0]

    n = min(len(tinsns), len(ginsns))
    # In-order alignment with a PC-equality gate.  Both sides run the SAME
    # static, deterministic ELF, so the streams are identical up to the point
    # gem5 leaves the instruction trace; anything else is a real divergence
    # and stops the scoring rather than sliding the two apart silently.
    i = 0
    while i < n:
        t, g = tinsns[i], ginsns[i]
        if t.pc != g.pc:
            notes.append(
                '%s: streams diverge at index %d -- tracer pc=0x%x, '
                'reference pc=0x%x.  Scoring stops here; a slid alignment '
                'would attribute every later edge to the wrong instruction.'
                % (name, i, t.pc, g.pc))
            break
        i += 1
    aligned = i

    for k in range(aligned):
        t, g = tinsns[k], ginsns[k]
        compared += 1
        ident = '%s@0x%x' % (name, t.pc)

        # ---- axis 1: the source set
        #
        # THE TRACER'S SOURCE SET IS THE DECLARED OPERAND LIST, NOT THE UNION
        # OF THE MASKS.  The two are different objects and conflating them
        # manufactures defects: an instruction with no register destination
        # and no memory operand -- every conditional branch, every `jr` --
        # has NO SINK for a mask to route a source to, so its mask union is
        # empty while its declared source list names the compare operands.
        # Read through the masks alone, `bne r8, r9` came back as a tracer
        # that names no sources at all, and the first reading of this leg
        # reported eight MISSING-EDGE rows that were the harness's own.  The
        # masks state the ROUTING among declared sources; the declaration is
        # what states that they are read.
        tsrc = set(t.src_regs)
        gsrc = set(g.ext_srcs)
        if tsrc or gsrc:
            subj.note('dep-src-set', t)
            if tsrc != gsrc:
                rows.append(Row(name, t.pc, g.disas, 'dep-src-set', '-',
                                _fmt(gsrc), _fmt(tsrc),
                                _src_label(t, g, tsrc, gsrc, ref_vocab, ref_dst_vocab)))

        # ---- axis 2: the destination set
        tdst = {r for r in t.dst_deps if not r.startswith('UNRESOLVED')}
        gdst = set(g.arch_dsts)
        if tdst or gdst:
            subj.note('dep-dst-set', t)
            if tdst != gdst:
                rows.append(Row(name, t.pc, g.disas, 'dep-dst-set', '-',
                                _fmt(gdst), _fmt(tdst),
                                _src_label(t, g, tdst, gdst, ref_vocab, ref_dst_vocab)))

        # ---- axis 3: the per-destination closure
        for d in sorted(tdst & gdst):
            subj.note('dep-dst-closure', t)
            tc = {r for r in t.closure(d) if not r.startswith('UNRESOLVED')}
            gc = set(g.dst_closure.get(d, ()))
            if tc != gc:
                rows.append(Row(name, t.pc, g.disas, 'dep-dst-closure', d,
                                _fmt(gc), _fmt(tc),
                                _src_label(t, g, tc, gc, ref_vocab, ref_dst_vocab)))

        # ---- axis 5: every declared source must reach a sink
        #
        # Only asked where a SINK EXISTS.  An instruction with no register
        # destination and no memory operand has nothing for a mask to route
        # to, and charging it here would turn a structural fact about
        # branches into a defect count.  The exemption is counted, never
        # silent.
        sinks = (len(t.dst_deps) + len(t.sdata) + len(t.laddr) +
                 len(t.saddr))
        if sinks:
            routed = set()
            for d in t.dst_deps:
                routed |= t.closure(d)
            for grp in (t.sdata, t.laddr, t.saddr):
                for st in grp.values():
                    routed |= {e for e in st
                               if e != 'imm' and not e.startswith('ld')}
            for d in t.dst_deps:
                for e in t.dst_deps[d]:
                    if e.startswith('ld'):
                        routed |= {a for a in t.laddr.get(int(e[2:]), ())
                                   if a != 'imm'}
            for sreg in sorted(set(t.src_regs)):
                subj.note('dep-mask-coverage', t)
                if sreg not in routed:
                    rows.append(Row(name, t.pc, g.disas, 'dep-mask-coverage',
                                    sreg, 'DECLARED-SOURCE', 'ROUTED-NOWHERE',
                                    'ORPHANED-SOURCE-NOT-ROUTED'))
        else:
            no_sink[0] += 1

        # ---- axis 4: destination discrimination
        #
        # Only asked where the REFERENCE distinguishes: two destinations with
        # different closures.  Asking it anywhere else would score gem5's
        # decision to give both destinations one micro-op, which is
        # granularity and out of scope by ruling.
        common = sorted(tdst & gdst)
        if len(common) >= 2:
            gpairs = {(a, b) for a in common for b in common
                      if a < b and set(g.dst_closure.get(a, ())) !=
                      set(g.dst_closure.get(b, ()))}
            if gpairs:
                subj.note('dep-dst-discrimination', t, n=len(gpairs))
                for a, b in sorted(gpairs):
                    ta = {r for r in t.closure(a)
                          if not r.startswith('UNRESOLVED')}
                    tb = {r for r in t.closure(b)
                          if not r.startswith('UNRESOLVED')}
                    if ta == tb:
                        rows.append(Row(
                            name, t.pc, g.disas, 'dep-dst-discrimination',
                            '%s/%s' % (a, b),
                            'DISTINCT', 'FLATTENED-TO-' + _fmt(ta),
                            'FLATTENED-CHAIN'))

    # ---- the declared == compared identity
    for t in tinsns[aligned:]:
        if t.mnemonic in ('syscall', 'ecall', 'sc', 'int'):
            gap['REF-STOPPED-AT-GUEST-EXIT'] += 1
        else:
            gap['UNALIGNED-MID-STREAM'] += 1
    for _g in ginsns[aligned:]:
        gap['REF-BEYOND-TRACER-STREAM'] += 1
    if no_sink[0]:
        notes.append('%s: %d instructions have NO SINK (no register '
                     'destination, no memory operand), so dep-mask-coverage '
                     'is not asked of them -- branches and jumps.  Counted, '
                     'not silent.' % (name, no_sink[0]))
    return len(tinsns), compared, gap


def _saturated(t):
    """True when EVERY sink's mask names every declared source.

    That is the all-to-all default ``format.rst`` defines for an absent
    dependency block, and it is measured here rather than inferred from the
    absence of a wire block -- the renderer synthesizes the same masks either
    way, so the two are indistinguishable to a consumer and must be
    indistinguishable to this test.
    """
    if not t.dst_deps or not t.src_regs:
        return False
    want = set(t.src_regs)
    for d, elems in t.dst_deps.items():
        if not want <= {e for e in elems
                        if e != 'imm' and not e.startswith('ld')}:
            return False
    return True


def _src_label(t, g, tset, gset, ref_vocab, ref_dst_vocab=frozenset()):
    """The MECHANISM of a disagreement, MEASURED -- never read off a mnemonic.

    R8.7: a claim needs an observed decode or an observed run.  Every test
    below reads one of three measured things -- the two sets, the reference's
    own disassembly text for THIS instruction, or the vocabulary census of the
    WHOLE run.  None reads an opcode name out of a table.

    The census is what makes "the reference does not model this state" a
    measurement rather than an excuse: a register the reference never names
    once, anywhere, over every probe, is state it does not have.  A register
    it names elsewhere and omits here is a disagreement and stays one.
    """
    missing = gset - tset          # the reference names it, the map does not
    false = tset - gset            # the map names it, the reference never reads

    if 'unimplemented' in (g.disas or ''):
        return 'REF-UNIMPLEMENTED-INSN'
    if missing and any(m.startswith('MISC:') for m in missing):
        return 'VOCAB-NO-GENERIC-FOR-REF-MISC'
    if false and not missing:
        if false == {'REG_ZERO'} and 'REG_ZERO' not in ref_vocab:
            return 'REF-DROPS-REG-ZERO'
        if not (false & ref_vocab):
            return 'REF-MODELS-NO-SUCH-STATE'
        if false <= FP_STATUS and not (
                (set(g.ext_srcs) | set(g.arch_dsts)) & FP_STATUS):
            return 'REF-NO-FP-STATUS-ON-ARITH'
        if false == ACC_PAIR:
            return 'TRACER-NAMES-ACC-PAIR'
        # LAYERED EXPLANATION.  A row can carry two mechanisms at once -- the
        # riscv64 vector rows carry a register the reference does not model
        # AND the saturated default -- and collapsing them onto whichever
        # test fired first would leave one of the two invisible.  So the part
        # the reference cannot model is REMOVED, and the RESIDUE is labelled.
        residue = false & ref_vocab
        if not residue:
            return 'REF-MODELS-NO-SUCH-STATE'
        if 'REG_VCTRL' in false and 'REG_VCTRL' not in ref_vocab and \
                residue <= set(t.dst_regs):
            return 'REF-NO-VECTOR-CONTROL-DEP+TRACER-SATURATED-DEFAULT'
        if residue <= set(t.dst_regs) and _saturated(t):
            return 'TRACER-SATURATED-DEFAULT'
        return 'FALSE-EDGE'
    if missing and not false:
        if ref_dst_vocab and not (missing & ref_dst_vocab):
            return 'REF-SOURCE-IS-NEVER-WRITTEN'
        # DECLARED BUT UNROUTED is a different defect from ABSENT, and the
        # difference is the whole point: the register is in the wire's operand
        # list, so the tracer SAW it; what is missing is the edge.
        if missing <= set(t.src_regs):
            return 'ORPHANED-SOURCE-NOT-ROUTED'
        return 'MISSING-EDGE'
    return 'ORTHOGONAL-EDGES'


# ------------------------------------------------------------------ report
def _unfmt(txt):
    """The inverse of ``_fmt`` for a rendered set; anything else is opaque."""
    if txt.startswith('{') and txt.endswith('}'):
        return {x for x in txt[1:-1].split(',') if x}
    return {txt}


def report(fh, isa, subj, rows, identity, notes, ref_notes, uop_census):
    fh.write('ARC 3 -- intra-instruction DEPENDENCY leg, %s, against gem5\n'
             % isa)
    fh.write('=' * 72 + '\n\n')

    fh.write('AXES -- facts and distinct subjects\n')
    inert = []
    for a in AXES:
        f = subj.facts.get(a, 0)
        s = len(subj.enc.get(a, ()))
        mark = ' [SELF -- no reference side]' if a in SELF_AXES else ''
        if f == 0:
            mark += '   INERT  <- compared nothing; this is a demand for a ' \
                    'better probe, never a pass'
            inert.append(a)
        fh.write('  %-26s facts=%-8d subjects=%-6d%s\n' % (a, f, s, mark))
    fh.write('\n')

    # THE MICRO-OP CENSUS IS PRINTED, AND IT IS NOT AN AXIS.
    #
    # gem5's decomposition is its implementation choice and is never scored.
    # It is printed because it is the MEASUREMENT that explains what
    # dep-dst-discrimination can and cannot reach: that axis asks whether the
    # map flattens a chain the reference resolves, and a reference that emits
    # one micro-op per instruction resolves no chain to flatten.  Printing the
    # census turns "INERT, get a better probe" into a statement about the
    # reference, which is what it is.
    fh.write('REFERENCE MICRO-OP CENSUS (never scored -- granularity)\n')
    for k in sorted(uop_census):
        fh.write('  %d micro-op(s) per instruction: %d instructions\n'
                 % (k, uop_census[k]))
    if set(uop_census) <= {1}:
        fh.write('  THE REFERENCE CRACKS NOTHING ON THIS ISA.  Every macro-op\n'
                 '  is one micro-op, so every destination of an instruction\n'
                 '  necessarily has the SAME source closure and the reference\n'
                 '  distinguishes no two destinations.  dep-dst-discrimination\n'
                 '  is therefore INERT BY CONSTRUCTION here: it is a limit of\n'
                 '  the reference, not a gap in the probe, and no probe on this\n'
                 '  ISA can make it fire.\n')
    fh.write('\n')

    bad = [r for r in rows]
    fh.write('DISAGREEING ROWS: %d  (of which %d are self-axis)\n\n'
             % (len(bad), sum(1 for r in bad if r.axis in SELF_AXES)))

    # DIRECTION IS MEASURED FROM THE TWO SETS AND CATEGORY COMES FROM THE
    # RULE; neither is read off the label.  A row whose rule does not admit
    # its measured relation is reported as a CONFLICT rather than quietly
    # re-labelled -- that is the allowlist-false-justification class.
    # A SELF AXIS HAS NO DIRECTION AND IS NOT PUT THROUGH THE CROSS-TAB.
    # `dep-mask-coverage` compares the wire against itself, so there is no
    # reference set to be a superset or a subset of; forcing its rows through
    # `set_relation` measured them as ORTHOGONAL and then reported the rule as
    # conflicting with its own rows.  They are reported in their own section
    # with their own count.
    selfrows = [r for r in bad if r.axis in SELF_AXES]
    bad = [r for r in bad if r.axis not in SELF_AXES]

    trows = []
    for r in bad:
        ref, trc = _unfmt(r.ref), _unfmt(r.trc)
        rel = tax.set_relation(ref, (), trc, ())
        if rel is tax.EQUAL:
            rel = tax.ORTHOGONAL
        trows.append(tax.classify('%s@0x%x' % (r.guest, r.pc), r.mnemonic,
                                  r.label, rel, rule_for(r.label)))
    fh.write(tax.render_crosstab(trows, 'direction x mechanism'))
    fh.write('\n')
    conf = tax.render_conflicts(trows)
    if conf:
        fh.write(conf)
        fh.write('\n')

    by_label = collections.Counter(r.label for r in bad)
    for lab, n in by_label.most_common():
        rule = rule_for(lab)
        fh.write('  %-34s %5d   %-20s %s\n'
                 % (lab, n, rule.category if rule else 'UNACCOUNTED',
                    'ACCOUNTS' if (rule and rule.accounts) else
                    ('NAMED, NOT RULED' if rule
                     else 'must be adjudicated')))
    fh.write('\n')

    for r in bad[:80]:
        fh.write('  %-22s %-26s %s\n'
                 '      ref=%s\n      trc=%s\n'
                 % ('%s@0x%x' % (r.guest, r.pc), r.axis + ':' + r.subject,
                    r.mnemonic, r.ref, r.trc))
    if len(bad) > 80:
        fh.write('  ... %d more (see the TSV)\n' % (len(bad) - 80))
    fh.write('\n')

    if selfrows:
        fh.write('SELF-AXIS ROWS (no reference side; the wire against '
                 'itself): %d\n' % len(selfrows))
        for r in selfrows:
            fh.write('  %-22s %-24s %-14s %s\n'
                     % ('%s@0x%x' % (r.guest, r.pc), r.mnemonic, r.subject,
                        r.label))
        fh.write('\n')

    fh.write('THE DECLARED == COMPARED IDENTITY\n')
    tot_d = tot_c = 0
    allgap = collections.Counter()
    for guest, d, c, gp in identity:
        tot_d += d
        tot_c += c
        allgap.update(gp)
        fh.write('  %-14s declared=%-6d compared=%-6d gap=%d\n'
                 % (guest, d, c, d - c))
    fh.write('  %-14s declared=%-6d compared=%-6d gap=%d\n'
             % ('TOTAL', tot_d, tot_c, tot_d - tot_c))
    for k, v in sorted(allgap.items()):
        fh.write('      %-30s %d\n' % (k, v))
    accounted = sum(v for k, v in allgap.items()
                    if k != 'UNALIGNED-MID-STREAM'
                    and k != 'REF-BEYOND-TRACER-STREAM')
    unacc = (tot_d - tot_c) - accounted
    fh.write('      %-30s %d   MUST BE 0\n' % ('UNACCOUNTED', unacc))
    fh.write('\n')

    if ref_notes or notes:
        fh.write('NOTES\n')
        for n in list(ref_notes) + list(notes):
            fh.write('  * %s\n' % n)
        fh.write('\n')
    return inert, unacc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument('--isa', required=True, choices=('riscv64', 'mipsel'))
    ap.add_argument('--gem5-dir', required=True)
    ap.add_argument('--qemu-dir', required=True)
    ap.add_argument('--decode', required=True)
    ap.add_argument('-o', '--outdir', required=True)
    ap.add_argument('--tsv')
    ap.add_argument('--python-home')
    ap.add_argument('guests', nargs='+')
    args = ap.parse_args(argv)

    os.makedirs(args.outdir, exist_ok=True)
    try:
        binary, cfg, env, pnotes = cex.gem5_prereqs(
            args.gem5_dir, args.isa, args.outdir,
            python_home=args.python_home)
    except gem5_env.MissingPrerequisite as e:
        sys.stderr.write('%s\n' % e)
        return 3
    with open(os.path.join(args.outdir, 'PREREQ.txt'), 'w') as fh:
        fh.write('\n'.join(pnotes) + '\n')

    subj = axis_subjects.Subjects()
    rows, identity, notes, refnotes = [], [], [], []
    ref_vocab, ref_dst_vocab, pending, uop_census = set(), set(), [], {}

    for guest in args.guests:
        try:
            log = cex.run_gem5(binary, cfg, env, args.isa, guest, args.outdir)
        except (gem5_env.MissingPrerequisite, RuntimeError) as e:
            sys.stderr.write('REFUSED on %s: %s\n' % (guest, e))
            return 3
        trace = cex.run_tracer(args.qemu_dir, args.isa, guest, args.outdir)

        ranges = gem5_ref.exec_ranges(guest)
        g, gn = dep_ref_gem5.parse(log, args.isa, ranges=ranges,
                                   gem5_dir=args.gem5_dir)
        t, _v, tn = dep_map.parse(args.decode, trace)
        refnotes += ['%s: %s' % (os.path.basename(guest), x)
                     for x in gn + tn]
        vocab = set()
        for x in g:
            vocab |= set(x.ext_srcs) | set(x.arch_dsts)
            ref_dst_vocab |= set(x.arch_dsts)
        ref_vocab |= vocab
        for x in g:
            uop_census[x.uops] = uop_census.get(x.uops, 0) + 1
        pending.append((guest, t, g))
    # THE VOCABULARY CENSUS IS TAKEN OVER EVERY PROBE BEFORE ANYTHING IS
    # SCORED.  "The reference never models this register" is a claim about the
    # whole run; deciding it per guest would call a register unmodelled on the
    # integer probe because only the FP probe touches it.
    for guest, t, g in pending:
        d, c, gp = score_guest(guest, t, g, subj, rows, notes, ref_vocab,
                               ref_dst_vocab)
        identity.append((os.path.basename(guest), d, c, gp))

    rpt = os.path.join(args.outdir, 'REPORT.txt')
    with open(rpt, 'w') as fh:
        inert, unacc = report(fh, args.isa, subj, rows, identity,
                              notes, refnotes, uop_census)
    sys.stdout.write(open(rpt).read())

    if args.tsv:
        with open(args.tsv, 'w') as fh:
            fh.write('guest\tpc\taxis\tsubject\tref\ttrc\tlabel\tmnemonic\n')
            for r in sorted(rows, key=lambda x: (x.guest, x.pc, x.axis,
                                                 x.subject)):
                fh.write('%s\t0x%x\t%s\t%s\t%s\t%s\t%s\t%s\n'
                         % (r.guest, r.pc, r.axis, r.subject, r.ref, r.trc,
                            r.label, r.mnemonic))

    if inert:
        return 2
    if rows or unacc:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
