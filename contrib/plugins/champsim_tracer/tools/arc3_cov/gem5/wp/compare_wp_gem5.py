"""
ARC 3 -- x86_64 WRONG-PATH execution cross-check: the tracer against gem5.

NO WP GOLDEN EXISTS ON ANY ISA.  Every gate this project runs compares correct
path against correct path, so a wrong-path divergence has been invisible for
the whole arc -- and on x86_64 the wrong-path arm is the largest fraction of
what the tracer emits.  The PIN reference this project uses elsewhere is
explicitly NOT an execution reference for the wrong path: PIN observes what the
machine really retired, and a wrong-path excursion is by construction a path
the machine did not take.

This leg closes that hole the way the riscv64 leg did, with gem5 in the
reference seat:

    trace ---> reconstructed regfile + memory ---> injected static ELF
                                                        |
                                                    gem5 X86 SE
                                                        |
    the tracer's WP record  <---- compared against ---- what the ISA does

THE THREE VERDICTS, AND WHY THEY MUST NOT BE BLURRED
====================================================
  WP-DEFECT           the excursion executed something the architecture would
                      not, from a starting state the trace fully specified.
                      A tracer bug.
  RECONSTRUCTION-GAP  the trace does not carry enough state to rebuild the
                      starting point, so the two runs began from different
                      machines.  A finding about what the WIRE drops.
  GEM5-LIMIT          the reference cannot state the fact.  Named one by one,
                      with the observed text, and never counted as agreement.

plus TRACER-SUPERSET, which is COVERED -- each row carries a NAMED rule from
``x86_exec_rules.X86_EXEC`` saying why the reference cannot state the fact --
and UNACCOUNTED, which must be 0.

The gap verdict is assigned from EVIDENCE, never from plausibility: a register
is a gap only where the ``wp-entry-state`` axis measures the reconstruction
wrong against the correct-path run's own ground truth, and an address only
where no ELF byte, no correct-path load datum and no correct-path store datum
ever established it.

THE DECLARED/COMPARED IDENTITY
==============================
Every wrong-path instruction the tracer declared is either COMPARED or sits in
a NAMED tail, and the report asserts

    sum of uncompared tails  ==  declared - compared

so a declared-versus-compared gap can never sit unexplained.  The riscv64
leg's 287 was exactly the tails of its named reference-limit rows; this leg
asserts it rather than leaving it to be rediscovered.

Author: Maccoy Merrell.
"""
import argparse
import collections
import difflib
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_COV = os.path.abspath(os.path.join(_HERE, '..', '..'))
for _p in (_HERE, _COV, os.path.join(_COV, 'gem5'),
           os.path.join(_COV, 'x86_64'),
           os.path.join(_COV, 'riscv64', 'spike', 'wp')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import elfimage                                              # noqa: E402
import wp_trace                                              # noqa: E402
import qemu_preserve_oracle as QPO                           # noqa: E402
import x87_cw_derive as X87D                                 # noqa: E402
import wp_seed_x86                                           # noqa: E402
import gem5_wp_ref                                           # noqa: E402
import gem5_env                                              # noqa: E402
import x86_vocab as V                                        # noqa: E402
from x86_exec_rules import x86_exec_rule                     # noqa: E402
from arc3_taxonomy import set_relation, EQUAL, SUPERSET, SUBSET  # noqa: E402
from axis_subjects import Subjects                           # noqa: E402

#: every fact this leg checks about a wrong-path instruction.  Named in full
#: so a report can never quote a subset as if it were the whole comparison.
AXES = ('pc-sequence', 'insn-length', 'reg-dst-set', 'reg-dst-value',
        'reg-src-set', 'memop-count', 'memop-addr', 'memop-width',
        'load-data', 'store-data')

WP_DEFECT = 'WP-DEFECT'
RECON_GAP = 'RECONSTRUCTION-GAP'
GEM5_LIMIT = 'GEM5-LIMIT'
SUPERSET_OK = 'TRACER-SUPERSET'
#: the SUBSET-direction counterpart: the REFERENCE states a fact the
#: architecture does not, and a named rule says why.  Kept apart from
#: TRACER-SUPERSET because the two are opposite directions and a report that
#: spelled a reference artefact as a tracer superset would misname it.
REF_SIDE = 'REFERENCE-SIDE'
UNACCOUNTED = 'UNACCOUNTED'
VERDICTS = (WP_DEFECT, RECON_GAP, GEM5_LIMIT, SUPERSET_OK, REF_SIDE,
            UNACCOUNTED)

Row = collections.namedtuple(
    'Row', 'guest seq idx pc axis verdict ref trc detail')

#: the tracer ids no gem5 register can ever match, because gem5 models the
#: state somewhere that is not a register operand.  Named here so that their
#: appearance in a tracer set is adjudicated by RULE and not by a guess.
_RIP = 'REG_IP'
_SEGS = frozenset('REG_SEG%d' % i for i in range(6))
_SYSCALL_BYTES = 0x050f          # `0f 05`, little-endian in the tracer's word

#: gem5's x87 file is backed by a 64-bit double, not the 80-bit architectural
#: encoding: its FLD80 lowering is `ld t1 ; ld t2w ; cvtint_fp80`.  Measured on
#: a plain load, the tracer's 80-bit 0xc050edd2f552d6407d98 and gem5's 64-bit
#: 0xc50dba5eaa5ac813 are the SAME number -- exponent 0x4050-16383+1023 = 0x450
#: and the mantissa is the 80-bit significand's top 52 bits after the explicit
#: leading one.  ``x87_is_rounded`` proves that correspondence per row, so the
#: limit is confirmed by measurement rather than asserted.
_X87_VALUE_LIMIT = 'REF-X87-DOUBLE-BACKED'
#: REG_FCSR is a fold on BOTH sides -- the tracer folds the x87 status word,
#: MXCSR and the tag word onto one id, gem5 keeps Fcw/Fsw/Ftw/X87Top/Mxcsr
#: apart -- so a VALUE comparison on it compares two different registers.
_FCSR_VALUE_LIMIT = 'FCSR-FOLD-NOT-COMPARABLE'


def x87_to_double(v80):
    """An 80-bit x87 encoding -> the IEEE-754 double bit pattern, or None.

    Used to CHECK that a reference/tracer x87 disagreement really is gem5's
    double backing and nothing else.  Subnormal, infinite and NaN forms
    return None: the correspondence this function demonstrates is the normal
    one, and claiming it where it does not hold would be the same
    plausibility-over-evidence error the taxonomy exists to prevent.
    """
    sign = (v80 >> 79) & 1
    exp = (v80 >> 64) & 0x7fff
    sig = v80 & ((1 << 64) - 1)
    if exp == 0 or exp == 0x7fff or not (sig >> 63):
        return None
    e = exp - 16383 + 1023
    if not (0 < e < 0x7ff):
        return None
    frac = (sig & ((1 << 63) - 1)) >> 11
    return (sign << 63) | (e << 52) | frac


def x87_is_rounded(v80, v64):
    """True when ``v64`` is ``v80`` rounded to a double, either way."""
    d = x87_to_double(v80)
    if d is None:
        return False
    return d == v64 or abs(d - v64) <= 1


# ---------------------------------------------------------------- the oracle
#
# REF-PRESERVE-READ-OVERNAMED cannot be decided from gem5's text alone.  A
# narrow write whose destination gem5 names in the slot it preserves is
# spelled IDENTICALLY for `setz %al`, whose destination R7.1 rules is not a
# source, and for `add %al, %bl`, whose destination the maintainer ruled IS
# one: "an instruction can have a register as both a source and destination,
# and that is perfectly valid (for example, an in-place ADD that doubles the
# quantity of a single register)".  The instruction's OWN SEMANTICS separate
# them and QEMU is the ground truth for those, so the rule is gated on
# ``qemu_preserve_oracle``: the translation either reads the destination into
# the computation or it only merges it back.
#
# A row the oracle will not answer is REFUSED, never excused.  Without a
# wired oracle every SUBSET row is refused, which is why nothing here falls
# back to gem5 alone.
ORACLE = None

# THE FALSIFICATION ARM.  Set False to restore the rule to what it was before
# the gate existed -- gem5's text alone -- so that the injection control can
# demonstrate the gate is LOAD-BEARING rather than decorative.  A rule whose
# blind spot cannot be shown closed is still open, and the only way to show
# it is to run the same injection with the gate off and watch the leg forgive
# it.  This is a measurement arm, never a mode to measure in.
GATE = True


#: THE x87 TOP GATE.  Its subject is the SOURCE-axis REG_FCSR the tracer
#: names on every form that reads the top of the x87 stack, and gem5's
#: silence about it is the same text whether the tracer is right or wrong:
#: gem5 flattens `%st(0)` to a physical index at DECODE
#: (src/arch/x86/regs/float.cc, `fpr((X87Top + (idx - NumRegs)) % 8)`), so a
#: resolved operand carries no TOP source to compare against.  That the read
#: is real therefore comes from QEMU or from nowhere -- ST0 expands to
#: `env->fpregs[env->fpstt].d` and the read is in the macro, not in the
#: helper's text.  Without a wired gate every such row is REFUSED, exactly
#: as the preserve gate refuses.
X87 = None
X87_GATE = True


def set_oracle(o):
    global ORACLE
    ORACLE = o


def set_x87(o):
    global X87
    X87 = o


def _x87_top_label(enc):
    """The SOURCE-axis label for a tracer-only REG_FCSR, decided by QEMU.

    Three outcomes and they must stay three.  A refusal is not a conviction
    and a conviction is not a refusal; the report has to say which.
    """
    if not X87_GATE:
        return 'REF-X87-TOP-FOLDED-AT-DECODE'
    if X87 is None or enc is None:
        return 'REF-X87-TOP-UNDECIDED'
    v = X87.reads_status(enc)
    if v is True:
        return 'REF-X87-TOP-FOLDED-AT-DECODE'
    if v is False:
        return 'TRACER-X87-TOP-NOT-READ'
    return 'REF-X87-TOP-UNDECIDED'


def _superset_families(side, enc):
    """[(does this register belong to the family, label)], for a SUPERSET.

    PEELED FAMILY BY FAMILY rather than matched as one set.  A row whose
    surplus is {REG_FCSR, REG_FPCW} carries TWO independent reference gaps --
    gem5 resolves the stack slot at decode and names no TOP source, and its
    x87 lowering carries no control-word operand at all -- and an
    `elif rest == {...}` chain reaches neither, so the row reported
    UNACCOUNTED with an EMPTY label: "the rules do not reach this" when in
    fact two of them did.  Each entry removes only its own members; the row
    accounts when the surplus EMPTIES and every named rule accounts on its
    own.  None of these families overlap, so the order is not load-bearing.

    REG_FCSR is TWO different gaps depending on the axis, which is why
    `side` is consulted rather than one label serving both.  On the
    DESTINATION axis it is gem5 publishing an x87 status-word write for
    `fabs` and not for `fadd`.  On the SOURCE axis it is the read of TOP.
    Calling both by the destination's name would put a measurement behind a
    note that does not describe it.
    """
    return [
        (lambda n: n == _RIP, 'REF-NO-RIP-OPERAND'),
        (lambda n: n in _SEGS, 'REF-SEG-EFF-BASE-ONLY'),
        (lambda n: n == 'REG_FLAGS', 'REF-FLAGS-PARTIAL'),
        (lambda n: n.startswith('REG_VEC'), 'REF-XMM-HALF-ONLY'),
        (lambda n: n.startswith('REG_FPR'), 'REF-X87-CONVERTED'),
        (lambda n: n == 'REG_FCSR',
         _x87_top_label(enc) if side == 'src'
         else 'REF-X87-STATUS-NOT-PUBLISHED'),
        (lambda n: n == 'REG_FPCW', 'REF-NO-X87-CONTROL-OPERAND'),
    ]


def _oracle_verdict(enc, surplus):
    """(encoding hex, the registers gem5 named and the tracer did not)
    -> 'preserve' | 'arch' | None (refused)."""
    if not GATE:
        return QPO.PRESERVE
    if ORACLE is None or enc is None:
        return None
    seen = set()
    for r in surplus:
        v = ORACLE.ask(enc, r)
        if v is None:
            return None
        seen.add(v)
    if QPO.ARCH in seen:
        return QPO.ARCH
    return QPO.PRESERVE


def _enc(t):
    """A tracer instruction -> its encoding as lowercase hex, or None.

    The oracle is keyed on the ENCODING and not on the PC: the same bytes
    have the same TCG lowering wherever they sit, and a PC key would answer
    from a DIFFERENT instruction if a wrong-path walk ever decoded at an
    offset the correct path never took.
    """
    try:
        return t.bits.to_bytes(t.nbytes, 'little').hex()
    except (AttributeError, OverflowError, ValueError):
        return None


def adjudicate(rel, only_ref, only_trc, side, preserve=frozenset(), enc=None):
    """(measured direction, the surplus/deficit sets) -> (verdict, label).

    The direction is MEASURED by ``set_relation`` before any label is
    consulted; the label only explains a direction that was already
    established.  A direction with no rule is UNACCOUNTED and says so.

    ``preserve`` is the set of registers gem5 read back ONLY to keep the bits
    its own narrow write does not produce, measured per row from gem5's
    operand text and slot positions (``gem5_wp_ref.Insn.preserve_reads``).
    Under R7.1 those are not sources, so a SUBSET made up entirely of them is
    the REFERENCE over-naming and not a tracer defect.
    """
    label, labels = None, []
    if rel == SUPERSET:
        rest = set(only_trc)
        for match, lab in _superset_families(side, enc):
            hit = {n for n in rest if match(n)}
            if hit:
                labels.append(lab)
                rest -= hit
        if rest:
            labels = []             # something the rules do not reach
        label = ' + '.join(labels) if labels else None
    elif rel == SUBSET:
        surplus = set(only_ref)
        if surplus and surplus <= set(preserve):
            # gem5 SAYS preserve-read.  QEMU decides whether it is one.
            v = _oracle_verdict(enc, surplus)
            if v == QPO.PRESERVE:
                label = 'REF-PRESERVE-READ-OVERNAMED'
            elif v == QPO.ARCH:
                label = 'TRACER-DROPPED-RMW-SOURCE'
            else:
                label = 'REF-PRESERVE-READ-UNDECIDED'
        else:
            label = 'REF-ONLY-UNEXPLAINED'
    # A SUPERSET row may carry several families, and it accounts only when
    # EVERY named rule accounts on its own and expects the direction that was
    # measured.  One refusing or convicting family is enough to hold the
    # whole row open -- an accounted family cannot pay for an unaccounted one.
    named = labels if labels else ([label] if label else [])
    rules = [x86_exec_rule(n) for n in named]
    if rules and all(r is not None and rel in r.expect and r.accounts
                     for r in rules):
        return (REF_SIDE if rel == SUBSET else SUPERSET_OK), label
    if any(n in ('REF-PRESERVE-READ-UNDECIDED', 'REF-X87-TOP-UNDECIDED')
           for n in named):
        # A REFUSAL is not a conviction.  The rule declined to adjudicate the
        # row, and calling that a tracer defect would be as wrong as calling
        # it agreement -- it counts against the leg either way, but the
        # report must say WHICH.
        return UNACCOUNTED, label
    if rel == SUBSET:
        return WP_DEFECT, label
    return UNACCOUNTED, label


# ------------------------------------------------------------------ the runs
def run_tracer(qemu, plugin, guest, out, wpdepth, compress=None):
    trace = out + '.cst'
    opt = ('%s,outfile=%s,memdata=1,regdata=1,wpdepth=%d'
           % (plugin, out, wpdepth))
    if compress:
        opt += ',compress=%s' % compress
    p = subprocess.run([qemu, '-plugin', opt, guest],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        raise RuntimeError('qemu exit %d: %s'
                           % (p.returncode,
                              p.stdout.decode('utf-8', 'replace')[-800:]))
    if not os.path.exists(trace):
        raise RuntimeError('tracer produced no %s' % trace)
    return trace


def guest_ranges(xr):
    def sel(pc):
        return any(lo <= pc < hi for lo, hi in xr)
    return sel


# ------------------------------------------------------- entry-state truth
def ground_truth(insns, entry_flags=None):
    """Per index, the register file the CORRECT-PATH reference actually held.

    ``snaps[i]`` is {generic id: value} for the state BEFORE reference
    instruction ``i``, built from gem5's own writes.  Unlike Spike, gem5's log
    names a register READ but never prints its value, so a register the
    reference never WROTE is simply absent -- and absence is reported as "the
    reference cannot say", never as agreement.
    """
    cur = {}
    snaps = []
    word = (entry_flags or 0) & V.RFLAGS_MASK
    have_flags = entry_flags is not None
    for ins in insns:
        snaps.append(dict(cur))
        for g, val in ins.writes.items():
            if val is None:
                continue
            cur[g] = val
        if ins.cc:
            w, m = V.rflags_from_cc(ins.cc)
            word = (word & ~m) | (w & m)
            have_flags = True
        if have_flags:
            cur['REG_FLAGS'] = word
    snaps.append(dict(cur))
    return snaps


def align(ref, trc):
    """Index-preserving alignment of two instruction streams, keyed on PC.

    gem5's log carries no encoding, so the PC is the whole key.  Deletions on
    the reference side are carried through as ``None`` rather than collapsed:
    the reference is silent about an instruction it did not retire, and an
    alignment that hid that would make the silence look like a tracer
    invention.
    """
    rk = [i.pc for i in ref]
    tk = [i.pc for i in trc]
    sm = difflib.SequenceMatcher(a=rk, b=tk, autojunk=False)
    out = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            for k in range(i2 - i1):
                out.append((i1 + k, j1 + k))
        else:
            for k in range(i1, i2):
                out.append((k, None))
            for k in range(j1, j2):
                out.append((None, k))
    return out


def entry_state_rows(guest, ex, truth, reg_gaps):
    """Score the RECONSTRUCTED entry state against the correct-path truth.

    This is the axis that makes the gap attribution evidence rather than
    plausibility.  A register the reference never wrote is absent from
    ``truth`` and counted apart: the reference cannot say, so nobody may call
    it an agreement.
    """
    rows, stats = [], collections.Counter()
    sub = Subjects()
    for name, (val, w) in sorted(ex.regs.items()):
        if V.install_class(name) is None:
            stats['tracer-only-id'] += 1
            continue
        if name not in truth:
            stats['reference-silent'] += 1
            continue
        if name == 'REG_FLAGS':
            mask = V.RFLAGS_MASK
        elif w and 0 < w <= 16:
            mask = (1 << (8 * w)) - 1
        else:
            mask = (1 << 64) - 1
        sub.note('wp-entry-state')
        if (truth[name] & mask) != (val & mask):
            stats['wrong'] += 1
            reg_gaps.add(name)
            rows.append(Row(guest, ex.seq, -1, ex.start_pc, 'wp-entry-state',
                            RECON_GAP, '%s=0x%x' % (name, truth[name]),
                            '%s=0x%x' % (name, val),
                            'reconstructed from REGFILE seed + DST snapshots'))
        else:
            stats['agree'] += 1
    for name in truth:
        if name not in ex.regs and V.install_class(name) is not None:
            stats['not-reconstructed'] += 1
            reg_gaps.add(name)
            rows.append(Row(guest, ex.seq, -1, ex.start_pc, 'wp-entry-state',
                            RECON_GAP, '%s=0x%x' % (name, truth[name]),
                            'ABSENT', 'the wire never stated this register'))
    return rows, stats, sub


# -------------------------------------------------------------- comparison
def trc_writes(ins):
    """{generic id: value} for one tracer instruction."""
    out = {}
    for name, val, w in ins.writes:
        out[name] = val
    return out


def compare_excursion(guest, ex, ref, gapinfo, run_note):
    """One excursion vs the reference run of the same state.

    -> (rows, compared, tail_reason).  ``compared`` is the number of positions
    actually scored and ``tail_reason`` names why the rest were not, so the
    caller can assert the declared/compared identity.
    """
    rows = []
    sub = Subjects()
    reg_gaps = gapinfo['reg_gaps']
    unestablished = gapinfo['unestablished']
    declared = len(ex.insns)
    n = min(declared, len(ref))
    tail_reason = None

    # --- pc-sequence.  The whole excursion, in order, is one fact.
    ref_pcs = [i.pc for i in ref[:declared]]
    trc_pcs = [i.pc for i in ex.insns]
    k = 0
    while k < min(len(ref_pcs), len(trc_pcs)) and ref_pcs[k] == trc_pcs[k]:
        k += 1
    if k < min(len(ref_pcs), len(trc_pcs)):
        verdict = RECON_GAP if reg_gaps else WP_DEFECT
        rows.append(Row(guest, ex.seq, k, trc_pcs[k], 'pc-sequence', verdict,
                        ['0x%x' % p for p in ref_pcs],
                        ['0x%x' % p for p in trc_pcs],
                        'first divergence at index %d; reconstruction gaps: %s'
                        % (k, ','.join(sorted(reg_gaps)) or 'none')))
        tail_reason = 'PC-DIVERGENCE'
        n = k
    elif len(ref_pcs) < declared:
        # The reference stopped early.  WHY it stopped is the tail's name, and
        # it is taken from the run rather than assumed.
        nxt = ex.insns[len(ref_pcs)]
        if nxt.bits & 0xffff == _SYSCALL_BYTES:
            tail_reason = 'REF-SYSCALL-NOT-RETIRED'
        elif run_note:
            tail_reason = 'GEM5-STOP:' + run_note
        else:
            tail_reason = 'GEM5-STOP:reference retired nothing further'
        rows.append(Row(guest, ex.seq, len(ref_pcs), nxt.pc, 'pc-sequence',
                        GEM5_LIMIT, '%d insns' % len(ref_pcs),
                        '%d insns' % declared, tail_reason))
        n = len(ref_pcs)

    sub.note('pc-sequence')
    for i in range(n):
        r, t = ref[i], ex.insns[i]

        sub.note('insn-length', t)
        # --- insn-length.  gem5 prints no encoding, so the equivalent fact on
        # a variable-length ISA is where the instruction ENDS.  A length the
        # reference could not derive is named, never counted as agreement.
        if r.length is None:
            rows.append(Row(guest, ex.seq, i, t.pc, 'insn-length', GEM5_LIMIT,
                            'unknown', t.nbytes,
                            'no rdip fall-through and no sequential successor'))
        elif r.length != t.nbytes:
            rows.append(Row(guest, ex.seq, i, t.pc, 'insn-length', WP_DEFECT,
                            r.length, t.nbytes, 'decoders disagree on the '
                            'instruction boundary'))

        rw, tw = r.writes, trc_writes(t)
        sub.note('reg-dst-set', t)
        if frozenset(rw) != frozenset(tw):
            rel = set_relation((), sorted(rw), (), sorted(tw))
            if rel != EQUAL:
                v, lab = adjudicate(rel, frozenset(rw) - frozenset(tw),
                                    frozenset(tw) - frozenset(rw), 'dst',
                                    enc=_enc(t))
                rows.append(Row(guest, ex.seq, i, t.pc, 'reg-dst-set',
                                v, sorted(rw), sorted(tw),
                                '%s %s' % (rel, lab or '')))
        for kk in frozenset(rw) & frozenset(tw):
            rv = rw[kk]
            if rv is None:
                continue            # named by the reference, not valued
            sub.note('reg-dst-value', t)
            tv = tw[kk]
            if kk == 'REG_FCSR':
                rows.append(Row(guest, ex.seq, i, t.pc, 'reg-dst-value',
                                GEM5_LIMIT, '%s=0x%x' % (kk, rv),
                                '%s=0x%x' % (kk, tv), _FCSR_VALUE_LIMIT))
                continue
            if kk.startswith('REG_FPR') and rv != tv:
                # An x87 value is only round-trip CONFIRMABLE where nothing
                # but the load stood between the wire and the register.  Once
                # an x87 ARITHMETIC instruction has run, gem5 computed the
                # whole chain in double and the result is not the 80-bit one
                # rounded -- it is a different number, and saying "rounding
                # confirmed: NO" of it would read as an unexplained row when
                # the explanation is the same named limit one step earlier.
                arith = any(n.startswith('REG_FPR') for n in t.srcs)
                if arith:
                    note = ('%s: an x87 ARITHMETIC result, computed by gem5 '
                            'in double throughout; not round-trip '
                            'confirmable by construction' % _X87_VALUE_LIMIT)
                elif x87_is_rounded(tv, rv):
                    note = ('%s: CONFIRMED on this row -- the wire\'s 80-bit '
                            'datum IS this 64-bit one rounded' %
                            _X87_VALUE_LIMIT)
                elif r.ufp is not None and x87_is_rounded(tv, r.ufp):
                    # The reference disagrees WITH ITSELF: the load micro-op
                    # published the converted datum into its FP scratch and
                    # the destination write published something else.
                    # Measured on `flds` (FLD m32): `ldfp87 %ufp1` prints
                    # 0x41da678a80000000, which IS the wire's 80-bit datum
                    # rounded, and `movfp %st(7), %ufp1` then publishes
                    # 0x80000000 -- the raw four bytes from memory, not the
                    # register's value.  The tracer is right; gem5's
                    # destination publication is the outlier.
                    note = ('REF-X87-DEST-PUBLISHES-RAW: gem5\'s own load '
                            'micro-op published 0x%x, which IS the wire\'s '
                            '80-bit datum rounded; its destination write '
                            'published something else' % r.ufp)
                else:
                    note = ('%s: NOT confirmed and NOT an arithmetic result '
                            '-- interrogate this row' % _X87_VALUE_LIMIT)
                rows.append(Row(guest, ex.seq, i, t.pc, 'reg-dst-value',
                                GEM5_LIMIT, '%s=0x%x' % (kk, rv),
                                '%s=0x%x' % (kk, tv), note))
                continue
            if kk == 'REG_FLAGS':
                if r.rflags is None:
                    continue
                m = V.RFLAGS_MASK & r.rflags_mask
                rv, tv = r.rflags & m, tv & m
            if rv != tv:
                rows.append(Row(guest, ex.seq, i, t.pc, 'reg-dst-value',
                                RECON_GAP if kk in reg_gaps else WP_DEFECT,
                                '%s=0x%x' % (kk, rv), '%s=0x%x' % (kk, tv),
                                ''))

        rs, ts = r.srcs, frozenset(t.srcs)
        sub.note('reg-src-set', t)
        if rs != ts:
            rel = set_relation((), sorted(rs), (), sorted(ts))
            if rel != EQUAL:
                v, lab = adjudicate(rel, rs - ts, ts - rs, 'src',
                                    r.preserve_reads, enc=_enc(t))
                rows.append(Row(guest, ex.seq, i, t.pc, 'reg-src-set',
                                v, sorted(rs), sorted(ts),
                                '%s %s' % (rel, lab or '')))

        # --- memory
        sub.note('memop-count', t)
        if len(r.loads) != len(t.loads) or len(r.stores) != len(t.stores):
            rows.append(Row(guest, ex.seq, i, t.pc, 'memop-count', WP_DEFECT,
                            '%dL/%dS' % (len(r.loads), len(r.stores)),
                            '%dL/%dS' % (len(t.loads), len(t.stores)), ''))
            continue
        for kind, rl, tl in (('load', r.loads, t.loads),
                             ('store', r.stores, t.stores)):
            for _j, (rec, tec) in enumerate(zip(rl, tl)):
                ra, rd, rw_ = rec
                ta, td, tw_ = tec
                sub.note('memop-addr', t)
                if ra != ta:
                    gap = any(a in unestablished for a in range(ta, ta + 8))
                    rows.append(Row(guest, ex.seq, i, t.pc, 'memop-addr',
                                    RECON_GAP if (gap or reg_gaps)
                                    else WP_DEFECT,
                                    '0x%x' % ra, '0x%x' % ta, kind))
                    continue
                if tw_ is not None:
                    sub.note('memop-width', t)
                if tw_ is not None and rw_ != tw_:
                    rows.append(Row(guest, ex.seq, i, t.pc, 'memop-width',
                                    WP_DEFECT, rw_, tw_, kind))
                if td is None or rd is None:
                    continue
                sub.note('load-data' if kind == 'load' else 'store-data', t)
                w = min(rw_, tw_ or rw_)
                mask = (1 << (8 * w)) - 1
                if (rd & mask) != (td & mask):
                    unest = any(a in unestablished for a in range(ta, ta + w))
                    axis = 'load-data' if kind == 'load' else 'store-data'
                    # A datum that passed through the x87 file is a DOUBLE on
                    # the reference side, whatever its architectural width --
                    # so a store of one is the same named limit as an x87
                    # register value, not a fresh disagreement.
                    x87 = any(n.startswith('REG_FPR') for n in t.srcs)
                    if x87 and kind == 'store':
                        rows.append(Row(guest, ex.seq, i, t.pc, axis,
                                        GEM5_LIMIT, '0x%x' % rd, '0x%x' % td,
                                        '%s: a store OF an x87 register, so '
                                        'the datum is gem5\'s double'
                                        % _X87_VALUE_LIMIT))
                        continue
                    rows.append(Row(guest, ex.seq, i, t.pc, axis,
                                    RECON_GAP if unest else WP_DEFECT,
                                    '0x%x' % rd, '0x%x' % td,
                                    'address never established by the wire'
                                    if unest else ''))
    return rows, n, tail_reason, sub


def excursion_gaps(ex, seedgaps):
    """What the reconstruction could not establish, as evidence.

    ``unestablished`` is every address this excursion READS that no ELF byte,
    no correct-path load datum and no correct-path store datum ever put a
    value under.  Computed from the excursion's own accesses, so it is a fact
    about this experiment and not a whole-address-space claim.
    """
    unest = set()
    for ins in ex.insns:
        for addr, _d, size in ins.loads:
            for k in range(addr, addr + (size or 8)):
                if k not in ex.mem_src:
                    unest.add(k)
    return {'reg_gaps': set(), 'unestablished': unest, 'seedgaps': seedgaps}


# ------------------------------------------------------------------ driver
class Env(object):
    """Everything the leg needs to start, resolved once and NAMED."""

    def __init__(self, args):
        self.gem5_bin = os.path.join(args.gem5_build, 'gem5.opt')
        if not os.path.exists(self.gem5_bin):
            raise gem5_env.MissingPrerequisite(
                'MISSING PREREQUISITE: %s\n  the X86 gem5 this leg needs was '
                'not built.  Build it with\n    scons build/X86/gem5.opt\n'
                '  in %s.  Substituting QEMU for the reference is BANNED here: '
                'QEMU against\n  QEMU is not an independent reference.'
                % (self.gem5_bin, args.gem5_dir))
        self.gem5_dir = args.gem5_dir
        self.env, self.notes = gem5_env.gem5_environment(
            self.gem5_bin, args.outdir)
        bad = V.verify_misc_map(args.gem5_dir)
        if bad:
            raise RuntimeError(
                'gem5 misc-register indices have moved: %r.  A misc index '
                'read as the WRONG name puts a register in the wrong tracer '
                'family and reads as AGREEMENT, so this is fatal.' % (bad,))
        self.notes.append('gem5 misc-register map verified against '
                          'src/arch/x86/regs/misc.hh: %d indices, 0 moved'
                          % len(V.MISC))


def inject_rmw_drop(exc):
    """THE FALSIFIER FOR REF-PRESERVE-READ-OVERNAMED.

    Drop, on the TRACER side, exactly the sources the QEMU oracle calls
    ARCHITECTURAL on a register the same instruction also writes -- the 8-
    and 16-bit read-modify-write case the rule's blind spot used to forgive.
    The rule is closed only if the leg CONVICTS this, so the injection is run
    and its effect counted; an injection that removed nothing is a failed
    control, not a pass.

    -> Counter of 'encoding:register' actually dropped.
    """
    hit = collections.Counter()
    for ex in exc:
        for ins in ex.insns:
            enc = _enc(ins)
            if enc is None:
                continue
            written = set(w[0] for w in ins.writes)
            keep = []
            for r in ins.srcs:
                if r in written and ORACLE is not None and \
                        ORACLE.ask(enc, r) == QPO.ARCH:
                    hit['%s:%s' % (enc, r)] += 1
                    continue
                keep.append(r)
            ins.srcs = keep
    return hit


def inject_x87_top(exc):
    """THE FALSIFIER FOR REF-X87-TOP-FOLDED-AT-DECODE.

    The mirror of ``inject_rmw_drop``, on the other side of the same
    question.  PLANT, on the TRACER side, a REG_FCSR source on every
    instruction whose encoding the QEMU status-group oracle answers NO on --
    an instruction that reads no part of {fpus, fpstt, fptags}.  gem5 names
    no TOP source on ANY encoding, so its text cannot tell a planted read
    from a real one, and the pre-gate rule excuses both.  The leg must report
    these as TRACER-X87-TOP-NOT-READ; run the same injection under
    ``--rule-gem5-only`` and the ungated rule forgives them, which is what
    makes the gate a measurement rather than a decoration.

    -> Counter of encodings actually given a planted source.
    """
    hit = collections.Counter()
    for ex in exc:
        for ins in ex.insns:
            enc = _enc(ins)
            if enc is None or 'REG_FCSR' in ins.srcs:
                continue
            if X87 is None or X87.reads_status(enc) is not False:
                continue
            ins.srcs = list(ins.srcs) + ['REG_FCSR']
            hit[enc] += 1
    return hit


def process_guest(args, envx, guest, out):
    stem = os.path.join(out, os.path.basename(guest))
    trace = run_tracer(args.qemu, args.plugin, guest, stem, args.wpdepth)
    image, xranges, _entry = elfimage.load(guest)
    exc, cp, tstats = wp_trace.build(args.decode, trace, image)
    sel = guest_ranges(xranges)
    if getattr(args, 'inject_rmw_drop', False):
        got = inject_rmw_drop(exc)
        envx.notes.append('INJECTION rmw-drop on %s: %d sources removed, %d '
                          'distinct encoding:register  %s'
                          % (os.path.basename(guest), sum(got.values()),
                             len(got), ' '.join(sorted(got))[:400]))
    if getattr(args, 'inject_x87_top', False):
        got = inject_x87_top(exc)
        envx.notes.append('INJECTION x87-top on %s: %d REG_FCSR sources '
                          'planted over %d distinct encodings  %s'
                          % (os.path.basename(guest), sum(got.values()),
                             len(got), ' '.join(sorted(got))[:400]))

    stats = collections.Counter()
    rows = []
    dropped = collections.Counter()
    folded = collections.Counter()
    merged = collections.Counter()

    # ---- correct-path ground truth: gem5 running the SAME static ELF.
    cprun = gem5_wp_ref.run(envx.gem5_bin, envx.gem5_dir, envx.env, guest,
                            out, os.path.basename(guest) + '.cp',
                            args.cp_maxinsts, args.timeout)
    if cprun.log is None:
        raise RuntimeError('gem5 produced no log for the correct-path run of '
                           '%s (exit %d): %s'
                           % (guest, cprun.exit, cprun.stdout[-600:]))
    refcp = gem5_wp_ref.parse(cprun.log, sel, dropped, folded, merged)
    gem5_wp_ref.running_rflags(refcp, None)
    snaps = ground_truth(refcp)
    pairs = align(refcp, cp)
    trc2ref = dict((t, r) for r, t in pairs if r is not None and t is not None)
    stats['cp-aligned'] = len(trc2ref)
    stats['cp-ref-insns'] = len(refcp)
    stats['cp-trc-insns'] = len(cp)

    distinct = wp_trace.dedupe(exc)
    stats['excursions-dynamic'] = len(exc)
    stats['excursions-distinct'] = len(distinct)
    todo = distinct if args.max <= 0 else distinct[:args.max]
    stats['excursions-run'] = len(todo)
    stats['excursions-stood-for'] = sum(n for _e, n in todo)

    tails = collections.Counter()
    sub = Subjects()
    for k, (ex, _mult) in enumerate(todo):
        tag = '%s.e%04d' % (os.path.basename(guest), k)
        seed = wp_seed_x86.build(out, tag, ex, args.cc)
        cap = args.prologue_cap + 8 * len(ex.insns) + 32
        run = gem5_wp_ref.run(envx.gem5_bin, envx.gem5_dir, envx.env,
                              seed.elf, out, tag, cap, args.timeout)
        gapinfo = excursion_gaps(ex, seed.gaps)

        ridx = trc2ref.get(ex.cp_index - 1)
        if ridx is not None:
            erows, estats, esub = entry_state_rows(guest, ex,
                                                   snaps[ridx + 1],
                                                   gapinfo['reg_gaps'])
            sub.merge(esub)
            rows.extend(erows)
            for kk, vv in estats.items():
                stats['entry-state:' + kk] += vv
        else:
            stats['entry-state:unaligned'] += 1

        stats['wp-insns-declared'] += len(ex.insns)
        if run.log is None:
            rows.append(Row(guest, ex.seq, 0, ex.start_pc, 'pc-sequence',
                            GEM5_LIMIT, 'no log', '0x%x' % ex.start_pc,
                            'gem5 wrote no trace: %s'
                            % (run.tail or 'exit %d' % run.exit)))
            tails['GEM5-NO-LOG'] += len(ex.insns)
            stats['excursion-no-reference'] += 1
            continue
        ref = gem5_wp_ref.parse(run.log, sel, dropped, folded, merged)
        gem5_wp_ref.running_rflags(ref, seed.flags_word)
        if not ref:
            rows.append(Row(guest, ex.seq, 0, ex.start_pc, 'pc-sequence',
                            GEM5_LIMIT, 'no guest-range instruction',
                            '0x%x' % ex.start_pc,
                            'the injected run retired nothing inside the '
                            'guest image: %s'
                            % (run.tail or 'exit %d' % run.exit)))
            tails['GEM5-NO-GUEST-INSN'] += len(ex.insns)
            stats['excursion-trapped'] += 1
            continue
        r, compared, tail, csub = compare_excursion(guest, ex, ref, gapinfo,
                                                    run.tail)
        sub.merge(csub)
        rows.extend(r)
        stats['wp-insns-compared'] += compared
        if compared < len(ex.insns):
            tails[tail or 'UNNAMED'] += len(ex.insns) - compared
        if not r:
            stats['excursions-clean'] += 1
        stats['unestablished-bytes'] += len(gapinfo['unestablished'])
        for g in seed.gaps:
            stats['seed-gap:' + g] += 1
        for u in seed.unmapped:
            stats['unmappable-id:' + u] += 1
    for kk, vv in tstats.items():
        stats['trace:' + kk] += vv
    return rows, stats, tails, dropped, folded, merged, sub


def render(rows, stats, tails, dropped, folded, merged, notes, guests,
           sub):
    out = []
    w = out.append
    w('=' * 74)
    w('ARC 3 -- x86_64 WRONG-PATH execution cross-check vs gem5')
    w('=' * 74)
    w('')
    w('The wrong-path arm had NO execution reference on any ISA, and on')
    w('x86_64 the PIN reference this project uses elsewhere is explicitly')
    w('NOT one: PIN observes what the machine really retired, and a')
    w('wrong-path excursion is a path the machine did not take.  gem5')
    w('decodes and executes x86-64 itself, in syscall-emulation mode, from')
    w('the SAME static ELF the tracer traces.  Every excursion below was')
    w('rebuilt from the trace alone -- the REGFILE seed, the destination')
    w('snapshots, the correct-path load and store data and the guest image')
    w('-- installed as instructions at the excursion\'s own PC, and')
    w('compared instruction for instruction.')
    w('')
    for n in notes:
        w('  NOTE  %s' % n)
    w('')
    w('AXES: ' + ', '.join(AXES) + ', wp-entry-state')
    w('')
    hdr = '%-46s %10s' % ('measure', 'count')
    w(hdr)
    w('-' * len(hdr))
    for k in sorted(stats):
        w('%-46s %10d' % (k, stats[k]))
    w('')
    w('=' * 74)
    w('THE DECLARED/COMPARED IDENTITY')
    w('')
    declared = stats['wp-insns-declared']
    compared = stats['wp-insns-compared']
    w('  declared  %d' % declared)
    w('  compared  %d' % compared)
    w('  gap       %d' % (declared - compared))
    w('')
    w('  uncompared tails, by NAME:')
    tot = 0
    for k in sorted(tails):
        w('    %-52s %8d' % (k, tails[k]))
        tot += tails[k]
    if not tails:
        w('    (none)')
    w('    %-52s %8d' % ('SUM', tot))
    ok = (tot == declared - compared)
    w('')
    w('  IDENTITY  sum-of-uncompared-tails == declared - compared : %s'
      % ('HOLDS' if ok else 'VIOLATED'))
    w('')
    w('=' * 74)
    w('THE VERDICT SPLIT.  A divergence is a WP DEFECT, a RECONSTRUCTION GAP')
    w('or a GEM5 LIMIT, and never a fourth thing.')
    w('')
    byv = collections.Counter(r.verdict for r in rows)
    bya = collections.Counter((r.axis, r.verdict) for r in rows)
    for line in sub.render(AXES + ('wp-entry-state',), bya, VERDICTS):
        w(line)
    w('THE NUMBER THAT MATTERS: WP-DEFECT + RECONSTRUCTION-GAP +')
    w('UNACCOUNTED = %d.  TRACER-SUPERSET rows are COVERED -- each carries a'
      % (byv[WP_DEFECT] + byv[RECON_GAP] + byv[UNACCOUNTED]))
    w('named rule from x86_exec_rules.X86_EXEC saying why the reference')
    w('cannot state the fact.  REFERENCE-SIDE rows are the opposite')
    w('direction and carry a rule too: the reference states a fact the')
    w('ARCHITECTURE does not, so the tracer is right and no edge is owed.')
    w('GEM5-LIMIT rows are the reference\'s own silence and are named one by')
    w('one, never counted as agreement.')
    w('')
    if dropped:
        w('REFERENCE-INTERNAL REGISTERS DROPPED (not architectural state; see')
        w('x86_vocab).  Counted so that an exclusion which stops matching')
        w('cannot go unnoticed.')
        for k in sorted(dropped, key=lambda x: -dropped[x])[:24]:
            w('  %10d  %s' % (dropped[k], k))
        w('')
    if merged:
        w('REFERENCE MICRO-OP MERGE READS SUPPRESSED.  gem5 passes a value')
        w('through an architectural register its own lowering picked as a')
        w('temporary; the read is not an architectural dependency.  The rule')
        w('is mechanical -- the register was written by an EARLIER micro-op')
        w('of the same macro-op, or the micro-op does not NAME it as a source')
        w('and the macro-op writes it at FULL architectural width.  A NARROW')
        w('write is not suppressed here: gem5 still states the read, and R7.1')
        w('rules on it at the comparison, as REF-PRESERVE-READ-OVERNAMED.')
        for k in sorted(merged, key=lambda x: -merged[x])[:16]:
            w('  %10d  %s' % (merged[k], k))
        w('')
    if folded:
        w('REFERENCE ACCESSES FOLDED.  gem5 cracks a 128-bit access into two')
        w('64-bit halves; contiguous accesses of one macro-op are the single')
        w('access the INSTRUCTION makes.')
        for k in sorted(folded, key=lambda x: -folded[x])[:16]:
            w('  %10d  %s' % (folded[k], k))
        w('')
    defects = collections.defaultdict(list)
    for r in rows:
        if r.verdict in (WP_DEFECT, RECON_GAP, UNACCOUNTED):
            defects[(os.path.basename(r.guest), r.pc, r.axis,
                     str(r.ref), str(r.trc))].append(r)
    if defects:
        w('DEFECT ROWS, GROUPED BY SITE.  Every one of these is a place where')
        w('the reference names architectural state the tracer does not -- the')
        w('one direction the project treats as disqualifying.')
        w('')
        w('  %-10s %-10s %-13s %5s  %s' % ('guest', 'pc', 'axis', 'count',
                                           'reference \\ tracer'))
        for k in sorted(defects, key=lambda x: (x[0], x[1])):
            g, pc, ax, ref, trc = k
            w('  %-10s 0x%-8x %-13s %5d  %s' % (g, pc, ax, len(defects[k]),
                                                ref))
            w('  %-10s %-10s %-13s %5s  %s' % ('', '', '', '', trc))
        w('')
    named = collections.Counter()
    for r in rows:
        if r.verdict == GEM5_LIMIT:
            named[r.detail.split(';')[0]] += 1
    if named:
        w('EVERY GEM5-LIMIT, NAMED:')
        for k in sorted(named, key=lambda x: -named[x]):
            w('  %6d  %s' % (named[k], k))
        w('')
    if not rows:
        w('NO DIVERGENCE on any axis, over every excursion run.  That is a')
        w('result only because the negative control (selftest_wp_gem5.py)')
        w('shows every axis CAN fire; a check that cannot fire agrees')
        w('forever.')
        w('')
    else:
        w('EVERY ROW, none summarised away:')
        w('')
        for r in rows[:400]:
            w('  %-20s %-16s %-10s pc=0x%x idx=%d'
              % (r.verdict, r.axis, os.path.basename(r.guest), r.pc, r.idx))
            w('      ref=%s' % (r.ref,))
            w('      trc=%s' % (r.trc,))
            if r.detail:
                w('      %s' % (r.detail,))
        if len(rows) > 400:
            w('  ... %d more rows; use --tsv for the complete list'
              % (len(rows) - 400))
        w('')
    return '\n'.join(out) + '\n', ok


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('guest', nargs='+')
    ap.add_argument('--gem5-dir', required=True)
    ap.add_argument('--gem5-build', required=True,
                    help='the build/X86 directory holding gem5.opt')
    ap.add_argument('--qemu', required=True)
    ap.add_argument('--plugin', required=True)
    ap.add_argument('--decode', required=True)
    ap.add_argument('--cc', default='gcc')
    ap.add_argument('--wpdepth', type=int, default=16)
    ap.add_argument('--max', type=int, default=0,
                    help='distinct excursions per guest; <=0 for all')
    ap.add_argument('--prologue-cap', type=int, default=400,
                    help='micro-op budget the injection prologue needs; it '
                         'is excluded by ADDRESS, this only bounds gem5')
    ap.add_argument('--cp-maxinsts', type=int, default=200000)
    ap.add_argument('--timeout', type=int, default=900)
    ap.add_argument('-o', '--outdir', required=True)
    ap.add_argument('--tsv')
    ap.add_argument('--rule-gem5-only', action='store_true',
                    help='FALSIFICATION ARM: adjudicate '
                         'REF-PRESERVE-READ-OVERNAMED from gem5\'s operand '
                         'text alone, as the rule did before the QEMU gate.  '
                         'Run WITH --inject-rmw-drop to see the blind spot '
                         'forgive a dropped architectural source')
    ap.add_argument('--inject-x87-top', action='store_true',
                    help='NEGATIVE CONTROL: plant, on the tracer side, a '
                         'REG_FCSR source on every encoding the QEMU '
                         'status-group oracle says reads no part of '
                         '{fpus, fpstt, fptags}.  The leg MUST report '
                         'TRACER-X87-TOP-NOT-READ; a green run under this '
                         'flag means the rule excuses a TOP read QEMU does '
                         'not perform')
    ap.add_argument('--inject-rmw-drop', action='store_true',
                    help='NEGATIVE CONTROL: drop, on the tracer side, every '
                         'source the QEMU oracle calls architectural on a '
                         'register the instruction also writes.  The leg '
                         'MUST report TRACER-DROPPED-RMW-SOURCE; a green run '
                         'under this flag means the rule still forgives an '
                         '8/16-bit read-modify-write')
    a = ap.parse_args()

    os.makedirs(a.outdir, exist_ok=True)
    envx = Env(a)
    # The QEMU-side discriminator for REF-PRESERVE-READ-OVERNAMED, built from
    # the SAME guests and the SAME qemu-x86_64 this run measures.  Without it
    # every SUBSET row is refused rather than excused.
    oracle, _olog = QPO.build(a.qemu, a.guest,
                              os.path.join(a.outdir, 'oracle'))
    set_oracle(oracle)
    # The x87 half of the same question, off the SAME dumps.  It answers for
    # state QEMU keeps at an env offset, which is precisely what the preserve
    # oracle refuses on -- the two are complementary, not alternatives.
    x87 = X87D.StatusOracle()
    for _l in _olog:
        x87.add_dump(_l)
    set_x87(x87)
    if a.rule_gem5_only:
        global GATE, X87_GATE
        GATE = False
        X87_GATE = False
        envx.notes.append('FALSIFICATION ARM: the QEMU gates on '
                          'REF-PRESERVE-READ-OVERNAMED and '
                          'REF-X87-TOP-FOLDED-AT-DECODE are OFF; the rules '
                          'are adjudicating from gem5\'s operand text alone')
    rows = []
    stats, tails = collections.Counter(), collections.Counter()
    dropped, folded, merged = (collections.Counter(), collections.Counter(),
                               collections.Counter())
    sub = Subjects()
    for g in a.guest:
        r, s, t, d, f, m, fs = process_guest(a, envx, g, a.outdir)
        rows.extend(r)
        stats.update(s)
        tails.update(t)
        dropped.update(d)
        folded.update(f)
        merged.update(m)
        sub.merge(fs)
    sub.write_tsv(os.path.join(a.outdir, 'axis_subjects.tsv'),
                  AXES + ('wp-entry-state',))
    txt, identity_ok = render(rows, stats, tails, dropped, folded, merged,
                              envx.notes, a.guest, sub)
    sys.stdout.write(txt)
    open(os.path.join(a.outdir, 'REPORT.txt'), 'w').write(txt)
    if a.tsv:
        with open(a.tsv, 'w') as fh:
            fh.write('guest\tseq\tidx\tpc\taxis\tverdict\tref\ttrc\tdetail\n')
            for r in rows:
                fh.write('\t'.join((os.path.basename(r.guest), str(r.seq),
                                    str(r.idx), '0x%x' % r.pc, r.axis,
                                    r.verdict, repr(r.ref), repr(r.trc),
                                    r.detail)) + '\n')
    bad = sum(1 for r in rows
              if r.verdict in (WP_DEFECT, RECON_GAP, UNACCOUNTED))
    return 1 if (bad or not identity_ok) else 0


if __name__ == '__main__':
    sys.exit(main())
