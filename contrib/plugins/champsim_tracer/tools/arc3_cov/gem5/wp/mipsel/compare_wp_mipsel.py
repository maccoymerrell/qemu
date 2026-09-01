"""
ARC 3 -- mipsel WRONG-PATH execution cross-check: the tracer against gem5.

NO WP GOLDEN EXISTS ON ANY ISA.  Every gate this project runs compares correct
path against correct path, so a wrong-path divergence has been invisible for
the whole arc, and the wrong-path arm is a large fraction of what the tracer
emits.  The riscv64 leg closed that hole against Spike; the maintainer's
direction for the remaining three ISAs is that their wrong paths be verified
by gem5, and this is the mipsel leg of it.

    trace ---> reconstructed regfile + memory ---> injected ELF32
                                                        |
                                                    gem5 MIPS SE
                                                        |
    the tracer's WP record  <---- compared against ---- what the ISA does

THE VERDICTS, AND WHY THEY MUST NOT BE BLURRED
==============================================
A divergence is exactly one of:

  WP-DEFECT           the excursion recorded something the architecture would
                      not, from a starting state the trace fully specified.
                      A tracer bug.
  RECONSTRUCTION-GAP  the trace does not carry enough state to rebuild the
                      starting point, so the two runs began from different
                      machines.  A finding about what the WIRE drops.
  GEM5-LIMIT          the reference cannot state the architectural fact --
                      either it is silent (SE mode panics on a class; an
                      accumulator write never reaches gem5's own instruction
                      trace) or it states a fact the architecture does not
                      have (its ``jr`` reads a configuration register).  Named
                      one by one, with the observed text, and NEVER quoted as
                      agreement.

and two columns that are not divergences:

  TRACER-SUPERSET     we record a fact the reference cannot, and a NAMED rule
                      from ``wp_rules_mipsel.MIPSEL_WP`` says why.  COVERED.
  UNACCOUNTED         a disagreement nobody has explained.  MUST BE 0.

The gap verdict is assigned from EVIDENCE, never from plausibility.  A register
is a RECONSTRUCTION-GAP only where the ``wp-entry-state`` axis measures the
reconstruction wrong against the correct-path run's own ground truth; an
address only where no ELF byte, no correct-path load datum and no correct-path
store datum ever established it.

WHY A SUPERSET STILL HAS TO BE EARNED
=====================================
gem5 has already caught one mipsel tracer defect on the CORRECT path this arc:
every conditional branch published a phantom REG_GPR1 ($at) destination, fixed
at 95a0d89e92.  It scored TRACER-SUPERSET the entire time it was live, because
the DIRECTION of a set difference says nothing about whether the extra is
TRUE.  A SUPERSET row here is COVERED only with a rule naming why the
reference cannot state the fact; without one it is UNACCOUNTED and the run is
red.

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
import re
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, '..', '..'))
sys.path.insert(0, os.path.join(_HERE, '..', '..', '..'))
sys.path.insert(0, os.path.join(_HERE, '..', '..', '..',
                                'riscv64', 'spike', 'wp'))

import wp_image32 as wp_image                                # noqa: E402
import wp_seed_mipsel as wp_seed                             # noqa: E402
import wp_trace                                              # noqa: E402
import gem5_ref                                              # noqa: E402
import gem5_env                                              # noqa: E402
from arc3_taxonomy import set_relation, EQUAL, SUPERSET, SUBSET  # noqa: E402
from wp_rules_mipsel import mipsel_wp_rule                   # noqa: E402
from axis_subjects import Subjects                           # noqa: E402

WP_DEFECT = 'WP-DEFECT'
RECON_GAP = 'RECONSTRUCTION-GAP'
GEM5_LIMIT = 'GEM5-LIMIT'
SUPERSET_OK = 'TRACER-SUPERSET'
UNACCOUNTED = 'UNACCOUNTED'
VERDICTS = (WP_DEFECT, RECON_GAP, GEM5_LIMIT, SUPERSET_OK, UNACCOUNTED)

#: every fact this leg checks about a wrong-path instruction.  Named in full so
#: a report can never quote a subset as if it were the whole comparison.
AXES = ('pc-sequence', 'insn-bits', 'reg-dst-set', 'reg-dst-value',
        'reg-dst-valued', 'reg-src-set', 'memop-count', 'memop-addr',
        'memop-width', 'load-data', 'store-data')

Row = collections.namedtuple(
    'Row', 'guest seq idx pc axis verdict ref trc detail')

DBG = ('ExecEnable,ExecUser,ExecKernel,ExecMicro,ExecEffAddr,ExecResult,'
       'ExecOpClass,ExecThread,ExecRegDelta,ExecFlags')
GEM5_DONE = 'exiting with last active thread context'
_EXIT_RE = re.compile(r'^Exiting @ tick (\d+) because (.*)$', re.M)
_PANIC_RE = re.compile(r'^(src/\S+:\d+: (?:panic|fatal): .*)$', re.M)

#: The tracer's spelling of the register gem5 renders as the `invalid` class,
#: which ``gem5_ref`` drops as reference-internal -- so a REG_ZERO operand has
#: no counterpart to pair with.  See REF-ZERO-OPERAND-AS-INVALID.
REF_ZERO_INVISIBLE = 'REG_ZERO'

#: gem5 misc-register 129 is ``Config1`` (src/arch/mips/regs/misc.hh:112:
#: ``Config = 128`` then ``Config1``).  ``gem5_ref._mips_reg`` renders a misc
#: register as ``MISC:<index>``.
_MISC_CONFIG1 = 'MISC:129'


# ------------------------------------------------------------------ the runs
#: The standing compression for every trace this harness writes.
#: A reference run's trace is a working file, not a deliverable, and an
#: uncompressed one costs disk for nothing -- 124 of them, 34.6 MB, were
#: measured under one evidence root because these drivers built their
#: plugin option string without it.  It is set HERE, where the option
#: string is built, so no caller can forget it; `cst_audit` names the
#: member codec, which is how the compliance check reads it back rather
#: than assuming.
CST_COMPRESS = 'zstd -T0 -3 -q -c'


def run_tracer(qemu, plugin, guest, out, wpdepth, compress=None):
    trace = out + '.cst'
    opt = ('%s,outfile=%s,memdata=1,regdata=1,wpdepth=%d'
           % (plugin, out, wpdepth))
    opt += ',compress=%s' % (compress or CST_COMPRESS)
    p = subprocess.run([qemu, '-plugin', opt, guest],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        raise RuntimeError('qemu exit %d: %s'
                           % (p.returncode,
                              p.stdout.decode('utf-8', 'replace')[-800:]))
    if not os.path.exists(trace):
        raise RuntimeError('tracer produced no %s' % trace)
    return trace


class Gem5Run(object):
    """One gem5 invocation and what became of it.

    ``stopped`` is the reason gem5 printed, verbatim, and ``panic`` the panic
    text when there was one: a GEM5-LIMIT row is only a limit when it can be
    QUOTED, so the text is carried rather than a boolean.
    """

    __slots__ = ('log', 'rc', 'stopped', 'panic', 'console')

    def __init__(self, log, rc, stopped, panic, console):
        self.log = log
        self.rc = rc
        self.stopped = stopped
        self.panic = panic
        self.console = console

    @property
    def ok(self):
        return self.panic is None and self.rc == 0


def run_gem5(binary, cfg, env, elf, outdir, tag, maxinsts):
    d = os.path.join(outdir, tag + '.g5')
    cmd = [binary, '-d', d, '--debug-flags=' + DBG, '--debug-file=exec.log',
           cfg, '--cpu-type=AtomicSimpleCPU']
    if maxinsts:
        cmd += ['-I', str(maxinsts)]
    cmd += ['-c', elf]
    p = subprocess.run(cmd, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, env=env)
    console = p.stdout.decode('utf-8', 'replace')
    with open(os.path.join(outdir, tag + '.gem5.out'), 'w') as fh:
        fh.write(console)
    mp = _PANIC_RE.search(console)
    me = _EXIT_RE.search(console)
    return Gem5Run(os.path.join(d, 'exec.log'), p.returncode,
                   me.group(2) if me else None,
                   mp.group(1) if mp else None, console)


def gem5_prereqs(gem5_dir, cache_dir, python_home=None):
    """Every named thing this leg needs before a single guest is run.

    Delegates to the correct-path leg's environment resolution: the loader
    shim, the poisoned-``LD_LIBRARY_PATH`` sanitiser and the deep start proof
    are the same prerequisites, and a second copy of them would drift.
    """
    binary = gem5_env.require_file(
        os.path.join(gem5_dir, 'build/MIPS/gem5.opt'),
        'gem5.opt for the MIPS target (build it: scons build/MIPS/gem5.opt)')
    cfg = gem5_env.require_file(
        os.path.join(gem5_dir, 'configs/deprecated/example/se.py'),
        'gem5 syscall-emulation config se.py')
    proof = gem5_env.require_file(
        os.path.join(_HERE, '..', '..', 'startproof.py'),
        'the gem5 start-proof config script')
    env, notes = gem5_env.gem5_environment(binary, cache_dir,
                                           python_home=python_home)
    p = subprocess.run([binary, '-d', os.path.join(cache_dir, 'startproof'),
                        '--quiet', proof],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       env=env)
    out = p.stdout.decode('utf-8', 'replace')
    if p.returncode != 0 or 'ARC3-GEM5-START-OK' not in out:
        how = ('died on signal %d' % -p.returncode if p.returncode < 0
               else 'exited %d' % p.returncode)
        raise gem5_env.MissingPrerequisite(
            'PREREQUISITE UNMET: %s cannot run.  The start proof %s.\n'
            '  Decisions taken:\n%s\n  gem5 said:\n%s'
            % (binary, how, '\n'.join('    ' + n for n in notes),
               '\n'.join('    ' + l for l in out.splitlines()[-12:])))
    return binary, cfg, env, notes


# ------------------------------------------------------- entry-state truth
def ground_truth(commits):
    """Per index, the register file the REFERENCE run actually held.

    ``snaps[i]`` is {generic name: value} for the state BEFORE reference
    instruction ``i``, built from gem5's own destination writes.

    gem5's Exec trace prints no source VALUES -- only names -- so unlike the
    riscv64 leg against Spike there is no first-read evidence with which to
    back-date an initial value.  A register the reference never WROTE is
    therefore absent, and absence is reported as "the reference cannot say",
    never as agreement.
    """
    cur = {}
    snaps = []
    for ins in commits:
        snaps.append(dict(cur))
        for name, val, w in ins.writes:
            if w:
                cur[name] = val
    snaps.append(dict(cur))
    return snaps


def align(ref, trc):
    """Index-preserving alignment of two instruction streams."""
    rk = [(i.pc, i.bits) for i in ref]
    tk = [(i.pc, i.bits) for i in trc]
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


# -------------------------------------------------------------- comparison
def adjudicate(rel, label):
    """(direction, a named mechanism) -> a verdict.

    A direction with no rule is UNACCOUNTED and says so; it is never quietly
    folded into the superset.  A rule kept as a regression tripwire declares
    ``accounts=False`` and so also leaves its row UNACCOUNTED, which is the
    entire point of keeping it.
    """
    rule = mipsel_wp_rule(label)
    if rule is not None and rule.accounts and rel in rule.expect:
        if rel == SUPERSET:
            return SUPERSET_OK, label
        # The reference names something the tracer does not.  That is a
        # tracer deficit UNLESS the named mechanism is on the reference's
        # side -- gem5 modelling its own `jr` through a configuration
        # register, or spelling a fact differently.
        if rule.category in ('reference-defect', 'reference-gap',
                             'vocabulary-difference'):
            return GEM5_LIMIT, label
        return WP_DEFECT, label
    if rel == SUBSET and label is None:
        # The reference names an architectural fact the tracer does not, and
        # nothing explains it.  That is the one disqualifying direction.
        return WP_DEFECT, label
    return UNACCOUNTED, label


#: gem5's own disassembly mnemonics for the hint instructions it does not
#: implement.  Read off the REFERENCE's text, never off the tracer's opcode
#: class -- the question is what gem5 did, and gem5 is the one who says.
_HINT_MNEMONICS = ('pref', 'prefe', 'synci')

#: the SIGNED accumulator forms.  `multu`/`divu`/`maddu`/`msubu` are excluded
#: by exact-token match: `mult` is a prefix of `multu` and a prefix test would
#: charge the unsigned forms with the signed forms' defect.
_SIGNED_ACC = ('mult', 'div', 'madd', 'msub')
_ACC_LO, _ACC_HI = 'REG_ACC0', 'REG_ACCHI0'


def mnemonic(ins):
    """gem5's own mnemonic for an instruction, or '' when it printed none."""
    d = (ins.disas or '').strip()
    return d.split()[0].lower() if d else ''


def _s32(x):
    x &= 0xffffffff
    return x - (1 << 32) if x >> 31 else x


def mips32_acc(mn, a, b, hi=None, lo=None):
    """The architectural MIPS32 (HI, LO) for a signed accumulator form.

    Computed so the harness ARBITRATES rather than asserts: when the two tools
    disagree about HI, this says which of them the ISA agrees with, from the
    reference's OWN operand values -- using the tracer's would beg the
    question the row asks.  ``madd``/``msub`` additionally need the prior
    accumulator, which is likewise taken from the reference's own earlier
    writes.  Returns None where the form has no defined answer (a zero
    divisor) or where an operand the answer depends on was never published.
    """
    x, y = _s32(a), _s32(b)
    if mn == 'mult':
        p = x * y
        return ((p >> 32) & 0xffffffff, p & 0xffffffff)
    if mn == 'div':
        if y == 0:
            return None
        # C99 / MIPS truncate toward zero; Python's // floors, so the sign is
        # applied after an unsigned division rather than taken from //.
        q = abs(x) // abs(y)
        if (x < 0) != (y < 0):
            q = -q
        r = x - q * y
        return (r & 0xffffffff, q & 0xffffffff)
    if mn in ('madd', 'msub'):
        if hi is None or lo is None:
            return None
        acc = ((hi & 0xffffffff) << 32) | (lo & 0xffffffff)
        if acc >> 63:
            acc -= 1 << 64
        acc = acc + x * y if mn == 'madd' else acc - x * y
        acc &= (1 << 64) - 1
        return ((acc >> 32) & 0xffffffff, acc & 0xffffffff)
    return None


def label_dst(only_ref, only_trc, ref, trc):
    if only_trc and not only_ref:
        if mnemonic(ref) in _HINT_MNEMONICS:
            return 'REF-HINT-UNIMPLEMENTED'
        if all(n.startswith('REG_ACC') for n in only_trc):
            return 'REF-NO-ACC-WRITE'
        if only_trc == frozenset(('REG_FCSR',)):
            return 'REF-NO-FCSR-TRAFFIC'
        if only_trc == frozenset(('REG_GPR1',)) and ref.ctrl:
            return 'TRC-INVENTED-BRANCH-DEST'
        if all(n == REF_ZERO_INVISIBLE for n in only_trc):
            return 'REF-ZERO-OPERAND-AS-INVALID'
        if only_trc == frozenset(('REG_PRED0',)) and \
                any(n == 'REG_FCSR' for n, _v, _w in ref.writes):
            return 'FPCC-GRANULARITY'
    return None


def label_src(only_ref, only_trc, ref):
    if only_ref and all(n == _MISC_CONFIG1 for n in only_ref):
        return 'REF-JR-READS-CONFIG1'
    if only_trc and not only_ref:
        if mnemonic(ref) in _HINT_MNEMONICS:
            return 'REF-HINT-UNIMPLEMENTED'
        if all(n == REF_ZERO_INVISIBLE for n in only_trc):
            return 'REF-ZERO-OPERAND-AS-INVALID'
        if only_trc == frozenset(('REG_FCSR',)):
            return 'REF-NO-FCSR-TRAFFIC'
    return None


def split_ref_writes(ins):
    """{generic id: (value, width)}.

    ``gem5_ref`` records a destination gem5 printed as ``=?`` with width 0.
    Such a name stays in the SET and carries no value; the value axes skip it,
    because a 0 there is the ABSENCE of a number and not the number zero.
    """
    return dict((name, (val, w)) for name, val, w in ins.writes)


def split_trc_writes(ins):
    return dict((name, (val, w)) for name, val, w in ins.writes)


def compare_excursion(guest, ex, ref, gapinfo, stopped=None):
    """One excursion vs the reference run of the same state -> ([Row], n).

    Returns the rows AND the number of wrong-path instructions actually
    compared, so the report can print the declared-versus-compared identity
    rather than leave a gap to be rediscovered.
    """
    rows = []
    sub = Subjects()
    reg_gaps = gapinfo['reg_gaps']
    unestablished = gapinfo['unestablished']
    n = len(ex.insns)

    ref_pcs = [i.pc for i in ref[:n]]
    trc_pcs = [i.pc for i in ex.insns]
    if ref_pcs != trc_pcs:
        k = 0
        while k < min(len(ref_pcs), len(trc_pcs)) and ref_pcs[k] == trc_pcs[k]:
            k += 1
        if len(ref) < n and k == len(ref_pcs):
            # The reference simply STOPPED; it did not go somewhere else.
            verdict = RECON_GAP if reg_gaps else GEM5_LIMIT
            # Named from gem5's OWN stop reason, not guessed: an excursion
            # that wanders into the guest's exit syscall ends the reference
            # process, and gem5 writes no trace line for the instruction that
            # terminated it -- so the last declared instruction has no
            # counterpart for a reason that is the reference's, not ours.
            why = ('the excursion reached the guest\'s own exit and gem5 '
                   'ended the process; it writes no trace line for the '
                   'terminating syscall'
                   if stopped and GEM5_DONE in stopped else
                   'gem5 stopped: %s' % (stopped or 'reason not printed'))
            detail = ('the reference retired %d of %d and stopped, it did not '
                      'diverge -- %s' % (len(ref), n, why))
        else:
            verdict = RECON_GAP if reg_gaps else WP_DEFECT
            detail = ('first divergence at index %d; reconstruction gaps: %s'
                      % (k, ','.join(sorted(reg_gaps)) or 'none'))
        rows.append(Row(guest, ex.seq, k,
                        trc_pcs[k] if k < len(trc_pcs) else -1,
                        'pc-sequence', verdict,
                        ['0x%x' % p for p in ref_pcs],
                        ['0x%x' % p for p in trc_pcs], detail))
        n = k                      # beyond the split the streams are unrelated

    compared = min(n, len(ref))
    sub.note('pc-sequence')
    # The reference's OWN register file as it runs, from its own writes.  It
    # is what lets the arithmetic arbitration below recompute the ISA answer
    # from the operands the REFERENCE had, rather than from the tracer's --
    # which would beg the question the row asks.
    refstate = {}
    #: register ids whose REFERENCE value is known wrong, established by the
    #: arithmetic arbitration below and then carried forward as a TAINT: an
    #: instruction that reads a poisoned register and disagrees about its own
    #: result is repeating the reference's earlier error, not exhibiting a
    #: second one.  A register is un-poisoned the moment the two sides agree
    #: about a write to it, so the taint cannot outlive its cause.
    poisoned = set()
    for i in range(compared):
        r, t = ref[i], ex.insns[i]
        sub.note('insn-bits', t)
        if r.bits != t.bits:
            rows.append(Row(guest, ex.seq, i, t.pc, 'insn-bits', WP_DEFECT,
                            hex(r.bits), hex(t.bits), 'same PC, other bytes'))
            continue
        rw, tw = split_ref_writes(r), split_trc_writes(t)

        # --- reg-dst-set
        sub.note('reg-dst-set', t)
        if frozenset(rw) != frozenset(tw):
            rel = set_relation((), sorted(rw), (), sorted(tw))
            if rel != EQUAL:
                only_ref = frozenset(rw) - frozenset(tw)
                only_trc = frozenset(tw) - frozenset(rw)
                v, lab = adjudicate(rel, label_dst(only_ref, only_trc, r, t))
                rows.append(Row(guest, ex.seq, i, t.pc, 'reg-dst-set',
                                v, sorted(rw), sorted(tw),
                                '%s %s' % (rel, lab or '')))

        # --- reg-dst-valued.  A destination BOTH sides name, where the
        # reference states a value and the tracer states WIDTH 0.  The name is
        # on the wire and the number is not, so nothing downstream can rebuild
        # the register file past this instruction.  It is scored as an axis of
        # its own because the VALUE comparison necessarily skips it, and a
        # skipped comparison is exactly how a dropped fact reads as agreement.
        both = sorted(frozenset(rw) & frozenset(tw))
        for k_ in both:
            rvv, rww = rw[k_]
            tvv, tww = tw[k_]
            sub.note('reg-dst-valued', t)
            if rww and not tww:
                rows.append(Row(guest, ex.seq, i, t.pc, 'reg-dst-valued',
                                WP_DEFECT, '%s=0x%x:w=%d' % (k_, rvv, rww),
                                '%s:w=0' % k_,
                                'the destination is named on the wire and its '
                                'value is not stated'))
            elif tww and not rww:
                rows.append(Row(guest, ex.seq, i, t.pc, 'reg-dst-valued',
                                GEM5_LIMIT, '%s:?' % k_,
                                '%s=0x%x:w=%d' % (k_, tvv, tww),
                                'gem5 printed the destination with no value'))

        # --- reg-dst-value, on the destinations BOTH sides valued
        mn = mnemonic(r)
        for k_ in both:
            rvv, rww = rw[k_]
            tvv, tww = tw[k_]
            if not rww or not tww:
                continue
            sub.note('reg-dst-value', t)
            w = min(rww, tww)
            m = (1 << (8 * w)) - 1
            if (rvv & m) == (tvv & m):
                continue
            verdict, detail = (RECON_GAP if k_ in reg_gaps else WP_DEFECT,
                               '')
            # ARBITRATE, do not assert.  For a signed accumulator form whose
            # two operand values the reference itself published earlier in
            # this excursion, recompute the MIPS32 answer and say which side
            # the ISA agrees with.  A rule name alone would be an opinion; a
            # recomputation is a measurement.
            if mn in _SIGNED_ACC and k_ in (_ACC_LO, _ACC_HI):
                # The two GPR operands, separated from the accumulator sources
                # madd/msub also name.
                srcs = [refstate.get(sname) for sname in r.srcs
                        if sname not in (_ACC_LO, _ACC_HI)]
                if len(srcs) == 2 and None not in srcs:
                    truth = mips32_acc(mn, srcs[0], srcs[1],
                                       hi=refstate.get(_ACC_HI),
                                       lo=refstate.get(_ACC_LO))
                    if truth is not None:
                        want = truth[0] if k_ == _ACC_HI else truth[1]
                        if (want & m) == (tvv & m) and (want & m) != (rvv & m):
                            verdict = GEM5_LIMIT
                            detail = ('MIPS32 %s of 0x%08x and 0x%08x gives '
                                      '%s=0x%08x: the TRACER matches the ISA, '
                                      'gem5 does not -- '
                                      'REF-MIPS32-SIGNED-ON-ZEXT'
                                      % (mn, srcs[0], srcs[1], k_, want))
                        elif (want & m) == (rvv & m):
                            detail = ('MIPS32 %s of 0x%08x and 0x%08x gives '
                                      '%s=0x%08x: the REFERENCE matches the '
                                      'ISA' % (mn, srcs[0], srcs[1], k_, want))
            if verdict != GEM5_LIMIT:
                tainted = sorted(n_ for n_ in r.srcs if n_ in poisoned)
                if tainted:
                    verdict = GEM5_LIMIT
                    detail = ('%s reads %s, whose reference value gem5 already '
                              'computed through the zero-extended signed path '
                              '-- REF-MIPS32-SIGNED-ON-ZEXT-PROPAGATED'
                              % (mn or 'this instruction', ','.join(tainted)))
            poisoned.add(k_) if verdict == GEM5_LIMIT else None
            rows.append(Row(guest, ex.seq, i, t.pc, 'reg-dst-value',
                            verdict, '%s=0x%x' % (k_, rvv),
                            '%s=0x%x' % (k_, tvv), detail))
        # A destination the two sides AGREE about is clean again: the taint
        # must not outlive the value that carried it.
        for k_ in both:
            rvv, rww = rw[k_]
            tvv, tww = tw[k_]
            if rww and tww:
                mm = (1 << (8 * min(rww, tww))) - 1
                if (rvv & mm) == (tvv & mm):
                    poisoned.discard(k_)
        for name, (val, ww) in rw.items():
            if ww:
                refstate[name] = val

        # --- reg-src-set
        rs, ts = frozenset(r.srcs), frozenset(t.srcs)
        sub.note('reg-src-set', t)
        if rs != ts:
            rel = set_relation((), sorted(rs), (), sorted(ts))
            if rel != EQUAL:
                v, lab = adjudicate(rel, label_src(rs - ts, ts - rs, r))
                rows.append(Row(guest, ex.seq, i, t.pc, 'reg-src-set',
                                v, sorted(rs), sorted(ts),
                                '%s %s' % (rel, lab or '')))

        # --- memory
        sub.note('memop-count', t)
        if len(r.loads) != len(t.loads) or len(r.stores) != len(t.stores):
            def byteset(recs, tag):
                out = set()
                for a, _d, sz in recs:
                    for kk in range(max(sz, 1)):
                        out.add((tag, a + kk))
                return out
            rb = byteset(r.loads, 'L') | byteset(r.stores, 'S')
            tb = byteset(t.loads, 'L') | byteset(t.stores, 'S')
            hint = (mnemonic(r) in _HINT_MNEMONICS or
                    (not r.loads and not r.stores and (t.loads or t.stores)
                     and all(sz == 0 for _a, _d, sz in t.loads + t.stores)))
            sc = (len(t.loads) == len(r.loads) + 1 and
                  len(t.stores) == len(r.stores) and bool(r.stores))
            lab = ('REF-HINT-UNIMPLEMENTED'
                   if mnemonic(r) in _HINT_MNEMONICS else
                   'HINT-MEMOP-REF-SILENT' if hint else
                   # MEASURED: the same bytes, a different number of requests.
                   'SAME-BYTES-DIFFERENT-SPLIT' if rb == tb else
                   'QEMU-SC-CMPXCHG' if sc else None)
            rel = (SUPERSET if (len(t.loads) >= len(r.loads) and
                                len(t.stores) >= len(r.stores)) else SUBSET)
            v, lab = adjudicate(rel, lab)
            rows.append(Row(guest, ex.seq, i, t.pc, 'memop-count', v,
                            '%dL/%dS' % (len(r.loads), len(r.stores)),
                            '%dL/%dS' % (len(t.loads), len(t.stores)),
                            '%s %s' % (rel, lab or '')))
            continue
        for kind, rl, tl in (('load', r.loads, t.loads),
                             ('store', r.stores, t.stores)):
            for _j, (rec, tec) in enumerate(zip(rl, tl)):
                ra, rd, rww = rec
                ta, td, tww = tec
                sub.note('memop-addr', t)
                if ra != ta:
                    gap = any(a in unestablished for a in range(ta, ta + 4))
                    rows.append(Row(guest, ex.seq, i, t.pc, 'memop-addr',
                                    RECON_GAP if (gap or reg_gaps)
                                    else WP_DEFECT,
                                    '0x%x' % ra, '0x%x' % ta, kind))
                    continue
                if tww and rww:
                    sub.note('memop-width', t)
                if tww and rww and tww != rww:
                    rows.append(Row(guest, ex.seq, i, t.pc, 'memop-width',
                                    WP_DEFECT, rww, tww, kind))
                if td is None or rd is None:
                    continue
                w = min(rww or 0, tww or 0)
                if not w:
                    continue
                sub.note('load-data' if kind == 'load' else 'store-data', t)
                m = (1 << (8 * w)) - 1
                if (rd & m) != (td & m):
                    unest = any(a in unestablished for a in range(ta, ta + w))
                    axis = 'load-data' if kind == 'load' else 'store-data'
                    rows.append(Row(guest, ex.seq, i, t.pc, axis,
                                    RECON_GAP if unest else WP_DEFECT,
                                    '0x%x' % rd, '0x%x' % td,
                                    'address never established by the wire'
                                    if unest else ''))
    return rows, compared, sub


def entry_state_rows(guest, ex, truth, reg_gaps):
    """Score the RECONSTRUCTED entry state against the correct-path truth.

    This is the axis that makes the gap attribution EVIDENCE rather than
    plausibility.  A register the reference never wrote is absent from
    ``truth`` and is counted apart -- the reference cannot say, so nobody may
    call it an agreement.
    """
    rows, stats = [], collections.Counter()
    sub = Subjects()
    for name, (val, w) in sorted(ex.regs.items()):
        if wp_seed.reg_to_mips(name) is None:
            stats['tracer-only-id'] += 1
            continue
        if name not in truth:
            stats['reference-silent'] += 1
            continue
        mask = (1 << (8 * w)) - 1 if 0 < w < 4 else 0xffffffff
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
        if name not in ex.regs:
            stats['not-reconstructed'] += 1
            reg_gaps.add(name)
            rows.append(Row(guest, ex.seq, -1, ex.start_pc, 'wp-entry-state',
                            RECON_GAP, '%s=0x%x' % (name, truth[name]),
                            'ABSENT', 'the wire never stated this register'))
    return rows, stats, sub


def excursion_gaps(ex, seedgaps):
    """What the reconstruction could not establish, as evidence.

    ``unestablished`` is every address this excursion touches that no ELF
    byte, no correct-path load datum and no correct-path store datum ever put
    a value under.  Computed from the excursion's own accesses, so it is a
    fact about this experiment rather than a whole-address-space claim.
    """
    unest = set()
    for ins in ex.insns:
        for addr, _d, size in ins.loads + ins.stores:
            for k in range(addr, addr + (size or 4)):
                if k not in ex.mem_src:
                    unest.add(k)
    return {'reg_gaps': set(), 'unestablished': unest, 'seedgaps': seedgaps}


def in_prologue(pc, boot):
    return boot[0] <= pc < boot[1] or \
        wp_seed.FPTAB_BASE <= pc < wp_seed.FPTAB_BASE + 128


def parse_injected(run, elf, boot):
    """The reference stream of one injected run, prologue EXCLUDED BY ADDRESS.

    ``gem5_ref.parse`` filters to the executable ranges of the ELF it is
    handed, and every segment of the injected image is marked executable
    precisely so that filter cannot delete a reference instruction the
    excursion really reached.  The prologue is then removed by its own address
    range -- never by counting how many instructions the assembler emitted.
    """
    if not os.path.exists(run.log):
        return []
    ins = gem5_ref.parse(run.log, elf, 'mipsel')
    return [i for i in ins if not in_prologue(i.pc, boot)]


# ------------------------------------------------------------------ driver
def process_guest(args, binary, cfg, env, guest, out):
    stem = os.path.join(out, os.path.basename(guest))
    trace = run_tracer(args.qemu, args.plugin, guest, stem, args.wpdepth)
    image, _xr, _entry, is64 = wp_image.load(guest)
    if is64:
        raise RuntimeError('%s is ELF64; the mipsel leg expects ELF32' % guest)
    exc, cp, tstats = wp_trace.build(args.decode, trace, image)

    stats = collections.Counter()
    rows = []
    tails = collections.Counter()
    sub = Subjects()

    # ---- correct-path ground truth for the entry state
    cprun = run_gem5(binary, cfg, env, guest, out,
                     os.path.basename(guest) + '.cp', 0)
    if not cprun.ok or GEM5_DONE not in (cprun.stopped or ''):
        raise RuntimeError(
            'gem5 did not run %s to completion on the CORRECT path '
            '(rc=%d stopped=%r panic=%r).  Without the correct-path ground '
            'truth the entry-state axis cannot be scored, and a '
            'RECONSTRUCTION-GAP could not be told apart from a WP-DEFECT.  '
            'Nothing is scored.'
            % (guest, cprun.rc, cprun.stopped, cprun.panic))
    refcp = gem5_ref.parse(cprun.log, guest, 'mipsel')
    snaps = ground_truth(refcp)
    pairs = align(refcp, cp)
    trc2ref = dict((t, r) for r, t in pairs if r is not None and t is not None)
    stats['cp-ref-insns'] = len(refcp)
    stats['cp-trc-insns'] = len(cp)
    stats['cp-aligned'] = len(trc2ref)

    distinct = wp_trace.dedupe(exc)
    stats['excursions-dynamic'] = len(exc)
    stats['excursions-distinct'] = len(distinct)
    todo = distinct if args.max <= 0 else distinct[:args.max]
    stats['excursions-run'] = len(todo)
    stats['excursions-stood-for'] = sum(n for _e, n in todo)

    for k, (ex, _mult) in enumerate(todo):
        tag = '%s.e%04d' % (os.path.basename(guest), k)
        touched = set()
        for ins in ex.insns:
            for addr, _d, size in ins.loads + ins.stores:
                touched.update(range(addr, addr + (size or 4)))
        stats['wp-insns-declared'] += len(ex.insns)
        try:
            elf, npro, seedgaps, unmapped, boot = wp_seed.build(
                out, tag, ex, extra_pages=touched, cc=args.cc)
        except wp_seed.SameRegionRefused as exc_:
            rows.append(Row(guest, ex.seq, 0, ex.start_pc, 'pc-sequence',
                            GEM5_LIMIT, 'not built', '0x%x' % ex.start_pc,
                            str(exc_)))
            stats['excursion-unbuildable'] += 1
            tails['excursion-unbuildable'] += len(ex.insns)
            continue
        # The cap is a BOUND, never the definition of what is compared: the
        # prologue is excluded by ADDRESS and the comparison walks the
        # excursion's own length.  Measured on this host, gem5 checks its
        # max-instruction limit before the tick that would retire the next
        # instruction, so a cap of exactly N leaves N-1 retired; the slack is
        # why a reference stopping one short cannot be manufactured by the
        # harness.  Overrunning is safe: an access past the reconstructed
        # image ends in a gem5 panic, which is caught and reported as a
        # GEM5-LIMIT carrying the panic text.
        run = run_gem5(binary, cfg, env, elf, out, tag,
                       npro + len(ex.insns) + args.cap_slack)
        ref = parse_injected(run, elf, boot)
        gapinfo = excursion_gaps(ex, seedgaps)

        ridx = trc2ref.get(ex.cp_index - 1)
        if ridx is not None:
            truth = snaps[ridx + 1]
            erows, estats, esub = entry_state_rows(guest, ex, truth,
                                                   gapinfo['reg_gaps'])
            sub.merge(esub)
            rows.extend(erows)
            for kk, vv in estats.items():
                stats['entry-state:' + kk] += vv
        else:
            stats['entry-state:unaligned'] += 1

        if run.panic is not None:
            rows.append(Row(guest, ex.seq, len(ref), ex.start_pc,
                            'pc-sequence', GEM5_LIMIT, run.panic,
                            '0x%x' % ex.start_pc,
                            'gem5 aborted inside the excursion; the %d '
                            'instructions it did retire are still compared'
                            % len(ref)))
            stats['excursion-panicked'] += 1
        if not ref:
            rows.append(Row(guest, ex.seq, 0, ex.start_pc, 'pc-sequence',
                            GEM5_LIMIT, run.panic or 'no guest-range commit',
                            '0x%x' % ex.start_pc,
                            'the injected run retired nothing outside the '
                            'prologue'))
            stats['excursion-empty-ref'] += 1
            tails['reference-retired-nothing'] += len(ex.insns)
            continue
        r, compared, csub = compare_excursion(guest, ex, ref, gapinfo,
                                              stopped=run.stopped)
        sub.merge(csub)
        rows.extend(r)
        stats['wp-insns-compared'] += compared
        if compared < len(ex.insns):
            why = ('reference-stopped-short' if len(ref) < len(ex.insns)
                   else 'pc-diverged')
            tails[why] += len(ex.insns) - compared
        if not r:
            stats['excursions-clean'] += 1
        stats['unestablished-bytes'] += len(gapinfo['unestablished'])
        for g in seedgaps:
            stats['seed-gap:' + g] += 1
        for u in unmapped:
            stats['unmappable-id:' + u] += 1
    for kk, vv in tstats.items():
        stats['trace:' + kk] += vv
    return rows, stats, tails, sub


def render(rows, stats, tails, sub):
    out = []
    w = out.append
    w('=' * 74)
    w('ARC 3 -- mipsel WRONG-PATH execution cross-check vs gem5')
    w('=' * 74)
    w('')
    w('The wrong-path arm had NO execution reference on this ISA.  Every')
    w('excursion below was rebuilt from the trace alone -- the REGFILE seed,')
    w('the destination snapshots, the correct-path load and store data and')
    w('the guest image -- injected into gem5 at the excursion\'s own PC, and')
    w('compared instruction for instruction.')
    w('')
    w('AXES: ' + ', '.join(AXES) + ', wp-entry-state')
    w('')
    hdr = '%-44s %10s' % ('measure', 'count')
    w(hdr)
    w('-' * len(hdr))
    for k in sorted(stats):
        w('%-44s %10d' % (k, stats[k]))
    w('')
    dec, cmpd = stats['wp-insns-declared'], stats['wp-insns-compared']
    w('=' * 74)
    w('THE DECLARED-VS-COMPARED IDENTITY.  A gap here is never left to be')
    w('rediscovered: every wrong-path instruction the tracer declared is')
    w('either compared against the reference or sits in a NAMED tail.')
    w('')
    w('  declared %d - compared %d = %d' % (dec, cmpd, dec - cmpd))
    for k in sorted(tails):
        w('  tail: %-38s %d' % (k, tails[k]))
    w('  %-44s %d' % ('sum of tails', sum(tails.values())))
    identity_ok = (dec - cmpd) == sum(tails.values())
    w('  IDENTITY %s'
      % ('HOLDS' if identity_ok else 'DOES NOT HOLD -- unexplained gap'))
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
    w('named rule from wp_rules_mipsel.MIPSEL_WP saying why the reference')
    w('cannot state the fact.  GEM5-LIMIT rows are the reference\'s own')
    w('silence or its own modelling artefact, named one by one and never')
    w('counted as agreement.')
    w('')
    lim = [r for r in rows if r.verdict == GEM5_LIMIT]
    if lim:
        w('EVERY GEM5-LIMIT, NAMED:')
        seen = collections.Counter()
        for r in lim:
            seen['%-14s %s' % (r.axis, r.detail or r.ref)] += 1
        for k, n in seen.most_common():
            w('  %4d  %s' % (n, k))
        w('')
    if not rows:
        w('NO DIVERGENCE on any axis, over every excursion run.  That is a')
        w('result only because the negative control (selftest_wp_mipsel.py)')
        w('shows every axis CAN fire; a check that cannot fire agrees forever.')
        w('')
    else:
        w('EVERY DISTINCT ROW, none summarised away:')
        w('')
        seen = collections.OrderedDict()
        for r in rows:
            key = (r.verdict, r.axis, os.path.basename(r.guest), r.pc,
                   str(r.ref), str(r.trc), r.detail)
            seen[key] = seen.get(key, 0) + 1
        for (verdict, axis, guest, pc, sref, strc, detail), n in seen.items():
            w('  %-20s %-16s %-8s pc=0x%x  x%d'
              % (verdict, axis, guest, pc, n))
            w('      ref=%s' % sref)
            w('      trc=%s' % strc)
            if detail:
                w('      %s' % detail)
        w('')
    return '\n'.join(out) + '\n', identity_ok


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('guest', nargs='+')
    ap.add_argument('--isa', default='mipsel', choices=('mipsel',))
    ap.add_argument('--gem5-dir', required=True)
    ap.add_argument('--qemu', required=True)
    ap.add_argument('--plugin', required=True)
    ap.add_argument('--decode', required=True)
    ap.add_argument('--cc', default='mipsel-linux-gnu-gcc')
    ap.add_argument('--wpdepth', type=int, default=16)
    ap.add_argument('--max', type=int, default=0,
                    help='distinct excursions per guest; <=0 for all')
    ap.add_argument('--cap-slack', type=int, default=4,
                    help='instructions added to gem5\'s --maxinsts bound; the '
                         'comparison never depends on it, since the prologue '
                         'is excluded by ADDRESS')
    ap.add_argument('--python-home')
    ap.add_argument('-o', '--outdir', required=True)
    ap.add_argument('--tsv')
    a = ap.parse_args()

    os.makedirs(a.outdir, exist_ok=True)
    try:
        binary, cfg, env, notes = gem5_prereqs(a.gem5_dir, a.outdir,
                                               python_home=a.python_home)
    except gem5_env.MissingPrerequisite as exc:
        sys.stderr.write('%s\n' % exc)
        sys.stderr.write('REFUSING TO SCORE: the execution reference did not '
                         'run.  No facet cell may be written from this '
                         'invocation.\n')
        return 3
    with open(os.path.join(a.outdir, 'PREREQ.txt'), 'w') as fh:
        fh.write('gem5 mipsel wrong-path leg -- prerequisites, as resolved\n')
        for n in notes:
            fh.write('  %s\n' % n)
        fh.write('  gem5.opt: %s\n  se.py:    %s\n' % (binary, cfg))

    rows, stats, tails = [], collections.Counter(), collections.Counter()
    sub = Subjects()
    for g in a.guest:
        try:
            r, s, t, f = process_guest(a, binary, cfg, env, g, a.outdir)
        except RuntimeError as exc:
            sys.stderr.write('%s\n' % exc)
            sys.stderr.write('REFUSING TO SCORE.\n')
            return 3
        rows.extend(r)
        stats.update(s)
        tails.update(t)
        sub.merge(f)
    sub.write_tsv(os.path.join(a.outdir, 'axis_subjects.tsv'),
                  AXES + ('wp-entry-state',))
    txt, identity_ok = render(rows, stats, tails, sub)
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
