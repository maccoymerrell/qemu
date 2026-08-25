"""
ARC 3 -- aarch64 / mipsel EXECUTION cross-check: the tracer against gem5, 1 to 1.

Runs one guest binary twice -- once under ``gem5.opt`` in syscall-emulation
mode with the ``Exec`` debug flags, once under ``qemu-<isa>`` with the ChampSim
Tracer plugin -- and compares the two records of the SAME run, instruction by
instruction.

Before this leg existed, aarch64 and mipsel had NO execution reference at all:
eight of the ten ``NONE`` cells in ``EXEC_VERDICT.md`` §2 were on these two
ISAs, and their memop addresses and data had never been compared with anything
that ran.  A static decoder cannot supply an address or a value, and ``irdf``
compares the tracer against QEMU's own translation, so neither can close those
cells.

AXES

    reg-dst-set     which architectural registers the instruction wrote
    reg-dst-value   the VALUE, on the registers both sides name
    flags-dst-set   the condition-code word, kept in its own partition
                    because gem5 splits AArch64's NZCV into three registers
                    and the tracer names one -- a granularity difference that
                    must not be allowed to dilute the register-file result
    memop-count     loads and stores per instruction
    memop-addr      the effective address of each
    memop-width     the number of bytes each moved
    store-data      the value written
    load-data       the value read

Every disagreeing row carries a DIRECTION and a CATEGORY through
``arc3_taxonomy``, so "N disagree" is never the result.  The headline is
TRACER-SUBSET + UNACCOUNTED.

Author: Maccoy Merrell.
"""
import argparse
import collections
import difflib
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, os.path.join(HERE, '..', 'riscv64', 'spike'))

import gem5_ref
import gem5_env
import tracer_log
from arc3_taxonomy import (set_relation, classify, render_crosstab,
                           render_conflicts, render_unaccounted, EQUAL,
                           SUBSET, SUPERSET, ORTHOGONAL, UNACCOUNTED)
from gem5_rules import gem5_exec_rule

AXES = ('reg-dst-set', 'reg-dst-value', 'flags-dst-set', 'fpsr-dst-set',
        'memop-count', 'memop-addr', 'memop-width', 'store-data', 'load-data')

QEMU_BIN = {'aarch64': 'qemu-aarch64', 'mipsel': 'qemu-mipsel',
            'x86_64': 'qemu-x86_64'}
#: gem5 build target per ISA.  ``x86_64`` is listed because the X86 gem5.opt is
#: BUILT and proven to run a real workload to completion -- but the reference
#: PARSER has no x86 register vocabulary yet (``gem5_ref.REGMAP``), so naming
#: it here buys a NAMED refusal instead of a KeyError three call levels down.
GEM5_BUILD = {'aarch64': 'ARM', 'mipsel': 'MIPS', 'x86_64': 'X86'}

DBG = ('ExecEnable,ExecUser,ExecKernel,ExecMicro,ExecEffAddr,ExecResult,'
       'ExecOpClass,ExecThread,ExecRegDelta,ExecFlags')


# ------------------------------------------------------------------ the runs
#: The line gem5 prints when the simulated program reached its own end.  A run
#: that does not print it did NOT run to completion, whatever its exit status
#: says: gem5 exits 0 after a tick limit, after ``m5 exit`` from anywhere, and
#: after a config-level abort that never entered the simulation loop.  Scoring
#: a truncated instruction stream against a complete one manufactures
#: TRACER-SUPERSET rows out of the harness's own failure, so this leg refuses
#: to score at all unless the reason is a natural termination.
GEM5_DONE = 'exiting with last active thread context'
_EXIT_RE = re.compile(r'^Exiting @ tick (\d+) because (.*)$', re.M)


def gem5_prereqs(gem5_dir, isa, cache_dir, python_home=None):
    """Every named thing this leg needs before a single guest is run.

    Raises ``gem5_env.MissingPrerequisite``, whose message names what is
    absent.  It never returns a partially usable environment, and it never
    lets the caller reach the point where a missing interpreter becomes a
    SIGSEGV instead of a sentence.
    """
    if isa not in gem5_ref.REGMAP:
        raise gem5_env.MissingPrerequisite(
            'MISSING PREREQUISITE: a gem5 register vocabulary for %s.\n'
            '  gem5_ref.REGMAP knows %s.  The %s gem5.opt builds and runs -- '
            'that half is done --\n  but without a REGMAP entry every gem5 '
            'register name would fall through as unmapped\n  and the '
            'comparison would score agreement it never established.\n'
            '  Fix: add the %s reader to gem5_ref.REGMAP, the way _arm_reg '
            'and _mips_reg are built.'
            % (isa, ', '.join(sorted(gem5_ref.REGMAP)), GEM5_BUILD[isa], isa))
    binary = gem5_env.require_file(
        os.path.join(gem5_dir, 'build', GEM5_BUILD[isa], 'gem5.opt'),
        'gem5.opt for the %s target (build it: '
        'scons build/%s/gem5.opt)' % (GEM5_BUILD[isa], GEM5_BUILD[isa]))
    cfg = gem5_env.require_file(
        os.path.join(gem5_dir, 'configs/deprecated/example/se.py'),
        'gem5 syscall-emulation config se.py')
    env, notes = gem5_env.gem5_environment(binary, cache_dir,
                                           python_home=python_home)

    # A POSITIVE start proof, and it has to be a deep one.  Resolving the
    # soname is not the same as gem5 being able to run: the failure this whole
    # module exists for happens AFTER a successful link and AFTER the embedded
    # interpreter is up.  ``gem5.opt --help`` returns 0 under the broken
    # loader path -- measured -- so a preflight built on it is INERT.
    # ``startproof.py`` calls ``m5.instantiate()``, which is what reaches
    # ``fixClockFrequency`` -> ``cprintf`` -> ``cp::Print::Print``, the frame
    # the segfault actually occupies.
    proof = gem5_env.require_file(os.path.join(HERE, 'startproof.py'),
                                  'the gem5 start-proof config script')
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
            '  The loader resolved every library it names, so this is an ABI '
            'mismatch inside a\n  RESOLVED one, not an absence -- gem5 gets '
            'as far as m5.instantiate() and faults at\n  '
            'src/base/cprintf.cc:55 reading std::cout\'s format state.  On '
            'this host the cause\n  is an LD_LIBRARY_PATH entry supplying a '
            'libstdc++ that is not the one gem5 was\n  compiled against '
            '(see gem5_env.ABI_LIBS).\n  Decisions taken:\n%s\n'
            '  gem5 said:\n%s'
            % (binary, how, '\n'.join('    ' + n for n in notes),
               '\n'.join('    ' + l for l in out.splitlines()[-12:])))
    return binary, cfg, env, notes


def require_complete_run(returncode, tail, log, guest):
    """Refuse, by name, unless gem5 ran the whole guest.

    Split out of ``run_gem5`` so it can be exercised against a REAL truncated
    gem5 run rather than a mocked one -- an instrument nobody has watched fire
    vouches for nothing.
    """
    if returncode < 0:
        raise gem5_env.MissingPrerequisite(
            'gem5 DIED ON SIGNAL %d running %s.  Nothing is scored.\n%s'
            % (-returncode, guest, tail[-1500:]))
    if returncode != 0:
        raise RuntimeError('gem5 exit %d on %s -- nothing is scored: %s'
                           % (returncode, guest, tail[-1500:]))
    if not os.path.exists(log):
        raise RuntimeError('gem5 wrote no %s for %s -- nothing is scored: %s'
                           % (log, guest, tail[-1500:]))

    m = _EXIT_RE.search(tail)
    if m is None:
        raise RuntimeError(
            'gem5 exited 0 on %s but never printed "Exiting @ tick ..." -- '
            'the simulation\n  loop was not reached and the trace is not a '
            'complete run.  Nothing is scored.\n%s' % (guest, tail[-1500:]))
    if GEM5_DONE not in m.group(2):
        raise RuntimeError(
            'gem5 stopped on %s for a reason that is NOT the guest reaching '
            'its own end:\n  "%s"\n  The instruction stream is truncated; '
            'scoring it would read as tracer superset.\n  Nothing is scored.'
            % (guest, m.group(2)))
    if os.path.getsize(log) == 0:
        raise RuntimeError(
            'gem5 ran %s to completion but wrote an EMPTY exec.log -- the '
            'debug flags produced\n  no reference. Nothing is scored.' % guest)


def run_gem5(binary, cfg, env, isa, guest, outdir):
    d = os.path.join(outdir, os.path.basename(guest) + '.g5')
    p = subprocess.run([binary, '-d', d, '--debug-flags=' + DBG,
                        '--debug-file=exec.log', cfg,
                        '--cpu-type=AtomicSimpleCPU', '-c', guest],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       env=env)
    tail = p.stdout.decode('utf-8', 'replace')
    with open(os.path.join(outdir,
                           os.path.basename(guest) + '.gem5.out'), 'w') as fh:
        fh.write(tail)
    log = os.path.join(d, 'exec.log')

    require_complete_run(p.returncode, tail, log, guest)
    return log


def run_tracer(qemu_dir, isa, guest, outdir):
    qemu = os.path.join(qemu_dir, 'build', QEMU_BIN[isa])
    plugin = os.path.join(qemu_dir,
                          'build/contrib/plugins/libchampsim_tracer.so')
    stem = os.path.join(outdir, os.path.basename(guest))
    p = subprocess.run(
        [qemu, '-plugin',
         '%s,outfile=%s,memdata=1,regdata=1,wp=0' % (plugin, stem), guest],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        raise RuntimeError('qemu exit %d: %s'
                           % (p.returncode,
                              p.stdout.decode('utf-8', 'replace')[-800:]))
    return stem + '.cst'


# --------------------------------------------------------------- the mapping
FLAG_IDS = ('REG_FLAGS',)
FPSR_IDS = ('REG_FCSR',)


def split_regs(writes):
    """[(id, value, width)] -> ({arch id: (value, width)}, {flag id: ...}).

    A register written more than once by the same architectural instruction
    (gem5 cracks such an instruction into several micro-ops) keeps the LAST
    value, which is the architectural result.
    """
    arch, flags, fpsr = {}, {}, {}
    for name, val, w in writes:
        if name in FLAG_IDS:
            flags[name] = (val, w)
        elif name in FPSR_IDS:
            fpsr[name] = (val, w)
        else:
            arch[name] = (val, w)
    return arch, flags, fpsr


def mask(val, w):
    """The value as the field's own width states it.

    w == 0 means the width was NOT stated; masking there would force the value
    to 0 and manufacture agreement out of the harness's arithmetic.
    """
    return val & ((1 << (8 * w)) - 1) if 0 < w < 8 else val


def render(v):
    """A stable text form for a row's two sides.

    ``repr`` of a ``set``/``frozenset`` follows hash order, which CPython
    randomises per process, so two identical measurements produced TSVs that
    differed on 24 of 49 aarch64 rows for no reason but ``PYTHONHASHSEED``.
    A reference nobody can diff against the last run is a reference nobody can
    check.  Sorting by the printed form makes the ordering a property of the
    content.
    """
    if isinstance(v, (set, frozenset)):
        return '{%s}' % ', '.join(sorted(render(x) for x in v))
    if isinstance(v, tuple):
        return '(%s)' % ', '.join(render(x) for x in v)
    if isinstance(v, list):
        return '[%s]' % ', '.join(render(x) for x in v)
    return repr(v)


Disagreement = collections.namedtuple(
    'Disagreement', 'pc axis ref trc relation label')


def _set_row(pc, axis, ref, trc, label=None):
    if ref == trc:
        return None
    rel = set_relation((), sorted(map(repr, ref)), (), sorted(map(repr, trc)))
    if rel == EQUAL:
        return None
    return Disagreement(pc, axis, ref, trc, rel, label)


def compare_insn(r, t, isa):
    """One aligned instruction -> its disagreeing axes (possibly none)."""
    rows = []
    ra, rf, rp = split_regs(r.writes)
    ta, tf, tp = split_regs(t.writes)

    # --- reg-dst-set
    row = _set_row(r.pc, 'reg-dst-set', frozenset(ra), frozenset(ta))
    if row is not None:
        only_ref = frozenset(ra) - frozenset(ta)
        only_trc = frozenset(ta) - frozenset(ra)
        if only_ref and not only_trc and all(n == 'REG_ZERO' for n in only_ref):
            row = row._replace(label='REF-NAMES-ZERO-DEST')
        elif only_trc and not only_ref and \
                all(n == 'REG_ZERO' for n in only_trc):
            row = row._replace(label='REF-DISCARDS-ZERO-DEST')
        elif only_ref and not only_trc and all(n == 'REG_SP' for n in only_ref):
            row = row._replace(label='REF-NAMES-SP-WRITEBACK')
        elif (only_trc and not only_ref and
              only_trc == frozenset(('REG_PRED0',)) and
              'REG_FCSR' in rp):
            # The FP condition-code bit.  gem5 keeps it inside FCSR and
            # reports only the FCSR write; the tracer names FCSR AND gives
            # the condition code an id of its own, which is the finer -- and
            # for a dependence model the more useful -- spelling of the same
            # bit.
            row = row._replace(label='FPCC-GRANULARITY')
        elif (only_trc and not only_ref and
              all(n.startswith('REG_ACC') for n in only_trc)):
            # gem5's MIPS accumulator writes do not reach the ExeTracer at
            # all: `mult`, `div`, `madd`, `mthi`, `mtlo` report NO
            # destination.  The architecture writes HI/LO and the tracer
            # names them.
            row = row._replace(label='REF-NO-ACC-WRITE')
        elif (only_trc and not only_ref and r.ctrl and
              only_trc == frozenset(('REG_GPR1',))):
            # A destination register on a MIPS conditional branch.  The
            # instruction has none; the reference names none; the tracer
            # publishes a write to $at.  Carrying MORE is not a defence when
            # what is carried did not happen.
            row = row._replace(label='TRC-INVENTED-BRANCH-DEST')
        elif (only_ref and not only_trc and
              all(n.startswith('REG_VEC') for n in only_ref) and
              all(n.startswith('REG_VEC') for n in ta) and
              len(ra) == len(ta) + (len(ta) & 1)):
            # gem5's NEON load/store micro-ops write vector registers in
            # PAIRS: a form with an odd number of registers names one more
            # than the instruction has.  Measured, not assumed -- the label
            # is emitted only when the reference count is exactly the tracer
            # count rounded up to even and every extra name is a vector
            # register.
            row = row._replace(label='REF-NEON-PAIRWISE-DEST')
        rows.append(row)

    # --- reg-dst-value, on the registers BOTH sides name and BOTH valued
    both = frozenset(ra) & frozenset(ta)
    bad = []
    for n in sorted(both):
        rv, rw = ra[n]
        tv, tw = ta[n]
        if rw == 0 or tw == 0:
            continue                      # no value on one side: not a compare
        if mask(rv, min(rw, tw)) != mask(tv, min(rw, tw)):
            bad.append((n, rv, tv))
    if bad:
        # A destination whose value the reference SOURCED from an
        # implementation-defined identification register or from a
        # free-running counter cannot agree between two different modelled
        # CPUs, and neither tool is wrong.  Decided from the reference's own
        # source set, not from the mnemonic.
        implsrc = any(s_ in ('REG_SYSID', 'REG_SYSTIMER') for s_ in r.srcs)
        # An FP CONTROL word read into a general register: FCSR's
        # implementation-defined bits (flush-to-zero, the condition codes, the
        # cause field) are not the same on two different modelled FPUs, and
        # the reference is not wrong about its own.
        if not implsrc and 'REG_FCSR' in r.srcs and \
                all(n.startswith('REG_GPR') for n, _, _ in bad):
            implsrc = True
        rows.append(Disagreement(
            r.pc, 'reg-dst-value',
            frozenset((n, v) for n, v, _ in bad),
            frozenset((n, v) for n, _, v in bad),
            SUBSET,
            'IMPLDEF-MACHINE-VALUE' if implsrc else 'VALUE-MISMATCH'))

    # --- flags partition
    row = _set_row(r.pc, 'flags-dst-set', frozenset(rf), frozenset(tf))
    if row is not None:
        rows.append(row._replace(label='FLAGS-GRANULARITY'))

    # --- FP status partition.  Kept apart from the register file for the
    # same reason the flags are: gem5 does not model FPSCR as one register.
    # It splits it into `fpscr_exc`, `fpscr_qc` and the rest, writes
    # `fpscr_exc` on every FP operation whether or not a flag changed, and
    # publishes only that sub-field's value.  Comparing that against the
    # tracer's whole FPSR word is a granularity question, not a value one,
    # and it must not be allowed to dilute either result.
    row = _set_row(r.pc, 'fpsr-dst-set', frozenset(rp), frozenset(tp))
    if row is not None:
        rows.append(row._replace(label='FPSR-GRANULARITY'))

    # ------------------------------------------------------------- memops
    #
    # The mechanism is decided ONCE, from the two access lists, and the same
    # label is then carried by every axis the mechanism makes disagree.  A
    # per-axis label would charge one instruction to three different
    # mechanisms and let the same fact be counted three ways.
    def byteset(recs, tag):
        out = set()
        for a, _, sz in recs:
            for k in range(max(sz, 1)):
                out.add((tag, a + k))
        return out

    rb = byteset(r.loads, 'L') | byteset(r.stores, 'S')
    tb = byteset(t.loads, 'L') | byteset(t.stores, 'S')
    rcnt = (len(r.loads), len(r.stores))
    tcnt = (len(t.loads), len(t.stores))
    rw = (sum(sz for _, _, sz in r.loads), sum(sz for _, _, sz in r.stores))
    tw = (sum(sz for _, _, sz in t.loads), sum(sz for _, _, sz in t.stores))

    mech = None
    if (not r.loads and not r.stores) and (t.loads or t.stores) and \
            all(sz == 0 for _, _, sz in t.loads + t.stores):
        # The tracer mints a zero-width memop for a HINT the reference does
        # not execute at all.  gem5's MIPS says so out loud -- "Prefetching
        # not implemented for MIPS", "instruction 'synci' unimplemented" --
        # so there is nothing on the reference side to compare against.
        mech = 'HINT-MEMOP-REF-SILENT'
    elif rb == tb and rcnt != tcnt:
        # Byte-for-byte the same accesses, split into a different number of
        # requests.  Neither tool is wrong about what the instruction touched.
        mech = 'SAME-BYTES-DIFFERENT-SPLIT'
    elif (not r.loads and t.loads and
          set(a for a, _, _ in t.loads) <= set(a for a, _, _ in r.stores) and
          [(a, sz) for a, _, sz in t.stores] == [(a, sz) for a, _, sz in
                                                 r.stores]):
        # The tracer records a LOAD the reference does not, at the address of
        # the store the same instruction makes, and agrees on the store.
        # That is a store-exclusive lowered onto a compare-exchange, which
        # really reads.  The riscv64 leg found the same shape on `sc`.
        mech = 'QEMU-EXCLUSIVE-CMPXCHG'
    elif (r.loads or r.stores) and \
            all(sz == 0 for _, _, sz in t.loads + t.stores) and \
            all(sz > 0 for _, _, sz in r.loads + r.stores) and \
            set(a for a, _, _ in t.loads + t.stores) == \
            set(a for a, _, _ in r.loads + r.stores):
        # Same address, and the tracer states NO WIDTH for it.  A prefetch:
        # the access size is IMPLEMENTATION DEFINED, gem5 models 8 bytes and
        # the tracer publishes 0, so a consumer cannot size the access.
        mech = 'MEMOP-WIDTH-UNSTATED'

    if rcnt != tcnt:
        if tcnt[0] >= rcnt[0] and tcnt[1] >= rcnt[1]:
            rel = SUPERSET
        elif tcnt[0] <= rcnt[0] and tcnt[1] <= rcnt[1]:
            rel = SUBSET
        else:
            rel = ORTHOGONAL
        rows.append(Disagreement(r.pc, 'memop-count', rcnt, tcnt, rel, mech))

    row = _set_row(r.pc, 'memop-addr', rb, tb)
    if row is not None:
        rows.append(row._replace(ref=(len(rb),), trc=(len(tb),), label=mech))

    if rw != tw:
        if tw[0] >= rw[0] and tw[1] >= rw[1]:
            rel = SUPERSET
        elif tw[0] <= rw[0] and tw[1] <= rw[1]:
            rel = SUBSET
        else:
            rel = ORTHOGONAL
        rows.append(Disagreement(r.pc, 'memop-width', rw, tw, rel, mech))

    # --- store-data / load-data, per BYTE, for the same reason as memop-addr
    def bytemap(recs):
        out = {}
        for a, d, s in recs:
            if d is None or s == 0 or s > 8:
                continue
            for k in range(s):
                out[a + k] = (d >> (8 * k)) & 0xff
        return out
    for axis, rrec, trec in (('store-data', r.stores, t.stores),
                             ('load-data', r.loads, t.loads)):
        rm, tm = bytemap(rrec), bytemap(trec)
        both_b = frozenset(rm) & frozenset(tm)
        diff = frozenset(b for b in both_b if rm[b] != tm[b])
        if diff:
            rows.append(Disagreement(
                r.pc, axis,
                frozenset((b, rm[b]) for b in diff),
                frozenset((b, tm[b]) for b in diff),
                SUBSET, 'VALUE-MISMATCH'))
    return rows


# ---------------------------------------------------------------- alignment
def align(ref, trc):
    rk = [(i.pc, i.bits) for i in ref]
    tk = [(i.pc, i.bits) for i in trc]
    sm = difflib.SequenceMatcher(a=rk, b=tk, autojunk=False)
    pairs, ref_only, trc_only = [], [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            for k in range(i2 - i1):
                pairs.append((ref[i1 + k], trc[j1 + k]))
        else:
            ref_only.extend(ref[i1:i2])
            trc_only.extend(trc[j1:j2])
    return pairs, ref_only, trc_only


# ------------------------------------------------------------------- report
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('guest', nargs='+')
    ap.add_argument('--isa', required=True,
                    choices=tuple(sorted(GEM5_BUILD)))
    ap.add_argument('--gem5-dir', required=True)
    ap.add_argument('--qemu-dir', required=True)
    ap.add_argument('--decode', required=True)
    ap.add_argument('-o', '--outdir', required=True)
    ap.add_argument('--tsv')
    ap.add_argument('--python-home', metavar='PREFIX',
                    help='installation prefix of the interpreter gem5 was '
                         'BUILT against; its lib/ must hold the libpython '
                         'soname in gem5.opt\'s DT_NEEDED.  Only its '
                         'libpython is exposed to the loader -- see '
                         'gem5_env for why the whole lib/ must not be.')
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    try:
        binary, cfg, g5env, notes = gem5_prereqs(
            args.gem5_dir, args.isa, args.outdir,
            python_home=args.python_home)
    except gem5_env.MissingPrerequisite as exc:
        sys.stderr.write('%s\n' % exc)
        sys.stderr.write('REFUSING TO SCORE: the execution reference did not '
                         'run.  No facet cell may be\n'
                         'written from this invocation.\n')
        return 3
    with open(os.path.join(args.outdir, 'PREREQ.txt'), 'w') as fh:
        fh.write('gem5 execution leg -- prerequisites, as resolved\n')
        for n in notes:
            fh.write('  %s\n' % n)
        fh.write('  gem5.opt: %s\n  se.py:    %s\n' % (binary, cfg))
    all_rows, per_guest, unaligned = [], [], []
    totals = collections.Counter()
    unmapped = collections.Counter()
    dropped = {}
    axis_ok = collections.Counter()
    axis_n = collections.Counter()
    raw = []

    for guest in args.guest:
        try:
            log = run_gem5(binary, cfg, g5env, args.isa, guest, args.outdir)
        except (gem5_env.MissingPrerequisite, RuntimeError) as exc:
            sys.stderr.write('%s\n' % exc)
            sys.stderr.write('REFUSING TO SCORE: gem5 did not run %s to '
                             'completion.  No facet cell may be\n'
                             'written from this invocation.\n'
                             % os.path.basename(guest))
            return 3
        trace = run_tracer(args.qemu_dir, args.isa, guest, args.outdir)
        ref = gem5_ref.parse(log, guest, args.isa,
                             gem5_dir=args.gem5_dir,
                             dropped=dropped)
        # tracer_log.parse also returns the source-value provenance the
        # riscv64 leg reports; this leg does not measure that axis.
        trc, _ = tracer_log.parse(args.decode, trace)
        pairs, ref_only, trc_only = align(ref, trc)
        per_guest.append((os.path.basename(guest), len(ref), len(trc),
                          len(pairs), len(ref_only), len(trc_only)))
        for ins in ref_only:
            unaligned.append((os.path.basename(guest), ins.pc, 'REF-ONLY',
                              ins.disas))
        for ins in trc_only:
            unaligned.append((os.path.basename(guest), ins.pc, 'TRC-ONLY', ''))

        totals['ref_insns'] += len(ref)
        totals['trc_insns'] += len(trc)
        totals['aligned'] += len(pairs)
        for r, t in pairs:
            for u in r.unmapped:
                unmapped[u] += 1
            totals['ref_writes'] += len(r.writes)
            totals['trc_writes'] += len(t.writes)
            totals['ref_loads'] += len(r.loads)
            totals['trc_loads'] += len(t.loads)
            totals['ref_stores'] += len(r.stores)
            totals['trc_stores'] += len(t.stores)
            bad = compare_insn(r, t, args.isa)
            hit = set(d.axis for d in bad)
            for ax in AXES:
                axis_n[ax] += 1
                if ax not in hit:
                    axis_ok[ax] += 1
            for d in bad:
                lab = d.label or 'NO-LABEL:' + d.axis
                rule = gem5_exec_rule(d.label)
                row = classify('%s:0x%x' % (os.path.basename(guest), d.pc),
                               d.axis, lab, d.relation, rule)
                all_rows.append(row)
                raw.append((os.path.basename(guest), d.pc, d.axis, d.relation,
                            d.label or '', render(d.ref), render(d.trc),
                            r.disas))

    out = []
    out.append('ARC 3 -- %s EXECUTION cross-check: ChampSim Tracer vs gem5'
               % args.isa)
    out.append('=' * 72)
    out.append('')
    out.append('REFERENCE   gem5 syscall-emulation mode, AtomicSimpleCPU,')
    out.append('            --debug-flags=%s' % DBG)
    out.append('            An execution reference: gem5 decodes and executes')
    out.append('            the guest ISA itself.  No part of QEMU is involved.')
    out.append('')
    hdr = '%-24s %8s %8s %8s %9s %9s' % ('guest', 'ref', 'tracer', 'aligned',
                                         'ref-only', 'trc-only')
    out.append(hdr)
    for g in per_guest:
        out.append('%-24s %8d %8d %8d %9d %9d' % g)
    out.append('')
    out.append('TOTALS')
    for k in ('ref_insns', 'trc_insns', 'aligned', 'ref_writes', 'trc_writes',
              'ref_loads', 'trc_loads', 'ref_stores', 'trc_stores'):
        out.append('  %-24s %8d' % (k, totals[k]))
    out.append('')
    out.append('PER-AXIS AGREEMENT (over %d aligned instructions)'
               % totals['aligned'])
    for ax in AXES:
        n, ok = axis_n[ax], axis_ok[ax]
        out.append('  %-16s %7d / %-7d   %s'
                   % (ax, ok, n,
                      'ALL AGREE' if ok == n else '%d disagree' % (n - ok)))
    out.append('')
    if unaligned:
        out.append('UNALIGNED -- %d' % len(unaligned))
        for g, pc, kind, d in unaligned[:40]:
            out.append('  %-16s 0x%08x  %-9s %s' % (g, pc, kind, d))
        out.append('')
    if unmapped:
        out.append('REFERENCE TOKENS NO VOCABULARY RULE REACHES')
        out.append('  A gem5 register class or an access with no direction '
                   'bit.  Counted, never')
        out.append('  folded into agreement.')
        for k, n in unmapped.most_common(30):
            out.append('    %8d  %s' % (n, k))
        out.append('')
    if gem5_ref._ARM_MISC_CONFLICTS:
        out.append('MISC-REGISTER NAME TABLE CONFLICTS -- gem5\'s transcribed '
                   'miscRegName[] disagrees')
        out.append('  with gem5\'s own disassembly at these indices.  The '
                   'disassembly wins; the conflict')
        out.append('  is reported rather than absorbed.')
        for k, (a, b) in sorted(gem5_ref._ARM_MISC_CONFLICTS.items()):
            out.append('    idx %-5d table=%-20s disassembly=%s' % (k, a, b))
        out.append('')
    if dropped:
        out.append('REFERENCE-INTERNAL REGISTERS DROPPED (not architectural '
                   'state; see gem5_ref.INTERNAL)')
        out.append('  Counted so that an exclusion which stops matching '
                   'cannot go unnoticed.')
        for k, n in sorted(dropped.items(), key=lambda kv: -kv[1]):
            out.append('    %8d  %s' % (n, k))
        out.append('')
    out.append(render_crosstab(all_rows,
                               'CROSS-TABULATION -- %d disagreeing rows'
                               % len(all_rows)))
    out.append('')
    out.append(render_conflicts(all_rows))
    out.append('')
    out.append(render_unaccounted(all_rows))

    txt = '\n'.join(out) + '\n'
    with open(os.path.join(args.outdir, 'REPORT.txt'), 'w') as fh:
        fh.write(txt)
    sys.stdout.write(txt)

    if args.tsv:
        with open(args.tsv, 'w') as fh:
            fh.write('guest\tpc\taxis\trelation\tlabel\tref\ttrc\tdisas\n')
            for r in raw:
                fh.write('%s\t0x%x\t%s\t%s\t%s\t%s\t%s\t%s\n' % r)

    nsub = sum(1 for r in all_rows if r.direction == SUBSET)
    nun = sum(1 for r in all_rows if r.direction == UNACCOUNTED)
    sys.stderr.write('SUBSET=%d UNACCOUNTED=%d\n' % (nsub, nun))
    return 1 if (nsub or nun) else 0


if __name__ == '__main__':
    sys.exit(main())
