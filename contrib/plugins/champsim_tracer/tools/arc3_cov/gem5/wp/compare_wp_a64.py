"""
ARC 3 -- aarch64 WRONG-PATH execution cross-check: the tracer against gem5.

The wrong path had no execution reference on any ISA until the riscv64 leg
against Spike; the maintainer's direction for the remaining three was that
"the remaining 3 ISAs can have their wrong-paths verified by gem5".  This is
that leg for aarch64, and it mirrors the riscv64 one fact for fact.

    trace ---> reconstructed regfile + memory ---> injected static ELF
                                                        |
                                                      gem5
                                                        |
    tracer's WP record  <----- compared against ----- what the ISA does

The architectural state at the excursion's entry is rebuilt from the trace
ALONE -- the REGFILE seed plus the DST_REG snapshots replayed forward, which is
the model ``docs/format.rst`` §5.4 mandates for a consumer -- and memory from
the guest ELF image plus the datum every correct-path load returned and every
correct-path store wrote.  It is then installed as INSTRUCTIONS (see
``wp_seed_a64``), because gem5 has no interface for setting a register file.

THE VERDICTS, AND WHY THEY MUST NOT BE BLURRED
==============================================
  WP-DEFECT           the excursion executed something the architecture would
                      not, from a starting state the trace fully specified.
  RECONSTRUCTION-GAP  the trace does not carry enough state to rebuild the
                      starting point, so the two runs began from different
                      machines.  A finding about what the WIRE drops.
  GEM5-LIMIT          the reference cannot state the fact -- it stopped before
                      the excursion did, it panicked on an instruction class,
                      or its own record names something the architecture does
                      not.  Named with the reason, never quoted as agreement.
  TRACER-SUPERSET     we record a fact the reference omits, and a NAMED rule
                      says why.  COVERED: "we record more" is the project's
                      goal; "we record less" is its one disqualifying failure,
                      and the measured direction is what tells them apart.
  UNACCOUNTED         a disagreement nobody has explained.  MUST BE 0.

The gap verdict is assigned from EVIDENCE, never from plausibility: a register
is a gap only where the ``wp-entry-state`` axis measures the reconstruction
wrong against the correct-path run's own ground truth, and an address only
where no ELF byte, no correct-path load datum and no correct-path store datum
ever established it.

WHY THE SOURCE AXES ARE PARTITIONED
===================================
gem5's ``SR=`` is a MICRO-OP source list, not an architectural read set: it
threads ``cpsr`` through essentially every instruction and the FP-enable misc
register through every vector one.  Those are machine-state reads, and mixing
them into the register-file comparison would drown it -- the same reason the
correct-path leg keeps ``flags-dst-set`` and ``fpsr-dst-set`` in their own
partitions.  The partition is taken on gem5's own register CLASS and not on
the mapped id, because ``condition_code:0`` and ``miscellaneous:0`` both map to
``REG_FLAGS`` while meaning entirely different things.  Three partitions, each
saying what it covers:

    reg-src-set    the general and vector register FILE
    flags-src-set  the condition-code word, as gem5's own cc registers state it
    sys-src-set    everything gem5 reads out of its misc file

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
sys.path.insert(0, os.path.join(_HERE, '..'))
sys.path.insert(0, os.path.join(_HERE, '..', '..'))
sys.path.insert(0, os.path.join(_HERE, '..', '..', 'riscv64', 'spike', 'wp'))

import elfimage                                              # noqa: E402
import wp_trace                                              # noqa: E402
import wp_seed_a64                                           # noqa: E402
import gem5_ref                                              # noqa: E402
import gem5_env                                              # noqa: E402
from arc3_taxonomy import (set_relation, EQUAL, SUPERSET,
                           SUBSET)                           # noqa: E402
from gem5_rules import gem5_exec_rule                        # noqa: E402
from axis_subjects import Subjects                           # noqa: E402

#: every fact this leg checks about a wrong-path instruction.  Named in full
#: so a report can never quote a subset as if it were the whole comparison.
AXES = ('pc-sequence', 'insn-bits', 'reg-dst-set', 'reg-dst-value',
        'flags-dst-set', 'fpsr-dst-set', 'reg-src-set', 'flags-src-set',
        'sys-src-set', 'memop-count', 'memop-addr', 'memop-width',
        'load-data', 'store-data')

WP_DEFECT = 'WP-DEFECT'
RECON_GAP = 'RECONSTRUCTION-GAP'
GEM5_LIMIT = 'GEM5-LIMIT'
SUPERSET_OK = 'TRACER-SUPERSET'
UNACCOUNTED = 'UNACCOUNTED'
VERDICTS = (WP_DEFECT, RECON_GAP, GEM5_LIMIT, SUPERSET_OK, UNACCOUNTED)

Row = collections.namedtuple(
    'Row', 'guest seq idx pc axis verdict ref trc detail')

DBG = ('ExecEnable,ExecUser,ExecKernel,ExecMicro,ExecEffAddr,ExecResult,'
       'ExecOpClass,ExecThread,ExecRegDelta,ExecFlags')

#: An injected wrong-path run is EXPECTED to end abnormally -- an excursion is
#: not a program.  So unlike the correct-path leg this one does not refuse when
#: gem5 stops early; it RECORDS the reason and charges the uncompared tail to
#: GEM5-LIMIT under that name.  What it must never do is treat the reference's
#: own silence as agreement, which is what the tail accounting prevents.
_EXIT_RE = re.compile(r'^Exiting @ tick (\d+) because (.*)$', re.M)
#: gem5 prefixes its abort with the source location that raised it, and that
#: location IS the useful half of the name -- `src/sim/faults.cc:103: panic:
#: ... Page table fault when accessing virtual address 0x400` is what an
#: AArch64 cache-maintenance instruction does to SE mode.  The whole line is
#: captured, so a GEM5-LIMIT row quotes gem5's own text rather than a
#: paraphrase of it.
_PANIC_RE = re.compile(r'^(\S+:\d+: )?(?:panic|fatal): .*$', re.M)
_SR = re.compile(r'\sSR=\[([^\]]*)\]')

FLAG_IDS = frozenset(('REG_FLAGS',))
FPSR_IDS = frozenset(('REG_FCSR',))


def _is_sys(name):
    """A fact gem5 keeps in its MISC file, or an id no vocabulary rule reached."""
    return (name.startswith('MISC:') or name.startswith('REG_SYS') or
            name in FPSR_IDS or name == 'REG_TLS')


# --------------------------------------------- reference sources, BY CLASS
def ref_source_classes(logpath, elfpath):
    """[(arch-file ids, condition-code ids, misc-file ids)] per instruction.

    gem5_ref.parse discards the register CLASS before the caller sees it, and
    the class is exactly what this partition has to be taken on: reading the
    mapped id instead would charge gem5's blanket ``cpsr`` sourcing to the
    same bucket as a real NZCV read and report machine-state noise as dropped
    register sources.  The walker replicates gem5_ref's micro-op folding rule
    and is CHECKED against it by ``parse_ref``.
    """
    ranges = gem5_ref.exec_ranges(elfpath)
    mapper = gem5_ref.REGMAP['aarch64']
    out, cur, prev_upc = [], None, None
    for line in open(logpath, 'r', errors='replace'):
        m = gem5_ref._LINE.match(line)
        if not m:
            continue
        pc = int(m.group(2), 16)
        upc = int(m.group(3)) if m.group(3) is not None else None
        if not any(lo <= pc < hi for lo, hi in ranges):
            continue
        if (cur is None or cur[0] != pc or upc is None or prev_upc is None or
                upc != prev_upc + 1):
            cur = [pc, set(), set(), set()]
            out.append(cur)
        prev_upc = upc
        msr = _SR.search(m.group(4))
        if not msr:
            continue
        for tok in msr.group(1).split(','):
            tok = tok.strip()
            if not tok:
                continue
            cls, _, idx = tok.rpartition(':')
            try:
                g = mapper(cls, int(idx))
            except ValueError:
                g = None
            if g is None or g is gem5_ref.INTERNAL:
                continue
            if cls == 'condition_code':
                cur[2].add(g)
            elif cls == 'miscellaneous':
                cur[3].add(g)
            else:
                cur[1].add(g)
    return [(a, c, mm) for _pc, a, c, mm in out]


def parse_ref(logpath, elfpath, gem5_dir, sel=None):
    """gem5's log -> [(Insn, arch srcs, cc srcs, misc srcs)].

    The two walkers are CHECKED against each other rather than trusted to
    agree: if they ever fold micro-ops differently the source sets would slide
    silently against the instructions they belong to and every source axis
    would report noise.
    """
    ins = gem5_ref.parse(logpath, elfpath, 'aarch64', gem5_dir=gem5_dir)
    cls = ref_source_classes(logpath, elfpath)
    if len(ins) != len(cls):
        raise RuntimeError(
            'the two reference walkers disagree about how many architectural '
            'instructions %s holds (%d vs %d); the source classes cannot be '
            'attached to the instructions they came from'
            % (logpath, len(ins), len(cls)))
    rows = list(zip(ins, cls))
    if sel is not None:
        rows = [(i, c) for i, c in rows if sel(i.pc)]
    return [(i, c[0], c[1], c[2]) for i, c in rows]


# ------------------------------------------------------------------ the runs
def run_tracer(qemu, plugin, guest, out, wpdepth):
    trace = out + '.cst'
    opt = ('%s,outfile=%s,memdata=1,regdata=1,wpdepth=%d'
           % (plugin, out, wpdepth))
    p = subprocess.run([qemu, '-plugin', opt, guest],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        raise RuntimeError('qemu exit %d: %s'
                           % (p.returncode,
                              p.stdout.decode('utf-8', 'replace')[-800:]))
    if not os.path.exists(trace):
        raise RuntimeError('tracer produced no %s' % trace)
    return trace


def run_gem5(binary, cfg, env, elf, outdir, tag, maxinsts):
    """-> (exec.log path, the reason gem5 stopped, whether it panicked)."""
    d = os.path.join(outdir, tag + '.g5')
    cmd = [binary, '-d', d, '--debug-flags=' + DBG, '--debug-file=exec.log',
           cfg, '--cpu-type=AtomicSimpleCPU']
    if maxinsts:
        cmd += ['-I', str(maxinsts)]
    cmd += ['-c', elf]
    p = subprocess.run(cmd, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, env=env)
    tail = p.stdout.decode('utf-8', 'replace')
    with open(os.path.join(outdir, tag + '.gem5.out'), 'w') as fh:
        fh.write(tail)
    log = os.path.join(d, 'exec.log')
    pan = _PANIC_RE.search(tail)
    if pan is not None:
        return log, pan.group(0).strip()[:400], True
    m = _EXIT_RE.search(tail)
    reason = m.group(2).strip() if m else (
        'gem5 exited %d printing no reason' % p.returncode)
    if not os.path.exists(log):
        raise RuntimeError('gem5 wrote no exec.log for %s (%s)' % (tag, reason))
    return log, reason, False


def prereqs(gem5_dir, cache_dir, python_home=None):
    """The named prerequisites, reusing the correct-path leg's resolver.

    gem5.opt embeds the CPython that built it and carries no RUNPATH; the
    obvious remedy for that (the whole Anaconda lib on LD_LIBRARY_PATH) makes
    gem5 SIGSEGV.  gem5_env owns that whole story, and the start proof is a
    real ``m5.instantiate()`` because ``--help`` returns 0 even when gem5
    cannot run.
    """
    binary = gem5_env.require_file(
        os.path.join(gem5_dir, 'build/ARM/gem5.opt'),
        'gem5.opt for the ARM target (build it: scons build/ARM/gem5.opt)')
    cfg = gem5_env.require_file(
        os.path.join(gem5_dir, 'configs/deprecated/example/se.py'),
        'gem5 syscall-emulation config se.py')
    env, notes = gem5_env.gem5_environment(binary, cache_dir,
                                           python_home=python_home)
    proof = gem5_env.require_file(
        os.path.join(_HERE, '..', 'startproof.py'),
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
            '  Decisions taken:\n%s\n  gem5 said:\n%s'
            % (binary, how, '\n'.join('    ' + n for n in notes),
               '\n'.join('    ' + l for l in out.splitlines()[-12:])))
    gem5_ref.load_misc_names(gem5_dir)
    return binary, cfg, env, notes


# --------------------------------------------------------------- the mapping
def split_ref_writes(ins):
    """gem5's write list -> (arch file, flags, fp/system status).

    A register written more than once by the same architectural instruction
    (gem5 cracks such an instruction into several micro-ops) keeps the LAST
    value, which is the architectural result.
    """
    arch, flags, fpsr = {}, {}, {}
    for name, val, w in ins.writes:
        if name in FLAG_IDS:
            flags[name] = (val, w)
        elif _is_sys(name):
            fpsr[name] = (val, w)
        else:
            arch[name] = (val, w)
    return arch, flags, fpsr


def split_trc_writes(ins):
    arch, flags, fpsr = {}, {}, {}
    for name, val, w in ins.writes:
        v = (val & ((1 << (8 * w)) - 1)) if 0 < w < 8 else val
        if name in FLAG_IDS:
            flags[name] = (v, w)
        elif _is_sys(name):
            fpsr[name] = (v, w)
        else:
            arch[name] = (v, w)
    return arch, flags, fpsr


def split_srcs(names):
    """The TRACER's source list, into the same three partitions."""
    arch, flags, sysr = set(), set(), set()
    for n in names:
        if n in FLAG_IDS:
            flags.add(n)
        elif _is_sys(n):
            sysr.add(n)
        else:
            arch.add(n)
    return arch, flags, sysr


# ---------------------------------------------------------------- adjudicate
class _Rule(object):
    """A rule this leg adds, in the shape ``arc3_taxonomy.Rule`` has."""

    def __init__(self, name, category, expect, note):
        self.key, self.category = name, category
        self.expect, self.note, self.accounts = frozenset(expect), note, True


#: Rules kept HERE rather than in ``gem5_rules`` because they are facts about
#: gem5's SOURCE list and about its atomic micro-ops, and the correct-path leg
#: does not score sources at all.
_WP_RULES = {
    # gem5 threads `cpsr` through the source list of essentially every
    # micro-op it executes.  That is a machine-state read, not an
    # architectural edge: under R7 -- would a renaming regfile have to respect
    # it for the instruction to execute correctly? -- it does not qualify, so
    # gem5's trace cannot state the architectural read set for that register.
    #
    # The exemption is held to EXACTLY the registers measured to behave that
    # way, and to nothing else.  A blanket "the misc file does not count"
    # would swallow cpacr_el1 and fpscr -- both of which the tracer and gem5
    # already AGREE on -- and with them any future row where the tracer really
    # did drop a system source.  Watched: the control drops a REG_SYSFPEN
    # source and this rule does not reach it, so the axis fires.
    'REF-READS-MACHINE-STATE': _Rule(
        'REF-READS-MACHINE-STATE', 'reference-gap', {SUBSET},
        'gem5 names cpsr as a source of essentially every micro-op'),

    # gem5's AArch64 decoder resolves a zero-register SOURCE operand into its
    # `invalid` register class, so `cset x9, lt` -- architecturally
    # `csinc x9, xzr, xzr, lt` -- reaches the ExeTracer naming no integer
    # source at all.  The tracer names REG_ZERO, which is what R7.3 requires
    # ("REG_ZERO exists, so it should be specified").  This is the source-side
    # twin of the correct-path leg's REF-DISCARDS-ZERO-DEST and of the
    # riscv64 leg's REF-C-IMM-NO-X0-READ.
    'REF-DISCARDS-ZERO-SRC': _Rule(
        'REF-DISCARDS-ZERO-SRC', 'reference-gap', {SUPERSET},
        'gem5 resolves a zero-register source into its `invalid` class and '
        'names no source; the tracer names REG_ZERO'),

    # gem5's LSE atomic micro-op names its own DESTINATION in its source list.
    'REF-ATOMIC-DEST-AS-SRC': _Rule(
        'REF-ATOMIC-DEST-AS-SRC', 'reference-defect', {SUBSET},
        'ldadd/swp/cas name Xt in SR= although Xt is written with the '
        'pre-image of memory and nothing of its previous content survives'),
}


#: MEASURED, never assumed: the misc-file registers gem5 names as a source of
#: essentially every micro-op regardless of what the instruction does.  On
#: this build, over one p_wpmem excursion, the misc source tokens are
#: ``miscellaneous:0`` (cpsr) 47 times, ``miscellaneous:523`` (cpacr_el1 ->
#: REG_SYSFPEN) 46 and ``miscellaneous:17`` (fpscr_exc -> REG_FCSR) 3 -- and
#: the tracer names REG_SYSFPEN on exactly those 46 and REG_FCSR on exactly
#: those 3.  Only cpsr is unmatched, so only cpsr is exempt.
REF_MACHINE_STATE = frozenset(('REG_FLAGS',))


def _rule(label):
    return gem5_exec_rule(label) or _WP_RULES.get(label)


def _neon_pairwise(r, t):
    """gem5's NEON load/store micro-ops write vector registers in PAIRS.

    Measured, never assumed: the label is earned only when the reference
    destination count is exactly the tracer's rounded up to even and every
    tracer destination is a vector register.  ``ld1 {v5.16b}`` reports v5 AND
    v6; the two- and four-register forms agree exactly.
    """
    ra = split_ref_writes(r)[0]
    ta = split_trc_writes(t)[0]
    return (bool(ta) and all(n.startswith('REG_VEC') for n in ta) and
            len(ra) == len(ta) + (len(ta) & 1))


#: A cache-maintenance destination the TRACE names.  Read out of the trace's
#: own write list rather than off a mnemonic (R8.7): the record is what says
#: this instruction is maintenance, and a text match would stop working the
#: day either tool renamed the operation.
MAINT_DEST = 'REG_SYSCACHE'


def _addr_only(ins):
    """The trace performed at least one access and NONE of them carries data.

    Only ``record_synthetic_load`` mints a size-0 memop, so this is the wire's
    own statement that the record is an ADDRESS and not an access -- the
    GEN_OP_PREFETCH / GEN_OP_CACHE_FLUSH / GEN_OP_TLB_FLUSH class of
    docs/format.rst 5.2.
    """
    accs = ins.loads + ins.stores
    return bool(accs) and all((sz or 0) == 0 for _a, _d, sz in accs)


def _ref_covers_same_line(r, t):
    """The reference's accesses are ONE contiguous granule containing ours.

    This is the guard that keeps the address-only rules a measurement rather
    than a blanket: the reference must describe a single contiguous run of a
    power-of-two byte count, and every address the trace published must fall
    INSIDE it.  A trace that named the wrong line fails containment, earns no
    label, and stays a defect.
    """
    ra = sorted(a for a, _d, _s in r.loads + r.stores)
    if not ra:
        return False
    lo = min(ra)
    span = 0
    for a, _d, sz in r.loads + r.stores:
        span = max(span, a + max(sz or 0, 1) - lo)
    if span <= 0 or (span & (span - 1)) != 0:
        return False                      # not a granule
    if set(ra) != set(range(lo, lo + span)) and len(ra) != 1:
        return False                      # not contiguous, and not one record
    return all(lo <= a < lo + span for a, _d, _s in t.loads + t.stores)


def is_svc(bits):
    """``SVC #imm16``: 1101 0100 000 imm16 00001.

    Tested on the ENCODING rather than on a disassembly string, because the
    reason this matters -- gem5's SE mode turns the guest's own supervisor
    call into a process exit and prints no commit line for it -- is a property
    of the instruction, and a text match would silently stop working the day
    gem5 renamed its mnemonic.
    """
    return (bits & 0xffe0001f) == 0xd4000001


def _atomic_dest_as_src(r, only_ref):
    """gem5's LSE atomic micro-op names its DESTINATION in its source list.

    ``ldadd Xs, Xt, [Xn]`` writes Xt with the pre-image of memory; nothing of
    Xt's previous content reaches the result, so under R7 -- would a renaming
    regfile have to respect the edge? -- Xt is not a source.  gem5 lists it
    because the micro-op carries the returned value in that register slot.

    Measured from the record and not from the mnemonic: the surplus must be
    exactly registers the reference itself says the instruction WROTE, and the
    reference must have performed a read and a write at the same address --
    which is what an atomic read-modify-write looks like in the log.
    """
    wrote = frozenset(split_ref_writes(r)[0])
    rmw = (bool(r.loads) and bool(r.stores) and
           set(a for a, _d, _s in r.loads) ==
           set(a for a, _d, _s in r.stores))
    return rmw and bool(only_ref) and frozenset(only_ref) <= wrote


def label_for(axis, only_ref, only_trc, ref_ins, trc_ins):
    """The MECHANISM, chosen from the two records -- never from a mnemonic."""
    if axis == 'reg-dst-set':
        if only_trc and not only_ref and all(n == 'REG_ZERO' for n in only_trc):
            return 'REF-DISCARDS-ZERO-DEST'
        if (only_ref and not only_trc and
                all(n.startswith('REG_VEC') for n in only_ref) and
                _neon_pairwise(ref_ins, trc_ins)):
            return 'REF-NEON-PAIRWISE-DEST'
    elif axis == 'reg-src-set':
        if only_trc and not only_ref and all(n == 'REG_ZERO' for n in only_trc):
            return 'REF-DISCARDS-ZERO-SRC'
        if only_ref and not only_trc and _atomic_dest_as_src(ref_ins, only_ref):
            return 'REF-ATOMIC-DEST-AS-SRC'
    elif axis in ('fpsr-dst-set', 'reg-dst-set'):
        # A cache-maintenance destination.  Two mechanisms, kept apart because
        # they are not the same fact: gem5 names NOTHING for a DC clean, and
        # names its own operation-titled misc register for IC IVAU.
        if only_trc == frozenset((MAINT_DEST,)):
            if not only_ref:
                return 'REF-NO-CACHE-MAINT-DEST'
            if len(only_ref) == 1 and \
                    next(iter(only_ref)).startswith('MISC:'):
                return 'CACHE-MAINT-DEST-SPELLING'
    elif axis == 'sys-src-set':
        # Held to the measured set.  A label applied to a whole AXIS rather
        # than to a measured shape is the kind arc3_taxonomy declares
        # accounts=False: it restates which way the sets differ and explains
        # no individual row.
        if only_ref and not only_trc and \
                frozenset(only_ref) <= REF_MACHINE_STATE:
            return 'REF-READS-MACHINE-STATE'
    # NOTE on the flag and FP-status partitions: the correct-path leg needs
    # FLAGS-GRANULARITY and FPSR-GRANULARITY because it compares gem5's
    # sub-field registers against the tracer's whole word.  Here both sides
    # have already been mapped onto GenericRegIds, where gem5's nz/c/v are one
    # REG_FLAGS and its fpscr_exc is one REG_FCSR -- so the granularity is
    # gone before the comparison and a disagreement on those axes is a REAL
    # one.  Labelling them by axis would have hidden exactly that, and the
    # negative control caught it: with the blanket labels in place, dropping
    # the tracer's flag destination did NOT fire.
    return None


def adjudicate(rel, label):
    """(measured direction, named mechanism) -> a verdict.

    The verdict comes from the rule's CATEGORY together with the MEASURED
    direction, never from the direction alone.  Reading the direction by
    itself would call every TRACER-SUBSET a tracer defect, and a row where
    gem5 names a register the instruction does not touch is the reference
    failing to state the fact rather than the tracer dropping one.

    A direction with no rule is UNACCOUNTED and says so; it is never quietly
    folded into the superset.
    """
    rule = _rule(label)
    if rule is not None and rule.accounts and rel in rule.expect:
        if rule.category == 'tracer-defect':
            return WP_DEFECT, label
        if rel == SUPERSET:
            return SUPERSET_OK, label
        return GEM5_LIMIT, label
    if rel == SUBSET:
        # The reference names an architectural fact the tracer does not.  That
        # is the one disqualifying direction, and a bare "we dropped it"
        # cannot be closed by assertion -- so it is a defect only when no
        # label was offered, and UNACCOUNTED when a label was offered that the
        # rule table did not honour.
        return (WP_DEFECT if label is None else UNACCOUNTED), label
    return UNACCOUNTED, label


# ------------------------------------------------------- entry-state truth
def ground_truth(commits):
    """Per index, the register file the REFERENCE run had actually written.

    ``snaps[i]`` is {generic name: value} for the state BEFORE reference
    instruction ``i``.  Unlike Spike, gem5's trace prints no value for a
    register it merely READ, so a register the correct path never WROTE is
    absent -- and absence is reported as "the reference cannot say", never as
    agreement.
    """
    cur, snaps = {}, []
    for ins in commits:
        snaps.append(dict(cur))
        for name, val, w in ins.writes:
            if w:
                cur[name] = val
    snaps.append(dict(cur))
    return snaps


def align(ref, trc):
    """Index-preserving alignment of two instruction streams.

    -> [(ref index | None, trc index | None)].  Deletions on the reference
    side are carried through as ``None`` rather than collapsed: gem5 is silent
    about anything it did not reach, and an alignment that hid that would make
    the reference's own stop look like a tracer invention.
    """
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
def compare_excursion(guest, ex, refrows, gapinfo, stop_reason):
    """One excursion vs the reference run of the same state.

    -> ([Row], uncompared tail, compared count, facts per axis).  The tail is
    returned rather than inferred so the report can print
    ``sum-of-tails == declared - compared`` and leave no declared instruction
    sitting unexplained; the per-axis fact count is returned for the same
    reason one step further in -- a zero row count on an axis that compared
    NOTHING is survivorship bias, not coverage, and the report must be able
    to tell the two apart.
    """
    rows = []
    facts = Subjects()
    reg_gaps = gapinfo['reg_gaps']
    unestablished = gapinfo['unestablished']
    declared = len(ex.insns)
    n = declared
    ref = [r[0] for r in refrows]

    ref_pcs = [i.pc for i in ref[:n]]
    trc_pcs = [i.pc for i in ex.insns]
    if ref_pcs != trc_pcs:
        k = 0
        while k < min(len(ref_pcs), len(trc_pcs)) and ref_pcs[k] == trc_pcs[k]:
            k += 1
        if len(ref) < n and k == len(ref_pcs):
            # The reference STOPPED; it did not go somewhere else.
            verdict = RECON_GAP if reg_gaps else GEM5_LIMIT
            why = ('the first uncompared instruction is the guest\'s own '
                   'SVC, which gem5\'s SE mode executes as a process exit -- '
                   'it prints no commit line for it and can say nothing '
                   'about what follows'
                   if (k < len(ex.insns) and is_svc(ex.insns[k].bits))
                   else 'gem5 stopped: %s' % stop_reason)
            detail = ('the reference retired %d of the %d declared and then '
                      'stopped -- it did not diverge; its last commit was '
                      '0x%x and the excursion continues at 0x%x.  %s'
                      % (len(ref), n, ref_pcs[-1] if ref_pcs else 0,
                         trc_pcs[k] if k < len(trc_pcs) else 0, why))
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

    facts.note('pc-sequence')
    compared = min(n, len(ref))
    for i in range(compared):
        r, t = ref[i], ex.insns[i]
        facts.note('insn-bits', t)
        if r.bits != t.bits:
            rows.append(Row(guest, ex.seq, i, t.pc, 'insn-bits', WP_DEFECT,
                            hex(r.bits), hex(t.bits), 'same PC, other bytes'))
            continue
        ra, rf, rp = split_ref_writes(r)
        ta, tf, tp = split_trc_writes(t)

        for axis, rs, ts in (('reg-dst-set', ra, ta),
                             ('flags-dst-set', rf, tf),
                             ('fpsr-dst-set', rp, tp)):
            facts.note(axis, t)
            if frozenset(rs) == frozenset(ts):
                continue
            rel = set_relation((), sorted(rs), (), sorted(ts))
            if rel == EQUAL:
                continue
            only_ref = frozenset(rs) - frozenset(ts)
            only_trc = frozenset(ts) - frozenset(rs)
            lab = label_for(axis, only_ref, only_trc, r, t)
            v, lab = adjudicate(rel, lab)
            rows.append(Row(guest, ex.seq, i, t.pc, axis, v,
                            sorted(rs), sorted(ts), '%s %s' % (rel, lab or '')))

        # --- reg-dst-value, on the destinations BOTH sides name and VALUE.
        # gem5 prints a vector destination as `=?`, which gem5_ref records
        # with width 0: that is the absence of a number, not the number zero,
        # and comparing it would manufacture agreement out of the harness.
        for k_ in sorted(frozenset(ra) & frozenset(ta)):
            rv, rw = ra[k_]
            tv, tw = ta[k_]
            if not rw or not tw:
                continue
            facts.note('reg-dst-value', t)
            m = (1 << (8 * min(rw, tw))) - 1
            if (rv & m) != (tv & m):
                rows.append(Row(guest, ex.seq, i, t.pc, 'reg-dst-value',
                                RECON_GAP if k_ in reg_gaps else WP_DEFECT,
                                '%s=0x%x' % (k_, rv), '%s=0x%x' % (k_, tv),
                                ''))

        _ri, rsa, rsf, rss = refrows[i]
        tsa, tsf, tss = split_srcs(t.srcs)
        for axis, rs, ts in (('reg-src-set', rsa, tsa),
                             ('flags-src-set', rsf, tsf),
                             ('sys-src-set', rss, tss)):
            facts.note(axis, t)
            if rs == ts:
                continue
            rel = set_relation((), sorted(rs), (), sorted(ts))
            if rel == EQUAL:
                continue
            lab = label_for(axis, rs - ts, ts - rs, r, t)
            v, lab = adjudicate(rel, lab)
            rows.append(Row(guest, ex.seq, i, t.pc, axis, v,
                            sorted(rs), sorted(ts), '%s %s' % (rel, lab or '')))

        # ------------------------------------------------------- memory
        #
        # The MECHANISM is decided ONCE, from the two access lists, and the
        # same label is then carried by every axis the mechanism makes
        # disagree.  A per-axis label would charge one instruction to three
        # different mechanisms and let the same fact be counted three ways.
        def byteset(recs, tag):
            out = set()
            for a, _d, sz in recs:
                for kk in range(max(sz or 0, 1)):
                    out.add((tag, a + kk))
            return out

        rb = byteset(r.loads, 'L') | byteset(r.stores, 'S')
        tb = byteset(t.loads, 'L') | byteset(t.stores, 'S')
        rcnt = (len(r.loads), len(r.stores))
        tcnt = (len(t.loads), len(t.stores))
        rwid = (sum(sz or 0 for _a, _d, sz in r.loads),
                sum(sz or 0 for _a, _d, sz in r.stores))
        twid = (sum(sz or 0 for _a, _d, sz in t.loads),
                sum(sz or 0 for _a, _d, sz in t.stores))

        for _ax in ('memop-count', 'memop-addr', 'memop-width'):
            facts.note(_ax, t)
        mech = None
        if _addr_only(t) and not r.loads and not r.stores:
            # The reference executed the hint / maintenance operation as a
            # no-op and issued no request at all.
            mech = 'HINT-MEMOP-REF-SILENT'
        elif _addr_only(t) and _ref_covers_same_line(r, t):
            # Both name the same granule; they disagree only on whether the
            # record carries the modelled cache's geometry.  WHICH mechanism
            # is read off the trace's own write list, never off a mnemonic.
            mech = ('MAINT-EXTENT-IS-CACHE-GEOMETRY'
                    if any(n == MAINT_DEST for n, _v, _w in t.writes)
                    else 'PREFETCH-SIZE-IS-REF-CHOICE')
        elif rb == tb and rcnt != tcnt:
            mech = 'SAME-BYTES-DIFFERENT-SPLIT'
        elif (not r.loads and t.loads and
              set(a for a, _d, _s in t.loads) <=
              set(a for a, _d, _s in r.stores) and
              [(a, sz) for a, _d, sz in t.stores] ==
              [(a, sz) for a, _d, sz in r.stores]):
            mech = 'QEMU-EXCLUSIVE-CMPXCHG'

        def memv(rel):
            rule = gem5_exec_rule(mech)
            if rule is not None and rule.accounts and rel in rule.expect:
                return (SUPERSET_OK if rel == SUPERSET else GEM5_LIMIT)
            if reg_gaps:
                return RECON_GAP
            return WP_DEFECT if rel == SUBSET else UNACCOUNTED

        if rcnt != tcnt:
            rel = set_relation((), sorted(map(repr, rb)), (),
                               sorted(map(repr, tb)))
            rel = rel if rel != EQUAL else (
                SUPERSET if tcnt > rcnt else SUBSET)
            rows.append(Row(guest, ex.seq, i, t.pc, 'memop-count', memv(rel),
                            '%dL/%dS' % rcnt, '%dL/%dS' % tcnt, mech or ''))
        if rb != tb:
            rel = set_relation((), sorted(map(repr, rb)), (),
                               sorted(map(repr, tb)))
            gap = any(a in unestablished for _tg, a in (tb - rb))
            rows.append(Row(guest, ex.seq, i, t.pc, 'memop-addr',
                            RECON_GAP if gap else memv(rel),
                            sorted('%s:0x%x' % (tg, a) for tg, a in rb - tb),
                            sorted('%s:0x%x' % (tg, a) for tg, a in tb - rb),
                            mech or ''))
        if rwid != twid and rb != tb:
            rel = SUPERSET if twid >= rwid else SUBSET
            rows.append(Row(guest, ex.seq, i, t.pc, 'memop-width', memv(rel),
                            '%dL/%dS bytes' % rwid, '%dL/%dS bytes' % twid,
                            mech or ''))

        def bytemap(recs):
            out = {}
            for a, d, s in recs:
                if d is None or not s or s > 8:
                    continue
                for kk in range(s):
                    out[a + kk] = (d >> (8 * kk)) & 0xff
            return out
        for axis, rrec, trec in (('store-data', r.stores, t.stores),
                                 ('load-data', r.loads, t.loads)):
            rm, tm = bytemap(rrec), bytemap(trec)
            both_b = frozenset(rm) & frozenset(tm)
            if both_b:
                facts.note(axis, t, len(both_b))
            diff = sorted(b for b in both_b if rm[b] != tm[b])
            if diff:
                unest = any(b in unestablished for b in diff)
                rows.append(Row(guest, ex.seq, i, t.pc, axis,
                                RECON_GAP if unest else WP_DEFECT,
                                ['0x%x=0x%02x' % (b, rm[b]) for b in diff],
                                ['0x%x=0x%02x' % (b, tm[b]) for b in diff],
                                'address never established by the wire'
                                if unest else ''))
    return rows, declared - compared, compared, facts


def entry_state_rows(guest, ex, truth, reg_gaps):
    """Score the RECONSTRUCTED entry state against the correct-path truth.

    This is the axis that makes the gap attribution evidence rather than
    plausibility.  gem5 publishes no value for a vector destination
    (``RW=[vector:0=?]``) and splits the flag word into three registers, so
    those are counted as "the reference cannot value it" -- an exclusion that
    is NAMED and COUNTED, never folded into agreement.
    """
    rows, stats = [], collections.Counter()
    for name, (val, w) in sorted(ex.regs.items()):
        if wp_seed_a64.reg_to_a64(name) is None:
            stats['tracer-only-id'] += 1
            continue
        if name in FLAG_IDS or name in FPSR_IDS:
            stats['reference-cannot-value'] += 1
            continue
        if name not in truth:
            stats['reference-silent'] += 1
            continue
        m = (1 << (8 * w)) - 1 if 0 < w < 8 else (1 << 64) - 1
        if (truth[name] & m) != (val & m):
            stats['wrong'] += 1
            reg_gaps.add(name)
            rows.append(Row(guest, ex.seq, -1, ex.start_pc, 'wp-entry-state',
                            RECON_GAP, '%s=0x%x' % (name, truth[name]),
                            '%s=0x%x' % (name, val),
                            'reconstructed from REGFILE seed + DST snapshots'))
        else:
            stats['agree'] += 1
    for name in sorted(truth):
        if name in ex.regs or name in FLAG_IDS or name in FPSR_IDS:
            continue
        if wp_seed_a64.reg_to_a64(name) is None:
            continue
        stats['not-reconstructed'] += 1
        reg_gaps.add(name)
        rows.append(Row(guest, ex.seq, -1, ex.start_pc, 'wp-entry-state',
                        RECON_GAP, '%s=0x%x' % (name, truth[name]), 'ABSENT',
                        'the wire never stated this register'))
    return rows, stats


# ------------------------------------------------------------------ driver
def excursion_gaps(ex, seedgaps):
    """What the reconstruction could not establish, as evidence.

    ``unestablished`` is every address this excursion touches that no ELF
    byte, no correct-path load datum and no correct-path store datum put a
    value under.  Computed from the excursion's own accesses, so it is a fact
    about this experiment rather than a whole-address-space claim.
    """
    unest = set()
    for ins in ex.insns:
        for addr, _d, size in ins.loads + ins.stores:
            for k in range(addr, addr + (size or 8)):
                if k not in ex.mem_src:
                    unest.add(k)
    return {'reg_gaps': set(), 'unestablished': unest, 'seedgaps': seedgaps}


def not_prologue(plen):
    """The injected image's own scaffolding, EXCLUDED BY ADDRESS.

    Every segment of the injected image is marked executable precisely so
    gem5_ref's own range filter cannot delete a reference instruction the
    excursion really reached; the prologue is then removed by its own address
    range, never by counting how many instructions the assembler emitted.
    """
    lo, hi = wp_seed_a64.BOOT_BASE, wp_seed_a64.BOOT_BASE + plen
    vlo, vhi = wp_seed_a64.VTAB_BASE, wp_seed_a64.VTAB_BASE + 32 * 16

    def sel(pc):
        return not (lo <= pc < hi or vlo <= pc < vhi)
    return sel


def process_guest(args, binary, cfg, env, guest, out):
    stem = os.path.join(out, os.path.basename(guest))
    trace = run_tracer(args.qemu, args.plugin, guest, stem, args.wpdepth)
    image, _xr, _entry = elfimage.load(guest)
    exc, cp, tstats = wp_trace.build(args.decode, trace, image)

    # ---- correct-path ground truth for the entry state
    cplog, cpreason, cppanic = run_gem5(binary, cfg, env, guest, out,
                                        os.path.basename(guest) + '.cp', 0)
    if cppanic or 'last active thread context' not in cpreason:
        raise RuntimeError(
            'gem5 did not run %s to completion on the CORRECT path (%s).  '
            'Without the correct-path ground truth the entry-state axis '
            'cannot be scored, and a RECONSTRUCTION-GAP could not be told '
            'from a WP-DEFECT.  Nothing is scored.' % (guest, cpreason))
    refcp = [r[0] for r in parse_ref(cplog, guest, args.gem5_dir)]
    snaps = ground_truth(refcp)
    pairs = align(refcp, cp)
    trc2ref = dict((t, r) for r, t in pairs if r is not None and t is not None)

    distinct = wp_trace.dedupe(exc)
    rows, stats = [], collections.Counter()
    tails = collections.Counter()
    axisfacts = Subjects()
    stats['excursions-dynamic'] = len(exc)
    stats['excursions-distinct'] = len(distinct)
    stats['cp-aligned'] = len(trc2ref)
    stats['cp-ref-insns'] = len(refcp)
    stats['cp-trc-insns'] = len(cp)

    todo = distinct if args.max <= 0 else distinct[:args.max]
    stats['excursions-run'] = len(todo)
    stats['excursions-stood-for'] = sum(n for _e, n in todo)
    for k, (ex, _mult) in enumerate(todo):
        tag = '%s.e%04d' % (os.path.basename(guest), k)
        elf, seedgaps, unmapped, plen = wp_seed_a64.build(out, tag, ex)
        cap = plen // 4 + len(ex.insns) + 16
        log, reason, panicked = run_gem5(binary, cfg, env, elf, out, tag, cap)
        refrows = parse_ref(log, elf, args.gem5_dir, not_prologue(plen))
        gapinfo = excursion_gaps(ex, seedgaps)
        ridx = trc2ref.get(ex.cp_index - 1)
        if ridx is not None:
            erows, estats = entry_state_rows(guest, ex, snaps[ridx + 1],
                                             gapinfo['reg_gaps'])
            rows.extend(erows)
            axisfacts.note('wp-entry-state',
                           n=estats['agree'] + estats['wrong'])
            for kk, vv in estats.items():
                stats['entry-state:' + kk] += vv
        else:
            stats['entry-state:unaligned'] += 1
        stats['wp-insns-declared'] += len(ex.insns)
        stats['gem5-stop:' + reason] += 1
        if panicked:
            stats['excursion-panicked'] += 1
        if not refrows:
            rows.append(Row(guest, ex.seq, 0, ex.start_pc, 'pc-sequence',
                            GEM5_LIMIT, reason, '0x%x' % ex.start_pc,
                            'the injected run retired nothing outside the '
                            'prologue -- the excursion\'s FIRST instruction '
                            'stopped the reference.  %s' % reason))
            tails['reference-retired-nothing'] += len(ex.insns)
            stats['excursion-no-reference'] += 1
            continue
        r, tail, compared, facts = compare_excursion(guest, ex, refrows,
                                                     gapinfo, reason)
        rows.extend(r)
        axisfacts.merge(facts)
        if tail:
            tails['reference-stopped-short' if len(refrows) < len(ex.insns)
                  else 'pc-diverged'] += tail
        stats['wp-insns-compared'] += compared
        if not r:
            stats['excursions-clean'] += 1
        stats['unestablished-bytes'] += len(gapinfo['unestablished'])
        for g in seedgaps:
            stats['seed-gap:' + g] += 1
        for u in unmapped:
            stats['unmappable-id:' + u] += 1
    for kk, vv in tstats.items():
        stats['trace:' + kk] += vv
    return rows, stats, tails, axisfacts


def render(rows, stats, tails, axisfacts):
    out = []
    w = out.append
    w('=' * 74)
    w('ARC 3 -- aarch64 WRONG-PATH execution cross-check vs gem5')
    w('=' * 74)
    w('')
    w('The wrong-path arm had NO execution reference on this ISA.  Every')
    w('excursion below was rebuilt from the trace alone -- the REGFILE seed,')
    w('the destination snapshots, the correct-path load and store data and')
    w('the guest image -- installed as INSTRUCTIONS into a real simulator at')
    w('the excursion\'s own PC, and compared instruction for instruction.')
    w('')
    w('AXES: ' + ', '.join(AXES) + ', wp-entry-state')
    w('')
    hdr = '%-58s %10s' % ('measure', 'count')
    w(hdr)
    w('-' * len(hdr))
    for k in sorted(stats):
        w('%-58s %10d' % (k, stats[k]))
    w('')
    dec, cmpd = stats['wp-insns-declared'], stats['wp-insns-compared']
    w('=' * 74)
    w('THE DECLARED-VS-COMPARED IDENTITY.  A gap here is never left to be')
    w('rediscovered: every wrong-path instruction the tracer declared is')
    w('either compared against the reference or sits in a NAMED tail.')
    w('')
    w('  declared %d - compared %d = %d' % (dec, cmpd, dec - cmpd))
    for k in sorted(tails):
        w('  tail: %-40s %d' % (k, tails[k]))
    w('  sum of uncompared tails                        %d'
      % sum(tails.values()))
    ok = (dec - cmpd) == sum(tails.values())
    w('  IDENTITY %s'
      % ('HOLDS' if ok else 'DOES NOT HOLD -- a declared instruction is '
                            'unaccounted for'))
    w('')
    w('=' * 74)
    w('THE VERDICT SPLIT.  A divergence is a WP DEFECT, a RECONSTRUCTION GAP')
    w('or a GEM5 LIMIT, and never a fourth thing.')
    w('')
    byv = collections.Counter(r.verdict for r in rows)
    bya = collections.Counter((r.axis, r.verdict) for r in rows)
    for line in axisfacts.render(AXES + ('wp-entry-state',), bya, VERDICTS):
        w(line)
    w('THE NUMBER THAT MATTERS: WP-DEFECT + RECONSTRUCTION-GAP +')
    w('UNACCOUNTED = %d.  TRACER-SUPERSET rows are COVERED -- each carries a'
      % (byv[WP_DEFECT] + byv[RECON_GAP] + byv[UNACCOUNTED]))
    w('named rule saying why the reference omits the fact.  GEM5-LIMIT rows')
    w('are the reference\'s own silence or its own modelling artefact, named')
    w('one by one and never counted as agreement.')
    w('')
    lim = [r for r in rows if r.verdict == GEM5_LIMIT]
    if lim:
        w('EVERY GEM5-LIMIT, NAMED:')
        seen = collections.Counter()
        for r in lim:
            seen['%-16s %s' % (r.axis, r.detail or r.ref)] += 1
        for k, n in seen.most_common():
            w('  %4d  %s' % (n, k))
        w('')
    if not rows:
        w('NO DIVERGENCE on any axis, over every excursion run.  That is a')
        w('result only because the negative control (selftest_wp_a64.py)')
        w('shows every axis CAN fire; a check that cannot fire agrees for')
        w('ever.')
        w('')
    else:
        w('EVERY DISTINCT ROW SHAPE, with how many rows carry it:')
        w('')
        shapes = collections.Counter(
            (r.verdict, r.axis, os.path.basename(r.guest), r.detail[:110])
            for r in rows)
        for (v, ax, g, det), n in sorted(shapes.items(),
                                         key=lambda kv: (-kv[1], kv[0])):
            w('  %-18s %-16s %-10s x%-5d %s' % (v, ax, g, n, det))
        w('')
        w('EVERY ROW, none summarised away:')
        w('')
        for r in rows[:400]:
            w('  %-18s %-16s %-10s pc=0x%x idx=%d'
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
    ap.add_argument('--qemu', required=True)
    ap.add_argument('--plugin', required=True)
    ap.add_argument('--decode', required=True)
    ap.add_argument('--python-home')
    ap.add_argument('--wpdepth', type=int, default=32)
    ap.add_argument('--max', type=int, default=0,
                    help='distinct excursions per guest; <=0 for all')
    ap.add_argument('-o', '--outdir', required=True)
    ap.add_argument('--tsv')
    a = ap.parse_args()

    os.makedirs(a.outdir, exist_ok=True)
    try:
        binary, cfg, env, notes = prereqs(a.gem5_dir, a.outdir,
                                          python_home=a.python_home)
    except gem5_env.MissingPrerequisite as exc:
        sys.stderr.write('%s\nREFUSING TO SCORE: the execution reference did '
                         'not run.  No facet cell may be written from this '
                         'invocation.\n' % exc)
        return 3
    with open(os.path.join(a.outdir, 'PREREQ.txt'), 'w') as fh:
        fh.write('gem5 aarch64 wrong-path leg -- prerequisites, as resolved\n')
        for n in notes:
            fh.write('  %s\n' % n)
        fh.write('  gem5.opt: %s\n  se.py:    %s\n' % (binary, cfg))

    rows, stats = [], collections.Counter()
    tails, axisfacts = collections.Counter(), Subjects()
    for g in a.guest:
        try:
            r, s, t, f = process_guest(a, binary, cfg, env, g, a.outdir)
        except RuntimeError as exc:
            sys.stderr.write('%s\n' % exc)
            return 3
        rows.extend(r)
        stats.update(s)
        tails.update(t)
        axisfacts.merge(f)
    axisfacts.write_tsv(os.path.join(a.outdir, 'axis_subjects.tsv'),
                        AXES + ('wp-entry-state',))
    txt, identity_ok = render(rows, stats, tails, axisfacts)
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
