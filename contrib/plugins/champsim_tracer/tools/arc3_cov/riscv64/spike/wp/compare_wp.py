"""
ARC 3 -- riscv64 WRONG-PATH execution cross-check: the tracer against Spike.

NO WP GOLDEN EXISTS ON ANY ISA.  Every gate this project runs compares correct
path against correct path, so a wrong-path divergence is invisible today, and
the wrong-path arm is a large fraction of what the tracer emits.  This leg
closes that by the method the maintainer named: recreate the architectural
state the trace SAYS holds when an excursion begins, start a real simulator at
that PC with that state, and compare instruction for instruction.

    trace ---> reconstructed regfile + memory ---> injected bare-metal ELF
                                                        |
                                                     spike
                                                        |
    tracer's WP record  <----- compared against ----- what the ISA does

THE THREE VERDICTS, AND WHY THEY MUST NOT BE BLURRED
====================================================
A divergence is exactly one of:

  WP-DEFECT           the excursion executed something the architecture would
                      not, from a starting state the trace fully specified.
                      A tracer bug.
  RECONSTRUCTION-GAP  the trace does not carry enough state to rebuild the
                      starting point, so the two runs began from different
                      machines.  A finding about what the WIRE drops -- and
                      the more interesting of the two, because a trace that
                      cannot reproduce its own wrong-path starting state is
                      not a complete record of the run.
  SPIKE-LIMIT         the reference cannot state the fact.  Spike prints a
                      commit line only on completion, so a trapping
                      instruction leaves no record at all.

The gap is attributed from EVIDENCE, never from plausibility: a register is
a gap only when the reconstruction is measurably wrong at the entry (see the
``wp-entry-state`` axis, which scores the reconstructed register file against
the correct-path run's own ground truth), and a memory address is a gap only
when no ELF byte, no correct-path load datum and no correct-path store datum
ever established it.

Author: Maccoy Merrell.
"""
import argparse
import collections
import difflib
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, '..'))
sys.path.insert(0, os.path.join(_HERE, '..', '..', '..'))

import elfimage                                              # noqa: E402
import wp_trace                                              # noqa: E402
import wp_seed                                               # noqa: E402
import spike_ref                                             # noqa: E402
from compare_exec import is_sc, is_fence, is_vset                     # noqa: E402
from arc3_taxonomy import (set_relation, EQUAL, SUPERSET,
                           SUBSET)                           # noqa: E402
from arc3_rules import riscv_exec_rule                       # noqa: E402
from axis_subjects import Subjects                           # noqa: E402

#: every fact this leg checks about a wrong-path instruction.  Named in full
#: so a report can never quote a subset as if it were the whole comparison.
AXES = ('pc-sequence', 'insn-bits', 'reg-dst-set', 'reg-dst-value',
        'reg-src-set', 'memop-count', 'memop-addr', 'memop-width',
        'load-data', 'store-data')

Row = collections.namedtuple(
    'Row', 'guest seq idx pc axis verdict ref trc detail')


def adjudicate(rel, only_ref, only_trc, bits, side):
    """(direction, surplus/deficit sets) -> (verdict, label).

    The SAME rule table the correct-path leg uses (``arc3_rules.RISCV_EXEC``),
    applied here so a disagreement the CP leg has already adjudicated does not
    reappear as a fresh wrong-path defect.  A direction with no rule is
    UNACCOUNTED and says so; it is never quietly folded into the superset.
    """
    label = None
    if rel == SUPERSET:
        if only_trc and all(n == 'REG_ZERO' for n in only_trc):
            label = 'REF-X0-DISCARD' if side == 'dst' \
                else 'REF-C-IMM-NO-X0-READ'
        elif is_fence(bits) and only_trc == {'REG_SYS'}:
            label = 'REF-NO-ORDERING-STATE'
        elif is_vset(bits) and 'REG_SYS' in only_trc and \
                only_trc <= {'REG_SYS', 'REG_ZERO'}:
            # THE CURRENT XLEN, on the wrong path.  The same rule the CP leg
            # applies, applied here for the reason this function exists: a
            # disagreement the correct-path leg has adjudicated must not
            # reappear as a fresh wrong-path defect.  helper_vsetvl() reads
            # CPURISCVState::xl, spike keeps the current XLEN as a machine
            # mode with no register standing for it.  Only reachable under
            # rel == SUPERSET, so it can never cover a row where the tracer
            # dropped something.
            label = 'REF-NO-XLEN-STATE'
        elif only_trc and all(n.startswith('REG_VEC') for n in only_trc):
            label = 'REF-VEC-ELEMENT-ONLY' if side == 'dst' \
                else 'REF-VEC-ELEMENT-READ-ONLY'
    elif rel == SUBSET:
        if only_ref and all(n.startswith('REG_VEC') for n in only_ref):
            label = 'REF-VEC-TAIL-READ'
    rule = riscv_exec_rule(label)
    if rule is not None and rel in rule.expect and rule.accounts:
        return (SUPERSET_OK if rel == SUPERSET else WP_DEFECT), label
    if rel == SUBSET:
        return WP_DEFECT, label
    return UNACCOUNTED, label

WP_DEFECT = 'WP-DEFECT'
RECON_GAP = 'RECONSTRUCTION-GAP'
SPIKE_LIMIT = 'SPIKE-LIMIT'
#: the tracer records a fact the reference cannot, and a NAMED rule from
#: arc3_rules says why.  Under the three-valued split this is COVERED, not a
#: defect: "we record more" is the project's goal, "we record less" is its one
#: disqualifying failure, and the direction is what tells them apart.
SUPERSET_OK = 'TRACER-SUPERSET'
#: a disagreement nobody has explained.  MUST BE 0.
UNACCOUNTED = 'UNACCOUNTED'
AGREE = 'AGREE'
VERDICTS = (WP_DEFECT, RECON_GAP, SPIKE_LIMIT, SUPERSET_OK, UNACCOUNTED)


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


def run_spike_pk(spike, pk, guest, out, dtc_dir, isa):
    """The CORRECT-PATH reference run, used only for entry-state ground truth."""
    env = dict(os.environ)
    if dtc_dir:
        env['PATH'] = dtc_dir + os.pathsep + env.get('PATH', '')
    log = out + '.cp.log'
    p = subprocess.run([spike, '--isa=' + isa, '-l', '--log-commits',
                        '--log=' + log, pk, guest],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       env=env)
    if p.returncode != 0:
        raise RuntimeError('spike (pk) exit %d: %s'
                           % (p.returncode,
                              p.stdout.decode('utf-8', 'replace')[-800:]))
    return log


def run_spike_injected(spike, elf, mem, out, dtc_dir, isa, cap):
    env = dict(os.environ)
    if dtc_dir:
        env['PATH'] = dtc_dir + os.pathsep + env.get('PATH', '')
    log = out + '.log'
    cmd = [spike, '--isa=' + isa, '-m' + mem, '-l', '--log-commits',
           '--log=' + log, '--instructions=%d' % cap,
           '--pc=0x%x' % wp_seed.BOOT_ENTRY, elf]
    p = subprocess.run(cmd, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, env=env)
    if p.returncode != 0:
        raise RuntimeError('spike (injected) exit %d: %s'
                           % (p.returncode,
                              p.stdout.decode('utf-8', 'replace')[-800:]))
    return log


# ------------------------------------------------------- entry-state truth
def ground_truth(commits):
    """Per index, the register file the REFERENCE run actually held.

    Returns (snapshots, initial).  ``snapshots[i]`` is {generic name: value}
    for the state BEFORE reference instruction ``i``, built from spike's own
    writes and -- for a register not yet written -- from the first read of it,
    which by definition still carries the value it entered the run with.

    A register the reference neither read nor wrote is absent, and absence is
    reported as "the reference cannot say", never as agreement.
    """
    cur, initial = {}, {}
    written = set()
    snaps = []
    for ins in commits:
        snaps.append(dict(cur))
        # A READ is evidence of the pre-state only when the SAME instruction
        # does not also write the register.  Spike's vector element read-back
        # (vectorUnit_t::elt on the write path) logs `read vN` carrying the
        # POST-write value, so treating it as a pre-state observation
        # back-dated a vector register's final content to the start of the run
        # and manufactured 30 reconstruction "gaps" that were the harness's
        # own arithmetic.  Losing the read-modify-write case costs only
        # evidence: the register then reports as `reference-silent`, which is
        # honest, where the alternative was a confident wrong answer.
        selfwrite = set()
        for name, _v in ins.writes:
            g = spike_ref.to_generic(name)
            if g and not g.startswith('CSR:'):
                selfwrite.add(g)
        for name, val in ins.reads:
            g = spike_ref.to_generic(name)
            if g is None or g.startswith('CSR:'):
                continue
            if g in selfwrite:
                continue
            if g not in written and g not in initial:
                initial[g] = val
        for name, val in ins.writes:
            g = spike_ref.to_generic(name)
            if g is None or g.startswith('CSR:'):
                continue
            cur[g] = val
            written.add(g)
    snaps.append(dict(cur))
    # backfill: a register first read at index k held `initial[g]` at every
    # index up to its first write, so state it there too.
    firstwrite = {}
    for i, ins in enumerate(commits):
        for name, _v in ins.writes:
            g = spike_ref.to_generic(name)
            if g and not g.startswith('CSR:') and g not in firstwrite:
                firstwrite[g] = i
    for g, v in initial.items():
        upto = firstwrite.get(g, len(snaps))
        for i in range(0, min(upto + 1, len(snaps))):
            snaps[i].setdefault(g, v)
    return snaps


def align(ref, trc):
    """Index-preserving alignment of two instruction streams.

    -> [(ref index | None, trc index | None)] in order.  The reference is
    silent about any instruction that TRAPPED, so deletions on the reference
    side are expected and are carried through as `None` rather than collapsed;
    an alignment that hid them would make a trap look like a tracer invention.
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
def split_ref_writes(ins):
    arch = {}
    for name, val in ins.writes:
        g = spike_ref.to_generic(name)
        if g is None or g.startswith('CSR:') or g in spike_ref.CSR_IDS:
            continue
        arch[g] = val
    return arch


def split_ref_reads(ins):
    arch = set()
    for name, _val in ins.reads:
        g = spike_ref.to_generic(name)
        if g is None or g.startswith('CSR:') or g in spike_ref.CSR_IDS:
            continue
        arch.add(g)
    return arch


def split_trc_writes(ins):
    arch = {}
    for name, val, w in ins.writes:
        if name in spike_ref.CSR_IDS:
            continue
        arch[name] = val & ((1 << (8 * w)) - 1) if 0 < w < 8 else val
    return arch


def compare_excursion(guest, ex, ref, gapinfo):
    """One excursion vs the reference run of the same state.

    -> ([Row], number of declared instructions actually COMPARED).  The
    caller charges ``declared - compared`` to a named tail so the report can
    assert ``sum-of-tails == declared - compared`` instead of leaving the
    difference to be rediscovered by hand.  The count is taken AFTER the
    pc-sequence truncation, not from ``min(len(ex.insns), len(ref))``:
    beyond a PC divergence the two streams are unrelated and nothing past
    the split is compared, so the wider expression counts instructions the
    walk never looked at.

    ``gapinfo`` carries what the reconstruction could NOT establish, so a
    divergence can be charged to the wire rather than to the excursion --
    but only where the evidence names the specific register or address.
    """
    rows = []
    sub = Subjects()
    reg_gaps = gapinfo['reg_gaps']
    unestablished = gapinfo['unestablished']
    n = len(ex.insns)

    # --- pc-sequence.  The whole excursion, in order, is one fact.
    ref_pcs = [i.pc for i in ref[:n]]
    trc_pcs = [i.pc for i in ex.insns]
    if ref_pcs != trc_pcs:
        k = 0
        while k < min(len(ref_pcs), len(trc_pcs)) and ref_pcs[k] == trc_pcs[k]:
            k += 1
        verdict = RECON_GAP if reg_gaps else WP_DEFECT
        if len(ref) < n:
            verdict = SPIKE_LIMIT if not reg_gaps else verdict
        rows.append(Row(guest, ex.seq, k,
                        trc_pcs[k] if k < len(trc_pcs) else -1,
                        'pc-sequence', verdict,
                        ['0x%x' % p for p in ref_pcs],
                        ['0x%x' % p for p in trc_pcs],
                        'first divergence at index %d; reconstruction gaps: %s'
                        % (k, ','.join(sorted(reg_gaps)) or 'none')))
        n = k                      # beyond the split the streams are unrelated

    sub.note('pc-sequence')
    for i in range(min(n, len(ref))):
        r, t = ref[i], ex.insns[i]
        sub.note('insn-bits', t)
        if r.bits != t.bits:
            rows.append(Row(guest, ex.seq, i, t.pc, 'insn-bits', WP_DEFECT,
                            hex(r.bits), hex(t.bits), 'same PC, other bytes'))
            continue
        rw, tw = split_ref_writes(r), split_trc_writes(t)
        sub.note('reg-dst-set', t)
        if frozenset(rw) != frozenset(tw):
            rel = set_relation((), sorted(rw), (), sorted(tw))
            if rel != EQUAL:
                v, lab = adjudicate(rel, frozenset(rw) - frozenset(tw),
                                    frozenset(tw) - frozenset(rw), r.bits,
                                    'dst')
                rows.append(Row(guest, ex.seq, i, t.pc, 'reg-dst-set',
                                v, sorted(rw), sorted(tw),
                                '%s %s' % (rel, lab or '')))
        for k in frozenset(rw) & frozenset(tw):
            sub.note('reg-dst-value', t)
            if rw[k] != tw[k]:
                rows.append(Row(guest, ex.seq, i, t.pc, 'reg-dst-value',
                                RECON_GAP if k in reg_gaps else WP_DEFECT,
                                '%s=0x%x' % (k, rw[k]),
                                '%s=0x%x' % (k, tw[k]), ''))
        rs, ts = split_ref_reads(r), frozenset(
            x for x in t.srcs if x not in spike_ref.CSR_IDS)
        sub.note('reg-src-set', t)
        if rs != ts:
            rel = set_relation((), sorted(rs), (), sorted(ts))
            if rel != EQUAL:
                v, lab = adjudicate(rel, rs - ts, ts - rs, r.bits, 'src')
                rows.append(Row(guest, ex.seq, i, t.pc, 'reg-src-set',
                                v, sorted(rs), sorted(ts),
                                '%s %s' % (rel, lab or '')))
        # --- memory
        sub.note('memop-count', t)
        if len(r.loads) != len(t.loads) or len(r.stores) != len(t.stores):
            # QEMU lowers store-conditional onto tcg_gen_atomic_cmpxchg, which
            # really reads the line; the tracer records the access the guest
            # performed and the architecture does not have.  arc3_rules calls
            # it QEMU-SC-CMPXCHG and the correct-path leg already carries it.
            sc = (is_sc(r.bits) and len(t.loads) == len(r.loads) + 1
                  and len(t.stores) == len(r.stores))
            rows.append(Row(guest, ex.seq, i, t.pc, 'memop-count',
                            SUPERSET_OK if sc else WP_DEFECT,
                            '%dL/%dS' % (len(r.loads), len(r.stores)),
                            '%dL/%dS' % (len(t.loads), len(t.stores)),
                            'QEMU-SC-CMPXCHG' if sc else ''))
            continue
        for kind, rl, tl in (('load', r.loads, t.loads),
                             ('store', r.stores, t.stores)):
            for j, (rec, tec) in enumerate(zip(rl, tl)):
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
                if td is None:
                    continue
                sub.note('load-data' if kind == 'load' else 'store-data', t)
                w = min(rw_, tw_ or rw_)
                mask = (1 << (8 * w)) - 1
                if (rd & mask) != (td & mask):
                    unest = any(a in unestablished for a in range(ta, ta + w))
                    axis = 'load-data' if kind == 'load' else 'store-data'
                    rows.append(Row(guest, ex.seq, i, t.pc, axis,
                                    RECON_GAP if unest else WP_DEFECT,
                                    '0x%x' % rd, '0x%x' % td,
                                    'address never established by the wire'
                                    if unest else ''))
    return rows, min(n, len(ref)), sub


def entry_state_rows(guest, ex, truth, reg_gaps):
    """Score the RECONSTRUCTED entry state against the correct-path truth.

    This is the axis that makes the gap attribution evidence rather than
    plausibility.  A register the reference never touched is absent from
    ``truth`` and is counted apart -- the reference cannot say, so nobody may
    call it an agreement.
    """
    rows, stats = [], collections.Counter()
    sub = Subjects()
    for name, (val, w) in sorted(ex.regs.items()):
        if wp_seed.reg_to_riscv(name) is None:
            stats['tracer-only-id'] += 1
            continue
        if name not in truth:
            stats['reference-silent'] += 1
            continue
        mask = (1 << (8 * w)) - 1 if 0 < w < 8 else (1 << 64) - 1
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
        if name not in ex.regs and not name.startswith('REG_VEC'):
            stats['not-reconstructed'] += 1
            reg_gaps.add(name)
            rows.append(Row(guest, ex.seq, -1, ex.start_pc, 'wp-entry-state',
                            RECON_GAP, '%s=0x%x' % (name, truth[name]),
                            'ABSENT', 'the wire never stated this register'))
    return rows, stats, sub


# ------------------------------------------------------------------ driver
def excursion_gaps(ex, seedgaps):
    """What the reconstruction could not establish, as evidence.

    ``unestablished`` is every address this excursion READS that no ELF byte,
    no correct-path load datum and no correct-path store datum ever put a
    value under.  Computed from the excursion's own accesses so it is a fact
    about this experiment, not a whole-address-space claim.
    """
    unest = set()
    for ins in ex.insns:
        for addr, _d, size in ins.loads:
            for k in range(addr, addr + (size or 8)):
                if k not in ex.mem_src:
                    unest.add(k)
    return {'reg_gaps': set(), 'unestablished': unest, 'seedgaps': seedgaps}


def guest_ranges(xr):
    def sel(pc):
        return any(lo <= pc < hi for lo, hi in xr)
    return sel


def process_guest(args, guest, out):
    stem = os.path.join(out, os.path.basename(guest))
    trace = run_tracer(args.qemu, args.plugin, guest, stem, args.wpdepth)
    image, xranges, _entry = elfimage.load(guest)
    exc, cp, tstats = wp_trace.build(args.decode, trace, image)

    # ---- correct-path ground truth for the entry state
    cplog = run_spike_pk(args.spike, args.pk, guest, stem, args.dtc_dir,
                         args.isa)
    spike_ref.require_patched(cplog, 1)
    lo = min(l for l, _h in xranges)
    hi = max(h for _l, h in xranges)
    refcp = spike_ref.parse_commit_log(cplog, lo, hi, priv=0)
    snaps = ground_truth(refcp)
    pairs = align(refcp, cp)
    trc2ref = dict((t, r) for r, t in pairs if r is not None and t is not None)

    distinct = wp_trace.dedupe(exc)
    rows, stats, tails = [], collections.Counter(), collections.Counter()
    sub = Subjects()
    stats['excursions-dynamic'] = len(exc)
    stats['excursions-distinct'] = len(distinct)
    stats['cp-aligned'] = len(trc2ref)
    stats['cp-ref-insns'] = len(refcp)
    stats['cp-trc-insns'] = len(cp)
    sel = guest_ranges(xranges)

    todo = distinct if args.max <= 0 else distinct[:args.max]
    stats['excursions-run'] = len(todo)
    stats['excursions-stood-for'] = sum(n for _e, n in todo)
    for k, (ex, mult) in enumerate(todo):
        tag = '%s.e%04d' % (os.path.basename(guest), k)
        elf, mem, seedgaps, unmapped = wp_seed.build(out, tag, ex)
        cap = args.prologue_cap + len(ex.insns) + 8
        log = run_spike_injected(args.spike, elf, mem,
                                 os.path.join(out, tag), args.dtc_dir,
                                 args.isa, cap)
        ref = [i for i in spike_ref.parse_commit_log(log) if sel(i.pc)]
        gapinfo = excursion_gaps(ex, seedgaps)
        # entry-state truth: the reference index this excursion sits at
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
        stats['wp-insns-declared'] += len(ex.insns)
        if not ref:
            rows.append(Row(guest, ex.seq, 0, ex.start_pc, 'pc-sequence',
                            SPIKE_LIMIT, 'no guest-range commit', '0x%x'
                            % ex.start_pc,
                            'the injected run retired nothing in the guest; '
                            'the first instruction trapped'))
            stats['excursion-trapped'] += 1
            tails['reference-retired-nothing'] += len(ex.insns)
            continue
        r, compared, csub = compare_excursion(guest, ex, ref, gapinfo)
        sub.merge(csub)
        rows.extend(r)
        stats['wp-insns-compared'] += compared
        tail = len(ex.insns) - compared
        if tail:
            tails['reference-stopped-short' if len(ref) < len(ex.insns)
                  else 'pc-diverged'] += tail
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


def render(rows, stats, tails, guests, sub):
    out = []
    w = out.append
    w('=' * 74)
    w('ARC 3 -- riscv64 WRONG-PATH execution cross-check vs Spike')
    w('=' * 74)
    w('')
    w('The wrong-path arm had NO execution reference on any ISA.  Every')
    w('excursion below was rebuilt from the trace alone -- the REGFILE seed,')
    w('the destination snapshots, the correct-path load and store data and')
    w('the guest image -- injected into a real simulator at the excursion\'s')
    w('own PC, and compared instruction for instruction.')
    w('')
    w('AXES: ' + ', '.join(AXES) + ', wp-entry-state')
    w('')
    hdr = '%-28s %10s' % ('measure', 'count')
    w(hdr)
    w('-' * len(hdr))
    for k in sorted(stats):
        w('%-28s %10d' % (k, stats[k]))
    w('')
    dec, cmpd = stats['wp-insns-declared'], stats['wp-insns-compared']
    w('=' * 74)
    w('THE DECLARED-VS-COMPARED IDENTITY.  A gap here is never left to be')
    w('rediscovered: every wrong-path instruction the tracer declared is')
    w('either compared against the reference or sits in a NAMED tail.  The')
    w('difference used to be printed as two numbers and reconciled by hand.')
    w('Spike prints a commit line only on completion, so at the exit ecall')
    w('an excursion runs into, the reference\'s pc-sequence ends while the')
    w('tracer\'s continues -- that silence is the reference\'s, and it is')
    w('already counted one SPIKE-LIMIT row at a time.')
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
    w('or a SPIKE LIMIT, and never a fourth thing.')
    w('')
    byv = collections.Counter(r.verdict for r in rows)
    bya = collections.Counter((r.axis, r.verdict) for r in rows)
    for line in sub.render(AXES + ('wp-entry-state',), bya, VERDICTS):
        w(line)
    w('THE NUMBER THAT MATTERS: WP-DEFECT + RECONSTRUCTION-GAP +')
    w('UNACCOUNTED = %d.  TRACER-SUPERSET rows are COVERED -- each carries a'
      % (byv[WP_DEFECT] + byv[RECON_GAP] + byv[UNACCOUNTED]))
    w('named rule from arc3_rules.RISCV_EXEC saying why the reference cannot')
    w('state the fact.  SPIKE-LIMIT rows are the reference\'s own silence and')
    w('are named one by one, never counted as agreement.')
    w('')
    if not rows:
        w('NO DIVERGENCE on any axis, over every excursion run.  That is a')
        w('result only because the negative control (selftest_wp.py) shows')
        w('every axis CAN fire; a check that cannot fire agrees forever.')
        w('')
    else:
        w('EVERY ROW, none summarised away:')
        w('')
        for r in rows[:400]:
            w('  %-20s %-16s %-8s pc=0x%x idx=%d'
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
    ap.add_argument('--spike', required=True)
    ap.add_argument('--pk', required=True)
    ap.add_argument('--qemu', required=True)
    ap.add_argument('--plugin', required=True)
    ap.add_argument('--decode', required=True)
    ap.add_argument('--dtc-dir')
    ap.add_argument('--isa', default='rv64gcv')
    ap.add_argument('--wpdepth', type=int, default=8)
    ap.add_argument('--max', type=int, default=64,
                    help='distinct excursions to run per guest; <=0 for all')
    ap.add_argument('--prologue-cap', type=int, default=900,
                    help='instruction budget the injection prologue needs; '
                         'it is excluded by ADDRESS, this only bounds spike')
    ap.add_argument('-o', '--outdir', required=True)
    ap.add_argument('--tsv')
    a = ap.parse_args()

    os.makedirs(a.outdir, exist_ok=True)
    rows, stats, tails = [], collections.Counter(), collections.Counter()
    sub = Subjects()
    for g in a.guest:
        r, s, t, f = process_guest(a, g, a.outdir)
        rows.extend(r)
        stats.update(s)
        tails.update(t)
        sub.merge(f)
    sub.write_tsv(os.path.join(a.outdir, 'axis_subjects.tsv'),
                  AXES + ('wp-entry-state',))
    txt, identity_ok = render(rows, stats, tails, a.guest, sub)
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
