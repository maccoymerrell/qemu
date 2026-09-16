"""
Score the EMITTER-STATED intra-instruction dependency map against gem5.

    usage: score_depmap.py --isa <x86_64|aarch64> --qemu-dir D --gem5-dir D
                           -o OUT  <guest> [<guest> ...]

WHAT IS BEING ASKED
===================
The wire states four dependency families -- which inputs reach each
destination register, each stored datum, each load address and each store
address.  Where the wire states nothing, ``docs/format.rst`` makes the reader
assume the all-to-all over-approximation, and ``cst_decode`` renders that
default, so what is scored here is WHAT A CONSUMER SEES.

gem5 is the only reference that can convict the map.  CP-M and CP-H derive it
from QEMU's emitters, and Capstone gives architectural operands with no edges
at all; gem5 cracks each macro-op into micro-ops carrying explicit
``srcRegIdx``/``destRegIdx`` lists that its O3 model renames over, which is
the R7 regfile-dependency semantics at intra-instruction granularity.

THE SCOPE GUARD IS PART OF THE METHOD, NOT A CAVEAT
---------------------------------------------------
gem5's micro-op decomposition is gem5's IMPLEMENTATION choice.  Nothing here
scores micro-op COUNT, and every loaded value collapses to one ``LD`` token on
both sides, so a paired load cracked into two micro-ops against the wire's one
memop slot cannot read as a dependency disagreement.  Only two things convict:

    MISSING-EDGE       gem5 renames a source into a destination that the map's
                       set for that destination does not contain
    STRICTLY-SMALLER   the map's set for a destination properly CONTAINS
                       gem5's -- precision the trace is discarding

and both are computed on the COMMON UNIVERSE: the intersection of the two
sides' input sets.  That is what keeps this axis separate from the register
SET axis ``compare_exec_gem5`` already scores.  A register only one side names
is a set disagreement, already counted there, and letting it in here would
double-count it as an edge.

Author: Maccoy Merrell.
"""
import argparse
import collections
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import gem5_depmap                                              # noqa: E402
import tracer_depmap                                            # noqa: E402
import depmap_refiners                                          # noqa: E402
import compare_exec_gem5 as C                                   # noqa: E402

AXES = ('dst-dep', 'store-data-dep', 'load-addr-dep', 'store-addr-dep')

#: never scored: gem5 names no immediate operand in ``SR=``, so an immediate
#: edge is unobservable in this reference.  Removed from BOTH sides, and the
#: number of masks that carried it is reported so the blind spot has a size.
UNOBSERVABLE = ('imm',)


def _u(s):
    return set(x for x in s if x not in UNOBSERVABLE)


class Tally(object):
    def __init__(self):
        self.facts = 0
        self.agree = 0
        self.missing = 0
        self.smaller = 0
        self.both = 0
        self.rows = []

    def add(self, t, g, ctx):
        self.facts += 1
        if t == g:
            self.agree += 1
            return 'AGREE'
        miss = g - t
        extra = t - g
        if miss and extra:
            self.both += 1
            v = 'BOTH'
        elif miss:
            self.missing += 1
            v = 'MISSING-EDGE'
        else:
            self.smaller += 1
            v = 'STRICTLY-SMALLER'
        if len(self.rows) < 4000:
            self.rows.append(dict(ctx, verdict=v,
                                  tracer=sorted(t), gem5=sorted(g)))
        return v


def align(tr, g5):
    """Pair the two streams on PC, in execution order.

    A greedy walk with a bounded resync, and every unpaired entry counted on
    the side it came from.  Nothing is dropped quietly: an alignment that
    silently skips is how a comparison ends up reporting a denominator it
    never met.
    """
    out = []
    i = j = 0
    skipped_t = skipped_g = 0
    while i < len(tr) and j < len(g5):
        if tr[i].pc == g5[j].pc:
            out.append((tr[i], g5[j]))
            i += 1
            j += 1
            continue
        for k in range(1, 8):
            if j + k < len(g5) and g5[j + k].pc == tr[i].pc:
                skipped_g += k
                j += k
                break
            if i + k < len(tr) and tr[i + k].pc == g5[j].pc:
                skipped_t += k
                i += k
                break
        else:
            skipped_t += 1
            skipped_g += 1
            i += 1
            j += 1
    skipped_t += len(tr) - i
    skipped_g += len(g5) - j
    return out, skipped_t, skipped_g


def run_gem5_bounded(binary, cfg, env, guest, outdir, maxinsts):
    """A gem5 run stopped after N instructions.

    ONLY legitimate under ``--join=pc``.  ``compare_exec_gem5`` refuses a
    truncated run because scoring a short instruction STREAM against a
    complete one manufactures TRACER-SUPERSET rows out of the harness's own
    failure.  A PC join cannot do that: it scores only the identities BOTH
    sides observed, so truncation costs coverage and nothing else.  The
    coverage it costs is reported as the paired count.
    """
    d = os.path.join(outdir, os.path.basename(guest) + '.g5')
    p = subprocess.run([binary, '-d', d, '--debug-flags=' + C.DBG,
                        '--debug-file=exec.log', cfg,
                        '--cpu-type=AtomicSimpleCPU',
                        '-I', str(maxinsts), '-c', guest],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       env=env)
    tail = p.stdout.decode('utf-8', 'replace')
    with open(os.path.join(outdir,
                           os.path.basename(guest) + '.gem5.out'), 'w') as fh:
        fh.write(tail)
    log = os.path.join(d, 'exec.log')
    if p.returncode < 0:
        raise RuntimeError('gem5 died on signal %d running %s'
                           % (-p.returncode, guest))
    if not os.path.exists(log) or os.path.getsize(log) == 0:
        raise RuntimeError('gem5 wrote no exec.log for %s' % guest)
    return log


def join_pc(tr, g5):
    """Join the two sides on INSTRUCTION IDENTITY rather than execution order.

    The dependency map is a property of the ENCODING, not of one dynamic
    instance, so a PC is the right key for it.  gem5's map for a PC is
    checked for STABILITY across every execution of that PC and an unstable
    one is DROPPED and counted -- if the reference itself gives two answers
    for one identity, neither can convict.
    """
    gm, unstable = {}, 0
    for g in g5:
        key = g.pc
        sig = (tuple(sorted((k, tuple(sorted(v)))
                            for k, v in g.dst_dep.items())),
               tuple(tuple(sorted(x)) for x in g.load_addr),
               tuple(tuple(sorted(x)) for x in g.store_addr),
               tuple(tuple(sorted(x)) for x in g.store_data))
        if key in gm:
            if gm[key][0] != sig:
                gm[key] = (gm[key][0], None)
            continue
        gm[key] = (sig, g)
    for k, v in list(gm.items()):
        if v[1] is None:
            unstable += 1
            del gm[k]
    seen, pairs, tskip = set(), [], 0
    for t in tr:
        if t.pc in seen:
            continue
        seen.add(t.pc)
        g = gm.get(t.pc)
        if g is None:
            tskip += 1
            continue
        pairs.append((t, g[1]))
    return pairs, tskip, len(gm) - len(pairs), unstable


def score_pair(t, g, att, tallies, per_family, imm_masks, notes):
    fam, fam_now, enum = att.family(t.pc, t.bits)
    # The COMMON UNIVERSE.  A register only one side names is a SET
    # disagreement, which `compare_exec_gem5` already scores on its own axis;
    # admitting it here would count the same fact twice, once as a missing
    # register and again as a missing edge.  The load token is an input to
    # either side that performed a load.
    tsrc = _u(tracer_depmap.sources(t))
    gsrc = _u(g.srcs)
    if g.load_addr:
        gsrc.add(gem5_depmap.LOAD_TOKEN)
    if t.load_addr:
        tsrc.add(gem5_depmap.LOAD_TOKEN)
    univ = tsrc & gsrc
    # THE ADDRESS AXES TAKE A WIDER UNIVERSE, and the reason is that the
    # narrow one made them unfalsifiable.  An x86 base register usually has
    # no other role in its instruction, so emptying `laddr0` removes it from
    # `tsrc` as well and the intersection cannot see the edge that was
    # deleted: measured, the drop-addr-edge falsifier moved 0 of 45 x86
    # load-addr rows.  A register named as an address by only ONE side is not
    # a register-SET disagreement -- `compare_exec_gem5` does not score
    # address ROLES at all -- so admitting it here double-counts nothing.
    univ_addr = tsrc | gsrc
    ctx = {'pc': t.pc, 'enum': enum, 'family': fam,
           'gem5': g.macro or '', 'uops': g.uops}

    addr_regs = set()
    for v in t.load_addr + t.store_addr:
        addr_regs |= v

    def mechanism(axis, slot, tt, gg, v):
        """A NAME for every disagreeing row.  "N disagree" is never a result.

        Derived from the two SETS and the instruction's own addressing
        registers, never from a mnemonic: the same shape has to be named the
        same way on both targets.
        """
        if v == 'AGREE':
            return None
        if (axis in ('load-addr-dep', 'store-addr-dep')
                and (tt - gg) == {'REG_PC'}):
            # gem5's x86 decoder resolves RIP-relative addressing at DECODE
            # time -- the displacement is folded against the instruction's
            # own PC and length -- so its address micro-op names no register
            # at all.  The trace names REG_PC, which is architecturally right
            # and strictly more informative.  Reference-side, and named here
            # so that 345 rows of it cannot read as trace imprecision.
            return 'REF-RIP-RELATIVE-FOLDED'
        if v == 'STRICTLY-SMALLER':
            # Sound: the map contains every edge gem5 renames, and more.
            return ('REF-FP-CONTROL-UNMODELLED'
                    if ('REG_FCSR' in (tt ^ gg) or 'REG_FPCW' in (tt ^ gg))
                    else 'PRECISION-DISCARDED')
        if axis == 'dst-dep' and slot in addr_regs:
            # The destination IS one of the instruction's addressing
            # registers -- a post-index / pre-index WRITEBACK.  Its true and
            # only source is the base register it increments, and the map
            # instead names the value the access moved.
            return 'WRITEBACK-DEST-EDGE-INVERTED'
        if 'REG_FCSR' in (tt ^ gg) or 'REG_FPCW' in (tt ^ gg):
            return 'REF-FP-CONTROL-UNMODELLED'
        if v == 'MISSING-EDGE':
            return 'TRACER-SUBSET'
        if v == 'BOTH':
            return 'EDGE-DISJOINT'
        return 'PRECISION-DISCARDED'

    def rec(axis, tv, gv, slot):
        if any(x in UNOBSERVABLE for x in tv):
            imm_masks[axis] += 1
        u = univ_addr if axis in ('load-addr-dep', 'store-addr-dep') else univ
        tt, gg = _u(tv) & u, _u(gv) & u
        c = dict(ctx, axis=axis, slot=slot)
        v = tallies[axis].add(tt, gg, c)
        mech = mechanism(axis, slot, tt, gg, v)
        if mech:
            notes['mech:' + mech] += 1
            if tallies[axis].rows and tallies[axis].rows[-1].get('slot') == slot:
                tallies[axis].rows[-1]['mechanism'] = mech
        key = (fam, axis)
        pf = per_family.setdefault(key, Tally())
        pf.facts += 1
        setattr(pf, {'AGREE': 'agree', 'MISSING-EDGE': 'missing',
                     'STRICTLY-SMALLER': 'smaller', 'BOTH': 'both'}[v],
                getattr(pf, {'AGREE': 'agree', 'MISSING-EDGE': 'missing',
                             'STRICTLY-SMALLER': 'smaller',
                             'BOTH': 'both'}[v]) + 1)
        return v

    def fold(tl, gl, axis):
        """Compare slot-for-slot, or FOLDED when the two slot counts differ.

        A differing count is GRANULARITY, not disagreement: the wire's
        ``max_dep_stores`` counts an instruction's static memory OPERANDS
        (format.rst 4.5) while gem5 cracks one operand into several micro-ops,
        so `stp x0, x1, [x20]` is one slot against two.  Comparing slot 0 to
        slot 0 there convicts the trace of omitting x1 from a slot that
        legitimately covers both.  When the counts differ the two sides are
        folded to their unions and the fold is counted.
        """
        if not tl or not gl:
            return []
        if len(tl) == len(gl):
            return [(k, tl[k], gl[k]) for k in range(len(tl))]
        notes['slot-count-folded:' + axis] += 1
        return [('fold', set().union(*tl), set().union(*gl))]

    verdicts = []
    for d, tv in t.dst_dep.items():
        if d not in g.dst_dep:
            notes['dst-only-in-tracer'] += 1
            continue
        verdicts.append((d, rec('dst-dep', tv, g.dst_dep[d], d)))
    for d in g.dst_dep:
        if d not in t.dst_dep:
            notes['dst-only-in-gem5'] += 1
    if g.ambiguous_store:
        notes['store-split-ambiguous'] += g.ambiguous_store
    else:
        for k, tv, gv in fold(t.store_data, g.store_data, 'store-data-dep'):
            verdicts.append(('sd%s' % k, rec('store-data-dep', tv, gv, k)))
        for k, tv, gv in fold(t.store_addr, g.store_addr, 'store-addr-dep'):
            verdicts.append(('sa%s' % k, rec('store-addr-dep', tv, gv, k)))
    for k, tv, gv in fold(t.load_addr, g.load_addr, 'load-addr-dep'):
        verdicts.append(('la%s' % k, rec('load-addr-dep', tv, gv, k)))
    return fam, enum, verdicts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--isa', required=True, choices=('x86_64', 'aarch64'))
    ap.add_argument('--qemu-dir', required=True)
    ap.add_argument('--gem5-dir', required=True)
    ap.add_argument('-o', '--out', required=True)
    ap.add_argument('--decode')
    ap.add_argument('--join', default='seq', choices=('seq', 'pc'),
                    help='seq: lockstep on the execution order, which is what '
                         'a -nostdlib probe supports.  pc: join the two sides '
                         'on INSTRUCTION IDENTITY instead, which is what the '
                         'dependency map is a property of -- it survives '
                         'divergent control flow and a bounded gem5 run, at '
                         'the cost of scoring each identity once.')
    ap.add_argument('--gem5-maxinsts', type=int, default=0)
    ap.add_argument('--tracer-max', type=int, default=0)
    ap.add_argument('--falsify', default='none',
                    choices=('none', 'drop-edge', 'add-edge', 'swap-addr-data',
                             'all-to-all', 'drop-addr-edge'))
    ap.add_argument('guests', nargs='+')
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    decode = a.decode or os.path.join(
        a.qemu_dir, 'build/contrib/plugins/cst_decode')

    binary, cfg, env, _notes = C.gem5_prereqs(a.gem5_dir, a.isa, a.out)
    att = depmap_refiners.Attributor(a.qemu_dir, a.isa)

    tallies = dict((ax, Tally()) for ax in AXES)
    per_family = {}
    imm_masks = collections.Counter()
    notes = collections.Counter()
    fam_seen = collections.defaultdict(set)      # family -> {enum}
    fam_smaller = collections.defaultdict(set)   # family -> {enum with < set}
    fam_missing = collections.defaultdict(set)
    align_notes = collections.Counter()

    for guest in a.guests:
        if a.gem5_maxinsts:
            log = run_gem5_bounded(binary, cfg, env, guest, a.out,
                                   a.gem5_maxinsts)
        else:
            log = C.run_gem5(binary, cfg, env, a.isa, guest, a.out)
        g5 = gem5_depmap.build_all(a.isa, log)
        cst = C.run_tracer(a.qemu_dir, a.isa, guest, a.out)
        cmd = [decode, '--show-deps']
        if a.tracer_max:
            cmd += ['--max', str(a.tracer_max)]
        cmd.append(cst)
        if a.join == 'pc':
            # STREAMED and deduplicated by PC.  A full workload decode is tens
            # of millions of lines and the dependency map has one answer per
            # IDENTITY, so materialising the body would spend gigabytes to
            # learn nothing extra -- the same eager-materialisation mistake
            # that took this host down at ~190 GiB once already.
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    universal_newlines=True, errors='replace')
            tr = []
            seen = set()
            for ins in tracer_depmap.iter_parse(proc.stdout):
                if ins.pc in seen:
                    continue
                seen.add(ins.pc)
                tr.append(ins)
            proc.stdout.close()
            rc = proc.wait()          # the PROCESS's status, never a pipe's
            if rc != 0:
                raise RuntimeError('cst_decode exit %d on %s' % (rc, cst))
        else:
            txt = os.path.join(a.out,
                               os.path.basename(guest) + '.deps.txt')
            with open(txt, 'w') as fh:
                p = subprocess.run(cmd, stdout=fh)
            if p.returncode != 0:
                raise RuntimeError('cst_decode exit %d on %s'
                                   % (p.returncode, cst))
            tr = tracer_depmap.parse(txt)
        if a.falsify != 'none':
            tr = _falsify(a.falsify, tr)
        if a.join == 'pc':
            pairs, st, sg, unstable = join_pc(tr, g5)
            align_notes['gem5-pc-unstable'] += unstable
        else:
            pairs, st, sg = align(tr, g5)
        align_notes['paired'] += len(pairs)
        align_notes['tracer-unpaired'] += st
        align_notes['gem5-unpaired'] += sg
        for t, g in pairs:
            fam, enum, verdicts = score_pair(t, g, att, tallies, per_family,
                                             imm_masks, notes)
            if enum:
                fam_seen[fam].add(enum)
                for _slot, v in verdicts:
                    if v in ('STRICTLY-SMALLER', 'BOTH'):
                        fam_smaller[fam].add(enum)
                    if v in ('MISSING-EDGE', 'BOTH'):
                        fam_missing[fam].add(enum)

    report(a, tallies, per_family, imm_masks, notes, fam_seen, fam_smaller,
           fam_missing, align_notes, att)
    bad = sum(t.missing + t.both for t in tallies.values())
    inert = [ax for ax in AXES if tallies[ax].facts == 0]
    return 1 if (bad or inert) else 0


def _falsify(kind, tr):
    """Make a KNOWN change to the tracer side and require the axis to convict.

    An axis nobody could falsify is not a validated axis, so every one of
    these must FIRE.
    """
    for ins in tr:
        if kind == 'drop-edge':
            for d, v in ins.dst_dep.items():
                if v:
                    ins.dst_dep[d] = set(sorted(v)[1:])
            ins.store_data = [set(sorted(s)[1:]) for s in ins.store_data]
        elif kind == 'add-edge':
            # The spurious edge must be a register the INSTRUCTION already
            # names, or the common-universe restriction filters it out and the
            # falsifier is inert.  Measured: adding REG_GPR31 -- a register no
            # probe touches -- moved 4 rows where this moves the population.
            extra = set()
            for v in ins.load_addr + ins.store_addr:
                extra |= v
            if not extra:
                continue
            for d in ins.dst_dep:
                ins.dst_dep[d] = ins.dst_dep[d] | extra
            ins.store_data = [s | extra for s in ins.store_data]
        elif kind == 'drop-addr-edge':
            # The four earlier falsifiers convict dst-dep, store-data-dep and
            # store-addr-dep and leave LOAD-ADDR-DEP untouched -- measured, 0
            # in all eight cells.  An axis nobody could falsify is not a
            # validated axis, so it gets its own.
            ins.load_addr = [set(sorted(v)[1:]) for v in ins.load_addr]
            ins.store_addr = [set(sorted(v)[1:]) for v in ins.store_addr]
        elif kind == 'swap-addr-data':
            ins.store_data, ins.store_addr = ins.store_addr, ins.store_data
        elif kind == 'all-to-all':
            allin = tracer_depmap.sources(ins)
            for d in ins.dst_dep:
                ins.dst_dep[d] = set(allin)
            ins.store_data = [set(allin) for _ in ins.store_data]
    return tr


def report(a, tallies, per_family, imm_masks, notes, fam_seen, fam_smaller,
           fam_missing, align_notes, att):
    lines = []
    w = lines.append
    w('# intra-instruction dependency map vs gem5 -- %s' % a.isa)
    w('')
    w('falsify=%s   guests=%s' % (a.falsify, ' '.join(
        os.path.basename(g) for g in a.guests)))
    w('alignment: %s' % dict(align_notes))
    w('')

    # ---- THE HEADLINE BLOCK -- what the R13 gate reads ---------------------
    #
    # This leg is scored by external_truth_gate/score.py, and that scorer
    # refuses to guess: a headline it cannot parse is a FAILURE and never a
    # zero.  So the three numbers it holds against the manifest are stated
    # here, on their own lines, by the process that computed them.
    #
    # TWO ceilings, not one, and the reason is the falsifiers.  The loss
    # direction (MISSING-EDGE + BOTH -- the map omits an edge the reference
    # states) is what R12.1 forbids, and it is the criterion.  But three of
    # the five falsifiers this instrument carries -- add-edge, all-to-all and
    # part of drop-addr-edge -- land in STRICTLY-SMALLER, so a gate holding
    # only the loss number would be BLIND to the arms that prove the axis can
    # convict.  The precision number is therefore held at its adjudicated
    # measurement too, exactly like `pin`: no margin, and a row above it is a
    # finding to open rather than slack to spend.
    loss = sum(tallies[ax].missing + tallies[ax].both for ax in AXES)
    prec = sum(tallies[ax].smaller for ax in AXES)
    facts = sum(tallies[ax].facts for ax in AXES)
    inert = [ax for ax in AXES if tallies[ax].facts == 0]
    w('THE NUMBER THAT MATTERS: MISSING-EDGE + BOTH = %d' % loss)
    w('PRECISION-DISCARDED (STRICTLY-SMALLER) = %d' % prec)
    w('TOTAL FACTS = %d' % facts)
    w('INERT AXES = %d%s' % (len(inert),
                             ('  [%s]' % ' '.join(inert)) if inert else ''))
    w('')
    w('## axes')
    w('')
    w('| axis | facts | agree | MISSING-EDGE | STRICTLY-SMALLER | BOTH |')
    w('|---|---|---|---|---|---|')
    for ax in AXES:
        t = tallies[ax]
        if t.facts == 0:
            w('| %s | **INERT 0** | - | - | - | - |' % ax)
        else:
            w('| %s | %d | %d | %d | %d | %d |'
              % (ax, t.facts, t.agree, t.missing, t.smaller, t.both))
    w('')
    w('An axis reading 0 facts is INERT: it is a demand for a better probe, '
      'never a pass.')
    w('')
    w('## per refiner family')
    w('')
    w('| family | axis | facts | agree | MISSING | SMALLER | BOTH |')
    w('|---|---|---|---|---|---|---|')
    for (fam, ax) in sorted(per_family,
                            key=lambda k: (str(k[0]), k[1])):
        t = per_family[(fam, ax)]
        w('| %s | %s | %d | %d | %d | %d | %d |'
          % (fam or '(no refiner row)', ax, t.facts, t.agree, t.missing,
             t.smaller, t.both))
    w('')
    w('## the retirement question, per family')
    w('')
    w('For how many DISTINCT table rows -- reached by an OBSERVED decode, '
      'never listed from the table -- does gem5 show a strictly smaller true '
      'dependency set than the map publishes?')
    w('')
    w('| family | rows in table | rows observed | rows STRICTLY SMALLER | '
      'rows MISSING-EDGE |')
    w('|---|---|---|---|---|')
    tab = collections.Counter(att.fam.values())
    for fam in sorted(set(list(fam_seen) + list(tab)), key=str):
        if fam is None and not fam_seen.get(fam):
            continue
        w('| %s | %s | %d | %d | %d |'
          % (fam or '(no refiner row)', tab.get(fam, '-') if fam else '-',
             len(fam_seen.get(fam, ())), len(fam_smaller.get(fam, ())),
             len(fam_missing.get(fam, ()))))
    w('')
    w('## reference-side and harness notes (every one counted)')
    w('')
    for k, v in sorted(notes.items()):
        w('  %-28s %d' % (k, v))
    for k, v in sorted(att.miss.items()):
        w('  attribution:%-17s %d' % (k, v))
    for k, v in sorted(imm_masks.items()):
        w('  imm-bearing masks on %-8s %d  (imm is UNOBSERVABLE in gem5)'
          % (k, v))
    txt = '\n'.join(lines) + '\n'
    with open(os.path.join(a.out, 'REPORT.md'), 'w') as fh:
        fh.write(txt)
    with open(os.path.join(a.out, 'rows.json'), 'w') as fh:
        json.dump(dict((ax, tallies[ax].rows) for ax in AXES), fh, indent=1)
    sys.stdout.write(txt)


if __name__ == '__main__':
    sys.exit(main())
