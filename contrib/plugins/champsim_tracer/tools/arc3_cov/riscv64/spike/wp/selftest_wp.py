"""
The negative control for the wrong-path execution leg.

A green cross-check is a result only if every axis it scores CAN go red.  This
project has been caught by checks that reported success without verifying, so
each axis here is deliberately broken on one side of one real aligned pair and
the axis that owns that fact is required to fire.  An axis with no firing
mutation reports UNPROVEN and its zero is not counted as a pass.

TWO KINDS OF CONTROL, AND BOTH ARE NEEDED
=========================================
1. COMPARATOR controls.  Perturb the tracer's record of one instruction and
   require the owning axis to report it.  These prove the comparison reads the
   fields it claims to read.

2. THE INJECTION control.  Perturb the STATE that is installed into the
   simulator and require the simulator's own execution to change.  This is the
   load-bearing one: without it, an agreement could mean the reconstruction is
   correct, or it could mean the reconstruction never reached the simulator and
   the excursion followed the same path regardless.  The two are
   indistinguishable from the comparison alone.

Author: Maccoy Merrell.
"""
import argparse
import collections
import copy
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, '..'))
sys.path.insert(0, os.path.join(_HERE, '..', '..', '..'))

import elfimage                                              # noqa: E402
import wp_trace                                              # noqa: E402
import wp_seed                                               # noqa: E402
import spike_ref                                             # noqa: E402
import compare_wp as C                                       # noqa: E402


def _pick(exc, pred):
    for ex in exc:
        for i, ins in enumerate(ex.insns):
            if pred(ins):
                return ex, i
    return None, None


def mutations(ex, ref):
    """[(axis, description, mutated excursion)] -- one per axis, on real data."""
    out = []

    def clone():
        return copy.deepcopy(ex)

    m = clone()
    m.insns[0].pc ^= 0x10
    out.append(('pc-sequence', 'move the first WP PC by 0x10', m))

    m = clone()
    m.insns[0].bits ^= 0xff
    out.append(('insn-bits', 'flip the low byte of the first encoding', m))

    for i, ins in enumerate(ex.insns):
        if ins.writes:
            m = clone()
            m.insns[i].writes = []
            out.append(('reg-dst-set', 'drop the destination of insn %d' % i,
                        m))
            m = clone()
            n, v, w = m.insns[i].writes[0]
            m.insns[i].writes[0] = (n, v ^ 0x5a5a, w)
            out.append(('reg-dst-value', 'corrupt the value of insn %d' % i,
                        m))
            break

    for i, ins in enumerate(ex.insns):
        if ins.srcs:
            m = clone()
            m.insns[i].srcs = ins.srcs[1:]
            out.append(('reg-src-set', 'drop a source of insn %d' % i, m))
            break

    # loads and stores are walked SEPARATELY.  Taking "the first instruction
    # with a memop" left store-data with no mutation whenever that
    # instruction happened to be a load, which is how an axis ends up
    # unprovable without anyone noticing.
    for which, axis in (('loads', 'load-data'), ('stores', 'store-data')):
        for i, ins in enumerate(ex.insns):
            recs = getattr(ins, which)
            if not recs:
                continue
            m = clone()
            getattr(m.insns[i], which).pop()
            out.append(('memop-count',
                        'drop the %s of insn %d' % (which[:-1], i), m))
            m = clone()
            a, d, sz = getattr(m.insns[i], which)[0]
            getattr(m.insns[i], which)[0] = (a + 8, d, sz)
            out.append(('memop-addr',
                        'move the %s address of insn %d' % (which[:-1], i), m))
            if sz:
                m = clone()
                a, d, sz2 = getattr(m.insns[i], which)[0]
                getattr(m.insns[i], which)[0] = (a, d, max(1, sz2 // 2))
                out.append(('memop-width',
                            'halve the %s width of insn %d' % (which[:-1], i),
                            m))
            if d is not None:
                m = clone()
                a, d2, sz2 = getattr(m.insns[i], which)[0]
                getattr(m.insns[i], which)[0] = (a, d2 ^ 0xff, sz2)
                out.append((axis, 'corrupt the %s datum of insn %d'
                            % (which[:-1], i), m))
            break
    return out


def _clean_pairs(args, guest, limit):
    """[(excursion, reference)] for excursions whose baseline comparison is
    clean.  A mutation proves nothing against a pair that already disagrees:
    the axis would have fired anyway."""
    image, xranges, _e = elfimage.load(guest)
    stem = os.path.join(args.outdir, os.path.basename(guest))
    trace = C.run_tracer(args.qemu, args.plugin, guest, stem, args.wpdepth)
    exc, _cp, _st = wp_trace.build(args.decode, trace, image)
    if not exc:
        # straight-line code kicks no excursion.  That is a property of the
        # guest, not a failure of the control; the caller reports which
        # guests contributed.
        return []
    sel = C.guest_ranges(xranges)
    out = []
    for k, ex in enumerate(exc):
        if len(out) >= limit:
            break
        tag = '%s.st%04d' % (os.path.basename(guest), k)
        elf, mem, _g, _u = wp_seed.build(args.outdir, tag, ex)
        log = C.run_spike_injected(args.spike, elf, mem,
                                   os.path.join(args.outdir, tag),
                                   args.dtc_dir, args.isa,
                                   args.prologue_cap + len(ex.insns) + 8)
        ref = [i for i in spike_ref.parse_commit_log(log) if sel(i.pc)]
        gi = C.excursion_gaps(ex, [])
        # A reference that stops early (spike is silent about a trapping
        # instruction) still supports every mutation that lands inside the
        # prefix it DID retire; requiring the full length instead left the
        # memop axes with no subject at all.
        if len(ref) >= 4:
            base, _cmp = C.compare_excursion(guest, ex, ref, gi)
            # Cleanliness is judged PER AXIS, not globally: an excursion whose
            # store-conditional already reports a named TRACER-SUPERSET on
            # memop-count is still a sound subject for a reg-dst-value
            # mutation, and refusing it outright is how the memop axes ended
            # up with no mutation at all.
            out.append((ex, ref, set(r.axis for r in base)))
    return out


def run(args):
    pairs = []
    for g in args.guest:
        pairs.extend((g, ex, ref, dirty)
                     for ex, ref, dirty in _clean_pairs(args, g, 6))
    if not pairs:
        raise RuntimeError('no clean aligned excursion to mutate: the control '
                           'cannot prove anything against a pair that already '
                           'disagrees')

    fired = collections.Counter()
    attempted = set()
    lines = []
    for guest, ex, ref, dirty in pairs:
        for axis, what, m in mutations(ex, ref):
            if fired[axis] or axis in dirty:
                continue          # one firing mutation per axis is the bar
            attempted.add(axis)
            rows, _cmp = C.compare_excursion(guest, m, ref,
                                             C.excursion_gaps(m, []))
            hit = [r for r in rows if r.axis == axis and
                   r.verdict in (C.WP_DEFECT, C.RECON_GAP, C.UNACCOUNTED)]
            fired[axis] += bool(hit)
            lines.append('  %-14s %-14s %-40s %s'
                         % (axis, os.path.basename(guest), what,
                            'FIRED' if hit else 'DID NOT FIRE'))

    # ---- wp-entry-state.  It is scored in process_guest rather than in
    # compare_excursion, so it needs its own mutation or its zero would be
    # the zero of a check nobody made fire.
    guest, ex, ref, _dirty = pairs[0]
    truth = dict((n, v) for n, (v, _w) in ex.regs.items()
                 if wp_seed.reg_to_riscv(n))
    m = copy.deepcopy(ex)
    vic = sorted(truth)[0]
    m.regs[vic] = (truth[vic] ^ 0x1234, 8)
    gaps = set()
    erows, _es = C.entry_state_rows(guest, m, truth, gaps)
    es_ok = any(r.axis == 'wp-entry-state' and r.verdict == C.RECON_GAP
                for r in erows)
    lines.append('  %-14s %-14s %-40s %s'
                 % ('wp-entry-state', os.path.basename(guest),
                    'corrupt the reconstructed %s' % vic,
                    'FIRED' if es_ok else 'DID NOT FIRE'))
    attempted.add('wp-entry-state')
    fired['wp-entry-state'] += bool(es_ok)

    # ---- the injection control: change what is INSTALLED, not what is scored.
    image, xranges, _e = elfimage.load(guest)
    sel = C.guest_ranges(xranges)
    inj = copy.deepcopy(ex)
    victim = None
    for ins in ex.insns:
        for sname in ins.srcs:
            if sname in inj.regs and wp_seed.reg_to_riscv(sname) and \
                    sname != 'REG_ZERO':
                victim = sname
                break
        if victim:
            break
    inj_line = '  injection      -- no source register to perturb   UNPROVEN'
    inj_ok = False
    if victim:
        v, w = inj.regs[victim]
        inj.regs[victim] = (v ^ 0xdeadbeef, w)
        elf2, mem2, _g, _u = wp_seed.build(args.outdir, 'stinj', inj)
        log2 = C.run_spike_injected(args.spike, elf2, mem2,
                                    os.path.join(args.outdir, 'stinj'),
                                    args.dtc_dir, args.isa,
                                    args.prologue_cap + len(ex.insns) + 8)
        ref2 = [i for i in spike_ref.parse_commit_log(log2) if sel(i.pc)]
        moved = ([(i.pc, tuple(i.writes)) for i in ref2[:len(ex.insns)]] !=
                 [(i.pc, tuple(i.writes)) for i in ref[:len(ex.insns)]])
        inj_ok = moved
        inj_line = ('  injection      %-14s perturb %-24s %s'
                    % (os.path.basename(guest), victim,
                       'FIRED' if moved else 'DID NOT FIRE'))

    # ---- the DECLARED-VS-COMPARED identity.  render() asserts that every
    # declared wrong-path instruction is either compared or sits in a named
    # tail; an assertion that cannot report a violation is not an assertion,
    # so one is staged here.  The control drops a single instruction from
    # one tail and requires the report to say so.
    id_stats = collections.Counter({'wp-insns-declared': 100,
                                    'wp-insns-compared': 90})
    _t, id_true = C.render([], id_stats, collections.Counter(
        {'reference-stopped-short': 10}), args.guest)
    _t, id_false = C.render([], id_stats, collections.Counter(
        {'reference-stopped-short': 9}), args.guest)
    id_ok = id_true and not id_false
    id_line = ('  identity       --             '
               'lose one instruction from a named tail   %s'
               % ('FIRED' if id_ok else 'DID NOT FIRE'))

    out = ['NEGATIVE CONTROL -- riscv64 wrong-path execution leg',
           '',
           'A green cross-check is a result only if every axis it scores CAN',
           'go red.  Each axis below is broken on one side of one real',
           'aligned pair, and the axis that owns that fact must fire.',
           '',
           'clean pairs available for mutation: %d over %d guests'
           % (len(pairs), len(args.guest)),
           '']
    out += lines
    out.append(inj_line)
    out.append(id_line)
    out.append('')
    unproven = sorted(a for a in attempted if not fired[a])
    nomut = [a for a in C.AXES + ('wp-entry-state',)
             if a not in attempted]
    out.append('AXES WITH A FIRING MUTATION: %d of %d attempted'
               % (sum(1 for a in fired if fired[a]), len(attempted)))
    if unproven:
        out.append('UNPROVEN (mutation written, axis did not fire): %s'
                   % ', '.join(unproven))
    if nomut:
        out.append('NO MUTATION AVAILABLE (no excursion in this set carries '
                   'an instance of the fact): %s' % ', '.join(nomut))
    out.append('INJECTION CONTROL: %s'
               % ('FIRED -- the installed state determines what the simulator '
                  'executes' if inj_ok else 'UNPROVEN'))
    out.append('IDENTITY CONTROL: %s'
               % ('FIRED -- an unaccounted declared instruction is reported'
                  if id_ok else 'UNPROVEN -- the identity cannot report a '
                                'violation and its HOLDS means nothing'))
    txt = '\n'.join(out) + '\n'
    sys.stdout.write(txt)
    open(os.path.join(args.outdir, 'SELFTEST.txt'), 'w').write(txt)
    return 0 if (not unproven and inj_ok and id_ok and not nomut) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('guest', nargs='+')
    ap.add_argument('--spike', required=True)
    ap.add_argument('--qemu', required=True)
    ap.add_argument('--plugin', required=True)
    ap.add_argument('--decode', required=True)
    ap.add_argument('--dtc-dir')
    ap.add_argument('--isa', default='rv64gcv')
    ap.add_argument('--wpdepth', type=int, default=16)
    ap.add_argument('--prologue-cap', type=int, default=900)
    ap.add_argument('-o', '--outdir', required=True)
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    return run(a)


if __name__ == '__main__':
    sys.exit(main())
