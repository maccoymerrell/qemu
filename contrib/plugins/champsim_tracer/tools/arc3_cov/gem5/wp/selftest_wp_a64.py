"""
The negative control for the aarch64 wrong-path execution leg.

A green cross-check is a result only if every axis it scores CAN go red.  This
project's dominant failure mode is a check that reports success without
verifying, so each axis here is deliberately broken on ONE SIDE of ONE REAL
aligned pair and the axis that owns that fact is required to fire.  An axis
with no firing mutation reports UNPROVEN and its zero is NOT counted as a pass;
an axis with no instance of its fact anywhere in the probe set reports NO
MUTATION AVAILABLE, which is a demand for a better probe rather than a result.

TWO KINDS OF CONTROL, AND BOTH ARE NEEDED
=========================================
1. COMPARATOR controls.  Perturb the tracer's record of one instruction and
   require the owning axis to report it.  These prove the comparison reads the
   fields it claims to read.

2. THE INJECTION control.  Perturb the STATE THAT IS INSTALLED into gem5 and
   require gem5's own execution to change.  This is the load-bearing one:
   without it, an agreement could mean the reconstruction is correct, or it
   could mean the reconstruction never reached the simulator and the excursion
   followed the same path regardless.  The two are indistinguishable from the
   comparison alone.

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
sys.path.insert(0, os.path.join(_HERE, '..', '..'))
sys.path.insert(0, os.path.join(_HERE, '..', '..', 'riscv64', 'spike', 'wp'))

import elfimage                                              # noqa: E402
import wp_trace                                              # noqa: E402
import wp_seed_a64                                           # noqa: E402
import compare_wp_a64 as C                                   # noqa: E402

RED = (C.WP_DEFECT, C.RECON_GAP, C.UNACCOUNTED)


def mutations(ex):
    """[(axis, description, mutated excursion)] -- one per axis, on real data.

    Every mutation is applied to the TRACER's side of a pair whose baseline
    comparison is clean on that axis, so a firing row can only come from the
    mutation.
    """
    out = []

    def clone():
        return copy.deepcopy(ex)

    m = clone()
    m.insns[0].pc ^= 0x10
    out.append(('pc-sequence', 'move the first WP PC by 0x10', m))

    m = clone()
    m.insns[0].bits ^= 0xff
    out.append(('insn-bits', 'flip the low byte of the first encoding', m))

    # The three write partitions are walked SEPARATELY.  Taking "the first
    # instruction with a write" left the flag and FP-status axes with no
    # mutation whenever that instruction happened to write only a GPR, which
    # is exactly how an axis ends up unprovable without anyone noticing.
    for axis, pred in (
            ('reg-dst-set', lambda n: not (n in C.FLAG_IDS or C._is_sys(n))),
            ('flags-dst-set', lambda n: n in C.FLAG_IDS),
            ('fpsr-dst-set', C._is_sys)):
        for i, ins in enumerate(ex.insns):
            hit = [k for k, (n, _v, _w) in enumerate(ins.writes) if pred(n)]
            if not hit:
                continue
            m = clone()
            del m.insns[i].writes[hit[0]]
            out.append((axis, 'drop the %s destination of insn %d'
                        % (axis.split('-')[0], i), m))
            if axis == 'reg-dst-set':
                m = clone()
                n, v, w = m.insns[i].writes[hit[0]]
                m.insns[i].writes[hit[0]] = (n, v ^ 0x5a5a, w)
                out.append(('reg-dst-value',
                            'corrupt the value of insn %d' % i, m))
            break

    for axis, pred in (
            ('reg-src-set', lambda n: not (n in C.FLAG_IDS or C._is_sys(n))),
            ('flags-src-set', lambda n: n in C.FLAG_IDS),
            ('sys-src-set', C._is_sys)):
        for i, ins in enumerate(ex.insns):
            hit = [k for k, n in enumerate(ins.srcs) if pred(n)]
            if not hit:
                continue
            m = clone()
            del m.insns[i].srcs[hit[0]]
            out.append((axis, 'drop a %s source of insn %d'
                        % (axis.split('-')[0], i), m))
            break

    # Loads and stores are walked separately for the same reason.
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
            getattr(m.insns[i], which)[0] = (a + 64, d, sz)
            out.append(('memop-addr',
                        'move the %s address of insn %d' % (which[:-1], i), m))
            if sz and sz > 1:
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


def _pairs(args, binary, cfg, env, guest, limit):
    """[(guest, excursion, reference rows, axes already dirty)].

    A mutation proves nothing against a pair that already disagrees on the
    axis it targets: that axis would have fired anyway.  Cleanliness is judged
    PER AXIS rather than globally -- an excursion whose store-exclusive
    already reports a named row on memop-count is still a sound subject for a
    reg-dst-value mutation, and refusing it outright is how the memop axes
    ended up with no mutation at all on the riscv64 leg.
    """
    image, _xr, _e = elfimage.load(guest)
    stem = os.path.join(args.outdir, os.path.basename(guest))
    trace = C.run_tracer(args.qemu, args.plugin, guest, stem, args.wpdepth)
    exc, _cp, _st = wp_trace.build(args.decode, trace, image)
    out = []
    for k, ex in enumerate(exc):
        if len(out) >= limit:
            break
        tag = '%s.st%04d' % (os.path.basename(guest), k)
        elf, _g, _u, plen = wp_seed_a64.build(args.outdir, tag, ex)
        log, reason, _pan = C.run_gem5(binary, cfg, env, elf, args.outdir, tag,
                                       plen // 4 + len(ex.insns) + 16)
        refrows = C.parse_ref(log, elf, args.gem5_dir, C.not_prologue(plen))
        if len(refrows) < 8:
            continue
        gi = C.excursion_gaps(ex, [])
        base, _tail, _cmp = C.compare_excursion(guest, ex, refrows, gi, reason)
        out.append((guest, ex, refrows, reason,
                    set(r.axis for r in base if r.verdict in RED)))
    return out


def run(args, binary, cfg, env):
    pairs = []
    for g in args.guest:
        pairs.extend(_pairs(args, binary, cfg, env, g, 4))
    if not pairs:
        raise RuntimeError('no aligned excursion to mutate: the control '
                           'cannot prove anything without a subject')

    fired = collections.Counter()
    attempted = set()
    seen = set()
    lines = []
    for guest, ex, refrows, reason, dirty in pairs:
        for axis, what, m in mutations(ex):
            if fired[axis] or axis in dirty:
                continue          # one firing mutation per axis is the bar
            attempted.add(axis)
            rows, _t, _c = C.compare_excursion(guest, m, refrows,
                                               C.excursion_gaps(m, []), reason)
            hit = [r for r in rows if r.axis == axis and r.verdict in RED]
            fired[axis] += bool(hit)
            key = (axis, os.path.basename(guest), what)
            if key in seen:
                continue        # the same mutation on the same subject twice
            seen.add(key)
            lines.append('  %-15s %-11s %-42s %s'
                         % (axis, os.path.basename(guest), what,
                            'FIRED' if hit else 'DID NOT FIRE'))

    # ---- wp-entry-state.  It is scored in process_guest rather than in
    # compare_excursion, so it needs its own mutation or its zero would be
    # the zero of a check nobody made fire.
    guest, ex, refrows, _reason, _dirty = pairs[0]
    truth = dict((n, v) for n, (v, _w) in ex.regs.items()
                 if wp_seed_a64.reg_to_a64(n) and n not in C.FLAG_IDS
                 and n not in C.FPSR_IDS)
    m = copy.deepcopy(ex)
    vic = sorted(truth)[0]
    m.regs[vic] = (truth[vic] ^ 0x1234, 8)
    erows, _es = C.entry_state_rows(guest, m, truth, set())
    es_ok = any(r.axis == 'wp-entry-state' and r.verdict == C.RECON_GAP
                for r in erows)
    lines.append('  %-15s %-11s %-42s %s'
                 % ('wp-entry-state', os.path.basename(guest),
                    'corrupt the reconstructed %s' % vic,
                    'FIRED' if es_ok else 'DID NOT FIRE'))
    attempted.add('wp-entry-state')
    fired['wp-entry-state'] += bool(es_ok)

    # ---- the injection control: change what is INSTALLED, not what is scored.
    inj = copy.deepcopy(ex)
    victim = None
    for ins in ex.insns:
        for sname in ins.srcs:
            if (sname in inj.regs and wp_seed_a64.reg_to_a64(sname) and
                    sname not in ('REG_ZERO', 'REG_SP') and
                    sname not in C.FLAG_IDS and sname not in C.FPSR_IDS):
                victim = sname
                break
        if victim:
            break
    inj_line = ('  injection       %-11s no source register to perturb'
                '                UNPROVEN' % '')
    inj_ok = False
    if victim:
        v, w = inj.regs[victim]
        inj.regs[victim] = (v ^ 0xdeadbeef, w)
        elf2, _g, _u, plen2 = wp_seed_a64.build(args.outdir, 'stinj', inj)
        log2, _r2, _p2 = C.run_gem5(binary, cfg, env, elf2, args.outdir,
                                    'stinj',
                                    plen2 // 4 + len(ex.insns) + 16)
        ref2 = C.parse_ref(log2, elf2, args.gem5_dir, C.not_prologue(plen2))
        n = len(ex.insns)

        def sig(rows):
            return [(i.pc, tuple(sorted(i.writes)), tuple(sorted(i.loads)),
                     tuple(sorted(i.stores))) for i, _a, _c, _s in rows[:n]]
        moved = sig(ref2) != sig(refrows)
        inj_ok = moved
        inj_line = ('  injection       %-11s perturb %-34s %s'
                    % (os.path.basename(guest), victim,
                       'FIRED' if moved else 'DID NOT FIRE'))

    out = ['NEGATIVE CONTROL -- aarch64 wrong-path execution leg (gem5)',
           '',
           'A green cross-check is a result only if every axis it scores CAN',
           'go red.  Each axis below is broken on one side of one real',
           'aligned pair, and the axis that owns that fact must fire.',
           '',
           'pairs available for mutation: %d over %d guests'
           % (len(pairs), len(args.guest)),
           '']
    out += lines
    out.append(inj_line)
    out.append('')
    unproven = sorted(a for a in attempted if not fired[a])
    nomut = [a for a in C.AXES + ('wp-entry-state',) if a not in attempted]
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
    txt = '\n'.join(out) + '\n'
    sys.stdout.write(txt)
    open(os.path.join(args.outdir, 'SELFTEST.txt'), 'w').write(txt)
    return 0 if (not unproven and inj_ok and not nomut) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('guest', nargs='+')
    ap.add_argument('--gem5-dir', required=True)
    ap.add_argument('--qemu', required=True)
    ap.add_argument('--plugin', required=True)
    ap.add_argument('--decode', required=True)
    ap.add_argument('--python-home')
    ap.add_argument('--wpdepth', type=int, default=32)
    ap.add_argument('-o', '--outdir', required=True)
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    binary, cfg, env, _notes = C.prereqs(a.gem5_dir, a.outdir,
                                         python_home=a.python_home)
    return run(a, binary, cfg, env)


if __name__ == '__main__':
    sys.exit(main())
