"""
The negative control for the mipsel wrong-path execution leg.

A green cross-check is a result only if every axis it scores CAN go red.  This
project's dominant failure mode is a check that reports success without
verifying, so each axis here is deliberately broken on one side of one real
aligned pair and the axis that owns that fact is required to fire.  An axis
with no firing mutation reports UNPROVEN, and its zero is not counted as a
pass.

TWO KINDS OF CONTROL, AND BOTH ARE NEEDED
=========================================
1. COMPARATOR controls.  Perturb the tracer's record of one instruction and
   require the owning axis to report it.  These prove the comparison reads the
   fields it claims to read.

2. THE INJECTION control.  Perturb the state that is INSTALLED into gem5 and
   require gem5's OWN EXECUTION to change.  This is the load-bearing one:
   without it, an agreement could mean the reconstruction is correct, or it
   could mean the reconstruction never reached the simulator and the excursion
   went the same way regardless.  The two are indistinguishable from the
   comparison alone.

WHY THE PROBE SET GREW
======================
The control is also what proved the CORRECT-PATH probe set insufficient.
Measured at ``wpdepth=16``, only ``p_flow`` of the four correct-path mipsel
probes kicks an excursion at all, and its shadow is branches and one ``jal`` --
so the memop, FP and accumulator axes had NO MUTATION AVAILABLE, which is a
zero that proves nothing.  ``probes_wp_mipsel.py`` exists for exactly that
reason and is part of this control's subject set.

Author: Maccoy Merrell.
"""
import argparse
import collections
import copy
import os
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
import gem5_env                                              # noqa: E402
import compare_wp_mipsel as C                                # noqa: E402


def mutations(ex):
    """[(axis, description, mutated excursion)] -- one per axis, on real data.

    Every mutation is applied to a REAL excursion's real record; none of them
    invents an instruction.  A control built on synthetic data proves the
    comparator can read a synthetic record, which is not the question.
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

    for i, ins in enumerate(ex.insns):
        if ins.writes:
            m = clone()
            m.insns[i].writes = []
            out.append(('reg-dst-set', 'drop the destination of insn %d' % i,
                        m))
            break

    # A VALUED destination is needed for the value axes, and a destination
    # published with width 0 would make both of them unprovable -- which is
    # the very defect this leg found, so the two searches are separate.
    for i, ins in enumerate(ex.insns):
        valued = [k for k, (_n, _v, w) in enumerate(
            [(n, v, w) for n, v, w in ins.writes]) if w]
        if not valued:
            continue
        k = valued[0]
        m = clone()
        n_, v_, w_ = m.insns[i].writes[k]
        m.insns[i].writes[k] = (n_, v_ ^ 0x5a5a, w_)
        out.append(('reg-dst-value', 'corrupt the value of insn %d' % i, m))
        m = clone()
        n_, v_, w_ = m.insns[i].writes[k]
        m.insns[i].writes[k] = (n_, v_, 0)
        out.append(('reg-dst-valued',
                    'publish insn %d\'s destination with no value' % i, m))
        break

    for i, ins in enumerate(ex.insns):
        if ins.srcs:
            m = clone()
            m.insns[i].srcs = ins.srcs[1:]
            out.append(('reg-src-set', 'drop a source of insn %d' % i, m))
            break

    # Loads and stores are walked SEPARATELY.  Taking "the first instruction
    # with a memop" left store-data with no mutation whenever that instruction
    # happened to be a load, which is how an axis ends up unprovable without
    # anyone noticing.
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


def _subjects(args, binary, cfg, env, guest, limit):
    """[(guest, excursion, reference, axes already dirty)].

    A mutation proves nothing against a pair that already disagrees on the
    axis it targets: the axis would have fired anyway.  Cleanliness is judged
    PER AXIS rather than globally -- an excursion whose `jal` already reports
    a reg-dst-valued row is still a sound subject for a memop mutation.
    """
    image, _xr, _e, is64 = wp_image.load(guest)
    if is64:
        raise RuntimeError('%s is ELF64; the mipsel leg expects ELF32' % guest)
    stem = os.path.join(args.outdir, os.path.basename(guest))
    trace = C.run_tracer(args.qemu, args.plugin, guest, stem, args.wpdepth)
    exc, _cp, _st = wp_trace.build(args.decode, trace, image)
    out = []
    for k, ex in enumerate(exc):
        if len(out) >= limit:
            break
        tag = '%s.st%04d' % (os.path.basename(guest), k)
        touched = set()
        for ins in ex.insns:
            for addr, _d, size in ins.loads + ins.stores:
                touched.update(range(addr, addr + (size or 4)))
        try:
            elf, npro, _g, _u, boot = wp_seed.build(args.outdir, tag, ex,
                                                    extra_pages=touched,
                                                    cc=args.cc)
        except wp_seed.SameRegionRefused:
            continue
        run = C.run_gem5(binary, cfg, env, elf, args.outdir, tag,
                         npro + len(ex.insns) + args.cap_slack)
        ref = C.parse_injected(run, elf, boot)
        if len(ref) < 4:
            continue
        gi = C.excursion_gaps(ex, [])
        base, _n, _sub = C.compare_excursion(guest, ex, ref, gi,
                                       stopped=run.stopped)
        out.append((guest, ex, ref, set(r.axis for r in base),
                    elf, npro, boot))
    return out


def run(args, binary, cfg, env):
    subjects = []
    for g in args.guest:
        subjects.extend(_subjects(args, binary, cfg, env, g, 4))
    if not subjects:
        raise RuntimeError(
            'no aligned excursion to mutate: the control cannot prove '
            'anything without a real pair to break')

    fired = collections.Counter()
    attempted = set()
    lines = []
    for guest, ex, ref, dirty, _elf, _npro, _boot in subjects:
        for axis, what, m in mutations(ex):
            if fired[axis] or axis in dirty:
                continue          # one firing mutation per axis is the bar
            attempted.add(axis)
            rows, _n, _sub = C.compare_excursion(guest, m, ref,
                                           C.excursion_gaps(m, []))
            hit = [r for r in rows if r.axis == axis and
                   r.verdict in (C.WP_DEFECT, C.RECON_GAP, C.UNACCOUNTED)]
            fired[axis] += bool(hit)
            lines.append('  %-16s %-10s %-46s %s'
                         % (axis, os.path.basename(guest), what,
                            'FIRED' if hit else 'DID NOT FIRE'))

    # ---- wp-entry-state.  Scored in process_guest rather than in
    # compare_excursion, so it needs its own mutation or its zero would be the
    # zero of a check nobody made fire.
    guest, ex, ref, _dirty, _elf, _npro, _boot = subjects[0]
    truth = dict((n, v) for n, (v, _w) in ex.regs.items()
                 if wp_seed.reg_to_mips(n))
    m = copy.deepcopy(ex)
    victim = sorted(truth)[0]
    m.regs[victim] = (truth[victim] ^ 0x1234, 4)
    erows, _es, _sub = C.entry_state_rows(guest, m, truth, set())
    es_ok = any(r.axis == 'wp-entry-state' and r.verdict == C.RECON_GAP
                for r in erows)
    lines.append('  %-16s %-10s %-46s %s'
                 % ('wp-entry-state', os.path.basename(guest),
                    'corrupt the reconstructed %s' % victim,
                    'FIRED' if es_ok else 'DID NOT FIRE'))
    attempted.add('wp-entry-state')
    fired['wp-entry-state'] += bool(es_ok)

    # ---- THE INJECTION CONTROL: change what is INSTALLED, not what is scored.
    inj_ok = False
    inj_line = ('  injection        -- no source register to perturb'
                '                            UNPROVEN')
    for guest, ex, ref, _dirty, _elf, _npro, boot in subjects:
        victim = None
        for ins in ex.insns:
            for sname in ins.srcs:
                if sname in ex.regs and wp_seed.reg_to_mips(sname) and \
                        sname != 'REG_ZERO':
                    victim = sname
                    break
            if victim:
                break
        if not victim:
            continue
        inj = copy.deepcopy(ex)
        v, w = inj.regs[victim]
        inj.regs[victim] = (v ^ 0xdeadbee0, w)
        touched = set()
        for ins in inj.insns:
            for addr, _d, size in ins.loads + ins.stores:
                touched.update(range(addr, addr + (size or 4)))
        elf2, npro2, _g, _u, boot2 = wp_seed.build(
            args.outdir, 'stinj', inj, extra_pages=touched, cc=args.cc)
        run2 = C.run_gem5(binary, cfg, env, elf2, args.outdir, 'stinj',
                          npro2 + len(inj.insns) + args.cap_slack)
        ref2 = C.parse_injected(run2, elf2, boot2)
        moved = ([(i.pc, tuple(i.writes)) for i in ref2[:len(ex.insns)]] !=
                 [(i.pc, tuple(i.writes)) for i in ref[:len(ex.insns)]])
        inj_line = ('  injection        %-10s perturb %-38s %s'
                    % (os.path.basename(guest), victim,
                       'FIRED' if moved else 'DID NOT FIRE'))
        inj_ok = moved
        if moved:
            break

    out = ['NEGATIVE CONTROL -- mipsel wrong-path execution leg, vs gem5',
           '',
           'A green cross-check is a result only if every axis it scores CAN',
           'go red.  Each axis below is broken on one side of one real',
           'aligned pair, and the axis that owns that fact must fire.',
           '',
           'subjects available for mutation: %d over %d guests'
           % (len(subjects), len(args.guest)),
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
               % ('FIRED -- the installed state determines what gem5 executes'
                  if inj_ok else 'UNPROVEN'))
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
    ap.add_argument('--cc', default='mipsel-linux-gnu-gcc')
    ap.add_argument('--wpdepth', type=int, default=16)
    ap.add_argument('--cap-slack', type=int, default=4)
    ap.add_argument('--python-home')
    ap.add_argument('-o', '--outdir', required=True)
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    try:
        binary, cfg, env, _notes = C.gem5_prereqs(a.gem5_dir, a.outdir,
                                                  python_home=a.python_home)
    except gem5_env.MissingPrerequisite as exc:
        sys.stderr.write('%s\nREFUSING TO RUN THE CONTROL.\n' % exc)
        return 3
    return run(a, binary, cfg, env)


if __name__ == '__main__':
    sys.exit(main())
