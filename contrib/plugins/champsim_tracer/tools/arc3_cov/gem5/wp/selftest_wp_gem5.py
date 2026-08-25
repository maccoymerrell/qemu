"""
The negative control for the x86_64 wrong-path execution leg.

A green cross-check is a result only if every axis it scores CAN go red.  This
project's dominant failure mode is a check that reports success without
verifying, so each axis here is deliberately broken on one side of one real
aligned pair and the axis that owns that fact is required to fire.  An axis
with no firing mutation reports UNPROVEN and its zero is not counted as a pass.

TWO KINDS OF CONTROL, AND BOTH ARE NEEDED
=========================================
1. COMPARATOR controls.  Perturb the tracer's record of one instruction and
   require the owning axis to report it.  These prove the comparison reads the
   fields it claims to read.

2. THE INJECTION control.  Perturb the STATE THAT IS INSTALLED into gem5 and
   require gem5's own execution to change.  This is the load-bearing one:
   without it, an agreement could mean the reconstruction is correct, or it
   could mean the reconstruction never reached the simulator and the excursion
   went the same way regardless.  The two are indistinguishable from the
   comparison alone.

Author: Maccoy Merrell.
"""
import argparse
import collections
import copy
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_COV = os.path.abspath(os.path.join(_HERE, '..', '..'))
for _p in (_HERE, _COV, os.path.join(_COV, 'gem5'),
           os.path.join(_COV, 'riscv64', 'spike', 'wp')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import elfimage                                              # noqa: E402
import wp_trace                                              # noqa: E402
import wp_seed_x86                                           # noqa: E402
import gem5_wp_ref                                           # noqa: E402
import compare_wp_gem5 as C                                  # noqa: E402


def _non_x87(ins):
    """True when this instruction's data does not pass through the x87 file.

    An x87 value is a DOUBLE on the reference side, so the comparator routes
    it to a named GEM5-LIMIT rather than to a defect -- correct for the
    measurement and useless for a control, because the mutated axis would
    report a limit instead of firing.  A control that cannot fire is exactly
    what this file exists to prevent, so the mutation subject is chosen to
    avoid it rather than the result being explained away afterwards.
    """
    return not any(n.startswith('REG_FPR') for n in ins.srcs) and \
        not any(n.startswith('REG_FPR') or n == 'REG_FCSR'
                for n, _v, _w in ins.writes)


def mutations(ex):
    """[(axis, description, mutated excursion)] -- one per axis, on real data."""
    out = []

    def clone():
        return copy.deepcopy(ex)

    m = clone()
    m.insns[0].pc ^= 0x10
    out.append(('pc-sequence', 'move the first WP PC by 0x10', m, 0))

    m = clone()
    m.insns[0].nbytes += 1
    out.append(('insn-length', 'lengthen the first encoding by one byte',
                m, 0))

    for i, ins in enumerate(ex.insns):
        if ins.writes and _non_x87(ins):
            m = clone()
            m.insns[i].writes = []
            out.append(('reg-dst-set', 'drop the destination of insn %d' % i,
                        m, i))
            m = clone()
            n, v, w = m.insns[i].writes[0]
            m.insns[i].writes[0] = (n, v ^ 0x5a5a, w)
            out.append(('reg-dst-value', 'corrupt the value of insn %d' % i,
                        m, i))
            break

    for i, ins in enumerate(ex.insns):
        if len(ins.srcs) > 1:
            m = clone()
            m.insns[i].srcs = ins.srcs[1:]
            out.append(('reg-src-set', 'drop a source of insn %d' % i, m, i))
            break

    # Loads and stores are walked SEPARATELY.  Taking "the first instruction
    # with a memop" leaves store-data with no mutation whenever that
    # instruction happens to be a load, which is how an axis ends up
    # unprovable without anyone noticing.
    #
    # WHY THIS WALKS EVERY INSTRUCTION AND NOT JUST THE FIRST ONE WITH A
    # MEMOP.  It used to stop at the first, and on `p_wpmem` that is a
    # ONE-BYTE `movzx` load: halving its width is `max(1, 1 // 2) == 1`, a
    # mutation that changes NOTHING, so the axis could not possibly fire and
    # the control printed DID NOT FIRE five times over -- once per pair --
    # for a reason that was the harness's, not the tracer's.  A reader cannot
    # tell that apart from a blind axis, which is the whole thing this
    # control exists to rule out.
    #
    # Two rules follow, and they are the fix:
    #   * a mutation that leaves the record IDENTICAL is never emitted.  A
    #     no-op falsifier is not a falsifier.
    #   * the walk continues to the next instruction instead of breaking, so
    #     an axis with no subject on insn N can still find one on insn N+1 of
    #     the SAME guest.
    for which, axis in (('loads', 'load-data'), ('stores', 'store-data')):
        want = set(('memop-count', 'memop-addr', 'memop-width', axis))
        # The DATA axes get up to three candidate subjects rather than one.
        # A datum mutation can only be scored where the REFERENCE also states
        # a datum for that access, and gem5 does not state one for every
        # access it retires -- so a single candidate makes the control's
        # verdict depend on which access happened to come first.  Three
        # candidates in the same guest is the difference between "the axis is
        # blind" and "this particular access has no reference datum".
        data_left = 3
        for i, ins in enumerate(ex.insns):
            if not want and not data_left:
                break
            recs = getattr(ins, which)
            if not recs or not _non_x87(ins):
                continue
            a, d, sz = recs[0]
            if 'memop-count' in want:
                m = clone()
                getattr(m.insns[i], which).pop()
                out.append(('memop-count',
                            'drop the %s of insn %d' % (which[:-1], i), m, i))
                want.discard('memop-count')
            if 'memop-addr' in want:
                m = clone()
                getattr(m.insns[i], which)[0] = (a + 8, d, sz)
                out.append(('memop-addr', 'move the %s address of insn %d'
                            % (which[:-1], i), m, i))
                want.discard('memop-addr')
            if 'memop-width' in want and sz and max(1, sz // 2) != sz:
                m = clone()
                getattr(m.insns[i], which)[0] = (a, d, max(1, sz // 2))
                out.append(('memop-width',
                            'halve the %s width of insn %d (%d -> %d bytes)'
                            % (which[:-1], i, sz, max(1, sz // 2)), m, i))
                want.discard('memop-width')
            if data_left and d is not None and (d ^ 0xff) != d:
                m = clone()
                getattr(m.insns[i], which)[0] = (a, d ^ 0xff, sz)
                out.append((axis, 'corrupt the %s datum of insn %d'
                            % (which[:-1], i), m, i))
                data_left -= 1
                if not data_left:
                    want.discard(axis)
    return out


def _pairs(args, envx, guest, limit):
    """[(excursion, reference, axes already disagreeing)] for real excursions.

    A mutation proves nothing against a pair that already disagrees on the
    axis being mutated: it would have fired anyway.  Cleanliness is judged
    PER AXIS rather than globally -- an excursion whose `dec` already reports
    a reg-src-set row is still a sound subject for a memop-addr mutation, and
    refusing it outright is how the memory axes end up with no mutation.
    """
    image, xranges, _e = elfimage.load(guest)
    stem = os.path.join(args.outdir, os.path.basename(guest))
    trace = C.run_tracer(args.qemu, args.plugin, guest, stem, args.wpdepth)
    exc, _cp, _st = wp_trace.build(args.decode, trace, image)
    if not exc:
        return []
    sel = C.guest_ranges(xranges)
    out = []
    for k, (ex, _mult) in enumerate(wp_trace.dedupe(exc)):
        if len(out) >= limit:
            break
        tag = '%s.st%04d' % (os.path.basename(guest), k)
        seed = wp_seed_x86.build(args.outdir, tag, ex, args.cc)
        run = gem5_wp_ref.run(envx.gem5_bin, envx.gem5_dir, envx.env, seed.elf,
                              args.outdir, tag,
                              args.prologue_cap + 8 * len(ex.insns) + 32,
                              args.timeout)
        if run.log is None:
            continue
        ref = gem5_wp_ref.parse(run.log, sel)
        gem5_wp_ref.running_rflags(ref, seed.flags_word)
        if len(ref) < 4:
            continue
        gi = C.excursion_gaps(ex, [])
        base, _n, _t, _sub = C.compare_excursion(guest, ex, ref, gi,
                                                 run.tail)
        dirty = set(r.axis for r in base
                    if r.verdict in (C.WP_DEFECT, C.RECON_GAP, C.UNACCOUNTED))
        out.append((ex, ref, dirty, seed, run))
    return out



def why_not(sub, axis, insn):
    """Why a mutation did not fire, taken from the comparison it ran.

    A bare "DID NOT FIRE" cannot be told apart from a blind axis, and that is
    the one thing this control exists to rule out.  The per-axis SUBJECT
    census the comparator now returns answers it mechanically, and it answers
    it about THE INSTRUCTION THAT WAS MUTATED rather than about the axis in
    general: an axis can compare five facts on a pair and still have compared
    none of them on the access the mutation broke, because the reference
    states no datum for that access.  Those are different sentences and only
    one of them is a demand to interrogate the tracer.
    """
    enc = insn.bits.to_bytes(insn.nbytes, 'little').hex()
    if not sub.facts[axis]:
        return ('DID NOT FIRE -- the axis compared NOTHING on this pair; '
                'the reference states no such fact anywhere in it')
    if enc not in sub.enc[axis]:
        return ('DID NOT FIRE -- the axis compared %d facts on this pair and '
                'NONE of them on the mutated instruction; the reference '
                'states no such fact for that access' % sub.facts[axis])
    return ('DID NOT FIRE -- the axis compared %d facts, one of them on the '
            'mutated instruction, and none moved; INTERROGATE THIS'
            % sub.facts[axis])

def run(args, envx):
    pairs = []
    for g in args.guest:
        pairs.extend((g,) + p for p in _pairs(args, envx, g, 4))
    if not pairs:
        raise RuntimeError('no aligned excursion to mutate: the control '
                           'cannot prove anything without a real pair')

    fired = collections.Counter()
    attempted = set()
    lines = []
    for guest, ex, ref, dirty, _seed, run_ in pairs:
        for axis, what, m, idx in mutations(ex):
            if fired[axis] or axis in dirty:
                continue          # one firing mutation per axis is the bar
            attempted.add(axis)
            rows, _n, _t, msub = C.compare_excursion(
                guest, m, ref, C.excursion_gaps(m, []), run_.tail)
            hit = [r for r in rows if r.axis == axis and
                   r.verdict in (C.WP_DEFECT, C.RECON_GAP, C.UNACCOUNTED)]
            fired[axis] += bool(hit)
            lines.append('  %-14s %-12s %-44s %s'
                         % (axis, os.path.basename(guest), what,
                            'FIRED' if hit
                            else why_not(msub, axis, m.insns[idx])))

    # ---- wp-entry-state.  It is scored in process_guest rather than in
    # compare_excursion, so it needs its own mutation or its zero would be
    # the zero of a check nobody made fire.
    guest, ex, ref, _dirty, _seed, _run = pairs[0]
    truth = dict((n, v) for n, (v, _w) in ex.regs.items()
                 if wp_seed_x86.V.install_class(n) == 'gpr')
    m = copy.deepcopy(ex)
    victim = sorted(truth)[0]
    m.regs[victim] = (truth[victim] ^ 0x1234, 8)
    erows, _es, _sub = C.entry_state_rows(guest, m, truth, set())
    es_ok = any(r.axis == 'wp-entry-state' and r.verdict == C.RECON_GAP
                for r in erows)
    lines.append('  %-14s %-12s %-44s %s'
                 % ('wp-entry-state', os.path.basename(guest),
                    'corrupt the reconstructed %s' % victim,
                    'FIRED' if es_ok else 'DID NOT FIRE'))
    attempted.add('wp-entry-state')
    fired['wp-entry-state'] += bool(es_ok)

    # ---- the injection control: change what is INSTALLED, not what is scored.
    image, xranges, _e = elfimage.load(guest)
    sel = C.guest_ranges(xranges)
    inj = copy.deepcopy(ex)
    picked = None
    for ins in ex.insns:
        for sname in ins.srcs:
            if sname in inj.regs and \
                    wp_seed_x86.V.install_class(sname) == 'gpr':
                picked = sname
                break
        if picked:
            break
    inj_line = '  injection      -- no source register to perturb   UNPROVEN'
    inj_ok = False
    if picked:
        v, w = inj.regs[picked]
        inj.regs[picked] = (v ^ 0xdeadbeef, w)
        seed2 = wp_seed_x86.build(args.outdir, 'stinj', inj, args.cc)
        run2 = gem5_wp_ref.run(envx.gem5_bin, envx.gem5_dir, envx.env,
                               seed2.elf, args.outdir, 'stinj',
                               args.prologue_cap + 8 * len(ex.insns) + 32,
                               args.timeout)
        moved = True
        if run2.log is not None:
            ref2 = gem5_wp_ref.parse(run2.log, sel)
            a = [(i.pc, tuple(sorted(i.writes.items(), key=str)))
                 for i in ref2[:len(ex.insns)]]
            b = [(i.pc, tuple(sorted(i.writes.items(), key=str)))
                 for i in ref[:len(ex.insns)]]
            moved = (a != b)
        inj_ok = moved
        inj_line = ('  injection      %-12s perturb %-30s %s'
                    % (os.path.basename(guest), picked,
                       'FIRED' if moved else 'DID NOT FIRE'))

    out = ['NEGATIVE CONTROL -- x86_64 wrong-path execution leg, vs gem5',
           '',
           'A green cross-check is a result only if every axis it scores CAN',
           'go red.  Each axis below is broken on one side of one real',
           'aligned pair, and the axis that owns that fact must fire.',
           '',
           'aligned pairs available for mutation: %d over %d guests'
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
    ap.add_argument('--gem5-build', required=True)
    ap.add_argument('--qemu', required=True)
    ap.add_argument('--plugin', required=True)
    ap.add_argument('--decode', required=True)
    ap.add_argument('--cc', default='gcc')
    ap.add_argument('--wpdepth', type=int, default=32)
    ap.add_argument('--prologue-cap', type=int, default=400)
    ap.add_argument('--timeout', type=int, default=900)
    ap.add_argument('-o', '--outdir', required=True)
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    envx = C.Env(a)
    return run(a, envx)


if __name__ == '__main__':
    sys.exit(main())
