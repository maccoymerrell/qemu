"""
The NEGATIVE CONTROL for the gem5 CORRECT-PATH execution leg.

A green cell nobody could falsify is not a validated cell.  ``compare_exec_gem5``
reports a row per DISAGREEMENT, so an axis that is broken -- one that reads the
wrong field, compares the wrong pair, or silently skips -- reports the same
clean zero as an axis that compared everything and found it right.  This tool
breaks the TRACER's record, one axis at a time, in the way a real defect would,
and requires the axis it targets to CONVICT.

    reg-dst-set     drop a destination register / add one that is not written
    reg-dst-value   corrupt a destination value
    flags-dst-set   drop the flags destination
    fpsr-dst-set    drop the FP status destination
    memop-count     drop an access
    memop-addr      move an access to another page
    memop-width     halve an access
    store-data      corrupt a stored byte
    load-data       corrupt a loaded byte

EVERY MUTATION IS APPLIED TO A SUBJECT THE AXIS ACTUALLY HAS.  A mutation that
changes nothing cannot fire, and a control that cannot fire vouches for
nothing: the x86_64 wrong-path control printed DID NOT FIRE sixteen times
because it halved the width of a one-byte access.  So each mutator is handed
the axis's own subject census -- the instructions where that axis compared a
fact -- and reports, per axis, whether the axis moved and by how much.

WHAT "FIRED" MEANS, exactly: the axis's disagreement count STRICTLY INCREASES
against the same run's unmutated baseline.  Not "the report changed"; not "some
axis moved".

Author: Maccoy Merrell.
"""
import argparse
import collections
import copy
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (HERE, os.path.join(HERE, '..'),
           os.path.join(HERE, '..', 'riscv64', 'spike')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import gem5_ref                                                 # noqa: E402
import gem5_env                                                 # noqa: E402
import tracer_log                                               # noqa: E402
import compare_exec_gem5 as C                                   # noqa: E402
from axis_subjects import Subjects                              # noqa: E402


def _has_arch_dst(t):
    a, _f, _p = C.split_regs(t.writes)
    return bool(a)


def _has_flag(t):
    _a, f, _p = C.split_regs(t.writes)
    return bool(f)


def _has_fpsr(t):
    _a, _f, p = C.split_regs(t.writes)
    return bool(p)


def _has_valued_dst(t):
    a, _f, _p = C.split_regs(t.writes)
    return any(w for _v, w in a.values())


def _has_access(t):
    return bool(t.loads or t.stores)


def _has_sized(t):
    return any(sz > 1 for _a, _d, sz in t.loads + t.stores)


def _has_store_data(t):
    return any(d is not None and 0 < sz <= 8 for _a, d, sz in t.stores)


def _has_load_data(t):
    return any(d is not None and 0 < sz <= 8 for _a, d, sz in t.loads)


def _drop_arch_dst(t):
    a, _f, _p = C.split_regs(t.writes)
    victim = sorted(a)[0]
    t.writes = [w for w in t.writes if w[0] != victim]


def _corrupt_value(t):
    for i, (n, v, w) in enumerate(t.writes):
        if w and n not in C.FLAG_IDS and n not in C.FPSR_IDS:
            t.writes[i] = (n, v ^ 0x5a5a, w)
            return


def _drop_flags(t):
    t.writes = [w for w in t.writes if w[0] not in C.FLAG_IDS]


def _drop_fpsr(t):
    t.writes = [w for w in t.writes if w[0] not in C.FPSR_IDS]


# INVENTING a destination is the OTHER defect a set axis has to convict, and
# on some ISAs it is the only one that can.  Measured on mipsel: the tracer
# publishes an FP status destination the reference does not, so DROPPING it
# makes the two sets AGREE -- the mutation repaired a known granularity
# difference instead of injecting a defect, and the axis reported DID NOT
# FIRE while working perfectly.  A control that can only delete is half a
# control.
def _invent(partition_name):
    def go(t):
        t.writes = list(t.writes) + [(partition_name, 0x5a5a, 8)]
    return go


def _drop_access(t):
    if t.loads:
        t.loads = t.loads[1:]
    else:
        t.stores = t.stores[1:]


def _move_access(t):
    for which in ('loads', 'stores'):
        lst = getattr(t, which)
        if lst:
            a, d, s = lst[0]
            setattr(t, which, [(a + 0x1000, d, s)] + lst[1:])
            return


def _halve_width(t):
    for which in ('loads', 'stores'):
        lst = getattr(t, which)
        for i, (a, d, s) in enumerate(lst):
            if s > 1:
                lst[i] = (a, d, s // 2)
                return


def _corrupt_store(t):
    for i, (a, d, s) in enumerate(t.stores):
        if d is not None and 0 < s <= 8:
            t.stores[i] = (a, d ^ 0xff, s)
            return


def _corrupt_load(t):
    for i, (a, d, s) in enumerate(t.loads):
        if d is not None and 0 < s <= 8:
            t.loads[i] = (a, d ^ 0xff, s)
            return


#: axis -> (does this instruction carry a subject for it, how to break it)
#: axis -> [(name, does this instruction carry a subject, how to break it)].
#: An axis FIRES when AT LEAST ONE of its mutations convicts, and the report
#: prints the verdict of each.
MUTATORS = collections.OrderedDict((
    ('reg-dst-set', [('drop-dst', _has_arch_dst, _drop_arch_dst),
                     ('invent-dst', _has_arch_dst, _invent('REG_GPR30'))]),
    ('reg-dst-value', [('corrupt', _has_valued_dst, _corrupt_value)]),
    ('flags-dst-set', [('drop-flags', _has_flag, _drop_flags),
                       ('invent-flags', _has_arch_dst,
                        _invent(C.FLAG_IDS[0]))]),
    ('fpsr-dst-set', [('drop-fpsr', _has_fpsr, _drop_fpsr),
                      ('invent-fpsr', _has_arch_dst,
                       _invent(C.FPSR_IDS[0]))]),
    ('memop-count', [('drop-access', _has_access, _drop_access)]),
    ('memop-addr', [('move-page', _has_access, _move_access)]),
    ('memop-width', [('halve', _has_sized, _halve_width)]),
    ('store-data', [('corrupt', _has_store_data, _corrupt_store)]),
    ('load-data', [('corrupt', _has_load_data, _corrupt_load)]),
))


def score(pairs, isa):
    """Disagreements per axis over an aligned stream."""
    n = collections.Counter()
    sub = Subjects()
    for r, t in pairs:
        for d in C.compare_insn(r, t, isa, sub):
            n[d.axis] += 1
    return n, sub


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('guest', nargs='+')
    ap.add_argument('--isa', required=True,
                    choices=tuple(sorted(C.GEM5_BUILD)))
    ap.add_argument('--gem5-dir', required=True)
    ap.add_argument('--qemu-dir', required=True)
    ap.add_argument('--decode', required=True)
    ap.add_argument('-o', '--outdir', required=True)
    ap.add_argument('--python-home')
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    try:
        binary, cfg, env, notes = C.gem5_prereqs(
            args.gem5_dir, args.isa, args.outdir,
            python_home=args.python_home)
    except gem5_env.MissingPrerequisite as exc:
        sys.stderr.write('%s\nREFUSING: the reference did not run.\n' % exc)
        return 3

    streams = []
    for guest in args.guest:
        log = C.run_gem5(binary, cfg, env, args.isa, guest, args.outdir)
        trace = C.run_tracer(args.qemu_dir, args.isa, guest, args.outdir)
        ref = gem5_ref.parse(log, guest, args.isa, gem5_dir=args.gem5_dir,
                             dropped={}, notes=collections.Counter())
        trc, _ = tracer_log.parse(args.decode, trace)
        pairs, _ro, _to = C.align(ref, trc, args.isa)
        streams.append((os.path.basename(guest), pairs))

    base = collections.Counter()
    basesub = Subjects()
    for _g, pairs in streams:
        n, s = score(pairs, args.isa)
        base.update(n)
        basesub.merge(s)

    out = []
    w = out.append
    w('ARC 3 -- %s CORRECT-PATH leg: THE NEGATIVE CONTROL' % args.isa)
    w('=' * 72)
    w('')
    w('Each axis is broken in the TRACER record, one at a time, on an')
    w('instruction that carries a SUBJECT for that axis, and the axis must')
    w('CONVICT.  FIRED means the axis\'s disagreement count strictly')
    w('increased against the unmutated baseline of the same run.')
    w('')
    w('%-16s %-14s %8s %10s %10s %10s   %s'
      % ('axis', 'mutation', 'subjects', 'baseline', 'mutated', 'mutations',
         'verdict'))
    fired = {}
    axes = C.axes_for(args.isa)
    for axis in axes:
        for mname, has, mutate in MUTATORS[axis]:
            got = collections.Counter()
            nmut = 0
            for _g, pairs in streams:
                mp = []
                for r, t in pairs:
                    if has(t):
                        t2 = copy.deepcopy(t)
                        mutate(t2)
                        nmut += 1
                        mp.append((r, t2))
                    else:
                        mp.append((r, t))
                n, _s = score(mp, args.isa)
                got.update(n)
            ok = got[axis] > base[axis]
            fired[axis] = fired.get(axis, False) or ok
            w('%-16s %-14s %8d %10d %10d %10d   %s'
              % (axis, mname, len(basesub.enc[axis]), base[axis], got[axis],
                 nmut, 'FIRED' if ok else
                 ('DID NOT FIRE -- NO SUBJECT' if not nmut
                  else 'DID NOT FIRE')))
    w('')
    for (i_, a_), why in sorted(C.NO_SUCH_AXIS.items()):
        if i_ == args.isa:
            w('AXIS NOT PRESENT ON THIS ISA: %s -- %s' % (a_, why))
    nf = [a for a, ok in fired.items() if not ok]
    if nf:
        w('AXES THAT DID NOT FIRE: %s' % ', '.join(nf))
        w('An axis that cannot be made to convict is not validated by its own')
        w('clean result.  Where the reason is NO SUBJECT the remedy is a')
        w('better probe; where a subject existed, the axis is broken.')
    else:
        w('ALL %d AXES FIRED.' % len(axes))
    txt = '\n'.join(out) + '\n'
    with open(os.path.join(args.outdir, 'SELFTEST.txt'), 'w') as fh:
        fh.write(txt)
    sys.stdout.write(txt)
    sys.stderr.write('fired=%d/%d\n' % (len(axes) - len(nf), len(axes)))
    return 1 if nf else 0


if __name__ == '__main__':
    sys.exit(main())
