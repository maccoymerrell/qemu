"""
The NEGATIVE CONTROL for the dependency leg.  Run it BEFORE believing a
clean run.

WHY
===
Every axis in ``compare_dep.py`` reports disagreements, so an axis that is
broken -- one whose comparison can never fail -- reports the same clean row as
an axis that checked ten thousand facts and found them right.  This project
has been caught by that shape repeatedly: a wrong-path guard that looked for
``' WP '`` when the renderer writes ``wp[0]``, a start proof built on
``--help`` that returned 0 under the very loader path it was meant to detect.
Both were INERT and both were silent.

WHAT IT DOES
============
For each axis it BREAKS THE TRACER RECORD, on an instruction that actually
carries a subject for that axis, and requires the axis's disagreement count to
STRICTLY INCREASE against the same run's unmutated baseline.  The set axes get
TWO mutations, DROP and INVENT, because on some ISAs only one of them can fire
-- where the tracer already publishes state the reference does not model,
DROPPING it moves the two sets TOWARDS each other and the mutation repairs a
known reference gap instead of injecting a defect.

A mutation that does not fire is a FAILED CONTROL and this exits non-zero.  An
axis that CANNOT be made to fire on an ISA is reported with the reason, and
the reason has to be a measured property of the reference -- not a guess.

Author: Maccoy Merrell.
"""
import argparse
import copy
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# compare_dep puts every shared arc3_cov directory on sys.path as its own
# prerequisite; importing it FIRST is what makes the rest resolvable, and
# doing it in the other order is an ImportError three modules deep.
import compare_dep as cd                                        # noqa: E402
import axis_subjects                                            # noqa: E402
import dep_ref_gem5                                             # noqa: E402
import gem5_ref                                                 # noqa: E402
import dep_map                                                  # noqa: E402


def _count(tins, gins, ref_vocab, ref_dst_vocab):
    subj = axis_subjects.Subjects()
    rows, notes = [], []
    cd.score_guest('m', tins, gins, subj, rows, notes, ref_vocab,
                   ref_dst_vocab)
    out = {}
    for r in rows:
        out[r.axis] = out.get(r.axis, 0) + 1
    return out, subj


# ------------------------------------------------------------- the mutations
def mut_src_drop(tins):
    for t in tins:
        if len(t.src_regs) >= 1:
            t.src_regs = t.src_regs[1:]
            return 'dropped a declared source of pc=0x%x' % t.pc
    return None


#: Registers an INVENT mutation may add.  The mutation must pick one the
#: instruction does not ALREADY name: adding a register that is already there
#: is a no-op under set semantics, the axis correctly reports no change, and
#: the control reads as "the axis cannot convict" when nothing was injected.
#: Measured -- the first version of this file added REG_GPR31 unconditionally
#: and the riscv64 probes open with `add %gp31, ... -> %gp31`, so seven of
#: seven guests reported a DID NOT FIRE that was the mutation's own fault.
_INVENT_POOL = ('REG_GPR28', 'REG_GPR29', 'REG_GPR30', 'REG_GPR31',
                'REG_GPR27', 'REG_GPR26')


def _absent(t, extra=()):
    """A register this instruction names nowhere -- source, dest or edge."""
    used = set(t.src_regs) | set(t.dst_regs) | set(t.dst_deps) | set(extra)
    for v in t.dst_deps.values():
        used |= set(v)
    for c in _INVENT_POOL:
        if c not in used:
            return c
    return None


def mut_src_invent(tins):
    for t in tins:
        if not t.src_regs:
            continue
        c = _absent(t)
        if c is None:
            continue
        t.src_regs = t.src_regs + [c]
        return 'invented declared source %s on pc=0x%x' % (c, t.pc)
    return None


def mut_dst_drop(tins):
    for t in tins:
        if len(t.dst_deps) >= 1:
            k = sorted(t.dst_deps)[0]
            del t.dst_deps[k]
            return 'dropped destination %s of pc=0x%x' % (k, t.pc)
    return None


def mut_dst_invent(tins):
    for t in tins:
        if not t.dst_deps:
            continue
        c = _absent(t)
        if c is None:
            continue
        t.dst_deps[c] = set(t.src_regs)
        return 'invented destination %s on pc=0x%x' % (c, t.pc)
    return None


def mut_closure_drop(tins):
    for t in tins:
        for k, v in t.dst_deps.items():
            real = {e for e in v if e != 'imm' and not e.startswith('ld')}
            if real:
                t.dst_deps[k] = v - {sorted(real)[0]}
                return 'dropped an edge into %s of pc=0x%x' % (k, t.pc)
    return None


def mut_closure_invent(tins):
    for t in tins:
        if not t.dst_deps:
            continue
        c = _absent(t)
        if c is None:
            continue
        k = sorted(t.dst_deps)[0]
        t.dst_deps[k] = t.dst_deps[k] | {c}
        return 'invented edge %s -> %s of pc=0x%x' % (c, k, t.pc)
    return None


def mut_coverage(tins):
    """Orphan a declared source: keep it declared, route it nowhere."""
    for t in tins:
        if not t.dst_deps or not t.src_regs:
            continue
        routed = set()
        for v in t.dst_deps.values():
            routed |= {e for e in v if e != 'imm' and not e.startswith('ld')}
        cand = [r for r in t.src_regs if r in routed]
        if not cand:
            continue
        for k in t.dst_deps:
            t.dst_deps[k] = t.dst_deps[k] - {cand[0]}
        return 'orphaned declared source %s on pc=0x%x' % (cand[0], t.pc)
    return None


MUTATIONS = (
    ('dep-src-set', 'drop', mut_src_drop),
    ('dep-src-set', 'invent', mut_src_invent),
    ('dep-dst-set', 'drop', mut_dst_drop),
    ('dep-dst-set', 'invent', mut_dst_invent),
    ('dep-dst-closure', 'drop', mut_closure_drop),
    ('dep-dst-closure', 'invent', mut_closure_invent),
    ('dep-mask-coverage', 'orphan', mut_coverage),
)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument('--isa', required=True, choices=('riscv64', 'mipsel'))
    ap.add_argument('--decode', required=True)
    ap.add_argument('--rundir', required=True,
                    help='an outdir a compare_dep run already populated')
    ap.add_argument('--probes', required=True)
    ap.add_argument('guests', nargs='+')
    args = ap.parse_args(argv)

    ok = True
    for guest in args.guests:
        elf = os.path.join(args.probes, guest)
        log = os.path.join(args.rundir, guest + '.g5', 'exec.log')
        cst = os.path.join(args.rundir, guest + '.cst')
        for p in (elf, log, cst):
            if not os.path.exists(p):
                sys.stderr.write('MISSING: %s -- run compare_dep first\n' % p)
                return 3
        g, _ = dep_ref_gem5.parse(log, args.isa,
                                  ranges=gem5_ref.exec_ranges(elf))
        t0, _v, _n = dep_map.parse(args.decode, cst)
        vocab = set()
        dvocab = set()
        for x in g:
            vocab |= set(x.ext_srcs) | set(x.arch_dsts)
            dvocab |= set(x.arch_dsts)

        base, subj = _count(copy.deepcopy(t0), g, vocab, dvocab)
        print('\n%s / %s  baseline: %s' % (args.isa, guest,
                                           base or '{} (clean)'))
        for axis, kind, fn in MUTATIONS:
            if subj.facts.get(axis, 0) == 0:
                print('  %-22s %-7s NO SUBJECT on this guest -- skipped'
                      % (axis, kind))
                continue
            t = copy.deepcopy(t0)
            what = fn(t)
            if what is None:
                print('  %-22s %-7s NO MUTABLE SUBJECT -- skipped'
                      % (axis, kind))
                continue
            after, _ = _count(t, g, vocab, dvocab)
            b, a = base.get(axis, 0), after.get(axis, 0)
            fired = a > b
            ok = ok and fired
            print('  %-22s %-7s %-6s %d -> %d   (%s)'
                  % (axis, kind, 'FIRED' if fired else 'DID NOT FIRE',
                     b, a, what))
    print('\n%s' % ('ALL CONTROLS FIRED' if ok else
                    'A CONTROL DID NOT FIRE -- the axis cannot convict and '
                    'its clean rows vouch for nothing'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
