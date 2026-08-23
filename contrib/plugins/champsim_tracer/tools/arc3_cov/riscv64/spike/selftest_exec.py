"""
Negative control for the riscv64 execution cross-check.

"reg-dst-value: ALL AGREE" is only evidence if the check COULD have said
otherwise.  A comparison that silently cannot fire reports agreement forever,
and this project has been caught by exactly that shape before -- which is why
an enumerated list of zeros is not accepted here as proof of anything.

So: take a real aligned pair, perturb ONE side by ONE fact, and require the
axis that owns that fact to go red.  Every axis the harness reports must have
a mutation that fires it; an axis with no firing mutation is reported as
UNPROVEN and the self-test fails, because its zero means nothing.

Run it against any trace pair the comparator can build.  It mutates the parsed
records in memory only -- nothing on disk is touched.

Author: Maccoy Merrell.
"""
import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import compare_exec
import spike_ref
import tracer_log


def _first(insns, pred):
    for i in insns:
        if pred(i):
            return i
    return None


#: (axis, description, mutate(ref_insn, trc_insn)).  Each mutation changes one
#: fact on one side; the named axis must report it.
MUTATIONS = []


def mutation(axis, why, need=None):
    def deco(fn):
        MUTATIONS.append((axis, why, fn, need))
        return fn
    return deco


@mutation('reg-dst-set', 'drop a destination register from the tracer',
          need=lambda r, t: bool(t.writes))
def m_regset(r, t):
    t.writes.pop()


@mutation('reg-dst-value', 'corrupt one destination register VALUE',
          need=lambda r, t: bool(t.writes))
def m_regval(r, t):
    n, v, w = t.writes[0]
    t.writes[0] = (n, v ^ 0x1, w)


@mutation('memop-count', 'invent an extra load on the tracer side',
          need=lambda r, t: True)
def m_memcount(r, t):
    t.loads.append((0xdead000, 0, 8))


@mutation('memop-addr', 'move a store address on the tracer side',
          need=lambda r, t: bool(t.stores))
def m_memaddr(r, t):
    a, d, w = t.stores[0]
    t.stores[0] = (a ^ 0x40, d, w)


@mutation('store-data', 'corrupt one store DATUM on the tracer side',
          need=lambda r, t: bool(t.stores))
def m_stdata(r, t):
    a, d, w = t.stores[0]
    t.stores[0] = (a, d ^ 0xff, w)


@mutation('csr-dst-set', 'drop a CSR destination from the tracer',
          need=lambda r, t: any(n in spike_ref.CSR_IDS
                                for n, _, _ in t.writes))
def m_csrset(r, t):
    t.writes[:] = [w for w in t.writes if w[0] not in spike_ref.CSR_IDS]


@mutation('csr-dst-value', 'corrupt a CSR VALUE the reference also names',
          need=lambda r, t: (any(n in spike_ref.CSR_IDS
                                 for n, _, _ in t.writes)
                             and any(spike_ref.bank(n) == 'csr'
                                     for n, _ in r.writes)))
def m_csrval(r, t):
    for i, (n, v, w) in enumerate(t.writes):
        if n in spike_ref.CSR_IDS:
            # 0xff, not 0x1f: fcsr is {frm[7:5], fflags[4:0]} and the
            # reference may name either field, so the perturbation has to
            # reach both.  A 0x1f flip leaves an frm comparison unchanged --
            # which is how this control first reported itself UNPROVEN
            # instead of quietly passing.
            t.writes[i] = (n, v ^ 0xff, w)
            return


def run(corpus, verbose=True):
    """-> (fired, unproven).  Non-empty `unproven` means the test failed.

    `corpus` is [(name, ref insns, tracer insns)].  An axis is proven when it
    fires on ANY guest: a guest with no CSR traffic at all cannot exercise the
    CSR axes, and treating that as a failure would say nothing about the check.
    """
    pairs = []
    for name, ref, trc in corpus:
        p, _, _ = compare_exec.align(ref, trc)
        pairs.extend((name, r, t) for r, t in p)
    fired, unproven = [], []
    for axis, why, fn, need in MUTATIONS:
        hit = None
        for name, r, t in pairs:
            if need is not None and not need(r, t):
                continue
            r2, t2 = copy.deepcopy(r), copy.deepcopy(t)
            before = compare_exec.compare_insn(r2, t2)
            if any(x.axis == axis for x in before):
                continue                     # already disagrees: no signal
            fn(r2, t2)
            after = compare_exec.compare_insn(r2, t2)
            if any(x.axis == axis for x in after):
                hit = (name, r.pc, why)
                break
        if hit:
            fired.append((axis, hit[0], hit[1], why))
        else:
            unproven.append((axis, why))
    if verbose:
        print('NEGATIVE CONTROL -- can each axis fire at all?')
        print('')
        for axis, name, pc, why in fired:
            print('  FIRES     %-14s %s @ 0x%x   (%s)'
                  % (axis, name, pc, why))
        for axis, why in unproven:
            print('  UNPROVEN  %-14s            (%s)' % (axis, why))
        print('')
        print('  %d/%d axes proven able to report a disagreement'
              % (len(fired), len(MUTATIONS)))
    return fired, unproven


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--commits', required=True, help='spike commit log')
    ap.add_argument('--trace', required=True, help='.cst trace')
    ap.add_argument('--guest', required=True, help='the guest ELF')
    ap.add_argument('--decode', required=True)
    args = ap.parse_args()

    lo, hi = compare_exec.exec_ranges(args.guest)[0]
    ref = spike_ref.parse_commit_log(args.commits, lo, hi, priv=0)
    trc = tracer_log.parse(args.decode, args.trace)
    _, unproven = run([(os.path.basename(args.guest), ref, trc)])
    return 1 if unproven else 0


if __name__ == '__main__':
    sys.exit(main())
