"""
riscv64 has TWO execution references.  This scores the map against BOTH and,
more importantly, scores THE TWO REFERENCES AGAINST EACH OTHER.

WHY THE SECOND REFERENCE IS NOT REDUNDANT
=========================================
gem5 and Spike are independent implementations with independent notions of
what an instruction reads, and where they disagree the tracer is being scored
against a coin flip.  This arc has already found several such disagreements
and each one was a fact about the references, not about the trace.  A leg that
quotes one reference and never asks the other cannot tell "the tracer is
wrong" from "this reference is".

Spike's contract is narrower than gem5's and the difference is what makes the
pairing useful:

* Spike's commit log is PER INSTRUCTION, so it states a SOURCE SET and no
  per-destination structure.  Exactly one axis is asked of it -- the source
  set -- and the per-destination closure is not, because Spike cannot answer.
* Spike is PATCHED to record reads at all (``spike-patches/``), and
  ``spike_ref.require_patched`` refuses a log from an unpatched binary, so a
  stale Spike reports as an error rather than as an axis quietly agreeing
  with nothing.
* Spike reports ``x0`` as a source.  Its own patch notes say why: "an x0
  source is a real fact about the encoding, unlike an x0 destination".  gem5
  does not report it at all.  THAT IS THE HEADLINE DISAGREEMENT and R7.3
  settles which of the two is right.

Author: Maccoy Merrell.
"""
import argparse
import collections
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import compare_dep as cd                                        # noqa: E402
import dep_map                                                  # noqa: E402
import dep_ref_gem5                                             # noqa: E402
import gem5_ref                                                 # noqa: E402
import spike_ref                                                # noqa: E402


def run_spike(spike, pk, guest, out, isa='rv64gcv', dtc_dir=None):
    # SPIKE SHELLS OUT TO `dtc` to build the device tree it hands the guest,
    # and without it on PATH it dies with "Failed to run dtc" before writing a
    # single commit line.  The failure is named here rather than left to the
    # caller for the same reason the gem5 prerequisites are: a reference that
    # cannot run must say what it needs.
    env = dict(os.environ)
    if dtc_dir:
        env['PATH'] = dtc_dir + os.pathsep + env.get('PATH', '')
    log = out + '.commits.log'
    p = subprocess.run([spike, '--isa=' + isa, '-l', '--log-commits',
                        '--log=' + log, pk, guest],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       env=env)
    # Spike exits non-zero on a bare-metal guest that ends with `ecall`; the
    # log is still complete.  What is NOT tolerated is a log that the patch
    # gate rejects, or one with no lines in the guest's own range -- both are
    # refusals below, by name.
    if not os.path.exists(log) or os.path.getsize(log) == 0:
        raise RuntimeError('spike wrote no commit log for %s: %s'
                           % (guest, p.stdout.decode('utf-8', 'replace')[-600:]))
    return log


def spike_srcs(log, lo, hi):
    """``[(pc, {REG_*})]`` in retirement order, plus the unmappable census."""
    ins = spike_ref.parse_commit_log(log, pc_lo=lo, pc_hi=hi)
    spike_ref.require_patched(log, len(ins))
    out, unmapped = [], collections.Counter()
    for i in ins:
        s = set()
        for name in {r[0] for r in i.reads}:
            g = spike_ref.to_generic(name)
            if g is None or g.startswith('CSR:'):
                unmapped[name] += 1
                continue
            s.add(g)
        out.append((i.pc, s))
    return out, unmapped


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument('--spike', required=True)
    ap.add_argument('--pk', required=True,
                    help='riscv-pk.  Spike bare-metal maps memory at '
                         '0x80000000 and the probes link at 0x10000, so a '
                         'bare run dies with "Memory address 0x101f0 is '
                         'invalid" before writing a line; the proxy kernel '
                         'is what puts the guest at its own link address.')
    ap.add_argument('--dtc-dir', help='directory holding the dtc binary '
                    'spike shells out to')
    ap.add_argument('--decode', required=True)
    ap.add_argument('--rundir', required=True,
                    help='an outdir a compare_dep riscv64 run populated')
    ap.add_argument('--probes', required=True)
    ap.add_argument('-o', '--out', required=True)
    ap.add_argument('guests', nargs='+')
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)

    tally = collections.Counter()
    detail = collections.Counter()
    lines = []

    for guest in args.guests:
        elf = os.path.join(args.probes, guest)
        g5log = os.path.join(args.rundir, guest + '.g5', 'exec.log')
        cst = os.path.join(args.rundir, guest + '.cst')
        for p in (elf, g5log, cst):
            if not os.path.exists(p):
                sys.stderr.write('MISSING %s -- run compare_dep first\n' % p)
                return 3
        ranges = gem5_ref.exec_ranges(elf)
        lo, hi = ranges[0]
        slog = run_spike(args.spike, args.pk, elf,
                         os.path.join(args.out, guest),
                         dtc_dir=args.dtc_dir)
        sp, unmapped = spike_srcs(slog, lo, hi)
        g5, _ = dep_ref_gem5.parse(g5log, 'riscv64', ranges=ranges)
        tr, _v, _n = dep_map.parse(args.decode, cst)
        for k, v in unmapped.items():
            detail['SPIKE-UNMAPPED:' + k] += v

        n = min(len(sp), len(g5), len(tr))
        aligned = 0
        for i in range(n):
            if not (sp[i][0] == g5[i].pc == tr[i].pc):
                break
            aligned += 1
        lines.append('%-10s spike=%d gem5=%d tracer=%d aligned=%d'
                     % (guest, len(sp), len(g5), len(tr), aligned))

        for i in range(aligned):
            _pc, s = sp[i]
            gset = set(g5[i].ext_srcs)
            tset = set(tr[i].src_regs)
            tally['facts'] += 1
            # ---- tracer vs spike
            if tset != s:
                tally['tracer-vs-spike'] += 1
                detail['T\\S:' + ','.join(sorted(tset - s))] += 1
                detail['S\\T:' + ','.join(sorted(s - tset))] += 1
            # ---- THE REFERENCE PAIRING
            if gset != s:
                tally['gem5-vs-spike'] += 1
                detail['G\\S:' + ','.join(sorted(gset - s))] += 1
                detail['S\\G:' + ','.join(sorted(s - gset))] += 1

    rpt = os.path.join(args.out, 'CROSSCHECK.txt')
    with open(rpt, 'w') as fh:
        fh.write('riscv64 -- the map against BOTH references, and the two '
                 'references against each other\n')
        fh.write('=' * 72 + '\n\n')
        for l in lines:
            fh.write('  %s\n' % l)
        fh.write('\n  facts (instructions aligned on all three): %d\n'
                 % tally['facts'])
        fh.write('  tracer disagrees with spike : %d\n'
                 % tally['tracer-vs-spike'])
        fh.write('  gem5   disagrees with spike : %d\n'
                 % tally['gem5-vs-spike'])
        fh.write('\nSET DIFFERENCES (T=tracer, G=gem5, S=spike; "A\\B" is in '
                 'A and not in B)\n')
        for k, v in sorted(detail.items(), key=lambda x: -x[1]):
            if k.endswith(':'):
                continue
            fh.write('  %-44s %d\n' % (k, v))
        if tally['facts'] == 0:
            fh.write('\nINERT -- nothing was compared.\n')
    sys.stdout.write(open(rpt).read())
    return 0 if tally['facts'] else 2


if __name__ == '__main__':
    sys.exit(main())
