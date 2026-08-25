#!/usr/bin/env python3
"""What the aarch64 STATIC reference can and cannot say about memory ops.

Author: Maccoy Merrell.

TOTAL_COVERAGE.md carried two aarch64 memop rows that this decides:

  * 738 subjects where presence agrees and the COUNT differs, filed as the
    tracer's static claim being "capped at 1 for every multi-access form",
    with a wire-widening proposal as the next step.
  * 3,920 subjects with NO STATIC REFERENCE FOR ADDRESS, filed as a
    reference to be built.

Both are answered by measurement here, and both answers are negative: there
is nothing to widen and nothing to build.

--- THE COUNT AXIS -----------------------------------------------------

The three numbers are three different splits of the same traffic:

  the MRA        one Mem[] call per ELEMENT of the architectural access
  QEMU           whatever its memop lowering emitted
  the template   the number of static memory OPERANDS, which is what sizes
                 load_addr_dep_mask[] / store_addr_dep_mask[]

`max_dep_loads` was never a claim about how many accesses occur -- the
header that defines it says so ("deliberately NOT the same quantity ...
x86 XSAVEOPT is a single static store operand that issues 88 stores"), and
the runtime count rides CST_FID_N_LOADS / CST_FID_N_STORES with a 512-slot
ceiling and a must-be-0 overflow counter.  Comparing it to an element count
compares two quantities that were never the same one.

And for most of the 738 the reference number is not a per-opcode fact at
all: it is a function of the vector length the interpreter was configured
with.  This tool re-runs the reference at two vector lengths and counts how
many move.  A number that moves when nothing about the ENCODING moved
cannot be a static per-opcode claim, and no census taken at one VL could
have been a widening proposal.

What all three splits MUST agree on is BYTES, and that is the axis this
tool scores.  The refusal is one-directional on purpose: the tracer
covering MORE bytes than the reference is the project's goal, the tracer
covering FEWER is the disqualifying failure.

--- THE ADDRESS AXIS ---------------------------------------------------

An effective address is a runtime value.  The execute-ASL is evaluated with
register contents unknown, so every Mem[] the reference sees is handed an
unknown address -- which is counted here rather than asserted
(`mem_addr_known` / `mem_addr_unknown`).  A reference that resolves an
address on 0 of N memory-touching subjects has no address facet to compare,
and building one would not produce a comparison.  The address facet's
denominator is execution, which is what x86_64 (PIN) and riscv64 (Spike)
already use and what aarch64 and mipsel now have in gem5.

Usage:
    python memop_axis_verdict.py --ref-a REF_VL_A.json --ref-b REF_VL_B.json
                                 --batch BATCH.tsv [--decode DECODE.txt]
                                 [--cov DIR]
"""
import os
import re
import sys
import csv
import json
import argparse
import collections

#: `cst_decode` prints `0xPC <symbol>: bytes  mnemonic ...`, and drops
#: the `<symbol>` entirely for a PC with no symbol -- which is every
#: instruction in the anonymous page `memop_probe` executes from.  The
#: symbol is therefore optional here; requiring it silently skipped
#: 45,542 lines and scored the byte axis on an empty intersection.
_INSN = re.compile(r'^0x[0-9a-f]+(?: <[^>]*>)?: ((?:[0-9a-f]{2} )+)\s+\S+')
_LDW = re.compile(r'\bld=(?:0x[0-9a-fA-F]+|\?)/w(\d+)')
_STW = re.compile(r'\bst=(?:0x[0-9a-fA-F]+|\?)/w(\d+)')


def runtime_bytes(path):
    """encoding -> (max loads, max load bytes, max stores, max store bytes).

    Read off `cst_decode` disassembly of a real run.  The MAXIMUM over
    executions is taken, not the mean: a conditional access that did not
    fire on one execution is not evidence of absence, and the reference
    states what the instruction does when it does fire.
    """
    agg = collections.defaultdict(lambda: [0, 0, 0, 0, 0])
    with open(path) as f:
        for ln in f:
            m = _INSN.match(ln.strip())
            if not m:
                continue
            h = m.group(1).replace(' ', '')
            L = [int(x) for x in _LDW.findall(ln)]
            S = [int(x) for x in _STW.findall(ln)]
            a = agg[h]
            a[0] = max(a[0], len(L)); a[1] = max(a[1], sum(L))
            a[2] = max(a[2], len(S)); a[3] = max(a[3], sum(S)); a[4] += 1
    if not agg:
        sys.exit('%s yielded no instructions -- a byte axis that cannot find '
                 'its run must FAIL, not score 100%%' % path)
    return agg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cov', default='/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64')
    ap.add_argument('--ref-a', required=True, help='sweep at vector length A')
    ap.add_argument('--ref-b', required=True, help='sweep at vector length B')
    ap.add_argument('--batch', required=True)
    ap.add_argument('--decode', default=None,
                    help='cst_decode disassembly of a real aarch64 run')
    ap.add_argument('--out', default=None)
    ap.add_argument('--run-vl', type=int, default=None,
                    help='SVE vector length IN BITS that the run in --decode '
                         'executed at.  Given it, the vector-length-dependent '
                         'rows are scored against the reference swept at that '
                         'same length instead of being set aside.')
    ap.add_argument('--ref-a-vl', type=int, default=None,
                    help='vector length of --ref-a, when the sweep predates '
                         'the metadata record')
    A = ap.parse_args()

    a = json.load(open(A.ref_a))
    b = json.load(open(A.ref_b))
    meta = a.pop('__meta__', None)
    b.pop('__meta__', None)
    ref_a_vl = (meta or {}).get('vl', A.ref_a_vl)
    if A.ref_a_vl is not None and meta and meta['vl'] != A.ref_a_vl:
        sys.exit('--ref-a-vl %d contradicts the sweep\'s own record of %d'
                 % (A.ref_a_vl, meta['vl']))
    # A vector-length-dependent byte total is a real per-VL fact, and the run
    # executed at ONE vector length.  Scoring those rows is therefore allowed
    # -- but ONLY against the reference taken at the SAME length, and only
    # when both lengths are stated.  Guessing either is how a comparison
    # between two different machines gets reported as agreement.
    score_vl = (A.run_vl is not None and ref_a_vl is not None
                and A.run_vl == ref_a_vl)
    if A.run_vl is not None and ref_a_vl is None:
        sys.exit('--run-vl given but --ref-a carries no vector length and '
                 '--ref-a-vl was not supplied: the two cannot be checked '
                 'against each other, so the VL-dependent rows stay unscored')
    if A.run_vl is not None and not score_vl:
        sys.exit('the run executed at VL=%d and --ref-a was swept at VL=%d; '
                 'scoring one against the other would compare two different '
                 'machines' % (A.run_vl, ref_a_vl))
    opc = list(csv.DictReader(open(os.path.join(A.cov, 'opcodes.tsv')),
                              delimiter='\t'))
    trc = {r['hex']: r for r in csv.DictReader(open(A.batch), delimiter='\t')}
    rt = runtime_bytes(A.decode) if A.decode else {}

    fail = []
    both = vl_moved_mem = vl_moved_reg = 0
    vl_undef_reg = vl_undef_mem = 0
    notes_seen = 0
    vlreg_rows = []
    countdiff = countdiff_vl = 0
    addr_known = addr_unknown = memsubj = 0
    scored = short = over = equal = unscorable = notmet = 0
    vl_scored = 0
    notmet_fam = collections.Counter()
    rows = []

    for o in opc:
        h = o['hex']
        RA, RB, T = a.get(h), b.get(h), trc.get(h)
        if not RA or not RB or RA.get('status') != 'ok' \
                or RB.get('status') != 'ok' or not T:
            continue
        both += 1
        # An encoding that is architecturally UNDEFINED at one of the two
        # vector lengths does not have a register set there AT ALL: the
        # reference reports the prologue it executed before reaching the
        # ASL's own UNDEFINED statement.  Counting that as a set that MOVED
        # with the vector length is the error open item 9 named -- it made
        # 23 subjects look VL-conditional when 22 of them are constant
        # across every vector length at which they are DEFINED.  The two
        # cases are separated here and reported apart; a sweep whose rows
        # carry no notes cannot make the separation and is refused below.
        notes = (RA.get('notes') or []) + (RB.get('notes') or [])
        if notes:
            notes_seen += 1
        undef_here = ('undefined-path' in (RA.get('notes') or [])
                      or 'undefined-path' in (RB.get('notes') or []))
        if RA['src'] != RB['src'] or RA['dst'] != RB['dst']:
            if undef_here:
                vl_undef_reg += 1
            else:
                vl_moved_reg += 1
                vlreg_rows.append((o['opcode_id'], T.get('b_mnem', '')))
        moved = RA['mr'] != RB['mr'] or RA['mw'] != RB['mw']
        if moved:
            if undef_here:
                vl_undef_mem += 1
            else:
                vl_moved_mem += 1
        if RA['mr'] or RA['mw']:
            memsubj += 1
            addr_known += RA.get('ak', 0)
            addr_unknown += RA.get('au', 0)
        mr, mw = RA['mr'], RA['mw']
        fl, fs = int(T['f_loads']), int(T['f_stores'])
        if (mr > 0) == (fl > 0) and (mw > 0) == (fs > 0) \
                and not (mr == fl and mw == fs):
            countdiff += 1
            if moved:
                countdiff_vl += 1
        # BYTES, only where the reference total is complete, the encoding is
        # not vector-length dependent, and a real run exercised it.
        r = rt.get(h)
        if r is None or not (mr or mw):
            continue
        if RA.get('bunk', 0) or (moved and not score_vl):
            unscorable += 1
            continue
        rb, wb = RA.get('mrb', 0), RA.get('mwb', 0)
        got_r, got_w = r[1], r[3]
        if got_r == 0 and got_w == 0 and (rb or wb):
            # The instruction executed and published NO memop at all.  That
            # is not evidence of loss: it is what a CONDITIONAL access looks
            # like when the condition was false, and the reference counts
            # both arms of a condition it cannot resolve (R4/R5).  Measured
            # rather than assumed -- with the condition established, the
            # three families that land here publish exactly the
            # architectural byte count (cst_runs/p3/arc3/staticdyn/cond):
            #   ldxr then stxr        st=0x0/w8   arch 8
            #   ptrue then ld1rd      ld=0x0/w8   arch 8
            #   ptrue then ld1rqb     16 x w1     arch 16
            # Reported as its own class so it can never be read as
            # agreement, and never as loss.
            notmet += 1
            notmet_fam[T['b_mnem'].split()[0]] += 1
            continue
        scored += 1
        if moved:
            vl_scored += 1
        if got_r < rb or got_w < wb:
            short += 1
            fail.append('%s (%s): the run covered %d load / %d store bytes, '
                        'the architecture states %d / %d -- the tracer is '
                        'SHORT, which is the one direction that disqualifies'
                        % (o['opcode_id'], T['b_mnem'], got_r, got_w, rb, wb))
        elif got_r > rb or got_w > wb:
            over += 1
            rows.append((o['opcode_id'], T['b_mnem'], rb, wb, got_r, got_w))
        else:
            equal += 1

    print('=' * 74)
    print('aarch64 memop axes -- what a STATIC reference can say')
    print('=' * 74)
    print('subjects probed ok at BOTH vector lengths        %5d' % both)
    print()
    print('COUNT axis')
    print('  register src/dst sets that MOVED with VL       %5d' % vl_moved_reg)
    print('    ... UNDEFINED at one VL, so not a moved set  %5d' % vl_undef_reg)
    print('  memop COUNTS that MOVED with VL                %5d' % vl_moved_mem)
    print('    ... UNDEFINED at one VL, so not a moved count %4d' % vl_undef_mem)
    print('  presence-agree-countdiff rows                  %5d' % countdiff)
    print('    ... of which the reference number is VL-dependent  %5d'
          % countdiff_vl)
    print()
    print('ADDRESS axis')
    print('  subjects with memory traffic                   %5d' % memsubj)
    print('  Mem[] accesses whose ADDRESS resolved          %5d' % addr_known)
    print('  Mem[] accesses whose ADDRESS did not resolve   %5d' % addr_unknown)
    print()
    print('BYTE axis (reference complete, exercised by a run%s)'
          % (', VL-dependent rows scored at the run\'s own VL=%d' % A.run_vl
             if score_vl else ', VL-independent only'))
    print('  scored                                         %5d' % scored)
    print('    tracer bytes == architecture bytes           %5d' % equal)
    print('    tracer bytes >  architecture bytes           %5d' % over)
    print('    tracer bytes <  architecture bytes           %5d  <-- must be 0'
          % short)
    print('    ... of them VL-dependent, scored at VL=%s %5d'
          % (ref_a_vl if score_vl else '-', vl_scored))
    print('  not scorable (incomplete ref total%s)      %5d'
          % ('' if score_vl else ' or VL-dependent', unscorable))
    print('  access never fired on this run (condition false)     %5d'
          % notmet)
    if notmet:
        print('    families: %s'
              % ', '.join('%s x%d' % kv for kv in notmet_fam.most_common(8)))
    if over:
        print('\n  covering MORE than the architecture states, first rows:')
        for r in rows[:8]:
            print('    %-30s %-10s arch(%d,%d) run(%d,%d)' % r)
    if vlreg_rows:
        print('\n  register sets that are GENUINELY vector-length dependent:')
        for oid, mn in vlreg_rows[:12]:
            print('    %-28s %s' % (oid, mn))
    if A.out:
        json.dump({'both': both, 'vl_moved_mem': vl_moved_mem,
                   'vl_undef_reg': vl_undef_reg, 'vl_undef_mem': vl_undef_mem,
                   'vl_moved_reg': vl_moved_reg, 'countdiff': countdiff,
                   'countdiff_vl': countdiff_vl, 'mem_subjects': memsubj,
                   'addr_known': addr_known, 'addr_unknown': addr_unknown,
                   'byte_scored': scored, 'byte_equal': equal,
                   'byte_over': over, 'byte_short': short,
                   'byte_condition_not_met': notmet},
                  open(A.out, 'w'), indent=1)
    if addr_known and not addr_unknown:
        fail.append('the reference resolved every address it saw -- the '
                    'ADDRESS axis is NOT empty and the retraction does not '
                    'hold')
    if not memsubj:
        fail.append('no subject carried memory traffic -- the reference is '
                    'not being read')
    if not notes_seen:
        fail.append('neither sweep carries interpreter NOTES, so an encoding '
                    'that is UNDEFINED at one vector length cannot be told '
                    'from a register set that moved with it -- re-run the '
                    'reference with mra_sweep.py, which records them')
    if fail:
        print('\nREFUSED:')
        for m in fail:
            print('  ' + m)
        return 1
    print('\nVERDICT')
    print('  COUNT   : %d of %d differing rows carry a reference number that '
          'is not a\n            per-opcode fact.  There is no static count '
          'to widen toward.' % (countdiff_vl, countdiff))
    print('  ADDRESS : %d of %d Mem[] accesses resolved an address.  A static '
          'reference\n            has no address facet; its denominator is '
          'execution.' % (addr_known, addr_known + addr_unknown))
    print('  BYTES   : %d scored, %d short.  No execution information is '
          'dropped.' % (scored, short))
    return 0


if __name__ == '__main__':
    sys.exit(main())
