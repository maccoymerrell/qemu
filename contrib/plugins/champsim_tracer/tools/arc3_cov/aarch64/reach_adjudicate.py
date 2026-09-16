#!/usr/bin/env python3
"""Per-row aarch64 reachability, with every leg printed on the row.

Author: Maccoy Merrell.

THE HOLE THIS CLOSES.  The aarch64 UNREACHABLE column read 0 while 1,103 of
the 3,920 subjects SIGILL at EL0.  110 of those carried a second leg -- an ID
register QEMU hardwires to zero (`unprobed_adjudicate.py`) -- and 993 carried
none.  A column that reads 0 because nobody measured the other direction is
not a measurement, and "SIGILL at EL0" alone cannot separate

    the translator has no pattern for this encoding      (UNREACHABLE)
    the encoding needs a PSTATE this probe never set     (an ENABLE)
    the encoding is implemented above EL0                (a PRIVILEGE)

exactly as CPL3 could not separate them on x86_64 until `sysprobe.S` existed.
This tool takes the legs that do separate them and prints a verdict per row.

THE LEGS, in the order they are consulted.

  EL0-off       `reach_probe_a64 --pre=off`: the encoding executed under
                qemu-aarch64 with SVCR = 0.  Ran -> REACHABLE, done.

  EL0-enable    `--pre=smstart|sm|za`: the same encoding with PSTATE.SM
                and/or PSTATE.ZA set.  The whole SME instruction set is
                UNDEFINED outside streaming mode, so an SME row refused with
                SVCR = 0 was refused for the PSTATE and not for the opcode.
                An encoding that runs under ANY arm is REACHABLE: the arms
                are a union, because entering streaming mode makes the
                non-streaming SVE forms UNDEFINED in exactly the same way.

  EL1           `sysreach.S` under qemu-system-aarch64: the encoding at EL1
                with FP, SVE and SME enabled at maximum vector length.
                ESR_EL1.EC == 0x00 is the architecture's UNDEFINED; ANY
                other EC, and the 0xFE "ran and transferred control" case,
                mean QEMU DECODED it.  Decoded at EL1 while refused at EL0
                is a PRIVILEGE row, not an unimplemented one.

  ID register   `unprobed_adjudicate.py`'s feature gates, carried in as a
                reason for rows that refuse everywhere.  A row that refuses
                on every leg is UNREACHABLE whether or not a gate is named;
                the gate says WHY.

A row with no leg at all is not adjudicated -- it is REFUSED by name, and
the tool exits non-zero.  That is the whole point: the previous column read
0 because a missing leg scored as a verdict.

Usage:
    python reach_adjudicate.py --cov DIR --el0 off=FILE --el0 smstart=FILE ...
                               --el1 FILE [--gates FILE] [--out FILE]
"""
import os
import sys
import csv
import argparse
import collections


def read_el0(path):
    rows = {}
    with open(path) as f:
        for r in csv.DictReader(f, delimiter='\t'):
            rows[r['hex']] = (r['exec'], r['signal'])
    if not rows:
        sys.exit('%s carries no readings -- a leg that cannot find its '
                 'evidence must FAIL, not adjudicate' % path)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cov', default='/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64')
    ap.add_argument('--el0', action='append', default=[], metavar='ARM=FILE',
                    help='reach_probe_a64 output for one enable arm')
    ap.add_argument('--el1', default=None, help='sysreach el1.tsv')
    ap.add_argument('--gates', default=None,
                    help='unprobed_adjudicate.py per-row verdicts')
    ap.add_argument('--out', default=None)
    A = ap.parse_args()

    if not A.el0:
        sys.exit('no EL0 arm given')
    arms = {}
    for spec in A.el0:
        name, _, path = spec.partition('=')
        arms[name] = read_el0(path)
    if 'off' not in arms:
        sys.exit('the `off` arm is the control and is required')

    el1 = {}
    if A.el1:
        with open(A.el1) as f:
            for r in csv.DictReader(f, delimiter='\t'):
                el1[r['hex']] = (int(r['el1_ec'], 16), r['el1_decoded'])

    gate = {}
    if A.gates:
        with open(A.gates) as f:
            for r in csv.DictReader(f, delimiter='\t'):
                gate[r['hex']] = (r['feature'], r['gate_reg'])

    opc = list(csv.DictReader(open(os.path.join(A.cov, 'opcodes.tsv')),
                              delimiter='\t'))

    # AN ARM THAT DID NOT COVER EVERY SUBJECT IS NOT AN ARM.
    # The arms are a UNION -- a row is reachable if it runs under ANY of them --
    # so a subject MISSING from one arm is silently indistinguishable from a
    # subject that arm refused, and it weakens the union without ever being
    # noticed.  Measured 2026-08-25: a `za` arm that had completed 3,192 of
    # 3,920 subjects adjudicated all 3,920 rows without a word.  A partial arm
    # is a wrong answer, not a slow one.
    _subjects = set(o['hex'] for o in opc)
    _short = {name: len(_subjects - set(rows_))
              for name, rows_ in arms.items()}
    _bad = {n: k for n, k in _short.items() if k}
    if _bad:
        sys.exit('INCOMPLETE EL0 ARM -- %s.  The arms are a union, so a '
                 'subject missing from one arm reads exactly like a subject '
                 'that arm refused; finish the arm and adjudicate again.'
                 % ', '.join('%s is missing %d of %d subjects'
                             % (n, k, len(_subjects))
                             for n, k in sorted(_bad.items())))
    if el1:
        _el1_short = len(_subjects - set(el1))
        if _el1_short:
            print('EL1 leg: %d of %d subjects NOT MEASURED (the machine wedged '
                  'on them); every such row must carry an EL0 leg or be '
                  'REFUSED below' % (_el1_short, len(_subjects)))

    fail = []
    tally = collections.Counter()
    by_arm = collections.Counter()
    rows = []
    for o in opc:
        h = o['hex']
        legs = {}
        ran_on = []
        for name, tbl in arms.items():
            r = tbl.get(h)
            if r is None:
                continue
            legs['el0_' + name] = '%s/%s' % r
            if r[0] == 'yes' or r[1] not in ('4',):
                # Ran, or refused for a reason that is NOT "no such
                # instruction": SIGSEGV is an address, SIGALRM is a loop,
                # SIGTRAP is a breakpoint.  Every one of those required the
                # encoding to be decoded and executed first.
                ran_on.append(name)
        e = el1.get(h)
        legs['el1'] = ('%02x/%s' % e) if e else '-'

        if not legs or ('el0_off' not in legs):
            fail.append('%s (%s): no EL0 control reading' % (o['opcode_id'],
                                                             o['mnemonic']))
            tally['NO-LEG'] += 1
            continue
        if ran_on:
            v = 'REACHABLE'
            why = 'EL0:' + ','.join(sorted(ran_on))
            if 'off' in ran_on:
                by_arm['ran at EL0 with SVCR=0 (the original leg)'] += 1
            else:
                by_arm['refused with SVCR=0, ran ONLY with a PSTATE enable: '
                       + ','.join(sorted(ran_on))] += 1
        elif e is None:
            fail.append('%s (%s): refused on every EL0 arm and has no EL1 '
                        'reading -- this is the REACHABLE-UNPROBED hole the '
                        'tool exists to refuse' % (o['opcode_id'],
                                                   o['mnemonic']))
            tally['NO-EL1-LEG'] += 1
            continue
        elif e[1] == 'yes':
            v = 'REACHABLE'
            why = 'EL1:decoded,EC=%02x' % e[0]
            by_arm['refused at EL0, DECODED at EL1 (a privilege row)'] += 1
        else:
            v = 'UNREACHABLE'
            g = gate.get(h)
            why = ('EL0+EL1:UNDEF' + (';gate=%s(%s)' % g if g else ';no gate named'))
            by_arm['UNDEF on every leg'] += 1
        tally[v] += 1
        rec = {'opcode_id': o['opcode_id'], 'mnemonic': o['mnemonic'],
               'hex': h, 'verdict': v, 'why': why}
        rec.update(legs)
        rows.append(rec)

    print('=' * 74)
    print('aarch64 reachability -- per row, with the legs on the row')
    print('=' * 74)
    print('  arms measured: %s' % ', '.join(sorted(arms)))
    print('  EL1 readings : %d' % len(el1))
    print()
    for k, v in sorted(tally.items()):
        print('  %-14s %5d' % (k, v))
    print()
    for k, v in by_arm.most_common():
        print('  %5d  %s' % (v, k))
    if A.out and rows:
        with open(A.out, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()),
                               delimiter='\t')
            w.writeheader()
            w.writerows(rows)
        print('\n  per-row verdicts -> %s' % A.out)
    if fail:
        print('\nREFUSED (%d):' % len(fail))
        for m in fail[:20]:
            print('  ' + m)
        if len(fail) > 20:
            print('  ... and %d more' % (len(fail) - 20))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
