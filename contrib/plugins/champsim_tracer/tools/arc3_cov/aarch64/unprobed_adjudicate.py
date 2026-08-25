#!/usr/bin/env python3
"""Adjudicate the aarch64 opcodes the MRA memop reference cannot probe.

Author: Maccoy Merrell.

THE HOLE.  `mra_ref.py` returns `ok` for 3,810 of the 3,920 aarch64 opcode
subjects.  106 have no Arm MRA instruction page at all -- they entered the
denominator from LLVM MC as post-2022-12 architecture additions -- and 4
exhaust the ASL interpreter's loop budget.  Those 110 rows scored REF-UNPROBED,
which is a fourth value: not COVERED, not UNREACHABLE, not UNCOVERED.  A row
a reference cannot probe is a REACHABLE-UNPROBED hole unless the encoding is
shown to be unreachable, and this decides which.

WHAT IS *NOT* SUFFICIENT, measured rather than assumed:

  * SIGILL at EL0 alone.  1,103 of the 3,920 subjects SIGILL under
    `qemu-aarch64 -cpu max`, and an encoding QEMU implements only at EL1 or
    above would look identical from EL0.  The refusal is necessary evidence
    and is required here, but it does not separate "no decoder" from "wrong
    exception level".

  * "the mnemonic is absent from every target/arm/tcg .decode file".  It is
    absent for all 110 -- and also for 1,683 subjects that RUN, because the
    decodetree pattern names are not the assembly mnemonics.  The leg was
    tried, it does not discriminate, and it is recorded here so nobody
    reaches for it again.

THE LEG THAT DECIDES, and it is privilege-independent.  Every one of the 110
is a data-processing encoding gated by an architectural feature, and the
architecture makes such an encoding UNDEFINED at EVERY exception level when
the feature is not implemented.  So the question becomes whether QEMU
implements the feature, which is read off the ID register the guest sees --
not off a header, and not off a table.

For the three registers that gate 108 of the 110 rows, QEMU does not merely
leave the field clear on one CPU model: `ID_AA64ISAR3_EL1`, `ID_AA64PFR2_EL1`
and `ID_AA64FPFR0_EL1` are declared in the RESERVED block of
`target/arm/helper.c` as `ARM_CP_CONST` with `resetvalue = 0`, so their value
is not taken from `cpu->isar` at all and NO CPU model can raise it.  That
locator is resolved against the tree on every run; a locator that stops
matching exits non-zero rather than printing a stale claim.

Usage:
    python unprobed_adjudicate.py --cov DIR --batch FILE --reach FILE
                                  --idregs FILE [--out FILE]
"""
import os
import re
import sys
import csv
import json
import argparse
import collections

#: mnemonic family -> (feature, gate).  A gate is (register, lambda value ->
#: True when the feature IS implemented).  Nothing is keyed on an encoding
#: bit: the subject list names the family and the family names the feature.
GATES = {
    'addpt':   ('FEAT_CPA',       'ID_AA64ISAR3_EL1', lambda v: v != 0),
    'subpt':   ('FEAT_CPA',       'ID_AA64ISAR3_EL1', lambda v: v != 0),
    'maddpt':  ('FEAT_CPA',       'ID_AA64ISAR3_EL1', lambda v: v != 0),
    'msubpt':  ('FEAT_CPA',       'ID_AA64ISAR3_EL1', lambda v: v != 0),
    'madpt':   ('FEAT_CPA',       'ID_AA64ISAR3_EL1', lambda v: v != 0),
    'mlapt':   ('FEAT_CPA',       'ID_AA64ISAR3_EL1', lambda v: v != 0),
    'famax':   ('FEAT_FAMINMAX',  'ID_AA64ISAR3_EL1', lambda v: v != 0),
    'famin':   ('FEAT_FAMINMAX',  'ID_AA64ISAR3_EL1', lambda v: v != 0),
    'fmaxqv':   ('FEAT_SVE2p1',   'ID_AA64ZFR0_EL1',  lambda v: (v & 0xf) >= 2),
    'fminqv':   ('FEAT_SVE2p1',   'ID_AA64ZFR0_EL1',  lambda v: (v & 0xf) >= 2),
    'fmaxnmqv': ('FEAT_SVE2p1',   'ID_AA64ZFR0_EL1',  lambda v: (v & 0xf) >= 2),
    'fminnmqv': ('FEAT_SVE2p1',   'ID_AA64ZFR0_EL1',  lambda v: (v & 0xf) >= 2),
    'retaasppc': ('FEAT_PAuth_LR', 'ID_AA64ISAR1_EL1',
                  lambda v: ((v >> 4) & 0xf) >= 7 or ((v >> 8) & 0xf) >= 7),
    'retabsppc': ('FEAT_PAuth_LR', 'ID_AA64ISAR1_EL1',
                  lambda v: ((v >> 4) & 0xf) >= 7 or ((v >> 8) & 0xf) >= 7),
}
#: the FP8 conversion / dot / multiply-accumulate family, all of which need
#: FEAT_FP8 (ID_AA64FPFR0_EL1) and the FPMR it reads (ID_AA64PFR2_EL1.FPMR).
_FP8 = ('f1cvt f1cvtl f1cvtl2 f1cvtlt f2cvt f2cvtl f2cvtl2 f2cvtlt '
        'bf1cvt bf1cvtl bf1cvtl2 bf1cvtlt bf2cvt bf2cvtl bf2cvtl2 bf2cvtlt '
        'fcvtnb fvdotb fmlall fmlallbb fmlallbt fmlalltb fmlalltt').split()
for _m in _FP8:
    GATES[_m] = ('FEAT_FP8', 'ID_AA64FPFR0_EL1', lambda v: v != 0)

#: Registers whose zero is structural in QEMU rather than a model choice:
#: (architectural name -> source locator that must still resolve).  QEMU does
#: not know the architectural name of S3_0_C0_C4_7 at all -- ID_AA64FPFR0_EL1,
#: which gates the whole FP8 family -- and carries the encoding in its
#: reserved block as `ID_AA64PFR7_EL1_RESERVED`.  A register the emulator has
#: no name for is a stronger statement of absence than a cleared field, and
#: the locator is written against the name QEMU actually uses so a rename
#: fails the run instead of being papered over.
CONST_ZERO = {
    'ID_AA64ISAR3_EL1': ('target/arm/helper.c', 'ID_AA64ISAR3_EL1_RESERVED'),
    'ID_AA64PFR2_EL1':  ('target/arm/helper.c', 'ID_AA64PFR2_EL1_RESERVED'),
    'ID_AA64FPFR0_EL1': ('target/arm/helper.c', 'ID_AA64PFR7_EL1_RESERVED'),
}

QEMU = os.environ.get('CST_QEMU_SRC', '/mnt/md0/QEMU/qemu')


def read_idregs(path):
    v = {}
    with open(path) as f:
        for ln in f:
            p = ln.split()
            if len(p) == 2 and p[0].startswith('ID_'):
                v[p[0]] = int(p[1], 16)
    if not v:
        sys.exit('%s carries no ID register readings -- a leg that cannot '
                 'find its evidence must FAIL, not adjudicate' % path)
    return v


def check_locators(fail):
    """A RESERVED-block claim is only as good as the line still being there."""
    for reg, (rel, needle) in CONST_ZERO.items():
        path = os.path.join(QEMU, rel)
        try:
            src = open(path).read()
        except OSError as e:
            fail.append('locator unreadable for %s: %s' % (reg, e))
            continue
        i = src.find(needle)
        if i < 0:
            fail.append('%s: "%s" no longer appears in %s -- the RESERVED '
                        'claim is stale' % (reg, needle, rel))
            continue
        blk = src[i:i + 400]
        if 'ARM_CP_CONST' not in blk or 'resetvalue = 0' not in blk:
            fail.append('%s: %s no longer declares ARM_CP_CONST resetvalue = 0'
                        % (reg, needle))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cov', default='/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64')
    ap.add_argument('--batch', required=True,
                    help='isaxcheck --isa=aarch64 --batch over the denominator')
    ap.add_argument('--reach', required=True,
                    help='reach_probe_a64 output over the denominator')
    ap.add_argument('--idregs', required=True, help='idprobe output')
    ap.add_argument('--out', default=None)
    A = ap.parse_args()

    ref = json.load(open(os.path.join(A.cov, 'ref_mra.json')))
    opc = list(csv.DictReader(open(os.path.join(A.cov, 'opcodes.tsv')),
                              delimiter='\t'))
    trc = {r['hex']: r for r in csv.DictReader(open(A.batch), delimiter='\t')}
    rch = {r['hex']: r for r in csv.DictReader(open(A.reach), delimiter='\t')}
    idr = read_idregs(A.idregs)

    fail = []
    check_locators(fail)

    rows = []
    tally = collections.Counter()
    for o in opc:
        h = o['hex']
        R = ref.get(h)
        if R is not None and R.get('status') == 'ok':
            continue
        T = trc.get(h)
        mn = (T['b_mnem'].split()[0] if T and T['b_mnem'] else o['mnemonic'])
        g = GATES.get(mn)
        e = rch.get(h)
        if g is None:
            fail.append('%s (%s): no feature gate named -- an unprobed row '
                        'with no gate is a REACHABLE-UNPROBED hole'
                        % (o['opcode_id'], mn))
            tally['NO-GATE'] += 1
            continue
        feat, reg, implemented = g
        if reg not in idr:
            fail.append('%s: %s absent from the ID dump' % (mn, reg))
            tally['NO-READING'] += 1
            continue
        val = idr[reg]
        if implemented(val):
            fail.append('%s (%s): %s reads %#x -- %s IS implemented, so the '
                        'encoding is REACHABLE and UNCOVERED'
                        % (o['opcode_id'], mn, reg, val, feat))
            tally['REACHABLE'] += 1
            continue
        if e is None:
            fail.append('%s: no reachability probe reading' % o['opcode_id'])
            tally['NO-PROBE'] += 1
            continue
        if e['exec'] != 'no' or e['signal'] != '4':
            fail.append('%s (%s): %s says the feature is absent but the '
                        'encoding executed (exec=%s signal=%s)'
                        % (o['opcode_id'], mn, reg, e['exec'], e['signal']))
            tally['RAN-ANYWAY'] += 1
            continue
        tally['UNREACHABLE'] += 1
        rows.append({'opcode_id': o['opcode_id'], 'mnemonic': mn, 'hex': h,
                     'mra_status': (R or {}).get('status', 'no-row'),
                     'feature': feat, 'gate_reg': reg,
                     'gate_value': '%#x' % val,
                     'const_zero_in_qemu': reg in CONST_ZERO,
                     'el0_signal': e['signal'], 'verdict': 'UNREACHABLE'})

    print('=' * 74)
    print('aarch64 MRA-UNPROBED rows -- reachability adjudication')
    print('=' * 74)
    for r, v in sorted(idr.items()):
        print('  %-20s %016x' % (r, v))
    print()
    byf = collections.Counter((r['feature'], r['gate_reg']) for r in rows)
    for (feat, reg), n in sorted(byf.items()):
        print('  %-14s gated by %-18s %3d rows  UNREACHABLE%s'
              % (feat, reg, n, '  (ARM_CP_CONST 0)' if reg in CONST_ZERO
                 else ''))
    print()
    for k, v in sorted(tally.items()):
        print('  %-14s %d' % (k, v))
    if A.out:
        with open(A.out, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()),
                               delimiter='\t')
            w.writeheader()
            w.writerows(rows)
        print('\n  per-row verdicts -> %s' % A.out)
    if fail:
        print('\nREFUSED:')
        for m in fail:
            print('  ' + m)
        return 1
    print('\nALL %d ROWS ADJUDICATED UNREACHABLE.  0 REACHABLE-UNPROBED.'
          % tally['UNREACHABLE'])
    return 0


if __name__ == '__main__':
    sys.exit(main())
