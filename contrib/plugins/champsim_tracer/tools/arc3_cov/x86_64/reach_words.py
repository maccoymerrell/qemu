#!/usr/bin/env python3
"""
ARC 3 -- the reachability class words the x86_64 leg publishes TWICE, and the
measurements behind them.

The leg writes two tables in one run.  qemu_reach_matrix.py publishes the
three-valued verdict per encoding; qemu_decode_adjudicate.py publishes, for
the rows the matrix labels DECODED-THEN-REFUSED, which line of QEMU refused
them and under what class.  Two tables, one run, one subject -- and until
FINDING 254-D they could disagree about it, because each reached for the
evidence on its own and only one of them reached for the vendor arm.  They
did: SYSENTER and SYSEXIT were adjudicated REACHABLE-INTEL-VENDOR while the
matrix published UNREACHABLE for the same two encodings.

So the words live here, spelled once, and the two facts that decide them are
read through here as well:

  * THE VENDOR ARM is a MEASUREMENT -- sysprobe_vendor.sh runs the encodings
    decode-new.c.inc gates on chk(i64_amd) under `-cpu max` (whose vendor
    QEMU sets to AMD) and under `-cpu max,vendor=GenuineIntel`.  read_vendor()
    applies the guards that make the file evidence rather than a file.

  * THE STATE GATE is read out of the TREE -- state_gated_smm() derives the
    encodings whose decode entry carries chk(smm) instead of naming them.  A
    machine state no probe boot in this corpus enters is not a property of
    the encoding, so the row says which state, and the leg that would reach it
    is named work rather than a silence.

Author: Maccoy Merrell.
SPDX-License-Identifier: GPL-2.0-or-later
"""
import re
import csv
import sys

#: The row is REACHABLE IN QEMU and the #UD every other leg reports comes from
#: the model's VENDOR, not from QEMU's decoder.  Measured, never asserted.
REACHABLE_INTEL_VENDOR = 'REACHABLE-INTEL-VENDOR'

#: The row is implemented in QEMU and its decode entry is gated on a MACHINE
#: STATE no probe in this corpus enters.  The refusal measures the corpus's
#: probes, so the state is named on the row and the probe that would reach it
#: is filed work -- TASK_LEDGER row 486, the ARC 4 SMM-entering CPL0 leg.
#:
#: It replaced PROBE-HOLE(SMM), which said the same thing in a spelling only
#: one of the two tables used.  The verdict it carries is the one the D17
#: trap-state precedent gives an encoding gated by state the corpus does not
#: enter: the matrix publishes UNREACHABLE, because nothing measured reached
#: it, and the row carries the state and the work that would.
REFUSED_BY_STATE_SMM = 'REFUSED-BY-STATE(SMM)'

_VENDOR_COLS = ('hex', 'vec_amd', 'vec_intel', 'role', 'moved')


def read_vendor(path, who):
    """cpl0_vendor.tsv -> (moved, steady), with the arm's own guards applied.

    `moved` is {hex: row} for the SUBJECT encodings whose exception vector
    changes when the model's vendor does; `steady` is {hex: row} for the
    CONTROLs that did not.  `who` names the caller in every refusal, because
    a refusal that does not say which table stopped is a refusal nobody can
    act on.

    THE GUARDS ARE THE ARM'S, NOT THE CALLER'S TASTE, and they are here so
    that two consumers cannot come to apply different ones.  An arm with no
    subject measured nothing about the vendor gate; an arm in which no subject
    moved is INERT and its zero proves nothing; an arm whose CONTROL moved
    says the two boots differ for some reason other than the vendor, so
    nothing in it attributes a subject's movement to the vendor at all.
    """
    try:
        with open(path) as f:
            rows = list(csv.DictReader(f, delimiter='\t'))
    except IOError as e:
        sys.exit('%s: the vendor arm (%s) cannot be read (%s).  The class '
                 'word %s is a MEASUREMENT and will not be asserted without '
                 'it' % (who, path, e, REACHABLE_INTEL_VENDOR))
    if not rows:
        sys.exit('%s: the vendor arm (%s) is empty -- a clean read over no '
                 'rows is not a measurement' % (who, path))
    for c in _VENDOR_COLS:
        if c not in rows[0]:
            sys.exit('%s: the vendor arm (%s) has no %r column; this is not '
                     'the table sysprobe_vendor.sh writes' % (who, path, c))

    bad, moved, steady, subjects = [], {}, {}, []
    for r in rows:
        if r['role'] == 'SUBJECT':
            subjects.append(r['hex'])
            if r['moved'] == '1':
                moved[r['hex']] = r
                if r['vec_amd'] != '6':
                    bad.append('subject %s moved but its AMD-vendor vector is '
                               '%s, not the #UD a vendor test produces'
                               % (r['hex'], r['vec_amd']))
        elif r['role'] == 'CONTROL':
            steady[r['hex']] = r
            if r['moved'] == '1':
                bad.append('CONTROL %s MOVED (amd=%s intel=%s): the two arms '
                           'differ for some reason other than the vendor, so '
                           'nothing here attributes a subject\'s movement to '
                           'it' % (r['hex'], r['vec_amd'], r['vec_intel']))
        else:
            bad.append('%s carries role %r, which is neither SUBJECT nor '
                       'CONTROL' % (r['hex'], r['role']))
    if not subjects:
        bad.append('the arm has NO SUBJECT: it exists to measure exactly the '
                   'chk(i64_amd) entries and a run over none of them measures '
                   'nothing')
    elif not moved:
        bad.append('NO SUBJECT MOVED: every vendor-gated row reads the same '
                   'vector under both vendors, so this arm is INERT and its '
                   'zero proves nothing about the vendor gate')
    if not steady:
        bad.append('the arm carries no CONTROL row: an arm with no control '
                   'cannot say the movement is the vendor\'s')
    if bad:
        sys.exit('%s: the vendor arm (%s) REFUSED:\n  %s'
                 % (who, path, '\n  '.join(bad)))
    return moved, steady


def _op_table(src, decl, who):
    try:
        i = src.index('static const X86OpEntry %s = {' % decl)
        return src[i:src.index('\n};', i)]
    except ValueError:
        sys.exit('%s: target/i386/tcg/decode-new.c.inc has no %s table any '
                 'more; the state-gate derivation reads it and must not be '
                 'guessed' % (who, decl))


def state_gated_smm(decode_src, who):
    """-> {probe hex: REFUSED_BY_STATE_SMM} for every chk(smm) decode entry.

    DERIVED FROM THE TREE, NEVER WRITTEN DOWN, for the reason
    sysprobe_vendor.sh derives its subjects the same way: a hand-kept list
    goes on naming an encoding after QEMU stops gating it, and the row it
    labels then carries a reason that is no longer true.  An empty derivation
    is fatal -- the word exists to name exactly these rows, and a run that
    labels none of them while the adjudication still files one is the
    contradiction this module was written to end.
    """
    out = {}
    for decl, prefix in (('opcodes_root[256]', ''), ('opcodes_0F[256]', '0f')):
        for m in re.finditer(r'^\s*\[(0x[0-9a-fA-F]+)\]\s*=\s*([^\n]*)$',
                             _op_table(decode_src, decl, who), re.M):
            if re.search(r'\bchk[0-9]?\([^)]*\bsmm\b', m.group(2)):
                out[prefix + '%02x' % int(m.group(1), 16)] = \
                    REFUSED_BY_STATE_SMM
    if not out:
        sys.exit('%s: no decode-new.c.inc entry carries chk(smm) any more, so '
                 '%s has lost its subject.  The class is derived from the '
                 'tree; a run that can label nothing must say so rather than '
                 'publish a table with the word missing'
                 % (who, REFUSED_BY_STATE_SMM))
    return out
