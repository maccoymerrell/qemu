#!/usr/bin/env python3
"""ARC 3 -- per-row adjudication of the DECODED-THEN-REFUSED encodings.

THE QUESTION THIS ANSWERS, and it is the maintainer's, verbatim: "these are
actually unreachable instructions, and not just instructions you need
privilege to execute right?  They are actually not supported by QEMU?"

The reachability legs already remove privilege: the encodings take #UD at
CPL 0 in long mode, so no ring can execute them.  They do NOT remove an
ENABLE: an instruction QEMU implemented behind CR4.VMXE, EFER.SVME, XCR0 or
an IA32_* enable MSR would fault at CPL 0 exactly the way an unimplemented
one does, and the vector cannot tell the two apart.  Two things separate
them, and both are needed:

  * sysprobe_enab_run.sh -- the same encodings at CPL 0 with every enable
    QEMU accepts SET AND PROVEN SET by reading the register back.
  * this file -- QEMU's own decode tables, read per encoding, so the refusal
    is attributed to a NAMED line of the tree rather than to a vector.

Every row lands in exactly one of:

  NOT-IMPLEMENTED    no decode path exists for the instruction.  The citation
                     is the absence: either the opcode slot the instruction
                     would occupy is not in the switch at all, or the slot
                     holds a DIFFERENT instruction whose mandatory prefix,
                     operand form or VEX class rejects these bytes.
  ENABLE-GATED-OFF   a decode path exists and is gated on an enable the probe
                     can set.  Such a row must be RE-PROBED with the enable
                     held, and if it then runs it is REACHABLE and the
                     verdict is UNCOVERED, not UNREACHABLE.
  REFUSED-BY-MODEL   QEMU refuses the ENABLE itself under every CPU model,
                     which is the strongest of the three: there is no
                     configuration in which the gate could open.

Every citation is a LOCATOR resolved against the tree on each run, never a
line number written down.  A locator that stops matching exits non-zero --
the same discipline as qemu_tcg_scope.py -- because a citation that has
quietly stopped being true is worse than no citation.

Author: Maccoy Merrell.
SPDX-License-Identifier: GPL-2.0-or-later
"""
import os
import re
import csv
import sys
import argparse

QEMU_ROOT = os.environ.get('CST_QEMU_ROOT', '/mnt/md0/QEMU/qemu')
_DECODE = 'target/i386/tcg/decode-new.c.inc'
_TRANSLATE = 'target/i386/tcg/translate.c'
_CPU_H = 'target/i386/cpu.h'

NOT_IMPL = 'NOT-IMPLEMENTED'
ENABLE_OFF = 'ENABLE-GATED-OFF'
REFUSED = 'REFUSED-BY-MODEL'

# --------------------------------------------------------------------------
# The refusal sites.  `locator` is matched against `file`; the citation is
# file:LINE where LINE is where it matched, computed on every run.
SITES = {
    'grp7-absent': dict(
        file=_TRANSLATE,
        locator=r'default:\n            goto illegal_op;\n        \}\n'
                r'        break;\n\n    case 0x11a:',
        what='the 0F 01 (group 7) switch has no case for this modrm byte, so '
             'it falls to the group default'),
    'grp7-rdpkru-prefix': dict(
        file=_TRANSLATE,
        locator=r'case 0xee: /\* rdpkru \*/',
        what='the 0F 01 EE/EF slot holds RDPKRU/WRPKRU, which refuse any '
             '66/F2/F3 prefix; the F3 form is not decoded as anything'),
    'grp6-absent': dict(
        file=_TRANSLATE,
        locator=r'default:\n            goto illegal_op;\n        \}\n'
                r'        break;\n\n    case 0x101:',
        what='the 0F 00 (group 6) switch stops at /5 (VERW); /6 falls to the '
             'group default'),
    'rdrand-prefix': dict(
        file=_TRANSLATE,
        locator=r'case 6: /\* RDRAND \*/',
        what='the 0F C7 /6 reg-form slot holds RDRAND, which refuses F3/F2'),
    'vaes-p66': dict(
        file=_DECODE,
        locator=r'\[0xdc\] = X86_OP_ENTRY3\(VAESENC,',
        what='0F 38 DC..DF is VAESENC/VAESDEC and is p_66; the F3 forms match '
             'no entry'),
    'mfence-p00': dict(
        file=_DECODE,
        locator=r'\[6\] = X86_OP_ENTRY0\(MFENCE,',
        what='0F AE /6 reg-form is MFENCE and is p_00; the 66 and F2 forms '
             'match no entry'),
    'rorx-pf2': dict(
        file=_DECODE,
        locator=r'\[0xF0\] = X86_OP_ENTRY3\(RORX,',
        what='0F 3A F0 is RORX, p_f2 and VEX-only; the legacy F3 form matches '
             'no entry'),
    'sha-novex': dict(
        file=_DECODE,
        locator=r'\[0xcb\] = X86_OP_ENTRY2\(SHA256RNDS2,',
        what='0F 38 CB..CD is the legacy SHA-NI trio with no VEX class, and a '
             'VEX prefix on a vex_class 0 entry is rejected'),
    'insertq-regform': dict(
        file=_DECODE,
        locator=r'\[0x79\] = X86_OP_GROUP2\(0F79,',
        what='0F 79 is the SSE4A EXTRQ/INSERTQ register form (operand U); a '
             'memory modrm matches no entry'),
    'prefetch-memonly': dict(
        file=_DECODE,
        locator=r'\[0x0d\] = X86_OP_ENTRY1\(NOP,',
        what='0F 0D is the 3DNow! prefetch and takes a MEMORY operand only; '
             'the register form matches no entry'),
    # supporting mechanism citations
    'sse-prefix-check': dict(
        file=_DECODE,
        locator=r'return e->valid_prefix & \(1 << sse_prefixes\);',
        what='mandatory-prefix mismatch fails decode_insn'),
    'vex-class0': dict(
        file=_DECODE,
        locator=r'    case 0:\n        if \(s->prefix & PREFIX_VEX\) \{\n'
                r'            goto illegal;',
        what='validate_vex refuses a VEX prefix on a legacy-only entry'),
    'modrm-mem-only': dict(
        file=_DECODE,
        locator=r'    case X86_TYPE_M:  /\* modrm byte selects a memory '
                r'operand \*/',
        what='a memory-only operand refuses mod==3'),
    'modrm-reg-only': dict(
        file=_DECODE,
        locator=r'    get_modrm_reg:',
        what='a register-only operand refuses mod!=3'),
    'feature-vocabulary': dict(
        file=_DECODE,
        locator=r'static bool has_cpuid_feature\(DisasContext \*s, '
                r'X86CPUIDFeature cpuid\)',
        what='the complete list of CPUID features any decode-table entry can '
             'be gated on'),
    'cr4-reserved': dict(
        file=_CPU_H,
        locator=r'#define CR4_RESERVED_MASK',
        what='the CR4 bits QEMU permits; every other bit #GPs on write under '
             'every CPU model'),
}

# encoding -> (mnemonic, verdict, refusal site, the enable that would have to
# open for the row to become reachable -- or None when QEMU has no such gate)
ROWS = [
    # ---- 0F 01 group 7, no case for this modrm ---------------------------
    ('0f01c1', 'VMCALL',      REFUSED,  'grp7-absent',        'CR4.VMXE'),
    ('0f01c2', 'VMLAUNCH',    REFUSED,  'grp7-absent',        'CR4.VMXE'),
    ('0f01c3', 'VMRESUME',    REFUSED,  'grp7-absent',        'CR4.VMXE'),
    ('0f01c4', 'VMXOFF',      REFUSED,  'grp7-absent',        'CR4.VMXE'),
    ('0f01c5', 'PCONFIG',     NOT_IMPL, 'grp7-absent',        None),
    ('0f01c6', 'WRMSRNS',     NOT_IMPL, 'grp7-absent',        None),
    ('f20f01c6', 'RDMSRLIST', NOT_IMPL, 'grp7-absent',        None),
    ('f30f01c6', 'WRMSRLIST', NOT_IMPL, 'grp7-absent',        None),
    ('0f01c7', 'PBNDKB',      NOT_IMPL, 'grp7-absent',        None),
    ('660f01cc', 'TDCALL',    NOT_IMPL, 'grp7-absent',        None),
    ('660f01cd', 'SEAMRET',   NOT_IMPL, 'grp7-absent',        None),
    ('660f01ce', 'SEAMOPS',   NOT_IMPL, 'grp7-absent',        None),
    ('660f01cf', 'SEAMCALL',  NOT_IMPL, 'grp7-absent',        None),
    ('0f01e8', 'SERIALIZE',   NOT_IMPL, 'grp7-absent',        None),
    ('f20f01e8', 'XSUSLDTRK', NOT_IMPL, 'grp7-absent',        None),
    ('f20f01e9', 'XRESLDTRK', NOT_IMPL, 'grp7-absent',        None),
    ('f30f01ec', 'UIRET',     REFUSED,  'grp7-absent',        'CR4.UINTR'),
    ('f30f01ed', 'TESTUI',    REFUSED,  'grp7-absent',        'CR4.UINTR'),
    ('f30f01fa', 'MCOMMIT',   NOT_IMPL, 'grp7-absent',        None),
    ('0f01fd', 'RDPRU',       NOT_IMPL, 'grp7-absent',        None),
    ('0f01fe', 'INVLPGB',     NOT_IMPL, 'grp7-absent',        None),
    ('f30f01fe', 'RMPADJUST', NOT_IMPL, 'grp7-absent',        None),
    ('f20f01fe', 'RMPUPDATE', NOT_IMPL, 'grp7-absent',        None),
    ('0f01ff', 'TLBSYNC',     NOT_IMPL, 'grp7-absent',        None),
    ('f30f01ff', 'PSMASH',    NOT_IMPL, 'grp7-absent',        None),
    ('f20f01ff', 'PVALIDATE', NOT_IMPL, 'grp7-absent',        None),
    # ---- 0F 01 EE/EF: the slot is RDPKRU/WRPKRU and refuses the prefix ----
    ('f30f01ee', 'CLUI',      REFUSED,  'grp7-rdpkru-prefix', 'CR4.UINTR'),
    ('f30f01ef', 'STUI',      REFUSED,  'grp7-rdpkru-prefix', 'CR4.UINTR'),
    # ---- 0F 38 DC..DF: the slot is VAESENC/VAESDEC and is p_66 -----------
    ('f30f38dc00', 'AESENC128KL', NOT_IMPL, 'vaes-p66',       None),
    ('f30f38dcc0', 'LOADIWKEY',   NOT_IMPL, 'vaes-p66',       None),
    ('f30f38dd00', 'AESDEC128KL', NOT_IMPL, 'vaes-p66',       None),
    ('f30f38de00', 'AESENC256KL', NOT_IMPL, 'vaes-p66',       None),
    ('f30f38df00', 'AESDEC256KL', NOT_IMPL, 'vaes-p66',       None),
    # ---- 0F AE /6: the slot is MFENCE and is p_00 ------------------------
    ('660faef0', 'TPAUSE',    NOT_IMPL, 'mfence-p00',         None),
    ('f20faef0', 'UMWAIT',    NOT_IMPL, 'mfence-p00',         None),
    # ---- 0F C7 /6 reg: the slot is RDRAND and refuses F3 -----------------
    ('f30fc7f0', 'SENDUIPI',  REFUSED,  'rdrand-prefix',      'CR4.UINTR'),
    # ---- 0F 79: SSE4A register form ---------------------------------------
    ('0f7900', 'VMWRITE',     REFUSED,  'insertq-regform',    'CR4.VMXE'),
    # ---- 0F 3A F0: RORX, p_f2 and VEX-only --------------------------------
    ('f30f3af0c000', 'HRESET', NOT_IMPL, 'rorx-pf2',          None),
    # ---- VEX.256.F2.0F38 CB..CD over the legacy SHA-NI trio ---------------
    ('c4e27fcbc0', 'VSHA512RNDS2', NOT_IMPL, 'sha-novex',     None),
    ('c4e27fccc0', 'VSHA512MSG1',  NOT_IMPL, 'sha-novex',     None),
    ('c4e27fcdc0', 'VSHA512MSG2',  NOT_IMPL, 'sha-novex',     None),
    # ---- 0F 00 group 6 stops at /5 ---------------------------------------
    ('f20f00f0', 'LKGS',      NOT_IMPL, 'grp6-absent',        None),
    ('f20f0030', 'LKGS',      NOT_IMPL, 'grp6-absent',        None),
    # ---- 0F 0D reg form ---------------------------------------------------
    ('0f0dc0', 'NOP',         NOT_IMPL, 'prefetch-memonly',   None),
]

# The extensions whose absence from has_cpuid_feature() is itself the proof
# that no decode-table entry could be gated on them.
EXTENSIONS = ('KEYLOCKER', 'UINTR', 'WAITPKG', 'SERIALIZE', 'SHA512', 'LKGS',
              'WRMSRNS', 'TSX_LDTRK', 'HRESET', 'PCONFIG', 'RDPRU', 'MSRLIST',
              'PBNDKB', 'SNP', 'TDX', 'VTX', 'INVLPGB', 'MCOMMIT', 'VMX',
              'SEAM')


def read(root, rel):
    p = os.path.join(root, rel)
    if not os.path.exists(p):
        sys.exit('%s: not in the QEMU tree at %s.  The adjudication is derived '
                 'from the tree and must not be guessed' % (rel, root))
    return open(p).read()


def resolve(root):
    """site -> 'file:line'.  A locator that no longer matches is fatal."""
    text, out, dead = {}, {}, []
    for name, d in SITES.items():
        if d['file'] not in text:
            text[d['file']] = read(root, d['file'])
        t = text[d['file']]
        ms = list(re.finditer(d['locator'], t))
        if len(ms) != 1:
            dead.append('%s: locator matched %d times in %s -- the citation '
                        'has stopped being true and must not be printed'
                        % (name, len(ms), d['file']))
            continue
        out[name] = '%s:%d' % (d['file'], t[:ms[0].start()].count('\n') + 1)
    if dead:
        sys.exit('ADJUDICATION REFUSED:\n  ' + '\n  '.join(dead))
    return out, text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default=QEMU_ROOT)
    ap.add_argument('--matrix', help='reach_matrix.tsv; the DECODED-THEN-'
                                     'REFUSED rows must match this table')
    ap.add_argument('--enables', help='enables.tsv from the enable-bit leg')
    ap.add_argument('--cpl0-enab', help='cpl0_enab.tsv from the enable leg')
    ap.add_argument('-o', help='write the adjudication here')
    a = ap.parse_args()

    cites, text = resolve(a.root)

    # ---- the feature vocabulary: no entry can be gated on what is not there
    body = text[_DECODE]
    i = body.index('static bool has_cpuid_feature(')
    vocab = set(re.findall(r'case (X86_FEAT_\w+):', body[i:i + 4000]))
    leaked = sorted(e for e in EXTENSIONS
                    if any(e in v for v in vocab))
    if leaked:
        sys.exit('%s now has a decode-time feature gate for %s: those rows '
                 'must be re-adjudicated as ENABLE-GATED-OFF rather than '
                 'reported as absent' % (_DECODE, ','.join(leaked)))

    # ---- "under EVERY CPU model" is DERIVED, not asserted -----------------
    # CR4_RESERVED_MASK is a compile-time constant naming the CR4 bits QEMU
    # permits, and cr4_reserved_bits() only ever ADDS to it per model.  A bit
    # missing from that list therefore #GPs on write under every model there
    # is, which is what makes REFUSED-BY-MODEL a statement about QEMU rather
    # than about the one model the probe happened to run.
    cpu_h = text[_CPU_H]
    i = cpu_h.index('#define CR4_RESERVED_MASK')
    permitted = set(re.findall(r'CR4_\w+_MASK', cpu_h[i:cpu_h.index(')))', i)]))
    for bit in ('CR4_VMXE_MASK', 'CR4_SMXE_MASK'):
        if bit in permitted:
            sys.exit('%s now permits %s: the VMX rows are no longer '
                     'REFUSED-BY-MODEL and must be re-probed with it set'
                     % (_CPU_H, bit))
    for bit in ('CR4_CET_MASK', 'CR4_UINTR_MASK'):
        if re.search(r'#define\s+%s\b' % bit, cpu_h):
            sys.exit('%s now defines %s: QEMU has gained the enable and those '
                     'rows must be re-probed with it set' % (_CPU_H, bit))

    # ---- the row set must be exactly the matrix's DECODED-THEN-REFUSED set
    if a.matrix:
        with open(a.matrix) as f:
            want = set(r['probe_hex'] for r in csv.DictReader(f, delimiter='\t')
                       if r['qemu_refusal'] == 'DECODED-THEN-REFUSED')
        have = set(h for h, _, _, _, _ in ROWS)
        if want != have:
            sys.exit('the adjudicated set and the matrix disagree.\n'
                     '  in the matrix, not adjudicated: %s\n'
                     '  adjudicated, not in the matrix: %s'
                     % (' '.join(sorted(want - have)) or '-',
                        ' '.join(sorted(have - want)) or '-'))

    held, refused = {}, {}
    if a.enables:
        with open(a.enables) as f:
            for r in csv.DictReader(f, delimiter='\t'):
                (held if r['held'] == '1' else refused)[r['enable']] = r
    vec = {}
    if a.cpl0_enab:
        with open(a.cpl0_enab) as f:
            for r in csv.DictReader(f, delimiter='\t'):
                vec[r['hex']] = int(r['cpl0_enab_vec'])

    flips, out = [], []
    for h, mn, verdict, site, gate in ROWS:
        v = vec.get(h)
        if v == 255:
            flips.append((h, mn))
        # A REFUSED-BY-MODEL claim is only true while QEMU really refuses the
        # enable; if the leg reports it held, the claim is retracted here
        # rather than reprinted.
        if verdict == REFUSED and gate and gate in held:
            sys.exit('%s (%s) is filed REFUSED-BY-MODEL on %s, and the enable '
                     'leg HELD %s.  The row must be re-probed with it set, '
                     'not reported' % (mn, h, gate, gate))
        out.append((h, mn, verdict, gate or '-', cites[site],
                    SITES[site]['what'],
                    'ran' if v == 255 else ('#UD' if v == 6 else
                                            ('vec=%s' % v if v is not None
                                             else 'NOT-MEASURED'))))

    hdr = ('probe_hex', 'mnemonic', 'adjudication', 'gating_enable',
           'qemu_citation', 'why', 'cpl0_with_enables')
    body_out = '\t'.join(hdr) + '\n' + ''.join(
        '\t'.join(r) + '\n' for r in out)
    if a.o:
        open(a.o, 'w').write(body_out)
    sys.stdout.write(body_out)

    for name in ('feature-vocabulary', 'cr4-reserved'):
        print('# %s -> %s' % (name, cites[name]), file=sys.stderr)
    print('# decode-time CPUID vocabulary: %d features, none of %s'
          % (len(vocab), ','.join(EXTENSIONS)), file=sys.stderr)
    if refused:
        print('# enables QEMU REFUSED: %s'
              % ' '.join('%s(vec=%s)' % (k, v['vector'])
                         for k, v in refused.items()), file=sys.stderr)
    if flips:
        sys.exit('REACHABLE WITH ENABLES SET -- the UNREACHABLE claim is '
                 'FALSE for: %s' % ' '.join('%s(%s)' % (m, h)
                                            for h, m in flips))
    return 0


if __name__ == '__main__':
    sys.exit(main())
