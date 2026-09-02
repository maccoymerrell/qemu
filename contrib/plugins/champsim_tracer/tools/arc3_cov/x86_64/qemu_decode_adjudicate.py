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

AND EVERY ROW IS KEYED ON THE OPCODE IDENTITY, never on the probe encoding.
The claim a row makes is about an INSTRUCTION -- QEMU has no decode path for
it, or has one behind an enable -- so a probe re-seated for a reason that has
nothing to do with decode must not be able to move a row.  Under the old key
it could and did: HRESET's row followed its probe from `f30f3af0c0` to
`f30f3af0c001` when mkprobe.py moved the immediate off zero.  The encoding is
still reported, resolved from the matrix on every run, and `--selftest`
measures the indifference rather than asserting it.

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

# THE KEY IS THE OPCODE IDENTITY, NOT THE PROBE ENCODING.
#
# It was the probe's byte string until now, and that coupled every row of
# this table to mkprobe.py's seating rules: a probe re-seated for a reason
# that has nothing to do with decode -- an EVEX mask operand moved off
# `aaa=000`, an immediate moved off zero -- moved its row's key, and the row
# either had to be edited to follow or fell out of the matrix cross-check.
# The HRESET row carried a written note about exactly that, because
# `f30f3af0c0` had become `f30f3af0c001` underneath it.
#
# `opcode_id` is the XED iform the matrix is built on.  It names the
# INSTRUCTION, which is what this table adjudicates: whether QEMU has a
# decode path for it, and if not, which line of the tree says so.  Nothing
# here is a claim about one byte string, so nothing here should move when a
# byte string does.  The probe encoding is still REPORTED -- it is resolved
# from the matrix on every run, and two re-seats landing in this pass
# (riscv64's RVV `vm` bit, aarch64's MOVPRFX `M` bit) are the occasion this
# coupling would otherwise have cost something on.
#
# opcode_id -> (mnemonic, verdict, refusal site, the enable that would have to
# open for the row to become reachable -- or None when QEMU has no such gate)
ROWS = [
    # ---- 0F 01 group 7, no case for this modrm ---------------------------
    ('XED_IFORM_VMCALL',
     'VMCALL', REFUSED, 'grp7-absent', 'CR4.VMXE'),
    ('XED_IFORM_VMLAUNCH',
     'VMLAUNCH', REFUSED, 'grp7-absent', 'CR4.VMXE'),
    ('XED_IFORM_VMRESUME',
     'VMRESUME', REFUSED, 'grp7-absent', 'CR4.VMXE'),
    ('XED_IFORM_VMXOFF',
     'VMXOFF', REFUSED, 'grp7-absent', 'CR4.VMXE'),
    ('XED_IFORM_PCONFIG64',
     'PCONFIG', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_WRMSRNS',
     'WRMSRNS', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_RDMSRLIST',
     'RDMSRLIST', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_WRMSRLIST',
     'WRMSRLIST', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_PBNDKB',
     'PBNDKB', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_TDCALL',
     'TDCALL', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_SEAMRET',
     'SEAMRET', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_SEAMOPS',
     'SEAMOPS', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_SEAMCALL',
     'SEAMCALL', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_SERIALIZE',
     'SERIALIZE', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_XSUSLDTRK',
     'XSUSLDTRK', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_XRESLDTRK',
     'XRESLDTRK', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_UIRET',
     'UIRET', REFUSED, 'grp7-absent', 'CR4.UINTR'),
    ('XED_IFORM_TESTUI',
     'TESTUI', REFUSED, 'grp7-absent', 'CR4.UINTR'),
    ('XED_IFORM_MCOMMIT',
     'MCOMMIT', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_RDPRU',
     'RDPRU', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_INVLPGB',
     'INVLPGB', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_RMPADJUST_RAX_RCX_RDX',
     'RMPADJUST', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_RMPUPDATE_RAX_RCX',
     'RMPUPDATE', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_TLBSYNC',
     'TLBSYNC', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_PSMASH_RAX',
     'PSMASH', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_PVALIDATE_RAX_ECX_EDX',
     'PVALIDATE', NOT_IMPL, 'grp7-absent', None),
    # ---- 0F 01 EE/EF: the slot is RDPKRU/WRPKRU and refuses the prefix ----
    ('XED_IFORM_CLUI',
     'CLUI', REFUSED, 'grp7-rdpkru-prefix', 'CR4.UINTR'),
    ('XED_IFORM_STUI',
     'STUI', REFUSED, 'grp7-rdpkru-prefix', 'CR4.UINTR'),
    # ---- 0F 38 DC..DF: the slot is VAESENC/VAESDEC and is p_66 -----------
    ('XED_IFORM_AESENC128KL_XMMu8_MEMu8',
     'AESENC128KL', NOT_IMPL, 'vaes-p66', None),
    ('XED_IFORM_LOADIWKEY_XMMu8_XMMu8',
     'LOADIWKEY', NOT_IMPL, 'vaes-p66', None),
    ('XED_IFORM_AESDEC128KL_XMMu8_MEMu8',
     'AESDEC128KL', NOT_IMPL, 'vaes-p66', None),
    ('XED_IFORM_AESENC256KL_XMMu8_MEMu8',
     'AESENC256KL', NOT_IMPL, 'vaes-p66', None),
    ('XED_IFORM_AESDEC256KL_XMMu8_MEMu8',
     'AESDEC256KL', NOT_IMPL, 'vaes-p66', None),
    # ---- 0F AE /6: the slot is MFENCE and is p_00 ------------------------
    ('XED_IFORM_TPAUSE_GPR32u32',
     'TPAUSE', NOT_IMPL, 'mfence-p00', None),
    ('XED_IFORM_UMWAIT_GPR32',
     'UMWAIT', NOT_IMPL, 'mfence-p00', None),
    # ---- 0F C7 /6 reg: the slot is RDRAND and refuses F3 -----------------
    ('XED_IFORM_SENDUIPI_GPR64u32',
     'SENDUIPI', REFUSED, 'rdrand-prefix', 'CR4.UINTR'),
    # ---- 0F 79: SSE4A register form ---------------------------------------
    ('XED_IFORM_VMWRITE_GPR64_MEMq',
     'VMWRITE', REFUSED, 'insertq-regform', 'CR4.VMXE'),
    # ---- 0F 3A F0: RORX, p_f2 and VEX-only --------------------------------
    # THE ROW THAT PAID FOR THE OLD KEY, kept as the worked example.  HRESET
    # is `F3 0F 3A F0 /0 ib`, so its probe carries an imm8, and mkprobe.py
    # re-seats a probe whose only immediate is zero to 1 (a zero shift count
    # is the value at which the shift family's flag write does not happen --
    # see that file).  Keyed on the probe encoding, this row followed that
    # re-seat from `f30f3af0c0` to `f30f3af0c001` for a reason that has
    # nothing to do with its adjudication: `rorx-pf2` is about the 0F3AF0
    # slot holding RORX and being VEX-only, which no immediate value can
    # change.  Keyed on the iform it does not move at all.
    ('XED_IFORM_HRESET_IMM8',
     'HRESET', NOT_IMPL, 'rorx-pf2', None),
    # ---- VEX.256.F2.0F38 CB..CD over the legacy SHA-NI trio ---------------
    ('XED_IFORM_VSHA512RNDS2_YMMu64_YMMu64_XMMu64',
     'VSHA512RNDS2', NOT_IMPL, 'sha-novex', None),
    ('XED_IFORM_VSHA512MSG1_YMMu64_XMMu64',
     'VSHA512MSG1', NOT_IMPL, 'sha-novex', None),
    ('XED_IFORM_VSHA512MSG2_YMMu64_YMMu64',
     'VSHA512MSG2', NOT_IMPL, 'sha-novex', None),
    # ---- 0F 00 group 6 stops at /5 ---------------------------------------
    ('XED_IFORM_LKGS_GPR16u16',
     'LKGS', NOT_IMPL, 'grp6-absent', None),
    ('XED_IFORM_LKGS_MEMu16',
     'LKGS', NOT_IMPL, 'grp6-absent', None),
    # ---- 0F 0D reg form ---------------------------------------------------
    ('XED_IFORM_NOP_GPRv_GPRv_0F0D',
     'NOP', NOT_IMPL, 'prefetch-memonly', None),
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


def _selftest(root):
    """Four arms, and the first one is the reason the key changed.

    A table that joins on the opcode identity must be INDIFFERENT to the
    probe encoding.  That is not provable by inspection -- the old table
    also looked indifferent, and it was not -- so it is measured: the same
    matrix is offered twice, once as captured and once with EVERY probe
    encoding rewritten, and the adjudication must be identical except for
    the column that reports the encoding.
    """
    import io
    import subprocess
    import tempfile

    hdr = ('opcode_id\tmnemonic\tisa_set\textension\tprobe_hex\t'
           'qemu_refusal\n')
    rows = [(i, mn) for i, mn, _, _, _ in ROWS]

    def matrix(mut=None, drop=None, dup=None):
        out = io.StringIO()
        out.write(hdr)
        for i, mn in rows:
            if drop and i == drop:
                continue
            h = 'deadbeef' if mut else ('%08x' % (abs(hash(i)) & 0xffffffff))
            out.write('%s\t%s\t-\t-\t%s\tDECODED-THEN-REFUSED\n'
                      % (i, mn, mut(i) if mut else h))
            if dup and i == dup:
                out.write('%s\t%s\t-\t-\tcafe\tDECODED-THEN-REFUSED\n'
                          % (i, mn))
        return out.getvalue()

    def run(text, extra=()):
        with tempfile.NamedTemporaryFile('w', suffix='.tsv',
                                         delete=False) as f:
            f.write(text)
            path = f.name
        cmd = [sys.executable, os.path.abspath(__file__), '--root', root,
               '--matrix', path] + list(extra)
        r = subprocess.run(cmd, capture_output=True, text=True)
        os.unlink(path)
        return r

    fails = 0

    def t(name, cond):
        nonlocal fails
        print('%-4s %s' % ('ok' if cond else 'FAIL', name))
        if not cond:
            fails += 1

    a = run(matrix(mut=lambda i: 'aa%06x' % (abs(hash(i)) & 0xffffff)))
    b = run(matrix(mut=lambda i: 'bb%06x' % (abs(hash(i)) & 0xffffff)))
    t('A both probe seatings adjudicate', a.returncode == 0 and
      b.returncode == 0)
    stripa = [l.split('\t')[:1] + l.split('\t')[2:]
              for l in a.stdout.splitlines()]
    stripb = [l.split('\t')[:1] + l.split('\t')[2:]
              for l in b.stdout.splitlines()]
    t('B a probe RE-SEAT moves nothing but the reported encoding',
      stripa == stripb and len(stripa) == len(ROWS) + 1)
    t('C ... and the reported encoding DID move (the arm is not vacuous)',
      a.stdout != b.stdout)
    d = run(matrix(drop=ROWS[0][0]))
    t('D an iform missing from the matrix REFUSES', d.returncode != 0 and
      'disagree' in d.stderr)
    u = run(matrix(dup=ROWS[0][0]))
    t('E an iform named twice REFUSES rather than joining on one of them',
      u.returncode != 0 and 'not a key' in u.stderr)
    with tempfile.NamedTemporaryFile('w', suffix='.tsv', delete=False) as f:
        f.write('hex\tcpl0_enab_vec\n')
        enab = f.name
    r = subprocess.run([sys.executable, os.path.abspath(__file__),
                        '--root', root, '--cpl0-enab', enab],
                       capture_output=True, text=True)
    os.unlink(enab)
    t('F --cpl0-enab without --matrix REFUSES (nothing maps iform -> hex)',
      r.returncode != 0 and 'needs --matrix' in r.stderr)
    print('arms=6 failures=%d' % fails)
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default=QEMU_ROOT)
    ap.add_argument('--selftest', action='store_true',
                    help='prove the table is indifferent to a probe re-seat')
    ap.add_argument('--matrix', help='reach_matrix.tsv; the DECODED-THEN-'
                                     'REFUSED rows must match this table on '
                                     'opcode_id, which is also where each '
                                     "row's probe encoding is resolved from")
    ap.add_argument('--enables', help='enables.tsv from the enable-bit leg')
    ap.add_argument('--cpl0-enab', help='cpl0_enab.tsv from the enable leg')
    ap.add_argument('-o', help='write the adjudication here')
    a = ap.parse_args()

    if a.selftest:
        return _selftest(a.root)

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

    # ---- the row set must be exactly the matrix's DECODED-THEN-REFUSED set,
    # ---- and the matrix is also where each row's PROBE ENCODING comes from.
    #
    # The encoding is DERIVED here rather than written down, which is the
    # whole point of the re-key: a probe re-seat changes what this column
    # prints and changes nothing this table says.  A row whose iform the
    # matrix does not carry has no encoding to print, and printing '-' for it
    # would be a citation that stopped being true -- so the set comparison
    # below refuses first.
    hex_of = {}
    if a.matrix:
        with open(a.matrix) as f:
            rows = [r for r in csv.DictReader(f, delimiter='\t')
                    if r['qemu_refusal'] == 'DECODED-THEN-REFUSED']
        want = set(r['opcode_id'] for r in rows)
        for r in rows:
            hex_of[r['opcode_id']] = r['probe_hex']
        have = set(i for i, _, _, _, _ in ROWS)
        if want != have:
            sys.exit('the adjudicated set and the matrix disagree.\n'
                     '  in the matrix, not adjudicated: %s\n'
                     '  adjudicated, not in the matrix: %s'
                     % (' '.join(sorted(want - have)) or '-',
                        ' '.join(sorted(have - want)) or '-'))
        if len(want) != len(rows):
            sys.exit('the matrix names an opcode_id twice among its '
                     'DECODED-THEN-REFUSED rows; the iform is not a key '
                     'there and this table cannot be joined on it')
    elif a.cpl0_enab:
        # The enable-leg vector is keyed on the probe encoding, and without
        # the matrix there is nothing to resolve an iform to one.  A lookup
        # that silently found nothing would print NOT-MEASURED for every row
        # of a leg that ran, so it refuses instead.
        sys.exit('--cpl0-enab needs --matrix: the enable leg is keyed on the '
                 'probe encoding and the matrix is what maps an opcode '
                 'identity to it')

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
    for opid, mn, verdict, site, gate in ROWS:
        h = hex_of.get(opid, '-')
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
        out.append((opid, h, mn, verdict, gate or '-', cites[site],
                    SITES[site]['what'],
                    'ran' if v == 255 else ('#UD' if v == 6 else
                                            ('vec=%s' % v if v is not None
                                             else 'NOT-MEASURED'))))

    hdr = ('opcode_id', 'probe_hex', 'mnemonic', 'adjudication',
           'gating_enable', 'qemu_citation', 'why', 'cpl0_with_enables')
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
