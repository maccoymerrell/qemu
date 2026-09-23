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

  NOT-IMPLEMENTED    QEMU does not implement the instruction, and the citation
                     is where it says so.  Usually that is an ABSENCE: the
                     opcode slot the instruction would occupy is not in the
                     switch at all, or the slot holds a DIFFERENT instruction
                     whose mandatory prefix, operand form or VEX class rejects
                     these bytes.  It can also be a STATEMENT: a slot the
                     decoder does reach whose emitter's whole effect is the
                     invalid-opcode fault, which is QEMU saying in code that
                     it has not implemented the instruction (SKINIT's
                     "not implemented -- raise #UD", helper_vmmcall's
                     raise_exception(EXCP06_ILLOP)).  Both are the same
                     answer to the maintainer's question and both cite a line.
  ENABLE-GATED-OFF   a decode path exists and is gated on an enable the probe
                     can set.  Such a row must be RE-PROBED with the enable
                     held, and if it then runs it is REACHABLE and the
                     verdict is UNCOVERED, not UNREACHABLE.
  REFUSED-BY-MODEL   QEMU refuses the ENABLE itself under every CPU model,
                     which is the strongest of the three: there is no
                     configuration in which the gate could open.

A row that none of the three describes HONESTLY is not given one anyway.  It
goes in REMAINDER below, which names it, cites it, and states the question a
maintainer has to answer before it can be adjudicated.  The set comparison
counts REMAINDER, so such a row is visible and bounded rather than missing --
but the table never prints a verdict it cannot support.

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
import collections

QEMU_ROOT = os.environ.get('CST_QEMU_ROOT', '/mnt/md0/QEMU/qemu')
_DECODE = 'target/i386/tcg/decode-new.c.inc'
_TRANSLATE = 'target/i386/tcg/translate.c'
_CPU_H = 'target/i386/cpu.h'
_CPU_C = 'target/i386/cpu.c'
_SVM = 'target/i386/tcg/system/svm_helper.c'

NOT_IMPL = 'NOT-IMPLEMENTED'
ENABLE_OFF = 'ENABLE-GATED-OFF'
REFUSED = 'REFUSED-BY-MODEL'
UNADJ = 'UNADJUDICATED-REMAINDER'

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
    'ud-entry': dict(
        file=_DECODE,
        locator=r'\[0x0b\] = X86_OP_ENTRY0\(UD\)',
        what='UD0, UD1 and UD2 have decode-table entries whose emitter is '
             'gen_UD() = gen_illegal_opcode(): QEMU decodes the bytes and the '
             'machine takes the invalid-opcode fault the ISA defines for '
             'them, so no instruction executes'),
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
        # THIS LOCATOR WAS STALE AND THE REFUSAL CAUGHT IT.  9a3607dcf6 (our
        # own, the x86 decoder-site statements) turned the table entry from
        # `X86_OP_ENTRY1(NOP, M,v)' into `X86_OP_GROUP1(0F0D, M,v)' so the
        # group function could set INSN_DF_WORD_PREFETCH for /0 /1 /2.  The
        # FACT did not move: the operand spec is still `M,v', and the entry
        # decode_0F0D() hands back is `X86_OP_ENTRY1(NOP, M,v)' -- memory
        # only, both before the group and inside it.  Only the line changed,
        # so only the line changes here.  (The refusal had never been SEEN
        # because the leg exited at its NOT-MEASURED assertion first; closing
        # that assertion is what reached this one.)
        locator=r'\[0x0d\] = X86_OP_GROUP1\(0F0D, M,v\)',
        what='0F 0D is the 3DNow! prefetch and takes a MEMORY operand only '
             '-- decode_0F0D() returns X86_OP_ENTRY1(NOP, M,v) for every '
             'modrm.reg -- so the register form matches no entry'),
    'cmovcc-slot': dict(
        file=_DECODE,
        locator=r'\[0x41\] = X86_OP_ENTRY2\(CMOVcc,',
        what='0F 41..4B is the CMOVcc block, a legacy entry with no VEX '
             'class, so validate_vex refuses the VEX prefix the AVX-512 '
             'mask-register opcodes carry; QEMU has no mask registers and no '
             'entry that could hold them'),
    'setcc-slot': dict(
        file=_DECODE,
        locator=r'\[0x90\] = X86_OP_ENTRYw\(SETcc, E,b\)',
        what='0F 90..99 is the SETcc block, a legacy entry with no VEX '
             'class, so validate_vex refuses the VEX prefix the AVX-512 '
             'KMOV/KORTEST/KTEST opcodes carry'),
    'lfence-p00': dict(
        file=_DECODE,
        locator=r'\[5\] = X86_OP_ENTRY0\(LFENCE,',
        what='0F AE /5 reg-form is LFENCE and is p_00; the F3 form matches '
             'no entry'),
    'xsave-p00': dict(
        file=_DECODE,
        locator=r'\[4\] = X86_OP_ENTRYw\(XSAVE,',
        what='0F AE /4 mem-form is XSAVE and is p_00; the F3 form matches no '
             'entry'),
    'xsaveopt-p00': dict(
        file=_DECODE,
        locator=r'\[6\] = X86_OP_ENTRYw\(XSAVEOPT,',
        what='0F AE /6 mem-form is XSAVEOPT and is p_00; the F3 form matches '
             'no entry'),
    'svm-skinit-ud': dict(
        file=_TRANSLATE,
        locator=r'/\* If not intercepted, not implemented -- raise #UD\. \*/'
                r'\n            goto illegal_op;',
        what='0F 01 DE is decoded as SKINIT and QEMU states in this line '
             'that it does not implement it: the case falls straight to '
             'illegal_op whatever the SVM state'),
    'svm-vmmcall-ud': dict(
        file=_SVM,
        locator=r'void helper_vmmcall\(CPUX86State \*env\)\n\{\n'
                r'    cpu_svm_check_intercept_param\(env, SVM_EXIT_VMMCALL, '
                r'0, GETPC\(\)\);\n    raise_exception\(env, EXCP06_ILLOP\);',
        what='0F 01 D9 is decoded as VMMCALL and emitted; the helper it '
             'emits raises #UD unconditionally once the intercept check is '
             'past, so QEMU enters the instruction and then states that it '
             'has none to run.  The EFER.SVME gate in translate.c is not '
             'what refuses it -- the enable leg HOLDS EFER.SVME and the '
             'CPL0+enables probe still reads #UD'),
    'pclmulqdq-128only': dict(
        file=_DECODE,
        locator=r'\[0x44\] = X86_OP_ENTRY4\(PCLMULQDQ,  V,dq, H,dq, W,dq,',
        what='0F 3A 44 is PCLMULQDQ with every operand fixed at dq '
             '(128-bit); a dq operand under VEX.L=1 fails decode_op_size, so '
             'the 256-bit VPCLMULQDQ form matches no entry'),
    # ---- the REMAINDER's sites: cited, not adjudicated --------------------
    'sysenter-entry': dict(
        file=_DECODE,
        locator=r'\[0x34\] = X86_OP_ENTRY0\(SYSENTER,',
        what='0F 34 HAS a decode-table entry and a real emitter '
             '(gen_SYSENTER -> helper_sysenter); in 64-bit mode it is refused '
             'by chk(i64_amd), which is a CPU-VENDOR test, not an absence'),
    'sysexit-entry': dict(
        file=_DECODE,
        locator=r'\[0x35\] = X86_OP_ENTRY0\(SYSEXIT,',
        what='0F 35 HAS a decode-table entry and a real emitter '
             '(gen_SYSEXIT -> helper_sysexit); in 64-bit mode it is refused '
             'by chk(i64_amd), which is a CPU-VENDOR test, not an absence'),
    'rsm-entry': dict(
        file=_DECODE,
        locator=r'\[0xaa\] = X86_OP_ENTRY0\(RSM,',
        what='0F AA HAS a decode-table entry and a real emitter '
             '(gen_RSM -> helper_rsm); it is refused by chk(smm), which asks '
             'whether the machine is in SMM, not whether QEMU implements it'),
    # supporting mechanism citations
    'i64-amd-check': dict(
        file=_DECODE,
        locator=r'if \(\(decode\.e\.check & X86_CHECK_i64_amd\) && '
                r'env->cpuid_vendor1 != CPUID_VENDOR_INTEL_1\)',
        what='in 64-bit mode an i64_amd entry is refused on any non-Intel '
             'vendor'),
    'max-vendor-is-amd': dict(
        file=_CPU_C,
        locator=r'object_property_set_str\(OBJECT\(cpu\), "vendor", '
                r'CPUID_VENDOR_AMD,',
        what='the `max` CPU model -- the one every reachability leg in this '
             'corpus runs -- sets its vendor to AMD, so every i64_amd entry '
             'is refused in 64-bit mode under the model the legs measured'),
    'smm-check': dict(
        file=_DECODE,
        locator=r'if \(\(decode\.e\.check & X86_CHECK_smm\) && '
                r'!\(s->flags & HF_SMM_MASK\)\)',
        what='an smm entry is refused outside system-management mode'),
    'dq-refuses-vex-l': dict(
        file=_DECODE,
        locator=r'if \(s->vex_l && e->s0 != X86_SIZE_qq && '
                r'e->s1 != X86_SIZE_qq\)',
        what='a 128-bit-only operand size refuses VEX.L=1'),
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
    # ---- UD0 / UD1 / UD2: DECODED, AND THE DECODE IS A FAULT --------------
    #
    # Not a QEMU gap and not a model refusal in the sense the rest of this
    # table means: the entry exists, the emitter runs, and what it emits is
    # the architectural #UD.  These are the only rows here whose refusal is
    # the ISA's own answer rather than a limit of the emulator, which is why
    # they carry no enable -- there is no bit that would make them execute.
    #
    # They arrived when 7773e9a469 withdrew GEN_OP_SYSCALL from all three:
    # #UD is not a system call, the shared vocabulary has no word for an
    # invalid-opcode fault, and the ruled row REFUSES the opcode rather than
    # borrowing a neighbouring trap's name.  The tracer stating no class is
    # what puts them in the unprobed population, and the population is where
    # this table has to answer for them.
    ('XED_IFORM_UD2',              'UD2',  REFUSED, 'ud-entry', None),
    ('XED_IFORM_UD1_GPR32_GPR32',  'UD1',  REFUSED, 'ud-entry', None),
    ('XED_IFORM_UD1_GPR32_MEMd',   'UD1',  REFUSED, 'ud-entry', None),
    ('XED_IFORM_UD0',              'UD0',  REFUSED, 'ud-entry', None),
    ('XED_IFORM_UD0_GPR32_GPR32',  'UD0',  REFUSED, 'ud-entry', None),
    ('XED_IFORM_UD0_GPR32_MEMd',   'UD0',  REFUSED, 'ud-entry', None),

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

    # ======================================================================
    # THE 2026-09-22 ADDITIONS.  Closing the six NOT-MEASURED CPL0 encodings
    # is what let the leg reach this file for the first time since the table
    # was written, and what it found was a set 115 rows short.  Thirty-three
    # of those were a CLASSIFIER fact and are gone from this population --
    # qemu_reach_matrix.py now labels an encoding QEMU ENTERED
    # ENTERED-THEN-FAULTED(PROBE-STATE), because a fault that is not #UD is
    # the probe's own operands or state and not a decode refusal.  The rest
    # are adjudicated here, one row at a time, and three are not adjudicated
    # at all: they are in REMAINDER below with the question each poses.
    #
    # Each row's SITE was checked against its OWN probe bytes -- the legacy
    # prefixes, REX, VEX map/L/W/pp, opcode and ModRM the encoding carries --
    # and not inferred from its mnemonic or its family.  Sixty of the rows
    # reach an opcode slot that holds a LEGACY entry (CMOVcc, SETcc, LFENCE,
    # MFENCE, XSAVE, XSAVEOPT, PCLMULQDQ); their refusal is that slot's own
    # prefix, VEX-class or operand-size rule, exactly as the older rows above
    # are refused.  Twelve fall to the 0F 01 group default.  Two are QEMU
    # STATING in code that it has not implemented the instruction.
    # ---- cmovcc-slot
    ('XED_IFORM_KADDB_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KADDB', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KADDD_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KADDD', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KADDQ_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KADDQ', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KADDW_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KADDW', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KANDB_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KANDB', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KANDD_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KANDD', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KANDNB_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KANDNB', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KANDND_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KANDND', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KANDNQ_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KANDNQ', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KANDNW_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KANDNW', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KANDQ_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KANDQ', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KANDW_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KANDW', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KNOTB_MASKmskw_MASKmskw_AVX512',
     'KNOTB', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KNOTD_MASKmskw_MASKmskw_AVX512',
     'KNOTD', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KNOTQ_MASKmskw_MASKmskw_AVX512',
     'KNOTQ', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KNOTW_MASKmskw_MASKmskw_AVX512',
     'KNOTW', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KORB_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KORB', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KORD_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KORD', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KORQ_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KORQ', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KORW_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KORW', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KUNPCKBW_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KUNPCKBW', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KUNPCKDQ_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KUNPCKDQ', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KUNPCKWD_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KUNPCKWD', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KXNORB_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KXNORB', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KXNORD_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KXNORD', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KXNORQ_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KXNORQ', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KXNORW_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KXNORW', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KXORB_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KXORB', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KXORD_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KXORD', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KXORQ_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KXORQ', NOT_IMPL, 'cmovcc-slot', None),
    ('XED_IFORM_KXORW_MASKmskw_MASKmskw_MASKmskw_AVX512',
     'KXORW', NOT_IMPL, 'cmovcc-slot', None),
    # ---- setcc-slot
    ('XED_IFORM_KMOVB_GPR32u32_MASKmskw_AVX512',
     'KMOVB', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVB_MASKmskw_GPR32u32_AVX512',
     'KMOVB', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVB_MASKmskw_MASKu8_AVX512',
     'KMOVB', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVB_MASKmskw_MEMu8_AVX512',
     'KMOVB', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVB_MEMu8_MASKmskw_AVX512',
     'KMOVB', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVD_GPR32u32_MASKmskw_AVX512',
     'KMOVD', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVD_MASKmskw_GPR32u32_AVX512',
     'KMOVD', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVD_MASKmskw_MASKu32_AVX512',
     'KMOVD', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVD_MASKmskw_MEMu32_AVX512',
     'KMOVD', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVD_MEMu32_MASKmskw_AVX512',
     'KMOVD', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVQ_GPR64u64_MASKmskw_AVX512',
     'KMOVQ', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVQ_MASKmskw_GPR64u64_AVX512',
     'KMOVQ', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVQ_MASKmskw_MASKu64_AVX512',
     'KMOVQ', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVQ_MASKmskw_MEMu64_AVX512',
     'KMOVQ', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVQ_MEMu64_MASKmskw_AVX512',
     'KMOVQ', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVW_GPR32u32_MASKmskw_AVX512',
     'KMOVW', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVW_MASKmskw_GPR32u32_AVX512',
     'KMOVW', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVW_MASKmskw_MASKu16_AVX512',
     'KMOVW', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVW_MASKmskw_MEMu16_AVX512',
     'KMOVW', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KMOVW_MEMu16_MASKmskw_AVX512',
     'KMOVW', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KORTESTB_MASKmskw_MASKmskw_AVX512',
     'KORTESTB', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KORTESTD_MASKmskw_MASKmskw_AVX512',
     'KORTESTD', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KORTESTQ_MASKmskw_MASKmskw_AVX512',
     'KORTESTQ', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KORTESTW_MASKmskw_MASKmskw_AVX512',
     'KORTESTW', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KTESTB_MASKmskw_MASKmskw_AVX512',
     'KTESTB', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KTESTD_MASKmskw_MASKmskw_AVX512',
     'KTESTD', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KTESTQ_MASKmskw_MASKmskw_AVX512',
     'KTESTQ', NOT_IMPL, 'setcc-slot', None),
    ('XED_IFORM_KTESTW_MASKmskw_MASKmskw_AVX512',
     'KTESTW', NOT_IMPL, 'setcc-slot', None),
    # ---- grp7-absent
    ('XED_IFORM_CLZERO',
     'CLZERO', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_ENCLS',
     'ENCLS', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_ENCLU',
     'ENCLU', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_ENCLV',
     'ENCLV', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_MONITORX',
     'MONITORX', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_MWAITX',
     'MWAITX', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_RSTORSSP_MEMu64',
     'RSTORSSP', REFUSED, 'grp7-absent', 'CR4.CET'),
    ('XED_IFORM_SAVEPREVSSP',
     'SAVEPREVSSP', REFUSED, 'grp7-absent', 'CR4.CET'),
    ('XED_IFORM_SETSSBSY',
     'SETSSBSY', REFUSED, 'grp7-absent', 'CR4.CET'),
    ('XED_IFORM_VMFUNC',
     'VMFUNC', REFUSED, 'grp7-absent', 'CR4.VMXE'),
    ('XED_IFORM_XEND',
     'XEND', NOT_IMPL, 'grp7-absent', None),
    ('XED_IFORM_XTEST',
     'XTEST', NOT_IMPL, 'grp7-absent', None),
    # ---- xsaveopt-p00
    ('XED_IFORM_CLRSSBSY_MEMu64',
     'CLRSSBSY', REFUSED, 'xsaveopt-p00', 'CR4.CET'),
    # ---- lfence-p00
    ('XED_IFORM_INCSSPD_GPR32u8',
     'INCSSPD', REFUSED, 'lfence-p00', 'CR4.CET'),
    ('XED_IFORM_INCSSPQ_GPR64u8',
     'INCSSPQ', REFUSED, 'lfence-p00', 'CR4.CET'),
    # ---- xsave-p00
    ('XED_IFORM_PTWRITE_MEMy',
     'PTWRITE', NOT_IMPL, 'xsave-p00', None),
    # ---- mfence-p00
    ('XED_IFORM_UMONITOR_GPRa',
     'UMONITOR', NOT_IMPL, 'mfence-p00', None),
    # ---- svm-vmmcall-ud
    ('XED_IFORM_VMMCALL',
     'VMMCALL', NOT_IMPL, 'svm-vmmcall-ud', None),
    # ---- svm-skinit-ud
    ('XED_IFORM_SKINIT_EAX',
     'SKINIT', NOT_IMPL, 'svm-skinit-ud', None),
    # ---- pclmulqdq-128only
    ('XED_IFORM_VPCLMULQDQ_YMMu128_YMMu64_MEMu64_IMM8',
     'VPCLMULQDQ', NOT_IMPL, 'pclmulqdq-128only', None),
    ('XED_IFORM_VPCLMULQDQ_YMMu128_YMMu64_YMMu64_IMM8',
     'VPCLMULQDQ', NOT_IMPL, 'pclmulqdq-128only', None),
]

# THE REMAINDER -- rows this table will NOT adjudicate, and why.
#
# A short named remainder beats a false justification.  Each of these three
# encodings HAS a decode-table entry and a working emitter in QEMU; what
# refuses it is a property of the machine the probe legs happened to build,
# not a statement that QEMU cannot run it.  Calling any of them
# NOT-IMPLEMENTED would be false, ENABLE-GATED-OFF would promise a re-probe
# this corpus has no leg for, and REFUSED-BY-MODEL would be the opposite of
# the truth for two of them.  So they are printed, counted, cited, and left
# open with the question stated -- and because the set comparison below
# counts them, the leg cannot lose them.
#
# opcode_id -> (mnemonic, refusal site, the question a maintainer must answer)
REMAINDER = [
    ('XED_IFORM_SYSENTER', 'SYSENTER', 'sysenter-entry',
     'every reachability leg in this corpus runs -cpu max, and QEMU sets the '
     'max model vendor to AMD, so chk(i64_amd) refuses SYSENTER in 64-bit '
     'mode.  Under an Intel-vendor model the same entry decodes and emits.  '
     'Is the x86_64 corpus AMD-vendor-scoped by decision -- in which case '
     'these rows are UNREACHABLE for the scope and should say so -- or is an '
     'Intel-vendor CPL0 re-probe owed before any UNREACHABLE claim stands?'),
    ('XED_IFORM_SYSEXIT', 'SYSEXIT', 'sysexit-entry',
     'same question as SYSENTER: chk(i64_amd) against the max model vendor, '
     'which QEMU sets to AMD; the entry and the emitter both exist'),
    ('XED_IFORM_RSM', 'RSM', 'rsm-entry',
     'RSM is implemented (gen_RSM -> helper_rsm) and refused by chk(smm) '
     'because the probe boots are never in system-management mode.  SMM is '
     'reachable in QEMU system mode, so "no configuration executes it" is '
     'not established.  Does the tracer scope include SMM -- in which case a '
     'CPL0 leg that enters SMM is owed -- or is SMM out of scope and the row '
     'UNREACHABLE for that stated reason?'),
]

# The extensions whose absence from has_cpuid_feature() is itself the proof
# that no decode-table entry could be gated on them.
EXTENSIONS = ('KEYLOCKER', 'UINTR', 'WAITPKG', 'SERIALIZE', 'SHA512', 'LKGS',
              'WRMSRNS', 'TSX_LDTRK', 'HRESET', 'PCONFIG', 'RDPRU', 'MSRLIST',
              'PBNDKB', 'SNP', 'TDX', 'VTX', 'INVLPGB', 'MCOMMIT', 'VMX',
              'SEAM',
              # added with the 2026-09-22 rows, each checked ABSENT from the
              # decode-time vocabulary before it was written here
              'CET', 'SGX', 'CLZERO', 'MONITORX', 'PTWRITE', 'RTM', 'VMFUNC',
              'AVX512')


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
    # The synthetic matrix must carry the REMAINDER too, or arm A would fail
    # on this file's own set comparison rather than on anything it measures.
    rows = ([(i, mn) for i, mn, _, _, _ in ROWS]
            + [(i, mn) for i, mn, _, _ in REMAINDER])

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
      stripa == stripb
      and len(stripa) == len(ROWS) + len(REMAINDER) + 1)
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
    # G PROVES THE REMAINDER IS COUNTED.  An unadjudicated row is only
    # "named and bounded" if losing it is still a refusal; without this arm
    # the REMAINDER list would be indistinguishable from a hole.
    g = run(matrix(drop=REMAINDER[0][0]))
    t('G a REMAINDER iform missing from the matrix REFUSES too',
      g.returncode != 0 and 'disagree' in g.stderr)
    # H the remainder rows are PRINTED, and printed without a verdict.
    rem = set(i for i, _, _, _ in REMAINDER)
    lines = [row for row in a.stdout.splitlines()
             if row.split('\t')[0] in rem]
    t('H every REMAINDER row is published, carrying %s and no verdict' % UNADJ,
      len(lines) == len(REMAINDER)
      and all(row.split('\t')[3] == UNADJ for row in lines))
    print('arms=8 failures=%d' % fails)
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
        # THE REMAINDER COUNTS.  A row nobody could adjudicate is still a row
        # this table has to account for, so it joins the comparison here; what
        # it does not get is a verdict.  Keeping it out of `have` instead
        # would make the leg refuse forever on rows whose answer is not the
        # table's to give, and dropping it silently would be worse.
        have = set(i for i, _, _, _, _ in ROWS) | set(i for i, _, _, _
                                                      in REMAINDER)
        if want != have:
            # THE COUNTS ARE PART OF THE REFUSAL.  Printing two bare lists
            # leaves the reader to count 165 iforms by eye to find out
            # whether this is one stale row or a population, and the answer
            # changes what has to happen next.  The CPL0/CPL3 signals go
            # with the missing ones for the same reason: a row that takes
            # #UD everywhere is the population this table exists for, and a
            # row that faults #DE or #GP is an encoding QEMU RAN whose
            # refusal class is itself in question.
            miss = sorted(want - have)
            sig = collections.Counter(
                '%s/%s/%s' % (r['exec_user_cpl3_max'], r['exec_sys_cpl0'],
                              r['exec_sys_cpl0_enabled'])
                for r in rows if r['opcode_id'] in set(miss))
            sys.exit('the adjudicated set and the matrix disagree: the '
                     'matrix has %d DECODED-THEN-REFUSED rows and this '
                     'table adjudicates %d of them.\n'
                     '  in the matrix, not adjudicated: %d -- %s\n'
                     '  their cpl3/cpl0/cpl0+enables signals: %s\n'
                     '  adjudicated, not in the matrix: %s'
                     % (len(want), len(want & have), len(miss),
                        ' '.join(miss) or '-',
                        '  '.join('%s x%d' % (k, n)
                                  for k, n in sig.most_common()) or '-',
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

    for opid, mn, site, question in REMAINDER:
        h = hex_of.get(opid, '-')
        v = vec.get(h)
        if v == 255:
            flips.append((h, mn))
        out.append((opid, h, mn, UNADJ, '-', cites[site],
                    '%s.  OPEN QUESTION: %s' % (SITES[site]['what'], question),
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

    for name in ('feature-vocabulary', 'cr4-reserved', 'sse-prefix-check',
                 'vex-class0', 'dq-refuses-vex-l', 'i64-amd-check',
                 'max-vendor-is-amd', 'smm-check'):
        print('# %s -> %s' % (name, cites[name]), file=sys.stderr)
    print('# adjudicated %d rows; REMAINDER %d rows carry no verdict: %s'
          % (len(ROWS), len(REMAINDER),
             ' '.join(m for _, m, _, _ in REMAINDER)), file=sys.stderr)
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
