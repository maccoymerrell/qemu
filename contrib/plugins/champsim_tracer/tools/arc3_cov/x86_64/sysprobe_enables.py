#!/usr/bin/env python3
"""ARC 3 -- the architectural ENABLES the CPL0 probe holds while it probes.

A #UD at CPL 0 says the refusal is not a PRIVILEGE refusal.  It does not say
the refusal is not an ENABLE refusal, and the two look identical from the
vector.  This is the manifest of every architectural enable that could gate
any encoding in the reachability set; the probe sets each one, reads the
register BACK, and scores the enable as held only on the readback.

kind  meaning                                   a1            a2
  0   CR4 bit                                   bit index     -
  1   MSR, OR these bits in                     MSR number    bits
  2   MSR, write this exact value               MSR number    value
  3   XCR0 <- every bit CPUID.0Dh:EDX:EAX names -             -
  4   XCR0, OR these bits in                    -             bits

DELIBERATELY ABSENT, and each for a stated reason rather than an oversight:

  CR4.LA57 (bit 12)  switches the probe's own 4-level page tables to 5-level.
                     QEMU refuses it outright while CS is 64-bit
                     (target/i386/tcg/system/misc_helper.c:146), and no
                     encoding in the set is gated on it.
  CR4.FRED (bit 32)  replaces IDT event delivery, which is the mechanism this
                     probe measures WITH.  Holding it would destroy the
                     instrument.  LKGS is the only encoding in the set
                     enumerated alongside FRED, and it is adjudicated from the
                     decoder instead (translate.c:3299).
  CR0.PG / CR0.PE    already set; clearing them leaves long mode.

Author: Maccoy Merrell.
SPDX-License-Identifier: GPL-2.0-or-later
"""
import os
import sys

CR4, MSR_OR, MSR_SET, XCR0_CPUID, XCR0_OR = 0, 1, 2, 3, 4

# name, kind, a1, a2, what it would gate
ENABLES = [
    # ---- controls.  R8.7: an instrument nobody has watched fire vouches for
    # nothing, so the manifest carries enables QEMU MUST take and enables QEMU
    # MUST refuse, and the harness fails if either behaves the other way.
    ('CTL-CR4.OSXSAVE',      CR4, 18, 0),
    ('CTL-XCR0.cpuid0Dh',    XCR0_CPUID, 0, 0),
    ('CTL-EFER.NXE',         MSR_OR, 0xC0000080, 1 << 11),
    ('CTL-CR4.RESERVED31',   CR4, 31, 0),          # must NOT take

    # ---- VMX / SMX ---------------------------------------------------------
    ('CR4.VMXE',             CR4, 13, 0),
    ('CR4.SMXE',             CR4, 14, 0),
    ('IA32_FEATURE_CONTROL', MSR_SET, 0x0000003A, 0x5),

    # ---- SVM (the AMD virtualisation QEMU DOES implement) ------------------
    ('EFER.SVME',            MSR_OR, 0xC0000080, 1 << 12),
    ('MSR_VM_HSAVE_PA',      MSR_SET, 0xC0010117, 0x0F000000),
    ('EFER.SCE',             MSR_OR, 0xC0000080, 1 << 0),
    ('EFER.FFXSR',           MSR_OR, 0xC0000080, 1 << 14),

    # ---- CET ---------------------------------------------------------------
    ('CR4.CET',              CR4, 23, 0),
    ('IA32_XSS.CET',         MSR_OR, 0x00000DA0, (1 << 11) | (1 << 12)),
    ('IA32_U_CET',           MSR_SET, 0x000006A0, 0x1),
    ('IA32_S_CET',           MSR_SET, 0x000006A2, 0x1),
    ('IA32_PL0_SSP',         MSR_SET, 0x000006A4, 0x0F001000),
    ('IA32_INT_SSP_TABLE',   MSR_SET, 0x000006A8, 0x0F002000),

    # ---- UINTR -------------------------------------------------------------
    ('CR4.UINTR',            CR4, 25, 0),
    ('IA32_UINTR_RR',        MSR_SET, 0x00000985, 0x1),
    ('IA32_UINTR_HANDLER',   MSR_SET, 0x00000986, 0x00100000),
    ('IA32_UINTR_STACKADJ',  MSR_SET, 0x00000987, 0x0F003000),
    ('IA32_UINTR_MISC',      MSR_SET, 0x00000988, 0x1),
    ('IA32_UINTR_PD',        MSR_SET, 0x00000989, 0x0F004000),
    ('IA32_UINTR_TT',        MSR_SET, 0x0000098A, 0x0F005001),

    # ---- protection keys, UMIP, FSGSBASE, PCID, SMEP/SMAP ------------------
    ('CR4.PKE',              CR4, 22, 0),
    ('CR4.PKS',              CR4, 24, 0),
    ('CR4.UMIP',             CR4, 11, 0),
    ('CR4.FSGSBASE',         CR4, 16, 0),
    ('CR4.PCIDE',            CR4, 17, 0),
    ('CR4.SMEP',             CR4, 20, 0),
    ('CR4.SMAP',             CR4, 21, 0),

    # ---- Keylocker ---------------------------------------------------------
    ('IA32_COPY_L2P',        MSR_SET, 0x00000D91, 0x1),
    ('IA32_COPY_P2L',        MSR_SET, 0x00000D92, 0x1),
    ('IA32_COPY_STATUS',     MSR_SET, 0x00000D93, 0x1),
    ('IA32_IWKEYBACKUP_ST',  MSR_SET, 0x00000D94, 0x1),

    # ---- WAITPKG, HRESET, TDX/SEAM, SNP ------------------------------------
    ('IA32_UMWAIT_CONTROL',  MSR_SET, 0x000000E1, 0x00000001),
    ('IA32_HRESET_ENABLE',   MSR_SET, 0x000017DA, 0x1),
    ('IA32_SEAMRR_BASE',     MSR_SET, 0x00001400, 0x0F000008),
    ('AMD_SYSCFG.SNP',       MSR_OR, 0xC0010010, 1 << 24),
    ('AMD_SEV_STATUS',       MSR_OR, 0xC0010131, 0x1),

    # ---- XCR0 supervisor / AVX-512 halves ----------------------------------
    ('XCR0.avx512',          XCR0_OR, 0, (1 << 5) | (1 << 6) | (1 << 7)),
    ('XCR0.tile',            XCR0_OR, 0, (1 << 17) | (1 << 18)),
]

# Enables that MUST be held for the leg to mean anything, and enables that
# MUST be refused.  Both are asserted by sysprobe_enab_run.sh.
MUST_HOLD = ('CTL-CR4.OSXSAVE', 'CTL-XCR0.cpuid0Dh', 'CTL-EFER.NXE')
MUST_REFUSE = ('CTL-CR4.RESERVED31',)


def _check():
    """A readback proves nothing about bits that are all zero.

    `took` is `(readback & bits) == bits`, so an entry whose bits are zero is
    scored as HELD no matter what QEMU did with the write.  IA32_UMWAIT_CONTROL
    was written as 0 in the first draft of this manifest and duly reported
    itself held under a QEMU that has no such MSR.
    """
    for nm, kind, a1, a2 in ENABLES:
        if kind != CR4 and kind != XCR0_CPUID and not a2:
            raise AssertionError(
                '%s asks for zero bits: its readback cannot distinguish "QEMU '
                'held it" from "QEMU discarded it"' % nm)
    if len(set(e[0] for e in ENABLES)) != len(ENABLES):
        raise AssertionError('duplicate enable name')


def emit(path, skip):
    _check()
    sel = [e for e in ENABLES if e[0] not in skip]
    with open(path, 'w') as f:
        f.write('/* GENERATED by sysprobe_enables.py -- do not edit */\n'
                '    .section .rodata\n    .align 16\n'
                '    .globl enab_blob\nenab_blob:\n')
        for k, (nm, kind, a1, a2) in enumerate(sel):
            f.write('    .quad %d, %d, %d, enab_nm%d\n' % (kind, a1, a2, k))
        f.write('    .globl enab_count\n    .align 8\n'
                'enab_count: .quad %d\n' % len(sel))
        for k, (nm, kind, a1, a2) in enumerate(sel):
            f.write('enab_nm%d: .asciz "%s"\n' % (k, nm))
    return sel


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'enabblob.S'
    skip = (set(open('eskip.txt').read().split())
            if os.path.exists('eskip.txt') else set())
    sel = emit(out, skip)
    sys.stderr.write('enables %d, skipped %d\n' % (len(sel), len(skip)))
