#!/usr/bin/env python3
"""A ONE-INSTRUCTION aarch64 GUEST: the image both aarch64 coverage legs run.

WHY A HAND-ASSEMBLED IMAGE
--------------------------
The coverage pass has to place CHOSEN BYTES at a CHOSEN ADDRESS and run them.
An assembler refuses the encodings that matter most -- the unallocated and the
privileged -- and a linker is free to move what it accepts.  So the image is
built here, byte by byte, with one PT_LOAD and no loader involvement.

WHY A FALSE "DID NOT RUN" IS HARD TO PRODUCE
--------------------------------------------
Everything the probe can reach is mapped and legal:

  * every word of the image is `nop` (0xd503201f) unless this file wrote
    something else there, so a branch landing anywhere inside runs to an exit
    stub instead of hitting an undefined word.  aarch64 instructions are
    4-byte aligned, so there is no odd-offset landing to worry about.
  * x0..x30 and SP are preloaded with the address of the middle of the nop
    slide, so a register-indirect branch lands in the image and a load or
    store through any register hits mapped memory rather than faulting for a
    reason that has nothing to do with the encoding under test.
  * the image is mapped RWX, so a store through a preloaded register does not
    fault on permissions either.
  * nothing else is mapped, so a transfer outside the image raises SIGSEGV --
    which is positive evidence of DECODE, because the target had to be
    computed first.

That leaves SIGILL as the only negative signal, and only the probe can raise
it.

THE TWO EXIT STUBS SAY WHICH WAY THE PROBE SURVIVED.  `exit(1)` sits
immediately after the probe, so a probe that simply completed ends the guest at
once; `exit(2)` sits at the end of the slide, so a probe that TRANSFERRED
control reports itself differently.  Collapsing the two would lose the
difference between an instruction that ran and one that jumped.

THE ARMS ARE AN ARCHITECTURAL STATE, NOT A RETRY.  SME's instructions are
UNDEFINED unless PSTATE.SM / PSTATE.ZA are set, so probing them from the
default state would report the whole of SME unreachable and the number would
look like a fact about the CPU.  `SMSTART` is therefore a second prologue arm,
run only for rows the first arm did not reach, exactly as the riscv64 leg
treats `vsetvli`.  A row counts reachable if ANY arm ran it.

Author: Maccoy Merrell.

SPDX-License-Identifier: GPL-2.0-or-later
"""

import struct

EM_AARCH64 = 183

BASE = 0x10000000
OFF_ENTRY = 0x1000
OFF_PROBE = 0x2000
OFF_SLIDE = 0x4000
SLIDE_LEN = 0x10000
IMAGE_LEN = OFF_SLIDE + SLIDE_LEN
#: The middle of the slide: a branch to it lands on a nop, and a load or store
#: through it lands on mapped memory.
SCRATCH = BASE + OFF_SLIDE + SLIDE_LEN // 2

PROBE_PC = BASE + OFF_PROBE

NOP = 0xD503201F

#: Exit codes the guest can reach, distinct so a reader of the raw result can
#: say WHICH way the probe survived rather than only that it did.
EXIT_FELL_THROUGH = 1
EXIT_TRANSFERRED = 2

#: `msr SVCRSMZA, #1` -- enter streaming mode AND enable ZA.  a64.decode states
#: the encoding as MSR_i_SVCR (mask:2 imm:1), so this word is read off the
#: tree rather than remembered: mask=3, imm=1.
SMSTART = 0xD503477F

#: The prologue arms, as (extra trailing instruction, registers to ZERO).
#:
#: "zeroidx" EXISTS BECAUSE A SCALED-INDEX ADDRESS NEEDS A ZERO SOMEWHERE.
#: The default prologue puts the slide address in EVERY register, which is what
#: makes a base-plus-offset load land on mapped memory -- and what makes a
#: base-plus-INDEX load compute base + index, twice the slide address, off the
#: end of the image.  MEASURED: aarch64's four register-offset rows (LDR,
#: LDR_v, STR, STR_v) came back not-exercised for exactly that reason, which is
#: a fact about the operand VALUES this file chose and not about the row.  The
#: arm zeroes x1..x7, so a word whose index register is a low one addresses the
#: slide itself; the higher registers keep the slide address, so base registers
#: still point at mapped memory.
ARMS = {
    "plain": (None, ()),
    "sm": (SMSTART, ()),
    "zeroidx": (None, tuple(range(1, 8))),
}


def movz(rd, imm16, shift16=0):
    """movz xRd, #imm16, lsl #(16*shift16)"""
    return (0xD2800000 | ((shift16 & 3) << 21) | ((imm16 & 0xFFFF) << 5)
            | (rd & 31))


def movk(rd, imm16, shift16=0):
    """movk xRd, #imm16, lsl #(16*shift16)"""
    return (0xF2800000 | ((shift16 & 3) << 21) | ((imm16 & 0xFFFF) << 5)
            | (rd & 31))


def mov_reg(rd, rm):
    """mov xRd, xRm -- orr xRd, xzr, xRm"""
    return 0xAA0003E0 | ((rm & 31) << 16) | (rd & 31)


def mov_sp_from(rn):
    """mov sp, xRn -- add sp, xRn, #0"""
    return 0x91000000 | ((rn & 31) << 5) | 31


SVC0 = 0xD4000001


def exit_stub(code):
    """movz x8,#93 ; movz x0,#code ; svc #0 -- the guest's only way out."""
    return [movz(8, 93), movz(0, code), SVC0]


def prologue(arm):
    """Point every general register and SP at the slide, then fall through.

    @arm is a key of ARMS.
    """
    arm_word, zero_regs = ARMS[arm]
    words = []
    for sh in range(4):
        part = (SCRATCH >> (16 * sh)) & 0xFFFF
        if sh == 0:
            words.append(movz(0, part, 0))
        elif part:
            words.append(movk(0, part, sh))
    for rd in range(1, 31):
        words.append(mov_reg(rd, 0))
    words.append(mov_sp_from(0))
    for rd in zero_regs:
        words.append(movz(rd, 0))
    if arm_word is not None:
        words.append(arm_word)
    return words


def build_elf(probe_word, arm):
    """A one-PT_LOAD static aarch64 ELF: prologue, probe, exit, nop slide.

    @arm is a key of ARMS.
    """
    img = bytearray(struct.pack("<I", NOP) * (IMAGE_LEN // 4))

    ehsize, phentsize = 64, 56
    hdr = bytearray()
    hdr += b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    hdr += struct.pack("<HHI", 2, EM_AARCH64, 1)            # ET_EXEC
    hdr += struct.pack("<QQQ", BASE + OFF_ENTRY, ehsize, 0)
    hdr += struct.pack("<IHHHHHH", 0, ehsize, phentsize, 1, 0, 0, 0)
    assert len(hdr) == ehsize, len(hdr)
    img[0:ehsize] = hdr

    # PF_R|PF_W|PF_X: the probe may store through a preloaded register, and a
    # store to a read-only page would fault for the mapping's reason and not
    # the encoding's.
    ph = struct.pack("<IIQQQQQQ", 1, 7, 0, BASE, BASE,
                     IMAGE_LEN, IMAGE_LEN, 0x1000)
    assert len(ph) == phentsize, len(ph)
    img[ehsize:ehsize + phentsize] = ph

    def put(off, words):
        for i, w in enumerate(words):
            img[off + 4 * i: off + 4 * i + 4] = struct.pack("<I", w)

    pro = prologue(arm)
    if OFF_ENTRY + 4 * len(pro) > OFF_PROBE:
        raise ValueError("prologue overruns the probe slot")
    put(OFF_ENTRY, pro)
    put(OFF_PROBE, [probe_word])
    put(OFF_PROBE + 4, exit_stub(EXIT_FELL_THROUGH))
    put(OFF_SLIDE + SLIDE_LEN - 4 * 3, exit_stub(EXIT_TRANSFERRED))
    return bytes(img)
