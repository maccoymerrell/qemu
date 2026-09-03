/*
 * THE OPERANDS A RESERVED NOP, A PREFETCH AND UD0/UD1 NAME.
 *
 * WHAT IS MISSING WITHOUT THIS.  Nine rows of the 0F table decode a ModRM
 * byte and then generate nothing that uses it: the reserved-NOP space
 * (0F 18, 0F 19, 0F 1C, 0F 1D, 0F 1E, 0F 1F), the two prefetch groups
 * (0F 0D, and 0F 18 /0../3) and the two undefined-opcode rows UD1 (0F B9)
 * and UD0 (0F FF).  The address is computed into DisasContext::A0 and
 * nothing ever reads it, so a walk of the op stream -- which credits a
 * register read when the value it produced is used -- finds no read at all,
 * and the instruction reaches a consumer with an EMPTY source list.
 *
 * That emptiness is a statement about QEMU's lowering, not about the
 * architecture.  R16 says it in the sentence this file exists for: A NOP
 * SEMANTIC STILL HAS REAL DEPENDENCIES IN THE CHOSEN REGISTER.  R15 says a
 * lowering decision is not architectural truth, and R7.3 says a register the
 * encoding names is not the emulator's to drop.  So the operands are STATED
 * here, at the decode site, where the encoding fields are still in hand --
 * R20's shape: a static fact of the encoding, stated once per translation,
 * nothing observed and nothing derived.
 *
 * WHICH OPERANDS, PER REFERENCE.
 *
 *   0F 1F /r, 0F 1E /r, 0F 1D /r, 0F 1C /r, 0F 19 /r and the reserved forms
 *   of 0F 18 -- XED's reserved-NOP patterns name BOTH ModRM operands
 *   (`NOP MEMv GPRv` for mod!=3, `NOP GPRv GPRv` for mod=3): the r/m
 *   operand and the register the reg field selects.  The Intel SDM's table
 *   entry for `0F 1F /0 NOP r/m16/r/m32` spells only the r/m operand, so the
 *   two references differ in the SUPERSET direction, and the standing
 *   in-tree ruling on that is to publish rather than to take the strict
 *   subset (R12.1: no information loss).  Both are stated.
 *
 *   0F B9 /r UD1 and 0F FF /r UD0 -- `UD1 r32, r/m32` and `UD0 r32,
 *   r/m32` in the SDM's own operand column, which is XED's reading too.
 *   Both operands, on the same rule.
 *
 *   0F 0D /0../2 (prefetch, prefetchw, prefetchwt1) and 0F 18 /0../3
 *   (prefetchnta, prefetcht0, prefetcht1, prefetcht2) -- one operand.  The
 *   reg field of a prefetch is the HINT, an opcode extension and not a
 *   register number, so it is NOT stated; XED's operand list for every
 *   prefetch arm is the memory operand alone.  prefetch_ident_of() already
 *   owns that discrimination, bit for bit, and is asked rather than
 *   re-derived so the two cannot drift.
 *
 *   F3 0F 1E FA / FB (endbr64 / endbr32) and F3 0F 1E /1 mod=3
 *   (rdsspd / rdsspq) -- NOTHING is stated.  endbr names no operand, and
 *   rdssp's ModRM r/m register is its DESTINATION, not a source: stating it
 *   as a read would fabricate a dependency the encoding does not have.
 *   cet_ident_of() already separates those three arms from the reserved NOP
 *   they share a row with, and is asked here for the same reason.
 *
 * A MEMORY OPERAND IS ITS ADDRESS REGISTERS.  For mod!=3 the registers the
 * encoding names are the base and the index; the instruction depends on
 * their values because the address is a function of them, which is the same
 * reading every other address-generating access on this target gets.  A
 * RIP-relative form (base == -2) names no general register -- the program
 * counter reaches the read list through the fold notes the PC-relative path
 * already takes -- and an absent base or index (-1) names nothing.
 *
 * Capture only: no op is emitted, altered or suppressed, and every note is
 * taken after the last #UD/#GP check, beside the identity publish, so an
 * encoding that faults instead of executing states nothing.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * One general register of the guest, stated by the byte range that IS the
 * register -- the form gen_note_dividend_read() uses for the same file.
 */
static void nop_operands_note_gpr(int reg)
{
    if (reg < 0 || reg >= CPU_NB_REGS) {
        return;
    }
    insn_dataflow_note_stated_read_env(offsetof(CPUX86State, regs[reg]),
                                       sizeof(((CPUX86State *)0)->regs[reg]));
}

static void nop_operands_note(DisasContext *s, X86DecodedInsn *decode)
{
    const X86DecodedOp *rm;

    if (!decode->e.encoded_operands) {
        return;
    }

    /*
     * The three CET arms share this row and do not share its operands; see
     * the header comment.  Nothing is stated for them here.
     */
    if (cet_ident_of(decode->e.slot, (s->prefix & PREFIX_REPZ) != 0,
                     s->modrm)) {
        return;
    }

    /*
     * The ModRM operand is op[0] on the NOP rows (X86_OP_ENTRY1 puts it
     * there and copies it into op[1]) and op[1] on the UD rows, which are
     * X86_OP_ENTRYr and leave op[0] absent.
     */
    rm = decode->e.op0 != X86_TYPE_None ? &decode->op[0] : &decode->op[1];

    if (rm->has_ea) {
        nop_operands_note_gpr(decode->mem.base);
        nop_operands_note_gpr(decode->mem.index);
    } else {
        nop_operands_note_gpr(rm->n);
    }

    /* The reg field is a register operand on every arm but the prefetches. */
    if (!prefetch_ident_of(decode->e.slot, s->modrm)) {
        nop_operands_note_gpr(((s->modrm >> 3) & 7) | REX_R(s));
    }
}
