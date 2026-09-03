/*
 * THE REGISTERS A SOFTWARE INTERRUPT NAMES, ON A BUILD THAT RAISES INSTEAD
 * OF TAKING IT.
 *
 * WHAT IS MISSING WITHOUT THIS.  `INT n`, `INT3`, `INT1` and `INTO` all reach
 * gen_interrupt() or its two siblings, which emit an update of cc_op and EIP
 * and then one TCG_CALL_NO_RETURN helper.  Everything the instruction DOES is
 * inside that helper: do_interrupt() pushes EFLAGS, CS and EIP through
 * do_interrupt_protected(), which is where the stack pointer moves and where
 * IF, TF, VM, RF and NT are cleared.  A walk of the op stream sees a raise
 * with an empty read list and no architectural write, so the instruction
 * reaches a consumer with a source list holding NOTHING -- not the flags word
 * it pushes and then edits, and not the stack pointer it decrements -- and a
 * destination list holding nothing either.
 *
 * That emptiness is a statement about QEMU's LOWERING, not about the
 * architecture.  R15 says a lowering decision is not architectural truth and
 * R16 says the ISA-defined dependency is recorded regardless of machine
 * state.  It is the same position io_operands.c.inc takes for the port
 * instructions and gen_note_bnd_write() takes for MPX: the work is real, it
 * is simply on the other side of a helper call, and a consumer must not be
 * able to tell that from the register lists.
 *
 * WHICH REGISTERS, PER REFERENCE.  Vol. 2A, "INT n/INTO/INT3/INT1 -- Call to
 * Interrupt Procedure", the Operation section, INTRA-PRIVILEGE-LEVEL-
 * INTERRUPT arm -- the arm every one of these takes when it does not change
 * privilege:
 *
 *   Push(EFLAGS);  Push(CS);  Push(EIP);
 *   IF gate is interrupt gate THEN IF := 0; FI;
 *   TF := 0;  VM := 0;  RF := 0;  NT := 0;
 *   CS:EIP := gate's selector:offset
 *
 * so, by generic name:
 *
 *   EFLAGS  READ  -- it is pushed.  WRITTEN -- five of its bits are cleared
 *                    by the transfer itself.
 *   rSP     READ and WRITTEN -- three pushes are three decrements, and the
 *                    address each one stores to is a function of its value.
 *   CS      READ  -- it is pushed.  WRITTEN -- the gate loads it.
 *
 *   The vector is an immediate (`INT n`) or fixed by the opcode (`INT3`,
 *   `INT1`, `INTO`), never a register, so nothing else is named.  `INTO`
 *   takes the same arm and reads the same EFLAGS word for OF as well as for
 *   the push; one read of a one-word register covers both, exactly as
 *   io_operands.c.inc's INS/OUTS note covers the IOPL test and DF together.
 *
 * A FULL-WIDTH RANGE.  The stack pointer is stated as the whole guest
 * register, which is what QEMU's own softmmu lowering of the pushes presents
 * to the extraction, and what every other statement on this target uses.
 *
 * Capture only: no op is emitted, altered or suppressed, and the note is
 * taken at the END of the emitter, after the raise it did emit, so the
 * ordered lists keep the body's own order.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The stack pushes, the flags word they carry and then edit, and the code
 * segment the gate replaces.  Shared by all four forms because all four take
 * the same arm of the same Operation section.
 */
static void gen_trap_operands_note_gate(void)
{
    insn_dataflow_note_stated_read_name("eflags");
    insn_dataflow_note_stated_read_env(
        offsetof(CPUX86State, regs[R_ESP]),
        sizeof(((CPUX86State *)0)->regs[R_ESP]));
    insn_dataflow_note_stated_read_env(
        offsetof(CPUX86State, segs[R_CS].selector),
        sizeof(((CPUX86State *)0)->segs[R_CS].selector));
    insn_dataflow_note_stated_write_env(
        offsetof(CPUX86State, regs[R_ESP]),
        sizeof(((CPUX86State *)0)->regs[R_ESP]));
    insn_dataflow_note_stated_write_name("eflags");
    insn_dataflow_note_stated_write_env(
        offsetof(CPUX86State, segs[R_CS].selector),
        sizeof(((CPUX86State *)0)->segs[R_CS].selector));
}
