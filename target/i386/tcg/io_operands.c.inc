/*
 * THE REGISTERS AN I/O INSTRUCTION NAMES, ON A BUILD THAT REFUSES TO RUN IT.
 *
 * WHAT IS MISSING WITHOUT THIS.  `IN`, `OUT`, `INS` and `OUTS` all begin by
 * asking gen_check_io() whether this translation may perform port I/O.  Under
 * CONFIG_USER_ONLY that function has one arm:
 *
 *     We do not implement the ioperm(2) syscall, so the TSS check
 *     will always fail.
 *         gen_exception_gpf(s); return false;
 *
 * so the emitter returns having produced a #GP raise and nothing else.  The
 * accumulator write of `in %dx,%al`, the pointer advance of `insb`, the
 * counter of `rep outsb` and the EFLAGS every one of the four consults are
 * all emitted inside the arm that was never taken, and the instruction
 * reaches a consumer with a source list holding only the port operand the
 * generic loader had already materialised and a destination list holding
 * nothing at all.
 *
 * That emptiness is a statement about this BUILD, not about the
 * architecture.  R15 says a lowering decision is not architectural truth and
 * R16 says the ISA-defined dependency is recorded regardless of machine
 * state -- the position gen_note_bnd_write() already occupies for MPX, whose
 * destination is stated whether or not the guest enabled the feature and for
 * exactly this reason.  The same encoding, translated by the same decoder in
 * a softmmu build at CPL <= IOPL, emits every one of these accesses; a
 * consumer must not be able to tell the two apart by the register lists.
 *
 * WHICH REGISTERS, PER REFERENCE.  Each instruction's own SDM Operation
 * section, Vol. 2:
 *
 *   IN   -- the permission test reads EFLAGS (IOPL, and VM for the
 *           virtual-8086 arm); `DEST := SRC` writes AL/AX/EAX.  The port is
 *           DX or an imm8, and the register form's DX is loaded by the
 *           generic operand loader before the emitter runs, so it is already
 *           on the read side and is not restated.
 *
 *   OUT  -- the same permission test, so the same EFLAGS read.  The
 *           accumulator and the port are both operands the loader has
 *           already read, and the instruction has no register destination.
 *
 *   INS  -- the permission test's EFLAGS, plus DF from the same section's
 *           `IF DF = 0 THEN (E)DI := (E)DI + n ELSE ... - n`.  One EFLAGS
 *           read covers both: the guest register is one word and the
 *           consumer's vocabulary names it once.  (E)DI is READ (it is the
 *           destination address) and WRITTEN (the advance).
 *
 *   OUTS -- identically, on (E)SI.
 *
 *   REP  -- Vol. 2B's REP section: `CountReg := CountReg - 1` each iteration
 *           and the termination test reads it, so a prefixed form reads AND
 *           writes rCX.  The prefix is a static property of these bytes,
 *           taken off @s->prefix exactly as the emitter's own gen_repz()
 *           dispatch takes it.
 *
 * THE SEGMENT, AND WHY IT IS NOT A SEPARATE QUESTION.  `INS` addresses
 * ES:(E)DI and `OUTS` addresses DS:(E)SI, and the sibling string family --
 * `movs`, `stos`, `lods`, `scas`, `cmps` -- addresses memory the same way.
 * Those five already publish the segment on exactly the encodings where
 * QEMU's own address computation reads one: gen_lea_v_seg_dest() adds
 * cpu_seg_base[seg] when, and only when, an override or ADDSEG puts a base
 * in the sum, so `fs movsb` names FS and a bare `movsb` in 64-bit code names
 * nothing.  An `outs` under the same prefix must name the same register, and
 * the rule is ASKED rather than restated: gen_lea_seg_of() is the decision
 * gen_lea_v_seg_dest() itself makes, factored out so the two cannot drift.
 * Nothing is added to the family's reading -- the default ES and DS of a
 * 64-bit access contribute no base to any of the seven, and none of the
 * seven names them.
 *
 * A FULL-WIDTH RANGE, DELIBERATELY.  `in %dx,%al` architecturally writes AL,
 * and the softmmu build's own lowering of it -- gen_writeback() ->
 * gen_op_mov_reg_v() -> tcg_gen_deposit_tl() into cpu_regs[R_EAX] -- presents
 * a whole-global write to the extraction.  Stating one byte here would make
 * the user-mode row differ from the softmmu row for the same encoding, which
 * is the difference this file exists to remove.  The range is the register.
 *
 * Capture only: no op is emitted, altered or suppressed, and every note is
 * taken at the END of the emitter, after any body it did emit, so the
 * ordered lists keep the body's own order and these statements only fill
 * what the refused arm left empty.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* One general register of the guest, by the byte range that IS the register. */
static void io_operands_note_gpr(int reg, bool write)
{
    if (reg < 0 || reg >= CPU_NB_REGS) {
        return;
    }
    if (write) {
        insn_dataflow_note_stated_write_env(
            offsetof(CPUX86State, regs[reg]),
            sizeof(((CPUX86State *)0)->regs[reg]));
    } else {
        insn_dataflow_note_stated_read_env(
            offsetof(CPUX86State, regs[reg]),
            sizeof(((CPUX86State *)0)->regs[reg]));
    }
}

/* The counter a REP-prefixed string I/O form reads and writes. */
static void io_operands_note_rep_count(DisasContext *s)
{
    if (!(s->prefix & (PREFIX_REPZ | PREFIX_REPNZ))) {
        return;
    }
    io_operands_note_gpr(R_ECX, false);
    io_operands_note_gpr(R_ECX, true);
}

/*
 * `in`/`out`: the permission test's EFLAGS, and IN's accumulator
 * destination.  @dest is R_EAX for IN and -1 for OUT, which has none.
 */
static void gen_io_operands_note_port(int dest)
{
    insn_dataflow_note_stated_read_name("eflags");
    io_operands_note_gpr(dest, true);
}

/* The segment base gen_lea_v_seg_dest() would have added to the address. */
static void io_operands_note_seg(DisasContext *s, int def_seg, int ovr_seg)
{
    int seg = gen_lea_seg_of(s, s->aflag, def_seg, ovr_seg);

    if (seg < 0) {
        return;
    }
    insn_dataflow_note_stated_read_env(
        offsetof(CPUX86State, segs[seg].base),
        sizeof(((CPUX86State *)0)->segs[seg].base));
}

/*
 * `ins`/`outs`: the permission test's EFLAGS and the same word's DF, the
 * pointer register in both directions, the segment its address is taken
 * through, and the REP counter when the prefix is there.  @ptr is R_EDI for
 * INS and R_ESI for OUTS; @def_seg and @ovr_seg are the pair
 * gen_string_movl_A0_EDI() and gen_string_movl_A0_ESI() pass -- ES and no
 * override for INS, DS and the instruction's own override for OUTS.
 */
static void gen_io_operands_note_string(DisasContext *s, int ptr,
                                        int def_seg, int ovr_seg)
{
    insn_dataflow_note_stated_read_name("eflags");
    io_operands_note_gpr(ptr, false);
    io_operands_note_seg(s, def_seg, ovr_seg);
    io_operands_note_gpr(ptr, true);
    io_operands_note_rep_count(s);
}
