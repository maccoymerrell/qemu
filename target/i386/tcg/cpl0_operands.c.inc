/*
 * THE OPERANDS OF A PRIVILEGED ENCODING NO REACHED EMITTER NAMES.
 *
 * WHAT IS MISSING WITHOUT THIS.  Ten rows of the x86 tables carry chk(cpl0)
 * or chk(iopl), and on every CPL the measurement corpus can reach that arm
 * does `goto gp_fault` before a single op is generated.  Four of the ten have
 * no reachable body to generate from either: gen_WRMSR and gen_RDMSR are
 * `gen_unreachable` under CONFIG_USER_ONLY, gen_INVPCID is
 * gen_illegal_opcode() even in a system build, and MOV to/from CR and DR has
 * its whole load and writeback arm inside `#ifndef CONFIG_USER_ONLY`
 * (emit.c.inc gen_load / gen_writeback, X86_OP_CR and X86_OP_DR).  So QEMU's
 * ordered read list for these encodings is COMPLETE AND EMPTY -- a statement
 * that the instruction reads nothing, which is false of every one of them --
 * and the destination list carries nothing either.
 *
 * The source bar measured it: 5,544 registers over eight families on
 * x86_64 and nothing on any other ISA, every one classified `Q-SILENT`
 * (mechclass.py: QEMU stated a complete read list and it does not mention
 * the lost register).  The destination bar measured 593 over seven.
 *
 * THAT EMPTINESS IS A STATEMENT ABOUT THIS BUILD, NOT ABOUT THE
 * ARCHITECTURE.  R16 is the rule and it is verbatim: "IF THE DEPENDENCY
 * EXISTS IN THE ISA, OR THE REGISTER IS AN ISA REGISTER, THEN WE RECORD IT
 * ... QEMU OPTIMIZATIONS SHOULD NOT BE LEAKING INTO THE TRACE."  A CPL check
 * that jumps past code generation, and a `#ifndef CONFIG_USER_ONLY` that
 * removes the accessor, are both facts about the emulator's configuration.
 * R7.3 says the same thing about the half of this that the ENCODING names:
 * a register the encoding names is not the emulator's to drop.  22d7666262
 * is the precedent in the tree, on the row directly below RDMSR:
 * gen_note_rdpmc_selector() states ECX and EDX:EAX for an instruction whose
 * helper on this build raises #GP rather than reading a counter.
 *
 * WHY HERE AND NOT AT THE EMITTER.  gen_note_rdpmc_selector() sits in the
 * emitter because RDPMC's emitter is REACHED -- `rdpmc` is not cpl0-checked.
 * These ten are, so their emitters are not reached at CPL 3 and the note has
 * to be taken where the identity is: at the row-selection point, ahead of
 * every fault arm.  5d9154d8c2 moved the identity publish there for exactly
 * this reason and measured the reason that had kept it downstream to be
 * false -- a faulting instruction publishes perfectly well; only a check
 * UPSTREAM of the call withholds.  The same sentence governs the operands.
 *
 * IT IS ALSO WHAT MAKES USER AND SYSTEM AGREE.  A statement taken at the
 * decode site is present in both builds and on both sides of the CPL check,
 * so `mov %cr3,%rax` names CR3 whether the trace came from qemu-x86_64 or
 * from qemu-system-x86_64.  A statement taken inside the emitter would make
 * the wire's answer depend on how QEMU was configured, which is the leak R16
 * forbids.
 *
 * WHAT IS STATED IS WHAT THE REFERENCE NAMES, AND NO MORE.  Every register
 * below is one the wire already publishes for these encodings through the
 * operand walk; the statement's whole job is to make QEMU the source of a
 * fact the wire already carries, so that the walk can go without the fact
 * going with it (R12.1).  SYSRET architecturally loads RIP, CS and SS as
 * well; those are NOT stated here, because adding them would move the wire
 * rather than hold it, and a gain is a different program with a different
 * proof.
 *
 * TWO REGISTERS ARE REFUSED RATHER THAN STATED, and the refusal is written
 * down instead of being left as an omission.  `rdmsr` reads and `wrmsr`
 * writes THE MODEL-SPECIFIC REGISTER ECX SELECTS.  Which register that is is
 * a run-time value, so there is no CPUArchState member to give a range for
 * and no name to give -- the position gen_note_rdpmc_selector()'s own header
 * takes for the performance counter, in the same words, and inventing either
 * is what insn_dataflow_note_stated_read_name()'s header refuses.  They stay
 * on the bar with this sentence behind them (BAR_CLASSES `x86-msr-selected`,
 * DEST_CLASSES `x86-msr-selected-dst`).
 *
 * Capture only: no op is emitted, altered or suppressed, and nothing here
 * reads guest memory or CPU state -- only decode->op[], decode->mem and
 * s->modrm, all of them filled by decode_insn() before this runs.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * ONE CONTROL REGISTER, stated by the byte range that IS the register.
 *
 * env->cr[] holds CR0, CR2, CR3 and CR4 and target/i386/tcg/translate.c
 * declares those four under the GDB stub's names, which is the namespace the
 * consumer answers in.  CR8 is the exception in both directions: QEMU keeps
 * no env->cr[8] (the array is five wide, "NOTE: cr1 is unused") and reads it
 * out of the APIC's task-priority register through helper_read_cr8(), so
 * there is no range to state and none is stated.  The bar carries no
 * REG_CTRL8 row, which is the measurement agreeing.
 */
static void cpl0_operands_note_cr(int n, bool write)
{
    if (n < 0 || n >= (int)ARRAY_SIZE(((CPUX86State *)0)->cr) || n == 1) {
        return;
    }
    if (write) {
        insn_dataflow_note_stated_write_env(
            offsetof(CPUX86State, cr[0]) + n * sizeof(((CPUX86State *)0)->cr[0]),
            sizeof(((CPUX86State *)0)->cr[0]));
    } else {
        insn_dataflow_note_stated_read_env(
            offsetof(CPUX86State, cr[0]) + n * sizeof(((CPUX86State *)0)->cr[0]),
            sizeof(((CPUX86State *)0)->cr[0]));
    }
}

/*
 * ONE DEBUG REGISTER, with QEMU'S OWN ALIAS applied.
 *
 * DR4 and DR5 are not registers of their own.  helper_get_dr() and
 * helper_set_dr() (target/i386/tcg/system/bpt_helper.c) say so in code:
 *
 *     if (reg >= 4 && reg < 6) {
 *         if (env->cr[4] & CR4_DE_MASK) {
 *             raise_exception_ra(env, EXCP06_ILLOP, GETPC());
 *         } else {
 *             reg += 2;
 *         }
 *     }
 *
 * so with CR4.DE clear they ARE DR6 and DR7, and with CR4.DE set the encoding
 * raises #UD and executes nothing at all.  The alias arm is therefore the
 * only arm under which the instruction has a dependency, and folding to it is
 * not a guess about run-time state -- it is the only reading that names a
 * register.  The plugin's vocabulary already made the same call for the same
 * reason: champsim_tracer_generic_ids.h leaves REG_DEBUG4/REG_DEBUG5 unused
 * under R8.2 ("an alias is not an independent register") and the shipped
 * table maps X86_REG_DR4 to REG_DEBUG6 and X86_REG_DR5 to REG_DEBUG7.
 *
 * env->dr[] is eight wide and QEMU's own comment says dr4 and dr5 are unused,
 * so the fold reaches a member that is never read or written; naming it would
 * publish a register that does not exist.
 */
static void cpl0_operands_note_dr(int n, bool write)
{
    if (n < 0 || n >= 8) {
        return;
    }
    if (n >= 4 && n < 6) {
        n += 2;
    }
    if (write) {
        insn_dataflow_note_stated_write_env(
            offsetof(CPUX86State, dr[0]) + n * sizeof(((CPUX86State *)0)->dr[0]),
            sizeof(((CPUX86State *)0)->dr[0]));
    } else {
        insn_dataflow_note_stated_read_env(
            offsetof(CPUX86State, dr[0]) + n * sizeof(((CPUX86State *)0)->dr[0]),
            sizeof(((CPUX86State *)0)->dr[0]));
    }
}

static void cpl0_operands_note_gpr_write(int n)
{
    if (n < 0 || n >= CPU_NB_REGS) {
        return;
    }
    insn_dataflow_note_stated_write_env(
        offsetof(CPUX86State, regs[0]) + n * sizeof(((CPUX86State *)0)->regs[0]),
        sizeof(((CPUX86State *)0)->regs[0]));
}

/*
 * ONE OPERAND OF `mov` TO OR FROM A CONTROL OR DEBUG REGISTER, by its unit.
 *
 * The four rows are X86_OP_GROUPwr, so op[0] is the operand written and op[1]
 * the operand read, whichever side the control register is on: 0F 20 and
 * 0F 21 write a GPR and read CR/DR, 0F 22 and 0F 23 read a GPR and write
 * CR/DR.  decode_MOV_CR_DR() forces mod to 3 (AMD 24594 and the 386/486
 * testing the comment there cites), so the r/m operand is always a register
 * and never an address.
 */
static void cpl0_operands_note_crdr_op(const X86DecodedOp *op, bool write)
{
    switch (op->unit) {
    case X86_OP_INT:
        if (write) {
            cpl0_operands_note_gpr_write(op->n);
        } else {
            gen_note_gpr_read(op->n);
        }
        break;
    case X86_OP_CR:
        cpl0_operands_note_cr(op->n, write);
        break;
    case X86_OP_DR:
        cpl0_operands_note_dr(op->n, write);
        break;
    default:
        break;
    }
}

static void cpl0_operands_note(DisasContext *s, X86DecodedInsn *decode)
{
    switch (decode->e.cpl0_operands) {
    case X86_CPL0OPS_NONE:
        return;

    case X86_CPL0OPS_MODRM:
        /*
         * INVPCID.  `0F 38 82 /r` is X86_OP_ENTRY3(INVPCID, None,None, G,y,
         * M,dq): the reg field selects the GPR holding the INVPCID TYPE and
         * the r/m operand is the memory descriptor.  Both are read, and the
         * memory operand is read as its ADDRESS registers -- the base and the
         * index -- which is the reading every other address-generating access
         * on this target gets (nop_operands.c.inc states the same shape for
         * the reserved-NOP space, and gives the RIP-relative and absent-field
         * cases the same answer: base == -2 names no general register and -1
         * names nothing).
         *
         * gen_INVPCID() is gen_illegal_opcode() in EVERY build, so this is
         * the one family here whose registers no configuration of QEMU could
         * ever name from its op stream.  That is a QEMU MODELING fact and R16
         * says a modeling fact does not decide an architectural dependency.
         *
         * THE ADDRESS REGISTERS ARE STATED FIRST, and that is the wire's own
         * convention rather than a preference: format.rst, on src_regs[] --
         * "on an instruction whose memory-address inputs QEMU's own emitters
         * stated, those inputs occupy the LEADING slots ... ahead of the
         * instruction's remaining sources."  Slot order carries no semantic
         * weight (same paragraph; the masks index the array and a consumer
         * resolves a bit by index, never by position), so this settles a
         * question nothing else settles -- and it holds the wire exactly
         * where it already was on 5,390 of the 6,000 encodings.
         */
        if (decode->op[2].has_ea) {
            if (decode->mem.base == -2) {
                /*
                 * RIP-RELATIVE, AND THE PROGRAM COUNTER IS THE BASE.
                 *
                 * nop_operands.c.inc says of its own rows that a
                 * RIP-relative form "names no general register -- the
                 * program counter reaches the read list through the fold
                 * notes the PC-relative path already takes".  That is true
                 * THERE and false HERE, and the difference is the whole
                 * reason this file exists: gen_lea_modrm() runs downstream
                 * of the chk(cpl0) arm, so on these encodings the
                 * PC-relative path is never walked and nothing takes the
                 * fold note.  The address is RIP + disp32 either way, so
                 * the read is stated -- by the same range gen_note_far_call
                 * _pushes() states for the same register, one file over.
                 */
                insn_dataflow_note_stated_read_env(
                    offsetof(CPUX86State, eip),
                    sizeof(((CPUX86State *)0)->eip));
            } else if (decode->mem.base >= 0) {
                gen_note_gpr_read(decode->mem.base);
            }
            if (decode->mem.index >= 0) {
                gen_note_gpr_read(decode->mem.index);
            }
        }
        gen_note_gpr_read(((s->modrm >> 3) & 7) | REX_R(s));
        return;

    case X86_CPL0OPS_CRDR:
        cpl0_operands_note_crdr_op(&decode->op[0], true);
        cpl0_operands_note_crdr_op(&decode->op[1], false);
        return;

    case X86_CPL0OPS_WRMSR:
        /*
         * WRMSR.  Intel SDM: "Writes the contents of registers EDX:EAX into
         * the 64-bit model specific register (MSR) specified in the ECX
         * register."  Three reads; the write is the selected MSR and is
         * refused, see the header.
         *
         * IN ARCHITECTURAL REGISTER ORDER -- EAX, ECX, EDX -- because
         * nothing else orders three IMPLICIT operands.  There is no address
         * to take the leading slots (the INVPCID arm's rule does not reach
         * here) and format.rst gives slot order no semantic weight, so the
         * order is chosen to hold the wire where it already is rather than
         * to move it for no reader's benefit.
         */
        gen_note_gpr_read(R_EAX);
        gen_note_gpr_read(R_ECX);
        gen_note_gpr_read(R_EDX);
        return;

    case X86_CPL0OPS_RDMSR:
        /*
         * RDMSR.  The same definition read the other way: ECX selects, and
         * EDX:EAX receive.  The read of the selected MSR is refused, see the
         * header -- and refusing the SOURCE while stating the DESTINATION is
         * not the model choosing which half of one sentence to believe, which
         * is what 22d7666262 forbids: EDX:EAX have storage and a name and the
         * selected MSR has neither.
         */
        gen_note_gpr_read(R_ECX);
        cpl0_operands_note_gpr_write(R_EAX);
        cpl0_operands_note_gpr_write(R_EDX);
        return;

    case X86_CPL0OPS_SYSRET:
        /*
         * SYSRET.  AMD 24594 and the Intel SDM agree on the two registers the
         * instruction takes its result from: RIP is loaded from RCX and
         * RFLAGS from R11.  R11 has no R_* enumerator -- the CPUX86State
         * regs[] indices past R_EDI are the REX-extended eight and are spelled
         * as numbers throughout this target -- so it is written as 11 with
         * this sentence beside it.
         *
         * RIP, CS and SS are also loaded, and are deliberately NOT stated;
         * the header says why.
         */
        gen_note_gpr_read(R_ECX);
        gen_note_gpr_read(11);
        insn_dataflow_note_stated_write_name("eflags");
        return;

    case X86_CPL0OPS_IF:
        /*
         * STI and CLI.  Both are a read-modify-write of EFLAGS.IF, and QEMU
         * writes them that way: gen_set_eflags() and gen_reset_eflags()
         * (target/i386/tcg/translate.c) load env->eflags, or/and the mask in,
         * and store it back.  That op stream exists in both builds -- neither
         * emitter is #ifndef CONFIG_USER_ONLY -- and is simply never REACHED
         * from the corpus, because chk(iopl) faults first at CPL 3 with
         * IOPL < 3.  So unlike the families above this one is not a modeling
         * gap at all: it is the same fact QEMU's own translation carries,
         * stated at a point the fault arm cannot jump past.
         *
         * By NAME rather than by range, because env->eflags carries no
         * insn_dataflow_declare_regfile() of its own: `eflags` is declared
         * over env->df, the one architectural flag QEMU keeps outside the
         * lazy cc_* quartet.  The name route is the one translate.c:1020
         * already uses for this register and it resolves through the i386 GDB
         * stub's own spelling.
         */
        insn_dataflow_note_stated_read_name("eflags");
        insn_dataflow_note_stated_write_name("eflags");
        return;
    }
}
