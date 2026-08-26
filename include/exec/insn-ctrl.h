/*
 * Per-instruction CONTROL TRANSFER, derived from the IR the target's
 * translator emitted.
 *
 * The premise is insn-dataflow.c's, applied to the other half of what a
 * tracer needs from a decoder.  A branch is not something to look up in a
 * mnemonic table: it is something QEMU has already written down, in the ops
 * it emitted to perform the transfer.  Reading them back says what the
 * emulator DID, which is the only account that cannot disagree with the
 * machine.
 *
 * The vocabulary is small and it is the same on every target, because it is
 * TCG's, not an ISA's:
 *
 *   goto_tb      the successor is a compile-time constant; the ops between
 *                it and the following exit_tb assign that constant to the
 *                program-counter global.  A DIRECT transfer.
 *   goto_ptr     the successor is computed; the value assigned to the
 *                program-counter global before it is the target expression.
 *                An INDIRECT transfer.
 *   two goto_tb  two statically-known successors, so the instruction chose
 *                between them.  CONDITIONAL.
 *   exit_tb only the block ends without a successor QEMU will chain to --
 *                an exception, a syscall, a state change forcing a re-look.
 *                NOT a branch, and reported as its own thing rather than
 *                folded into one.
 *
 * Two derived facts ride along because they are equally structural and no
 * ISA-specific rule is needed for either:
 *
 *   LINK       the instruction publishes its own fall-through address --
 *              writes the constant (vaddr + len) into a guest register, or
 *              stores it to memory.  That is what makes a transfer a CALL,
 *              on every target, whether the return address goes to a link
 *              register (aarch64 bl -> lr, riscv jal -> rd, mips jal -> ra)
 *              or to the stack (x86 call -> a qemu_st of the constant).
 *   SELF       a statically-known successor equal to the instruction's own
 *              address: a self-loop, which is how QEMU lowers a REP string
 *              operation's continuation.
 *
 * And for an indirect transfer, the PROVENANCE of the target expression: the
 * guest register it was read from, and whether a memory load stood between.
 * That is what separates a return from an indirect jump without asking a
 * disassembler -- x86 `ret` loads its target through the stack pointer,
 * aarch64 `ret` reads the link register -- but the RULE is left to the
 * consumer, because which register is "the link register" is a fact about
 * the ABI, not about the transfer.  This reports the register; it does not
 * name it.
 *
 * WHAT BOUNDS AN INSTRUCTION'S OPS.  Not the insn_start markers: the block's
 * epilogue (the interrupt-exit path, and the goto_tb QEMU emits when a block
 * simply ran out of room) is emitted AFTER the last instruction's ops, and a
 * walk bounded by the next marker would attribute it to that instruction --
 * turning every block-ending non-branch into a branch.  The bound is taken
 * from the translator instead: plugin_gen_insn_end() runs immediately after
 * translate_insn() returns and before anything else is emitted, so the op
 * list's tail at that moment is exactly this instruction's last op.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ACCEL_TCG_INSN_CTRL_H
#define ACCEL_TCG_INSN_CTRL_H

#ifdef CONFIG_PLUGIN

struct qemu_plugin_tb;

/*
 * Classify every instruction of the TB currently being translated, from the
 * op ranges plugin_gen_insn_start()/_end() recorded, and leave the answer on
 * each qemu_plugin_insn.  Called from plugin_gen_tb_end() BEFORE the
 * translate callback runs (the plugin reads the answer there) and before
 * plugin_gen_inject() rewrites the op list (which would invalidate the
 * recorded ranges).  Reads only: no op is emitted, altered or suppressed.
 */
void insn_ctrl_classify(struct qemu_plugin_tb *ptb);

#endif /* CONFIG_PLUGIN */

#endif /* ACCEL_TCG_INSN_CTRL_H */
