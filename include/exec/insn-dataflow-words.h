/*
 * The generic words a decode rule may carry.
 *
 * Standalone and dependency-free on purpose: this list is a contract between
 * QEMU's decode sites, which state a word, and a consumer that reads one, and
 * both sides must be able to include it without dragging in the other's world.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXEC_INSN_DATAFLOW_WORDS_H
#define EXEC_INSN_DATAFLOW_WORDS_H

/*
 * A rule's word says what the instruction DOES, in terms that mean the same
 * thing on every target: an aarch64 ADD, an x86 ADD and a MIPS ADDU all carry
 * "int.add".  It is a static property of the rule, stated where the rule is
 * written, and it exists because the ops cannot supply it -- the same
 * add_i64 carries an addition, an address computation and a stack adjustment,
 * and which of those it was is something only the decoder knew.
 *
 * The domain is part of the word rather than inferred from the operands.
 * Inference was the alternative: read the destination's register class and
 * widen "add" into an integer, floating-point or vector addition.  It fails
 * on exactly the instructions a consumer cares about -- a scalar operation on
 * a vector register file, a vector compare writing a general register, an
 * integer multiply accumulating into a floating-point pair -- and it fails
 * silently, because the wrong answer is a plausible one.  A decode rule in
 * QEMU is already domain-specific (FADD and ADD are different rules, and
 * neither is reached by the other's encodings), so the domain costs the
 * decode site nothing and is not guessed anywhere.
 *
 * WHAT IS NOT HERE is as deliberate.  There is no word for atomicity, for a
 * repeat prefix, for a delay slot or for conditionality on a non-branch:
 * those are properties an instruction has in addition to what it does, and
 * they are stated separately (insn_dataflow_note_property(), the transfer
 * bits) so that one instruction can carry several without the vocabulary
 * multiplying out.  There is also no word meaning "unknown": a rule with
 * nothing generic to say states no word at all, which a consumer can tell
 * apart from a rule that was never reached.
 *
 * A word the consumer does not know is not a licence to guess -- see the
 * translation table in contrib/plugins/champsim_tracer, which refuses.
 */
#define INSN_DF_WORD_INT_ADD      "int.add"
#define INSN_DF_WORD_INT_SUB      "int.sub"
#define INSN_DF_WORD_INT_MUL      "int.mul"
#define INSN_DF_WORD_INT_DIV      "int.div"
#define INSN_DF_WORD_INT_MADD     "int.madd"
#define INSN_DF_WORD_INT_MSUB     "int.msub"
#define INSN_DF_WORD_INT_NEG      "int.neg"
#define INSN_DF_WORD_INT_INC      "int.inc"
#define INSN_DF_WORD_INT_DEC      "int.dec"

#define INSN_DF_WORD_AND          "and"
#define INSN_DF_WORD_OR           "or"
#define INSN_DF_WORD_XOR          "xor"
#define INSN_DF_WORD_NOT          "not"
#define INSN_DF_WORD_SHL          "shl"
#define INSN_DF_WORD_SHR          "shr"
#define INSN_DF_WORD_ROL          "rol"
#define INSN_DF_WORD_ROR          "ror"
#define INSN_DF_WORD_BITMANIP     "bitmanip"

#define INSN_DF_WORD_CMP          "cmp"
#define INSN_DF_WORD_TEST         "test"
#define INSN_DF_WORD_CMOV         "cmov"
#define INSN_DF_WORD_SETCC        "setcc"

#define INSN_DF_WORD_MOV          "mov"
#define INSN_DF_WORD_MOVSX        "movsx"
#define INSN_DF_WORD_MOVZX        "movzx"
#define INSN_DF_WORD_XCHG         "xchg"
#define INSN_DF_WORD_LEA          "lea"

#define INSN_DF_WORD_LOAD         "load"
#define INSN_DF_WORD_STORE        "store"
#define INSN_DF_WORD_PUSH         "push"
#define INSN_DF_WORD_POP          "pop"

#define INSN_DF_WORD_FP_ADD       "fp.add"
#define INSN_DF_WORD_FP_SUB       "fp.sub"
#define INSN_DF_WORD_FP_MUL       "fp.mul"
#define INSN_DF_WORD_FP_DIV       "fp.div"
#define INSN_DF_WORD_FP_SQRT      "fp.sqrt"
#define INSN_DF_WORD_FP_MOV       "fp.mov"
#define INSN_DF_WORD_FP_CVT       "fp.cvt"
#define INSN_DF_WORD_FP_CMP       "fp.cmp"
#define INSN_DF_WORD_FP_MADD      "fp.madd"
#define INSN_DF_WORD_FP_MSUB      "fp.msub"
/*
 * A sign edit, and the long-latency operations that are none of the above.
 *
 * fp.neg and fp.abs are separate words rather than one "fp.signop" because
 * they compute different values and every target that has one has both --
 * aarch64 FNEG/FABS, RISC-V fneg.d/fabs.d (the fsgnj family), MIPS neg.d/
 * abs.d, x87 FCHS/FABS.  Neither is a move: the value changes.
 *
 * fp.transcendental is one word for a family whose members differ in what
 * they compute and agree in everything a consumer schedules on -- they run
 * on the same unit, for tens to hundreds of cycles, over the same operands.
 * Splitting it per function would put fsin, fcos, f2xm1 and fyl2x in the
 * vocabulary as four rows that no consumer distinguishes, which is the
 * fragmentation this list is kept short to avoid.
 */
#define INSN_DF_WORD_FP_NEG       "fp.neg"
#define INSN_DF_WORD_FP_ABS       "fp.abs"
#define INSN_DF_WORD_FP_TRANSCENDENTAL "fp.transcendental"

#define INSN_DF_WORD_VEC_ADD      "vec.add"
#define INSN_DF_WORD_VEC_SUB      "vec.sub"
#define INSN_DF_WORD_VEC_MUL      "vec.mul"
#define INSN_DF_WORD_VEC_DIV      "vec.div"
#define INSN_DF_WORD_VEC_SQRT     "vec.sqrt"
#define INSN_DF_WORD_VEC_MOV      "vec.mov"
#define INSN_DF_WORD_VEC_LOAD     "vec.load"
#define INSN_DF_WORD_VEC_STORE    "vec.store"
#define INSN_DF_WORD_VEC_SHUFFLE  "vec.shuffle"
#define INSN_DF_WORD_VEC_LOGIC    "vec.logic"
#define INSN_DF_WORD_VEC_MADD     "vec.madd"
#define INSN_DF_WORD_VEC_MSUB     "vec.msub"
#define INSN_DF_WORD_VEC_PREFETCH "vec.prefetch"

#define INSN_DF_WORD_PREFETCH     "prefetch"
#define INSN_DF_WORD_CACHEFLUSH   "cacheflush"
#define INSN_DF_WORD_TLBFLUSH     "tlbflush"

/*
 * Control transfer.  The reader derives the shape of the transfer from the
 * ops (INSN_DF_X_*); these say the part the ops cannot -- whether a return
 * address was linked, and whether a condition the emitter folded away was
 * ever there.
 */
#define INSN_DF_WORD_JUMP         "jump"
#define INSN_DF_WORD_JUMP_COND    "jump.cond"
#define INSN_DF_WORD_JUMP_REG     "jump.reg"
#define INSN_DF_WORD_CALL         "call"
#define INSN_DF_WORD_CALL_REG     "call.reg"
#define INSN_DF_WORD_RET          "ret"
#define INSN_DF_WORD_SYSCALL      "syscall"

#define INSN_DF_WORD_NOP          "nop"
#define INSN_DF_WORD_FENCE        "fence"

#endif /* EXEC_INSN_DATAFLOW_WORDS_H */
