/*
 * Per-instruction dataflow, read off the ops the target's translator emitted.
 *
 * A guest instruction's register reads and writes are not something to look
 * up.  They are already written down, exactly, in the ops QEMU produced for
 * it: every TCG op declares how many of its arguments are outputs and how
 * many are inputs, and a temp that is TEMP_GLOBAL based on tcg_env is a guest
 * register at a known offset in CPUArchState.  Walking the ops between two
 * insn_start markers and sorting the globals by argument position gives one
 * instruction's read and write sets, from the machine's own translation of it.
 *
 * This is the machine's answer, not a disassembler's, and the two differ in
 * both directions: it includes reads a decoder misses -- a conditional move
 * preserves its destination, so it reads it -- excludes writes a decoder
 * invents, and reports a write whose value equals what was already there,
 * which no comparison of state before and after can see.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXEC_INSN_DATAFLOW_H
#define EXEC_INSN_DATAFLOW_H

/*
 * Enough bits for every TCG global any in-tree target registers; the largest
 * is MIPS at 128.  A target that outgrows this would lose the globals above
 * the limit, so the reader says so rather than truncating in silence.
 */
#define INSN_DF_REG_WORDS   4
#define INSN_DF_MAX_REGS    (INSN_DF_REG_WORDS * 64)

/*
 * An instruction writing more registers than this is vanishingly rare, and
 * the one that does gets its whole answer refused rather than a prefix of it.
 */
#define INSN_DF_MAX_WRITES  8

/*
 * Why a set may be unavailable.
 *
 * Which way an error in this code falls is decided once, here, because every
 * choice below follows it.  A dependency recorded that does not exist is
 * pessimistic: a consumer serialises two instructions that could have run
 * together and loses some scheduling accuracy, but nothing it computes is
 * wrong.  A dependency MISSED is wrong: a consumer reorders across an edge the
 * machine could not have crossed, and everything downstream of that is
 * unsound.
 *
 * The two are not symmetric and this code does not treat them as though they
 * were.  A truncated set is the second kind, and it is also the shape most
 * likely to pass for a whole one, because it is plausible -- an empty set on
 * an instruction that plainly reads something is not.  So an instruction the
 * reader could not record in full carries a reason here and hands back
 * nothing at all.
 */
#define INSN_DF_INCOMPLETE_WRITES   (1u << 0)   /* more writes than slots */

typedef struct InsnDataflowWrite {
    uint8_t  reg;                           /* index into the globals table */
    /*
     * The registers this write's value came from.
     *
     * A fact, and deliberately not a verdict.  The verdict a consumer usually
     * wants -- did this instruction define the register, or only move it
     * between the fields QEMU represents it in -- depends on which fields
     * stand for one architectural register, and that map belongs to the
     * consumer.  A store into x86's cc_src whose value came from
     * cc_op/cc_dst/cc_src is the flags changing representation, not value; a
     * store into rbx whose value came from rbx is bswap, an ordinary
     * definition.  QEMU cannot tell those apart and does not try.
     *
     * An empty provenance means the value came from nothing the instruction
     * read.  For the program counter that is the direct-versus-indirect
     * branch discriminator; for any register it means the dependency chain is
     * broken, which is what a zeroing idiom does and what hardware
     * special-cases.
     */
    uint64_t prov[INSN_DF_REG_WORDS];
} InsnDataflowWrite;

typedef struct InsnDataflow {
    uint64_t rd[INSN_DF_REG_WORDS];
    uint64_t wr[INSN_DF_REG_WORDS];
    /*
     * A killed value -- TCG told that the temp holding it is dead -- is
     * neither a read nor a write.  On x86 it is how the flag fields an
     * instruction does not define are retired, so folding it into the write
     * set would put cc_src2 in the write set of every add.  It is a fact a
     * consumer can use, so it is kept apart rather than folded into either.
     */
    uint64_t kill[INSN_DF_REG_WORDS];

    InsnDataflowWrite writes[INSN_DF_MAX_WRITES];
    uint8_t  n_writes;
    uint8_t  incomplete;        /* INSN_DF_INCOMPLETE_* */

    /*
     * Helper calls, and guest memory accesses, counted.  What the helper did
     * is opaque at this level -- it is a host function, not ops -- and the
     * count is what lets a consumer tell "this instruction touches nothing"
     * from "this instruction's effects are behind a call".
     */
    uint16_t n_calls;
    uint16_t n_mem_rd;
    uint16_t n_mem_wr;
} InsnDataflow;

#ifdef CONFIG_PLUGIN

/*
 * Read the TB currently being translated and leave each instruction's result
 * where the translation's own callbacks can reach it.
 *
 * Called from translator_loop() after the last op is emitted and before the
 * plugin translate callback runs, so the ops are still exactly what the target
 * produced: tcg_optimize() is entitled to delete an architecturally real write
 * that nothing downstream consumes, and on x86 the whole lazy-flags scheme
 * exists so that it can.
 */
void insn_dataflow_extract(unsigned num_insns);

/* Instruction @i of the TB just translated, or NULL if there is no answer. */
const InsnDataflow *insn_dataflow_get(unsigned i);

/* How many bits of the sets above are meaningful. */
unsigned insn_dataflow_nregs(void);

/* Name and env location of global @i, for a consumer building its own map. */
const char *insn_dataflow_reg_name(unsigned i, uint32_t *off, uint32_t *size);

#else /* !CONFIG_PLUGIN */

/*
 * accel/tcg/insn-dataflow.c is only compiled when plugins are enabled, but
 * translator_loop() is generic code and reaches the reader behind
 * @plugin_enabled -- a runtime flag, not a compile-time one.  With plugins off
 * that flag is a constant false and the call is dead, but it still has to
 * compile, so the entry point gets the same no-op stub plugin-gen.h gives
 * plugin_gen_tb_end() next to it.  Only this one needs a stub: everything else
 * above is reached from plugins/, which is not built either.
 */
static inline void insn_dataflow_extract(unsigned num_insns)
{ }

#endif /* CONFIG_PLUGIN */

#endif /* EXEC_INSN_DATAFLOW_H */
