/*
 * Per-instruction dataflow, read off the ops the target's translator emitted,
 * plus the facts the decode site states because no op carries them.
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
 * Not every fact survives into ops, though, and the ones that do not are
 * stated rather than guessed.  A register an addressing fold consumed is still
 * in the emitter's hand at the fold; an architectural zero register lowers to
 * no op at all; state that lives in CPUArchState with no TCG global naming it
 * is reached at an offset only the target can name.  The five verbs at the
 * bottom of this file are how a decode site says those things, and they are
 * deliberately few: each says WHAT is true and never how to record it.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXEC_INSN_DATAFLOW_H
#define EXEC_INSN_DATAFLOW_H

/*
 * Enough bits for every TCG global any in-tree target registers -- the largest
 * is MIPS at 128 -- plus the env ranges interned per translation block and the
 * three atoms at the top that do not stand for storage at all.
 */
#define INSN_DF_REG_WORDS   4
#define INSN_DF_MAX_REGS    (INSN_DF_REG_WORDS * 64)

/*
 * The three provenance bits that are not registers.
 *
 * They live at the top of the namespace, out of the way of the globals at the
 * bottom and the interned env ranges growing up from nb_globals; interning
 * stops below them.  A value that came from one of these came from somewhere
 * real, so the bit is set rather than left empty -- which keeps an empty
 * provenance meaning the one thing it should, that the dependency chain is
 * broken.
 */
#define INSN_DF_BIT_ZERO    (INSN_DF_MAX_REGS - 1)  /* architectural zero reg */
#define INSN_DF_BIT_IMM     (INSN_DF_MAX_REGS - 2)  /* an encoded immediate */
#define INSN_DF_BIT_CONST   (INSN_DF_MAX_REGS - 3)  /* any other constant */
#define INSN_DF_BIT_LOWEST_ATOM  INSN_DF_BIT_CONST

/* How many distinct env byte ranges one translation block may intern. */
#define INSN_DF_MAX_FIELD_SLOTS  64

/* How many distinct env byte ranges one instruction may touch. */
#define INSN_DF_MAX_FIELDS  16

/*
 * An instruction writing more registers than this is vanishingly rare, and
 * the one that does gets its whole answer refused rather than a prefix of it.
 */
#define INSN_DF_MAX_WRITES  8

/*
 * Guest memory accesses recorded individually.  A string operation or a
 * multi-register load can exceed this; the counts below stay exact when the
 * rows run out, so a consumer is told how many accesses there were even when
 * it cannot be told about each one.
 */
#define INSN_DF_MAX_MEMOPS  16

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
#define INSN_DF_INCOMPLETE_FIELDS   (1u << 1)   /* more env ranges than slots */
#define INSN_DF_INCOMPLETE_MEMOPS   (1u << 2)   /* more accesses than rows */

/* Direction of an access. */
#define INSN_DF_RD          1
#define INSN_DF_WR          2

/*
 * An env byte range no TCG global names: x86's vector file and x87 stack,
 * ARM's Z registers, every FP status word.  Carried as an offset and an extent
 * and resolved by the consumer, which is the only side that knows what a byte
 * range means -- except where the target declared the layout, in which case
 * insn_dataflow_field_reg() names it here.
 *
 * A size of DF_FIELD_UNBOUNDED means the range was reached through a pointer
 * built from tcg_env, so the access does not state its extent.  That is the
 * honest answer and not a zero, which a consumer would read as "no bytes".
 */
#define DF_FIELD_UNBOUNDED  0xffffffffu

typedef struct InsnDataflowField {
    uint32_t off;
    uint32_t size;              /* or DF_FIELD_UNBOUNDED */
    uint8_t  dir;               /* INSN_DF_RD / _WR / both */
    /*
     * Where a written range's value came from, in the same namespace as a
     * register write's provenance.  A field is a register no TCG global
     * happens to name, and nothing about it is different enough to justify a
     * second way of saying where its value came from.
     */
    uint64_t prov[INSN_DF_REG_WORDS];
} InsnDataflowField;

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
     * An empty provenance means the value came from nothing at all.  For the
     * program counter that is the direct-versus-indirect branch
     * discriminator; for any register it means the dependency chain is
     * broken, which is what a zeroing idiom does and what hardware
     * special-cases.
     */
    uint64_t prov[INSN_DF_REG_WORDS];
} InsnDataflowWrite;

/*
 * One guest memory access, in the order the instruction performs them.
 *
 * Per access, not per instruction: an instruction with two accesses computes
 * two addresses, and a consumer modelling either one needs to know which
 * registers that ONE address came from.  Folding them together would say that
 * every address of a two-operand move depends on every register the move
 * reads, which is true of neither.
 *
 * The address provenance is the set the address operand was computed from --
 * the emitter's own arithmetic, followed through the temps.  The data
 * provenance is the set the stored value came from, and is empty on a load:
 * a load's datum comes from memory, which is not a register and has no bit.
 */
typedef struct InsnDataflowMemop {
    uint8_t  dir;               /* INSN_DF_RD / _WR */
    uint8_t  size;              /* bytes */
    uint64_t addr_prov[INSN_DF_REG_WORDS];
    uint64_t data_prov[INSN_DF_REG_WORDS];
} InsnDataflowMemop;

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

    InsnDataflowField fields[INSN_DF_MAX_FIELDS];
    uint8_t  n_fields;

    InsnDataflowMemop memops[INSN_DF_MAX_MEMOPS];
    uint8_t  n_memops;

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

/*
 * What a value is, when a decode site has to say so because no op does.
 *
 * A_REG names a register the target registered with TCG or declared with
 * insn_dataflow_declare_regfile(); the two namespaces are searched in that
 * order, and a name in neither is refused rather than invented.
 */
#define INSN_DF_A_REG    0
#define INSN_DF_A_ENV    1      /* a CPUArchState byte range */
#define INSN_DF_A_ZERO   2      /* the architectural zero register */
#define INSN_DF_A_IMM    3      /* an immediate field of the encoding */
#define INSN_DF_A_CONST  4      /* a constant that is not an encoded field */

typedef struct InsnDataflowAtom {
    uint8_t kind;
    const char *name;           /* A_REG */
    uint32_t off;               /* A_ENV */
    uint32_t size;              /* A_ENV; DF_FIELD_UNBOUNDED if not stated */
} InsnDataflowAtom;

static inline InsnDataflowAtom insn_df_reg(const char *name)
{
    InsnDataflowAtom a = { .kind = INSN_DF_A_REG, .name = name };
    return a;
}

static inline InsnDataflowAtom insn_df_env(uint32_t off, uint32_t size)
{
    InsnDataflowAtom a = { .kind = INSN_DF_A_ENV, .off = off, .size = size };
    return a;
}

static inline InsnDataflowAtom insn_df_zero(void)
{
    InsnDataflowAtom a = { .kind = INSN_DF_A_ZERO };
    return a;
}

static inline InsnDataflowAtom insn_df_imm(void)
{
    InsnDataflowAtom a = { .kind = INSN_DF_A_IMM };
    return a;
}

static inline InsnDataflowAtom insn_df_const(void)
{
    InsnDataflowAtom a = { .kind = INSN_DF_A_CONST };
    return a;
}

/*
 * Ops that are QEMU's bookkeeping rather than the instruction's behaviour.
 *
 * A translator emits more than the guest instruction: a block's exit writes
 * the program counter, and a mid-block pc materialisation exists so a fault
 * can restart.  Neither is an architectural effect of the instruction whose op
 * range happens to contain it.  A window brackets those ops and the reader
 * leaves them out.
 *
 * The two kinds are not interchangeable even though both are ignored: a
 * consumer asking why an op was left out gets a different answer for each.
 */
#define INSN_DF_W_EPILOGUE  0   /* the block's exit sequence */
#define INSN_DF_W_BLOCK_PC  1   /* a pc write that exists so a fault restarts */

#ifdef CONFIG_PLUGIN

/*
 * Open instruction @idx.  Called from translator_loop() before the target
 * decodes, so every statement below lands on the instruction being decoded
 * and nothing has to work out afterwards which one that was.
 */
void insn_dataflow_insn_begin(unsigned idx);

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

/*
 * The instruction being decoded reads, or writes, @a -- though no op says so.
 *
 * This is for facts the emitter holds and the op stream does not: a register
 * an addressing fold consumed before any op saw it, an architectural zero
 * register that lowers to no op at all, a CPUArchState range a helper reaches
 * that the call's arguments do not name.
 */
void insn_dataflow_state_read(InsnDataflowAtom a);
void insn_dataflow_state_write(InsnDataflowAtom a);

/*
 * @ts carries the value of @a.
 *
 * Applied where it was made, not where the reader happens to arrive: the
 * binding is anchored to the op most recently emitted, and the reader applies
 * it at that point in the op stream.  Binding for the whole translation would
 * be wrong in the one direction that matters -- a temp reused later in the
 * block would carry the atom into accesses that never had it, which is a
 * dependency invented out of nothing.
 */
void insn_dataflow_bind(const void *ts, InsnDataflowAtom a);

/* Ops emitted between these two are QEMU's, not the instruction's. */
void insn_dataflow_window_begin(unsigned kind);
void insn_dataflow_window_end(void);

/*
 * Declare a register file that lives in CPUArchState with no TCG global naming
 * it: @count registers named @names, @size bytes each, @stride apart, starting
 * at @base_off.
 *
 * The offsets come from the compiler at the call site -- offsetof and sizeof
 * over the target's own structure -- so they cannot drift from the layout they
 * describe the way a hand-written table would.  A target may call this once
 * per file it has.
 */
void insn_dataflow_declare_regfile(const char *const *names, unsigned count,
                                   uint32_t base_off, uint32_t stride,
                                   uint32_t size);

/* Instruction @i of the TB just translated, or NULL if there is no answer. */
const InsnDataflow *insn_dataflow_get(unsigned i);

/* How many bits of the sets above stand for TCG globals. */
unsigned insn_dataflow_nregs(void);

/* Name and env location of global @i, for a consumer building its own map. */
const char *insn_dataflow_reg_name(unsigned i, uint32_t *off, uint32_t *size);

/* The env range a provenance bit at or above nregs stands for. */
bool insn_dataflow_prov_field(unsigned bit, uint32_t *off, uint32_t *size);

/* The declared name of an env range, or NULL if no target declared it. */
const char *insn_dataflow_field_reg(uint32_t off, uint32_t size);

/* Did interning run out of slots during this translation? */
bool insn_dataflow_fields_truncated(void);

#else /* !CONFIG_PLUGIN */

/*
 * accel/tcg/insn-dataflow.c is only compiled when plugins are enabled, but the
 * translator and the targets reach it from plain code, some of it behind
 * @plugin_enabled -- a runtime flag, not a compile-time one.  With plugins off
 * those calls are dead, but they still have to compile, so every entry point a
 * target or the translator can reach gets a no-op stub.  The read side does
 * not need one: it is reached from plugins/, which is not built either.
 */
static inline void insn_dataflow_insn_begin(unsigned idx)
{ }
static inline void insn_dataflow_extract(unsigned num_insns)
{ }
static inline void insn_dataflow_state_read(InsnDataflowAtom a)
{ }
static inline void insn_dataflow_state_write(InsnDataflowAtom a)
{ }
static inline void insn_dataflow_bind(const void *ts, InsnDataflowAtom a)
{ }
static inline void insn_dataflow_window_begin(unsigned kind)
{ }
static inline void insn_dataflow_window_end(void)
{ }
static inline void insn_dataflow_declare_regfile(const char *const *names,
                                                 unsigned count,
                                                 uint32_t base_off,
                                                 uint32_t stride,
                                                 uint32_t size)
{ }

#endif /* CONFIG_PLUGIN */

#endif /* EXEC_INSN_DATAFLOW_H */
