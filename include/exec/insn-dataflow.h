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

/* The words insn_dataflow_note_word() takes, and the whole list of them. */
#include "exec/insn-dataflow-words.h"

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
 * How many vector-operand statements one instruction may make.
 *
 * Five is the widest gvec expander QEMU has (tcg_gen_gvec_5_*), and an
 * instruction that expands several of them -- a structured load, an SVE
 * sequence -- can exceed this.  The overflow is counted rather than dropped
 * silently, and the operands past it fall back to the unbounded record a
 * bare pointer argument gets.
 */
#define INSN_DF_MAX_VECOPS  12

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

/* Immediate and displacement values one encoding may carry. */
#define INSN_DF_MAX_IMM  4

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
/*
 * The decode site said not to trust this instruction's ops.  A target reaches
 * for this where it translated something whose architectural effect its own
 * op stream does not stand for; saying so is the only honest answer, and it is
 * a refusal rather than a silence so that a consumer cannot mistake the empty
 * result for an instruction that touches nothing.
 */
#define INSN_DF_INCOMPLETE_REFUSED  (1u << 3)

/* Direction of an access. */
#define INSN_DF_RD          1
#define INSN_DF_WR          2

/*
 * A lender that is not in this translation.
 *
 * MIPS can begin a block with a delay slot whose branch was translated in the
 * previous one: the transfer ops are emitted here and belong to an
 * instruction with no row to receive them.  A window opened with this index
 * makes the reader drop those ops rather than charge them to the delay slot,
 * which is the fabrication the borrow exists to prevent.  It is above every
 * index a TB can have -- TCG_MAX_INSNS bounds a block far below it.
 */
#define INSN_DF_NO_LENDER  0xffffu

/*
 * Properties the decoder holds and the ops cannot show.
 *
 * Atomicity is the case in point: the ops of an atomic read-modify-write and
 * the ops of the same arithmetic done in three steps are the same ops.  What
 * makes one atomic is the encoding -- a LOCK prefix, an LL/SC pair, an LSE
 * form -- which only the decoder saw.  Flagging the instruction keeps every
 * register it touches where it was; the flag says how the access happened, not
 * which registers it used.
 */
#define INSN_DF_P_ATOMIC    (1u << 0)

/*
 * The transfer of control this instruction performed, as the translator
 * emitted it.
 *
 * QEMU's own conventions make this readable without a decoder.  goto_tb is
 * used only for a successor whose address the translator knew, so it marks a
 * static edge; lookup_and_goto_ptr is used when the successor is a value, so
 * it marks a computed one; a second static edge is the shape of a conditional
 * branch, whose taken and not-taken sides each get one.  An instruction that
 * emitted none of them performed no transfer, whatever its mnemonic suggests.
 *
 * What this cannot say is what the emitter folded: a condition evaluated at
 * translation time leaves one edge where the architecture has two.  That is
 * why the rule's own word is stated beside this rather than derived from it.
 */
#define INSN_DF_X_TRANSFER  (1u << 0)   /* any transfer op */
#define INSN_DF_X_STATIC    (1u << 1)   /* a successor known at translation */
#define INSN_DF_X_COMPUTED  (1u << 2)   /* the successor is a value */
#define INSN_DF_X_MULTI     (1u << 3)   /* more than one static successor */

/*
 * A value the encoding carries, in the role it plays.
 *
 * IMM is an operand in its own right; DISP is a displacement folded into an
 * address.  Both are stated by the decoder because a fold can consume the
 * value before any op reads it, and once folded there is nothing left in the
 * op stream to read it back from.
 */
#define INSN_DF_IMM_OPERAND  0
#define INSN_DF_IMM_DISP     1

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

/*
 * One operand of a vector expansion: the env range it occupies and the
 * direction the helper uses it in.
 *
 * A gvec helper reaches its operands as pointers built from tcg_env, and a
 * pointer argument says neither how many bytes it spans nor whether the
 * helper reads or writes through it.  The expander knows both -- it computed
 * the offset and it holds oprsz -- so it states them, and the reader uses the
 * statement in place of the unbounded both-directions record the bare pointer
 * would otherwise get.  An operand that is both (an in-place vector op) is
 * stated twice and the directions accumulate.
 */
typedef struct InsnDataflowVecOp {
    uint32_t off;               /* CPUArchState byte offset */
    uint32_t size;              /* bytes of that operand */
    uint8_t  dir;               /* INSN_DF_RD / _WR / both */
} InsnDataflowVecOp;

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

/*
 * How many components one synthetic effective address is built from, and how
 * many such addresses one instruction may name.  x86's modrm reaches two (base
 * and index) and aarch64's register-offset form the same; nothing in tree
 * states more, and an instruction that named a third would be refused rather
 * than recorded short.
 */
#define INSN_DF_MAX_EA_PARTS   4
#define INSN_DF_MAX_SYNTH_EA   2

/*
 * What an address computation does to a component before adding it in.
 *
 * SXTX and a 64-bit register are the same thing, so they share _NONE: this
 * enumerates the transforms that change the value, not the encodings that name
 * them.
 */
#define INSN_DF_EA_EXT_NONE  0  /* the whole register */
#define INSN_DF_EA_EXT_UXTW  1  /* its low 32 bits, zero-extended */
#define INSN_DF_EA_EXT_SXTW  2  /* its low 32 bits, sign-extended */

/*
 * A synthetic address, as the components it is computed from.
 *
 * @memop is the row in memops[] this address belongs to, so a consumer joins
 * the two without guessing; @part_bit indexes the provenance namespace, which
 * is where a component's register already has a name.  A component whose atom
 * resolves to no bit makes the whole row unrecordable -- an address missing one
 * of its terms computes a different address, not an approximate one -- so the
 * row is dropped and counted rather than written short.
 */
typedef struct InsnDataflowSynthEa {
    uint8_t  memop;
    uint8_t  n_parts;
    uint8_t  part_bit[INSN_DF_MAX_EA_PARTS];
    uint8_t  part_shift[INSN_DF_MAX_EA_PARTS];
    uint8_t  part_ext[INSN_DF_MAX_EA_PARTS];
    int64_t  disp;
} InsnDataflowSynthEa;

/*
 * The element size and operand size of a vector instruction.
 *
 * A static fact of the encoding: QEMU's vector expanders are called with vece
 * and oprsz and lower them into ops that no longer carry either.  A consumer
 * modelling per-lane dependence cannot recover them from the ops, so the
 * expander states them.
 *
 * vece is a log2 element size, the same convention TCG uses; INSN_DF_VECE_NONE
 * means no vector expander ran for this instruction, which is different from
 * an element size of one byte.
 */
#define INSN_DF_VECE_NONE  0xff

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
     * The addresses an instruction names and the emulation never computes.
     *
     * Kept beside the memop rows rather than inside them: only a synthetic
     * address has components to carry, and a row on every memop would be
     * empty on almost all of them.  @n_synth_ea_refused counts the addresses
     * that could not be recorded whole, so a consumer never reads their
     * absence as an instruction that named none.
     */
    InsnDataflowSynthEa synth_ea[INSN_DF_MAX_SYNTH_EA];
    uint8_t  n_synth_ea;
    uint8_t  n_synth_ea_refused;

    uint8_t  properties;        /* INSN_DF_P_* */
    uint8_t  xfer;              /* INSN_DF_X_* */

    /*
     * The decode rule the bytes reached, and the generic word that rule
     * carries.  Both are static strings owned by the target; NULL means no
     * rule matched, which is a different answer from a rule that matched and
     * has nothing to say.
     */
    const char *rule;
    const char *word;

    uint8_t  vec_vece;          /* log2 element size, or INSN_DF_VECE_NONE */
    uint32_t vec_oprsz;         /* bytes of one vector operand, 0 if unstated */

    InsnDataflowVecOp vecops[INSN_DF_MAX_VECOPS];
    uint8_t  n_vecops;
    /*
     * Env pointers a vector-operand statement did not cover, and vector
     * operands that did not fit.  Both are the unbounded fallback, and both
     * are counted so a consumer can tell a bounded answer from a blob and
     * this file's own coverage can be measured rather than assumed.
     */
    uint16_t n_env_ptr_bounded;
    uint16_t n_env_ptr_unbounded;
    uint16_t n_vecops_dropped;

    uint64_t imm[INSN_DF_MAX_IMM];
    uint8_t  imm_role[INSN_DF_MAX_IMM];
    uint8_t  n_imm;

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
 * One component of a synthetic effective address.
 *
 * @shift is a LEFT SHIFT and not a multiplier because every form a target
 * states here scales by a power of two -- x86's SIB scale is 1, 2, 4 or 8 and
 * aarch64's register offset is an LSL -- so one field spells both exactly and
 * leaves no way to state a factor the address computation cannot perform.
 *
 * @ext is the narrowing the computation applies first, for the aarch64 forms
 * that index with the low half of a register.
 */
typedef struct InsnDataflowEaPart {
    InsnDataflowAtom atom;
    uint8_t shift;
    uint8_t ext;                /* INSN_DF_EA_EXT_* */
} InsnDataflowEaPart;

static inline InsnDataflowEaPart insn_df_ea(InsnDataflowAtom atom,
                                            unsigned shift, unsigned ext)
{
    InsnDataflowEaPart p = { .atom = atom, .shift = (uint8_t)shift,
                             .ext = (uint8_t)ext };
    return p;
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

/*
 * The most arguments a DEF_HELPER line can carry.
 */
#define INSN_DF_MAX_HELPER_ARGS 7

/*
 * One helper's argument shape, taken from the target's own DEF_HELPER line.
 *
 * @argsize[i] is the bytes of CPUArchState argument i names when its declared
 * type is a pointer to one register -- x86's `Reg *`, and whatever a target
 * spells for the same thing -- and 0 when the type names none.  The numbers
 * come from the compiler (sizeof of the declared pointee), so they cannot
 * drift from the structure they describe.
 */
typedef struct InsnDfHelperArgs {
    const char *name;
    uint8_t nargs;
    uint16_t argsize[INSN_DF_MAX_HELPER_ARGS];
} InsnDfHelperArgs;

/*
 * One helper's adjudicated argument directions.
 *
 * @dirs carries one character per argument: '-' the argument names no
 * register, 'r' the helper reads through it, 'w' it writes through it, 'b'
 * both.  A type cannot say this -- a pointer is a pointer -- so it is
 * adjudicated in the target's checked-in usage data, one reviewable row per
 * helper, and this is the only place that answer comes from.
 */
typedef struct InsnDfHelperDir {
    const char *name;
    const char *dirs;
} InsnDfHelperDir;

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
 * Ops emitted between these two belong to instruction @lender, not to the one
 * being decoded.
 *
 * MIPS is the case this exists for: the branch's transfer is emitted after its
 * delay slot has been translated, so the ops that perform the branch sit
 * inside the delay-slot instruction's range.  Attributing them where they were
 * emitted would give the delay slot a program-counter write it does not
 * perform and take one away from the branch that does.
 */
void insn_dataflow_borrow_begin(unsigned lender);
void insn_dataflow_borrow_end(void);

/* A property of this instruction the ops cannot show. */
void insn_dataflow_note_property(unsigned prop);

/*
 * The decode rule these bytes reached.
 *
 * Emitted by decodetree at each pattern's own dispatch site, after the
 * pattern's translate function has accepted it -- so the name is the rule that
 * actually ran, not a rule that merely matched a mask.  Where decoders nest,
 * the innermost accepts first and its name is the one kept: it is the specific
 * rule, and the outer dispatcher is the table that reached it.
 */
void insn_dataflow_note_rule(const char *name);

/* The generic word that rule carries, stated with the rule. */
void insn_dataflow_note_word(const char *word);

/* Do not trust this instruction's ops; say so rather than publish them. */
void insn_dataflow_refuse(void);

/* A value this encoding carries, in the role it plays. */
void insn_dataflow_note_immediate(uint64_t value, unsigned role);

/* The element and operand size a vector expander was called with. */
void insn_dataflow_note_vec_shape(unsigned vece, uint32_t oprsz);

/*
 * One operand of a vector expansion: where it lives in CPUArchState, how many
 * bytes of it the helper may touch, and whether it is read, written or both.
 *
 * Stated by the expander, which is the only place that holds the offset and
 * oprsz together, and consumed where a helper argument that is a pointer into
 * env would otherwise be recorded as the whole of env, in both directions.
 */
void insn_dataflow_note_vec_operand(uint32_t envofs, uint32_t bytes,
                                    unsigned dir);

/*
 * An effective address the emulation computes no address for.
 *
 * Prefetches and cache-maintenance operations -- x86 prefetch*, aarch64 PRFM
 * and DC CVAU, MIPS PREF and SYNCI -- lower to a NOP or to a bare block exit.
 * There is no memop, so there is nothing for the reader to walk, and a
 * consumer is handed an instruction that names an address in its encoding and
 * touches nothing.  The decode site still holds the operand, so it says so.
 *
 * @parts are the components the address is built from -- each an atom, the
 * shift the computation applies to it and any narrowing extend -- and @disp
 * the displacement added to them.
 *
 * THE SCALE IS CARRIED, and the earlier contract that dropped it was wrong on
 * its own terms.  It said the emulation computes no value here, so there was
 * no value for a scale to be consistent with and a component serving only a
 * reconstruction nobody performs would be a field with no reader.  The first
 * half is true and the second does not follow: the consumer this whole layer
 * exists to serve reconstructs exactly this address and publishes it, and two
 * encodings that differ only in the scale field name two different addresses.
 * Measured on both targets that have the form -- x86 `prefetcht0
 * 0x20(%rax,%rbx,8)` against the same instruction with scale 1, and aarch64
 * `prfm [x0, x1, lsl #3]` against `prfm [x0, x1]` -- the published addresses
 * differ by exactly the scale, so a row without it says an address came from
 * two registers and a displacement while leaving the reader unable to say
 * which address.
 *
 * One shape serves all four targets -- components plus a displacement covers
 * x86's base/index/RIP fold, aarch64's base plus offset or extended index, and
 * MIPS's base plus displacement -- so the note does not diverge per ISA.
 */
void insn_dataflow_note_synthetic_ea(unsigned dir, uint32_t size,
                                     const InsnDataflowEaPart *parts,
                                     unsigned nparts, int64_t disp);

/*
 * Install a target's helper-usage table.
 *
 * @args is the shape the compiler derived, @dirs the adjudication.  The two
 * are joined here and the join REFUSES IN BOTH DIRECTIONS: a helper whose
 * declared arguments include a register pointer and that has no adjudicated
 * row is a gap, and a row naming a helper with no register pointer is a dead
 * rule.  Either aborts with the offending names, because a table that is
 * quietly short answers with the pessimistic blob it exists to replace and
 * nothing would say so.
 */
void insn_dataflow_declare_helper_usage(const InsnDfHelperArgs *args,
                                        unsigned nargs,
                                        const InsnDfHelperDir *dirs,
                                        unsigned ndirs);

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
static inline void insn_dataflow_borrow_begin(unsigned lender)
{ }
static inline void insn_dataflow_borrow_end(void)
{ }
static inline void insn_dataflow_note_property(unsigned prop)
{ }
static inline void insn_dataflow_note_rule(const char *name)
{ }
static inline void insn_dataflow_note_word(const char *word)
{ }
static inline void insn_dataflow_refuse(void)
{ }
static inline void insn_dataflow_note_immediate(uint64_t value, unsigned role)
{ }
static inline void insn_dataflow_note_vec_shape(unsigned vece, uint32_t oprsz)
{ }
static inline void insn_dataflow_note_vec_operand(uint32_t envofs,
                                                  uint32_t bytes,
                                                  unsigned dir)
{ }
static inline void insn_dataflow_note_synthetic_ea(unsigned dir, uint32_t size,
                                                   const InsnDataflowEaPart *p,
                                                   unsigned nparts,
                                                   int64_t disp)
{ }
static inline void insn_dataflow_declare_regfile(const char *const *names,
                                                 unsigned count,
                                                 uint32_t base_off,
                                                 uint32_t stride,
                                                 uint32_t size)
{ }
static inline void insn_dataflow_declare_helper_usage(
    const InsnDfHelperArgs *args, unsigned nargs,
    const InsnDfHelperDir *dirs, unsigned ndirs)
{ }

#endif /* CONFIG_PLUGIN */

#endif /* EXEC_INSN_DATAFLOW_H */
