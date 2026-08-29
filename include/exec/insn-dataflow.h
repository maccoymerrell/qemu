/*
 * Per-instruction dataflow, derived from the IR the target's translator
 * emitted.
 *
 * The register reads and writes of a guest instruction are already stated,
 * exactly, in the ops QEMU produced for it: every TCG op declares how many of
 * its arguments are outputs and how many are inputs, and a temp that is
 * TEMP_GLOBAL based on tcg_env is a guest register at a known offset.  This
 * reads them off, once per translation, so a plugin can have the machine's own
 * answer instead of a disassembler's.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXEC_INSN_DATAFLOW_H
#define EXEC_INSN_DATAFLOW_H

/*
 * Enough bits for every TCG global any in-tree target registers; the largest
 * is MIPS at 128.  A target that outgrows this loses the globals above the
 * limit from the sets, so the extractor records that rather than truncating
 * silently.
 */
#define INSN_DF_REG_WORDS   4
#define INSN_DF_MAX_REGS    (INSN_DF_REG_WORDS * 64)

/*
 * One provenance namespace for both kinds of register.
 *
 * Bits below insn_dataflow_nregs() are TCG globals -- the GPRs, the flags, the
 * things a target registered by name.  Bits at or above it are env byte ranges
 * that no global names, interned per translation block: x86's whole vector
 * file and x87 stack, ARM's V registers, every FP status word.
 * insn_dataflow_prov_field() maps one of the upper bits back to its offset.
 *
 * They share a namespace because they are the same thing.  Splitting them was
 * the first shape of this code and it meant a consumer asking "does this
 * write depend on anything?" got its answer from the provenance for a GPR and
 * from the presence of a read for a vector register -- one question, two
 * mechanisms, and the two disagreed about idioms that differ only in which
 * register file they land in.
 */
#define INSN_DF_MAX_FIELD_SLOTS  64

/*
 * Env state no TCG global names -- x86's vector file and x87 stack, ARM's V
 * registers, every FP status word -- is reached by load and store at a
 * constant offset, or by a pointer built from tcg_env.  Those are carried as
 * offsets and resolved by the consumer, which is the only side that knows
 * what a byte range means.
 */
#define INSN_DF_MAX_FIELDS  24

/*
 * An env byte range whose reach nothing stated.  A helper handed tcg_env, or
 * a pointer this walk could not bound, may touch any of CPUArchState, so the
 * range cannot be named for a register and must not be.
 */
#define DF_FIELD_UNBOUNDED  0xffffffffu

/*
 * How many register FILES a target may declare (see
 * insn_dataflow_declare_regfile()).  One per array of architectural registers
 * that no TCG global names, plus the scalars beside them; the widest in-tree
 * target uses a handful.
 */
#define INSN_DF_MAX_REGFILES  24

/*
 * Representation SELECTORS -- globals that say how a lowered register's
 * other globals are to be read (see insn_dataflow_declare_repr_selector()).
 * One target declares one today; the bound is small on purpose, so a target
 * that starts declaring whole files here shows up as a refused declaration
 * rather than as a silently growing table.
 */
#define INSN_DF_MAX_SELECTORS  8

/* Instructions writing more than this are vanishingly rare; overflow is flagged. */
#define INSN_DF_MAX_WRITES  8

/*
 * THE ORDERED LISTS.
 *
 * The bitmaps above answer "is this register read/written".  A consumer that
 * has to PUBLISH a register LIST needs a second thing the bitmap cannot give
 * it: an order, and one that does not change between two translations of the
 * same encoding.  Sorting a bitmap by register index would supply an order,
 * but it is the TARGET's index, so `add rd,rs1,rs2` and `add rd,rs2,rs1`
 * would come out identical and a mask written against slot 0 would mean a
 * different operand on the two.
 *
 * So the order is recorded rather than reconstructed: each member is appended
 * the first time the extraction observes it, walking the instruction's ops
 * from first to last.  See qemu-plugin-dataflow.h for the contract as a
 * consumer sees it; the two files must agree and this is the shorter half.
 *
 * The bound is per instruction and per direction.  It is above the widest
 * real case in the tree (x86 far-call reads eight globals and two env
 * ranges) with room, and the overflow is FLAGGED rather than truncated for
 * the reason every other set here is: a list short by a member is a missing
 * dependency, and it is the shape most likely to pass for a whole one.
 */
#define INSN_DF_MAX_ORDERED  24

/* @kind of one ordered member. */
#define INSN_DF_ORD_GLOBAL   0  /* a TCG global; @index is its register index */
#define INSN_DF_ORD_FIELD    1  /* a CPUArchState byte range; @index into fields[] */
#define INSN_DF_ORD_DISCARD  2  /* encoding names it, no op carries it; into discards[] */
#define INSN_DF_ORD_ZERO     3  /* the architectural zero register; @index unused */

typedef struct InsnDataflowOrdered {
    uint8_t  kind;
    /*
     * GLOBAL: the register index, the same namespace the bitmaps use.
     * FIELD:  the index into fields[] -- NOT an env offset, because the
     *         field's extent and provenance live there and duplicating
     *         either here would give a consumer two places to read one fact.
     * DISCARD: the index into discards[].
     * ZERO:   unused, and zero.
     */
    uint8_t  index;
} InsnDataflowOrdered;

/*
 * Destinations the encoding names that the emulator discards.  Two is the
 * widest real case in this tree -- MIPS' `mul rd,rs,rt`, whose HI and LO the
 * architecture leaves UNPREDICTABLE -- and four leaves room without making
 * the overflow flag unreachable.
 */
#define INSN_DF_MAX_DISCARDS 4

/* tcg_gen_gvec_5_ool/_ptr is the widest: one destination and four sources. */
#define INSN_DF_MAX_GVEC_OPERANDS 5
/*
 * Guest memory accesses recorded per instruction.  The widest real cases are
 * AArch64's LD4/ST4 (four) and 32-bit x86's PUSHA (eight); beyond that the
 * count is flagged rather than silently short.
 */
#define INSN_DF_MAX_MEMOPS  8

/*
 * The third region of the provenance namespace: the DATA a load returned.
 *
 * Bits below insn_dataflow_nregs() are TCG globals and the bits above it are
 * interned env byte ranges (see below).  The top INSN_DF_MAX_MEMOPS bits are
 * neither: bit INSN_DF_MEMOP_PROV_BASE + k means "the value load slot k
 * returned", which is the fact a post-hoc walk cannot state at all.
 *
 * It has to be a region of the SAME namespace rather than a second bitmap
 * for the reason the fields share it: a consumer asking "where did this
 * value come from" must get one answer, and a value that came half from a
 * register and half from a load is one answer, not two half-answers in two
 * encodings.  The base is fixed rather than following nregs so that a
 * consumer can classify a bit without a second call, and df_intern() stops
 * interning at it so the two regions cannot collide.
 */
#define INSN_DF_MEMOP_PROV_BASE  (INSN_DF_MAX_REGS - INSN_DF_MAX_MEMOPS)

/*
 * The fourth region: the architectural ZERO REGISTER.
 *
 * Three of the four targets this tree traces have one -- AArch64's XZR,
 * RISC-V's x0, MIPS' $zero -- and NONE of them has a TCG global for it.
 * `cpu_reg(s, 31)`, `get_gpr(ctx, 0, ...)` and `gen_load_gpr(t, 0)` each
 * hand back a constant, so an instruction that names the zero register as
 * an operand reads, in the op stream, from nothing at all.
 *
 * That is a QEMU optimisation and not the architecture.  `str xzr, [x0]`
 * stores the value of XZR, which the encoding names as its data operand
 * exactly the way `str x5, [x0]` names X5; that the value is known at
 * translation time is the emulator's business and a downstream simulator's,
 * not this record's.  So the emitters that resolve the operand -- the three
 * accessors above, where the register NUMBER is still in hand -- say so, and
 * the fact reaches a consumer as a provenance bit like any other.
 *
 * One bit rather than a global index because there is only one such
 * register per target and it has no env storage to name: a global index
 * would be a lie about where it lives.  It sits directly below the memop
 * region so that df_intern() -- which already stops before that region --
 * needs one bound moved and no new arithmetic.
 */
#define INSN_DF_ZERO_PROV_BIT    (INSN_DF_MEMOP_PROV_BASE - 1)

/*
 * The fifth region: the instruction's ENCODED IMMEDIATE.
 *
 * A destination whose provenance names registers on an instruction that also
 * carries an immediate poses a question no reading of the register set can
 * answer: did the encoding contribute to this value, or not?  `add $5,(%rax)`
 * and `ldr x0,[x1,#8]` are the two answers, and they are indistinguishable
 * from the register set alone -- the first's FLAGS destination really does
 * depend on the 5, and the second's loaded value does not depend on the 8,
 * which belongs to the ADDRESS and is already carried there.
 *
 * So the fact is stated where it is a fact: at the DECODER, in the emitter
 * that turns the encoding's immediate field into a TCG value.  It is
 * emphatically NOT a bit for "a translation-time constant" -- QEMU
 * synthesises those everywhere, for shift amounts it invented, for masks a
 * lowering needed, for the length of the instruction -- and a bit that meant
 * that would say nothing about the machine.
 *
 * The bit then travels the ordinary provenance dataflow, which is what makes
 * the two cases separate themselves: the address's immediate lands in the
 * address's provenance and the load's destination takes the memop bit
 * instead, while an ALU immediate lands in the destination the ALU wrote.
 *
 * It sits directly below the zero-register bit for that bit's reason: the
 * interning bound moves by one and no new arithmetic is needed.
 */
#define INSN_DF_IMM_PROV_BIT     (INSN_DF_ZERO_PROV_BIT - 1)

typedef struct InsnDataflowField {
    uint32_t off;
    uint16_t size;
    uint8_t  dir;               /* INSN_DF_RD / _WR / both */
    /*
     * Where a written field's value came from, in the same namespace as a
     * register write's provenance.  A field is a register that no TCG global
     * happens to name, and nothing about it is different enough to justify a
     * second way of saying where its value came from.
     */
    uint64_t prov[INSN_DF_REG_WORDS];
} InsnDataflowField;

#define INSN_DF_RD          1
#define INSN_DF_WR          2

/*
 * One guest memory access, as the emitter stated it.
 *
 * @addr_prov and @data_prov are separate because they are separate
 * parameters of tcg_gen_qemu_ld/st_*, and conflating them is exactly what
 * this record exists to stop: the op stream carries a load's address temp as
 * its only input, so a walk over the ops reports `mov (%rbx),%rax` and
 * `mov %rbx,%rax` identically.  Load-to-use -- the edge a consumer modelling
 * a memory hierarchy most needs -- does not survive that.
 *
 * @data_prov is meaningful for a STORE, where the value is an input the op
 * carries.  A load's data provenance is not a set of registers at all: it is
 * the load, and it is stated by giving the loaded value its own provenance
 * bit (INSN_DF_MEMOP_PROV_BASE + slot) rather than by naming the address
 * registers a second time.
 */
typedef struct InsnDataflowMemop {
    uint8_t  is_store;
    uint8_t  size;                          /* access width in bytes */
    /*
     * CP1.  The access is performed INSIDE a called helper, so no qemu_ld /
     * qemu_st op names it and the three flags below say how much of it the
     * helper's usage row could state.
     *
     * Without this the access list is SHORT for every helper-implemented
     * access -- aarch64's MOPS copies and MIPS's unaligned stores move guest
     * memory with the op list naming no access at all -- and a short list is
     * the one error direction that costs a consumer correctness rather than
     * accuracy.
     */
    uint8_t  by_helper;
    /*
     * The helper performs one OR MORE accesses of this direction through
     * this address, and the number is data-dependent.  helper_swr stores one
     * to four bytes according to the address's alignment; a count read off
     * the static call sites would be a number nothing measured, so none is
     * given.  @size is then the width of ONE access, not of the whole.
     */
    uint8_t  count_unbounded;
    /*
     * The address is not one of the helper's arguments -- aarch64's MOPS
     * helpers address through env->xregs[] named by a syndrome word -- so
     * @addr_prov is EMPTY and that emptiness is not evidence of absence.  A
     * consumer that publishes an address dependency must refuse this access
     * rather than read the empty set as "depends on nothing".
     */
    uint8_t  addr_unstated;
    /* The same, for a STORE's value: it did not travel through an argument
     * either, so @data_prov is empty and means "not stated", not "nothing". */
    uint8_t  data_unstated;
    uint64_t addr_prov[INSN_DF_REG_WORDS];  /* what computed the address */
    uint64_t data_prov[INSN_DF_REG_WORDS];  /* what produced it: stores */
} InsnDataflowMemop;

/*
 * A destination the ENCODING names that the op stream does not carry.
 *
 * TWO CAUSES, and they are opposite claims about the same absent op, so the
 * row says which.  The emulator DISCARDED the write -- see
 * insn_dataflow_note_discarded_write() -- or the emulator PERFORMS it through
 * a runtime index no op names, see insn_dataflow_note_indexed_write().
 *
 * @reg is the architectural register's name in the target's own namespace --
 * the same strings insn_dataflow_reg_name() and insn_dataflow_field_reg()
 * produce -- because a discarded register has neither a TCG global nor an env
 * byte range to be named by, and inventing a third vocabulary for it would
 * make the consumer's name-to-register map incomplete in a way nothing
 * measures.  An indexed write names the same way for the same reason from the
 * other side: the global exists, but which one it is is a value the encoding
 * carries and the op list does not.
 */
typedef struct InsnDataflowDiscard {
    /*
     * The architectural name, or NULL when @zero_reg says which register it
     * is.  The zero register has no name in QEMU's namespace on every target
     * that has one -- AArch64's XZR is not a GDB register and MIPS' `zero`
     * only is by accident of the XML -- so it is identified the way the READ
     * side already identifies it (insn_dataflow_prov_zero_reg): by being the
     * one register that needs no name.
     */
    const char *reg;
    uint8_t  zero_reg;
    /*
     * The emulator PERFORMS this write; it is not thrown away.  Set by
     * insn_dataflow_note_indexed_write() and STICKY across the merge, on the
     * same discipline InsnDataflowWrite.supplies_value uses: a register
     * stated twice, once as discarded by one lowering arm and once as
     * performed by another, has been performed.
     *
     * A consumer that only wants "what does this instruction write" may
     * ignore it; a consumer counting the emulator's dead-code elimination
     * must not, and the two counts are what it exists to keep apart.
     */
    uint8_t  by_index;
    uint64_t prov[INSN_DF_REG_WORDS];   /* where the value came from */
} InsnDataflowDiscard;

typedef struct InsnDataflowWrite {
    uint8_t  reg;                           /* index into the globals table */
    /*
     * An emitter said this write SUPPLIES a value (see
     * insn_dataflow_note_supplied_value()).  Sticky across the merge below:
     * a register written twice, once by a lowering that only re-expressed it
     * and once by an emitter that put a new value in, has had a value put in
     * it.
     */
    uint8_t  supplies_value;
    uint64_t prov[INSN_DF_REG_WORDS];       /* registers the value came from */
} InsnDataflowWrite;

typedef struct InsnDataflow {
    uint64_t rd[INSN_DF_REG_WORDS];
    uint64_t wr[INSN_DF_REG_WORDS];
    /*
     * A value that has been killed -- TCG told its temp is dead -- is neither
     * a read nor a write, and on x86 it is how the flag fields an instruction
     * does not define are retired.  It is a fact a consumer can use, so it is
     * kept apart rather than folded into either set.
     */
    uint64_t kill[INSN_DF_REG_WORDS];
    /*
     * Where each written register's value came from.
     *
     * This is a fact and deliberately not a verdict.  The verdict a consumer
     * usually wants -- "did this instruction really define the register, or
     * only move it between the fields QEMU represents it in" -- cannot be
     * reached from here, because it depends on which fields stand for one
     * architectural register, and that is the consumer's map, not QEMU's.
     * x86 is the case in point: a store into cc_src whose value came from
     * cc_op/cc_dst/cc_src is gen_compute_eflags() changing the flags'
     * representation and not their value, but a store into rbx whose value
     * came from rbx is bswap, which is an ordinary definition.  The two are
     * indistinguishable without knowing that the four cc_ fields are one
     * register and rbx is one register on its own.
     *
     * So the provenance goes across whole and the grouping is applied on the
     * far side.  An empty provenance is a constant, which for the program
     * counter is the direct-versus-indirect branch discriminator.
     */
    InsnDataflowWrite writes[INSN_DF_MAX_WRITES];
    uint8_t  n_writes;
    uint8_t  writes_overflow;

    /*
     * The writes the emulator threw away.  Kept apart from writes[] because
     * they are named differently and for no other reason: writes[] is indexed
     * by TCG global and these registers have none, which is the whole fact
     * that puts them here.  A consumer building a destination LIST must read
     * both; one reading only writes[] is short by exactly the registers the
     * ISA says the instruction writes and QEMU had no storage to write them
     * to.
     */
    InsnDataflowDiscard discards[INSN_DF_MAX_DISCARDS];
    uint8_t  n_discards;
    uint8_t  discards_overflow;

    /*
     * THE SAME FACTS, IN THE ORDER THE TRANSLATION STATED THEM.
     *
     * Not a permutation of rd[]/wr[]: those are indexed by TCG global and
     * these lists also carry the members a global cannot name -- a
     * CPUArchState byte range, and the architectural zero register, which on
     * every target that has one is a constant with no global at all.  A
     * consumer building a register LIST from the bitmaps alone is short by
     * exactly those, which is why the lists exist rather than an ordering
     * hint beside the bitmaps.
     *
     * A member appears ONCE, at the position of its first observation.  See
     * INSN_DF_MAX_ORDERED for what the bound means and why the overflow is
     * flagged rather than truncated.
     */
    InsnDataflowOrdered rd_ord[INSN_DF_MAX_ORDERED];
    uint8_t  n_rd_ord;
    uint8_t  rd_ord_overflow;
    InsnDataflowOrdered wr_ord[INSN_DF_MAX_ORDERED];
    uint8_t  n_wr_ord;
    uint8_t  wr_ord_overflow;

    InsnDataflowField fields[INSN_DF_MAX_FIELDS];
    uint8_t  n_fields;
    uint8_t  fields_overflow;
    uint8_t  n_mem_rd;
    uint8_t  n_mem_wr;
    uint8_t  n_calls;
    /*
     * CP-H -- how much of this instruction's helper work the emitter was
     * able to state, and how much is an over-approximation standing in for
     * it.  An instruction that calls no helper is EXACT trivially.
     *
     * This is a LABEL, not a verdict on correctness.  An APPROX set is still
     * sound in the pessimistic direction -- it names operands that may not
     * be touched, never omits ones that are -- but a consumer that treats it
     * as exact will believe a dependency that is not there, so it is told.
     */
    uint8_t  helper_model;
    /*
     * How many (helper, pointer argument) pairs this instruction reached
     * whose direction the per-helper usage table does not state.  A count,
     * because "some" is the adjective this project keeps having to unlearn.
     */
    uint8_t  n_helper_unknown;
    /*
     * Helper calls on this instruction whose FOOTPRINT nothing bounds: the
     * helper was handed tcg_env, or a pointer that is not tcg_env plus a
     * constant, or it is not declared TCG_CALL_NO_RWG -- in which case QEMU's
     * own liveness treats it as reading and writing EVERY global
     * (la_global_kill / la_global_sync, tcg/tcg.c), while the op list names
     * none of them.
     */
    uint8_t  n_helper_unbounded;
    /*
     * A helper WROTE a register file whose element the reader could not
     * name: `env->xregs[mops_destreg(syndrome)]`, where the index is
     * computed at run time.  The write is accounted for -- the range covers
     * the file -- and no element of it can be published, so the write set
     * this instruction states is a SUPERSET of the registers it names.
     *
     * A consumer that merely FILLS its own destination list from these rows
     * is unaffected.  A consumer that REPLACES its list with them must
     * refuse this instruction, because "somewhere in the general file" is
     * not the same claim as "these registers" and publishing the named
     * subset as though it were complete would be a missing dependency.
     */
    uint8_t  helper_writes_unbounded;

    /*
     * THE ENCODED IMMEDIATE, as a pair of facts rather than one.
     *
     * @imm_stated says a decoder on this instruction's path called
     * insn_dataflow_note_encoded_imm() -- the instruction HAS an encoded
     * immediate and the emitter said so.  @imm_reached says the temp it named
     * was then read by an op of this instruction, so the bit had somewhere to
     * go.
     *
     * Both are needed and neither implies the other.  Without @imm_stated a
     * consumer cannot tell "the immediate did not feed this destination" from
     * "no emitter on this path states immediates yet", and the second is a
     * coverage hole that must not be published as the first.  Without
     * @imm_reached it cannot tell that case from the one where the emitter
     * DID state the immediate and QEMU then folded it away before any op saw
     * it -- `addi rd,rs,0` becomes a mov, `andi rd,rs,0xff` becomes an
     * extract -- where the absence of the bit is again the emulator's
     * optimisation and not the machine's.
     *
     * Only @imm_stated && @imm_reached licenses reading a destination without
     * the bit as "the encoding did not contribute to this value".
     */
    uint8_t  imm_stated;
    uint8_t  imm_reached;

    /*
     * A decoder stated that one of this instruction's encoded fields is a
     * field THE ARCHITECTURE DOES NOT DEFINE AS A DATAFLOW OPERAND -- see
     * insn_dataflow_note_encoded_imm_value() and its NON_DATAFLOW role.
     *
     * It answers the one question @imm_stated and @imm_reached together
     * cannot.  MIPS' `teq rs,rt,code` and `break code` carry a software-
     * defined trap code that the architecture never feeds to anything: the
     * exception state the instruction writes is decided by the OPCODE, and
     * QEMU is right never to materialise the field.  Read through the other
     * two flags that instruction is indistinguishable from one whose
     * immediate the emulator FOLDED away -- stated, never reached -- and the
     * fold is an emulator optimisation R7.3 forbids publishing.  They are
     * opposite facts: one says the encoding's contribution was optimised out
     * of the op stream, the other says the architecture never gave it one.
     *
     * Its presence licenses reading a register-only destination mask as
     * COMPLETE.  Its absence licenses nothing, exactly as @imm_stated's
     * absence does: a decoder that has not been reached yet reports 0 and
     * every consumer keeps refusing.
     *
     * GRANULARITY, stated so it cannot be over-read: this is a fact about
     * the INSTRUCTION, the same granularity @imm_stated and @imm_reached
     * already run under.  An instruction carrying two encoded fields, one a
     * dataflow operand and one not, reports both flags and a consumer cannot
     * ask which field the answer is about.  No ISA in the corpus has one;
     * when one appears the note carries the VALUE that distinguishes them
     * and this becomes a count.
     */
    uint8_t  imm_non_dataflow;

    /*
     * How many reads this instruction folded onto a REPRESENTATION CARRIER's
     * register.  See insn_dataflow_note_repr_carrier().  Saturating, and
     * present so the rule's zero is a measurement rather than an assumption:
     * an ISA that declares no carrier reads 0 because it has no subject, and
     * that is a different fact from a declared carrier the walk never folded.
     */
    uint8_t  n_repr_carrier;

    /*
     * The accesses themselves, in the order the target emitted them.
     *
     * n_mem_rd/n_mem_wr count qemu_ld/qemu_st OPS; @n_memops counts the
     * ACCESSES, which is the larger set: an emitter-noted op contributes one,
     * and so does each access a called helper performs itself, which no op
     * names at all (CP1, @memops_by_helper).  For an instruction that calls
     * no such helper the two agree, and @memops_unnoted says so when a
     * qemu_ld/st op could not be matched rather than letting a consumer read
     * the shorter array as though it described every access.
     */
    InsnDataflowMemop memops[INSN_DF_MAX_MEMOPS];
    uint8_t  n_memops;
    uint8_t  memops_overflow;   /* more accesses than there was room for */
    uint8_t  memops_unnoted;    /* an access no emitter note accounted for */
    /*
     * CP1 summaries over @memops, so a consumer can gate without walking.
     *
     * @memops_by_helper is a COUNT and not a flag for the reason the helper
     * counters beside it are: the question a consumer ends up asking is how
     * much of its access list came from a written-down row rather than from
     * an op, and a flag cannot answer that.
     */
    uint8_t  memops_by_helper;
    uint8_t  memops_count_unbounded;  /* >=1 helper access of unstated count */
    uint8_t  memops_addr_unstated;    /* >=1 access whose address is unnamed */
    uint8_t  memops_data_unstated;    /* >=1 store whose value is unnamed */
} InsnDataflow;

/*
 * Every operand of every helper this instruction called is stated by the
 * emitter: which env region, how many bytes, read or written.
 */
#define INSN_DF_HELPER_EXACT    0
/*
 * The operand SET is stated but at least one operand's DIRECTION is not, so
 * it is recorded as read-and-written.  This is the residual DEPMAP_DESIGN.md
 * names: the argument list gives operand IDENTITY, not per-argument USAGE.
 */
#define INSN_DF_HELPER_APPROX   1
/*
 * A helper whose FOOTPRINT nothing bounds.  Either an argument reaches
 * arbitrary CPUArchState -- tcg_env itself, or a pointer that is not tcg_env
 * plus a constant -- or the helper is not declared TCG_CALL_NO_RWG, which is
 * QEMU stating that it reads and/or writes EVERY TCG global.  In the second
 * case the op list names none of those accesses and the extracted read and
 * write sets are SHORT of the truth, which is the one direction this code
 * treats as an error rather than as a loss of accuracy.
 *
 * This is also what the pre-CP-H code produced for every helper, without
 * saying so.
 */
#define INSN_DF_HELPER_OPAQUE   2

/*
 * The ROLE a decoder gives an encoded field it states BY VALUE.
 *
 * insn_dataflow_note_encoded_imm() names a TEMP, which is the whole of what
 * it can say: the emitter materialised the encoding into a temp and the
 * dataflow walk follows the temp.  A field that never becomes a temp is
 * outside its reach entirely, and there are two disjoint reasons a field
 * never becomes one.  They need opposite answers, so the note that states
 * them carries which.
 */
enum {
    /*
     * The value IS an operand of the computation -- it just travels as an
     * ARGUMENT OF AN OP rather than through a temp.  A bitfield extract's
     * position and length, a shift-by-immediate's count, a MOVK's insert
     * position: `tcg_gen_extract_i64(rd, rn, pos, len)` puts pos and len in
     * op->args, where no temp exists to carry a provenance bit, and the
     * destination's value depends on them exactly as it depends on rn.
     */
    INSN_DF_IMM_ROLE_OPERAND = 1,
    /*
     * The architecture defines the field as NOT a dataflow operand, and
     * QEMU is right never to read it.  MIPS' trap and break codes are the
     * class: `teq rs,rt,code` raises with Cause.ExcCode fixed by the opcode
     * and the code left for software to read out of the instruction word,
     * so nothing the instruction writes depends on it.
     */
    INSN_DF_IMM_ROLE_NON_DATAFLOW = 2,
};

#ifdef CONFIG_PLUGIN

/*
 * Run the extraction over the TB currently being translated and leave the
 * per-instruction results where translator_loop()'s caller can hand them to a
 * plugin.  Called from translator_loop() after the last op is emitted and
 * before the plugin's translate callback runs, so the ops are still exactly
 * what the target produced -- tcg_optimize() is entitled to delete an
 * architecturally real write that nothing downstream consumes, and on x86 the
 * whole lazy-flags scheme exists so that it can.
 */
void insn_dataflow_extract(unsigned num_insns);

/*
 * CP4 -- the vector choke point.
 *
 * Eight of the 74 tcg_gen_gvec_* constructors fold a same-register operand
 * away before emitting anything: `if (aofs == bofs)` turns pxor %xmm0,%xmm0
 * into a constant store, and the read of xmm0 never reaches the op stream
 * the extractor walks.  The operands are not lost, though -- they are the
 * constructor's own PARAMETERS, one statement earlier.  So the constructor
 * states them here, and the walk folds them in when it reaches the op this
 * was anchored to.
 *
 * That the result is a constant is a QEMU optimisation, not the
 * architecture: the instruction reads what its encoding names, and whether
 * a downstream simulator breaks that dependency is the simulator's business.
 * Recording it here is what keeps the answer the same whether or not TCG
 * happens to fold -- and where TCG folds moves silently across versions.
 *
 * Capture only.  No op is emitted, altered or suppressed, so generated guest
 * code is bit-identical with this compiled in.
 */
void insn_dataflow_note_gvec(uint32_t dofs, uint32_t aofs, uint32_t bofs,
                             uint32_t oprsz);

/*
 * CP-M -- the memop choke point.
 *
 * qemu_ld_i64 carries ONE input, the address temp, so a post-hoc walk over
 * the ops makes the loaded value's provenance the ADDRESS registers:
 * `mov (%rbx),%rax` becomes indistinguishable from `mov %rbx,%rax`, and
 * load-to-use latency -- the single edge a consumer most needs -- is gone.
 * qemu_st_i64 has no output at all, so a store's data and address
 * provenance are both computed and then dropped.
 *
 * The emitter does not have to derive any of it: `val` is the data and
 * `addr` is the address because they are separate parameters, and `mo`
 * states the width.  So it says so, and nothing downstream has to guess.
 *
 * @val_ts and @addr_ts are TCGTemp pointers, typed void here only so that
 * this header stays includable without tcg/tcg.h.  They are TEMPS, not the
 * TCGv_* handles the emitters take: a TCGv_i32 is an OFFSET from tcg_ctx
 * (see tcgv_i32_temp()), so passing one where a temp is expected records a
 * pointer that matches no temp the walk will ever see.  The recording half
 * of this choke point did exactly that and the mismatch was invisible
 * because nothing read the notes yet.
 *
 * @nval is how many CONSECUTIVE temps hold the value, which the emitter
 * knows and a reader cannot: an i128 is two temps, and on a 32-bit host so
 * is an i64.  A store's data provenance is the union across all of them, and
 * taking only the first would drop half of a 128-bit store's inputs.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
void insn_dataflow_note_memop(const void *val_ts, unsigned nval,
                              const void *addr_ts,
                              unsigned size, bool is_store);

/*
 * CP-M, the ALTERNATE-PATH half -- one architectural access an emitter
 * lowers at TWO code sites.
 *
 * The wire's per-access slot model asks how many accesses ONE EXECUTION of
 * the instruction performs.  A note is taken per emission, and for most
 * lowerings those are the same number.  They are not the same number when a
 * translator peels a copy of the access onto a second, mutually exclusive
 * path: i386's `do_gen_rep()` emits its string operation once for the loop
 * body and once again for the last iteration (`can_loop`, target/i386/tcg/
 * translate.c), so `rep stosq` arrives here with TWO store notes for the one
 * store an iteration performs.  Counting them as two accesses gives the
 * template a slot no execution ever fills -- a fabricated dependency with an
 * address provenance nothing states.
 *
 * The emitter is the only party that knows the two sites are one access, so
 * it says so.  Take @mark before the FIRST emission; open the scope before
 * the peeled copy and close it after.  Notes taken inside the scope fill the
 * records their counterparts at @mark filled, unioning provenance rather
 * than allocating a record of their own.
 *
 * The mapping is positional: the i-th note inside the scope mirrors the
 * (@mark + i)-th note.  That holds because the two sites emit the same
 * accesses in the same order -- they are the same emitter call.  A note
 * whose counterpart does not exist, or disagrees about direction, falls back
 * to allocating its own record: an unmatched alternate is reported as an
 * access rather than silently dropped.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
unsigned insn_dataflow_memop_mark(void);
void insn_dataflow_note_path_alt(unsigned mark);
void insn_dataflow_note_path_alt_end(void);

/*
 * CP-M, the address half -- an access QEMU routes through a temp of its own.
 *
 * Three translators lower store-conditional onto a compare-exchange whose
 * ADDRESS parameter is the reservation monitor rather than the register the
 * guest instruction names:
 *
 *   target/arm/tcg/translate-a64.c:3008,3027,3045   cpu_exclusive_addr
 *   target/mips/tcg/translate.c:2238                cpu_lladdr
 *   target/riscv/insn_trans/trans_rva.c.inc:74      load_res
 *
 * So `stxr w2, w0, [x1]` states an address provenance of `exclusive_addr`
 * and not of x1, and a consumer is handed an address dependency on a
 * register no guest instruction ever writes -- while the edge a renaming
 * regfile must actually respect, x1 to this store's address, is absent.  A
 * short set is the one error direction that costs correctness rather than
 * accuracy, so it is not left standing.
 *
 * The equality is not inferred and not pattern-matched.  Every one of those
 * three sites is dominated by its own brcond comparing the monitor against
 * the guest-derived temp, and the access is emitted only on the edge where
 * they are equal:
 *
 *   translate-a64.c:2972   brcond NE clean_addr, cpu_exclusive_addr -> fail
 *   translate.c:2230       brcond EQ addr,       cpu_lladdr         -> l1
 *   trans_rva.c.inc:66     brcond NE load_res,   src1               -> l1
 *
 * The note is taken on that edge, so the emitter states a fact its own
 * control flow has just proved: for the accesses that follow, @alias_ts and
 * @real_ts hold the same address, and @real_ts is the one in the guest's
 * namespace.  Address provenance is then read off @real_ts.
 *
 * It SUBSTITUTES rather than unions.  A monitor is not a register -- the
 * reservation is a property of the instruction, not of any regfile entry --
 * so naming it beside the guest register would keep exactly the dependency
 * this exists to remove.
 *
 * Scoped to the accesses emitted after it: each memop note records how many
 * aliases had been stated when it was taken, and resolution searches only
 * those, most recent first.  Two store-conditionals in one TB therefore
 * cannot borrow each other's address.
 *
 * @alias_ts and @real_ts are TCGTemp pointers, void here for the same reason
 * insn_dataflow_note_memop()'s are.  Capture only; no op is emitted, altered
 * or suppressed, and a target that never calls this is unaffected.
 */
void insn_dataflow_note_addr_alias(const void *alias_ts, const void *real_ts);

/*
 * CP-M, the ZERO-REGISTER half -- an operand QEMU resolves to a constant.
 *
 * `str xzr, [x0]`, `sd x0, 0(a0)` and `sw $zero, 0($a0)` all name a register
 * as the data operand of a store, and all three translators resolve it to a
 * constant before the store emitter ever sees it:
 *
 *   target/arm/tcg/translate-a64.c   cpu_reg(s, 31)      movi 0 into a temp
 *   target/arm/tcg/translate-a64.c   read_cpu_reg(s, 31) movi 0 into a temp
 *   target/riscv/translate.c         get_gpr(ctx, 0, _)  ctx->zero
 *   target/mips/tcg/translate.c      gen_load_gpr(t, 0)  movi 0 into @t
 *
 * So the store's data provenance, read off the ops, is EMPTY -- and a
 * consumer is told the stored value came from nowhere, when the instruction
 * says where it came from and a renaming regfile has an entry for it.
 *
 * The note is taken AT THE ACCESSOR, which is the one place the register
 * NUMBER is still known: by the time the value reaches tcg_gen_qemu_st_* it
 * is a temp like any other and no amount of walking recovers which register
 * it stood for.  @ts is the temp the accessor is about to return.
 *
 * It states an operand, not a value.  A consumer that wants to model the
 * folding away is welcome to -- that is a microarchitectural decision, and
 * making it here would put the emulator's optimisation on the wire as though
 * it were the machine.
 *
 * @ts is a TCGTemp pointer, void here for the same reason
 * insn_dataflow_note_memop()'s are.  Capture only; no op is emitted, altered
 * or suppressed, and a target that never calls this is unaffected.
 */
void insn_dataflow_note_zero_reg(const void *ts);

/*
 * CP-M, the DISCARDED-WRITE half -- a destination the ENCODING names and the
 * emulator does not keep.
 *
 * `cmp x0,x1` IS `subs xzr,x0,x1`; `tst`/`cmn` are `ands`/`adds` into the same
 * place.  The encoding names XZR as the destination register, and QEMU hands
 * the emitter a throwaway temp for it (cpu_reg(s, 31)) because the value has
 * nowhere to go.  MIPS `mul rd,rs,rt` is the same shape from the other side:
 * the architecture leaves HI and LO UNPREDICTABLE, which is the ISA saying the
 * multiplier destroyed them, and QEMU -- correct to emulate, since nothing may
 * read them -- writes neither.  `move $zero,$ra` is the smallest case of all:
 * gen_logic() sees rd == 0 and emits no op at all.
 *
 * In every one of those the op list carries NO write, so a walk over the ops
 * reports a destination set SHORT of what the instruction names.  That is a
 * missing dependency for any consumer that keeps a scoreboard: XZR and $zero
 * are architecturally written (R7.3 -- "REG_ZERO exists, so it should be
 * specified"), and a destroyed HI/LO is a WAW hazard against the next `mfhi`
 * whether or not the value is defined.  R2 decides it: what the ISA says the
 * instruction writes is the machine's, and that the emulator can prove nobody
 * will look is the emulator's business.
 *
 * THE NOTE IS THE WRITE-SIDE SIBLING OF insn_dataflow_note_zero_reg(), taken
 * at the same kind of place and for the same reason: the accessor or the
 * emitter is where the register NUMBER is still known, and one op later it is
 * not known anywhere.
 *
 * @reg is the architectural register's name in the target's own namespace --
 * the spelling insn_dataflow_reg_name() gives a global and
 * insn_dataflow_field_reg() gives an env range.  It has to be a name rather
 * than an index because these registers have neither a global nor a byte range
 * to index, which is exactly why their writes are invisible.  The pointer must
 * outlive the translation; a string literal is the intended form.
 *
 * @ts is the temp or global whose CONTENTS AT THE END OF THIS INSTRUCTION are
 * the value the architecture writes.  It may be
 *
 *   the throwaway destination itself -- AArch64's cpu_reg(s, 31), which the
 *   flag-setting op writes and nothing reads, so the walk's provenance for it
 *   is exactly the subtraction's inputs;
 *
 *   a register the same computation DID land in -- MIPS' cpu_gpr[rd] on
 *   `mul`, whose provenance is the multiply's two operands, which are the two
 *   operands HI and LO were destroyed by;
 *
 *   or a global the instruction only read -- MIPS' cpu_gpr[rs] on
 *   `move $zero,$rs`, where the emulator emitted nothing and the value that
 *   would have been written is the one it was handed.
 *
 * It states an OPERAND RELATIONSHIP, not a value.  Whether a discarded write
 * is worth a dependency edge is the consumer's decision; making it here would
 * put the emulator's dead-code elimination on the wire as though it were the
 * machine.
 *
 * THE NOTE IS ANCHORED, on the same discipline as the zero-register notes: it
 * records the op its emitter had last produced, and the walk resolves it only
 * inside the instruction whose op range reached it.  Without that a single
 * `cmp` would name XZR as a destination of every later instruction in the
 * block.
 *
 * Capture only; no op is emitted, altered or suppressed, and a target that
 * never calls this is unaffected -- it reports no discarded writes, which is
 * a different fact from "this instruction discards none" only in that nobody
 * looked, and the count says which.
 */
void insn_dataflow_note_discarded_write(const void *ts, const char *reg);

/*
 * The same statement for the ARCHITECTURAL ZERO REGISTER, which needs no name.
 *
 * XZR, x0 and $zero are the one destination no target can spell in the
 * namespace above: AArch64's is not a GDB register at all, and giving it a
 * synthetic row in QEMU's register table would put a register that does not
 * exist into the namespace a consumer READS VALUES from.  The read side
 * already solved this -- a zero-register operand travels as a reserved
 * provenance bit and insn_dataflow_prov_zero_reg() names it -- and the write
 * side uses the same identity rather than inventing a second one.
 *
 * @ts is read exactly as insn_dataflow_note_discarded_write()'s is.
 */
void insn_dataflow_note_discarded_zero_write(const void *ts);

/*
 * The zero register again, from an accessor that CANNOT KNOW whether this use
 * is a read or a write.
 *
 * AArch64's cpu_reg(s, 31) hands out one throwaway temp for both: `cmp x0,x1`
 * writes the subtraction into it and drops it, and `mov x0,xzr` reads it as a
 * source.  The accessor is still the only place the register number is known,
 * so the statement is made there and the walk decides which use it was, by
 * the one thing that separates them: whether an op of this instruction OTHER
 * than the movi that materialised the temp wrote it.
 *
 * Getting that wrong in the permissive direction is not a loss of precision,
 * it is a FABRICATED destination -- `mov x0,xzr` would publish a write to a
 * register it only reads -- so the test is on the op that defines the temp
 * and not on anything softer.
 *
 * @ts is the temp the accessor is about to return, and the note must be taken
 * while the materialising write is still the last op emitted.
 */
void insn_dataflow_note_zero_write_holder(const void *ts);

/*
 * CP-M, the INDEXED-WRITE half -- a destination the emulator writes through
 * an index only the ENCODING states.
 *
 * AArch64's FEAT_MOPS is the whole of the class today.  `cpyfe`, `cpyfm`,
 * `sete` and `setm` hand the helper ONE constant -- the syndrome -- and the
 * helper pulls the three register numbers back out of it and addresses
 * env->xregs[] with them (target/arm/tcg/helper-a64.c).  The op list carries
 * a call and two constants; it carries no write to any GPR at all, and the
 * per-helper usage row can only say `xregs` with INDEX NOT STATED.  So a
 * destination list built from the op stream is SHORT by exactly the
 * registers the instruction's own encoding names, which is the one error
 * direction this file treats as worse than an imprecise one.
 *
 * THIS IS NOT insn_dataflow_note_discarded_write(), and the difference is a
 * fact and not a shade.  A discarded write is one the emulator PROVED nobody
 * would read and therefore did not perform; MOPS' writes are performed, and
 * the next instruction reads them.  Saying so with the discarded-write note
 * would put a performed write into the count of the emulator's dead-code
 * elimination -- a number that then means neither thing.  @by_index carries
 * the separation onto the row.
 *
 * @reg is the architectural name, and it must be a pointer that outlives the
 * translation: the target's own register-name table is the intended form
 * (AArch64's `regnames[]`), which is also what insn_dataflow_reg_name()
 * returns for the same global, so the two vocabularies cannot drift.
 *
 * @ts is read exactly as insn_dataflow_note_discarded_write()'s is -- the
 * temp or global whose provenance at the END of this instruction is where the
 * written value came from.  For MOPS that is a GLOBAL the instruction only
 * READS, so the note resolves to the register itself, and the emitter states
 * the write once per SOURCE it depends on: the rows merge on the register
 * NAME and their provenances union, which is how a value the helper computes
 * from three registers gets all three named without any op having said so.
 *
 * THE ANCHOR IS LOAD-BEARING and it points the other way from the zero
 * register's.  The note must be taken AFTER the helper call is emitted, not
 * before: taken before, the last op produced still belongs to the PREVIOUS
 * instruction and the walk would give the whole statement away to it.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
void insn_dataflow_note_indexed_write(const void *ts, const char *reg);

/*
 * CP-M, the FOLDED-REGISTER half -- a value an emitter derived from a
 * register whose live value it did not have to read.
 *
 * `callq` pushes the return address, which the ISA defines as RIP plus the
 * instruction's length.  x86's eip_next_tl() (target/i386/tcg/translate.c)
 * hands that back three different ways depending on how the block is being
 * translated: under CF_PCREL it emits `addi cpu_eip, delta` and the op stream
 * carries the read, and otherwise it returns tcg_constant_tl(s->pc), because
 * at translation time the value is already known.
 *
 * That difference is the emulator's, not the machine's.  The architectural
 * source of the pushed datum is the instruction pointer in both regimes, so
 * a walk over the ops must not report it as a register read in one and as a
 * value from nowhere in the other -- and "from nowhere" is worse than vague:
 * the format's store-data block reads an empty-and-complete provenance as
 * "the datum came from the instruction's own encoding", so the fold arrives
 * on the wire as an IMMEDIATE.  A consumer is then told the return-address
 * store waits on nothing, when it waits on RIP.
 *
 * THE SAME FOLD REACHES ADDRESSES, and by the same route.  A RIP-relative
 * memory operand is the instruction pointer plus a displacement, and
 * gen_lea_modrm_0() adds s->pc into the displacement at decode time so that
 * gen_lea_modrm_1() can materialise the whole address with one movi.  The
 * empty provenance that leaves behind is not read as an immediate -- an
 * address family has no immediate rule to fire -- it is published as an
 * address that waits on nothing at all, which for the commonest form of
 * access in position-independent code is a dependency simply missing.  The
 * note is taken there too.
 *
 * The note is taken AT THE ACCESSOR, the same place and for the same reason
 * as insn_dataflow_note_zero_reg()'s: the register the value stands for is
 * known there and nowhere downstream.  @ts is the temp the accessor returns
 * and @src_ts is the TCG global whose architectural register it stands for,
 * so this states a fact in the namespace every other provenance uses rather
 * than reserving a bit of its own -- the instruction pointer HAS a global,
 * which is exactly what the zero register does not.
 *
 * It states an operand, not a value.  The consumer decides whether a folded
 * constant is worth a dependency edge; that is a microarchitectural decision
 * and making it here would put the emulator's optimisation on the wire as
 * though it were the machine.  Taking the note in the CF_PCREL arm as well
 * is deliberate and not redundant bookkeeping: it makes the two regimes
 * publish the same set by construction instead of by coincidence.
 *
 * A NOTE DESCRIBES A TEMP'S CONTENTS AND EXPIRES WITH THEM.  Unless @ts is a
 * constant -- interned by value, defined by no op, impossible to rewrite --
 * the note is anchored to the op that has just written @ts, and the walk
 * discards it once that temp has been written again.  This matters because
 * x86 computes every address in a block into ONE temp (DisasContext::A0):
 * without the anchor a single RIP-relative access would name the instruction
 * pointer in the address set of every later access in the same block, which
 * is a fabricated dependency and strictly worse than the missing one the
 * note exists to supply.  So call this from the emitter that produced the
 * value, while the write is still the last op emitted.
 *
 * @ts and @src_ts are TCGTemp pointers, void here for the same reason
 * insn_dataflow_note_memop()'s are.  Capture only; no op is emitted, altered
 * or suppressed, and a target that never calls this is unaffected.
 */
void insn_dataflow_note_folded_reg(const void *ts, const void *src_ts);

/*
 * CP-M, the ENCODED-IMMEDIATE half -- the value the instruction's own
 * encoding names, as it becomes a TCG value.
 *
 * WHAT THIS IS FOR.  A wire consumer reading a destination's dependency mask
 * has to know whether the instruction's immediate is one of that
 * destination's sources.  Two candidate rules were tried against the two
 * shapes on the workload and both failed: a blanket "the instruction carries
 * an immediate, so every destination depends on it" is refuted by
 * `ldr x0,[x1,#8]`, whose destination came from the LOAD and whose #8 is the
 * ADDRESS's and already carried in the address's own provenance; and "it
 * depends on the immediate unless the instruction has a load" is refuted by
 * `add $5,(%rax)`, whose FLAGS destination does depend on the 5.  Neither
 * question is answerable from the register set, and both are answerable from
 * the dataflow -- once the immediate is IN it.
 *
 * WHERE IT IS STATED, and why nowhere else.  At the decoder, in the emitter
 * that materialises the encoding's immediate field: x86's X86_OP_IMM operand
 * load, the shared trans_ helpers that turn a decodetree `imm`/`shamt` field
 * into an operand, MIPS' gen_* immediate arguments.  Those are the places
 * where "this value is the instruction's immediate" is a FACT.  One level
 * down it is not: tcg_constant_tl() is called by every part of QEMU for
 * every reason, and a bit set there would mean "a constant appeared", which
 * says nothing about the encoding.  @ts is the temp the emitter is about to
 * use as the immediate operand.
 *
 * It states an OPERAND, not a value.  Whether a consumer models the
 * immediate as a dependency at all is its decision; stating it here is what
 * gives it one to make.
 *
 * THE ANCHOR MAKES IT A FACT ABOUT ONE INSTRUCTION, exactly as
 * insn_dataflow_note_zero_reg()'s does and for a sharper version of the same
 * reason: an immediate is usually a small integer, tcg_constant_tl() interns
 * by value, and a block full of `addi rd,rs,8` and `slli rd,rs,3` resolves
 * every 8 and every 3 to one temp apiece.  A note carrying only the temp
 * would say "somewhere in this TB an 8 was an immediate" and would then
 * name the encoding in the provenance of every later instruction that
 * happened to use an 8 for a reason of QEMU's own.  So the note records the
 * op the emitter had last produced, and the walk resolves a note only inside
 * the instruction whose op range reached it.
 *
 * @ts is a TCGTemp pointer, void here for the same reason
 * insn_dataflow_note_memop()'s is.  Capture only; no op is emitted, altered
 * or suppressed, and a target that never calls this is unaffected -- its
 * instructions report imm_stated = 0 and every consumer of the bit keeps
 * refusing rather than reading the absence as an answer.
 */
void insn_dataflow_note_encoded_imm(const void *ts);


/*
 * CP-M, the encoded-immediate half -- the VALUE-STATING form.
 *
 * WHAT IT IS FOR.  The temp-stating form above can only speak about fields
 * the emitter materialised.  Two populations it cannot reach were measured
 * and filed rather than guessed at (#252): 39 aarch64/mipsel bitfield and
 * shift rows whose immediate is an op ARGUMENT, and the mipsel trap/break
 * rows whose code QEMU correctly never touches.  Both arrive at a consumer
 * as "no decoder on this path states this instruction's immediate", which
 * is a coverage hole -- and a coverage hole is not an answer, so both
 * refuse.  This states the fact the temp form has no temp for.
 *
 * @value is the field as the decoder extracted it and @role is what the
 * architecture makes of it.  The value is recorded rather than dropped
 * because it is what makes this a statement about a FIELD: a note carrying
 * only a role would be an assertion about the instruction that nothing
 * could later separate into its fields, which is the granularity trap
 * @imm_non_dataflow's own comment names.
 *
 * WHERE IT IS STATED, and why nowhere else.  At the decoder, in the
 * function that has the field in hand: MIPS' gen_trap() and its break
 * sibling, gen_bitops(), AArch64's trans_SBFM/UBFM/BFM/MOVK/EXTR.  Those
 * are the places where "this is the instruction's field, and this is what
 * the ISA says it does" is a FACT.  One level down it is not -- an op
 * argument is an integer and says nothing about an encoding.
 *
 * THE ANCHOR, and it means something DIFFERENT for the two roles, which is
 * why they are one call and not two.
 *
 * An OPERAND note is taken AFTER the op that takes the value as an
 * argument has been emitted, so its anchor IS that op, and the walk gives
 * the immediate's provenance bit to that op's result -- the same place the
 * temp form's bit would have landed had a temp existed.  (The temp form is
 * stated BEFORE its op for the mirror-image reason: its anchor has to be
 * the op the consuming op FOLLOWS, so the note is resolvable when the
 * consuming op is walked.)
 *
 * A NON_DATAFLOW note has no consuming op by construction, so its anchor
 * only says WHICH INSTRUCTION spoke -- the same scoping every note here
 * runs under, and the reason a block full of `teq` does not let one
 * instruction's statement answer for the next one's.
 *
 * Capture only; no op is emitted, altered or suppressed, and a target that
 * never calls this is unaffected -- its instructions report
 * imm_non_dataflow = 0 and every consumer keeps refusing rather than
 * reading the absence as an answer.
 */
void insn_dataflow_note_encoded_imm_value(uint64_t value, unsigned role);

/*
 * CP-M, the PRESERVE-READ half -- the read a WRITEBACK performs to carry the
 * bits it is not writing.
 *
 * WHAT THIS IS FOR.  A destination register that appears in its OWN
 * provenance poses a question the op list cannot answer.  `add %rax,%rbx`
 * really does read RBX; `setne %al` does not read RAX, and QEMU emits the
 * identical shape for both -- an op whose output global is also one of its
 * input globals -- because a byte write into a 64-bit register is lowered as
 * a deposit whose background operand is the register.  R7.1 rules on which
 * is which, verbatim: "the fact that a register's upper contents may not be
 * modified does not imply it is a source AND a destination for the
 * instruction unless the instruction specifically takes it as a source."
 *
 * WHERE IT IS STATED, and why nowhere else.  At the WRITEBACK EMITTER, which
 * is the one place that knows it is preserving rather than reading: x86's
 * gen_op_deposit_reg_v(), which every byte- and word-width destination goes
 * through, and MIPS's gen_store_fpr32()/gen_store_fpr32h(), which write one
 * half of a 64-bit FP register.  A structural test on the op cannot stand in
 * for it -- AArch64's MOVK emits the same `deposit d,d,x,pos,len` and the
 * architecture DOES define it as reading Xd, so the same three ops mean
 * opposite things in the two places, and only the emitter knows which it is.
 *
 * @ts is the temp being read as the background, and the note is keyed on the
 * op that has just consumed it, so it strikes out THAT ARGUMENT OF THAT OP
 * and nothing else.  `add %al,%bl` fetches BL as an operand in one op and
 * preserves RBX in another; a note scoped to the instruction would strike
 * out both and lose an architectural edge.
 *
 * ITS ABSENCE IS NOT AN ANSWER AND IS NOT USED AS ONE.  A read nobody marked
 * stays exactly what it was -- an operand read -- so an emitter this call
 * has not reached yet publishes an edge a consumer does not need, which is
 * pessimism, rather than dropping one it does, which is the error direction
 * the extractor may not take.  That is why this note reads the opposite way
 * round from insn_dataflow_note_encoded_imm(): there the absence of a bit
 * had to be qualified by @imm_stated, here it needs no qualification at all.
 *
 * @ts is a TCGTemp pointer, void here for the same reason
 * insn_dataflow_note_memop()'s is.  Capture only; no op is emitted, altered
 * or suppressed.
 */
void insn_dataflow_note_preserve_read(const void *ts, const void *mark);

/*
 * The write just emitted puts a value INTO @ts that did not come from @ts.
 *
 * WHAT THIS IS FOR, and it is one shape.  A consumer reading a lowered
 * register -- one architectural name over several TCG globals -- can tell a
 * change of REPRESENTATION from a change of VALUE by looking at where the
 * write read from: x86's `gen_compute_eflags()` recomputes EFLAGS from
 * cc_op/cc_dst/cc_src/cc_src2 and puts the answer back in cc_src, and every
 * register it names is one of the flags' own globals.  `jcc` does that and
 * writes no flag the ISA defines, which is exactly the right reading.
 *
 * `clc` breaks it.  It materialises, THEN clears CF with
 * `andi cc_src, cc_src, ~CC_C` -- a second write whose only named input is
 * cc_src again, and whose new information is a TRANSLATOR constant that no
 * op names and no encoding carries.  Provenance is a union over the writes,
 * so the two are indistinguishable from the materialisation alone, and the
 * shape reading would delete a flag write the ISA does define.
 *
 * So the emitter that supplied the constant says so.  It is not a mnemonic
 * allowlist and could not be one: what it states is a property of the OP it
 * has just emitted, and the same three ops mean the opposite thing when
 * gen_compute_eflags emits them.
 *
 * ITS ABSENCE IS THE PESSIMISTIC DIRECTION IN THE OTHER FAMILIES AND THE
 * DANGEROUS ONE HERE, which is why the consumer's must-be-0 census exists:
 * a lowered register the wire names as a destination and no write supplied a
 * value to refuses the whole dependency block and is counted, so an emitter
 * this call has not reached shows up as a number rather than as a silently
 * deleted destination.
 *
 * @ts is the global written; @mark bounds the note to the ops this emitter
 * produced, taken with insn_dataflow_mark() before the write is emitted, as
 * insn_dataflow_note_preserve_read()'s is.  Capture only: no op is emitted,
 * altered or suppressed.
 */
void insn_dataflow_note_supplied_value(const void *ts, const void *mark);

/*
 * Temp @ts is a REPRESENTATION CARRIER for the lowered register that TCG
 * global @stands_for_ts belongs to: a redundant spelling of a value that
 * register already holds, kept in a temp because it is only live inside one
 * translation block.
 *
 * WHAT THIS IS FOR, and again it is one shape.  x86 keeps no EFLAGS, and
 * three of the four globals it keeps instead are not quite enough: for the
 * subtract family CF is `CC_SRCT < CC_SRC` unsigned, and CC_SRCT -- the
 * compare's FIRST operand -- is recoverable from cc_dst + cc_src but not
 * present in either.  So the translator caches it, in DisasContext::cc_srcT,
 * and every later flags CONSUMER in the same block reads it.
 *
 * The op list says that read came from the GPR the compare fetched.  It did:
 * `cmp %rbx,%rsi` copies RSI into the carrier, and `cmovb`, `seta` and `setb`
 * two instructions later read the carrier back.  Chasing that provenance
 * publishes RSI as a source of all three -- an edge the architecture does not
 * define, on instructions whose only input is the flags.  TWO INDEPENDENT
 * REFERENCES saw it: gem5's wrong-path leg counted it UNACCOUNTED and PIN's
 * correct-path leg absorbed it as an unexplained tracer superset.
 *
 * WHY THE EMITTER STATES IT AND NOTHING INFERS IT, which is the same answer
 * insn_dataflow_declare_repr_selector() gives.  The carrier is an ordinary
 * temp holding an ordinary value; nothing about `mov cc_srcT,T0` distinguishes
 * it from `mov tmp,T0`.  Only the code that chose to cache the flags in a temp
 * knows that is what the temp is for, so it says so beside the tcg_temp_new()
 * that creates it.
 *
 * THE INSTRUCTION BOUNDARY IS THE DISCRIMINATOR, and it is not a refinement --
 * without it the note would delete real edges.  The same temp is ordinary
 * scratch INSIDE the instruction that fills it: x86's `cmpxchg` loads memory
 * into cc_srcT and writes it back to a register, and `xadd` and `sub`-with-LOCK
 * take their result out of it.  Those reads follow a write this instruction
 * performed and are left exactly as they were.  A read that follows no write of
 * this instruction's is reading a value the PREVIOUS instruction left behind,
 * and emulator-private storage is the only thing that could have carried it
 * there -- architecturally, what crosses an instruction boundary crosses it in
 * a register or in memory.  So that read is a read of @stands_for_ts's
 * register, which is what the carrier is a spelling of.
 *
 * IT ADDS AN EDGE AND CANNOT REMOVE ONE.  The register the carrier stands for
 * enters the read set and the provenance; what leaves is the stale origin,
 * which is the fabricated half.  On the measured witnesses the flags global is
 * read directly as well, so the fold is idempotent there -- the point is the
 * case where it is not.
 *
 * @ts and @stands_for_ts are TCGTemp pointers, void here for the reason every
 * other note's are; @stands_for_ts must be a TEMP_GLOBAL.  Stated once per
 * translation, before any op is emitted.  Capture only: no op is emitted,
 * altered or suppressed.
 */
void insn_dataflow_note_repr_carrier(const void *ts,
                                     const void *stands_for_ts);

/*
 * The emitter's position in the op stream, for bounding a preserve-read note.
 * Opaque: the only thing a caller may do with it is hand it back.
 */
const void *insn_dataflow_mark(void);

/*
 * CP-H -- the helper choke point.
 *
 * INDEX_op_call is the one op whose arguments do not describe themselves.
 * The walk sees a list of temps and a count; it cannot say which of them the
 * helper reads, which it writes, or how many bytes a pointer argument stands
 * for.  So it did the only sound thing available to it and called every
 * pointer argument read-and-written with an extent of zero, and unioned every
 * input's provenance into every output -- which is dep_all_to_all, arrived at
 * by necessity rather than by measurement.
 *
 * tcg_gen_callN has what the walk is missing.  TCGHelperInfo names the helper
 * and states each argument's TYPE, and @args holds the LOGICAL arguments, one
 * per source-level parameter, before i128 splitting and before the sign- and
 * zero-extension temps that stand in for i32 arguments in op->args.  So the
 * emitter states identity, and identity is what the walk cannot recover.
 *
 * It does NOT state usage.  Whether helper H reads, writes or both through
 * its third argument is a static per-helper fact, and until it is written
 * down the set is an over-approximation -- which is why it is LABELLED one
 * (INSN_DF_HELPER_APPROX) rather than published as though it were exact.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
void insn_dataflow_note_helper(const void *call_op, const void *info,
                               const void *ret_ts, const void *const *args);

/*
 * CP1 -- the ACCESSES a helper performs, and why they are stated here.
 *
 * tcg_gen_qemu_ld/st states an access because it emits one.  A helper that
 * moves guest memory emits NO access op at all: aarch64's `cpyfp` calls
 * do_cpyp(), which walks the copy with cpu_ldub_mmuidx_ra() /
 * cpu_stb_mmuidx_ra(), and MIPS's `swr` calls helper_swr(), which stores one
 * to four bytes byte-by-byte.  The op list is then EMPTY of accesses for an
 * instruction that plainly performs them, and every consumer downstream --
 * including the SHAPE gate that compares a decoder's operand list against
 * QEMU's -- reads that emptiness as "there was no access".
 *
 * So the helper's usage row states them, in the same discipline the emitters
 * use: a FACT stream, never a derivation.  What it states is what the call
 * site knows -- the DIRECTION and, when the address travels through one of
 * the helper's own arguments, WHICH argument.  What it does not state, it
 * says it does not state: a helper whose access count is data-dependent
 * carries count_unbounded rather than a fabricated number, and a helper that
 * addresses through CPU state rather than through an argument carries
 * addr_unstated rather than an empty address set that reads as "no
 * dependency".
 *
 * There is no separate emitter call for this: the fact belongs to the
 * HELPER, not to the call, and it is the same for every call site.  It is
 * read off the row insn_dataflow_note_helper() already looks up.
 */

/*
 * CP-H, the vector half -- the out-of-line gvec constructors.
 *
 * tcg_gen_gvec_3_ool(dofs, aofs, bofs, oprsz, ...) builds three pointers into
 * env and hands them to a helper.  After the fact those are three identical
 * pointer arguments; at the constructor they are a DESTINATION, two SOURCES
 * and a WIDTH, because that is what the parameters are called and what the
 * caller passed them for.  Saying so gives the field records their true
 * extent and takes the fabricated write off every source operand.
 *
 * @dir[] carries INSN_DF_WR for the destination and INSN_DF_RD for the
 * sources.  Whether the destination is ALSO read -- an accumulate -- is the
 * per-helper fact above, and the consumer marks the instruction APPROX when
 * the table does not state it.
 *
 * Anchored on the call the constructor has just emitted, so it is taken after
 * @fn returns and not before.
 */
void insn_dataflow_note_gvec_ool(const uint32_t *off, const uint8_t *dir,
                                 unsigned n, uint32_t oprsz);

/*
 * Drop every emitter note.
 *
 * Called from tcg_func_start(), which is where the op list is emptied and so
 * where every note's anchor stops naming anything.  Without it a note taken
 * AFTER the extraction ran -- and plugin instrumentation emits helper calls
 * exactly there, from plugin_gen_tb_end() -- survives into the next
 * translation, where TCGOps are handed out of a recycled pool and a stale
 * anchor address can match a live op belonging to a different instruction.
 */
void insn_dataflow_note_reset(void);

/* The result for instruction @i of the TB just translated, or NULL. */
const InsnDataflow *insn_dataflow_get(unsigned i);

/* Number of TCG globals, i.e. how many bits of the sets are meaningful. */
uint32_t insn_dataflow_prov_field(unsigned bit, bool *valid);

/*
 * Is @bit one of the load-data bits, and if so which access?
 *
 * The mirror of insn_dataflow_prov_field() for the third region of the
 * namespace.  A consumer that does not ask still cannot be misled: a bit it
 * cannot resolve is one it must not attribute to a register, which is the
 * same rule the field bits already impose.
 */
bool insn_dataflow_prov_memop(unsigned bit, unsigned *slot);

/* True if provenance lost a field to slot exhaustion in this translation. */
bool insn_dataflow_prov_truncated(void);

unsigned insn_dataflow_nregs(void);

/* Name and env offset of global @i, for a consumer building its own map. */
const char *insn_dataflow_reg_name(unsigned i, uint32_t *off, uint32_t *size);

/*
 * Declare that @n architectural registers live in CPUArchState at @off, one
 * every @stride bytes, each occupying the first @elem bytes of its slot.
 *
 * The k-th is called @names[k] when @names is given, and "@base<k>"
 * otherwise -- or just "@base" when @n is 1.  Two spellings because two
 * targets number their files and two name them: x86's are xmm0..xmm31 and
 * ARM's v0..v31, while RISC-V's GDB stub calls f10 "fa0" and a rule that
 * pasted a number onto a stem would name a register that does not exist.
 *
 * This is the answer to a question the extractor asks constantly and could
 * not previously answer: an env byte range IS a register, and the offset IS
 * its identity, but inverting one back to the other needs the CPUArchState
 * layout and only the target has that.  So the target says so, once, at the
 * same place and in the same terms it registers its TCG globals -- with
 * offsetof() and sizeof(), which is the compiler reading the struct rather
 * than anyone typing a number.
 *
 * The names are the target's GDB-stub spellings, because that is the
 * namespace insn_dataflow_reg_name() already answers in and a consumer must
 * not have to learn a second one to ask the same question twice.
 *
 * @elem may be smaller than @stride: ARM's ARMVectorReg is 256 bytes of SVE
 * storage of which V<n> is the first 16, and x86's ZMMReg is 64.  The whole
 * slot still belongs to the register, so @elem is the SLOT's extent, not the
 * architectural width -- what it excludes is the padding between files.
 *
 * Idempotent: a target that initialises its TCG globals more than once
 * declares the same files again and the second declaration is dropped.
 */
void insn_dataflow_declare_regfile(const char *base, const char *const *names,
                                   uint32_t off, uint32_t stride,
                                   uint32_t elem, uint32_t n);

/*
 * Declare that TCG global @ts is the SELECTOR of a lowered register's
 * representation: it says how the register's OTHER globals are to be read
 * and carries no part of the architectural value itself.
 *
 * There is one on x86 and, so far, nowhere else.  QEMU does not keep EFLAGS;
 * it keeps cc_op, cc_dst, cc_src and cc_src2, and the architectural value is
 * a FUNCTION of the four.  Three of them hold operands and results -- real
 * pieces of the value -- while cc_op holds which function to apply.  A
 * consumer reading writes as architectural facts therefore sees `ja` define
 * EFLAGS, because materialising the flags for the test writes cc_op (and
 * re-expresses cc_src), and `ja` writes no flag the ISA defines.
 *
 * WHY THE TARGET STATES IT AND NOTHING INFERS IT.  The shape is not
 * recoverable from the op stream: cc_op is written with a constant, and so
 * is the destination of `mov $5,%rax`.  Nothing about the write says which
 * of the two is a value.  Only the code that chose the lowering knows, so it
 * says so here, beside the tcg_global_mem_new() that creates the global --
 * the same place and the same terms insn_dataflow_declare_regfile() uses.
 *
 * R10.1's category, arrived at from the register side rather than the pc
 * side: a QEMU bookkeeping artifact is not architectural information, and
 * publishing it as a destination is not fidelity but noise.  What this does
 * NOT do is touch the value-carrying globals -- cc_dst and cc_src are how
 * `add` states the flags it really does write, and they keep saying so.
 *
 * @ts is a TCGTemp pointer, void here for the reason every other note's is.
 * Idempotent; a second declaration of the same global is dropped.  Capture
 * only: no op is emitted, altered or suppressed.
 */
void insn_dataflow_declare_repr_selector(const void *ts);

/*
 * True when global @i was declared a representation selector above.  The
 * index space is insn_dataflow_reg_name()'s.
 */
bool insn_dataflow_reg_is_repr_selector(unsigned i);

/*
 * Name the register an env byte range belongs to, in the same namespace
 * insn_dataflow_reg_name() answers in.  false when nothing declared covers
 * it, or when the range REACHES BEYOND one register -- an access spanning
 * two of them is not either of them, and naming it for the one it starts in
 * would publish a set short by everything else it touched.
 *
 * @size is the access's extent; DF_FIELD_UNBOUNDED (or a size that leaves
 * the register's slot) always refuses.
 */
bool insn_dataflow_field_reg(uint32_t off, uint32_t size,
                             char *buf, size_t buflen);

/* The same, for a provenance bit: the extent comes from the interned slot. */
bool insn_dataflow_prov_field_reg(unsigned bit, char *buf, size_t buflen);

#else /* !CONFIG_PLUGIN */

/*
 * accel/tcg/insn-dataflow.c is only compiled when plugins are enabled, but
 * translator_loop() is generic code and reaches the extractor behind
 * @plugin_enabled -- a runtime flag, not a compile-time one.  With plugins
 * off that flag is a constant false and the call is dead, but it still has to
 * compile, so the entry point gets the same no-op stub plugin-gen.h gives
 * plugin_gen_tb_end() next to it.  Only the extractor needs one: every other
 * entry point above is reached from plugins/, which is not built either.
 */
static inline void insn_dataflow_extract(unsigned num_insns)
{ }

static inline void insn_dataflow_note_gvec(uint32_t dofs, uint32_t aofs,
                                           uint32_t bofs, uint32_t oprsz)
{ }

static inline void insn_dataflow_note_memop(const void *val_ts, unsigned nval,
                                            const void *addr_ts,
                                            unsigned size, bool is_store)
{ }

static inline unsigned insn_dataflow_memop_mark(void)
{ return 0; }

static inline void insn_dataflow_note_path_alt(unsigned mark)
{ }

static inline void insn_dataflow_note_path_alt_end(void)
{ }

static inline void insn_dataflow_note_addr_alias(const void *alias_ts,
                                                const void *real_ts)
{ }

static inline void insn_dataflow_note_zero_reg(const void *ts)
{ }

static inline void insn_dataflow_note_folded_reg(const void *ts,
                                                 const void *src_ts)
{ }

static inline void insn_dataflow_note_encoded_imm(const void *ts)
{
}
static inline void insn_dataflow_note_encoded_imm_value(uint64_t value,
                                                        unsigned role)
{
}
static inline void insn_dataflow_note_discarded_write(const void *ts,
                                                      const char *reg)
{
}
static inline void insn_dataflow_note_discarded_zero_write(const void *ts)
{
}
static inline void insn_dataflow_note_zero_write_holder(const void *ts)
{
}
static inline void insn_dataflow_note_indexed_write(const void *ts,
                                                    const char *reg)
{ }


static inline void insn_dataflow_note_helper(const void *call_op,
                                             const void *info,
                                             const void *ret_ts,
                                             const void *const *args)
{ }

static inline void insn_dataflow_note_gvec_ool(const uint32_t *off,
                                               const uint8_t *dir,
                                               unsigned n, uint32_t oprsz)
{ }

static inline void insn_dataflow_note_preserve_read(const void *ts,
                                                    const void *mark)
{ }

static inline void insn_dataflow_note_supplied_value(const void *ts,
                                                     const void *mark)
{ }

static inline void insn_dataflow_note_repr_carrier(const void *ts,
                                                   const void *stands_for_ts)
{ }

static inline const void *insn_dataflow_mark(void)
{ return NULL; }

static inline void insn_dataflow_note_reset(void)
{ }

static inline void insn_dataflow_declare_regfile(const char *base,
                                                 const char *const *names,
                                                 uint32_t off, uint32_t stride,
                                                 uint32_t elem, uint32_t n)
{ }

static inline void insn_dataflow_declare_repr_selector(const void *ts)
{ }

static inline bool insn_dataflow_reg_is_repr_selector(unsigned i)
{ return false; }

#endif /* CONFIG_PLUGIN */

#endif /* EXEC_INSN_DATAFLOW_H */
