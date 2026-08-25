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
#define INSN_DF_MAX_FIELDS  8

/* Instructions writing more than this are vanishingly rare; overflow is flagged. */
#define INSN_DF_MAX_WRITES  8

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
    uint64_t addr_prov[INSN_DF_REG_WORDS];  /* what computed the address */
    uint64_t data_prov[INSN_DF_REG_WORDS];  /* what produced it: stores */
} InsnDataflowMemop;

typedef struct InsnDataflowWrite {
    uint8_t  reg;                           /* index into the globals table */
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
     * The accesses themselves, in the order the target emitted them.
     *
     * n_mem_rd/n_mem_wr count qemu_ld/qemu_st ops; @n_memops counts the ones
     * an emitter's note could be matched to.  They are equal in every case
     * the extractor can account for, and @memops_unnoted says so when they
     * are not rather than letting a consumer read the shorter array as
     * though it described every access.
     */
    InsnDataflowMemop memops[INSN_DF_MAX_MEMOPS];
    uint8_t  n_memops;
    uint8_t  memops_overflow;   /* more accesses than there was room for */
    uint8_t  memops_unnoted;    /* an access no emitter note accounted for */
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

static inline void insn_dataflow_note_helper(const void *call_op,
                                             const void *info,
                                             const void *ret_ts,
                                             const void *const *args)
{ }

static inline void insn_dataflow_note_gvec_ool(const uint32_t *off,
                                               const uint8_t *dir,
                                               unsigned n, uint32_t oprsz)
{ }

static inline void insn_dataflow_note_reset(void)
{ }

#endif /* CONFIG_PLUGIN */

#endif /* EXEC_INSN_DATAFLOW_H */
