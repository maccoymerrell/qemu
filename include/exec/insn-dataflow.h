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
 * @ts and @src_ts are TCGTemp pointers, void here for the same reason
 * insn_dataflow_note_memop()'s are.  Capture only; no op is emitted, altered
 * or suppressed, and a target that never calls this is unaffected.
 */
void insn_dataflow_note_folded_reg(const void *ts, const void *src_ts);

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

static inline void insn_dataflow_note_addr_alias(const void *alias_ts,
                                                const void *real_ts)
{ }

static inline void insn_dataflow_note_zero_reg(const void *ts)
{ }

static inline void insn_dataflow_note_folded_reg(const void *ts,
                                                 const void *src_ts)
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
