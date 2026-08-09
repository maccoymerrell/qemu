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
} InsnDataflow;

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

/* The result for instruction @i of the TB just translated, or NULL. */
const InsnDataflow *insn_dataflow_get(unsigned i);

/* Number of TCG globals, i.e. how many bits of the sets are meaningful. */
uint32_t insn_dataflow_prov_field(unsigned bit, bool *valid);

/* True if provenance lost a field to slot exhaustion in this translation. */
bool insn_dataflow_prov_truncated(void);

unsigned insn_dataflow_nregs(void);

/* Name and env offset of global @i, for a consumer building its own map. */
const char *insn_dataflow_reg_name(unsigned i, uint32_t *off, uint32_t *size);

#endif /* EXEC_INSN_DATAFLOW_H */
