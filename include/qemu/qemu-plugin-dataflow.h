/*
 * The dataflow statement ABI: what QEMU says about an instruction, for a
 * plugin to read.
 *
 * Everything here is implemented.  Its subject is accel/tcg/insn-dataflow.c,
 * which reads each instruction's register accesses off the ops the target's
 * translator emitted and carries the facts the decode sites stated because no
 * op could.  This file is the boundary those facts cross, and nothing else.
 *
 * Why the API looks defensive
 * ---------------------------
 * The failure it exists to prevent has already happened here.  Raising a
 * per-instruction array's size moved every field after it; the struct crossed
 * the boundary by value and its layout depended on a constant both sides had
 * to agree on out of band, so a plugin built against one value and a QEMU
 * binary built against the other disagreed about where the fields were -- and
 * nothing said so.  There was no error, no version mismatch, no truncation:
 * the plugin read from offsets that held something else and carried on.  What
 * it cost was a stale-binary hunt, because wrong data that looks like data
 * sends you looking at the decoder before it sends you looking at the build.
 *
 * Three rules follow, and everything here obeys them.
 *
 * 1. No bitmap or array crosses inside a struct.  Sets are copied into a
 *    buffer the caller owns and sized.  The number of guest registers is a
 *    target property QEMU knows and the plugin does not, so it cannot be a
 *    compile-time constant on the plugin side at all.
 *
 *    Unlike snprintf, these calls do NOT write a partial answer.  A buffer too
 *    small gets nothing written and a return value saying how much was needed.
 *    That is the failure-direction rule applied to the API surface: a partial
 *    read set is a set with dependencies missing from it, and a consumer
 *    acting on one reorders across edges the machine could not cross.  A
 *    partial set is also the shape most likely to be mistaken for a whole one,
 *    because it is plausible; an empty set on an instruction that plainly
 *    reads something is not.  Refusing to truncate turns a silent wrong answer
 *    into a loud absent one.
 *
 * 2. Structs that do cross are versioned by size.  The caller sets
 *    struct_size; QEMU writes at most that many bytes.  Fields are only ever
 *    appended, so a stale plugin sees a correct prefix and a new plugin
 *    against old QEMU sees a version it can test.
 *
 * 3. Nothing is keyed on a pointer into QEMU's own structures.  The accessors
 *    take (tb, idx) exactly as qemu_plugin_tb_get_insn() does, so no existing
 *    type changes shape and a plugin that never calls these is unaffected.
 *
 * What the data is, and is not
 * ----------------------------
 * It is what the machine did, not what a disassembler says it should have
 * done: it includes reads a decoder misses -- a conditional move preserves its
 * destination, so it reads it -- excludes writes a decoder invents, and
 * reports a write whose value equals what was already there, which no
 * comparison of state before and after can see.
 *
 * It is readable only while the translation that produced it is the current
 * one.  Every accessor checks that, and a plugin that stashes a tb and asks
 * later gets a refusal rather than another block's answer.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_PLUGIN_DATAFLOW_H
#define QEMU_PLUGIN_DATAFLOW_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "qemu/qemu-plugin.h"   /* for the plugin API export marker */

#define QEMU_PLUGIN_DATAFLOW_VERSION 3

/*
 * Returned by any set accessor whose instruction could not be read in full.
 * Distinguishable from every real word count, and chosen so a caller using the
 * return value as a length allocates absurdly rather than subtly -- a bug that
 * fails immediately beats one that computes.
 */
#define QEMU_PLUGIN_DF_INCOMPLETE  UINT32_MAX

/*
 * The version handshake.
 *
 * A plugin passes what it was compiled against; QEMU compares against what it
 * was built with and refuses if they cannot interoperate.  This is the check
 * the moved array did not have: a mismatch that would shift a struct fails
 * loudly at load time rather than producing data that looks right.
 *
 * A plugin should call this once, at install time, and refuse to run if it
 * returns false.  Nothing else in this header is safe to call otherwise.
 */
QEMU_PLUGIN_API
bool qemu_plugin_dataflow_abi_ok(uint32_t plugin_version,
                                 uint32_t field_struct_size,
                                 uint32_t memop_struct_size,
                                 uint32_t status_struct_size);

struct qemu_plugin_tb;

/*
 * The provenance namespace.
 *
 * A bit below qemu_plugin_dataflow_nregs() is a TCG global -- a register the
 * target registered by name, resolvable with qemu_plugin_dataflow_reg_name().
 * A bit at or above it is either a CPUArchState byte range interned for this
 * translation block (qemu_plugin_dataflow_prov_field(), and
 * qemu_plugin_dataflow_field_reg() if the target declared its layout) or one
 * of the three atoms that are not storage at all
 * (qemu_plugin_dataflow_prov_atom()).
 *
 * The three share one namespace with the registers because they answer the
 * same question.  Splitting them was tried: a consumer asking "does this write
 * depend on anything?" then got its answer from provenance for a GPR and from
 * the presence of a read for a vector register -- one question, two
 * mechanisms, and the two disagreed about idioms that differ only in which
 * register file they land in.
 *
 * Indices are stable for the lifetime of the process but are NOT stable across
 * QEMU versions or targets, and the interned range bits are stable only within
 * one translation block.  A consumer that wants to persist either must record
 * the name or the offset alongside.
 */
QEMU_PLUGIN_API
unsigned qemu_plugin_dataflow_nregs(void);
QEMU_PLUGIN_API
const char *qemu_plugin_dataflow_reg_name(unsigned reg, uint32_t *env_offset,
                                          uint32_t *size);
QEMU_PLUGIN_API
bool qemu_plugin_dataflow_prov_field(unsigned bit, uint32_t *env_offset,
                                     uint32_t *size);
QEMU_PLUGIN_API
const char *qemu_plugin_dataflow_field_reg(uint32_t env_offset, uint32_t size);

/* The three provenance bits that do not stand for storage. */
#define QEMU_PLUGIN_DF_ATOM_ZERO   0    /* the architectural zero register */
#define QEMU_PLUGIN_DF_ATOM_IMM    1    /* a value the encoding carries */
#define QEMU_PLUGIN_DF_ATOM_CONST  2    /* any other constant */

QEMU_PLUGIN_API
bool qemu_plugin_dataflow_prov_atom(unsigned bit, uint32_t *atom);

/*
 * Register sets, copied into @words as a bitmap of @nwords 64-bit words.
 *
 * Returns the number of words needed to hold the whole set.  If that exceeds
 * @nwords, NOTHING is written and the caller must ask again with a larger
 * buffer; see rule 1 above for why a partial set is never handed out.
 *
 * Returns QEMU_PLUGIN_DF_INCOMPLETE if this instruction could not be recorded
 * in full.  Nothing is written in that case either, so a caller cannot obtain
 * a set at all without having dealt with incompleteness -- which is the only
 * way to stop a caller that ignores the status accessor from quietly consuming
 * a partial answer as a whole one.  qemu_plugin_insn_dataflow_status() says
 * which limit was hit.
 *
 *   reads   every register the instruction's ops take as an input, plus every
 *           register a decode site stated it reads
 *   writes  every register they name as an output, including a write the
 *           condition made inert: tcg_gen_movcond_* names its destination as a
 *           plain output, and a consumer modelling speculative register
 *           release needs to know the write happened
 *   kills   registers whose value TCG was told is dead.  Neither a read nor a
 *           write; on x86 it is how the flag fields an instruction does not
 *           define are retired, and folding it into either set would put
 *           cc_src2 in the write set of every add
 */
QEMU_PLUGIN_API
unsigned qemu_plugin_insn_reg_reads(const struct qemu_plugin_tb *tb, size_t idx,
                                    uint64_t *words, unsigned nwords);
QEMU_PLUGIN_API
unsigned qemu_plugin_insn_reg_writes(const struct qemu_plugin_tb *tb,
                                     size_t idx,
                                     uint64_t *words, unsigned nwords);
QEMU_PLUGIN_API
unsigned qemu_plugin_insn_reg_kills(const struct qemu_plugin_tb *tb, size_t idx,
                                    uint64_t *words, unsigned nwords);

/*
 * Where a written register's value came from, as a set in the same namespace.
 *
 * A fact, and deliberately not a verdict.  The verdict a consumer usually
 * wants -- did this instruction define the register, or only move it between
 * the fields QEMU represents it in -- depends on which fields stand for one
 * architectural register, and that map belongs to the consumer.  A store into
 * x86's cc_src whose value came from cc_op/cc_dst/cc_src is the flags changing
 * representation, not value; a store into rbx whose value came from rbx is
 * bswap, an ordinary definition.  QEMU cannot tell those apart and does not
 * try.
 *
 * An empty provenance means the value came from nothing at all.  For the
 * program counter that is the direct-versus-indirect branch discriminator; for
 * any register it means the dependency chain is broken, which is what a
 * zeroing idiom does and what hardware special-cases.
 *
 * @reg must be in the write set; anything else is refused.
 */
QEMU_PLUGIN_API
unsigned qemu_plugin_insn_write_prov(const struct qemu_plugin_tb *tb,
                                     size_t idx, unsigned reg,
                                     uint64_t *words, unsigned nwords);

/*
 * State no TCG global names -- x86's vector file and x87 stack, ARM's Z
 * registers, every FP status word -- reached by load and store at a constant
 * offset into CPUArchState or through a pointer built from it.
 *
 * A size of QEMU_PLUGIN_DF_UNBOUNDED means the range was reached through a
 * pointer, so the access does not state its extent.  That is the honest answer
 * and not a zero, which a consumer would read as "no bytes".
 */
#define QEMU_PLUGIN_DF_UNBOUNDED  0xffffffffu

#define QEMU_PLUGIN_DF_RD  1
#define QEMU_PLUGIN_DF_WR  2

typedef struct qemu_plugin_dataflow_field {
    uint32_t struct_size;       /* caller sets to sizeof(*this) */
    uint32_t env_offset;
    uint32_t size;              /* or QEMU_PLUGIN_DF_UNBOUNDED */
    uint32_t dir;               /* QEMU_PLUGIN_DF_RD / _WR */
} qemu_plugin_dataflow_field;

QEMU_PLUGIN_API
unsigned qemu_plugin_insn_fields(const struct qemu_plugin_tb *tb, size_t idx,
                                 qemu_plugin_dataflow_field *out,
                                 unsigned nfields);
QEMU_PLUGIN_API
unsigned qemu_plugin_insn_field_prov(const struct qemu_plugin_tb *tb,
                                     size_t idx, unsigned field,
                                     uint64_t *words, unsigned nwords);

/*
 * Guest memory accesses, one row per access, in the order the instruction
 * performs them.
 *
 * Per access, and not per instruction: an instruction with two accesses
 * computes two addresses, and a consumer modelling either one needs to know
 * which registers THAT address came from.
 *
 * A load's data provenance is empty and stays empty: a loaded datum comes from
 * memory, which is not a register and has no bit here.  Saying otherwise would
 * put the address registers in the datum's dependency set, which is the one
 * substitution a memory model must not make.
 */
typedef struct qemu_plugin_dataflow_memop {
    uint32_t struct_size;       /* caller sets to sizeof(*this) */
    uint32_t dir;               /* QEMU_PLUGIN_DF_RD / _WR */
    uint32_t size;              /* bytes */
} qemu_plugin_dataflow_memop;

QEMU_PLUGIN_API
unsigned qemu_plugin_insn_memops(const struct qemu_plugin_tb *tb, size_t idx,
                                 qemu_plugin_dataflow_memop *out,
                                 unsigned nmemops);
QEMU_PLUGIN_API
unsigned qemu_plugin_insn_memop_addr_prov(const struct qemu_plugin_tb *tb,
                                          size_t idx, unsigned memop,
                                          uint64_t *words, unsigned nwords);
QEMU_PLUGIN_API
unsigned qemu_plugin_insn_memop_data_prov(const struct qemu_plugin_tb *tb,
                                          size_t idx, unsigned memop,
                                          uint64_t *words, unsigned nwords);

/*
 * An address the instruction names and the emulation computes nothing for.
 *
 * A prefetch or a cache-maintenance operation lowers to a NOP or a bare block
 * exit, so its memop row exists only because the decode site stated it, and a
 * consumer that wants the ADDRESS has no ops to read it off.  The components
 * are therefore carried: the registers in the provenance namespace, the left
 * shift applied to each, any narrowing extend, and the displacement.
 *
 * The provenance set alone is not enough and that is not a theoretical point.
 * `prefetcht0 0x20(%rax,%rbx,8)` and `prefetcht0 0x20(%rax,%rbx,1)` have the
 * same components and name addresses 0x77 apart; so do aarch64's `prfm [x0,
 * x1, lsl #3]` and `prfm [x0, x1]`.  A row without the shift says which
 * registers an address came from while leaving its reader unable to say which
 * address.
 *
 * A row is present only when every component resolved and the memop it names
 * was recorded.  An address missing one term is a different address, not an
 * approximate one, so the whole row is withheld and counted in
 * @n_synth_ea_refused rather than handed over short.
 */
#define QEMU_PLUGIN_DF_MAX_EA_PARTS  4

#define QEMU_PLUGIN_DF_EA_EXT_NONE  0   /* the whole register */
#define QEMU_PLUGIN_DF_EA_EXT_UXTW  1   /* its low 32 bits, zero-extended */
#define QEMU_PLUGIN_DF_EA_EXT_SXTW  2   /* its low 32 bits, sign-extended */

typedef struct qemu_plugin_dataflow_ea {
    uint32_t struct_size;       /* caller sets to sizeof(*this) */
    uint32_t memop;             /* the memop row this address belongs to */
    uint32_t n_parts;
    int64_t  disp;
    uint32_t part_reg[QEMU_PLUGIN_DF_MAX_EA_PARTS];
    uint8_t  part_shift[QEMU_PLUGIN_DF_MAX_EA_PARTS];
    uint8_t  part_ext[QEMU_PLUGIN_DF_MAX_EA_PARTS];
} qemu_plugin_dataflow_ea;

QEMU_PLUGIN_API
unsigned qemu_plugin_insn_synthetic_eas(const struct qemu_plugin_tb *tb,
                                        size_t idx,
                                        qemu_plugin_dataflow_ea *out,
                                        unsigned neas);

/*
 * The decode rule these bytes reached, and the generic word that rule carries.
 *
 * NULL from _decode_name() means no rule matched -- which is a different
 * answer from a rule that matched and had nothing to say, and different again
 * from a target whose decoder does not state rules at all.
 */
QEMU_PLUGIN_API
const char *qemu_plugin_insn_decode_name(const struct qemu_plugin_tb *tb,
                                         size_t idx);
QEMU_PLUGIN_API
const char *qemu_plugin_insn_decode_word(const struct qemu_plugin_tb *tb,
                                         size_t idx);
QEMU_PLUGIN_API
bool qemu_plugin_insn_undecoded(const struct qemu_plugin_tb *tb, size_t idx);

/* A value this encoding carries, in the role it plays. */
#define QEMU_PLUGIN_DF_IMM_OPERAND  0
#define QEMU_PLUGIN_DF_IMM_DISP     1

QEMU_PLUGIN_API
bool qemu_plugin_insn_immediate(const struct qemu_plugin_tb *tb, size_t idx,
                                unsigned i, uint64_t *value, uint32_t *role);

/*
 * Everything else the instruction carries, including anything the reading
 * could not represent.
 *
 * A consumer is never left to infer completeness from silence, and is not
 * trusted to ask either: when @incomplete is nonzero the set accessors refuse
 * to hand anything back, so the only way to get data out of an incomplete
 * instruction is to have looked here first.  A set reported complete when it
 * is not is the failure that matters: a dependency recorded that does not
 * exist costs a consumer some scheduling accuracy, while a dependency missed
 * makes it reorder across an edge the machine could not cross.  Those are not
 * symmetric, and a truncated set is the second kind.
 */
#define QEMU_PLUGIN_DF_INC_WRITES   (1u << 0)   /* more writes than slots */
#define QEMU_PLUGIN_DF_INC_FIELDS   (1u << 1)   /* more env ranges than slots */
#define QEMU_PLUGIN_DF_INC_MEMOPS   (1u << 2)   /* more accesses than rows */
#define QEMU_PLUGIN_DF_INC_REFUSED  (1u << 3)   /* the decode site said so */

/* Properties the ops cannot show. */
#define QEMU_PLUGIN_DF_P_ATOMIC     (1u << 0)

/* The transfer of control the translator emitted. */
#define QEMU_PLUGIN_DF_X_TRANSFER   (1u << 0)
#define QEMU_PLUGIN_DF_X_STATIC     (1u << 1)
#define QEMU_PLUGIN_DF_X_COMPUTED   (1u << 2)
#define QEMU_PLUGIN_DF_X_MULTI      (1u << 3)

/* No vector expander ran; different from an element size of one byte. */
#define QEMU_PLUGIN_DF_VECE_NONE    0xff

typedef struct qemu_plugin_dataflow_status {
    uint32_t struct_size;       /* caller sets to sizeof(*this) */
    uint32_t version;           /* QEMU sets to QEMU_PLUGIN_DATAFLOW_VERSION */
    uint32_t incomplete;        /* QEMU_PLUGIN_DF_INC_* */
    uint32_t n_calls;           /* helper calls: opaque at this level */
    uint32_t n_mem_reads;       /* accesses, exact even when rows ran out */
    uint32_t n_mem_writes;
    uint32_t n_writes;          /* rows available from _write_prov() */
    uint32_t n_fields;          /* rows available from _fields() */
    uint32_t n_memops;          /* rows available from _memops() */
    uint32_t n_immediates;      /* rows available from _immediate() */
    uint32_t properties;        /* QEMU_PLUGIN_DF_P_* */
    uint32_t xfer;              /* QEMU_PLUGIN_DF_X_* */
    uint32_t vec_vece;          /* log2 element size, or _VECE_NONE */
    uint32_t vec_oprsz;         /* bytes of one vector operand, 0 if unstated */
    /*
     * How the env pointers a helper was handed were recorded.
     *
     * A gvec expander states each operand's offset, extent and direction, so
     * the pointer is recorded as the vector registers it actually names.
     * Where no statement covered it the range is the whole of CPUArchState in
     * both directions, which is honest and coarse -- and counted here, so the
     * two are never added together and a coarse answer is never read as a
     * measured one.
     */
    uint32_t n_vec_operands;    /* operand statements this instruction made */
    uint32_t n_vec_dropped;     /* statements past the per-instruction limit */
    uint32_t n_env_ptr_bounded;   /* env pointers a statement covered */
    uint32_t n_env_ptr_unbounded; /* env pointers recorded as all of env */
    uint32_t n_synth_ea;          /* rows available from _synthetic_eas() */
    uint32_t n_synth_ea_refused;  /* addresses that could not be recorded */
} qemu_plugin_dataflow_status;

QEMU_PLUGIN_API
bool qemu_plugin_insn_dataflow_status(const struct qemu_plugin_tb *tb,
                                      size_t idx,
                                      qemu_plugin_dataflow_status *out);

#endif /* QEMU_PLUGIN_DATAFLOW_H */
