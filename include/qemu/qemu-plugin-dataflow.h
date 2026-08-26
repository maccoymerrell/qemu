/*
 * Plugin ABI for per-instruction dataflow derived from QEMU's own translation.
 *
 * IMPLEMENTED in plugins/api.c and exported by visibility; the layout rules
 * below are the point of the file and were agreed before anything was built
 * against them.  (This header said "PROPOSED - not yet wired into
 * plugins/api.c" long after api.c grew qemu_plugin_dataflow_nregs() and the
 * PLUGIN_DF_SET accessors, which is the kind of stale claim that sends a
 * reader looking for work already done.)
 *
 * WHAT IS STILL NOT DONE, so the distinction stays visible: champsim_tracer
 * still takes the register and memory dataflow it PUBLISHES from Capstone.
 * What it does call these for is the irdf instrument, which scores the two
 * accounts against each other on every encoding it translates and writes the
 * verdict to a log.  Reading is not substituting: nothing here reaches the
 * wire, and the substitution is the remaining work of the behavioural-oracle
 * arc.
 *
 * Why the API looks defensive
 * ---------------------------
 * The failure it exists to prevent has already happened here.  Raising
 * QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS from 12 to 16 moved every field after the
 * implicit-register arrays.  The struct crossed the boundary by value and its
 * layout depended on a constant both sides had to agree on out of band, so a
 * plugin built against one value and a qemu binary built against the other
 * disagreed about where the fields were -- and nothing said so.  There was no
 * error, no version mismatch, no truncation: the plugin read implicit
 * registers from offsets that held something else and carried on.  What it
 * cost was a stale-binary hunt, because wrong data that looks like data sends
 * you looking at the decoder before it sends you looking at the build.
 *
 * Every rule below is that lesson.  A future reader changing this file should
 * know that the alternative was tried and this is what it cost.
 *
 * Three rules follow from that, and everything here obeys them.
 *
 * 1. No bitmap or array crosses the boundary inside a struct.  Sets are copied
 *    into a buffer the caller owns and sized.  The number of guest registers
 *    is a target property QEMU knows and the plugin does not, so it cannot be
 *    a compile-time constant on the plugin side at all.
 *
 *    Unlike snprintf, these calls do NOT write a partial answer.  A buffer too
 *    small gets nothing written and a return value saying how much was needed.
 *    That is deliberate and it is the failure-direction rule applied to the
 *    API surface: a partial read set is a set with dependencies missing from
 *    it, and a consumer that acts on one reorders across edges the machine
 *    could not cross.  A partial set is also the shape most likely to be
 *    mistaken for a whole one, because it is plausible.  An empty set on an
 *    instruction that plainly reads something is not plausible, so it gets
 *    noticed.  Refusing to truncate converts a silent wrong answer into a
 *    loud absent one.
 *
 * 2. Structs that do cross are versioned by size.  The caller sets
 *    struct_size; QEMU writes at most that many bytes and zeroes any tail it
 *    does not know about.  Fields are only ever appended.  A stale plugin sees
 *    a correct prefix; a new plugin against old QEMU sees zeroes where the new
 *    fields would be and a version it can test.
 *
 * 3. Nothing is keyed on a pointer into QEMU's own structures.  The accessors
 *    take (tb, idx) exactly as qemu_plugin_tb_get_insn() does, so no existing
 *    type changes shape and a plugin that never calls these is unaffected.
 *
 * What the data is
 * ----------------
 * The register reads and writes of a guest instruction, read off the TCG ops
 * the target's translator emitted, before any optimisation pass has touched
 * them.
 *
 * This does not replace a disassembler and is not meant to.  A consumer still
 * needs to know WHICH instruction it is looking at -- the mnemonic, the opcode
 * taxonomy built on it, the branch class, the length -- and that still comes
 * from decoding the bytes.  What this replaces is the other half: which
 * registers were read and written, which operands are implicit or tied, which
 * way a memory operand goes.  Those are facts about behaviour, the machine
 * already states them, and asking a decoder to restate them is where the
 * disagreements have always been.  It is what the machine does, not what a disassembler says it should:
 * it includes reads a decoder misses (a conditional move preserves its
 * destination, so it reads it), excludes writes a decoder invents, and reports
 * a write whose value equals what was already there, which no comparison of
 * state before and after can see.
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
 * Returned by any set accessor whose instruction could not be extracted in
 * full.  Distinguishable from every real word count, and chosen so that a
 * caller using the return value as a length allocates absurdly rather than
 * subtly -- a bug that fails immediately beats one that computes.
 */
#define QEMU_PLUGIN_DF_INCOMPLETE  UINT32_MAX

/*
 * The version handshake.
 *
 * A plugin passes what it was compiled against; QEMU compares against what it
 * was built with and refuses if they cannot interoperate.  This is the check
 * that MAX_IREGS did not have: a mismatch that would have shifted a struct
 * must fail loudly at load time rather than produce data that looks right.
 *
 * A plugin should call this once, at install time, and refuse to run if it
 * returns false.  Nothing else in this header is safe to call otherwise.
 */
QEMU_PLUGIN_API
bool qemu_plugin_dataflow_abi_ok(uint32_t plugin_version,
                                 uint32_t field_struct_size,
                                 uint32_t status_struct_size);

struct qemu_plugin_tb;

/*
 * The register namespace.
 *
 * A register is an index below qemu_plugin_dataflow_nregs().  The mapping to a
 * name and a location in CPUArchState comes from QEMU's own TCG globals table,
 * so it cannot drift from the target it describes the way a hand-written table
 * would.  Indices are stable for the lifetime of the process but are NOT
 * stable across QEMU versions or targets: a plugin that wants to persist them
 * must record the names alongside.
 */
QEMU_PLUGIN_API
unsigned qemu_plugin_dataflow_nregs(void);
QEMU_PLUGIN_API
const char *qemu_plugin_dataflow_reg_name(unsigned reg,
                                          uint32_t *env_offset,
                                          uint32_t *size);

/*
 * Register sets, copied into @words as a bitmap of @nwords 64-bit words.
 *
 * Returns the number of words needed to hold the whole set.  If that exceeds
 * @nwords, NOTHING is written and the caller must ask again with a larger
 * buffer; see rule 1 above for why a partial set is never handed out.
 *
 * Returns QEMU_PLUGIN_DF_INCOMPLETE if the extraction could not record this
 * instruction's dataflow in full -- more fields, writes or provenance sources
 * than it had room for.  Nothing is written in that case either.  A caller
 * therefore cannot obtain a set at all without having dealt with
 * incompleteness, which is the only way to stop a caller that ignores the
 * status accessor from quietly consuming a partial answer as though it were
 * whole.  Call qemu_plugin_insn_dataflow_status() to find out which limit was
 * hit.
 *
 *   reads   every register the instruction's ops take as an input
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
unsigned qemu_plugin_insn_reg_writes(const struct qemu_plugin_tb *tb, size_t idx,
                                     uint64_t *words, unsigned nwords);
QEMU_PLUGIN_API
unsigned qemu_plugin_insn_reg_kills(const struct qemu_plugin_tb *tb, size_t idx,
                                    uint64_t *words, unsigned nwords);

/*
 * Where a written register's value came from, as a set in the same namespace.
 *
 * This is a fact and deliberately not a verdict.  The verdict a consumer
 * usually wants -- did this instruction really define the register, or only
 * move it between the fields QEMU represents it in -- depends on which fields
 * stand for one architectural register, and that map belongs to the consumer.
 * A store into x86's cc_src whose value came from cc_op/cc_dst/cc_src is the
 * flags changing representation, not value; a store into rbx whose value came
 * from rbx is bswap, an ordinary definition.  QEMU cannot tell those apart and
 * does not try.
 *
 * An empty provenance means the value came from nothing the instruction read.
 * For the program counter that is the direct-versus-indirect branch
 * discriminator; for any register it means the dependency chain is broken,
 * which is what a zeroing idiom does and what hardware special-cases.
 *
 * Returns words needed, as above; 0 with a successful call means the
 * provenance is empty.  @reg must be in the write set.
 */
/*
 * How many words a PROVENANCE set needs.
 *
 * Not the same as the register sets need.  A read or write set holds TCG
 * globals only; a provenance set also holds the env byte ranges the block
 * interned and the load-data bits, which live above the globals in the same
 * namespace.  QEMU knows how wide that is and the plugin cannot, so it is
 * asked for rather than assumed -- the same reason nregs is a call.
 */
QEMU_PLUGIN_API
unsigned qemu_plugin_dataflow_prov_words(void);

QEMU_PLUGIN_API
unsigned qemu_plugin_insn_write_prov(const struct qemu_plugin_tb *tb,
                                     size_t idx, unsigned reg,
                                     uint64_t *words, unsigned nwords);

/*
 * State no TCG global names -- x86's vector file and x87 stack, ARM's V
 * registers, every FP status word -- reached by load and store at a constant
 * offset into CPUArchState, or by a pointer built from it.  The offset carries
 * the register number wherever the target lays the file out as a flat array,
 * which is everywhere it matters, so the consumer inverts it with the layout
 * it already has.
 *
 * Provenance bits at or above qemu_plugin_dataflow_nregs() refer to these
 * fields rather than to registers; qemu_plugin_dataflow_prov_field() maps one
 * back to its offset.  They share a namespace because they are the same thing,
 * and splitting them meant one question got two answers depending on which
 * register file it landed in.
 */
#define QEMU_PLUGIN_DF_RD  1
#define QEMU_PLUGIN_DF_WR  2

typedef struct qemu_plugin_dataflow_field {
    uint32_t struct_size;       /* caller sets to sizeof(*this) */
    uint32_t env_offset;
    uint32_t size;              /* 0 when reached by pointer: extent unknown */
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
QEMU_PLUGIN_API
bool qemu_plugin_dataflow_prov_field(unsigned bit, uint32_t *env_offset);

/*
 * The guest memory accesses of an instruction, as the emitters stated them.
 *
 * A post-hoc walk over the ops cannot tell a load's DATA from its ADDRESS:
 * qemu_ld carries the address temp as its only input, so the loaded value's
 * provenance comes out as the address registers and `mov (%rbx),%rax` is
 * indistinguishable from `mov %rbx,%rax`.  A store is worse -- it has no
 * output at all, and its two inputs are the data and the address with
 * nothing in the op to say which is which.  Both facts ARE stated, one call
 * earlier, as separate parameters of tcg_gen_qemu_ld/st_*, and that is where
 * these records come from.
 *
 * So a consumer gets the two dependencies apart: which registers computed
 * the address, and separately which produced the value.  The load-to-use
 * edge -- what a model of a memory hierarchy is built on -- exists only in
 * that separation.
 *
 * Accesses are in the order the target emitted them.  ONE record can cover
 * more than one op: a 128-bit access a host cannot perform atomically is
 * emitted as two 64-bit ones, and it is one access of 16 bytes.
 */
typedef struct qemu_plugin_dataflow_memop {
    uint32_t struct_size;       /* caller sets to sizeof(*this) */
    uint32_t size;              /* access width in bytes */
    uint32_t is_store;
} qemu_plugin_dataflow_memop;

/*
 * Returns the number of accesses, writing them only if @nmemops is at least
 * that many -- the same refuse-rather-than-truncate rule as the register
 * sets, for the same reason.
 *
 * Returns QEMU_PLUGIN_DF_INCOMPLETE when the record set is not whole: more
 * accesses than could be recorded, an access no emitter accounted for, or a
 * provenance that lost a field to slot exhaustion.  A short list of accesses
 * is the shape most likely to pass for a complete one.
 */
QEMU_PLUGIN_API
unsigned qemu_plugin_insn_memops(const struct qemu_plugin_tb *tb, size_t idx,
                                 qemu_plugin_dataflow_memop *out,
                                 unsigned nmemops);

/*
 * The two provenance sets of one access, in the register namespace above.
 *
 *   addr  what computed the address.  Present for both directions.
 *   data  what produced the value.  A STORE's data comes from registers and
 *         is given here; a LOAD's does not come from registers at all -- it
 *         came from memory -- and is stated instead by the loaded value's
 *         own provenance bit, which qemu_plugin_dataflow_prov_memop() maps
 *         back to this access.  data is empty for a load, and that emptiness
 *         is a fact rather than a gap.
 */
QEMU_PLUGIN_API
unsigned qemu_plugin_insn_memop_addr_prov(const struct qemu_plugin_tb *tb,
                                          size_t idx, unsigned memop,
                                          uint64_t *words, unsigned nwords);
QEMU_PLUGIN_API
unsigned qemu_plugin_insn_memop_data_prov(const struct qemu_plugin_tb *tb,
                                          size_t idx, unsigned memop,
                                          uint64_t *words, unsigned nwords);

/*
 * Is this provenance bit a loaded value, and if so which access produced it?
 *
 * The third region of the namespace, and the reason a write provenance can
 * now say "this came from the load" rather than naming the address registers
 * a second time.  A consumer that never asks cannot be misled: a bit that
 * resolves to neither a register nor a field is one it must not attribute.
 */
QEMU_PLUGIN_API
bool qemu_plugin_dataflow_prov_memop(unsigned bit, unsigned *slot);

/*
 * Is this provenance bit the architectural ZERO REGISTER?
 *
 * The fourth region of the namespace, and it exists because three of the
 * four targets have a register that QEMU models as a constant: AArch64's
 * XZR, RISC-V's x0, MIPS' $zero have no TCG global, so an instruction that
 * names one as an operand reads, in the op stream, from nothing.  The
 * emitters that resolve the operand say so instead, and the fact arrives
 * here as a bit like any other.
 *
 * WHAT IT IS NOT: a claim that a value depends on something that can change.
 * It says the ENCODING named that register, which is what a consumer needs
 * in order to decide for itself whether to break the dependency.  Deciding
 * that here would put an emulator optimisation on the wire as a property of
 * the machine.
 *
 * A consumer that does not ask is not misled, on the same rule as the memop
 * region: a bit it cannot resolve is one it must not attribute to a register.
 */
QEMU_PLUGIN_API
bool qemu_plugin_dataflow_prov_zero_reg(unsigned bit);

/*
 * Anything the extraction could not represent.
 *
 * A consumer is never left to infer completeness from silence, and it is not
 * trusted to ask either: when any of these flags is set the set accessors
 * refuse to hand anything back, so the only way to get data out of an
 * incomplete instruction is to have looked here first.  A set reported as complete when it is not
 * is the failure that matters here: a dependency recorded that does not exist
 * costs a consumer some scheduling accuracy, while a dependency missed makes
 * it reorder across an edge the machine could not cross.  Those are not
 * symmetric, and a truncated set is the second kind.
 */
typedef struct qemu_plugin_dataflow_status {
    uint32_t struct_size;       /* caller sets to sizeof(*this) */
    uint32_t version;           /* QEMU sets to QEMU_PLUGIN_DATAFLOW_VERSION */
    uint32_t n_calls;           /* helper calls: opaque at this level */
    uint32_t n_mem_reads;
    uint32_t n_mem_writes;
    uint8_t  fields_truncated;  /* more fields than could be recorded */
    uint8_t  writes_truncated;  /* more writes than could carry provenance */
    uint8_t  prov_truncated;    /* provenance lost a field to slot exhaustion */
    /*
     * How much of this instruction's HELPER work is stated and how much is
     * standing in for it -- QEMU_PLUGIN_DF_HELPER_*.  An instruction that
     * calls no helper is EXACT.
     *
     * n_calls above says only that a helper ran.  This says whether the
     * operands attributed to it were named by the emitter that called it or
     * assumed because nothing named them, which is the difference between a
     * dependency edge that was measured and one that was assumed.
     */
    uint8_t  helper_model;
    /*
     * (helper, pointer argument) pairs on this instruction whose DIRECTION
     * the per-helper usage table does not state, and which are therefore
     * recorded as read-and-written.  A count rather than a flag, because the
     * question a consumer eventually asks is how much of its dependency graph
     * rests on the over-approximation, and a flag cannot answer that.
     */
    uint32_t n_helper_unknown;
    /*
     * Helper calls on this instruction whose FOOTPRINT nothing bounds -- the
     * helper was handed the whole CPU state pointer, or it is not declared
     * free of global reads and writes, in which case QEMU's own register
     * allocator treats it as touching every register while the op list names
     * none of them.  The reported read and write sets are then SHORT, not
     * merely coarse.
     */
    uint32_t n_helper_unbounded;
    uint8_t  memops_truncated;  /* more accesses than could be recorded */
    uint8_t  memops_unnoted;    /* an access no emitter note accounted for */
    uint8_t  reserved[2];
} qemu_plugin_dataflow_status;

/*
 * Every operand of every helper the instruction called was named by the
 * emitter that called it: which env region, how many bytes, read or written.
 */
#define QEMU_PLUGIN_DF_HELPER_EXACT   0
/*
 * The operand SET is stated but at least one operand's DIRECTION is not, so
 * it is reported as read-and-written.  Sound in the pessimistic direction --
 * it can name an operand that was not touched, never omit one that was.
 */
#define QEMU_PLUGIN_DF_HELPER_APPROX  1
/*
 * A helper whose operand set was not stated at all.  The fields reported for
 * it are whatever a walk over the ops could resolve, with unknown extent and
 * unknown direction.
 */
#define QEMU_PLUGIN_DF_HELPER_OPAQUE  2

QEMU_PLUGIN_API
bool qemu_plugin_insn_dataflow_status(const struct qemu_plugin_tb *tb,
                                      size_t idx,
                                      qemu_plugin_dataflow_status *out);

#endif /* QEMU_PLUGIN_DATAFLOW_H */
