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

#define QEMU_PLUGIN_DATAFLOW_VERSION 14

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
 * True when @reg is the SELECTOR of a lowered register's representation --
 * a global that says how the register's OTHER globals are to be read, and
 * that carries no part of the architectural value.
 *
 * x86 declares one, cc_op.  QEMU does not keep EFLAGS: it keeps cc_op,
 * cc_dst, cc_src and cc_src2, and the architectural value is a function of
 * the four.  Three hold operands and results and ARE the flags an
 * instruction writes; cc_op holds which function to apply.
 *
 * A consumer that reads every write as an architectural fact therefore sees
 * `ja` define EFLAGS -- materialising the flags for its own test writes
 * cc_op -- when `ja` writes no flag the ISA defines.  The distinction is not
 * recoverable from the ops (a selector is written with a constant, and so is
 * `mov $5,%rax`'s destination) and not recoverable from a mnemonic without
 * asking a disassembler, which is the thing this interface exists to stop
 * asking.  The target states it beside the global it creates.
 *
 * false for every register on a target that declares none, which is every
 * target but x86 today -- AArch64, RISC-V and MIPS lower their condition
 * state eagerly and have no selector to declare.
 */
QEMU_PLUGIN_API
bool qemu_plugin_dataflow_reg_is_repr_selector(unsigned reg);

/*
 * Did an emitter state that a write to @reg on this instruction SUPPLIES a
 * value -- put something in the register that did not come out of it?
 *
 * The question only has content for a LOWERED register, one architectural
 * name spread over several TCG globals.  There, a write whose whole
 * provenance is the register's own globals is a change of representation:
 * x86 recomputes EFLAGS from cc_op/cc_dst/cc_src/cc_src2 into cc_src, which
 * is why `jcc` looks like a flags writer and is not one.  `clc` then does
 * the same thing and clears CF with a translator constant, and provenance --
 * a union over the writes -- cannot tell the pair apart.  So the emitter
 * that supplied the constant says so and this reports it.
 *
 * false when @reg is not a register this instruction wrote, and false when
 * no emitter has said anything, which is the answer that keeps a consumer
 * publishing what it already published.
 */
QEMU_PLUGIN_API
bool qemu_plugin_insn_write_supplies_value(const struct qemu_plugin_tb *tb,
                                           size_t idx, unsigned reg);

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
 * THE SAME TWO SETS AS ORDERED LISTS.
 *
 * WHY A LIST AS WELL AS A SET.  A consumer that only asks "does this
 * instruction read rbx" is served by the bitmaps above.  A consumer that
 * PUBLISHES a register list -- a trace format with a source array and a
 * dependency mask whose bit i means "slot i" -- needs two things a bitmap
 * cannot give it.  It needs every member, including the ones no TCG global
 * names; and it needs an ORDER that is a property of the instruction rather
 * than of the register file's numbering.  Sorting the bitmap supplies an
 * order, but it is the target's register index, so `sub rd,rs1,rs2` and
 * `sub rd,rs2,rs1` sort identically and a mask written for slot 0 would mean
 * a different operand on the two.
 *
 * THE ORDERING CONTRACT, in full, because a consumer will build a wire format
 * on it:
 *
 *   1. Entries appear in the order the extraction FIRST OBSERVED each member,
 *      walking the instruction's TCG ops from first to last.  A member
 *      observed more than once appears ONCE, at its first position.
 *
 *   2. A member no op names -- a destination the emulator discarded, the env
 *      footprint of a called helper or of a gvec expansion -- is appended
 *      after the op-walk entries, in the order its emitter's notes were
 *      applied.  It CANNOT be interleaved, because there is no op to
 *      interleave it at.  This is stated rather than hidden: a consumer that
 *      needs "the second architectural operand" must not read entry 1.
 *
 *   3. The ORDER OF DIRECTIONS is independent.  A CPUArchState range read and
 *      written by one emitter statement is one row of
 *      qemu_plugin_insn_fields() and appears in BOTH lists, at the position
 *      each direction was stated in that list.
 *
 *   4. The lists are NOT a permutation of the bitmaps.  They also carry
 *      members the bitmaps cannot name:
 *        - a CPUArchState byte range (a vector register, an x87 slot, an FP
 *          status word), which has no TCG global to set a bit for;
 *        - the architectural ZERO REGISTER, which on every target that has
 *          one is a constant with no global at all.  A consumer building a
 *          source list from the read bitmap alone is short by exactly the
 *          register the encoding named;
 *        - a source stated by NAME ALONE (READ list only), which has neither
 *          a global nor an env range because it does not live in
 *          CPUArchState -- AArch64's ARM_CP_CONST system registers are read
 *          out of the CPU object at translate time.  Read its name from
 *          qemu_plugin_insn_named_reads().
 *      Conversely a KILL is in neither list: it is not a read and not a
 *      write, and it stays where it is, in its own bitmap.
 *
 *   5. Determinism.  For a given QEMU binary, target and translation of a
 *      given encoding, the order is fixed.  It is a property of the ops the
 *      TARGET EMITTED, so it may differ between two QEMU versions in the way
 *      every other fact here may, and it is emphatically NOT the operand
 *      order the ISA manual prints.  A consumer that persists a list must
 *      persist it with the names, exactly as the register namespace's own
 *      rule says.
 *
 * REFUSAL, on the same rule as the sets: nothing is written and
 * QEMU_PLUGIN_DF_INCOMPLETE is returned when the extraction could not record
 * this instruction in full -- including when the LIST itself overflowed, which
 * is its own limit and is reported by qemu_plugin_insn_dataflow_status().  A
 * list short by a member is a missing dependency wearing the shape of a whole
 * answer.
 *
 * Otherwise returns the number of entries; if that exceeds @nentries, or @out
 * is NULL, nothing is written and the caller asks again with room.  A return
 * of 0 with a successful call means the instruction states no member of that
 * direction, which is a fact and not a refusal -- ask the status accessor if
 * the difference matters.
 */
#define QEMU_PLUGIN_DF_ENT_GLOBAL   0
#define QEMU_PLUGIN_DF_ENT_FIELD    1
#define QEMU_PLUGIN_DF_ENT_DISCARD  2
#define QEMU_PLUGIN_DF_ENT_ZERO     3
#define QEMU_PLUGIN_DF_ENT_NAME     4

typedef struct qemu_plugin_dataflow_reg_entry {
    uint32_t struct_size;       /* caller sets to sizeof(*this) */
    uint32_t kind;              /* QEMU_PLUGIN_DF_ENT_* */
    /*
     * GLOBAL: the register, in the qemu_plugin_dataflow_reg_name() namespace.
     * Otherwise UINT32_MAX -- not 0, which is a valid register.
     */
    uint32_t reg;
    /*
     * FIELD: the index into this instruction's qemu_plugin_insn_fields()
     * array, so the extent and the provenance are read from the one place
     * that holds them rather than duplicated here where they could drift.
     * DISCARD: the index into qemu_plugin_insn_discards().
     * NAME:    the index into qemu_plugin_insn_named_reads().
     * Otherwise UINT32_MAX.
     */
    uint32_t index;
} qemu_plugin_dataflow_reg_entry;

QEMU_PLUGIN_API
unsigned qemu_plugin_insn_reg_read_list(const struct qemu_plugin_tb *tb,
                                        size_t idx,
                                        qemu_plugin_dataflow_reg_entry *out,
                                        unsigned nentries);
QEMU_PLUGIN_API
unsigned qemu_plugin_insn_reg_write_list(const struct qemu_plugin_tb *tb,
                                         size_t idx,
                                         qemu_plugin_dataflow_reg_entry *out,
                                         unsigned nentries);

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
 * THE DESTINATIONS THE ENCODING NAMES AND THE OP STREAM DOES NOT CARRY.
 *
 * TWO CAUSES, opposite claims about the same absent op, and @by_index says
 * which.
 *
 * THE EMULATOR DISCARDED IT.  A register with no TCG global and no
 * CPUArchState storage cannot appear in qemu_plugin_insn_reg_writes() or in
 * qemu_plugin_insn_fields(), because both are indexed by a place the value
 * lives and this value lives nowhere.  AArch64's XZR is the case in point:
 * `cmp x0,x1` IS `subs xzr,x0,x1`, and the op stream carries the subtraction
 * with its result going into a temp that is then dropped.  MIPS reaches the
 * same shape twice more -- `mul` leaves HI and LO architecturally
 * UNPREDICTABLE, and `move $zero,$ra` translates to no op at all.
 *
 * THE EMULATOR PERFORMED IT, THROUGH AN INDEX ONLY THE ENCODING STATES.
 * AArch64's FEAT_MOPS hands its helper one syndrome word and the helper pulls
 * the three register numbers out of it to address env->xregs[]; the op stream
 * carries a call and two constants and no GPR write at all, and the
 * per-helper usage row can say `xregs` but not WHICH.  The registers are
 * named here because the decoder knew them, and @by_index is set because the
 * write happens -- the next instruction reads it.
 *
 * A consumer that FILLS a destination list from the two accessors above is
 * short by exactly these registers.  They are named here, with the same
 * provenance every other write carries, so a list built from QEMU's facts is
 * the list the instruction writes.
 *
 * @reg is the architectural name in the namespace qemu_plugin_dataflow_reg_name()
 * and qemu_plugin_dataflow_field_reg() answer in; the pointer is owned by QEMU
 * and stays valid for the process's life.
 *
 * Returns the number of rows, or writes min(n, count) of them when @out is
 * non-NULL, on the two-call convention qemu_plugin_insn_fields() uses.
 */
typedef struct qemu_plugin_dataflow_discard {
    uint32_t struct_size;
    /*
     * NULL when @zero_reg is set.  The architectural ZERO register has no
     * name in this namespace on the targets that have one -- AArch64's XZR
     * is not a GDB register -- so it is identified the way a zero-register
     * OPERAND already is (qemu_plugin_dataflow_prov_zero_reg): by being the
     * one register that needs no name.
     */
    const char *reg;
    uint8_t zero_reg;
    /*
     * The emulator PERFORMS this write; it is not thrown away.  A consumer
     * building the instruction's destination list wants both kinds and may
     * ignore this; a consumer counting how much the emulator elides must not,
     * because folding the two makes that number mean neither thing.
     */
    uint8_t by_index;
} qemu_plugin_dataflow_discard;

QEMU_PLUGIN_API
unsigned qemu_plugin_insn_discards(const struct qemu_plugin_tb *tb, size_t idx,
                                   qemu_plugin_dataflow_discard *out,
                                   unsigned ndiscards);

/*
 * The sources this instruction NAMES that have no global and no env range.
 *
 * The read side's counterpart to qemu_plugin_insn_discards().  A register
 * QEMU resolves at translation time out of storage that is not CPUArchState
 * -- AArch64's ARM_CP_CONST system registers live in the ARMCPU object --
 * has no bit to set and no byte range to state, so it travels by name and
 * reaches the ORDERED READ LIST as QEMU_PLUGIN_DF_ENT_NAME with @index into
 * this array.  It never appears in the write list and never in a bitmap.
 *
 * The name is in the same namespace qemu_plugin_dataflow_reg_name() and
 * qemu_plugin_insn_discards() use, so a consumer's name-to-register map
 * needs no second spelling.  There is no provenance: the instruction depends
 * on the value, it did not compute it.
 *
 * Refusal and sizing exactly as qemu_plugin_insn_discards(): nothing is
 * written and QEMU_PLUGIN_DF_INCOMPLETE is returned when the record is not
 * whole, and a short @nnames or a NULL @out returns the count.
 */
typedef struct qemu_plugin_dataflow_named_read {
    uint32_t struct_size;       /* caller sets to sizeof(*this) */
    const char *reg;            /* the architectural name */
} qemu_plugin_dataflow_named_read;

QEMU_PLUGIN_API
unsigned qemu_plugin_insn_named_reads(const struct qemu_plugin_tb *tb,
                                      size_t idx,
                                      qemu_plugin_dataflow_named_read *out,
                                      unsigned nnames);
QEMU_PLUGIN_API
unsigned qemu_plugin_insn_discard_prov(const struct qemu_plugin_tb *tb,
                                       size_t idx, unsigned discard,
                                       uint64_t *words, unsigned nwords);

/*
 * NAME the register an env byte range belongs to, in the same namespace
 * qemu_plugin_dataflow_reg_name() answers in.
 *
 * An env offset is not a shortfall in what QEMU knows; it is a register
 * whose storage no TCG global happens to name -- x86's vector file, ARM's V
 * registers, every target's FP status word.  The offset IS the identity, and
 * inverting it needs the CPUArchState layout, which each target states once
 * beside its globals.  A consumer that reads an unnamed offset as "QEMU
 * cannot tell us" is reading its own missing lookup as a property of the
 * machine.
 *
 * false when nothing covers the range, or when the range REACHES BEYOND one
 * register: a helper handed a whole register file starts at the same byte as
 * an access to its first element, and naming that for the first would
 * publish a set short by the rest.  @size is the access's extent and must be
 * the caller's real one.
 *
 * @buf is filled only on true.
 */
QEMU_PLUGIN_API
bool qemu_plugin_dataflow_field_reg(uint32_t env_offset, uint32_t size,
                                    char *buf, size_t buflen);

/*
 * The same, for a PROVENANCE bit above the globals: the extent comes from
 * the slot the translation interned, so a caller holding only a bit does not
 * have to reconstruct one it never saw.
 */
QEMU_PLUGIN_API
bool qemu_plugin_dataflow_prov_field_reg(unsigned bit, char *buf,
                                         size_t buflen);

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
    /*
     * The access is performed INSIDE a helper the instruction called, and is
     * stated by that helper's written-down usage row rather than by a
     * qemu_ld/qemu_st emitter -- because there is no such op to state it.
     * aarch64's MOPS copies and MIPS's unaligned stores move guest memory
     * with the op list naming no access at all, so without these records the
     * access list is SHORT for the instruction that called them, and short
     * is the error direction that costs correctness rather than accuracy.
     */
    uint32_t by_helper;
    /*
     * The helper performs one OR MORE accesses of this direction through
     * this address and the number is data-dependent, so no number is given.
     * @size is then the width of ONE access.  A consumer sizing an array by
     * the access count must read this record as "at least one".
     */
    uint32_t count_unbounded;
    /*
     * The address is not one of the helper's arguments, so nothing at the
     * call site names it and this access's addr provenance is EMPTY.  That
     * emptiness is NOT evidence of absence: a consumer publishing an address
     * dependency must refuse this access rather than read it as "depends on
     * nothing".
     */
    uint32_t addr_unstated;
    /*
     * The same for a STORE's VALUE: it did not travel through one of the
     * helper's arguments, so the data provenance is empty and means "not
     * stated" rather than "produced by nothing".
     */
    uint32_t data_unstated;
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
 * Is @bit the INSTRUCTION'S OWN ENCODED IMMEDIATE?
 *
 * A destination whose dependency mask names registers on an instruction that
 * also carries an immediate raises a question the register names cannot
 * settle: is the encoding one of that destination's sources?  `add $5,(%rax)`
 * says yes -- its FLAGS destination is computed from the 5 -- and
 * `ldr x0,[x1,#8]` says no, because the 8 is the ADDRESS's and is carried in
 * the address's own provenance, where a consumer that wants it will find it.
 *
 * So the emitters that turn an encoding's immediate field into a TCG value
 * say so, and the bit then travels the ordinary dataflow: it lands wherever
 * the immediate's value went and nowhere else.
 *
 * WHAT IT IS NOT: a bit for "a translation-time constant".  QEMU makes those
 * everywhere and for its own reasons, and a bit that meant that would say
 * nothing about the machine.  It is the ENCODING's immediate or it is not
 * set.
 *
 * READ IT TOGETHER WITH imm_stated / imm_reached from the status.  The
 * ABSENCE of this bit is only an answer when the instruction's decoder
 * actually spoke and the value it named reached an op; otherwise absence
 * means nobody looked, which a consumer must refuse on rather than read as
 * "the encoding did not contribute".
 *
 * A consumer that does not ask is not misled, on the same rule as the memop
 * and zero-register regions: a bit it cannot resolve is one it must not
 * attribute to a register.
 */
QEMU_PLUGIN_API
bool qemu_plugin_dataflow_prov_encoded_imm(unsigned bit);

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
    /*
     * More writes than could carry provenance -- OR more discarded
     * destinations (qemu_plugin_insn_discards()) than there was room for,
     * which is the same fact about the same list.
     */
    uint8_t  writes_truncated;
    uint8_t  prov_truncated;    /* a provenance lost a member to an array cap */
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
    /*
     * Accesses on this instruction that a called HELPER performs itself,
     * stated by its usage row because no op names them.  A count, so a
     * consumer can say how much of its access list came from a written-down
     * row rather than from an op.
     */
    uint8_t  memops_by_helper;
    /*
     * At least one of those accesses has an unstated count, or an unstated
     * address.  Kept apart because they forbid different things: an unstated
     * COUNT still lets a consumer say the direction happened, while an
     * unstated ADDRESS forbids publishing an address dependency for it.
     */
    uint8_t  memops_count_unbounded;
    uint8_t  memops_addr_unstated;
    uint8_t  memops_data_unstated;
    /*
     * A helper WROTE a register FILE and the index it wrote was computed at
     * run time, so the range QEMU accounted for covers the file and names
     * none of its elements: aarch64's MOPS set writes
     * `env->xregs[mops_destreg(syndrome)]`.
     *
     * The write set this instruction reports is therefore a SUPERSET of the
     * registers it names.  A consumer that FILLS its own destination list
     * from these rows is unaffected -- every name it does get is real.  A
     * consumer that REPLACES its list with them must refuse the instruction,
     * because "somewhere in this file" is a different claim from "these
     * registers" and publishing the named subset as complete would be a
     * missing dependency.
     */
    uint8_t  helper_writes_unbounded;
    uint8_t  reserved[1];
    /*
     * THE ENCODED IMMEDIATE, as the two facts a consumer needs to read the
     * absence of the immediate provenance bit.
     *
     * @imm_stated: a decoder on this instruction's path named its encoded
     * immediate.  @imm_reached: the value it named was then read by an op of
     * this instruction, so the bit had a route into the dataflow.
     *
     * Only when BOTH are set may a destination that does not carry the
     * immediate bit be read as "the encoding did not contribute to this
     * value".  With @imm_stated clear the target's decoder does not state
     * immediates on this path at all and the absence means nothing; with it
     * set and @imm_reached clear, QEMU folded the immediate away before
     * emitting anything -- `addi rd,rs,0` becomes a move -- and the absence
     * is the emulator's optimisation rather than the machine's.
     */
    uint8_t  imm_stated;
    uint8_t  imm_reached;
    /*
     * THE THIRD FACT, and the one the two above cannot express.
     *
     * @imm_non_dataflow: a decoder said one of this instruction's encoded
     * fields is a field the ARCHITECTURE does not define as a dataflow
     * operand.  MIPS' `teq rs,rt,code` and `break code` are the class: the
     * exception they raise has its cause fixed by the OPCODE and the code
     * is left in the instruction word for software to read, so nothing the
     * instruction writes depends on it and QEMU is right never to
     * materialise it.
     *
     * Without this, such an instruction is indistinguishable from one whose
     * immediate the emulator FOLDED away -- stated, never reached -- and
     * those want opposite answers: a fold is an emulator optimisation a
     * consumer must not publish as the machine's, while this is the
     * machine's own definition and licenses reading a register-only
     * destination mask as COMPLETE.
     *
     * Instruction granularity, the same as the two flags above: an
     * instruction with two encoded fields, one a dataflow operand and one
     * not, sets both and a consumer cannot ask which field the answer is
     * about.
     */
    uint8_t  imm_non_dataflow;
    /*
     * The ORDERED LIST of that direction ran out of room, so the list is
     * short by at least one member and MUST NOT be published.
     *
     * Its own limit, and reported on its own, because it is not the same
     * question as @fields_truncated or @writes_truncated: a list carries
     * members from several arrays -- globals, env ranges, discarded
     * destinations, the zero register -- and can overflow while every one of
     * those arrays had room.  The list accessors already refuse on it; this
     * is what lets a consumer say WHY it was refused, and what makes the
     * refusal countable rather than an unexplained empty answer.
     */
    uint8_t  read_list_truncated;
    uint8_t  write_list_truncated;
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
