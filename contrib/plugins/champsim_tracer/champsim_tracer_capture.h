/*
 * The comparison capture, and why it is not in the plugin.
 *
 * The apparatus that scores this classifier needs to see, per encoding, what
 * the classifier made of it.  There are three ways to get that and two of them
 * are wrong.
 *
 * A separate plugin would have to re-implement the classifier it is scoring,
 * and a scorer that re-implements its subject measures nothing.  Capture hooks
 * compiled into the shipping plugin are what the tree already did -- eight of
 * them, in the same file family where the lever rip-out had just removed
 * thirty-seven -- and they are apparatus living inside a product, which is the
 * thing that rip-out settled.
 *
 * So: one file, EMPTY unless the build was configured for it.  The release
 * object contains no capture code, no capture symbol and none of the
 * environment-variable names below, and that is a property a reader can check
 * with nm and strings rather than a promise.
 *
 * It is reached through two calls and not one, because the two sides being
 * compared are held at different moments.  The classifier's answer exists at
 * the end of classification; QEMU's own statements about the same bytes exist
 * at translation, where the translation block is still in hand.  Carrying
 * either to the other's site would mean threading apparatus data through
 * shipping structures, which is what segregating this file was for.
 *
 * THE CAPSTONE COLUMN IS NO LONGER PRODUCED IN-PROCESS.  RETIRED DELIBERATELY.
 * ---------------------------------------------------------------------------
 * Checking Capstone belongs outside QEMU, and for as long as both columns were
 * written from inside one running emulator the comparison was a dependent of
 * its own subject.  That is not a worry, it is a measured outcome: when the
 * wire's facts became QEMU's, the Capstone operand walk lost its last plugin
 * caller, the two hooks below stopped being reached, and four corpora --
 * srcenc, opcenc, src-mech and alias -- stopped being written.  The
 * whole-population loss bar did not go red; it went to NO SUBJECT, which is
 * worse, because a missing subject looks like nothing at all.
 *
 * So the in-process Capstone arm is retired rather than repaired.  The two
 * hooks that write the Capstone side -- cst_capture_insn() and
 * cst_capture_alias() -- are alive and unchanged, and their producer is now
 * `cst_referee`: an offline binary that reads the (isa, encoding) keys out of
 * a QEMU-side corpus, disassembles those bytes with its OWN copy of the pinned
 * Capstone the tree names, and runs this same walk over the result.  It links
 * no plugin .so and no emulator, so nothing done to the tracer's Capstone
 * dependency can make it stop answering.  See tools/cst_referee.cc.
 *
 * What survives here in-process is the QEMU side: the identity, statement,
 * register-map, generic-set and vector-env corpora, which only a running
 * emulator can write.  Those are the corpora a run still produces, and the
 * referee is what gives them a second column to be scored against.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_CAPTURE_H
#define CHAMPSIM_TRACER_CAPTURE_H

#include <cstddef>
#include <cstdint>

struct qemu_plugin_insn_info;
struct qemu_plugin_tb;
struct InsnFields;

/*
 * What the classification looked like at ONE point in the refiner chain.
 *
 * The alias refiners are the only wire-bearing Capstone reads the corpora
 * could not score, because nothing recorded the answer they were handed.
 * They key on the PRINTED MNEMONIC to separate what one Capstone instruction
 * id merged -- aarch64 `b` from `b.<cc>`, mips `jr $ra` from `jr $rN`, `bal`'s
 * false conditional, riscv's alias-hidden link register and the C-extension
 * HINT code points -- so the question a scorer has to answer is not "what is
 * the branch type" but "WHICH SIDE PRODUCED IT", and that needs the value
 * before as well as after.
 *
 * Declared outside the CST_CAPTURE guard because the decoder takes the two
 * snapshots either way, which is what keeps the guard out of the decoder.
 * They cost the release build nothing, and that is MEASURED rather than
 * assumed: the entry point below is an empty inline there, and an A/B of the
 * shipped object with and without the snapshots leaves .text, .rodata and
 * .data.rel.ro BYTE-IDENTICAL.  The `.so` file's own sha does move, because
 * its build-id and debug line tables move with any source edit at all -- so
 * the file hash is the wrong instrument for this question and the section
 * contents are the right one.
 */
struct InsnAliasSnap {
    uint8_t branch_type;
    uint8_t n_src_regs;
    uint8_t n_dst_regs;
    bool    branch_conditional;
};

/*
 * WHY AN INSTRUCTION HAS NO PUBLISHED REGISTER LISTS.
 *
 * The seating can decline, and when it does the template keeps the zeroed
 * lists it was reset with -- so the trace publishes an instruction naming no
 * register, which is also what an instruction that genuinely touches none
 * looks like.  The comparison corpus is read to decide whether a name was
 * LOST, so it has to be told which of the two it is looking at.
 *
 * The first five values mirror QdepRefusal; the last is for a caller that did
 * not run the seating at all, which is a third claim again.  Declared outside
 * the capture guard because the caller passes one either way, and checked
 * against QdepRefusal at the call site so the two cannot drift apart.
 */
enum {
    CST_WIRE_SEATED       = 0,
    CST_WIRE_NO_RULE      = 1,
    CST_WIRE_INCOMPLETE   = 2,
    CST_WIRE_UNKNOWN_WORD = 3,
    CST_WIRE_NO_STATUS    = 4,
    CST_WIRE_NOT_ASKED    = 5,
};

#ifdef CST_CAPTURE

/*
 * Write this instruction's classification to whichever corpora the run asked
 * for.  Called once, at the end of classification, with everything the
 * apparatus keys on: the encoding bytes, the decoder's own words, and the
 * classification those produced.
 *
 * A corpus that was asked for and could not be written is a refusal, not a
 * silence: a short corpus reads downstream as an encoding the classifier had
 * nothing to say about, which is the silent false success this tree keeps
 * having to relearn.
 *
 * ITS CALLER IS OFFLINE.  decode_detail_to_generic() has no plugin caller at
 * this tip, so in a running emulator this is dead and the corpora it writes
 * are empty.  cst_referee drives it instead, over the encodings a QEMU-side
 * corpus recorded.  Written from the same source either way, so the rows are
 * the rows the in-process arm produced and not a second implementation of
 * them -- measured: 0 differing rows against the last corpora that arm ever
 * wrote, on all four ISAs.
 */
void cst_capture_insn(uint64_t pc, const void *bytes, size_t nbytes,
                      const struct qemu_plugin_insn_info *info,
                      const struct InsnFields *f);

/*
 * Write what QEMU itself said about instruction @idx of @tb: the decode rule
 * the bytes reached, the generic word that rule carries, and what the
 * vocabulary table makes of that word.
 *
 * Keyed on the encoding, like every other corpus, so a scorer joins this
 * against the classifier's own answer for the same bytes without either side
 * having to know about the other.  Called at translation, where the
 * translation block is readable; the dataflow ABI is reached only from here,
 * so a release plugin does not so much as reference it.
 */
void cst_capture_qemu_ident(const struct qemu_plugin_tb *tb, size_t idx,
                            const void *bytes, size_t nbytes,
                            const char *mnem);

/*
 * How the env pointers instruction @idx handed its helpers were recorded:
 * the vector-operand statements the expanders made, and the split between
 * pointers a statement bounded and pointers recorded as the whole of
 * CPUArchState in both directions.  An instruction that hands no env pointer
 * writes no row, so the corpus cannot report coverage it never measured.
 */
void cst_capture_vec_env(const struct qemu_plugin_tb *tb, size_t idx,
                         const void *bytes, size_t nbytes);

/*
 * The decoder-only statements, per encoding: the facts no op stream carries
 * and a decode site therefore has to say out loud.
 *
 * Atomicity, the encoded immediate's VALUE, the vector lane shape, the
 * synthetic address of an instruction that names one and accesses nothing,
 * and the env ranges that resolve to a register name.  Each is a column, so
 * a scorer can read a zero as "this ISA states none" rather than as "the
 * corpus does not carry the question", and an arm that masks one statement
 * moves exactly its own column.
 */
void cst_capture_df_stmt(const struct qemu_plugin_tb *tb, size_t idx,
                         const void *bytes, size_t nbytes);

/*
 * The refiner chain's three readings of one encoding: as the operand walk and
 * the mnemonic table left it, after refine_alias_fields(), and after the
 * per-row .refine callback.
 *
 * A row where the three agree is an encoding the alias surface does not touch,
 * and a row where they differ names exactly what would be lost if that surface
 * went away -- which is the fact a flip to QEMU's decode rule has to be
 * decided on, and the one no corpus carried.
 *
 * Offline like its sibling above, and for the same reason: this is a reading
 * of the Capstone refiner chain, and the tracer no longer walks it.
 */
void cst_capture_alias(const void *bytes, size_t nbytes, const char *mnem,
                       const struct InsnAliasSnap *walk,
                       const struct InsnAliasSnap *alias,
                       const struct InsnFields *f);

/*
 * The register lists the trace PUBLISHES for these bytes: @f's src_regs[] and
 * dst_regs[], as the seating just produced them.
 *
 * Called from the one site that runs the seating, and handed its result, so
 * the corpus carries the wire's own lists rather than a re-derivation of them.
 * The alternative -- running the seating a second time from inside the capture
 * -- would double every refusal tally its census reads, which is a corrupted
 * instrument in exchange for a column that is already in hand.
 *
 * THIS IS THE JOIN'S QEMU SIDE.  What used to fill it was
 * qemu_plugin_insn_reg_reads/writes, the raw provenance bit sets the seating
 * works FROM; those are still written, under side 'p', because they answer a
 * different question and the difference between the two columns is itself a
 * reading.  See the 'p' comment in champsim_tracer_capture.cc.
 */
void cst_capture_wire_sets(const struct qemu_plugin_tb *tb, size_t idx,
                           const void *bytes, size_t nbytes,
                           const struct InsnFields *f, int refusal);

#else

static inline void cst_capture_insn(uint64_t, const void *, size_t,
                                    const struct qemu_plugin_insn_info *,
                                    const struct InsnFields *)
{ }

static inline void cst_capture_qemu_ident(const struct qemu_plugin_tb *, size_t,
                                          const void *, size_t, const char *)
{ }
static inline void cst_capture_vec_env(const struct qemu_plugin_tb *, size_t,
                                       const void *, size_t)
{ }
static inline void cst_capture_df_stmt(const struct qemu_plugin_tb *, size_t,
                                       const void *, size_t)
{ }
static inline void cst_capture_alias(const void *, size_t, const char *,
                                    const struct InsnAliasSnap *,
                                    const struct InsnAliasSnap *,
                                    const struct InsnFields *)
{ }
static inline void cst_capture_wire_sets(const struct qemu_plugin_tb *, size_t,
                                         const void *, size_t,
                                         const struct InsnFields *, int)
{ }

#endif /* CST_CAPTURE */

#endif /* CHAMPSIM_TRACER_CAPTURE_H */
