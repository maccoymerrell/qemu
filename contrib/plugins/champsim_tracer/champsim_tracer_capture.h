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
 * THE CAPSTONE COLUMN IS NOT PRODUCED IN-PROCESS.  IT IS NOT IN THIS TREE.
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
 * So the comparison moved out of the process, and then out of the repository.
 * Its producer is tools/cst_referee.py: an offline program that reads the
 * (isa, encoding) keys out of a QEMU-side corpus, disassembles those bytes
 * through the Python Capstone bindings -- the same way the mnemonic tables
 * were always generated -- and runs the same walk over the result.  It links
 * no plugin .so and no emulator and compiles nothing, so nothing done to this
 * tree can make it stop answering.  See tools/cst_referee.py.
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
                            const void *bytes, size_t nbytes);

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

/*
 * THE SLED DRIVER.  The corpus every per-encoding instrument reads is
 * produced HERE, and it could not be produced anywhere else.
 *
 * `tools/srcenc_sled.py` writes a guest whose text is a run of fixed-stride
 * SLOTS, one encoding per slot followed by a terminator, and hands this
 * plugin `CST_SLED=<base hex>:<stride>:<slots>`.  The driver asks QEMU to
 * TRANSLATE each slot and to execute none of them.  Translation is the whole
 * point: it is what runs vcpu_tb_trans -> create_tb_template -> qdep_apply,
 * which is where the capture hooks above write the row the wire publishes.
 * An arbitrary word is not a runnable program, so a sled that EXECUTED its
 * slots could only ever reach the encodings that happen not to fault -- a
 * biased sample of exactly the wrong shape, because the undefined and
 * privileged space is where decoder disagreements live.
 *
 * WHAT IT WAS COSTING TO NOT HAVE IT.  Measured at exec239, before this
 * landed: three of the four `static` R13 legs -- aarch64, riscv64, mipsel --
 * refused with `srcenc_sled: chunk 0 wrote no '# sled ... declined=' line`
 * and `REFUSED: the sled could not capture an identity`, and both `--srcenc`
 * isax arms had no corpus to score.  Five R13 rows, blocked on one absent
 * driver.  (The x86_64 static leg refuses on a DIFFERENT and unrelated
 * condition, the binutils >= 2.45 objdump of #286.)
 *
 * IT IS DRIVEN FROM AN EXECUTION CALLBACK, NOT FROM PLUGIN INSTALL.
 * qemu_plugin_translate_at() must run from inside a plugin callback with a
 * live vCPU -- see its contract in qemu-plugin.h -- so the guest's job is to
 * give the driver one and then exit.  It runs ONCE, on the first TB the
 * guest executes.
 *
 * THE TWO FAILURE COUNTS MEAN DIFFERENT THINGS AND ARE REPORTED SEPARATELY,
 * because the sweep's caller acts on the difference:
 *
 *   declined   qemu_plugin_translate_at() returned false.  For a mapped,
 *              executable slot the reason is the TCG code buffer, which is
 *              a property of the RUN; srcenc_sled.py re-lays the leftovers
 *              in a fresh process, whose buffer is empty.
 *   no_chain   QEMU translated the slot and the plugin built no template
 *              chain -- a property of the ENCODING, identical in every arm.
 *              Each one is named on its own line so the caller can join it
 *              back to the encoding through that run's own layout.
 */
void cst_capture_sled_run(void);

/*
 * The one primitive the sweep cannot own.  Defined in champsim_tracer.cc,
 * under this same guard, because the translate-and-keep machinery
 * (`qemu_plugin_translate_at` plus the chain the translation callback hands
 * back) and the template store are file-static there.  Returns whether QEMU
 * TRANSLATED the block at @pc, and sets *@out_chain to whether the plugin
 * has a template chain for it -- the two facts the sweep reports separately.
 */
bool cst_sled_translate_slot(uint64_t pc, bool *out_chain);

#else

static inline void cst_capture_qemu_ident(const struct qemu_plugin_tb *, size_t,
                                          const void *, size_t)
{ }
static inline void cst_capture_vec_env(const struct qemu_plugin_tb *, size_t,
                                       const void *, size_t)
{ }
static inline void cst_capture_df_stmt(const struct qemu_plugin_tb *, size_t,
                                       const void *, size_t)
{ }
static inline void cst_capture_wire_sets(const struct qemu_plugin_tb *, size_t,
                                         const void *, size_t,
                                         const struct InsnFields *, int)
{ }
static inline void cst_capture_sled_run(void)
{ }

#endif /* CST_CAPTURE */

#endif /* CHAMPSIM_TRACER_CAPTURE_H */
