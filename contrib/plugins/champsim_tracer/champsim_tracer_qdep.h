/*
 * The wire's facts, taken from QEMU.
 *
 * Every field of InsnFields that used to come from a decoder running beside
 * the emulator now comes from the emulator: the classification from the rule
 * the bytes reached and the generic word that rule carries; the register
 * lists from the TCG globals and CPUArchState ranges the instruction's own
 * ops touched; the memory operands, their addresses and their data from the
 * accesses those ops performed; the lane shape, the self-loop unit, the
 * atomicity and the encoded immediate from the decode sites that hold them.
 *
 * WHY THIS IS KEYED ON (tb, idx) AND NOTHING ELSE.  The statement ABI's own
 * header says its answers are readable only while the translation that
 * produced them is the current one.  There is no post-hoc route: the identity
 * is the row a trans_ function accepted, which is the same event as emitting
 * its ops.  So the seating runs inside the translation callback, from the
 * block that is still in hand, and a caller with only bytes and an address
 * has nothing to call.
 *
 * WHAT A FALSE RETURN MEANS.  Three different things, and they are counted
 * apart because they are not the same condition:
 *
 *   - the bytes reached no rule (qemu_plugin_insn_undecoded);
 *   - the instruction could not be recorded in full, so the ABI refuses to
 *     hand out a set at all rather than hand out a short one;
 *   - the rule stated a word this build's vocabulary cannot read, which means
 *     the emulator and the plugin were built from different vocabularies.
 *
 * None of the three is GEN_OP_UNKNOWN in the old sense of "a mnemonic with no
 * row".  The caller leaves the instruction unclassified and counts which of
 * the three it was.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_QDEP_H
#define CHAMPSIM_TRACER_QDEP_H

#include <stdint.h>
#include <stddef.h>

struct qemu_plugin_tb;
struct InsnFields;
struct InsnRegNames;

/* Why a seating declined.  Counted separately; see the header comment. */
enum QdepRefusal {
    QDEP_OK = 0,
    QDEP_NO_RULE,          /* the bytes reached no decode rule           */
    QDEP_INCOMPLETE,       /* QEMU could not record the instruction whole */
    QDEP_UNKNOWN_WORD,     /* the rule's word is not in this vocabulary   */
    QDEP_NO_STATUS,        /* the (tb, idx) pair names nothing readable   */
};

/*
 * Seat every wire fact for instruction @idx of @tb into @out (and the value-
 * read keys into @out_names when it is non-NULL).
 *
 * @out must be a freshly reset InsnFieldsScratch::f -- all scalars zero and
 * every span wired to zeroed full-size backing -- exactly as the operand walk
 * it replaces required.  @pc is the instruction's virtual address, used only
 * for the sidecar log of a refusal.
 *
 * Returns QDEP_OK when the instruction is classified.  Anything else leaves
 * @out at its reset state except for what the caller stamps itself.
 */
QdepRefusal qdep_apply(const struct qemu_plugin_tb *tb, size_t idx,
                       uint64_t pc, struct InsnFields *out,
                       struct InsnRegNames *out_names);

/*
 * The per-run refusal tallies, for a census that must not be vacuous.  Each
 * is a count of instructions, not of translations.
 */
struct QdepCounters {
    uint64_t seated;
    uint64_t no_rule;
    uint64_t incomplete;
    uint64_t unknown_word;
    uint64_t no_status;
    /* Members of a set that QEMU named and the register map could not read.
     * Not a refusal -- the instruction is still seated -- but it is a name
     * the wire cannot publish, so it is counted rather than dropped in
     * silence. */
    uint64_t unmapped_names;
    /* Set members that are neither a name nor an atom: an undeclared
     * CPUArchState range.  The target has not declared a register file that
     * contains them, so there is nothing to publish; counted for the same
     * reason. */
    uint64_t unnamed_ranges;
    /* Writes and accesses past this build's slot ceilings. */
    uint64_t dropped_srcs;
    uint64_t dropped_dsts;
    uint64_t dropped_loads;
    uint64_t dropped_stores;
    /* A destination or a stored datum whose value came from a guest load
     * this instruction performed, seated on the wire's load-data bit; and
     * the same provenance reaching an ADDRESS mask, which the format's
     * address layout has no slot for.  The second is counted rather than
     * dropped because an address computed from a datum the same instruction
     * loaded is a real shape and a silent zero would read as no dependency
     * at all.  It is 0 on every ISA measured so far. */
    uint64_t load_datum_seated;
    uint64_t load_datum_in_addr;
    /* Synthetic addresses seated, and those withheld whole because the
     * descriptor cannot express one of their terms. */
    uint64_t synth_ea_seated;
    uint64_t synth_ea_refused;
};

const QdepCounters *qdep_counters(void);

/*
 * The address instruction @idx NAMES and the emulation computes nothing for
 * -- a prefetch hint, a cache-maintenance operation -- built from the
 * components the decode site stated.  Returns true and fills @out when every
 * term resolved; false, with @out zeroed, when the opcode is not one of the
 * memory-hint classes, when no address was stated, or when a term the
 * descriptor cannot express would have had to be dropped.
 */
struct SyntheticEAInfo;
bool qdep_synthetic_ea(const struct qemu_plugin_tb *tb, size_t idx,
                       uint8_t opcode, struct SyntheticEAInfo *out);

/*
 * Check what this build can answer with before the first translation: the
 * vocabulary's own invariants and the register map's.  Returns the number of
 * defects so the caller can refuse rather than publish from a table that is
 * not ordered.
 */
unsigned qdep_selfcheck(void);

#endif /* CHAMPSIM_TRACER_QDEP_H */
