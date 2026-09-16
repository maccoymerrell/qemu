/*
 * The words QEMU states, and what each one means on the wire.
 *
 * QEMU's decode sites carry a generic word per rule (include/exec/
 * insn-dataflow.h); the wire carries GenericOpcode and BranchType.  This is
 * the whole of the translation between them: one sorted table, one lookup,
 * no per-ISA arm and no inference from operands.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_VOCABULARY_H
#define CHAMPSIM_TRACER_VOCABULARY_H

#include <stdint.h>

/*
 * Translate @word.  Returns false, and writes nothing, for a word this build
 * does not know -- which a caller must treat as "QEMU said something I cannot
 * read", never as GEN_OP_UNKNOWN.  The two differ: a rule with no word has
 * nothing to say about itself, while an unreadable word means the emulator
 * and the plugin were built from different vocabularies, and publishing the
 * first answer for the second condition hides a skewed build behind a
 * plausible classification.
 *
 * @word may be NULL (a rule that stated none), which returns false.
 */
bool cst_vocabulary_lookup(const char *word, uint8_t *opcode,
                           uint8_t *branch_type);

/*
 * Check the table's own invariants: sorted by word, no duplicate word, and
 * every row's opcode and branch type inside their enums.  Returns the number
 * of defects, so a caller can refuse rather than bisect a table that is not
 * ordered.  Cheap enough to run at install and nowhere near a hot path.
 */
unsigned cst_vocabulary_selfcheck(void);

/* How many words this build knows, for a census that must not be vacuous. */
unsigned cst_vocabulary_size(void);

#endif /* CHAMPSIM_TRACER_VOCABULARY_H */
