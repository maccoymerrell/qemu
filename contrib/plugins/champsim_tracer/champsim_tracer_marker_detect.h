/*
 * ChampSim Tracer — marker detection.
 *
 * A marker is CST_MARKER_SEQ_LEN identical immediate-loads in a row (see
 * champsim_marker.h).  The repetition exists for one reason: three
 * back-to-back loads of the same constant into the same register are
 * provably-dead redundant work no compiler emits, so the pattern cannot
 * occur in real code by accident.  It is a property of the BYTES.
 *
 * It is therefore decided in the BYTES, at translation time, and fires from
 * ONE instruction.
 *
 * For every instruction whose encoding equals the LAST instruction of a
 * marker sequence, the translator compares the CST_MARKER_SEQ_LEN-1
 * instruction slots immediately before it against the rest of that sequence
 * — all read out of the SAME TB, which the base-QEMU never-split guarantee
 * (docs/qemu_modifications.rst) makes complete.  If they match, this
 * instruction ends a complete marker and the window open/release happens
 * right there at translation.  One instruction, one decision, no callbacks
 * and no state.
 *
 * What that buys, and why the previous design could not have it: detection
 * used to be an execution-time ADJACENCY RUN — per-instruction words, a
 * per-vCPU in-flight run, a process-wide handoff bank for runs split by a
 * migration, one-word candidates, eviction.  Every way a marker was ever
 * lost was that state losing its place: a fault taken between two words, a
 * task migrating mid-sequence, a page straddle cutting the run across TBs,
 * and — on the fixed-width targets, where the two magics differ only in
 * their low byte — the two sequences sharing their high-half word, so a
 * healthy START fed the END detector chaff.  None of those can touch a
 * decision made from bytes at a single instruction:
 *
 *   - a fault, an interrupt or a single-step trap between two marker
 *     instructions changes nothing; the bytes are still the bytes;
 *   - a migration between two marker instructions changes nothing; the
 *     callback is on one instruction, on whichever vCPU runs it;
 *   - TB slicing changes nothing; the base-QEMU translator NEVER SPLITS
 *     a marker sequence across a TB boundary (the never-split guarantee,
 *     docs/qemu_modifications.rst), so the whole sequence — page
 *     straddles included, as a cross-page TB — is always readable from
 *     the one TB that carries its terminating instruction;
 *   - -icount / one-instruction-per-TB / a single-stepping ptrace injector
 *     changes nothing, for the same reason;
 *   - START and END are compared as WHOLE sequences, immediates included,
 *     so a shared word cannot confuse them and no sequence can be mistaken
 *     for the other.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_MARKER_DETECT_H
#define CHAMPSIM_TRACER_MARKER_DETECT_H

#include <stdint.h>

#include "champsim_marker.h"   /* CST_MARKER_* encodings + sizes */

/*
 * Per-ISA marker byte sequences, built once from the shared contract at
 * install time.  x86 is CST_MARKER_SEQ_LEN identical 5-byte movs; the
 * fixed-width ISAs are the minimal two-insn load pair repeated
 * CST_MARKER_SEQ_LEN times.  Either way the sequence is a fixed run of
 * fixed-width slots, which is what makes the backward look exact.
 */
struct MarkerSeq {
    uint8_t  start[CST_MARKER_PAIR_SEQ_BYTES];
    uint8_t  end[CST_MARKER_PAIR_SEQ_BYTES];
    uint8_t  insn_bytes = 0;           /* fixed insn width in the seq */
    uint8_t  n_insns    = 0;           /* insns per full sequence */
    uint16_t seq_bytes  = 0;           /* insn_bytes * n_insns */
    uint16_t prefix_bytes = 0;         /* seq_bytes - insn_bytes */
    bool     valid      = false;
};

extern MarkerSeq g_marker_seq;

/* Which sequence an instruction terminates. */
enum MarkerWhich {
    MARKER_WHICH_NONE  = 0,
    MARKER_WHICH_START = 1,
    MARKER_WHICH_END   = 2,
};

/* Build g_marker_seq's START/END byte patterns for the active target ISA. */
void marker_seq_init(void);

/*
 * Could @bytes/@size be the LAST instruction of a marker sequence?  This is
 * the cheap translation-time filter: it is true only for an instruction that
 * IS, byte for byte, the terminating instruction of the START or the END
 * sequence.  On the fixed-width targets both sequences share that
 * instruction, so a true answer does not say which — marker_whole_match()
 * does, from the whole sequence.
 */
bool marker_tail_word_match(const uint8_t *bytes, uint8_t size);

/*
 * Decide, from the bytes alone, whether the instruction @bytes/@size ends a
 * complete marker sequence.  @prefix holds the g_marker_seq.prefix_bytes
 * bytes that immediately PRECEDE it in guest memory (the CST_MARKER_SEQ_LEN-1
 * instruction slots before it).  Returns which sequence, or MARKER_WHICH_NONE.
 *
 * The comparison covers every byte of the sequence, immediates included, so
 * START and END are distinguished even where their terminating instruction is
 * identical.
 */
MarkerWhich marker_whole_match(const uint8_t *bytes, uint8_t size,
                               const uint8_t *prefix);

#endif /* CHAMPSIM_TRACER_MARKER_DETECT_H */
