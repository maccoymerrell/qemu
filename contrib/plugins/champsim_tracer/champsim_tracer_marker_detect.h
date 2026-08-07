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
 * instruction slots immediately before it against the rest of that sequence.
 * If they match, this instruction is the final instruction of a complete
 * marker and carries the marker's execution callback; nothing else does.
 * One instruction, one callback, one event.
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
 *   - TB slicing changes nothing; the match is over guest memory, not over
 *     a TB.  A sequence that STRADDLES A PAGE BOUNDARY is the one case that
 *     needs more than "read the bytes": the slots before the terminating
 *     instruction are on another page, that page's translation can be gone
 *     by the time the tail runs, and a software-managed TLB cannot refill
 *     it for a debug read.  Such a sequence is decided from its PHYSICAL
 *     PAGE PAIR at translation time — see marker_straddle_* below;
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

/*
 * udata for the marker execution callback: the terminating instruction's
 * vaddr, its size, and whether the translation-time backward look failed and
 * must be retried when the instruction executes.  Marker instructions are
 * 4/5-byte encodings and vaddrs on every target fit 56 bits.
 */
static inline void *marker_udata_pack(uint64_t pc, uint8_t size, bool recheck)
{
    return (void *)(uintptr_t)((pc << 8) | (recheck ? 0x80u : 0u) | size);
}

static inline void marker_udata_unpack(void *udata, uint64_t *pc,
                                       uint8_t *size, bool *recheck)
{
    uintptr_t v = (uintptr_t)udata;
    *size    = (uint8_t)(v & 0x7f);
    *recheck = (v & 0x80) != 0;
    *pc      = (uint64_t)(v >> 8);
}

/*
 * An instruction that IS, byte for byte, the terminating instruction of a
 * marker sequence, but whose preceding instruction slots could not be read
 * from guest memory when it executed.
 *
 * THIS IS NOT A DECIDED CASE.  It used to be documented as one, on this
 * argument: "the preceding slots of a real marker were fetched and retired
 * by this same CPU one or two instructions earlier, so they were mapped
 * then and nothing has run since that could unmap them; slots that cannot
 * be read now therefore did not execute."  That argument is FALSE on a
 * target with a SOFTWARE-MANAGED TLB, and mipsel is one.  Measured, with
 * the read instrumented:
 *
 *   [readdiag] pc=0x77c30008 base=0x77c2fff4 len=24 FAILED
 *              | first_insn_at_base=0 tail_at_pc=1
 *                page_of_pc=1 page_of_base=0 priv=0 asid=0x37
 *
 * The tail's own page reads; the page holding the slots before it does
 * NOT — moments after this same CPU fetched and retired instructions from
 * it.  The page is still mapped in the guest's page tables; what is gone is
 * its TLB entry, evicted by the kernel code that ran between the two halves
 * of the sequence (a fault handler, a preemption).  A hardware-walked
 * target refills transparently and the read succeeds; MIPS has no hardware
 * walker, so QEMU's debug read has nothing to consult and fails.  The cost
 * was real and measured: 4 of 200,000 START sequences lost (cell migstr),
 * plus a missed END (cell endsmc), intermittently — 2 of 6 identical runs.
 *
 * So a count here is a READ THAT COULD NOT BE SERVICED, not a proof about
 * what executed, and a marker must never be decided by it alone.  Which is
 * why a sequence that spans two pages is decided from its PHYSICAL PAGE
 * PAIR at translation time (see marker_straddle_* below); the read remains
 * the preferred, address-space-exact source when it can be serviced, and
 * this counter is what says how often it could not.
 *
 * What is still genuinely undecided is a straddling sequence for which no
 * pair was ever witnessed AND whose read fails: marker_straddle_undecided()
 * counts exactly those.  On a sequence that really ran there is always a
 * witness — the predecessor page's own translation takes one while that
 * page is resident — so what remains under that counter is the lone
 * marker-shaped instruction at a page start whose predecessor page never
 * held a marker prefix.  Claiming nothing for THAT is right, and it is the
 * only thing the counter should ever hold.
 *
 * The other case the read does not cover is a target that maps its text
 * EXECUTE-ONLY, where the guest read fails for a page the CPU can
 * nonetheless fetch from.  A sequence there is decided from the translation
 * block's own instruction stream whenever the block reaches back over the
 * whole of it, and from the physical page pair when the block does not and
 * the sequence spans two pages.  What is left — an execute-only sequence
 * entered mid-way WITHIN one page — has no second source, and would show up
 * here as a marker_prefix_unreadable() with no straddle counterpart.  No
 * target this tracer supports maps text that way today.
 */
uint64_t marker_prefix_unreadable(void);
void     marker_prefix_unreadable_note(void);

/*
 * STRADDLE: a marker sequence whose slots span two pages.
 *
 * The bytes are still the bytes, but they are now the bytes of TWO pages,
 * and only one of them is named by the translation block that carries the
 * terminating instruction.  QEMU keys a TB by the physical pages it covers
 * (tb_lookup_cmp compares tb_page_addr0 AND tb_page_addr1), so:
 *
 *   - a TB that COVERS the whole sequence is already keyed by the physical
 *     page pair.  Its answer is decided at translation time and needs no
 *     recheck: any address space that reuses that TB maps the same two
 *     physical pages at those virtual addresses, by QEMU's own key.
 *
 *   - a TB that starts ON the tail's page (a branch target, a fault resume,
 *     -icount, a single-stepping injector) is keyed by that page ALONE.  It
 *     can legitimately be reused by another address space mapping the same
 *     tail page behind a DIFFERENT predecessor page.  Deciding such a
 *     sequence from the tail alone would carry one address space's answer
 *     into another's, so the pair is recorded EXPLICITLY here and the
 *     decision is keyed by it.
 *
 * Two tables, both populated only at translation time:
 *
 *   WITNESS   The predecessor side, keyed by the tail's VIRTUAL address —
 *             that is what the other side knows to come looking with.  When
 *             a TB's trailing instructions are the leading slots of a marker
 *             sequence whose remainder lies past the end of its page, this
 *             records how many slots they were, which sequence(s) they
 *             matched, and the PHYSICAL address they sat at.  That is the
 *             only moment those bytes are knowable on a software-walked
 *             target: the page is resident because QEMU has just translated
 *             code out of it.
 *
 *             A virtual key decides nothing by itself, and this one does
 *             not: the witness only SUPPLIES BYTES, they are re-checked
 *             against the tail page's own content by marker_whole_match, and
 *             what gets recorded is the physical pair below.  A witness left
 *             behind by another address space at the same virtual address
 *             produces a verdict filed under ITS pair, not this one's.
 *
 *   PAIR      The decided verdict, keyed by the TAIL's PHYSICAL address and
 *             carrying the PREFIX's physical page with it.  This is the key
 *             the execution-time fallback consults, and it may answer only
 *             while the tail DETERMINES the pair.  Two things enforce that:
 *             a second, DIFFERENT prefix page recorded behind the same tail
 *             marks the entry conflicting, and the fallback re-asks the
 *             RUNNING address space for the prefix page and refuses on a
 *             mismatch whenever that question can be answered at all.
 *
 *             What neither can see is an address space that maps the same
 *             physical tail page at the same virtual address behind a
 *             different physical predecessor page, has never itself
 *             translated a marker there, AND cannot translate that
 *             predecessor page at the instant its tail runs.  That is the
 *             residual, and it is named here rather than assumed away.  It
 *             is traded against a MEASURED loss — 4 in 200,000 STARTs and a
 *             whole END — which the pair removes.
 *
 * Both are dropped at tb_flush (marker_straddle_reset): every entry is a
 * fact about code QEMU is about to re-translate, which re-establishes it
 * before the sequence can run again, and that bounds how stale a recorded
 * pair can be if the guest rewrites a predecessor page underneath one.
 */
/*
 * @head_slots leading slots, seen on the first page, that matched START
 * and/or END.  BOTH is the ordinary answer for a short head: on the
 * fixed-width targets the two magics differ only in their low half, so a
 * head of one slot is the word they SHARE and cannot say which sequence it
 * belongs to.  It does not have to: the bytes are identical either way, and
 * what distinguishes them is on the tail's own page, which the side that
 * consults this witness is reading out of.  Recording the shared head is
 * the whole point — refusing it is what loses an END whose sequence is
 * split at its first instruction (cell endsig1).
 */
struct MarkerStraddleWitness {
    bool     match_start = false;
    bool     match_end = false;
    uint8_t  head_slots = 0;         /* leading slots seen on the first page */
    uint64_t prefix_paddr = 0;       /* physical address of slot 0 */
};

void marker_straddle_witness_note(uint64_t tail_vaddr,
                                  const MarkerStraddleWitness &w);
bool marker_straddle_witness_get(uint64_t tail_vaddr,
                                 MarkerStraddleWitness *out);

/* Record / consult the decided verdict for the physical page pair. */
void        marker_straddle_pair_note(uint64_t tail_paddr,
                                      uint64_t prefix_paddr, MarkerWhich which);
MarkerWhich marker_straddle_pair_lookup(uint64_t tail_paddr,
                                        uint64_t live_prefix_paddr);

/* Dropped wholesale when QEMU re-translates the world. */
void marker_straddle_reset(void);

uint64_t marker_straddle_pair_resolved(void);   /* read failed, pair decided */
uint64_t marker_straddle_conflicts(void);       /* two pairs, one tail */
uint64_t marker_straddle_undecided(void);       /* MUST BE 0 */
void     marker_straddle_undecided_note(void);

#endif /* CHAMPSIM_TRACER_MARKER_DETECT_H */
