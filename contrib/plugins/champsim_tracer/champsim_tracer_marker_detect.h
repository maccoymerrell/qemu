/*
 * Wrong-Path Tracing Plugin — marker byte-sequence detection.
 *
 * The per-ISA START/END marker sequences (MarkerSeq / g_marker_seq) and the
 * execution-time adjacency runs (MarkerRunSet) that recognise them in the
 * user-space instruction stream.  Extracted verbatim from champsim_tracer.cc;
 * the marker callbacks (which own the one-shot fired flag and the per-thread
 * run sets) stay there and drive these primitives.
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
 * CST_MARKER_SEQ_LEN times (so their per-insn words ALTERNATE — the
 * detector matches by sequence position, not by identical-insn run).
 */
struct MarkerSeq {
    uint8_t start[CST_MARKER_PAIR_SEQ_BYTES];
    uint8_t end[CST_MARKER_PAIR_SEQ_BYTES];
    uint8_t insn_bytes = 0;            /* fixed insn width in the seq */
    uint8_t n_insns    = 0;            /* insns per full sequence */
    bool    valid      = false;
};

extern MarkerSeq g_marker_seq;

/* Build g_marker_seq's START/END byte patterns for the active target ISA. */
void marker_seq_init(void);

/* Does @bytes/@size match ANY per-insn word of @seq?  Membership is all
 * translation needs to know: consecutivity is judged at EXECUTION time,
 * in the user-space instruction stream, by PC adjacency (below) — so the
 * marker is detected regardless of how translation happens to slice it
 * into TBs (page splits, single-stepping under a guest debugger/ptrace
 * injector, chained 1-insn TBs). */
bool marker_word_match(const uint8_t *seq, const uint8_t *bytes, uint8_t size);

/*
 * Execution-time marker run, per thread: three(+) marker instructions are
 * a marker exactly when they are CONSECUTIVE IN THE USER-SPACE STREAM —
 * i.e. each executes at user privilege, in the same address space, at the
 * PC immediately after the previous one.  Kernel instructions interposed
 * between them (single-step traps, interrupts) do not break the run: they
 * never match the adjacency test and are not part of the user stream.
 * A marker insn that is NOT adjacent to the previous one simply starts a
 * fresh run of length 1.
 */
struct MarkerExecRun {
    uint64_t next_pc = 0;      /* pc the run's next insn must have */
    uint64_t asid = 0;         /* the address space this run belongs to */
    uint32_t run = 0;          /* run length so far (0 == free slot) */
    uint32_t used = 0;         /* LRU timestamp (0 == never advanced) */
};

/*
 * Per-vCPU set of in-flight marker runs, one slot per address space.
 *
 * A single shared run per vCPU cannot survive CONCURRENT ptrace injections:
 * cst_attach single-steps the marker's instructions (each a separate
 * ptrace stop -> resume, with a scheduling window between them), so two
 * simultaneous injections interleave in the user stream — A1, B1, A2, B2,
 * A3, B3.  A single run keyed nothing but "the last marker word seen"
 * resets on every foreign-asid step (the old `else { run = 1; asid = a; }`
 * branch), so NEITHER injection ever reaches full sequence length: they
 * mutually cancel (observed: traced_icount=0 on a simultaneous 2xmcf
 * launch).  Compiled-in markers execute back-to-back and so never exposed
 * this — only the stepped injector interleaves.
 *
 * Keying each run by address space isolates the injections: asid A advances
 * its own run across B's interposed steps, and vice versa.  Bounded to a
 * handful of slots (concurrent injections are few — the working set during
 * a simultaneous launch is just the injecting asids); the least-recently-
 * advanced slot is evicted when full.  A legitimate marker's words are
 * back-to-back in the user stream, so an evicted stale partial run costs
 * nothing (it would reset on its next non-adjacent word anyway).  A single
 * address space (user mode, or a compiled-in back-to-back marker) uses
 * exactly one slot and behaves identically to the former single run, so
 * those traces stay byte-identical.
 */
struct MarkerRunSet {
    static constexpr int SLOTS = 8;
    MarkerExecRun runs[SLOTS];
    uint32_t tick = 0;         /* monotonic LRU clock */
};

/* udata for the per-insn marker exec cb: the insn's vaddr and size packed
 * into a pointer-sized word (size in the low byte; marker insns are
 * 4/5/8-byte encodings, and vaddrs on every target fit 56 bits). */
static inline void *marker_udata_pack(uint64_t pc, uint8_t size)
{
    return (void *)(uintptr_t)((pc << 8) | size);
}

static inline void marker_udata_unpack(void *udata, uint64_t *pc,
                                       uint8_t *size)
{
    uintptr_t v = (uintptr_t)udata;
    *size = (uint8_t)(v & 0xff);
    *pc = (uint64_t)(v >> 8);
}

/* Read-only peek at @asid's current run (diagnostics only); null if none. */
const MarkerExecRun *marker_run_peek(const MarkerRunSet *set, uint64_t asid);

/* Advance the current address space's execution-time run with this marker-
 * word execution; returns true when that run reaches full sequence length.
 * Runs are kept per address space (see MarkerRunSet) so a concurrently
 * injected marker in a different address space does not reset this one. */
bool marker_exec_step(MarkerRunSet *set, uint64_t pc, uint8_t size);

#endif /* CHAMPSIM_TRACER_MARKER_DETECT_H */
