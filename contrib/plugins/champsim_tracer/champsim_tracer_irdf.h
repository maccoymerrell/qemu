/*
 * IR dataflow cross-check (irdf=1) — QEMU's own translation, scored against
 * the tracer's Capstone-derived register sets on every instruction that is
 * translated, not just the ones a hand-written probe ELF happens to contain.
 *
 * Author: Maccoy Merrell
 *
 * This is an INSTRUMENT.  It reads; it never feeds the wire, and the
 * comparison's verdict is written to the sidecar log at exit.
 *
 * The trace CONTENT is unaffected: decoded and with the recorded invocation
 * and datetime normalised away, a trace captured with irdf=1 is identical to
 * one captured without it (measured on x86_64 and riscv64, cst_runs/p3/arc3/
 * w7/ab/).  This comment used to claim BYTE identity, which cannot be true
 * and is not: the wire records the command line, so an option that appears
 * on it necessarily changes the bytes -- as does the tar mtime, which moves
 * between two runs of the SAME command.  A claim that a byte comparison
 * would have refuted is worse than no claim, because the check it invites
 * fails for a reason that has nothing to do with the instrument.
 *
 * WHAT ITS NUMBER MEANS, because a number whose meaning is unstated gets
 * quoted as whichever thing the reader needed.  irdf is NOT a reference and
 * can never become one: both of its sides derive from this tree.  QEMU's
 * translation of an encoding and the tracer's Capstone decode of the SAME
 * bytes are two accounts of one machine, so agreement between them is
 * evidence of INTERNAL CONSISTENCY and of nothing else, and a disagreement
 * convicts one of the two without saying which.  Its number therefore
 * belongs beside the coverage document's reference legs, never inside their
 * totals.  What it is FOR is the thing an external reference cannot give:
 * it runs on every instruction that is TRANSLATED, so it covers whatever a
 * workload reaches rather than whatever a probe ELF was written to contain,
 * and it is the tripwire that says when the two accounts start to diverge.
 *
 * A CORRECTION, because this comment carried the opposite claim for as long
 * as the instrument has existed.  It used to say that substituting QEMU's
 * sets for Capstone's would drop vector, x87, selector and MXCSR state,
 * because the x86_64 TCG-global namespace holds only 37 names (cc_*, rip,
 * 16 GPRs, 6 segment bases, 8 MPX bounds).  That is this INSTRUMENT's
 * ceiling stated as though it were QEMU's, and it is false.  The 37 globals
 * bound the post-hoc TCG-GLOBAL walk this file performs; QEMU reaches the
 * rest of CPU state by ENV OFFSET, and it already reports those accesses --
 * qemu_plugin_dataflow_field carries env_offset and size, this very file
 * calls qemu_plugin_insn_fields() to see them, and it then throws the answer
 * away and counts the instruction `declined: field`.  x86 vector state is
 * reached at offsetof(CPUX86State, xmm_regs[reg]) (ZMM_OFFSET, target/i386/
 * tcg/emit.c.inc:36, used at :198 and handed to tcg_gen_addi_ptr at :339),
 * and the additive primitives the substitution design specifies are
 * env-offset keyed for exactly that reason (insn_dep_field_src/_dst).  So
 * the blocker the old text described was imaginary; the real work is
 * reading the field records this instrument discards.
 */
#ifndef CHAMPSIM_TRACER_IRDF_H
#define CHAMPSIM_TRACER_IRDF_H

#include <cstddef>

#include <glib.h>

struct qemu_plugin_tb;
struct qemu_plugin_insn_info;

/*
 * Called once per instruction at TRANSLATION time, while @tb is live -- the
 * accessors are keyed on (tb, idx) and there is no later moment at which
 * that pair still means anything.  @info is the tracer's own decode of the
 * same instruction, already filled by the caller.
 *
 * Cheap no-op unless irdf=1: the first call decides, once, whether the ABI
 * handshake and the namespace map succeeded, and a failure disables the
 * instrument loudly rather than scoring against a map it does not trust.
 */
void irdf_note_insn(const struct qemu_plugin_tb *tb, size_t idx,
                    const qemu_plugin_insn_info *info);

/* Arm the instrument from the parsed options.  Off unless irdf=1. */
void irdf_enable(bool on);

/* Append the verdict.  Safe to call when the instrument never ran. */
void irdf_report(GString *report);

#endif /* CHAMPSIM_TRACER_IRDF_H */
