/*
 * IR dataflow cross-check (irdf=1) — QEMU's own translation, scored against
 * the tracer's Capstone-derived register sets on every instruction that is
 * translated, not just the ones a hand-written probe ELF happens to contain.
 *
 * Author: Maccoy Merrell
 *
 * This is an INSTRUMENT.  It reads; it never feeds the wire.  A trace
 * captured with irdf=1 is byte-identical to one captured without it, and the
 * comparison's verdict is written to the sidecar log at exit.  Substituting
 * QEMU's sets for Capstone's is a separate, later change: on x86_64 the
 * register namespace holds no vector, x87, selector or MXCSR state at all
 * (35 TCG globals: cc_*, rip, 16 GPRs, 6 segment bases, 8 MPX bounds), so a
 * substitution today would silently drop dependencies the tracer publishes.
 * Measuring the two against each other is what tells us when that stops
 * being true.
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
