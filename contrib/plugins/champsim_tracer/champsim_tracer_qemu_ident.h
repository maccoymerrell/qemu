/*
 * ChampSim Tracer — the reader for QEMU's own decode identity.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Author: Maccoy Merrell
 */
#ifndef CHAMPSIM_TRACER_QEMU_IDENT_READER_H
#define CHAMPSIM_TRACER_QEMU_IDENT_READER_H

#include <glib.h>

extern "C" {
#include <qemu-plugin.h>
#include <qemu-plugin-dataflow.h>
}

#include "champsim_tracer_mnemonics.h"

/*
 * Bind the reader to the running ISA's table.  Runs the STATIC checks the
 * table's own header promises and nothing else can: that the rows really
 * are sorted by id (the header tells a consumer to bisect) and that no two
 * rows share one.  Returns the number of static defects; non-zero means the
 * table is stale or hand-edited and the generator would have refused it.
 */
unsigned qemu_ident_install(TraceISA isa);

/*
 * One translated instruction.  Reads the identity QEMU exported for it,
 * finds the row, and scores the row against what Capstone said about the
 * same bytes.  Translation time only, reads only, cannot reach the wire.
 */
void qemu_ident_note(const struct qemu_plugin_insn *insn,
                     const qemu_plugin_insn_info *info);

/*
 * One translated instruction, LENGTH arm.  Independent of the identity
 * table and therefore run on all four targets: @qlen is what QEMU's
 * translator advanced pc by, @caplen what Capstone claims for the same
 * address (0 = it refused), @window_len how many real bytes Capstone was
 * allowed to look at.  A window wider than @qlen is what lets Capstone
 * over-claim and be seen doing it.
 */
void qemu_ident_note_length(uint64_t pc, uint8_t qlen, uint8_t caplen,
                            uint8_t window_len, const char *cap_mnem,
                            const char *qname, const uint8_t *bytes);

/*
 * One translated instruction, BRANCH arm.  @tracer_bt is the branch class
 * the tracer would publish for it (decode_detail_to_generic's answer, alias
 * repairs included), scored against the transfer QEMU's translator actually
 * emitted.  Translation time only, reads only, cannot reach the wire.
 */
void qemu_ident_note_ctrl(const struct qemu_plugin_insn *insn,
                          const qemu_plugin_insn_info *info,
                          uint8_t tracer_bt, const char *qname,
                          uint64_t pc, uint8_t len);

/* Append the census to the exit report. */
void qemu_ident_report(GString *report);

#endif /* CHAMPSIM_TRACER_QEMU_IDENT_READER_H */
