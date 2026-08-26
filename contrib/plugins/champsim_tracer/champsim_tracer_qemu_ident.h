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

/* Append the census to the exit report. */
void qemu_ident_report(GString *report);

#endif /* CHAMPSIM_TRACER_QEMU_IDENT_READER_H */
