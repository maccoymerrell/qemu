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
 *
 * @wire is the classification the TRACER would PUBLISH for this
 * instruction -- decode_detail_to_generic()'s answer, after the per-
 * instance refiners.  It is a separate argument from @info because the
 * mnemonic table row @info->insn_id indexes is the input to those
 * refiners, not their result: on every family a refiner touches (aarch64
 * `b` vs `b.<cc>`, mips `jr $ra`, `mfhi`/`mflo`, the x86 call-branch
 * callback) the row and the wire hold DIFFERENT values, and a comparison
 * against the row alone can neither confirm nor deny a wire defect there.
 * Both are scored, and the report names which is which.
 */
void qemu_ident_note(const struct qemu_plugin_insn *insn,
                     const qemu_plugin_insn_info *info,
                     const InsnFields *wire);

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
