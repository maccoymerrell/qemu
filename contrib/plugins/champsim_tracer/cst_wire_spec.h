/*
 * ChampSim Tracer — shared wire-format invariants.
 *
 * Single source of truth for the handful of format constants that BOTH
 * the plugin (champsim_tracer.h) and the offline tools (tools/cst_common.h)
 * must agree on.  Each side keeps its own historical spelling as a thin
 * alias to the values defined here, so the magic and the layout caps can
 * never silently diverge between writer and readers.
 *
 * Only invariants are shared.  The field-ID enum is deliberately NOT here:
 * the tools resolve field IDs by NAME out of the trace's own encoding
 * maps, never by compile-time value, so the numeric enum stays plugin-only.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_CST_WIRE_SPEC_H
#define CHAMPSIM_TRACER_CST_WIRE_SPEC_H

#include <cstdint>

namespace cst_wire {

/* Format-epoch identifier, written at the start of each .cst member and
 * as a trailing sentinel after BODY_TAG_END.  Frozen pre-release. */
inline constexpr uint32_t MAGIC          = 0x1D545343u;

/* Maximum raw bytes captured per instruction (fixed-stride insn_bytes). */
inline constexpr int      INSN_BYTES_MAX = 16;

/* Slots per slotted field-ID family (e.g. one per insn position). */
inline constexpr int      FID_SLOT_COUNT = 64;

/* 512-bit data / register scalar cap, in bytes. */
inline constexpr int      WIDE_BYTES_MAX = 64;

/* Physical-page granule for the CST_FID_*_PPAGE families (physaddr=1,
 * system mode).  A ppage is the physical address masked to this page
 * shift; a consumer rebuilds the full physical address as
 *   ppage | (vaddr & PPAGE_OFFSET_MASK).
 * Fixed at 4 KiB — the low 12 bits of a virtual address equal the low 12
 * bits of its physical address for every hardware page size >= 4 KiB, so
 * the reconstruction is exact regardless of the guest's actual page size. */
inline constexpr int      PPAGE_SHIFT       = 12;
inline constexpr uint64_t PPAGE_OFFSET_MASK = (uint64_t(1) << PPAGE_SHIFT) - 1;

} /* namespace cst_wire */

#endif /* CHAMPSIM_TRACER_CST_WIRE_SPEC_H */
