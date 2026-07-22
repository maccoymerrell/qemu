/*
 * cst_decode --format=raw — pseudo-wire structural dump.
 *
 * Walks the raw bytes of a .cst trace (header member then body record
 * stream) and prints every field, record, and section in decode order,
 * annotated with its byte offset and the docs/format.rst
 * recipe step that produced it.  Unlike the disasm/legacy renderers it
 * does NOT reconstruct architectural state — it surfaces the wire
 * structure verbatim (tags, ULEB/SLEB framing, per-record field-deltas)
 * for debugging a producer or a third-party reader.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <cstdint>
#include <cstdio>
#include <unordered_map>
#include <vector>

#include "cst_common.h"
#include "cst_format.h"

namespace cst {

/* Emit the pseudo-wire dump of @cf to @out.  @h / @templates / @by_id
 * are the already-parsed header (used only for the encoding-map name
 * resolution the dump annotates each numeric id with).  @max_entries
 * stops the body walk after that many BODY_TAG_ENTRY records (0 =
 * unbounded); when it fires the trailing-magic check is skipped, exactly
 * like the other renderers under --max. */
void render_raw(FILE *out, const CstFile &cf, const Header &h,
                const std::vector<Template> &templates,
                const std::unordered_map<uint32_t, size_t> &by_id,
                uint64_t max_entries);

}  /* namespace cst */
