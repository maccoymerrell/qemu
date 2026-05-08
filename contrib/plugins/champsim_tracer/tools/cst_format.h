/*
 * ChampSim Tracer offline tools — format parsers.
 *
 * Reads the trailer + header + templates from a memory-mapped trace
 * file and produces fully-typed cst::Header / cst::Trailer /
 * cst::Template values.  Used by both cst_audit (which only needs
 * the offsets and template count) and cst_decode (which needs the
 * full parsed templates so the body walker can resolve per-(insn,
 * field-id) defaults during delta replay).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "cst_common.h"
#include "cst_reader.h"

namespace cst {

/* Read the fixed-size trailer at the tail of @data and validate its
 * magic.  Throws std::runtime_error on a malformed trailer. */
Trailer parse_trailer(const uint8_t *data, size_t size);

/* Read the variable-length header starting at offset 0 of @data and
 * the encoding-map / initial-regfile section that follows.  Validates
 * that the parser consumed exactly up to @body_off.  Returns the
 * fully-populated Header (with built-in name lookups merged into
 * maps.opcode / maps.reg / etc). */
Header parse_header(const uint8_t *data, size_t size,
                    uint64_t body_off, uint64_t trailer_magic);

/* Read the templates section starting at @templates_off.  Validates
 * the count against @expected (from the trailer).  Returns a vector
 * sorted in file order; @out_by_id is populated with id->index
 * mappings into that vector. */
std::vector<Template> parse_templates(const uint8_t *data, size_t size,
                                      uint64_t templates_off,
                                      uint64_t expected,
                                      std::unordered_map<uint32_t, size_t> *out_by_id);

/* Look up a generic-ID name through the header's encoding maps,
 * falling back to the built-in tables.  These are convenience
 * wrappers around the maps in Header::maps; used mostly by
 * renderers. */
std::string opcode_name(const Header &h, uint64_t id);
std::string branch_type_name(const Header &h, uint64_t id);
std::string sync_hint_name(const Header &h, uint64_t id);
std::string reg_name_or_unknown(const Header &h, uint64_t id);
std::string field_id_name(const Header &h, uint64_t id);

}  /* namespace cst */
