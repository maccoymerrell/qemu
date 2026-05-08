/*
 * ChampSim Tracer offline tools — body walker / delta replay.
 *
 * Streams cst::DecodedEntry values out of a memory-mapped trace's
 * body section by walking the unified delta stream and rebuilding
 * the per-(template, insn-position, field-id) state across entries.
 * Mirrors champsim_tracer_decode.py's _iter_body_entries +
 * _decode_field_delta_section.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <functional>

#include "cst_common.h"
#include "cst_format.h"
#include "cst_reader.h"

namespace cst {

/* Per-(template, ipos, field-id) cell: a Wide value plus a "set" bit
 * so a missed lookup can fall through to the template default
 * cleanly.  Keyed by a 32-bit composite (template_id<<24 | ipos<<8 |
 * fid), same layout as the Python decoder. */
struct FieldStateTable {
    /* unordered_map keyed by composite int (template_id<<24 |
     * ipos<<8 | fid).  Trace state is inherently sparse: only
     * (template, ipos, fid) cells the writer actually emitted are
     * present.  Key needs at least 40 bits — uint64_t to leave room
     * for traces with many thousands of templates. */
    std::unordered_map<uint64_t, Wide> cells;
};

class BodyWalker {
public:
    using Callback = std::function<void(const DecodedEntry &)>;

    BodyWalker(const Header &header,
               const std::vector<Template> &templates,
               const std::unordered_map<uint32_t, size_t> &template_by_id,
               const uint8_t *data, size_t size,
               uint64_t body_off, uint64_t body_end);

    /* Walk every body record once.  @cb is invoked with each
     * BODY_TAG_ENTRY's fully-decoded entry; IFRAME records validate
     * against the immediately-preceding ENTRY and do not produce a
     * callback.  THREAD_SWITCH records flip the next entry's
     * thread_id and set thread_switched. */
    void walk(const Callback &cb);

private:
    void  decode_field_delta(Reader &r, uint32_t template_id,
                             const Template *tmpl,
                             FieldStateTable &state,
                             const FieldStateTable *base_state,
                             std::vector<DynParam> *dyn_params,
                             std::vector<RegSnap>  *reg_snaps);
    Wide  template_default(const Template *tmpl,
                           uint32_t ipos, uint8_t fid) const;

    const Header                                       &header_;
    const std::vector<Template>                        &templates_;
    const std::unordered_map<uint32_t, size_t>         &by_id_;
    Reader                                              body_;

    int      scalar_bits_;
    bool     wp_persistent_;
    uint8_t  flags_;
};

}  /* namespace cst */
