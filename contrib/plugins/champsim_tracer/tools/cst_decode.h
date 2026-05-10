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
#include <memory>

#include "cst_common.h"
#include "cst_format.h"
#include "cst_reader.h"

namespace cst {

/*
 * FieldStateTable storage layout (mirrors the writer's
 * BodyStreamState::cp_field_state, see champsim_tracer_output.cc):
 *
 *   FieldStateTable.blocks  : vector indexed by template_id
 *   FieldStateBlock.values  : flat (n_insns * FIELD_STATE_SLOT_COUNT)
 *                              Wides.  Slot index for a given fid is
 *                              field_state_slot_index(fid); see the
 *                              decoder .cc for the mapping table.
 *   FieldStateBlock.gens    : per-cell generation; cells "exist" only
 *                              when gens[idx] == table.generation.
 *                              Letting the table bump its generation
 *                              invalidates every cell in O(1).
 *
 * Replaces the prior unordered_map<u64, Wide> design (~10% of total
 * decode time in hashtable lookups).  Direct array indexing is a
 * load + compare per cell. */
inline constexpr size_t FIELD_STATE_SLOT_COUNT = 89;
inline constexpr uint8_t FIELD_STATE_SLOT_INVALID = 0xFF;

struct FieldStateBlock {
    uint32_t              n_insns = 0;
    std::vector<Wide>     values;
    std::vector<uint32_t> gens;
};

struct FieldStateTable {
    std::vector<std::unique_ptr<FieldStateBlock>> blocks; /* index = template_id */
    uint32_t generation = 1;
};

/* One initial-regfile slot, parsed from a BODY_TAG_REGFILE record. */
struct RegfileSlot {
    uint8_t                   gen_id  = 0;
    std::vector<uint8_t>      bytes;        /* target-endian raw bytes */
};

/* A BODY_TAG_REGFILE record: per-thread initial-state snapshot.
 * Emitted once per (segment, thread_id) by the writer, before that
 * thread's first ENTRY in the segment.  Decoder consumers may use
 * it to seed simulator state. */
struct DecodedRegfile {
    uint32_t                  thread_id = 0;
    std::vector<RegfileSlot>  regs;
};

class BodyWalker {
public:
    using Callback = std::function<void(const DecodedEntry &)>;
    using RegfileCallback = std::function<void(const DecodedRegfile &)>;

    BodyWalker(const Header &header,
               const std::vector<Template> &templates,
               const std::unordered_map<uint32_t, size_t> &template_by_id,
               const uint8_t *data, size_t size,
               uint64_t body_off, uint64_t body_end);

    /* Walk every body record once.  @cb is invoked with each
     * BODY_TAG_ENTRY's fully-decoded entry; IFRAME records validate
     * against the immediately-preceding ENTRY and do not produce a
     * callback.  THREAD_SWITCH records flip the next entry's
     * thread_id and set thread_switched.  @rb (optional) receives
     * each BODY_TAG_REGFILE record (v1.10+); on v1.9 traces no
     * REGFILE callback fires (the regfile lives on the header). */
    void walk(const Callback &cb,
              const RegfileCallback &rb = {});

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
