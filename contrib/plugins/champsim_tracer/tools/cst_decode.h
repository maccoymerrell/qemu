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
/* Layout matches FIELD_STATE_SLOT_COUNT in champsim_tracer_output.cc:
 *   1 N_LOADS + 5*16 slotted (load_addr/store_addr/load_data/store_data
 *   /dst_reg) + 1 N_STORES + 7 insn-metadata + 1 METAFLAGS = 90.
 * Bump alongside the writer when new families are added.            */
inline constexpr size_t FIELD_STATE_SLOT_COUNT = 90;
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

/* Structural counts surfaced after walk() completes.  Lets consumers
 * sanity-check writer cadence (one REGFILE per (segment, thread); at
 * least one IFRAME every N entries; no THREAD_SWITCH on single-vCPU
 * traces; no non-NONE sync_hints on synthetic programs) without
 * having to re-walk the body. */
struct BodyStats {
    uint64_t cp_entries        = 0;
    uint64_t wp_entries        = 0;
    uint64_t iframe_count      = 0;
    uint64_t regfile_count     = 0;
    uint64_t thread_switch_count = 0;
    uint64_t fault_count       = 0;
    uint64_t translation_unavail_count = 0;
    /* Per-insn template sync_hint value -> count of insns observed
     * carrying that hint.  Aggregated across both CP and WP entries
     * by template-walk, so each (entry × insn) contributes once. */
    std::unordered_map<uint8_t, uint64_t> sync_hint_counts;
};

class BodyWalker {
public:
    using Callback = std::function<void(const DecodedEntry &)>;
    using RegfileCallback = std::function<void(const DecodedRegfile &)>;

    BodyWalker(const Header &header,
               const std::vector<Template> &templates,
               const std::unordered_map<uint32_t, size_t> &template_by_id,
               Reader &body);

    /* Stop after @n BODY_TAG_ENTRY records; 0 = unlimited.  Set this
     * before calling walk().  When the limit fires, walk() returns
     * without consuming BODY_TAG_END; the caller must skip the
     * trailing-magic check in that case (the body wasn't fully
     * drained). */
    void set_max_entries(uint64_t n) { max_entries_ = n; }

    const BodyStats &stats() const { return stats_; }

    /* Walk every body record once.  @cb is invoked with each
     * BODY_TAG_ENTRY's fully-decoded entry; IFRAME records validate
     * against the immediately-preceding ENTRY and do not produce a
     * callback.  THREAD_SWITCH records flip the next entry's
     * thread_id and set thread_switched.  @rb (optional) receives
     * each BODY_TAG_REGFILE record. */
    void walk(const Callback &cb,
              const RegfileCallback &rb = {});

private:
    void  decode_field_delta(Reader &r, uint32_t template_id,
                             const Template *tmpl,
                             FieldStateTable &state,
                             const FieldStateTable *base_state,
                             std::vector<DynParam>       *dyn_params,
                             std::vector<RegSnap>        *reg_snaps,
                             std::vector<MetaFlagsEntry> *metaflags);
    Wide  template_default(const Template *tmpl,
                           uint32_t ipos, uint8_t fid) const;

    const Header                                       &header_;
    const std::vector<Template>                        &templates_;
    const std::unordered_map<uint32_t, size_t>         &by_id_;
    Reader                                             &body_;
    uint64_t                                            max_entries_ = 0;

    int      scalar_bits_;
    uint8_t  flags_;
    /* REG_FLAGS' numeric id, resolved from the trace's "reg" encoding
     * map at construction.  -1 if the trace doesn't name a flags
     * register (e.g. RISC-V), in which case no metaflags are surfaced. */
    int      reg_flags_id_;
    /* fid -> dense slot index, built from header_.ids at construction.
     * EXTRA_* / EXTENDED return FIELD_STATE_SLOT_INVALID. */
    std::array<uint8_t, 256> slot_lut_{};
    BodyStats stats_;
};

/*
 * Fan a DecodedEntry out into a sequence of per-instance Instruction
 * containers.  Order: every CP insn of the parent BB in template
 * order (CP), then for each WP entry in chain order every insn of
 * that WP's template (WP).  Per-insn dyn_params / reg_snaps /
 * metaflags are filtered down to just the relevant insn.  Branch
 * target templates are resolved when the trailing CP / WP insn
 * carries a recognised direct branch immediate.
 *
 * Renderers and simulators that prefer "one instruction at a time"
 * walk the returned vector; the walker-level DecodedEntry is no
 * longer needed once the fan-out is built.
 */
std::vector<Instruction> instructions_from_entry(
    const DecodedEntry &entry,
    const Header &h,
    const std::vector<Template> &templates,
    const std::unordered_map<uint32_t, size_t> &template_by_id);

}  /* namespace cst */
