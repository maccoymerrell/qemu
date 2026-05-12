/*
 * ChampSim Tracer offline tools — body walker / delta replay (impl).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cst_decode.h"

#include <cstdio>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace cst {

namespace {

static bool is_extra_vector_fid(const ResolvedIds &ids, uint8_t fid)
{
    return fid == ids.fid_extra_load_addr ||
           fid == ids.fid_extra_store_addr ||
           fid == ids.fid_extra_load_data ||
           fid == ids.fid_extra_store_data;
}

/*
 * Build the fid -> dense slot index map for FieldStateBlock storage.
 * Mirrors the writer's field_state_slot_lut (see
 * champsim_tracer_output.cc field_state_slot_lut_build).  EXTRA_* and
 * EXTENDED implicitly return SLOT_INVALID (the lut is initialised to
 * INVALID and these fids are never assigned a slot) — those fids are
 * handled out-of-band (per-entry vector records / extension stream)
 * and never sit in the persistent state.
 */
static void slot_lut_build(const ResolvedIds &ids,
                           std::array<uint8_t, 256> *out)
{
    out->fill(FIELD_STATE_SLOT_INVALID);
    (*out)[ids.fid_n_loads] = 0;
    for (unsigned k = 0; k < FID_SLOT_COUNT; k++) {
        (*out)[ids.fid_load_addr_base  + k] = (uint8_t)(1                + k);
        (*out)[ids.fid_store_addr_base + k] = (uint8_t)(1 + 1*FID_SLOT_COUNT + k);
        (*out)[ids.fid_load_data_base  + k] = (uint8_t)(1 + 2*FID_SLOT_COUNT + k);
        (*out)[ids.fid_store_data_base + k] = (uint8_t)(1 + 3*FID_SLOT_COUNT + k);
        (*out)[ids.fid_dst_reg_base    + k] = (uint8_t)(1 + 4*FID_SLOT_COUNT + k);
    }
    (*out)[ids.fid_n_stores] = (uint8_t)(1 + 5*FID_SLOT_COUNT);
    for (unsigned f = ids.fid_insn_bytes_lo; f <= ids.fid_insn_size; f++) {
        (*out)[f] = (uint8_t)(2 + 5*FID_SLOT_COUNT +
                              (f - ids.fid_insn_bytes_lo));
    }
    /* METAFLAGS sits immediately after the insn-metadata band.  See
     * the matching slot assignment in champsim_tracer_output.cc.    */
    (*out)[ids.fid_metaflags] = (uint8_t)(2 + 5*FID_SLOT_COUNT +
        (ids.fid_insn_size - ids.fid_insn_bytes_lo + 1));
}

/* Resize/grow a block's storage to accommodate @n_insns instructions.
 * Idempotent; never shrinks. */
void block_ensure_capacity(FieldStateBlock *blk, uint32_t n_insns)
{
    if (blk->n_insns >= n_insns) return;
    size_t new_cells = (size_t)n_insns * FIELD_STATE_SLOT_COUNT;
    blk->values.resize(new_cells);
    blk->gens.resize(new_cells, 0);
    blk->n_insns = n_insns;
}

FieldStateBlock *table_get_or_create_block(FieldStateTable &t,
                                           uint32_t template_id,
                                           uint32_t need_n_insns)
{
    if (template_id >= t.blocks.size()) {
        t.blocks.resize((size_t)template_id + 1);
    }
    auto &slot = t.blocks[template_id];
    if (!slot) {
        slot = std::make_unique<FieldStateBlock>();
    }
    block_ensure_capacity(slot.get(), need_n_insns);
    return slot.get();
}

const FieldStateBlock *table_get_block(const FieldStateTable &t,
                                       uint32_t template_id)
{
    if (template_id >= t.blocks.size()) return nullptr;
    return t.blocks[template_id].get();
}

/*
 * Read cell (block, ipos, fid).  Falls through to base_state on miss,
 * then to template_default; returns whether the lookup hit a real
 * (writer-set) cell — the boolean lets the field-extender code
 * distinguish "we have a value" from "this is the template default
 * silently filled in."
 */
bool cell_read(const FieldStateBlock *blk, uint32_t table_gen,
               uint32_t ipos, uint8_t slot, Wide *out)
{
    if (!blk || ipos >= blk->n_insns || slot == FIELD_STATE_SLOT_INVALID) {
        return false;
    }
    size_t idx = (size_t)ipos * FIELD_STATE_SLOT_COUNT + slot;
    if (blk->gens[idx] != table_gen) return false;
    *out = blk->values[idx];
    return true;
}

void cell_write(FieldStateBlock *blk, uint32_t table_gen,
                uint32_t ipos, uint8_t slot, const Wide &val)
{
    if (!blk || slot == FIELD_STATE_SLOT_INVALID) return;
    block_ensure_capacity(blk, ipos + 1);
    size_t idx = (size_t)ipos * FIELD_STATE_SLOT_COUNT + slot;
    blk->values[idx] = val;
    blk->gens[idx] = table_gen;
}

/*
 * Compare two DynParam vectors for IFRAME validation.  Order is
 * meaningful (encoded position-then-type within a template walk),
 * so we compare elementwise rather than as a multiset.  Returns the
 * 1-based index of the first differing element (1..N) or 0 if all
 * elements match through min(size).  size mismatch is reported via
 * the count check that calls this helper.
 */
size_t first_dyn_param_diff(const std::vector<DynParam> &a,
                            const std::vector<DynParam> &b)
{
    size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; i++) {
        if (a[i].type != b[i].type ||
            a[i].insn_index != b[i].insn_index ||
            a[i].addr != b[i].addr ||
            a[i].has_data != b[i].has_data ||
            (a[i].has_data && a[i].data != b[i].data)) {
            return i + 1;
        }
    }
    return 0;
}

size_t first_reg_snap_diff(const std::vector<RegSnap> &a,
                           const std::vector<RegSnap> &b)
{
    size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; i++) {
        if (a[i].insn_index != b[i].insn_index ||
            a[i].operand_index != b[i].operand_index ||
            a[i].reg_id != b[i].reg_id ||
            a[i].value != b[i].value) {
            return i + 1;
        }
    }
    return 0;
}

size_t first_metaflags_diff(const std::vector<MetaFlagsEntry> &a,
                            const std::vector<MetaFlagsEntry> &b)
{
    size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; i++) {
        if (a[i].insn_index != b[i].insn_index ||
            a[i].byte != b[i].byte) {
            return i + 1;
        }
    }
    return 0;
}

/*
 * Throw a descriptive runtime_error when the IFRAME-decoded entry
 * disagrees with the immediately-preceding ENTRY.  Validates:
 *   - template_id (carried over implicitly; we set it ourselves but
 *     check anyway as a backstop against future refactors)
 *   - dyn_params count + each (type, insn_index, addr, has_data, data)
 *   - reg_snaps count + each (insn_index, operand_index, reg_id, value)
 *   - WP chain: count, plus per-entry template_id + dyn_params + reg_snaps
 *   - WP events: per-entry fault, translation_unavailable, fault_insn_index
 */
void validate_iframe(const DecodedEntry &prev, const DecodedEntry &iframe)
{
    auto fail = [&](const std::string &msg) {
        throw std::runtime_error("IFRAME validation: " + msg +
                                 " (seq=" +
                                 std::to_string(prev.seq_num) + ")");
    };

    if (prev.template_id != iframe.template_id) {
        fail("template_id mismatch: ENTRY=" +
             std::to_string(prev.template_id) +
             " IFRAME=" + std::to_string(iframe.template_id));
    }
    if (prev.dyn_params.size() != iframe.dyn_params.size()) {
        fail("CP dyn_params count mismatch: ENTRY=" +
             std::to_string(prev.dyn_params.size()) +
             " IFRAME=" + std::to_string(iframe.dyn_params.size()));
    }
    if (size_t d = first_dyn_param_diff(prev.dyn_params, iframe.dyn_params)) {
        fail("CP dyn_params[" + std::to_string(d - 1) + "] mismatch");
    }
    if (prev.reg_snaps.size() != iframe.reg_snaps.size()) {
        fail("CP reg_snaps count mismatch: ENTRY=" +
             std::to_string(prev.reg_snaps.size()) +
             " IFRAME=" + std::to_string(iframe.reg_snaps.size()));
    }
    if (size_t d = first_reg_snap_diff(prev.reg_snaps, iframe.reg_snaps)) {
        fail("CP reg_snaps[" + std::to_string(d - 1) + "] mismatch");
    }
    if (prev.metaflags.size() != iframe.metaflags.size()) {
        fail("CP metaflags count mismatch: ENTRY=" +
             std::to_string(prev.metaflags.size()) +
             " IFRAME=" + std::to_string(iframe.metaflags.size()));
    }
    if (size_t d = first_metaflags_diff(prev.metaflags, iframe.metaflags)) {
        fail("CP metaflags[" + std::to_string(d - 1) + "] mismatch");
    }

    if (prev.wp_entries.size() != iframe.wp_entries.size()) {
        fail("WP chain length mismatch: ENTRY=" +
             std::to_string(prev.wp_entries.size()) +
             " IFRAME=" + std::to_string(iframe.wp_entries.size()));
    }
    for (size_t w = 0; w < prev.wp_entries.size(); w++) {
        const WPEntry &pe = prev.wp_entries[w];
        const WPEntry &ie = iframe.wp_entries[w];
        std::string ws = "wp[" + std::to_string(w) + "]";
        if (pe.template_id != ie.template_id) {
            fail(ws + " template_id mismatch: ENTRY=" +
                 std::to_string(pe.template_id) +
                 " IFRAME=" + std::to_string(ie.template_id));
        }
        if (pe.dyn_params.size() != ie.dyn_params.size()) {
            fail(ws + " dyn_params count mismatch: ENTRY=" +
                 std::to_string(pe.dyn_params.size()) +
                 " IFRAME=" + std::to_string(ie.dyn_params.size()));
        }
        if (size_t d = first_dyn_param_diff(pe.dyn_params, ie.dyn_params)) {
            fail(ws + " dyn_params[" + std::to_string(d - 1) + "] mismatch");
        }
        if (pe.reg_snaps.size() != ie.reg_snaps.size()) {
            fail(ws + " reg_snaps count mismatch: ENTRY=" +
                 std::to_string(pe.reg_snaps.size()) +
                 " IFRAME=" + std::to_string(ie.reg_snaps.size()));
        }
        if (size_t d = first_reg_snap_diff(pe.reg_snaps, ie.reg_snaps)) {
            fail(ws + " reg_snaps[" + std::to_string(d - 1) + "] mismatch");
        }
        if (pe.metaflags.size() != ie.metaflags.size()) {
            fail(ws + " metaflags count mismatch: ENTRY=" +
                 std::to_string(pe.metaflags.size()) +
                 " IFRAME=" + std::to_string(ie.metaflags.size()));
        }
        if (size_t d = first_metaflags_diff(pe.metaflags, ie.metaflags)) {
            fail(ws + " metaflags[" + std::to_string(d - 1) + "] mismatch");
        }
        if (pe.fault != ie.fault) {
            fail(ws + " fault flag mismatch");
        }
        if (pe.translation_unavailable != ie.translation_unavailable) {
            fail(ws + " translation_unavailable flag mismatch");
        }
        if (pe.fault && pe.fault_insn_index != ie.fault_insn_index) {
            fail(ws + " fault_insn_index mismatch: ENTRY=" +
                 std::to_string(pe.fault_insn_index) +
                 " IFRAME=" + std::to_string(ie.fault_insn_index));
        }
    }
}

/* Compose a template-default Wide for the FID_INSN_* range, where the
 * baseline is the template's static value (so an emit-equal-to-
 * template produces no record on the wire).  Other FID ranges
 * default to zero; callers handle that path inline. */
static Wide insn_field_default(const InsnTemplate &I, uint8_t fid,
                               const ResolvedIds &ids)
{
    Wide w;
    if (fid == ids.fid_insn_bytes_lo || fid == ids.fid_insn_bytes_hi) {
        size_t off = (fid == ids.fid_insn_bytes_lo) ? 0 : 8;
        size_t take = std::min<size_t>(8, I.raw_bytes.size() > off
                                          ? I.raw_bytes.size() - off : 0);
        if (take) {
            uint64_t v = 0;
            std::memcpy(&v, I.raw_bytes.data() + off, take);
            w.limb[0] = v;
        }
        return w;
    }
    if (fid == ids.fid_insn_opcode)      { w.limb[0] = I.opcode; }
    else if (fid == ids.fid_insn_branch_type) { w.limb[0] = I.branch_type; }
    else if (fid == ids.fid_insn_flags) {
        uint64_t f = 0;
        if (I.branch_conditional) f |= ids.insn_flag_branch_cond;
        if (I.has_imm)            f |= ids.insn_flag_has_imm;
        f |= ((uint64_t)I.sync_hint << INSN_FLAG_SYNC_SHIFT) & INSN_FLAG_SYNC_MASK;
        w.limb[0] = f & 0xFF;
    }
    else if (fid == ids.fid_insn_immediate) { w.limb[0] = (uint64_t)I.imm; }
    else if (fid == ids.fid_insn_size)      { w.limb[0] = I.raw_bytes.size() & 0xFF; }
    return w;
}

}  /* namespace */

Wide BodyWalker::template_default(const Template *tmpl,
                                  uint32_t ipos, uint8_t fid) const
{
    if (!tmpl || ipos >= tmpl->insns.size()) return Wide{};
    const ResolvedIds &ids = header_.ids;
    if (fid >= ids.fid_insn_bytes_lo && fid <= ids.fid_insn_size) {
        return insn_field_default(tmpl->insns[ipos], fid, ids);
    }
    return Wide{};
}

BodyWalker::BodyWalker(const Header &header,
                       const std::vector<Template> &templates,
                       const std::unordered_map<uint32_t, size_t> &template_by_id,
                       Reader &body)
    : header_(header),
      templates_(templates),
      by_id_(template_by_id),
      body_(body),
      scalar_bits_(header.scalar_width_bits()),
      flags_(header.flags),
      reg_flags_id_(-1)
{
    /* Resolve REG_FLAGS' numeric id from the trace's own reg map.
     * The trace is self-describing; no compile-time table lives here. */
    for (const auto &kv : header.maps.reg) {
        if (kv.second == "REG_FLAGS") {
            reg_flags_id_ = (int)kv.first;
            break;
        }
    }
    slot_lut_build(header_.ids, &slot_lut_);
}

void BodyWalker::walk(const Callback &cb,
                      const RegfileCallback &rb)
{
    int32_t prev_entry_template = 0;
    uint32_t current_thread = 0;
    bool pending_thread_switch = false;
    /*
     * Per-thread FieldStateTables, std::vector indexed by thread_id
     * (dense small ints handed out by the writer's
     * get_or_assign_thread_id).
     */
    std::vector<FieldStateTable> cp_states;
    std::vector<FieldStateTable> wp_states;
    auto state_at = [&](std::vector<FieldStateTable> &v,
                        uint32_t k) -> FieldStateTable & {
        if (k >= v.size()) v.resize((size_t)k + 1);
        return v[k];
    };
    std::optional<DecodedEntry> prev_entry;
    uint32_t seq = 0;
    std::optional<uint64_t> footer_num_entries;

    const ResolvedIds &ids = header_.ids;
    while (true) {
        uint8_t tag = body_.u8();

        if (tag == ids.body_tag_end) {
            footer_num_entries = body_.uleb();
            break;
        }
        if (tag == ids.body_tag_thread_switch) {
            int64_t d = body_.sleb();
            current_thread = (uint32_t)((int64_t)current_thread + d);
            pending_thread_switch = true;
            stats_.thread_switch_count++;
            continue;
        }
        if (tag == ids.body_tag_regfile) {
            DecodedRegfile rec;
            rec.thread_id = (uint32_t)body_.uleb();
            uint64_t n_present = body_.uleb();
            rec.regs.reserve(n_present);
            for (uint64_t i = 0; i < n_present; i++) {
                RegfileSlot s;
                s.gen_id = body_.u8();
                uint8_t width = body_.u8();
                s.bytes.resize(width);
                if (width) {
                    body_.raw(s.bytes.data(), width);
                }
                rec.regs.push_back(std::move(s));
            }
            if (rb) rb(rec);
            stats_.regfile_count++;
            continue;
        }
        if (tag == ids.body_tag_entry) {
            int64_t tdelta = body_.sleb();
            int32_t entry_tmpl = prev_entry_template + (int32_t)tdelta;
            prev_entry_template = entry_tmpl;

            FieldStateTable &cp_state = state_at(cp_states, current_thread);
            FieldStateTable &wp_state = state_at(wp_states, current_thread);

            DecodedEntry entry;
            entry.template_id = (uint32_t)entry_tmpl;

            /* CP delta section. */
            const Template *cp_tmpl = by_id_.count((uint32_t)entry_tmpl)
                ? &templates_[by_id_.at((uint32_t)entry_tmpl)] : nullptr;
            decode_field_delta(body_, (uint32_t)entry_tmpl, cp_tmpl,
                               cp_state, nullptr,
                               &entry.dyn_params, &entry.reg_snaps,
                               &entry.metaflags);

            /* WP chain section. */
            Reader wpb = body_.sub();
            uint64_t num_wp = wpb.uleb();
            int32_t prev_wp_tmpl = 0;
            const FieldStateTable *wp_base = &cp_state;
            for (uint64_t w = 0; w < num_wp; w++) {
                int64_t wd = wpb.sleb();
                int32_t wp_tmpl = prev_wp_tmpl + (int32_t)wd;
                prev_wp_tmpl = wp_tmpl;
                WPEntry we;
                we.index = (uint32_t)w;
                we.template_id = (uint32_t)wp_tmpl;
                const Template *wtmpl = by_id_.count((uint32_t)wp_tmpl)
                    ? &templates_[by_id_.at((uint32_t)wp_tmpl)] : nullptr;
                if (wtmpl) we.n_insns = (uint32_t)wtmpl->insns.size();
                decode_field_delta(wpb, (uint32_t)wp_tmpl, wtmpl,
                                   wp_state, wp_base,
                                   &we.dyn_params, &we.reg_snaps,
                                   &we.metaflags);
                entry.wp_entries.push_back(std::move(we));
            }

            /* WP events sub-section. */
            Reader evb = body_.sub();
            uint64_t num_events = evb.uleb();
            int64_t prev_idx = -1;
            for (uint64_t k = 0; k < num_events; k++) {
                uint64_t gap = evb.uleb();
                int64_t idx = prev_idx + 1 + (int64_t)gap;
                if (idx >= (int64_t)num_wp) {
                    throw std::runtime_error("wp event index out of range");
                }
                uint8_t evf = evb.u8();
                entry.wp_entries[idx].translation_unavailable =
                    (evf & ids.wp_event_translation_unavail) != 0;
                bool is_fault = (evf & ids.wp_event_fault) != 0;
                entry.wp_entries[idx].fault = is_fault;
                if (is_fault) {
                    entry.wp_entries[idx].fault_insn_index =
                        (uint32_t)evb.uleb();
                    entry.wp_entries[idx].has_fault_idx = true;
                }
                prev_idx = idx;
            }

            entry.thread_id = current_thread;
            entry.thread_switched = pending_thread_switch;
            entry.seq_num = ++seq;
            pending_thread_switch = false;

            stats_.cp_entries++;
            stats_.wp_entries += entry.wp_entries.size();
            for (const auto &we : entry.wp_entries) {
                if (we.fault) stats_.fault_count++;
                if (we.translation_unavailable) {
                    stats_.translation_unavail_count++;
                }
            }
            /* Aggregate sync_hint values: walk every insn position in
             * every CP+WP template touched by this entry.  This counts
             * each (template,insn) once per entry it appears in, so a
             * hot block contributes multiple times — matches the
             * "how many insn observations carried this hint" intent. */
            if (auto it = by_id_.find(entry.template_id);
                it != by_id_.end()) {
                const Template &t = templates_[it->second];
                for (const auto &I : t.insns) {
                    stats_.sync_hint_counts[I.sync_hint]++;
                }
            }
            for (const auto &we : entry.wp_entries) {
                auto wit = by_id_.find(we.template_id);
                if (wit == by_id_.end()) continue;
                const Template &t = templates_[wit->second];
                for (const auto &I : t.insns) {
                    stats_.sync_hint_counts[I.sync_hint]++;
                }
            }

            cb(entry);
            prev_entry = std::move(entry);
            if (max_entries_ && stats_.cp_entries >= max_entries_) {
                /* Early stop.  Caller skips trailing-magic check; the
                 * underlying decompressor subprocess (if any) is torn
                 * down when the Reader's Source is destroyed. */
                return;
            }
            continue;
        }
        if (tag == ids.body_tag_iframe) {
            /*
             * Validation record: decode the IFRAME against fresh empty
             * overlays (so every value is delta-from-template-default
             * = absolute) and assert it matches the immediately-
             * preceding ENTRY's dyn_params, reg_snaps, WP chain, and
             * WP events.  An IFRAME is the writer's claim that "after
             * the prior ENTRY the per-thread state is exactly this";
             * if the decoder's delta-replay disagrees, throw — the
             * trace is corrupt or the encoder/decoder are out of sync.
             */
            if (!prev_entry) {
                throw std::runtime_error("IFRAME with no preceding ENTRY");
            }
            FieldStateTable iframe_cp;
            FieldStateTable iframe_wp;
            DecodedEntry iframe_entry;
            iframe_entry.template_id = prev_entry->template_id;
            decode_field_delta(body_, prev_entry->template_id,
                               by_id_.count(prev_entry->template_id)
                                   ? &templates_[by_id_.at(prev_entry->template_id)]
                                   : nullptr,
                               iframe_cp, nullptr,
                               &iframe_entry.dyn_params,
                               &iframe_entry.reg_snaps,
                               &iframe_entry.metaflags);

            /* WP chain.  Mirror the encoder's IFRAME emission: the
             * iframe_wp overlay falls back to iframe_cp as base
             * (writer uses st->iframe_cp_scratch for both wp_state
             * and wp_base in IFRAME mode) so unset cells fall through
             * to the same place the cp section just populated. */
            Reader wpb = body_.sub();
            uint64_t num_wp = wpb.uleb();
            int32_t prev_wp_tmpl = 0;
            iframe_entry.wp_entries.reserve(num_wp);
            const FieldStateTable *iframe_wp_base = &iframe_cp;
            for (uint64_t w = 0; w < num_wp; w++) {
                int64_t wd = wpb.sleb();
                int32_t wp_tmpl = prev_wp_tmpl + (int32_t)wd;
                prev_wp_tmpl = wp_tmpl;
                WPEntry we;
                we.index = (uint32_t)w;
                we.template_id = (uint32_t)wp_tmpl;
                const Template *wtmpl = by_id_.count((uint32_t)wp_tmpl)
                    ? &templates_[by_id_.at((uint32_t)wp_tmpl)] : nullptr;
                if (wtmpl) we.n_insns = (uint32_t)wtmpl->insns.size();
                decode_field_delta(wpb, (uint32_t)wp_tmpl, wtmpl,
                                   iframe_wp, iframe_wp_base,
                                   &we.dyn_params, &we.reg_snaps,
                                   &we.metaflags);
                iframe_entry.wp_entries.push_back(std::move(we));
            }
            /* Events sub-section. */
            Reader evb = body_.sub();
            uint64_t num_events = evb.uleb();
            int64_t prev_idx = -1;
            for (uint64_t k = 0; k < num_events; k++) {
                uint64_t gap = evb.uleb();
                int64_t idx = prev_idx + 1 + (int64_t)gap;
                if (idx >= (int64_t)num_wp) {
                    throw std::runtime_error("IFRAME wp event index out of range");
                }
                uint8_t evf = evb.u8();
                iframe_entry.wp_entries[idx].translation_unavailable =
                    (evf & ids.wp_event_translation_unavail) != 0;
                bool is_fault = (evf & ids.wp_event_fault) != 0;
                iframe_entry.wp_entries[idx].fault = is_fault;
                if (is_fault) {
                    iframe_entry.wp_entries[idx].fault_insn_index =
                        (uint32_t)evb.uleb();
                    iframe_entry.wp_entries[idx].has_fault_idx = true;
                }
                prev_idx = idx;
            }

            /*
             * Now validate iframe_entry against prev_entry.  Mismatch
             * implies decoder state has diverged from the writer's —
             * either a corrupt trace or an encoder/decoder bug.
             * Throws on the first divergence with a descriptive
             * message.
             */
            validate_iframe(*prev_entry, iframe_entry);
            stats_.iframe_count++;
            continue;
        }
        throw std::runtime_error("Unknown body tag");
    }

    if (footer_num_entries && *footer_num_entries != seq) {
        throw std::runtime_error("Footer entry-count mismatch");
    }
}

void BodyWalker::decode_field_delta(Reader &outer,
                                    uint32_t template_id,
                                    const Template *tmpl,
                                    FieldStateTable &state,
                                    const FieldStateTable *base_state,
                                    std::vector<DynParam>       *dyn_params,
                                    std::vector<RegSnap>        *reg_snaps,
                                    std::vector<MetaFlagsEntry> *metaflags)
{
    Reader sec = outer.sub();
    uint64_t n_records = sec.uleb();
    const ResolvedIds &ids = header_.ids;

    /* Pass 1: apply record deltas to the per-template block. */
    uint32_t pos = 0;
    /* (ipos, fid) -> EXTRA_* raw vector for this entry only. */
    std::unordered_map<uint64_t, std::vector<Wide>> extras;
    auto extra_key = [](uint32_t ipos, uint8_t fid) -> uint64_t {
        return ((uint64_t)ipos << 8) | fid;
    };

    /* Resolve the per-(state,base) blocks once for this entry; the
     * record loop below indexes into them directly instead of hash-
     * looking-up per record (the prior unordered_map<u64, Wide>
     * design was ~10% of total decoder time on full-config mcf). */
    uint32_t need_insns = tmpl ? (uint32_t)tmpl->insns.size() : 0;
    FieldStateBlock *state_blk =
        table_get_or_create_block(state, template_id,
                                   std::max<uint32_t>(need_insns, 1));
    const FieldStateBlock *base_blk =
        base_state ? table_get_block(*base_state, template_id) : nullptr;
    uint32_t state_gen = state.generation;
    uint32_t base_gen  = base_state ? base_state->generation : 0;

    for (uint64_t i = 0; i < n_records; i++) {
        pos += (uint32_t)sec.uleb();
        uint8_t fid = sec.u8();
        if (is_extra_vector_fid(ids, fid)) {
            uint64_t nv = sec.uleb();
            std::vector<Wide> v;
            v.reserve(nv);
            for (uint64_t k = 0; k < nv; k++) {
                uint64_t low = sec.uleb();
                v.push_back(Wide::from_u64(low));
            }
            extras[extra_key(pos, fid)] = std::move(v);
            continue;
        }
        std::array<uint64_t, Wide::LIMBS> wd = sec.sleb_wide();
        if (fid == ids.fid_extended) {
            (void)sec.uleb();
            continue;
        }
        uint8_t slot = slot_lut_[fid];
        Wide base;
        if (!cell_read(state_blk, state_gen, pos, slot, &base) &&
            !cell_read(base_blk, base_gen, pos, slot, &base)) {
            base = template_default(tmpl, pos, fid);
        }
        base.add_signed_mod_wide(wd, scalar_bits_);
        cell_write(state_blk, state_gen, pos, slot, base);
    }

    /* Pass 2: materialize dyn_params and reg_snaps from the per-
     * (template, ipos, fid_slot) cells we just updated.  state_blk
     * has been ensured-sized for tmpl->insns; base_blk may be smaller
     * or absent — cell_read tolerates both. */
    if (!tmpl) return;
    bool has_mem = (flags_ & ids.flag_mem_data) != 0;
    bool has_reg = (flags_ & ids.flag_reg_data) != 0;

    auto lookup_fid = [&](uint32_t ipos, uint8_t fid) -> Wide {
        Wide out;
        uint8_t slot = slot_lut_[fid];
        if (cell_read(state_blk, state_gen, ipos, slot, &out)) return out;
        if (cell_read(base_blk, base_gen, ipos, slot, &out)) return out;
        return Wide{};
    };

    for (size_t i = 0; i < tmpl->insns.size(); i++) {
        uint64_t n_loads  = lookup_fid((uint32_t)i, ids.fid_n_loads).low64();
        uint64_t n_stores = lookup_fid((uint32_t)i, ids.fid_n_stores).low64();

        if (n_loads || n_stores) {
            uint64_t fixed_loads  = std::min<uint64_t>(n_loads,  FID_SLOT_COUNT);
            uint64_t fixed_stores = std::min<uint64_t>(n_stores, FID_SLOT_COUNT);

            for (uint64_t s = 0; s < fixed_loads; s++) {
                Wide a = lookup_fid((uint32_t)i,
                                    (uint8_t)(ids.fid_load_addr_base + s));
                DynParam dp;
                dp.type = DynParam::Load;
                dp.insn_index = (uint32_t)i;
                dp.addr = a.low64();
                if (has_mem) {
                    dp.data = lookup_fid((uint32_t)i,
                                         (uint8_t)(ids.fid_load_data_base + s));
                    dp.has_data = true;
                }
                dyn_params->push_back(dp);
            }

            uint64_t extra_loads = (n_loads > FID_SLOT_COUNT) ? n_loads - FID_SLOT_COUNT : 0;
            if (extra_loads) {
                auto eit = extras.find(extra_key(i, ids.fid_extra_load_addr));
                if (eit == extras.end() || eit->second.size() != extra_loads) {
                    throw std::runtime_error("EXTRA_LOAD_ADDR count mismatch");
                }
                std::vector<Wide> *edata = nullptr;
                if (has_mem) {
                    auto dit = extras.find(extra_key(i, ids.fid_extra_load_data));
                    if (dit == extras.end() || dit->second.size() != extra_loads) {
                        throw std::runtime_error("EXTRA_LOAD_DATA count mismatch");
                    }
                    edata = &dit->second;
                }
                for (size_t j = 0; j < extra_loads; j++) {
                    DynParam dp;
                    dp.type = DynParam::Load;
                    dp.insn_index = (uint32_t)i;
                    dp.addr = eit->second[j].low64();
                    if (has_mem) {
                        dp.data = (*edata)[j];
                        dp.has_data = true;
                    }
                    dyn_params->push_back(dp);
                }
            }

            for (uint64_t s = 0; s < fixed_stores; s++) {
                Wide a = lookup_fid((uint32_t)i,
                                    (uint8_t)(ids.fid_store_addr_base + s));
                DynParam dp;
                dp.type = DynParam::Store;
                dp.insn_index = (uint32_t)i;
                dp.addr = a.low64();
                if (has_mem) {
                    dp.data = lookup_fid((uint32_t)i,
                                         (uint8_t)(ids.fid_store_data_base + s));
                    dp.has_data = true;
                }
                dyn_params->push_back(dp);
            }

            uint64_t extra_stores = (n_stores > FID_SLOT_COUNT) ? n_stores - FID_SLOT_COUNT : 0;
            if (extra_stores) {
                auto eit = extras.find(extra_key(i, ids.fid_extra_store_addr));
                if (eit == extras.end() || eit->second.size() != extra_stores) {
                    throw std::runtime_error("EXTRA_STORE_ADDR count mismatch");
                }
                std::vector<Wide> *edata = nullptr;
                if (has_mem) {
                    auto dit = extras.find(extra_key(i, ids.fid_extra_store_data));
                    if (dit == extras.end() || dit->second.size() != extra_stores) {
                        throw std::runtime_error("EXTRA_STORE_DATA count mismatch");
                    }
                    edata = &dit->second;
                }
                for (size_t j = 0; j < extra_stores; j++) {
                    DynParam dp;
                    dp.type = DynParam::Store;
                    dp.insn_index = (uint32_t)i;
                    dp.addr = eit->second[j].low64();
                    if (has_mem) {
                        dp.data = (*edata)[j];
                        dp.has_data = true;
                    }
                    dyn_params->push_back(dp);
                }
            }
        }

        if (has_reg) {
            for (size_t op_i = 0; op_i < tmpl->insns[i].dst_regs.size(); op_i++) {
                Wide v = lookup_fid((uint32_t)i,
                                    (uint8_t)(ids.fid_dst_reg_base + op_i));
                RegSnap r;
                r.insn_index = (uint32_t)i;
                r.operand_index = (uint8_t)op_i;
                r.reg_id = tmpl->insns[i].dst_regs[op_i];
                r.value = v;
                reg_snaps->push_back(r);
            }
            /* Surface FID_METAFLAGS for any insn whose template writes
             * the canonical integer-flags register.  The writer emits
             * the byte only when both regdata is enabled and the insn
             * actually writes flags. */
            if (metaflags && reg_flags_id_ >= 0) {
                const auto &dsts = tmpl->insns[i].dst_regs;
                bool writes_flags = false;
                for (uint8_t r : dsts) {
                    if ((int)r == reg_flags_id_) { writes_flags = true; break; }
                }
                if (writes_flags) {
                    Wide v = lookup_fid((uint32_t)i, ids.fid_metaflags);
                    MetaFlagsEntry mfe;
                    mfe.insn_index = (uint32_t)i;
                    mfe.byte = (uint8_t)(v.low64() & 0xFF);
                    metaflags->push_back(mfe);
                }
            }
        }
    }
}

}  /* namespace cst */
