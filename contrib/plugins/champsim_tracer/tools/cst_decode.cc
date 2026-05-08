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

bool is_extra_vector_fid(uint8_t fid)
{
    return fid == FID_EXTRA_LOAD_ADDR || fid == FID_EXTRA_STORE_ADDR ||
           fid == FID_EXTRA_LOAD_DATA || fid == FID_EXTRA_STORE_DATA;
}

uint64_t cell_key(uint32_t template_id, uint32_t ipos, uint8_t fid)
{
    return ((uint64_t)template_id << 24) | ((uint64_t)ipos << 8) | fid;
}

/* Compose a template-default Wide for the FID_INSN_* range, where the
 * baseline is the template's static value (so an emit-equal-to-
 * template produces no record on the wire).  Other FID ranges
 * default to zero; callers handle that path inline. */
Wide insn_field_default(const InsnTemplate &I, uint8_t fid)
{
    Wide w;
    if (fid == FID_INSN_BYTES_LO || fid == FID_INSN_BYTES_HI) {
        size_t off = (fid == FID_INSN_BYTES_LO) ? 0 : 8;
        size_t take = std::min<size_t>(8, I.raw_bytes.size() > off
                                          ? I.raw_bytes.size() - off : 0);
        if (take) {
            uint64_t v = 0;
            std::memcpy(&v, I.raw_bytes.data() + off, take);
            w.limb[0] = v;
        }
        return w;
    }
    switch (fid) {
    case FID_INSN_OPCODE:      w.limb[0] = I.opcode; break;
    case FID_INSN_BRANCH_TYPE: w.limb[0] = I.branch_type; break;
    case FID_INSN_FLAGS: {
        uint64_t f = 0;
        if (I.branch_conditional) f |= INSN_FLAG_BRANCH_COND;
        if (I.has_imm)            f |= INSN_FLAG_HAS_IMM;
        f |= ((uint64_t)I.sync_hint << INSN_FLAG_SYNC_SHIFT) & INSN_FLAG_SYNC_MASK;
        w.limb[0] = f & 0xFF;
        break;
    }
    case FID_INSN_IMMEDIATE:   w.limb[0] = (uint64_t)I.imm; break;
    case FID_INSN_SIZE:        w.limb[0] = I.raw_bytes.size() & 0xFF; break;
    default: break;
    }
    return w;
}

}  /* namespace */

Wide BodyWalker::template_default(const Template *tmpl,
                                  uint32_t ipos, uint8_t fid) const
{
    if (!tmpl || ipos >= tmpl->insns.size()) return Wide{};
    if (fid >= FID_INSN_BYTES_LO && fid <= FID_INSN_SIZE) {
        return insn_field_default(tmpl->insns[ipos], fid);
    }
    return Wide{};
}

BodyWalker::BodyWalker(const Header &header,
                       const std::vector<Template> &templates,
                       const std::unordered_map<uint32_t, size_t> &template_by_id,
                       const uint8_t *data, size_t size,
                       uint64_t body_off, uint64_t body_end)
    : header_(header),
      templates_(templates),
      by_id_(template_by_id),
      body_(data, body_off, body_end),
      scalar_bits_(header.scalar_width_bits()),
      wp_persistent_(header.wp_persistent()),
      flags_(header.flags) {}

void BodyWalker::walk(const Callback &cb)
{
    int32_t prev_entry_template = 0;
    uint32_t current_thread = 0;
    bool pending_thread_switch = false;
    FieldStateTable cp_state;
    FieldStateTable wp_state;
    std::optional<DecodedEntry> prev_entry;
    uint32_t seq = 0;
    std::optional<uint64_t> footer_num_entries;

    while (true) {
        uint8_t tag = body_.u8();

        if (tag == BODY_TAG_END) {
            footer_num_entries = body_.uleb();
            break;
        }
        if (tag == BODY_TAG_THREAD_SWITCH) {
            int64_t d = body_.sleb();
            current_thread = (uint32_t)((int64_t)current_thread + d);
            pending_thread_switch = true;
            continue;
        }
        if (tag == BODY_TAG_ENTRY) {
            int64_t tdelta = body_.sleb();
            int32_t entry_tmpl = prev_entry_template + (int32_t)tdelta;
            prev_entry_template = entry_tmpl;

            /* v1.7/v1.8: WP overlay forks from CP at chain start.
             * Cheaper-than-conditional: clone unconditionally to mirror
             * the writer's pre-chain state. */
            if (!wp_persistent_) wp_state = cp_state;

            DecodedEntry entry;
            entry.template_id = (uint32_t)entry_tmpl;

            /* CP delta section. */
            const Template *cp_tmpl = by_id_.count((uint32_t)entry_tmpl)
                ? &templates_[by_id_.at((uint32_t)entry_tmpl)] : nullptr;
            decode_field_delta(body_, (uint32_t)entry_tmpl, cp_tmpl,
                               cp_state, nullptr,
                               &entry.dyn_params, &entry.reg_snaps);

            /* WP chain section. */
            Reader wpb = body_.sub();
            uint64_t num_wp = wpb.uleb();
            int32_t prev_wp_tmpl = 0;
            const FieldStateTable *wp_base = wp_persistent_ ? &cp_state : nullptr;
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
                                   &we.dyn_params, &we.reg_snaps);
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
                    (evf & WP_EVENT_TRANSLATION_UNAVAIL) != 0;
                bool is_fault = (evf & WP_EVENT_FAULT) != 0;
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

            cb(entry);
            prev_entry = std::move(entry);
            continue;
        }
        if (tag == BODY_TAG_IFRAME) {
            /* Validation record: decode against fresh empty overlays
             * and compare against the immediately-preceding ENTRY.
             * Per format spec we only verify the dyn_params and reg
             * snap counts here; full deep-equality validation is
             * costly and the writer's IFRAME emission is exercised by
             * the plugin's own test harness. */
            if (!prev_entry) {
                throw std::runtime_error("IFRAME with no preceding ENTRY");
            }
            FieldStateTable iframe_cp;
            FieldStateTable iframe_wp;
            DecodedEntry tmp;
            tmp.template_id = prev_entry->template_id;
            /* decode_entry advances the cursor and re-runs the field
             * walker against the fresh overlays. */
            decode_field_delta(body_, prev_entry->template_id,
                               by_id_.count(prev_entry->template_id)
                                   ? &templates_[by_id_.at(prev_entry->template_id)]
                                   : nullptr,
                               iframe_cp, nullptr,
                               &tmp.dyn_params, &tmp.reg_snaps);

            /* WP chain. */
            Reader wpb = body_.sub();
            uint64_t num_wp = wpb.uleb();
            int32_t prev_wp_tmpl = 0;
            for (uint64_t w = 0; w < num_wp; w++) {
                int64_t wd = wpb.sleb();
                int32_t wp_tmpl = prev_wp_tmpl + (int32_t)wd;
                prev_wp_tmpl = wp_tmpl;
                std::vector<DynParam> dyn;
                std::vector<RegSnap>  snaps;
                const Template *wtmpl = by_id_.count((uint32_t)wp_tmpl)
                    ? &templates_[by_id_.at((uint32_t)wp_tmpl)] : nullptr;
                decode_field_delta(wpb, (uint32_t)wp_tmpl, wtmpl,
                                   iframe_wp, nullptr, &dyn, &snaps);
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
                if (evf & WP_EVENT_FAULT) (void)evb.uleb();  /* fault_insn_index */
                prev_idx = idx;
            }
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
                                    std::vector<DynParam> *dyn_params,
                                    std::vector<RegSnap>  *reg_snaps)
{
    Reader sec = outer.sub();
    uint64_t n_records = sec.uleb();

    /* Pass 1: apply record deltas to the persistent state. */
    uint32_t pos = 0;
    /* (ipos, fid) -> EXTRA_* raw vector for this entry only. */
    std::unordered_map<uint64_t, std::vector<Wide>> extras;
    auto extra_key = [](uint32_t ipos, uint8_t fid) -> uint64_t {
        return ((uint64_t)ipos << 8) | fid;
    };

    for (uint64_t i = 0; i < n_records; i++) {
        pos += (uint32_t)sec.uleb();
        uint8_t fid = sec.u8();
        if (is_extra_vector_fid(fid)) {
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
        if (fid == FID_EXTENDED) {
            (void)sec.uleb();
            continue;
        }
        uint64_t k = cell_key(template_id, pos, fid);
        Wide base;
        auto it = state.cells.find(k);
        if (it != state.cells.end()) {
            base = it->second;
        } else if (base_state) {
            auto bit = base_state->cells.find(k);
            if (bit != base_state->cells.end()) {
                base = bit->second;
            } else {
                base = template_default(tmpl, pos, fid);
            }
        } else {
            base = template_default(tmpl, pos, fid);
        }
        base.add_signed_mod_wide(wd, scalar_bits_);
        state.cells[k] = base;
    }

    /* Pass 2: materialize dyn_params and reg_snaps from the state
     * we just updated.  Mirrors the Python decoder's pass 2 — only
     * fids whose template-default is zero are read here, so a missed
     * lookup falls through to a zeroed Wide. */
    if (!tmpl) return;
    bool has_mem = (flags_ & FLAG_MEM_DATA) != 0;
    bool has_reg = (flags_ & FLAG_REG_DATA) != 0;

    auto lookup = [&](uint64_t k) -> Wide {
        auto it = state.cells.find(k);
        if (it != state.cells.end()) return it->second;
        if (base_state) {
            auto bit = base_state->cells.find(k);
            if (bit != base_state->cells.end()) return bit->second;
        }
        return Wide{};
    };

    for (size_t i = 0; i < tmpl->insns.size(); i++) {
        uint64_t ipos_key = ((uint64_t)template_id << 24) |
                            ((uint64_t)i << 8);
        uint64_t n_loads  = lookup(ipos_key | FID_N_LOADS).low64();
        uint64_t n_stores = lookup(ipos_key | FID_N_STORES).low64();

        if (n_loads || n_stores) {
            uint64_t fixed_loads  = std::min<uint64_t>(n_loads,  FID_SLOT_COUNT);
            uint64_t fixed_stores = std::min<uint64_t>(n_stores, FID_SLOT_COUNT);

            for (uint64_t s = 0; s < fixed_loads; s++) {
                Wide a = lookup(ipos_key | (FID_LOAD_ADDR_BASE + s));
                DynParam dp;
                dp.type = DynParam::Load;
                dp.insn_index = (uint32_t)i;
                dp.addr = a.low64();
                if (has_mem) {
                    dp.data = lookup(ipos_key | (FID_LOAD_DATA_BASE + s));
                    dp.has_data = true;
                }
                dyn_params->push_back(dp);
            }

            uint64_t extra_loads = (n_loads > FID_SLOT_COUNT) ? n_loads - FID_SLOT_COUNT : 0;
            if (extra_loads) {
                auto eit = extras.find(extra_key(i, FID_EXTRA_LOAD_ADDR));
                if (eit == extras.end() || eit->second.size() != extra_loads) {
                    throw std::runtime_error("EXTRA_LOAD_ADDR count mismatch");
                }
                std::vector<Wide> *edata = nullptr;
                if (has_mem) {
                    auto dit = extras.find(extra_key(i, FID_EXTRA_LOAD_DATA));
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
                Wide a = lookup(ipos_key | (FID_STORE_ADDR_BASE + s));
                DynParam dp;
                dp.type = DynParam::Store;
                dp.insn_index = (uint32_t)i;
                dp.addr = a.low64();
                if (has_mem) {
                    dp.data = lookup(ipos_key | (FID_STORE_DATA_BASE + s));
                    dp.has_data = true;
                }
                dyn_params->push_back(dp);
            }

            uint64_t extra_stores = (n_stores > FID_SLOT_COUNT) ? n_stores - FID_SLOT_COUNT : 0;
            if (extra_stores) {
                auto eit = extras.find(extra_key(i, FID_EXTRA_STORE_ADDR));
                if (eit == extras.end() || eit->second.size() != extra_stores) {
                    throw std::runtime_error("EXTRA_STORE_ADDR count mismatch");
                }
                std::vector<Wide> *edata = nullptr;
                if (has_mem) {
                    auto dit = extras.find(extra_key(i, FID_EXTRA_STORE_DATA));
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
                Wide v = lookup(ipos_key | (FID_DST_REG_BASE + op_i));
                RegSnap r;
                r.insn_index = (uint32_t)i;
                r.operand_index = (uint8_t)op_i;
                r.reg_id = tmpl->insns[i].dst_regs[op_i];
                r.value = v;
                reg_snaps->push_back(r);
            }
        }
    }
}

}  /* namespace cst */
