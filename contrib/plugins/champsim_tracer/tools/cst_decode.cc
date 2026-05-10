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

/*
 * fid -> dense slot index mapping for FieldStateBlock storage.
 * Mirrors the writer's field_state_slot_lut (see
 * champsim_tracer_output.cc field_state_slot_lut_build).  Built once
 * at first call.  EXTRA_* and EXTENDED return SLOT_INVALID — those
 * fids are handled out-of-band (per-entry vector records / extension
 * stream) and never sit in the persistent state.
 */
std::array<uint8_t, 256> g_slot_lut{};
bool g_slot_lut_built = false;

void slot_lut_build()
{
    g_slot_lut.fill(FIELD_STATE_SLOT_INVALID);
    g_slot_lut[FID_N_LOADS] = 0;
    for (unsigned k = 0; k < FID_SLOT_COUNT; k++) {
        g_slot_lut[FID_LOAD_ADDR_BASE  + k] = (uint8_t)(1                + k);
        g_slot_lut[FID_STORE_ADDR_BASE + k] = (uint8_t)(1 + 1*FID_SLOT_COUNT + k);
        g_slot_lut[FID_LOAD_DATA_BASE  + k] = (uint8_t)(1 + 2*FID_SLOT_COUNT + k);
        g_slot_lut[FID_STORE_DATA_BASE + k] = (uint8_t)(1 + 3*FID_SLOT_COUNT + k);
        g_slot_lut[FID_DST_REG_BASE    + k] = (uint8_t)(1 + 4*FID_SLOT_COUNT + k);
    }
    g_slot_lut[FID_N_STORES] = (uint8_t)(1 + 5*FID_SLOT_COUNT);
    for (unsigned f = FID_INSN_BYTES_LO; f <= FID_INSN_SIZE; f++) {
        g_slot_lut[f] = (uint8_t)(2 + 5*FID_SLOT_COUNT +
                                   (f - FID_INSN_BYTES_LO));
    }
    g_slot_lut_built = true;
}

uint8_t slot_index(uint8_t fid)
{
    return g_slot_lut[fid];
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

/* Deep-clone @src into @dst.  Used by the v1.7/v1.8 wp-fork behavior
 * (wp_state = cp_state at every ENTRY's chain start); v1.9+ traces
 * have wp_persistent_ true and never invoke this. */
void clone_field_state_table(FieldStateTable &dst,
                             const FieldStateTable &src)
{
    dst.generation = src.generation;
    dst.blocks.clear();
    dst.blocks.resize(src.blocks.size());
    for (size_t i = 0; i < src.blocks.size(); i++) {
        if (src.blocks[i]) {
            dst.blocks[i] = std::make_unique<FieldStateBlock>(*src.blocks[i]);
        }
    }
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

void BodyWalker::walk(const Callback &cb,
                      const RegfileCallback &rb)
{
    int32_t prev_entry_template = 0;
    uint32_t current_thread = 0;
    bool pending_thread_switch = false;
    /*
     * v1.10 (0x1A): per-thread FieldStateTables.  Earlier versions
     * shared one cp_state / wp_state across all body entries; that
     * meant deltas crossed thread boundaries and made multi-vCPU
     * traces inflated and self-inconsistent.  v1.10 emits each
     * thread's deltas against its own prior emission.  We use
     * std::vector indexed by thread_id (dense small ints handed out
     * by the writer's get_or_assign_thread_id) — direct array access
     * is fast enough that the per-body-entry lookup is invisible vs
     * the field-delta replay's own cost.  v1.7..v1.9 traces always
     * route every entry through tid 0.
     */
    std::vector<FieldStateTable> cp_states;
    std::vector<FieldStateTable> wp_states;
    bool versioned_per_thread = (header_.format_version >= 0x1A);
    auto state_at = [&](std::vector<FieldStateTable> &v,
                        uint32_t k) -> FieldStateTable & {
        if (k >= v.size()) v.resize((size_t)k + 1);
        return v[k];
    };
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
        if (tag == BODY_TAG_REGFILE) {
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
            continue;
        }
        if (tag == BODY_TAG_ENTRY) {
            int64_t tdelta = body_.sleb();
            int32_t entry_tmpl = prev_entry_template + (int32_t)tdelta;
            prev_entry_template = entry_tmpl;

            uint32_t state_key = versioned_per_thread ? current_thread : 0;
            FieldStateTable &cp_state = state_at(cp_states, state_key);
            FieldStateTable &wp_state = state_at(wp_states, state_key);

            /* v1.7/v1.8: WP overlay forks from CP at chain start.
             * v1.9+ persists wp_state across entries and doesn't clone. */
            if (!wp_persistent_) clone_field_state_table(wp_state, cp_state);

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
                               &iframe_entry.reg_snaps);

            /* WP chain.  Mirror the encoder's IFRAME emission: the
             * iframe_wp overlay falls back to iframe_cp as base
             * (writer uses st->iframe_cp_scratch for both wp_state
             * and wp_base in IFRAME mode), and on persistent-WP
             * versions the wp_base parameter is the iframe_cp
             * overlay so unset cells fall through to the same place
             * the cp section just populated. */
            Reader wpb = body_.sub();
            uint64_t num_wp = wpb.uleb();
            int32_t prev_wp_tmpl = 0;
            iframe_entry.wp_entries.reserve(num_wp);
            const FieldStateTable *iframe_wp_base =
                wp_persistent_ ? &iframe_cp : nullptr;
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
                                   &we.dyn_params, &we.reg_snaps);
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
                    (evf & WP_EVENT_TRANSLATION_UNAVAIL) != 0;
                bool is_fault = (evf & WP_EVENT_FAULT) != 0;
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

    if (!g_slot_lut_built) slot_lut_build();

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
        uint8_t slot = slot_index(fid);
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
    bool has_mem = (flags_ & FLAG_MEM_DATA) != 0;
    bool has_reg = (flags_ & FLAG_REG_DATA) != 0;

    auto lookup_fid = [&](uint32_t ipos, uint8_t fid) -> Wide {
        Wide out;
        uint8_t slot = slot_index(fid);
        if (cell_read(state_blk, state_gen, ipos, slot, &out)) return out;
        if (cell_read(base_blk, base_gen, ipos, slot, &out)) return out;
        return Wide{};
    };

    for (size_t i = 0; i < tmpl->insns.size(); i++) {
        uint64_t n_loads  = lookup_fid((uint32_t)i, FID_N_LOADS).low64();
        uint64_t n_stores = lookup_fid((uint32_t)i, FID_N_STORES).low64();

        if (n_loads || n_stores) {
            uint64_t fixed_loads  = std::min<uint64_t>(n_loads,  FID_SLOT_COUNT);
            uint64_t fixed_stores = std::min<uint64_t>(n_stores, FID_SLOT_COUNT);

            for (uint64_t s = 0; s < fixed_loads; s++) {
                Wide a = lookup_fid((uint32_t)i,
                                    (uint8_t)(FID_LOAD_ADDR_BASE + s));
                DynParam dp;
                dp.type = DynParam::Load;
                dp.insn_index = (uint32_t)i;
                dp.addr = a.low64();
                if (has_mem) {
                    dp.data = lookup_fid((uint32_t)i,
                                         (uint8_t)(FID_LOAD_DATA_BASE + s));
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
                Wide a = lookup_fid((uint32_t)i,
                                    (uint8_t)(FID_STORE_ADDR_BASE + s));
                DynParam dp;
                dp.type = DynParam::Store;
                dp.insn_index = (uint32_t)i;
                dp.addr = a.low64();
                if (has_mem) {
                    dp.data = lookup_fid((uint32_t)i,
                                         (uint8_t)(FID_STORE_DATA_BASE + s));
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
                Wide v = lookup_fid((uint32_t)i,
                                    (uint8_t)(FID_DST_REG_BASE + op_i));
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
