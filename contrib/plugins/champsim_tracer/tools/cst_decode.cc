/*
 * ChampSim Tracer offline tools — body walker / delta replay (impl).
 *
 * File layout (top -> bottom):
 *   §1  FieldStateTable storage helpers   (slot LUT, cell read/write)
 *   §2  IFRAME validation                 (DecodedEntry equality checks)
 *   §3  Template-default values           (FID_INSN_* baselines)
 *   §4  BodyWalker construction
 *   §5  BodyWalker::walk + per-tag handlers
 *           handle_thread_switch / handle_regfile / handle_entry /
 *           handle_iframe / handle_end + WP chain/events helpers
 *   §6  decode_field_delta                (pass1 deltas, pass2 materialise)
 *   §7  Instruction fan-out               (instructions_from_entry)
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

/* ====================================================================
 * §1  FieldStateTable storage helpers
 * ==================================================================== */

/* Build the fid -> dense slot index map for FieldStateBlock storage.
 * Mirrors the writer's field_state_slot_lut_build:
 *
 *   slot 0:   N_LOADS         (singleton at fid 0..3)
 *   slot 1:   N_STORES
 *   slot 2:   METAFLAGS
 *   slot (3 + 5*k + f):   family f of slot k
 *                          (LOAD_ADDR / STORE_ADDR / LOAD_DATA /
 *                           STORE_DATA / DST_REG)
 *   slot (3 + 5*N + i):   INSN_BYTES_LO + i      (N = FID_SLOT_COUNT)
 *
 * Total = 3 + 5*N + 7 = FIELD_STATE_SLOT_COUNT.  EXTENDED has no
 * persistent cell. */
void slot_lut_build(const ResolvedIds &ids,
                    std::array<uint16_t, FID_LUT_SIZE> *out)
{
    out->fill(FIELD_STATE_SLOT_INVALID);
    (*out)[ids.fid_n_loads]   = 0;
    (*out)[ids.fid_n_stores]  = 1;
    (*out)[ids.fid_metaflags] = 2;

    /* Dense slot order is a consumer-side internal mapping; the FID
     * each (family, k) pair takes on the wire comes from
     * ResolvedIds' per-slot arrays (resolved by name) and is not
     * assumed to follow any stride. */
    const std::array<uint16_t, FID_SLOT_COUNT> *const slotted_fams[] = {
        &ids.fid_load_addr,
        &ids.fid_store_addr,
        &ids.fid_load_data,
        &ids.fid_store_data,
        &ids.fid_dst_reg,
        &ids.fid_src_lane_mask,
        &ids.fid_dst_lane_mask,
        &ids.fid_load_data_lane_mask,
        &ids.fid_store_data_lane_mask,
    };
    constexpr size_t N_FAM = sizeof(slotted_fams) / sizeof(slotted_fams[0]);

    unsigned dense_idx = 3;
    for (unsigned k = 0; k < FID_SLOT_COUNT; k++) {
        for (size_t f = 0; f < N_FAM; f++) {
            uint16_t fid = (*slotted_fams[f])[k];
            if (fid != 0 && fid < FID_LUT_SIZE) {
                (*out)[fid] = (uint16_t)dense_idx;
            }
            dense_idx++;
        }
    }

    /* Cold insn-metadata singletons.  Each FID is resolved by name in
     * ResolvedIds; map each into its own dense slot. */
    const uint16_t cold_fids[] = {
        ids.fid_insn_bytes_lo, ids.fid_insn_bytes_hi,
        ids.fid_insn_opcode,   ids.fid_insn_branch_type,
        ids.fid_insn_flags,    ids.fid_insn_immediate,
        ids.fid_insn_size,
    };
    for (size_t i = 0; i < sizeof(cold_fids) / sizeof(cold_fids[0]); i++) {
        if (cold_fids[i] < FID_LUT_SIZE) {
            (*out)[cold_fids[i]] = (uint16_t)(dense_idx + i);
        }
    }
}

/* Grow @blk to hold @n_insns instructions worth of cells.  Idempotent;
 * never shrinks. */
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

/* Read cell (block, ipos, slot).  Returns whether the lookup hit a
 * real (writer-set) cell — callers fall through to base_state /
 * template_default when this returns false. */
bool cell_read(const FieldStateBlock *blk, uint32_t table_gen,
               uint32_t ipos, uint16_t slot, Wide *out)
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
                uint32_t ipos, uint16_t slot, const Wide &val)
{
    if (!blk || slot == FIELD_STATE_SLOT_INVALID) return;
    block_ensure_capacity(blk, ipos + 1);
    size_t idx = (size_t)ipos * FIELD_STATE_SLOT_COUNT + slot;
    blk->values[idx] = val;
    blk->gens[idx] = table_gen;
}

/* Look up (ipos, fid) through the {state, base} cell hierarchy.  Used
 * by pass2's per-insn materialisation — pass1 reaches cell_read
 * directly because it also needs the "was this set?" boolean. */
Wide lookup_cell(const FieldStateBlock *state_blk, uint32_t state_gen,
                 const FieldStateBlock *base_blk, uint32_t base_gen,
                 const std::array<uint16_t, FID_LUT_SIZE> &slot_lut,
                 uint32_t ipos, uint16_t fid)
{
    Wide out;
    uint16_t slot = (fid < FID_LUT_SIZE) ? slot_lut[fid]
                                         : FIELD_STATE_SLOT_INVALID;
    if (cell_read(state_blk, state_gen, ipos, slot, &out)) return out;
    if (cell_read(base_blk,  base_gen,  ipos, slot, &out)) return out;
    return Wide{};
}

/* ====================================================================
 * §2  IFRAME validation  (elementwise equality against the preceding
 *     ENTRY; throws on the first divergence with a descriptive message)
 * ==================================================================== */

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

/* Helper for validate_iframe: compare one (DynParam, RegSnap,
 * MetaFlags) triple between @prev and @iframe.  @label is a "cp" or
 * "wp[k]" prefix attached to the failure message. */
void compare_observation_triple(const std::string &label,
    const std::vector<DynParam> &prev_dyn,
    const std::vector<DynParam> &iframe_dyn,
    const std::vector<RegSnap> &prev_snap,
    const std::vector<RegSnap> &iframe_snap,
    const std::vector<MetaFlagsEntry> &prev_mf,
    const std::vector<MetaFlagsEntry> &iframe_mf,
    uint32_t seq_num)
{
    auto fail = [&](const std::string &msg) {
        throw std::runtime_error("IFRAME validation: " + label + " " + msg +
                                 " (seq=" + std::to_string(seq_num) + ")");
    };
    if (prev_dyn.size() != iframe_dyn.size()) {
        fail("dyn_params count mismatch: ENTRY=" +
             std::to_string(prev_dyn.size()) +
             " IFRAME=" + std::to_string(iframe_dyn.size()));
    }
    if (size_t d = first_dyn_param_diff(prev_dyn, iframe_dyn)) {
        fail("dyn_params[" + std::to_string(d - 1) + "] mismatch");
    }
    if (prev_snap.size() != iframe_snap.size()) {
        fail("reg_snaps count mismatch: ENTRY=" +
             std::to_string(prev_snap.size()) +
             " IFRAME=" + std::to_string(iframe_snap.size()));
    }
    if (size_t d = first_reg_snap_diff(prev_snap, iframe_snap)) {
        fail("reg_snaps[" + std::to_string(d - 1) + "] mismatch");
    }
    if (prev_mf.size() != iframe_mf.size()) {
        fail("metaflags count mismatch: ENTRY=" +
             std::to_string(prev_mf.size()) +
             " IFRAME=" + std::to_string(iframe_mf.size()));
    }
    if (size_t d = first_metaflags_diff(prev_mf, iframe_mf)) {
        fail("metaflags[" + std::to_string(d - 1) + "] mismatch");
    }
}

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

    compare_observation_triple("cp",
        prev.dyn_params, iframe.dyn_params,
        prev.reg_snaps,  iframe.reg_snaps,
        prev.metaflags,  iframe.metaflags,
        prev.seq_num);

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
        compare_observation_triple(ws,
            pe.dyn_params, ie.dyn_params,
            pe.reg_snaps,  ie.reg_snaps,
            pe.metaflags,  ie.metaflags,
            prev.seq_num);
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

/* ====================================================================
 * §3  Template-default field values
 * ==================================================================== */

/* Compose a template-default Wide for the FID_INSN_* range, where the
 * baseline is the template's static value (so an emit-equal-to-
 * template produces no record on the wire).  Other FID ranges default
 * to zero — those are handled by the caller's Wide{} fallback. */
Wide insn_field_default(const InsnTemplate &I, uint8_t fid,
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
        if (I.is_atomic)          f |= ids.insn_flag_atomic;
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

/* ====================================================================
 * §4  BodyWalker construction
 * ==================================================================== */

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

/* ====================================================================
 * §5  walk() + per-tag handlers
 *
 * walk() is a small dispatch loop: read the leading tag byte and
 * dispatch to handle_thread_switch / handle_regfile / handle_entry /
 * handle_iframe / handle_end based on the trace's body_tag encoding
 * map.  Each handler consumes that tag's payload from body_, updates
 * stats_, and (for ENTRY / REGFILE) invokes the consumer callback.
 * ==================================================================== */

/* Transient state carried across one walk() invocation.  Lives on the
 * stack inside walk(); each handler takes it by reference. */
struct BodyWalker::WalkState {
    int32_t  prev_entry_template   = 0;
    uint32_t current_thread        = 0;
    bool     pending_thread_switch = false;

    /* Per-thread FieldStateTables, indexed by thread_id.  The writer
     * hands out dense small ints via get_or_assign_thread_id, so the
     * vectors stay short. */
    std::vector<FieldStateTable> cp_states;
    std::vector<FieldStateTable> wp_states;

    /* Last observed ENTRY, retained for the next IFRAME's validation. */
    std::optional<DecodedEntry> prev_entry;

    /* 1-based sequence number assigned to each ENTRY for the
     * DecodedEntry::seq_num field. */
    uint32_t seq = 0;

    FieldStateTable &state_at(std::vector<FieldStateTable> &v, uint32_t k) {
        if (k >= v.size()) v.resize((size_t)k + 1);
        return v[k];
    }
};

void BodyWalker::handle_thread_switch(WalkState &ws)
{
    int64_t d = body_.sleb();
    ws.current_thread = (uint32_t)((int64_t)ws.current_thread + d);
    ws.pending_thread_switch = true;
    stats_.thread_switch_count++;
}

void BodyWalker::handle_regfile(const RegfileCallback &rb)
{
    DecodedRegfile rec;
    rec.thread_id = (uint32_t)body_.uleb();
    uint64_t n_present = body_.uleb();
    rec.regs.reserve(n_present);
    for (uint64_t i = 0; i < n_present; i++) {
        RegfileSlot s;
        s.gen_id = body_.u8();
        uint8_t width = body_.u8();
        s.bytes.resize(width);
        if (width) body_.raw(s.bytes.data(), width);
        rec.regs.push_back(std::move(s));
    }
    if (rb) rb(rec);
    stats_.regfile_count++;
}

std::vector<WPEntry> BodyWalker::decode_wp_chain(
    Reader &wpb, FieldStateTable &state,
    const FieldStateTable *base_state)
{
    std::vector<WPEntry> out;
    uint64_t num_wp = wpb.uleb();
    out.reserve(num_wp);
    int32_t prev_wp_tmpl = 0;
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
                           state, base_state,
                           &we.dyn_params, &we.reg_snaps, &we.metaflags,
                           &we.lane_masks);
        out.push_back(std::move(we));
    }
    return out;
}

void BodyWalker::decode_wp_events(Reader &evb,
                                  std::vector<WPEntry> *wp_entries)
{
    const ResolvedIds &ids = header_.ids;
    uint64_t num_events = evb.uleb();
    int64_t prev_idx = -1;
    for (uint64_t k = 0; k < num_events; k++) {
        uint64_t gap = evb.uleb();
        int64_t idx = prev_idx + 1 + (int64_t)gap;
        if (idx < 0 || (size_t)idx >= wp_entries->size()) {
            throw std::runtime_error("wp event index out of range");
        }
        uint8_t evf = evb.u8();
        WPEntry &we = (*wp_entries)[idx];
        we.translation_unavailable = (evf & ids.wp_event_translation_unavail) != 0;
        bool is_fault = (evf & ids.wp_event_fault) != 0;
        we.fault = is_fault;
        if (is_fault) {
            we.fault_insn_index = (uint32_t)evb.uleb();
            we.has_fault_idx = true;
        }
        prev_idx = idx;
    }
}

/* Tally each (template, insn) is_atomic into stats_.  Counts every
 * (entry × insn) once, so a hot block contributes its atomic-bit
 * vector multiple times — matches the "how many insn observations
 * were atomic" intent rather than the dedupe count. */
namespace {
void tally_atomic_count(const Template *tmpl, uint64_t &out)
{
    if (!tmpl) return;
    for (const auto &I : tmpl->insns) {
        if (I.is_atomic) out++;
    }
}
}  /* namespace */

void BodyWalker::handle_entry(WalkState &ws, const Callback &cb)
{
    int64_t tdelta = body_.sleb();
    int32_t entry_tmpl = ws.prev_entry_template + (int32_t)tdelta;
    ws.prev_entry_template = entry_tmpl;

    FieldStateTable &cp_state = ws.state_at(ws.cp_states, ws.current_thread);
    FieldStateTable &wp_state = ws.state_at(ws.wp_states, ws.current_thread);

    DecodedEntry entry;
    entry.template_id = (uint32_t)entry_tmpl;

    /* CP delta section. */
    const Template *cp_tmpl = by_id_.count((uint32_t)entry_tmpl)
        ? &templates_[by_id_.at((uint32_t)entry_tmpl)] : nullptr;
    decode_field_delta(body_, (uint32_t)entry_tmpl, cp_tmpl,
                       cp_state, nullptr,
                       &entry.dyn_params, &entry.reg_snaps, &entry.metaflags,
                       &entry.lane_masks);

    /* WP chain + events.  Both live in their own length-prefixed
     * sub-sections of body_. */
    Reader wpb = body_.sub();
    entry.wp_entries = decode_wp_chain(wpb, wp_state, &cp_state);
    Reader evb = body_.sub();
    decode_wp_events(evb, &entry.wp_entries);

    entry.thread_id       = ws.current_thread;
    entry.thread_switched = ws.pending_thread_switch;
    entry.seq_num         = ++ws.seq;
    ws.pending_thread_switch = false;

    /* stats_ aggregation. */
    stats_.cp_entries++;
    stats_.wp_entries += entry.wp_entries.size();
    for (const auto &we : entry.wp_entries) {
        if (we.fault) stats_.fault_count++;
        if (we.translation_unavailable) stats_.translation_unavail_count++;
    }
    if (auto it = by_id_.find(entry.template_id); it != by_id_.end()) {
        tally_atomic_count(&templates_[it->second], stats_.atomic_count);
    }
    for (const auto &we : entry.wp_entries) {
        auto wit = by_id_.find(we.template_id);
        if (wit != by_id_.end()) {
            tally_atomic_count(&templates_[wit->second],
                               stats_.atomic_count);
        }
    }

    cb(entry);
    ws.prev_entry = std::move(entry);
}

void BodyWalker::handle_iframe(WalkState &ws)
{
    /* Validation record: decode the IFRAME against fresh empty
     * overlays (so every value is delta-from-template-default =
     * absolute) and assert it matches the immediately-preceding
     * ENTRY's dyn_params, reg_snaps, WP chain, and WP events.  If
     * the decoder's delta-replay disagrees, throw — the trace is
     * corrupt or the encoder/decoder are out of sync. */
    if (!ws.prev_entry) {
        throw std::runtime_error("IFRAME with no preceding ENTRY");
    }
    FieldStateTable iframe_cp;
    FieldStateTable iframe_wp;

    DecodedEntry iframe_entry;
    iframe_entry.template_id = ws.prev_entry->template_id;

    const Template *prev_tmpl =
        by_id_.count(ws.prev_entry->template_id)
            ? &templates_[by_id_.at(ws.prev_entry->template_id)]
            : nullptr;
    decode_field_delta(body_, ws.prev_entry->template_id, prev_tmpl,
                       iframe_cp, nullptr,
                       &iframe_entry.dyn_params,
                       &iframe_entry.reg_snaps,
                       &iframe_entry.metaflags,
                       &iframe_entry.lane_masks);

    /* WP chain + events.  Mirror the writer's IFRAME emission: the
     * iframe_wp overlay falls back to iframe_cp as base, matching
     * st->iframe_cp_scratch shared between wp_state and wp_base. */
    Reader wpb = body_.sub();
    iframe_entry.wp_entries = decode_wp_chain(wpb, iframe_wp, &iframe_cp);
    Reader evb = body_.sub();
    decode_wp_events(evb, &iframe_entry.wp_entries);

    validate_iframe(*ws.prev_entry, iframe_entry);
    stats_.iframe_count++;
}

uint64_t BodyWalker::handle_end()
{
    return body_.uleb();
}

void BodyWalker::walk(const Callback &cb, const RegfileCallback &rb)
{
    WalkState ws;
    std::optional<uint64_t> footer_num_entries;
    const ResolvedIds &ids = header_.ids;

    for (;;) {
        uint8_t tag = body_.u8();

        if (tag == ids.body_tag_end) {
            footer_num_entries = handle_end();
            break;
        }
        if (tag == ids.body_tag_thread_switch) {
            handle_thread_switch(ws);
            continue;
        }
        if (tag == ids.body_tag_regfile) {
            handle_regfile(rb);
            continue;
        }
        if (tag == ids.body_tag_entry) {
            handle_entry(ws, cb);
            if (max_entries_ && stats_.cp_entries >= max_entries_) {
                /* Early stop.  Caller skips trailing-magic check; the
                 * underlying decompressor subprocess (if any) is torn
                 * down when the Reader's Source is destroyed. */
                return;
            }
            continue;
        }
        if (tag == ids.body_tag_iframe) {
            handle_iframe(ws);
            continue;
        }
        throw std::runtime_error("Unknown body tag");
    }

    if (footer_num_entries && *footer_num_entries != ws.seq) {
        throw std::runtime_error("Footer entry-count mismatch");
    }
}

/* ====================================================================
 * §6  decode_field_delta — pass1 apply + pass2 materialise
 *
 * Pass 1: walk the wire records, apply each delta to the matching
 *         (state_blk, ipos, slot) cell.  Records on EXTRA_* fids
 *         carry per-entry variable-length vectors (memops overflow
 *         past the 16 slotted families) — those are collected into
 *         the @extras map indexed by (ipos, fid).
 *
 * Pass 2: walk every insn in @tmpl, reading the per-(template, ipos,
 *         fid) cells back out and materialising DynParam / RegSnap /
 *         MetaFlagsEntry rows into the entry's output vectors.
 * ==================================================================== */

namespace {

/* Pass-1 record loop.  Reads @n_records records from @sec, applying
 * each non-EXTENDED delta to the (state_blk, ipos, slot) cell.
 * Format version 0x1D: fid is ULEB128 (previously u8); the
 * EXTRA_LOAD/EXTRA_STORE raw-vector overflow path is retired. */
void apply_record_deltas(BodyWalker &walker, Reader &sec, uint64_t n_records,
                         uint32_t template_id, const Template *tmpl,
                         const ResolvedIds &ids,
                         const std::array<uint16_t, FID_LUT_SIZE> &slot_lut,
                         FieldStateBlock *state_blk, uint32_t state_gen,
                         const FieldStateBlock *base_blk, uint32_t base_gen,
                         int scalar_bits,
                         Wide (BodyWalker::*tmpl_default)(const Template*, uint32_t, uint8_t) const)
{
    (void)template_id;
    uint32_t pos = 0;
    for (uint64_t i = 0; i < n_records; i++) {
        pos += (uint32_t)sec.uleb();
        uint16_t fid = (uint16_t)sec.uleb();

        std::array<uint64_t, Wide::LIMBS> wd = sec.sleb_wide();
        if (fid == ids.fid_extended) {
            (void)sec.uleb();
            continue;
        }
        uint16_t slot = (fid < FID_LUT_SIZE) ? slot_lut[fid]
                                             : FIELD_STATE_SLOT_INVALID;
        Wide base;
        if (!cell_read(state_blk, state_gen, pos, slot, &base) &&
            !cell_read(base_blk,  base_gen,  pos, slot, &base)) {
            base = (walker.*tmpl_default)(tmpl, pos, (uint8_t)fid);
        }
        base.add_signed_mod_wide(wd, scalar_bits);
        cell_write(state_blk, state_gen, pos, slot, base);
    }
}

/* Materialise the slotted loads or stores for one insn into @out.
 * @type picks Load vs Store; @addr_fids / @data_fids are the
 * per-slot FID arrays for this family, name-resolved out of the
 * encoding map (no stride assumption — the writer chooses the
 * slot-to-FID mapping freely). */
void materialise_slotted_memops(uint32_t insn_idx, uint64_t n_fixed,
                                DynParam::Type type,
                                const std::array<uint16_t, FID_SLOT_COUNT> &addr_fids,
                                const std::array<uint16_t, FID_SLOT_COUNT> &data_fids,
                                bool has_mem,
                                const FieldStateBlock *state_blk,
                                uint32_t state_gen,
                                const FieldStateBlock *base_blk,
                                uint32_t base_gen,
                                const std::array<uint16_t, FID_LUT_SIZE> &slot_lut,
                                std::vector<DynParam> *out)
{
    /* Clamp at FID_SLOT_COUNT.  Writers compliant with the 0x1D
     * format reject overflow at emit time and log to
     * unknown_warnings.log; a defensive clamp here protects against
     * a malformed trace whose N_LOADS / N_STORES exceed the cap. */
    if (n_fixed > FID_SLOT_COUNT) n_fixed = FID_SLOT_COUNT;
    for (uint64_t s = 0; s < n_fixed; s++) {
        uint16_t addr_fid = addr_fids[s];
        uint16_t data_fid = data_fids[s];
        Wide a = lookup_cell(state_blk, state_gen, base_blk, base_gen,
                             slot_lut, insn_idx, addr_fid);
        DynParam dp;
        dp.type = type;
        dp.insn_index = insn_idx;
        dp.addr = a.low64();
        if (has_mem) {
            dp.data = lookup_cell(state_blk, state_gen, base_blk, base_gen,
                                  slot_lut, insn_idx, data_fid);
            dp.has_data = true;
        }
        out->push_back(dp);
    }
}

/* Materialise dst-register snapshots + the optional FID_METAFLAGS
 * side-channel for one insn. */
void materialise_reg_snaps_and_metaflags(uint32_t insn_idx,
                                         const InsnTemplate &it,
                                         const ResolvedIds &ids,
                                         int reg_flags_id,
                                         const FieldStateBlock *state_blk,
                                         uint32_t state_gen,
                                         const FieldStateBlock *base_blk,
                                         uint32_t base_gen,
                                         const std::array<uint16_t, FID_LUT_SIZE> &slot_lut,
                                         std::vector<RegSnap> *snaps_out,
                                         std::vector<MetaFlagsEntry> *mflags_out)
{
    for (size_t op_i = 0; op_i < it.dst_regs.size(); op_i++) {
        if (op_i >= FID_SLOT_COUNT) break;
        uint16_t fid = ids.fid_dst_reg[op_i];
        Wide v = lookup_cell(state_blk, state_gen, base_blk, base_gen,
                             slot_lut, insn_idx, fid);
        RegSnap r;
        r.insn_index = insn_idx;
        r.operand_index = (uint8_t)op_i;
        r.reg_id = it.dst_regs[op_i];
        r.value = v;
        snaps_out->push_back(r);
    }
    /* FID_METAFLAGS only fires when (a) the trace names a flags reg
     * and (b) this insn's template writes that reg.  Avoids surfacing
     * empty bytes on ISAs without integer flags. */
    if (!mflags_out || reg_flags_id < 0) return;
    bool writes_flags = false;
    for (uint8_t r : it.dst_regs) {
        if ((int)r == reg_flags_id) { writes_flags = true; break; }
    }
    if (!writes_flags) return;
    Wide v = lookup_cell(state_blk, state_gen, base_blk, base_gen,
                         slot_lut, insn_idx, ids.fid_metaflags);
    MetaFlagsEntry mfe;
    mfe.insn_index = insn_idx;
    mfe.byte = (uint8_t)(v.low64() & 0xFF);
    mflags_out->push_back(mfe);
}

}  /* namespace */

void BodyWalker::decode_field_delta(Reader &outer,
                                    uint32_t template_id,
                                    const Template *tmpl,
                                    FieldStateTable &state,
                                    const FieldStateTable *base_state,
                                    std::vector<DynParam>       *dyn_params,
                                    std::vector<RegSnap>        *reg_snaps,
                                    std::vector<MetaFlagsEntry> *metaflags,
                                    std::vector<LaneMaskEntry>  *lane_masks)
{
    Reader sec = outer.sub();
    uint64_t n_records = sec.uleb();
    const ResolvedIds &ids = header_.ids;

    /* Resolve the per-(state,base) blocks once for this entry.  The
     * record loop indexes into them directly instead of hash-looking
     * up per record. */
    uint32_t need_insns = tmpl ? (uint32_t)tmpl->insns.size() : 0;
    FieldStateBlock *state_blk =
        table_get_or_create_block(state, template_id,
                                  std::max<uint32_t>(need_insns, 1));
    const FieldStateBlock *base_blk =
        base_state ? table_get_block(*base_state, template_id) : nullptr;
    uint32_t state_gen = state.generation;
    uint32_t base_gen  = base_state ? base_state->generation : 0;

    /* Pass 1: apply record deltas.  Format version 0x1D — no
     * EXTRA_* overflow vectors; all memops address through slotted
     * fids directly. */
    apply_record_deltas(*this, sec, n_records,
                        template_id, tmpl, ids, slot_lut_,
                        state_blk, state_gen, base_blk, base_gen,
                        scalar_bits_,
                        &BodyWalker::template_default);

    /* Pass 2: materialise per-insn outputs.  Skipped entirely when
     * we don't have a template (decoder doesn't know the insn count). */
    if (!tmpl) return;
    const bool has_mem = (flags_ & ids.flag_mem_data) != 0;
    const bool has_reg = (flags_ & ids.flag_reg_data) != 0;

    for (size_t i = 0; i < tmpl->insns.size(); i++) {
        uint32_t idx = (uint32_t)i;
        uint64_t n_loads = lookup_cell(state_blk, state_gen,
                                        base_blk,  base_gen,
                                        slot_lut_, idx,
                                        ids.fid_n_loads).low64();
        uint64_t n_stores = lookup_cell(state_blk, state_gen,
                                        base_blk,  base_gen,
                                        slot_lut_, idx,
                                        ids.fid_n_stores).low64();

        if (n_loads || n_stores) {
            materialise_slotted_memops(idx, n_loads, DynParam::Load,
                                       ids.fid_load_addr,
                                       ids.fid_load_data,
                                       has_mem,
                                       state_blk, state_gen,
                                       base_blk,  base_gen,
                                       slot_lut_, dyn_params);
            materialise_slotted_memops(idx, n_stores, DynParam::Store,
                                       ids.fid_store_addr,
                                       ids.fid_store_data,
                                       has_mem,
                                       state_blk, state_gen,
                                       base_blk,  base_gen,
                                       slot_lut_, dyn_params);
        }

        if (has_reg) {
            materialise_reg_snaps_and_metaflags(idx, tmpl->insns[i],
                                                ids, reg_flags_id_,
                                                state_blk, state_gen,
                                                base_blk,  base_gen,
                                                slot_lut_,
                                                reg_snaps, metaflags);
        }
        /* Lane masks: per-family per-slot dynamic FIDs.  Each non-zero
         * cell becomes one LaneMaskEntry; zero-valued cells are skipped
         * so scalar (lane_mask_kind=NONE) instances stay empty. */
        if (lane_masks) {
            const InsnTemplate &it = tmpl->insns[i];
            auto emit_fam = [&](LaneMaskEntry::Family fam,
                                const std::array<uint16_t, FID_SLOT_COUNT> &fids,
                                uint8_t n_slots) {
                if (n_slots > FID_SLOT_COUNT) n_slots = FID_SLOT_COUNT;
                for (uint8_t s = 0; s < n_slots; s++) {
                    uint16_t fid = fids[s];
                    if (fid == 0) continue;
                    Wide v = lookup_cell(state_blk, state_gen,
                                         base_blk,  base_gen,
                                         slot_lut_, idx, fid);
                    uint64_t mask = v.low64();
                    if (!mask) continue;
                    LaneMaskEntry e;
                    e.insn_index = idx;
                    e.family     = fam;
                    e.slot_index = s;
                    e.mask       = mask;
                    lane_masks->push_back(e);
                }
            };
            emit_fam(LaneMaskEntry::Src,       ids.fid_src_lane_mask,
                     (uint8_t)it.src_regs.size());
            emit_fam(LaneMaskEntry::Dst,       ids.fid_dst_lane_mask,
                     (uint8_t)it.dst_regs.size());
            emit_fam(LaneMaskEntry::LoadData,  ids.fid_load_data_lane_mask,
                     (uint8_t)std::min<uint32_t>(it.max_dep_loads,
                                                 (uint32_t)n_loads));
            emit_fam(LaneMaskEntry::StoreData, ids.fid_store_data_lane_mask,
                     (uint8_t)std::min<uint32_t>(it.max_dep_stores,
                                                 (uint32_t)n_stores));
        }
    }
}

/* ====================================================================
 * §7  Instruction fan-out  (instructions_from_entry)
 *
 * Converts the entry-shaped output of walk() into a flat sequence of
 * per-architectural-instance Instruction containers — the natural
 * consumption shape for renderers / simulators.
 * ==================================================================== */

namespace {

/* Resolve a direct-branch target into the templates vector by
 * matching the branch's static target PC against template start_pc.
 * Returns nullptr for indirect / return / REP branches and for
 * direct branches whose target is outside the trace window.
 *
 * Matches on the trace's own branch_type encoding-map names rather
 * than compile-time enum values; the tools are intentionally
 * decoupled from the plugin's generic_ids enum so a future tracer
 * that re-numbers BRANCH_* stays decodable. */
const Template *resolve_branch_target(
    const Header &h, const InsnTemplate &I,
    const std::vector<Template> &templates)
{
    if (!I.has_imm) return nullptr;
    auto it = h.maps.branch_type.find(I.branch_type);
    if (it == h.maps.branch_type.end()) return nullptr;
    const std::string &name = it->second;
    if (name != "BRANCH_DIRECT_JUMP" && name != "BRANCH_COND_DIRECT") {
        return nullptr;
    }
    uint64_t target_pc = (uint64_t)I.imm;
    /* Linear scan; for typical traces with <10k templates this is
     * already cache-resident in the renderer hot path. */
    for (const Template &t : templates) {
        if (t.start_pc == target_pc) return &t;
    }
    return nullptr;
}

/* Resize @v to cover slot_index and write @mask there. */
void place_lane_mask(std::vector<uint64_t> &v,
                     uint8_t slot_index, uint64_t mask)
{
    if (v.size() <= slot_index) v.resize((size_t)slot_index + 1, 0);
    v[slot_index] = mask;
}

/* Pull every dyn_param / reg_snap / metaflags / lane_mask entry whose
 * insn_index matches @idx into @out's per-instance vectors.  Existing
 * vectors are in template-walk order, so relative ordering is
 * preserved.  Lane masks fan out into the four per-slot vectors keyed
 * by family + slot index. */
void filter_per_insn(Instruction &out, uint32_t idx,
                     const std::vector<DynParam> &dyns,
                     const std::vector<RegSnap> &snaps,
                     const std::vector<MetaFlagsEntry> &metaflags,
                     const std::vector<LaneMaskEntry> &lane_masks)
{
    for (const DynParam &dp : dyns) {
        if (dp.insn_index == idx) out.dyn_params.push_back(dp);
    }
    for (const RegSnap &rs : snaps) {
        if (rs.insn_index == idx) out.reg_snaps.push_back(rs);
    }
    for (const MetaFlagsEntry &mf : metaflags) {
        if (mf.insn_index == idx) out.metaflags.push_back(mf);
    }
    for (const LaneMaskEntry &lm : lane_masks) {
        if (lm.insn_index != idx) continue;
        switch (lm.family) {
        case LaneMaskEntry::Src:
            place_lane_mask(out.src_lane_mask,        lm.slot_index, lm.mask);
            break;
        case LaneMaskEntry::Dst:
            place_lane_mask(out.dst_lane_mask,        lm.slot_index, lm.mask);
            break;
        case LaneMaskEntry::LoadData:
            place_lane_mask(out.load_data_lane_mask,  lm.slot_index, lm.mask);
            break;
        case LaneMaskEntry::StoreData:
            place_lane_mask(out.store_data_lane_mask, lm.slot_index, lm.mask);
            break;
        }
    }
}

/* Build an Instruction for a single template insn position.  Used by
 * both the CP and WP fan-out paths.  Callers fill wp-specific fields
 * afterwards if applicable. */
Instruction build_one(const Template &tmpl, uint32_t insn_idx,
                      const DecodedEntry &entry,
                      const Header &h,
                      const std::vector<Template> &templates,
                      const std::vector<DynParam> &dyns,
                      const std::vector<RegSnap> &snaps,
                      const std::vector<MetaFlagsEntry> &metaflags,
                      const std::vector<LaneMaskEntry> &lane_masks)
{
    Instruction insn;
    const InsnTemplate &I = tmpl.insns[insn_idx];
    insn.pc                 = I.pc;
    insn.opcode             = I.opcode;
    insn.branch_type        = I.branch_type;
    insn.branch_conditional = I.branch_conditional;
    insn.has_immediate      = I.has_imm;
    insn.immediate          = I.imm;
    insn.is_atomic          = I.is_atomic;
    insn.src_regs            = I.src_regs;
    insn.dst_regs            = I.dst_regs;
    insn.raw_bytes           = I.raw_bytes;
    insn.max_dep_loads       = I.max_dep_loads;
    insn.max_dep_stores      = I.max_dep_stores;
    insn.has_reg_deps        = I.has_reg_deps;
    insn.has_addr_deps       = I.has_addr_deps;
    insn.dst_dep_mask        = I.dst_dep_mask;
    insn.store_data_dep_mask = I.store_data_dep_mask;
    insn.load_addr_dep_mask  = I.load_addr_dep_mask;
    insn.store_addr_dep_mask = I.store_addr_dep_mask;
    insn.lane_parallel       = I.lane_parallel;
    insn.bb_template_id     = tmpl.template_id;
    insn.insn_index_in_bb   = insn_idx;
    insn.seq_num            = entry.seq_num;
    insn.thread_id          = entry.thread_id;
    insn.thread_switched    = entry.thread_switched;
    insn.bb_template        = &tmpl;
    insn.branch_target_template = resolve_branch_target(h, I, templates);
    filter_per_insn(insn, insn_idx, dyns, snaps, metaflags, lane_masks);
    return insn;
}

}  /* namespace */

std::vector<Instruction> instructions_from_entry(
    const DecodedEntry &entry,
    const Header &h,
    const std::vector<Template> &templates,
    const std::unordered_map<uint32_t, size_t> &template_by_id)
{
    std::vector<Instruction> out;
    auto cp_it = template_by_id.find(entry.template_id);
    if (cp_it == template_by_id.end()) return out;
    const Template &cp_tmpl = templates[cp_it->second];
    out.reserve(cp_tmpl.insns.size() +
                entry.wp_entries.size() * 4);  /* rough; growth fine */

    /* CP insns first, in template order. */
    for (size_t i = 0; i < cp_tmpl.insns.size(); i++) {
        out.push_back(build_one(cp_tmpl, (uint32_t)i, entry, h, templates,
                                entry.dyn_params, entry.reg_snaps,
                                entry.metaflags, entry.lane_masks));
    }

    /* WP chain: every WP entry's insns in chain order.  A WP entry
     * may execute only a prefix of its template (wp.n_insns) before
     * being cut off by a fault or translation gap — honour the wire
     * value rather than the template's full insn count. */
    for (const WPEntry &wp : entry.wp_entries) {
        auto wp_it = template_by_id.find(wp.template_id);
        if (wp_it == template_by_id.end()) continue;
        const Template &wp_tmpl = templates[wp_it->second];
        uint32_t wp_n = wp.n_insns < wp_tmpl.insns.size()
                            ? wp.n_insns
                            : (uint32_t)wp_tmpl.insns.size();
        for (uint32_t i = 0; i < wp_n; i++) {
            Instruction insn = build_one(wp_tmpl, i, entry, h, templates,
                                         wp.dyn_params, wp.reg_snaps,
                                         wp.metaflags, wp.lane_masks);
            insn.is_wp                  = true;
            insn.wp_index               = (uint16_t)wp.index;
            insn.wp_fault               = wp.fault;
            insn.wp_translation_unavail = wp.translation_unavailable;
            insn.wp_has_fault_idx       = wp.has_fault_idx;
            insn.wp_fault_insn_index    = wp.fault_insn_index;
            out.push_back(std::move(insn));
        }
    }
    return out;
}

}  /* namespace cst */
