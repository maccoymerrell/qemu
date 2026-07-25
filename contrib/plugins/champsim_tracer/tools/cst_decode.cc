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

/* Build the fid -> dense slot index map for FieldStateBlock storage,
 * mirroring the writer's field_state_slot_lut_build (slots 0..2 =
 * N_LOADS/N_STORES/METAFLAGS, then slotted families, then cold
 * insn-metadata singletons; EXTENDED has no persistent cell). */
void slot_lut_build(const ResolvedIds &ids,
                    std::array<uint16_t, FID_LUT_SIZE> *out)
{
    out->fill(FIELD_STATE_SLOT_INVALID);
    /* Singletons may be absent (sentinel) on a trace that doesn't use
     * them — guard so an out-of-range fid never indexes the LUT. */
    if (ids.fid_n_loads   < FID_LUT_SIZE) (*out)[ids.fid_n_loads]   = 0;
    if (ids.fid_n_stores  < FID_LUT_SIZE) (*out)[ids.fid_n_stores]  = 1;
    if (ids.fid_metaflags < FID_LUT_SIZE) (*out)[ids.fid_metaflags] = 2;

    /* Dense slot order is a consumer-side internal mapping; the FID
     * each (family, k) pair takes on the wire comes from
     * ResolvedIds' per-slot arrays (resolved by name) and is not
     * assumed to follow any stride. */
    const FidSlotArray *const slotted_fams[] = {
        &ids.fid_load_addr,
        &ids.fid_store_addr,
        &ids.fid_load_data,
        &ids.fid_store_data,
        &ids.fid_dst_reg,
        &ids.fid_load_size,
        &ids.fid_store_size,
        &ids.fid_dst_reg_width,
        &ids.fid_src_lane_mask,
        &ids.fid_dst_lane_mask,
        &ids.fid_load_data_lane_mask,
        &ids.fid_store_data_lane_mask,
        &ids.fid_load_ppage,
        &ids.fid_store_ppage,
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

    /* Cold insn-metadata singletons + the 2 branch-outcome singletons.
     * Each FID is resolved by name in ResolvedIds; map each into its own
     * dense slot after the slotted region (fs_phys_offset lands them at
     * fixed cells 3..11).  The branch pair (fixed cells 10..11) is a purely
     * internal storage choice; it is simply never written on a trace that
     * predates the feature (fid_branch_* == 0), so older traces decode
     * unchanged. */
    const uint16_t cold_fids[] = {
        ids.fid_insn_bytes_lo, ids.fid_insn_bytes_hi,
        ids.fid_insn_opcode,   ids.fid_insn_branch_type,
        ids.fid_insn_flags,    ids.fid_insn_immediate,
        ids.fid_insn_size,
        ids.fid_branch_taken,  ids.fid_branch_target,
    };
    for (size_t i = 0; i < sizeof(cold_fids) / sizeof(cold_fids[0]); i++) {
        if (cold_fids[i] < FID_LUT_SIZE) {
            (*out)[cold_fids[i]] = (uint16_t)(dense_idx + i);
        }
    }
}

/*
 * Physical block layout (mirrors the writer's lazy max_slots design;
 * see the FieldStateBlock comment in cst_decode.h).  Logical slot
 * indices from slot_lut_build decompose as:
 *   [0, 3)                       hot singletons  -> fixed offset 0..2
 *   [3, 3 + FID_SLOT_COUNT*12)   slot-major slotted: k=(L-3)/12,
 *                                f=(L-3)%12 -> family-major physical
 *                                cell FS_FIXED_CELLS + f*max_slots + k
 *   [.., +9)                     cold metadata (7) + branch pair (2)
 *                                -> fixed offsets 3..11
 */
/* Slotted families tracked in the decoder's family-major block: the 8 wire
 * slotted families + 4 lane-mask families + 2 physical-page families.  Must
 * equal the slotted_fams[] array length in slot_lut_build (a purely
 * internal storage layout; the ppage families are simply never written on a
 * non-physaddr trace, so decode of older traces is unaffected). */
inline constexpr uint32_t FS_N_FAMILIES  = 14;
inline constexpr uint32_t FS_FIXED_CELLS = 12;   /* 3 hot + 7 cold + 2 branch */
inline constexpr uint32_t FS_SLOTTED_BASE = 3;
inline constexpr uint32_t FS_SLOTTED_END  =
    FS_SLOTTED_BASE + FID_SLOT_COUNT * FS_N_FAMILIES;

static inline size_t fs_stride(uint32_t max_slots)
{
    return (size_t)FS_FIXED_CELLS + (size_t)FS_N_FAMILIES * max_slots;
}

/* Decompose a logical slot.  Returns false for a slotted cell whose
 * slot index k is beyond @max_slots (an unobserved high slot — the
 * caller treats it as a state miss, or grows the block on write). */
static inline bool fs_phys_offset(uint16_t lslot, uint32_t max_slots,
                                  uint32_t *off, uint32_t *k_out)
{
    if (lslot < FS_SLOTTED_BASE) {          /* hot singleton */
        *off = lslot;
        *k_out = 0;
        return true;
    }
    if (lslot < FS_SLOTTED_END) {           /* slotted family cell */
        uint32_t r = (uint32_t)lslot - FS_SLOTTED_BASE;
        uint32_t k = r / FS_N_FAMILIES;
        uint32_t f = r % FS_N_FAMILIES;
        *k_out = k;
        if (k >= max_slots) return false;
        *off = FS_FIXED_CELLS + f * max_slots + k;
        return true;
    }
    /* cold metadata singleton */
    *off = 3 + ((uint32_t)lslot - FS_SLOTTED_END);
    *k_out = 0;
    return true;
}

/* Grow @blk to hold @n_insns instructions worth of cells.  Idempotent;
 * never shrinks.  Stride is constant here, so the resize appends whole
 * rows without disturbing existing indices. */
void block_ensure_capacity(FieldStateBlock *blk, uint32_t n_insns)
{
    if (blk->n_insns >= n_insns) return;
    size_t new_cells = (size_t)n_insns * fs_stride(blk->max_slots);
    blk->values.resize(new_cells);
    blk->gens.resize(new_cells, 0);
    blk->n_insns = n_insns;
}

/* Grow @blk's per-family slot occupancy to at least @need slots,
 * re-laying-out into the wider stride and copying every live cell
 * (deltas are computed against these — losing one would desync the
 * decode), exactly like the writer's field_state_block_ensure_slots. */
static void block_grow_slots(FieldStateBlock *blk, uint32_t need)
{
    if (need <= blk->max_slots) return;
    if (need > FID_SLOT_COUNT) need = FID_SLOT_COUNT;
    uint32_t old_ms = blk->max_slots, new_ms = need;
    size_t old_st = fs_stride(old_ms), new_st = fs_stride(new_ms);
    uint32_t n = blk->n_insns;

    std::vector<Wide>     nv((size_t)n * new_st);
    std::vector<uint32_t> ng((size_t)n * new_st, 0);
    for (uint32_t i = 0; i < n; i++) {
        size_t o = (size_t)i * old_st, nn = (size_t)i * new_st;
        for (uint32_t c = 0; c < FS_FIXED_CELLS; c++) {
            nv[nn + c] = blk->values[o + c];
            ng[nn + c] = blk->gens[o + c];
        }
        for (uint32_t f = 0; f < FS_N_FAMILIES; f++) {
            size_t of = o + FS_FIXED_CELLS + (size_t)f * old_ms;
            size_t nf = nn + FS_FIXED_CELLS + (size_t)f * new_ms;
            for (uint32_t k = 0; k < old_ms; k++) {
                nv[nf + k] = blk->values[of + k];
                ng[nf + k] = blk->gens[of + k];
            }
        }
    }
    blk->values.swap(nv);
    blk->gens.swap(ng);
    blk->max_slots = new_ms;
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
    uint32_t off, k;
    if (!fs_phys_offset(slot, blk->max_slots, &off, &k)) {
        return false;   /* unobserved high slot -> state miss */
    }
    size_t idx = (size_t)ipos * fs_stride(blk->max_slots) + off;
    if (blk->gens[idx] != table_gen) return false;
    *out = blk->values[idx];
    return true;
}

void cell_write(FieldStateBlock *blk, uint32_t table_gen,
                uint32_t ipos, uint16_t slot, const Wide &val)
{
    if (!blk || slot == FIELD_STATE_SLOT_INVALID) return;
    block_ensure_capacity(blk, ipos + 1);
    uint32_t off, k;
    if (!fs_phys_offset(slot, blk->max_slots, &off, &k)) {
        block_grow_slots(blk, k + 1);
        if (!fs_phys_offset(slot, blk->max_slots, &off, &k)) {
            return;     /* slot beyond FID_SLOT_COUNT: cap, drop */
        }
    }
    size_t idx = (size_t)ipos * fs_stride(blk->max_slots) + off;
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
            (a[i].has_data && a[i].data != b[i].data) ||
            a[i].has_ppage != b[i].has_ppage ||
            (a[i].has_ppage && a[i].ppage != b[i].ppage)) {
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
        const RegSnap &p = prev_snap[d - 1];
        const RegSnap &f = iframe_snap[d - 1];
        char detail[256];
        std::snprintf(detail, sizeof(detail),
                      " (ENTRY insn=%u op=%u reg=%u v0=0x%llx"
                      " | IFRAME insn=%u op=%u reg=%u v0=0x%llx)",
                      p.insn_index, p.operand_index, p.reg_id,
                      (unsigned long long)p.value.low64(),
                      f.insn_index, f.operand_index, f.reg_id,
                      (unsigned long long)f.value.low64());
        fail("reg_snaps[" + std::to_string(d - 1) + "] mismatch" + detail);
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
    if (prev.wp_first_fetch_unavailable != iframe.wp_first_fetch_unavailable) {
        fail("chain-level wp event mismatch: ENTRY=" +
             std::to_string(prev.wp_first_fetch_unavailable) +
             " IFRAME=" + std::to_string(iframe.wp_first_fetch_unavailable));
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

/* Template-default Wide for the FID_INSN_* range: the baseline is the
 * template's static value (so emit-equal-to-template writes no
 * record).  Other ranges default to zero via the caller's Wide{}. */
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
      reg_flags_id_(-1),
      lint_(header, templates)
{
    /* Resolve REG_FLAGS' id from the trace's own reg map. */
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
 * walk() dispatches on the body_tag-mapped leading byte; each handler
 * consumes its payload, updates stats_, and (ENTRY/REGFILE) invokes
 * the callback.
 * ==================================================================== */

/* Transient state carried across one walk() invocation.  Lives on the
 * stack inside walk(); each handler takes it by reference. */
struct BodyWalker::WalkState {
    int32_t  prev_entry_template   = 0;
    /* Base 0: the body's first record is always a THREAD_SWITCH, so
     * the starting thread arrives as an ordinary delta from 0 (no
     * special-case base). */
    uint32_t current_thread        = 0;
    bool     pending_thread_switch = false;

    /* Active address-space (ASID) index, the second half of the
     * (thread_id, asid) context.  Base 0: the body's first record is
     * always an ASID_SWITCH, so the opening asid arrives as an ordinary
     * delta from 0 (mandatory initial declaration).  @seen_asids tracks
     * which indices have already carried their inline identity so the
     * decoder reads it on first sighting only — mirroring the writer's
     * asid_identity_emitted. */
    uint32_t current_asid          = 0;
    bool     pending_asid_switch   = false;
    std::vector<bool> seen_asids;

    /* Per-context FieldStateTables, keyed by (asid_index, thread_id) —
     * mirroring the writer's per-(ctx_asid, thread) field-state overlays
     * (body_stream_write_entry's ctx_key).  The writer computes each
     * entry's delta baselines against the OWNING PROCESS's history, so a
     * single guest thread that spans multiple address spaces (e.g. a
     * kernel/idle thread running clear_page for different processes)
     * carries a FRESH baseline per asid.  Keying by thread alone would
     * merge those, mis-accumulating deltas (an N_STORES 0->1 emitted
     * against a process's fresh block would be applied on top of another
     * process's resident 1, yielding 2).  In user mode / single-address-
     * space traces asid_index is always 0, so the key collapses to the
     * thread and behaviour is unchanged. */
    std::unordered_map<uint64_t, FieldStateTable> cp_states;
    std::unordered_map<uint64_t, FieldStateTable> wp_states;

    /* Last observed ENTRY, retained for the next IFRAME's validation. */
    std::optional<DecodedEntry> prev_entry;

    /* 1-based sequence number assigned to each ENTRY for the
     * DecodedEntry::seq_num field. */
    uint32_t seq = 0;

    static uint64_t ctx_key(uint32_t asid, uint32_t thread) {
        return ((uint64_t)asid << 32) | thread;
    }
    FieldStateTable &state_at(std::unordered_map<uint64_t, FieldStateTable> &m,
                              uint32_t asid, uint32_t thread) {
        return m[ctx_key(asid, thread)];
    }
};

void BodyWalker::handle_thread_switch(WalkState &ws)
{
    int64_t d = body_.sleb();
    ws.current_thread = (uint32_t)((int64_t)ws.current_thread + d);
    ws.pending_thread_switch = true;
    stats_.thread_switch_count++;
}

/*
 * BODY_TAG_ASID_SWITCH: rebase the address-space dimension of the
 * context.  Read the sleb128 asid-index delta; on an index's FIRST
 * sighting also consume its inline identity (u64 root_phys + u64 sig),
 * exactly as the writer emitted it.  P1 records only current_asid; the
 * identity bytes are parsed for wire consistency (Phase 2 surfaces them
 * to consumers).
 */
void BodyWalker::handle_asid_switch(WalkState &ws)
{
    int64_t d = body_.sleb();
    ws.current_asid = (uint32_t)((int64_t)ws.current_asid + d);
    if (ws.current_asid >= ws.seen_asids.size()) {
        ws.seen_asids.resize((size_t)ws.current_asid + 1, false);
    }
    if (!ws.seen_asids[ws.current_asid]) {
        (void)body_.u64_le();   /* root_phys — Phase 2 surfaces identity */
        (void)body_.u64_le();   /* sig                                   */
        ws.seen_asids[ws.current_asid] = true;
    }
    ws.pending_asid_switch = true;
    stats_.asid_switch_count++;
}

/*
 * BODY_TAG_DEVIO_START / _STOP: a disk-I/O request bracket.  START
 * payload: uleb request_id, u8 rw (CST_DEVIO_*), uleb bytes, uleb block
 * (disk block number), u8 attr (CST_DEVIO_ATTR_*); iff attr == EXACT
 * then uleb owner_thread_id, uleb owner_asid.  STOP payload: uleb
 * request_id.
 *
 * Owner attribution: an EXACT START carries its owning (thread, asid)
 * inline — the process the doorbell captured in the issuing vCPU's
 * context — so it does not depend on the record's position in the
 * interleaved stream.  A POSITIONAL START (no doorbell matched) and any
 * STOP use the stream context, except a STOP inherits the owner of a
 * START the walker has already seen (devio_owner_).
 */
void BodyWalker::handle_devio(WalkState &ws, bool is_start)
{
    DecodedDevio d;
    d.is_start = is_start;
    d.request_id = body_.uleb();
    if (is_start) {
        d.rw = body_.u8();
        d.bytes = body_.uleb();
        d.block = body_.uleb();
        uint8_t attr = body_.u8();
        if (attr == CST_DEVIO_ATTR_EXACT) {
            d.exact = true;
            d.thread_id = (uint32_t)body_.uleb();
            d.asid = (uint32_t)body_.uleb();
            devio_owner_[d.request_id] = { d.thread_id, d.asid };
        } else {
            d.thread_id = ws.current_thread;
            d.asid = ws.current_asid;
        }
        stats_.devio_start_count++;
    } else {
        /* STOP: inherit the paired START's owner when known. */
        auto it = devio_owner_.find(d.request_id);
        if (it != devio_owner_.end()) {
            d.thread_id = it->second.first;
            d.asid = it->second.second;
            devio_owner_.erase(it);
        } else {
            d.thread_id = ws.current_thread;
            d.asid = ws.current_asid;
        }
        stats_.devio_stop_count++;
    }
    if (devio_cb_) {
        devio_cb_(d);
    }
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
    const FieldStateTable *base_state, bool *has_events)
{
    std::vector<WPEntry> out;
    uint64_t chain_hdr = wpb.uleb();
    uint64_t num_wp = chain_hdr >> 1;
    if (has_events) {
        *has_events = (chain_hdr & header_.ids.wp_chain_has_events) != 0;
    }
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
        /* Dangling-template-ref lint (cst_lint.h): id 0 is the writer's
         * "no template" sentinel, every other id must resolve. */
        if (!wtmpl && wp_tmpl != 0) {
            lint_.note_dangling((uint32_t)wp_tmpl, /*is_wp=*/true);
        }
        /* WP blocks now carry the CST_FID_BRANCH_* singletons too, decoded
         * into we.branch (displacement reconstructed against the template
         * insn PC, same as CP).  The successor is the next chain block's
         * start_pc, so --verify-branch can cross-check it in-chain. */
        decode_field_delta(wpb, (uint32_t)wp_tmpl, wtmpl,
                           state, base_state,
                           &we.dyn_params, &we.reg_snaps, &we.metaflags,
                           &we.lane_masks, /*lint=*/nullptr, &we.branch);
        out.push_back(std::move(we));
    }
    return out;
}

void BodyWalker::decode_wp_events(Reader &evb,
                                  std::vector<WPEntry> *wp_entries,
                                  bool *chain_unavail)
{
    const ResolvedIds &ids = header_.ids;
    uint64_t num_events = evb.uleb();
    int64_t prev_idx = -1;
    for (uint64_t k = 0; k < num_events; k++) {
        uint64_t gap = evb.uleb();
        int64_t idx = prev_idx + 1 + (int64_t)gap;
        if (idx < 0) {
            throw std::runtime_error("wp event index out of range");
        }
        uint8_t evf = evb.u8();
        bool is_fault = (evf & ids.wp_event_fault) != 0;
        if ((size_t)idx >= wp_entries->size()) {
            /* Chain-level event (§4.4): the resolved index lies past
             * the encoded chain, so it describes the excursion's
             * unrealized first target rather than any block.  The
             * FAULT payload, if present, is consumed for wire
             * consistency but carries no per-block anchor. */
            if ((evf & ids.wp_event_translation_unavail) && chain_unavail) {
                *chain_unavail = true;
            }
            if (is_fault) {
                (void)evb.uleb();
            }
            prev_idx = idx;
            continue;
        }
        WPEntry &we = (*wp_entries)[idx];
        we.translation_unavailable = (evf & ids.wp_event_translation_unavail) != 0;
        we.fault = is_fault;
        if (is_fault) {
            we.fault_insn_index = (uint32_t)evb.uleb();
            we.has_fault_idx = true;
        }
        prev_idx = idx;
    }
}

/* Tally is_atomic per (entry × insn) — counts observations, not
 * deduped templates. */
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

    FieldStateTable &cp_state =
        ws.state_at(ws.cp_states, ws.current_asid, ws.current_thread);
    FieldStateTable &wp_state =
        ws.state_at(ws.wp_states, ws.current_asid, ws.current_thread);

    DecodedEntry entry;
    entry.template_id = (uint32_t)entry_tmpl;

    /* CP delta section. */
    const Template *cp_tmpl = by_id_.count((uint32_t)entry_tmpl)
        ? &templates_[by_id_.at((uint32_t)entry_tmpl)] : nullptr;
    /* Dangling-template-ref lint (cst_lint.h): a CP ENTRY naming a
     * template the templates section never defined is structural
     * corruption, whatever the id's value. */
    if (!cp_tmpl) {
        lint_.note_dangling((uint32_t)entry_tmpl, /*is_wp=*/false);
    }
    decode_field_delta(body_, (uint32_t)entry_tmpl, cp_tmpl,
                       cp_state, nullptr,
                       &entry.dyn_params, &entry.reg_snaps, &entry.metaflags,
                       &entry.lane_masks, &lint_, &entry.branch);

    /* Per-entry synchronous-fault trailer (docs/format.rst §4.2a), present
     * only when the CST_FLAG_FAULT header bit is set; sits between the CP
     * delta and the WP sections.  Exception-nesting depth at which this
     * BB executed. */
    if (flags_ & header_.ids.flag_fault) {
        entry.fault_depth = (uint32_t)body_.uleb();
        uint64_t n_anchors = body_.uleb();
        for (uint64_t a = 0; a < n_anchors; a++) {
            entry.fault_anchors.push_back((uint32_t)body_.uleb());
        }
    }

    /* WP chain + events, present only when the CST_FLAG_WP header bit
     * is set; otherwise the entry is just its CP delta.  wp_chain is
     * its own length-prefixed sub-section; wp_events is conditional on
     * that chain's CST_WP_CHAIN_HAS_EVENTS bit — entirely absent from
     * the wire (no length prefix) when the chain produced no event. */
    if (flags_ & header_.ids.flag_wp) {
        bool has_events = false;
        { SectionScope s(body_); Reader &wpb = s;
          entry.wp_entries = decode_wp_chain(wpb, wp_state, &cp_state,
                                             &has_events); }
        if (has_events) {
            SectionScope s(body_); Reader &evb = s;
            decode_wp_events(evb, &entry.wp_entries,
                             &entry.wp_first_fetch_unavailable);
        }
    }

    entry.thread_id       = ws.current_thread;
    entry.thread_switched = ws.pending_thread_switch;
    entry.asid            = ws.current_asid;
    entry.seq_num         = ++ws.seq;
    ws.pending_thread_switch = false;
    ws.pending_asid_switch = false;

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
    /* Decode the IFRAME against fresh empty overlays (every value =
     * delta-from-template-default = absolute) and assert it matches
     * the preceding ENTRY; divergence => corrupt trace or out-of-sync
     * encoder/decoder, so throw. */
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
                       &iframe_entry.lane_masks,
                       /*lint=*/nullptr);   /* re-encodes the prev ENTRY;
                                             * counting would double-report */

    /* Fault trailer, mirroring the ENTRY path (writer emits the same payload
     * for an IFRAME).  Consume to stay in sync. */
    if (flags_ & header_.ids.flag_fault) {
        iframe_entry.fault_depth = (uint32_t)body_.uleb();
        uint64_t n_anchors = body_.uleb();
        for (uint64_t a = 0; a < n_anchors; a++) {
            iframe_entry.fault_anchors.push_back((uint32_t)body_.uleb());
        }
    }

    /* WP chain + events, gated by CST_FLAG_WP exactly as the ENTRY
     * path.  Mirror the writer's IFRAME emission: the iframe_wp
     * overlay falls back to iframe_cp as base, matching
     * st->iframe_cp_scratch shared between wp_state and wp_base. */
    if (flags_ & header_.ids.flag_wp) {
        bool has_events = false;
        { SectionScope s(body_); Reader &wpb = s;
          iframe_entry.wp_entries = decode_wp_chain(wpb, iframe_wp,
                                                    &iframe_cp,
                                                    &has_events); }
        if (has_events) {
            SectionScope s(body_); Reader &evb = s;
            decode_wp_events(evb, &iframe_entry.wp_entries,
                             &iframe_entry.wp_first_fetch_unavailable);
        }
    }

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
        if (tag == ids.body_tag_asid_switch) {
            handle_asid_switch(ws);
            continue;
        }
        if (tag == ids.body_tag_regfile) {
            handle_regfile(rb);
            continue;
        }
        if (tag == ids.body_tag_devio_start) {
            handle_devio(ws, /*is_start=*/true);
            continue;
        }
        if (tag == ids.body_tag_devio_stop) {
            handle_devio(ws, /*is_start=*/false);
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
 * Pass 1 applies each wire record's delta to its (state_blk, ipos,
 * slot) cell.  Pass 2 walks @tmpl's insns, reads the cells back, and
 * materialises DynParam / RegSnap / MetaFlagsEntry / LaneMask rows.
 * ==================================================================== */

namespace {

/* Pass-1 record loop: apply each non-EXTENDED delta to its
 * (state_blk, ipos, slot) cell.  Format 0x1D: fid is ULEB128, no
 * EXTRA_* overflow path.  @lint (with @lint_row, the template's
 * per-insn capability row) is non-null only for CP ENTRY sections:
 * a dst-reg VALUE record naming an operand slot the template does
 * not carry — or an insn position past the template — is an
 * impossible attribution (the writer never emits such records). */
void apply_record_deltas(BodyWalker &walker, Reader &sec, uint64_t n_records,
                         uint32_t template_id, const Template *tmpl,
                         const ResolvedIds &ids,
                         const std::array<uint16_t, FID_LUT_SIZE> &slot_lut,
                         FieldStateBlock *state_blk, uint32_t state_gen,
                         const FieldStateBlock *base_blk, uint32_t base_gen,
                         int scalar_bits,
                         Wide (BodyWalker::*tmpl_default)(const Template*, uint32_t, uint8_t) const,
                         AttributionLint *lint,
                         const std::vector<uint8_t> *lint_row)
{
    uint32_t pos = 0;
    for (uint64_t i = 0; i < n_records; i++) {
        pos += (uint32_t)sec.uleb();
        uint16_t fid = (uint16_t)sec.uleb();

        if (lint && lint_row && lint->reg_check_enabled()) {
            int slot = lint->dst_slot_for_fid(fid);
            if (slot >= 0 &&
                (pos >= lint_row->size() ||
                 slot >= (int)((*lint_row)[pos] &
                               AttributionLint::N_DST_MASK))) {
                lint->note_reg(template_id, pos);
            }
        }

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

/* Materialise the slotted loads/stores for one insn into @out.
 * @addr_fids / @data_fids are name-resolved per-slot FID arrays (no
 * stride assumption). */
void materialise_slotted_memops(uint32_t insn_idx, uint64_t n_fixed,
                                DynParam::Type type,
                                const FidSlotArray &addr_fids,
                                const FidSlotArray &data_fids,
                                const FidSlotArray &size_fids,
                                const FidSlotArray &ppage_fids,
                                bool has_mem,
                                bool has_ppage,
                                const FieldStateBlock *state_blk,
                                uint32_t state_gen,
                                const FieldStateBlock *base_blk,
                                uint32_t base_gen,
                                const std::array<uint16_t, FID_LUT_SIZE> &slot_lut,
                                std::vector<DynParam> *out)
{
    /* Defensive clamp: a malformed trace whose N_LOADS/N_STORES
     * exceed FID_SLOT_COUNT must not index past the slot arrays. */
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
        /* Physical PAGE base (CST_FLAG_PHYSADDR).  The delta stream omits
         * the record for a memop with no observable translation, so a slot
         * whose ppage cell was never written keeps the running (last real)
         * value; a value of 0 means "no translation seen yet" -> not
         * surfaced.  has_ppage gates the whole family off for non-physaddr
         * traces. */
        if (has_ppage && ppage_fids[s] != 0) {
            uint64_t pp = lookup_cell(state_blk, state_gen, base_blk, base_gen,
                                      slot_lut, insn_idx, ppage_fids[s]).low64();
            if (pp != 0) {
                dp.ppage = pp;
                dp.has_ppage = true;
            }
        }
        if (has_mem) {
            dp.data = lookup_cell(state_blk, state_gen, base_blk, base_gen,
                                  slot_lut, insn_idx, data_fid);
            dp.has_data = true;
            /* Access byte width rides with the value (gated by mem_data).
             * 0 when the trace predates the *_SIZE families. */
            dp.data_size = (uint8_t)lookup_cell(state_blk, state_gen,
                                                base_blk, base_gen, slot_lut,
                                                insn_idx, size_fids[s]).low64();
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
        r.width_bytes = (uint8_t)lookup_cell(state_blk, state_gen,
                                             base_blk, base_gen, slot_lut,
                                             insn_idx,
                                             ids.fid_dst_reg_width[op_i])
                            .low64();
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
                                    std::vector<LaneMaskEntry>  *lane_masks,
                                    AttributionLint             *lint,
                                    BranchOutcome               *branch)
{
    SectionScope scope(outer);
    Reader &sec = scope;
    uint64_t n_records = sec.uleb();
    const ResolvedIds &ids = header_.ids;

    /* Per-insn capability row for the lint checks; resolved once per
     * section so the record loop stays hash-free. */
    const std::vector<uint8_t> *lint_row =
        lint ? lint->row(template_id) : nullptr;

    /* Resolve the per-(state,base) blocks once; the record loop
     * indexes directly rather than hashing per record. */
    uint32_t need_insns = tmpl ? (uint32_t)tmpl->insns.size() : 0;
    FieldStateBlock *state_blk =
        table_get_or_create_block(state, template_id,
                                  std::max<uint32_t>(need_insns, 1));
    const FieldStateBlock *base_blk =
        base_state ? table_get_block(*base_state, template_id) : nullptr;
    uint32_t state_gen = state.generation;
    uint32_t base_gen  = base_state ? base_state->generation : 0;

    /* Pass 1: apply record deltas. */
    apply_record_deltas(*this, sec, n_records,
                        template_id, tmpl, ids, slot_lut_,
                        state_blk, state_gen, base_blk, base_gen,
                        scalar_bits_,
                        &BodyWalker::template_default,
                        lint, lint_row);

    /* Pass 2: materialise per-insn outputs.  Skipped entirely when
     * we don't have a template (decoder doesn't know the insn count). */
    if (!tmpl) return;
    const bool has_mem = (flags_ & ids.flag_mem_data) != 0;
    const bool has_reg = (flags_ & ids.flag_reg_data) != 0;
    const bool has_ppage = (flags_ & ids.flag_physaddr) != 0;

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

        /* Impossible attribution: a runtime memop count on an insn
         * whose template can produce none (static max loads AND
         * stores both zero).  The n_loads/n_stores cells were read
         * anyway, so a conformant trace pays one flag test. */
        if (lint && (n_loads || n_stores) && lint_row &&
            i < lint_row->size() &&
            ((*lint_row)[i] & AttributionLint::MEM_IMPOSSIBLE)) {
            lint->note_mem(template_id, idx, n_loads + n_stores);
        }

        if (n_loads || n_stores) {
            materialise_slotted_memops(idx, n_loads, DynParam::Load,
                                       ids.fid_load_addr,
                                       ids.fid_load_data,
                                       ids.fid_load_size,
                                       ids.fid_load_ppage,
                                       has_mem, has_ppage,
                                       state_blk, state_gen,
                                       base_blk,  base_gen,
                                       slot_lut_, dyn_params);
            materialise_slotted_memops(idx, n_stores, DynParam::Store,
                                       ids.fid_store_addr,
                                       ids.fid_store_data,
                                       ids.fid_store_size,
                                       ids.fid_store_ppage,
                                       has_mem, has_ppage,
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
                                const FidSlotArray &fids,
                                uint16_t n_slots) {
                if (n_slots > FID_SLOT_COUNT) n_slots = FID_SLOT_COUNT;
                for (uint16_t s = 0; s < n_slots; s++) {
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
                     (uint16_t)it.src_regs.size());
            emit_fam(LaneMaskEntry::Dst,       ids.fid_dst_lane_mask,
                     (uint16_t)it.dst_regs.size());
            emit_fam(LaneMaskEntry::LoadData,  ids.fid_load_data_lane_mask,
                     (uint16_t)std::min<uint32_t>(it.max_dep_loads,
                                                  (uint32_t)n_loads));
            emit_fam(LaneMaskEntry::StoreData, ids.fid_store_data_lane_mask,
                     (uint16_t)std::min<uint32_t>(it.max_dep_stores,
                                                  (uint32_t)n_stores));
        }
    }

    /* Branch-outcome singletons (CST_FID_BRANCH_TAKEN / _TARGET).  Exposed
     * directly per entry (CP) and per WP chain block, with no successor
     * look-ahead: locate the terminating branch exactly as the writer does
     * (highest-indexed branch-type insn — n-1 normally, n-2 on a delay-slot
     * tail), then read its two persisted cells.  Direction/target ride the
     * branch insn's position through the same delta model as METAFLAGS, so a
     * static direct branch simply keeps its last value.  BRANCH_TARGET is a
     * SIGNED DISPLACEMENT from the branch insn's own PC, so the absolute
     * successor is reconstructed as branch_pc + displacement (branch_pc is
     * the template insn's PC).  valid iff the template ends in a branch AND
     * the trace advertises both FIDs; a pre-branch writer resolves them to
     * the absent sentinel (>= FID_LUT_SIZE), so the block is skipped and no
     * direction/target is surfaced for such a trace. */
    if (branch && ids.fid_branch_taken  < FID_LUT_SIZE
               && ids.fid_branch_target < FID_LUT_SIZE) {
        int bidx = -1;
        for (int j = (int)tmpl->insns.size() - 1; j >= 0; j--) {
            if (tmpl->insns[j].branch_type != 0) { bidx = j; break; }
        }
        if (bidx >= 0) {
            uint32_t bi = (uint32_t)bidx;
            branch->valid  = true;
            branch->taken  = lookup_cell(state_blk, state_gen,
                                         base_blk, base_gen, slot_lut_,
                                         bi, ids.fid_branch_taken).low64() != 0;
            uint64_t disp  = lookup_cell(state_blk, state_gen,
                                         base_blk, base_gen, slot_lut_,
                                         bi, ids.fid_branch_target).low64();
            branch->target = tmpl->insns[bi].pc + disp;
        }
    }
}

/* ====================================================================
 * §6b  Streaming BB walk  (walk_bb — zero per-BB allocation)
 *
 * Reuses §1's cell storage and §6's apply_record_deltas, but never runs
 * pass-2 materialisation: instead of building dyn_params / reg_snaps
 * vectors, the BB handed to the consumer exposes scalar accessors that
 * read the live field-state cells on demand.  One BB at a time, CP then
 * its WP chain, per Step 6.8 of the format spec.
 * ==================================================================== */

/* BB scalar accessors: read one cell through the (state, base) cell
 * hierarchy.  blk_ is null when the relevant fields were not decoded
 * for this BB (cp_fields=false, or a WP BB below Fields level), in
 * which case the accessors return zero. */
uint64_t BodyWalker::BB::load_count(uint32_t insn) const
{
    if (!blk_) return 0;
    return lookup_cell(blk_, state_gen_, base_blk_, base_gen_,
                       *slot_lut_, insn, ids_->fid_n_loads).low64();
}
uint64_t BodyWalker::BB::store_count(uint32_t insn) const
{
    if (!blk_) return 0;
    return lookup_cell(blk_, state_gen_, base_blk_, base_gen_,
                       *slot_lut_, insn, ids_->fid_n_stores).low64();
}
uint64_t BodyWalker::BB::load_addr(uint32_t insn, uint32_t slot) const
{
    if (!blk_ || slot >= FID_SLOT_COUNT) return 0;
    return lookup_cell(blk_, state_gen_, base_blk_, base_gen_,
                       *slot_lut_, insn, ids_->fid_load_addr[slot]).low64();
}
uint64_t BodyWalker::BB::store_addr(uint32_t insn, uint32_t slot) const
{
    if (!blk_ || slot >= FID_SLOT_COUNT) return 0;
    return lookup_cell(blk_, state_gen_, base_blk_, base_gen_,
                       *slot_lut_, insn, ids_->fid_store_addr[slot]).low64();
}
/* Physical PAGE base of the memop (CST_FLAG_PHYSADDR).  Same cell
 * hierarchy as load_addr; 0 = no translation observed yet for this
 * (insn, slot) cell, and unconditionally 0 on a non-physaddr trace
 * (the ppage FIDs resolve to 0, which the slot LUT never maps). */
uint64_t BodyWalker::BB::load_ppage(uint32_t insn, uint32_t slot) const
{
    if (!blk_ || slot >= FID_SLOT_COUNT) return 0;
    return lookup_cell(blk_, state_gen_, base_blk_, base_gen_,
                       *slot_lut_, insn, ids_->fid_load_ppage[slot]).low64();
}
uint64_t BodyWalker::BB::store_ppage(uint32_t insn, uint32_t slot) const
{
    if (!blk_ || slot >= FID_SLOT_COUNT) return 0;
    return lookup_cell(blk_, state_gen_, base_blk_, base_gen_,
                       *slot_lut_, insn, ids_->fid_store_ppage[slot]).low64();
}
Wide BodyWalker::BB::load_data(uint32_t insn, uint32_t slot) const
{
    if (!blk_ || slot >= FID_SLOT_COUNT) return Wide{};
    return lookup_cell(blk_, state_gen_, base_blk_, base_gen_,
                       *slot_lut_, insn, ids_->fid_load_data[slot]);
}
Wide BodyWalker::BB::store_data(uint32_t insn, uint32_t slot) const
{
    if (!blk_ || slot >= FID_SLOT_COUNT) return Wide{};
    return lookup_cell(blk_, state_gen_, base_blk_, base_gen_,
                       *slot_lut_, insn, ids_->fid_store_data[slot]);
}
Wide BodyWalker::BB::dst_reg(uint32_t insn, uint32_t op) const
{
    if (!blk_ || op >= FID_SLOT_COUNT) return Wide{};
    return lookup_cell(blk_, state_gen_, base_blk_, base_gen_,
                       *slot_lut_, insn, ids_->fid_dst_reg[op]);
}
/* Byte width of memop value / dst-register write.  0 means the trace did
 * not carry the width (memdata/regdata off, or a trace produced before the
 * *_SIZE / *_WIDTH families existed — those fids resolve to 0, which the
 * slot LUT never maps). */
uint64_t BodyWalker::BB::load_size(uint32_t insn, uint32_t slot) const
{
    if (!blk_ || slot >= FID_SLOT_COUNT) return 0;
    return lookup_cell(blk_, state_gen_, base_blk_, base_gen_,
                       *slot_lut_, insn, ids_->fid_load_size[slot]).low64();
}
uint64_t BodyWalker::BB::store_size(uint32_t insn, uint32_t slot) const
{
    if (!blk_ || slot >= FID_SLOT_COUNT) return 0;
    return lookup_cell(blk_, state_gen_, base_blk_, base_gen_,
                       *slot_lut_, insn, ids_->fid_store_size[slot]).low64();
}
uint64_t BodyWalker::BB::dst_reg_width(uint32_t insn, uint32_t op) const
{
    if (!blk_ || op >= FID_SLOT_COUNT) return 0;
    return lookup_cell(blk_, state_gen_, base_blk_, base_gen_,
                       *slot_lut_, insn, ids_->fid_dst_reg_width[op]).low64();
}

void BodyWalker::consume_field_section(Reader &outer, uint32_t template_id,
                                       const Template *tmpl,
                                       FieldStateTable *state,
                                       const FieldStateTable *base_state)
{
    /* Decode the length-prefixed section IN PLACE — no sub-reader, no copy.
     * Records are consumed strictly sequentially into the per-template state
     * block (allocated once per bb template), so the bytes never need to be
     * materialised; SectionScope skips any unknown trailing bytes on exit
     * (forward-compat), matching the old sub() dtor. */
    SectionScope scope(outer);
    Reader &sec = scope;
    uint64_t n_records = sec.uleb();
    const ResolvedIds &ids = header_.ids;

    /* Parse-skip: advance past every record's bytes without touching
     * the state table.  No accessor at this level reads these cells,
     * so applying them would be pure waste (Step 6.10 byte shape). */
    if (!state) {
        for (uint64_t i = 0; i < n_records; i++) {
            sec.uleb();                              /* ipos delta */
            uint16_t fid = (uint16_t)sec.uleb();
            sec.sleb_wide();                         /* value delta */
            if (fid == ids.fid_extended) sec.uleb(); /* ext payload */
        }
        return;
    }

    uint32_t need_insns = tmpl ? (uint32_t)tmpl->insns.size() : 0;
    FieldStateBlock *state_blk =
        table_get_or_create_block(*state, template_id,
                                  std::max<uint32_t>(need_insns, 1));
    const FieldStateBlock *base_blk =
        base_state ? table_get_block(*base_state, template_id) : nullptr;
    apply_record_deltas(*this, sec, n_records, template_id, tmpl, ids,
                        slot_lut_, state_blk, state->generation,
                        base_blk, base_state ? base_state->generation : 0,
                        scalar_bits_, &BodyWalker::template_default,
                        /*lint=*/nullptr, /*lint_row=*/nullptr);
}

uint64_t BodyWalker::stream_wp_chain_bb(Reader &wpb, FieldStateTable &wp_state,
                                        FieldStateTable &cp_state, WpDecode wp,
                                        uint32_t seq, uint32_t thread,
                                        uint32_t asid, const BBCallback &cb,
                                        bool *has_events)
{
    const bool fields = (wp == WpDecode::Fields);
    uint64_t chain_hdr = wpb.uleb();
    uint64_t num_wp = chain_hdr >> 1;
    if (has_events) {
        *has_events = (chain_hdr & header_.ids.wp_chain_has_events) != 0;
    }
    int32_t prev_wp_tmpl = 0;
    for (uint64_t w = 0; w < num_wp; w++) {
        int32_t wt = prev_wp_tmpl + (int32_t)wpb.sleb();
        prev_wp_tmpl = wt;
        auto it = by_id_.find((uint32_t)wt);
        const Template *wtmpl = (it != by_id_.end())
            ? &templates_[it->second] : nullptr;

        /* Apply (Fields) or parse-skip (Structure) this BB's deltas
         * before reading it — Step 6.8 makes each pair self-contained,
         * so reading now is correct even if a later BB in the chain
         * reuses this template and overwrites the cells. */
        consume_field_section(wpb, (uint32_t)wt, wtmpl,
                              fields ? &wp_state : nullptr,
                              fields ? &cp_state : nullptr);

        stats_.wp_entries++;
        BB bb;
        bb.template_id    = (uint32_t)wt;
        bb.template_index = (it != by_id_.end())
            ? (uint32_t)it->second : 0xFFFFFFFFu;
        bb.tmpl           = wtmpl;
        bb.thread_id      = thread;
        bb.asid           = asid;   /* WP BB inherits its CP entry's asid */
        bb.seq_num        = seq;
        bb.is_wp          = true;
        bb.wp_index       = (uint32_t)w;
        bb.wp_chain_start = (w == 0);
        bb.wp_chain_last  = (w + 1 == num_wp);
        bb.n_insns        = wtmpl ? (uint32_t)wtmpl->insns.size() : 0;
        if (fields) {
            bb.blk_       = table_get_block(wp_state, (uint32_t)wt);
            bb.state_gen_ = wp_state.generation;
            bb.base_blk_  = table_get_block(cp_state, (uint32_t)wt);
            bb.base_gen_  = cp_state.generation;
            bb.slot_lut_  = &slot_lut_;
            bb.ids_       = &header_.ids;
        }
        cb(bb);
    }
    return num_wp;
}

void BodyWalker::handle_entry_bb(WalkState &ws, bool cp_fields, WpDecode wp,
                                 const BBCallback &cb)
{
    int64_t tdelta = body_.sleb();
    int32_t entry_tmpl = ws.prev_entry_template + (int32_t)tdelta;
    ws.prev_entry_template = entry_tmpl;

    FieldStateTable &cp_state =
        ws.state_at(ws.cp_states, ws.current_asid, ws.current_thread);

    auto cp_it = by_id_.find((uint32_t)entry_tmpl);
    const Template *cp_tmpl = (cp_it != by_id_.end())
        ? &templates_[cp_it->second] : nullptr;

    consume_field_section(body_, (uint32_t)entry_tmpl, cp_tmpl,
                          cp_fields ? &cp_state : nullptr, nullptr);

    /* Fault trailer (docs/format.rst §4.2a), between the CP delta and the
     * WP sections. */
    uint32_t fault_depth = 0;
    if (flags_ & header_.ids.flag_fault) {
        fault_depth = (uint32_t)body_.uleb();
        uint64_t n_anchors = body_.uleb();   /* anchors: parse-skipped here */
        for (uint64_t a = 0; a < n_anchors; a++) {
            (void)body_.uleb();
        }
    }

    uint32_t seq = ++ws.seq;
    stats_.cp_entries++;

    BB bb;
    bb.template_id     = (uint32_t)entry_tmpl;
    bb.template_index  = (cp_it != by_id_.end())
        ? (uint32_t)cp_it->second : 0xFFFFFFFFu;
    bb.tmpl            = cp_tmpl;
    bb.thread_id       = ws.current_thread;
    bb.asid            = ws.current_asid;
    bb.seq_num         = seq;
    bb.thread_switched = ws.pending_thread_switch;
    bb.n_insns         = cp_tmpl ? (uint32_t)cp_tmpl->insns.size() : 0;
    bb.fault_depth     = fault_depth;
    if (cp_fields) {
        bb.blk_       = table_get_block(cp_state, (uint32_t)entry_tmpl);
        bb.state_gen_ = cp_state.generation;
        bb.slot_lut_  = &slot_lut_;
        bb.ids_       = &header_.ids;
    }
    ws.pending_thread_switch = false;
    ws.pending_asid_switch = false;
    cb(bb);

    /* WP chain + events (Steps 6.8 / 6.9), present only under
     * CST_FLAG_WP.  sub() consumes each section regardless of whether
     * we walk it, so Skip / event parse-skip are one line each.  The
     * events section is conditional on the chain header's
     * CST_WP_CHAIN_HAS_EVENTS bit (unpacked below as @has_events) —
     * absent entirely from the wire when clear, so it must be read
     * unconditionally (not just when wp_events_cb_ is set) to know
     * whether a second SectionScope even has bytes to open. */
    if (flags_ & header_.ids.flag_wp) {
        uint64_t chain_len = 0;
        bool has_events = false;
        { SectionScope s(body_); Reader &wpb = s;
          if (wp != WpDecode::Skip) {
              FieldStateTable &wp_state =
                  ws.state_at(ws.wp_states, ws.current_asid,
                              ws.current_thread);
              chain_len = stream_wp_chain_bb(wpb, wp_state, cp_state, wp,
                                             seq, ws.current_thread,
                                             ws.current_asid, cb,
                                             &has_events);
          } else {
              /* Chain walking skipped, but num_wp (chain length, used to
               * resolve past-chain / chain-level event indices) and the
               * HAS_EVENTS bit both live in the header's leading ULEB —
               * SectionScope skips the remaining chain bytes either
               * way. */
              uint64_t chain_hdr = wpb.uleb();
              chain_len = chain_hdr >> 1;
              has_events = (chain_hdr & header_.ids.wp_chain_has_events) != 0;
          }
        }
        if (!has_events) {
            return;
        }
        { SectionScope s(body_);
          if (wp_events_cb_) {
              /* Parse the events section (identical byte consumption to
               * the skip; see decode_wp_events for the batch-path twin)
               * and fire the per-entry summary. */
              Reader &evb = s;
              const ResolvedIds &ids = header_.ids;
              WpEventsSummary sum;
              sum.seq_num   = seq;
              sum.chain_len = (uint32_t)chain_len;
              uint64_t num_events = evb.uleb();
              int64_t prev_idx = -1;
              for (uint64_t k = 0; k < num_events; k++) {
                  uint64_t gap = evb.uleb();
                  int64_t idx = prev_idx + 1 + (int64_t)gap;
                  uint8_t evf = evb.u8();
                  bool is_fault = (evf & ids.wp_event_fault) != 0;
                  bool is_unavail =
                      (evf & ids.wp_event_translation_unavail) != 0;
                  if (idx < 0 || (uint64_t)idx >= chain_len) {
                      /* Chain-level event (§4.4): the unrealized first
                       * target.  FAULT payload consumed for wire
                       * consistency. */
                      if (is_unavail) sum.chain_unavailable = true;
                      if (is_fault)   (void)evb.uleb();
                  } else {
                      if (is_fault) {
                          sum.fault_count++;
                          (void)evb.uleb();     /* fault insn index */
                          if ((uint64_t)idx + 1 == chain_len) {
                              sum.last_fault = true;
                          }
                      }
                      if (is_unavail) {
                          sum.unavail_count++;
                          if ((uint64_t)idx + 1 == chain_len) {
                              sum.last_unavail = true;
                          }
                      }
                  }
                  prev_idx = idx;
              }
              wp_events_cb_(sum);
          }
        }
    }
}

void BodyWalker::skip_iframe_bb()
{
    /* IFRAME (Step 6.5): cp_delta_section [+ wp_chain + wp_events
     * under CST_FLAG_WP], no leading template delta.  Consume the
     * sections to stay byte-aligned; the streaming path does not
     * field-validate. */
    { SectionScope s(body_); (void)s; }
    if (flags_ & header_.ids.flag_fault) {
        (void)body_.uleb();    /* fault depth */
        uint64_t n_anchors = body_.uleb();
        for (uint64_t a = 0; a < n_anchors; a++) {
            (void)body_.uleb();
        }
    }
    if (flags_ & header_.ids.flag_wp) {
        bool has_events = false;
        { SectionScope s(body_); Reader &wpb = s;
          uint64_t chain_hdr = wpb.uleb();
          has_events = (chain_hdr & header_.ids.wp_chain_has_events) != 0;
        }
        if (has_events) {
            SectionScope s(body_); (void)s;
        }
    }
    stats_.iframe_count++;
}

void BodyWalker::walk_bb(bool cp_fields, WpDecode wp,
                         const BBCallback &cb, const RegfileCallback &rb)
{
    /* WP field cells fall back to the CP field state (base_state), so
     * reconstructing WP fields requires the CP deltas to have been
     * applied — a WP BB that reuses a CP template need not re-encode an
     * unchanged n_loads/addr.  Force CP-field decode whenever WP fields
     * are requested, regardless of what the caller passed. */
    if (wp == WpDecode::Fields) cp_fields = true;

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
        if (tag == ids.body_tag_asid_switch) {
            handle_asid_switch(ws);
            continue;
        }
        if (tag == ids.body_tag_regfile) {
            handle_regfile(rb);
            continue;
        }
        if (tag == ids.body_tag_devio_start) {
            handle_devio(ws, /*is_start=*/true);
            continue;
        }
        if (tag == ids.body_tag_devio_stop) {
            handle_devio(ws, /*is_start=*/false);
            continue;
        }
        if (tag == ids.body_tag_entry) {
            handle_entry_bb(ws, cp_fields, wp, cb);
            if (max_entries_ && stats_.cp_entries >= max_entries_) {
                return;
            }
            continue;
        }
        if (tag == ids.body_tag_iframe) {
            skip_iframe_bb();
            continue;
        }
        throw std::runtime_error("Unknown body tag");
    }

    if (footer_num_entries && *footer_num_entries != ws.seq) {
        throw std::runtime_error("Footer entry-count mismatch");
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

/* Resolve a direct-branch target by matching its static target PC
 * against template start_pc.  nullptr for indirect/return/REP or
 * out-of-window targets.  Keyed on branch_type map names (not
 * compile-time enums) so a renumbered BRANCH_* stays decodable. */
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
