/*
 * ChampSim Tracer offline tools — body walker / delta replay.
 *
 * Streams cst::DecodedEntry values out of a trace's body section by
 * walking the unified delta stream and rebuilding the per-(template,
 * insn-position, field-id) state across entries.
 *
 * Rippable bundle for consuming .cst traces elsewhere: cst_common.h
 * (wire types), cst_reader.h (pull reader + Source), cst_format.h/.cc
 * (container open + parse_header), cst_decode.h/.cc (this file:
 * BodyWalker + instructions_from_entry), cst_objdump.h/.cc (OPTIONAL
 * --objdump; no-op stub without -DCST_HAVE_CAPSTONE).  Plain C++17 +
 * a small POSIX set for cst_format.cc; no QEMU/glib.  Consumers can
 * feed the walker from their own byte source via Reader(const
 * uint8_t *, size_t, size_t) and skip the subprocess decompressor.
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
 * FieldStateTable storage (mirrors the writer's
 * BodyStreamState::cp_field_state in champsim_tracer_output.cc):
 * blocks indexed by template_id; values is a flat
 * (n_insns * FIELD_STATE_SLOT_COUNT) Wide array; gens is per-cell
 * generation — a cell "exists" only when gens[idx]==table.generation,
 * so bumping the generation invalidates every cell in O(1).  Replaces
 * an unordered_map<u64,Wide> (~10% of decode time in hash lookups). */
/* Layout matches FIELD_STATE_SLOT_COUNT in champsim_tracer_output.cc:
 *   3 singletons (N_LOADS, N_STORES, METAFLAGS) + 8 * FID_SLOT_COUNT
 *   (slotted families: load_addr/store_addr/load_data/store_data/
 *   dst_reg/load_size/store_size/dst_reg_width) + 4 * FID_SLOT_COUNT
 *   (lane-mask block: SRC_LANE_MASK / DST_LANE_MASK / LOAD_DATA_LANE_MASK
 *   / STORE_DATA_LANE_MASK) + 7 insn-metadata.  EXTENDED has no
 *   persistent cell.  Bump alongside the writer when new families are
 *   added. */
inline constexpr size_t  FIELD_STATE_SLOT_COUNT   =
    3 + 8 * FID_SLOT_COUNT + 4 * FID_SLOT_COUNT + 7;
inline constexpr uint16_t FIELD_STATE_SLOT_INVALID = 0xFFFFu;
/* fid space is ULEB-encoded; the highest slotted FID at slot 63 is
 * ~322.  Round to next power-of-two for a single-load slot lookup. */
inline constexpr size_t  FID_LUT_SIZE             = 1024;

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

/* Structural counts surfaced after walk(), so consumers can
 * sanity-check writer cadence without re-walking the body. */
struct BodyStats {
    uint64_t cp_entries        = 0;
    uint64_t wp_entries        = 0;
    uint64_t iframe_count      = 0;
    uint64_t regfile_count     = 0;
    uint64_t thread_switch_count = 0;
    uint64_t fault_count       = 0;
    uint64_t translation_unavail_count = 0;
    /* Count of insns observed carrying CST_INSN_FLAG_ATOMIC.
     * Aggregated across both CP and WP entries by template-walk, so
     * each (entry × insn) contributes once. */
    uint64_t atomic_count      = 0;
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
     * each BODY_TAG_REGFILE record.
     *
     * This is the batch path: it materialises a DecodedEntry (and,
     * under CST_FLAG_WP, the whole wrong-path chain) per ENTRY.  Use
     * it when the consumer wants the fully-assembled entry shape
     * (objdump / instructions_from_entry / IFRAME validation).  For a
     * streaming consumer that processes one basic block at a time,
     * prefer walk_bb() below — it allocates no per-entry containers. */
    void walk(const Callback &cb,
              const RegfileCallback &rb = {});

    /* ====== Streaming BB walk (zero per-BB allocation) ============
     *
     * walk_bb() surfaces the body one basic block at a time — correct
     * path then, in order, its wrong-path chain — with NO difference
     * in shape between CP and WP (the BB::is_wp flag distinguishes).
     * Per Step 6.8 of the format spec each WP BB is fully decodable on
     * its own as the chain is walked, so there is no batching: the
     * walker applies that BB's field deltas, hands the consumer a BB
     * whose scalar accessors read the live per-template field-state,
     * and only then advances to the next BB.  Nothing is materialised
     * into vectors; a consumer reads exactly the cells it asks for.
     *
     * Two orthogonal cost dials let a metric pay only for what it
     * reads:
     *   @cp_fields  false => CP field deltas are parse-skipped (the BB
     *               still carries template_id / n_insns); the CP
     *               scalar accessors are unavailable.  true => CP
     *               deltas are applied and the accessors are live.
     *   @wp         Skip      => the WP chain section is consumed but
     *                           not walked; no WP BBs are emitted.
     *               Structure => WP BBs are emitted (template_id /
     *                           n_insns / chain markers) but their
     *                           field deltas are parse-skipped.
     *               Fields    => WP BBs are emitted with field deltas
     *                           applied and accessors live.
     * The WP events section (fault / translation flags, Step 6.9) is
     * always parse-skipped here — it is not surfaced on BB.  Consumers
     * that need it must use the batch walk().  IFRAME records are
     * parse-skipped (no field-content validation on this path). */
    enum class WpDecode { Skip, Structure, Fields };

    /* One basic-block execution surfaced by walk_bb().  The scalar
     * accessors read the live field-state block for this BB; they are
     * valid only for the duration of the callback (the next BB may
     * overwrite the shared block).  Accessors return 0 / Wide{} when
     * the relevant fields were not decoded (cp_fields=false, or a WP
     * BB at Structure level). */
    struct BB {
        uint32_t        template_id    = 0;
        /* Index into the templates vector (and any parallel per-
         * template array the consumer keeps), or UINT32_MAX if the
         * template id is unknown (never happens for a conformant CP
         * BB). */
        uint32_t        template_index = 0xFFFFFFFFu;
        const Template *tmpl           = nullptr;
        uint32_t        thread_id      = 0;
        uint32_t        seq_num        = 0;   /* CP visit counter; a WP
                                               * BB shares its parent
                                               * CP entry's seq_num. */
        bool            thread_switched = false; /* CP only */
        bool            is_wp          = false;
        uint32_t        wp_index       = 0;   /* position in WP chain */
        bool            wp_chain_start = false;
        bool            wp_chain_last  = false;
        uint32_t        n_insns        = 0;   /* template insn count */
        /* Exception-nesting depth (CST_FLAG_FAULT traces): 0 = normal code,
         * >=1 = synchronous-fault handler code at that nesting level.  CP
         * only; WP BBs inherit their parent CP entry's depth. */
        uint32_t        fault_depth    = 0;

        bool     has_fields() const { return blk_ != nullptr; }
        uint64_t load_count(uint32_t insn) const;
        uint64_t store_count(uint32_t insn) const;
        uint64_t load_addr(uint32_t insn, uint32_t slot) const;
        uint64_t store_addr(uint32_t insn, uint32_t slot) const;
        Wide     load_data(uint32_t insn, uint32_t slot) const;
        Wide     store_data(uint32_t insn, uint32_t slot) const;
        Wide     dst_reg(uint32_t insn, uint32_t op) const;
        /* Byte width (1..64) of the memop value / dst-register write;
         * 0 when the trace did not capture it. */
        uint64_t load_size(uint32_t insn, uint32_t slot) const;
        uint64_t store_size(uint32_t insn, uint32_t slot) const;
        uint64_t dst_reg_width(uint32_t insn, uint32_t op) const;

    private:
        friend class BodyWalker;
        const FieldStateBlock *blk_      = nullptr;
        uint32_t               state_gen_ = 0;
        const FieldStateBlock *base_blk_ = nullptr;
        uint32_t               base_gen_  = 0;
        const std::array<uint16_t, FID_LUT_SIZE> *slot_lut_ = nullptr;
        const ResolvedIds     *ids_      = nullptr;
    };
    using BBCallback = std::function<void(const BB &)>;

    void walk_bb(bool cp_fields, WpDecode wp,
                 const BBCallback &cb,
                 const RegfileCallback &rb = {});

private:
    /* Transient bookkeeping shared across the per-tag handlers below.
     * Defined in cst_decode.cc — forward declared here so the handler
     * signatures can reference it. */
    struct WalkState;

    /* Per-tag handlers.  walk() decodes the leading tag byte and
     * dispatches to one of these; each consumes that tag's payload
     * from body_ and updates @ws / stats_ accordingly.  handle_end()
     * returns the trailer's num_entries field. */
    void     handle_thread_switch(WalkState &ws);
    void     handle_regfile(const RegfileCallback &rb);
    void     handle_entry(WalkState &ws, const Callback &cb);
    void     handle_iframe(WalkState &ws);
    uint64_t handle_end();

    /* Streaming-path counterparts of handle_entry / handle_iframe.
     * handle_entry_bb applies (or parse-skips) the CP field deltas,
     * emits the CP BB, then walks the WP chain per @wp.  skip_iframe_bb
     * consumes an IFRAME's sections without applying or validating.
     * consume_field_section applies one field-delta section into
     * @state (or parse-skips it when @state is null) with no pass-2
     * materialisation.  stream_wp_chain_bb walks one WP chain,
     * emitting a BB per entry. */
    void consume_field_section(Reader &outer, uint32_t template_id,
                               const Template *tmpl,
                               FieldStateTable *state,
                               const FieldStateTable *base_state);
    void stream_wp_chain_bb(Reader &wpb, FieldStateTable &wp_state,
                            FieldStateTable &cp_state, WpDecode wp,
                            uint32_t seq, uint32_t thread,
                            const BBCallback &cb);
    void handle_entry_bb(WalkState &ws, bool cp_fields, WpDecode wp,
                         const BBCallback &cb);
    void skip_iframe_bb();

    /* Read one WP chain section from @wpb, returning the populated WP
     * entries.  Used by both handle_entry and handle_iframe.  @state
     * is the per-thread WP overlay; @base_state is the corresponding
     * CP overlay that WP cells fall back into. */
    std::vector<WPEntry> decode_wp_chain(Reader &wpb,
                                         FieldStateTable &state,
                                         const FieldStateTable *base_state);
    /* Read one WP events sub-section, attaching fault /
     * translation_unavailable flags to entries in @wp_entries by
     * index.  Throws when an event index is past the chain length. */
    void decode_wp_events(Reader &evb,
                          std::vector<WPEntry> *wp_entries);

    /* Field-delta record decoder.  Splits into two passes: pass 1
     * applies record deltas to the per-template state block and
     * collects per-entry EXTRA_* vectors; pass 2 walks the template
     * insns and materialises dyn_params / reg_snaps / metaflags /
     * lane_masks. */
    void decode_field_delta(Reader &outer, uint32_t template_id,
                            const Template *tmpl,
                            FieldStateTable &state,
                            const FieldStateTable *base_state,
                            std::vector<DynParam>       *dyn_params,
                            std::vector<RegSnap>        *reg_snaps,
                            std::vector<MetaFlagsEntry> *metaflags,
                            std::vector<LaneMaskEntry>  *lane_masks);

    /* Compute the template-default for FID_INSN_* fields (those whose
     * baseline is the template's static value).  Returns Wide{} for
     * fields that default to zero. */
    Wide template_default(const Template *tmpl,
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
     * EXTENDED returns FIELD_STATE_SLOT_INVALID.  Sized by
     * FID_LUT_SIZE (covers the ULEB-encoded fid space). */
    std::array<uint16_t, FID_LUT_SIZE> slot_lut_{};
    BodyStats stats_;
};

/*
 * Fan a DecodedEntry into per-instance Instructions: CP insns in
 * template order, then each WP entry's insns in chain order.  Per-insn
 * dyn_params / reg_snaps / metaflags are filtered to that insn; branch
 * targets resolved when the trailing insn carries a recognised direct
 * branch immediate.
 */
std::vector<Instruction> instructions_from_entry(
    const DecodedEntry &entry,
    const Header &h,
    const std::vector<Template> &templates,
    const std::unordered_map<uint32_t, size_t> &template_by_id);

}  /* namespace cst */
