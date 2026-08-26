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
 * cosmetic --objdump column, rendered by a binutils objdump child
 * process; disabled at run time when the host has none).  Plain C++17 +
 * a small POSIX set for cst_format.cc; no QEMU/glib.  Consumers can
 * feed the walker from their own byte source via Reader(const
 * uint8_t *, size_t, size_t) and skip the subprocess decompressor.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <functional>
#include <memory>
#include <unordered_map>
#include <utility>

#include "cst_common.h"
#include "cst_format.h"
#include "cst_lint.h"
#include "cst_reader.h"

namespace cst {

/*
 * FieldStateTable storage (mirrors the writer's
 * BodyStreamState::cp_field_state in champsim_tracer_output.cc):
 * blocks indexed by template_id; values is a flat
 * (n_insns * physical stride) Wide array; gens is per-cell
 * generation — a cell "exists" only when gens[idx]==table.generation,
 * so bumping the generation invalidates every cell in O(1).  Replaces
 * an unordered_map<u64,Wide> (~10% of decode time in hash lookups). */
/* FIELD_STATE_SLOT_COUNT is the LOGICAL slot-index space produced by
 * slot_lut_build (the fid -> dense-slot LUT):
 *   3 singletons (N_LOADS, N_STORES, METAFLAGS) + 14 * FID_SLOT_COUNT
 *   slot-major slotted cells (families: load_addr/store_addr/load_data/
 *   store_data/dst_reg/load_size/store_size/dst_reg_width + the 4
 *   lane-mask families + the 2 physical-page families) + 7
 *   insn-metadata singletons + the 2 branch-outcome singletons + the 5
 *   block-level singletons (CST_FID_BB_*, live only at BLOCK_POS).
 *   EXTENDED has no persistent cell.  Bump alongside the writer when
 *   new families are added.  (Kept in step with FS_N_FAMILIES /
 *   FS_SLOTTED_END in cst_decode.cc, which own the same layout.)
 *
 * The PHYSICAL block layout is compacted per FieldStateBlock::max_slots
 * (see cell_read/cell_write in cst_decode.cc): fixed singletons first,
 * then family-major slotted cells with only max_slots cells per family,
 * exactly like the writer's two-plane block.  The logical index is
 * decomposed on access; a slot >= max_slots reads as a miss and grows
 * the block on write. */
inline constexpr size_t  FIELD_STATE_SLOT_COUNT   =
    3 + 14 * FID_SLOT_COUNT + 14;
inline constexpr uint16_t FIELD_STATE_SLOT_INVALID = 0xFFFFu;
/* FID_LUT_SIZE (the reverse index's span over the field-id space) is
 * defined once in cst_common.h and shared by every tool. */
static_assert(FID_LUT_SIZE > FIELD_STATE_SLOT_COUNT,
              "fid LUT must span the whole well-known field-id space");
static_assert(FIELD_STATE_SLOT_COUNT < FIELD_STATE_SLOT_INVALID,
              "logical slot indices must stay distinguishable from the "
              "invalid sentinel");

struct FieldStateBlock {
    /* POSITION capacity: template num_insns + 1 — the extra row is the
     * block's own (BLOCK_POS = num_insns, §5.7), one index past the
     * instruction array the block also spans. */
    uint32_t              n_insns = 0;
    /* Slot occupancy high-water mark, mirroring the writer's
     * FieldStateBlock::max_slots: the physical row holds only
     * max_slots cells per slotted family (grown lazily on the first
     * write to a higher slot), not the full FID_SLOT_COUNT stride.
     * The overwhelmingly common scalar template (<=1 memop / dst reg
     * per insn) stays at 1, which keeps a full-length system-trace
     * decode's field-state footprint ~35x smaller than the eager
     * fixed-stride layout it replaces (which exceeded 20 GiB on a
     * 100M-entry trace and aborted the decode with bad_alloc). */
    uint32_t              max_slots = 1;
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

/* A decoded disk-I/O record (BODY_TAG_DEVIO_START / _STOP), surfaced as
 * the body is walked.  is_start distinguishes the two; for a STOP only
 * request_id is meaningful.
 *
 * thread_id / asid are the owning process/thread.  For an EXACT START
 * (exact == true) they are carried inline on the record — the owner the
 * doorbell captured in the issuing vCPU's context — so attribution does
 * not depend on where the record fell in the interleaved stream.  For a
 * POSITIONAL START (exact == false, and for every STOP) they are the
 * body context in force at the record's stream position.  A STOP inherits
 * its START's owner when the walker has seen that START (surfaced too, so
 * consumers need not join). */
struct DecodedDevio {
    bool     is_start   = false;
    bool     exact      = false;   /* owner carried inline (START only) */
    uint64_t request_id = 0;
    uint8_t  rw         = 0;   /* CST_DEVIO_* (START only) */
    uint64_t bytes      = 0;   /* START only */
    uint64_t block      = 0;   /* disk block number (START only) */
    uint32_t thread_id  = 0;
    uint32_t asid       = 0;
};

/* Structural counts surfaced after walk(), so consumers can
 * sanity-check writer cadence without re-walking the body. */
struct BodyStats {
    uint64_t cp_entries        = 0;
    uint64_t wp_entries        = 0;
    uint64_t iframe_count      = 0;
    uint64_t regfile_count     = 0;
    uint64_t thread_switch_count = 0;
    uint64_t asid_switch_count = 0;
    uint64_t devio_start_count = 0;
    uint64_t devio_stop_count  = 0;
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
    using DevioCallback = std::function<void(const DecodedDevio &)>;

    /* Optional sink for BODY_TAG_DEVIO_START / _STOP records, surfaced
     * positionally by both walk() and walk_bb().  Set before walking. */
    void set_devio_callback(DevioCallback cb) { devio_cb_ = std::move(cb); }

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

    /* Impossible-attribution lint (see cst_lint.h).  Populated on the
     * batch walk() path only — CP entries checked, WP chains and
     * IFRAMEs exempt.  Zero counters on a conformant trace. */
    const AttributionLint &lint() const { return lint_; }

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
     * A WP block's events (fault / translation flags) are block-level
     * field records in its own wp_delta_section (§4.4), surfaced on
     * BB::bb_flags at Fields level like every other cell.  IFRAME
     * records are parse-skipped (no field-content validation on this
     * path). */
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
        /* Address-space (ASID) index this BB executed under; the second
         * half of the (thread_id, asid) context.  Rebased by
         * BODY_TAG_ASID_SWITCH; a WP BB inherits its parent CP entry's
         * asid. */
        uint32_t        asid           = 0;
        uint32_t        seq_num        = 0;   /* CP visit counter; a WP
                                               * BB shares its parent
                                               * CP entry's seq_num. */
        bool            thread_switched = false; /* CP only */
        bool            is_wp          = false;
        uint32_t        wp_index       = 0;   /* position in WP chain */
        bool            wp_chain_start = false;
        bool            wp_chain_last  = false;
        uint32_t        n_insns        = 0;   /* template insn count */
        /* Exception-nesting depth (CST_FID_BB_FAULT_DEPTH block cell):
         * 0 = normal code, >=1 = synchronous-fault handler code at that
         * nesting level.  CP only; populated only when this BB's field
         * deltas were applied (cp_fields / WpDecode::Fields — the cell
         * is delta-persistent, so a parse-skipped section cannot read
         * it honestly). */
        uint32_t        fault_depth    = 0;
        /* Executed range [bb_start, bb_stop) (§4.2a) and the raw
         * CST_FID_BB_FLAGS cell.  Same caveat as fault_depth: honest
         * only when this BB's deltas were applied; a parse-skipped BB
         * reports the whole-block defaults [0, n_insns) and flags 0. */
        uint32_t        bb_start       = 0;
        uint32_t        bb_stop        = 0;
        uint64_t        bb_flags       = 0;

        bool     has_fields() const { return blk_ != nullptr; }
        /* bb_flags bits resolved through the trace's bb_flag map.
         * False when this BB's fields were not decoded (ids_ unset). */
        bool flag_synthetic_fault() const {
            return ids_ && (bb_flags & ids_->bb_flag_synthetic_fault);
        }
        bool flag_translation_unavail() const {
            return ids_ && (bb_flags & ids_->bb_flag_translation_unavail);
        }
        bool flag_wp_first_target_unavail() const {
            return ids_ && (bb_flags & ids_->bb_flag_wp_first_target_unavail);
        }
        bool flag_thread_end() const {
            return ids_ && (bb_flags & ids_->bb_flag_thread_end);
        }
        uint64_t load_count(uint32_t insn) const;
        uint64_t store_count(uint32_t insn) const;
        uint64_t load_addr(uint32_t insn, uint32_t slot) const;
        uint64_t store_addr(uint32_t insn, uint32_t slot) const;
        /* Physical PAGE base of the memop (CST_FLAG_PHYSADDR traces).
         * Reads the running cell exactly like load_addr: 0 means no
         * translation has been observed for this (insn, slot) cell yet
         * (and always 0 on a non-physaddr trace, whose ppage FIDs never
         * resolve).  A memop whose own execution had no observable
         * translation reads the last real translation, per the delta
         * stream's designed omission. */
        uint64_t load_ppage(uint32_t insn, uint32_t slot) const;
        uint64_t store_ppage(uint32_t insn, uint32_t slot) const;
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

    /* There is no side wp_events channel in this epoch: a wrong-path
     * block's events are block-level facts riding its own
     * wp_delta_section (CST_FID_BB_FLAGS / CST_FID_BB_FAULT_INSN at its
     * BLOCK_POS, §4.4), surfaced on BB::bb_flags at WpDecode::Fields
     * and on WPEntry by the batch walk. */

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
    void     handle_asid_switch(WalkState &ws);
    void     handle_regfile(const RegfileCallback &rb);
    /* Disk-I/O record: consumes the DEVIO_START / _STOP payload, bumps
     * stats_, and fires devio_cb_ (if set) with the current context.
     * Shared by walk() and walk_bb(). */
    void     handle_devio(WalkState &ws, bool is_start);
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
    /* Block-level cells read back from a section's BLOCK_POS row after
     * pass 1, with baseline defaults resolved (bb_start 0, bb_stop
     * num_insns, everything else 0).  §5.7's range/position validation
     * happens where these are read. */
    struct BlockCells {
        uint32_t bb_start    = 0;
        uint32_t bb_stop     = 0;
        uint64_t bb_flags    = 0;
        uint32_t fault_depth = 0;
        uint32_t fault_insn  = 0;
    };

    void consume_field_section(Reader &outer, uint32_t template_id,
                               const Template *tmpl,
                               FieldStateTable *state,
                               const FieldStateTable *base_state,
                               BlockCells *bc = nullptr);
    uint64_t stream_wp_chain_bb(Reader &wpb, FieldStateTable &wp_state,
                                FieldStateTable &cp_state, WpDecode wp,
                                uint32_t seq, uint32_t thread, uint32_t asid,
                                const BBCallback &cb,
                                uint64_t *insns = nullptr);
    void handle_entry_bb(WalkState &ws, bool cp_fields, WpDecode wp,
                         const BBCallback &cb);
    void skip_iframe_bb();

    /* Read one WP chain section from @wpb, returning the populated WP
     * entries.  Used by both handle_entry and handle_iframe.  @state
     * is the per-thread WP overlay; @base_state is the corresponding
     * CP overlay that WP cells fall back into.  The section's leading
     * ULEB is the bare block count (Step 6.8) — nothing is packed into
     * it.  Each block's events arrive as its own CST_FID_BB_FLAGS /
     * CST_FID_BB_FAULT_INSN block records (§4.4). */
    std::vector<WPEntry> decode_wp_chain(Reader &wpb,
                                         FieldStateTable &state,
                                         const FieldStateTable *base_state);

    /* Field-delta record decoder.  Splits into two passes: pass 1
     * applies record deltas to the per-template state block and
     * collects per-entry EXTRA_* vectors; pass 2 walks the template
     * insns and materialises dyn_params / reg_snaps / metaflags /
     * lane_masks.  @lint non-null only for CP ENTRY sections: pass 1
     * flags dst-reg records on impossible operand slots, pass 2 flags
     * runtime memop counts on memop-incapable insns. */
    void decode_field_delta(Reader &outer, uint32_t template_id,
                            const Template *tmpl,
                            FieldStateTable &state,
                            const FieldStateTable *base_state,
                            std::vector<DynParam>       *dyn_params,
                            std::vector<RegSnap>        *reg_snaps,
                            std::vector<MetaFlagsEntry> *metaflags,
                            std::vector<LaneMaskEntry>  *lane_masks,
                            AttributionLint             *lint,
                            BranchOutcome               *branch = nullptr,
                            BlockCells                  *bc_out = nullptr);

    /* Compute the template-default for FID_INSN_* fields (those whose
     * baseline is the template's static value) and for CST_FID_BB_STOP
     * (whose baseline is the template's num_insns, §5.7).  Returns
     * Wide{} for fields that default to zero. */
    Wide template_default(const Template *tmpl,
                          uint32_t ipos, uint16_t fid) const;

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
    AttributionLint lint_;
    /* Optional positional sink for disk-I/O records (set_devio_callback). */
    DevioCallback devio_cb_;
    /* request_id -> (thread_id, asid) captured from an EXACT DEVIO_START,
     * so its paired DEVIO_STOP can be surfaced with the same owner. */
    std::unordered_map<uint64_t, std::pair<uint32_t, uint32_t>> devio_owner_;
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
