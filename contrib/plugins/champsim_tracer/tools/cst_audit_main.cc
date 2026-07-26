/*
 * cst_audit — byte-composition auditor for .cst traces.
 *
 * C++ port of cst_audit.py; mirrors that script's report layout and
 * field-delta bucket categorization byte-for-byte.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "cst_format.h"
#include "cst_lint.h"
#include "cst_reader.h"

namespace {

/* Field-delta record bucket indices (parallel to the Python audit). */
enum : int {
    BIDX_OVERHEAD   = 0,
    BIDX_MEM_COUNTS = 1,
    BIDX_LOAD_ADDR  = 2,
    BIDX_STORE_ADDR = 3,
    BIDX_LOAD_DATA  = 4,
    BIDX_STORE_DATA = 5,
    BIDX_DST_REG    = 6,
    BIDX_INSN_META  = 7,
    BIDX_EXTENDED   = 8,
    BIDX_LANE_MASK  = 9,
    BIDX_PHYS_PAGE  = 10,   /* CST_FID_LOAD_PPAGE / STORE_PPAGE (physaddr) */
    BIDX_BRANCH     = 11,   /* CST_FID_BRANCH_TAKEN / _TARGET (always on)  */
    BIDX_OTHER      = 12,
    NUM_BUCKETS     = 13,
};

/* FID -> bucket lookup over the ULEB FID space.  Slotted families
 * come from ResolvedIds' name-resolved per-slot arrays (no stride). */
struct FidTables {
    /* cst_common.h owns the one definition, sized from the wire's slot
     * ceiling, so this index can never fall behind it. */
    static constexpr size_t LUT_SIZE = cst::FID_LUT_SIZE;
    std::array<uint8_t, LUT_SIZE> bucket{};
    /* For FIDs in the dst-register-value family, the per-instruction
     * destination slot index this FID names (so a field-delta record
     * can be charged to the architectural register the template binds
     * to that slot); -1 for every other FID. */
    std::array<int16_t, LUT_SIZE> dst_slot{};

    explicit FidTables(const cst::ResolvedIds &ids) {
        bucket.fill(BIDX_OTHER);
        dst_slot.fill(-1);
        for (int k = 0; k < cst::FID_SLOT_COUNT; k++) {
            uint16_t fid = ids.fid_dst_reg[k];
            if (fid != 0 && fid < LUT_SIZE) dst_slot[fid] = (int16_t)k;
        }
        if (ids.fid_n_loads   < LUT_SIZE) bucket[ids.fid_n_loads]   = BIDX_MEM_COUNTS;
        if (ids.fid_n_stores  < LUT_SIZE) bucket[ids.fid_n_stores]  = BIDX_MEM_COUNTS;
        if (ids.fid_metaflags < LUT_SIZE) bucket[ids.fid_metaflags] = BIDX_INSN_META;

        const struct {
            const cst::FidSlotArray *fids;
            uint8_t bucket_id;
        } fam[11] = {
            { &ids.fid_load_addr,             (uint8_t)BIDX_LOAD_ADDR  },
            { &ids.fid_store_addr,            (uint8_t)BIDX_STORE_ADDR },
            { &ids.fid_load_data,             (uint8_t)BIDX_LOAD_DATA  },
            { &ids.fid_store_data,            (uint8_t)BIDX_STORE_DATA },
            { &ids.fid_dst_reg,               (uint8_t)BIDX_DST_REG    },
            { &ids.fid_src_lane_mask,         (uint8_t)BIDX_LANE_MASK  },
            { &ids.fid_dst_lane_mask,         (uint8_t)BIDX_LANE_MASK  },
            { &ids.fid_load_data_lane_mask,   (uint8_t)BIDX_LANE_MASK  },
            { &ids.fid_store_data_lane_mask,  (uint8_t)BIDX_LANE_MASK  },
            { &ids.fid_load_ppage,            (uint8_t)BIDX_PHYS_PAGE  },
            { &ids.fid_store_ppage,           (uint8_t)BIDX_PHYS_PAGE  },
        };
        for (int k = 0; k < cst::FID_SLOT_COUNT; k++) {
            for (auto &fa : fam) {
                uint16_t fid = (*fa.fids)[k];
                if (fid != 0 && fid < LUT_SIZE) bucket[fid] = fa.bucket_id;
            }
        }
        /* Cold insn-metadata singletons, named explicitly (the wire
         * format doesn't promise they're contiguous). */
        const uint16_t cold_fids[] = {
            ids.fid_insn_bytes_lo, ids.fid_insn_bytes_hi,
            ids.fid_insn_opcode,   ids.fid_insn_branch_type,
            ids.fid_insn_flags,    ids.fid_insn_immediate,
            ids.fid_insn_size,
        };
        for (uint16_t f : cold_fids) {
            if (f < LUT_SIZE) bucket[f] = BIDX_INSN_META;
        }
        if (ids.fid_extended < LUT_SIZE) bucket[ids.fid_extended] = BIDX_EXTENDED;
        /* Branch-outcome singletons (always-on): their own bucket so the
         * direction/target cost is visible separately from "other". */
        if (ids.fid_branch_taken  < LUT_SIZE) bucket[ids.fid_branch_taken]  = BIDX_BRANCH;
        if (ids.fid_branch_target < LUT_SIZE) bucket[ids.fid_branch_target] = BIDX_BRANCH;
    }

    uint8_t bucket_for(unsigned fid) const {
        return fid < LUT_SIZE ? bucket[fid] : (uint8_t)BIDX_OTHER;
    }
};

struct Bucket {
    uint64_t bytes = 0;
    uint64_t count = 0;
};

struct Stats {
    /* On-disk .cst container size.  Informational only — NOT a valid
     * denominator for the uncompressed member sizes below. */
    uint64_t file_size         = 0;
    /* Body member size in the tar (compressed when codec'd, else
     * == body_total). */
    uint64_t body_compressed   = 0;
    std::string body_codec;
    uint64_t header_bytes      = 0;
    uint64_t templates_count   = 0;
    uint64_t body_total        = 0;
    uint64_t body_terminator   = 0;
    uint64_t cp_entries        = 0;
    uint64_t wp_entries_total  = 0;
    uint64_t cp_total_insns    = 0;
    uint64_t wp_total_insns    = 0;

    Bucket cp_entry_framing;
    Bucket cp_field_delta;
    Bucket thread_switch;
    Bucket asid_switch;
    Bucket wp_chain_envelope;
    Bucket wp_entry_framing;
    Bucket wp_field_delta;
    Bucket wp_events;
    uint64_t iframe_count = 0;
    Bucket   iframe_bytes;
    /* BODY_TAG_REGFILE: per-thread initial regfile snapshot,
     * one record per (segment, thread_id). */
    uint64_t regfile_count = 0;
    Bucket   regfile_bytes;
    /* BODY_TAG_DEVIO_START / _STOP: disk-I/O request brackets. */
    Bucket   devio_start;
    Bucket   devio_stop;

    /* Per-bucket detail across CP and WP field-delta streams. */
    std::array<Bucket, NUM_BUCKETS> cp_fd{};
    std::array<Bucket, NUM_BUCKETS> wp_fd{};

    /* Per-architectural-register breakdown of the dest-register-value
     * family (the regdata payload).  Keyed by generic register id; the
     * cp+wp byte sum reconciles exactly with the BIDX_DST_REG bucket.
     * Records whose (template, ipos, slot) can't resolve to a register
     * (missing template, out-of-range slot) land in @reg_unresolved. */
    struct RegBucket { uint64_t cp_bytes = 0, wp_bytes = 0,
                                cp_count = 0, wp_count = 0; };
    std::unordered_map<uint16_t, RegBucket> reg_data;
    RegBucket reg_unresolved;

    /* HEADER member byte breakdown (templates section + preamble). */
    struct HeaderBreakdown {
        uint64_t preamble  = 0;  /* meta fields + encoding-map section */
        uint64_t framing   = 0;  /* tmpl count + per-tmpl length prefix */
        uint64_t bb_info   = 0;  /* id/pc/n_insns/ft/n_targets/targets/sym */
        uint64_t insn_desc = 0;  /* per-insn descriptors (excl. dep block) */
        uint64_t dep_block = 0;  /* optional dependency sub-blocks */
        uint64_t profile   = 0;  /* template profile block (format §6) */
        uint64_t other     = 0;  /* unaccounted residue (should be 0) */
    } hdr;
};

/*
 * Re-walk the header member attributing every byte to a group.
 * Mirrors cst::parse_templates_at field-for-field so the sum
 * reconciles exactly with the HEADER member size (rollup assert in
 * print_report).
 */
void account_header(cst::MemberView hv, const cst::ResolvedIds &ids,
                    Stats::HeaderBreakdown *b)
{
    cst::Reader r(hv.data, 0, hv.size);
    r.u32_le();                       /* magic                       */
    r.u8();                           /* isa                         */
    r.u8();                           /* flags                       */
    r.uleb(); r.uleb(); r.uleb();     /* start / warmup / total      */
    r.u64_le();                       /* simpoint weight             */
    r.string(); r.string();           /* command / datetime          */
    r.string(); r.string();           /* comment / target_name       */
    { cst::Reader maps = r.sub(); (void)maps; }   /* encoding maps    */
    r.uleb();                         /* warmup_end_arch_insns §2.13 */
    b->preamble = r.pos();
    if (r.eof()) {
        return;
    }

    size_t cnt0 = r.pos();
    uint64_t ntmpl = r.uleb();
    b->framing += r.pos() - cnt0;

    for (uint64_t i = 0; i < ntmpl; i++) {
        size_t before = r.pos();
        cst::Reader s = r.sub();
        size_t payload = s.remaining();
        b->framing += (r.pos() - before) - payload;

        size_t p = s.pos();
        s.uleb();                     /* template_id                 */
        s.uleb();                     /* start_pc                    */
        uint64_t n_insns = s.uleb();
        s.uleb();                     /* fall_through_pc             */
        uint64_t n_tgt = s.uleb();
        for (uint64_t k = 0; k < n_tgt; k++) s.uleb();   /* target_pc */
        s.string();                   /* symbol_name                 */
        b->bb_info += s.pos() - p;

        for (uint64_t k = 0; k < n_insns; k++) {
            p = s.pos();
            s.uleb();                 /* pc_delta                    */
            s.u8();                   /* opcode                      */
            s.u8();                   /* branch_type                 */
            uint8_t flags = s.u8();
            uint8_t n_src = s.u8();
            uint8_t n_dst = s.u8();
            for (uint8_t x = 0; x < n_src; x++) s.u8();
            for (uint8_t x = 0; x < n_dst; x++) s.u8();
            uint8_t mdl = s.u8();     /* max_dep_loads               */
            uint8_t mds = s.u8();     /* max_dep_stores              */
            if (flags & ids.insn_flag_has_imm) s.sleb();
            uint8_t isz = s.u8();
            if (isz) { std::vector<uint8_t> t(isz); s.raw(t.data(), isz); }
            b->insn_desc += s.pos() - p;

            if (flags & ids.insn_flag_has_dep_block) {
                p = s.pos();
                uint8_t df = s.u8();
                if (df & ids.dep_block_has_reg) {
                    for (uint8_t d = 0; d < n_dst; d++) s.uleb();
                    for (uint8_t st = 0; st < mds; st++) s.uleb();
                }
                if (df & ids.dep_block_has_addr) {
                    for (uint8_t l = 0; l < mdl; l++) s.uleb();
                    for (uint8_t st = 0; st < mds; st++) s.uleb();
                }
                b->dep_block += s.pos() - p;
            }
        }

        p = s.pos();
        s.uleb(); s.uleb();           /* exec_cp / exec_wp           */
        for (uint64_t k = 0; k < n_tgt; k++) {
            s.uleb(); s.uleb(); s.uleb(); s.uleb();   /* per-target  */
        }
        for (uint64_t k = 0; k < n_insns; k++) {
            uint64_t mcp = s.uleb();
            uint64_t mwp = s.uleb();
            s.u8();                   /* pat_flags                   */
            if (mcp > 0) { s.uleb(); s.uleb(); }
            if (mwp > 0) { s.uleb(); s.uleb(); }
        }
        b->profile += s.pos() - p;
        b->other += s.remaining();    /* should be 0                 */
    }
}

/* Impossible-attribution lint context for one CP field-delta section
 * (cst_lint.h).  Null for WP sections — wrong-path wandering is not
 * held to the CP attribution contract. */
struct LintCtx {
    cst::AttributionLint               *lint;
    cst::AttributionLint::DeltaTracker *tracker;
    const std::vector<uint8_t>         *row;      /* template caps row */
    uint32_t                            thread;
    uint32_t                            template_id;
    uint64_t                            entry_ordinal;  /* debug locator */
    /* Memop bimodality lint (cst_lint.h) — null when disabled
     * (--bimodal-off) or, like @lint above, for WP sections. */
    cst::MemopBimodalityLint           *bimodal;
};

/* Tally one field-delta record's bytes into @fd_b.  Format 0x1D:
 * fid is ULEB128, every record carries a single SLEB_WIDE delta (up
 * to 512 bits) walked by skip_varint (no overflow guard). */
static inline void tally_fd_record(
    cst::Reader &sec, const FidTables &fid, const cst::ResolvedIds &ids,
    std::array<Bucket, NUM_BUCKETS> *fd_b,
    uint32_t *ipos, const cst::Template *tmpl, bool is_wp, Stats *s,
    const LintCtx *lctx)
{
    size_t before = sec.consumed();
    *ipos += (uint32_t)sec.uleb();           /* ipos delta (accumulates) */
    uint64_t f = sec.uleb();                 /* fid (ULEB128) */

    /* Reg-side lint: a dst-reg VALUE record naming an operand slot the
     * template's insn does not carry (or an insn past the template) is
     * an impossible attribution — the writer never emits such records. */
    if (lctx && lctx->row && lctx->lint->reg_check_enabled()) {
        int slot = (f < FidTables::LUT_SIZE) ? fid.dst_slot[f] : -1;
        if (slot >= 0 &&
            (*ipos >= lctx->row->size() ||
             slot >= (int)((*lctx->row)[*ipos] &
                           cst::AttributionLint::N_DST_MASK))) {
            lctx->lint->note_reg(lctx->template_id, *ipos);
        }
    }

    /* Mem-side: an N_LOADS/N_STORES delta feeds two independent trackers
     * that both need the decoded value, so decode once and hand it to
     * whichever wants it — every other record keeps the skip fast path.
     *   - impossible-attribution: only for a delta landing on an insn
     *     whose static max memop counts are both zero (the existing
     *     one-sided lint).
     *   - bimodality (cst_lint.h MemopBimodalityLint): every delta on a
     *     memop-CAPABLE template, regardless of insn position — it
     *     tracks a single running per-template total (see its header
     *     comment for why record presence alone cannot be used). */
    bool is_count_fid = (f == ids.fid_n_loads || f == ids.fid_n_stores);
    bool want_impossible = lctx && lctx->row && is_count_fid &&
        *ipos < lctx->row->size() &&
        ((*lctx->row)[*ipos] & cst::AttributionLint::MEM_IMPOSSIBLE);
    bool want_bimodal = lctx && lctx->bimodal && is_count_fid &&
        lctx->bimodal->tracks(lctx->template_id);
    if (want_impossible || want_bimodal) {
        std::array<uint64_t, 8> wd = sec.sleb_wide();  /* same bytes */
        if (want_impossible) {
            lctx->tracker->on_count_delta(lctx->thread, lctx->template_id,
                                          *ipos, f == ids.fid_n_stores,
                                          wd[0], lctx->entry_ordinal);
        }
        if (want_bimodal) {
            lctx->bimodal->on_count_delta(lctx->thread, lctx->template_id,
                                          wd[0]);
        }
    } else {
        sec.skip_varint();                   /* sleb_wide delta */
    }
    if (f == ids.fid_extended) sec.skip_varint();
    int idx = fid.bucket_for((unsigned)f);
    uint64_t nbytes = sec.consumed() - before;
    (*fd_b)[idx].bytes += nbytes;
    (*fd_b)[idx].count += 1;

    /* Charge dest-register-value records to the architectural register
     * the template binds to this (ipos, slot).  Sums back to the
     * BIDX_DST_REG bucket (resolvable + unresolved). */
    if (idx == BIDX_DST_REG) {
        int slot = (f < FidTables::LUT_SIZE) ? fid.dst_slot[f] : -1;
        Stats::RegBucket *rb = &s->reg_unresolved;
        if (slot >= 0 && tmpl && *ipos < tmpl->insns.size()) {
            const auto &dr = tmpl->insns[*ipos].dst_regs;
            if ((size_t)slot < dr.size()) rb = &s->reg_data[dr[(size_t)slot]];
        }
        if (is_wp) { rb->wp_bytes += nbytes; rb->wp_count += 1; }
        else       { rb->cp_bytes += nbytes; rb->cp_count += 1; }
    }
}

/* Walk the body record stream through a Reader.  Works identically
 * for memory-backed (uncompressed body) and stream-backed
 * (decompressor-piped) inputs; the Reader handles refilling. */
void walk_body(cst::Reader &body, const cst::ResolvedIds &ids,
               uint8_t header_flags,
               const std::unordered_map<uint32_t, uint32_t> &insns_by_tid,
               const std::vector<cst::Template> &templates,
               const std::unordered_map<uint32_t, size_t> &by_id,
               Stats *s, cst::AttributionLint *lint,
               cst::MemopBimodalityLint *bimodal /* nullptr disables it */)
{
    const bool have_wp = (header_flags & ids.flag_wp) != 0;
    const bool have_fault = (ids.flag_fault != 0) &&
                            (header_flags & ids.flag_fault) != 0;
    const FidTables fid(ids);
    auto tmpl_for = [&](int32_t tid) -> const cst::Template * {
        auto it = by_id.find((uint32_t)tid);
        return it != by_id.end() ? &templates[it->second] : nullptr;
    };
    int32_t prev_cp_tid = 0;
    auto &cpfd_b = s->cp_fd;
    auto &wpfd_b = s->wp_fd;

    /* Impossible-attribution lint over the CP stream.  The count
     * cells are per-guest-thread writer state, so mirror the
     * decoder's thread tracking off the THREAD_SWITCH records. */
    cst::AttributionLint::DeltaTracker tracker(*lint);
    int32_t current_thread = 0;
    /* ASID index tracking mirrors the decoder: the inline identity
     * (root_phys + sig) rides an index's FIRST sighting only. */
    int32_t current_asid = 0;
    std::vector<bool> seen_asids;

    while (!body.eof()) {
        size_t tag_start = body.consumed();
        uint8_t tag = body.u8();

        if (tag == ids.body_tag_entry) {
            int64_t tdelta = body.sleb();
            prev_cp_tid += (int32_t)tdelta;
            s->cp_entry_framing.bytes += body.consumed() - tag_start;
            s->cp_entries++;
            if (prev_cp_tid >= 0) {
                auto it = insns_by_tid.find((uint32_t)prev_cp_tid);
                if (it != insns_by_tid.end()) {
                    s->cp_total_insns += it->second;
                }
            }

            /* CP field-delta section.  Account the length prefix by
             * subtracting payload size (captured via remaining()
             * before any read) from the parent's consumed delta.
             * NOTE: must use remaining(), not sec.end() — for
             * mem-backed subs end() is the absolute offset, not
             * payload size, and the subtraction underflows. */
            /* Decode the length-prefixed section IN PLACE — no sub-reader,
             * no copy.  Derive the same byte split (overhead = prefix +
             * framing, payload = section bytes) from the length, and assert
             * exact consumption instead of the old sub-reader eof(). */
            size_t sec_in_start = body.consumed();
            uint64_t sec_payload = body.uleb();
            cst::Reader &sec = body;
            size_t sec_end = sec.consumed() + sec_payload;
            size_t sec_total = (sec.consumed() - sec_in_start) + sec_payload;
            s->cp_field_delta.bytes += sec_total;
            cpfd_b[BIDX_OVERHEAD].bytes += sec_total - sec_payload;
            cpfd_b[BIDX_OVERHEAD].count += 1;

            size_t rec_st = sec.consumed();
            uint64_t n_records = sec.uleb();
            cpfd_b[BIDX_OVERHEAD].bytes += sec.consumed() - rec_st;
            cpfd_b[BIDX_OVERHEAD].count += 1;

            const cst::Template *cp_tmpl = tmpl_for(prev_cp_tid);
            /* Dangling-template-ref lint (cst_lint.h): a CP ENTRY
             * naming an id the templates section never defined. */
            if (!cp_tmpl) {
                lint->note_dangling((uint32_t)prev_cp_tid,
                                    /*is_wp=*/false);
            }
            LintCtx lctx = {
                lint, &tracker, lint->row((uint32_t)prev_cp_tid),
                (uint32_t)current_thread, (uint32_t)prev_cp_tid,
                s->cp_entries, bimodal,
            };
            uint32_t cp_ipos = 0;
            for (uint64_t r = 0; r < n_records; r++) {
                tally_fd_record(sec, fid, ids, &cpfd_b,
                                &cp_ipos, cp_tmpl, /*is_wp=*/false, s,
                                &lctx);
            }
            if (sec.consumed() != sec_end) {
                throw std::runtime_error("CP field-delta had trailing bytes");
            }
            /* Per-entry lint accounting: counts are persistent cells,
             * so a violating insn stays violating on every subsequent
             * entry of its template until a delta zeroes it — matching
             * what the decoder's resolved cells would report. */
            tracker.on_cp_entry_end((uint32_t)current_thread,
                                    (uint32_t)prev_cp_tid);

            /* Per-entry sync-fault trailer (CST_FLAG_FAULT): exception-nesting
             * depth ULEB, between the CP delta and the WP sections.  Charge
             * its bytes to CP-field-delta overhead so the budget rolls to
             * 100%. */
            uint64_t cp_fault_anchors = 0;
            if (have_fault) {
                size_t ft_st = body.consumed();
                (void)body.uleb();                  /* fault depth */
                uint64_t n_anchors = body.uleb();   /* anchor count */
                cp_fault_anchors = n_anchors;
                for (uint64_t a = 0; a < n_anchors; a++) {
                    (void)body.uleb();
                }
                size_t ft_bytes = body.consumed() - ft_st;
                s->cp_field_delta.bytes += ft_bytes;
                cpfd_b[BIDX_OVERHEAD].bytes += ft_bytes;
                cpfd_b[BIDX_OVERHEAD].count += 1;
            }

            /* Bimodality histogram: this execution's realised-memop
             * verdict (its running total, after this entry's own deltas)
             * folds into the template's zero/nonzero tally.  Folded only
             * AFTER the fault trailer is read, because an entry carrying
             * fault anchors was truncated mid-template and is excluded
             * from the population — see MemopBimodalityLint. */
            if (bimodal) {
                bimodal->on_cp_entry_end((uint32_t)current_thread,
                                         (uint32_t)prev_cp_tid,
                                         /*fault_truncated=*/
                                         cp_fault_anchors > 0);
            }

            /* WP chain + events present only under CST_FLAG_WP. */
            if (!have_wp) {
                continue;
            }

            /* WP chain envelope — decoded in place (no sub-reader). */
            size_t wp_in_start = body.consumed();
            uint64_t wp_env_payload = body.uleb();
            cst::Reader &wpb = body;
            size_t wp_env_end = wpb.consumed() + wp_env_payload;
            s->wp_chain_envelope.bytes +=
                (wpb.consumed() - wp_in_start) + wp_env_payload;

            /* Chain header (format.rst Step 6.8): num_wp packed with the
             * CST_WP_CHAIN_HAS_EVENTS bit that announces whether a
             * wp_events_section follows this entry on the wire. */
            uint64_t chain_hdr = wpb.uleb();
            uint64_t num_wp = chain_hdr >> 1;
            bool has_wp_events = (chain_hdr & ids.wp_chain_has_events) != 0;
            int32_t prev_wp_tid = 0;
            for (uint64_t w = 0; w < num_wp; w++) {
                size_t wfs = wpb.consumed();
                int64_t wd = wpb.sleb();
                prev_wp_tid += (int32_t)wd;
                s->wp_entry_framing.bytes += wpb.consumed() - wfs;
                s->wp_entry_framing.count += 1;
                if (prev_wp_tid >= 0) {
                    auto it = insns_by_tid.find((uint32_t)prev_wp_tid);
                    if (it != insns_by_tid.end()) {
                        s->wp_total_insns += it->second;
                    }
                }

                size_t wp_sec_in = wpb.consumed();
                uint64_t wp_sec_payload = wpb.uleb();
                cst::Reader &wpsec = wpb;
                size_t wp_sec_end = wpsec.consumed() + wp_sec_payload;
                size_t wp_sec_total =
                    (wpsec.consumed() - wp_sec_in) + wp_sec_payload;
                s->wp_field_delta.bytes += wp_sec_total;
                wpfd_b[BIDX_OVERHEAD].bytes += wp_sec_total - wp_sec_payload;
                wpfd_b[BIDX_OVERHEAD].count += 1;

                size_t wp_rec_st = wpsec.consumed();
                uint64_t wp_nrec = wpsec.uleb();
                wpfd_b[BIDX_OVERHEAD].bytes += wpsec.consumed() - wp_rec_st;
                wpfd_b[BIDX_OVERHEAD].count += 1;
                const cst::Template *wp_tmpl = tmpl_for(prev_wp_tid);
                /* Dangling-template-ref lint: id 0 is the writer's
                 * "no template" sentinel, every other id must resolve. */
                if (!wp_tmpl && prev_wp_tid != 0) {
                    lint->note_dangling((uint32_t)prev_wp_tid,
                                        /*is_wp=*/true);
                }
                uint32_t wp_ipos = 0;
                for (uint64_t r = 0; r < wp_nrec; r++) {
                    tally_fd_record(wpsec, fid, ids, &wpfd_b,
                                    &wp_ipos, wp_tmpl, /*is_wp=*/true, s,
                                    /*lctx=*/nullptr);
                }
                if (wpsec.consumed() != wp_sec_end) {
                    throw std::runtime_error("WP field-delta had trailing bytes");
                }
            }
            s->wp_entries_total += num_wp;
            if (wpb.consumed() != wp_env_end) {
                throw std::runtime_error("WP chain had trailing bytes");
            }

            /* WP events sub-section: opaque to audit — skip in place.
             * Entirely absent from the wire (no length prefix) unless
             * the chain header's HAS_EVENTS bit, just decoded above,
             * announced one. */
            if (has_wp_events) {
                size_t ev_in = body.consumed();
                uint64_t ev_payload = body.uleb();
                body.skip(ev_payload);
                s->wp_events.bytes += body.consumed() - ev_in;
            }
            continue;
        }

        if (tag == ids.body_tag_thread_switch) {
            current_thread += (int32_t)body.sleb();   /* signed delta */
            s->thread_switch.bytes += body.consumed() - tag_start;
            s->thread_switch.count += 1;
            continue;
        }

        if (tag == ids.body_tag_asid_switch) {
            current_asid += (int32_t)body.sleb();     /* signed delta */
            if (current_asid >= 0) {
                if ((size_t)current_asid >= seen_asids.size()) {
                    seen_asids.resize((size_t)current_asid + 1, false);
                }
                if (!seen_asids[current_asid]) {
                    (void)body.u64_le();              /* root_phys */
                    (void)body.u64_le();              /* sig       */
                    seen_asids[current_asid] = true;
                }
            }
            s->asid_switch.bytes += body.consumed() - tag_start;
            s->asid_switch.count += 1;
            continue;
        }

        if (tag == ids.body_tag_iframe) {
            { uint64_t n = body.uleb(); body.skip(n); }   /* cp delta section */
            if (have_fault) {
                (void)body.uleb();                        /* fault depth      */
                uint64_t na = body.uleb();                /* anchor count     */
                for (uint64_t a = 0; a < na; a++) {
                    (void)body.uleb();
                }
            }
            if (have_wp) {
                /* wp chain: peek the leading chain_hdr ULEB (packs
                 * num_wp with CST_WP_CHAIN_HAS_EVENTS) before skipping
                 * the rest of the section's payload. */
                bool has_wp_events = false;
                {
                    uint64_t n = body.uleb();
                    size_t chain_end = body.consumed() + n;
                    uint64_t chain_hdr = body.uleb();
                    has_wp_events = (chain_hdr & ids.wp_chain_has_events) != 0;
                    body.skip_to_consumed(chain_end);
                }
                /* wp events: entirely absent unless has_wp_events. */
                if (has_wp_events) {
                    uint64_t n = body.uleb(); body.skip(n);
                }
            }
            s->iframe_count++;
            s->iframe_bytes.bytes += body.consumed() - tag_start;
            continue;
        }

        if (tag == ids.body_tag_regfile) {
            (void)body.uleb();                  /* thread_id */
            uint64_t n_regs = body.uleb();
            for (uint64_t i = 0; i < n_regs; i++) {
                (void)body.u8();                /* gen_id */
                uint8_t width = body.u8();
                uint8_t scratch[256];
                while (width > 0) {
                    size_t take = std::min<size_t>(width, sizeof(scratch));
                    body.raw(scratch, take);
                    width = (uint8_t)(width - take);
                }
            }
            s->regfile_count++;
            s->regfile_bytes.bytes += body.consumed() - tag_start;
            continue;
        }

        if (tag == ids.body_tag_devio_start) {
            (void)body.uleb();               /* request_id */
            (void)body.u8();                 /* rw         */
            (void)body.uleb();               /* bytes      */
            (void)body.uleb();               /* block      */
            uint8_t attr = body.u8();        /* attribution */
            if (attr == CST_DEVIO_ATTR_EXACT) {
                (void)body.uleb();           /* owner_thread_id */
                (void)body.uleb();           /* owner_asid      */
            }
            s->devio_start.bytes += body.consumed() - tag_start;
            s->devio_start.count += 1;
            continue;
        }

        if (tag == ids.body_tag_devio_stop) {
            (void)body.uleb();               /* request_id */
            s->devio_stop.bytes += body.consumed() - tag_start;
            s->devio_stop.count += 1;
            continue;
        }

        if (tag == ids.body_tag_end) {
            body.uleb();                     /* num_entries */
            s->body_terminator = body.consumed() - tag_start;
            break;
        }

        throw std::runtime_error("unknown body tag");
    }

    s->cp_entry_framing.count = s->cp_entries;
    s->cp_field_delta.count = s->cp_entries;
    s->wp_chain_envelope.count = s->cp_entries;
    s->wp_field_delta.count = s->wp_entries_total;
    s->wp_events.count = s->cp_entries;
    s->iframe_bytes.count = s->iframe_count;
    s->regfile_bytes.count = s->regfile_count;
}

/* ===== Output formatting ===== */

std::string human(double n)
{
    char buf[32];
    if (n < 1024.0) { std::snprintf(buf, sizeof(buf), "%d B", (int)n); return buf; }
    static const char *units[] = {"KiB", "MiB", "GiB", "TiB", "PiB"};
    for (auto u : units) {
        n /= 1024.0;
        if (n < 1024.0) {
            std::snprintf(buf, sizeof(buf), "%.2f %s", n, u);
            return buf;
        }
    }
    std::snprintf(buf, sizeof(buf), "%.2f PiB", n);
    return buf;
}

/* Format a long integer with thousands separators (en_US locale-style). */
std::string fmt_n(uint64_t v)
{
    char raw[32];
    int len = std::snprintf(raw, sizeof(raw), "%llu", (unsigned long long)v);
    std::string out;
    int g = ((len - 1) % 3) + 1;
    for (int i = 0; i < len; i++) {
        if (i > 0 && (i - g) % 3 == 0) out.push_back(',');
        out.push_back(raw[i]);
    }
    return out;
}

/* Shared label column width; must be >= the longest label (42 chars)
 * so every value/percent column lines up. */
static constexpr int LABEL_W = 42;

std::string row(const std::string &label, uint64_t b, uint64_t total,
                uint64_t count = 0, const char *per = nullptr)
{
    double pct = total ? 100.0 * b / total : 0.0;
    char buf[256];
    std::string lbl = label;
    if (lbl.size() < (size_t)LABEL_W) lbl.resize(LABEL_W, ' ');
    std::string hb = human((double)b);
    if (count) {
        std::snprintf(buf, sizeof(buf),
                      "  %s %14s  %6.2f%%  [%10s %s, avg %6.1f B]",
                      lbl.c_str(), hb.c_str(), pct,
                      fmt_n(count).c_str(),
                      per ? per : "evt",
                      (double)b / count);
    } else {
        std::snprintf(buf, sizeof(buf), "  %s %14s  %6.2f%%",
                      lbl.c_str(), hb.c_str(), pct);
    }
    return buf;
}

/*
 * Oracle 1 surface — the plugin's own dropped-slice accounting.
 *
 * "CP reg-snap slice dropped" / "CP reg-snap leak trimmed" (Stats in
 * champsim_tracer_stats.h, printed by append_stats_summary) are a
 * completeness invariant the plugin already computes at trace-generation
 * time but does not put on the wire: a positional reg-snap shortfall the
 * seal walk could not recover is counted as "dropped" (its entry's whole
 * reg-data section is discarded rather than mis-sliced onto the wrong
 * insn); a leaked prefix the walk COULD recover by trimming is counted as
 * "trimmed", separately.  On a conformant run these two counters are
 * equal — every genuine shortfall is either a recoverable leak (trimmed)
 * or an unrecoverable drop the counter itself accounts for; the invariant
 * this audit checks is `dropped == trimmed`, not "both zero" (a busy
 * fault-storm trace can legitimately trim many leaked prefixes while
 * dropping none of them, and vice versa on a run with an upstream bug
 * feeding it bad data — the shape that matters is that the two counters
 * reconcile, mirroring how the byte-budget rollup above reconciles what
 * IS on the wire; this is the same reconciliation applied to what the
 * plugin observed but chose not to serialise).
 *
 * The counters live only in the plugin's own `<outfile>.stats.log`
 * sidecar (or the equivalent stderr report) — never on the wire, so a
 * pure trace-file reader cannot recover them after the fact.  This is
 * the offline half of the gate the validator enforces at run time
 * (champsim_tracer_validator._full, features.reg_snap_accounting):
 * passing --stats-log (or letting cst_audit auto-detect the sidecar next
 * to the trace) lets an offline consumer, with both files in hand, see
 * the same numbers and the same verdict cst_audit's exit code reflects.
 */
struct CompletenessStats {
    bool     present  = false;
    uint64_t dropped  = 0;
    uint64_t trimmed  = 0;
};

CompletenessStats read_completeness_stats(const std::string &path)
{
    CompletenessStats out;
    FILE *f = std::fopen(path.c_str(), "r");
    if (!f) return out;
    char line[512];
    static const char *kDropped = "CP reg-snap slice dropped";
    static const char *kTrimmed = "CP reg-snap leak trimmed";
    bool saw_dropped = false, saw_trimmed = false;
    while (std::fgets(line, sizeof(line), f)) {
        unsigned long long v;
        size_t dn = std::strlen(kDropped), tn = std::strlen(kTrimmed);
        if (std::strncmp(line, kDropped, dn) == 0 &&
            std::sscanf(line + dn, "%llu", &v) == 1) {
            out.dropped = v;
            saw_dropped = true;
        } else if (std::strncmp(line, kTrimmed, tn) == 0 &&
                   std::sscanf(line + tn, "%llu", &v) == 1) {
            out.trimmed = v;
            saw_trimmed = true;
        }
    }
    std::fclose(f);
    /* Cumulative totals (the section this audit wants) are the LAST
     * occurrence in the file: the plugin prints a per-segment summary at
     * every segment close plus one final "Cumulative" summary at exit,
     * so later occurrences supersede earlier ones — exactly like
     * re-reading a running counter.  The loop above already keeps
     * overwriting @out with each match, so it naturally lands on the
     * last (cumulative) one. */
    out.present = saw_dropped && saw_trimmed;
    return out;
}

/* Auto-detect the sidecar beside @trace_path: the plugin names it
 * `<outfile>.stats.log`, where `<outfile>` is the SAME basename the
 * `.cst` itself was derived from (quickstart.rst, `outfile=` — a
 * trailing `.cst` on the user's basename is stripped before either
 * suffix is appended).  So for the common non-simpoint case, stripping
 * the trace's own `.cst` suffix and appending `.stats.log` recovers it
 * exactly.  Simpoint mode's `<basename>-<positionB>.cst` segment files
 * do NOT map back to the shared `.stats.log` this way (the position
 * suffix has no fixed un-delimiting rule) — pass --stats-log explicitly
 * in that case. */
std::string default_stats_log_path(const std::string &trace_path)
{
    std::string p = trace_path;
    static const char kSuffix[] = ".cst";
    size_t sn = sizeof(kSuffix) - 1;
    if (p.size() >= sn && p.compare(p.size() - sn, sn, kSuffix) == 0) {
        p.resize(p.size() - sn);
    }
    return p + ".stats.log";
}

std::string fd_row(const std::string &label, const Bucket &cp,
                   const Bucket &wp, uint64_t total)
{
    uint64_t b = cp.bytes + wp.bytes;
    uint64_t count = cp.count + wp.count;
    double pct = total ? 100.0 * b / total : 0.0;
    double avg = count ? (double)b / count : 0.0;
    char buf[512];
    std::string lbl = label;
    if (lbl.size() < 20) lbl.resize(20, ' ');
    std::snprintf(buf, sizeof(buf),
                  "  %s %12s  %6.2f%%  cp=%10s  wp=%10s  [%10s rec, avg %5.1f B]",
                  lbl.c_str(), human((double)b).c_str(), pct,
                  human((double)cp.bytes).c_str(),
                  human((double)wp.bytes).c_str(),
                  fmt_n(count).c_str(), avg);
    return buf;
}

void print_report(const Stats &s, const cst::Header &h)
{
    /* Member sizes are uncompressed, so the 100% anchor MUST be the
     * uncompressed total, not the on-disk container size (else
     * codec'd traces show >100%). */
    uint64_t total = s.header_bytes + s.body_total;

    std::printf("=== ON DISK ===\n");
    std::printf("  %-*s %14s\n", LABEL_W, "container (.cst)",
                human((double)s.file_size).c_str());
    if (!s.body_codec.empty()) {
        double ratio = s.body_compressed
                     ? (double)s.body_total / (double)s.body_compressed
                     : 0.0;
        char note[64];
        std::snprintf(note, sizeof(note), "body member (%s)",
                      s.body_codec.c_str());
        std::printf("  %-*s %14s  %.2fx vs uncompressed body\n",
                    LABEL_W, note,
                    human((double)s.body_compressed).c_str(), ratio);
    }

    std::printf("\n=== MEMBER SIZES (uncompressed) ===\n");
    std::printf("  %-*s %14s  100.00%%\n", LABEL_W, "TOTAL uncompressed",
                human((double)total).c_str());
    std::printf("%s\n", row("HEADER member", s.header_bytes, total,
                             s.templates_count, "tmpl").c_str());
    std::printf("%s\n", row("BODY member (records)", s.body_total, total).c_str());

    const Stats::HeaderBreakdown &hb = s.hdr;
    uint64_t hb_sum = hb.preamble + hb.framing + hb.bb_info +
                      hb.insn_desc + hb.dep_block + hb.profile + hb.other;
    std::printf("\n=== HEADER BREAKDOWN (%s) ===\n",
                human((double)s.header_bytes).c_str());
    std::printf("%s\n", row("preamble + encoding maps",
                             hb.preamble, s.header_bytes).c_str());
    std::printf("%s\n", row("section framing (counts+lengths)",
                             hb.framing, s.header_bytes).c_str());
    std::printf("%s\n", row("BB info (id/pc/n/ft/targets/sym)",
                             hb.bb_info, s.header_bytes,
                             s.templates_count, "tmpl").c_str());
    std::printf("%s\n", row("instruction descriptors",
                             hb.insn_desc, s.header_bytes,
                             s.templates_count, "tmpl").c_str());
    std::printf("%s\n", row("dependency sub-blocks",
                             hb.dep_block, s.header_bytes,
                             s.templates_count, "tmpl").c_str());
    std::printf("%s\n", row("template profile block",
                             hb.profile, s.header_bytes,
                             s.templates_count, "tmpl").c_str());
    if (hb.other) {
        std::printf("%s\n", row("UNACCOUNTED (should be 0)",
                                 hb.other, s.header_bytes).c_str());
    }
    std::printf("%s  [rollup %.2f%%]\n",
                row("  sum", hb_sum, s.header_bytes).c_str(),
                s.header_bytes ? 100.0 * hb_sum / s.header_bytes : 0.0);

    uint64_t body = s.body_total;
    std::printf("\n=== BODY BREAKDOWN (%s) ===\n", human((double)body).c_str());
    std::printf("%s\n", row("CP entry framing",
                             s.cp_entry_framing.bytes, body,
                             s.cp_entries, "entry").c_str());
    std::printf("%s\n", row("CP field-delta section",
                             s.cp_field_delta.bytes, body,
                             s.cp_entries, "entry").c_str());
    std::printf("%s\n", row("thread-switch records",
                             s.thread_switch.bytes, body,
                             s.thread_switch.count, "switch").c_str());
    std::printf("%s\n", row("asid-switch records",
                             s.asid_switch.bytes, body,
                             s.asid_switch.count, "switch").c_str());
    std::printf("%s\n", row("WP chain envelope (incl. inner)",
                             s.wp_chain_envelope.bytes, body,
                             s.cp_entries, "entry").c_str());
    std::printf("    expanded:\n");
    std::printf("%s\n", row("    WP entry framing",
                             s.wp_entry_framing.bytes, body,
                             s.wp_entry_framing.count, "WP").c_str());
    std::printf("%s\n", row("    WP field-delta section",
                             s.wp_field_delta.bytes, body,
                             s.wp_entries_total, "WP").c_str());
    std::printf("%s\n", row("WP events", s.wp_events.bytes, body,
                             s.cp_entries, "entry").c_str());
    std::printf("%s\n", row("IFRAME records (validation redundancy)",
                             s.iframe_bytes.bytes, body,
                             s.iframe_count, "iframe").c_str());
    std::printf("%s\n", row("REGFILE records (per-thread initial state)",
                             s.regfile_bytes.bytes, body,
                             s.regfile_count, "regfile").c_str());
    std::printf("%s\n", row("DEVIO START records (disk request issue)",
                             s.devio_start.bytes, body,
                             s.devio_start.count, "req").c_str());
    std::printf("%s\n", row("DEVIO STOP records (disk request complete)",
                             s.devio_stop.bytes, body,
                             s.devio_stop.count, "req").c_str());
    std::printf("%s\n", row("BODY terminator", s.body_terminator, body).c_str());

    uint64_t fd_total = s.cp_field_delta.bytes + s.wp_field_delta.bytes;
    std::printf("\n=== FIELD-DELTA RECORD BREAKDOWN (%s) ===\n",
                human((double)fd_total).c_str());
    static const struct { const char *label; int idx; } rows[] = {
        {"section overhead",     BIDX_OVERHEAD},
        {"memop counts",         BIDX_MEM_COUNTS},
        {"load addresses",       BIDX_LOAD_ADDR},
        {"store addresses",      BIDX_STORE_ADDR},
        {"load data",            BIDX_LOAD_DATA},
        {"store data",           BIDX_STORE_DATA},
        {"dest registers",       BIDX_DST_REG},
        {"instruction metadata", BIDX_INSN_META},
        {"extended",             BIDX_EXTENDED},
        {"lane masks",           BIDX_LANE_MASK},
        {"physical pages",       BIDX_PHYS_PAGE},
        {"branch outcome",       BIDX_BRANCH},
        {"other",                BIDX_OTHER},
    };
    for (auto &r : rows) {
        std::printf("%s\n", fd_row(r.label, s.cp_fd[r.idx], s.wp_fd[r.idx],
                                    fd_total).c_str());
    }

    /* Per-register split of the dest-register-value family (regdata).
     * Empty unless the trace carried regdata; sorted by total bytes so
     * the registers blowing up the trace surface first. */
    uint64_t dstreg_total = s.cp_fd[BIDX_DST_REG].bytes +
                            s.wp_fd[BIDX_DST_REG].bytes;
    if (dstreg_total || !s.reg_data.empty()) {
        std::printf("\n=== REGISTER-DATA BREAKDOWN "
                    "(dest-register values, per architectural register) ===\n");
        std::vector<std::pair<uint16_t, Stats::RegBucket>> regs(
            s.reg_data.begin(), s.reg_data.end());
        std::sort(regs.begin(), regs.end(),
                  [](const auto &a, const auto &b) {
                      uint64_t ta = a.second.cp_bytes + a.second.wp_bytes;
                      uint64_t tb = b.second.cp_bytes + b.second.wp_bytes;
                      if (ta != tb) return ta > tb;
                      return a.first < b.first;   /* stable tiebreak */
                  });
        uint64_t roll = 0;
        for (const auto &pr : regs) {
            const Stats::RegBucket &rb = pr.second;
            Bucket cp{rb.cp_bytes, rb.cp_count};
            Bucket wp{rb.wp_bytes, rb.wp_count};
            roll += rb.cp_bytes + rb.wp_bytes;
            std::printf("%s\n", fd_row(cst::reg_name_or_unknown(h, pr.first),
                                       cp, wp, dstreg_total).c_str());
        }
        if (s.reg_unresolved.cp_bytes || s.reg_unresolved.wp_bytes) {
            Bucket cp{s.reg_unresolved.cp_bytes, s.reg_unresolved.cp_count};
            Bucket wp{s.reg_unresolved.wp_bytes, s.reg_unresolved.wp_count};
            roll += s.reg_unresolved.cp_bytes + s.reg_unresolved.wp_bytes;
            std::printf("%s\n", fd_row("(unresolved)", cp, wp,
                                       dstreg_total).c_str());
        }
        std::printf("  %-20s %12s  [rollup %.2f%% of dest-register bucket]\n",
                    "sum", human((double)roll).c_str(),
                    dstreg_total ? 100.0 * roll / dstreg_total : 100.0);
    }

    std::printf("\n=== ENTRIES & INSNS ===\n");
    std::printf("  CP entries           %14s\n", fmt_n(s.cp_entries).c_str());
    std::printf("  WP entries (total)   %14s\n", fmt_n(s.wp_entries_total).c_str());
    std::printf("  CP insns (total)     %14s\n", fmt_n(s.cp_total_insns).c_str());
    std::printf("  WP insns (total)     %14s\n", fmt_n(s.wp_total_insns).c_str());
    if (s.cp_total_insns) {
        std::printf("  bytes / CP insn      %14.2f\n",
                    (double)body / s.cp_total_insns);
    }
    uint64_t all_insns = s.cp_total_insns + s.wp_total_insns;
    if (all_insns) {
        std::printf("  bytes / any insn     %14.2f\n",
                    (double)body / all_insns);
    }
    if (s.cp_entries) {
        std::printf("  WPs / CP entry       %14.2f\n",
                    (double)s.wp_entries_total / s.cp_entries);
    }
}

}  /* namespace */

static void usage(const char *argv0)
{
    std::fprintf(stderr,
        "usage: %s [options] <trace.cst>\n"
        "  --stats-log=PATH          plugin sidecar for the completeness\n"
        "                            check (Oracle 1); default: auto-detect\n"
        "                            <trace-without-.cst>.stats.log beside\n"
        "                            the trace\n"
        "  --no-stats-log            skip the completeness check even if a\n"
        "                            sidecar is auto-detected\n"
        "  --bimodal-off             skip the memop bimodality lint (Oracle 2)\n"
        "  --bimodal-min-execs=N     min CP executions before a template's\n"
        "                            zero-rate is judged (default 8)\n"
        "  --bimodal-max-outlier-rate=F   zero-memop executions at or below\n"
        "                            this fraction of total are flagged as\n"
        "                            outliers (default 0.10)\n",
        argv0);
}

int main(int argc, char **argv)
{
    const char *trace_path = nullptr;
    std::string stats_log_path;
    bool stats_log_explicit = false;
    bool no_stats_log = false;
    bool bimodal_off = false;
    cst::MemopBimodalityLint::Config bimodal_cfg;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto val_after = [&](const std::string &prefix) -> const char * {
            return a.c_str() + prefix.size();
        };
        if (a.rfind("--stats-log=", 0) == 0) {
            stats_log_path = val_after("--stats-log=");
            stats_log_explicit = true;
        } else if (a == "--no-stats-log") {
            no_stats_log = true;
        } else if (a == "--bimodal-off") {
            bimodal_off = true;
        } else if (a.rfind("--bimodal-min-execs=", 0) == 0) {
            bimodal_cfg.min_execs =
                (uint32_t)std::strtoul(val_after("--bimodal-min-execs="),
                                       nullptr, 10);
        } else if (a.rfind("--bimodal-max-outlier-rate=", 0) == 0) {
            bimodal_cfg.max_outlier_rate =
                std::strtod(val_after("--bimodal-max-outlier-rate="),
                           nullptr);
        } else if (a == "-h" || a == "--help") {
            usage(argv[0]);
            return 0;
        } else if (!a.empty() && a[0] == '-') {
            std::fprintf(stderr, "cst_audit: unrecognized option: %s\n",
                         a.c_str());
            usage(argv[0]);
            return 2;
        } else if (!trace_path) {
            trace_path = argv[i];
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!trace_path) {
        usage(argv[0]);
        return 2;
    }
    if (!stats_log_explicit && !no_stats_log) {
        stats_log_path = default_stats_log_path(trace_path);
    }

    try {
        /* cst_file_open resolves both tar members + decompresses. */
        std::unique_ptr<cst::CstFile> cf = cst::cst_file_open(trace_path);

        struct stat st;
        if (::stat(trace_path, &st) != 0) {
            throw std::runtime_error("stat failed");
        }

        std::vector<cst::Template> templates;
        std::unordered_map<uint32_t, size_t> by_id;
        cst::Header h = cst::parse_header(cf->header(), &templates, &by_id);

        /* Stream the body records through a Reader (decompressor
         * subprocess for codec'd bodies, mmap view otherwise).
         * Streaming avoids materialising the whole decompressed
         * body in RAM. */
        auto body_stream = cst::body_stream_open(*cf);

        Stats s;
        s.file_size = (size_t)st.st_size;
        s.body_compressed = cf->body_raw().size;
        s.body_codec = cf->body_codec();
        s.header_bytes = cf->header().size;
        s.templates_count = templates.size();
        account_header(cf->header(), h.ids, &s.hdr);

        /* Key by the producer-assigned template_id, NOT vector
         * position: ids are read verbatim and aren't dense/ordered
         * (matches the decoder's by_id resolution).  A by-position
         * lookup mis-maps entries and drops any id past the count. */
        std::unordered_map<uint32_t, uint32_t> insns_by_tid;
        insns_by_tid.reserve(templates.size());
        uint64_t prof_exec_cp = 0, prof_exec_wp = 0;
        uint64_t prof_memop_insns = 0, prof_addr_insns = 0;
        uint64_t prof_pat[4] = {0, 0, 0, 0};
        /* Self-modifying-code revision tally (smc_plan.md §1.5): templates are
         * id-keyed, so an SMC revision is a second (or later) template sharing
         * one start_pc.  Count them and the distinct pcs that carry >1.
         * (The overflow event is a plugin-side stat only — no wire bit — so it
         * is not recoverable here; a start_pc holding exactly the configured
         * cap is the on-wire hint, reported by the plugin's own stats.) */
        std::unordered_map<uint64_t, uint32_t> tmpls_by_start_pc;
        tmpls_by_start_pc.reserve(templates.size());
        for (const auto &t : templates) {
            insns_by_tid[t.template_id] = (uint32_t)t.insns.size();
            tmpls_by_start_pc[t.start_pc]++;
            prof_exec_cp += t.profile.exec_cp;
            prof_exec_wp += t.profile.exec_wp;
            for (const auto &ip : t.profile.insns) {
                if (ip.memops_cp || ip.memops_wp) prof_memop_insns++;
                if (ip.addr_cp || ip.addr_wp) prof_addr_insns++;
                prof_pat[ip.pat_cp & 0x3]++;
            }
        }
        uint64_t smc_revisions = 0, smc_revised_pcs = 0, smc_max_rev = 0;
        for (const auto &kv : tmpls_by_start_pc) {
            if (kv.second > 1) {
                smc_revisions += (kv.second - 1);
                smc_revised_pcs++;
                if (kv.second > smc_max_rev) smc_max_rev = kv.second;
            }
        }
        std::printf("  profile: exec_cp=%llu exec_wp=%llu  "
                    "mem-insns=%llu addr-insns=%llu  "
                    "pat[none/reg/irr/rand]=%llu/%llu/%llu/%llu\n",
                    (unsigned long long)prof_exec_cp,
                    (unsigned long long)prof_exec_wp,
                    (unsigned long long)prof_memop_insns,
                    (unsigned long long)prof_addr_insns,
                    (unsigned long long)prof_pat[0],
                    (unsigned long long)prof_pat[1],
                    (unsigned long long)prof_pat[2],
                    (unsigned long long)prof_pat[3]);
        if (smc_revisions > 0) {
            std::printf("  smc: %llu revision templates across %llu pc(s) "
                        "(max %llu states at one pc)\n",
                        (unsigned long long)smc_revisions,
                        (unsigned long long)smc_revised_pcs,
                        (unsigned long long)smc_max_rev);
        }

        cst::AttributionLint lint(h, templates);
        cst::MemopBimodalityLint bimodal(templates, bimodal_cfg);
        try {
            walk_body(body_stream->reader(), h.ids, h.flags,
                      insns_by_tid, templates, by_id, &s, &lint,
                      bimodal_off ? nullptr : &bimodal);
        } catch (const std::exception &e) {
            std::fprintf(stderr,
                "cst_audit: body walk failed at cp_entries=%lu wp_entries=%lu thread_switches=%lu iframes=%lu: %s\n",
                (unsigned long)s.cp_entries,
                (unsigned long)s.wp_entries_total,
                (unsigned long)s.thread_switch.count,
                (unsigned long)s.iframe_count,
                e.what());
            throw;
        }
        body_stream->finalize();
        /* body_total: consumed bytes for the record stream (between
         * leading and trailing CST_MAGIC). */
        s.body_total = s.cp_entry_framing.bytes
                     + s.cp_field_delta.bytes
                     + s.thread_switch.bytes
                     + s.asid_switch.bytes
                     + s.wp_chain_envelope.bytes
                     + s.wp_events.bytes
                     + s.iframe_bytes.bytes
                     + s.regfile_bytes.bytes
                     + s.devio_start.bytes
                     + s.devio_stop.bytes
                     + s.body_terminator;

        print_report(s, h);

        bool fail = false;

        /* Impossible-attribution lint verdict (cst_lint.h): always
         * printed, and a nonzero count fails the audit — a corrupt
         * trace must not exit 0.  A conservation-only check (the byte
         * rollup above) reconciles what the wire DOES carry; this and
         * the two sections below are completeness checks — they look
         * for what should be on the wire and is not, which a rollup
         * can never see (a record never written contributes to neither
         * side of a byte partition, so it reconciles trivially). */
        std::printf("\n=== ATTRIBUTION LINT ===\n");
        std::printf("  impossible attributions: %s\n",
                    lint.summary().c_str());
        if (lint.any()) {
            std::fprintf(stderr,
                         "cst_audit: FAIL: impossible attributions: %s\n",
                         lint.summary().c_str());
            fail = true;
        }

        /* Oracle 2 — memop bimodality (cst_lint.h MemopBimodalityLint):
         * a template whose CP executions overwhelmingly realise memops,
         * with a small minority realising none, is the D4 signature.
         * Always printed when enabled; a nonzero flagged-template count
         * fails the audit, same contract as the attribution lint. */
        if (!bimodal_off) {
            std::vector<cst::MemopBimodalityLint::Finding> findings =
                bimodal.flagged();
            std::printf("\n=== MEMOP BIMODALITY (Oracle 2; min_execs=%u, "
                        "max_outlier_rate=%.2f) ===\n",
                        bimodal_cfg.min_execs, bimodal_cfg.max_outlier_rate);
            std::printf("  %s fault-truncated CP execution(s) excluded "
                        "from the population\n",
                        fmt_n(bimodal.truncated_execs()).c_str());
            if (findings.empty()) {
                std::printf("  clean: 0 templates with a nonzero-majority / "
                            "zero-outlier memop split\n");
            } else {
                for (const auto &fnd : findings) {
                    std::printf("  template %-8u %8s executions, %6s "
                                "zero-memop outlier(s)  (rate %.4f)\n",
                                fnd.template_id,
                                fmt_n(fnd.total).c_str(),
                                fmt_n(fnd.zero).c_str(), fnd.rate);
                    std::fprintf(stderr,
                        "cst_audit: FAIL: template %u: %llu/%llu CP "
                        "executions realised zero memops (rate %.4f) "
                        "against a %llu-execution nonzero majority — "
                        "memop bimodality (D4-class completeness loss)\n",
                        fnd.template_id,
                        (unsigned long long)fnd.zero,
                        (unsigned long long)fnd.total, fnd.rate,
                        (unsigned long long)fnd.nonzero);
                }
                fail = true;
            }
        }

        /* Oracle 1 — the plugin's own dropped-slice accounting, surfaced
         * from the <outfile>.stats.log sidecar when available (see
         * read_completeness_stats above).  Silently absent when no
         * sidecar was found and none was requested; --stats-log=PATH
         * makes an unreadable/malformed sidecar an explicit failure. */
        if (!no_stats_log && !stats_log_path.empty()) {
            CompletenessStats cs = read_completeness_stats(stats_log_path);
            if (cs.present) {
                bool ok = cs.dropped == cs.trimmed;
                std::printf("\n=== COMPLETENESS (Oracle 1; %s) ===\n",
                            stats_log_path.c_str());
                std::printf("  CP reg-snap slice dropped   %14s\n",
                            fmt_n(cs.dropped).c_str());
                std::printf("  CP reg-snap leak trimmed    %14s\n",
                            fmt_n(cs.trimmed).c_str());
                std::printf("  invariant dropped == trimmed: %s\n",
                            ok ? "OK" : "MISMATCH");
                if (!ok) {
                    std::fprintf(stderr,
                        "cst_audit: FAIL: dropped-slice accounting "
                        "mismatch: dropped=%llu trimmed=%llu (%s)\n",
                        (unsigned long long)cs.dropped,
                        (unsigned long long)cs.trimmed, stats_log_path.c_str());
                    fail = true;
                }
            } else if (stats_log_explicit) {
                std::fprintf(stderr,
                    "cst_audit: FAIL: --stats-log=%s did not carry both "
                    "completeness counters\n", stats_log_path.c_str());
                fail = true;
            }
            /* Auto-detected path that doesn't exist: silent, matching
             * the auto-detection's best-effort contract. */
        }

        if (fail) {
            return 1;
        }
    } catch (const std::exception &e) {
        std::fprintf(stderr, "cst_audit: %s\n", e.what());
        return 1;
    }
    return 0;
}
