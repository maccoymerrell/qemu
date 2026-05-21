/*
 * Wrong-Path Tracing Plugin — BB template cache implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <algorithm>
#include <atomic>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <vector>

#include "champsim_tracer_bb_template_cache.h"
#include "champsim_tracer_stats.h"

BBTemplateCache g_bb_template_cache;

/* Stable zeroed sentinel: a fragment may lack insn_reg_names while
 * reg-data is enabled; the by-reference commit points such slots
 * here so every regnames pointer is valid and reads as all-zero. */
static const InsnRegNames kCacheEmptyRegNames{};

void BBTemplateDeleter::operator()(BBTemplate *t) const noexcept
{
    if (!t) {
        return;
    }
    g_free(t->insn_fields);
    g_free(t->insn_pcs);
    g_free(t->symbol_name);
    g_free(t->insn_sizes);
    g_free(t->insn_bytes);
    g_free(t->insn_reg_names);
    g_free(t->insn_snap_refs);
    g_free(t->insn_synthetic_ea);
    g_free(t->insn_synth_ea_refs);
    if (t->profile) {
        g_free(t->profile->insns);
        g_free(t->profile);
    }
    g_free(t);
}

BBTemplate *BBTemplateCache::find_tb_template(uint64_t start_pc)
{
    auto it = tb_map_.find(start_pc);
    return it == tb_map_.end() ? nullptr : it->second.get();
}

BBTemplate *BBTemplateCache::find_bb_template(uint64_t entry_pc)
{
    auto it = bb_map_.find(entry_pc);
    return it == bb_map_.end() ? nullptr : it->second.get();
}

size_t BBTemplateCache::tb_count() const
{
    return tb_map_.size();
}

void BBTemplateCache::clear_bb_map()
{
    bb_map_.clear();
    /*
     * Reset template-id counter so each segment starts at id 1; else
     * ids accumulate across segments and the fresh FieldStateTable's
     * per-id vector grows past unused prior-segment slots on first hit.
     * Wire format unaffected — ids are intra-segment deltas and each
     * segment opens a new TEMPLATES section.
     */
    next_template_id_ = 1;
}

size_t BBTemplateCache::bb_count() const
{
    return bb_map_.size();
}

void BBTemplateCache::for_each_bb(const std::function<void(BBTemplate &)> &fn)
{
    /* Walk by sorted start_pc so templates-section serialization is
     * deterministic (unordered_map order is implementation-defined).
     * Called once at end-of-trace; sort cost amortized over the run. */
    std::vector<uint64_t> keys;
    keys.reserve(bb_map_.size());
    for (const auto &kv : bb_map_) {
        keys.push_back(kv.first);
    }
    std::sort(keys.begin(), keys.end());
    for (uint64_t pc : keys) {
        fn(*bb_map_[pc]);
    }
}

int BBTemplateCache::template_branch_index(const BBTemplate *tmpl)
{
    if (!tmpl || tmpl->n_insns == 0) {
        return -1;
    }

    uint32_t last = tmpl->n_insns - 1;
    if (tmpl->insn_fields[last].branch_type != BRANCH_NONE) {
        return (int)last;
    }

    return -1;
}

/*
 * Delay-slot reordering: swap a trailing [branch, delay-slot] pair to
 * [delay-slot, branch] so the terminating branch is always the last
 * insn — template_branch_index and WP steering then stay ISA-uniform.
 *
 * Idempotent: the swap condition (insn[n-2] is a branch, insn[n-1] is
 * not) is false for an already-normalised [delay-slot, branch] tail,
 * so calling this on a template built from already-swapped fragments
 * is a no-op.  That matters for assembled true-BBs: a single-TB BB
 * inherits the TB fragment's already-swapped order, while a page-split
 * BB ([..,branch] TB + [delay-slot] TB) arrives unswapped and needs
 * this pass.
 */
static void apply_delay_slot_swap(BBTemplate *tmpl)
{
    uint32_t n_insns = tmpl->n_insns;
    if (isa_properties[trace_isa].branch_delay_slots == 0 || n_insns < 2) {
        return;
    }
    uint32_t br = n_insns - 2;
    uint32_t ds = n_insns - 1;
    if (tmpl->insn_fields[br].branch_type == BRANCH_NONE ||
        tmpl->insn_fields[ds].branch_type != BRANCH_NONE) {
        return;
    }
    uint64_t tmp_pc = tmpl->insn_pcs[br];
    tmpl->insn_pcs[br] = tmpl->insn_pcs[ds];
    tmpl->insn_pcs[ds] = tmp_pc;
    uint8_t tmp_sz = tmpl->insn_sizes[br];
    tmpl->insn_sizes[br] = tmpl->insn_sizes[ds];
    tmpl->insn_sizes[ds] = tmp_sz;
    uint8_t tmp_bytes[MAX_INSN_BYTES];
    memcpy(tmp_bytes, &tmpl->insn_bytes[(size_t)br * MAX_INSN_BYTES],
           MAX_INSN_BYTES);
    memcpy(&tmpl->insn_bytes[(size_t)br * MAX_INSN_BYTES],
           &tmpl->insn_bytes[(size_t)ds * MAX_INSN_BYTES], MAX_INSN_BYTES);
    memcpy(&tmpl->insn_bytes[(size_t)ds * MAX_INSN_BYTES],
           tmp_bytes, MAX_INSN_BYTES);
    InsnFields tmp_fld = tmpl->insn_fields[br];
    tmpl->insn_fields[br] = tmpl->insn_fields[ds];
    tmpl->insn_fields[ds] = tmp_fld;
    if (tmpl->insn_reg_names) {
        InsnRegNames tmp_n = tmpl->insn_reg_names[br];
        tmpl->insn_reg_names[br] = tmpl->insn_reg_names[ds];
        tmpl->insn_reg_names[ds] = tmp_n;
    }
}

/* Allocate and populate a fresh BBTemplate with @n_insns entries from
 * @insn_*.  template_id assigned by the caller's map-insertion path.
 * Returns the unique_ptr; caller moves it into the appropriate map. */
static BBTemplatePtr build_bb_template(uint32_t template_id,
                                       uint64_t start_pc,
                                       uint32_t n_insns,
                                       const uint64_t *insn_pcs,
                                       const InsnFields *insn_fields,
                                       const uint8_t *insn_sizes,
                                       const uint8_t *insn_bytes,
                                       const InsnRegNames *insn_reg_names,
                                       const char *symbol_name,
                                       uint64_t fall_through_pc)
{
    BBTemplatePtr tmpl(g_new0(BBTemplate, 1));
    tmpl->template_id = template_id;
    tmpl->start_pc = start_pc;
    tmpl->n_insns = n_insns;
    tmpl->fall_through_pc = fall_through_pc;
    tmpl->symbol_name = symbol_name ? g_strdup(symbol_name) : nullptr;
    tmpl->insn_pcs = g_new0(uint64_t, n_insns);
    tmpl->insn_sizes = g_new0(uint8_t, n_insns);
    tmpl->insn_bytes = g_new0(uint8_t, (size_t)n_insns * MAX_INSN_BYTES);
    tmpl->insn_fields = g_new0(InsnFields, n_insns);
    if (insn_reg_names) {
        tmpl->insn_reg_names = g_new0(InsnRegNames, n_insns);
    }
    for (uint32_t i = 0; i < n_insns; i++) {
        tmpl->insn_pcs[i] = insn_pcs[i];
        tmpl->insn_sizes[i] = insn_sizes[i];
        memcpy(&tmpl->insn_bytes[(size_t)i * MAX_INSN_BYTES],
               &insn_bytes[(size_t)i * MAX_INSN_BYTES],
               MAX_INSN_BYTES);
        tmpl->insn_fields[i] = insn_fields[i];
        if (tmpl->insn_reg_names) {
            tmpl->insn_reg_names[i] = insn_reg_names[i];
        }
    }
    /*
     * Normalise the terminating branch to the last slot.  A page-split
     * true BB is assembled as [.., branch][delay-slot] across two TB
     * fragments and arrives here unswapped; without this its branch
     * sits at n-2 and template_branch_index would miss it.
     */
    apply_delay_slot_swap(tmpl.get());
    return tmpl;
}

BBTemplate *BBTemplateCache::find_existing_true_bb(
    uint64_t start_pc, uint32_t n_insns, const uint64_t *insn_pcs)
{
    BBTemplate *existing = find_bb_template(start_pc);
    if (!existing) {
        return nullptr;
    }
    bool same = (existing->n_insns == n_insns);
    if (same) {
        for (uint32_t i = 0; i < n_insns; i++) {
            if (existing->insn_pcs[i] != insn_pcs[i]) {
                same = false;
                break;
            }
        }
    }
    if (!same) {
        static std::atomic<int> warned{0};
        int expected = 0;
        if (warned.compare_exchange_strong(expected, 1)) {
            /* First divergence distinguishes a length-only prefix
             * difference (chain finalized at different lengths)
             * from a true sequence mismatch (likely SMC). */
            uint32_t first_diff = 0;
            uint32_t common = existing->n_insns < n_insns
                ? existing->n_insns : n_insns;
            while (first_diff < common &&
                   existing->insn_pcs[first_diff] ==
                       insn_pcs[first_diff]) {
                first_diff++;
            }
            fprintf(stderr,
                "champsim_tracer: WARNING true-BB at start_pc=0x%"
                PRIx64 " seen with differing insn sequence "
                "(existing n_insns=%u, new n_insns=%u, "
                "first_diff at i=%u; "
                "existing[i]=0x%" PRIx64 ", new[i]=0x%" PRIx64 "). "
                "Keeping original; this indicates self-modifying "
                "code or a tracer bug.  (Further occurrences "
                "suppressed.)\n",
                start_pc, existing->n_insns, n_insns, first_diff,
                first_diff < existing->n_insns
                    ? existing->insn_pcs[first_diff] : 0,
                first_diff < n_insns
                    ? insn_pcs[first_diff] : 0);
        }
    }
    return existing;
}

BBTemplate *BBTemplateCache::commit_true_bb(uint64_t start_pc,
                                            uint32_t n_insns,
                                            const uint64_t *insn_pcs,
                                            const InsnFields *insn_fields,
                                            const uint8_t *insn_sizes,
                                            const uint8_t *insn_bytes,
                                            const InsnRegNames *insn_reg_names,
                                            const char *symbol_name,
                                            uint64_t fall_through_pc)
{
    if (BBTemplate *existing =
            find_existing_true_bb(start_pc, n_insns, insn_pcs)) {
        return existing;
    }

    BBTemplatePtr tmpl = build_bb_template(next_template_id_++,
                                           start_pc, n_insns,
                                           insn_pcs, insn_fields,
                                           insn_sizes, insn_bytes,
                                           insn_reg_names,
                                           symbol_name, fall_through_pc);
    BBTemplate *raw = tmpl.get();
    bb_map_[start_pc] = std::move(tmpl);
    g_stats.bb_templates_created++;
    return raw;
}

BBTemplate *BBTemplateCache::commit_true_bb_refs(
    uint64_t start_pc, uint32_t n_insns,
    const uint64_t *insn_pcs,
    const InsnFields *const *insn_fields,
    const uint8_t *insn_sizes, const uint8_t *insn_bytes,
    const InsnRegNames *const *insn_reg_names,
    const char *symbol_name, uint64_t fall_through_pc)
{
    /* Already-templated BB: return the cached record without
     * touching the field/regnames payload at all. */
    if (BBTemplate *existing =
            find_existing_true_bb(start_pc, n_insns, insn_pcs)) {
        return existing;
    }

    /* Cold path (first sighting of this BB only): gather the
     * pointed-to records into a thread-local contiguous scratch
     * once, then build exactly as the array form does.  O(unique
     * BBs), not O(WP visits). */
    thread_local std::vector<InsnFields>   gather_fields;
    thread_local std::vector<InsnRegNames> gather_regs;
    if (gather_fields.size() < n_insns) {
        gather_fields.resize(n_insns);
    }
    for (uint32_t i = 0; i < n_insns; i++) {
        gather_fields[i] = *insn_fields[i];
    }
    const InsnRegNames *reg_src = nullptr;
    if (insn_reg_names) {
        if (gather_regs.size() < n_insns) {
            gather_regs.resize(n_insns);
        }
        for (uint32_t i = 0; i < n_insns; i++) {
            gather_regs[i] = *insn_reg_names[i];
        }
        reg_src = gather_regs.data();
    }

    BBTemplatePtr tmpl = build_bb_template(next_template_id_++,
                                           start_pc, n_insns,
                                           insn_pcs, gather_fields.data(),
                                           insn_sizes, insn_bytes,
                                           reg_src,
                                           symbol_name, fall_through_pc);
    BBTemplate *raw = tmpl.get();
    bb_map_[start_pc] = std::move(tmpl);
    g_stats.bb_templates_created++;
    return raw;
}

BBTemplate *BBTemplateCache::get_or_create_bb_template(
    uint64_t entry_pc,
    BBTemplate *const *fragments,
    unsigned int n_fragments)
{
    uint32_t max_insns = 0;
    for (unsigned int i = 0; i < n_fragments; i++) {
        max_insns += fragments[i]->n_insns;
    }
    if (max_insns == 0) {
        return nullptr;
    }

    /* Thread-local fragment-walk scratch.  Per-call g_new0 here was
     * ~3% of tracer runtime on mcf; reusable per-thread buffers drop
     * the per-finalization malloc/free.  thread_local: this is called
     * only from vcpu_tb_exec on the per-vCPU host thread. */
    /* Scratch.  pcs/sizes/bytes stay contiguous (cheap, passed
     * through to the builder); the InsnFields / InsnRegNames per-insn
     * structs are NOT copied here — like the WP path, fragment-insn
     * pointers are gathered and committed by reference, so a BB that
     * is already templated (the hot case for the re-finalized CP
     * chain) copies no field payload at all. */
    thread_local std::vector<uint64_t> tls_insn_pcs;
    thread_local std::vector<uint8_t>  tls_insn_sizes;
    thread_local std::vector<uint8_t>  tls_insn_bytes;
    thread_local std::vector<const InsnFields *>   tls_field_ptrs;
    thread_local std::vector<const InsnRegNames *> tls_regname_ptrs;

    if (tls_insn_pcs.size() < max_insns) {
        tls_insn_pcs.assign(max_insns, 0);
        tls_insn_sizes.assign(max_insns, 0);
        tls_insn_bytes.assign((size_t)max_insns * MAX_INSN_BYTES, 0);
    } else {
        std::fill_n(tls_insn_pcs.begin(),    max_insns, 0);
        std::fill_n(tls_insn_sizes.begin(),  max_insns, 0);
        std::fill_n(tls_insn_bytes.begin(),
                    (size_t)max_insns * MAX_INSN_BYTES, 0);
    }
    if (tls_field_ptrs.size() < max_insns) {
        tls_field_ptrs.resize(max_insns);
    }
    uint64_t   *insn_pcs   = tls_insn_pcs.data();
    uint8_t    *insn_sizes = tls_insn_sizes.data();
    uint8_t    *insn_bytes = tls_insn_bytes.data();
    const InsnFields **field_ptrs = tls_field_ptrs.data();

    const InsnRegNames **regname_ptrs = nullptr;
    if (enable_reg_data) {
        if (tls_regname_ptrs.size() < max_insns) {
            tls_regname_ptrs.resize(max_insns);
        }
        regname_ptrs = tls_regname_ptrs.data();
    }
    const char *symbol_name = nullptr;
    uint64_t final_ft = 0;

    uint32_t off = 0;
    for (unsigned int f = 0; f < n_fragments; f++) {
        BBTemplate *frag = fragments[f];
        if (f == 0) {
            symbol_name = frag->symbol_name;
        }
        for (uint32_t i = 0; i < frag->n_insns; i++) {
            bool duplicate = false;
            if (off > 0) {
                duplicate = insn_pcs[off - 1] == frag->insn_pcs[i] &&
                            insn_sizes[off - 1] == frag->insn_sizes[i] &&
                            memcmp(&insn_bytes[(size_t)(off - 1) *
                                                MAX_INSN_BYTES],
                                   &frag->insn_bytes[(size_t)i *
                                                     MAX_INSN_BYTES],
                                   MAX_INSN_BYTES) == 0;
            }
            if (duplicate) {
                continue;
            }

            insn_pcs[off] = frag->insn_pcs[i];
            insn_sizes[off] = frag->insn_sizes[i];
            memcpy(&insn_bytes[(size_t)off * MAX_INSN_BYTES],
                   &frag->insn_bytes[(size_t)i * MAX_INSN_BYTES],
                   MAX_INSN_BYTES);
            field_ptrs[off] = &frag->insn_fields[i];
            if (regname_ptrs) {
                regname_ptrs[off] = frag->insn_reg_names
                    ? &frag->insn_reg_names[i]
                    : &kCacheEmptyRegNames;
            }
            off++;
        }
        final_ft = frag->fall_through_pc;
    }

    if (off == 0) {
        return nullptr;
    }

    BBTemplate *tmpl = commit_true_bb_refs(entry_pc, off,
                                           insn_pcs, field_ptrs,
                                           insn_sizes, insn_bytes,
                                           regname_ptrs,
                                           symbol_name, final_ft);
    /*
     * Propagate the REP self-loop sub-template from the last fragment
     * (the TB ending in the REP string op, built at TB-translation
     * time) onto the assembled BB so emit_body_entry can fan iterations
     * without re-walking fragments.  No-op for non-REP BBs.
     */
    if (tmpl && n_fragments > 0 && fragments[n_fragments - 1]) {
        tmpl->rep_subtmpl = fragments[n_fragments - 1]->rep_subtmpl;
    }
    return tmpl;
}

BBTemplate *BBTemplateCache::get_or_create_tb_template(
    uint64_t start_pc,
    uint32_t n_insns,
    uint64_t *insn_pcs,
    qemu_plugin_insn_info *insn_info,
    const uint64_t *insn_branch_target_pcs,
    uint8_t *insn_sizes,
    uint8_t *insn_bytes,
    const char *symbol_name,
    uint64_t fall_through_pc)
{
    if (BBTemplate *cached = find_tb_template(start_pc)) {
        return cached;
    }

    BBTemplatePtr tmpl(g_new0(BBTemplate, 1));
    tmpl->template_id = next_template_id_++;
    tmpl->start_pc = start_pc;
    tmpl->n_insns = n_insns;
    tmpl->fall_through_pc = fall_through_pc;
    tmpl->insn_pcs = g_new0(uint64_t, n_insns);
    tmpl->insn_sizes = g_new0(uint8_t, n_insns);
    tmpl->insn_bytes = g_new0(uint8_t, n_insns * MAX_INSN_BYTES);
    tmpl->symbol_name = symbol_name ? g_strdup(symbol_name) : nullptr;

    for (uint32_t i = 0; i < n_insns; i++) {
        tmpl->insn_pcs[i] = insn_pcs[i];
        tmpl->insn_sizes[i] = insn_sizes[i];
        memcpy(&tmpl->insn_bytes[(size_t)i * MAX_INSN_BYTES],
               &insn_bytes[(size_t)i * MAX_INSN_BYTES],
               MAX_INSN_BYTES);
    }

    tmpl->insn_fields = g_new0(InsnFields, n_insns);
    if (enable_reg_data) {
        tmpl->insn_reg_names = g_new0(InsnRegNames, n_insns);
    }
    for (uint32_t i = 0; i < n_insns; i++) {
        if (insn_info && insn_info[i].mnemonic[0]) {
            decode_detail_to_generic(
                tmpl->insn_pcs[i], &insn_info[i],
                &tmpl->insn_fields[i],
                tmpl->insn_reg_names ? &tmpl->insn_reg_names[i] : nullptr);
        }
        /*
         * Static branch target as resolved by the per-ISA translator,
         * not Capstone.  See InsnFields::taken_target_pc.  0 means
         * "no static target" — non-branch or indirect; WP-resolution
         * routes those through the observed-target history instead.
         */
        if (insn_branch_target_pcs) {
            tmpl->insn_fields[i].taken_target_pc =
                insn_branch_target_pcs[i];
        }
    }

    /* Normalise the terminating branch to the last slot (delay-slot
     * ISAs); see apply_delay_slot_swap. */
    apply_delay_slot_swap(tmpl.get());

    BBTemplate *raw = tmpl.get();
    tb_map_[start_pc] = std::move(tmpl);
    g_stats.tb_templates_created++;

    /*
     * REP string ops fan into per-iteration body entries: iter 1 stays
     * on the parent TB template (the BB first entering the loop ends
     * with the first REP, like a normal branch); iter 2..N emit on a
     * 1-insn self-loop sub-template built here.  The body emitter
     * follows raw->rep_subtmpl when the terminator has
     * rep_loads_per_iter + rep_stores_per_iter > 0.  The sub-template
     * is a 1-insn BB at the REP PC with the same InsnFields (incl.
     * BRANCH_COND_DIRECT) so it is structurally a self-loop.
     */
    if (raw->n_insns > 0) {
        uint32_t last = raw->n_insns - 1;
        const InsnFields *lf = &raw->insn_fields[last];
        if (lf->rep_loads_per_iter + lf->rep_stores_per_iter > 0) {
            uint64_t  sub_pc   = raw->insn_pcs[last];
            uint8_t   sub_size = raw->insn_sizes[last];
            const uint8_t *sub_bytes =
                &raw->insn_bytes[(size_t)last * MAX_INSN_BYTES];
            const InsnRegNames *sub_regs =
                raw->insn_reg_names ? &raw->insn_reg_names[last] : nullptr;
            uint64_t  sub_ft   = sub_pc + sub_size;
            raw->rep_subtmpl = commit_true_bb(sub_pc, 1, &sub_pc, lf,
                                              &sub_size, sub_bytes,
                                              sub_regs,
                                              raw->symbol_name, sub_ft);
        }
    }
    return raw;
}
