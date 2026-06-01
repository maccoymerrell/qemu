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
#include <unordered_set>
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

BBTemplate *BBTemplateCache::find_bb_template(uint64_t entry_pc)
{
    auto it = bb_map_.find(entry_pc);
    return it == bb_map_.end() ? nullptr : it->second.get();
}

size_t BBTemplateCache::tb_count() const
{
    return tb_templates_.size();
}

void BBTemplateCache::clear_bb_map()
{
    bb_map_.clear();
    /* TB templates hold two back-edges into bb_map_ — parent_true_bb
     * (fast-path link to the assembled true-BB) and rep_subtmpl (the
     * 1-insn REP self-loop true-BB built at translation time for x86
     * REP string ops).  Both must be invalidated after the wipe;
     * otherwise commit_true_bb_refs propagates a dangling rep_subtmpl
     * onto the next finalized true-BB, and emit_body_entry's REP
     * fan-out path then derefs freed memory.  Walking tb_templates_
     * is O(distinct translations) and only runs on segment switches,
     * not per-exec. */
    for (auto &p : tb_templates_) {
        if (p) {
            p->parent_true_bb = nullptr;
            p->rep_subtmpl    = nullptr;
        }
    }
    /*
     * Reset template-id counter so each segment starts at id 1; else
     * ids accumulate across segments and the fresh FieldStateTable's
     * per-id vector grows past unused prior-segment slots on first hit.
     * Wire format unaffected — ids are intra-segment deltas and each
     * segment opens a new TEMPLATES section.
     */
    next_template_id_ = 1;
}

BBTemplate *BBTemplateCache::lookup_tb_chain(uint64_t tb_start_pc,
                                             uint32_t total_n_insns)
{
    auto it = tb_chain_dedup_.find(tb_start_pc);
    if (it == tb_chain_dedup_.end()) {
        return nullptr;
    }
    for (BBTemplate *head : it->second) {
        uint32_t sum = 0;
        for (BBTemplate *f = head; f; f = f->next_tb_fragment) {
            sum += f->n_insns;
        }
        if (sum == total_n_insns) {
            return head;
        }
    }
    return nullptr;
}

void BBTemplateCache::register_tb_chain(uint64_t tb_start_pc, BBTemplate *head)
{
    tb_chain_dedup_[tb_start_pc].push_back(head);
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

    /* The terminating branch is the highest-indexed branch-type insn.
     * On a delay-slot ISA the template is in true execution order
     * [branch, delay-slot], so the branch is at n-2 (the delay slot at
     * n-1 is BRANCH_NONE); on every other ISA it is the last insn.
     * Scan from the end for the first branch-type insn either way. */
    for (int i = (int)tmpl->n_insns - 1; i >= 0; i--) {
        if (tmpl->insn_fields[i].branch_type != BRANCH_NONE) {
            return i;
        }
    }

    return -1;
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
     * No delay-slot reorder: the template stays in TRUE EXECUTION ORDER
     * [.., branch, delay-slot].  Reordering to branch-last would make
     * per-insn register/dependency deltas incoherent (the delay slot
     * really executes after the branch).  Consumers (and
     * template_branch_index) locate the terminating branch by scanning
     * for the branch-type insn; the fall-through is the separate
     * fall_through_pc field.
     */
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
        /* Templates are stored in true execution order (no delay-slot
         * reorder), so the candidate and the stored copy share the same
         * insn ordering — compare PCs directly. */
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
    /* Already-templated BB: return the cached record without touching
     * the field/regnames payload at all.  Templates are stored in true
     * execution order, so the dedup compares insn PCs directly. */
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

    /*
     * Fast path: every fragment of this chain has already been folded
     * into the same true-BB whose start_pc matches @entry_pc.  Skip
     * the per-fragment concat + dedup + find_existing_true_bb dance
     * and return the cached BB directly.  parent_true_bb is cleared
     * across segment switches (clear_bb_map drops bb_map_'s
     * ownership), so a non-NULL value here is always live.
     */
    if (n_fragments > 0) {
        BBTemplate *cand = fragments[0]->parent_true_bb;
        if (cand && cand->start_pc == entry_pc) {
            bool all_match = true;
            for (unsigned int f = 1; f < n_fragments; f++) {
                if (fragments[f]->parent_true_bb != cand) {
                    all_match = false;
                    break;
                }
            }
            if (all_match) {
                return cand;
            }
        }
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
     * (the TB ending in the REP string op) onto the assembled BB so
     * emit_body_entry can fan iterations without re-walking fragments.
     * No-op for non-REP BBs.  Materialization is lazy: the parent
     * TB's rep_subtmpl is built on first chain-finalize use here, not
     * at translation time — that avoids paying the cost for REP TBs
     * translated outside an active segment, AND rebuilds the pointer
     * the next time it is needed after clear_bb_map() invalidated it
     * at a segment switch.
     */
    if (tmpl && n_fragments > 0 && fragments[n_fragments - 1]) {
        ensure_rep_subtmpl(fragments[n_fragments - 1]);
        tmpl->rep_subtmpl = fragments[n_fragments - 1]->rep_subtmpl;
    }

    /* Arm the fast-path back-edges: every fragment of this chain now
     * resolves to @tmpl, so a future re-finalization with the same
     * fragment set takes the fast-path at the top of this function
     * without walking the fragments. */
    if (tmpl) {
        for (unsigned int f = 0; f < n_fragments; f++) {
            fragments[f]->parent_true_bb = tmpl;
        }
    }
    return tmpl;
}

BBTemplate *BBTemplateCache::create_tb_template(
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
    /* Always fresh: one template per QEMU translation, attached to
     * that TB via udata.  Distinct CP-mode and WP-mode translations
     * at the same start_pc therefore each get their own template and
     * cannot collide. */
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
    /* Allocate the per-insn reg-name table when either CP or WP
     * regdata is enabled — the WP fragment-walk reads dst_qemu_reg_keys
     * out of this table for its per-insn-accurate snap consumption
     * (see vcpu_insn_reg_snap_cb / champsim_tracer_wp.cc).  Skipping
     * it would force WP regdata-only runs back to the old post-
     * fragment live-read fallback. */
    if (enable_reg_data || enable_wp_reg_data) {
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

    /* No delay-slot reorder: template stays in true execution order. */
    BBTemplate *raw = tmpl.get();
    tb_templates_.push_back(std::move(tmpl));
    g_stats.tb_templates_created++;
    /* rep_subtmpl is materialized lazily on first chain-finalize use
     * inside an active segment (see ensure_rep_subtmpl); doing it
     * here would burn translation cost on every TB during warmup, on
     * top of leaving a freed pointer cached on the TB after the next
     * clear_bb_map. */
    return raw;
}

void BBTemplateCache::ensure_rep_subtmpl(BBTemplate *tb)
{
    /* No-op when already built, when not a REP TB, or on a degenerate
     * template (no insns).  commit_true_bb dedups by start_pc, so
     * repeated calls within a segment are safe — but the early-out
     * keeps the hot path branch-predicted. */
    if (!tb || tb->rep_subtmpl || tb->n_insns == 0) {
        return;
    }
    uint32_t last = tb->n_insns - 1;
    const InsnFields *lf = &tb->insn_fields[last];
    if (lf->rep_loads_per_iter + lf->rep_stores_per_iter == 0) {
        return;
    }
    /* 1-insn self-loop sub-template at the REP PC with the same
     * InsnFields (incl. BRANCH_COND_DIRECT), structurally a self-
     * loop.  emit_body_entry fans iter 2..N onto this template. */
    uint64_t  sub_pc   = tb->insn_pcs[last];
    uint8_t   sub_size = tb->insn_sizes[last];
    const uint8_t *sub_bytes =
        &tb->insn_bytes[(size_t)last * MAX_INSN_BYTES];
    const InsnRegNames *sub_regs =
        tb->insn_reg_names ? &tb->insn_reg_names[last] : nullptr;
    uint64_t sub_ft = sub_pc + sub_size;
    tb->rep_subtmpl = commit_true_bb(sub_pc, 1, &sub_pc, lf,
                                     &sub_size, sub_bytes,
                                     sub_regs,
                                     tb->symbol_name, sub_ft);
}
