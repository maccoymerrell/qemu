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
     * Reset the template-id counter so the next segment starts at id 1.
     * Otherwise template ids accumulate monotonically across segments
     * and the per-(template_id) FieldStateBlock vector inside each
     * segment's fresh FieldStateTable is forced to grow past the
     * unused 1..N1 slots from the previous segment on first hit.
     * Wire format unaffected — template ids are emitted as deltas
     * relative to the previous template id within the segment, and
     * each segment opens a new TEMPLATES section anyway.
     */
    next_template_id_ = 1;
}

size_t BBTemplateCache::bb_count() const
{
    return bb_map_.size();
}

void BBTemplateCache::for_each_bb(const std::function<void(BBTemplate &)> &fn)
{
    /* unordered_map iteration order is implementation-defined and varies
     * with bucket count.  Walk by sorted start_pc so the templates
     * section serialization is deterministic across runs and across
     * libstdc++ revisions.  Called once at end-of-trace, so the sort
     * cost is amortized over the whole run. */
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

/* Allocate and populate a fresh BBTemplate with @n_insns entries
 * copied from @insn_*.  Common to commit_true_bb and
 * commit_truncated_bb; the template_id is assigned by the caller's
 * map insertion path (so truncated entries don't burn IDs unless
 * actually inserted).  Returns the heap-allocated unique_ptr; caller
 * moves it into the appropriate map. */
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
    return tmpl;
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
    BBTemplate *existing = find_bb_template(start_pc);
    if (existing) {
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
                /* Find first divergence so we can tell whether it's
                 * a length-only difference (one is a prefix of the
                 * other — likely a chain that finalized at different
                 * lengths) or a true sequence mismatch (likely SMC). */
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

    /* Thread-local scratch for the fragment-walk staging area.
     * Profiling on mcf showed these per-call g_new0 allocations
     * accounting for ~3% of total tracer runtime; making them
     * per-thread reusable buffers eliminates the malloc/free pair
     * on every BB finalization.  Capacity grows to the largest
     * BB seen and stays put for the run.
     *
     * thread_local because get_or_create_bb_template is called
     * exclusively from vcpu_tb_exec on the per-vCPU host thread;
     * each vCPU thread owns its own scratch. */
    thread_local std::vector<uint64_t>   tls_insn_pcs;
    thread_local std::vector<uint8_t>    tls_insn_sizes;
    thread_local std::vector<uint8_t>    tls_insn_bytes;
    thread_local std::vector<InsnFields> tls_insn_fields;
    thread_local std::vector<InsnRegNames> tls_insn_reg_names;

    if (tls_insn_pcs.size() < max_insns) {
        tls_insn_pcs.assign(max_insns, 0);
        tls_insn_sizes.assign(max_insns, 0);
        tls_insn_bytes.assign((size_t)max_insns * MAX_INSN_BYTES, 0);
        tls_insn_fields.assign(max_insns, InsnFields{});
    } else {
        std::fill_n(tls_insn_pcs.begin(),    max_insns, 0);
        std::fill_n(tls_insn_sizes.begin(),  max_insns, 0);
        std::fill_n(tls_insn_bytes.begin(),
                    (size_t)max_insns * MAX_INSN_BYTES, 0);
        std::fill_n(tls_insn_fields.begin(), max_insns, InsnFields{});
    }
    uint64_t   *insn_pcs    = tls_insn_pcs.data();
    uint8_t    *insn_sizes  = tls_insn_sizes.data();
    uint8_t    *insn_bytes  = tls_insn_bytes.data();
    InsnFields *insn_fields = tls_insn_fields.data();

    InsnRegNames *insn_reg_names = nullptr;
    if (enable_reg_data) {
        if (tls_insn_reg_names.size() < max_insns) {
            tls_insn_reg_names.assign(max_insns, InsnRegNames{});
        } else {
            std::fill_n(tls_insn_reg_names.begin(),
                        max_insns, InsnRegNames{});
        }
        insn_reg_names = tls_insn_reg_names.data();
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
            insn_fields[off] = frag->insn_fields[i];
            if (insn_reg_names && frag->insn_reg_names) {
                insn_reg_names[off] = frag->insn_reg_names[i];
            }
            off++;
        }
        final_ft = frag->fall_through_pc;
    }

    if (off == 0) {
        return nullptr;
    }

    BBTemplate *tmpl = commit_true_bb(entry_pc, off,
                                      insn_pcs, insn_fields,
                                      insn_sizes, insn_bytes,
                                      insn_reg_names,
                                      symbol_name, final_ft);
    return tmpl;
}

BBTemplate *BBTemplateCache::get_or_create_tb_template(
    uint64_t start_pc,
    uint32_t n_insns,
    uint64_t *insn_pcs,
    qemu_plugin_insn_info *insn_info,
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
    }

    /*
     * Delay-slot reordering: swap [branch, delay] -> [delay, branch] on
     * ISAs with branch delay slots so the last instruction is always the
     * branch.  This lets template_branch_index and WP steering be
     * uniform across ISAs.
     */
    if (isa_properties[trace_isa].branch_delay_slots > 0 && n_insns >= 2) {
        uint32_t br = n_insns - 2;
        uint32_t ds = n_insns - 1;
        if (tmpl->insn_fields[br].branch_type != BRANCH_NONE &&
            tmpl->insn_fields[ds].branch_type == BRANCH_NONE) {
            uint64_t tmp_pc = tmpl->insn_pcs[br];
            tmpl->insn_pcs[br] = tmpl->insn_pcs[ds];
            tmpl->insn_pcs[ds] = tmp_pc;
            uint8_t tmp_sz = tmpl->insn_sizes[br];
            tmpl->insn_sizes[br] = tmpl->insn_sizes[ds];
            tmpl->insn_sizes[ds] = tmp_sz;
            uint8_t tmp_bytes[MAX_INSN_BYTES];
            memcpy(tmp_bytes,
                   &tmpl->insn_bytes[(size_t)br * MAX_INSN_BYTES],
                   MAX_INSN_BYTES);
            memcpy(&tmpl->insn_bytes[(size_t)br * MAX_INSN_BYTES],
                   &tmpl->insn_bytes[(size_t)ds * MAX_INSN_BYTES],
                   MAX_INSN_BYTES);
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
    }

    BBTemplate *raw = tmpl.get();
    tb_map_[start_pc] = std::move(tmpl);
    g_stats.tb_templates_created++;
    return raw;
}
