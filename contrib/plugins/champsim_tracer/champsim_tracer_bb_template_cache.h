/*
 * Wrong-Path Tracing Plugin — BB template cache.
 *
 * Owns two hash tables of BBTemplate records:
 *   - tb_map: per-TB fragment templates keyed by TB start_pc (the unit
 *     from vcpu_tb_trans; looked up from vcpu_tb_exec / wp.cc).
 *   - bb_map: true-BB templates keyed by BB start_pc, assembled from
 *     TB fragments; what the trace's templates section serializes.
 *
 * Templates are immutable once committed.  The cache owns the heap
 * records and frees their inner arrays via a custom unique_ptr deleter.
 *
 * Unsynchronised: callers hold data_lock around mutators
 * (commit_true_bb, get_or_create_*) and around read-only methods
 * (find_*, *_count, for_each_bb, template_branch_index) if a concurrent
 * mutator could be running.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_BB_TEMPLATE_CACHE_H
#define CHAMPSIM_TRACER_BB_TEMPLATE_CACHE_H

#include <functional>
#include <memory>
#include <unordered_map>

#include "champsim_tracer.h"

struct BBTemplateDeleter {
    void operator()(BBTemplate *t) const noexcept;
};

using BBTemplatePtr = std::unique_ptr<BBTemplate, BBTemplateDeleter>;

class BBTemplateCache {
public:
    BBTemplateCache() = default;
    ~BBTemplateCache() = default;

    BBTemplateCache(const BBTemplateCache &) = delete;
    BBTemplateCache &operator=(const BBTemplateCache &) = delete;

    /* Per-TB fragment templates. */
    BBTemplate *find_tb_template(uint64_t start_pc);
    BBTemplate *get_or_create_tb_template(uint64_t start_pc,
                                          uint32_t n_insns,
                                          uint64_t *insn_pcs,
                                          qemu_plugin_insn_info *insn_info,
                                          const uint64_t *insn_branch_target_pcs,
                                          uint8_t *insn_sizes,
                                          uint8_t *insn_bytes,
                                          const char *symbol_name,
                                          uint64_t fall_through_pc);

    /* True basic blocks. */
    BBTemplate *find_bb_template(uint64_t entry_pc);
    BBTemplate *commit_true_bb(uint64_t start_pc,
                               uint32_t n_insns,
                               const uint64_t *insn_pcs,
                               const InsnFields *insn_fields,
                               const uint8_t *insn_sizes,
                               const uint8_t *insn_bytes,
                               const InsnRegNames *insn_reg_names,
                               const char *symbol_name,
                               uint64_t fall_through_pc);
    /*
     * Reference variant of commit_true_bb for the wrong-path walker.
     * @insn_fields / @insn_reg_names are arrays of *pointers* into
     * stable per-TB-template storage rather than contiguous copies.
     * The hot path is a BB already templated (commit just returns the
     * existing record): this variant touches no field payload at all
     * there — eliminating the per-WP-visit InsnFields/InsnRegNames
     * struct copy the array form forced.  Only a genuine cache miss
     * (first sighting of a BB) materialises a contiguous copy, once.
     * @insn_reg_names may be nullptr (reg-data disabled).
     */
    BBTemplate *commit_true_bb_refs(uint64_t start_pc,
                                    uint32_t n_insns,
                                    const uint64_t *insn_pcs,
                                    const InsnFields *const *insn_fields,
                                    const uint8_t *insn_sizes,
                                    const uint8_t *insn_bytes,
                                    const InsnRegNames *const *insn_reg_names,
                                    const char *symbol_name,
                                    uint64_t fall_through_pc);
    BBTemplate *get_or_create_bb_template(uint64_t entry_pc,
                                          BBTemplate *const *fragments,
                                          unsigned int n_fragments);

    size_t tb_count() const;
    size_t bb_count() const;

    /* Iterate true-BB templates in sorted start_pc order (deterministic
     * serialization).  Invoked once at end-of-trace by the writer. */
    void for_each_bb(const std::function<void(BBTemplate &)> &fn);

    /* Pure: return the index of the (last) branch instruction within
     * @tmpl, or -1 if @tmpl has no branch.  After delay-slot
     * normalization the branch is always the last instruction. */
    static int template_branch_index(const BBTemplate *tmpl);

    /* Drop all true-BB templates so the next segment serializes only
     * BBs reached after this point.  tb_map_ is preserved: QEMU issues
     * vcpu_tb_trans only on first translation, so dropping fragments
     * would orphan the chain assembler on re-execution of a translated
     * TB.  True-BBs are re-assembled at runtime from those fragments,
     * so clearing bb_map_ alone is safe. */
    void clear_bb_map();

private:
    /* Shared existing-true-BB handling for commit_true_bb and its
     * reference variant: returns the cached template (logging a
     * one-shot SMC/divergence warning if the insn-pc sequence
     * differs) or nullptr on a true miss.  Uses only insn_pcs. */
    BBTemplate *find_existing_true_bb(uint64_t start_pc,
                                      uint32_t n_insns,
                                      const uint64_t *insn_pcs);

    std::unordered_map<uint64_t, BBTemplatePtr> tb_map_;
    std::unordered_map<uint64_t, BBTemplatePtr> bb_map_;
    uint32_t                                    next_template_id_ = 1;
};

extern BBTemplateCache g_bb_template_cache;

#endif /* CHAMPSIM_TRACER_BB_TEMPLATE_CACHE_H */
