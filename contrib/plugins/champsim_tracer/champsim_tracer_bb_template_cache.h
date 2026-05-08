/*
 * Wrong-Path Tracing Plugin — BB template cache.
 *
 * Owns the two hash tables that index BBTemplate records:
 *   - tb_map: per-TB fragment templates, keyed by TB start_pc.  These
 *     are the unit returned from QEMU's vcpu_tb_trans callback and
 *     looked up later from vcpu_tb_exec / wp.cc.
 *   - bb_map: true-basic-block templates, keyed by BB start_pc.  These
 *     are assembled from one or more TB fragments and are what the
 *     trace's templates section serializes.
 *
 * Templates are immutable once committed.  Every map entry is heap-
 * allocated; the cache owns the records and frees their inner arrays
 * via a custom unique_ptr deleter when it shuts down.
 *
 * The cache itself is unsynchronised; callers must hold data_lock
 * around any method that mutates state (commit_true_bb,
 * get_or_create_*).  Read-only methods (find_*, *_count, for_each_bb,
 * template_branch_index) need the same lock if a concurrent mutator
 * could be running.
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
    BBTemplate *get_or_create_bb_template(uint64_t entry_pc,
                                          BBTemplate *const *fragments,
                                          unsigned int n_fragments);

    size_t tb_count() const;
    size_t bb_count() const;

    /* Iterate true-BB templates.  Invoked once at end-of-trace by the
     * binary writer; ordering matches the underlying GHashTable's
     * iteration order, which the format does not constrain. */
    void for_each_bb(const std::function<void(BBTemplate &)> &fn);

    /* Pure: return the index of the (last) branch instruction within
     * @tmpl, or -1 if @tmpl has no branch.  After delay-slot
     * normalization the branch is always the last instruction. */
    static int template_branch_index(const BBTemplate *tmpl);

    /* Drop all true-BB templates so the next segment serializes a
     * dictionary that only covers BBs reached after this point.
     * tb_map_ (per-TB fragments) is intentionally preserved: QEMU
     * issues vcpu_tb_trans only on first translation of each TB, so
     * dropping fragments would orphan the chain assembler the next
     * time a previously-translated TB executes.  True-BBs are re-
     * assembled at runtime by BBChainAssembler from those fragments,
     * so clearing bb_map_ alone is safe and gives each segment a
     * clean template dictionary. */
    void clear_bb_map();

private:
    std::unordered_map<uint64_t, BBTemplatePtr> tb_map_;
    std::unordered_map<uint64_t, BBTemplatePtr> bb_map_;
    uint32_t                                    next_template_id_ = 1;
};

extern BBTemplateCache g_bb_template_cache;

#endif /* CHAMPSIM_TRACER_BB_TEMPLATE_CACHE_H */
