/*
 * Wrong-Path Tracing Plugin — BB template cache.
 *
 * Owns two distinct stores of BBTemplate records:
 *   - tb_templates_: per-translation TB templates, pure ownership (no
 *     start_pc lookup).  Each QEMU translation creates a fresh entry
 *     and the template pointer is handed to that QEMU TB as its
 *     per-TB exec-cb udata.  vcpu_tb_exec reads it back directly on
 *     both CP and WP paths, so distinct CP-mode and WP-mode QEMU
 *     translations of the same start_pc cannot conflate.  Cleared
 *     together on tb_flush, when QEMU drops the TBs themselves.
 *   - bb_map_: true-BB templates keyed by BB start_pc, assembled from
 *     TB fragments; what the trace's templates section serializes.
 *
 * Templates are immutable once committed.  The cache owns the heap
 * records and frees their inner arrays via a custom unique_ptr deleter.
 *
 * Unsynchronised: callers hold data_lock around mutators
 * (commit_true_bb, create_tb_template) and around read-only methods
 * (find_bb_template, *_count, for_each_bb, template_branch_index) if a
 * concurrent mutator could be running.
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

/*
 * Read-only view of a contiguous run of canonical instructions (a whole TB
 * or a fragment slice).  Groups the six parallel per-insn arrays that
 * describe a translation so they travel together rather than as a
 * six-pointer parameter clump.  Non-owning: the backing arrays must outlive
 * the view.
 */
struct TbInsnView {
    uint32_t                     n;
    const uint64_t              *pcs;
    const qemu_plugin_insn_info *info;
    const uint64_t              *branch_target_pcs;
    const uint8_t               *sizes;
    const uint8_t               *bytes;   /* n * MAX_INSN_BYTES */

    /* Sub-view covering canonical insns [first, first + count). */
    TbInsnView slice(uint32_t first, uint32_t count) const
    {
        return TbInsnView{
            count,
            pcs + first,
            info + first,
            branch_target_pcs + first,
            sizes + first,
            bytes + (size_t)first * MAX_INSN_BYTES,
        };
    }
};

class BBTemplateCache {
public:
    BBTemplateCache() = default;
    ~BBTemplateCache() = default;

    BBTemplateCache(const BBTemplateCache &) = delete;
    BBTemplateCache &operator=(const BBTemplateCache &) = delete;

    /* Create a fresh per-translation TB template.  Always allocates
     * (no start_pc dedup) and stores the BBTemplatePtr in
     * tb_templates_ for the QEMU TB's lifetime.  The returned raw
     * pointer is what vcpu_tb_trans attaches to the QEMU TB as its
     * per-TB exec-cb udata; vcpu_tb_exec reads it back as the current
     * TB's exact-shape template on both CP and WP paths. */
    BBTemplate *create_tb_template(uint64_t start_pc,
                                   const TbInsnView &insns,
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
     * BBs reached after this point.  tb_templates_ is preserved
     * across segment switches: each QEMU TB carries its template via
     * the per-TB exec-cb udata for the QEMU TB's lifetime, and
     * clearing the ownership list would leave that udata dangling.
     * Cleared by clear_tb_templates() on tb_flush, when QEMU drops
     * the TBs themselves. */
    void clear_bb_map();

    /* Dedup support for the persistent per-translation store.  TB
     * templates are NEVER freed on tb_flush: a flush just re-translates
     * the same code, so the matching chain is reused instead.  This keeps
     * every per-insn-callback udata (RegSnapInsnRef inside a template)
     * valid for the QEMU TB's whole lifetime without any flush-time
     * reclamation — the trace is flush-invariant by construction, because
     * a flush changes nothing in the plugin's state.
     *
     * lookup_tb_chain returns the head fragment of an already-built chain
     * for a TB starting at @tb_start_pc with @total_n_insns canonical
     * insns, or nullptr on a miss.  Byte-identity is guaranteed by the
     * caller's bytes-changed/poison gate (a TB that reaches here has
     * insns matching their first sighting), so (start_pc, n_insns) is a
     * sufficient key.  register_tb_chain records a freshly built chain's
     * head for future reuse.  Memory is bounded by the segment's
     * distinct-translation footprint (code size), not execution length;
     * SMC produces a new entry and leaves the dead one in place (rare,
     * bounded, never dereferenced once its QEMU TB is gone). */
    BBTemplate *lookup_tb_chain(uint64_t tb_start_pc, uint32_t total_n_insns);
    void        register_tb_chain(uint64_t tb_start_pc, BBTemplate *head);

private:
    /* Materialize @tb's REP self-loop sub-template lazily on first
     * demand from the chain-finalize path.  No-op when @tb's
     * terminator is not a REP string op, or when rep_subtmpl is
     * already populated.  Deferring the build to first use (instead
     * of running it for every TB during translation) avoids paying
     * the cost for TBs that never run inside an active trace
     * segment, AND avoids leaving stale rep_subtmpl pointers behind
     * across segment switches — the only consumer (emit_body_entry's
     * REP fan-out) runs while the segment owning the sub-template is
     * still live. */
    void ensure_rep_subtmpl(BBTemplate *tb);

    /* Shared existing-true-BB handling for commit_true_bb and its
     * reference variant: returns the cached template (logging a
     * one-shot SMC/divergence warning if the insn-pc sequence
     * differs) or nullptr on a true miss.  Compares only insn_pcs;
     * templates are stored in true execution order so the comparison
     * is direct. */
    BBTemplate *find_existing_true_bb(uint64_t start_pc,
                                      uint32_t n_insns,
                                      const uint64_t *insn_pcs);

    /* Persistent set of per-translation templates (one BBTemplatePtr per
     * TB fragment), never freed on tb_flush.  Owned here for the whole
     * run; deduped via tb_chain_dedup_ so a re-translation reuses the
     * existing chain instead of appending a duplicate. */
    std::vector<BBTemplatePtr>                  tb_templates_;
    /* Dedup index: TB start_pc -> heads of already-built fragment chains
     * (one per distinct canonical length seen at that PC — sibling
     * translations of the same start_pc can differ in length, e.g. a
     * full-BB correct-path TB vs a wrong-path TB that entered mid-block or
     * stopped at a different branch terminator).  lookup_tb_chain matches on
     * total canonical insn count so they never conflate. */
    std::unordered_map<uint64_t, std::vector<BBTemplate *>> tb_chain_dedup_;
    std::unordered_map<uint64_t, BBTemplatePtr> bb_map_;
    uint32_t                                    next_template_id_ = 1;
};

extern BBTemplateCache g_bb_template_cache;

#endif /* CHAMPSIM_TRACER_BB_TEMPLATE_CACHE_H */
