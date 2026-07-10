/*
 * Wrong-Path Tracing Plugin — TemplateStore.
 *
 * Naming note: the class is TemplateStore (it owns template lifetime,
 * not just caching), but the file keeps its historical
 * champsim_tracer_bb_template_cache.* name so build entries and diffs
 * stay stable.
 *
 * Owns two distinct stores of BBTemplate records:
 *   - tb_templates_: per-translation TB templates, pure ownership (no
 *     start_pc lookup).  Each QEMU translation creates (or dedup-reuses)
 *     an entry and the template pointer is handed to that QEMU TB as its
 *     per-TB exec-cb udata.  vcpu_tb_exec reads it back directly on
 *     both CP and WP paths, so distinct CP-mode and WP-mode QEMU
 *     translations of the same start_pc cannot conflate.  Lifetime is
 *     class-split (TmplLife): CODE templates persist for the run;
 *     SPEC templates are reclaimed at tb_flush.
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

#include <cstdio>
#include <functional>
#include <memory>
#include <unordered_map>
#include <unordered_set>

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

class TemplateStore {
public:
    TemplateStore() = default;
    ~TemplateStore() = default;

    TemplateStore(const TemplateStore &) = delete;
    TemplateStore &operator=(const TemplateStore &) = delete;

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

    /* SPEC-lifetime template reclaim (#91): see TmplLife.
     * set_creating_spec selects the lifetime class of templates built by
     * the CURRENT translation (called by vcpu_tb_trans with its spec
     * flag; SPEC for a wrong-path translation, CODE otherwise).
     * spec_pending_bytes is the estimated footprint of SPEC templates
     * created since the last reclaim — the proactive-flush trigger.
     * reclaim_spec_templates frees every template still in the SPEC
     * class; call it ONLY from the tb_flush callback (all owning QEMU
     * TBs are gone, wrong-path walks have unwound).  Returns the number
     * of templates freed. */
    void set_creating_spec(bool spec);
    uint64_t spec_pending_bytes() const { return spec_pending_bytes_; }
    void note_spec_creation(uint64_t bytes) { spec_pending_bytes_ += bytes; }
    uint64_t reclaim_spec_templates(void);

    /* CST_MEMSTATS: print a footprint breakdown of the template store to
     * @out — template counts, per-array byte totals (insn_fields dominates:
     * sizeof(InsnFields) is KBs because of the fixed 64-slot dep/lane mask
     * arrays), and the tb_chain_dedup_ duplicate-chain histogram (how many
     * PCs carry >1 sibling chain = dedup misses accumulating duplicates
     * across tb_flush cycles).  Diagnostic for the multi-GiB heap baseline. */
    void mem_stats(FILE *out) const;

    /* Pure: return the index of the (last) branch instruction within
     * @tmpl, or -1 if @tmpl has no branch.  After delay-slot
     * normalization the branch is always the last instruction. */
    static int template_branch_index(const BBTemplate *tmpl);

    /* Drop all true-BB templates so the next segment serializes only
     * BBs reached after this point.  tb_templates_ is preserved
     * across segment switches: each QEMU TB carries its template via
     * the per-TB exec-cb udata for the QEMU TB's lifetime, and
     * clearing the ownership list would leave that udata dangling.
     * Bumps the segment generation, which invalidates every SegRef
     * into the dropped store at its next deref — no invalidation walk
     * over the persistent translations. */
    void clear_bb_map();

    /* SegRef mint/deref pair for references into bb_map_ (see SegRef).
     * seg_ref stamps the store's current segment generation; seg_deref
     * yields the pointee only while that generation is still current —
     * a stale handle reads as nullptr, exactly like the pre-handle
     * "field was reset at segment switch" contract.  Inline: the REP
     * fan-out derefs on the body-emit hot path. */
    SegRef seg_ref(BBTemplate *t) const
    {
        return SegRef{t, segment_gen_};
    }
    BBTemplate *seg_deref(const SegRef &r) const
    {
        return r.seg_gen == segment_gen_ ? r.ptr : nullptr;
    }

    /* Dedup support for the persistent per-translation store.  CODE
     * templates are NEVER freed on tb_flush: a flush just re-translates
     * the same code, so the matching chain is reused instead.  This keeps
     * every per-insn-callback udata (RegSnapInsnRef inside a template)
     * valid for the QEMU TB's whole lifetime without any flush-time
     * reclamation — the trace is flush-invariant by construction, because
     * a flush changes nothing in the plugin's state.
     *
     * lookup_tb_chain returns the head fragment of an already-built chain
     * for a TB starting at @tb_start_pc with @total_n_insns canonical
     * insns whose per-insn sizes/bytes match @insn_sizes / @insn_bytes
     * (canonical layout, MAX_INSN_BYTES stride, zero-padded), or
     * nullptr on a miss.  Byte identity is VERIFIED here, not assumed
     * from the caller's poison gate: that gate follows the
     * "correct path is ground truth" rule and refreshes its
     * first-sighting cache when CP bytes change, so guest code
     * patching — canonically the x86 kernel's boot-time alternatives
     * rewriting `jmp __x86_return_thunk` into `ret` at the same VA
     * with the same canonical insn count — would otherwise reuse the
     * stale pre-patch chain and serialize templates whose bytes the
     * guest no longer executes (surfaced by the impossible-attribution
     * lint as return-address pops riding on "jmp" templates).  The
     * lookup consults the CODE index first, then
     * the SPEC index: chains of both lifetime classes are visible from
     * creation (register_tb_chain routes on the chain's class), so a CP
     * translation adopts a chain the wrong path minted first — the
     * common shape for code WP discovers before CP reaches it (spec
     * translations are full multi-insn TBs) — and a WP translation
     * reuses real code's chain.  Memory is bounded by the segment's
     * distinct-translation footprint (code size), not execution length;
     * SMC produces a new entry and leaves the dead one in place (rare,
     * bounded, never dereferenced once its QEMU TB is gone). */
    BBTemplate *lookup_tb_chain(uint64_t tb_start_pc, uint32_t total_n_insns,
                                const uint8_t *insn_sizes,
                                const uint8_t *insn_bytes);
    void        register_tb_chain(uint64_t tb_start_pc, BBTemplate *head);

    /* Correct-path execution notice for the chain headed by @head (the
     * per-TB exec-cb udata).  Converts every sibling fragment on the
     * next_tb_fragment chain SPEC→CODE — code the correct path really
     * runs is real code whose pointers may sit in deferred prev/chain
     * state across a flush, and whose decode is worth keeping for
     * re-translation dedup — and enters the chain into the CODE index.
     * This is the ONLY SPEC→CODE transition; whole-chain conversion
     * makes a mixed-class chain impossible by construction.  The
     * chain's now-stale SPEC-index entry is left in place: harmless,
     * since lookups prefer the CODE index and reclaim drops the SPEC
     * index wholesale.  Idempotent (chain_indexed guards re-insertion);
     * caller holds data_lock. */
    void promote(BBTemplate *head);

private:
    /* Materialize @tb's REP self-loop sub-template lazily on first
     * demand from the chain-finalize path.  No-op when @tb's
     * terminator is not a REP string op, or when rep_subtmpl is
     * already live in the current segment.  Deferring the build to
     * first use (instead of running it for every TB during
     * translation) avoids paying the cost for TBs that never run
     * inside an active trace segment; a handle left over from a
     * previous segment is stale by generation and simply rebuilt
     * here — the only consumer (emit_body_entry's REP fan-out) runs
     * while the segment owning the sub-template is still live. */
    void ensure_rep_subtmpl(BBTemplate *tb);

    /* CST_LIFE_AUDIT (env-gated) boundary checks: walk the surviving
     * stores after a lifetime boundary and abort with a report if any
     * survivor still references reclaimed memory.  after_reclaim
     * verifies no surviving fragment's next_tb_fragment or SegRef
     * targets a freed SPEC template and that survivors are uniformly
     * CODE (whole-chain promotion makes mixed chains impossible by
     * construction — this proves it live).  after_clear verifies no
     * persistent template holds a SegRef stamped with the CURRENT
     * (just-bumped) generation, i.e. nothing can deref into the
     * dropped bb_map_.  Pointer-value comparisons only; freed memory
     * is never dereferenced. */
    void life_audit_after_reclaim(
        const std::unordered_set<const BBTemplate *> &freed) const;
    void life_audit_after_clear() const;

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
    /* CODE-class dedup index: TB start_pc -> heads of already-built
     * fragment chains (one per distinct canonical length seen at that
     * PC — sibling translations of the same start_pc can differ in
     * length, e.g. a full-BB correct-path TB vs a wrong-path TB that
     * entered mid-block or stopped at a different branch terminator).
     * lookup_tb_chain matches on total canonical insn count so they
     * never conflate.  Holds CODE chains only (CODE-born at creation,
     * SPEC-born on promotion), so reclaim never touches it. */
    std::unordered_map<uint64_t, std::vector<BBTemplate *>> tb_chain_dedup_;
    /* SPEC-class twin of tb_chain_dedup_, populated at creation for
     * SPEC-born chains and dropped WHOLESALE by reclaim_spec_templates
     * — correct because reclaim frees every still-SPEC chain, and an
     * adopted (promoted) chain lives on in the CODE index.  A promoted
     * chain's entry here goes stale rather than being erased; lookups
     * prefer the CODE index, so the stale entry only ever resolves to
     * the same head, and it vanishes at the next reclaim.  This split
     * is what lets reclaim be a pure partition: no per-chain index
     * surgery, ever. */
    std::unordered_map<uint64_t, std::vector<BBTemplate *>> spec_chain_index_;
    std::unordered_map<uint64_t, BBTemplatePtr> bb_map_;
    uint32_t                                    next_template_id_ = 1;
    uint64_t                                    spec_pending_bytes_ = 0;
    /* Current bb_map_ generation, bumped by clear_bb_map at every
     * segment switch.  Starts at 1 so a zero-initialized SegRef is
     * stale from birth.  Store-owned (not the global
     * g_segment_generation): handle validity is a property of THIS
     * store's clear cycle, and coupling it to the window manager's
     * counter would make deref correctness depend on reset ordering
     * at the segment boundary. */
    uint32_t                                    segment_gen_ = 1;
};

/* Immortal reference — see the definition's lifetime note. */
extern TemplateStore &g_template_store;

#endif /* CHAMPSIM_TRACER_BB_TEMPLATE_CACHE_H */
