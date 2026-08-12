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
#include <vector>

#include "champsim_tracer.h"

struct BBTemplateDeleter {
    void operator()(BBTemplate *t) const noexcept;
};

using BBTemplatePtr = std::unique_ptr<BBTemplate, BBTemplateDeleter>;

/*
 * Multi-ASID cache key: a template (and its dedup chains) is identified by
 * the pair (asid_root, start_pc), NOT by start_pc alone.  Two owned
 * processes routinely map distinct code at the SAME virtual address (every
 * static binary loads its .text at the same low VA), so a start_pc-only key
 * conflates them — the second process's block is misattributed to the
 * first's template.  asid_root is the CODE's live translation address-space
 * id (qemu_plugin_get_addr_space_id(), the same value the per-entry memory
 * dimension resolves from); a single address space is all root 0, so this
 * partitions bit-identically to the old start_pc key and single-process
 * traces stay byte-identical.
 *
 * KERNEL code is the one exception (KPTI-off canonical model, multiasid_plan
 * §7): kernel-privilege translations key with CST_KERNEL_ASID_ROOT — a
 * single SHARED kernel bucket — instead of the live process root.  The kernel
 * is one physical instance; keying it by the entering process's root would
 * mint a duplicate template per process for the same kernel code.  Kernel VAs
 * never collide with user VAs (disjoint ranges, maintainer-guaranteed), so
 * the sentinel bucket is collision-safe against every user (asid_root,
 * start_pc).  store_live_asid_root() picks the sentinel from the live
 * privilege level. */
static constexpr uint64_t CST_KERNEL_ASID_ROOT = ~(uint64_t)0;

struct BBKey {
    uint64_t asid_root;
    uint64_t start_pc;
    bool operator==(const BBKey &o) const
    {
        return asid_root == o.asid_root && start_pc == o.start_pc;
    }
};

/* Key for a block whose execution was cut short: the slot it belongs to plus
 * the extent that actually ran.  Two truncations of one block at different
 * points are two different blocks and must not share a template. */
struct PartialKey {
    uint64_t asid_root;
    uint64_t start_pc;
    uint32_t n_insns;
    /* Content signature, so a pc whose BYTES changed under a truncation of
     * the same length gets its own template instead of silently adopting
     * the earlier state's. */
    uint64_t sig;
    bool operator==(const PartialKey &o) const
    {
        return asid_root == o.asid_root && start_pc == o.start_pc &&
               n_insns == o.n_insns && sig == o.sig;
    }
};

struct PartialKeyHash {
    size_t operator()(const PartialKey &k) const
    {
        uint64_t h = k.asid_root + 0x9e3779b97f4a7c15ULL;
        h ^= k.start_pc + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= (uint64_t)k.n_insns + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= k.sig + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= h >> 30;
        h *= 0xbf58476d1ce4e5b9ULL;
        h ^= h >> 27;
        return (size_t)h;
    }
};

struct BBKeyHash {
    size_t operator()(const BBKey &k) const
    {
        /* Mix the two 64-bit halves (splitmix-style finaliser on a
         * boost::hash_combine of the pair) so nearby start_pcs under one
         * asid, and one start_pc across asids, both scatter. */
        uint64_t h = k.asid_root + 0x9e3779b97f4a7c15ULL;
        h ^= k.start_pc + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= h >> 30;
        h *= 0xbf58476d1ce4e5b9ULL;
        h ^= h >> 27;
        return (size_t)h;
    }
};

/*
 * Self-modifying-code (SMC) revision key: a (asid_root, start_pc) slot plus
 * the FNV content signature of a specific executed program-text STATE at that
 * pc.  When correct-path code re-executes with different bytes at a pc the
 * tracer already committed, the store mints a new template revision (a fresh
 * template_id) and remembers the retired one by this key, so a state the guest
 * later restores (inline-cache A/B/A patching) reuses its original id rather
 * than minting an unbounded chain of revisions.  See smc_plan.md §1.3. */
struct RevKey {
    uint64_t asid_root;
    uint64_t start_pc;
    uint64_t content_sig;
    bool operator==(const RevKey &o) const
    {
        return asid_root == o.asid_root && start_pc == o.start_pc &&
               content_sig == o.content_sig;
    }
};

struct RevKeyHash {
    size_t operator()(const RevKey &k) const
    {
        uint64_t h = k.asid_root + 0x9e3779b97f4a7c15ULL;
        h ^= k.start_pc + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= k.content_sig + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= h >> 30;
        h *= 0xbf58476d1ce4e5b9ULL;
        h ^= h >> 27;
        return (size_t)h;
    }
};

/* Per-(asid_root, start_pc) SMC bookkeeping: how many DISTINCT executed states
 * have minted a revision at this pc (the cap backstop, smc_plan.md §5-A), and
 * whether the overflow warning has already fired this segment (LOUD once per
 * segment, §5-B).  Segment-scoped: cleared with bb_map_. */
struct RevisionSlot {
    uint32_t distinct = 0;
    bool     overflow_warned = false;
};

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

    /* True basic blocks.  Keyed by (asid_root, entry_pc): the caller
     * supplies the live translation address-space id so a shared code VA
     * in two owned processes resolves to each process's own template. */
    BBTemplate *find_bb_template(uint64_t asid_root, uint64_t entry_pc);
    /*
     * The COMPLETE cached block that begins with exactly @cut's
     * instructions and extends beyond them, or nullptr.
     *
     * @cut is a force-committed translation-cut head: a TB whose
     * translator stopped at an instruction it knew would raise (a MIPS
     * coprocessor-unusable store, an x86 #NM shape), so the committed
     * template ends AT the faulting instruction instead of at the
     * block's terminal branch.  The fault fold substitutes the cached
     * whole block when one exists so the frame's continuation can cover
     * the resumed suffix (docs/format.rst: prefix and continuation must
     * name one template, and the chain must end at num_insns).  Guards:
     * strictly longer, byte-identical over @cut's extent, and carrying a
     * terminal branch AT or PAST the cut boundary — a cached template
     * that is itself a shorter-lived cut fails the last guard rather
     * than substituting a second lie.  Caller holds data_lock.
     */
    BBTemplate *whole_block_covering(const BBTemplate *cut);
    /* The cache key's asid_root is selected from @start_pc by the
     * architectural VA classifier (kernel-VA code → the shared kernel
     * sentinel bucket, user-VA code → the live process root; see BBKey /
     * store_asid_root).  Path-independent and speculation-proof: a wrong-path
     * commit of kernel code joins the shared template, and a user VA can never
     * reach the sentinel regardless of any is_system mis-stamp. */
    BBTemplate *commit_true_bb(uint64_t start_pc,
                               uint32_t n_insns,
                               const uint64_t *insn_pcs,
                               const InsnFields *insn_fields,
                               const uint8_t *insn_sizes,
                               const uint8_t *insn_bytes,
                               const InsnRegNames *insn_reg_names,
                               const char *symbol_name,
                               uint64_t fall_through_pc,
                               bool cp_confirmed);
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
                                    uint64_t fall_through_pc,
                                    bool cp_confirmed,
                                    bool *out_extent_only = nullptr);
    BBTemplate *get_or_create_bb_template(uint64_t entry_pc,
                                          BBTemplate *const *fragments,
                                          unsigned int n_fragments);

    /*
     * Assemble a block the guest ENTERED AND DID NOT FINISH: @fragments as
     * usual, except the last one contributes only its first
     * @last_frag_insns instructions.  @last_frag_insns == 0 means the whole
     * last fragment ran and only the BB itself is partial (no terminating
     * branch was reached).
     *
     * This is the alternative to the two things the tracer used to do with
     * such a block, both of them wrong: emit it at its full TRANSLATED
     * length (instructions on the wire that never executed) or throw the
     * whole chain away (instructions that executed and never reached the
     * wire).  The template goes to partial_bb_map_, keyed by extent, so it
     * can never be confused with — or displaced by — the complete block at
     * the same pc.  Caller holds data_lock.  nullptr if nothing ran.
     */
    BBTemplate *commit_partial_bb(uint64_t entry_pc,
                                  BBTemplate *const *fragments,
                                  unsigned int n_fragments,
                                  uint32_t last_frag_insns);
    /* Templates in partial_bb_map_ — serialised alongside bb_map_. */
    size_t partial_bb_count() const { return partial_bb_map_.size(); }

    /* Install a block at the extent that ran; see the definition.  Reuses
     * the complete block when the extents agree.  Caller holds data_lock. */
    BBTemplate *install_own_extent(uint64_t entry_pc, uint32_t n_insns,
                                   const uint64_t *insn_pcs,
                                   const InsnFields *insn_fields,
                                   const uint8_t *insn_sizes,
                                   const uint8_t *insn_bytes,
                                   const InsnRegNames *insn_reg_names,
                                   const char *symbol_name,
                                   uint64_t fall_through_pc,
                                   bool is_system, bool stamp_system);

    /* Opportunistic branch-alternate minting (static_templates=1, both
     * modes).  Mint a never-executed true-BB template into the
     * segment-scoped alt_map_ — a sibling of bb_map_, keyed by the same
     * (asid_root, start_pc).  Carries NO wire flag (life CODE, so
     * write_insn_descriptors stamps nothing extra): an alternate is an
     * ordinary never-executed dictionary entry, indistinguishable on the
     * wire from any other block that happened not to execute.  It does NOT
     * consume the executed-template id counter (placeholder id 0; the
     * serialised id is assigned lazily by for_each_alt above every executed
     * id) so executed blocks number exactly as they would with the feature
     * off — the trace body stays byte-identical.  Dedups within alt_map_ by
     * (asid_root, start_pc); a re-mint of the same block is idempotent.
     * Caller holds data_lock.  Returns the (possibly pre-existing) record. */
    BBTemplate *commit_alt_bb(uint64_t start_pc,
                              uint32_t n_insns,
                              const uint64_t *insn_pcs,
                              const InsnFields *insn_fields,
                              const uint8_t *insn_sizes,
                              const uint8_t *insn_bytes,
                              const InsnRegNames *insn_reg_names,
                              const char *symbol_name,
                              uint64_t fall_through_pc);

    /* True iff @start_pc's true BB is already covered by an executed
     * (bb_map_) or a previously-minted alternate (alt_map_) template — the
     * opportunistic-mint miss test (skip the decode when either wins).  The
     * cache key's asid_root is selected from @start_pc by the VA-domain
     * classifier, exactly as commit_alt_bb / commit_true_bb.  Caller holds
     * data_lock. */
    bool alt_or_bb_covered(uint64_t start_pc) const;

    size_t tb_count() const;
    size_t bb_count() const;
    /* Count of retired SMC revisions across all (asid_root, start_pc) slots —
     * displaced-but-still-serialised templates.  Zero unless code
     * self-modifies, so a non-SMC trace's template count (and wire bytes) is
     * unchanged.  Added to the templates-section count alongside bb_count(). */
    size_t retired_revision_count() const;
    /* Count of alt_map_ templates that WOULD serialise: those whose
     * (asid_root, start_pc) key is not shadowed by an executed bb_map_
     * entry (a block that ran is carried by bb_map_; dynamic wins over the
     * flag-less alternate). */
    size_t alt_serialisable_count() const;

    /* Iterate true-BB templates in sorted start_pc order (deterministic
     * serialization).  Invoked once at end-of-trace by the writer. */
    void for_each_bb(const std::function<void(BBTemplate &)> &fn);

    /* Iterate the serialisable alternate templates (alt_map_ entries not
     * shadowed by an executed bb_map_ template) in sorted start_pc order,
     * assigning each a fresh wire template_id from @next_id (post-incremented)
     * just before @fn runs.  Alternate ids are section-local and referenced
     * by nothing, so @next_id must start above every executed id already
     * written in this segment's templates section to avoid a same-section
     * collision.  Caller supplies that high base.  Invoked by the writer
     * after for_each_bb. */
    void for_each_alt(uint32_t &next_id,
                      const std::function<void(BBTemplate &)> &fn);

    /* Diagnostic: dump a per-bucket census of the serialisable true-BB
     * cache (bb_map_) to @out, splitting the shared kernel sentinel bucket
     * from the per-process root buckets and CODE vs SPEC lifetime, and
     * quantifying kernel-code duplication (distinct kernel start_pcs vs
     * kernel templates).  Gated by CST_TMPL_CENSUS at the call site; must
     * run before clear_bb_map drops the segment's templates. */
    void census(std::FILE *out) const;

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

    /* Drop @asid_root's (asid_root, *) entries from the per-class chain
     * dedup indices when its trace window closes (its END marker / removal
     * from the owned set), so the dedup index does not accumulate one
     * bucket per address space across many disparate ASIDs.  These buckets
     * cache only lookup_tb_chain's "already translated" shortcut and are
     * not serialised, so dropping them is wire-neutral and frees no
     * fragment (the pointers index tb_templates_, which persists).
     *
     * The closed process's true-BB templates (bb_map_) are NOT freed here:
     * the templates section is serialised once at segment finish and every
     * emitted body entry references its template_id, so freeing an emitted
     * template mid-segment dangles those references — emitted templates
     * live until clear_bb_map at the segment boundary.  tb_templates_
     * fragments likewise stay pinned by live QEMU exec-cb udata until a
     * tb_flush (reclaim_spec_templates).  Within a segment, template memory
     * is bounded by the window's distinct-code footprint, not by process
     * turnover.  Returns the number of dedup buckets dropped.  Caller holds
     * data_lock. */
    uint64_t reclaim_asid(uint64_t asid_root);

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
     * is direct.  @asid_root scopes the lookup to the executing address
     * space (see BBKey). */
    BBTemplate *find_existing_true_bb(uint64_t asid_root,
                                      uint64_t start_pc,
                                      uint32_t n_insns,
                                      const uint64_t *insn_pcs);

    /*
     * SMC revision resolver — the shared front-end for both commit_true_bb
     * variants (smc_plan.md §1).  Given the incoming canonical arrays for a
     * (asid_root, start_pc) slot, decide whether to REUSE an existing template
     * or BUILD a fresh one:
     *
     *   - returns a non-null BBTemplate*  -> reuse it, do not build.  Covers
     *       the byte-identical hot path, the length/prefix-divergence
     *       "keep original" legacy path, the wrong-path speculation guard
     *       (spec never versions), the content-signature A/B/A reuse of a
     *       retired revision, and the cap-overflow degrade.
     *   - returns nullptr                 -> the caller must build a fresh
     *       template and hand it to install_live_revision(@key, tmpl,
     *       *out_sig).  Covers a first sighting and a newly-minted revision;
     *       for a revision the current live template has ALREADY been retired
     *       here so the caller's install just re-populates the live slot.
     *
     * Revisions mint ONLY when @cp_confirmed and the superseded live template
     * was itself CP-confirmed — a wrong-path/spec translation, or the very
     * first CP confirmation of a WP-seeded block, never versions (the
     * established mis-stamp guard, §1.4).  Caller holds data_lock. */
    BBTemplate *resolve_true_bb(const BBKey &key, uint32_t n_insns,
                                const uint64_t *insn_pcs,
                                const uint8_t *insn_sizes,
                                const uint8_t *insn_bytes,
                                bool cp_confirmed, uint64_t *out_sig,
                                bool *out_extent_only = nullptr);
    /* Insert @tmpl as the live revision of @key and index it by @sig for a
     * future A/B/A return.  Bumps the slot's distinct-state count. */
    void install_live_revision(const BBKey &key, BBTemplatePtr tmpl,
                               uint64_t sig);
    /* Move @key's current live template into the retired stash (still
     * serialised; body entries pin it).  The live slot is emptied so the
     * caller's install re-populates it. */
    void retire_live_revision(const BBKey &key);
    /* Make retired revision @prior the live one for @key, retiring whatever
     * was live — the A/B/A content-signature swap. */
    void swap_live_revision(const BBKey &key, BBTemplate *prior);
    /* One-shot per-segment LOUD overflow warning + stats when @key exceeds the
     * revision cap (smc_plan.md §5-B). */
    void note_revision_overflow(const BBKey &key, RevisionSlot &slot);

    /* Persistent set of per-translation templates (one BBTemplatePtr per
     * TB fragment), never freed on tb_flush.  Owned here for the whole
     * run; deduped via tb_chain_dedup_ so a re-translation reuses the
     * existing chain instead of appending a duplicate. */
    std::vector<BBTemplatePtr>                  tb_templates_;
    /* CODE-class dedup index: (asid_root, TB start_pc) -> heads of
     * already-built fragment chains (one per distinct canonical length
     * seen at that PC — sibling translations of the same start_pc can
     * differ in length, e.g. a full-BB correct-path TB vs a wrong-path TB
     * that entered mid-block or stopped at a different branch terminator).
     * lookup_tb_chain matches on total canonical insn count so they
     * never conflate.  The asid_root component is what keeps two owned
     * processes sharing a code VA from adopting each other's fragment
     * chain.  Holds CODE chains only (CODE-born at creation, SPEC-born on
     * promotion), so reclaim_spec_templates never touches it. */
    std::unordered_map<BBKey, std::vector<BBTemplate *>, BBKeyHash>
        tb_chain_dedup_;
    /* SPEC-class twin of tb_chain_dedup_, populated at creation for
     * SPEC-born chains and dropped WHOLESALE by reclaim_spec_templates
     * — correct because reclaim frees every still-SPEC chain, and an
     * adopted (promoted) chain lives on in the CODE index.  A promoted
     * chain's entry here goes stale rather than being erased; lookups
     * prefer the CODE index, so the stale entry only ever resolves to
     * the same head, and it vanishes at the next reclaim.  This split
     * is what lets reclaim be a pure partition: no per-chain index
     * surgery, ever.  Keyed by (asid_root, start_pc), as tb_chain_dedup_. */
    std::unordered_map<BBKey, std::vector<BBTemplate *>, BBKeyHash>
        spec_chain_index_;
    /* True-BB templates, keyed by (asid_root, start_pc) — what the
     * trace's templates section serialises.  The asid_root key is Bug-A's
     * fix: a shared code VA in two owned processes now lands two distinct
     * templates instead of the second block silently adopting the first. */
    std::unordered_map<BBKey, BBTemplatePtr, BBKeyHash> bb_map_;
    /* Segment-scoped never-executed true-BB templates minted opportunistically
     * at branch evaluation (static_templates=1, both modes) for the UNTAKEN
     * side of a branch not already templated, and — with static_depth>0 —
     * their statically-known successors.  Keyed by (asid_root, start_pc) like
     * bb_map_.  Serialised (by for_each_alt) as ordinary dictionary entries
     * carrying NO wire flag, for the subset NOT shadowed by an executed
     * bb_map_ key.  Dropped wholesale by clear_bb_map at the segment boundary.
     * Empty (and inert) unless the feature runs, so a trace without it is
     * byte-identical. */
    std::unordered_map<BBKey, BBTemplatePtr, BBKeyHash> alt_map_;
    /*
     * Blocks whose EXECUTION was cut short — the guest entered the block and
     * something ended it before its last instruction: the END marker closing
     * the window, a ceiling, a control-flow discontinuity that abandoned the
     * chain mid-BB.
     *
     * They cannot live in bb_map_.  That map is keyed by (asid_root,
     * start_pc) only, and resolve_true_bb classifies a shorter run of the
     * same byte-identical code as EXTENT_ONLY and deliberately returns the
     * LONGER committed template — so a block that ran five instructions
     * would be emitted claiming eight, which is precisely the over-claim
     * this store exists to stop.  Keyed here by extent as well, so the same
     * pc truncated at the same point reuses one template (a fork storm's
     * repeated cut at one pc mints one entry, not one per occurrence) and a
     * different extent gets its own.  Serialised by for_each_bb alongside
     * bb_map_ and the retired revisions; dropped wholesale by clear_bb_map.
     * Empty — and every dependent path inert — on a run where nothing is
     * ever cut short.
     */
    std::unordered_map<PartialKey, BBTemplatePtr, PartialKeyHash>
        partial_bb_map_;
    /* Retired SMC revisions, per (asid_root, start_pc): templates a newer
     * correct-path revision displaced from bb_map_.  They keep their run-
     * assigned template_id and serialise alongside their successors (body
     * entries emitted while they were live reference them), so the wire stays
     * self-consistent.  Segment-scoped: cleared wholesale by clear_bb_map.
     * Empty (and every dependent path inert) unless code self-modifies, so a
     * non-SMC trace is byte-identical. */
    std::unordered_map<BBKey, std::vector<BBTemplatePtr>, BBKeyHash>
        retired_revisions_;
    /* Content-signature index for A/B/A/B state reuse: (asid_root, start_pc,
     * FNV content_sig) -> the template (live or retired) that carries exactly
     * that program-text state, so a mutation returning to a previously-seen
     * state reuses its template_id instead of minting an unbounded chain.
     * Segment-scoped. */
    std::unordered_map<RevKey, BBTemplate *, RevKeyHash> revision_by_sig_;
    /* Per-(asid_root, start_pc) distinct-state count + overflow latch — the
     * cap backstop and its once-per-segment warning.  Segment-scoped. */
    std::unordered_map<BBKey, RevisionSlot, BBKeyHash> revision_slots_;
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
