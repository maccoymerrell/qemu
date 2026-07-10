/*
 * Wrong-Path Tracing Plugin — TemplateStore implementation.
 *
 * Naming note: the class is TemplateStore, but the file keeps its
 * historical champsim_tracer_bb_template_cache.* name so build entries
 * and diffs stay stable.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <algorithm>
#include <atomic>
#include <inttypes.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <unordered_set>
#include <vector>

#include "champsim_tracer_bb_template_cache.h"
#include "champsim_tracer_stats.h"

/* Immortalized (never-destructed heap object): exit(0) at a segment close
 * runs static destructors on the closing vCPU thread while, on an SMP
 * guest, other vCPU threads may still be translating — a survivor inside
 * lookup_tb_chain scanning a store whose containers were just destructed
 * SIGSEGVs (observed: mipsel -smp 2 thread_test, one thread in
 * chain_index_scan racing another in ~vector<unique_ptr<BBTemplate>>).
 * The process is exiting; reclaiming tens of MiB of templates one
 * unique_ptr at a time buys nothing (same policy as VCPUScoreboard). */
TemplateStore &g_template_store = *new TemplateStore();

/* Per-thread: is the translation currently being templated a wrong-path
 * (spec-mode) one?  Thread-local because translations run on each vCPU's
 * own thread; a plain member would cross-mislabel under MTTCG. */
static thread_local bool tls_creating_spec = false;

void TemplateStore::set_creating_spec(bool spec)
{
    tls_creating_spec = spec;
}

/* Stable zeroed sentinel: a fragment may lack insn_reg_names while
 * reg-data is enabled; the by-reference commit points such slots
 * here so every regnames pointer is valid and reads as all-zero. */
/* Shared all-NULL key span (declared in champsim_tracer.h): readers index
 * empty/sentinel reg-name tables with the SIBLING InsnFields' real counts,
 * so the sentinel spans must be dereferenceable up to MAX_*_REGS. */
const QemuRegKey *g_zero_regkeys[MAX_SRC_REGS];
static const InsnRegNames kCacheEmptyRegNames{g_zero_regkeys, g_zero_regkeys};

void BBTemplateDeleter::operator()(BBTemplate *t) const noexcept
{
    if (!t) {
        return;
    }
    g_free(t->insn_fields);
    g_free(t->insn_fields_pool);
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

BBTemplate *TemplateStore::find_bb_template(uint64_t entry_pc)
{
    auto it = bb_map_.find(entry_pc);
    return it == bb_map_.end() ? nullptr : it->second.get();
}

size_t TemplateStore::tb_count() const
{
    return tb_templates_.size();
}

/* CST_LIFE_AUDIT: opt-in debug boundary audit (see the header). */
static bool life_audit_enabled(void)
{
    static const bool on = getenv("CST_LIFE_AUDIT") != nullptr;
    return on;
}

void TemplateStore::life_audit_after_reclaim(
    const std::unordered_set<const BBTemplate *> &freed) const
{
    /* Pointer-target checks apply to both stores; the class check only
     * to fragments — a bb_map_ template's lifetime IS its bb_map_
     * membership, and one committed during a wrong-path walk can carry
     * a SPEC birth-stamp without ever being reclaim-eligible. */
    auto check_targets = [&](const BBTemplate *t, const char *store) {
        if (t->next_tb_fragment && freed.count(t->next_tb_fragment)) {
            fprintf(stderr, "champsim_tracer: LIFE_AUDIT violation: "
                    "%s survivor pc=0x%" PRIx64 " sibling link targets a "
                    "reclaimed fragment\n", store, t->start_pc);
            abort();
        }
        if ((t->parent_true_bb.ptr && freed.count(t->parent_true_bb.ptr)) ||
            (t->rep_subtmpl.ptr && freed.count(t->rep_subtmpl.ptr))) {
            fprintf(stderr, "champsim_tracer: LIFE_AUDIT violation: "
                    "%s survivor pc=0x%" PRIx64 " SegRef targets a "
                    "reclaimed fragment\n", store, t->start_pc);
            abort();
        }
    };
    for (const auto &p : tb_templates_) {
        if (!p) {
            continue;
        }
        if (p->life != TmplLife::CODE) {
            fprintf(stderr, "champsim_tracer: LIFE_AUDIT violation: "
                    "fragment survivor pc=0x%" PRIx64
                    " not CODE after reclaim\n", p->start_pc);
            abort();
        }
        /* Membership checks run BEFORE the sibling class check: the
         * latter dereferences next_tb_fragment, which is only safe
         * once it is known not to be a freed pointer. */
        check_targets(p.get(), "tb_templates");
        if (p->next_tb_fragment &&
            p->next_tb_fragment->life != TmplLife::CODE) {
            fprintf(stderr, "champsim_tracer: LIFE_AUDIT violation: "
                    "fragment survivor pc=0x%" PRIx64
                    " sibling link targets a SPEC fragment\n", p->start_pc);
            abort();
        }
    }
    for (const auto &kv : bb_map_) {
        if (kv.second) {
            check_targets(kv.second.get(), "bb_map");
        }
    }
}

void TemplateStore::life_audit_after_clear() const
{
    for (const auto &p : tb_templates_) {
        if (!p) {
            continue;
        }
        if ((p->parent_true_bb.ptr &&
             p->parent_true_bb.seg_gen == segment_gen_) ||
            (p->rep_subtmpl.ptr &&
             p->rep_subtmpl.seg_gen == segment_gen_)) {
            fprintf(stderr, "champsim_tracer: LIFE_AUDIT violation: "
                    "fragment pc=0x%" PRIx64 " holds a current-generation "
                    "SegRef right after clear_bb_map\n", p->start_pc);
            abort();
        }
    }
}

void TemplateStore::clear_bb_map()
{
    bb_map_.clear();
    /* TB templates hold two back-edges into the store just dropped —
     * parent_true_bb (fast-path link to the assembled true-BB) and
     * rep_subtmpl (the 1-insn REP self-loop true-BB for x86 REP
     * string ops).  Both are SegRef handles: bumping the generation
     * invalidates every one of them at its next deref, with no walk
     * over the persistent translations. */
    segment_gen_++;
    /*
     * Reset template-id counter so each segment starts at id 1; else
     * ids accumulate across segments and the fresh FieldStateTable's
     * per-id vector grows past unused prior-segment slots on first hit.
     * Wire format unaffected — ids are intra-segment deltas and each
     * segment opens a new TEMPLATES section.
     */
    next_template_id_ = 1;
    if (life_audit_enabled()) {
        life_audit_after_clear();
    }
}

/* Scan one class index for a chain at @tb_start_pc totalling
 * @total_n_insns canonical insns with byte-identical content.
 * @insn_sizes / @insn_bytes carry the candidate TB's canonical view
 * (MAX_INSN_BYTES stride, zero-padded); a chain whose count matches
 * but whose bytes differ is guest-patched code sharing the VA and
 * must NOT be reused (see the lookup_tb_chain header comment). */
static BBTemplate *chain_index_scan(
    const std::unordered_map<uint64_t, std::vector<BBTemplate *>> &index,
    uint64_t tb_start_pc, uint32_t total_n_insns,
    const uint8_t *insn_sizes, const uint8_t *insn_bytes)
{
    auto it = index.find(tb_start_pc);
    if (it == index.end()) {
        return nullptr;
    }
    for (BBTemplate *head : it->second) {
        uint32_t sum = 0;
        bool same = true;
        for (BBTemplate *f = head; f && same; f = f->next_tb_fragment) {
            if (sum + f->n_insns > total_n_insns) {
                same = false;
                break;
            }
            same = memcmp(f->insn_sizes, &insn_sizes[sum],
                          f->n_insns) == 0 &&
                   memcmp(f->insn_bytes,
                          &insn_bytes[(size_t)sum * MAX_INSN_BYTES],
                          (size_t)f->n_insns * MAX_INSN_BYTES) == 0;
            sum += f->n_insns;
        }
        if (same && sum == total_n_insns) {
            return head;
        }
    }
    return nullptr;
}

BBTemplate *TemplateStore::lookup_tb_chain(uint64_t tb_start_pc,
                                             uint32_t total_n_insns,
                                             const uint8_t *insn_sizes,
                                             const uint8_t *insn_bytes)
{
    /* CODE index first: a promoted chain's SPEC-index entry is left
     * stale (see promote), so the CODE side is the authoritative one
     * whenever both hold the chain. */
    if (BBTemplate *head =
            chain_index_scan(tb_chain_dedup_, tb_start_pc, total_n_insns,
                             insn_sizes, insn_bytes)) {
        return head;
    }
    return chain_index_scan(spec_chain_index_, tb_start_pc, total_n_insns,
                            insn_sizes, insn_bytes);
}

void TemplateStore::register_tb_chain(uint64_t tb_start_pc, BBTemplate *head)
{
    /* Route on the chain's lifetime class so each class is visible to
     * dedup from creation — mint sequences (and with them serialized
     * template ids) are independent of when a chain first executes. */
    if (head->life == TmplLife::SPEC) {
        spec_chain_index_[tb_start_pc].push_back(head);
    } else {
        tb_chain_dedup_[tb_start_pc].push_back(head);
        head->chain_indexed = true;
    }
}

void TemplateStore::promote(BBTemplate *head)
{
    /* Idempotence recheck under data_lock: the caller's pre-lock gate
     * on chain_indexed is racy across vCPUs executing the same TB.
     * CODE-born chains enter the CODE index at registration, so only a
     * SPEC-born chain's first correct-path execution reaches past this
     * check. */
    if (!head || head->chain_indexed) {
        return;
    }
    /* Whole-chain conversion: every sibling fragment of an executed TB
     * shares the TB's fate, so promoting only the head would leave a
     * mixed-class chain for the reclaim to tear apart. */
    for (BBTemplate *f = head; f; f = f->next_tb_fragment) {
        f->life = TmplLife::CODE;
    }
    /* Move the chain's dedup visibility to the CODE index.  The stale
     * SPEC-index entry stays behind (lookups prefer the CODE index;
     * reclaim clears the SPEC index wholesale).  head->start_pc is the
     * TB start_pc (the head fragment begins at canonical insn 0). */
    tb_chain_dedup_[head->start_pc].push_back(head);
    head->chain_indexed = true;
}

size_t TemplateStore::bb_count() const
{
    return bb_map_.size();
}

void TemplateStore::for_each_bb(const std::function<void(BBTemplate &)> &fn)
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

int TemplateStore::template_branch_index(const BBTemplate *tmpl)
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

/*
 * InsnFields span pool (see the SPAN MEMBERS comment in
 * champsim_tracer_mnemonics.h).  Committed templates carry one pool
 * allocation holding the final-count prefixes of every span; empty spans
 * alias the shared zero arrays below so an out-of-count read still returns
 * 0 (bit-identical to the old fixed-array g_new0 semantics).  The arrays
 * are non-const only to keep the span pointer type uniform; nothing writes
 * spans after commit (verified: every writer runs inside
 * decode_detail_to_generic or a .dep_refine it calls, on scratch backing).
 */
static uint64_t g_zero_mask64[MAX_SRC_REGS];
static uint8_t  g_zero_reg8[MAX_SRC_REGS];

/* Pool bytes needed for @f's spans (u64 block first, u8 block padded to 8
 * so per-insn regions stay 8-aligned within one pool allocation). */
static size_t insn_fields_pool_size(const InsnFields *f, bool with_names)
{
    size_t u64s = (size_t)f->n_dst_regs * 2 +        /* dst_dep + dst_lane */
                  (size_t)f->max_dep_stores * 2 +    /* store_data + store_addr */
                  (size_t)f->max_dep_loads +         /* load_addr */
                  (size_t)f->n_src_regs;             /* src_lane */
    size_t keys = with_names
        ? ((size_t)f->n_src_regs + f->n_dst_regs) * sizeof(QemuRegKey *)
        : 0;
    size_t u8s = (size_t)f->n_src_regs + f->n_dst_regs;
    return u64s * sizeof(uint64_t) + keys + ((u8s + 7) & ~(size_t)7);
}

/* Copy @src (any InsnFields with valid spans — a build scratch or an
 * already-committed template) into @dst: scalars by assignment, spans
 * deep-copied into the pool at *@cursor (advanced; caller pre-sized via
 * insn_fields_pool_size).  Count-zero spans alias the shared zero arrays.
 * This is THE commit funnel for span contents; a plain struct assignment
 * would alias the source template's pool across divergent lifetimes. */
static void insn_fields_pack(InsnFields *dst, const InsnFields *src,
                             uint8_t **cursor)
{
    *dst = *src;                    /* scalars; span ptrs overwritten below */
    uint8_t *p = *cursor;
    auto take_u64 = [&p](const uint64_t *sp, unsigned n) -> uint64_t * {
        if (n == 0) {
            return g_zero_mask64;
        }
        uint64_t *d = (uint64_t *)(void *)p;
        memcpy(d, sp, (size_t)n * sizeof(uint64_t));
        p += (size_t)n * sizeof(uint64_t);
        return d;
    };
    auto take_u8 = [&p](const uint8_t *sp, unsigned n) -> uint8_t * {
        if (n == 0) {
            return g_zero_reg8;
        }
        uint8_t *d = p;
        memcpy(d, sp, n);
        p += n;
        return d;
    };
    dst->dst_dep_mask        = take_u64(src->dst_dep_mask, src->n_dst_regs);
    dst->store_data_dep_mask = take_u64(src->store_data_dep_mask,
                                        src->max_dep_stores);
    dst->load_addr_dep_mask  = take_u64(src->load_addr_dep_mask,
                                        src->max_dep_loads);
    dst->store_addr_dep_mask = take_u64(src->store_addr_dep_mask,
                                        src->max_dep_stores);
    dst->src_lane_mask       = take_u64(src->src_lane_mask, src->n_src_regs);
    dst->dst_lane_mask       = take_u64(src->dst_lane_mask, src->n_dst_regs);
    dst->src_regs            = take_u8(src->src_regs, src->n_src_regs);
    dst->dst_regs            = take_u8(src->dst_regs, src->n_dst_regs);
    p = (uint8_t *)(((uintptr_t)p + 7) & ~(uintptr_t)7);
    *cursor = p;
}

/* Names twin of insn_fields_pack: spans sized by the SIBLING InsnFields'
 * counts (parallel arrays).  A NULL source span (defensive) or zero count
 * aliases the shared all-NULL key array, preserving the read-as-NULL
 * semantics sentinel tables rely on. */
static void insn_reg_names_pack(InsnRegNames *dst, const InsnRegNames *src,
                                const InsnFields *f, uint8_t **cursor)
{
    if (!src) {
        dst->src_qemu_reg_keys = g_zero_regkeys;
        dst->dst_qemu_reg_keys = g_zero_regkeys;
        return;
    }
    uint8_t *p = *cursor;
    auto take_keys = [&p](const QemuRegKey *const *sp,
                          unsigned n) -> const QemuRegKey ** {
        if (n == 0 || !sp) {
            return g_zero_regkeys;
        }
        const QemuRegKey **d = (const QemuRegKey **)(void *)p;
        memcpy(d, sp, (size_t)n * sizeof(*d));
        p += (size_t)n * sizeof(*d);
        return d;
    };
    dst->src_qemu_reg_keys = take_keys(src->src_qemu_reg_keys,
                                       f->n_src_regs);
    dst->dst_qemu_reg_keys = take_keys(src->dst_qemu_reg_keys,
                                       f->n_dst_regs);
    *cursor = p;
}

/* Allocate @tmpl's span pool and pack @n sources (parallel to
 * tmpl->insn_fields, already allocated) — shared by the fragment and
 * true-BB creation paths. */
static void insn_fields_pack_all(BBTemplate *tmpl, uint32_t n,
                                 const InsnFields *const *srcs,
                                 const InsnRegNames *const *name_srcs)
{
    bool with_names = tmpl->insn_reg_names != nullptr;
    size_t pool_bytes = 0;
    for (uint32_t i = 0; i < n; i++) {
        pool_bytes += insn_fields_pool_size(srcs[i], with_names);
    }
    tmpl->insn_fields_pool = pool_bytes ? g_malloc0(pool_bytes) : nullptr;
    tmpl->insn_fields_pool_bytes = (uint32_t)pool_bytes;
    uint8_t *cursor = (uint8_t *)tmpl->insn_fields_pool;
    for (uint32_t i = 0; i < n; i++) {
        insn_fields_pack(&tmpl->insn_fields[i], srcs[i], &cursor);
        if (with_names) {
            insn_reg_names_pack(&tmpl->insn_reg_names[i],
                                name_srcs ? name_srcs[i] : nullptr,
                                srcs[i], &cursor);
        }
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
    /* CST_MEMSTATS (#91): periodic dump keyed to CREATION rate, so a
     * template-runaway (millions of one-insn spec templates) reports its
     * region breakdown while it grows — the end-of-segment dump never runs
     * when the run aborts at the rlimit first. */
    if (getenv("CST_MEMSTATS")) {
        static uint64_t n_created;
        if (++n_created % 200000 == 0) {
            g_template_store.mem_stats(stderr);
        }
    }
    BBTemplatePtr tmpl(g_new0(BBTemplate, 1));
    tmpl->template_id = template_id;
    tmpl->life = tls_creating_spec ? TmplLife::SPEC : TmplLife::CODE;
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
    {
        /* Sources are committed templates or transit copies whose spans
         * still reference live pools; pack deep-copies the span contents
         * into THIS template's pool (a struct assignment would alias the
         * source pool across divergent template lifetimes). */
        std::vector<const InsnFields *> srcs(n_insns);
        std::vector<const InsnRegNames *> name_srcs(n_insns);
        for (uint32_t i = 0; i < n_insns; i++) {
            srcs[i] = &insn_fields[i];
            name_srcs[i] = insn_reg_names ? &insn_reg_names[i] : nullptr;
        }
        insn_fields_pack_all(tmpl.get(), n_insns, srcs.data(),
                             name_srcs.data());
    }
    for (uint32_t i = 0; i < n_insns; i++) {
        tmpl->insn_pcs[i] = insn_pcs[i];
        tmpl->insn_sizes[i] = insn_sizes[i];
        memcpy(&tmpl->insn_bytes[(size_t)i * MAX_INSN_BYTES],
               &insn_bytes[(size_t)i * MAX_INSN_BYTES],
               MAX_INSN_BYTES);
    }
    if (tls_creating_spec) {
        /* Reclaimable-footprint accounting for the proactive-flush
         * trigger — exact now that the span pool is sized. */
        g_template_store.note_spec_creation(sizeof(BBTemplate) +
            (uint64_t)n_insns * (sizeof(InsnFields) + sizeof(uint64_t) +
                                 1 + MAX_INSN_BYTES + sizeof(InsnRegNames)) +
            tmpl->insn_fields_pool_bytes);
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

BBTemplate *TemplateStore::find_existing_true_bb(
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

BBTemplate *TemplateStore::commit_true_bb(uint64_t start_pc,
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

BBTemplate *TemplateStore::commit_true_bb_refs(
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

BBTemplate *TemplateStore::get_or_create_bb_template(
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
     * and return the cached BB directly.  parent_true_bb is a SegRef
     * (clear_bb_map drops bb_map_'s ownership and bumps the
     * generation), so a successful deref here is always live — a
     * prior-segment handle reads as nullptr and falls to the slow
     * path, which re-commits the BB in this segment.
     */
    if (n_fragments > 0) {
        BBTemplate *cand = seg_deref(fragments[0]->parent_true_bb);
        if (cand && cand->start_pc == entry_pc) {
            bool all_match = true;
            for (unsigned int f = 1; f < n_fragments; f++) {
                if (seg_deref(fragments[f]->parent_true_bb) != cand) {
                    all_match = false;
                    break;
                }
            }
            if (all_match) {
                /* Refresh the privilege stamp from this correct-path
                 * execution: the cached true-BB may have been first
                 * committed with a wrong-path seed (a WP session that
                 * spec-translated this PC at the other privilege), and
                 * the fast path would otherwise return that stale value
                 * without passing through the re-stamp below. */
                cand->is_system = fragments[0]->is_system;
                cand->is_system_cp_confirmed = true;
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
    if (g_features.reg_data) {
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
    /* Privilege context rides from the translation-time stamp on the
     * fragments onto the assembled true-BB.  Fragments of one BB share
     * one privilege level (the transition instruction seals the BB).
     * ASSIGN and latch: correct-path fragments are translated in the
     * context that really executes this code, so they override and
     * then lock out any wrong-path seed (see BBTemplate::is_system). */
    if (tmpl && n_fragments > 0) {
        tmpl->is_system = fragments[0]->is_system;
        tmpl->is_system_cp_confirmed = true;
    }
    /*
     * Propagate the REP self-loop sub-template from the last fragment
     * (the TB ending in the REP string op) onto the assembled BB so
     * emit_body_entry can fan iterations without re-walking fragments.
     * No-op for non-REP BBs.  Materialization is lazy: the parent
     * TB's rep_subtmpl is built on first chain-finalize use here, not
     * at translation time — that avoids paying the cost for REP TBs
     * translated outside an active segment, and a handle stale from a
     * previous segment is rebuilt the next time it is needed.  The
     * handle copies verbatim: for a REP fragment ensure_rep_subtmpl
     * just (re)built it in this generation, and for anything else the
     * copied handle is null/stale and derefs to nullptr on the
     * emit-side read.
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
            fragments[f]->parent_true_bb = seg_ref(tmpl);
        }
    }
    return tmpl;
}

BBTemplate *TemplateStore::create_tb_template(
    uint64_t start_pc,
    const TbInsnView &insns,
    const char *symbol_name,
    uint64_t fall_through_pc)
{
    uint32_t n_insns                            = insns.n;
    const uint64_t *insn_pcs                    = insns.pcs;
    const qemu_plugin_insn_info *insn_info      = insns.info;
    const uint64_t *insn_branch_target_pcs      = insns.branch_target_pcs;
    const uint8_t *insn_sizes                   = insns.sizes;
    const uint8_t *insn_bytes                   = insns.bytes;

    /* Always fresh: one template per QEMU translation, attached to
     * that TB via udata.  Distinct CP-mode and WP-mode translations
     * at the same start_pc therefore each get their own template and
     * cannot collide. */
    /* CST_MEMSTATS (#91): periodic dump keyed to FRAGMENT creation rate —
     * this is the volume path a wandering wrong path mints through, so a
     * runaway reports its region breakdown while it grows. */
    if (getenv("CST_MEMSTATS")) {
        static uint64_t n_created;
        if (++n_created % 200000 == 0) {
            mem_stats(stderr);
        }
    }
    BBTemplatePtr tmpl(g_new0(BBTemplate, 1));
    tmpl->template_id = next_template_id_++;
    tmpl->life = tls_creating_spec ? TmplLife::SPEC : TmplLife::CODE;
    tmpl->start_pc = start_pc;
    tmpl->n_insns = n_insns;
    tmpl->fall_through_pc = fall_through_pc;
    /* Privilege of the code being translated — see BBTemplate::is_system.
     * Translation runs in the context about to execute this TB, so the
     * level read here belongs to this code (a seal-time read would see
     * the successor's context instead).  User mode always reads 0. */
    tmpl->is_system = qemu_plugin_get_priv_level() != 0;
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
    if (g_features.reg_data || g_features.wp_reg_data) {
        tmpl->insn_reg_names = g_new0(InsnRegNames, n_insns);
    }
    /* Decode into full-size scratch backing (the walker and refiners
     * append and compact past the interim counts), then pack the
     * final-count span prefixes into this template's pool.  The scratch
     * vector is resized BEFORE any reset — InsnFieldsScratch is
     * self-referential, so every element is (re)wired in place after
     * the vector's storage is settled. */
    {
        static thread_local std::vector<InsnFieldsScratch> scratch;
        static thread_local std::vector<InsnRegNamesScratch> nscratch;
        if (scratch.size() < n_insns) {
            scratch.resize(n_insns);
        }
        bool with_names = tmpl->insn_reg_names != nullptr;
        if (with_names && nscratch.size() < n_insns) {
            nscratch.resize(n_insns);
        }
        std::vector<const InsnFields *> srcs(n_insns);
        std::vector<const InsnRegNames *> name_srcs(n_insns);
        for (uint32_t i = 0; i < n_insns; i++) {
            insn_fields_scratch_reset(&scratch[i]);
            if (with_names) {
                insn_reg_names_scratch_reset(&nscratch[i]);
            }
            if (insn_info && insn_info[i].mnemonic[0]) {
                decode_detail_to_generic(
                    tmpl->insn_pcs[i], &insn_info[i], &scratch[i].f,
                    with_names ? &nscratch[i].rn : nullptr);
            }
            /*
             * Static branch target as resolved by the per-ISA
             * translator, not Capstone.  See
             * InsnFields::taken_target_pc.  0 means "no static target"
             * — non-branch or indirect; WP-resolution routes those
             * through the observed-target history instead.
             */
            if (insn_branch_target_pcs) {
                scratch[i].f.taken_target_pc = insn_branch_target_pcs[i];
            }
            srcs[i] = &scratch[i].f;
            name_srcs[i] = with_names ? &nscratch[i].rn : nullptr;
        }
        insn_fields_pack_all(tmpl.get(), n_insns, srcs.data(),
                             name_srcs.data());
    }
    if (tls_creating_spec) {
        /* Reclaimable-footprint accounting for the proactive-flush
         * trigger.  Fragments are the volume path — a wandering
         * wrong path mints its templates HERE, not through the
         * true-BB funnel. */
        g_template_store.note_spec_creation(sizeof(BBTemplate) +
            (uint64_t)n_insns * (sizeof(InsnFields) + sizeof(uint64_t) +
                                 1 + MAX_INSN_BYTES) +
            tmpl->insn_fields_pool_bytes);
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

void TemplateStore::ensure_rep_subtmpl(BBTemplate *tb)
{
    /* No-op when already live in this segment (a stale prior-segment
     * handle derefs to nullptr and is rebuilt), when not a REP TB, or
     * on a degenerate template (no insns).  commit_true_bb dedups by
     * start_pc, so repeated calls within a segment are safe — but the
     * early-out keeps the hot path branch-predicted. */
    if (!tb || seg_deref(tb->rep_subtmpl) || tb->n_insns == 0) {
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
    BBTemplate *sub = commit_true_bb(sub_pc, 1, &sub_pc, lf,
                                     &sub_size, sub_bytes,
                                     sub_regs,
                                     tb->symbol_name, sub_ft);
    tb->rep_subtmpl = seg_ref(sub);
    /* Inherit the parent REP TB's privilege: the sub-template covers the
     * same instruction, so it shares its execution context.  commit_true_bb
     * (unlike the CP/WP commit paths) does not stamp is_system, so without
     * this a kernel REP (memset/memcpy clear_page) sub-template would
     * serialize as user code. */
    if (sub) {
        sub->is_system = tb->is_system;
        sub->is_system_cp_confirmed = tb->is_system_cp_confirmed;
    }
}

void TemplateStore::mem_stats(FILE *out) const
{
    /* Footprint estimator matching the allocations in create_tb_template /
     * commit_true_bb: per-template fixed struct + per-insn arrays.  The
     * insn_fields term covers the core structs plus each template's span
     * pool (post-diet; formerly six fixed 64-slot
     * uint64_t mask arrays (dep + lane), ~3.3 KB per instruction. */
    auto tmpl_bytes = [](const BBTemplate &t) -> uint64_t {
        uint64_t b = sizeof(BBTemplate);
        uint64_t n = t.n_insns;
        if (t.insn_pcs)       b += n * sizeof(uint64_t);
        if (t.insn_sizes)     b += n;
        if (t.insn_bytes)     b += n * MAX_INSN_BYTES;
        if (t.insn_fields)    b += n * sizeof(InsnFields);
        b += t.insn_fields_pool_bytes;
        if (t.insn_reg_names) b += n * sizeof(InsnRegNames);
        if (t.insn_snap_refs) b += n * sizeof(void *);
        if (t.symbol_name)    b += strlen(t.symbol_name) + 1;
        return b;
    };

    uint64_t tb_count = 0, tb_insns = 0, tb_bytes = 0, tb_fields_bytes = 0;
    /* Region buckets: where do the templates live?  (mipsel layout:
     * user .text ~0x400000-0x40ffff, user data/arena/stack above,
     * kernel 0x80000000+.)  A runaway dominated by one-insn templates at
     * non-.text user addresses = the wrong path wandering the mutable
     * data arena, minting a fresh CF_SINGLE_STEP template per PC. */
    uint64_t n_utext = 0, n_udata = 0, n_kernel = 0, n_one_insn = 0;
    /* Window attribution: a pinned window's correct path stamps
     * is_system_cp_confirmed on every TB it executes, so templates
     * WITHOUT the stamp were never CP-executed inside the traced
     * window — boot-time translations plus wrong-path-only mints.
     * Their byte total is the upper bound a pin-time reclaim of
     * pre-window templates could free. */
    uint64_t idle_cnt = 0, idle_bytes = 0;
    for (const auto &p : tb_templates_) {
        if (!p) {
            continue;
        }
        tb_count++;
        tb_insns += p->n_insns;
        uint64_t b = tmpl_bytes(*p);
        tb_bytes += b;
        if (!p->is_system_cp_confirmed) {
            idle_cnt++;
            idle_bytes += b;
        }
        if (p->insn_fields) {
            tb_fields_bytes += (uint64_t)p->n_insns * sizeof(InsnFields) +
                               p->insn_fields_pool_bytes;
        }
        if (p->n_insns == 1) {
            n_one_insn++;
        }
        if (p->start_pc >= 0x80000000ull) {
            n_kernel++;
        } else if (p->start_pc < 0x410000ull) {
            n_utext++;
        } else {
            n_udata++;
        }
    }
    uint64_t bb_count = 0, bb_insns = 0, bb_bytes = 0;
    for (const auto &kv : bb_map_) {
        if (!kv.second) {
            continue;
        }
        bb_count++;
        bb_insns += kv.second->n_insns;
        bb_bytes += tmpl_bytes(*kv.second);
    }
    /* Dedup-miss histogram over BOTH class indexes: PCs whose
     * sibling-chain list holds >1 head mean re-translations at the same
     * start_pc produced different canonical lengths and accumulated as
     * duplicates.  The spec-index totals are reported separately — its
     * chains (plus any stale entries for promoted chains) vanish
     * wholesale at the next reclaim. */
    uint64_t dedup_pcs = tb_chain_dedup_.size();
    uint64_t dedup_multi = 0, dedup_chains = 0, dedup_max = 0;
    for (const auto &kv : tb_chain_dedup_) {
        dedup_chains += kv.second.size();
        if (kv.second.size() > 1) {
            dedup_multi++;
        }
        if (kv.second.size() > dedup_max) {
            dedup_max = kv.second.size();
        }
    }
    uint64_t spec_pcs = spec_chain_index_.size(), spec_chains = 0;
    for (const auto &kv : spec_chain_index_) {
        spec_chains += kv.second.size();
    }
    fprintf(out,
            "[memstats] sizeof(InsnFields)=%zu sizeof(BBTemplate)=%zu\n"
            "[memstats] tb_templates: %" PRIu64 " tmpl, %" PRIu64 " insns, "
            "%.2f GiB total (%.2f GiB in insn_fields)\n"
            "[memstats] bb_map: %" PRIu64 " tmpl, %" PRIu64 " insns, "
            "%.2f GiB\n"
            "[memstats] dedup: %" PRIu64 " pcs, %" PRIu64 " chains, %" PRIu64
            " pcs with >1 sibling (max %" PRIu64 "); spec index: %" PRIu64
            " pcs, %" PRIu64 " chains\n",
            sizeof(InsnFields), sizeof(BBTemplate),
            tb_count, tb_insns, tb_bytes / 1073741824.0,
            tb_fields_bytes / 1073741824.0,
            bb_count, bb_insns, bb_bytes / 1073741824.0,
            dedup_pcs, dedup_chains, dedup_multi, dedup_max,
            spec_pcs, spec_chains);
    fprintf(out, "[memstats] regions: utext=%" PRIu64 " udata=%" PRIu64
            " kernel=%" PRIu64 " one_insn=%" PRIu64 "\n",
            n_utext, n_udata, n_kernel, n_one_insn);
    fprintf(out, "[memstats] window split: idle (never CP-executed "
            "in-window) %" PRIu64 " tmpl %.3f GiB of %" PRIu64
            " tmpl %.3f GiB\n",
            idle_cnt, idle_bytes / 1073741824.0,
            tb_count, tb_bytes / 1073741824.0);
    /* Process-level ground truth alongside the store's own estimate:
     * glibc arena usage (what malloc holds) and the kernel's RSS view
     * (VmHWM = peak).  The gap between VmRSS and the store's total is
     * everything else — QEMU's guest RAM and JIT caches, the writer's
     * buffers, the auxiliary maps. */
    struct mallinfo2 mi = mallinfo2();
    fprintf(out, "[memstats] mallinfo2: arena=%.2f GiB (in-use=%.2f GiB) "
            "mmap=%.2f GiB\n",
            mi.arena / 1073741824.0, mi.uordblks / 1073741824.0,
            mi.hblkhd / 1073741824.0);
    FILE *st = fopen("/proc/self/status", "r");
    if (st) {
        char line[256];
        while (fgets(line, sizeof(line), st)) {
            if (!strncmp(line, "VmRSS:", 6) || !strncmp(line, "VmHWM:", 6)) {
                fprintf(out, "[memstats] %s", line);
            }
        }
        fclose(st);
    }
}

uint64_t TemplateStore::reclaim_spec_templates(void)
{
    /* Free every template still in the SPEC class.  Safe only at
     * tb_flush: every QEMU TB (and thus every JIT udata reference to a
     * fragment) is gone, and the deferred-flush machinery guarantees no
     * wrong-path walk is in flight.  CODE templates stay — the
     * PathBuilder's deferred pending-seal slot / chain state may reference
     * them across the flush, and real code should keep its decoded template
     * so a re-translation dedups instead of re-decoding (flush invariance).
     *
     * A plain partition suffices: still-SPEC chains live only in the
     * SPEC index (dropped wholesale below) and are all-SPEC by
     * construction (chains are minted under one lifetime class and
     * promote() converts whole chains), so there is no per-chain index
     * surgery and no surviving sibling link into freed memory —
     * promoted chains live on in the CODE index, which reclaim never
     * touches. */
    /* CST_LIFE_AUDIT captures the doomed pointer VALUES up front so the
     * post-partition walk can prove no survivor still references them
     * (membership tests only — freed memory is never dereferenced). */
    std::unordered_set<const BBTemplate *> freed;
    const bool audit = life_audit_enabled();
    if (audit) {
        for (const auto &p : tb_templates_) {
            if (p && p->life == TmplLife::SPEC) {
                freed.insert(p.get());
            }
        }
    }
    uint64_t n = 0;
    tb_templates_.erase(
        std::remove_if(tb_templates_.begin(), tb_templates_.end(),
                       [&n](const BBTemplatePtr &p) {
                           if (p && p->life == TmplLife::SPEC) {
                               n++;
                               return true;
                           }
                           return false;
                       }),
        tb_templates_.end());
    spec_chain_index_.clear();
    spec_pending_bytes_ = 0;
    if (audit) {
        life_audit_after_reclaim(freed);
    }
    return n;
}
