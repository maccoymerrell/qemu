/*
 * The wire's address dependency, from the emitter that stated it.
 *
 * Author: Maccoy Merrell
 *
 * See champsim_tracer_qdep.h for what this replaces and why these two
 * families and not the other two.
 */

#include <algorithm>
#include <atomic>
#include <cstring>
#include <vector>

#include "champsim_tracer.h"
#include "champsim_tracer_qdep.h"

/* The dataflow header carries no linkage guard of its own -- neither does
 * qemu-plugin.h, which champsim_tracer.h wraps the same way.  Without this
 * the plugin asks the loader for a mangled name and fails to dlopen, which
 * is exactly what happened on the first build of this file and exactly what
 * the four-target dlopen smoke exists to catch. */
extern "C" {
#include <qemu-plugin-dataflow.h>
}

namespace {

/*
 * Room for one instruction's accesses.  A form that needs more is REFUSED
 * and counted, never truncated: a partial access list is the shape most
 * likely to pass for a whole one, and a mask built from a partial list is
 * short in exactly the direction that costs a consumer correctness.
 */
constexpr unsigned kMaxMemops = 64;

std::atomic<bool>     g_tried{false};
bool                  g_live = false;
const char           *g_refusal = nullptr;
unsigned              g_nregs = 0;
unsigned              g_prov_words = 0;
std::vector<uint8_t>  g_gen_of_reg;      /* TCG global index -> GenericRegId */

/* Census.  Indexed by QDepState; every extracted instruction lands in
 * exactly one bucket, so the columns sum to the instructions seen. */
std::atomic<uint64_t> g_state[QDEP_STATE_COUNT];

/* The shadow: what the Capstone operand walk would have published, scored
 * against what QEMU's emitters stated, on the rows where the wire now
 * carries QEMU's answer.  Counted per direction because a load and a store
 * of the same instruction are two independent claims. */
std::atomic<uint64_t> g_shadow_ld_same{0}, g_shadow_ld_diff{0};
std::atomic<uint64_t> g_shadow_st_same{0}, g_shadow_st_diff{0};
/* The Capstone side had no block at all to compare: the row reached the
 * format default before this flip and reaches QEMU's mask after it. */
std::atomic<uint64_t> g_shadow_absent{0};

/*
 * Every differing row, by mnemonic and by the names the two sides do not
 * share.  A count of disagreements that cannot say WHICH rows disagree
 * cannot be adjudicated, and an unadjudicated difference on the wire is
 * the thing this whole flip is supposed to remove.  Same for a global with
 * no generic word: the refusal is only actionable if the name is printed.
 */
GMutex g_tally_lock;
GHashTable *g_shadow_sigs   = nullptr;   /* signature -> count */
GHashTable *g_unmapped_name = nullptr;   /* qemu global name -> count */

void tally(GHashTable **t, const char *key)
{
    g_mutex_lock(&g_tally_lock);
    if (!*t) {
        *t = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, nullptr);
    }
    gpointer v = g_hash_table_lookup(*t, key);
    g_hash_table_insert(*t, g_strdup(key),
                        GUINT_TO_POINTER(GPOINTER_TO_UINT(v) + 1));
    g_mutex_unlock(&g_tally_lock);
}

void dump_tally(GString *report, GHashTable *t, const char *heading)
{
    g_string_append_printf(report, "\n%s\n", heading);
    if (!t || g_hash_table_size(t) == 0) {
        g_string_append(report, "  (none)\n");
        return;
    }
    GList *keys = g_hash_table_get_keys(t);
    keys = g_list_sort_with_data(
        keys, [](gconstpointer a, gconstpointer b, gpointer u) -> gint {
            GHashTable *h = (GHashTable *)u;
            guint ca = GPOINTER_TO_UINT(g_hash_table_lookup(h, a));
            guint cb = GPOINTER_TO_UINT(g_hash_table_lookup(h, b));
            return ca == cb ? g_strcmp0((const char *)a, (const char *)b)
                            : (cb > ca ? 1 : -1);
        }, t);
    for (GList *l = keys; l; l = l->next) {
        g_string_append_printf(report, "  %8u  %s\n",
            GPOINTER_TO_UINT(g_hash_table_lookup(t, l->data)),
            (const char *)l->data);
    }
    g_list_free(keys);
}

void qdep_init(void)
{
    bool expected = false;
    if (!g_tried.compare_exchange_strong(expected, true)) {
        return;
    }
    if (!qemu_plugin_dataflow_abi_ok(
            QEMU_PLUGIN_DATAFLOW_VERSION,
            (uint32_t)sizeof(qemu_plugin_dataflow_field),
            (uint32_t)sizeof(qemu_plugin_dataflow_status))) {
        g_refusal = "ABI handshake refused: this plugin and this qemu were "
                    "built against different dataflow versions";
        return;
    }
    g_nregs = qemu_plugin_dataflow_nregs();
    g_prov_words = qemu_plugin_dataflow_prov_words();
    if (g_nregs == 0 || g_prov_words == 0) {
        g_refusal = "target exposes no dataflow namespace";
        return;
    }
    g_gen_of_reg.assign(g_nregs, (uint8_t)REG_ID_COUNT);
    for (unsigned i = 0; i < g_nregs; i++) {
        const char *nm = qemu_plugin_dataflow_reg_name(i, nullptr, nullptr);
        if (nm) {
            /* Two stages, the same two the instrument uses.  The fold layer
             * is not optional: riscv64's x8 is spelled "x8/s0" by TCG and
             * "fp" by the GDB stub, and leaving the fold out refused 719
             * riscv64 instructions for a gap that was in this map rather
             * than in QEMU's answer. */
            uint8_t gen = generic_for_qemu_name(nm);
            if (gen == REG_ID_COUNT) {
                gen = fold_nonarch(nm);
            }
            g_gen_of_reg[i] = gen;
        }
    }
    g_live = true;
}

/* Add @gen to @regs, keeping it sorted and unique.  false when full. */
bool add_reg(uint8_t *regs, uint8_t *n, uint8_t gen)
{
    for (uint8_t i = 0; i < *n; i++) {
        if (regs[i] == gen) {
            return true;
        }
    }
    if (*n >= QDEP_MAX_ADDR_REGS) {
        return false;
    }
    regs[(*n)++] = gen;
    return true;
}

/*
 * Fold one access's address provenance into @regs.
 *
 * UNION rather than replace, because one static memory OPERAND expands into
 * as many architectural accesses as the form performs -- AArch64
 * `ld4 {v0.16b-v3.16b}, [x1]` is one operand and 64 accesses -- and the
 * wire carries one mask per operand.  The format says every access an
 * operand expands into computes its address from the same registers; if a
 * target ever contradicts that, the union is the direction that keeps the
 * mask from being short.
 */
QDepState fold_addr_prov(const uint64_t *words, uint8_t *regs, uint8_t *n)
{
    for (unsigned b = 0; b < g_prov_words * 64; b++) {
        unsigned slot;

        if (!(words[b / 64] & (1ULL << (b % 64)))) {
            continue;
        }
        if (b < g_nregs) {
            uint8_t gen = g_gen_of_reg[b];
            if (gen >= REG_ID_COUNT) {
                const char *nm =
                    qemu_plugin_dataflow_reg_name(b, nullptr, nullptr);
                tally(&g_unmapped_name, nm ? nm : "?");
                return QDEP_R_UNMAPPED;
            }
            if (!add_reg(regs, n, gen)) {
                return QDEP_R_WIDE;
            }
        } else if (qemu_plugin_dataflow_prov_memop(b, &slot)) {
            /*
             * An address computed from a value this same instruction
             * loaded.  The HAS_ADDR mask's bit layout has no load-data
             * slots in it -- addresses compute before any load fires, which
             * is the assumption the layout is built on and which this form
             * breaks.  Refused rather than dropped: dropping it is exactly
             * the short mask this file exists to never publish.
             */
            return QDEP_R_UNREPRESENTABLE;
        } else {
            /* An env byte range.  Inverting an offset back to a register
             * needs the CPUArchState layout, which a plugin does not have
             * and must not hard-code. */
            return QDEP_R_FIELD;
        }
    }
    return QDEP_OK;
}

/* The generic registers a published mask names, read back out of the
 * template's own src_regs[] -- the shadow's left-hand side. */
void mask_to_regs(const InsnFields *f, uint64_t mask, std::vector<uint8_t> &out)
{
    out.clear();
    for (unsigned i = 0; i < f->n_src_regs && i < 64; i++) {
        if (mask & (1ULL << i)) {
            out.push_back(f->src_regs[i]);
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
}

bool same_set(const std::vector<uint8_t> &a, const uint8_t *b, uint8_t nb)
{
    std::vector<uint8_t> bb(b, b + nb);
    std::sort(bb.begin(), bb.end());
    bb.erase(std::unique(bb.begin(), bb.end()), bb.end());
    return a == bb;
}

/* One row's disagreement, named on both sides.  qemu-extra is a register
 * QEMU's emitter said computes the address and Capstone's mask does not
 * name -- the direction in which the OLD wire was SHORT.  cap-extra is the
 * other way round. */
void shadow_sig(const char *mnem, const char *tag,
                const std::vector<uint8_t> &cap,
                const uint8_t *q, uint8_t nq)
{
    std::vector<uint8_t> qq(q, q + nq);
    std::sort(qq.begin(), qq.end());
    qq.erase(std::unique(qq.begin(), qq.end()), qq.end());

    GString *sig = g_string_new(mnem ? mnem : "?");
    g_string_append_printf(sig, " %s", tag);
    for (uint8_t g : qq) {
        if (!std::binary_search(cap.begin(), cap.end(), g)) {
            g_string_append_printf(sig, " qemu-extra:%s",
                                   generic_reg_name_or_unknown(g));
        }
    }
    for (uint8_t g : cap) {
        if (!std::binary_search(qq.begin(), qq.end(), g)) {
            g_string_append_printf(sig, " cap-extra:%s",
                                   generic_reg_name_or_unknown(g));
        }
    }
    tally(&g_shadow_sigs, sig->str);
    g_string_free(sig, TRUE);
}

/*
 * Turn a generic-register set into a mask over this template's src slots.
 *
 * Returns false when a named register occupies no slot -- there is no bit
 * to set, so the mask would be SHORT.  That is the disqualifying direction
 * and the whole instruction is refused for it.
 */
bool regs_to_mask(const InsnFields *f, const uint8_t *regs, uint8_t n,
                  uint64_t *out)
{
    uint64_t m = 0;

    for (uint8_t k = 0; k < n; k++) {
        bool found = false;
        for (unsigned i = 0; i < f->n_src_regs && i < 64; i++) {
            if (f->src_regs[i] == regs[k]) {
                m |= 1ULL << i;
                found = true;
            }
        }
        if (!found) {
            return false;
        }
    }
    *out = m;
    return true;
}

const char *state_name(unsigned s)
{
    switch (s) {
    case QDEP_NONE:             return "no accesses / no dataflow ABI";
    case QDEP_OK:               return "PUBLISHED from QEMU's emitters";
    case QDEP_R_STATUS:         return "refused: extraction reported itself incomplete";
    case QDEP_R_NORECORD:       return "refused: qemu withheld the access list or a provenance";
    case QDEP_R_MULTI:          return "refused: >1 operand of a direction (slot pairing unproven)";
    case QDEP_R_SHAPE:          return "refused: a direction the tracer claims that QEMU did not emit";
    case QDEP_R_FIELD:          return "refused: provenance named env state with no generic word";
    case QDEP_R_UNMAPPED:       return "refused: provenance named a global with no generic word";
    case QDEP_R_WIDE:           return "refused: more address registers than the record holds";
    case QDEP_R_UNREPRESENTABLE:return "refused: a named register occupies no src slot to set";
    default:                    return "?";
    }
}

}  /* namespace */

void qdep_note_insn(const struct qemu_plugin_tb *tb, size_t idx, QDepAddr *out)
{
    qemu_plugin_dataflow_memop mo[kMaxMemops];
    qemu_plugin_dataflow_status st;
    unsigned n;

    memset(out, 0, sizeof(*out));
    out->state = QDEP_NONE;

    qdep_init();
    if (!g_live) {
        return;
    }

    st.struct_size = sizeof(st);
    if (!qemu_plugin_insn_dataflow_status(tb, idx, &st)) {
        out->state = QDEP_R_NORECORD;
        return;
    }
    /*
     * memops_unnoted is the one that matters most here and it is checked
     * FIRST: it says an access happened that no emitter note accounted for,
     * so the list below is not merely capped, it is missing a member whose
     * address nothing states.  fields/writes/prov truncation are included
     * because a provenance that lost a source to slot exhaustion produces
     * precisely a short set.
     */
    if (st.memops_truncated || st.memops_unnoted ||
        st.fields_truncated || st.writes_truncated || st.prov_truncated) {
        out->state = QDEP_R_STATUS;
        return;
    }

    for (unsigned i = 0; i < kMaxMemops; i++) {
        mo[i].struct_size = sizeof(mo[i]);
    }
    n = qemu_plugin_insn_memops(tb, idx, mo, kMaxMemops);
    if (n == QEMU_PLUGIN_DF_INCOMPLETE || n > kMaxMemops) {
        out->state = QDEP_R_NORECORD;
        return;
    }
    if (n == 0) {
        out->state = QDEP_NONE;      /* no accesses: nothing to state */
        return;
    }

    std::vector<uint64_t> w(g_prov_words);
    for (unsigned i = 0; i < n; i++) {
        bool store = mo[i].is_store != 0;
        QDepState rc;

        if (qemu_plugin_insn_memop_addr_prov(tb, idx, i, w.data(),
                                             g_prov_words) != g_prov_words) {
            out->state = QDEP_R_NORECORD;
            return;
        }
        if (store) {
            out->qemu_has_store = true;
            rc = fold_addr_prov(w.data(), out->store_regs, &out->n_store_regs);
        } else {
            out->qemu_has_load = true;
            rc = fold_addr_prov(w.data(), out->load_regs, &out->n_load_regs);
        }
        if (rc != QDEP_OK) {
            out->state = rc;
            return;
        }
    }
    out->state = QDEP_OK;
}

void qdep_apply_addr(InsnFields *f, const QDepAddr *q, const char *mnem)
{
    static thread_local std::vector<uint8_t> cap;
    unsigned state = q ? q->state : QDEP_NONE;

    if (f->max_dep_loads == 0 && f->max_dep_stores == 0) {
        /*
         * The tracer's walk found no memory operand.  Nothing on this
         * instruction can carry an address mask, whatever QEMU said -- the
         * HAS_ADDR block's arrays are sized by these two counts and a mask
         * with no array to live in cannot be written.  Not a refusal: there
         * is no claim here to refuse.
         */
        g_state[QDEP_NONE].fetch_add(1, std::memory_order_relaxed);
        return;
    }

    if (state == QDEP_OK) {
        /*
         * The tracer claims a direction QEMU did not emit (a helper
         * performed the access inside the call, or the walk invented an
         * operand).  Either way there is no emitter statement to publish
         * for that direction, and publishing one direction from QEMU and
         * leaving the other from Capstone would put two sources in one
         * block.
         */
        if ((f->max_dep_loads > 0) != q->qemu_has_load ||
            (f->max_dep_stores > 0) != q->qemu_has_store) {
            state = QDEP_R_SHAPE;
        } else if (f->max_dep_loads > 1 || f->max_dep_stores > 1) {
            /*
             * More than one operand of a direction.  QEMU's list is in
             * emission order and the tracer's is in Capstone operand order;
             * nothing proves the k-th of one is the k-th of the other, and
             * a mask attached to the wrong access is worse than no mask.
             */
            state = QDEP_R_MULTI;
        }
    }

    if (state != QDEP_OK) {
        /*
         * The format default, by name.  has_addr_deps false means the
         * consumer assumes every input may feed every address, which is the
         * over-approximation -- never a short mask, and never a silent
         * return to the Capstone answer that used to be here.
         */
        f->has_addr_deps = false;
        g_state[state].fetch_add(1, std::memory_order_relaxed);
        return;
    }

    uint64_t ld_mask = 0, st_mask = 0;
    if (f->max_dep_loads > 0 &&
        !regs_to_mask(f, q->load_regs, q->n_load_regs, &ld_mask)) {
        f->has_addr_deps = false;
        g_state[QDEP_R_UNREPRESENTABLE].fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (f->max_dep_stores > 0 &&
        !regs_to_mask(f, q->store_regs, q->n_store_regs, &st_mask)) {
        f->has_addr_deps = false;
        g_state[QDEP_R_UNREPRESENTABLE].fetch_add(1, std::memory_order_relaxed);
        return;
    }

    /* The shadow, taken BEFORE the overwrite -- afterwards there is nothing
     * left to compare against. */
    if (!f->has_addr_deps) {
        g_shadow_absent.fetch_add(1, std::memory_order_relaxed);
    } else {
        if (f->max_dep_loads > 0) {
            mask_to_regs(f, f->load_addr_dep_mask[0], cap);
            if (same_set(cap, q->load_regs, q->n_load_regs)) {
                g_shadow_ld_same.fetch_add(1, std::memory_order_relaxed);
            } else {
                g_shadow_ld_diff.fetch_add(1, std::memory_order_relaxed);
                shadow_sig(mnem, "ldaddr", cap, q->load_regs, q->n_load_regs);
            }
        }
        if (f->max_dep_stores > 0) {
            mask_to_regs(f, f->store_addr_dep_mask[0], cap);
            if (same_set(cap, q->store_regs, q->n_store_regs)) {
                g_shadow_st_same.fetch_add(1, std::memory_order_relaxed);
            } else {
                g_shadow_st_diff.fetch_add(1, std::memory_order_relaxed);
                shadow_sig(mnem, "staddr", cap, q->store_regs, q->n_store_regs);
            }
        }
    }

    for (uint8_t k = 0; k < f->max_dep_loads; k++) {
        f->load_addr_dep_mask[k] = ld_mask;
    }
    for (uint8_t k = 0; k < f->max_dep_stores; k++) {
        f->store_addr_dep_mask[k] = st_mask;
    }
    f->has_addr_deps = true;
    g_state[QDEP_OK].fetch_add(1, std::memory_order_relaxed);
}

void qdep_report(GString *report)
{
    uint64_t total = 0;

    for (unsigned s = 0; s < QDEP_STATE_COUNT; s++) {
        total += g_state[s].load(std::memory_order_relaxed);
    }
    if (total == 0) {
        return;
    }

    g_string_append(report,
        "\n=== address dependency: the source is QEMU's emitters ===\n"
        "The HAS_ADDR block of every template's dependency sub-block --\n"
        "load_addr_dep[] and store_addr_dep[] -- is written from the\n"
        "provenance QEMU's own tcg_gen_qemu_ld/st emitters stated for each\n"
        "access, not from the Capstone MEM operand.  A row this extractor\n"
        "cannot state IN FULL publishes no block at all and reaches the\n"
        "format's own all-inputs default; it never publishes a short mask\n"
        "and never falls back to the Capstone answer.  The refusal rows\n"
        "below are that fallback, counted.\n");

    for (unsigned s = 0; s < QDEP_STATE_COUNT; s++) {
        uint64_t v = g_state[s].load(std::memory_order_relaxed);
        if (v) {
            g_string_append_printf(report, "  %10" G_GUINT64_FORMAT
                                   "  %s\n", v, state_name(s));
        }
    }
    if (g_refusal) {
        g_string_append_printf(report, "  extractor DISABLED: %s\n", g_refusal);
    }

    g_string_append(report,
        "\nthe Capstone shadow, on the rows the wire now takes from QEMU\n"
        "(compared before the overwrite; it feeds nothing):\n");
    g_string_append_printf(report,
        "  load address:  %" G_GUINT64_FORMAT " same, %" G_GUINT64_FORMAT " differ\n"
        "  store address: %" G_GUINT64_FORMAT " same, %" G_GUINT64_FORMAT " differ\n"
        "  %" G_GUINT64_FORMAT " rows had no Capstone block to compare\n",
        g_shadow_ld_same.load(std::memory_order_relaxed),
        g_shadow_ld_diff.load(std::memory_order_relaxed),
        g_shadow_st_same.load(std::memory_order_relaxed),
        g_shadow_st_diff.load(std::memory_order_relaxed),
        g_shadow_absent.load(std::memory_order_relaxed));

    g_mutex_lock(&g_tally_lock);
    dump_tally(report, g_shadow_sigs,
               "shadow disagreements (qemu-extra = a register the OLD wire's "
               "mask did NOT name):");
    dump_tally(report, g_unmapped_name,
               "globals an address provenance named that have no generic word\n(per ACCESS, so an instruction refused on both a load and a store\ncounts twice here and once above):");
    g_mutex_unlock(&g_tally_lock);
}
