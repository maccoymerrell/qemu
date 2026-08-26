/*
 * The wire's address and store-data dependencies, from the emitters that
 * stated them.
 *
 * Author: Maccoy Merrell
 *
 * See champsim_tracer_qdep.h for what this replaces, what the zero-register
 * ruling decided, and why the HAS_REG flag being shared bounds the third
 * family in a way the first two were not bounded.
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
 * exactly one bucket per family, so each column sums to the instructions
 * seen.  Two arrays because the two families refuse for different reasons on
 * different rows and one merged column could not say which. */
std::atomic<uint64_t> g_state[QDEP_STATE_COUNT];
std::atomic<uint64_t> g_dstate[QDEP_STATE_COUNT];

/* The shadow: what the Capstone operand walk would have published, scored
 * against what QEMU's emitters stated, on the rows where the wire now
 * carries QEMU's answer.  Counted per direction because a load and a store
 * of the same instruction are two independent claims. */
std::atomic<uint64_t> g_shadow_ld_same{0}, g_shadow_ld_diff{0};
std::atomic<uint64_t> g_shadow_st_same{0}, g_shadow_st_diff{0};
/* The Capstone side had no block at all to compare: the row reached the
 * format default before this flip and reaches QEMU's mask after it. */
std::atomic<uint64_t> g_shadow_absent{0};
/* The store-data family's own shadow, scored on the rows where the wire now
 * takes that mask from QEMU. */
std::atomic<uint64_t> g_shadow_sd_same{0}, g_shadow_sd_diff{0};

/*
 * Every differing row, by mnemonic and by the names the two sides do not
 * share.  A count of disagreements that cannot say WHICH rows disagree
 * cannot be adjudicated, and an unadjudicated difference on the wire is
 * the thing this whole flip is supposed to remove.  Same for a global with
 * no generic word: the refusal is only actionable if the name is printed.
 */
GMutex g_tally_lock;
GHashTable *g_shadow_sigs   = nullptr;   /* signature -> count */
GHashTable *g_sd_sigs       = nullptr;   /* store-data signature -> count */
GHashTable *g_unmapped_name = nullptr;   /* qemu global name -> count */
GHashTable *g_monitor_name  = nullptr;   /* reservation-monitor global -> count */

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
 * The reservation monitor's VALUE half, by the name its target gave the TCG
 * global.  Three targets lower store-conditional onto a cmpxchg whose
 * COMPARE operand is this global, so it shows up as one input of the datum
 * the access stores.
 *
 * It is not an unmapped register and it must not be given a generic word:
 * R7.7 already ruled that reservation state "is a product of the
 * instruction, not the register used".  It is the emulation-artefact
 * category f46873a738 established for #177, and it is named here so the
 * census can say so instead of filing it under a decoder gap.
 */
bool is_monitor_value(const char *nm)
{
    return nm && (!strcmp(nm, "exclusive_val") ||     /* aarch64 */
                  !strcmp(nm, "exclusive_high") ||    /* aarch64, 128-bit */
                  !strcmp(nm, "load_val") ||          /* riscv64 */
                  !strcmp(nm, "llval"));              /* mipsel */
}

/*
 * Fold one access's provenance -- address or store-data -- into @regs.
 *
 * UNION rather than replace, because one static memory OPERAND expands into
 * as many architectural accesses as the form performs -- AArch64
 * `ld4 {v0.16b-v3.16b}, [x1]` is one operand and 64 accesses -- and the
 * wire carries one mask per operand.  The format says every access an
 * operand expands into computes its address from the same registers; if a
 * target ever contradicts that, the union is the direction that keeps the
 * mask from being short.
 *
 * @load_slots is non-NULL for the DATA arm and NULL for the ADDRESS arm, and
 * that is the whole difference between them.  A store's datum genuinely may
 * be a value this same instruction loaded -- every read-modify-write is that
 * shape -- and the HAS_REG mask HAS a bit per load slot to carry it.  An
 * ADDRESS mask has no such bits, because the layout is built on addresses
 * computing before any load fires, so the same provenance bit is a refusal
 * there and a recorded slot here.
 */
QDepState fold_prov(const uint64_t *words, uint8_t *regs, uint8_t *n,
                    uint8_t *load_slots)
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
                if (is_monitor_value(nm)) {
                    tally(&g_monitor_name, nm);
                    return QDEP_R_EMU_MONITOR;
                }
                tally(&g_unmapped_name, nm ? nm : "?");
                return QDEP_R_UNMAPPED;
            }
            if (!add_reg(regs, n, gen)) {
                return QDEP_R_WIDE;
            }
        } else if (qemu_plugin_dataflow_prov_zero_reg(b)) {
            /*
             * The architectural ZERO register, stated by the accessor that
             * resolved the operand.  QEMU folds it to a constant, so without
             * that note the set would be SHORT by exactly the register the
             * encoding names -- which is what R7.3 refused and what the 575
             * `ir-stdata-missing:REG_ZERO` rows were.
             */
            if (!add_reg(regs, n, (uint8_t)REG_ZERO)) {
                return QDEP_R_WIDE;
            }
        } else if (qemu_plugin_dataflow_prov_memop(b, &slot)) {
            if (!load_slots) {
                return QDEP_R_UNREPRESENTABLE;
            }
            if (slot >= 8) {
                return QDEP_R_WIDE;
            }
            *load_slots |= (uint8_t)(1u << slot);
        } else {
            /* An env byte range.  Inverting an offset back to a register
             * needs the CPUArchState layout, which a plugin does not have
             * and must not hard-code. */
            return QDEP_R_FIELD;
        }
    }
    return QDEP_OK;
}

/*
 * Name every bit a mask sets, in the format's own layout: src regs, then
 * @nloads load-data slots, then the immediate.  @nloads is max_dep_loads for
 * a store-data mask and ZERO for an address mask, which is the whole
 * difference between the two layouts.
 *
 * Used on both sides of both shadows, so a difference in a LOAD-DATA bit or
 * the IMMEDIATE bit is a named signature rather than something the
 * comparison silently agrees about.  It was the latter until now: the
 * address shadow compared REGISTER SETS, which cannot see either bit, so an
 * address mask losing its immediate bit to the flip would have scored as
 * agreement.  Same erasure shape as irdf's REG_IP drop, and found the same
 * way -- by writing the comparison down and asking what it cannot see.
 */
void name_mask_bits(GString *out, const InsnFields *f, unsigned nloads,
                    uint64_t mask, const char *prefix)
{
    unsigned nsrc = f->n_src_regs;

    for (unsigned i = 0; i < nsrc && i < 64; i++) {
        if (mask & (1ULL << i)) {
            g_string_append_printf(out, " %s:%s", prefix,
                                   generic_reg_name_or_unknown(f->src_regs[i]));
        }
    }
    for (unsigned k = 0; k < nloads && nsrc + k < 64; k++) {
        if (mask & (1ULL << (nsrc + k))) {
            g_string_append_printf(out, " %s:LOAD%u", prefix, k);
        }
    }
    if (nsrc + nloads < 64 && (mask & (1ULL << (nsrc + nloads)))) {
        g_string_append_printf(out, " %s:IMM", prefix);
    }
}

/* One row's disagreement on either family, named by BIT on both sides. */
void mask_shadow_sig(GHashTable **tally_into, const char *mnem,
                     const InsnFields *f, unsigned nloads, const char *tag,
                     uint64_t cap_mask, uint64_t q_mask)
{
    GString *sig = g_string_new(mnem ? mnem : "?");

    g_string_append_printf(sig, " %s", tag);
    name_mask_bits(sig, f, nloads, q_mask & ~cap_mask, "qemu-extra");
    name_mask_bits(sig, f, nloads, cap_mask & ~q_mask, "cap-extra");
    tally(tally_into, sig->str);
    g_string_free(sig, TRUE);
}

/*
 * One store-data row's disagreement, named on both sides and by BIT rather
 * than by register set, because the two masks differ in a load-data or
 * immediate bit as readily as in a register and a comparison that could not
 * see those would report agreement it had not established.
 */
void data_shadow_sig(const char *mnem, const InsnFields *f,
                     uint64_t cap_mask, uint64_t q_mask)
{
    mask_shadow_sig(&g_sd_sigs, mnem, f, f->max_dep_loads, "stdata",
                    cap_mask, q_mask);
}

/*
 * Turn a generic-register set into a mask over this template's src slots.
 *
 * Returns false when a named register occupies no slot -- there is no bit
 * to set, so the mask would be SHORT.  That is the disqualifying direction
 * and the whole instruction is refused for it.
 */
bool regs_to_mask(const InsnFields *f, const uint8_t *regs, uint8_t n,
                  uint8_t load_slots, uint64_t *out)
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
    /*
     * The load-data slots, for the store-data arm.  The bit positions start
     * at n_src_regs, and a slot beyond max_dep_loads has no bit to set --
     * which is the same disqualifying direction as a register with no slot,
     * so it fails the same way.
     */
    for (unsigned k = 0; k < 8; k++) {
        if (!(load_slots & (1u << k))) {
            continue;
        }
        if (k >= f->max_dep_loads || f->n_src_regs + k >= 64) {
            return false;
        }
        m |= 1ULL << (f->n_src_regs + k);
    }
    *out = m;
    return true;
}

/*
 * The format's own all-inputs default, written out.
 *
 * Reached when the store-data family is refused on an instruction whose
 * HAS_REG flag is set by a refiner: the field is on the wire and something
 * has to be in it, and the only honest something is what a consumer would
 * have assumed had the block been absent -- every src, every load slot, the
 * immediate.  Never the Capstone mask this replaces, and never a short one.
 */
uint64_t all_inputs_mask(const InsnFields *f)
{
    unsigned nsrc = f->n_src_regs;
    unsigned nbits = nsrc + f->max_dep_loads + (f->has_immediate ? 1u : 0u);
    uint64_t m = 0;

    for (unsigned i = 0; i < nbits && i < 64; i++) {
        m |= 1ULL << i;
    }
    return m;
}


/*
 * THE COORDINATE SYSTEM, and why it is rebuilt rather than read.
 *
 * A dependency mask on the wire is a set of BIT POSITIONS, and
 * docs/format.rst fixes what a position means: "bits [0, n_src) depends on
 * src_reg[i]".  So the mask says nothing on its own -- src_regs[] is the
 * dictionary it is read through, and until this function existed that
 * dictionary was built entirely by the Capstone operand walk.  Every
 * register QEMU's emitters named was then LOOKED UP in Capstone's list to
 * find the bit that would carry it.
 *
 * That is a live Capstone route into a QEMU-sourced block, and it was
 * MEASURED rather than argued: under `QEMU_CAP_MUTATE=access`, 88 published
 * address dependencies across x86_64, aarch64 and riscv64 named a DIFFERENT
 * architectural register, because a flipped access flag moved a register
 * out of src_regs[] and every later slot shifted down underneath a mask
 * whose bit positions index it (ARC3_CLOSE.md 1.5).  J3's bar is verbatim
 * "If we are still susceptible to Capstone artifacts, we didn't do it
 * right", so the answer is not to document the coupling but to remove it.
 *
 * WHAT THIS DOES.  Every register QEMU's own emitters named -- the address
 * provenance of each access, then the store datum's -- is seated at the
 * HEAD of src_regs[], in QEMU's order, before anything the operand walk
 * found.  The address mask is then a set of bit positions inside a run that
 * QEMU alone decides the length, the order and the contents of, so its
 * VALUE is a function of QEMU's answer and of nothing else.  Corrupting
 * Capstone's operands can still change what follows the prefix; it cannot
 * reach into it.
 *
 * IT IS A PERMUTATION, NOT A REPLACEMENT.  Nothing is dropped: the walk's
 * sources that QEMU did not name keep their identity and follow the prefix
 * in their original relative order, and a register QEMU named that the walk
 * missed is APPENDED to the instruction's sources rather than being cause
 * to refuse.  Every mask, lane array and register key that indexes a source
 * slot is carried through the same permutation in the same step, so no
 * consumer sees a mask and a dictionary from different orders.
 *
 * WHY HERE AND NOT IN THE WALK.  The refiners write source-slot masks and
 * run between the walk and this file; a reindex before them would be undone
 * by them.  qdep_apply() is the last writer, which is the only place the
 * permutation can be applied once and be final.
 *
 * WHAT IT DOES NOT REACH, stated because a half-closed route reads like a
 * closed one.  n_src_regs is still the walk's COUNT, so the load-data bits
 * at [n_src, n_src + max_dep_loads) and the immediate bit above them still
 * sit at Capstone-decided offsets.  The ADDRESS masks never set those bits
 * -- their layout has no load-data slots and this extractor never sets
 * their immediate -- so the address families are complete.  The STORE-DATA
 * family sets both, and is therefore invariant in its register bits and not
 * in the other two.  See champsim_tracer_qdep.h.
 */
bool reindex_src_for_qemu(InsnFields *f, InsnRegNames *rn,
                          const uint8_t *q, uint8_t nq)
{
    uint8_t neworder[MAX_SRC_REGS];
    uint8_t map[MAX_SRC_REGS];          /* old source slot -> new slot */
    unsigned n = 0;
    const unsigned nsrc_o = f->n_src_regs;
    const unsigned mdl = f->max_dep_loads;

    if (nsrc_o > MAX_SRC_REGS) {
        return false;
    }
    for (uint8_t k = 0; k < nq; k++) {
        if (n >= MAX_SRC_REGS) {
            return false;
        }
        neworder[n++] = q[k];
    }
    for (unsigned i = 0; i < nsrc_o; i++) {
        uint8_t r = f->src_regs[i];
        bool seated = false;

        for (uint8_t k = 0; k < nq; k++) {
            if (q[k] == r) {
                map[i] = k;
                seated = true;
                break;
            }
        }
        if (seated) {
            continue;
        }
        if (n >= MAX_SRC_REGS) {
            return false;
        }
        map[i] = (uint8_t)n;
        neworder[n++] = r;
    }
    const unsigned nsrc_n = n;
    /*
     * The widest bit either layout addresses is the register mask's
     * immediate, one above the load-data run.  Refuse rather than write a
     * mask whose top bit fell off the end of the word.
     */
    if (nsrc_o + mdl >= 64 || nsrc_n + mdl >= 64) {
        return false;
    }
    if (nsrc_n == nsrc_o) {
        bool moved = false;
        for (unsigned i = 0; i < nsrc_o; i++) {
            if (map[i] != i) {
                moved = true;
                break;
            }
        }
        if (!moved) {
            return true;        /* already QEMU's order; nothing to carry */
        }
    }

    /*
     * @nloads is max_dep_loads for a register mask and ZERO for an address
     * mask, which is the whole difference between the two layouts -- and
     * the immediate bit sits one above the run in both.
     */
    auto carry = [&](uint64_t m, unsigned nloads) -> uint64_t {
        uint64_t o = 0;

        for (unsigned i = 0; i < nsrc_o; i++) {
            if (m & (1ULL << i)) {
                o |= 1ULL << map[i];
            }
        }
        for (unsigned k = 0; k < nloads; k++) {
            if (m & (1ULL << (nsrc_o + k))) {
                o |= 1ULL << (nsrc_n + k);
            }
        }
        if (m & (1ULL << (nsrc_o + nloads))) {
            o |= 1ULL << (nsrc_n + nloads);
        }
        return o;
    };

    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        f->dst_dep_mask[d] = carry(f->dst_dep_mask[d], mdl);
    }
    for (uint8_t st = 0; st < f->max_dep_stores; st++) {
        f->store_data_dep_mask[st] = carry(f->store_data_dep_mask[st], mdl);
        f->store_addr_dep_mask[st] = carry(f->store_addr_dep_mask[st], 0);
    }
    for (uint8_t l = 0; l < f->max_dep_loads; l++) {
        f->load_addr_dep_mask[l] = carry(f->load_addr_dep_mask[l], 0);
    }

    uint64_t lane[MAX_SRC_REGS];
    const QemuRegKey *keys[MAX_SRC_REGS];
    memset(lane, 0, sizeof(lane));
    memset(keys, 0, sizeof(keys));
    for (unsigned i = 0; i < nsrc_o; i++) {
        lane[map[i]] = f->src_lane_mask[i];
        if (rn && rn->src_qemu_reg_keys) {
            keys[map[i]] = rn->src_qemu_reg_keys[i];
        }
    }
    for (unsigned i = 0; i < nsrc_n; i++) {
        f->src_regs[i] = neworder[i];
        f->src_lane_mask[i] = lane[i];
        if (rn && rn->src_qemu_reg_keys) {
            /*
             * A slot the walk never held has no key to carry, so it is
             * resolved from the generic ID -- the same singleton the walk
             * would have installed.  Without this the register would be on
             * the wire as an identity with no readable value behind it.
             */
            rn->src_qemu_reg_keys[i] =
                keys[i] ? keys[i] : qemu_reg_key_for_generic(neworder[i]);
        }
    }
    f->n_src_regs = (uint8_t)nsrc_n;
    return true;
}

/*
 * The register list QEMU's emitters named for this instruction, in QEMU's
 * own order: every access's address provenance first, in the order the
 * accesses were emitted, then the store datum's.
 *
 * Both halves are included whenever QEMU stated them IN FULL, and the test
 * is q->state / q->data_state as qdep_note_insn() left them -- the RAW
 * per-family verdicts, before qdep_apply()'s shape and multi gates, which
 * are the two places a Capstone-derived count still speaks.  Gating the
 * prefix on those would make its LENGTH a function of Capstone's operand
 * list and put back, one level up, exactly the coupling this removes.
 */
uint8_t qemu_named_regs(const QDepInsn *q, uint8_t *out)
{
    uint8_t n = 0;

    auto take = [&](const uint8_t *regs, uint8_t cnt) {
        for (uint8_t i = 0; i < cnt; i++) {
            bool dup = false;
            for (uint8_t k = 0; k < n; k++) {
                if (out[k] == regs[i]) {
                    dup = true;
                    break;
                }
            }
            if (!dup && n < MAX_SRC_REGS) {
                out[n++] = regs[i];
            }
        }
    };

    if (q->state == QDEP_OK) {
        take(q->load_regs, q->n_load_regs);
        take(q->store_regs, q->n_store_regs);
    }
    if (q->data_state == QDEP_OK) {
        take(q->data_regs, q->n_data_regs);
    }
    return n;
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
    case QDEP_R_UNREPRESENTABLE:return "refused: a named input occupies no slot to set";
    case QDEP_R_EMU_MONITOR:    return "refused: names the reservation monitor's value half (emulation artefact, #177 / f46873a738)";
    case QDEP_R_REINDEX:        return "refused: QEMU's own source index does not fit (src slots or mask width)";
    case QDEP_NO_BLOCK:         return "stated by QEMU but the wire's HAS_REG flag is clear: consumer already at the default";
    default:                    return "?";
    }
}

}  /* namespace */

void qdep_note_insn(const struct qemu_plugin_tb *tb, size_t idx, QDepInsn *out)
{
    qemu_plugin_dataflow_memop mo[kMaxMemops];
    qemu_plugin_dataflow_status st;
    unsigned n;

    memset(out, 0, sizeof(*out));
    out->state = QDEP_NONE;
    out->data_state = QDEP_NONE;

    qdep_init();
    if (!g_live) {
        return;
    }

    st.struct_size = sizeof(st);
    if (!qemu_plugin_insn_dataflow_status(tb, idx, &st)) {
        out->state = out->data_state = QDEP_R_NORECORD;
        return;
    }
    /*
     * memops_unnoted is the one that matters most here and it is checked
     * FIRST: it says an access happened that no emitter note accounted for,
     * so the list below is not merely capped, it is missing a member whose
     * address nothing states.  fields/writes/prov truncation are included
     * because a provenance that lost a source to slot exhaustion produces
     * precisely a short set.
     *
     * n_helper_unbounded is the fourth, and it is the one an earlier draft
     * of this file did not check.  Its own contract says the reported sets
     * "are then SHORT, not merely coarse" -- a helper handed the whole CPU
     * state, whose real reads no op names.  A store lowered through such a
     * helper would arrive here with an EMPTY data provenance that means "the
     * walk could not see" and not "nothing was read", and publishing it
     * would be the short mask this file exists to never publish.
     *
     * n_helper_unknown is NOT in this list, and the difference is the point.
     * Unknown DIRECTION is recorded as read-and-written, which is the
     * over-approximation; unbounded FOOTPRINT is a set with members missing.
     * Refusing on the first would be irdf's `n_calls > 0` decline, which R5
     * ruled is a reader's limit written down as the machine's.
     */
    if (st.memops_truncated || st.memops_unnoted ||
        st.fields_truncated || st.writes_truncated || st.prov_truncated ||
        st.n_helper_unbounded) {
        out->state = out->data_state = QDEP_R_STATUS;
        return;
    }

    for (unsigned i = 0; i < kMaxMemops; i++) {
        mo[i].struct_size = sizeof(mo[i]);
    }
    n = qemu_plugin_insn_memops(tb, idx, mo, kMaxMemops);
    if (n == QEMU_PLUGIN_DF_INCOMPLETE || n > kMaxMemops) {
        out->state = out->data_state = QDEP_R_NORECORD;
        return;
    }
    if (n == 0) {
        /* No accesses: nothing to state, for either family. */
        out->state = out->data_state = QDEP_NONE;
        return;
    }

    /*
     * The two families are extracted in one pass but refused INDEPENDENTLY.
     * They are separate parameters of the same emitter and separate blocks on
     * the wire, and folding one's refusal into the other would throw away an
     * answer QEMU gave -- which is the same shape of loss as publishing a
     * short mask, one level up.
     */
    std::vector<uint64_t> w(g_prov_words);
    for (unsigned i = 0; i < n; i++) {
        bool store = mo[i].is_store != 0;
        QDepState rc;

        if (qemu_plugin_insn_memop_addr_prov(tb, idx, i, w.data(),
                                             g_prov_words) != g_prov_words) {
            out->state = out->data_state = QDEP_R_NORECORD;
            return;
        }
        if (store) {
            out->qemu_has_store = true;
            rc = fold_prov(w.data(), out->store_regs, &out->n_store_regs,
                           nullptr);
        } else {
            out->qemu_has_load = true;
            rc = fold_prov(w.data(), out->load_regs, &out->n_load_regs,
                           nullptr);
        }
        if (rc != QDEP_OK && out->state == QDEP_NONE) {
            out->state = rc;    /* first refusal wins; a later access
                                 * succeeding does not undo it */
        }

        if (!store) {
            continue;
        }
        if (qemu_plugin_insn_memop_data_prov(tb, idx, i, w.data(),
                                             g_prov_words) != g_prov_words) {
            if (out->data_state == QDEP_NONE) {
                out->data_state = QDEP_R_NORECORD;
            }
            continue;
        }
        rc = fold_prov(w.data(), out->data_regs, &out->n_data_regs,
                       &out->data_load_slots);
        if (rc != QDEP_OK && out->data_state == QDEP_NONE) {
            out->data_state = rc;   /* first refusal wins */
        }
    }
    /*
     * A family with no refusal recorded above was stated in full.  Written
     * this way round rather than as an early `= QDEP_OK` so that the FIRST
     * refusal wins and a later access cannot overwrite it with a success.
     */
    if (out->state == QDEP_NONE) {
        out->state = QDEP_OK;
    }
    if (out->data_state == QDEP_NONE && out->qemu_has_store) {
        out->data_state = QDEP_OK;
    }
}

void qdep_apply(InsnFields *f, InsnRegNames *rn, const QDepInsn *q,
                const char *mnem)
{
    unsigned state = q ? q->state : QDEP_NONE;
    unsigned dstate = q ? q->data_state : QDEP_NONE;

    if (f->max_dep_loads == 0 && f->max_dep_stores == 0) {
        /*
         * The tracer's walk found no memory operand.  Nothing on this
         * instruction can carry an address or store-data mask, whatever QEMU
         * said -- both blocks' arrays are sized by these two counts and a
         * mask with no array to live in cannot be written.  Not a refusal:
         * there is no claim here to refuse.
         */
        g_state[QDEP_NONE].fetch_add(1, std::memory_order_relaxed);
        g_dstate[QDEP_NONE].fetch_add(1, std::memory_order_relaxed);
        return;
    }

    /*
     * The two SHAPE checks below disqualify both families at once, and that
     * is not a fold of one into the other: they say the tracer's operand list
     * and QEMU's access list do not describe the same accesses, so neither
     * family's per-access pairing means anything.
     */
    /*
     * Seat QEMU's own register list at the head of src_regs[] FIRST, so
     * every mask written below is written in a coordinate system QEMU owns.
     * Done before the gates, not after: the gates only decide whether the
     * masks are PUBLISHED, and the permutation has to be applied whether
     * they are or not -- dst_dep_mask[] indexes the same slots and would
     * otherwise be left reading the old order.
     */
    {
        uint8_t qregs[MAX_SRC_REGS];
        uint8_t nq = qemu_named_regs(q, qregs);

        if (nq && !reindex_src_for_qemu(f, rn, qregs, nq)) {
            /*
             * The index could not be seated, so nothing below can be
             * written in QEMU's coordinates.  Refuse both families rather
             * than publish a mask indexed against the operand walk's order
             * while claiming it is QEMU's.
             */
            f->has_addr_deps = false;
            g_state[QDEP_R_REINDEX].fetch_add(1, std::memory_order_relaxed);
            if (f->has_reg_deps) {
                for (uint8_t st = 0; st < f->max_dep_stores; st++) {
                    f->store_data_dep_mask[st] = all_inputs_mask(f);
                }
            }
            g_dstate[QDEP_R_REINDEX].fetch_add(1, std::memory_order_relaxed);
            return;
        }
    }

    bool shape_bad = false, multi = false;
    if ((f->max_dep_loads > 0) != q->qemu_has_load ||
        (f->max_dep_stores > 0) != q->qemu_has_store) {
        /*
         * The tracer claims a direction QEMU did not emit (a helper
         * performed the access inside the call, or the walk invented an
         * operand).  Either way there is no emitter statement to publish
         * for that direction, and publishing one direction from QEMU and
         * leaving the other from Capstone would put two sources in one
         * block.
         */
        shape_bad = true;
    } else if (f->max_dep_loads > 1 || f->max_dep_stores > 1) {
        /*
         * More than one operand of a direction.  QEMU's list is in
         * emission order and the tracer's is in Capstone operand order;
         * nothing proves the k-th of one is the k-th of the other, and
         * a mask attached to the wrong access is worse than no mask.
         */
        multi = true;
    }
    if (shape_bad || multi) {
        unsigned r = shape_bad ? QDEP_R_SHAPE : QDEP_R_MULTI;
        if (state == QDEP_OK) {
            state = r;
        }
        if (dstate == QDEP_OK) {
            dstate = r;
        }
    }

    /* ---------------- the HAS_ADDR block ---------------- */

    uint64_t ld_mask = 0, st_mask = 0;
    if (state == QDEP_OK) {
        if (f->max_dep_loads > 0 &&
            !regs_to_mask(f, q->load_regs, q->n_load_regs, 0, &ld_mask)) {
            state = QDEP_R_UNREPRESENTABLE;
        } else if (f->max_dep_stores > 0 &&
                   !regs_to_mask(f, q->store_regs, q->n_store_regs, 0,
                                 &st_mask)) {
            state = QDEP_R_UNREPRESENTABLE;
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
    } else {
        /* The shadow, taken BEFORE the overwrite -- afterwards there is
         * nothing left to compare against. */
        if (!f->has_addr_deps) {
            g_shadow_absent.fetch_add(1, std::memory_order_relaxed);
        } else {
            /*
             * Compared as WHOLE MASKS, not as register sets.  An address
             * mask has an immediate bit as well as its register bits, and a
             * comparison over register sets alone cannot see it -- so a row
             * whose immediate bit this flip drops would have been scored as
             * agreement.  That is the erasure shape irdf's REG_IP drop had,
             * and it is not repeated here.
             */
            if (f->max_dep_loads > 0 && f->load_addr_dep_mask[0] != ld_mask) {
                g_shadow_ld_diff.fetch_add(1, std::memory_order_relaxed);
                mask_shadow_sig(&g_shadow_sigs, mnem, f, 0, "ldaddr",
                                f->load_addr_dep_mask[0], ld_mask);
            } else if (f->max_dep_loads > 0) {
                g_shadow_ld_same.fetch_add(1, std::memory_order_relaxed);
            }
            if (f->max_dep_stores > 0 && f->store_addr_dep_mask[0] != st_mask) {
                g_shadow_st_diff.fetch_add(1, std::memory_order_relaxed);
                mask_shadow_sig(&g_shadow_sigs, mnem, f, 0, "staddr",
                                f->store_addr_dep_mask[0], st_mask);
            } else if (f->max_dep_stores > 0) {
                g_shadow_st_same.fetch_add(1, std::memory_order_relaxed);
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

    /* ---------------- the store-data half of HAS_REG ---------------- */

    if (f->max_dep_stores == 0) {
        /* No store operand: no store_data_dep[] array exists to write. */
        g_dstate[QDEP_NONE].fetch_add(1, std::memory_order_relaxed);
        return;
    }

    uint64_t sd_mask = 0;
    if (dstate == QDEP_OK &&
        !regs_to_mask(f, q->data_regs, q->n_data_regs, q->data_load_slots,
                      &sd_mask)) {
        dstate = QDEP_R_UNREPRESENTABLE;
    }
    if (dstate == QDEP_OK && sd_mask == 0 && f->has_immediate) {
        /*
         * The stored value came from no register, no load slot and no env
         * state -- and the provenance that says so is COMPLETE, because
         * every way it could have been short is a refusal above.  A store
         * must take its datum from somewhere, so what is left is the
         * instruction's own encoding, which is exactly what the format's
         * immediate bit means.  `movq $5,(%rax)` and `callq` (whose pushed
         * return address is tcg_constant_tl(s->pc), target/i386/tcg/
         * translate.c:599-610) are the two shapes on the workload.
         *
         * Set only when the template HAS an immediate slot.  An indirect
         * `callq *%rax` pushes the same translation-time constant and has no
         * immediate operand, and pointing at a slot the template says does
         * not exist would be naming a source rather than reporting one; that
         * row publishes the empty mask, which is true as far as it goes.
         */
        sd_mask = 1ULL << (f->n_src_regs + f->max_dep_loads);
    }

    if (!f->has_reg_deps) {
        /*
         * The HAS_REG flag is clear, so store_data_dep[] is not on the wire
         * and the consumer is already at the all-inputs default.  Nothing to
         * displace and nothing to write -- see champsim_tracer_qdep.h on why
         * the flag is not promoted to carry a mask.  Counted in two buckets
         * so the report can say how much precision that costs: QDEP_NO_BLOCK
         * where QEMU HAD an answer, the refusal reason where it did not.
         */
        g_dstate[dstate == QDEP_OK ? QDEP_NO_BLOCK : dstate]
            .fetch_add(1, std::memory_order_relaxed);
        return;
    }

    /* The shadow, taken BEFORE the overwrite. */
    if (dstate == QDEP_OK) {
        uint64_t cap_mask = f->store_data_dep_mask[0];
        if (cap_mask == sd_mask) {
            g_shadow_sd_same.fetch_add(1, std::memory_order_relaxed);
        } else {
            g_shadow_sd_diff.fetch_add(1, std::memory_order_relaxed);
            data_shadow_sig(mnem, f, cap_mask, sd_mask);
        }
    }

    /*
     * Written either way, and that is the point.  When QEMU stated the datum
     * the mask is QEMU's; when it could not, the mask is the format's own
     * all-inputs default written out.  What never happens is the Capstone
     * mask staying where it is -- a family whose source has flipped may not
     * have rows still quietly carrying the old one.
     */
    uint64_t publish = (dstate == QDEP_OK) ? sd_mask : all_inputs_mask(f);
    for (uint8_t k = 0; k < f->max_dep_stores; k++) {
        f->store_data_dep_mask[k] = publish;
    }
    g_dstate[dstate].fetch_add(1, std::memory_order_relaxed);
}

void qdep_report(GString *report)
{
    uint64_t total = 0, dtotal = 0;

    for (unsigned s = 0; s < QDEP_STATE_COUNT; s++) {
        total += g_state[s].load(std::memory_order_relaxed);
        dtotal += g_dstate[s].load(std::memory_order_relaxed);
    }
    if (total == 0 && dtotal == 0) {
        return;
    }

    g_string_append(report,
        "\n=== address and store-data dependencies: the source is QEMU's "
        "emitters ===\n"
        "Three of the template dependency sub-block's four families --\n"
        "load_addr_dep[], store_addr_dep[] and store_data_dep[] -- are\n"
        "written from the provenance QEMU's own tcg_gen_qemu_ld/st emitters\n"
        "stated for each access, not from the Capstone MEM operand.  A row\n"
        "this extractor cannot state IN FULL reaches the format's own\n"
        "all-inputs default; it never publishes a short mask and never falls\n"
        "back to the Capstone answer.  The refusal rows below are that\n"
        "fallback, counted.\n");

    g_string_append(report, "\naddress families (HAS_ADDR):\n");
    for (unsigned s = 0; s < QDEP_STATE_COUNT; s++) {
        uint64_t v = g_state[s].load(std::memory_order_relaxed);
        if (v) {
            g_string_append_printf(report, "  %10" G_GUINT64_FORMAT
                                   "  %s\n", v, state_name(s));
        }
    }
    g_string_append(report,
        "\nstore-data family (the HAS_REG block's store_data_dep[]):\n");
    for (unsigned s = 0; s < QDEP_STATE_COUNT; s++) {
        uint64_t v = g_dstate[s].load(std::memory_order_relaxed);
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
        "  store data:    %" G_GUINT64_FORMAT " same, %" G_GUINT64_FORMAT " differ\n"
        "  %" G_GUINT64_FORMAT " rows had no Capstone address block to compare\n",
        g_shadow_ld_same.load(std::memory_order_relaxed),
        g_shadow_ld_diff.load(std::memory_order_relaxed),
        g_shadow_st_same.load(std::memory_order_relaxed),
        g_shadow_st_diff.load(std::memory_order_relaxed),
        g_shadow_sd_same.load(std::memory_order_relaxed),
        g_shadow_sd_diff.load(std::memory_order_relaxed),
        g_shadow_absent.load(std::memory_order_relaxed));

    g_mutex_lock(&g_tally_lock);
    dump_tally(report, g_shadow_sigs,
               "address shadow disagreements (qemu-extra = a register the OLD "
               "wire's mask did NOT name):");
    dump_tally(report, g_sd_sigs,
               "store-data shadow disagreements, by BIT of the published mask\n"
               "(qemu-extra = an input the OLD wire's mask did NOT name):");
    dump_tally(report, g_unmapped_name,
               "globals a provenance named that have no generic word\n(per ACCESS, so an instruction refused on both an address and a datum\ncounts twice here and once above):");
    dump_tally(report, g_monitor_name,
               "reservation-monitor value globals a store's datum named\n(the emulation-artefact category, #177 / f46873a738 -- NOT a decoder gap):");
    g_mutex_unlock(&g_tally_lock);
}
