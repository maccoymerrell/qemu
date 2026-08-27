/*
 * The wire's dependency families, from the emitters that stated them.
 *
 * Author: Maccoy Merrell
 *
 * See champsim_tracer_qdep.h for what this replaces, what the zero-register
 * ruling decided, why the HAS_REG flag being shared bounds both halves of
 * the register block, and which population of the DESTINATION family is
 * QEMU's -- the rest keeps the refiner's mask and is counted by cause.
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
/* The destination family's own column.  Third array for the same reason
 * there are two: a row refused here is refused for reasons the other two
 * cannot reach -- a wire destination QEMU named only as a CPUArchState byte
 * range -- and a merged column could not say which family that was. */
std::atomic<uint64_t> g_wstate[QDEP_STATE_COUNT];

/*
 * THE CAPSTONE SHADOW IS GONE, and that is a deletion rather than an
 * omission.  Six counters and two signature tallies used to score the masks
 * the operand walk would have published against the ones QEMU's emitters
 * state, on every row the wire takes from QEMU.  They fed nothing and were
 * kept as a comparison arm -- which is exactly the shape J7 forbids on a
 * path whose source has become QEMU, because a value still read is a value
 * still relied on and the next question that needs an answer takes it.  The
 * one-time A/B that retired them is in this wave's evidence, not in the
 * running plugin.
 *
 * What survives is QEMU-side and not comparative: a name QEMU's provenance
 * gave that this file has no generic word for is a REFUSAL, and a refusal
 * nobody can name is a refusal nobody can act on.
 */
GMutex g_tally_lock;
GHashTable *g_unmapped_name = nullptr;   /* qemu global name -> count */
GHashTable *g_monitor_name  = nullptr;   /* reservation-monitor global -> count */
/*
 * A TCG global QEMU stated a WRITE to that this file has no generic word
 * for.  Not a refusal: a name the tracer's vocabulary does not contain
 * cannot equal any `dst_regs[d]`, so it is never the slot a mask would be
 * written for.  Tallied because "it cannot be a destination" is a claim
 * about a population, and a population nobody counted is a population
 * nobody checked.
 */
GHashTable *g_dst_unmapped_name = nullptr;
/*
 * Every refused row by MNEMONIC and reason.  A refusal count that cannot say
 * WHICH instructions refused cannot be adjudicated, and an unadjudicated
 * refusal is a published all-inputs default nobody ever looks at again.  The
 * shadow tallies this replaces asked what CAPSTONE would have said; this one
 * asks what QEMU could not say, which is the only question left.
 */
GHashTable *g_refusal_sig   = nullptr;   /* "mnem  reason" -> count */

const char *state_name(unsigned s);

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

void note_refusal(const char *mnem, unsigned st, const char *fam,
                  const char *detail)
{
    char *k = g_strdup_printf("%-10s %s  %s%s%s", mnem ? mnem : "?", fam,
                              state_name(st),
                              (detail && *detail) ? " -- " : "",
                              (detail && *detail) ? detail : "");
    tally(&g_refusal_sig, k);
    g_free(k);
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
            if (slot >= QDEP_MAX_ACCESS) {
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
 * Turn a generic-register set into a mask over this template's src slots.
 *
 * Returns false when a named register occupies no slot -- there is no bit
 * to set, so the mask would be SHORT.  That is the disqualifying direction
 * and the whole instruction is refused for it.
 */
bool regs_to_mask(const InsnFields *f, const uint8_t *regs, uint8_t n,
                  uint8_t load_slots, uint64_t *out, char *why, size_t whysz)
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
            if (why) {
                g_snprintf(why, whysz, "no slot for %s",
                           generic_reg_name_or_unknown(regs[k]));
            }
            return false;
        }
    }
    /*
     * The load-data slots, for the store-data arm.  The bit positions start
     * at n_src_regs, and a slot beyond max_dep_loads has no bit to set --
     * which is the same disqualifying direction as a register with no slot,
     * so it fails the same way.
     */
    for (unsigned k = 0; k < QDEP_MAX_ACCESS; k++) {
        if (!(load_slots & (1u << k))) {
            continue;
        }
        if (k >= f->max_dep_loads || f->n_src_regs + k >= 64) {
            if (why) {
                g_snprintf(why, whysz, "no slot for LOAD%u (of %u)",
                           k, f->max_dep_loads);
            }
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
/*
 * Carry a REGISTER-side mask (dst_dep[] / store_data_dep[]) across a change
 * in the LOAD SLOT COUNT.
 *
 * The layout is  [0,nsrc) src | [nsrc, nsrc+nload) load-data | one imm bit
 * (champsim_tracer_mnemonics.h), so resizing the load run moves both bands
 * above the sources.  The src bits are untouched: they index a run this
 * change does not resize.
 *
 * The load band cannot always be carried exactly, and where it cannot the
 * answer is the OVER-approximation, never the short one -- a mask naming
 * fewer inputs than really feed a value tells a consumer it may issue before
 * a producer has landed:
 *
 *   GROWN   a slot the old count did not have is a sub-access of an operand
 *           the old count DID have: `vmovdqu (%rax),%ymm0` is one Capstone
 *           operand and two QEMU loads, and the destination takes both
 *           halves.  So a mask that named any load slot names every new one
 *           too; a mask that named none still names none, because the writer
 *           positively said this value does not come from memory.
 *   SHRUNK  a named slot may have no bit left.  Every remaining slot is set,
 *           and when none remain the memory input cannot be expressed at
 *           all -- *@lost says so and the caller publishes the all-inputs
 *           default rather than a mask that quietly dropped it.
 */
uint64_t carry_load_band(uint64_t m, unsigned nsrc, unsigned old_n,
                         unsigned new_n, bool *lost)
{
    const uint64_t src_bits = nsrc >= 64 ? ~0ULL : ((1ULL << nsrc) - 1);
    uint64_t out = m & src_bits;
    bool named = false;

    *lost = false;
    if (nsrc + new_n >= 64) {
        *lost = true;
        return out;
    }
    for (unsigned k = 0; k < old_n && nsrc + k < 64; k++) {
        if (m & (1ULL << (nsrc + k))) {
            named = true;
            if (k < new_n) {
                out |= 1ULL << (nsrc + k);
            }
        }
    }
    if (named) {
        if (new_n == 0) {
            *lost = true;
        }
        for (unsigned k = 0; k < new_n; k++) {
            out |= 1ULL << (nsrc + k);
        }
    }
    if (nsrc + old_n < 64 && (m & (1ULL << (nsrc + old_n)))) {
        out |= 1ULL << (nsrc + new_n);      /* the immediate bit */
    }
    return out;
}

uint8_t qemu_named_regs(const QDepInsn *q, uint8_t *out,
                        const InsnFields *f, bool dst_ok)
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
        for (uint8_t a = 0; a < q->n_loads; a++) {
            take(q->load_addr_regs[a], q->n_load_addr_regs[a]);
        }
        for (uint8_t a = 0; a < q->n_stores; a++) {
            take(q->store_addr_regs[a], q->n_store_addr_regs[a]);
        }
    }
    if (q->data_state == QDEP_OK) {
        for (uint8_t a = 0; a < q->n_stores; a++) {
            take(q->store_data_regs[a], q->n_store_data_regs[a]);
        }
    }
    /*
     * The DESTINATION family's inputs, last, and ONLY the rows that will
     * actually be published.  Last rather than first so that an instruction
     * whose destinations name nothing the memory families did not already
     * name keeps the exact prefix -- and therefore the exact bit positions --
     * it had before this family existed.
     *
     * @dst_ok is dst_precheck()'s verdict and @f is the slot list, because a
     * register seated for a destination the WIRE does not have is a source
     * on the wire that no dependency refers to.  See dst_precheck().
     */
    if (dst_ok && f) {
        for (uint8_t d = 0; d < f->n_dst_regs; d++) {
            for (uint8_t k = 0; k < q->n_dst; k++) {
                if (q->dst_reg[k] == f->dst_regs[d]) {
                    take(q->dst_dep_regs[k], q->n_dst_dep_regs[k]);
                    break;
                }
            }
        }
    }
    return n;
}

/*
 * THE DESTINATION FAMILY, read off the writes QEMU's emitters stated.
 *
 * `writes[]` carries, per TCG global this instruction defines, the set the
 * value came from -- the same provenance namespace the address and store-data
 * arms fold, so the same fold_prov() reads it and the same rules decide what
 * it may not say.  Two things are different and both are deliberate:
 *
 *   THE LOAD BAND IS OPEN.  @load_slots is non-NULL, because a destination
 *   genuinely may be a value this same instruction loaded -- that is what
 *   every load instruction is -- and the HAS_REG layout has a bit per load
 *   slot to carry it.  An ADDRESS mask has no such bits and refuses there.
 *
 *   THE ROWS ARE GENERIC, NOT GLOBAL.  Several globals stand for one
 *   architectural register: x86 lowers the flags onto cc_op, cc_dst, cc_src
 *   and cc_src2, and the wire has ONE destination slot for REG_FLAGS.  Its
 *   dependency set is the UNION over the globals that make it up, which is
 *   the only fold that cannot be short -- taking any one of them would drop
 *   the inputs the others carry.
 *
 * A written global with no generic word is SKIPPED and tallied, not refused.
 * It has no name in the tracer's vocabulary, so it cannot equal any
 * `dst_regs[d]`, so no mask is ever written for it.  What DOES decide the
 * family is the slot side, and that is decided in qdep_apply() where
 * `dst_regs[]` exists: a wire destination with no row here refuses the whole
 * instruction rather than leaving one slot to be filled from the answer this
 * flip replaces.
 */
void note_dst(const struct qemu_plugin_tb *tb, size_t idx, QDepInsn *out,
              const uint8_t *load_ord, unsigned n_memops)
{
    const unsigned nw = (g_nregs + 63) / 64;
    std::vector<uint64_t> wr(nw ? nw : 1);
    unsigned got;

    if (g_nregs == 0) {
        out->dst_state = QDEP_R_NORECORD;
        return;
    }
    got = qemu_plugin_insn_reg_writes(tb, idx, wr.data(), nw);
    if (got == QEMU_PLUGIN_DF_INCOMPLETE || got != nw) {
        out->dst_state = QDEP_R_NORECORD;
        return;
    }

    std::vector<uint64_t> w(g_prov_words);
    for (unsigned r = 0; r < g_nregs; r++) {
        uint8_t gen, k;
        uint8_t memop_slots = 0;
        QDepState rc;

        if (!(wr[r / 64] & (1ULL << (r % 64)))) {
            continue;
        }
        gen = g_gen_of_reg[r];
        if (gen >= REG_ID_COUNT) {
            const char *nm =
                qemu_plugin_dataflow_reg_name(r, nullptr, nullptr);
            tally(&g_dst_unmapped_name, nm ? nm : "?");
            continue;
        }
        for (k = 0; k < out->n_dst; k++) {
            if (out->dst_reg[k] == gen) {
                break;
            }
        }
        if (k == out->n_dst) {
            if (out->n_dst >= QDEP_MAX_DST) {
                out->dst_state = QDEP_R_WIDE;
                return;
            }
            out->dst_reg[out->n_dst++] = gen;
        }
        if (qemu_plugin_insn_write_prov(tb, idx, r, w.data(),
                                        g_prov_words) != g_prov_words) {
            out->dst_state = QDEP_R_NORECORD;
            return;
        }
        rc = fold_prov(w.data(), out->dst_dep_regs[k],
                       &out->n_dst_dep_regs[k], &memop_slots);
        if (rc == QDEP_OK) {
            /*
             * MEMOP ordinals into LOAD ordinals, exactly as the store-data
             * arm does it and for the same reason: QEMU numbers the
             * load-data provenance bits by position in the WHOLE access
             * list and the wire's load-data band is indexed by position
             * among the LOADS.
             */
            for (unsigned m = 0; m < QDEP_MAX_ACCESS; m++) {
                if (!(memop_slots & (1u << m))) {
                    continue;
                }
                if (m >= n_memops || load_ord[m] == 0xFF) {
                    rc = QDEP_R_UNREPRESENTABLE;
                    break;
                }
                out->dst_dep_load_slots[k] |= (uint8_t)(1u << load_ord[m]);
            }
        }
        if (rc != QDEP_OK) {
            out->dst_state = rc;
            return;
        }
    }
    out->dst_state = QDEP_OK;
}

/*
 * Publish the destination family, or say why it was not published.
 *
 * The matching runs HERE and not in note_dst() because it needs
 * `dst_regs[]`, which does not exist until the template builder has run the
 * operand walk.  What is matched is a GENERIC register on both sides: the
 * wire's destination slot d names dst_regs[d], and QEMU's rows name the
 * register each write folded to, so slot d takes the row for the same
 * register no matter what ORDER either side enumerated in.  There is no
 * k-th-of-one-is-k-th-of-the-other assumption to make.
 *
 * THE WHOLE FAMILY REFUSES ON ONE UNMATCHED SLOT.  A wire destination QEMU
 * named only as a CPUArchState byte range -- x86's XMM and x87 files,
 * aarch64's V registers -- has no row here (#218).  Filling the slots that
 * DID match and leaving that one as the refiner left it would publish a
 * block whose entries come from two sources, which is worse than either
 * source alone: nothing downstream can tell which entry is which.
 *
 * AND A REFUSED FAMILY KEEPS WHAT THE REFINER WROTE.  Not the all-inputs
 * default -- that is a WIDENING of a published mask, and widening the
 * remainder is a separate decision that belongs with the numbers for it,
 * not with this flip.  The surviving population is counted by cause and by
 * mnemonic so the size of the decision is a measurement.
 */
/*
 * WILL the destination family be written, and if not, why.
 *
 * Split out from the writing because the answer is needed BEFORE the source
 * index is rebuilt.  qemu_named_regs() seats every register a published mask
 * could name at the head of src_regs[], and seating one for a family that
 * then publishes nothing puts a register on the wire that no dependency
 * refers to.  That is not hypothetical: the first draft seated the PC write's
 * provenance on every aarch64 `br x17`, whose wire destination list is EMPTY,
 * and 1,786 instructions gained a REG_IP source with nothing pointing at it.
 * The validator's static_reg_sets check failed on 11 of them, which is the
 * gate doing its job -- and the reason this predicate exists.
 *
 * Every test here reads q, f->dst_regs[] and the two flags; none reads a bit
 * position, so all of it is decidable before the permutation.  The one check
 * that is NOT here is regs_to_mask()'s, and it cannot fail after the prefix
 * is seated: the prefix is exactly the set of registers those masks name.
 */
unsigned dst_precheck(const InsnFields *f, const QDepInsn *q,
                      char *why, size_t whysz)
{
    unsigned st = q->dst_state;

    if (f->n_dst_regs == 0) {
        return QDEP_NONE;       /* no slot: no dst_dep[] array to write */
    }
    if (f->n_dst_regs > MAX_DST_REGS) {
        return QDEP_R_WIDE;
    }
    if (st != QDEP_OK) {
        return st;
    }
    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        uint8_t k;

        for (k = 0; k < q->n_dst; k++) {
            if (q->dst_reg[k] == f->dst_regs[d]) {
                break;
            }
        }
        if (k == q->n_dst) {
            g_snprintf(why, whysz, "no QEMU write row for %s",
                       generic_reg_name_or_unknown(f->dst_regs[d]));
            return QDEP_R_DST_UNNAMED;
        }
        /*
         * R7.1's gate.  See QDEP_R_DST_SELF: a destination inside its own
         * provenance is an in-place lowering as often as it is an
         * accumulate, and nothing stated here separates them.
         */
        for (uint8_t z = 0; z < q->n_dst_dep_regs[k]; z++) {
            if (q->dst_dep_regs[k][z] == q->dst_reg[k]) {
                g_snprintf(why, whysz, "%s in its own provenance",
                           generic_reg_name_or_unknown(q->dst_reg[k]));
                return QDEP_R_DST_SELF;
            }
        }
        /*
         * THE CONSTANT GATE.  The store-data family substitutes the immediate
         * bit into an empty mask; this family may not, and the difference is
         * which ways the set can be empty.
         *
         * A store's datum arrives on a provenance whose every short shape is
         * already a refusal one gate earlier, so an empty set there leaves
         * exactly one candidate: the encoding.  A destination's does not.  It
         * can be empty because the value is the instruction's immediate,
         * because the source operand was the architectural ZERO REGISTER
         * whose note never reaches writes[].prov, or because the instruction
         * genuinely breaks the chain.  Choosing between those would be a
         * guess, and one of the three is the case R7.3 rules on by name.
         */
        if (q->n_dst_dep_regs[k] == 0 && q->dst_dep_load_slots[k] == 0) {
            g_snprintf(why, whysz, "empty set for %s",
                       generic_reg_name_or_unknown(q->dst_reg[k]));
            return QDEP_R_DST_UNSTATED_CONST;
        }
    }
    if (f->has_immediate) {
        g_snprintf(why, whysz, "immediate no provenance can mention");
        return QDEP_R_DST_UNSTATED_CONST;
    }
    if (!f->has_reg_deps) {
        /*
         * The flag is clear, so dst_dep[] is not on the wire at all and the
         * consumer is already at the all-inputs default.  Counted apart so
         * the cost of not promoting the flag is a number -- and the prefix
         * is not seated for it, because nothing will name those registers.
         */
        return QDEP_NO_BLOCK;
    }
    return QDEP_OK;
}

/*
 * Publish the destination family, or say why it was not published.
 *
 * The matching runs HERE and not in note_dst() because it needs
 * `dst_regs[]`, which does not exist until the template builder has run the
 * operand walk.  What is matched is a GENERIC register on both sides: the
 * wire's destination slot d names dst_regs[d], and QEMU's rows name the
 * register each write folded to, so slot d takes the row for the same
 * register no matter what ORDER either side enumerated in.  There is no
 * k-th-of-one-is-k-th-of-the-other assumption to make.
 *
 * THE WHOLE FAMILY REFUSES ON ONE UNMATCHED SLOT.  A wire destination QEMU
 * named only as a CPUArchState byte range -- x86's XMM and x87 files,
 * aarch64's V registers -- has no row here (#218).  Filling the slots that
 * DID match and leaving that one as the refiner left it would publish a
 * block whose entries come from two sources, which is worse than either
 * source alone: nothing downstream can tell which entry is which.
 *
 * AND A REFUSED FAMILY KEEPS WHAT THE REFINER WROTE.  Not the all-inputs
 * default -- that is a WIDENING of a published mask, and widening the
 * remainder is a separate decision that belongs with the numbers for it,
 * not with this flip.  The surviving population is counted by cause and by
 * mnemonic so the size of the decision is a measurement.
 */
void apply_dst(InsnFields *f, const QDepInsn *q, const char *mnem,
               unsigned wstate, const char *why)
{
    if (wstate != QDEP_OK) {
        if (wstate != QDEP_NONE && wstate != QDEP_NO_BLOCK) {
            note_refusal(mnem, wstate, "dst  ", why);
        }
        g_wstate[wstate].fetch_add(1, std::memory_order_relaxed);
        return;
    }
    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        uint8_t k;
        uint64_t m = 0;
        char w2[64] = "";

        for (k = 0; k < q->n_dst; k++) {
            if (q->dst_reg[k] == f->dst_regs[d]) {
                break;
            }
        }
        if (k == q->n_dst ||
            !regs_to_mask(f, q->dst_dep_regs[k], q->n_dst_dep_regs[k],
                          q->dst_dep_load_slots[k], &m, w2, sizeof(w2))) {
            /*
             * Unreachable by construction -- the prefix seated exactly these
             * registers -- so it is a REFUSAL and not a fallback: publishing
             * the slots that did resolve would leave the rest carrying the
             * answer this flip replaces, and the block would come from two
             * sources at once.
             */
            note_refusal(mnem, QDEP_R_UNREPRESENTABLE, "dst  ", w2);
            g_wstate[QDEP_R_UNREPRESENTABLE]
                .fetch_add(1, std::memory_order_relaxed);
            return;
        }
        f->dst_dep_mask[d] = m;
    }
    g_wstate[QDEP_OK].fetch_add(1, std::memory_order_relaxed);
}

const char *state_name(unsigned s)
{
    switch (s) {
    case QDEP_NONE:             return "no accesses / no dataflow ABI";
    case QDEP_OK:               return "PUBLISHED from QEMU's emitters";
    case QDEP_R_STATUS:         return "refused: extraction reported itself incomplete";
    case QDEP_R_NORECORD:       return "refused: qemu withheld the access list or a provenance";
    case QDEP_R_FIELD:          return "refused: provenance named env state with no generic word";
    case QDEP_R_UNMAPPED:       return "refused: provenance named a global with no generic word";
    case QDEP_R_WIDE:           return "refused: more address registers than the record holds";
    case QDEP_R_UNREPRESENTABLE:return "refused: a named input occupies no slot to set";
    case QDEP_R_EMU_MONITOR:    return "refused: names the reservation monitor's value half (emulation artefact, #177 / f46873a738)";
    case QDEP_R_REINDEX:        return "refused: QEMU's own source index does not fit (src slots or mask width)";
    case QDEP_R_HELPER_UNSTATED:return "refused: a helper-performed access whose operand travels through no argument (CP1)";
    case QDEP_NO_BLOCK:         return "stated by QEMU but the wire's HAS_REG flag is clear: consumer already at the default";
    case QDEP_R_DST_UNNAMED:    return "refused: a wire destination QEMU named only as env state, not as a TCG global (#218)";
    case QDEP_R_DST_UNSTATED_CONST: return "refused: a destination's value came from a constant QEMU's provenance cannot name -- an immediate, or the zero register R7.3 forbids dropping";
    case QDEP_R_DST_SELF:       return "refused: a destination is in its own provenance and R7.1 says only the INSTRUCTION's own source counts (in-place lowering)";
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
        out->state = out->data_state = out->dst_state = QDEP_R_NORECORD;
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
     * Since the wire's SLOT COUNT is this list's length, every flag here is
     * also a statement that the count is a lower bound rather than the MAX
     * the template header means -- which is why `have_list` stays false on
     * this path and the counts reach the format default instead.
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
        out->state = out->data_state = out->dst_state = QDEP_R_STATUS;
        return;
    }

    for (unsigned i = 0; i < kMaxMemops; i++) {
        mo[i].struct_size = sizeof(mo[i]);
    }
    n = qemu_plugin_insn_memops(tb, idx, mo, kMaxMemops);
    if (n == QEMU_PLUGIN_DF_INCOMPLETE || n > kMaxMemops) {
        out->state = out->data_state = out->dst_state = QDEP_R_NORECORD;
        return;
    }

    /*
     * From here the ACCESS LIST IS WHOLE, and that is the fact the slot
     * counts are taken from.  It stays true even when a provenance below is
     * refused: how many accesses there are and what each depends on are two
     * different questions, and only the second can fail on its own.
     */
    out->have_list = true;

    if (n == 0) {
        /*
         * No accesses: nothing to state for either MEMORY family.  The
         * destination family does not read the access list and is extracted
         * all the same -- an ALU instruction has no memop and is exactly
         * where dst_dep[] carries the whole of the answer.
         */
        uint8_t no_loads[kMaxMemops];

        memset(no_loads, 0xFF, sizeof(no_loads));
        out->state = out->data_state = QDEP_NONE;
        note_dst(tb, idx, out, no_loads, 0);
        return;
    }

    /*
     * Ordinals within each direction.  QEMU numbers the accesses in one
     * list; the wire numbers loads and stores separately, and the load-data
     * provenance bits are numbered the FIRST way while the mask band they
     * feed is indexed the SECOND.  @load_ord translates, and it exists
     * because on `lock cmpxchgl` the two happen to agree and on anything
     * whose accesses interleave they do not.
     */
    uint8_t load_ord[kMaxMemops];
    memset(load_ord, 0xFF, sizeof(load_ord));

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
        uint8_t a;

        /*
         * More accesses of one direction than this extractor holds.  QEMU's
         * own cap is the same number, so reaching it here means the list is
         * whole and simply wider than the arrays -- refuse the COUNT for
         * that direction rather than publish a truncated slot layout.
         */
        if ((store ? out->n_stores : out->n_loads) >= QDEP_MAX_ACCESS) {
            out->state = out->data_state = out->dst_state = QDEP_R_STATUS;
            out->have_list = false;
            return;
        }
        if (store) {
            a = out->n_stores++;
        } else {
            a = out->n_loads++;
            load_ord[i] = a;
        }
        /*
         * mo[i].count_unbounded is DELIBERATELY not consulted.  It says a
         * helper repeats THIS ONE stated access a data-dependent number of
         * times, and the slot count has never been a bound on the dynamic
         * count -- see champsim_tracer_qdep.h, and mnemonics.h on XSAVEOPT.
         * One record is one slot carrying one address mask either way.
         */
        if (qemu_plugin_insn_memop_addr_prov(tb, idx, i, w.data(),
                                             g_prov_words) != g_prov_words) {
            out->state = out->data_state = out->dst_state = QDEP_R_NORECORD;
            out->have_list = false;
            return;
        }
        /*
         * CP1.  A helper-performed access whose address is not one of the
         * helper's arguments hands over an EMPTY provenance, and folding it
         * would publish "this address depends on nothing" for an access that
         * genuinely reads registers -- the short mask this file exists never
         * to write.  The COUNT is still exact, because the access was
         * stated; only the mask is refused.
         */
        if (mo[i].addr_unstated) {
            if (out->state == QDEP_NONE) {
                out->state = QDEP_R_HELPER_UNSTATED;
            }
        }
        rc = store
            ? fold_prov(w.data(), out->store_addr_regs[a],
                        &out->n_store_addr_regs[a], nullptr)
            : fold_prov(w.data(), out->load_addr_regs[a],
                        &out->n_load_addr_regs[a], nullptr);
        if (rc != QDEP_OK && out->state == QDEP_NONE) {
            out->state = rc;    /* first refusal wins; a later access
                                 * succeeding does not undo it */
        }

        if (!store) {
            continue;
        }
        if (mo[i].data_unstated) {
            if (out->data_state == QDEP_NONE) {
                out->data_state = QDEP_R_HELPER_UNSTATED;
            }
            continue;
        }
        if (qemu_plugin_insn_memop_data_prov(tb, idx, i, w.data(),
                                             g_prov_words) != g_prov_words) {
            if (out->data_state == QDEP_NONE) {
                out->data_state = QDEP_R_NORECORD;
            }
            continue;
        }
        uint8_t memop_slots = 0;
        rc = fold_prov(w.data(), out->store_data_regs[a],
                       &out->n_store_data_regs[a], &memop_slots);
        if (rc == QDEP_OK) {
            /*
             * Translate MEMOP ordinals into LOAD ordinals.  A bit naming an
             * access that is not one of this instruction's loads is one this
             * extractor cannot place in the load-data band, and placing it
             * anywhere else would name a slot that means something different
             * -- so it is refused rather than approximated.
             */
            for (unsigned k = 0; k < QDEP_MAX_ACCESS; k++) {
                if (!(memop_slots & (1u << k))) {
                    continue;
                }
                if (k >= n || load_ord[k] == 0xFF) {
                    rc = QDEP_R_UNREPRESENTABLE;
                    break;
                }
                out->store_data_load_slots[a] |=
                    (uint8_t)(1u << load_ord[k]);
            }
        }
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
    if (out->data_state == QDEP_NONE && out->n_stores > 0) {
        out->data_state = QDEP_OK;
    }
    note_dst(tb, idx, out, load_ord, n);
}

void qdep_apply(InsnFields *f, InsnRegNames *rn, const QDepInsn *q,
                const char *mnem)
{
    if (!g_live || !q) {
        /*
         * The dataflow ABI handshake never succeeded, so there is no answer
         * to prefer and nothing to displace.  The counts stay exactly as the
         * operand walk left them: zeroing them here would gut every memory
         * annotation in the trace to say something this file did not learn.
         * The disablement itself is reported by name in qdep_report().
         */
        g_state[QDEP_NONE].fetch_add(1, std::memory_order_relaxed);
        g_dstate[QDEP_NONE].fetch_add(1, std::memory_order_relaxed);
        g_wstate[QDEP_NONE].fetch_add(1, std::memory_order_relaxed);
        return;
    }

    unsigned state = q->state;
    unsigned dstate = q->data_state;
    char wwhy[64] = "";

    /* ---------------- ADMISSION: the slot counts are QEMU's ------------- */
    /*
     * How many load slots and store slots this instruction HAS is now the
     * length of QEMU's access list for each direction, and no longer the
     * number of memory OPERANDS the Capstone walk enumerated.  The two were
     * never answers to the same question -- one operand is two accesses on
     * `vmovdqu`, `ldp` and `stp`, and `lock cmpxchgl` has a store no operand
     * counted -- and the count is what sizes the mask arrays, fixes the
     * register masks' load-data and immediate bit offsets, and decides
     * whether a runtime memop finds a static slot at all.
     *
     * When QEMU cannot state a direction's count the direction reaches the
     * format's own default, ZERO slots: no mask array, the consumer back at
     * all-to-all, and the DYNAMIC count still riding CST_FID_N_LOADS /
     * CST_FID_N_STORES.  It never falls back to the operand walk's number.
     */
    const uint8_t mdl_old = f->max_dep_loads;
    const uint8_t mds_old = f->max_dep_stores;
    uint8_t mdl_new = 0, mds_new = 0;
    unsigned adm = QDEP_OK;

    if (!q->have_list) {
        adm = (state == QDEP_R_STATUS) ? QDEP_R_STATUS : QDEP_R_NORECORD;
    } else {
        mdl_new = q->n_loads;
        mds_new = q->n_stores;
    }

    f->max_dep_loads  = mdl_new;
    f->max_dep_stores = mds_new;

    /*
     * The register masks were written against the OLD load run and have to
     * be re-seated onto the new one.  store_data_dep_mask[] is overwritten
     * in full further down and needs no carry; dst_dep_mask[] is overwritten
     * only where QEMU could state it, so the carry is what keeps the rows it
     * could NOT state readable in the new layout -- those keep the refiner's
     * answer, and a refiner's answer indexed against a load run that no
     * longer exists would name a slot that means something else.
     */
    if (mdl_old != mdl_new) {
        for (uint8_t d = 0; d < f->n_dst_regs; d++) {
            bool lost = false;
            uint64_t v = carry_load_band(f->dst_dep_mask[d], f->n_src_regs,
                                         mdl_old, mdl_new, &lost);
            f->dst_dep_mask[d] = lost ? all_inputs_mask(f) : v;
        }
    }

    /*
     * Seat QEMU's own register list at the head of src_regs[], so every mask
     * written below is written in a coordinate system QEMU owns.  Done after
     * the counts and before the masks, because the permutation carries the
     * load-data band with it and that band's width is the count just set.
     *
     * AND BEFORE THE NO-SLOT RETURN, which it was not until the destination
     * family arrived.  An instruction with no memory access used to leave
     * here with nothing to write; it now has a dst_dep[] to write, and a
     * mask indexed against the operand walk's order while claiming to be
     * QEMU's is exactly the coupling J3 measured and refused.
     */
    unsigned wstate = dst_precheck(f, q, wwhy, sizeof(wwhy));
    {
        uint8_t qregs[MAX_SRC_REGS];
        uint8_t nq = qemu_named_regs(q, qregs, f, wstate == QDEP_OK);

        if (nq && !reindex_src_for_qemu(f, rn, qregs, nq)) {
            /*
             * The index could not be seated, so nothing below can be
             * written in QEMU's coordinates.  Refuse all three families
             * rather than publish a mask indexed against the operand walk's
             * order while claiming it is QEMU's.
             */
            f->has_addr_deps = false;
            g_state[QDEP_R_REINDEX].fetch_add(1, std::memory_order_relaxed);
            if (f->has_reg_deps) {
                for (uint8_t st = 0; st < f->max_dep_stores; st++) {
                    f->store_data_dep_mask[st] = all_inputs_mask(f);
                }
            }
            g_dstate[QDEP_R_REINDEX].fetch_add(1, std::memory_order_relaxed);
            note_refusal(mnem, QDEP_R_REINDEX, "dst  ", nullptr);
            g_wstate[QDEP_R_REINDEX].fetch_add(1, std::memory_order_relaxed);
            return;
        }
    }

    if (mdl_new == 0 && mds_new == 0) {
        /*
         * No slots at all: neither MEMORY block has an array to live in,
         * whatever either side said.  Where that is QEMU's own answer -- an
         * instruction with no accesses -- it is not a refusal and there is
         * no claim here to refuse; where it is a refusal it is counted as
         * one, so the cost of the honest default is a number.
         */
        f->has_addr_deps = false;
        if (mds_old != 0 || mdl_old != 0) {
            /* Something WAS claimed and is now unclaimed; say which. */
            unsigned r = (adm != QDEP_OK) ? adm : QDEP_NONE;
            if (r != QDEP_NONE) {
                note_refusal(mnem, r, "count", nullptr);
            }
            g_state[r].fetch_add(1, std::memory_order_relaxed);
            g_dstate[r].fetch_add(1, std::memory_order_relaxed);
        } else {
            g_state[QDEP_NONE].fetch_add(1, std::memory_order_relaxed);
            g_dstate[QDEP_NONE].fetch_add(1, std::memory_order_relaxed);
        }
        apply_dst(f, q, mnem, wstate, wwhy);
        return;
    }

    /* ---------------- the HAS_ADDR block ---------------- */
    /*
     * One mask per ACCESS, and slot k is QEMU's access k in both the count
     * and the mask.  The MULTI refusal that used to sit here -- "nothing
     * proves the k-th of one list is the k-th of the other" -- was true of
     * two lists and has no subject when there is one.
     */
    char why[64] = "";
    char dwhy[64] = "";
    uint64_t ld_mask[QDEP_MAX_ACCESS];
    uint64_t st_mask[QDEP_MAX_ACCESS];
    memset(ld_mask, 0, sizeof(ld_mask));
    memset(st_mask, 0, sizeof(st_mask));

    if (state == QDEP_OK) {
        for (uint8_t k = 0; k < mdl_new && state == QDEP_OK; k++) {
            if (!regs_to_mask(f, q->load_addr_regs[k],
                              q->n_load_addr_regs[k], 0, &ld_mask[k],
                              why, sizeof(why))) {
                state = QDEP_R_UNREPRESENTABLE;
            }
        }
        for (uint8_t k = 0; k < mds_new && state == QDEP_OK; k++) {
            if (!regs_to_mask(f, q->store_addr_regs[k],
                              q->n_store_addr_regs[k], 0, &st_mask[k],
                              why, sizeof(why))) {
                state = QDEP_R_UNREPRESENTABLE;
            }
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
        note_refusal(mnem, state, "addr ", why);
        g_state[state].fetch_add(1, std::memory_order_relaxed);
    } else {
        for (uint8_t k = 0; k < mdl_new; k++) {
            f->load_addr_dep_mask[k] = ld_mask[k];
        }
        for (uint8_t k = 0; k < mds_new; k++) {
            f->store_addr_dep_mask[k] = st_mask[k];
        }
        f->has_addr_deps = true;
        g_state[QDEP_OK].fetch_add(1, std::memory_order_relaxed);
    }

    /* ---------------- the store-data half of HAS_REG ---------------- */

    if (mds_new == 0) {
        /* No store slot: no store_data_dep[] array exists to write. */
        g_dstate[dstate == QDEP_OK ? QDEP_NONE : dstate]
            .fetch_add(1, std::memory_order_relaxed);
        apply_dst(f, q, mnem, wstate, wwhy);
        return;
    }

    uint64_t sd_mask[QDEP_MAX_ACCESS];
    memset(sd_mask, 0, sizeof(sd_mask));
    if (dstate == QDEP_OK) {
        for (uint8_t k = 0; k < mds_new && dstate == QDEP_OK; k++) {
            if (!regs_to_mask(f, q->store_data_regs[k],
                              q->n_store_data_regs[k],
                              q->store_data_load_slots[k], &sd_mask[k],
                              dwhy, sizeof(dwhy))) {
                dstate = QDEP_R_UNREPRESENTABLE;
            }
        }
    }
    if (dstate == QDEP_OK && f->has_immediate) {
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
        for (uint8_t k = 0; k < mds_new; k++) {
            if (sd_mask[k] == 0) {
                sd_mask[k] = 1ULL << (f->n_src_regs + f->max_dep_loads);
            }
        }
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
        if (dstate != QDEP_OK) {
            note_refusal(mnem, dstate, "sdata(HAS_REG clear, unpublished)",
                         dwhy);
        }
        g_dstate[dstate == QDEP_OK ? QDEP_NO_BLOCK : dstate]
            .fetch_add(1, std::memory_order_relaxed);
        apply_dst(f, q, mnem, wstate, wwhy);
        return;
    }

    /*
     * Written either way, and that is the point.  When QEMU stated the datum
     * the mask is QEMU's; when it could not, the mask is the format's own
     * all-inputs default written out.  What never happens is the Capstone
     * mask staying where it is -- a family whose source has flipped may not
     * have rows still quietly carrying the old one.
     */
    for (uint8_t k = 0; k < mds_new; k++) {
        f->store_data_dep_mask[k] =
            (dstate == QDEP_OK) ? sd_mask[k] : all_inputs_mask(f);
    }
    if (dstate != QDEP_OK) {
        note_refusal(mnem, dstate, "sdata", dwhy);
    }
    g_dstate[dstate].fetch_add(1, std::memory_order_relaxed);

    apply_dst(f, q, mnem, wstate, wwhy);
}

void qdep_report(GString *report)
{
    uint64_t total = 0, dtotal = 0, wtotal = 0;

    for (unsigned s = 0; s < QDEP_STATE_COUNT; s++) {
        total += g_state[s].load(std::memory_order_relaxed);
        dtotal += g_dstate[s].load(std::memory_order_relaxed);
        wtotal += g_wstate[s].load(std::memory_order_relaxed);
    }
    if (total == 0 && dtotal == 0 && wtotal == 0) {
        return;
    }

    g_string_append(report,
        "\n=== template dependencies: the source is QEMU's emitters ===\n"
        "All FOUR of the template dependency sub-block's families --\n"
        "load_addr_dep[], store_addr_dep[], store_data_dep[] and\n"
        "dst_dep[] -- are written from the provenance QEMU's own emitters\n"
        "stated: the three memory families from what each\n"
        "tcg_gen_qemu_ld/st named, and dst_dep[] from what each register\n"
        "WRITE named.  The number of SLOTS the memory families have is the\n"
        "length of that access list.\n"
        "\n"
        "A memory row this extractor cannot state IN FULL reaches the\n"
        "format's own default -- all-inputs for a mask, ZERO slots for a\n"
        "count -- and never falls back to the Capstone operand walk.  A\n"
        "DESTINATION row it cannot state keeps what the refiner wrote,\n"
        "which is the one place a Capstone answer still reaches the wire;\n"
        "it is counted by cause and by mnemonic below, because widening\n"
        "that remainder to the default is a decision that belongs with the\n"
        "numbers for it and not with the flip.\n");

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
    g_string_append(report,
        "\ndestination family (the HAS_REG block's dst_dep[]);\n"
        "every row NOT reading `PUBLISHED from QEMU's emitters` or\n"
        "`no accesses / no dataflow ABI` still carries the refiner's mask:\n");
    for (unsigned s = 0; s < QDEP_STATE_COUNT; s++) {
        uint64_t v = g_wstate[s].load(std::memory_order_relaxed);
        if (v) {
            g_string_append_printf(report, "  %10" G_GUINT64_FORMAT
                                   "  %s\n", v, state_name(s));
        }
    }
    if (g_refusal) {
        g_string_append_printf(report, "  extractor DISABLED: %s\n", g_refusal);
    }

    g_mutex_lock(&g_tally_lock);
    dump_tally(report, g_unmapped_name,
               "globals a provenance named that have no generic word\n(per ACCESS, so an instruction refused on both an address and a datum\ncounts twice here and once above):");
    dump_tally(report, g_refusal_sig,
               "refused rows by mnemonic and reason (the format default,\nwritten out; `count` means the SLOT COUNT went to zero):");
    dump_tally(report, g_monitor_name,
               "reservation-monitor value globals a store's datum named\n(the emulation-artefact category, #177 / f46873a738 -- NOT a decoder gap):");
    dump_tally(report, g_dst_unmapped_name,
               "globals QEMU stated a WRITE to that have no generic word\n(skipped, not refused: a name the tracer's vocabulary does not contain\ncannot equal any dst_regs[d], so no mask is ever written for it):");
    g_mutex_unlock(&g_tally_lock);
}
