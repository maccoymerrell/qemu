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
    return n;
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

    /*
     * From here the ACCESS LIST IS WHOLE, and that is the fact the slot
     * counts are taken from.  It stays true even when a provenance below is
     * refused: how many accesses there are and what each depends on are two
     * different questions, and only the second can fail on its own.
     */
    out->have_list = true;

    if (n == 0) {
        /* No accesses: nothing to state, for either family. */
        out->state = out->data_state = QDEP_NONE;
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
            out->state = out->data_state = QDEP_R_STATUS;
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
            out->state = out->data_state = QDEP_R_NORECORD;
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
        return;
    }

    unsigned state = q->state;
    unsigned dstate = q->data_state;

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
     * be re-seated onto the new one.  dst_dep_mask[] is the refiners' and is
     * not rewritten below, so it is carried here; store_data_dep_mask[] is
     * overwritten in full further down and needs no carry.
     */
    if (mdl_old != mdl_new) {
        for (uint8_t d = 0; d < f->n_dst_regs; d++) {
            bool lost = false;
            uint64_t v = carry_load_band(f->dst_dep_mask[d], f->n_src_regs,
                                         mdl_old, mdl_new, &lost);
            f->dst_dep_mask[d] = lost ? all_inputs_mask(f) : v;
        }
    }

    if (mdl_new == 0 && mds_new == 0) {
        /*
         * No slots at all: neither block has an array to live in, whatever
         * either side said.  Where that is QEMU's own answer -- an
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
        return;
    }
    /*
     * Seat QEMU's own register list at the head of src_regs[], so every mask
     * written below is written in a coordinate system QEMU owns.  Done after
     * the counts and before the masks, because the permutation carries the
     * load-data band with it and that band's width is the count just set.
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
        "stated for each access, and the number of SLOTS each family has is\n"
        "the length of that access list.  A row this extractor cannot state\n"
        "IN FULL reaches the format's own default -- all-inputs for a mask,\n"
        "ZERO slots for a count -- and never falls back to the Capstone\n"
        "operand walk.  The refusal rows below are that default, counted.\n");

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

    g_mutex_lock(&g_tally_lock);
    dump_tally(report, g_unmapped_name,
               "globals a provenance named that have no generic word\n(per ACCESS, so an instruction refused on both an address and a datum\ncounts twice here and once above):");
    dump_tally(report, g_refusal_sig,
               "refused rows by mnemonic and reason (the format default,\nwritten out; `count` means the SLOT COUNT went to zero):");
    dump_tally(report, g_monitor_name,
               "reservation-monitor value globals a store's datum named\n(the emulation-artefact category, #177 / f46873a738 -- NOT a decoder gap):");
    g_mutex_unlock(&g_tally_lock);
}
