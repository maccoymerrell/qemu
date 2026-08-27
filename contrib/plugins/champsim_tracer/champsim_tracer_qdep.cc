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
/*
 * Env-field records per instruction.  Comfortably above QEMU's own
 * INSN_DF_MAX_FIELDS so the cap that bites is the extractor's, which SAYS it
 * overflowed, rather than this one, which would only see a smaller number.
 */
constexpr unsigned kMaxFields = 64;

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
 * The two remaining ways an ENV BYTE RANGE stays refused (#226).
 *
 * They are separate tallies because they are separate defects with separate
 * owners.  g_field_unnamed is a range no target DECLARED -- a gap in the
 * CPUArchState statement beside the globals, fixed in QEMU.  Both entries it
 * can carry name the shape, not the offset, because an offset means nothing
 * without the struct it indexes and the shapes are what a reader acts on.
 *
 * g_field_unmapped_name is a range QEMU DID name and the tracer has no
 * generic word for -- a gap in the register table, fixed in its generator.
 * Naming those by their QEMU spelling is the whole point: it is the list a
 * table pass works from.
 */
GHashTable *g_field_unnamed = nullptr;
GHashTable *g_field_unmapped_name = nullptr;
/*
 * A register QEMU DID give this file a generic word for, stated as WRITTEN
 * by an instruction whose destination family is published -- and which the
 * wire's own destination list does not carry.
 *
 * This is the direction of the two lists' disagreement that nothing counted.
 * dst_precheck() covers the other one: a wire destination with no QEMU write
 * row refuses the whole family (QDEP_R_DST_UNNAMED).  Its mirror was
 * silently dropped, and a silently dropped population is one nobody can say
 * is empty.  It is NOT empty: on the four-ISA workload it is 212 rows, and
 * every one of them names REG_PC.
 *
 * THE PC ROW IS NO LONGER EXCLUDED -- R10 (2026-08-27).  A translation block
 * ends by writing the program counter, and QEMU attributes that write to
 * whichever instruction happened to be last, so `lw` at 0x4fffe on mipsel is
 * a page-final load that writes the pc.  The exclusion argued that adding the
 * write would make a load into a jump; the maintainer's ruling is that it
 * does not, because the wire already has a field that says what an
 * instruction IS:
 *
 *     "It would be natural for any consumer to understand pc writes as
 *      branches, thus to treat pc dependencies differently (the consumer
 *      will likely drop the pc as a destination reg when consuming)."
 *
 * So the machine fact is published and `branch_type` stays the control-flow
 * authority.  seat_pc_destination() puts REG_PC in `dst_regs[]` where QEMU
 * states the write and the walk did not list it; both counters below are
 * now tripwires and both must be 0:
 *
 *   _pc    -- QEMU stated a pc write on a PUBLISHED row and the wire still
 *             does not carry it.  Reachable only if the slot list is
 *             already at MAX_DST_REGS, which is a capacity fact worth
 *             hearing about rather than silently dropping.
 *   _other -- any OTHER named register the machine writes and the wire does
 *             not name.  Unchanged, and still a must-be-0.
 */
GHashTable *g_dst_wire_missing = nullptr;   /* "mnem  REG" -> count */
std::atomic<uint64_t> g_dst_wire_missing_pc{0};
std::atomic<uint64_t> g_dst_wire_missing_other{0};
/*
 * R10 accounting: destinations seated by seat_pc_destination(), and of those,
 * the ones whose provenance QEMU could not state so the slot took the
 * format's own all-inputs default rather than a narrower claim.
 */
std::atomic<uint64_t> g_dst_pc_seated{0};
std::atomic<uint64_t> g_dst_pc_default{0};
/*
 * Address slots whose provenance was COMPLETE and named no register, on a
 * template that carries an immediate -- the encoding-derived address, counted
 * because a rule nobody can see fire is a rule nobody can check.  See the
 * immediate-provenance block in the HAS_ADDR section.
 */
std::atomic<uint64_t> g_addr_imm{0};
std::atomic<uint64_t> g_addr_empty_no_imm{0};
/*
 * DESTINATION slots the same rule reached: the write's provenance was
 * COMPLETE and named no register, no load slot and no env range, so the value
 * is the instruction's own encoding and the mask carries the immediate bit.
 * Counted per SLOT, beside the per-instruction refusal buckets, for
 * g_addr_imm's reason -- and because the population it replaces (#227) was
 * refused for as long as one refusal covered three different facts.
 */
std::atomic<uint64_t> g_dst_imm{0};
/*
 * The two DECIDED directions of the encoded-immediate rule (#248), on
 * destination slots whose mask ALSO names registers -- the population that
 * refused wholesale until the provenance bit existed.
 *
 * @g_dst_imm_feeds: the encoding reached this destination and the slot's mask
 * takes the immediate bit beside its registers -- `add $5,(%rax)`'s flags.
 * @g_dst_imm_absent: the decoder stated the immediate, an op read it, and it
 * did not arrive here, so the register-only mask is COMPLETE and abstains
 * from the bit -- `ldr x0,[x1,#8]`, whose #8 is the address's.
 *
 * Both are counted because a rule that only reports the direction it likes
 * cannot be checked: the abstention is a published claim of completeness and
 * is exactly as load-bearing as the bit.
 */
std::atomic<uint64_t> g_dst_imm_feeds{0};
std::atomic<uint64_t> g_dst_imm_absent{0};
/*
 * ACCUMULATES: destination slots published with the destination register in
 * their own mask (#228).
 *
 * Counted because this population was a refusal until the emitter could say
 * which self-reference is architectural, and a flip from "refused" to
 * "published" that reports no number is a claim nobody can check.  Every row
 * here is an instruction that takes its destination as a source -- R7's test
 * says the regfile must respect the edge and R3 says the tracer does not
 * elide it for being redundant.  The two shapes that are NOT this are gone
 * before they reach here: see dst_precheck().
 */
std::atomic<uint64_t> g_dst_accum{0};
/*
 * THE #236 FLIP'S REFUSE ROUTE, COUNTED BEFORE THE FLIP EXISTS.
 *
 * An instruction whose wire destination list is non-empty AND whose QEMU
 * write list is short by a register the source cannot name (aarch64 MOPS,
 * `env->xregs[mops_destreg(syndrome)]`).  The flip cannot publish QEMU's
 * list for these -- it would delete an architectural destination -- so the
 * flip must REFUSE the instruction, and this is how many that is.
 *
 * Nothing is refused today: the row counts, the wire does not move.
 */
std::atomic<uint64_t> g_dst_would_refuse_unbounded{0};
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
 * The generic word for an env byte range, by the name QEMU gives it.
 *
 * R5's case exactly: an env offset is a register whose storage no TCG global
 * happens to name, and the offset IS the identity.  QEMU inverts it -- each
 * target declares its register files beside the globals it registers -- and
 * this puts the answer through the same two-stage name map the globals go
 * through, because a register must not get one generic word by one route and
 * a different one by the other.
 *
 * REG_ID_COUNT when the range has no name (nothing declared covers it, or it
 * reaches past one register) or has a name the tracer's vocabulary does not
 * carry.  Both are refusals, and the caller tallies which.
 */
/*
 * Tally an env range by its OFFSET.
 *
 * The offset is meaningless without the struct it indexes and is exactly
 * what a reader needs: `pahole`-ing CPUArchState at that number names the
 * field, and naming it is the whole of the follow-up work.  A single
 * "some ranges are undeclared" key would report that a gap exists and
 * nothing about where.
 */
void tally_field_off(GHashTable **t, uint32_t off)
{
    char k[48];

    g_snprintf(k, sizeof(k), "env offset %u (0x%x), no target declaration",
               off, off);
    tally(t, k);
}

uint8_t generic_for_field_name(const char *nm)
{
    uint8_t gen;

    if (!nm || !*nm) {
        return REG_ID_COUNT;
    }
    gen = generic_for_qemu_name(nm);
    if (gen == REG_ID_COUNT) {
        gen = fold_nonarch(nm);
    }
    /*
     * REG_NONE is 0, so it passes every `< REG_ID_COUNT` test while meaning
     * the opposite: the register table carries the register and states that
     * it has NO generic word.  Returning it would put a dependency on
     * "REG_NONE" into a published mask, which is a fabricated edge.
     *
     * The rows that read that way are not the same set they were.  A row
     * Capstone cannot name USED to be REG_NONE by construction, because its
     * generic ID came from whichever Capstone constant routed to it and no
     * constant did -- so x86's `fctrl` said "no word" while REG_FPCW is
     * exactly the word for it.  QEMU_ONLY_REG_IDS in the generator answers
     * that from QEMU's side; what still reaches here is a register whose
     * ROLE the vocabulary has no class for (x86 efer, the segment bases).
     */
    if (gen == REG_NONE) {
        return REG_ID_COUNT;
    }
    return gen;
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
                    uint8_t *load_slots, uint8_t *saw_imm)
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
        } else if (qemu_plugin_dataflow_prov_encoded_imm(b)) {
            /*
             * THE INSTRUCTION'S OWN ENCODED IMMEDIATE, stated by the decoder
             * that materialised it (#248).  Not a register, so nothing is
             * added to @regs; reported through @saw_imm to the one family
             * that has a question only it can answer -- whether a
             * destination whose mask names registers ALSO depends on the
             * encoding.
             *
             * Consumed rather than refused on every arm, including the ones
             * that pass NULL.  The address and store-data families reached
             * their own settled reading of the encoding before this bit
             * existed (4a104e0be4, fb92a61ea4) and both key it on the mask
             * being EMPTY, which a bit that adds no register leaves it.
             * Refusing here instead would have turned every RIP-relative
             * address and every immediate store into a refusal for carrying
             * a fact.
             */
            if (saw_imm) {
                *saw_imm = 1;
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
            /*
             * An env byte range -- a register whose storage no TCG global
             * names.  QEMU inverts the offset for us (each target declares
             * its files beside its globals), so the answer is a NAME and
             * goes through the same map every global's does.
             *
             * What still refuses: a range nothing declared covers, one that
             * reaches past a single register -- a helper handed the whole
             * vector file starts at the same byte as an access to its first
             * element, and taking the first would publish a SHORT set -- and
             * a register the tracer's vocabulary has no word for.  Each is
             * tallied by name so the residual is a list, not an adjective.
             */
            char fnm[64];
            uint8_t gen;

            uint32_t foff = 0;

            qemu_plugin_dataflow_prov_field(b, &foff);
            if (!qemu_plugin_dataflow_prov_field_reg(b, fnm, sizeof(fnm))) {
                tally_field_off(&g_field_unnamed, foff);
                return QDEP_R_FIELD;
            }
            if (is_monitor_value(fnm)) {
                tally(&g_monitor_name, fnm);
                return QDEP_R_EMU_MONITOR;
            }
            gen = generic_for_field_name(fnm);
            if (gen >= REG_ID_COUNT) {
                tally(&g_field_unmapped_name, fnm);
                return QDEP_R_FIELD;
            }
            if (!add_reg(regs, n, gen)) {
                return QDEP_R_WIDE;
            }
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
                       &out->n_dst_dep_regs[k], &memop_slots,
                       &out->dst_dep_imm[k]);
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

    /*
     * THE WRITES THAT ARE NOT GLOBALS (#226).
     *
     * A vector register is written by a store into CPUArchState, not by a
     * write to a TCG global, so the loop above sees nothing at all for
     * `movdqa %xmm1,%xmm2` -- and the wire's destination list, which does
     * name REG_VEC2, then had no row to match and refused the whole family
     * (QDEP_R_DST_UNNAMED).  The env fields carry the same two facts a
     * global write does, the register and where its value came from, so
     * they go through the same union.
     *
     * A field whose range has no name, or a name with no generic word, is
     * SKIPPED and tallied exactly as an unmapped global is: it cannot equal
     * any dst_regs[d], so no mask is ever written for it, and the wire slot
     * that wanted it refuses one gate later where the slot list exists.
     */
    unsigned nf = qemu_plugin_insn_fields(tb, idx, nullptr, 0);

    if (nf == QEMU_PLUGIN_DF_INCOMPLETE) {
        out->dst_state = QDEP_R_NORECORD;
        return;
    }
    if (nf > kMaxFields) {
        out->dst_state = QDEP_R_WIDE;
        return;
    }
    if (nf) {
        qemu_plugin_dataflow_field fl[kMaxFields];

        for (unsigned i = 0; i < nf; i++) {
            fl[i].struct_size = sizeof(fl[i]);
        }
        if (qemu_plugin_insn_fields(tb, idx, fl, nf) != nf) {
            out->dst_state = QDEP_R_NORECORD;
            return;
        }
        for (unsigned i = 0; i < nf; i++) {
            char fnm[64];
            uint8_t gen, k;
            uint8_t memop_slots = 0;
            QDepState rc;

            if (!(fl[i].dir & QEMU_PLUGIN_DF_WR)) {
                continue;
            }
            if (!qemu_plugin_dataflow_field_reg(fl[i].env_offset, fl[i].size,
                                                fnm, sizeof(fnm))) {
                tally_field_off(&g_field_unnamed, fl[i].env_offset);
                continue;
            }
            /*
             * R7.7's category, reached by the field route rather than the
             * global one: the reservation monitor is a product of the
             * emulation and is deliberately given no generic word.  Skipped
             * like any other write with no word, and tallied where the
             * globals' monitor writes are so the category stays one number.
             */
            if (is_monitor_value(fnm)) {
                tally(&g_monitor_name, fnm);
                continue;
            }
            gen = generic_for_field_name(fnm);
            if (gen >= REG_ID_COUNT) {
                tally(&g_field_unmapped_name, fnm);
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
            if (qemu_plugin_insn_field_prov(tb, idx, i, w.data(),
                                            g_prov_words) != g_prov_words) {
                out->dst_state = QDEP_R_NORECORD;
                return;
            }
            rc = fold_prov(w.data(), out->dst_dep_regs[k],
                           &out->n_dst_dep_regs[k], &memop_slots,
                           &out->dst_dep_imm[k]);
            if (rc == QDEP_OK) {
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
    }
    out->dst_state = QDEP_OK;
}

/*
 * R10 -- THE TERMINATOR'S pc WRITE IS A WIRE DESTINATION.
 *
 * A translation block ends by writing the program counter.  QEMU charges
 * that write to whichever instruction was last in the block, which on a
 * page boundary is an ordinary `lw` or `mov` that no ISA manual calls a
 * branch.  The wire's destination list comes from the operand walk and the
 * walk has never listed it, so the machine wrote a register the trace did
 * not name -- 3/0/3/209 rows on the four-ISA workload at c9d278d247, and
 * the number is layout-dependent because WHICH instruction lands last
 * depends on where the page ends.
 *
 * It is published now.  The ruling's own reason is the consumer's:
 * consumers read a pc write as control flow and drop pc as a destination
 * register, so stating the fact costs a consumer nothing and hiding it
 * costs one the ability to see block boundaries at all.
 *
 * TWO THINGS THIS DOES NOT DO.
 *
 * It does not change what the instruction IS.  `branch_type` is the
 * control-flow authority and is not consulted or written here; a page-final
 * `lw` carrying REG_PC is still BRANCH_NONE, and any future coupling of
 * classification to the pc destination is a defect, not a shortcut.
 *
 * It does not turn a publishing row into a refusal.  The seating happens
 * AFTER dst_precheck() has already returned its verdict on the list the
 * walk built, so a row that published before publishes now.  The cost of
 * that order is that the new slot never went through precheck's immediate
 * rules, which is why apply_dst() gives it the all-inputs default rather
 * than the "empty and complete means the encoding" reading: a block-final
 * pc write's constant is the translator's next-PC, not a field of the
 * instruction, and claiming the encoding for it would be a fabrication of
 * exactly the kind #205 and #248 closed.  Where QEMU DOES state a
 * provenance -- a real branch's target registers -- that mask is published
 * unchanged, because it is the machine's answer.
 *
 * Returns the seated slot index, or 0xFF when nothing was seated (QEMU
 * stated no pc write, the wire already carries it, or the slot list is
 * full -- the last of which leaves the tripwire counting, deliberately).
 */
uint8_t seat_pc_destination(InsnFields *f, InsnRegNames *rn,
                            const QDepInsn *q)
{
    bool stated = false;

    for (uint8_t k = 0; k < q->n_dst; k++) {
        if (q->dst_reg[k] == REG_PC) {
            stated = true;
            break;
        }
    }
    if (!stated) {
        return 0xFF;
    }
    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        if (f->dst_regs[d] == REG_PC) {
            return 0xFF;    /* the walk listed it; nothing to add */
        }
    }
    if (f->n_dst_regs >= MAX_DST_REGS) {
        return 0xFF;        /* counted by g_dst_wire_missing_pc */
    }

    uint8_t slot = f->n_dst_regs++;

    f->dst_regs[slot] = REG_PC;
    f->dst_dep_mask[slot] = 0;
    /*
     * No lanes.  The pc is scalar, and a scalar destination on a vector
     * instruction already carries a zero lane mask -- the operand walk only
     * assigns lanes from vector operands.  This is that same shape, not a
     * new one, and extr_u64_dst_lane_mask() gates on has_vec_lanes so a
     * scalar instruction never publishes it at all.
     */
    f->dst_lane_mask[slot] = 0;
    if (rn && rn->dst_qemu_reg_keys) {
        /*
         * The same key every walk-built slot carries.  Without it the slot
         * names a register whose VALUE never reaches the wire, and the
         * goto_tb override in snap_prev_tail_dsts() -- which stamps the
         * BB-terminating instruction's pc destination with the successor
         * this block actually went to -- would have nothing to override.
         */
        rn->dst_qemu_reg_keys[slot] = qemu_reg_key_for_generic(REG_PC);
    }
    g_dst_pc_seated.fetch_add(1, std::memory_order_relaxed);
    return slot;
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
 * and 1,786 instructions gained a REG_PC source with nothing pointing at it.
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
         * A DESTINATION IN ITS OWN PROVENANCE IS NOW A DECISION AND NOT A
         * DILEMMA, and this is where the old refusal stood.
         *
         * The two shapes it could not separate are separated at the emitter
         * now.  An in-place LOWERING -- riscv64's `flw fa0,0(a6)` loading
         * straight into cpu_fpr[rd] and NaN-boxing it there -- reads back a
         * value THIS instruction produced, and df_written_prov() forwards
         * that write's own provenance instead of naming the register, so the
         * self-reference never arrives.  A narrow WRITEBACK -- `setne %al`,
         * `mtc1` -- reads the register only to carry the bits it does not
         * write, and insn_dataflow_note_preserve_read() says so at the
         * writeback, so that read contributes nothing (R7.1: a register is a
         * source when the INSTRUCTION takes it as one).
         *
         * What is left is the genuine accumulate: `add %rax,%rbx`, `push`
         * and `pop` on RSP, `movk` on Xd, `lwl`/`lwr` merging into their
         * destination, `cmovcc` preserving it on a false condition.  Every
         * one of those is an edge a renaming regfile must respect (R7), and
         * R3 forbids eliding a dependency because it looks redundant -- the
         * tracer records it and a downstream simulator decides what to do
         * with it.  So it PUBLISHES, and it is counted so the population is
         * visible rather than assumed.
         */
        for (uint8_t z = 0; z < q->n_dst_dep_regs[k]; z++) {
            if (q->dst_dep_regs[k][z] == q->dst_reg[k]) {
                g_dst_accum.fetch_add(1, std::memory_order_relaxed);
                break;
            }
        }
        /*
         * THE CONSTANT GATE, split into the two shapes it used to report as
         * one.  A destination's provenance can be empty for three reasons and
         * they do NOT have one answer, which is why one refusal covering all
         * three could never be discharged:
         *
         *   the value is the instruction's own ENCODING -- the empty-and-
         *   complete reading the address and store-data families already run
         *   under, and the template has an immediate slot to point at;
         *
         *   the source operand was the architectural ZERO REGISTER, which
         *   reaches this set as a provenance BIT (INSN_DF_ZERO_PROV_BIT) now
         *   that insn_dataflow_note_zero_reg() is anchored to the writing
         *   instruction -- so such a row is no longer empty and does not
         *   arrive here at all;
         *
         *   a constant that is neither, which nothing here can name.
         *
         * The first two publish.  Only the third refuses, and it is counted
         * under its own state so its size is a number rather than a residue.
         */
        if (q->n_dst_dep_regs[k] == 0 && q->dst_dep_load_slots[k] == 0) {
            if (!f->has_immediate) {
                g_snprintf(why, whysz, "empty set for %s",
                           generic_reg_name_or_unknown(q->dst_reg[k]));
                return QDEP_R_DST_UNSTATED_CONST;
            }
            /*
             * The encoding.  apply_dst() writes the immediate bit for this
             * slot; nothing is refused for it.
             */
        } else if (f->has_immediate) {
            /*
             * The destination named registers AND the instruction carries an
             * immediate.  The encoding is an ADDITIONAL candidate source
             * beside the registers QEMU named, and no reading of "empty and
             * complete" reaches it -- which is why this was a flat refusal
             * until the ENCODED-IMMEDIATE PROVENANCE BIT existed (#248).
             *
             * Neither of the two rules that suggest themselves survives its
             * counter-example.  A blanket bit is refuted by `ldr x0,[x1,#8]`:
             * that destination's value came from the LOAD, and the #8 is the
             * ADDRESS's, already carried in load_addr_dep[] -- setting the
             * bit here would put the address's arithmetic into the data mask,
             * the one conflation the separate provenances exist to prevent.
             * And "it depends on the immediate unless there is a load" is
             * refuted by `add $5,(%rax)`, whose FLAGS destination does depend
             * on the 5.
             *
             * The BIT decides it, because it is a fact rather than a rule:
             * the decoder that materialised the encoding's immediate said so,
             * and the bit travelled the same dataflow every other provenance
             * bit travels.  Where it arrived is the answer, in both
             * directions.
             */
            if (q->dst_dep_imm[k]) {
                /*
                 * The encoding reached this destination.  Nothing is refused;
                 * apply_dst() adds the immediate bit to this slot's mask.
                 */
            } else if (q->imm_stated && q->imm_reached) {
                /*
                 * The decoder stated the immediate, the value it named was
                 * read by an op of this instruction, and it did not arrive
                 * here.  The register-only mask IS complete: this is the
                 * `ldr x0,[x1,#8]` case, and the #8 is in the address mask
                 * where a consumer that wants it will find it.
                 */
            } else if (q->imm_stated) {
                /*
                 * Stated, but QEMU folded the value away before any op read
                 * it -- `addi rd,rs,0` lowers to a move.  The bit had nowhere
                 * to travel, so its absence is the emulator's optimisation
                 * and not the machine's, which R7.3 forbids publishing.
                 */
                g_snprintf(why, whysz, "immediate folded before any op");
                return QDEP_R_DST_IMM_FOLDED;
            } else {
                /*
                 * No decoder on this instruction's path states its encoded
                 * immediate yet.  The absence of the bit means nobody looked.
                 * Refused, and counted per mnemonic so the coverage hole is a
                 * LIST of decoder paths rather than an adjective.
                 */
                g_snprintf(why, whysz, "no decoder stated this immediate");
                return QDEP_R_DST_IMM_UNSTATED_PATH;
            }
        }
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

static bool qdep_mutate_is(const char *want)
{
    static const char *mode;
    static bool read;

    if (!read) {
        mode = getenv("QEMU_DF_MUTATE");
        read = true;
    }
    return mode && !strcmp(mode, want);
}

/*
 * Move a published destination mask, without changing what it can express.
 *
 * The immediate bit is the one slot every layout has -- it sits above the
 * source registers and the load-data band, so it exists whatever the
 * template's shape -- and flipping it moves the mask's VALUE and its
 * resolved NAME set together.  Non-emptiness is preserved in both
 * directions because emptiness is a decision made elsewhere and must not
 * be made here: an empty mask is how the encoding rule is spelled, and a
 * mask that exists at all is what dep_publish() decided from the refiner's
 * answer.  A mutation that emptied or filled one would move rows by moving
 * a gate rather than a mask, and the movement would not be this family's.
 */
static uint64_t qdep_move_mask(const InsnFields *f, uint64_t m)
{
    unsigned imm = (unsigned)f->n_src_regs + f->max_dep_loads;
    uint64_t b;

    if (m == 0 || imm >= 63) {
        return m;
    }
    b = 1ULL << imm;
    return (m == b) ? (m | 1ULL) : (m ^ b);
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
               unsigned wstate, const char *why, uint8_t pc_slot)
{
    if (wstate != QDEP_OK) {
        if (wstate != QDEP_NONE && wstate != QDEP_NO_BLOCK) {
            note_refusal(mnem, wstate, "dst  ", why);
        }
        g_wstate[wstate].fetch_add(1, std::memory_order_relaxed);
        return;
    }
    /*
     * THE DESTINATION LIST IS STILL THE OPERAND WALK'S, and this is the one
     * place that can see it.  The masks below are QEMU's and are written in
     * a source coordinate system QEMU owns; which SLOT each one belongs to,
     * and how many slots exist, is `dst_regs[]` -- and that comes from the
     * walk.  Counted here rather than argued about: see g_dst_wire_missing.
     */
    for (uint8_t k = 0; k < q->n_dst; k++) {
        bool on_wire = false;

        for (uint8_t d = 0; d < f->n_dst_regs; d++) {
            if (f->dst_regs[d] == q->dst_reg[k]) {
                on_wire = true;
                break;
            }
        }
        if (on_wire) {
            continue;
        }
        if (q->dst_reg[k] == REG_PC) {
            g_dst_wire_missing_pc.fetch_add(1, std::memory_order_relaxed);
        } else {
            char *key = g_strdup_printf("%-10s %s", mnem ? mnem : "?",
                                        generic_reg_name_or_unknown(
                                            q->dst_reg[k]));
            tally(&g_dst_wire_missing, key);
            g_free(key);
            g_dst_wire_missing_other.fetch_add(1, std::memory_order_relaxed);
        }
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
        if (m == 0 && d == pc_slot) {
            /*
             * THE SEATED pc SLOT, and it never reaches the encoding rule
             * below.  That rule reads an empty-and-complete provenance as
             * "the value is the instruction's own immediate", which is true
             * of every slot dst_precheck() vetted and false of this one: a
             * block-final pc write is `movi` of the NEXT PC, a number the
             * translator computed, not a field anyone decoded.  The format's
             * own over-approximation is the honest answer -- it claims no
             * more than "this depends on the instruction's inputs", which
             * cannot be wrong, where the encoding bit would claim something
             * specific and false.
             */
            m = all_inputs_mask(f);
            g_dst_pc_default.fetch_add(1, std::memory_order_relaxed);
        } else if (m == 0) {
            /*
             * THE ENCODING.  The provenance is empty and it is COMPLETE --
             * every way it could have been short is a refusal in
             * dst_precheck() -- so the value came from the one place a
             * provenance made of registers and env ranges cannot name: the
             * instruction's own encoding.  dst_precheck() has already refused
             * the case with no immediate slot to point at, so reaching here
             * means the bit exists.
             *
             * The same rule 4a104e0be4 settled for the address families and
             * fb92a61ea4 for store data, under #230's condition -- it fires
             * only where NO NOTE NAMES A REGISTER.  A folded register and the
             * architectural zero register both arrive as provenance bits, so
             * a row whose encoding does name a register has a non-empty mask
             * and never reaches this line.  A shape that ought to carry a
             * note appearing in this count means the note is not reaching the
             * write, never that the rule needs an exception.
             */
            m = 1ULL << (f->n_src_regs + f->max_dep_loads);
            g_dst_imm.fetch_add(1, std::memory_order_relaxed);
        } else if (f->has_immediate) {
            /*
             * THE ENCODING BESIDE REGISTERS (#248).  The mask is not empty,
             * so the "empty and complete" reading above cannot reach this
             * slot -- but the instruction carries an immediate, and whether
             * that immediate is one of THIS destination's sources is a
             * question the register names cannot settle.
             *
             * The encoded-immediate provenance bit settles it, and
             * dst_precheck() has already refused every row where it could
             * not: a row reaching here either carries the bit or was proven
             * not to, so both branches are decisions and neither is a
             * default.
             */
            if (q->dst_dep_imm[k]) {
                m |= 1ULL << (f->n_src_regs + f->max_dep_loads);
                g_dst_imm_feeds.fetch_add(1, std::memory_order_relaxed);
            } else {
                g_dst_imm_absent.fetch_add(1, std::memory_order_relaxed);
            }
        }
        /*
         * THE DESTINATION FAMILY'S J3 CONTROL (#249), and it is placed on
         * the last line that writes a published mask because nothing
         * earlier can serve.
         *
         * The `mnem` arm every other family's zero is scored against blanks
         * the opcode taxonomy, and the refiner then emits no dep block at
         * all: on aarch64, riscv64 and mipsel the control arm's whole
         * subject vanished, so no dst zero on those ISAs was ever quotable.
         * Two mutations further upstream were built and MEASURED before
         * this one, and both are inert on at least one ISA for a reason
         * worth keeping: scribbling the refiner's mask (`refmask`) moves
         * only the rows this function REFUSED, and corrupting QEMU's write
         * provenance (`wprov`, plugins/api.c) moves only the rows where
         * QEMU's answer and the refiner's DIFFER -- and on aarch64 they
         * agree, because a load's destination is `LOAD0` to both.  A
         * control has to move where the two sources agree as well as where
         * they do not, which is only possible after the choice between
         * them has been made.  So the arm lands here, on the value that
         * actually reaches the wire, and every QDEP_OK destination on every
         * ISA is its subject.
         *
         * It is a control and not a test: it says the chain from this
         * assignment to the scorer's key is live for this family on this
         * ISA.  What the mask is SOURCED from is what the Capstone arms and
         * the two upstream arms measure.
         */
        f->dst_dep_mask[d] = qdep_mutate_is("dstmask") ?
                             qdep_move_mask(f, m) : m;
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
    case QDEP_R_DST_UNSTATED_CONST: return "refused: a destination's value came from a constant that is neither the encoding nor the zero register";
    case QDEP_R_DST_IMM_UNSTATED: return "refused: the instruction carries an immediate QEMU's provenance cannot mention, so a register-only mask would be short by the immediate bit";
    case QDEP_R_DST_IMM_UNSTATED_PATH: return "refused: the instruction carries an immediate NO DECODER ON ITS PATH STATES, so an absent immediate-provenance bit means nobody looked (#248 coverage)";
    case QDEP_R_DST_IMM_FOLDED: return "refused: the decoder stated this instruction's immediate and QEMU folded the value away before any op read it, so the absent bit is the emulator's optimisation";
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

    /*
     * The two encoded-immediate facts, carried whole to the destination
     * family (#248).  Not a refusal condition on their own: an instruction
     * whose decoder never states an immediate is perfectly extractable in
     * every other respect, and only the one rule that would read an ABSENT
     * immediate bit as an answer has to know.
     */
    out->imm_stated = st.imm_stated;
    out->imm_reached = st.imm_reached;
    /*
     * The destination-side unbounded flag, carried but NOT acted on -- see
     * QDepInsn::writes_unbounded.  It is deliberately not in the refusal
     * test above: st.n_helper_unbounded there is about SOURCES the walk
     * could not see, and refusing on it keeps a short mask off the wire.
     * This one is about a DESTINATION QEMU wrote and could not name, which
     * only matters once the wire's list is QEMU's -- i.e. at the flip.
     */
    out->writes_unbounded = st.helper_writes_unbounded;

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
                        &out->n_store_addr_regs[a], nullptr, nullptr)
            : fold_prov(w.data(), out->load_addr_regs[a],
                        &out->n_load_addr_regs[a], nullptr, nullptr);
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
                       &out->n_store_data_regs[a], &memop_slots, nullptr);
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

/*
 * THE J3 CONTROL CANDIDATE THAT SCORES THE REFINER, not QEMU (#249).
 *
 * Every mask the destination family publishes is written twice: the row's
 * `.dep_refine` writes one from Capstone's operand detail, and qdep_apply()
 * below overwrites it with QEMU's provenance -- or does NOT, on the rows it
 * refuses, where the refiner's answer is what reaches the wire.  Scribbling
 * the refiner's mask HERE, in the window between the two writers, therefore
 * moves exactly the destination slots the wire still takes from Capstone,
 * and nothing else.  It is a measurement of the family's residual coupling
 * with the sign of a control: rows that move are rows QEMU did not decide.
 *
 * NON-EMPTINESS IS PRESERVED, because emptiness is a decision elsewhere:
 * dep_publish() reads the refiner's mask to decide whether a dep block
 * exists at all (#242/#247), so a scribble that emptied a mask, or filled
 * an empty one, would change which blocks are on the wire and the movement
 * would be the block gate's rather than the mask's.  Flipping the immediate
 * bit of a non-empty mask cannot do either.
 */
void qdep_mutate_refiner_dst(InsnFields *f)
{
    if (!qdep_mutate_is("refmask") || !f || !f->dst_dep_mask) {
        return;
    }
    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        f->dst_dep_mask[d] = qdep_move_mask(f, f->dst_dep_mask[d]);
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
    /*
     * THE #236 FLIP'S REFUSE ROUTE, COUNTED (not taken).
     *
     * Counted HERE and not in qdep_note_insn() because the question only
     * exists where the wire has a destination list to replace: an
     * instruction with no destination slot has nothing for the flip to get
     * wrong.  `f->n_dst_regs` is that list, and it does not exist until the
     * template builder has run.
     *
     * This is the population the flip would have to REFUSE rather than
     * publish, because QEMU's write list is short by a register whose index
     * the source does not state.  It is a lower bound on nothing and an
     * upper bound on nothing -- it is exactly the set, and it is counted
     * before the flip so the flip's cost is measured rather than argued.
     */
    if (q->writes_unbounded && f->n_dst_regs) {
        g_dst_would_refuse_unbounded.fetch_add(1, std::memory_order_relaxed);
    }
    /*
     * R10: seat the terminator's pc write BEFORE the source index is built,
     * so the new slot's provenance registers are in the prefix every mask
     * below is written against, and AFTER dst_precheck() so its verdict is
     * the one the walk's own list earned.  Gated on that verdict because a
     * refused family never reaches apply_dst()'s mask loop: seating a slot
     * there would put a name on the wire with nothing to fill it.
     */
    uint8_t pc_slot = 0xFF;
    if (wstate == QDEP_OK) {
        pc_slot = seat_pc_destination(f, rn, q);
    }
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
        apply_dst(f, q, mnem, wstate, wwhy, pc_slot);
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

    if (state == QDEP_OK) {
        /*
         * THE IMMEDIATE-PROVENANCE RULE, ON THE ADDRESS SIDE.
         *
         * fb92a61ea4 established it for store data: a provenance that is
         * EMPTY and COMPLETE cannot mean the value came from nowhere, and
         * the only remaining source is the instruction's own encoding, which
         * is what the format's immediate bit means.  An address is under the
         * same arithmetic -- it is computed from registers, from the
         * encoding, or from both -- so the same reading applies and this
         * settles it deliberately rather than leaving an empty address mask
         * to mean two different things depending on which shape produced it.
         * The x86-64 shape is displacement-only addressing, where the modrm
         * names no base and no index.
         *
         * COMPLETE is what makes it sound, and completeness here is not an
         * assumption: every way the provenance could have been short -- an
         * unrepresentable register, an env range with no generic word, a
         * dropped note -- is a refusal that has already sent this row to the
         * all-inputs default above, so reaching this line means QEMU stated
         * the address in full and stated no register.
         *
         * AND IT MAY FIRE ONLY WHERE NO NOTE NAMES A REGISTER, which is
         * #230's lesson written as a condition rather than as advice.  A
         * RIP-relative access has exactly this shape at the op stream --
         * gen_lea_modrm_1() folds the program counter into the displacement
         * and materialises the whole address with one movi -- and answering
         * it "immediate" would state that an address the machine derives
         * from RIP waits on nothing.  It does not reach here: the emitter
         * states the fold (insn_dataflow_note_folded_reg on cpu_eip) and the
         * row arrives with REG_PC in its mask.  A RIP-relative row appearing
         * in g_addr_imm means the note is not reaching the access -- never
         * that the rule needs an exception.
         *
         * Set only where the template HAS an immediate slot; without one
         * there is no bit to point at and the empty mask stands, which is
         * true as far as it goes.  Both halves are counted so the split is a
         * measurement.
         */
        if (f->has_immediate) {
            for (uint8_t k = 0; k < mdl_new; k++) {
                if (ld_mask[k] == 0) {
                    ld_mask[k] = 1ULL << f->n_src_regs;
                    g_addr_imm.fetch_add(1, std::memory_order_relaxed);
                }
            }
            for (uint8_t k = 0; k < mds_new; k++) {
                if (st_mask[k] == 0) {
                    st_mask[k] = 1ULL << f->n_src_regs;
                    g_addr_imm.fetch_add(1, std::memory_order_relaxed);
                }
            }
        } else {
            for (uint8_t k = 0; k < mdl_new; k++) {
                if (ld_mask[k] == 0) {
                    g_addr_empty_no_imm.fetch_add(1,
                                                  std::memory_order_relaxed);
                }
            }
            for (uint8_t k = 0; k < mds_new; k++) {
                if (st_mask[k] == 0) {
                    g_addr_empty_no_imm.fetch_add(1,
                                                  std::memory_order_relaxed);
                }
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
        apply_dst(f, q, mnem, wstate, wwhy, pc_slot);
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
         * immediate bit means.  `movq $5,(%rax)` is the shape on the
         * workload: x86 materialises an immediate operand with movi into a
         * temp of its own, so the walk sees a value with no antecedent and
         * that is the truth about it.
         *
         * `callq` USED TO REACH HERE AND MUST NOT.  Its pushed datum is the
         * return address, and eip_next_tl() folds that to tcg_constant_tl(
         * s->pc) whenever CF_PCREL is off -- the same empty-and-complete
         * shape, arriving at the same test, and answered "immediate" for a
         * value the ISA derives from RIP.  R2, R3/J2.3 and R7.3 all say a
         * QEMU fold is not the machine, so the fix is at QEMU's emitter:
         * insn_dataflow_note_folded_reg() states the instruction pointer as
         * the datum's source and the row arrives here with a non-empty mask.
         * If a direct call is ever seen taking this branch again, the note is
         * not reaching the access, not that the rule needs a call exception.
         *
         * Set only when the template HAS an immediate slot.  Pointing at a
         * slot the template says does not exist would be naming a source
         * rather than reporting one; such a row publishes the empty mask,
         * which is true as far as it goes.
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
        apply_dst(f, q, mnem, wstate, wwhy, pc_slot);
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

    apply_dst(f, q, mnem, wstate, wwhy, pc_slot);
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
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  slots whose complete provenance named no register,"
        " published as\n"
        "              the ENCODING (displacement-only addressing; a"
        " RIP-relative row\n"
        "               here means the folded-register note is not reaching"
        " the access)\n"
        "  %10" G_GUINT64_FORMAT "  the same, on a template with no immediate slot to"
        " point at:\n"
        "               published EMPTY, which is true as far as it goes\n",
        g_addr_imm.load(std::memory_order_relaxed),
        g_addr_empty_no_imm.load(std::memory_order_relaxed));
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
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  destination SLOTS (not rows) whose complete provenance"
        " named nothing,\n"
        "              published as the ENCODING (the immediate bit); a shape"
        " whose value\n"
        "               a note should name -- the zero register, a folded"
        " register --\n"
        "               appearing here means the note is not reaching the"
        " write\n",
        g_dst_imm.load(std::memory_order_relaxed));
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  destination SLOTS whose mask names registers AND"
        " ALSO takes the\n"
        "              immediate bit, because the decoder's"
        " encoded-immediate note reached them\n"
        "  %10" G_GUINT64_FORMAT "  the same shape, ABSTAINING: the note was stated, an"
        " op read the\n"
        "              value, and it did not arrive here -- the"
        " register-only mask is complete\n"
        "               and the encoding belongs to the ADDRESS"
        " (`ldr x0,[x1,#8]`)\n",
        g_dst_imm_feeds.load(std::memory_order_relaxed),
        g_dst_imm_absent.load(std::memory_order_relaxed));
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  destination SLOTS published with the DESTINATION"
        " ITSELF in their mask:\n"
        "              an accumulate, whose result depends on the"
        " destination's prior value\n"
        "               (R7/R3).  An in-place lowering's read-back and a"
        " narrow writeback's\n"
        "               preserve-read are struck out at QEMU's emitters and"
        " are not in here\n",
        g_dst_accum.load(std::memory_order_relaxed));
    g_string_append_printf(report,
        "  %10" G_GUINT64_FORMAT "  destination rows the #236 LIST FLIP would have to"
        " REFUSE:\n"
        "              QEMU wrote a register through a helper whose INDEX the"
        " source does\n"
        "               not state (aarch64 MOPS, env->xregs[mops_destreg(syndrome)]),"
        " so\n"
        "               QEMU's list is SHORT and publishing it would DELETE an"
        " architectural\n"
        "               destination.  COUNTED, NOT REFUSED -- nothing here changes"
        " the wire\n"
        "               today; the row exists so the flip's refusal population is a"
        "\n"
        "               measurement.  R12.1: the refusal is INTERIM -- the index is"
        " in the\n"
        "               instruction's own syndrome, so stating it at the emitter"
        " retires\n"
        "               this row rather than making it permanent\n",
        g_dst_would_refuse_unbounded.load(std::memory_order_relaxed));
    for (unsigned s = 0; s < QDEP_STATE_COUNT; s++) {
        uint64_t v = g_wstate[s].load(std::memory_order_relaxed);
        if (v) {
            g_string_append_printf(report, "  %10" G_GUINT64_FORMAT
                                   "  %s\n", v, state_name(s));
        }
    }
    {
        uint64_t pc_only = g_dst_wire_missing_pc.load(std::memory_order_relaxed);
        uint64_t other = g_dst_wire_missing_other.load(std::memory_order_relaxed);

        g_string_append_printf(report,
            "\n  the wire's destination LIST against QEMU's writes, on the\n"
            "  rows above that PUBLISHED (the direction dst_precheck does not\n"
            "  cover -- `dst_regs[]` is otherwise the operand walk's, and a\n"
            "  mask seated on QEMU's coordinates does not change that):\n"
            "  %10" G_GUINT64_FORMAT "  QEMU wrote REG_PC and the wire's list does not"
            " carry it\n"
            "              (MUST BE 0 since R10 -- the terminator's pc write is"
            " seated as a\n"
            "               destination; a row here means the slot list was"
            " already full)\n"
            "  %10" G_GUINT64_FORMAT "  QEMU wrote some OTHER named register the wire"
            " does not carry\n"
            "              (MUST BE 0 -- a destination the machine writes and"
            " the wire\n"
            "               does not name)\n"
            "  %10" G_GUINT64_FORMAT "  REG_PC destinations SEATED by R10 (the gain"
            " leg, on the wire)\n"
            "  %10" G_GUINT64_FORMAT "  of those, mask = the all-inputs default"
            " because QEMU stated no\n"
            "              provenance (a translator-computed next-PC is not"
            " the encoding)\n",
            pc_only, other,
            g_dst_pc_seated.load(std::memory_order_relaxed),
            g_dst_pc_default.load(std::memory_order_relaxed));
        if (other) {
            dump_tally(report, g_dst_wire_missing,
                       "  by mnemonic and register:");
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
    dump_tally(report, g_field_unnamed,
               "env byte ranges no target declared a register file for\n(#226: the offset IS the identity, so this is a gap in QEMU's statement\nof its own layout -- never a limit of what the machine knows):");
    dump_tally(report, g_field_unmapped_name,
               "env byte ranges QEMU NAMED that have no generic word\n(#226: the name reached this file and the register table has no row for\nit -- a generator pass, not a boundary question):");
    g_mutex_unlock(&g_tally_lock);
}
