/*
 * IR dataflow cross-check (irdf=1).
 *
 * Author: Maccoy Merrell
 *
 * See champsim_tracer_irdf.h for what this is and, more to the point, what
 * it is not: nothing here reaches the wire.
 *
 * The comparison is between two namespaces that do not line up, and the
 * whole difficulty is refusing to paper over that.  QEMU names TCG globals;
 * the tracer names architectural registers.  Where the two agree on a name
 * the mapping is read from the tracer's OWN generated tables, so it cannot
 * drift from the vocabulary the tracer publishes.  Where they do not, the
 * register is counted into a named bucket and reported -- never dropped.  A
 * silently discarded register is a disagreement that scores as agreement,
 * which is the one outcome that would make this instrument worse than
 * having none.
 */
#include <algorithm>
#include <inttypes.h>
#include <string.h>
#include <mutex>
#include <vector>

#include <glib.h>

#include "champsim_tracer.h"
#include "champsim_tracer_irdf.h"
#include "champsim_tracer_mnemonics.h"
#include "champsim_tracer_generic_ids.h"

/* The dataflow header carries no linkage guard of its own -- neither does
 * qemu-plugin.h, which champsim_tracer.h wraps the same way.  Without this
 * the plugin asks the loader for a mangled name and fails to dlopen. */
extern "C" {
#include <qemu-plugin-dataflow.h>
}

namespace {

std::mutex g_lock;

bool g_on = false;

/* Same predicate the decode TU uses; it is file-local there. */
inline bool reg_key_valid(const QemuRegKey *key)
{
    return key && key->name;
}

/* One shot at initialisation; a failure disables the instrument and says so. */
bool        g_tried   = false;
bool        g_live    = false;
unsigned    g_nregs   = 0;
unsigned    g_nwords  = 0;
const char *g_refusal = nullptr;        /* why, if !g_live */

/* TCG global index -> GenericRegId, or REG_ID_COUNT for "no tracer word".
 *
 * The names are QEMU's own static strings (the TCG globals table lives as
 * long as the process), so the pointer is the string -- and std::string is
 * not available here at all: include/qemu/ctype.h shadows the system
 * <ctype.h> on the plugin include path, so every libstdc++ header that
 * pulls <cctype> fails to compile.  That is why no TU in this plugin uses
 * std::string, and why the tallies below are GHashTables. */
std::vector<uint8_t>     g_gen_of_reg;
std::vector<const char *> g_reg_names;

/* Counters.  Every instruction lands in exactly one of the first three. */
uint64_t g_n_declined = 0;   /* extraction incomplete: QEMU refused to answer */
uint64_t g_n_helper   = 0;   /* went through a helper: the walk cannot see in */
uint64_t g_n_fields   = 0;   /* touched CPU state the register namespace omits */
uint64_t g_n_agree    = 0;
uint64_t g_n_disagree = 0;
uint64_t g_n_unmapped = 0;   /* had a register neither side can name in common */

/*
 * The memop arm.
 *
 * The register arm above declines an instruction the moment QEMU's
 * extraction is short of whole -- a helper, a field, an overflow.  The
 * memop question must NOT inherit those refusals: n_mem_reads /
 * n_mem_writes come from qemu_plugin_insn_dataflow_status(), which counts
 * the qemu_ld / qemu_st ops the target emitted and answers even when the
 * register extraction overflowed.  So every translated instruction is
 * scored here, including the ones the register arm had to set aside.
 *
 * What is compared is the tracer's TEMPLATE-STATIC claim (max_dep_loads /
 * max_dep_stores, walked out of the Capstone operand list) against the
 * number of memory ops QEMU's own translation of the same bytes emitted.
 * Neither is the runtime count -- a predicated or self-looping instruction
 * issues fewer or more, and CST_FID_N_LOADS / N_STORES carry that -- so the
 * comparison is of PRESENCE and of the static bound, which is exactly what
 * the dep-mask layout is built from.
 *
 * A helper is the one case where QEMU's zero is not evidence of absence:
 * an access performed inside a helper emits no qemu_ld/qemu_st, so it is
 * counted apart rather than called a tracer overclaim.
 */
uint64_t g_m_agree     = 0;
uint64_t g_m_disagree  = 0;
uint64_t g_m_helper_lo = 0;  /* ir says fewer, and the insn calls a helper */
uint64_t g_m_nostatus  = 0;  /* status refused outright */
/* Truncation census.  STATUS section 5 records 0.011%/0.001% as a FLOOR:
 * these count what this workload actually hit, per instruction and as a
 * distinct-opcode set, so the floor stops being quoted as a bound. */
uint64_t g_t_fields    = 0;
uint64_t g_t_writes    = 0;
uint64_t g_t_prov      = 0;

GHashTable *g_sigs = nullptr;             /* char* -> count, boxed */
GHashTable *g_unmapped_by_name = nullptr;
GHashTable *g_msigs = nullptr;            /* memop disagreement signatures */
GHashTable *g_trunc_by_mnem = nullptr;    /* opcodes that overflowed 8/8 */

void tally(GHashTable **t, const char *key)
{
    if (!*t) {
        *t = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, nullptr);
    }
    gsize n = GPOINTER_TO_SIZE(g_hash_table_lookup(*t, key)) + 1;
    g_hash_table_insert(*t, g_strdup(key), GSIZE_TO_POINTER(n));
}

/*
 * The non-architectural globals, folded where the fold is a fact.
 *
 * x86's flags live in four TCG globals holding a lazy representation --
 * cc_op selects how cc_dst/cc_src/cc_src2 are to be read.  All four ARE the
 * flags register, so all four fold to REG_FLAGS.  That is the only fold
 * asserted here: it is checked by the oracle report, where every flags-
 * bearing instruction touches exactly these names.
 *
 * Everything else with no tracer word -- x86's segment BASES (a base is not
 * the selector the tracer models) and the MPX bound registers -- is left
 * unmapped ON PURPOSE and reported by name, because inventing a mapping for
 * a register the tracer has no concept of would score a fabrication as
 * agreement.  Per-ISA folds get added as each ISA is measured, not guessed.
 */
uint8_t fold_nonarch(const char *name)
{
    if (!strcmp(name, "cc_op") || !strcmp(name, "cc_dst") ||
        !strcmp(name, "cc_src") || !strcmp(name, "cc_src2")) {
        return REG_FLAGS;
    }
    return REG_ID_COUNT;
}

/* Reverse of build_qemu_reg_reverse_index(): a QEMU register name -> id. */
uint8_t generic_for_qemu_name(const char *name)
{
    if (!active_reg_table || active_reg_table_size == 0) {
        return REG_ID_COUNT;
    }
    for (unsigned i = 0; i < active_reg_table_size; i++) {
        const RegClassification *rc = &active_reg_table[i];
        if (rc->n_regs != 0 || !reg_key_valid(&rc->qemu_reg)) {
            continue;
        }
        if (rc->qemu_reg.name && !strcasecmp(rc->qemu_reg.name, name) &&
            rc->reg_id < REG_ID_COUNT) {
            return rc->reg_id;
        }
    }
    return REG_ID_COUNT;
}

void irdf_init_locked(void)
{
    g_tried = true;

    if (!qemu_plugin_dataflow_abi_ok(
            QEMU_PLUGIN_DATAFLOW_VERSION,
            (uint32_t)sizeof(qemu_plugin_dataflow_field),
            (uint32_t)sizeof(qemu_plugin_dataflow_status))) {
        g_refusal = "ABI handshake refused: this plugin and this qemu were "
                    "built against different dataflow versions";
        return;
    }

    g_nregs = qemu_plugin_dataflow_nregs();
    if (g_nregs == 0) {
        g_refusal = "target exposes no TCG globals: nothing to compare";
        return;
    }
    g_nwords = (g_nregs + 63) / 64;

    g_gen_of_reg.assign(g_nregs, (uint8_t)REG_ID_COUNT);
    g_reg_names.assign(g_nregs, nullptr);
    for (unsigned i = 0; i < g_nregs; i++) {
        const char *nm = qemu_plugin_dataflow_reg_name(i, nullptr, nullptr);
        if (!nm) {
            continue;
        }
        g_reg_names[i] = nm;
        uint8_t gen = generic_for_qemu_name(nm);
        if (gen == REG_ID_COUNT) {
            gen = fold_nonarch(nm);
        }
        g_gen_of_reg[i] = gen;
    }
    g_live = true;
}

/* Collect a bitmap into the tracer's vocabulary.  Returns false if the set
 * held a register with no tracer word -- the caller must not score it. */
bool to_generic(const uint64_t *words, std::vector<uint8_t> &out,
                const char **unmapped_name)
{
    bool whole = true;
    out.clear();
    for (unsigned i = 0; i < g_nregs; i++) {
        if (!(words[i / 64] & (1ULL << (i % 64)))) {
            continue;
        }
        uint8_t gen = g_gen_of_reg[i];
        if (gen >= REG_ID_COUNT) {
            if (whole && unmapped_name) {
                *unmapped_name = g_reg_names[i];
            }
            whole = false;
            continue;
        }
        out.push_back(gen);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return whole;
}

void diff_names(const std::vector<uint8_t> &ir,
                const std::vector<uint8_t> &tracer,
                const char *tag, GString *sig)
{
    for (uint8_t g : ir) {
        if (!std::binary_search(tracer.begin(), tracer.end(), g)) {
            g_string_append_printf(sig, " ir-%s-extra:%s", tag,
                                   generic_reg_name_or_unknown(g));
        }
    }
    for (uint8_t g : tracer) {
        if (!std::binary_search(ir.begin(), ir.end(), g)) {
            g_string_append_printf(sig, " ir-%s-missing:%s", tag,
                                   generic_reg_name_or_unknown(g));
        }
    }
}

/*
 * Score one instruction's memop claim against QEMU's translation of it, and
 * record whether the 8/8 dataflow capacity was exceeded.
 *
 * The tracer's static claim is decoded here rather than taken from the
 * caller so that the template path is untouched by the presence of the
 * instrument -- the same reason the register arm re-decodes.
 */
void score_memops(const qemu_plugin_insn_info *info,
                  const qemu_plugin_dataflow_status *st)
{
    InsnFieldsScratch s;
    char sig[192];

    if (st->fields_truncated || st->writes_truncated || st->prov_truncated) {
        g_t_fields += st->fields_truncated ? 1 : 0;
        g_t_writes += st->writes_truncated ? 1 : 0;
        g_t_prov   += st->prov_truncated ? 1 : 0;
        tally(&g_trunc_by_mnem, info->mnemonic);
    }

    insn_fields_scratch_reset(&s);
    decode_detail_to_generic(0, info, &s.f, nullptr);

    unsigned tr_ld = s.f.max_dep_loads, tr_st = s.f.max_dep_stores;
    unsigned ir_ld = st->n_mem_reads,   ir_st = st->n_mem_writes;

    if (tr_ld == ir_ld && tr_st == ir_st) {
        g_m_agree++;
        return;
    }
    /*
     * QEMU emitted fewer memops than the tracer claims AND the instruction
     * calls a helper: the access, if there is one, happens inside the call
     * where no qemu_ld/qemu_st exists to be counted.  Silence there is not
     * evidence, so it is set aside by name instead of scored.
     */
    if (st->n_calls > 0 && ir_ld <= tr_ld && ir_st <= tr_st) {
        g_m_helper_lo++;
        return;
    }
    g_m_disagree++;
    snprintf(sig, sizeof sig, "%s  ir(%u,%u) tracer(%u,%u)%s",
             info->mnemonic, ir_ld, ir_st, tr_ld, tr_st,
             st->n_calls > 0 ? " [helper]" : "");
    tally(&g_msigs, sig);
}

void dump_tally(GString *report, GHashTable *t, const char *heading)
{
    GList *keys;

    if (!t || g_hash_table_size(t) == 0) {
        return;
    }
    g_string_append_printf(report, "\n%s:\n", heading);
    keys = g_list_sort(g_hash_table_get_keys(t), (GCompareFunc)g_strcmp0);
    for (GList *l = keys; l; l = l->next) {
        gpointer v = g_hash_table_lookup(t, l->data);
        g_string_append_printf(report, "  %8" PRIu64 "  %s\n",
                               (uint64_t)GPOINTER_TO_SIZE(v),
                               (const char *)l->data);
    }
    g_list_free(keys);
}

} /* namespace */

void irdf_note_insn(const struct qemu_plugin_tb *tb, size_t idx,
                    const qemu_plugin_insn_info *info)
{
    if (!g_on || !info || !info->mnemonic[0]) {
        return;
    }

    std::lock_guard<std::mutex> lk(g_lock);
    if (!g_tried) {
        irdf_init_locked();
    }
    if (!g_live) {
        return;
    }

    /*
     * Ask what was NOT seen before asking what was.
     *
     * QEMU_PLUGIN_DF_INCOMPLETE covers only the extraction running out of
     * room.  It does NOT cover a helper: an instruction whose work happens
     * inside helper_divq or the SSE helpers yields a set that is complete
     * for the TCG globals it touched and silent about everything the helper
     * did, because that state is not a TCG global at all.  Scoring such an
     * instruction reports "the tracer claims reads the IR does not have",
     * which is true and useless -- the IR never looked.  n_calls is how the
     * status struct says so, and it is the same distinction the offline
     * comparison already had to be taught: a refusal is not a disagreement.
     */
    qemu_plugin_dataflow_status st;
    memset(&st, 0, sizeof(st));
    st.struct_size = sizeof(st);
    if (!qemu_plugin_insn_dataflow_status(tb, idx, &st)) {
        g_n_declined++;
        g_m_nostatus++;
        return;
    }

    /* The memop arm runs BEFORE the register arm's refusals, because none of
     * them applies to it -- see the counter block. */
    score_memops(info, &st);

    if (st.n_calls > 0) {
        g_n_helper++;
        return;
    }

    /*
     * The third refusal, and the one specific to this target.
     *
     * x86's vector file, x87 stack, MXCSR and segment SELECTORS are not TCG
     * globals; QEMU reaches them by load and store at an offset into
     * CPUArchState, and the register bitmap is silent about them by
     * construction.  A `pxor %xmm0,%xmm0` therefore comes back with an empty
     * read set even though the extraction recorded the accesses perfectly
     * well -- as FIELDS, in a namespace this instrument cannot yet spell,
     * because inverting an env offset back to a register number needs the
     * CPUArchState layout, which a plugin does not have and must not
     * hard-code (that assumption is the exact failure the dataflow header
     * was designed around).
     *
     * So: if the instruction touched any field, decline it.  Scoring it
     * would report the tracer's xmm dependencies as things "the IR does not
     * have", when the IR has them and the gap is in the reader.
     */
    qemu_plugin_dataflow_field fields[1];
    fields[0].struct_size = sizeof(fields[0]);
    if (qemu_plugin_insn_fields(tb, idx, fields, 1) > 0) {
        g_n_fields++;
        return;
    }

    std::vector<uint64_t> rd(g_nwords), wr(g_nwords);
    unsigned nr = qemu_plugin_insn_reg_reads(tb, idx, rd.data(), g_nwords);
    unsigned nw = qemu_plugin_insn_reg_writes(tb, idx, wr.data(), g_nwords);

    /*
     * A refusal is not a disagreement.  The accessors hand back nothing at
     * all when the extraction could not represent the instruction -- a
     * helper it cannot see inside, most often -- and counting that as a
     * decoder mismatch is exactly the overstatement this arc already had to
     * correct once, in the offline comparison.
     */
    if (nr == QEMU_PLUGIN_DF_INCOMPLETE || nw == QEMU_PLUGIN_DF_INCOMPLETE ||
        nr > g_nwords || nw > g_nwords) {
        g_n_declined++;
        return;
    }

    std::vector<uint8_t> ir_r, ir_w;
    const char *unmapped = nullptr;
    bool whole = to_generic(rd.data(), ir_r, &unmapped);
    whole &= to_generic(wr.data(), ir_w, &unmapped);
    if (!whole) {
        g_n_unmapped++;
        tally(&g_unmapped_by_name, unmapped ? unmapped : "?");
        return;
    }

    /* The tracer's own answer for the same encoding, decoded here so the
     * template path is untouched by the presence of the instrument. */
    InsnFieldsScratch s;
    insn_fields_scratch_reset(&s);
    decode_detail_to_generic(0, info, &s.f, nullptr);

    std::vector<uint8_t> tr_r(s.f.src_regs, s.f.src_regs + s.f.n_src_regs);
    std::vector<uint8_t> tr_w(s.f.dst_regs, s.f.dst_regs + s.f.n_dst_regs);
    std::sort(tr_r.begin(), tr_r.end());
    std::sort(tr_w.begin(), tr_w.end());
    tr_r.erase(std::unique(tr_r.begin(), tr_r.end()), tr_r.end());
    tr_w.erase(std::unique(tr_w.begin(), tr_w.end()), tr_w.end());

    /*
     * The program counter is dropped from both sides, for the reason
     * isaxcheck drops it: whether QEMU materialises it is a property of
     * where the TB ended, not of the instruction.
     */
    auto drop_ip = [](std::vector<uint8_t> &v) {
        v.erase(std::remove(v.begin(), v.end(), (uint8_t)REG_IP), v.end());
    };
    drop_ip(ir_r); drop_ip(ir_w); drop_ip(tr_r); drop_ip(tr_w);

    GString *sig = g_string_new(info->mnemonic);
    gsize mnem_len = sig->len;
    diff_names(ir_r, tr_r, "rd", sig);
    diff_names(ir_w, tr_w, "wr", sig);
    if (sig->len == mnem_len) {
        g_n_agree++;
    } else {
        g_n_disagree++;
        tally(&g_sigs, sig->str);
    }
    g_string_free(sig, TRUE);
}

void irdf_enable(bool on)
{
    std::lock_guard<std::mutex> lk(g_lock);
    g_on = on;
}

void irdf_report(GString *report)
{
    if (!report || !g_on) {
        return;
    }
    std::lock_guard<std::mutex> lk(g_lock);

    g_string_append_printf(report, "\n=== irdf: QEMU IR dataflow vs the tracer's decode ===\n");
    if (!g_tried) {
        g_string_append_printf(report, "irdf=1 but no instruction was ever translated\n");
        return;
    }
    if (!g_live) {
        g_string_append_printf(report, "DISABLED: %s\n", g_refusal);
        return;
    }

    g_string_append_printf(report, "namespace: %u TCG globals, %u mapped to a tracer register\n",
            g_nregs,
            (unsigned)std::count_if(g_gen_of_reg.begin(), g_gen_of_reg.end(),
                                    [](uint8_t g) { return g < REG_ID_COUNT; }));
    for (unsigned i = 0; i < g_nregs; i++) {
        g_string_append_printf(report, "  %-16s %s\n",
                g_reg_names[i] ? g_reg_names[i] : "(unnamed)",
                g_gen_of_reg[i] < REG_ID_COUNT
                    ? generic_reg_name_or_unknown(g_gen_of_reg[i])
                    : "(no tracer word)");
    }

    g_string_append_printf(report, "\nscored:   %" PRIu64 " agree, %" PRIu64 " disagree\n",
            g_n_agree, g_n_disagree);
    g_string_append_printf(report,
            "declined: %" PRIu64 " helper (work inside a call the walk cannot "
            "see into)\n"
            "          %" PRIu64 " field  (touched CPU state the register "
            "namespace omits -- vector, x87, selectors)\n"
            "          %" PRIu64 " incomplete (extraction ran out of room)\n"
            "          -- NONE of these is a disagreement\n",
            g_n_helper, g_n_fields, g_n_declined);
    g_string_append_printf(report, "unmapped: %" PRIu64 " (touched a global with no tracer word; "
               "reported, never scored)\n", g_n_unmapped);

    dump_tally(report, g_unmapped_by_name,
               "globals the tracer has no word for");
    dump_tally(report, g_sigs, "disagreement signatures");

    g_string_append_printf(report,
            "\n--- memops: QEMU's translation vs the tracer's static claim ---\n"
            "scored:   %" PRIu64 " agree, %" PRIu64 " disagree\n"
            "declined: %" PRIu64 " helper-low (ir has fewer AND the insn calls "
            "a helper: an access inside the call emits no qemu_ld/qemu_st, so "
            "silence is not evidence)\n"
            "          %" PRIu64 " no status\n",
            g_m_agree, g_m_disagree, g_m_helper_lo, g_m_nostatus);
    dump_tally(report, g_msigs, "memop disagreement signatures");

    g_string_append_printf(report,
            "\ntruncation (INSN_DF_MAX_FIELDS=8 / INSN_DF_MAX_WRITES=8): "
            "%" PRIu64 " fields, %" PRIu64 " writes, %" PRIu64 " prov; "
            "%u distinct opcodes\n"
            "  -- this bounds the REGISTER dataflow API only: memop recording "
            "runs off the runtime memory callback and is not gated by it.\n",
            g_t_fields, g_t_writes, g_t_prov,
            g_trunc_by_mnem ? g_hash_table_size(g_trunc_by_mnem) : 0);
    dump_tally(report, g_trunc_by_mnem, "opcodes that overflowed the 8/8 limits");
}
