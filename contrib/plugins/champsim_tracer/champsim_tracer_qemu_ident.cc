/*
 * ChampSim Tracer — the reader for QEMU's own decode identity.
 *
 * champsim_tracer_qemu_ident_<isa>.h tabulates every decodetree pattern a
 * target can dispatch on, keyed by the id qemu_plugin_insn_decode_id()
 * reports.  The tables landed at a8169b825b with nothing reading them, and
 * an unread table is an unverified one: it cannot be stale, wrong or dead
 * in any way anybody finds out about.  This is what reads them.
 *
 * WHAT IT IS AND IS NOT.  It is NOT a second source of opcode truth.  J4
 * of the arc's rulings retains Capstone permanently for instruction
 * identification, so the wire's opcode still comes from the mnemonic
 * table and nothing here can move a byte of it.  What the QEMU identity
 * adds is a KEY that Capstone does not control, and that key can be asked
 * three questions Capstone cannot be asked about itself:
 *
 *   1. IS THE TABLE CURRENT?  Every row carries the pattern's name.  QEMU
 *      reports the name too, at runtime, from the decoder that actually
 *      ran.  A row whose name does not match the name reported for its own
 *      id is a table built against different decoders -- the staleness that
 *      a generated file acquires silently.  An id with no row at all is the
 *      same defect, louder.
 *
 *   2. IS THE ROW'S TIER HONEST?  QID_OBSERVED claims a decode through the
 *      rule was seen; QID_NAME_MATCHED claims none was.  Observing a
 *      QID_NAME_MATCHED row executing does not make the row wrong, but it
 *      does make the tier an UNDERSTATEMENT, and the census says by how
 *      much.  A QID_NONE row that executes is live residue: an instruction
 *      the tracer classifies from Capstone alone with no QEMU-side name
 *      agreeing about what it is.
 *
 *   3. WHERE DO THE TWO DECODERS DISAGREE ABOUT WHAT THIS IS?  The row and
 *      the Capstone insn_id each carry a GenericOpcode and a BranchType.
 *      Both are static classifications of the same bytes by different
 *      decoders, so a disagreement is a real finding on one side or the
 *      other, and the signature tally names which instruction produced it
 *      rather than reporting a count nobody can chase.
 *
 * GRANULARITY IS MEASURED, NOT ASSUMED.  A QEMU pattern and a Capstone
 * insn_id are not the same partition of the encoding space and neither is
 * finer everywhere: `disas_a64/SUBS_r` carries subs and cmp and negs,
 * while one Capstone AARCH64_INS_B spreads across the patterns QEMU
 * separates.  Both directions are counted so the coarser side of any
 * disagreement is visible instead of inferred.
 *
 * x86_64 HAS NO TABLE AND THAT IS REPORTED AS SUCH.  The i386 leg derives
 * its id from the source line of an X86_OP_ENTRY expansion; there is no
 * generated pattern universe to tabulate.  mipsel HAS a table whose rows
 * are all vendor extensions, because the MIPS32/64 base ISA is decoded by
 * a hand-written switch -- so the expected reading there is that almost
 * nothing carries an identity at all, and the reader states that instead
 * of burying it in a percentage.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Author: Maccoy Merrell
 */

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "champsim_tracer_qemu_ident.h"

/* The per-ISA classification tables, for the Capstone half of each row. */
extern const InsnClassification *const isa_insn_class[];
extern const unsigned isa_insn_class_size[];

namespace {

const QemuIdentRow *g_rows;
unsigned            g_nrows;
const InsnClassification *g_cap;
unsigned            g_cap_size;
bool                g_have_table;      /* this ISA tabulates identities */
bool                g_detail;          /* CST_QEMU_IDENT_AUDIT */

GMutex g_lock;

/* Scalars.  Always tallied: one bisect per translated instruction, at
 * translation time, is not a cost worth an option. */
uint64_t g_n_insns;
uint64_t g_n_no_identity;      /* QEMU exported none (id == 0) */
uint64_t g_n_row_missing;      /* id carried, no row -- STALE TABLE */
uint64_t g_n_name_mismatch;    /* row found, name disagrees -- STALE TABLE */
uint64_t g_n_scored;           /* row found and name agreed */
uint64_t g_tier_seen[3];
uint64_t g_op_agree, g_op_disagree;
uint64_t g_br_agree, g_br_disagree;
uint64_t g_op_row_unknown;     /* row says GEN_OP_UNKNOWN: nothing to check */

/* Which rows were reached at all -- the table's live coverage. */
GHashTable *g_rows_hit;        /* id -> (gpointer)1 */

/* Granularity, both directions, and the disagreement signatures.  Detail
 * only: these are per-signature hash tables and the counts above are what
 * a shipped run needs. */
GHashTable *g_id_to_caps;      /* qemu id   -> GHashTable of capstone ids */
GHashTable *g_cap_to_ids;      /* cap id    -> GHashTable of qemu ids */
GHashTable *g_opsig;           /* signature -> count */
GHashTable *g_brsig;
GHashTable *g_stalesig;

void tally(GHashTable **t, const char *key)
{
    if (!*t) {
        *t = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, nullptr);
    }
    gpointer v = g_hash_table_lookup(*t, key);
    g_hash_table_insert(*t, g_strdup(key),
                        GUINT_TO_POINTER(GPOINTER_TO_UINT(v) + 1));
}

void note_pair(GHashTable **outer, uint32_t okey, uint32_t inner)
{
    if (!*outer) {
        *outer = g_hash_table_new_full(g_direct_hash, g_direct_equal, nullptr,
                                       (GDestroyNotify)g_hash_table_destroy);
    }
    GHashTable *set = (GHashTable *)g_hash_table_lookup(
        *outer, GUINT_TO_POINTER(okey));
    if (!set) {
        set = g_hash_table_new(g_direct_hash, g_direct_equal);
        g_hash_table_insert(*outer, GUINT_TO_POINTER(okey), set);
    }
    g_hash_table_add(set, GUINT_TO_POINTER(inner));
}

/* Rows are sorted by id; the header says so and qemu_ident_install()
 * proves it before this is ever called. */
const QemuIdentRow *row_find(uint32_t id)
{
    unsigned lo = 0, hi = g_nrows;
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2;
        if (g_rows[mid].id < id) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return (lo < g_nrows && g_rows[lo].id == id) ? &g_rows[lo] : nullptr;
}

/* distinct-inner-set histogram: how many outer keys map to 1, 2, 3+ */
void fanout(GString *report, GHashTable *t, const char *what)
{
    if (!t) {
        g_string_append_printf(report, "  %s: not measured\n", what);
        return;
    }
    uint64_t one = 0, two = 0, more = 0, worst = 0;
    uint32_t worst_key = 0;
    GHashTableIter it;
    gpointer k, v;
    g_hash_table_iter_init(&it, t);
    while (g_hash_table_iter_next(&it, &k, &v)) {
        guint n = g_hash_table_size((GHashTable *)v);
        if (n == 1)      one++;
        else if (n == 2) two++;
        else             more++;
        if (n > worst) { worst = n; worst_key = GPOINTER_TO_UINT(k); }
    }
    g_string_append_printf(report,
            "  %-46s 1:1 %6" PRIu64 "   1:2 %6" PRIu64 "   1:3+ %6" PRIu64
            "   widest %" PRIu64 " (key 0x%08x)\n",
            what, one, two, more, worst, worst_key);
}

void dump_tally(GString *report, GHashTable *t, const char *title,
                unsigned max_lines)
{
    if (!t || g_hash_table_size(t) == 0) {
        return;
    }
    g_string_append_printf(report, "  %s (%u distinct):\n", title,
                           g_hash_table_size(t));
    GList *keys = g_hash_table_get_keys(t);
    keys = g_list_sort(keys, (GCompareFunc)g_strcmp0);
    unsigned n = 0;
    for (GList *l = keys; l && n < max_lines; l = l->next, n++) {
        g_string_append_printf(report, "    %8u  %s\n",
                GPOINTER_TO_UINT(g_hash_table_lookup(t, l->data)),
                (const char *)l->data);
    }
    if (g_hash_table_size(t) > max_lines) {
        g_string_append_printf(report, "    ... %u more\n",
                               g_hash_table_size(t) - max_lines);
    }
    g_list_free(keys);
}

} /* namespace */

unsigned qemu_ident_install(TraceISA isa)
{
    g_mutex_init(&g_lock);
    g_detail = getenv("CST_QEMU_IDENT_AUDIT") != nullptr;

    if (isa > TRACE_ISA_MIPS) {
        return 0;
    }
    g_rows     = isa_qemu_ident[isa];
    g_nrows    = isa_qemu_ident_count[isa];
    g_cap      = isa_insn_class[isa];
    g_cap_size = isa_insn_class_size[isa];
    g_have_table = (g_rows != nullptr && g_nrows > 0);
    if (!g_have_table) {
        return 0;
    }

    /*
     * The two properties the header states and a consumer relies on.  A
     * bisect over an unsorted table silently MISSES rows -- it reports
     * "no identity for this id" for a row sitting in the file -- so this
     * is checked once rather than trusted.
     */
    unsigned bad = 0;
    for (unsigned i = 1; i < g_nrows; i++) {
        if (g_rows[i].id < g_rows[i - 1].id) {
            if (bad == 0) {
                fprintf(stderr, "champsim_tracer: qemu-ident table for isa %u "
                        "is NOT sorted by id (row %u: 0x%08x after 0x%08x); "
                        "the bisect this table promises cannot find rows\n",
                        (unsigned)isa, i, g_rows[i].id, g_rows[i - 1].id);
            }
            bad++;
        } else if (g_rows[i].id == g_rows[i - 1].id) {
            fprintf(stderr, "champsim_tracer: qemu-ident table for isa %u has "
                    "duplicate id 0x%08x (%s / %s)\n", (unsigned)isa,
                    g_rows[i].id, g_rows[i - 1].name, g_rows[i].name);
            bad++;
        }
    }
    g_rows_hit = g_hash_table_new(g_direct_hash, g_direct_equal);
    return bad;
}

void qemu_ident_note(const struct qemu_plugin_insn *insn,
                     const qemu_plugin_insn_info *info)
{
    if (!g_have_table || !insn) {
        return;
    }

    uint32_t id = qemu_plugin_insn_decode_id(insn);
    const char *qname = qemu_plugin_insn_decode_name(insn);

    g_mutex_lock(&g_lock);
    g_n_insns++;

    /*
     * 0 is the contract's "this target recorded no identity for this
     * instruction".  On mipsel that is the expected reading for nearly
     * everything and it is not a defect of the table -- the MIPS base ISA
     * is not decoded by decodetree at all.
     */
    if (id == 0) {
        g_n_no_identity++;
        g_mutex_unlock(&g_lock);
        return;
    }

    const QemuIdentRow *row = row_find(id);
    if (!row) {
        g_n_row_missing++;
        if (g_detail) {
            char sig[160];
            g_snprintf(sig, sizeof(sig), "id=0x%08x name=%s cap=%s",
                       id, qname ? qname : "-", info ? info->mnemonic : "-");
            tally(&g_stalesig, sig);
        }
        g_mutex_unlock(&g_lock);
        return;
    }
    if (qname && row->name && strcmp(qname, row->name) != 0) {
        g_n_name_mismatch++;
        if (g_detail) {
            char sig[224];
            g_snprintf(sig, sizeof(sig), "id=0x%08x qemu=%s table=%s",
                       id, qname, row->name);
            tally(&g_stalesig, sig);
        }
        g_mutex_unlock(&g_lock);
        return;
    }

    g_n_scored++;
    g_hash_table_add(g_rows_hit, GUINT_TO_POINTER(id));
    g_tier_seen[row->tier < 3 ? row->tier : 0]++;

    /* The Capstone half of the same instruction, taken from the same table
     * the wire's opcode comes from. */
    const InsnClassification *c = nullptr;
    if (info && g_cap && info->insn_id < g_cap_size) {
        c = &g_cap[info->insn_id];
    }
    if (c) {
        if (g_detail) {
            note_pair(&g_id_to_caps, id, info->insn_id);
            note_pair(&g_cap_to_ids, info->insn_id, id);
        }
        /*
         * A QID_NONE row carries GEN_OP_UNKNOWN because nothing named it,
         * not because it disagrees.  Scoring that as a disagreement would
         * report the table's own residue as a decoder conflict, which is
         * the enumerated-zero shape in reverse: a number that is large for
         * a reason having nothing to do with what it claims to measure.
         */
        if (row->opcode == GEN_OP_UNKNOWN) {
            g_op_row_unknown++;
        } else if (row->opcode == c->opcode) {
            g_op_agree++;
        } else {
            g_op_disagree++;
            if (g_detail) {
                char sig[224];
                g_snprintf(sig, sizeof(sig), "%-34s qemu=%-18s cap=%-18s (%s)",
                           row->name,
                           generic_opcode_name_or_unknown(row->opcode),
                           generic_opcode_name_or_unknown(c->opcode),
                           info->mnemonic);
                tally(&g_opsig, sig);
            }
        }
        if (row->branch_type == c->branch_type) {
            g_br_agree++;
        } else {
            g_br_disagree++;
            if (g_detail) {
                char sig[224];
                g_snprintf(sig, sizeof(sig), "%-34s qemu=%-18s cap=%-18s (%s)",
                           row->name,
                           branch_type_name_or_unknown(row->branch_type),
                           branch_type_name_or_unknown(c->branch_type),
                           info->mnemonic);
                tally(&g_brsig, sig);
            }
        }
    }
    g_mutex_unlock(&g_lock);
}

void qemu_ident_report(GString *report)
{
    if (!g_have_table) {
        g_string_append_printf(report,
            "\n--- QEMU decode identity: no table for this target ---\n"
            "  The i386 leg derives its id from the source line of an "
            "X86_OP_ENTRY expansion, which is not a decodetree pattern and "
            "has no generated universe to tabulate.  Reported rather than "
            "counted as 100%% unidentified.\n");
        return;
    }
    if (g_n_insns == 0) {
        g_string_append_printf(report,
            "\n--- QEMU decode identity: the reader saw NO instruction ---\n"
            "  A table with a reader that is never reached is the state this "
            "reader exists to end, so this line is a FAILURE, not a zero.\n");
        return;
    }

    g_string_append_printf(report,
        "\n--- QEMU decode identity: the rule the translator dispatched on "
        "---\n"
        "The table is champsim_tracer_qemu_ident_<isa>.h, one row per "
        "decodetree pattern, keyed by qemu_plugin_insn_decode_id().  It is "
        "NOT a second source of opcode truth -- the wire's opcode still "
        "comes from Capstone (ruling J4) and nothing here can move it.  What "
        "it gives is a key Capstone does not control.\n"
        "  translated instructions read           %10" PRIu64 "\n"
        "  no identity exported (id == 0)         %10" PRIu64 "  %5.1f%%\n"
        "  id carried, NO ROW IN TABLE            %10" PRIu64 "  <- stale table\n"
        "  row found, NAME DISAGREES              %10" PRIu64 "  <- stale table\n"
        "  scored against the Capstone row        %10" PRIu64 "\n",
        g_n_insns, g_n_no_identity,
        100.0 * (double)g_n_no_identity / (double)g_n_insns,
        g_n_row_missing, g_n_name_mismatch, g_n_scored);

    g_string_append_printf(report,
        "  table rows reached                     %10u of %u\n"
        "  tier of the rows that executed:  OBSERVED %" PRIu64
        "   NAME_MATCHED %" PRIu64 "   NONE %" PRIu64 "\n"
        "    a NAME_MATCHED row that executes is a row the table "
        "UNDERSTATES; a NONE row that executes is live residue -- an "
        "instruction with no QEMU-side name agreeing about what it is.\n",
        g_rows_hit ? g_hash_table_size(g_rows_hit) : 0, g_nrows,
        g_tier_seen[QID_OBSERVED], g_tier_seen[QID_NAME_MATCHED],
        g_tier_seen[QID_NONE]);

    g_string_append_printf(report,
        "  opcode     agree %10" PRIu64 "   disagree %10" PRIu64
        "   row unclassified %" PRIu64 "\n"
        "  branchtype agree %10" PRIu64 "   disagree %10" PRIu64 "\n",
        g_op_agree, g_op_disagree, g_op_row_unknown,
        g_br_agree, g_br_disagree);

    if (!g_detail) {
        g_string_append_printf(report,
            "  (set CST_QEMU_IDENT_AUDIT=1 for the per-signature "
            "disagreements and the two-way granularity census)\n");
        return;
    }

    g_string_append_printf(report,
        "  granularity -- the two decoders do NOT partition the encoding "
        "space the same way, and neither is finer everywhere:\n");
    fanout(report, g_id_to_caps, "distinct Capstone ids per QEMU pattern");
    fanout(report, g_cap_to_ids, "distinct QEMU patterns per Capstone id");

    dump_tally(report, g_stalesig,  "staleness signatures", 16);
    dump_tally(report, g_opsig,     "opcode disagreements", 24);
    dump_tally(report, g_brsig,     "branch-type disagreements", 24);
}
