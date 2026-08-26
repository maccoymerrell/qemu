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
#include <vector>

#include "champsim_tracer_qemu_ident.h"
#include "champsim_tracer.h"

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

/*
 * THE PAIR CENSUS -- CST_QEMU_IDENT_PAIRS=<path>.
 *
 * One row per (QEMU decode identity, Capstone insn id) pair actually seen,
 * with the count.  It exists because the generator that keys the tables on
 * the identity needs to know which classification row each identity
 * carries, and that join has to be id -> id: joining on the disassembly
 * TEXT is unsound (QEMU prints x86 in AT&T syntax, so `cmpq` matches no
 * constant and `movq` matches the wrong one).
 *
 * It is emitted from HERE, and not from a standalone probe, because this
 * is the only place both halves come from the boundary the TABLES are
 * keyed by.  A standalone plugin sees qemu_plugin_insn_detail(), whose
 * Capstone is QEMU's own disassembler setup -- and that is enabled for
 * x86 and arm and NOT for riscv or mips, where it returns insn_id 0 for
 * every instruction.  A probe written that way reports "riscv has no
 * classification" when what happened is that nothing was decoded.
 */
GHashTable         *g_pairs;           /* (id<<32|cap) -> count */
GHashTable         *g_pair_names;      /* id -> interned QEMU name */

GMutex g_lock;

/* Scalars.  Always tallied: one bisect per translated instruction, at
 * translation time, is not a cost worth an option. */
uint64_t g_n_insns;
uint64_t g_n_no_identity;      /* QEMU exported none (id == 0) */
uint64_t g_n_row_missing;      /* id carried, no row -- STALE TABLE */
uint64_t g_n_name_mismatch;    /* row found, name disagrees -- STALE TABLE */
uint64_t g_n_scored;           /* row found and name agreed */
uint64_t g_tier_seen[4];
uint64_t g_op_agree, g_op_disagree;
uint64_t g_br_agree, g_br_disagree;
uint64_t g_op_row_unknown;     /* row says GEN_OP_UNKNOWN: nothing to check */
uint64_t g_br_row_unknown;     /* same row, same reason, branch class */

/*
 * THE LENGTH ARM.  Independent of the identity table -- it runs on all four
 * targets, x86_64 included, because instruction length is a fact QEMU states
 * for every instruction it translates whether or not a decodetree pattern
 * named it.
 *
 * QEMU's answer is the translator's own pc advance (plugin_gen_insn_end:
 * insn->len = db->pc_next - vaddr), i.e. the number of bytes the emulator
 * consumed to produce the code it then ran.  Capstone's answer is cs_insn
 * ->size for the same address.  They are scored against each other over a
 * window WIDER than QEMU's answer wherever the TB supplies one, so Capstone
 * is free to claim a longer instruction and be caught at it; where the
 * window is exactly QEMU's length (the last instruction of a TB, whose
 * successor bytes this pass does not have) Capstone is bounded by the
 * number under test and the sample is tallied apart rather than counted as
 * an agreement it could not have failed.
 */
uint64_t g_len_seen;          /* instructions with both answers available   */
uint64_t g_len_agree;
uint64_t g_len_disagree;
uint64_t g_len_cap_failed;    /* Capstone would not decode the window       */
uint64_t g_len_window_bound;  /* subset of seen: window == QEMU's own answer */
uint64_t g_len_wide_seen;     /* subset of seen: window strictly wider       */
uint64_t g_len_wide_disagree; /* the disagreements that a wide window found  */
GHashTable *g_lensig;

/*
 * THE BRANCH ARM.  Also independent of the identity table, and for a
 * stronger reason than the length arm's: what it scores against the tracer
 * is not a decodetree row's .branch_type column -- e6711c158b measured that
 * column and found it unusable, because one pattern carries architecturally
 * different instructions (disas_a64/ORR_r is both `mov` and `orr`) and one
 * column cannot be right for all of its traffic.
 *
 * This reads the ops the translator EMITTED instead.  A pattern name is a
 * name; goto_tb, goto_ptr, a link constant and a self-edge are the transfer
 * itself, and they do not blur across aliases -- `c.j` and `c.jal` share one
 * decodetree pattern and one Capstone id, and differ in exactly the fact
 * this arm reads, which is whether a link value was published.
 */
uint64_t g_br2_seen;              /* QEMU stated a classification         */
uint64_t g_br2_unavail;           /* no VALID bit -- nothing to score      */
uint64_t g_br2_incomplete;        /* the walk refused                      */
uint64_t g_br2_agree;
uint64_t g_br2_disagree;
uint64_t g_br2_redispatch;        /* DIRECT to fall-through, uncond, no link */
GHashTable *g_br2sig;
GHashTable *g_br2_redisp_sig;

/*
 * THE LINK REGISTER, LEARNED.
 *
 * Not looked up.  Every instruction QEMU says published a return address
 * names where it put it, so the set of link registers is the set of places
 * calls have put one, and the set of stack pointers is the set of registers
 * calls have addressed a return-address store through.  Two sets, filled by
 * observation, and a return is then an indirect transfer whose target came
 * out of one of them.
 *
 * The alternative was a name, and the name does not survive contact: on
 * aarch64 the TCG global is `lr` while the register table -- QEMU's own,
 * in the GDB stub's vocabulary -- calls the same register `x30`, so a
 * name-keyed test silently fails to recognise every aarch64 return.  It DID
 * fail, on 127 of them, before this replaced it.
 */
uint64_t g_link_reg_mask;        /* TCG globals a call has linked INTO      */
uint64_t g_link_addr_mask;       /* TCG globals a call has stored THROUGH   */

void note_link_site(int32_t link_reg, int32_t link_addr_reg)
{
    if (link_reg >= 0 && link_reg < 64) {
        g_link_reg_mask |= 1ull << link_reg;
    }
    if (link_addr_reg >= 0 && link_addr_reg < 64) {
        g_link_addr_mask |= 1ull << link_addr_reg;
    }
}

bool is_link_reg(int32_t r)
{
    return r >= 0 && r < 64 && (g_link_reg_mask & (1ull << r));
}

bool is_stack_reg(int32_t r)
{
    return r >= 0 && r < 64 && (g_link_addr_mask & (1ull << r));
}

/* The generic register a TCG global index names, resolved once. */
std::vector<uint8_t> g_ctrl_reg_gen;
bool g_ctrl_regs_ready;

uint8_t ctrl_reg_generic(int32_t idx)
{
    if (idx < 0) {
        return REG_NONE;
    }
    if (!g_ctrl_regs_ready) {
        unsigned n = qemu_plugin_dataflow_nregs();
        g_ctrl_reg_gen.assign(n, (uint8_t)REG_NONE);
        for (unsigned i = 0; i < n; i++) {
            const char *nm = qemu_plugin_dataflow_reg_name(i, nullptr, nullptr);
            g_ctrl_reg_gen[i] = nm ? generic_for_qemu_name(nm)
                                   : (uint8_t)REG_NONE;
        }
        g_ctrl_regs_ready = true;
    }
    return (unsigned)idx < g_ctrl_reg_gen.size() ? g_ctrl_reg_gen[idx]
                                                 : (uint8_t)REG_NONE;
}

/*
 * The one place a NAME is turned into a CLASS, and it is TCG's vocabulary
 * being combined, not an ISA's being looked up.  See the QEMU_PLUGIN_CTRL_*
 * contract in qemu-plugin.h for why the combination is the consumer's job.
 */
uint8_t ctrl_branch_type(uint32_t f, int32_t tgt_reg, int32_t addr_reg,
                         bool *redispatch, uint64_t pc, uint64_t len,
                         uint64_t target)
{
    *redispatch = false;

    if (!(f & QEMU_PLUGIN_CTRL_TRANSFER)) {
        return BRANCH_NONE;
    }

    bool dir  = (f & QEMU_PLUGIN_CTRL_DIRECT) != 0;
    bool ind  = (f & QEMU_PLUGIN_CTRL_INDIRECT) != 0;
    bool cond = (f & QEMU_PLUGIN_CTRL_CONDITIONAL) != 0;
    bool link = (f & QEMU_PLUGIN_CTRL_LINK) != 0;

    /*
     * A self-edge among the static successors is how QEMU continues a string
     * operation: the instruction re-enters itself until its count runs out.
     * That IS the tracer's BRANCH_REP and it is stated structurally, without
     * a prefix byte being consulted.
     */
    if ((f & QEMU_PLUGIN_CTRL_SELF) && dir && !ind) {
        return BRANCH_REP;
    }

    if (link) {
        return ind ? BRANCH_INDIRECT_CALL : BRANCH_DIRECT_CALL;
    }

    if (ind) {
        /*
         * Learned first, named second.  ctrl_reg_generic() is kept as a
         * second opinion for the case where a return is met before any call
         * has been -- it cannot happen in a program that was entered by one,
         * but a zero that depends on execution order is not a zero.
         */
        if (is_link_reg(tgt_reg)) {
            return BRANCH_RETURN;
        }
        if ((f & QEMU_PLUGIN_CTRL_TGT_LOAD) && is_stack_reg(addr_reg)) {
            return BRANCH_RETURN;
        }
        if (ctrl_reg_generic(tgt_reg) == REG_LR) {
            return BRANCH_RETURN;
        }
        if ((f & QEMU_PLUGIN_CTRL_TGT_LOAD) &&
            ctrl_reg_generic(addr_reg) == REG_SP) {
            return BRANCH_RETURN;
        }
        return BRANCH_INDIRECT_JUMP;
    }

    if (cond) {
        return BRANCH_COND_DIRECT;
    }
    /*
     * An unconditional, unlinked, statically-known successor equal to the
     * NEXT instruction is QEMU re-dispatching rather than the guest
     * branching -- how a translator ends a block after a state change it
     * cannot carry across (a cache maintenance op, an x86 segment reload).
     * `jmp .+len` is architecturally a branch and lands here too, so the
     * class is COUNTED rather than folded into BRANCH_NONE.
     */
    if (target == pc + len) {
        *redispatch = true;
    }
    return BRANCH_DIRECT_JUMP;
}

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
    if (getenv("CST_QEMU_IDENT_PAIRS")) {
        g_pairs = g_hash_table_new(g_direct_hash, g_direct_equal);
        g_pair_names = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                             nullptr, g_free);
    }

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

void qemu_ident_note_ctrl(const struct qemu_plugin_insn *insn,
                          const qemu_plugin_insn_info *info,
                          uint8_t tracer_bt, const char *qname,
                          uint64_t pc, uint8_t len)
{
    uint32_t f = qemu_plugin_insn_ctrl_flags(insn);

    g_mutex_lock(&g_lock);
    if (!(f & QEMU_PLUGIN_CTRL_VALID)) {
        g_br2_unavail++;
        g_mutex_unlock(&g_lock);
        return;
    }
    if (f & QEMU_PLUGIN_CTRL_INCOMPLETE) {
        g_br2_incomplete++;
        g_mutex_unlock(&g_lock);
        return;
    }

    bool redispatch = false;
    uint64_t target = qemu_plugin_insn_ctrl_target(insn);
    if (f & QEMU_PLUGIN_CTRL_LINK) {
        note_link_site(qemu_plugin_insn_ctrl_link_reg(insn),
                       qemu_plugin_insn_ctrl_link_addr_reg(insn));
    }
    uint8_t qbt = ctrl_branch_type(f,
                                   qemu_plugin_insn_ctrl_target_reg(insn),
                                   qemu_plugin_insn_ctrl_addr_reg(insn),
                                   &redispatch, pc, len, target);
    g_br2_seen++;
    if (redispatch) {
        g_br2_redispatch++;
        if (g_detail) {
            char sig[224];
            g_snprintf(sig, sizeof(sig), "%-16s %-26s tracer=%s",
                       info ? info->mnemonic : "-", qname ? qname : "-",
                       branch_type_name_or_unknown(tracer_bt));
            tally(&g_br2_redisp_sig, sig);
        }
        g_mutex_unlock(&g_lock);
        return;
    }
    if (qbt == tracer_bt) {
        g_br2_agree++;
    } else {
        g_br2_disagree++;
        if (g_detail) {
            char sig[256];
            g_snprintf(sig, sizeof(sig),
                       "%-16s qemu=%-18s tracer=%-18s flags=%03x %s",
                       info ? info->mnemonic : "-",
                       branch_type_name_or_unknown(qbt),
                       branch_type_name_or_unknown(tracer_bt),
                       f & 0x1ff, qname ? qname : "-");
            tally(&g_br2sig, sig);
        }
    }
    g_mutex_unlock(&g_lock);
}

void qemu_ident_note_length(uint64_t pc, uint8_t qlen, uint8_t caplen,
                            uint8_t window_len, const char *cap_mnem,
                            const char *qname, const uint8_t *bytes)
{
    g_mutex_lock(&g_lock);
    if (caplen == 0) {
        g_len_cap_failed++;
        if (g_detail) {
            char sig[224];
            char hex[3 * 16 + 1];
            unsigned n = window_len > 16 ? 16 : window_len;
            for (unsigned i = 0; i < n; i++) {
                g_snprintf(hex + 3 * i, 4, "%02x ", bytes[i]);
            }
            hex[3 * n] = 0;
            g_snprintf(sig, sizeof(sig),
                       "CAPSTONE REFUSED  qlen=%u qemu=%-24s [%s]",
                       qlen, qname ? qname : "-", hex);
            tally(&g_lensig, sig);
        }
        g_mutex_unlock(&g_lock);
        return;
    }

    g_len_seen++;
    bool wide = window_len > qlen;
    if (wide) {
        g_len_wide_seen++;
    } else {
        g_len_window_bound++;
    }
    if (caplen == qlen) {
        g_len_agree++;
    } else {
        g_len_disagree++;
        if (wide) {
            g_len_wide_disagree++;
        }
        if (g_detail) {
            char sig[256];
            char hex[3 * 16 + 1];
            unsigned n = window_len > 16 ? 16 : window_len;
            for (unsigned i = 0; i < n; i++) {
                g_snprintf(hex + 3 * i, 4, "%02x ", bytes[i]);
            }
            hex[3 * n] = 0;
            g_snprintf(sig, sizeof(sig),
                       "qemu=%u cap=%u  win=%u  %-14s %-24s [%s]",
                       qlen, caplen, window_len,
                       cap_mnem ? cap_mnem : "-", qname ? qname : "-", hex);
            tally(&g_lensig, sig);
        }
    }
    (void)pc;
    g_mutex_unlock(&g_lock);
}

void qemu_ident_note(const struct qemu_plugin_insn *insn,
                     const qemu_plugin_insn_info *info)
{
    /*
     * The pair census runs with no table: it is how the FIRST table for a
     * target gets generated, and i386 has none until it does.
     */
    if ((!g_have_table && !g_pairs) || !insn) {
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

    /*
     * The pair is tallied HERE, above every table check, because both
     * halves come from the running emulator and neither comes from the
     * table: the QEMU id is what the translator exported and the
     * Capstone id is what the boundary decoded.  A missing or stale row
     * cannot change either one, and gating the census on a row existing
     * would make the census unable to bootstrap the very table it feeds
     * -- which is exactly the state i386 is in before its table is
     * generated for the first time.
     */
    if (g_pairs) {
        uint64_t key = ((uint64_t)id << 32)
                     | (info ? (uint64_t)info->insn_id : 0);
        gpointer k = GSIZE_TO_POINTER(key);
        gpointer v = g_hash_table_lookup(g_pairs, k);
        g_hash_table_insert(g_pairs, k,
                            GSIZE_TO_POINTER(GPOINTER_TO_SIZE(v) + 1));
        if (qname && !g_hash_table_contains(g_pair_names,
                                            GUINT_TO_POINTER(id))) {
            g_hash_table_insert(g_pair_names, GUINT_TO_POINTER(id),
                                g_strdup(qname));
        }
    }

    if (!g_have_table) {
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
    g_tier_seen[row->tier < 4 ? row->tier : 0]++;

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
        if (row->cls.opcode == GEN_OP_UNKNOWN) {
            g_op_row_unknown++;
        } else if (row->cls.opcode == c->opcode) {
            g_op_agree++;
        } else {
            g_op_disagree++;
            if (g_detail) {
                char sig[224];
                g_snprintf(sig, sizeof(sig), "%-34s qemu=%-18s cap=%-18s (%s)",
                           row->name,
                           generic_opcode_name_or_unknown(row->cls.opcode),
                           generic_opcode_name_or_unknown(c->opcode),
                           info->mnemonic);
                tally(&g_opsig, sig);
            }
        }
        /*
         * Same rule for the branch class, and it has to be said in terms
         * of the ROW rather than of BRANCH_NONE: a row that states no
         * classification states no branch class either, and BRANCH_NONE
         * is what "states none" looks like.  Scoring it turned every
         * riscv64 `c.jr`/`c.jalr`/`c.ret` into a branch-class conflict --
         * 442 of them on one small run -- when what had actually
         * happened is that decode_insn16/jalr is a SPLIT row and the
         * rule genuinely does not say which of the three it is.
         */
        if (row->cls.opcode == GEN_OP_UNKNOWN) {
            g_br_row_unknown++;
        } else if (row->cls.branch_type == c->branch_type) {
            g_br_agree++;
        } else {
            g_br_disagree++;
            if (g_detail) {
                char sig[224];
                g_snprintf(sig, sizeof(sig), "%-34s qemu=%-18s cap=%-18s (%s)",
                           row->name,
                           branch_type_name_or_unknown(row->cls.branch_type),
                           branch_type_name_or_unknown(c->branch_type),
                           info->mnemonic);
                tally(&g_brsig, sig);
            }
        }
    }
    g_mutex_unlock(&g_lock);
}

/*
 * Write the pair census.  Refuses to report success on an empty table:
 * a file with a header and no rows is exactly what a run that decoded
 * nothing produces, and the generator reading it would take that for
 * "this ISA has no classification".
 */
static void write_pair_census(GString *report)
{
    const char *path = getenv("CST_QEMU_IDENT_PAIRS");
    if (!g_pairs || !path) {
        return;
    }
    unsigned n = g_hash_table_size(g_pairs);
    if (n == 0) {
        g_string_append_printf(report,
            "\nqemu-ident pair census: NOTHING SCORED, %s not written -- "
            "an empty census would read as 'no classification exists'\n",
            path);
        return;
    }
    FILE *f = fopen(path, "w");
    if (!f) {
        g_string_append_printf(report,
            "\nqemu-ident pair census: could not open %s\n", path);
        return;
    }
    fprintf(f, "#decode_id\tdecode_name\tcap_insn_id\tcount\n");
    GHashTableIter it;
    gpointer k, v;
    g_hash_table_iter_init(&it, g_pairs);
    while (g_hash_table_iter_next(&it, &k, &v)) {
        uint64_t key = GPOINTER_TO_SIZE(k);
        uint32_t id  = (uint32_t)(key >> 32);
        uint32_t cap = (uint32_t)key;
        const char *nm = (const char *)g_hash_table_lookup(
            g_pair_names, GUINT_TO_POINTER(id));
        fprintf(f, "%" PRIu32 "\t%s\t%" PRIu32 "\t%zu\n",
                id, nm ? nm : "-", cap, (size_t)GPOINTER_TO_SIZE(v));
    }
    fclose(f);
    g_string_append_printf(report,
        "\nqemu-ident pair census: %u (identity, capstone-id) pairs -> %s\n",
        n, path);
}

void qemu_ident_report(GString *report)
{
    write_pair_census(report);
    if (g_len_seen || g_len_cap_failed) {
        g_string_append_printf(report,
            "\n--- instruction LENGTH: the translator's pc advance against "
            "the disassembler's ---\n"
            "QEMU's answer is what the emulator consumed to produce the code "
            "it ran (db->pc_next - vaddr).  Capstone's is cs_insn->size over "
            "the same address.  Where the TB supplies bytes past the "
            "instruction, Capstone is given them, so it is free to claim a "
            "LONGER instruction and be caught at it; where it is not, the "
            "sample is counted apart because Capstone was bounded by the "
            "number under test.\n"
            "  scored                                 %10" PRIu64 "\n"
            "    of which given a WIDER window        %10" PRIu64 "\n"
            "    of which bounded by QEMU's answer    %10" PRIu64 "\n"
            "  agree                                  %10" PRIu64 "\n"
            "  DISAGREE                               %10" PRIu64
            "   (wide-window subset %" PRIu64 ")\n"
            "  Capstone refused the window            %10" PRIu64 "\n",
            g_len_seen, g_len_wide_seen, g_len_window_bound,
            g_len_agree, g_len_disagree, g_len_wide_disagree,
            g_len_cap_failed);
        if (g_detail) {
            dump_tally(report, g_lensig, "length disagreements", 40);
        } else {
            g_string_append_printf(report,
                "  (set CST_QEMU_IDENT_AUDIT=1 for the per-encoding "
                "disagreements)\n");
        }
    }

    if (g_br2_seen || g_br2_unavail) {
        g_string_append_printf(report,
            "\n--- BRANCH class: the transfer the translator PERFORMED "
            "against the one the mnemonic table names ---\n"
            "QEMU's answer is read off the ops that carried out the "
            "transfer: goto_tb is a compile-time successor, goto_ptr a "
            "computed one, two distinct goto_tb edges a choice, a constant "
            "equal to (pc + len) published into a register or onto the stack "
            "is a LINK, and a static successor equal to the instruction's own "
            "address is a string operation's self-edge.  None of it is a "
            "pattern NAME, which is what makes it immune to the alias "
            "blurring that made the identity table's .branch_type column "
            "unusable.\n"
            "  scored                                 %10" PRIu64 "\n"
            "  agree                                  %10" PRIu64 "\n"
            "  DISAGREE                               %10" PRIu64 "\n"
            "  re-dispatch (static edge == next insn) %10" PRIu64 "\n"
            "  no classification exported             %10" PRIu64 "\n"
            "  walk refused (INCOMPLETE)              %10" PRIu64 "\n",
            g_br2_seen, g_br2_agree, g_br2_disagree, g_br2_redispatch,
            g_br2_unavail, g_br2_incomplete);
        if (g_detail) {
            dump_tally(report, g_br2sig, "branch-class disagreements", 40);
            dump_tally(report, g_br2_redisp_sig, "re-dispatch signatures", 20);
        } else {
            g_string_append_printf(report,
                "  (set CST_QEMU_IDENT_AUDIT=1 for the per-encoding "
                "disagreements)\n");
        }
    }

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
        "   SPLIT %" PRIu64 "   NAME_MATCHED %" PRIu64
        "   NONE %" PRIu64 "\n"
        "    a NAME_MATCHED row that executes is a row the table "
        "UNDERSTATES; a NONE row that executes is live residue -- an "
        "instruction with no QEMU-side name agreeing about what it is; "
        "a SPLIT row that executes is a rule whose own observations "
        "disagreed, so the identity alone does not classify it.\n",
        g_rows_hit ? g_hash_table_size(g_rows_hit) : 0, g_nrows,
        g_tier_seen[QID_OBSERVED], g_tier_seen[QID_SPLIT],
        g_tier_seen[QID_NAME_MATCHED], g_tier_seen[QID_NONE]);

    g_string_append_printf(report,
        "  opcode     agree %10" PRIu64 "   disagree %10" PRIu64
        "   row unclassified %" PRIu64 "\n"
        "  branchtype agree %10" PRIu64 "   disagree %10" PRIu64
        "   row unclassified %" PRIu64 "\n",
        g_op_agree, g_op_disagree, g_op_row_unknown,
        g_br_agree, g_br_disagree, g_br_row_unknown);

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
