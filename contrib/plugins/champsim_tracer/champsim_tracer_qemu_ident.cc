/*
 * ChampSim Tracer — the reader for QEMU's own decode identity.
 *
 * champsim_tracer_qemu_ident_<isa>.h tabulates every decodetree pattern a
 * target can dispatch on, keyed by the id qemu_plugin_insn_decode_id()
 * reports.  The tables landed at a8169b825b with nothing reading them, and
 * an unread table is an unverified one: it cannot be stale, wrong or dead
 * in any way anybody finds out about.  This is what reads them.
 *
 * WHAT IT IS AND IS NOT.  This header used to say that J4 retains
 * Capstone permanently for instruction identification, so nothing here
 * could move a byte of the wire.  J4 IS RETIRED -- J6 (2026-08-25) takes
 * Capstone off every correctness path including identification, and makes
 * this identity the intended SOURCE of the opcode taxonomy rather than a
 * key beside it.
 *
 * THE FLIP HAS HAPPENED.  The classifier in champsim_tracer_decode.cc
 * takes the wire's opcode, branch class, refiner selection and lane shape
 * from THIS key: qemu_ident_classify() answers for every rule whose row
 * carries a classification (tiers QID_OBSERVED and QID_ADJUDICATED), and
 * the Capstone-keyed table is what a row that carries none falls back to.
 * The rows that fall back are counted per reason and named below as
 * survivors, not left as a silent default.
 *
 * The flip moved no byte of the wire on the census workloads, and that is
 * the result rather than a disappointment: on every deciding row the two
 * accounts already agreed -- 0 opcode and 0 branch-class disagreements
 * against the WIRE on four ISAs -- so what changed is WHERE the answer
 * comes from, which is the whole of what J6 asks.  What the flip does buy
 * is that corrupting Capstone's identity can no longer move those rows,
 * and the mutation control measures exactly that.
 *
 * Beside that, the identity is a KEY that Capstone does not control, and
 * that key can be asked three questions Capstone cannot be asked about
 * itself:
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
 * ALL FOUR ISAs TABULATE, and the two that once did not are the reason
 * this paragraph is worth reading.  x86_64 was described here as having
 * no table, because the i386 leg derives its id from the source line of
 * an X86_OP_ENTRY expansion rather than a decodetree pattern; that was a
 * statement about where the generator looked, and the universe is the
 * decode table itself (cb05983200).  mipsel was described as carrying
 * almost no identity at all, because its base ISA is a hand-written
 * switch rather than decodetree; that switch is now instrumented
 * (7e2e1baf07).  Measured at cb05983200 on a four-ISA workload, the
 * share of translated instructions exporting NO identity is 0.0% on all
 * four -- 2, 2, 0 and 0 instructions on x86_64, aarch64, riscv64 and
 * mipsel.  The percentage is still printed rather than asserted, because
 * a generated table can go stale between one build and the next.
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
/*
 * ONE SLOT PER TIER, and the bound is written from the enum rather than
 * from a number.  It used to be [4] with a `tier < 4 ? tier : 0` clamp,
 * and QID_ADJUDICATED is 4: every adjudicated row was therefore tallied
 * into slot 0, QID_NONE, and the census reported the tracer's most
 * resolved rows as its residue.  Measured on x86_64 at the flip: 349 of
 * 13,824 translated instructions, all four reached MOVDQ/NOP
 * adjudications, printed as "NONE 349" -- exactly backwards.  A clamp
 * that silently folds an unknown tier into a real one is the defect; the
 * array is now sized by the enum and an out-of-range tier is counted
 * apart and reported, never folded.
 */
uint64_t g_tier_seen[QID_ADJUDICATED + 1];
uint64_t g_tier_out_of_range;
/*
 * TWO Capstone-side accounts of the same instruction, and the difference
 * between them is the whole point of scoring both:
 *
 *   _tbl  the mnemonic TABLE row `info->insn_id` indexes.  That row is the
 *         INPUT to decode_detail_to_generic()'s per-instance refiners, so
 *         on every family a refiner touches it is not what any trace says.
 *   _wire what decode_detail_to_generic() ANSWERED for this instruction --
 *         the value the tracer publishes.  This is the account a claim
 *         about a wire defect has to be made against.
 *
 * The `_tbl` pair was the only one scored until the four-ISA audit was
 * asked to adjudicate a refiner-touched family and could not.
 */
uint64_t g_op_agree, g_op_disagree;          /* wire */
uint64_t g_br_agree, g_br_disagree;          /* wire */
uint64_t g_op_agree_tbl, g_op_disagree_tbl;  /* pre-refinement table row */
uint64_t g_br_agree_tbl, g_br_disagree_tbl;
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
/*
 * THE SPLIT DELAY SLOT, and it is the delay-slot sibling of a page-straddling
 * block rather than a new idea.  A MIPS branch's transfer is emitted while
 * its delay slot is translated; when the block ENDS between the two, the
 * translator's statement of ownership cannot be completed inside one block.
 *
 *   pending  the branch is in this block and the ops that perform its
 *            transfer are not.  QEMU says it IS a transfer and cannot say
 *            what kind, so the row is COUNTED AND NOT SCORED -- the same
 *            treatment INCOMPLETE gets, and for the same reason: a refusal
 *            is not a wrong answer and must not be charged as one.
 *   foreign  ops emitted during this instruction performed the transfer of a
 *            branch in the PREVIOUS block.  This instruction is classified
 *            normally and IS scored; the count exists so the exclusion is
 *            visible rather than looking like an absence.
 */
uint64_t g_br2_pending;
/*
 * QEMU ended the block WITHOUT stating a successor: exit_tb and nothing
 * else.  It is a REFUSAL, not an answer, and gets the treatment INCOMPLETE
 * and PENDING get -- counted, not scored -- for the reason this file
 * already commits to: a refusal is not a wrong answer and must not be
 * charged as one.
 *
 * The regime that produces it in bulk is CF_NO_GOTO_TB (`-one-insn-per-tb`,
 * `-d nochain`), where translator_use_goto_tb() declines unconditionally and
 * the x86 translator lowers every branch to a bare exit_tb.  MEASURED on the
 * mixed-C workload: 0 on all four ISAs in the shipped regime, 2,308 on
 * x86_64 under `-one-insn-per-tb`, where they were being reported as
 * disagreements about instructions QEMU had said nothing about.
 *
 * It is tested AFTER the identity adjudications, because x86 `syscall` also
 * carries NOCHAIN and the syscall rule has a real answer for it.
 */
uint64_t g_br2_nochain;
uint64_t g_br2_foreign;
GHashTable *g_br2sig;
GHashTable *g_br2_redisp_sig;

/*
 * THE TWO IDENTITY-KEYED ADJUDICATIONS.
 *
 * The ops say what the translator DID; the decode identity says which rule
 * it dispatched on.  Two classes of instruction need both, because the
 * transfer the ops carried out is not the transfer the ISA encodes -- and
 * under R1 ("every instruction has EXACTLY ONE set ... determined by the
 * instruction itself.  There are NO special cases where the CONTEXT of an
 * instruction changes that set") and R2 ("we record ARCHITECTURAL (ISA)
 * dependencies.  Not microarchitectural ones") the ISA is what the wire
 * publishes.
 *
 * Both are keyed by qemu_plugin_insn_decode_id() -- QEMU's own decode
 * identity, per J6 -- and NEITHER consults a Capstone id or a mnemonic
 * string.  The tracer's own answer is not an input either: the adjudicated
 * class is computed from the ops and the identity alone, so it is the same
 * value a wire flip would publish, and the audit then scores it.
 *
 *   ctrl_syscall_ident   the ops carried out NO transfer because the
 *                        instruction RAISES -- the helper does the
 *                        transfer, not the translator -- and the identity
 *                        row states BRANCH_SYSCALL_TYPE.  x86 `syscall`,
 *                        aarch64 `svc`, riscv `ecall`, mips `syscall`.
 *                        That QEMU's ops show no transfer is CONTEXT, which
 *                        R1 excludes.
 *
 *   ctrl_folded_cond     the identity row states a CONDITIONAL branch and
 *                        the ops carried out ONE unconditional static edge,
 *                        because the condition was decidable at translation
 *                        time and QEMU folded it.  mipsel `b label` IS
 *                        `beq $zero,$zero,label`.  R3: an idiom is not a
 *                        different instruction, and "the redundancy of that
 *                        dependency is a microarchitectural optimization for
 *                        a DOWNSTREAM SIMULATOR to model.  The tracer never
 *                        resolves or elides it."  J2.3: "you are describing
 *                        a QEMU optimization behavior, not reality."
 *
 * NOT a general licence to prefer the table.  The identity table's
 * .branch_type column IS blurred by aliasing where one rule carries
 * architecturally different instructions, which is why the branch arm reads
 * the ops in the first place.  Each arm below fires only on a shape the ops
 * cannot express at all -- no transfer, or one edge where the rule has two
 * -- so a blurred row cannot move a row the ops already answered.
 */
/*
 *   ctrl_redispatch_ident  the ops carried out ONE unconditional static
 *                        edge to the instruction's own architectural
 *                        continuation.  That shape is QEMU re-dispatching
 *                        after a state change it cannot carry across AND
 *                        an architectural `b .+4` AND a string
 *                        operation's re-entry, and the ops cannot tell
 *                        them apart -- MEASURED on the mixed-C workload,
 *                        the same shape on the same run carried
 *                        `aarch64 b` (a real branch to the next
 *                        instruction, 16), `cpyfp`/`setp` (12),
 *                        `str/sub/leaq/rdtsc/movl/nopl` (7).  The
 *                        identity CAN tell them apart, because it names
 *                        the rule the translator dispatched on, so the
 *                        row answers where the ops decline.
 *
 *                        It fires only when the row carries a
 *                        classification at all: a QID_SPLIT or QID_NONE
 *                        row's BRANCH_NONE is the absence of an answer
 *                        and publishing it would be manufacturing one.
 *                        Those stay the NAMED REFUSAL they were.
 */
uint64_t g_ctrl_syscall_ident;
uint64_t g_ctrl_folded_cond;
uint64_t g_ctrl_redispatch_ident;
GHashTable *g_ctrl_syscall_sig;
GHashTable *g_ctrl_folded_sig;
GHashTable *g_ctrl_redisp_ident_sig;

/*
 * THE REFUSALS, NAMED.
 *
 * Five ways this arm ends without an answer, and every one of them is
 * counted under its own name with its own signature table.  A refusal
 * that is only a number is a category a reader has to guess the contents
 * of, and the wire flip these rows are staged for inherits whatever the
 * audit could say about them -- so it has to be able to say what they
 * ARE, not just how many.
 */
GHashTable *g_br2_unavail_sig;
GHashTable *g_br2_incomplete_sig;
GHashTable *g_br2_pending_sig;
GHashTable *g_br2_nochain_sig;

/* The identity row for an id, or nullptr.  Rows are sorted and the sort is
 * PROVEN at install, so the bisect cannot silently miss one. */
const QemuIdentRow *ident_row(uint32_t id)
{
    if (id == 0 || !g_have_table) {
        return nullptr;
    }
    unsigned lo = 0, hi = g_nrows;
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2;
        if (g_rows[mid].id < id) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo >= g_nrows || g_rows[lo].id != id) {
        return nullptr;
    }
    return &g_rows[lo];
}

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
GHashTable *g_opsig;           /* signature -> count (wire) */
GHashTable *g_brsig;
GHashTable *g_opsig_tbl;       /* same, scored against the table row */
GHashTable *g_brsig_tbl;
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

/*
 * One refusal, recorded under its own name.  The signature carries the
 * disassembly text and the QEMU rule so a reader can see WHAT was refused
 * without re-running anything; the tracer's own class rides along because
 * the refusal is exactly the row a wire flip would have to publish
 * something for, and the value it publishes today is that one.
 */
void note_refusal(GHashTable **t, const qemu_plugin_insn_info *info,
                  const char *qname, uint8_t tracer_bt, uint32_t f)
{
    if (!g_detail) {
        return;
    }
    char sig[256];
    g_snprintf(sig, sizeof(sig), "%-16s %-26s tracer=%-18s flags=%03x",
               info ? info->mnemonic : "-", qname ? qname : "-",
               branch_type_name_or_unknown(tracer_bt), f & 0x7ff);
    tally(t, sig);
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
        note_refusal(&g_br2_unavail_sig, info, qname, tracer_bt, f);
        g_mutex_unlock(&g_lock);
        return;
    }
    if (f & QEMU_PLUGIN_CTRL_INCOMPLETE) {
        g_br2_incomplete++;
        note_refusal(&g_br2_incomplete_sig, info, qname, tracer_bt, f);
        g_mutex_unlock(&g_lock);
        return;
    }
    if (f & QEMU_PLUGIN_CTRL_FOREIGN) {
        g_br2_foreign++;
    }
    if (f & QEMU_PLUGIN_CTRL_PENDING) {
        g_br2_pending++;
        note_refusal(&g_br2_pending_sig, info, qname, tracer_bt, f);
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

    /*
     * The two identity-keyed adjudications, applied to QEMU's own answer
     * before anything is scored.  See the block comment at
     * g_ctrl_syscall_ident.
     */
    const QemuIdentRow *row = ident_row(info ? info->decode_id : 0u);
    bool ident_adjudicated = false;
    {
        if (row && qbt == BRANCH_NONE &&
            row->cls.branch_type == BRANCH_SYSCALL_TYPE) {
            qbt = BRANCH_SYSCALL_TYPE;
            g_ctrl_syscall_ident++;
            ident_adjudicated = true;
            if (g_detail) {
                char sig[224];
                g_snprintf(sig, sizeof(sig), "%-16s %-26s -> %s",
                           info ? info->mnemonic : "-", row->name,
                           branch_type_name_or_unknown(qbt));
                tally(&g_ctrl_syscall_sig, sig);
            }
        } else if (row && qbt == BRANCH_DIRECT_JUMP &&
                   !(f & QEMU_PLUGIN_CTRL_CONDITIONAL) &&
                   row->cls.branch_type == BRANCH_COND_DIRECT) {
            qbt = BRANCH_COND_DIRECT;
            g_ctrl_folded_cond++;
            ident_adjudicated = true;
            if (g_detail) {
                char sig[224];
                g_snprintf(sig, sizeof(sig), "%-16s %-26s -> %s",
                           info ? info->mnemonic : "-", row->name,
                           branch_type_name_or_unknown(qbt));
                tally(&g_ctrl_folded_sig, sig);
            }
        }
        if (qbt == BRANCH_NONE && (f & QEMU_PLUGIN_CTRL_NOCHAIN)) {
            g_br2_nochain++;
            note_refusal(&g_br2_nochain_sig, info, qname, tracer_bt, f);
            g_mutex_unlock(&g_lock);
            return;
        }
    }
    g_br2_seen++;
    /*
     * THE THIRD IDENTITY-KEYED ADJUDICATION.  Same composition as the two
     * above -- computed from the ops and qemu_plugin_insn_decode_id()
     * alone, never a Capstone id and never a mnemonic string (J6) -- and
     * fired on the one shape the ops cannot express: an unconditional
     * static edge to the architectural continuation, which is three
     * unrelated instructions wearing one face.
     *
     * ident_adjudicated guards against double-counting a row an earlier
     * arm already answered; the row's own classification is what is
     * published, so a rule with no classification refuses instead.
     */
    if (redispatch) {
        if (ident_adjudicated) {
            /* An earlier arm read the identity for this row already; the
             * re-dispatch face is not what this instruction is, and the
             * answer it produced stands.  Scored below. */
        } else if (row && row->cls.opcode != GEN_OP_UNKNOWN) {
            /*
             * WHAT THE ROW IS ASKED, and it is deliberately ONE question:
             * does this rule perform a transfer at all?  The ops have
             * already settled the KIND -- they saw the link bit or its
             * absence and the direct/indirect bits -- and the identity
             * column is blurred exactly where one rule carries several
             * instructions, so it may not overrule them on that.
             *
             *   BRANCH_NONE   the rule is not a transfer.  The edge is
             *                 QEMU re-dispatching after a state change.
             *   BRANCH_REP    the rule is a self-re-entering string
             *                 operation; the static edge IS its re-entry,
             *                 which no other class can express.
             *   anything else the rule IS a branch and the ops' own class
             *                 for it stands.
             *
             * MEASURED, and this is why the third arm is not a row-take:
             * riscv `j label` decodes through decode_insn32/jal, whose row
             * carries BRANCH_DIRECT_CALL because the SAME rule spells
             * `jal ra, label`.  `j` is `jal x0, label` and publishes no
             * link -- the ops say so, flags=003 with LINK clear -- so the
             * row is REFUTED by the evidence the ops carry and the ops win.
             */
            uint8_t rowbt = row->cls.branch_type;
            if (rowbt == BRANCH_NONE || rowbt == BRANCH_REP) {
                qbt = rowbt;
            }
            g_ctrl_redispatch_ident++;
            if (g_detail) {
                char sig[224];
                g_snprintf(sig, sizeof(sig), "%-16s %-26s -> %-18s %s",
                           info ? info->mnemonic : "-", row->name,
                           branch_type_name_or_unknown(qbt),
                           (rowbt == qbt) ? "(rule)" : "(ops kind, rule row "
                           "says transfer)");
                tally(&g_ctrl_redisp_ident_sig, sig);
            }
        } else {
            /* Neither the ops nor an identity row can say.  NAMED
             * refusal: counted, not scored. */
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
                       f & 0x7ff, qname ? qname : "-");
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
                     const qemu_plugin_insn_info *info,
                     const InsnFields *wire)
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
    if (row->tier <= QID_ADJUDICATED) {
        g_tier_seen[row->tier]++;
    } else {
        g_tier_out_of_range++;
    }

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
        uint8_t cap_op = wire ? wire->opcode : c->opcode;
        if (row->cls.opcode == GEN_OP_UNKNOWN) {
            g_op_row_unknown++;
        } else {
            if (row->cls.opcode == cap_op) {
                g_op_agree++;
            } else {
                g_op_disagree++;
                if (g_detail) {
                    char sig[224];
                    g_snprintf(sig, sizeof(sig),
                               "%-34s qemu=%-18s wire=%-18s (%s)",
                               row->name,
                               generic_opcode_name_or_unknown(row->cls.opcode),
                               generic_opcode_name_or_unknown(cap_op),
                               info->mnemonic);
                    tally(&g_opsig, sig);
                }
            }
            if (row->cls.opcode == c->opcode) {
                g_op_agree_tbl++;
            } else {
                g_op_disagree_tbl++;
                if (g_detail) {
                    char sig[224];
                    g_snprintf(sig, sizeof(sig),
                               "%-34s qemu=%-18s captbl=%-18s (%s)",
                               row->name,
                               generic_opcode_name_or_unknown(row->cls.opcode),
                               generic_opcode_name_or_unknown(c->opcode),
                               info->mnemonic);
                    tally(&g_opsig_tbl, sig);
                }
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
        uint8_t cap_bt = wire ? wire->branch_type : c->branch_type;
        if (row->cls.opcode == GEN_OP_UNKNOWN) {
            g_br_row_unknown++;
        } else {
            if (row->cls.branch_type == cap_bt) {
                g_br_agree++;
            } else {
                g_br_disagree++;
                if (g_detail) {
                    char sig[224];
                    g_snprintf(sig, sizeof(sig),
                               "%-34s qemu=%-18s wire=%-18s (%s)",
                               row->name,
                               branch_type_name_or_unknown(row->cls.branch_type),
                               branch_type_name_or_unknown(cap_bt),
                               info->mnemonic);
                    tally(&g_brsig, sig);
                }
            }
            if (row->cls.branch_type == c->branch_type) {
                g_br_agree_tbl++;
            } else {
                g_br_disagree_tbl++;
                if (g_detail) {
                    char sig[224];
                    g_snprintf(sig, sizeof(sig),
                               "%-34s qemu=%-18s captbl=%-18s (%s)",
                               row->name,
                               branch_type_name_or_unknown(row->cls.branch_type),
                               branch_type_name_or_unknown(c->branch_type),
                               info->mnemonic);
                    tally(&g_brsig_tbl, sig);
                }
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

    /*
     * WHERE THE WIRE'S CLASSIFICATION CAME FROM, for every decode this run
     * classified.  The two DECIDED rows are the flipped population -- the
     * opcode, branch class, refiner selection and lane shape those
     * instructions publish were read off the rule QEMU dispatched on.  The
     * SURVIVOR rows are the instructions whose rule states no
     * classification, counted per reason, each with its own coverage path;
     * they still take Capstone's answer and that is what makes them
     * survivors rather than losses.
     *
     * Reported UNCONDITIONALLY, zeros included.  A zero in the survivor
     * block is a claim this run supports; a zero in the DECIDED block would
     * mean the flip did nothing here and no claim about it may be made from
     * this run at all.
     */
    QemuIdentSurvivors sv;
    qemu_ident_survivors(&sv);
    {
        uint64_t decided = qemu_ident_decided_observed() +
                           qemu_ident_adjudicated_hits();
        uint64_t surv = sv.split + sv.name_matched + sv.none +
                        sv.no_row + sv.no_ident + sv.isa_held;
        g_string_append_printf(report,
            "\n--- classification SOURCE: the decode rule, or Capstone "
            "where the rule states nothing ---\n"
            "  DECIDED by QEMU's rule, tier OBSERVED %10" PRIu64 "\n"
            "  DECIDED by QEMU's rule, ADJUDICATED   %10" PRIu64 "\n"
            "  SURVIVOR: rule's observations SPLIT   %10" PRIu64 "\n"
            "  SURVIVOR: row NAME_MATCHED, unobserved%10" PRIu64 "\n"
            "  SURVIVOR: row carries no class (NONE) %10" PRIu64 "\n"
            "  SURVIVOR: id carried, no row          %10" PRIu64 "\n"
            "  SURVIVOR: no identity exported (id 0) %10" PRIu64 "\n"
            "  HELD: this ISA's flip is not taken (must be 0) %5" PRIu64 "\n"
            "  decided rows carrying UNKNOWN (must be 0) %6" PRIu64 "\n"
            "  decided rows the Capstone row disputes    %10" PRIu64 "\n"
            "  decided %" PRIu64 " of %" PRIu64 " classified\n"
            "    HELD is now a MUST-BE-0 row: all four targets are "
            "flipped, so a decode counted here is one whose TraceISA "
            "qemu_ident_key_flipped() does not name.  riscv64 and mipsel "
            "were held on a measured corpus gap and the gap is closed -- "
            "translate_mips/OPC_SLL is split by `ssnop` and "
            "decode_insn32/ori by the three Zicbop prefetches, both rows "
            "QID_SPLIT and therefore survivors on the Capstone answer "
            "they already published, with no table edit.\n"
            "    `the Capstone row disputes` is the STANDING GUARD on the "
            "generic exposure the hold was one instance of: a rule the "
            "generator's corpus covered under only one of the spellings "
            "that reach it.  It is not a defect count -- x86_64 `rdsspq` "
            "sits in it and the identity is right (QEMU decodes it "
            "through the NOP slot and writes nothing) -- it is the "
            "population an adjudication has to be written for, reported "
            "per ISA at every run.\n",
            qemu_ident_decided_observed(), qemu_ident_adjudicated_hits(),
            sv.split, sv.name_matched, sv.none, sv.no_row, sv.no_ident,
            sv.isa_held, sv.decided_unknown, sv.cap_disagree,
            decided, decided + surv);
    }
    {
        unsigned n_adj = 0, n_fired = 0, n_untallied = 0;
        for (unsigned i = 0; i < g_nrows; i++) {
            if (g_rows[i].tier == QID_ADJUDICATED) {
                n_adj++;
                if (i >= CST_QID_MAX_ROW_HITS) {
                    n_untallied++;
                } else if (qemu_ident_row_hits(i)) {
                    n_fired++;
                }
            }
        }
        g_string_append_printf(report,
            "\n--- ADJUDICATED rows: where QEMU's own decode-table row "
            "settles a classification the Capstone key cannot express ---\n"
            "  rows this ISA adjudicates             %10u\n"
            "  of them REACHED by this run           %10u\n"
            "  instructions classified through them  %10" PRIu64 "\n",
            n_adj, n_fired, qemu_ident_adjudicated_hits());
        if (n_untallied) {
            g_string_append_printf(report,
                "  rows past the per-row tally's size    %10u   "
                "(counted in the total, not per row)\n", n_untallied);
        }
        for (unsigned i = 0; i < g_nrows && i < CST_QID_MAX_ROW_HITS; i++) {
            if (g_rows[i].tier != QID_ADJUDICATED) {
                continue;
            }
            uint64_t n = qemu_ident_row_hits(i);
            g_string_append_printf(report,
                "    0x%08x %-14s %10" PRIu64 "%s\n",
                g_rows[i].id, g_rows[i].name, n,
                n ? "" : "   NOT REACHED by this run");
        }
    }

    /*
     * THE SURVIVOR CENSUS, BY RULE.  The counters above say how many
     * decodes fell back and why; this says WHICH rules, because a
     * survivor is only a named population if it is actually named.  Each
     * tier's coverage path is stated beside it -- what would have to
     * happen for the rule to start deciding -- so the list reads as work
     * with a route rather than as residue.  A run that reaches no
     * survivor rule prints the header and nothing else, which is itself
     * the claim.
     */
    {
        g_string_append_printf(report,
            "\n--- SURVIVOR rules REACHED by this run, by decode rule ---\n"
            "  QID_SPLIT        several classifications were observed "
            "through the one rule; coverage path = an adjudication (a fact "
            "QEMU's own decode-table row states that refutes or subsumes "
            "all but one candidate), or a finer pattern-qualified key.\n"
            "  QID_NAME_MATCHED nothing was ever observed decoding through "
            "the rule, so its payload rests on its NAME; coverage path = a "
            "generator corpus that reaches it, which promotes it to "
            "QID_OBSERVED with no table edit at all.\n"
            "  QID_NONE         the rule carries no classification; "
            "coverage path = the same, plus a generic word for what it "
            "decodes to.\n");
        unsigned printed = 0;
        for (unsigned i = 0; i < g_nrows && i < CST_QID_MAX_ROW_HITS; i++) {
            uint8_t t = g_rows[i].tier;
            if (t == QID_OBSERVED || t == QID_ADJUDICATED) {
                continue;
            }
            uint64_t n = qemu_ident_row_hits(i);
            if (!n) {
                continue;
            }
            g_string_append_printf(report,
                "    0x%08x %-14s %-16s %10" PRIu64 "\n",
                g_rows[i].id,
                t == QID_SPLIT ? "QID_SPLIT"
                               : (t == QID_NAME_MATCHED ? "QID_NAME_MATCHED"
                                                        : "QID_NONE"),
                g_rows[i].name, n);
            printed++;
        }
        if (!printed) {
            /*
             * TWO DIFFERENT ZEROS, and printing one word for both would be
             * the silent-false-success shape exactly: on a flipped ISA an
             * empty list means every rule decided, and on a HELD ISA it
             * means no rule was ever consulted.  Say which.
             */
            g_string_append_printf(report, "%s",
                sv.isa_held
                ? "    n/a -- this ISA's flip is HELD, so no rule was "
                  "consulted and this list has no subject\n"
                : "    none -- every rule this run decoded through states "
                  "a classification\n");
        }
    }
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
            "equal to the instruction's own ARCHITECTURAL CONTINUATION "
            "published into a register or onto the stack is a LINK, and a "
            "static successor equal to the instruction's own address is a "
            "string operation's self-edge.  None of it is a pattern NAME, "
            "which is what makes it immune to the alias blurring that made "
            "the identity table's .branch_type column unusable.\n"
            "The continuation is (pc + len) on most targets and PAST THE "
            "DELAY SLOT on MIPS -- a mips call publishes pc + 8 and its "
            "not-taken edge is that same address -- which QEMU states by "
            "naming the slot that emitted the transfer, so no per-target "
            "constant is assumed here.\n"
            "  scored                                 %10" PRIu64 "\n"
            "  agree                                  %10" PRIu64 "\n"
            "  DISAGREE                               %10" PRIu64 "\n"
            "  FOREIGN: slot of a previous block's br %10" PRIu64
            "   (counted AND scored)\n"
            "  adjudicated: ctrl_syscall_ident        %10" PRIu64
            "   (identity says SYSCALL, the helper raises)\n"
            "  adjudicated: ctrl_folded_cond          %10" PRIu64
            "   (identity says CONDITIONAL, QEMU folded the edge)\n"
            "  adjudicated: ctrl_redispatch_ident     %10" PRIu64
            "   (ops say `edge to the next insn`, identity says which)\n"
            "REFUSALS -- counted, NOT scored.  A refusal is not a wrong\n"
            "answer and must not be charged as one; each is named because\n"
            "a wire flip has to publish something for these same rows.\n"
            "  REFUSED no classification exported     %10" PRIu64
            "   (CTRL_VALID clear: QEMU stated nothing)\n"
            "  REFUSED walk INCOMPLETE                %10" PRIu64
            "   (the op walk gave up on this block)\n"
            "  REFUSED no successor stated            %10" PRIu64
            "   (exit_tb only)\n"
            "  REFUSED PENDING                        %10" PRIu64
            "   (branch here, its transfer in the next block)\n"
            "  REFUSED re-dispatch, no identity       %10" PRIu64
            "   (edge == next insn and the rule carries no class)\n",
            g_br2_seen, g_br2_agree, g_br2_disagree,
            g_br2_foreign, g_ctrl_syscall_ident, g_ctrl_folded_cond,
            g_ctrl_redispatch_ident,
            g_br2_unavail, g_br2_incomplete, g_br2_nochain, g_br2_pending,
            g_br2_redispatch);
        if (g_detail) {
            dump_tally(report, g_br2sig, "branch-class disagreements", 40);
            dump_tally(report, g_ctrl_syscall_sig,
                       "ctrl_syscall_ident adjudications", 20);
            dump_tally(report, g_ctrl_folded_sig,
                       "ctrl_folded_cond adjudications", 20);
            dump_tally(report, g_ctrl_redisp_ident_sig,
                       "ctrl_redispatch_ident adjudications", 20);
            dump_tally(report, g_br2_unavail_sig,
                       "REFUSED: no classification exported", 20);
            dump_tally(report, g_br2_incomplete_sig,
                       "REFUSED: walk INCOMPLETE", 20);
            dump_tally(report, g_br2_nochain_sig,
                       "REFUSED: no successor stated (exit_tb only)", 20);
            dump_tally(report, g_br2_pending_sig,
                       "REFUSED: PENDING (split branch/slot)", 20);
            dump_tally(report, g_br2_redisp_sig,
                       "REFUSED: re-dispatch with no identity", 20);
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
        "decode rule, keyed by qemu_plugin_insn_decode_id().  Under ruling "
        "J6 this identity is the INTENDED source of the wire's opcode "
        "taxonomy; it is not the source yet, so today the wire still "
        "takes its opcode from Capstone and the numbers below measure "
        "how ready the replacement is.\n"
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
        "   ADJUDICATED %" PRIu64
        "   SPLIT %" PRIu64 "   NAME_MATCHED %" PRIu64
        "   NONE %" PRIu64 "   tier out of range %" PRIu64 "\n"
        "    OBSERVED and ADJUDICATED are the tiers the classifier takes "
        "the wire's answer from; the other three are the survivor "
        "population that still falls back to Capstone.  A NAME_MATCHED "
        "row that executes is a row the table UNDERSTATES; a NONE row "
        "that executes is live residue -- an instruction with no "
        "QEMU-side name agreeing about what it is; a SPLIT row that "
        "executes is a rule whose own observations disagreed, so the "
        "identity alone does not classify it.  `tier out of range` must "
        "be 0: it means a row carries a tier this reader has no column "
        "for.\n",
        g_rows_hit ? g_hash_table_size(g_rows_hit) : 0, g_nrows,
        g_tier_seen[QID_OBSERVED], g_tier_seen[QID_ADJUDICATED],
        g_tier_seen[QID_SPLIT], g_tier_seen[QID_NAME_MATCHED],
        g_tier_seen[QID_NONE], g_tier_out_of_range);

    g_string_append_printf(report,
        "  scored against the WIRE -- decode_detail_to_generic()'s answer, "
        "which is what a trace carries:\n"
        "  opcode     agree %10" PRIu64 "   disagree %10" PRIu64
        "   row unclassified %" PRIu64 "\n"
        "  branchtype agree %10" PRIu64 "   disagree %10" PRIu64
        "   row unclassified %" PRIu64 "\n"
        "  scored against the pre-refinement mnemonic TABLE ROW -- the "
        "INPUT to those refiners, published nowhere.  A row where the two "
        "accounts differ is a row a refiner rewrote, and only the WIRE "
        "figure above can adjudicate it:\n"
        "  opcode     agree %10" PRIu64 "   disagree %10" PRIu64 "\n"
        "  branchtype agree %10" PRIu64 "   disagree %10" PRIu64 "\n",
        g_op_agree, g_op_disagree, g_op_row_unknown,
        g_br_agree, g_br_disagree, g_br_row_unknown,
        g_op_agree_tbl, g_op_disagree_tbl,
        g_br_agree_tbl, g_br_disagree_tbl);

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
    dump_tally(report, g_opsig,     "opcode disagreements (vs WIRE)", 24);
    dump_tally(report, g_brsig,     "branch-type disagreements (vs WIRE)", 24);
    dump_tally(report, g_opsig_tbl,
               "opcode disagreements (vs pre-refinement table row)", 24);
    dump_tally(report, g_brsig_tbl,
               "branch-type disagreements (vs pre-refinement table row)", 24);
}
