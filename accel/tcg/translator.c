/*
 * Generic intermediate code generation.
 *
 * Copyright (C) 2016-2017 Lluís Vilanova <vilanova@ac.upc.edu>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "exec/exec-all.h"
#include "exec/translator.h"
#include "exec/insn-dataflow.h"
#include "exec/cpu_ldst.h"
#include "exec/plugin-gen.h"
#include "qemu/plugin.h"
#include "exec/oracle.h"
#include "qemu/cst_bqslice.h"
#include "tcg/helper-info.h"
#include "exec/helper-head.h.inc"
#include "exec/cpu_ldst.h"
#include "exec/tswap.h"
#include "tcg/tcg-op-common.h"
#include "internal-target.h"
#include "disas/disas.h"
#include "tb-internal.h"

static void set_can_do_io(DisasContextBase *db, bool val)
{
    QEMU_BUILD_BUG_ON(sizeof_field(CPUState, neg.can_do_io) != 1);
    tcg_gen_st8_i32(tcg_constant_i32(val), tcg_env,
                    offsetof(ArchCPU, parent_obj.neg.can_do_io) -
                    offsetof(ArchCPU, env));
}

bool translator_io_start(DisasContextBase *db)
{
    /*
     * Ensure that this instruction will be the last in the TB.
     * The target may override this to something more forceful.
     */
    if (db->is_jmp == DISAS_NEXT) {
        db->is_jmp = DISAS_TOO_MANY;
    }
    return true;
}

static TCGOp *gen_tb_start(DisasContextBase *db, uint32_t cflags)
{
    TCGv_i32 count = NULL;
    TCGOp *icount_start_insn = NULL;
    /*
     * CST_BUDGET_QUANTUM (knob A): emit the SAME budget prologue icount
     * emits (the sub below and the st16 back to icount_decr.u16.low),
     * on the default clock, with no other CF_USE_ICOUNT effect.  The
     * exit check against u32 < 0 is the EXISTING !CF_NOIRQ check --
     * unchanged.  CF_NOIRQ TBs are not billed: icount may bill them
     * because higher-level code guarantees budget (and the replay
     * exception step strips CF_USE_ICOUNT); off-icount an unchecked sub
     * would wrap u16.low.  The knob is translate-time-global (set before
     * any translation, constant for the run), so every cached TB agrees.
     * See include/qemu/cst_bqslice.h.
     */
    bool cst_bq_bill = cst_bq_on && !(cflags & (CF_USE_ICOUNT | CF_NOIRQ));

    if ((cflags & CF_USE_ICOUNT) || !(cflags & CF_NOIRQ)) {
        count = tcg_temp_new_i32();
        tcg_gen_ld_i32(count, tcg_env,
                       offsetof(ArchCPU, parent_obj.neg.icount_decr.u32)
                       - offsetof(ArchCPU, env));
    }

    if ((cflags & CF_USE_ICOUNT) || cst_bq_bill) {
        /*
         * We emit a sub with a dummy immediate argument. Keep the insn index
         * of the sub so that we later (when we know the actual insn count)
         * can update the argument with the actual insn count.
         */
        tcg_gen_sub_i32(count, count, tcg_constant_i32(0));
        icount_start_insn = tcg_last_op();
    }

    /*
     * Emit the check against icount_decr.u32 to see if we should exit
     * unless we suppress the check with CF_NOIRQ. If we are using
     * icount and have suppressed interruption the higher level code
     * should have ensured we don't run more instructions than the
     * budget.
     */
    if (cflags & CF_NOIRQ) {
        tcg_ctx->exitreq_label = NULL;
    } else {
        tcg_ctx->exitreq_label = gen_new_label();
        tcg_gen_brcondi_i32(TCG_COND_LT, count, 0, tcg_ctx->exitreq_label);
    }

    if ((cflags & CF_USE_ICOUNT) || cst_bq_bill) {
        tcg_gen_st16_i32(count, tcg_env,
                         offsetof(ArchCPU, parent_obj.neg.icount_decr.u16.low)
                         - offsetof(ArchCPU, env));
    }

    return icount_start_insn;
}

static void gen_tb_end(const TranslationBlock *tb, uint32_t cflags,
                       TCGOp *icount_start_insn, int num_insns)
{
    if (icount_start_insn) {
        /*
         * Update the num_insn immediate parameter now that we know
         * the actual insn count.  Non-NULL exactly when gen_tb_start
         * emitted the budget sub: always under CF_USE_ICOUNT (identical
         * to the old CF_USE_ICOUNT test), and under CST_BUDGET_QUANTUM
         * (knob A) billing.
         */
        tcg_set_insn_param(icount_start_insn, 2,
                           tcgv_i32_arg(tcg_constant_i32(num_insns)));
    }

    if (tcg_ctx->exitreq_label) {
        gen_set_label(tcg_ctx->exitreq_label);
        tcg_gen_exit_tb(tb, TB_EXIT_REQUESTED);
    }
}

bool translator_is_same_page(const DisasContextBase *db, vaddr addr)
{
    return ((addr ^ db->pc_first) & TARGET_PAGE_MASK) == 0;
}

bool translator_use_goto_tb(DisasContextBase *db, vaddr dest)
{
    /* Suppress goto_tb if requested. */
    if (tb_cflags(db->tb) & CF_NO_GOTO_TB) {
        return false;
    }

    /* Check for the dest on the same page as the start of the TB.  */
    return translator_is_same_page(db, dest);
}

/*
 * NEVER-SPLIT (atomic) CODE SEQUENCES — plugin-registered byte patterns
 * the translator keeps whole inside one TB (ChampSim Tracer marker
 * sequences; see qemu_plugin_register_nosplit_code_sequences and
 * docs/qemu_modifications.rst).
 *
 * At every CLEAN TB-end decision (DISAS_TOO_MANY: page boundary, budget,
 * single-step — never a real control transfer), the translated tail is
 * compared against the registered sequences.  If it is a PROPER prefix of
 * one, translation continues through the sequence via the normal
 * code-fetch path: a cross-page continuation is an ordinary cross-page TB
 * (tb->page_addr[1]), and a fetch fault is the fault the next fetch was
 * about to take — the standard translation restart services it.  The
 * whole sequence therefore always appears together in one TB.
 */

/* Read @len already-translated bytes at @addr out of the TB's own host
 * pages.  Mirrors translator_st's page-split walk, but is valid mid-loop
 * (translator_st sizes itself from tb->size, which is only set at the
 * end).  Refuses the MMIO/record paths — those TBs are deliberately
 * capped and must not be extended. */
static bool translator_nosplit_read(const DisasContextBase *db, void *dest,
                                    vaddr addr, size_t len)
{
    size_t offset, offset_end, offset_page1;

    if (db->fake_insn || db->record_len != 0 || !db->host_addr[0] ||
        addr < db->pc_first) {
        return false;
    }
    offset = addr - db->pc_first;
    offset_end = offset + len;
    offset_page1 = -(db->pc_first | TARGET_PAGE_MASK);

    if (offset_end <= offset_page1) {
        memcpy(dest, db->host_addr[0] + offset, len);
        return true;
    }
    if (offset < offset_page1) {
        size_t len0 = offset_page1 - offset;
        memcpy(dest, db->host_addr[0] + offset, len0);
        offset += len0;
        dest = (uint8_t *)dest + len0;
    }
    if (db->host_addr[1] && offset >= offset_page1) {
        memcpy(dest, db->host_addr[1] + (offset - offset_page1),
               offset_end - offset);
        return true;
    }
    return false;
}

/*
 * v4 repair (maintainer-vetoable): the stop-decision verdict.
 *
 * EXTEND  — the tail is a proper prefix of a registered sequence and the
 *           continuation is representable: rescind the stop and continue
 *           through the sequence.
 * REFUSE  — the tail is mid-sequence but extension is impossible for a
 *           hard reason (CF_COUNT_MASK ceiling, third page).  The caller
 *           RETREATS: it ends the TB before the sequence's first
 *           instruction so the sequence opens the next TB whole.
 * NO_MATCH — an ordinary stop.
 */
typedef enum {
    NOSPLIT_NO_MATCH,
    NOSPLIT_EXTEND,
    NOSPLIT_REFUSE,
} NosplitVerdict;

/* Classify the TB's translated tail against the registered never-split
 * sequences.  On EXTEND the continuation stays within pc_first's page
 * pair (a TB holds at most two pages) and the insn count stays under
 * CF_COUNT_MASK.  On REFUSE, @seq_start_pc is the guest pc where the
 * longest matched prefix begins — the retreat point. */
static NosplitVerdict translator_nosplit_continue(const DisasContextBase *db,
                                                  vaddr *seq_start_pc)
{
    const uint8_t *seqs[QEMU_PLUGIN_NOSPLIT_MAX];
    size_t seq_len, n, max_l, best_match = 0, best_feasible = 0;
    uint8_t tail[64];

    n = qemu_plugin_nosplit_seqs(seqs, &seq_len);
    if (n == 0) {
        return NOSPLIT_NO_MATCH;
    }
    max_l = MIN((size_t)(db->pc_next - db->pc_first), seq_len - 1);
    if (max_l == 0 || max_l > sizeof(tail)) {
        return NOSPLIT_NO_MATCH;
    }
    if (!translator_nosplit_read(db, tail, db->pc_next - max_l, max_l)) {
        return NOSPLIT_NO_MATCH;
    }
    for (size_t i = 0; i < n; i++) {
        for (size_t l = max_l; l >= 1; l--) {
            if (l <= best_feasible) {
                break;                          /* cannot improve */
            }
            if (memcmp(tail + (max_l - l), seqs[i], l) != 0) {
                continue;
            }
            best_match = MAX(best_match, l);
            vaddr end = db->pc_next + (seq_len - l) - 1;
            vaddr page0 = db->pc_first & TARGET_PAGE_MASK;
            if (end < db->pc_next) {
                continue;                       /* address-space wrap */
            }
            if ((end & TARGET_PAGE_MASK) - page0 > TARGET_PAGE_SIZE) {
                continue;                       /* would need a 3rd page */
            }
            best_feasible = l;
            break;                              /* longest for this seq */
        }
    }
    if (best_match == 0) {
        return NOSPLIT_NO_MATCH;
    }
    *seq_start_pc = db->pc_next - best_match;
    if (db->num_insns >= CF_COUNT_MASK) {
        /* Ceiling refusal is hard for any match: retreat, don't split. */
        return NOSPLIT_REFUSE;
    }
    return best_feasible ? NOSPLIT_EXTEND : NOSPLIT_REFUSE;
}

/*
 * v4 repair (maintainer-vetoable): per-insn boundary records for the
 * never-split RETREAT.  A sequence prefix is at most seq_len-1 < 64
 * bytes, instructions are at least one byte, so the last 64 boundaries
 * always cover any retreat point.  Records are only maintained while
 * never-split sequences are registered.
 */
#define NOSPLIT_RING_LEN 64
typedef struct NosplitInsnRec {
    vaddr pc;                   /* guest pc of this insn's first byte */
    TCGOp *op_tail;             /* last op emitted before this insn */
    TCGOp *insn_start_prev;     /* db->insn_start of the previous insn */
    uint64_t tstate;            /* target checkpoint (ops->nosplit_checkpoint) */
} NosplitInsnRec;

/*
 * End the TB before the sequence's first instruction instead of
 * splitting the sequence: drop every op from that boundary on (the
 * precedent is the target-side one-insn rewind on a refused page
 * crossing, e.g. i386 advance_pc's siglongjmp), rewind
 * pc_next/num_insns/insn_start, and leave is_jmp = DISAS_TOO_MANY so
 * the sequence opens the NEXT TB whole.  Single-shot by construction:
 * the caller breaks out of the translation loop immediately after.
 *
 * Gives up (plain split, no rewind of state) when the retreat point is
 * mid-insn, would empty the TB, predates the ring, or the target hook
 * vetoes.  The dropped insns are a byte-prefix of a registered sequence
 * — immediate loads by construction — so target-private decode state
 * they could dirty is limited to what ops->nosplit_retreat re-syncs.
 */
static void translator_nosplit_retreat(DisasContextBase *db, CPUState *cpu,
                                       const TranslatorOps *ops,
                                       int *max_insns,
                                       const NosplitInsnRec *ring,
                                       vaddr seq_start_pc)
{
    int j, lo;

    db->is_jmp = DISAS_TOO_MANY;
    /* Keep at least insn 1: an empty TB cannot be emitted. */
    lo = MAX(db->num_insns - (NOSPLIT_RING_LEN - 1), 2);
    for (j = db->num_insns; j >= lo; j--) {
        const NosplitInsnRec *r = &ring[(j - 1) % NOSPLIT_RING_LEN];
        if (r->pc < seq_start_pc) {
            return;             /* sequence starts mid-insn: give up */
        }
        if (r->pc == seq_start_pc) {
            if (ops->nosplit_retreat &&
                !ops->nosplit_retreat(db, cpu, r->pc, r->tstate)) {
                return;         /* target vetoed: give up */
            }
            tcg_remove_ops_after(r->op_tail);
            db->num_insns = j - 1;
            *max_insns = j - 1;
            db->pc_next = r->pc;
            db->insn_start = r->insn_start_prev;
            return;
        }
    }
    /* Retreat point at pc_first or beyond the ring: give up. */
}

void translator_loop(CPUState *cpu, TranslationBlock *tb, int *max_insns,
                     vaddr pc, void *host_pc, const TranslatorOps *ops,
                     DisasContextBase *db)
{
    uint32_t cflags = tb_cflags(tb);
    TCGOp *icount_start_insn;
    TCGOp *first_insn_start = NULL;
    bool plugin_enabled;
    int nosplit_icount_cap;
    bool nosplit_active;
    vaddr nosplit_rearm_pc = 0;
    NosplitInsnRec nosplit_ring[NOSPLIT_RING_LEN];
    {
        const uint8_t *nosplit_seqs[QEMU_PLUGIN_NOSPLIT_MAX];
        size_t nosplit_seq_len;
        nosplit_active =
            qemu_plugin_nosplit_seqs(nosplit_seqs, &nosplit_seq_len) != 0;
    }

    /* Initialize DisasContext */
    db->tb = tb;
    db->pc_first = pc;
    db->pc_next = pc;
    db->is_jmp = DISAS_NEXT;
    db->num_insns = 0;
    db->max_insns = *max_insns;
    nosplit_icount_cap = db->max_insns;
    db->insn_start = NULL;
    db->fake_insn = false;
    db->nosplit_extend = false;
    db->host_addr[0] = host_pc;
    db->host_addr[1] = NULL;
    db->record_start = 0;
    db->record_len = 0;

    ops->init_disas_context(db, cpu);
    tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

    /* Start translating.  */
    icount_start_insn = gen_tb_start(db, cflags);
    ops->tb_start(db, cpu);
    tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

    plugin_enabled = plugin_gen_tb_start(cpu, db);
    db->plugin_enabled = plugin_enabled;

    while (true) {
        *max_insns = ++db->num_insns;
        if (nosplit_active) {
            /* v4 repair: record this insn's boundary for a possible
             * never-split RETREAT (see translator_nosplit_retreat). */
            NosplitInsnRec *r =
                &nosplit_ring[(db->num_insns - 1) % NOSPLIT_RING_LEN];
            r->pc = db->pc_next;
            r->op_tail = tcg_last_op();
            r->insn_start_prev = db->insn_start;
            r->tstate = ops->nosplit_checkpoint
                        ? ops->nosplit_checkpoint(db, cpu) : 0;
        }
        ops->insn_start(db, cpu);
        db->insn_start = tcg_last_op();
        if (first_insn_start == NULL) {
            first_insn_start = db->insn_start;
        }
        tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

        if (plugin_enabled) {
            plugin_gen_insn_start(cpu, db);
        }

#ifdef CONFIG_ORACLE
        /*
         * One call site delimits instructions for every target: the probe
         * forces TCG to spill the guest registers it is holding in host
         * registers, so CPUArchState is coherent and the delta since the
         * previous boundary is exactly what the previous instruction wrote.
         *
         * Whether a probe is emitted at all is decided here, at translation
         * time, from the TB's CF_ORACLE flag and the instruction's pc.  An
         * instruction outside the observation window costs nothing rather
         * than costing a call that returns immediately.
         */
        oracle_gen_insn_boundary(db->pc_next, db->num_insns == 1);
#endif

        /*
         * Disassemble one instruction.  The translate_insn hook should
         * update db->pc_next and db->is_jmp to indicate what should be
         * done next -- either exiting this loop or locate the start of
         * the next instruction.
         */
        ops->translate_insn(db, cpu);

        /*
         * We can't instrument after instructions that change control
         * flow although this only really affects post-load operations.
         *
         * Calling plugin_gen_insn_end() before we possibly stop translation
         * is important. Even if this ends up as dead code, plugin generation
         * needs to see a matching plugin_gen_insn_{start,end}() pair in order
         * to accurately track instrumented helpers that might access memory.
         */
        if (plugin_enabled) {
            plugin_gen_insn_end();
        }

        /* Stop translation if translate_insn so indicated.  */
        if (db->is_jmp != DISAS_NEXT) {
            /* Never-split: a CLEAN stop (page boundary / target budget)
             * mid-sequence continues through the sequence instead.  Real
             * control transfers are never DISAS_TOO_MANY and never
             * continue.
             *
             * v4 repair (maintainer-vetoable), refuse-once semantics:
             * a re-arm at a pc where a previous re-arm made no progress
             * is a target refusal that persists; together with op-buffer
             * pressure it is a HARD refusal, and a hard refusal mid-
             * sequence RETREATS — ends the TB before the sequence's
             * first insn — instead of re-arming (the old re-arm spin)
             * or splitting the sequence. */
            if (db->is_jmp == DISAS_TOO_MANY && nosplit_active) {
                vaddr seq_start = 0;
                NosplitVerdict v =
                    translator_nosplit_continue(db, &seq_start);
                if (v == NOSPLIT_EXTEND &&
                    (tcg_op_buf_full() ||
                     (db->nosplit_extend &&
                      db->pc_next == nosplit_rearm_pc))) {
                    v = NOSPLIT_REFUSE;
                }
                if (v == NOSPLIT_EXTEND) {
                    nosplit_rearm_pc = db->pc_next;
                    db->nosplit_extend = true;
                    db->is_jmp = DISAS_NEXT;
                } else {
                    if (v == NOSPLIT_REFUSE) {
                        translator_nosplit_retreat(db, cpu, ops, max_insns,
                                                   nosplit_ring, seq_start);
                    }
                    break;
                }
            } else {
                break;
            }
        }

        /* Stop translation if the output buffer is full,
           or we have executed all of the allowed instructions.  */
        if (tcg_op_buf_full() || db->num_insns >= db->max_insns) {
            /* Never-split: extend the budget (icount / single-step
             * included — the sequence is atomic to the translator by
             * design) rather than end mid-sequence.  gen_tb_end bills
             * at most the ORIGINAL budget so an icount slice cannot
             * livelock on a TB it can never afford.
             *
             * v4 repair: a hard refusal mid-sequence (op-buffer
             * pressure, CF_COUNT_MASK ceiling) RETREATS instead of
             * splitting, so budget-and-boundary collisions no longer
             * split fixed-width straddles. */
            NosplitVerdict v = NOSPLIT_NO_MATCH;
            vaddr seq_start = 0;
            if (nosplit_active) {
                v = translator_nosplit_continue(db, &seq_start);
                if (v == NOSPLIT_EXTEND && tcg_op_buf_full()) {
                    v = NOSPLIT_REFUSE;
                }
            }
            if (v == NOSPLIT_EXTEND) {
                nosplit_rearm_pc = db->pc_next;
                db->nosplit_extend = true;
                db->max_insns = db->num_insns + 1;
            } else if (v == NOSPLIT_REFUSE) {
                translator_nosplit_retreat(db, cpu, ops, max_insns,
                                           nosplit_ring, seq_start);
                break;
            } else {
                db->is_jmp = DISAS_TOO_MANY;
                break;
            }
        }
    }

    /* Emit code to exit the TB, as indicated by db->is_jmp.  */
    ops->tb_stop(db, cpu);
    /* Never-split extension: bill at most the budget the TB was asked
     * for.  Identical to db->num_insns except when the atomic-sequence
     * continue-through pushed num_insns past the requested count — an
     * icount head check billed the full count would then exit forever
     * on a slice that can never afford the TB. */
    gen_tb_end(tb, cflags, icount_start_insn,
               MIN(db->num_insns, nosplit_icount_cap));

    /*
     * Manage can_do_io for the translation block: set to false before
     * the first insn and set to true before the last insn.
     */
    if (db->num_insns == 1) {
        tcg_debug_assert(first_insn_start == db->insn_start);
    } else {
        tcg_debug_assert(first_insn_start != db->insn_start);
        tcg_ctx->emit_before_op = first_insn_start;
        set_can_do_io(db, false);
    }
    tcg_ctx->emit_before_op = db->insn_start;
    set_can_do_io(db, true);
    tcg_ctx->emit_before_op = NULL;

    /* May be used by disas_log or plugin callbacks. */
    tb->size = db->pc_next - db->pc_first;
    tb->icount = db->num_insns;

    if (plugin_enabled) {
        /*
         * Read each instruction's register accesses off the ops the target
         * just emitted, before the plugin's translate callback asks for them
         * and long before tcg_optimize() is entitled to delete a write that
         * nothing downstream consumes.
         */
        insn_dataflow_extract(db->num_insns);
        plugin_gen_tb_end(cpu, db->num_insns);
    }

    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)
        && qemu_log_in_addr_range(db->pc_first)) {
        FILE *logfile = qemu_log_trylock();
        if (logfile) {
            fprintf(logfile, "----------------\n");

            if (!ops->disas_log ||
                !ops->disas_log(db, cpu, logfile)) {
                fprintf(logfile, "IN: %s\n", lookup_symbol(db->pc_first));
                target_disas(logfile, cpu, db);
            }
            fprintf(logfile, "\n");
            qemu_log_unlock(logfile);
        }
    }
}

static bool translator_ld(CPUArchState *env, DisasContextBase *db,
                          void *dest, vaddr pc, size_t len)
{
    TranslationBlock *tb = db->tb;
    vaddr last = pc + len - 1;
    void *host;
    vaddr base;

    /* Use slow path if first page is MMIO. */
    if (unlikely(tb_page_addr0(tb) == -1)) {
        /* We capped translation with first page MMIO in tb_gen_code. */
        tcg_debug_assert(db->max_insns == 1);
        return false;
    }

    host = db->host_addr[0];
    base = db->pc_first;

    if (likely(((base ^ last) & TARGET_PAGE_MASK) == 0)) {
        /* Entire read is from the first page. */
        memcpy(dest, host + (pc - base), len);
        return true;
    }

    if (unlikely(((base ^ pc) & TARGET_PAGE_MASK) == 0)) {
        /* Read begins on the first page and extends to the second. */
        size_t len0 = -(pc | TARGET_PAGE_MASK);
        memcpy(dest, host + (pc - base), len0);
        pc += len0;
        dest += len0;
        len -= len0;
    }

    /*
     * The read must conclude on the second page and not extend to a third.
     *
     * TODO: We could allow the two pages to be virtually discontiguous,
     * since we already allow the two pages to be physically discontiguous.
     * The only reasonable use case would be executing an insn at the end
     * of the address space wrapping around to the beginning.  For that,
     * we would need to know the current width of the address space.
     * In the meantime, assert.
     */
    base = (base & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
    assert(((base ^ pc) & TARGET_PAGE_MASK) == 0);
    assert(((base ^ last) & TARGET_PAGE_MASK) == 0);
    host = db->host_addr[1];

    if (host == NULL) {
        tb_page_addr_t page0, old_page1, new_page1;

        new_page1 = get_page_addr_code_hostp(env, base, &db->host_addr[1]);

        /*
         * If the second page is MMIO, treat as if the first page
         * was MMIO as well, so that we do not cache the TB.
         */
        if (unlikely(new_page1 == -1)) {
            tb_unlock_pages(tb);
            tb_set_page_addr0(tb, -1);
            /* Require that this be the final insn. */
            db->max_insns = db->num_insns;
            return false;
        }

        /*
         * If this is not the first time around, and page1 matches,
         * then we already have the page locked.  Alternately, we're
         * not doing anything to prevent the PTE from changing, so
         * we might wind up with a different page, requiring us to
         * re-do the locking.
         */
        old_page1 = tb_page_addr1(tb);
        if (likely(new_page1 != old_page1)) {
            page0 = tb_page_addr0(tb);
            if (unlikely(old_page1 != -1)) {
                tb_unlock_page1(page0, old_page1);
            }
            tb_set_page_addr1(tb, new_page1);
            tb_lock_page1(page0, new_page1);
        }
        host = db->host_addr[1];
    }

    memcpy(dest, host + (pc - base), len);
    return true;
}

static void record_save(DisasContextBase *db, vaddr pc,
                        const void *from, int size)
{
    int offset;

    /* Do not record probes before the start of TB. */
    if (pc < db->pc_first) {
        return;
    }

    /*
     * In translator_access, we verified that pc is within 2 pages
     * of pc_first, thus this will never overflow.
     */
    offset = pc - db->pc_first;

    /*
     * Either the first or second page may be I/O.  If it is the second,
     * then the first byte we need to record will be at a non-zero offset.
     * In either case, we should not need to record but a single insn.
     */
    if (db->record_len == 0) {
        db->record_start = offset;
        db->record_len = size;
    } else {
        assert(offset == db->record_start + db->record_len);
        assert(db->record_len + size <= sizeof(db->record));
        db->record_len += size;
    }

    memcpy(db->record + (offset - db->record_start), from, size);
}

size_t translator_st_len(const DisasContextBase *db)
{
    return db->fake_insn ? db->record_len : db->tb->size;
}

bool translator_st(const DisasContextBase *db, void *dest,
                   vaddr addr, size_t len)
{
    size_t offset, offset_end;

    if (addr < db->pc_first) {
        return false;
    }
    offset = addr - db->pc_first;
    offset_end = offset + len;
    if (offset_end > translator_st_len(db)) {
        return false;
    }

    if (!db->fake_insn) {
        size_t offset_page1 = -(db->pc_first | TARGET_PAGE_MASK);

        /* Get all the bytes from the first page. */
        if (db->host_addr[0]) {
            if (offset_end <= offset_page1) {
                memcpy(dest, db->host_addr[0] + offset, len);
                return true;
            }
            if (offset < offset_page1) {
                size_t len0 = offset_page1 - offset;
                memcpy(dest, db->host_addr[0] + offset, len0);
                offset += len0;
                dest += len0;
            }
        }

        /* Get any bytes from the second page. */
        if (db->host_addr[1] && offset >= offset_page1) {
            memcpy(dest, db->host_addr[1] + (offset - offset_page1),
                   offset_end - offset);
            return true;
        }
    }

    /* Else get recorded bytes. */
    if (db->record_len != 0 &&
        offset >= db->record_start &&
        offset_end <= db->record_start + db->record_len) {
        memcpy(dest, db->record + (offset - db->record_start),
               offset_end - offset);
        return true;
    }
    return false;
}

uint8_t translator_ldub(CPUArchState *env, DisasContextBase *db, vaddr pc)
{
    uint8_t raw;

    if (!translator_ld(env, db, &raw, pc, sizeof(raw))) {
        raw = cpu_ldub_code(env, pc);
        record_save(db, pc, &raw, sizeof(raw));
    }
    return raw;
}

uint16_t translator_lduw(CPUArchState *env, DisasContextBase *db, vaddr pc)
{
    uint16_t raw, tgt;

    if (translator_ld(env, db, &raw, pc, sizeof(raw))) {
        tgt = tswap16(raw);
    } else {
        tgt = cpu_lduw_code(env, pc);
        raw = tswap16(tgt);
        record_save(db, pc, &raw, sizeof(raw));
    }
    return tgt;
}

uint32_t translator_ldl(CPUArchState *env, DisasContextBase *db, vaddr pc)
{
    uint32_t raw, tgt;

    if (translator_ld(env, db, &raw, pc, sizeof(raw))) {
        tgt = tswap32(raw);
    } else {
        tgt = cpu_ldl_code(env, pc);
        raw = tswap32(tgt);
        record_save(db, pc, &raw, sizeof(raw));
    }
    return tgt;
}

uint64_t translator_ldq(CPUArchState *env, DisasContextBase *db, vaddr pc)
{
    uint64_t raw, tgt;

    if (translator_ld(env, db, &raw, pc, sizeof(raw))) {
        tgt = tswap64(raw);
    } else {
        tgt = cpu_ldq_code(env, pc);
        raw = tswap64(tgt);
        record_save(db, pc, &raw, sizeof(raw));
    }
    return tgt;
}

void translator_fake_ld(DisasContextBase *db, const void *data, size_t len)
{
    db->fake_insn = true;
    record_save(db, db->pc_first, data, len);
}
