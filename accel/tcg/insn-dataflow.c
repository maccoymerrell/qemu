/*
 * Per-instruction dataflow, read off the ops the target's translator emitted.
 *
 * The premise is the one that makes memory instrumentation work: a guest
 * instruction's accesses are not something to be looked up, they are something
 * QEMU has already written down.  A memory access is an explicit TCG op; so is
 * a register access.  Every op declares how many of its arguments are outputs
 * and how many are inputs, and a temp that is TEMP_GLOBAL based on tcg_env is
 * a guest register at a known offset in CPUArchState.  The ops between two
 * insn_start markers are one instruction, and sorting their globals by
 * argument position is that instruction's read and write sets.
 *
 * This supplies dataflow only.  Which instruction it is looking at -- the rule
 * the bytes reached, the opcode class, the branch class, the length -- is
 * stated separately, at the decode site that knows it; nothing here can say
 * and nothing here guesses.
 *
 * Why before tcg_optimize()
 * -------------------------
 * Dead-store elimination removes architecturally real writes that nothing
 * downstream consumes.  x86 is the extreme case: the whole lazy-flags scheme
 * exists so that a flag write can be dropped when the next instruction does
 * not look at them.  So this runs at the end of translator_loop(), before any
 * pass has touched the ops and before the translation's own callbacks need the
 * answer.
 *
 * What it gives that a state differ cannot
 * ---------------------------------------
 * Reads, at all.  Inert writes -- tcg_gen_movcond_* names its destination as a
 * plain output, so a conditional move's write is in the IR whether or not the
 * condition made it a no-op, and a consumer modelling speculative register
 * release needs to know it happened.  And writes whose value equals what was
 * already there, which are invisible to anything comparing state before and
 * after.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op-common.h"
#include "tcg/tcg-internal.h"
#include "exec/insn-dataflow.h"

/*
 * TCG's own cap on instructions per TB.  A TB cannot hold more, so the result
 * array never needs to grow and never needs to be allocated per translation.
 * A TB that somehow did would have its tail marked incomplete rather than
 * dropped, which is the direction stated in the header.
 */
#define INSN_DF_MAX_INSNS   512

/*
 * Per-translation scratch.
 *
 * It belongs to the TCGContext, which is the object whose lifetime and
 * exclusion it needs: one context per translating vCPU in system mode, and in
 * user mode the single tcg_init_ctx every guest thread shares while holding
 * the translation lock.  translator_loop() is not re-entrant on a context, so
 * one set per context is enough and none of it needs a lock of its own.
 * Keying on the context rather than the thread also makes this agree with the
 * accessor guard the plugin layer applies, which decides whether a result is
 * still readable by comparing against tcg_ctx->plugin_tb.
 *
 * It is emphatically NOT a thread-local.  At hundreds of KiB it is far too
 * large for static TLS, which is charged to every thread the process creates
 * -- vCPU, iothread, RCU, and every guest thread -- whether or not that thread
 * ever translates anything, and which glibc places INSIDE the stack allocation
 * pthread_create is handed, so a static TLS block approaching a guest thread's
 * stack size makes clone(2) fail outright.
 *
 * The generation counter is what keeps this cheap.  Clearing a provenance
 * table of TCG_MAX_TEMPS entries at the top of every TB is kilobytes of memset
 * on a path that runs for every translation in the program; stamping each
 * entry with the translation it belongs to and treating a stale stamp as empty
 * costs one comparison on first touch and nothing at all for a temp the TB
 * never uses.
 */
struct InsnDataflowScratch {
    uint32_t gen;
    uint32_t stamp[TCG_MAX_TEMPS];
    uint64_t prov[TCG_MAX_TEMPS][INSN_DF_REG_WORDS];

    InsnDataflow out[INSN_DF_MAX_INSNS];
    unsigned ninsns;
};

/*
 * The scratch for the translation in progress.
 *
 * Cached in a pointer-sized thread-local so the per-op helpers below cost a
 * load rather than a dereference chain.  insn_dataflow_extract() refreshes it
 * from tcg_ctx before anything reads it, allocating on the first translation
 * this context performs.  The read-side entry points treat a NULL scratch as
 * "nothing read", which is what a caller arriving before any translation must
 * be told.
 */
static __thread struct InsnDataflowScratch *df;

/*
 * Bind @df to the current translation context, allocating on first use.
 *
 * The generation starts at 1 and the stamps start at 0, so every provenance
 * entry reads as stale until the translation that touches it says otherwise.
 */
static void df_bind(void)
{
    struct InsnDataflowScratch *s = tcg_ctx->insn_df;

    if (unlikely(s == NULL)) {
        s = g_malloc0(sizeof(*s));
        s->gen = 1;
        tcg_ctx->insn_df = s;
    }
    df = s;
}

/* Provenance sets, in the register namespace. */
static void df_set_bit(uint64_t *set, unsigned bit)
{
    if (bit < INSN_DF_MAX_REGS) {
        set[bit / 64] |= 1ULL << (bit % 64);
    }
}

static void df_union(uint64_t *dst, const uint64_t *src)
{
    for (unsigned i = 0; i < INSN_DF_REG_WORDS; i++) {
        dst[i] |= src[i];
    }
}

/* A temp's provenance, cleared on first touch in this translation. */
static uint64_t *df_prov(size_t temp)
{
    if (df->stamp[temp] != df->gen) {
        df->stamp[temp] = df->gen;
        memset(df->prov[temp], 0, sizeof(df->prov[temp]));
    }
    return df->prov[temp];
}

/*
 * Is @ts a guest register?
 *
 * Globals occupy the first nb_globals slots of the temps array, so a global's
 * index in that array is its register number -- no lookup table, and nothing
 * to keep in step with the target's own.
 */
static bool df_is_reg(const TCGTemp *ts, unsigned *idx)
{
    TCGContext *s = tcg_ctx;
    size_t i;

    if (ts->kind != TEMP_GLOBAL) {
        return false;
    }
    i = ts - s->temps;
    if (i >= (size_t)s->nb_globals) {
        return false;
    }
    *idx = (unsigned)i;
    return true;
}

/*
 * Record a write, merging provenance if the instruction writes the register
 * more than once.
 *
 * An instruction with more destinations than there are slots is refused whole
 * rather than recorded short: the header states why, and the flag set here is
 * what the refusal is made of.
 */
static void df_add_write(InsnDataflow *d, unsigned reg, const uint64_t *prov)
{
    for (unsigned i = 0; i < d->n_writes; i++) {
        if (d->writes[i].reg == reg) {
            df_union(d->writes[i].prov, prov);
            return;
        }
    }
    if (d->n_writes >= INSN_DF_MAX_WRITES) {
        d->incomplete |= INSN_DF_INCOMPLETE_WRITES;
        return;
    }
    d->writes[d->n_writes].reg = (uint8_t)reg;
    memcpy(d->writes[d->n_writes].prov, prov, sizeof(d->writes[0].prov));
    d->n_writes++;
}

/*
 * A call's arguments and results.
 *
 * What the helper does between them is a host function, not ops, so at this
 * level it is one edge: every result depends on every argument.  That is an
 * over-approximation and it is visibly one -- n_calls says a call happened --
 * which is the pessimistic direction the header commits to.
 */
static void df_call(InsnDataflow *d, TCGOp *op)
{
    TCGContext *s = tcg_ctx;
    unsigned nb_oargs = TCGOP_CALLO(op);
    unsigned nb_iargs = TCGOP_CALLI(op);
    uint64_t prov[INSN_DF_REG_WORDS] = { 0 };
    unsigned idx;

    d->n_calls++;

    for (unsigned i = 0; i < nb_iargs; i++) {
        TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);

        if (ts == NULL) {
            continue;
        }
        df_union(prov, df_prov(ts - s->temps));
        if (df_is_reg(ts, &idx)) {
            df_set_bit(d->rd, idx);
            df_set_bit(prov, idx);
        }
    }
    for (unsigned i = 0; i < nb_oargs; i++) {
        TCGTemp *ts = arg_temp(op->args[i]);

        if (ts == NULL) {
            continue;
        }
        if (df_is_reg(ts, &idx)) {
            df_set_bit(d->wr, idx);
            df_add_write(d, idx, prov);
        } else {
            df_union(df_prov(ts - s->temps), prov);
        }
    }
}

/* Walk one instruction's ops: [first, end). */
static void df_insn(InsnDataflow *d, TCGOp *first, TCGOp *end)
{
    TCGContext *s = tcg_ctx;

    for (TCGOp *op = first; op != end; op = QTAILQ_NEXT(op, link)) {
        const TCGOpDef *def = &tcg_op_defs[op->opc];
        uint64_t prov[INSN_DF_REG_WORDS] = { 0 };
        unsigned nb_oargs, nb_iargs, idx;

        switch (op->opc) {
        case INDEX_op_insn_start:
            continue;

        case INDEX_op_call:
            df_call(d, op);
            continue;

        case INDEX_op_discard:
            /*
             * discard names its argument as an output but is not a write: it
             * is TCG being told the temp's value is dead, which on x86 is how
             * the flag fields an instruction does not define are retired.
             * Counting it as a write would put cc_src2 in the write set of
             * every add.
             */
            {
                TCGTemp *ts = arg_temp(op->args[0]);

                if (ts != NULL && df_is_reg(ts, &idx)) {
                    df_set_bit(d->kill, idx);
                }
            }
            continue;

        case INDEX_op_qemu_ld_i32:
        case INDEX_op_qemu_ld_i64:
        case INDEX_op_qemu_ld_i128:
            d->n_mem_rd++;
            break;

        case INDEX_op_qemu_st_i32:
        case INDEX_op_qemu_st_i64:
        case INDEX_op_qemu_st8_i32:
        case INDEX_op_qemu_st_i128:
            d->n_mem_wr++;
            break;

        default:
            break;
        }

        nb_oargs = def->nb_oargs;
        nb_iargs = def->nb_iargs;

        for (unsigned i = 0; i < nb_iargs; i++) {
            TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);

            if (ts == NULL) {
                continue;
            }
            df_union(prov, df_prov(ts - s->temps));
            if (df_is_reg(ts, &idx)) {
                df_set_bit(d->rd, idx);
                df_set_bit(prov, idx);
            }
        }

        for (unsigned i = 0; i < nb_oargs; i++) {
            TCGTemp *ts = arg_temp(op->args[i]);

            if (ts == NULL) {
                continue;
            }
            if (df_is_reg(ts, &idx)) {
                df_set_bit(d->wr, idx);
                df_add_write(d, idx, prov);
            } else {
                memcpy(df_prov(ts - s->temps), prov, sizeof(prov));
            }
        }
    }
}

void insn_dataflow_extract(unsigned num_insns)
{
    TCGContext *s = tcg_ctx;
    TCGOp *op, *first = NULL;
    unsigned idx = 0;

    df_bind();

    df->gen++;
    df->ninsns = 0;
    /*
     * TCG_MAX_INSNS is the translator's own cap, so this clamp is belt and
     * braces; an instruction past it simply has no entry, and a caller asking
     * for one is told there is no answer rather than handed a short one.
     */
    if (num_insns > INSN_DF_MAX_INSNS) {
        num_insns = INSN_DF_MAX_INSNS;
    }
    memset(df->out, 0, num_insns * sizeof(df->out[0]));

    /*
     * insn_start opens an instruction and closes the one before it, so the
     * walk always attributes ops to the marker that preceded them and the last
     * instruction is closed by the end of the op list.
     */
    QTAILQ_FOREACH(op, &s->ops, link) {
        if (op->opc != INDEX_op_insn_start) {
            continue;
        }
        if (first != NULL && idx > 0) {
            df_insn(&df->out[idx - 1], first, op);
        }
        if (idx >= num_insns) {
            first = NULL;
            break;
        }
        idx++;
        first = QTAILQ_NEXT(op, link);
    }
    if (first != NULL && idx > 0) {
        df_insn(&df->out[idx - 1], first, NULL);
    }
    df->ninsns = idx;
}

const InsnDataflow *insn_dataflow_get(unsigned i)
{
    return df != NULL && i < df->ninsns ? &df->out[i] : NULL;
}

unsigned insn_dataflow_nregs(void)
{
    return tcg_ctx->nb_globals;
}

const char *insn_dataflow_reg_name(unsigned i, uint32_t *off, uint32_t *size)
{
    TCGContext *s = tcg_ctx;
    const TCGTemp *ts;

    if (i >= (unsigned)s->nb_globals) {
        return NULL;
    }
    ts = &s->temps[i];
    if (ts->kind != TEMP_GLOBAL || ts->mem_base != tcgv_ptr_temp(tcg_env)) {
        return NULL;
    }
    if (off) {
        *off = (uint32_t)ts->mem_offset;
    }
    if (size) {
        *size = tcg_type_size(ts->base_type);
    }
    return ts->name;
}
