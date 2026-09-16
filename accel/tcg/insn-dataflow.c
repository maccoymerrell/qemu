/*
 * Per-instruction dataflow, read off the ops the target's translator emitted,
 * plus the facts the decode site states because no op carries them.
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
 * Two things the op stream alone does not give, and this file gets both:
 *
 *   State no TCG global names -- x86's vector file and x87 stack, ARM's Z
 *   registers, every FP status word -- is reached by load and store at a
 *   constant offset from tcg_env, or through a pointer built from it.  Those
 *   are followed, interned for the block, and carried as byte ranges that the
 *   target can name by declaring its own layout through the compiler.
 *
 *   Facts the emitter held and threw away -- a register an addressing fold
 *   consumed, an architectural zero register with no ops at all, a range a
 *   helper reaches that its arguments do not name -- are STATED at the site
 *   that held them.  A statement lands on the instruction being decoded, and a
 *   statement about a value is anchored to the op stream where it was made, so
 *   it cannot leak into a later use of the same temp.
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
 */
#define INSN_DF_MAX_INSNS   512

/* Statements about values, and bookkeeping windows, per translation. */
#define INSN_DF_MAX_BINDINGS  256
#define INSN_DF_MAX_WINDOWS   64

/* A temp that is not tcg_env plus a constant. */
#define INSN_DF_NOT_ENV     INT64_MIN

/*
 * A statement that a temp carries a value the ops do not name.
 *
 * @anchor is the op most recently emitted when the statement was made, so the
 * reader applies the binding at exactly that point in the stream: the temp
 * carries the atom from there on, and a later op that redefines the temp
 * overwrites it as it would any other value.
 */
typedef struct DfBinding {
    const TCGOp *anchor;        /* NULL: before this translation's first op */
    uint16_t insn;
    uint16_t temp;
    uint16_t bit;
} DfBinding;

/* A bracket around ops that are QEMU's bookkeeping, not the instruction's. */
typedef struct DfWindow {
    const TCGOp *from;          /* last op before the window opened */
    const TCGOp *to;            /* last op inside the window */
    uint16_t insn;
    uint8_t kind;
} DfWindow;

/*
 * Per-translation scratch.
 *
 * It belongs to the TCGContext, which is the object whose lifetime and
 * exclusion it needs: one context per translating vCPU in system mode, and in
 * user mode the single tcg_init_ctx every guest thread shares while holding
 * the translation lock.  translator_loop() is not re-entrant on a context, so
 * one set per context is enough and none of it needs a lock of its own.
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
    int64_t  envoff[TCG_MAX_TEMPS];

    InsnDataflow out[INSN_DF_MAX_INSNS];
    unsigned ninsns;
    unsigned cur;               /* the instruction being decoded */
    bool     decoding;          /* insn_begin seen since the last extract */

    /*
     * Env byte ranges no TCG global names, interned for the block so they can
     * carry provenance bits alongside the globals.  A block touches very few
     * distinct ones; running out stops interning, which is recorded rather
     * than hidden -- a range that could not be interned makes a value look as
     * though it came from nowhere, and that is the direction this file does
     * not take quietly.
     */
    uint32_t slot_off[INSN_DF_MAX_FIELD_SLOTS];
    uint32_t slot_size[INSN_DF_MAX_FIELD_SLOTS];
    unsigned nslots;
    bool     slots_full;

    DfBinding bind[INSN_DF_MAX_BINDINGS];
    unsigned nbind;

    DfWindow win[INSN_DF_MAX_WINDOWS];
    unsigned nwin;
    int      win_open;          /* index of the window awaiting its end, or -1 */
};

/*
 * The scratch for the translation in progress.
 *
 * Cached in a pointer-sized thread-local so the per-op helpers below cost a
 * load rather than a dereference chain.  df_bind() refreshes it from tcg_ctx,
 * allocating on the first translation this context performs.  The read-side
 * entry points treat a NULL scratch as "nothing read", which is what a caller
 * arriving before any translation must be told.
 */
static __thread struct InsnDataflowScratch *df;

/*
 * Register files a target declared out of CPUArchState.
 *
 * Process-global because a QEMU binary emulates one target, and the
 * declaration is a property of that target's structure rather than of any
 * translation.  Declared once at target init; read afterwards.
 */
typedef struct DfRegfile {
    const char *const *names;
    unsigned count;
    uint32_t base_off;
    uint32_t stride;
    uint32_t size;
} DfRegfile;

#define INSN_DF_MAX_REGFILES 16

static DfRegfile df_regfiles[INSN_DF_MAX_REGFILES];
static unsigned df_nregfiles;

/*
 * Bind @df to the current translation context, allocating on first use.
 *
 * The generation starts at 1 and the stamps start at 0, so every provenance
 * entry reads as stale until the translation that touches it says otherwise.
 */
static void df_attach(void)
{
    struct InsnDataflowScratch *s = tcg_ctx->insn_df;

    if (unlikely(s == NULL)) {
        s = g_malloc0(sizeof(*s));
        s->gen = 1;
        s->win_open = -1;
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

static bool df_empty(const uint64_t *set)
{
    for (unsigned i = 0; i < INSN_DF_REG_WORDS; i++) {
        if (set[i]) {
            return false;
        }
    }
    return true;
}

static void df_union(uint64_t *dst, const uint64_t *src)
{
    for (unsigned i = 0; i < INSN_DF_REG_WORDS; i++) {
        dst[i] |= src[i];
    }
}

/* A temp's per-translation state, cleared on first touch. */
static void df_touch(size_t temp)
{
    if (df->stamp[temp] != df->gen) {
        df->stamp[temp] = df->gen;
        memset(df->prov[temp], 0, sizeof(df->prov[temp]));
        df->envoff[temp] = INSN_DF_NOT_ENV;
    }
}

static uint64_t *df_prov(size_t temp)
{
    df_touch(temp);
    return df->prov[temp];
}

static int64_t df_envoff(size_t temp)
{
    df_touch(temp);
    return df->envoff[temp];
}

static void df_set_envoff(size_t temp, int64_t v)
{
    df_touch(temp);
    df->envoff[temp] = v;
}

/*
 * Give an env byte range a provenance bit, above the globals and below the
 * three atoms at the top.
 *
 * Interning keys on the offset AND the extent: a 16-byte vector register and
 * the 4-byte word at its base are different storage and a consumer that
 * conflated them would see a dependency between instructions that share only
 * an address.  When the table is full this returns -1, the caller records
 * nothing, and slots_full says so -- a value whose source could not be
 * interned looks as though it came from nowhere, which is the one direction
 * this file does not take in silence.
 */
static int df_intern(uint32_t off, uint32_t size)
{
    unsigned base = tcg_ctx->nb_globals;

    for (unsigned i = 0; i < df->nslots; i++) {
        if (df->slot_off[i] == off && df->slot_size[i] == size) {
            return (int)(base + i);
        }
    }
    if (df->nslots >= INSN_DF_MAX_FIELD_SLOTS ||
        base + df->nslots >= INSN_DF_BIT_LOWEST_ATOM) {
        df->slots_full = true;
        return -1;
    }
    df->slot_off[df->nslots] = off;
    df->slot_size[df->nslots] = size;
    return (int)(base + df->nslots++);
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

/* The TCG global of this name, or -1. */
static int df_global_by_name(const char *name)
{
    TCGContext *s = tcg_ctx;

    for (unsigned i = 0; i < (unsigned)s->nb_globals; i++) {
        const TCGTemp *ts = &s->temps[i];

        if (ts->name && !strcmp(ts->name, name)) {
            return (int)i;
        }
    }
    return -1;
}

/* The declared env range of this name, or false. */
static bool df_declared_by_name(const char *name, uint32_t *off, uint32_t *size)
{
    for (unsigned f = 0; f < df_nregfiles; f++) {
        const DfRegfile *rf = &df_regfiles[f];

        for (unsigned i = 0; i < rf->count; i++) {
            if (rf->names[i] && !strcmp(rf->names[i], name)) {
                *off = rf->base_off + i * rf->stride;
                *size = rf->size;
                return true;
            }
        }
    }
    return false;
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
 * Record an access to an env byte range, and for a write, where its value came
 * from.
 *
 * The concrete case that made the provenance rule worth writing down: giving a
 * field write an empty provenance because field READS were not tracked would
 * have reported psubb %xmm2,%xmm2 as breaking its dependency chain, which it
 * does not -- a missed dependency, arrived at by a change that looked like a
 * simplification.
 */
static void df_add_field(InsnDataflow *d, uint32_t off, uint32_t size,
                         uint8_t dir, const uint64_t *prov)
{
    for (unsigned i = 0; i < d->n_fields; i++) {
        if (d->fields[i].off == off && d->fields[i].size == size) {
            d->fields[i].dir |= dir;
            if (prov) {
                df_union(d->fields[i].prov, prov);
            }
            return;
        }
    }
    if (d->n_fields >= INSN_DF_MAX_FIELDS) {
        d->incomplete |= INSN_DF_INCOMPLETE_FIELDS;
        return;
    }
    d->fields[d->n_fields].off = off;
    d->fields[d->n_fields].size = size;
    d->fields[d->n_fields].dir = dir;
    memset(d->fields[d->n_fields].prov, 0,
           sizeof(d->fields[d->n_fields].prov));
    if (prov) {
        memcpy(d->fields[d->n_fields].prov, prov,
               sizeof(d->fields[d->n_fields].prov));
    }
    d->n_fields++;
}

/* Direct env access: a load or a store of how many bytes? */
static bool df_ldst(const TCGOp *op, bool *store, uint32_t *size)
{
    switch (op->opc) {
    case INDEX_op_ld8u_i32: case INDEX_op_ld8s_i32:
    case INDEX_op_ld8u_i64: case INDEX_op_ld8s_i64:
        *store = false; *size = 1; return true;
    case INDEX_op_ld16u_i32: case INDEX_op_ld16s_i32:
    case INDEX_op_ld16u_i64: case INDEX_op_ld16s_i64:
        *store = false; *size = 2; return true;
    case INDEX_op_ld_i32:
    case INDEX_op_ld32u_i64: case INDEX_op_ld32s_i64:
        *store = false; *size = 4; return true;
    case INDEX_op_ld_i64:
        *store = false; *size = 8; return true;
    case INDEX_op_ld_vec:
        *store = false; *size = tcg_type_size(TCGOP_TYPE(op)); return true;
    case INDEX_op_st8_i32: case INDEX_op_st8_i64:
        *store = true; *size = 1; return true;
    case INDEX_op_st16_i32: case INDEX_op_st16_i64:
        *store = true; *size = 2; return true;
    case INDEX_op_st_i32: case INDEX_op_st32_i64:
        *store = true; *size = 4; return true;
    case INDEX_op_st_i64:
        *store = true; *size = 8; return true;
    case INDEX_op_st_vec:
        *store = true; *size = tcg_type_size(TCGOP_TYPE(op)); return true;
    default:
        return false;
    }
}

/*
 * A call's arguments and results.
 *
 * What the helper does between them is a host function, not ops, so at this
 * level it is one edge: every result depends on every argument.  That is an
 * over-approximation and it is visibly one -- n_calls says a call happened --
 * which is the pessimistic direction the header commits to.
 *
 * A pointer into env is how a vector register reaches a gvec helper.  The
 * argument does not say whether the helper reads or writes through it, so the
 * range is recorded as both: an over-approximation the consumer can see is
 * one, rather than a guess that looks like a fact.  tcg_env itself does not
 * count -- it is the first argument of nearly every helper there is.
 */
static void df_call(InsnDataflow *d, TCGOp *op)
{
    TCGContext *s = tcg_ctx;
    TCGTemp *env_ts = tcgv_ptr_temp(tcg_env);
    unsigned nb_oargs = TCGOP_CALLO(op);
    unsigned nb_iargs = TCGOP_CALLI(op);
    uint64_t prov[INSN_DF_REG_WORDS] = { 0 };
    unsigned idx;

    d->n_calls++;

    for (unsigned i = 0; i < nb_iargs; i++) {
        TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);
        int64_t eo;

        if (ts == NULL) {
            continue;
        }
        df_union(prov, df_prov(ts - s->temps));
        if (df_is_reg(ts, &idx)) {
            df_set_bit(d->rd, idx);
            df_set_bit(prov, idx);
        }
        if (ts == env_ts) {
            continue;
        }
        eo = df_envoff(ts - s->temps);
        if (eo != INSN_DF_NOT_ENV && eo >= 0) {
            int bit = df_intern((uint32_t)eo, DF_FIELD_UNBOUNDED);

            if (bit >= 0) {
                df_set_bit(prov, (unsigned)bit);
            }
            df_add_field(d, (uint32_t)eo, DF_FIELD_UNBOUNDED,
                         INSN_DF_RD | INSN_DF_WR, prov);
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

/* One op, attributed to instruction @d. */
static void df_op(InsnDataflow *d, TCGOp *op)
{
    TCGContext *s = tcg_ctx;
    TCGTemp *env_ts = tcgv_ptr_temp(tcg_env);
    const TCGOpDef *def = &tcg_op_defs[op->opc];
    uint64_t prov[INSN_DF_REG_WORDS] = { 0 };
    unsigned nb_oargs, nb_iargs, idx;
    int ld_field_bit = -1;
    bool store;
    uint32_t size;

    switch (op->opc) {
    case INDEX_op_call:
        df_call(d, op);
        return;

    case INDEX_op_discard:
        /*
         * discard names its argument as an output but is not a write: it is
         * TCG being told the temp's value is dead, which on x86 is how the
         * flag fields an instruction does not define are retired.  Counting it
         * as a write would put cc_src2 in the write set of every add.
         */
        {
            TCGTemp *ts = arg_temp(op->args[0]);

            if (ts == NULL) {
                return;
            }
            if (df_is_reg(ts, &idx)) {
                df_set_bit(d->kill, idx);
            } else {
                df_set_envoff(ts - s->temps, INSN_DF_NOT_ENV);
            }
        }
        return;

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

    /* State reached at a constant offset from tcg_env. */
    if (df_ldst(op, &store, &size)) {
        TCGTemp *bts = arg_temp(op->args[1]);
        int64_t bo = bts == env_ts ? 0 : df_envoff(bts - s->temps);

        if (bo != INSN_DF_NOT_ENV) {
            int64_t eo = bo + (int64_t)op->args[2];

            if (eo >= 0) {
                if (store) {
                    /*
                     * The value's provenance is the range's provenance: this
                     * is where a vector register's write gets the same account
                     * of itself a GPR's write already had.
                     */
                    TCGTemp *vts = arg_temp(op->args[0]);

                    df_add_field(d, (uint32_t)eo, size, INSN_DF_WR,
                                 df_prov(vts - s->temps));
                } else {
                    df_add_field(d, (uint32_t)eo, size, INSN_DF_RD, NULL);
                    ld_field_bit = df_intern((uint32_t)eo, size);
                }
            }
        }
    }

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
            uint64_t *dp = df_prov(ts - s->temps);

            memcpy(dp, prov, sizeof(prov));
            /*
             * A load's value came from the range it loaded, which the op's own
             * inputs do not say -- they name the base pointer.  Without this a
             * value read out of the vector file looks as though it came from
             * nowhere, and every instruction operating on it would report a
             * broken dependency chain it does not have.
             */
            if (ld_field_bit >= 0) {
                df_set_bit(dp, (unsigned)ld_field_bit);
            }
        }
    }

    /*
     * Track temps whose value is tcg_env plus a constant.  Only mov and
     * add-of-a-constant can produce one; anything else writing a tracked temp
     * stops tracking it, so the map never outlives the fact.
     */
    if (nb_oargs == 1) {
        TCGTemp *dts = arg_temp(op->args[0]);
        int64_t v = INSN_DF_NOT_ENV;

        if (dts == NULL) {
            return;
        }
        if (op->opc == INDEX_op_mov_i64 || op->opc == INDEX_op_mov_i32) {
            TCGTemp *a = arg_temp(op->args[1]);

            v = a == env_ts ? 0 : df_envoff(a - s->temps);
        } else if (op->opc == INDEX_op_add_i64 || op->opc == INDEX_op_add_i32) {
            TCGTemp *a = arg_temp(op->args[1]);
            TCGTemp *b = arg_temp(op->args[2]);
            int64_t ao = a == env_ts ? 0 : df_envoff(a - s->temps);
            int64_t bo = b == env_ts ? 0 : df_envoff(b - s->temps);

            if (ao != INSN_DF_NOT_ENV && b->kind == TEMP_CONST) {
                v = ao + b->val;
            } else if (bo != INSN_DF_NOT_ENV && a->kind == TEMP_CONST) {
                v = bo + a->val;
            }
        }
        df_set_envoff(dts - s->temps, v);
    }
}

/*
 * The statement side: what a decode site says because no op says it.
 */

/* The provenance bit an atom stands for, or -1 if it has none. */
static int df_atom_bit(InsnDataflowAtom a)
{
    uint32_t off, size;
    int g;

    switch (a.kind) {
    case INSN_DF_A_ZERO:
        return INSN_DF_BIT_ZERO;
    case INSN_DF_A_IMM:
        return INSN_DF_BIT_IMM;
    case INSN_DF_A_CONST:
        return INSN_DF_BIT_CONST;
    case INSN_DF_A_ENV:
        return df_intern(a.off, a.size);
    case INSN_DF_A_REG:
        if (a.name == NULL) {
            return -1;
        }
        g = df_global_by_name(a.name);
        if (g >= 0) {
            return g;
        }
        if (df_declared_by_name(a.name, &off, &size)) {
            return df_intern(off, size);
        }
        return -1;
    default:
        return -1;
    }
}

/*
 * A stated access, in whichever of the two shapes the atom resolves to.
 *
 * A stated WRITE arrives with no account of where its value came from, and an
 * empty provenance is not a neutral answer -- it asserts a broken dependency
 * chain.  So the write is marked and filled at the end of the translation with
 * the instruction's own read set: pessimistic, visible as such, and never a
 * dependency invented or a dependency dropped.
 */
static void df_state(InsnDataflowAtom a, uint8_t dir)
{
    InsnDataflow *d;
    uint32_t off, size;
    int g;

    if (df == NULL || !df->decoding) {
        return;
    }
    d = &df->out[df->cur];

    switch (a.kind) {
    case INSN_DF_A_ZERO:
        df_set_bit(dir == INSN_DF_RD ? d->rd : d->wr, INSN_DF_BIT_ZERO);
        return;

    case INSN_DF_A_ENV:
        df_add_field(d, a.off, a.size, dir, NULL);
        return;

    case INSN_DF_A_REG:
        if (a.name == NULL) {
            return;
        }
        g = df_global_by_name(a.name);
        if (g >= 0) {
            if (dir == INSN_DF_RD) {
                df_set_bit(d->rd, (unsigned)g);
            } else {
                uint64_t none[INSN_DF_REG_WORDS] = { 0 };

                df_set_bit(d->wr, (unsigned)g);
                df_add_write(d, (unsigned)g, none);
            }
            return;
        }
        if (df_declared_by_name(a.name, &off, &size)) {
            df_add_field(d, off, size, dir, NULL);
        }
        return;

    default:
        /*
         * An immediate or a constant is a property of a value, not an access:
         * an instruction does not read storage by reading its own encoding.
         * Those atoms reach the wire through insn_dataflow_bind() instead.
         */
        return;
    }
}

void insn_dataflow_state_read(InsnDataflowAtom a)
{
    df_state(a, INSN_DF_RD);
}

void insn_dataflow_state_write(InsnDataflowAtom a)
{
    df_state(a, INSN_DF_WR);
}

void insn_dataflow_bind(const void *ts, InsnDataflowAtom a)
{
    const TCGTemp *t = ts;
    size_t temp;
    int bit;

    if (df == NULL || !df->decoding || t == NULL) {
        return;
    }
    temp = t - tcg_ctx->temps;
    if (temp >= TCG_MAX_TEMPS) {
        return;
    }
    bit = df_atom_bit(a);
    if (bit < 0 || df->nbind >= INSN_DF_MAX_BINDINGS) {
        /*
         * Either the atom named nothing this build knows, or the block has
         * made more statements about values than there is room for.  Both drop
         * a source rather than invent one, and both are visible: an unnamed
         * atom is a decode site naming a register the target never registered
         * or declared, which is a bug in the statement and not in the reader.
         */
        return;
    }
    df->bind[df->nbind].anchor = tcg_last_op();
    df->bind[df->nbind].insn = df->cur;
    df->bind[df->nbind].temp = temp;
    df->bind[df->nbind].bit = (uint16_t)bit;
    df->nbind++;
}

void insn_dataflow_window_begin(unsigned kind)
{
    if (df == NULL || !df->decoding || df->nwin >= INSN_DF_MAX_WINDOWS ||
        df->win_open >= 0) {
        return;
    }
    df->win[df->nwin].from = tcg_last_op();
    df->win[df->nwin].to = NULL;
    df->win[df->nwin].insn = df->cur;
    df->win[df->nwin].kind = (uint8_t)kind;
    df->win_open = (int)df->nwin;
    df->nwin++;
}

void insn_dataflow_window_end(void)
{
    if (df == NULL || df->win_open < 0) {
        return;
    }
    df->win[df->win_open].to = tcg_last_op();
    df->win_open = -1;
}

void insn_dataflow_declare_regfile(const char *const *names, unsigned count,
                                   uint32_t base_off, uint32_t stride,
                                   uint32_t size)
{
    DfRegfile *rf;

    if (df_nregfiles >= INSN_DF_MAX_REGFILES || names == NULL || count == 0) {
        return;
    }
    rf = &df_regfiles[df_nregfiles++];
    rf->names = names;
    rf->count = count;
    rf->base_off = base_off;
    rf->stride = stride;
    rf->size = size;
}

void insn_dataflow_insn_begin(unsigned idx)
{
    df_attach();

    if (idx == 0) {
        df->gen++;
        df->nslots = 0;
        df->slots_full = false;
        df->nbind = 0;
        df->nwin = 0;
        df->win_open = -1;
        df->ninsns = 0;
    }
    if (idx >= INSN_DF_MAX_INSNS) {
        df->decoding = false;
        return;
    }
    memset(&df->out[idx], 0, sizeof(df->out[idx]));
    df->cur = idx;
    df->decoding = true;
}

/*
 * Fill in the writes whose value had no stated source with the instruction's
 * read set.  Runs after the op walk, which is the first moment that set is
 * complete.
 */
static void df_close_unsourced(InsnDataflow *d)
{
    for (unsigned i = 0; i < d->n_writes; i++) {
        if (df_empty(d->writes[i].prov)) {
            df_union(d->writes[i].prov, d->rd);
        }
    }
    for (unsigned i = 0; i < d->n_fields; i++) {
        if ((d->fields[i].dir & INSN_DF_WR) && df_empty(d->fields[i].prov)) {
            df_union(d->fields[i].prov, d->rd);
        }
    }
}

void insn_dataflow_extract(unsigned num_insns)
{
    TCGContext *s = tcg_ctx;
    const TCGOp *prev = NULL;
    const TCGOp *win_to = NULL;
    TCGOp *op;
    unsigned wi = 0, bi = 0;
    int idx = -1;

    if (df == NULL) {
        return;
    }
    df->decoding = false;
    if (num_insns > INSN_DF_MAX_INSNS) {
        num_insns = INSN_DF_MAX_INSNS;
    }

    /*
     * One pass, in emission order, which is what makes the statements cheap to
     * place: windows and bindings were recorded in that same order, so a
     * cursor over each is enough and no op ever needs to be searched for.
     *
     * A statement whose instruction index is at or above @num_insns belongs to
     * an instruction the translator rewound off the end of the block (a
     * never-split retreat), and its anchor op no longer exists.  Those are
     * skipped by index rather than by pointer: the op was freed, and a later
     * op allocated at the same address would otherwise match it.
     */
    QTAILQ_FOREACH(op, &s->ops, link) {
        /*
         * Both cursors fire on the op the statement was anchored TO, and fire
         * before this op is read: a binding made after op X describes the
         * temp's value from X onwards, and a window opened after X covers the
         * ops from here.
         */
        while (wi < df->nwin && df->win[wi].from == prev) {
            const DfWindow *w = &df->win[wi];

            /*
             * A window with no end, or one that closed without an op inside
             * it, covers nothing.  Opening it anyway would swallow the rest of
             * the block, because nothing later would ever match its end.
             */
            if (w->insn < num_insns && win_to == NULL &&
                w->to != NULL && w->to != w->from) {
                win_to = w->to;
            }
            wi++;
        }
        while (bi < df->nbind && df->bind[bi].anchor == prev) {
            if (df->bind[bi].insn < num_insns) {
                df_set_bit(df_prov(df->bind[bi].temp), df->bind[bi].bit);
            }
            bi++;
        }

        if (op->opc == INDEX_op_insn_start) {
            idx++;
            prev = op;
            continue;
        }

        if (idx >= 0 && (unsigned)idx < num_insns && win_to == NULL) {
            df_op(&df->out[idx], op);
        }
        if (win_to == op) {
            win_to = NULL;
        }
        prev = op;
    }

    df->ninsns = idx < 0 ? 0 : MIN((unsigned)idx + 1, num_insns);
    for (unsigned i = 0; i < df->ninsns; i++) {
        df_close_unsourced(&df->out[i]);
    }
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

bool insn_dataflow_prov_field(unsigned bit, uint32_t *off, uint32_t *size)
{
    unsigned base = tcg_ctx->nb_globals;

    if (df == NULL || bit < base || bit - base >= df->nslots) {
        return false;
    }
    if (off) {
        *off = df->slot_off[bit - base];
    }
    if (size) {
        *size = df->slot_size[bit - base];
    }
    return true;
}

const char *insn_dataflow_field_reg(uint32_t off, uint32_t size)
{
    for (unsigned f = 0; f < df_nregfiles; f++) {
        const DfRegfile *rf = &df_regfiles[f];
        uint32_t rel, i;

        if (off < rf->base_off || rf->stride == 0) {
            continue;
        }
        rel = off - rf->base_off;
        i = rel / rf->stride;
        if (i >= rf->count || rel % rf->stride != 0) {
            continue;
        }
        /*
         * An access narrower than the register is still that register: a
         * 4-byte load out of a 16-byte vector reads part of it, and naming the
         * container is the whole point of the declaration.  An access WIDER
         * than the register is not, and is left unnamed rather than
         * misattributed.
         */
        if (size != DF_FIELD_UNBOUNDED && size > rf->size) {
            continue;
        }
        return rf->names[i];
    }
    return NULL;
}

bool insn_dataflow_fields_truncated(void)
{
    return df != NULL && df->slots_full;
}
