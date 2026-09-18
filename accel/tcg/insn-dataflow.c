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
#include "exec/memopidx.h"
#include "exec/insn-dataflow.h"
#include "qemu/error-report.h"

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

/*
 * A preserve-read note, anchored the same way a binding is.
 *
 * The anchor is what makes the note honest.  The reader walks ops in emission
 * order, so a note that applied to the whole instruction would suppress a
 * read that happened BEFORE it: `mov.s $f0,$f0` loads f0 as its operand and
 * then merges into f0, and an unanchored note deleted the operand read as
 * well as the merge's.  MEASURED, and the reason this field exists: the
 * mipsel static register-set check reported 32 encodings whose source the
 * referee named and the wire did not, all of them fd == fs.
 */
typedef struct DfPreserve {
    const TCGOp *anchor;        /* NULL: before this translation's first op */
    uint16_t insn;
    uint16_t bit;
} DfPreserve;

/* A bracket around ops that are QEMU's bookkeeping, not the instruction's. */
/*
 * A bracket around ops that are not the decoding instruction's own.
 *
 * @kind says what to do with them: the bookkeeping kinds are left out of every
 * instruction, and the borrow kind moves them to instruction @arg -- the
 * branch whose transfer its delay slot's op range happens to contain.
 */
#define DF_W_BORROW  0xff

typedef struct DfWindow {
    const TCGOp *from;          /* last op before the window opened */
    const TCGOp *to;            /* last op inside the window */
    uint16_t insn;
    uint16_t arg;               /* DF_W_BORROW: the lending instruction */
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

    /*
     * Is this temp's provenance KNOWN INCOMPLETE?
     *
     * The interning table below is per BLOCK, so the instruction that fills it
     * is not necessarily the instruction that loses a source: a range that
     * could not be interned gives the value read out of it an account with a
     * member missing, and that value then travels through temps into whatever
     * reads it next.  Carrying the fact on the VALUE is what lets the reader
     * say which instructions actually lost something -- one bit per temp,
     * unioned along the same edges the provenance sets are, and cleared when
     * an op writes the temp a fresh value.
     *
     * The alternative, a block-wide flag, is what this replaces, and it was
     * wrong in the only direction that matters: an instruction WALKED BEFORE
     * the table filled cannot have lost anything to it -- ops are read in
     * emission order, which is program order -- yet a block-wide flag
     * convicted it anyway, and a consumer that refuses a set on any
     * incompleteness then dropped that instruction's whole dependency block.
     */
    bool     trunc[TCG_MAX_TEMPS];

    InsnDataflow out[INSN_DF_MAX_INSNS];
    unsigned ninsns;
    unsigned cur;               /* the instruction being decoded */
    bool     decoding;          /* insn_begin seen since the last extract */

    /*
     * Globals whose next read is a PRESERVE READ, per instruction.
     *
     * R7.1: a narrow write does not acquire a source.  When a target has to
     * write part of a register it lowers the write as a read-modify-write of
     * the whole one, and the read of the container that merge performs is the
     * lowering's, not the instruction's -- the instruction did not take that
     * register as an operand, and a consumer handed it as a source sees a
     * read-after-write edge the machine does not have.
     *
     * Kept HERE rather than in InsnDataflow because it is scratch the reader
     * consumes, not a fact the wire publishes: adding a field to the published
     * per-instruction record would move the plugin ABI for a bitmap no
     * consumer ever sees.
     *
     * NOTED at the decode site against the op most recently emitted, ARMED
     * when the walk reaches that op, consumed by df_read_global(), and cleared
     * when an op writes the register -- which is the merge landing.  The two
     * ends together bound the note to the one merge it was made about: an
     * operand read earlier in the same instruction is before the anchor, and
     * anything after the merge is past the clear.
     */
    uint64_t preserve[INSN_DF_MAX_INSNS][INSN_DF_REG_WORDS];

    /*
     * Env byte ranges no TCG global names, interned for the block so they can
     * carry provenance bits alongside the globals.  A block touches very few
     * distinct ones; running out stops interning, which is recorded rather
     * than hidden -- a range that could not be interned makes a value look as
     * though it came from nowhere, and that is the direction this file does
     * not take quietly.  Where it is recorded is @trunc above, on the value,
     * and from there in the incompleteness of the instructions that read it.
     */
    uint32_t slot_off[INSN_DF_MAX_FIELD_SLOTS];
    uint32_t slot_size[INSN_DF_MAX_FIELD_SLOTS];
    unsigned nslots;

    DfBinding bind[INSN_DF_MAX_BINDINGS];
    unsigned nbind;

    DfPreserve pres[INSN_DF_MAX_BINDINGS];
    unsigned npres;

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

static bool df_test_bit(const uint64_t *set, unsigned bit)
{
    return bit < INSN_DF_MAX_REGS &&
           (set[bit / 64] & (1ULL << (bit % 64))) != 0;
}

static void df_clear_bit(uint64_t *set, unsigned bit)
{
    if (bit < INSN_DF_MAX_REGS) {
        set[bit / 64] &= ~(1ULL << (bit % 64));
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
        df->trunc[temp] = false;
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

/* Is this temp's account of itself known to be missing a member? */
static bool df_trunc(size_t temp)
{
    df_touch(temp);
    return df->trunc[temp];
}

static void df_set_trunc(size_t temp, bool v)
{
    df_touch(temp);
    df->trunc[temp] = v;
}

/*
 * The declared register an env byte range lies inside, at the register's own
 * offset and extent.  False when no declaration contains it.
 *
 * A DE-INTERLEAVING VECTOR ACCESS REACHES ONE REGISTER A BYTE AT A TIME.
 * aarch64 `ld4 {v20.16b-v23.16b}` writes sixty-four one-byte ranges and `st4`
 * reads sixty-four, because the elements of the structure are interleaved in
 * memory and the lowering cannot promote them to wider accesses the way the
 * contiguous `ld1` forms are promoted.  Every one of those is a distinct
 * (offset, extent) key.
 *
 * Keyed that way one instruction exhausts the block's interning table, and
 * from then on every value any LATER instruction reads out of env is handed
 * an account missing its one real member -- so the later instruction is
 * incomplete too, and the reader hands back nothing for either.
 *
 * A range inside a declared register resolves to that register and to nothing
 * finer.  insn_dataflow_field_reg() already answers the container for any
 * offset inside it, and that name is the whole of what this layer's consumers
 * receive from a field row: the register, and the direction.  So the
 * container is the key.  What it costs is the byte WITHIN the register, which
 * no reader of this layer asks for; what it buys is that sixty-four keys are
 * four.  A range no declaration contains -- a status word, a lazy-flag field,
 * anything the target did not declare as a file -- keeps its exact extent,
 * because there is no coarser answer that is still a register.
 */
static bool df_container(uint32_t off, uint32_t size,
                         uint32_t *cont_off, uint32_t *cont_size)
{
    if (size == 0 || size == DF_FIELD_UNBOUNDED) {
        return false;
    }
    for (unsigned f = 0; f < df_nregfiles; f++) {
        const DfRegfile *rf = &df_regfiles[f];
        uint32_t rel, i;

        if (off < rf->base_off || rf->stride == 0) {
            continue;
        }
        rel = off - rf->base_off;
        i = rel / rf->stride;
        if (i >= rf->count) {
            continue;
        }
        rel %= rf->stride;
        if (rel + (uint64_t)size > rf->size) {
            continue;
        }
        *cont_off = rf->base_off + i * rf->stride;
        *cont_size = rf->size;
        return true;
    }
    return false;
}

/*
 * Give an env byte range a provenance bit, above the globals and below the
 * three atoms at the top.
 *
 * Interning keys on the offset AND the extent, CANONICALISED to the declared
 * register that contains the range (see df_container): a 16-byte vector
 * register and the 4-byte word at its base are the same storage and want one
 * bit, while two ranges no declaration contains are different storage and a
 * consumer that conflated them would see a dependency between instructions
 * that share only an address.  When the table is full this returns -1 and the
 * caller records nothing -- a value whose source could not be interned looks
 * as though it came from nowhere, which is the one direction this file does
 * not take in silence.  Saying so is the CALLER'S job, because only the
 * caller knows which value lost the member, and the table is shared by the
 * whole block while the answer is owed per instruction.
 */
static int df_intern(uint32_t off, uint32_t size)
{
    unsigned base = tcg_ctx->nb_globals;
    uint32_t c_off, c_size;

    if (df_container(off, size, &c_off, &c_size)) {
        off = c_off;
        size = c_size;
    }

    for (unsigned i = 0; i < df->nslots; i++) {
        if (df->slot_off[i] == off && df->slot_size[i] == size) {
            return (int)(base + i);
        }
    }
    if (df->nslots >= INSN_DF_MAX_FIELD_SLOTS ||
        base + df->nslots >= INSN_DF_BIT_LOWEST_ATOM) {
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
static void df_add_write(InsnDataflow *d, unsigned reg, const uint64_t *prov,
                         bool sourced, bool from_loads)
{
    for (unsigned i = 0; i < d->n_writes; i++) {
        if (d->writes[i].reg == reg) {
            df_union(d->writes[i].prov, prov);
            d->writes[i].sourced |= sourced;
            d->writes[i].from_loads |= from_loads;
            return;
        }
    }
    if (d->n_writes >= INSN_DF_MAX_WRITES) {
        d->incomplete |= INSN_DF_INCOMPLETE_WRITES;
        return;
    }
    d->writes[d->n_writes].reg = (uint8_t)reg;
    memcpy(d->writes[d->n_writes].prov, prov, sizeof(d->writes[0].prov));
    d->writes[d->n_writes].sourced = sourced;
    d->writes[d->n_writes].from_loads = from_loads;
    d->n_writes++;
}

/*
 * A GLOBAL THIS INSTRUCTION'S OWN OPS HAVE ALREADY WRITTEN IS NOT AN INPUT.
 *
 * TCG globals are two things at once: the storage a target's registers live
 * in, and a convenient place for a lowering to park an intermediate.  Reading
 * one back inside the same instruction therefore has two possible meanings,
 * and only one of them is an architectural read.
 *
 *   `ldp w0,w1,[x2]` loads 64 bits INTO w0 and then extracts the two halves
 *   back out of it.  w0 at that moment holds the datum the load returned, not
 *   the value the program left in w0, so naming w0 as a source published a
 *   read-after-write edge on a register the instruction never read -- and the
 *   load's own datum, which is what both halves actually depend on, reached
 *   neither destination.
 *
 *   `ldxr x0,[x1]` lands its datum in exclusive_val, a global no architecture
 *   names, and copies it out.  Naming exclusive_val gave the destination a
 *   source the wire cannot spell, so it published an empty dependency set --
 *   a load that depends on nothing.
 *
 * So a read of such a global takes the PROVENANCE OF THE WRITE instead: the
 * account of where that value came from, which is the account the consumer
 * needs.  The register is not added to the read set, for the same reason a
 * read of bytes the same call wrote is not an input.
 *
 * The test is the ops' own write bitmap and not the write SET, because a
 * decode site may state a write before any op runs, and a read after such a
 * statement is a genuine architectural read.
 */
static void df_read_global(InsnDataflow *d, unsigned idx, uint64_t *prov)
{
    if (!df_test_bit(d->opwr, idx)) {
        /*
         * A PRESERVE READ IS NOT AN INPUT (R7.1).  The decode site said this
         * read exists only to carry across the bits the instruction does not
         * modify; the register is therefore neither a source nor a
         * contributor to the merged value's account, and the merge's result
         * depends on what the instruction actually computed.
         */
        if (df_test_bit(df->preserve[d - df->out], idx)) {
            return;
        }
        df_set_bit(d->rd, idx);
        df_set_bit(prov, idx);
        return;
    }
    for (unsigned i = 0; i < d->n_writes; i++) {
        if (d->writes[i].reg == idx) {
            df_union(prov, d->writes[i].prov);
            return;
        }
    }
    /*
     * Written, but the write rows ran out before this one got recorded.  The
     * instruction is already marked INCOMPLETE_WRITES; adding the register's
     * own name here would answer the question with the one thing known to be
     * wrong, so nothing is added and the account stays short rather than
     * false.
     */
}

static void df_write_global(InsnDataflow *d, unsigned idx,
                            const uint64_t *prov)
{
    df_set_bit(d->wr, idx);
    df_set_bit(d->opwr, idx);
    /*
     * The merge has landed, so the preserve note is spent.  Bounding it to
     * the write it was made about is what keeps it from swallowing a later,
     * genuine read of the same register inside the same instruction.
     */
    df_clear_bit(df->preserve[d - df->out], idx);
    df_add_write(d, idx, prov, false, false);
    /*
     * A GLOBAL AN OP HAS JUST WRITTEN CARRIES NO INHERITED ACCOUNT.
     *
     * A decode site may bind a register atom to a global to say which
     * register a fold consumed -- aarch64's store-exclusive names the base
     * register that reached the monitor, which no op mentions.  Such a
     * binding describes the value that was there, and the next op to write
     * that global replaces the value, so the binding has to die with it or
     * it would attach to whatever comes after.  Clearing here is what bounds
     * a fold note to the value it was made about.
     */
    memset(df_prov(idx), 0, sizeof(uint64_t) * INSN_DF_REG_WORDS);
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
                         uint8_t dir, const uint64_t *prov, bool sourced,
                         bool from_loads)
{
    uint32_t c_off, c_size;

    /*
     * A READ of part of a declared register is a read of that register, and
     * the row says so at the register's own extent -- the same rule df_intern
     * keys on, for the same reason: aarch64 `st4 {v20.16b-v23.16b}` reads
     * sixty-four one-byte ranges out of four registers, and sixty-four rows
     * do not fit in sixteen while four do.
     *
     * THE WRITE SIDE KEEPS ITS EXACT EXTENT.  df_env_writes_cover() decides
     * from these rows whether a read inside the same instruction came out of
     * a write the instruction itself made, and answers with the write's
     * account instead of naming the range as a source.  A write row widened
     * to its whole register would answer yes for bytes the instruction never
     * wrote, and the source that read really had would vanish -- a dependency
     * missed, which is the direction this file does not take.  So the
     * canonical form is the read's alone.
     */
    if (dir == INSN_DF_RD && df_container(off, size, &c_off, &c_size)) {
        off = c_off;
        size = c_size;
    }

    for (unsigned i = 0; i < d->n_fields; i++) {
        if (d->fields[i].off == off && d->fields[i].size == size) {
            d->fields[i].dir |= dir;
            d->fields[i].sourced |= sourced;
            d->fields[i].from_loads |= from_loads;
            if (prov) {
                df_union(d->fields[i].prov, prov);
            }
            return;
        }
    }

    /*
     * TWO WRITES THAT TOUCH ARE ONE WRITE, AND THIS IS EXACT.
     *
     * `ld4 {v20.16b-v23.16b}' writes its four destinations one byte at a
     * time -- sixty-four rows against sixteen slots -- and the same shape
     * reaches any register a lowering fills piecewise.  Merging two adjacent
     * WRITE rows of one declared register gives a row covering exactly the
     * bytes those two covered: df_env_writes_cover() answers identically for
     * every offset, so the rule the write side exists to serve is untouched.
     *
     * WHY THE MERGE IS THIS NARROW.  The write row carries an account of
     * where its bytes came from, and merging rows with DIFFERENT accounts
     * would hand a later read inside the same instruction the union instead
     * of the bytes' own source -- a source it did not have.  So the accounts
     * must be identical, which is what makes this a re-spelling of the same
     * rows rather than an approximation of them.  A row that is also read is
     * left alone for the same reason: its RD half was canonicalised to the
     * whole register above, and growing it would move the read.
     */
    if (dir == INSN_DF_WR && df_container(off, size, &c_off, &c_size)) {
        static const uint64_t no_prov[INSN_DF_REG_WORDS];

        for (unsigned i = 0; i < d->n_fields; i++) {
            InsnDataflowField *f = &d->fields[i];
            uint32_t f_coff, f_csize;

            if (f->dir != INSN_DF_WR || f->sourced != sourced ||
                f->from_loads != from_loads ||
                f->size == DF_FIELD_UNBOUNDED) {
                continue;
            }
            if (!df_container(f->off, f->size, &f_coff, &f_csize) ||
                f_coff != c_off) {
                continue;
            }
            if (off + size < f->off || f->off + f->size < off) {
                continue;       /* disjoint, and not even touching */
            }
            if (memcmp(f->prov, prov ? prov : no_prov,
                       sizeof(f->prov)) != 0) {
                continue;
            }
            {
                uint32_t lo = MIN(f->off, off);
                uint32_t hi = MAX(f->off + f->size, off + size);

                f->off = lo;
                f->size = hi - lo;
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
    d->fields[d->n_fields].sourced = sourced;
    d->fields[d->n_fields].from_loads = from_loads;
    memset(d->fields[d->n_fields].prov, 0,
           sizeof(d->fields[d->n_fields].prov));
    if (prov) {
        memcpy(d->fields[d->n_fields].prov, prov,
               sizeof(d->fields[d->n_fields].prov));
    }
    d->n_fields++;
}

/*
 * One guest memory access, recorded where the op stream performs it.
 *
 * The access order within an instruction is the op order, which is the order
 * the guest performs them in: TCG emits the ops in the sequence the target's
 * emitter wrote, and that sequence is the architectural one.  So the rows need
 * no sorting and no note -- they are read off in the order they will happen.
 */
static int df_add_memop(InsnDataflow *d, uint8_t dir, uint32_t size,
                        const uint64_t *addr_prov, const uint64_t *data_prov)
{
    InsnDataflowMemop *m;
    int k;

    /*
     * THE EMITTER SAID THIS RUN IS ONE ACCESS, SO IT GETS ONE ROW.
     *
     * The fold is bounded by the direction because that is the one thing a
     * run cannot cross and still be one access: a load run and a store run
     * are two accesses however adjacent their addresses are.  Size adds --
     * the run covers a contiguous region and its extent is the sum -- and
     * both accounts union, because the address every element was computed
     * from and the datum they carry between them are the access's own.
     */
    if (d->split_access && d->n_memops > 0 &&
        d->memops[d->n_memops - 1].dir == dir) {
        uint32_t grown;

        m = &d->memops[d->n_memops - 1];
        grown = (uint32_t)m->size + size;
        m->size = grown > UINT16_MAX ? UINT16_MAX : (uint16_t)grown;
        if (addr_prov) {
            df_union(m->addr_prov, addr_prov);
        }
        if (data_prov) {
            df_union(m->data_prov, data_prov);
        }
        return (int)(d->n_memops - 1);
    }

    if (d->n_memops >= INSN_DF_MAX_MEMOPS) {
        d->incomplete |= INSN_DF_INCOMPLETE_MEMOPS;
        return -1;
    }
    k = (int)d->n_memops;
    m = &d->memops[d->n_memops++];
    m->dir = dir;
    m->size = size > UINT16_MAX ? UINT16_MAX : (uint16_t)size;
    memset(m->addr_prov, 0, sizeof(m->addr_prov));
    memset(m->data_prov, 0, sizeof(m->data_prov));
    if (addr_prov) {
        memcpy(m->addr_prov, addr_prov, sizeof(m->addr_prov));
    }
    if (data_prov) {
        memcpy(m->data_prov, data_prov, sizeof(m->data_prov));
    }
    return k;
}

/*
 * A guest load or store: which way, how wide, and where its address and datum
 * came from.
 *
 * The argument layout is derived from the op definition rather than from a
 * per-opcode table, so a target or host configuration that gives an access a
 * different number of data arguments (a 128-bit access, or a 64-bit datum on a
 * 32-bit host) needs nothing here: a load names its data first and its address
 * last among the inputs; a store names its data first and its address last.
 */
static int df_guest_memop(InsnDataflow *d, TCGOp *op)
{
    TCGContext *s = tcg_ctx;
    const TCGOpDef *def = &tcg_op_defs[op->opc];
    unsigned nb_oargs = def->nb_oargs, nb_iargs = def->nb_iargs;
    uint64_t addr_prov[INSN_DF_REG_WORDS] = { 0 };
    uint64_t data_prov[INSN_DF_REG_WORDS] = { 0 };
    unsigned ndata, addr_arg;
    TCGTemp *ts;
    MemOpIdx oi;
    uint8_t dir;

    switch (op->opc) {
    case INDEX_op_qemu_ld_i32:
    case INDEX_op_qemu_ld_i64:
    case INDEX_op_qemu_ld_i128:
        dir = INSN_DF_RD;
        ndata = nb_oargs;
        addr_arg = nb_oargs;        /* the one input is the address */
        break;
    case INDEX_op_qemu_st_i32:
    case INDEX_op_qemu_st_i64:
    case INDEX_op_qemu_st8_i32:
    case INDEX_op_qemu_st_i128:
        dir = INSN_DF_WR;
        ndata = nb_iargs - 1;
        addr_arg = nb_iargs - 1;    /* the address is the last input */
        break;
    default:
        return -1;
    }

    ts = arg_temp(op->args[addr_arg]);
    if (ts != NULL) {
        df_union(addr_prov, df_prov(ts - s->temps));
        {
            unsigned idx;

            if (df_is_reg(ts, &idx)) {
                df_set_bit(addr_prov, idx);
            }
        }
    }
    for (unsigned i = 0; i < ndata && dir == INSN_DF_WR; i++) {
        TCGTemp *dts = arg_temp(op->args[i]);
        unsigned idx;

        if (dts == NULL) {
            continue;
        }
        df_union(data_prov, df_prov(dts - s->temps));
        if (df_is_reg(dts, &idx)) {
            df_set_bit(data_prov, idx);
        }
    }

    oi = op->args[nb_oargs + nb_iargs];
    return df_add_memop(d, dir, memop_size(get_memop(oi)), addr_prov,
                        dir == INSN_DF_WR ? data_prov : NULL);
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
/*
 * The vector-operand statement covering an env offset, if one was made.
 *
 * An in-place vector operation states the same offset twice, once written and
 * once read, so every matching statement contributes: the directions are
 * unioned and the widest extent wins.  Returns false when no statement covers
 * the offset, which is the caller's signal to fall back and count.
 */
static bool df_vec_operand(const InsnDataflow *d, uint32_t off,
                           uint32_t *size, unsigned *dir)
{
    bool found = false;

    for (unsigned i = 0; i < d->n_vecops; i++) {
        if (d->vecops[i].off != off) {
            continue;
        }
        if (!found) {
            *size = d->vecops[i].size;
            *dir = d->vecops[i].dir;
            found = true;
        } else {
            *size = MAX(*size, d->vecops[i].size);
            *dir |= d->vecops[i].dir;
        }
    }
    return found;
}

/* Defined below, beside the table it reads. */
static bool df_helper_usage(TCGOp *op, unsigned argidx,
                            uint32_t *size, unsigned *dir);

/*
 * The pointer arguments of one call, held until the read side is complete.
 *
 * A helper takes at most a handful -- x86's SSE form is destination, src1,
 * src2; aarch64's widest gvec expansion is four -- so a small array covers
 * every call in tree, and a call that overran it would be recorded short
 * rather than wrong.
 */
#define DF_CALL_MAX_PTR_ARGS 8

typedef struct DfCallPtrArg {
    uint32_t off;
    uint32_t size;
    unsigned dir;
} DfCallPtrArg;

static void df_call(InsnDataflow *d, TCGOp *op)
{
    TCGContext *s = tcg_ctx;
    TCGTemp *env_ts = tcgv_ptr_temp(tcg_env);
    unsigned nb_oargs = TCGOP_CALLO(op);
    unsigned nb_iargs = TCGOP_CALLI(op);
    uint64_t prov[INSN_DF_REG_WORDS] = { 0 };
    DfCallPtrArg ptr_args[DF_CALL_MAX_PTR_ARGS];
    unsigned n_ptr_args = 0;
    unsigned idx;
    bool trunc = false;

    d->n_calls++;

    for (unsigned i = 0; i < nb_iargs; i++) {
        TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);
        int64_t eo;

        if (ts == NULL) {
            continue;
        }
        df_union(prov, df_prov(ts - s->temps));
        if (df_trunc(ts - s->temps)) {
            trunc = true;
            d->incomplete |= INSN_DF_INCOMPLETE_FIELDS;
        }
        if (df_is_reg(ts, &idx)) {
            df_read_global(d, idx, prov);
        }
        if (ts == env_ts) {
            continue;
        }
        eo = df_envoff(ts - s->temps);
        if (eo != INSN_DF_NOT_ENV && eo >= 0) {
            uint32_t size = DF_FIELD_UNBOUNDED;
            unsigned dir = INSN_DF_RD | INSN_DF_WR;
            int bit;

            /*
             * A vector expander states each operand's extent and direction,
             * because it is the only place that holds the offset and oprsz
             * together.  Where it did, that is the answer; where it did not,
             * the unbounded both-directions record stands and is counted, so
             * a blob is never mistaken for a measurement.
             */
            if (df_vec_operand(d, (uint32_t)eo, &size, &dir)) {
                d->n_env_ptr_bounded++;
            } else if (df_helper_usage(op, i, &size, &dir)) {
                d->n_env_ptr_bounded++;
            } else {
                d->n_env_ptr_unbounded++;
            }
            bit = df_intern((uint32_t)eo, size);
            if (bit >= 0) {
                /*
                 * A RANGE THE HELPER ONLY WRITES IS NOT AN INPUT.  The bit
                 * exists so a result can name where its value came from, and
                 * a destination buffer supplies none of it; setting the bit
                 * for a write-only pointer would publish every result of the
                 * call as depending on its own destination.  Where the
                 * direction is the unbounded both-ways fallback the read half
                 * stands, which is the pessimistic direction this file keeps.
                 */
                if (dir & INSN_DF_RD) {
                    df_set_bit(prov, (unsigned)bit);
                }
            } else {
                trunc = true;
                d->incomplete |= INSN_DF_INCOMPLETE_FIELDS;
            }
            if (n_ptr_args < DF_CALL_MAX_PTR_ARGS) {
                ptr_args[n_ptr_args].off = (uint32_t)eo;
                ptr_args[n_ptr_args].size = size;
                ptr_args[n_ptr_args].dir = dir;
                n_ptr_args++;
            } else {
                d->incomplete |= INSN_DF_INCOMPLETE_FIELDS;
                df_add_field(d, (uint32_t)eo, size, dir, prov, true, false);
            }
        }
    }
    /*
     * THE ROWS LAND AFTER THE WHOLE READ SIDE, AND THAT IS THE FIX.
     *
     * This function's contract is one edge: every result depends on every
     * argument.  Adding each pointer argument's row inside the walk broke it
     * in one direction -- the row carried only the provenance accumulated up
     * to that argument's position, so a row early in the list could not name
     * a source that came later.  QEMU's SSE calling shape puts the
     * destination FIRST and its sources after it, so every helper-implemented
     * vector operation published a destination whose account named the
     * operands before it and nothing else.  Measured on x86_64:
     * `punpcklqdq %xmm1,%xmm0` published dst=%xmm0 depending on %xmm0 alone,
     * with %xmm1 in the read set and out of the account, and the same for
     * punpckldq, punpckhdq and every sibling of theirs.
     *
     * The rows are held and added here instead, where @prov is the whole read
     * side, so the contract the comment above states is the one the code
     * keeps.
     */
    for (unsigned k = 0; k < n_ptr_args; k++) {
        df_add_field(d, ptr_args[k].off, ptr_args[k].size, ptr_args[k].dir,
                     prov, true, false);
    }
    for (unsigned i = 0; i < nb_oargs; i++) {
        TCGTemp *ts = arg_temp(op->args[i]);

        if (ts == NULL) {
            continue;
        }
        if (df_is_reg(ts, &idx)) {
            df_write_global(d, idx, prov);
            df_set_trunc(idx, trunc);
        } else {
            df_union(df_prov(ts - s->temps), prov);
            if (trunc) {
                df_set_trunc(ts - s->temps, true);
            }
        }
    }
}

/*
 * ENV BYTES THIS INSTRUCTION ALREADY WROTE, AND WHETHER THEY COVER THE READ.
 *
 * A target stages a value through CPUArchState as readily as through a temp.
 * x86's 128-bit vector moves do exactly that: the load lands in two 64-bit
 * temps, both are stored into the scratch at xmm_t0, and the destination
 * register is then filled by ONE 16-byte vector load out of that scratch.
 * Nothing in the op stream connects the two halves to the whole -- interning
 * keys a range on its offset AND its extent, on purpose, so that a 4-byte word
 * is not confused with the vector containing it -- so the account stopped at
 * the scratch and every 128-bit vector load published a destination that
 * depended on nothing.
 *
 * The rule is the one the call side has followed since the self-reload pass: a
 * read of bytes the same instruction wrote is not an input, and its value is
 * whatever the writes put there.  @prov collects those writes' accounts; the
 * return says whether they cover the range completely, which is what decides
 * if the architectural range is still a source at all.
 *
 * Ranges wider than 64 bytes and pointer-reached ranges have no coverage
 * answer here and are reported as uncovered, which leaves them exactly as they
 * were.
 */
static bool df_env_writes_cover(const InsnDataflow *d, uint32_t off,
                                uint32_t size, uint64_t *prov)
{
    uint64_t seen = 0;
    bool any = false;

    if (size == 0 || size > 64 || size == DF_FIELD_UNBOUNDED) {
        return false;
    }
    for (unsigned i = 0; i < d->n_fields; i++) {
        const InsnDataflowField *f = &d->fields[i];
        uint32_t lo, hi;

        if (!(f->dir & INSN_DF_WR) || f->size == DF_FIELD_UNBOUNDED) {
            continue;
        }
        lo = MAX(f->off, off);
        hi = MIN(f->off + f->size, off + size);
        if (lo >= hi) {
            continue;
        }
        any = true;
        df_union(prov, f->prov);
        for (uint32_t b = lo - off; b < hi - off; b++) {
            seen |= 1ULL << b;
        }
    }
    return any && seen == (size == 64 ? ~0ULL : (1ULL << size) - 1);
}

/* One op, attributed to instruction @d. */
static void df_op(InsnDataflow *d, TCGOp *op)
{
    TCGContext *s = tcg_ctx;
    TCGTemp *env_ts = tcgv_ptr_temp(tcg_env);
    const TCGOpDef *def = &tcg_op_defs[op->opc];
    uint64_t prov[INSN_DF_REG_WORDS] = { 0 };
    uint64_t ld_env_prov[INSN_DF_REG_WORDS] = { 0 };
    unsigned nb_oargs, nb_iargs, idx;
    int ld_field_bit = -1;
    int ld_memop_bit = -1;
    bool ld_env_written = false;
    bool trunc = false;
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

    case INDEX_op_goto_tb:
        /*
         * QEMU emits goto_tb only for a successor it knew at translation
         * time, and a conditional branch materialises one for each side, so a
         * second is the conditional shape rather than a second instruction.
         */
        d->xfer |= d->xfer & INSN_DF_X_STATIC
                   ? INSN_DF_X_MULTI
                   : INSN_DF_X_TRANSFER | INSN_DF_X_STATIC;
        return;

    case INDEX_op_goto_ptr:
        d->xfer |= INSN_DF_X_TRANSFER | INSN_DF_X_COMPUTED;
        break;

    case INDEX_op_exit_tb:
        d->xfer |= INSN_DF_X_TRANSFER;
        return;

    case INDEX_op_qemu_ld_i32:
    case INDEX_op_qemu_ld_i64:
    case INDEX_op_qemu_ld_i128:
        d->n_mem_rd++;
        {
            int k = df_guest_memop(d, op);

            if (k >= 0) {
                ld_memop_bit = INSN_DF_BIT_MEMOP0 + k;
            }
        }
        break;

    case INDEX_op_qemu_st_i32:
    case INDEX_op_qemu_st_i64:
    case INDEX_op_qemu_st8_i32:
    case INDEX_op_qemu_st_i128:
        d->n_mem_wr++;
        df_guest_memop(d, op);
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

            if (eo < 0) {
                /*
                 * BELOW tcg_env IS NOT ARCHITECTURAL STATE, so an op that
                 * reaches it is not the instruction's behaviour.
                 *
                 * tcg_env points at CPUArchState, and the bytes at a NEGATIVE
                 * offset from it are the CPUState header QEMU keeps for
                 * itself: the icount decrementer, the io permission, and the
                 * slot the plugin memory callback reads a value out of.  No
                 * guest register lives there.
                 *
                 * Attributing such an op's operands to the instruction does
                 * not merely add noise, it INVENTS A DEPENDENCY.  The store
                 * that carries a load's value to the plugin
                 * (plugin_gen_mem_callbacks_i64(), tcg/tcg-op-ldst.c) names
                 * the load's DESTINATION as its datum; on a target whose load
                 * writes the architectural global directly -- riscv64's
                 * dest_gpr(), aarch64's cpu_reg() -- that destination is a
                 * TCG global, so it landed in the instruction's own READ set
                 * and every register-offset load published a
                 * read-after-write edge on itself.  x86 and mips never showed
                 * it because their loads land in a temp first, which is why
                 * the shape read as a two-ISA mystery rather than as one rule
                 * about where the op was pointing.
                 *
                 * The load direction is handled too, and not by falling
                 * through: a temp is recycled across a translation, so
                 * leaving the destination's provenance alone would let it
                 * keep the account of whatever the temp last held.  Clearing
                 * it says what is true -- the value came from QEMU's own
                 * bookkeeping and from no guest register.
                 */
                if (!store) {
                    TCGTemp *vts = arg_temp(op->args[0]);

                    if (vts != NULL && !df_is_reg(vts, &idx)) {
                        memset(df_prov(vts - s->temps), 0, sizeof(prov));
                        df_set_trunc(vts - s->temps, false);
                    }
                }
                return;
            }
            if (store) {
                /*
                 * The value's provenance is the range's provenance: this
                 * is where a vector register's write gets the same account
                 * of itself a GPR's write already had.
                 */
                TCGTemp *vts = arg_temp(op->args[0]);

                df_add_field(d, (uint32_t)eo, size, INSN_DF_WR,
                             df_prov(vts - s->temps), true, false);
            } else if (df_env_writes_cover(d, (uint32_t)eo, size,
                                           ld_env_prov)) {
                /*
                 * Every byte read came from a write this same instruction
                 * made.  The range is not an input and the interned bit is
                 * not the value's source: the writes' own account is, and it
                 * is carried to the destination below.
                 */
                ld_env_written = true;
            } else {
                df_add_field(d, (uint32_t)eo, size, INSN_DF_RD, NULL, true,
                             false);
                ld_field_bit = df_intern((uint32_t)eo, size);
                if (ld_field_bit < 0) {
                    /*
                     * The range this value came out of could not be interned,
                     * so the value below will be handed an account that is
                     * missing its one real member.  Said here, about THIS
                     * instruction, and carried on the value from here.
                     */
                    trunc = true;
                    d->incomplete |= INSN_DF_INCOMPLETE_FIELDS;
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
        if (df_trunc(ts - s->temps)) {
            trunc = true;
            d->incomplete |= INSN_DF_INCOMPLETE_FIELDS;
        }
        if (df_is_reg(ts, &idx)) {
            df_read_global(d, idx, prov);
        }
    }

    /*
     * A GUEST LOAD'S RESULT CAME FROM MEMORY, NOT FROM THE POINTER.
     *
     * The loop above has just done its real work -- the address register is in
     * the instruction's read set, where it belongs, and in the memop's own
     * address provenance.  What it must not do is hand that account on to the
     * VALUE: `mov (%r15),%rax` does not compute rax from r15, it computes an
     * address from r15 and takes rax from whatever that address held.  Leaving
     * the union in place published the pointer as the datum's source and left
     * the wire's load-data bits -- specified since the format's first epoch --
     * with no producer at all, which is how a uniformly false fact survives.
     *
     * The replacement is total rather than additive on purpose.  Naming both
     * would say the value depends on the register AND on the access, and a
     * consumer scheduling on that would let rax issue as soon as r15 was
     * ready.  The address dependency is a fact about the ACCESS and is
     * published as one, in load_addr_dep.
     */
    if (ld_memop_bit >= 0) {
        memset(prov, 0, sizeof(prov));
        df_set_bit(prov, (unsigned)ld_memop_bit);
    }

    for (unsigned i = 0; i < nb_oargs; i++) {
        TCGTemp *ts = arg_temp(op->args[i]);

        if (ts == NULL) {
            continue;
        }
        if (df_is_reg(ts, &idx)) {
            df_write_global(d, idx, prov);
            df_set_trunc(idx, trunc);
        } else {
            uint64_t *dp = df_prov(ts - s->temps);

            memcpy(dp, prov, sizeof(prov));
            df_set_trunc(ts - s->temps, trunc);
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
            if (ld_env_written) {
                df_union(dp, ld_env_prov);
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
                df_add_write(d, (unsigned)g, none, false, false);
            }
            return;
        }
        if (df_declared_by_name(a.name, &off, &size)) {
            df_add_field(d, off, size, dir, NULL, false, false);
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

void insn_dataflow_note_preserve_read(InsnDataflowAtom a)
{
    int g;

    if (df == NULL || !df->decoding || a.kind != INSN_DF_A_REG ||
        a.name == NULL) {
        return;
    }
    g = df_global_by_name(a.name);
    if (g < 0 || df->npres >= INSN_DF_MAX_BINDINGS) {
        /*
         * Only a TCG global can carry the note: a declared env range is
         * recorded per byte range by df_add_field(), which the merge case
         * this exists for does not go through.  A name that resolves to
         * nothing -- or a block that has made more notes than there is room
         * for -- leaves the read exactly as it was: the register stays in the
         * read set, which is the pessimistic direction and visible there.
         */
        return;
    }
    df->pres[df->npres].anchor = tcg_last_op();
    df->pres[df->npres].insn = df->cur;
    df->pres[df->npres].bit = (uint16_t)g;
    df->npres++;
}

void insn_dataflow_state_write(InsnDataflowAtom a)
{
    df_state(a, INSN_DF_WR);
}

void insn_dataflow_state_write_from(InsnDataflowAtom a,
                                    const InsnDataflowAtom *src,
                                    unsigned nsrc)
{
    InsnDataflow *d;
    uint64_t prov[INSN_DF_REG_WORDS] = { 0 };
    bool from_loads = false;
    bool any = false;
    uint32_t off, size;
    int g;

    if (df == NULL || !df->decoding) {
        return;
    }
    d = &df->out[df->cur];

    for (unsigned i = 0; i < nsrc; i++) {
        int bit;

        if (src[i].kind == INSN_DF_A_LOADED) {
            from_loads = true;
            continue;
        }
        bit = df_atom_bit(src[i]);
        if (bit >= 0) {
            df_set_bit(prov, (unsigned)bit);
            any = true;
        }
        /*
         * An atom that named nothing this build knows adds no bit.  It is not
         * an error here: the statement's other sources still stand, and a
         * statement left with none at all falls through to the read set
         * below, which is where a write with no account belongs.
         */
    }

    switch (a.kind) {
    case INSN_DF_A_REG:
        if (a.name == NULL) {
            return;
        }
        g = df_global_by_name(a.name);
        if (g >= 0) {
            df_set_bit(d->wr, (unsigned)g);
            df_add_write(d, (unsigned)g, prov, any || from_loads, from_loads);
            return;
        }
        if (df_declared_by_name(a.name, &off, &size)) {
            df_add_field(d, off, size, INSN_DF_WR, prov,
                         any || from_loads, from_loads);
        }
        return;

    default:
        /* Only storage can be written; an immediate is not a destination. */
        return;
    }
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

static void df_window_open(unsigned kind, unsigned arg)
{
    if (df == NULL || !df->decoding || df->nwin >= INSN_DF_MAX_WINDOWS ||
        df->win_open >= 0) {
        return;
    }
    df->win[df->nwin].from = tcg_last_op();
    df->win[df->nwin].to = NULL;
    df->win[df->nwin].insn = df->cur;
    df->win[df->nwin].arg = (uint16_t)arg;
    df->win[df->nwin].kind = (uint8_t)kind;
    df->win_open = (int)df->nwin;
    df->nwin++;
}

void insn_dataflow_window_begin(unsigned kind)
{
    df_window_open(kind, 0);
}

void insn_dataflow_borrow_begin(unsigned lender)
{
    df_window_open(DF_W_BORROW, lender);
}

void insn_dataflow_borrow_end(void)
{
    insn_dataflow_window_end();
}

void insn_dataflow_note_property(unsigned prop)
{
    if (df == NULL || !df->decoding) {
        return;
    }
    df->out[df->cur].properties |= (uint8_t)prop;
}

void insn_dataflow_note_rule(const char *name)
{
    if (df == NULL || !df->decoding || name == NULL) {
        return;
    }
    /*
     * First wins.  Decoders nest -- a compressed-encoding table inside a
     * width dispatcher, a prefix table inside an opcode table -- and the
     * innermost pattern's translate function returns first, so the first name
     * to arrive is the specific rule and every later one is a table that
     * reached it.
     */
    if (df->out[df->cur].rule == NULL) {
        df->out[df->cur].rule = name;
    }
}

void insn_dataflow_note_word(const char *word)
{
    if (df == NULL || !df->decoding || word == NULL) {
        return;
    }
    if (df->out[df->cur].word == NULL) {
        df->out[df->cur].word = word;
    }
}

void insn_dataflow_refuse(void)
{
    if (df == NULL || !df->decoding) {
        return;
    }
    df->out[df->cur].incomplete |= INSN_DF_INCOMPLETE_REFUSED;
}

void insn_dataflow_note_immediate(uint64_t value, unsigned role)
{
    InsnDataflow *d;

    if (df == NULL || !df->decoding) {
        return;
    }
    d = &df->out[df->cur];
    for (unsigned i = 0; i < d->n_imm; i++) {
        if (d->imm[i] == value && d->imm_role[i] == role) {
            return;             /* the same field stated twice is one field */
        }
    }
    if (d->n_imm >= INSN_DF_MAX_IMM) {
        return;
    }
    d->imm[d->n_imm] = value;
    d->imm_role[d->n_imm] = (uint8_t)role;
    d->n_imm++;
}

void insn_dataflow_note_self_loop(unsigned memops, bool iterated)
{
    InsnDataflow *d;

    if (df == NULL || !df->decoding) {
        return;
    }
    if (memops == 0 || memops > INSN_DF_SELF_LOOP_MAX) {
        return;
    }
    d = &df->out[df->cur];
    /*
     * The first statement is the encoding's.  An x86 string operation states
     * its unit once, at the emitter; a MOPS instruction states it once, beside
     * the publication of its own address.  A second statement on the same
     * instruction would be QEMU's lowering of the first.
     */
    if (d->self_loop_memops != 0) {
        return;
    }
    d->self_loop_memops = (uint8_t)memops;
    d->self_loop_iterated = iterated;
}

void insn_dataflow_note_split_access(void)
{
    if (df == NULL || !df->decoding) {
        return;
    }
    df->out[df->cur].split_access = true;
}

void insn_dataflow_note_vec_shape(unsigned vece, uint32_t oprsz)
{
    InsnDataflow *d;

    if (df == NULL || !df->decoding || vece > 7) {
        return;
    }
    d = &df->out[df->cur];
    /*
     * One instruction can run more than one expander -- a widening operation
     * is two passes over the same operand.  The element size that reaches the
     * wire is the FIRST stated: it is the one the encoding names, and the
     * later passes are QEMU's lowering of it.
     */
    if (d->vec_vece == INSN_DF_VECE_NONE) {
        d->vec_vece = (uint8_t)vece;
        d->vec_oprsz = oprsz;
    }
    /*
     * An expansion is elementwise, so stating a shape states a UNIFORM kind.
     * It does not overrule a decode site: an element insert copies the lanes
     * it does not touch with a gvec move, so the expander's UNIFORM arrives
     * first and the insert's own statement second, and the encoding's answer
     * is the one that has to survive.
     */
    if (!d->vec_kind_stated) {
        d->vec_kind = INSN_DF_VEC_KIND_UNIFORM;
        d->vec_lane = INSN_DF_VEC_LANE_NONE;
    }
}

void insn_dataflow_note_vec_lane(unsigned kind, int lane)
{
    InsnDataflow *d;

    if (df == NULL || !df->decoding) {
        return;
    }
    if (kind == INSN_DF_VEC_KIND_NONE || kind > INSN_DF_VEC_KIND_BROADCAST) {
        return;
    }
    if (lane < INSN_DF_VEC_LANE_NONE || lane > INT16_MAX) {
        return;
    }
    d = &df->out[df->cur];
    if (d->vec_kind_stated) {
        return;             /* the first statement is the encoding's */
    }
    d->vec_kind = (uint8_t)kind;
    d->vec_lane = (int16_t)lane;
    d->vec_kind_stated = true;
}

void insn_dataflow_refuse_vec_lane(unsigned reason)
{
    InsnDataflow *d;

    if (df == NULL || !df->decoding) {
        return;
    }
    if (reason == 0 || reason > INSN_DF_VEC_REFUSE_COMPOSITE) {
        return;
    }
    d = &df->out[df->cur];
    if (d->vec_lane_refuse == 0) {
        d->vec_lane_refuse = (uint8_t)reason;
    }
    if (d->n_vec_lane_refused < UINT8_MAX) {
        d->n_vec_lane_refused++;
    }
    /*
     * A REFUSAL ALSO REFUSES THE KIND, and must, because every site that
     * refuses is a site the shape's implicit UNIFORM is wrong about.
     *
     * Measured on all three targets that have one: x86 INSERTPS, SVE INSR and
     * MSA SLDI each run an expansion -- the copy that fills the lanes the
     * instruction does not itself write -- so a shape arrives and the kind
     * read UNIFORM beside a refused lane.  A consumer taking UNIFORM at its
     * word would tie lane i of the result to lane i of the source, which is
     * exactly what a slide and a zeroing insert do not do, so the pair said
     * something false in the direction that loses an edge.  Marking the kind
     * stated-as-NONE clears it and stops a later expansion from setting it.
     */
    d->vec_kind = INSN_DF_VEC_KIND_NONE;
    d->vec_lane = INSN_DF_VEC_LANE_NONE;
    d->vec_kind_stated = true;
}

void insn_dataflow_note_vec_operand(uint32_t envofs, uint32_t bytes,
                                    unsigned dir)
{
    InsnDataflow *d;

    if (df == NULL || !df->decoding || bytes == 0) {
        return;
    }
    dir &= INSN_DF_RD | INSN_DF_WR;
    if (dir == 0) {
        return;
    }
    d = &df->out[df->cur];

    /*
     * The same operand stated twice -- an in-place vector operation names one
     * offset as both destination and source -- is one operand with both
     * directions, not two.  Merging here keeps the reader's lookup simple and
     * keeps the row count meaning what it says.
     */
    for (unsigned i = 0; i < d->n_vecops; i++) {
        if (d->vecops[i].off == envofs) {
            d->vecops[i].size = MAX(d->vecops[i].size, bytes);
            d->vecops[i].dir |= (uint8_t)dir;
            return;
        }
    }
    if (d->n_vecops >= INSN_DF_MAX_VECOPS) {
        d->n_vecops_dropped++;
        return;
    }
    d->vecops[d->n_vecops].off = envofs;
    d->vecops[d->n_vecops].size = bytes;
    d->vecops[d->n_vecops].dir = (uint8_t)dir;
    d->n_vecops++;
}

void insn_dataflow_note_synthetic_ea(unsigned dir, uint32_t size,
                                     const InsnDataflowEaPart *parts,
                                     unsigned nparts, int64_t disp)
{
    uint64_t addr_prov[INSN_DF_REG_WORDS] = { 0 };
    InsnDataflowSynthEa row = { 0 };
    InsnDataflow *d;
    bool whole = true;

    if (df == NULL || !df->decoding) {
        return;
    }
    d = &df->out[df->cur];

    for (unsigned i = 0; i < nparts; i++) {
        int bit = df_atom_bit(parts[i].atom);

        if (bit >= 0) {
            df_set_bit(addr_prov, (unsigned)bit);
        } else {
            whole = false;
        }
        /*
         * The instruction really does read the register that names the
         * address, whether or not the emulation computes anything with it.
         */
        df_state(parts[i].atom, INSN_DF_RD);

        /*
         * The components, for the consumer that recomputes the address.  An
         * address short one of its terms is a DIFFERENT address and not an
         * approximate one, so a component that resolved to no bit, or one
         * more component than a row holds, voids the whole row rather than
         * shortening it.
         */
        if (i < INSN_DF_MAX_EA_PARTS && bit >= 0) {
            row.part_bit[i] = (uint8_t)bit;
            row.part_shift[i] = parts[i].shift;
            row.part_ext[i] = parts[i].ext;
            row.n_parts = (uint8_t)(i + 1);
        } else {
            whole = false;
        }
    }
    if (disp != 0) {
        df_set_bit(addr_prov, INSN_DF_BIT_IMM);
        insn_dataflow_note_immediate((uint64_t)disp, INSN_DF_IMM_DISP);
    }
    row.memop = d->n_memops;
    row.disp = disp;
    df_add_memop(d, (uint8_t)dir, size, addr_prov, NULL);

    /*
     * Recorded only if the memop it names was recorded: a row pointing at a
     * memop that ran out of slots names nothing.
     */
    if (!whole || row.memop >= d->n_memops) {
        d->n_synth_ea_refused++;
    } else if (d->n_synth_ea >= INSN_DF_MAX_SYNTH_EA) {
        d->n_synth_ea_refused++;
    } else {
        d->synth_ea[d->n_synth_ea++] = row;
    }
}

void insn_dataflow_window_end(void)
{
    if (df == NULL || df->win_open < 0) {
        return;
    }
    df->win[df->win_open].to = tcg_last_op();
    df->win_open = -1;
}

/*
 * The target's helper-usage table, installed once by the target.
 *
 * A helper call is one edge at this level, and an argument that is a pointer
 * built from tcg_env is how a register with no TCG global reaches it.  The
 * pointer alone says neither extent nor direction, so the reader used to
 * record the whole of CPUArchState in both directions.  That is honest and it
 * is a loss: a consumer handed one unbounded blob in place of the two or three
 * registers the instruction touched has been told less than QEMU knew.
 *
 * The extent comes from the declared pointee type (the compiler's sizeof) and
 * the direction from the target's adjudicated rows; the join below refuses
 * unless both sides account for each other exactly.
 */
static const InsnDfHelperArgs *df_hu_args;
static unsigned df_hu_nargs;
static const InsnDfHelperDir *df_hu_dirs;
static unsigned df_hu_ndirs;

static const InsnDfHelperDir *df_hu_find_dir(const char *name)
{
    for (unsigned i = 0; i < df_hu_ndirs; i++) {
        if (strcmp(df_hu_dirs[i].name, name) == 0) {
            return &df_hu_dirs[i];
        }
    }
    return NULL;
}

static const InsnDfHelperArgs *df_hu_find_args(const char *name)
{
    for (unsigned i = 0; i < df_hu_nargs; i++) {
        if (strcmp(df_hu_args[i].name, name) == 0) {
            return &df_hu_args[i];
        }
    }
    return NULL;
}

/* Does this helper name any register through a pointer argument? */
static bool df_hu_has_regptr(const InsnDfHelperArgs *a)
{
    for (unsigned k = 0; k < a->nargs && k < INSN_DF_MAX_HELPER_ARGS; k++) {
        if (a->argsize[k]) {
            return true;
        }
    }
    return false;
}

void insn_dataflow_declare_helper_usage(const InsnDfHelperArgs *args,
                                        unsigned nargs,
                                        const InsnDfHelperDir *dirs,
                                        unsigned ndirs)
{
    unsigned missing = 0, dead = 0, shape = 0;

    if (args == NULL || nargs == 0) {
        return;
    }

    /*
     * Both directions, and both are printed in full rather than counted: a
     * table that is quietly short falls back to the unbounded blob it exists
     * to replace, which is exactly the shape nothing else would report.
     */
    for (unsigned i = 0; i < nargs; i++) {
        const InsnDfHelperDir *d;

        if (!df_hu_has_regptr(&args[i])) {
            continue;
        }
        d = NULL;
        for (unsigned j = 0; j < ndirs; j++) {
            if (strcmp(dirs[j].name, args[i].name) == 0) {
                d = &dirs[j];
                break;
            }
        }
        if (d == NULL) {
            {
                char sh[INSN_DF_MAX_HELPER_ARGS + 1];
                unsigned k;

                for (k = 0; k < args[i].nargs &&
                            k < INSN_DF_MAX_HELPER_ARGS; k++) {
                    sh[k] = args[i].argsize[k] ? 'R' : '-';
                }
                sh[k] = '\0';
                error_report("insn-dataflow: helper %s takes a register "
                             "pointer and has no adjudicated usage row "
                             "(shape %s)", args[i].name, sh);
            }
            missing++;
        } else if (strlen(d->dirs) != args[i].nargs) {
            error_report("insn-dataflow: helper %s has %u arguments and its "
                         "usage row states %zu directions", args[i].name,
                         args[i].nargs, strlen(d->dirs));
            shape++;
        }
    }
    for (unsigned j = 0; j < ndirs; j++) {
        const InsnDfHelperArgs *a = NULL;

        for (unsigned i = 0; i < nargs; i++) {
            if (strcmp(args[i].name, dirs[j].name) == 0) {
                a = &args[i];
                break;
            }
        }
        if (a == NULL || !df_hu_has_regptr(a)) {
            error_report("insn-dataflow: usage row %s names no helper that "
                         "takes a register pointer", dirs[j].name);
            dead++;
        }
    }
    if (missing || dead || shape) {
        error_report("insn-dataflow: helper usage table refused "
                     "(%u unadjudicated, %u dead, %u mis-shaped)",
                     missing, dead, shape);
        exit(1);
    }

    df_hu_args = args;
    df_hu_nargs = nargs;
    df_hu_dirs = dirs;
    df_hu_ndirs = ndirs;
}

/*
 * The extent and direction of a helper call's pointer argument @argidx, if
 * the target adjudicated one.  False means no answer, and the caller then
 * keeps the unbounded record and counts it.
 */
static bool df_helper_usage(TCGOp *op, unsigned argidx,
                            uint32_t *size, unsigned *dir)
{
    const TCGHelperInfo *hi;
    const InsnDfHelperArgs *a;
    const InsnDfHelperDir *d;
    unsigned nb_iargs = TCGOP_CALLI(op);

    if (df_hu_args == NULL) {
        return false;
    }
    hi = tcg_call_info(op);
    if (hi == NULL || hi->name == NULL) {
        return false;
    }
    a = df_hu_find_args(hi->name);
    d = df_hu_find_dir(hi->name);
    if (a == NULL || d == NULL) {
        return false;
    }
    /*
     * The declared argument count and the emitted one must agree before an
     * index means the same thing on both sides.  A by-reference type occupies
     * two call slots, and reading a direction off a shifted index would put a
     * different operand's answer on this one; no target in this table has
     * one, and if one arrives the row is declined rather than mis-applied.
     */
    if (nb_iargs != a->nargs || strlen(d->dirs) != a->nargs) {
        return false;
    }
    if (argidx >= a->nargs || a->argsize[argidx] == 0) {
        return false;
    }
    switch (d->dirs[argidx]) {
    case 'r': *dir = INSN_DF_RD; break;
    case 'w': *dir = INSN_DF_WR; break;
    case 'b': *dir = INSN_DF_RD | INSN_DF_WR; break;
    default:  return false;
    }
    *size = a->argsize[argidx];
    return true;
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
        df->nbind = 0;
        df->npres = 0;
        df->nwin = 0;
        df->win_open = -1;
        df->ninsns = 0;
    }
    if (idx >= INSN_DF_MAX_INSNS) {
        df->decoding = false;
        return;
    }
    memset(&df->out[idx], 0, sizeof(df->out[idx]));
    df->out[idx].vec_vece = INSN_DF_VECE_NONE;
    df->out[idx].vec_kind = INSN_DF_VEC_KIND_NONE;
    df->out[idx].vec_lane = INSN_DF_VEC_LANE_NONE;
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
    uint64_t loads[INSN_DF_REG_WORDS] = { 0 };
    bool any_load = false;

    /*
     * The data every load returned, as the bits a load's own destination
     * carries.  Built here because the access rows are what the op walk
     * produced, and a statement made at decode time could not have named
     * them.
     */
    for (unsigned i = 0; i < d->n_memops; i++) {
        if (d->memops[i].dir == INSN_DF_RD) {
            df_set_bit(loads, INSN_DF_BIT_MEMOP0 + i);
            any_load = true;
        }
    }

    for (unsigned i = 0; i < d->n_writes; i++) {
        if (d->writes[i].from_loads) {
            if (any_load) {
                df_union(d->writes[i].prov, loads);
            } else if (df_empty(d->writes[i].prov)) {
                /*
                 * The arm said the value came from the access and the
                 * instruction performed none this reader can see -- QEMU does
                 * it inside the helper.  Publishing the empty set would say
                 * the chain is broken, so the statement is withdrawn and the
                 * read-set fallback below stands instead.
                 */
                d->writes[i].sourced = false;
            }
        }
        if (!d->writes[i].sourced && df_empty(d->writes[i].prov)) {
            df_union(d->writes[i].prov, d->rd);
        }
    }
    for (unsigned i = 0; i < d->n_fields; i++) {
        if (!(d->fields[i].dir & INSN_DF_WR)) {
            continue;
        }
        if (d->fields[i].from_loads) {
            if (any_load) {
                df_union(d->fields[i].prov, loads);
            } else if (df_empty(d->fields[i].prov)) {
                d->fields[i].sourced = false;
            }
        }
        if (!d->fields[i].sourced && df_empty(d->fields[i].prov)) {
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
    int win_lender = -1;
    unsigned wi = 0, bi = 0, pi = 0;
    int idx = -1;

    if (df == NULL) {
        return;
    }
    df->decoding = false;
    /*
     * The preserve bits are armed by the cursor below as the walk reaches each
     * note's anchor, so the walk starts with none of them set.
     */
    memset(df->preserve, 0, sizeof(df->preserve));
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
                win_lender = w->kind == DF_W_BORROW && w->arg < num_insns
                             ? (int)w->arg : -1;
            }
            wi++;
        }
        while (bi < df->nbind && df->bind[bi].anchor == prev) {
            if (df->bind[bi].insn < num_insns) {
                df_set_bit(df_prov(df->bind[bi].temp), df->bind[bi].bit);
            }
            bi++;
        }
        /*
         * A preserve-read note arms HERE, at the op it was anchored to, and
         * not before: the merge it describes is the next op, and any read of
         * the same register earlier in this instruction was the instruction's
         * own operand.
         */
        while (pi < df->npres && df->pres[pi].anchor == prev) {
            if (df->pres[pi].insn < num_insns) {
                df_set_bit(df->preserve[df->pres[pi].insn], df->pres[pi].bit);
            }
            pi++;
        }

        if (op->opc == INDEX_op_insn_start) {
            idx++;
            prev = op;
            continue;
        }

        if (win_to != NULL) {
            if (win_lender >= 0) {
                df_op(&df->out[win_lender], op);
            }
        } else if (idx >= 0 && (unsigned)idx < num_insns) {
            df_op(&df->out[idx], op);
        }
        if (win_to == op) {
            win_to = NULL;
            win_lender = -1;
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

bool insn_dataflow_prov_memop(unsigned bit, uint32_t *index)
{
    if (bit < INSN_DF_BIT_MEMOP0 ||
        bit >= INSN_DF_BIT_MEMOP0 + INSN_DF_MAX_MEMOPS) {
        return false;
    }
    if (index) {
        *index = bit - INSN_DF_BIT_MEMOP0;
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
        if (i >= rf->count) {
            continue;
        }
        /*
         * An access narrower than the register is still that register, AT ANY
         * OFFSET INSIDE IT: a 4-byte load of element 1 of a 16-byte vector
         * starts four bytes past the register's base, and naming the container
         * is the whole point of the declaration.  Requiring the access to
         * start at the base was the earlier rule and it left every element but
         * the first unnamed -- measured on aarch64, 61 distinct ranges inside
         * the declared Z file answered with no name at all.
         *
         * The test is containment: the whole access must lie inside one
         * register.  An access that runs off the end of one is not that
         * register and is left unnamed rather than misattributed, which is the
         * same rule the width test used to state and the only part of it that
         * was right.
         */
        rel %= rf->stride;
        if (size == DF_FIELD_UNBOUNDED) {
            /*
             * The extent was not stated, so containment cannot be tested, and
             * the range may well cover the whole file: a helper handed a
             * pointer to vreg[0] can write every vector register through it.
             * Naming the register the access BEGINS in would be read by a
             * consumer as naming the only register it touched, which is the
             * under-reporting direction -- a dependency missed, not one
             * invented.  So an unstated extent gets no name, and the caller is
             * left with an env range it must treat as the blob it is.
             *
             * Measured on riscv64 with V enabled: six of nine field rows are
             * unbounded helper pointers into vreg, and all six begin at vreg[0].
             */
            return NULL;
        }
        if (rel + (uint64_t)size > rf->size) {
            continue;
        }
        return rf->names[i];
    }
    return NULL;
}

