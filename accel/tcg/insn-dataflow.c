/*
 * Per-instruction dataflow, derived from the IR the target's translator
 * emitted.
 *
 * This supplies dataflow only.  Identifying the instruction -- mnemonic,
 * opcode class, branch class, length -- stays with the decoder, permanently;
 * nothing here can say which instruction it is looking at and nothing here
 * tries.
 *
 * The premise is the same one that makes memory instrumentation work: a guest
 * instruction's accesses are not something to be looked up, they are
 * something QEMU has already written down.  A memory access is an explicit
 * TCG op; so is a register access.  Every op declares how many of its
 * arguments are outputs and how many are inputs, and a temp that is
 * TEMP_GLOBAL based on tcg_env is a guest register at a known offset in
 * CPUArchState.  Walking the ops between two insn_start markers and sorting
 * the global temps by argument position gives the read and write sets of one
 * instruction, from the machine's own translation of it.
 *
 * Why before tcg_optimize()
 * -------------------------
 * Dead-store elimination removes architecturally real writes that nothing
 * downstream consumes.  x86 is the extreme case: the whole lazy-flags scheme
 * exists so that a flag write can be dropped when the next instruction does
 * not look at them.  So this runs at the end of translator_loop(), before any
 * pass has touched the ops and before the plugin's translate callback needs
 * the answer.
 *
 * What it gives that a state differ cannot
 * ---------------------------------------
 * Reads, at all.  Inert writes -- tcg_gen_movcond_* names its destination as
 * a plain output, so a conditional move's write is in the IR whether or not
 * the condition made it a no-op, and a consumer modelling speculative
 * register release needs to know it happened.  And writes whose value equals
 * what was already there, which are invisible to anything that compares
 * state before and after.
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

#define INSN_DF_NOT_ENV     INT64_MIN

/*
 * Per-translation scratch.  translator_loop() is not re-entrant on a thread,
 * so one set per thread is enough and none of it needs a lock.
 *
 * The generation counter is what keeps this cheap.  Clearing a provenance
 * table of TCG_MAX_TEMPS entries at the top of every TB is kilobytes of memset
 * on a path that runs for every translation in the program; stamping each
 * entry with the translation it belongs to and treating a stale stamp as empty
 * costs one comparison on first touch and nothing at all for a temp the TB
 * never uses.
 */
static __thread uint32_t df_gen = 1;
static __thread uint32_t df_stamp[TCG_MAX_TEMPS];
static __thread uint64_t df_prov[TCG_MAX_TEMPS][INSN_DF_REG_WORDS];
static __thread int64_t df_envoff[TCG_MAX_TEMPS];

static __thread InsnDataflow df_out[INSN_DF_MAX_INSNS];
static __thread unsigned df_ninsns;

/*
 * Env byte ranges no TCG global names, interned for the duration of one
 * translation block so they can carry provenance bits alongside the globals.
 * A TB touches very few distinct ones; overflow stops interning, which is the
 * safe direction -- see df_intern().
 */
static __thread uint32_t df_slot_off[INSN_DF_MAX_FIELD_SLOTS];
static __thread unsigned df_nslots;
static __thread bool df_slots_overflow;

/*
 * Give @off a provenance bit, above the globals.
 *
 * When the table is full this returns -1 and the caller records nothing,
 * which makes a value that came from this field look as though it came from
 * nowhere.  That is the direction that must never be taken lightly and is
 * taken here only because the alternative is worse: see the note on
 * df_field_prov() about which way an error in this code should fall.  With 64
 * slots against the handful of distinct fields any real instruction touches,
 * the case is not reachable in practice, and df_slots_overflow says so out
 * loud when it is.
 */
static int df_intern(uint32_t off)
{
    unsigned base = tcg_ctx->nb_globals;

    for (unsigned i = 0; i < df_nslots; i++) {
        if (df_slot_off[i] == off) {
            return (int)(base + i);
        }
    }
    if (df_nslots >= INSN_DF_MAX_FIELD_SLOTS ||
        base + df_nslots >= INSN_DF_MAX_REGS) {
        df_slots_overflow = true;
        return -1;
    }
    df_slot_off[df_nslots] = off;
    return (int)(base + df_nslots++);
}

/*
 * Measurement scaffolding.  The extraction is meant to be unconditional in a
 * production build, so the only way to say what it costs is to be able to run
 * the same binary without it: QEMU_DF_OFF makes it return immediately, which
 * is the baseline every reported figure is against.  QEMU_DF_PROFILE reports
 * the extraction's own time, and both are read once.
 */
static bool df_off, df_off_read;
static bool df_prof, df_prof_read;
static int64_t df_prof_tbs, df_prof_insns, df_prof_ops, df_prof_ns;
static int64_t df_prof_every = 20000;

static int64_t df_now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void df_prof_dump(void)
{
    if (!df_prof_tbs) {
        return;
    }
    fprintf(stderr, "df_profile: tbs=%" PRId64 " insns=%" PRId64
            " ops=%" PRId64 " ns=%" PRId64 " ns_per_tb=%.0f"
            " ns_per_insn=%.1f ns_per_op=%.1f\n",
            df_prof_tbs, df_prof_insns, df_prof_ops, df_prof_ns,
            (double)df_prof_ns / df_prof_tbs,
            (double)df_prof_ns / MAX(df_prof_insns, 1),
            (double)df_prof_ns / MAX(df_prof_ops, 1));
}

static bool df_disabled(void)
{
    if (!df_off_read) {
        const char *e = getenv("QEMU_DF_OFF");

        df_off = e && atoi(e) != 0;
        df_off_read = true;
    }
    return df_off;
}

static bool df_test(const uint64_t *p, unsigned bit);

/*
 * Cross-check output.
 *
 * This extractor is a second implementation of the same derivation the
 * behavioural oracle does, written lean enough to run on every translation.
 * Two implementations of one thing agree until they do not, so it can emit
 * its answer in the oracle's own report format and be diffed against it.
 * QEMU_DF_DUMP names the file; QEMU_DF_PC_LO/_PC_HI bound it.
 */
static FILE *df_dump;
static bool df_dump_read;
static uint64_t df_pc_lo, df_pc_hi = UINT64_MAX;

static FILE *df_dumping(void)
{
    if (!df_dump_read) {
        const char *e = getenv("QEMU_DF_DUMP");
        const char *lo = getenv("QEMU_DF_PC_LO");
        const char *hi = getenv("QEMU_DF_PC_HI");

        df_dump_read = true;
        if (e && *e) {
            df_dump = fopen(e, "w");
            if (df_dump) {
                setvbuf(df_dump, NULL, _IOLBF, 0);
                fprintf(df_dump, "# qemu insn-dataflow\n");
                fprintf(df_dump, "T target=%s env_size=0 nb_tcg_globals=%d\n",
                        TARGET_NAME, tcg_ctx->nb_globals);
                for (unsigned i = 0; i < (unsigned)tcg_ctx->nb_globals; i++) {
                    uint32_t off, size;
                    const char *nm = insn_dataflow_reg_name(i, &off, &size);

                    if (nm) {
                        fprintf(df_dump, "G %6u %2u %s\n", off, size, nm);
                    }
                }
            }
        }
        if (lo) {
            df_pc_lo = strtoull(lo, NULL, 0);
        }
        if (hi) {
            df_pc_hi = strtoull(hi, NULL, 0);
        }
    }
    return df_dump;
}

static void df_emit(uint64_t pc, const InsnDataflow *d)
{
    FILE *f = df_dumping();
    unsigned n = tcg_ctx->nb_globals;

    if (!f || pc < df_pc_lo || pc > df_pc_hi) {
        return;
    }
    for (unsigned i = 0; i < n; i++) {
        uint32_t off, size;
        const char *nm = insn_dataflow_reg_name(i, &off, &size);

        if (!nm) {
            continue;
        }
        if (df_test(d->rd, i)) {
            fprintf(f, "D 0x%" PRIx64 " r reg=%s off=%u size=%u via=arg "
                    "op=df argno=0\n", pc, nm, off, size);
        }
        if (df_test(d->wr, i)) {
            const uint64_t *pv = NULL;

            for (unsigned w = 0; w < d->n_writes; w++) {
                if (d->writes[w].reg == i) {
                    pv = d->writes[w].prov;
                    break;
                }
            }
            fprintf(f, "D 0x%" PRIx64 " w reg=%s off=%u size=%u via=arg "
                    "op=df argno=0 from=", pc, nm, off, size);
            if (pv) {
                unsigned k = 0;

                for (unsigned r = 0; r < n; r++) {
                    if (df_test(pv, r)) {
                        const char *rn = insn_dataflow_reg_name(r, NULL, NULL);

                        fprintf(f, "%s%s", k++ ? "," : "", rn ? rn : "?");
                    }
                }
                if (!k) {
                    fputc('-', f);
                }
            } else {
                fputc('-', f);
            }
            fputc('\n', f);
        }
        if (df_test(d->kill, i)) {
            fprintf(f, "D 0x%" PRIx64 " k reg=%s off=%u size=%u via=arg "
                    "op=df argno=0\n", pc, nm, off, size);
        }
    }
    for (unsigned i = 0; i < d->n_fields; i++) {
        const InsnDataflowField *fl = &d->fields[i];

        if (fl->dir & INSN_DF_RD) {
            fprintf(f, "D 0x%" PRIx64 " r reg=? off=%u size=%u via=ld op=df "
                    "argno=0\n", pc, fl->off, fl->size);
        }
        if (fl->dir & INSN_DF_WR) {
            unsigned k = 0;

            fprintf(f, "D 0x%" PRIx64 " w reg=? off=%u size=%u via=st op=df "
                    "argno=0 from=", pc, fl->off, fl->size);
            for (unsigned b = 0; b < INSN_DF_MAX_REGS; b++) {
                bool ok;
                uint32_t foff;

                if (!df_test(fl->prov, b)) {
                    continue;
                }
                if (b < n) {
                    const char *rn = insn_dataflow_reg_name(b, NULL, NULL);

                    fprintf(f, "%s%s", k++ ? "," : "", rn ? rn : "?");
                } else {
                    foff = insn_dataflow_prov_field(b, &ok);
                    if (ok) {
                        fprintf(f, "%s@%u", k++ ? "," : "", foff);
                    }
                }
            }
            if (!k) {
                fputc('-', f);
            }
            fputc('\n', f);
        }
    }
    for (unsigned i = 0; i < d->n_mem_rd; i++) {
        fprintf(f, "D 0x%" PRIx64 " r mem op=df\n", pc);
    }
    for (unsigned i = 0; i < d->n_mem_wr; i++) {
        fprintf(f, "D 0x%" PRIx64 " w mem op=df\n", pc);
    }
    fprintf(f, "A 0x%" PRIx64 " ops=0 calls=%u opaque=%u\n",
            pc, d->n_calls, d->n_calls);
}

static bool df_profiling(void)
{
    if (!df_prof_read) {
        const char *e = getenv("QEMU_DF_PROFILE");

        df_prof = e && atoi(e) != 0;
        df_prof_read = true;
        if (df_prof) {
            const char *n = getenv("QEMU_DF_PROFILE_EVERY");

            if (n) {
                df_prof_every = strtoll(n, NULL, 0);
            }
        }
    }
    return df_prof;
}

static void df_touch(size_t i)
{
    if (df_stamp[i] != df_gen) {
        df_stamp[i] = df_gen;
        memset(df_prov[i], 0, sizeof(df_prov[i]));
        df_envoff[i] = INSN_DF_NOT_ENV;
    }
}

static uint64_t *df_prov_of(size_t i)
{
    df_touch(i);
    return df_prov[i];
}

static int64_t df_envoff_of(size_t i)
{
    df_touch(i);
    return df_envoff[i];
}

static void df_set_envoff(size_t i, int64_t v)
{
    df_touch(i);
    df_envoff[i] = v;
}

static void df_or(uint64_t *dst, const uint64_t *src)
{
    for (int i = 0; i < INSN_DF_REG_WORDS; i++) {
        dst[i] |= src[i];
    }
}

static void df_bit(uint64_t *p, unsigned bit)
{
    if (bit < INSN_DF_MAX_REGS) {
        p[bit / 64] |= 1ULL << (bit % 64);
    }
}

static bool df_test(const uint64_t *p, unsigned bit)
{
    return bit < INSN_DF_MAX_REGS && (p[bit / 64] & (1ULL << (bit % 64)));
}

/*
 * Is @ts a guest register?
 *
 * Globals occupy the first nb_globals slots of the temps array, so a global's
 * index in that array is its register number -- no lookup table, and nothing
 * to keep in step with the target's own.
 */
static bool df_reg(const TCGTemp *ts, unsigned *idx)
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

static void df_add_write(InsnDataflow *d, unsigned reg, const uint64_t *prov)
{
    for (unsigned i = 0; i < d->n_writes; i++) {
        if (d->writes[i].reg == reg) {
            df_or(d->writes[i].prov, prov);
            return;
        }
    }
    if (d->n_writes >= INSN_DF_MAX_WRITES) {
        d->writes_overflow = 1;
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
 * Which way this code should err, stated once here because every choice below
 * follows it:
 *
 *   A dependency recorded that does not exist is PESSIMISTIC.  A consumer
 *   serialises two instructions that could have run together and loses some
 *   scheduling accuracy.  Nothing it computes is wrong.
 *
 *   A dependency MISSED is WRONG.  A consumer reorders across an edge the
 *   machine could not have crossed, and everything downstream of that is
 *   unsound.
 *
 * They are not symmetric and this code does not treat them as though they
 * were.  Where it cannot tell, it records the dependency.  The concrete case
 * that made this worth writing down: giving a field write an empty provenance
 * because field *reads* were not tracked would have reported psubb
 * %xmm2,%xmm2 as breaking its dependency chain, which it does not -- a missed
 * dependency, arrived at by a change that looked like a simplification.
 */
static void df_add_field(InsnDataflow *d, uint32_t off, uint32_t size,
                         uint8_t dir, const uint64_t *prov)
{
    for (unsigned i = 0; i < d->n_fields; i++) {
        if (d->fields[i].off == off && d->fields[i].size == size) {
            d->fields[i].dir |= dir;
            if (prov) {
                df_or(d->fields[i].prov, prov);
            }
            return;
        }
    }
    if (d->n_fields >= INSN_DF_MAX_FIELDS) {
        /*
         * Out of room to say what was touched.  The instruction's field
         * accesses are now under-reported, which for a write means a
         * dependency could go missing, so it is flagged rather than dropped
         * quietly.
         */
        d->fields_overflow = 1;
        return;
    }
    d->fields[d->n_fields].off = off;
    d->fields[d->n_fields].size = (uint16_t)size;
    d->fields[d->n_fields].dir = dir;
    memset(d->fields[d->n_fields].prov, 0,
           sizeof(d->fields[d->n_fields].prov));
    if (prov) {
        memcpy(d->fields[d->n_fields].prov, prov,
               sizeof(d->fields[d->n_fields].prov));
    }
    d->n_fields++;
}

/* Walk one instruction's ops: [first, end). */
static void df_insn(InsnDataflow *d, TCGOp *first, TCGOp *end)
{
    TCGContext *s = tcg_ctx;
    TCGTemp *env_ts = tcgv_ptr_temp(tcg_env);
    uint64_t prov[INSN_DF_REG_WORDS];

    for (TCGOp *op = first; op != end; op = QTAILQ_NEXT(op, link)) {
        const TCGOpDef *def = &tcg_op_defs[op->opc];
        unsigned nb_oargs, nb_iargs, idx;
        bool store;
        uint32_t size;
        int ld_field_bit = -1;

        if (op->opc == INDEX_op_insn_start) {
            continue;
        }

        if (op->opc == INDEX_op_call) {
            nb_oargs = TCGOP_CALLO(op);
            nb_iargs = TCGOP_CALLI(op);
            d->n_calls++;

            memset(prov, 0, sizeof(prov));
            for (unsigned i = 0; i < nb_iargs; i++) {
                TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);
                int64_t eo;

                df_or(prov, df_prov_of(ts - s->temps));
                if (df_reg(ts, &idx)) {
                    df_bit(d->rd, idx);
                    df_bit(prov, idx);
                }
                /*
                 * A pointer into env: how a vector register reaches a gvec
                 * helper.  The argument does not say whether the helper reads
                 * or writes through it, so it is reported as both -- an
                 * over-approximation the consumer can see is one, rather than
                 * a guess that looks like a fact.  tcg_env itself does not
                 * count: it is the first argument of nearly every helper
                 * there is.
                 */
                if (ts != env_ts) {
                    eo = df_envoff_of(ts - s->temps);
                    if (eo != INSN_DF_NOT_ENV && eo >= 0) {
                        int bit = df_intern((uint32_t)eo);

                        /*
                         * The argument does not say whether the helper reads
                         * or writes through the pointer, so both are recorded
                         * and the region taints everything the call produces.
                         * Over-recording here is the pessimistic direction.
                         */
                        if (bit >= 0) {
                            df_bit(prov, (unsigned)bit);
                        }
                        df_add_field(d, (uint32_t)eo, 0,
                                     INSN_DF_RD | INSN_DF_WR, prov);
                    }
                }
            }
            for (unsigned i = 0; i < nb_oargs; i++) {
                TCGTemp *ts = arg_temp(op->args[i]);

                if (df_reg(ts, &idx)) {
                    df_bit(d->wr, idx);
                    df_add_write(d, idx, prov);
                } else {
                    df_or(df_prov_of(ts - s->temps), prov);
                }
            }
            continue;
        }

        /*
         * discard names its argument as an output but is not a write: it is
         * TCG being told the temp's value is dead, which on x86 is how the
         * flag fields an instruction does not define are retired.  Counting
         * it as a write would put cc_src2 in the write set of every add.
         */
        if (op->opc == INDEX_op_discard) {
            TCGTemp *ts = arg_temp(op->args[0]);

            if (df_reg(ts, &idx)) {
                df_bit(d->kill, idx);
            } else {
                df_set_envoff(ts - s->temps, INSN_DF_NOT_ENV);
            }
            continue;
        }

        nb_oargs = def->nb_oargs;
        nb_iargs = def->nb_iargs;

        if (df_ldst(op, &store, &size)) {
            TCGTemp *bts = arg_temp(op->args[1]);
            int64_t bo = bts == env_ts ? 0 : df_envoff_of(bts - s->temps);

            if (bo != INSN_DF_NOT_ENV) {
                int64_t eo = bo + (int64_t)op->args[2];

                if (eo >= 0) {
                    if (store) {
                        /*
                         * The value's provenance is the field's provenance:
                         * this is where a vector register's write gets the
                         * same account of itself a GPR's write already had.
                         */
                        TCGTemp *vts = arg_temp(op->args[0]);

                        df_add_field(d, (uint32_t)eo, size, INSN_DF_WR,
                                     df_prov_of(vts - s->temps));
                    } else {
                        df_add_field(d, (uint32_t)eo, size, INSN_DF_RD, NULL);
                        ld_field_bit = df_intern((uint32_t)eo);
                    }
                }
            }
        }

        switch (op->opc) {
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

        memset(prov, 0, sizeof(prov));
        for (unsigned i = 0; i < nb_iargs; i++) {
            TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);

            df_or(prov, df_prov_of(ts - s->temps));
            if (df_reg(ts, &idx)) {
                df_bit(d->rd, idx);
                df_bit(prov, idx);
            }
        }

        for (unsigned i = 0; i < nb_oargs; i++) {
            TCGTemp *ts = arg_temp(op->args[i]);

            if (df_reg(ts, &idx)) {
                df_bit(d->wr, idx);
                df_add_write(d, idx, prov);
            } else {
                uint64_t *dp = df_prov_of(ts - s->temps);

                memcpy(dp, prov, sizeof(prov));
                /*
                 * A load's value came from the field it loaded, which the
                 * op's own inputs do not say -- they name the base pointer.
                 * Without this a value read out of the vector file looks like
                 * it came from nowhere, and every instruction operating on it
                 * would report a broken dependency chain it does not have.
                 */
                if (ld_field_bit >= 0) {
                    df_bit(dp, (unsigned)ld_field_bit);
                }
            }
        }

        /*
         * Track temps whose value is tcg_env plus a constant, and temps whose
         * value is a constant.  Only mov and add-of-a-constant can produce
         * one; anything else writing a tracked temp stops tracking it, so the
         * map never outlives the fact.
         */
        if (nb_oargs == 1) {
            TCGTemp *dts = arg_temp(op->args[0]);
            size_t di = dts - s->temps;
            int64_t v = INSN_DF_NOT_ENV;

            if (op->opc == INDEX_op_mov_i64 || op->opc == INDEX_op_mov_i32) {
                TCGTemp *a = arg_temp(op->args[1]);

                v = a == env_ts ? 0 : df_envoff_of(a - s->temps);
            } else if (op->opc == INDEX_op_add_i64 ||
                       op->opc == INDEX_op_add_i32) {
                TCGTemp *a = arg_temp(op->args[1]);
                TCGTemp *b = arg_temp(op->args[2]);
                int64_t ao = a == env_ts ? 0 : df_envoff_of(a - s->temps);
                int64_t bo = b == env_ts ? 0 : df_envoff_of(b - s->temps);

                if (ao != INSN_DF_NOT_ENV && b->kind == TEMP_CONST) {
                    v = ao + b->val;
                } else if (bo != INSN_DF_NOT_ENV && a->kind == TEMP_CONST) {
                    v = bo + a->val;
                }
            }
            df_set_envoff(di, v);
        }
    }
}

void insn_dataflow_extract(unsigned num_insns)
{
    TCGContext *s = tcg_ctx;
    TCGOp *op, *first = NULL;
    unsigned idx = 0;
    bool prof;
    int64_t t0;

    if (df_disabled()) {
        df_ninsns = 0;
        return;
    }
    prof = df_profiling();
    t0 = prof ? df_now() : 0;

    df_gen++;
    df_nslots = 0;
    df_slots_overflow = false;
    df_ninsns = 0;
    if (num_insns > INSN_DF_MAX_INSNS) {
        num_insns = INSN_DF_MAX_INSNS;
    }
    memset(df_out, 0, num_insns * sizeof(df_out[0]));

    QTAILQ_FOREACH(op, &s->ops, link) {
        if (op->opc != INDEX_op_insn_start) {
            continue;
        }
        if (first != NULL && idx > 0) {
            df_insn(&df_out[idx - 1], first, op);
        }
        if (idx >= num_insns) {
            first = NULL;
            break;
        }
        idx++;
        first = QTAILQ_NEXT(op, link);
    }
    if (first != NULL && idx > 0) {
        df_insn(&df_out[idx - 1], first, NULL);
    }
    df_ninsns = idx;

    if (df_dumping()) {
        unsigned k = 0;

        QTAILQ_FOREACH(op, &s->ops, link) {
            if (op->opc != INDEX_op_insn_start || k >= df_ninsns) {
                continue;
            }
            df_emit(tcg_get_insn_start_param(op, 0), &df_out[k]);
            k++;
        }
    }

    if (prof) {
        df_prof_ns += df_now() - t0;
        df_prof_tbs++;
        df_prof_insns += idx;
        QTAILQ_FOREACH(op, &s->ops, link) {
            df_prof_ops++;
        }
        if (df_prof_tbs % df_prof_every == 0) {
            df_prof_dump();
        }
    }
}

const InsnDataflow *insn_dataflow_get(unsigned i)
{
    return i < df_ninsns ? &df_out[i] : NULL;
}

/* Map a provenance bit at or above nregs back to the env offset it interned. */
uint32_t insn_dataflow_prov_field(unsigned bit, bool *valid)
{
    unsigned base = tcg_ctx->nb_globals;

    if (bit < base || bit - base >= df_nslots) {
        *valid = false;
        return 0;
    }
    *valid = true;
    return df_slot_off[bit - base];
}

/*
 * Did provenance lose a field to slot exhaustion during this translation?
 *
 * Reported per TB rather than per instruction because that is the truth: the
 * slot table is interned for the block.  A consumer told "incomplete" for one
 * instruction when the exhaustion happened in another is being told something
 * pessimistic, which is the direction this code errs in everywhere else.
 */
bool insn_dataflow_prov_truncated(void)
{
    return df_slots_overflow;
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
