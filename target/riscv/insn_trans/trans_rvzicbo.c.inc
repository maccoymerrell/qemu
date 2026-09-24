/*
 * RISC-V translation routines for the RISC-V CBO Extension.
 *
 * Copyright (c) 2021 Philipp Tomsich, philipp.tomsich@vrull.eu
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define REQUIRE_ZICBOM(ctx) do {     \
    if (!ctx->cfg_ptr->ext_zicbom) { \
        return false;                \
    }                                \
} while (0)

#define REQUIRE_ZICBOZ(ctx) do {     \
    if (!ctx->cfg_ptr->ext_zicboz) { \
        return false;                \
    }                                \
} while (0)

/*
 * THE SYNTHETIC ADDRESS (fact 18).
 *
 * A cache-block operation names an address in its encoding and QEMU performs
 * no guest memory access for it: the block is handed to a helper, which probes
 * for permission and -- since QEMU models no cache hierarchy -- returns.  There
 * is no memop for the reader to walk, so a consumer is handed an instruction
 * whose encoding plainly carries an address and whose record touches nothing.
 * The decode site still holds the base register, so it says so.
 *
 * @dir is QEMU's own reading of the access, not a guess.  check_zicbom_access()
 * probes MMU_DATA_LOAD and accepts a readable block, so the maintenance forms
 * are stated as reads, a block of the CPU's own configured length rather than
 * a constant written here.  CBO.ZERO is not this shape: its helper really
 * stores, and states its stores below.
 *
 * THE COMPONENT IS UNSHIFTED AND UNEXTENDED, which RISC-V's encoding settles
 * rather than this file: the base register is added whole, and the
 * displacement is genuinely absent -- these encodings have no offset field, so
 * nothing is stated for one.
 */
static void note_cbo_ea(DisasContext *ctx, int rs1, unsigned dir, uint32_t len)
{
    InsnDataflowEaPart base =
        insn_df_ea(rs1 == 0 ? insn_df_zero()
                            : insn_df_reg(riscv_int_regnames[rs1]),
                   0, INSN_DF_EA_EXT_NONE);

    insn_dataflow_note_synthetic_ea(dir, len, &base, 1, 0);
}

static bool trans_cbo_clean(DisasContext *ctx, arg_cbo_clean *a)
{
    REQUIRE_ZICBOM(ctx);
    TCGv src = get_address(ctx, a->rs1, 0);

    note_cbo_ea(ctx, a->rs1, INSN_DF_RD, ctx->cfg_ptr->cbom_blocksize);
    gen_helper_cbo_clean_flush(tcg_env, src);
    return true;
}

static bool trans_cbo_flush(DisasContext *ctx, arg_cbo_flush *a)
{
    REQUIRE_ZICBOM(ctx);
    TCGv src = get_address(ctx, a->rs1, 0);

    note_cbo_ea(ctx, a->rs1, INSN_DF_RD, ctx->cfg_ptr->cbom_blocksize);
    gen_helper_cbo_clean_flush(tcg_env, src);
    return true;
}

static bool trans_cbo_inval(DisasContext *ctx, arg_cbo_inval *a)
{
    REQUIRE_ZICBOM(ctx);
    TCGv src = get_address(ctx, a->rs1, 0);

    note_cbo_ea(ctx, a->rs1, INSN_DF_RD, ctx->cfg_ptr->cbom_blocksize);
    gen_helper_cbo_inval(tcg_env, src);
    return true;
}

/*
 * THE STORES CBO.ZERO PERFORMS.
 *
 * helper_cbo_zero() probes the block for a store and then zeroes it.  Where
 * the probe hands back a host pointer the zeroing is a memset no plugin sees;
 * where it does not -- an I/O page, and under plugins in system mode every
 * page, since the probe then refuses host pointers -- it is one
 * cpu_stb_mmuidx_ra() per byte, each delivered as its own store.  The most
 * the helper can perform is therefore cboz_blocksize one-byte stores, from
 * the block the address is aligned down into, and that is the count the
 * template states: an execution that delivers fewer (the memset, or the
 * wrong path, which zeroes nothing) publishes a smaller count, never a larger
 * one.  The address account is the base register's, as the single row's was.
 */
static void note_cbo_zero_stores(DisasContext *ctx, int rs1, uint32_t len)
{
    InsnDataflowHelperAccess rows[UINT8_MAX];
    InsnDataflowEaPart base =
        insn_df_ea(rs1 == 0 ? insn_df_zero()
                            : insn_df_reg(riscv_int_regnames[rs1]),
                   0, INSN_DF_EA_EXT_NONE);

    if (len == 0 || len > ARRAY_SIZE(rows)) {
        /*
         * A template counts at most UINT8_MAX accesses per direction (a
         * u8 on the wire): a wider fan is refused, not clamped.
         */
        insn_dataflow_refuse();
        return;
    }
    for (uint32_t i = 0; i < len; i++) {
        rows[i].dir = INSN_DF_WR;
        rows[i].size = 1;
        rows[i].offset = i;
        rows[i].datum = 0;
    }
    insn_dataflow_note_helper_accesses(rows, len, &base, 1, 0);
}

static bool trans_cbo_zero(DisasContext *ctx, arg_cbo_zero *a)
{
    REQUIRE_ZICBOZ(ctx);
    TCGv src = get_address(ctx, a->rs1, 0);

    note_cbo_zero_stores(ctx, a->rs1, ctx->cfg_ptr->cboz_blocksize);
    gen_helper_cbo_zero(tcg_env, src);
    return true;
}

/*
 * ZICBOP: PREFETCH.I, PREFETCH.R and PREFETCH.W.
 *
 * These were not decoded at all.  Their encodings are ORI with rd == x0 and
 * the low five immediate bits zero, and QEMU let them fall through to the ORI
 * rule, which discards the whole of their meaning: the base register survives
 * as an ORI source, the offset arrives as an unrelated immediate, and the
 * prefetch itself is a write to x0 that nothing performs.  A consumer was
 * handed a logical OR.
 *
 * They are rules now, gated on the extension whose cfg flag QEMU already
 * advertises and until now had no consumer.  Each emits NO OPS -- which is
 * exactly what the ORI-with-rd-x0 path emitted after dead-code elimination,
 * so no architectural behaviour moves -- and states the address the encoding
 * names.  A hart without Zicbop still decodes them as the ORI hints they are,
 * because a trans function returning false lets decodetree fall through to the
 * overlapping pattern.
 */
static bool trans_prefetch_common(DisasContext *ctx, int rs1, int imm)
{
    if (!ctx->cfg_ptr->ext_zicbop) {
        return false;
    }

    InsnDataflowEaPart base =
        insn_df_ea(rs1 == 0 ? insn_df_zero()
                            : insn_df_reg(riscv_int_regnames[rs1]),
                   0, INSN_DF_EA_EXT_NONE);

    insn_dataflow_note_immediate(imm, INSN_DF_IMM_DISP);
    insn_dataflow_note_synthetic_ea(INSN_DF_RD, ctx->cfg_ptr->cbop_blocksize,
                                    &base, 1, imm);
    return true;
}

static bool trans_prefetch_i(DisasContext *ctx, arg_prefetch_i *a)
{
    return trans_prefetch_common(ctx, a->rs1, a->imm);
}

static bool trans_prefetch_r(DisasContext *ctx, arg_prefetch_r *a)
{
    return trans_prefetch_common(ctx, a->rs1, a->imm);
}

static bool trans_prefetch_w(DisasContext *ctx, arg_prefetch_w *a)
{
    return trans_prefetch_common(ctx, a->rs1, a->imm);
}
