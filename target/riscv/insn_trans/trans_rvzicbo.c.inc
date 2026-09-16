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
 * are stated as reads; helper_cbo_zero() calls probe_write() and then memsets
 * cboz_blocksize bytes, so CBO.ZERO is a write of exactly that many.  The size
 * likewise comes from the CPU's own configured block length rather than a
 * constant written here.
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

static bool trans_cbo_zero(DisasContext *ctx, arg_cbo_zero *a)
{
    REQUIRE_ZICBOZ(ctx);
    TCGv src = get_address(ctx, a->rs1, 0);

    note_cbo_ea(ctx, a->rs1, INSN_DF_WR, ctx->cfg_ptr->cboz_blocksize);
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
