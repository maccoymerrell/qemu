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
 * The block address a cbo names, for plugins: rs1, cut to the address width
 * as get_address() does (a pointer-masking width other than 32 or XLEN is
 * not stateable and is left unstated).
 */
static void cbo_record_ea(DisasContext *ctx, int rs1)
{
    int ext = ctx->addr_xl != 32 ? 0 : ctx->addr_signed ? -32 : 32;

    plugin_gen_record_ea(offsetof(CPURISCVState, gpr[rs1]), -1, 0, ext, 0);
}

static bool trans_cbo_clean(DisasContext *ctx, arg_cbo_clean *a)
{
    REQUIRE_ZICBOM(ctx);
    cbo_record_ea(ctx, a->rs1);
    TCGv src = get_address(ctx, a->rs1, 0);

    gen_helper_cbo_clean_flush(tcg_env, src);
    return true;
}

static bool trans_cbo_flush(DisasContext *ctx, arg_cbo_flush *a)
{
    REQUIRE_ZICBOM(ctx);
    cbo_record_ea(ctx, a->rs1);
    TCGv src = get_address(ctx, a->rs1, 0);

    gen_helper_cbo_clean_flush(tcg_env, src);
    return true;
}

static bool trans_cbo_inval(DisasContext *ctx, arg_cbo_inval *a)
{
    REQUIRE_ZICBOM(ctx);
    cbo_record_ea(ctx, a->rs1);
    TCGv src = get_address(ctx, a->rs1, 0);

    gen_helper_cbo_inval(tcg_env, src);
    return true;
}

static bool trans_cbo_zero(DisasContext *ctx, arg_cbo_zero *a)
{
    REQUIRE_ZICBOZ(ctx);
    TCGv src = get_address(ctx, a->rs1, 0);

    gen_helper_cbo_zero(tcg_env, src);
    return true;
}
