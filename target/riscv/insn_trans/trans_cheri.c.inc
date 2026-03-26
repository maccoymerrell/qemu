/*
 * CHERI RISC-V instruction translation
 *
 * Adapted from the CTSRD-CHERI/qemu implementation.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020-2023 University of Cambridge
 * Copyright (c) 2020-2023 SRI International
 */

/*
 * This file is included from translate.c and uses the DisasContext and
 * TCG machinery defined there.
 */

static bool require_xcheri(DisasContext *ctx)
{
    return ctx->cfg_ptr->ext_xcheri;
}

/* ---------- Capability inspection (rd = f(cs1)) ---------- */

#define GEN_CHERI_INSPECT(NAME)                                          \
static bool trans_ ## NAME(DisasContext *ctx, arg_rc *a)                  \
{                                                                        \
    if (!require_xcheri(ctx)) return false;                              \
    TCGv dst = dest_gpr(ctx, a->rd);                                     \
    TCGv_i32 rd_i = tcg_constant_i32(a->rd);                            \
    TCGv_i32 cs1_i = tcg_constant_i32(a->cs1);                          \
    gen_helper_cheri_ ## NAME(dst, tcg_env, rd_i, cs1_i);                \
    gen_set_gpr(ctx, a->rd, dst);                                        \
    return true;                                                         \
}

GEN_CHERI_INSPECT(cgetperm)
GEN_CHERI_INSPECT(cgettype)
GEN_CHERI_INSPECT(cgetbase)
GEN_CHERI_INSPECT(cgetlen)
GEN_CHERI_INSPECT(cgettag)
GEN_CHERI_INSPECT(cgetsealed)
GEN_CHERI_INSPECT(cgetoffset)
GEN_CHERI_INSPECT(cgetflags)
GEN_CHERI_INSPECT(cgetaddr)
GEN_CHERI_INSPECT(cgethigh)

/* cloadtags: rd = tag bits for aligned group at address in cs1 */
static bool trans_cloadtags(DisasContext *ctx, arg_rc *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    /*
     * CLoadTags loads the tag bits for a capability-aligned group of
     * memory.  A full implementation would load 8 tag bits (for 8
     * consecutive cap-aligned granules).  For now, we return 0 as tag
     * memory queries require physical address translation.
     *
     * In system mode, this would be implemented via a helper that
     * translates the virtual address to physical and queries the tag
     * table.
     */
    TCGv dst = dest_gpr(ctx, a->rd);
    tcg_gen_movi_tl(dst, 0);
    gen_set_gpr(ctx, a->rd, dst);
    return true;
}

/* ---------- Capability modification (cd = f(cs1, rs2)) ---------- */

#define GEN_CHERI_MODIFY_CCR(NAME)                                       \
static bool trans_ ## NAME(DisasContext *ctx, arg_ccr *a)                 \
{                                                                        \
    if (!require_xcheri(ctx)) return false;                              \
    TCGv rs2_val = get_gpr(ctx, a->rs2, EXT_NONE);                      \
    TCGv_i32 cd_i = tcg_constant_i32(a->cd);                            \
    TCGv_i32 cs1_i = tcg_constant_i32(a->cs1);                          \
    gen_helper_cheri_ ## NAME(tcg_env, cd_i, cs1_i, rs2_val);            \
    /* Helper writes both gpcr[cd] and gpr[cd] */                        \
    if (a->cd != 0) {                                                    \
        TCGv dst = dest_gpr(ctx, a->cd);                                 \
        tcg_gen_ld_tl(dst, tcg_env,                                      \
                      offsetof(CPURISCVState, gpr[a->cd]));              \
        gen_set_gpr(ctx, a->cd, dst);                                    \
    }                                                                    \
    return true;                                                         \
}

GEN_CHERI_MODIFY_CCR(csetbounds)
GEN_CHERI_MODIFY_CCR(csetboundsexact)
GEN_CHERI_MODIFY_CCR(candperm)
GEN_CHERI_MODIFY_CCR(csetflags)
GEN_CHERI_MODIFY_CCR(csetoffset)
GEN_CHERI_MODIFY_CCR(csetaddr)
GEN_CHERI_MODIFY_CCR(cincoffset)
GEN_CHERI_MODIFY_CCR(csethigh)

/* cfromptr: cd = f(cs1, rs2) but rs2 is the pointer value */
static bool trans_cfromptr(DisasContext *ctx, arg_ccr *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv rs2_val = get_gpr(ctx, a->rs2, EXT_NONE);
    TCGv_i32 cd_i = tcg_constant_i32(a->cd);
    TCGv_i32 cs1_i = tcg_constant_i32(a->cs1);
    gen_helper_cheri_cfromptr(tcg_env, cd_i, cs1_i, rs2_val);
    if (a->cd != 0) {
        TCGv dst = dest_gpr(ctx, a->cd);
        tcg_gen_ld_tl(dst, tcg_env,
                      offsetof(CPURISCVState, gpr[a->cd]));
        gen_set_gpr(ctx, a->cd, dst);
    }
    return true;
}

/* ---------- Cap-Cap-Cap operations (cd = f(cs1, cs2)) ---------- */

#define GEN_CHERI_CCC(NAME)                                              \
static bool trans_ ## NAME(DisasContext *ctx, arg_ccc *a)                 \
{                                                                        \
    if (!require_xcheri(ctx)) return false;                              \
    TCGv_i32 cd_i = tcg_constant_i32(a->cd);                            \
    TCGv_i32 cs1_i = tcg_constant_i32(a->cs1);                          \
    TCGv_i32 cs2_i = tcg_constant_i32(a->cs2);                          \
    gen_helper_cheri_ ## NAME(tcg_env, cd_i, cs1_i, cs2_i);              \
    if (a->cd != 0) {                                                    \
        TCGv dst = dest_gpr(ctx, a->cd);                                 \
        tcg_gen_ld_tl(dst, tcg_env,                                      \
                      offsetof(CPURISCVState, gpr[a->cd]));              \
        gen_set_gpr(ctx, a->cd, dst);                                    \
    }                                                                    \
    return true;                                                         \
}

GEN_CHERI_CCC(cseal)
GEN_CHERI_CCC(cunseal)
GEN_CHERI_CCC(cbuildcap)
GEN_CHERI_CCC(ccopytype)
GEN_CHERI_CCC(ccseal)
GEN_CHERI_CCC(cspecialrw)

/* ---------- Reg-Cap-Cap operations (rd = f(cs1, cs2)) ---------- */

#define GEN_CHERI_RCC(NAME)                                              \
static bool trans_ ## NAME(DisasContext *ctx, arg_rcc *a)                 \
{                                                                        \
    if (!require_xcheri(ctx)) return false;                              \
    TCGv dst = dest_gpr(ctx, a->rd);                                     \
    TCGv_i32 rd_i = tcg_constant_i32(a->rd);                            \
    TCGv_i32 cs1_i = tcg_constant_i32(a->cs1);                          \
    TCGv_i32 cs2_i = tcg_constant_i32(a->cs2);                          \
    gen_helper_cheri_ ## NAME(dst, tcg_env, rd_i, cs1_i, cs2_i);         \
    gen_set_gpr(ctx, a->rd, dst);                                        \
    return true;                                                         \
}

GEN_CHERI_RCC(ctestsubset)
GEN_CHERI_RCC(ctoptr)
GEN_CHERI_RCC(csub)
GEN_CHERI_RCC(cseqx)

/* ---------- Cap-Cap operations (cd = f(cs1)) ---------- */

#define GEN_CHERI_CC(NAME)                                               \
static bool trans_ ## NAME(DisasContext *ctx, arg_cc *a)                  \
{                                                                        \
    if (!require_xcheri(ctx)) return false;                              \
    TCGv_i32 cd_i = tcg_constant_i32(a->cd);                            \
    TCGv_i32 cs1_i = tcg_constant_i32(a->cs1);                          \
    gen_helper_cheri_ ## NAME(tcg_env, cd_i, cs1_i);                     \
    if (a->cd != 0) {                                                    \
        TCGv dst = dest_gpr(ctx, a->cd);                                 \
        tcg_gen_ld_tl(dst, tcg_env,                                      \
                      offsetof(CPURISCVState, gpr[a->cd]));              \
        gen_set_gpr(ctx, a->cd, dst);                                    \
    }                                                                    \
    return true;                                                         \
}

GEN_CHERI_CC(cmv)
GEN_CHERI_CC(ccleartag)
GEN_CHERI_CC(csealentry)

/* ---------- Immediate operations ---------- */

static bool trans_caddi(DisasContext *ctx, arg_cci *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    /* First perform the integer add (cs1 + imm) into gpr[cd] */
    TCGv src = get_gpr(ctx, a->cs1, EXT_NONE);
    TCGv dst = dest_gpr(ctx, a->cd);
    tcg_gen_addi_tl(dst, src, a->imm);
    gen_set_gpr(ctx, a->cd, dst);

    /* Then sync the capability register */
    TCGv_i32 cd_i = tcg_constant_i32(a->cd);
    TCGv_i32 cs1_i = tcg_constant_i32(a->cs1);
    gen_helper_cheri_caddi(tcg_env, cd_i, cs1_i);
    return true;
}

static bool trans_csetboundsimm(DisasContext *ctx, arg_cci *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv len = tcg_constant_tl((target_ulong)(uint32_t)a->imm);
    TCGv_i32 cd_i = tcg_constant_i32(a->cd);
    TCGv_i32 cs1_i = tcg_constant_i32(a->cs1);
    gen_helper_cheri_csetboundsimm(tcg_env, cd_i, cs1_i, len);
    if (a->cd != 0) {
        TCGv dst2 = dest_gpr(ctx, a->cd);
        tcg_gen_ld_tl(dst2, tcg_env,
                      offsetof(CPURISCVState, gpr[a->cd]));
        gen_set_gpr(ctx, a->cd, dst2);
    }
    return true;
}

/* ---------- Branch instructions ---------- */

static bool trans_jalr_cap(DisasContext *ctx, arg_cc *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }

    /* Save return address (pc + 4) into cd as a capability */
    if (a->cd != 0) {
        TCGv ret_addr = dest_gpr(ctx, a->cd);
        tcg_gen_movi_tl(ret_addr, ctx->base.pc_next + 4);
        gen_set_gpr(ctx, a->cd, ret_addr);
        /* Also update the capability register cursor */
        TCGv_i32 cd_i = tcg_constant_i32(a->cd);
        TCGv_i32 cs1_zero = tcg_constant_i32(a->cd);
        gen_helper_cheri_caddi(tcg_env, cd_i, cs1_zero);
    }

    /* Jump to target capability */
    TCGv new_pc = tcg_temp_new();
    TCGv_i32 cs1_i = tcg_constant_i32(a->cs1);
    gen_helper_cheri_jalr_cap(new_pc, tcg_env, cs1_i);
    gen_set_pc(ctx, new_pc);
    lookup_and_goto_ptr(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
}

static bool trans_jalr_pcc(DisasContext *ctx, arg_r2 *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }

    /* Save return address capability to rd */
    if (a->rd != 0) {
        TCGv ret_addr = dest_gpr(ctx, a->rd);
        tcg_gen_movi_tl(ret_addr, ctx->base.pc_next + 4);
        gen_set_gpr(ctx, a->rd, ret_addr);
    }

    /* Jump within PCC bounds */
    TCGv addr = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv new_pc = tcg_temp_new();
    gen_helper_cheri_jalr_pcc(new_pc, tcg_env, addr);
    gen_set_pc(ctx, new_pc);
    lookup_and_goto_ptr(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
}

/* crrl: representable length rounding (CC128) */
static bool trans_crrl(DisasContext *ctx, arg_r2 *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    /*
     * CRRL computes the smallest representable length >= input.
     * We implement this inline using the CC128 algorithm:
     * find the exponent, then round up to the corresponding granule.
     */
    TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv dst = dest_gpr(ctx, a->rd);

    /* For simplicity, call into a helper-like inline computation.
     * The CC128 representable length is computed at runtime. */
    TCGv_i32 dummy = tcg_constant_i32(0);
    /* Use src as length, compute representable length */
    /* Inline: if length fits in 9 bits, return as-is.
     * Otherwise, round up to nearest 2^E boundary. */
    TCGv one = tcg_constant_tl(1);
    TCGv mask = tcg_temp_new();
    TCGv shift = tcg_temp_new();
    TCGv msb = tcg_temp_new();
    TCGv result = tcg_temp_new();

    /* Compute msb = 63 - clz(src) */
    tcg_gen_clzi_tl(msb, src, TARGET_LONG_BITS);
    tcg_gen_subfi_tl(msb, TARGET_LONG_BITS - 1, msb);

    /* If msb < 9, result = src (exact) */
    /* Otherwise, E = msb - 8; mask = (1<<E) - 1; result = (src+mask) & ~mask */
    tcg_gen_subfi_tl(shift, CC128_MANTISSA_BITS - 1, msb);
    /* shift is negative when E > 0 */
    tcg_gen_subi_tl(shift, msb, CC128_MANTISSA_BITS - 1);
    /* E = max(0, msb - 8) */
    TCGv zero = tcg_constant_tl(0);
    tcg_gen_movcond_tl(TCG_COND_LT, shift, shift, zero, zero, shift);
    /* mask = (1 << E) - 1 */
    tcg_gen_shl_tl(mask, one, shift);
    tcg_gen_subi_tl(mask, mask, 1);
    /* result = (src + mask) & ~mask */
    tcg_gen_add_tl(result, src, mask);
    tcg_gen_not_tl(mask, mask);
    tcg_gen_and_tl(result, result, mask);
    /* If src == 0, result = 0 */
    tcg_gen_movcond_tl(TCG_COND_EQ, dst, src, zero, zero, result);

    gen_set_gpr(ctx, a->rd, dst);
    return true;
}

static bool trans_cram(DisasContext *ctx, arg_r2 *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    /*
     * CRAM computes the representable alignment mask for a length.
     * mask = ~((1 << E) - 1), where E = max(0, msb(length) - 8).
     */
    TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv dst = dest_gpr(ctx, a->rd);
    TCGv one = tcg_constant_tl(1);
    TCGv msb = tcg_temp_new();
    TCGv shift = tcg_temp_new();
    TCGv mask = tcg_temp_new();
    TCGv zero = tcg_constant_tl(0);
    TCGv all_ones = tcg_constant_tl(-1);

    tcg_gen_clzi_tl(msb, src, TARGET_LONG_BITS);
    tcg_gen_subfi_tl(msb, TARGET_LONG_BITS - 1, msb);
    tcg_gen_subi_tl(shift, msb, CC128_MANTISSA_BITS - 1);
    tcg_gen_movcond_tl(TCG_COND_LT, shift, shift, zero, zero, shift);
    tcg_gen_shl_tl(mask, one, shift);
    tcg_gen_subi_tl(mask, mask, 1);
    tcg_gen_not_tl(mask, mask);
    /* If src == 0, return all-ones */
    tcg_gen_movcond_tl(TCG_COND_EQ, dst, src, zero, all_ones, mask);

    gen_set_gpr(ctx, a->rd, dst);
    return true;
}

/* cinvoke — not commonly used, stub as illegal */
static bool trans_cinvoke(DisasContext *ctx, arg_r_2source *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    generate_exception(ctx, RISCV_EXCP_ILLEGAL_INST);
    return true;
}

/* ==========================================================================
 * CHERI Load/Store via DDC — bounds-checked loads/stores through DDC.
 *
 * These call TCG helpers that verify DDC tag, seal, permissions, and bounds
 * before performing the memory access.
 * ========================================================================== */

/* Load via DDC: rd = mem[DDC.base + rs1] */
static bool gen_cheri_load_ddc(DisasContext *ctx, int rd, int rs1,
                               MemOp memop)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv addr = get_gpr(ctx, rs1, EXT_NONE);
    TCGv dst = dest_gpr(ctx, rd);
    TCGv_i32 mop = tcg_constant_i32(memop & MO_SIZE);

    gen_helper_cheri_load_ddc(dst, tcg_env, addr, mop);

    /* Sign extend if needed */
    switch (memop) {
    case MO_SB:
        tcg_gen_ext8s_tl(dst, dst);
        break;
    case MO_TESW:
        tcg_gen_ext16s_tl(dst, dst);
        break;
    case MO_TESL:
        tcg_gen_ext32s_tl(dst, dst);
        break;
    default:
        break;
    }

    gen_set_gpr(ctx, rd, dst);
    return true;
}

/* Store via DDC: mem[DDC.base + rs1] = rs2 */
static bool gen_cheri_store_ddc(DisasContext *ctx, int rs1, int rs2,
                                MemOp memop)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv addr = get_gpr(ctx, rs1, EXT_NONE);
    TCGv data = get_gpr(ctx, rs2, EXT_NONE);
    TCGv_i32 mop = tcg_constant_i32(memop & MO_SIZE);

    gen_helper_cheri_store_ddc(tcg_env, addr, data, mop);
    return true;
}

/* Loads via DDC */
static bool trans_ld_b_ddc(DisasContext *ctx, arg_r2 *a)
{ return gen_cheri_load_ddc(ctx, a->rd, a->rs1, MO_SB); }

static bool trans_ld_h_ddc(DisasContext *ctx, arg_r2 *a)
{ return gen_cheri_load_ddc(ctx, a->rd, a->rs1, MO_TESW); }

static bool trans_ld_w_ddc(DisasContext *ctx, arg_r2 *a)
{ return gen_cheri_load_ddc(ctx, a->rd, a->rs1, MO_TESL); }

static bool trans_ld_d_ddc(DisasContext *ctx, arg_r2 *a)
{ return gen_cheri_load_ddc(ctx, a->rd, a->rs1, MO_TEUQ); }

static bool trans_ld_bu_ddc(DisasContext *ctx, arg_r2 *a)
{ return gen_cheri_load_ddc(ctx, a->rd, a->rs1, MO_UB); }

static bool trans_ld_hu_ddc(DisasContext *ctx, arg_r2 *a)
{ return gen_cheri_load_ddc(ctx, a->rd, a->rs1, MO_TEUW); }

static bool trans_ld_wu_ddc(DisasContext *ctx, arg_r2 *a)
{ return gen_cheri_load_ddc(ctx, a->rd, a->rs1, MO_TEUL); }

/* LC via DDC */
static bool trans_ld_c_ddc(DisasContext *ctx, arg_r2 *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv addr = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv_i32 cd = tcg_constant_i32(a->rd);
    gen_helper_cheri_load_cap_ddc(tcg_env, cd, addr);
    /* Reload gpr from the helper result */
    if (a->rd != 0) {
        TCGv dst = dest_gpr(ctx, a->rd);
        tcg_gen_ld_tl(dst, tcg_env,
                      offsetof(CPURISCVState, gpr[a->rd]));
        gen_set_gpr(ctx, a->rd, dst);
    }
    return true;
}

/* Stores via DDC */
static bool trans_st_b_ddc(DisasContext *ctx, arg_r_2source *a)
{ return gen_cheri_store_ddc(ctx, a->rs1, a->rs2, MO_UB); }

static bool trans_st_h_ddc(DisasContext *ctx, arg_r_2source *a)
{ return gen_cheri_store_ddc(ctx, a->rs1, a->rs2, MO_TEUW); }

static bool trans_st_w_ddc(DisasContext *ctx, arg_r_2source *a)
{ return gen_cheri_store_ddc(ctx, a->rs1, a->rs2, MO_TEUL); }

static bool trans_st_d_ddc(DisasContext *ctx, arg_r_2source *a)
{ return gen_cheri_store_ddc(ctx, a->rs1, a->rs2, MO_TEUQ); }

/* SC via DDC */
static bool trans_st_c_ddc(DisasContext *ctx, arg_r_2source *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv addr = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv_i32 cs2 = tcg_constant_i32(a->rs2);
    gen_helper_cheri_store_cap_ddc(tcg_env, cs2, addr);
    return true;
}

/* ==========================================================================
 * CHERI Load/Store via Capability register
 *
 * Effective address = cap[cs1].cursor + rs2 (for loads, rd = cs1 in @r2)
 * ========================================================================== */

/* Load via capability: rd = mem[cap[cs1].cursor + 0] */
static bool gen_cheri_load_cap_reg(DisasContext *ctx, int rd, int cs1,
                                   MemOp memop)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv offset = tcg_constant_tl(0);
    TCGv dst = dest_gpr(ctx, rd);
    TCGv_i32 cs1_i = tcg_constant_i32(cs1);
    TCGv_i32 mop = tcg_constant_i32(memop & MO_SIZE);

    gen_helper_cheri_load_cap(dst, tcg_env, cs1_i, offset, mop);

    switch (memop) {
    case MO_SB:
        tcg_gen_ext8s_tl(dst, dst);
        break;
    case MO_TESW:
        tcg_gen_ext16s_tl(dst, dst);
        break;
    case MO_TESL:
        tcg_gen_ext32s_tl(dst, dst);
        break;
    default:
        break;
    }

    gen_set_gpr(ctx, rd, dst);
    return true;
}

/* Store via capability: mem[cap[cs1].cursor + 0] = rs2 */
static bool gen_cheri_store_cap_reg(DisasContext *ctx, int cs1, int rs2,
                                    MemOp memop)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv offset = tcg_constant_tl(0);
    TCGv data = get_gpr(ctx, rs2, EXT_NONE);
    TCGv_i32 cs1_i = tcg_constant_i32(cs1);
    TCGv_i32 mop = tcg_constant_i32(memop & MO_SIZE);

    gen_helper_cheri_store_cap(tcg_env, cs1_i, offset, data, mop);
    return true;
}

/* Loads via capability register */
static bool trans_ld_b_cap(DisasContext *ctx, arg_r2 *a)
{ return gen_cheri_load_cap_reg(ctx, a->rd, a->rs1, MO_SB); }

static bool trans_ld_h_cap(DisasContext *ctx, arg_r2 *a)
{ return gen_cheri_load_cap_reg(ctx, a->rd, a->rs1, MO_TESW); }

static bool trans_ld_w_cap(DisasContext *ctx, arg_r2 *a)
{ return gen_cheri_load_cap_reg(ctx, a->rd, a->rs1, MO_TESL); }

static bool trans_ld_d_cap(DisasContext *ctx, arg_r2 *a)
{ return gen_cheri_load_cap_reg(ctx, a->rd, a->rs1, MO_TEUQ); }

static bool trans_ld_bu_cap(DisasContext *ctx, arg_r2 *a)
{ return gen_cheri_load_cap_reg(ctx, a->rd, a->rs1, MO_UB); }

static bool trans_ld_hu_cap(DisasContext *ctx, arg_r2 *a)
{ return gen_cheri_load_cap_reg(ctx, a->rd, a->rs1, MO_TEUW); }

static bool trans_ld_wu_cap(DisasContext *ctx, arg_r2 *a)
{ return gen_cheri_load_cap_reg(ctx, a->rd, a->rs1, MO_TEUL); }

/* LC via capability */
static bool trans_ld_c_cap(DisasContext *ctx, arg_r2 *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv offset = tcg_constant_tl(0);
    TCGv_i32 cd = tcg_constant_i32(a->rd);
    TCGv_i32 cs1 = tcg_constant_i32(a->rs1);
    gen_helper_cheri_load_cap_via_cap(tcg_env, cd, cs1, offset);
    if (a->rd != 0) {
        TCGv dst = dest_gpr(ctx, a->rd);
        tcg_gen_ld_tl(dst, tcg_env,
                      offsetof(CPURISCVState, gpr[a->rd]));
        gen_set_gpr(ctx, a->rd, dst);
    }
    return true;
}

/* Stores via capability register */
static bool trans_st_b_cap(DisasContext *ctx, arg_r_2source *a)
{ return gen_cheri_store_cap_reg(ctx, a->rs1, a->rs2, MO_UB); }

static bool trans_st_h_cap(DisasContext *ctx, arg_r_2source *a)
{ return gen_cheri_store_cap_reg(ctx, a->rs1, a->rs2, MO_TEUW); }

static bool trans_st_w_cap(DisasContext *ctx, arg_r_2source *a)
{ return gen_cheri_store_cap_reg(ctx, a->rs1, a->rs2, MO_TEUL); }

static bool trans_st_d_cap(DisasContext *ctx, arg_r_2source *a)
{ return gen_cheri_store_cap_reg(ctx, a->rs1, a->rs2, MO_TEUQ); }

/* SC via capability */
static bool trans_st_c_cap(DisasContext *ctx, arg_r_2source *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv offset = tcg_constant_tl(0);
    TCGv_i32 cs2 = tcg_constant_i32(a->rs2);
    TCGv_i32 cs1 = tcg_constant_i32(a->rs1);
    gen_helper_cheri_store_cap_via_cap(tcg_env, cs2, cs1, offset);
    return true;
}

/* ==========================================================================
 * Atomic LR/SC via DDC
 * ========================================================================== */

static bool gen_cheri_lr_ddc(DisasContext *ctx, int rd, int rs1,
                             MemOp memop)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv addr = get_gpr(ctx, rs1, EXT_NONE);
    TCGv dst = dest_gpr(ctx, rd);
    TCGv_i32 mop = tcg_constant_i32(memop & MO_SIZE);

    gen_helper_cheri_lr_ddc(dst, tcg_env, addr, mop);

    switch (memop) {
    case MO_SB:
        tcg_gen_ext8s_tl(dst, dst);
        break;
    case MO_TESW:
        tcg_gen_ext16s_tl(dst, dst);
        break;
    case MO_TESL:
        tcg_gen_ext32s_tl(dst, dst);
        break;
    default:
        break;
    }

    gen_set_gpr(ctx, rd, dst);
    return true;
}

static bool gen_cheri_sc_ddc(DisasContext *ctx, int rd, int rs1, int rs2,
                             MemOp memop)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv addr = get_gpr(ctx, rs1, EXT_NONE);
    TCGv data = get_gpr(ctx, rs2, EXT_NONE);
    TCGv dst = dest_gpr(ctx, rd);
    TCGv_i32 mop = tcg_constant_i32(memop & MO_SIZE);

    gen_helper_cheri_sc_ddc(dst, tcg_env, addr, data, mop);
    gen_set_gpr(ctx, rd, dst);
    return true;
}

/* LR via DDC */
static bool trans_lr_b_ddc(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_lr_ddc(ctx, a->rd, a->rs1, MO_SB); }

static bool trans_lr_h_ddc(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_lr_ddc(ctx, a->rd, a->rs1, MO_TESW); }

static bool trans_lr_w_ddc(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_lr_ddc(ctx, a->rd, a->rs1, MO_TESL); }

static bool trans_lr_d_ddc(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_lr_ddc(ctx, a->rd, a->rs1, MO_TEUQ); }

static bool trans_lr_c_ddc(DisasContext *ctx, arg_atomic *a)
{
    /* LR.C via DDC: load-reserve a full capability */
    if (!require_xcheri(ctx)) {
        return false;
    }
    /* For capability LR, just do a regular LC + set reservation */
    TCGv addr = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv_i32 cd = tcg_constant_i32(a->rd);
    gen_helper_cheri_load_cap_ddc(tcg_env, cd, addr);
    if (a->rd != 0) {
        TCGv dst = dest_gpr(ctx, a->rd);
        tcg_gen_ld_tl(dst, tcg_env,
                      offsetof(CPURISCVState, gpr[a->rd]));
        gen_set_gpr(ctx, a->rd, dst);
    }
    return true;
}

/* SC via DDC */
static bool trans_sc_b_ddc(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_sc_ddc(ctx, a->rd, a->rs1, a->rs2, MO_UB); }

static bool trans_sc_h_ddc(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_sc_ddc(ctx, a->rd, a->rs1, a->rs2, MO_TEUW); }

static bool trans_sc_w_ddc(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_sc_ddc(ctx, a->rd, a->rs1, a->rs2, MO_TEUL); }

static bool trans_sc_d_ddc(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_sc_ddc(ctx, a->rd, a->rs1, a->rs2, MO_TEUQ); }

static bool trans_sc_c_ddc(DisasContext *ctx, arg_atomic *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv addr = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv_i32 cs2 = tcg_constant_i32(a->rs2);
    gen_helper_cheri_store_cap_ddc(tcg_env, cs2, addr);
    /* SC.C always succeeds in this simplified impl */
    if (a->rd != 0) {
        TCGv dst = dest_gpr(ctx, a->rd);
        tcg_gen_movi_tl(dst, 0);
        gen_set_gpr(ctx, a->rd, dst);
    }
    return true;
}

/* ==========================================================================
 * Atomic LR/SC via Capability register
 * ========================================================================== */

static bool gen_cheri_lr_cap_reg(DisasContext *ctx, int rd, int cs1,
                                 MemOp memop)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv offset = tcg_constant_tl(0);
    TCGv dst = dest_gpr(ctx, rd);
    TCGv_i32 cs1_i = tcg_constant_i32(cs1);
    TCGv_i32 mop = tcg_constant_i32(memop & MO_SIZE);

    gen_helper_cheri_lr_cap(dst, tcg_env, cs1_i, offset, mop);

    switch (memop) {
    case MO_SB:
        tcg_gen_ext8s_tl(dst, dst);
        break;
    case MO_TESW:
        tcg_gen_ext16s_tl(dst, dst);
        break;
    case MO_TESL:
        tcg_gen_ext32s_tl(dst, dst);
        break;
    default:
        break;
    }

    gen_set_gpr(ctx, rd, dst);
    return true;
}

static bool gen_cheri_sc_cap_reg(DisasContext *ctx, int rd, int cs1, int rs2,
                                 MemOp memop)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv offset = tcg_constant_tl(0);
    TCGv data = get_gpr(ctx, rs2, EXT_NONE);
    TCGv dst = dest_gpr(ctx, rd);
    TCGv_i32 cs1_i = tcg_constant_i32(cs1);
    TCGv_i32 mop = tcg_constant_i32(memop & MO_SIZE);

    gen_helper_cheri_sc_cap(dst, tcg_env, cs1_i, offset, data, mop);
    gen_set_gpr(ctx, rd, dst);
    return true;
}

/* LR via capability */
static bool trans_lr_b_cap(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_lr_cap_reg(ctx, a->rd, a->rs1, MO_SB); }

static bool trans_lr_h_cap(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_lr_cap_reg(ctx, a->rd, a->rs1, MO_TESW); }

static bool trans_lr_w_cap(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_lr_cap_reg(ctx, a->rd, a->rs1, MO_TESL); }

static bool trans_lr_d_cap(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_lr_cap_reg(ctx, a->rd, a->rs1, MO_TEUQ); }

static bool trans_lr_c_cap(DisasContext *ctx, arg_atomic *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv offset = tcg_constant_tl(0);
    TCGv_i32 cd = tcg_constant_i32(a->rd);
    TCGv_i32 cs1 = tcg_constant_i32(a->rs1);
    gen_helper_cheri_load_cap_via_cap(tcg_env, cd, cs1, offset);
    if (a->rd != 0) {
        TCGv dst = dest_gpr(ctx, a->rd);
        tcg_gen_ld_tl(dst, tcg_env,
                      offsetof(CPURISCVState, gpr[a->rd]));
        gen_set_gpr(ctx, a->rd, dst);
    }
    return true;
}

/* SC via capability */
static bool trans_sc_b_cap(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_sc_cap_reg(ctx, a->rd, a->rs1, a->rs2, MO_UB); }

static bool trans_sc_h_cap(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_sc_cap_reg(ctx, a->rd, a->rs1, a->rs2, MO_TEUW); }

static bool trans_sc_w_cap(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_sc_cap_reg(ctx, a->rd, a->rs1, a->rs2, MO_TEUL); }

static bool trans_sc_d_cap(DisasContext *ctx, arg_atomic *a)
{ return gen_cheri_sc_cap_reg(ctx, a->rd, a->rs1, a->rs2, MO_TEUQ); }

static bool trans_sc_c_cap(DisasContext *ctx, arg_atomic *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    TCGv offset = tcg_constant_tl(0);
    TCGv_i32 cs2 = tcg_constant_i32(a->rs2);
    TCGv_i32 cs1 = tcg_constant_i32(a->rs1);
    gen_helper_cheri_store_cap_via_cap(tcg_env, cs2, cs1, offset);
    if (a->rd != 0) {
        TCGv dst = dest_gpr(ctx, a->rd);
        tcg_gen_movi_tl(dst, 0);
        gen_set_gpr(ctx, a->rd, dst);
    }
    return true;
}
