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
    /* Stub: always return 0 for now (no tag memory in user-mode) */
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

/* crrl and cram use the @r2 format (existing) */
static bool trans_crrl(DisasContext *ctx, arg_r2 *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    /* Representable length rounding — stub: return input unchanged */
    TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv dst = dest_gpr(ctx, a->rd);
    tcg_gen_mov_tl(dst, src);
    gen_set_gpr(ctx, a->rd, dst);
    return true;
}

static bool trans_cram(DisasContext *ctx, arg_r2 *a)
{
    if (!require_xcheri(ctx)) {
        return false;
    }
    /* Representable alignment mask — stub: return all-ones */
    TCGv dst = dest_gpr(ctx, a->rd);
    tcg_gen_movi_tl(dst, -1);
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
 * CHERI Load/Store stubs — These all return false (unhandled) for now.
 * A full implementation would emit TCG code for capability-bounded
 * memory access.  Returning false causes the decoder to fall through
 * to the next pattern, so standard loads/stores remain functional.
 * ========================================================================== */

#define CHERI_LD_STUB(NAME, FMT)                                         \
static bool trans_ ## NAME(DisasContext *ctx, arg_ ## FMT *a)             \
{ return !require_xcheri(ctx) ? false : false; /* TODO */ }

#define CHERI_ST_STUB(NAME, FMT)                                         \
static bool trans_ ## NAME(DisasContext *ctx, arg_ ## FMT *a)             \
{ return !require_xcheri(ctx) ? false : false; /* TODO */ }

#define CHERI_ATOM_LD_STUB(NAME)                                         \
static bool trans_ ## NAME(DisasContext *ctx, arg_atomic *a)              \
{ return !require_xcheri(ctx) ? false : false; /* TODO */ }

#define CHERI_ATOM_ST_STUB(NAME)                                         \
static bool trans_ ## NAME(DisasContext *ctx, arg_atomic *a)              \
{ return !require_xcheri(ctx) ? false : false; /* TODO */ }

/* Loads via DDC */
CHERI_LD_STUB(ld_b_ddc,  r2)
CHERI_LD_STUB(ld_h_ddc,  r2)
CHERI_LD_STUB(ld_w_ddc,  r2)
CHERI_LD_STUB(ld_d_ddc,  r2)
CHERI_LD_STUB(ld_bu_ddc, r2)
CHERI_LD_STUB(ld_hu_ddc, r2)
CHERI_LD_STUB(ld_wu_ddc, r2)
CHERI_LD_STUB(ld_c_ddc,  r2)

/* Loads via capability */
CHERI_LD_STUB(ld_b_cap,  r2)
CHERI_LD_STUB(ld_h_cap,  r2)
CHERI_LD_STUB(ld_w_cap,  r2)
CHERI_LD_STUB(ld_d_cap,  r2)
CHERI_LD_STUB(ld_bu_cap, r2)
CHERI_LD_STUB(ld_hu_cap, r2)
CHERI_LD_STUB(ld_wu_cap, r2)
CHERI_LD_STUB(ld_c_cap,  r2)

/* Stores via DDC */
CHERI_ST_STUB(st_b_ddc, r_2source)
CHERI_ST_STUB(st_h_ddc, r_2source)
CHERI_ST_STUB(st_w_ddc, r_2source)
CHERI_ST_STUB(st_d_ddc, r_2source)
CHERI_ST_STUB(st_c_ddc, r_2source)

/* Stores via capability */
CHERI_ST_STUB(st_b_cap, r_2source)
CHERI_ST_STUB(st_h_cap, r_2source)
CHERI_ST_STUB(st_w_cap, r_2source)
CHERI_ST_STUB(st_d_cap, r_2source)
CHERI_ST_STUB(st_c_cap, r_2source)

/* LR via DDC and capability */
CHERI_ATOM_LD_STUB(lr_b_ddc)
CHERI_ATOM_LD_STUB(lr_h_ddc)
CHERI_ATOM_LD_STUB(lr_w_ddc)
CHERI_ATOM_LD_STUB(lr_d_ddc)
CHERI_ATOM_LD_STUB(lr_c_ddc)
CHERI_ATOM_LD_STUB(lr_b_cap)
CHERI_ATOM_LD_STUB(lr_h_cap)
CHERI_ATOM_LD_STUB(lr_w_cap)
CHERI_ATOM_LD_STUB(lr_d_cap)
CHERI_ATOM_LD_STUB(lr_c_cap)

/* SC via DDC and capability */
CHERI_ATOM_ST_STUB(sc_b_ddc)
CHERI_ATOM_ST_STUB(sc_h_ddc)
CHERI_ATOM_ST_STUB(sc_w_ddc)
CHERI_ATOM_ST_STUB(sc_d_ddc)
CHERI_ATOM_ST_STUB(sc_c_ddc)
CHERI_ATOM_ST_STUB(sc_b_cap)
CHERI_ATOM_ST_STUB(sc_h_cap)
CHERI_ATOM_ST_STUB(sc_w_cap)
CHERI_ATOM_ST_STUB(sc_d_cap)
CHERI_ATOM_ST_STUB(sc_c_cap)
