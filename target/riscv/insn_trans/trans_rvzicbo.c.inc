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
 * THE ENABLE GATE THE CACHE-BLOCK OPERATIONS ARE SUBJECT TO.
 *
 * `menvcfg.CBIE/CBCFE/CBZE` and `senvcfg`'s copies of the same fields decide
 * whether a cbo.* executes, traps to a higher privilege level, or raises
 * illegal-instruction.  check_zicbo_envcfg() in op_helper.c reads exactly
 * those two members to make that decision -- and it is wrapped in
 * `#ifndef CONFIG_USER_ONLY`, so on a linux-user build the whole check
 * compiles out and NOTHING in the op stream reaches either register.
 *
 * That is a lowering fact and not an architectural one.  R7.4 rules the gate
 * a SOURCE, and it names the RISC-V CSRs alongside the AArch64 CPACR case
 * that motivated the rule: a pending write to the gate must resolve before
 * the instruction may proceed.  R15 says an answer the emulator arranged to
 * have early is not architectural truth, and R16 records an ISA-defined
 * dependency the model does not implement -- the same sentence 22d7666262
 * lands for a feature x86 refuses to execute.
 *
 * THE MEMBERS EXIST ON EVERY BUILD, and that had to be established before a
 * range could be given for them: `menvcfg` and `senvcfg` sit OUTSIDE
 * cpu.h's `#ifndef CONFIG_USER_ONLY` block, so the bytes this names are
 * present and declared on the user-mode target the statement is measured on.
 * Only the READER of them is conditional.
 *
 * BY RANGE rather than by name, on note_vector_config_read()'s reasoning in
 * trans_rvv.c.inc: the range IS the register, the CSR declarations name
 * these bytes already, and named_reads[] is a four-entry record an operand
 * has a better claim on.
 *
 * BOTH are stated, because both are gates and which one applies is a
 * function of the CURRENT PRIVILEGE LEVEL rather than of the encoding:
 * menvcfg governs below M, senvcfg additionally below S.  A decode site that
 * named only one would be picking a privilege level the encoding does not
 * carry.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
static void note_cbo_envcfg_read(void)
{
    insn_dataflow_note_stated_read_env(
        offsetof(CPURISCVState, menvcfg),
        sizeof(((CPURISCVState *)0)->menvcfg));
    insn_dataflow_note_stated_read_env(
        offsetof(CPURISCVState, senvcfg),
        sizeof(((CPURISCVState *)0)->senvcfg));
}

static bool trans_cbo_clean(DisasContext *ctx, arg_cbo_clean *a)
{
    REQUIRE_ZICBOM(ctx);
    TCGv src = get_address(ctx, a->rs1, 0);

    /* The CBCFE gate; see note_cbo_envcfg_read(). */
    note_cbo_envcfg_read();
    gen_helper_cbo_clean_flush(tcg_env, src);
    return true;
}

static bool trans_cbo_flush(DisasContext *ctx, arg_cbo_flush *a)
{
    REQUIRE_ZICBOM(ctx);
    TCGv src = get_address(ctx, a->rs1, 0);

    /* The CBCFE gate; see note_cbo_envcfg_read(). */
    note_cbo_envcfg_read();
    gen_helper_cbo_clean_flush(tcg_env, src);
    return true;
}

static bool trans_cbo_inval(DisasContext *ctx, arg_cbo_inval *a)
{
    REQUIRE_ZICBOM(ctx);
    TCGv src = get_address(ctx, a->rs1, 0);

    /* The CBIE gate; see note_cbo_envcfg_read(). */
    note_cbo_envcfg_read();
    gen_helper_cbo_inval(tcg_env, src);
    return true;
}

static bool trans_cbo_zero(DisasContext *ctx, arg_cbo_zero *a)
{
    REQUIRE_ZICBOZ(ctx);
    TCGv src = get_address(ctx, a->rs1, 0);

    /* The CBZE gate; see note_cbo_envcfg_read(). */
    note_cbo_envcfg_read();
    gen_helper_cbo_zero(tcg_env, src);
    return true;
}
