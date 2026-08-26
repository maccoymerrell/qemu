/*
 * CP-H per-helper usage -- mipsel.  GENERATED, do not edit.
 *
 * Generator: contrib/plugins/champsim_tracer/tools/arc3_cov/
 *            helper_usage/gen_table.py
 * Subjects:  the helpers an OBSERVED run reached (the CP-H census,
 *            QEMU_DF_HELPER_CENSUS), never a list from memory.
 * Facts:     read off the PREPROCESSED body of each helper -- R5,
 *            "if the information is in a macro body, expand the
 *            macro" -- and every field name below was accepted by
 *            offsetof(CPUArchState, ...) before it was written.
 *
 * Every field name was accepted on EVERY configured target that
 * compiles this file (they define TARGET_MIPS): mips-linux-user, mips-softmmu, mips64-linux-user, mips64-softmmu, mips64el-linux-user, mips64el-softmmu, mipsel-linux-user, mipsel-softmmu, mipsn32-linux-user, mipsn32el-linux-user.
 *
 * Rows refused, and therefore still OVER-APPROXIMATED at run time:
 *   (none)
 *
 * Rows the mechanical reader refused and a HAND enumeration supplies.
 * Each carries its justification in full:
 *   lookup_tb_ptr:
 *     The mechanical reader refuses this helper because tb_lookup() reaches
 *     tb_lookup_cmp(), which calls get_page_addr_code(desc->env,
 *     virt_page1) -- an INSTRUCTION FETCH address translation on the
 *     hash-table miss path (accel/tcg/cpu-exec.c tb_lookup_cmp). The row
 *     below states the only CPUArchState access on the path that returns:
 *     cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags) at
 *     ../target/mips/cpu.h:1429, whose read set is derived by the same
 *     reader and is listed here verbatim. It writes nothing: no member
 *     appears on the left of an assignment in that function. The fetch is
 *     not in the model on any instruction -- no instruction records reading
 *     its own encoding -- so leaving it out is the same treatment every
 *     other instruction already gets, not an exception made for this one.
 *     Every field below is marked DF_HF_XLAT: these are the members
 *     cpu_get_tb_cpu_state() reads to compute the TB LOOKUP KEY, not
 *     operands of the guest instruction that chained. They are enumerated
 *     so the row accounts for the whole footprint, and not published,
 *     because a `ret` does not depend on the vector type register.
 */

static const DfHelperField dfu_cfc1_env[] = {
    { offsetof(CPUArchState, CP0_Config5), sizeof(((CPUArchState *)0)->CP0_Config5), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:52 */
    { offsetof(CPUArchState, CP0_Status), sizeof(((CPUArchState *)0)->CP0_Status), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:54 */
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:47 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_le_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:1838 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_ule_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:1814 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_un_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:1798 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_eq_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:1879 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_le_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:1917 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_lt_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:1911 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_add_d_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:1222 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_add_s_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:1232 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvt_w_s_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:387 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvtd_s_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:253 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_div_s_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:1340 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_mul_d_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:1294 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_mul_s_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:1304 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_sqrt_d_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:237 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_sqrt_s_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:244 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_sub_d_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:1258 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_sub_s_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:1268 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_trunc_w_d_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:504 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_trunc_w_s_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/fpu_helper.c:517 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_raise_exception_env[] = {
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_raise_exception_err_env[] = {
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_swl_env[] = {
    { offsetof(CPUArchState, CP0_Config0), sizeof(((CPUArchState *)0)->CP0_Config0), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/mips/internal.h:346 */
};
static const DfHelperField dfu_swr_env[] = {
    { offsetof(CPUArchState, CP0_Config0), sizeof(((CPUArchState *)0)->CP0_Config0), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/mips/internal.h:346 */
};
static const DfHelperField dfu_lookup_tb_ptr_env[] = {
    { offsetof(CPUArchState, active_tc), sizeof(((CPUArchState *)0)->active_tc), INSN_DF_RD, DF_HF_XLAT },   /* ../target/mips/cpu.h:1432 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_XLAT },   /* ../target/mips/cpu.h:1434 */
};

static const DfHelperUsage df_helper_usage[] = {
    { "cfc1", { 0 },
      dfu_cfc1_env, ARRAY_SIZE(dfu_cfc1_env), true,
      "../target/mips/tcg/fpu_helper.c:41" },
    { "cmp_d_le", { 0 },
      dfu_cmp_d_le_env, ARRAY_SIZE(dfu_cmp_d_le_env), true,
      "../target/mips/tcg/fpu_helper.c:1838" },
    { "cmp_d_ule", { 0 },
      dfu_cmp_d_ule_env, ARRAY_SIZE(dfu_cmp_d_ule_env), true,
      "../target/mips/tcg/fpu_helper.c:1814" },
    { "cmp_d_un", { 0 },
      dfu_cmp_d_un_env, ARRAY_SIZE(dfu_cmp_d_un_env), true,
      "../target/mips/tcg/fpu_helper.c:1798" },
    { "cmp_s_eq", { 0 },
      dfu_cmp_s_eq_env, ARRAY_SIZE(dfu_cmp_s_eq_env), true,
      "../target/mips/tcg/fpu_helper.c:1879" },
    { "cmp_s_le", { 0 },
      dfu_cmp_s_le_env, ARRAY_SIZE(dfu_cmp_s_le_env), true,
      "../target/mips/tcg/fpu_helper.c:1917" },
    { "cmp_s_lt", { 0 },
      dfu_cmp_s_lt_env, ARRAY_SIZE(dfu_cmp_s_lt_env), true,
      "../target/mips/tcg/fpu_helper.c:1911" },
    { "float_abs_s", { 0 },
      NULL, 0, true,
      "../target/mips/tcg/fpu_helper.c:981" },
    { "float_add_d", { 0 },
      dfu_float_add_d_env, ARRAY_SIZE(dfu_float_add_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1217" },
    { "float_add_s", { 0 },
      dfu_float_add_s_env, ARRAY_SIZE(dfu_float_add_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1227" },
    { "float_chs_s", { 0 },
      NULL, 0, true,
      "../target/mips/tcg/fpu_helper.c:1001" },
    { "float_cvt_w_s", { 0 },
      dfu_float_cvt_w_s_env, ARRAY_SIZE(dfu_float_cvt_w_s_env), true,
      "../target/mips/tcg/fpu_helper.c:383" },
    { "float_cvtd_s", { 0 },
      dfu_float_cvtd_s_env, ARRAY_SIZE(dfu_float_cvtd_s_env), true,
      "../target/mips/tcg/fpu_helper.c:249" },
    { "float_div_s", { 0 },
      dfu_float_div_s_env, ARRAY_SIZE(dfu_float_div_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1335" },
    { "float_mul_d", { 0 },
      dfu_float_mul_d_env, ARRAY_SIZE(dfu_float_mul_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1289" },
    { "float_mul_s", { 0 },
      dfu_float_mul_s_env, ARRAY_SIZE(dfu_float_mul_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1299" },
    { "float_sqrt_d", { 0 },
      dfu_float_sqrt_d_env, ARRAY_SIZE(dfu_float_sqrt_d_env), true,
      "../target/mips/tcg/fpu_helper.c:235" },
    { "float_sqrt_s", { 0 },
      dfu_float_sqrt_s_env, ARRAY_SIZE(dfu_float_sqrt_s_env), true,
      "../target/mips/tcg/fpu_helper.c:242" },
    { "float_sub_d", { 0 },
      dfu_float_sub_d_env, ARRAY_SIZE(dfu_float_sub_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1253" },
    { "float_sub_s", { 0 },
      dfu_float_sub_s_env, ARRAY_SIZE(dfu_float_sub_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1263" },
    { "float_trunc_w_d", { 0 },
      dfu_float_trunc_w_d_env, ARRAY_SIZE(dfu_float_trunc_w_d_env), true,
      "../target/mips/tcg/fpu_helper.c:500" },
    { "float_trunc_w_s", { 0 },
      dfu_float_trunc_w_s_env, ARRAY_SIZE(dfu_float_trunc_w_s_env), true,
      "../target/mips/tcg/fpu_helper.c:513" },
    { "raise_exception", { 0 },
      dfu_raise_exception_env, ARRAY_SIZE(dfu_raise_exception_env), true,
      "../target/mips/tcg/exception.c:54" },
    { "raise_exception_err", { 0 },
      dfu_raise_exception_err_env, ARRAY_SIZE(dfu_raise_exception_err_env), true,
      "../target/mips/tcg/exception.c:48" },
    { "swl", { 0 },
      dfu_swl_env, ARRAY_SIZE(dfu_swl_env), true,
      "../target/mips/tcg/ldst_helper.c:71" },
    { "swr", { 0 },
      dfu_swr_env, ARRAY_SIZE(dfu_swr_env), true,
      "../target/mips/tcg/ldst_helper.c:95" },
    { "lookup_tb_ptr", { 0 },
      dfu_lookup_tb_ptr_env, ARRAY_SIZE(dfu_lookup_tb_ptr_env), true,
      "accel/tcg/cpu-exec.c HELPER(lookup_tb_ptr)" },
    { NULL, { 0 }, NULL, 0, false, NULL }
};
