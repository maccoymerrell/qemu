/*
 * CP-H per-helper usage -- riscv64.  GENERATED, do not edit.
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
 * compiles this file (they define TARGET_RISCV): riscv32-linux-user, riscv32-softmmu, riscv64-linux-user, riscv64-softmmu.
 *
 * Rows refused, and therefore still OVER-APPROXIMATED at run time:
 *   csrr                     env passed to predicate(), not defined in this unit
 *   csrw                     env passed to predicate(), not defined in this unit
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
 *     ../target/riscv/cpu_helper.c:138, whose read set is derived by the
 *     same reader and is listed here verbatim. It writes nothing: no member
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

static const DfHelperField dfu_fadd_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:398 */
};
static const DfHelperField dfu_fcvt_d_l_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:518 */
};
static const DfHelperField dfu_fcvt_d_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:448 */
};
static const DfHelperField dfu_fcvt_lu_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:503 */
};
static const DfHelperField dfu_fcvt_lu_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:343 */
};
static const DfHelperField dfu_fcvt_s_l_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:358 */
};
static const DfHelperField dfu_feq_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:478 */
};
static const DfHelperField dfu_flt_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:468 */
};
static const DfHelperField dfu_fmadd_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:151 */
};
static const DfHelperField dfu_fmadd_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:139 */
};
static const DfHelperField dfu_fmul_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:408 */
};
static const DfHelperField dfu_fmul_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:237 */
};
static const DfHelperField dfu_fsqrt_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:453 */
};
static const DfHelperField dfu_raise_exception_env[] = {
    { offsetof(CPUArchState, pc), sizeof(((CPUArchState *)0)->pc), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/riscv/op_helper.c:41 */
};
static const DfHelperField dfu_set_rounding_mode_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:82 */
    { offsetof(CPUArchState, frm), sizeof(((CPUArchState *)0)->frm), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/riscv/fpu_helper.c:60 */
    { offsetof(CPUArchState, pc), sizeof(((CPUArchState *)0)->pc), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/riscv/op_helper.c:41 */
};
static const DfHelperField dfu_lookup_tb_ptr_env[] = {
    { offsetof(CPUArchState, elp), sizeof(((CPUArchState *)0)->elp), INSN_DF_RD, DF_HF_XLAT },   /* ../target/riscv/cpu_helper.c:186 */
    { offsetof(CPUArchState, menvcfg), sizeof(((CPUArchState *)0)->menvcfg), INSN_DF_RD, DF_HF_XLAT },   /* ../target/riscv/cpu_helper.c:81 */
    { offsetof(CPUArchState, misa_ext), sizeof(((CPUArchState *)0)->misa_ext), INSN_DF_RD, DF_HF_XLAT },   /* ../target/riscv/cpu.h:572 */
    { offsetof(CPUArchState, pc), sizeof(((CPUArchState *)0)->pc), INSN_DF_RD, DF_HF_XLAT },   /* ../target/riscv/cpu_helper.c:146 */
    { offsetof(CPUArchState, priv), sizeof(((CPUArchState *)0)->priv), INSN_DF_RD, DF_HF_XLAT },   /* ../target/riscv/cpu_helper.c:76 */
    { offsetof(CPUArchState, senvcfg), sizeof(((CPUArchState *)0)->senvcfg), INSN_DF_RD, DF_HF_XLAT },   /* ../target/riscv/cpu_helper.c:79 */
    { offsetof(CPUArchState, vill), sizeof(((CPUArchState *)0)->vill), INSN_DF_RD, DF_HF_XLAT },   /* ../target/riscv/cpu_helper.c:166 */
    { offsetof(CPUArchState, vl), sizeof(((CPUArchState *)0)->vl), INSN_DF_RD, DF_HF_XLAT },   /* ../target/riscv/cpu_helper.c:164 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD, DF_HF_XLAT },   /* ../target/riscv/cpu_helper.c:164 */
    { offsetof(CPUArchState, vtype), sizeof(((CPUArchState *)0)->vtype), INSN_DF_RD, DF_HF_XLAT },   /* ../target/riscv/cpu_helper.c:160 */
    { offsetof(CPUArchState, xl), sizeof(((CPUArchState *)0)->xl), INSN_DF_RD, DF_HF_XLAT },   /* ../target/riscv/cpu_helper.c:146 */
};

static const DfHelperUsage df_helper_usage[] = {
    { "fadd_d", { 0 },
      dfu_fadd_d_env, ARRAY_SIZE(dfu_fadd_d_env), true,
      "../target/riscv/fpu_helper.c:396" },
    { "fcvt_d_l", { 0 },
      dfu_fcvt_d_l_env, ARRAY_SIZE(dfu_fcvt_d_l_env), true,
      "../target/riscv/fpu_helper.c:516" },
    { "fcvt_d_s", { 0 },
      dfu_fcvt_d_s_env, ARRAY_SIZE(dfu_fcvt_d_s_env), true,
      "../target/riscv/fpu_helper.c:445" },
    { "fcvt_lu_d", { 0 },
      dfu_fcvt_lu_d_env, ARRAY_SIZE(dfu_fcvt_lu_d_env), true,
      "../target/riscv/fpu_helper.c:501" },
    { "fcvt_lu_s", { 0 },
      dfu_fcvt_lu_s_env, ARRAY_SIZE(dfu_fcvt_lu_s_env), true,
      "../target/riscv/fpu_helper.c:340" },
    { "fcvt_s_l", { 0 },
      dfu_fcvt_s_l_env, ARRAY_SIZE(dfu_fcvt_s_l_env), true,
      "../target/riscv/fpu_helper.c:356" },
    { "feq_d", { 0 },
      dfu_feq_d_env, ARRAY_SIZE(dfu_feq_d_env), true,
      "../target/riscv/fpu_helper.c:476" },
    { "flt_d", { 0 },
      dfu_flt_d_env, ARRAY_SIZE(dfu_flt_d_env), true,
      "../target/riscv/fpu_helper.c:466" },
    { "fmadd_d", { 0 },
      dfu_fmadd_d_env, ARRAY_SIZE(dfu_fmadd_d_env), true,
      "../target/riscv/fpu_helper.c:148" },
    { "fmadd_s", { 0 },
      dfu_fmadd_s_env, ARRAY_SIZE(dfu_fmadd_s_env), true,
      "../target/riscv/fpu_helper.c:142" },
    { "fmul_d", { 0 },
      dfu_fmul_d_env, ARRAY_SIZE(dfu_fmul_d_env), true,
      "../target/riscv/fpu_helper.c:406" },
    { "fmul_s", { 0 },
      dfu_fmul_s_env, ARRAY_SIZE(dfu_fmul_s_env), true,
      "../target/riscv/fpu_helper.c:233" },
    { "fsqrt_d", { 0 },
      dfu_fsqrt_d_env, ARRAY_SIZE(dfu_fsqrt_d_env), true,
      "../target/riscv/fpu_helper.c:451" },
    { "raise_exception", { 0 },
      dfu_raise_exception_env, ARRAY_SIZE(dfu_raise_exception_env), true,
      "../target/riscv/op_helper.c:47" },
    { "set_rounding_mode", { 0 },
      dfu_set_rounding_mode_env, ARRAY_SIZE(dfu_set_rounding_mode_env), true,
      "../target/riscv/fpu_helper.c:55" },
    { "lookup_tb_ptr", { 0 },
      dfu_lookup_tb_ptr_env, ARRAY_SIZE(dfu_lookup_tb_ptr_env), true,
      "accel/tcg/cpu-exec.c HELPER(lookup_tb_ptr)" },
    { NULL, { 0 }, NULL, 0, false, NULL }
};
