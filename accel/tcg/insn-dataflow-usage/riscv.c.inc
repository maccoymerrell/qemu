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
 * CP1 -- helpers that perform GUEST MEMORY ACCESSES themselves.
 * No qemu_ld/qemu_st op names these: the access happens inside
 * the call, so without the row below QEMU's access list is SHORT
 * for the instruction that called the helper.  Direction and the
 * ADDRESS ARGUMENT are read off the call site; a count is NOT
 * invented when the helper's access pattern is data-dependent.
 *   cbo_zero             write addr=arg1 data=-    one access
 *   vl1re16_v            read  addr=UNSTATED data=-    one access
 *   vl1re32_v            read  addr=UNSTATED data=-    one access
 *   vl1re64_v            read  addr=UNSTATED data=-    one access
 *   vl1re8_v             read  addr=UNSTATED data=-    one access
 *   vl2re16_v            read  addr=UNSTATED data=-    one access
 *   vl2re32_v            read  addr=UNSTATED data=-    one access
 *   vl2re64_v            read  addr=UNSTATED data=-    one access
 *   vl2re8_v             read  addr=UNSTATED data=-    one access
 *   vl4re16_v            read  addr=UNSTATED data=-    one access
 *   vl4re32_v            read  addr=UNSTATED data=-    one access
 *   vl4re64_v            read  addr=UNSTATED data=-    one access
 *   vl4re8_v             read  addr=UNSTATED data=-    one access
 *   vl8re16_v            read  addr=UNSTATED data=-    one access
 *   vl8re32_v            read  addr=UNSTATED data=-    one access
 *   vl8re64_v            read  addr=UNSTATED data=-    one access
 *   vl8re8_v             read  addr=UNSTATED data=-    one access
 *   vs1r_v               write addr=UNSTATED data=-    one access
 *   vs2r_v               write addr=UNSTATED data=-    one access
 *   vs4r_v               write addr=UNSTATED data=-    one access
 *   vs8r_v               write addr=UNSTATED data=-    one access
 *
 * READS THE EMULATOR MAKES ON ITS OWN BEHALF -- derived,
 * enumerated, and marked DF_HF_XLAT so the footprint is complete
 * and the OPERAND set is not.  Selected by the SOURCE LINE the
 * reader read the member off, never by helper name, so a sibling
 * reaching the same line is covered the day it is derived:
 *   raise_exception          pc       ../target/riscv/op_helper.c:41
 *   set_rounding_mode        pc       ../target/riscv/op_helper.c:41
 *   pc @ ../target/riscv/op_helper.c:41:
 *     a TRACE POINT -- trace_riscv_exception(exception, name, env->pc)
 *     inside riscv_raise_exception(). It names the faulting address for a
 *     log line and reaches no guest state
 *
 * Rows refused, and therefore still OVER-APPROXIMATED at run time:
 *   csrr                     env passed to predicate(), not defined in this unit
 *   csrrw                    env passed to predicate(), not defined in this unit
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
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:398 */
};
static const DfHelperField dfu_fadd_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:556 */
};
static const DfHelperField dfu_fadd_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:223 */
};
static const DfHelperField dfu_fcvt_bf16_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:755 */
};
static const DfHelperField dfu_fcvt_d_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:749 */
};
static const DfHelperField dfu_fcvt_d_l_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:518 */
};
static const DfHelperField dfu_fcvt_d_lu_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:523 */
};
static const DfHelperField dfu_fcvt_d_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:448 */
};
static const DfHelperField dfu_fcvt_d_w_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:508 */
};
static const DfHelperField dfu_fcvt_d_wu_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:513 */
};
static const DfHelperField dfu_fcvt_h_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:743 */
};
static const DfHelperField dfu_fcvt_h_l_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:721 */
};
static const DfHelperField dfu_fcvt_h_lu_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:726 */
};
static const DfHelperField dfu_fcvt_h_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:732 */
};
static const DfHelperField dfu_fcvt_h_w_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:711 */
};
static const DfHelperField dfu_fcvt_h_wu_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:716 */
};
static const DfHelperField dfu_fcvt_l_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:498 */
};
static const DfHelperField dfu_fcvt_l_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:700 */
};
static const DfHelperField dfu_fcvt_l_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:337 */
};
static const DfHelperField dfu_fcvt_lu_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:503 */
};
static const DfHelperField dfu_fcvt_lu_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:706 */
};
static const DfHelperField dfu_fcvt_lu_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:343 */
};
static const DfHelperField dfu_fcvt_s_bf16_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:761 */
};
static const DfHelperField dfu_fcvt_s_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:442 */
};
static const DfHelperField dfu_fcvt_s_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:738 */
};
static const DfHelperField dfu_fcvt_s_l_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:358 */
};
static const DfHelperField dfu_fcvt_s_lu_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:363 */
};
static const DfHelperField dfu_fcvt_s_w_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:348 */
};
static const DfHelperField dfu_fcvt_s_wu_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:353 */
};
static const DfHelperField dfu_fcvt_w_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:483 */
};
static const DfHelperField dfu_fcvt_w_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:688 */
};
static const DfHelperField dfu_fcvt_w_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:325 */
};
static const DfHelperField dfu_fcvt_wu_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:493 */
};
static const DfHelperField dfu_fcvt_wu_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:694 */
};
static const DfHelperField dfu_fcvt_wu_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:331 */
};
static const DfHelperField dfu_fcvtmod_w_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:488 */
};
static const DfHelperField dfu_fdiv_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:413 */
};
static const DfHelperField dfu_fdiv_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:577 */
};
static const DfHelperField dfu_fdiv_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:244 */
};
static const DfHelperField dfu_feq_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:478 */
};
static const DfHelperField dfu_feq_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:652 */
};
static const DfHelperField dfu_feq_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:319 */
};
static const DfHelperField dfu_fle_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:458 */
};
static const DfHelperField dfu_fle_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:624 */
};
static const DfHelperField dfu_fle_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:291 */
};
static const DfHelperField dfu_fleq_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:463 */
};
static const DfHelperField dfu_fleq_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:631 */
};
static const DfHelperField dfu_fleq_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:298 */
};
static const DfHelperField dfu_flt_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:468 */
};
static const DfHelperField dfu_flt_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:638 */
};
static const DfHelperField dfu_flt_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:305 */
};
static const DfHelperField dfu_fltq_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:473 */
};
static const DfHelperField dfu_fltq_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:645 */
};
static const DfHelperField dfu_fltq_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:312 */
};
static const DfHelperField dfu_fmadd_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:151 */
};
static const DfHelperField dfu_fmadd_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:129 */
};
static const DfHelperField dfu_fmadd_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:139 */
};
static const DfHelperField dfu_fmax_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:431 */
    { offsetof(CPUArchState, priv_ver), sizeof(((CPUArchState *)0)->priv_ver), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:430 */
};
static const DfHelperField dfu_fmax_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:602 */
    { offsetof(CPUArchState, priv_ver), sizeof(((CPUArchState *)0)->priv_ver), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:601 */
};
static const DfHelperField dfu_fmax_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:269 */
    { offsetof(CPUArchState, priv_ver), sizeof(((CPUArchState *)0)->priv_ver), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:268 */
};
static const DfHelperField dfu_fmaxm_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:437 */
};
static const DfHelperField dfu_fmaxm_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:610 */
};
static const DfHelperField dfu_fmaxm_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:277 */
};
static const DfHelperField dfu_fmin_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:419 */
    { offsetof(CPUArchState, priv_ver), sizeof(((CPUArchState *)0)->priv_ver), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:418 */
};
static const DfHelperField dfu_fmin_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:585 */
    { offsetof(CPUArchState, priv_ver), sizeof(((CPUArchState *)0)->priv_ver), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:584 */
};
static const DfHelperField dfu_fmin_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:252 */
    { offsetof(CPUArchState, priv_ver), sizeof(((CPUArchState *)0)->priv_ver), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:251 */
};
static const DfHelperField dfu_fminm_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:425 */
};
static const DfHelperField dfu_fminm_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:593 */
};
static const DfHelperField dfu_fminm_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:260 */
};
static const DfHelperField dfu_fmsub_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:170 */
};
static const DfHelperField dfu_fmsub_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:129 */
};
static const DfHelperField dfu_fmsub_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:139 */
};
static const DfHelperField dfu_fmul_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:408 */
};
static const DfHelperField dfu_fmul_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:570 */
};
static const DfHelperField dfu_fmul_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:237 */
};
static const DfHelperField dfu_fnmadd_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:209 */
};
static const DfHelperField dfu_fnmadd_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:129 */
};
static const DfHelperField dfu_fnmadd_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:139 */
};
static const DfHelperField dfu_fnmsub_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:189 */
};
static const DfHelperField dfu_fnmsub_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:129 */
};
static const DfHelperField dfu_fnmsub_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:139 */
};
static const DfHelperField dfu_fround_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:533 */
};
static const DfHelperField dfu_fround_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:663 */
};
static const DfHelperField dfu_fround_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:374 */
};
static const DfHelperField dfu_froundnx_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:549 */
};
static const DfHelperField dfu_froundnx_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:681 */
};
static const DfHelperField dfu_froundnx_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:392 */
};
static const DfHelperField dfu_fsqrt_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:453 */
};
static const DfHelperField dfu_fsqrt_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:617 */
};
static const DfHelperField dfu_fsqrt_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:284 */
};
static const DfHelperField dfu_fsub_d_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:403 */
};
static const DfHelperField dfu_fsub_h_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:563 */
};
static const DfHelperField dfu_fsub_s_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:230 */
};
static const DfHelperField dfu_raise_exception_env[] = {
    { offsetof(CPUArchState, pc), sizeof(((CPUArchState *)0)->pc), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/riscv/op_helper.c:41 */
};
static const DfHelperField dfu_set_rounding_mode_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:82 */
    { offsetof(CPUArchState, frm), sizeof(((CPUArchState *)0)->frm), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/fpu_helper.c:60 */
    { offsetof(CPUArchState, pc), sizeof(((CPUArchState *)0)->pc), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/riscv/op_helper.c:41 */
};
static const DfHelperField dfu_vl1re16_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl1re32_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl1re64_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl1re8_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl2re16_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl2re32_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl2re64_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl2re8_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl4re16_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl4re32_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl4re64_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl4re8_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl8re16_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl8re32_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl8re64_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vl8re8_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vs1r_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vs2r_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vs4r_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vs8r_v_env[] = {
    { offsetof(CPUArchState, misa_mxl), sizeof(((CPUArchState *)0)->misa_mxl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:701 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:801 */
};
static const DfHelperField dfu_vsetvl_env[] = {
    { offsetof(CPUArchState, vill), sizeof(((CPUArchState *)0)->vill), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:67 */
    { offsetof(CPUArchState, vl), sizeof(((CPUArchState *)0)->vl), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:69 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:70 */
    { offsetof(CPUArchState, vtype), sizeof(((CPUArchState *)0)->vtype), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/riscv/vector_helper.c:68 */
    { offsetof(CPUArchState, xl), sizeof(((CPUArchState *)0)->xl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/riscv/cpu.h:777 */
};
static const DfHelperField dfu_lookup_tb_ptr_env[] = {
    { offsetof(CPUArchState, elp), sizeof(((CPUArchState *)0)->elp), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/riscv/cpu_helper.c:186 */
    { offsetof(CPUArchState, menvcfg), sizeof(((CPUArchState *)0)->menvcfg), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/riscv/cpu_helper.c:81 */
    { offsetof(CPUArchState, misa_ext), sizeof(((CPUArchState *)0)->misa_ext), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/riscv/cpu.h:572 */
    { offsetof(CPUArchState, pc), sizeof(((CPUArchState *)0)->pc), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/riscv/cpu_helper.c:146 */
    { offsetof(CPUArchState, priv), sizeof(((CPUArchState *)0)->priv), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/riscv/cpu_helper.c:76 */
    { offsetof(CPUArchState, senvcfg), sizeof(((CPUArchState *)0)->senvcfg), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/riscv/cpu_helper.c:79 */
    { offsetof(CPUArchState, vill), sizeof(((CPUArchState *)0)->vill), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/riscv/cpu_helper.c:166 */
    { offsetof(CPUArchState, vl), sizeof(((CPUArchState *)0)->vl), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/riscv/cpu_helper.c:164 */
    { offsetof(CPUArchState, vstart), sizeof(((CPUArchState *)0)->vstart), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/riscv/cpu_helper.c:164 */
    { offsetof(CPUArchState, vtype), sizeof(((CPUArchState *)0)->vtype), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/riscv/cpu_helper.c:160 */
    { offsetof(CPUArchState, xl), sizeof(((CPUArchState *)0)->xl), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/riscv/cpu_helper.c:146 */
};
static const DfHelperAccess dfu_cbo_zero_acc[] = {
    { INSN_DF_WR, 1, DF_HA_NO_ARG, 1, 0 },   /* ../target/riscv/op_helper.c:214, 1 site(s) */
};
static const DfHelperAccess dfu_vl1re16_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/riscv/vector_helper.c:168, 1 site(s) */
};
static const DfHelperAccess dfu_vl1re32_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/riscv/vector_helper.c:169, 1 site(s) */
};
static const DfHelperAccess dfu_vl1re64_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/riscv/vector_helper.c:170, 1 site(s) */
};
static const DfHelperAccess dfu_vl1re8_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/riscv/vector_helper.c:167, 1 site(s) */
};
static const DfHelperAccess dfu_vl2re16_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/riscv/vector_helper.c:168, 1 site(s) */
};
static const DfHelperAccess dfu_vl2re32_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/riscv/vector_helper.c:169, 1 site(s) */
};
static const DfHelperAccess dfu_vl2re64_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/riscv/vector_helper.c:170, 1 site(s) */
};
static const DfHelperAccess dfu_vl2re8_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/riscv/vector_helper.c:167, 1 site(s) */
};
static const DfHelperAccess dfu_vl4re16_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/riscv/vector_helper.c:168, 1 site(s) */
};
static const DfHelperAccess dfu_vl4re32_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/riscv/vector_helper.c:169, 1 site(s) */
};
static const DfHelperAccess dfu_vl4re64_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/riscv/vector_helper.c:170, 1 site(s) */
};
static const DfHelperAccess dfu_vl4re8_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/riscv/vector_helper.c:167, 1 site(s) */
};
static const DfHelperAccess dfu_vl8re16_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/riscv/vector_helper.c:168, 1 site(s) */
};
static const DfHelperAccess dfu_vl8re32_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/riscv/vector_helper.c:169, 1 site(s) */
};
static const DfHelperAccess dfu_vl8re64_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/riscv/vector_helper.c:170, 1 site(s) */
};
static const DfHelperAccess dfu_vl8re8_v_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/riscv/vector_helper.c:167, 1 site(s) */
};
static const DfHelperAccess dfu_vs1r_v_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/riscv/vector_helper.c:188, 1 site(s) */
};
static const DfHelperAccess dfu_vs2r_v_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/riscv/vector_helper.c:188, 1 site(s) */
};
static const DfHelperAccess dfu_vs4r_v_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/riscv/vector_helper.c:188, 1 site(s) */
};
static const DfHelperAccess dfu_vs8r_v_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/riscv/vector_helper.c:188, 1 site(s) */
};

static const DfHelperUsage df_helper_usage[] = {
    { "aes64ds", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/crypto_helper.c:104",
      NULL, 0 },
    { "aes64dsm", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/crypto_helper.c:114",
      NULL, 0 },
    { "aes64es", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/crypto_helper.c:94",
      NULL, 0 },
    { "aes64esm", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/crypto_helper.c:84",
      NULL, 0 },
    { "aes64im", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/crypto_helper.c:165",
      NULL, 0 },
    { "aes64ks1i", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/crypto_helper.c:143",
      NULL, 0 },
    { "aes64ks2", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/crypto_helper.c:128",
      NULL, 0 },
    { "brev8", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/bitmanip_helper.c:59",
      NULL, 0 },
    { "cbo_clean_flush", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/op_helper.c:268",
      NULL, 0 },
    { "cbo_inval", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/op_helper.c:277",
      NULL, 0 },
    { "cbo_zero", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/op_helper.c:164",
      dfu_cbo_zero_acc, ARRAY_SIZE(dfu_cbo_zero_acc) },
    { "clmul", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/bitmanip_helper.c:28",
      NULL, 0 },
    { "clmulr", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/bitmanip_helper.c:41",
      NULL, 0 },
    { "fadd_d", { 0 }, { 0 },
      dfu_fadd_d_env, ARRAY_SIZE(dfu_fadd_d_env), true,
      "../target/riscv/fpu_helper.c:396",
      NULL, 0 },
    { "fadd_h", { 0 }, { 0 },
      dfu_fadd_h_env, ARRAY_SIZE(dfu_fadd_h_env), true,
      "../target/riscv/fpu_helper.c:552",
      NULL, 0 },
    { "fadd_s", { 0 }, { 0 },
      dfu_fadd_s_env, ARRAY_SIZE(dfu_fadd_s_env), true,
      "../target/riscv/fpu_helper.c:219",
      NULL, 0 },
    { "fclass_d", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/fpu_helper.c:526",
      NULL, 0 },
    { "fclass_h", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/fpu_helper.c:655",
      NULL, 0 },
    { "fclass_s", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/fpu_helper.c:366",
      NULL, 0 },
    { "fcvt_bf16_s", { 0 }, { 0 },
      dfu_fcvt_bf16_s_env, ARRAY_SIZE(dfu_fcvt_bf16_s_env), true,
      "../target/riscv/fpu_helper.c:752",
      NULL, 0 },
    { "fcvt_d_h", { 0 }, { 0 },
      dfu_fcvt_d_h_env, ARRAY_SIZE(dfu_fcvt_d_h_env), true,
      "../target/riscv/fpu_helper.c:746",
      NULL, 0 },
    { "fcvt_d_l", { 0 }, { 0 },
      dfu_fcvt_d_l_env, ARRAY_SIZE(dfu_fcvt_d_l_env), true,
      "../target/riscv/fpu_helper.c:516",
      NULL, 0 },
    { "fcvt_d_lu", { 0 }, { 0 },
      dfu_fcvt_d_lu_env, ARRAY_SIZE(dfu_fcvt_d_lu_env), true,
      "../target/riscv/fpu_helper.c:521",
      NULL, 0 },
    { "fcvt_d_s", { 0 }, { 0 },
      dfu_fcvt_d_s_env, ARRAY_SIZE(dfu_fcvt_d_s_env), true,
      "../target/riscv/fpu_helper.c:445",
      NULL, 0 },
    { "fcvt_d_w", { 0 }, { 0 },
      dfu_fcvt_d_w_env, ARRAY_SIZE(dfu_fcvt_d_w_env), true,
      "../target/riscv/fpu_helper.c:506",
      NULL, 0 },
    { "fcvt_d_wu", { 0 }, { 0 },
      dfu_fcvt_d_wu_env, ARRAY_SIZE(dfu_fcvt_d_wu_env), true,
      "../target/riscv/fpu_helper.c:511",
      NULL, 0 },
    { "fcvt_h_d", { 0 }, { 0 },
      dfu_fcvt_h_d_env, ARRAY_SIZE(dfu_fcvt_h_d_env), true,
      "../target/riscv/fpu_helper.c:741",
      NULL, 0 },
    { "fcvt_h_l", { 0 }, { 0 },
      dfu_fcvt_h_l_env, ARRAY_SIZE(dfu_fcvt_h_l_env), true,
      "../target/riscv/fpu_helper.c:719",
      NULL, 0 },
    { "fcvt_h_lu", { 0 }, { 0 },
      dfu_fcvt_h_lu_env, ARRAY_SIZE(dfu_fcvt_h_lu_env), true,
      "../target/riscv/fpu_helper.c:724",
      NULL, 0 },
    { "fcvt_h_s", { 0 }, { 0 },
      dfu_fcvt_h_s_env, ARRAY_SIZE(dfu_fcvt_h_s_env), true,
      "../target/riscv/fpu_helper.c:729",
      NULL, 0 },
    { "fcvt_h_w", { 0 }, { 0 },
      dfu_fcvt_h_w_env, ARRAY_SIZE(dfu_fcvt_h_w_env), true,
      "../target/riscv/fpu_helper.c:709",
      NULL, 0 },
    { "fcvt_h_wu", { 0 }, { 0 },
      dfu_fcvt_h_wu_env, ARRAY_SIZE(dfu_fcvt_h_wu_env), true,
      "../target/riscv/fpu_helper.c:714",
      NULL, 0 },
    { "fcvt_l_d", { 0 }, { 0 },
      dfu_fcvt_l_d_env, ARRAY_SIZE(dfu_fcvt_l_d_env), true,
      "../target/riscv/fpu_helper.c:496",
      NULL, 0 },
    { "fcvt_l_h", { 0 }, { 0 },
      dfu_fcvt_l_h_env, ARRAY_SIZE(dfu_fcvt_l_h_env), true,
      "../target/riscv/fpu_helper.c:697",
      NULL, 0 },
    { "fcvt_l_s", { 0 }, { 0 },
      dfu_fcvt_l_s_env, ARRAY_SIZE(dfu_fcvt_l_s_env), true,
      "../target/riscv/fpu_helper.c:334",
      NULL, 0 },
    { "fcvt_lu_d", { 0 }, { 0 },
      dfu_fcvt_lu_d_env, ARRAY_SIZE(dfu_fcvt_lu_d_env), true,
      "../target/riscv/fpu_helper.c:501",
      NULL, 0 },
    { "fcvt_lu_h", { 0 }, { 0 },
      dfu_fcvt_lu_h_env, ARRAY_SIZE(dfu_fcvt_lu_h_env), true,
      "../target/riscv/fpu_helper.c:703",
      NULL, 0 },
    { "fcvt_lu_s", { 0 }, { 0 },
      dfu_fcvt_lu_s_env, ARRAY_SIZE(dfu_fcvt_lu_s_env), true,
      "../target/riscv/fpu_helper.c:340",
      NULL, 0 },
    { "fcvt_s_bf16", { 0 }, { 0 },
      dfu_fcvt_s_bf16_env, ARRAY_SIZE(dfu_fcvt_s_bf16_env), true,
      "../target/riscv/fpu_helper.c:758",
      NULL, 0 },
    { "fcvt_s_d", { 0 }, { 0 },
      dfu_fcvt_s_d_env, ARRAY_SIZE(dfu_fcvt_s_d_env), true,
      "../target/riscv/fpu_helper.c:440",
      NULL, 0 },
    { "fcvt_s_h", { 0 }, { 0 },
      dfu_fcvt_s_h_env, ARRAY_SIZE(dfu_fcvt_s_h_env), true,
      "../target/riscv/fpu_helper.c:735",
      NULL, 0 },
    { "fcvt_s_l", { 0 }, { 0 },
      dfu_fcvt_s_l_env, ARRAY_SIZE(dfu_fcvt_s_l_env), true,
      "../target/riscv/fpu_helper.c:356",
      NULL, 0 },
    { "fcvt_s_lu", { 0 }, { 0 },
      dfu_fcvt_s_lu_env, ARRAY_SIZE(dfu_fcvt_s_lu_env), true,
      "../target/riscv/fpu_helper.c:361",
      NULL, 0 },
    { "fcvt_s_w", { 0 }, { 0 },
      dfu_fcvt_s_w_env, ARRAY_SIZE(dfu_fcvt_s_w_env), true,
      "../target/riscv/fpu_helper.c:346",
      NULL, 0 },
    { "fcvt_s_wu", { 0 }, { 0 },
      dfu_fcvt_s_wu_env, ARRAY_SIZE(dfu_fcvt_s_wu_env), true,
      "../target/riscv/fpu_helper.c:351",
      NULL, 0 },
    { "fcvt_w_d", { 0 }, { 0 },
      dfu_fcvt_w_d_env, ARRAY_SIZE(dfu_fcvt_w_d_env), true,
      "../target/riscv/fpu_helper.c:481",
      NULL, 0 },
    { "fcvt_w_h", { 0 }, { 0 },
      dfu_fcvt_w_h_env, ARRAY_SIZE(dfu_fcvt_w_h_env), true,
      "../target/riscv/fpu_helper.c:685",
      NULL, 0 },
    { "fcvt_w_s", { 0 }, { 0 },
      dfu_fcvt_w_s_env, ARRAY_SIZE(dfu_fcvt_w_s_env), true,
      "../target/riscv/fpu_helper.c:322",
      NULL, 0 },
    { "fcvt_wu_d", { 0 }, { 0 },
      dfu_fcvt_wu_d_env, ARRAY_SIZE(dfu_fcvt_wu_d_env), true,
      "../target/riscv/fpu_helper.c:491",
      NULL, 0 },
    { "fcvt_wu_h", { 0 }, { 0 },
      dfu_fcvt_wu_h_env, ARRAY_SIZE(dfu_fcvt_wu_h_env), true,
      "../target/riscv/fpu_helper.c:691",
      NULL, 0 },
    { "fcvt_wu_s", { 0 }, { 0 },
      dfu_fcvt_wu_s_env, ARRAY_SIZE(dfu_fcvt_wu_s_env), true,
      "../target/riscv/fpu_helper.c:328",
      NULL, 0 },
    { "fcvtmod_w_d", { 0 }, { 0 },
      dfu_fcvtmod_w_d_env, ARRAY_SIZE(dfu_fcvtmod_w_d_env), true,
      "../target/riscv/fpu_helper.c:486",
      NULL, 0 },
    { "fdiv_d", { 0 }, { 0 },
      dfu_fdiv_d_env, ARRAY_SIZE(dfu_fdiv_d_env), true,
      "../target/riscv/fpu_helper.c:411",
      NULL, 0 },
    { "fdiv_h", { 0 }, { 0 },
      dfu_fdiv_h_env, ARRAY_SIZE(dfu_fdiv_h_env), true,
      "../target/riscv/fpu_helper.c:573",
      NULL, 0 },
    { "fdiv_s", { 0 }, { 0 },
      dfu_fdiv_s_env, ARRAY_SIZE(dfu_fdiv_s_env), true,
      "../target/riscv/fpu_helper.c:240",
      NULL, 0 },
    { "feq_d", { 0 }, { 0 },
      dfu_feq_d_env, ARRAY_SIZE(dfu_feq_d_env), true,
      "../target/riscv/fpu_helper.c:476",
      NULL, 0 },
    { "feq_h", { 0 }, { 0 },
      dfu_feq_h_env, ARRAY_SIZE(dfu_feq_h_env), true,
      "../target/riscv/fpu_helper.c:648",
      NULL, 0 },
    { "feq_s", { 0 }, { 0 },
      dfu_feq_s_env, ARRAY_SIZE(dfu_feq_s_env), true,
      "../target/riscv/fpu_helper.c:315",
      NULL, 0 },
    { "fle_d", { 0 }, { 0 },
      dfu_fle_d_env, ARRAY_SIZE(dfu_fle_d_env), true,
      "../target/riscv/fpu_helper.c:456",
      NULL, 0 },
    { "fle_h", { 0 }, { 0 },
      dfu_fle_h_env, ARRAY_SIZE(dfu_fle_h_env), true,
      "../target/riscv/fpu_helper.c:620",
      NULL, 0 },
    { "fle_s", { 0 }, { 0 },
      dfu_fle_s_env, ARRAY_SIZE(dfu_fle_s_env), true,
      "../target/riscv/fpu_helper.c:287",
      NULL, 0 },
    { "fleq_d", { 0 }, { 0 },
      dfu_fleq_d_env, ARRAY_SIZE(dfu_fleq_d_env), true,
      "../target/riscv/fpu_helper.c:461",
      NULL, 0 },
    { "fleq_h", { 0 }, { 0 },
      dfu_fleq_h_env, ARRAY_SIZE(dfu_fleq_h_env), true,
      "../target/riscv/fpu_helper.c:627",
      NULL, 0 },
    { "fleq_s", { 0 }, { 0 },
      dfu_fleq_s_env, ARRAY_SIZE(dfu_fleq_s_env), true,
      "../target/riscv/fpu_helper.c:294",
      NULL, 0 },
    { "flt_d", { 0 }, { 0 },
      dfu_flt_d_env, ARRAY_SIZE(dfu_flt_d_env), true,
      "../target/riscv/fpu_helper.c:466",
      NULL, 0 },
    { "flt_h", { 0 }, { 0 },
      dfu_flt_h_env, ARRAY_SIZE(dfu_flt_h_env), true,
      "../target/riscv/fpu_helper.c:634",
      NULL, 0 },
    { "flt_s", { 0 }, { 0 },
      dfu_flt_s_env, ARRAY_SIZE(dfu_flt_s_env), true,
      "../target/riscv/fpu_helper.c:301",
      NULL, 0 },
    { "fltq_d", { 0 }, { 0 },
      dfu_fltq_d_env, ARRAY_SIZE(dfu_fltq_d_env), true,
      "../target/riscv/fpu_helper.c:471",
      NULL, 0 },
    { "fltq_h", { 0 }, { 0 },
      dfu_fltq_h_env, ARRAY_SIZE(dfu_fltq_h_env), true,
      "../target/riscv/fpu_helper.c:641",
      NULL, 0 },
    { "fltq_s", { 0 }, { 0 },
      dfu_fltq_s_env, ARRAY_SIZE(dfu_fltq_s_env), true,
      "../target/riscv/fpu_helper.c:308",
      NULL, 0 },
    { "fmadd_d", { 0 }, { 0 },
      dfu_fmadd_d_env, ARRAY_SIZE(dfu_fmadd_d_env), true,
      "../target/riscv/fpu_helper.c:148",
      NULL, 0 },
    { "fmadd_h", { 0 }, { 0 },
      dfu_fmadd_h_env, ARRAY_SIZE(dfu_fmadd_h_env), true,
      "../target/riscv/fpu_helper.c:154",
      NULL, 0 },
    { "fmadd_s", { 0 }, { 0 },
      dfu_fmadd_s_env, ARRAY_SIZE(dfu_fmadd_s_env), true,
      "../target/riscv/fpu_helper.c:142",
      NULL, 0 },
    { "fmax_d", { 0 }, { 0 },
      dfu_fmax_d_env, ARRAY_SIZE(dfu_fmax_d_env), true,
      "../target/riscv/fpu_helper.c:428",
      NULL, 0 },
    { "fmax_h", { 0 }, { 0 },
      dfu_fmax_h_env, ARRAY_SIZE(dfu_fmax_h_env), true,
      "../target/riscv/fpu_helper.c:597",
      NULL, 0 },
    { "fmax_s", { 0 }, { 0 },
      dfu_fmax_s_env, ARRAY_SIZE(dfu_fmax_s_env), true,
      "../target/riscv/fpu_helper.c:264",
      NULL, 0 },
    { "fmaxm_d", { 0 }, { 0 },
      dfu_fmaxm_d_env, ARRAY_SIZE(dfu_fmaxm_d_env), true,
      "../target/riscv/fpu_helper.c:435",
      NULL, 0 },
    { "fmaxm_h", { 0 }, { 0 },
      dfu_fmaxm_h_env, ARRAY_SIZE(dfu_fmaxm_h_env), true,
      "../target/riscv/fpu_helper.c:606",
      NULL, 0 },
    { "fmaxm_s", { 0 }, { 0 },
      dfu_fmaxm_s_env, ARRAY_SIZE(dfu_fmaxm_s_env), true,
      "../target/riscv/fpu_helper.c:273",
      NULL, 0 },
    { "fmin_d", { 0 }, { 0 },
      dfu_fmin_d_env, ARRAY_SIZE(dfu_fmin_d_env), true,
      "../target/riscv/fpu_helper.c:416",
      NULL, 0 },
    { "fmin_h", { 0 }, { 0 },
      dfu_fmin_h_env, ARRAY_SIZE(dfu_fmin_h_env), true,
      "../target/riscv/fpu_helper.c:580",
      NULL, 0 },
    { "fmin_s", { 0 }, { 0 },
      dfu_fmin_s_env, ARRAY_SIZE(dfu_fmin_s_env), true,
      "../target/riscv/fpu_helper.c:247",
      NULL, 0 },
    { "fminm_d", { 0 }, { 0 },
      dfu_fminm_d_env, ARRAY_SIZE(dfu_fminm_d_env), true,
      "../target/riscv/fpu_helper.c:423",
      NULL, 0 },
    { "fminm_h", { 0 }, { 0 },
      dfu_fminm_h_env, ARRAY_SIZE(dfu_fminm_h_env), true,
      "../target/riscv/fpu_helper.c:589",
      NULL, 0 },
    { "fminm_s", { 0 }, { 0 },
      dfu_fminm_s_env, ARRAY_SIZE(dfu_fminm_s_env), true,
      "../target/riscv/fpu_helper.c:256",
      NULL, 0 },
    { "fmsub_d", { 0 }, { 0 },
      dfu_fmsub_d_env, ARRAY_SIZE(dfu_fmsub_d_env), true,
      "../target/riscv/fpu_helper.c:166",
      NULL, 0 },
    { "fmsub_h", { 0 }, { 0 },
      dfu_fmsub_h_env, ARRAY_SIZE(dfu_fmsub_h_env), true,
      "../target/riscv/fpu_helper.c:173",
      NULL, 0 },
    { "fmsub_s", { 0 }, { 0 },
      dfu_fmsub_s_env, ARRAY_SIZE(dfu_fmsub_s_env), true,
      "../target/riscv/fpu_helper.c:160",
      NULL, 0 },
    { "fmul_d", { 0 }, { 0 },
      dfu_fmul_d_env, ARRAY_SIZE(dfu_fmul_d_env), true,
      "../target/riscv/fpu_helper.c:406",
      NULL, 0 },
    { "fmul_h", { 0 }, { 0 },
      dfu_fmul_h_env, ARRAY_SIZE(dfu_fmul_h_env), true,
      "../target/riscv/fpu_helper.c:566",
      NULL, 0 },
    { "fmul_s", { 0 }, { 0 },
      dfu_fmul_s_env, ARRAY_SIZE(dfu_fmul_s_env), true,
      "../target/riscv/fpu_helper.c:233",
      NULL, 0 },
    { "fnmadd_d", { 0 }, { 0 },
      dfu_fnmadd_d_env, ARRAY_SIZE(dfu_fnmadd_d_env), true,
      "../target/riscv/fpu_helper.c:205",
      NULL, 0 },
    { "fnmadd_h", { 0 }, { 0 },
      dfu_fnmadd_h_env, ARRAY_SIZE(dfu_fnmadd_h_env), true,
      "../target/riscv/fpu_helper.c:212",
      NULL, 0 },
    { "fnmadd_s", { 0 }, { 0 },
      dfu_fnmadd_s_env, ARRAY_SIZE(dfu_fnmadd_s_env), true,
      "../target/riscv/fpu_helper.c:198",
      NULL, 0 },
    { "fnmsub_d", { 0 }, { 0 },
      dfu_fnmsub_d_env, ARRAY_SIZE(dfu_fnmsub_d_env), true,
      "../target/riscv/fpu_helper.c:185",
      NULL, 0 },
    { "fnmsub_h", { 0 }, { 0 },
      dfu_fnmsub_h_env, ARRAY_SIZE(dfu_fnmsub_h_env), true,
      "../target/riscv/fpu_helper.c:192",
      NULL, 0 },
    { "fnmsub_s", { 0 }, { 0 },
      dfu_fnmsub_s_env, ARRAY_SIZE(dfu_fnmsub_s_env), true,
      "../target/riscv/fpu_helper.c:179",
      NULL, 0 },
    { "fround_d", { 0 }, { 0 },
      dfu_fround_d_env, ARRAY_SIZE(dfu_fround_d_env), true,
      "../target/riscv/fpu_helper.c:531",
      NULL, 0 },
    { "fround_h", { 0 }, { 0 },
      dfu_fround_h_env, ARRAY_SIZE(dfu_fround_h_env), true,
      "../target/riscv/fpu_helper.c:661",
      NULL, 0 },
    { "fround_s", { 0 }, { 0 },
      dfu_fround_s_env, ARRAY_SIZE(dfu_fround_s_env), true,
      "../target/riscv/fpu_helper.c:372",
      NULL, 0 },
    { "froundnx_d", { 0 }, { 0 },
      dfu_froundnx_d_env, ARRAY_SIZE(dfu_froundnx_d_env), true,
      "../target/riscv/fpu_helper.c:547",
      NULL, 0 },
    { "froundnx_h", { 0 }, { 0 },
      dfu_froundnx_h_env, ARRAY_SIZE(dfu_froundnx_h_env), true,
      "../target/riscv/fpu_helper.c:678",
      NULL, 0 },
    { "froundnx_s", { 0 }, { 0 },
      dfu_froundnx_s_env, ARRAY_SIZE(dfu_froundnx_s_env), true,
      "../target/riscv/fpu_helper.c:389",
      NULL, 0 },
    { "fsqrt_d", { 0 }, { 0 },
      dfu_fsqrt_d_env, ARRAY_SIZE(dfu_fsqrt_d_env), true,
      "../target/riscv/fpu_helper.c:451",
      NULL, 0 },
    { "fsqrt_h", { 0 }, { 0 },
      dfu_fsqrt_h_env, ARRAY_SIZE(dfu_fsqrt_h_env), true,
      "../target/riscv/fpu_helper.c:614",
      NULL, 0 },
    { "fsqrt_s", { 0 }, { 0 },
      dfu_fsqrt_s_env, ARRAY_SIZE(dfu_fsqrt_s_env), true,
      "../target/riscv/fpu_helper.c:281",
      NULL, 0 },
    { "fsub_d", { 0 }, { 0 },
      dfu_fsub_d_env, ARRAY_SIZE(dfu_fsub_d_env), true,
      "../target/riscv/fpu_helper.c:401",
      NULL, 0 },
    { "fsub_h", { 0 }, { 0 },
      dfu_fsub_h_env, ARRAY_SIZE(dfu_fsub_h_env), true,
      "../target/riscv/fpu_helper.c:559",
      NULL, 0 },
    { "fsub_s", { 0 }, { 0 },
      dfu_fsub_s_env, ARRAY_SIZE(dfu_fsub_s_env), true,
      "../target/riscv/fpu_helper.c:226",
      NULL, 0 },
    { "raise_exception", { 0 }, { 0 },
      dfu_raise_exception_env, ARRAY_SIZE(dfu_raise_exception_env), true,
      "../target/riscv/op_helper.c:47",
      NULL, 0 },
    { "set_rounding_mode", { 0 }, { 0 },
      dfu_set_rounding_mode_env, ARRAY_SIZE(dfu_set_rounding_mode_env), true,
      "../target/riscv/fpu_helper.c:55",
      NULL, 0 },
    { "sm4ed", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/crypto_helper.c:175",
      NULL, 0 },
    { "sm4ks", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/crypto_helper.c:189",
      NULL, 0 },
    { "vl1re16_v", { 3 }, { 1 },
      dfu_vl1re16_v_env, ARRAY_SIZE(dfu_vl1re16_v_env), true,
      "../target/riscv/vector_helper.c:845",
      dfu_vl1re16_v_acc, ARRAY_SIZE(dfu_vl1re16_v_acc) },
    { "vl1re32_v", { 3 }, { 1 },
      dfu_vl1re32_v_env, ARRAY_SIZE(dfu_vl1re32_v_env), true,
      "../target/riscv/vector_helper.c:846",
      dfu_vl1re32_v_acc, ARRAY_SIZE(dfu_vl1re32_v_acc) },
    { "vl1re64_v", { 3 }, { 1 },
      dfu_vl1re64_v_env, ARRAY_SIZE(dfu_vl1re64_v_env), true,
      "../target/riscv/vector_helper.c:847",
      dfu_vl1re64_v_acc, ARRAY_SIZE(dfu_vl1re64_v_acc) },
    { "vl1re8_v", { 3 }, { 1 },
      dfu_vl1re8_v_env, ARRAY_SIZE(dfu_vl1re8_v_env), true,
      "../target/riscv/vector_helper.c:844",
      dfu_vl1re8_v_acc, ARRAY_SIZE(dfu_vl1re8_v_acc) },
    { "vl2re16_v", { 3 }, { 1 },
      dfu_vl2re16_v_env, ARRAY_SIZE(dfu_vl2re16_v_env), true,
      "../target/riscv/vector_helper.c:849",
      dfu_vl2re16_v_acc, ARRAY_SIZE(dfu_vl2re16_v_acc) },
    { "vl2re32_v", { 3 }, { 1 },
      dfu_vl2re32_v_env, ARRAY_SIZE(dfu_vl2re32_v_env), true,
      "../target/riscv/vector_helper.c:850",
      dfu_vl2re32_v_acc, ARRAY_SIZE(dfu_vl2re32_v_acc) },
    { "vl2re64_v", { 3 }, { 1 },
      dfu_vl2re64_v_env, ARRAY_SIZE(dfu_vl2re64_v_env), true,
      "../target/riscv/vector_helper.c:851",
      dfu_vl2re64_v_acc, ARRAY_SIZE(dfu_vl2re64_v_acc) },
    { "vl2re8_v", { 3 }, { 1 },
      dfu_vl2re8_v_env, ARRAY_SIZE(dfu_vl2re8_v_env), true,
      "../target/riscv/vector_helper.c:848",
      dfu_vl2re8_v_acc, ARRAY_SIZE(dfu_vl2re8_v_acc) },
    { "vl4re16_v", { 3 }, { 1 },
      dfu_vl4re16_v_env, ARRAY_SIZE(dfu_vl4re16_v_env), true,
      "../target/riscv/vector_helper.c:853",
      dfu_vl4re16_v_acc, ARRAY_SIZE(dfu_vl4re16_v_acc) },
    { "vl4re32_v", { 3 }, { 1 },
      dfu_vl4re32_v_env, ARRAY_SIZE(dfu_vl4re32_v_env), true,
      "../target/riscv/vector_helper.c:854",
      dfu_vl4re32_v_acc, ARRAY_SIZE(dfu_vl4re32_v_acc) },
    { "vl4re64_v", { 3 }, { 1 },
      dfu_vl4re64_v_env, ARRAY_SIZE(dfu_vl4re64_v_env), true,
      "../target/riscv/vector_helper.c:855",
      dfu_vl4re64_v_acc, ARRAY_SIZE(dfu_vl4re64_v_acc) },
    { "vl4re8_v", { 3 }, { 1 },
      dfu_vl4re8_v_env, ARRAY_SIZE(dfu_vl4re8_v_env), true,
      "../target/riscv/vector_helper.c:852",
      dfu_vl4re8_v_acc, ARRAY_SIZE(dfu_vl4re8_v_acc) },
    { "vl8re16_v", { 3 }, { 1 },
      dfu_vl8re16_v_env, ARRAY_SIZE(dfu_vl8re16_v_env), true,
      "../target/riscv/vector_helper.c:857",
      dfu_vl8re16_v_acc, ARRAY_SIZE(dfu_vl8re16_v_acc) },
    { "vl8re32_v", { 3 }, { 1 },
      dfu_vl8re32_v_env, ARRAY_SIZE(dfu_vl8re32_v_env), true,
      "../target/riscv/vector_helper.c:858",
      dfu_vl8re32_v_acc, ARRAY_SIZE(dfu_vl8re32_v_acc) },
    { "vl8re64_v", { 3 }, { 1 },
      dfu_vl8re64_v_env, ARRAY_SIZE(dfu_vl8re64_v_env), true,
      "../target/riscv/vector_helper.c:859",
      dfu_vl8re64_v_acc, ARRAY_SIZE(dfu_vl8re64_v_acc) },
    { "vl8re8_v", { 3 }, { 1 },
      dfu_vl8re8_v_env, ARRAY_SIZE(dfu_vl8re8_v_env), true,
      "../target/riscv/vector_helper.c:856",
      dfu_vl8re8_v_acc, ARRAY_SIZE(dfu_vl8re8_v_acc) },
    { "vs1r_v", { 3 }, { 1 },
      dfu_vs1r_v_env, ARRAY_SIZE(dfu_vs1r_v_env), true,
      "../target/riscv/vector_helper.c:869",
      dfu_vs1r_v_acc, ARRAY_SIZE(dfu_vs1r_v_acc) },
    { "vs2r_v", { 3 }, { 1 },
      dfu_vs2r_v_env, ARRAY_SIZE(dfu_vs2r_v_env), true,
      "../target/riscv/vector_helper.c:870",
      dfu_vs2r_v_acc, ARRAY_SIZE(dfu_vs2r_v_acc) },
    { "vs4r_v", { 3 }, { 1 },
      dfu_vs4r_v_env, ARRAY_SIZE(dfu_vs4r_v_env), true,
      "../target/riscv/vector_helper.c:871",
      dfu_vs4r_v_acc, ARRAY_SIZE(dfu_vs4r_v_acc) },
    { "vs8r_v", { 3 }, { 1 },
      dfu_vs8r_v_env, ARRAY_SIZE(dfu_vs8r_v_env), true,
      "../target/riscv/vector_helper.c:872",
      dfu_vs8r_v_acc, ARRAY_SIZE(dfu_vs8r_v_acc) },
    { "vsetvl", { 0 }, { 0 },
      dfu_vsetvl_env, ARRAY_SIZE(dfu_vsetvl_env), true,
      "../target/riscv/vector_helper.c:35",
      NULL, 0 },
    { "xperm4", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/bitmanip_helper.c:124",
      NULL, 0 },
    { "xperm8", { 0 }, { 0 },
      NULL, 0, true,
      "../target/riscv/bitmanip_helper.c:129",
      NULL, 0 },
    { "lookup_tb_ptr", { 0 }, { 0 },
      dfu_lookup_tb_ptr_env, ARRAY_SIZE(dfu_lookup_tb_ptr_env), true,
      "accel/tcg/cpu-exec.c HELPER(lookup_tb_ptr)",
      NULL, 0 },
    { NULL, { 0 }, { 0 }, NULL, 0, false, NULL, NULL, 0 }
};
