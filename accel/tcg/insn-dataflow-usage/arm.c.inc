/*
 * CP-H per-helper usage -- aarch64.  GENERATED, do not edit.
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
 * Rows refused, and therefore still OVER-APPROXIMATED at run time:
 *   access_check_cp_reg      env passed to accessfn(), not defined in this unit
 *   sete                     env passed to stepfn(), not defined in this unit
 *   setm                     env passed to stepfn(), not defined in this unit
 *   setp                     env passed to stepfn(), not defined in this unit
 *   sve_ld1bb_r              env passed to tlb_fn(), not defined in this unit
 *   sve_st1bb_r              env passed to tlb_fn(), not defined in this unit
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
 *     ../target/arm/helper.c:11768, whose read set is derived by the same
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

static const DfHelperField dfu_autia_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception), sizeof(((CPUArchState *)0)->exception), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys), sizeof(((CPUArchState *)0)->keys), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/pauth_helper.c:549 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2676 */
};
static const DfHelperField dfu_cpye_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:1462 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception), sizeof(((CPUArchState *)0)->exception), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2454 */
};
static const DfHelperField dfu_cpyfe_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:1462 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception), sizeof(((CPUArchState *)0)->exception), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2454 */
};
static const DfHelperField dfu_cpyfm_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:1462 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception), sizeof(((CPUArchState *)0)->exception), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2357 */
};
static const DfHelperField dfu_cpyfp_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2324 */
    { offsetof(CPUArchState, NF), sizeof(((CPUArchState *)0)->NF), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2322 */
    { offsetof(CPUArchState, VF), sizeof(((CPUArchState *)0)->VF), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2325 */
    { offsetof(CPUArchState, ZF), sizeof(((CPUArchState *)0)->ZF), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2323 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception), sizeof(((CPUArchState *)0)->exception), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2236 */
};
static const DfHelperField dfu_cpym_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:1462 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception), sizeof(((CPUArchState *)0)->exception), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2357 */
};
static const DfHelperField dfu_cpyp_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2324 */
    { offsetof(CPUArchState, NF), sizeof(((CPUArchState *)0)->NF), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2322 */
    { offsetof(CPUArchState, VF), sizeof(((CPUArchState *)0)->VF), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2325 */
    { offsetof(CPUArchState, ZF), sizeof(((CPUArchState *)0)->ZF), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2323 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception), sizeof(((CPUArchState *)0)->exception), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2236 */
};
static const DfHelperField dfu_dc_zva_env[] = {
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:47 */
};
static const DfHelperField dfu_exception_bkpt_insn_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/debug_helper.c:31 */
    { offsetof(CPUArchState, exception), sizeof(((CPUArchState *)0)->exception), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/debug_helper.c:522 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2676 */
};
static const DfHelperField dfu_exception_with_syndrome_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/helper.c:5631 */
    { offsetof(CPUArchState, exception), sizeof(((CPUArchState *)0)->exception), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2676 */
};
static const DfHelperField dfu_guarded_page_br_env[] = {
    { offsetof(CPUArchState, btype), sizeof(((CPUArchState *)0)->btype), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2567 */
};
static const DfHelperField dfu_guarded_page_check_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, btype), sizeof(((CPUArchState *)0)->btype), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2556 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/helper.c:5631 */
    { offsetof(CPUArchState, exception), sizeof(((CPUArchState *)0)->exception), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pc), sizeof(((CPUArchState *)0)->pc), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/tcg/helper-a64.c:2555 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2676 */
};
static const DfHelperField dfu_irg_env[] = {
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/mte_helper.c:224 */
};
static const DfHelperField dfu_ldg_env[] = {
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:47 */
};
static const DfHelperField dfu_pacia_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception), sizeof(((CPUArchState *)0)->exception), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys), sizeof(((CPUArchState *)0)->keys), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/pauth_helper.c:498 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2676 */
};
static const DfHelperField dfu_rebuild_hflags_a64_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/helper.c:5631 */
    { offsetof(CPUArchState, daif), sizeof(((CPUArchState *)0)->daif), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/debug_helper.c:89 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_WR, DF_HF_OPERAND },   /* ../target/arm/tcg/hflags.c:499 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/helper.c:275 */
    { offsetof(CPUArchState, svcr), sizeof(((CPUArchState *)0)->svcr), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/helper.c:6771 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/helper.c:277 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/helper.c:11687 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/helper.c:6740 */
};
static const DfHelperField dfu_st2g_env[] = {
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:47 */
};
static const DfHelperField dfu_stg_env[] = {
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND },   /* ../target/arm/internals.h:47 */
};
static const DfHelperField dfu_lookup_tb_ptr_env[] = {
    { offsetof(CPUArchState, btype), sizeof(((CPUArchState *)0)->btype), INSN_DF_RD, DF_HF_XLAT },   /* ../target/arm/helper.c:11779 */
    { offsetof(CPUArchState, condexec_bits), sizeof(((CPUArchState *)0)->condexec_bits), INSN_DF_RD, DF_HF_XLAT },   /* ../target/arm/helper.c:11828 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_XLAT },   /* ../target/arm/helper.c:11817 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_XLAT },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_XLAT },   /* ../target/arm/helper.c:11774 */
    { offsetof(CPUArchState, pc), sizeof(((CPUArchState *)0)->pc), INSN_DF_RD, DF_HF_XLAT },   /* ../target/arm/helper.c:11777 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_XLAT },   /* ../target/arm/helper.c:11840 */
    { offsetof(CPUArchState, regs), sizeof(((CPUArchState *)0)->regs), INSN_DF_RD, DF_HF_XLAT },   /* ../target/arm/helper.c:11782 */
    { offsetof(CPUArchState, thumb), sizeof(((CPUArchState *)0)->thumb), INSN_DF_RD, DF_HF_XLAT },   /* ../target/arm/helper.c:11827 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_XLAT },   /* ../target/arm/helper.c:11786 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD, DF_HF_XLAT },   /* ../target/arm/helper.c:11819 */
};

static const DfHelperUsage df_helper_usage[] = {
    { "autia", { 0 },
      dfu_autia_env, ARRAY_SIZE(dfu_autia_env), true,
      "../target/arm/tcg/pauth_helper.c:552" },
    { "cpye", { 0 },
      dfu_cpye_env, ARRAY_SIZE(dfu_cpye_env), true,
      "../target/arm/tcg/helper-a64.c:2519" },
    { "cpyfe", { 0 },
      dfu_cpyfe_env, ARRAY_SIZE(dfu_cpyfe_env), true,
      "../target/arm/tcg/helper-a64.c:2525" },
    { "cpyfm", { 0 },
      dfu_cpyfm_env, ARRAY_SIZE(dfu_cpyfm_env), true,
      "../target/arm/tcg/helper-a64.c:2433" },
    { "cpyfp", { 0 },
      dfu_cpyfp_env, ARRAY_SIZE(dfu_cpyfp_env), true,
      "../target/arm/tcg/helper-a64.c:2335" },
    { "cpym", { 0 },
      dfu_cpym_env, ARRAY_SIZE(dfu_cpym_env), true,
      "../target/arm/tcg/helper-a64.c:2427" },
    { "cpyp", { 0 },
      dfu_cpyp_env, ARRAY_SIZE(dfu_cpyp_env), true,
      "../target/arm/tcg/helper-a64.c:2329" },
    { "dc_zva", { 0 },
      dfu_dc_zva_env, ARRAY_SIZE(dfu_dc_zva_env), true,
      "../target/arm/tcg/helper-a64.c:1274" },
    { "exception_bkpt_insn", { 0 },
      dfu_exception_bkpt_insn_env, ARRAY_SIZE(dfu_exception_bkpt_insn_env), true,
      "../target/arm/debug_helper.c:516" },
    { "exception_with_syndrome", { 0 },
      dfu_exception_with_syndrome_env, ARRAY_SIZE(dfu_exception_with_syndrome_env), true,
      "../target/arm/tcg/op_helper.c:536" },
    { "get_cp_reg64", { 0, 1 },
      NULL, 0, true,
      "../target/arm/tcg/op_helper.c:1064" },
    { "guarded_page_br", { 0 },
      dfu_guarded_page_br_env, ARRAY_SIZE(dfu_guarded_page_br_env), true,
      "../target/arm/tcg/helper-a64.c:2561" },
    { "guarded_page_check", { 0 },
      dfu_guarded_page_check_env, ARRAY_SIZE(dfu_guarded_page_check_env), true,
      "../target/arm/tcg/helper-a64.c:2547" },
    { "gvec_addp_b", { 3, 3, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2609" },
    { "gvec_umaxp_b", { 3, 3, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2619" },
    { "gvec_vfma_d", { 3, 3, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1622" },
    { "gvec_vfma_s", { 3, 3, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1621" },
    { "irg", { 0 },
      dfu_irg_env, ARRAY_SIZE(dfu_irg_env), true,
      "../target/arm/tcg/mte_helper.c:222" },
    { "ldg", { 0 },
      dfu_ldg_env, ARRAY_SIZE(dfu_ldg_env), true,
      "../target/arm/tcg/mte_helper.c:301" },
    { "lookup_cp_reg", { 0 },
      NULL, 0, true,
      "../target/arm/tcg/op_helper.c:930" },
    { "pacia", { 0 },
      dfu_pacia_env, ARRAY_SIZE(dfu_pacia_env), true,
      "../target/arm/tcg/pauth_helper.c:491" },
    { "rbit64", { 0 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:67" },
    { "rebuild_hflags_a64", { 0 },
      dfu_rebuild_hflags_a64_env, ARRAY_SIZE(dfu_rebuild_hflags_a64_env), true,
      "../target/arm/tcg/hflags.c:494" },
    { "rintd", { 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:1171" },
    { "sdiv64", { 0 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:56" },
    { "set_cp_reg64", { 0, 1 },
      NULL, 0, true,
      "../target/arm/tcg/op_helper.c:1044" },
    { "set_rmode", { 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:479" },
    { "st2g", { 0 },
      dfu_st2g_env, ARRAY_SIZE(dfu_st2g_env), true,
      "../target/arm/tcg/mte_helper.c:429" },
    { "stg", { 0 },
      dfu_stg_env, ARRAY_SIZE(dfu_stg_env), true,
      "../target/arm/tcg/mte_helper.c:371" },
    { "sve_whilel", { 3 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4143" },
    { "udiv64", { 0 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:48" },
    { "unaligned_access", { 0 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:1392" },
    { "vfp_addd", { 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:278" },
    { "vfp_cmpd_a64", { 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:161" },
    { "vfp_divd", { 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:281" },
    { "vfp_fcvtds", { 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:377" },
    { "vfp_fcvtsd", { 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:382" },
    { "vfp_maxd", { 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:283" },
    { "vfp_mind", { 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:282" },
    { "vfp_muladdd", { 0, 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:1117" },
    { "vfp_muld", { 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:280" },
    { "vfp_muls", { 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:280" },
    { "vfp_sqrtd", { 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:298" },
    { "vfp_sqtod", { 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:450" },
    { "vfp_sqtos", { 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:456" },
    { "vfp_subd", { 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:279" },
    { "vfp_tosqd", { 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:450" },
    { "vfp_touqd", { 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:453" },
    { "vfp_touqs", { 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:459" },
    { "vfp_uqtod", { 0, 0, 3 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:453" },
    { "yield", { 0 },
      NULL, 0, true,
      "../target/arm/tcg/op_helper.c:498" },
    { "lookup_tb_ptr", { 0 },
      dfu_lookup_tb_ptr_env, ARRAY_SIZE(dfu_lookup_tb_ptr_env), true,
      "accel/tcg/cpu-exec.c HELPER(lookup_tb_ptr)" },
    { NULL, { 0 }, NULL, 0, false, NULL }
};
