/*
 * CP-H per-helper usage -- x86_64.  GENERATED, do not edit.
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
 * compiles this file (they define TARGET_I386): i386-linux-user, i386-softmmu, x86_64-linux-user, x86_64-softmmu.
 *
 * Rows emitted under a DERIVED guard -- the field is a member on
 * only part of that family, and the macro named is the one whose
 * truth set over the family is exactly the set that has it:
 *   syscall                defined(TARGET_X86_64)     regs[11]
 *
 * READS THE EMULATOR MAKES ON ITS OWN BEHALF -- derived,
 * enumerated, and marked DF_HF_XLAT so the footprint is complete
 * and the OPERAND set is not.  Selected by the SOURCE LINE the
 * reader read the member off, never by helper name, so a sibling
 * reaching the same line is covered the day it is derived:
 *   divl_EAX                 eip      ../target/i386/tcg/excp_helper.c:127
 *   divq_EAX                 eip      ../target/i386/tcg/excp_helper.c:127
 *   fwait                    eip      ../target/i386/tcg/excp_helper.c:127
 *   idivq_EAX                eip      ../target/i386/tcg/excp_helper.c:127
 *   raise_exception          eip      ../target/i386/tcg/excp_helper.c:127
 *   rechecking_single_step   eip      ../target/i386/tcg/excp_helper.c:127
 *   xgetbv                   eip      ../target/i386/tcg/excp_helper.c:127
 *   eip @ ../target/i386/tcg/excp_helper.c:127:
 *     the exception frame's return address -- `env->exception_next_eip =
 *     env->eip + next_eip_addend` in raise_interrupt2(), the common raise
 *     path every helper that can fault reaches. It records WHERE the
 *     exception happened; the instruction computes nothing from it
 *
 * Rows refused, and therefore still OVER-APPROXIMATED at run time:
 *   rdtsc                    env passed to cpu_get_tsc(), not defined in this unit
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
 *     ../target/i386/cpu.h:2630, whose read set is derived by the same
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

static const DfHelperField dfu_addpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:529 */
};
static const DfHelperField dfu_addps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:529 */
};
static const DfHelperField dfu_addsd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:529 */
};
static const DfHelperField dfu_comisd_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1151 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1150 */
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1149 */
};
static const DfHelperField dfu_comiss_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1127 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1126 */
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1125 */
};
static const DfHelperField dfu_cpuid_env[] = {
    { offsetof(CPUArchState, avail_cpu_topo), sizeof(((CPUArchState *)0)->avail_cpu_topo), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7040 */
    { offsetof(CPUArchState, avx10_version), sizeof(((CPUArchState *)0)->avx10_version), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7230 */
    { offsetof(CPUArchState, cache_info_amd.l1d_cache), sizeof(((CPUArchState *)0)->cache_info_amd.l1d_cache), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7293 */
    { offsetof(CPUArchState, cache_info_amd.l1i_cache), sizeof(((CPUArchState *)0)->cache_info_amd.l1i_cache), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7294 */
    { offsetof(CPUArchState, cache_info_amd.l2_cache), sizeof(((CPUArchState *)0)->cache_info_amd.l2_cache), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7310 */
    { offsetof(CPUArchState, cache_info_amd.l3_cache), sizeof(((CPUArchState *)0)->cache_info_amd.l3_cache), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7312 */
    { offsetof(CPUArchState, cache_info_cpuid2.l1d_cache), sizeof(((CPUArchState *)0)->cache_info_cpuid2.l1d_cache), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6876 */
    { offsetof(CPUArchState, cache_info_cpuid2.l1i_cache), sizeof(((CPUArchState *)0)->cache_info_cpuid2.l1i_cache), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6877 */
    { offsetof(CPUArchState, cache_info_cpuid2.l2_cache), sizeof(((CPUArchState *)0)->cache_info_cpuid2.l2_cache), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6878 */
    { offsetof(CPUArchState, cache_info_cpuid2.l3_cache), sizeof(((CPUArchState *)0)->cache_info_cpuid2.l3_cache), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6874 */
    { offsetof(CPUArchState, cache_info_cpuid4.l1d_cache), sizeof(((CPUArchState *)0)->cache_info_cpuid4.l1d_cache), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6908 */
    { offsetof(CPUArchState, cache_info_cpuid4.l1i_cache), sizeof(((CPUArchState *)0)->cache_info_cpuid4.l1i_cache), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6916 */
    { offsetof(CPUArchState, cache_info_cpuid4.l2_cache), sizeof(((CPUArchState *)0)->cache_info_cpuid4.l2_cache), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6924 */
    { offsetof(CPUArchState, cache_info_cpuid4.l3_cache), sizeof(((CPUArchState *)0)->cache_info_cpuid4.l3_cache), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6930 */
    { offsetof(CPUArchState, cpuid_level), sizeof(((CPUArchState *)0)->cpuid_level), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6812 */
    { offsetof(CPUArchState, cpuid_level_func7), sizeof(((CPUArchState *)0)->cpuid_level_func7), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6960 */
    { offsetof(CPUArchState, cpuid_model), sizeof(((CPUArchState *)0)->cpuid_model), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/cpu.c:7278, INDEX NOT STATED */
    { offsetof(CPUArchState, cpuid_vendor1), sizeof(((CPUArchState *)0)->cpuid_vendor1), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6826 */
    { offsetof(CPUArchState, cpuid_vendor2), sizeof(((CPUArchState *)0)->cpuid_vendor2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6827 */
    { offsetof(CPUArchState, cpuid_vendor3), sizeof(((CPUArchState *)0)->cpuid_vendor3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6828 */
    { offsetof(CPUArchState, cpuid_version), sizeof(((CPUArchState *)0)->cpuid_version), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6831 */
    { offsetof(CPUArchState, cpuid_xlevel), sizeof(((CPUArchState *)0)->cpuid_xlevel), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6808 */
    { offsetof(CPUArchState, cpuid_xlevel2), sizeof(((CPUArchState *)0)->cpuid_xlevel2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6806 */
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6835 */
    { offsetof(CPUArchState, features[0]), sizeof(((CPUArchState *)0)->features[0]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6838 */
    { offsetof(CPUArchState, features[10]), sizeof(((CPUArchState *)0)->features[10]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7329 */
    { offsetof(CPUArchState, features[11]), sizeof(((CPUArchState *)0)->features[11]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7442 */
    { offsetof(CPUArchState, features[12]), sizeof(((CPUArchState *)0)->features[12]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7443 */
    { offsetof(CPUArchState, features[13]), sizeof(((CPUArchState *)0)->features[13]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7402 */
    { offsetof(CPUArchState, features[14]), sizeof(((CPUArchState *)0)->features[14]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7419 */
    { offsetof(CPUArchState, features[17]), sizeof(((CPUArchState *)0)->features[17]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7349 */
    { offsetof(CPUArchState, features[18]), sizeof(((CPUArchState *)0)->features[18]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7072 */
    { offsetof(CPUArchState, features[19]), sizeof(((CPUArchState *)0)->features[19]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6951 */
    { offsetof(CPUArchState, features[1]), sizeof(((CPUArchState *)0)->features[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6834 */
    { offsetof(CPUArchState, features[20]), sizeof(((CPUArchState *)0)->features[20]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:1915 */
    { offsetof(CPUArchState, features[21]), sizeof(((CPUArchState *)0)->features[21]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:1914 */
    { offsetof(CPUArchState, features[2]), sizeof(((CPUArchState *)0)->features[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6961 */
    { offsetof(CPUArchState, features[34]), sizeof(((CPUArchState *)0)->features[34]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7178 */
    { offsetof(CPUArchState, features[38]), sizeof(((CPUArchState *)0)->features[38]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:1930 */
    { offsetof(CPUArchState, features[39]), sizeof(((CPUArchState *)0)->features[39]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:1929 */
    { offsetof(CPUArchState, features[3]), sizeof(((CPUArchState *)0)->features[3]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6962 */
    { offsetof(CPUArchState, features[40]), sizeof(((CPUArchState *)0)->features[40]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6969 */
    { offsetof(CPUArchState, features[41]), sizeof(((CPUArchState *)0)->features[41]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6973 */
    { offsetof(CPUArchState, features[42]), sizeof(((CPUArchState *)0)->features[42]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7230 */
    { offsetof(CPUArchState, features[4]), sizeof(((CPUArchState *)0)->features[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6966 */
    { offsetof(CPUArchState, features[5]), sizeof(((CPUArchState *)0)->features[5]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6968 */
    { offsetof(CPUArchState, features[6]), sizeof(((CPUArchState *)0)->features[6]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7268 */
    { offsetof(CPUArchState, features[7]), sizeof(((CPUArchState *)0)->features[7]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7267 */
    { offsetof(CPUArchState, features[8]), sizeof(((CPUArchState *)0)->features[8]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7317 */
    { offsetof(CPUArchState, features[9]), sizeof(((CPUArchState *)0)->features[9]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7319 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7271 */
    { offsetof(CPUArchState, regs[0]), sizeof(((CPUArchState *)0)->regs[0]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:57 */
    { offsetof(CPUArchState, regs[1]), sizeof(((CPUArchState *)0)->regs[1]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:57 */
    { offsetof(CPUArchState, regs[2]), sizeof(((CPUArchState *)0)->regs[2]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:62 */
    { offsetof(CPUArchState, regs[3]), sizeof(((CPUArchState *)0)->regs[3]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:60 */
    { offsetof(CPUArchState, topo_info), sizeof(((CPUArchState *)0)->topo_info), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:6799 */
    { offsetof(CPUArchState, xcr0), sizeof(((CPUArchState *)0)->xcr0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:7067 */
};
static const DfHelperField dfu_cvtsi2sd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:679 */
};
static const DfHelperField dfu_cvtsq2sd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:690 */
};
static const DfHelperField dfu_cvtsq2ss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:685 */
};
static const DfHelperField dfu_cvtss2sd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:625 */
};
static const DfHelperField dfu_cvttsd2sq_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:839 */
};
static const DfHelperField dfu_cvttss2sq_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:834 */
};
static const DfHelperField dfu_divl_EAX_env[] = {
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, regs[0]), sizeof(((CPUArchState *)0)->regs[0]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:114 */
    { offsetof(CPUArchState, regs[2]), sizeof(((CPUArchState *)0)->regs[2]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:114 */
};
static const DfHelperField dfu_divq_EAX_env[] = {
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, regs[0]), sizeof(((CPUArchState *)0)->regs[0]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:376 */
    { offsetof(CPUArchState, regs[2]), sizeof(((CPUArchState *)0)->regs[2]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:377 */
};
static const DfHelperField dfu_fabs_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:669, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:669 */
};
static const DfHelperField dfu_fadd_ST0_FT0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:580, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:580 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:580 */
};
static const DfHelperField dfu_fadd_STN_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:620, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:620 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fchs_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:664, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:664 */
};
static const DfHelperField dfu_fdecstp_env[] = {
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:479 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:480 */
};
static const DfHelperField dfu_ffree_STN_env[] = {
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:493 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:493, INDEX NOT STATED */
};
static const DfHelperField dfu_fincstp_env[] = {
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:485 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:486 */
};
static const DfHelperField dfu_fld1_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:674, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:674 */
};
static const DfHelperField dfu_fldcw_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:780 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2731 */
};
static const DfHelperField dfu_fldenv_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:780 */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2520 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2545, INDEX NOT STATED */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2731 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2521 */
};
static const DfHelperField dfu_fldl_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:301, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:299 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:303, INDEX NOT STATED */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fldpi_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:707, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:707 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:704 */
};
static const DfHelperField dfu_flds_FT0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:251 */
};
static const DfHelperField dfu_flds_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:284, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:282 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:286, INDEX NOT STATED */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fldt_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:454, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:453 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:456, INDEX NOT STATED */
};
static const DfHelperField dfu_fldz_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:743, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:743 */
};
static const DfHelperField dfu_fmov_FT0_STN_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:503, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:503 */
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:503 */
};
static const DfHelperField dfu_fmov_ST0_STN_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:508, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:508 */
};
static const DfHelperField dfu_fmov_STN_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:513, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:513 */
};
static const DfHelperField dfu_fmul_ST0_FT0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:587, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:587 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:587 */
};
static const DfHelperField dfu_fnstcw_env[] = {
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:758 */
};
static const DfHelperField dfu_fnstsw_env[] = {
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:753 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:753 */
};
static const DfHelperField dfu_fpop_env[] = {
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:85 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:85, INDEX NOT STATED */
};
static const DfHelperField dfu_fpush_env[] = {
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:79 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:80, INDEX NOT STATED */
};
static const DfHelperField dfu_fsqrt_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2303, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2303 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2304 */
};
static const DfHelperField dfu_fstenv_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:780 */
    { offsetof(CPUArchState, fpcs), sizeof(((CPUArchState *)0)->fpcs), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2478 */
    { offsetof(CPUArchState, fpdp), sizeof(((CPUArchState *)0)->fpdp), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2479 */
    { offsetof(CPUArchState, fpds), sizeof(((CPUArchState *)0)->fpds), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2480 */
    { offsetof(CPUArchState, fpip), sizeof(((CPUArchState *)0)->fpip), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2477 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2459, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2452 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2456, INDEX NOT STATED */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2474 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2452 */
};
static const DfHelperField dfu_fstl_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:361, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:361 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fsts_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:348, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:348 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fstt_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:464, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:464 */
};
static const DfHelperField dfu_fsubr_STN_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:641, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:641 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fucomi_ST0_FT0_env[] = {
    { offsetof(CPUArchState, cc_dst), sizeof(((CPUArchState *)0)->cc_dst), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src2), sizeof(((CPUArchState *)0)->cc_src2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:570, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:570 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:570 */
};
static const DfHelperField dfu_fwait_env[] = {
    { offsetof(CPUArchState, cr[0]), sizeof(((CPUArchState *)0)->cr[0]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:232 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:809 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
};
static const DfHelperField dfu_fxam_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2415, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2415 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2422, INDEX NOT STATED */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2417 */
};
static const DfHelperField dfu_fxchg_ST0_STN_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:520, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:520 */
};
static const DfHelperField dfu_idivq_EAX_env[] = {
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, regs[0]), sizeof(((CPUArchState *)0)->regs[0]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:392 */
    { offsetof(CPUArchState, regs[2]), sizeof(((CPUArchState *)0)->regs[2]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:393 */
};
static const DfHelperField dfu_ldmxcsr_env[] = {
    { offsetof(CPUArchState, mxcsr), sizeof(((CPUArchState *)0)->mxcsr), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2723 */
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3271 */
};
static const DfHelperField dfu_mulpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:531 */
};
static const DfHelperField dfu_mulps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:531 */
};
static const DfHelperField dfu_mulsd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:531 */
};
static const DfHelperField dfu_mulss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:531 */
};
static const DfHelperField dfu_raise_exception_env[] = {
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
};
static const DfHelperField dfu_read_eflags_env[] = {
    { offsetof(CPUArchState, cc_dst), sizeof(((CPUArchState *)0)->cc_dst), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src2), sizeof(((CPUArchState *)0)->cc_src2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, df), sizeof(((CPUArchState *)0)->df), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:333 */
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:334 */
};
static const DfHelperField dfu_rechecking_single_step_env[] = {
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/bpt_helper.c:37 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
};
static const DfHelperField dfu_sqrtsd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:565 */
};
static const DfHelperField dfu_subps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:530 */
};
static const DfHelperField dfu_subsd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:530 */
};
static const DfHelperField dfu_subss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:530 */
};
#if defined(TARGET_X86_64)
static const DfHelperField dfu_syscall_env[] = {
    { offsetof(CPUArchState, cc_dst), sizeof(((CPUArchState *)0)->cc_dst), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src2), sizeof(((CPUArchState *)0)->cc_src2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, df), sizeof(((CPUArchState *)0)->df), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2659 */
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2657 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/user/seg_helper.c:108 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/user/seg_helper.c:114 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/user/seg_helper.c:115 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/user/seg_helper.c:103 */
    { offsetof(CPUArchState, regs[11]), sizeof(((CPUArchState *)0)->regs[11]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/user/seg_helper.c:109 */
    { offsetof(CPUArchState, regs[1]), sizeof(((CPUArchState *)0)->regs[1]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/user/seg_helper.c:108 */
};
#endif
static const DfHelperField dfu_ucomisd_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1139 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1138 */
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1137 */
};
static const DfHelperField dfu_update_mxcsr_env[] = {
    { offsetof(CPUArchState, mxcsr), sizeof(((CPUArchState *)0)->mxcsr), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3298 */
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3290 */
};
static const DfHelperField dfu_xgetbv_env[] = {
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3198 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, features[18]), sizeof(((CPUArchState *)0)->features[18]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3206 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2751 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, xcr0), sizeof(((CPUArchState *)0)->xcr0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3204 */
};
static const DfHelperField dfu_lookup_tb_ptr_env[] = {
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/cpu.h:2634 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/cpu.h:2637 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/cpu.h:2633 */
    { offsetof(CPUArchState, segs), sizeof(((CPUArchState *)0)->segs), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/cpu.h:2639 */
};

static const DfHelperUsage df_helper_usage[] = {
    { "addpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_addpd_xmm_env, ARRAY_SIZE(dfu_addpd_xmm_env), true,
      "../target/i386/ops_sse.h:529",
      NULL, 0 },
    { "addps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_addps_xmm_env, ARRAY_SIZE(dfu_addps_xmm_env), true,
      "../target/i386/ops_sse.h:529",
      NULL, 0 },
    { "addsd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_addsd_env, ARRAY_SIZE(dfu_addsd_env), true,
      "../target/i386/ops_sse.h:529",
      NULL, 0 },
    { "cc_compute_all", { 0 }, { 0 },
      NULL, 0, true,
      "../target/i386/tcg/cc_helper.c:77",
      NULL, 0 },
    { "cc_compute_c", { 0 }, { 0 },
      NULL, 0, true,
      "../target/i386/tcg/cc_helper.c:214",
      NULL, 0 },
    { "cc_compute_nz", { 0 }, { 0 },
      NULL, 0, true,
      "../target/i386/tcg/cc_helper.c:64",
      NULL, 0 },
    { "comisd", { 0, 1, 1 }, { 0, 64, 64 },
      dfu_comisd_env, ARRAY_SIZE(dfu_comisd_env), true,
      "../target/i386/ops_sse.h:1142",
      NULL, 0 },
    { "comiss", { 0, 1, 1 }, { 0, 64, 64 },
      dfu_comiss_env, ARRAY_SIZE(dfu_comiss_env), true,
      "../target/i386/ops_sse.h:1118",
      NULL, 0 },
    { "cpuid", { 0 }, { 0 },
      dfu_cpuid_env, ARRAY_SIZE(dfu_cpuid_env), true,
      "../target/i386/tcg/misc_helper.c:51",
      NULL, 0 },
    { "cvtsi2sd", { 0, 2 }, { 0, 64 },
      dfu_cvtsi2sd_env, ARRAY_SIZE(dfu_cvtsi2sd_env), true,
      "../target/i386/ops_sse.h:677",
      NULL, 0 },
    { "cvtsq2sd", { 0, 2 }, { 0, 64 },
      dfu_cvtsq2sd_env, ARRAY_SIZE(dfu_cvtsq2sd_env), true,
      "../target/i386/ops_sse.h:688",
      NULL, 0 },
    { "cvtsq2ss", { 0, 2 }, { 0, 64 },
      dfu_cvtsq2ss_env, ARRAY_SIZE(dfu_cvtsq2ss_env), true,
      "../target/i386/ops_sse.h:683",
      NULL, 0 },
    { "cvtss2sd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cvtss2sd_env, ARRAY_SIZE(dfu_cvtss2sd_env), true,
      "../target/i386/ops_sse.h:622",
      NULL, 0 },
    { "cvttsd2sq", { 0, 1 }, { 0, 64 },
      dfu_cvttsd2sq_env, ARRAY_SIZE(dfu_cvttsd2sq_env), true,
      "../target/i386/ops_sse.h:837",
      NULL, 0 },
    { "cvttss2sq", { 0, 1 }, { 0, 64 },
      dfu_cvttss2sq_env, ARRAY_SIZE(dfu_cvttss2sq_env), true,
      "../target/i386/ops_sse.h:832",
      NULL, 0 },
    { "divl_EAX", { 0 }, { 0 },
      dfu_divl_EAX_env, ARRAY_SIZE(dfu_divl_EAX_env), true,
      "../target/i386/tcg/int_helper.c:109",
      NULL, 0 },
    { "divq_EAX", { 0 }, { 0 },
      dfu_divq_EAX_env, ARRAY_SIZE(dfu_divq_EAX_env), true,
      "../target/i386/tcg/int_helper.c:369",
      NULL, 0 },
    { "fabs_ST0", { 0 }, { 0 },
      dfu_fabs_ST0_env, ARRAY_SIZE(dfu_fabs_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:667",
      NULL, 0 },
    { "fadd_ST0_FT0", { 0 }, { 0 },
      dfu_fadd_ST0_FT0_env, ARRAY_SIZE(dfu_fadd_ST0_FT0_env), true,
      "../target/i386/tcg/fpu_helper.c:577",
      NULL, 0 },
    { "fadd_STN_ST0", { 0 }, { 0 },
      dfu_fadd_STN_ST0_env, ARRAY_SIZE(dfu_fadd_STN_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:617",
      NULL, 0 },
    { "fchs_ST0", { 0 }, { 0 },
      dfu_fchs_ST0_env, ARRAY_SIZE(dfu_fchs_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:662",
      NULL, 0 },
    { "fdecstp", { 0 }, { 0 },
      dfu_fdecstp_env, ARRAY_SIZE(dfu_fdecstp_env), true,
      "../target/i386/tcg/fpu_helper.c:477",
      NULL, 0 },
    { "ffree_STN", { 0 }, { 0 },
      dfu_ffree_STN_env, ARRAY_SIZE(dfu_ffree_STN_env), true,
      "../target/i386/tcg/fpu_helper.c:491",
      NULL, 0 },
    { "fincstp", { 0 }, { 0 },
      dfu_fincstp_env, ARRAY_SIZE(dfu_fincstp_env), true,
      "../target/i386/tcg/fpu_helper.c:483",
      NULL, 0 },
    { "fld1_ST0", { 0 }, { 0 },
      dfu_fld1_ST0_env, ARRAY_SIZE(dfu_fld1_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:672",
      NULL, 0 },
    { "fldcw", { 0 }, { 0 },
      dfu_fldcw_env, ARRAY_SIZE(dfu_fldcw_env), true,
      "../target/i386/tcg/fpu_helper.c:797",
      NULL, 0 },
    { "fldenv", { 0 }, { 0 },
      dfu_fldenv_env, ARRAY_SIZE(dfu_fldenv_env), true,
      "../target/i386/tcg/fpu_helper.c:2550",
      NULL, 0 },
    { "fldl_ST0", { 0 }, { 0 },
      dfu_fldl_ST0_env, ARRAY_SIZE(dfu_fldl_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:290",
      NULL, 0 },
    { "fldpi_ST0", { 0 }, { 0 },
      dfu_fldpi_ST0_env, ARRAY_SIZE(dfu_fldpi_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:702",
      NULL, 0 },
    { "flds_FT0", { 0 }, { 0 },
      dfu_flds_FT0_env, ARRAY_SIZE(dfu_flds_FT0_env), true,
      "../target/i386/tcg/fpu_helper.c:242",
      NULL, 0 },
    { "flds_ST0", { 0 }, { 0 },
      dfu_flds_ST0_env, ARRAY_SIZE(dfu_flds_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:273",
      NULL, 0 },
    { "fldt_ST0", { 0 }, { 0 },
      dfu_fldt_ST0_env, ARRAY_SIZE(dfu_fldt_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:446",
      NULL, 0 },
    { "fldz_ST0", { 0 }, { 0 },
      dfu_fldz_ST0_env, ARRAY_SIZE(dfu_fldz_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:741",
      NULL, 0 },
    { "fmov_FT0_STN", { 0 }, { 0 },
      dfu_fmov_FT0_STN_env, ARRAY_SIZE(dfu_fmov_FT0_STN_env), true,
      "../target/i386/tcg/fpu_helper.c:501",
      NULL, 0 },
    { "fmov_ST0_STN", { 0 }, { 0 },
      dfu_fmov_ST0_STN_env, ARRAY_SIZE(dfu_fmov_ST0_STN_env), true,
      "../target/i386/tcg/fpu_helper.c:506",
      NULL, 0 },
    { "fmov_STN_ST0", { 0 }, { 0 },
      dfu_fmov_STN_ST0_env, ARRAY_SIZE(dfu_fmov_STN_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:511",
      NULL, 0 },
    { "fmul_ST0_FT0", { 0 }, { 0 },
      dfu_fmul_ST0_FT0_env, ARRAY_SIZE(dfu_fmul_ST0_FT0_env), true,
      "../target/i386/tcg/fpu_helper.c:584",
      NULL, 0 },
    { "fnstcw", { 0 }, { 0 },
      dfu_fnstcw_env, ARRAY_SIZE(dfu_fnstcw_env), true,
      "../target/i386/tcg/fpu_helper.c:756",
      NULL, 0 },
    { "fnstsw", { 0 }, { 0 },
      dfu_fnstsw_env, ARRAY_SIZE(dfu_fnstsw_env), true,
      "../target/i386/tcg/fpu_helper.c:751",
      NULL, 0 },
    { "fpop", { 0 }, { 0 },
      dfu_fpop_env, ARRAY_SIZE(dfu_fpop_env), true,
      "../target/i386/tcg/fpu_helper.c:472",
      NULL, 0 },
    { "fpush", { 0 }, { 0 },
      dfu_fpush_env, ARRAY_SIZE(dfu_fpush_env), true,
      "../target/i386/tcg/fpu_helper.c:467",
      NULL, 0 },
    { "fsqrt", { 0 }, { 0 },
      dfu_fsqrt_env, ARRAY_SIZE(dfu_fsqrt_env), true,
      "../target/i386/tcg/fpu_helper.c:2300",
      NULL, 0 },
    { "fstenv", { 0 }, { 0 },
      dfu_fstenv_env, ARRAY_SIZE(dfu_fstenv_env), true,
      "../target/i386/tcg/fpu_helper.c:2510",
      NULL, 0 },
    { "fstl_ST0", { 0 }, { 0 },
      dfu_fstl_ST0_env, ARRAY_SIZE(dfu_fstl_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:353",
      NULL, 0 },
    { "fsts_ST0", { 0 }, { 0 },
      dfu_fsts_ST0_env, ARRAY_SIZE(dfu_fsts_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:340",
      NULL, 0 },
    { "fstt_ST0", { 0 }, { 0 },
      dfu_fstt_ST0_env, ARRAY_SIZE(dfu_fstt_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:459",
      NULL, 0 },
    { "fsubr_STN_ST0", { 0 }, { 0 },
      dfu_fsubr_STN_ST0_env, ARRAY_SIZE(dfu_fsubr_STN_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:638",
      NULL, 0 },
    { "fucomi_ST0_FT0", { 0 }, { 0 },
      dfu_fucomi_ST0_FT0_env, ARRAY_SIZE(dfu_fucomi_ST0_FT0_env), true,
      "../target/i386/tcg/fpu_helper.c:564",
      NULL, 0 },
    { "fwait", { 0 }, { 0 },
      dfu_fwait_env, ARRAY_SIZE(dfu_fwait_env), true,
      "../target/i386/tcg/fpu_helper.c:807",
      NULL, 0 },
    { "fxam_ST0", { 0 }, { 0 },
      dfu_fxam_ST0_env, ARRAY_SIZE(dfu_fxam_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:2410",
      NULL, 0 },
    { "fxchg_ST0_STN", { 0 }, { 0 },
      dfu_fxchg_ST0_STN_env, ARRAY_SIZE(dfu_fxchg_ST0_STN_env), true,
      "../target/i386/tcg/fpu_helper.c:516",
      NULL, 0 },
    { "idivq_EAX", { 0 }, { 0 },
      dfu_idivq_EAX_env, ARRAY_SIZE(dfu_idivq_EAX_env), true,
      "../target/i386/tcg/int_helper.c:385",
      NULL, 0 },
    { "ldmxcsr", { 0 }, { 0 },
      dfu_ldmxcsr_env, ARRAY_SIZE(dfu_ldmxcsr_env), true,
      "../target/i386/tcg/fpu_helper.c:3312",
      NULL, 0 },
    { "movmskpd_xmm", { 0, 1 }, { 0, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1167",
      NULL, 0 },
    { "mulpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_mulpd_xmm_env, ARRAY_SIZE(dfu_mulpd_xmm_env), true,
      "../target/i386/ops_sse.h:531",
      NULL, 0 },
    { "mulps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_mulps_xmm_env, ARRAY_SIZE(dfu_mulps_xmm_env), true,
      "../target/i386/ops_sse.h:531",
      NULL, 0 },
    { "mulsd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_mulsd_env, ARRAY_SIZE(dfu_mulsd_env), true,
      "../target/i386/ops_sse.h:531",
      NULL, 0 },
    { "mulss", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_mulss_env, ARRAY_SIZE(dfu_mulss_env), true,
      "../target/i386/ops_sse.h:531",
      NULL, 0 },
    { "pshufd_xmm", { 2, 1 }, { 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:430",
      NULL, 0 },
    { "pslldq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:193",
      NULL, 0 },
    { "psrldq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:175",
      NULL, 0 },
    { "punpckhdq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1294",
      NULL, 0 },
    { "punpckhqdq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1294",
      NULL, 0 },
    { "punpcklbw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "punpckldq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "punpcklqdq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "punpcklwd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "raise_exception", { 0 }, { 0 },
      dfu_raise_exception_env, ARRAY_SIZE(dfu_raise_exception_env), true,
      "../target/i386/tcg/excp_helper.c:35",
      NULL, 0 },
    { "read_eflags", { 0 }, { 0 },
      dfu_read_eflags_env, ARRAY_SIZE(dfu_read_eflags_env), true,
      "../target/i386/tcg/cc_helper.c:328",
      NULL, 0 },
    { "rechecking_single_step", { 0 }, { 0 },
      dfu_rechecking_single_step_env, ARRAY_SIZE(dfu_rechecking_single_step_env), true,
      "../target/i386/tcg/bpt_helper.c:35",
      NULL, 0 },
    { "shufpd_xmm", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:416",
      NULL, 0 },
    { "shufps_xmm", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:406",
      NULL, 0 },
    { "sqrtsd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_sqrtsd_env, ARRAY_SIZE(dfu_sqrtsd_env), true,
      "../target/i386/ops_sse.h:562",
      NULL, 0 },
    { "subps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_subps_xmm_env, ARRAY_SIZE(dfu_subps_xmm_env), true,
      "../target/i386/ops_sse.h:530",
      NULL, 0 },
    { "subsd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_subsd_env, ARRAY_SIZE(dfu_subsd_env), true,
      "../target/i386/ops_sse.h:530",
      NULL, 0 },
    { "subss", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_subss_env, ARRAY_SIZE(dfu_subss_env), true,
      "../target/i386/ops_sse.h:530",
      NULL, 0 },
#if defined(TARGET_X86_64)
    { "syscall", { 0 }, { 0 },
      dfu_syscall_env, ARRAY_SIZE(dfu_syscall_env), true,
      "../target/i386/tcg/user/seg_helper.c:30",
      NULL, 0 },
#endif
    { "ucomisd", { 0, 1, 1 }, { 0, 64, 64 },
      dfu_ucomisd_env, ARRAY_SIZE(dfu_ucomisd_env), true,
      "../target/i386/ops_sse.h:1130",
      NULL, 0 },
    { "update_mxcsr", { 0 }, { 0 },
      dfu_update_mxcsr_env, ARRAY_SIZE(dfu_update_mxcsr_env), true,
      "../target/i386/tcg/fpu_helper.c:3307",
      NULL, 0 },
    { "xgetbv", { 0 }, { 0 },
      dfu_xgetbv_env, ARRAY_SIZE(dfu_xgetbv_env), true,
      "../target/i386/tcg/fpu_helper.c:3195",
      NULL, 0 },
    { "lookup_tb_ptr", { 0 }, { 0 },
      dfu_lookup_tb_ptr_env, ARRAY_SIZE(dfu_lookup_tb_ptr_env), true,
      "accel/tcg/cpu-exec.c HELPER(lookup_tb_ptr)",
      NULL, 0 },
    { NULL, { 0 }, { 0 }, NULL, 0, false, NULL, NULL, 0 }
};
