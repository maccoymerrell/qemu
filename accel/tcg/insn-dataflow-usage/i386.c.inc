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
 * CP1 -- helpers that perform GUEST MEMORY ACCESSES themselves.
 * No qemu_ld/qemu_st op names these: the access happens inside
 * the call, so without the row below QEMU's access list is SHORT
 * for the instruction that called the helper.  Direction and the
 * ADDRESS ARGUMENT are read off the call site; a count is NOT
 * invented when the helper's access pattern is data-dependent.
 *   iret_protected       read  addr=UNSTATED data=-    count unbounded
 *   iret_protected       write addr=UNSTATED data=-    one access
 *   lar                  read  addr=UNSTATED data=-    count unbounded
 *   lcall_protected      read  addr=UNSTATED data=-    count unbounded
 *   lcall_protected      write addr=UNSTATED data=-    one access
 *   ljmp_protected       read  addr=UNSTATED data=-    count unbounded
 *   ljmp_protected       write addr=UNSTATED data=-    one access
 *   load_seg             read  addr=UNSTATED data=-    count unbounded
 *   load_seg             write addr=UNSTATED data=-    one access
 *   lret_protected       read  addr=UNSTATED data=-    count unbounded
 *   lsl                  read  addr=UNSTATED data=-    count unbounded
 *   maskmov_mmx          write addr=arg3 data=-    one access
 *   maskmov_xmm          write addr=arg3 data=-    one access
 *   verr                 read  addr=UNSTATED data=-    count unbounded
 *   verw                 read  addr=UNSTATED data=-    count unbounded
 *   vpgatherdd_xmm       read  addr=arg6 data=-    one access
 *   vpgatherdd_ymm       read  addr=arg6 data=-    one access
 *   vpgatherdq_xmm       read  addr=arg6 data=-    one access
 *   vpgatherdq_ymm       read  addr=arg6 data=-    one access
 *   vpgatherqd_xmm       read  addr=arg6 data=-    one access
 *   vpgatherqd_ymm       read  addr=arg6 data=-    one access
 *   vpgatherqq_xmm       read  addr=arg6 data=-    one access
 *   vpgatherqq_ymm       read  addr=arg6 data=-    one access
 *   vpmaskmovd_st_xmm    write addr=arg3 data=-    one access
 *   vpmaskmovq_st_xmm    write addr=arg3 data=-    one access
 *
 * READS THE EMULATOR MAKES ON ITS OWN BEHALF -- derived,
 * enumerated, and marked DF_HF_XLAT so the footprint is complete
 * and the OPERAND set is not.  Selected by the SOURCE LINE the
 * reader read the member off, never by helper name, so a sibling
 * reaching the same line is covered the day it is derived:
 *   cr4_testbit              eip      ../target/i386/tcg/excp_helper.c:127
 *   divb_AL                  eip      ../target/i386/tcg/excp_helper.c:127
 *   divl_EAX                 eip      ../target/i386/tcg/excp_helper.c:127
 *   divq_EAX                 eip      ../target/i386/tcg/excp_helper.c:127
 *   divw_AX                  eip      ../target/i386/tcg/excp_helper.c:127
 *   fwait                    eip      ../target/i386/tcg/excp_helper.c:127
 *   fxrstor                  eip      ../target/i386/tcg/excp_helper.c:127
 *   fxsave                   eip      ../target/i386/tcg/excp_helper.c:127
 *   idivb_AL                 eip      ../target/i386/tcg/excp_helper.c:127
 *   idivl_EAX                eip      ../target/i386/tcg/excp_helper.c:127
 *   idivq_EAX                eip      ../target/i386/tcg/excp_helper.c:127
 *   idivw_AX                 eip      ../target/i386/tcg/excp_helper.c:127
 *   iret_protected           eip      ../target/i386/tcg/excp_helper.c:127
 *   lcall_protected          eip      ../target/i386/tcg/excp_helper.c:127
 *   ljmp_protected           eip      ../target/i386/tcg/excp_helper.c:127
 *   load_seg                 eip      ../target/i386/tcg/excp_helper.c:127
 *   lret_protected           eip      ../target/i386/tcg/excp_helper.c:127
 *   pause                    eip      ../target/i386/tcg/excp_helper.c:127
 *   raise_exception          eip      ../target/i386/tcg/excp_helper.c:127
 *   raise_interrupt          eip      ../target/i386/tcg/excp_helper.c:127
 *   rdpkru                   eip      ../target/i386/tcg/excp_helper.c:127
 *   rdpmc                    eip      ../target/i386/tcg/excp_helper.c:127
 *   rechecking_single_step   eip      ../target/i386/tcg/excp_helper.c:127
 *   wrpkru                   eip      ../target/i386/tcg/excp_helper.c:127
 *   xgetbv                   eip      ../target/i386/tcg/excp_helper.c:127
 *   xrstor                   eip      ../target/i386/tcg/excp_helper.c:127
 *   xsave                    eip      ../target/i386/tcg/excp_helper.c:127
 *   eip @ ../target/i386/tcg/excp_helper.c:127:
 *     the exception frame's return address -- `env->exception_next_eip =
 *     env->eip + next_eip_addend` in raise_interrupt2(), the common raise
 *     path every helper that can fault reaches. It records WHERE the
 *     exception happened; the instruction computes nothing from it
 *
 * Rows refused, and therefore still OVER-APPROXIMATED at run time:
 *   memset                   helper_memset is defined in no preprocessed unit
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
static const DfHelperField dfu_addpd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:529 */
};
static const DfHelperField dfu_addps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:529 */
};
static const DfHelperField dfu_addps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:529 */
};
static const DfHelperField dfu_addsd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:529 */
};
static const DfHelperField dfu_addss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:529 */
};
static const DfHelperField dfu_addsubpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:995 */
};
static const DfHelperField dfu_addsubpd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:995 */
};
static const DfHelperField dfu_addsubps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:986 */
};
static const DfHelperField dfu_addsubps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:986 */
};
static const DfHelperField dfu_cmpeqpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1065 */
};
static const DfHelperField dfu_cmpeqpd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1065 */
};
static const DfHelperField dfu_cmpeqps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1065 */
};
static const DfHelperField dfu_cmpeqps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1065 */
};
static const DfHelperField dfu_cmpeqsd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1065 */
};
static const DfHelperField dfu_cmpeqss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1065 */
};
static const DfHelperField dfu_cmpgepd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1079 */
};
static const DfHelperField dfu_cmpgepd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1079 */
};
static const DfHelperField dfu_cmpgeps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1079 */
};
static const DfHelperField dfu_cmpgeps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1079 */
};
static const DfHelperField dfu_cmpgesd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1079 */
};
static const DfHelperField dfu_cmpgess_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1079 */
};
static const DfHelperField dfu_cmplepd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1067 */
};
static const DfHelperField dfu_cmplepd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1067 */
};
static const DfHelperField dfu_cmpleps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1067 */
};
static const DfHelperField dfu_cmpleps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1067 */
};
static const DfHelperField dfu_cmplesd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1067 */
};
static const DfHelperField dfu_cmpless_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1067 */
};
static const DfHelperField dfu_cmpltpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1066 */
};
static const DfHelperField dfu_cmpltps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1066 */
};
static const DfHelperField dfu_cmpltqpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1084 */
};
static const DfHelperField dfu_cmpltqpd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1084 */
};
static const DfHelperField dfu_cmpltqps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1084 */
};
static const DfHelperField dfu_cmpltqps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1084 */
};
static const DfHelperField dfu_cmpltqsd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1084 */
};
static const DfHelperField dfu_cmpltqss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1084 */
};
static const DfHelperField dfu_cmpltsd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1066 */
};
static const DfHelperField dfu_cmpltss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1066 */
};
static const DfHelperField dfu_cmpnltpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1070 */
};
static const DfHelperField dfu_cmpnltps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1070 */
};
static const DfHelperField dfu_cmpnltsd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1070 */
};
static const DfHelperField dfu_cmpnltss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1070 */
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
static const DfHelperField dfu_cr4_testbit_env[] = {
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:441 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
};
static const DfHelperField dfu_cvtdq2pd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:655 */
};
static const DfHelperField dfu_cvtdq2pd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:655 */
};
static const DfHelperField dfu_cvtdq2ps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:646 */
};
static const DfHelperField dfu_cvtdq2ps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:646 */
};
static const DfHelperField dfu_cvtpd2dq_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:743 */
};
static const DfHelperField dfu_cvtpd2dq_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:743 */
};
static const DfHelperField dfu_cvtpd2pi_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:759 */
};
static const DfHelperField dfu_cvtpd2ps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:585 */
};
static const DfHelperField dfu_cvtpd2ps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:585 */
};
static const DfHelperField dfu_cvtph2ps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:598 */
};
static const DfHelperField dfu_cvtpi2pd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:668 */
};
static const DfHelperField dfu_cvtpi2ps_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:662 */
};
static const DfHelperField dfu_cvtps2dq_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:735 */
};
static const DfHelperField dfu_cvtps2dq_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:735 */
};
static const DfHelperField dfu_cvtps2pd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:577 */
};
static const DfHelperField dfu_cvtps2pd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:577 */
};
static const DfHelperField dfu_cvtps2ph_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:607 */
    { offsetof(CPUArchState, sse_status.float_rounding_mode), sizeof(((CPUArchState *)0)->sse_status.float_rounding_mode), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:605 */
};
static const DfHelperField dfu_cvtps2pi_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:753 */
};
static const DfHelperField dfu_cvtsd2si_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:770 */
};
static const DfHelperField dfu_cvtsd2ss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:634 */
};
static const DfHelperField dfu_cvtsi2sd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:679 */
};
static const DfHelperField dfu_cvtsi2ss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:674 */
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
static const DfHelperField dfu_cvtss2si_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:765 */
};
static const DfHelperField dfu_cvttpd2dq_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:801 */
};
static const DfHelperField dfu_cvttpd2dq_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:801 */
};
static const DfHelperField dfu_cvttpd2pi_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:817 */
};
static const DfHelperField dfu_cvttps2dq_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:792 */
};
static const DfHelperField dfu_cvttps2dq_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:792 */
};
static const DfHelperField dfu_cvttps2pi_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:811 */
};
static const DfHelperField dfu_cvttsd2si_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:828 */
};
static const DfHelperField dfu_cvttsd2sq_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:839 */
};
static const DfHelperField dfu_cvttss2si_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:823 */
};
static const DfHelperField dfu_cvttss2sq_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:834 */
};
static const DfHelperField dfu_divb_AL_env[] = {
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, regs[0]), sizeof(((CPUArchState *)0)->regs[0]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:39 */
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
static const DfHelperField dfu_divpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:532 */
};
static const DfHelperField dfu_divpd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:532 */
};
static const DfHelperField dfu_divps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:532 */
};
static const DfHelperField dfu_divps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:532 */
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
static const DfHelperField dfu_divsd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:532 */
};
static const DfHelperField dfu_divss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:532 */
};
static const DfHelperField dfu_divw_AX_env[] = {
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, regs[0]), sizeof(((CPUArchState *)0)->regs[0]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:75 */
    { offsetof(CPUArchState, regs[2]), sizeof(((CPUArchState *)0)->regs[2]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:75 */
};
static const DfHelperField dfu_dppd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1870 */
};
static const DfHelperField dfu_dpps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1832 */
};
static const DfHelperField dfu_emms_env[] = {
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3327 */
};
static const DfHelperField dfu_enter_mmx_env[] = {
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3319 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3320 */
};
static const DfHelperField dfu_f2xm1_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fp_status.float_rounding_mode), sizeof(((CPUArchState *)0)->fp_status.float_rounding_mode), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:1187 */
    { offsetof(CPUArchState, fp_status.floatx80_rounding_precision), sizeof(((CPUArchState *)0)->fp_status.floatx80_rounding_precision), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:1189 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:1141, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:1141 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
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
static const DfHelperField dfu_fbld_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:855 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:860, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:79 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:80, INDEX NOT STATED */
};
static const DfHelperField dfu_fbst_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:873, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:873 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fchs_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:664, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:664 */
};
static const DfHelperField dfu_fclex_env[] = {
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:804 */
};
static const DfHelperField dfu_fcom_ST0_FT0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:534, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:534 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:535 */
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:534 */
};
static const DfHelperField dfu_fcomi_ST0_FT0_env[] = {
    { offsetof(CPUArchState, cc_dst), sizeof(((CPUArchState *)0)->cc_dst), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src2), sizeof(((CPUArchState *)0)->cc_src2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:557, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:557 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:557 */
};
static const DfHelperField dfu_fcos_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:116 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2399, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2399 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2402 */
};
static const DfHelperField dfu_fdecstp_env[] = {
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:479 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:480 */
};
static const DfHelperField dfu_fdiv_ST0_FT0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:607, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:607 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:607 */
};
static const DfHelperField dfu_fdiv_STN_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:649, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:649 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fdivr_ST0_FT0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:612, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:612 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:612 */
};
static const DfHelperField dfu_fdivr_STN_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:657, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:657 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_ffree_STN_env[] = {
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:493 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:493, INDEX NOT STATED */
};
static const DfHelperField dfu_fildl_FT0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:270 */
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:270 */
};
static const DfHelperField dfu_fildl_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:317 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:320, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:319 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:322, INDEX NOT STATED */
};
static const DfHelperField dfu_fildll_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:330 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:333, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:332 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:335, INDEX NOT STATED */
};
static const DfHelperField dfu_fincstp_env[] = {
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:485 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:486 */
};
static const DfHelperField dfu_fist_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:371, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:371 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fistl_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:385, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:385 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fistll_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:398, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:398 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fistt_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:411, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:411 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fisttl_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:425, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:425 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fisttll_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:438, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:438 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fld1_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:674, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:674 */
};
static const DfHelperField dfu_fldcw_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:780 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2731 */
};
static const DfHelperField dfu_fldenv_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:780 */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2520 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2545, INDEX NOT STATED */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2731 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2521 */
};
static const DfHelperField dfu_fldl2e_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:694, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:694 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:691 */
};
static const DfHelperField dfu_fldl2t_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:681, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:681 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:679 */
};
static const DfHelperField dfu_fldl_FT0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:264 */
};
static const DfHelperField dfu_fldl_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:301, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:299 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:303, INDEX NOT STATED */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fldlg2_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:720, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:720 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:717 */
};
static const DfHelperField dfu_fldln2_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:733, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:733 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:730 */
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
static const DfHelperField dfu_fldz_FT0_env[] = {
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:748 */
};
static const DfHelperField dfu_fldz_ST0_env[] = {
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:743, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:743 */
};
static const DfHelperField dfu_fma4pd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2536 */
};
static const DfHelperField dfu_fma4pd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2536 */
};
static const DfHelperField dfu_fma4ps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2535 */
};
static const DfHelperField dfu_fma4ps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2535 */
};
static const DfHelperField dfu_fma4sd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2531 */
};
static const DfHelperField dfu_fma4ss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2530 */
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
static const DfHelperField dfu_fmul_STN_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:627, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:627 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fninit_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:780 */
    { offsetof(CPUArchState, fpcs), sizeof(((CPUArchState *)0)->fpcs), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:818 */
    { offsetof(CPUArchState, fpdp), sizeof(((CPUArchState *)0)->fpdp), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:821 */
    { offsetof(CPUArchState, fpds), sizeof(((CPUArchState *)0)->fpds), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:819 */
    { offsetof(CPUArchState, fpip), sizeof(((CPUArchState *)0)->fpip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:820 */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:817 */
    { offsetof(CPUArchState, fptags[0]), sizeof(((CPUArchState *)0)->fptags[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:823 */
    { offsetof(CPUArchState, fptags[1]), sizeof(((CPUArchState *)0)->fptags[1]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:824 */
    { offsetof(CPUArchState, fptags[2]), sizeof(((CPUArchState *)0)->fptags[2]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:825 */
    { offsetof(CPUArchState, fptags[3]), sizeof(((CPUArchState *)0)->fptags[3]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:826 */
    { offsetof(CPUArchState, fptags[4]), sizeof(((CPUArchState *)0)->fptags[4]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:827 */
    { offsetof(CPUArchState, fptags[5]), sizeof(((CPUArchState *)0)->fptags[5]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:828 */
    { offsetof(CPUArchState, fptags[6]), sizeof(((CPUArchState *)0)->fptags[6]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:829 */
    { offsetof(CPUArchState, fptags[7]), sizeof(((CPUArchState *)0)->fptags[7]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:830 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2731 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:816 */
};
static const DfHelperField dfu_fnstcw_env[] = {
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:758 */
};
static const DfHelperField dfu_fnstsw_env[] = {
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:753 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:753 */
};
static const DfHelperField dfu_fpatan_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fp_status.float_rounding_mode), sizeof(((CPUArchState *)0)->fp_status.float_rounding_mode), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:1487 */
    { offsetof(CPUArchState, fp_status.floatx80_rounding_precision), sizeof(((CPUArchState *)0)->fp_status.floatx80_rounding_precision), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:1410 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:1374, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:1374 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:85, INDEX NOT STATED */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fpop_env[] = {
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:85 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:85, INDEX NOT STATED */
};
static const DfHelperField dfu_fprem_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:1866, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:1866 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:1871 */
};
static const DfHelperField dfu_fprem1_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:1866, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:1866 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:1871 */
};
static const DfHelperField dfu_fptan_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:116 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:1301, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:1301 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:80, INDEX NOT STATED */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:1304 */
};
static const DfHelperField dfu_fpush_env[] = {
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:79 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:80, INDEX NOT STATED */
};
static const DfHelperField dfu_frndint_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2329, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2329 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_frstor_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:780 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2592, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2520 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2545, INDEX NOT STATED */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2731 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2521 */
};
static const DfHelperField dfu_fsave_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:780 */
    { offsetof(CPUArchState, fpcs), sizeof(((CPUArchState *)0)->fpcs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2478 */
    { offsetof(CPUArchState, fpdp), sizeof(((CPUArchState *)0)->fpdp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2479 */
    { offsetof(CPUArchState, fpds), sizeof(((CPUArchState *)0)->fpds), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2480 */
    { offsetof(CPUArchState, fpip), sizeof(((CPUArchState *)0)->fpip), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2477 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2459, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2452 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2456, INDEX NOT STATED */
    { offsetof(CPUArchState, fptags[0]), sizeof(((CPUArchState *)0)->fptags[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:823 */
    { offsetof(CPUArchState, fptags[1]), sizeof(((CPUArchState *)0)->fptags[1]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:824 */
    { offsetof(CPUArchState, fptags[2]), sizeof(((CPUArchState *)0)->fptags[2]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:825 */
    { offsetof(CPUArchState, fptags[3]), sizeof(((CPUArchState *)0)->fptags[3]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:826 */
    { offsetof(CPUArchState, fptags[4]), sizeof(((CPUArchState *)0)->fptags[4]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:827 */
    { offsetof(CPUArchState, fptags[5]), sizeof(((CPUArchState *)0)->fptags[5]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:828 */
    { offsetof(CPUArchState, fptags[6]), sizeof(((CPUArchState *)0)->fptags[6]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:829 */
    { offsetof(CPUArchState, fptags[7]), sizeof(((CPUArchState *)0)->fptags[7]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:830 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2474 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2452 */
};
static const DfHelperField dfu_fscale_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fp_status.floatx80_rounding_precision), sizeof(((CPUArchState *)0)->fp_status.floatx80_rounding_precision), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2372 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2336, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2336 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fsin_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:116 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2386, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2386 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2389 */
};
static const DfHelperField dfu_fsincos_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:116 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2313, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2313 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:80, INDEX NOT STATED */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2316 */
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
static const DfHelperField dfu_fsub_ST0_FT0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:594, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:594 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:594 */
};
static const DfHelperField dfu_fsub_STN_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:634, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:634 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fsubr_ST0_FT0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:601, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:601 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:601 */
};
static const DfHelperField dfu_fsubr_STN_ST0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:641, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:641 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fucom_ST0_FT0_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:544, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:544 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:545 */
    { offsetof(CPUArchState, ft0), sizeof(((CPUArchState *)0)->ft0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:544 */
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
static const DfHelperField dfu_fxrstor_env[] = {
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2966 */
    { offsetof(CPUArchState, efer), sizeof(((CPUArchState *)0)->efer), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2969 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:780 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2853, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2520 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2846, INDEX NOT STATED */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2731 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2521 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2970 */
    { offsetof(CPUArchState, mxcsr), sizeof(((CPUArchState *)0)->mxcsr), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2723 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3271 */
    { offsetof(CPUArchState, xmm_regs), sizeof(((CPUArchState *)0)->xmm_regs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2878, INDEX NOT STATED */
};
static const DfHelperField dfu_fxsave_env[] = {
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2717 */
    { offsetof(CPUArchState, efer), sizeof(((CPUArchState *)0)->efer), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2720 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2633, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2614 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2617, INDEX NOT STATED */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2620 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2614 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2721 */
    { offsetof(CPUArchState, mxcsr), sizeof(((CPUArchState *)0)->mxcsr), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3298 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3290 */
    { offsetof(CPUArchState, xmm_regs), sizeof(((CPUArchState *)0)->xmm_regs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2662, INDEX NOT STATED */
};
static const DfHelperField dfu_fxtract_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:1815, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:1815 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:80, INDEX NOT STATED */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fyl2x_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fp_status.float_rounding_mode), sizeof(((CPUArchState *)0)->fp_status.float_rounding_mode), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2228 */
    { offsetof(CPUArchState, fp_status.floatx80_rounding_precision), sizeof(((CPUArchState *)0)->fp_status.floatx80_rounding_precision), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2230 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2156, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2156 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:85, INDEX NOT STATED */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_fyl2xp1_env[] = {
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:204 */
    { offsetof(CPUArchState, fp_status.float_rounding_mode), sizeof(((CPUArchState *)0)->fp_status.float_rounding_mode), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2125 */
    { offsetof(CPUArchState, fp_status.floatx80_rounding_precision), sizeof(((CPUArchState *)0)->fp_status.floatx80_rounding_precision), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2127 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2058, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2058 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:85, INDEX NOT STATED */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:134 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:133 */
};
static const DfHelperField dfu_haddpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:979 */
};
static const DfHelperField dfu_haddpd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:979 */
};
static const DfHelperField dfu_haddps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:958 */
};
static const DfHelperField dfu_haddps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:958 */
};
static const DfHelperField dfu_hsubpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:980 */
};
static const DfHelperField dfu_hsubpd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:980 */
};
static const DfHelperField dfu_hsubps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:959 */
};
static const DfHelperField dfu_hsubps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:959 */
};
static const DfHelperField dfu_icebp_env[] = {
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/helper-tcg.h:131 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:177 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:175 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:176 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:177 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/helper-tcg.h:130 */
};
static const DfHelperField dfu_idivb_AL_env[] = {
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, regs[0]), sizeof(((CPUArchState *)0)->regs[0]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:57 */
};
static const DfHelperField dfu_idivl_EAX_env[] = {
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, regs[0]), sizeof(((CPUArchState *)0)->regs[0]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:133 */
    { offsetof(CPUArchState, regs[2]), sizeof(((CPUArchState *)0)->regs[2]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:133 */
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
static const DfHelperField dfu_idivw_AX_env[] = {
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, regs[0]), sizeof(((CPUArchState *)0)->regs[0]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:94 */
    { offsetof(CPUArchState, regs[2]), sizeof(((CPUArchState *)0)->regs[2]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:94 */
};
static const DfHelperField dfu_iret_protected_env[] = {
    { offsetof(CPUArchState, bndcs_regs.cfgu), sizeof(((CPUArchState *)0)->bndcs_regs.cfgu), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:55 */
    { offsetof(CPUArchState, cc_dst), sizeof(((CPUArchState *)0)->cc_dst), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src2), sizeof(((CPUArchState *)0)->cc_src2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cr[0]), sizeof(((CPUArchState *)0)->cr[0]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:497 */
    { offsetof(CPUArchState, cr[3]), sizeof(((CPUArchState *)0)->cr[3]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:179 */
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:60 */
    { offsetof(CPUArchState, df), sizeof(((CPUArchState *)0)->df), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2659 */
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:2278 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD | INSN_DF_WR, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, gdt), sizeof(((CPUArchState *)0)->gdt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:144 */
    { offsetof(CPUArchState, gdt.base), sizeof(((CPUArchState *)0)->gdt.base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:297 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:2280 */
    { offsetof(CPUArchState, hflags2), sizeof(((CPUArchState *)0)->hflags2), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:51 */
    { offsetof(CPUArchState, ldt), sizeof(((CPUArchState *)0)->ldt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:142 */
    { offsetof(CPUArchState, ldt.base), sizeof(((CPUArchState *)0)->ldt.base), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:536 */
    { offsetof(CPUArchState, ldt.flags), sizeof(((CPUArchState *)0)->ldt.flags), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:538 */
    { offsetof(CPUArchState, ldt.limit), sizeof(((CPUArchState *)0)->ldt.limit), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:537 */
    { offsetof(CPUArchState, ldt.selector), sizeof(((CPUArchState *)0)->ldt.selector), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:535 */
    { offsetof(CPUArchState, msr_bndcfgs), sizeof(((CPUArchState *)0)->msr_bndcfgs), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:57 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, regs), sizeof(((CPUArchState *)0)->regs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/seg_helper.c:516, INDEX NOT STATED */
    { offsetof(CPUArchState, regs[0]), sizeof(((CPUArchState *)0)->regs[0]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:400 */
    { offsetof(CPUArchState, regs[1]), sizeof(((CPUArchState *)0)->regs[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:401 */
    { offsetof(CPUArchState, regs[2]), sizeof(((CPUArchState *)0)->regs[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:402 */
    { offsetof(CPUArchState, regs[3]), sizeof(((CPUArchState *)0)->regs[3]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:403 */
    { offsetof(CPUArchState, regs[4]), sizeof(((CPUArchState *)0)->regs[4]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:404 */
    { offsetof(CPUArchState, regs[5]), sizeof(((CPUArchState *)0)->regs[5]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:405 */
    { offsetof(CPUArchState, regs[6]), sizeof(((CPUArchState *)0)->regs[6]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:406 */
    { offsetof(CPUArchState, regs[7]), sizeof(((CPUArchState *)0)->regs[7]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:407 */
    { offsetof(CPUArchState, segs), sizeof(((CPUArchState *)0)->segs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/seg_helper.c:410, INDEX NOT STATED */
    { offsetof(CPUArchState, segs[0].base), sizeof(((CPUArchState *)0)->segs[0].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2459 */
    { offsetof(CPUArchState, segs[1].flags), sizeof(((CPUArchState *)0)->segs[1].flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2429 */
    { offsetof(CPUArchState, segs[1].limit), sizeof(((CPUArchState *)0)->segs[1].limit), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:575 */
    { offsetof(CPUArchState, segs[2].base), sizeof(((CPUArchState *)0)->segs[2].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2460 */
    { offsetof(CPUArchState, segs[2].flags), sizeof(((CPUArchState *)0)->segs[2].flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2444 */
    { offsetof(CPUArchState, segs[3].base), sizeof(((CPUArchState *)0)->segs[3].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2458 */
    { offsetof(CPUArchState, tr.base), sizeof(((CPUArchState *)0)->tr.base), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:2284 */
    { offsetof(CPUArchState, tr.flags), sizeof(((CPUArchState *)0)->tr.flags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:368 */
    { offsetof(CPUArchState, tr.limit), sizeof(((CPUArchState *)0)->tr.limit), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:501 */
    { offsetof(CPUArchState, tr.selector), sizeof(((CPUArchState *)0)->tr.selector), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:467 */
    { offsetof(CPUArchState, xcr0), sizeof(((CPUArchState *)0)->xcr0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:61 */
};
static const DfHelperField dfu_lar_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:2448 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:2483 */
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:8713 */
    { offsetof(CPUArchState, gdt), sizeof(((CPUArchState *)0)->gdt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:144 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:8710 */
    { offsetof(CPUArchState, ldt), sizeof(((CPUArchState *)0)->ldt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:142 */
};
static const DfHelperField dfu_lcall_protected_env[] = {
    { offsetof(CPUArchState, bndcs_regs.cfgu), sizeof(((CPUArchState *)0)->bndcs_regs.cfgu), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:55 */
    { offsetof(CPUArchState, cc_dst), sizeof(((CPUArchState *)0)->cc_dst), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src2), sizeof(((CPUArchState *)0)->cc_src2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cr[0]), sizeof(((CPUArchState *)0)->cr[0]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2448 */
    { offsetof(CPUArchState, cr[3]), sizeof(((CPUArchState *)0)->cr[3]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:179 */
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:60 */
    { offsetof(CPUArchState, df), sizeof(((CPUArchState *)0)->df), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2659 */
    { offsetof(CPUArchState, efer), sizeof(((CPUArchState *)0)->efer), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:1758 */
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:8713 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD | INSN_DF_WR, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, gdt), sizeof(((CPUArchState *)0)->gdt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:144 */
    { offsetof(CPUArchState, gdt.base), sizeof(((CPUArchState *)0)->gdt.base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:297 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:8710 */
    { offsetof(CPUArchState, hflags2), sizeof(((CPUArchState *)0)->hflags2), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:51 */
    { offsetof(CPUArchState, ldt), sizeof(((CPUArchState *)0)->ldt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:142 */
    { offsetof(CPUArchState, ldt.base), sizeof(((CPUArchState *)0)->ldt.base), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:536 */
    { offsetof(CPUArchState, ldt.flags), sizeof(((CPUArchState *)0)->ldt.flags), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:538 */
    { offsetof(CPUArchState, ldt.limit), sizeof(((CPUArchState *)0)->ldt.limit), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:537 */
    { offsetof(CPUArchState, ldt.selector), sizeof(((CPUArchState *)0)->ldt.selector), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:535 */
    { offsetof(CPUArchState, msr_bndcfgs), sizeof(((CPUArchState *)0)->msr_bndcfgs), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:57 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, regs), sizeof(((CPUArchState *)0)->regs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/seg_helper.c:516, INDEX NOT STATED */
    { offsetof(CPUArchState, regs[0]), sizeof(((CPUArchState *)0)->regs[0]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:400 */
    { offsetof(CPUArchState, regs[1]), sizeof(((CPUArchState *)0)->regs[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:401 */
    { offsetof(CPUArchState, regs[2]), sizeof(((CPUArchState *)0)->regs[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:402 */
    { offsetof(CPUArchState, regs[3]), sizeof(((CPUArchState *)0)->regs[3]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:403 */
    { offsetof(CPUArchState, regs[4]), sizeof(((CPUArchState *)0)->regs[4]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:1716 */
    { offsetof(CPUArchState, regs[5]), sizeof(((CPUArchState *)0)->regs[5]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:405 */
    { offsetof(CPUArchState, regs[6]), sizeof(((CPUArchState *)0)->regs[6]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:406 */
    { offsetof(CPUArchState, regs[7]), sizeof(((CPUArchState *)0)->regs[7]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:407 */
    { offsetof(CPUArchState, segs), sizeof(((CPUArchState *)0)->segs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/cpu.h:2411, INDEX NOT STATED */
    { offsetof(CPUArchState, segs[0].base), sizeof(((CPUArchState *)0)->segs[0].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2459 */
    { offsetof(CPUArchState, segs[1].flags), sizeof(((CPUArchState *)0)->segs[1].flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2429 */
    { offsetof(CPUArchState, segs[1].limit), sizeof(((CPUArchState *)0)->segs[1].limit), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:575 */
    { offsetof(CPUArchState, segs[1].selector), sizeof(((CPUArchState *)0)->segs[1].selector), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:1719 */
    { offsetof(CPUArchState, segs[2].base), sizeof(((CPUArchState *)0)->segs[2].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2460 */
    { offsetof(CPUArchState, segs[2].flags), sizeof(((CPUArchState *)0)->segs[2].flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2444 */
    { offsetof(CPUArchState, segs[2].selector), sizeof(((CPUArchState *)0)->segs[2].selector), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:1891 */
    { offsetof(CPUArchState, segs[3].base), sizeof(((CPUArchState *)0)->segs[3].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2458 */
    { offsetof(CPUArchState, tr.base), sizeof(((CPUArchState *)0)->tr.base), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:382 */
    { offsetof(CPUArchState, tr.flags), sizeof(((CPUArchState *)0)->tr.flags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:368 */
    { offsetof(CPUArchState, tr.limit), sizeof(((CPUArchState *)0)->tr.limit), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:501 */
    { offsetof(CPUArchState, tr.selector), sizeof(((CPUArchState *)0)->tr.selector), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:467 */
    { offsetof(CPUArchState, xcr0), sizeof(((CPUArchState *)0)->xcr0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:61 */
};
static const DfHelperField dfu_ldmxcsr_env[] = {
    { offsetof(CPUArchState, mxcsr), sizeof(((CPUArchState *)0)->mxcsr), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2723 */
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3271 */
};
static const DfHelperField dfu_ljmp_protected_env[] = {
    { offsetof(CPUArchState, bndcs_regs.cfgu), sizeof(((CPUArchState *)0)->bndcs_regs.cfgu), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:55 */
    { offsetof(CPUArchState, cc_dst), sizeof(((CPUArchState *)0)->cc_dst), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src2), sizeof(((CPUArchState *)0)->cc_src2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cr[0]), sizeof(((CPUArchState *)0)->cr[0]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2448 */
    { offsetof(CPUArchState, cr[3]), sizeof(((CPUArchState *)0)->cr[3]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:179 */
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:60 */
    { offsetof(CPUArchState, df), sizeof(((CPUArchState *)0)->df), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2659 */
    { offsetof(CPUArchState, efer), sizeof(((CPUArchState *)0)->efer), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:1547 */
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:8713 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD | INSN_DF_WR, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, gdt), sizeof(((CPUArchState *)0)->gdt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:144 */
    { offsetof(CPUArchState, gdt.base), sizeof(((CPUArchState *)0)->gdt.base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:297 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:8710 */
    { offsetof(CPUArchState, hflags2), sizeof(((CPUArchState *)0)->hflags2), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:51 */
    { offsetof(CPUArchState, ldt), sizeof(((CPUArchState *)0)->ldt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:142 */
    { offsetof(CPUArchState, ldt.base), sizeof(((CPUArchState *)0)->ldt.base), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:536 */
    { offsetof(CPUArchState, ldt.flags), sizeof(((CPUArchState *)0)->ldt.flags), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:538 */
    { offsetof(CPUArchState, ldt.limit), sizeof(((CPUArchState *)0)->ldt.limit), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:537 */
    { offsetof(CPUArchState, ldt.selector), sizeof(((CPUArchState *)0)->ldt.selector), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:535 */
    { offsetof(CPUArchState, msr_bndcfgs), sizeof(((CPUArchState *)0)->msr_bndcfgs), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:57 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, regs), sizeof(((CPUArchState *)0)->regs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/seg_helper.c:516, INDEX NOT STATED */
    { offsetof(CPUArchState, regs[0]), sizeof(((CPUArchState *)0)->regs[0]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:400 */
    { offsetof(CPUArchState, regs[1]), sizeof(((CPUArchState *)0)->regs[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:401 */
    { offsetof(CPUArchState, regs[2]), sizeof(((CPUArchState *)0)->regs[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:402 */
    { offsetof(CPUArchState, regs[3]), sizeof(((CPUArchState *)0)->regs[3]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:403 */
    { offsetof(CPUArchState, regs[4]), sizeof(((CPUArchState *)0)->regs[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:404 */
    { offsetof(CPUArchState, regs[5]), sizeof(((CPUArchState *)0)->regs[5]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:405 */
    { offsetof(CPUArchState, regs[6]), sizeof(((CPUArchState *)0)->regs[6]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:406 */
    { offsetof(CPUArchState, regs[7]), sizeof(((CPUArchState *)0)->regs[7]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:407 */
    { offsetof(CPUArchState, segs), sizeof(((CPUArchState *)0)->segs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/cpu.h:2411, INDEX NOT STATED */
    { offsetof(CPUArchState, segs[0].base), sizeof(((CPUArchState *)0)->segs[0].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2459 */
    { offsetof(CPUArchState, segs[1].flags), sizeof(((CPUArchState *)0)->segs[1].flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2429 */
    { offsetof(CPUArchState, segs[1].limit), sizeof(((CPUArchState *)0)->segs[1].limit), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:575 */
    { offsetof(CPUArchState, segs[2].base), sizeof(((CPUArchState *)0)->segs[2].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2460 */
    { offsetof(CPUArchState, segs[2].flags), sizeof(((CPUArchState *)0)->segs[2].flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2444 */
    { offsetof(CPUArchState, segs[3].base), sizeof(((CPUArchState *)0)->segs[3].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2458 */
    { offsetof(CPUArchState, tr.base), sizeof(((CPUArchState *)0)->tr.base), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:382 */
    { offsetof(CPUArchState, tr.flags), sizeof(((CPUArchState *)0)->tr.flags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:368 */
    { offsetof(CPUArchState, tr.limit), sizeof(((CPUArchState *)0)->tr.limit), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:501 */
    { offsetof(CPUArchState, tr.selector), sizeof(((CPUArchState *)0)->tr.selector), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:467 */
    { offsetof(CPUArchState, xcr0), sizeof(((CPUArchState *)0)->xcr0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:61 */
};
static const DfHelperField dfu_load_seg_env[] = {
    { offsetof(CPUArchState, bndcs_regs.cfgu), sizeof(((CPUArchState *)0)->bndcs_regs.cfgu), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:55 */
    { offsetof(CPUArchState, cr[0]), sizeof(((CPUArchState *)0)->cr[0]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2448 */
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:60 */
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2449 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, gdt), sizeof(((CPUArchState *)0)->gdt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:1432 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:1416 */
    { offsetof(CPUArchState, hflags2), sizeof(((CPUArchState *)0)->hflags2), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:51 */
    { offsetof(CPUArchState, ldt), sizeof(((CPUArchState *)0)->ldt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:1430 */
    { offsetof(CPUArchState, msr_bndcfgs), sizeof(((CPUArchState *)0)->msr_bndcfgs), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:57 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, segs), sizeof(((CPUArchState *)0)->segs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/cpu.h:2411, INDEX NOT STATED */
    { offsetof(CPUArchState, segs[0].base), sizeof(((CPUArchState *)0)->segs[0].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2459 */
    { offsetof(CPUArchState, segs[1].flags), sizeof(((CPUArchState *)0)->segs[1].flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2429 */
    { offsetof(CPUArchState, segs[2].base), sizeof(((CPUArchState *)0)->segs[2].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2460 */
    { offsetof(CPUArchState, segs[2].flags), sizeof(((CPUArchState *)0)->segs[2].flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2444 */
    { offsetof(CPUArchState, segs[3].base), sizeof(((CPUArchState *)0)->segs[3].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2458 */
    { offsetof(CPUArchState, xcr0), sizeof(((CPUArchState *)0)->xcr0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:61 */
};
static const DfHelperField dfu_lret_protected_env[] = {
    { offsetof(CPUArchState, bndcs_regs.cfgu), sizeof(((CPUArchState *)0)->bndcs_regs.cfgu), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:55 */
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:35 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:34 */
    { offsetof(CPUArchState, cr[0]), sizeof(((CPUArchState *)0)->cr[0]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2448 */
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:60 */
    { offsetof(CPUArchState, df), sizeof(((CPUArchState *)0)->df), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:36 */
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:8697 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD | INSN_DF_WR, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, gdt), sizeof(((CPUArchState *)0)->gdt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:144 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:2048 */
    { offsetof(CPUArchState, hflags2), sizeof(((CPUArchState *)0)->hflags2), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:51 */
    { offsetof(CPUArchState, ldt), sizeof(((CPUArchState *)0)->ldt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:142 */
    { offsetof(CPUArchState, msr_bndcfgs), sizeof(((CPUArchState *)0)->msr_bndcfgs), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:57 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, regs[4]), sizeof(((CPUArchState *)0)->regs[4]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:2062 */
    { offsetof(CPUArchState, segs), sizeof(((CPUArchState *)0)->segs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/cpu.h:2411, INDEX NOT STATED */
    { offsetof(CPUArchState, segs[0].base), sizeof(((CPUArchState *)0)->segs[0].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2459 */
    { offsetof(CPUArchState, segs[1].flags), sizeof(((CPUArchState *)0)->segs[1].flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2429 */
    { offsetof(CPUArchState, segs[2].base), sizeof(((CPUArchState *)0)->segs[2].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:2063 */
    { offsetof(CPUArchState, segs[2].flags), sizeof(((CPUArchState *)0)->segs[2].flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:2060 */
    { offsetof(CPUArchState, segs[3].base), sizeof(((CPUArchState *)0)->segs[3].base), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2458 */
    { offsetof(CPUArchState, xcr0), sizeof(((CPUArchState *)0)->xcr0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:61 */
};
static const DfHelperField dfu_lsl_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:2401 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:2433 */
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:8713 */
    { offsetof(CPUArchState, gdt), sizeof(((CPUArchState *)0)->gdt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:144 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:8710 */
    { offsetof(CPUArchState, ldt), sizeof(((CPUArchState *)0)->ldt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:142 */
};
static const DfHelperField dfu_maxpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:534 */
};
static const DfHelperField dfu_maxpd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:534 */
};
static const DfHelperField dfu_maxps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:534 */
};
static const DfHelperField dfu_maxps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:534 */
};
static const DfHelperField dfu_maxsd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:534 */
};
static const DfHelperField dfu_maxss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:534 */
};
static const DfHelperField dfu_minpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:533 */
};
static const DfHelperField dfu_minpd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:533 */
};
static const DfHelperField dfu_minps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:533 */
};
static const DfHelperField dfu_minps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:533 */
};
static const DfHelperField dfu_minsd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:533 */
};
static const DfHelperField dfu_minss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:533 */
};
static const DfHelperField dfu_mulpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:531 */
};
static const DfHelperField dfu_mulpd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:531 */
};
static const DfHelperField dfu_mulps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:531 */
};
static const DfHelperField dfu_mulps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:531 */
};
static const DfHelperField dfu_mulsd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:531 */
};
static const DfHelperField dfu_mulss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:531 */
};
static const DfHelperField dfu_pause_env[] = {
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/helper-tcg.h:131 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/helper-tcg.h:130 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
};
static const DfHelperField dfu_pcmpestri_xmm_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1975 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1974 */
    { offsetof(CPUArchState, regs), sizeof(((CPUArchState *)0)->regs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/ops_sse.h:1916, INDEX NOT STATED */
    { offsetof(CPUArchState, regs[1]), sizeof(((CPUArchState *)0)->regs[1]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2049 */
};
static const DfHelperField dfu_pcmpestrm_xmm_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1975 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1974 */
    { offsetof(CPUArchState, regs), sizeof(((CPUArchState *)0)->regs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/ops_sse.h:1916, INDEX NOT STATED */
    { offsetof(CPUArchState, xmm_regs), sizeof(((CPUArchState *)0)->xmm_regs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/ops_sse.h:2066, INDEX NOT STATED */
    { offsetof(CPUArchState, xmm_regs[0]._q_ZMMReg[0]), sizeof(((CPUArchState *)0)->xmm_regs[0]._q_ZMMReg[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2075 */
    { offsetof(CPUArchState, xmm_regs[0]._q_ZMMReg[1]), sizeof(((CPUArchState *)0)->xmm_regs[0]._q_ZMMReg[1]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2074 */
};
static const DfHelperField dfu_pcmpistri_xmm_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1975 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1974 */
    { offsetof(CPUArchState, regs[1]), sizeof(((CPUArchState *)0)->regs[1]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2087 */
};
static const DfHelperField dfu_pcmpistrm_xmm_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1975 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1974 */
    { offsetof(CPUArchState, xmm_regs), sizeof(((CPUArchState *)0)->xmm_regs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/ops_sse.h:2104, INDEX NOT STATED */
    { offsetof(CPUArchState, xmm_regs[0]._q_ZMMReg[0]), sizeof(((CPUArchState *)0)->xmm_regs[0]._q_ZMMReg[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2113 */
    { offsetof(CPUArchState, xmm_regs[0]._q_ZMMReg[1]), sizeof(((CPUArchState *)0)->xmm_regs[0]._q_ZMMReg[1]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2112 */
};
static const DfHelperField dfu_ptest_xmm_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1618 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1617 */
};
static const DfHelperField dfu_raise_exception_env[] = {
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
};
static const DfHelperField dfu_raise_interrupt_env[] = {
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
};
static const DfHelperField dfu_rcpps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:873 */
};
static const DfHelperField dfu_rcpps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:873 */
};
static const DfHelperField dfu_rcpss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:884 */
};
static const DfHelperField dfu_rdpkru_env[] = {
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:107 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, pkru), sizeof(((CPUArchState *)0)->pkru), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:114 */
};
static const DfHelperField dfu_rdpmc_env[] = {
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:81 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:82 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
};
static const DfHelperField dfu_rdrand_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:461 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/int_helper.c:460 */
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
static const DfHelperField dfu_roundpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1742 */
    { offsetof(CPUArchState, sse_status.float_rounding_mode), sizeof(((CPUArchState *)0)->sse_status.float_rounding_mode), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1746 */
};
static const DfHelperField dfu_roundpd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1742 */
    { offsetof(CPUArchState, sse_status.float_rounding_mode), sizeof(((CPUArchState *)0)->sse_status.float_rounding_mode), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1746 */
};
static const DfHelperField dfu_roundps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1718 */
    { offsetof(CPUArchState, sse_status.float_rounding_mode), sizeof(((CPUArchState *)0)->sse_status.float_rounding_mode), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1722 */
};
static const DfHelperField dfu_roundps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1718 */
    { offsetof(CPUArchState, sse_status.float_rounding_mode), sizeof(((CPUArchState *)0)->sse_status.float_rounding_mode), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1722 */
};
static const DfHelperField dfu_roundsd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1792 */
    { offsetof(CPUArchState, sse_status.float_rounding_mode), sizeof(((CPUArchState *)0)->sse_status.float_rounding_mode), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1796 */
};
static const DfHelperField dfu_roundss_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1767 */
    { offsetof(CPUArchState, sse_status.float_rounding_mode), sizeof(((CPUArchState *)0)->sse_status.float_rounding_mode), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1771 */
};
static const DfHelperField dfu_rsqrtps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:846 */
};
static const DfHelperField dfu_rsqrtps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:846 */
};
static const DfHelperField dfu_rsqrtss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:859 */
};
static const DfHelperField dfu_sqrtpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:548 */
};
static const DfHelperField dfu_sqrtpd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:548 */
};
static const DfHelperField dfu_sqrtps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:540 */
};
static const DfHelperField dfu_sqrtps_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:540 */
};
static const DfHelperField dfu_sqrtsd_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:565 */
};
static const DfHelperField dfu_sqrtss_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:556 */
};
static const DfHelperField dfu_subpd_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:530 */
};
static const DfHelperField dfu_subpd_ymm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:530 */
};
static const DfHelperField dfu_subps_xmm_env[] = {
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:530 */
};
static const DfHelperField dfu_subps_ymm_env[] = {
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
static const DfHelperField dfu_ucomiss_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1115 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1114 */
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:1113 */
};
static const DfHelperField dfu_update_mxcsr_env[] = {
    { offsetof(CPUArchState, mxcsr), sizeof(((CPUArchState *)0)->mxcsr), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3298 */
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3290 */
};
static const DfHelperField dfu_verr_env[] = {
    { offsetof(CPUArchState, cc_dst), sizeof(((CPUArchState *)0)->cc_dst), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src2), sizeof(((CPUArchState *)0)->cc_src2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:8713 */
    { offsetof(CPUArchState, gdt), sizeof(((CPUArchState *)0)->gdt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:144 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:8710 */
    { offsetof(CPUArchState, ldt), sizeof(((CPUArchState *)0)->ldt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:142 */
};
static const DfHelperField dfu_verw_env[] = {
    { offsetof(CPUArchState, cc_dst), sizeof(((CPUArchState *)0)->cc_dst), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, cc_src2), sizeof(((CPUArchState *)0)->cc_src2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/cc_helper.c:211 */
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:8713 */
    { offsetof(CPUArchState, gdt), sizeof(((CPUArchState *)0)->gdt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:144 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.c:8710 */
    { offsetof(CPUArchState, ldt), sizeof(((CPUArchState *)0)->ldt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/seg_helper.c:142 */
};
static const DfHelperField dfu_vtestpd_xmm_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2320 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2319 */
};
static const DfHelperField dfu_vtestps_xmm_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2307 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/ops_sse.h:2306 */
};
static const DfHelperField dfu_write_eflags_env[] = {
    { offsetof(CPUArchState, cc_op), sizeof(((CPUArchState *)0)->cc_op), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:35 */
    { offsetof(CPUArchState, cc_src), sizeof(((CPUArchState *)0)->cc_src), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:34 */
    { offsetof(CPUArchState, df), sizeof(((CPUArchState *)0)->df), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:36 */
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:37 */
};
static const DfHelperField dfu_wrpkru_env[] = {
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:121 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, pkru), sizeof(((CPUArchState *)0)->pkru), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/misc_helper.c:128 */
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
static const DfHelperField dfu_xrstor_env[] = {
    { offsetof(CPUArchState, bnd_regs), sizeof(((CPUArchState *)0)->bnd_regs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2940, INDEX NOT STATED */
    { offsetof(CPUArchState, bndcs_regs), sizeof(((CPUArchState *)0)->bndcs_regs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3059 */
    { offsetof(CPUArchState, bndcs_regs.cfgu), sizeof(((CPUArchState *)0)->bndcs_regs.cfgu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2950 */
    { offsetof(CPUArchState, bndcs_regs.sts), sizeof(((CPUArchState *)0)->bndcs_regs.sts), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2952 */
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2794 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, fp_status), sizeof(((CPUArchState *)0)->fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:780 */
    { offsetof(CPUArchState, fpcs), sizeof(((CPUArchState *)0)->fpcs), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:818 */
    { offsetof(CPUArchState, fpdp), sizeof(((CPUArchState *)0)->fpdp), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:821 */
    { offsetof(CPUArchState, fpds), sizeof(((CPUArchState *)0)->fpds), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:819 */
    { offsetof(CPUArchState, fpip), sizeof(((CPUArchState *)0)->fpip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:820 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2853, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2520 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2846, INDEX NOT STATED */
    { offsetof(CPUArchState, fptags[0]), sizeof(((CPUArchState *)0)->fptags[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:823 */
    { offsetof(CPUArchState, fptags[1]), sizeof(((CPUArchState *)0)->fptags[1]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:824 */
    { offsetof(CPUArchState, fptags[2]), sizeof(((CPUArchState *)0)->fptags[2]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:825 */
    { offsetof(CPUArchState, fptags[3]), sizeof(((CPUArchState *)0)->fptags[3]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:826 */
    { offsetof(CPUArchState, fptags[4]), sizeof(((CPUArchState *)0)->fptags[4]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:827 */
    { offsetof(CPUArchState, fptags[5]), sizeof(((CPUArchState *)0)->fptags[5]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:828 */
    { offsetof(CPUArchState, fptags[6]), sizeof(((CPUArchState *)0)->fptags[6]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:829 */
    { offsetof(CPUArchState, fptags[7]), sizeof(((CPUArchState *)0)->fptags[7]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:830 */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2731 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2521 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2870 */
    { offsetof(CPUArchState, hflags2), sizeof(((CPUArchState *)0)->hflags2), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:51 */
    { offsetof(CPUArchState, msr_bndcfgs), sizeof(((CPUArchState *)0)->msr_bndcfgs), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/helper.c:57 */
    { offsetof(CPUArchState, mxcsr), sizeof(((CPUArchState *)0)->mxcsr), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/cpu.h:2723 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, pkru), sizeof(((CPUArchState *)0)->pkru), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3064 */
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3271 */
    { offsetof(CPUArchState, xcr0), sizeof(((CPUArchState *)0)->xcr0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3013 */
    { offsetof(CPUArchState, xmm_regs), sizeof(((CPUArchState *)0)->xmm_regs), INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2878, INDEX NOT STATED */
};
static const DfHelperField dfu_xsave_env[] = {
    { offsetof(CPUArchState, bnd_regs), sizeof(((CPUArchState *)0)->bnd_regs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2692, INDEX NOT STATED */
    { offsetof(CPUArchState, bndcs_regs.cfgu), sizeof(((CPUArchState *)0)->bndcs_regs.cfgu), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2702 */
    { offsetof(CPUArchState, bndcs_regs.sts), sizeof(((CPUArchState *)0)->bndcs_regs.sts), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2704 */
    { offsetof(CPUArchState, cr[4]), sizeof(((CPUArchState *)0)->cr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2794 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:125 */
    { offsetof(CPUArchState, exception_is_int), sizeof(((CPUArchState *)0)->exception_is_int), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:126 */
    { offsetof(CPUArchState, exception_next_eip), sizeof(((CPUArchState *)0)->exception_next_eip), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:127 */
    { offsetof(CPUArchState, fpregs), sizeof(((CPUArchState *)0)->fpregs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2633, INDEX NOT STATED */
    { offsetof(CPUArchState, fpstt), sizeof(((CPUArchState *)0)->fpstt), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2614 */
    { offsetof(CPUArchState, fptags), sizeof(((CPUArchState *)0)->fptags), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2617, INDEX NOT STATED */
    { offsetof(CPUArchState, fpuc), sizeof(((CPUArchState *)0)->fpuc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2620 */
    { offsetof(CPUArchState, fpus), sizeof(((CPUArchState *)0)->fpus), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2614 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2654 */
    { offsetof(CPUArchState, mxcsr), sizeof(((CPUArchState *)0)->mxcsr), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3298 */
    { offsetof(CPUArchState, old_exception), sizeof(((CPUArchState *)0)->old_exception), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/excp_helper.c:48 */
    { offsetof(CPUArchState, pkru), sizeof(((CPUArchState *)0)->pkru), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2709 */
    { offsetof(CPUArchState, sse_status), sizeof(((CPUArchState *)0)->sse_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:3290 */
    { offsetof(CPUArchState, xcr0), sizeof(((CPUArchState *)0)->xcr0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/i386/tcg/fpu_helper.c:2813 */
    { offsetof(CPUArchState, xmm_regs), sizeof(((CPUArchState *)0)->xmm_regs), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/i386/tcg/fpu_helper.c:2662, INDEX NOT STATED */
};
static const DfHelperField dfu_lookup_tb_ptr_env[] = {
    { offsetof(CPUArchState, eflags), sizeof(((CPUArchState *)0)->eflags), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/cpu.h:2634 */
    { offsetof(CPUArchState, eip), sizeof(((CPUArchState *)0)->eip), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/cpu.h:2637 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/cpu.h:2633 */
    { offsetof(CPUArchState, segs), sizeof(((CPUArchState *)0)->segs), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/i386/cpu.h:2639 */
};
static const DfHelperAccess dfu_iret_protected_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 0, 1 },   /* ../target/i386/tcg/seg_helper.c:2284, 6 site(s) */
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/i386/tcg/seg_helper.c:306, 1 site(s) */
};
static const DfHelperAccess dfu_lar_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 1 },   /* ../target/i386/tcg/seg_helper.c:151, 2 site(s) */
};
static const DfHelperAccess dfu_lcall_protected_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 0, 1 },   /* ../target/i386/tcg/seg_helper.c:151, 14 site(s) */
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/i386/tcg/seg_helper.c:306, 1 site(s) */
};
static const DfHelperAccess dfu_ljmp_protected_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 1 },   /* ../target/i386/tcg/seg_helper.c:151, 5 site(s) */
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/i386/tcg/seg_helper.c:306, 1 site(s) */
};
static const DfHelperAccess dfu_load_seg_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 1 },   /* ../target/i386/tcg/seg_helper.c:1439, 2 site(s) */
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/i386/tcg/seg_helper.c:1480, 1 site(s) */
};
static const DfHelperAccess dfu_lret_protected_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 1 },   /* ../target/i386/tcg/seg_helper.c:151, 2 site(s) */
};
static const DfHelperAccess dfu_lsl_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 1 },   /* ../target/i386/tcg/seg_helper.c:151, 2 site(s) */
};
static const DfHelperAccess dfu_maskmov_mmx_acc[] = {
    { INSN_DF_WR, 3, DF_HA_NO_ARG, 1, 0 },   /* ../target/i386/ops_sse.h:381, 1 site(s) */
};
static const DfHelperAccess dfu_maskmov_xmm_acc[] = {
    { INSN_DF_WR, 3, DF_HA_NO_ARG, 1, 0 },   /* ../target/i386/ops_sse.h:381, 1 site(s) */
};
static const DfHelperAccess dfu_verr_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 1 },   /* ../target/i386/tcg/seg_helper.c:151, 2 site(s) */
};
static const DfHelperAccess dfu_verw_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 1 },   /* ../target/i386/tcg/seg_helper.c:151, 2 site(s) */
};
static const DfHelperAccess dfu_vpgatherdd_xmm_acc[] = {
    { INSN_DF_RD, 6, DF_HA_NO_ARG, 4, 0 },   /* ../target/i386/ops_sse.h:2373, 1 site(s) */
};
static const DfHelperAccess dfu_vpgatherdd_ymm_acc[] = {
    { INSN_DF_RD, 6, DF_HA_NO_ARG, 4, 0 },   /* ../target/i386/ops_sse.h:2373, 1 site(s) */
};
static const DfHelperAccess dfu_vpgatherdq_xmm_acc[] = {
    { INSN_DF_RD, 6, DF_HA_NO_ARG, 8, 0 },   /* ../target/i386/ops_sse.h:2387, 1 site(s) */
};
static const DfHelperAccess dfu_vpgatherdq_ymm_acc[] = {
    { INSN_DF_RD, 6, DF_HA_NO_ARG, 8, 0 },   /* ../target/i386/ops_sse.h:2387, 1 site(s) */
};
static const DfHelperAccess dfu_vpgatherqd_xmm_acc[] = {
    { INSN_DF_RD, 6, DF_HA_NO_ARG, 4, 0 },   /* ../target/i386/ops_sse.h:2401, 1 site(s) */
};
static const DfHelperAccess dfu_vpgatherqd_ymm_acc[] = {
    { INSN_DF_RD, 6, DF_HA_NO_ARG, 4, 0 },   /* ../target/i386/ops_sse.h:2401, 1 site(s) */
};
static const DfHelperAccess dfu_vpgatherqq_xmm_acc[] = {
    { INSN_DF_RD, 6, DF_HA_NO_ARG, 8, 0 },   /* ../target/i386/ops_sse.h:2419, 1 site(s) */
};
static const DfHelperAccess dfu_vpgatherqq_ymm_acc[] = {
    { INSN_DF_RD, 6, DF_HA_NO_ARG, 8, 0 },   /* ../target/i386/ops_sse.h:2419, 1 site(s) */
};
static const DfHelperAccess dfu_vpmaskmovd_st_xmm_acc[] = {
    { INSN_DF_WR, 3, DF_HA_NO_ARG, 4, 0 },   /* ../target/i386/ops_sse.h:2330, 1 site(s) */
};
static const DfHelperAccess dfu_vpmaskmovq_st_xmm_acc[] = {
    { INSN_DF_WR, 3, DF_HA_NO_ARG, 8, 0 },   /* ../target/i386/ops_sse.h:2342, 1 site(s) */
};

static const DfHelperUsage df_helper_usage[] = {
    { "addpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_addpd_xmm_env, ARRAY_SIZE(dfu_addpd_xmm_env), true,
      "../target/i386/ops_sse.h:529",
      NULL, 0 },
    { "addpd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_addpd_ymm_env, ARRAY_SIZE(dfu_addpd_ymm_env), true,
      "../target/i386/ops_sse.h:529",
      NULL, 0 },
    { "addps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_addps_xmm_env, ARRAY_SIZE(dfu_addps_xmm_env), true,
      "../target/i386/ops_sse.h:529",
      NULL, 0 },
    { "addps_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_addps_ymm_env, ARRAY_SIZE(dfu_addps_ymm_env), true,
      "../target/i386/ops_sse.h:529",
      NULL, 0 },
    { "addsd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_addsd_env, ARRAY_SIZE(dfu_addsd_env), true,
      "../target/i386/ops_sse.h:529",
      NULL, 0 },
    { "addss", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_addss_env, ARRAY_SIZE(dfu_addss_env), true,
      "../target/i386/ops_sse.h:529",
      NULL, 0 },
    { "addsubpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_addsubpd_xmm_env, ARRAY_SIZE(dfu_addsubpd_xmm_env), true,
      "../target/i386/ops_sse.h:991",
      NULL, 0 },
    { "addsubpd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_addsubpd_ymm_env, ARRAY_SIZE(dfu_addsubpd_ymm_env), true,
      "../target/i386/ops_sse.h:991",
      NULL, 0 },
    { "addsubps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_addsubps_xmm_env, ARRAY_SIZE(dfu_addsubps_xmm_env), true,
      "../target/i386/ops_sse.h:982",
      NULL, 0 },
    { "addsubps_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_addsubps_ymm_env, ARRAY_SIZE(dfu_addsubps_ymm_env), true,
      "../target/i386/ops_sse.h:982",
      NULL, 0 },
    { "aesdec_xmm", { 0, 3, 3, 3 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2148",
      NULL, 0 },
    { "aesdeclast_xmm", { 0, 3, 3, 3 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2159",
      NULL, 0 },
    { "aesenc_xmm", { 0, 3, 3, 3 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2170",
      NULL, 0 },
    { "aesenc_ymm", { 0, 3, 3, 3 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2170",
      NULL, 0 },
    { "aesenclast_xmm", { 0, 3, 3, 3 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2181",
      NULL, 0 },
    { "aesenclast_ymm", { 0, 3, 3, 3 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2181",
      NULL, 0 },
    { "aesimc_xmm", { 0, 3, 3 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2193",
      NULL, 0 },
    { "aeskeygenassist_xmm", { 0, 3, 3 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2201",
      NULL, 0 },
    { "blendpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1817",
      NULL, 0 },
    { "blendps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1816",
      NULL, 0 },
    { "blendps_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1816",
      NULL, 0 },
    { "blendvpd_xmm", { 0, 2, 1, 1, 1 }, { 0, 64, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1606",
      NULL, 0 },
    { "blendvps_xmm", { 0, 2, 1, 1, 1 }, { 0, 64, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1605",
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
    { "cmpeqpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpeqpd_xmm_env, ARRAY_SIZE(dfu_cmpeqpd_xmm_env), true,
      "../target/i386/ops_sse.h:1065",
      NULL, 0 },
    { "cmpeqpd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpeqpd_ymm_env, ARRAY_SIZE(dfu_cmpeqpd_ymm_env), true,
      "../target/i386/ops_sse.h:1065",
      NULL, 0 },
    { "cmpeqps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpeqps_xmm_env, ARRAY_SIZE(dfu_cmpeqps_xmm_env), true,
      "../target/i386/ops_sse.h:1065",
      NULL, 0 },
    { "cmpeqps_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpeqps_ymm_env, ARRAY_SIZE(dfu_cmpeqps_ymm_env), true,
      "../target/i386/ops_sse.h:1065",
      NULL, 0 },
    { "cmpeqsd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpeqsd_env, ARRAY_SIZE(dfu_cmpeqsd_env), true,
      "../target/i386/ops_sse.h:1065",
      NULL, 0 },
    { "cmpeqss", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpeqss_env, ARRAY_SIZE(dfu_cmpeqss_env), true,
      "../target/i386/ops_sse.h:1065",
      NULL, 0 },
    { "cmpgepd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpgepd_xmm_env, ARRAY_SIZE(dfu_cmpgepd_xmm_env), true,
      "../target/i386/ops_sse.h:1079",
      NULL, 0 },
    { "cmpgepd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpgepd_ymm_env, ARRAY_SIZE(dfu_cmpgepd_ymm_env), true,
      "../target/i386/ops_sse.h:1079",
      NULL, 0 },
    { "cmpgeps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpgeps_xmm_env, ARRAY_SIZE(dfu_cmpgeps_xmm_env), true,
      "../target/i386/ops_sse.h:1079",
      NULL, 0 },
    { "cmpgeps_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpgeps_ymm_env, ARRAY_SIZE(dfu_cmpgeps_ymm_env), true,
      "../target/i386/ops_sse.h:1079",
      NULL, 0 },
    { "cmpgesd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpgesd_env, ARRAY_SIZE(dfu_cmpgesd_env), true,
      "../target/i386/ops_sse.h:1079",
      NULL, 0 },
    { "cmpgess", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpgess_env, ARRAY_SIZE(dfu_cmpgess_env), true,
      "../target/i386/ops_sse.h:1079",
      NULL, 0 },
    { "cmplepd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmplepd_xmm_env, ARRAY_SIZE(dfu_cmplepd_xmm_env), true,
      "../target/i386/ops_sse.h:1067",
      NULL, 0 },
    { "cmplepd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmplepd_ymm_env, ARRAY_SIZE(dfu_cmplepd_ymm_env), true,
      "../target/i386/ops_sse.h:1067",
      NULL, 0 },
    { "cmpleps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpleps_xmm_env, ARRAY_SIZE(dfu_cmpleps_xmm_env), true,
      "../target/i386/ops_sse.h:1067",
      NULL, 0 },
    { "cmpleps_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpleps_ymm_env, ARRAY_SIZE(dfu_cmpleps_ymm_env), true,
      "../target/i386/ops_sse.h:1067",
      NULL, 0 },
    { "cmplesd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmplesd_env, ARRAY_SIZE(dfu_cmplesd_env), true,
      "../target/i386/ops_sse.h:1067",
      NULL, 0 },
    { "cmpless", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpless_env, ARRAY_SIZE(dfu_cmpless_env), true,
      "../target/i386/ops_sse.h:1067",
      NULL, 0 },
    { "cmpltpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpltpd_xmm_env, ARRAY_SIZE(dfu_cmpltpd_xmm_env), true,
      "../target/i386/ops_sse.h:1066",
      NULL, 0 },
    { "cmpltps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpltps_xmm_env, ARRAY_SIZE(dfu_cmpltps_xmm_env), true,
      "../target/i386/ops_sse.h:1066",
      NULL, 0 },
    { "cmpltqpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpltqpd_xmm_env, ARRAY_SIZE(dfu_cmpltqpd_xmm_env), true,
      "../target/i386/ops_sse.h:1084",
      NULL, 0 },
    { "cmpltqpd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpltqpd_ymm_env, ARRAY_SIZE(dfu_cmpltqpd_ymm_env), true,
      "../target/i386/ops_sse.h:1084",
      NULL, 0 },
    { "cmpltqps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpltqps_xmm_env, ARRAY_SIZE(dfu_cmpltqps_xmm_env), true,
      "../target/i386/ops_sse.h:1084",
      NULL, 0 },
    { "cmpltqps_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpltqps_ymm_env, ARRAY_SIZE(dfu_cmpltqps_ymm_env), true,
      "../target/i386/ops_sse.h:1084",
      NULL, 0 },
    { "cmpltqsd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpltqsd_env, ARRAY_SIZE(dfu_cmpltqsd_env), true,
      "../target/i386/ops_sse.h:1084",
      NULL, 0 },
    { "cmpltqss", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpltqss_env, ARRAY_SIZE(dfu_cmpltqss_env), true,
      "../target/i386/ops_sse.h:1084",
      NULL, 0 },
    { "cmpltsd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpltsd_env, ARRAY_SIZE(dfu_cmpltsd_env), true,
      "../target/i386/ops_sse.h:1066",
      NULL, 0 },
    { "cmpltss", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpltss_env, ARRAY_SIZE(dfu_cmpltss_env), true,
      "../target/i386/ops_sse.h:1066",
      NULL, 0 },
    { "cmpnltpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpnltpd_xmm_env, ARRAY_SIZE(dfu_cmpnltpd_xmm_env), true,
      "../target/i386/ops_sse.h:1070",
      NULL, 0 },
    { "cmpnltps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpnltps_xmm_env, ARRAY_SIZE(dfu_cmpnltps_xmm_env), true,
      "../target/i386/ops_sse.h:1070",
      NULL, 0 },
    { "cmpnltsd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpnltsd_env, ARRAY_SIZE(dfu_cmpnltsd_env), true,
      "../target/i386/ops_sse.h:1070",
      NULL, 0 },
    { "cmpnltss", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cmpnltss_env, ARRAY_SIZE(dfu_cmpnltss_env), true,
      "../target/i386/ops_sse.h:1070",
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
    { "cr4_testbit", { 0 }, { 0 },
      dfu_cr4_testbit_env, ARRAY_SIZE(dfu_cr4_testbit_env), true,
      "../target/i386/tcg/int_helper.c:439",
      NULL, 0 },
    { "crc32", { 0 }, { 0 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2119",
      NULL, 0 },
    { "cvtdq2pd_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvtdq2pd_xmm_env, ARRAY_SIZE(dfu_cvtdq2pd_xmm_env), true,
      "../target/i386/ops_sse.h:650",
      NULL, 0 },
    { "cvtdq2pd_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvtdq2pd_ymm_env, ARRAY_SIZE(dfu_cvtdq2pd_ymm_env), true,
      "../target/i386/ops_sse.h:650",
      NULL, 0 },
    { "cvtdq2ps_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvtdq2ps_xmm_env, ARRAY_SIZE(dfu_cvtdq2ps_xmm_env), true,
      "../target/i386/ops_sse.h:642",
      NULL, 0 },
    { "cvtdq2ps_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvtdq2ps_ymm_env, ARRAY_SIZE(dfu_cvtdq2ps_ymm_env), true,
      "../target/i386/ops_sse.h:642",
      NULL, 0 },
    { "cvtpd2dq_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvtpd2dq_xmm_env, ARRAY_SIZE(dfu_cvtpd2dq_xmm_env), true,
      "../target/i386/ops_sse.h:739",
      NULL, 0 },
    { "cvtpd2dq_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvtpd2dq_ymm_env, ARRAY_SIZE(dfu_cvtpd2dq_ymm_env), true,
      "../target/i386/ops_sse.h:739",
      NULL, 0 },
    { "cvtpd2pi", { 0, 2, 1 }, { 0, 8, 64 },
      dfu_cvtpd2pi_env, ARRAY_SIZE(dfu_cvtpd2pi_env), true,
      "../target/i386/ops_sse.h:757",
      NULL, 0 },
    { "cvtpd2ps_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvtpd2ps_xmm_env, ARRAY_SIZE(dfu_cvtpd2ps_xmm_env), true,
      "../target/i386/ops_sse.h:581",
      NULL, 0 },
    { "cvtpd2ps_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvtpd2ps_ymm_env, ARRAY_SIZE(dfu_cvtpd2ps_ymm_env), true,
      "../target/i386/ops_sse.h:581",
      NULL, 0 },
    { "cvtph2ps_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvtph2ps_xmm_env, ARRAY_SIZE(dfu_cvtph2ps_xmm_env), true,
      "../target/i386/ops_sse.h:593",
      NULL, 0 },
    { "cvtpi2pd", { 0, 2, 1 }, { 0, 64, 8 },
      dfu_cvtpi2pd_env, ARRAY_SIZE(dfu_cvtpi2pd_env), true,
      "../target/i386/ops_sse.h:666",
      NULL, 0 },
    { "cvtpi2ps", { 0, 2, 1 }, { 0, 64, 8 },
      dfu_cvtpi2ps_env, ARRAY_SIZE(dfu_cvtpi2ps_env), true,
      "../target/i386/ops_sse.h:660",
      NULL, 0 },
    { "cvtps2dq_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvtps2dq_xmm_env, ARRAY_SIZE(dfu_cvtps2dq_xmm_env), true,
      "../target/i386/ops_sse.h:731",
      NULL, 0 },
    { "cvtps2dq_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvtps2dq_ymm_env, ARRAY_SIZE(dfu_cvtps2dq_ymm_env), true,
      "../target/i386/ops_sse.h:731",
      NULL, 0 },
    { "cvtps2pd_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvtps2pd_xmm_env, ARRAY_SIZE(dfu_cvtps2pd_xmm_env), true,
      "../target/i386/ops_sse.h:573",
      NULL, 0 },
    { "cvtps2pd_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvtps2pd_ymm_env, ARRAY_SIZE(dfu_cvtps2pd_ymm_env), true,
      "../target/i386/ops_sse.h:573",
      NULL, 0 },
    { "cvtps2ph_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvtps2ph_xmm_env, ARRAY_SIZE(dfu_cvtps2ph_xmm_env), true,
      "../target/i386/ops_sse.h:602",
      NULL, 0 },
    { "cvtps2pi", { 0, 2, 1 }, { 0, 8, 64 },
      dfu_cvtps2pi_env, ARRAY_SIZE(dfu_cvtps2pi_env), true,
      "../target/i386/ops_sse.h:751",
      NULL, 0 },
    { "cvtsd2si", { 0, 1 }, { 0, 64 },
      dfu_cvtsd2si_env, ARRAY_SIZE(dfu_cvtsd2si_env), true,
      "../target/i386/ops_sse.h:768",
      NULL, 0 },
    { "cvtsd2ss", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_cvtsd2ss_env, ARRAY_SIZE(dfu_cvtsd2ss_env), true,
      "../target/i386/ops_sse.h:631",
      NULL, 0 },
    { "cvtsi2sd", { 0, 2 }, { 0, 64 },
      dfu_cvtsi2sd_env, ARRAY_SIZE(dfu_cvtsi2sd_env), true,
      "../target/i386/ops_sse.h:677",
      NULL, 0 },
    { "cvtsi2ss", { 0, 2 }, { 0, 64 },
      dfu_cvtsi2ss_env, ARRAY_SIZE(dfu_cvtsi2ss_env), true,
      "../target/i386/ops_sse.h:672",
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
    { "cvtss2si", { 0, 1 }, { 0, 64 },
      dfu_cvtss2si_env, ARRAY_SIZE(dfu_cvtss2si_env), true,
      "../target/i386/ops_sse.h:763",
      NULL, 0 },
    { "cvttpd2dq_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvttpd2dq_xmm_env, ARRAY_SIZE(dfu_cvttpd2dq_xmm_env), true,
      "../target/i386/ops_sse.h:796",
      NULL, 0 },
    { "cvttpd2dq_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvttpd2dq_ymm_env, ARRAY_SIZE(dfu_cvttpd2dq_ymm_env), true,
      "../target/i386/ops_sse.h:796",
      NULL, 0 },
    { "cvttpd2pi", { 0, 2, 1 }, { 0, 8, 64 },
      dfu_cvttpd2pi_env, ARRAY_SIZE(dfu_cvttpd2pi_env), true,
      "../target/i386/ops_sse.h:815",
      NULL, 0 },
    { "cvttps2dq_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvttps2dq_xmm_env, ARRAY_SIZE(dfu_cvttps2dq_xmm_env), true,
      "../target/i386/ops_sse.h:787",
      NULL, 0 },
    { "cvttps2dq_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_cvttps2dq_ymm_env, ARRAY_SIZE(dfu_cvttps2dq_ymm_env), true,
      "../target/i386/ops_sse.h:787",
      NULL, 0 },
    { "cvttps2pi", { 0, 2, 1 }, { 0, 8, 64 },
      dfu_cvttps2pi_env, ARRAY_SIZE(dfu_cvttps2pi_env), true,
      "../target/i386/ops_sse.h:809",
      NULL, 0 },
    { "cvttsd2si", { 0, 1 }, { 0, 64 },
      dfu_cvttsd2si_env, ARRAY_SIZE(dfu_cvttsd2si_env), true,
      "../target/i386/ops_sse.h:826",
      NULL, 0 },
    { "cvttsd2sq", { 0, 1 }, { 0, 64 },
      dfu_cvttsd2sq_env, ARRAY_SIZE(dfu_cvttsd2sq_env), true,
      "../target/i386/ops_sse.h:837",
      NULL, 0 },
    { "cvttss2si", { 0, 1 }, { 0, 64 },
      dfu_cvttss2si_env, ARRAY_SIZE(dfu_cvttss2si_env), true,
      "../target/i386/ops_sse.h:821",
      NULL, 0 },
    { "cvttss2sq", { 0, 1 }, { 0, 64 },
      dfu_cvttss2sq_env, ARRAY_SIZE(dfu_cvttss2sq_env), true,
      "../target/i386/ops_sse.h:832",
      NULL, 0 },
    { "divb_AL", { 0 }, { 0 },
      dfu_divb_AL_env, ARRAY_SIZE(dfu_divb_AL_env), true,
      "../target/i386/tcg/int_helper.c:35",
      NULL, 0 },
    { "divl_EAX", { 0 }, { 0 },
      dfu_divl_EAX_env, ARRAY_SIZE(dfu_divl_EAX_env), true,
      "../target/i386/tcg/int_helper.c:109",
      NULL, 0 },
    { "divpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_divpd_xmm_env, ARRAY_SIZE(dfu_divpd_xmm_env), true,
      "../target/i386/ops_sse.h:532",
      NULL, 0 },
    { "divpd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_divpd_ymm_env, ARRAY_SIZE(dfu_divpd_ymm_env), true,
      "../target/i386/ops_sse.h:532",
      NULL, 0 },
    { "divps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_divps_xmm_env, ARRAY_SIZE(dfu_divps_xmm_env), true,
      "../target/i386/ops_sse.h:532",
      NULL, 0 },
    { "divps_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_divps_ymm_env, ARRAY_SIZE(dfu_divps_ymm_env), true,
      "../target/i386/ops_sse.h:532",
      NULL, 0 },
    { "divq_EAX", { 0 }, { 0 },
      dfu_divq_EAX_env, ARRAY_SIZE(dfu_divq_EAX_env), true,
      "../target/i386/tcg/int_helper.c:369",
      NULL, 0 },
    { "divsd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_divsd_env, ARRAY_SIZE(dfu_divsd_env), true,
      "../target/i386/ops_sse.h:532",
      NULL, 0 },
    { "divss", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_divss_env, ARRAY_SIZE(dfu_divss_env), true,
      "../target/i386/ops_sse.h:532",
      NULL, 0 },
    { "divw_AX", { 0 }, { 0 },
      dfu_divw_AX_env, ARRAY_SIZE(dfu_divw_AX_env), true,
      "../target/i386/tcg/int_helper.c:71",
      NULL, 0 },
    { "dppd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_dppd_xmm_env, ARRAY_SIZE(dfu_dppd_xmm_env), true,
      "../target/i386/ops_sse.h:1864",
      NULL, 0 },
    { "dpps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_dpps_xmm_env, ARRAY_SIZE(dfu_dpps_xmm_env), true,
      "../target/i386/ops_sse.h:1820",
      NULL, 0 },
    { "emms", { 0 }, { 0 },
      dfu_emms_env, ARRAY_SIZE(dfu_emms_env), true,
      "../target/i386/tcg/fpu_helper.c:3324",
      NULL, 0 },
    { "enter_mmx", { 0 }, { 0 },
      dfu_enter_mmx_env, ARRAY_SIZE(dfu_enter_mmx_env), true,
      "../target/i386/tcg/fpu_helper.c:3317",
      NULL, 0 },
    { "extrq_i", { 0, 3 }, { 0, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:912",
      NULL, 0 },
    { "extrq_r", { 0, 3, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:907",
      NULL, 0 },
    { "f2xm1", { 0 }, { 0 },
      dfu_f2xm1_env, ARRAY_SIZE(dfu_f2xm1_env), true,
      "../target/i386/tcg/fpu_helper.c:1138",
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
    { "fbld_ST0", { 0 }, { 0 },
      dfu_fbld_ST0_env, ARRAY_SIZE(dfu_fbld_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:840",
      NULL, 0 },
    { "fbst_ST0", { 0 }, { 0 },
      dfu_fbst_ST0_env, ARRAY_SIZE(dfu_fbst_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:863",
      NULL, 0 },
    { "fchs_ST0", { 0 }, { 0 },
      dfu_fchs_ST0_env, ARRAY_SIZE(dfu_fchs_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:662",
      NULL, 0 },
    { "fclex", { 0 }, { 0 },
      dfu_fclex_env, ARRAY_SIZE(dfu_fclex_env), true,
      "../target/i386/tcg/fpu_helper.c:802",
      NULL, 0 },
    { "fcom_ST0_FT0", { 0 }, { 0 },
      dfu_fcom_ST0_FT0_env, ARRAY_SIZE(dfu_fcom_ST0_FT0_env), true,
      "../target/i386/tcg/fpu_helper.c:529",
      NULL, 0 },
    { "fcomi_ST0_FT0", { 0 }, { 0 },
      dfu_fcomi_ST0_FT0_env, ARRAY_SIZE(dfu_fcomi_ST0_FT0_env), true,
      "../target/i386/tcg/fpu_helper.c:551",
      NULL, 0 },
    { "fcos", { 0 }, { 0 },
      dfu_fcos_env, ARRAY_SIZE(dfu_fcos_env), true,
      "../target/i386/tcg/fpu_helper.c:2397",
      NULL, 0 },
    { "fdecstp", { 0 }, { 0 },
      dfu_fdecstp_env, ARRAY_SIZE(dfu_fdecstp_env), true,
      "../target/i386/tcg/fpu_helper.c:477",
      NULL, 0 },
    { "fdiv_ST0_FT0", { 0 }, { 0 },
      dfu_fdiv_ST0_FT0_env, ARRAY_SIZE(dfu_fdiv_ST0_FT0_env), true,
      "../target/i386/tcg/fpu_helper.c:605",
      NULL, 0 },
    { "fdiv_STN_ST0", { 0 }, { 0 },
      dfu_fdiv_STN_ST0_env, ARRAY_SIZE(dfu_fdiv_STN_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:645",
      NULL, 0 },
    { "fdivr_ST0_FT0", { 0 }, { 0 },
      dfu_fdivr_ST0_FT0_env, ARRAY_SIZE(dfu_fdivr_ST0_FT0_env), true,
      "../target/i386/tcg/fpu_helper.c:610",
      NULL, 0 },
    { "fdivr_STN_ST0", { 0 }, { 0 },
      dfu_fdivr_STN_ST0_env, ARRAY_SIZE(dfu_fdivr_STN_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:653",
      NULL, 0 },
    { "ffree_STN", { 0 }, { 0 },
      dfu_ffree_STN_env, ARRAY_SIZE(dfu_ffree_STN_env), true,
      "../target/i386/tcg/fpu_helper.c:491",
      NULL, 0 },
    { "fildl_FT0", { 0 }, { 0 },
      dfu_fildl_FT0_env, ARRAY_SIZE(dfu_fildl_FT0_env), true,
      "../target/i386/tcg/fpu_helper.c:268",
      NULL, 0 },
    { "fildl_ST0", { 0 }, { 0 },
      dfu_fildl_ST0_env, ARRAY_SIZE(dfu_fildl_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:314",
      NULL, 0 },
    { "fildll_ST0", { 0 }, { 0 },
      dfu_fildll_ST0_env, ARRAY_SIZE(dfu_fildll_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:327",
      NULL, 0 },
    { "fincstp", { 0 }, { 0 },
      dfu_fincstp_env, ARRAY_SIZE(dfu_fincstp_env), true,
      "../target/i386/tcg/fpu_helper.c:483",
      NULL, 0 },
    { "fist_ST0", { 0 }, { 0 },
      dfu_fist_ST0_env, ARRAY_SIZE(dfu_fist_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:366",
      NULL, 0 },
    { "fistl_ST0", { 0 }, { 0 },
      dfu_fistl_ST0_env, ARRAY_SIZE(dfu_fistl_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:380",
      NULL, 0 },
    { "fistll_ST0", { 0 }, { 0 },
      dfu_fistll_ST0_env, ARRAY_SIZE(dfu_fistll_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:393",
      NULL, 0 },
    { "fistt_ST0", { 0 }, { 0 },
      dfu_fistt_ST0_env, ARRAY_SIZE(dfu_fistt_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:406",
      NULL, 0 },
    { "fisttl_ST0", { 0 }, { 0 },
      dfu_fisttl_ST0_env, ARRAY_SIZE(dfu_fisttl_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:420",
      NULL, 0 },
    { "fisttll_ST0", { 0 }, { 0 },
      dfu_fisttll_ST0_env, ARRAY_SIZE(dfu_fisttll_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:433",
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
    { "fldl2e_ST0", { 0 }, { 0 },
      dfu_fldl2e_ST0_env, ARRAY_SIZE(dfu_fldl2e_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:689",
      NULL, 0 },
    { "fldl2t_ST0", { 0 }, { 0 },
      dfu_fldl2t_ST0_env, ARRAY_SIZE(dfu_fldl2t_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:677",
      NULL, 0 },
    { "fldl_FT0", { 0 }, { 0 },
      dfu_fldl_FT0_env, ARRAY_SIZE(dfu_fldl_FT0_env), true,
      "../target/i386/tcg/fpu_helper.c:255",
      NULL, 0 },
    { "fldl_ST0", { 0 }, { 0 },
      dfu_fldl_ST0_env, ARRAY_SIZE(dfu_fldl_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:290",
      NULL, 0 },
    { "fldlg2_ST0", { 0 }, { 0 },
      dfu_fldlg2_ST0_env, ARRAY_SIZE(dfu_fldlg2_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:715",
      NULL, 0 },
    { "fldln2_ST0", { 0 }, { 0 },
      dfu_fldln2_ST0_env, ARRAY_SIZE(dfu_fldln2_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:728",
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
    { "fldz_FT0", { 0 }, { 0 },
      dfu_fldz_FT0_env, ARRAY_SIZE(dfu_fldz_FT0_env), true,
      "../target/i386/tcg/fpu_helper.c:746",
      NULL, 0 },
    { "fldz_ST0", { 0 }, { 0 },
      dfu_fldz_ST0_env, ARRAY_SIZE(dfu_fldz_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:741",
      NULL, 0 },
    { "fma4pd_xmm", { 0, 2, 1, 1, 1 }, { 0, 64, 64, 64, 64 },
      dfu_fma4pd_xmm_env, ARRAY_SIZE(dfu_fma4pd_xmm_env), true,
      "../target/i386/ops_sse.h:2536",
      NULL, 0 },
    { "fma4pd_ymm", { 0, 2, 1, 1, 1 }, { 0, 64, 64, 64, 64 },
      dfu_fma4pd_ymm_env, ARRAY_SIZE(dfu_fma4pd_ymm_env), true,
      "../target/i386/ops_sse.h:2536",
      NULL, 0 },
    { "fma4ps_xmm", { 0, 2, 1, 1, 1 }, { 0, 64, 64, 64, 64 },
      dfu_fma4ps_xmm_env, ARRAY_SIZE(dfu_fma4ps_xmm_env), true,
      "../target/i386/ops_sse.h:2535",
      NULL, 0 },
    { "fma4ps_ymm", { 0, 2, 1, 1, 1 }, { 0, 64, 64, 64, 64 },
      dfu_fma4ps_ymm_env, ARRAY_SIZE(dfu_fma4ps_ymm_env), true,
      "../target/i386/ops_sse.h:2535",
      NULL, 0 },
    { "fma4sd", { 0, 2, 1, 1, 1 }, { 0, 64, 64, 64, 64 },
      dfu_fma4sd_env, ARRAY_SIZE(dfu_fma4sd_env), true,
      "../target/i386/ops_sse.h:2531",
      NULL, 0 },
    { "fma4ss", { 0, 2, 1, 1, 1 }, { 0, 64, 64, 64, 64 },
      dfu_fma4ss_env, ARRAY_SIZE(dfu_fma4ss_env), true,
      "../target/i386/ops_sse.h:2530",
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
    { "fmul_STN_ST0", { 0 }, { 0 },
      dfu_fmul_STN_ST0_env, ARRAY_SIZE(dfu_fmul_STN_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:624",
      NULL, 0 },
    { "fninit", { 0 }, { 0 },
      dfu_fninit_env, ARRAY_SIZE(dfu_fninit_env), true,
      "../target/i386/tcg/fpu_helper.c:833",
      NULL, 0 },
    { "fnstcw", { 0 }, { 0 },
      dfu_fnstcw_env, ARRAY_SIZE(dfu_fnstcw_env), true,
      "../target/i386/tcg/fpu_helper.c:756",
      NULL, 0 },
    { "fnstsw", { 0 }, { 0 },
      dfu_fnstsw_env, ARRAY_SIZE(dfu_fnstsw_env), true,
      "../target/i386/tcg/fpu_helper.c:751",
      NULL, 0 },
    { "fpatan", { 0 }, { 0 },
      dfu_fpatan_env, ARRAY_SIZE(dfu_fpatan_env), true,
      "../target/i386/tcg/fpu_helper.c:1371",
      NULL, 0 },
    { "fpop", { 0 }, { 0 },
      dfu_fpop_env, ARRAY_SIZE(dfu_fpop_env), true,
      "../target/i386/tcg/fpu_helper.c:472",
      NULL, 0 },
    { "fprem", { 0 }, { 0 },
      dfu_fprem_env, ARRAY_SIZE(dfu_fprem_env), true,
      "../target/i386/tcg/fpu_helper.c:1915",
      NULL, 0 },
    { "fprem1", { 0 }, { 0 },
      dfu_fprem1_env, ARRAY_SIZE(dfu_fprem1_env), true,
      "../target/i386/tcg/fpu_helper.c:1910",
      NULL, 0 },
    { "fptan", { 0 }, { 0 },
      dfu_fptan_env, ARRAY_SIZE(dfu_fptan_env), true,
      "../target/i386/tcg/fpu_helper.c:1299",
      NULL, 0 },
    { "fpush", { 0 }, { 0 },
      dfu_fpush_env, ARRAY_SIZE(dfu_fpush_env), true,
      "../target/i386/tcg/fpu_helper.c:467",
      NULL, 0 },
    { "frndint", { 0 }, { 0 },
      dfu_frndint_env, ARRAY_SIZE(dfu_frndint_env), true,
      "../target/i386/tcg/fpu_helper.c:2326",
      NULL, 0 },
    { "frstor", { 0 }, { 0 },
      dfu_frstor_env, ARRAY_SIZE(dfu_frstor_env), true,
      "../target/i386/tcg/fpu_helper.c:2597",
      NULL, 0 },
    { "fsave", { 0 }, { 0 },
      dfu_fsave_env, ARRAY_SIZE(dfu_fsave_env), true,
      "../target/i386/tcg/fpu_helper.c:2574",
      NULL, 0 },
    { "fscale", { 0 }, { 0 },
      dfu_fscale_env, ARRAY_SIZE(dfu_fscale_env), true,
      "../target/i386/tcg/fpu_helper.c:2333",
      NULL, 0 },
    { "fsin", { 0 }, { 0 },
      dfu_fsin_env, ARRAY_SIZE(dfu_fsin_env), true,
      "../target/i386/tcg/fpu_helper.c:2384",
      NULL, 0 },
    { "fsincos", { 0 }, { 0 },
      dfu_fsincos_env, ARRAY_SIZE(dfu_fsincos_env), true,
      "../target/i386/tcg/fpu_helper.c:2311",
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
    { "fsub_ST0_FT0", { 0 }, { 0 },
      dfu_fsub_ST0_FT0_env, ARRAY_SIZE(dfu_fsub_ST0_FT0_env), true,
      "../target/i386/tcg/fpu_helper.c:591",
      NULL, 0 },
    { "fsub_STN_ST0", { 0 }, { 0 },
      dfu_fsub_STN_ST0_env, ARRAY_SIZE(dfu_fsub_STN_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:631",
      NULL, 0 },
    { "fsubr_ST0_FT0", { 0 }, { 0 },
      dfu_fsubr_ST0_FT0_env, ARRAY_SIZE(dfu_fsubr_ST0_FT0_env), true,
      "../target/i386/tcg/fpu_helper.c:598",
      NULL, 0 },
    { "fsubr_STN_ST0", { 0 }, { 0 },
      dfu_fsubr_STN_ST0_env, ARRAY_SIZE(dfu_fsubr_STN_ST0_env), true,
      "../target/i386/tcg/fpu_helper.c:638",
      NULL, 0 },
    { "fucom_ST0_FT0", { 0 }, { 0 },
      dfu_fucom_ST0_FT0_env, ARRAY_SIZE(dfu_fucom_ST0_FT0_env), true,
      "../target/i386/tcg/fpu_helper.c:539",
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
    { "fxrstor", { 0 }, { 0 },
      dfu_fxrstor_env, ARRAY_SIZE(dfu_fxrstor_env), true,
      "../target/i386/tcg/fpu_helper.c:2977",
      NULL, 0 },
    { "fxsave", { 0 }, { 0 },
      dfu_fxsave_env, ARRAY_SIZE(dfu_fxsave_env), true,
      "../target/i386/tcg/fpu_helper.c:2728",
      NULL, 0 },
    { "fxtract", { 0 }, { 0 },
      dfu_fxtract_env, ARRAY_SIZE(dfu_fxtract_env), true,
      "../target/i386/tcg/fpu_helper.c:1810",
      NULL, 0 },
    { "fyl2x", { 0 }, { 0 },
      dfu_fyl2x_env, ARRAY_SIZE(dfu_fyl2x_env), true,
      "../target/i386/tcg/fpu_helper.c:2153",
      NULL, 0 },
    { "fyl2xp1", { 0 }, { 0 },
      dfu_fyl2xp1_env, ARRAY_SIZE(dfu_fyl2xp1_env), true,
      "../target/i386/tcg/fpu_helper.c:2055",
      NULL, 0 },
    { "haddpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_haddpd_xmm_env, ARRAY_SIZE(dfu_haddpd_xmm_env), true,
      "../target/i386/ops_sse.h:979",
      NULL, 0 },
    { "haddpd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_haddpd_ymm_env, ARRAY_SIZE(dfu_haddpd_ymm_env), true,
      "../target/i386/ops_sse.h:979",
      NULL, 0 },
    { "haddps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_haddps_xmm_env, ARRAY_SIZE(dfu_haddps_xmm_env), true,
      "../target/i386/ops_sse.h:958",
      NULL, 0 },
    { "haddps_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_haddps_ymm_env, ARRAY_SIZE(dfu_haddps_ymm_env), true,
      "../target/i386/ops_sse.h:958",
      NULL, 0 },
    { "hsubpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_hsubpd_xmm_env, ARRAY_SIZE(dfu_hsubpd_xmm_env), true,
      "../target/i386/ops_sse.h:980",
      NULL, 0 },
    { "hsubpd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_hsubpd_ymm_env, ARRAY_SIZE(dfu_hsubpd_ymm_env), true,
      "../target/i386/ops_sse.h:980",
      NULL, 0 },
    { "hsubps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_hsubps_xmm_env, ARRAY_SIZE(dfu_hsubps_xmm_env), true,
      "../target/i386/ops_sse.h:959",
      NULL, 0 },
    { "hsubps_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_hsubps_ymm_env, ARRAY_SIZE(dfu_hsubps_ymm_env), true,
      "../target/i386/ops_sse.h:959",
      NULL, 0 },
    { "icebp", { 0 }, { 0 },
      dfu_icebp_env, ARRAY_SIZE(dfu_icebp_env), true,
      "../target/i386/tcg/excp_helper.c:161",
      NULL, 0 },
    { "idivb_AL", { 0 }, { 0 },
      dfu_idivb_AL_env, ARRAY_SIZE(dfu_idivb_AL_env), true,
      "../target/i386/tcg/int_helper.c:53",
      NULL, 0 },
    { "idivl_EAX", { 0 }, { 0 },
      dfu_idivl_EAX_env, ARRAY_SIZE(dfu_idivl_EAX_env), true,
      "../target/i386/tcg/int_helper.c:128",
      NULL, 0 },
    { "idivq_EAX", { 0 }, { 0 },
      dfu_idivq_EAX_env, ARRAY_SIZE(dfu_idivq_EAX_env), true,
      "../target/i386/tcg/int_helper.c:385",
      NULL, 0 },
    { "idivw_AX", { 0 }, { 0 },
      dfu_idivw_AX_env, ARRAY_SIZE(dfu_idivw_AX_env), true,
      "../target/i386/tcg/int_helper.c:90",
      NULL, 0 },
    { "insertq_i", { 0, 3, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:934",
      NULL, 0 },
    { "insertq_r", { 0, 3, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:929",
      NULL, 0 },
    { "iret_protected", { 0 }, { 0 },
      dfu_iret_protected_env, ARRAY_SIZE(dfu_iret_protected_env), true,
      "../target/i386/tcg/seg_helper.c:2272",
      dfu_iret_protected_acc, ARRAY_SIZE(dfu_iret_protected_acc) },
    { "lar", { 0 }, { 0 },
      dfu_lar_env, ARRAY_SIZE(dfu_lar_env), true,
      "../target/i386/tcg/seg_helper.c:2442",
      dfu_lar_acc, ARRAY_SIZE(dfu_lar_acc) },
    { "lcall_protected", { 0 }, { 0 },
      dfu_lcall_protected_env, ARRAY_SIZE(dfu_lcall_protected_env), true,
      "../target/i386/tcg/seg_helper.c:1662",
      dfu_lcall_protected_acc, ARRAY_SIZE(dfu_lcall_protected_acc) },
    { "ldmxcsr", { 0 }, { 0 },
      dfu_ldmxcsr_env, ARRAY_SIZE(dfu_ldmxcsr_env), true,
      "../target/i386/tcg/fpu_helper.c:3312",
      NULL, 0 },
    { "ljmp_protected", { 0 }, { 0 },
      dfu_ljmp_protected_env, ARRAY_SIZE(dfu_ljmp_protected_env), true,
      "../target/i386/tcg/seg_helper.c:1495",
      dfu_ljmp_protected_acc, ARRAY_SIZE(dfu_ljmp_protected_acc) },
    { "load_seg", { 0 }, { 0 },
      dfu_load_seg_env, ARRAY_SIZE(dfu_load_seg_env), true,
      "../target/i386/tcg/seg_helper.c:1407",
      dfu_load_seg_acc, ARRAY_SIZE(dfu_load_seg_acc) },
    { "lret_protected", { 0 }, { 0 },
      dfu_lret_protected_env, ARRAY_SIZE(dfu_lret_protected_env), true,
      "../target/i386/tcg/seg_helper.c:2303",
      dfu_lret_protected_acc, ARRAY_SIZE(dfu_lret_protected_acc) },
    { "lsl", { 0 }, { 0 },
      dfu_lsl_env, ARRAY_SIZE(dfu_lsl_env), true,
      "../target/i386/tcg/seg_helper.c:2394",
      dfu_lsl_acc, ARRAY_SIZE(dfu_lsl_acc) },
    { "maskmov_mmx", { 0, 1, 1 }, { 0, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:374",
      dfu_maskmov_mmx_acc, ARRAY_SIZE(dfu_maskmov_mmx_acc) },
    { "maskmov_xmm", { 0, 1, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:374",
      dfu_maskmov_xmm_acc, ARRAY_SIZE(dfu_maskmov_xmm_acc) },
    { "maxpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_maxpd_xmm_env, ARRAY_SIZE(dfu_maxpd_xmm_env), true,
      "../target/i386/ops_sse.h:534",
      NULL, 0 },
    { "maxpd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_maxpd_ymm_env, ARRAY_SIZE(dfu_maxpd_ymm_env), true,
      "../target/i386/ops_sse.h:534",
      NULL, 0 },
    { "maxps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_maxps_xmm_env, ARRAY_SIZE(dfu_maxps_xmm_env), true,
      "../target/i386/ops_sse.h:534",
      NULL, 0 },
    { "maxps_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_maxps_ymm_env, ARRAY_SIZE(dfu_maxps_ymm_env), true,
      "../target/i386/ops_sse.h:534",
      NULL, 0 },
    { "maxsd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_maxsd_env, ARRAY_SIZE(dfu_maxsd_env), true,
      "../target/i386/ops_sse.h:534",
      NULL, 0 },
    { "maxss", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_maxss_env, ARRAY_SIZE(dfu_maxss_env), true,
      "../target/i386/ops_sse.h:534",
      NULL, 0 },
    { "minpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_minpd_xmm_env, ARRAY_SIZE(dfu_minpd_xmm_env), true,
      "../target/i386/ops_sse.h:533",
      NULL, 0 },
    { "minpd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_minpd_ymm_env, ARRAY_SIZE(dfu_minpd_ymm_env), true,
      "../target/i386/ops_sse.h:533",
      NULL, 0 },
    { "minps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_minps_xmm_env, ARRAY_SIZE(dfu_minps_xmm_env), true,
      "../target/i386/ops_sse.h:533",
      NULL, 0 },
    { "minps_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_minps_ymm_env, ARRAY_SIZE(dfu_minps_ymm_env), true,
      "../target/i386/ops_sse.h:533",
      NULL, 0 },
    { "minsd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_minsd_env, ARRAY_SIZE(dfu_minsd_env), true,
      "../target/i386/ops_sse.h:533",
      NULL, 0 },
    { "minss", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_minss_env, ARRAY_SIZE(dfu_minss_env), true,
      "../target/i386/ops_sse.h:533",
      NULL, 0 },
    { "movmskpd_xmm", { 0, 1 }, { 0, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1167",
      NULL, 0 },
    { "movmskpd_ymm", { 0, 1 }, { 0, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1167",
      NULL, 0 },
    { "movmskps_xmm", { 0, 1 }, { 0, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1155",
      NULL, 0 },
    { "movmskps_ymm", { 0, 1 }, { 0, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1155",
      NULL, 0 },
    { "mpsadbw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1885",
      NULL, 0 },
    { "mulpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_mulpd_xmm_env, ARRAY_SIZE(dfu_mulpd_xmm_env), true,
      "../target/i386/ops_sse.h:531",
      NULL, 0 },
    { "mulpd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_mulpd_ymm_env, ARRAY_SIZE(dfu_mulpd_ymm_env), true,
      "../target/i386/ops_sse.h:531",
      NULL, 0 },
    { "mulps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_mulps_xmm_env, ARRAY_SIZE(dfu_mulps_xmm_env), true,
      "../target/i386/ops_sse.h:531",
      NULL, 0 },
    { "mulps_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_mulps_ymm_env, ARRAY_SIZE(dfu_mulps_ymm_env), true,
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
    { "packssdw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1203",
      NULL, 0 },
    { "packssdw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1203",
      NULL, 0 },
    { "packssdw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1203",
      NULL, 0 },
    { "packsswb_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1200",
      NULL, 0 },
    { "packsswb_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1200",
      NULL, 0 },
    { "packsswb_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1200",
      NULL, 0 },
    { "packusdw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1661",
      NULL, 0 },
    { "packusdw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1661",
      NULL, 0 },
    { "packuswb_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1201",
      NULL, 0 },
    { "packuswb_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1201",
      NULL, 0 },
    { "packuswb_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1201",
      NULL, 0 },
    { "palignr_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1541",
      NULL, 0 },
    { "palignr_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1541",
      NULL, 0 },
    { "pause", { 0 }, { 0 },
      dfu_pause_env, ARRAY_SIZE(dfu_pause_env), true,
      "../target/i386/tcg/misc_helper.c:92",
      NULL, 0 },
    { "pavgb_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:323",
      NULL, 0 },
    { "pavgb_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:323",
      NULL, 0 },
    { "pavgb_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:323",
      NULL, 0 },
    { "pavgw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:324",
      NULL, 0 },
    { "pavgw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:324",
      NULL, 0 },
    { "pavgw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:324",
      NULL, 0 },
    { "pblendvb_xmm", { 0, 2, 1, 1, 1 }, { 0, 64, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1604",
      NULL, 0 },
    { "pblendw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1818",
      NULL, 0 },
    { "pclmulqdq_xmm", { 0, 3, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2133",
      NULL, 0 },
    { "pcmpestri_xmm", { 0, 1, 1 }, { 0, 64, 64 },
      dfu_pcmpestri_xmm_env, ARRAY_SIZE(dfu_pcmpestri_xmm_env), true,
      "../target/i386/ops_sse.h:2041",
      NULL, 0 },
    { "pcmpestrm_xmm", { 0, 1, 1 }, { 0, 64, 64 },
      dfu_pcmpestrm_xmm_env, ARRAY_SIZE(dfu_pcmpestrm_xmm_env), true,
      "../target/i386/ops_sse.h:2055",
      NULL, 0 },
    { "pcmpistri_xmm", { 0, 1, 1 }, { 0, 64, 64 },
      dfu_pcmpistri_xmm_env, ARRAY_SIZE(dfu_pcmpistri_xmm_env), true,
      "../target/i386/ops_sse.h:2079",
      NULL, 0 },
    { "pcmpistrm_xmm", { 0, 1, 1 }, { 0, 64, 64 },
      dfu_pcmpistrm_xmm_env, ARRAY_SIZE(dfu_pcmpistrm_xmm_env), true,
      "../target/i386/ops_sse.h:2093",
      NULL, 0 },
    { "pdep", { 0 }, { 0 },
      NULL, 0, true,
      "../target/i386/tcg/int_helper.c:410",
      NULL, 0 },
    { "pext", { 0 }, { 0 },
      NULL, 0, true,
      "../target/i386/tcg/int_helper.c:423",
      NULL, 0 },
    { "phaddd_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1516",
      NULL, 0 },
    { "phaddd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1516",
      NULL, 0 },
    { "phaddd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1516",
      NULL, 0 },
    { "phaddsw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1514",
      NULL, 0 },
    { "phaddsw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1514",
      NULL, 0 },
    { "phaddsw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1514",
      NULL, 0 },
    { "phaddw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1512",
      NULL, 0 },
    { "phaddw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1512",
      NULL, 0 },
    { "phaddw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1512",
      NULL, 0 },
    { "phminposuw_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1682",
      NULL, 0 },
    { "phsubd_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1517",
      NULL, 0 },
    { "phsubd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1517",
      NULL, 0 },
    { "phsubd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1517",
      NULL, 0 },
    { "phsubsw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1515",
      NULL, 0 },
    { "phsubsw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1515",
      NULL, 0 },
    { "phsubsw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1515",
      NULL, 0 },
    { "phsubw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1513",
      NULL, 0 },
    { "phsubw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1513",
      NULL, 0 },
    { "phsubw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1513",
      NULL, 0 },
    { "pmaddubsw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1522",
      NULL, 0 },
    { "pmaddubsw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1522",
      NULL, 0 },
    { "pmaddubsw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1522",
      NULL, 0 },
    { "pmaddwd_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:335",
      NULL, 0 },
    { "pmaddwd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:335",
      NULL, 0 },
    { "pmaddwd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:335",
      NULL, 0 },
    { "pmovdldup_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1649",
      NULL, 0 },
    { "pmovdldup_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1649",
      NULL, 0 },
    { "pmovshdup_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1648",
      NULL, 0 },
    { "pmovshdup_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1648",
      NULL, 0 },
    { "pmovsldup_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1647",
      NULL, 0 },
    { "pmovsldup_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1647",
      NULL, 0 },
    { "pmovsxbd_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1636",
      NULL, 0 },
    { "pmovsxbd_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1636",
      NULL, 0 },
    { "pmovsxbq_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1637",
      NULL, 0 },
    { "pmovsxbq_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1637",
      NULL, 0 },
    { "pmovsxbw_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1635",
      NULL, 0 },
    { "pmovsxbw_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1635",
      NULL, 0 },
    { "pmovsxdq_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1640",
      NULL, 0 },
    { "pmovsxdq_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1640",
      NULL, 0 },
    { "pmovsxwd_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1638",
      NULL, 0 },
    { "pmovsxwd_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1638",
      NULL, 0 },
    { "pmovsxwq_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1639",
      NULL, 0 },
    { "pmovsxwq_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1639",
      NULL, 0 },
    { "pmovzxbd_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1642",
      NULL, 0 },
    { "pmovzxbd_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1642",
      NULL, 0 },
    { "pmovzxbq_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1643",
      NULL, 0 },
    { "pmovzxbq_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1643",
      NULL, 0 },
    { "pmovzxbw_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1641",
      NULL, 0 },
    { "pmovzxbw_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1641",
      NULL, 0 },
    { "pmovzxdq_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1646",
      NULL, 0 },
    { "pmovzxdq_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1646",
      NULL, 0 },
    { "pmovzxwd_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1644",
      NULL, 0 },
    { "pmovzxwd_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1644",
      NULL, 0 },
    { "pmovzxwq_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1645",
      NULL, 0 },
    { "pmovzxwq_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1645",
      NULL, 0 },
    { "pmuldq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1652",
      NULL, 0 },
    { "pmuldq_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1652",
      NULL, 0 },
    { "pmulhrsw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1532",
      NULL, 0 },
    { "pmulhrsw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1532",
      NULL, 0 },
    { "pmulhuw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:310",
      NULL, 0 },
    { "pmulhuw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:310",
      NULL, 0 },
    { "pmulhuw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:310",
      NULL, 0 },
    { "pmulhw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:311",
      NULL, 0 },
    { "pmulhw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:311",
      NULL, 0 },
    { "pmulhw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:311",
      NULL, 0 },
    { "pmuludq_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:326",
      NULL, 0 },
    { "pmuludq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:326",
      NULL, 0 },
    { "pmuludq_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:326",
      NULL, 0 },
    { "psadbw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:355",
      NULL, 0 },
    { "psadbw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:355",
      NULL, 0 },
    { "psadbw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:355",
      NULL, 0 },
    { "pshufb_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1451",
      NULL, 0 },
    { "pshufb_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1451",
      NULL, 0 },
    { "pshufb_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1451",
      NULL, 0 },
    { "pshufd_xmm", { 2, 1 }, { 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:430",
      NULL, 0 },
    { "pshufd_ymm", { 2, 1 }, { 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:430",
      NULL, 0 },
    { "pshufhw_xmm", { 2, 1 }, { 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:451",
      NULL, 0 },
    { "pshufhw_ymm", { 2, 1 }, { 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:451",
      NULL, 0 },
    { "pshuflw_xmm", { 2, 1 }, { 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:440",
      NULL, 0 },
    { "pshuflw_ymm", { 2, 1 }, { 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:440",
      NULL, 0 },
    { "pshufw_mmx", { 2, 1 }, { 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:399",
      NULL, 0 },
    { "psignb_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1537",
      NULL, 0 },
    { "psignb_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1537",
      NULL, 0 },
    { "psignb_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1537",
      NULL, 0 },
    { "psignd_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1539",
      NULL, 0 },
    { "psignd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1539",
      NULL, 0 },
    { "psignw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1538",
      NULL, 0 },
    { "psignw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1538",
      NULL, 0 },
    { "psignw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1538",
      NULL, 0 },
    { "pslld_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:116",
      NULL, 0 },
    { "pslld_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:116",
      NULL, 0 },
    { "pslld_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:116",
      NULL, 0 },
    { "pslldq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:193",
      NULL, 0 },
    { "pslldq_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:193",
      NULL, 0 },
    { "psllq_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:159",
      NULL, 0 },
    { "psllq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:159",
      NULL, 0 },
    { "psllq_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:159",
      NULL, 0 },
    { "psllw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:73",
      NULL, 0 },
    { "psllw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:73",
      NULL, 0 },
    { "psllw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:73",
      NULL, 0 },
    { "psrad_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:131",
      NULL, 0 },
    { "psrad_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:131",
      NULL, 0 },
    { "psrad_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:131",
      NULL, 0 },
    { "psraw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:88",
      NULL, 0 },
    { "psraw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:88",
      NULL, 0 },
    { "psraw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:88",
      NULL, 0 },
    { "psrld_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:101",
      NULL, 0 },
    { "psrld_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:101",
      NULL, 0 },
    { "psrld_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:101",
      NULL, 0 },
    { "psrldq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:175",
      NULL, 0 },
    { "psrldq_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:175",
      NULL, 0 },
    { "psrlq_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:144",
      NULL, 0 },
    { "psrlq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:144",
      NULL, 0 },
    { "psrlw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:58",
      NULL, 0 },
    { "psrlw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:58",
      NULL, 0 },
    { "psrlw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:58",
      NULL, 0 },
    { "ptest_xmm", { 0, 3, 1 }, { 0, 64, 64 },
      dfu_ptest_xmm_env, ARRAY_SIZE(dfu_ptest_xmm_env), true,
      "../target/i386/ops_sse.h:1608",
      NULL, 0 },
    { "punpckhbw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1294",
      NULL, 0 },
    { "punpckhbw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1294",
      NULL, 0 },
    { "punpckhbw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1294",
      NULL, 0 },
    { "punpckhdq_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1294",
      NULL, 0 },
    { "punpckhdq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1294",
      NULL, 0 },
    { "punpckhdq_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1294",
      NULL, 0 },
    { "punpckhqdq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1294",
      NULL, 0 },
    { "punpckhqdq_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1294",
      NULL, 0 },
    { "punpckhwd_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1294",
      NULL, 0 },
    { "punpckhwd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1294",
      NULL, 0 },
    { "punpckhwd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1294",
      NULL, 0 },
    { "punpcklbw_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "punpcklbw_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "punpcklbw_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "punpckldq_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "punpckldq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "punpckldq_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "punpcklqdq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "punpcklqdq_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "punpcklwd_mmx", { 0, 2, 1, 1 }, { 0, 8, 8, 8 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "punpcklwd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "punpcklwd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:1293",
      NULL, 0 },
    { "raise_exception", { 0 }, { 0 },
      dfu_raise_exception_env, ARRAY_SIZE(dfu_raise_exception_env), true,
      "../target/i386/tcg/excp_helper.c:35",
      NULL, 0 },
    { "raise_interrupt", { 0 }, { 0 },
      dfu_raise_interrupt_env, ARRAY_SIZE(dfu_raise_interrupt_env), true,
      "../target/i386/tcg/excp_helper.c:29",
      NULL, 0 },
    { "rcpps_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_rcpps_xmm_env, ARRAY_SIZE(dfu_rcpps_xmm_env), true,
      "../target/i386/ops_sse.h:871",
      NULL, 0 },
    { "rcpps_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_rcpps_ymm_env, ARRAY_SIZE(dfu_rcpps_ymm_env), true,
      "../target/i386/ops_sse.h:871",
      NULL, 0 },
    { "rcpss", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_rcpss_env, ARRAY_SIZE(dfu_rcpss_env), true,
      "../target/i386/ops_sse.h:882",
      NULL, 0 },
    { "rdpid", { 0 }, { 0 },
      NULL, 0, true,
      "../target/i386/tcg/misc_helper.c:132",
      NULL, 0 },
    { "rdpkru", { 0 }, { 0 },
      dfu_rdpkru_env, ARRAY_SIZE(dfu_rdpkru_env), true,
      "../target/i386/tcg/misc_helper.c:105",
      NULL, 0 },
    { "rdpmc", { 0 }, { 0 },
      dfu_rdpmc_env, ARRAY_SIZE(dfu_rdpmc_env), true,
      "../target/i386/tcg/misc_helper.c:79",
      NULL, 0 },
    { "rdrand", { 0 }, { 0 },
      dfu_rdrand_env, ARRAY_SIZE(dfu_rdrand_env), true,
      "../target/i386/tcg/int_helper.c:446",
      NULL, 0 },
    { "read_eflags", { 0 }, { 0 },
      dfu_read_eflags_env, ARRAY_SIZE(dfu_read_eflags_env), true,
      "../target/i386/tcg/cc_helper.c:328",
      NULL, 0 },
    { "rechecking_single_step", { 0 }, { 0 },
      dfu_rechecking_single_step_env, ARRAY_SIZE(dfu_rechecking_single_step_env), true,
      "../target/i386/tcg/bpt_helper.c:35",
      NULL, 0 },
    { "roundpd_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_roundpd_xmm_env, ARRAY_SIZE(dfu_roundpd_xmm_env), true,
      "../target/i386/ops_sse.h:1739",
      NULL, 0 },
    { "roundpd_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_roundpd_ymm_env, ARRAY_SIZE(dfu_roundpd_ymm_env), true,
      "../target/i386/ops_sse.h:1739",
      NULL, 0 },
    { "roundps_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_roundps_xmm_env, ARRAY_SIZE(dfu_roundps_xmm_env), true,
      "../target/i386/ops_sse.h:1715",
      NULL, 0 },
    { "roundps_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_roundps_ymm_env, ARRAY_SIZE(dfu_roundps_ymm_env), true,
      "../target/i386/ops_sse.h:1715",
      NULL, 0 },
    { "roundsd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_roundsd_xmm_env, ARRAY_SIZE(dfu_roundsd_xmm_env), true,
      "../target/i386/ops_sse.h:1789",
      NULL, 0 },
    { "roundss_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_roundss_xmm_env, ARRAY_SIZE(dfu_roundss_xmm_env), true,
      "../target/i386/ops_sse.h:1764",
      NULL, 0 },
    { "rsqrtps_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_rsqrtps_xmm_env, ARRAY_SIZE(dfu_rsqrtps_xmm_env), true,
      "../target/i386/ops_sse.h:844",
      NULL, 0 },
    { "rsqrtps_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_rsqrtps_ymm_env, ARRAY_SIZE(dfu_rsqrtps_ymm_env), true,
      "../target/i386/ops_sse.h:844",
      NULL, 0 },
    { "rsqrtss", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_rsqrtss_env, ARRAY_SIZE(dfu_rsqrtss_env), true,
      "../target/i386/ops_sse.h:857",
      NULL, 0 },
    { "sha1msg1", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2583",
      NULL, 0 },
    { "sha1msg2", { 3, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2595",
      NULL, 0 },
    { "sha1nexte", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2575",
      NULL, 0 },
    { "sha1rnds4_f0", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2570",
      NULL, 0 },
    { "sha1rnds4_f1", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2571",
      NULL, 0 },
    { "sha1rnds4_f2", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2572",
      NULL, 0 },
    { "sha256msg1", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2645",
      NULL, 0 },
    { "sha256msg2", { 3, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2656",
      NULL, 0 },
    { "sha256rnds2", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2611",
      NULL, 0 },
    { "shufpd_xmm", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:416",
      NULL, 0 },
    { "shufpd_ymm", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:416",
      NULL, 0 },
    { "shufps_xmm", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:406",
      NULL, 0 },
    { "shufps_ymm", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:406",
      NULL, 0 },
    { "sqrtpd_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_sqrtpd_xmm_env, ARRAY_SIZE(dfu_sqrtpd_xmm_env), true,
      "../target/i386/ops_sse.h:544",
      NULL, 0 },
    { "sqrtpd_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_sqrtpd_ymm_env, ARRAY_SIZE(dfu_sqrtpd_ymm_env), true,
      "../target/i386/ops_sse.h:544",
      NULL, 0 },
    { "sqrtps_xmm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_sqrtps_xmm_env, ARRAY_SIZE(dfu_sqrtps_xmm_env), true,
      "../target/i386/ops_sse.h:536",
      NULL, 0 },
    { "sqrtps_ymm", { 0, 2, 1 }, { 0, 64, 64 },
      dfu_sqrtps_ymm_env, ARRAY_SIZE(dfu_sqrtps_ymm_env), true,
      "../target/i386/ops_sse.h:536",
      NULL, 0 },
    { "sqrtsd", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_sqrtsd_env, ARRAY_SIZE(dfu_sqrtsd_env), true,
      "../target/i386/ops_sse.h:562",
      NULL, 0 },
    { "sqrtss", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_sqrtss_env, ARRAY_SIZE(dfu_sqrtss_env), true,
      "../target/i386/ops_sse.h:553",
      NULL, 0 },
    { "subpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_subpd_xmm_env, ARRAY_SIZE(dfu_subpd_xmm_env), true,
      "../target/i386/ops_sse.h:530",
      NULL, 0 },
    { "subpd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_subpd_ymm_env, ARRAY_SIZE(dfu_subpd_ymm_env), true,
      "../target/i386/ops_sse.h:530",
      NULL, 0 },
    { "subps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_subps_xmm_env, ARRAY_SIZE(dfu_subps_xmm_env), true,
      "../target/i386/ops_sse.h:530",
      NULL, 0 },
    { "subps_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      dfu_subps_ymm_env, ARRAY_SIZE(dfu_subps_ymm_env), true,
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
    { "ucomiss", { 0, 1, 1 }, { 0, 64, 64 },
      dfu_ucomiss_env, ARRAY_SIZE(dfu_ucomiss_env), true,
      "../target/i386/ops_sse.h:1106",
      NULL, 0 },
    { "update_mxcsr", { 0 }, { 0 },
      dfu_update_mxcsr_env, ARRAY_SIZE(dfu_update_mxcsr_env), true,
      "../target/i386/tcg/fpu_helper.c:3307",
      NULL, 0 },
    { "verr", { 0 }, { 0 },
      dfu_verr_env, ARRAY_SIZE(dfu_verr_env), true,
      "../target/i386/tcg/seg_helper.c:2491",
      dfu_verr_acc, ARRAY_SIZE(dfu_verr_acc) },
    { "verw", { 0 }, { 0 },
      dfu_verw_env, ARRAY_SIZE(dfu_verw_env), true,
      "../target/i386/tcg/seg_helper.c:2529",
      dfu_verw_acc, ARRAY_SIZE(dfu_verw_acc) },
    { "vpermd_ymm", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2498",
      NULL, 0 },
    { "vpermdq_ymm", { 2, 1, 1 }, { 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2427",
      NULL, 0 },
    { "vpermilpd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2218",
      NULL, 0 },
    { "vpermilps_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2231",
      NULL, 0 },
    { "vpermq_ymm", { 2, 1 }, { 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2485",
      NULL, 0 },
    { "vpgatherdd_xmm", { 0, 2, 3, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2365",
      dfu_vpgatherdd_xmm_acc, ARRAY_SIZE(dfu_vpgatherdd_xmm_acc) },
    { "vpgatherdd_ymm", { 0, 2, 3, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2365",
      dfu_vpgatherdd_ymm_acc, ARRAY_SIZE(dfu_vpgatherdd_ymm_acc) },
    { "vpgatherdq_xmm", { 0, 2, 3, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2379",
      dfu_vpgatherdq_xmm_acc, ARRAY_SIZE(dfu_vpgatherdq_xmm_acc) },
    { "vpgatherdq_ymm", { 0, 2, 3, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2379",
      dfu_vpgatherdq_ymm_acc, ARRAY_SIZE(dfu_vpgatherdq_ymm_acc) },
    { "vpgatherqd_xmm", { 0, 2, 3, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2393",
      dfu_vpgatherqd_xmm_acc, ARRAY_SIZE(dfu_vpgatherqd_xmm_acc) },
    { "vpgatherqd_ymm", { 0, 2, 3, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2393",
      dfu_vpgatherqd_ymm_acc, ARRAY_SIZE(dfu_vpgatherqd_ymm_acc) },
    { "vpgatherqq_xmm", { 0, 2, 3, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2411",
      dfu_vpgatherqq_xmm_acc, ARRAY_SIZE(dfu_vpgatherqq_xmm_acc) },
    { "vpgatherqq_ymm", { 0, 2, 3, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2411",
      dfu_vpgatherqq_ymm_acc, ARRAY_SIZE(dfu_vpgatherqq_ymm_acc) },
    { "vpmaskmovd_st_xmm", { 0, 1, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2323",
      dfu_vpmaskmovd_st_xmm_acc, ARRAY_SIZE(dfu_vpmaskmovd_st_xmm_acc) },
    { "vpmaskmovd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2347",
      NULL, 0 },
    { "vpmaskmovd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2347",
      NULL, 0 },
    { "vpmaskmovq_st_xmm", { 0, 1, 1 }, { 0, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2335",
      dfu_vpmaskmovq_st_xmm_acc, ARRAY_SIZE(dfu_vpmaskmovq_st_xmm_acc) },
    { "vpmaskmovq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2356",
      NULL, 0 },
    { "vpmaskmovq_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2356",
      NULL, 0 },
    { "vpsllvd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2291",
      NULL, 0 },
    { "vpsllvd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2291",
      NULL, 0 },
    { "vpsllvq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2295",
      NULL, 0 },
    { "vpsllvq_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2295",
      NULL, 0 },
    { "vpsravd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2290",
      NULL, 0 },
    { "vpsravd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2290",
      NULL, 0 },
    { "vpsrlvd_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2289",
      NULL, 0 },
    { "vpsrlvd_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2289",
      NULL, 0 },
    { "vpsrlvq_xmm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2293",
      NULL, 0 },
    { "vpsrlvq_ymm", { 0, 2, 1, 1 }, { 0, 64, 64, 64 },
      NULL, 0, true,
      "../target/i386/ops_sse.h:2293",
      NULL, 0 },
    { "vtestpd_xmm", { 0, 3, 1 }, { 0, 64, 64 },
      dfu_vtestpd_xmm_env, ARRAY_SIZE(dfu_vtestpd_xmm_env), true,
      "../target/i386/ops_sse.h:2310",
      NULL, 0 },
    { "vtestps_xmm", { 0, 3, 1 }, { 0, 64, 64 },
      dfu_vtestps_xmm_env, ARRAY_SIZE(dfu_vtestps_xmm_env), true,
      "../target/i386/ops_sse.h:2297",
      NULL, 0 },
    { "write_eflags", { 0 }, { 0 },
      dfu_write_eflags_env, ARRAY_SIZE(dfu_write_eflags_env), true,
      "../target/i386/tcg/cc_helper.c:322",
      NULL, 0 },
    { "wrpkru", { 0 }, { 0 },
      dfu_wrpkru_env, ARRAY_SIZE(dfu_wrpkru_env), true,
      "../target/i386/tcg/misc_helper.c:117",
      NULL, 0 },
    { "xgetbv", { 0 }, { 0 },
      dfu_xgetbv_env, ARRAY_SIZE(dfu_xgetbv_env), true,
      "../target/i386/tcg/fpu_helper.c:3195",
      NULL, 0 },
    { "xrstor", { 0 }, { 0 },
      dfu_xrstor_env, ARRAY_SIZE(dfu_xrstor_env), true,
      "../target/i386/tcg/fpu_helper.c:3079",
      NULL, 0 },
    { "xsave", { 0 }, { 0 },
      dfu_xsave_env, ARRAY_SIZE(dfu_xsave_env), true,
      "../target/i386/tcg/fpu_helper.c:2821",
      NULL, 0 },
    { "lookup_tb_ptr", { 0 }, { 0 },
      dfu_lookup_tb_ptr_env, ARRAY_SIZE(dfu_lookup_tb_ptr_env), true,
      "accel/tcg/cpu-exec.c HELPER(lookup_tb_ptr)",
      NULL, 0 },
    { NULL, { 0 }, { 0 }, NULL, 0, false, NULL, NULL, 0 }
};
