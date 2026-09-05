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
 * Every field name was accepted on EVERY configured target that
 * compiles this file (they define TARGET_ARM): aarch64-linux-user, aarch64-softmmu, aarch64_be-linux-user, arm-linux-user, arm-softmmu, armeb-linux-user.
 *
 * Rows emitted under a DERIVED guard -- the field is a member on
 * only part of that family, and the macro named is the one whose
 * truth set over the family is exactly the set that has it:
 *   autda                  defined(TARGET_AARCH64)    keys.apda
 *   autda_combined         defined(TARGET_AARCH64)    keys.apda
 *   autdb                  defined(TARGET_AARCH64)    keys.apdb
 *   autdb_combined         defined(TARGET_AARCH64)    keys.apdb
 *   autia                  defined(TARGET_AARCH64)    keys.apia
 *   autia_combined         defined(TARGET_AARCH64)    keys.apia
 *   autib                  defined(TARGET_AARCH64)    keys.apib
 *   autib_combined         defined(TARGET_AARCH64)    keys.apib
 *   pacda                  defined(TARGET_AARCH64)    keys.apda
 *   pacdb                  defined(TARGET_AARCH64)    keys.apdb
 *   pacga                  defined(TARGET_AARCH64)    keys.apga
 *   pacia                  defined(TARGET_AARCH64)    keys.apia
 *   pacib                  defined(TARGET_AARCH64)    keys.apib
 *   set_svcr               defined(TARGET_AARCH64)    vfp.pregs,zarray
 *   sve_ldff1bds_r         defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldff1dd_le_r       defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldff1hds_le_r      defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldff1sds_le_r      defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldffbss_zsu        defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldffbsu_zsu        defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldffdd_le_zd       defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldffhss_le_zsu     defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldffhsu_le_zsu     defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldffsds_le_zd      defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldffsds_le_zsu     defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldffss_le_zsu      defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldnf1bb_r          defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldnf1bds_r         defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldnf1dd_le_r       defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldnf1hds_le_r      defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldnf1hh_le_r       defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldnf1sds_le_r      defined(TARGET_AARCH64)    vfp.pregs[16].p
 *   sve_ldnf1ss_le_r       defined(TARGET_AARCH64)    vfp.pregs[16].p
 *
 * CP1 -- helpers that perform GUEST MEMORY ACCESSES themselves.
 * No qemu_ld/qemu_st op names these: the access happens inside
 * the call, so without the row below QEMU's access list is SHORT
 * for the instruction that called the helper.  Direction and the
 * ADDRESS ARGUMENT are read off the call site; a count is NOT
 * invented when the helper's access pattern is data-dependent.
 *   cpye                 read  addr=UNSTATED data=-    count unbounded
 *   cpye                 write addr=UNSTATED data=-    count unbounded
 *   cpyfe                read  addr=UNSTATED data=-    count unbounded
 *   cpyfe                write addr=UNSTATED data=-    count unbounded
 *   cpyfm                read  addr=UNSTATED data=-    count unbounded
 *   cpyfm                write addr=UNSTATED data=-    count unbounded
 *   cpyfp                read  addr=UNSTATED data=-    count unbounded
 *   cpyfp                write addr=UNSTATED data=-    count unbounded
 *   cpym                 read  addr=UNSTATED data=-    count unbounded
 *   cpym                 write addr=UNSTATED data=-    count unbounded
 *   cpyp                 read  addr=UNSTATED data=-    count unbounded
 *   cpyp                 write addr=UNSTATED data=-    count unbounded
 *   dc_zva               write addr=UNSTATED data=-    one access
 *   sete                 write addr=UNSTATED data=-    count unbounded
 *   setge                write addr=UNSTATED data=-    one access
 *   setgm                write addr=UNSTATED data=-    one access
 *   setgp                write addr=UNSTATED data=-    one access
 *   setm                 write addr=UNSTATED data=-    count unbounded
 *   setp                 write addr=UNSTATED data=-    count unbounded
 *   sve_ld1bb_r          read  addr=UNSTATED data=-    one access
 *   sve_ld1bds_r         read  addr=UNSTATED data=-    one access
 *   sve_ld1dd_le_r       read  addr=UNSTATED data=-    one access
 *   sve_ld1hds_le_r      read  addr=UNSTATED data=-    one access
 *   sve_ld1hh_le_r       read  addr=UNSTATED data=-    one access
 *   sve_ld1sds_le_r      read  addr=UNSTATED data=-    one access
 *   sve_ld1ss_le_r       read  addr=UNSTATED data=-    one access
 *   sve_ld2bb_r          read  addr=UNSTATED data=-    one access
 *   sve_ld2dd_le_r       read  addr=UNSTATED data=-    one access
 *   sve_ld2hh_le_r       read  addr=UNSTATED data=-    one access
 *   sve_ld2ss_le_r       read  addr=UNSTATED data=-    one access
 *   sve_ld3bb_r          read  addr=UNSTATED data=-    one access
 *   sve_ld3dd_le_r       read  addr=UNSTATED data=-    one access
 *   sve_ld3hh_le_r       read  addr=UNSTATED data=-    one access
 *   sve_ld3ss_le_r       read  addr=UNSTATED data=-    one access
 *   sve_ld4bb_r          read  addr=UNSTATED data=-    one access
 *   sve_ld4dd_le_r       read  addr=UNSTATED data=-    one access
 *   sve_ld4hh_le_r       read  addr=UNSTATED data=-    one access
 *   sve_ld4ss_le_r       read  addr=UNSTATED data=-    one access
 *   sve_ldbss_zsu        read  addr=UNSTATED data=-    one access
 *   sve_ldbsu_zsu        read  addr=UNSTATED data=-    one access
 *   sve_lddd_le_zd       read  addr=UNSTATED data=-    one access
 *   sve_ldff1bds_r       read  addr=UNSTATED data=-    one access
 *   sve_ldff1dd_le_r     read  addr=UNSTATED data=-    one access
 *   sve_ldff1hds_le_r    read  addr=UNSTATED data=-    one access
 *   sve_ldff1sds_le_r    read  addr=UNSTATED data=-    one access
 *   sve_ldffbss_zsu      read  addr=UNSTATED data=-    one access
 *   sve_ldffbsu_zsu      read  addr=UNSTATED data=-    one access
 *   sve_ldffdd_le_zd     read  addr=UNSTATED data=-    one access
 *   sve_ldffhss_le_zsu   read  addr=UNSTATED data=-    one access
 *   sve_ldffhsu_le_zsu   read  addr=UNSTATED data=-    one access
 *   sve_ldffsds_le_zd    read  addr=UNSTATED data=-    one access
 *   sve_ldffsds_le_zsu   read  addr=UNSTATED data=-    one access
 *   sve_ldffss_le_zsu    read  addr=UNSTATED data=-    one access
 *   sve_ldhss_le_zsu     read  addr=UNSTATED data=-    one access
 *   sve_ldhsu_le_zsu     read  addr=UNSTATED data=-    one access
 *   sve_ldnf1bb_r        read  addr=UNSTATED data=-    one access
 *   sve_ldnf1bds_r       read  addr=UNSTATED data=-    one access
 *   sve_ldnf1dd_le_r     read  addr=UNSTATED data=-    one access
 *   sve_ldnf1hds_le_r    read  addr=UNSTATED data=-    one access
 *   sve_ldnf1hh_le_r     read  addr=UNSTATED data=-    one access
 *   sve_ldnf1sds_le_r    read  addr=UNSTATED data=-    one access
 *   sve_ldnf1ss_le_r     read  addr=UNSTATED data=-    one access
 *   sve_ldsds_le_zd      read  addr=UNSTATED data=-    one access
 *   sve_ldsds_le_zsu     read  addr=UNSTATED data=-    one access
 *   sve_ldss_le_zsu      read  addr=UNSTATED data=-    one access
 *   sve_st1bb_r          write addr=UNSTATED data=-    one access
 *   sve_st1hh_le_r       write addr=UNSTATED data=-    one access
 *   sve_st1ss_le_r       write addr=UNSTATED data=-    one access
 *   sve_st2bb_r          write addr=UNSTATED data=-    one access
 *   sve_st2dd_le_r       write addr=UNSTATED data=-    one access
 *   sve_st2hh_le_r       write addr=UNSTATED data=-    one access
 *   sve_st2ss_le_r       write addr=UNSTATED data=-    one access
 *   sve_st3bb_r          write addr=UNSTATED data=-    one access
 *   sve_st3dd_le_r       write addr=UNSTATED data=-    one access
 *   sve_st3hh_le_r       write addr=UNSTATED data=-    one access
 *   sve_st3ss_le_r       write addr=UNSTATED data=-    one access
 *   sve_st4bb_r          write addr=UNSTATED data=-    one access
 *   sve_st4dd_le_r       write addr=UNSTATED data=-    one access
 *   sve_st4hh_le_r       write addr=UNSTATED data=-    one access
 *   sve_st4ss_le_r       write addr=UNSTATED data=-    one access
 *   sve_stbd_zd          write addr=UNSTATED data=-    one access
 *   sve_stdd_le_zd       write addr=UNSTATED data=-    one access
 *   sve_stsd_le_zd       write addr=UNSTATED data=-    one access
 *
 * READS THE EMULATOR MAKES ON ITS OWN BEHALF -- derived,
 * enumerated, and marked DF_HF_XLAT so the footprint is complete
 * and the OPERAND set is not.  Selected by the SOURCE LINE the
 * reader read the member off, never by helper name, so a sibling
 * reaching the same line is covered the day it is derived:
 *   guarded_page_check       pc       ../target/arm/tcg/helper-a64.c:2555
 *   pc @ ../target/arm/tcg/helper-a64.c:2555:
 *     the BTI guarded-page check -- `is_guarded_page(env, env->pc, 0)`,
 *     an MMU_INST_FETCH probe of the attributes of the page the
 *     instruction was FETCHED from. QEMU's own comment says the value is
 *     the block's start address and is up to date for exactly that
 *     reason. No instruction records reading its own encoding, and this
 *     is that read
 *
 * THE TRANSLATION KEY, RECOMPUTED.  A helper whose ONLY
 * CPUArchState write is the cached TB-lookup key has computed
 * that key and nothing the guest can observe, so its WHOLE
 * footprint is the emulator's own and is marked DF_HF_XLAT --
 * enumerated so the row still accounts for it, not published
 * because the wire carries operands.  Selected by the WRITE SET,
 * never by helper name:
 *   rebuild_hflags_a64       writes only hflags; 29 member(s) not published
 *
 * Rows refused, and therefore still OVER-APPROXIMATED at run time:
 *   access_check_cp_reg      env passed to accessfn(), not defined in this unit
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

static const DfHelperField dfu_addsubg_env[] = {
    { offsetof(CPUArchState, cp15.gcr_el1), sizeof(((CPUArchState *)0)->cp15.gcr_el1), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:289 */
};
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_autda_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/helper.c:11274, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys.apda), sizeof(((CPUArchState *)0)->keys.apda), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/pauth_helper.c:591 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_autda_combined_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/helper.c:11274, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys.apda), sizeof(((CPUArchState *)0)->keys.apda), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/pauth_helper.c:591 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_autdb_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/helper.c:11274, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys.apdb), sizeof(((CPUArchState *)0)->keys.apdb), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/pauth_helper.c:612 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_autdb_combined_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/helper.c:11274, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys.apdb), sizeof(((CPUArchState *)0)->keys.apdb), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/pauth_helper.c:612 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_autia_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/helper.c:11274, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys.apia), sizeof(((CPUArchState *)0)->keys.apia), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/pauth_helper.c:549 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_autia_combined_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/helper.c:11274, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys.apia), sizeof(((CPUArchState *)0)->keys.apia), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/pauth_helper.c:549 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_autib_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/helper.c:11274, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys.apib), sizeof(((CPUArchState *)0)->keys.apib), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/pauth_helper.c:570 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_autib_combined_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/helper.c:11274, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys.apib), sizeof(((CPUArchState *)0)->keys.apib), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/pauth_helper.c:570 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#endif
static const DfHelperField dfu_cpye_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1462 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.hcrx_el2), sizeof(((CPUArchState *)0)->cp15.hcrx_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5820 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.sctlr_el[1]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1417 */
    { offsetof(CPUArchState, cp15.sctlr_el[2]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1419 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/helper-a64.c:2454, INDEX NOT STATED */
};
static const DfHelperField dfu_cpyfe_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1462 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.hcrx_el2), sizeof(((CPUArchState *)0)->cp15.hcrx_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5820 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.sctlr_el[1]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1417 */
    { offsetof(CPUArchState, cp15.sctlr_el[2]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1419 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/helper-a64.c:2454, INDEX NOT STATED */
};
static const DfHelperField dfu_cpyfm_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1462 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.hcrx_el2), sizeof(((CPUArchState *)0)->cp15.hcrx_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5820 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.sctlr_el[1]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1417 */
    { offsetof(CPUArchState, cp15.sctlr_el[2]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1419 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/helper-a64.c:2357, INDEX NOT STATED */
};
static const DfHelperField dfu_cpyfp_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:2324 */
    { offsetof(CPUArchState, NF), sizeof(((CPUArchState *)0)->NF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:2322 */
    { offsetof(CPUArchState, VF), sizeof(((CPUArchState *)0)->VF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:2325 */
    { offsetof(CPUArchState, ZF), sizeof(((CPUArchState *)0)->ZF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:2323 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.hcrx_el2), sizeof(((CPUArchState *)0)->cp15.hcrx_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5820 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.sctlr_el[1]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1417 */
    { offsetof(CPUArchState, cp15.sctlr_el[2]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1419 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/helper-a64.c:2236, INDEX NOT STATED */
};
static const DfHelperField dfu_cpym_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1462 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.hcrx_el2), sizeof(((CPUArchState *)0)->cp15.hcrx_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5820 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.sctlr_el[1]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1417 */
    { offsetof(CPUArchState, cp15.sctlr_el[2]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1419 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/helper-a64.c:2357, INDEX NOT STATED */
};
static const DfHelperField dfu_cpyp_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:2324 */
    { offsetof(CPUArchState, NF), sizeof(((CPUArchState *)0)->NF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:2322 */
    { offsetof(CPUArchState, VF), sizeof(((CPUArchState *)0)->VF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:2325 */
    { offsetof(CPUArchState, ZF), sizeof(((CPUArchState *)0)->ZF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:2323 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.hcrx_el2), sizeof(((CPUArchState *)0)->cp15.hcrx_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5820 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.sctlr_el[1]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1417 */
    { offsetof(CPUArchState, cp15.sctlr_el[2]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1419 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/helper-a64.c:2236, INDEX NOT STATED */
};
static const DfHelperField dfu_dc_zva_env[] = {
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
};
static const DfHelperField dfu_exception_bkpt_insn_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/debug_helper.c:453, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/debug_helper.c:31 */
    { offsetof(CPUArchState, cp15.mdcr_el2), sizeof(((CPUArchState *)0)->cp15.mdcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/debug_helper.c:32 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.fsr), sizeof(((CPUArchState *)0)->exception.fsr), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/debug_helper.c:522 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/debug_helper.c:528 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
static const DfHelperField dfu_exception_with_syndrome_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5631 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
static const DfHelperField dfu_guarded_page_br_env[] = {
    { offsetof(CPUArchState, btype), sizeof(((CPUArchState *)0)->btype), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:2567 */
};
static const DfHelperField dfu_guarded_page_check_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, btype), sizeof(((CPUArchState *)0)->btype), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:2556 */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5631 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pc), sizeof(((CPUArchState *)0)->pc), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/tcg/helper-a64.c:2555 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
static const DfHelperField dfu_gvec_bfdot_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/vec_helper.c:2959, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.fpcr), sizeof(((CPUArchState *)0)->vfp.fpcr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vec_helper.c:2957 */
};
static const DfHelperField dfu_gvec_bfdot_idx_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/vec_helper.c:2959, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.fpcr), sizeof(((CPUArchState *)0)->vfp.fpcr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vec_helper.c:2957 */
};
static const DfHelperField dfu_gvec_bfmmla_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/vec_helper.c:2959, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.fpcr), sizeof(((CPUArchState *)0)->vfp.fpcr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vec_helper.c:2957 */
};
static const DfHelperField dfu_gvec_fmlal_a64_env[] = {
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/vec_helper.c:2134, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.fpcr), sizeof(((CPUArchState *)0)->vfp.fpcr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vec_helper.c:2173 */
};
static const DfHelperField dfu_gvec_fmlal_idx_a64_env[] = {
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/vec_helper.c:2216, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.fpcr), sizeof(((CPUArchState *)0)->vfp.fpcr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vec_helper.c:2256 */
};
static const DfHelperField dfu_irg_env[] = {
    { offsetof(CPUArchState, cp15.gcr_el1), sizeof(((CPUArchState *)0)->cp15.gcr_el1), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:224 */
    { offsetof(CPUArchState, cp15.rgsr_el1), sizeof(((CPUArchState *)0)->cp15.rgsr_el1), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:226 */
};
static const DfHelperField dfu_ldg_env[] = {
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
};
static const DfHelperField dfu_neon_addl_saturate_s32_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:880 */
};
static const DfHelperField dfu_neon_narrow_sat_s16_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:744 */
};
static const DfHelperField dfu_neon_narrow_sat_s32_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:782 */
};
static const DfHelperField dfu_neon_narrow_sat_s8_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:686 */
};
static const DfHelperField dfu_neon_narrow_sat_u16_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:726 */
};
static const DfHelperField dfu_neon_narrow_sat_u32_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:772 */
};
static const DfHelperField dfu_neon_narrow_sat_u8_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:662 */
};
static const DfHelperField dfu_neon_qabs_s16_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:1107 */
};
static const DfHelperField dfu_neon_qabs_s32_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:1135 */
};
static const DfHelperField dfu_neon_qabs_s8_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:1067 */
};
static const DfHelperField dfu_neon_qneg_s16_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:1125 */
};
static const DfHelperField dfu_neon_qneg_s32_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:1146 */
};
static const DfHelperField dfu_neon_qneg_s8_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:1087 */
};
static const DfHelperField dfu_neon_sqrshl_b_env[] = {
    { offsetof(CPUArchState, vfp.qc), sizeof(((CPUArchState *)0)->vfp.qc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:421 */
};
static const DfHelperField dfu_neon_sqshl_b_env[] = {
    { offsetof(CPUArchState, vfp.qc), sizeof(((CPUArchState *)0)->vfp.qc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:321 */
};
static const DfHelperField dfu_neon_sqshli_b_env[] = {
    { offsetof(CPUArchState, vfp.qc), sizeof(((CPUArchState *)0)->vfp.qc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:322 */
};
static const DfHelperField dfu_neon_sqshlui_b_env[] = {
    { offsetof(CPUArchState, vfp.qc), sizeof(((CPUArchState *)0)->vfp.qc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:357 */
};
static const DfHelperField dfu_neon_unarrow_sat16_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:702 */
};
static const DfHelperField dfu_neon_unarrow_sat32_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:758 */
};
static const DfHelperField dfu_neon_unarrow_sat8_env[] = {
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:638 */
};
static const DfHelperField dfu_neon_uqrshl_b_env[] = {
    { offsetof(CPUArchState, vfp.qc), sizeof(((CPUArchState *)0)->vfp.qc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:389 */
};
static const DfHelperField dfu_neon_uqshl_b_env[] = {
    { offsetof(CPUArchState, vfp.qc), sizeof(((CPUArchState *)0)->vfp.qc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:285 */
};
static const DfHelperField dfu_neon_uqshli_b_env[] = {
    { offsetof(CPUArchState, vfp.qc), sizeof(((CPUArchState *)0)->vfp.qc), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/neon_helper.c:286 */
};
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_pacda_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/helper.c:11274, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys.apda), sizeof(((CPUArchState *)0)->keys.apda), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/pauth_helper.c:518 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_pacdb_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/helper.c:11274, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys.apdb), sizeof(((CPUArchState *)0)->keys.apdb), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/pauth_helper.c:528 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_pacga_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5631 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys.apga), sizeof(((CPUArchState *)0)->keys.apga), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/pauth_helper.c:536 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_pacia_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/helper.c:11274, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys.apia), sizeof(((CPUArchState *)0)->keys.apia), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/pauth_helper.c:498 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_pacib_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/helper.c:11274, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, keys.apib), sizeof(((CPUArchState *)0)->keys.apib), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/pauth_helper.c:508 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#endif
static const DfHelperField dfu_rebuild_hflags_a64_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_XLAT, 1 },   /* ../target/arm/internals.h:1169, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.fgt_exec[0]), sizeof(((CPUArchState *)0)->cp15.fgt_exec[0]), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/tcg/hflags.c:338 */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:5631 */
    { offsetof(CPUArchState, cp15.mdcr_el2), sizeof(((CPUArchState *)0)->cp15.mdcr_el2), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/debug_helper.c:32 */
    { offsetof(CPUArchState, cp15.mdcr_el3), sizeof(((CPUArchState *)0)->cp15.mdcr_el3), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/debug_helper.c:77 */
    { offsetof(CPUArchState, cp15.mdscr_el1), sizeof(((CPUArchState *)0)->cp15.mdscr_el1), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/debug_helper.c:168 */
    { offsetof(CPUArchState, cp15.osdlr_el1), sizeof(((CPUArchState *)0)->cp15.osdlr_el1), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/debug_helper.c:152 */
    { offsetof(CPUArchState, cp15.oslsr_el1), sizeof(((CPUArchState *)0)->cp15.oslsr_el1), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/debug_helper.c:152 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.sctlr_el[2]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[2]), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/tcg/hflags.c:361 */
    { offsetof(CPUArchState, cp15.sder), sizeof(((CPUArchState *)0)->cp15.sder), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/debug_helper.c:107 */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/internals.h:1154 */
    { offsetof(CPUArchState, daif), sizeof(((CPUArchState *)0)->daif), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/debug_helper.c:89 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_WR, DF_HF_XLAT, 0 },   /* ../target/arm/tcg/hflags.c:499 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:275 */
    { offsetof(CPUArchState, svcr), sizeof(((CPUArchState *)0)->svcr), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:6771 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:277 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_XLAT, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:11687 */
    { offsetof(CPUArchState, vfp.fpcr), sizeof(((CPUArchState *)0)->vfp.fpcr), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/tcg/hflags.c:417 */
    { offsetof(CPUArchState, vfp.smcr_el), sizeof(((CPUArchState *)0)->vfp.smcr_el), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:6745 */
    { offsetof(CPUArchState, vfp.smcr_el[1]), sizeof(((CPUArchState *)0)->vfp.smcr_el[1]), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/tcg/hflags.c:148 */
    { offsetof(CPUArchState, vfp.smcr_el[2]), sizeof(((CPUArchState *)0)->vfp.smcr_el[2]), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/tcg/hflags.c:153 */
    { offsetof(CPUArchState, vfp.smcr_el[3]), sizeof(((CPUArchState *)0)->vfp.smcr_el[3]), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/tcg/hflags.c:158 */
    { offsetof(CPUArchState, vfp.zcr_el), sizeof(((CPUArchState *)0)->vfp.zcr_el), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:6740 */
};
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_set_svcr_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:1169, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.fgt_exec[0]), sizeof(((CPUArchState *)0)->cp15.fgt_exec[0]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/hflags.c:338 */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.hstr_el2), sizeof(((CPUArchState *)0)->cp15.hstr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/hflags.c:181 */
    { offsetof(CPUArchState, cp15.mdcr_el2), sizeof(((CPUArchState *)0)->cp15.mdcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/debug_helper.c:32 */
    { offsetof(CPUArchState, cp15.mdcr_el3), sizeof(((CPUArchState *)0)->cp15.mdcr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/debug_helper.c:77 */
    { offsetof(CPUArchState, cp15.mdscr_el1), sizeof(((CPUArchState *)0)->cp15.mdscr_el1), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/debug_helper.c:168 */
    { offsetof(CPUArchState, cp15.osdlr_el1), sizeof(((CPUArchState *)0)->cp15.osdlr_el1), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/debug_helper.c:152 */
    { offsetof(CPUArchState, cp15.oslsr_el1), sizeof(((CPUArchState *)0)->cp15.oslsr_el1), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/debug_helper.c:152 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.sctlr_el[1]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2974 */
    { offsetof(CPUArchState, cp15.sctlr_el[2]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/hflags.c:361 */
    { offsetof(CPUArchState, cp15.sder), sizeof(((CPUArchState *)0)->cp15.sder), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/debug_helper.c:107 */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
    { offsetof(CPUArchState, daif), sizeof(((CPUArchState *)0)->daif), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/debug_helper.c:89 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/hflags.c:450 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, svcr), sizeof(((CPUArchState *)0)->svcr), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:6869 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp.fp_status[0]), sizeof(((CPUArchState *)0)->vfp.fp_status[0]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vfp_helper.c:151 */
    { offsetof(CPUArchState, vfp.fp_status[1]), sizeof(((CPUArchState *)0)->vfp.fp_status[1]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vfp_helper.c:152 */
    { offsetof(CPUArchState, vfp.fp_status[2]), sizeof(((CPUArchState *)0)->vfp.fp_status[2]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vfp_helper.c:153 */
    { offsetof(CPUArchState, vfp.fp_status[3]), sizeof(((CPUArchState *)0)->vfp.fp_status[3]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vfp_helper.c:154 */
    { offsetof(CPUArchState, vfp.fp_status[4]), sizeof(((CPUArchState *)0)->vfp.fp_status[4]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vfp_helper.c:157 */
    { offsetof(CPUArchState, vfp.fp_status[5]), sizeof(((CPUArchState *)0)->vfp.fp_status[5]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vfp_helper.c:158 */
    { offsetof(CPUArchState, vfp.fp_status[6]), sizeof(((CPUArchState *)0)->vfp.fp_status[6]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vfp_helper.c:155 */
    { offsetof(CPUArchState, vfp.fp_status[7]), sizeof(((CPUArchState *)0)->vfp.fp_status[7]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vfp_helper.c:156 */
    { offsetof(CPUArchState, vfp.fpcr), sizeof(((CPUArchState *)0)->vfp.fpcr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/hflags.c:417 */
    { offsetof(CPUArchState, vfp.fpsr), sizeof(((CPUArchState *)0)->vfp.fpsr), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/vfp_fpscr.c:86 */
    { offsetof(CPUArchState, vfp.pregs), sizeof(((CPUArchState *)0)->vfp.pregs), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:6863 */
    { offsetof(CPUArchState, vfp.qc[0]), sizeof(((CPUArchState *)0)->vfp.qc[0]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/vfp_fpscr.c:69 */
    { offsetof(CPUArchState, vfp.qc[1]), sizeof(((CPUArchState *)0)->vfp.qc[1]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/vfp_fpscr.c:70 */
    { offsetof(CPUArchState, vfp.qc[2]), sizeof(((CPUArchState *)0)->vfp.qc[2]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/vfp_fpscr.c:71 */
    { offsetof(CPUArchState, vfp.qc[3]), sizeof(((CPUArchState *)0)->vfp.qc[3]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/vfp_fpscr.c:72 */
    { offsetof(CPUArchState, vfp.smcr_el), sizeof(((CPUArchState *)0)->vfp.smcr_el), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:6745 */
    { offsetof(CPUArchState, vfp.smcr_el[1]), sizeof(((CPUArchState *)0)->vfp.smcr_el[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/hflags.c:148 */
    { offsetof(CPUArchState, vfp.smcr_el[2]), sizeof(((CPUArchState *)0)->vfp.smcr_el[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/hflags.c:153 */
    { offsetof(CPUArchState, vfp.smcr_el[3]), sizeof(((CPUArchState *)0)->vfp.smcr_el[3]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/hflags.c:158 */
    { offsetof(CPUArchState, vfp.zcr_el), sizeof(((CPUArchState *)0)->vfp.zcr_el), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:6740 */
    { offsetof(CPUArchState, vfp.zregs), sizeof(((CPUArchState *)0)->vfp.zregs), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:6861 */
    { offsetof(CPUArchState, zarray), sizeof(((CPUArchState *)0)->zarray), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:6889 */
};
#endif
static const DfHelperField dfu_sete_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1462 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.hcrx_el2), sizeof(((CPUArchState *)0)->cp15.hcrx_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5820 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.sctlr_el[1]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1417 */
    { offsetof(CPUArchState, cp15.sctlr_el[2]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1419 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/helper-a64.c:1684, INDEX NOT STATED */
};
static const DfHelperField dfu_setge_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1462 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.hcrx_el2), sizeof(((CPUArchState *)0)->cp15.hcrx_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5820 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.sctlr_el[1]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1417 */
    { offsetof(CPUArchState, cp15.sctlr_el[2]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1419 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/helper-a64.c:1684, INDEX NOT STATED */
};
static const DfHelperField dfu_setgm_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1462 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.hcrx_el2), sizeof(((CPUArchState *)0)->cp15.hcrx_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5820 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.sctlr_el[1]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1417 */
    { offsetof(CPUArchState, cp15.sctlr_el[2]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1419 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/helper-a64.c:1684, INDEX NOT STATED */
};
static const DfHelperField dfu_setgp_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1782 */
    { offsetof(CPUArchState, NF), sizeof(((CPUArchState *)0)->NF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1780 */
    { offsetof(CPUArchState, VF), sizeof(((CPUArchState *)0)->VF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1783 */
    { offsetof(CPUArchState, ZF), sizeof(((CPUArchState *)0)->ZF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1781 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.hcrx_el2), sizeof(((CPUArchState *)0)->cp15.hcrx_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5820 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.sctlr_el[1]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1417 */
    { offsetof(CPUArchState, cp15.sctlr_el[2]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1419 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/helper-a64.c:1684, INDEX NOT STATED */
};
static const DfHelperField dfu_setm_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1462 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.hcrx_el2), sizeof(((CPUArchState *)0)->cp15.hcrx_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5820 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.sctlr_el[1]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1417 */
    { offsetof(CPUArchState, cp15.sctlr_el[2]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1419 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/helper-a64.c:1684, INDEX NOT STATED */
};
static const DfHelperField dfu_setp_env[] = {
    { offsetof(CPUArchState, CF), sizeof(((CPUArchState *)0)->CF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1782 */
    { offsetof(CPUArchState, NF), sizeof(((CPUArchState *)0)->NF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1780 */
    { offsetof(CPUArchState, VF), sizeof(((CPUArchState *)0)->VF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1783 */
    { offsetof(CPUArchState, ZF), sizeof(((CPUArchState *)0)->ZF), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1781 */
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.hcrx_el2), sizeof(((CPUArchState *)0)->cp15.hcrx_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5820 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, cp15.sctlr_el[1]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[1]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1417 */
    { offsetof(CPUArchState, cp15.sctlr_el[2]), sizeof(((CPUArchState *)0)->cp15.sctlr_el[2]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/helper-a64.c:1419 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, xregs), sizeof(((CPUArchState *)0)->xregs), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/helper-a64.c:1684, INDEX NOT STATED */
};
static const DfHelperField dfu_simd_tblx_env[] = {
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/cpu.h:3245, INDEX NOT STATED */
};
static const DfHelperField dfu_st2g_env[] = {
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
};
static const DfHelperField dfu_stg_env[] = {
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
};
static const DfHelperField dfu_stzgm_tags_env[] = {
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
};
static const DfHelperField dfu_sve2_fmlal_zzxw_s_env[] = {
    { offsetof(CPUArchState, vfp.fp_status[1]), sizeof(((CPUArchState *)0)->vfp.fp_status[1]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vec_helper.c:2272 */
    { offsetof(CPUArchState, vfp.fpcr), sizeof(((CPUArchState *)0)->vfp.fpcr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vec_helper.c:2273 */
};
static const DfHelperField dfu_sve2_fmlal_zzzw_s_env[] = {
    { offsetof(CPUArchState, vfp.fp_status[1]), sizeof(((CPUArchState *)0)->vfp.fp_status[1]), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vec_helper.c:2188 */
    { offsetof(CPUArchState, vfp.fpcr), sizeof(((CPUArchState *)0)->vfp.fpcr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/vec_helper.c:2189 */
};
static const DfHelperField dfu_sve_ld1bb_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld1bds_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld1dd_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld1hds_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld1hh_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld1sds_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld1ss_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld2bb_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld2dd_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld2hh_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld2ss_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld3bb_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld3dd_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld3hh_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld3ss_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld4bb_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld4dd_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld4hh_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ld4ss_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:5874, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_ldbss_zsu_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
static const DfHelperField dfu_sve_ldbsu_zsu_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
static const DfHelperField dfu_sve_lddd_le_zd_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldff1bds_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6185, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldff1dd_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6185, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldff1hds_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6185, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldff1sds_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6185, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldffbss_zsu_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldffbsu_zsu_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldffdd_le_zd_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldffhss_le_zsu_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldffhsu_le_zsu_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldffsds_le_zd_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldffsds_le_zsu_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldffss_le_zsu_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
static const DfHelperField dfu_sve_ldhss_le_zsu_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
static const DfHelperField dfu_sve_ldhsu_le_zsu_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldnf1bb_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6185, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldnf1bds_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6185, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldnf1dd_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6185, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldnf1hds_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6185, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldnf1hh_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6185, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldnf1sds_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6185, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperField dfu_sve_ldnf1ss_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6185, INDEX NOT STATED */
    { offsetof(CPUArchState, vfp.pregs[16].p), sizeof(((CPUArchState *)0)->vfp.pregs[16].p), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6163, INDEX NOT STATED */
};
#endif
static const DfHelperField dfu_sve_ldsds_le_zd_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
static const DfHelperField dfu_sve_ldsds_le_zsu_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
static const DfHelperField dfu_sve_ldss_le_zsu_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
static const DfHelperField dfu_sve_st1bb_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_st1hh_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_st1ss_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_st2bb_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_st2dd_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_st2hh_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_st2ss_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_st3bb_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_st3dd_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_st3hh_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_st3ss_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_st4bb_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_st4dd_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_st4hh_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_st4ss_le_r_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/sve_helper.c:6546, INDEX NOT STATED */
};
static const DfHelperField dfu_sve_stbd_zd_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
static const DfHelperField dfu_sve_stdd_le_zd_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
static const DfHelperField dfu_sve_stsd_le_zd_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/mte_helper.c:650, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:445 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, exception.vaddress), sizeof(((CPUArchState *)0)->exception.vaddress), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/mte_helper.c:608 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags.flags), sizeof(((CPUArchState *)0)->hflags.flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:47 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:463 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:466 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:459, INDEX NOT STATED */
    { offsetof(CPUArchState, v7m.exception), sizeof(((CPUArchState *)0)->v7m.exception), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2676 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:459 */
};
static const DfHelperField dfu_tidcp_el0_env[] = {
    { offsetof(CPUArchState, aarch64), sizeof(((CPUArchState *)0)->aarch64), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:1312 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/tcg/op_helper.c:978, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.hcr_el2), sizeof(((CPUArchState *)0)->cp15.hcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:5631 */
    { offsetof(CPUArchState, cp15.scr_el3), sizeof(((CPUArchState *)0)->cp15.scr_el3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:406 */
    { offsetof(CPUArchState, exception.syndrome), sizeof(((CPUArchState *)0)->exception.syndrome), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:68 */
    { offsetof(CPUArchState, exception.target_el), sizeof(((CPUArchState *)0)->exception.target_el), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/arm/tcg/op_helper.c:69 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:275 */
    { offsetof(CPUArchState, uncached_cpsr), sizeof(((CPUArchState *)0)->uncached_cpsr), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:277 */
    { offsetof(CPUArchState, v7m.secure), sizeof(((CPUArchState *)0)->v7m.secure), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/helper.c:11687 */
};
static const DfHelperField dfu_xpacd_env[] = {
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:1169, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
};
static const DfHelperField dfu_xpaci_env[] = {
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/arm/internals.h:1169, INDEX NOT STATED */
    { offsetof(CPUArchState, cp15.vstcr_el2), sizeof(((CPUArchState *)0)->cp15.vstcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1165 */
    { offsetof(CPUArchState, cp15.vtcr_el2), sizeof(((CPUArchState *)0)->cp15.vtcr_el2), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/arm/internals.h:1154 */
};
static const DfHelperField dfu_lookup_tb_ptr_env[] = {
    { offsetof(CPUArchState, btype), sizeof(((CPUArchState *)0)->btype), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:11779 */
    { offsetof(CPUArchState, condexec_bits), sizeof(((CPUArchState *)0)->condexec_bits), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:11828 */
    { offsetof(CPUArchState, cp15), sizeof(((CPUArchState *)0)->cp15), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:11817 */
    { offsetof(CPUArchState, features), sizeof(((CPUArchState *)0)->features), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/cpu.h:2493 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:11774 */
    { offsetof(CPUArchState, pc), sizeof(((CPUArchState *)0)->pc), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:11777 */
    { offsetof(CPUArchState, pstate), sizeof(((CPUArchState *)0)->pstate), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:11840 */
    { offsetof(CPUArchState, regs), sizeof(((CPUArchState *)0)->regs), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:11782 */
    { offsetof(CPUArchState, thumb), sizeof(((CPUArchState *)0)->thumb), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:11827 */
    { offsetof(CPUArchState, v7m), sizeof(((CPUArchState *)0)->v7m), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:11786 */
    { offsetof(CPUArchState, vfp), sizeof(((CPUArchState *)0)->vfp), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/arm/helper.c:11819 */
};
static const DfHelperAccess dfu_cpye_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:2022, 6 site(s) */
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:2037, 6 site(s) */
};
static const DfHelperAccess dfu_cpyfe_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:2022, 6 site(s) */
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:2037, 6 site(s) */
};
static const DfHelperAccess dfu_cpyfm_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:2022, 6 site(s) */
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:2037, 6 site(s) */
};
static const DfHelperAccess dfu_cpyfp_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:2022, 6 site(s) */
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:2037, 6 site(s) */
};
static const DfHelperAccess dfu_cpym_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:2022, 6 site(s) */
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:2037, 6 site(s) */
};
static const DfHelperAccess dfu_cpyp_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:2022, 6 site(s) */
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:2037, 6 site(s) */
};
static const DfHelperAccess dfu_dc_zva_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/helper-a64.c:1358, 1 site(s) */
};
static const DfHelperAccess dfu_sete_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:1547, 3 site(s) */
};
static const DfHelperAccess dfu_setge_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 16, 0 },   /* ../target/arm/tcg/helper-a64.c:1605, 1 site(s) */
};
static const DfHelperAccess dfu_setgm_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 16, 0 },   /* ../target/arm/tcg/helper-a64.c:1605, 1 site(s) */
};
static const DfHelperAccess dfu_setgp_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 16, 0 },   /* ../target/arm/tcg/helper-a64.c:1605, 1 site(s) */
};
static const DfHelperAccess dfu_setm_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:1547, 3 site(s) */
};
static const DfHelperAccess dfu_setp_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 1 },   /* ../target/arm/tcg/helper-a64.c:1547, 3 site(s) */
};
static const DfHelperAccess dfu_sve_ld1bb_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:71, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld1bds_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:77, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld1dd_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:117, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld1hds_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:104, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld1hh_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:100, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld1sds_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:112, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld1ss_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:110, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld2bb_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:71, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld2dd_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:117, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld2hh_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:100, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld2ss_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:110, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld3bb_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:71, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld3dd_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:117, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld3hh_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:100, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld3ss_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:110, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld4bb_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:71, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld4dd_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:117, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld4hh_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:100, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ld4ss_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:110, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ldbss_zsu_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:75, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ldbsu_zsu_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:74, 1 site(s) */
};
static const DfHelperAccess dfu_sve_lddd_le_zd_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:117, 1 site(s) */
};
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldff1bds_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:77, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldff1dd_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:117, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldff1hds_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:104, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldff1sds_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:112, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldffbss_zsu_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:75, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldffbsu_zsu_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:74, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldffdd_le_zd_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:117, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldffhss_le_zsu_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:102, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldffhsu_le_zsu_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:101, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldffsds_le_zd_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:112, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldffsds_le_zsu_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:112, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldffss_le_zsu_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:110, 1 site(s) */
};
#endif
static const DfHelperAccess dfu_sve_ldhss_le_zsu_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:102, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ldhsu_le_zsu_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:101, 1 site(s) */
};
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldnf1bb_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:71, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldnf1bds_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:77, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldnf1dd_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:117, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldnf1hds_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:104, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldnf1hh_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:100, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldnf1sds_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:112, 1 site(s) */
};
#endif
#if defined(TARGET_AARCH64)
static const DfHelperAccess dfu_sve_ldnf1ss_le_r_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:110, 1 site(s) */
};
#endif
static const DfHelperAccess dfu_sve_ldsds_le_zd_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:112, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ldsds_le_zsu_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:112, 1 site(s) */
};
static const DfHelperAccess dfu_sve_ldss_le_zsu_acc[] = {
    { INSN_DF_RD, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:110, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st1bb_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:83, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st1hh_le_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:106, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st1ss_le_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:114, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st2bb_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:83, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st2dd_le_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:118, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st2hh_le_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:106, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st2ss_le_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:114, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st3bb_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:83, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st3dd_le_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:118, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st3hh_le_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:106, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st3ss_le_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:114, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st4bb_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:83, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st4dd_le_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:118, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st4hh_le_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 2, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:106, 1 site(s) */
};
static const DfHelperAccess dfu_sve_st4ss_le_r_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:114, 1 site(s) */
};
static const DfHelperAccess dfu_sve_stbd_zd_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 1, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:86, 1 site(s) */
};
static const DfHelperAccess dfu_sve_stdd_le_zd_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 8, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:118, 1 site(s) */
};
static const DfHelperAccess dfu_sve_stsd_le_zd_acc[] = {
    { INSN_DF_WR, DF_HA_NO_ARG, DF_HA_NO_ARG, 4, 0 },   /* ../target/arm/tcg/sve_ldst_internal.h:115, 1 site(s) */
};

static const DfHelperUsage df_helper_usage[] = {
    { "addsubg", { 0 }, { 0 },
      dfu_addsubg_env, ARRAY_SIZE(dfu_addsubg_env), true,
      "../target/arm/tcg/mte_helper.c:285",
      NULL, 0 },
    { "advsimd_rinth", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:561",
      NULL, 0 },
    { "advsimd_rinth_exact", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:556",
      NULL, 0 },
#if defined(TARGET_AARCH64)
    { "autda", { 0 }, { 0 },
      dfu_autda_env, ARRAY_SIZE(dfu_autda_env), true,
      "../target/arm/tcg/pauth_helper.c:594",
      NULL, 0 },
#endif
#if defined(TARGET_AARCH64)
    { "autda_combined", { 0 }, { 0 },
      dfu_autda_combined_env, ARRAY_SIZE(dfu_autda_combined_env), true,
      "../target/arm/tcg/pauth_helper.c:599",
      NULL, 0 },
#endif
#if defined(TARGET_AARCH64)
    { "autdb", { 0 }, { 0 },
      dfu_autdb_env, ARRAY_SIZE(dfu_autdb_env), true,
      "../target/arm/tcg/pauth_helper.c:615",
      NULL, 0 },
#endif
#if defined(TARGET_AARCH64)
    { "autdb_combined", { 0 }, { 0 },
      dfu_autdb_combined_env, ARRAY_SIZE(dfu_autdb_combined_env), true,
      "../target/arm/tcg/pauth_helper.c:620",
      NULL, 0 },
#endif
#if defined(TARGET_AARCH64)
    { "autia", { 0 }, { 0 },
      dfu_autia_env, ARRAY_SIZE(dfu_autia_env), true,
      "../target/arm/tcg/pauth_helper.c:552",
      NULL, 0 },
#endif
#if defined(TARGET_AARCH64)
    { "autia_combined", { 0 }, { 0 },
      dfu_autia_combined_env, ARRAY_SIZE(dfu_autia_combined_env), true,
      "../target/arm/tcg/pauth_helper.c:557",
      NULL, 0 },
#endif
#if defined(TARGET_AARCH64)
    { "autib", { 0 }, { 0 },
      dfu_autib_env, ARRAY_SIZE(dfu_autib_env), true,
      "../target/arm/tcg/pauth_helper.c:573",
      NULL, 0 },
#endif
#if defined(TARGET_AARCH64)
    { "autib_combined", { 0 }, { 0 },
      dfu_autib_combined_env, ARRAY_SIZE(dfu_autib_combined_env), true,
      "../target/arm/tcg/pauth_helper.c:578",
      NULL, 0 },
#endif
    { "bfcvt", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:387",
      NULL, 0 },
    { "bfcvt_pair", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:392",
      NULL, 0 },
    { "cpye", { 0 }, { 0 },
      dfu_cpye_env, ARRAY_SIZE(dfu_cpye_env), true,
      "../target/arm/tcg/helper-a64.c:2519",
      dfu_cpye_acc, ARRAY_SIZE(dfu_cpye_acc) },
    { "cpyfe", { 0 }, { 0 },
      dfu_cpyfe_env, ARRAY_SIZE(dfu_cpyfe_env), true,
      "../target/arm/tcg/helper-a64.c:2525",
      dfu_cpyfe_acc, ARRAY_SIZE(dfu_cpyfe_acc) },
    { "cpyfm", { 0 }, { 0 },
      dfu_cpyfm_env, ARRAY_SIZE(dfu_cpyfm_env), true,
      "../target/arm/tcg/helper-a64.c:2433",
      dfu_cpyfm_acc, ARRAY_SIZE(dfu_cpyfm_acc) },
    { "cpyfp", { 0 }, { 0 },
      dfu_cpyfp_env, ARRAY_SIZE(dfu_cpyfp_env), true,
      "../target/arm/tcg/helper-a64.c:2335",
      dfu_cpyfp_acc, ARRAY_SIZE(dfu_cpyfp_acc) },
    { "cpym", { 0 }, { 0 },
      dfu_cpym_env, ARRAY_SIZE(dfu_cpym_env), true,
      "../target/arm/tcg/helper-a64.c:2427",
      dfu_cpym_acc, ARRAY_SIZE(dfu_cpym_acc) },
    { "cpyp", { 0 }, { 0 },
      dfu_cpyp_env, ARRAY_SIZE(dfu_cpyp_env), true,
      "../target/arm/tcg/helper-a64.c:2329",
      dfu_cpyp_acc, ARRAY_SIZE(dfu_cpyp_acc) },
    { "crc32_64", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:414",
      NULL, 0 },
    { "crc32c_64", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:424",
      NULL, 0 },
    { "crypto_aesd", { 3, 3, 3 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:80",
      NULL, 0 },
    { "crypto_aese", { 3, 3, 3 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:51",
      NULL, 0 },
    { "crypto_aesimc", { 3, 3 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:128",
      NULL, 0 },
    { "crypto_aesmc", { 3, 3 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:105",
      NULL, 0 },
    { "crypto_sha1c", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:215",
      NULL, 0 },
    { "crypto_sha1h", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:240",
      NULL, 0 },
    { "crypto_sha1m", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:235",
      NULL, 0 },
    { "crypto_sha1p", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:225",
      NULL, 0 },
    { "crypto_sha1su0", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:170",
      NULL, 0 },
    { "crypto_sha1su1", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:255",
      NULL, 0 },
    { "crypto_sha256h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:298",
      NULL, 0 },
    { "crypto_sha256h2", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:333",
      NULL, 0 },
    { "crypto_sha256su0", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:360",
      NULL, 0 },
    { "crypto_sha256su1", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:378",
      NULL, 0 },
    { "crypto_sha512h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:432",
      NULL, 0 },
    { "crypto_sha512h2", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:449",
      NULL, 0 },
    { "crypto_sha512su0", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:466",
      NULL, 0 },
    { "crypto_sha512su1", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:482",
      NULL, 0 },
    { "crypto_sm3partw1", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:494",
      NULL, 0 },
    { "crypto_sm3partw2", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:522",
      NULL, 0 },
    { "crypto_sm3tt1a", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:599",
      NULL, 0 },
    { "crypto_sm3tt1b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:600",
      NULL, 0 },
    { "crypto_sm3tt2a", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:601",
      NULL, 0 },
    { "crypto_sm3tt2b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:602",
      NULL, 0 },
    { "crypto_sm4e", { 3, 3, 3 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:628",
      NULL, 0 },
    { "crypto_sm4ekey", { 3, 3, 3 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/crypto_helper.c:661",
      NULL, 0 },
    { "dc_zva", { 0 }, { 0 },
      dfu_dc_zva_env, ARRAY_SIZE(dfu_dc_zva_env), true,
      "../target/arm/tcg/helper-a64.c:1274",
      dfu_dc_zva_acc, ARRAY_SIZE(dfu_dc_zva_acc) },
    { "exception_bkpt_insn", { 0 }, { 0 },
      dfu_exception_bkpt_insn_env, ARRAY_SIZE(dfu_exception_bkpt_insn_env), true,
      "../target/arm/debug_helper.c:516",
      NULL, 0 },
    { "exception_internal", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/op_helper.c:516",
      NULL, 0 },
    { "exception_with_syndrome", { 0 }, { 0 },
      dfu_exception_with_syndrome_env, ARRAY_SIZE(dfu_exception_with_syndrome_env), true,
      "../target/arm/tcg/op_helper.c:536",
      NULL, 0 },
    { "fcvtx_f64_to_f32", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:359",
      NULL, 0 },
    { "fjcvtzs", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:1201",
      NULL, 0 },
    { "flogb_d", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4812",
      NULL, 0 },
    { "flogb_h", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4810",
      NULL, 0 },
    { "flogb_s", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4811",
      NULL, 0 },
    { "fmmla_s", { 3, 3, 3, 3, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:7596",
      NULL, 0 },
    { "frecpx_f16", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:263",
      NULL, 0 },
    { "frecpx_f32", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:295",
      NULL, 0 },
    { "frecpx_f64", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:327",
      NULL, 0 },
    { "frint32_d", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:1322",
      NULL, 0 },
    { "frint32_s", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:1274",
      NULL, 0 },
    { "frint64_d", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:1327",
      NULL, 0 },
    { "frint64_s", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:1279",
      NULL, 0 },
    { "get_cp_reg64", { 0, 1 }, { 0, 1 },
      NULL, 0, true,
      "../target/arm/tcg/op_helper.c:1064",
      NULL, 0 },
    { "guarded_page_br", { 0 }, { 0 },
      dfu_guarded_page_br_env, ARRAY_SIZE(dfu_guarded_page_br_env), true,
      "../target/arm/tcg/helper-a64.c:2561",
      NULL, 0 },
    { "guarded_page_check", { 0 }, { 0 },
      dfu_guarded_page_check_env, ARRAY_SIZE(dfu_guarded_page_check_env), true,
      "../target/arm/tcg/helper-a64.c:2547",
      NULL, 0 },
    { "gvec_addp_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2609",
      NULL, 0 },
    { "gvec_bfdot", { 3, 3, 1, 1 }, { 1, 1, 1, 1 },
      dfu_gvec_bfdot_env, ARRAY_SIZE(dfu_gvec_bfdot_env), true,
      "../target/arm/tcg/vec_helper.c:3054",
      NULL, 0 },
    { "gvec_bfdot_idx", { 3, 3, 1, 1 }, { 1, 1, 1, 1 },
      dfu_gvec_bfdot_idx_env, ARRAY_SIZE(dfu_gvec_bfdot_idx_env), true,
      "../target/arm/tcg/vec_helper.c:3074",
      NULL, 0 },
    { "gvec_bfmlal", { 3, 3, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:3181",
      NULL, 0 },
    { "gvec_bfmlal_idx", { 3, 3, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:3197",
      NULL, 0 },
    { "gvec_bfmmla", { 3, 3, 1, 1 }, { 1, 1, 1, 1 },
      dfu_gvec_bfmmla_env, ARRAY_SIZE(dfu_gvec_bfmmla_env), true,
      "../target/arm/tcg/vec_helper.c:3105",
      NULL, 0 },
    { "gvec_cnt_b", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:3244",
      NULL, 0 },
    { "gvec_fabd_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1436",
      NULL, 0 },
    { "gvec_fabd_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1437",
      NULL, 0 },
    { "gvec_facge_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1456",
      NULL, 0 },
    { "gvec_facge_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1457",
      NULL, 0 },
    { "gvec_facgt_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1460",
      NULL, 0 },
    { "gvec_facgt_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1461",
      NULL, 0 },
    { "gvec_fadd_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1420",
      NULL, 0 },
    { "gvec_fadd_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1421",
      NULL, 0 },
    { "gvec_faddp_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2557",
      NULL, 0 },
    { "gvec_faddp_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2558",
      NULL, 0 },
    { "gvec_fcaddh", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:876",
      NULL, 0 },
    { "gvec_fceq0_h", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1282",
      NULL, 0 },
    { "gvec_fceq0_s", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1282",
      NULL, 0 },
    { "gvec_fceq_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1444",
      NULL, 0 },
    { "gvec_fceq_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1445",
      NULL, 0 },
    { "gvec_fcge0_h", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1281",
      NULL, 0 },
    { "gvec_fcge0_s", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1281",
      NULL, 0 },
    { "gvec_fcge_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1448",
      NULL, 0 },
    { "gvec_fcge_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1449",
      NULL, 0 },
    { "gvec_fcgt0_h", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1280",
      NULL, 0 },
    { "gvec_fcgt0_s", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1280",
      NULL, 0 },
    { "gvec_fcgt_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1452",
      NULL, 0 },
    { "gvec_fcgt_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1453",
      NULL, 0 },
    { "gvec_fcle0_h", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1284",
      NULL, 0 },
    { "gvec_fcle0_s", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1284",
      NULL, 0 },
    { "gvec_fclt0_h", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1283",
      NULL, 0 },
    { "gvec_fclt0_s", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1283",
      NULL, 0 },
    { "gvec_fcmlah", { 3, 3, 3, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:963",
      NULL, 0 },
    { "gvec_fcmlah_idx", { 3, 3, 3, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:993",
      NULL, 0 },
    { "gvec_fdiv_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1487",
      NULL, 0 },
    { "gvec_fdiv_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1488",
      NULL, 0 },
    { "gvec_fmax_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1464",
      NULL, 0 },
    { "gvec_fmax_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1465",
      NULL, 0 },
    { "gvec_fmaxnum_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1472",
      NULL, 0 },
    { "gvec_fmaxnum_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1473",
      NULL, 0 },
    { "gvec_fmaxnump_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2569",
      NULL, 0 },
    { "gvec_fmaxnump_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2570",
      NULL, 0 },
    { "gvec_fmaxp_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2561",
      NULL, 0 },
    { "gvec_fmaxp_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2562",
      NULL, 0 },
    { "gvec_fmin_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1468",
      NULL, 0 },
    { "gvec_fmin_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1469",
      NULL, 0 },
    { "gvec_fminnum_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1476",
      NULL, 0 },
    { "gvec_fminnum_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1477",
      NULL, 0 },
    { "gvec_fminnump_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2573",
      NULL, 0 },
    { "gvec_fminnump_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2574",
      NULL, 0 },
    { "gvec_fminp_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2565",
      NULL, 0 },
    { "gvec_fminp_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2566",
      NULL, 0 },
    { "gvec_fmla_idx_h", { 3, 3, 3, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1746",
      NULL, 0 },
    { "gvec_fmlal_a64", { 3, 1, 1 }, { 1, 1, 1 },
      dfu_gvec_fmlal_a64_env, ARRAY_SIZE(dfu_gvec_fmlal_a64_env), true,
      "../target/arm/tcg/vec_helper.c:2165",
      NULL, 0 },
    { "gvec_fmlal_idx_a64", { 3, 1, 3 }, { 1, 1, 1 },
      dfu_gvec_fmlal_idx_a64_env, ARRAY_SIZE(dfu_gvec_fmlal_idx_a64_env), true,
      "../target/arm/tcg/vec_helper.c:2248",
      NULL, 0 },
    { "gvec_fmls_idx_h", { 3, 3, 3, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1750",
      NULL, 0 },
    { "gvec_fmul_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1428",
      NULL, 0 },
    { "gvec_fmul_idx_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1703",
      NULL, 0 },
    { "gvec_fmul_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1429",
      NULL, 0 },
    { "gvec_fmulx_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1491",
      NULL, 0 },
    { "gvec_fmulx_idx_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1709",
      NULL, 0 },
    { "gvec_fmulx_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1492",
      NULL, 0 },
    { "gvec_frecpe_d", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1241",
      NULL, 0 },
    { "gvec_frecpe_h", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1238",
      NULL, 0 },
    { "gvec_frecpe_s", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1239",
      NULL, 0 },
    { "gvec_frsqrte_d", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1246",
      NULL, 0 },
    { "gvec_frsqrte_h", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1243",
      NULL, 0 },
    { "gvec_frsqrte_s", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1244",
      NULL, 0 },
    { "gvec_fsub_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1424",
      NULL, 0 },
    { "gvec_fsub_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1425",
      NULL, 0 },
    { "gvec_ftsmul_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1432",
      NULL, 0 },
    { "gvec_mla_idx_h", { 3, 3, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1674",
      NULL, 0 },
    { "gvec_mls_idx_h", { 3, 3, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1678",
      NULL, 0 },
    { "gvec_mul_idx_h", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1652",
      NULL, 0 },
    { "gvec_pmul_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2395",
      NULL, 0 },
    { "gvec_pmull_q", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2411",
      NULL, 0 },
    { "gvec_qrdmlah_s16", { 3, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:251",
      NULL, 0 },
    { "gvec_qrdmlsh_s16", { 3, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:276",
      NULL, 0 },
    { "gvec_rbit_b", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:3256",
      NULL, 0 },
    { "gvec_recps_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1495",
      NULL, 0 },
    { "gvec_recps_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1496",
      NULL, 0 },
    { "gvec_rsqrts_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1499",
      NULL, 0 },
    { "gvec_rsqrts_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1500",
      NULL, 0 },
    { "gvec_sdot_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:829",
      NULL, 0 },
    { "gvec_sdot_idx_b", { 3, 1, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:869",
      NULL, 0 },
    { "gvec_smaxp_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2615",
      NULL, 0 },
    { "gvec_sminp_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2623",
      NULL, 0 },
    { "gvec_smmla_b", { 3, 3, 3, 3 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2934",
      NULL, 0 },
    { "gvec_smulh_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2759",
      NULL, 0 },
    { "gvec_srshl_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/neon_helper.c:221",
      NULL, 0 },
    { "gvec_sshl_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2298",
      NULL, 0 },
    { "gvec_sudot_idx_b", { 3, 1, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:871",
      NULL, 0 },
    { "gvec_udot_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:830",
      NULL, 0 },
    { "gvec_udot_idx_b", { 3, 1, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:870",
      NULL, 0 },
    { "gvec_umaxp_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2619",
      NULL, 0 },
    { "gvec_uminp_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2627",
      NULL, 0 },
    { "gvec_ummla_b", { 3, 3, 3, 3 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2935",
      NULL, 0 },
    { "gvec_umulh_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2804",
      NULL, 0 },
    { "gvec_urecpe_s", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:3267",
      NULL, 0 },
    { "gvec_urshl_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/neon_helper.c:253",
      NULL, 0 },
    { "gvec_ursqrte_s", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:3278",
      NULL, 0 },
    { "gvec_usdot_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:831",
      NULL, 0 },
    { "gvec_usdot_idx_b", { 3, 1, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:872",
      NULL, 0 },
    { "gvec_ushl_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2340",
      NULL, 0 },
    { "gvec_usmmla_b", { 3, 3, 3, 3 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2936",
      NULL, 0 },
    { "gvec_vcvt_rm_sh", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2681",
      NULL, 0 },
    { "gvec_vcvt_rm_ss", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2679",
      NULL, 0 },
    { "gvec_vcvt_rm_uh", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2682",
      NULL, 0 },
    { "gvec_vcvt_rm_us", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2680",
      NULL, 0 },
    { "gvec_vcvt_rz_hs", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2657",
      NULL, 0 },
    { "gvec_vcvt_sf", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2648",
      NULL, 0 },
    { "gvec_vcvt_sh", { 3, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2650",
      NULL, 0 },
    { "gvec_vfma_d", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1622",
      NULL, 0 },
    { "gvec_vfma_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1620",
      NULL, 0 },
    { "gvec_vfma_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1621",
      NULL, 0 },
    { "gvec_vfms_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1624",
      NULL, 0 },
    { "gvec_vfms_s", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:1625",
      NULL, 0 },
    { "irg", { 0 }, { 0 },
      dfu_irg_env, ARRAY_SIZE(dfu_irg_env), true,
      "../target/arm/tcg/mte_helper.c:222",
      NULL, 0 },
    { "ldg", { 0 }, { 0 },
      dfu_ldg_env, ARRAY_SIZE(dfu_ldg_env), true,
      "../target/arm/tcg/mte_helper.c:301",
      NULL, 0 },
    { "lookup_cp_reg", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/op_helper.c:930",
      NULL, 0 },
    { "neon_addl_saturate_s32", { 0 }, { 0 },
      dfu_neon_addl_saturate_s32_env, ARRAY_SIZE(dfu_neon_addl_saturate_s32_env), true,
      "../target/arm/tcg/neon_helper.c:871",
      NULL, 0 },
    { "neon_cls_s16", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/neon_helper.c:514",
      NULL, 0 },
    { "neon_cls_s8", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/neon_helper.c:510",
      NULL, 0 },
    { "neon_clz_u16", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/neon_helper.c:506",
      NULL, 0 },
    { "neon_clz_u8", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/neon_helper.c:502",
      NULL, 0 },
    { "neon_narrow_sat_s16", { 0 }, { 0 },
      dfu_neon_narrow_sat_s16_env, ARRAY_SIZE(dfu_neon_narrow_sat_s16_env), true,
      "../target/arm/tcg/neon_helper.c:737",
      NULL, 0 },
    { "neon_narrow_sat_s32", { 0 }, { 0 },
      dfu_neon_narrow_sat_s32_env, ARRAY_SIZE(dfu_neon_narrow_sat_s32_env), true,
      "../target/arm/tcg/neon_helper.c:779",
      NULL, 0 },
    { "neon_narrow_sat_s8", { 0 }, { 0 },
      dfu_neon_narrow_sat_s8_env, ARRAY_SIZE(dfu_neon_narrow_sat_s8_env), true,
      "../target/arm/tcg/neon_helper.c:671",
      NULL, 0 },
    { "neon_narrow_sat_u16", { 0 }, { 0 },
      dfu_neon_narrow_sat_u16_env, ARRAY_SIZE(dfu_neon_narrow_sat_u16_env), true,
      "../target/arm/tcg/neon_helper.c:719",
      NULL, 0 },
    { "neon_narrow_sat_u32", { 0 }, { 0 },
      dfu_neon_narrow_sat_u32_env, ARRAY_SIZE(dfu_neon_narrow_sat_u32_env), true,
      "../target/arm/tcg/neon_helper.c:769",
      NULL, 0 },
    { "neon_narrow_sat_u8", { 0 }, { 0 },
      dfu_neon_narrow_sat_u8_env, ARRAY_SIZE(dfu_neon_narrow_sat_u8_env), true,
      "../target/arm/tcg/neon_helper.c:647",
      NULL, 0 },
    { "neon_narrow_u16", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/neon_helper.c:587",
      NULL, 0 },
    { "neon_narrow_u8", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/neon_helper.c:580",
      NULL, 0 },
    { "neon_pmull_h", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:2425",
      NULL, 0 },
    { "neon_qabs_s16", { 0 }, { 0 },
      dfu_neon_qabs_s16_env, ARRAY_SIZE(dfu_neon_qabs_s16_env), true,
      "../target/arm/tcg/neon_helper.c:1103",
      NULL, 0 },
    { "neon_qabs_s32", { 0 }, { 0 },
      dfu_neon_qabs_s32_env, ARRAY_SIZE(dfu_neon_qabs_s32_env), true,
      "../target/arm/tcg/neon_helper.c:1132",
      NULL, 0 },
    { "neon_qabs_s8", { 0 }, { 0 },
      dfu_neon_qabs_s8_env, ARRAY_SIZE(dfu_neon_qabs_s8_env), true,
      "../target/arm/tcg/neon_helper.c:1063",
      NULL, 0 },
    { "neon_qneg_s16", { 0 }, { 0 },
      dfu_neon_qneg_s16_env, ARRAY_SIZE(dfu_neon_qneg_s16_env), true,
      "../target/arm/tcg/neon_helper.c:1121",
      NULL, 0 },
    { "neon_qneg_s32", { 0 }, { 0 },
      dfu_neon_qneg_s32_env, ARRAY_SIZE(dfu_neon_qneg_s32_env), true,
      "../target/arm/tcg/neon_helper.c:1143",
      NULL, 0 },
    { "neon_qneg_s8", { 0 }, { 0 },
      dfu_neon_qneg_s8_env, ARRAY_SIZE(dfu_neon_qneg_s8_env), true,
      "../target/arm/tcg/neon_helper.c:1083",
      NULL, 0 },
    { "neon_sqdmulh_h", { 3, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:291",
      NULL, 0 },
    { "neon_sqdmulh_idx_h", { 3, 3, 3 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:315",
      NULL, 0 },
    { "neon_sqrdmlah_idx_h", { 3, 3, 3 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:351",
      NULL, 0 },
    { "neon_sqrdmlsh_idx_h", { 3, 3, 3 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:369",
      NULL, 0 },
    { "neon_sqrdmulh_h", { 3, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:303",
      NULL, 0 },
    { "neon_sqrdmulh_idx_h", { 3, 3, 3 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:333",
      NULL, 0 },
    { "neon_sqrshl_b", { 3, 3, 1 }, { 1, 1, 1 },
      dfu_neon_sqrshl_b_env, ARRAY_SIZE(dfu_neon_sqrshl_b_env), true,
      "../target/arm/tcg/neon_helper.c:421",
      NULL, 0 },
    { "neon_sqshl_b", { 3, 3, 1 }, { 1, 1, 1 },
      dfu_neon_sqshl_b_env, ARRAY_SIZE(dfu_neon_sqshl_b_env), true,
      "../target/arm/tcg/neon_helper.c:321",
      NULL, 0 },
    { "neon_sqshli_b", { 3, 1 }, { 1, 1 },
      dfu_neon_sqshli_b_env, ARRAY_SIZE(dfu_neon_sqshli_b_env), true,
      "../target/arm/tcg/neon_helper.c:322",
      NULL, 0 },
    { "neon_sqshlui_b", { 3, 1 }, { 1, 1 },
      dfu_neon_sqshlui_b_env, ARRAY_SIZE(dfu_neon_sqshlui_b_env), true,
      "../target/arm/tcg/neon_helper.c:357",
      NULL, 0 },
    { "neon_unarrow_sat16", { 0 }, { 0 },
      dfu_neon_unarrow_sat16_env, ARRAY_SIZE(dfu_neon_unarrow_sat16_env), true,
      "../target/arm/tcg/neon_helper.c:695",
      NULL, 0 },
    { "neon_unarrow_sat32", { 0 }, { 0 },
      dfu_neon_unarrow_sat32_env, ARRAY_SIZE(dfu_neon_unarrow_sat32_env), true,
      "../target/arm/tcg/neon_helper.c:755",
      NULL, 0 },
    { "neon_unarrow_sat8", { 0 }, { 0 },
      dfu_neon_unarrow_sat8_env, ARRAY_SIZE(dfu_neon_unarrow_sat8_env), true,
      "../target/arm/tcg/neon_helper.c:619",
      NULL, 0 },
    { "neon_uqrshl_b", { 3, 3, 1 }, { 1, 1, 1 },
      dfu_neon_uqrshl_b_env, ARRAY_SIZE(dfu_neon_uqrshl_b_env), true,
      "../target/arm/tcg/neon_helper.c:389",
      NULL, 0 },
    { "neon_uqshl_b", { 3, 3, 1 }, { 1, 1, 1 },
      dfu_neon_uqshl_b_env, ARRAY_SIZE(dfu_neon_uqshl_b_env), true,
      "../target/arm/tcg/neon_helper.c:285",
      NULL, 0 },
    { "neon_uqshli_b", { 3, 1 }, { 1, 1 },
      dfu_neon_uqshli_b_env, ARRAY_SIZE(dfu_neon_uqshli_b_env), true,
      "../target/arm/tcg/neon_helper.c:286",
      NULL, 0 },
    { "neon_widen_u16", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/neon_helper.c:816",
      NULL, 0 },
    { "neon_widen_u8", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/neon_helper.c:788",
      NULL, 0 },
#if defined(TARGET_AARCH64)
    { "pacda", { 0 }, { 0 },
      dfu_pacda_env, ARRAY_SIZE(dfu_pacda_env), true,
      "../target/arm/tcg/pauth_helper.c:511",
      NULL, 0 },
#endif
#if defined(TARGET_AARCH64)
    { "pacdb", { 0 }, { 0 },
      dfu_pacdb_env, ARRAY_SIZE(dfu_pacdb_env), true,
      "../target/arm/tcg/pauth_helper.c:521",
      NULL, 0 },
#endif
#if defined(TARGET_AARCH64)
    { "pacga", { 0 }, { 0 },
      dfu_pacga_env, ARRAY_SIZE(dfu_pacga_env), true,
      "../target/arm/tcg/pauth_helper.c:531",
      NULL, 0 },
#endif
#if defined(TARGET_AARCH64)
    { "pacia", { 0 }, { 0 },
      dfu_pacia_env, ARRAY_SIZE(dfu_pacia_env), true,
      "../target/arm/tcg/pauth_helper.c:491",
      NULL, 0 },
#endif
#if defined(TARGET_AARCH64)
    { "pacib", { 0 }, { 0 },
      dfu_pacib_env, ARRAY_SIZE(dfu_pacib_env), true,
      "../target/arm/tcg/pauth_helper.c:501",
      NULL, 0 },
#endif
    { "probe_access", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/op_helper.c:1284",
      NULL, 0 },
    { "rbit", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/op_helper.c:175",
      NULL, 0 },
    { "rbit64", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:67",
      NULL, 0 },
    { "rebuild_hflags_a64", { 0 }, { 0 },
      dfu_rebuild_hflags_a64_env, ARRAY_SIZE(dfu_rebuild_hflags_a64_env), true,
      "../target/arm/tcg/hflags.c:494",
      NULL, 0 },
    { "rintd", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:1171",
      NULL, 0 },
    { "rintd_exact", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:1134",
      NULL, 0 },
    { "rints", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:1155",
      NULL, 0 },
    { "rints_exact", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:1129",
      NULL, 0 },
    { "sdiv64", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:56",
      NULL, 0 },
    { "set_cp_reg64", { 0, 1 }, { 0, 1 },
      NULL, 0, true,
      "../target/arm/tcg/op_helper.c:1044",
      NULL, 0 },
    { "set_rmode", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:479",
      NULL, 0 },
#if defined(TARGET_AARCH64)
    { "set_svcr", { 0 }, { 0 },
      dfu_set_svcr_env, ARRAY_SIZE(dfu_set_svcr_env), true,
      "../target/arm/tcg/sme_helper.c:33",
      NULL, 0 },
#endif
    { "sete", { 0 }, { 0 },
      dfu_sete_env, ARRAY_SIZE(dfu_sete_env), true,
      "../target/arm/tcg/helper-a64.c:1930",
      dfu_sete_acc, ARRAY_SIZE(dfu_sete_acc) },
    { "setge", { 0 }, { 0 },
      dfu_setge_env, ARRAY_SIZE(dfu_setge_env), true,
      "../target/arm/tcg/helper-a64.c:1935",
      dfu_setge_acc, ARRAY_SIZE(dfu_setge_acc) },
    { "setgm", { 0 }, { 0 },
      dfu_setgm_env, ARRAY_SIZE(dfu_setgm_env), true,
      "../target/arm/tcg/helper-a64.c:1867",
      dfu_setgm_acc, ARRAY_SIZE(dfu_setgm_acc) },
    { "setgp", { 0 }, { 0 },
      dfu_setgp_env, ARRAY_SIZE(dfu_setgp_env), true,
      "../target/arm/tcg/helper-a64.c:1792",
      dfu_setgp_acc, ARRAY_SIZE(dfu_setgp_acc) },
    { "setm", { 0 }, { 0 },
      dfu_setm_env, ARRAY_SIZE(dfu_setm_env), true,
      "../target/arm/tcg/helper-a64.c:1862",
      dfu_setm_acc, ARRAY_SIZE(dfu_setm_acc) },
    { "setp", { 0 }, { 0 },
      dfu_setp_env, ARRAY_SIZE(dfu_setp_env), true,
      "../target/arm/tcg/helper-a64.c:1787",
      dfu_setp_acc, ARRAY_SIZE(dfu_setp_acc) },
    { "simd_tblx", { 3, 1 }, { 1, 1 },
      dfu_simd_tblx_env, ARRAY_SIZE(dfu_simd_tblx_env), true,
      "../target/arm/tcg/vec_helper.c:2707",
      NULL, 0 },
    { "sme_revd_q", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:956",
      NULL, 0 },
    { "st2g", { 0 }, { 0 },
      dfu_st2g_env, ARRAY_SIZE(dfu_st2g_env), true,
      "../target/arm/tcg/mte_helper.c:429",
      NULL, 0 },
    { "stg", { 0 }, { 0 },
      dfu_stg_env, ARRAY_SIZE(dfu_stg_env), true,
      "../target/arm/tcg/mte_helper.c:371",
      NULL, 0 },
    { "stzgm_tags", { 0 }, { 0 },
      dfu_stzgm_tags_env, ARRAY_SIZE(dfu_stzgm_tags_env), true,
      "../target/arm/tcg/mte_helper.c:576",
      NULL, 0 },
    { "sve2_adcl_s", { 3, 1, 1, 3 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1261",
      NULL, 0 },
    { "sve2_addhnb_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2290",
      NULL, 0 },
    { "sve2_addhnt_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2294",
      NULL, 0 },
    { "sve2_addp_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:707",
      NULL, 0 },
    { "sve2_addp_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:708",
      NULL, 0 },
    { "sve2_addp_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:709",
      NULL, 0 },
    { "sve2_bdep_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1650",
      NULL, 0 },
    { "sve2_bext_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1631",
      NULL, 0 },
    { "sve2_bgrp_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1672",
      NULL, 0 },
    { "sve2_cadd_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1709",
      NULL, 0 },
    { "sve2_cadd_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1710",
      NULL, 0 },
    { "sve2_cadd_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1711",
      NULL, 0 },
    { "sve2_cdot_idx_s", { 3, 3, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1458",
      NULL, 0 },
    { "sve2_cdot_zzzz_s", { 3, 3, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1428",
      NULL, 0 },
    { "sve2_cmla_idx_h", { 3, 3, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1385",
      NULL, 0 },
    { "sve2_cmla_zzzz_b", { 3, 3, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1345",
      NULL, 0 },
    { "sve2_eoril_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1157",
      NULL, 0 },
    { "sve2_faddp_zpzz_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:761",
      NULL, 0 },
    { "sve2_faddp_zpzz_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:759",
      NULL, 0 },
    { "sve2_faddp_zpzz_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:760",
      NULL, 0 },
    { "sve2_fcvtlt_hs", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:7710",
      NULL, 0 },
    { "sve2_fcvtlt_sd", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:7711",
      NULL, 0 },
    { "sve2_fcvtnt_ds", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:7690",
      NULL, 0 },
    { "sve2_fcvtnt_sh", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:7689",
      NULL, 0 },
    { "sve2_fmaxnmp_zpzz_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:765",
      NULL, 0 },
    { "sve2_fmaxnmp_zpzz_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:763",
      NULL, 0 },
    { "sve2_fmaxnmp_zpzz_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:764",
      NULL, 0 },
    { "sve2_fmaxp_zpzz_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:773",
      NULL, 0 },
    { "sve2_fmaxp_zpzz_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:771",
      NULL, 0 },
    { "sve2_fmaxp_zpzz_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:772",
      NULL, 0 },
    { "sve2_fminnmp_zpzz_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:769",
      NULL, 0 },
    { "sve2_fminnmp_zpzz_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:767",
      NULL, 0 },
    { "sve2_fminnmp_zpzz_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:768",
      NULL, 0 },
    { "sve2_fminp_zpzz_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:777",
      NULL, 0 },
    { "sve2_fminp_zpzz_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:775",
      NULL, 0 },
    { "sve2_fminp_zpzz_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:776",
      NULL, 0 },
    { "sve2_fmlal_zzxw_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      dfu_sve2_fmlal_zzxw_s_env, ARRAY_SIZE(dfu_sve2_fmlal_zzxw_s_env), true,
      "../target/arm/tcg/vec_helper.c:2265",
      NULL, 0 },
    { "sve2_fmlal_zzzw_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      dfu_sve2_fmlal_zzzw_s_env, ARRAY_SIZE(dfu_sve2_fmlal_zzzw_s_env), true,
      "../target/arm/tcg/vec_helper.c:2182",
      NULL, 0 },
    { "sve2_histcnt_s", { 3, 3, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:7426",
      NULL, 0 },
    { "sve2_histseg", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:7532",
      NULL, 0 },
    { "sve2_match_ppzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:7418",
      NULL, 0 },
    { "sve2_nmatch_ppzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:7421",
      NULL, 0 },
    { "sve2_raddhnb_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2298",
      NULL, 0 },
    { "sve2_raddhnt_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2302",
      NULL, 0 },
    { "sve2_rshrnb_h", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2179",
      NULL, 0 },
    { "sve2_rshrnt_h", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2183",
      NULL, 0 },
    { "sve2_rsubhnb_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2314",
      NULL, 0 },
    { "sve2_rsubhnt_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2318",
      NULL, 0 },
    { "sve2_sabal_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1177",
      NULL, 0 },
    { "sve2_sabdl_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1065",
      NULL, 0 },
    { "sve2_sadalp_zpzz_d", { 3, 3, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:378",
      NULL, 0 },
    { "sve2_sadalp_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:376",
      NULL, 0 },
    { "sve2_sadalp_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:377",
      NULL, 0 },
    { "sve2_saddl_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1057",
      NULL, 0 },
    { "sve2_saddw_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1126",
      NULL, 0 },
    { "sve2_shadd_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:491",
      NULL, 0 },
    { "sve2_shadd_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:492",
      NULL, 0 },
    { "sve2_shadd_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:493",
      NULL, 0 },
    { "sve2_shsub_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:517",
      NULL, 0 },
    { "sve2_shsub_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:518",
      NULL, 0 },
    { "sve2_shsub_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:519",
      NULL, 0 },
    { "sve2_smaxp_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:722",
      NULL, 0 },
    { "sve2_smaxp_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:723",
      NULL, 0 },
    { "sve2_smaxp_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:724",
      NULL, 0 },
    { "sve2_sminp_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:727",
      NULL, 0 },
    { "sve2_sminp_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:728",
      NULL, 0 },
    { "sve2_sminp_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:729",
      NULL, 0 },
    { "sve2_smlal_idx_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1552",
      NULL, 0 },
    { "sve2_smlal_zzzw_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1185",
      NULL, 0 },
    { "sve2_smlsl_idx_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1559",
      NULL, 0 },
    { "sve2_smlsl_zzzw_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1195",
      NULL, 0 },
    { "sve2_smull_idx_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1598",
      NULL, 0 },
    { "sve2_smull_zzz_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1081",
      NULL, 0 },
    { "sve2_sqabs_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:981",
      NULL, 0 },
    { "sve2_sqabs_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:982",
      NULL, 0 },
    { "sve2_sqabs_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:983",
      NULL, 0 },
    { "sve2_sqadd_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:546",
      NULL, 0 },
    { "sve2_sqadd_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:547",
      NULL, 0 },
    { "sve2_sqadd_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:548",
      NULL, 0 },
    { "sve2_sqcadd_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1714",
      NULL, 0 },
    { "sve2_sqcadd_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1715",
      NULL, 0 },
    { "sve2_sqcadd_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1716",
      NULL, 0 },
    { "sve2_sqdmlal_idx_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1567",
      NULL, 0 },
    { "sve2_sqdmlal_zzzw_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1309",
      NULL, 0 },
    { "sve2_sqdmlsl_idx_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1573",
      NULL, 0 },
    { "sve2_sqdmlsl_zzzw_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1316",
      NULL, 0 },
    { "sve2_sqdmulh_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:202",
      NULL, 0 },
    { "sve2_sqdmulh_idx_h", { 3, 3, 3 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:433",
      NULL, 0 },
    { "sve2_sqdmull_idx_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1595",
      NULL, 0 },
    { "sve2_sqdmull_zzz_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1108",
      NULL, 0 },
    { "sve2_sqneg_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:990",
      NULL, 0 },
    { "sve2_sqneg_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:991",
      NULL, 0 },
    { "sve2_sqneg_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:992",
      NULL, 0 },
    { "sve2_sqrdcmlah_idx_h", { 3, 3, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1388",
      NULL, 0 },
    { "sve2_sqrdcmlah_zzzz_b", { 3, 3, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1359",
      NULL, 0 },
    { "sve2_sqrdmlah_b", { 3, 3, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:180",
      NULL, 0 },
    { "sve2_sqrdmlah_idx_h", { 3, 3, 3, 3 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1518",
      NULL, 0 },
    { "sve2_sqrdmlsh_b", { 3, 3, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:191",
      NULL, 0 },
    { "sve2_sqrdmlsh_idx_h", { 3, 3, 3, 3 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1528",
      NULL, 0 },
    { "sve2_sqrdmulh_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:212",
      NULL, 0 },
    { "sve2_sqrdmulh_idx_h", { 3, 3, 3 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/vec_helper.c:448",
      NULL, 0 },
    { "sve2_sqrshl_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:465",
      NULL, 0 },
    { "sve2_sqrshl_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:466",
      NULL, 0 },
    { "sve2_sqrshl_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:467",
      NULL, 0 },
    { "sve2_sqrshrnb_h", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2228",
      NULL, 0 },
    { "sve2_sqrshrnt_h", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2232",
      NULL, 0 },
    { "sve2_sqrshrunb_h", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2204",
      NULL, 0 },
    { "sve2_sqrshrunt_h", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2208",
      NULL, 0 },
    { "sve2_sqshl_zpzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2111",
      NULL, 0 },
    { "sve2_sqshl_zpzi_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2114",
      NULL, 0 },
    { "sve2_sqshl_zpzi_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2112",
      NULL, 0 },
    { "sve2_sqshl_zpzi_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2113",
      NULL, 0 },
    { "sve2_sqshl_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:437",
      NULL, 0 },
    { "sve2_sqshl_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:438",
      NULL, 0 },
    { "sve2_sqshl_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:439",
      NULL, 0 },
    { "sve2_sqshlu_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2140",
      NULL, 0 },
    { "sve2_sqshlu_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2143",
      NULL, 0 },
    { "sve2_sqshlu_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2141",
      NULL, 0 },
    { "sve2_sqshlu_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2142",
      NULL, 0 },
    { "sve2_sqsub_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:580",
      NULL, 0 },
    { "sve2_sqsub_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:581",
      NULL, 0 },
    { "sve2_sqsub_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:582",
      NULL, 0 },
    { "sve2_srhadd_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:504",
      NULL, 0 },
    { "sve2_srhadd_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:505",
      NULL, 0 },
    { "sve2_srhadd_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:506",
      NULL, 0 },
    { "sve2_srshl_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:407",
      NULL, 0 },
    { "sve2_srshl_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:408",
      NULL, 0 },
    { "sve2_srshl_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:409",
      NULL, 0 },
    { "sve2_srshr_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2121",
      NULL, 0 },
    { "sve2_srshr_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2124",
      NULL, 0 },
    { "sve2_srshr_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2122",
      NULL, 0 },
    { "sve2_srshr_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2123",
      NULL, 0 },
    { "sve2_ssubl_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1061",
      NULL, 0 },
    { "sve2_ssubw_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1130",
      NULL, 0 },
    { "sve2_subhnb_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2306",
      NULL, 0 },
    { "sve2_subhnt_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2310",
      NULL, 0 },
    { "sve2_suqadd_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:629",
      NULL, 0 },
    { "sve2_suqadd_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:630",
      NULL, 0 },
    { "sve2_suqadd_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:631",
      NULL, 0 },
    { "sve2_tbl_b", { 3, 3, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3056",
      NULL, 0 },
    { "sve2_tbx_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3056",
      NULL, 0 },
    { "sve2_trn_q", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3474",
      NULL, 0 },
    { "sve2_uabal_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1181",
      NULL, 0 },
    { "sve2_uabdl_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1077",
      NULL, 0 },
    { "sve2_uadalp_zpzz_d", { 3, 3, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:400",
      NULL, 0 },
    { "sve2_uadalp_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:398",
      NULL, 0 },
    { "sve2_uadalp_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:399",
      NULL, 0 },
    { "sve2_uaddl_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1069",
      NULL, 0 },
    { "sve2_uaddw_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1134",
      NULL, 0 },
    { "sve2_uhadd_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:496",
      NULL, 0 },
    { "sve2_uhadd_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:497",
      NULL, 0 },
    { "sve2_uhadd_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:498",
      NULL, 0 },
    { "sve2_uhsub_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:522",
      NULL, 0 },
    { "sve2_uhsub_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:523",
      NULL, 0 },
    { "sve2_uhsub_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:524",
      NULL, 0 },
    { "sve2_umaxp_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:712",
      NULL, 0 },
    { "sve2_umaxp_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:713",
      NULL, 0 },
    { "sve2_umaxp_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:714",
      NULL, 0 },
    { "sve2_uminp_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:717",
      NULL, 0 },
    { "sve2_uminp_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:718",
      NULL, 0 },
    { "sve2_uminp_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:719",
      NULL, 0 },
    { "sve2_umlal_idx_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1554",
      NULL, 0 },
    { "sve2_umlal_zzzw_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1189",
      NULL, 0 },
    { "sve2_umlsl_idx_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1561",
      NULL, 0 },
    { "sve2_umlsl_zzzw_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1199",
      NULL, 0 },
    { "sve2_umull_idx_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1601",
      NULL, 0 },
    { "sve2_umull_zzz_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1085",
      NULL, 0 },
    { "sve2_uqadd_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:561",
      NULL, 0 },
    { "sve2_uqadd_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:562",
      NULL, 0 },
    { "sve2_uqadd_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:563",
      NULL, 0 },
    { "sve2_uqrshl_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:481",
      NULL, 0 },
    { "sve2_uqrshl_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:482",
      NULL, 0 },
    { "sve2_uqrshl_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:483",
      NULL, 0 },
    { "sve2_uqrshrnb_h", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2252",
      NULL, 0 },
    { "sve2_uqrshrnt_h", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2256",
      NULL, 0 },
    { "sve2_uqshl_zpzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2116",
      NULL, 0 },
    { "sve2_uqshl_zpzi_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2119",
      NULL, 0 },
    { "sve2_uqshl_zpzi_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2117",
      NULL, 0 },
    { "sve2_uqshl_zpzi_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2118",
      NULL, 0 },
    { "sve2_uqshl_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:451",
      NULL, 0 },
    { "sve2_uqshl_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:452",
      NULL, 0 },
    { "sve2_uqshl_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:453",
      NULL, 0 },
    { "sve2_uqsub_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:594",
      NULL, 0 },
    { "sve2_uqsub_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:595",
      NULL, 0 },
    { "sve2_uqsub_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:596",
      NULL, 0 },
    { "sve2_urecpe_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:995",
      NULL, 0 },
    { "sve2_urhadd_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:509",
      NULL, 0 },
    { "sve2_urhadd_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:510",
      NULL, 0 },
    { "sve2_urhadd_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:511",
      NULL, 0 },
    { "sve2_urshl_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:417",
      NULL, 0 },
    { "sve2_urshl_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:418",
      NULL, 0 },
    { "sve2_urshl_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:419",
      NULL, 0 },
    { "sve2_urshr_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2126",
      NULL, 0 },
    { "sve2_urshr_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2129",
      NULL, 0 },
    { "sve2_urshr_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2127",
      NULL, 0 },
    { "sve2_urshr_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2128",
      NULL, 0 },
    { "sve2_ursqrte_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:996",
      NULL, 0 },
    { "sve2_usqadd_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:651",
      NULL, 0 },
    { "sve2_usqadd_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:652",
      NULL, 0 },
    { "sve2_usqadd_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:653",
      NULL, 0 },
    { "sve2_usubl_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1073",
      NULL, 0 },
    { "sve2_usubw_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1138",
      NULL, 0 },
    { "sve2_uzp_q", { 3, 1, 3 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3451",
      NULL, 0 },
    { "sve2_zip_q", { 3, 3, 3 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3422",
      NULL, 0 },
    { "sve_abs_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:935",
      NULL, 0 },
    { "sve_abs_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:936",
      NULL, 0 },
    { "sve_abs_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:937",
      NULL, 0 },
    { "sve_add_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:244",
      NULL, 0 },
    { "sve_add_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:245",
      NULL, 0 },
    { "sve_add_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:246",
      NULL, 0 },
    { "sve_adr_s32", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2446",
      NULL, 0 },
    { "sve_and_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:224",
      NULL, 0 },
    { "sve_and_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:225",
      NULL, 0 },
    { "sve_and_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:226",
      NULL, 0 },
    { "sve_andv_b", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1796",
      NULL, 0 },
    { "sve_andv_h", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1797",
      NULL, 0 },
    { "sve_andv_s", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1798",
      NULL, 0 },
    { "sve_asr_zpzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2090",
      NULL, 0 },
    { "sve_asr_zpzi_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2091",
      NULL, 0 },
    { "sve_asr_zpzw_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:802",
      NULL, 0 },
    { "sve_asr_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:342",
      NULL, 0 },
    { "sve_asr_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:346",
      NULL, 0 },
    { "sve_asr_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:350",
      NULL, 0 },
    { "sve_asrd_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2105",
      NULL, 0 },
    { "sve_asrd_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2108",
      NULL, 0 },
    { "sve_asrd_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2106",
      NULL, 0 },
    { "sve_asrd_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2107",
      NULL, 0 },
    { "sve_bfcvt", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4672",
      NULL, 0 },
    { "sve_bfcvtnt", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:7688",
      NULL, 0 },
    { "sve_bic_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:239",
      NULL, 0 },
    { "sve_bic_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:240",
      NULL, 0 },
    { "sve_bic_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:241",
      NULL, 0 },
    { "sve_brka_m", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4070",
      NULL, 0 },
    { "sve_brka_z", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4046",
      NULL, 0 },
    { "sve_brkas_z", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4052",
      NULL, 0 },
    { "sve_brkb_m", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4082",
      NULL, 0 },
    { "sve_brkb_z", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4058",
      NULL, 0 },
    { "sve_brkbs_z", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4064",
      NULL, 0 },
    { "sve_brkn", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4094",
      NULL, 0 },
    { "sve_brkns", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4119",
      NULL, 0 },
    { "sve_brkpa", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4002",
      NULL, 0 },
    { "sve_brkpas", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4013",
      NULL, 0 },
    { "sve_brkpb", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4024",
      NULL, 0 },
    { "sve_brkpbs", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4035",
      NULL, 0 },
    { "sve_cls_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:852",
      NULL, 0 },
    { "sve_cls_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:853",
      NULL, 0 },
    { "sve_cls_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:854",
      NULL, 0 },
    { "sve_clz_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:860",
      NULL, 0 },
    { "sve_clz_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:861",
      NULL, 0 },
    { "sve_clz_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:862",
      NULL, 0 },
    { "sve_cmpeq_ppzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3827",
      NULL, 0 },
    { "sve_cmpeq_ppzw_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3750",
      NULL, 0 },
    { "sve_cmpeq_ppzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3682",
      NULL, 0 },
    { "sve_cmpge_ppzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3842",
      NULL, 0 },
    { "sve_cmpge_ppzw_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3762",
      NULL, 0 },
    { "sve_cmpge_ppzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3697",
      NULL, 0 },
    { "sve_cmpgt_ppzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3837",
      NULL, 0 },
    { "sve_cmpgt_ppzw_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3758",
      NULL, 0 },
    { "sve_cmpgt_ppzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3692",
      NULL, 0 },
    { "sve_cmphi_ppzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3847",
      NULL, 0 },
    { "sve_cmphi_ppzw_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3766",
      NULL, 0 },
    { "sve_cmphi_ppzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3702",
      NULL, 0 },
    { "sve_cmphs_ppzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3852",
      NULL, 0 },
    { "sve_cmphs_ppzw_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3770",
      NULL, 0 },
    { "sve_cmphs_ppzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3707",
      NULL, 0 },
    { "sve_cmple_ppzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3862",
      NULL, 0 },
    { "sve_cmple_ppzw_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3778",
      NULL, 0 },
    { "sve_cmplo_ppzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3867",
      NULL, 0 },
    { "sve_cmplo_ppzw_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3782",
      NULL, 0 },
    { "sve_cmpls_ppzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3872",
      NULL, 0 },
    { "sve_cmpls_ppzw_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3786",
      NULL, 0 },
    { "sve_cmplt_ppzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3857",
      NULL, 0 },
    { "sve_cmplt_ppzw_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3774",
      NULL, 0 },
    { "sve_cmpne_ppzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3832",
      NULL, 0 },
    { "sve_cmpne_ppzw_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3754",
      NULL, 0 },
    { "sve_cmpne_ppzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3687",
      NULL, 0 },
    { "sve_cnot_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:872",
      NULL, 0 },
    { "sve_cnot_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:873",
      NULL, 0 },
    { "sve_cnot_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:874",
      NULL, 0 },
    { "sve_cnt_zpz_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:865",
      NULL, 0 },
    { "sve_cnt_zpz_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:866",
      NULL, 0 },
    { "sve_cnt_zpz_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:867",
      NULL, 0 },
    { "sve_compact_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3497",
      NULL, 0 },
    { "sve_compact_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3480",
      NULL, 0 },
    { "sve_cpy_m_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2702",
      NULL, 0 },
    { "sve_cpy_m_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2717",
      NULL, 0 },
    { "sve_cpy_m_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2732",
      NULL, 0 },
    { "sve_cpy_z_b", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2760",
      NULL, 0 },
    { "sve_cpy_z_h", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2772",
      NULL, 0 },
    { "sve_eor_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:234",
      NULL, 0 },
    { "sve_eor_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:235",
      NULL, 0 },
    { "sve_eor_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:236",
      NULL, 0 },
    { "sve_eorv_b", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1791",
      NULL, 0 },
    { "sve_eorv_h", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1792",
      NULL, 0 },
    { "sve_eorv_s", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1793",
      NULL, 0 },
    { "sve_ext", { 3, 3, 3 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2908",
      NULL, 0 },
    { "sve_fabd_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4431",
      NULL, 0 },
    { "sve_fabd_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4429",
      NULL, 0 },
    { "sve_fabd_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4430",
      NULL, 0 },
    { "sve_fabs_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:881",
      NULL, 0 },
    { "sve_fabs_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:879",
      NULL, 0 },
    { "sve_fabs_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:880",
      NULL, 0 },
    { "sve_facge_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5078",
      NULL, 0 },
    { "sve_facgt_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5079",
      NULL, 0 },
    { "sve_fadd_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4357",
      NULL, 0 },
    { "sve_fadd_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4355",
      NULL, 0 },
    { "sve_fadd_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4356",
      NULL, 0 },
    { "sve_fadda_d", { 0, 1, 1, 3 }, { 0, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4317",
      NULL, 0 },
    { "sve_fadda_h", { 0, 1, 1, 3 }, { 0, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4277",
      NULL, 0 },
    { "sve_fadda_s", { 0, 1, 1, 3 }, { 0, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4297",
      NULL, 0 },
    { "sve_fadds_h", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4474",
      NULL, 0 },
    { "sve_fadds_s", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4475",
      NULL, 0 },
    { "sve_faddv_d", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4245",
      NULL, 0 },
    { "sve_faddv_h", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4243",
      NULL, 0 },
    { "sve_faddv_s", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4244",
      NULL, 0 },
    { "sve_fcadd_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5229",
      NULL, 0 },
    { "sve_fcadd_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5267",
      NULL, 0 },
    { "sve_fcmeq0_d", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5125",
      NULL, 0 },
    { "sve_fcmeq0_h", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5125",
      NULL, 0 },
    { "sve_fcmeq0_s", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5125",
      NULL, 0 },
    { "sve_fcmeq_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5075",
      NULL, 0 },
    { "sve_fcmge0_d", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5121",
      NULL, 0 },
    { "sve_fcmge0_h", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5121",
      NULL, 0 },
    { "sve_fcmge0_s", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5121",
      NULL, 0 },
    { "sve_fcmge_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5073",
      NULL, 0 },
    { "sve_fcmgt0_d", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5122",
      NULL, 0 },
    { "sve_fcmgt0_h", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5122",
      NULL, 0 },
    { "sve_fcmgt0_s", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5122",
      NULL, 0 },
    { "sve_fcmgt_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5074",
      NULL, 0 },
    { "sve_fcmla_zpzzz_h", { 3, 1, 1, 1, 1, 3 }, { 1, 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5347",
      NULL, 0 },
    { "sve_fcmle0_d", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5123",
      NULL, 0 },
    { "sve_fcmle0_h", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5123",
      NULL, 0 },
    { "sve_fcmle0_s", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5123",
      NULL, 0 },
    { "sve_fcmlt0_d", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5124",
      NULL, 0 },
    { "sve_fcmlt0_h", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5124",
      NULL, 0 },
    { "sve_fcmlt0_s", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5124",
      NULL, 0 },
    { "sve_fcmne0_d", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5126",
      NULL, 0 },
    { "sve_fcmne0_h", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5126",
      NULL, 0 },
    { "sve_fcmne0_s", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5126",
      NULL, 0 },
    { "sve_fcmne_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5076",
      NULL, 0 },
    { "sve_fcmuo_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5077",
      NULL, 0 },
    { "sve_fcvt_dh", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4673",
      NULL, 0 },
    { "sve_fcvt_ds", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4675",
      NULL, 0 },
    { "sve_fcvt_hs", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4671",
      NULL, 0 },
    { "sve_fcvt_sh", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4670",
      NULL, 0 },
    { "sve_fdiv_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4369",
      NULL, 0 },
    { "sve_fdiv_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4367",
      NULL, 0 },
    { "sve_fdiv_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4368",
      NULL, 0 },
    { "sve_fexpa_d", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2518",
      NULL, 0 },
    { "sve_fexpa_h", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2466",
      NULL, 0 },
    { "sve_fexpa_s", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2486",
      NULL, 0 },
    { "sve_fmax_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4377",
      NULL, 0 },
    { "sve_fmax_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4375",
      NULL, 0 },
    { "sve_fmax_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4376",
      NULL, 0 },
    { "sve_fmaxnms_h", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4505",
      NULL, 0 },
    { "sve_fmaxnms_s", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4506",
      NULL, 0 },
    { "sve_fmaxnmv_d", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4254",
      NULL, 0 },
    { "sve_fmaxnmv_h", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4252",
      NULL, 0 },
    { "sve_fmaxnmv_s", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4253",
      NULL, 0 },
    { "sve_fmaxnum_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4393",
      NULL, 0 },
    { "sve_fmaxnum_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4391",
      NULL, 0 },
    { "sve_fmaxnum_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4392",
      NULL, 0 },
    { "sve_fmaxs_h", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4513",
      NULL, 0 },
    { "sve_fmaxs_s", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4514",
      NULL, 0 },
    { "sve_fmaxv_d", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4262",
      NULL, 0 },
    { "sve_fmaxv_h", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4260",
      NULL, 0 },
    { "sve_fmaxv_s", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4261",
      NULL, 0 },
    { "sve_fmin_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4373",
      NULL, 0 },
    { "sve_fmin_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4371",
      NULL, 0 },
    { "sve_fmin_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4372",
      NULL, 0 },
    { "sve_fminnms_h", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4509",
      NULL, 0 },
    { "sve_fminnms_s", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4510",
      NULL, 0 },
    { "sve_fminnmv_d", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4250",
      NULL, 0 },
    { "sve_fminnmv_h", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4248",
      NULL, 0 },
    { "sve_fminnmv_s", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4249",
      NULL, 0 },
    { "sve_fminnum_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4389",
      NULL, 0 },
    { "sve_fminnum_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4387",
      NULL, 0 },
    { "sve_fminnum_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4388",
      NULL, 0 },
    { "sve_fmins_h", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4517",
      NULL, 0 },
    { "sve_fmins_s", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4518",
      NULL, 0 },
    { "sve_fminv_d", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4258",
      NULL, 0 },
    { "sve_fminv_h", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4256",
      NULL, 0 },
    { "sve_fminv_s", { 1, 1, 3 }, { 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4257",
      NULL, 0 },
    { "sve_fmla_zpzzz_h", { 3, 1, 1, 1, 1, 3 }, { 1, 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4840",
      NULL, 0 },
    { "sve_fmls_zpzzz_h", { 3, 1, 1, 1, 1, 3 }, { 1, 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4846",
      NULL, 0 },
    { "sve_fmul_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4365",
      NULL, 0 },
    { "sve_fmul_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4363",
      NULL, 0 },
    { "sve_fmul_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4364",
      NULL, 0 },
    { "sve_fmuls_h", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4482",
      NULL, 0 },
    { "sve_fmuls_s", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4483",
      NULL, 0 },
    { "sve_fmulx_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4448",
      NULL, 0 },
    { "sve_fmulx_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4446",
      NULL, 0 },
    { "sve_fmulx_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4447",
      NULL, 0 },
    { "sve_fneg_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:895",
      NULL, 0 },
    { "sve_fneg_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:893",
      NULL, 0 },
    { "sve_fneg_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:894",
      NULL, 0 },
    { "sve_fnmla_zpzzz_h", { 3, 1, 1, 1, 1, 3 }, { 1, 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4852",
      NULL, 0 },
    { "sve_fnmls_zpzzz_h", { 3, 1, 1, 1, 1, 3 }, { 1, 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4858",
      NULL, 0 },
    { "sve_frecpx_d", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4704",
      NULL, 0 },
    { "sve_frecpx_h", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4702",
      NULL, 0 },
    { "sve_frecpx_s", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4703",
      NULL, 0 },
    { "sve_frint_d", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4696",
      NULL, 0 },
    { "sve_frint_h", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4694",
      NULL, 0 },
    { "sve_frint_s", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4695",
      NULL, 0 },
    { "sve_frintx_d", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4700",
      NULL, 0 },
    { "sve_frintx_h", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4698",
      NULL, 0 },
    { "sve_frintx_s", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4699",
      NULL, 0 },
    { "sve_fscalbn_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4444",
      NULL, 0 },
    { "sve_fscalbn_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4442",
      NULL, 0 },
    { "sve_fscalbn_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4443",
      NULL, 0 },
    { "sve_fsqrt_d", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4708",
      NULL, 0 },
    { "sve_fsqrt_h", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4706",
      NULL, 0 },
    { "sve_fsqrt_s", { 3, 1, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4707",
      NULL, 0 },
    { "sve_fsub_d", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4361",
      NULL, 0 },
    { "sve_fsub_h", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4359",
      NULL, 0 },
    { "sve_fsub_s", { 3, 1, 1, 1, 3 }, { 1, 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4360",
      NULL, 0 },
    { "sve_fsubrs_h", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4501",
      NULL, 0 },
    { "sve_fsubrs_s", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4502",
      NULL, 0 },
    { "sve_fsubs_h", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4478",
      NULL, 0 },
    { "sve_fsubs_s", { 3, 1, 1, 0, 3 }, { 1, 1, 1, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4479",
      NULL, 0 },
    { "sve_ftmad_h", { 3, 3, 1, 3 }, { 1, 1, 1, 18 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:5130",
      NULL, 0 },
    { "sve_ftssel_h", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2556",
      NULL, 0 },
    { "sve_index_b", { 2 }, { 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2386",
      NULL, 0 },
    { "sve_insr_b", { 3, 3 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2937",
      NULL, 0 },
    { "sve_insr_h", { 3, 3 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2938",
      NULL, 0 },
    { "sve_last_active_element", { 1 }, { 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3518",
      NULL, 0 },
    { "sve_ld1bb_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld1bb_r_env, ARRAY_SIZE(dfu_sve_ld1bb_r_env), true,
      "../target/arm/tcg/sve_helper.c:6065",
      dfu_sve_ld1bb_r_acc, ARRAY_SIZE(dfu_sve_ld1bb_r_acc) },
    { "sve_ld1bds_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld1bds_r_env, ARRAY_SIZE(dfu_sve_ld1bds_r_env), true,
      "../target/arm/tcg/sve_helper.c:6071",
      dfu_sve_ld1bds_r_acc, ARRAY_SIZE(dfu_sve_ld1bds_r_acc) },
    { "sve_ld1dd_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld1dd_le_r_env, ARRAY_SIZE(dfu_sve_ld1dd_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6083",
      dfu_sve_ld1dd_le_r_acc, ARRAY_SIZE(dfu_sve_ld1dd_le_r_acc) },
    { "sve_ld1hds_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld1hds_le_r_env, ARRAY_SIZE(dfu_sve_ld1hds_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6077",
      dfu_sve_ld1hds_le_r_acc, ARRAY_SIZE(dfu_sve_ld1hds_le_r_acc) },
    { "sve_ld1hh_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld1hh_le_r_env, ARRAY_SIZE(dfu_sve_ld1hh_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6073",
      dfu_sve_ld1hh_le_r_acc, ARRAY_SIZE(dfu_sve_ld1hh_le_r_acc) },
    { "sve_ld1sds_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld1sds_le_r_env, ARRAY_SIZE(dfu_sve_ld1sds_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6081",
      dfu_sve_ld1sds_le_r_acc, ARRAY_SIZE(dfu_sve_ld1sds_le_r_acc) },
    { "sve_ld1ss_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld1ss_le_r_env, ARRAY_SIZE(dfu_sve_ld1ss_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6079",
      dfu_sve_ld1ss_le_r_acc, ARRAY_SIZE(dfu_sve_ld1ss_le_r_acc) },
    { "sve_ld2bb_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld2bb_r_env, ARRAY_SIZE(dfu_sve_ld2bb_r_env), true,
      "../target/arm/tcg/sve_helper.c:6128",
      dfu_sve_ld2bb_r_acc, ARRAY_SIZE(dfu_sve_ld2bb_r_acc) },
    { "sve_ld2dd_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld2dd_le_r_env, ARRAY_SIZE(dfu_sve_ld2dd_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6140",
      dfu_sve_ld2dd_le_r_acc, ARRAY_SIZE(dfu_sve_ld2dd_le_r_acc) },
    { "sve_ld2hh_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld2hh_le_r_env, ARRAY_SIZE(dfu_sve_ld2hh_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6132",
      dfu_sve_ld2hh_le_r_acc, ARRAY_SIZE(dfu_sve_ld2hh_le_r_acc) },
    { "sve_ld2ss_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld2ss_le_r_env, ARRAY_SIZE(dfu_sve_ld2ss_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6136",
      dfu_sve_ld2ss_le_r_acc, ARRAY_SIZE(dfu_sve_ld2ss_le_r_acc) },
    { "sve_ld3bb_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld3bb_r_env, ARRAY_SIZE(dfu_sve_ld3bb_r_env), true,
      "../target/arm/tcg/sve_helper.c:6129",
      dfu_sve_ld3bb_r_acc, ARRAY_SIZE(dfu_sve_ld3bb_r_acc) },
    { "sve_ld3dd_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld3dd_le_r_env, ARRAY_SIZE(dfu_sve_ld3dd_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6141",
      dfu_sve_ld3dd_le_r_acc, ARRAY_SIZE(dfu_sve_ld3dd_le_r_acc) },
    { "sve_ld3hh_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld3hh_le_r_env, ARRAY_SIZE(dfu_sve_ld3hh_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6133",
      dfu_sve_ld3hh_le_r_acc, ARRAY_SIZE(dfu_sve_ld3hh_le_r_acc) },
    { "sve_ld3ss_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld3ss_le_r_env, ARRAY_SIZE(dfu_sve_ld3ss_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6137",
      dfu_sve_ld3ss_le_r_acc, ARRAY_SIZE(dfu_sve_ld3ss_le_r_acc) },
    { "sve_ld4bb_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld4bb_r_env, ARRAY_SIZE(dfu_sve_ld4bb_r_env), true,
      "../target/arm/tcg/sve_helper.c:6130",
      dfu_sve_ld4bb_r_acc, ARRAY_SIZE(dfu_sve_ld4bb_r_acc) },
    { "sve_ld4dd_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld4dd_le_r_env, ARRAY_SIZE(dfu_sve_ld4dd_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6142",
      dfu_sve_ld4dd_le_r_acc, ARRAY_SIZE(dfu_sve_ld4dd_le_r_acc) },
    { "sve_ld4hh_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld4hh_le_r_env, ARRAY_SIZE(dfu_sve_ld4hh_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6134",
      dfu_sve_ld4hh_le_r_acc, ARRAY_SIZE(dfu_sve_ld4hh_le_r_acc) },
    { "sve_ld4ss_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ld4ss_le_r_env, ARRAY_SIZE(dfu_sve_ld4ss_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6138",
      dfu_sve_ld4ss_le_r_acc, ARRAY_SIZE(dfu_sve_ld4ss_le_r_acc) },
    { "sve_ldbss_zsu", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldbss_zsu_env, ARRAY_SIZE(dfu_sve_ldbss_zsu_env), true,
      "../target/arm/tcg/sve_helper.c:6865",
      dfu_sve_ldbss_zsu_acc, ARRAY_SIZE(dfu_sve_ldbss_zsu_acc) },
    { "sve_ldbsu_zsu", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldbsu_zsu_env, ARRAY_SIZE(dfu_sve_ldbsu_zsu_env), true,
      "../target/arm/tcg/sve_helper.c:6859",
      dfu_sve_ldbsu_zsu_acc, ARRAY_SIZE(dfu_sve_ldbsu_zsu_acc) },
    { "sve_lddd_le_zd", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_lddd_le_zd_env, ARRAY_SIZE(dfu_sve_lddd_le_zd_env), true,
      "../target/arm/tcg/sve_helper.c:6917",
      dfu_sve_lddd_le_zd_acc, ARRAY_SIZE(dfu_sve_lddd_le_zd_acc) },
#if defined(TARGET_AARCH64)
    { "sve_ldff1bds_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ldff1bds_r_env, ARRAY_SIZE(dfu_sve_ldff1bds_r_env), true,
      "../target/arm/tcg/sve_helper.c:6466",
      dfu_sve_ldff1bds_r_acc, ARRAY_SIZE(dfu_sve_ldff1bds_r_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldff1dd_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ldff1dd_le_r_env, ARRAY_SIZE(dfu_sve_ldff1dd_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6478",
      dfu_sve_ldff1dd_le_r_acc, ARRAY_SIZE(dfu_sve_ldff1dd_le_r_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldff1hds_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ldff1hds_le_r_env, ARRAY_SIZE(dfu_sve_ldff1hds_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6472",
      dfu_sve_ldff1hds_le_r_acc, ARRAY_SIZE(dfu_sve_ldff1hds_le_r_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldff1sds_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ldff1sds_le_r_env, ARRAY_SIZE(dfu_sve_ldff1sds_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6476",
      dfu_sve_ldff1sds_le_r_acc, ARRAY_SIZE(dfu_sve_ldff1sds_le_r_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldffbss_zsu", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldffbss_zsu_env, ARRAY_SIZE(dfu_sve_ldffbss_zsu_env), true,
      "../target/arm/tcg/sve_helper.c:7079",
      dfu_sve_ldffbss_zsu_acc, ARRAY_SIZE(dfu_sve_ldffbss_zsu_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldffbsu_zsu", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldffbsu_zsu_env, ARRAY_SIZE(dfu_sve_ldffbsu_zsu_env), true,
      "../target/arm/tcg/sve_helper.c:7073",
      dfu_sve_ldffbsu_zsu_acc, ARRAY_SIZE(dfu_sve_ldffbsu_zsu_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldffdd_le_zd", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldffdd_le_zd_env, ARRAY_SIZE(dfu_sve_ldffdd_le_zd_env), true,
      "../target/arm/tcg/sve_helper.c:7131",
      dfu_sve_ldffdd_le_zd_acc, ARRAY_SIZE(dfu_sve_ldffdd_le_zd_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldffhss_le_zsu", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldffhss_le_zsu_env, ARRAY_SIZE(dfu_sve_ldffhss_le_zsu_env), true,
      "../target/arm/tcg/sve_helper.c:7097",
      dfu_sve_ldffhss_le_zsu_acc, ARRAY_SIZE(dfu_sve_ldffhss_le_zsu_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldffhsu_le_zsu", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldffhsu_le_zsu_env, ARRAY_SIZE(dfu_sve_ldffhsu_le_zsu_env), true,
      "../target/arm/tcg/sve_helper.c:7085",
      dfu_sve_ldffhsu_le_zsu_acc, ARRAY_SIZE(dfu_sve_ldffhsu_le_zsu_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldffsds_le_zd", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldffsds_le_zd_env, ARRAY_SIZE(dfu_sve_ldffsds_le_zd_env), true,
      "../target/arm/tcg/sve_helper.c:7123",
      dfu_sve_ldffsds_le_zd_acc, ARRAY_SIZE(dfu_sve_ldffsds_le_zd_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldffsds_le_zsu", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldffsds_le_zsu_env, ARRAY_SIZE(dfu_sve_ldffsds_le_zsu_env), true,
      "../target/arm/tcg/sve_helper.c:7121",
      dfu_sve_ldffsds_le_zsu_acc, ARRAY_SIZE(dfu_sve_ldffsds_le_zsu_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldffss_le_zsu", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldffss_le_zsu_env, ARRAY_SIZE(dfu_sve_ldffss_le_zsu_env), true,
      "../target/arm/tcg/sve_helper.c:7109",
      dfu_sve_ldffss_le_zsu_acc, ARRAY_SIZE(dfu_sve_ldffss_le_zsu_acc) },
#endif
    { "sve_ldhss_le_zsu", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldhss_le_zsu_env, ARRAY_SIZE(dfu_sve_ldhss_le_zsu_env), true,
      "../target/arm/tcg/sve_helper.c:6883",
      dfu_sve_ldhss_le_zsu_acc, ARRAY_SIZE(dfu_sve_ldhss_le_zsu_acc) },
    { "sve_ldhsu_le_zsu", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldhsu_le_zsu_env, ARRAY_SIZE(dfu_sve_ldhsu_le_zsu_env), true,
      "../target/arm/tcg/sve_helper.c:6871",
      dfu_sve_ldhsu_le_zsu_acc, ARRAY_SIZE(dfu_sve_ldhsu_le_zsu_acc) },
#if defined(TARGET_AARCH64)
    { "sve_ldnf1bb_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ldnf1bb_r_env, ARRAY_SIZE(dfu_sve_ldnf1bb_r_env), true,
      "../target/arm/tcg/sve_helper.c:6460",
      dfu_sve_ldnf1bb_r_acc, ARRAY_SIZE(dfu_sve_ldnf1bb_r_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldnf1bds_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ldnf1bds_r_env, ARRAY_SIZE(dfu_sve_ldnf1bds_r_env), true,
      "../target/arm/tcg/sve_helper.c:6466",
      dfu_sve_ldnf1bds_r_acc, ARRAY_SIZE(dfu_sve_ldnf1bds_r_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldnf1dd_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ldnf1dd_le_r_env, ARRAY_SIZE(dfu_sve_ldnf1dd_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6478",
      dfu_sve_ldnf1dd_le_r_acc, ARRAY_SIZE(dfu_sve_ldnf1dd_le_r_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldnf1hds_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ldnf1hds_le_r_env, ARRAY_SIZE(dfu_sve_ldnf1hds_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6472",
      dfu_sve_ldnf1hds_le_r_acc, ARRAY_SIZE(dfu_sve_ldnf1hds_le_r_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldnf1hh_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ldnf1hh_le_r_env, ARRAY_SIZE(dfu_sve_ldnf1hh_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6468",
      dfu_sve_ldnf1hh_le_r_acc, ARRAY_SIZE(dfu_sve_ldnf1hh_le_r_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldnf1sds_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ldnf1sds_le_r_env, ARRAY_SIZE(dfu_sve_ldnf1sds_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6476",
      dfu_sve_ldnf1sds_le_r_acc, ARRAY_SIZE(dfu_sve_ldnf1sds_le_r_acc) },
#endif
#if defined(TARGET_AARCH64)
    { "sve_ldnf1ss_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_ldnf1ss_le_r_env, ARRAY_SIZE(dfu_sve_ldnf1ss_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6474",
      dfu_sve_ldnf1ss_le_r_acc, ARRAY_SIZE(dfu_sve_ldnf1ss_le_r_acc) },
#endif
    { "sve_ldsds_le_zd", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldsds_le_zd_env, ARRAY_SIZE(dfu_sve_ldsds_le_zd_env), true,
      "../target/arm/tcg/sve_helper.c:6909",
      dfu_sve_ldsds_le_zd_acc, ARRAY_SIZE(dfu_sve_ldsds_le_zd_acc) },
    { "sve_ldsds_le_zsu", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldsds_le_zsu_env, ARRAY_SIZE(dfu_sve_ldsds_le_zsu_env), true,
      "../target/arm/tcg/sve_helper.c:6907",
      dfu_sve_ldsds_le_zsu_acc, ARRAY_SIZE(dfu_sve_ldsds_le_zsu_acc) },
    { "sve_ldss_le_zsu", { 0, 2, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_ldss_le_zsu_env, ARRAY_SIZE(dfu_sve_ldss_le_zsu_env), true,
      "../target/arm/tcg/sve_helper.c:6895",
      dfu_sve_ldss_le_zsu_acc, ARRAY_SIZE(dfu_sve_ldss_le_zsu_acc) },
    { "sve_lsl_zpzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2100",
      NULL, 0 },
    { "sve_lsl_zpzi_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2101",
      NULL, 0 },
    { "sve_lsl_zpzw_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:804",
      NULL, 0 },
    { "sve_lsl_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:344",
      NULL, 0 },
    { "sve_lsl_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:348",
      NULL, 0 },
    { "sve_lsl_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:352",
      NULL, 0 },
    { "sve_lsr_zpzi_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2095",
      NULL, 0 },
    { "sve_lsr_zpzi_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2096",
      NULL, 0 },
    { "sve_lsr_zpzw_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:803",
      NULL, 0 },
    { "sve_lsr_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:343",
      NULL, 0 },
    { "sve_lsr_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:347",
      NULL, 0 },
    { "sve_lsr_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:351",
      NULL, 0 },
    { "sve_mla_b", { 3, 1, 1, 1, 1 }, { 1, 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2369",
      NULL, 0 },
    { "sve_mls_b", { 3, 1, 1, 1, 1 }, { 1, 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2370",
      NULL, 0 },
    { "sve_movz_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1978",
      NULL, 0 },
    { "sve_movz_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2014",
      NULL, 0 },
    { "sve_movz_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1990",
      NULL, 0 },
    { "sve_movz_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2002",
      NULL, 0 },
    { "sve_mul_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:315",
      NULL, 0 },
    { "sve_mul_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:316",
      NULL, 0 },
    { "sve_mul_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:317",
      NULL, 0 },
    { "sve_neg_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:942",
      NULL, 0 },
    { "sve_neg_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:943",
      NULL, 0 },
    { "sve_neg_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:944",
      NULL, 0 },
    { "sve_not_zpz_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:907",
      NULL, 0 },
    { "sve_not_zpz_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:908",
      NULL, 0 },
    { "sve_not_zpz_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:909",
      NULL, 0 },
    { "sve_orr_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:229",
      NULL, 0 },
    { "sve_orr_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:230",
      NULL, 0 },
    { "sve_orr_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:231",
      NULL, 0 },
    { "sve_orv_b", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1786",
      NULL, 0 },
    { "sve_orv_h", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1787",
      NULL, 0 },
    { "sve_orv_s", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1788",
      NULL, 0 },
    { "sve_pfirst", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1906",
      NULL, 0 },
    { "sve_pnext", { 3, 3 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1930",
      NULL, 0 },
    { "sve_predtest1", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:93",
      NULL, 0 },
    { "sve_punpk_p", { 3, 3 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3347",
      NULL, 0 },
    { "sve_rbit_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:972",
      NULL, 0 },
    { "sve_rbit_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:973",
      NULL, 0 },
    { "sve_rbit_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:974",
      NULL, 0 },
    { "sve_rev_b", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2944",
      NULL, 0 },
    { "sve_rev_h", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2955",
      NULL, 0 },
    { "sve_rev_p", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3317",
      NULL, 0 },
    { "sve_rev_s", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2966",
      NULL, 0 },
    { "sve_revb_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:949",
      NULL, 0 },
    { "sve_revb_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:947",
      NULL, 0 },
    { "sve_revb_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:948",
      NULL, 0 },
    { "sve_revh_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:952",
      NULL, 0 },
    { "sve_revh_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:951",
      NULL, 0 },
    { "sve_revw_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:954",
      NULL, 0 },
    { "sve_sabd_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:274",
      NULL, 0 },
    { "sve_sabd_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:275",
      NULL, 0 },
    { "sve_sabd_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:276",
      NULL, 0 },
    { "sve_saddv_b", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1801",
      NULL, 0 },
    { "sve_saddv_h", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1802",
      NULL, 0 },
    { "sve_saddv_s", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1803",
      NULL, 0 },
    { "sve_sdiv_zpzz_d", { 3, 3, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:331",
      NULL, 0 },
    { "sve_sdiv_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:330",
      NULL, 0 },
    { "sve_sel_zpzz_b", { 3, 3, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3563",
      NULL, 0 },
    { "sve_sel_zpzz_h", { 3, 3, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3577",
      NULL, 0 },
    { "sve_sel_zpzz_s", { 3, 3, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3591",
      NULL, 0 },
    { "sve_smax_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:254",
      NULL, 0 },
    { "sve_smax_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:255",
      NULL, 0 },
    { "sve_smax_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:256",
      NULL, 0 },
    { "sve_smaxv_b", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1810",
      NULL, 0 },
    { "sve_smaxv_h", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1811",
      NULL, 0 },
    { "sve_smaxv_s", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1812",
      NULL, 0 },
    { "sve_smin_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:264",
      NULL, 0 },
    { "sve_smin_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:265",
      NULL, 0 },
    { "sve_smin_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:266",
      NULL, 0 },
    { "sve_sminv_b", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1820",
      NULL, 0 },
    { "sve_sminv_h", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1821",
      NULL, 0 },
    { "sve_sminv_s", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1822",
      NULL, 0 },
    { "sve_smulh_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:320",
      NULL, 0 },
    { "sve_smulh_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:321",
      NULL, 0 },
    { "sve_smulh_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:322",
      NULL, 0 },
    { "sve_splice", { 3, 3, 3, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3526",
      NULL, 0 },
    { "sve_sqaddi_b", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2614",
      NULL, 0 },
    { "sve_sqaddi_d", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2641",
      NULL, 0 },
    { "sve_sqaddi_h", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2623",
      NULL, 0 },
    { "sve_sqaddi_s", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2632",
      NULL, 0 },
    { "sve_st1bb_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st1bb_r_env, ARRAY_SIZE(dfu_sve_st1bb_r_env), true,
      "../target/arm/tcg/sve_helper.c:6681",
      dfu_sve_st1bb_r_acc, ARRAY_SIZE(dfu_sve_st1bb_r_acc) },
    { "sve_st1hh_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st1hh_le_r_env, ARRAY_SIZE(dfu_sve_st1hh_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6689",
      dfu_sve_st1hh_le_r_acc, ARRAY_SIZE(dfu_sve_st1hh_le_r_acc) },
    { "sve_st1ss_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st1ss_le_r_env, ARRAY_SIZE(dfu_sve_st1ss_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6696",
      dfu_sve_st1ss_le_r_acc, ARRAY_SIZE(dfu_sve_st1ss_le_r_acc) },
    { "sve_st2bb_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st2bb_r_env, ARRAY_SIZE(dfu_sve_st2bb_r_env), true,
      "../target/arm/tcg/sve_helper.c:6685",
      dfu_sve_st2bb_r_acc, ARRAY_SIZE(dfu_sve_st2bb_r_acc) },
    { "sve_st2dd_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st2dd_le_r_env, ARRAY_SIZE(dfu_sve_st2dd_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6703",
      dfu_sve_st2dd_le_r_acc, ARRAY_SIZE(dfu_sve_st2dd_le_r_acc) },
    { "sve_st2hh_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st2hh_le_r_env, ARRAY_SIZE(dfu_sve_st2hh_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6692",
      dfu_sve_st2hh_le_r_acc, ARRAY_SIZE(dfu_sve_st2hh_le_r_acc) },
    { "sve_st2ss_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st2ss_le_r_env, ARRAY_SIZE(dfu_sve_st2ss_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6698",
      dfu_sve_st2ss_le_r_acc, ARRAY_SIZE(dfu_sve_st2ss_le_r_acc) },
    { "sve_st3bb_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st3bb_r_env, ARRAY_SIZE(dfu_sve_st3bb_r_env), true,
      "../target/arm/tcg/sve_helper.c:6686",
      dfu_sve_st3bb_r_acc, ARRAY_SIZE(dfu_sve_st3bb_r_acc) },
    { "sve_st3dd_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st3dd_le_r_env, ARRAY_SIZE(dfu_sve_st3dd_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6704",
      dfu_sve_st3dd_le_r_acc, ARRAY_SIZE(dfu_sve_st3dd_le_r_acc) },
    { "sve_st3hh_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st3hh_le_r_env, ARRAY_SIZE(dfu_sve_st3hh_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6693",
      dfu_sve_st3hh_le_r_acc, ARRAY_SIZE(dfu_sve_st3hh_le_r_acc) },
    { "sve_st3ss_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st3ss_le_r_env, ARRAY_SIZE(dfu_sve_st3ss_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6699",
      dfu_sve_st3ss_le_r_acc, ARRAY_SIZE(dfu_sve_st3ss_le_r_acc) },
    { "sve_st4bb_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st4bb_r_env, ARRAY_SIZE(dfu_sve_st4bb_r_env), true,
      "../target/arm/tcg/sve_helper.c:6687",
      dfu_sve_st4bb_r_acc, ARRAY_SIZE(dfu_sve_st4bb_r_acc) },
    { "sve_st4dd_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st4dd_le_r_env, ARRAY_SIZE(dfu_sve_st4dd_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6705",
      dfu_sve_st4dd_le_r_acc, ARRAY_SIZE(dfu_sve_st4dd_le_r_acc) },
    { "sve_st4hh_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st4hh_le_r_env, ARRAY_SIZE(dfu_sve_st4hh_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6694",
      dfu_sve_st4hh_le_r_acc, ARRAY_SIZE(dfu_sve_st4hh_le_r_acc) },
    { "sve_st4ss_le_r", { 0, 1 }, { 0, 1 },
      dfu_sve_st4ss_le_r_env, ARRAY_SIZE(dfu_sve_st4ss_le_r_env), true,
      "../target/arm/tcg/sve_helper.c:6700",
      dfu_sve_st4ss_le_r_acc, ARRAY_SIZE(dfu_sve_st4ss_le_r_acc) },
    { "sve_stbd_zd", { 0, 1, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_stbd_zd_env, ARRAY_SIZE(dfu_sve_stbd_zd_env), true,
      "../target/arm/tcg/sve_helper.c:7301",
      dfu_sve_stbd_zd_acc, ARRAY_SIZE(dfu_sve_stbd_zd_acc) },
    { "sve_stdd_le_zd", { 0, 1, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_stdd_le_zd_env, ARRAY_SIZE(dfu_sve_stdd_le_zd_env), true,
      "../target/arm/tcg/sve_helper.c:7306",
      dfu_sve_stdd_le_zd_acc, ARRAY_SIZE(dfu_sve_stdd_le_zd_acc) },
    { "sve_stsd_le_zd", { 0, 1, 1, 1 }, { 0, 1, 1, 1 },
      dfu_sve_stsd_le_zd_env, ARRAY_SIZE(dfu_sve_stsd_le_zd_env), true,
      "../target/arm/tcg/sve_helper.c:7304",
      dfu_sve_stsd_le_zd_acc, ARRAY_SIZE(dfu_sve_stsd_le_zd_acc) },
    { "sve_sub_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:249",
      NULL, 0 },
    { "sve_sub_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:250",
      NULL, 0 },
    { "sve_sub_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:251",
      NULL, 0 },
    { "sve_sunpk_d", { 3, 3 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3080",
      NULL, 0 },
    { "sve_sunpk_h", { 3, 3 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3078",
      NULL, 0 },
    { "sve_sunpk_s", { 3, 3 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3079",
      NULL, 0 },
    { "sve_sxtb_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:922",
      NULL, 0 },
    { "sve_sxtb_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:919",
      NULL, 0 },
    { "sve_sxtb_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:920",
      NULL, 0 },
    { "sve_sxth_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:923",
      NULL, 0 },
    { "sve_sxth_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:921",
      NULL, 0 },
    { "sve_sxtw_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:924",
      NULL, 0 },
    { "sve_tbl_b", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3056",
      NULL, 0 },
    { "sve_trn_b", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3470",
      NULL, 0 },
    { "sve_trn_p", { 3, 3, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3267",
      NULL, 0 },
    { "sve_uabd_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:279",
      NULL, 0 },
    { "sve_uabd_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:280",
      NULL, 0 },
    { "sve_uabd_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:281",
      NULL, 0 },
    { "sve_uaddv_b", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1805",
      NULL, 0 },
    { "sve_uaddv_h", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1806",
      NULL, 0 },
    { "sve_uaddv_s", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1807",
      NULL, 0 },
    { "sve_udiv_zpzz_d", { 3, 3, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:334",
      NULL, 0 },
    { "sve_udiv_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:333",
      NULL, 0 },
    { "sve_umax_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:259",
      NULL, 0 },
    { "sve_umax_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:260",
      NULL, 0 },
    { "sve_umax_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:261",
      NULL, 0 },
    { "sve_umaxv_b", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1815",
      NULL, 0 },
    { "sve_umaxv_h", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1816",
      NULL, 0 },
    { "sve_umaxv_s", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1817",
      NULL, 0 },
    { "sve_umin_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:269",
      NULL, 0 },
    { "sve_umin_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:270",
      NULL, 0 },
    { "sve_umin_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:271",
      NULL, 0 },
    { "sve_uminv_b", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1825",
      NULL, 0 },
    { "sve_uminv_h", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1826",
      NULL, 0 },
    { "sve_uminv_s", { 1, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:1827",
      NULL, 0 },
    { "sve_umulh_zpzz_b", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:325",
      NULL, 0 },
    { "sve_umulh_zpzz_h", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:326",
      NULL, 0 },
    { "sve_umulh_zpzz_s", { 3, 1, 1, 1 }, { 1, 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:327",
      NULL, 0 },
    { "sve_uqaddi_b", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2654",
      NULL, 0 },
    { "sve_uqaddi_d", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2681",
      NULL, 0 },
    { "sve_uqaddi_h", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2663",
      NULL, 0 },
    { "sve_uqaddi_s", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2672",
      NULL, 0 },
    { "sve_uqsubi_d", { 3, 1 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:2690",
      NULL, 0 },
    { "sve_uunpk_d", { 3, 3 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3084",
      NULL, 0 },
    { "sve_uunpk_h", { 3, 3 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3082",
      NULL, 0 },
    { "sve_uunpk_s", { 3, 3 }, { 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3083",
      NULL, 0 },
    { "sve_uxtb_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:929",
      NULL, 0 },
    { "sve_uxtb_h", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:926",
      NULL, 0 },
    { "sve_uxtb_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:927",
      NULL, 0 },
    { "sve_uxth_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:930",
      NULL, 0 },
    { "sve_uxth_s", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:928",
      NULL, 0 },
    { "sve_uxtw_d", { 3, 1, 1 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:931",
      NULL, 0 },
    { "sve_uzp_b", { 3, 1, 3 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3447",
      NULL, 0 },
    { "sve_uzp_p", { 3, 3, 3 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3198",
      NULL, 0 },
    { "sve_whileg", { 2 }, { 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4169",
      NULL, 0 },
    { "sve_whilel", { 2 }, { 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:4143",
      NULL, 0 },
    { "sve_zip_b", { 3, 3, 3 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3418",
      NULL, 0 },
    { "sve_zip_p", { 3, 3, 3 }, { 1, 1, 1 },
      NULL, 0, true,
      "../target/arm/tcg/sve_helper.c:3134",
      NULL, 0 },
    { "tidcp_el0", { 0 }, { 0 },
      dfu_tidcp_el0_env, ARRAY_SIZE(dfu_tidcp_el0_env), true,
      "../target/arm/tcg/op_helper.c:956",
      NULL, 0 },
    { "udiv64", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:48",
      NULL, 0 },
    { "unaligned_access", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:1392",
      NULL, 0 },
    { "vfp_addd", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:278",
      NULL, 0 },
    { "vfp_addh", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:278",
      NULL, 0 },
    { "vfp_adds", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:278",
      NULL, 0 },
    { "vfp_cmpd_a64", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:161",
      NULL, 0 },
    { "vfp_cmpes_a64", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:156",
      NULL, 0 },
    { "vfp_cmps_a64", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/helper-a64.c:151",
      NULL, 0 },
    { "vfp_divd", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:281",
      NULL, 0 },
    { "vfp_divs", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:281",
      NULL, 0 },
    { "vfp_fcvt_f16_to_f32", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:488",
      NULL, 0 },
    { "vfp_fcvt_f32_to_f16", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:501",
      NULL, 0 },
    { "vfp_fcvt_f64_to_f16", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:527",
      NULL, 0 },
    { "vfp_fcvtds", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:377",
      NULL, 0 },
    { "vfp_fcvtsd", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:382",
      NULL, 0 },
    { "vfp_maxd", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:283",
      NULL, 0 },
    { "vfp_maxh", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:283",
      NULL, 0 },
    { "vfp_maxnumd", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:285",
      NULL, 0 },
    { "vfp_maxnumh", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:285",
      NULL, 0 },
    { "vfp_maxnums", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:285",
      NULL, 0 },
    { "vfp_maxs", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:283",
      NULL, 0 },
    { "vfp_mind", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:282",
      NULL, 0 },
    { "vfp_minh", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:282",
      NULL, 0 },
    { "vfp_minnumd", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:284",
      NULL, 0 },
    { "vfp_minnumh", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:284",
      NULL, 0 },
    { "vfp_minnums", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:284",
      NULL, 0 },
    { "vfp_mins", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:282",
      NULL, 0 },
    { "vfp_muladdd", { 0, 0, 0, 3 }, { 0, 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:1117",
      NULL, 0 },
    { "vfp_muladds", { 0, 0, 0, 3 }, { 0, 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:1111",
      NULL, 0 },
    { "vfp_muld", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:280",
      NULL, 0 },
    { "vfp_muls", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:280",
      NULL, 0 },
    { "vfp_sqrtd", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:298",
      NULL, 0 },
    { "vfp_sqrth", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:288",
      NULL, 0 },
    { "vfp_sqrts", { 0, 3 }, { 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:293",
      NULL, 0 },
    { "vfp_sqtod", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:450",
      NULL, 0 },
    { "vfp_sqtoh", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:462",
      NULL, 0 },
    { "vfp_sqtos", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:456",
      NULL, 0 },
    { "vfp_subd", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:279",
      NULL, 0 },
    { "vfp_subs", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:279",
      NULL, 0 },
    { "vfp_tosld", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:449",
      NULL, 0 },
    { "vfp_toslh", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:461",
      NULL, 0 },
    { "vfp_tosls", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:455",
      NULL, 0 },
    { "vfp_tosqd", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:450",
      NULL, 0 },
    { "vfp_tosqh", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:462",
      NULL, 0 },
    { "vfp_tosqs", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:456",
      NULL, 0 },
    { "vfp_tould", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:452",
      NULL, 0 },
    { "vfp_toulh", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:464",
      NULL, 0 },
    { "vfp_touls", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:458",
      NULL, 0 },
    { "vfp_touqd", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:453",
      NULL, 0 },
    { "vfp_touqh", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:465",
      NULL, 0 },
    { "vfp_touqs", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:459",
      NULL, 0 },
    { "vfp_uqtod", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:453",
      NULL, 0 },
    { "vfp_uqtoh", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:465",
      NULL, 0 },
    { "vfp_uqtos", { 0, 0, 3 }, { 0, 0, 18 },
      NULL, 0, true,
      "../target/arm/tcg/vfp_helper.c:459",
      NULL, 0 },
    { "wfe", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/op_helper.c:486",
      NULL, 0 },
    { "wfi", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/op_helper.c:371",
      NULL, 0 },
    { "wfit", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/op_helper.c:419",
      NULL, 0 },
    { "xpacd", { 0 }, { 0 },
      dfu_xpacd_env, ARRAY_SIZE(dfu_xpacd_env), true,
      "../target/arm/tcg/pauth_helper.c:630",
      NULL, 0 },
    { "xpaci", { 0 }, { 0 },
      dfu_xpaci_env, ARRAY_SIZE(dfu_xpaci_env), true,
      "../target/arm/tcg/pauth_helper.c:625",
      NULL, 0 },
    { "yield", { 0 }, { 0 },
      NULL, 0, true,
      "../target/arm/tcg/op_helper.c:498",
      NULL, 0 },
    { "lookup_tb_ptr", { 0 }, { 0 },
      dfu_lookup_tb_ptr_env, ARRAY_SIZE(dfu_lookup_tb_ptr_env), true,
      "accel/tcg/cpu-exec.c HELPER(lookup_tb_ptr)",
      NULL, 0 },
    { NULL, { 0 }, { 0 }, NULL, 0, false, NULL, NULL, 0 }
};
