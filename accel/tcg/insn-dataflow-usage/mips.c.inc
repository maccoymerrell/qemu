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
 * CP1 -- helpers that perform GUEST MEMORY ACCESSES themselves.
 * No qemu_ld/qemu_st op names these: the access happens inside
 * the call, so without the row below QEMU's access list is SHORT
 * for the instruction that called the helper.  Direction and the
 * ADDRESS ARGUMENT are read off the call site; a count is NOT
 * invented when the helper's access pattern is data-dependent.
 *   swl                  write addr=arg2 data=arg1 count unbounded
 *   swr                  write addr=arg2 data=arg1 count unbounded
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
 *   raise_exception:
 *     MERGED with the row the mechanical reader DID derive for this helper,
 *     whose fields (error_code) keep their derived citations above; the
 *     fields below are the hand enumeration. R7.6: the state an
 *     instruction's EXCEPTION writes is in that instruction's destination
 *     set. The mechanical reader cannot reach it because the write is not
 *     in the helper's body and not on any path the helper RETURNS from:
 *     helper_raise_exception() sets cs->exception_index and env->error_code
 *     and then calls cpu_loop_exit_restore()
 *     (../target/mips/tcg/exception.c:163-166), which longjmps out; the CP0
 *     state is written afterwards by mips_cpu_do_interrupt() during
 *     exception DELIVERY. EXCP_SYSCALL
 *     (../target/mips/tcg/system/tlb_helper.c:1354) and EXCP_TRAP (:1376)
 *     both `goto set_EPC`, and the set_EPC path is the source for every
 *     field below, cited per field. BOTH fields carry REG_SYSEXC, which is
 *     the generic word the wire's destination slot for `syscall` and `teq`
 *     already names -- the row makes QEMU's list carry what the wire has
 *     been publishing, it does not add a destination the wire lacks. NOT
 *     ENUMERATED, and each for a stated reason: env->CP0_EPC is written at
 *     :1423 but the tracer's register vocabulary has no row spelling `epc`,
 *     so naming it would produce a name that resolves to nothing (it is the
 *     same REG_SYSEXC either way, so nothing is lost by the omission);
 *     env->CP0_BadVAddr is NOT written on this path at all -- set_EPC only
 *     READS it (:1479, :1500, in the TLB cases), and the address exceptions
 *     that do write it arrive by a different route than a raise_exception
 *     call; env->hflags and env->active_tc.PC are written by delivery
 *     (:1440, :1443, and :1445/:1449/:1451/:1454) and are QEMU's own
 *     control-flow bookkeeping for the handler entry, not architectural
 *     destinations of the raising instruction -- R2 and J2.3, the same
 *     discriminator R10.1 applies to the block-final pc write. The set
 *     below is therefore what the source states AND the vocabulary can
 *     name, and nothing else. DIRECTION CORRECTED 2026-08-27: both fields
 *     are 3 (READ-MODIFY-WRITE), not 2 (write). The citations above were
 *     always read-modify-writes and the row understated them. CP0_Status is
 *     READ twice before it is written -- `if (!(env->CP0_Status & (1 <<
 *     CP0St_EXL)))` is the gate on the whole set_EPC body (:1418) and
 *     Status.BEV selects the vector (:1445/:1449) -- and the write is
 *     `env->CP0_Status |= 1 << CP0St_EXL` (:1432), which reads it a third
 *     time. CP0_Cause is read by every one of its three writes: the BD bit
 *     is a qatomic_or/qatomic_and (:1428/:1430) and the exception code goes
 *     through mips_cause_set_field (:1456), a cmpxchg loop over the whole
 *     word (../target/mips/internal.h:172). R7 is the reason this matters
 *     rather than being a pedantic label: a read-modify-write MAKES THE OLD
 *     VALUE A SOURCE, so the destination's provenance names REG_SYSEXC
 *     instead of being empty -- and an empty provenance on a published
 *     destination is what dst_precheck() refuses, taking the whole
 *     destination family of the raising instruction with it. Measured on
 *     `neg` (a TRAPPING `sub`, whose other destination is an ordinary GPR):
 *     with dir=2 the refusal deleted that GPR's published mask and the
 *     instruction's whole dep block. Stating the read that the source
 *     performs is both the true fact and the fix.
 *   raise_exception_err:
 *     MERGED with the row the mechanical reader DID derive for this helper,
 *     whose fields (error_code) keep their derived citations above; the
 *     fields below are the hand enumeration. The `_err` form of the same
 *     helper, reaching the same do_raise_exception_err() and therefore the
 *     same delivery. R7.6: the state an instruction's EXCEPTION writes is
 *     in that instruction's destination set. The mechanical reader cannot
 *     reach it because the write is not in the helper's body and not on any
 *     path the helper RETURNS from: helper_raise_exception() sets
 *     cs->exception_index and env->error_code and then calls
 *     cpu_loop_exit_restore() (../target/mips/tcg/exception.c:163-166),
 *     which longjmps out; the CP0 state is written afterwards by
 *     mips_cpu_do_interrupt() during exception DELIVERY. EXCP_SYSCALL
 *     (../target/mips/tcg/system/tlb_helper.c:1354) and EXCP_TRAP (:1376)
 *     both `goto set_EPC`, and the set_EPC path is the source for every
 *     field below, cited per field. BOTH fields carry REG_SYSEXC, which is
 *     the generic word the wire's destination slot for `syscall` and `teq`
 *     already names -- the row makes QEMU's list carry what the wire has
 *     been publishing, it does not add a destination the wire lacks. NOT
 *     ENUMERATED, and each for a stated reason: env->CP0_EPC is written at
 *     :1423 but the tracer's register vocabulary has no row spelling `epc`,
 *     so naming it would produce a name that resolves to nothing (it is the
 *     same REG_SYSEXC either way, so nothing is lost by the omission);
 *     env->CP0_BadVAddr is NOT written on this path at all -- set_EPC only
 *     READS it (:1479, :1500, in the TLB cases), and the address exceptions
 *     that do write it arrive by a different route than a raise_exception
 *     call; env->hflags and env->active_tc.PC are written by delivery
 *     (:1440, :1443, and :1445/:1449/:1451/:1454) and are QEMU's own
 *     control-flow bookkeeping for the handler entry, not architectural
 *     destinations of the raising instruction -- R2 and J2.3, the same
 *     discriminator R10.1 applies to the block-final pc write. The set
 *     below is therefore what the source states AND the vocabulary can
 *     name, and nothing else. DIRECTION CORRECTED 2026-08-27: both fields
 *     are 3 (READ-MODIFY-WRITE), not 2 (write). The citations above were
 *     always read-modify-writes and the row understated them. CP0_Status is
 *     READ twice before it is written -- `if (!(env->CP0_Status & (1 <<
 *     CP0St_EXL)))` is the gate on the whole set_EPC body (:1418) and
 *     Status.BEV selects the vector (:1445/:1449) -- and the write is
 *     `env->CP0_Status |= 1 << CP0St_EXL` (:1432), which reads it a third
 *     time. CP0_Cause is read by every one of its three writes: the BD bit
 *     is a qatomic_or/qatomic_and (:1428/:1430) and the exception code goes
 *     through mips_cause_set_field (:1456), a cmpxchg loop over the whole
 *     word (../target/mips/internal.h:172). R7 is the reason this matters
 *     rather than being a pedantic label: a read-modify-write MAKES THE OLD
 *     VALUE A SOURCE, so the destination's provenance names REG_SYSEXC
 *     instead of being empty -- and an empty provenance on a published
 *     destination is what dst_precheck() refuses, taking the whole
 *     destination family of the raising instruction with it. Measured on
 *     `neg` (a TRAPPING `sub`, whose other destination is an ordinary GPR):
 *     with dir=2 the refusal deleted that GPR's published mask and the
 *     instruction's whole dep block. Stating the read that the source
 *     performs is both the true fact and the fix.
 */

static const DfHelperField dfu_cfc1_env[] = {
    { offsetof(CPUArchState, CP0_Config5), sizeof(((CPUArchState *)0)->CP0_Config5), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:52 */
    { offsetof(CPUArchState, CP0_Status), sizeof(((CPUArchState *)0)->CP0_Status), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:54 */
    { offsetof(CPUArchState, active_fpu.fcr0), sizeof(((CPUArchState *)0)->active_fpu.fcr0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:47 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:71 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_le_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1838 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1838 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_ule_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1814 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1814 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_un_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1798 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1798 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_eq_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1879 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1879 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_le_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1917 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1917 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_lt_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1911 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1911 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_add_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1222 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_add_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1232 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvt_w_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:387 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvtd_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:253 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvtd_w_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:262 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_div_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1340 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_mul_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1294 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_mul_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1304 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_sqrt_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:237 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_sqrt_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:244 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_sub_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1258 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_sub_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1268 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_trunc_w_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:504 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_trunc_w_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:517 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_swl_env[] = {
    { offsetof(CPUArchState, CP0_Config0), sizeof(((CPUArchState *)0)->CP0_Config0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/internal.h:346 */
};
static const DfHelperField dfu_swr_env[] = {
    { offsetof(CPUArchState, CP0_Config0), sizeof(((CPUArchState *)0)->CP0_Config0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/internal.h:346 */
};
static const DfHelperField dfu_lookup_tb_ptr_env[] = {
    { offsetof(CPUArchState, active_tc), sizeof(((CPUArchState *)0)->active_tc), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/mips/cpu.h:1432 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD, DF_HF_XLAT, 0 },   /* ../target/mips/cpu.h:1434 */
};
static const DfHelperField dfu_raise_exception_env[] = {
    { offsetof(CPUArchState, CP0_Cause), sizeof(((CPUArchState *)0)->CP0_Cause), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/system/tlb_helper.c:1428 (BD set), :1430 (BD cleared), :1456 (ExcCode via mips_cause_set_field) */
    { offsetof(CPUArchState, CP0_Status), sizeof(((CPUArchState *)0)->CP0_Status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/system/tlb_helper.c:1432 (EXL set) */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_raise_exception_err_env[] = {
    { offsetof(CPUArchState, CP0_Cause), sizeof(((CPUArchState *)0)->CP0_Cause), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/system/tlb_helper.c:1428 (BD set), :1430 (BD cleared), :1456 (ExcCode via mips_cause_set_field) */
    { offsetof(CPUArchState, CP0_Status), sizeof(((CPUArchState *)0)->CP0_Status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/system/tlb_helper.c:1432 (EXL set) */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperAccess dfu_swl_acc[] = {
    { INSN_DF_WR, 2, 1, 1, 1 },   /* ../target/mips/tcg/ldst_helper.c:77, 4 site(s) */
};
static const DfHelperAccess dfu_swr_acc[] = {
    { INSN_DF_WR, 2, 1, 1, 1 },   /* ../target/mips/tcg/ldst_helper.c:101, 4 site(s) */
};

static const DfHelperUsage df_helper_usage[] = {
    { "cfc1", { 0 }, { 0 },
      dfu_cfc1_env, ARRAY_SIZE(dfu_cfc1_env), true,
      "../target/mips/tcg/fpu_helper.c:41",
      NULL, 0 },
    { "cmp_d_le", { 0 }, { 0 },
      dfu_cmp_d_le_env, ARRAY_SIZE(dfu_cmp_d_le_env), true,
      "../target/mips/tcg/fpu_helper.c:1838",
      NULL, 0 },
    { "cmp_d_ule", { 0 }, { 0 },
      dfu_cmp_d_ule_env, ARRAY_SIZE(dfu_cmp_d_ule_env), true,
      "../target/mips/tcg/fpu_helper.c:1814",
      NULL, 0 },
    { "cmp_d_un", { 0 }, { 0 },
      dfu_cmp_d_un_env, ARRAY_SIZE(dfu_cmp_d_un_env), true,
      "../target/mips/tcg/fpu_helper.c:1798",
      NULL, 0 },
    { "cmp_s_eq", { 0 }, { 0 },
      dfu_cmp_s_eq_env, ARRAY_SIZE(dfu_cmp_s_eq_env), true,
      "../target/mips/tcg/fpu_helper.c:1879",
      NULL, 0 },
    { "cmp_s_le", { 0 }, { 0 },
      dfu_cmp_s_le_env, ARRAY_SIZE(dfu_cmp_s_le_env), true,
      "../target/mips/tcg/fpu_helper.c:1917",
      NULL, 0 },
    { "cmp_s_lt", { 0 }, { 0 },
      dfu_cmp_s_lt_env, ARRAY_SIZE(dfu_cmp_s_lt_env), true,
      "../target/mips/tcg/fpu_helper.c:1911",
      NULL, 0 },
    { "float_abs_s", { 0 }, { 0 },
      NULL, 0, true,
      "../target/mips/tcg/fpu_helper.c:981",
      NULL, 0 },
    { "float_add_d", { 0 }, { 0 },
      dfu_float_add_d_env, ARRAY_SIZE(dfu_float_add_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1217",
      NULL, 0 },
    { "float_add_s", { 0 }, { 0 },
      dfu_float_add_s_env, ARRAY_SIZE(dfu_float_add_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1227",
      NULL, 0 },
    { "float_chs_s", { 0 }, { 0 },
      NULL, 0, true,
      "../target/mips/tcg/fpu_helper.c:1001",
      NULL, 0 },
    { "float_cvt_w_s", { 0 }, { 0 },
      dfu_float_cvt_w_s_env, ARRAY_SIZE(dfu_float_cvt_w_s_env), true,
      "../target/mips/tcg/fpu_helper.c:383",
      NULL, 0 },
    { "float_cvtd_s", { 0 }, { 0 },
      dfu_float_cvtd_s_env, ARRAY_SIZE(dfu_float_cvtd_s_env), true,
      "../target/mips/tcg/fpu_helper.c:249",
      NULL, 0 },
    { "float_cvtd_w", { 0 }, { 0 },
      dfu_float_cvtd_w_env, ARRAY_SIZE(dfu_float_cvtd_w_env), true,
      "../target/mips/tcg/fpu_helper.c:258",
      NULL, 0 },
    { "float_div_s", { 0 }, { 0 },
      dfu_float_div_s_env, ARRAY_SIZE(dfu_float_div_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1335",
      NULL, 0 },
    { "float_mul_d", { 0 }, { 0 },
      dfu_float_mul_d_env, ARRAY_SIZE(dfu_float_mul_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1289",
      NULL, 0 },
    { "float_mul_s", { 0 }, { 0 },
      dfu_float_mul_s_env, ARRAY_SIZE(dfu_float_mul_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1299",
      NULL, 0 },
    { "float_sqrt_d", { 0 }, { 0 },
      dfu_float_sqrt_d_env, ARRAY_SIZE(dfu_float_sqrt_d_env), true,
      "../target/mips/tcg/fpu_helper.c:235",
      NULL, 0 },
    { "float_sqrt_s", { 0 }, { 0 },
      dfu_float_sqrt_s_env, ARRAY_SIZE(dfu_float_sqrt_s_env), true,
      "../target/mips/tcg/fpu_helper.c:242",
      NULL, 0 },
    { "float_sub_d", { 0 }, { 0 },
      dfu_float_sub_d_env, ARRAY_SIZE(dfu_float_sub_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1253",
      NULL, 0 },
    { "float_sub_s", { 0 }, { 0 },
      dfu_float_sub_s_env, ARRAY_SIZE(dfu_float_sub_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1263",
      NULL, 0 },
    { "float_trunc_w_d", { 0 }, { 0 },
      dfu_float_trunc_w_d_env, ARRAY_SIZE(dfu_float_trunc_w_d_env), true,
      "../target/mips/tcg/fpu_helper.c:500",
      NULL, 0 },
    { "float_trunc_w_s", { 0 }, { 0 },
      dfu_float_trunc_w_s_env, ARRAY_SIZE(dfu_float_trunc_w_s_env), true,
      "../target/mips/tcg/fpu_helper.c:513",
      NULL, 0 },
    { "swl", { 0 }, { 0 },
      dfu_swl_env, ARRAY_SIZE(dfu_swl_env), true,
      "../target/mips/tcg/ldst_helper.c:71",
      dfu_swl_acc, ARRAY_SIZE(dfu_swl_acc) },
    { "swr", { 0 }, { 0 },
      dfu_swr_env, ARRAY_SIZE(dfu_swr_env), true,
      "../target/mips/tcg/ldst_helper.c:95",
      dfu_swr_acc, ARRAY_SIZE(dfu_swr_acc) },
    { "lookup_tb_ptr", { 0 }, { 0 },
      dfu_lookup_tb_ptr_env, ARRAY_SIZE(dfu_lookup_tb_ptr_env), true,
      "accel/tcg/cpu-exec.c HELPER(lookup_tb_ptr)",
      NULL, 0 },
    { "raise_exception", { 0 }, { 0 },
      dfu_raise_exception_env, ARRAY_SIZE(dfu_raise_exception_env), true,
      "../target/mips/tcg/exception.c:54",
      NULL, 0 },
    { "raise_exception_err", { 0 }, { 0 },
      dfu_raise_exception_err_env, ARRAY_SIZE(dfu_raise_exception_err_env), true,
      "../target/mips/tcg/exception.c:48",
      NULL, 0 },
    { NULL, { 0 }, { 0 }, NULL, 0, false, NULL, NULL, 0 }
};
