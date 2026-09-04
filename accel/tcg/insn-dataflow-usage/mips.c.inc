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

static const DfHelperField dfu_addsc_env[] = {
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:63 */
};
static const DfHelperField dfu_addu_ph_env[] = {
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_addu_qb_env[] = {
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_addu_s_ph_env[] = {
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_addu_s_qb_env[] = {
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_cfc1_env[] = {
    { offsetof(CPUArchState, CP0_Config5), sizeof(((CPUArchState *)0)->CP0_Config5), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:52 */
    { offsetof(CPUArchState, CP0_Status), sizeof(((CPUArchState *)0)->CP0_Status), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:54 */
    { offsetof(CPUArchState, active_fpu.fcr0), sizeof(((CPUArchState *)0)->active_fpu.fcr0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:47 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:71 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_eq_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1800 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1800 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_f_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1796 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1796 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_le_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1838 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1838 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_lt_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1832 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1832 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_nge_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1834 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1834 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_ngl_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1828 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1828 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_ngle_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1824 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1824 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_ngt_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1840 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1840 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_ole_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1812 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1812 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_olt_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1806 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1806 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_seq_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1826 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1826 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_sf_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1822 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1822 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_ueq_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1802 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1802 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_ule_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1814 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1814 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_d_ult_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1808 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1808 */
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
static const DfHelperField dfu_cmp_s_f_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1875 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1875 */
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
static const DfHelperField dfu_cmp_s_nge_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1913 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1913 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_ngl_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1907 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1907 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_ngle_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1903 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1903 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_ngt_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1919 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1919 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_ole_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1891 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1891 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_olt_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1885 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1885 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_seq_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1905 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1905 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_sf_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1901 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1901 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_ueq_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1881 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1881 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_ule_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1893 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1893 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_ult_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1887 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1887 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmp_s_un_env[] = {
    { offsetof(CPUArchState, active_fpu), sizeof(((CPUArchState *)0)->active_fpu), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1877 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1877 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_cmpu_eq_qb_env[] = {
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:79 */
};
static const DfHelperField dfu_ctc1_env[] = {
    { offsetof(CPUArchState, CP0_Config3), sizeof(((CPUArchState *)0)->CP0_Config3), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/cpu.h:1382 */
    { offsetof(CPUArchState, CP0_Config5), sizeof(((CPUArchState *)0)->CP0_Config5), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:97 */
    { offsetof(CPUArchState, CP0_PageGrain), sizeof(((CPUArchState *)0)->CP0_PageGrain), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/internal.h:545 */
    { offsetof(CPUArchState, CP0_Status), sizeof(((CPUArchState *)0)->CP0_Status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:98 */
    { offsetof(CPUArchState, active_fpu.fcr0), sizeof(((CPUArchState *)0)->active_fpu.fcr0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:94 */
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:144 */
    { offsetof(CPUArchState, active_fpu.fcr31_rw_bitmask), sizeof(((CPUArchState *)0)->active_fpu.fcr31_rw_bitmask), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:164 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/fpu_helper.h:20 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
    { offsetof(CPUArchState, hflags), sizeof(((CPUArchState *)0)->hflags), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/internal.h:435 */
    { offsetof(CPUArchState, insn_flags), sizeof(((CPUArchState *)0)->insn_flags), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/internal.h:473 */
};
static const DfHelperField dfu_dpa_w_ph_env[] = {
    { offsetof(CPUArchState, active_tc), sizeof(((CPUArchState *)0)->active_tc), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/mips/tcg/dsp_helper.c:2313, INDEX NOT STATED */
};
static const DfHelperField dfu_dpaq_s_w_ph_env[] = {
    { offsetof(CPUArchState, active_tc), sizeof(((CPUArchState *)0)->active_tc), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/mips/tcg/dsp_helper.c:2351, INDEX NOT STATED */
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_dpaq_sa_l_w_env[] = {
    { offsetof(CPUArchState, active_tc), sizeof(((CPUArchState *)0)->active_tc), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/mips/tcg/dsp_helper.c:2512, INDEX NOT STATED */
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_dpaqx_s_w_ph_env[] = {
    { offsetof(CPUArchState, active_tc), sizeof(((CPUArchState *)0)->active_tc), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/mips/tcg/dsp_helper.c:2352, INDEX NOT STATED */
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_dpax_w_ph_env[] = {
    { offsetof(CPUArchState, active_tc), sizeof(((CPUArchState *)0)->active_tc), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/mips/tcg/dsp_helper.c:2314, INDEX NOT STATED */
};
static const DfHelperField dfu_extr_r_w_env[] = {
    { offsetof(CPUArchState, active_tc), sizeof(((CPUArchState *)0)->active_tc), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/mips/tcg/dsp_helper.c:511, INDEX NOT STATED */
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_extr_w_env[] = {
    { offsetof(CPUArchState, active_tc), sizeof(((CPUArchState *)0)->active_tc), INSN_DF_RD, DF_HF_OPERAND, 1 },   /* ../target/mips/tcg/dsp_helper.c:511, INDEX NOT STATED */
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_float_add_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1222 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_add_ps_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1247 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_add_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1232 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_addr_ps_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1446 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_ceil_l_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/fpu_helper.h:19 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:530 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_ceil_l_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/fpu_helper.h:19 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:545 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_ceil_w_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/fpu_helper.h:19 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:560 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_ceil_w_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/fpu_helper.h:19 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:575 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvt_l_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:280 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvt_l_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:293 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvt_w_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:400 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvt_w_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:387 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvtd_l_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:271 */
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
static const DfHelperField dfu_float_cvtps_pw_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:307 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvtpw_ps_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:319 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvts_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:342 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvts_l_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:360 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvts_pl_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:207 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvts_pu_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:207 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_cvts_w_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:351 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_div_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1330 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_div_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1340 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_floor_l_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/fpu_helper.h:19 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:590 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_floor_l_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/fpu_helper.h:19 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:605 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_floor_w_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/fpu_helper.h:19 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:620 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_floor_w_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/fpu_helper.h:19 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:635 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_madd_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1554 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_madd_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1564 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_msub_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1593 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_msub_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1603 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_mul_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1294 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_mul_ps_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1319 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_mul_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1304 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_mulr_ps_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1461 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_nmadd_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1632 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_nmadd_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1643 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_nmsub_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1675 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_nmsub_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1686 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_recip_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1021 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_recip_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1030 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_round_l_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/fpu_helper.h:19 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:414 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_round_l_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/fpu_helper.h:19 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:430 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_round_w_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/fpu_helper.h:19 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:446 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_round_w_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/fpu_helper.h:19 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:462 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_rsqrt_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1039 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_rsqrt_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1049 */
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
static const DfHelperField dfu_float_sub_ps_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1283 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_sub_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:1268 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_trunc_l_d_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:478 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
};
static const DfHelperField dfu_float_trunc_l_s_env[] = {
    { offsetof(CPUArchState, active_fpu.fcr31), sizeof(((CPUArchState *)0)->active_fpu.fcr31), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:214 */
    { offsetof(CPUArchState, active_fpu.fp_status), sizeof(((CPUArchState *)0)->active_fpu.fp_status), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/fpu_helper.c:491 */
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
static const DfHelperField dfu_insv_env[] = {
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:2946 */
};
static const DfHelperField dfu_maq_s_w_phl_env[] = {
    { offsetof(CPUArchState, active_tc), sizeof(((CPUArchState *)0)->active_tc), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/mips/tcg/dsp_helper.c:2648, INDEX NOT STATED */
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_maq_sa_w_phl_env[] = {
    { offsetof(CPUArchState, active_tc), sizeof(((CPUArchState *)0)->active_tc), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 1 },   /* ../target/mips/tcg/dsp_helper.c:257, INDEX NOT STATED */
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_muleq_s_w_phl_env[] = {
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_pmon_env[] = {
    { offsetof(CPUArchState, active_tc.gpr[2]), sizeof(((CPUArchState *)0)->active_tc.gpr[2]), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/op_helper.c:240 */
    { offsetof(CPUArchState, active_tc.gpr[4]), sizeof(((CPUArchState *)0)->active_tc.gpr[4]), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/op_helper.c:239 */
};
static const DfHelperField dfu_shll_ph_env[] = {
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_shll_qb_env[] = {
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_shll_s_ph_env[] = {
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_shll_s_w_env[] = {
    { offsetof(CPUArchState, active_tc.DSPControl), sizeof(((CPUArchState *)0)->active_tc.DSPControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/dsp_helper.c:58 */
};
static const DfHelperField dfu_swl_env[] = {
    { offsetof(CPUArchState, CP0_Config0), sizeof(((CPUArchState *)0)->CP0_Config0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/internal.h:346 */
};
static const DfHelperField dfu_swr_env[] = {
    { offsetof(CPUArchState, CP0_Config0), sizeof(((CPUArchState *)0)->CP0_Config0), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/internal.h:346 */
};
static const DfHelperField dfu_yield_env[] = {
    { offsetof(CPUArchState, CP0_VPEControl), sizeof(((CPUArchState *)0)->CP0_VPEControl), INSN_DF_RD | INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/op_helper.c:162 */
    { offsetof(CPUArchState, CP0_YQMask), sizeof(((CPUArchState *)0)->CP0_YQMask), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/op_helper.c:183 */
    { offsetof(CPUArchState, active_tc.CP0_TCStatus), sizeof(((CPUArchState *)0)->active_tc.CP0_TCStatus), INSN_DF_RD, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/op_helper.c:163 */
    { offsetof(CPUArchState, error_code), sizeof(((CPUArchState *)0)->error_code), INSN_DF_WR, DF_HF_OPERAND, 0 },   /* ../target/mips/tcg/exception.c:164 */
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
    { "addsc", { 0 }, { 0 },
      dfu_addsc_env, ARRAY_SIZE(dfu_addsc_env), true,
      "../target/mips/tcg/dsp_helper.c:1278",
      NULL, 0 },
    { "addu_ph", { 0 }, { 0 },
      dfu_addu_ph_env, ARRAY_SIZE(dfu_addu_ph_env), true,
      "../target/mips/tcg/dsp_helper.c:1183",
      NULL, 0 },
    { "addu_qb", { 0 }, { 0 },
      dfu_addu_qb_env, ARRAY_SIZE(dfu_addu_qb_env), true,
      "../target/mips/tcg/dsp_helper.c:1184",
      NULL, 0 },
    { "addu_s_ph", { 0 }, { 0 },
      dfu_addu_s_ph_env, ARRAY_SIZE(dfu_addu_s_ph_env), true,
      "../target/mips/tcg/dsp_helper.c:1185",
      NULL, 0 },
    { "addu_s_qb", { 0 }, { 0 },
      dfu_addu_s_qb_env, ARRAY_SIZE(dfu_addu_s_qb_env), true,
      "../target/mips/tcg/dsp_helper.c:1186",
      NULL, 0 },
    { "cfc1", { 0 }, { 0 },
      dfu_cfc1_env, ARRAY_SIZE(dfu_cfc1_env), true,
      "../target/mips/tcg/fpu_helper.c:41",
      NULL, 0 },
    { "cmp_d_eq", { 0 }, { 0 },
      dfu_cmp_d_eq_env, ARRAY_SIZE(dfu_cmp_d_eq_env), true,
      "../target/mips/tcg/fpu_helper.c:1800",
      NULL, 0 },
    { "cmp_d_f", { 0 }, { 0 },
      dfu_cmp_d_f_env, ARRAY_SIZE(dfu_cmp_d_f_env), true,
      "../target/mips/tcg/fpu_helper.c:1796",
      NULL, 0 },
    { "cmp_d_le", { 0 }, { 0 },
      dfu_cmp_d_le_env, ARRAY_SIZE(dfu_cmp_d_le_env), true,
      "../target/mips/tcg/fpu_helper.c:1838",
      NULL, 0 },
    { "cmp_d_lt", { 0 }, { 0 },
      dfu_cmp_d_lt_env, ARRAY_SIZE(dfu_cmp_d_lt_env), true,
      "../target/mips/tcg/fpu_helper.c:1832",
      NULL, 0 },
    { "cmp_d_nge", { 0 }, { 0 },
      dfu_cmp_d_nge_env, ARRAY_SIZE(dfu_cmp_d_nge_env), true,
      "../target/mips/tcg/fpu_helper.c:1834",
      NULL, 0 },
    { "cmp_d_ngl", { 0 }, { 0 },
      dfu_cmp_d_ngl_env, ARRAY_SIZE(dfu_cmp_d_ngl_env), true,
      "../target/mips/tcg/fpu_helper.c:1828",
      NULL, 0 },
    { "cmp_d_ngle", { 0 }, { 0 },
      dfu_cmp_d_ngle_env, ARRAY_SIZE(dfu_cmp_d_ngle_env), true,
      "../target/mips/tcg/fpu_helper.c:1824",
      NULL, 0 },
    { "cmp_d_ngt", { 0 }, { 0 },
      dfu_cmp_d_ngt_env, ARRAY_SIZE(dfu_cmp_d_ngt_env), true,
      "../target/mips/tcg/fpu_helper.c:1840",
      NULL, 0 },
    { "cmp_d_ole", { 0 }, { 0 },
      dfu_cmp_d_ole_env, ARRAY_SIZE(dfu_cmp_d_ole_env), true,
      "../target/mips/tcg/fpu_helper.c:1812",
      NULL, 0 },
    { "cmp_d_olt", { 0 }, { 0 },
      dfu_cmp_d_olt_env, ARRAY_SIZE(dfu_cmp_d_olt_env), true,
      "../target/mips/tcg/fpu_helper.c:1806",
      NULL, 0 },
    { "cmp_d_seq", { 0 }, { 0 },
      dfu_cmp_d_seq_env, ARRAY_SIZE(dfu_cmp_d_seq_env), true,
      "../target/mips/tcg/fpu_helper.c:1826",
      NULL, 0 },
    { "cmp_d_sf", { 0 }, { 0 },
      dfu_cmp_d_sf_env, ARRAY_SIZE(dfu_cmp_d_sf_env), true,
      "../target/mips/tcg/fpu_helper.c:1822",
      NULL, 0 },
    { "cmp_d_ueq", { 0 }, { 0 },
      dfu_cmp_d_ueq_env, ARRAY_SIZE(dfu_cmp_d_ueq_env), true,
      "../target/mips/tcg/fpu_helper.c:1802",
      NULL, 0 },
    { "cmp_d_ule", { 0 }, { 0 },
      dfu_cmp_d_ule_env, ARRAY_SIZE(dfu_cmp_d_ule_env), true,
      "../target/mips/tcg/fpu_helper.c:1814",
      NULL, 0 },
    { "cmp_d_ult", { 0 }, { 0 },
      dfu_cmp_d_ult_env, ARRAY_SIZE(dfu_cmp_d_ult_env), true,
      "../target/mips/tcg/fpu_helper.c:1808",
      NULL, 0 },
    { "cmp_d_un", { 0 }, { 0 },
      dfu_cmp_d_un_env, ARRAY_SIZE(dfu_cmp_d_un_env), true,
      "../target/mips/tcg/fpu_helper.c:1798",
      NULL, 0 },
    { "cmp_s_eq", { 0 }, { 0 },
      dfu_cmp_s_eq_env, ARRAY_SIZE(dfu_cmp_s_eq_env), true,
      "../target/mips/tcg/fpu_helper.c:1879",
      NULL, 0 },
    { "cmp_s_f", { 0 }, { 0 },
      dfu_cmp_s_f_env, ARRAY_SIZE(dfu_cmp_s_f_env), true,
      "../target/mips/tcg/fpu_helper.c:1875",
      NULL, 0 },
    { "cmp_s_le", { 0 }, { 0 },
      dfu_cmp_s_le_env, ARRAY_SIZE(dfu_cmp_s_le_env), true,
      "../target/mips/tcg/fpu_helper.c:1917",
      NULL, 0 },
    { "cmp_s_lt", { 0 }, { 0 },
      dfu_cmp_s_lt_env, ARRAY_SIZE(dfu_cmp_s_lt_env), true,
      "../target/mips/tcg/fpu_helper.c:1911",
      NULL, 0 },
    { "cmp_s_nge", { 0 }, { 0 },
      dfu_cmp_s_nge_env, ARRAY_SIZE(dfu_cmp_s_nge_env), true,
      "../target/mips/tcg/fpu_helper.c:1913",
      NULL, 0 },
    { "cmp_s_ngl", { 0 }, { 0 },
      dfu_cmp_s_ngl_env, ARRAY_SIZE(dfu_cmp_s_ngl_env), true,
      "../target/mips/tcg/fpu_helper.c:1907",
      NULL, 0 },
    { "cmp_s_ngle", { 0 }, { 0 },
      dfu_cmp_s_ngle_env, ARRAY_SIZE(dfu_cmp_s_ngle_env), true,
      "../target/mips/tcg/fpu_helper.c:1903",
      NULL, 0 },
    { "cmp_s_ngt", { 0 }, { 0 },
      dfu_cmp_s_ngt_env, ARRAY_SIZE(dfu_cmp_s_ngt_env), true,
      "../target/mips/tcg/fpu_helper.c:1919",
      NULL, 0 },
    { "cmp_s_ole", { 0 }, { 0 },
      dfu_cmp_s_ole_env, ARRAY_SIZE(dfu_cmp_s_ole_env), true,
      "../target/mips/tcg/fpu_helper.c:1891",
      NULL, 0 },
    { "cmp_s_olt", { 0 }, { 0 },
      dfu_cmp_s_olt_env, ARRAY_SIZE(dfu_cmp_s_olt_env), true,
      "../target/mips/tcg/fpu_helper.c:1885",
      NULL, 0 },
    { "cmp_s_seq", { 0 }, { 0 },
      dfu_cmp_s_seq_env, ARRAY_SIZE(dfu_cmp_s_seq_env), true,
      "../target/mips/tcg/fpu_helper.c:1905",
      NULL, 0 },
    { "cmp_s_sf", { 0 }, { 0 },
      dfu_cmp_s_sf_env, ARRAY_SIZE(dfu_cmp_s_sf_env), true,
      "../target/mips/tcg/fpu_helper.c:1901",
      NULL, 0 },
    { "cmp_s_ueq", { 0 }, { 0 },
      dfu_cmp_s_ueq_env, ARRAY_SIZE(dfu_cmp_s_ueq_env), true,
      "../target/mips/tcg/fpu_helper.c:1881",
      NULL, 0 },
    { "cmp_s_ule", { 0 }, { 0 },
      dfu_cmp_s_ule_env, ARRAY_SIZE(dfu_cmp_s_ule_env), true,
      "../target/mips/tcg/fpu_helper.c:1893",
      NULL, 0 },
    { "cmp_s_ult", { 0 }, { 0 },
      dfu_cmp_s_ult_env, ARRAY_SIZE(dfu_cmp_s_ult_env), true,
      "../target/mips/tcg/fpu_helper.c:1887",
      NULL, 0 },
    { "cmp_s_un", { 0 }, { 0 },
      dfu_cmp_s_un_env, ARRAY_SIZE(dfu_cmp_s_un_env), true,
      "../target/mips/tcg/fpu_helper.c:1877",
      NULL, 0 },
    { "cmpgu_eq_qb", { 0 }, { 0 },
      NULL, 0, true,
      "../target/mips/tcg/dsp_helper.c:2973",
      NULL, 0 },
    { "cmpu_eq_qb", { 0 }, { 0 },
      dfu_cmpu_eq_qb_env, ARRAY_SIZE(dfu_cmpu_eq_qb_env), true,
      "../target/mips/tcg/dsp_helper.c:3006",
      NULL, 0 },
    { "ctc1", { 0 }, { 0 },
      dfu_ctc1_env, ARRAY_SIZE(dfu_ctc1_env), true,
      "../target/mips/tcg/fpu_helper.c:89",
      NULL, 0 },
    { "dpa_w_ph", { 0 }, { 0 },
      dfu_dpa_w_ph_env, ARRAY_SIZE(dfu_dpa_w_ph_env), true,
      "../target/mips/tcg/dsp_helper.c:2313",
      NULL, 0 },
    { "dpaq_s_w_ph", { 0 }, { 0 },
      dfu_dpaq_s_w_ph_env, ARRAY_SIZE(dfu_dpaq_s_w_ph_env), true,
      "../target/mips/tcg/dsp_helper.c:2351",
      NULL, 0 },
    { "dpaq_sa_l_w", { 0 }, { 0 },
      dfu_dpaq_sa_l_w_env, ARRAY_SIZE(dfu_dpaq_sa_l_w_env), true,
      "../target/mips/tcg/dsp_helper.c:2512",
      NULL, 0 },
    { "dpaqx_s_w_ph", { 0 }, { 0 },
      dfu_dpaqx_s_w_ph_env, ARRAY_SIZE(dfu_dpaqx_s_w_ph_env), true,
      "../target/mips/tcg/dsp_helper.c:2352",
      NULL, 0 },
    { "dpax_w_ph", { 0 }, { 0 },
      dfu_dpax_w_ph_env, ARRAY_SIZE(dfu_dpax_w_ph_env), true,
      "../target/mips/tcg/dsp_helper.c:2314",
      NULL, 0 },
    { "extr_r_w", { 0 }, { 0 },
      dfu_extr_r_w_env, ARRAY_SIZE(dfu_extr_r_w_env), true,
      "../target/mips/tcg/dsp_helper.c:3150",
      NULL, 0 },
    { "extr_w", { 0 }, { 0 },
      dfu_extr_w_env, ARRAY_SIZE(dfu_extr_w_env), true,
      "../target/mips/tcg/dsp_helper.c:3121",
      NULL, 0 },
    { "float_abs_d", { 0 }, { 0 },
      NULL, 0, true,
      "../target/mips/tcg/fpu_helper.c:976",
      NULL, 0 },
    { "float_abs_s", { 0 }, { 0 },
      NULL, 0, true,
      "../target/mips/tcg/fpu_helper.c:981",
      NULL, 0 },
    { "float_add_d", { 0 }, { 0 },
      dfu_float_add_d_env, ARRAY_SIZE(dfu_float_add_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1217",
      NULL, 0 },
    { "float_add_ps", { 0 }, { 0 },
      dfu_float_add_ps_env, ARRAY_SIZE(dfu_float_add_ps_env), true,
      "../target/mips/tcg/fpu_helper.c:1237",
      NULL, 0 },
    { "float_add_s", { 0 }, { 0 },
      dfu_float_add_s_env, ARRAY_SIZE(dfu_float_add_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1227",
      NULL, 0 },
    { "float_addr_ps", { 0 }, { 0 },
      dfu_float_addr_ps_env, ARRAY_SIZE(dfu_float_addr_ps_env), true,
      "../target/mips/tcg/fpu_helper.c:1437",
      NULL, 0 },
    { "float_ceil_l_d", { 0 }, { 0 },
      dfu_float_ceil_l_d_env, ARRAY_SIZE(dfu_float_ceil_l_d_env), true,
      "../target/mips/tcg/fpu_helper.c:526",
      NULL, 0 },
    { "float_ceil_l_s", { 0 }, { 0 },
      dfu_float_ceil_l_s_env, ARRAY_SIZE(dfu_float_ceil_l_s_env), true,
      "../target/mips/tcg/fpu_helper.c:541",
      NULL, 0 },
    { "float_ceil_w_d", { 0 }, { 0 },
      dfu_float_ceil_w_d_env, ARRAY_SIZE(dfu_float_ceil_w_d_env), true,
      "../target/mips/tcg/fpu_helper.c:556",
      NULL, 0 },
    { "float_ceil_w_s", { 0 }, { 0 },
      dfu_float_ceil_w_s_env, ARRAY_SIZE(dfu_float_ceil_w_s_env), true,
      "../target/mips/tcg/fpu_helper.c:571",
      NULL, 0 },
    { "float_chs_d", { 0 }, { 0 },
      NULL, 0, true,
      "../target/mips/tcg/fpu_helper.c:996",
      NULL, 0 },
    { "float_chs_s", { 0 }, { 0 },
      NULL, 0, true,
      "../target/mips/tcg/fpu_helper.c:1001",
      NULL, 0 },
    { "float_cvt_l_d", { 0 }, { 0 },
      dfu_float_cvt_l_d_env, ARRAY_SIZE(dfu_float_cvt_l_d_env), true,
      "../target/mips/tcg/fpu_helper.c:276",
      NULL, 0 },
    { "float_cvt_l_s", { 0 }, { 0 },
      dfu_float_cvt_l_s_env, ARRAY_SIZE(dfu_float_cvt_l_s_env), true,
      "../target/mips/tcg/fpu_helper.c:289",
      NULL, 0 },
    { "float_cvt_w_d", { 0 }, { 0 },
      dfu_float_cvt_w_d_env, ARRAY_SIZE(dfu_float_cvt_w_d_env), true,
      "../target/mips/tcg/fpu_helper.c:396",
      NULL, 0 },
    { "float_cvt_w_s", { 0 }, { 0 },
      dfu_float_cvt_w_s_env, ARRAY_SIZE(dfu_float_cvt_w_s_env), true,
      "../target/mips/tcg/fpu_helper.c:383",
      NULL, 0 },
    { "float_cvtd_l", { 0 }, { 0 },
      dfu_float_cvtd_l_env, ARRAY_SIZE(dfu_float_cvtd_l_env), true,
      "../target/mips/tcg/fpu_helper.c:267",
      NULL, 0 },
    { "float_cvtd_s", { 0 }, { 0 },
      dfu_float_cvtd_s_env, ARRAY_SIZE(dfu_float_cvtd_s_env), true,
      "../target/mips/tcg/fpu_helper.c:249",
      NULL, 0 },
    { "float_cvtd_w", { 0 }, { 0 },
      dfu_float_cvtd_w_env, ARRAY_SIZE(dfu_float_cvtd_w_env), true,
      "../target/mips/tcg/fpu_helper.c:258",
      NULL, 0 },
    { "float_cvtps_pw", { 0 }, { 0 },
      dfu_float_cvtps_pw_env, ARRAY_SIZE(dfu_float_cvtps_pw_env), true,
      "../target/mips/tcg/fpu_helper.c:302",
      NULL, 0 },
    { "float_cvtpw_ps", { 0 }, { 0 },
      dfu_float_cvtpw_ps_env, ARRAY_SIZE(dfu_float_cvtpw_ps_env), true,
      "../target/mips/tcg/fpu_helper.c:313",
      NULL, 0 },
    { "float_cvts_d", { 0 }, { 0 },
      dfu_float_cvts_d_env, ARRAY_SIZE(dfu_float_cvts_d_env), true,
      "../target/mips/tcg/fpu_helper.c:338",
      NULL, 0 },
    { "float_cvts_l", { 0 }, { 0 },
      dfu_float_cvts_l_env, ARRAY_SIZE(dfu_float_cvts_l_env), true,
      "../target/mips/tcg/fpu_helper.c:356",
      NULL, 0 },
    { "float_cvts_pl", { 0 }, { 0 },
      dfu_float_cvts_pl_env, ARRAY_SIZE(dfu_float_cvts_pl_env), true,
      "../target/mips/tcg/fpu_helper.c:365",
      NULL, 0 },
    { "float_cvts_pu", { 0 }, { 0 },
      dfu_float_cvts_pu_env, ARRAY_SIZE(dfu_float_cvts_pu_env), true,
      "../target/mips/tcg/fpu_helper.c:374",
      NULL, 0 },
    { "float_cvts_w", { 0 }, { 0 },
      dfu_float_cvts_w_env, ARRAY_SIZE(dfu_float_cvts_w_env), true,
      "../target/mips/tcg/fpu_helper.c:347",
      NULL, 0 },
    { "float_div_d", { 0 }, { 0 },
      dfu_float_div_d_env, ARRAY_SIZE(dfu_float_div_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1325",
      NULL, 0 },
    { "float_div_s", { 0 }, { 0 },
      dfu_float_div_s_env, ARRAY_SIZE(dfu_float_div_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1335",
      NULL, 0 },
    { "float_floor_l_d", { 0 }, { 0 },
      dfu_float_floor_l_d_env, ARRAY_SIZE(dfu_float_floor_l_d_env), true,
      "../target/mips/tcg/fpu_helper.c:586",
      NULL, 0 },
    { "float_floor_l_s", { 0 }, { 0 },
      dfu_float_floor_l_s_env, ARRAY_SIZE(dfu_float_floor_l_s_env), true,
      "../target/mips/tcg/fpu_helper.c:601",
      NULL, 0 },
    { "float_floor_w_d", { 0 }, { 0 },
      dfu_float_floor_w_d_env, ARRAY_SIZE(dfu_float_floor_w_d_env), true,
      "../target/mips/tcg/fpu_helper.c:616",
      NULL, 0 },
    { "float_floor_w_s", { 0 }, { 0 },
      dfu_float_floor_w_s_env, ARRAY_SIZE(dfu_float_floor_w_s_env), true,
      "../target/mips/tcg/fpu_helper.c:631",
      NULL, 0 },
    { "float_madd_d", { 0 }, { 0 },
      dfu_float_madd_d_env, ARRAY_SIZE(dfu_float_madd_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1551",
      NULL, 0 },
    { "float_madd_s", { 0 }, { 0 },
      dfu_float_madd_s_env, ARRAY_SIZE(dfu_float_madd_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1561",
      NULL, 0 },
    { "float_msub_d", { 0 }, { 0 },
      dfu_float_msub_d_env, ARRAY_SIZE(dfu_float_msub_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1590",
      NULL, 0 },
    { "float_msub_s", { 0 }, { 0 },
      dfu_float_msub_s_env, ARRAY_SIZE(dfu_float_msub_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1600",
      NULL, 0 },
    { "float_mul_d", { 0 }, { 0 },
      dfu_float_mul_d_env, ARRAY_SIZE(dfu_float_mul_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1289",
      NULL, 0 },
    { "float_mul_ps", { 0 }, { 0 },
      dfu_float_mul_ps_env, ARRAY_SIZE(dfu_float_mul_ps_env), true,
      "../target/mips/tcg/fpu_helper.c:1309",
      NULL, 0 },
    { "float_mul_s", { 0 }, { 0 },
      dfu_float_mul_s_env, ARRAY_SIZE(dfu_float_mul_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1299",
      NULL, 0 },
    { "float_mulr_ps", { 0 }, { 0 },
      dfu_float_mulr_ps_env, ARRAY_SIZE(dfu_float_mulr_ps_env), true,
      "../target/mips/tcg/fpu_helper.c:1452",
      NULL, 0 },
    { "float_nmadd_d", { 0 }, { 0 },
      dfu_float_nmadd_d_env, ARRAY_SIZE(dfu_float_nmadd_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1629",
      NULL, 0 },
    { "float_nmadd_s", { 0 }, { 0 },
      dfu_float_nmadd_s_env, ARRAY_SIZE(dfu_float_nmadd_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1640",
      NULL, 0 },
    { "float_nmsub_d", { 0 }, { 0 },
      dfu_float_nmsub_d_env, ARRAY_SIZE(dfu_float_nmsub_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1672",
      NULL, 0 },
    { "float_nmsub_s", { 0 }, { 0 },
      dfu_float_nmsub_s_env, ARRAY_SIZE(dfu_float_nmsub_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1683",
      NULL, 0 },
    { "float_recip_d", { 0 }, { 0 },
      dfu_float_recip_d_env, ARRAY_SIZE(dfu_float_recip_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1017",
      NULL, 0 },
    { "float_recip_s", { 0 }, { 0 },
      dfu_float_recip_s_env, ARRAY_SIZE(dfu_float_recip_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1026",
      NULL, 0 },
    { "float_round_l_d", { 0 }, { 0 },
      dfu_float_round_l_d_env, ARRAY_SIZE(dfu_float_round_l_d_env), true,
      "../target/mips/tcg/fpu_helper.c:409",
      NULL, 0 },
    { "float_round_l_s", { 0 }, { 0 },
      dfu_float_round_l_s_env, ARRAY_SIZE(dfu_float_round_l_s_env), true,
      "../target/mips/tcg/fpu_helper.c:425",
      NULL, 0 },
    { "float_round_w_d", { 0 }, { 0 },
      dfu_float_round_w_d_env, ARRAY_SIZE(dfu_float_round_w_d_env), true,
      "../target/mips/tcg/fpu_helper.c:441",
      NULL, 0 },
    { "float_round_w_s", { 0 }, { 0 },
      dfu_float_round_w_s_env, ARRAY_SIZE(dfu_float_round_w_s_env), true,
      "../target/mips/tcg/fpu_helper.c:457",
      NULL, 0 },
    { "float_rsqrt_d", { 0 }, { 0 },
      dfu_float_rsqrt_d_env, ARRAY_SIZE(dfu_float_rsqrt_d_env), true,
      "../target/mips/tcg/fpu_helper.c:1035",
      NULL, 0 },
    { "float_rsqrt_s", { 0 }, { 0 },
      dfu_float_rsqrt_s_env, ARRAY_SIZE(dfu_float_rsqrt_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1045",
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
    { "float_sub_ps", { 0 }, { 0 },
      dfu_float_sub_ps_env, ARRAY_SIZE(dfu_float_sub_ps_env), true,
      "../target/mips/tcg/fpu_helper.c:1273",
      NULL, 0 },
    { "float_sub_s", { 0 }, { 0 },
      dfu_float_sub_s_env, ARRAY_SIZE(dfu_float_sub_s_env), true,
      "../target/mips/tcg/fpu_helper.c:1263",
      NULL, 0 },
    { "float_trunc_l_d", { 0 }, { 0 },
      dfu_float_trunc_l_d_env, ARRAY_SIZE(dfu_float_trunc_l_d_env), true,
      "../target/mips/tcg/fpu_helper.c:473",
      NULL, 0 },
    { "float_trunc_l_s", { 0 }, { 0 },
      dfu_float_trunc_l_s_env, ARRAY_SIZE(dfu_float_trunc_l_s_env), true,
      "../target/mips/tcg/fpu_helper.c:487",
      NULL, 0 },
    { "float_trunc_w_d", { 0 }, { 0 },
      dfu_float_trunc_w_d_env, ARRAY_SIZE(dfu_float_trunc_w_d_env), true,
      "../target/mips/tcg/fpu_helper.c:500",
      NULL, 0 },
    { "float_trunc_w_s", { 0 }, { 0 },
      dfu_float_trunc_w_s_env, ARRAY_SIZE(dfu_float_trunc_w_s_env), true,
      "../target/mips/tcg/fpu_helper.c:513",
      NULL, 0 },
    { "fork", { 0 }, { 0 },
      NULL, 0, true,
      "../target/mips/tcg/op_helper.c:147",
      NULL, 0 },
    { "insv", { 0 }, { 0 },
      dfu_insv_env, ARRAY_SIZE(dfu_insv_env), true,
      "../target/mips/tcg/dsp_helper.c:2946",
      NULL, 0 },
    { "maq_s_w_phl", { 0 }, { 0 },
      dfu_maq_s_w_phl_env, ARRAY_SIZE(dfu_maq_s_w_phl_env), true,
      "../target/mips/tcg/dsp_helper.c:2648",
      NULL, 0 },
    { "maq_sa_w_phl", { 0 }, { 0 },
      dfu_maq_sa_w_phl_env, ARRAY_SIZE(dfu_maq_sa_w_phl_env), true,
      "../target/mips/tcg/dsp_helper.c:2671",
      NULL, 0 },
    { "muleq_s_w_phl", { 0 }, { 0 },
      dfu_muleq_s_w_phl_env, ARRAY_SIZE(dfu_muleq_s_w_phl_env), true,
      "../target/mips/tcg/dsp_helper.c:2033",
      NULL, 0 },
    { "pmon", { 0 }, { 0 },
      dfu_pmon_env, ARRAY_SIZE(dfu_pmon_env), true,
      "../target/mips/tcg/op_helper.c:234",
      NULL, 0 },
    { "precequ_ph_qbl", { 0 }, { 0 },
      NULL, 0, true,
      "../target/mips/tcg/dsp_helper.c:1642",
      NULL, 0 },
    { "preceu_ph_qbl", { 0 }, { 0 },
      NULL, 0, true,
      "../target/mips/tcg/dsp_helper.c:1688",
      NULL, 0 },
    { "precrq_ph_w", { 0 }, { 0 },
      NULL, 0, true,
      "../target/mips/tcg/dsp_helper.c:1406",
      NULL, 0 },
    { "precrq_qb_ph", { 0 }, { 0 },
      NULL, 0, true,
      "../target/mips/tcg/dsp_helper.c:1373",
      NULL, 0 },
    { "raddu_w_qb", { 0 }, { 0 },
      NULL, 0, true,
      "../target/mips/tcg/dsp_helper.c:1331",
      NULL, 0 },
    { "shll_ph", { 0 }, { 0 },
      dfu_shll_ph_env, ARRAY_SIZE(dfu_shll_ph_env), true,
      "../target/mips/tcg/dsp_helper.c:1830",
      NULL, 0 },
    { "shll_qb", { 0 }, { 0 },
      dfu_shll_qb_env, ARRAY_SIZE(dfu_shll_qb_env), true,
      "../target/mips/tcg/dsp_helper.c:1754",
      NULL, 0 },
    { "shll_s_ph", { 0 }, { 0 },
      dfu_shll_s_ph_env, ARRAY_SIZE(dfu_shll_s_ph_env), true,
      "../target/mips/tcg/dsp_helper.c:1831",
      NULL, 0 },
    { "shll_s_w", { 0 }, { 0 },
      dfu_shll_s_w_env, ARRAY_SIZE(dfu_shll_s_w_env), true,
      "../target/mips/tcg/dsp_helper.c:1906",
      NULL, 0 },
    { "shra_qb", { 0 }, { 0 },
      NULL, 0, true,
      "../target/mips/tcg/dsp_helper.c:1757",
      NULL, 0 },
    { "swl", { 0 }, { 0 },
      dfu_swl_env, ARRAY_SIZE(dfu_swl_env), true,
      "../target/mips/tcg/ldst_helper.c:71",
      dfu_swl_acc, ARRAY_SIZE(dfu_swl_acc) },
    { "swr", { 0 }, { 0 },
      dfu_swr_env, ARRAY_SIZE(dfu_swr_env), true,
      "../target/mips/tcg/ldst_helper.c:95",
      dfu_swr_acc, ARRAY_SIZE(dfu_swr_acc) },
    { "yield", { 0 }, { 0 },
      dfu_yield_env, ARRAY_SIZE(dfu_yield_env), true,
      "../target/mips/tcg/op_helper.c:155",
      NULL, 0 },
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
