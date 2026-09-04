#ifndef TARGET_ARM_TRANSLATE_H
#define TARGET_ARM_TRANSLATE_H

#include "cpu.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-op-gvec.h"
#include "exec/exec-all.h"
#include "exec/translator.h"
#include "exec/translation-block.h"
#include "exec/helper-gen.h"
#include "internals.h"
#include "cpu-features.h"
#include "exec/insn-dataflow.h"

/* internal defines */

/*
 * Save pc_save across a branch, so that we may restore the value from
 * before the branch at the point the label is emitted.
 */
typedef struct DisasLabel {
    TCGLabel *label;
    target_ulong pc_save;
} DisasLabel;

typedef struct DisasContext {
    DisasContextBase base;
    const ARMISARegisters *isar;

    /* The address of the current instruction being translated. */
    target_ulong pc_curr;
    /*
     * For CF_PCREL, the full value of cpu_pc is not known
     * (although the page offset is known).  For convenience, the
     * translation loop uses the full virtual address that triggered
     * the translation, from base.pc_start through pc_curr.
     * For efficiency, we do not update cpu_pc for every instruction.
     * Instead, pc_save has the value of pc_curr at the time of the
     * last update to cpu_pc, which allows us to compute the addend
     * needed to bring cpu_pc current: pc_curr - pc_save.
     * If cpu_pc now contains the destination of an indirect branch,
     * pc_save contains -1 to indicate that relative updates are no
     * longer possible.
     */
    target_ulong pc_save;
    target_ulong page_start;
    uint32_t insn;
    /* Nonzero if this instruction has been conditionally skipped.  */
    int condjmp;
    /* The label that will be jumped to when the instruction is skipped.  */
    DisasLabel condlabel;
    /* Thumb-2 conditional execution bits.  */
    int condexec_mask;
    int condexec_cond;
    /* M-profile ECI/ICI exception-continuable instruction state */
    int eci;
    /*
     * trans_ functions for insns which are continuable should set this true
     * after decode (ie after any UNDEF checks)
     */
    bool eci_handled;
    int sctlr_b;
    MemOp be_data;
#if !defined(CONFIG_USER_ONLY)
    int user;
#endif
    ARMMMUIdx mmu_idx; /* MMU index to use for normal loads/stores */
    uint8_t tbii;      /* TBI1|TBI0 for insns */
    uint8_t tbid;      /* TBI1|TBI0 for data */
    uint8_t tcma;      /* TCMA1|TCMA0 for MTE */
    bool ns;        /* Use non-secure CPREG bank on access */
    int fp_excp_el; /* FP exception EL or 0 if enabled */
    int sve_excp_el; /* SVE exception EL or 0 if enabled */
    int sme_excp_el; /* SME exception EL or 0 if enabled */
    int vl;          /* current vector length in bytes */
    int svl;         /* current streaming vector length in bytes */
    bool vfp_enabled; /* FP enabled via FPSCR.EN */
    int vec_len;
    int vec_stride;
    bool v7m_handler_mode;
    bool v8m_secure; /* true if v8M and we're in Secure mode */
    bool v8m_stackcheck; /* true if we need to perform v8M stack limit checks */
    bool v8m_fpccr_s_wrong; /* true if v8M FPCCR.S != v8m_secure */
    bool v7m_new_fp_ctxt_needed; /* ASPEN set but no active FP context */
    bool v7m_lspact; /* FPCCR.LSPACT set */
    /* Immediate value in AArch32 SVC insn; must be set if is_jmp == DISAS_SWI
     * so that top level loop can generate correct syndrome information.
     */
    uint32_t svc_imm;
    int current_el;
    GHashTable *cp_regs;
    uint64_t features; /* CPU features bits */
    bool aarch64;
    bool thumb;
    bool lse2;
    /*
     * Because unallocated encodings generate different exception syndrome
     * information from traps due to FP being disabled, we can't do a single
     * "is fp access disabled" check at a high level in the decode tree.
     * To help in catching bugs where the access check was forgotten in some
     * code path, we set this flag when the access check is done, and assert
     * that it is set at the point where we actually touch the FP regs.
     *   0: not checked,
     *   1: checked, access ok
     *  -1: checked, access denied
     */
    int8_t fp_access_checked;
    int8_t sve_access_checked;
    /* ARMv8 single-step state (this is distinct from the QEMU gdbstub
     * single-step support).
     */
    bool ss_active;
    bool pstate_ss;
    /* True if the insn just emitted was a load-exclusive instruction
     * (necessary for syndrome information for single step exceptions),
     * ie A64 LDX*, LDAX*, A32/T32 LDREX*, LDAEX*.
     */
    bool is_ldex;
    /* True if AccType_UNPRIV should be used for LDTR et al */
    bool unpriv;
    /* True if v8.3-PAuth is active.  */
    bool pauth_active;
    /* True if v8.5-MTE access to tags is enabled; index with is_unpriv.  */
    bool ata[2];
    /* True if v8.5-MTE tag checks affect the PE; index with is_unpriv.  */
    bool mte_active[2];
    /* True with v8.5-BTI and SCTLR_ELx.BT* set.  */
    bool bt;
    /* True if any CP15 access is trapped by HSTR_EL2 */
    bool hstr_active;
    /* True if memory operations require alignment */
    bool align_mem;
    /* True if PSTATE.IL is set */
    bool pstate_il;
    /* True if PSTATE.SM is set. */
    bool pstate_sm;
    /* True if PSTATE.ZA is set. */
    bool pstate_za;
    /* True if non-streaming insns should raise an SME Streaming exception. */
    bool sme_trap_nonstreaming;
    /* True if the current instruction is non-streaming. */
    bool is_nonstreaming;
    /* True if MVE insns are definitely not predicated by VPR or LTPSIZE */
    bool mve_no_pred;
    /* True if fine-grained traps are active */
    bool fgt_active;
    /* True if fine-grained trap on SVC is enabled */
    bool fgt_svc;
    /* True if a trap on ERET is enabled (FGT or NV) */
    bool trap_eret;
    /* True if FEAT_LSE2 SCTLR_ELx.nAA is set */
    bool naa;
    /* True if FEAT_NV HCR_EL2.NV is enabled */
    bool nv;
    /* True if NV enabled and HCR_EL2.NV1 is set */
    bool nv1;
    /* True if NV enabled and HCR_EL2.NV2 is set */
    bool nv2;
    /* True if NV2 enabled and NV2 RAM accesses use EL2&0 translation regime */
    bool nv2_mem_e20;
    /* True if NV2 enabled and NV2 RAM accesses are big-endian */
    bool nv2_mem_be;
    /* True if FPCR.AH is 1 (alternate floating point handling) */
    bool fpcr_ah;
    /* True if FPCR.NEP is 1 (FEAT_AFP scalar upper-element result handling) */
    bool fpcr_nep;
    /*
     * >= 0, a copy of PSTATE.BTYPE, which will be 0 without v8.5-BTI.
     *  < 0, set by the current instruction.
     */
    int8_t btype;
    /* A copy of cpu->dcz_blocksize. */
    uint8_t dcz_blocksize;
    /* A copy of cpu->gm_blocksize. */
    uint8_t gm_blocksize;
    /* True if the current insn_start has been updated. */
    bool insn_start_updated;
    /* Bottom two bits of XScale c15_cpar coprocessor access control reg */
    int c15_cpar;
    /* Offset from VNCR_EL2 when FEAT_NV2 redirects this reg to memory */
    uint32_t nv2_redirect_offset;
} DisasContext;

typedef struct DisasCompare {
    TCGCond cond;
    TCGv_i32 value;
} DisasCompare;

/* Share the TCG temporaries common between 32 and 64 bit modes.  */
extern TCGv_i32 cpu_NF, cpu_ZF, cpu_CF, cpu_VF;
extern TCGv_i64 cpu_exclusive_addr;
extern TCGv_i64 cpu_exclusive_val;

/*
 * Constant expanders for the decoders.
 */

static inline int negate(DisasContext *s, int x)
{
    return -x;
}

static inline int plus_1(DisasContext *s, int x)
{
    return x + 1;
}

static inline int plus_2(DisasContext *s, int x)
{
    return x + 2;
}

static inline int plus_12(DisasContext *s, int x)
{
    return x + 12;
}

static inline int times_2(DisasContext *s, int x)
{
    return x * 2;
}

static inline int times_4(DisasContext *s, int x)
{
    return x * 4;
}

static inline int times_8(DisasContext *s, int x)
{
    return x * 8;
}

static inline int times_2_plus_1(DisasContext *s, int x)
{
    return x * 2 + 1;
}

/*
 * The Advanced SIMD modified-immediate table fixes some of cmode's four
 * bits per row and leaves the rest free; these rebuild the whole cmode
 * value from the free ones.  x is bit 13 for the 10x0 / 10x1 rows.
 */
static inline int times_2_plus_8(DisasContext *s, int x)
{
    return x * 2 + 8;
}

static inline int times_2_plus_9(DisasContext *s, int x)
{
    return x * 2 + 9;
}

static inline int rsub_64(DisasContext *s, int x)
{
    return 64 - x;
}

static inline int rsub_32(DisasContext *s, int x)
{
    return 32 - x;
}

static inline int rsub_16(DisasContext *s, int x)
{
    return 16 - x;
}

static inline int rsub_8(DisasContext *s, int x)
{
    return 8 - x;
}

static inline int shl_12(DisasContext *s, int x)
{
    return x << 12;
}

static inline int xor_2(DisasContext *s, int x)
{
    return x ^ 2;
}

static inline int neon_3same_fp_size(DisasContext *s, int x)
{
    /* Convert 0==fp32, 1==fp16 into a MO_* value */
    return MO_32 - x;
}

static inline int arm_dc_feature(DisasContext *dc, int feature)
{
    return (dc->features & (1ULL << feature)) != 0;
}

static inline int get_mem_index(DisasContext *s)
{
    return arm_to_core_mmu_idx(s->mmu_idx);
}

static inline void disas_set_insn_syndrome(DisasContext *s, uint32_t syn)
{
    /* We don't need to save all of the syndrome so we mask and shift
     * out unneeded bits to help the sleb128 encoder do a better job.
     */
    syn &= ARM_INSN_START_WORD2_MASK;
    syn >>= ARM_INSN_START_WORD2_SHIFT;

    /* Check for multiple updates.  */
    assert(!s->insn_start_updated);
    s->insn_start_updated = true;
    tcg_set_insn_start_param(s->base.insn_start, 2, syn);
}

static inline int curr_insn_len(DisasContext *s)
{
    return s->base.pc_next - s->pc_curr;
}

/* is_jmp field values */
#define DISAS_JUMP      DISAS_TARGET_0 /* only pc was modified dynamically */
/* CPU state was modified dynamically; exit to main loop for interrupts. */
#define DISAS_UPDATE_EXIT  DISAS_TARGET_1
/* These instructions trap after executing, so the A32/T32 decoder must
 * defer them until after the conditional execution state has been updated.
 * WFI also needs special handling when single-stepping.
 */
#define DISAS_WFI       DISAS_TARGET_2
#define DISAS_SWI       DISAS_TARGET_3
/* WFE */
#define DISAS_WFE       DISAS_TARGET_4
#define DISAS_HVC       DISAS_TARGET_5
#define DISAS_SMC       DISAS_TARGET_6
#define DISAS_YIELD     DISAS_TARGET_7
/* M profile branch which might be an exception return (and so needs
 * custom end-of-TB code)
 */
#define DISAS_BX_EXCRET DISAS_TARGET_8
/*
 * For instructions which want an immediate exit to the main loop, as opposed
 * to attempting to use lookup_and_goto_ptr.  Unlike DISAS_UPDATE_EXIT, this
 * doesn't write the PC on exiting the translation loop so you need to ensure
 * something (gen_a64_update_pc or runtime helper) has done so before we reach
 * return from cpu_tb_exec.
 */
#define DISAS_EXIT      DISAS_TARGET_9
/* CPU state was modified dynamically; no need to exit, but do not chain. */
#define DISAS_UPDATE_NOCHAIN  DISAS_TARGET_10

#ifdef TARGET_AARCH64
void a64_translate_init(void);
void gen_a64_update_pc(DisasContext *s, target_long diff);
extern const TranslatorOps aarch64_translator_ops;
#else
static inline void a64_translate_init(void)
{
}

static inline void gen_a64_update_pc(DisasContext *s, target_long diff)
{
}
#endif

void arm_test_cc(DisasCompare *cmp, int cc);
void arm_jump_cc(DisasCompare *cmp, TCGLabel *label);
void arm_gen_test_cc(int cc, TCGLabel *label);
MemOp pow2_align(unsigned i);
void unallocated_encoding(DisasContext *s);
void gen_exception_insn_el(DisasContext *s, target_long pc_diff, int excp,
                           uint32_t syn, uint32_t target_el);
void gen_exception_insn(DisasContext *s, target_long pc_diff,
                        int excp, uint32_t syn);

/* Return state of Alternate Half-precision flag, caller frees result */
static inline TCGv_i32 get_ahp_flag(void)
{
    TCGv_i32 ret = tcg_temp_new_i32();

    tcg_gen_ld_i32(ret, tcg_env, offsetoflow32(CPUARMState, vfp.fpcr));
    tcg_gen_extract_i32(ret, ret, 26, 1);

    return ret;
}

/* Set bits within PSTATE.  */
static inline void set_pstate_bits(uint32_t bits)
{
    TCGv_i32 p = tcg_temp_new_i32();

    tcg_debug_assert(!(bits & CACHED_PSTATE_BITS));

    tcg_gen_ld_i32(p, tcg_env, offsetof(CPUARMState, pstate));
    tcg_gen_ori_i32(p, p, bits);
    tcg_gen_st_i32(p, tcg_env, offsetof(CPUARMState, pstate));
}

/* Clear bits within PSTATE.  */
static inline void clear_pstate_bits(uint32_t bits)
{
    TCGv_i32 p = tcg_temp_new_i32();

    tcg_debug_assert(!(bits & CACHED_PSTATE_BITS));

    tcg_gen_ld_i32(p, tcg_env, offsetof(CPUARMState, pstate));
    tcg_gen_andi_i32(p, p, ~bits);
    tcg_gen_st_i32(p, tcg_env, offsetof(CPUARMState, pstate));
}

/* If the singlestep state is Active-not-pending, advance to Active-pending. */
static inline void gen_ss_advance(DisasContext *s)
{
    if (s->ss_active) {
        s->pstate_ss = 0;
        clear_pstate_bits(PSTATE_SS);
    }
}

/* Generate an architectural singlestep exception */
static inline void gen_swstep_exception(DisasContext *s, int isv, int ex)
{
    /* Fill in the same_el field of the syndrome in the helper. */
    uint32_t syn = syn_swstep(false, isv, ex);
    gen_helper_exception_swstep(tcg_env, tcg_constant_i32(syn));
}

/*
 * Given a VFP floating point constant encoded into an 8 bit immediate in an
 * instruction, expand it to the actual constant value of the specified
 * size, as per the VFPExpandImm() pseudocode in the Arm ARM.
 */
uint64_t vfp_expand_imm(int size, uint8_t imm8);

static inline void gen_vfp_absh(TCGv_i32 d, TCGv_i32 s)
{
    tcg_gen_andi_i32(d, s, INT16_MAX);
}

static inline void gen_vfp_abss(TCGv_i32 d, TCGv_i32 s)
{
    tcg_gen_andi_i32(d, s, INT32_MAX);
}

static inline void gen_vfp_absd(TCGv_i64 d, TCGv_i64 s)
{
    tcg_gen_andi_i64(d, s, INT64_MAX);
}

static inline void gen_vfp_negh(TCGv_i32 d, TCGv_i32 s)
{
    tcg_gen_xori_i32(d, s, 1u << 15);
}

static inline void gen_vfp_negs(TCGv_i32 d, TCGv_i32 s)
{
    tcg_gen_xori_i32(d, s, 1u << 31);
}

static inline void gen_vfp_negd(TCGv_i64 d, TCGv_i64 s)
{
    tcg_gen_xori_i64(d, s, 1ull << 63);
}

/* Vector operations shared between ARM and AArch64.  */
void gen_gvec_ceq0(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                   uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_clt0(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                   uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_cgt0(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                   uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_cle0(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                   uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_cge0(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                   uint32_t opr_sz, uint32_t max_sz);

void gen_gvec_mla(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                  uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_mls(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                  uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);

void gen_gvec_cmtst(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_sshl(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                   uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_ushl(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                   uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_srshl(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_urshl(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_neon_sqshl(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_neon_uqshl(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_neon_sqrshl(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                     uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_neon_uqrshl(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                     uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);

void gen_neon_sqshli(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                     int64_t c, uint32_t opr_sz, uint32_t max_sz);
void gen_neon_uqshli(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                     int64_t c, uint32_t opr_sz, uint32_t max_sz);
void gen_neon_sqshlui(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                      int64_t c, uint32_t opr_sz, uint32_t max_sz);

void gen_gvec_shadd(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_uhadd(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_shsub(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_uhsub(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_srhadd(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                     uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_urhadd(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                     uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);

void gen_cmtst_i64(TCGv_i64 d, TCGv_i64 a, TCGv_i64 b);
void gen_ushl_i32(TCGv_i32 d, TCGv_i32 a, TCGv_i32 b);
void gen_sshl_i32(TCGv_i32 d, TCGv_i32 a, TCGv_i32 b);
void gen_ushl_i64(TCGv_i64 d, TCGv_i64 a, TCGv_i64 b);
void gen_sshl_i64(TCGv_i64 d, TCGv_i64 a, TCGv_i64 b);

void gen_uqadd_bhs(TCGv_i64 res, TCGv_i64 qc,
                   TCGv_i64 a, TCGv_i64 b, MemOp esz);
void gen_uqadd_d(TCGv_i64 d, TCGv_i64 q, TCGv_i64 a, TCGv_i64 b);
void gen_gvec_uqadd_qc(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                       uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);

void gen_sqadd_bhs(TCGv_i64 res, TCGv_i64 qc,
                   TCGv_i64 a, TCGv_i64 b, MemOp esz);
void gen_sqadd_d(TCGv_i64 d, TCGv_i64 q, TCGv_i64 a, TCGv_i64 b);
void gen_gvec_sqadd_qc(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                       uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);

void gen_uqsub_bhs(TCGv_i64 res, TCGv_i64 qc,
                   TCGv_i64 a, TCGv_i64 b, MemOp esz);
void gen_uqsub_d(TCGv_i64 d, TCGv_i64 q, TCGv_i64 a, TCGv_i64 b);
void gen_gvec_uqsub_qc(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                       uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);

void gen_sqsub_bhs(TCGv_i64 res, TCGv_i64 qc,
                   TCGv_i64 a, TCGv_i64 b, MemOp esz);
void gen_sqsub_d(TCGv_i64 d, TCGv_i64 q, TCGv_i64 a, TCGv_i64 b);
void gen_gvec_sqsub_qc(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                       uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);

void gen_gvec_sshr(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                   int64_t shift, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_ushr(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                   int64_t shift, uint32_t opr_sz, uint32_t max_sz);

void gen_gvec_ssra(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                   int64_t shift, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_usra(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                   int64_t shift, uint32_t opr_sz, uint32_t max_sz);

void gen_srshr32_i32(TCGv_i32 d, TCGv_i32 a, int32_t sh);
void gen_srshr64_i64(TCGv_i64 d, TCGv_i64 a, int64_t sh);
void gen_urshr32_i32(TCGv_i32 d, TCGv_i32 a, int32_t sh);
void gen_urshr64_i64(TCGv_i64 d, TCGv_i64 a, int64_t sh);

void gen_gvec_srshr(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                    int64_t shift, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_urshr(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                    int64_t shift, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_srsra(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                    int64_t shift, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_ursra(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                    int64_t shift, uint32_t opr_sz, uint32_t max_sz);

void gen_gvec_sri(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                  int64_t shift, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_sli(unsigned vece, uint32_t rd_ofs, uint32_t rm_ofs,
                  int64_t shift, uint32_t opr_sz, uint32_t max_sz);

void gen_gvec_sqdmulh_qc(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                         uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_sqrdmulh_qc(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                          uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_sqrdmlah_qc(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                          uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_sqrdmlsh_qc(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                          uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);

void gen_gvec_sabd(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                   uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_uabd(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                   uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);

void gen_gvec_saba(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                   uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_uaba(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                   uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);

void gen_gvec_addp(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                   uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_smaxp(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_sminp(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_umaxp(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_uminp(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t rm_ofs, uint32_t opr_sz, uint32_t max_sz);

void gen_gvec_cls(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                  uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_clz(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                  uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_cnt(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                  uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_rbit(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                   uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_rev16(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_rev32(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_rev64(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                    uint32_t opr_sz, uint32_t max_sz);

void gen_gvec_saddlp(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                     uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_sadalp(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                     uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_uaddlp(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                     uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_uadalp(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                     uint32_t opr_sz, uint32_t max_sz);

/* These exclusively manipulate the sign bit. */
void gen_gvec_fabs(unsigned vece, uint32_t dofs, uint32_t aofs,
                   uint32_t oprsz, uint32_t maxsz);
void gen_gvec_fneg(unsigned vece, uint32_t dofs, uint32_t aofs,
                   uint32_t oprsz, uint32_t maxsz);

void gen_gvec_urecpe(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                     uint32_t opr_sz, uint32_t max_sz);
void gen_gvec_ursqrte(unsigned vece, uint32_t rd_ofs, uint32_t rn_ofs,
                      uint32_t opr_sz, uint32_t max_sz);

/*
 * Forward to the isar_feature_* tests given a DisasContext pointer.
 */
#define dc_isar_feature(name, ctx) \
    ({ DisasContext *ctx_ = (ctx); isar_feature_##name(ctx_->isar); })

/* Note that the gvec expanders operate on offsets + sizes.  */
typedef void GVecGen2Fn(unsigned, uint32_t, uint32_t, uint32_t, uint32_t);
typedef void GVecGen2iFn(unsigned, uint32_t, uint32_t, int64_t,
                         uint32_t, uint32_t);
typedef void GVecGen3Fn(unsigned, uint32_t, uint32_t,
                        uint32_t, uint32_t, uint32_t);
typedef void GVecGen4Fn(unsigned, uint32_t, uint32_t, uint32_t,
                        uint32_t, uint32_t, uint32_t);

/* Function prototype for gen_ functions for calling Neon helpers */
typedef void NeonGenOneOpFn(TCGv_i32, TCGv_i32);
typedef void NeonGenOneOpEnvFn(TCGv_i32, TCGv_ptr, TCGv_i32);
typedef void NeonGenTwoOpFn(TCGv_i32, TCGv_i32, TCGv_i32);
typedef void NeonGenTwoOpEnvFn(TCGv_i32, TCGv_ptr, TCGv_i32, TCGv_i32);
typedef void NeonGenThreeOpEnvFn(TCGv_i32, TCGv_env, TCGv_i32,
                                 TCGv_i32, TCGv_i32);
typedef void NeonGenTwo64OpFn(TCGv_i64, TCGv_i64, TCGv_i64);
typedef void NeonGenTwo64OpEnvFn(TCGv_i64, TCGv_ptr, TCGv_i64, TCGv_i64);
typedef void NeonGenNarrowFn(TCGv_i32, TCGv_i64);
typedef void NeonGenWidenFn(TCGv_i64, TCGv_i32);
typedef void NeonGenTwoOpWidenFn(TCGv_i64, TCGv_i32, TCGv_i32);
typedef void NeonGenOneSingleOpFn(TCGv_i32, TCGv_i32, TCGv_ptr);
typedef void NeonGenTwoSingleOpFn(TCGv_i32, TCGv_i32, TCGv_i32, TCGv_ptr);
typedef void NeonGenTwoDoubleOpFn(TCGv_i64, TCGv_i64, TCGv_i64, TCGv_ptr);
typedef void NeonGenOne64OpFn(TCGv_i64, TCGv_i64);
typedef void NeonGenOne64OpEnvFn(TCGv_i64, TCGv_env, TCGv_i64);
typedef void CryptoTwoOpFn(TCGv_ptr, TCGv_ptr);
typedef void CryptoThreeOpIntFn(TCGv_ptr, TCGv_ptr, TCGv_i32);
typedef void CryptoThreeOpFn(TCGv_ptr, TCGv_ptr, TCGv_ptr);
typedef void AtomicThreeOpFn(TCGv_i64, TCGv_i64, TCGv_i64, TCGArg, MemOp);
typedef void WideShiftImmFn(TCGv_i64, TCGv_i64, int64_t shift);
typedef void WideShiftFn(TCGv_i64, TCGv_ptr, TCGv_i64, TCGv_i32);
typedef void ShiftImmFn(TCGv_i32, TCGv_i32, int32_t shift);
typedef void ShiftFn(TCGv_i32, TCGv_ptr, TCGv_i32, TCGv_i32);

/**
 * arm_tbflags_from_tb:
 * @tb: the TranslationBlock
 *
 * Extract the flag values from @tb.
 */
static inline CPUARMTBFlags arm_tbflags_from_tb(const TranslationBlock *tb)
{
    return (CPUARMTBFlags){ tb->flags, tb->cs_base };
}

/**
 * fpstatus_ptr: return TCGv_ptr to the specified fp_status field
 *
 * We have multiple softfloat float_status fields in the Arm CPU state struct
 * (see the comment in cpu.h for details). Return a TCGv_ptr which has
 * been set up to point to the requested field in the CPU state struct.
 */
/*
 * THE FP CONTROL AND STATUS THE INSTRUCTION OPERATES UNDER.
 *
 * Split out of fpstatus_ptr() below so that the handful of emitters which
 * hand the helper tcg_env INSTEAD of a status pointer -- FMLAL and its
 * siblings, which reach vfp.fp_status[FPST_A64] and vfp.fpcr from inside
 * the helper -- can state the same fact in the same terms.  For those, the
 * pointer the walk would have followed does not exist at all.
 */
static inline void note_fpstatus_read(ARMFPStatusFlavour flavour)
{
    insn_dataflow_note_stated_read_env(
        offsetof(CPUARMState, vfp.fp_status[flavour]),
        sizeof(((CPUARMState *)0)->vfp.fp_status[0]));
}

/*
 * THE FP STATUS THE INSTRUCTION ACCUMULATES ITS EXCEPTIONS INTO.
 *
 * The write twin of note_fpstatus_read(), and needed at the same sites: an
 * FP instruction's cumulative exception bits are set by softfloat inside the
 * helper, so the ops the translation emitted name the status POINTER and
 * never a write of the bytes it addresses.  The register the architecture
 * says the instruction updates is missing from the write side entirely, and a
 * missing destination is a dependency edge that does not exist.
 *
 * WHICH FLAVOURS, and it is QEMU's own answer rather than a judgement made
 * here.  vfp_get_fpsr_from_host() ORs the accrued flags of six of the eight
 * status words into FPSR and deliberately skips FPST_AH and FPST_AH_F16,
 * "because they are used for insns that must not set the cumulative exception
 * bits" -- FPCR.AH == 1 is defined to suppress exactly that.  So the two AH
 * flavours are REFUSED here: stating a write for them would put a register on
 * the wire that the instruction does not update, which is the direction the
 * x87 `fnop` arm was caught in at PASS 57 and the reason that arm was cut.
 *
 * BY RANGE, on the read note's rule: the range IS the register, named by the
 * insn_dataflow_declare_regfile("fp_status", ...) in translate-a64.c, so one
 * declaration names the read, the write and every ordinary access alike.
 *
 * WHAT IT DOES NOT SAY.  Nothing about the VALUE: the flags an execution
 * actually raises are a property of the operands, not of the encoding, and
 * this note is the STATIC fact that the encoding updates the register (R20).
 * A consumer that needs the inputs reads the instruction's source list, which
 * note_fpstatus_read() already fills with the same register.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
static inline void note_fpstatus_write(ARMFPStatusFlavour flavour)
{
    if (flavour == FPST_AH || flavour == FPST_AH_F16) {
        return;
    }
    insn_dataflow_note_stated_write_env(
        offsetof(CPUARMState, vfp.fp_status[flavour]),
        sizeof(((CPUARMState *)0)->vfp.fp_status[0]));
}

/*
 * FPSR.QC, THE CUMULATIVE SATURATION BIT, IN BOTH DIRECTIONS.
 *
 * The saturating integer vector instructions raise FPSR.QC when a lane
 * clips.  QEMU keeps the bit in vfp.qc[] apart from the rest of the status
 * word, and reaches it three different ways: as a gvec OPERAND (the
 * expander states its own direction and owes nothing), as a POINTER handed
 * to a gvec helper, and from inside an env-taking helper.  The last two
 * emit no op that names the bytes, so without a statement here the register
 * the instruction exists to update is missing from the wire entirely --
 * measured at PASS 69 as 9,408 aarch64 encodings over 35 saturating
 * mnemonics publishing QC as a destination with QEMU stating neither
 * direction.
 *
 * IT IS A READ AS WELL AS A WRITE, and that is R17 rather than a judgement
 * made here.  QC is STICKY: a lane that does not saturate leaves the bit
 * exactly as it found it, so the value the instruction leaves behind
 * depends on the value it was handed.  93247f8507 ruled that shape a
 * merging partial write in its own words -- "the value written depends on
 * the value held" -- and stated the source for the softfloat status word on
 * the same ground.  The saturating forms are the same shape and get the
 * same answer.
 *
 * THE RANGE IS THE REGISTER, named by the
 * insn_dataflow_declare_regfile("fpsr_qc", ...) in translate-a64.c, so one
 * declaration names the read, the write and every ordinary access alike.
 *
 * WHAT IT DOES NOT SAY.  Nothing about the VALUE: whether an execution
 * actually clipped is a property of the operands, not of the encoding, and
 * this is the STATIC fact that the encoding reads and updates the register
 * (R20).
 *
 * STATED ONCE PER INSTRUCTION, by the emitter that runs once -- a gvec
 * constructor, or the wrapper around an element loop -- never from inside
 * the loop body.  A note per element would say the same thing N times and
 * spend the translation's note budget saying it.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
static inline void note_fpsr_qc_read(void)
{
    insn_dataflow_note_stated_read_env(offsetof(CPUARMState, vfp.qc),
                                       sizeof(((CPUARMState *)0)->vfp.qc));
}

static inline void note_fpsr_qc_write(void)
{
    insn_dataflow_note_stated_write_env(offsetof(CPUARMState, vfp.qc),
                                        sizeof(((CPUARMState *)0)->vfp.qc));
}

/* Both halves of the sticky bit, which is what a saturating form owes. */
static inline void note_fpsr_qc(void)
{
    note_fpsr_qc_read();
    note_fpsr_qc_write();
}

static inline TCGv_ptr fpstatus_ptr(ARMFPStatusFlavour flavour)
{
    TCGv_ptr statusptr = tcg_temp_new_ptr();
    int offset = offsetof(CPUARMState, vfp.fp_status[flavour]);

    tcg_gen_addi_ptr(statusptr, tcg_env, offset);

    /*
     * THE FP CONTROL AND STATUS THE INSTRUCTION OPERATES UNDER, stated here
     * because here is where the fact is: this function exists for one
     * purpose, to hand a floating-point helper the status word its result
     * depends on, and every caller is an instruction that reads the rounding
     * mode, the flush-to-zero and default-NaN behaviour, or both.
     *
     * WHAT IT REPLACES.  The pointer built above is an ADDRESS computed from
     * tcg_env, not a read of the bytes it addresses, so the read reaches the
     * ordered list only through the helper's own usage row -- and only where
     * that row exists and carries an argument size.  Measured on the sled at
     * PASS 49, that made the answer a property of the TABLE rather than of
     * the architecture: `ucvtf` published REG_FCSR on 1,248 encodings of one
     * decode rule and not on the 1,824 beside them, three widths of one
     * instruction disagreeing about a register all three of them read.  That
     * is the same shape a76f8026d6 found on x86 div/idiv, and it has the same
     * answer -- state it at the site that knows, once, for every form.
     *
     * BY RANGE, because the range IS the register: it is the offsetof()/
     * sizeof() pair insn_dataflow_declare_regfile("fp_status", ...) already
     * takes in translate-a64.c, so the declaration that names every other
     * access to these bytes names this one too and there is no second
     * spelling to keep in step.  (The predicate file is stated by NAME for
     * the opposite reason: it is not declared, and declaring it would rename
     * accesses whose direction the extraction cannot see.)
     *
     * Capture only; no op is emitted, altered or suppressed.
     */
    note_fpstatus_read(flavour);
    note_fpstatus_write(flavour);
    return statusptr;
}

/**
 * finalize_memop_atom:
 * @s: DisasContext
 * @opc: size+sign+align of the memory operation
 * @atom: atomicity of the memory operation
 *
 * Build the complete MemOp for a memory operation, including alignment,
 * endianness, and atomicity.
 *
 * If (op & MO_AMASK) then the operation already contains the required
 * alignment, e.g. for AccType_ATOMIC.  Otherwise, this an optionally
 * unaligned operation, e.g. for AccType_NORMAL.
 *
 * In the latter case, there are configuration bits that require alignment,
 * and this is applied here.  Note that there is no way to indicate that
 * no alignment should ever be enforced; this must be handled manually.
 */
static inline MemOp finalize_memop_atom(DisasContext *s, MemOp opc, MemOp atom)
{
    if (s->align_mem && !(opc & MO_AMASK)) {
        opc |= MO_ALIGN;
    }
    return opc | atom | s->be_data;
}

/**
 * finalize_memop:
 * @s: DisasContext
 * @opc: size+sign+align of the memory operation
 *
 * Like finalize_memop_atom, but with default atomicity.
 */
static inline MemOp finalize_memop(DisasContext *s, MemOp opc)
{
    MemOp atom = s->lse2 ? MO_ATOM_WITHIN16 : MO_ATOM_IFALIGN;
    return finalize_memop_atom(s, opc, atom);
}

/**
 * finalize_memop_pair:
 * @s: DisasContext
 * @opc: size+sign+align of the memory operation
 *
 * Like finalize_memop_atom, but with atomicity for a pair.
 * C.f. Pseudocode for Mem[], operand ispair.
 */
static inline MemOp finalize_memop_pair(DisasContext *s, MemOp opc)
{
    MemOp atom = s->lse2 ? MO_ATOM_WITHIN16_PAIR : MO_ATOM_IFALIGN_PAIR;
    return finalize_memop_atom(s, opc, atom);
}

/**
 * finalize_memop_asimd:
 * @s: DisasContext
 * @opc: size+sign+align of the memory operation
 *
 * Like finalize_memop_atom, but with atomicity of AccessType_ASIMD.
 */
static inline MemOp finalize_memop_asimd(DisasContext *s, MemOp opc)
{
    /*
     * In the pseudocode for Mem[], with AccessType_ASIMD, size == 16,
     * if IsAligned(8), the first case provides separate atomicity for
     * the pair of 64-bit accesses.  If !IsAligned(8), the middle cases
     * do not apply, and we're left with the final case of no atomicity.
     * Thus MO_ATOM_IFALIGN_PAIR.
     *
     * For other sizes, normal LSE2 rules apply.
     */
    if ((opc & MO_SIZE) == MO_128) {
        return finalize_memop_atom(s, opc, MO_ATOM_IFALIGN_PAIR);
    }
    return finalize_memop(s, opc);
}

/**
 * asimd_imm_const: Expand an encoded SIMD constant value
 *
 * Expand a SIMD constant value. This is essentially the pseudocode
 * AdvSIMDExpandImm, except that we also perform the boolean NOT needed for
 * VMVN and VBIC (when cmode < 14 && op == 1).
 *
 * The combination cmode == 15 op == 1 is a reserved encoding for AArch32;
 * callers must catch this; we return the 64-bit constant value defined
 * for AArch64.
 *
 * cmode = 2,3,4,5,6,7,10,11,12,13 imm=0 was UNPREDICTABLE in v7A but
 * is either not unpredictable or merely CONSTRAINED UNPREDICTABLE in v8A;
 * we produce an immediate constant value of 0 in these cases.
 */
uint64_t asimd_imm_const(uint32_t imm, int cmode, int op);

/*
 * gen_disas_label:
 * Create a label and cache a copy of pc_save.
 */
static inline DisasLabel gen_disas_label(DisasContext *s)
{
    return (DisasLabel){
        .label = gen_new_label(),
        .pc_save = s->pc_save,
    };
}

/*
 * set_disas_label:
 * Emit a label and restore the cached copy of pc_save.
 */
static inline void set_disas_label(DisasContext *s, DisasLabel l)
{
    gen_set_label(l.label);
    s->pc_save = l.pc_save;
}

static inline TCGv_ptr gen_lookup_cp_reg(uint32_t key)
{
    TCGv_ptr ret = tcg_temp_new_ptr();
    gen_helper_lookup_cp_reg(ret, tcg_env, tcg_constant_i32(key));
    return ret;
}

/*
 * Set and reset rounding mode around another operation.
 */
static inline TCGv_i32 gen_set_rmode(ARMFPRounding rmode, TCGv_ptr fpst)
{
    TCGv_i32 new = tcg_constant_i32(arm_rmode_to_sf(rmode));
    TCGv_i32 old = tcg_temp_new_i32();

    gen_helper_set_rmode(old, new, fpst);
    return old;
}

static inline void gen_restore_rmode(TCGv_i32 old, TCGv_ptr fpst)
{
    gen_helper_set_rmode(old, old, fpst);
}

/*
 * Helpers for implementing sets of trans_* functions.
 * Defer the implementation of NAME to FUNC, with optional extra arguments.
 */
#define TRANS(NAME, FUNC, ...) \
    static bool trans_##NAME(DisasContext *s, arg_##NAME *a) \
    { return FUNC(s, __VA_ARGS__); }
#define TRANS_FEAT(NAME, FEAT, FUNC, ...) \
    static bool trans_##NAME(DisasContext *s, arg_##NAME *a) \
    { return dc_isar_feature(FEAT, s) && FUNC(s, __VA_ARGS__); }

#define TRANS_FEAT_NONSTREAMING(NAME, FEAT, FUNC, ...)            \
    static bool trans_##NAME(DisasContext *s, arg_##NAME *a)      \
    {                                                             \
        s->is_nonstreaming = true;                                \
        return dc_isar_feature(FEAT, s) && FUNC(s, __VA_ARGS__);  \
    }

#endif /* TARGET_ARM_TRANSLATE_H */
