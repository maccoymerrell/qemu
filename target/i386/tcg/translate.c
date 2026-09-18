/*
 *  i386 translation
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"

#include "qemu/host-utils.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/plugin-gen.h"
#include "exec/translation-block.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-op-gvec.h"
#include "exec/translator.h"
#include "exec/insn-dataflow.h"
#include "fpu/softfloat.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "helper-tcg.h"
#include "decode-new.h"

#include "exec/log.h"

#define HELPER_H "helper.h"
#include "exec/helper-info.c.inc"
#undef  HELPER_H

/* Fixes for Windows namespace pollution.  */
#undef IN
#undef OUT

#define PREFIX_REPZ   0x01
#define PREFIX_REPNZ  0x02
#define PREFIX_LOCK   0x04
#define PREFIX_DATA   0x08
#define PREFIX_ADR    0x10
#define PREFIX_VEX    0x20
#define PREFIX_REX    0x40

/*
 * The name the program counter's TCG global is registered under.
 *
 * It is spelled once because two places need the same string: the
 * registration itself, and the decode sites that name the register in a
 * dataflow statement where no op does.  insn_df_reg() resolves an atom by
 * looking the name up among the globals, so the two spellings agreeing is
 * not a nicety -- a mismatch resolves to nothing and drops the source.
 */
#ifdef TARGET_X86_64
# define X86_DF_PC_NAME "rip"
#else
# define X86_DF_PC_NAME "eip"
#endif

/*
 * The names the general-purpose TCG globals are registered under.
 *
 * At file scope because the decode sites need them too: a statement that
 * names a register the emitter folded away resolves by NAME, and the name
 * has to be the one the global carries.
 */
static const char x86_reg_names[CPU_NB_REGS][4] = {
#ifdef TARGET_X86_64
    [R_EAX] = "rax",
    [R_EBX] = "rbx",
    [R_ECX] = "rcx",
    [R_EDX] = "rdx",
    [R_ESI] = "rsi",
    [R_EDI] = "rdi",
    [R_EBP] = "rbp",
    [R_ESP] = "rsp",
    [8]  = "r8",
    [9]  = "r9",
    [10] = "r10",
    [11] = "r11",
    [12] = "r12",
    [13] = "r13",
    [14] = "r14",
    [15] = "r15",
#else
    [R_EAX] = "eax",
    [R_EBX] = "ebx",
    [R_ECX] = "ecx",
    [R_EDX] = "edx",
    [R_ESI] = "esi",
    [R_EDI] = "edi",
    [R_EBP] = "ebp",
    [R_ESP] = "esp",
#endif
};

#ifdef TARGET_X86_64
# define ctztl  ctz64
# define clztl  clz64
#else
# define ctztl  ctz32
# define clztl  clz32
#endif

/* For a switch indexed by MODRM, match all memory operands for a given OP.  */
#define CASE_MODRM_MEM_OP(OP) \
    case (0 << 6) | (OP << 3) | 0 ... (0 << 6) | (OP << 3) | 7: \
    case (1 << 6) | (OP << 3) | 0 ... (1 << 6) | (OP << 3) | 7: \
    case (2 << 6) | (OP << 3) | 0 ... (2 << 6) | (OP << 3) | 7

#define CASE_MODRM_OP(OP) \
    case (0 << 6) | (OP << 3) | 0 ... (0 << 6) | (OP << 3) | 7: \
    case (1 << 6) | (OP << 3) | 0 ... (1 << 6) | (OP << 3) | 7: \
    case (2 << 6) | (OP << 3) | 0 ... (2 << 6) | (OP << 3) | 7: \
    case (3 << 6) | (OP << 3) | 0 ... (3 << 6) | (OP << 3) | 7

//#define MACRO_TEST   1

/* global register indexes */
static TCGv cpu_cc_dst, cpu_cc_src, cpu_cc_src2;
static TCGv cpu_eip;
static TCGv_i32 cpu_cc_op;
static TCGv cpu_regs[CPU_NB_REGS];
static TCGv cpu_seg_base[6];
/*
 * The names cpu_seg_base[] is registered under, at file scope because two
 * places need them: tcg_x86_init, which registers the globals, and
 * gen_movl_seg(), which states the write a helper hides.  One table so the
 * statement cannot drift from the registration.
 */
static const char seg_base_names[6][8] = {
    [R_CS] = "cs_base",
    [R_DS] = "ds_base",
    [R_ES] = "es_base",
    [R_FS] = "fs_base",
    [R_GS] = "gs_base",
    [R_SS] = "ss_base",
};
/*
 * The names the vector register file is declared under, at file scope for the
 * same reason: tcg_x86_init declares the file, and the emitter of a
 * partial-width move states the read of the half it leaves alone.
 */
static const char *const x86_xmm_names[] = {
    "xmm0",  "xmm1",  "xmm2",  "xmm3",  "xmm4",  "xmm5",
    "xmm6",  "xmm7",  "xmm8",  "xmm9",  "xmm10", "xmm11",
    "xmm12", "xmm13", "xmm14", "xmm15", "xmm16", "xmm17",
    "xmm18", "xmm19", "xmm20", "xmm21", "xmm22", "xmm23",
    "xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29",
    "xmm30", "xmm31",
};
static TCGv_i64 cpu_bndl[4];
static TCGv_i64 cpu_bndu[4];

typedef struct DisasContext {
    DisasContextBase base;

    target_ulong pc;       /* pc = eip + cs_base */
    target_ulong cs_base;  /* base of CS segment */
    target_ulong pc_save;

    MemOp aflag;
    MemOp dflag;

    int8_t override; /* -1 if no override, else R_CS, R_DS, etc */
    uint8_t prefix;

    bool has_modrm;
    uint8_t modrm;

#ifndef CONFIG_USER_ONLY
    uint8_t cpl;   /* code priv level */
    uint8_t iopl;  /* i/o priv level */
#endif
    uint8_t vex_l;  /* vex vector length */
    uint8_t vex_v;  /* vex vvvv register, without 1's complement.  */
    uint8_t popl_esp_hack; /* for correct popl with esp base handling */
    uint8_t rip_offset; /* only used in x86_64, but left for simplicity */

#ifdef TARGET_X86_64
    uint8_t rex_r;
    uint8_t rex_x;
    uint8_t rex_b;
#endif
    bool vex_w; /* used by AVX even on 32-bit processors */
    bool jmp_opt; /* use direct block chaining for direct jumps */
    bool cc_op_dirty;

    CCOp cc_op;  /* current CC operation */
    int mem_index; /* select memory access functions */
    uint32_t flags; /* all execution flags */
    int cpuid_features;
    int cpuid_ext_features;
    int cpuid_ext2_features;
    int cpuid_ext3_features;
    int cpuid_7_0_ebx_features;
    int cpuid_7_0_ecx_features;
    int cpuid_7_1_eax_features;
    int cpuid_xsave_features;

    /* TCG local temps */
    TCGv cc_srcT;
    TCGv A0;
    TCGv T0;
    TCGv T1;

    /* TCG local register indexes (only used inside old micro ops) */
    TCGv tmp0;
    TCGv tmp4;
    TCGv_i32 tmp2_i32;
    TCGv_i32 tmp3_i32;
    TCGv_i64 tmp1_i64;

    sigjmp_buf jmpbuf;
    TCGOp *prev_insn_start;
    TCGOp *prev_insn_end;
} DisasContext;

/*
 * Point EIP to next instruction before ending translation.
 * For instructions that can change hflags.
 */
#define DISAS_EOB_NEXT         DISAS_TARGET_0

/*
 * Point EIP to next instruction and set HF_INHIBIT_IRQ if not
 * already set.  For instructions that activate interrupt shadow.
 */
#define DISAS_EOB_INHIBIT_IRQ  DISAS_TARGET_1

/*
 * Return to the main loop; EIP might have already been updated
 * but even in that case do not use lookup_and_goto_ptr().
 */
#define DISAS_EOB_ONLY         DISAS_TARGET_2

/*
 * EIP has already been updated.  For jumps that wish to use
 * lookup_and_goto_ptr()
 */
#define DISAS_JUMP             DISAS_TARGET_3

/*
 * EIP has already been updated.  Use updated value of
 * EFLAGS.TF to determine singlestep trap (SYSCALL/SYSRET).
 */
#define DISAS_EOB_RECHECK_TF   DISAS_TARGET_4

/* The environment in which user-only runs is constrained. */
#ifdef CONFIG_USER_ONLY
#define PE(S)     true
#define CPL(S)    3
#define IOPL(S)   0
#define SVME(S)   false
#define GUEST(S)  false
#else
#define PE(S)     (((S)->flags & HF_PE_MASK) != 0)
#define CPL(S)    ((S)->cpl)
#define IOPL(S)   ((S)->iopl)
#define SVME(S)   (((S)->flags & HF_SVME_MASK) != 0)
#define GUEST(S)  (((S)->flags & HF_GUEST_MASK) != 0)
#endif
#if defined(CONFIG_USER_ONLY) && defined(TARGET_X86_64)
#define VM86(S)   false
#define CODE32(S) true
#define SS32(S)   true
#define ADDSEG(S) false
#else
#define VM86(S)   (((S)->flags & HF_VM_MASK) != 0)
#define CODE32(S) (((S)->flags & HF_CS32_MASK) != 0)
#define SS32(S)   (((S)->flags & HF_SS32_MASK) != 0)
#define ADDSEG(S) (((S)->flags & HF_ADDSEG_MASK) != 0)
#endif
#if !defined(TARGET_X86_64)
#define CODE64(S) false
#elif defined(CONFIG_USER_ONLY)
#define CODE64(S) true
#else
#define CODE64(S) (((S)->flags & HF_CS64_MASK) != 0)
#endif
#if defined(CONFIG_USER_ONLY) || defined(TARGET_X86_64)
#define LMA(S)    (((S)->flags & HF_LMA_MASK) != 0)
#else
#define LMA(S)    false
#endif

#ifdef TARGET_X86_64
#define REX_PREFIX(S)  (((S)->prefix & PREFIX_REX) != 0)
#define REX_W(S)       ((S)->vex_w)
#define REX_R(S)       ((S)->rex_r + 0)
#define REX_X(S)       ((S)->rex_x + 0)
#define REX_B(S)       ((S)->rex_b + 0)
#else
#define REX_PREFIX(S)  false
#define REX_W(S)       false
#define REX_R(S)       0
#define REX_X(S)       0
#define REX_B(S)       0
#endif

/*
 * Many system-only helpers are not reachable for user-only.
 * Define stub generators here, so that we need not either sprinkle
 * ifdefs through the translator, nor provide the helper function.
 */
#define STUB_HELPER(NAME, ...) \
    static inline void gen_helper_##NAME(__VA_ARGS__) \
    { qemu_build_not_reached(); }

#ifdef CONFIG_USER_ONLY
STUB_HELPER(clgi, TCGv_env env)
STUB_HELPER(flush_page, TCGv_env env, TCGv addr)
STUB_HELPER(inb, TCGv ret, TCGv_env env, TCGv_i32 port)
STUB_HELPER(inw, TCGv ret, TCGv_env env, TCGv_i32 port)
STUB_HELPER(inl, TCGv ret, TCGv_env env, TCGv_i32 port)
STUB_HELPER(monitor, TCGv_env env, TCGv addr)
STUB_HELPER(mwait, TCGv_env env, TCGv_i32 pc_ofs)
STUB_HELPER(outb, TCGv_env env, TCGv_i32 port, TCGv_i32 val)
STUB_HELPER(outw, TCGv_env env, TCGv_i32 port, TCGv_i32 val)
STUB_HELPER(outl, TCGv_env env, TCGv_i32 port, TCGv_i32 val)
STUB_HELPER(stgi, TCGv_env env)
STUB_HELPER(svm_check_intercept, TCGv_env env, TCGv_i32 type)
STUB_HELPER(vmload, TCGv_env env, TCGv_i32 aflag)
STUB_HELPER(vmmcall, TCGv_env env)
STUB_HELPER(vmrun, TCGv_env env, TCGv_i32 aflag, TCGv_i32 pc_ofs)
STUB_HELPER(vmsave, TCGv_env env, TCGv_i32 aflag)
STUB_HELPER(write_crN, TCGv_env env, TCGv_i32 reg, TCGv val)
#endif

static void gen_jmp_rel(DisasContext *s, MemOp ot, int diff, int tb_num);
static void gen_jmp_rel_csize(DisasContext *s, int diff, int tb_num);
static void gen_exception_gpf(DisasContext *s);

/* i386 shift ops */
enum {
    OP_ROL,
    OP_ROR,
    OP_RCL,
    OP_RCR,
    OP_SHL,
    OP_SHR,
    OP_SHL1, /* undocumented */
    OP_SAR = 7,
};

enum {
    JCC_O,
    JCC_B,
    JCC_Z,
    JCC_BE,
    JCC_S,
    JCC_P,
    JCC_L,
    JCC_LE,
};

enum {
    USES_CC_DST  = 1,
    USES_CC_SRC  = 2,
    USES_CC_SRC2 = 4,
    USES_CC_SRCT = 8,
};

/* Bit set if the global variable is live after setting CC_OP to X.  */
static const uint8_t cc_op_live_[] = {
    [CC_OP_DYNAMIC] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_EFLAGS] = USES_CC_SRC,
    [CC_OP_MULB ... CC_OP_MULQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADDB ... CC_OP_ADDQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADCB ... CC_OP_ADCQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_SUBB ... CC_OP_SUBQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRCT,
    [CC_OP_SBBB ... CC_OP_SBBQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_LOGICB ... CC_OP_LOGICQ] = USES_CC_DST,
    [CC_OP_INCB ... CC_OP_INCQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_DECB ... CC_OP_DECQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SHLB ... CC_OP_SHLQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_SARB ... CC_OP_SARQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_BMILGB ... CC_OP_BMILGQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_BLSIB ... CC_OP_BLSIQ] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADCX] = USES_CC_DST | USES_CC_SRC,
    [CC_OP_ADOX] = USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_ADCOX] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
    [CC_OP_POPCNT] = USES_CC_DST,
};

static uint8_t cc_op_live(CCOp op)
{
    uint8_t result;
    assert(op >= 0 && op < ARRAY_SIZE(cc_op_live_));

    /*
     * Check that the array is fully populated.  A zero entry would correspond
     * to a fixed value of EFLAGS, which can be obtained with CC_OP_EFLAGS
     * as well.
     */
    result = cc_op_live_[op];
    assert(result);
    return result;
}

static void set_cc_op_1(DisasContext *s, CCOp op, bool dirty)
{
    int dead;

    if (s->cc_op == op) {
        return;
    }

    /* Discard CC computation that will no longer be used.  */
    dead = cc_op_live(s->cc_op) & ~cc_op_live(op);
    if (dead & USES_CC_DST) {
        tcg_gen_discard_tl(cpu_cc_dst);
    }
    if (dead & USES_CC_SRC) {
        tcg_gen_discard_tl(cpu_cc_src);
    }
    if (dead & USES_CC_SRC2) {
        tcg_gen_discard_tl(cpu_cc_src2);
    }
    if (dead & USES_CC_SRCT) {
        tcg_gen_discard_tl(s->cc_srcT);
    }

    if (dirty && s->cc_op == CC_OP_DYNAMIC) {
        tcg_gen_discard_i32(cpu_cc_op);
    }
    s->cc_op_dirty = dirty;
    s->cc_op = op;
}

static void set_cc_op(DisasContext *s, CCOp op)
{
    /*
     * The DYNAMIC setting is translator only, everything else
     * will be spilled later.
     */
    set_cc_op_1(s, op, op != CC_OP_DYNAMIC);
}

static void assume_cc_op(DisasContext *s, CCOp op)
{
    set_cc_op_1(s, op, false);
}

static void gen_update_cc_op(DisasContext *s)
{
    if (s->cc_op_dirty) {
        tcg_gen_movi_i32(cpu_cc_op, s->cc_op);
        s->cc_op_dirty = false;
    }
}

#ifdef TARGET_X86_64

#define NB_OP_SIZES 4

#else /* !TARGET_X86_64 */

#define NB_OP_SIZES 3

#endif /* !TARGET_X86_64 */

#if HOST_BIG_ENDIAN
#define REG_B_OFFSET (sizeof(target_ulong) - 1)
#define REG_H_OFFSET (sizeof(target_ulong) - 2)
#define REG_W_OFFSET (sizeof(target_ulong) - 2)
#define REG_L_OFFSET (sizeof(target_ulong) - 4)
#define REG_LH_OFFSET (sizeof(target_ulong) - 8)
#else
#define REG_B_OFFSET 0
#define REG_H_OFFSET 1
#define REG_W_OFFSET 0
#define REG_L_OFFSET 0
#define REG_LH_OFFSET 4
#endif

/* In instruction encodings for byte register accesses the
 * register number usually indicates "low 8 bits of register N";
 * however there are some special cases where N 4..7 indicates
 * [AH, CH, DH, BH], ie "bits 15..8 of register N-4". Return
 * true for this special case, false otherwise.
 */
static inline bool byte_reg_is_xH(DisasContext *s, int reg)
{
    /* Any time the REX prefix is present, byte registers are uniform */
    if (reg < 4 || REX_PREFIX(s)) {
        return false;
    }
    return true;
}

/* Select the size of a push/pop operation.  */
static inline MemOp mo_pushpop(DisasContext *s, MemOp ot)
{
    if (CODE64(s)) {
        return ot == MO_16 ? MO_16 : MO_64;
    } else {
        return ot;
    }
}

/* Select the size of the stack pointer.  */
static inline MemOp mo_stacksize(DisasContext *s)
{
    return CODE64(s) ? MO_64 : SS32(s) ? MO_32 : MO_16;
}

/* Compute the result of writing t0 to the OT-sized register REG.
 *
 * If DEST is NULL, store the result into the register and return the
 * register's TCGv.
 *
 * If DEST is not NULL, store the result into DEST and return the
 * register's TCGv.
 */
static TCGv gen_op_deposit_reg_v(DisasContext *s, MemOp ot, int reg, TCGv dest, TCGv t0)
{
    switch(ot) {
    case MO_8:
        if (byte_reg_is_xH(s, reg)) {
            dest = dest ? dest : cpu_regs[reg - 4];
            tcg_gen_deposit_tl(dest, cpu_regs[reg - 4], t0, 8, 8);
            return cpu_regs[reg - 4];
        }
        dest = dest ? dest : cpu_regs[reg];
        tcg_gen_deposit_tl(dest, cpu_regs[reg], t0, 0, 8);
        break;
    case MO_16:
        dest = dest ? dest : cpu_regs[reg];
        tcg_gen_deposit_tl(dest, cpu_regs[reg], t0, 0, 16);
        break;
    case MO_32:
        /* For x86_64, this sets the higher half of register to zero.
           For i386, this is equivalent to a mov. */
        dest = dest ? dest : cpu_regs[reg];
        tcg_gen_ext32u_tl(dest, t0);
        break;
#ifdef TARGET_X86_64
    case MO_64:
        dest = dest ? dest : cpu_regs[reg];
        tcg_gen_mov_tl(dest, t0);
        break;
#endif
    default:
        g_assert_not_reached();
    }
    return cpu_regs[reg];
}

static void gen_op_mov_reg_v(DisasContext *s, MemOp ot, int reg, TCGv t0)
{
    gen_op_deposit_reg_v(s, ot, reg, NULL, t0);
}

static inline
void gen_op_mov_v_reg(DisasContext *s, MemOp ot, TCGv t0, int reg)
{
    if (ot == MO_8 && byte_reg_is_xH(s, reg)) {
        tcg_gen_shri_tl(t0, cpu_regs[reg - 4], 8);
    } else {
        tcg_gen_mov_tl(t0, cpu_regs[reg]);
    }
}

static void gen_add_A0_im(DisasContext *s, int val)
{
    tcg_gen_addi_tl(s->A0, s->A0, val);
    if (!CODE64(s)) {
        tcg_gen_ext32u_tl(s->A0, s->A0);
    }
}

static inline void gen_op_jmp_v(DisasContext *s, TCGv dest)
{
    tcg_gen_mov_tl(cpu_eip, dest);
    s->pc_save = -1;
}

static inline void gen_op_add_reg(DisasContext *s, MemOp size, int reg, TCGv val)
{
    /* Using cpu_regs[reg] does not work for xH registers.  */
    assert(size >= MO_16);
    if (size == MO_16) {
        TCGv temp = tcg_temp_new();
        tcg_gen_add_tl(temp, cpu_regs[reg], val);
        gen_op_mov_reg_v(s, size, reg, temp);
    } else {
        tcg_gen_add_tl(cpu_regs[reg], cpu_regs[reg], val);
        tcg_gen_ext_tl(cpu_regs[reg], cpu_regs[reg], size);
    }
}

static inline
void gen_op_add_reg_im(DisasContext *s, MemOp size, int reg, int32_t val)
{
    gen_op_add_reg(s, size, reg, tcg_constant_tl(val));
}

static inline void gen_op_ld_v(DisasContext *s, int idx, TCGv t0, TCGv a0)
{
    tcg_gen_qemu_ld_tl(t0, a0, s->mem_index, idx | MO_LE);
}

static inline void gen_op_st_v(DisasContext *s, int idx, TCGv t0, TCGv a0)
{
    tcg_gen_qemu_st_tl(t0, a0, s->mem_index, idx | MO_LE);
}

static void gen_update_eip_next(DisasContext *s)
{
    assert(s->pc_save != -1);
    if (tb_cflags(s->base.tb) & CF_PCREL) {
        tcg_gen_addi_tl(cpu_eip, cpu_eip, s->pc - s->pc_save);
    } else if (CODE64(s)) {
        tcg_gen_movi_tl(cpu_eip, s->pc);
    } else {
        tcg_gen_movi_tl(cpu_eip, (uint32_t)(s->pc - s->cs_base));
    }
    s->pc_save = s->pc;
}

static void gen_update_eip_cur(DisasContext *s)
{
    assert(s->pc_save != -1);
    if (tb_cflags(s->base.tb) & CF_PCREL) {
        tcg_gen_addi_tl(cpu_eip, cpu_eip, s->base.pc_next - s->pc_save);
    } else if (CODE64(s)) {
        tcg_gen_movi_tl(cpu_eip, s->base.pc_next);
    } else {
        tcg_gen_movi_tl(cpu_eip, (uint32_t)(s->base.pc_next - s->cs_base));
    }
    s->pc_save = s->base.pc_next;
}

static int cur_insn_len(DisasContext *s)
{
    return s->pc - s->base.pc_next;
}

static TCGv_i32 cur_insn_len_i32(DisasContext *s)
{
    return tcg_constant_i32(cur_insn_len(s));
}

static TCGv_i32 eip_next_i32(DisasContext *s)
{
    assert(s->pc_save != -1);
    /*
     * This function has two users: lcall_real (always 16-bit mode), and
     * iret_protected (16, 32, or 64-bit mode).  IRET only uses the value
     * when EFLAGS.NT is set, which is illegal in 64-bit mode, which is
     * why passing a 32-bit value isn't broken.  To avoid using this where
     * we shouldn't, return -1 in 64-bit mode so that execution goes into
     * the weeds quickly.
     */
    if (CODE64(s)) {
        return tcg_constant_i32(-1);
    }
    if (tb_cflags(s->base.tb) & CF_PCREL) {
        TCGv_i32 ret = tcg_temp_new_i32();
        tcg_gen_trunc_tl_i32(ret, cpu_eip);
        tcg_gen_addi_i32(ret, ret, s->pc - s->pc_save);
        return ret;
    } else {
        return tcg_constant_i32(s->pc - s->cs_base);
    }
}

static TCGv eip_next_tl(DisasContext *s)
{
    TCGv ret;

    assert(s->pc_save != -1);
    if (tb_cflags(s->base.tb) & CF_PCREL) {
        ret = tcg_temp_new();
        tcg_gen_addi_tl(ret, cpu_eip, s->pc - s->pc_save);
    } else if (CODE64(s)) {
        ret = tcg_constant_tl(s->pc);
    } else {
        ret = tcg_constant_tl((uint32_t)(s->pc - s->cs_base));
    }
    /*
     * THE VALUE IS THE INSTRUCTION POINTER PLUS THIS INSTRUCTION'S LENGTH,
     * whichever of the three ways above produced it.
     *
     * gen_CALL and gen_CALL_m push it, so it reaches the wire as a store's
     * data operand -- and without CF_PCREL the two constant arms have folded
     * the whole computation at translation time, leaving a value that came
     * from nothing in the op stream.  A store datum with an empty and
     * complete provenance is what the format spells "the instruction's
     * immediate", so a direct `callq` published the IMMEDIATE bit and every
     * indirect form published the EMPTY mask.  Both say the pushed value came
     * from the encoding.  It did not: the ISA defines it as RIP plus the
     * instruction's length.
     *
     * Stated in the CF_PCREL arm too, where the add above already carries the
     * read.  That costs one deduplicated entry and makes the two translation
     * regimes publish the same set BY CONSTRUCTION rather than by
     * coincidence.
     *
     * BOUND TO THE TEMP, not to the instruction, so that nothing else can
     * inherit it.  Without CF_PCREL the temp is the interned
     * tcg_constant_tl(s->pc), so a second route to the same statement would
     * be a store whose data operand is that same interned constant: x86 has
     * none, because an immediate operand is materialised with
     * tcg_gen_movi_tl() into a temp of its own (emit.c.inc, X86_OP_IMM) and
     * is never handed to a store emitter as a shared constant.
     *
     * Capture only; no op is emitted, altered or suppressed.
     *
     * THE BIND ALONE IS INERT AND THAT IS WHY THE READ IS STATED TOO.  A
     * binding puts the atom in the TEMP's provenance, which is what a store's
     * data-dependency mask is resolved from -- but the mask's bits INDEX the
     * instruction's read list, so a register that is in no read set has no
     * bit to point at and the mask comes out empty anyway.  Measured, not
     * assumed: with only the bind, `call_return_store` still read 4 of 4 with
     * `store_data_dep_mask` 0x0 and `src_regs` [REG_SP].  Both halves, or
     * neither.
     *
     * The read is stated only where the fold consumed it.  Under CF_PCREL the
     * add above genuinely reads cpu_eip and the walk names it, so a statement
     * there would be a duplicate; the bind is taken in that arm regardless so
     * that the two regimes publish the same set by construction.
     */
    insn_dataflow_bind(tcgv_tl_temp(ret), insn_df_reg(X86_DF_PC_NAME));
    if (!(tb_cflags(s->base.tb) & CF_PCREL)) {
        insn_dataflow_state_read(insn_df_reg(X86_DF_PC_NAME));
    }
    return ret;
}

static TCGv eip_cur_tl(DisasContext *s)
{
    assert(s->pc_save != -1);
    if (tb_cflags(s->base.tb) & CF_PCREL) {
        TCGv ret = tcg_temp_new();
        tcg_gen_addi_tl(ret, cpu_eip, s->base.pc_next - s->pc_save);
        return ret;
    } else if (CODE64(s)) {
        return tcg_constant_tl(s->base.pc_next);
    } else {
        return tcg_constant_tl((uint32_t)(s->base.pc_next - s->cs_base));
    }
}

/* Compute SEG:REG into DEST.  SEG is selected from the override segment
   (OVR_SEG) and the default segment (DEF_SEG).  OVR_SEG may be -1 to
   indicate no override.  */
static void gen_lea_v_seg_dest(DisasContext *s, MemOp aflag, TCGv dest, TCGv a0,
                               int def_seg, int ovr_seg)
{
    switch (aflag) {
#ifdef TARGET_X86_64
    case MO_64:
        if (ovr_seg < 0) {
            tcg_gen_mov_tl(dest, a0);
            return;
        }
        break;
#endif
    case MO_32:
        /* 32 bit address */
        if (ovr_seg < 0 && ADDSEG(s)) {
            ovr_seg = def_seg;
        }
        if (ovr_seg < 0) {
            tcg_gen_ext32u_tl(dest, a0);
            return;
        }
        break;
    case MO_16:
        /* 16 bit address */
        tcg_gen_ext16u_tl(dest, a0);
        a0 = dest;
        if (ovr_seg < 0) {
            if (ADDSEG(s)) {
                ovr_seg = def_seg;
            } else {
                return;
            }
        }
        break;
    default:
        g_assert_not_reached();
    }

    if (ovr_seg >= 0) {
        TCGv seg = cpu_seg_base[ovr_seg];

        if (aflag == MO_64) {
            tcg_gen_add_tl(dest, a0, seg);
        } else if (CODE64(s)) {
            tcg_gen_ext32u_tl(dest, a0);
            tcg_gen_add_tl(dest, dest, seg);
        } else {
            tcg_gen_add_tl(dest, a0, seg);
            tcg_gen_ext32u_tl(dest, dest);
        }
    }
}

static void gen_lea_v_seg(DisasContext *s, TCGv a0,
                          int def_seg, int ovr_seg)
{
    gen_lea_v_seg_dest(s, s->aflag, s->A0, a0, def_seg, ovr_seg);
}

static inline void gen_string_movl_A0_ESI(DisasContext *s)
{
    gen_lea_v_seg(s, cpu_regs[R_ESI], R_DS, s->override);
}

static inline void gen_string_movl_A0_EDI(DisasContext *s)
{
    gen_lea_v_seg(s, cpu_regs[R_EDI], R_ES, -1);
}

static TCGv gen_ext_tl(TCGv dst, TCGv src, MemOp size, bool sign)
{
    if (size == MO_TL) {
        return src;
    }
    if (!dst) {
        dst = tcg_temp_new();
    }
    tcg_gen_ext_tl(dst, src, size | (sign ? MO_SIGN : 0));
    return dst;
}

static void gen_op_j_ecx(DisasContext *s, TCGCond cond, TCGLabel *label1)
{
    TCGv tmp = gen_ext_tl(NULL, cpu_regs[R_ECX], s->aflag, false);

    tcg_gen_brcondi_tl(cond, tmp, 0, label1);
}

static inline void gen_op_jz_ecx(DisasContext *s, TCGLabel *label1)
{
    gen_op_j_ecx(s, TCG_COND_EQ, label1);
}

static inline void gen_op_jnz_ecx(DisasContext *s, TCGLabel *label1)
{
    gen_op_j_ecx(s, TCG_COND_NE, label1);
}

static void gen_set_hflag(DisasContext *s, uint32_t mask)
{
    if ((s->flags & mask) == 0) {
        TCGv_i32 t = tcg_temp_new_i32();
        tcg_gen_ld_i32(t, tcg_env, offsetof(CPUX86State, hflags));
        tcg_gen_ori_i32(t, t, mask);
        tcg_gen_st_i32(t, tcg_env, offsetof(CPUX86State, hflags));
        s->flags |= mask;
    }
}

static void gen_reset_hflag(DisasContext *s, uint32_t mask)
{
    if (s->flags & mask) {
        TCGv_i32 t = tcg_temp_new_i32();
        tcg_gen_ld_i32(t, tcg_env, offsetof(CPUX86State, hflags));
        tcg_gen_andi_i32(t, t, ~mask);
        tcg_gen_st_i32(t, tcg_env, offsetof(CPUX86State, hflags));
        s->flags &= ~mask;
    }
}

static void gen_set_eflags(DisasContext *s, target_ulong mask)
{
    TCGv t = tcg_temp_new();

    tcg_gen_ld_tl(t, tcg_env, offsetof(CPUX86State, eflags));
    tcg_gen_ori_tl(t, t, mask);
    tcg_gen_st_tl(t, tcg_env, offsetof(CPUX86State, eflags));
}

static void gen_reset_eflags(DisasContext *s, target_ulong mask)
{
    TCGv t = tcg_temp_new();

    tcg_gen_ld_tl(t, tcg_env, offsetof(CPUX86State, eflags));
    tcg_gen_andi_tl(t, t, ~mask);
    tcg_gen_st_tl(t, tcg_env, offsetof(CPUX86State, eflags));
}

static void gen_helper_in_func(MemOp ot, TCGv v, TCGv_i32 n)
{
    switch (ot) {
    case MO_8:
        gen_helper_inb(v, tcg_env, n);
        break;
    case MO_16:
        gen_helper_inw(v, tcg_env, n);
        break;
    case MO_32:
        gen_helper_inl(v, tcg_env, n);
        break;
    default:
        g_assert_not_reached();
    }
}

static void gen_helper_out_func(MemOp ot, TCGv_i32 v, TCGv_i32 n)
{
    switch (ot) {
    case MO_8:
        gen_helper_outb(tcg_env, v, n);
        break;
    case MO_16:
        gen_helper_outw(tcg_env, v, n);
        break;
    case MO_32:
        gen_helper_outl(tcg_env, v, n);
        break;
    default:
        g_assert_not_reached();
    }
}

/*
 * Validate that access to [port, port + 1<<ot) is allowed.
 * Raise #GP, or VMM exit if not.
 */
static bool gen_check_io(DisasContext *s, MemOp ot, TCGv_i32 port,
                         uint32_t svm_flags)
{
#ifdef CONFIG_USER_ONLY
    /*
     * We do not implement the ioperm(2) syscall, so the TSS check
     * will always fail.
     */
    gen_exception_gpf(s);
    return false;
#else
    if (PE(s) && (CPL(s) > IOPL(s) || VM86(s))) {
        gen_helper_check_io(tcg_env, port, tcg_constant_i32(1 << ot));
    }
    if (GUEST(s)) {
        gen_update_cc_op(s);
        gen_update_eip_cur(s);
        if (s->prefix & (PREFIX_REPZ | PREFIX_REPNZ)) {
            svm_flags |= SVM_IOIO_REP_MASK;
        }
        svm_flags |= 1 << (SVM_IOIO_SIZE_SHIFT + ot);
        gen_helper_svm_check_io(tcg_env, port,
                                tcg_constant_i32(svm_flags),
                                cur_insn_len_i32(s));
    }
    return true;
#endif
}

/*
 * The fan-out unit of a REP-prefixed string operation.
 *
 * Stated inside the emitter rather than at the decode rule so the number sits
 * beside the accesses it counts and cannot drift from them, and only when a
 * REP prefix is present: an unprefixed MOVSB runs once and is not a fan-out
 * instruction at all.  @memops is what THIS emitter performs per iteration,
 * which for INS is not what the architecture performs -- see
 * INSN_DF_SELF_LOOP_MAX.
 */
static void gen_string_self_loop(DisasContext *s, unsigned memops)
{
    if (s->prefix & (PREFIX_REPZ | PREFIX_REPNZ)) {
        insn_dataflow_note_self_loop(memops, true);
    }
}

static void gen_movs(DisasContext *s, MemOp ot, TCGv dshift)
{
    gen_string_self_loop(s, 2);         /* one load, one store */
    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, s->T0, s->A0);
    gen_string_movl_A0_EDI(s);
    gen_op_st_v(s, ot, s->T0, s->A0);

    gen_op_add_reg(s, s->aflag, R_ESI, dshift);
    gen_op_add_reg(s, s->aflag, R_EDI, dshift);
}

/* compute all eflags to reg */
static void gen_mov_eflags(DisasContext *s, TCGv reg)
{
    TCGv dst, src1, src2;
    TCGv_i32 cc_op;
    int live, dead;

    if (s->cc_op == CC_OP_EFLAGS) {
        tcg_gen_mov_tl(reg, cpu_cc_src);
        return;
    }

    dst = cpu_cc_dst;
    src1 = cpu_cc_src;
    src2 = cpu_cc_src2;

    /* Take care to not read values that are not live.  */
    live = cc_op_live(s->cc_op) & ~USES_CC_SRCT;
    dead = live ^ (USES_CC_DST | USES_CC_SRC | USES_CC_SRC2);
    if (dead) {
        TCGv zero = tcg_constant_tl(0);
        if (dead & USES_CC_DST) {
            dst = zero;
        }
        if (dead & USES_CC_SRC) {
            src1 = zero;
        }
        if (dead & USES_CC_SRC2) {
            src2 = zero;
        }
    }

    if (s->cc_op != CC_OP_DYNAMIC) {
        cc_op = tcg_constant_i32(s->cc_op);
    } else {
        cc_op = cpu_cc_op;
    }
    gen_helper_cc_compute_all(reg, dst, src1, src2, cc_op);
}

/* compute all eflags to cc_src */
static void gen_compute_eflags(DisasContext *s)
{
    gen_mov_eflags(s, cpu_cc_src);
    set_cc_op(s, CC_OP_EFLAGS);
}

typedef struct CCPrepare {
    TCGCond cond;
    TCGv reg;
    TCGv reg2;
    target_ulong imm;
    bool use_reg2;
    bool no_setcond;
} CCPrepare;

static CCPrepare gen_prepare_sign_nz(TCGv src, MemOp size)
{
    if (size == MO_TL) {
        return (CCPrepare) { .cond = TCG_COND_LT, .reg = src };
    } else {
        return (CCPrepare) { .cond = TCG_COND_TSTNE, .reg = src,
                             .imm = 1ull << ((8 << size) - 1) };
    }
}

static CCPrepare gen_prepare_val_nz(TCGv src, MemOp size, bool eqz)
{
    if (size == MO_TL) {
        return (CCPrepare) { .cond = eqz ? TCG_COND_EQ : TCG_COND_NE,
                             .reg = src };
    } else {
        return (CCPrepare) { .cond = eqz ? TCG_COND_TSTEQ : TCG_COND_TSTNE,
                             .imm = MAKE_64BIT_MASK(0, 8 << size),
                             .reg = src };
    }
}

/* compute eflags.C, trying to store it in reg if not NULL */
static CCPrepare gen_prepare_eflags_c(DisasContext *s, TCGv reg)
{
    MemOp size;

    switch (s->cc_op) {
    case CC_OP_SUBB ... CC_OP_SUBQ:
        /* (DATA_TYPE)CC_SRCT < (DATA_TYPE)CC_SRC */
        size = s->cc_op - CC_OP_SUBB;
        tcg_gen_ext_tl(s->cc_srcT, s->cc_srcT, size);
        tcg_gen_ext_tl(cpu_cc_src, cpu_cc_src, size);
        return (CCPrepare) { .cond = TCG_COND_LTU, .reg = s->cc_srcT,
                             .reg2 = cpu_cc_src, .use_reg2 = true };

    case CC_OP_ADDB ... CC_OP_ADDQ:
        /* (DATA_TYPE)CC_DST < (DATA_TYPE)CC_SRC */
        size = cc_op_size(s->cc_op);
        tcg_gen_ext_tl(cpu_cc_dst, cpu_cc_dst, size);
        tcg_gen_ext_tl(cpu_cc_src, cpu_cc_src, size);
        return (CCPrepare) { .cond = TCG_COND_LTU, .reg = cpu_cc_dst,
                             .reg2 = cpu_cc_src, .use_reg2 = true };

    case CC_OP_LOGICB ... CC_OP_LOGICQ:
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_NEVER };

    case CC_OP_INCB ... CC_OP_INCQ:
    case CC_OP_DECB ... CC_OP_DECQ:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = cpu_cc_src,
                             .no_setcond = true };

    case CC_OP_SHLB ... CC_OP_SHLQ:
        /* (CC_SRC >> (DATA_BITS - 1)) & 1 */
        size = cc_op_size(s->cc_op);
        return gen_prepare_sign_nz(cpu_cc_src, size);

    case CC_OP_MULB ... CC_OP_MULQ:
        return (CCPrepare) { .cond = TCG_COND_NE,
                             .reg = cpu_cc_src };

    case CC_OP_BMILGB ... CC_OP_BMILGQ:
        size = cc_op_size(s->cc_op);
        return gen_prepare_val_nz(cpu_cc_src, size, true);

    case CC_OP_BLSIB ... CC_OP_BLSIQ:
        size = cc_op_size(s->cc_op);
        return gen_prepare_val_nz(cpu_cc_src, size, false);

    case CC_OP_ADCX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = cpu_cc_dst,
                             .no_setcond = true };

    case CC_OP_EFLAGS:
    case CC_OP_SARB ... CC_OP_SARQ:
        /* CC_SRC & 1 */
        return (CCPrepare) { .cond = TCG_COND_TSTNE,
                             .reg = cpu_cc_src, .imm = CC_C };

    default:
       /* The need to compute only C from CC_OP_DYNAMIC is important
          in efficiently implementing e.g. INC at the start of a TB.  */
       gen_update_cc_op(s);
       if (!reg) {
           reg = tcg_temp_new();
       }
       gen_helper_cc_compute_c(reg, cpu_cc_dst, cpu_cc_src,
                               cpu_cc_src2, cpu_cc_op);
       return (CCPrepare) { .cond = TCG_COND_NE, .reg = reg,
                            .no_setcond = true };
    }
}

/* compute eflags.P, trying to store it in reg if not NULL */
static CCPrepare gen_prepare_eflags_p(DisasContext *s, TCGv reg)
{
    gen_compute_eflags(s);
    return (CCPrepare) { .cond = TCG_COND_TSTNE, .reg = cpu_cc_src,
                         .imm = CC_P };
}

/* compute eflags.S, trying to store it in reg if not NULL */
static CCPrepare gen_prepare_eflags_s(DisasContext *s, TCGv reg)
{
    switch (s->cc_op) {
    case CC_OP_DYNAMIC:
        gen_compute_eflags(s);
        /* FALLTHRU */
    case CC_OP_EFLAGS:
    case CC_OP_ADCX:
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_TSTNE, .reg = cpu_cc_src,
                             .imm = CC_S };
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_NEVER };
    default:
        return gen_prepare_sign_nz(cpu_cc_dst, cc_op_size(s->cc_op));
    }
}

/* compute eflags.O, trying to store it in reg if not NULL */
static CCPrepare gen_prepare_eflags_o(DisasContext *s, TCGv reg)
{
    switch (s->cc_op) {
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = cpu_cc_src2,
                             .no_setcond = true };
    case CC_OP_LOGICB ... CC_OP_LOGICQ:
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_NEVER };
    case CC_OP_MULB ... CC_OP_MULQ:
        return (CCPrepare) { .cond = TCG_COND_NE, .reg = cpu_cc_src };
    default:
        gen_compute_eflags(s);
        return (CCPrepare) { .cond = TCG_COND_TSTNE, .reg = cpu_cc_src,
                             .imm = CC_O };
    }
}

/* compute eflags.Z, trying to store it in reg if not NULL */
static CCPrepare gen_prepare_eflags_z(DisasContext *s, TCGv reg)
{
    switch (s->cc_op) {
    case CC_OP_EFLAGS:
    case CC_OP_ADCX:
    case CC_OP_ADOX:
    case CC_OP_ADCOX:
        return (CCPrepare) { .cond = TCG_COND_TSTNE, .reg = cpu_cc_src,
                             .imm = CC_Z };
    case CC_OP_DYNAMIC:
        gen_update_cc_op(s);
        if (!reg) {
            reg = tcg_temp_new();
        }
        gen_helper_cc_compute_nz(reg, cpu_cc_dst, cpu_cc_src, cpu_cc_op);
        return (CCPrepare) { .cond = TCG_COND_EQ, .reg = reg, .imm = 0 };
    case CC_OP_POPCNT:
        return (CCPrepare) { .cond = TCG_COND_EQ, .reg = cpu_cc_dst };
    default:
        {
            MemOp size = cc_op_size(s->cc_op);
            return gen_prepare_val_nz(cpu_cc_dst, size, true);
        }
    }
}

/* return how to compute jump opcode 'b'.  'reg' can be clobbered
 * if needed; it may be used for CCPrepare.reg if that will
 * provide more freedom in the translation of a subsequent setcond. */
static CCPrepare gen_prepare_cc(DisasContext *s, int b, TCGv reg)
{
    int inv, jcc_op, cond;
    MemOp size;
    CCPrepare cc;

    inv = b & 1;
    jcc_op = (b >> 1) & 7;

    switch (s->cc_op) {
    case CC_OP_SUBB ... CC_OP_SUBQ:
        /* We optimize relational operators for the cmp/jcc case.  */
        size = cc_op_size(s->cc_op);
        switch (jcc_op) {
        case JCC_BE:
            tcg_gen_ext_tl(s->cc_srcT, s->cc_srcT, size);
            tcg_gen_ext_tl(cpu_cc_src, cpu_cc_src, size);
            cc = (CCPrepare) { .cond = TCG_COND_LEU, .reg = s->cc_srcT,
                               .reg2 = cpu_cc_src, .use_reg2 = true };
            break;
        case JCC_L:
            cond = TCG_COND_LT;
            goto fast_jcc_l;
        case JCC_LE:
            cond = TCG_COND_LE;
        fast_jcc_l:
            tcg_gen_ext_tl(s->cc_srcT, s->cc_srcT, size | MO_SIGN);
            tcg_gen_ext_tl(cpu_cc_src, cpu_cc_src, size | MO_SIGN);
            cc = (CCPrepare) { .cond = cond, .reg = s->cc_srcT,
                               .reg2 = cpu_cc_src, .use_reg2 = true };
            break;

        default:
            goto slow_jcc;
        }
        break;

    case CC_OP_LOGICB ... CC_OP_LOGICQ:
        /* Mostly used for test+jump */
        size = s->cc_op - CC_OP_LOGICB;
        switch (jcc_op) {
        case JCC_BE:
            /* CF = 0, becomes jz/je */
            jcc_op = JCC_Z;
            goto slow_jcc;
        case JCC_L:
            /* OF = 0, becomes js/jns */
            jcc_op = JCC_S;
            goto slow_jcc;
        case JCC_LE:
            /* SF or ZF, becomes signed <= 0 */
            tcg_gen_ext_tl(cpu_cc_dst, cpu_cc_dst, size | MO_SIGN);
            cc = (CCPrepare) { .cond = TCG_COND_LE, .reg = cpu_cc_dst };
            break;
        default:
            goto slow_jcc;
        }
        break;

    default:
    slow_jcc:
        /* This actually generates good code for JC, JZ and JS.  */
        switch (jcc_op) {
        case JCC_O:
            cc = gen_prepare_eflags_o(s, reg);
            break;
        case JCC_B:
            cc = gen_prepare_eflags_c(s, reg);
            break;
        case JCC_Z:
            cc = gen_prepare_eflags_z(s, reg);
            break;
        case JCC_BE:
            gen_compute_eflags(s);
            cc = (CCPrepare) { .cond = TCG_COND_TSTNE, .reg = cpu_cc_src,
                               .imm = CC_Z | CC_C };
            break;
        case JCC_S:
            cc = gen_prepare_eflags_s(s, reg);
            break;
        case JCC_P:
            cc = gen_prepare_eflags_p(s, reg);
            break;
        case JCC_L:
            gen_compute_eflags(s);
            if (!reg || reg == cpu_cc_src) {
                reg = tcg_temp_new();
            }
            tcg_gen_addi_tl(reg, cpu_cc_src, CC_O - CC_S);
            cc = (CCPrepare) { .cond = TCG_COND_TSTNE, .reg = reg,
                               .imm = CC_O };
            break;
        default:
        case JCC_LE:
            gen_compute_eflags(s);
            if (!reg || reg == cpu_cc_src) {
                reg = tcg_temp_new();
            }
            tcg_gen_addi_tl(reg, cpu_cc_src, CC_O - CC_S);
            cc = (CCPrepare) { .cond = TCG_COND_TSTNE, .reg = reg,
                               .imm = CC_O | CC_Z };
            break;
        }
        break;
    }

    if (inv) {
        cc.cond = tcg_invert_cond(cc.cond);
    }
    return cc;
}

static void gen_setcc(DisasContext *s, int b, TCGv reg)
{
    CCPrepare cc = gen_prepare_cc(s, b, reg);

    if (cc.no_setcond) {
        if (cc.cond == TCG_COND_EQ) {
            tcg_gen_xori_tl(reg, cc.reg, 1);
        } else {
            tcg_gen_mov_tl(reg, cc.reg);
        }
        return;
    }

    if (cc.use_reg2) {
        tcg_gen_setcond_tl(cc.cond, reg, cc.reg, cc.reg2);
    } else {
        tcg_gen_setcondi_tl(cc.cond, reg, cc.reg, cc.imm);
    }
}

static inline void gen_compute_eflags_c(DisasContext *s, TCGv reg)
{
    gen_setcc(s, JCC_B << 1, reg);
}

/* generate a conditional jump to label 'l1' according to jump opcode
   value 'b'. In the fast case, T0 is guaranteed not to be used. */
static inline void gen_jcc_noeob(DisasContext *s, int b, TCGLabel *l1)
{
    CCPrepare cc = gen_prepare_cc(s, b, NULL);

    if (cc.use_reg2) {
        tcg_gen_brcond_tl(cc.cond, cc.reg, cc.reg2, l1);
    } else {
        tcg_gen_brcondi_tl(cc.cond, cc.reg, cc.imm, l1);
    }
}

/* Generate a conditional jump to label 'l1' according to jump opcode
   value 'b'. In the fast case, T0 is guaranteed not to be used.
   One or both of the branches will call gen_jmp_rel, so ensure
   cc_op is clean.  */
static inline void gen_jcc(DisasContext *s, int b, TCGLabel *l1)
{
    CCPrepare cc = gen_prepare_cc(s, b, NULL);

    /*
     * Note that this must be _after_ gen_prepare_cc, because it can change
     * the cc_op to CC_OP_EFLAGS (because it's CC_OP_DYNAMIC or because
     * it's cheaper to just compute the flags)!
     */
    gen_update_cc_op(s);
    if (cc.use_reg2) {
        tcg_gen_brcond_tl(cc.cond, cc.reg, cc.reg2, l1);
    } else {
        tcg_gen_brcondi_tl(cc.cond, cc.reg, cc.imm, l1);
    }
}

static void gen_stos(DisasContext *s, MemOp ot, TCGv dshift)
{
    gen_string_self_loop(s, 1);         /* one store */
    gen_string_movl_A0_EDI(s);
    gen_op_st_v(s, ot, s->T0, s->A0);
    gen_op_add_reg(s, s->aflag, R_EDI, dshift);
}

static void gen_lods(DisasContext *s, MemOp ot, TCGv dshift)
{
    gen_string_self_loop(s, 1);         /* one load */
    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, s->T0, s->A0);
    gen_op_mov_reg_v(s, ot, R_EAX, s->T0);
    gen_op_add_reg(s, s->aflag, R_ESI, dshift);
}

static void gen_scas(DisasContext *s, MemOp ot, TCGv dshift)
{
    gen_string_self_loop(s, 1);         /* one load */
    gen_string_movl_A0_EDI(s);
    gen_op_ld_v(s, ot, s->T1, s->A0);
    tcg_gen_mov_tl(cpu_cc_src, s->T1);
    tcg_gen_mov_tl(s->cc_srcT, s->T0);
    tcg_gen_sub_tl(cpu_cc_dst, s->T0, s->T1);
    set_cc_op(s, CC_OP_SUBB + ot);

    gen_op_add_reg(s, s->aflag, R_EDI, dshift);
}

static void gen_cmps(DisasContext *s, MemOp ot, TCGv dshift)
{
    gen_string_self_loop(s, 2);         /* two loads */
    gen_string_movl_A0_EDI(s);
    gen_op_ld_v(s, ot, s->T1, s->A0);
    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, s->T0, s->A0);
    tcg_gen_mov_tl(cpu_cc_src, s->T1);
    tcg_gen_mov_tl(s->cc_srcT, s->T0);
    tcg_gen_sub_tl(cpu_cc_dst, s->T0, s->T1);
    set_cc_op(s, CC_OP_SUBB + ot);

    gen_op_add_reg(s, s->aflag, R_ESI, dshift);
    gen_op_add_reg(s, s->aflag, R_EDI, dshift);
}

static void gen_bpt_io(DisasContext *s, TCGv_i32 t_port, int ot)
{
    if (s->flags & HF_IOBPT_MASK) {
#ifdef CONFIG_USER_ONLY
        /* user-mode cpu should not be in IOBPT mode */
        g_assert_not_reached();
#else
        TCGv_i32 t_size = tcg_constant_i32(1 << ot);
        TCGv t_next = eip_next_tl(s);
        gen_helper_bpt_io(tcg_env, t_port, t_size, t_next);
#endif /* CONFIG_USER_ONLY */
    }
}

static void gen_ins(DisasContext *s, MemOp ot, TCGv dshift)
{
    /*
     * TWO stores, not one.  The dummy write below is a real guest access that
     * a plugin is told about, and it is what makes the instruction restartable
     * after a page fault; an architectural count of 1 would cut every
     * iteration's access pair in half for anything partitioning the stream.
     */
    gen_string_self_loop(s, 2);
    gen_string_movl_A0_EDI(s);
    /* Note: we must do this dummy write first to be restartable in
       case of page fault. */
    tcg_gen_movi_tl(s->T0, 0);
    gen_op_st_v(s, ot, s->T0, s->A0);
    tcg_gen_trunc_tl_i32(s->tmp2_i32, cpu_regs[R_EDX]);
    tcg_gen_andi_i32(s->tmp2_i32, s->tmp2_i32, 0xffff);
    gen_helper_in_func(ot, s->T0, s->tmp2_i32);
    gen_op_st_v(s, ot, s->T0, s->A0);
    gen_op_add_reg(s, s->aflag, R_EDI, dshift);
    gen_bpt_io(s, s->tmp2_i32, ot);
}

static void gen_outs(DisasContext *s, MemOp ot, TCGv dshift)
{
    gen_string_self_loop(s, 1);         /* one load; the port is not memory */
    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, s->T0, s->A0);

    tcg_gen_trunc_tl_i32(s->tmp2_i32, cpu_regs[R_EDX]);
    tcg_gen_andi_i32(s->tmp2_i32, s->tmp2_i32, 0xffff);
    tcg_gen_trunc_tl_i32(s->tmp3_i32, s->T0);
    gen_helper_out_func(ot, s->tmp2_i32, s->tmp3_i32);
    gen_op_add_reg(s, s->aflag, R_ESI, dshift);
    gen_bpt_io(s, s->tmp2_i32, ot);
}

#define REP_MAX 65535

#ifdef CONFIG_PLUGIN
/*
 * Offsets of the CPUState self-loop accounting fields relative to tcg_env,
 * which points at CPUArchState.  Same relocation the icount and can_do_io
 * accessors in accel/tcg/translator.c use.
 */
#define REP_PLUGIN_OFF(field)                                           \
    (offsetof(ArchCPU, parent_obj.field) - offsetof(ArchCPU, env))

/*
 * Publish the architectural iteration count of the REP instance in flight.
 * Called after each iteration's CX/ECX/RCX writeback, so a fault inside a
 * later iteration leaves the field holding exactly the iterations that
 * retired.  @iters is a TB-scoped temp holding the running count.
 */
static void gen_rep_plugin_count_iter(DisasContext *s, TCGv iters)
{
    if (!s->base.plugin_enabled) {
        return;
    }
    tcg_gen_addi_tl(iters, iters, 1);
    tcg_gen_st_tl(iters, tcg_env, REP_PLUGIN_OFF(plugin_rep_iters));
}

/*
 * Publish whether the REP instance retired in this execution.  Constant
 * @complete forms cover the paths where retirement is known at translation
 * time (instruction entry: not yet; the done label: the counter hit zero or
 * a REPZ/REPNZ condition broke it).
 */
static void gen_rep_plugin_complete(DisasContext *s, bool complete)
{
    if (!s->base.plugin_enabled) {
        return;
    }
    tcg_gen_st8_tl(tcg_constant_tl(complete), tcg_env,
                   REP_PLUGIN_OFF(plugin_rep_complete));
}

/*
 * Publish which exit this execution took: the re-enter-the-same-instruction
 * path, or past the instruction.  Both call sites are unconditional within
 * their path, so the value is a translation-time constant.
 */
static void gen_rep_plugin_reenter(DisasContext *s, bool reenter)
{
    if (!s->base.plugin_enabled) {
        return;
    }
    tcg_gen_st8_tl(tcg_constant_tl(reenter), tcg_env,
                   REP_PLUGIN_OFF(plugin_rep_reenter));
}

/*
 * Publish whether a re-enter exit sits on a canonical chunk boundary — the
 * exit a looping translation itself takes (counter writeback 65536*m + 1,
 * m >= 1; see the REP_MAX loop bound in do_gen_rep).  On the looping
 * translation's re-enter path that is structurally always true.  A
 * single-iteration translation (can_loop == false) re-enters after every
 * iteration, so there the boundary must be computed from the written-back
 * counter @cx_wb: the canonical translation would have left the block here
 * iff (cx_wb - 1) is a non-zero multiple of REP_MAX + 1 under the
 * instruction's address-size mask.
 */
static void gen_rep_plugin_chunk_const(DisasContext *s, bool chunk)
{
    if (!s->base.plugin_enabled) {
        return;
    }
    tcg_gen_st8_tl(tcg_constant_tl(chunk), tcg_env,
                   REP_PLUGIN_OFF(plugin_rep_chunk));
}

static void gen_rep_plugin_chunk_dynamic(DisasContext *s, TCGv cx_wb,
                                         target_ulong cx_mask)
{
    if (!s->base.plugin_enabled) {
        return;
    }
    TCGv t = tcg_temp_new();
    TCGv low = tcg_temp_new();
    TCGv nz = tcg_temp_new();
    tcg_gen_subi_tl(t, cx_wb, 1);
    /* (t & REP_MAX) == 0: t is a multiple of REP_MAX + 1. */
    tcg_gen_andi_tl(low, t, REP_MAX);
    tcg_gen_setcondi_tl(TCG_COND_EQ, low, low, 0);
    /* (t & cx_mask) != 0: a NON-ZERO multiple within the address size. */
    tcg_gen_andi_tl(nz, t, cx_mask);
    tcg_gen_setcondi_tl(TCG_COND_NE, nz, nz, 0);
    tcg_gen_and_tl(low, low, nz);
    tcg_gen_st8_tl(low, tcg_env, REP_PLUGIN_OFF(plugin_rep_chunk));
}

/*
 * Publish retirement on the re-enter-the-same-instruction path, where it is
 * only knowable at run time: a REP translated as a single iteration
 * (can_loop == false) takes this path after its *final* iteration too, and
 * the instruction has retired exactly when the loop counter reached zero.
 * When the REP did loop internally this path is only taken at a REP_MAX
 * chunk boundary, where the counter is provably non-zero, so the test
 * simply always yields false there.
 */
static void gen_rep_plugin_complete_dynamic(DisasContext *s,
                                            target_ulong cx_mask)
{
    if (!s->base.plugin_enabled) {
        return;
    }
    TCGv done_now = tcg_temp_new();
    tcg_gen_andi_tl(done_now, cpu_regs[R_ECX], cx_mask);
    tcg_gen_setcondi_tl(TCG_COND_EQ, done_now, done_now, 0);
    tcg_gen_st8_tl(done_now, tcg_env, REP_PLUGIN_OFF(plugin_rep_complete));
}
#endif /* CONFIG_PLUGIN */

static void do_gen_rep(DisasContext *s, MemOp ot, TCGv dshift,
                       void (*fn)(DisasContext *s, MemOp ot, TCGv dshift),
                       bool is_repz_nz)
{
    TCGLabel *last = gen_new_label();
    TCGLabel *loop = gen_new_label();
    TCGLabel *done = gen_new_label();

    target_ulong cx_mask = MAKE_64BIT_MASK(0, 8 << s->aflag);
    TCGv cx_next = tcg_temp_new();
#ifdef CONFIG_PLUGIN
    /*
     * Running architectural iteration count for this execution of the REP.
     * TB-scoped so it survives the loop back-edge and the branch to @last.
     */
    TCGv rep_iters = tcg_temp_new();
#endif

    /*
     * Check if we must translate a single iteration only.  Normally, HF_RF_MASK
     * would also limit translation blocks to one instruction, so that gen_eob
     * can reset the flag; here however RF is set throughout the repetition, so
     * we can plow through until CX/ECX/RCX is zero.
     */
    bool can_loop =
        (!(tb_cflags(s->base.tb) & (CF_USE_ICOUNT | CF_SINGLE_STEP))
	 && !(s->flags & (HF_TF_MASK | HF_INHIBIT_IRQ_MASK)));
    bool had_rf = s->flags & HF_RF_MASK;

    /*
     * Even if EFLAGS.RF was set on entry (such as if we're on the second or
     * later iteration and an exception or interrupt happened), force gen_eob()
     * not to clear the flag.  We do that ourselves after the last iteration.
     */
    s->flags &= ~HF_RF_MASK;

    /*
     * For CMPS/SCAS, the CC_OP after a memory fault could come from either
     * the previous instruction or the string instruction; but because we
     * arrange to keep CC_OP up to date all the time, just mark the whole
     * insn as CC_OP_DYNAMIC.
     *
     * It's not a problem to do this even for instructions that do not
     * modify the flags, so do it unconditionally.
     */
    gen_update_cc_op(s);
    tcg_set_insn_start_param(s->base.insn_start, 1, CC_OP_DYNAMIC);

#ifdef CONFIG_PLUGIN
    /*
     * Open this execution's self-loop accounting: no iterations retired
     * yet, instruction not retired yet.  Ahead of the zero-count test, so
     * a REP entered with CX/ECX/RCX already zero still publishes a count
     * of 0 rather than leaving the previous REP's value behind.
     */
    if (s->base.plugin_enabled) {
        tcg_gen_movi_tl(rep_iters, 0);
        /*
         * Zero the whole 64-bit counter here (the per-iteration updates below
         * are target_ulong-wide, which would leave a 32-bit target's upper
         * half stale) and name the instruction the accounting describes.
         * s->base.pc_next is the current instruction's start address during
         * translation, the same value plugin_gen_insn_start() publishes as
         * the instruction's vaddr.
         */
        tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                       REP_PLUGIN_OFF(plugin_rep_iters));
        tcg_gen_st_i64(tcg_constant_i64(s->base.pc_next), tcg_env,
                       REP_PLUGIN_OFF(plugin_rep_pc));
    }
    gen_rep_plugin_complete(s, false);
    gen_rep_plugin_reenter(s, false);
    gen_rep_plugin_chunk_const(s, false);
#endif

    /* Any iteration at all?  */
    tcg_gen_brcondi_tl(TCG_COND_TSTEQ, cpu_regs[R_ECX], cx_mask, done);

    /*
     * From now on we operate on the value of CX/ECX/RCX that will be written
     * back, which is stored in cx_next.  There can be no carry, so we can zero
     * extend here if needed and not do any expensive deposit operations later.
     */
    tcg_gen_subi_tl(cx_next, cpu_regs[R_ECX], 1);
#ifdef TARGET_X86_64
    if (s->aflag == MO_32) {
        tcg_gen_ext32u_tl(cx_next, cx_next);
        cx_mask = ~0;
    }
#endif

    /*
     * The last iteration is handled outside the loop, so that cx_next
     * can never underflow.
     */
    if (can_loop) {
        tcg_gen_brcondi_tl(TCG_COND_TSTEQ, cx_next, cx_mask, last);
    }

    gen_set_label(loop);
    fn(s, ot, dshift);
    tcg_gen_mov_tl(cpu_regs[R_ECX], cx_next);
#ifdef CONFIG_PLUGIN
    /* This iteration has retired (its writeback is committed above). */
    gen_rep_plugin_count_iter(s, rep_iters);
#endif
    gen_update_cc_op(s);

    /* Leave if REP condition fails.  */
    if (is_repz_nz) {
        int nz = (s->prefix & PREFIX_REPNZ) ? 1 : 0;
        gen_jcc_noeob(s, (JCC_Z << 1) | (nz ^ 1), done);
        /* gen_prepare_eflags_z never changes cc_op.  */
	assert(!s->cc_op_dirty);
    }

    if (can_loop) {
        tcg_gen_subi_tl(cx_next, cx_next, 1);
        tcg_gen_brcondi_tl(TCG_COND_TSTNE, cx_next, REP_MAX, loop);
        tcg_gen_brcondi_tl(TCG_COND_TSTEQ, cx_next, cx_mask, last);
    }

    /*
     * Traps or interrupts set RF_MASK if they happen after any iteration
     * but the last.  Set it here before giving the main loop a chance to
     * execute.  (For faults, seg_helper.c sets the flag as usual).
     */
    if (!had_rf) {
        gen_set_eflags(s, RF_MASK);
    }

#ifdef CONFIG_PLUGIN
    /*
     * This path re-enters the same instruction, so retirement is decided by
     * the counter rather than by which label we left through.
     *
     * Chunk boundary: a looping translation only reaches this path when the
     * loop bound expired — cx_next (already holding the NEXT iteration's
     * writeback, one below the committed counter) passed both brcond tests
     * above, i.e. it is a non-zero multiple of REP_MAX + 1 — so the flag is
     * constant true.  A single-iteration translation reaches it after every
     * iteration with cx_next still holding the committed writeback, so the
     * boundary is computed from it.
     */
    gen_rep_plugin_complete_dynamic(s, cx_mask);
    gen_rep_plugin_reenter(s, true);
    if (can_loop) {
        gen_rep_plugin_chunk_const(s, true);
    } else {
        gen_rep_plugin_chunk_dynamic(s, cx_next, cx_mask);
    }
#endif

    /* Go to the main loop but reenter the same instruction.  */
    gen_jmp_rel_csize(s, -cur_insn_len(s), 0);

    if (can_loop) {
        /*
         * The last iteration needs no conditional jump, even if is_repz_nz,
         * because the repeats are ending anyway.
         */
        gen_set_label(last);
        set_cc_op(s, CC_OP_DYNAMIC);
        fn(s, ot, dshift);
        tcg_gen_mov_tl(cpu_regs[R_ECX], cx_next);
#ifdef CONFIG_PLUGIN
        gen_rep_plugin_count_iter(s, rep_iters);
#endif
        gen_update_cc_op(s);
    }

    /* CX/ECX/RCX is zero, or REPZ/REPNZ broke the repetition.  */
    gen_set_label(done);
    set_cc_op(s, CC_OP_DYNAMIC);
#ifdef CONFIG_PLUGIN
    /* Every path into @done retires the instruction and advances past it. */
    gen_rep_plugin_complete(s, true);
    gen_rep_plugin_reenter(s, false);
#endif
    if (had_rf) {
        gen_reset_eflags(s, RF_MASK);
    }
    gen_jmp_rel_csize(s, 0, 1);
}

static void do_gen_string(DisasContext *s, MemOp ot,
                          void (*fn)(DisasContext *s, MemOp ot, TCGv dshift),
                          bool is_repz_nz)
{
    TCGv dshift = tcg_temp_new();
    tcg_gen_ld32s_tl(dshift, tcg_env, offsetof(CPUX86State, df));
    tcg_gen_shli_tl(dshift, dshift, ot);

    if (s->prefix & (PREFIX_REPZ | PREFIX_REPNZ)) {
        do_gen_rep(s, ot, dshift, fn, is_repz_nz);
    } else {
        fn(s, ot, dshift);
    }
}

static void gen_repz(DisasContext *s, MemOp ot,
                     void (*fn)(DisasContext *s, MemOp ot, TCGv dshift))
{
    do_gen_string(s, ot, fn, false);
}

static void gen_repz_nz(DisasContext *s, MemOp ot,
                        void (*fn)(DisasContext *s, MemOp ot, TCGv dshift))
{
    do_gen_string(s, ot, fn, true);
}

static void gen_helper_fp_arith_ST0_FT0(int op)
{
    switch (op) {
    case 0:
        gen_helper_fadd_ST0_FT0(tcg_env);
        break;
    case 1:
        gen_helper_fmul_ST0_FT0(tcg_env);
        break;
    case 2:
        gen_helper_fcom_ST0_FT0(tcg_env);
        break;
    case 3:
        gen_helper_fcom_ST0_FT0(tcg_env);
        break;
    case 4:
        gen_helper_fsub_ST0_FT0(tcg_env);
        break;
    case 5:
        gen_helper_fsubr_ST0_FT0(tcg_env);
        break;
    case 6:
        gen_helper_fdiv_ST0_FT0(tcg_env);
        break;
    case 7:
        gen_helper_fdivr_ST0_FT0(tcg_env);
        break;
    }
}

/* NOTE the exception in "r" op ordering */
static void gen_helper_fp_arith_STN_ST0(int op, int opreg)
{
    TCGv_i32 tmp = tcg_constant_i32(opreg);
    switch (op) {
    case 0:
        gen_helper_fadd_STN_ST0(tcg_env, tmp);
        break;
    case 1:
        gen_helper_fmul_STN_ST0(tcg_env, tmp);
        break;
    case 4:
        gen_helper_fsubr_STN_ST0(tcg_env, tmp);
        break;
    case 5:
        gen_helper_fsub_STN_ST0(tcg_env, tmp);
        break;
    case 6:
        gen_helper_fdivr_STN_ST0(tcg_env, tmp);
        break;
    case 7:
        gen_helper_fdiv_STN_ST0(tcg_env, tmp);
        break;
    }
}

static void gen_exception(DisasContext *s, int trapno)
{
    gen_update_cc_op(s);
    gen_update_eip_cur(s);
    gen_helper_raise_exception(tcg_env, tcg_constant_i32(trapno));
    s->base.is_jmp = DISAS_NORETURN;
}

/* Generate #UD for the current instruction.  The assumption here is that
   the instruction is known, but it isn't allowed in the current cpu mode.  */
static void gen_illegal_opcode(DisasContext *s)
{
    gen_exception(s, EXCP06_ILLOP);
}

/* Generate #GP for the current instruction. */
static void gen_exception_gpf(DisasContext *s)
{
    gen_exception(s, EXCP0D_GPF);
}

/* Check for cpl == 0; if not, raise #GP and return false. */
static bool check_cpl0(DisasContext *s)
{
    if (CPL(s) == 0) {
        return true;
    }
    gen_exception_gpf(s);
    return false;
}

/* XXX: add faster immediate case */
static void gen_shiftd_rm_T1(DisasContext *s, MemOp ot,
                             bool is_right, TCGv count)
{
    target_ulong mask = (ot == MO_64 ? 63 : 31);

    switch (ot) {
    case MO_16:
        /* Note: we implement the Intel behaviour for shift count > 16.
           This means "shrdw C, B, A" shifts A:B:A >> C.  Build the B:A
           portion by constructing it as a 32-bit value.  */
        if (is_right) {
            tcg_gen_deposit_tl(s->tmp0, s->T0, s->T1, 16, 16);
            tcg_gen_mov_tl(s->T1, s->T0);
            tcg_gen_mov_tl(s->T0, s->tmp0);
        } else {
            tcg_gen_deposit_tl(s->T1, s->T0, s->T1, 16, 16);
        }
        /*
         * If TARGET_X86_64 defined then fall through into MO_32 case,
         * otherwise fall through default case.
         */
    case MO_32:
#ifdef TARGET_X86_64
        /* Concatenate the two 32-bit values and use a 64-bit shift.  */
        tcg_gen_subi_tl(s->tmp0, count, 1);
        if (is_right) {
            tcg_gen_concat_tl_i64(s->T0, s->T0, s->T1);
            tcg_gen_shr_i64(s->tmp0, s->T0, s->tmp0);
            tcg_gen_shr_i64(s->T0, s->T0, count);
        } else {
            tcg_gen_concat_tl_i64(s->T0, s->T1, s->T0);
            tcg_gen_shl_i64(s->tmp0, s->T0, s->tmp0);
            tcg_gen_shl_i64(s->T0, s->T0, count);
            tcg_gen_shri_i64(s->tmp0, s->tmp0, 32);
            tcg_gen_shri_i64(s->T0, s->T0, 32);
        }
        break;
#endif
    default:
        tcg_gen_subi_tl(s->tmp0, count, 1);
        if (is_right) {
            tcg_gen_shr_tl(s->tmp0, s->T0, s->tmp0);

            tcg_gen_subfi_tl(s->tmp4, mask + 1, count);
            tcg_gen_shr_tl(s->T0, s->T0, count);
            tcg_gen_shl_tl(s->T1, s->T1, s->tmp4);
        } else {
            tcg_gen_shl_tl(s->tmp0, s->T0, s->tmp0);
            if (ot == MO_16) {
                /* Only needed if count > 16, for Intel behaviour.  */
                tcg_gen_subfi_tl(s->tmp4, 33, count);
                tcg_gen_shr_tl(s->tmp4, s->T1, s->tmp4);
                tcg_gen_or_tl(s->tmp0, s->tmp0, s->tmp4);
            }

            tcg_gen_subfi_tl(s->tmp4, mask + 1, count);
            tcg_gen_shl_tl(s->T0, s->T0, count);
            tcg_gen_shr_tl(s->T1, s->T1, s->tmp4);
        }
        tcg_gen_movi_tl(s->tmp4, 0);
        tcg_gen_movcond_tl(TCG_COND_EQ, s->T1, count, s->tmp4,
                           s->tmp4, s->T1);
        tcg_gen_or_tl(s->T0, s->T0, s->T1);
        break;
    }
}

#define X86_MAX_INSN_LENGTH 15

static uint64_t advance_pc(CPUX86State *env, DisasContext *s, int num_bytes)
{
    uint64_t pc = s->pc;

    /* This is a subsequent insn that crosses a page boundary.  */
    if (s->base.num_insns > 1 &&
        !translator_is_same_page(&s->base, s->pc + num_bytes - 1)) {
        /*
         * v4 repair (maintainer-vetoable): while a never-split extension
         * is active, permit instructions whose bytes lie entirely within
         * the TB's TWO-page window — page slot 1 is already claimed by
         * the first crossing fetch, so page-protection tracking is
         * intact by construction.  Never beyond page 2.  The flag is
         * only ever set once a registered sequence's prefix has been
         * matched at a clean stop, so ordinary translation is
         * byte-identical.
         */
        uint64_t last = s->pc + num_bytes - 1;
        if (!s->base.nosplit_extend ||
            (last & TARGET_PAGE_MASK) -
            (s->base.pc_first & TARGET_PAGE_MASK) > TARGET_PAGE_SIZE) {
            siglongjmp(s->jmpbuf, 2);
        }
    }

    s->pc += num_bytes;
    if (unlikely(cur_insn_len(s) > X86_MAX_INSN_LENGTH)) {
        /* If the instruction's 16th byte is on a different page than the 1st, a
         * page fault on the second page wins over the general protection fault
         * caused by the instruction being too long.
         * This can happen even if the operand is only one byte long!
         */
        if (((s->pc - 1) ^ (pc - 1)) & TARGET_PAGE_MASK) {
            (void)translator_ldub(env, &s->base,
                                  (s->pc - 1) & TARGET_PAGE_MASK);
        }
        siglongjmp(s->jmpbuf, 1);
    }

    return pc;
}

static inline uint8_t x86_ldub_code(CPUX86State *env, DisasContext *s)
{
    return translator_ldub(env, &s->base, advance_pc(env, s, 1));
}

static inline uint16_t x86_lduw_code(CPUX86State *env, DisasContext *s)
{
    return translator_lduw(env, &s->base, advance_pc(env, s, 2));
}

static inline uint32_t x86_ldl_code(CPUX86State *env, DisasContext *s)
{
    return translator_ldl(env, &s->base, advance_pc(env, s, 4));
}

#ifdef TARGET_X86_64
static inline uint64_t x86_ldq_code(CPUX86State *env, DisasContext *s)
{
    return translator_ldq(env, &s->base, advance_pc(env, s, 8));
}
#endif

/* Decompose an address.  */

static AddressParts gen_lea_modrm_0(CPUX86State *env, DisasContext *s,
                                    int modrm, bool is_vsib)
{
    int def_seg, base, index, scale, mod, rm;
    target_long disp;
    bool havesib;

    def_seg = R_DS;
    index = -1;
    scale = 0;
    disp = 0;

    mod = (modrm >> 6) & 3;
    rm = modrm & 7;
    base = rm | REX_B(s);

    if (mod == 3) {
        /* Normally filtered out earlier, but including this path
           simplifies multi-byte nop, as well as bndcl, bndcu, bndcn.  */
        goto done;
    }

    switch (s->aflag) {
    case MO_64:
    case MO_32:
        havesib = 0;
        if (rm == 4) {
            int code = x86_ldub_code(env, s);
            scale = (code >> 6) & 3;
            index = ((code >> 3) & 7) | REX_X(s);
            if (index == 4 && !is_vsib) {
                index = -1;  /* no index */
            }
            base = (code & 7) | REX_B(s);
            havesib = 1;
        }

        switch (mod) {
        case 0:
            if ((base & 7) == 5) {
                base = -1;
                disp = (int32_t)x86_ldl_code(env, s);
                if (CODE64(s) && !havesib) {
                    base = -2;
                    disp += s->pc + s->rip_offset;
                }
            }
            break;
        case 1:
            disp = (int8_t)x86_ldub_code(env, s);
            break;
        default:
        case 2:
            disp = (int32_t)x86_ldl_code(env, s);
            break;
        }

        /* For correct popl handling with esp.  */
        if (base == R_ESP && s->popl_esp_hack) {
            disp += s->popl_esp_hack;
        }
        if (base == R_EBP || base == R_ESP) {
            def_seg = R_SS;
        }
        break;

    case MO_16:
        if (mod == 0) {
            if (rm == 6) {
                base = -1;
                disp = x86_lduw_code(env, s);
                break;
            }
        } else if (mod == 1) {
            disp = (int8_t)x86_ldub_code(env, s);
        } else {
            disp = (int16_t)x86_lduw_code(env, s);
        }

        switch (rm) {
        case 0:
            base = R_EBX;
            index = R_ESI;
            break;
        case 1:
            base = R_EBX;
            index = R_EDI;
            break;
        case 2:
            base = R_EBP;
            index = R_ESI;
            def_seg = R_SS;
            break;
        case 3:
            base = R_EBP;
            index = R_EDI;
            def_seg = R_SS;
            break;
        case 4:
            base = R_ESI;
            break;
        case 5:
            base = R_EDI;
            break;
        case 6:
            base = R_EBP;
            def_seg = R_SS;
            break;
        default:
        case 7:
            base = R_EBX;
            break;
        }
        break;

    default:
        g_assert_not_reached();
    }

 done:
    return (AddressParts){ def_seg, base, index, scale, disp };
}

/* Compute the address, with a minimum number of TCG ops.  */
static TCGv gen_lea_modrm_1(DisasContext *s, AddressParts a, bool is_vsib)
{
    TCGv ea = NULL;

    if (a.index >= 0 && !is_vsib) {
        if (a.scale == 0) {
            ea = cpu_regs[a.index];
        } else {
            tcg_gen_shli_tl(s->A0, cpu_regs[a.index], a.scale);
            ea = s->A0;
        }
        if (a.base >= 0) {
            tcg_gen_add_tl(s->A0, ea, cpu_regs[a.base]);
            ea = s->A0;
        }
    } else if (a.base >= 0) {
        ea = cpu_regs[a.base];
    }
    if (!ea) {
        if (tb_cflags(s->base.tb) & CF_PCREL && a.base == -2) {
            /* With cpu_eip ~= pc_save, the expression is pc-relative. */
            tcg_gen_addi_tl(s->A0, cpu_eip, a.disp - s->pc_save);
        } else {
            tcg_gen_movi_tl(s->A0, a.disp);
            /*
             * The address came from somewhere, and which somewhere depends on
             * a translation-time choice the encoding knows nothing about.
             *
             * a.base == -2 is RIP-relative: the architectural address is the
             * next instruction's address plus the displacement, so the
             * program counter is an input.  Without CF_PCREL the translator
             * knows that address and folds it into a constant here, and the
             * fold consumes the only op that would have named cpu_eip -- an
             * op-stream reader is left with an address that depends on
             * nothing.  The register is still in hand at the fold, so it is
             * stated, and the statement is bound to the TEMP rather than to
             * the instruction so that a later reuse of A0 cannot inherit it.
             *
             * Every other route here is a genuine absolute address, whose one
             * input is the encoding's own displacement field.
             */
            insn_dataflow_bind(tcgv_tl_temp(s->A0),
                               a.base == -2 ? insn_df_reg(X86_DF_PC_NAME)
                                            : insn_df_imm());
            if (a.base == -2) {
                insn_dataflow_state_read(insn_df_reg(X86_DF_PC_NAME));
            }
        }
        ea = s->A0;
    } else if (a.disp != 0) {
        tcg_gen_addi_tl(s->A0, ea, a.disp);
        ea = s->A0;
    }

    return ea;
}

/* Used for BNDCL, BNDCU, BNDCN.  */
static void gen_bndck(DisasContext *s, X86DecodedInsn *decode,
                      TCGCond cond, TCGv_i64 bndv)
{
    TCGv ea = gen_lea_modrm_1(s, decode->mem, false);

    tcg_gen_extu_tl_i64(s->tmp1_i64, ea);
    if (!CODE64(s)) {
        tcg_gen_ext32u_i64(s->tmp1_i64, s->tmp1_i64);
    }
    tcg_gen_setcond_i64(cond, s->tmp1_i64, s->tmp1_i64, bndv);
    tcg_gen_extrl_i64_i32(s->tmp2_i32, s->tmp1_i64);
    gen_helper_bndck(tcg_env, s->tmp2_i32);
}

/* generate modrm load of memory or register. */
static void gen_ld_modrm(DisasContext *s, X86DecodedInsn *decode, MemOp ot)
{
    int modrm = s->modrm;
    int mod, rm;

    mod = (modrm >> 6) & 3;
    rm = (modrm & 7) | REX_B(s);
    if (mod == 3) {
        gen_op_mov_v_reg(s, ot, s->T0, rm);
    } else {
        gen_lea_modrm(s, decode);
        gen_op_ld_v(s, ot, s->T0, s->A0);
    }
}

/* generate modrm store of memory or register. */
static void gen_st_modrm(DisasContext *s, X86DecodedInsn *decode, MemOp ot)
{
    int modrm = s->modrm;
    int mod, rm;

    mod = (modrm >> 6) & 3;
    rm = (modrm & 7) | REX_B(s);
    if (mod == 3) {
        gen_op_mov_reg_v(s, ot, rm, s->T0);
    } else {
        gen_lea_modrm(s, decode);
        gen_op_st_v(s, ot, s->T0, s->A0);
    }
}

static target_ulong insn_get_addr(CPUX86State *env, DisasContext *s, MemOp ot)
{
    target_ulong ret;

    switch (ot) {
    case MO_8:
        ret = x86_ldub_code(env, s);
        break;
    case MO_16:
        ret = x86_lduw_code(env, s);
        break;
    case MO_32:
        ret = x86_ldl_code(env, s);
        break;
#ifdef TARGET_X86_64
    case MO_64:
        ret = x86_ldq_code(env, s);
        break;
#endif
    default:
        g_assert_not_reached();
    }
    return ret;
}

static inline uint32_t insn_get(CPUX86State *env, DisasContext *s, MemOp ot)
{
    uint32_t ret;

    switch (ot) {
    case MO_8:
        ret = x86_ldub_code(env, s);
        break;
    case MO_16:
        ret = x86_lduw_code(env, s);
        break;
    case MO_32:
#ifdef TARGET_X86_64
    case MO_64:
#endif
        ret = x86_ldl_code(env, s);
        break;
    default:
        g_assert_not_reached();
    }
    return ret;
}

static target_long insn_get_signed(CPUX86State *env, DisasContext *s, MemOp ot)
{
    target_long ret;

    switch (ot) {
    case MO_8:
        ret = (int8_t) x86_ldub_code(env, s);
        break;
    case MO_16:
        ret = (int16_t) x86_lduw_code(env, s);
        break;
    case MO_32:
        ret = (int32_t) x86_ldl_code(env, s);
        break;
#ifdef TARGET_X86_64
    case MO_64:
        ret = x86_ldq_code(env, s);
        break;
#endif
    default:
        g_assert_not_reached();
    }
    return ret;
}

static void gen_conditional_jump_labels(DisasContext *s, target_long diff,
                                        TCGLabel *not_taken, TCGLabel *taken)
{
    /*
     * Static taken-edge target for direct conditional jumps (Jcc /
     * JCXZ / LOOPcc).  Surfaced to plugins for wrong-path tracing —
     * see plugin_gen_record_branch_target() docs.  Indirect branches
     * (JMP_m / CALL_m) take a different path and never reach here.
     */
/*
 * THE PROGRAM COUNTER, READ BY A PC-RELATIVE TRANSFER.
 *
 * A direct branch's target is this instruction's own address plus the
 * displacement its encoding carries.  The translator knows the address, so it
 * computes the target at translation time and the op stream carries a
 * constant; nothing in the ops says the program counter was read, and without
 * a statement the wire publishes a transfer whose only input is the condition.
 *
 * It IS an input.  The reference simulators say so -- PIN reports rip among a
 * relative branch's sources on every one of them -- and so do two of this
 * tree's own four targets: mipsel states it for every branch (note_folded_pc),
 * and riscv64 states it wherever gen_pc_plus_diff materialises a value that is
 * not cpu_pc itself.  Leaving x86_64 and aarch64 silent made one architectural
 * fact publish three different ways across four machines.
 *
 * The objection this replaces was that naming the read ties a direct branch to
 * whatever last wrote the program counter, which is every preceding transfer.
 * That is true and it is the machine: the next pc is computed from this pc,
 * which the last transfer produced.  R10 already settled what a consumer does
 * with it -- "consumers understand pc writes as control flow and drop pc as a
 * destination register when consuming" -- and a consumer that drops the write
 * has nothing left to chain the read to.  Nor does the read carry the
 * direct/indirect distinction it was said to: branch_type carries that, and
 * carried it before this statement existed.
 *
 * Stated at the branch decode sites and not inside the transfer helper,
 * because that helper also ends a block that merely ran out of room, and a
 * read stated there would land on whichever instruction happened to sit last.
 */
    insn_dataflow_state_read(insn_df_reg(X86_DF_PC_NAME));

    plugin_gen_record_branch_target((uint64_t)(s->pc + diff));
    if (not_taken) {
        gen_set_label(not_taken);
    }
    gen_jmp_rel_csize(s, 0, 1);

    gen_set_label(taken);
    gen_jmp_rel(s, s->dflag, diff, 0);
}

static void gen_cmovcc(DisasContext *s, int b, TCGv dest, TCGv src)
{
    CCPrepare cc = gen_prepare_cc(s, b, NULL);

    if (!cc.use_reg2) {
        cc.reg2 = tcg_constant_tl(cc.imm);
    }

    tcg_gen_movcond_tl(cc.cond, dest, cc.reg, cc.reg2, src, dest);
}

static void gen_op_movl_seg_real(DisasContext *s, X86Seg seg_reg, TCGv seg)
{
    TCGv selector = tcg_temp_new();
    tcg_gen_ext16u_tl(selector, seg);
    tcg_gen_st32_tl(selector, tcg_env,
                    offsetof(CPUX86State,segs[seg_reg].selector));
    tcg_gen_shli_tl(cpu_seg_base[seg_reg], selector, 4);
}

/* move SRC to seg_reg and compute if the CPU state may change. Never
   call this function with seg_reg == R_CS */
static void gen_movl_seg(DisasContext *s, X86Seg seg_reg, TCGv src, bool inhibit_irq)
{
    /*
     * THE SEGMENT REGISTER IS A DESTINATION, AND ON THE PROTECTED-MODE PATH
     * NO OP SAYS SO.
     *
     * helper_load_seg() reads the descriptor and installs the base, limit and
     * flags inside CPUArchState, so the call is the whole of the write and
     * tcg_env is its only pointer argument: the op stream shows a call and
     * names nothing.  Measured on an x86_64 system trace, `8e e0`
     * (mov %eax,%fs) and `8e ef` (mov %edi,%gs) published NO destination
     * register at all -- an instruction that writes FS or GS and names
     * nothing is a write missing from the wire.
     *
     * Stated on both paths.  The real-mode lowering does write the base
     * global with an op, and saying so again is the same fact twice rather
     * than a second one; keeping the statement unconditional is what makes
     * the destination independent of the mode the guest happens to be in.
     */
    insn_dataflow_state_write(insn_df_reg(seg_base_names[seg_reg]));

    if (PE(s) && !VM86(s)) {
        TCGv_i32 sel = tcg_temp_new_i32();

        tcg_gen_trunc_tl_i32(sel, src);
        gen_helper_load_seg(tcg_env, tcg_constant_i32(seg_reg), sel);

        /*
         * For moves to SS, the SS32 flag may change. For CODE32 only, changes
         * to SS, DS and ES may change the ADDSEG flags.
         */
        if (seg_reg == R_SS || (CODE32(s) && seg_reg < R_FS)) {
            s->base.is_jmp = DISAS_EOB_NEXT;
        }
    } else {
        gen_op_movl_seg_real(s, seg_reg, src);
    }

    /*
     * For MOV or POP to SS (but not LSS) translation must always
     * stop as a special handling must be done to disable hardware
     * interrupts for the next instruction.
     *
     * This is the last instruction, so it's okay to overwrite
     * HF_TF_MASK; the next TB will start with the flag set.
     *
     * DISAS_EOB_INHIBIT_IRQ is a superset of DISAS_EOB_NEXT which
     * might have been set above.
     */
    if (inhibit_irq) {
        s->base.is_jmp = DISAS_EOB_INHIBIT_IRQ;
        s->flags &= ~HF_TF_MASK;
    }
}

static void gen_far_call(DisasContext *s)
{
    TCGv_i32 new_cs = tcg_temp_new_i32();
    tcg_gen_trunc_tl_i32(new_cs, s->T1);
    if (PE(s) && !VM86(s)) {
        gen_helper_lcall_protected(tcg_env, new_cs, s->T0,
                                   tcg_constant_i32(s->dflag - 1),
                                   eip_next_tl(s));
    } else {
        TCGv_i32 new_eip = tcg_temp_new_i32();
        tcg_gen_trunc_tl_i32(new_eip, s->T0);
        gen_helper_lcall_real(tcg_env, new_cs, new_eip,
                              tcg_constant_i32(s->dflag - 1),
                              eip_next_i32(s));
    }
    s->base.is_jmp = DISAS_JUMP;
}

static void gen_far_jmp(DisasContext *s)
{
    if (PE(s) && !VM86(s)) {
        TCGv_i32 new_cs = tcg_temp_new_i32();
        tcg_gen_trunc_tl_i32(new_cs, s->T1);
        gen_helper_ljmp_protected(tcg_env, new_cs, s->T0,
                                  eip_next_tl(s));
    } else {
        gen_op_movl_seg_real(s, R_CS, s->T1);
        gen_op_jmp_v(s, s->T0);
    }
    s->base.is_jmp = DISAS_JUMP;
}

static void gen_svm_check_intercept(DisasContext *s, uint32_t type)
{
    /* no SVM activated; fast case */
    if (likely(!GUEST(s))) {
        return;
    }
    gen_helper_svm_check_intercept(tcg_env, tcg_constant_i32(type));
}

static inline void gen_stack_update(DisasContext *s, int addend)
{
    gen_op_add_reg_im(s, mo_stacksize(s), R_ESP, addend);
}

static void gen_lea_ss_ofs(DisasContext *s, TCGv dest, TCGv src, target_ulong offset)
{
    if (offset) {
        tcg_gen_addi_tl(dest, src, offset);
        src = dest;
    }
    gen_lea_v_seg_dest(s, mo_stacksize(s), dest, src, R_SS, -1);
}

/* Generate a push. It depends on ss32, addseg and dflag.  */
static void gen_push_v(DisasContext *s, TCGv val)
{
    MemOp d_ot = mo_pushpop(s, s->dflag);
    MemOp a_ot = mo_stacksize(s);
    int size = 1 << d_ot;
    TCGv new_esp = tcg_temp_new();

    tcg_gen_subi_tl(new_esp, cpu_regs[R_ESP], size);

    /* Now reduce the value to the address size and apply SS base.  */
    gen_lea_ss_ofs(s, s->A0, new_esp, 0);
    gen_op_st_v(s, d_ot, val, s->A0);
    gen_op_mov_reg_v(s, a_ot, R_ESP, new_esp);
}

/* two step pop is necessary for precise exceptions */
static MemOp gen_pop_T0(DisasContext *s)
{
    MemOp d_ot = mo_pushpop(s, s->dflag);

    gen_lea_ss_ofs(s, s->T0, cpu_regs[R_ESP], 0);
    gen_op_ld_v(s, d_ot, s->T0, s->T0);

    return d_ot;
}

static inline void gen_pop_update(DisasContext *s, MemOp ot)
{
    gen_stack_update(s, 1 << ot);
}

static void gen_pusha(DisasContext *s)
{
    MemOp d_ot = s->dflag;
    int size = 1 << d_ot;
    int i;

    for (i = 0; i < 8; i++) {
        gen_lea_ss_ofs(s, s->A0, cpu_regs[R_ESP], (i - 8) * size);
        gen_op_st_v(s, d_ot, cpu_regs[7 - i], s->A0);
    }

    gen_stack_update(s, -8 * size);
}

static void gen_popa(DisasContext *s)
{
    MemOp d_ot = s->dflag;
    int size = 1 << d_ot;
    int i;

    for (i = 0; i < 8; i++) {
        /* ESP is not reloaded */
        if (7 - i == R_ESP) {
            continue;
        }
        gen_lea_ss_ofs(s, s->A0, cpu_regs[R_ESP], i * size);
        gen_op_ld_v(s, d_ot, s->T0, s->A0);
        gen_op_mov_reg_v(s, d_ot, 7 - i, s->T0);
    }

    gen_stack_update(s, 8 * size);
}

static void gen_enter(DisasContext *s, int esp_addend, int level)
{
    MemOp d_ot = mo_pushpop(s, s->dflag);
    MemOp a_ot = mo_stacksize(s);
    int size = 1 << d_ot;

    /* Push BP; compute FrameTemp into T1.  */
    tcg_gen_subi_tl(s->T1, cpu_regs[R_ESP], size);
    gen_lea_ss_ofs(s, s->A0, s->T1, 0);
    gen_op_st_v(s, d_ot, cpu_regs[R_EBP], s->A0);

    level &= 31;
    if (level != 0) {
        int i;

        /* Copy level-1 pointers from the previous frame.  */
        for (i = 1; i < level; ++i) {
            gen_lea_ss_ofs(s, s->A0, cpu_regs[R_EBP], -size * i);
            gen_op_ld_v(s, d_ot, s->tmp0, s->A0);

            gen_lea_ss_ofs(s, s->A0, s->T1, -size * i);
            gen_op_st_v(s, d_ot, s->tmp0, s->A0);
        }

        /* Push the current FrameTemp as the last level.  */
        gen_lea_ss_ofs(s, s->A0, s->T1, -size * level);
        gen_op_st_v(s, d_ot, s->T1, s->A0);
    }

    /* Copy the FrameTemp value to EBP.  */
    gen_op_mov_reg_v(s, d_ot, R_EBP, s->T1);

    /* Compute the final value of ESP.  */
    tcg_gen_subi_tl(s->T1, s->T1, esp_addend + size * level);
    gen_op_mov_reg_v(s, a_ot, R_ESP, s->T1);
}

static void gen_leave(DisasContext *s)
{
    MemOp d_ot = mo_pushpop(s, s->dflag);
    MemOp a_ot = mo_stacksize(s);

    gen_lea_ss_ofs(s, s->A0, cpu_regs[R_EBP], 0);
    gen_op_ld_v(s, d_ot, s->T0, s->A0);

    tcg_gen_addi_tl(s->T1, cpu_regs[R_EBP], 1 << d_ot);

    gen_op_mov_reg_v(s, d_ot, R_EBP, s->T0);
    gen_op_mov_reg_v(s, a_ot, R_ESP, s->T1);
}

/* Similarly, except that the assumption here is that we don't decode
   the instruction at all -- either a missing opcode, an unimplemented
   feature, or just a bogus instruction stream.  */
static void gen_unknown_opcode(CPUX86State *env, DisasContext *s)
{
    gen_illegal_opcode(s);

    if (qemu_loglevel_mask(LOG_UNIMP)) {
        FILE *logfile = qemu_log_trylock();
        if (logfile) {
            target_ulong pc = s->base.pc_next, end = s->pc;

            fprintf(logfile, "ILLOPC: " TARGET_FMT_lx ":", pc);
            for (; pc < end; ++pc) {
                fprintf(logfile, " %02x", translator_ldub(env, &s->base, pc));
            }
            fprintf(logfile, "\n");
            qemu_log_unlock(logfile);
        }
    }
}

/* an interrupt is different from an exception because of the
   privilege checks */
static void gen_interrupt(DisasContext *s, uint8_t intno)
{
    gen_update_cc_op(s);
    gen_update_eip_cur(s);
    gen_helper_raise_interrupt(tcg_env, tcg_constant_i32(intno),
                               cur_insn_len_i32(s));
    s->base.is_jmp = DISAS_NORETURN;
}

/* Clear BND registers during legacy branches.  */
static void gen_bnd_jmp(DisasContext *s)
{
    /* Clear the registers only if BND prefix is missing, MPX is enabled,
       and if the BNDREGs are known to be in use (non-zero) already.
       The helper itself will check BNDPRESERVE at runtime.  */
    if ((s->prefix & PREFIX_REPNZ) == 0
        && (s->flags & HF_MPX_EN_MASK) != 0
        && (s->flags & HF_MPX_IU_MASK) != 0) {
        gen_helper_bnd_jmp(tcg_env);
    }
}

/*
 * Generate an end of block, including common tasks such as generating
 * single step traps, resetting the RF flag, and handling the interrupt
 * shadow.
 */
static void
gen_eob(DisasContext *s, int mode)
{
    bool inhibit_reset;

    gen_update_cc_op(s);

    /* If several instructions disable interrupts, only the first does it.  */
    inhibit_reset = false;
    if (s->flags & HF_INHIBIT_IRQ_MASK) {
        gen_reset_hflag(s, HF_INHIBIT_IRQ_MASK);
        inhibit_reset = true;
    } else if (mode == DISAS_EOB_INHIBIT_IRQ) {
        gen_set_hflag(s, HF_INHIBIT_IRQ_MASK);
    }

    if (s->flags & HF_RF_MASK) {
        gen_reset_eflags(s, RF_MASK);
    }
    if (mode == DISAS_EOB_RECHECK_TF) {
        gen_helper_rechecking_single_step(tcg_env);
        tcg_gen_exit_tb(NULL, 0);
    } else if (s->flags & HF_TF_MASK) {
        gen_helper_single_step(tcg_env);
    } else if (mode == DISAS_JUMP &&
               /* give irqs a chance to happen */
               !inhibit_reset) {
        tcg_gen_lookup_and_goto_ptr();
    } else {
        tcg_gen_exit_tb(NULL, 0);
    }

    s->base.is_jmp = DISAS_NORETURN;
}

/* Jump to eip+diff, truncating the result to OT. */
static void gen_jmp_rel(DisasContext *s, MemOp ot, int diff, int tb_num)
{
    bool use_goto_tb = s->jmp_opt;
    target_ulong mask = -1;
    target_ulong new_pc = s->pc + diff;
    target_ulong new_eip = new_pc - s->cs_base;

    assert(!s->cc_op_dirty);

    /* In 64-bit mode, operand size is fixed at 64 bits. */
    if (!CODE64(s)) {
        if (ot == MO_16) {
            mask = 0xffff;
            if (tb_cflags(s->base.tb) & CF_PCREL && CODE32(s)) {
                use_goto_tb = false;
            }
        } else {
            mask = 0xffffffff;
        }
    }
    new_eip &= mask;

    if (tb_cflags(s->base.tb) & CF_PCREL) {
        tcg_gen_addi_tl(cpu_eip, cpu_eip, new_pc - s->pc_save);
        /*
         * If we can prove the branch does not leave the page and we have
         * no extra masking to apply (data16 branch in code32, see above),
         * then we have also proven that the addition does not wrap.
         */
        if (!use_goto_tb || !translator_is_same_page(&s->base, new_pc)) {
            tcg_gen_andi_tl(cpu_eip, cpu_eip, mask);
            use_goto_tb = false;
        }
    } else if (!CODE64(s)) {
        new_pc = (uint32_t)(new_eip + s->cs_base);
    }

    if (use_goto_tb && translator_use_goto_tb(&s->base, new_pc)) {
        /* jump to same page: we can use a direct jump */
        tcg_gen_goto_tb(tb_num);
        if (!(tb_cflags(s->base.tb) & CF_PCREL)) {
            tcg_gen_movi_tl(cpu_eip, new_eip);
        }
        tcg_gen_exit_tb(s->base.tb, tb_num);
        s->base.is_jmp = DISAS_NORETURN;
    } else {
        if (!(tb_cflags(s->base.tb) & CF_PCREL)) {
            tcg_gen_movi_tl(cpu_eip, new_eip);
        }
        if (s->jmp_opt) {
            gen_eob(s, DISAS_JUMP);   /* jump to another page */
        } else {
            gen_eob(s, DISAS_EOB_ONLY);  /* exit to main loop */
        }
    }
}

/* Jump to eip+diff, truncating to the current code size. */
static void gen_jmp_rel_csize(DisasContext *s, int diff, int tb_num)
{
    /* CODE64 ignores the OT argument, so we need not consider it. */
    gen_jmp_rel(s, CODE32(s) ? MO_32 : MO_16, diff, tb_num);
}

static inline void gen_ldq_env_A0(DisasContext *s, int offset)
{
    tcg_gen_qemu_ld_i64(s->tmp1_i64, s->A0, s->mem_index, MO_LEUQ);
    tcg_gen_st_i64(s->tmp1_i64, tcg_env, offset);
}

static inline void gen_stq_env_A0(DisasContext *s, int offset)
{
    tcg_gen_ld_i64(s->tmp1_i64, tcg_env, offset);
    tcg_gen_qemu_st_i64(s->tmp1_i64, s->A0, s->mem_index, MO_LEUQ);
}

static inline void gen_ldo_env_A0(DisasContext *s, int offset, bool align)
{
    MemOp atom = (s->cpuid_ext_features & CPUID_EXT_AVX
                  ? MO_ATOM_IFALIGN : MO_ATOM_IFALIGN_PAIR);
    MemOp mop = MO_128 | MO_LE | atom | (align ? MO_ALIGN_16 : 0);
    int mem_index = s->mem_index;
    TCGv_i128 t = tcg_temp_new_i128();

    tcg_gen_qemu_ld_i128(t, s->A0, mem_index, mop);
    tcg_gen_st_i128(t, tcg_env, offset);
}

static inline void gen_sto_env_A0(DisasContext *s, int offset, bool align)
{
    MemOp atom = (s->cpuid_ext_features & CPUID_EXT_AVX
                  ? MO_ATOM_IFALIGN : MO_ATOM_IFALIGN_PAIR);
    MemOp mop = MO_128 | MO_LE | atom | (align ? MO_ALIGN_16 : 0);
    int mem_index = s->mem_index;
    TCGv_i128 t = tcg_temp_new_i128();

    tcg_gen_ld_i128(t, tcg_env, offset);
    tcg_gen_qemu_st_i128(t, s->A0, mem_index, mop);
}

static void gen_ldy_env_A0(DisasContext *s, int offset, bool align)
{
    MemOp mop = MO_128 | MO_LE | MO_ATOM_IFALIGN_PAIR;
    int mem_index = s->mem_index;
    TCGv_i128 t0 = tcg_temp_new_i128();
    TCGv_i128 t1 = tcg_temp_new_i128();

    tcg_gen_qemu_ld_i128(t0, s->A0, mem_index, mop | (align ? MO_ALIGN_32 : 0));
    tcg_gen_addi_tl(s->tmp0, s->A0, 16);
    tcg_gen_qemu_ld_i128(t1, s->tmp0, mem_index, mop);

    tcg_gen_st_i128(t0, tcg_env, offset + offsetof(YMMReg, YMM_X(0)));
    tcg_gen_st_i128(t1, tcg_env, offset + offsetof(YMMReg, YMM_X(1)));
}

static void gen_sty_env_A0(DisasContext *s, int offset, bool align)
{
    MemOp mop = MO_128 | MO_LE | MO_ATOM_IFALIGN_PAIR;
    int mem_index = s->mem_index;
    TCGv_i128 t = tcg_temp_new_i128();

    tcg_gen_ld_i128(t, tcg_env, offset + offsetof(YMMReg, YMM_X(0)));
    tcg_gen_qemu_st_i128(t, s->A0, mem_index, mop | (align ? MO_ALIGN_32 : 0));
    tcg_gen_addi_tl(s->tmp0, s->A0, 16);
    tcg_gen_ld_i128(t, tcg_env, offset + offsetof(YMMReg, YMM_X(1)));
    tcg_gen_qemu_st_i128(t, s->tmp0, mem_index, mop);
}

#include "emit.c.inc"

/*
 * The x87 state, named.
 *
 * WHAT ST(i) IS, AND WHY THE NAME IS THE STACK-RELATIVE ONE.  QEMU models the
 * x87 data registers exactly as the hardware does: fpregs[8] is a physical
 * file and fpstt is the top-of-stack pointer, so `ST(n)` is the macro
 * `fpregs[(fpstt + n) & 7]` (fpu_helper.c) -- an element chosen by a register
 * VALUE at execution, not by the encoding.  The encoding carries n.
 *
 * So a decode site has two candidate names and can only supply one of them.
 * The physical slot is the one a consumer would rather join on, and it is not
 * available here: it is a function of fpstt, which no translation knows, and
 * the wire's templates are per-encoding and invariant across executions, so a
 * field that varies per execution cannot live in one.  The stack-relative
 * name IS available, is what the encoding says, is what the SDM's own
 * Operation sections say -- FLD's destination is ST(0) AFTER the push, which
 * is why the FLD arm below names 0 and not the (opreg + 1) QEMU passes the
 * helper -- and is what every reference decoder publishes, so the external
 * comparison is against the same name rather than against a spelling nothing
 * else uses.
 *
 * THE COST IS REAL AND IT IS NOT HIDDEN.  A consumer that joins ST names
 * without tracking the top of stack joins the wrong producer across a push or
 * a pop: two `fld`s both write "st0" and are not a WAW, and a value parked in
 * ST(0) before a push is read as ST(1) after it.  What makes that recoverable
 * rather than lost is that the selector is on the wire too: every arm below
 * that indexes the stack names fpstt as a source, and every arm that moves
 * the top names it as a destination, so the top-of-stack chain a consumer
 * needs in order to resolve the names the way hardware's rename stage does is
 * published beside them.  Naming the whole file instead would be sound and
 * would serialise every x87 instruction against every other one; that is a
 * coarser answer, not a truer one.
 *
 * THE MMX ALIAS IS EXACT, NOT A CONFLATION.  MM(i) is the same storage --
 * emit.c.inc reaches it at offsetof(CPUX86State, fpregs[reg].mmx) -- and MM(i)
 * is the PHYSICAL slot i, which would be a second meaning for the same name
 * if the two could ever disagree.  They cannot: every MMX-unit instruction is
 * preceded by helper_enter_mmx(), which sets fpstt = 0, and at fpstt == 0
 * ST(i) and MM(i) are the same register by construction.
 */
static const char *const x86_x87_st_names[] = {
    "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
};
static const char *const x86_x87_fpstt_names[] = { "fpstt" };
static const char *const x86_x87_fpus_names[]  = { "fpus" };
static const char *const x86_x87_fpuc_names[]  = { "fpuc" };
static const char *const x86_x87_fptag_names[] = { "fptag" };
static const char *const x86_x87_fpip_names[]  = { "fpip" };
static const char *const x86_x87_fpcs_names[]  = { "fpcs" };
static const char *const x86_x87_fpdp_names[]  = { "fpdp" };
static const char *const x86_x87_fpds_names[]  = { "fpds" };

static void x87_rd(const char *name)
{
    insn_dataflow_state_read(insn_df_reg(name));
}

static void x87_wr(const char *name)
{
    insn_dataflow_state_write(insn_df_reg(name));
}

/* ST(i), in the frame the SDM's Operation section for the instruction uses. */
static void x87_rd_st(int i)
{
    x87_rd(x86_x87_st_names[i & 7]);
}

static void x87_wr_st(int i)
{
    x87_wr(x86_x87_st_names[i & 7]);
}

/*
 * The top-of-stack pointer every stack reference is indexed through.
 *
 * Stated as a READ on every arm that names an ST operand, because ST(n) is
 * fpregs[(fpstt + n) & 7] and the instruction genuinely consumes fpstt to
 * reach its operand.  Without it a consumer has the names and no way to
 * resolve them.
 */
static void x87_top(void)
{
    x87_rd("fpstt");
}

/*
 * An operation whose helper ends in merge_exception_flags().
 *
 * That path is fpu_set_exception(), which ORs the new flags into fpus and
 * consults fpuc's exception masks to decide whether to raise SE/B -- so the
 * status word is read-modify-written and the control word is read.  Both are
 * behind a helper call whose only argument is tcg_env, so neither is visible
 * in the op stream and both are stated here.
 */
static void x87_exc(void)
{
    x87_rd("fpuc");
    x87_rd("fpus");
    x87_wr("fpus");
}

/* fpush(): fpstt -= 1, and the entry it lands on is tagged valid. */
static void x87_push(void)
{
    x87_rd("fpstt");
    x87_wr("fpstt");
    x87_rd("fptag");
    x87_wr("fptag");
}

/* fpop(): the current entry is tagged empty, then fpstt += 1. */
static void x87_pop(void)
{
    x87_push();
}

/*
 * WHERE A MEMORY FORM'S VALUE CAME FROM, AND WHY IT HAS TO BE SAID.
 *
 * The statements above name the accesses and say nothing about the values.
 * That is all the reader needs on a register form, where the fallback it
 * applies -- the instruction's own register read set -- is empty and an empty
 * account is what the arm would have said anyway.  On a MEMORY form the same
 * fallback is actively wrong: the only register such an instruction reads is
 * the one that computed the ADDRESS, so the wire named the pointer as the
 * producer of ST(0) and of the status word.  It is not.  FLD's ST(0) and the
 * exception bits it accumulates are functions of the DATUM the access moved
 * and of the control word; FADD's are functions of the datum, of ST(0) and of
 * the rounding mode; a store's are functions of ST(0).  The pointer chose
 * which memory and supplied no part of the value.
 *
 * gem5 was the witness: over the six x87 memory forms of the depmap probe it
 * routes the loaded value into the FP result and into the status word, and
 * names the base register in neither.  The address half of the same
 * instructions already agreed 56 of 56, which is what made the disagreement
 * readable as a value-half defect rather than an addressing one.
 *
 * Only the memory arms say this.  The register arms' value half is a separate
 * question with a separate answer -- they have no datum, and what they under-
 * report is the stack operands themselves -- and it is not settled here.
 */
static void x87_wr_from(const char *name, const InsnDataflowAtom *src,
                        unsigned n)
{
    insn_dataflow_state_write_from(insn_df_reg(name), src, n);
}

/*
 * The status word an exception check accumulates into, with its value stated.
 *
 * @v is what the operation consumed besides the control and status words
 * themselves: the loaded datum, ST(0), or both, depending on the form.
 */
static void x87_exc_from(const InsnDataflowAtom *v, unsigned n)
{
    InsnDataflowAtom src[4];
    unsigned k = 0;

    x87_rd("fpuc");
    x87_rd("fpus");
    for (unsigned i = 0; i < n && k < ARRAY_SIZE(src) - 2; i++) {
        src[k++] = v[i];
    }
    src[k++] = insn_df_reg("fpuc");
    src[k++] = insn_df_reg("fpus");
    x87_wr_from("fpus", src, k);
}

/*
 * fpush()/fpop() on a memory form: the top moves on its own value, and the
 * tag word the moved-to entry lands in is a function of the tag word and of
 * the top that selected the entry.
 */
static void x87_topmove_sourced(void)
{
    InsnDataflowAtom top = insn_df_reg("fpstt");
    InsnDataflowAtom tag[2] = { insn_df_reg("fptag"), insn_df_reg("fpstt") };

    x87_rd("fpstt");
    x87_rd("fptag");
    x87_wr_from("fpstt", &top, 1);
    x87_wr_from("fptag", tag, 2);
}

/*
 * The x87 facts the ops cannot carry, stated once per instruction.
 *
 * Every effect of an x87 instruction except its memory access is behind a
 * helper call taking tcg_env and nothing else, so the op stream shows a call
 * and no operands at all: undeclared and unstated, `faddp %st,%st(1)` reaches
 * a consumer reading nothing and writing nothing.  These are the facts, taken
 * from what the helpers in fpu_helper.c actually do.
 *
 * THIS MIRRORS gen_x87's OWN SWITCH and must move with it.  It is one table
 * rather than forty statements scattered through the emitter because what a
 * reviewer has to check is that each encoding's row is right, and that check
 * is only possible when the rows sit together.  It is called once, at the end
 * of gen_x87 and only on the paths that did not goto illegal_op, so an
 * encoding the decoder declined states nothing.
 */
static void x86_df_x87(bool mem, int op, int rm)
{
    /* Which of the eight arithmetic forms an fxxx encoding selects. */
    static const char *const arith_word[8] = {
        [0] = INSN_DF_WORD_FP_ADD,      /* fadd  */
        [1] = INSN_DF_WORD_FP_MUL,      /* fmul  */
        [2] = INSN_DF_WORD_FP_CMP,      /* fcom  */
        [3] = INSN_DF_WORD_FP_CMP,      /* fcomp */
        [4] = INSN_DF_WORD_FP_SUB,      /* fsub  */
        [5] = INSN_DF_WORD_FP_SUB,      /* fsubr */
        [6] = INSN_DF_WORD_FP_DIV,      /* fdiv  */
        [7] = INSN_DF_WORD_FP_DIV,      /* fdivr */
    };

    if (mem) {
        int op1 = op & 7;

        switch (op) {
        case 0x00 ... 0x07:     /* fxxxs   m32fp   */
        case 0x10 ... 0x17:     /* fixxxl  m32int  */
        case 0x20 ... 0x27:     /* fxxxl   m64fp   */
        case 0x30 ... 0x37:     /* fixxx   m16int  */
            /*
             * The memory operand is converted into QEMU's ft0 scratch and
             * combined with ST(0).  ft0 is not a register: it is the
             * emulation's carrier for an operand the architecture never
             * names, so it is not stated.  Its VALUE is stated, as the datum
             * of the access that produced it.
             */
            {
                InsnDataflowAtom v[2] = { insn_df_loaded(),
                                          insn_df_reg(x86_x87_st_names[0]) };
                InsnDataflowAtom r[3] = { insn_df_loaded(),
                                          insn_df_reg(x86_x87_st_names[0]),
                                          insn_df_reg("fpuc") };

                insn_dataflow_note_word(arith_word[op1]);
                x87_top();
                x87_rd_st(0);
                x87_exc_from(v, 2);
                if (op1 != 2 && op1 != 3) {
                    /*
                     * The result is the datum, ST(0) and the rounding and
                     * precision control the control word carries.
                     */
                    x87_wr_from(x86_x87_st_names[0], r, 3);
                }
                if (op1 == 3) { /* fcomp pops */
                    x87_topmove_sourced();
                }
            }
            break;

        case 0x08:              /* flds    m32fp   */
        case 0x18:              /* fildl   m32int  */
        case 0x28:              /* fldl    m64fp   */
        case 0x38:              /* filds   m16int  */
        case 0x1d:              /* fldt    m80fp   */
        case 0x3c:              /* fbld    m80bcd  */
        case 0x3d:              /* fildll  m64int  */
            /*
             * A load with the format widening every x87 memory form performs.
             * The widening is implicit in the access and does not distinguish
             * these encodings from each other, so the access is the word.
             *
             * fldt and fbld pass tcg_env and an address to a helper that
             * performs the access itself, so there is no load op and no datum
             * atom to resolve; the reader withdraws the statement for them and
             * the pessimistic fallback stands.  That is the undeclared-access
             * class, not a second answer to this question.
             */
            {
                InsnDataflowAtom v[1] = { insn_df_loaded() };

                insn_dataflow_note_word(INSN_DF_WORD_LOAD);
                x87_topmove_sourced();
                x87_wr_from(x86_x87_st_names[0], v, 1);
                x87_exc_from(v, 1);
            }
            break;

        case 0x19: case 0x1a: case 0x1b:   /* fisttpl, fistl,  fistpl  */
        case 0x29: case 0x2a: case 0x2b:   /* fisttpll, fstl,  fstpl   */
        case 0x39: case 0x3a: case 0x3b:   /* fisttps, fists,  fistps  */
        case 0x0a: case 0x0b:              /* fsts,             fstps  */
        case 0x1f:                         /* fstpt   m80fp            */
        case 0x3e:                         /* fbstp   m80bcd           */
        case 0x3f:                         /* fistpll m64int           */
            {
                InsnDataflowAtom v[1] = { insn_df_reg(x86_x87_st_names[0]) };

                insn_dataflow_note_word(INSN_DF_WORD_STORE);
                x87_top();
                x87_rd_st(0);
                /*
                 * The conversion that produces the stored datum is what can
                 * raise, so the status word accumulates from ST(0) and from
                 * the control word -- and, again, not from the pointer.
                 */
                x87_exc_from(v, 1);
                /*
                 * The popping forms: every `p` suffix, plus fisttp, which pops
                 * unconditionally.  0x1f/0x3e/0x3f are fstpt/fbstp/fistpll.
                 */
                if (op1 == 1 || op1 == 3 || op == 0x1f || op == 0x3e ||
                    op == 0x3f) {
                    x87_topmove_sourced();
                }
            }
            break;

        case 0x0c:              /* fldenv  m14/28byte */
            insn_dataflow_note_word(INSN_DF_WORD_LOAD);
            x87_wr("fpuc");
            x87_wr("fpus");
            x87_wr("fpstt");
            x87_wr("fptag");
            break;

        case 0x0d:              /* fldcw   m16 */
            {
                InsnDataflowAtom v[1] = { insn_df_loaded() };

                insn_dataflow_note_word(INSN_DF_WORD_LOAD);
                x87_wr_from("fpuc", v, 1);
            }
            break;

        case 0x0e:              /* fnstenv m14/28byte */
            insn_dataflow_note_word(INSN_DF_WORD_STORE);
            x87_rd("fpuc");
            x87_rd("fpus");
            x87_rd("fpstt");
            x87_rd("fptag");
            break;

        case 0x0f:              /* fnstcw  m16 */
            insn_dataflow_note_word(INSN_DF_WORD_STORE);
            x87_rd("fpuc");
            break;

        case 0x2c:              /* frstor  m94/108byte */
            /*
             * The whole file is restored, and stating that costs more
             * destination slots than the reader has.  It is stated anyway:
             * the reader's answer to more writes than it can hold is a
             * refusal a consumer can see, which is the honest result for a
             * state-restore instruction, and a short list that looked
             * complete would be the one outcome this layer must not produce.
             */
            insn_dataflow_note_word(INSN_DF_WORD_LOAD);
            for (int i = 0; i < 8; i++) {
                x87_wr_st(i);
            }
            x87_wr("fpuc");
            x87_wr("fpus");
            x87_wr("fpstt");
            x87_wr("fptag");
            break;

        case 0x2e:              /* fnsave  m94/108byte */
            insn_dataflow_note_word(INSN_DF_WORD_STORE);
            for (int i = 0; i < 8; i++) {
                x87_rd_st(i);
            }
            x87_rd("fpuc");
            x87_rd("fpus");
            x87_rd("fpstt");
            x87_rd("fptag");
            /* fsave reinitialises the FPU after writing it out. */
            x87_wr("fpuc");
            x87_wr("fpus");
            x87_wr("fpstt");
            x87_wr("fptag");
            break;

        case 0x2f:              /* fnstsw  m16 */
            insn_dataflow_note_word(INSN_DF_WORD_STORE);
            x87_rd("fpus");
            x87_rd("fpstt");
            break;

        default:
            break;
        }
        return;
    }

    switch (op) {
    case 0x08:                  /* fld  st(i) */
        insn_dataflow_note_word(INSN_DF_WORD_FP_MOV);
        x87_rd_st(rm);          /* the SDM's frame: ST(i) before the push */
        x87_push();
        x87_wr_st(0);
        break;

    case 0x09: case 0x29: case 0x39:    /* fxch st(i), and its two aliases */
        insn_dataflow_note_word(INSN_DF_WORD_XCHG);
        x87_top();
        x87_rd_st(0);
        x87_rd_st(rm);
        x87_wr_st(0);
        x87_wr_st(rm);
        break;

    case 0x0a:                  /* fnop */
        insn_dataflow_note_word(INSN_DF_WORD_NOP);
        x87_rd("fpuc");
        x87_rd("fpus");
        break;

    case 0x0c:                  /* d9/4 */
        switch (rm) {
        case 0:                 /* fchs */
            insn_dataflow_note_word(INSN_DF_WORD_FP_NEG);
            x87_top();
            x87_rd_st(0);
            x87_wr_st(0);
            break;
        case 1:                 /* fabs */
            insn_dataflow_note_word(INSN_DF_WORD_FP_ABS);
            x87_top();
            x87_rd_st(0);
            x87_wr_st(0);
            break;
        case 4:                 /* ftst */
            insn_dataflow_note_word(INSN_DF_WORD_FP_CMP);
            x87_top();
            x87_rd_st(0);
            x87_exc();
            break;
        default:                /* fxam */
            insn_dataflow_note_word(INSN_DF_WORD_FP_CMP);
            x87_top();
            x87_rd_st(0);
            x87_rd("fptag");
            x87_rd("fpus");
            x87_wr("fpus");
            break;
        }
        break;

    case 0x0d:                  /* d9/5: the seven constant loads */
        insn_dataflow_note_word(INSN_DF_WORD_FP_MOV);
        x87_push();
        x87_wr_st(0);
        x87_exc();
        break;

    case 0x0e:                  /* d9/6 */
        switch (rm) {
        case 0:                 /* f2xm1 */
            insn_dataflow_note_word(INSN_DF_WORD_FP_TRANSCENDENTAL);
            x87_top();
            x87_rd_st(0);
            x87_wr_st(0);
            x87_exc();
            break;
        case 1:                 /* fyl2x: ST(1) *= log2(ST(0)), then pop */
            insn_dataflow_note_word(INSN_DF_WORD_FP_TRANSCENDENTAL);
            x87_top();
            x87_rd_st(0);
            x87_rd_st(1);
            x87_wr_st(1);
            x87_exc();
            x87_pop();
            break;
        case 2:                 /* fptan: ST(0) = tan(ST(0)), then push 1.0 */
            insn_dataflow_note_word(INSN_DF_WORD_FP_TRANSCENDENTAL);
            x87_top();
            x87_rd_st(0);
            x87_wr_st(0);
            x87_exc();
            x87_push();
            break;
        case 3:                 /* fpatan: ST(1) = atan(ST(1)/ST(0)), pop */
            insn_dataflow_note_word(INSN_DF_WORD_FP_TRANSCENDENTAL);
            x87_top();
            x87_rd_st(0);
            x87_rd_st(1);
            x87_wr_st(1);
            x87_exc();
            x87_pop();
            break;
        case 4:                 /* fxtract: exponent into ST(0), push sig. */
            insn_dataflow_note_word(INSN_DF_WORD_FP_CVT);
            x87_top();
            x87_rd_st(0);
            x87_wr_st(0);
            x87_exc();
            x87_push();
            x87_wr_st(0);
            break;
        case 5:                 /* fprem1 */
            insn_dataflow_note_word(INSN_DF_WORD_FP_DIV);
            x87_top();
            x87_rd_st(0);
            x87_rd_st(1);
            x87_wr_st(0);
            x87_exc();
            break;
        case 6:                 /* fdecstp */
            insn_dataflow_note_word(INSN_DF_WORD_INT_DEC);
            x87_rd("fpstt");
            x87_wr("fpstt");
            x87_rd("fpus");
            x87_wr("fpus");
            break;
        default:                /* fincstp */
            insn_dataflow_note_word(INSN_DF_WORD_INT_INC);
            x87_rd("fpstt");
            x87_wr("fpstt");
            x87_rd("fpus");
            x87_wr("fpus");
            break;
        }
        break;

    case 0x0f:                  /* d9/7 */
        switch (rm) {
        case 0:                 /* fprem */
            insn_dataflow_note_word(INSN_DF_WORD_FP_DIV);
            x87_top();
            x87_rd_st(0);
            x87_rd_st(1);
            x87_wr_st(0);
            x87_exc();
            break;
        case 1:                 /* fyl2xp1 */
            insn_dataflow_note_word(INSN_DF_WORD_FP_TRANSCENDENTAL);
            x87_top();
            x87_rd_st(0);
            x87_rd_st(1);
            x87_wr_st(1);
            x87_exc();
            x87_pop();
            break;
        case 2:                 /* fsqrt */
            insn_dataflow_note_word(INSN_DF_WORD_FP_SQRT);
            x87_top();
            x87_rd_st(0);
            x87_wr_st(0);
            x87_exc();
            break;
        case 3:                 /* fsincos: sin into ST(0), push cos */
            insn_dataflow_note_word(INSN_DF_WORD_FP_TRANSCENDENTAL);
            x87_top();
            x87_rd_st(0);
            x87_wr_st(0);
            x87_exc();
            x87_push();
            x87_wr_st(0);
            break;
        case 4:                 /* frndint */
            insn_dataflow_note_word(INSN_DF_WORD_FP_CVT);
            x87_top();
            x87_rd_st(0);
            x87_wr_st(0);
            x87_exc();
            break;
        case 5:                 /* fscale: ST(0) *= 2^trunc(ST(1)) */
            insn_dataflow_note_word(INSN_DF_WORD_FP_MUL);
            x87_top();
            x87_rd_st(0);
            x87_rd_st(1);
            x87_wr_st(0);
            x87_exc();
            break;
        default:                /* fsin, fcos */
            insn_dataflow_note_word(INSN_DF_WORD_FP_TRANSCENDENTAL);
            x87_top();
            x87_rd_st(0);
            x87_wr_st(0);
            x87_exc();
            break;
        }
        break;

    case 0x00: case 0x01: case 0x04 ... 0x07:   /* fxxx   st(0), st(i) */
    case 0x20: case 0x21: case 0x24 ... 0x27:   /* fxxx   st(i), st(0) */
    case 0x30: case 0x31: case 0x34 ... 0x37:   /* fxxxp  st(i), st(0) */
        insn_dataflow_note_word(arith_word[op & 7]);
        x87_top();
        x87_rd_st(0);
        x87_rd_st(rm);
        x87_wr_st(op >= 0x20 ? rm : 0);
        x87_exc();
        if (op >= 0x30) {
            x87_pop();
        }
        break;

    case 0x02: case 0x22:       /* fcom  st(i), and its alias */
    case 0x2c:                  /* fucom st(i) */
        insn_dataflow_note_word(INSN_DF_WORD_FP_CMP);
        x87_top();
        x87_rd_st(0);
        x87_rd_st(rm);
        x87_exc();
        break;

    case 0x03: case 0x23: case 0x32:    /* fcomp  st(i), and its aliases */
    case 0x2d:                          /* fucomp st(i) */
        insn_dataflow_note_word(INSN_DF_WORD_FP_CMP);
        x87_top();
        x87_rd_st(0);
        x87_rd_st(rm);
        x87_exc();
        x87_pop();
        break;

    case 0x15:                  /* da/5: fucompp */
    case 0x33:                  /* de/3: fcompp  */
        insn_dataflow_note_word(INSN_DF_WORD_FP_CMP);
        x87_top();
        x87_rd_st(0);
        x87_rd_st(1);
        x87_exc();
        x87_pop();
        x87_pop();
        break;

    case 0x1c:                  /* db/4 */
        switch (rm) {
        case 2:                 /* fnclex: the exception bits are cleared */
            insn_dataflow_note_word(INSN_DF_WORD_AND);
            x87_rd("fpus");
            x87_wr("fpus");
            break;
        case 3:                 /* fninit */
            insn_dataflow_note_word(INSN_DF_WORD_MOV);
            x87_wr("fpuc");
            x87_wr("fpus");
            x87_wr("fpstt");
            x87_wr("fptag");
            break;
        default:                /* feni, fdisi, fsetpm: 287 only, no-ops */
            insn_dataflow_note_word(INSN_DF_WORD_NOP);
            break;
        }
        break;

    case 0x1d:                  /* fucomi  st(0), st(i) */
    case 0x1e:                  /* fcomi   st(0), st(i) */
        insn_dataflow_note_word(INSN_DF_WORD_FP_CMP);
        x87_top();
        x87_rd_st(0);
        x87_rd_st(rm);
        x87_exc();
        x87_wr("eflags");
        break;

    case 0x3d:                  /* fucomip st(0), st(i) */
    case 0x3e:                  /* fcomip  st(0), st(i) */
        insn_dataflow_note_word(INSN_DF_WORD_FP_CMP);
        x87_top();
        x87_rd_st(0);
        x87_rd_st(rm);
        x87_exc();
        x87_wr("eflags");
        x87_pop();
        break;

    case 0x28:                  /* ffree st(i) */
        insn_dataflow_note_word(INSN_DF_WORD_MOV);
        x87_top();
        x87_rd("fptag");
        x87_wr("fptag");
        break;

    case 0x38:                  /* ffreep st(i) */
        insn_dataflow_note_word(INSN_DF_WORD_MOV);
        x87_top();
        x87_rd("fptag");
        x87_wr("fptag");
        x87_pop();
        break;

    case 0x2a:                  /* fst  st(i) */
        insn_dataflow_note_word(INSN_DF_WORD_FP_MOV);
        x87_top();
        x87_rd_st(0);
        x87_wr_st(rm);
        break;

    case 0x0b: case 0x2b: case 0x3a: case 0x3b: /* fstp st(i), and 3 aliases */
        insn_dataflow_note_word(INSN_DF_WORD_FP_MOV);
        x87_top();
        x87_rd_st(0);
        x87_wr_st(rm);
        x87_pop();
        break;

    case 0x3c:                  /* fnstsw ax */
        insn_dataflow_note_word(INSN_DF_WORD_MOV);
        x87_rd("fpus");
        x87_rd("fpstt");
        break;

    case 0x10 ... 0x13:         /* fcmovcc st(0), st(i) */
    case 0x18 ... 0x1b:
        /*
         * The destination is preserved when the condition is false, so it is
         * read as well as written -- the case the header names as one a
         * decoder misses and the ops do not.
         */
        insn_dataflow_note_word(INSN_DF_WORD_CMOV);
        x87_top();
        x87_rd("eflags");
        x87_rd_st(0);
        x87_rd_st(rm);
        x87_wr_st(0);
        break;

    default:
        break;
    }
}

/*
 * THE DATUM AN x87 STORE MOVES IS ST(0), AND NO OP SAYS SO.
 *
 * The helper that converts ST(0) into the format the store writes takes
 * tcg_env and returns the value in a temp, so the temp's account is empty and
 * the store published a datum that depended on nothing.  Binding the temp
 * where the helper produced it is what the emitter knows and the op stream
 * does not.  The two spellings differ only in the width the helper returned.
 */
static void x87_bind_st0_i32(DisasContext *s)
{
    insn_dataflow_bind(tcgv_i32_temp(s->tmp2_i32),
                       insn_df_reg(x86_x87_st_names[0]));
}

static void x87_bind_st0_i64(DisasContext *s)
{
    insn_dataflow_bind(tcgv_i64_temp(s->tmp1_i64),
                       insn_df_reg(x86_x87_st_names[0]));
}

static void gen_x87(DisasContext *s, X86DecodedInsn *decode)
{
    bool update_fip = true;
    int b = decode->b;
    int modrm = s->modrm;
    int mod, rm, op;

    if (s->flags & (HF_EM_MASK | HF_TS_MASK)) {
        /* if CR0.EM or CR0.TS are set, generate an FPU exception */
        /* XXX: what to do if illegal op ? */
        gen_exception(s, EXCP07_PREX);
        return;
    }
    mod = (modrm >> 6) & 3;
    rm = modrm & 7;
    op = ((b & 7) << 3) | ((modrm >> 3) & 7);
    if (mod != 3) {
        /* memory op */
        TCGv ea = gen_lea_modrm_1(s, decode->mem, false);
        TCGv last_addr = tcg_temp_new();
        bool update_fdp = true;

        tcg_gen_mov_tl(last_addr, ea);
        gen_lea_v_seg(s, ea, decode->mem.def_seg, s->override);

        switch (op) {
        case 0x00 ... 0x07: /* fxxxs */
        case 0x10 ... 0x17: /* fixxxl */
        case 0x20 ... 0x27: /* fxxxl */
        case 0x30 ... 0x37: /* fixxx */
            {
                int op1;
                op1 = op & 7;

                switch (op >> 4) {
                case 0:
                    tcg_gen_qemu_ld_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUL);
                    gen_helper_flds_FT0(tcg_env, s->tmp2_i32);
                    break;
                case 1:
                    tcg_gen_qemu_ld_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUL);
                    gen_helper_fildl_FT0(tcg_env, s->tmp2_i32);
                    break;
                case 2:
                    tcg_gen_qemu_ld_i64(s->tmp1_i64, s->A0,
                                        s->mem_index, MO_LEUQ);
                    gen_helper_fldl_FT0(tcg_env, s->tmp1_i64);
                    break;
                case 3:
                default:
                    tcg_gen_qemu_ld_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LESW);
                    gen_helper_fildl_FT0(tcg_env, s->tmp2_i32);
                    break;
                }

                gen_helper_fp_arith_ST0_FT0(op1);
                if (op1 == 3) {
                    /* fcomp needs pop */
                    gen_helper_fpop(tcg_env);
                }
            }
            break;
        case 0x08: /* flds */
        case 0x0a: /* fsts */
        case 0x0b: /* fstps */
        case 0x18 ... 0x1b: /* fildl, fisttpl, fistl, fistpl */
        case 0x28 ... 0x2b: /* fldl, fisttpll, fstl, fstpl */
        case 0x38 ... 0x3b: /* filds, fisttps, fists, fistps */
            switch (op & 7) {
            case 0:
                switch (op >> 4) {
                case 0:
                    tcg_gen_qemu_ld_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUL);
                    gen_helper_flds_ST0(tcg_env, s->tmp2_i32);
                    break;
                case 1:
                    tcg_gen_qemu_ld_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUL);
                    gen_helper_fildl_ST0(tcg_env, s->tmp2_i32);
                    break;
                case 2:
                    tcg_gen_qemu_ld_i64(s->tmp1_i64, s->A0,
                                        s->mem_index, MO_LEUQ);
                    gen_helper_fldl_ST0(tcg_env, s->tmp1_i64);
                    break;
                case 3:
                default:
                    tcg_gen_qemu_ld_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LESW);
                    gen_helper_fildl_ST0(tcg_env, s->tmp2_i32);
                    break;
                }
                break;
            case 1:
                /* XXX: the corresponding CPUID bit must be tested ! */
                switch (op >> 4) {
                case 1:
                    gen_helper_fisttl_ST0(s->tmp2_i32, tcg_env);
                    x87_bind_st0_i32(s);
                    tcg_gen_qemu_st_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUL);
                    break;
                case 2:
                    gen_helper_fisttll_ST0(s->tmp1_i64, tcg_env);
                    x87_bind_st0_i64(s);
                    tcg_gen_qemu_st_i64(s->tmp1_i64, s->A0,
                                        s->mem_index, MO_LEUQ);
                    break;
                case 3:
                default:
                    gen_helper_fistt_ST0(s->tmp2_i32, tcg_env);
                    x87_bind_st0_i32(s);
                    tcg_gen_qemu_st_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUW);
                    break;
                }
                gen_helper_fpop(tcg_env);
                break;
            default:
                switch (op >> 4) {
                case 0:
                    gen_helper_fsts_ST0(s->tmp2_i32, tcg_env);
                    x87_bind_st0_i32(s);
                    tcg_gen_qemu_st_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUL);
                    break;
                case 1:
                    gen_helper_fistl_ST0(s->tmp2_i32, tcg_env);
                    x87_bind_st0_i32(s);
                    tcg_gen_qemu_st_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUL);
                    break;
                case 2:
                    gen_helper_fstl_ST0(s->tmp1_i64, tcg_env);
                    x87_bind_st0_i64(s);
                    tcg_gen_qemu_st_i64(s->tmp1_i64, s->A0,
                                        s->mem_index, MO_LEUQ);
                    break;
                case 3:
                default:
                    gen_helper_fist_ST0(s->tmp2_i32, tcg_env);
                    x87_bind_st0_i32(s);
                    tcg_gen_qemu_st_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUW);
                    break;
                }
                if ((op & 7) == 3) {
                    gen_helper_fpop(tcg_env);
                }
                break;
            }
            break;
        case 0x0c: /* fldenv mem */
            gen_helper_fldenv(tcg_env, s->A0,
                              tcg_constant_i32(s->dflag - 1));
            update_fip = update_fdp = false;
            break;
        case 0x0d: /* fldcw mem */
            tcg_gen_qemu_ld_i32(s->tmp2_i32, s->A0,
                                s->mem_index, MO_LEUW);
            gen_helper_fldcw(tcg_env, s->tmp2_i32);
            update_fip = update_fdp = false;
            break;
        case 0x0e: /* fnstenv mem */
            gen_helper_fstenv(tcg_env, s->A0,
                              tcg_constant_i32(s->dflag - 1));
            update_fip = update_fdp = false;
            break;
        case 0x0f: /* fnstcw mem */
            gen_helper_fnstcw(s->tmp2_i32, tcg_env);
            insn_dataflow_bind(tcgv_i32_temp(s->tmp2_i32),
                               insn_df_reg("fpuc"));
            tcg_gen_qemu_st_i32(s->tmp2_i32, s->A0,
                                s->mem_index, MO_LEUW);
            update_fip = update_fdp = false;
            break;
        case 0x1d: /* fldt mem */
            gen_helper_fldt_ST0(tcg_env, s->A0);
            break;
        case 0x1f: /* fstpt mem */
            gen_helper_fstt_ST0(tcg_env, s->A0);
            gen_helper_fpop(tcg_env);
            break;
        case 0x2c: /* frstor mem */
            gen_helper_frstor(tcg_env, s->A0,
                              tcg_constant_i32(s->dflag - 1));
            update_fip = update_fdp = false;
            break;
        case 0x2e: /* fnsave mem */
            gen_helper_fsave(tcg_env, s->A0,
                             tcg_constant_i32(s->dflag - 1));
            update_fip = update_fdp = false;
            break;
        case 0x2f: /* fnstsw mem */
            gen_helper_fnstsw(s->tmp2_i32, tcg_env);
            insn_dataflow_bind(tcgv_i32_temp(s->tmp2_i32),
                               insn_df_reg("fpus"));
            tcg_gen_qemu_st_i32(s->tmp2_i32, s->A0,
                                s->mem_index, MO_LEUW);
            update_fip = update_fdp = false;
            break;
        case 0x3c: /* fbld */
            gen_helper_fbld_ST0(tcg_env, s->A0);
            break;
        case 0x3e: /* fbstp */
            gen_helper_fbst_ST0(tcg_env, s->A0);
            gen_helper_fpop(tcg_env);
            break;
        case 0x3d: /* fildll */
            tcg_gen_qemu_ld_i64(s->tmp1_i64, s->A0,
                                s->mem_index, MO_LEUQ);
            gen_helper_fildll_ST0(tcg_env, s->tmp1_i64);
            break;
        case 0x3f: /* fistpll */
            gen_helper_fistll_ST0(s->tmp1_i64, tcg_env);
            x87_bind_st0_i64(s);
            tcg_gen_qemu_st_i64(s->tmp1_i64, s->A0,
                                s->mem_index, MO_LEUQ);
            gen_helper_fpop(tcg_env);
            break;
        default:
            goto illegal_op;
        }

        if (update_fdp) {
            int last_seg = s->override >= 0 ? s->override : decode->mem.def_seg;

            tcg_gen_ld_i32(s->tmp2_i32, tcg_env,
                           offsetof(CPUX86State,
                                    segs[last_seg].selector));
            tcg_gen_st16_i32(s->tmp2_i32, tcg_env,
                             offsetof(CPUX86State, fpds));
            tcg_gen_st_tl(last_addr, tcg_env,
                          offsetof(CPUX86State, fpdp));
        }
    } else {
        /* register float ops */
        int opreg = rm;

        switch (op) {
        case 0x08: /* fld sti */
            gen_helper_fpush(tcg_env);
            gen_helper_fmov_ST0_STN(tcg_env,
                                    tcg_constant_i32((opreg + 1) & 7));
            break;
        case 0x09: /* fxchg sti */
        case 0x29: /* fxchg4 sti, undocumented op */
        case 0x39: /* fxchg7 sti, undocumented op */
            gen_helper_fxchg_ST0_STN(tcg_env, tcg_constant_i32(opreg));
            break;
        case 0x0a: /* grp d9/2 */
            switch (rm) {
            case 0: /* fnop */
                /*
                 * check exceptions (FreeBSD FPU probe)
                 * needs to be treated as I/O because of ferr_irq
                 */
                translator_io_start(&s->base);
                gen_helper_fwait(tcg_env);
                update_fip = false;
                break;
            default:
                goto illegal_op;
            }
            break;
        case 0x0c: /* grp d9/4 */
            switch (rm) {
            case 0: /* fchs */
                gen_helper_fchs_ST0(tcg_env);
                break;
            case 1: /* fabs */
                gen_helper_fabs_ST0(tcg_env);
                break;
            case 4: /* ftst */
                gen_helper_fldz_FT0(tcg_env);
                gen_helper_fcom_ST0_FT0(tcg_env);
                break;
            case 5: /* fxam */
                gen_helper_fxam_ST0(tcg_env);
                break;
            default:
                goto illegal_op;
            }
            break;
        case 0x0d: /* grp d9/5 */
            {
                switch (rm) {
                case 0:
                    gen_helper_fpush(tcg_env);
                    gen_helper_fld1_ST0(tcg_env);
                    break;
                case 1:
                    gen_helper_fpush(tcg_env);
                    gen_helper_fldl2t_ST0(tcg_env);
                    break;
                case 2:
                    gen_helper_fpush(tcg_env);
                    gen_helper_fldl2e_ST0(tcg_env);
                    break;
                case 3:
                    gen_helper_fpush(tcg_env);
                    gen_helper_fldpi_ST0(tcg_env);
                    break;
                case 4:
                    gen_helper_fpush(tcg_env);
                    gen_helper_fldlg2_ST0(tcg_env);
                    break;
                case 5:
                    gen_helper_fpush(tcg_env);
                    gen_helper_fldln2_ST0(tcg_env);
                    break;
                case 6:
                    gen_helper_fpush(tcg_env);
                    gen_helper_fldz_ST0(tcg_env);
                    break;
                default:
                    goto illegal_op;
                }
            }
            break;
        case 0x0e: /* grp d9/6 */
            switch (rm) {
            case 0: /* f2xm1 */
                gen_helper_f2xm1(tcg_env);
                break;
            case 1: /* fyl2x */
                gen_helper_fyl2x(tcg_env);
                break;
            case 2: /* fptan */
                gen_helper_fptan(tcg_env);
                break;
            case 3: /* fpatan */
                gen_helper_fpatan(tcg_env);
                break;
            case 4: /* fxtract */
                gen_helper_fxtract(tcg_env);
                break;
            case 5: /* fprem1 */
                gen_helper_fprem1(tcg_env);
                break;
            case 6: /* fdecstp */
                gen_helper_fdecstp(tcg_env);
                break;
            default:
            case 7: /* fincstp */
                gen_helper_fincstp(tcg_env);
                break;
            }
            break;
        case 0x0f: /* grp d9/7 */
            switch (rm) {
            case 0: /* fprem */
                gen_helper_fprem(tcg_env);
                break;
            case 1: /* fyl2xp1 */
                gen_helper_fyl2xp1(tcg_env);
                break;
            case 2: /* fsqrt */
                gen_helper_fsqrt(tcg_env);
                break;
            case 3: /* fsincos */
                gen_helper_fsincos(tcg_env);
                break;
            case 5: /* fscale */
                gen_helper_fscale(tcg_env);
                break;
            case 4: /* frndint */
                gen_helper_frndint(tcg_env);
                break;
            case 6: /* fsin */
                gen_helper_fsin(tcg_env);
                break;
            default:
            case 7: /* fcos */
                gen_helper_fcos(tcg_env);
                break;
            }
            break;
        case 0x00: case 0x01: case 0x04 ... 0x07: /* fxxx st, sti */
        case 0x20: case 0x21: case 0x24 ... 0x27: /* fxxx sti, st */
        case 0x30: case 0x31: case 0x34 ... 0x37: /* fxxxp sti, st */
            {
                int op1;

                op1 = op & 7;
                if (op >= 0x20) {
                    gen_helper_fp_arith_STN_ST0(op1, opreg);
                    if (op >= 0x30) {
                        gen_helper_fpop(tcg_env);
                    }
                } else {
                    gen_helper_fmov_FT0_STN(tcg_env,
                                            tcg_constant_i32(opreg));
                    gen_helper_fp_arith_ST0_FT0(op1);
                }
            }
            break;
        case 0x02: /* fcom */
        case 0x22: /* fcom2, undocumented op */
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_helper_fcom_ST0_FT0(tcg_env);
            break;
        case 0x03: /* fcomp */
        case 0x23: /* fcomp3, undocumented op */
        case 0x32: /* fcomp5, undocumented op */
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_helper_fcom_ST0_FT0(tcg_env);
            gen_helper_fpop(tcg_env);
            break;
        case 0x15: /* da/5 */
            switch (rm) {
            case 1: /* fucompp */
                gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(1));
                gen_helper_fucom_ST0_FT0(tcg_env);
                gen_helper_fpop(tcg_env);
                gen_helper_fpop(tcg_env);
                break;
            default:
                goto illegal_op;
            }
            break;
        case 0x1c:
            switch (rm) {
            case 0: /* feni (287 only, just do nop here) */
                break;
            case 1: /* fdisi (287 only, just do nop here) */
                break;
            case 2: /* fclex */
                gen_helper_fclex(tcg_env);
                update_fip = false;
                break;
            case 3: /* fninit */
                gen_helper_fninit(tcg_env);
                update_fip = false;
                break;
            case 4: /* fsetpm (287 only, just do nop here) */
                break;
            default:
                goto illegal_op;
            }
            break;
        case 0x1d: /* fucomi */
            if (!(s->cpuid_features & CPUID_CMOV)) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_helper_fucomi_ST0_FT0(tcg_env);
            assume_cc_op(s, CC_OP_EFLAGS);
            break;
        case 0x1e: /* fcomi */
            if (!(s->cpuid_features & CPUID_CMOV)) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_helper_fcomi_ST0_FT0(tcg_env);
            assume_cc_op(s, CC_OP_EFLAGS);
            break;
        case 0x28: /* ffree sti */
            gen_helper_ffree_STN(tcg_env, tcg_constant_i32(opreg));
            break;
        case 0x2a: /* fst sti */
            gen_helper_fmov_STN_ST0(tcg_env, tcg_constant_i32(opreg));
            break;
        case 0x2b: /* fstp sti */
        case 0x0b: /* fstp1 sti, undocumented op */
        case 0x3a: /* fstp8 sti, undocumented op */
        case 0x3b: /* fstp9 sti, undocumented op */
            gen_helper_fmov_STN_ST0(tcg_env, tcg_constant_i32(opreg));
            gen_helper_fpop(tcg_env);
            break;
        case 0x2c: /* fucom st(i) */
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_helper_fucom_ST0_FT0(tcg_env);
            break;
        case 0x2d: /* fucomp st(i) */
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_helper_fucom_ST0_FT0(tcg_env);
            gen_helper_fpop(tcg_env);
            break;
        case 0x33: /* de/3 */
            switch (rm) {
            case 1: /* fcompp */
                gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(1));
                gen_helper_fcom_ST0_FT0(tcg_env);
                gen_helper_fpop(tcg_env);
                gen_helper_fpop(tcg_env);
                break;
            default:
                goto illegal_op;
            }
            break;
        case 0x38: /* ffreep sti, undocumented op */
            gen_helper_ffree_STN(tcg_env, tcg_constant_i32(opreg));
            gen_helper_fpop(tcg_env);
            break;
        case 0x3c: /* df/4 */
            switch (rm) {
            case 0:
                gen_helper_fnstsw(s->tmp2_i32, tcg_env);
                tcg_gen_extu_i32_tl(s->T0, s->tmp2_i32);
                gen_op_mov_reg_v(s, MO_16, R_EAX, s->T0);
                break;
            default:
                goto illegal_op;
            }
            break;
        case 0x3d: /* fucomip */
            if (!(s->cpuid_features & CPUID_CMOV)) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_helper_fucomi_ST0_FT0(tcg_env);
            gen_helper_fpop(tcg_env);
            assume_cc_op(s, CC_OP_EFLAGS);
            break;
        case 0x3e: /* fcomip */
            if (!(s->cpuid_features & CPUID_CMOV)) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_helper_fcomi_ST0_FT0(tcg_env);
            gen_helper_fpop(tcg_env);
            assume_cc_op(s, CC_OP_EFLAGS);
            break;
        case 0x10 ... 0x13: /* fcmovxx */
        case 0x18 ... 0x1b:
            {
                int op1;
                TCGLabel *l1;
                static const uint8_t fcmov_cc[8] = {
                    (JCC_B << 1),
                    (JCC_Z << 1),
                    (JCC_BE << 1),
                    (JCC_P << 1),
                };

                if (!(s->cpuid_features & CPUID_CMOV)) {
                    goto illegal_op;
                }
                op1 = fcmov_cc[op & 3] | (((op >> 3) & 1) ^ 1);
                l1 = gen_new_label();
                gen_jcc_noeob(s, op1, l1);
                gen_helper_fmov_ST0_STN(tcg_env,
                                        tcg_constant_i32(opreg));
                gen_set_label(l1);
            }
            break;
        default:
            goto illegal_op;
        }
    }

    /*
     * Reached only by an encoding the switches above accepted: every other
     * route went to illegal_op, and an encoding the decoder declined states
     * nothing.
     */
    x86_df_x87(mod != 3, op, rm);

    if (update_fip) {
        tcg_gen_ld_i32(s->tmp2_i32, tcg_env,
                       offsetof(CPUX86State, segs[R_CS].selector));
        tcg_gen_st16_i32(s->tmp2_i32, tcg_env,
                         offsetof(CPUX86State, fpcs));
        tcg_gen_st_tl(eip_cur_tl(s),
                      tcg_env, offsetof(CPUX86State, fpip));
    }
    return;

 illegal_op:
    gen_illegal_opcode(s);
}

static void gen_multi0F(DisasContext *s, X86DecodedInsn *decode)
{
    int prefixes = s->prefix;
    MemOp dflag = s->dflag;
    int b = decode->b + 0x100;
    int modrm = s->modrm;
    MemOp ot;
    int reg, rm, mod, op;

    /* now check op code */
    switch (b) {
    case 0x1c7: /* RDSEED, RDPID with f3 prefix */
        mod = (modrm >> 6) & 3;
        switch ((modrm >> 3) & 7) {
        case 7:
            if (mod != 3 ||
                (s->prefix & PREFIX_REPNZ)) {
                goto illegal_op;
            }
            if (s->prefix & PREFIX_REPZ) {
                if (!(s->cpuid_7_0_ecx_features & CPUID_7_0_ECX_RDPID)) {
                    goto illegal_op;
                }
                gen_helper_rdpid(s->T0, tcg_env);
                rm = (modrm & 7) | REX_B(s);
                gen_op_mov_reg_v(s, dflag, rm, s->T0);
                break;
            } else {
                if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_RDSEED)) {
                    goto illegal_op;
                }
                goto do_rdrand;
            }

        case 6: /* RDRAND */
            if (mod != 3 ||
                (s->prefix & (PREFIX_REPZ | PREFIX_REPNZ)) ||
                !(s->cpuid_ext_features & CPUID_EXT_RDRAND)) {
                goto illegal_op;
            }
        do_rdrand:
            translator_io_start(&s->base);
            gen_helper_rdrand(s->T0, tcg_env);
            rm = (modrm & 7) | REX_B(s);
            gen_op_mov_reg_v(s, dflag, rm, s->T0);
            assume_cc_op(s, CC_OP_EFLAGS);
            break;

        default:
            goto illegal_op;
        }
        break;

    case 0x100:
        mod = (modrm >> 6) & 3;
        op = (modrm >> 3) & 7;
        switch(op) {
        case 0: /* sldt */
            if (!PE(s) || VM86(s))
                goto illegal_op;
            if (s->flags & HF_UMIP_MASK && !check_cpl0(s)) {
                break;
            }
            gen_svm_check_intercept(s, SVM_EXIT_LDTR_READ);
            tcg_gen_ld32u_tl(s->T0, tcg_env,
                             offsetof(CPUX86State, ldt.selector));
            ot = mod == 3 ? dflag : MO_16;
            gen_st_modrm(s, decode, ot);
            break;
        case 2: /* lldt */
            if (!PE(s) || VM86(s))
                goto illegal_op;
            if (check_cpl0(s)) {
                gen_svm_check_intercept(s, SVM_EXIT_LDTR_WRITE);
                gen_ld_modrm(s, decode, MO_16);
                tcg_gen_trunc_tl_i32(s->tmp2_i32, s->T0);
                gen_helper_lldt(tcg_env, s->tmp2_i32);
            }
            break;
        case 1: /* str */
            if (!PE(s) || VM86(s))
                goto illegal_op;
            if (s->flags & HF_UMIP_MASK && !check_cpl0(s)) {
                break;
            }
            gen_svm_check_intercept(s, SVM_EXIT_TR_READ);
            tcg_gen_ld32u_tl(s->T0, tcg_env,
                             offsetof(CPUX86State, tr.selector));
            ot = mod == 3 ? dflag : MO_16;
            gen_st_modrm(s, decode, ot);
            break;
        case 3: /* ltr */
            if (!PE(s) || VM86(s))
                goto illegal_op;
            if (check_cpl0(s)) {
                gen_svm_check_intercept(s, SVM_EXIT_TR_WRITE);
                gen_ld_modrm(s, decode, MO_16);
                tcg_gen_trunc_tl_i32(s->tmp2_i32, s->T0);
                gen_helper_ltr(tcg_env, s->tmp2_i32);
            }
            break;
        case 4: /* verr */
        case 5: /* verw */
            if (!PE(s) || VM86(s))
                goto illegal_op;
            gen_ld_modrm(s, decode, MO_16);
            gen_update_cc_op(s);
            if (op == 4) {
                gen_helper_verr(tcg_env, s->T0);
            } else {
                gen_helper_verw(tcg_env, s->T0);
            }
            assume_cc_op(s, CC_OP_EFLAGS);
            break;
        default:
            goto illegal_op;
        }
        break;

    case 0x101:
        switch (modrm) {
        CASE_MODRM_MEM_OP(0): /* sgdt */
            if (s->flags & HF_UMIP_MASK && !check_cpl0(s)) {
                break;
            }
            gen_svm_check_intercept(s, SVM_EXIT_GDTR_READ);
            gen_lea_modrm(s, decode);
            tcg_gen_ld32u_tl(s->T0,
                             tcg_env, offsetof(CPUX86State, gdt.limit));
            gen_op_st_v(s, MO_16, s->T0, s->A0);
            gen_add_A0_im(s, 2);
            tcg_gen_ld_tl(s->T0, tcg_env, offsetof(CPUX86State, gdt.base));
            /*
             * NB: Despite a confusing description in Intel CPU documentation,
             *     all 32-bits are written regardless of operand size.
             */
            gen_op_st_v(s, CODE64(s) + MO_32, s->T0, s->A0);
            break;

        case 0xc8: /* monitor */
            if (!(s->cpuid_ext_features & CPUID_EXT_MONITOR) || CPL(s) != 0) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_update_eip_cur(s);
            gen_lea_v_seg(s, cpu_regs[R_EAX], R_DS, s->override);
            gen_helper_monitor(tcg_env, s->A0);
            break;

        case 0xc9: /* mwait */
            if (!(s->cpuid_ext_features & CPUID_EXT_MONITOR) || CPL(s) != 0) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_update_eip_cur(s);
            gen_helper_mwait(tcg_env, cur_insn_len_i32(s));
            s->base.is_jmp = DISAS_NORETURN;
            break;

        case 0xca: /* clac */
            if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_SMAP)
                || CPL(s) != 0) {
                goto illegal_op;
            }
            gen_reset_eflags(s, AC_MASK);
            s->base.is_jmp = DISAS_EOB_NEXT;
            break;

        case 0xcb: /* stac */
            if (!(s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_SMAP)
                || CPL(s) != 0) {
                goto illegal_op;
            }
            gen_set_eflags(s, AC_MASK);
            s->base.is_jmp = DISAS_EOB_NEXT;
            break;

        CASE_MODRM_MEM_OP(1): /* sidt */
            if (s->flags & HF_UMIP_MASK && !check_cpl0(s)) {
                break;
            }
            gen_svm_check_intercept(s, SVM_EXIT_IDTR_READ);
            gen_lea_modrm(s, decode);
            tcg_gen_ld32u_tl(s->T0, tcg_env, offsetof(CPUX86State, idt.limit));
            gen_op_st_v(s, MO_16, s->T0, s->A0);
            gen_add_A0_im(s, 2);
            tcg_gen_ld_tl(s->T0, tcg_env, offsetof(CPUX86State, idt.base));
            /*
             * NB: Despite a confusing description in Intel CPU documentation,
             *     all 32-bits are written regardless of operand size.
             */
            gen_op_st_v(s, CODE64(s) + MO_32, s->T0, s->A0);
            break;

        case 0xd0: /* xgetbv */
            if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                || (s->prefix & (PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }
            tcg_gen_trunc_tl_i32(s->tmp2_i32, cpu_regs[R_ECX]);
            gen_helper_xgetbv(s->tmp1_i64, tcg_env, s->tmp2_i32);
            tcg_gen_extr_i64_tl(cpu_regs[R_EAX], cpu_regs[R_EDX], s->tmp1_i64);
            break;

        case 0xd1: /* xsetbv */
            if ((s->cpuid_ext_features & CPUID_EXT_XSAVE) == 0
                || (s->prefix & (PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ))) {
                goto illegal_op;
            }
            gen_svm_check_intercept(s, SVM_EXIT_XSETBV);
            if (!check_cpl0(s)) {
                break;
            }
            tcg_gen_concat_tl_i64(s->tmp1_i64, cpu_regs[R_EAX],
                                  cpu_regs[R_EDX]);
            tcg_gen_trunc_tl_i32(s->tmp2_i32, cpu_regs[R_ECX]);
            gen_helper_xsetbv(tcg_env, s->tmp2_i32, s->tmp1_i64);
            /* End TB because translation flags may change.  */
            s->base.is_jmp = DISAS_EOB_NEXT;
            break;

        case 0xd8: /* VMRUN */
            if (!SVME(s) || !PE(s)) {
                goto illegal_op;
            }
            if (!check_cpl0(s)) {
                break;
            }
            gen_update_cc_op(s);
            gen_update_eip_cur(s);
            /*
             * Reloads INHIBIT_IRQ mask as well as TF and RF with guest state.
             * The usual gen_eob() handling is performed on vmexit after
             * host state is reloaded.
             */
            gen_helper_vmrun(tcg_env, tcg_constant_i32(s->aflag - 1),
                             cur_insn_len_i32(s));
            tcg_gen_exit_tb(NULL, 0);
            s->base.is_jmp = DISAS_NORETURN;
            break;

        case 0xd9: /* VMMCALL */
            if (!SVME(s)) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_update_eip_cur(s);
            gen_helper_vmmcall(tcg_env);
            break;

        case 0xda: /* VMLOAD */
            if (!SVME(s) || !PE(s)) {
                goto illegal_op;
            }
            if (!check_cpl0(s)) {
                break;
            }
            gen_update_cc_op(s);
            gen_update_eip_cur(s);
            gen_helper_vmload(tcg_env, tcg_constant_i32(s->aflag - 1));
            break;

        case 0xdb: /* VMSAVE */
            if (!SVME(s) || !PE(s)) {
                goto illegal_op;
            }
            if (!check_cpl0(s)) {
                break;
            }
            gen_update_cc_op(s);
            gen_update_eip_cur(s);
            gen_helper_vmsave(tcg_env, tcg_constant_i32(s->aflag - 1));
            break;

        case 0xdc: /* STGI */
            if ((!SVME(s) && !(s->cpuid_ext3_features & CPUID_EXT3_SKINIT))
                || !PE(s)) {
                goto illegal_op;
            }
            if (!check_cpl0(s)) {
                break;
            }
            gen_update_cc_op(s);
            gen_helper_stgi(tcg_env);
            s->base.is_jmp = DISAS_EOB_NEXT;
            break;

        case 0xdd: /* CLGI */
            if (!SVME(s) || !PE(s)) {
                goto illegal_op;
            }
            if (!check_cpl0(s)) {
                break;
            }
            gen_update_cc_op(s);
            gen_update_eip_cur(s);
            gen_helper_clgi(tcg_env);
            break;

        case 0xde: /* SKINIT */
            if ((!SVME(s) && !(s->cpuid_ext3_features & CPUID_EXT3_SKINIT))
                || !PE(s)) {
                goto illegal_op;
            }
            gen_svm_check_intercept(s, SVM_EXIT_SKINIT);
            /* If not intercepted, not implemented -- raise #UD. */
            goto illegal_op;

        case 0xdf: /* INVLPGA */
            if (!SVME(s) || !PE(s)) {
                goto illegal_op;
            }
            if (!check_cpl0(s)) {
                break;
            }
            gen_svm_check_intercept(s, SVM_EXIT_INVLPGA);
            if (s->aflag == MO_64) {
                tcg_gen_mov_tl(s->A0, cpu_regs[R_EAX]);
            } else {
                tcg_gen_ext32u_tl(s->A0, cpu_regs[R_EAX]);
            }
            gen_helper_flush_page(tcg_env, s->A0);
            s->base.is_jmp = DISAS_EOB_NEXT;
            break;

        CASE_MODRM_MEM_OP(2): /* lgdt */
            if (!check_cpl0(s)) {
                break;
            }
            gen_svm_check_intercept(s, SVM_EXIT_GDTR_WRITE);
            gen_lea_modrm(s, decode);
            gen_op_ld_v(s, MO_16, s->T1, s->A0);
            gen_add_A0_im(s, 2);
            gen_op_ld_v(s, CODE64(s) + MO_32, s->T0, s->A0);
            if (dflag == MO_16) {
                tcg_gen_andi_tl(s->T0, s->T0, 0xffffff);
            }
            tcg_gen_st_tl(s->T0, tcg_env, offsetof(CPUX86State, gdt.base));
            tcg_gen_st32_tl(s->T1, tcg_env, offsetof(CPUX86State, gdt.limit));
            break;

        CASE_MODRM_MEM_OP(3): /* lidt */
            if (!check_cpl0(s)) {
                break;
            }
            gen_svm_check_intercept(s, SVM_EXIT_IDTR_WRITE);
            gen_lea_modrm(s, decode);
            gen_op_ld_v(s, MO_16, s->T1, s->A0);
            gen_add_A0_im(s, 2);
            gen_op_ld_v(s, CODE64(s) + MO_32, s->T0, s->A0);
            if (dflag == MO_16) {
                tcg_gen_andi_tl(s->T0, s->T0, 0xffffff);
            }
            tcg_gen_st_tl(s->T0, tcg_env, offsetof(CPUX86State, idt.base));
            tcg_gen_st32_tl(s->T1, tcg_env, offsetof(CPUX86State, idt.limit));
            break;

        CASE_MODRM_OP(4): /* smsw */
            if (s->flags & HF_UMIP_MASK && !check_cpl0(s)) {
                break;
            }
            gen_svm_check_intercept(s, SVM_EXIT_READ_CR0);
            tcg_gen_ld_tl(s->T0, tcg_env, offsetof(CPUX86State, cr[0]));
            /*
             * In 32-bit mode, the higher 16 bits of the destination
             * register are undefined.  In practice CR0[31:0] is stored
             * just like in 64-bit mode.
             */
            mod = (modrm >> 6) & 3;
            ot = (mod != 3 ? MO_16 : s->dflag);
            gen_st_modrm(s, decode, ot);
            break;
        case 0xee: /* rdpkru */
            if (s->prefix & (PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ)) {
                goto illegal_op;
            }
            tcg_gen_trunc_tl_i32(s->tmp2_i32, cpu_regs[R_ECX]);
            gen_helper_rdpkru(s->tmp1_i64, tcg_env, s->tmp2_i32);
            tcg_gen_extr_i64_tl(cpu_regs[R_EAX], cpu_regs[R_EDX], s->tmp1_i64);
            break;
        case 0xef: /* wrpkru */
            if (s->prefix & (PREFIX_DATA | PREFIX_REPZ | PREFIX_REPNZ)) {
                goto illegal_op;
            }
            tcg_gen_concat_tl_i64(s->tmp1_i64, cpu_regs[R_EAX],
                                  cpu_regs[R_EDX]);
            tcg_gen_trunc_tl_i32(s->tmp2_i32, cpu_regs[R_ECX]);
            gen_helper_wrpkru(tcg_env, s->tmp2_i32, s->tmp1_i64);
            break;

        CASE_MODRM_OP(6): /* lmsw */
            if (!check_cpl0(s)) {
                break;
            }
            gen_svm_check_intercept(s, SVM_EXIT_WRITE_CR0);
            gen_ld_modrm(s, decode, MO_16);
            /*
             * Only the 4 lower bits of CR0 are modified.
             * PE cannot be set to zero if already set to one.
             */
            tcg_gen_ld_tl(s->T1, tcg_env, offsetof(CPUX86State, cr[0]));
            tcg_gen_andi_tl(s->T0, s->T0, 0xf);
            tcg_gen_andi_tl(s->T1, s->T1, ~0xe);
            tcg_gen_or_tl(s->T0, s->T0, s->T1);
            gen_helper_write_crN(tcg_env, tcg_constant_i32(0), s->T0);
            s->base.is_jmp = DISAS_EOB_NEXT;
            break;

        CASE_MODRM_MEM_OP(7): /* invlpg */
            if (!check_cpl0(s)) {
                break;
            }
            gen_svm_check_intercept(s, SVM_EXIT_INVLPG);
            gen_lea_modrm(s, decode);
            gen_helper_flush_page(tcg_env, s->A0);
            s->base.is_jmp = DISAS_EOB_NEXT;
            break;

        case 0xf8: /* swapgs */
#ifdef TARGET_X86_64
            if (CODE64(s)) {
                if (check_cpl0(s)) {
                    tcg_gen_mov_tl(s->T0, cpu_seg_base[R_GS]);
                    tcg_gen_ld_tl(cpu_seg_base[R_GS], tcg_env,
                                  offsetof(CPUX86State, kernelgsbase));
                    tcg_gen_st_tl(s->T0, tcg_env,
                                  offsetof(CPUX86State, kernelgsbase));
                }
                break;
            }
#endif
            goto illegal_op;

        case 0xf9: /* rdtscp */
            if (!(s->cpuid_ext2_features & CPUID_EXT2_RDTSCP)) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_update_eip_cur(s);
            translator_io_start(&s->base);
            gen_helper_rdtsc(tcg_env);
            gen_helper_rdpid(s->T0, tcg_env);
            gen_op_mov_reg_v(s, dflag, R_ECX, s->T0);
            break;

        default:
            goto illegal_op;
        }
        break;

    case 0x11a:
        if (s->flags & HF_MPX_EN_MASK) {
            mod = (modrm >> 6) & 3;
            reg = ((modrm >> 3) & 7) | REX_R(s);
            if (prefixes & PREFIX_REPZ) {
                /* bndcl */
                if (reg >= 4
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                gen_bndck(s, decode, TCG_COND_LTU, cpu_bndl[reg]);
            } else if (prefixes & PREFIX_REPNZ) {
                /* bndcu */
                if (reg >= 4
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                TCGv_i64 notu = tcg_temp_new_i64();
                tcg_gen_not_i64(notu, cpu_bndu[reg]);
                gen_bndck(s, decode, TCG_COND_GTU, notu);
            } else if (prefixes & PREFIX_DATA) {
                /* bndmov -- from reg/mem */
                if (reg >= 4 || s->aflag == MO_16) {
                    goto illegal_op;
                }
                if (mod == 3) {
                    int reg2 = (modrm & 7) | REX_B(s);
                    if (reg2 >= 4) {
                        goto illegal_op;
                    }
                    if (s->flags & HF_MPX_IU_MASK) {
                        tcg_gen_mov_i64(cpu_bndl[reg], cpu_bndl[reg2]);
                        tcg_gen_mov_i64(cpu_bndu[reg], cpu_bndu[reg2]);
                    }
                } else {
                    gen_lea_modrm(s, decode);
                    if (CODE64(s)) {
                        tcg_gen_qemu_ld_i64(cpu_bndl[reg], s->A0,
                                            s->mem_index, MO_LEUQ);
                        tcg_gen_addi_tl(s->A0, s->A0, 8);
                        tcg_gen_qemu_ld_i64(cpu_bndu[reg], s->A0,
                                            s->mem_index, MO_LEUQ);
                    } else {
                        tcg_gen_qemu_ld_i64(cpu_bndl[reg], s->A0,
                                            s->mem_index, MO_LEUL);
                        tcg_gen_addi_tl(s->A0, s->A0, 4);
                        tcg_gen_qemu_ld_i64(cpu_bndu[reg], s->A0,
                                            s->mem_index, MO_LEUL);
                    }
                    /* bnd registers are now in-use */
                    gen_set_hflag(s, HF_MPX_IU_MASK);
                }
            } else if (mod != 3) {
                /* bndldx */
                AddressParts a = decode->mem;
                if (reg >= 4
                    || s->aflag == MO_16
                    || a.base < -1) {
                    goto illegal_op;
                }
                if (a.base >= 0) {
                    tcg_gen_addi_tl(s->A0, cpu_regs[a.base], a.disp);
                } else {
                    tcg_gen_movi_tl(s->A0, 0);
                }
                gen_lea_v_seg(s, s->A0, a.def_seg, s->override);
                if (a.index >= 0) {
                    tcg_gen_mov_tl(s->T0, cpu_regs[a.index]);
                } else {
                    tcg_gen_movi_tl(s->T0, 0);
                }
                if (CODE64(s)) {
                    gen_helper_bndldx64(cpu_bndl[reg], tcg_env, s->A0, s->T0);
                    tcg_gen_ld_i64(cpu_bndu[reg], tcg_env,
                                   offsetof(CPUX86State, mmx_t0.MMX_Q(0)));
                } else {
                    gen_helper_bndldx32(cpu_bndu[reg], tcg_env, s->A0, s->T0);
                    tcg_gen_ext32u_i64(cpu_bndl[reg], cpu_bndu[reg]);
                    tcg_gen_shri_i64(cpu_bndu[reg], cpu_bndu[reg], 32);
                }
                gen_set_hflag(s, HF_MPX_IU_MASK);
            }
        }
        break;
    case 0x11b:
        if (s->flags & HF_MPX_EN_MASK) {
            mod = (modrm >> 6) & 3;
            reg = ((modrm >> 3) & 7) | REX_R(s);
            if (mod != 3 && (prefixes & PREFIX_REPZ)) {
                /* bndmk */
                if (reg >= 4
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                AddressParts a = decode->mem;
                if (a.base >= 0) {
                    tcg_gen_extu_tl_i64(cpu_bndl[reg], cpu_regs[a.base]);
                    if (!CODE64(s)) {
                        tcg_gen_ext32u_i64(cpu_bndl[reg], cpu_bndl[reg]);
                    }
                } else if (a.base == -1) {
                    /* no base register has lower bound of 0 */
                    tcg_gen_movi_i64(cpu_bndl[reg], 0);
                } else {
                    /* rip-relative generates #ud */
                    goto illegal_op;
                }
                tcg_gen_not_tl(s->A0, gen_lea_modrm_1(s, decode->mem, false));
                if (!CODE64(s)) {
                    tcg_gen_ext32u_tl(s->A0, s->A0);
                }
                tcg_gen_extu_tl_i64(cpu_bndu[reg], s->A0);
                /* bnd registers are now in-use */
                gen_set_hflag(s, HF_MPX_IU_MASK);
                break;
            } else if (prefixes & PREFIX_REPNZ) {
                /* bndcn */
                if (reg >= 4
                    || s->aflag == MO_16) {
                    goto illegal_op;
                }
                gen_bndck(s, decode, TCG_COND_GTU, cpu_bndu[reg]);
            } else if (prefixes & PREFIX_DATA) {
                /* bndmov -- to reg/mem */
                if (reg >= 4 || s->aflag == MO_16) {
                    goto illegal_op;
                }
                if (mod == 3) {
                    int reg2 = (modrm & 7) | REX_B(s);
                    if (reg2 >= 4) {
                        goto illegal_op;
                    }
                    if (s->flags & HF_MPX_IU_MASK) {
                        tcg_gen_mov_i64(cpu_bndl[reg2], cpu_bndl[reg]);
                        tcg_gen_mov_i64(cpu_bndu[reg2], cpu_bndu[reg]);
                    }
                } else {
                    gen_lea_modrm(s, decode);
                    if (CODE64(s)) {
                        tcg_gen_qemu_st_i64(cpu_bndl[reg], s->A0,
                                            s->mem_index, MO_LEUQ);
                        tcg_gen_addi_tl(s->A0, s->A0, 8);
                        tcg_gen_qemu_st_i64(cpu_bndu[reg], s->A0,
                                            s->mem_index, MO_LEUQ);
                    } else {
                        tcg_gen_qemu_st_i64(cpu_bndl[reg], s->A0,
                                            s->mem_index, MO_LEUL);
                        tcg_gen_addi_tl(s->A0, s->A0, 4);
                        tcg_gen_qemu_st_i64(cpu_bndu[reg], s->A0,
                                            s->mem_index, MO_LEUL);
                    }
                }
            } else if (mod != 3) {
                /* bndstx */
                AddressParts a = decode->mem;
                if (reg >= 4
                    || s->aflag == MO_16
                    || a.base < -1) {
                    goto illegal_op;
                }
                if (a.base >= 0) {
                    tcg_gen_addi_tl(s->A0, cpu_regs[a.base], a.disp);
                } else {
                    tcg_gen_movi_tl(s->A0, 0);
                }
                gen_lea_v_seg(s, s->A0, a.def_seg, s->override);
                if (a.index >= 0) {
                    tcg_gen_mov_tl(s->T0, cpu_regs[a.index]);
                } else {
                    tcg_gen_movi_tl(s->T0, 0);
                }
                if (CODE64(s)) {
                    gen_helper_bndstx64(tcg_env, s->A0, s->T0,
                                        cpu_bndl[reg], cpu_bndu[reg]);
                } else {
                    gen_helper_bndstx32(tcg_env, s->A0, s->T0,
                                        cpu_bndl[reg], cpu_bndu[reg]);
                }
            }
        }
        break;
    default:
        g_assert_not_reached();
    }
    return;
 illegal_op:
    gen_illegal_opcode(s);
    return;
}

#include "decode-new.c.inc"

void tcg_x86_init(void)
{
    /*
     * The helper-usage table, installed once beside the TCG globals: the
     * reader consults it when a helper argument is a pointer into env, and
     * the join refuses a table that does not account for every such helper.
     */
    x86_insn_df_declare_helper_usage();

    /*
     * The register files that live in CPUArchState and no TCG global names.
     *
     * x86's vector and x87 state is reached by load and store at an offset
     * into env, so the op stream shows a byte range and not a register.  A
     * consumer handed that range can say an instruction touched SOMETHING at
     * offset 1056 and nothing more; with these declared it is handed "xmm0",
     * which is what the range means.  The offsets and extents come from the
     * compiler over this target's own structure, so they cannot drift from it.
     *
     * The declaration names the CONTAINER: a 4-byte read out of a 64-byte ZMM
     * is still that register, which is how a consumer sees one register and
     * not sixteen unrelated ranges.
     */
    {
        static const char *const k_p[] = {
            "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7",
        };
        CPUX86State *e = NULL;

        QEMU_BUILD_BUG_ON(ARRAY_SIZE(x86_xmm_names) < ARRAY_SIZE(e->xmm_regs));
        QEMU_BUILD_BUG_ON(ARRAY_SIZE(x86_x87_st_names) !=
                          ARRAY_SIZE(e->fpregs));
        QEMU_BUILD_BUG_ON(ARRAY_SIZE(k_p) != ARRAY_SIZE(e->opmask_regs));

        insn_dataflow_declare_regfile(x86_xmm_names, ARRAY_SIZE(e->xmm_regs),
                                      offsetof(CPUX86State, xmm_regs),
                                      sizeof(e->xmm_regs[0]),
                                      sizeof(e->xmm_regs[0]));
        insn_dataflow_declare_regfile(x86_x87_st_names,
                                      ARRAY_SIZE(e->fpregs),
                                      offsetof(CPUX86State, fpregs),
                                      sizeof(e->fpregs[0]),
                                      sizeof(e->fpregs[0]));
        insn_dataflow_declare_regfile(k_p, ARRAY_SIZE(e->opmask_regs),
                                      offsetof(CPUX86State, opmask_regs),
                                      sizeof(e->opmask_regs[0]),
                                      sizeof(e->opmask_regs[0]));
    }

    /*
     * The rest of the x87 state, which no TCG global names either.
     *
     * The data file above is only half of what an x87 instruction touches.
     * The other half is the control word it reads its exception masks and
     * rounding mode from, the status word it accumulates exception flags and
     * condition codes into, the tag word a push validates and a pop
     * invalidates, the top-of-stack pointer every stack reference is indexed
     * through, and the four exception pointers QEMU's own emitted epilogue
     * stores at the end of nearly every x87 instruction.  Undeclared, each of
     * those reaches a consumer as an anonymous byte range, and an instruction
     * that plainly writes the status word publishes "two bytes at offset
     * 6320" instead.
     *
     * fptags is eight bytes in QEMU and ONE register in the architecture --
     * FTW, two bits per stack slot -- so it is declared as the one register
     * it is rather than as a file of eight.  Declaring eight would invite a
     * decode site to name one of them, and which slot an x87 instruction
     * tags is a function of fpstt at execution, which no decode site holds.
     *
     * fpstt is likewise architecturally a FIELD of the status word (FSW bits
     * 13:11, which is exactly how helper_fnstsw() reassembles it) that QEMU
     * keeps in its own word.  It gets its own NAME because QEMU moves the two
     * independently and a statement about one should not read as a statement
     * about the other; what a consumer sees is a separate question, and the
     * generic map folds both onto the FP control-and-status register the way
     * it folds every other single-ISA register onto an existing one.
     */
    {
        CPUX86State *e = NULL;

        insn_dataflow_declare_regfile(x86_x87_fpstt_names, 1,
                                      offsetof(CPUX86State, fpstt),
                                      sizeof(e->fpstt), sizeof(e->fpstt));
        insn_dataflow_declare_regfile(x86_x87_fpus_names, 1,
                                      offsetof(CPUX86State, fpus),
                                      sizeof(e->fpus), sizeof(e->fpus));
        insn_dataflow_declare_regfile(x86_x87_fpuc_names, 1,
                                      offsetof(CPUX86State, fpuc),
                                      sizeof(e->fpuc), sizeof(e->fpuc));
        insn_dataflow_declare_regfile(x86_x87_fptag_names, 1,
                                      offsetof(CPUX86State, fptags),
                                      sizeof(e->fptags), sizeof(e->fptags));
        insn_dataflow_declare_regfile(x86_x87_fpip_names, 1,
                                      offsetof(CPUX86State, fpip),
                                      sizeof(e->fpip), sizeof(e->fpip));
        insn_dataflow_declare_regfile(x86_x87_fpcs_names, 1,
                                      offsetof(CPUX86State, fpcs),
                                      sizeof(e->fpcs), sizeof(e->fpcs));
        insn_dataflow_declare_regfile(x86_x87_fpdp_names, 1,
                                      offsetof(CPUX86State, fpdp),
                                      sizeof(e->fpdp), sizeof(e->fpdp));
        insn_dataflow_declare_regfile(x86_x87_fpds_names, 1,
                                      offsetof(CPUX86State, fpds),
                                      sizeof(e->fpds), sizeof(e->fpds));
    }

    /*
     * Two architectural registers that are neither a TCG global nor part of a
     * file: the flags word the lazy-flags scheme does not represent, and the
     * direction flag the string operations read.
     *
     * Both are reached by an ordinary load or store at a fixed offset into
     * env -- gen_read_eflags()/gen_write_eflags() for the first,
     * gen_compute_dshift() and the CLD/STD emitters for the second -- so the
     * op-stream reader records a byte range and a consumer is handed "four
     * bytes at offset 1234" for the D flag.  They are registers, and a
     * consumer should be told so.
     *
     * A single register is a file of ONE, which is the shape declared here
     * rather than a second primitive: the containment rule the resolver
     * already uses (an access wholly inside one entry names that entry) is
     * exactly right for a scalar, and count == 1 with stride == size makes
     * the arithmetic degenerate to that case.  The earlier reading -- that
     * declare_regfile could not express a scalar -- was checked here and is
     * wrong; what it could not express is an entry whose stride differs from
     * its size, which neither of these has.
     *
     * eflags is a target_ulong and df an int32_t, and the extents come from
     * the compiler for the same reason the files above do.
     */
    {
        static const char *const eflags_p[] = { "eflags" };
        static const char *const df_p[] = { "df" };
        CPUX86State *e = NULL;

        insn_dataflow_declare_regfile(eflags_p, 1,
                                      offsetof(CPUX86State, eflags),
                                      sizeof(e->eflags), sizeof(e->eflags));
        insn_dataflow_declare_regfile(df_p, 1, offsetof(CPUX86State, df),
                                      sizeof(e->df), sizeof(e->df));
    }

    static const char bnd_regl_names[4][8] = {
        "bnd0_lb", "bnd1_lb", "bnd2_lb", "bnd3_lb"
    };
    static const char bnd_regu_names[4][8] = {
        "bnd0_ub", "bnd1_ub", "bnd2_ub", "bnd3_ub"
    };
    int i;

    cpu_cc_op = tcg_global_mem_new_i32(tcg_env,
                                       offsetof(CPUX86State, cc_op), "cc_op");
    cpu_cc_dst = tcg_global_mem_new(tcg_env, offsetof(CPUX86State, cc_dst),
                                    "cc_dst");
    cpu_cc_src = tcg_global_mem_new(tcg_env, offsetof(CPUX86State, cc_src),
                                    "cc_src");
    cpu_cc_src2 = tcg_global_mem_new(tcg_env, offsetof(CPUX86State, cc_src2),
                                     "cc_src2");
    cpu_eip = tcg_global_mem_new(tcg_env, offsetof(CPUX86State, eip),
                                 X86_DF_PC_NAME);

    for (i = 0; i < CPU_NB_REGS; ++i) {
        cpu_regs[i] = tcg_global_mem_new(tcg_env,
                                         offsetof(CPUX86State, regs[i]),
                                         x86_reg_names[i]);
    }

    for (i = 0; i < 6; ++i) {
        cpu_seg_base[i]
            = tcg_global_mem_new(tcg_env,
                                 offsetof(CPUX86State, segs[i].base),
                                 seg_base_names[i]);
    }

    for (i = 0; i < 4; ++i) {
        cpu_bndl[i]
            = tcg_global_mem_new_i64(tcg_env,
                                     offsetof(CPUX86State, bnd_regs[i].lb),
                                     bnd_regl_names[i]);
        cpu_bndu[i]
            = tcg_global_mem_new_i64(tcg_env,
                                     offsetof(CPUX86State, bnd_regs[i].ub),
                                     bnd_regu_names[i]);
    }
}

static void i386_tr_init_disas_context(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    CPUX86State *env = cpu_env(cpu);
    uint32_t flags = dc->base.tb->flags;
    uint32_t cflags = tb_cflags(dc->base.tb);
    int cpl = (flags >> HF_CPL_SHIFT) & 3;
    int iopl = (flags >> IOPL_SHIFT) & 3;

    dc->cs_base = dc->base.tb->cs_base;
    dc->pc_save = dc->base.pc_next;
    dc->flags = flags;
#ifndef CONFIG_USER_ONLY
    dc->cpl = cpl;
    dc->iopl = iopl;
#endif

    /* We make some simplifying assumptions; validate they're correct. */
    g_assert(PE(dc) == ((flags & HF_PE_MASK) != 0));
    g_assert(CPL(dc) == cpl);
    g_assert(IOPL(dc) == iopl);
    g_assert(VM86(dc) == ((flags & HF_VM_MASK) != 0));
    g_assert(CODE32(dc) == ((flags & HF_CS32_MASK) != 0));
    g_assert(CODE64(dc) == ((flags & HF_CS64_MASK) != 0));
    g_assert(SS32(dc) == ((flags & HF_SS32_MASK) != 0));
    g_assert(LMA(dc) == ((flags & HF_LMA_MASK) != 0));
    g_assert(ADDSEG(dc) == ((flags & HF_ADDSEG_MASK) != 0));
    g_assert(SVME(dc) == ((flags & HF_SVME_MASK) != 0));
    g_assert(GUEST(dc) == ((flags & HF_GUEST_MASK) != 0));

    dc->cc_op = CC_OP_DYNAMIC;
    dc->cc_op_dirty = false;
    /* select memory access functions */
    dc->mem_index = cpu_mmu_index(cpu, false);
    dc->cpuid_features = env->features[FEAT_1_EDX];
    dc->cpuid_ext_features = env->features[FEAT_1_ECX];
    dc->cpuid_ext2_features = env->features[FEAT_8000_0001_EDX];
    dc->cpuid_ext3_features = env->features[FEAT_8000_0001_ECX];
    dc->cpuid_7_0_ebx_features = env->features[FEAT_7_0_EBX];
    dc->cpuid_7_0_ecx_features = env->features[FEAT_7_0_ECX];
    dc->cpuid_7_1_eax_features = env->features[FEAT_7_1_EAX];
    dc->cpuid_xsave_features = env->features[FEAT_XSAVE];
    dc->jmp_opt = !((cflags & CF_NO_GOTO_TB) ||
                    (flags & (HF_RF_MASK | HF_TF_MASK | HF_INHIBIT_IRQ_MASK)));

    dc->T0 = tcg_temp_new();
    dc->T1 = tcg_temp_new();
    dc->A0 = tcg_temp_new();

    dc->tmp0 = tcg_temp_new();
    dc->tmp1_i64 = tcg_temp_new_i64();
    dc->tmp2_i32 = tcg_temp_new_i32();
    dc->tmp3_i32 = tcg_temp_new_i32();
    dc->tmp4 = tcg_temp_new();
    dc->cc_srcT = tcg_temp_new();
}

static void i386_tr_tb_start(DisasContextBase *db, CPUState *cpu)
{
}

static void i386_tr_insn_start(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    target_ulong pc_arg = dc->base.pc_next;

    /* Plugin R_REGS callbacks fire next; flush deferred cc_op so
     * env->cc_op reflects the prior insn's ALU op (cpu_compute_eflags
     * dispatches on it). */
    if (dcbase->plugin_enabled) {
        gen_update_cc_op(dc);
    }

    dc->prev_insn_start = dc->base.insn_start;
    dc->prev_insn_end = tcg_last_op();
    if (tb_cflags(dcbase->tb) & CF_PCREL) {
        pc_arg &= ~TARGET_PAGE_MASK;
    }
    tcg_gen_insn_start(pc_arg, dc->cc_op);
}

static void i386_tr_translate_insn(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);
    bool orig_cc_op_dirty = dc->cc_op_dirty;
    CCOp orig_cc_op = dc->cc_op;
    target_ulong orig_pc_save = dc->pc_save;

#ifdef TARGET_VSYSCALL_PAGE
    /*
     * Detect entry into the vsyscall page and invoke the syscall.
     */
    if ((dc->base.pc_next & TARGET_PAGE_MASK) == TARGET_VSYSCALL_PAGE) {
        gen_exception(dc, EXCP_VSYSCALL);
        dc->base.pc_next = dc->pc + 1;
        return;
    }
#endif

    switch (sigsetjmp(dc->jmpbuf, 0)) {
    case 0:
        disas_insn(dc, cpu);
        break;
    case 1:
        gen_exception_gpf(dc);
        break;
    case 2:
        /* Restore state that may affect the next instruction. */
        dc->pc = dc->base.pc_next;
        assert(dc->cc_op_dirty == orig_cc_op_dirty);
        assert(dc->cc_op == orig_cc_op);
        assert(dc->pc_save == orig_pc_save);
        dc->base.num_insns--;
        tcg_remove_ops_after(dc->prev_insn_end);
        dc->base.insn_start = dc->prev_insn_start;
        dc->base.is_jmp = DISAS_TOO_MANY;
        return;
    default:
        g_assert_not_reached();
    }

    /*
     * Instruction decoding completed (possibly with #GP if the
     * 15-byte boundary was exceeded).
     */
    dc->base.pc_next = dc->pc;
    if (dc->base.is_jmp == DISAS_NEXT) {
        if (dc->flags & (HF_TF_MASK | HF_INHIBIT_IRQ_MASK)) {
            /*
             * If single step mode, we generate only one instruction and
             * generate an exception.
             * If irq were inhibited with HF_INHIBIT_IRQ_MASK, we clear
             * the flag and abort the translation to give the irqs a
             * chance to happen.
             */
            dc->base.is_jmp = DISAS_EOB_NEXT;
        } else if (!translator_is_same_page(&dc->base, dc->base.pc_next)) {
            dc->base.is_jmp = DISAS_TOO_MANY;
        }
    }
}

static void i386_tr_tb_stop(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);

    switch (dc->base.is_jmp) {
    case DISAS_NORETURN:
        /*
         * Most instructions should not use DISAS_NORETURN, as that suppresses
         * the handling of hflags normally done by gen_eob().  We can
         * get here:
         * - for exception and interrupts
         * - for jump optimization (which is disabled by INHIBIT_IRQ/RF/TF)
         * - for VMRUN because RF/TF handling for the host is done after vmexit,
         *   and INHIBIT_IRQ is loaded from the VMCB
         * - for HLT/PAUSE/MWAIT to exit the main loop with specific EXCP_* values;
         *   the helpers handle themselves the tasks normally done by gen_eob().
         */
        break;
    case DISAS_TOO_MANY:
        /*
         * The block ran out and this is the jump-to-the-next-instruction
         * QEMU emits for that.  Every op of it belongs to the BLOCK: the EIP
         * it writes is the address after the last instruction translated,
         * which no instruction here produces as a result.  Attributed where
         * it is emitted it lands on whichever encoding happens to sit last,
         * and the same encoding one slot earlier in the block publishes no
         * such write -- which is the defect this window exists to close.
         *
         * gen_update_cc_op() is OUTSIDE it on purpose.  That is the DEFERRED
         * SPILL of a flags-state change some instruction in this block really
         * made; lazy flags is why it is late, not why it is fictional, and
         * swallowing the store would delete a real write.
         */
        gen_update_cc_op(dc);
        insn_dataflow_window_begin(INSN_DF_W_EPILOGUE);
        gen_jmp_rel_csize(dc, 0, 0);
        insn_dataflow_window_end();
        break;
    case DISAS_EOB_NEXT:
    case DISAS_EOB_INHIBIT_IRQ:
        assert(dc->base.pc_next == dc->pc);
        /*
         * Only the EIP write is the block's.  gen_eob() below is not: it
         * resets RF, maintains the interrupt shadow and raises the
         * single-step trap, and those are effects of the instruction that
         * asked for the block to end.
         */
        insn_dataflow_window_begin(INSN_DF_W_EPILOGUE);
        gen_update_eip_cur(dc);
        insn_dataflow_window_end();
        /* fall through */
    case DISAS_EOB_ONLY:
    case DISAS_EOB_RECHECK_TF:
    case DISAS_JUMP:
        gen_eob(dc, dc->base.is_jmp);
        break;
    default:
        g_assert_not_reached();
    }
}

/*
 * v4 repair (maintainer-vetoable): never-split RETREAT re-sync.  The
 * generic loop is ending the TB at @retreat_pc, dropping the sequence-
 * prefix insns translated beyond it (immediate moves: they never sync
 * EIP, so pc_save is stable, and they never touch the flags, so cc_op
 * is unchanged).  Re-sync the private decode pc, and conservatively
 * re-arm the cc_op spill: the first dropped insn's insn_start may have
 * flushed cc_op and its (now dropped) spill op with it.  A redundant
 * re-spill of an already-clean cc_op stores the same value again —
 * harmless.  CC_OP_DYNAMIC must never be marked dirty.
 */
static bool i386_tr_nosplit_retreat(DisasContextBase *dcbase, CPUState *cpu,
                                    vaddr retreat_pc, uint64_t checkpoint)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);

    dc->pc = retreat_pc;
    if (dc->cc_op != CC_OP_DYNAMIC) {
        dc->cc_op_dirty = true;
    }
    return true;
}

static const TranslatorOps i386_tr_ops = {
    .init_disas_context = i386_tr_init_disas_context,
    .tb_start           = i386_tr_tb_start,
    .insn_start         = i386_tr_insn_start,
    .translate_insn     = i386_tr_translate_insn,
    .tb_stop            = i386_tr_tb_stop,
    .nosplit_retreat    = i386_tr_nosplit_retreat,
};

void x86_translate_code(CPUState *cpu, TranslationBlock *tb,
                        int *max_insns, vaddr pc, void *host_pc)
{
    DisasContext dc;

    translator_loop(cpu, tb, max_insns, pc, host_pc, &i386_tr_ops, &dc.base);
}
