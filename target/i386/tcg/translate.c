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
/*
 * The deposit just emitted read @bg only to carry the bits it did not write.
 *
 * R7.1: a narrow write does not make the enclosing register a source, and
 * this is the emitter that performs every one of x86's narrow writes -- the
 * background operand is here because the register file is 64 bits wide and
 * `setne %al` is 8, not because the instruction named RAX.  Where the
 * instruction DOES name it -- `add %al,%bl` -- the operand was fetched by a
 * different op through gen_op_mov_v_reg(), and the note, which is keyed on
 * the consuming op, leaves that read alone.
 *
 * Stated only for the IN-PLACE form.  When a caller passes its own @dest the
 * preserved bits travel into a temp that may become a different
 * architectural register, and there the dependency is real.
 */
static void gen_note_deposit_preserve(TCGv dest, TCGv bg, const void *mark)
{
    if (dest == bg) {
        insn_dataflow_note_preserve_read(tcgv_tl_temp(bg), mark);
    }
}

static TCGv gen_op_deposit_reg_v(DisasContext *s, MemOp ot, int reg, TCGv dest, TCGv t0)
{
    const void *mark = insn_dataflow_mark();

    switch(ot) {
    case MO_8:
        if (byte_reg_is_xH(s, reg)) {
            dest = dest ? dest : cpu_regs[reg - 4];
            tcg_gen_deposit_tl(dest, cpu_regs[reg - 4], t0, 8, 8);
            gen_note_deposit_preserve(dest, cpu_regs[reg - 4], mark);
            return cpu_regs[reg - 4];
        }
        dest = dest ? dest : cpu_regs[reg];
        tcg_gen_deposit_tl(dest, cpu_regs[reg], t0, 0, 8);
        gen_note_deposit_preserve(dest, cpu_regs[reg], mark);
        break;
    case MO_16:
        dest = dest ? dest : cpu_regs[reg];
        tcg_gen_deposit_tl(dest, cpu_regs[reg], t0, 0, 16);
        gen_note_deposit_preserve(dest, cpu_regs[reg], mark);
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
     * The value is the instruction pointer plus this instruction's length,
     * whichever of the three ways above produced it.  gen_CALL and gen_CALL_m
     * push it, so it reaches the wire as a store's data operand, and the two
     * constant arms read as a value that came from nowhere -- which the
     * format's store-data block spells "the instruction's immediate".  Say
     * where it came from instead.  Stated in the CF_PCREL arm too, where the
     * add above already carries the read: that costs one deduplicated list
     * entry and makes the regimes identical by construction.
     * Capture only; no op is emitted, altered or suppressed.
     */
    insn_dataflow_note_folded_reg(tcgv_tl_temp(ret), tcgv_tl_temp(cpu_eip));
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
/*
 * WHICH SEGMENT'S BASE AN ADDRESS COMPUTATION ADDS, or -1 for none.
 *
 * Split out of gen_lea_v_seg_dest() below, which used to decide it inline,
 * because a second caller has to ask the identical question about an access
 * it never emitted: io_operands.c.inc states the segment read of an `outs`
 * whose body gen_check_io() refused, and a copy of this rule there would be
 * a copy that goes stale the first time the addressing rules move.
 */
static int gen_lea_seg_of(DisasContext *s, MemOp aflag, int def_seg,
                          int ovr_seg)
{
    switch (aflag) {
#ifdef TARGET_X86_64
    case MO_64:
        return ovr_seg;
#endif
    case MO_32:
    case MO_16:
        return (ovr_seg < 0 && ADDSEG(s)) ? def_seg : ovr_seg;
    default:
        g_assert_not_reached();
    }
}

static void gen_lea_v_seg_dest(DisasContext *s, MemOp aflag, TCGv dest, TCGv a0,
                               int def_seg, int ovr_seg)
{
    ovr_seg = gen_lea_seg_of(s, aflag, def_seg, ovr_seg);

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
            return;
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

static void gen_movs(DisasContext *s, MemOp ot, TCGv dshift)
{
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

/*
 * THE FLAG AN INSTRUCTION READS THAT QEMU ALREADY KNOWS THE VALUE OF.
 *
 * The lazy-flag representation carries the OPERANDS of the last flag-setting
 * instruction rather than EFLAGS itself, so the arms below can answer a flag
 * query from s->cc_op alone: after a logic op CF and OF are architecturally
 * zero, after `popcnt` CF, OF and SF are, and gen_prepare_eflags_c/o/s hand
 * their caller TCG_COND_NEVER and emit nothing at all.  No op reads a global,
 * so a walk of the op stream finds no flag read, and `adcw` -- whose SDM
 * Operation is DEST <- DEST + SRC + CF -- reaches a consumer with no
 * REG_FLAGS in its source list while the very same instruction one cc_op
 * later has one.
 *
 * One architectural question with two answers depending on what the PREVIOUS
 * instruction was is the defect; R17 requires the source set to be invocation
 * invariant, R15 says QEMU resolving the question early is a lowering
 * decision and not architectural truth, and R16 records the dependency
 * regardless of the machine state that makes its value predictable.  So the
 * folded arms STATE the read the emitted arms perform.
 *
 * NOT THE ZERO-SHIFT CASE.  9075cbf1a1 removed a published flag from
 * `shl $0` because the ISA says a shift by an encoded zero touches no flag --
 * the instruction genuinely has no flag dependency there.  This is the
 * opposite shape: the dependency is in the instruction's own Operation
 * section and only its VALUE is known early, which R16 says is not a reason
 * to drop it.
 *
 * Stated under the GDB stub's name for the word, which is how the direction
 * flag's declaration already names EFLAGS on this target.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
static void gen_note_folded_eflags_read(void)
{
    insn_dataflow_note_stated_read_name("eflags");
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
        gen_note_folded_eflags_read();
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
        gen_note_folded_eflags_read();
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
        gen_note_folded_eflags_read();
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
    gen_string_movl_A0_EDI(s);
    gen_op_st_v(s, ot, s->T0, s->A0);
    gen_op_add_reg(s, s->aflag, R_EDI, dshift);
}

static void gen_lods(DisasContext *s, MemOp ot, TCGv dshift)
{
    gen_string_movl_A0_ESI(s);
    gen_op_ld_v(s, ot, s->T0, s->A0);
    gen_op_mov_reg_v(s, ot, R_EAX, s->T0);
    gen_op_add_reg(s, s->aflag, R_ESI, dshift);
}

static void gen_scas(DisasContext *s, MemOp ot, TCGv dshift)
{
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
    unsigned df_memop_mark = 0;

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
    /*
     * Where this iteration's accesses are noted.  With @can_loop the same
     * accesses are emitted a SECOND time below for the peeled last
     * iteration, and the two emissions are one architectural access on
     * mutually exclusive paths -- see insn_dataflow_note_path_alt().
     */
    df_memop_mark = insn_dataflow_memop_mark();
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
        /*
         * The peeled last iteration performs the SAME access the loop body
         * performs, on the path the loop body does not take.  Told, not
         * inferred: a per-emission count would give the instruction a memory
         * slot no execution ever fills.
         */
        insn_dataflow_note_path_alt(df_memop_mark);
        fn(s, ot, dshift);
        insn_dataflow_note_path_alt_end();
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
    /*
     * WHAT FOLLOWS IS NOT THE INSTRUCTION.  Every caller returns without
     * emitting a single op of the body -- `lgdt` never reaches its two
     * tcg_gen_st_tl()s, `lmsw` never reaches its helper -- so the
     * translation is a #GP raise with no read list and no architectural
     * write, which is exactly the shape `syscall` has and `syscall` is a
     * body.  The privilege that decided is not in the op stream either:
     * QEMU hoists CPL out of the guest state into DisasContext at
     * translation time, so nothing downstream can see the check happen.
     * Only this function knows, so this function says it.
     *
     * NOT a claim about the encoding in general: the same bytes at CPL 0
     * translate the body and this note is never taken.
     *
     * Capture only; no op is emitted, altered or suppressed.
     */
    insn_dataflow_note_translation_refused();
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
        }
        ea = s->A0;
        if (a.base == -2) {
            /*
             * RIP-relative, which is what base == -2 means and the only
             * thing it means: gen_lea_modrm_0() sets it where CODE64 and
             * mod == 0 and no SIB select the pc-relative form, and adds
             * s->pc + s->rip_offset into the displacement there.  So the
             * address the guest computes IS the instruction pointer plus a
             * constant, and the movi arm above hands on a value that reads
             * as having come from nowhere -- an address with no producer,
             * which is what an empty address mask on the wire says.  Say
             * where it came from instead.  Stated in the CF_PCREL arm too,
             * where the add already carries the read: that costs one
             * deduplicated list entry and makes the two regimes publish the
             * same set by construction rather than by coincidence.
             * Capture only; no op is emitted, altered or suppressed.
             */
            insn_dataflow_note_folded_reg(tcgv_tl_temp(ea),
                                          tcgv_tl_temp(cpu_eip));
        }
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
    plugin_gen_record_branch_target((uint64_t)(s->pc + diff));
    /*
     * The target is the INSTRUCTION POINTER plus a displacement the encoding
     * carries, which makes RIP a source operand of every Jcc, JCXZ and LOOPcc
     * in the program.  Without CF_PCREL, gen_jmp_rel() does that addition in C
     * and emits `movi cpu_eip, <constant>`: no op reads the register, no temp
     * stands for it, and a consumer asking what this instruction reads is told
     * nothing at all.  R7.3 rules that the register the encoding names is not
     * the emulator's to drop, so it is said here, where the pc-relative form is
     * known.  Stated in the CF_PCREL arm too, where the addition already
     * carries the read: one deduplicated list entry, and the two regimes
     * publish the same read set by construction.
     *
     * Here rather than inside gen_jmp_rel(), which is also the FALL-THROUGH
     * edge's emitter: naming RIP there would make it a source of whichever
     * instruction happened to end a translation block, a fabricated dependency
     * that moves with the block boundaries.
     * Capture only; no op is emitted, altered or suppressed.
     */
    insn_dataflow_note_folded_read(tcgv_tl_temp(cpu_eip));
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

/*
 * WHAT A FAR CALL READS TO PUSH WITH.
 *
 * A far call saves the current CS:(E)IP on the stack before it transfers, so
 * two registers it never names in its encoding are operands: the STACK
 * POINTER it stores through, and the PROGRAM COUNTER whose next value is the
 * return address being pushed.
 *
 * Neither reaches QEMU's ordered read list, and for two different reasons.
 * The stack pointer is read by helper_lcall_protected() / helper_lcall_real()
 * from inside a helper the extraction reports it cannot bound.  The program
 * counter is worse: eip_next_tl() resolves the return address at TRANSLATION
 * time into a CONSTANT, so by the time the helper runs there is no read of
 * cpu_eip left to see -- the same shape as AArch64's FP-enable gate, and the
 * same answer.  R15: the emulator working the value out early is a lowering
 * decision, not architectural truth.
 *
 * Measured on the encoding sled, `lcallq`, `lcalll` and `lcallw` all read
 * `RD = <the two address GPRs>` and nothing else, while the wire carried
 * REG_SP and REG_PC from the operand walk beside it -- 42,071 registers over
 * the CALLF_m rule.
 *
 * STATED IN gen_far_call() rather than at CALLF_m, because it is true of the
 * direct far call too; the register-indirect form is only where the loss was
 * measured.  gen_far_jmp() is NOT annotated: a far jump pushes nothing.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
static void gen_note_far_call_pushes(void)
{
    insn_dataflow_note_stated_read_env(
        offsetof(CPUX86State, regs[R_ESP]),
        sizeof(((CPUX86State *)0)->regs[R_ESP]));
    insn_dataflow_note_stated_read_env(
        offsetof(CPUX86State, eip),
        sizeof(((CPUX86State *)0)->eip));
}

/*
 * WHAT A RETURN READS TO POP WITH.
 *
 * `ret`, `lret` and `iret` all take their operands off the stack, and the
 * stack is addressed through SS.  Neither the near nor the far form reaches
 * QEMU's ordered read list with it:
 *
 *   - gen_lea_v_seg_dest() returns EARLY in 64-bit address mode without
 *     touching cpu_seg_base[R_SS], because SS.base is architecturally zero
 *     there and adding it would be a no-op.  That is a lowering decision --
 *     R15 -- and it removes the only op that named the segment.
 *   - helper_lret_protected() and the two iret helpers do the whole pop
 *     themselves, so the extraction reports the helper unbounded and the
 *     STACK POINTER goes with the segment; `lretl` reads RD = - and nothing
 *     else, while the wire carried REG_SP and REG_SEG5 from the operand walk
 *     beside it.
 *
 * 35,993 registers over the RET and RETF rules, plus 21,069 REG_SP on RETF.
 *
 * THE REFERENCE TABLES NAME EXACTLY THESE THREE.  Capstone's x86 mapping --
 * generated from LLVM -- gives `X86_RETQ` regs_use `{ RSP, SS }`, `X86_LRETQ`
 * `{ RSP, SS }` with `{ RSP, RIP, CS }` modified, and the same for the 16-
 * and 32-bit forms and for IRET; `X86_CALL64pcrel32`, `PUSH64r` and `POP64r`
 * carry no SS at all.  XED describes the same asymmetry from the other side,
 * as an SS-segmented memory operand on the returns.  That asymmetry is the
 * table's and it is NOT adjudicated here: a push writes through SS as surely
 * as a return reads through it, and this note deliberately does not extend to
 * the push and pop forms, because the loss it closes is on the returns and a
 * wire change that wide belongs to a measurement of its own.
 *
 * @far says whether the stack pointer goes with the segment.  The near
 * return's RSP is already in the read list -- gen_pop_T0() reads the global
 * -- so stating it there would add nothing; the far and interrupt returns
 * lose it inside the helper.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
/*
 * `lldt` AND `ltr` READ THE GDT TO RESOLVE THE SELECTOR THEY ARE GIVEN.
 *
 * The selector is an index into the global descriptor table, and both helpers
 * say so in one line -- `dt = &env->gdt` in helper_lldt() and helper_ltr()
 * (seg_helper.c) -- before they walk it and write env->ldt or env->tr.  The
 * read is inside the helper, so nothing in the op stream carries it; the wire
 * carried REG_SYSMMU from disas/capstone.c, which models the same two
 * instructions the same way and cites the same two lines.
 *
 * STATED BEFORE THE CPL TEST, not inside it.  `if (!PE(s) || VM86(s)) goto
 * illegal_op` is a DECODE refusal and the note sits after it; check_cpl0() is
 * a run-time privilege fault on an instruction that decoded as `lldt`, and
 * R17 says a conditional carries all its potential sources.  Placing the note
 * inside the CPL0 arm would make the fact true only of a kernel translation,
 * which is a statement about the guest's current privilege rather than about
 * the instruction.
 *
 * Only the GDT is stated.  The destination -- env->ldt or env->tr -- is a
 * WRITE, and the declarations above name it on that side.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
static void gen_note_gdt_read(void)
{
    insn_dataflow_note_stated_read_env(offsetof(CPUX86State, gdt.base),
                                       sizeof(((CPUX86State *)0)->gdt.base));
    insn_dataflow_note_stated_read_env(offsetof(CPUX86State, gdt.limit),
                                       sizeof(((CPUX86State *)0)->gdt.limit));
}

static void gen_note_return_pops(bool far)
{
    insn_dataflow_note_stated_read_env(
        offsetof(CPUX86State, segs[R_SS].selector),
        sizeof(((CPUX86State *)0)->segs[R_SS].selector));
    if (far) {
        insn_dataflow_note_stated_read_env(
            offsetof(CPUX86State, regs[R_ESP]),
            sizeof(((CPUX86State *)0)->regs[R_ESP]));
    }
}

static void gen_far_call(DisasContext *s)
{
    TCGv_i32 new_cs = tcg_temp_new_i32();

    gen_note_far_call_pushes();
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

/*
 * THE x87 CONTROL AND STATUS WORDS, stated for the instruction that reads
 * them.
 *
 * WHAT IS MISSING WITHOUT THIS.  FPCW decides how the x87 datapath rounds
 * (RC), to what precision (PC) and which exceptions are delivered rather
 * than defaulted (the mask bits); FPSW carries the stack top, the condition
 * codes and the sticky exception flags.  Neither is a TCG global and neither
 * is read by an op: every x87 instruction reaches them from inside a helper
 * that was handed nothing but `tcg_env`, so `helper_fadd_ST0_FT0()` reading
 * `env->fpuc` on its way into `floatx80_add()` leaves nothing at all in the
 * op stream.  Measured with the operand walk's read arm deleted, 199,166
 * encodings lose REG_FPCW and 131,791 lose REG_FCSR -- the largest single
 * class left on x86_64, and 62.6% of that target's whole remaining bar.
 *
 * WHY A RANGE.  Both words ARE their env fields, and both are declared:
 * `fctrl` over env->fpuc, `fstat` over env->fpus and env->fpstt (QEMU keeps
 * FPSW.TOP in a field of its own, and the declaration puts both under the one
 * architectural name).  So the range is the register and there is no second
 * spelling to keep in step -- the same reason
 * insn_dataflow_note_stated_read_env() exists.
 *
 * WHERE IT IS PLACED, and why nowhere earlier.  On the RETURNING path,
 * beside x87_ident_publish(), for the reason stated above that publish: every
 * refusal in gen_x87() jumps to illegal_op, so a note taken here describes a
 * decision the emulator TOOK.  A note at the head of the function would
 * describe one it merely considered, and would put the control word in the
 * read list of an encoding that never executes.
 *
 * WHICH INSTRUCTIONS READ WHICH, and why this is not "all of them".  The
 * classification below is the architecture's, checked against an external
 * table rather than read off this emulator: LLVM's x86 scheduling info --
 * which is where Capstone's regs_use comes from -- DISCRIMINATES exactly
 * where the SDM does.  `fld1` and `fldz` do not read FPCW and `fldl2t`,
 * `fldl2e`, `fldpi`, `fldlg2` and `fldln2` do, because 1.0 and 0.0 are
 * exactly representable and the five irrational constants are rounded per
 * RC.  `fldt` and `fstpt` do not, because m80 is the internal format and the
 * move is exact, while `flds`/`fstps` and every integer and BCD form convert
 * and therefore round.  `fld %st(i)`, `fxch`, `fst %st(i)`, `fchs`, `fabs`,
 * `fxam`, `ffree`, `fdecstp`, `fincstp` and `fcmovcc` do not, because none of
 * them computes a numeric result; their only tie to FPCW is the IM mask for a
 * stack fault, which is a delivery question and not a dataflow one.  A table
 * that draws those lines is evidence about the ISA; a table that blanketed
 * the x87 space would be evidence about nothing.
 *
 * FPSW is read wherever the instruction TOUCHES THE STACK, which is the
 * uniform fact its TOP field makes true: an ST(i) reference, a push and a pop
 * all resolve through TOP, so the word is a source of each of them.  The
 * exceptions are the four that do not go near the stack -- `fldcw` and
 * `fnstcw`, which name only the control word -- and the three that WRITE the
 * status word outright: `fnclex`, `fninit` and the environment restores
 * `fldenv` and `frstor`.  `fnstsw` reads it, `fnstenv` and `fnsave` read it
 * because they store it, and `fldcw` and `fldenv` do NOT read the control
 * word they load, whatever a MOD flag in a decoder table says about it.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
static void gen_note_fctrl_read(void)
{
    insn_dataflow_note_stated_read_env(offsetof(CPUX86State, fpuc),
                                       sizeof(((CPUX86State *)0)->fpuc));
}

static void gen_note_fstat_read(void)
{
    insn_dataflow_note_stated_read_env(offsetof(CPUX86State, fpus),
                                       sizeof(((CPUX86State *)0)->fpus));
    insn_dataflow_note_stated_read_env(offsetof(CPUX86State, fpstt),
                                       sizeof(((CPUX86State *)0)->fpstt));
}

#include "io_operands.c.inc"
#include "trap_operands.c.inc"
#include "emit.c.inc"

/*
 * THE x87 ESCAPE SPACE HAS EIGHT DECODE-TABLE ROWS AND OVER A HUNDRED
 * INSTRUCTIONS.
 *
 * decode-new.c.inc gives each of 0xD8..0xDF one X86_OP_ENTRY row, and the
 * identity plugin_gen_record_insn_identity() publishes for it is that
 * row's __LINE__.  gen_x87() then dispatches on the modrm byte itself, so
 * one identity answers for every instruction under an escape byte, and a
 * consumer that learns what the rule decodes to from watching it decode
 * learns whichever instruction it happened to see: the 0xD8 row was
 * observed with an `fadds` and thereafter named an addition for `fdivs`
 * too.  The discriminator never reaches the decode table, so no amount of
 * further observation can settle it.
 *
 * scripts/x86_x87_ident_instrument.py states the finer identity, reading
 * the switches below and emitting one row per dispatch leaf into
 * x87_ident.c.inc, named by the fixed (opcode, modrm) bits that select it.
 * The eight escape rows keep their own ids and their name; an encoding
 * gen_x87 refuses publishes nothing and leaves the escape row's identity
 * exactly as it was.
 *
 * The publish sits on the RETURNING path, not at the point the leaf is
 * chosen: the CR0.EM/TS arm returns before any decode happens, and every
 * refusal jumps to illegal_op past it, so what is published is a decision
 * the emulator took rather than one it considered.
 */
#include "x87_ident.c.inc"

/*
 * ST(0), THE TOP OF THE x87 STACK, stated by name.
 *
 * Every x87 instruction that touches the stack reaches it through a helper
 * taking the WHOLE `fpregs` array, so what the extraction sees is the
 * CONTAINER -- off=fpregs size=128 -- and nothing about which element.  The
 * file is declared as one register for exactly that reason (see the note
 * above its declaration): env->fpregs is indexed by PHYSICAL register while
 * ST(i) is relative to env->fpstt, so no offset names an ST(i) without a
 * run-time top, and an element declaration would be a lie about the layout.
 *
 * Under the composed-register contract a stated container JUSTIFIES a
 * published member and supplies nothing -- which leaves ST(0) on the wire
 * only for as long as something else puts it there.  Measured: with the
 * operand walk's read arm deleted, `fxam`, `fstp`, `fstpt` and `fucomi` all
 * lose REG_FPR0 while the census still reads the read as justified, because
 * the justification is the container's and the register is the walk's.
 *
 * So the MEMBER is stated.  ST(0) is not the run-time question ST(i) is: it
 * is the stack top by definition, the implicit operand of every arm below,
 * and `st0` is the GDB stub's own spelling for it -- the namespace
 * insn_dataflow_reg_name() answers in and the one REG_FPR0 is keyed on.
 * R7.3 and R15, by the route 48b8579a3f took for the MIPS condition-code
 * bit: the emulator keeping a member inside a container is a storage
 * decision, not an architectural one.
 *
 * PLACED AT THE HELPER CALLS THAT READ THE TOP, not once per instruction and
 * not at the head of gen_x87().  The class is not "every x87 instruction":
 * `flds`, `fldl`, `fildl`, `fldt`, `fbld` and `fld sti` PUSH -- they write
 * the new top and touch the old one only as stack discipline, never as an
 * operand -- and `ffree`, `fnstsw`, `fldcw`, `fnstcw`, `fldenv`, `fnstenv`,
 * `frstor` and `fnsave` do not read an element at all.  Stating ST(0) for
 * any of those would fabricate a source, which is the failure this line of
 * work exists to stop, so the note sits beside the read itself and each site
 * is one helper whose name says which operand it takes.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
/* The GDB stub's own top-relative spelling, shared by both directions. */
static const char *const st_names[8] = {
    "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
};

static void gen_note_st0_read(void)
{
    insn_dataflow_note_stated_read_name("st0");
}

/*
 * ST(i), THE STACK OPERAND THE ENCODING NAMES.
 *
 * The block above states ST(0), the implicit operand.  This states the
 * EXPLICIT one, and it is the same fact for the same reason: the helper is
 * handed the whole `fpregs` array, the extraction sees the container, and a
 * stated container justifies a published member without supplying one.
 * Measured with the operand walk's read arm deleted, `faddp`, `fcmovb`,
 * `fxch`, `fucomi`, `fcompp` and the register-operand arithmetic all lose
 * their REG_FPR<i> -- 34,464 registers over the class.
 *
 * WHY A NAME AND NOT A RANGE, again.  env->fpregs is indexed by PHYSICAL
 * register and ST(i) is relative to env->fpstt, so no offset names an ST(i);
 * the file's declaration says exactly that.  But `st<i>` IS the name -- the
 * GDB stub answers st<n> by reading env->fpregs[(env->fpstt + n) & 7], so
 * the stub's spelling is TOP-relative in precisely the way the encoding's
 * ST(i) is, and @i here is the ModRM r/m field the instruction carries.
 *
 * PLACED AT THE HELPER CALLS THAT TAKE THE INDEX, never once per
 * instruction.  `ffree %st(i)` and `ffreep %st(i)` are NOT annotated: they
 * mark the tag word empty and never look at the value, so ST(i) is not a
 * source of theirs and stating it would fabricate.  `fld %st(i)` IS
 * annotated, and the index stated is the ENCODING'S: QEMU pushes before the
 * move and hands the helper (i + 1), which is the same register under the
 * adjustment the instruction itself makes.  See gen_note_sti_write() for
 * the frame rule that settles it.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
static void gen_note_sti_read(int i)
{
    insn_dataflow_note_stated_read_name(st_names[i & 7]);
}

/*
 * THE SAME TWO REGISTERS ON THE WRITE SIDE.
 *
 * The two blocks above state x87 SOURCES.  These state DESTINATIONS, and
 * they exist because the destination was missing outright: every x87
 * instruction that writes the stack does it inside a helper handed
 * `tcg_env`, so what the extraction sees is a store into the 128-byte
 * `fpregs` CONTAINER and nothing about which element.  `fpregs` is declared
 * as one register (see its declaration) and a stated container justifies a
 * published member without supplying one, so QEMU's write list carried no
 * ST(i) at all.  Measured at exec104: 13,788 x86_64 registers reach the
 * destination bar as REG_FPR0 that the operand walk supplies and QEMU does
 * not state, led by `fldt` at 5,474 -- the largest single row on that side.
 *
 * WHY A NAME AND NOT A RANGE, unchanged from the read side: env->fpregs is
 * indexed by PHYSICAL register, ST(i) is relative to env->fpstt, and `st<n>`
 * is the GDB stub's own top-relative spelling.
 *
 * WHICH FRAME THE NAME IS IN, which is the whole of the rule.
 *
 * A top-relative name is only a name once you say WHEN it is read.  An
 * earlier form of these notes answered "in the architectural POST-state",
 * and that answer made every form which adjusts the stack unstatable:
 * `fstp %st(i)` writes the register the encoding calls ST(i) and then pops,
 * so in the post-state those bytes are ST(i-1); `faddp` has the same shape;
 * `fptan`, `fsincos` and `fxtract` write ST(0) and then push.  Eight
 * families and 2,256 registers stayed off QEMU's write side for want of a
 * frame, while the ENCODING named the destination unambiguously the whole
 * time.
 *
 * THE FRAME IS THE INSTRUCTION'S OWN SDM PAGE.  Every name published for an
 * instruction -- source and destination alike -- is the name that
 * instruction's own operation section uses, evaluated before the stack
 * adjustment that same section describes.  `fstp %st(i)` states `st<i>`
 * because its page says "ST(i) <- ST(0); pop"; `fyl2x` states `st1` because
 * its page says "ST(1) <- ST(1) * log2 ST(0); pop"; `fld %st(i)` states
 * `st<i>` as a SOURCE because its page says "push ST(i)".  Nothing is
 * derived and nothing depends on a runtime TOP: the name is a static
 * property of the encoding, which is what R20 requires of a decode-site
 * statement.
 *
 * THE CONSUMER RESOLVES THE FRAMES, and it already has everything it needs
 * to: the stack adjustment each x87 instruction makes is a static property
 * of its opcode, so a consumer walking the body stream in PROGRAM ORDER
 * tracks TOP across the strand and reads each instruction's names in the
 * frame that instruction established.  That is the same shape R21 settles
 * for the other per-instruction frame in this format, and format.rst carries
 * the join.
 *
 * SO EVERY ARM THAT WRITES A DATA REGISTER IS ANNOTATED, and the classes
 * that are not are the ones that write no data register at all: `fcom`,
 * `fcomp`, `fucom`, `fcomi`, `ftst` and `fxam` produce flags; `ffree` marks
 * a tag word and never touches the value; `fdecstp` and `fincstp` move TOP
 * and nothing else; `fldenv`, `fldcw`, `fclex` and `fninit` name the
 * environment.  `frstor` writes all eight and is stated as all eight -- the
 * one arm whose answer needs no frame, because {st0..st7} is closed under
 * the rotation.
 *
 * The classification is the architecture's, taken from the SDM's own
 * destination column, and it is checked against the read side's: an arm that
 * states a read of ST(0) and no write is a compare or a store, and every one
 * of them is named above.
 *
 * NO PROVENANCE, on the primitive's contract: the note says the write
 * happened and which register it landed in.  What fed it is the
 * instruction's source list, which the two blocks above already fill.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
static void gen_note_st0_write(void)
{
    insn_dataflow_note_stated_write_name("st0");
}

static void gen_note_sti_write(int i)
{
    insn_dataflow_note_stated_write_name(st_names[i & 7]);
}

/*
 * THE SHIFTED FORMS -- AND THE FRAME RULE'S SECOND HALF.
 *
 * The block above settles which NAME an x87 destination gets: the one that
 * instruction's own SDM page uses, in that page's frame.  It does not settle
 * what a consumer must do to read that name's VALUE, and the two are not the
 * same question, because the value is sampled AFTER the instruction and
 * `st<i>` resolves against env->fpstt at the read.
 *
 * MEASURED (FINDING 66V-A).  On a stack holding 44/33/22/11,
 * `faddp %st,%st(2)` states `st2` -- right, its page says "ST(2) <-
 * ST(2)+ST(0); pop" -- and the value published beside it was 11.0, which is
 * ST(2) in the frame after the pop.  The result, 66.0, was in the trace
 * nowhere at all.  `fstp %st(1)` had the same shape.  These are the eight
 * families whose destinations became statable when the frame rule landed, so
 * the change that made the names right is the change that made this
 * reachable, and it is closed here rather than left for the consumer to
 * infer from an opcode table it would have to keep in step with this file.
 *
 * The shift is the offset from the stated name's index to the
 * POST-instruction spelling of the same physical register -- the inverse of
 * the adjustment, and only where the name is in the PRE-adjustment frame.
 * See insn_dataflow_note_stated_write_name_shift().
 *
 * TWO FORMS TAKE NO SHIFT HERE AND THE REASON IS THE SAME ONE.  `fptan` and
 * `fsincos` push only on the arm where |ST(0)| is in range; the C2 arm sets
 * the exception bit and writes no data register at all.  Their adjustment is
 * therefore a property of the OPERAND and not of the encoding, and R20 asks
 * this site for static facts.  A static -1 or +1 would be wrong on one of
 * the two arms, and wrong is worse than absent because absent is visible.
 * They keep the frame they had.  `frstor` is left alone for the neighbouring
 * reason: it loads TOP from memory, so no static answer exists there either,
 * and it states all eight names, which is closed under the rotation as a
 * SET even though the pairing inside it is not.
 */
static void gen_note_st0_write_shift(int value_shift)
{
    insn_dataflow_note_stated_write_name_shift("st0", value_shift);
}

static void gen_note_sti_write_shift(int i, int value_shift)
{
    insn_dataflow_note_stated_write_name_shift(st_names[i & 7], value_shift);
}

/*
 * @mod, @op and @rm are gen_x87()'s own decode variables, in its own
 * spelling: @op is ((b & 7) << 3) | ModRM.reg, which is the value its two
 * switches dispatch on, and @rm is ModRM.rm, which is the second-level
 * selector for the register-form groups.  Reading the classification off
 * anything else -- a mnemonic, a helper name, a scratch table of opcodes --
 * would be a second decoder to keep in step with this one.
 */
static void gen_note_x87_env_reads(int mod, int op, int rm)
{
    bool ctrl, stat;

    if (mod != 3) {
        switch (op) {
        case 0x0c: /* fldenv  -- loads the environment, reads neither */
        case 0x0d: /* fldcw   -- loads the control word, reads neither */
        case 0x2c: /* frstor  -- restores the whole state */
            ctrl = false;
            stat = false;
            break;
        case 0x0f: /* fnstcw  -- stores the control word, and only that */
            ctrl = true;
            stat = false;
            break;
        case 0x1d: /* fldt    -- m80 is the internal format: exact */
        case 0x1f: /* fstpt   -- likewise */
        case 0x2f: /* fnstsw  -- stores the status word, and only that */
            ctrl = false;
            stat = true;
            break;
        default:
            /*
             * Every remaining memory form converts or computes: the eight
             * arithmetic groups over all four operand widths, the real and
             * integer loads and stores, fisttp, fbld, fbstp, fnstenv and
             * fnsave.
             */
            ctrl = true;
            stat = true;
            break;
        }
    } else {
        switch (op) {
        case 0x1c: /* feni, fdisi, fclex, fninit, fsetpm */
            /*
             * fnclex and fninit WRITE the status word; the three 287-era
             * arms are nops on this CPU.  None of the five reads either.
             */
            ctrl = false;
            stat = false;
            break;
        case 0x0c: /* grp d9/4: fchs, fabs, ftst, fxam */
            ctrl = (rm == 4);          /* ftst compares against 0.0 */
            stat = true;
            break;
        case 0x0d: /* grp d9/5: the seven constants */
            ctrl = (rm >= 1 && rm <= 5);   /* l2t l2e pi lg2 ln2 round */
            stat = true;
            break;
        case 0x0e: /* grp d9/6 */
            ctrl = (rm <= 5);          /* not fdecstp, not fincstp */
            stat = true;
            break;
        case 0x08: /* fld %st(i)     -- an exact move */
        case 0x09: /* fxch %st(i) */
        case 0x29:
        case 0x39:
        case 0x0a: /* d9/2 group: fnop */
        case 0x0b: /* fstp1 %st(i), undocumented */
        case 0x3a: /* fstp8 %st(i), undocumented */
        case 0x3b: /* fstp9 %st(i), undocumented */
        case 0x10 ... 0x13: /* fcmovcc */
        case 0x18 ... 0x1b:
        case 0x28: /* ffree %st(i)   -- marks the tag word, reads no value */
        case 0x38: /* ffreep %st(i) */
        case 0x2a: /* fst %st(i)     -- an exact move */
        case 0x2b: /* fstp %st(i) */
        case 0x3c: /* df/4: fnstsw %ax */
            ctrl = false;
            stat = true;
            break;
        default:
            /*
             * Every remaining register form computes or compares: the
             * arithmetic groups in all three directions, the compare and
             * unordered-compare groups including the EFLAGS-setting ones,
             * and the d9/7 transcendentals.
             */
            ctrl = true;
            stat = true;
            break;
        }
    }

    if (ctrl) {
        gen_note_fctrl_read();
    }
    if (stat) {
        gen_note_fstat_read();
    }
}

/*
 * THE STATUS WORD IS WRITTEN BY ALMOST EVERY x87 INSTRUCTION, and QEMU
 * writes it for most of them by accident of where the value lives.
 *
 * FPSW carries the condition codes, the sticky exception flags and TOP, and
 * the SDM gives every arithmetic, load, store, compare, transcendental and
 * stack instruction in the escape space a FPU-flags row: C1 at minimum, the
 * exception bits wherever the operation can raise, TOP wherever it pushes or
 * pops.  Nothing about that is conditional on the operand, so this is one
 * fact about the space rather than a table over it -- which is why it is
 * stated uniformly here and not arm by arm.
 *
 * WHAT WAS MISSING.  A helper that pushes, pops or sets a condition code
 * touches env->fpus or env->fpstt, and the extraction sees that store, so
 * most of the space already carried the write.  The instructions QEMU
 * implements WITHOUT touching either word did not: `fcmovcc`, `fst %st(i)`,
 * `fxch`, `fchs` and `fabs` are moves and sign flips in this emulator, and
 * the SDM defines all five as updating C1.  Measured at exec104 that is the
 * whole of x86_64's REG_FCSR destination bar -- 7,638 registers over 14
 * rule-and-mnemonic classes and no others.  Not modelling C1 is a lowering
 * decision, and R15 says a lowering decision is not architectural truth;
 * R16 says the ISA-defined write is recorded whatever the emulator does
 * with it.
 *
 * WHAT DOES NOT WRITE IT, and every one is the architecture's own exception
 * rather than this emulator's.  Two groups:
 *
 *   THE WORDS THAT NAME SOMETHING ELSE.  `fldcw` and `fnstcw` name only the
 *   control word, `fnstsw` (both the memory form and `fnstsw %ax`) READS the
 *   status word to store it, and `fnstenv` stores the environment and then
 *   masks exceptions in FCW, leaving FSW alone.  The read side above draws
 *   its FPSW line through the same instructions from the other direction,
 *   which is the cross-check.
 *
 *   THE ONES THAT PERFORM NO OPERATION.  `fnop`, and the three 287 encodings
 *   `feni`, `fdisi` and `fsetpm` that a 387 and later treat as `fnop`.  The
 *   SDM lists their condition codes as UNDEFINED rather than as written, and
 *   an instruction with no operation has no exception condition to record
 *   either, so there is no defined update to state.  This is the direction
 *   the first measurement of this note got wrong: stating FSW for the four
 *   put 374 registers on the GAIN side of the destination bar -- a
 *   destination QEMU claims and the wire does not carry -- which is the
 *   fabrication direction, and it was the whole of that arm's gain.
 *
 * TOP IS NOT STATED HERE.  env->fpstt is the other half of the declared
 * `fstat` register, and it moves only where the instruction pushes or pops
 * -- which is exactly where QEMU's own helper already writes it, so a
 * statement would add nothing and a blanket one would claim a TOP update for
 * `fchs`.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
static void gen_note_x87_env_writes(int mod, int op, int rm)
{
    if (mod != 3) {
        switch (op) {
        case 0x0d: /* fldcw   -- the control word, and only that */
        case 0x0e: /* fnstenv -- stores the environment, masks in FCW */
        case 0x0f: /* fnstcw  -- the control word, and only that */
        case 0x2f: /* fnstsw  -- READS the status word to store it */
            return;
        }
    } else {
        switch (op) {
        case 0x0a:
            if (rm == 0) {
                return;         /* fnop */
            }
            break;
        case 0x1c:
            if (rm == 0 || rm == 1 || rm == 4) {
                return;         /* feni, fdisi, fsetpm */
            }
            break;
        case 0x3c:
            if (rm == 0) {
                return;         /* fnstsw %ax, the register form of the same */
            }
            break;
        }
    }
    insn_dataflow_note_stated_write_env(offsetof(CPUX86State, fpus),
                                        sizeof(((CPUX86State *)0)->fpus));
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

                gen_note_st0_read();
                /*
                 * op1 2 and 3 are `fcom`/`fcomp`: they produce condition
                 * codes and leave the stack value alone.  Every other arm
                 * of gen_helper_fp_arith_ST0_FT0() replaces ST(0) in place.
                 */
                if (op1 != 2 && op1 != 3) {
                    gen_note_st0_write();
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
                gen_note_st0_write();
                break;
            case 1:
                /* XXX: the corresponding CPUID bit must be tested ! */
                switch (op >> 4) {
                case 1:
                    gen_note_st0_read();
                    gen_helper_fisttl_ST0(s->tmp2_i32, tcg_env);
                    tcg_gen_qemu_st_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUL);
                    break;
                case 2:
                    gen_note_st0_read();
                    gen_helper_fisttll_ST0(s->tmp1_i64, tcg_env);
                    tcg_gen_qemu_st_i64(s->tmp1_i64, s->A0,
                                        s->mem_index, MO_LEUQ);
                    break;
                case 3:
                default:
                    gen_note_st0_read();
                    gen_helper_fistt_ST0(s->tmp2_i32, tcg_env);
                    tcg_gen_qemu_st_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUW);
                    break;
                }
                gen_helper_fpop(tcg_env);
                break;
            default:
                switch (op >> 4) {
                case 0:
                    gen_note_st0_read();
                    gen_helper_fsts_ST0(s->tmp2_i32, tcg_env);
                    tcg_gen_qemu_st_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUL);
                    break;
                case 1:
                    gen_note_st0_read();
                    gen_helper_fistl_ST0(s->tmp2_i32, tcg_env);
                    tcg_gen_qemu_st_i32(s->tmp2_i32, s->A0,
                                        s->mem_index, MO_LEUL);
                    break;
                case 2:
                    gen_note_st0_read();
                    gen_helper_fstl_ST0(s->tmp1_i64, tcg_env);
                    tcg_gen_qemu_st_i64(s->tmp1_i64, s->A0,
                                        s->mem_index, MO_LEUQ);
                    break;
                case 3:
                default:
                    gen_note_st0_read();
                    gen_helper_fist_ST0(s->tmp2_i32, tcg_env);
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
            tcg_gen_qemu_st_i32(s->tmp2_i32, s->A0,
                                s->mem_index, MO_LEUW);
            update_fip = update_fdp = false;
            break;
        case 0x1d: /* fldt mem */
            gen_note_st0_write();
            gen_helper_fldt_ST0(tcg_env, s->A0);
            break;
        case 0x1f: /* fstpt mem */
            gen_note_st0_read();
            gen_helper_fstt_ST0(tcg_env, s->A0);
            gen_helper_fpop(tcg_env);
            break;
        case 0x2c: /* frstor mem */
            /*
             * FRSTOR loads all eight data registers, and the SET {st0..st7}
             * is CLOSED under the stack rotation -- whatever TOP the restored
             * image carries, the eight names are the same eight registers.
             * So this one arm needs no frame argument at all: it is the only
             * x87 destination statement whose answer does not depend on which
             * frame it is read in.
             */
            for (int i = 0; i < 8; i++) {
                gen_note_sti_write(i);
            }
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
            tcg_gen_qemu_st_i32(s->tmp2_i32, s->A0,
                                s->mem_index, MO_LEUW);
            update_fip = update_fdp = false;
            break;
        case 0x3c: /* fbld */
            gen_note_st0_write();
            gen_helper_fbld_ST0(tcg_env, s->A0);
            break;
        case 0x3e: /* fbstp */
            gen_note_st0_read();
            gen_helper_fbst_ST0(tcg_env, s->A0);
            gen_helper_fpop(tcg_env);
            break;
        case 0x3d: /* fildll */
            tcg_gen_qemu_ld_i64(s->tmp1_i64, s->A0,
                                s->mem_index, MO_LEUQ);
            gen_note_st0_write();
            gen_helper_fildll_ST0(tcg_env, s->tmp1_i64);
            break;
        case 0x3f: /* fistpll */
            gen_note_st0_read();
            gen_helper_fistll_ST0(s->tmp1_i64, tcg_env);
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
            /*
             * `fld %st(i)` reads ST(i) IN ITS OWN PAGE'S FRAME -- before the
             * push -- and writes the new ST(0).  QEMU pushes first and hands
             * the helper (opreg + 1), which is the same register renamed by
             * the adjustment the instruction itself makes; the name the
             * ENCODING carries is `st<i>`, and that is what is stated.
             */
            gen_note_sti_read(opreg);
            gen_note_st0_write();
            gen_helper_fpush(tcg_env);
            gen_helper_fmov_ST0_STN(tcg_env,
                                    tcg_constant_i32((opreg + 1) & 7));
            break;
        case 0x09: /* fxchg sti */
        case 0x29: /* fxchg4 sti, undocumented op */
        case 0x39: /* fxchg7 sti, undocumented op */
            gen_note_st0_read();
            gen_note_sti_read(opreg);
            gen_note_st0_write();
            gen_note_sti_write(opreg);
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
                gen_note_st0_read();
                gen_note_st0_write();
                gen_helper_fchs_ST0(tcg_env);
                break;
            case 1: /* fabs */
                gen_note_st0_read();
                gen_note_st0_write();
                gen_helper_fabs_ST0(tcg_env);
                break;
            case 4: /* ftst */
                gen_helper_fldz_FT0(tcg_env);
                gen_note_st0_read();
                gen_helper_fcom_ST0_FT0(tcg_env);
                break;
            case 5: /* fxam */
                gen_note_st0_read();
                gen_helper_fxam_ST0(tcg_env);
                break;
            default:
                goto illegal_op;
            }
            break;
        case 0x0d: /* grp d9/5 */
            {
                /*
                 * The seven constant loads all PUSH and then write the new
                 * top; the note is taken once for the group because the
                 * destination is the same register on every arm.
                 */
                if (rm <= 6) {
                    gen_note_st0_write();
                }
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
                gen_note_st0_read();
                gen_note_st0_write();
                gen_helper_f2xm1(tcg_env);
                break;
            case 1: /* fyl2x */
                /* Two-operand: ST(1) is the other multiplicand /
                 * dividend / scale, and several of these write it. */
                gen_note_st0_read();
                gen_note_sti_read(1);
                /* "ST(1) <- ST(1)*log2 ST(0); pop": named pre-pop. */
                gen_note_sti_write_shift(1, -1);
                gen_helper_fyl2x(tcg_env);
                break;
            case 2: /* fptan */
                gen_note_st0_read();
                gen_note_st0_write();
                gen_helper_fptan(tcg_env);
                break;
            case 3: /* fpatan */
                /* Two-operand: ST(1) is the other multiplicand /
                 * dividend / scale, and several of these write it. */
                gen_note_st0_read();
                gen_note_sti_read(1);
                /* "ST(1) <- arctan(ST(1)/ST(0)); pop": named pre-pop. */
                gen_note_sti_write_shift(1, -1);
                gen_helper_fpatan(tcg_env);
                break;
            case 4: /* fxtract */
                gen_note_st0_read();
                /*
                 * "ST(0) <- exponent; push; ST(0) <- significand": the
                 * exponent is named in the pre-push frame.  Every arm of
                 * helper_fxtract() pushes, so the adjustment is static --
                 * which is what separates it from fptan and fsincos below.
                 */
                gen_note_st0_write_shift(+1);
                gen_helper_fxtract(tcg_env);
                break;
            case 5: /* fprem1 */
                /* Two-operand: ST(1) is the other multiplicand /
                 * dividend / scale, and several of these write it. */
                gen_note_st0_read();
                gen_note_sti_read(1);
                gen_note_st0_write();
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
                /* Two-operand: ST(1) is the other multiplicand /
                 * dividend / scale, and several of these write it. */
                gen_note_st0_read();
                gen_note_sti_read(1);
                gen_note_st0_write();
                gen_helper_fprem(tcg_env);
                break;
            case 1: /* fyl2xp1 */
                /* Two-operand: ST(1) is the other multiplicand /
                 * dividend / scale, and several of these write it. */
                gen_note_st0_read();
                gen_note_sti_read(1);
                /* "ST(1) <- ST(1)*log2(ST(0)+1.0); pop": named pre-pop. */
                gen_note_sti_write_shift(1, -1);
                gen_helper_fyl2xp1(tcg_env);
                break;
            case 2: /* fsqrt */
                gen_note_st0_read();
                gen_note_st0_write();
                gen_helper_fsqrt(tcg_env);
                break;
            case 3: /* fsincos */
                gen_note_st0_read();
                gen_note_st0_write();
                gen_helper_fsincos(tcg_env);
                break;
            case 5: /* fscale */
                /* Two-operand: ST(1) is the other multiplicand /
                 * dividend / scale, and several of these write it. */
                gen_note_st0_read();
                gen_note_sti_read(1);
                gen_note_st0_write();
                gen_helper_fscale(tcg_env);
                break;
            case 4: /* frndint */
                gen_note_st0_read();
                gen_note_st0_write();
                gen_helper_frndint(tcg_env);
                break;
            case 6: /* fsin */
                gen_note_st0_read();
                gen_note_st0_write();
                gen_helper_fsin(tcg_env);
                break;
            default:
            case 7: /* fcos */
                gen_note_st0_read();
                gen_note_st0_write();
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
                    /* `fxxx %st,%st(i)`: both operands, result into ST(i). */
                    gen_note_st0_read();
                    gen_note_sti_read(opreg);
                    /*
                     * The 0x30 block is `fxxxp %st,%st(i)`, which writes
                     * ST(i) and then pops.  The name is the ENCODING'S,
                     * taken in its own page's frame, so the pop that follows
                     * does not change what is stated.  See
                     * gen_note_sti_write() for the rule.
                     */
                    gen_note_sti_write_shift(opreg,
                                             op >= 0x30 ? -1 : 0);
                    gen_helper_fp_arith_STN_ST0(op1, opreg);
                    if (op >= 0x30) {
                        gen_helper_fpop(tcg_env);
                    }
                } else {
                    gen_note_sti_read(opreg);
                    gen_helper_fmov_FT0_STN(tcg_env,
                                            tcg_constant_i32(opreg));
                    gen_note_st0_read();
                    gen_note_st0_write();
                    gen_helper_fp_arith_ST0_FT0(op1);
                }
            }
            break;
        case 0x02: /* fcom */
        case 0x22: /* fcom2, undocumented op */
            gen_note_sti_read(opreg);
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_note_st0_read();
            gen_helper_fcom_ST0_FT0(tcg_env);
            break;
        case 0x03: /* fcomp */
        case 0x23: /* fcomp3, undocumented op */
        case 0x32: /* fcomp5, undocumented op */
            gen_note_sti_read(opreg);
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_note_st0_read();
            gen_helper_fcom_ST0_FT0(tcg_env);
            gen_helper_fpop(tcg_env);
            break;
        case 0x15: /* da/5 */
            switch (rm) {
            case 1: /* fucompp */
                gen_note_sti_read(1);
                gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(1));
                gen_note_st0_read();
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
            gen_note_sti_read(opreg);
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_note_st0_read();
            gen_helper_fucomi_ST0_FT0(tcg_env);
            assume_cc_op(s, CC_OP_EFLAGS);
            break;
        case 0x1e: /* fcomi */
            if (!(s->cpuid_features & CPUID_CMOV)) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_note_sti_read(opreg);
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_note_st0_read();
            gen_helper_fcomi_ST0_FT0(tcg_env);
            assume_cc_op(s, CC_OP_EFLAGS);
            break;
        case 0x28: /* ffree sti */
            gen_helper_ffree_STN(tcg_env, tcg_constant_i32(opreg));
            break;
        case 0x2a: /* fst sti */
            gen_note_st0_read();
            gen_note_sti_write(opreg);
            gen_helper_fmov_STN_ST0(tcg_env, tcg_constant_i32(opreg));
            break;
        case 0x2b: /* fstp sti */
        case 0x0b: /* fstp1 sti, undocumented op */
        case 0x3a: /* fstp8 sti, undocumented op */
        case 0x3b: /* fstp9 sti, undocumented op */
            gen_note_st0_read();
            /* "ST(i) <- ST(0); pop": the destination is named pre-pop. */
            gen_note_sti_write_shift(opreg, -1);
            gen_helper_fmov_STN_ST0(tcg_env, tcg_constant_i32(opreg));
            gen_helper_fpop(tcg_env);
            break;
        case 0x2c: /* fucom st(i) */
            gen_note_sti_read(opreg);
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_note_st0_read();
            gen_helper_fucom_ST0_FT0(tcg_env);
            break;
        case 0x2d: /* fucomp st(i) */
            gen_note_sti_read(opreg);
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_note_st0_read();
            gen_helper_fucom_ST0_FT0(tcg_env);
            gen_helper_fpop(tcg_env);
            break;
        case 0x33: /* de/3 */
            switch (rm) {
            case 1: /* fcompp */
                gen_note_sti_read(1);
                gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(1));
                gen_note_st0_read();
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
            gen_note_sti_read(opreg);
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_note_st0_read();
            gen_helper_fucomi_ST0_FT0(tcg_env);
            gen_helper_fpop(tcg_env);
            assume_cc_op(s, CC_OP_EFLAGS);
            break;
        case 0x3e: /* fcomip */
            if (!(s->cpuid_features & CPUID_CMOV)) {
                goto illegal_op;
            }
            gen_update_cc_op(s);
            gen_note_sti_read(opreg);
            gen_helper_fmov_FT0_STN(tcg_env, tcg_constant_i32(opreg));
            gen_note_st0_read();
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
                /*
                 * R17: a conditional carries ALL its potential sources, so
                 * ST(i) is stated whether or not the condition takes -- and
                 * ST(0) with it, because the arm that does not take LEAVES
                 * ST(0) alone, which makes the destination its own source.
                 */
                gen_note_st0_read();
                gen_note_sti_read(opreg);
                /*
                 * And the destination on the same rule: `fcmovcc` writes
                 * ST(0) in place with no stack adjustment either way, so
                 * `st0` names it whether the condition took or not.
                 */
                gen_note_st0_write();
                gen_helper_fmov_ST0_STN(tcg_env,
                                        tcg_constant_i32(opreg));
                gen_set_label(l1);
            }
            break;
        default:
            goto illegal_op;
        }
    }

    if (update_fip) {
        tcg_gen_ld_i32(s->tmp2_i32, tcg_env,
                       offsetof(CPUX86State, segs[R_CS].selector));
        tcg_gen_st16_i32(s->tmp2_i32, tcg_env,
                         offsetof(CPUX86State, fpcs));
        tcg_gen_st_tl(eip_cur_tl(s),
                      tcg_env, offsetof(CPUX86State, fpip));
    }
    gen_note_x87_env_reads(mod, op, rm);
    gen_note_x87_env_writes(mod, op, rm);
    x87_ident_publish(b, modrm);  /* x87_ident */
    return;

 illegal_op:
    gen_illegal_opcode(s);
}

/*
 * THE BOUND REGISTER AN MPX INSTRUCTION READS.
 *
 * QEMU translates the whole of `0F 1A` and `0F 1B` to NOTHING unless
 * HF_MPX_EN_MASK is set in the TB flags -- `if (s->flags & HF_MPX_EN_MASK)`
 * wraps both cases end to end -- so on a guest that has not enabled MPX the
 * op stream carries no read of any bound register and `bndcl`, `bndcu`,
 * `bndcn`, `bndmov` and `bndstx` all reach the extraction with `RD = -`.
 * 26,741 registers over five decode rules, and the wire carried REG_BOUND<n>
 * from the operand walk alone.
 *
 * R16 IS WHY THIS IS STATED ANYWAY.  Whether the enable bit is set is machine
 * state; the ISA defines `bndcl bnd0,rax` as reading BND0.LB whatever
 * BNDCFGx says, and R16 records ISA-defined dependencies regardless of
 * machine state.  R17 says the same thing from the other side: a conditional
 * carries all its potential sources, and the enable bit is the condition.
 *
 * ON THE RETURNING PATH, beside multi0f_ident_publish(), for that publish's
 * reason -- the `reg >= 4` and 16-bit-address refusals inside the enabled
 * arms jump to illegal_op, and a note taken here therefore describes an
 * encoding the emulator accepted.
 *
 * THE LEGALITY TESTS ARE RESTATED HERE, and that is worth naming rather than
 * hiding.  They live inside the enable guard, where a disabled machine never
 * runs them: with MPX off, `bndcl bnd4,rax` is a NOP and not #UD, and moving
 * the tests out would change what the guest does.  So the note applies the
 * same two conditions in the same spelling -- the register field is
 * `((modrm >> 3) & 7) | REX_R(s)` and must be below four, and a 16-bit
 * address form has no MPX encoding -- and reads them off @modrm and @s, never
 * off a private table.
 *
 * WHICH HALF.  BND<n> is one 128-bit register that QEMU keeps as two
 * globals, bnd<n>_lb and bnd<n>_ub, and both fold to REG_BOUND<n>; the note
 * states the half the instruction actually uses, because that is what the
 * ISA defines -- `bndcl` checks the LOWER bound and `bndcu`/`bndcn` the
 * upper -- and the two forms that move a whole register state both.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
static void gen_note_bnd_lb(int n)
{
    insn_dataflow_note_stated_read_env(
        offsetof(CPUX86State, bnd_regs[0].lb) + n * sizeof(BNDReg),
        sizeof(((CPUX86State *)0)->bnd_regs[0].lb));
}

static void gen_note_bnd_ub(int n)
{
    insn_dataflow_note_stated_read_env(
        offsetof(CPUX86State, bnd_regs[0].ub) + n * sizeof(BNDReg),
        sizeof(((CPUX86State *)0)->bnd_regs[0].ub));
}

/*
 * THE BOUND REGISTER AN MPX INSTRUCTION WRITES.
 *
 * The exact mirror of gen_note_mpx_source(), and it exists for the identical
 * reason: both emitter blocks sit inside `if (s->flags & HF_MPX_EN_MASK)`,
 * so on a guest that has not enabled MPX the op stream carries no write of
 * any bound register and `bndmk`, `bndldx` and `bndmov` all reach the
 * extraction with no architectural destination at all.  Measured at exec104
 * that is 15,441 x86_64 registers on the destination bar -- REG_BOUND0
 * through REG_BOUND3, and the second-largest class on that side.
 *
 * IT IS AN ARCHITECTURAL WRITE WHETHER OR NOT MPX IS ON.  With MPX disabled
 * the instruction is a NOP on real silicon too, and QEMU is right to emit
 * nothing; R16 records the ISA-defined destination regardless of machine
 * state, exactly as the source note records the ISA-defined dependency.
 * The `mod == 3` register-to-register `bndmov` has a second version of the
 * same shape -- QEMU skips the two moves when HF_MPX_IU_MASK is clear,
 * because the bounds are at their INIT value -- and the write is stated
 * there too, on the same rule.
 *
 * THE LEGALITY TESTS ARE RESTATED, in the same spelling and off @modrm and
 * @s, for the reason gen_note_mpx_source() restates them: they live inside
 * the enable guard where a disabled machine never runs them.
 *
 * WHICH INSTRUCTIONS, and which half.  `bndmk`, `bndldx` and the two
 * `bndmov` directions write a WHOLE bound register, so both halves are
 * stated; `bndcl`, `bndcu` and `bndcn` are checks with no destination, and
 * `bndstx` and the memory form of `bndmov` write MEMORY.  The destination
 * of the store-direction `bndmov` is bnd<reg2>, not bnd<reg> -- the source
 * note states the opposite register for the same encoding, which is the
 * cross-check that the direction is right.
 *
 * Capture only; no op is emitted, altered or suppressed.
 */
static void gen_note_bnd_write(int n)
{
    insn_dataflow_note_stated_write_env(
        offsetof(CPUX86State, bnd_regs[0].lb) + n * sizeof(BNDReg),
        sizeof(((CPUX86State *)0)->bnd_regs[0].lb));
    insn_dataflow_note_stated_write_env(
        offsetof(CPUX86State, bnd_regs[0].ub) + n * sizeof(BNDReg),
        sizeof(((CPUX86State *)0)->bnd_regs[0].ub));
}

static void gen_note_mpx_dest(DisasContext *s, int b, int modrm, int prefixes)
{
    int mod = (modrm >> 6) & 3;
    int reg = ((modrm >> 3) & 7) | REX_R(s);
    int reg2 = (modrm & 7) | REX_B(s);

    if ((b != 0x11a && b != 0x11b) || reg >= 4 || s->aflag == MO_16) {
        return;
    }

    if (b == 0x11a) {
        if (prefixes & (PREFIX_REPZ | PREFIX_REPNZ)) {
            /* bndcl / bndcu: a check, and it writes no bound register. */
        } else if (prefixes & PREFIX_DATA) {
            /* bndmov bnd<reg> <- bnd<reg2>/m */
            if (mod != 3 || reg2 < 4) {
                gen_note_bnd_write(reg);
            }
        } else if (mod != 3) {
            gen_note_bnd_write(reg);            /* bndldx bnd<reg> <- mib */
        }
    } else {
        if (mod != 3 && (prefixes & PREFIX_REPZ)) {
            gen_note_bnd_write(reg);            /* bndmk bnd<reg> <- m */
        } else if (prefixes & PREFIX_REPNZ) {
            /* bndcn: a check. */
        } else if (prefixes & PREFIX_DATA) {
            /* bndmov bnd<reg2>/m <- bnd<reg>; only the register form
             * writes a bound register. */
            if (mod == 3 && reg2 < 4) {
                gen_note_bnd_write(reg2);
            }
        }
        /* bndstx writes MEMORY. */
    }
}

static void gen_note_mpx_source(DisasContext *s, int b, int modrm,
                                int prefixes)
{
    int mod = (modrm >> 6) & 3;
    int reg = ((modrm >> 3) & 7) | REX_R(s);
    int reg2 = (modrm & 7) | REX_B(s);

    if ((b != 0x11a && b != 0x11b) || reg >= 4 || s->aflag == MO_16) {
        return;
    }

    if (b == 0x11a) {
        if (prefixes & PREFIX_REPZ) {            /* bndcl: lower bound */
            gen_note_bnd_lb(reg);
        } else if (prefixes & PREFIX_REPNZ) {    /* bndcu: upper bound */
            gen_note_bnd_ub(reg);
        } else if (prefixes & PREFIX_DATA) {
            /* bndmov bnd<reg> <- bnd<reg2>; the memory form reads memory */
            if (mod == 3 && reg2 < 4) {
                gen_note_bnd_lb(reg2);
                gen_note_bnd_ub(reg2);
            }
        }
        /* bndldx WRITES bnd<reg> and reads no bound register. */
    } else {
        if (mod != 3 && (prefixes & PREFIX_REPZ)) {
            /* bndmk WRITES bnd<reg>. */
        } else if (prefixes & PREFIX_REPNZ) {    /* bndcn: upper bound */
            gen_note_bnd_ub(reg);
        } else if (prefixes & PREFIX_DATA) {
            /* bndmov bnd<reg2>/m <- bnd<reg> */
            if (mod != 3 || reg2 < 4) {
                gen_note_bnd_lb(reg);
                gen_note_bnd_ub(reg);
            }
        } else if (mod != 3) {                   /* bndstx */
            gen_note_bnd_lb(reg);
            gen_note_bnd_ub(reg);
        }
    }
}

/*
 * multi0f_ident: ENCODING-QUALIFIED IDENTITY for the unconverted 0F spaces.
 *
 * gen_multi0F() is reached from five decode-table rows and
 * dispatches on `b`, `s->modrm` and `s->prefix` to forty-one
 * different instructions.  The table below states each arm as its
 * own identity, so a consumer can tell `xgetbv` from `swapgs`.
 * Generated by scripts/x86_multi0f_ident_instrument.py.
 */
#include "multi0f_ident.c.inc"  /* multi0f_ident */

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
            gen_note_gdt_read();
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
            gen_note_gdt_read();
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
            /*
             * XGETBV RETURNS XCR[ECX], SO THE EXTENDED CONTROL REGISTER IS
             * ITS OPERAND, NOT ITS PERMISSION.  helper_xgetbv() reads
             * env->xcr0 on BOTH selectors the architecture defines -- ecx=0
             * returns it whole and ecx=1 returns `env->xcr0 & get_xinuse()`
             * (fpu_helper.c:3201-3208) -- so the read happens on every path
             * that does not fault.  It happens INSIDE the helper, the
             * extraction reports the helper unbounded, and no TCG global
             * names XCR0, which is exactly the shape gen_note_xcr0_read()
             * was added for at the XSAVE sites.
             *
             * Capture only; no op is emitted, altered or suppressed.
             */
            gen_note_xcr0_read();
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
    gen_note_mpx_source(s, b, modrm, prefixes);
    gen_note_mpx_dest(s, b, modrm, prefixes);
    multi0f_ident_publish(b, modrm, prefixes);  /* multi0f_ident */
    return;
 illegal_op:
    gen_illegal_opcode(s);
    return;
}

#include "decode-new.c.inc"

void tcg_x86_init(void)
{
    static const char reg_names[CPU_NB_REGS][4] = {
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
    static const char eip_name[] = {
#ifdef TARGET_X86_64
        "rip"
#else
        "eip"
#endif
    };
    static const char seg_base_names[6][8] = {
        [R_CS] = "cs_base",
        [R_DS] = "ds_base",
        [R_ES] = "es_base",
        [R_FS] = "fs_base",
        [R_GS] = "gs_base",
        [R_SS] = "ss_base",
    };
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
    cpu_eip = tcg_global_mem_new(tcg_env, offsetof(CPUX86State, eip), eip_name);

    /*
     * cc_op is the SELECTOR of the lazy-flag representation, not a piece of
     * the flags.  cc_dst, cc_src and cc_src2 hold the operands and results
     * that EFLAGS is computed FROM, and are therefore how an instruction
     * that architecturally writes flags states what it wrote; cc_op holds
     * which computation to apply, which is this emulator's bookkeeping and
     * no part of the architectural value.
     *
     * Said here, and only here, because nothing downstream can tell: the
     * write is `mov cc_op, <const>`, and so is `mov $5,%rax`'s.  Only the
     * code that chose the lowering knows which of the two carries a value.
     * Without this statement `ja` -- which writes NO flag the ISA defines --
     * arrives at a consumer as an EFLAGS producer, because materialising the
     * flags for its own test writes cc_op.
     */
    insn_dataflow_declare_repr_selector(tcgv_i32_temp(cpu_cc_op));

    for (i = 0; i < CPU_NB_REGS; ++i) {
        cpu_regs[i] = tcg_global_mem_new(tcg_env,
                                         offsetof(CPUX86State, regs[i]),
                                         reg_names[i]);
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

    /*
     * The vector file, for the dataflow extraction.
     *
     * Nothing above registers a TCG global for it -- SSE and AVX reach
     * env->xmm_regs by ld/st and by helper, so every dependency on a vector
     * register arrives at a consumer as a CPUArchState byte offset.  The
     * offset IS the register's identity; inverting it back needs this
     * struct's layout, which is why the statement belongs here, beside the
     * globals, in offsetof() and sizeof() rather than in numbers.
     *
     * The x87 stack is deliberately NOT declared.  env->fpregs[] is indexed
     * by PHYSICAL register while the GDB stub's st0..st7 are relative to
     * fpstt, so an offset does not name an ST(i) without a run-time top --
     * which a translation-time answer does not have.
     */
    insn_dataflow_declare_regfile("xmm", NULL,
                                  offsetof(CPUX86State, xmm_regs),
                                  sizeof(ZMMReg), sizeof(ZMMReg),
                                  ARRAY_SIZE(((CPUX86State *)0)->xmm_regs));

    /*
     * The x87 and SSE control/status file.
     *
     * Same reason as the vector file: no TCG global names these, so every
     * dependency on one arrives as a CPUArchState byte offset, and only this
     * file knows which register that offset is.  `fnstcw` is the witness --
     * it stores env->fpuc and nothing else, and until this declaration its
     * store-data provenance was an unnamed range.
     *
     * The names are the GDB stub's, which is the namespace
     * insn_dataflow_reg_name() answers in.  Two of them are one register in
     * two fields: target/i386/gdbstub.c builds `fstat` as
     * (fpus & ~0x3800) | (fpstt & 7) << 11, because QEMU keeps the x87
     * stack top out of the status word it stores.  Both are declared under
     * that one name, since FPSW.TOP is architecturally part of FPSW, and an
     * access that spans the two lands in neither file's extent and refuses.
     *
     * `ftag` is QEMU's UNPACKED tag array, one byte per stack slot, and the
     * whole array is the one architectural tag word -- so it is declared as
     * a single 8-byte register rather than eight.  (The gdbstub reports 0
     * for the packed word rather than composing it; the storage here is
     * nonetheless what x87 execution reads and writes.)
     *
     * env->fpregs[] -- the stack itself -- stays undeclared, for the reason
     * stated above the vector file: it is indexed by PHYSICAL register while
     * st0..st7 are relative to fpstt, so an offset does not name an ST(i)
     * without a run-time top.
     */
    insn_dataflow_declare_regfile("fctrl", NULL,
                                  offsetof(CPUX86State, fpuc),
                                  sizeof(((CPUX86State *)0)->fpuc),
                                  sizeof(((CPUX86State *)0)->fpuc), 1);
    insn_dataflow_declare_regfile("fstat", NULL,
                                  offsetof(CPUX86State, fpus),
                                  sizeof(((CPUX86State *)0)->fpus),
                                  sizeof(((CPUX86State *)0)->fpus), 1);
    insn_dataflow_declare_regfile("fstat", NULL,
                                  offsetof(CPUX86State, fpstt),
                                  sizeof(((CPUX86State *)0)->fpstt),
                                  sizeof(((CPUX86State *)0)->fpstt), 1);
    insn_dataflow_declare_regfile("ftag", NULL,
                                  offsetof(CPUX86State, fptags),
                                  sizeof(((CPUX86State *)0)->fptags),
                                  sizeof(((CPUX86State *)0)->fptags), 1);
    insn_dataflow_declare_regfile("mxcsr", NULL,
                                  offsetof(CPUX86State, mxcsr),
                                  sizeof(((CPUX86State *)0)->mxcsr),
                                  sizeof(((CPUX86State *)0)->mxcsr), 1);

    /*
     * The DIRECTION FLAG.
     *
     * EFLAGS.DF is the one architectural flag QEMU does not keep in the
     * lazy cc_* quartet: do_gen_string() reads env->df to build the pointer
     * increment for every string instruction, and gen_CLD()/gen_STD() are
     * the only writers.  The field IS EFLAGS.DF -- QEMU stores it as +1/-1
     * rather than as bit 10, which is a representation choice and not a
     * different register -- so it is declared under the GDB stub's name for
     * the word it belongs to.  `rep stosq` is the witness: it reads this
     * field to decide which way rdi walks, and until this declaration that
     * read arrived downstream as an anonymous four-byte range.
     */
    insn_dataflow_declare_regfile("eflags", NULL,
                                  offsetof(CPUX86State, df),
                                  sizeof(((CPUX86State *)0)->df),
                                  sizeof(((CPUX86State *)0)->df), 1);

    /*
     * XCR0, the extended control register.
     *
     * `xgetbv` reads it and returns it in edx:eax; no TCG global names it
     * and it is not in the GDB stub's namespace, so the read arrives as a
     * CPUArchState byte offset and only this file knows which register that
     * offset is.  Declared under its architectural name.
     */
    insn_dataflow_declare_regfile("xcr0", NULL,
                                  offsetof(CPUX86State, xcr0),
                                  sizeof(((CPUX86State *)0)->xcr0),
                                  sizeof(((CPUX86State *)0)->xcr0), 1);

    /*
     * THE CONTROL REGISTERS.
     *
     * `smsw` reads env->cr[0] with a plain tcg_gen_ld_tl() and `lmsw` reads
     * it to merge the low four bits into -- both in the op stream, both
     * arriving as an anonymous span for want of a declaration, exactly like
     * the descriptor tables below.  6,745 registers on the smsw rule alone.
     *
     * The names are the GDB stub's, which is the namespace
     * insn_dataflow_reg_name() answers in and the one REG_CTRL<n> is keyed
     * on.  cr[1] is skipped because QEMU says at the member that it is
     * unused and no instruction names it; the file is therefore declared one
     * register at a time rather than as an array, so the hole is visible
     * instead of being papered over with a name for a register that does not
     * exist.
     */
    insn_dataflow_declare_regfile("cr0", NULL,
                                  offsetof(CPUX86State, cr[0]),
                                  sizeof(((CPUX86State *)0)->cr[0]),
                                  sizeof(((CPUX86State *)0)->cr[0]), 1);
    insn_dataflow_declare_regfile("cr2", NULL,
                                  offsetof(CPUX86State, cr[2]),
                                  sizeof(((CPUX86State *)0)->cr[2]),
                                  sizeof(((CPUX86State *)0)->cr[2]), 1);
    insn_dataflow_declare_regfile("cr3", NULL,
                                  offsetof(CPUX86State, cr[3]),
                                  sizeof(((CPUX86State *)0)->cr[3]),
                                  sizeof(((CPUX86State *)0)->cr[3]), 1);
    insn_dataflow_declare_regfile("cr4", NULL,
                                  offsetof(CPUX86State, cr[4]),
                                  sizeof(((CPUX86State *)0)->cr[4]),
                                  sizeof(((CPUX86State *)0)->cr[4]), 1);

    /*
     * THE DESCRIPTOR-TABLE AND TASK REGISTERS: GDTR, IDTR, LDTR and TR.
     *
     * `sldt` and `str` read env->ldt.selector and env->tr.selector with a
     * plain tcg_gen_ld32u_tl(), and `sgdt` and `sidt` read env->gdt.limit /
     * .base and env->idt.limit / .base the same way -- so unlike the system
     * registers around them these ARE in the op stream.  What they were
     * missing is a NAME: nothing declared those bytes, so the read arrived
     * downstream as an anonymous span and was dropped, and the wire carried
     * REG_SYSMMU from disas/capstone.c's own modelling of the four
     * instructions instead.  36,571 registers over six decode rules, closed
     * by a declaration rather than by a statement, because the emulator was
     * already doing the read.
     *
     * The names are the ones disas/capstone.c uses for the same four
     * registers -- gdtr, idtr, ldtr, tr -- so the spelling that reaches the
     * consumer is the spelling the boundary already answers in, and nothing
     * new is invented on either side.  None of the four is in the i386 GDB
     * stub's namespace, which is why the generated QEMU-indexed table has no
     * row for them and the plugin's fold_nonarch() carries the word.
     *
     * EACH FIELD IS DECLARED SEPARATELY under the one name, exactly as
     * `fstat` is: QEMU spreads one architectural register over several
     * SegmentCache members, and an access that spanned two of them would land
     * in neither extent and refuse -- which is the direction this file treats
     * as correct.  GDTR and IDTR have no selector, and QEMU says so at the
     * struct member ("only base and limit are used"); LDTR and TR have one,
     * and their base and limit are the hidden descriptor the architecture
     * loads with it.  `flags` is left out of all four: it is QEMU's packed
     * access-rights word, which is a storage form and not a field the ISA
     * names.
     */
    insn_dataflow_declare_regfile("gdtr", NULL,
                                  offsetof(CPUX86State, gdt.base),
                                  sizeof(((CPUX86State *)0)->gdt.base),
                                  sizeof(((CPUX86State *)0)->gdt.base), 1);
    insn_dataflow_declare_regfile("gdtr", NULL,
                                  offsetof(CPUX86State, gdt.limit),
                                  sizeof(((CPUX86State *)0)->gdt.limit),
                                  sizeof(((CPUX86State *)0)->gdt.limit), 1);
    insn_dataflow_declare_regfile("idtr", NULL,
                                  offsetof(CPUX86State, idt.base),
                                  sizeof(((CPUX86State *)0)->idt.base),
                                  sizeof(((CPUX86State *)0)->idt.base), 1);
    insn_dataflow_declare_regfile("idtr", NULL,
                                  offsetof(CPUX86State, idt.limit),
                                  sizeof(((CPUX86State *)0)->idt.limit),
                                  sizeof(((CPUX86State *)0)->idt.limit), 1);
    insn_dataflow_declare_regfile("ldtr", NULL,
                                  offsetof(CPUX86State, ldt.selector),
                                  sizeof(((CPUX86State *)0)->ldt.selector),
                                  sizeof(((CPUX86State *)0)->ldt.selector), 1);
    insn_dataflow_declare_regfile("ldtr", NULL,
                                  offsetof(CPUX86State, ldt.base),
                                  sizeof(((CPUX86State *)0)->ldt.base),
                                  sizeof(((CPUX86State *)0)->ldt.base), 1);
    insn_dataflow_declare_regfile("ldtr", NULL,
                                  offsetof(CPUX86State, ldt.limit),
                                  sizeof(((CPUX86State *)0)->ldt.limit),
                                  sizeof(((CPUX86State *)0)->ldt.limit), 1);
    insn_dataflow_declare_regfile("tr", NULL,
                                  offsetof(CPUX86State, tr.selector),
                                  sizeof(((CPUX86State *)0)->tr.selector),
                                  sizeof(((CPUX86State *)0)->tr.selector), 1);
    insn_dataflow_declare_regfile("tr", NULL,
                                  offsetof(CPUX86State, tr.base),
                                  sizeof(((CPUX86State *)0)->tr.base),
                                  sizeof(((CPUX86State *)0)->tr.base), 1);
    insn_dataflow_declare_regfile("tr", NULL,
                                  offsetof(CPUX86State, tr.limit),
                                  sizeof(((CPUX86State *)0)->tr.limit),
                                  sizeof(((CPUX86State *)0)->tr.limit), 1);

    /*
     * The SEGMENT SELECTORS.
     *
     * `mov %es,%ax` and its five siblings read env->segs[seg].selector by
     * ld -- no TCG global names the selector, only the hidden base does
     * (es_base .. gs_base above) -- so the read arrives at a consumer as a
     * CPUArchState byte offset and only this file knows which register that
     * offset is.  Witnessed on QEMU's own dump: the six instructions at
     * 0x401275..0x401284 of the golden net's w3_coverage cell read
     * off=184/208/232/256/280/304 size=4, which is exactly
     * segs[R_ES..R_GS].selector, and until this declaration every one of
     * them arrived as an unnamed four-byte range.
     *
     * The names are the GDB stub's, in QEMU'S OWN R_* ORDER -- ES, CS, SS,
     * DS, FS, GS -- because that is the order env->segs[] is indexed in and
     * the declaration inverts an OFFSET, not a GDB register number.
     *
     * @elem is the SELECTOR's four bytes, not the 24-byte SegmentCache slot.
     * The rest of the slot is the hidden descriptor cache: `base` already
     * has a TCG global of its own (which the lookup consults first), and
     * `limit`/`flags` are not the selector and must not be named for it.
     * A read that reaches past the four bytes therefore refuses, which is
     * the direction this file treats as correct.
     */
    {
        static const char *const seg_names[] = {
            "es", "cs", "ss", "ds", "fs", "gs",
        };

        QEMU_BUILD_BUG_ON(ARRAY_SIZE(seg_names) !=
                          ARRAY_SIZE(((CPUX86State *)0)->segs));
        insn_dataflow_declare_regfile(
            NULL, seg_names,
            offsetof(CPUX86State, segs),
            sizeof(((CPUX86State *)0)->segs[0]),
            sizeof(((CPUX86State *)0)->segs[0].selector),
            ARRAY_SIZE(((CPUX86State *)0)->segs));
    }

    /*
     * The x87 STACK, declared as ONE register and not as eight.
     *
     * The reason eight is wrong is stated above the vector file: env->fpregs
     * is indexed by PHYSICAL register while ST(i) is relative to env->fpstt,
     * so an offset does not name an ST(i) without a run-time top.  That
     * argument rules out naming an ELEMENT.  It does not rule out naming the
     * FILE, and naming the file is what the accesses actually are: every x87
     * instruction that reads the stack reaches it through a helper that
     * takes the whole array, so what arrives here is off=fpregs size=128 --
     * the container, exactly.
     *
     * It is declared with NO generic word on the consumer side on purpose.
     * A container justifies a member (a published ST(0) is covered by a
     * stated read of the file it lives in, #277) and it must never stand IN
     * for one, which is what a generic word would let it do on the write
     * side.
     */
    /*
     * THE MMX FILE, declared BEFORE the container it lives inside.
     *
     * mm<n> is the low 64 bits of the PHYSICAL x87 slot fpregs[n] -- the
     * architecture aliases them, and QEMU stores them that way
     * (FPReg is a union of floatx80 and MMXReg).  Unlike ST(i) the index is
     * not relative to anything: MMX_OFFSET(n) IS mm<n>, so here the range is
     * the register and the file can be declared element by element.
     *
     * SPELLED st<n>, which is not a compromise.  The consumer's namespace is
     * the GDB stub's, and the i386 stub has no mm<n>: `st<n>` is the only
     * name those bytes have there, which is why the operand walk beside this
     * publishes an MMX operand as REG_FPR<n> already.  The two spellings
     * denote the same eight slots by the same index whenever an MMX
     * instruction is running, and QEMU is what guarantees it -- every MMX
     * form emits gen_helper_enter_mmx(), and helper_enter_mmx() sets
     * env->fpstt = 0, so ST(i) and the physical slot coincide for exactly
     * the instructions this file answers for.
     *
     * ORDER MATTERS AND IS THE POINT.  insn_dataflow_field_reg() walks the
     * declarations in order and takes the first whose element CONTAINS the
     * access, so the narrow file has to come first or an eight-byte read at
     * fpregs[n] would be answered by the 128-byte container.  A read wider
     * than eight bytes declines here and the container below answers it.
     */
    {
        static const char *const mmx_names[8] = {
            "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
        };

        insn_dataflow_declare_regfile(
            NULL, mmx_names,
            offsetof(CPUX86State, fpregs[0].mmx),
            sizeof(((CPUX86State *)0)->fpregs[0]),
            sizeof(((CPUX86State *)0)->fpregs[0].mmx), 8);
    }

    insn_dataflow_declare_regfile("fpregs", NULL,
                                  offsetof(CPUX86State, fpregs),
                                  sizeof(((CPUX86State *)0)->fpregs),
                                  sizeof(((CPUX86State *)0)->fpregs), 1);
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
    /*
     * cc_srcT is the fifth member of the flags lowering and the only one that
     * is not a global.  For the subtract family CF is `CC_SRCT < CC_SRC`
     * unsigned, and CC_SRCT -- the compare's first operand -- is
     * cc_dst + cc_src, so it holds nothing the flags do not already hold; it
     * is cached here because recomputing it inside a block is pointless work
     * and because it only ever has to live as far as the next TB boundary
     * (i386_tr_init_disas_context starts every block at CC_OP_DYNAMIC, so
     * nothing reads it before this block's own compare fills it).
     *
     * Which means a read of it that this instruction did not fill is a read
     * of the FLAGS, and the extractor must not publish it as a read of the
     * register the compare happened to take.  Only this file knows that, so
     * this file says it, beside the tcg_temp_new() that creates the temp.
     */
    insn_dataflow_note_repr_carrier(tcgv_tl_temp(dc->cc_srcT),
                                    tcgv_tl_temp(cpu_cc_src));
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
        gen_update_cc_op(dc);
        gen_jmp_rel_csize(dc, 0, 0);
        break;
    case DISAS_EOB_NEXT:
    case DISAS_EOB_INHIBIT_IRQ:
        assert(dc->base.pc_next == dc->pc);
        gen_update_eip_cur(dc);
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
