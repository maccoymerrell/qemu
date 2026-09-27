/*
 * riscv TCG cpu class initialization
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2017-2018 SiFive, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "exec/exec-all.h"
#include "exec/translation-block.h"
#include "tcg-cpu.h"
#include "cpu.h"
#include "internals.h"
#include "pmu.h"
#include "time_helper.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/accel.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "accel/accel-cpu-target.h"
#include "accel/tcg/cpu-ops.h"
#include "tcg/tcg.h"
#include "exec/plugin-gen.h"
#ifndef CONFIG_USER_ONLY
#include "hw/boards.h"
#endif

/* Hash that stores user set extensions */
static GHashTable *multi_ext_user_opts;
static GHashTable *misa_ext_user_opts;

static GHashTable *multi_ext_implied_rules;
static GHashTable *misa_ext_implied_rules;

static bool cpu_cfg_ext_is_user_set(uint32_t ext_offset)
{
    return g_hash_table_contains(multi_ext_user_opts,
                                 GUINT_TO_POINTER(ext_offset));
}

static bool cpu_misa_ext_is_user_set(uint32_t misa_bit)
{
    return g_hash_table_contains(misa_ext_user_opts,
                                 GUINT_TO_POINTER(misa_bit));
}

static void cpu_cfg_ext_add_user_opt(uint32_t ext_offset, bool value)
{
    g_hash_table_insert(multi_ext_user_opts, GUINT_TO_POINTER(ext_offset),
                        (gpointer)value);
}

static void cpu_misa_ext_add_user_opt(uint32_t bit, bool value)
{
    g_hash_table_insert(misa_ext_user_opts, GUINT_TO_POINTER(bit),
                        (gpointer)value);
}

static void riscv_cpu_write_misa_bit(RISCVCPU *cpu, uint32_t bit,
                                     bool enabled)
{
    CPURISCVState *env = &cpu->env;

    if (enabled) {
        env->misa_ext |= bit;
        env->misa_ext_mask |= bit;
    } else {
        env->misa_ext &= ~bit;
        env->misa_ext_mask &= ~bit;
    }
}

static const char *cpu_priv_ver_to_str(int priv_ver)
{
    const char *priv_spec_str = priv_spec_to_str(priv_ver);

    g_assert(priv_spec_str);

    return priv_spec_str;
}

static void riscv_cpu_synchronize_from_tb(CPUState *cs,
                                          const TranslationBlock *tb)
{
    if (!(tb_cflags(tb) & CF_PCREL)) {
        RISCVCPU *cpu = RISCV_CPU(cs);
        CPURISCVState *env = &cpu->env;
        RISCVMXL xl = FIELD_EX32(tb->flags, TB_FLAGS, XL);

        tcg_debug_assert(!tcg_cflags_has(cs, CF_PCREL));

        if (xl == MXL_RV32) {
            env->pc = (int32_t) tb->pc;
        } else {
            env->pc = tb->pc;
        }
    }
}

static void riscv_restore_state_to_opc(CPUState *cs,
                                       const TranslationBlock *tb,
                                       const uint64_t *data)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    RISCVMXL xl = FIELD_EX32(tb->flags, TB_FLAGS, XL);
    target_ulong pc;

    if (tb_cflags(tb) & CF_PCREL) {
        pc = (env->pc & TARGET_PAGE_MASK) | data[0];
    } else {
        pc = data[0];
    }

    if (xl == MXL_RV32) {
        env->pc = (int32_t)pc;
    } else {
        env->pc = pc;
    }
    env->bins = data[1];
    env->excp_uw2 = data[2];
}

#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
static void riscv_get_plugin_state(CPUState *cs, int *priv, uint64_t *asid,
                                   bool *mmu_on)
{
    CPURISCVState *env = cpu_env(cs);
    *priv = env->priv;     /* PRV_U(0) = user, PRV_S(1)/PRV_M(3) privileged */
    *asid = env->satp;     /* SATP: page-table base + ASID */
    /*
     * Translation active iff not M-mode and SATP selects a paging mode
     * (SATP != 0 => MODE field non-Bare).
     */
    *mmu_on = (env->priv != PRV_M) && (env->satp != 0);
}

static bool riscv_vaddr_is_kernel(CPUState *cs, uint64_t vaddr)
{
    CPURISCVState *env = cpu_env(cs);
    unsigned va_bits;

    /*
     * A paged RV64 VA must be sign-extended (canonical) from the width of the
     * active SATP mode: Sv39 -> 39 bits, Sv48 -> 48, Sv57 -> 57.  User VAs
     * occupy the low canonical half (sign bit clear); the kernel half is the
     * high, all-ones-extended range (sign bit set), where the OS maps kernel
     * text.  The guest PC reaches the plugin already sign-extended to 64 bits,
     * so "kernel" is exactly the addresses whose bits above the sign bit are
     * all ones -- a threshold derived from the live paging width.  With paging
     * Bare, in M-mode (translation bypassed), or on RV32 (not a system-mode
     * target; its 32-bit VA is not 64-bit sign-extended), there is no such
     * kernel/user split -- report user. */
    if (env->priv == PRV_M || riscv_cpu_mxl(env) == MXL_RV32) {
        return false;
    }
    switch (get_field(env->satp, SATP64_MODE)) {
    case VM_1_10_SV39: va_bits = 39; break;
    case VM_1_10_SV48: va_bits = 48; break;
    case VM_1_10_SV57: va_bits = 57; break;
    default:           return false;   /* Bare / unknown: do not classify */
    }
    return vaddr_in_upper_half(vaddr, va_bits);
}

static uint64_t riscv_get_plugin_thread_ptr(CPUState *cs)
{
    CPURISCVState *env = cpu_env(cs);
    /*
     * tp (x4), the psABI thread pointer, the register alone.  It names
     * the thread at user privilege only: tp is a general-purpose register
     * a privileged mode may use for anything of its own (a kernel's trap
     * entry is free to swap it with a scratch CSR), so no answer is given
     * above user -- this target installs no tracks-current hook, and no
     * kernel convention for the tp/sscratch pair is consulted.
     */
    return env->gpr[4];
}

static uint64_t riscv_get_plugin_sp(CPUState *cs)
{
    return cpu_env(cs)->gpr[2];
}

/*
 * TCGCPUOps::plugin_clock_resync for RISC-V -- see the contract in
 * include/accel/tcg/cpu-ops.h.
 *
 * RISC-V's audit.  The guest reads time through the `time` CSR, which is
 * rdtime_fn into the ACLINT mtime counter, itself a function of
 * QEMU_CLOCK_VIRTUAL: frozen and thawed at the same value, so the counter
 * needs no re-derivation.  The armed host timers are three -- the ACLINT
 * machine timer behind mtimecmp (device state, but a one-shot QEMUTimer that
 * does not re-arm itself), and the Sstc env->stimer/env->vstimer behind
 * stimecmp/vstimecmp (architectural registers inside the rolled-back
 * snapshot).  All three are re-armed from their compare registers, and any
 * expiry the vstimer gate deferred or the restore erased is re-delivered, by
 * riscv_cpu_plugin_resync_timers.
 *
 * The pending-interrupt side has two halves.  CPU_INTERRUPT_HARD is
 * recomputed from the restored mip (riscv_cpu_interrupt suppresses line
 * drives for the whole excursion, so line and register can disagree in either
 * direction), and the externally-asserted mip bits an excursion would
 * otherwise have swallowed are replayed by cpu_plugin_arch_state_restore
 * before we get here.
 *
 * CPU_PLUGIN_CLOCK_CB_WINDOW_END needs nothing: every RISC-V counter is a
 * pure function of the virtual clock.
 */
static void riscv_plugin_clock_resync(CPUState *cs,
                                      CPUPluginClockResyncReason reason)
{
    if (reason != CPU_PLUGIN_CLOCK_EXCURSION_END) {
        return;
    }
    riscv_cpu_plugin_resync_timers(cs);
}
#endif

#ifdef CONFIG_PLUGIN
/* The register behind a CPURISCVState field (TCGCPUOps.plugin_reg_resolve) */
static int riscv_plugin_reg_resolve(CPUState *cs, intptr_t off, unsigned size,
                                    PluginRegDesc *d)
{
    static const char *const gpr[] = {
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
        "fp", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
        "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
        "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
    };
    static const char *const fpr[] = {
        "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7",
        "fs0", "fs1", "fa0", "fa1", "fa2", "fa3", "fa4", "fa5",
        "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7",
        "fs8", "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
    };
    int vlenb = riscv_cpu_cfg(cpu_env(cs))->vlenb;
    int i;

#define IN(f) PLUGIN_REG_IN(CPURISCVState, f, off)
#define ELT(f) PLUGIN_REG_ELT(CPURISCVState, f, off)
    if (IN(gpr)) {
        i = ELT(gpr);
        return plugin_reg_desc(d, i ? QEMU_PLUGIN_REG_GPR : QEMU_PLUGIN_REG_ZERO,
                               i, 8, "%s", gpr[i]);
    }
    if (IN(vreg) && vlenb) {    /* the stride is the run-time VLEN */
        i = (off - offsetof(CPURISCVState, vreg)) / vlenb;
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_VECTOR, i, vlenb, "v%d", i);
    }
    if (IN(fpr)) {
        i = ELT(fpr);
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_FP, i, 8, "%s", fpr[i]);
    }
    if (IN(frm)) {
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_CONTROL, 0, 8, "frm");
    }
    if (IN(vl)) {
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_CONTROL, 1, 8, "vl");
    }
    if (IN(vtype) || IN(vill)) {
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_CONTROL, 2, 8, "vtype");
    }
    if (IN(vstart)) {
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_CONTROL, 3, 8, "vstart");
    }
    if (IN(vxrm)) {
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_CONTROL, 4, 8, "vxrm");
    }
    if (IN(vxsat)) {
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_CONTROL, 5, 8, "vxsat");
    }
    /*
     * The pc, the reservation, fault bookkeeping, and mstatus, whose FS/VS
     * dirty marking every FP and vector instruction performs for the OS's
     * context switch, not as a data access the instruction makes.
     */
#ifndef CONFIG_USER_ONLY
    if (IN(mstatus)) {
        return PLUGIN_REG_DROP;
    }
#endif
    if (off < 0 || IN(pc) || IN(load_res) || IN(load_val) || IN(bins) ||
        IN(badaddr) || IN(fp_status) || IN(priv) || IN(retxh) || IN(elp) ||
        IN(sw_check_code) || IN(xl)) {
        return PLUGIN_REG_DROP;
    }
#undef IN
#undef ELT
    return PLUGIN_REG_UNKNOWN;
}

/*
 * The word of every pattern of insn32/insn16/xthead/XVentanaCondOps.decode
 * (TCGCPUOps.plugin_word); insn16 patterns named like insn32's share the
 * row.  jal/jalr state their call/return/jump flavour in trans_rvi.c.inc.
 * Zicbop prefetch.{i,r,w} are ORI with rd=x0 (not decoded apart): int.or.
 */
#define IA PLUGIN_WORD_IMM_ADDR
static const PluginWordRow riscv_words[] = {
    { "int.add", 0, "add addi addiw addw addd addid amoadd_b amoadd_h "
                    "amoadd_w amoadd_d" },
    { "int.sub", 0, "sub subw subd" },
    /* Zba is the address-generation extension; th.addsl is Zba's shNadd */
    { "int.lea", 0, "add_uw sh1add sh2add sh3add sh1add_uw sh2add_uw "
                    "sh3add_uw th_addsl1 th_addsl2 th_addsl3" },
    { "int.lea", IA, "auipc" },
    { "int.mov", 0, "lui cm_mva01s cm_mvsa01" },
    /* Zimop: imm is the MOP number, a selector (rd := 0) */
    { "int.mov", PLUGIN_WORD_NO_IMM, "mop_r_n mop_rr_n" },
    { "int.mul", 0, "mul mulh mulhsu mulhu mulw muld c_mul clmul clmulh "
                    "clmulr" },
    { "int.div", 0, "div divu rem remu divw divuw remw remuw divd divud remd "
                    "remud" },
    { "int.madd", 0, "th_mula th_mulah th_mulaw" },
    { "int.msub", 0, "th_muls th_mulsh th_mulsw" },
    { "int.and", 0, "and andi amoand_b amoand_h amoand_w amoand_d" },
    { "int.or", 0, "or ori amoor_b amoor_h amoor_w amoor_d" },
    { "int.xor", 0, "xor xori amoxor_b amoxor_h amoxor_w amoxor_d" },
    { "int.andn", 0, "andn" },
    { "int.orn", 0, "orn" },
    { "int.xnor", 0, "xnor" },
    { "int.not", 0, "c_not" },
    { "int.shl", 0, "sll slli sllw slliw slld sllid slli_uw" },
    { "int.shr", 0, "srl srli srlw srliw srld srlid" },
    { "int.sar", 0, "sra srai sraw sraiw srad sraid" },
    { "int.rol", 0, "rol rolw" },
    { "int.ror", 0, "ror rori rorw roriw th_srri th_srriw" },
    { "int.setcc", 0, "slt slti sltu sltiu" },
    { "int.minmax", 0, "min minu max maxu" },
    { "int.cmov", 0, "czero_eqz czero_nez th_mveqz th_mvnez vt_maskc "
                     "vt_maskcn" },
    { "int.movsx", 0, "sext_b sext_h c_sext_b c_sext_h" },
    { "int.movzx", 0, "zext_h_32 zext_h_64 c_zext_b c_zext_h c_zext_w" },
    { "int.count", 0, "clz clzw ctz ctzw cpop cpopw th_ff0 th_ff1" },
    { "int.bitrev", 0, "brev8" },
    { "int.bswap", 0, "rev8_32 rev8_64 orc_b th_rev th_revw th_tstnbz" },
    { "int.bitfield", 0, "pack packh packw zip unzip xperm4 xperm8 th_ext "
                         "th_extu" },
    /* bit ops; scalar crypto (Zkn/Zks) too: no int.* crypto word yet */
    { "int.bits", 0, "bclr bclri bext bexti binv binvi bset bseti th_tst "
                     "aes32dsi aes32dsmi aes32esi aes32esmi aes64ds aes64dsm "
                     "aes64es aes64esm aes64im aes64ks1i aes64ks2 sha256sig0 "
                     "sha256sig1 sha256sum0 sha256sum1 sha512sig0 "
                     "sha512sig0h sha512sig0l sha512sig1 sha512sig1h "
                     "sha512sig1l sha512sum0 sha512sum0r sha512sum1 "
                     "sha512sum1r sm3p0 sm3p1 sm4ed sm4ks" },
    { "mem.minmax", 0, "amomin_b amomin_h amomin_w amomin_d amomax_b "
                       "amomax_h amomax_w amomax_d amominu_b amominu_h "
                       "amominu_w amominu_d amomaxu_b amomaxu_h amomaxu_w "
                       "amomaxu_d" },
    { "int.xchg", 0, "amoswap_b amoswap_h amoswap_w amoswap_d ssamoswap_w "
                     "ssamoswap_d amocas_b amocas_h amocas_w amocas_d "
                     "amocas_q" },
    { "mem.load", PLUGIN_WORD_ATOMIC, "lr_w lr_d" },
    { "mem.load", IA, "lb lh lw ld lbu lhu lwu ldu lq c_lbu c_lh c_lhu flh "
                      "flw fld c_flw c_fld" },
    { "mem.store", IA, "sb sh sw sd sq c_sb c_sh fsh fsw fsd c_fsw c_fsd" },
    { "mem.load", 0, "hlv_b hlv_bu hlv_h hlv_hu hlv_w hlv_wu hlv_d hlvx_hu "
                     "hlvx_wu th_lrb th_lrbu th_lrh th_lrhu th_lrw th_lrwu "
                     "th_lrd th_lurb th_lurbu th_lurh th_lurhu th_lurw "
                     "th_lurwu th_lurd th_ldd th_lwd th_lwud th_flrd th_flrw "
                     "th_flurd th_flurw" },
    /* sc_*: atomic by gen_sc's cmpxchg */
    { "mem.store", 0, "sc_w sc_d hsv_b hsv_h hsv_w hsv_d th_srb th_srh "
                      "th_srw th_srd th_surb th_surh th_surw th_surd th_sdd "
                      "th_swd th_fsrd th_fsrw th_fsurd th_fsurw" },
    { "mem.load.wb", 0, "th_lbia th_lbib th_lbuia th_lbuib th_lhia th_lhib "
                        "th_lhuia th_lhuib th_lwia th_lwib th_lwuia th_lwuib "
                        "th_ldia th_ldib" },
    { "mem.store.wb", 0, "th_sbia th_sbib th_shia th_shib th_swia th_swib "
                         "th_sdia th_sdib" },
    { "mem.push", 0, "cm_push sspush" },
    { "mem.pop", 0, "cm_pop sspopchk" },
    { "mem.fence", 0, "fence fence_i sfence_w_inval sfence_inval_ir th_sync "
                      "th_sync_i th_sync_is th_sync_s th_dcache_call "
                      "th_dcache_ciall th_dcache_iall th_dcache_csw "
                      "th_dcache_cisw th_dcache_isw th_icache_iall "
                      "th_icache_ialls th_l2cache_call th_l2cache_ciall "
                      "th_l2cache_iall" },
    { "mem.cache", 0, "cbo_clean cbo_flush cbo_inval th_dcache_cpa "
                      "th_dcache_cipa th_dcache_ipa th_dcache_cva "
                      "th_dcache_civa th_dcache_iva th_dcache_cpal1 "
                      "th_dcache_cval1 th_icache_ipa th_icache_iva" },
    { "mem.zero", 0, "cbo_zero" },
    { "mem.tlb", 0, "sfence_vma hfence_gvma hfence_vvma sinval_vma "
                    "hinval_vvma hinval_gvma th_sfence_vmas" },
    { "branch.cond", 0, "beq bne blt bge bltu bgeu" },
    { "branch.jump", 0, "jal" },
    { "branch.jump.ind", 0, "jalr" },
    { "branch.call.ind", 0, "cm_jalt" },
    { "branch.ret", 0, "cm_popret cm_popretz" },
    { "sys.syscall", 0, "ecall" },
    { "sys.trap", 0, "ebreak illegal c64_illegal" },
    { "sys.eret", 0, "uret sret mret mnret" },
    { "sys.misc", 0, "wfi wrs_nto wrs_sto sctrclr" },
    { "sys.nop", 0, "pause lpad c_mop_n" },
    { "sys.reg", 0, "csrrw csrrs csrrc csrrwi csrrsi csrrci ssrdp" },
    { "fp.add", 0, "fadd_h fadd_s fadd_d" },
    { "fp.sub", 0, "fsub_h fsub_s fsub_d" },
    { "fp.mul", 0, "fmul_h fmul_s fmul_d" },
    { "fp.div", 0, "fdiv_h fdiv_s fdiv_d" },
    { "fp.sqrt", 0, "fsqrt_h fsqrt_s fsqrt_d" },
    { "fp.madd", 0, "fmadd_h fmadd_s fmadd_d fnmadd_h fnmadd_s fnmadd_d" },
    { "fp.msub", 0, "fmsub_h fmsub_s fmsub_d fnmsub_h fnmsub_s fnmsub_d" },
    { "fp.mov", 0, "fsgnj_h fsgnj_s fsgnj_d fsgnjn_h fsgnjn_s fsgnjn_d "
                   "fsgnjx_h fsgnjx_s fsgnjx_d fmv_x_h fmv_h_x fmv_x_w "
                   "fmv_w_x fmv_x_d fmv_d_x fmvh_x_d fmvp_d_x fli_h fli_s "
                   "fli_d th_fmv_hw_x th_fmv_x_hw" },
    { "fp.cvt", 0, "fcvt_w_s fcvt_wu_s fcvt_s_w fcvt_s_wu fcvt_l_s fcvt_lu_s "
                   "fcvt_s_l fcvt_s_lu fcvt_s_d fcvt_d_s fcvt_w_d fcvt_wu_d "
                   "fcvt_d_w fcvt_d_wu fcvt_l_d fcvt_lu_d fcvt_d_l fcvt_d_lu "
                   "fcvt_h_s fcvt_s_h fcvt_h_d fcvt_d_h fcvt_w_h fcvt_wu_h "
                   "fcvt_h_w fcvt_h_wu fcvt_l_h fcvt_lu_h fcvt_h_l fcvt_h_lu "
                   "fcvt_bf16_s fcvt_s_bf16 fcvtmod_w_d fround_h fround_s "
                   "fround_d froundnx_h froundnx_s froundnx_d" },
    { "fp.cmp", 0, "feq_h feq_s feq_d flt_h flt_s flt_d fle_h fle_s fle_d "
                   "fleq_h fleq_s fleq_d fltq_h fltq_s fltq_d fclass_h "
                   "fclass_s fclass_d" },
    { "fp.minmax", 0, "fmin_h fmin_s fmin_d fmax_h fmax_s fmax_d fminm_h "
                      "fminm_s fminm_d fmaxm_h fmaxm_s fmaxm_d" },
    /* RVV: everything on the vector register file is vec.* */
    { "vec.config", 0, "vsetvl vsetvli vsetivli" },
    { "vec.load", 0, "vle8_v vle16_v vle32_v vle64_v vle8ff_v vle16ff_v "
                     "vle32ff_v vle64ff_v vlm_v vlse8_v vlse16_v vlse32_v "
                     "vlse64_v vl1re8_v vl1re16_v vl1re32_v vl1re64_v "
                     "vl2re8_v vl2re16_v vl2re32_v vl2re64_v vl4re8_v "
                     "vl4re16_v vl4re32_v vl4re64_v vl8re8_v vl8re16_v "
                     "vl8re32_v vl8re64_v" },
    { "vec.store", 0, "vse8_v vse16_v vse32_v vse64_v vsm_v vsse8_v vsse16_v "
                      "vsse32_v vsse64_v vs1r_v vs2r_v vs4r_v vs8r_v" },
    { "vec.gather", 0, "vlxei8_v vlxei16_v vlxei32_v vlxei64_v" },
    { "vec.scatter", 0, "vsxei8_v vsxei16_v vsxei32_v vsxei64_v" },
    { "vec.add", 0, "vadd_vv vadd_vx vadd_vi vwaddu_vv vwaddu_vx vwadd_vv "
                    "vwadd_vx vwaddu_wv vwaddu_wx vwadd_wv vwadd_wx vadc_vvm "
                    "vadc_vxm vadc_vim vmadc_vvm vmadc_vxm vmadc_vim "
                    "vsaddu_vv vsaddu_vx vsaddu_vi vsadd_vv vsadd_vx "
                    "vsadd_vi vaadd_vv vaadd_vx vaaddu_vv vaaddu_vx vfadd_vv "
                    "vfadd_vf vfwadd_vv vfwadd_vf vfwadd_wv vfwadd_wf "
                    "vredsum_vs vwredsumu_vs vwredsum_vs vfredusum_vs "
                    "vfredosum_vs vfwredusum_vs vfwredosum_vs" },
    { "vec.sub", 0, "vsub_vv vsub_vx vrsub_vx vrsub_vi vwsubu_vv vwsubu_vx "
                    "vwsub_vv vwsub_vx vwsubu_wv vwsubu_wx vwsub_wv vwsub_wx "
                    "vsbc_vvm vsbc_vxm vmsbc_vvm vmsbc_vxm vssubu_vv "
                    "vssubu_vx vssub_vv vssub_vx vasub_vv vasub_vx vasubu_vv "
                    "vasubu_vx vfsub_vv vfsub_vf vfrsub_vf vfwsub_vv "
                    "vfwsub_vf vfwsub_wv vfwsub_wf" },
    { "vec.mul", 0, "vmul_vv vmul_vx vmulh_vv vmulh_vx vmulhu_vv vmulhu_vx "
                    "vmulhsu_vv vmulhsu_vx vwmulu_vv vwmulu_vx vwmulsu_vv "
                    "vwmulsu_vx vwmul_vv vwmul_vx vsmul_vv vsmul_vx vfmul_vv "
                    "vfmul_vf vfwmul_vv vfwmul_vf vclmul_vv vclmul_vx "
                    "vclmulh_vv vclmulh_vx" },
    { "vec.div", 0, "vdivu_vv vdivu_vx vdiv_vv vdiv_vx vremu_vv vremu_vx "
                    "vrem_vv vrem_vx vfdiv_vv vfdiv_vf vfrdiv_vf vfrec7_v" },
    { "vec.sqrt", 0, "vfsqrt_v vfrsqrt7_v" },
    { "vec.madd", 0, "vmacc_vv vmacc_vx vmadd_vv vmadd_vx vwmaccu_vv "
                     "vwmaccu_vx vwmacc_vv vwmacc_vx vwmaccsu_vv vwmaccsu_vx "
                     "vwmaccus_vx vfmacc_vv vfmacc_vf vfnmacc_vv vfnmacc_vf "
                     "vfmadd_vv vfmadd_vf vfnmadd_vv vfnmadd_vf vfwmacc_vv "
                     "vfwmacc_vf vfwnmacc_vv vfwnmacc_vf vfwmaccbf16_vv "
                     "vfwmaccbf16_vf" },
    { "vec.msub", 0, "vnmsac_vv vnmsac_vx vnmsub_vv vnmsub_vx vfmsac_vv "
                     "vfmsac_vf vfnmsac_vv vfnmsac_vf vfmsub_vv vfmsub_vf "
                     "vfnmsub_vv vfnmsub_vf vfwmsac_vv vfwmsac_vf "
                     "vfwnmsac_vv vfwnmsac_vf" },
    { "vec.logic", 0, "vand_vv vand_vx vand_vi vor_vv vor_vx vor_vi vxor_vv "
                      "vxor_vx vxor_vi vandn_vv vandn_vx vredand_vs "
                      "vredor_vs vredxor_vs" },
    { "vec.shift", 0, "vsll_vv vsll_vx vsll_vi vsrl_vv vsrl_vx vsrl_vi "
                      "vsra_vv vsra_vx vsra_vi vnsrl_wv vnsrl_wx vnsrl_wi "
                      "vnsra_wv vnsra_wx vnsra_wi vssrl_vv vssrl_vx vssrl_vi "
                      "vssra_vv vssra_vx vssra_vi vnclipu_wv vnclipu_wx "
                      "vnclipu_wi vnclip_wv vnclip_wx vnclip_wi vwsll_vv "
                      "vwsll_vx vwsll_vi vrol_vv vrol_vx vror_vv vror_vx "
                      "vror_vi" },
    { "vec.cmp", 0, "vmseq_vv vmseq_vx vmseq_vi vmsne_vv vmsne_vx vmsne_vi "
                    "vmsltu_vv vmsltu_vx vmslt_vv vmslt_vx vmsleu_vv "
                    "vmsleu_vx vmsleu_vi vmsle_vv vmsle_vx vmsle_vi "
                    "vmsgtu_vx vmsgtu_vi vmsgt_vx vmsgt_vi" },
    { "vec.minmax", 0, "vminu_vv vminu_vx vmin_vv vmin_vx vmaxu_vv vmaxu_vx "
                       "vmax_vv vmax_vx vredminu_vs vredmin_vs vredmaxu_vs "
                       "vredmax_vs" },
    { "vec.fcmp", 0, "vmfeq_vv vmfeq_vf vmfne_vv vmfne_vf vmflt_vv vmflt_vf "
                     "vmfle_vv vmfle_vf vmfgt_vf vmfge_vf vfclass_v vfmin_vv "
                     "vfmin_vf vfmax_vv vfmax_vf vfredmin_vs vfredmax_vs" },
    { "vec.abs", 0, "vfsgnj_vv vfsgnj_vf vfsgnjn_vv vfsgnjn_vf vfsgnjx_vv "
                    "vfsgnjx_vf" },
    { "vec.count", 0, "vbrev8_v vbrev_v vclz_v vctz_v vcpop_v" },
    { "vec.fcvt", 0, "vfcvt_xu_f_v vfcvt_x_f_v vfcvt_f_xu_v vfcvt_f_x_v "
                     "vfcvt_rtz_xu_f_v vfcvt_rtz_x_f_v vfwcvt_xu_f_v "
                     "vfwcvt_x_f_v vfwcvt_f_xu_v vfwcvt_f_x_v vfwcvt_f_f_v "
                     "vfwcvt_rtz_xu_f_v vfwcvt_rtz_x_f_v vfncvt_xu_f_w "
                     "vfncvt_x_f_w vfncvt_f_xu_w vfncvt_f_x_w vfncvt_f_f_w "
                     "vfncvt_rod_f_f_w vfncvt_rtz_xu_f_w vfncvt_rtz_x_f_w "
                     "vfncvtbf16_f_f_w vfwcvtbf16_f_f_v" },
    { "vec.mov", 0, "vmv_v_v vmv_v_x vmv_v_i vmerge_vvm vmerge_vxm "
                    "vmerge_vim vfmerge_vfm vfmv_v_f vmv1r_v vmv2r_v vmv4r_v "
                    "vmv8r_v vid_v vzext_vf2 vzext_vf4 vzext_vf8 vsext_vf2 "
                    "vsext_vf4 vsext_vf8" },
    { "vec.shuf", 0, "vmv_x_s vmv_s_x vfmv_f_s vfmv_s_f vslideup_vx "
                     "vslideup_vi vslide1up_vx vslidedown_vx vslidedown_vi "
                     "vslide1down_vx vfslide1up_vf vfslide1down_vf "
                     "vrgather_vv vrgatherei16_vv vrgather_vx vrgather_vi "
                     "vcompress_vm vrev8_v" },
    { "vec.pred", 0, "vmand_mm vmnand_mm vmandn_mm vmxor_mm vmor_mm vmnor_mm "
                     "vmorn_mm vmxnor_mm vcpop_m vfirst_m vmsbf_m vmsif_m "
                     "vmsof_m viota_m" },
    { "vec.crypto", 0, "vaesef_vv vaesef_vs vaesdf_vv vaesdf_vs vaesem_vv "
                       "vaesem_vs vaesdm_vv vaesdm_vs vaesz_vs vaeskf1_vi "
                       "vaeskf2_vi vsha2ms_vv vsha2ch_vv vsha2cl_vv "
                       "vsm3me_vv vsm3c_vi vghsh_vv vgmul_vv vsm4k_vi "
                       "vsm4r_vv vsm4r_vs" },
};
#undef IA

static const char *riscv_plugin_word(const char *pattern, unsigned *flags)
{
    return plugin_word_lookup(riscv_words, ARRAY_SIZE(riscv_words), pattern,
                              flags);
}
#endif

static const TCGCPUOps riscv_tcg_ops = {
    .initialize = riscv_translate_init,
    .translate_code = riscv_translate_code,
    .synchronize_from_tb = riscv_cpu_synchronize_from_tb,
    .restore_state_to_opc = riscv_restore_state_to_opc,
#ifdef CONFIG_PLUGIN
    .plugin_reg_resolve = riscv_plugin_reg_resolve,
    .plugin_word = riscv_plugin_word,
#endif
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
    .get_plugin_state = riscv_get_plugin_state,
    .get_plugin_thread_ptr = riscv_get_plugin_thread_ptr,
    .get_plugin_sp = riscv_get_plugin_sp,
    .vaddr_is_kernel = riscv_vaddr_is_kernel,
    .plugin_clock_resync = riscv_plugin_clock_resync,
#endif

#ifndef CONFIG_USER_ONLY
    .tlb_fill = riscv_cpu_tlb_fill,
    .cpu_exec_interrupt = riscv_cpu_exec_interrupt,
    .cpu_exec_halt = riscv_cpu_has_work,
    .do_interrupt = riscv_cpu_do_interrupt,
    .do_transaction_failed = riscv_cpu_do_transaction_failed,
    .do_unaligned_access = riscv_cpu_do_unaligned_access,
    .debug_excp_handler = riscv_cpu_debug_excp_handler,
    .debug_check_breakpoint = riscv_cpu_debug_check_breakpoint,
    .debug_check_watchpoint = riscv_cpu_debug_check_watchpoint,
#endif /* !CONFIG_USER_ONLY */
};

static int cpu_cfg_ext_get_min_version(uint32_t ext_offset)
{
    const RISCVIsaExtData *edata;

    for (edata = isa_edata_arr; edata && edata->name; edata++) {
        if (edata->ext_enable_offset != ext_offset) {
            continue;
        }

        return edata->min_version;
    }

    g_assert_not_reached();
}

static const char *cpu_cfg_ext_get_name(uint32_t ext_offset)
{
    const RISCVCPUMultiExtConfig *feat;
    const RISCVIsaExtData *edata;

    for (edata = isa_edata_arr; edata->name != NULL; edata++) {
        if (edata->ext_enable_offset == ext_offset) {
            return edata->name;
        }
    }

    for (feat = riscv_cpu_named_features; feat->name != NULL; feat++) {
        if (feat->offset == ext_offset) {
            return feat->name;
        }
    }

    g_assert_not_reached();
}

static bool cpu_cfg_offset_is_named_feat(uint32_t ext_offset)
{
    const RISCVCPUMultiExtConfig *feat;

    for (feat = riscv_cpu_named_features; feat->name != NULL; feat++) {
        if (feat->offset == ext_offset) {
            return true;
        }
    }

    return false;
}

static void riscv_cpu_enable_named_feat(RISCVCPU *cpu, uint32_t feat_offset)
{
     /*
      * All other named features are already enabled
      * in riscv_tcg_cpu_instance_init().
      */
    switch (feat_offset) {
    case CPU_CFG_OFFSET(ext_zic64b):
        cpu->cfg.cbom_blocksize = 64;
        cpu->cfg.cbop_blocksize = 64;
        cpu->cfg.cboz_blocksize = 64;
        break;
    case CPU_CFG_OFFSET(ext_sha):
        if (!cpu_misa_ext_is_user_set(RVH)) {
            riscv_cpu_write_misa_bit(cpu, RVH, true);
        }
        /* fallthrough */
    case CPU_CFG_OFFSET(ext_ssstateen):
        cpu->cfg.ext_smstateen = true;
        break;
    }
}

static void cpu_bump_multi_ext_priv_ver(CPURISCVState *env,
                                        uint32_t ext_offset)
{
    int ext_priv_ver;

    if (env->priv_ver == PRIV_VERSION_LATEST) {
        return;
    }

    ext_priv_ver = cpu_cfg_ext_get_min_version(ext_offset);

    if (env->priv_ver < ext_priv_ver) {
        /*
         * Note: the 'priv_spec' command line option, if present,
         * will take precedence over this priv_ver bump.
         */
        env->priv_ver = ext_priv_ver;
    }
}

static void cpu_cfg_ext_auto_update(RISCVCPU *cpu, uint32_t ext_offset,
                                    bool value)
{
    CPURISCVState *env = &cpu->env;
    bool prev_val = isa_ext_is_enabled(cpu, ext_offset);
    int min_version;

    if (prev_val == value) {
        return;
    }

    if (cpu_cfg_ext_is_user_set(ext_offset)) {
        return;
    }

    if (value && env->priv_ver != PRIV_VERSION_LATEST) {
        /* Do not enable it if priv_ver is older than min_version */
        min_version = cpu_cfg_ext_get_min_version(ext_offset);
        if (env->priv_ver < min_version) {
            return;
        }
    }

    isa_ext_update_enabled(cpu, ext_offset, value);
}

static void riscv_cpu_validate_misa_priv(CPURISCVState *env, Error **errp)
{
    if (riscv_has_ext(env, RVH) && env->priv_ver < PRIV_VERSION_1_12_0) {
        error_setg(errp, "H extension requires priv spec 1.12.0");
        return;
    }
}

static void riscv_cpu_validate_v(CPURISCVState *env, RISCVCPUConfig *cfg,
                                 Error **errp)
{
    uint32_t min_vlen;
    uint32_t vlen = cfg->vlenb << 3;

    if (riscv_has_ext(env, RVV)) {
        min_vlen = 128;
    } else if (cfg->ext_zve64x) {
        min_vlen = 64;
    } else if (cfg->ext_zve32x) {
        min_vlen = 32;
    }

    if (vlen > RV_VLEN_MAX || vlen < min_vlen) {
        error_setg(errp,
                   "Vector extension implementation only supports VLEN "
                   "in the range [%d, %d]", min_vlen, RV_VLEN_MAX);
        return;
    }

    if (cfg->elen > 64 || cfg->elen < 8) {
        error_setg(errp,
                   "Vector extension implementation only supports ELEN "
                   "in the range [8, 64]");
        return;
    }

    if (vlen < cfg->elen) {
        error_setg(errp, "Vector extension implementation requires VLEN "
                         "to be greater than or equal to ELEN");
        return;
    }
}

static void riscv_cpu_disable_priv_spec_isa_exts(RISCVCPU *cpu)
{
    CPURISCVState *env = &cpu->env;
    const RISCVIsaExtData *edata;

    /* Force disable extensions if priv spec version does not match */
    for (edata = isa_edata_arr; edata && edata->name; edata++) {
        if (isa_ext_is_enabled(cpu, edata->ext_enable_offset) &&
            (env->priv_ver < edata->min_version)) {
            /*
             * These two extensions are always enabled as they were supported
             * by QEMU before they were added as extensions in the ISA.
             */
            if (!strcmp(edata->name, "zicntr") ||
                !strcmp(edata->name, "zihpm")) {
                continue;
            }

            isa_ext_update_enabled(cpu, edata->ext_enable_offset, false);

            /*
             * Do not show user warnings for named features that users
             * can't enable/disable in the command line. See commit
             * 68c9e54bea for more info.
             */
            if (cpu_cfg_offset_is_named_feat(edata->ext_enable_offset)) {
                continue;
            }
#ifndef CONFIG_USER_ONLY
            warn_report("disabling %s extension for hart 0x" TARGET_FMT_lx
                        " because privilege spec version does not match",
                        edata->name, env->mhartid);
#else
            warn_report("disabling %s extension because "
                        "privilege spec version does not match",
                        edata->name);
#endif
        }
    }
}

static void riscv_cpu_update_named_features(RISCVCPU *cpu)
{
    if (cpu->env.priv_ver >= PRIV_VERSION_1_11_0) {
        cpu->cfg.has_priv_1_11 = true;
    }

    if (cpu->env.priv_ver >= PRIV_VERSION_1_12_0) {
        cpu->cfg.has_priv_1_12 = true;
    }

    if (cpu->env.priv_ver >= PRIV_VERSION_1_13_0) {
        cpu->cfg.has_priv_1_13 = true;
    }

    cpu->cfg.ext_zic64b = cpu->cfg.cbom_blocksize == 64 &&
                          cpu->cfg.cbop_blocksize == 64 &&
                          cpu->cfg.cboz_blocksize == 64;

    cpu->cfg.ext_ssstateen = cpu->cfg.ext_smstateen;

    cpu->cfg.ext_sha = riscv_has_ext(&cpu->env, RVH) &&
                       cpu->cfg.ext_ssstateen;

    cpu->cfg.ext_ziccrse = cpu->cfg.has_priv_1_11;
}

static void riscv_cpu_validate_g(RISCVCPU *cpu)
{
    const char *warn_msg = "RVG mandates disabled extension %s";
    uint32_t g_misa_bits[] = {RVI, RVM, RVA, RVF, RVD};
    bool send_warn = cpu_misa_ext_is_user_set(RVG);

    for (int i = 0; i < ARRAY_SIZE(g_misa_bits); i++) {
        uint32_t bit = g_misa_bits[i];

        if (riscv_has_ext(&cpu->env, bit)) {
            continue;
        }

        if (!cpu_misa_ext_is_user_set(bit)) {
            riscv_cpu_write_misa_bit(cpu, bit, true);
            continue;
        }

        if (send_warn) {
            warn_report(warn_msg, riscv_get_misa_ext_name(bit));
        }
    }

    if (!cpu->cfg.ext_zicsr) {
        if (!cpu_cfg_ext_is_user_set(CPU_CFG_OFFSET(ext_zicsr))) {
            cpu->cfg.ext_zicsr = true;
        } else if (send_warn) {
            warn_report(warn_msg, "zicsr");
        }
    }

    if (!cpu->cfg.ext_zifencei) {
        if (!cpu_cfg_ext_is_user_set(CPU_CFG_OFFSET(ext_zifencei))) {
            cpu->cfg.ext_zifencei = true;
        } else if (send_warn) {
            warn_report(warn_msg, "zifencei");
        }
    }
}

static void riscv_cpu_validate_b(RISCVCPU *cpu)
{
    const char *warn_msg = "RVB mandates disabled extension %s";

    if (!cpu->cfg.ext_zba) {
        if (!cpu_cfg_ext_is_user_set(CPU_CFG_OFFSET(ext_zba))) {
            cpu->cfg.ext_zba = true;
        } else {
            warn_report(warn_msg, "zba");
        }
    }

    if (!cpu->cfg.ext_zbb) {
        if (!cpu_cfg_ext_is_user_set(CPU_CFG_OFFSET(ext_zbb))) {
            cpu->cfg.ext_zbb = true;
        } else {
            warn_report(warn_msg, "zbb");
        }
    }

    if (!cpu->cfg.ext_zbs) {
        if (!cpu_cfg_ext_is_user_set(CPU_CFG_OFFSET(ext_zbs))) {
            cpu->cfg.ext_zbs = true;
        } else {
            warn_report(warn_msg, "zbs");
        }
    }
}

/*
 * Check consistency between chosen extensions while setting
 * cpu->cfg accordingly.
 */
void riscv_cpu_validate_set_extensions(RISCVCPU *cpu, Error **errp)
{
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(cpu);
    CPURISCVState *env = &cpu->env;
    Error *local_err = NULL;

    if (riscv_has_ext(env, RVG)) {
        riscv_cpu_validate_g(cpu);
    }

    if (riscv_has_ext(env, RVB)) {
        riscv_cpu_validate_b(cpu);
    }

    if (riscv_has_ext(env, RVI) && riscv_has_ext(env, RVE)) {
        error_setg(errp,
                   "I and E extensions are incompatible");
        return;
    }

    if (!riscv_has_ext(env, RVI) && !riscv_has_ext(env, RVE)) {
        error_setg(errp,
                   "Either I or E extension must be set");
        return;
    }

    if (riscv_has_ext(env, RVS) && !riscv_has_ext(env, RVU)) {
        error_setg(errp,
                   "Setting S extension without U extension is illegal");
        return;
    }

    if (riscv_has_ext(env, RVH) && !riscv_has_ext(env, RVI)) {
        error_setg(errp,
                   "H depends on an I base integer ISA with 32 x registers");
        return;
    }

    if (riscv_has_ext(env, RVH) && !riscv_has_ext(env, RVS)) {
        error_setg(errp, "H extension implicitly requires S-mode");
        return;
    }

    if (riscv_has_ext(env, RVF) && !cpu->cfg.ext_zicsr) {
        error_setg(errp, "F extension requires Zicsr");
        return;
    }

    if ((cpu->cfg.ext_zacas) && !riscv_has_ext(env, RVA)) {
        error_setg(errp, "Zacas extension requires A extension");
        return;
    }

    if ((cpu->cfg.ext_zawrs) && !riscv_has_ext(env, RVA)) {
        error_setg(errp, "Zawrs extension requires A extension");
        return;
    }

    if (cpu->cfg.ext_zfa && !riscv_has_ext(env, RVF)) {
        error_setg(errp, "Zfa extension requires F extension");
        return;
    }

    if (cpu->cfg.ext_zfhmin && !riscv_has_ext(env, RVF)) {
        error_setg(errp, "Zfh/Zfhmin extensions require F extension");
        return;
    }

    if (cpu->cfg.ext_zfbfmin && !riscv_has_ext(env, RVF)) {
        error_setg(errp, "Zfbfmin extension depends on F extension");
        return;
    }

    if (riscv_has_ext(env, RVD) && !riscv_has_ext(env, RVF)) {
        error_setg(errp, "D extension requires F extension");
        return;
    }

    if (cpu->cfg.ext_zve32x) {
        riscv_cpu_validate_v(env, &cpu->cfg, &local_err);
        if (local_err != NULL) {
            error_propagate(errp, local_err);
            return;
        }
    }

    /* The Zve64d extension depends on the Zve64f extension */
    if (cpu->cfg.ext_zve64d) {
        if (!riscv_has_ext(env, RVD)) {
            error_setg(errp, "Zve64d/V extensions require D extension");
            return;
        }
    }

    /* The Zve32f extension depends on the Zve32x extension */
    if (cpu->cfg.ext_zve32f) {
        if (!riscv_has_ext(env, RVF)) {
            error_setg(errp, "Zve32f/Zve64f extensions require F extension");
            return;
        }
    }

    if (cpu->cfg.ext_zvfhmin && !cpu->cfg.ext_zve32f) {
        error_setg(errp, "Zvfh/Zvfhmin extensions require Zve32f extension");
        return;
    }

    if (cpu->cfg.ext_zvfh && !cpu->cfg.ext_zfhmin) {
        error_setg(errp, "Zvfh extensions requires Zfhmin extension");
        return;
    }

    if (cpu->cfg.ext_zvfbfmin && !cpu->cfg.ext_zve32f) {
        error_setg(errp, "Zvfbfmin extension depends on Zve32f extension");
        return;
    }

    if (cpu->cfg.ext_zvfbfwma && !cpu->cfg.ext_zvfbfmin) {
        error_setg(errp, "Zvfbfwma extension depends on Zvfbfmin extension");
        return;
    }

    if ((cpu->cfg.ext_zdinx || cpu->cfg.ext_zhinxmin) && !cpu->cfg.ext_zfinx) {
        error_setg(errp, "Zdinx/Zhinx/Zhinxmin extensions require Zfinx");
        return;
    }

    if (cpu->cfg.ext_zfinx) {
        if (!cpu->cfg.ext_zicsr) {
            error_setg(errp, "Zfinx extension requires Zicsr");
            return;
        }
        if (riscv_has_ext(env, RVF)) {
            error_setg(errp,
                       "Zfinx cannot be supported together with F extension");
            return;
        }
    }

    if (cpu->cfg.ext_zcmop && !cpu->cfg.ext_zca) {
        error_setg(errp, "Zcmop extensions require Zca");
        return;
    }

    if (mcc->misa_mxl_max != MXL_RV32 && cpu->cfg.ext_zcf) {
        error_setg(errp, "Zcf extension is only relevant to RV32");
        return;
    }

    if (!riscv_has_ext(env, RVF) && cpu->cfg.ext_zcf) {
        error_setg(errp, "Zcf extension requires F extension");
        return;
    }

    if (!riscv_has_ext(env, RVD) && cpu->cfg.ext_zcd) {
        error_setg(errp, "Zcd extension requires D extension");
        return;
    }

    if ((cpu->cfg.ext_zcf || cpu->cfg.ext_zcd || cpu->cfg.ext_zcb ||
         cpu->cfg.ext_zcmp || cpu->cfg.ext_zcmt) && !cpu->cfg.ext_zca) {
        error_setg(errp, "Zcf/Zcd/Zcb/Zcmp/Zcmt extensions require Zca "
                         "extension");
        return;
    }

    if (cpu->cfg.ext_zcd && (cpu->cfg.ext_zcmp || cpu->cfg.ext_zcmt)) {
        error_setg(errp, "Zcmp/Zcmt extensions are incompatible with "
                         "Zcd extension");
        return;
    }

    if (cpu->cfg.ext_zcmt && !cpu->cfg.ext_zicsr) {
        error_setg(errp, "Zcmt extension requires Zicsr extension");
        return;
    }

    if ((cpu->cfg.ext_zvbb || cpu->cfg.ext_zvkb || cpu->cfg.ext_zvkg ||
         cpu->cfg.ext_zvkned || cpu->cfg.ext_zvknha || cpu->cfg.ext_zvksed ||
         cpu->cfg.ext_zvksh) && !cpu->cfg.ext_zve32x) {
        error_setg(errp,
                   "Vector crypto extensions require V or Zve* extensions");
        return;
    }

    if ((cpu->cfg.ext_zvbc || cpu->cfg.ext_zvknhb) && !cpu->cfg.ext_zve64x) {
        error_setg(
            errp,
            "Zvbc and Zvknhb extensions require V or Zve64x extensions");
        return;
    }

    if (cpu->cfg.ext_zicntr && !cpu->cfg.ext_zicsr) {
        if (cpu_cfg_ext_is_user_set(CPU_CFG_OFFSET(ext_zicntr))) {
            error_setg(errp, "zicntr requires zicsr");
            return;
        }
        cpu->cfg.ext_zicntr = false;
    }

    if (cpu->cfg.ext_zihpm && !cpu->cfg.ext_zicsr) {
        if (cpu_cfg_ext_is_user_set(CPU_CFG_OFFSET(ext_zihpm))) {
            error_setg(errp, "zihpm requires zicsr");
            return;
        }
        cpu->cfg.ext_zihpm = false;
    }

    if (cpu->cfg.ext_zicfiss) {
        if (!cpu->cfg.ext_zicsr) {
            error_setg(errp, "zicfiss extension requires zicsr extension");
            return;
        }
        if (!riscv_has_ext(env, RVA)) {
            error_setg(errp, "zicfiss extension requires A extension");
            return;
        }
        if (!riscv_has_ext(env, RVS)) {
            error_setg(errp, "zicfiss extension requires S");
            return;
        }
        if (!cpu->cfg.ext_zimop) {
            error_setg(errp, "zicfiss extension requires zimop extension");
            return;
        }
        if (cpu->cfg.ext_zca && !cpu->cfg.ext_zcmop) {
            error_setg(errp, "zicfiss with zca requires zcmop extension");
            return;
        }
    }

    if (!cpu->cfg.ext_zihpm) {
        cpu->cfg.pmu_mask = 0;
        cpu->pmu_avail_ctrs = 0;
    }

    if (cpu->cfg.ext_zicfilp && !cpu->cfg.ext_zicsr) {
        error_setg(errp, "zicfilp extension requires zicsr extension");
        return;
    }

    if (mcc->misa_mxl_max == MXL_RV32 && cpu->cfg.ext_svukte) {
        error_setg(errp, "svukte is not supported for RV32");
        return;
    }

    if ((cpu->cfg.ext_smctr || cpu->cfg.ext_ssctr) &&
        (!riscv_has_ext(env, RVS) || !cpu->cfg.ext_sscsrind)) {
        if (cpu_cfg_ext_is_user_set(CPU_CFG_OFFSET(ext_smctr)) ||
            cpu_cfg_ext_is_user_set(CPU_CFG_OFFSET(ext_ssctr))) {
            error_setg(errp, "Smctr and Ssctr require S-mode and Sscsrind");
            return;
        }
        cpu->cfg.ext_smctr = false;
        cpu->cfg.ext_ssctr = false;
    }

    /*
     * Disable isa extensions based on priv spec after we
     * validated and set everything we need.
     */
    riscv_cpu_disable_priv_spec_isa_exts(cpu);
}

#ifndef CONFIG_USER_ONLY
static bool riscv_cpu_validate_profile_satp(RISCVCPU *cpu,
                                            RISCVCPUProfile *profile,
                                            bool send_warn)
{
    int satp_max = satp_mode_max_from_map(cpu->cfg.satp_mode.supported);

    if (profile->satp_mode > satp_max) {
        if (send_warn) {
            bool is_32bit = riscv_cpu_is_32bit(cpu);
            const char *req_satp = satp_mode_str(profile->satp_mode, is_32bit);
            const char *cur_satp = satp_mode_str(satp_max, is_32bit);

            warn_report("Profile %s requires satp mode %s, "
                        "but satp mode %s was set", profile->name,
                        req_satp, cur_satp);
        }

        return false;
    }

    return true;
}
#endif

static void riscv_cpu_check_parent_profile(RISCVCPU *cpu,
                                           RISCVCPUProfile *profile,
                                           RISCVCPUProfile *parent)
{
    const char *parent_name;
    bool parent_enabled;

    if (!profile->enabled || !parent) {
        return;
    }

    parent_name = parent->name;
    parent_enabled = object_property_get_bool(OBJECT(cpu), parent_name, NULL);
    profile->enabled = parent_enabled;
}

static void riscv_cpu_validate_profile(RISCVCPU *cpu,
                                       RISCVCPUProfile *profile)
{
    CPURISCVState *env = &cpu->env;
    const char *warn_msg = "Profile %s mandates disabled extension %s";
    bool send_warn = profile->user_set && profile->enabled;
    bool profile_impl = true;
    int i;

#ifndef CONFIG_USER_ONLY
    if (profile->satp_mode != RISCV_PROFILE_ATTR_UNUSED) {
        profile_impl = riscv_cpu_validate_profile_satp(cpu, profile,
                                                       send_warn);
    }
#endif

    if (profile->priv_spec != RISCV_PROFILE_ATTR_UNUSED &&
        profile->priv_spec > env->priv_ver) {
        profile_impl = false;

        if (send_warn) {
            warn_report("Profile %s requires priv spec %s, "
                        "but priv ver %s was set", profile->name,
                        cpu_priv_ver_to_str(profile->priv_spec),
                        cpu_priv_ver_to_str(env->priv_ver));
        }
    }

    for (i = 0; misa_bits[i] != 0; i++) {
        uint32_t bit = misa_bits[i];

        if (!(profile->misa_ext & bit)) {
            continue;
        }

        if (!riscv_has_ext(&cpu->env, bit)) {
            profile_impl = false;

            if (send_warn) {
                warn_report(warn_msg, profile->name,
                            riscv_get_misa_ext_name(bit));
            }
        }
    }

    for (i = 0; profile->ext_offsets[i] != RISCV_PROFILE_EXT_LIST_END; i++) {
        int ext_offset = profile->ext_offsets[i];

        if (!isa_ext_is_enabled(cpu, ext_offset)) {
            profile_impl = false;

            if (send_warn) {
                warn_report(warn_msg, profile->name,
                            cpu_cfg_ext_get_name(ext_offset));
            }
        }
    }

    profile->enabled = profile_impl;

    riscv_cpu_check_parent_profile(cpu, profile, profile->u_parent);
    riscv_cpu_check_parent_profile(cpu, profile, profile->s_parent);
}

static void riscv_cpu_validate_profiles(RISCVCPU *cpu)
{
    for (int i = 0; riscv_profiles[i] != NULL; i++) {
        riscv_cpu_validate_profile(cpu, riscv_profiles[i]);
    }
}

static void riscv_cpu_init_implied_exts_rules(void)
{
    RISCVCPUImpliedExtsRule *rule;
#ifndef CONFIG_USER_ONLY
    MachineState *ms = MACHINE(qdev_get_machine());
#endif
    static bool initialized;
    int i;

    /* Implied rules only need to be initialized once. */
    if (initialized) {
        return;
    }

    for (i = 0; (rule = riscv_misa_ext_implied_rules[i]); i++) {
#ifndef CONFIG_USER_ONLY
        rule->enabled = bitmap_new(ms->smp.cpus);
#endif
        g_hash_table_insert(misa_ext_implied_rules,
                            GUINT_TO_POINTER(rule->ext), (gpointer)rule);
    }

    for (i = 0; (rule = riscv_multi_ext_implied_rules[i]); i++) {
#ifndef CONFIG_USER_ONLY
        rule->enabled = bitmap_new(ms->smp.cpus);
#endif
        g_hash_table_insert(multi_ext_implied_rules,
                            GUINT_TO_POINTER(rule->ext), (gpointer)rule);
    }

    initialized = true;
}

static void cpu_enable_implied_rule(RISCVCPU *cpu,
                                    RISCVCPUImpliedExtsRule *rule)
{
    CPURISCVState *env = &cpu->env;
    RISCVCPUImpliedExtsRule *ir;
    bool enabled = false;
    int i;

#ifndef CONFIG_USER_ONLY
    enabled = test_bit(cpu->env.mhartid, rule->enabled);
#endif

    if (!enabled) {
        /* Enable the implied MISAs. */
        if (rule->implied_misa_exts) {
            for (i = 0; misa_bits[i] != 0; i++) {
                if (rule->implied_misa_exts & misa_bits[i]) {
                    /*
                     * If the user disabled the misa_bit do not re-enable it
                     * and do not apply any implied rules related to it.
                     */
                    if (cpu_misa_ext_is_user_set(misa_bits[i]) &&
                        !(env->misa_ext & misa_bits[i])) {
                        continue;
                    }

                    riscv_cpu_set_misa_ext(env, env->misa_ext | misa_bits[i]);
                    ir = g_hash_table_lookup(misa_ext_implied_rules,
                                             GUINT_TO_POINTER(misa_bits[i]));

                    if (ir) {
                        cpu_enable_implied_rule(cpu, ir);
                    }
                }
            }
        }

        /* Enable the implied extensions. */
        for (i = 0;
             rule->implied_multi_exts[i] != RISCV_IMPLIED_EXTS_RULE_END; i++) {
            cpu_cfg_ext_auto_update(cpu, rule->implied_multi_exts[i], true);

            ir = g_hash_table_lookup(multi_ext_implied_rules,
                                     GUINT_TO_POINTER(
                                         rule->implied_multi_exts[i]));

            if (ir) {
                cpu_enable_implied_rule(cpu, ir);
            }
        }

#ifndef CONFIG_USER_ONLY
        bitmap_set(rule->enabled, cpu->env.mhartid, 1);
#endif
    }
}

/* Zc extension has special implied rules that need to be handled separately. */
static void cpu_enable_zc_implied_rules(RISCVCPU *cpu)
{
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(cpu);
    CPURISCVState *env = &cpu->env;

    if (cpu->cfg.ext_zce) {
        cpu_cfg_ext_auto_update(cpu, CPU_CFG_OFFSET(ext_zca), true);
        cpu_cfg_ext_auto_update(cpu, CPU_CFG_OFFSET(ext_zcb), true);
        cpu_cfg_ext_auto_update(cpu, CPU_CFG_OFFSET(ext_zcmp), true);
        cpu_cfg_ext_auto_update(cpu, CPU_CFG_OFFSET(ext_zcmt), true);

        if (riscv_has_ext(env, RVF) && mcc->misa_mxl_max == MXL_RV32) {
            cpu_cfg_ext_auto_update(cpu, CPU_CFG_OFFSET(ext_zcf), true);
        }
    }

    /* Zca, Zcd and Zcf has a PRIV 1.12.0 restriction */
    if (riscv_has_ext(env, RVC) && env->priv_ver >= PRIV_VERSION_1_12_0) {
        cpu_cfg_ext_auto_update(cpu, CPU_CFG_OFFSET(ext_zca), true);

        if (riscv_has_ext(env, RVF) && mcc->misa_mxl_max == MXL_RV32) {
            cpu_cfg_ext_auto_update(cpu, CPU_CFG_OFFSET(ext_zcf), true);
        }

        if (riscv_has_ext(env, RVD)) {
            cpu_cfg_ext_auto_update(cpu, CPU_CFG_OFFSET(ext_zcd), true);
        }
    }
}

static void riscv_cpu_enable_implied_rules(RISCVCPU *cpu)
{
    RISCVCPUImpliedExtsRule *rule;
    int i;

    /* Enable the implied extensions for Zc. */
    cpu_enable_zc_implied_rules(cpu);

    /* Enable the implied MISAs. */
    for (i = 0; (rule = riscv_misa_ext_implied_rules[i]); i++) {
        if (riscv_has_ext(&cpu->env, rule->ext)) {
            cpu_enable_implied_rule(cpu, rule);
        }
    }

    /* Enable the implied extensions. */
    for (i = 0; (rule = riscv_multi_ext_implied_rules[i]); i++) {
        if (isa_ext_is_enabled(cpu, rule->ext)) {
            cpu_enable_implied_rule(cpu, rule);
        }
    }
}

void riscv_tcg_cpu_finalize_features(RISCVCPU *cpu, Error **errp)
{
    CPURISCVState *env = &cpu->env;
    Error *local_err = NULL;

    riscv_cpu_init_implied_exts_rules();
    riscv_cpu_enable_implied_rules(cpu);

    riscv_cpu_validate_misa_priv(env, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

    riscv_cpu_update_named_features(cpu);
    riscv_cpu_validate_profiles(cpu);

    if (cpu->cfg.ext_smepmp && !cpu->cfg.pmp) {
        /*
         * Enhanced PMP should only be available
         * on harts with PMP support
         */
        error_setg(errp, "Invalid configuration: Smepmp requires PMP support");
        return;
    }

    riscv_cpu_validate_set_extensions(cpu, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }
#ifndef CONFIG_USER_ONLY
    if (cpu->cfg.pmu_mask) {
        riscv_pmu_init(cpu, &local_err);
        if (local_err != NULL) {
            error_propagate(errp, local_err);
            return;
        }

        if (cpu->cfg.ext_sscofpmf) {
            cpu->pmu_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                          riscv_pmu_timer_cb, cpu);
        }
    }
#endif
}

void riscv_tcg_cpu_finalize_dynamic_decoder(RISCVCPU *cpu)
{
    GPtrArray *dynamic_decoders;
    dynamic_decoders = g_ptr_array_sized_new(decoder_table_size);
    for (size_t i = 0; i < decoder_table_size; ++i) {
        if (decoder_table[i].guard_func &&
            decoder_table[i].guard_func(&cpu->cfg)) {
            g_ptr_array_add(dynamic_decoders,
                            (gpointer)decoder_table[i].riscv_cpu_decode_fn);
        }
    }

    cpu->decoders = dynamic_decoders;
}

bool riscv_cpu_tcg_compatible(RISCVCPU *cpu)
{
    return object_dynamic_cast(OBJECT(cpu), TYPE_RISCV_CPU_HOST) == NULL;
}

static bool riscv_cpu_is_generic(Object *cpu_obj)
{
    return object_dynamic_cast(cpu_obj, TYPE_RISCV_DYNAMIC_CPU) != NULL;
}

/*
 * We'll get here via the following path:
 *
 * riscv_cpu_realize()
 *   -> cpu_exec_realizefn()
 *      -> tcg_cpu_realize() (via accel_cpu_common_realize())
 */
static bool riscv_tcg_cpu_realize(CPUState *cs, Error **errp)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(cpu);

    if (!riscv_cpu_tcg_compatible(cpu)) {
        g_autofree char *name = riscv_cpu_get_name(cpu);
        error_setg(errp, "'%s' CPU is not compatible with TCG acceleration",
                   name);
        return false;
    }

    if (mcc->misa_mxl_max >= MXL_RV128 && qemu_tcg_mttcg_enabled()) {
        /* Missing 128-bit aligned atomics */
        error_setg(errp,
                   "128-bit RISC-V currently does not work with Multi "
                   "Threaded TCG. Please use: -accel tcg,thread=single");
        return false;
    }

#ifndef CONFIG_USER_ONLY
    CPURISCVState *env = &cpu->env;

    /* Pc-relative TBs; see tcg_cflags_set_pcrel. */
    tcg_cflags_set_pcrel(CPU(cs));

    if (cpu->cfg.ext_sstc) {
        riscv_timer_init(cpu);
    }

    /* With H-Ext, VSSIP, VSTIP, VSEIP and SGEIP are hardwired to one. */
    if (riscv_has_ext(env, RVH)) {
        env->mideleg = MIP_VSSIP | MIP_VSTIP | MIP_VSEIP | MIP_SGEIP;
    }
#endif

    return true;
}

typedef struct RISCVCPUMisaExtConfig {
    target_ulong misa_bit;
    bool enabled;
} RISCVCPUMisaExtConfig;

static void cpu_set_misa_ext_cfg(Object *obj, Visitor *v, const char *name,
                                 void *opaque, Error **errp)
{
    const RISCVCPUMisaExtConfig *misa_ext_cfg = opaque;
    target_ulong misa_bit = misa_ext_cfg->misa_bit;
    RISCVCPU *cpu = RISCV_CPU(obj);
    CPURISCVState *env = &cpu->env;
    bool vendor_cpu = riscv_cpu_is_vendor(obj);
    bool prev_val, value;

    if (!visit_type_bool(v, name, &value, errp)) {
        return;
    }

    cpu_misa_ext_add_user_opt(misa_bit, value);

    prev_val = env->misa_ext & misa_bit;

    if (value == prev_val) {
        return;
    }

    if (value) {
        if (vendor_cpu) {
            g_autofree char *cpuname = riscv_cpu_get_name(cpu);
            error_setg(errp, "'%s' CPU does not allow enabling extensions",
                       cpuname);
            return;
        }

        if (misa_bit == RVH && env->priv_ver < PRIV_VERSION_1_12_0) {
            /*
             * Note: the 'priv_spec' command line option, if present,
             * will take precedence over this priv_ver bump.
             */
            env->priv_ver = PRIV_VERSION_1_12_0;
        }
    }

    riscv_cpu_write_misa_bit(cpu, misa_bit, value);
}

static void cpu_get_misa_ext_cfg(Object *obj, Visitor *v, const char *name,
                                 void *opaque, Error **errp)
{
    const RISCVCPUMisaExtConfig *misa_ext_cfg = opaque;
    target_ulong misa_bit = misa_ext_cfg->misa_bit;
    RISCVCPU *cpu = RISCV_CPU(obj);
    CPURISCVState *env = &cpu->env;
    bool value;

    value = env->misa_ext & misa_bit;

    visit_type_bool(v, name, &value, errp);
}

#define MISA_CFG(_bit, _enabled) \
    {.misa_bit = _bit, .enabled = _enabled}

static const RISCVCPUMisaExtConfig misa_ext_cfgs[] = {
    MISA_CFG(RVA, true),
    MISA_CFG(RVC, true),
    MISA_CFG(RVD, true),
    MISA_CFG(RVF, true),
    MISA_CFG(RVI, true),
    MISA_CFG(RVE, false),
    MISA_CFG(RVM, true),
    MISA_CFG(RVS, true),
    MISA_CFG(RVU, true),
    MISA_CFG(RVH, true),
    MISA_CFG(RVV, false),
    MISA_CFG(RVG, false),
    MISA_CFG(RVB, false),
};

/*
 * We do not support user choice tracking for MISA
 * extensions yet because, so far, we do not silently
 * change MISA bits during realize() (RVG enables MISA
 * bits but the user is warned about it).
 */
static void riscv_cpu_add_misa_properties(Object *cpu_obj)
{
    bool use_def_vals = riscv_cpu_is_generic(cpu_obj);
    int i;

    for (i = 0; i < ARRAY_SIZE(misa_ext_cfgs); i++) {
        const RISCVCPUMisaExtConfig *misa_cfg = &misa_ext_cfgs[i];
        int bit = misa_cfg->misa_bit;
        const char *name = riscv_get_misa_ext_name(bit);
        const char *desc = riscv_get_misa_ext_description(bit);

        /* Check if KVM already created the property */
        if (object_property_find(cpu_obj, name)) {
            continue;
        }

        object_property_add(cpu_obj, name, "bool",
                            cpu_get_misa_ext_cfg,
                            cpu_set_misa_ext_cfg,
                            NULL, (void *)misa_cfg);
        object_property_set_description(cpu_obj, name, desc);
        if (use_def_vals) {
            riscv_cpu_write_misa_bit(RISCV_CPU(cpu_obj), bit,
                                     misa_cfg->enabled);
        }
    }
}

static void cpu_set_profile(Object *obj, Visitor *v, const char *name,
                            void *opaque, Error **errp)
{
    RISCVCPUProfile *profile = opaque;
    RISCVCPU *cpu = RISCV_CPU(obj);
    bool value;
    int i, ext_offset;

    if (riscv_cpu_is_vendor(obj)) {
        error_setg(errp, "Profile %s is not available for vendor CPUs",
                   profile->name);
        return;
    }

    if (cpu->env.misa_mxl != MXL_RV64) {
        error_setg(errp, "Profile %s only available for 64 bit CPUs",
                   profile->name);
        return;
    }

    if (!visit_type_bool(v, name, &value, errp)) {
        return;
    }

    profile->user_set = true;
    profile->enabled = value;

    if (profile->u_parent != NULL) {
        object_property_set_bool(obj, profile->u_parent->name,
                                 profile->enabled, NULL);
    }

    if (profile->s_parent != NULL) {
        object_property_set_bool(obj, profile->s_parent->name,
                                 profile->enabled, NULL);
    }

    if (profile->enabled) {
        cpu->env.priv_ver = profile->priv_spec;
    }

#ifndef CONFIG_USER_ONLY
    if (profile->satp_mode != RISCV_PROFILE_ATTR_UNUSED) {
        object_property_set_bool(obj, "mmu", true, NULL);
        const char *satp_prop = satp_mode_str(profile->satp_mode,
                                              riscv_cpu_is_32bit(cpu));
        object_property_set_bool(obj, satp_prop, profile->enabled, NULL);
    }
#endif

    for (i = 0; misa_bits[i] != 0; i++) {
        uint32_t bit = misa_bits[i];

        if  (!(profile->misa_ext & bit)) {
            continue;
        }

        if (bit == RVI && !profile->enabled) {
            /*
             * Disabling profiles will not disable the base
             * ISA RV64I.
             */
            continue;
        }

        cpu_misa_ext_add_user_opt(bit, profile->enabled);
        riscv_cpu_write_misa_bit(cpu, bit, profile->enabled);
    }

    for (i = 0; profile->ext_offsets[i] != RISCV_PROFILE_EXT_LIST_END; i++) {
        ext_offset = profile->ext_offsets[i];

        if (profile->enabled) {
            if (cpu_cfg_offset_is_named_feat(ext_offset)) {
                riscv_cpu_enable_named_feat(cpu, ext_offset);
            }

            cpu_bump_multi_ext_priv_ver(&cpu->env, ext_offset);
        }

        cpu_cfg_ext_add_user_opt(ext_offset, profile->enabled);
        isa_ext_update_enabled(cpu, ext_offset, profile->enabled);
    }
}

static void cpu_get_profile(Object *obj, Visitor *v, const char *name,
                            void *opaque, Error **errp)
{
    RISCVCPUProfile *profile = opaque;
    bool value = profile->enabled;

    visit_type_bool(v, name, &value, errp);
}

static void riscv_cpu_add_profiles(Object *cpu_obj)
{
    for (int i = 0; riscv_profiles[i] != NULL; i++) {
        const RISCVCPUProfile *profile = riscv_profiles[i];

        object_property_add(cpu_obj, profile->name, "bool",
                            cpu_get_profile, cpu_set_profile,
                            NULL, (void *)profile);

        /*
         * CPUs might enable a profile right from the start.
         * Enable its mandatory extensions right away in this
         * case.
         */
        if (profile->enabled) {
            object_property_set_bool(cpu_obj, profile->name, true, NULL);
        }
    }
}

static bool cpu_ext_is_deprecated(const char *ext_name)
{
    return isupper(ext_name[0]);
}

/*
 * String will be allocated in the heap. Caller is responsible
 * for freeing it.
 */
static char *cpu_ext_to_lower(const char *ext_name)
{
    char *ret = g_malloc0(strlen(ext_name) + 1);

    strcpy(ret, ext_name);
    ret[0] = tolower(ret[0]);

    return ret;
}

static void cpu_set_multi_ext_cfg(Object *obj, Visitor *v, const char *name,
                                  void *opaque, Error **errp)
{
    const RISCVCPUMultiExtConfig *multi_ext_cfg = opaque;
    RISCVCPU *cpu = RISCV_CPU(obj);
    bool vendor_cpu = riscv_cpu_is_vendor(obj);
    bool prev_val, value;

    if (!visit_type_bool(v, name, &value, errp)) {
        return;
    }

    if (cpu_ext_is_deprecated(multi_ext_cfg->name)) {
        g_autofree char *lower = cpu_ext_to_lower(multi_ext_cfg->name);

        warn_report("CPU property '%s' is deprecated. Please use '%s' instead",
                    multi_ext_cfg->name, lower);
    }

    cpu_cfg_ext_add_user_opt(multi_ext_cfg->offset, value);

    prev_val = isa_ext_is_enabled(cpu, multi_ext_cfg->offset);

    if (value == prev_val) {
        return;
    }

    if (value && vendor_cpu) {
        g_autofree char *cpuname = riscv_cpu_get_name(cpu);
        error_setg(errp, "'%s' CPU does not allow enabling extensions",
                   cpuname);
        return;
    }

    if (value) {
        cpu_bump_multi_ext_priv_ver(&cpu->env, multi_ext_cfg->offset);
    }

    isa_ext_update_enabled(cpu, multi_ext_cfg->offset, value);
}

static void cpu_get_multi_ext_cfg(Object *obj, Visitor *v, const char *name,
                                  void *opaque, Error **errp)
{
    const RISCVCPUMultiExtConfig *multi_ext_cfg = opaque;
    bool value = isa_ext_is_enabled(RISCV_CPU(obj), multi_ext_cfg->offset);

    visit_type_bool(v, name, &value, errp);
}

static void cpu_add_multi_ext_prop(Object *cpu_obj,
                                   const RISCVCPUMultiExtConfig *multi_cfg)
{
    bool generic_cpu = riscv_cpu_is_generic(cpu_obj);
    bool deprecated_ext = cpu_ext_is_deprecated(multi_cfg->name);

    object_property_add(cpu_obj, multi_cfg->name, "bool",
                        cpu_get_multi_ext_cfg,
                        cpu_set_multi_ext_cfg,
                        NULL, (void *)multi_cfg);

    if (!generic_cpu || deprecated_ext) {
        return;
    }

    /*
     * Set def val directly instead of using
     * object_property_set_bool() to save the set()
     * callback hash for user inputs.
     */
    isa_ext_update_enabled(RISCV_CPU(cpu_obj), multi_cfg->offset,
                           multi_cfg->enabled);
}

static void riscv_cpu_add_multiext_prop_array(Object *obj,
                                        const RISCVCPUMultiExtConfig *array)
{
    const RISCVCPUMultiExtConfig *prop;

    g_assert(array);

    for (prop = array; prop && prop->name; prop++) {
        cpu_add_multi_ext_prop(obj, prop);
    }
}

/*
 * Add CPU properties with user-facing flags.
 *
 * This will overwrite existing env->misa_ext values with the
 * defaults set via riscv_cpu_add_misa_properties().
 */
static void riscv_cpu_add_user_properties(Object *obj)
{
#ifndef CONFIG_USER_ONLY
    riscv_add_satp_mode_properties(obj);
#endif

    riscv_cpu_add_misa_properties(obj);

    riscv_cpu_add_multiext_prop_array(obj, riscv_cpu_extensions);
    riscv_cpu_add_multiext_prop_array(obj, riscv_cpu_vendor_exts);
    riscv_cpu_add_multiext_prop_array(obj, riscv_cpu_experimental_exts);

    riscv_cpu_add_multiext_prop_array(obj, riscv_cpu_deprecated_exts);

    riscv_cpu_add_profiles(obj);
}

/*
 * The 'max' type CPU will have all possible ratified
 * non-vendor extensions enabled.
 */
static void riscv_init_max_cpu_extensions(Object *obj)
{
    RISCVCPU *cpu = RISCV_CPU(obj);
    CPURISCVState *env = &cpu->env;
    const RISCVCPUMultiExtConfig *prop;

    /* Enable RVG and RVV that are disabled by default */
    riscv_cpu_set_misa_ext(env, env->misa_ext | RVB | RVG | RVV);

    for (prop = riscv_cpu_extensions; prop && prop->name; prop++) {
        isa_ext_update_enabled(cpu, prop->offset, true);
    }

    /*
     * Some extensions can't be added without backward compatibilty concerns.
     * Disable those, the user can still opt in to them on the command line.
     */
    cpu->cfg.ext_svade = false;

    /* set vector version */
    env->vext_ver = VEXT_VERSION_1_00_0;

    /* Zfinx is not compatible with F. Disable it */
    isa_ext_update_enabled(cpu, CPU_CFG_OFFSET(ext_zfinx), false);
    isa_ext_update_enabled(cpu, CPU_CFG_OFFSET(ext_zdinx), false);
    isa_ext_update_enabled(cpu, CPU_CFG_OFFSET(ext_zhinx), false);
    isa_ext_update_enabled(cpu, CPU_CFG_OFFSET(ext_zhinxmin), false);

    isa_ext_update_enabled(cpu, CPU_CFG_OFFSET(ext_zce), false);
    isa_ext_update_enabled(cpu, CPU_CFG_OFFSET(ext_zcmp), false);
    isa_ext_update_enabled(cpu, CPU_CFG_OFFSET(ext_zcmt), false);

    if (env->misa_mxl != MXL_RV32) {
        isa_ext_update_enabled(cpu, CPU_CFG_OFFSET(ext_zcf), false);
    }

    /*
     * TODO: ext_smrnmi requires OpenSBI changes that our current
     * image does not have. Disable it for now.
     */
    if (cpu->cfg.ext_smrnmi) {
        isa_ext_update_enabled(cpu, CPU_CFG_OFFSET(ext_smrnmi), false);
    }

    /*
     * TODO: ext_smdbltrp requires the firmware to clear MSTATUS.MDT on startup
     * to avoid generating a double trap. OpenSBI does not currently support it,
     * disable it for now.
     */
    if (cpu->cfg.ext_smdbltrp) {
        isa_ext_update_enabled(cpu, CPU_CFG_OFFSET(ext_smdbltrp), false);
    }
}

static bool riscv_cpu_has_max_extensions(Object *cpu_obj)
{
    return object_dynamic_cast(cpu_obj, TYPE_RISCV_CPU_MAX) != NULL;
}

static void riscv_tcg_cpu_instance_init(CPUState *cs)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    Object *obj = OBJECT(cpu);

    misa_ext_user_opts = g_hash_table_new(NULL, g_direct_equal);
    multi_ext_user_opts = g_hash_table_new(NULL, g_direct_equal);

    if (!misa_ext_implied_rules) {
        misa_ext_implied_rules = g_hash_table_new(NULL, g_direct_equal);
    }

    if (!multi_ext_implied_rules) {
        multi_ext_implied_rules = g_hash_table_new(NULL, g_direct_equal);
    }

    riscv_cpu_add_user_properties(obj);

    if (riscv_cpu_has_max_extensions(obj)) {
        riscv_init_max_cpu_extensions(obj);
    }
}

static void riscv_tcg_cpu_init_ops(AccelCPUClass *accel_cpu, CPUClass *cc)
{
    /*
     * All cpus use the same set of operations.
     */
    cc->tcg_ops = &riscv_tcg_ops;
}

static void riscv_tcg_cpu_class_init(CPUClass *cc)
{
    cc->init_accel_cpu = riscv_tcg_cpu_init_ops;
}

static void riscv_tcg_cpu_accel_class_init(ObjectClass *oc, void *data)
{
    AccelCPUClass *acc = ACCEL_CPU_CLASS(oc);

    acc->cpu_class_init = riscv_tcg_cpu_class_init;
    acc->cpu_instance_init = riscv_tcg_cpu_instance_init;
    acc->cpu_target_realize = riscv_tcg_cpu_realize;
}

static const TypeInfo riscv_tcg_cpu_accel_type_info = {
    .name = ACCEL_CPU_NAME("tcg"),

    .parent = TYPE_ACCEL_CPU,
    .class_init = riscv_tcg_cpu_accel_class_init,
    .abstract = true,
};

static void riscv_tcg_cpu_accel_register_types(void)
{
    type_register_static(&riscv_tcg_cpu_accel_type_info);
}
type_init(riscv_tcg_cpu_accel_register_types);
