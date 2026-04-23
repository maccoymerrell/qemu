/*
 * CHERI Helper Functions for RISC-V
 *
 * Adapted from the CTSRD-CHERI/qemu implementation.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020-2023 University of Cambridge
 * Copyright (c) 2020-2023 SRI International
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"
#include "cheri_cap.h"
#include "cheri_tag_mem.h"
#include "exec/cpu_ldst.h"

/*
 * Helper to get a pointer to a capability register.
 * Index 0-31 = general-purpose capability registers (gpcr[0..31]).
 * For special registers, use cspecialrw.
 *
 * LAZY SYNC: In our implementation, standard RISC-V integer instructions
 * write to gpr[] without updating gpcr[].  Before any CHERI helper reads
 * a capability register, we must check whether gpr[i] has diverged from
 * gpcr[i]._cursor.  If so, an integer instruction wrote to gpr[i] since
 * the last CHERI sync, and we need to propagate gpr → gpcr (creating a
 * NULL-derived capability).
 *
 * This is analogous to the CREG_INTEGER lazy state in the original
 * CTSRD-CHERI/qemu: the capability register is logically an integer
 * (NULL-derived with cursor = integer value), and we materialise it
 * on first access by a CHERI instruction.
 */
static inline void cheri_lazy_sync(CPURISCVState *env, uint32_t idx)
{
    if (idx != 0 && env->gpr[idx] != (target_ulong)env->gpcr[idx]._cursor) {
        cheri_gpr_to_cap(env, idx);
    }
}

static inline cap_register_t *get_cap_reg(CPURISCVState *env, uint32_t idx)
{
    assert(idx < 32);
    cheri_lazy_sync(env, idx);
    return &env->gpcr[idx];
}

static inline const cap_register_t *get_cap_reg_const(CPURISCVState *env,
                                                       uint32_t idx)
{
    assert(idx < 32);
    cheri_lazy_sync(env, idx);
    return &env->gpcr[idx];
}

/*
 * Raise a CHERI capability exception.
 * Maps to RISC-V mcause = 28 (CHERI fault) with mtval encoding the cause.
 *
 * Per CTSRD-CHERI/qemu: stores cause/regnum in env fields, then the trap
 * handler (riscv_cpu_do_interrupt) encodes them into xtval as:
 *   xtval = cause[4:0] | (regnum[5:0] << 5)
 */
static void raise_cheri_exception(CPURISCVState *env, uint32_t cause,
                                  uint32_t regnum, uintptr_t ra)
{
    env->last_cap_cause = (int8_t)cause;
    env->last_cap_index = (int8_t)regnum;
    env->badaddr = (target_ulong)((cause & 0x1f) | ((regnum & 0x3f) << 5));
    riscv_raise_exception(env, RISCV_EXCP_CHERI, ra);
}

/* CHERI exception cause codes (from cheri-archspecific-early.h) */
#define CapEx_TagViolation               0x2
#define CapEx_SealViolation              0x3
#define CapEx_LengthViolation            0x1
#define CapEx_PermitExecuteViolation     0x11
#define CapEx_PermitLoadViolation        0x12
#define CapEx_PermitStoreViolation       0x13
#define CapEx_PermitSealViolation        0x17
#define CapEx_PermitUnsealViolation      0x1B
#define CapEx_AccessSystemRegsViolation  0x18

/* ===========================================================================
 * Capability inspection helpers
 * ===========================================================================*/

target_ulong helper_cheri_cgetperm(CPURISCVState *env, uint32_t rd,
                                   uint32_t cs1)
{
    const cap_register_t *c = get_cap_reg_const(env, cs1);
    return (target_ulong)cap_get_perms(c);
}

target_ulong helper_cheri_cgettype(CPURISCVState *env, uint32_t rd,
                                   uint32_t cs1)
{
    const cap_register_t *c = get_cap_reg_const(env, cs1);
    uint32_t otype = cap_get_otype(c);
    if (otype == CAP_OTYPE_UNSEALED) {
        return (target_ulong)-1;  /* -1 for unsealed */
    }
    return (target_ulong)otype;
}

target_ulong helper_cheri_cgetbase(CPURISCVState *env, uint32_t rd,
                                   uint32_t cs1)
{
    const cap_register_t *c = get_cap_reg_const(env, cs1);
    return (target_ulong)cap_get_base(c);
}

target_ulong helper_cheri_cgetlen(CPURISCVState *env, uint32_t rd,
                                  uint32_t cs1)
{
    const cap_register_t *c = get_cap_reg_const(env, cs1);
    return (target_ulong)cap_get_length(c);
}

target_ulong helper_cheri_cgettag(CPURISCVState *env, uint32_t rd,
                                  uint32_t cs1)
{
    const cap_register_t *c = get_cap_reg_const(env, cs1);
    return (target_ulong)cap_get_tag(c);
}

target_ulong helper_cheri_cgetsealed(CPURISCVState *env, uint32_t rd,
                                     uint32_t cs1)
{
    const cap_register_t *c = get_cap_reg_const(env, cs1);
    return (target_ulong)cap_is_sealed(c);
}

target_ulong helper_cheri_cgetoffset(CPURISCVState *env, uint32_t rd,
                                     uint32_t cs1)
{
    const cap_register_t *c = get_cap_reg_const(env, cs1);
    return (target_ulong)cap_get_offset(c);
}

target_ulong helper_cheri_cgetflags(CPURISCVState *env, uint32_t rd,
                                    uint32_t cs1)
{
    const cap_register_t *c = get_cap_reg_const(env, cs1);
    return (target_ulong)cap_get_flags(c);
}

target_ulong helper_cheri_cgetaddr(CPURISCVState *env, uint32_t rd,
                                   uint32_t cs1)
{
    const cap_register_t *c = get_cap_reg_const(env, cs1);
    return (target_ulong)cap_get_cursor(c);
}

target_ulong helper_cheri_cgethigh(CPURISCVState *env, uint32_t rd,
                                   uint32_t cs1)
{
    const cap_register_t *c = get_cap_reg_const(env, cs1);
    return (target_ulong)cap_get_high(c);
}

/* ===========================================================================
 * Capability modification helpers
 * ===========================================================================*/

void helper_cheri_csetbounds(CPURISCVState *env, uint32_t cd, uint32_t cs1,
                             target_ulong len)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    cap_register_t *dst = get_cap_reg(env, cd);

    if (!cap_get_tag(src)) {
        raise_cheri_exception(env, CapEx_TagViolation, cs1, GETPC());
        return;
    }
    if (cap_is_sealed(src)) {
        raise_cheri_exception(env, CapEx_SealViolation, cs1, GETPC());
        return;
    }

    cap_register_t result = *src;
    cap_set_bounds(&result, (uint64_t)len);
    *dst = result;
    cheri_cap_to_gpr(env, cd);
}

void helper_cheri_csetboundsexact(CPURISCVState *env, uint32_t cd,
                                  uint32_t cs1, target_ulong len)
{
    /* For now same as csetbounds — exact check can be added later */
    helper_cheri_csetbounds(env, cd, cs1, len);
}

void helper_cheri_csetboundsimm(CPURISCVState *env, uint32_t cd,
                                uint32_t cs1, target_ulong len)
{
    helper_cheri_csetbounds(env, cd, cs1, len);
}

void helper_cheri_candperm(CPURISCVState *env, uint32_t cd, uint32_t cs1,
                           target_ulong mask)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    cap_register_t *dst = get_cap_reg(env, cd);

    if (!cap_get_tag(src)) {
        raise_cheri_exception(env, CapEx_TagViolation, cs1, GETPC());
        return;
    }
    if (cap_is_sealed(src)) {
        raise_cheri_exception(env, CapEx_SealViolation, cs1, GETPC());
        return;
    }

    cap_register_t result = *src;
    cap_and_perms(&result, (uint32_t)mask);
    *dst = result;
    cheri_cap_to_gpr(env, cd);
}

void helper_cheri_csetoffset(CPURISCVState *env, uint32_t cd, uint32_t cs1,
                             target_ulong offset)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    cap_register_t *dst = get_cap_reg(env, cd);

    if (cap_is_sealed(src) && cap_get_tag(src)) {
        raise_cheri_exception(env, CapEx_SealViolation, cs1, GETPC());
        return;
    }

    cap_register_t result = *src;
    cap_set_offset(&result, (uint64_t)offset);
    *dst = result;
    cheri_cap_to_gpr(env, cd);
}

void helper_cheri_csetaddr(CPURISCVState *env, uint32_t cd, uint32_t cs1,
                           target_ulong addr)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    cap_register_t *dst = get_cap_reg(env, cd);

    if (cap_is_sealed(src) && cap_get_tag(src)) {
        raise_cheri_exception(env, CapEx_SealViolation, cs1, GETPC());
        return;
    }

    cap_register_t result = *src;
    cap_set_addr(&result, (uint64_t)addr);
    *dst = result;
    cheri_cap_to_gpr(env, cd);
}

void helper_cheri_cincoffset(CPURISCVState *env, uint32_t cd, uint32_t cs1,
                             target_ulong offset)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    cap_register_t *dst = get_cap_reg(env, cd);

    if (cap_is_sealed(src) && cap_get_tag(src)) {
        raise_cheri_exception(env, CapEx_SealViolation, cs1, GETPC());
        return;
    }

    cap_register_t result = *src;
    cap_inc_offset(&result, (int64_t)offset);
    *dst = result;
    cheri_cap_to_gpr(env, cd);
}

void helper_cheri_csetflags(CPURISCVState *env, uint32_t cd, uint32_t cs1,
                            target_ulong flags)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    cap_register_t *dst = get_cap_reg(env, cd);

    if (cap_is_sealed(src) && cap_get_tag(src)) {
        raise_cheri_exception(env, CapEx_SealViolation, cs1, GETPC());
        return;
    }

    cap_register_t result = *src;
    cap_set_flags(&result, (uint8_t)flags);
    *dst = result;
    cheri_cap_to_gpr(env, cd);
}

void helper_cheri_csethigh(CPURISCVState *env, uint32_t cd, uint32_t cs1,
                           target_ulong high)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    cap_register_t *dst = get_cap_reg(env, cd);

    cap_register_t result = *src;
    /* Set the high 64 bits (pesbt) — clears tag if it was set */
    result.pesbt = (uint64_t)high;
    result.tag = false;
    *dst = result;
    cheri_cap_to_gpr(env, cd);
}

void helper_cheri_cmv(CPURISCVState *env, uint32_t cd, uint32_t cs1)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    cap_register_t *dst = get_cap_reg(env, cd);
    *dst = *src;
    cheri_cap_to_gpr(env, cd);
}

void helper_cheri_ccleartag(CPURISCVState *env, uint32_t cd, uint32_t cs1)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    cap_register_t *dst = get_cap_reg(env, cd);

    cap_register_t result = *src;
    cap_clear_tag(&result);
    *dst = result;
    cheri_cap_to_gpr(env, cd);
}

/* ===========================================================================
 * Sealing helpers
 * ===========================================================================*/

void helper_cheri_cseal(CPURISCVState *env, uint32_t cd, uint32_t cs1,
                        uint32_t cs2)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    const cap_register_t *auth = get_cap_reg_const(env, cs2);
    cap_register_t *dst = get_cap_reg(env, cd);

    if (!cap_get_tag(src)) {
        raise_cheri_exception(env, CapEx_TagViolation, cs1, GETPC());
        return;
    }
    if (!cap_get_tag(auth)) {
        raise_cheri_exception(env, CapEx_TagViolation, cs2, GETPC());
        return;
    }
    if (cap_is_sealed(src)) {
        raise_cheri_exception(env, CapEx_SealViolation, cs1, GETPC());
        return;
    }
    if (!(cap_get_perms(auth) & CAP_PERM_SEAL)) {
        raise_cheri_exception(env, CapEx_PermitSealViolation, cs2, GETPC());
        return;
    }

    cap_register_t result = *src;
    uint32_t otype = (uint32_t)(cap_get_cursor(auth) & 0xFFFF);
    cap_seal(&result, otype);
    *dst = result;
    cheri_cap_to_gpr(env, cd);
}

void helper_cheri_cunseal(CPURISCVState *env, uint32_t cd, uint32_t cs1,
                          uint32_t cs2)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    const cap_register_t *auth = get_cap_reg_const(env, cs2);
    cap_register_t *dst = get_cap_reg(env, cd);

    if (!cap_get_tag(src)) {
        raise_cheri_exception(env, CapEx_TagViolation, cs1, GETPC());
        return;
    }
    if (!cap_get_tag(auth)) {
        raise_cheri_exception(env, CapEx_TagViolation, cs2, GETPC());
        return;
    }
    if (!cap_is_sealed(src)) {
        raise_cheri_exception(env, CapEx_SealViolation, cs1, GETPC());
        return;
    }
    if (!(cap_get_perms(auth) & CAP_PERM_UNSEAL)) {
        raise_cheri_exception(env, CapEx_PermitUnsealViolation, cs2, GETPC());
        return;
    }

    cap_register_t result = *src;
    cap_unseal(&result);
    *dst = result;
    cheri_cap_to_gpr(env, cd);
}

void helper_cheri_csealentry(CPURISCVState *env, uint32_t cd, uint32_t cs1)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    cap_register_t *dst = get_cap_reg(env, cd);

    if (!cap_get_tag(src)) {
        raise_cheri_exception(env, CapEx_TagViolation, cs1, GETPC());
        return;
    }
    if (cap_is_sealed(src)) {
        raise_cheri_exception(env, CapEx_SealViolation, cs1, GETPC());
        return;
    }

    cap_register_t result = *src;
    cap_seal_entry(&result);
    *dst = result;
    cheri_cap_to_gpr(env, cd);
}

/* ===========================================================================
 * Capability construction and comparison helpers
 * ===========================================================================*/

void helper_cheri_cbuildcap(CPURISCVState *env, uint32_t cd, uint32_t cs1,
                            uint32_t cs2)
{
    const cap_register_t *auth = get_cap_reg_const(env, cs1);
    const cap_register_t *src = get_cap_reg_const(env, cs2);
    cap_register_t *dst = get_cap_reg(env, cd);

    if (!cap_get_tag(auth)) {
        raise_cheri_exception(env, CapEx_TagViolation, cs1, GETPC());
        return;
    }

    /* Build a capability from src's bounds/cursor with auth's tag/perms check */
    cap_register_t result = *src;
    result.tag = true;
    *dst = result;
    cheri_cap_to_gpr(env, cd);
}

void helper_cheri_ccopytype(CPURISCVState *env, uint32_t cd, uint32_t cs1,
                            uint32_t cs2)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    const cap_register_t *type_src = get_cap_reg_const(env, cs2);
    cap_register_t *dst = get_cap_reg(env, cd);

    cap_register_t result = *src;
    if (cap_is_sealed(type_src)) {
        cap_set_addr(&result, (uint64_t)cap_get_otype(type_src));
    } else {
        cap_set_addr(&result, (uint64_t)-1);
        cap_clear_tag(&result);
    }
    *dst = result;
    cheri_cap_to_gpr(env, cd);
}

void helper_cheri_ccseal(CPURISCVState *env, uint32_t cd, uint32_t cs1,
                         uint32_t cs2)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    const cap_register_t *auth = get_cap_reg_const(env, cs2);
    cap_register_t *dst = get_cap_reg(env, cd);

    /* CCSeal: conditional seal — if auth is invalid/unsealed, just copy */
    if (!cap_get_tag(auth) || cap_is_sealed(auth) ||
        !(cap_get_perms(auth) & CAP_PERM_SEAL)) {
        *dst = *src;
    } else {
        cap_register_t result = *src;
        uint32_t otype = (uint32_t)(cap_get_cursor(auth) & 0xFFFF);
        if (cap_get_tag(src) && !cap_is_sealed(src)) {
            cap_seal(&result, otype);
        }
        *dst = result;
    }
    cheri_cap_to_gpr(env, cd);
}

target_ulong helper_cheri_ctestsubset(CPURISCVState *env, uint32_t rd,
                                      uint32_t cs1, uint32_t cs2)
{
    const cap_register_t *a = get_cap_reg_const(env, cs1);
    const cap_register_t *b = get_cap_reg_const(env, cs2);
    return (target_ulong)cap_is_subset(a, b);
}

target_ulong helper_cheri_cseqx(CPURISCVState *env, uint32_t rd,
                                uint32_t cs1, uint32_t cs2)
{
    const cap_register_t *a = get_cap_reg_const(env, cs1);
    const cap_register_t *b = get_cap_reg_const(env, cs2);
    return (target_ulong)cap_is_equal(a, b);
}

target_ulong helper_cheri_ctoptr(CPURISCVState *env, uint32_t rd,
                                 uint32_t cs1, uint32_t cs2)
{
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    const cap_register_t *base_cap = get_cap_reg_const(env, cs2);

    if (!cap_get_tag(src)) {
        return 0;
    }
    return (target_ulong)(cap_get_cursor(src) - cap_get_base(base_cap));
}

void helper_cheri_cfromptr(CPURISCVState *env, uint32_t cd, uint32_t cs1,
                           target_ulong ptr)
{
    const cap_register_t *auth = get_cap_reg_const(env, cs1);
    cap_register_t *dst = get_cap_reg(env, cd);

    if (ptr == 0) {
        *dst = cap_mk_null();
    } else {
        if (!cap_get_tag(auth)) {
            raise_cheri_exception(env, CapEx_TagViolation, cs1, GETPC());
            return;
        }
        cap_register_t result = *auth;
        cap_set_addr(&result, cap_get_base(auth) + (uint64_t)ptr);
        *dst = result;
    }
    cheri_cap_to_gpr(env, cd);
}

target_ulong helper_cheri_csub(CPURISCVState *env, uint32_t rd,
                               uint32_t cs1, uint32_t cs2)
{
    const cap_register_t *a = get_cap_reg_const(env, cs1);
    const cap_register_t *b = get_cap_reg_const(env, cs2);
    return (target_ulong)(cap_get_cursor(a) - cap_get_cursor(b));
}

/* ===========================================================================
 * Special register access
 * ===========================================================================*/

void helper_cheri_cspecialrw(CPURISCVState *env, uint32_t cd, uint32_t cs1,
                             uint32_t scr)
{
    cap_register_t old_val;
    cap_register_t *src = (cs1 != 0) ? get_cap_reg(env, cs1) : NULL;
    cap_register_t *special;

    /*
     * Per CTSRD-CHERI/qemu: CSpecialRW requires Access_System_Registers
     * permission in PCC for system-mode SCRs (anything beyond DDC).
     */
    if (scr >= 2 && !cheri_have_access_sysregs(env)) {
        raise_cheri_exception(env, CapEx_AccessSystemRegsViolation, 0, GETPC());
        return;
    }

    /* Select the special capability register */
    switch (scr) {
    case 0:  /* PCC */
        special = &env->pcc;
        break;
    case 1:  /* DDC */
        special = &env->ddc;
        break;
#ifndef CONFIG_USER_ONLY
    case 12: /* STCC - Supervisor Trap Code Capability */
        special = &env->stvecc;
        break;
    case 14: /* SScratchC - Supervisor Scratch Capability */
        special = &env->sscratchc;
        break;
    case 15: /* SEPCC - Supervisor Exception PC Capability */
        special = &env->sepcc;
        break;
    case 28: /* MTCC - Machine Trap Code Capability */
        special = &env->mtvecc;
        break;
    case 30: /* MScratchC - Machine Scratch Capability */
        special = &env->mscratchc;
        break;
    case 31: /* MEPCC - Machine Exception PC Capability */
        special = &env->mepcc;
        break;
#endif
    default:
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
        return;
    }

    /* Read old value */
    old_val = *special;

    /* Write new value if cs1 != 0 */
    if (src) {
        *special = *src;
        /* Sync the integer CSR/PC with the capability cursor */
        target_ulong cursor = (target_ulong)cap_get_cursor(special);
        switch (scr) {
        case 0: env->pc = cursor; break;
#ifndef CONFIG_USER_ONLY
        case 12: env->stvec = cursor; break;
        case 14: env->sscratch = cursor; break;
        case 15: env->sepc = cursor; break;
        case 28: env->mtvec = cursor; break;
        case 30: env->mscratch = cursor; break;
        case 31: env->mepc = cursor; break;
#endif
        default: break;
        }
    }

    /* Write old value to cd */
    if (cd != 0) {
        cap_register_t *dst = get_cap_reg(env, cd);
        *dst = old_val;
        cheri_cap_to_gpr(env, cd);
    }
}

/* ===========================================================================
 * Branch helpers
 * ===========================================================================*/

target_ulong helper_cheri_jalr_cap(CPURISCVState *env, uint32_t cs1)
{
    const cap_register_t *target = get_cap_reg_const(env, cs1);

    if (!cap_get_tag(target)) {
        raise_cheri_exception(env, CapEx_TagViolation, cs1, GETPC());
        return env->pc; /* unreachable after exception */
    }
    if (!(cap_get_perms(target) & CAP_PERM_EXECUTE)) {
        raise_cheri_exception(env, CapEx_PermitExecuteViolation, cs1, GETPC());
        return env->pc;
    }

    target_ulong new_pc = (target_ulong)cap_get_cursor(target);
    /* Update PCC from the target capability */
    env->pcc = *target;
    cap_set_addr(&env->pcc, (uint64_t)new_pc);
    return new_pc;
}

target_ulong helper_cheri_jalr_pcc(CPURISCVState *env, target_ulong addr)
{
    /* Jump within PCC bounds */
    if (!cap_get_tag(&env->pcc)) {
        raise_cheri_exception(env, CapEx_TagViolation, 0, GETPC());
        return env->pc;
    }
    if (!cap_in_bounds(&env->pcc, (uint64_t)addr, 2)) {
        raise_cheri_exception(env, CapEx_LengthViolation, 0, GETPC());
        return env->pc;
    }
    return addr;
}

/* CIncOffsetImm / caddi helper */
void helper_cheri_caddi(CPURISCVState *env, uint32_t cd, uint32_t cs1)
{
    /* The immediate has already been added to gpr[cd] by the TCG frontend,
     * so we just sync the capability register. For a full implementation,
     * this would need the immediate value passed separately. */
    const cap_register_t *src = get_cap_reg_const(env, cs1);
    cap_register_t *dst = get_cap_reg(env, cd);

    cap_register_t result = *src;
    /* The new cursor value is already in gpr[cd] from the caller */
    cap_set_addr(&result, (uint64_t)env->gpr[cd]);
    *dst = result;
}

/* ===========================================================================
 * Load/Store via DDC helpers
 *
 * These implement CHERI loads/stores where the effective address is formed
 * by adding an offset in rs1 to the DDC (Default Data Capability) base.
 * DDC bounds and permissions are checked before the memory access.
 * ===========================================================================*/

/*
 * Helper: check DDC for a load/store access.
 *  - Tag must be valid
 *  - Must not be sealed
 *  - Must have the required permission (LOAD or STORE)
 *  - Address must be in bounds
 *
 * Returns the physical effective address (DDC.base + addr_offset).
 */
static inline target_ulong check_ddc(CPURISCVState *env, target_ulong addr,
                                     uint32_t size, uint32_t perm_needed,
                                     uintptr_t ra)
{
    const cap_register_t *ddc = &env->ddc;

    if (!cap_get_tag(ddc)) {
        raise_cheri_exception(env, CapEx_TagViolation, /*DDC*/ 1, ra);
    }
    if (cap_is_sealed(ddc)) {
        raise_cheri_exception(env, CapEx_SealViolation, 1, ra);
    }
    if (!(cap_get_perms(ddc) & perm_needed)) {
        uint32_t cause = (perm_needed & CAP_PERM_LOAD)
                             ? CapEx_PermitLoadViolation
                             : CapEx_PermitStoreViolation;
        raise_cheri_exception(env, cause, 1, ra);
    }

    /* Effective address = DDC.base + addr (offset from rs1) */
    uint64_t ea = cap_get_base(ddc) + (uint64_t)addr;
    if (!cap_in_bounds(ddc, ea, size)) {
        raise_cheri_exception(env, CapEx_LengthViolation, 1, ra);
    }

    return (target_ulong)ea;
}

/*
 * Load via DDC: rd = mem[DDC.base + rs1]
 * @addr is the value of rs1 (offset from DDC base).
 * @memop_size is the MO_SIZE part (1/2/4/8).
 */
target_ulong helper_cheri_load_ddc(CPURISCVState *env, target_ulong addr,
                                   uint32_t memop_size)
{
    uint32_t size = 1u << (memop_size & MO_SIZE);
    target_ulong ea = check_ddc(env, addr, size, CAP_PERM_LOAD, GETPC());
    target_ulong val;

    switch (memop_size & MO_SIZE) {
    case MO_8:
        val = (target_ulong)cpu_ldub_data_ra(env, ea, GETPC());
        /* Sign extend if needed — handled by caller's MO flags */
        break;
    case MO_16:
        val = (target_ulong)cpu_lduw_data_ra(env, ea, GETPC());
        break;
    case MO_32:
        val = (target_ulong)cpu_ldl_data_ra(env, ea, GETPC());
        break;
    case MO_64:
        val = (target_ulong)cpu_ldq_data_ra(env, ea, GETPC());
        break;
    default:
        val = 0;
    }
    return val;
}

/*
 * Store via DDC: mem[DDC.base + rs1] = rs2
 */
void helper_cheri_store_ddc(CPURISCVState *env, target_ulong addr,
                            target_ulong val, uint32_t memop_size)
{
    uint32_t size = 1u << (memop_size & MO_SIZE);
    target_ulong ea = check_ddc(env, addr, size, CAP_PERM_STORE, GETPC());

    switch (memop_size & MO_SIZE) {
    case MO_8:
        cpu_stb_data_ra(env, ea, (uint8_t)val, GETPC());
        break;
    case MO_16:
        cpu_stw_data_ra(env, ea, (uint16_t)val, GETPC());
        break;
    case MO_32:
        cpu_stl_data_ra(env, ea, (uint32_t)val, GETPC());
        break;
    case MO_64:
        cpu_stq_data_ra(env, ea, (uint64_t)val, GETPC());
        break;
    }

    /* Non-capability store: clear any tag at this granule */
    hwaddr paddr = ea;  /* In softmmu this would be translated */
    cheri_tag_clear(paddr);
}

/* ===========================================================================
 * Load/Store via Capability register helpers
 *
 * Effective address = cap.cursor + offset (rs2)
 * Cap bounds and permissions are checked.
 * ===========================================================================*/

static inline target_ulong check_cap(CPURISCVState *env, uint32_t cs,
                                     target_ulong offset,
                                     uint32_t size, uint32_t perm_needed,
                                     uintptr_t ra)
{
    const cap_register_t *cap = get_cap_reg_const(env, cs);

    if (!cap_get_tag(cap)) {
        raise_cheri_exception(env, CapEx_TagViolation, cs, ra);
    }
    if (cap_is_sealed(cap)) {
        raise_cheri_exception(env, CapEx_SealViolation, cs, ra);
    }
    if (!(cap_get_perms(cap) & perm_needed)) {
        uint32_t cause = (perm_needed & CAP_PERM_LOAD)
                             ? CapEx_PermitLoadViolation
                             : CapEx_PermitStoreViolation;
        raise_cheri_exception(env, cause, cs, ra);
    }

    uint64_t ea = cap_get_cursor(cap) + (uint64_t)offset;
    if (!cap_in_bounds(cap, ea, size)) {
        raise_cheri_exception(env, CapEx_LengthViolation, cs, ra);
    }

    return (target_ulong)ea;
}

target_ulong helper_cheri_load_cap(CPURISCVState *env, uint32_t cs,
                                   target_ulong offset, uint32_t memop_size)
{
    uint32_t size = 1u << (memop_size & MO_SIZE);
    target_ulong ea = check_cap(env, cs, offset, size, CAP_PERM_LOAD,
                                GETPC());
    target_ulong val;

    switch (memop_size & MO_SIZE) {
    case MO_8:
        val = (target_ulong)cpu_ldub_data_ra(env, ea, GETPC());
        break;
    case MO_16:
        val = (target_ulong)cpu_lduw_data_ra(env, ea, GETPC());
        break;
    case MO_32:
        val = (target_ulong)cpu_ldl_data_ra(env, ea, GETPC());
        break;
    case MO_64:
        val = (target_ulong)cpu_ldq_data_ra(env, ea, GETPC());
        break;
    default:
        val = 0;
    }
    return val;
}

void helper_cheri_store_cap(CPURISCVState *env, uint32_t cs,
                            target_ulong offset, target_ulong val,
                            uint32_t memop_size)
{
    uint32_t size = 1u << (memop_size & MO_SIZE);
    target_ulong ea = check_cap(env, cs, offset, size, CAP_PERM_STORE,
                                GETPC());

    switch (memop_size & MO_SIZE) {
    case MO_8:
        cpu_stb_data_ra(env, ea, (uint8_t)val, GETPC());
        break;
    case MO_16:
        cpu_stw_data_ra(env, ea, (uint16_t)val, GETPC());
        break;
    case MO_32:
        cpu_stl_data_ra(env, ea, (uint32_t)val, GETPC());
        break;
    case MO_64:
        cpu_stq_data_ra(env, ea, (uint64_t)val, GETPC());
        break;
    }

    hwaddr paddr = ea;
    cheri_tag_clear(paddr);
}

/* ===========================================================================
 * Capability Load (LC) / Store (SC) — 16-byte capability with tag
 *
 * LC reads 16 bytes + tag bit.  SC writes 16 bytes + sets tag if valid.
 * ===========================================================================*/

/*
 * Load capability via DDC: cd = mem_cap[DDC.base + rs1]
 */
void helper_cheri_load_cap_ddc(CPURISCVState *env, uint32_t cd,
                               target_ulong addr)
{
    target_ulong ea = check_ddc(env, addr, CHERI_CAP_SIZE,
                                CAP_PERM_LOAD | CAP_PERM_LOAD_CAP, GETPC());

    /* Load the two 64-bit halves (pesbt ∥ cursor, little-endian) */
    uint64_t cursor_val = cpu_ldq_data_ra(env, ea, GETPC());
    uint64_t pesbt_val  = cpu_ldq_data_ra(env, ea + 8, GETPC());

    /* Read the tag from tag memory */
    hwaddr paddr = ea;  /* TODO: proper VA→PA in softmmu */
    bool tag = cheri_tag_get(paddr & ~(hwaddr)(CHERI_CAP_SIZE - 1));

    /* Construct the capability */
    cap_register_t result;
    result.pesbt   = pesbt_val;
    result._cursor = cursor_val;
    result.flags   = 0;
    result.tag     = tag;

    /* Decompress bounds from pesbt */
    cc128_decompress(&result);

    /* Write to destination register */
    if (cd != 0) {
        env->gpcr[cd] = result;
        env->gpr[cd]  = (target_ulong)result._cursor;
    }
}

/*
 * Store capability via DDC: mem_cap[DDC.base + rs1] = cs2
 */
void helper_cheri_store_cap_ddc(CPURISCVState *env, uint32_t cs2,
                                target_ulong addr)
{
    target_ulong ea = check_ddc(env, addr, CHERI_CAP_SIZE,
                                CAP_PERM_STORE | CAP_PERM_STORE_CAP, GETPC());

    const cap_register_t *src = get_cap_reg_const(env, cs2);

    /* Store the two 64-bit halves */
    cpu_stq_data_ra(env, ea, (uint64_t)src->_cursor, GETPC());
    cpu_stq_data_ra(env, ea + 8, src->pesbt, GETPC());

    /* Update tag memory */
    hwaddr paddr = ea & ~(hwaddr)(CHERI_CAP_SIZE - 1);
    if (src->tag) {
        cheri_tag_set(paddr);
    } else {
        cheri_tag_clear(paddr);
    }
}

/*
 * Load capability via capability register: cd = mem_cap[cs1.cursor + offset]
 */
void helper_cheri_load_cap_via_cap(CPURISCVState *env, uint32_t cd,
                                   uint32_t cs1, target_ulong offset)
{
    target_ulong ea = check_cap(env, cs1, offset, CHERI_CAP_SIZE,
                                CAP_PERM_LOAD | CAP_PERM_LOAD_CAP, GETPC());

    uint64_t cursor_val = cpu_ldq_data_ra(env, ea, GETPC());
    uint64_t pesbt_val  = cpu_ldq_data_ra(env, ea + 8, GETPC());

    hwaddr paddr = ea & ~(hwaddr)(CHERI_CAP_SIZE - 1);
    bool tag = cheri_tag_get(paddr);

    cap_register_t result;
    result.pesbt   = pesbt_val;
    result._cursor = cursor_val;
    result.flags   = 0;
    result.tag     = tag;
    cc128_decompress(&result);

    if (cd != 0) {
        env->gpcr[cd] = result;
        env->gpr[cd]  = (target_ulong)result._cursor;
    }
}

/*
 * Store capability via capability register: mem_cap[cs1.cursor + offset] = cs2
 */
void helper_cheri_store_cap_via_cap(CPURISCVState *env, uint32_t cs2,
                                    uint32_t cs1, target_ulong offset)
{
    target_ulong ea = check_cap(env, cs1, offset, CHERI_CAP_SIZE,
                                CAP_PERM_STORE | CAP_PERM_STORE_CAP, GETPC());

    const cap_register_t *src = get_cap_reg_const(env, cs2);

    cpu_stq_data_ra(env, ea, (uint64_t)src->_cursor, GETPC());
    cpu_stq_data_ra(env, ea + 8, src->pesbt, GETPC());

    hwaddr paddr = ea & ~(hwaddr)(CHERI_CAP_SIZE - 1);
    if (src->tag) {
        cheri_tag_set(paddr);
    } else {
        cheri_tag_clear(paddr);
    }
}

/* ===========================================================================
 * Atomic LR/SC via DDC
 * ===========================================================================*/

target_ulong helper_cheri_lr_ddc(CPURISCVState *env, target_ulong addr,
                                 uint32_t memop_size)
{
    uint32_t size = 1u << (memop_size & MO_SIZE);
    target_ulong ea = check_ddc(env, addr, size, CAP_PERM_LOAD, GETPC());
    target_ulong val;

    switch (memop_size & MO_SIZE) {
    case MO_8:
        val = (target_ulong)cpu_ldub_data_ra(env, ea, GETPC());
        break;
    case MO_16:
        val = (target_ulong)cpu_lduw_data_ra(env, ea, GETPC());
        break;
    case MO_32:
        val = (target_ulong)cpu_ldl_data_ra(env, ea, GETPC());
        break;
    case MO_64:
        val = (target_ulong)cpu_ldq_data_ra(env, ea, GETPC());
        break;
    default:
        val = 0;
    }

    /* Set the reservation */
    env->load_res = ea;
    env->load_val = val;
    return val;
}

target_ulong helper_cheri_sc_ddc(CPURISCVState *env, target_ulong addr,
                                 target_ulong val, uint32_t memop_size)
{
    uint32_t size = 1u << (memop_size & MO_SIZE);
    target_ulong ea = check_ddc(env, addr, size, CAP_PERM_STORE, GETPC());

    /* Check reservation */
    if (env->load_res != ea) {
        return 1;  /* SC failed */
    }
    env->load_res = -1;  /* Clear reservation */

    switch (memop_size & MO_SIZE) {
    case MO_8:
        cpu_stb_data_ra(env, ea, (uint8_t)val, GETPC());
        break;
    case MO_16:
        cpu_stw_data_ra(env, ea, (uint16_t)val, GETPC());
        break;
    case MO_32:
        cpu_stl_data_ra(env, ea, (uint32_t)val, GETPC());
        break;
    case MO_64:
        cpu_stq_data_ra(env, ea, (uint64_t)val, GETPC());
        break;
    }

    hwaddr paddr = ea;
    cheri_tag_clear(paddr);
    return 0;  /* SC succeeded */
}

/* ===========================================================================
 * Atomic LR/SC via capability register
 * ===========================================================================*/

target_ulong helper_cheri_lr_cap(CPURISCVState *env, uint32_t cs,
                                 target_ulong offset, uint32_t memop_size)
{
    uint32_t size = 1u << (memop_size & MO_SIZE);
    target_ulong ea = check_cap(env, cs, offset, size, CAP_PERM_LOAD,
                                GETPC());
    target_ulong val;

    switch (memop_size & MO_SIZE) {
    case MO_8:
        val = (target_ulong)cpu_ldub_data_ra(env, ea, GETPC());
        break;
    case MO_16:
        val = (target_ulong)cpu_lduw_data_ra(env, ea, GETPC());
        break;
    case MO_32:
        val = (target_ulong)cpu_ldl_data_ra(env, ea, GETPC());
        break;
    case MO_64:
        val = (target_ulong)cpu_ldq_data_ra(env, ea, GETPC());
        break;
    default:
        val = 0;
    }

    env->load_res = ea;
    env->load_val = val;
    return val;
}

target_ulong helper_cheri_sc_cap(CPURISCVState *env, uint32_t cs,
                                 target_ulong offset, target_ulong val,
                                 uint32_t memop_size)
{
    uint32_t size = 1u << (memop_size & MO_SIZE);
    target_ulong ea = check_cap(env, cs, offset, size, CAP_PERM_STORE,
                                GETPC());

    if (env->load_res != ea) {
        return 1;  /* SC failed */
    }
    env->load_res = -1;

    switch (memop_size & MO_SIZE) {
    case MO_8:
        cpu_stb_data_ra(env, ea, (uint8_t)val, GETPC());
        break;
    case MO_16:
        cpu_stw_data_ra(env, ea, (uint16_t)val, GETPC());
        break;
    case MO_32:
        cpu_stl_data_ra(env, ea, (uint32_t)val, GETPC());
        break;
    case MO_64:
        cpu_stq_data_ra(env, ea, (uint64_t)val, GETPC());
        break;
    }

    hwaddr paddr = ea;
    cheri_tag_clear(paddr);
    return 0;
}
