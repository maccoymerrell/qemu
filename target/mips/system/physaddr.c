/*
 * MIPS TLB (Translation lookaside buffer) helpers.
 *
 *  Copyright (c) 2004-2005 Jocelyn Mayer
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
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/page-protection.h"
#include "../internal.h"

static int is_seg_am_mapped(unsigned int am, bool eu, int mmu_idx)
{
    /*
     * Interpret access control mode and mmu_idx.
     *           AdE?     TLB?
     *      AM  K S U E  K S U E
     * UK    0  0 1 1 0  0 - - 0
     * MK    1  0 1 1 0  1 - - !eu
     * MSK   2  0 0 1 0  1 1 - !eu
     * MUSK  3  0 0 0 0  1 1 1 !eu
     * MUSUK 4  0 0 0 0  0 1 1 0
     * USK   5  0 0 1 0  0 0 - 0
     * -     6  - - - -  - - - -
     * UUSK  7  0 0 0 0  0 0 0 0
     */
    int32_t adetlb_mask;

    switch (mmu_idx) {
    case 3: /* ERL */
        /* If EU is set, always unmapped */
        if (eu) {
            return 0;
        }
        /* fall through */
    case MIPS_HFLAG_KM:
        /* Never AdE, TLB mapped if AM={1,2,3} */
        adetlb_mask = 0x70000000;
        goto check_tlb;

    case MIPS_HFLAG_SM:
        /* AdE if AM={0,1}, TLB mapped if AM={2,3,4} */
        adetlb_mask = 0xc0380000;
        goto check_ade;

    case MIPS_HFLAG_UM:
        /* AdE if AM={0,1,2,5}, TLB mapped if AM={3,4} */
        adetlb_mask = 0xe4180000;
        /* fall through */
    check_ade:
        /* does this AM cause AdE in current execution mode */
        if ((adetlb_mask << am) < 0) {
            return TLBRET_BADADDR;
        }
        adetlb_mask <<= 8;
        /* fall through */
    check_tlb:
        /* is this AM mapped in current execution mode */
        return ((adetlb_mask << am) < 0);
    default:
        g_assert_not_reached();
    };
}

static int get_seg_physical_address(CPUMIPSState *env, hwaddr *physical,
                                    int *prot, target_ulong real_address,
                                    MMUAccessType access_type, int mmu_idx,
                                    unsigned int am, bool eu,
                                    target_ulong segmask,
                                    hwaddr physical_base)
{
    int mapped = is_seg_am_mapped(am, eu, mmu_idx);

    if (mapped < 0) {
        /* is_seg_am_mapped can report TLBRET_BADADDR */
        return mapped;
    } else if (mapped) {
        /* The segment is TLB mapped */
        return env->tlb->map_address(env, physical, prot, real_address,
                                     access_type);
    } else {
        /* The segment is unmapped */
        *physical = physical_base | (real_address & segmask);
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return TLBRET_MATCH;
    }
}

static int get_segctl_physical_address(CPUMIPSState *env, hwaddr *physical,
                                       int *prot, target_ulong real_address,
                                       MMUAccessType access_type, int mmu_idx,
                                       uint16_t segctl, target_ulong segmask)
{
    unsigned int am = (segctl & CP0SC_AM_MASK) >> CP0SC_AM;
    bool eu = (segctl >> CP0SC_EU) & 1;
    hwaddr pa = ((hwaddr)segctl & CP0SC_PA_MASK) << 20;

    return get_seg_physical_address(env, physical, prot, real_address,
                                    access_type, mmu_idx, am, eu, segmask,
                                    pa & ~(hwaddr)segmask);
}

int get_physical_address(CPUMIPSState *env, hwaddr *physical,
                         int *prot, target_ulong real_address,
                         MMUAccessType access_type, int mmu_idx)
{
    /* User mode can only access useg/xuseg */
#if defined(TARGET_MIPS64)
    int user_mode = mmu_idx == MIPS_HFLAG_UM;
    int supervisor_mode = mmu_idx == MIPS_HFLAG_SM;
    int kernel_mode = !user_mode && !supervisor_mode;
    int UX = (env->CP0_Status & (1 << CP0St_UX)) != 0;
    int SX = (env->CP0_Status & (1 << CP0St_SX)) != 0;
    int KX = (env->CP0_Status & (1 << CP0St_KX)) != 0;
#endif
    int ret = TLBRET_MATCH;
    /* effective address (modified for KVM T&E kernel segments) */
    target_ulong address = real_address;

    if (address <= USEG_LIMIT) {
        /* useg */
        uint16_t segctl;

        if (address >= 0x40000000UL) {
            segctl = env->CP0_SegCtl2;
        } else {
            segctl = env->CP0_SegCtl2 >> 16;
        }
        ret = get_segctl_physical_address(env, physical, prot,
                                          real_address, access_type,
                                          mmu_idx, segctl, 0x3FFFFFFF);
#if defined(TARGET_MIPS64)
    } else if (address < 0x4000000000000000ULL) {
        /* xuseg */
        if (UX && address <= (0x3FFFFFFFFFFFFFFFULL & env->SEGMask)) {
            ret = env->tlb->map_address(env, physical, prot,
                                        real_address, access_type);
        } else {
            ret = TLBRET_BADADDR;
        }
    } else if (address < 0x8000000000000000ULL) {
        /* xsseg */
        if ((supervisor_mode || kernel_mode) &&
            SX && address <= (0x7FFFFFFFFFFFFFFFULL & env->SEGMask)) {
            ret = env->tlb->map_address(env, physical, prot,
                                        real_address, access_type);
        } else {
            ret = TLBRET_BADADDR;
        }
    } else if (address < 0xC000000000000000ULL) {
        /* xkphys */
        if ((address & 0x07FFFFFFFFFFFFFFULL) <= env->PAMask) {
            /* KX/SX/UX bit to check for each xkphys EVA access mode */
            static const uint8_t am_ksux[8] = {
                [CP0SC_AM_UK]    = (1u << CP0St_KX),
                [CP0SC_AM_MK]    = (1u << CP0St_KX),
                [CP0SC_AM_MSK]   = (1u << CP0St_SX),
                [CP0SC_AM_MUSK]  = (1u << CP0St_UX),
                [CP0SC_AM_MUSUK] = (1u << CP0St_UX),
                [CP0SC_AM_USK]   = (1u << CP0St_SX),
                [6]              = (1u << CP0St_KX),
                [CP0SC_AM_UUSK]  = (1u << CP0St_UX),
            };
            unsigned int am = CP0SC_AM_UK;
            unsigned int xr = (env->CP0_SegCtl2 & CP0SC2_XR_MASK) >> CP0SC2_XR;

            if (xr & (1 << ((address >> 59) & 0x7))) {
                am = (env->CP0_SegCtl1 & CP0SC1_XAM_MASK) >> CP0SC1_XAM;
            }
            /* Does CP0_Status.KX/SX/UX permit the access mode (am) */
            if (env->CP0_Status & am_ksux[am]) {
                ret = get_seg_physical_address(env, physical, prot,
                                               real_address, access_type,
                                               mmu_idx, am, false, env->PAMask,
                                               0);
            } else {
                ret = TLBRET_BADADDR;
            }
        } else {
            ret = TLBRET_BADADDR;
        }
    } else if (address < 0xFFFFFFFF80000000ULL) {
        /* xkseg */
        if (kernel_mode && KX &&
            address <= (0xFFFFFFFF7FFFFFFFULL & env->SEGMask)) {
            ret = env->tlb->map_address(env, physical, prot,
                                        real_address, access_type);
        } else {
            ret = TLBRET_BADADDR;
        }
#endif
    } else if (address < KSEG1_BASE) {
        /* kseg0 */
        ret = get_segctl_physical_address(env, physical, prot, real_address,
                                          access_type, mmu_idx,
                                          env->CP0_SegCtl1 >> 16, 0x1FFFFFFF);
    } else if (address < KSEG2_BASE) {
        /* kseg1 */
        ret = get_segctl_physical_address(env, physical, prot, real_address,
                                          access_type, mmu_idx,
                                          env->CP0_SegCtl1, 0x1FFFFFFF);
    } else if (address < KSEG3_BASE) {
        /* sseg (kseg2) */
        ret = get_segctl_physical_address(env, physical, prot, real_address,
                                          access_type, mmu_idx,
                                          env->CP0_SegCtl0 >> 16, 0x1FFFFFFF);
    } else {
        /*
         * kseg3
         * XXX: debug segment is not emulated
         */
        ret = get_segctl_physical_address(env, physical, prot, real_address,
                                          access_type, mmu_idx,
                                          env->CP0_SegCtl0, 0x1FFFFFFF);
    }
    return ret;
}

/*
 * Debug-read fallback through the guest page tables — v4 default #2,
 * maintainer-vetoable.
 *
 * A debug read (gdbstub, monitor, qemu_plugin_read_memory_vaddr — the
 * ChampSim Tracer's content-gate refresh) resolves through the software
 * TLB matched against the live EntryHi.ASID, so immediately after a
 * switch_mm a RESIDENT page's translation is simply not in the TLB and
 * the read fails even though the guest maps the page.  When the model
 * implements the hardware page-table walker (Config3.PW, PWCtl.PWEn),
 * fall back to the same directory walk the walker performs, from CP0
 * PWBase, SIDE-EFFECT-FREE: PWBase is used strictly as a TRANSLATION
 * INPUT — never stored, compared, or reported as an identity — and the
 * walk inserts no TLB entry and raises no exception.  Directory
 * pointers are virtual (kseg0 in practice) and resolve through
 * get_physical_address; entries are read from guest RAM physically.
 * Deliberately narrow: huge-page directory entries and non-4K leaf
 * configurations are not decoded — the walk reports failure and the
 * caller keeps today's behaviour (an honest gate-off, counted by the
 * plugin's unreadable-at-refresh witness).
 */
static bool mips_htw_walk_debug(CPUState *cs, vaddr address, hwaddr *out)
{
#if defined(TARGET_MIPS64)
    /* QEMU models the hardware page-table walker for 32-bit MIPS only:
     * page_table_walk_refill and the CP0PF_* fields it reads are
     * compiled out under TARGET_MIPS64 (tcg/system/tlb_helper.c), so
     * there is no walker here to mirror and no guest on such a model
     * programs PWBase.  The debug read keeps the TLB-resident path —
     * the same honest degradation every model without Config3.PW takes
     * under content gating, counted by the unreadable-at-refresh
     * witness.  No MIPS model is excluded by this; mirror the walker
     * here if upstream ever models it for MIPS64. */
    return false;
#else
    CPUMIPSState *env = cpu_env(cs);
    int gdw = (env->CP0_PWSize >> CP0PS_GDW) & 0x3F;
    int udw = (env->CP0_PWSize >> CP0PS_UDW) & 0x3F;
    int mdw = (env->CP0_PWSize >> CP0PS_MDW) & 0x3F;
    int ptw = (env->CP0_PWSize >> CP0PS_PTW) & 0x3F;
    int ptew = (env->CP0_PWSize >> CP0PS_PTEW) & 0x3F;
    int pf_gdw = (env->CP0_PWField >> CP0PF_GDW) & 0x3F;
    int pf_udw = (env->CP0_PWField >> CP0PF_UDW) & 0x3F;
    int pf_mdw = (env->CP0_PWField >> CP0PF_MDW) & 0x3F;
    int pf_ptw = (env->CP0_PWField >> CP0PF_PTW) & 0x3F;
    int pf_ptew = (env->CP0_PWField >> CP0PF_PTEW) & 0x3F;
    int hugepg = (env->CP0_PWCtl >> CP0PC_HUGEPG) & 0x1;
    int psn = (env->CP0_PWCtl >> CP0PC_PSN) & 0x3F;
    MemOp native_op =
        (((env->CP0_PWSize >> CP0PS_PS) & 1) == 0) ? MO_32 : MO_64;
    MemOp directory_mop = (hugepg && (ptew == 1)) ? native_op + 1 : native_op;
    MemOp leaf_mop = (ptew == 1) ? native_op + 1 : native_op;
    uint64_t base = env->CP0_PWBase;
    const struct { int dw; int pf; } lvl[3] = {
        { gdw, pf_gdw }, { udw, pf_udw }, { mdw, pf_mdw },
    };

    if (!(env->CP0_Config3 & (1 << CP0C3_PW)) ||
        !(env->CP0_PWCtl & (1 << CP0PC_PWEN)) ||
        !(gdw > 0 || udw > 0 || mdw > 0) || ptew > 1 ||
        pf_ptw != TARGET_PAGE_BITS || base == 0) {
        return false;
    }

    for (int l = 0; l < 3; l++) {
        hwaddr epa;
        int eprot;
        unsigned esz = memop_size(directory_mop);
        uint8_t buf[8];
        uint64_t entry;

        if (lvl[l].dw <= 0) {
            continue;
        }
        uint64_t eva = base |
            ((uint64_t)((address >> lvl[l].pf) & ((1 << lvl[l].dw) - 1))
             << directory_mop);
        if (get_physical_address(env, &epa, &eprot, eva, MMU_DATA_LOAD,
                                 mips_env_mmu_index(env)) != TLBRET_MATCH) {
            return false;
        }
        cpu_physical_memory_read(epa, buf, esz);
        if (esz == 8) {
            entry = mips_env_is_bigendian(env) ? ldq_be_p(buf) : ldq_le_p(buf);
        } else {
            entry = mips_env_is_bigendian(env) ? (uint32_t)ldl_be_p(buf)
                                               : (uint32_t)ldl_le_p(buf);
        }
        if (hugepg && extract64(entry, psn, 1)) {
            return false;               /* huge page: not decoded here */
        }
        base = entry;
    }

    {
        hwaddr ppa;
        int pprot;
        unsigned psz = memop_size(leaf_mop);
        uint8_t buf[8];
        uint64_t pte;
        unsigned entry_bits = psz << 3;
        int ptei = pf_ptew;
        uint64_t pva = base |
            ((uint64_t)((address >> pf_ptw) & ((1 << ptw) - 1)) << leaf_mop);

        if (get_physical_address(env, &ppa, &pprot, pva, MMU_DATA_LOAD,
                                 mips_env_mmu_index(env)) != TLBRET_MATCH) {
            return false;
        }
        cpu_physical_memory_read(ppa, buf, psz);
        if (psz == 8) {
            pte = mips_env_is_bigendian(env) ? ldq_be_p(buf) : ldq_le_p(buf);
        } else {
            pte = mips_env_is_bigendian(env) ? (uint32_t)ldl_be_p(buf)
                                             : (uint32_t)ldl_le_p(buf);
        }
        /* Same layout conversion the walker's get_tlb_entry_layout does. */
        if (ptei > (int)entry_bits) {
            ptei -= 32;
        }
        if (ptei < 2) {
            return false;
        }
        pte >>= (ptei - 2);
        uint64_t rixi = pte & 3;
        pte >>= 2;
        pte |= rixi << CP0EnLo_XI;
        if (!(pte & 2)) {
            return false;               /* EntryLo.V clear: not present */
        }
        *out = (hwaddr)((pte >> 6) << 12) |
               (address & ((1 << TARGET_PAGE_BITS) - 1));
        return true;
    }
#endif
}

hwaddr mips_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    CPUMIPSState *env = cpu_env(cs);
    hwaddr phys_addr;
    int prot;

    if (get_physical_address(env, &phys_addr, &prot, addr, MMU_DATA_LOAD,
                             mips_env_mmu_index(env)) != 0) {
        if (mips_htw_walk_debug(cs, addr, &phys_addr)) {
            return phys_addr;
        }
        return -1;
    }
    return phys_addr;
}
