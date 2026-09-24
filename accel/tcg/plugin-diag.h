/*
 * Wrong-path excursion diagnostics: the env-gated CST_* instruments the
 * excursion window (plugin-window.c) calls.  Every one is off unless its
 * environment variable is set.
 *
 * Copyright (C) 2026, Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef ACCEL_TCG_PLUGIN_DIAG_H
#define ACCEL_TCG_PLUGIN_DIAG_H

#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)

#if defined(TARGET_RISCV)
/*
 * The mip bits a DEVICE owns outright: absent from csr.c's delegable_ints, so
 * no guest write can reach them, and their only writer is an interrupt
 * controller going through riscv_cpu_update_mip.  A speculative excursion has
 * nothing to roll back in them.  MTIP is deliberately not here -- see
 * cpu_plugin_arch_state_restore().
 */
#define RISCV_MIP_DEVICE_OWNED ((uint64_t)(MIP_MSIP | MIP_MEIP | MIP_SGEIP))

void cst_miperase_check(const CPURISCVState *env,
                        const CPURISCVState *saved,
                        uint64_t replay_set, uint64_t replay_clear);
#endif

/* CST_WPROTECT: write-protect guest RAM for the excursion. */
extern bool g_wprot_active;
bool wprot_ready(void);
void wprot_setprot(int prot);

/* CST_STATEDIFF: snapshot at open, report un-restored state at close. */
void sdiff_snapshot(CPUState *cpu);
void sdiff_compare(CPUState *cpu);

/* CST_TLB_SAVE: snapshot the full TLB at open, revert it at close. */
void tlbsave_snapshot(CPUState *cpu);
void tlbsave_restore(CPUState *cpu);

/* CST_NOFREEZE: run excursions without freezing the guest clock. */
bool cst_nofreeze(void);

/* CST_CLKAUDIT: sample every guest-clock root at open and close. */
typedef enum {
    CST_CLKROOT_VIRTUAL,
    CST_CLKROOT_VMTICKS,
    CST_CLKROOT_VIRTUAL_RT,
    CST_CLKROOT_HOST,
    CST_CLKROOT_REALTIME,
    CST_CLKROOT_HOSTTICKS,
    CST_CLKROOT__COUNT
} CstClkRoot;

bool cst_clkaudit_on(void);
void cst_clkaudit_sample(int64_t v[CST_CLKROOT__COUNT]);
void cst_clkaudit_note_pause(void);
void cst_clkaudit_check(CPUState *cpu,
                        const int64_t pre_thaw[CST_CLKROOT__COUNT]);

/* CST_CLKPROBE: TSC-vs-monotonic skew across the freeze. */
void cst_clkprobe(bool resume);

#endif /* CONFIG_PLUGIN && !CONFIG_USER_ONLY */

#endif /* ACCEL_TCG_PLUGIN_DIAG_H */
