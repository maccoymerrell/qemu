/*
 * MIPS MT MVPControl and CP0 timer condition instruments
 * (MIPS_MVP_DEBUG).
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef MIPS_MVP_DEBUG_H
#define MIPS_MVP_DEBUG_H

/*
 * MVPControl condition instrument.  MIPS MT defines MVPControl as one
 * register per processor, shared by every VPE of that processor, and the
 * guest's dvpe()/evpe(prev) nesting protocol restores EVP only when the
 * dvpe that opened the section observed EVP already set.  A VPE left with
 * EVP clear fails mips_vpe_active() and mips_cpu_has_work() then forces
 * has_work false, so it never leaves WAIT again.
 *
 * The instrument records every read and every write of the shared word,
 * tracks how many VPEs currently owe an evpe restore, and names the
 * strand structurally: EVP clear with no outstanding restorer is a
 * processor that no future evpe can re-enable.  It is off unless
 * MIPS_MVP_DEBUG is set in the environment.  See
 * target/mips/system/mvp-debug.c.
 */
enum {
    MIPS_MVP_DVPE_RD,   /* dvpe on a VPE that owns MVP: opens a section  */
    MIPS_MVP_DVPE_WR,
    MIPS_MVP_EVPE_RD,   /* evpe on a VPE that owns MVP: closes it        */
    MIPS_MVP_EVPE_WR,
    MIPS_MVP_DVPE_NA,   /* dvpe/evpe on a VPE without MVP: architecturally */
    MIPS_MVP_EVPE_NA,   /* a no-op, recorded because the guest still ran it */
    MIPS_MVP_MTC0_WR,
    MIPS_MVP_MTC0_NA,
    /*
     * Run-state edges.  cs->halted decides whether a vCPU is offered to the
     * scheduler at all, so a stall in which every VPE is halted is only
     * explained by naming, for each VPE, which instruction on which VPE
     * halted it.  Each of these records the setter, the target and the
     * setter's guest PC; a per-VPE latch keeps the newest of each kind so
     * the answer survives the ring wrapping.
     */
    MIPS_MVP_SLEEP_DVPE,  /* dvpe put a sibling to sleep                  */
    MIPS_MVP_SLEEP_DVP,   /* dvp (R6) put a sibling to sleep              */
    MIPS_MVP_SLEEP_TC,    /* mtc0/mttc0 TCHalt deactivated a TC           */
    MIPS_MVP_SLEEP_WAIT,  /* the VPE executed WAIT                        */
    MIPS_MVP_WAKE_EVPE,
    MIPS_MVP_WAKE_EVP,
    MIPS_MVP_WAKE_TC,
};
/*
 * CP0 Count/Compare condition instrument, latched per VPE beside the
 * run-state edges above and printed by the same report.
 *
 * A guest that stops making progress with every VPE idle in WAIT and no
 * interrupt pending looks identical to a guest that is merely idle -- the
 * architectural state is the same word for word, measured.  What tells them
 * apart is not in the guest at all: it is where the HOST QEMUTimer that will
 * deliver the next tick has been armed, relative to where the guest's own
 * Compare asked for it.  cpu_mips_timer_update has one clamp arm that arms it
 * somewhere else, so the last arming of each kind is latched here and the
 * arms are counted, per VPE.
 */
enum {
    MIPS_CP0T_ARM,          /* deadline programmed from Compare - Count     */
    MIPS_CP0T_ARM_BEHIND,   /* target not in the future -> 2^24 (rescue)    */
    MIPS_CP0T_FIRE,         /* expiry delivered: Cause.TI set, IP7 raised   */
};
extern int mips_mvp_debug;
void mips_mvp_debug_init(void);
void mips_mvp_note(CPUMIPSState *env, int op, uint32_t before, uint32_t after);
void mips_mvp_note_gate(CPUMIPSState *env);
void mips_mvp_note_run(CPUState *target, int op);
void mips_cp0t_note(CPUMIPSState *env, int op, uint32_t wait,
                    int64_t now_ns, int64_t deadline_ns);

#endif /* MIPS_MVP_DEBUG_H */
