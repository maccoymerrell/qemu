/*
 * TCG guest-instruction slice: the delivery bound of the VIRTUAL-clock
 * event agency.  The model is described once, in qemu/vclock-agency.h
 * (mechanism 1); this header is the slice's interface.
 *
 * Copyright (C) 2026, Maccoy Merrell
 *
 * The slice mirrors icount's budget handling exactly, at four sites:
 *
 *   billed    accel/tcg/translator.c gen_tb_start()/gen_tb_end(): the
 *             icount prologue's sub, exit test and st16 back to
 *             icount_decr.u16.low, on TBs without CF_USE_ICOUNT|CF_NOIRQ.
 *             CF_NOIRQ TBs (one-instruction unchained re-executions) are
 *             not billed, because nothing guarantees their budget and
 *             an unchecked sub would wrap u16.low.
 *   refilled  accel/tcg/cpu-exec.c cpu_loop_exec_tb(), on
 *             TB_EXIT_REQUESTED without cpu_loop_exit_requested(), where
 *             icount refills its expired counter.
 *   seeded    accel/tcg/cpu-exec.c cpu_exec_loop() entry, when u16.low
 *             is 0.
 *   refunded  accel/tcg/translate-all.c cpu_restore_state_from_tb(): a
 *             faulting billed TB's unexecuted tail is added back.
 *
 * CST_BUDGET_QUANTUM=<insns> overrides the quantum within [512, 65535];
 * 512 is TCG_MAX_INSNS, so one TB can never exceed the quantum.  An
 * out-of-range or non-numeric value aborts, and an accepted override
 * prints a banner.  The counters below are silent on a healthy run: at
 * exit a [CSTBQ] tripwire row is printed only when max_slice (billed
 * instructions between refills) exceeds the quantum or an overrun
 * (u16.low above the quantum at a refill) was seen.
 */
#ifndef QEMU_TCG_SLICE_H
#define QEMU_TCG_SLICE_H

extern bool tcg_slice_armed;      /* armed (plugin install or env override) */
extern uint16_t tcg_slice_quantum; /* insns per slice, [512, 65535] */

/*
 * Arming at plugin install (plugins/system.c): arm at quantum 65535
 * unless the CST_BUDGET_QUANTUM override already armed.  There is no
 * disarm: a TB carrying the billing prologue would strand an exhausted
 * u16.low with no refill site.
 */
void tcg_slice_arm(void);

void tcg_slice_note_seed(void);              /* exec-loop-entry load    */
void tcg_slice_note_breakout(uint16_t remaining); /* mid-slice refill; pass
                                                   * u16.low BEFORE reload */
void tcg_slice_note_wp_reload(void);         /* spec dispatch quantum   */
void tcg_slice_note_exc_save(void);          /* excursion-open CP save  */
void tcg_slice_note_exc_restore(void);       /* excursion-close restore */
void tcg_slice_note_nonspec_dispatch(void);  /* plugin dispatch, spec
                                              * mode clear (tripwire)   */

#endif
