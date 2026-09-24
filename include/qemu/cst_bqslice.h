/*
 * Guest-insn slice bounding -- PRODUCT under the event-agency
 * discipline (see qemu/vclock-agency.h), formerly the #106
 * icount-feature bisection KNOB A.  Maccoy Merrell.
 *
 * WHAT IT IS.  A synthetic TB-slice budget on the DEFAULT clock: the icount
 * execution discipline's per-slice instruction budget (a bounded number of
 * instructions per uninterrupted TB chain, with a forced break through
 * cpu_handle_interrupt at each exhaustion), with NO icount timekeeping --
 * no deadline read, no VIRTUAL-clock coupling, no icount_get/icount_update,
 * no CF_USE_ICOUNT.
 *
 * PRODUCT ARMING: cst_bq_product_arm() -- called from the event-agency
 * arming edge at plugin install (plugins/system.c, system mode, TCG,
 * not icount) -- arms the slice at the documented
 * product quantum 65535.  The slice breakout is where the discipline
 * consumes VIRTUAL deadlines, so the quantum IS the discipline's
 * delivery bound, stated in guest instructions.  65535 is the u16
 * cadence icount itself runs at whenever a deadline exceeds the u16
 * budget (icount_prepare_for_run: insns_left = MIN(0xffff, budget)).
 *
 * QUANTUM OVERRIDE: CST_BUDGET_QUANTUM=<insns>, range [512, 65535].
 * 512 = TCG_MAX_INSNS, so a single TB can never exceed the quantum
 * (icount solves that case by regenerating a shorter TB via
 * cflags_next_tb; mirrored, but made unreachable by the floor).
 * Out-of-range or non-numeric ABORTS (a typo must not silently run a
 * different configuration than its label claims).
 *
 * EXACT MIRRORS (all in this tree, QEMU 10.0.8 base):
 *  - Translation: accel/tcg/translator.c gen_tb_start()/gen_tb_end() --
 *    the CF_USE_ICOUNT-gated sub of num_insns from icount_decr.u32, the
 *    existing brcond-LT-0 exit, and the st16 of the decremented count back
 *    to icount_decr.u16.low, emitted when the knob is armed on TBs without
 *    CF_USE_ICOUNT|CF_NOIRQ.  CF_NOIRQ TBs are NOT billed: icount can bill
 *    them because higher-level code guarantees budget (and the replay path
 *    strips CF_USE_ICOUNT, cpu-exec.c cpu_handle_exception); off-icount no
 *    such guarantee exists and an unchecked sub would wrap u16.low.  They
 *    are 1-insn unchained slivers; the exemption is a documented blind
 *    spot of the max-slice sanity, bounded by their count.
 *  - Mid-slice refill: accel/tcg/cpu-exec.c cpu_loop_exec_tb(), the
 *    TB_EXIT_REQUESTED && !cpu_loop_exit_requested() branch (the icount
 *    "Instruction counter expired" refill).  Chain already broken
 *    (*last_tb = NULL), the normal cpu_handle_interrupt pass follows on
 *    the loop iteration, u16.low reloads to the quantum, execution
 *    continues.  No icount_update, no icount_extra, no deadline.
 *  - Initial load: seeded at cpu_exec_loop() entry when u16.low == 0
 *    (icount's outer load lives in icount_prepare_for_run, which is
 *    deadline-derived and per scheduling round -- that locus is surface c,
 *    deliberately NOT mirrored; the knob's slice break stays inside the
 *    exec loop).
 *  - Mid-TB unwind refund: accel/tcg/translate-all.c
 *    cpu_restore_state_from_tb() adds insns_left back for CF_USE_ICOUNT
 *    TBs; mirrored for knob-billed TBs so a faulting TB's unexecuted tail
 *    is not billed (also what keeps a forced CF_NOIRQ re-execution step
 *    inside budget under icount).
 *  - WP excursions: under icount the excursion machinery saves/restores
 *    u16.low via icount_plugin_freeze/_thaw (accel/tcg/icount-common.c,
 *    called from cpu_plugin_spec_vtime_pause/_resume) -- a no-op on the
 *    default clock.  DECISION (per brief): the CP u16.low is saved at
 *    excursion open (beside the icount_plugin_freeze call, OUTSIDE the
 *    CST_NOFREEZE lever gate so the budget rule cannot silently change
 *    under another lever) and restored at excursion close (beside
 *    icount_plugin_thaw, which runs on both the normal and the abnormal
 *    longjmp exit).  Each SPEC-MODE dispatch (cpu_plugin_exec_tb /
 *    cpu_plugin_exec_inline, which inherit the prologue emission -- knob
 *    is translate-time-global, mirroring icount's effect on WP blocks)
 *    reloads a full quantum, so WP depth can never drain the CP slice and
 *    a spec TB can never see an exhausted budget.  A spec-mode dispatch
 *    with the knob armed but plugin_spec_mode clear is counted
 *    (nonspec_dispatch) rather than silently given budget.
 *
 * POSTURE GUARDS.  Armed together with -icount => FATAL at first exec-loop
 * entry (two writers of u16.low would corrupt both disciplines).  Armed in
 * a user-mode binary => FATAL (the WP save/restore bracket is softmmu-only).
 *
 * WITNESSES.  Counters only; healthy runs stay silent.  Sanity:
 * max_slice (max billed insns between refills, = quantum - u16.low at
 * refill) must be <= quantum and overruns (u16.low > quantum observed
 * at a refill -- the wrap/unbilled-writer tripwire) must be 0; a
 * violated invariant prints one [CSTBQ] tripwire row at exit.  The env
 * override banners at arming (an explicit opt-in earns an explicit
 * acknowledgement); the product arming edge is silent.
 */
#ifndef QEMU_CST_BQSLICE_H
#define QEMU_CST_BQSLICE_H

extern bool cst_bq_on;            /* armed (product edge, or env override) */
extern uint16_t cst_bq_quantum;   /* insns per slice, [512, 65535] */

/* Product arming edge (plugins/system.c): arm at the documented product
 * quantum (65535) unless the archival env override already armed.  Once
 * armed the slice stays armed for process life -- translated TBs carry
 * the billing prologue, so a disarm would strand an exhausted u16.low
 * with no refill site. */
void cst_bq_product_arm(void);

void cst_bq_note_seed(void);                    /* exec-loop-entry load    */
void cst_bq_note_breakout(uint16_t remaining);  /* mid-slice refill; pass
                                                 * u16.low BEFORE reload   */
void cst_bq_note_wp_reload(void);               /* spec dispatch quantum   */
void cst_bq_note_exc_save(void);                /* excursion-open CP save  */
void cst_bq_note_exc_restore(void);             /* excursion-close restore */
void cst_bq_note_nonspec_dispatch(void);        /* plugin dispatch, spec
                                                 * mode clear (tripwire)   */

#endif
