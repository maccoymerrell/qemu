/*
 * Wrong-Path Tracing Plugin — option parser.
 *
 * Plugin args arrive as `key=value`.  parse_plugin_options() fills
 * PluginConfig from argc/argv via a typed setter table; the caller
 * then applies each field to its final destination.
 *
 * String fields are g_strdup'd; plugin_config_free() releases them.
 * Long-term owners should transfer (assign + null) rather than copy.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_PLUGIN_CONFIG_H
#define CHAMPSIM_TRACER_PLUGIN_CONFIG_H

#include "champsim_tracer.h"

/*
 * Default user-clock stall ceiling (see PluginConfig::stall_ceiling), and
 * the level at which the developing stall is first reported.
 *
 * Both numbers are measured, not guessed (cst_runs/fence, 304 contended
 * marker cells on the devio fixture): a healthy capture's worst stall is
 * 2.2e5 architectural instructions (the fsync path, measured by the
 * user_clock_worst_stall counter this ceiling shares), while cells that
 * enter the stall condition stall for tens of millions and STILL recover —
 * the largest recovery observed was 1.25e8 instructions, while the cells
 * that never recovered were still stalled at 1.6e8 when their
 * 900-second cap ended them.  The ceiling is set at twice the largest
 * recovery on record (~1200x anything healthy), so it does not truncate a
 * capture that would have finished, and it ends the case that otherwise
 * never would.  The warning level is where an operator wants to
 * know a stall is developing, long before the ceiling acts.
 *
 * The bound is what is measured here; the condition's MECHANISM is not
 * settled and no name for it is asserted in this file.  Tick saturation
 * specifically is ruled out as the selector: the tracer's own tick-tax
 * ratio is LOWER in the stalled cells than in healthy ones (see the TICK
 * TAX note in champsim_tracer.cc).  A ceiling is a termination bound and
 * carries no theory of what it is bounding.
 */
#define CST_STALL_CEILING_DEFAULT 256000000ull
#define CST_STALL_WARN_DEFAULT     32000000ull

/*
 * Default ANY-CONTEXT stall ceiling (see PluginConfig::stall_ceiling_any).
 *
 * The owned-context ceiling above only counts while the traced process is
 * RUNNING.  It therefore cannot bound the case where the traced process is
 * not running at all — killed after the window opened, or blocked forever
 * in a syscall — while the rest of the guest stays busy.  In that state the
 * user clock is frozen, the END marker can never execute, no owned
 * instruction is ever retired, and nothing ends the run.
 *
 * This ceiling counts instructions the guest retires in ANY context since
 * the pinned user clock last advanced, so it holds whether the traced
 * process is spinning in the kernel, blocked, or gone.  It is a termination
 * bound, not a health check: a healthy traced process may legitimately stop
 * running for a long time, and the tighter owned-context ceiling above
 * already covers the far more common "running and never returning" case.
 *
 * MEASURED, not guessed (cst_runs/certainty): with a busy guest and the
 * traced process asleep, the counter advances 5.8-21.5 M instructions per
 * SECOND of guest time (30 s of guest sleep = 1.75e8; 1 s = 2.15e7 in the
 * densest configuration).  The longest idle any test in this suite creates
 * on purpose is the system churn test's ~30 s, so the default clears the
 * worst-case rate for that idle by 3x — about 93 seconds of guest time in
 * which the traced process does not run at all.  A workload whose traced
 * process idles longer should RAISE it, not disable it.
 */
#define CST_STALL_ANY_CEILING_DEFAULT 2000000000ull
#define CST_STALL_ANY_WARN_DEFAULT     250000000ull

struct PluginConfig {
    int       wp_depth          = 64;
    /* Wrong-path pruning level (wpprune=N): skip WP simulation for cold
     * branches.  0 = no pruning (default); 1 = drop WP for a branch never
     * seen taken on the correct path (indirect: < 2 observed targets, i.e.
     * monomorphic — no alternative target to mispredict toward); 2 = also
     * drop WP unless the branch has been seen BOTH taken and not-taken. */
    int       wp_prune          = 0;
    /* irdf=1: cross-check QEMU's own per-instruction dataflow against the
     * tracer's Capstone-derived register sets, at translation, and write
     * the verdict to the sidecar log.  Reads only -- a trace captured with
     * it on is byte-identical to one captured with it off. */
    bool      irdf              = false;
    bool      enable_wp         = true;
    bool      enable_mem_data   = false;
    bool      enable_reg_data   = false;
    /* Per-path data flags.  Tristate: -1 = unset (inherit from the
     * matching CP flag), 0 = off, 1 = on.  Lets users keep CP data on
     * but drop the WP-side data — typically the dominant share of
     * trace bytes — without affecting CP capture. */
    int       wp_mem_data       = -1;
    int       wp_reg_data       = -1;
    /* Histogram intervals per segment; 0 disables (default).  Non-zero
     * adds per-interval breakdowns of the attribution tables to the
     * per-segment summary. */
    int       histogram_intervals = 0;
    /* Synchronous-fault handler tracing (faults=0/1, system mode).  When on
     * (default), a synchronous fault detours execution into a handler that is
     * traced as first-class code at its exception-nesting depth, and the
     * interrupted basic block reassembles whole after the handler via the
     * kernel-handler merge (today's behavior).  faults=0 EXCLUDES the handler
     * excursion: capture is suspended across the handler exactly as an
     * asynchronous interrupt's is, the interrupted block still emits whole
     * (the merge is kept), but it carries no fault anchors and every entry's
     * depth trailer stays 0.  Inert in user mode (no fault stack). */
    int       faults            = 1;
    /* Asynchronous-interrupt handler tracing (interrupts=0/1, system mode).
     * When off (default), an async interrupt's whole delivery-to-return
     * excursion is excluded — capture suspends and the interrupted flow seals
     * against its real successor (today's behavior).  interrupts=1 TRACES the
     * handler: its kernel basic blocks appear at exception depth >= 1 between
     * the interrupted context's entries, attributed to the interrupted address
     * space through the same content-gate rule a synchronous
     * fault uses.  The wire carries it through the existing depth trailer — no
     * new records.  Inert in user mode (no asynchronous interrupts). */
    int       interrupts        = 0;
    /* Block-device (disk) I/O records (devio=0/1, system mode only).
     * When on (default), the plugin brackets disk requests in the body
     * stream with DEVIO_START/STOP records (system emulation only; a
     * no-op without disk traffic, so device-free traces are unchanged).
     * devio=0 disables the block hook entirely. */
    int       devio             = 1;
    /* Physical-page capture (physaddr=0/1, system mode only).  When on,
     * every load/store carries the physical PAGE base of its access via the
     * CST_FID_LOAD_PPAGE / STORE_PPAGE families, so a consumer can rebuild
     * the physical address as  ppage | (vaddr & CST_PPAGE_OFFSET_MASK).
     * Off by default; ignored (forced off) in user mode, where no
     * translation exists.  A device-/physaddr-free trace is unchanged. */
    int       physaddr          = 0;
    /* Opportunistic branch-alternate minting (static_templates=0/1, both
     * modes).  When on, at every evaluated branch the plugin decodes the
     * UNTAKEN side's true BB and mints it as a never-executed dictionary
     * template (if not already covered), so the dictionary convergently
     * covers the fall-through / branch-target space a trace-inferred
     * wrong-path consumer needs.  Off by default. */
    int       static_templates  = 0;
    /* Depth-N alternate exploration (static_depth=N).  From each minted
     * alternate BB, follow its statically-known successors — fall-through
     * always, and a direct branch's decoded target too — recursively up to
     * N levels, minting each never-executed block along the way (an indirect
     * terminator has no static target, so that edge ends the chain).  0 mints
     * only the immediate untaken side.  Inert unless static_templates=1. */
    int       static_depth      = CST_ALT_DEPTH_DEFAULT;
    /* Self-modifying-code per-PC revision cap (smc_revisions=N).  When a
     * correct-path (asid_root, start_pc) slot mints more than this many
     * DISTINCT executed program-text states, minting stops and the body keeps
     * referencing the last revision (a LOUD once-per-segment warning fires).
     * A BUG DETECTOR, not a fidelity budget (smc_plan.md §5-A): default 1024,
     * sized far above any real SMC pattern.  The CST_SMC_REVISION_CAP env var
     * overrides this at apply time (for the validator's cap-overflow test). */
    uint32_t  smc_revisions       = 1024;
    /* Per-template IFRAME trigger interval.  0 disables. */
    uint32_t  iframe_rate         = 100000;
    /* Per-image byte offset of the guest kernel's current-task pointer
     * within its per-CPU region (curtask_off=0x...; system mode,
     * consumed by the x86-64 target).  Declared to QEMU at install so
     * kernel-privilege thread identity resolves for tasks with no TLS
     * base.  @curtask_off_set distinguishes "not given" (legacy
     * collapse-onto-0 behaviour, byte-identical) from any given value
     * — 0 is a legal offset, not a sentinel. */
    uint64_t  curtask_off       = 0;
    bool      curtask_off_set   = false;
    uint64_t  simpoint_interval = 100000000ULL;
    uint64_t  trace_start_insn  = 0;
    uint64_t  trace_stop_insn   = UINT64_MAX;
    /* Simpoint windowing (only when simpoints_file is set).
     *   warmup_insns     : prime length before each simpoint;
     *                       start = max(0, sp->start_insn - warmup).
     *   simulation_insns : length at-and-after the simpoint;
     *                       stop = sp->start_insn + simulation.  0
     *                       (default) keeps legacy stop = sp->start +
     *                       simpoint_interval. */
    uint64_t  warmup_insns      = 0;
    uint64_t  simulation_insns  = 0;
    char     *output_path       = nullptr;   /* g_strdup, owned */
    char     *compress_cmd      = nullptr;   /* g_strdup, owned */
    char     *program_name      = nullptr;   /* g_strdup, owned */
    char     *simpoints_file    = nullptr;   /* g_strdup, owned */
    char     *comment           = nullptr;   /* g_strdup, owned */

    /*
     * Symbol-based trace start (trace_window=symbol:...).  Trace
     * begins on the @start_symbol_occurrence-th time the symbol
     * appears as a BB entry; runs @simulation_insns insns after.
     * warmup is not meaningful here.
     */
    char     *start_symbol      = nullptr;   /* g_strdup, owned */
    uint64_t  start_symbol_occurrence = 1;

    /*
     * Set from trace_window=; lets the runtime validate that
     * warmup=/start=/etc. aren't mixed across modes.  AUTO (unset)
     * falls back to the legacy flat-flags behavior.
     */
    enum WindowMode {
        WIN_AUTO     = 0,
        WIN_ICOUNT   = 1,
        WIN_SIMPOINT = 2,
        WIN_SYMBOL   = 3,
        /* Guest-driven: a magic marker instruction in the traced
         * process opens the segment, a second one closes it.  The only
         * window source that needs no ELF symbol table or host icount,
         * so it works in system mode (x86 only for now). */
        WIN_MARKER   = 4,
    };
    int window_mode = WIN_AUTO;

    /*
     * Marker-window multi-process policy (trace_window=marker:policy=...).
     * Governs how WIN_MARKER treats more than one marker-emitting process
     * (whole-system multi-ASID, Stage B).
     *   latch     (0, default): each process that runs the START marker
     *                           joins the owned set and is traced; the
     *                           segment closes when the LAST open window's
     *                           END marker fires (owned set empties) or the
     *                           icount budget is met, whichever comes first.
     *   trace-all (1): Stage B2 — the FIRST START begins tracing ALL
     *                  contexts/ASIDs (no foreign-drop) until that first
     *                  process runs its END marker (or the icount budget is
     *                  met).  Only the capture gate widens: the icount clock
     *                  and END detection still ride that first marker
     *                  process's user instructions (decision #4), so the
     *                  owned set stays the single clock pin.
     */
    enum MarkerPolicy { MARKER_LATCH = 0, MARKER_TRACE_ALL = 1 };
    int marker_policy = MARKER_LATCH;

    /* True once a marker window has been given any SimPoint-schedule key
     * (simpoints / interval / warmup).  Half a composition is refused at
     * install rather than silently ignored: schedule keys with no schedule
     * position nothing. */
    bool marker_sched_keys = false;

    /*
     * Dead-latch timeout (latch_timeout=<ms>).  In marker latch mode a
     * process that exits WITHOUT running its END marker would leave its
     * window open until the icount budget closes the segment.  When set,
     * the detector stamps each owned root's last schedule-in (wall time)
     * and, off the hot path, closes any window idle longer than this many
     * milliseconds — exactly as its END marker would.  When the last
     * window closes this way the whole segment shuts down (the backstop
     * for an all-died SIGKILL).
     *
     * DEFAULT 0 = DISABLED (opt-in).  The signal is wall-clock idleness,
     * which cannot distinguish a dead process from a merely long-idle live
     * one (a blocked/sleeping process, or a pinned process starved by heavy
     * foreign ASID churn — the churn stress test idles the pin ~30 s by
     * design).  So the detector is off unless the user opts in with a
     * timeout chosen to exceed the longest legitimate idle their workload
     * exhibits; enable it for latch traces where processes may die without
     * their END marker and the icount budget is too coarse a fallback.
     *
     * THE STAMP IS GATED LIFE.  With content-as-gate the refresh events
     * are not forgeable by a recycled root: the ONE global last-gated-
     * execution stamp advances only when a context that MAPS a latched
     * window's marker bytes executes (or evaluates gated at a committed
     * root write) — a successor process maps different bytes there, or
     * nothing, and cannot refresh.  Q-DEADWIN v4 default, maintainer-
     * vetoable: per-window closure is retired; the segment closes when
     * ALL gated activity has been idle past a threshold.
     */
    uint64_t latch_timeout_ms = 0;

    /*
     * Instruction-denominated dead latch (latch_idle_insns=<N>).
     *
     * The same detector as latch_timeout above — the same stamp at each
     * owned root's schedule-in, the same off-hot-path sweep, the same
     * per-window close, the same all-died segment shutdown — measured on a
     * different denominator.  An owned root is dead here when the GUEST as
     * a whole has retired N architectural instructions since that root was
     * last scheduled in.
     *
     * WHY INSTRUCTIONS AND NOT MILLISECONDS.  latch_timeout's idleness is
     * host wall-clock idleness, so where it closes a window rides on host
     * load: the same guest running the same workload ages a window out at
     * two different points in its own execution on a quiet box and on a
     * loaded one.  This project's standing rule is that trace validity and
     * hang prevention must NEVER depend on host load.  A guest-instruction
     * denominator is architectural state the host scheduler cannot move, so
     * the close point is reproducible across an idle and a loaded host.
     *
     * DEFAULT 0 = DISABLED (opt-in), for latch_timeout's reason: idleness
     * alone cannot tell a dead process from a merely long-idle live one,
     * only how much of it there is can, and only the operator knows how
     * much their workload legitimately exhibits.  The two detectors are
     * INDEPENDENT — either may be given alone or both together, and a root
     * is dead as soon as EITHER threshold is crossed.
     *
     * HOW IT RELATES TO ITS NEIGHBOURS.  Three bounds, three different
     * shapes; none subsumes another, so do not build a fourth:
     *
     *   stall_ceiling (ON by default, 256M arch insns) covers the shape
     *     where the pinned process is ALIVE and retiring kernel
     *     instructions in an owned context but never returns to user space,
     *     so its user clock is frozen.  Its denominator is OWNED-context
     *     instructions, which advance only because the process is running.
     *
     *   latch_idle_insns (this option) covers the DIFFERENT shape where the
     *     process is killed or never scheduled again, so NO owned-context
     *     instruction retires at all and stall_ceiling can never advance.
     *     Its denominator is every instruction the guest retires, in any
     *     context, and it is per-root: it closes one dead window and leaves
     *     live peers tracing.  Its SWEEP rides the same denominator
     *     (deadlatch_beat, one sweep per stride of globally retired
     *     instructions, from the per-TB step in any context), so the
     *     trigger cannot starve while the threshold can grow; a guest
     *     retiring nothing at all grows neither, which is the correct
     *     reading, not a hole.  The one shape neither arm can age is a
     *     FULLY HALTED guest with the wall-clock arm unset — no
     *     instruction retires and no wall-clock latch is armed; give
     *     latch_timeout as well when that shape matters.
     *
     *   stall_ceiling_any (ON by default) bounds the same not-running shape
     *     but at SEGMENT granularity — it is the termination bound of last
     *     resort and truncates the capture; this one is the per-window
     *     close that keeps the surviving windows.
     */
    uint64_t latch_idle_insns = 0;

    /*
     * User-clock stall ceiling (stall_ceiling=<arch insns>, 0 disables).
     *
     * A marker window's budget runs on the pinned process's USER
     * instruction clock, and that clock only advances while the pinned
     * process executes user-space code.  If the process stops returning to
     * user space — it is alive, on-CPU and retiring kernel instructions,
     * but never completes the syscall it is in — the budget can never be
     * reached and the END marker can never execute, so NOTHING ends the
     * segment: the run is unbounded.  Measured, not hypothesised
     * (cst_runs/fence: the traced process alive, __state=0, on_rq=1,
     * nvcsw=0, user clock frozen at 0 for the whole cap).
     *
     * The ceiling bounds it with an architectural, load-invariant count:
     * how many instructions the guest may retire IN A CONTEXT THIS TRACE
     * OWNS without the pinned process advancing its user clock.  Foreign
     * processes do not count (the churn stress idles the pin by design),
     * so the ceiling measures exactly "the traced process is running and
     * not coming back".  On crossing, the segment closes the same way its
     * budget would, loudly and with the trace finalised.
     */
    uint64_t stall_ceiling = CST_STALL_CEILING_DEFAULT;

    /*
     * Any-context stall ceiling (stall_ceiling_any=<arch insns>, 0
     * disables).  The termination bound of last resort, and the one that
     * holds when the traced process is NOT RUNNING: killed after its window
     * opened, or blocked in a syscall it never leaves.  The owned-context
     * ceiling cannot see that case — no owned instruction is retired at all
     * — and the dead-latch is opt-in wall-clock idleness, so with both off
     * the segment never ends and the run never terminates.  Measured, not
     * hypothesised (cst_runs/certainty: a probe that arms its marker and
     * then exits, or blocks in pause(), while the guest stays busy; the run
     * is unbounded at HEAD).
     *
     * Counts instructions retired by the guest in ANY context since the
     * pinned user clock last advanced.  Hang prevention is never opt-in, so
     * this is ON by default; a workload whose traced process legitimately
     * idles longer than the default should raise it rather than disable it.
     */
    uint64_t stall_ceiling_any = CST_STALL_ANY_CEILING_DEFAULT;
};

/* Parse plugin args.  Returns true on success; on failure prints to
 * stderr and leaves @cfg partially populated. */
bool parse_plugin_options(PluginConfig *cfg, int argc, char **argv);

/* Release any g_strdup'd strings still owned by @cfg.  Skips fields
 * the caller has already transferred (set to nullptr). */
void plugin_config_free(PluginConfig *cfg);

#endif /* CHAMPSIM_TRACER_PLUGIN_CONFIG_H */
