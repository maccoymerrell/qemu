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

struct PluginConfig {
    int       wp_depth          = 64;
    /* Wrong-path pruning level (wpprune=N): skip WP simulation for cold
     * branches.  0 = no pruning (default); 1 = drop WP for a branch never
     * seen taken on the correct path (indirect: < 2 observed targets, i.e.
     * monomorphic — no alternative target to mispredict toward); 2 = also
     * drop WP unless the branch has been seen BOTH taken and not-taken. */
    int       wp_prune          = 0;
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
    /* Kernel-excursion ownership model (kexc=1, system/marker mode).
     * When on, kernel (priv!=0) TBs are attributed to the trace by the
     * owning excursion — the user address space the kernel was entered
     * from, tracked through ASID-write path events — instead of by the
     * live ASID, so a kernel that switches to a private address space
     * on entry (PTI-style) keeps its synchronous-handler coverage.
     * kexc=0 restores the live-ASID rule (kernel work whose live ASID
     * differs from the pinned value — e.g. a PTI kernel page-table base
     * — is dropped); it is byte-for-byte the pre-ownership behavior. */
    int       kexc              = 1;
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
    /* Per-template IFRAME trigger interval.  0 disables. */
    uint32_t  iframe_rate         = 100000;
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
     */
    uint64_t latch_timeout_ms = 0;
};

/* Parse plugin args.  Returns true on success; on failure prints to
 * stderr and leaves @cfg partially populated. */
bool parse_plugin_options(PluginConfig *cfg, int argc, char **argv);

/* Release any g_strdup'd strings still owned by @cfg.  Skips fields
 * the caller has already transferred (set to nullptr). */
void plugin_config_free(PluginConfig *cfg);

#endif /* CHAMPSIM_TRACER_PLUGIN_CONFIG_H */
