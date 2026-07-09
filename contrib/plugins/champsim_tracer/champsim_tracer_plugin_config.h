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
     * 0 (default) keeps the live-ASID rule byte-for-byte. */
    int       kexc              = 0;
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
};

/* Parse plugin args.  Returns true on success; on failure prints to
 * stderr and leaves @cfg partially populated. */
bool parse_plugin_options(PluginConfig *cfg, int argc, char **argv);

/* Release any g_strdup'd strings still owned by @cfg.  Skips fields
 * the caller has already transferred (set to nullptr). */
void plugin_config_free(PluginConfig *cfg);

#endif /* CHAMPSIM_TRACER_PLUGIN_CONFIG_H */
