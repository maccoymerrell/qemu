/*
 * Wrong-Path Tracing Plugin — option parser.
 *
 * Plugin args arrive as `key=value` strings.  PluginConfig holds the
 * parsed values; parse_plugin_options() fills it from argc/argv via a
 * typed setter table.  The caller (qemu_plugin_install) then applies
 * each field to its final destination — a global, a class instance,
 * or a per-segment configuration.
 *
 * String fields are g_strdup'd into the struct; plugin_config_free()
 * releases them.  Owners that take long-term possession should
 * transfer (assign + null) rather than copy.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_PLUGIN_CONFIG_H
#define CHAMPSIM_TRACER_PLUGIN_CONFIG_H

#include "champsim_tracer.h"

struct PluginConfig {
    int       wp_depth          = 64;
    bool      enable_wp         = true;
    bool      enable_mem_data   = false;
    bool      enable_reg_data   = false;
    /* Per-path data flags.  Tristate: -1 = unset (inherit from the
     * matching CP flag), 0 = off, 1 = on.  Lets users keep CP data on
     * but drop the WP-side data — typically the dominant share of
     * trace bytes — without affecting CP capture. */
    int       wp_mem_data       = -1;
    int       wp_reg_data       = -1;
    /* Number of histogram intervals to bucket each segment into.
     * 0 disables (default).  When non-zero, the per-segment summary
     * is followed by per-interval breakdowns of the same attribution
     * tables (branch type, opcode, src/dst regs) so the user can see
     * how a long segment's instruction mix varies over time. */
    int       histogram_intervals = 0;
    /* Per-template IFRAME trigger interval.  0 disables. */
    uint32_t  iframe_rate         = 100000;
    uint64_t  simpoint_interval = 100000000ULL;
    uint64_t  trace_start_insn  = 0;
    uint64_t  trace_stop_insn   = UINT64_MAX;
    /* Simpoint windowing.  Only consulted when simpoints_file is set.
     *   warmup_insns      : insns to trace BEFORE each simpoint's
     *                       position to prime caches / branch predictors
     *                       / etc.  Effective segment start is
     *                       max(0, sp->start_insn - warmup_insns).
     *   simulation_insns  : insns to trace at-and-after the simpoint
     *                       position.  Effective segment stop is
     *                       sp->start_insn + simulation_insns.  When 0
     *                       (the default), the legacy behavior is kept:
     *                       stop = sp->start + simpoint_interval. */
    uint64_t  warmup_insns      = 0;
    uint64_t  simulation_insns  = 0;
    char     *output_path       = nullptr;   /* g_strdup, owned */
    char     *output_pipe       = nullptr;   /* g_strdup, owned */
    char     *program_name      = nullptr;   /* g_strdup, owned */
    char     *simpoints_file    = nullptr;   /* g_strdup, owned */
    char     *comment           = nullptr;   /* g_strdup, owned */

    /*
     * Symbol-based trace start (trace_window=symbol:...).  Trace
     * begins on the @start_symbol_occurrence-th time the named
     * symbol appears as a BB entry; runs for @simulation_insns
     * architectural instructions after that point.  warmup is
     * not meaningful here — we can't predict what executes before
     * an arbitrary symbol's Nth occurrence.
     */
    char     *start_symbol      = nullptr;   /* g_strdup, owned */
    uint64_t  start_symbol_occurrence = 1;

    /*
     * Set to one of WindowMode values when trace_window= is used,
     * so the runtime can validate that warmup= / start= / etc.
     * fields aren't being mixed across modes.  Unset (= AUTO) means
     * the plugin falls back to the legacy flat-flags behavior.
     */
    enum WindowMode {
        WIN_AUTO     = 0,
        WIN_ICOUNT   = 1,
        WIN_SIMPOINT = 2,
        WIN_SYMBOL   = 3,
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
