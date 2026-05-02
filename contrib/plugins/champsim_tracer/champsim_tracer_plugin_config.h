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
    int       depth             = 64;
    bool      enable_wp         = true;
    bool      enable_mem_data   = false;
    bool      enable_reg_data   = false;
    uint64_t  simpoint_interval = 100000000ULL;
    uint64_t  trace_start_insn  = 0;
    uint64_t  trace_stop_insn   = UINT64_MAX;
    char     *output_path       = nullptr;   /* g_strdup, owned */
    char     *output_pipe       = nullptr;   /* g_strdup, owned */
    char     *program_name      = nullptr;   /* g_strdup, owned */
    char     *simpoints_file    = nullptr;   /* g_strdup, owned */
    char     *comment           = nullptr;   /* g_strdup, owned */
};

/* Parse plugin args.  Returns true on success; on failure prints to
 * stderr and leaves @cfg partially populated. */
bool parse_plugin_options(PluginConfig *cfg, int argc, char **argv);

/* Release any g_strdup'd strings still owned by @cfg.  Skips fields
 * the caller has already transferred (set to nullptr). */
void plugin_config_free(PluginConfig *cfg);

#endif /* CHAMPSIM_TRACER_PLUGIN_CONFIG_H */
