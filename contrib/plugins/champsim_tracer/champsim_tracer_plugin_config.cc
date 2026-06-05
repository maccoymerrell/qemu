/*
 * Wrong-Path Tracing Plugin — option parser implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "champsim_tracer_plugin_config.h"

namespace {

bool set_wpdepth(PluginConfig *cfg, const char *v)
{
    cfg->wp_depth = atoi(v);
    return cfg->wp_depth > 0;
}

bool set_wpprune(PluginConfig *cfg, const char *v)
{
    cfg->wp_prune = atoi(v);
    return cfg->wp_prune >= 0 && cfg->wp_prune <= 2;
}

bool set_outfile(PluginConfig *cfg, const char *v)
{
    g_free(cfg->output_path);
    cfg->output_path = g_strdup(v);
    return true;
}

bool set_compress(PluginConfig *cfg, const char *v)
{
    /* Per-member compression command.  Each output member (body and
     * header) inside the outer tarball is piped through this command
     * before landing on disk.  Empty / unset = uncompressed members. */
    g_free(cfg->compress_cmd);
    cfg->compress_cmd = g_strdup(v);
    return true;
}

bool set_wp(PluginConfig *cfg, const char *v)
{
    cfg->enable_wp = atoi(v) != 0;
    return true;
}

bool set_program(PluginConfig *cfg, const char *v)
{
    g_free(cfg->program_name);
    cfg->program_name = g_strdup(v);
    return true;
}

bool set_comment(PluginConfig *cfg, const char *v)
{
    g_free(cfg->comment);
    cfg->comment = g_strdup(v);
    return true;
}

bool set_memdata(PluginConfig *cfg, const char *v)
{
    cfg->enable_mem_data = atoi(v) != 0;
    return true;
}

bool set_regdata(PluginConfig *cfg, const char *v)
{
    cfg->enable_reg_data = atoi(v) != 0;
    return true;
}

bool set_wp_memdata(PluginConfig *cfg, const char *v)
{
    cfg->wp_mem_data = atoi(v) != 0 ? 1 : 0;
    return true;
}

bool set_wp_regdata(PluginConfig *cfg, const char *v)
{
    cfg->wp_reg_data = atoi(v) != 0 ? 1 : 0;
    return true;
}

bool set_histogram(PluginConfig *cfg, const char *v)
{
    int n = atoi(v);
    if (n < 0) {
        return false;
    }
    cfg->histogram_intervals = n;
    return true;
}

bool set_iframe_rate(PluginConfig *cfg, const char *v)
{
    long long n = g_ascii_strtoll(v, nullptr, 10);
    if (n < 0 || n > UINT32_MAX) {
        return false;
    }
    cfg->iframe_rate = (uint32_t)n;
    return true;
}

/*
 * trace_window=PREFIX:KEY=VALUE+KEY=VALUE+...
 *
 *   trace_window=icount:start=0+stop=20000000
 *   trace_window=simpoint:file=mcf.sp+interval=100000000+simulation=20000000+warmup=2000000
 *   trace_window=symbol:name=main+occurrence=3+simulation=20000000
 *
 * First colon-delimited token names the mode; each mode accepts only
 * its own keys (cross-mode keys are rejected, no silent mixing).
 *
 * The inner k/v separator is '+' (preferred — no shell quoting
 * required) OR ';' (back-compat — works only when the whole
 * -plugin arg is shell-quoted, since unquoted ';' is a shell
 * command separator).  Both are accepted; commas can never appear
 * inside a value because QEMU's plugin-arg parser splits argv on
 * commas before the plugin sees it.
 */
bool parse_kv_pair(PluginConfig *cfg, const char *mode,
                   const std::pair<const char *, const char *> &kv)
{
    auto bad_key = [&](const char *legal) -> bool {
        fprintf(stderr,
                "champsim_tracer: trace_window=%s: unrecognised key '%s' "
                "(legal: %s)\n", mode, kv.first, legal);
        return false;
    };
    auto match = [&](const char *want) {
        return cst_str_eq(kv.first, want);
    };

    if (cst_str_eq(mode, "icount")) {
        if (match("start")) {
            cfg->trace_start_insn = g_ascii_strtoull(kv.second, nullptr, 10);
            return true;
        }
        if (match("stop")) {
            cfg->trace_stop_insn = g_ascii_strtoull(kv.second, nullptr, 10);
            return true;
        }
        return bad_key("start, stop");
    }
    if (cst_str_eq(mode, "simpoint")) {
        if (match("file")) {
            g_free(cfg->simpoints_file);
            cfg->simpoints_file = g_strdup(kv.second);
            return true;
        }
        if (match("interval")) {
            cfg->simpoint_interval = g_ascii_strtoull(kv.second, nullptr, 10);
            return cfg->simpoint_interval > 0;
        }
        if (match("warmup")) {
            cfg->warmup_insns = g_ascii_strtoull(kv.second, nullptr, 10);
            return true;
        }
        if (match("simulation")) {
            cfg->simulation_insns = g_ascii_strtoull(kv.second, nullptr, 10);
            return true;
        }
        return bad_key("file, interval, warmup, simulation");
    }
    if (cst_str_eq(mode, "symbol")) {
        if (match("name")) {
            g_free(cfg->start_symbol);
            cfg->start_symbol = g_strdup(kv.second);
            return true;
        }
        if (match("occurrence")) {
            cfg->start_symbol_occurrence =
                g_ascii_strtoull(kv.second, nullptr, 10);
            return cfg->start_symbol_occurrence > 0;
        }
        if (match("simulation")) {
            cfg->simulation_insns = g_ascii_strtoull(kv.second, nullptr, 10);
            return true;
        }
        return bad_key("name, occurrence, simulation");
    }
    if (cst_str_eq(mode, "marker")) {
        /* Guest-driven window: a launch wrapper issues a magic marker
         * instruction, the plugin opens a segment there and traces
         * `simulation` instructions of the launched process. */
        if (match("simulation")) {
            cfg->simulation_insns = g_ascii_strtoull(kv.second, nullptr, 10);
            return cfg->simulation_insns > 0;
        }
        return bad_key("simulation");
    }
    fprintf(stderr,
            "champsim_tracer: trace_window: unknown mode '%s' "
            "(expected: icount, simpoint, symbol, marker)\n", mode);
    return false;
}

bool set_trace_window(PluginConfig *cfg, const char *v)
{
    if (!v || !*v) {
        fprintf(stderr,
                "champsim_tracer: trace_window= requires "
                "MODE:KEY=VALUE+...  Example: "
                "trace_window=icount:start=0+stop=20000000\n");
        return false;
    }
    /* Normalise the back-compat ';' separator to the canonical '+'
     * so users can use either; '+' is the preferred form because it
     * needs no shell quoting (';' is a command separator). */
    g_autofree char *v_norm = g_strdup(v);
    for (char *p = v_norm; *p; p++) {
        if (*p == ';') *p = '+';
    }
    v = v_norm;
    g_auto(GStrv) head_tail = g_strsplit(v, ":", 2);
    if (!head_tail[0] || !head_tail[1]) {
        fprintf(stderr,
                "champsim_tracer: trace_window= missing ':' "
                "between mode and arg list (got '%s')\n", v);
        return false;
    }
    if (cst_str_eq(head_tail[0], "icount")) {
        cfg->window_mode = PluginConfig::WIN_ICOUNT;
    } else if (cst_str_eq(head_tail[0], "simpoint")) {
        cfg->window_mode = PluginConfig::WIN_SIMPOINT;
    } else if (cst_str_eq(head_tail[0], "symbol")) {
        cfg->window_mode = PluginConfig::WIN_SYMBOL;
    } else if (cst_str_eq(head_tail[0], "marker")) {
        cfg->window_mode = PluginConfig::WIN_MARKER;
    } else {
        fprintf(stderr,
                "champsim_tracer: trace_window: unknown mode '%s' "
                "(expected: icount, simpoint, symbol, marker)\n",
                head_tail[0]);
        return false;
    }
    g_auto(GStrv) pairs = g_strsplit(head_tail[1], "+", -1);
    for (int i = 0; pairs[i]; i++) {
        if (!*pairs[i]) continue;
        g_auto(GStrv) kv = g_strsplit(pairs[i], "=", 2);
        if (!kv[0] || !kv[1]) {
            fprintf(stderr,
                    "champsim_tracer: trace_window=%s: token '%s' "
                    "is not KEY=VALUE\n", head_tail[0], pairs[i]);
            return false;
        }
        if (!parse_kv_pair(cfg, head_tail[0],
                           {kv[0], kv[1]})) {
            return false;
        }
    }
    return true;
}

typedef bool (*OptionSetter)(PluginConfig *cfg, const char *value);

const struct {
    const char  *name;
    OptionSetter setter;
} options[] = {
    { "wpdepth",    set_wpdepth    },
    { "wpprune",    set_wpprune    },
    { "outfile",    set_outfile    },
    { "compress",   set_compress   },
    { "wp",         set_wp         },
    { "program",    set_program    },
    { "comment",    set_comment    },
    { "memdata",    set_memdata    },
    { "regdata",    set_regdata    },
    { "wp_memdata", set_wp_memdata },
    { "wp_regdata", set_wp_regdata },
    { "histogram",  set_histogram  },
    { "iframe_rate", set_iframe_rate },
    { "trace_window", set_trace_window },
    { nullptr, nullptr },
};

} /* namespace */

bool parse_plugin_options(PluginConfig *cfg, int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        g_auto(GStrv) tokens = g_strsplit(argv[i], "=", 2);
        if (!tokens[0]) {
            continue;
        }
        bool found = false;
        for (int j = 0; options[j].name; j++) {
            if (!cst_str_eq(tokens[0], options[j].name)) {
                continue;
            }
            if (!options[j].setter(cfg, tokens[1])) {
                fprintf(stderr,
                        "champsim_tracer: invalid value for %s: %s\n",
                        tokens[0], tokens[1] ? tokens[1] : "(null)");
                return false;
            }
            found = true;
            break;
        }
        if (!found) {
            /* Common typo: ',' instead of '+' inside trace_window=.
             * QEMU's plugin-arg parser splits on ',' before the
             * plugin sees argv, so a comma in the value scatters
             * the trailing key/value pairs across separate argv
             * entries — they arrive here as unknown top-level
             * options.  Detect the case by matching against the
             * trace_window inner-key vocabulary. */
            static const char *tw_keys[] = {
                "start", "stop",                       /* icount */
                "file", "interval", "warmup",
                "simulation",                          /* simpoint */
                "name", "occurrence",                  /* symbol */
                nullptr,
            };
            bool looks_like_tw = false;
            for (int k = 0; tw_keys[k]; k++) {
                if (cst_str_eq(tokens[0], tw_keys[k])) {
                    looks_like_tw = true;
                    break;
                }
            }
            if (looks_like_tw) {
                fprintf(stderr,
                    "champsim_tracer: unknown option: %s\n"
                    "  This looks like a trace_window inner key.  Use\n"
                    "  '+' (NOT ',') between key=value pairs inside\n"
                    "  trace_window=.  Example:\n"
                    "    -plugin libchampsim_tracer.so,...,"
                    "trace_window=icount:start=0+stop=20000000\n",
                    argv[i]);
            } else {
                fprintf(stderr, "champsim_tracer: unknown option: %s\n",
                        argv[i]);
            }
            return false;
        }
    }
    return true;
}

void plugin_config_free(PluginConfig *cfg)
{
    g_free(cfg->output_path);
    g_free(cfg->compress_cmd);
    g_free(cfg->program_name);
    g_free(cfg->simpoints_file);
    g_free(cfg->comment);
    g_free(cfg->start_symbol);
    cfg->output_path = nullptr;
    cfg->compress_cmd = nullptr;
    cfg->program_name = nullptr;
    cfg->simpoints_file = nullptr;
    cfg->comment = nullptr;
    cfg->start_symbol = nullptr;
}
