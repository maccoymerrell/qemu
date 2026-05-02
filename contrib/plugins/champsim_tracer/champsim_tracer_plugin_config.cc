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

bool set_depth(PluginConfig *cfg, const char *v)
{
    cfg->depth = atoi(v);
    return cfg->depth > 0;
}

bool set_outfile(PluginConfig *cfg, const char *v)
{
    g_free(cfg->output_path);
    cfg->output_path = g_strdup(v);
    return true;
}

bool set_outpipe(PluginConfig *cfg, const char *v)
{
    g_free(cfg->output_pipe);
    cfg->output_pipe = g_strdup(v);
    return true;
}

bool set_wp(PluginConfig *cfg, const char *v)
{
    cfg->enable_wp = atoi(v) != 0;
    return true;
}

bool set_start(PluginConfig *cfg, const char *v)
{
    cfg->trace_start_insn = g_ascii_strtoull(v, nullptr, 10);
    return true;
}

bool set_stop(PluginConfig *cfg, const char *v)
{
    cfg->trace_stop_insn = g_ascii_strtoull(v, nullptr, 10);
    return true;
}

bool set_program(PluginConfig *cfg, const char *v)
{
    g_free(cfg->program_name);
    cfg->program_name = g_strdup(v);
    return true;
}

bool set_spfile(PluginConfig *cfg, const char *v)
{
    g_free(cfg->simpoints_file);
    cfg->simpoints_file = g_strdup(v);
    return true;
}

bool set_spinterval(PluginConfig *cfg, const char *v)
{
    cfg->simpoint_interval = g_ascii_strtoull(v, nullptr, 10);
    return cfg->simpoint_interval > 0;
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

typedef bool (*OptionSetter)(PluginConfig *cfg, const char *value);

const struct {
    const char  *name;
    OptionSetter setter;
} options[] = {
    { "depth",      set_depth      },
    { "outfile",    set_outfile    },
    { "outpipe",    set_outpipe    },
    { "wp",         set_wp         },
    { "start",      set_start      },
    { "stop",       set_stop       },
    { "program",    set_program    },
    { "spfile",     set_spfile     },
    { "spinterval", set_spinterval },
    { "comment",    set_comment    },
    { "memdata",    set_memdata    },
    { "regdata",    set_regdata    },
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
            fprintf(stderr, "champsim_tracer: unknown option: %s\n",
                    argv[i]);
            return false;
        }
    }
    return true;
}

void plugin_config_free(PluginConfig *cfg)
{
    g_free(cfg->output_path);
    g_free(cfg->output_pipe);
    g_free(cfg->program_name);
    g_free(cfg->simpoints_file);
    g_free(cfg->comment);
    cfg->output_path = nullptr;
    cfg->output_pipe = nullptr;
    cfg->program_name = nullptr;
    cfg->simpoints_file = nullptr;
    cfg->comment = nullptr;
}
