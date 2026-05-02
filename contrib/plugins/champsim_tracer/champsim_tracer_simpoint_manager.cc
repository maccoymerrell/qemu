/*
 * Wrong-Path Tracing Plugin — SimPoint manager implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "champsim_tracer_simpoint_manager.h"

SimPointManager g_simpoints;

namespace {

gint compare_by_start_insn(gconstpointer a, gconstpointer b)
{
    const SimPointEntry *sa = (const SimPointEntry *)a;
    const SimPointEntry *sb = (const SimPointEntry *)b;
    if (sa->start_insn < sb->start_insn) {
        return -1;
    }
    if (sa->start_insn > sb->start_insn) {
        return 1;
    }
    return 0;
}

void load_weights(const char *path, GArray *entries)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        double weight;
        int cluster;
        if (sscanf(line, "%lf %d", &weight, &cluster) == 2) {
            for (guint i = 0; i < entries->len; i++) {
                SimPointEntry *sp = &g_array_index(entries, SimPointEntry, i);
                if (sp->cluster_id == cluster) {
                    sp->weight = weight;
                }
            }
        }
    }

    fclose(f);
}

GArray *parse_selections(const char *path, uint64_t interval_insns)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "champsim_tracer: cannot open simpoints file: %s\n",
                path);
        return nullptr;
    }

    GArray *entries = g_array_new(false, false, sizeof(SimPointEntry));
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }

        SimPointEntry sp = {};
        uint64_t interval_id;
        int cluster_id = -1;
        int parsed = sscanf(line, "%" SCNu64 " %d", &interval_id, &cluster_id);
        if (parsed < 1) {
            continue;
        }

        uint64_t start = interval_id * interval_insns;
        uint64_t stop = (interval_insns > UINT64_MAX - start)
            ? UINT64_MAX
            : start + interval_insns;

        sp.interval_id = interval_id;
        sp.start_insn = start;
        sp.stop_insn = stop;
        sp.cluster_id = (parsed == 2) ? cluster_id : (int)entries->len;
        sp.weight = 0.0;
        g_array_append_val(entries, sp);
    }

    fclose(f);

    {
        g_autofree char *weights_path = nullptr;
        if (g_str_has_suffix(path, ".simpoints")) {
            g_autofree char *base =
                g_strndup(path, strlen(path) - strlen(".simpoints"));
            weights_path = g_strconcat(base, ".weights", nullptr);
        } else {
            weights_path = g_strdup_printf("%s.weights", path);
        }
        load_weights(weights_path, entries);
    }

    g_array_sort(entries, compare_by_start_insn);
    return entries;
}

} /* namespace */

SimPointManager::~SimPointManager()
{
    if (entries_) {
        g_array_unref(entries_);
    }
}

bool SimPointManager::load(const char *path, uint64_t interval_insns)
{
    if (entries_) {
        g_array_unref(entries_);
        entries_ = nullptr;
    }
    interval_insns_ = interval_insns;
    current_idx_ = 0;
    entries_ = parse_selections(path, interval_insns);
    return entries_ && entries_->len > 0;
}

const SimPointEntry *SimPointManager::current() const
{
    if (!entries_ || current_idx_ >= entries_->len) {
        return nullptr;
    }
    return &g_array_index(entries_, SimPointEntry, current_idx_);
}
