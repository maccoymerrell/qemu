/*
 * SimPoints Discovery Plugin for QEMU
 *
 * Discovers representative simulation points using Basic Block Vector (BBV)
 * clustering via k-means.  Collects per-interval BBVs during execution,
 * then clusters them at exit to identify representative intervals.
 *
 * Output: a simpoints specification file that can be consumed by trace
 * replay tools (e.g. the wptrace plugin's simpoints=trace mode).
 *
 * Usage:
 *   -plugin simpoints[,outfile=PATH][,interval=N][,num_simpoints=K]
 *                     [,warmup=N][,kmeans_iter=N]
 *
 * Copyright (c) 2025
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* ========================= Configuration ========================= */

static char *output_path = NULL;
static uint64_t simpoint_interval = 100000000;  /* 100M instructions */
static int num_simpoints = 10;
static int simpoint_warmup = 10;    /* min intervals before clustering */
static int kmeans_max_iter = 100;

/* ========================= Data Structures ========================= */

/*
 * Sparse BBV (Basic Block Vector) for one interval.
 * Maps bb_index -> execution count for that interval.
 */
typedef struct {
    GHashTable *counts;         /* GUINT_TO_POINTER(bb_index) → uint64* count */
    uint64_t total_insns;       /* Total instructions in interval */
    uint64_t interval_id;       /* Which interval (0-based) */
} BBV;

/*
 * SimPoint specification: an interval to trace.
 */
typedef struct {
    uint64_t interval_id;       /* Which interval */
    uint64_t start_insn;        /* Start instruction number */
    uint64_t stop_insn;         /* Stop instruction number */
    int cluster_id;             /* Cluster this simpoint represents */
    double weight;              /* Weight (fraction of total intervals) */
} SimPointSpec;

/*
 * Lightweight per-vCPU scoreboard for instruction counting.
 */
typedef struct {
    uint64_t current_pc;
    uint64_t insn_count;
} VCPUScoreBoard;

/* ========================= Global State ========================= */

static GMutex data_lock;

/* BB information: start_pc -> n_insns (lightweight, no full template) */
static GHashTable *bb_insn_map;     /* uint64* start_pc -> uint32* n_insns */

/* BB symbol names: start_pc -> symbol (optional, best-effort) */
static GHashTable *bb_symbol_map;   /* uint64* start_pc -> char* symbol */

/* Per-vCPU scoreboard */
static struct qemu_plugin_scoreboard *vcpu_sb;
static qemu_plugin_u64 sb_current_pc;
static qemu_plugin_u64 sb_insn_count;

/* BBV collection state */
static GArray *bbv_collection;      /* GArray of BBV* */
static GHashTable *bbv_bb_map;      /* bb start_pc -> bb_index for BBV */
static uint32_t next_bb_index = 1;
static BBV *current_bbv;

/* ========================= BBV Functions ========================= */

static BBV *bbv_new(uint64_t interval_id)
{
    BBV *bbv = g_new0(BBV, 1);
    bbv->counts = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                        NULL, g_free);
    bbv->interval_id = interval_id;
    return bbv;
}

static void bbv_free(BBV *bbv)
{
    if (bbv) {
        if (bbv->counts) {
            g_hash_table_unref(bbv->counts);
        }
        g_free(bbv);
    }
}

static void bbv_increment(BBV *bbv, uint64_t bb_pc, uint64_t n_insns)
{
    uint32_t bb_idx;

    /* Get or assign a BB index */
    uint32_t *idx_ptr = g_hash_table_lookup(bbv_bb_map, &bb_pc);
    if (!idx_ptr) {
        uint64_t *new_key = g_new(uint64_t, 1);
        *new_key = bb_pc;
        idx_ptr = g_new(uint32_t, 1);
        *idx_ptr = next_bb_index++;
        g_hash_table_insert(bbv_bb_map, new_key, idx_ptr);
    }
    bb_idx = *idx_ptr;

    /* Increment count for this BB */
    gpointer bb_key = GUINT_TO_POINTER(bb_idx);
    uint64_t *count = g_hash_table_lookup(bbv->counts, bb_key);
    if (!count) {
        count = g_new0(uint64_t, 1);
        g_hash_table_insert(bbv->counts, bb_key, count);
    }
    *count += n_insns;
    bbv->total_insns += n_insns;
}

/* Helper for sorting (bb_index, count) pairs by count descending */
typedef struct {
    uint32_t bb_idx;
    uint64_t count;
} BBCountPair;

static gint bbcount_compare_desc(gconstpointer a, gconstpointer b)
{
    const BBCountPair *pa = a;
    const BBCountPair *pb = b;
    if (pa->count > pb->count) {
        return -1;
    }
    if (pa->count < pb->count) {
        return 1;
    }
    return 0;
}

/* ========================= K-Means Clustering ========================= */

/*
 * Compute squared L2 distance between two sparse BBVs.
 * Both are GHashTables mapping uint32 bb_index -> uint64 count.
 * We normalize by total instructions to get frequency vectors.
 */
static double bbv_distance_sq(BBV *a, BBV *b)
{
    double dist = 0.0;
    GHashTableIter iter;
    gpointer key, value;
    double a_total = a->total_insns > 0 ? (double)a->total_insns : 1.0;
    double b_total = b->total_insns > 0 ? (double)b->total_insns : 1.0;

    /* Iterate over a's entries */
    g_hash_table_iter_init(&iter, a->counts);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        double a_freq = (double)(*(uint64_t *)value) / a_total;
        uint64_t *b_count = g_hash_table_lookup(b->counts, key);
        double b_freq = b_count ? (double)(*b_count) / b_total : 0.0;
        double diff = a_freq - b_freq;
        dist += diff * diff;
    }

    /* Iterate over b's entries not in a */
    g_hash_table_iter_init(&iter, b->counts);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        if (!g_hash_table_contains(a->counts, key)) {
            double b_freq = (double)(*(uint64_t *)value) / b_total;
            dist += b_freq * b_freq;
        }
    }

    return dist;
}

static gint simpoint_spec_compare(gconstpointer a, gconstpointer b)
{
    const SimPointSpec *sa = a;
    const SimPointSpec *sb = b;
    if (sa->start_insn < sb->start_insn) {
        return -1;
    }
    if (sa->start_insn > sb->start_insn) {
        return 1;
    }
    return 0;
}

/*
 * Simple k-means clustering on BBVs.
 * Returns an array of SimPointSpec with the representative interval
 * for each cluster.
 */
static GArray *kmeans_cluster(GArray *bbvs, int k)
{
    int n = bbvs->len;
    GArray *specs = g_array_new(false, false, sizeof(SimPointSpec));

    if (n == 0 || k <= 0) {
        return specs;
    }

    if (k > n) {
        k = n;
    }

    /* Cluster assignments: which cluster each BBV belongs to */
    int *assignments = g_new0(int, n);
    int *cluster_sizes = g_new0(int, k);

    /* Initialize centers by picking k evenly-spaced BBVs */
    int *center_indices = g_new0(int, k);
    for (int i = 0; i < k; i++) {
        center_indices[i] = i * n / k;
    }

    /* K-means iterations */
    for (int iter = 0; iter < kmeans_max_iter; iter++) {
        bool changed = false;

        /* Assign each BBV to nearest center */
        memset(cluster_sizes, 0, sizeof(int) * k);
        for (int i = 0; i < n; i++) {
            BBV *bbv = g_array_index(bbvs, BBV *, i);
            double best_dist = -1;
            int best_cluster = 0;

            for (int c = 0; c < k; c++) {
                BBV *center = g_array_index(bbvs, BBV *, center_indices[c]);
                double d = bbv_distance_sq(bbv, center);
                if (best_dist < 0 || d < best_dist) {
                    best_dist = d;
                    best_cluster = c;
                }
            }

            if (assignments[i] != best_cluster) {
                assignments[i] = best_cluster;
                changed = true;
            }
            cluster_sizes[best_cluster]++;
        }

        if (!changed) {
            break;
        }

        /* Update centers: pick the medoid (BBV closest to cluster mean) */
        for (int c = 0; c < k; c++) {
            if (cluster_sizes[c] == 0) {
                continue;
            }

            double best_total_dist = -1;
            int best_idx = center_indices[c];

            for (int i = 0; i < n; i++) {
                if (assignments[i] != c) {
                    continue;
                }

                /* Compute total distance from i to all others in cluster */
                double total_dist = 0;
                for (int j = 0; j < n; j++) {
                    if (assignments[j] != c || i == j) {
                        continue;
                    }
                    BBV *bi = g_array_index(bbvs, BBV *, i);
                    BBV *bj = g_array_index(bbvs, BBV *, j);
                    total_dist += bbv_distance_sq(bi, bj);
                }

                if (best_total_dist < 0 || total_dist < best_total_dist) {
                    best_total_dist = total_dist;
                    best_idx = i;
                }
            }

            center_indices[c] = best_idx;
        }
    }

    /* Build simpoint specs from cluster centers */
    for (int c = 0; c < k; c++) {
        if (cluster_sizes[c] == 0) {
            continue;
        }

        BBV *center_bbv = g_array_index(bbvs, BBV *, center_indices[c]);
        SimPointSpec spec = {
            .interval_id = center_bbv->interval_id,
            .start_insn = center_bbv->interval_id * simpoint_interval,
            .stop_insn = (center_bbv->interval_id + 1) * simpoint_interval,
            .cluster_id = c,
            .weight = (double)cluster_sizes[c] / n,
        };
        g_array_append_val(specs, spec);
    }

    /* Sort by start_insn */
    g_array_sort(specs, simpoint_spec_compare);

    g_free(assignments);
    g_free(cluster_sizes);
    g_free(center_indices);

    return specs;
}

/* ========================= SimPoints File I/O ========================= */

/*
 * Write simpoints specification file.
 * Format: interval_id,start_insn,stop_insn,cluster_id,weight
 * Each simpoint entry is followed by a comment listing the most common
 * symbols (function names) in its representative BBV, if available.
 */
static void write_simpoints_file(const char *path, GArray *specs)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "simpoints: cannot open simpoints file: %s\n", path);
        return;
    }

    /*
     * Build reverse map: bb_index -> bb_pc so we can resolve symbols
     * from the BBV's sparse count entries.
     */
    GHashTable *idx_to_pc = g_hash_table_new(g_direct_hash, g_direct_equal);
    {
        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, bbv_bb_map);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            uint64_t *pc_ptr = key;
            uint32_t *idx_ptr = value;
            g_hash_table_insert(idx_to_pc,
                                GUINT_TO_POINTER(*idx_ptr),
                                pc_ptr);
        }
    }

    fprintf(f, "# SimPoints specification\n");
    fprintf(f, "# interval_id,start_insn,stop_insn,cluster_id,weight\n");
    fprintf(f, "# interval_size=%" PRIu64 "\n", simpoint_interval);
    fprintf(f, "# num_clusters=%d\n", num_simpoints);

    for (guint i = 0; i < specs->len; i++) {
        SimPointSpec *sp = &g_array_index(specs, SimPointSpec, i);
        fprintf(f, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%d,%.6f\n",
                sp->interval_id, sp->start_insn, sp->stop_insn,
                sp->cluster_id, sp->weight);

        /* Find the center BBV for this simpoint and list top symbols */
        BBV *bbv = NULL;
        for (guint j = 0; j < bbv_collection->len; j++) {
            BBV *candidate = g_array_index(bbv_collection, BBV *, j);
            if (candidate->interval_id == sp->interval_id) {
                bbv = candidate;
                break;
            }
        }
        if (!bbv || g_hash_table_size(bb_symbol_map) == 0) {
            continue;
        }

        /* Collect (bb_index, count) pairs from the BBV */
        GArray *pairs = g_array_new(false, false, sizeof(BBCountPair));
        {
            GHashTableIter biter;
            gpointer bkey, bvalue;
            g_hash_table_iter_init(&biter, bbv->counts);
            while (g_hash_table_iter_next(&biter, &bkey, &bvalue)) {
                BBCountPair pair = {
                    .bb_idx = GPOINTER_TO_UINT(bkey),
                    .count = *(uint64_t *)bvalue,
                };
                g_array_append_val(pairs, pair);
            }
        }
        g_array_sort(pairs, bbcount_compare_desc);

        /* Collect unique symbols from top blocks */
        GHashTable *seen_syms = g_hash_table_new(g_str_hash, g_str_equal);
        g_autoptr(GString) sym_line = g_string_new(NULL);
        int sym_count = 0;
        static const int MAX_SYMBOLS = 5;

        for (guint p = 0; p < pairs->len && sym_count < MAX_SYMBOLS; p++) {
            BBCountPair *pair = &g_array_index(pairs, BBCountPair, p);
            uint64_t *pc_ptr = g_hash_table_lookup(
                idx_to_pc, GUINT_TO_POINTER(pair->bb_idx));
            if (!pc_ptr) {
                continue;
            }
            char *sym = g_hash_table_lookup(bb_symbol_map, pc_ptr);
            if (sym && !g_hash_table_contains(seen_syms, sym)) {
                g_hash_table_add(seen_syms, sym);
                if (sym_line->len > 0) {
                    g_string_append(sym_line, ", ");
                }
                g_string_append(sym_line, sym);
                sym_count++;
            }
        }

        if (sym_line->len > 0) {
            fprintf(f, "# top_symbols: %s\n", sym_line->str);
        }

        g_hash_table_unref(seen_syms);
        g_array_unref(pairs);
    }

    fclose(f);
    g_hash_table_unref(idx_to_pc);
}

/* ========================= Execution Callback ========================= */

/*
 * Called at the start of each translated block.
 * Collects BBV data for the current interval.
 */
static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    uint64_t current_pc = qemu_plugin_u64_get(sb_current_pc, cpu_index);
    uint32_t n_insns = 1;

    g_mutex_lock(&data_lock);

    /* Look up instruction count for this block */
    uint32_t *n_ptr = g_hash_table_lookup(bb_insn_map, &current_pc);
    if (n_ptr) {
        n_insns = *n_ptr;
    }

    bbv_increment(current_bbv, current_pc, n_insns);

    /* Check if interval is complete */
    if (current_bbv->total_insns >= simpoint_interval) {
        current_bbv->interval_id = bbv_collection->len;
        g_array_append_val(bbv_collection, current_bbv);
        current_bbv = bbv_new(bbv_collection->len);
    }

    g_mutex_unlock(&data_lock);
}

/* ========================= Translation Callback ========================= */

/*
 * Called when a basic block is translated.
 * Records start_pc -> n_insns mapping and instruments the block.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t n_insns = qemu_plugin_tb_n_insns(tb);

    /* Record BB instruction count and symbol name */
    g_mutex_lock(&data_lock);
    if (!g_hash_table_contains(bb_insn_map, &pc)) {
        uint64_t *key = g_new(uint64_t, 1);
        uint32_t *val = g_new(uint32_t, 1);
        *key = pc;
        *val = (uint32_t)n_insns;
        g_hash_table_insert(bb_insn_map, key, val);

        /* Best-effort symbol lookup for the first instruction */
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, 0);
        if (insn) {
            const char *sym = qemu_plugin_insn_symbol(insn);
            if (sym) {
                uint64_t *sym_key = g_new(uint64_t, 1);
                *sym_key = pc;
                g_hash_table_insert(bb_symbol_map, sym_key,
                                    g_strdup(sym));
            }
        }
    }
    g_mutex_unlock(&data_lock);

    /* Store current block's start PC into scoreboard */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_STORE_U64, sb_current_pc, pc);

    /* Add instruction count for this block */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_ADD_U64, sb_insn_count, n_insns);

    /* Register execution callback */
    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, vcpu_tb_exec, QEMU_PLUGIN_CB_NO_REGS, NULL);
}

/* ========================= Exit / Statistics ========================= */

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    /* Add final partial interval if it has data */
    if (current_bbv && current_bbv->total_insns > 0) {
        current_bbv->interval_id = bbv_collection->len;
        g_array_append_val(bbv_collection, current_bbv);
        current_bbv = NULL;
    }

    /* Compute total instructions across all intervals */
    uint64_t total_insns = 0;
    for (guint i = 0; i < bbv_collection->len; i++) {
        BBV *bbv = g_array_index(bbv_collection, BBV *, i);
        total_insns += bbv->total_insns;
    }

    if (bbv_collection->len >= (guint)simpoint_warmup) {
        GArray *specs = kmeans_cluster(bbv_collection, num_simpoints);

        write_simpoints_file(output_path, specs);

        /* Print summary statistics */
        g_autoptr(GString) report = g_string_new("");
        g_string_append_printf(report,
            "\n=== SimPoints Discovery Summary ===\n");
        g_string_append_printf(report,
            "Intervals collected:    %u\n", bbv_collection->len);
        g_string_append_printf(report,
            "SimPoints discovered:   %u\n", specs->len);
        g_string_append_printf(report,
            "Total instructions:     %" PRIu64 "\n", total_insns);
        g_string_append_printf(report,
            "Interval size:          %" PRIu64 "\n", simpoint_interval);
        g_string_append_printf(report,
            "Output file:            %s\n", output_path);
        qemu_plugin_outs(report->str);

        g_array_unref(specs);
    } else {
        g_autofree char *msg = g_strdup_printf(
            "simpoints: only %u intervals collected "
            "(warmup requires %d), no clustering performed\n",
            bbv_collection->len, simpoint_warmup);
        qemu_plugin_outs(msg);
    }

    /* Cleanup BBVs */
    for (guint i = 0; i < bbv_collection->len; i++) {
        bbv_free(g_array_index(bbv_collection, BBV *, i));
    }
    g_array_unref(bbv_collection);
    if (current_bbv) {
        bbv_free(current_bbv);
    }

    g_hash_table_unref(bbv_bb_map);
    g_hash_table_unref(bb_insn_map);
    g_hash_table_unref(bb_symbol_map);
    g_free(output_path);
}

/* ========================= Plugin Install ========================= */

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                            const qemu_info_t *info,
                                            int argc, char **argv)
{
    /* Parse arguments */
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);

        if (g_strcmp0(tokens[0], "outfile") == 0) {
            output_path = g_strdup(tokens[1]);
        } else if (g_strcmp0(tokens[0], "interval") == 0) {
            simpoint_interval = g_ascii_strtoull(tokens[1], NULL, 10);
            if (simpoint_interval == 0) {
                fprintf(stderr, "simpoints: invalid interval: %s\n",
                        tokens[1]);
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "num_simpoints") == 0) {
            num_simpoints = atoi(tokens[1]);
            if (num_simpoints <= 0) {
                fprintf(stderr, "simpoints: invalid num_simpoints: %s\n",
                        tokens[1]);
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "warmup") == 0) {
            simpoint_warmup = atoi(tokens[1]);
        } else if (g_strcmp0(tokens[0], "kmeans_iter") == 0) {
            kmeans_max_iter = atoi(tokens[1]);
        } else {
            fprintf(stderr, "simpoints: unknown option: %s\n", opt);
            return -1;
        }
    }

    /* Default output path */
    if (!output_path) {
        output_path = g_strdup("simpoints_out");
    }

    /* Initialize data structures */
    g_mutex_init(&data_lock);
    bb_insn_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                        g_free, g_free);
    bb_symbol_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                          g_free, g_free);
    bbv_collection = g_array_new(false, false, sizeof(BBV *));
    bbv_bb_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                       g_free, g_free);
    current_bbv = bbv_new(0);

    /* Initialize per-vCPU scoreboard */
    vcpu_sb = qemu_plugin_scoreboard_new(sizeof(VCPUScoreBoard));
    sb_current_pc = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, current_pc);
    sb_insn_count = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, insn_count);

    /* Register callbacks */
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
