/*
 * Wrong-Path Tracing Plugin for QEMU
 *
 * Main translation unit.  Responsibilities:
 *   - Plugin install, option parsing, lifecycle
 *   - Tracing window management (start/stop + simpoints)
 *   - BB template creation (tb_map + bb_map)
 *   - vcpu_tb_trans / vcpu_tb_exec / vcpu_tb_flush callbacks
 *   - Memory-access callback (correct-path + wrong-path collection)
 *   - Exit-time statistics
 *
 * Peer TUs:
 *   - champsim_tracer_decode.cc  (Capstone → InsnFields)
 *   - champsim_tracer_wp.cc      (wrong-path simulator)
 *   - champsim_tracer_output.cc  (binary format v1.0 writer)
 *
 * Output: packed binary (.wpt).  A reference Python decoder
 * (champsim_tracer_decode.py) produces human-readable text.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "champsim_tracer.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* ========================= Configuration ========================= */

int max_wrong_path_depth = 64;
static bool enable_wrong_path = true;
static char *output_base_path = NULL;
static char *unknown_warn_path = NULL;
static char *program_name = NULL;
static uint64_t trace_start_insn = 0;
static uint64_t trace_stop_insn = UINT64_MAX;
const char *target_name;
FILE *unknown_warn_file;
GMutex unknown_warn_lock;

char *qemu_command_line = NULL;
char *trace_comment = NULL;
bool enable_mem_data = false;

/* ========================= Thread ID assignment ========================= */

static GHashTable *cpu_to_thread_id;
static uint32_t next_thread_id = 0;
static uint32_t last_active_thread = UINT32_MAX;

static uint32_t get_or_assign_thread_id(unsigned int cpu_index)
{
    gpointer val = g_hash_table_lookup(cpu_to_thread_id,
                                        GUINT_TO_POINTER(cpu_index + 1));
    if (val) {
        return GPOINTER_TO_UINT(val) - 1;
    }
    uint32_t tid = next_thread_id++;
    g_hash_table_insert(cpu_to_thread_id,
                        GUINT_TO_POINTER(cpu_index + 1),
                        GUINT_TO_POINTER(tid + 1));
    return tid;
}

/* ========================= SimPoints ========================= */

static char *simpoints_file_path = NULL;
static uint64_t simpoint_interval_insns = 100000000ULL;
static GArray *simpoints_list = NULL;
static guint simpoints_current_idx = 0;

/* ========================= Decode / ISA ========================= */

TraceISA trace_isa = TRACE_ISA_UNKNOWN;
int cst_cap_arch = -1;
unsigned int cst_cap_mode;

static_assert(TRACE_ISA_MIPS < 256,
              "TraceISA no longer fits in u8");
static_assert(GEN_OP_COUNT <= 256,
              "GenericOpcode no longer fits in u8");
static_assert(BRANCH_TYPE_COUNT <= 256,
              "BranchType no longer fits in u8");
static_assert(MAX_SRC_REGS <= 255,
              "MAX_SRC_REGS no longer fits in u8");
static_assert(MAX_DST_REGS <= 255,
              "MAX_DST_REGS no longer fits in u8");
static_assert(SYNC_ATOMIC < 16,
              "SyncEventType no longer fits in 4 bits of flags byte");

const InsnClassification *active_insn_table;
unsigned active_insn_table_size;
const RegClassification *active_reg_table;
unsigned active_reg_table_size;

static GHashTable *option_ht;
uint64_t stat_unknown_insn_warnings;

enum PluginOptId {
    OPT_DEPTH = 1,
    OPT_OUTFILE,
    OPT_WP,
    OPT_START,
    OPT_STOP,
    OPT_PROGRAM,
    OPT_SPFILE,
    OPT_SPINTERVAL,
    OPT_COMMENT,
    OPT_MEMDATA,
};

/* ========================= Global state ========================= */

GMutex data_lock;
static GMutex exec_lock;

GHashTable *tb_map;
GHashTable *bb_map;
GHashTable *branch_map;
uint32_t next_template_id = 1;

struct qemu_plugin_scoreboard *vcpu_sb;
qemu_plugin_u64 sb_current_pc;
qemu_plugin_u64 sb_prev_start_pc;
qemu_plugin_u64 sb_prev_last_pc;
qemu_plugin_u64 sb_prev_fall_through;
qemu_plugin_u64 sb_prev_bb_ends_in_branch;
qemu_plugin_u64 sb_insn_count;

static bool trace_active = false;
static volatile gint trace_active_atomic = 0;
static volatile gint trace_shutting_down = 0;
static TraceSegment *current_segment = NULL;

__thread bool wp_in_progress = false;
__thread GArray *wp_mem_accesses = NULL;
__thread uint64_t wp_saved_insn_count = 0;
__thread unsigned int wp_saved_cpu_index = 0;
__thread uint64_t wp_saved_prev_start_pc = 0;
__thread uint64_t wp_saved_prev_last_pc = 0;
__thread uint64_t wp_saved_prev_fall_through = 0;
__thread uint64_t wp_saved_prev_bb_ends_in_branch = 0;

static __thread GArray *cp_mem_accesses = NULL;

/* Statistics */
static uint64_t stat_blocks_translated;
static uint64_t stat_branches_observed;
static uint64_t stat_branches_taken;
static uint64_t stat_branches_not_taken;
uint64_t stat_wp_simulations;
uint64_t stat_wp_skipped;
uint64_t stat_wp_total_insns;
uint64_t stat_wp_early_exits;
uint64_t stat_wp_total_mem_accesses;
uint64_t stat_bin_total_bits;
uint64_t stat_bin_header_bits;
uint64_t stat_bin_body_bits;
uint64_t stat_bin_dyn_cp_bits;
uint64_t stat_bin_dyn_wp_bits;
uint64_t stat_bin_wp_exception_bits;

/* ========================= Memory management ========================= */

static void dyn_param_array_free(GArray *arr)
{
    if (arr) {
        g_array_unref(arr);
    }
}

static void wp_bb_entry_clear(WPBBEntry *entry)
{
    dyn_param_array_free(entry->dyn_params);
}

static void body_entry_clear(BodyEntry *entry)
{
    dyn_param_array_free(entry->dyn_params);
    if (entry->wp_entries) {
        for (guint i = 0; i < entry->wp_entries->len; i++) {
            wp_bb_entry_clear(&g_array_index(entry->wp_entries, WPBBEntry, i));
        }
        g_array_unref(entry->wp_entries);
    }
}

static void bb_template_free(gpointer data)
{
    BBTemplate *tmpl = (BBTemplate *)data;
    g_free(tmpl->insn_fields);
    g_free(tmpl->insn_pcs);
    g_free(tmpl->symbol_name);
    g_free(tmpl->insn_sizes);
    g_free(tmpl->insn_bytes);
    g_free(tmpl);
}

static TraceSegment *trace_segment_new(const char *label,
                                       uint64_t start, uint64_t stop)
{
    TraceSegment *seg = g_new0(TraceSegment, 1);
    seg->start_insn = start;
    seg->stop_insn = stop;
    seg->label = g_strdup(label);
    return seg;
}

static void trace_segment_free(TraceSegment *seg)
{
    if (!seg) {
        return;
    }
    if (seg->bin_stream) {
        g_free(seg->bin_stream);
    }
    if (seg->bin_file) {
        fclose(seg->bin_file);
    }
    g_free(seg->label);
    g_free(seg);
}

/* ========================= BB template management ========================= */

BBTemplate *find_template(uint64_t start_pc)
{
    return (BBTemplate *)g_hash_table_lookup(tb_map, &start_pc);
}

static BBTemplate *find_bb_template(uint64_t entry_pc)
{
    return (BBTemplate *)g_hash_table_lookup(bb_map, &entry_pc);
}

/*
 * Per-CPU state for assembling a basic block from the stream of TB
 * fragments reported by vcpu_tb_exec.  A basic block begins at a branch
 * target (entry_pc) and continues until the executing TB ends with a
 * branch instruction.
 */
static uint64_t cp_chain_entry_pc;
static uint64_t cp_chain_last_ft;
static GArray *cp_chain_fragments;

/*
 * Build (or reuse) a merged BB template covering @entry_pc through the
 * concatenation of the provided TB fragments.  Must be called with
 * data_lock held.
 */
BBTemplate *get_or_create_bb_template(uint64_t entry_pc,
                                      BBTemplate * const *fragments,
                                      guint n_fragments)
{
    BBTemplate *existing = find_bb_template(entry_pc);

    uint32_t total_insns = 0;
    for (guint i = 0; i < n_fragments; i++) {
        total_insns += fragments[i]->n_insns;
    }
    uint64_t final_ft = n_fragments > 0
        ? fragments[n_fragments - 1]->fall_through_pc : 0;

    if (existing && existing->n_insns == total_insns &&
        existing->fall_through_pc == final_ft &&
        existing->start_pc == entry_pc) {
        return existing;
    }

    BBTemplate *tmpl = g_new0(BBTemplate, 1);
    tmpl->template_id = next_template_id++;
    tmpl->start_pc = entry_pc;
    tmpl->n_insns = total_insns;
    tmpl->fall_through_pc = final_ft;
    tmpl->insn_pcs = g_new0(uint64_t, total_insns);
    tmpl->insn_sizes = g_new0(uint8_t, total_insns);
    tmpl->insn_bytes = g_new0(uint8_t, (size_t)total_insns * MAX_INSN_BYTES);
    tmpl->insn_fields = g_new0(InsnFields, total_insns);

    uint32_t off = 0;
    for (guint f = 0; f < n_fragments; f++) {
        BBTemplate *frag = fragments[f];
        if (f == 0 && frag->symbol_name) {
            tmpl->symbol_name = g_strdup(frag->symbol_name);
        }
        for (uint32_t i = 0; i < frag->n_insns; i++) {
            tmpl->insn_pcs[off + i] = frag->insn_pcs[i];
            tmpl->insn_sizes[off + i] = frag->insn_sizes[i];
            memcpy(&tmpl->insn_bytes[(size_t)(off + i) * MAX_INSN_BYTES],
                   &frag->insn_bytes[(size_t)i * MAX_INSN_BYTES],
                   MAX_INSN_BYTES);
            tmpl->insn_fields[off + i] = frag->insn_fields[i];
        }
        off += frag->n_insns;
    }

    g_hash_table_replace(bb_map, &tmpl->start_pc, tmpl);
    return tmpl;
}

static void cp_chain_reset(void)
{
    cp_chain_entry_pc = 0;
    cp_chain_last_ft = 0;
    if (cp_chain_fragments) {
        g_array_set_size(cp_chain_fragments, 0);
    }
}

/*
 * Return the index of the branch instruction within a BB template.
 * After template creation, delay-slot ISAs have been reordered so the
 * branch is always the last instruction.
 */
int template_branch_index(const BBTemplate *tmpl)
{
    if (!tmpl || tmpl->n_insns == 0) {
        return -1;
    }

    uint32_t last = tmpl->n_insns - 1;
    if (tmpl->insn_fields[last].branch_type != BRANCH_NONE) {
        return (int)last;
    }

    return -1;
}

/*
 * Find or create a per-TB fragment template.  Must be called with
 * data_lock held.
 */
static BBTemplate *get_or_create_template(uint64_t start_pc,
                                          uint32_t n_insns,
                                          uint64_t *insn_pcs,
                                          qemu_plugin_insn_info *insn_info,
                                          uint8_t *insn_sizes,
                                          uint8_t *insn_bytes,
                                          const char *symbol_name,
                                          uint64_t fall_through_pc)
{
    BBTemplate *tmpl = find_template(start_pc);
    if (tmpl) {
        return tmpl;
    }

    tmpl = g_new0(BBTemplate, 1);
    tmpl->template_id = next_template_id++;
    tmpl->start_pc = start_pc;
    tmpl->n_insns = n_insns;
    tmpl->fall_through_pc = fall_through_pc;
    tmpl->insn_pcs = g_new0(uint64_t, n_insns);
    tmpl->insn_sizes = g_new0(uint8_t, n_insns);
    tmpl->insn_bytes = g_new0(uint8_t, n_insns * MAX_INSN_BYTES);
    tmpl->symbol_name = symbol_name ? g_strdup(symbol_name) : NULL;

    for (uint32_t i = 0; i < n_insns; i++) {
        tmpl->insn_pcs[i] = insn_pcs[i];
        tmpl->insn_sizes[i] = insn_sizes[i];
        memcpy(&tmpl->insn_bytes[(size_t)i * MAX_INSN_BYTES],
               &insn_bytes[(size_t)i * MAX_INSN_BYTES],
               MAX_INSN_BYTES);
    }

    tmpl->insn_fields = g_new0(InsnFields, n_insns);
    for (uint32_t i = 0; i < n_insns; i++) {
        if (insn_info && insn_info[i].mnemonic[0]) {
            decode_detail_to_generic(tmpl->insn_pcs[i], &insn_info[i],
                                     &tmpl->insn_fields[i]);
        }
    }

    /*
     * Delay-slot reordering: swap [branch, delay] → [delay, branch] on
     * ISAs with branch delay slots so the last instruction is always the
     * branch.  This lets template_branch_index and WP steering be
     * uniform across ISAs.
     */
    if (isa_properties[trace_isa].branch_delay_slots > 0 && n_insns >= 2) {
        uint32_t br = n_insns - 2;
        uint32_t ds = n_insns - 1;
        if (tmpl->insn_fields[br].branch_type != BRANCH_NONE &&
            tmpl->insn_fields[ds].branch_type == BRANCH_NONE) {
            uint64_t tmp_pc = tmpl->insn_pcs[br];
            tmpl->insn_pcs[br] = tmpl->insn_pcs[ds];
            tmpl->insn_pcs[ds] = tmp_pc;
            uint8_t tmp_sz = tmpl->insn_sizes[br];
            tmpl->insn_sizes[br] = tmpl->insn_sizes[ds];
            tmpl->insn_sizes[ds] = tmp_sz;
            uint8_t tmp_bytes[MAX_INSN_BYTES];
            memcpy(tmp_bytes,
                   &tmpl->insn_bytes[(size_t)br * MAX_INSN_BYTES],
                   MAX_INSN_BYTES);
            memcpy(&tmpl->insn_bytes[(size_t)br * MAX_INSN_BYTES],
                   &tmpl->insn_bytes[(size_t)ds * MAX_INSN_BYTES],
                   MAX_INSN_BYTES);
            memcpy(&tmpl->insn_bytes[(size_t)ds * MAX_INSN_BYTES],
                   tmp_bytes, MAX_INSN_BYTES);
            InsnFields tmp_fld = tmpl->insn_fields[br];
            tmpl->insn_fields[br] = tmpl->insn_fields[ds];
            tmpl->insn_fields[ds] = tmp_fld;
        }
    }

    g_hash_table_replace(tb_map, &tmpl->start_pc, tmpl);
    stat_blocks_translated++;
    return tmpl;
}

/* ========================= Memory access callback ========================= */

static void vcpu_mem_cb(unsigned int cpu_index,
                        qemu_plugin_meminfo_t info,
                        uint64_t vaddr,
                        void *udata)
{
    uint64_t insn_pc = (uint64_t)(uintptr_t)udata;

    WPMemAccess acc = {
        .insn_pc = insn_pc,
        .mem_vaddr = vaddr,
        .is_store = qemu_plugin_mem_is_store(info),
        .data_size = 0,
        .data_lo = 0,
        .data_hi = 0,
    };

    if (enable_mem_data) {
        qemu_plugin_mem_value val = qemu_plugin_mem_get_value(info);
        switch (val.type) {
        case QEMU_PLUGIN_MEM_VALUE_U8:
            acc.data_size = 1;
            acc.data_lo = val.data.u8;
            break;
        case QEMU_PLUGIN_MEM_VALUE_U16:
            acc.data_size = 2;
            acc.data_lo = val.data.u16;
            break;
        case QEMU_PLUGIN_MEM_VALUE_U32:
            acc.data_size = 4;
            acc.data_lo = val.data.u32;
            break;
        case QEMU_PLUGIN_MEM_VALUE_U64:
            acc.data_size = 8;
            acc.data_lo = val.data.u64;
            break;
        case QEMU_PLUGIN_MEM_VALUE_U128:
            acc.data_size = 16;
            acc.data_lo = val.data.u128.low;
            acc.data_hi = val.data.u128.high;
            break;
        }
    }

    if (wp_in_progress && wp_mem_accesses) {
        g_array_append_val(wp_mem_accesses, acc);
        return;
    }

    if (g_atomic_int_get(&trace_active_atomic) && cp_mem_accesses) {
        g_array_append_val(cp_mem_accesses, acc);
    }
}

/* ========================= Trace state management ========================= */

static gint simpoint_entry_compare(gconstpointer a, gconstpointer b)
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

static void load_simpoint_weights_file(const char *path, GArray *entries)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        double weight;
        int cluster;

        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }

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

/*
 * Parse native SimPoint selections.  Lines: <interval_id> <cluster_id>.
 * start/stop are derived as interval_id * simpoint_interval_insns.
 */
static GArray *parse_simpoints_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "champsim_tracer: cannot open simpoints file: %s\n", path);
        return NULL;
    }

    GArray *entries = g_array_new(false, false, sizeof(SimPointEntry));
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }

        SimPointEntry sp = {0};
        uint64_t interval_id;
        int cluster_id = -1;
        int parsed = sscanf(line, "%" SCNu64 " %d", &interval_id,
                            &cluster_id);

        if (parsed >= 1) {
            uint64_t start = interval_id * simpoint_interval_insns;
            uint64_t stop = (simpoint_interval_insns > UINT64_MAX - start)
                ? UINT64_MAX
                : start + simpoint_interval_insns;

            sp.interval_id = interval_id;
            sp.start_insn = start;
            sp.stop_insn = stop;
            sp.cluster_id = (parsed == 2) ? cluster_id : (int)entries->len;
            sp.weight = 0.0;
            g_array_append_val(entries, sp);
        }
    }

    fclose(f);

    {
        g_autofree char *weights_path = NULL;
        if (g_str_has_suffix(path, ".simpoints")) {
            weights_path = g_strndup(path, strlen(path) - strlen(".simpoints"));
            weights_path = g_strconcat(weights_path, ".weights", NULL);
        } else {
            weights_path = g_strdup_printf("%s.weights", path);
        }
        load_simpoint_weights_file(weights_path, entries);
    }

    g_array_sort(entries, simpoint_entry_compare);

    return entries;
}

static void start_trace_segment(const char *label,
                                uint64_t start, uint64_t stop)
{
    if (current_segment) {
        trace_segment_free(current_segment);
    }

    current_segment = trace_segment_new(label, start, stop);
    current_segment->thread_id = 0;
    current_segment->body_seq_num = 0;

    {
        time_t now = time(NULL);
        struct tm tm_buf;
        localtime_r(&now, &tm_buf);
        strftime(current_segment->start_datetime,
                 sizeof(current_segment->start_datetime),
                 "%Y-%m-%d %H:%M:%S", &tm_buf);
    }

    if (cpu_to_thread_id) {
        g_hash_table_remove_all(cpu_to_thread_id);
    }
    next_thread_id = 0;
    last_active_thread = UINT32_MAX;

    g_autofree char *bin_path = NULL;
    if (output_base_path) {
        bin_path = simpoints_list
            ? g_strdup_printf("%s_%s.wpt", output_base_path, label)
            : g_strdup_printf("%s.wpt", output_base_path);
    }

    if (bin_path) {
        current_segment->bin_file = fopen(bin_path, "wb");
        if (!current_segment->bin_file) {
            fprintf(stderr, "champsim_tracer: cannot open binary output: %s\n",
                    bin_path);
        } else {
            current_segment->bin_stream = body_stream_new(
                current_segment->bin_file, 0,
                current_segment->start_datetime);
            if (!current_segment->bin_stream) {
                fprintf(stderr, "champsim_tracer: cannot initialize binary stream\n");
            }
        }
    }

    trace_active = true;
    g_atomic_int_set(&trace_active_atomic, 1);
}

static void drain_cp_mem_into_dyn_params(GArray *dyn_params,
                                         const BBTemplate *bb_tmpl)
{
    if (!cp_mem_accesses) {
        return;
    }
    /*
     * memops are recorded in execution order; insns within a BB execute
     * sequentially, so insn_pc is monotonically non-decreasing across
     * memops of a single entry.  Walk the template's insn_pcs[] in
     * lockstep to assign insn_index.
     */
    guint idx = 0;
    guint n_insns = bb_tmpl ? bb_tmpl->n_insns : 0;
    for (guint m = 0; m < cp_mem_accesses->len; m++) {
        const WPMemAccess *acc = &g_array_index(cp_mem_accesses,
                                                WPMemAccess, m);
        while (idx < n_insns && bb_tmpl->insn_pcs[idx] != acc->insn_pc) {
            idx++;
        }
        DynParam dp = {
            .type = (uint8_t)(acc->is_store ? DYN_STORE_ADDR : DYN_LOAD_ADDR),
            .insn_index = (uint16_t)(idx < n_insns ? idx : 0),
            .value = acc->mem_vaddr,
            .data_size = acc->data_size,
            .data_lo = acc->data_lo,
            .data_hi = acc->data_hi,
        };
        g_array_append_val(dyn_params, dp);
    }
    g_array_set_size(cp_mem_accesses, 0);
}

/*
 * Flush the pending final-TB body entry before a segment is finished.
 *
 * BodyEntries are emitted lazily from vcpu_tb_exec(): when a TB starts,
 * we emit the entry for the *previous* TB because only then do we know
 * whether that TB's branch was taken.  A TB terminated by a
 * process-exiting syscall never has a "next" TB to trigger the flush,
 * so its memops would silently disappear.  This helper emits that
 * pending entry (no wrong-path: WP is undefined after process exit).
 * Must be called with exec_lock held.
 */
static void flush_pending_final_body_entry(void)
{
    TraceSegment *seg = current_segment;
    unsigned int cpu_index = 0;
    uint64_t prev_start =
        qemu_plugin_u64_get(sb_prev_start_pc, cpu_index);
    uint64_t prev_ft =
        qemu_plugin_u64_get(sb_prev_fall_through, cpu_index);
    uint64_t prev_is_branch =
        qemu_plugin_u64_get(sb_prev_bb_ends_in_branch, cpu_index);

    if (!seg || !seg->bin_stream || prev_start == 0) {
        goto reset;
    }

    {
        g_mutex_lock(&data_lock);
        BBTemplate *prev_tb_tmpl = find_template(prev_start);
        if (prev_tb_tmpl) {
            if (cp_chain_entry_pc == 0 || cp_chain_last_ft != prev_start) {
                cp_chain_reset();
                cp_chain_entry_pc = prev_start;
            }
            g_array_append_val(cp_chain_fragments, prev_tb_tmpl);
            cp_chain_last_ft = prev_ft;
        }

        if (!prev_is_branch || !prev_tb_tmpl ||
            cp_chain_fragments->len == 0 || cp_chain_entry_pc == 0) {
            /* No terminating branch → not a valid basic block; discard. */
            g_mutex_unlock(&data_lock);
            goto reset;
        }

        BBTemplate *bb_tmpl = get_or_create_bb_template(
            cp_chain_entry_pc,
            (BBTemplate **)cp_chain_fragments->data,
            cp_chain_fragments->len);
        g_mutex_unlock(&data_lock);

        BodyEntry entry = {
            .seq_num = ++seg->body_seq_num,
            .template_id = bb_tmpl ? bb_tmpl->template_id : 0,
            .dyn_params = g_array_sized_new(false, false, sizeof(DynParam),
                              cp_mem_accesses ? cp_mem_accesses->len : 0),
            .wp_entries = NULL,
            .tmpl = bb_tmpl,
        };
        drain_cp_mem_into_dyn_params(entry.dyn_params, bb_tmpl);

        body_stream_write_entry(seg->bin_stream, &entry);
        body_entry_clear(&entry);
    }

reset:
    g_mutex_lock(&data_lock);
    cp_chain_reset();
    if (cp_mem_accesses) {
        g_array_set_size(cp_mem_accesses, 0);
    }
    g_mutex_unlock(&data_lock);

    qemu_plugin_u64_set(sb_prev_start_pc, 0, 0);
    qemu_plugin_u64_set(sb_prev_fall_through, 0, 0);
}

/*
 * Finalize and write the current trace segment.  Must be called with
 * exec_lock held.
 */
static void finish_trace_segment(void)
{
    if (!current_segment) {
        return;
    }

    trace_active = false;
    g_atomic_int_set(&trace_active_atomic, 0);

    flush_pending_final_body_entry();

    if (current_segment->bin_stream) {
        body_stream_finish(current_segment->bin_stream);
    }

    trace_segment_free(current_segment);
    current_segment = NULL;
}

/* ========================= Execution callback ========================= */

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    uint64_t n_insns = (uint64_t)(uintptr_t)udata;

    g_mutex_lock(&exec_lock);

    if (g_atomic_int_get(&trace_shutting_down)) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    if (!wp_in_progress) {
        uint64_t icount_prev = qemu_plugin_u64_get(sb_insn_count, cpu_index);
        qemu_plugin_u64_set(sb_insn_count, cpu_index, icount_prev + n_insns);
    }

    uint64_t icount = qemu_plugin_u64_get(sb_insn_count, cpu_index);

    if (wp_in_progress) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    /* --- Tracing window management --- */
    if (simpoints_list) {
        if (trace_active && icount >= trace_stop_insn) {
            finish_trace_segment();
            simpoints_current_idx++;
        }
        if (!trace_active && simpoints_current_idx < simpoints_list->len) {
            SimPointEntry *sp = &g_array_index(simpoints_list,
                                               SimPointEntry,
                                               simpoints_current_idx);
            if (icount >= sp->start_insn && icount < sp->stop_insn) {
                trace_start_insn = sp->start_insn;
                trace_stop_insn = sp->stop_insn;
                g_autofree char *label =
                    g_strdup_printf("sp%u", simpoints_current_idx);
                start_trace_segment(label, sp->start_insn, sp->stop_insn);
            }
        }
        if (!trace_active && simpoints_current_idx >= simpoints_list->len) {
            g_atomic_int_set(&trace_shutting_down, 1);
            g_mutex_unlock(&exec_lock);
            exit(0);
        }
    } else {
        if (!trace_active && icount >= trace_start_insn &&
            icount < trace_stop_insn) {
            start_trace_segment("trace", trace_start_insn, trace_stop_insn);
        }
        if (trace_active && icount >= trace_stop_insn) {
            finish_trace_segment();
            g_atomic_int_set(&trace_shutting_down, 1);
            g_mutex_unlock(&exec_lock);
            exit(0);
        }
    }

    TraceSegment *seg = current_segment;
    if (!trace_active || !seg) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    if (!cp_mem_accesses) {
        cp_mem_accesses = g_array_new(false, false, sizeof(WPMemAccess));
    }

    uint64_t current_pc = qemu_plugin_u64_get(sb_current_pc, cpu_index);
    uint64_t prev_start = qemu_plugin_u64_get(sb_prev_start_pc, cpu_index);
    uint64_t prev_last = qemu_plugin_u64_get(sb_prev_last_pc, cpu_index);
    uint64_t prev_ft = qemu_plugin_u64_get(sb_prev_fall_through, cpu_index);
    bool prev_is_branch = qemu_plugin_u64_get(sb_prev_bb_ends_in_branch,
                                              cpu_index);

    /* Skip initial block (no previous context) */
    if (prev_ft == 0) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    bool branch_taken = (current_pc != prev_ft);

    g_mutex_lock(&data_lock);

    if (prev_is_branch) {
        stat_branches_observed++;
        if (branch_taken) {
            stat_branches_taken++;
        } else {
            stat_branches_not_taken++;
        }
    }

    BranchRecord *br = (BranchRecord *)g_hash_table_lookup(branch_map,
                                                           &prev_last);
    if (prev_is_branch && !br) {
        br = g_new0(BranchRecord, 1);
        br->pc = prev_last;
        br->fall_through = prev_ft;
        g_hash_table_replace(branch_map, &br->pc, br);
    }

    if (prev_is_branch && branch_taken) {
        br->taken_target = current_pc;
        br->has_taken_target = true;
    }

    /* Append previous TB fragment to the in-flight basic-block chain. */
    BBTemplate *prev_tb_tmpl = find_template(prev_start);
    if (prev_tb_tmpl) {
        if (cp_chain_entry_pc == 0 || cp_chain_last_ft != prev_start) {
            /* Control-flow discontinuity: drop any partial accumulation. */
            cp_chain_reset();
            cp_chain_entry_pc = prev_start;
        }
        g_array_append_val(cp_chain_fragments, prev_tb_tmpl);
        cp_chain_last_ft = prev_ft;
    }

    bool finalize = prev_is_branch && prev_tb_tmpl != NULL;

    uint64_t wrong_target = 0;
    if (finalize) {
        if (branch_taken) {
            wrong_target = prev_ft;
        } else if (br && br->has_taken_target) {
            wrong_target = br->taken_target;
        } else {
            /* No learned alternative yet; skip WP until both directions
             * have been observed. */
            wrong_target = 0;
        }
    }

    BBTemplate *bb_tmpl = NULL;
    if (finalize && cp_chain_fragments->len > 0 && cp_chain_entry_pc != 0) {
        bb_tmpl = get_or_create_bb_template(
            cp_chain_entry_pc,
            (BBTemplate **)cp_chain_fragments->data,
            cp_chain_fragments->len);
    }

    g_mutex_unlock(&data_lock);

    if (!finalize) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    /* --- Emit one body entry for the finalized basic block --- */
    {
        BodyEntry entry;
        guint cp_mem_len = cp_mem_accesses ? cp_mem_accesses->len : 0;
        entry.seq_num = ++seg->body_seq_num;
        entry.template_id = bb_tmpl ? bb_tmpl->template_id : 0;
        entry.dyn_params = g_array_sized_new(false, false,
                             sizeof(DynParam), cp_mem_len);
        entry.wp_entries = NULL;
        entry.tmpl = bb_tmpl;

        drain_cp_mem_into_dyn_params(entry.dyn_params, bb_tmpl);

        g_mutex_lock(&data_lock);
        cp_chain_reset();
        g_mutex_unlock(&data_lock);

        if (enable_wrong_path && wrong_target != 0) {
            entry.wp_entries = simulate_wrong_path_ext(
                prev_last, current_pc, wrong_target, cpu_index);
        } else if (wrong_target == 0) {
            stat_wp_skipped++;
        }

        BodyStreamState *out_stream = seg->bin_stream;

        if (cpu_to_thread_id) {
            uint32_t cur_tid = get_or_assign_thread_id(cpu_index);
            if (cur_tid != last_active_thread) {
                last_active_thread = cur_tid;
            }
        }

        if (out_stream) {
            body_stream_write_entry(out_stream, &entry);
        }
        body_entry_clear(&entry);
    }

    g_mutex_unlock(&exec_lock);
}

/* ========================= Translation callback ========================= */

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t n_insns = qemu_plugin_tb_n_insns(tb);
    struct qemu_plugin_insn *first_insn = qemu_plugin_tb_get_insn(tb, 0);
    struct qemu_plugin_insn *last_insn = qemu_plugin_tb_get_insn(tb,
                                                                  n_insns - 1);
    uint64_t last_insn_pc = qemu_plugin_insn_vaddr(last_insn);
    size_t last_insn_size = qemu_plugin_insn_size(last_insn);
    uint64_t fall_through = last_insn_pc + last_insn_size;
    uint64_t bb_ends_in_branch = 0;
    uint64_t effective_last_pc = last_insn_pc;
    BBTemplate *existing_tmpl;

    g_mutex_lock(&data_lock);
    existing_tmpl = find_template(pc);
    if (existing_tmpl && existing_tmpl->n_insns > 0) {
        int br_idx = template_branch_index(existing_tmpl);
        bb_ends_in_branch = (br_idx >= 0) ? 1 : 0;
        if (br_idx >= 0) {
            effective_last_pc = existing_tmpl->insn_pcs[br_idx];
        }
    }
    g_mutex_unlock(&data_lock);

    if (!existing_tmpl) {
        uint64_t *insn_pcs = g_new0(uint64_t, n_insns);
        qemu_plugin_insn_info *insn_info = g_new0(qemu_plugin_insn_info, n_insns);
        uint8_t *insn_sizes = g_new0(uint8_t, n_insns);
        uint8_t *insn_bytes = g_new0(uint8_t, n_insns * MAX_INSN_BYTES);
        const char *symbol_name = qemu_plugin_insn_symbol(first_insn);

        for (size_t i = 0; i < n_insns; i++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
            insn_pcs[i] = qemu_plugin_insn_vaddr(insn);
            insn_sizes[i] = (uint8_t)MIN(qemu_plugin_insn_size(insn), MAX_INSN_BYTES);
            qemu_plugin_insn_data(insn,
                          &insn_bytes[i * MAX_INSN_BYTES],
                          insn_sizes[i]);

            if (cst_cap_arch >= 0) {
                qemu_plugin_cap_decode(cst_cap_arch, cst_cap_mode,
                                       &insn_bytes[i * MAX_INSN_BYTES],
                                       insn_sizes[i],
                                       insn_pcs[i],
                                       &insn_info[i]);
            }

            qemu_plugin_register_vcpu_mem_cb(
                insn, vcpu_mem_cb, QEMU_PLUGIN_CB_NO_REGS,
                QEMU_PLUGIN_MEM_RW, (void *)(uintptr_t)insn_pcs[i]);
        }

        g_mutex_lock(&data_lock);
        {
            BBTemplate *tmpl = get_or_create_template(pc,
                                                      (uint32_t)n_insns,
                                                      insn_pcs,
                                                      insn_info,
                                                      insn_sizes,
                                                      insn_bytes,
                                                      symbol_name, fall_through);
            if (tmpl && tmpl->n_insns > 0) {
                int br_idx = template_branch_index(tmpl);
                bb_ends_in_branch = (br_idx >= 0) ? 1 : 0;
                if (br_idx >= 0) {
                    effective_last_pc = tmpl->insn_pcs[br_idx];
                }
            }
        }
        g_mutex_unlock(&data_lock);

        g_free(insn_pcs);
        g_free(insn_info);
        g_free(insn_sizes);
        g_free(insn_bytes);
    } else {
        /* Re-translation of known BB: only dynamic memory callbacks needed. */
        for (size_t i = 0; i < n_insns; i++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
            uint64_t insn_pc = qemu_plugin_insn_vaddr(insn);

            qemu_plugin_register_vcpu_mem_cb(
                insn, vcpu_mem_cb, QEMU_PLUGIN_CB_NO_REGS,
                QEMU_PLUGIN_MEM_RW, (void *)(uintptr_t)insn_pc);
        }
    }

    /* Instrument the block for execution tracking. */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_STORE_U64, sb_current_pc, pc);

    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, vcpu_tb_exec, QEMU_PLUGIN_CB_RW_REGS,
        (void *)(uintptr_t)n_insns);

    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        sb_prev_start_pc, pc);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        sb_prev_last_pc, effective_last_pc);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        sb_prev_fall_through, fall_through);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        sb_prev_bb_ends_in_branch, bb_ends_in_branch);
}

/* ========================= Flush callback ========================= */

/*
 * Called when the TB cache is flushed.
 *
 * During wrong-path execution, tb_gen_code() may trigger tb_flush() when
 * the code buffer is full, longjmping past simulate_wrong_path_ext()'s
 * cleanup code.  Reset wp_* state here so vcpu_tb_exec is not
 * permanently suppressed.
 */
static void vcpu_tb_flush(qemu_plugin_id_t id)
{
    g_mutex_lock(&exec_lock);

    if (wp_in_progress) {
        wp_in_progress = false;
        qemu_plugin_u64_set(sb_insn_count, wp_saved_cpu_index,
                            wp_saved_insn_count);
        qemu_plugin_u64_set(sb_prev_start_pc, wp_saved_cpu_index,
                            wp_saved_prev_start_pc);
        qemu_plugin_u64_set(sb_prev_last_pc, wp_saved_cpu_index,
                            wp_saved_prev_last_pc);
        qemu_plugin_u64_set(sb_prev_fall_through, wp_saved_cpu_index,
                            wp_saved_prev_fall_through);
        qemu_plugin_u64_set(sb_prev_bb_ends_in_branch, wp_saved_cpu_index,
                            wp_saved_prev_bb_ends_in_branch);
        if (wp_mem_accesses) {
            g_array_unref(wp_mem_accesses);
            wp_mem_accesses = NULL;
        }
    }

    /* Drop partial BB being assembled — we can't know whether the flushed
     * TB will resume, so preserving partial state would risk splicing
     * fragments from before and after the flush. */
    g_mutex_lock(&data_lock);
    cp_chain_reset();
    if (cp_mem_accesses) {
        g_array_set_size(cp_mem_accesses, 0);
    }
    g_mutex_unlock(&data_lock);

    g_mutex_unlock(&exec_lock);
}

/* ========================= Exit / statistics ========================= */

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_atomic_int_set(&trace_shutting_down, 1);

    g_mutex_lock(&exec_lock);

    if (trace_active) {
        finish_trace_segment();
    }

    g_autoptr(GString) report = g_string_new("");

    g_mutex_lock(&data_lock);

    static const struct { const char *label; const uint64_t *value; } counters[] = {
        { "Basic blocks translated",             &stat_blocks_translated },
        { "Branch transitions observed",         &stat_branches_observed },
        { "  Taken",                             &stat_branches_taken },
        { "  Not-taken",                         &stat_branches_not_taken },
        { "WP simulations performed",            &stat_wp_simulations },
        { "WP simulations skipped",              &stat_wp_skipped },
        { "WP total instructions",               &stat_wp_total_insns },
        { "WP total memory accesses",            &stat_wp_total_mem_accesses },
        { "WP early exits (fault)",              &stat_wp_early_exits },
        { "Unknown-instruction warnings",        &stat_unknown_insn_warnings },
    };
    static const struct { const char *label; const uint64_t *value; } bin_counters[] = {
        { "  Header bits",        &stat_bin_header_bits },
        { "  Body bits",          &stat_bin_body_bits },
        { "  Dyn CP bits",        &stat_bin_dyn_cp_bits },
        { "  Dyn WP bits",        &stat_bin_dyn_wp_bits },
        { "  WP exception bits",  &stat_bin_wp_exception_bits },
    };

    g_string_append_printf(report,
        "\n=== Wrong-Path Trace Plugin Statistics ===\n"
        "Target architecture: %s\n"
        "Max wrong-path depth: %d instructions\n"
        "BB templates created: %u\n"
        "Unique branch PCs: %u\n",
        target_name ? target_name : "unknown",
        max_wrong_path_depth,
        g_hash_table_size(bb_map),
        g_hash_table_size(branch_map));

    for (size_t i = 0; i < G_N_ELEMENTS(counters); i++) {
        g_string_append_printf(report, "%-40s %" PRIu64 "\n",
                               counters[i].label, *counters[i].value);
    }

    if (stat_wp_simulations > 0) {
        g_string_append_printf(report,
            "Average wrong-path length: %.1f instructions\n",
            (double)stat_wp_total_insns / stat_wp_simulations);
    }

    if (simpoints_list) {
        g_string_append_printf(report,
            "SimPoints loaded/traced: %u / %u\n",
            simpoints_list->len, simpoints_current_idx);
    }

    if (stat_bin_total_bits > 0) {
        g_string_append_printf(report,
            "Total binary bits: %" PRIu64 " (%.2f MiB)\n",
            stat_bin_total_bits,
            (double)stat_bin_total_bits / 8.0 / (1024.0 * 1024.0));
        for (size_t i = 0; i < G_N_ELEMENTS(bin_counters); i++) {
            g_string_append_printf(report,
                "%-40s %" PRIu64 " (%.2f%%)\n",
                bin_counters[i].label, *bin_counters[i].value,
                100.0 * (double)(*bin_counters[i].value) / stat_bin_total_bits);
        }
    }

    g_string_append_printf(report,
        "==========================================\n");

    g_mutex_unlock(&data_lock);

    qemu_plugin_outs(report->str);

    if (unknown_warn_file) {
        fclose(unknown_warn_file);
    }
    g_free(unknown_warn_path);

    if (cp_mem_accesses) {
        g_array_unref(cp_mem_accesses);
    }
    if (simpoints_list) {
        g_array_unref(simpoints_list);
    }
    g_hash_table_unref(tb_map);
    g_hash_table_unref(bb_map);
    if (cp_chain_fragments) {
        g_array_unref(cp_chain_fragments);
    }
    g_hash_table_unref(branch_map);

    g_hash_table_unref(option_ht);
    qemu_plugin_scoreboard_free(vcpu_sb);
    g_free(output_base_path);
    g_free(program_name);
    g_free(simpoints_file_path);
}

/* ========================= Plugin installation ========================= */

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    target_name = info->target_name;

    /* Resolve ISA from target_name via the per-ISA prefix tables. */
    trace_isa = TRACE_ISA_UNKNOWN;
    for (unsigned isa_i = TRACE_ISA_X86;
         isa_i < G_N_ELEMENTS(isa_properties); isa_i++) {
        TraceISA isa = (TraceISA)isa_i;
        const char *const *prefixes = isa_properties[isa].target_prefixes;
        if (!prefixes) {
            continue;
        }
        for (; *prefixes; prefixes++) {
            if (g_str_has_prefix(target_name, *prefixes)) {
                trace_isa = isa;
                break;
            }
        }
        if (trace_isa != TRACE_ISA_UNKNOWN) {
            break;
        }
    }
    if (trace_isa == TRACE_ISA_UNKNOWN) {
        fprintf(stderr, "champsim_tracer: warning: unsupported ISA '%s', "
                "instruction decode will be limited\n", target_name);
    }

    /* Map ISA to Capstone arch/mode for qemu_plugin_cap_decode(). */
    cst_cap_arch = (trace_isa != TRACE_ISA_UNKNOWN)
                   ? isa_properties[trace_isa].cap_arch : -1;
    switch (trace_isa) {
    case TRACE_ISA_X86:
        cst_cap_mode = QEMU_PLUGIN_CAP_MODE_64;
        break;
    case TRACE_ISA_AARCH64:
        cst_cap_mode = QEMU_PLUGIN_CAP_MODE_LITTLE_ENDIAN;
        break;
    case TRACE_ISA_RISCV:
        cst_cap_mode = (g_str_has_prefix(target_name, "riscv32")
                        ? QEMU_PLUGIN_CAP_MODE_RISCV32
                        : QEMU_PLUGIN_CAP_MODE_RISCV64)
                       | QEMU_PLUGIN_CAP_MODE_RISCVC;
        break;
    case TRACE_ISA_MIPS:
        cst_cap_mode = QEMU_PLUGIN_CAP_MODE_32
                      | (g_str_has_suffix(target_name, "el")
                         ? QEMU_PLUGIN_CAP_MODE_LITTLE_ENDIAN
                         : QEMU_PLUGIN_CAP_MODE_BIG_ENDIAN);
        break;
    default:
        cst_cap_mode = 0;
        break;
    }

    /* Best-effort capture of the full QEMU command line. */
    {
        FILE *cmdline_f = fopen("/proc/self/cmdline", "r");
        if (cmdline_f) {
            char buf[4096];
            size_t n = fread(buf, 1, sizeof(buf) - 1, cmdline_f);
            fclose(cmdline_f);
            if (n > 0) {
                for (size_t i = 0; i < n - 1; i++) {
                    if (buf[i] == '\0') {
                        buf[i] = ' ';
                    }
                }
                buf[n] = '\0';
                qemu_command_line = g_strdup(buf);
            }
        }
    }

    /* Option dispatch table */
    option_ht = g_hash_table_new(g_str_hash, g_str_equal);
    {
        static const struct { const char *name; int id; }
        opt_entries[] = {
            {"depth",   OPT_DEPTH},   {"outfile", OPT_OUTFILE},
            {"wp",      OPT_WP},
            {"start",   OPT_START},   {"stop",    OPT_STOP},
            {"program", OPT_PROGRAM}, {"spfile",  OPT_SPFILE},
            {"spinterval", OPT_SPINTERVAL},
            {"comment", OPT_COMMENT}, {"memdata", OPT_MEMDATA},
            {NULL, 0}
        };
        for (int i = 0; opt_entries[i].name; i++) {
            g_hash_table_insert(option_ht,
                                (gpointer)opt_entries[i].name,
                                GINT_TO_POINTER(opt_entries[i].id));
        }
    }

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);

        gpointer val = tokens[0] ?
            g_hash_table_lookup(option_ht, tokens[0]) : NULL;
        if (!val) {
            fprintf(stderr, "champsim_tracer: unknown option: %s\n", opt);
            return -1;
        }

        switch (GPOINTER_TO_INT(val)) {
        case OPT_DEPTH:
            max_wrong_path_depth = atoi(tokens[1]);
            if (max_wrong_path_depth <= 0) {
                fprintf(stderr, "champsim_tracer: invalid depth: %s\n", tokens[1]);
                return -1;
            }
            break;
        case OPT_OUTFILE:
            output_base_path = g_strdup(tokens[1]);
            break;
        case OPT_WP:
            enable_wrong_path = (atoi(tokens[1]) != 0);
            break;
        case OPT_START:
            trace_start_insn = g_ascii_strtoull(tokens[1], NULL, 10);
            break;
        case OPT_STOP:
            trace_stop_insn = g_ascii_strtoull(tokens[1], NULL, 10);
            break;
        case OPT_PROGRAM:
            program_name = g_strdup(tokens[1]);
            break;
        case OPT_SPFILE:
            simpoints_file_path = g_strdup(tokens[1]);
            break;
        case OPT_SPINTERVAL:
            simpoint_interval_insns = g_ascii_strtoull(tokens[1], NULL, 10);
            if (simpoint_interval_insns == 0) {
                fprintf(stderr, "champsim_tracer: invalid spinterval: %s\n", tokens[1]);
                return -1;
            }
            break;
        case OPT_COMMENT:
            trace_comment = g_strdup(tokens[1]);
            break;
        case OPT_MEMDATA:
            enable_mem_data = (atoi(tokens[1]) != 0);
            break;
        }
    }

    if (!output_base_path) {
        output_base_path = g_strdup("champsim_tracer_out");
    }

    unknown_warn_path = g_strdup_printf("%s.unknown_warnings.log",
                                        output_base_path);
    unknown_warn_file = fopen(unknown_warn_path, "w");
    if (!unknown_warn_file) {
        fprintf(stderr, "champsim_tracer: cannot open unknown-warning output: %s\n",
                unknown_warn_path);
    } else {
        fprintf(unknown_warn_file, "# champsim_tracer unknown instruction warnings\n");
        fflush(unknown_warn_file);
    }

    if (simpoints_file_path) {
        simpoints_list = parse_simpoints_file(simpoints_file_path);
        if (!simpoints_list || simpoints_list->len == 0) {
            fprintf(stderr, "champsim_tracer: no valid simpoints in: %s\n",
                    simpoints_file_path);
            g_free(simpoints_file_path);
            return -1;
        }
        fprintf(stderr, "champsim_tracer: loaded %u simpoints from %s\n",
                simpoints_list->len, simpoints_file_path);
        simpoints_current_idx = 0;

        trace_start_insn = 0;
        trace_stop_insn = UINT64_MAX;
    }

    g_mutex_init(&data_lock);
    g_mutex_init(&exec_lock);
    g_mutex_init(&unknown_warn_lock);
    tb_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                   NULL, bb_template_free);
    bb_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                   NULL, bb_template_free);
    cp_chain_fragments = g_array_new(false, false, sizeof(BBTemplate *));
    branch_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                       NULL, g_free);

    active_insn_table = isa_insn_class[trace_isa];
    active_insn_table_size = isa_insn_class_size[trace_isa];
    active_reg_table = isa_reg_class[trace_isa];
    active_reg_table_size = isa_reg_class_size[trace_isa];

    vcpu_sb = qemu_plugin_scoreboard_new(sizeof(VCPUScoreBoard));
    sb_current_pc = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, current_pc);
    sb_prev_start_pc = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, prev_start_pc);
    sb_prev_last_pc = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, prev_last_pc);
    sb_prev_fall_through = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, prev_fall_through);
    sb_prev_bb_ends_in_branch = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, prev_bb_ends_in_branch);
    sb_insn_count = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, insn_count);

    cpu_to_thread_id = g_hash_table_new(g_direct_hash, g_direct_equal);

    if (!simpoints_list && trace_start_insn == 0) {
        start_trace_segment("trace", 0, trace_stop_insn);
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_flush_cb(id, vcpu_tb_flush);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
