/*
 * Wrong-Path Tracing Plugin for QEMU
 *
 * Main translation unit.  Responsibilities:
 *   - Plugin install, option parsing, lifecycle
 *   - Tracing window management (start/stop + simpoints)
 *   - BB template creation (delegated to BBTemplateCache)
 *   - vcpu_tb_trans / vcpu_tb_exec / vcpu_tb_flush callbacks
 *   - Memory-access callback (correct-path + wrong-path collection)
 *   - Exit-time statistics
 *
 * Peer TUs:
 *   - champsim_tracer_decode.cc  (Capstone → InsnFields)
 *   - champsim_tracer_wp.cc      (wrong-path simulator)
 *   - champsim_tracer_output.cc  (binary format v1.0 writer)
 *
 * Output: packed binary (.cst).  A reference Python decoder
 * (champsim_tracer_decode.py) produces human-readable text.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "champsim_tracer.h"
#include "champsim_tracer_bb_template_cache.h"
#include "champsim_tracer_branch_history.h"
#include "champsim_tracer_reg_handle_cache.h"
#include "champsim_tracer_simpoint_manager.h"
#include "champsim_tracer_stats.h"
#include "champsim_tracer_writer.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* ========================= Configuration ========================= */

int max_wrong_path_depth = 64;
static bool enable_wrong_path = true;
static char *output_base_path = NULL;
static char *output_pipe_command = NULL;
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
bool enable_reg_data = false;

/* ========================= Thread ID assignment ========================= */

static GHashTable *cpu_to_thread_id;
static uint32_t next_thread_id = 0;

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

static void vcpu_init_cb(qemu_plugin_id_t id, unsigned int cpu_index)
{
    (void)id;

    /*
     * Resolve cap_mode lazily on the first vCPU init.  The per-ISA
     * mode resolvers may call qemu_plugin_path_to_binary(), which
     * requires a live vCPU context (it dereferences current_cpu).
     */
    if (cst_cap_arch >= 0 && cst_cap_mode == 0
            && trace_isa != TRACE_ISA_UNKNOWN) {
        const IsaProperties *p = &isa_properties[trace_isa];
        if (p->cap_mode_for_target) {
            cst_cap_mode = p->cap_mode_for_target(target_name);
        }
    }

    if (enable_reg_data) {
        g_reg_handle_cache.ensure_initialized(cpu_index);
    }
}

enum PluginOptId {
    OPT_DEPTH = 1,
    OPT_OUTFILE,
    OPT_OUTPIPE,
    OPT_WP,
    OPT_START,
    OPT_STOP,
    OPT_PROGRAM,
    OPT_SPFILE,
    OPT_SPINTERVAL,
    OPT_COMMENT,
    OPT_MEMDATA,
    OPT_REGDATA,
};

/* ========================= Global state ========================= */

GMutex data_lock;
static GMutex exec_lock;

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

/*
 * Pending register snapshots produced by the per-insn reg-snap
 * callback for the currently-executing BB.  Each insn appends its src
 * snaps in InsnFields.src_regs[] order.  The buffer is drained into
 * BodyEntry.reg_snaps at BB-finalize time, and discarded on flush.
 * Active only when enable_reg_data is true.
 */
static __thread GArray *pending_reg_snaps = NULL;

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
    if (entry->reg_snaps) {
        g_array_unref(entry->reg_snaps);
    }
}

static void body_entry_clear(BodyEntry *entry)
{
    dyn_param_array_free(entry->dyn_params);
    if (entry->reg_snaps) {
        g_array_unref(entry->reg_snaps);
    }
    if (entry->wp_entries) {
        for (guint i = 0; i < entry->wp_entries->len; i++) {
            wp_bb_entry_clear(&g_array_index(entry->wp_entries, WPBBEntry, i));
        }
        g_array_unref(entry->wp_entries);
    }
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
    /* Drain async writer queue and join its thread BEFORE closing
     * the underlying FILE*, so all enqueued bytes hit xz/disk and
     * the writer can fflush cleanly. */
    if (seg->writer) {
        writer_finish(seg->writer);
        seg->writer = NULL;
    }
    if (seg->bin_file) {
        if (seg->bin_file_is_pipe) {
            int rc = pclose(seg->bin_file);
            if (rc != 0) {
                fprintf(stderr,
                        "champsim_tracer: output pipe child exited with status %d\n",
                        rc);
            }
        } else {
            fclose(seg->bin_file);
        }
    }
    g_free(seg->label);
    g_free(seg);
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

static void cp_chain_reset(void)
{
    cp_chain_entry_pc = 0;
    cp_chain_last_ft = 0;
    if (cp_chain_fragments) {
        g_array_set_size(cp_chain_fragments, 0);
    }
}

/* ========================= Reg-data snapshot capture ========================= */

/*
 * Read a register through the QEMU plugin descriptor handle.  Unknown
 * registers yield a zero snap.  Only meaningful when enable_reg_data is true
 * and the current callback requested QEMU_PLUGIN_CB_R_REGS.
 */
static __thread GByteArray *reg_read_buf;

static GByteArray *reg_read_scratch(void)
{
    if (!reg_read_buf) {
        reg_read_buf = g_byte_array_new();
    } else {
        g_byte_array_set_size(reg_read_buf, 0);
    }
    return reg_read_buf;
}

static inline bool qemu_reg_key_valid(const QemuRegKey *key)
{
    return key && key->name;
}

static inline bool qemu_reg_key_equal(const QemuRegKey *a, const QemuRegKey *b)
{
    return g_strcmp0(a->feature, b->feature) == 0 &&
           g_strcmp0(a->name, b->name) == 0;
}

static void read_qemu_reg_into_snap(unsigned int cpu_index,
                                    const QemuRegKey *qemu_reg,
                                    RegSnap *out)
{
    cst_wide_zero(&out->value);
    struct qemu_plugin_register *handle =
        g_reg_handle_cache.lookup(cpu_index, qemu_reg);
    if (!handle) {
        return;
    }
    GByteArray *buf = reg_read_scratch();
    int n = qemu_plugin_read_register(handle, buf);
    if (n <= 0) {
        return;
    }
    cst_wide_from_le_bytes(&out->value, buf->data, (size_t)n);
}

static inline void reg_snap_array_append(GArray *arr, const RegSnap *snap)
{
    guint pos = arr->len;
    g_array_set_size(arr, pos + 1);
    g_array_index(arr, RegSnap, pos) = *snap;
}

/*
 * Per-insn callback: snapshot source registers before execution, in
 * InsnFields.src_regs[] order.  Destination register identities remain
 * in the template, but destination values are not emitted because this
 * callback fires before the instruction executes.
 */
typedef struct {
    BBTemplate *tb_tmpl;
    uint32_t    insn_index;
} RegSnapInsnRef;

static void vcpu_insn_reg_snap_cb(unsigned int cpu_index, void *udata)
{
    if (!enable_reg_data || wp_in_progress) {
        return;
    }
    if (!g_atomic_int_get(&trace_active_atomic)) {
        return;
    }
    const RegSnapInsnRef *ref = (const RegSnapInsnRef *)udata;
    if (!ref || !ref->tb_tmpl ||
        ref->insn_index >= ref->tb_tmpl->n_insns ||
        !ref->tb_tmpl->insn_reg_names) {
        return;
    }
    const InsnFields *f = &ref->tb_tmpl->insn_fields[ref->insn_index];
    const InsnRegNames *names = &ref->tb_tmpl->insn_reg_names[ref->insn_index];

    if (!pending_reg_snaps) {
        pending_reg_snaps = g_array_new(false, false, sizeof(RegSnap));
    }
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        RegSnap s;
        read_qemu_reg_into_snap(cpu_index, &names->src_qemu_reg_keys[i], &s);
        reg_snap_array_append(pending_reg_snaps, &s);
    }
}

/* ========================= Wide regfile snapshot (WP path) =========================
 *
 * In wrong-path execution under qemu_plugin_spec_mode_begin(),
 * cpu_plugin_exec_tb() forces CF_MEMI_ONLY which silently drops any
 * subsequent qemu_plugin_register_vcpu_insn_exec_cb() registration.
 * So our normal per-insn snap callback never fires for WP fragments
 * even though the regfile is genuinely modified by speculative
 * execution.  To recover per-insn snapshots, the WP loop calls
 * wide_reg_snap_capture() *before* each cpu_plugin_exec_tb() and
 * later attributes the captured values to the per-insn slots of
 * the just-translated template via wp_capture_insn_snaps().  Spec
 * mode also forces CF_SINGLE_STEP|1 (one guest insn per fragment),
 * so a pre-fragment wide snap is semantically equivalent to a
 * pre-insn snap.
 */

typedef struct {
    QemuRegKey qemu_reg;
    RegSnap snap;
} WideRegEntry;

struct _WideRegSnap {
    WideRegEntry *entries;
    unsigned n;
};

static __thread WideRegSnap wide_reg_scratch;
static __thread unsigned wide_reg_scratch_cap;

static bool wide_reg_snap_contains(const WideRegSnap *w,
                                   const QemuRegKey *qemu_reg)
{
    for (unsigned i = 0; i < w->n; i++) {
        if (qemu_reg_key_equal(&w->entries[i].qemu_reg, qemu_reg)) {
            return true;
        }
    }
    return false;
}

WideRegSnap *wide_reg_snap_capture(unsigned int cpu_index)
{
    if (!enable_reg_data) {
        return NULL;
    }
    if (!active_reg_table || active_reg_table_size == 0) {
        return NULL;
    }

    wide_reg_scratch.n = 0;
    for (unsigned i = 0; i < active_reg_table_size; i++) {
        const QemuRegKey *qemu_reg = &active_reg_table[i].qemu_reg;
        if (!qemu_reg_key_valid(qemu_reg) ||
            wide_reg_snap_contains(&wide_reg_scratch, qemu_reg)) {
            continue;
        }
        if (wide_reg_scratch.n == wide_reg_scratch_cap) {
            wide_reg_scratch_cap = wide_reg_scratch_cap
                ? wide_reg_scratch_cap * 2 : 64;
            wide_reg_scratch.entries = g_renew(WideRegEntry,
                                               wide_reg_scratch.entries,
                                               wide_reg_scratch_cap);
        }
        unsigned slot = wide_reg_scratch.n++;
        wide_reg_scratch.entries[slot].qemu_reg = *qemu_reg;
        read_qemu_reg_into_snap(cpu_index, qemu_reg,
                                &wide_reg_scratch.entries[slot].snap);
    }
    return wide_reg_scratch.n ? &wide_reg_scratch : NULL;
}

void wide_reg_snap_free(WideRegSnap *w)
{
    (void)w;
}

static void wide_reg_snap_lookup(WideRegSnap *w, const QemuRegKey *qemu_reg,
                                 RegSnap *out)
{
    cst_wide_zero(&out->value);
    if (!w || !qemu_reg_key_valid(qemu_reg)) {
        return;
    }
    for (unsigned i = 0; i < w->n; i++) {
        if (qemu_reg_key_equal(&w->entries[i].qemu_reg, qemu_reg)) {
            *out = w->entries[i].snap;
            return;
        }
    }
}

void wp_capture_insn_snaps(const WideRegSnap *wide,
                           const BBTemplate *tmpl,
                           uint32_t insn_idx,
                           GArray *out_snaps)
{
    if (!enable_reg_data || !tmpl || !out_snaps ||
        !tmpl->insn_reg_names || insn_idx >= tmpl->n_insns) {
        return;
    }
    const InsnFields *f = &tmpl->insn_fields[insn_idx];
    const InsnRegNames *names = &tmpl->insn_reg_names[insn_idx];
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        RegSnap s;
        wide_reg_snap_lookup((WideRegSnap *)wide,
                             &names->src_qemu_reg_keys[i], &s);
        reg_snap_array_append(out_snaps, &s);
    }
}

void wp_capture_insn_snaps_live(unsigned int cpu_index,
                                const BBTemplate *tmpl,
                                uint32_t insn_idx,
                                GArray *out_snaps)
{
    if (!enable_reg_data || !tmpl || !out_snaps ||
        !tmpl->insn_reg_names || insn_idx >= tmpl->n_insns) {
        return;
    }
    const InsnFields *f = &tmpl->insn_fields[insn_idx];
    const InsnRegNames *names = &tmpl->insn_reg_names[insn_idx];
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        RegSnap s;
        read_qemu_reg_into_snap(cpu_index, &names->src_qemu_reg_keys[i], &s);
        reg_snap_array_append(out_snaps, &s);
    }
}

/* ========================= Memory access callback ========================= */

static __thread GByteArray *mem_read_buf;

static GByteArray *mem_read_scratch(void)
{
    if (!mem_read_buf) {
        mem_read_buf = g_byte_array_sized_new(CST_MAX_WIDE_BYTES);
    }
    g_byte_array_set_size(mem_read_buf, 0);
    return mem_read_buf;
}

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
    };
    cst_wide_zero(&acc.data);

    (void)cpu_index;

    if (enable_mem_data) {
        unsigned shift = qemu_plugin_mem_size_shift(info);
        size_t access_size = shift >= 6 ? CST_MAX_WIDE_BYTES
                                        : ((size_t)1 << shift);
        if (access_size > CST_MAX_WIDE_BYTES) {
            access_size = CST_MAX_WIDE_BYTES;
        }
        acc.data_size = (uint8_t)access_size;

        if (shift <= 4) {
            qemu_plugin_mem_value val = qemu_plugin_mem_get_value(info);
            switch (val.type) {
            case QEMU_PLUGIN_MEM_VALUE_U8:
                acc.data = cst_wide_from_u64(val.data.u8);
                break;
            case QEMU_PLUGIN_MEM_VALUE_U16:
                acc.data = cst_wide_from_u64(val.data.u16);
                break;
            case QEMU_PLUGIN_MEM_VALUE_U32:
                acc.data = cst_wide_from_u64(val.data.u32);
                break;
            case QEMU_PLUGIN_MEM_VALUE_U64:
                acc.data = cst_wide_from_u64(val.data.u64);
                break;
            case QEMU_PLUGIN_MEM_VALUE_U128:
                cst_wide_zero(&acc.data);
                acc.data.limb[0] = val.data.u128.low;
                acc.data.limb[1] = val.data.u128.high;
                break;
            }
        } else {
            GByteArray *buf = mem_read_scratch();
            if (qemu_plugin_read_memory_vaddr(vaddr, buf, access_size)) {
                cst_wide_from_le_bytes(&acc.data, buf->data, buf->len);
            } else {
                acc.data_size = 0;
            }
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

static void start_trace_segment(const char *label,
                                uint64_t start, uint64_t stop)
{
    if (current_segment) {
        trace_segment_free(current_segment);
    }

    current_segment = trace_segment_new(label, start, stop);
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

    g_autofree char *bin_path = NULL;
    if (output_base_path) {
        bin_path = g_simpoints.is_active()
            ? g_strdup_printf("%s_%s.cst", output_base_path, label)
            : g_strdup_printf("%s.cst", output_base_path);
    }

    /*
     * Output destination resolution:
     *   - outpipe=CMD     -> popen(CMD, "w").  Per-segment substitution
     *                        of "%s" in CMD is replaced with the segment
     *                        label so simpoint runs land in distinct files.
     *   - outfile=PATH    -> fopen(PATH[.cst|_LABEL.cst], "wb").
     * outpipe takes precedence when both are set.
     */
    if (output_pipe_command) {
        g_autofree char *cmd = NULL;
        if (strstr(output_pipe_command, "%s")) {
            cmd = g_strdup_printf(output_pipe_command, label);
        } else {
            cmd = g_strdup(output_pipe_command);
        }
        current_segment->bin_file = popen(cmd, "w");
        if (!current_segment->bin_file) {
            fprintf(stderr,
                    "champsim_tracer: cannot open output pipe: %s\n",
                    cmd);
        } else {
            current_segment->bin_file_is_pipe = true;
            current_segment->writer =
                writer_start(current_segment->bin_file, true);
            current_segment->bin_stream = body_stream_new(
                current_segment->writer, current_segment->start_datetime);
            if (!current_segment->bin_stream) {
                fprintf(stderr,
                        "champsim_tracer: cannot initialize binary stream\n");
            }
        }
    } else if (bin_path) {
        current_segment->bin_file = fopen(bin_path, "wb");
        if (!current_segment->bin_file) {
            fprintf(stderr, "champsim_tracer: cannot open binary output: %s\n",
                    bin_path);
        } else {
            current_segment->writer =
                writer_start(current_segment->bin_file, false);
            current_segment->bin_stream = body_stream_new(
                current_segment->writer, current_segment->start_datetime);
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
            .data = acc->data,
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
        BBTemplate *prev_tb_tmpl = g_bb_template_cache.find_tb_template(prev_start);
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

        BBTemplate *bb_tmpl = g_bb_template_cache.get_or_create_bb_template(
            cp_chain_entry_pc,
            (BBTemplate **)cp_chain_fragments->data,
            cp_chain_fragments->len);
        g_mutex_unlock(&data_lock);

        BodyEntry entry = {
            .seq_num = ++seg->body_seq_num,
            .template_id = bb_tmpl ? bb_tmpl->template_id : 0,
            .dyn_params = g_array_sized_new(false, false, sizeof(DynParam),
                              cp_mem_accesses ? cp_mem_accesses->len : 0),
            .reg_snaps = NULL,
            .wp_entries = NULL,
            .tmpl = bb_tmpl,
        };
        drain_cp_mem_into_dyn_params(entry.dyn_params, bb_tmpl);
        if (enable_reg_data && pending_reg_snaps) {
            entry.reg_snaps = g_array_ref(pending_reg_snaps);
            pending_reg_snaps = g_array_new(false, false, sizeof(RegSnap));
        }

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
    if (g_simpoints.is_active()) {
        if (trace_active && icount >= trace_stop_insn) {
            finish_trace_segment();
            g_simpoints.advance();
        }
        if (!trace_active) {
            if (const SimPointEntry *sp = g_simpoints.current()) {
                if (icount >= sp->start_insn && icount < sp->stop_insn) {
                    trace_start_insn = sp->start_insn;
                    trace_stop_insn = sp->stop_insn;
                    g_autofree char *label = g_strdup_printf(
                        "sp%zu", g_simpoints.current_index());
                    start_trace_segment(label, sp->start_insn, sp->stop_insn);
                }
            } else {
                g_atomic_int_set(&trace_shutting_down, 1);
                g_mutex_unlock(&exec_lock);
                exit(0);
            }
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
        g_stats.branches_observed++;
        if (branch_taken) {
            g_stats.branches_taken++;
        } else {
            g_stats.branches_not_taken++;
        }
    }

    BranchRecord *br = prev_is_branch
        ? g_branch_history.get_or_create(prev_last, prev_ft)
        : g_branch_history.find(prev_last);
    if (br) {
        br->fall_through = prev_ft;
    }

    /* Append previous TB fragment to the in-flight basic-block chain. */
    BBTemplate *prev_tb_tmpl = g_bb_template_cache.find_tb_template(prev_start);
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
        int br_idx = BBTemplateCache::template_branch_index(prev_tb_tmpl);
        const InsnFields *bf = (br_idx >= 0)
            ? &prev_tb_tmpl->insn_fields[br_idx] : NULL;
        bool is_indirect = bf && (
            bf->branch_type == BRANCH_INDIRECT_JUMP ||
            bf->branch_type == BRANCH_RETURN);
        bool direct_cond = bf && (
            (bf->branch_type == BRANCH_COND_DIRECT) ||
            (bf->branch_type == BRANCH_DIRECT_JUMP &&
             bf->branch_conditional));

        if (is_indirect) {
            if (branch_taken) {
                BranchHistory::note_target(br, current_pc);
            }
            wrong_target = BranchHistory::indirect_wrong_target(br,
                                                                current_pc,
                                                                prev_ft);
        } else if (branch_taken) {
            /* CP took a direct branch → WP is the fall-through. */
            wrong_target = prev_ft;
        } else if (direct_cond && bf->has_immediate &&
                   (uint64_t)bf->immediate != prev_ft) {
            /* CP fell through a direct conditional → WP is the
             * statically-resolved taken target. */
            wrong_target = (uint64_t)bf->immediate;
        } else {
            wrong_target = 0;
        }
    }

    BBTemplate *bb_tmpl = NULL;
    if (finalize && cp_chain_fragments->len > 0 && cp_chain_entry_pc != 0) {
        bb_tmpl = g_bb_template_cache.get_or_create_bb_template(
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
        entry.reg_snaps = NULL;
        entry.wp_entries = NULL;
        entry.tmpl = bb_tmpl;
        entry.thread_id = cpu_to_thread_id
            ? get_or_assign_thread_id(cpu_index) : cpu_index;

        drain_cp_mem_into_dyn_params(entry.dyn_params, bb_tmpl);
        if (enable_reg_data && pending_reg_snaps) {
            entry.reg_snaps = g_array_ref(pending_reg_snaps);
            pending_reg_snaps = g_array_new(false, false, sizeof(RegSnap));
        }

        g_mutex_lock(&data_lock);
        cp_chain_reset();
        g_mutex_unlock(&data_lock);

        if (enable_wrong_path && wrong_target != 0) {
            entry.wp_entries = simulate_wrong_path_ext(
                prev_last, current_pc, wrong_target, cpu_index);
        } else if (wrong_target == 0) {
            g_stats.wp_skipped++;
        }

        BodyStreamState *out_stream = seg->bin_stream;

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
    size_t raw_n_insns = qemu_plugin_tb_n_insns(tb);
    if (raw_n_insns == 0) {
        return;
    }
    struct qemu_plugin_insn *first_insn = qemu_plugin_tb_get_insn(tb, 0);
    struct qemu_plugin_insn *last_insn = qemu_plugin_tb_get_insn(tb,
                                                                  raw_n_insns - 1);
    uint64_t last_insn_pc = qemu_plugin_insn_vaddr(last_insn);
    size_t last_insn_size = qemu_plugin_insn_size(last_insn);
    uint64_t fall_through = last_insn_pc + last_insn_size;
    uint64_t bb_ends_in_branch = 0;
    uint64_t effective_last_pc = last_insn_pc;
    BBTemplate *existing_tmpl;

    uint64_t *insn_pcs = g_new0(uint64_t, raw_n_insns);
    qemu_plugin_insn_info *insn_info =
        g_new0(qemu_plugin_insn_info, raw_n_insns);
    uint8_t *insn_sizes = g_new0(uint8_t, raw_n_insns);
    uint8_t *insn_bytes = g_new0(uint8_t,
                                 raw_n_insns * MAX_INSN_BYTES);
    uint32_t *canonical_index = g_new0(uint32_t, raw_n_insns);
    bool *canonical_first = g_new0(bool, raw_n_insns);
    uint32_t canonical_n_insns = 0;

    for (size_t i = 0; i < raw_n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t raw_pc = qemu_plugin_insn_vaddr(insn);
        uint8_t raw_size =
            (uint8_t)MIN(qemu_plugin_insn_size(insn), MAX_INSN_BYTES);
        uint8_t raw_bytes[MAX_INSN_BYTES] = {0};

        qemu_plugin_insn_data(insn, raw_bytes, raw_size);

        bool duplicate = false;
        if (canonical_n_insns > 0) {
            uint32_t prev = canonical_n_insns - 1;
            duplicate = insn_pcs[prev] == raw_pc &&
                        insn_sizes[prev] == raw_size &&
                        memcmp(&insn_bytes[(size_t)prev * MAX_INSN_BYTES],
                               raw_bytes, MAX_INSN_BYTES) == 0;
        }

        if (duplicate) {
            canonical_index[i] = canonical_n_insns - 1;
        } else {
            uint32_t out = canonical_n_insns++;
            canonical_index[i] = out;
            canonical_first[i] = true;
            insn_pcs[out] = raw_pc;
            insn_sizes[out] = raw_size;
            memcpy(&insn_bytes[(size_t)out * MAX_INSN_BYTES],
                   raw_bytes, MAX_INSN_BYTES);

            if (cst_cap_arch >= 0) {
                qemu_plugin_cap_decode(cst_cap_arch, cst_cap_mode,
                                       &insn_bytes[(size_t)out *
                                                   MAX_INSN_BYTES],
                                       insn_sizes[out],
                                       insn_pcs[out],
                                       &insn_info[out]);
            }
        }

        qemu_plugin_register_vcpu_mem_cb(
            insn, vcpu_mem_cb, QEMU_PLUGIN_CB_NO_REGS,
            QEMU_PLUGIN_MEM_RW, (void *)(uintptr_t)raw_pc);
    }

    g_mutex_lock(&data_lock);
    existing_tmpl = g_bb_template_cache.find_tb_template(pc);
    if (existing_tmpl && existing_tmpl->n_insns > 0) {
        int br_idx = BBTemplateCache::template_branch_index(existing_tmpl);
        bb_ends_in_branch = (br_idx >= 0) ? 1 : 0;
        if (br_idx >= 0) {
            effective_last_pc = existing_tmpl->insn_pcs[br_idx];
        }
    }
    g_mutex_unlock(&data_lock);

    if (!existing_tmpl) {
        const char *symbol_name = qemu_plugin_insn_symbol(first_insn);

        g_mutex_lock(&data_lock);
        BBTemplate *new_tmpl = NULL;
        {
            new_tmpl = g_bb_template_cache.get_or_create_tb_template(pc,
                                              canonical_n_insns,
                                              insn_pcs,
                                              insn_info,
                                              insn_sizes,
                                              insn_bytes,
                                              symbol_name, fall_through);
            if (new_tmpl && new_tmpl->n_insns > 0) {
                int br_idx = BBTemplateCache::template_branch_index(new_tmpl);
                bb_ends_in_branch = (br_idx >= 0) ? 1 : 0;
                if (br_idx >= 0) {
                    effective_last_pc = new_tmpl->insn_pcs[br_idx];
                }
            }
        }
        g_mutex_unlock(&data_lock);

        if (enable_reg_data && new_tmpl && new_tmpl->insn_reg_names) {
            RegSnapInsnRef *refs = g_new0(RegSnapInsnRef,
                                          canonical_n_insns);
            new_tmpl->insn_snap_refs = refs;
            for (uint32_t i = 0; i < canonical_n_insns; i++) {
                refs[i].tb_tmpl = new_tmpl;
                refs[i].insn_index = i;
            }
            for (size_t i = 0; i < raw_n_insns; i++) {
                if (!canonical_first[i]) {
                    continue;
                }
                struct qemu_plugin_insn *insn =
                    qemu_plugin_tb_get_insn(tb, i);
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, vcpu_insn_reg_snap_cb,
                    QEMU_PLUGIN_CB_R_REGS,
                    &refs[canonical_index[i]]);
            }
        }
    } else {
        /* Re-translation of known BB: re-arm dynamic callbacks. */
        RegSnapInsnRef *refs =
            (RegSnapInsnRef *)existing_tmpl->insn_snap_refs;
        for (size_t i = 0; i < raw_n_insns; i++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

            if (enable_reg_data && refs && canonical_first[i] &&
                canonical_index[i] < existing_tmpl->n_insns) {
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, vcpu_insn_reg_snap_cb,
                    QEMU_PLUGIN_CB_R_REGS,
                    &refs[canonical_index[i]]);
            }
        }
    }

    /* Instrument the block for execution tracking. */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_STORE_U64, sb_current_pc, pc);

    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, vcpu_tb_exec, QEMU_PLUGIN_CB_RW_REGS,
        (void *)(uintptr_t)canonical_n_insns);

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

    g_free(insn_pcs);
    g_free(insn_info);
    g_free(insn_sizes);
    g_free(insn_bytes);
    g_free(canonical_index);
    g_free(canonical_first);
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
    if (pending_reg_snaps) {
        g_array_set_size(pending_reg_snaps, 0);
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
        { "Branch transitions observed",         &g_stats.branches_observed },
        { "  Taken",                             &g_stats.branches_taken },
        { "  Not-taken",                         &g_stats.branches_not_taken },
        { "WP simulations performed",            &g_stats.wp_simulations },
        { "WP simulations skipped",              &g_stats.wp_skipped },
        { "WP total instructions",               &g_stats.wp_total_insns },
        { "WP total memory accesses",            &g_stats.wp_total_mem_accesses },
        { "WP early exits (fault)",              &g_stats.wp_early_exits },
        { "Unknown-instruction warnings",        &g_stats.unknown_insn_warnings },
    };
    static const struct { const char *label; const uint64_t *value; } bin_counters[] = {
        { "  Header bits",        &g_stats.bin_header_bits },
        { "  Body bits",          &g_stats.bin_body_bits },
        { "  Dyn CP bits",        &g_stats.bin_dyn_cp_bits },
        { "  Dyn WP bits",        &g_stats.bin_dyn_wp_bits },
        { "  WP exception bits",  &g_stats.bin_wp_exception_bits },
    };

    g_string_append_printf(report,
        "\n=== Wrong-Path Trace Plugin Statistics ===\n"
        "Target architecture: %s\n"
        "Max wrong-path depth: %d instructions\n"
        "TB fragments translated: %u\n"
        "BB templates created: %u\n"
        "Unique branch PCs: %u\n",
        target_name ? target_name : "unknown",
        max_wrong_path_depth,
        (unsigned)g_bb_template_cache.tb_count(),
        (unsigned)g_bb_template_cache.bb_count(),
        (unsigned)g_branch_history.size());

    for (size_t i = 0; i < G_N_ELEMENTS(counters); i++) {
        g_string_append_printf(report, "%-40s %" PRIu64 "\n",
                               counters[i].label, *counters[i].value);
    }

    if (g_stats.wp_simulations > 0) {
        g_string_append_printf(report,
            "Average wrong-path length: %.1f instructions\n",
            (double)g_stats.wp_total_insns / g_stats.wp_simulations);
    }

    if (g_simpoints.is_active()) {
        g_string_append_printf(report,
            "SimPoints loaded/traced: %zu / %zu\n",
            g_simpoints.size(), g_simpoints.current_index());
    }

    if (g_stats.bin_total_bits > 0) {
        g_string_append_printf(report,
            "Total binary bits: %" PRIu64 " (%.2f MiB)\n",
            g_stats.bin_total_bits,
            (double)g_stats.bin_total_bits / 8.0 / (1024.0 * 1024.0));
        for (size_t i = 0; i < G_N_ELEMENTS(bin_counters); i++) {
            g_string_append_printf(report,
                "%-40s %" PRIu64 " (%.2f%%)\n",
                bin_counters[i].label, *bin_counters[i].value,
                100.0 * (double)(*bin_counters[i].value) / g_stats.bin_total_bits);
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
    if (reg_read_buf) {
        g_byte_array_unref(reg_read_buf);
        reg_read_buf = NULL;
    }
    g_free(wide_reg_scratch.entries);
    wide_reg_scratch.entries = NULL;
    wide_reg_scratch_cap = 0;
    if (cp_chain_fragments) {
        g_array_unref(cp_chain_fragments);
    }

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

    /*
     * Map ISA to Capstone arch/mode for qemu_plugin_cap_decode().  The
     * arch is fully determined by target_name and is set here.  The
     * mode resolver may need to introspect the guest binary (for
     * example to read .riscv.attributes or MIPS EF_* flags) which in
     * turn calls qemu_plugin_path_to_binary() — that helper requires
     * a live vCPU context, so the actual cap_mode_for_target() call is
     * deferred to the first vcpu_init_cb (see vcpu_init_cb).
     */
    if (trace_isa != TRACE_ISA_UNKNOWN) {
        const IsaProperties *p = &isa_properties[trace_isa];
        cst_cap_arch = p->cap_arch;
        cst_cap_mode = 0;  /* deferred — resolved in vcpu_init_cb */
    } else {
        cst_cap_arch = -1;
        cst_cap_mode = 0;
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
            {"outpipe", OPT_OUTPIPE},
            {"wp",      OPT_WP},
            {"start",   OPT_START},   {"stop",    OPT_STOP},
            {"program", OPT_PROGRAM}, {"spfile",  OPT_SPFILE},
            {"spinterval", OPT_SPINTERVAL},
            {"comment", OPT_COMMENT}, {"memdata", OPT_MEMDATA},
            {"regdata", OPT_REGDATA},
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
        case OPT_OUTPIPE:
            output_pipe_command = g_strdup(tokens[1]);
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
        case OPT_REGDATA:
            enable_reg_data = (atoi(tokens[1]) != 0);
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
        if (!g_simpoints.load(simpoints_file_path, simpoint_interval_insns)) {
            fprintf(stderr, "champsim_tracer: no valid simpoints in: %s\n",
                    simpoints_file_path);
            g_free(simpoints_file_path);
            return -1;
        }
        fprintf(stderr, "champsim_tracer: loaded %zu simpoints from %s\n",
                g_simpoints.size(), simpoints_file_path);
        trace_start_insn = 0;
        trace_stop_insn = UINT64_MAX;
    }

    g_mutex_init(&data_lock);
    g_mutex_init(&exec_lock);
    g_mutex_init(&unknown_warn_lock);
    cp_chain_fragments = g_array_new(false, false, sizeof(BBTemplate *));

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

    if (!g_simpoints.is_active() && trace_start_insn == 0) {
        start_trace_segment("trace", 0, trace_stop_insn);
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_flush_cb(id, vcpu_tb_flush);
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
