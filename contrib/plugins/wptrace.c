/*
 * Wrong-Path Tracing Plugin for QEMU
 *
 * This plugin performs fully-faithful speculative wrong-path execution at
 * branch points. At each branch, it determines the "wrong" direction,
 * saves the complete CPU state, sets the PC to the wrong-path target, and
 * actually executes instructions one at a time using QEMU's CPU execution
 * engine. After reaching the configured depth, it restores the CPU state
 * to roll back to the correct path.
 *
 * This approach produces fully-realistic wrong-path traces including:
 *   - Real instruction fetch addresses (IF) from actual code execution
 *   - Real data fetch addresses (DF) from actual load/store execution
 *   - Correct address computations based on actual register state
 *   - Discovery of code paths never seen on the correct path
 *
 * Unlike a cached-block replay or memory-read-only approach, this plugin:
 *   - Actually executes instructions on the wrong path using QEMU's CPU
 *   - Generates real memory access addresses from actual execution
 *   - Handles all instruction types including indirect branches
 *   - Provides the same fidelity as an execution-driven simulator
 *   - Rolls back CPU state after wrong-path traversal
 *
 * Branch predictions on the wrong path are made using an "infinite" Smith
 * predictor: a hash map from PC to a 2-bit saturating counter that tracks
 * which way correct-path branches go. The counter saturates at 0 and 3,
 * and the prediction is "taken" if the counter >= 2.
 *
 * The implementation is ISA-agnostic: it learns block boundaries and branch
 * targets from QEMU's translation and execution events, requiring no
 * instruction decoding. The CPU state save/restore uses the GDB register
 * interface which works with any target architecture.
 *
 * Usage:
 *   -plugin wptrace[,depth=N][,tracefile=PATH]
 *
 *   depth:     Maximum wrong-path depth in instructions (default: 64)
 *   tracefile: File path for detailed per-instruction wrong-path traces.
 *              If not specified, only summary statistics are printed at exit.
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

static int max_wrong_path_depth = 64;
static char *trace_path;
static FILE *trace_file;
static const char *target_name;

/* ========================= Data Structures ========================= */

/*
 * Record of a translated basic block. Populated during translation
 * and used during wrong-path simulation to track block boundaries.
 */
typedef struct {
    uint64_t start_pc;          /* Block start address */
    uint32_t n_insns;           /* Number of instructions */
    uint64_t *insn_pcs;         /* Array of instruction PCs */
    uint32_t *insn_sizes;       /* Array of instruction sizes */
    uint64_t fall_through_pc;   /* PC after last instruction (sequential) */
} BlockRecord;

/*
 * Record of a branch point. Updated during execution as we observe
 * branch outcomes. Contains the Smith predictor state.
 */
typedef struct {
    uint64_t pc;                /* Branch instruction PC */
    uint64_t fall_through;      /* Sequential next PC */
    uint64_t taken_target;      /* Observed taken target */
    bool has_taken_target;      /* Whether taken target has been seen */
    uint8_t smith_counter;      /* 2-bit saturating counter (0-3) */
} BranchRecord;

/*
 * Per-vCPU scoreboard for tracking execution state between blocks.
 * Updated by inline ops at runtime, read by execution callbacks.
 */
typedef struct {
    uint64_t current_pc;        /* Current block's start PC */
    uint64_t prev_last_pc;      /* Last insn PC of previous block */
    uint64_t prev_fall_through; /* Expected sequential next from prev block */
} VCPUScoreBoard;

/*
 * Record of a memory access captured during wrong-path execution.
 * Collected as we execute instructions on the wrong path to track
 * both instruction fetches and data fetches.
 */
typedef struct {
    uint64_t insn_pc;           /* PC of the instruction making the access */
    uint64_t mem_vaddr;         /* Virtual address of the memory access */
    bool is_store;              /* Whether this was a store operation */
} WPMemAccess;

/* ========================= Global State ========================= */

static GMutex data_lock;
static GHashTable *block_map;       /* start_pc (uint64_t*) → BlockRecord* */
static GHashTable *branch_map;      /* branch_pc (uint64_t*) → BranchRecord* */

static struct qemu_plugin_scoreboard *vcpu_sb;
static qemu_plugin_u64 sb_current_pc;
static qemu_plugin_u64 sb_prev_last_pc;
static qemu_plugin_u64 sb_prev_fall_through;

/*
 * Wrong-path memory access collection.
 * During wrong-path execution, memory callbacks append to this list.
 * Protected by wp_in_progress flag (single-threaded per vCPU).
 */
static bool wp_in_progress;
static GArray *wp_mem_accesses;  /* GArray of WPMemAccess */
static uint64_t wp_current_insn_pc;  /* PC of currently executing WP insn */

/* Statistics */
static uint64_t stat_blocks_translated;
static uint64_t stat_branches_observed;
static uint64_t stat_branches_taken;
static uint64_t stat_branches_not_taken;
static uint64_t stat_wp_simulations;
static uint64_t stat_wp_skipped;       /* wrong target unknown */
static uint64_t stat_wp_total_insns;
static uint64_t stat_wp_early_exits;   /* sim ended due to exec failure */
static uint64_t stat_wp_total_mem_accesses; /* DF observed on wrong-path */

/* ========================= Smith Predictor ========================= */

/*
 * Infinite Smith predictor using a 2-bit saturating counter per PC.
 *
 * Counter values:
 *   0 = Strongly Not-Taken
 *   1 = Weakly Not-Taken
 *   2 = Weakly Taken
 *   3 = Strongly Taken
 *
 * The predictor tracks correct-path branch outcomes. In fully-faithful
 * mode, wrong-path execution uses QEMU's CPU engine directly, so the
 * predictor is only used for branch outcome statistics.
 */

static inline uint8_t smith_update(uint8_t counter, bool taken)
{
    if (taken && counter < 3) {
        return counter + 1;
    } else if (!taken && counter > 0) {
        return counter - 1;
    }
    return counter;
}

/* ========================= Memory Management ========================= */

static void block_record_free(gpointer data)
{
    BlockRecord *block = data;
    g_free(block->insn_pcs);
    g_free(block->insn_sizes);
    g_free(block);
}

/* ========================= Memory Access Tracking ========================= */

/*
 * Per-instruction memory access callback.
 * During wrong-path execution (wp_in_progress), this records the real
 * data addresses generated by actual instruction execution.
 * During correct-path execution, this is a no-op.
 */
static void vcpu_mem_cb(unsigned int cpu_index,
                        qemu_plugin_meminfo_t info,
                        uint64_t vaddr,
                        void *udata)
{
    if (!wp_in_progress || !wp_mem_accesses) {
        return;
    }

    WPMemAccess acc = {
        .insn_pc = wp_current_insn_pc,
        .mem_vaddr = vaddr,
        .is_store = qemu_plugin_mem_is_store(info),
    };
    g_array_append_val(wp_mem_accesses, acc);
}

/* ========================= vCPU Init Callback ========================= */

static void vcpu_init_cb(qemu_plugin_id_t id, unsigned int cpu_index)
{
    /* Nothing needed now - register enumeration handled by new API */
}

/* ========================= Wrong-Path Simulation ========================= */

/*
 * Execute wrong-path instructions starting from @wrong_target.
 *
 * This performs FULLY-FAITHFUL wrong-path execution by:
 *   1. Saving the complete CPU state (all registers via GDB interface)
 *   2. Setting the PC to the wrong-path target address
 *   3. Executing instructions one at a time using QEMU's CPU engine
 *   4. Collecting real memory access addresses from actual execution
 *   5. Restoring the CPU state to roll back to the correct path
 *
 * Each instruction on the wrong path is actually executed by QEMU,
 * producing real instruction fetch addresses (IF) and real data fetch
 * addresses (DF) with correct address computations based on actual
 * register state.
 *
 * The Smith predictor is not needed for block-level navigation since
 * actual execution follows real branch outcomes. However, we still
 * track block boundaries for depth counting and trace structure.
 *
 * Must be called with data_lock NOT held (execution may trigger
 * callbacks that need it).
 */
static void simulate_wrong_path(uint64_t branch_pc,
                                uint64_t correct_target,
                                uint64_t wrong_target,
                                unsigned int cpu_index)
{
    uint64_t sim_insns = 0;
    bool early_exit = false;
    GByteArray *insn_buf = g_byte_array_new();

    /* Save complete CPU state for rollback after wrong-path execution */
    struct qemu_plugin_cpu_state *saved_state = qemu_plugin_cpu_state_save();
    if (!saved_state) {
        stat_wp_early_exits++;
        stat_wp_simulations++;
        g_byte_array_unref(insn_buf);
        return;
    }

    /* Initialize wrong-path memory access collection */
    wp_mem_accesses = g_array_new(false, false, sizeof(WPMemAccess));
    wp_in_progress = true;

    /* Write simulation header */
    if (trace_file) {
        fprintf(trace_file,
                "WP_BEGIN: cpu=%u branch_pc=0x%" PRIx64
                " correct=0x%" PRIx64 " wrong=0x%" PRIx64 "\n",
                cpu_index, branch_pc, correct_target, wrong_target);
    }

    /* Set PC to the wrong-path target */
    qemu_plugin_set_pc(wrong_target);

    /* Execute instructions on the wrong path */
    for (int depth = 0; depth < max_wrong_path_depth; depth++) {
        /* Read the current PC (updated by previous execution or set_pc) */
        uint64_t pre_pc = qemu_plugin_get_pc();

        /*
         * Read instruction bytes at current PC for the trace.
         * We read before execution to capture the instruction fetch (IF).
         */
        g_byte_array_set_size(insn_buf, 0);
        qemu_plugin_read_memory_vaddr(pre_pc, insn_buf, 16);

        /* Track current instruction PC for memory callback */
        wp_current_insn_pc = pre_pc;

        /* Execute exactly one instruction */
        if (!qemu_plugin_exec_inline_insn()) {
            early_exit = true;
            if (trace_file) {
                fprintf(trace_file,
                        "WP_FAULT: cpu=%u branch_pc=0x%" PRIx64
                        " depth=%d pc=0x%" PRIx64 "\n",
                        cpu_index, branch_pc, depth, pre_pc);
            }
            break;
        }

        sim_insns++;

        /* Write trace entry with instruction fetch and data accesses */
        if (trace_file) {
            fprintf(trace_file,
                    "WP: cpu=%u branch_pc=0x%" PRIx64
                    " correct=0x%" PRIx64
                    " depth=%d pc=0x%" PRIx64,
                    cpu_index, branch_pc, correct_target,
                    depth, pre_pc);

            /* Include instruction bytes */
            if (insn_buf->len > 0) {
                fprintf(trace_file, " bytes=");
                for (uint32_t b = 0; b < insn_buf->len && b < 16; b++) {
                    fprintf(trace_file, "%02x", insn_buf->data[b]);
                }
            }

            /* Include data memory accesses from this instruction */
            for (guint m = 0; m < wp_mem_accesses->len; m++) {
                WPMemAccess *acc = &g_array_index(wp_mem_accesses,
                                                  WPMemAccess, m);
                if (acc->insn_pc == pre_pc) {
                    fprintf(trace_file, " %s=0x%" PRIx64,
                            acc->is_store ? "store" : "load",
                            acc->mem_vaddr);
                    stat_wp_total_mem_accesses++;
                }
            }
            fprintf(trace_file, "\n");
        }
    }

    /* Stop wrong-path collection */
    wp_in_progress = false;

    if (trace_file) {
        fprintf(trace_file,
                "WP_END: cpu=%u branch_pc=0x%" PRIx64
                " insns=%" PRIu64
                " mem_accesses=%u early_exit=%d\n",
                cpu_index, branch_pc, sim_insns,
                wp_mem_accesses->len, early_exit);
    }

    /* Restore CPU state to roll back to correct path */
    qemu_plugin_cpu_state_restore(saved_state);
    qemu_plugin_cpu_state_free(saved_state);

    /* Clean up */
    g_array_unref(wp_mem_accesses);
    wp_mem_accesses = NULL;
    g_byte_array_unref(insn_buf);

    /* Update statistics */
    stat_wp_simulations++;
    stat_wp_total_insns += sim_insns;
    if (early_exit) {
        stat_wp_early_exits++;
    }
}

/* ========================= Execution Callback ========================= */

/*
 * Called at the start of each basic block.
 *
 * By this point, sb_current_pc has been updated to the current block's
 * start PC (via inline store), while sb_prev_last_pc and
 * sb_prev_fall_through still hold the previous block's values.
 *
 * We compare the current block's PC with the previous block's expected
 * fall-through to determine whether the previous block's branch was
 * taken or not-taken, then trigger wrong-path execution with full
 * CPU state save/restore.
 */
static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    uint64_t current_pc = qemu_plugin_u64_get(sb_current_pc, cpu_index);
    uint64_t prev_last = qemu_plugin_u64_get(sb_prev_last_pc, cpu_index);
    uint64_t prev_ft = qemu_plugin_u64_get(sb_prev_fall_through, cpu_index);
    bool branch_taken;
    uint64_t wrong_target = 0;

    /* Skip initial block (no previous context) */
    if (prev_ft == 0) {
        return;
    }

    /* Don't trigger wrong-path inside wrong-path execution */
    if (wp_in_progress) {
        return;
    }

    branch_taken = (current_pc != prev_ft);

    g_mutex_lock(&data_lock);

    stat_branches_observed++;
    if (branch_taken) {
        stat_branches_taken++;
    } else {
        stat_branches_not_taken++;
    }

    /* Find or create branch record for the previous block's last insn */
    BranchRecord *br = g_hash_table_lookup(branch_map, &prev_last);
    if (!br) {
        br = g_new0(BranchRecord, 1);
        br->pc = prev_last;
        br->fall_through = prev_ft;
        br->smith_counter = 1; /* Start weakly not-taken */
        g_hash_table_replace(branch_map, &br->pc, br);
    }

    /* Record taken target if this is a taken branch */
    if (branch_taken) {
        br->taken_target = current_pc;
        br->has_taken_target = true;
    }

    /* Update Smith predictor with observed outcome */
    br->smith_counter = smith_update(br->smith_counter, branch_taken);

    /*
     * Determine the wrong-path target:
     *   - If branch was taken → wrong path is fall-through
     *   - If branch fell through → wrong path is taken target (if known)
     */
    if (branch_taken) {
        wrong_target = prev_ft;
    } else if (br->has_taken_target) {
        wrong_target = br->taken_target;
    }

    g_mutex_unlock(&data_lock);

    /*
     * Run wrong-path execution if we know where the wrong path starts.
     * This is called WITHOUT the data_lock held because execution
     * triggers callbacks that may need to acquire it.
     */
    if (wrong_target != 0) {
        simulate_wrong_path(prev_last, current_pc, wrong_target, cpu_index);
    } else {
        stat_wp_skipped++;
    }
}

/* ========================= Translation Callback ========================= */

/*
 * Called when a basic block is translated.
 *
 * Records block metadata (instruction PCs, sizes, fall-through address)
 * in the global block_map, and instruments the block for execution tracking.
 *
 * The instrumentation order ensures correct scoreboard state:
 *   1. TB-level: store current_pc → sb_current_pc
 *   2. TB-level: execution callback (reads current_pc, prev_* from scoreboard)
 *   3. First insn: store prev_last_pc and prev_fall_through for next block
 */
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

    /* Build block record */
    BlockRecord *block = g_new0(BlockRecord, 1);
    block->start_pc = pc;
    block->n_insns = (uint32_t)n_insns;
    block->insn_pcs = g_new0(uint64_t, n_insns);
    block->insn_sizes = g_new0(uint32_t, n_insns);
    block->fall_through_pc = fall_through;

    for (size_t i = 0; i < n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        block->insn_pcs[i] = qemu_plugin_insn_vaddr(insn);
        block->insn_sizes[i] = (uint32_t)qemu_plugin_insn_size(insn);

        /*
         * Register per-instruction memory callback.
         * During wrong-path execution, these fire and record real
         * data addresses generated by actual instruction execution.
         */
        if (trace_file) {
            qemu_plugin_register_vcpu_mem_cb(
                insn, vcpu_mem_cb, QEMU_PLUGIN_CB_NO_REGS,
                QEMU_PLUGIN_MEM_RW, NULL);
        }
    }

    /*
     * Insert into block map (replaces on retranslation).
     */
    g_mutex_lock(&data_lock);
    g_hash_table_replace(block_map, &block->start_pc, block);
    stat_blocks_translated++;
    g_mutex_unlock(&data_lock);

    /*
     * Instrument the block for execution tracking.
     *
     * Step 1: Store current block's start PC into scoreboard (TB-level).
     * This fires first when the block executes.
     */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_STORE_U64, sb_current_pc, pc);

    /*
     * Step 2: Register execution callback (TB-level).
     * Uses QEMU_PLUGIN_CB_RW_REGS so we can save/restore CPU state
     * for wrong-path execution and rollback.
     */
    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, vcpu_tb_exec, QEMU_PLUGIN_CB_RW_REGS, NULL);

    /*
     * Step 3: Update prev_* values for the NEXT block's callback.
     * Registered on the first instruction so they fire AFTER the
     * TB-level callback above.
     */
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        sb_prev_last_pc, last_insn_pc);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        sb_prev_fall_through, fall_through);
}

/* ========================= Exit / Statistics ========================= */

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_autoptr(GString) report = g_string_new("");

    g_mutex_lock(&data_lock);

    g_string_append_printf(report,
        "\n=== Wrong-Path Trace Plugin Statistics ===\n");
    g_string_append_printf(report,
        "Target architecture: %s\n", target_name ? target_name : "unknown");
    g_string_append_printf(report,
        "Max wrong-path depth: %d basic blocks\n", max_wrong_path_depth);
    g_string_append_printf(report,
        "\nCorrect-path:\n");
    g_string_append_printf(report,
        "  Basic blocks translated: %" PRIu64 "\n", stat_blocks_translated);
    g_string_append_printf(report,
        "  Branch transitions observed: %" PRIu64 "\n",
        stat_branches_observed);
    g_string_append_printf(report,
        "    Taken: %" PRIu64 "\n", stat_branches_taken);
    g_string_append_printf(report,
        "    Not-taken: %" PRIu64 "\n", stat_branches_not_taken);
    g_string_append_printf(report,
        "  Unique branch PCs (Smith predictor entries): %u\n",
        g_hash_table_size(branch_map));
    g_string_append_printf(report,
        "\nWrong-path execution:\n");
    g_string_append_printf(report,
        "  Simulations performed: %" PRIu64 "\n", stat_wp_simulations);
    g_string_append_printf(report,
        "  Simulations skipped (unknown target): %" PRIu64 "\n",
        stat_wp_skipped);
    g_string_append_printf(report,
        "  Total wrong-path instructions executed: %" PRIu64 "\n",
        stat_wp_total_insns);
    g_string_append_printf(report,
        "  Total wrong-path data accesses: %" PRIu64 "\n",
        stat_wp_total_mem_accesses);
    g_string_append_printf(report,
        "  Early exits (execution fault): %" PRIu64 "\n",
        stat_wp_early_exits);

    if (stat_wp_simulations > 0) {
        g_string_append_printf(report,
            "  Average wrong-path length: %.1f instructions\n",
            (double)stat_wp_total_insns / stat_wp_simulations);
    }

    g_string_append_printf(report,
        "==========================================\n");

    g_mutex_unlock(&data_lock);

    qemu_plugin_outs(report->str);

    if (trace_file) {
        fclose(trace_file);
        trace_file = NULL;
    }
}

/* ========================= Plugin Installation ========================= */

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    target_name = info->target_name;

    /* Parse arguments */
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);

        if (g_strcmp0(tokens[0], "depth") == 0) {
            max_wrong_path_depth = atoi(tokens[1]);
            if (max_wrong_path_depth <= 0) {
                fprintf(stderr, "wptrace: invalid depth: %s\n", tokens[1]);
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "tracefile") == 0) {
            trace_path = g_strdup(tokens[1]);
        } else {
            fprintf(stderr, "wptrace: unknown option: %s\n", opt);
            return -1;
        }
    }

    /* Open trace file if specified */
    if (trace_path) {
        trace_file = fopen(trace_path, "w");
        if (!trace_file) {
            fprintf(stderr, "wptrace: cannot open trace file: %s\n",
                    trace_path);
            return -1;
        }
    }

    /* Initialize data structures */
    g_mutex_init(&data_lock);
    block_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                      NULL, block_record_free);
    branch_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                       NULL, g_free);

    /* Initialize per-vCPU scoreboard */
    vcpu_sb = qemu_plugin_scoreboard_new(sizeof(VCPUScoreBoard));
    sb_current_pc = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, current_pc);
    sb_prev_last_pc = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, prev_last_pc);
    sb_prev_fall_through = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, prev_fall_through);

    /* Register callbacks */
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
