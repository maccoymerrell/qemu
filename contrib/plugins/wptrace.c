/*
 * Wrong-Path Tracing Plugin for QEMU
 *
 * This plugin simulates speculative wrong-path execution at branch points
 * during correct-path execution. At each branch, it determines the "wrong"
 * direction and executes the wrong-path by reading instruction bytes from
 * guest memory and capturing CPU register state, producing traces with
 * realistic instruction data and address-computation context.
 *
 * Unlike a simple cached-block replay approach, this plugin:
 *   - Reads actual instruction bytes from guest memory at wrong-path
 *     addresses, enabling discovery of code never executed on the correct
 *     path.
 *   - Captures a full CPU register snapshot at each branch point, providing
 *     the dynamic state needed to compute data addresses that wrong-path
 *     load/store instructions would access.
 *   - Tracks per-instruction memory access addresses on the correct path,
 *     associating last-known data addresses with instruction PCs for
 *     wrong-path context.
 *   - After simulation, the CPU state is implicitly "rolled back" since
 *     the real CPU state is never modified (simulation is software-based).
 *
 * Branch predictions on the wrong path are made using an "infinite" Smith
 * predictor: a hash map from PC to a 2-bit saturating counter that tracks
 * which way correct-path branches go. The counter saturates at 0 and 3,
 * and the prediction is "taken" if the counter >= 2.
 *
 * The implementation is ISA-agnostic: it learns block boundaries and branch
 * targets from QEMU's translation and execution events, requiring no
 * instruction decoding. This means it works with any target architecture
 * (x86, ARM, RISC-V, etc.) without modification.
 *
 * Usage:
 *   -plugin wptrace[,depth=N][,tracefile=PATH]
 *
 *   depth:     Maximum wrong-path depth in basic blocks (default: 64)
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

/* Maximum bytes to read for unknown (uncached) wrong-path blocks */
#define WP_UNKNOWN_BLOCK_READ_SIZE 64

/* ========================= Data Structures ========================= */

/*
 * Record of a translated basic block. Populated during translation
 * and used during wrong-path simulation to walk speculative paths.
 */
typedef struct {
    uint64_t start_pc;          /* Block start address */
    uint32_t n_insns;           /* Number of instructions */
    uint64_t *insn_pcs;         /* Array of instruction PCs */
    uint32_t *insn_sizes;       /* Array of instruction sizes */
    uint8_t **insn_data;        /* Raw instruction bytes per insn */
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
 * Snapshot of CPU register state at a branch point.
 * Captures the dynamic state needed to compute addresses that
 * wrong-path instructions would access.
 */
typedef struct {
    GByteArray **values;        /* Array of register value buffers */
    int n_regs;                 /* Number of registers captured */
} RegSnapshot;

/*
 * Record of the most recent memory access at an instruction PC.
 * Updated on the correct path via per-instruction memory callbacks,
 * used as address context during wrong-path simulation.
 */
typedef struct {
    uint64_t vaddr;             /* Last observed memory access vaddr */
    bool is_store;              /* Whether the access was a store */
} MemAddrEntry;

/* ========================= Global State ========================= */

static GMutex data_lock;
static GHashTable *block_map;       /* start_pc (uint64_t*) → BlockRecord* */
static GHashTable *branch_map;      /* branch_pc (uint64_t*) → BranchRecord* */
static GHashTable *mem_addr_map;    /* insn_pc (uint64_t*) → MemAddrEntry* */

static struct qemu_plugin_scoreboard *vcpu_sb;
static qemu_plugin_u64 sb_current_pc;
static qemu_plugin_u64 sb_prev_last_pc;
static qemu_plugin_u64 sb_prev_fall_through;

/* Register descriptor cache (populated in vcpu_init) */
static GArray *cached_reg_list;
static bool regs_available;

/* Statistics */
static uint64_t stat_blocks_translated;
static uint64_t stat_branches_observed;
static uint64_t stat_branches_taken;
static uint64_t stat_branches_not_taken;
static uint64_t stat_wp_simulations;
static uint64_t stat_wp_skipped;       /* wrong target unknown */
static uint64_t stat_wp_total_insns;
static uint64_t stat_wp_total_blocks;
static uint64_t stat_wp_early_exits;   /* sim ended at unknown block */
static uint64_t stat_wp_mem_fetches;   /* insn bytes read from memory */
static uint64_t stat_wp_mem_fetch_fails; /* failed memory reads */
static uint64_t stat_wp_unknown_blocks;  /* uncached blocks encountered */

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
 * Prediction: taken if counter >= 2, not-taken otherwise.
 */

static inline bool smith_predict_taken(uint8_t counter)
{
    return counter >= 2;
}

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
    if (block->insn_data) {
        for (uint32_t i = 0; i < block->n_insns; i++) {
            g_free(block->insn_data[i]);
        }
        g_free(block->insn_data);
    }
    g_free(block->insn_pcs);
    g_free(block->insn_sizes);
    g_free(block);
}

/* ========================= Register Snapshot ========================= */

/*
 * Capture a snapshot of all CPU registers.
 * Must be called from a vCPU callback registered with QEMU_PLUGIN_CB_R_REGS.
 * Returns NULL if register tracking is not available.
 */
static RegSnapshot *take_reg_snapshot(void)
{
    if (!regs_available || !cached_reg_list || cached_reg_list->len == 0) {
        return NULL;
    }

    int n = cached_reg_list->len;
    RegSnapshot *snap = g_new0(RegSnapshot, 1);
    snap->n_regs = n;
    snap->values = g_new0(GByteArray *, n);

    for (int i = 0; i < n; i++) {
        qemu_plugin_reg_descriptor *rd = &g_array_index(
            cached_reg_list, qemu_plugin_reg_descriptor, i);
        snap->values[i] = g_byte_array_new();
        qemu_plugin_read_register(rd->handle, snap->values[i]);
    }

    return snap;
}

static void free_reg_snapshot(RegSnapshot *snap)
{
    if (!snap) {
        return;
    }
    for (int i = 0; i < snap->n_regs; i++) {
        if (snap->values[i]) {
            g_byte_array_unref(snap->values[i]);
        }
    }
    g_free(snap->values);
    g_free(snap);
}

/*
 * Write register snapshot to the trace file.
 * Outputs register names and values in hex for address computation context.
 */
static void write_reg_snapshot(FILE *f, RegSnapshot *snap)
{
    if (!snap || !f || !cached_reg_list) {
        return;
    }
    fprintf(f, "  REGS:");
    for (int i = 0; i < snap->n_regs; i++) {
        qemu_plugin_reg_descriptor *rd = &g_array_index(
            cached_reg_list, qemu_plugin_reg_descriptor, i);
        if (snap->values[i] && snap->values[i]->len > 0) {
            fprintf(f, " %s=0x", rd->name);
            for (int j = snap->values[i]->len - 1; j >= 0; j--) {
                fprintf(f, "%02x", snap->values[i]->data[j]);
            }
        }
    }
    fprintf(f, "\n");
}

/* ========================= Memory Access Tracking ========================= */

/*
 * Per-instruction memory access callback.
 * Records the most recent memory address accessed by each instruction PC
 * on the correct path. This data is used during wrong-path simulation to
 * provide address context for instructions that were previously executed.
 *
 * The instruction PC is passed via udata as a cast integer.
 */
static void vcpu_mem_cb(unsigned int cpu_index,
                        qemu_plugin_meminfo_t info,
                        uint64_t vaddr,
                        void *udata)
{
    uint64_t insn_pc = (uint64_t)(uintptr_t)udata;

    g_mutex_lock(&data_lock);

    MemAddrEntry *entry = g_hash_table_lookup(mem_addr_map, &insn_pc);
    if (!entry) {
        entry = g_new0(MemAddrEntry, 1);
        uint64_t *key = g_new(uint64_t, 1);
        *key = insn_pc;
        g_hash_table_insert(mem_addr_map, key, entry);
    }
    entry->vaddr = vaddr;
    entry->is_store = qemu_plugin_mem_is_store(info);

    g_mutex_unlock(&data_lock);
}

/* ========================= vCPU Init Callback ========================= */

/*
 * Called when a vCPU is initialized.
 * Enumerates available registers for state capture during wrong-path
 * simulation.
 */
static void vcpu_init_cb(qemu_plugin_id_t id, unsigned int cpu_index)
{
    if (!cached_reg_list) {
        cached_reg_list = qemu_plugin_get_registers();
        if (cached_reg_list && cached_reg_list->len > 0) {
            regs_available = true;
        }
    }
}

/* ========================= Wrong-Path Simulation ========================= */

/*
 * Simulate wrong-path execution starting from @wrong_target.
 *
 * Instead of simply replaying cached basic blocks, this function reads
 * actual instruction bytes from guest memory at wrong-path addresses and
 * uses the register snapshot captured at the branch point to provide
 * address-computation context. This produces traces with realistic
 * instruction data and memory address information.
 *
 * For blocks in the block_map, the cached structure provides instruction
 * boundaries while live memory reads provide current instruction bytes.
 * For unknown blocks (never translated on the correct path), raw bytes
 * are read directly from guest memory, enabling discovery of code that
 * exists only on wrong-path execution.
 *
 * The register snapshot (@reg_snap) represents the CPU state at the
 * branch point, enabling downstream tools to compute the actual data
 * addresses that wrong-path load/store instructions would access.
 *
 * Must be called with data_lock held.
 */
static void simulate_wrong_path(uint64_t branch_pc,
                                uint64_t correct_target,
                                uint64_t wrong_target,
                                unsigned int cpu_index,
                                RegSnapshot *reg_snap)
{
    uint64_t current_pc = wrong_target;
    uint64_t sim_insns = 0;
    uint64_t sim_blocks = 0;
    bool early_exit = false;
    GByteArray *mem_buf = g_byte_array_new();

    /* Write simulation header with register state at branch point */
    if (trace_file) {
        fprintf(trace_file,
                "WP_BEGIN: cpu=%u branch_pc=0x%" PRIx64
                " correct=0x%" PRIx64 " wrong=0x%" PRIx64 "\n",
                cpu_index, branch_pc, correct_target, wrong_target);
        write_reg_snapshot(trace_file, reg_snap);
    }

    for (int depth = 0; depth < max_wrong_path_depth; depth++) {
        BlockRecord *block = g_hash_table_lookup(block_map, &current_pc);

        if (block) {
            /*
             * Known block: use cached structure for instruction boundaries.
             * Read live instruction bytes from guest memory to capture the
             * actual code at these addresses (may differ from translation
             * time for self-modifying code).
             */
            sim_blocks++;

            for (uint32_t i = 0; i < block->n_insns; i++) {
                sim_insns++;

                /* Read instruction bytes from guest memory */
                g_byte_array_set_size(mem_buf, 0);
                bool mem_ok = qemu_plugin_read_memory_vaddr(
                    block->insn_pcs[i], mem_buf, block->insn_sizes[i]);

                if (mem_ok) {
                    stat_wp_mem_fetches++;
                } else {
                    stat_wp_mem_fetch_fails++;
                }

                /* Look up last-known memory address for this insn PC */
                MemAddrEntry *maddr = NULL;
                if (mem_addr_map) {
                    maddr = g_hash_table_lookup(mem_addr_map,
                                                &block->insn_pcs[i]);
                }

                if (trace_file) {
                    fprintf(trace_file,
                            "WP: cpu=%u branch_pc=0x%" PRIx64
                            " correct=0x%" PRIx64
                            " depth=%d pc=0x%" PRIx64
                            " size=%u",
                            cpu_index, branch_pc, correct_target,
                            depth, block->insn_pcs[i],
                            block->insn_sizes[i]);

                    /* Include live instruction bytes from memory */
                    if (mem_ok && mem_buf->len > 0) {
                        fprintf(trace_file, " bytes=");
                        for (uint32_t b = 0; b < mem_buf->len; b++) {
                            fprintf(trace_file, "%02x", mem_buf->data[b]);
                        }
                    }

                    /* Include memory address context if available */
                    if (maddr) {
                        fprintf(trace_file, " mem_addr=0x%" PRIx64
                                " mem_%s",
                                maddr->vaddr,
                                maddr->is_store ? "store" : "load");
                    }

                    fprintf(trace_file, "\n");
                }
            }

            /* Determine next block using Smith predictor */
            uint64_t end_pc = block->insn_pcs[block->n_insns - 1];
            BranchRecord *br = g_hash_table_lookup(branch_map, &end_pc);

            if (!br) {
                current_pc = block->fall_through_pc;
                continue;
            }

            if (smith_predict_taken(br->smith_counter)) {
                if (br->has_taken_target) {
                    current_pc = br->taken_target;
                } else {
                    early_exit = true;
                    break;
                }
            } else {
                current_pc = br->fall_through;
            }
        } else {
            /*
             * Unknown block: not in translation cache.
             * Read raw instruction bytes directly from guest memory.
             * This is a fundamental improvement over the cached-only
             * approach: we can discover and trace code on the wrong path
             * that was never executed on the correct path.
             */
            stat_wp_unknown_blocks++;
            sim_blocks++;

            g_byte_array_set_size(mem_buf, 0);
            bool raw_ok = qemu_plugin_read_memory_vaddr(
                current_pc, mem_buf, WP_UNKNOWN_BLOCK_READ_SIZE);

            if (!raw_ok) {
                /* Memory at wrong-path address is unmapped */
                stat_wp_mem_fetch_fails++;
                early_exit = true;
                if (trace_file) {
                    fprintf(trace_file,
                            "WP_UNMAPPED: cpu=%u branch_pc=0x%" PRIx64
                            " depth=%d pc=0x%" PRIx64 "\n",
                            cpu_index, branch_pc, depth, current_pc);
                }
                break;
            }

            stat_wp_mem_fetches++;
            sim_insns++;

            if (trace_file) {
                fprintf(trace_file,
                        "WP_RAW: cpu=%u branch_pc=0x%" PRIx64
                        " depth=%d pc=0x%" PRIx64 " raw_size=%u bytes=",
                        cpu_index, branch_pc, depth,
                        current_pc, mem_buf->len);
                for (uint32_t b = 0; b < mem_buf->len; b++) {
                    fprintf(trace_file, "%02x", mem_buf->data[b]);
                }
                fprintf(trace_file, "\n");
            }

            /*
             * Without ISA-specific instruction decoding, we cannot
             * determine instruction boundaries or branch targets in
             * unknown blocks. Exit simulation at this point.
             * A future enhancement could add per-ISA decoders to
             * continue walking through unknown code.
             */
            early_exit = true;
            break;
        }
    }

    if (trace_file) {
        fprintf(trace_file,
                "WP_END: cpu=%u branch_pc=0x%" PRIx64
                " blocks=%" PRIu64 " insns=%" PRIu64
                " early_exit=%d\n",
                cpu_index, branch_pc, sim_blocks, sim_insns, early_exit);
    }

    g_byte_array_unref(mem_buf);

    /* Update statistics */
    stat_wp_simulations++;
    stat_wp_total_insns += sim_insns;
    stat_wp_total_blocks += sim_blocks;
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
 * taken or not-taken, then trigger wrong-path simulation.
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

    branch_taken = (current_pc != prev_ft);

    /*
     * Capture register state at the branch point BEFORE acquiring the
     * data lock. This snapshot represents the CPU state that determines
     * what addresses wrong-path instructions would access.
     */
    RegSnapshot *reg_snap = take_reg_snapshot();

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
        /*
         * Key points into the value struct; safe because we only insert
         * new entries (never duplicates) and use g_hash_table_replace.
         */
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

    /* Run wrong-path simulation if we know where the wrong path starts */
    if (wrong_target != 0) {
        simulate_wrong_path(prev_last, current_pc, wrong_target,
                            cpu_index, reg_snap);
    } else {
        stat_wp_skipped++;
    }

    g_mutex_unlock(&data_lock);

    free_reg_snapshot(reg_snap);
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

    /* Build block record with instruction data */
    BlockRecord *block = g_new0(BlockRecord, 1);
    block->start_pc = pc;
    block->n_insns = (uint32_t)n_insns;
    block->insn_pcs = g_new0(uint64_t, n_insns);
    block->insn_sizes = g_new0(uint32_t, n_insns);
    block->insn_data = g_new0(uint8_t *, n_insns);
    block->fall_through_pc = fall_through;

    for (size_t i = 0; i < n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t insn_pc = qemu_plugin_insn_vaddr(insn);
        uint32_t insn_size = (uint32_t)qemu_plugin_insn_size(insn);

        block->insn_pcs[i] = insn_pc;
        block->insn_sizes[i] = insn_size;

        /* Cache raw instruction bytes for wrong-path reference */
        block->insn_data[i] = g_new(uint8_t, insn_size);
        qemu_plugin_insn_data(insn, block->insn_data[i], insn_size);

        /*
         * Register per-instruction memory callback to track data addresses.
         * The instruction PC is passed as userdata for the address mapping.
         * Only enabled when tracefile is specified to avoid overhead in
         * summary-only mode.
         */
        if (trace_file) {
            qemu_plugin_register_vcpu_mem_cb(
                insn, vcpu_mem_cb, QEMU_PLUGIN_CB_NO_REGS,
                QEMU_PLUGIN_MEM_RW, (void *)(uintptr_t)insn_pc);
        }
    }

    /*
     * Insert into block map (replaces on retranslation).
     * Key points into the value struct; g_hash_table_replace stores the
     * new key before freeing the old value, so this is safe.
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
     * Uses QEMU_PLUGIN_CB_R_REGS so registers are available for
     * state capture at branch points during wrong-path simulation.
     */
    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, vcpu_tb_exec, QEMU_PLUGIN_CB_R_REGS, NULL);

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
        "\nWrong-path simulation:\n");
    g_string_append_printf(report,
        "  Simulations performed: %" PRIu64 "\n", stat_wp_simulations);
    g_string_append_printf(report,
        "  Simulations skipped (unknown target): %" PRIu64 "\n",
        stat_wp_skipped);
    g_string_append_printf(report,
        "  Total wrong-path instructions traced: %" PRIu64 "\n",
        stat_wp_total_insns);
    g_string_append_printf(report,
        "  Total wrong-path blocks traversed: %" PRIu64 "\n",
        stat_wp_total_blocks);
    g_string_append_printf(report,
        "  Early exits (unknown block on path): %" PRIu64 "\n",
        stat_wp_early_exits);
    g_string_append_printf(report,
        "  Instruction bytes fetched from memory: %" PRIu64 "\n",
        stat_wp_mem_fetches);
    g_string_append_printf(report,
        "  Memory fetch failures: %" PRIu64 "\n",
        stat_wp_mem_fetch_fails);
    g_string_append_printf(report,
        "  Unknown (uncached) blocks encountered: %" PRIu64 "\n",
        stat_wp_unknown_blocks);

    if (stat_wp_simulations > 0) {
        g_string_append_printf(report,
            "  Average wrong-path depth: %.1f blocks\n",
            (double)stat_wp_total_blocks / stat_wp_simulations);
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
    mem_addr_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                         g_free, g_free);

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
