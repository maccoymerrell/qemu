/*
 * Wrong-Path Tracing Plugin — wrong-path simulator.
 *
 * Runs speculative basic blocks starting from a mispredicted branch
 * target, records their memory accesses and any faults, and rolls
 * back CPU state when done.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>

#include "champsim_tracer.h"

static bool wp_target_is_poisoned(const GArray *poisoned_targets, uint64_t pc)
{
    for (guint i = 0; i < poisoned_targets->len; i++) {
        uint64_t poisoned_pc = g_array_index(poisoned_targets, uint64_t, i);
        if (poisoned_pc == pc) {
            return true;
        }
    }
    return false;
}

static void wp_array_reserve(GArray *arr, guint *cap, guint need)
{
    if (need <= *cap) {
        return;
    }
    guint old_len = arr->len;
    guint new_cap = *cap ? *cap : 16;
    while (new_cap < need) {
        new_cap *= 2;
    }
    g_array_set_size(arr, new_cap);
    arr->len = old_len;
    *cap = new_cap;
}

static void wp_byte_array_reserve(GByteArray *arr, guint *cap, guint need)
{
    if (need <= *cap) {
        return;
    }
    guint old_len = arr->len;
    guint new_cap = *cap ? *cap : 16;
    while (new_cap < need) {
        new_cap *= 2;
    }
    g_byte_array_set_size(arr, new_cap);
    arr->len = old_len;
    *cap = new_cap;
}

static inline void wp_array_reset(GArray *arr)
{
    arr->len = 0;
}

static inline void wp_byte_array_reset(GByteArray *arr)
{
    arr->len = 0;
}

static inline void wp_u64_append(GArray *arr, guint *cap, uint64_t value)
{
    guint pos = arr->len;
    wp_array_reserve(arr, cap, pos + 1);
    ((uint64_t *)arr->data)[pos] = value;
    arr->len = pos + 1;
}

static inline void wp_u8_append(GArray *arr, guint *cap, uint8_t value)
{
    guint pos = arr->len;
    wp_array_reserve(arr, cap, pos + 1);
    ((uint8_t *)arr->data)[pos] = value;
    arr->len = pos + 1;
}

static inline void wp_bytes_append(GByteArray *arr, guint *cap,
                                   const uint8_t *data, guint len)
{
    guint pos = arr->len;
    wp_byte_array_reserve(arr, cap, pos + len);
    memcpy(arr->data + pos, data, len);
    arr->len = pos + len;
}

static inline void wp_fields_append(GArray *arr, guint *cap,
                                    const InsnFields *value)
{
    guint pos = arr->len;
    wp_array_reserve(arr, cap, pos + 1);
    ((InsnFields *)arr->data)[pos] = *value;
    arr->len = pos + 1;
}

static inline void wp_regnames_append(GArray *arr, guint *cap,
                                      const InsnRegNames *value)
{
    guint pos = arr->len;
    wp_array_reserve(arr, cap, pos + 1);
    ((InsnRegNames *)arr->data)[pos] = *value;
    arr->len = pos + 1;
}

static inline void wp_dyn_param_append(GArray *arr, guint *cap,
                                       const DynParam *value)
{
    guint pos = arr->len;
    wp_array_reserve(arr, cap, pos + 1);
    ((DynParam *)arr->data)[pos] = *value;
    arr->len = pos + 1;
}

static inline void wp_entry_append(GArray *arr, guint *cap,
                                   const WPBBEntry *value)
{
    guint pos = arr->len;
    wp_array_reserve(arr, cap, pos + 1);
    ((WPBBEntry *)arr->data)[pos] = *value;
    arr->len = pos + 1;
}

static GArray *wp_dyn_params_clone(const GArray *src)
{
    guint len = src ? src->len : 0;
    if (len == 0) {
        return NULL;
    }
    GArray *dst = g_array_sized_new(false, false, sizeof(DynParam), len);
    g_array_set_size(dst, len);
    memcpy(dst->data, src->data, (size_t)len * sizeof(DynParam));
    return dst;
}

static void wp_poison_target(GArray *poisoned_targets, guint *cap,
                             uint64_t pc)
{
    if (!wp_target_is_poisoned(poisoned_targets, pc)) {
        wp_u64_append(poisoned_targets, cap, pc);
    }
}

/*
 * Execute wrong-path basic blocks starting from @wrong_target.
 *
 * Flow per iteration:
 *   1. Execute one full TB at current PC via qemu_plugin_exec_tb().
 *      This triggers vcpu_tb_trans (template creation) and vcpu_mem_cb
 *      (memory access recording), but NOT vcpu_tb_exec or inline stores.
 *   2. Look up the template created by vcpu_tb_trans.
 *   3. Build a WPBBEntry from the template and collected memory accesses.
 *   4. Decide the next PC: not-taken for conditional branches, natural
 *      execution for unconditional/call/return.
 *   5. Repeat until instruction depth reached or fault.
 *
 * Returns a GArray of WPBBEntry representing the wrong-path BB chain.
 */
GArray *simulate_wrong_path_ext(uint64_t branch_pc,
                                uint64_t correct_target,
                                uint64_t wrong_target,
                                unsigned int cpu_index)
{
    (void)branch_pc;
    (void)correct_target;

    guint initial_insn_cap = max_wrong_path_depth > 16
        ? (guint)max_wrong_path_depth : 16;
    guint wp_chain_cap = initial_insn_cap;
    guint poisoned_targets_cap = 16;
    GArray *wp_chain = g_array_sized_new(false, false, sizeof(WPBBEntry),
                                         wp_chain_cap);
    GArray *poisoned_targets = g_array_sized_new(false, false,
                                                 sizeof(uint64_t),
                                                 poisoned_targets_cap);
    uint64_t sim_insns = 0;
    bool early_exit = false;
    uint64_t last_fault_pc = UINT64_MAX;
    unsigned int repeated_fault_pc = 0;

    struct qemu_plugin_cpu_state *saved_state = qemu_plugin_cpu_state_save();
    if (!saved_state) {
        stat_wp_early_exits++;
        stat_wp_simulations++;
        return wp_chain;
    }

    wp_mem_accesses = g_array_new(false, false, sizeof(WPMemAccess));

    wp_saved_cpu_index = cpu_index;
    wp_saved_insn_count = qemu_plugin_u64_get(sb_insn_count, cpu_index);
    wp_saved_prev_start_pc = qemu_plugin_u64_get(sb_prev_start_pc, cpu_index);
    wp_saved_prev_last_pc = qemu_plugin_u64_get(sb_prev_last_pc, cpu_index);
    wp_saved_prev_fall_through = qemu_plugin_u64_get(sb_prev_fall_through,
                                                     cpu_index);
    wp_saved_prev_bb_ends_in_branch =
        qemu_plugin_u64_get(sb_prev_bb_ends_in_branch, cpu_index);
    wp_in_progress = true;

    qemu_plugin_spec_mode_begin(saved_state);
    qemu_plugin_set_pc(wrong_target);

    /*
     * Per-insn accumulator for the BB currently being built.  Spec mode
     * forces CF_SINGLE_STEP|1 at EXECUTION time, but the
     * template returned by find_template(pre_pc) may be a multi-insn
     * cached translation from CP (translated under different cflags).
     * Only insn[0] of that template actually executed.  We therefore
     * accumulate per-step (1 insn each) into raw arrays and commit a
     * true BB at each branch fire via commit_true_bb().
     */
    guint bb_pcs_cap = initial_insn_cap;
    guint bb_sizes_cap = initial_insn_cap;
    guint bb_bytes_cap = initial_insn_cap * MAX_INSN_BYTES;
    guint bb_fields_cap = initial_insn_cap;
    guint bb_regnames_cap = initial_insn_cap;
    guint bb_dyn_params_cap = initial_insn_cap;
    guint bb_reg_snaps_cap = initial_insn_cap * MAX_SRC_REGS;
    GArray *bb_pcs = g_array_sized_new(false, false, sizeof(uint64_t),
                                       bb_pcs_cap);
    GArray *bb_sizes = g_array_sized_new(false, false, sizeof(uint8_t),
                                         bb_sizes_cap);
    GByteArray *bb_bytes = g_byte_array_sized_new(bb_bytes_cap);
    GArray *bb_fields = g_array_sized_new(false, false, sizeof(InsnFields),
                                          bb_fields_cap);
    GArray *bb_regnames = enable_reg_data
        ? g_array_sized_new(false, false, sizeof(InsnRegNames),
                            bb_regnames_cap) : NULL;
    GArray *bb_dyn_params = g_array_sized_new(false, false, sizeof(DynParam),
                                              bb_dyn_params_cap);
    GArray *bb_reg_snaps = enable_reg_data
        ? g_array_sized_new(false, false, sizeof(RegSnap), bb_reg_snaps_cap)
        : NULL;
    uint64_t bb_start_pc = 0;
    const char *bb_symbol_name = NULL;

    while (sim_insns < (uint64_t)max_wrong_path_depth ||
           bb_pcs->len > 0) {
        uint64_t pre_pc = qemu_plugin_get_pc();
        guint mem_start_idx = wp_mem_accesses->len;
        BBTemplate *tmpl = NULL;
        bool tb_ok;

        if (wp_target_is_poisoned(poisoned_targets, pre_pc)) {
            early_exit = true;
            break;
        }

        if (bb_pcs->len == 0) {
            bb_start_pc = pre_pc;
        }

        g_mutex_lock(&data_lock);
        tmpl = find_template(pre_pc);
        g_mutex_unlock(&data_lock);

        bool tmpl_known_before_exec = (tmpl != NULL);
        if (bb_reg_snaps && tmpl_known_before_exec) {
            uint64_t last_pc = 0;
            uint8_t last_size = 0;
            const uint8_t *last_bytes = NULL;
            bool have_last = false;

            if (bb_pcs->len > 0) {
                uint32_t prev = bb_pcs->len - 1;
                last_pc = g_array_index(bb_pcs, uint64_t, prev);
                last_size = g_array_index(bb_sizes, uint8_t, prev);
                last_bytes = &bb_bytes->data[(size_t)prev * MAX_INSN_BYTES];
                have_last = true;
            }

            for (uint32_t i = 0; i < tmpl->n_insns; i++) {
                const uint8_t *cur_bytes =
                    &tmpl->insn_bytes[(size_t)i * MAX_INSN_BYTES];
                bool duplicate = have_last &&
                    last_pc == tmpl->insn_pcs[i] &&
                    last_size == tmpl->insn_sizes[i] &&
                    memcmp(last_bytes, cur_bytes, MAX_INSN_BYTES) == 0;

                if (!duplicate) {
                    wp_capture_insn_snaps_live(cpu_index, tmpl, i,
                                               bb_reg_snaps);
                    last_pc = tmpl->insn_pcs[i];
                    last_size = tmpl->insn_sizes[i];
                    last_bytes = cur_bytes;
                    have_last = true;
                }
            }
        }

        WideRegSnap *wide = tmpl_known_before_exec
            ? NULL : wide_reg_snap_capture(cpu_index);

        tb_ok = qemu_plugin_exec_tb();

        if (!tmpl) {
            g_mutex_lock(&data_lock);
            tmpl = find_template(pre_pc);
            g_mutex_unlock(&data_lock);
        }

        if (!tmpl) {
            wide_reg_snap_free(wide);
            wp_array_reset(bb_pcs);
            wp_array_reset(bb_sizes);
            wp_byte_array_reset(bb_bytes);
            wp_array_reset(bb_fields);
            if (bb_regnames) wp_array_reset(bb_regnames);
            wp_array_reset(bb_dyn_params);
            if (bb_reg_snaps) wp_array_reset(bb_reg_snaps);
            bb_start_pc = 0;
            bb_symbol_name = NULL;
            early_exit = true;
            break;
        }

        /*
         * exec_tb may run multiple insns of a CP-cached translation
         * (CF_SINGLE_STEP only affects new translations).  Append the
         * full template so the BB we build matches what actually
         * executed.  The BB ends architecturally when the TB ends in
         * a branch; otherwise the next iteration's pre_pc will equal
         * post_pc and continue accumulating.
         */
        uint32_t bb_idx_base = bb_pcs->len;
        if (bb_pcs->len == 0 && tmpl->symbol_name) {
            bb_symbol_name = tmpl->symbol_name;
        }
        uint32_t appended_insns = 0;
        for (uint32_t i = 0; i < tmpl->n_insns; i++) {
            uint64_t insn_pc = tmpl->insn_pcs[i];
            uint8_t isz = tmpl->insn_sizes[i];
            bool duplicate = false;
            if (bb_pcs->len > 0) {
                uint32_t prev = bb_pcs->len - 1;
                duplicate = g_array_index(bb_pcs, uint64_t, prev) == insn_pc &&
                            g_array_index(bb_sizes, uint8_t, prev) == isz &&
                            memcmp(&bb_bytes->data[(size_t)prev *
                                                   MAX_INSN_BYTES],
                                   &tmpl->insn_bytes[(size_t)i *
                                                     MAX_INSN_BYTES],
                                   MAX_INSN_BYTES) == 0;
            }
            if (duplicate) {
                continue;
            }

            wp_u64_append(bb_pcs, &bb_pcs_cap, insn_pc);
            wp_u8_append(bb_sizes, &bb_sizes_cap, isz);
            wp_bytes_append(bb_bytes, &bb_bytes_cap,
                            &tmpl->insn_bytes[i * MAX_INSN_BYTES],
                            MAX_INSN_BYTES);
            wp_fields_append(bb_fields, &bb_fields_cap,
                             &tmpl->insn_fields[i]);
            if (bb_regnames && tmpl->insn_reg_names) {
                wp_regnames_append(bb_regnames, &bb_regnames_cap,
                                   &tmpl->insn_reg_names[i]);
            } else if (bb_regnames) {
                InsnRegNames empty = {0};
                wp_regnames_append(bb_regnames, &bb_regnames_cap, &empty);
            }
            if (bb_reg_snaps && !tmpl_known_before_exec) {
                wp_capture_insn_snaps(wide, tmpl, i, bb_reg_snaps);
            }
            appended_insns++;
        }
        uint8_t last_insn_size = tmpl->insn_sizes[tmpl->n_insns - 1];

        /*
         * Budget accounting: spec-mode exec_tb runs the full TB
         * starting at pre_pc to its natural end (branch / page-cross).
         * cpu_plugin_exec_tb sets cflags = CF_NO_GOTO_TB|CF_NO_GOTO_PTR|
         * CF_MEMI_ONLY|CF_SINGLE_STEP — note CF_COUNT_MASK is zero, so
         * tb_gen_code uses max_insns = TCG_MAX_INSNS.  CF_SINGLE_STEP
         * is only about preventing rep-prefixed insns from looping
         * internally on x86; it does NOT cap TB length to 1 insn.
         * Each executed insn must be counted exactly once toward the
         * wrong-path budget; this is executed-insn count, not unique
         * insns and not unique BBs.
         */
        sim_insns += appended_insns;

        /* Attribute mem accesses to insns within the just-appended
         * fragment by matching the recorded insn_pc. */
        for (guint m = mem_start_idx; m < wp_mem_accesses->len; m++) {
            WPMemAccess *acc = &g_array_index(wp_mem_accesses,
                                              WPMemAccess, m);
            uint16_t insn_idx = (uint16_t)bb_idx_base;
            for (uint32_t i = 0; i < tmpl->n_insns; i++) {
                if (tmpl->insn_pcs[i] == acc->insn_pc) {
                    insn_idx = (uint16_t)(bb_idx_base + i);
                    break;
                }
            }
            DynParam dp = {
                .type = (uint8_t)(acc->is_store ? DYN_STORE_ADDR
                                                : DYN_LOAD_ADDR),
                .insn_index = insn_idx,
                .value = acc->mem_vaddr,
                .data_size = acc->data_size,
                .data = acc->data,
            };
            wp_dyn_param_append(bb_dyn_params, &bb_dyn_params_cap, &dp);
            stat_wp_total_mem_accesses++;
        }

        wide_reg_snap_free(wide);
        wide = NULL;

        uint32_t last_local = bb_pcs->len - 1;
        bool ends_in_branch =
            (g_array_index(bb_fields, InsnFields, last_local).branch_type
             != BRANCH_NONE);

        if (!tb_ok) {
            /* Fault: commit current BB with fault flag. */
            uint64_t recovery_pc = qemu_plugin_get_pc();

            if (pre_pc == last_fault_pc) {
                repeated_fault_pc++;
            } else {
                repeated_fault_pc = 0;
                last_fault_pc = pre_pc;
            }

            uint64_t fall_through = pre_pc + last_insn_size;

            g_mutex_lock(&data_lock);
            BBTemplate *bb_tmpl = commit_true_bb(
                bb_start_pc, bb_pcs->len,
                (uint64_t *)bb_pcs->data,
                (InsnFields *)bb_fields->data,
                (uint8_t *)bb_sizes->data,
                bb_bytes->data,
                bb_regnames ? (InsnRegNames *)bb_regnames->data : NULL,
                bb_symbol_name, fall_through);
            g_mutex_unlock(&data_lock);

            uint32_t fault_idx = bb_pcs->len > 0
                ? (uint32_t)(bb_pcs->len - 1) : 0;
            bool has_syscall = false;
            if (bb_tmpl) {
                for (uint32_t i = 0; i < bb_tmpl->n_insns; i++) {
                    if (bb_tmpl->insn_fields[i].opcode
                        == GEN_OP_SYSCALL) {
                        fault_idx = i;
                        has_syscall = true;
                        break;
                    }
                }
                if (fault_idx + 1 < bb_tmpl->n_insns) {
                    recovery_pc = bb_tmpl->insn_pcs[fault_idx]
                                + bb_tmpl->insn_sizes[fault_idx];
                } else {
                    recovery_pc = bb_tmpl->fall_through_pc;
                }
            }

            WPBBEntry fault_wp = {
                .template_id = bb_tmpl ? bb_tmpl->template_id : 0,
                .start_pc = bb_start_pc,
                .dyn_params = wp_dyn_params_clone(bb_dyn_params),
                .n_insns_executed = (uint32_t)bb_pcs->len,
                .fault = true,
                .translation_unavailable = false,
                .fault_insn_index = fault_idx,
                .tmpl = bb_tmpl,
                .reg_snaps = NULL,
            };
            if (bb_reg_snaps) {
                fault_wp.reg_snaps = bb_reg_snaps;
                bb_reg_snaps_cap = initial_insn_cap * MAX_SRC_REGS;
                bb_reg_snaps = g_array_sized_new(false, false,
                                                 sizeof(RegSnap),
                                                 bb_reg_snaps_cap);
            }
            wp_entry_append(wp_chain, &wp_chain_cap, &fault_wp);

            wp_array_reset(bb_pcs);
            wp_array_reset(bb_sizes);
            wp_byte_array_reset(bb_bytes);
            wp_array_reset(bb_fields);
            if (bb_regnames) wp_array_reset(bb_regnames);
            wp_array_reset(bb_dyn_params);
            bb_start_pc = 0;
            bb_symbol_name = NULL;

            if (has_syscall) {
                early_exit = true;
                break;
            }

            wp_poison_target(poisoned_targets, &poisoned_targets_cap, pre_pc);
            repeated_fault_pc = 0;
            last_fault_pc = UINT64_MAX;

            if (sim_insns < (uint64_t)max_wrong_path_depth) {
                if (repeated_fault_pc >= 16) {
                    early_exit = true;
                    break;
                }
                if (wp_target_is_poisoned(poisoned_targets, recovery_pc)) {
                    early_exit = true;
                    break;
                }
                qemu_plugin_spec_mode_end();
                qemu_plugin_cpu_state_restore(saved_state);
                qemu_plugin_spec_mode_begin(saved_state);
                qemu_plugin_set_pc(recovery_pc);
                continue;
            }

            early_exit = true;
            break;
        }

        if (!ends_in_branch) {
            continue;
        }

        /* Branch fired: commit completed BB. */
        uint64_t post_pc = qemu_plugin_get_pc();
        repeated_fault_pc = 0;
        last_fault_pc = UINT64_MAX;

        uint64_t fall_through = pre_pc + last_insn_size;

        g_mutex_lock(&data_lock);
        BBTemplate *bb_tmpl = commit_true_bb(
            bb_start_pc, bb_pcs->len,
            (uint64_t *)bb_pcs->data,
            (InsnFields *)bb_fields->data,
            (uint8_t *)bb_sizes->data,
            bb_bytes->data,
            bb_regnames ? (InsnRegNames *)bb_regnames->data : NULL,
            bb_symbol_name, fall_through);
        g_mutex_unlock(&data_lock);

        WPBBEntry wp_bb = {
            .template_id = bb_tmpl ? bb_tmpl->template_id : 0,
            .start_pc = bb_start_pc,
            .dyn_params = wp_dyn_params_clone(bb_dyn_params),
            .n_insns_executed = (uint32_t)bb_pcs->len,
            .fault = false,
            .translation_unavailable = false,
            .fault_insn_index = 0,
            .tmpl = bb_tmpl,
            .reg_snaps = NULL,
        };
        if (bb_reg_snaps) {
            wp_bb.reg_snaps = bb_reg_snaps;
            bb_reg_snaps_cap = initial_insn_cap * MAX_SRC_REGS;
            bb_reg_snaps = g_array_sized_new(false, false, sizeof(RegSnap),
                                             bb_reg_snaps_cap);
        }
        wp_entry_append(wp_chain, &wp_chain_cap, &wp_bb);

        wp_array_reset(bb_pcs);
        wp_array_reset(bb_sizes);
        wp_byte_array_reset(bb_bytes);
        wp_array_reset(bb_fields);
        if (bb_regnames) wp_array_reset(bb_regnames);
        wp_array_reset(bb_dyn_params);
        bb_start_pc = 0;
        bb_symbol_name = NULL;

        if (wp_target_is_poisoned(poisoned_targets, post_pc)) {
            early_exit = true;
            break;
        }
    }

    g_array_unref(bb_pcs);
    g_array_unref(bb_sizes);
    g_byte_array_unref(bb_bytes);
    g_array_unref(bb_fields);
    if (bb_regnames) g_array_unref(bb_regnames);
    g_array_unref(bb_dyn_params);
    if (bb_reg_snaps) g_array_unref(bb_reg_snaps);

    wp_in_progress = false;

    qemu_plugin_u64_set(sb_insn_count, cpu_index, wp_saved_insn_count);
    qemu_plugin_u64_set(sb_prev_start_pc, cpu_index, wp_saved_prev_start_pc);
    qemu_plugin_u64_set(sb_prev_last_pc, cpu_index, wp_saved_prev_last_pc);
    qemu_plugin_u64_set(sb_prev_fall_through, cpu_index,
                        wp_saved_prev_fall_through);
    qemu_plugin_u64_set(sb_prev_bb_ends_in_branch, cpu_index,
                        wp_saved_prev_bb_ends_in_branch);

    qemu_plugin_spec_mode_end();
    qemu_plugin_cpu_state_restore(saved_state);
    qemu_plugin_cpu_state_free(saved_state);

    g_array_unref(wp_mem_accesses);
    wp_mem_accesses = NULL;
    g_array_unref(poisoned_targets);

    stat_wp_simulations++;
    stat_wp_total_insns += sim_insns;
    if (early_exit) {
        stat_wp_early_exits++;
    }

    return wp_chain;
}
