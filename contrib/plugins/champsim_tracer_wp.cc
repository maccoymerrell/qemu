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

static void wp_poison_target(GArray *poisoned_targets, uint64_t pc)
{
    if (!wp_target_is_poisoned(poisoned_targets, pc)) {
        g_array_append_val(poisoned_targets, pc);
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

    GArray *wp_chain = g_array_new(false, false, sizeof(WPBBEntry));
    GArray *poisoned_targets = g_array_new(false, false, sizeof(uint64_t));
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

    GArray *wp_frags = g_array_new(false, false, sizeof(BBTemplate *));
    GArray *wp_chain_mems = g_array_new(false, false, sizeof(DynParam));
    uint64_t wp_chain_entry_pc = 0;
    uint32_t wp_chain_insns = 0;

    while (sim_insns < (uint64_t)max_wrong_path_depth) {
        uint64_t pre_pc = qemu_plugin_get_pc();
        guint mem_start_idx = wp_mem_accesses->len;
        BBTemplate *tmpl = NULL;
        bool tb_ok;

        if (wp_target_is_poisoned(poisoned_targets, pre_pc)) {
            early_exit = true;
            break;
        }

        if (wp_chain_entry_pc == 0) {
            wp_chain_entry_pc = pre_pc;
        }

        tb_ok = qemu_plugin_exec_tb();

        g_mutex_lock(&data_lock);
        tmpl = find_template(pre_pc);
        g_mutex_unlock(&data_lock);

        if (!tmpl) {
            g_array_set_size(wp_frags, 0);
            g_array_set_size(wp_chain_mems, 0);
            wp_chain_entry_pc = 0;
            wp_chain_insns = 0;
            early_exit = true;
            break;
        }

        g_array_append_val(wp_frags, tmpl);
        uint32_t fragment_offset = wp_chain_insns;
        wp_chain_insns += tmpl->n_insns;
        sim_insns += tmpl->n_insns;

        {
            guint local_idx = 0;
            for (guint m = mem_start_idx; m < wp_mem_accesses->len; m++) {
                WPMemAccess *acc = &g_array_index(wp_mem_accesses,
                                                  WPMemAccess, m);
                while (local_idx < tmpl->n_insns &&
                       tmpl->insn_pcs[local_idx] != acc->insn_pc) {
                    local_idx++;
                }
                DynParam dp = {
                    .type = (uint8_t)(acc->is_store ? DYN_STORE_ADDR
                                                    : DYN_LOAD_ADDR),
                    .insn_index = (uint16_t)(fragment_offset +
                        (local_idx < tmpl->n_insns ? local_idx : 0)),
                    .value = acc->mem_vaddr,
                    .data_size = acc->data_size,
                    .data_lo = acc->data_lo,
                    .data_hi = acc->data_hi,
                };
                g_array_append_val(wp_chain_mems, dp);
                stat_wp_total_mem_accesses++;
            }
        }

        if (!tb_ok) {
            /* Fault: finalize accumulated chain as a faulting BB. */
            uint64_t recovery_pc = qemu_plugin_get_pc();

            if (pre_pc == last_fault_pc) {
                repeated_fault_pc++;
            } else {
                repeated_fault_pc = 0;
                last_fault_pc = pre_pc;
            }

            g_mutex_lock(&data_lock);
            BBTemplate *bb_tmpl = get_or_create_bb_template(
                wp_chain_entry_pc,
                (BBTemplate **)wp_frags->data, wp_frags->len);
            g_mutex_unlock(&data_lock);

            WPBBEntry fault_wp = {
                .template_id = bb_tmpl ? bb_tmpl->template_id : 0,
                .start_pc = wp_chain_entry_pc,
                .dyn_params = g_array_new(false, false, sizeof(DynParam)),
                .n_insns_executed = wp_chain_insns,
                .fault = true,
                .translation_unavailable = false,
                .tmpl = bb_tmpl,
            };

            for (guint m = 0; m < wp_chain_mems->len; m++) {
                DynParam dp = g_array_index(wp_chain_mems, DynParam, m);
                g_array_append_val(fault_wp.dyn_params, dp);
            }

            bool has_syscall = false;
            if (bb_tmpl && bb_tmpl->n_insns > 0) {
                uint32_t fault_idx = bb_tmpl->n_insns - 1;
                for (uint32_t i = 0; i < bb_tmpl->n_insns; i++) {
                    if (bb_tmpl->insn_fields[i].opcode == GEN_OP_SYSCALL) {
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

            g_array_append_val(wp_chain, fault_wp);

            g_array_set_size(wp_frags, 0);
            g_array_set_size(wp_chain_mems, 0);
            wp_chain_entry_pc = 0;
            wp_chain_insns = 0;

            if (has_syscall) {
                early_exit = true;
                break;
            }

            wp_poison_target(poisoned_targets, pre_pc);
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

        /* TB executed normally: branch-terminated? */
        uint64_t post_pc = qemu_plugin_get_pc();
        repeated_fault_pc = 0;
        last_fault_pc = UINT64_MAX;

        int br_idx = template_branch_index(tmpl);
        uint8_t last_br = (br_idx >= 0)
            ? tmpl->insn_fields[br_idx].branch_type : BRANCH_NONE;
        bool ends_in_branch = (br_idx >= 0 && last_br != BRANCH_NONE);

        if (!ends_in_branch) {
            continue;
        }

        g_mutex_lock(&data_lock);
        BBTemplate *bb_tmpl = get_or_create_bb_template(
            wp_chain_entry_pc,
            (BBTemplate **)wp_frags->data, wp_frags->len);
        g_mutex_unlock(&data_lock);

        WPBBEntry wp_bb;
        wp_bb.start_pc = wp_chain_entry_pc;
        wp_bb.template_id = bb_tmpl ? bb_tmpl->template_id : 0;
        wp_bb.n_insns_executed = wp_chain_insns;
        wp_bb.fault = false;
        wp_bb.translation_unavailable = false;
        wp_bb.tmpl = bb_tmpl;
        wp_bb.dyn_params = g_array_new(false, false, sizeof(DynParam));
        for (guint m = 0; m < wp_chain_mems->len; m++) {
            DynParam dp = g_array_index(wp_chain_mems, DynParam, m);
            g_array_append_val(wp_bb.dyn_params, dp);
        }

        uint64_t chosen_target = post_pc;

        g_array_append_val(wp_chain, wp_bb);

        g_array_set_size(wp_frags, 0);
        g_array_set_size(wp_chain_mems, 0);
        wp_chain_entry_pc = 0;
        wp_chain_insns = 0;

        if (wp_target_is_poisoned(poisoned_targets, chosen_target)) {
            early_exit = true;
            break;
        }

        if (chosen_target != post_pc) {
            qemu_plugin_set_pc(chosen_target);
        }
    }

    g_array_unref(wp_frags);
    g_array_unref(wp_chain_mems);

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
