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

#include <unordered_set>
#include <vector>

#include "champsim_tracer.h"
#include "champsim_tracer_bb_template_cache.h"
#include "champsim_tracer_stats.h"

/*
 * Internal scratch for a single in-progress wrong-path BB.  Six per-insn
 * parallel arrays accumulate template fragments as exec_tb runs them, plus
 * the dynamic memops attributed to the fragment.  All cleared at BB
 * boundaries, all destroyed when the simulation function returns.
 *
 * `bb_reg_snaps` stays a GArray because, on commit, ownership of the array
 * transfers wholesale into WPBBEntry::reg_snaps (which is a GArray field
 * across the TU boundary).
 */

static GArray *wp_dyn_params_clone(const std::vector<DynParam> &src)
{
    if (src.empty()) {
        return NULL;
    }
    GArray *dst = g_array_sized_new(false, false, sizeof(DynParam), src.size());
    g_array_set_size(dst, src.size());
    memcpy(dst->data, src.data(), src.size() * sizeof(DynParam));
    return dst;
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
    GArray *wp_chain = g_array_sized_new(false, false, sizeof(WPBBEntry),
                                         initial_insn_cap);
    std::unordered_set<uint64_t> poisoned_targets;
    uint64_t sim_insns = 0;
    bool early_exit = false;
    uint64_t last_fault_pc = UINT64_MAX;
    unsigned int repeated_fault_pc = 0;

    struct qemu_plugin_cpu_state *saved_state = qemu_plugin_cpu_state_save();
    if (!saved_state) {
        g_stats.wp_early_exits++;
        g_stats.wp_simulations++;
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
    std::vector<uint64_t>     bb_pcs;
    std::vector<uint8_t>      bb_sizes;
    std::vector<uint8_t>      bb_bytes;
    std::vector<InsnFields>   bb_fields;
    std::vector<InsnRegNames> bb_regnames;
    std::vector<DynParam>     bb_dyn_params;
    bb_pcs.reserve(initial_insn_cap);
    bb_sizes.reserve(initial_insn_cap);
    bb_bytes.reserve(initial_insn_cap * MAX_INSN_BYTES);
    bb_fields.reserve(initial_insn_cap);
    bb_dyn_params.reserve(initial_insn_cap);
    if (enable_reg_data) {
        bb_regnames.reserve(initial_insn_cap);
    }
    GArray *bb_reg_snaps = enable_reg_data
        ? g_array_sized_new(false, false, sizeof(RegSnap),
                            initial_insn_cap * MAX_SRC_REGS)
        : NULL;
    uint64_t bb_start_pc = 0;
    const char *bb_symbol_name = NULL;

    while (sim_insns < (uint64_t)max_wrong_path_depth ||
           !bb_pcs.empty()) {
        uint64_t pre_pc = qemu_plugin_get_pc();
        guint mem_start_idx = wp_mem_accesses->len;
        BBTemplate *tmpl = NULL;
        bool tb_ok;

        if (poisoned_targets.count(pre_pc)) {
            early_exit = true;
            break;
        }

        if (bb_pcs.empty()) {
            bb_start_pc = pre_pc;
        }

        g_mutex_lock(&data_lock);
        tmpl = g_bb_template_cache.find_tb_template(pre_pc);
        g_mutex_unlock(&data_lock);

        bool tmpl_known_before_exec = (tmpl != NULL);
        if (bb_reg_snaps && tmpl_known_before_exec) {
            uint64_t last_pc = 0;
            uint8_t last_size = 0;
            const uint8_t *last_bytes = NULL;
            bool have_last = false;

            if (!bb_pcs.empty()) {
                size_t prev = bb_pcs.size() - 1;
                last_pc = bb_pcs[prev];
                last_size = bb_sizes[prev];
                last_bytes = &bb_bytes[prev * MAX_INSN_BYTES];
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
            tmpl = g_bb_template_cache.find_tb_template(pre_pc);
            g_mutex_unlock(&data_lock);
        }

        if (!tmpl) {
            wide_reg_snap_free(wide);
            bb_pcs.clear();
            bb_sizes.clear();
            bb_bytes.clear();
            bb_fields.clear();
            bb_regnames.clear();
            bb_dyn_params.clear();
            if (bb_reg_snaps) {
                g_array_set_size(bb_reg_snaps, 0);
            }
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
        uint32_t bb_idx_base = (uint32_t)bb_pcs.size();
        if (bb_pcs.empty() && tmpl->symbol_name) {
            bb_symbol_name = tmpl->symbol_name;
        }
        uint32_t appended_insns = 0;
        for (uint32_t i = 0; i < tmpl->n_insns; i++) {
            uint64_t insn_pc = tmpl->insn_pcs[i];
            uint8_t isz = tmpl->insn_sizes[i];
            bool duplicate = false;
            if (!bb_pcs.empty()) {
                size_t prev = bb_pcs.size() - 1;
                duplicate = bb_pcs[prev] == insn_pc &&
                            bb_sizes[prev] == isz &&
                            memcmp(&bb_bytes[prev * MAX_INSN_BYTES],
                                   &tmpl->insn_bytes[(size_t)i *
                                                     MAX_INSN_BYTES],
                                   MAX_INSN_BYTES) == 0;
            }
            if (duplicate) {
                continue;
            }

            bb_pcs.push_back(insn_pc);
            bb_sizes.push_back(isz);
            bb_bytes.insert(bb_bytes.end(),
                            &tmpl->insn_bytes[i * MAX_INSN_BYTES],
                            &tmpl->insn_bytes[i * MAX_INSN_BYTES] + MAX_INSN_BYTES);
            bb_fields.push_back(tmpl->insn_fields[i]);
            if (enable_reg_data) {
                if (tmpl->insn_reg_names) {
                    bb_regnames.push_back(tmpl->insn_reg_names[i]);
                } else {
                    InsnRegNames empty = {};
                    bb_regnames.push_back(empty);
                }
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
            bb_dyn_params.push_back(dp);
            g_stats.wp_total_mem_accesses++;
        }

        wide_reg_snap_free(wide);
        wide = NULL;

        size_t last_local = bb_pcs.size() - 1;
        bool ends_in_branch =
            (bb_fields[last_local].branch_type != BRANCH_NONE);

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
            BBTemplate *bb_tmpl = g_bb_template_cache.commit_true_bb(
                bb_start_pc, (uint32_t)bb_pcs.size(),
                bb_pcs.data(),
                bb_fields.data(),
                bb_sizes.data(),
                bb_bytes.data(),
                enable_reg_data ? bb_regnames.data() : NULL,
                bb_symbol_name, fall_through);
            g_mutex_unlock(&data_lock);

            uint32_t fault_idx = !bb_pcs.empty()
                ? (uint32_t)(bb_pcs.size() - 1) : 0;
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
                .n_insns_executed = (uint32_t)bb_pcs.size(),
                .fault = true,
                .translation_unavailable = false,
                .fault_insn_index = fault_idx,
                .tmpl = bb_tmpl,
                .reg_snaps = NULL,
            };
            if (bb_reg_snaps) {
                fault_wp.reg_snaps = bb_reg_snaps;
                bb_reg_snaps = g_array_sized_new(false, false,
                                                 sizeof(RegSnap),
                                                 initial_insn_cap *
                                                 MAX_SRC_REGS);
            }
            g_array_append_val(wp_chain, fault_wp);

            bb_pcs.clear();
            bb_sizes.clear();
            bb_bytes.clear();
            bb_fields.clear();
            bb_regnames.clear();
            bb_dyn_params.clear();
            bb_start_pc = 0;
            bb_symbol_name = NULL;

            if (has_syscall) {
                early_exit = true;
                break;
            }

            poisoned_targets.insert(pre_pc);
            repeated_fault_pc = 0;
            last_fault_pc = UINT64_MAX;

            if (sim_insns < (uint64_t)max_wrong_path_depth) {
                if (repeated_fault_pc >= 16) {
                    early_exit = true;
                    break;
                }
                if (poisoned_targets.count(recovery_pc)) {
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
        BBTemplate *bb_tmpl = g_bb_template_cache.commit_true_bb(
            bb_start_pc, (uint32_t)bb_pcs.size(),
            bb_pcs.data(),
            bb_fields.data(),
            bb_sizes.data(),
            bb_bytes.data(),
            enable_reg_data ? bb_regnames.data() : NULL,
            bb_symbol_name, fall_through);
        g_mutex_unlock(&data_lock);

        WPBBEntry wp_bb = {
            .template_id = bb_tmpl ? bb_tmpl->template_id : 0,
            .start_pc = bb_start_pc,
            .dyn_params = wp_dyn_params_clone(bb_dyn_params),
            .n_insns_executed = (uint32_t)bb_pcs.size(),
            .fault = false,
            .translation_unavailable = false,
            .fault_insn_index = 0,
            .tmpl = bb_tmpl,
            .reg_snaps = NULL,
        };
        if (bb_reg_snaps) {
            wp_bb.reg_snaps = bb_reg_snaps;
            bb_reg_snaps = g_array_sized_new(false, false, sizeof(RegSnap),
                                             initial_insn_cap * MAX_SRC_REGS);
        }
        g_array_append_val(wp_chain, wp_bb);

        bb_pcs.clear();
        bb_sizes.clear();
        bb_bytes.clear();
        bb_fields.clear();
        bb_regnames.clear();
        bb_dyn_params.clear();
        bb_start_pc = 0;
        bb_symbol_name = NULL;

        if (poisoned_targets.count(post_pc)) {
            early_exit = true;
            break;
        }
    }

    if (bb_reg_snaps) {
        g_array_unref(bb_reg_snaps);
    }

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

    g_stats.wp_simulations++;
    g_stats.wp_total_insns += sim_insns;
    if (early_exit) {
        g_stats.wp_early_exits++;
    }

    return wp_chain;
}
