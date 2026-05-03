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
#include <utility>
#include <vector>

#include "champsim_tracer.h"
#include "champsim_tracer_bb_template_cache.h"
#include "champsim_tracer_reg_snap_collector.h"
#include "champsim_tracer_scoreboard.h"
#include "champsim_tracer_stats.h"
#include "champsim_tracer_wp_thread_state.h"

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
 * Returns the WPBBEntry chain by value; callers move it into
 * BodyEntry::wp_entries.
 */
std::vector<WPBBEntry> simulate_wrong_path_ext(uint64_t branch_pc,
                                               uint64_t correct_target,
                                               uint64_t wrong_target,
                                               unsigned int cpu_index)
{
    (void)branch_pc;
    (void)correct_target;

    unsigned int initial_insn_cap = max_wrong_path_depth > 16
        ? (unsigned int)max_wrong_path_depth : 16;
    std::vector<WPBBEntry> wp_chain;
    wp_chain.reserve(initial_insn_cap);
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

    g_wp_state.mem_accesses.clear();
    g_wp_state.mem_overflow = false;
    g_wp_state.cur_insn_pc = 0;
    g_wp_state.cur_insn_count = 0;

    g_wp_state.saved_cpu_index = cpu_index;
    g_wp_state.saved_insn_count = qemu_plugin_u64_get(g_scoreboard.insn_count, cpu_index);
    g_wp_state.saved_prev_start_pc = qemu_plugin_u64_get(g_scoreboard.prev_start_pc, cpu_index);
    g_wp_state.saved_prev_last_pc = qemu_plugin_u64_get(g_scoreboard.prev_last_pc, cpu_index);
    g_wp_state.saved_prev_fall_through = qemu_plugin_u64_get(g_scoreboard.prev_fall_through,
                                                     cpu_index);
    g_wp_state.saved_prev_bb_ends_in_branch =
        qemu_plugin_u64_get(g_scoreboard.prev_bb_ends_in_branch, cpu_index);
    g_wp_state.in_progress = true;

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
    std::vector<RegSnap>      bb_reg_snaps;
    bb_pcs.reserve(initial_insn_cap);
    bb_sizes.reserve(initial_insn_cap);
    bb_bytes.reserve(initial_insn_cap * MAX_INSN_BYTES);
    bb_fields.reserve(initial_insn_cap);
    bb_dyn_params.reserve(initial_insn_cap);
    if (enable_reg_data) {
        bb_regnames.reserve(initial_insn_cap);
        bb_reg_snaps.reserve((size_t)initial_insn_cap * MAX_SRC_REGS);
    }
    uint64_t bb_start_pc = 0;
    const char *bb_symbol_name = nullptr;

    /* Reset all per-BB accumulator state.  bb_reg_snaps is left alone
     * (caller handles it: clear after a no-template drop, transfer +
     * realloc after a successful commit). */
    auto clear_accum = [&]() {
        bb_pcs.clear();
        bb_sizes.clear();
        bb_bytes.clear();
        bb_fields.clear();
        bb_regnames.clear();
        bb_dyn_params.clear();
        bb_start_pc = 0;
        bb_symbol_name = nullptr;
    };

    /* Build a WPBBEntry from the current accumulator and move
     * bb_reg_snaps / bb_dyn_params into it.  After this call the
     * accumulator vectors are empty (moved-from); the caller still
     * runs clear_accum() afterwards to reset bb_pcs/etc. */
    auto make_wp_entry = [&](BBTemplate *bb_tmpl, bool fault,
                             uint32_t fault_insn_index) {
        WPBBEntry e;
        e.template_id = bb_tmpl ? bb_tmpl->template_id : 0;
        e.start_pc = bb_start_pc;
        e.dyn_params = std::move(bb_dyn_params);
        e.n_insns_executed = (uint32_t)bb_pcs.size();
        e.fault = fault;
        e.translation_unavailable = false;
        e.fault_insn_index = fault_insn_index;
        e.tmpl = bb_tmpl;
        if (enable_reg_data) {
            e.reg_snaps = std::move(bb_reg_snaps);
        }
        return e;
    };

    while (sim_insns < (uint64_t)max_wrong_path_depth ||
           !bb_pcs.empty()) {
        uint64_t pre_pc = qemu_plugin_get_pc();
        size_t mem_start_idx = g_wp_state.mem_accesses.size();
        BBTemplate *tmpl = nullptr;
        bool tb_ok;

        if (g_wp_state.mem_overflow) {
            /* A previous TB execution flooded mem_accesses past the
             * cap (typically a REP-prefixed string instruction with
             * junk speculative RCX).  Continuing risks heap exhaustion
             * and a NULL deref in QEMU's plugin machinery. */
            early_exit = true;
            break;
        }

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

        bool tmpl_known_before_exec = (tmpl != nullptr);
        if (enable_reg_data && tmpl_known_before_exec) {
            uint64_t last_pc = 0;
            uint8_t last_size = 0;
            const uint8_t *last_bytes = nullptr;
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
                    g_reg_snaps.capture_insn_snaps_live(cpu_index, tmpl, i,
                                               bb_reg_snaps);
                    last_pc = tmpl->insn_pcs[i];
                    last_size = tmpl->insn_sizes[i];
                    last_bytes = cur_bytes;
                    have_last = true;
                }
            }
        }

        WideRegSnap *wide = tmpl_known_before_exec
            ? nullptr : g_reg_snaps.capture_wide(cpu_index);

        tb_ok = qemu_plugin_exec_tb();

        if (!tmpl) {
            g_mutex_lock(&data_lock);
            tmpl = g_bb_template_cache.find_tb_template(pre_pc);
            g_mutex_unlock(&data_lock);
        }

        if (!tmpl) {
            RegSnapCollector::free_wide(wide);
            clear_accum();
            bb_reg_snaps.clear();
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
            if (enable_reg_data && !tmpl_known_before_exec) {
                g_reg_snaps.capture_insn_snaps(wide, tmpl, i, bb_reg_snaps);
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
        for (size_t m = mem_start_idx; m < g_wp_state.mem_accesses.size(); m++) {
            const WPMemAccess &acc = g_wp_state.mem_accesses[m];
            uint16_t insn_idx = (uint16_t)bb_idx_base;
            for (uint32_t i = 0; i < tmpl->n_insns; i++) {
                if (tmpl->insn_pcs[i] == acc.insn_pc) {
                    insn_idx = (uint16_t)(bb_idx_base + i);
                    break;
                }
            }
            DynParam dp = {
                .type = (uint8_t)(acc.is_store ? DYN_STORE_ADDR
                                                : DYN_LOAD_ADDR),
                .insn_index = insn_idx,
                .value = acc.mem_vaddr,
                .data_size = acc.data_size,
                .data = acc.data,
            };
            bb_dyn_params.push_back(dp);
            g_stats.wp_total_mem_accesses++;
        }

        RegSnapCollector::free_wide(wide);
        wide = nullptr;

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
                enable_reg_data ? bb_regnames.data() : nullptr,
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

            wp_chain.push_back(make_wp_entry(bb_tmpl, true, fault_idx));

            clear_accum();

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
            enable_reg_data ? bb_regnames.data() : nullptr,
            bb_symbol_name, fall_through);
        g_mutex_unlock(&data_lock);

        wp_chain.push_back(make_wp_entry(bb_tmpl, false, 0));

        clear_accum();

        if (poisoned_targets.count(post_pc)) {
            early_exit = true;
            break;
        }
    }

    g_wp_state.in_progress = false;

    qemu_plugin_u64_set(g_scoreboard.insn_count, cpu_index, g_wp_state.saved_insn_count);
    qemu_plugin_u64_set(g_scoreboard.prev_start_pc, cpu_index, g_wp_state.saved_prev_start_pc);
    qemu_plugin_u64_set(g_scoreboard.prev_last_pc, cpu_index, g_wp_state.saved_prev_last_pc);
    qemu_plugin_u64_set(g_scoreboard.prev_fall_through, cpu_index,
                        g_wp_state.saved_prev_fall_through);
    qemu_plugin_u64_set(g_scoreboard.prev_bb_ends_in_branch, cpu_index,
                        g_wp_state.saved_prev_bb_ends_in_branch);

    qemu_plugin_spec_mode_end();
    qemu_plugin_cpu_state_restore(saved_state);
    qemu_plugin_cpu_state_free(saved_state);

    g_wp_state.mem_accesses.clear();

    g_stats.wp_simulations++;
    g_stats.wp_total_insns += sim_insns;
    if (early_exit) {
        g_stats.wp_early_exits++;
    }

    return wp_chain;
}
