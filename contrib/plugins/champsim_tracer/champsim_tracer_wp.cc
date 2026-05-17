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
 * Per iteration: exec one TB via qemu_plugin_exec_tb() (triggers
 * vcpu_tb_trans + vcpu_mem_cb, not vcpu_tb_exec/inline stores), look up
 * its template, build a WPBBEntry, pick next PC, repeat until depth or
 * fault.  Returns the WPBBEntry chain by value (callers move it into
 * BodyEntry::wp_entries).
 */
std::vector<WPBBEntry> simulate_wrong_path_ext(uint64_t branch_pc,
                                               uint64_t correct_target,
                                               uint64_t wrong_target,
                                               unsigned int cpu_index)
{
    (void)branch_pc;
    (void)correct_target;

    /* Cache the per-thread Stats ref once: g_stats expands to a
     * thread_stats_get()/__tls_get_addr call, ~1% of total time from
     * this function alone (10+ bumps per WP chain).  Named "stats" to
     * avoid shadowing inner `s` loop indices. */
    Stats &stats = thread_stats_get();
    Stats *hist = g_current_hist_bucket;

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
        stats.wp_early_exits++;
        stats.wp_simulations++;
        if (hist) {
            hist->wp_early_exits++;
            hist->wp_simulations++;
        }
        return wp_chain;
    }

    g_wp_state.mem_accesses.clear();
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
     * Per-insn accumulator for the BB being built.  Spec mode forces
     * CF_SINGLE_STEP|1 at execution time, but find_template(pre_pc) may
     * return a multi-insn CP-cached translation (different cflags) where
     * only insn[0] executed.  Accumulate per-step (1 insn each) into raw
     * arrays and commit a true BB at each branch fire via commit_true_bb().
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
    }
    if (enable_wp_reg_data) {
        bb_reg_snaps.reserve((size_t)initial_insn_cap * MAX_SRC_REGS);
    }
    uint64_t bb_start_pc = 0;
    const char *bb_symbol_name = nullptr;

    /* Fault metadata for the in-progress BB.  A true BB always ends in
     * a branch (basic_block.md), so a spec-mode fault inside a BB does
     * not terminate it: WP skips past the faulting insn and accumulates
     * until the natural branch end.  bb_first_fault_idx marks the uop
     * speculation would actually squash on. */
    bool bb_has_fault = false;
    uint32_t bb_first_fault_idx = 0;

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
        bb_has_fault = false;
        bb_first_fault_idx = 0;
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

    uint64_t prev_pre_pc = UINT64_MAX;
    uint32_t same_pre_pc_count = 0;
    while (sim_insns < (uint64_t)max_wrong_path_depth ||
           !bb_pcs.empty()) {
        uint64_t pre_pc = qemu_plugin_get_pc();
        size_t mem_start_idx = g_wp_state.mem_accesses.size();
        BBTemplate *tmpl = nullptr;
        bool tb_ok;

        /* Forward-progress guard.  An x86 REP iter in spec mode can
         * decrement RCX while the sandboxed write keeps PC anchored, so
         * exec_tb returns without advancing PC; dedup skips appending
         * and the loop spins forever until a downstream NULL-deref.
         * Force PC past the offending insn after CST_FID_SLOT_COUNT
         * same-PC iterations (same threshold as the per-insn memop cap). */
        if (pre_pc == prev_pre_pc) {
            same_pre_pc_count++;
        } else {
            prev_pre_pc = pre_pc;
            same_pre_pc_count = 1;
        }
        if (same_pre_pc_count > CST_FID_SLOT_COUNT) {
            BBTemplate *stuck = g_bb_template_cache.find_tb_template(pre_pc);
            uint8_t isz = (stuck && stuck->n_insns > 0)
                ? stuck->insn_sizes[0] : 1;
            qemu_plugin_set_pc(pre_pc + isz);
            same_pre_pc_count = 0;
            prev_pre_pc = UINT64_MAX;
            continue;
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

        /*
         * WP reg-data capture is post-exec, per-insn live: no wide
         * regfile snapshot here (would read every arch reg on every WP
         * TB, dominating regdata=1+wp=1 runs).  capture_insn_snaps_live
         * below (after exec_tb) reads only the dst regs each insn writes.
         * When CF_SINGLE_STEP doesn't reduce to 1 insn and multiple
         * insns write the same reg, only the final post-fragment value
         * is visible — identical to a wide post-fragment snap, so
         * dropping the wide path costs no correctness.
         */
        tb_ok = qemu_plugin_exec_tb();

        if (!tmpl) {
            g_mutex_lock(&data_lock);
            tmpl = g_bb_template_cache.find_tb_template(pre_pc);
            g_mutex_unlock(&data_lock);
        }

        if (!tmpl) {
            clear_accum();
            bb_reg_snaps.clear();
            early_exit = true;
            break;
        }

        /*
         * exec_tb may run multiple insns of a CP-cached translation
         * (CF_SINGLE_STEP only affects new translations).  tb_ok means
         * the whole template executed; on fault only insns up to and
         * including the faulting one were issued, so cap
         * @n_executed_in_tmpl there.  The faulting insn is included so
         * consumers see the squashed uop (dyn_params, fault_insn_index).
         */
        uint32_t n_executed_in_tmpl = tmpl->n_insns;
        if (!tb_ok) {
            uint64_t fault_pc = qemu_plugin_get_pc();
            uint32_t fault_idx_in_tmpl = UINT32_MAX;
            /* Direct match: fault_pc IS one of the TB's insn PCs
             * (speculation faulted on insn k before retiring it). */
            for (uint32_t i = 0; i < tmpl->n_insns; i++) {
                if (tmpl->insn_pcs[i] == fault_pc) {
                    fault_idx_in_tmpl = i;
                    break;
                }
            }
            /* Post-completion match: fault_pc == insn_pc + insn_size
             * for some insn k (QEMU advanced PC past insn k as part of
             * executing it — canonical for syscall: SVC/ECALL retires,
             * the handler fails out of spec mode, PC = SVC_PC + size).
             * Without this fallback the chain truncates and every wrong
             * path's exit-block tail is invisible. */
            if (fault_idx_in_tmpl == UINT32_MAX) {
                for (uint32_t i = 0; i < tmpl->n_insns; i++) {
                    uint64_t post = tmpl->insn_pcs[i] + tmpl->insn_sizes[i];
                    if (post == fault_pc) {
                        fault_idx_in_tmpl = i;
                        break;
                    }
                }
            }
            if (fault_idx_in_tmpl == UINT32_MAX) {
                /* Fault PC truly outside the TB.  Give up the chain
                 * rather than guess; this is a real abnormal exit
                 * (e.g. translation-unavailable cousin). */
                clear_accum();
                bb_reg_snaps.clear();
                early_exit = true;
                break;
            }
            n_executed_in_tmpl = fault_idx_in_tmpl + 1;
        }

        uint32_t bb_idx_base = (uint32_t)bb_pcs.size();
        if (bb_pcs.empty() && tmpl->symbol_name) {
            bb_symbol_name = tmpl->symbol_name;
        }
        uint32_t appended_insns = 0;
        for (uint32_t i = 0; i < n_executed_in_tmpl; i++) {
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

            /* WP-side per-execution attribution: mirrors the CP walk in
             * vcpu_tb_exec, scoped to non-duplicate WP insns. */
            {
                const InsnFields *f = &tmpl->insn_fields[i];
                stats.wp_insns_by_opcode[f->opcode]++;
                if (hist) hist->wp_insns_by_opcode[f->opcode]++;
                if (f->branch_type != BRANCH_NONE) {
                    stats.wp_branches_by_type[f->branch_type]++;
                    if (hist) hist->wp_branches_by_type[f->branch_type]++;
                }
                for (uint8_t k = 0; k < f->n_src_regs; k++) {
                    stats.wp_src_reg_uses[f->src_regs[k]]++;
                    if (hist) hist->wp_src_reg_uses[f->src_regs[k]]++;
                }
                for (uint8_t d = 0; d < f->n_dst_regs; d++) {
                    stats.wp_dst_reg_writes[f->dst_regs[d]]++;
                    if (hist) hist->wp_dst_reg_writes[f->dst_regs[d]]++;
                }
            }

            if (enable_reg_data) {
                if (tmpl->insn_reg_names) {
                    bb_regnames.push_back(tmpl->insn_reg_names[i]);
                } else {
                    InsnRegNames empty = {};
                    bb_regnames.push_back(empty);
                }
            }
            if (enable_wp_reg_data) {
                /* Per-insn live read of only the dst regs this insn
                 * writes from post-fragment state, not the whole file. */
                g_reg_snaps.capture_insn_snaps_live(cpu_index, tmpl, i,
                                                    bb_reg_snaps);
            }
            appended_insns++;
        }
        uint8_t last_insn_size = n_executed_in_tmpl > 0
            ? tmpl->insn_sizes[n_executed_in_tmpl - 1]
            : 0;

        /*
         * Budget accounting.  CF_SINGLE_STEP only stops rep-prefixed
         * insns from looping internally on x86; it does NOT cap TB
         * length to 1 insn (CF_COUNT_MASK is zero, so tb_gen_code uses
         * max_insns = TCG_MAX_INSNS).  Charge AT LEAST 1 per exec_tb
         * even when every appended insn dedup'd against the prior tail,
         * else a self-looping single-insn REP TB spins forever (see the
         * forward-progress guard above).
         */
        sim_insns += appended_insns ? appended_insns : 1;

        /* Attribute mem accesses to fragment insns by matching insn_pc.
         * Only walk the @n_executed_in_tmpl prefix — mem callbacks past
         * the fault never fired and those insns aren't in bb_pcs. */
        for (size_t m = mem_start_idx; m < g_wp_state.mem_accesses.size(); m++) {
            const WPMemAccess &acc = g_wp_state.mem_accesses[m];
            uint16_t insn_idx = (uint16_t)bb_idx_base;
            for (uint32_t i = 0; i < n_executed_in_tmpl; i++) {
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
            stats.wp_total_mem_accesses++;
            if (hist) {
                hist->wp_total_mem_accesses++;
            }
        }

        /* Guard against an appended-nothing iteration (every insn
         * dedup'd against the prior tail): bb_pcs may be empty, so
         * don't read bb_fields.back(). */
        bool ends_in_branch = false;
        if (!bb_pcs.empty()) {
            size_t last_local = bb_pcs.size() - 1;
            ends_in_branch =
                (bb_fields[last_local].branch_type != BRANCH_NONE);
        }

        if (!tb_ok) {
            /* Trace past the fault.  bb_pcs has insns 0..fault (the
             * @n_executed_in_tmpl cap stopped at the faulting insn).
             * Mark fault metadata for the BB committed at the natural
             * branch end, then skip past the faulting insn so later
             * exec_tbs don't re-fault.  If the faulting insn IS the
             * branch terminator (e.g. a faulting BRANCH_SYSCALL_TYPE
             * syscall) ends_in_branch below catches it and the normal
             * commit path handles it with bb_has_fault propagating;
             * only branch-bounded true BBs ever reach commit_true_bb. */
            uint64_t fault_pc = qemu_plugin_get_pc();

            if (pre_pc == last_fault_pc) {
                repeated_fault_pc++;
            } else {
                repeated_fault_pc = 0;
                last_fault_pc = pre_pc;
            }

            if (!bb_has_fault) {
                bb_has_fault = true;
                bb_first_fault_idx = bb_pcs.empty()
                    ? 0 : (uint32_t)(bb_pcs.size() - 1);
            }

            /* Poison the faulting PC: later iterations that jump back
             * to it early-exit the chain. */
            poisoned_targets.insert(fault_pc);

            if (ends_in_branch) {
                /* Fault on a branch-classified insn (e.g. syscall):
                 * fall through to the normal commit path; bb_has_fault
                 * carries the squash marker.  WP chain naturally
                 * terminates here after a syscall. */
            } else {
                if (repeated_fault_pc >= 16) {
                    early_exit = true;
                    break;
                }
                uint64_t skip_pc = fault_pc + last_insn_size;
                if (poisoned_targets.count(skip_pc)) {
                    early_exit = true;
                    break;
                }
                qemu_plugin_spec_mode_end();
                qemu_plugin_cpu_state_restore(saved_state);
                qemu_plugin_spec_mode_begin(saved_state);
                qemu_plugin_set_pc(skip_pc);
                continue;
            }
        }

        if (!ends_in_branch) {
            continue;
        }

        /* Branch fired: commit completed BB.  Still a true
         * branch-bounded BB (basic_block.md) so it goes into bb_map_
         * unconditionally; bb_has_fault carries any earlier in-BB fault
         * and the WPBBEntry's fault flag tells the consumer speculation
         * would have squashed at fault_insn_index. */
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

        /*
         * Record the terminal-branch taken edge for NON-indirect
         * branches found on the wrong path.  Direct/conditional/
         * unconditional taken targets are architecturally pre-defined,
         * so legitimate even observed speculatively (@post_pc is the
         * actual successor).  Indirect/return targets depend on
         * speculative register state and are NOT legitimate on the
         * wrong path — left to the CP-only BranchRecord pool.  Only
         * fill when CP hasn't resolved it (CP stays authoritative;
         * value identical anyway).
         */
        if (bb_tmpl && bb_tmpl->taken_pc == 0 && !bb_fields.empty()) {
            const InsnFields *lf = &bb_fields.back();
            bool indirect =
                lf->branch_type == BRANCH_INDIRECT_JUMP ||
                lf->branch_type == BRANCH_RETURN;
            if (!indirect) {
                bool cond = lf->branch_type == BRANCH_COND_DIRECT ||
                            (lf->branch_type == BRANCH_DIRECT_JUMP &&
                             lf->branch_conditional);
                uint64_t taken;
                if (post_pc != fall_through) {
                    taken = post_pc;            /* WP took the branch */
                } else if (cond && lf->has_immediate &&
                           (uint64_t)lf->immediate != fall_through) {
                    /* Fell through a conditional → taken side is the
                     * resolved target (same value the CP resolver
                     * uses), not the raw-relative immediate. */
                    taken = (uint64_t)lf->immediate;
                } else {
                    taken = post_pc;            /* uncond → fall_through */
                }
                if (taken != 0) {
                    bb_tmpl->taken_pc = taken;
                }
            }
        }

        wp_chain.push_back(make_wp_entry(bb_tmpl,
                                         bb_has_fault,
                                         bb_first_fault_idx));

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

    stats.wp_simulations++;
    stats.wp_total_insns += sim_insns;
    if (early_exit) {
        stats.wp_early_exits++;
    }
    if (hist) {
        hist->wp_simulations++;
        hist->wp_total_insns += sim_insns;
        if (early_exit) {
            hist->wp_early_exits++;
        }
    }

    return wp_chain;
}
