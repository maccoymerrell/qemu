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
        if (Stats *h = g_current_hist_bucket) {
            h->wp_early_exits++;
            h->wp_simulations++;
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
    }
    if (enable_wp_reg_data) {
        bb_reg_snaps.reserve((size_t)initial_insn_cap * MAX_SRC_REGS);
    }
    uint64_t bb_start_pc = 0;
    const char *bb_symbol_name = nullptr;

    /* Fault metadata for the in-progress BB.  Spec-mode faults inside
     * a BB no longer terminate it: per basic_block.md a true BB
     * always ends in a branch, so the WP simulator now skips past the
     * faulting insn and keeps accumulating until the natural branch
     * end fires.  bb_first_fault_idx records where the FIRST fault
     * happened so the WPBBEntry can mark which uop speculation would
     * actually squash on. */
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

        /* Forward-progress guard.  In spec mode an instruction whose
         * architectural completion writes back through speculative
         * state (e.g. an x86 REP iter where RCX decrements but the
         * sandboxed memory write keeps PC anchored at the same insn)
         * can return from exec_tb without advancing PC.  When that
         * happens the WP loop reissues exec_tb on the same pre_pc
         * indefinitely, the dedup logic skips appending so
         * appended_insns stays 0, sim_insns is bumped only by the
         * "+= 1 fallback" but bb_pcs is non-empty so the OR keeps
         * the loop alive, and we eventually NULL-deref some
         * downstream QEMU bookkeeping.  Force PC past the offending
         * insn after CST_FID_SLOT_COUNT same-PC iterations — same
         * threshold as the per-insn memop cap. */
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
         * Reg-data capture for WP is now post-exec (destination
         * values).  We can't take a wide snap here yet because the
         * spec-mode exec_tb may translate this fragment for the first
         * time (so @tmpl might still be null), and we need the
         * post-fragment register state anyway.  Defer to right after
         * exec_tb returns — see the post-exec capture_wide() below.
         */
        bool tmpl_known_before_exec = (tmpl != nullptr);
        (void)tmpl_known_before_exec;

        tb_ok = qemu_plugin_exec_tb();

        /*
         * Wide post-fragment regfile snapshot: holds the speculative
         * register state after this WP TB completed but before the
         * next exec_tb (which would overwrite anything this TB
         * wrote).  We attribute per-insn destination values from it
         * inside the appended-insns loop below.
         *
         * Imprecision: when CF_SINGLE_STEP doesn't reduce the
         * fragment to one insn (cached translations) and multiple
         * insns in the fragment write to the same architectural
         * register, only the final value survives in the snap.
         * Documented limitation; mirrors the equivalent imprecision
         * the prior pre-fragment src-side capture had for sources
         * across multi-insn cached fragments.
         */
        WideRegSnap *wide = enable_wp_reg_data
            ? g_reg_snaps.capture_wide(cpu_index) : nullptr;

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
         * (CF_SINGLE_STEP only affects new translations).  When the
         * TB ran to completion (tb_ok=true), the whole template
         * executed; on fault, only insns up to and including the
         * faulting one were issued by speculation, so we cap
         * @n_executed_in_tmpl there.  The faulting insn itself is
         * included so consumers that care about the squashed uop
         * (its dyn_params, the fault_insn_index marker) have it.
         */
        uint32_t n_executed_in_tmpl = tmpl->n_insns;
        if (!tb_ok) {
            uint64_t fault_pc = qemu_plugin_get_pc();
            uint32_t fault_idx_in_tmpl = UINT32_MAX;
            /* Direct match: fault_pc IS one of the TB's architectural
             * insn PCs (the canonical "speculation faulted on insn
             * k before retiring it" case). */
            for (uint32_t i = 0; i < tmpl->n_insns; i++) {
                if (tmpl->insn_pcs[i] == fault_pc) {
                    fault_idx_in_tmpl = i;
                    break;
                }
            }
            /* Post-completion match: fault_pc == insn_pc + insn_size
             * for some insn k.  This happens when QEMU advances PC
             * past insn k as part of executing it (canonical for
             * syscall: the SVC/ECALL retires architecturally, then
             * the syscall handler fails out of spec mode and we
             * return with PC = SVC_PC + insn_size).  Insn k is the
             * one that "caused" the fault — it's the syscall (or
             * other privilege/exception-raising terminator) that
             * triggered the spec-mode exit.  Without this fallback
             * the chain truncates short and the exit-block tail of
             * any wrong path becomes invisible. */
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
                RegSnapCollector::free_wide(wide);
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

            /* WP-side per-execution attribution: mirror the CP walk in
             * vcpu_tb_exec, scoped to non-duplicate WP insns so the
             * counts reflect what the WP simulator actually appended. */
            {
                const InsnFields *f = &tmpl->insn_fields[i];
                Stats *h = g_current_hist_bucket;
                g_stats.wp_insns_by_opcode[f->opcode]++;
                if (h) h->wp_insns_by_opcode[f->opcode]++;
                if (f->branch_type != BRANCH_NONE) {
                    g_stats.wp_branches_by_type[f->branch_type]++;
                    if (h) h->wp_branches_by_type[f->branch_type]++;
                }
                for (uint8_t s = 0; s < f->n_src_regs; s++) {
                    g_stats.wp_src_reg_uses[f->src_regs[s]]++;
                    if (h) h->wp_src_reg_uses[f->src_regs[s]]++;
                }
                for (uint8_t d = 0; d < f->n_dst_regs; d++) {
                    g_stats.wp_dst_reg_writes[f->dst_regs[d]]++;
                    if (h) h->wp_dst_reg_writes[f->dst_regs[d]]++;
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
                g_reg_snaps.capture_insn_snaps(wide, tmpl, i, bb_reg_snaps);
            }
            appended_insns++;
        }
        uint8_t last_insn_size = n_executed_in_tmpl > 0
            ? tmpl->insn_sizes[n_executed_in_tmpl - 1]
            : 0;

        /*
         * Budget accounting: spec-mode exec_tb runs the full TB
         * starting at pre_pc to its natural end (branch / page-cross).
         * cpu_plugin_exec_tb sets cflags = CF_NO_GOTO_TB|CF_NO_GOTO_PTR|
         * CF_MEMI_ONLY|CF_SINGLE_STEP — note CF_COUNT_MASK is zero, so
         * tb_gen_code uses max_insns = TCG_MAX_INSNS.  CF_SINGLE_STEP
         * is only about preventing rep-prefixed insns from looping
         * internally on x86; it does NOT cap TB length to 1 insn.
         *
         * Charge AT LEAST 1 toward the budget per exec_tb call even
         * when the appended insns were all dedup'd against the prior
         * tail.  Without this, a self-looping single-insn TB (an x86
         * REP instruction in spec mode advances RCX-by-one per call
         * without advancing PC) would dedup every iteration into
         * appended_insns=0 and the loop would spin forever — eating
         * QEMU plugin bookkeeping until something deeper NULL-defs.
         */
        sim_insns += appended_insns ? appended_insns : 1;

        /* Attribute mem accesses to insns within the just-appended
         * fragment by matching the recorded insn_pc.  Only walk the
         * @n_executed_in_tmpl prefix — mem callbacks past the fault
         * never fired, so attributing them to phantom insns past
         * fault_idx would point at insns that aren't in bb_pcs. */
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
            g_stats.wp_total_mem_accesses++;
            if (g_current_hist_bucket) {
                g_current_hist_bucket->wp_total_mem_accesses++;
            }
        }

        RegSnapCollector::free_wide(wide);
        wide = nullptr;

        /* Guard against an appended-nothing iteration (every insn of
         * the just-executed TB was a dedup of the prior tail).  In
         * that case bb_pcs is unchanged from before this iteration;
         * if it's also empty we can't read bb_fields.back(), and
         * there's no in-progress BB to mark anyway. */
        bool ends_in_branch = false;
        if (!bb_pcs.empty()) {
            size_t last_local = bb_pcs.size() - 1;
            ends_in_branch =
                (bb_fields[last_local].branch_type != BRANCH_NONE);
        }

        if (!tb_ok) {
            /* Trace past the fault.  bb_pcs already has insns 0..fault
             * appended (the @n_executed_in_tmpl cap above stopped at
             * the faulting insn).  Mark fault metadata for the BB
             * we'll eventually commit at the natural branch end, then
             * skip past the faulting insn so subsequent exec_tbs
             * don't re-fault on the same address.
             *
             * If the faulting insn IS the natural BB terminator
             * (e.g., a syscall classified as BRANCH_SYSCALL_TYPE that
             * faulted), ends_in_branch below catches it and the
             * normal commit path handles it — with bb_has_fault
             * propagating to the WPBBEntry.  bb_map_ stays clean:
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

            /* Poison the faulting PC against unbounded re-faults
             * within this WP simulation.  Subsequent iterations that
             * jump back to this PC will early-exit the chain. */
            poisoned_targets.insert(fault_pc);

            if (ends_in_branch) {
                /* Fault occurred on a branch-classified insn (e.g.,
                 * syscall).  Fall through to the normal commit path
                 * below; bb_has_fault carries the speculation-squash
                 * marker.  This is also where the WP chain naturally
                 * terminates after a syscall. */
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

        /* Branch fired: commit completed BB.  bb_has_fault carries
         * any earlier fault that happened within this BB; the BB
         * itself is still a true branch-bounded BB in the sense of
         * basic_block.md, so it goes into bb_map_ unconditionally.
         * The WPBBEntry's fault flag tells the consumer that
         * speculation would have squashed at fault_insn_index. */
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

    g_stats.wp_simulations++;
    g_stats.wp_total_insns += sim_insns;
    if (early_exit) {
        g_stats.wp_early_exits++;
    }
    if (Stats *h = g_current_hist_bucket) {
        h->wp_simulations++;
        h->wp_total_insns += sim_insns;
        if (early_exit) {
            h->wp_early_exits++;
        }
    }

    return wp_chain;
}
