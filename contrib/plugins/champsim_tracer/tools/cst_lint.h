/*
 * ChampSim Tracer offline tools — impossible-attribution lint.
 *
 * A memop or destination-register value in the body stream names its
 * instruction by (template_id, insn position).  The template knows,
 * statically, whether that instruction can physically produce such an
 * observation: an insn whose static max memop counts are BOTH zero
 * cannot touch memory, and an insn with N destination slots cannot
 * write slot >= N.  Runtime observations landing on such insns are
 * attribution corruption (foreign records leaking into an entry's
 * drain — the class of bug where a `lui` "carried" a thousand memops),
 * and this lint exists so that class fails loudly instead of riding
 * through value-multiset checks unnoticed.
 *
 * The rule is deliberately conservative — one-sided, never flagging
 * a legitimate encoder behaviour:
 *
 *   MEM: flagged only when the template insn's static max loads AND
 *   max stores are both zero.  Runtime counts exceeding a NON-zero
 *   static max are legal (x86 REP fan-out); synthetic-EA classes
 *   (prefetch / cache-flush / TLB-flush) record load-style memops the
 *   operand walker may not have given static slots, so those opcode
 *   classes are exempted wholesale.  Definitionally-memory classes
 *   are exempt too — an insn of these classes with 0/0 static counts
 *   is a static-decode gap, not an attribution impossibility:
 *     - GEN_OP_LOAD / STORE / VEC_LOAD / VEC_STORE and atomics (by
 *       flag): Capstone 6.0.0-Alpha7 leaves the MEM operand's access
 *       flags empty on aarch64 register-offset / extended-register
 *       addressing (ldr w3, [x1, x2] — verified: access==0, while
 *       [x1, #8] reads access==READ) and on LSE atomics (SWP) — same
 *       upstream bug class as the MIPS MSA / x86 store-move
 *       workarounds in disas/capstone.c.  The proper fix is an arm64
 *       boundary workaround there (infer the MEM access from the
 *       ld- / st- / swp / cas mnemonic class); it changes template
 *       bytes, so it is deferred to a Capstone-bump / format window
 *       rather than folded into this lint.
 *     - GEN_OP_PUSH / POP / RET: implicit stack traffic.  The x86
 *       stack refiners mint their static slots, but corner encodings
 *       fall through (`pop %rsp` — dep_x86_stack_pop emits slots per
 *       NON-SP dst, and here SP is the only dst; `iretq` — no
 *       Capstone MEM operand for the frame pops).
 *     - segment-register writers (x86 mov %eax, %ss / %fs / %gs):
 *       the descriptor fetch QEMU's segment-load helper performs is a
 *       real load correctly attributed to the mov, with no Capstone
 *       MEM operand to mint a slot from.  Detected by a REG_SEG* id
 *       among the insn's dst_regs.
 *
 *   REG: flagged only when a dst-register value record lands on an
 *   operand slot >= the insn's static dst count (any slot when the
 *   count is zero), or on an insn position past the template.  Only
 *   meaningful on CST_FLAG_REG_DATA traces; disabled otherwise.
 *
 *   DANGLING TEMPLATE REF: a body record naming a template id the
 *   trace's own templates section does not define.  Every CP ENTRY and
 *   every WP chain block carries a template id, and the templates
 *   section is the id's only definition — a reference with no
 *   definition is structural corruption (the writer emitted entries
 *   whose templates never serialized; observed as the stale-ASID-pin
 *   empty-templates trace), not a decode-quality nuance.  The check is
 *   id-set membership only, so it costs one hash probe per entry.
 *   WP id 0 is exempt: the writer emits 0 as the "no template" sentinel
 *   (template ids start at 1).
 *
 * Correct-path entries only for the MEM/REG rules: wrong-path
 * excursions walk speculative wandering and are not held to that
 * contract.  The dangling-ref rule covers CP and WP alike — an id
 * without a definition is corrupt regardless of path.  IFRAMEs
 * re-encode the preceding entry and must not double-count.
 *
 * Two feeding modes cover both consumers:
 *   - cst_decode's BodyWalker resolves per-entry cell values anyway;
 *     it calls note_mem()/note_reg() directly (see cst_decode.cc).
 *   - cst_audit walks raw records without cell state; DeltaTracker
 *     reconstructs the N_LOADS/N_STORES cells for flagged insns only
 *     (zero-cost on clean traces) so both tools report identical
 *     counts for the same trace.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "cst_common.h"

namespace cst {

class AttributionLint {
public:
    /* Row byte layout: bit 7 = memop-impossible (static max loads and
     * stores both zero, opcode not exempt); bits 0..6 = static dst-reg
     * slot count (clamped; real insns stay <= 64). */
    static constexpr uint8_t MEM_IMPOSSIBLE = 0x80;
    static constexpr uint8_t N_DST_MASK     = 0x7F;
    /* fid lookup span; ULEB fid space, same bound the other tools use. */
    static constexpr size_t  FID_LUT = 1024;

    AttributionLint(const Header &h, const std::vector<Template> &templates)
        : reg_enabled_(h.has_reg_data()),
          debug_(std::getenv("CST_LINT_DEBUG") != nullptr)
    {
        /* Exempt opcode classes, resolved by name from the trace's
         * own opcode map so renumbering stays harmless.  Synthetic-EA
         * classes (PREFETCH / CACHE_FLUSH / TLB_FLUSH) record their
         * effective address as a load-style memop even when the
         * operand walker minted no static load slot; the explicit
         * memory classes (LOAD / STORE / VEC_*) are memory insns by
         * definition whose static counts can read 0/0 under the
         * Capstone aarch64 access-flag bug (see the header comment). */
        std::unordered_set<uint64_t> exempt;
        for (const auto &kv : h.maps.opcode) {
            if (kv.second == "GEN_OP_PREFETCH" ||
                kv.second == "GEN_OP_CACHE_FLUSH" ||
                kv.second == "GEN_OP_TLB_FLUSH" ||
                kv.second == "GEN_OP_LOAD" ||
                kv.second == "GEN_OP_STORE" ||
                kv.second == "GEN_OP_VEC_LOAD" ||
                kv.second == "GEN_OP_VEC_STORE" ||
                kv.second == "GEN_OP_PUSH" ||
                kv.second == "GEN_OP_POP" ||
                kv.second == "GEN_OP_RET") {
                exempt.insert(kv.first);
            }
        }
        /* Segment-register generic ids, for the descriptor-fetch
         * exemption (empty set on non-x86 traces). */
        std::unordered_set<uint8_t> seg_regs;
        for (const auto &kv : h.maps.reg) {
            if (kv.second.rfind("REG_SEG", 0) == 0 && kv.first <= 0xFF) {
                seg_regs.insert((uint8_t)kv.first);
            }
        }

        rows_.reserve(templates.size());
        for (const Template &t : templates) {
            std::vector<uint8_t> row;
            row.reserve(t.insns.size());
            for (const InsnTemplate &I : t.insns) {
                uint8_t b = (uint8_t)(I.dst_regs.size() < N_DST_MASK
                                          ? I.dst_regs.size() : N_DST_MASK);
                bool writes_seg = false;
                for (uint8_t r : I.dst_regs) {
                    if (seg_regs.count(r)) { writes_seg = true; break; }
                }
                if (I.max_dep_loads == 0 && I.max_dep_stores == 0 &&
                    !I.is_atomic && !writes_seg && !exempt.count(I.opcode)) {
                    b |= MEM_IMPOSSIBLE;
                }
                row.push_back(b);
            }
            rows_.emplace(t.template_id, std::move(row));
        }

        /* dst-reg VALUE family fid -> operand slot (the width family
         * deliberately excluded: widths ride with values, counting
         * both would double-report one corrupt write). */
        dst_slot_.assign(FID_LUT, -1);
        for (int k = 0; k < FID_SLOT_COUNT; k++) {
            uint16_t fid = h.ids.fid_dst_reg[k];
            if (fid != 0 && fid < FID_LUT) {
                dst_slot_[fid] = (int16_t)k;
            }
        }
    }

    const std::vector<uint8_t> *row(uint32_t template_id) const {
        auto it = rows_.find(template_id);
        return it == rows_.end() ? nullptr : &it->second;
    }

    bool reg_check_enabled() const { return reg_enabled_; }

    int dst_slot_for_fid(uint16_t fid) const {
        return fid < dst_slot_.size() ? dst_slot_[fid] : -1;
    }

    /* One CP entry observed @count runtime memops on mem-impossible
     * insn (template_id, ipos).  @count > 0. */
    void note_mem(uint32_t template_id, uint32_t ipos, uint64_t count) {
        mem_memops_ += count;
        if (distinct_mem_.insert(insn_key(template_id, ipos)).second &&
            debug_) {
            std::fprintf(stderr,
                         "cst lint: impossible memops on template %u "
                         "insn[%u] (count %llu this entry)\n",
                         template_id, ipos, (unsigned long long)count);
        }
    }

    /* One CP dst-reg value record landed on an impossible slot. */
    void note_reg(uint32_t template_id, uint32_t ipos) {
        reg_records_ += 1;
        if (distinct_reg_.insert(insn_key(template_id, ipos)).second &&
            debug_) {
            std::fprintf(stderr,
                         "cst lint: impossible dst-reg value on template %u "
                         "insn[%u]\n", template_id, ipos);
        }
    }

    /* One body record (CP ENTRY or WP chain block) named @template_id
     * and the templates section defines no such id. */
    void note_dangling(uint32_t template_id, bool is_wp) {
        dangling_refs_ += 1;
        if (distinct_dangling_.insert(template_id).second && debug_) {
            std::fprintf(stderr,
                         "cst lint: %s record references undefined "
                         "template id %u\n",
                         is_wp ? "WP" : "CP entry", template_id);
        }
    }

    uint64_t mem_violations() const { return mem_memops_; }
    uint64_t reg_violations() const { return reg_records_; }
    uint64_t dangling_refs() const { return dangling_refs_; }
    size_t   distinct_mem_insns() const { return distinct_mem_.size(); }
    size_t   distinct_reg_insns() const { return distinct_reg_.size(); }
    size_t   distinct_dangling_ids() const {
        return distinct_dangling_.size();
    }
    bool     any() const {
        return mem_memops_ || reg_records_ || dangling_refs_;
    }

    /* "N memop (M distinct insns), R regdata (S distinct insns),
     *  D dangling template refs (K distinct ids)" */
    std::string summary() const {
        char buf[224];
        std::snprintf(buf, sizeof(buf),
                      "%llu memop (%zu distinct insns), "
                      "%llu regdata (%zu distinct insns), "
                      "%llu dangling template refs (%zu distinct ids)",
                      (unsigned long long)mem_memops_, distinct_mem_.size(),
                      (unsigned long long)reg_records_, distinct_reg_.size(),
                      (unsigned long long)dangling_refs_,
                      distinct_dangling_.size());
        return buf;
    }

    /*
     * Record-level feeder for consumers with no field-state replay
     * (cst_audit).  Reconstructs the per-(thread, template, insn)
     * N_LOADS/N_STORES cells for mem-impossible insns only — clean
     * traces never populate the maps, so the steady-state cost is one
     * flag test per count record and one boolean per entry.
     *
     * Cell semantics mirror the writer: counts are per-thread
     * persistent state, delta-encoded, so a violating count keeps
     * violating on every subsequent entry of that template until a
     * delta returns it to zero — identical to what BodyWalker's
     * resolved cells report.
     */
    class DeltaTracker {
    public:
        explicit DeltaTracker(AttributionLint &lint) : lint_(lint) {}

        /* A CP N_LOADS/N_STORES record for mem-impossible insn
         * (template_id, ipos) on @thread carrying signed delta @d
         * (low 64 bits; counts live far below that).  @dbg_ordinal is
         * a caller-defined position hint (the audit's CP-entry count)
         * surfaced by CST_LINT_DEBUG so an offender can be located
         * without a full decode pass. */
        void on_count_delta(uint32_t thread, uint32_t template_id,
                            uint32_t ipos, bool is_stores, uint64_t d,
                            uint64_t dbg_ordinal = 0) {
            ThreadState &ts = state_at(thread);
            uint64_t ck = cell_key(template_id, ipos, is_stores);
            uint64_t &cell = ts.cells[ck];
            uint64_t other = 0;
            if (auto it = ts.cells.find(cell_key(template_id, ipos,
                                                 !is_stores));
                it != ts.cells.end()) {
                other = it->second;
            }
            uint64_t old_total = cell + other;
            cell += d;                       /* mod 2^64, matches Wide */
            uint64_t new_total = cell + other;
            Agg &agg = ts.per_template[template_id];
            agg.memops += new_total - old_total;
            if (old_total == 0 && new_total != 0) {
                agg.insns++;
                if (lint_.distinct_mem_.insert(
                        insn_key(template_id, ipos)).second &&
                    lint_.debug_) {
                    std::fprintf(stderr,
                                 "cst lint: impossible memops on template %u "
                                 "insn[%u] (count %llu, near CP entry %llu)\n",
                                 template_id, ipos,
                                 (unsigned long long)new_total,
                                 (unsigned long long)dbg_ordinal);
                }
            } else if (old_total != 0 && new_total == 0) {
                agg.insns--;
            }
            active_ = true;
        }

        /* End of one CP ENTRY on (thread, template_id): charge the
         * still-nonzero impossible counts to this entry. */
        void on_cp_entry_end(uint32_t thread, uint32_t template_id) {
            if (!active_ || thread >= threads_.size()) return;
            ThreadState &ts = threads_[thread];
            auto it = ts.per_template.find(template_id);
            if (it == ts.per_template.end() || it->second.insns == 0) return;
            lint_.mem_memops_ += it->second.memops;
        }

    private:
        struct Agg {
            uint64_t memops = 0;   /* Σ counts on currently-violating insns */
            uint32_t insns  = 0;   /* violating insns with nonzero counts   */
        };
        struct ThreadState {
            std::unordered_map<uint64_t, uint64_t> cells;
            std::unordered_map<uint32_t, Agg>      per_template;
        };

        ThreadState &state_at(uint32_t thread) {
            if (thread >= threads_.size()) {
                threads_.resize((size_t)thread + 1);
            }
            return threads_[thread];
        }
        static uint64_t cell_key(uint32_t tid, uint32_t ipos, bool stores) {
            return ((uint64_t)tid << 32) | ((uint64_t)ipos << 1) |
                   (stores ? 1u : 0u);
        }

        AttributionLint &lint_;
        std::vector<ThreadState> threads_;
        bool active_ = false;
    };

private:
    static uint64_t insn_key(uint32_t template_id, uint32_t ipos) {
        return ((uint64_t)template_id << 32) | ipos;
    }

    std::unordered_map<uint32_t, std::vector<uint8_t>> rows_;
    std::vector<int16_t> dst_slot_;
    bool reg_enabled_;
    /* CST_LINT_DEBUG=1: print each first-seen offending insn to
     * stderr so a flagged trace names its offenders without a
     * separate dump pass. */
    bool debug_;

    uint64_t mem_memops_    = 0;
    uint64_t reg_records_   = 0;
    uint64_t dangling_refs_ = 0;
    std::unordered_set<uint64_t> distinct_mem_;
    std::unordered_set<uint64_t> distinct_reg_;
    std::unordered_set<uint32_t> distinct_dangling_;
};

}  /* namespace cst */
