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
 *   (GEN_OP_LOAD / STORE / VEC_* / atomics) are deliberately NOT
 *   exempt: their static memop capability is decode-critical, so a
 *   0/0 template on one of them is exactly the failure this lint
 *   exists to surface.  The Capstone 6.0.0-Alpha7 hole that used to
 *   force an exemption here — access==0 on the MEM operand of aarch64
 *   register-offset / extended-register load-stores and the LSE SWP
 *   family — is closed at the boundary (cap_aarch64_infer_mem_access
 *   in disas/capstone.c, same workaround family as the MIPS MSA / x86
 *   store-move fixes), so those insns now mint their static slots.
 *   Remaining narrow exemptions:
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

#include <algorithm>
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
    /* fid lookup span; ULEB fid space, same bound the other tools use
     * (cst_common.h owns the one definition, sized from the wire's slot
     * ceiling, so this index can never fall behind it). */
    static constexpr size_t  FID_LUT = cst::FID_LUT_SIZE;

    AttributionLint(const Header &h, const std::vector<Template> &templates)
        : reg_enabled_(h.has_reg_data()),
          debug_(std::getenv("CST_LINT_DEBUG") != nullptr)
    {
        /* Exempt opcode classes, resolved by name from the trace's
         * own opcode map so renumbering stays harmless.  Synthetic-EA
         * classes (PREFETCH / CACHE_FLUSH / TLB_FLUSH) record their
         * effective address as a load-style memop even when the
         * operand walker minted no static load slot; PUSH / POP / RET
         * cover the x86 implicit-stack corner encodings (see the
         * header comment).  The explicit memory classes (LOAD / STORE
         * / VEC_*) and atomics are NOT exempt — with the aarch64
         * access-flag boundary workaround in disas/capstone.c their
         * templates always carry static slots, and a 0/0 memory insn
         * is a real decode failure this lint must surface. */
        std::unordered_set<uint64_t> exempt;
        for (const auto &kv : h.maps.opcode) {
            if (kv.second == "GEN_OP_PREFETCH" ||
                kv.second == "GEN_OP_CACHE_FLUSH" ||
                kv.second == "GEN_OP_TLB_FLUSH" ||
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
                    !writes_seg && !exempt.count(I.opcode)) {
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

/*
 * Per-template memop bimodality lint — the D4-class completeness oracle.
 *
 * AttributionLint (above) is one-sided by design: it only rejects a memop
 * on an insn that statically CANNOT produce one.  It has no converse rule,
 * because a memop-capable insn legitimately producing zero memops this
 * execution is common (predication, a zero-count REP, a suppressed
 * fault) — a naive "every execution must match" rule would false-positive
 * on all of those.  That asymmetry is exactly the hole the D4 bug rode
 * through: the plugin's deferred-window-close path emitted the segment's
 * final body entry BEFORE its instructions had run, so the entry carried
 * zero memops for a template whose every other execution carried the
 * same nonzero count — and every existing offline check passed, because
 * "zero memops on a memop-capable insn" is, on its own, unremarkable.
 *
 * This lint closes the hole statistically instead of absolutely: for
 * each memop-capable template, tally how many of its correct-path
 * executions realised at least one memop versus how many realised none.
 * A template that is OVERWHELMINGLY nonzero with a SMALL minority of
 * zero-memop outliers is the D4 signature — one (or a handful) of
 * executions silently lost their memops while the template's normal
 * behaviour is unambiguous.  A template that is legitimately bimodal at
 * scale (heavy predication, a REP loop that is empty as often as not)
 * has a zero-rate the default threshold does not consider an "outlier",
 * so it is not flagged.  Both bounds are tunable — see Config — for a
 * workload whose predication rate genuinely warrants a wider band.
 *
 * Correct-path only: wrong-path wandering is not held to any dataflow
 * contract (same scoping as AttributionLint's MEM/REG rules) — feed this
 * class only from CP field-delta sections.
 *
 * Realised-memop-this-execution signal: CST_FID_N_LOADS / CST_FID_N_STORES
 * are the writer's PERSISTENT per-(template_id, ins_pos) cells (format.rst
 * §5), delta-encoded like every other field — a record is emitted only
 * when the count *changes* from the last observation, not on every
 * execution.  So record PRESENCE in one entry is not a "this insn had
 * memops now" signal (a steady-state repeated count emits nothing after
 * its first observation).  The cell's *reconstructed current value* is
 * the real signal, and — because it is linear — the total memop count
 * across an entire template's insns can be tracked as a single running
 * per-(thread, template_id) accumulator: every N_LOADS/N_STORES delta,
 * regardless of which insn position it targets, is added to that one
 * running total, and the total after an entry's section is fully applied
 * is that execution's realised memop count.  Only zero-vs-nonzero is
 * asked of it, so no per-insn breakdown is needed.
 */
/* Hoisted out of MemopBimodalityLint (rather than nested) so its default
 * member initializers are complete at the point the class below uses
 * `MemopBimodalityConfig()` as a constructor default argument — a nested
 * class's default member initializers are only complete once the
 * ENCLOSING class's definition ends, which is too late for the
 * enclosing class's own constructor to default-construct one. */
struct MemopBimodalityConfig {
    /* A template needs at least this many CP executions before its
     * zero-rate is judged at all — too few samples make "1 zero out of
     * 3" indistinguishable from noise. */
    uint32_t min_execs = 8;
    /* Zero-memop executions at or below this FRACTION of total
     * executions count as "a small minority of outliers" (the D4
     * shape).  Above it, zero is common enough to be the template's own
     * legitimate behaviour (predication, a REP loop that is empty as
     * often as it is not), not a completeness bug. */
    double   max_outlier_rate = 0.10;
};

/*
 * Instructions whose memory access is ARCHITECTURALLY OPTIONAL: the
 * encoding declares a memory operand, but whether any access happens at
 * all is decided at run time by a register value, so a zero-memop
 * execution is the architecture working, not an observation the writer
 * lost.  Such an instruction cannot be held to "every execution realises
 * a memop", which is the whole premise of the bimodality lint below, so
 * its slots are excluded from that lint's running total.
 *
 * This is a static property of the encoding, decided here from the raw
 * bytes the template already carries.  The families:
 *
 *   AArch64 FEAT_MOPS  CPYP/CPYM/CPYE, CPYFP/CPYFM/CPYFE (top byte 0x1D)
 *                      SETP/SETM/SETE, SETGP/SETGM/SETGE (top byte 0x19)
 *     The size register Xn selects how much is transferred; at zero the
 *     helper's transfer loop never runs and the instruction touches no
 *     memory.  glibc routes every memcpy/memmove/memset through these on
 *     a FEAT_MOPS guest, so `memmove(dst, src, 0)` — a routine thing in
 *     a string-heavy program — reaches the wire as a zero-memop
 *     execution of an otherwise busy template.  So does every SMALL
 *     transfer: the prologue form may complete the whole thing on its
 *     own, leaving the main and epilogue forms with nothing to move.
 *     The writer's self-loop fan-out (format.rst §5.2) does not retire
 *     this — it splits an execution into one entry PER MEMORY ACCESS,
 *     and a transfer of nothing still executed the instruction, so it
 *     still owes the wire exactly one zero-memop entry.  Measured: with
 *     this exclusion lifted, a fanned-out memcpy/memset workload flags
 *     four templates at rates of 0.0000-0.0024, all of them legitimate.
 *
 *   RISC-V  SC.W / SC.D  (AMO major opcode, funct5 = 0b00011)
 *     A store-conditional whose reservation address does not match skips
 *     the compare-and-swap entirely and only writes the failure code to
 *     rd, so the failing iteration of an LR/SC retry loop realises no
 *     memop while every successful one realises two.
 *
 * The same class exists elsewhere and is NOT covered here, because no
 * trace has exercised it yet and a guessed encoding would silently blind
 * the lint: MIPS SC/SCD, x86 REP-prefixed string operations entered with
 * RCX == 0, and predicated SVE / masked AVX-512 accesses with an
 * all-false predicate.  The durable fix is a static wire flag set from
 * the writer's own Capstone classification, which would retire this
 * table; see the note in the lint's report.
 */
inline bool memop_is_architecturally_optional(uint8_t isa,
                                              const std::vector<uint8_t> &raw)
{
    if (raw.size() < 4) return false;
    uint32_t w = (uint32_t)raw[0] | ((uint32_t)raw[1] << 8) |
                 ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 24);
    switch (isa) {
    case 2:   /* aarch64 */
        /* Memory Copy and Memory Set class: bits[31:24] select the
         * family (0x19 set, 0x1D copy) and bits[11:10] == 0b01 pin the
         * class against the neighbouring load/store encodings. */
        return (w & 0xFF000C00u) == 0x19000400u ||
               (w & 0xFF000C00u) == 0x1D000400u;
    case 3:   /* riscv64 */
        /* AMO major opcode 0b0101111 with funct5 0b00011 = SC.  funct3
         * is pinned to 2/3 (word/doubleword) so the vector indexed-AMO
         * encodings, which share the major opcode and use funct3 for the
         * element width, cannot be swept in. */
        return (w & 0x7Fu) == 0x2Fu && ((w >> 27) & 0x1Fu) == 0x03u &&
               (((w >> 12) & 0x7u) == 2u || ((w >> 12) & 0x7u) == 3u);
    default:
        return false;
    }
}

class MemopBimodalityLint {
public:
    using Config = MemopBimodalityConfig;

    struct Finding {
        uint32_t template_id;
        uint64_t total;
        uint64_t zero;
        uint64_t nonzero;
        double   rate;      /* zero / total */
    };

    MemopBimodalityLint(uint8_t isa,
                        const std::vector<Template> &templates,
                        Config cfg = Config())
        : cfg_(cfg)
    {
        for (const Template &t : templates) {
            bool mandatory = false, optional = false;
            std::vector<bool> opt(t.insns.size(), false);
            for (size_t i = 0; i < t.insns.size(); i++) {
                const InsnTemplate &I = t.insns[i];
                if (I.max_dep_loads == 0 && I.max_dep_stores == 0) continue;
                if (memop_is_architecturally_optional(isa, I.raw_bytes)) {
                    opt[i] = true;
                    optional = true;
                } else {
                    mandatory = true;
                }
            }
            /* Track only a template that still has a memop-capable insn
             * whose access the architecture cannot suppress.  A template
             * whose whole memop capacity is optional has no "should have
             * realised a memop" contract to violate. */
            if (mandatory) {
                memop_capable_.insert(t.template_id);
                if (optional) optional_slots_[t.template_id] = opt;
            } else if (optional) {
                excluded_templates_++;
            }
        }
    }

    /* Whether @template_id has at least one insn with a nonzero static
     * memop capacity that the architecture cannot suppress — the only
     * templates worth tracking at all. */
    bool tracks(uint32_t template_id) const {
        return memop_capable_.count(template_id) != 0;
    }

    /* One CP CST_FID_N_LOADS/N_STORES delta record for @template_id on
     * @thread at insn position @ipos.  The running total is per-template,
     * not per-insn, so the position only matters for skipping the slots
     * of an architecturally-optional access (see the note above). */
    void on_count_delta(uint32_t thread, uint32_t template_id,
                        uint32_t ipos, uint64_t delta) {
        auto it = optional_slots_.find(template_id);
        if (it != optional_slots_.end() &&
            ipos < it->second.size() && it->second[ipos]) {
            return;
        }
        running_[cell_key(thread, template_id)] += delta;    /* mod 2^64 */
    }

    /* End of one CP ENTRY on (thread, template_id): tally this
     * execution's realised-memop verdict (its running total, post this
     * entry's deltas, is nonzero or not) into the template's histogram.
     * A no-op for a template with no static memop slot at all — its
     * running total is definitionally always zero and uninteresting.
     *
     * @fault_truncated entries are excluded from the population.  An
     * entry carrying fault anchors stopped part-way through its
     * template — in the limit at insn 0, before any memop-capable insn
     * retired — so it never had the chance to realise the template's
     * memops, and the wire records exactly that.  Counting it as a
     * zero-memop outlier would report a completeness loss the trace
     * already explains (the canonical case is a kernel copy loop taking
     * a page fault on its first store).  No strictness is lost: the
     * loss this lint exists to catch is a SILENT one, and a silently
     * dropped memop section carries no anchor. */
    void on_cp_entry_end(uint32_t thread, uint32_t template_id,
                         bool fault_truncated = false) {
        if (!tracks(template_id)) return;
        if (fault_truncated) { truncated_++; return; }
        bool nonzero = running_[cell_key(thread, template_id)] != 0;
        Hist &h = hist_[template_id];
        h.total++;
        if (nonzero) h.nonzero++; else h.zero++;
    }

    /* Templates whose zero-memop rate is a small (but nonzero) minority
     * against an established nonzero majority — the D4 signature.
     * Sorted by descending total executions (busiest offenders first). */
    std::vector<Finding> flagged() const {
        std::vector<Finding> out;
        for (const auto &kv : hist_) {
            const Hist &h = kv.second;
            if (h.total < cfg_.min_execs) continue;
            if (h.zero == 0 || h.nonzero == 0) continue;
            double rate = (double)h.zero / (double)h.total;
            if (rate > cfg_.max_outlier_rate) continue;
            out.push_back({kv.first, h.total, h.zero, h.nonzero, rate});
        }
        std::sort(out.begin(), out.end(),
                  [](const Finding &a, const Finding &b) {
                      return a.total > b.total;
                  });
        return out;
    }

    uint64_t flagged_templates() const { return flagged().size(); }

    /* CP executions excluded from the population because a fault
     * truncated them (reported, so the exclusion is never silent). */
    uint64_t truncated_execs() const { return truncated_; }

    /* Templates left untracked because every memop-capable insn they
     * carry has an architecturally-optional access (reported, so the
     * exclusion is never silent). */
    uint64_t excluded_templates() const { return excluded_templates_; }

    /* Running realised-memop total for (thread, template) — the value
     * on_cp_entry_end() turns into this execution's zero/nonzero
     * verdict.  Exposed for diagnostics only. */
    uint64_t running_total(uint32_t thread, uint32_t template_id) const {
        auto it = running_.find(cell_key(thread, template_id));
        return it == running_.end() ? 0 : it->second;
    }

private:
    struct Hist {
        uint64_t total = 0, zero = 0, nonzero = 0;
    };
    static uint64_t cell_key(uint32_t thread, uint32_t template_id) {
        return ((uint64_t)thread << 32) | template_id;
    }

    Config cfg_;
    uint64_t truncated_ = 0;              /* fault-truncated, excluded */
    uint64_t excluded_templates_ = 0;     /* all-optional, untracked */
    std::unordered_set<uint32_t> memop_capable_;
    /* tid -> per-ipos "this slot's access is architecturally optional",
     * present only for a MIXED template (some optional, some not). */
    std::unordered_map<uint32_t, std::vector<bool>> optional_slots_;
    std::unordered_map<uint64_t, uint64_t> running_;   /* (thread,tid)->total */
    std::unordered_map<uint32_t, Hist> hist_;          /* tid -> histogram */
};

}  /* namespace cst */
