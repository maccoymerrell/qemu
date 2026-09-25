/*
 * ChampSim Tracer - true basic blocks, learned from execution.
 *
 * Copyright (C) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * A QEMU TB is not a basic block: a run ends only where control
 * transfers.  With no decoder, a block end is evidence gathered as the
 * guest runs: a lowered jump or trap (translated()), a next pc that is
 * not the fall-through, a syscall, or the engine's fan-out account.
 * Evidence can arrive late -- an indirect transfer whose earlier runs fell
 * through was assembled as straight-line -- so entries name PROVISIONAL
 * shapes and the dictionary is minted at close, after every shape is
 * re-cut at the final set of block ends (recut()).
 */
#ifndef CHAMPSIM_TRACER_BLOCKS_H
#define CHAMPSIM_TRACER_BLOCKS_H

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <vector>

#include "wire.h"

namespace cst {

struct Insn {
    uint64_t pc;
    uint8_t size;
    uint8_t bytes[16];
    bool operator<(const Insn &o) const
    {
        return pc != o.pc ? pc < o.pc : size != o.size ? size < o.size :
               std::memcmp(bytes, o.bytes, size) < 0;
    }
};

using InsnId = uint32_t;
using Shape = std::vector<InsnId>;

/* A translated TB, as the translator exposed it. */
struct TbShape {
    Shape insns;
    int transfer = -1;  /* last insn the translator lowered a jump at */
};

/* The engine's account of the last bulk (fan-out) instruction it ran. */
struct BulkRun {
    uint64_t pc;        /* which instruction the account describes */
    uint64_t units;     /* architectural units this execution retired */
    bool reenter;       /* QEMU will execute the same instruction again */
};

class BlockAssembler {
public:
    InsnId intern(const Insn &i)
    {
        auto it = insn_ids_.emplace(i, InsnId(insns_.size()));
        if (it.second) {
            insns_.push_back(&it.first->first);
            marks_.push_back(0);
        }
        return it.first->second;
    }
    const Insn &insn(InsnId id) const { return *insns_[id]; }

    /* Evidence that @id ends a true BB. */
    void ends_block(InsnId id)
    {
        if (!(marks_[id] & kEnds)) {
            stats.late_ends += (marks_[id] & kFolded) != 0;
            marks_[id] |= kEnds;
        }
    }

    /*
     * A lowered jump, even to its own fall-through, ends the block at the
     * TB's end with the slots QEMU translates after it (MIPS); one whose
     * slots fall in the next TB (a page boundary) ends it there (retire()).
     */
    void translated(const TbShape &tb)
    {
        int tail = int(tb.insns.size()) - 1 - tb.transfer;
        if (tb.transfer >= 0 && tail > 0) {
            slots_ = std::max(slots_, size_t(tail));
        }
        if (tb.transfer >= 0 && (tail > 0 || !slots_)) {
            ends_block(tb.insns.back());
        }
    }

    /* @tb starts executing in thread @tid. */
    void begin(uint32_t tid, const TbShape *tb) { strand(tid).pending = tb; }
    const TbShape *pending(uint32_t tid) { return strand(tid).pending; }

    /*
     * The pending TB of @tid is over: @ran of its instructions started,
     * @bulk (or null) the engine's latest fan-out account, which is this
     * TB's only if it names the TB's last instruction, and @next_pc the pc
     * executing next (0 when the thread stopped).
     */
    void retire(uint32_t tid, size_t ran, const BulkRun *bulk, uint64_t next_pc)
    {
        Strand &s = strand(tid);
        const TbShape *tb = s.pending;
        if (!tb) {
            return;
        }
        s.pending = nullptr;
        size_t n = tb->insns.size();
        InsnId last = tb->insns[n - 1];
        if (ran < n) {
            stats.early_exits++;    /* left mid-TB: ranges come later */
        }
        if (ran < n || (bulk && bulk->pc != insn(last).pc)) {
            bulk = nullptr;
        }
        if (bulk && n == 1 && s.reentered == last) {
            /* A re-entered bulk op: every unit is one self-loop entry. */
            emit_units(tid, last, bulk->units);
        } else {
            for (size_t i = 0; i < ran && i < n; i++) {
                s.open.push_back(tb->insns[i]);
                if (s.slots_due && !--s.slots_due) {
                    ends_block(tb->insns[i]);
                }
                if (ends(tb->insns[i])) {
                    seal(tid, s);
                }
            }
            if (ran == n && tb->transfer == int(n) - 1 && slots_ &&
                !ends(last)) {
                s.slots_due = slots_;   /* the slots run in the next TB */
            }
            if (bulk) {
                ends_block(last);
                seal(tid, s);
                emit_units(tid, last, bulk->units ? bulk->units - 1 : 0);
            }
        }
        s.reentered = bulk && bulk->reenter ? last : kNone;
        if (ran < n) {
            seal(tid, s);
        } else if (next_pc && !s.open.empty()) {
            const Insn &l = insn(last);
            if (next_pc != l.pc + l.size) {
                ends_block(last);
                seal(tid, s);
            } else {
                marks_[last] |= kFolded;
            }
        }
    }

    /* The thread is gone: its unfinished block is published as it is. */
    void finish(uint32_t tid, size_t ran)
    {
        retire(tid, ran, nullptr, 0);
        seal(tid, strand(tid));
    }

    /* Every thread stops; @ran(tid) is how far its last TB got. */
    template <typename Ran> void finish_all(Ran ran)
    {
        for (auto &s : strands_) {
            finish(s.first, ran(s.first));
        }
    }

    /*
     * Re-cut every provisional shape at the final block ends and mint the
     * dictionary from what the body references, numbered in first-
     * reference order.
     */
    void recut(std::vector<WireTemplate> &templates,
               std::vector<WireEntry> &entries)
    {
        std::map<Shape, uint32_t> minted;
        std::vector<std::vector<uint32_t>> pieces(shapes_.size());
        for (const Entry &e : entries_) {
            if (pieces[e.shape].empty()) {     /* every shape has a piece */
                const Shape &sh = *shapes_[e.shape];
                Shape cut;
                for (size_t i = 0; i < sh.size(); i++) {
                    cut.push_back(sh[i]);
                    if (i + 1 == sh.size() || ends(sh[i])) {
                        auto it = minted.emplace(cut, uint32_t(templates.size()));
                        if (it.second) {
                            templates.push_back(wire_template(cut));
                        }
                        pieces[e.shape].push_back(it.first->second);
                        cut.clear();
                    }
                }
                stats.revised_shapes += pieces[e.shape].size() > 1;
            }
            for (uint32_t t : pieces[e.shape]) {
                entries.push_back({ e.tid, t });
            }
        }
        stats.recut_entries = entries.size() - entries_.size();
    }

    struct {
        uint64_t early_exits, late_ends, revised_shapes, recut_entries;
    } stats{};

private:
    static constexpr InsnId kNone = ~InsnId(0);
    enum : uint8_t { kEnds = 1, kFolded = 2 };  /* marks_ bits */

    bool ends(InsnId id) const { return marks_[id] & kEnds; }

    struct Strand {
        const TbShape *pending = nullptr;
        Shape open;                 /* the block assembled so far */
        InsnId reentered = kNone;   /* bulk op QEMU will run again */
        size_t slots_due = 0;       /* insns left before a branch lands */
    };
    struct Entry { uint32_t tid, shape; };

    Strand &strand(uint32_t tid) { return strands_[tid]; }

    uint32_t shape_id(const Shape &sh)
    {
        auto it = shape_ids_.emplace(sh, uint32_t(shapes_.size()));
        if (it.second) {
            shapes_.push_back(&it.first->first);
        }
        return it.first->second;
    }

    void seal(uint32_t tid, Strand &s)
    {
        if (!s.open.empty()) {
            entries_.push_back({ tid, shape_id(s.open) });
            s.open.clear();
        }
        s.slots_due = 0;
    }

    void emit_units(uint32_t tid, InsnId op, uint64_t units)
    {
        uint32_t self = shape_id(Shape{ op });
        for (uint64_t k = 0; k < units; k++) {
            entries_.push_back({ tid, self });
        }
    }

    WireTemplate wire_template(const Shape &sh) const
    {
        WireTemplate t;
        for (InsnId id : sh) {
            const Insn &i = insn(id);
            t.insns.push_back({ i.pc, i.size, i.bytes });
        }
        t.terminated = ends(sh.back());
        return t;
    }

    std::map<Insn, InsnId> insn_ids_;
    std::vector<const Insn *> insns_;
    /* per insn: known to end a block; TB-final and assembled straight on */
    std::vector<uint8_t> marks_;
    std::map<Shape, uint32_t> shape_ids_;
    std::vector<const Shape *> shapes_;
    std::map<uint32_t, Strand> strands_;
    std::vector<Entry> entries_;
    size_t slots_ = 0;              /* learned trailing slots per branch */
};

} /* namespace cst */

#endif
