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
 * re-cut at the final set of block ends (recut()).  A memop travels with
 * the instruction whose callback delivered it, into whichever entry and
 * position that instruction lands in.  A wrong-path excursion runs through
 * the same machinery on the thread's WP strand (tid | kWp); its sealed
 * blocks become the chain of the CP entry that launched it.  Entries,
 * chain blocks and memops are spilled to files as they seal (Spill): RAM
 * holds what scales with the static code and the threads, never the run.
 */
#ifndef CHAMPSIM_TRACER_BLOCKS_H
#define CHAMPSIM_TRACER_BLOCKS_H

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <vector>

#include "wire.h"

namespace cst {

/* @sys: executed above user privilege; the same bytes below it are another */
struct Insn {
    uint64_t pc;
    uint8_t size;
    uint8_t bytes[16];
    bool sys;
    bool operator<(const Insn &o) const
    {
        return pc != o.pc ? pc < o.pc : size != o.size ? size < o.size :
               sys != o.sys ? sys < o.sys : std::memcmp(bytes, o.bytes, size) < 0;
    }
};

/*
 * What a block executed in (section 4.1): the thread and address-space
 * label, the fault depth (5.7) and the privilege.  A change cuts the block.
 */
struct Ctx {
    uint64_t asid = 0;
    uint32_t tid = 0, depth = 0;
    bool sys = false;
    bool operator!=(const Ctx &o) const
    {
        return asid != o.asid || tid != o.tid || depth != o.depth || sys != o.sys;
    }
};

using InsnId = uint32_t;
using Shape = std::vector<InsnId>;

/* A translated TB, as the translator exposed it. */
struct TbShape {
    Shape insns;
    int transfer = -1;  /* last insn the translator lowered a jump at */
    bool indirect = false;  /* ... to a run-time target */
    uint64_t target = 0;    /* ... else to this translator-resolved one */
    /* As translated; each segment interns it at its first execution there */
    std::vector<Insn> raw;
    uint32_t epoch = 0;         /* the segment whose ids insns holds */
    bool end = false;           /* an END marker translated in a gated context */
    std::vector<size_t> traps;  /* conditional traps the translator lowered */
    std::vector<Regs> regs;     /* per insn, the register statement */
    /* where insn k's snapshot callback reads insn k - 1's destinations */
    struct At { const TbShape *tb; uint32_t pos; };
    std::vector<At> at;
};

/* The engine's account of the last bulk (fan-out) instruction it ran. */
struct BulkRun {
    uint64_t pc;        /* which instruction the account describes */
    uint64_t units;     /* architectural units this execution retired */
    bool reenter;       /* QEMU will execute the same instruction again */
};

class BlockAssembler {
public:
    static constexpr uint32_t kWp = 1u << 31;   /* a thread's WP strand */
    enum : uint8_t { kFault = 1, kUnavail = 2, kFirstUnavail = 4, kThreadEnd = 8,
                     kUnresolved = 16 };    /* bb_flag */

    InsnId intern(const Insn &i)
    {
        auto it = insn_ids_.emplace(i, InsnId(insns_.size()));
        if (it.second) {
            insns_.push_back(&it.first->first);
            marks_.push_back(0);
            regs.emplace_back();
            seen_.push_back(false);
        }
        return it.first->second;
    }

    /*
     * Per instruction, the register statement of its first translation;
     * a later translation stating another list is a variance, kept with
     * the list it stated (the reg_list_variance tripwire).
     */
    std::vector<Regs> regs;
    std::vector<std::pair<InsnId, Regs>> variance;
    const Insn &insn(InsnId id) const { return *insns_[id]; }

    /*
     * A TB's first execution states what its translation exposed.  Not at
     * translation: the translation callback runs under QEMU's mmap_lock,
     * which a wrong-path excursion takes while holding the plugin's lock.
     * A TB is translated for one privilege; @sys is the one it runs at.
     * Each segment (@epoch) numbers instructions afresh.
     */
    void absorb(TbShape &tb, bool sys)
    {
        if (tb.epoch == epoch) {
            return;
        }
        tb.epoch = epoch;
        tb.insns.clear();
        for (size_t k = 0; k < tb.raw.size(); k++) {
            tb.raw[k].sys = sys;
            InsnId id = intern(tb.raw[k]);
            tb.insns.push_back(id);
            if (!seen_[id]) {
                regs[id] = tb.regs[k];
                seen_[id] = true;
            } else if (!(regs[id] == tb.regs[k])) {
                variance.push_back({ id, tb.regs[k] });
            }
        }
        for (size_t t : tb.traps) {
            ends_block(tb.insns[t]);    /* a trap, in place */
        }
        if (!tb.raw.empty()) {
            translated(tb);
        }
    }
    uint32_t epoch = 1;

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
        if (tb.transfer >= 0) {
            marks_[tb.insns[tb.transfer]] |= kXfer;
        }
        if (tb.transfer >= 0 && tail > 0) {
            slots_ = std::max(slots_, size_t(tail));
        }
        if (tb.transfer >= 0 && (tail > 0 || !slots_)) {
            ends_block(tb.insns.back());
        }
    }

    /* The callback of the pending TB's instruction @m.pos delivered @m. */
    void memop(uint32_t tid, const Memop &m) { strand(tid).mem.push_back(m); }

    /* @tb starts executing in thread @tid. */
    void begin(uint32_t tid, const TbShape *tb) { strand(tid).pending = tb; }
    const TbShape *pending(uint32_t tid) { return strand(tid).pending; }
    /* @tid left what is traced: its open block ends where it stood */
    void cut(uint32_t tid) { seal(tid, strand(tid), 0); }
    /* Instructions the CP body holds so far, @tid's open block included */
    size_t position(uint32_t tid) { return cp_insns_ + strand(tid).open.size(); }

    /*
     * Strand @tid runs in context @c from its next TB on; the block it has
     * open is cut where the context changed.  @rf (register file index + 1)
     * rides the next entry sealed, the context's first.
     */
    void context(uint32_t tid, const Ctx &c, uint32_t rf = 0)
    {
        Strand &s = strand(tid);
        if (c != s.ctx) {
            seal(tid, s, 0);
            s.ctx = c;
        }
        s.rf = rf ? rf : s.rf;
    }

    /*
     * The pending TB of @tid is over: @ran of its instructions started,
     * @bulk (or null) the engine's latest fan-out account, which is this
     * TB's only if it names the TB's last instruction, and @next_pc the pc
     * executing next (0 when the thread stopped).  @skipped: instruction
     * @ran - 1 raised and was skipped; this execution of the block ends
     * there, as an early exit does (the instruction is not marked).
     */
    void retire(uint32_t tid, size_t ran, const BulkRun *bulk, uint64_t next_pc,
                bool skipped = false)
    {
        Strand &s = strand(tid);
        const TbShape *tb = s.pending;
        std::vector<Memop> mem;
        mem.swap(s.mem);
        if (!tb) {
            return;
        }
        s.pending = nullptr;
        size_t n = skipped ? ran : tb->insns.size();
        InsnId last = tb->insns[n - 1];
        if (ran < n) {
            stats.early_exits++;    /* left mid-TB: ranges come later */
        }
        if (ran < n || (bulk && bulk->pc != insn(last).pc)) {
            bulk = nullptr;
        }
        marks_[last] |= bulk ? kFanout : 0;     /* variable memops: expected */
        /* what ran after the TB's last instruction: a bulk op's next unit first */
        uint64_t after = bulk && bulk->units > 1 ? insn(last).pc : next_pc;
        /* A bulk op's register values follow its last unit, not its shares */
        std::vector<Memop> tail;
        while (bulk && !mem.empty() && mem.back().reg && mem.back().pos == n - 1) {
            tail.insert(tail.begin(), mem.back());
            mem.pop_back();
        }
        /* A bulk op's memops divide in order into one share per unit. */
        size_t own = std::find_if(mem.begin(), mem.end(), [n](const Memop &m) {
            return m.pos == n - 1; }) - mem.begin();
        size_t share = mem.size() - own;
        if (bulk && bulk->units) {
            stats.uneven_fanout += share % bulk->units != 0;
            share /= bulk->units;
        }
        const Memop *m = mem.data(), *cut = m + own + share;
        if (bulk && n == 1 && s.reentered == last) {
            /* A re-entered bulk op: every unit is one self-loop entry. */
            stats.uneven_fanout += !bulk->units && share;
            emit_units(tid, last, bulk->units, m, share, next_pc);
        } else {
            for (size_t i = 0; i < ran && i < n; i++) {
                for (; m < cut && m->pos <= i; m++) {
                    if (m->fault && s.fault < 0) {
                        s.fault = int32_t(s.open.size());
                    }
                    s.omem.push_back(*m);
                    s.omem.back().pos = uint32_t(s.open.size());
                }
                if (skipped && i + 1 == ran && s.fault < 0) {
                    s.fault = int32_t(s.open.size());
                }
                s.open.push_back(tb->insns[i]);
                if (s.slots_due && !--s.slots_due) {
                    ends_block(tb->insns[i]);
                }
                if (ends(tb->insns[i])) {   /* where the next one ran, if seen */
                    seal(tid, s, i + 1 < ran ? insn(tb->insns[i + 1]).pc :
                                 i + 1 == n ? after : 0);
                }
            }
            if (ran == n && tb->transfer == int(n) - 1 && slots_ &&
                !ends(last)) {
                s.slots_due = slots_;   /* the slots run in the next TB */
            }
            if (bulk) {     /* each unit loops to the op; the last leaves */
                ends_block(last);
                seal(tid, s, after);
                emit_units(tid, last, bulk->units ? bulk->units - 1 : 0, m,
                           share, next_pc);
            }
        }
        if (!tail.empty() && (bulk->units || !(n == 1 && s.reentered == last))) {
            Entry e = list(tid).back();
            for (Memop t : tail) {
                t.pos = uint32_t(shapes_[e.shape]->size() - 1);
                keep(t);
            }
            e.mem_e = mems_.size();
            list(tid).set(list(tid).size() - 1, e);
        }
        s.reentered = bulk && bulk->reenter ? last : kNone;
        if (ran < n || skipped) {   /* this execution left the block here */
            seal(tid, s, 0);
        } else if (next_pc && !s.open.empty()) {
            const Insn &l = insn(last);
            if (next_pc != l.pc + l.size) {
                ends_block(last);
                seal(tid, s, next_pc);
            } else {
                marks_[last] |= kFolded;
            }
        }
    }

    /*
     * The thread is gone: its unfinished block is published as it is, the
     * last its context contributes (THREAD_END).  Returns that entry, or
     * kNoEntry when nothing was pending.
     */
    size_t finish(uint32_t tid, size_t ran)
    {
        size_t n = entries_.size();
        retire(tid, ran, nullptr, 0);
        seal(tid, strand(tid), 0);
        if (entries_.size() == n) {
            return kNoEntry;
        }
        Entry e = entries_.back();
        e.flags |= kThreadEnd;
        entries_.set(entries_.size() - 1, e);
        return entries_.size() - 1;
    }

    /*
     * Every thread stops; @ran(tid) is how far its last TB got.  Two
     * strands closing in one context (a shared tid) end it once, last.
     */
    template <typename Ran> void finish_all(Ran ran)
    {
        std::vector<size_t> ended;
        for (auto &s : strands_) {
            ended.push_back(finish(s.first, ran(s.first)));
        }
        std::vector<std::pair<uint32_t, uint64_t>> seen;
        std::sort(ended.rbegin(), ended.rend());
        for (size_t i : ended) {
            Entry e = i != kNoEntry ? entries_[i] : Entry{};
            std::pair<uint32_t, uint64_t> c{ e.ctx.tid, e.ctx.asid };
            if (i != kNoEntry && std::count(seen.begin(), seen.end(), c)) {
                e.flags &= ~kThreadEnd;
                entries_.set(i, e);
            }
            if (i != kNoEntry) {
                seen.push_back(c);
            }
        }
    }
    size_t entries() const { return entries_.size(); }

    /* A wrong-path excursion begins on @wtid's strand, after CP entry @cp. */
    bool wp_begin(uint32_t wtid, uint32_t cp)
    {
        strands_[wtid] = Strand();
        strands_[wtid].ctx = strand(cp).ctx;    /* the thread's real id */
        chain_ = wp_.size();
        wp_insns_ = 0;
        return (cp_ = strand(cp).last) != kNoEntry;
    }
    /* WP instructions attributed so far: sealed, plus the block in flight */
    size_t wp_insns(uint32_t wtid) { return wp_insns_ + strand(wtid).open.size(); }
    size_t wp_blocks() const { return wp_.size() - chain_; }
    bool open_empty(uint32_t tid) { return strand(tid).open.empty(); }

    /*
     * The excursion is over: @unavail, the next fetch could not complete
     * (the block in flight is kept and flagged, or the CP entry is when
     * nothing ran); otherwise the block in flight is past the walk's end.
     */
    void wp_end(uint32_t wtid, bool unavail)
    {
        Strand &s = strand(wtid);
        if (unavail) {
            seal(wtid, s, 0);
        }
        Entry e = entries_[cp_];
        e.wp_b = chain_;
        e.wp_e = wp_.size();
        if (unavail && e.wp_b == e.wp_e) {
            e.flags |= kFirstUnavail;
        } else if (unavail) {
            Entry w = wp_.back();
            w.flags |= kUnavail;
            wp_.set(wp_.size() - 1, w);
        }
        entries_.set(cp_, e);
        strands_.erase(wtid);
    }

    /*
     * Re-cut every provisional shape at the final block ends and mint the
     * dictionary from what the body references, numbered in first-
     * reference order, handing @emit each CP entry's pieces in order, the
     * last with its chain.  A chain is cut so its ranges sum to @depth: the
     * block that crosses it stops there (a fault-marked one runs whole),
     * and nothing after it is attributed (format.rst 4.4).  One pass over
     * the spills, in the order they were written.
     */
    void recut(std::vector<WireTemplate> &templates, size_t depth,
               const EntrySink &emit)
    {
        std::map<Shape, uint32_t> minted;
        std::vector<std::vector<uint32_t>> pieces(shapes_.size());
        auto split = [&](const Entry &e, std::vector<WireEntry> &out) {
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
            size_t m = e.mem_b;
            uint32_t base = 0;
            for (uint32_t t : pieces[e.shape]) {
                uint32_t len = uint32_t(templates[t].insns.size());
                size_t b = m;
                for (size_t at = m; m < e.mem_e && mems_.read(at).pos < base + len;) {
                    m = at;
                }
                bool here = e.fault >= int32_t(base) && e.fault < int32_t(base + len);
                WireEntry w{ e.ctx.tid, t, base, b, m, 0,
                             here ? e.fault - int32_t(base) : -1, 0 };
                w.asid = e.ctx.asid;
                w.depth = e.ctx.depth;
                w.rf = base ? 0 : e.rf;
                if (templates[t].bpos >= 0) {   /* where the next one ran */
                    const Shape &sh = *shapes_[e.shape];
                    size_t k = base + len;
                    w.bpos = templates[t].bpos;
                    w.succ = k < sh.size() ? insn(sh[k]).pc : e.fault < 0 ? e.succ : 0;
                    w.flags = w.succ ? 0 : kUnresolved;
                }
                out.push_back(w);
                base += len;
            }
            out.back().flags |= e.flags & ~kFault;
            stats.recut_entries += pieces[e.shape].size() - 1;
        };
        std::vector<WireEntry> pieces_of, chain, wp, none;
        for (size_t i = 0; i < entries_.size(); i++) {
            const Entry e = entries_[i];
            pieces_of.clear();
            chain.clear();
            wp.clear();
            split(e, pieces_of);
            for (size_t w = e.wp_b; w < e.wp_e; w++) {
                split(wp_[w], chain);
            }
            size_t sum = 0;
            for (WireEntry &c : chain) {
                if (sum >= depth) {
                    break;
                }
                size_t len = templates[c.template_id].insns.size();
                if (sum + len > depth && c.fault < 0) {
                    c.stop = uint32_t(depth - sum);
                    if (c.bpos >= int32_t(c.stop)) {   /* the cut stops short */
                        c.bpos = -1;
                        c.flags &= ~kUnresolved;
                    }
                    size_t end = c.begin;   /* past the last memop it keeps */
                    for (size_t at = c.begin; at < c.end;) {
                        end = mems_.read(at).pos < c.base + c.stop ? at : end;
                    }
                    c.end = end;
                }
                sum += len;
                c.flags |= c.fault >= 0 ? kFault : 0;
                wp.push_back(c);
            }
            for (size_t k = 0; k < pieces_of.size(); k++) {
                emit(pieces_of[k], k + 1 == pieces_of.size() ? wp : none);
            }
        }
    }

    const MemSpill &memops() const { return mems_; }
    /* the files: CP entries, chain blocks, memops */
    std::array<SpillFile *, 3> spills() { return { &entries_, &wp_, &mems_ }; }

    struct {
        uint64_t early_exits, late_ends, revised_shapes, recut_entries,
                 uneven_fanout, memops;
    } stats{};

private:
    static constexpr InsnId kNone = ~InsnId(0);
    static constexpr size_t kNoEntry = ~size_t(0);
    /* marks_ bits; kXfer: the translator lowered a transfer at it */
    enum : uint8_t { kEnds = 1, kFolded = 2, kFanout = 4, kXfer = 8 };

    bool ends(InsnId id) const { return marks_[id] & kEnds; }

    struct Strand {
        const TbShape *pending = nullptr;
        Shape open;                 /* the block assembled so far */
        InsnId reentered = kNone;   /* bulk op QEMU will run again */
        size_t slots_due = 0;       /* insns left before a branch lands */
        std::vector<Memop> mem;     /* the pending TB's, pos = TB index */
        std::vector<Memop> omem;    /* the open block's, pos = its index */
        int32_t fault = -1;         /* open block's first faulting insn */
        size_t last = kNoEntry;     /* its latest sealed entry */
        Ctx ctx;                    /* the context it runs in */
        uint32_t rf = 0;            /* for the next entry: its REGFILE */
    };
    /* memops [mem_b, mem_e); a CP entry's chain is wp_[wp_b, wp_e) */
    struct Entry {
        uint32_t tid, shape;
        size_t mem_b, mem_e, wp_b = 0, wp_e = 0;
        int32_t fault = -1;
        uint8_t flags = 0;
        Ctx ctx;
        uint64_t succ = 0;          /* the pc run next, when observed */
        uint32_t rf = 0;
    };

    Strand &strand(uint32_t tid)
    {
        auto it = strands_.find(tid);
        if (it == strands_.end()) {
            it = strands_.emplace(tid, Strand()).first;
            it->second.ctx.tid = tid & ~kWp;
        }
        return it->second;
    }

    uint32_t shape_id(const Shape &sh)
    {
        auto it = shape_ids_.emplace(sh, uint32_t(shapes_.size()));
        if (it.second) {
            shapes_.push_back(&it.first->first);
        }
        return it.first->second;
    }

    /* The open block is an entry; @succ is the pc that ran next (0: unseen) */
    void seal(uint32_t tid, Strand &s, uint64_t succ)
    {
        if (!s.open.empty()) {
            size_t b = mems_.size();
            for (const Memop &m : s.omem) {
                keep(m);
            }
            Entry e{ tid, shape_id(s.open), b, mems_.size() };
            e.fault = s.fault;
            e.succ = succ;
            add(tid, e, s.open.size());
            s.open.clear();
            s.omem.clear();
            s.fault = -1;
        }
        s.slots_due = 0;
    }

    Spill<Entry> &list(uint32_t tid) { return tid & kWp ? wp_ : entries_; }
    void keep(const Memop &m)
    {
        mems_.push_back(m);
        stats.memops += !m.reg;
    }
    void add(uint32_t tid, Entry e, size_t len)
    {
        Strand &s = strand(tid);
        e.ctx = s.ctx;
        e.rf = s.rf;
        s.rf = 0;
        list(tid).push_back(e);
        strand(tid).last = list(tid).size() - 1;
        (tid & kWp ? wp_insns_ : cp_insns_) += len;
    }

    /* @units self-loop entries of @op, each with the next @share memops. */
    void emit_units(uint32_t tid, InsnId op, uint64_t units, const Memop *m,
                    size_t share, uint64_t next_pc)
    {
        uint32_t self = shape_id(Shape{ op });
        for (uint64_t k = 0; k < units; k++, m += share) {
            size_t b = mems_.size();
            bool fault = false;
            for (size_t j = 0; j < share; j++) {
                Memop x = m[j];
                x.pos = 0;
                keep(x);
                fault |= x.fault;
            }
            Entry e{ tid, self, b, mems_.size() };
            e.fault = fault ? 0 : -1;
            e.succ = k + 1 < units ? insn(op).pc : next_pc;
            add(tid, e, 1);
        }
    }

    WireTemplate wire_template(const Shape &sh) const
    {
        WireTemplate t;
        for (InsnId id : sh) {
            const Insn &i = insn(id);
            t.insns.push_back({ i.pc, i.size, i.bytes, id,
                                (marks_[id] & kFanout) != 0, {}, &regs[id], i.sys });
        }
        t.terminated = ends(sh.back());
        size_t n = sh.size();   /* the transfer ending it: before its slot */
        t.bpos = !t.terminated ? -1 :
                 int(n - 1 - (n > 1 && slots_ && (marks_[sh[n - 2]] & kXfer)));
        return t;
    }

    std::map<Insn, InsnId> insn_ids_;
    std::vector<const Insn *> insns_;
    /* per insn: known to end a block; TB-final and assembled straight on */
    std::vector<uint8_t> marks_;
    std::vector<bool> seen_;
    std::map<Shape, uint32_t> shape_ids_;
    std::vector<const Shape *> shapes_;
    std::map<uint32_t, Strand> strands_;
    Spill<Entry> entries_, wp_;
    size_t chain_ = 0, cp_ = 0, wp_insns_ = 0;  /* the excursion in flight */
    size_t cp_insns_ = 0;
    MemSpill mems_;                 /* every entry's, pos = its index */
    size_t slots_ = 0;              /* learned trailing slots per branch */
};

} /* namespace cst */

#endif
