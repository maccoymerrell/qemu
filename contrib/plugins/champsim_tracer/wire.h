/*
 * ChampSim Tracer - wire encoding of the .cst members.
 *
 * Copyright (C) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Everything here is dictated by docs/format.rst, the wire contract; the
 * section numbers in the comments are that document's.
 */
#ifndef CHAMPSIM_TRACER_WIRE_H
#define CHAMPSIM_TRACER_WIRE_H

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "container.h"
#include "vocab.h"

namespace cst {

/* Constants section: the format-epoch identifier. */
constexpr uint32_t kMagic = 0x1E545343;

/* A growable little-endian byte sink with the format's primitives. */
class Bytes {
public:
    void u8(uint8_t v) { buf_.push_back(v); }
    void u32(uint32_t v);
    void u64(uint64_t v);
    void f64(double v);
    void uleb(uint64_t v);
    void sleb(int64_t v);
    void sleb_wide(const uint64_t *limb, int n);    /* n limbs, two's complement */
    void str(const std::string &s);        /* string  := len:ULEB bytes */
    void section(const Bytes &payload);    /* section := len:ULEB payload */
    void raw(const Bytes &o) { buf_.insert(buf_.end(), o.buf_.begin(), o.buf_.end()); }
    const std::vector<uint8_t> &data() const { return buf_; }
    void clear() { buf_.clear(); }

private:
    std::vector<uint8_t> buf_;
};

/* The facts the header states (Step 2).  Nothing else is claimed. */
struct HeaderFacts {
    uint8_t isa = 0;
    std::string command;
    std::string datetime;
    std::string comment;
    std::string target_name;
    bool system = false;    /* system mode: SYSTEM and FAULT are claimed */
    /* the targeted window (section 3) and warmup_end_trace_insn_idx */
    uint64_t start = 0, warmup = 0, total = 0, warm_end = 0;
    double weight = 0.0;
};

/* Returns the TraceISA byte for a QEMU target name, or -1 if not traced. */
int isa_for_target(const std::string &target_name);

/*
 * The registers an instruction may read and write, as QEMU states them
 * (qemu_plugin_insn_reg_list), in the wire's GenericRegId (section 5.4):
 * @id per slot, first appearance first, the order the dependency and
 * lane masks index.  @snap[k] is the gdb handle DST_REG{k} is read
 * through (null: no snapshot, or the constant zero register when
 * @id is REG_ZERO); @opaque names what the statement could not state.
 * @acc is the access statement (qemu_plugin_insn_access_list()) in these
 * slots: per access its direction, address form and the src slots its
 * address reads (-1 none), and the slot it moves -- dst for a load, src
 * for a store (-1 unstated, -2 a constant); @aflags its HELPERS /
 * BRANCHES bits; @acc_varies: a retranslation stated another.
 */
struct Acc {
    uint8_t dir, form;
    int8_t base, index, seg, reg;
    bool operator==(const Acc &o) const
    {
        return dir == o.dir && form == o.form && base == o.base &&
               index == o.index && seg == o.seg && reg == o.reg;
    }
};
struct Regs {
    std::vector<uint8_t> src, dst;
    std::vector<void *> snap;
    const char *opaque = nullptr;
    std::vector<Acc> acc;
    uint8_t aflags = 0;
    bool acc_varies = false;
    bool operator==(const Regs &o) const { return src == o.src && dst == o.dst; }
};
/* GenericRegId values this writer assigns, in section 5.4's bands */
enum : uint8_t {
    kRegGpr = 1, kRegAccHi = 61, kRegFpr = 65, kRegVec = 129, kRegPred = 193,
    kRegSeg = 225, kRegCtrl = 231, kRegBound = 233, kRegAcc = 237,
    kRegZero = 241, kRegMatrix, kRegSys, kRegFcsr, kRegVctrl, kRegTls,
    kRegVstart, kRegDspctrl, kRegVcsr, kRegSp, kRegFlags, kRegIp, kRegLr,
    kRegFp,
};

/*
 * One template (section 6): a true basic block as a pc/size/bytes list.
 * @terminated says its last instruction was learned to end a block, which
 * is all fall_through_pc states; nothing else about the branch is claimed.
 * @id is the interned instruction; @fanout, the engine's bulk account named
 * it.  @dep_mask_len is the LOAD (0) / STORE (1) DEPENDENCY MASK LENGTH, the
 * wire's max_dep_loads / max_dep_stores: how many load / store positions
 * every dependency mask of the instruction spans.  It is NOT a memop count:
 * how many memops an execution performed is that entry's N_LOADS / N_STORES.
 * Filled as the widest count any one entry delivered, so it never under-
 * sizes a mask a delivered memop needs.  @sys: CST_INSN_FLAG_SYSTEM.
 */
struct WireInsn {
    uint64_t pc; uint8_t size; const uint8_t *bytes; uint32_t id; bool fanout;
    uint8_t dep_mask_len[2];
    const Regs *regs;
    bool sys;
    const Class *cls;   /* its class (vocab.h); fan-out makes it BRANCH_REP */
};
/* @bpos: the instruction whose transfer ends it (-1: none, a page split) */
struct WireTemplate { std::vector<WireInsn> insns; bool terminated; int bpos; };

/*
 * The should-be-static tripwire (maintainer ruling 2026-09-25): per
 * instruction, how many executions delivered each (loads << 32 | stores)
 * count -- correct path [0], wrong path [1], and a wrong-path execution
 * cut by its own fault [2], which is not a variance.  Decode fixes nearly
 * every instruction's count, so one outside the fan-out account whose
 * count varies is a finding.  Side log only; never on the wire.
 */
struct MemopCensus {
    struct Row { const WireInsn *insn; std::map<uint64_t, uint64_t> hist[3]; };
    std::map<uint32_t, Row> rows;
};

/*
 * One memory access as the callback stated it (sections 5.2, 5.3): @pos is
 * the instruction's index in its block, @data_ok says a value came with it,
 * @fault that the wrong path was served a placeholder (section 4.4).  With
 * @reg = k + 1 it is instead destination register k's value after the
 * instruction (section 5.4): @size bytes, the first 16 in @lo/@hi, the rest
 * at @addr in the snapshot arena.
 */
struct Memop {
    uint64_t addr, lo, hi;
    uint32_t pos;
    uint8_t size;
    uint8_t store : 1, data_ok : 1, fault : 1;
    uint8_t reg;
};

/*
 * The run's memops, spilled as they seal in a compact variable-length
 * record -- flags, position, size, register, then only the significant
 * bytes of address and value -- and named by byte offset.
 */
class MemSpill : public Spill<uint8_t> {
public:
    void push_back(const Memop &m);
    Memop read(size_t &at) const;       /* the record at @at; @at passes it */
};

/*
 * One body entry (section 4.2) or wrong-path chain block (4.3) of thread
 * @tid, with the memops at [begin, end) of the memop spill; @base is the
 * block position of the entry's first instruction in the positions those
 * memops carry.  @stop cuts the executed range (0: whole), @fault is the
 * CST_FID_BB_FAULT_INSN (-1: none), @flags the bb_flag bits.  @asid is
 * the address-space label, @depth the fault depth; the branch at @bpos
 * (-1: no outcome) sent control to @succ (5.6); @rf - 1 indexes the
 * REGFILE the entry's context opens with (0: none).
 */
struct WireEntry {
    uint32_t tid, template_id, base;
    size_t begin, end;
    uint32_t stop;
    int32_t fault;
    uint8_t flags;
    uint64_t asid = 0, succ = 0;
    uint32_t depth = 0, rf = 0;
    int32_t bpos = -1;
};
/* Where the body's entries come from: a CP entry and its chain, in order */
using EntrySink = std::function<void(const WireEntry &, const std::vector<WireEntry> &)>;
using EntryFeed = std::function<void(const EntrySink &)>;

/*
 * The header member: magic through the templates section (ids = index).
 * @slots is how many load/store slots the body can address; @census, the
 * memop counts each instruction's executions delivered, against which its
 * dependency block is checked, and @deps receives per instruction the
 * dependency family it carries (or why none) for the side log.
 */
Bytes header_member(const HeaderFacts &facts,
                    const std::vector<WireTemplate> &templates, size_t slots,
                    bool wp, bool regdata, const MemopCensus &census,
                    std::map<uint32_t, std::string> &deps);

/*
 * The body member, written to @fd as it is encoded: lead magic, the
 * opening (asid, thread) declaration of section 4, each entry @feed hands
 * over with its memops as field deltas (section 5) and, with @wp, its
 * chain (section 4.3), then END carrying their count, @count, and the
 * trailing magic.  Each entry's context is switched to as it changes: asid
 * labels are indexed at first sighting, and with @ordinals so are thread
 * ids (system mode; user mode's are the thread indices themselves).  Field
 * state is keyed (asid index, thread), and @regfiles[rf - 1] goes out as
 * REGFILE ahead of the entry that names it.  Returns
 * in @slots the slots it addressed, in each template instruction's
 * @dep_mask_len its dependency mask lengths, and in @census every
 * execution's memop counts.  It keeps the field state in RAM -- threads x
 * static code -- and nothing that grows with the body.  False: a write
 * failed.
 */
bool body_member(int fd, std::vector<WireTemplate> &templates,
                 const EntryFeed &feed, const MemSpill &memops,
                 size_t &slots, size_t &count, bool wp, MemopCensus &census,
                 const Spill<uint8_t> &arena, int isa, bool ordinals,
                 const std::vector<Bytes> &regfiles);

} /* namespace cst */

#endif
