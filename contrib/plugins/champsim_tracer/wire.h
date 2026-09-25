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
#include <map>
#include <string>
#include <vector>

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
    void sleb_wide(const uint64_t limb[3]);    /* 192-bit two's complement */
    void str(const std::string &s);        /* string  := len:ULEB bytes */
    void section(const Bytes &payload);    /* section := len:ULEB payload */
    void raw(const Bytes &o) { buf_.insert(buf_.end(), o.buf_.begin(), o.buf_.end()); }
    const std::vector<uint8_t> &data() const { return buf_; }

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
};

/* Returns the TraceISA byte for a QEMU target name, or -1 if not traced. */
int isa_for_target(const std::string &target_name);

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
 * sizes a mask a delivered memop needs.
 */
struct WireInsn {
    uint64_t pc; uint8_t size; const uint8_t *bytes; uint32_t id; bool fanout;
    uint8_t dep_mask_len[2];
};
struct WireTemplate { std::vector<WireInsn> insns; bool terminated; };

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
 * @fault that the wrong path was served a placeholder (section 4.4).
 */
struct Memop {
    uint64_t addr, lo, hi;
    uint32_t pos;
    uint8_t size;
    bool store, data_ok, fault;
};

/*
 * One body entry (section 4.2) or wrong-path chain block (4.3) of thread
 * @tid, with the memops [begin, end) of the memop array; @base is the
 * block position of the entry's first instruction in the positions those
 * memops carry.  @stop cuts the executed range (0: whole), @fault is the
 * CST_FID_BB_FAULT_INSN (-1: none), @flags the bb_flag bits; a CP entry's
 * chain is [wp_b, wp_e) of the chain-block array.
 */
struct WireEntry {
    uint32_t tid, template_id, base;
    size_t begin, end;
    uint32_t stop;
    int32_t fault;
    uint8_t flags;
    size_t wp_b, wp_e;
};

/*
 * The header member: magic through the templates section (ids = index).
 * @slots is how many load/store slots the body can address.
 */
Bytes header_member(const HeaderFacts &facts,
                    const std::vector<WireTemplate> &templates, size_t slots,
                    bool wp);

/*
 * The body member: lead magic, the opening (asid, thread) declaration of
 * section 4, the entries with their memops as field deltas (section 5),
 * END carrying their count, trailing magic.  @root_phys is the asid-0
 * label (section 4.1a).  With @wp each entry carries its chain of @chains
 * (section 4.3).  Returns in @slots the slots it addressed, in each
 * template instruction's @dep_mask_len its dependency mask lengths, and in
 * @census every execution's memop counts.
 */
Bytes body_member(uint64_t root_phys, std::vector<WireTemplate> &templates,
                  const std::vector<WireEntry> &entries,
                  const std::vector<WireEntry> &chains,
                  const std::vector<Memop> &memops, size_t &slots, bool wp,
                  MemopCensus &census);

} /* namespace cst */

#endif
