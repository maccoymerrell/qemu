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
 */
struct WireInsn { uint64_t pc; uint8_t size; const uint8_t *bytes; };
struct WireTemplate { std::vector<WireInsn> insns; bool terminated; };

/*
 * One memory access as the callback stated it (sections 5.2, 5.3): @pos is
 * the instruction's index in its block, @data_ok says a value came with it.
 */
struct Memop {
    uint64_t addr, lo, hi;
    uint32_t pos;
    uint8_t size;
    bool store, data_ok;
};

/*
 * One body entry: the block ran whole in thread @tid (section 4.2), with
 * the memops [begin, end) of the memop array; @base is the block position
 * of the entry's first instruction in the positions those memops carry.
 */
struct WireEntry { uint32_t tid, template_id, base; size_t begin, end; };

/*
 * The header member: magic through the templates section (ids = index).
 * @slots is how many load/store slots the body can address.
 */
Bytes header_member(const HeaderFacts &facts,
                    const std::vector<WireTemplate> &templates, size_t slots);

/*
 * The body member: lead magic, the opening (asid, thread) declaration of
 * section 4, the entries with their memops as field deltas (section 5),
 * END carrying their count, trailing magic.  @root_phys is the asid-0
 * label (section 4.1a).  Returns in @slots the slots it addressed.
 */
Bytes body_member(uint64_t root_phys, const std::vector<WireTemplate> &templates,
                  const std::vector<WireEntry> &entries,
                  const std::vector<Memop> &memops, size_t &slots);

} /* namespace cst */

#endif
