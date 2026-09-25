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
    void str(const std::string &s);        /* string  := len:ULEB bytes */
    void section(const Bytes &payload);    /* section := len:ULEB payload */
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

/* The header member: magic through the (empty) templates section. */
Bytes header_member(const HeaderFacts &facts);

/*
 * The body member of a segment with no entries: lead magic, the opening
 * (asid, thread) declaration of section 4, END carrying a count of 0,
 * trailing magic.  @root_phys is the asid-0 label (section 4.1a).
 */
Bytes empty_body_member(uint64_t root_phys);

} /* namespace cst */

#endif
