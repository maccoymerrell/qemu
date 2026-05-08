/*
 * ChampSim Tracer offline tools — byte stream reader.
 *
 * Stateful reader over an in-memory buffer (typically an mmap'd .cst
 * file).  Mirrors champsim_tracer_decode.py's ByteReader: ULEB / SLEB
 * walkers, length-prefixed string reader, and a sub() helper that
 * carves a length-prefixed sub-section into its own bounded reader so
 * the parent's cursor advances past it cleanly.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

namespace cst {

class Reader {
public:
    Reader() = default;
    /* Read from @data over [@begin, @end).  When constructing a
     * top-of-file reader pass begin=0; when carving a subrange via
     * sub() the helper passes the slice's bounds explicitly. */
    Reader(const uint8_t *data, size_t begin, size_t end)
        : data_(data), end_(end), pos_(begin) {}

    bool   eof() const { return pos_ >= end_; }
    size_t pos() const { return pos_; }
    size_t end() const { return end_; }
    size_t remaining() const { return end_ - pos_; }
    const uint8_t *data() const { return data_; }

    void seek(size_t p) {
        if (p > end_) throw std::runtime_error("reader seek past end");
        pos_ = p;
    }

    uint8_t u8() {
        check(1);
        return data_[pos_++];
    }

    uint32_t u32_le() {
        check(4);
        uint32_t v;
        std::memcpy(&v, data_ + pos_, 4);
        pos_ += 4;
        return v;
    }

    uint64_t u64_le() {
        check(8);
        uint64_t v;
        std::memcpy(&v, data_ + pos_, 8);
        pos_ += 8;
        return v;
    }

    void raw(uint8_t *out, size_t n) {
        check(n);
        std::memcpy(out, data_ + pos_, n);
        pos_ += n;
    }

    std::string raw_string(size_t n) {
        check(n);
        std::string s(reinterpret_cast<const char *>(data_ + pos_), n);
        pos_ += n;
        return s;
    }

    uint64_t uleb() {
        uint64_t out = 0;
        unsigned shift = 0;
        while (true) {
            uint8_t b = u8();
            out |= uint64_t(b & 0x7F) << shift;
            if (!(b & 0x80)) return out;
            shift += 7;
            if (shift >= 64) throw std::runtime_error("ULEB128 too large");
        }
    }

    /* Signed LEB sized to fit int64_t.  Used for compact deltas
     * (template-id delta, ipos delta, immediate, etc.); not safe
     * for wide-data deltas which can be > 64 bits — use sleb_wide()
     * for those. */
    int64_t sleb() {
        uint64_t out = 0;
        unsigned shift = 0;
        while (true) {
            uint8_t b = u8();
            out |= uint64_t(b & 0x7F) << shift;
            shift += 7;
            if (!(b & 0x80)) {
                if (shift < 64 && (b & 0x40)) {
                    out |= ~uint64_t(0) << shift;
                }
                return static_cast<int64_t>(out);
            }
            if (shift >= 64) throw std::runtime_error("SLEB128 too large");
        }
    }

    /* Wide signed LEB sized to fit a 512-bit Wide value, sign-
     * extended.  Used for the delta field of every scalar record in
     * the field-delta stream; data and dst-reg values can be up to
     * 512 bits, and the delta of two such values can also span the
     * full width.  Returns the decoded value packed into 8 little-
     * endian limbs.  The caller adds it modulo 2^N (128 or 512)
     * to the running base. */
    std::array<uint64_t, 8> sleb_wide() {
        std::array<uint64_t, 8> out{};
        unsigned shift = 0;
        while (true) {
            uint8_t b = u8();
            uint64_t chunk = (uint64_t)(b & 0x7F);
            unsigned limb = shift / 64;
            unsigned bit  = shift % 64;
            if (limb < 8) {
                out[limb] |= chunk << bit;
                if (bit + 7 > 64 && limb + 1 < 8) {
                    out[limb + 1] |= chunk >> (64 - bit);
                }
            }
            shift += 7;
            if (!(b & 0x80)) {
                /* Sign-extend if the high bit of the final group is
                 * set.  shift now points one past the end of the
                 * meaningful bits. */
                if (b & 0x40) {
                    while (shift < 8 * 64) {
                        unsigned l = shift / 64;
                        unsigned bb = shift % 64;
                        out[l] |= ~uint64_t(0) << bb;
                        shift = (l + 1) * 64;
                    }
                }
                return out;
            }
            if (shift > 8 * 64) {
                throw std::runtime_error("SLEB128 too large");
            }
        }
    }

    std::string string() {
        uint64_t n = uleb();
        if (n == 0) return {};
        return raw_string(n);
    }

    /* Read a ULEB length + that many bytes; return a Reader scoped to
     * the slice and advance the parent cursor past it. */
    Reader sub() {
        uint64_t n = uleb();
        check(n);
        size_t start = pos_;
        pos_ += n;
        return Reader(data_, start, start + n);
    }

private:
    void check(size_t n) const {
        if (pos_ + n > end_) {
            throw std::runtime_error("reader past end");
        }
    }

    const uint8_t *data_ = nullptr;
    size_t         end_  = 0;
    size_t         pos_  = 0;
};

}  /* namespace cst */
