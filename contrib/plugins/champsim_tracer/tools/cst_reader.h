/*
 * ChampSim Tracer offline tools — byte stream reader.
 *
 * Stateful reader over an in-memory buffer (mmap'd .cst) or a
 * Source-backed stream (decompressor pipe).  ULEB/SLEB walkers,
 * length-prefixed string reader, and sub() which carves a
 * length-prefixed sub-section into a bounded reader, advancing the
 * parent cursor past it.  Streaming mode owns a refillable buffer and
 * pulls on demand; sub() materialises the (few-KB) section into a
 * fresh memory-backed sub so the Source stays out of recursion.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace cst {

/* Pull-mode byte source (implementations in cst_format.cc). */
class Source {
public:
    virtual ~Source() = default;
    /* Read up to @n bytes into @out, return count.  0 means EOF
     * (never "not ready yet"); partial reads mid-stream are fine.
     * Throws on I/O error. */
    virtual size_t read(uint8_t *out, size_t n) = 0;
    /* Called once the consumer has drained to EOF; subprocess sources
     * wait() on the child and re-throw on non-zero exit.  No-op by
     * default. */
    virtual void finalize() {}
};

class Reader {
public:
    Reader() = default;
    /* Read from @data over [@begin, @end).  Top-of-file: begin=0;
     * sub() passes the slice bounds explicitly. */
    Reader(const uint8_t *data, size_t begin, size_t end)
        : data_(data), end_(end), pos_(begin) {}

    /* Streaming constructor: pulls from @src on demand into an owned
     * refillable buffer. */
    explicit Reader(std::unique_ptr<Source> src)
        : src_(std::move(src))
    {
        owned_.resize(STREAM_BUFFER_BYTES);
        data_ = owned_.data();
        end_  = 0;     /* nothing buffered yet */
        pos_  = 0;
    }

    Reader(Reader &&o) noexcept { *this = std::move(o); }
    Reader &operator=(Reader &&o) noexcept {
        if (this != &o) {
            src_     = std::move(o.src_);
            owned_   = std::move(o.owned_);
            data_    = o.data_;
            end_     = o.end_;
            pos_     = o.pos_;
            consumed_total_ = o.consumed_total_;
            /* If we own a buffer, rebase data_ to it after the move. */
            if (!owned_.empty()) {
                data_ = owned_.data();
            }
            o.data_ = nullptr;
            o.end_ = 0;
            o.pos_ = 0;
            o.consumed_total_ = 0;
        }
        return *this;
    }
    Reader(const Reader &) = delete;
    Reader &operator=(const Reader &) = delete;

    bool   eof() {
        if (pos_ < end_) return false;
        if (!src_) return true;
        /* Streaming: maybe more bytes to pull. */
        try_refill(1);
        return pos_ >= end_;
    }
    size_t pos() const { return pos_; }
    size_t end() const { return end_; }
    size_t remaining() const { return end_ - pos_; }
    const uint8_t *data() const { return data_; }
    /* Bytes consumed since construction (includes bytes shifted out
     * of a streaming reader's sliding buffer).  Valid for audit
     * per-section byte accounting. */
    size_t consumed() const { return consumed_total_ + pos_; }

    void seek(size_t p) {
        if (src_) throw std::runtime_error("seek on streaming reader");
        if (p > end_) throw std::runtime_error("reader seek past end");
        pos_ = p;
    }

    /* Finalize the Source if any (subprocess wait+check); no-op on
     * memory-backed Readers. */
    void finalize_source() {
        if (src_) src_->finalize();
    }

    uint8_t u8() {
        ensure(1);
        return data_[pos_++];
    }

    uint32_t u32_le() {
        ensure(4);
        uint32_t v;
        std::memcpy(&v, data_ + pos_, 4);
        pos_ += 4;
        return v;
    }

    uint64_t u64_le() {
        ensure(8);
        uint64_t v;
        std::memcpy(&v, data_ + pos_, 8);
        pos_ += 8;
        return v;
    }

    void raw(uint8_t *out, size_t n) {
        while (n > 0) {
            ensure(1);
            size_t take = end_ - pos_;
            if (take > n) take = n;
            std::memcpy(out, data_ + pos_, take);
            pos_ += take;
            out += take;
            n   -= take;
        }
    }

    std::string raw_string(size_t n) {
        std::string s;
        s.resize(n);
        raw(reinterpret_cast<uint8_t *>(s.data()), n);
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

    /*
     * Skip a LEB128 varint without decoding (no overflow guard).
     * Used by audit to advance past sleb_wide deltas that may exceed
     * 64 bits and would trip uleb()/sleb()'s overflow checks.
     */
    void skip_varint() {
        while (true) {
            uint8_t b = u8();
            if (!(b & 0x80)) return;
        }
    }

    /*
     * Unsigned wide ULEB packed into 8 LE limbs (512-bit).  Used for
     * EXTRA_LOAD_DATA / EXTRA_STORE_DATA, which can span the full
     * vector-register width; uleb() would truncate/throw.  Like
     * sleb_wide() without terminator sign-extension. */
    std::array<uint64_t, 8> uleb_wide() {
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
                return out;
            }
            if (shift > 8 * 64) {
                throw std::runtime_error("ULEB128 too large");
            }
        }
    }

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
     * the slice and advance the parent past it.  Zero-copy view for
     * memory-backed parents; a fresh owned buffer for streaming. */
    Reader sub() {
        uint64_t n = uleb();
        if (src_) {
            std::vector<uint8_t> tmp(n);
            raw(tmp.data(), n);
            Reader r;
            r.owned_ = std::move(tmp);
            r.data_  = r.owned_.data();
            r.end_   = n;
            r.pos_   = 0;
            return r;
        }
        check_mem(n);
        size_t start = pos_;
        pos_ += n;
        return Reader(data_, start, start + n);
    }

private:
    static constexpr size_t STREAM_BUFFER_BYTES = 64 * 1024;

    /* Memory-backed bounds check (used by sub() on mmap Readers). */
    void check_mem(size_t n) const {
        if (pos_ + n > end_) {
            throw std::runtime_error("reader past end");
        }
    }

    /* Ensure at least @n bytes are available at data_[pos_..end_).
     * For memory-backed Readers this is just a bounds check.  For
     * streaming Readers it shifts the buffer and pulls more from
     * the Source as needed. */
    void ensure(size_t n) {
        if (pos_ + n <= end_) return;
        if (!src_) {
            throw std::runtime_error("reader past end");
        }
        try_refill(n);
        if (pos_ + n > end_) {
            throw std::runtime_error("reader past end of stream");
        }
    }

    /* Best-effort refill: shift the remaining bytes to the front of
     * the buffer and pull more from src_ until at least @want bytes
     * are buffered or the source is exhausted.  Caller checks
     * post-condition. */
    void try_refill(size_t want) {
        if (!src_) return;
        if (pos_ > 0) {
            size_t kept = end_ - pos_;
            if (kept > 0) {
                std::memmove(owned_.data(), owned_.data() + pos_, kept);
            }
            consumed_total_ += pos_;
            pos_ = 0;
            end_ = kept;
        }
        while (end_ < want && end_ < owned_.size()) {
            size_t r = src_->read(owned_.data() + end_,
                                  owned_.size() - end_);
            if (r == 0) break;
            end_ += r;
        }
    }

    std::unique_ptr<Source> src_;
    std::vector<uint8_t>    owned_;
    const uint8_t          *data_ = nullptr;
    size_t                  end_  = 0;
    size_t                  pos_  = 0;
    /* For streaming readers: cumulative bytes shifted out of the
     * sliding buffer; consumed() returns this + pos_. */
    size_t                  consumed_total_ = 0;
};

}  /* namespace cst */
