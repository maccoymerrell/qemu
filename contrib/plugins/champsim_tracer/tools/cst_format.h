/*
 * ChampSim Tracer offline tools — format parsers.
 *
 * Reads a .cst file (an outer POSIX-ustar archive carrying two
 * regular-file members, ``body.cst[.<codec>]`` and
 * ``header.cst[.<codec>]``) and produces fully-typed cst::Header /
 * cst::Template values plus the body member's decoded byte range.
 *
 * The CstFile loader owns the mmap of the .cst path and, for each
 * member, either points back into the mmap (uncompressed member) or
 * holds a decompressed copy.  The two MemberView byte ranges remain
 * valid as long as the owning CstFile does.
 *
 * ===== Portability / embedding =====
 *
 * This header is part of the "rippable bundle" documented in
 * cst_decode.h.  cst_format.cc bundles three layers:
 *
 *   - Pure-byte parsers (parse_header, parse_templates, ustar
 *     walking, name lookups) — no I/O, no syscalls.  Portable.
 *
 *   - .cst container open (CstFile / cst_file_open) — uses POSIX
 *     mmap to project the on-disk archive into memory.
 *
 *   - Decompressor subprocess (ChildProcessSource, used by
 *     body_stream_open when the body member carries a codec suffix)
 *     — uses fork / pipe / wait, plus an execlp() of the codec
 *     binary on $PATH (`zstd -d -c`, `xz -d -c`, `gzip -d -c`,
 *     `bzip2 -d -c`, `lz4 -d -c`).
 *
 * Downstream consumers on POSIX hosts get the entire stack
 * (including transparent decompression of zstd/xz/gzip/bzip2/lz4
 * bodies) by just dropping this file onto their build.  Consumers
 * who want to provide their own I/O can construct a cst::Reader
 * over their byte source directly and bypass cst_file_open /
 * body_stream_open entirely; parse_header takes a MemberView (a
 * plain (data, size) pair), and BodyWalker takes a Reader.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "cst_common.h"
#include "cst_reader.h"

namespace cst {

/* Opaque carrier of the mmap + the eagerly-decompressed header
 * member.  Use cst_file_open to construct; destruction releases the
 * mmap + buffer.  The body member is NOT decompressed up-front —
 * spawn body_stream_open(*this) once you need to walk the records.
 * For consumers that only need the header (cst_decode
 * --templates-only) this means no decompressor process is spawned
 * and no body bytes are read off disk. */
class CstFile {
public:
    ~CstFile();
    CstFile(CstFile &&) noexcept;
    CstFile &operator=(CstFile &&) noexcept;
    CstFile(const CstFile &) = delete;
    CstFile &operator=(const CstFile &) = delete;

    MemberView header() const { return header_; }

    /* Filename of the underlying .cst on disk, for diagnostics. */
    const std::string &path() const { return path_; }

    /* Raw (still-compressed if a codec was used) body member, as a
     * byte range inside the outer mmap.  Used by body_stream_open
     * to dispatch the decompressor; consumers normally don't touch
     * it directly. */
    MemberView body_raw() const { return body_raw_; }
    /* Codec (zstd / xz / gzip / bzip2 / lz4) inferred from the body
     * member's filename suffix; empty for uncompressed bodies. */
    const std::string &body_codec() const { return body_codec_; }

private:
    CstFile() = default;
    friend std::unique_ptr<CstFile> cst_file_open(const std::string &);

    std::string path_;
    const uint8_t *map_ = nullptr;
    size_t map_size_ = 0;
    /* Eagerly-decompressed header buffer (empty if uncompressed). */
    std::vector<uint8_t> header_buf_;
    MemberView header_{};
    /* Raw body member view into the outer mmap (compressed bytes if
     * a codec suffix is present; otherwise uncompressed payload). */
    MemberView  body_raw_{};
    std::string body_codec_;
};

/* Open @path as a .cst (outer ustar archive).  Resolves the two
 * required members (body.cst[.<codec>] + header.cst[.<codec>]),
 * eagerly decompresses the small header member, and records the
 * raw body byte range plus its codec.  The body is opened lazily
 * via body_stream_open below.  Throws std::runtime_error on a
 * malformed archive or missing member. */
std::unique_ptr<CstFile> cst_file_open(const std::string &path);

/* Streaming body reader.  Wraps the body member with the appropriate
 * source — direct memory view for uncompressed bodies, a piped
 * decompressor subprocess for compressed ones — and the Reader
 * presented to the walker is identical either way.
 *
 * The leading CST_MAGIC is verified at open time and stripped from
 * the Reader's view.  The trailing CST_MAGIC must be verified by
 * calling finalize() after the BODY_TAG_END terminator is consumed;
 * destruction without finalize() is allowed (e.g. for --max early
 * exit) and tears down the decompressor subprocess. */
class BodyStream {
public:
    BodyStream(BodyStream &&) noexcept;
    BodyStream &operator=(BodyStream &&) noexcept;
    BodyStream(const BodyStream &) = delete;
    BodyStream &operator=(const BodyStream &) = delete;
    ~BodyStream();

    /* Reader yielding the body's record stream (leading CST_MAGIC
     * already consumed; stops at trailing CST_MAGIC, which finalize()
     * verifies). */
    Reader &reader() { return reader_; }

    /* Consume the trailing CST_MAGIC and check the decompressor
     * subprocess (if any) exited cleanly.  Call exactly once after
     * the walker has consumed BODY_TAG_END + num_entries.  Throws on
     * mismatched magic or non-zero subprocess exit. */
    void finalize();

private:
    friend std::unique_ptr<BodyStream> body_stream_open(const CstFile &);
    BodyStream() = default;

    Reader                 reader_;
    /* Move-only handle used to call wait()+verify after finalize.
     * Owned by the Source while the Reader is pulling; transferred
     * here when finalize() takes over. */
    std::unique_ptr<Source> retained_src_;
};

std::unique_ptr<BodyStream> body_stream_open(const CstFile &cf);

/* Read the header member's bytes into a populated cst::Header.
 * The header buffer is laid out as documented in
 * champsim_tracer_format.md:
 *
 *     CST_MAGIC u32
 *     isa u8 ; flags u8
 *     start_insn / warmup_insns / total_target_insns (ULEB)
 *     command / datetime / comment / target_name (strings)
 *     encoding maps section (length-prefixed)
 *     templates section
 *
 * The function consumes the entire @view, returning the parsed
 * Header.  Templates parsed out of the trailing templates section
 * are placed into @out_templates / @out_by_id. */
Header parse_header(MemberView view,
                    std::vector<Template> *out_templates,
                    std::unordered_map<uint32_t, size_t> *out_by_id);

/* Look up a generic-ID name through the header's encoding maps,
 * falling back to the built-in tables.  These are convenience
 * wrappers around the maps in Header::maps; used mostly by
 * renderers. */
std::string opcode_name(const Header &h, uint64_t id);
std::string branch_type_name(const Header &h, uint64_t id);
std::string sync_hint_name(const Header &h, uint64_t id);
std::string reg_name_or_unknown(const Header &h, uint64_t id);
std::string field_id_name(const Header &h, uint64_t id);

}  /* namespace cst */
