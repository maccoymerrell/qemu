/*
 * ChampSim Tracer offline tools — format parsers.
 *
 * Reads a .cst file (POSIX-ustar archive carrying body.cst[.<codec>]
 * + header.cst[.<codec>]) into typed cst::Header / cst::Template plus
 * the body member's decoded byte range.  The CstFile loader owns the
 * mmap and, per member, either points into it (uncompressed) or holds
 * a decompressed copy; MemberView ranges live as long as the CstFile.
 *
 * Part of the rippable bundle (see cst_decode.h).  cst_format.cc
 * bundles pure-byte parsers (no I/O), the .cst container open (POSIX
 * mmap), and the codec decompressor subprocess (fork/pipe/wait +
 * execlp of zstd|xz|gzip|bzip2|lz4 `-d -c` on $PATH).  Consumers can
 * instead construct a cst::Reader over their own byte source and
 * bypass cst_file_open / body_stream_open; parse_header takes a
 * MemberView and BodyWalker takes a Reader.
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

/* Carries the mmap + eagerly-decompressed header member.  Construct
 * via cst_file_open; dtor releases mmap + buffer.  The body is NOT
 * decompressed up-front — spawn body_stream_open(*this) to walk
 * records, so header-only consumers (--templates-only) spawn no
 * decompressor and read no body bytes. */
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

    /* Raw (still-compressed if codec'd) body member as a range in the
     * mmap.  Used by body_stream_open to dispatch the decompressor. */
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

/* Open @path as a .cst ustar archive: resolve the two required
 * members, eagerly decompress the header, record the raw body range +
 * codec (opened lazily via body_stream_open).  Throws on a malformed
 * archive or missing member. */
std::unique_ptr<CstFile> cst_file_open(const std::string &path);

/* Streaming body reader: direct memory view for uncompressed bodies,
 * a piped decompressor subprocess for compressed ones; the Reader is
 * identical either way.  Leading CST_MAGIC is verified + stripped at
 * open; trailing CST_MAGIC must be verified via finalize() after
 * BODY_TAG_END.  Destruction without finalize() (e.g. --max early
 * exit) is allowed and tears down the subprocess. */
class BodyStream {
public:
    BodyStream(BodyStream &&) noexcept;
    BodyStream &operator=(BodyStream &&) noexcept;
    BodyStream(const BodyStream &) = delete;
    BodyStream &operator=(const BodyStream &) = delete;
    ~BodyStream();

    /* Body record stream (leading CST_MAGIC consumed; stops at
     * trailing CST_MAGIC, verified by finalize()). */
    Reader &reader() { return reader_; }

    /* Consume the trailing CST_MAGIC + check the subprocess exited
     * cleanly.  Call exactly once after BODY_TAG_END + num_entries.
     * Throws on bad magic or non-zero subprocess exit. */
    void finalize();

private:
    friend std::unique_ptr<BodyStream> body_stream_open(const CstFile &);
    BodyStream() = default;

    Reader                 reader_;
    /* Move-only handle for wait()+verify after finalize. */
    std::unique_ptr<Source> retained_src_;
};

std::unique_ptr<BodyStream> body_stream_open(const CstFile &cf);

/* Parse the header member into a cst::Header (layout in
 * docs/format.rst).  Consumes the entire @view; trailing
 * templates go into @out_templates / @out_by_id. */
Header parse_header(MemberView view,
                    std::vector<Template> *out_templates,
                    std::unordered_map<uint32_t, size_t> *out_by_id);

/* Look up a generic-ID name through Header::maps with a synthetic
 * fallback.  Convenience wrappers used mostly by renderers. */
std::string opcode_name(const Header &h, uint64_t id);
std::string branch_type_name(const Header &h, uint64_t id);
std::string reg_name_or_unknown(const Header &h, uint64_t id);
std::string field_id_name(const Header &h, uint64_t id);

}  /* namespace cst */
