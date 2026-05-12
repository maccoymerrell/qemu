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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "cst_common.h"
#include "cst_reader.h"

namespace cst {

/* Opaque carrier of the mmap + any decompressed-member buffers.
 * Use cst_file_open to construct; destruction releases the mmap +
 * temp buffers. */
class CstFile {
public:
    ~CstFile();
    CstFile(CstFile &&) noexcept;
    CstFile &operator=(CstFile &&) noexcept;
    CstFile(const CstFile &) = delete;
    CstFile &operator=(const CstFile &) = delete;

    MemberView body()   const { return body_;   }
    MemberView header() const { return header_; }

    /* Filename of the underlying .cst on disk, for diagnostics. */
    const std::string &path() const { return path_; }

private:
    CstFile() = default;
    friend std::unique_ptr<CstFile> cst_file_open(const std::string &);

    std::string path_;
    const uint8_t *map_ = nullptr;
    size_t map_size_ = 0;
    /* Decompressed-member buffers, if any.  body_/header_ point
     * either into @map_ (uncompressed member) or into one of these
     * buffers (decompressed member). */
    std::vector<uint8_t> body_buf_;
    std::vector<uint8_t> header_buf_;
    MemberView body_{};
    MemberView header_{};
};

/* Open @path as a .cst (outer ustar archive).  Resolves the two
 * required members (body.cst[.<codec>] + header.cst[.<codec>]),
 * dispatches the matching decompressor per the suffix (.zst / .xz
 * / .gz / .bz2 / .lz4 — falls back to shelling out to the
 * matching CLI), and returns a CstFile carrying the two byte
 * ranges.  Throws std::runtime_error on a malformed archive or
 * missing member. */
std::unique_ptr<CstFile> cst_file_open(const std::string &path);

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

/* Validate the body member's leading and trailing CST_MAGIC and
 * return a MemberView covering just the BODY_TAG_* record stream
 * (with the leading magic skipped; the trailing magic is verified
 * but excluded).  Throws std::runtime_error on a truncated body. */
MemberView body_records_view(MemberView body_member);

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
