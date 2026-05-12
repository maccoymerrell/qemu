/*
 * ChampSim Tracer offline tools — format parsers (impl).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cst_format.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>

namespace cst {

/* ===== Template parsing (shared) ========================================= */

namespace {

void parse_encoding_maps(Reader &r, EncodingMaps *out)
{
    uint64_t n_maps = r.uleb();
    for (uint64_t i = 0; i < n_maps; i++) {
        std::string name = r.string();
        uint64_t n_entries = r.uleb();
        std::unordered_map<uint64_t, std::string> *target = nullptr;
        if      (name == "opcode")        target = &out->opcode;
        else if (name == "branch_type")   target = &out->branch_type;
        else if (name == "sync_hint")     target = &out->sync_hint;
        else if (name == "reg")           target = &out->reg;
        else if (name == "field_id")      target = &out->field_id;
        else if (name == "header_flag")   target = &out->header_flag;
        else if (name == "insn_flag")     target = &out->insn_flag;
        else if (name == "body_tag")      target = &out->body_tag;
        else if (name == "wp_event_flag") target = &out->wp_event_flag;
        else if (name == "metaflags")     target = &out->metaflags;

        for (uint64_t j = 0; j < n_entries; j++) {
            uint64_t value = r.uleb();
            std::string ename = r.string();
            if (target) (*target)[value] = std::move(ename);
        }
    }
}

void parse_templates_at(Reader &r,
                        std::vector<Template> *out,
                        std::unordered_map<uint32_t, size_t> *out_by_id)
{
    uint64_t n = r.uleb();
    out->reserve(n);
    for (uint64_t i = 0; i < n; i++) {
        Reader sub = r.sub();
        Template t;
        t.template_id     = (uint32_t)sub.uleb();
        t.start_pc        = sub.uleb();
        uint64_t n_insns  = sub.uleb();
        t.fall_through_pc = sub.uleb();
        t.symbol_name     = sub.string();

        uint64_t prev_pc = t.start_pc;
        t.insns.reserve(n_insns);
        for (uint64_t k = 0; k < n_insns; k++) {
            uint64_t delta = sub.uleb();
            uint64_t pc = (prev_pc + delta) & UINT64_MAX;
            prev_pc = pc;

            InsnTemplate I;
            I.pc          = pc;
            I.opcode      = sub.u8();
            I.branch_type = sub.u8();
            uint8_t flags = sub.u8();
            uint8_t n_src = sub.u8();
            uint8_t n_dst = sub.u8();
            I.src_regs.resize(n_src);
            for (auto &x : I.src_regs) x = sub.u8();
            I.dst_regs.resize(n_dst);
            for (auto &x : I.dst_regs) x = sub.u8();
            I.n_loads  = sub.u8();
            I.n_stores = sub.u8();
            I.branch_conditional = (flags & INSN_FLAG_BRANCH_COND) != 0;
            I.has_imm            = (flags & INSN_FLAG_HAS_IMM) != 0;
            I.sync_hint          =
                (flags & INSN_FLAG_SYNC_MASK) >> INSN_FLAG_SYNC_SHIFT;
            if (I.has_imm) I.imm = sub.sleb();
            uint8_t insn_size = sub.u8();
            I.raw_bytes.resize(insn_size);
            sub.raw(I.raw_bytes.data(), insn_size);

            t.insns.push_back(std::move(I));
        }

        if (out_by_id) (*out_by_id)[t.template_id] = out->size();
        out->push_back(std::move(t));
    }
}

/* ===== POSIX-ustar reader ================================================
 *
 * Walks @data scanning for the two known member names; once both are
 * located, returns their byte ranges as views into @data.  Pure-
 * memory: no I/O, no temp files.  Handles regular files at typeflag
 * '0' or '\0' (some tar implementations leave it nul).  Long
 * filenames (>100 bytes) aren't supported — our member names are
 * short and stable. */
struct UstarHeader {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char checksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char padding[12];
};
static_assert(sizeof(UstarHeader) == 512, "ustar header size");

uint64_t parse_octal(const char *field, size_t n)
{
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        char c = field[i];
        if (c == '\0' || c == ' ') break;
        if (c < '0' || c > '7') {
            throw std::runtime_error("tar: bad octal digit");
        }
        v = (v << 3) | (uint64_t)(c - '0');
    }
    return v;
}

struct TarMember {
    std::string name;
    const uint8_t *data;
    size_t size;
};

std::vector<TarMember> walk_tar(const uint8_t *data, size_t size)
{
    std::vector<TarMember> out;
    size_t off = 0;
    while (off + 512 <= size) {
        const UstarHeader *h = (const UstarHeader *)(data + off);
        /* Two consecutive zero blocks = end-of-archive. */
        bool all_zero = true;
        for (size_t i = 0; i < 512; i++) {
            if (((const uint8_t *)h)[i] != 0) { all_zero = false; break; }
        }
        if (all_zero) {
            break;
        }
        /* ustar magic check — be lenient: some writers omit the
         * "ustar\0" magic.  We require either "ustar" magic OR a
         * plausible name + size combination. */
        size_t name_len = strnlen(h->name, sizeof(h->name));
        if (name_len == 0) {
            throw std::runtime_error("tar: header with empty name");
        }
        uint64_t member_size = parse_octal(h->size, sizeof(h->size));
        off += 512;
        if (off + member_size > size) {
            throw std::runtime_error("tar: member extends past EOF");
        }
        char tf = h->typeflag;
        if (tf == '\0' || tf == '0') {
            TarMember m;
            m.name = std::string(h->name, name_len);
            m.data = data + off;
            m.size = (size_t)member_size;
            out.push_back(std::move(m));
        }
        /* Pad member data to 512-byte boundary. */
        size_t padded = (member_size + 511) & ~(size_t)511;
        off += padded;
    }
    return out;
}

/* Dispatch a decompressor based on filename suffix.  Reads @src into
 * @out_buf by piping through the matching CLI (zstd / xz / gzip /
 * bzip2 / lz4).  Throws if no decompressor matches or the child
 * exits non-zero.  An uncompressed (no recognised suffix) member is
 * copied straight from @src into @out_buf.
 *
 * popen-based: yes the cost is a fork+exec but it's a few ms per
 * decompression and avoids dragging in libzstd / liblzma / etc. as
 * link dependencies of the tools. */
std::string codec_from_suffix(const std::string &member_name)
{
    auto ends_with = [&](const char *suf) {
        size_t n = strlen(suf);
        return member_name.size() >= n &&
               member_name.compare(member_name.size() - n, n, suf) == 0;
    };
    if (ends_with(".zst")) return "zstd";
    if (ends_with(".xz"))  return "xz";
    if (ends_with(".gz"))  return "gzip";
    if (ends_with(".bz2")) return "bzip2";
    if (ends_with(".lz4")) return "lz4";
    return "";
}

void decompress_member(const TarMember &m, std::vector<uint8_t> *out_buf)
{
    std::string codec = codec_from_suffix(m.name);
    if (codec.empty()) {
        out_buf->assign(m.data, m.data + m.size);
        return;
    }
    /* Pipe: parent writes @m.data into child's stdin; child writes
     * decompressed bytes back via stdout to a separate pipe. */
    int in_pipe[2];
    int out_pipe[2];
    if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0) {
        throw std::runtime_error("pipe failed");
    }
    pid_t pid = fork();
    if (pid < 0) {
        throw std::runtime_error("fork failed");
    }
    if (pid == 0) {
        dup2(in_pipe[0], 0);
        dup2(out_pipe[1], 1);
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        execlp(codec.c_str(), codec.c_str(), "-d", "-c", (char *)nullptr);
        _exit(127);
    }
    close(in_pipe[0]);
    close(out_pipe[1]);

    /* fork+drain on a separate process for input; this thread reads
     * output.  Use a child for input writes to avoid the deadlock
     * where parent's stdin pipe fills before child has produced any
     * output. */
    pid_t feeder = fork();
    if (feeder < 0) {
        throw std::runtime_error("fork failed");
    }
    if (feeder == 0) {
        const uint8_t *p = m.data;
        size_t remaining = m.size;
        while (remaining > 0) {
            ssize_t n = write(in_pipe[1], p, remaining);
            if (n <= 0) break;
            p += n;
            remaining -= (size_t)n;
        }
        close(in_pipe[1]);
        _exit(0);
    }
    close(in_pipe[1]);

    uint8_t buf[64 * 1024];
    for (;;) {
        ssize_t n = read(out_pipe[0], buf, sizeof(buf));
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("decompress read failed");
        }
        out_buf->insert(out_buf->end(), buf, buf + n);
    }
    close(out_pipe[0]);

    int status = 0;
    waitpid(feeder, nullptr, 0);
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        throw std::runtime_error("decompress (" + codec +
                                 ") exited with non-zero status");
    }
}

}  /* namespace */

/* ===== CstFile loader ==================================================== */

CstFile::~CstFile()
{
    if (map_) {
        munmap((void *)map_, map_size_);
    }
}

CstFile::CstFile(CstFile &&o) noexcept
    : path_(std::move(o.path_)),
      map_(o.map_), map_size_(o.map_size_),
      body_buf_(std::move(o.body_buf_)),
      header_buf_(std::move(o.header_buf_)),
      body_(o.body_), header_(o.header_)
{
    o.map_ = nullptr;
    o.map_size_ = 0;
    o.body_ = {};
    o.header_ = {};
}

CstFile &CstFile::operator=(CstFile &&o) noexcept
{
    if (this != &o) {
        if (map_) munmap((void *)map_, map_size_);
        path_ = std::move(o.path_);
        map_ = o.map_;
        map_size_ = o.map_size_;
        body_buf_ = std::move(o.body_buf_);
        header_buf_ = std::move(o.header_buf_);
        body_ = o.body_;
        header_ = o.header_;
        o.map_ = nullptr;
        o.map_size_ = 0;
    }
    return *this;
}

std::unique_ptr<CstFile> cst_file_open(const std::string &path)
{
    std::unique_ptr<CstFile> cf(new CstFile());
    cf->path_ = path;

    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        throw std::runtime_error("open(" + path + "): " + strerror(errno));
    }
    struct stat st{};
    if (fstat(fd, &st) != 0) {
        ::close(fd);
        throw std::runtime_error("fstat: " + std::string(strerror(errno)));
    }
    void *map = mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    ::close(fd);
    if (map == MAP_FAILED) {
        throw std::runtime_error("mmap: " + std::string(strerror(errno)));
    }
    cf->map_ = (const uint8_t *)map;
    cf->map_size_ = (size_t)st.st_size;

    auto members = walk_tar(cf->map_, cf->map_size_);
    const TarMember *body_m = nullptr;
    const TarMember *header_m = nullptr;
    for (const auto &m : members) {
        /* Strip optional path prefix (rare; we never write one). */
        size_t slash = m.name.find_last_of('/');
        std::string base = (slash == std::string::npos)
            ? m.name : m.name.substr(slash + 1);
        if (base.compare(0, 9, "body.cst") == 0 ||
            base.compare(0, 8, "body.cst") == 0) {
            if (base == "body.cst" ||
                base.compare(0, 9, "body.cst.") == 0) {
                body_m = &m;
                continue;
            }
        }
        if (base == "header.cst" ||
            base.compare(0, 11, "header.cst.") == 0) {
            header_m = &m;
        }
    }
    if (!body_m || !header_m) {
        throw std::runtime_error("missing required tar member(s): " + path);
    }

    /* Decompress (or copy-through) each member into the owned
     * buffers if a codec suffix is present; otherwise point body_/
     * header_ directly into the mmap. */
    if (codec_from_suffix(body_m->name).empty()) {
        cf->body_.data = body_m->data;
        cf->body_.size = body_m->size;
    } else {
        decompress_member(*body_m, &cf->body_buf_);
        cf->body_.data = cf->body_buf_.data();
        cf->body_.size = cf->body_buf_.size();
    }
    if (codec_from_suffix(header_m->name).empty()) {
        cf->header_.data = header_m->data;
        cf->header_.size = header_m->size;
    } else {
        decompress_member(*header_m, &cf->header_buf_);
        cf->header_.data = cf->header_buf_.data();
        cf->header_.size = cf->header_buf_.size();
    }
    return cf;
}

/* ===== Header + templates ================================================ */

Header parse_header(MemberView view,
                    std::vector<Template> *out_templates,
                    std::unordered_map<uint32_t, size_t> *out_by_id)
{
    if (view.size < 8) {
        throw std::runtime_error("header member too small");
    }
    Header h;
    Reader r(view.data, 0, view.size);
    h.magic = r.u32_le();
    if (h.magic != CST_MAGIC) {
        throw std::runtime_error("Bad header magic");
    }
    h.format_version = (uint8_t)((h.magic >> 24) & 0xFF);
    h.isa            = r.u8();
    h.flags          = r.u8();
    h.start_insn         = r.uleb();
    h.warmup_insns       = r.uleb();
    h.total_target_insns = r.uleb();
    h.command     = r.string();
    h.datetime    = r.string();
    h.comment     = r.string();
    h.target_name = r.string();

    /* Length-prefixed encoding-maps section. */
    Reader maps_sub = r.sub();
    parse_encoding_maps(maps_sub, &h.maps);
    if (!maps_sub.eof()) {
        throw std::runtime_error("encoding-map section has trailing bytes");
    }

    /* Templates section consumes the remainder of the header
     * member.  No length prefix on the section itself — it ends at
     * end-of-buffer. */
    if (!r.eof() && out_templates) {
        parse_templates_at(r, out_templates, out_by_id);
    }
    if (!r.eof()) {
        throw std::runtime_error("header member has trailing bytes after templates");
    }
    return h;
}

MemberView body_records_view(MemberView body_member)
{
    if (body_member.size < 8) {
        throw std::runtime_error("body member too small");
    }
    Reader r(body_member.data, 0, body_member.size);
    uint32_t lead = r.u32_le();
    if (lead != CST_MAGIC) {
        throw std::runtime_error("Bad body leading magic");
    }
    /* Trailing magic check: the writer emits BODY_TAG_END +
     * num_entries + CST_MAGIC at end-of-body.  Verify the last 4
     * bytes match CST_MAGIC. */
    if (body_member.size < 8) {
        throw std::runtime_error("body member truncated (no trailing magic)");
    }
    const uint8_t *tail = body_member.data + body_member.size - 4;
    uint32_t trail = (uint32_t)tail[0]
                   | ((uint32_t)tail[1] << 8)
                   | ((uint32_t)tail[2] << 16)
                   | ((uint32_t)tail[3] << 24);
    if (trail != CST_MAGIC) {
        throw std::runtime_error("body member truncated (bad trailing magic)");
    }
    MemberView records;
    records.data = body_member.data + 4;
    records.size = body_member.size - 4 - 4;  /* strip leading + trailing magic */
    return records;
}

/* ===== Name lookups ====================================================== */

static std::string lookup_or(const std::unordered_map<uint64_t, std::string> &m,
                             uint64_t id, const std::string &fallback)
{
    auto it = m.find(id);
    return it == m.end() ? fallback : it->second;
}

std::string opcode_name(const Header &h, uint64_t id)
{
    return lookup_or(h.maps.opcode, id, "OP_" + std::to_string(id));
}
std::string branch_type_name(const Header &h, uint64_t id)
{
    return lookup_or(h.maps.branch_type, id, "BR_" + std::to_string(id));
}
std::string sync_hint_name(const Header &h, uint64_t id)
{
    return lookup_or(h.maps.sync_hint, id, "SYNC_" + std::to_string(id));
}
std::string reg_name_or_unknown(const Header &h, uint64_t id)
{
    auto it = h.maps.reg.find(id);
    if (it != h.maps.reg.end()) return it->second;
    return std::string("UNKNOWN_") + std::to_string(id);
}
std::string field_id_name(const Header &h, uint64_t id)
{
    auto it = h.maps.field_id.find(id);
    if (it != h.maps.field_id.end()) return it->second;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "FID_0x%02x", (unsigned)id);
    return buf;
}

}  /* namespace cst */
