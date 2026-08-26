/*
 * ChampSim Tracer offline tools — objdump-style cosmetic disassembly
 * (impl).  Backend rationale lives in cst_objdump.h.
 *
 * SHAPE.  cst_decode asks for one instruction at a time
 * (render_one), but spawning objdump per instruction would cost a
 * process per line.  So the caller primes the renderer with every
 * (pc, bytes) pair the templates section holds, and prefetch_run()
 * turns that set into a handful of objdump invocations: the pcs are
 * sorted, grouped into contiguous address regions, and each region is
 * materialised as a raw binary image that objdump linearly sweeps
 * with --adjust-vma set to the region base.  Holes between
 * instructions are packed with a one-instruction filler encoding so
 * the sweep stays in phase and every requested address is a decode
 * boundary.
 *
 * Every line objdump prints is checked against the bytes we asked
 * about before it is accepted, so a sweep that fell out of phase (x86
 * blocks that overlap mid-instruction) yields a miss and a one-shot
 * re-run, never a wrong rendering.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cst_objdump.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace cst {

namespace {

/* ---- per-ISA objdump configuration ---------------------------------- */

struct IsaSpec {
    const char   *machine;      /* objdump -m                           */
    const char   *endian;       /* --endian=<x>, nullptr to leave alone */
    const char   *progs[5];     /* candidate programs, nullptr-terminated */
    uint8_t       filler[4];    /* a 1-instruction encoding, non-zero   */
    size_t        filler_len;
    uint8_t       probe[4];     /* must disassemble, or the program is  */
    size_t        probe_len;    /* rejected for this ISA                */
};

/* Fillers are real single instructions so the linear sweep resynchronises
 * at every instruction boundary, and non-zero so objdump never collapses a
 * run of them into "...".  Probes are unambiguous encodings of the ISA. */
const IsaSpec kSpecX86 = {
    "i386:x86-64", nullptr,
    { "x86_64-linux-gnu-objdump", "objdump", "gobjdump", nullptr },
    { 0x90 }, 1,                       /* nop                           */
    { 0x48, 0x89, 0xe5 }, 3,           /* mov %rsp,%rbp                 */
};
const IsaSpec kSpecA64 = {
    "aarch64", nullptr,
    { "aarch64-linux-gnu-objdump", "aarch64-none-elf-objdump",
      "aarch64-elf-objdump", "objdump", nullptr },
    { 0x1f, 0x20, 0x03, 0xd5 }, 4,     /* nop                           */
    { 0x00, 0x00, 0xa0, 0xd2 }, 4,     /* movz x0, #0, lsl #16          */
};
const IsaSpec kSpecRV64 = {
    "riscv:rv64", nullptr,
    { "riscv64-linux-gnu-objdump", "riscv64-unknown-elf-objdump",
      "riscv64-unknown-linux-gnu-objdump", "objdump", nullptr },
    { 0x01, 0x00 }, 2,                 /* c.nop                         */
    { 0x13, 0x05, 0x10, 0x00 }, 4,     /* li a0,1                       */
};
const IsaSpec kSpecMipsel = {
    "mips:isa32r2", "little",
    { "mipsel-linux-gnu-objdump", "mips-linux-gnu-objdump",
      "mipsel-unknown-linux-gnu-objdump", "objdump", nullptr },
    { 0x40, 0x00, 0x00, 0x00 }, 4,     /* ssnop                         */
    { 0x21, 0x10, 0x00, 0x00 }, 4,     /* move v0,zero                  */
};

const IsaSpec *spec_for_trace_isa(uint8_t trace_isa)
{
    switch (trace_isa) {
    case 1: return &kSpecX86;
    case 2: return &kSpecA64;
    case 3: return &kSpecRV64;
    case 4: return &kSpecMipsel;
    default: return nullptr;
    }
}

/* Batch geometry.  A gap wider than MAX_GAP starts a new region rather
 * than paying filler for it; MAX_REGION bounds the image handed to any
 * one objdump run. */
constexpr uint64_t MAX_GAP    = 256;
constexpr uint64_t MAX_REGION = 1u << 20;
/* One-shot re-runs after a batch miss are bounded: a systematic batch
 * failure must not turn into a process storm. */
constexpr size_t   MAX_RETRIES = 4096;

/* ---- child process plumbing ----------------------------------------- */

/* Close every descriptor above stderr except @keep.  cst_decode also
 * runs a decompressor child, and its pipe ends have no business being
 * duplicated into an unrelated disassembler. */
void close_inherited_fds(int keep)
{
    if (keep > 3) syscall(SYS_close_range, 3u, (unsigned)keep - 1, 0u);
    syscall(SYS_close_range, (unsigned)(keep < 3 ? 3 : keep + 1), ~0u, 0u);
}

/* Run @prog with @args, capture stdout into @out, discard stderr;
 * @keep_fd is the only descriptor above stderr the child inherits.
 * True only when the child exited 0. */
bool run_capture(const std::string &prog,
                 const std::vector<std::string> &args,
                 int keep_fd, std::string *out)
{
    int pfd[2];
    if (pipe(pfd) != 0) return false;

    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return false; }

    if (pid == 0) {
        /* child */
        close(pfd[0]);
        if (dup2(pfd[1], STDOUT_FILENO) < 0) _exit(127);
        close(pfd[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        close_inherited_fds(keep_fd);

        std::vector<char *> argv;
        argv.push_back(const_cast<char *>(prog.c_str()));
        for (const std::string &a : args)
            argv.push_back(const_cast<char *>(a.c_str()));
        argv.push_back(nullptr);
        execvp(prog.c_str(), argv.data());
        _exit(127);
    }

    close(pfd[1]);
    out->clear();
    char buf[65536];
    ssize_t n;
    while ((n = read(pfd[0], buf, sizeof(buf))) > 0)
        out->append(buf, (size_t)n);
    close(pfd[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) { }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* A blob objdump can open by path, without touching a run directory.
 * memfd first (nothing hits the filesystem, and the fd is inherited so
 * /proc/self/fd/N resolves in the child); a temp file only if memfd is
 * unavailable. */
class Blob {
public:
    ~Blob()
    {
        if (fd_ >= 0) close(fd_);
        if (!unlink_path_.empty()) unlink(unlink_path_.c_str());
    }

    bool write(const std::vector<uint8_t> &data)
    {
        if (fd_ < 0 && !create()) return false;
        if (ftruncate(fd_, 0) != 0) return false;
        if (lseek(fd_, 0, SEEK_SET) != 0) return false;
        size_t off = 0;
        while (off < data.size()) {
            ssize_t n = ::write(fd_, data.data() + off, data.size() - off);
            if (n <= 0) { if (errno == EINTR) continue; return false; }
            off += (size_t)n;
        }
        return true;
    }

    const std::string &path() const { return path_; }
    int                fd()   const { return fd_; }

private:
    bool create()
    {
        /* No MFD_CLOEXEC: the child must inherit the descriptor for
         * /proc/self/fd/N to name the same blob. */
        fd_ = (int)syscall(SYS_memfd_create, "cst_objdump", 0u);
        if (fd_ >= 0) {
            path_ = "/proc/self/fd/" + std::to_string(fd_);
            return true;
        }
        const char *tmpdir = getenv("TMPDIR");
        std::string tpl = std::string(tmpdir && *tmpdir ? tmpdir : "/tmp")
                          + "/cst_objdump.XXXXXX";
        std::vector<char> nm(tpl.begin(), tpl.end());
        nm.push_back('\0');
        fd_ = mkstemp(nm.data());
        if (fd_ < 0) return false;
        path_ = unlink_path_ = nm.data();
        return true;
    }

    int         fd_ = -1;
    std::string path_;
    std::string unlink_path_;
};

/* ---- output parsing -------------------------------------------------- */

struct ParsedLine {
    uint64_t    addr = 0;
    std::string hex;      /* byte column, separators removed, lowercase */
    std::string mnem;
    std::string ops;
};

bool hex_nibble(char c, unsigned *v)
{
    if (c >= '0' && c <= '9') { *v = (unsigned)(c - '0');      return true; }
    if (c >= 'a' && c <= 'f') { *v = (unsigned)(c - 'a') + 10; return true; }
    if (c >= 'A' && c <= 'F') { *v = (unsigned)(c - 'A') + 10; return true; }
    return false;
}

/* An objdump disassembly line:
 *   "  <addr>:\t<bytes>\t<mnem>[\t| ]<operands>"
 * Anything else (banners, section headers, the byte-column continuation
 * objdump emits without --insn-width) is rejected. */
bool parse_line(const std::string &ln, ParsedLine *p)
{
    size_t colon = ln.find(':');
    if (colon == std::string::npos || colon == 0) return false;

    size_t i = 0;
    while (i < colon && ln[i] == ' ') i++;
    if (i == colon) return false;
    uint64_t addr = 0;
    for (size_t k = i; k < colon; k++) {
        unsigned v;
        if (!hex_nibble(ln[k], &v)) return false;
        addr = (addr << 4) | v;
    }
    if (colon + 1 >= ln.size() || ln[colon + 1] != '\t') return false;

    size_t bstart = colon + 2;
    size_t btab   = ln.find('\t', bstart);
    if (btab == std::string::npos) return false;   /* continuation line */

    p->addr = addr;
    p->hex.clear();
    for (size_t k = bstart; k < btab; k++) {
        char c = ln[k];
        if (c == ' ') continue;
        unsigned v;
        if (!hex_nibble(c, &v)) return false;
        p->hex.push_back((char)(c >= 'A' && c <= 'F' ? c - 'A' + 'a' : c));
    }
    if (p->hex.empty() || (p->hex.size() & 1)) return false;

    size_t r = btab + 1;
    size_t end = ln.size();
    while (end > r && (ln[end - 1] == ' ' || ln[end - 1] == '\r' ||
                       ln[end - 1] == '\t')) end--;
    size_t sep = r;
    while (sep < end && ln[sep] != '\t' && ln[sep] != ' ') sep++;
    p->mnem.assign(ln, r, sep - r);
    while (sep < end && (ln[sep] == '\t' || ln[sep] == ' ')) sep++;
    p->ops.assign(ln, sep, end - sep);
    return !p->mnem.empty();
}

/* objdump's way of saying it could not decode. */
bool mnem_is_undecodable(const std::string &m)
{
    return m == "(bad)" || m == "bad" || (!m.empty() && m[0] == '.');
}

std::string hex_of(const std::string &bytes, bool reversed)
{
    static const char *digits = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (size_t i = 0; i < bytes.size(); i++) {
        uint8_t b = (uint8_t)bytes[reversed ? bytes.size() - 1 - i : i];
        s.push_back(digits[b >> 4]);
        s.push_back(digits[b & 0xf]);
    }
    return s;
}

/* objdump prints x86 byte-by-byte but fixed-width ISAs as one big-endian
 * instruction word, so accept either orientation — and nothing else. */
bool hex_matches(const std::string &printed, const std::string &bytes)
{
    return printed == hex_of(bytes, false) || printed == hex_of(bytes, true);
}

std::string render_text(const ParsedLine &p)
{
    std::string s = p.mnem;
    while (s.size() < ObjdumpRenderer::MNEM_COL) s.push_back(' ');
    if (!p.ops.empty()) { s.push_back(' '); s.append(p.ops); }
    return s;
}

}  /* namespace */

/* ---- ObjdumpRenderer ------------------------------------------------- */

size_t ObjdumpRenderer::run_region(const std::vector<Key> &items) const
{
    if (items.empty()) return 0;
    const IsaSpec *sp = (const IsaSpec *)spec_;

    uint64_t base = items.front().first;
    uint64_t end  = base;
    for (const Key &k : items)
        end = std::max(end, k.first + k.second.size());
    if (end - base > MAX_REGION) return items.size();

    /* Image: filler everywhere, real bytes written over it. */
    std::vector<uint8_t> img((size_t)(end - base));
    for (size_t i = 0; i < img.size(); i++)
        img[i] = sp->filler[i % sp->filler_len];
    for (const Key &k : items) {
        size_t off = (size_t)(k.first - base);
        std::memcpy(img.data() + off, k.second.data(), k.second.size());
    }

    Blob blob;
    if (!blob.write(img)) return items.size();

    char vma[32];
    std::snprintf(vma, sizeof(vma), "--adjust-vma=0x%llx",
                  (unsigned long long)base);
    std::vector<std::string> args = {
        "-D", "-b", "binary", "-m", sp->machine,
        "--insn-width=16", "-z", vma,
    };
    if (sp->endian) args.push_back(std::string("--endian=") + sp->endian);
    args.push_back(blob.path());

    std::string out;
    if (!run_capture(prog_, args, blob.fd(), &out)) return items.size();

    /* Index the request set so a printed line is only accepted when its
     * address AND its bytes are the ones we asked about. */
    std::map<uint64_t, const Key *> want;
    for (const Key &k : items) want[k.first] = &k;

    size_t resolved = 0;
    size_t pos = 0;
    while (pos < out.size()) {
        size_t nl = out.find('\n', pos);
        if (nl == std::string::npos) nl = out.size();
        std::string ln = out.substr(pos, nl - pos);
        pos = nl + 1;

        ParsedLine p;
        if (!parse_line(ln, &p)) continue;
        auto it = want.find(p.addr);
        if (it == want.end()) continue;
        if (!hex_matches(p.hex, it->second->second)) continue;
        if (cache_.count(*it->second)) continue;
        cache_[*it->second] =
            mnem_is_undecodable(p.mnem) ? std::string() : render_text(p);
        resolved++;
    }
    return items.size() - resolved;
}

bool ObjdumpRenderer::open(uint8_t trace_isa)
{
    const IsaSpec *sp = spec_for_trace_isa(trace_isa);
    if (!sp) return false;
    spec_ = sp;

    std::vector<std::string> candidates;
    if (const char *env = getenv("CST_OBJDUMP")) {
        if (*env) candidates.push_back(env);
    } else {
        for (int i = 0; i < 5 && sp->progs[i]; i++)
            candidates.push_back(sp->progs[i]);
    }

    /* Probe through the production path: a program that cannot decode
     * this ISA is rejected here rather than rendering "(undecoded)"
     * for every instruction later. */
    Key probe(0x400000ull,
              std::string((const char *)sp->probe, sp->probe_len));
    for (const std::string &c : candidates) {
        prog_  = c;
        open_  = true;
        cache_.clear();
        if (run_region({ probe }) == 0 && !cache_[probe].empty()) {
            cache_.clear();
            return true;
        }
    }
    cache_.clear();
    prog_.clear();
    open_ = false;
    return false;
}

void ObjdumpRenderer::prefetch(uint64_t pc, const uint8_t *bytes,
                               size_t n_bytes)
{
    if (!open_ || !bytes || n_bytes == 0) return;
    pending_.emplace(pc, std::string((const char *)bytes, n_bytes));
}

size_t ObjdumpRenderer::prefetch_run()
{
    if (!open_ || pending_.empty()) return 0;

    /* pending_ is ordered by (pc, bytes).  Peel it into layers so each
     * objdump run sees at most one byte-string per address; a second
     * layer only appears where the same pc carries different code
     * (self-modified or re-mapped text). */
    std::vector<Key> layer, rest;
    for (const Key &k : pending_) {
        if (!layer.empty() && layer.back().first == k.first) rest.push_back(k);
        else                                                 layer.push_back(k);
    }
    pending_.clear();

    size_t unresolved = 0;
    std::vector<Key> retry;
    while (!layer.empty()) {
        /* Group the layer into contiguous regions. */
        size_t i = 0;
        while (i < layer.size()) {
            size_t j = i + 1;
            uint64_t base = layer[i].first;
            uint64_t cur  = base + layer[i].second.size();
            while (j < layer.size() &&
                   layer[j].first >= cur &&
                   layer[j].first - cur <= MAX_GAP &&
                   layer[j].first + layer[j].second.size() - base <= MAX_REGION) {
                cur = layer[j].first + layer[j].second.size();
                j++;
            }
            std::vector<Key> region(layer.begin() + (long)i,
                                    layer.begin() + (long)j);
            if (run_region(region) != 0) {
                for (const Key &k : region)
                    if (!cache_.count(k)) retry.push_back(k);
            }
            i = j;
        }
        /* Next layer from whatever collided on an address. */
        layer.clear();
        std::vector<Key> next_rest;
        for (const Key &k : rest) {
            if (!layer.empty() && layer.back().first == k.first)
                next_rest.push_back(k);
            else
                layer.push_back(k);
        }
        rest.swap(next_rest);
    }

    /* Batch misses (an overlapping x86 block puts a requested address
     * mid-instruction) get one single-instruction run each. */
    size_t retried = 0;
    for (const Key &k : retry) {
        if (cache_.count(k)) continue;
        if (retried >= MAX_RETRIES) { unresolved++; continue; }
        retried++;
        if (run_region({ k }) != 0 || cache_[k].empty()) {
            cache_[k] = std::string();
            unresolved++;
        }
    }
    if (retried >= MAX_RETRIES)
        std::fprintf(stderr,
            "cst_decode: objdump: %zu instructions past the %zu-retry "
            "bound were left undecoded\n", unresolved, MAX_RETRIES);
    return unresolved;
}

bool ObjdumpRenderer::lookup(const Key &k, std::string *out) const
{
    auto it = cache_.find(k);
    if (it == cache_.end()) return false;
    if (it->second.empty()) return false;      /* known undecodable */
    out->append(it->second);
    return true;
}

bool ObjdumpRenderer::render_one(uint64_t pc, const uint8_t *bytes,
                                 size_t n_bytes, std::string *out) const
{
    if (!open_ || !bytes || n_bytes == 0) return false;

    Key k(pc, std::string((const char *)bytes, n_bytes));
    if (cache_.count(k)) return lookup(k, out);

    /* Not primed: one instruction, one run, memoised either way. */
    if (run_region({ k }) != 0 && !cache_.count(k))
        cache_[k] = std::string();
    return lookup(k, out);
}

}  /* namespace cst */
