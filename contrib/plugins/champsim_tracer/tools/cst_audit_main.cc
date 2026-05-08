/*
 * cst_audit — byte-composition auditor for .cst traces.
 *
 * C++ port of cst_audit.py.  Mirrors that script's report layout and
 * field-delta bucket categorization byte-for-byte; the body walker is
 * a single tight loop over the mmap'd file with no per-record
 * allocations on the hot path.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <stdexcept>
#include <string>
#include <vector>

#include "cst_format.h"
#include "cst_reader.h"

namespace {

/* Field-delta record bucket indices (parallel to the Python audit). */
enum : int {
    BIDX_OVERHEAD   = 0,
    BIDX_MEM_COUNTS = 1,
    BIDX_LOAD_ADDR  = 2,
    BIDX_STORE_ADDR = 3,
    BIDX_LOAD_DATA  = 4,
    BIDX_STORE_DATA = 5,
    BIDX_DST_REG    = 6,
    BIDX_INSN_META  = 7,
    BIDX_EXTENDED   = 8,
    BIDX_OTHER      = 9,
    NUM_BUCKETS     = 10,
};

struct FidTables {
    std::array<uint8_t, 256> bucket{};
    std::array<bool, 256>    is_extra{};

    FidTables() {
        bucket.fill(BIDX_OTHER);
        is_extra.fill(false);
        bucket[cst::FID_N_LOADS]  = BIDX_MEM_COUNTS;
        bucket[cst::FID_N_STORES] = BIDX_MEM_COUNTS;
        for (int i = 0; i < cst::FID_SLOT_COUNT; i++) {
            bucket[cst::FID_LOAD_ADDR_BASE  + i] = BIDX_LOAD_ADDR;
            bucket[cst::FID_STORE_ADDR_BASE + i] = BIDX_STORE_ADDR;
            bucket[cst::FID_LOAD_DATA_BASE  + i] = BIDX_LOAD_DATA;
            bucket[cst::FID_STORE_DATA_BASE + i] = BIDX_STORE_DATA;
            bucket[cst::FID_DST_REG_BASE    + i] = BIDX_DST_REG;
        }
        bucket[cst::FID_EXTRA_LOAD_ADDR]  = BIDX_LOAD_ADDR;
        bucket[cst::FID_EXTRA_STORE_ADDR] = BIDX_STORE_ADDR;
        bucket[cst::FID_EXTRA_LOAD_DATA]  = BIDX_LOAD_DATA;
        bucket[cst::FID_EXTRA_STORE_DATA] = BIDX_STORE_DATA;
        for (int f = cst::FID_INSN_BYTES_LO; f <= cst::FID_INSN_SIZE; f++) {
            bucket[f] = BIDX_INSN_META;
        }
        bucket[cst::FID_EXTENDED] = BIDX_EXTENDED;
        is_extra[cst::FID_EXTRA_LOAD_ADDR]  = true;
        is_extra[cst::FID_EXTRA_STORE_ADDR] = true;
        is_extra[cst::FID_EXTRA_LOAD_DATA]  = true;
        is_extra[cst::FID_EXTRA_STORE_DATA] = true;
    }
};

struct Bucket {
    uint64_t bytes = 0;
    uint64_t count = 0;
};

struct Stats {
    uint64_t file_size         = 0;
    uint64_t header_bytes      = 0;
    uint64_t templates_section = 0;
    uint64_t templates_count   = 0;
    uint64_t trailer_bytes     = 0;
    uint64_t body_total        = 0;
    uint64_t body_terminator   = 0;
    uint64_t cp_entries        = 0;
    uint64_t wp_entries_total  = 0;
    uint64_t cp_total_insns    = 0;
    uint64_t wp_total_insns    = 0;

    Bucket cp_entry_framing;
    Bucket cp_field_delta;
    Bucket thread_switch;
    Bucket wp_chain_envelope;
    Bucket wp_entry_framing;
    Bucket wp_field_delta;
    Bucket wp_events;
    uint64_t iframe_count = 0;
    Bucket   iframe_bytes;

    /* Per-bucket detail across CP and WP field-delta streams. */
    std::array<Bucket, NUM_BUCKETS> cp_fd{};
    std::array<Bucket, NUM_BUCKETS> wp_fd{};
};

/* Inline ULEB skip: advance past the varint without decoding it. */
static inline void skip_uleb(const uint8_t *m, size_t &p)
{
    while (m[p] & 0x80) p++;
    p++;
}

/* Inline ULEB read: decode + advance. */
static inline uint64_t read_uleb(const uint8_t *m, size_t &p)
{
    uint64_t out = 0;
    unsigned shift = 0;
    while (true) {
        uint8_t b = m[p++];
        out |= uint64_t(b & 0x7F) << shift;
        if (!(b & 0x80)) return out;
        shift += 7;
    }
}

/* Inline SLEB read: decode + advance. */
static inline int64_t read_sleb(const uint8_t *m, size_t &p)
{
    uint64_t out = 0;
    unsigned shift = 0;
    while (true) {
        uint8_t b = m[p++];
        out |= uint64_t(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) {
            if (shift < 64 && (b & 0x40)) {
                out |= ~uint64_t(0) << shift;
            }
            return (int64_t)out;
        }
    }
}

/* Walk the templates section once, collecting (template_id ->
 * n_insns) so the body walker can count CP/WP architectural
 * instructions without re-parsing template records. */
void walk_templates(const uint8_t *m, size_t templates_off,
                    uint64_t expected,
                    std::vector<uint32_t> *insns_by_tid,
                    uint64_t *out_section_bytes)
{
    size_t p = templates_off;
    size_t st = p;
    uint64_t n = read_uleb(m, p);
    if (n != expected) {
        throw std::runtime_error("template count mismatch (header vs trailer)");
    }
    uint32_t max_tid = 0;
    /* Two-pass would be tidier; one-pass with growing vector keeps it
     * cache-friendly and avoids re-reading. */
    for (uint64_t i = 0; i < n; i++) {
        uint64_t tlen = read_uleb(m, p);
        size_t tend = p + tlen;
        uint64_t tid = read_uleb(m, p);
        read_uleb(m, p);                    /* start_pc */
        uint64_t n_insns = read_uleb(m, p);
        read_uleb(m, p);                    /* fall_through_pc */
        uint64_t sname_len = read_uleb(m, p);
        p += sname_len;
        for (uint64_t k = 0; k < n_insns; k++) {
            read_uleb(m, p);                /* pc_delta */
            p++;                            /* opcode */
            p++;                            /* branch_type */
            uint8_t iflags = m[p++];
            uint8_t n_src = m[p++];
            uint8_t n_dst = m[p++];
            p += n_src + n_dst;
            p++;                            /* n_loads */
            p++;                            /* n_stores */
            if (iflags & cst::INSN_FLAG_HAS_IMM) read_sleb(m, p);
            uint8_t isize = m[p++];
            p += isize;
        }
        if (p != tend) {
            throw std::runtime_error("template length mismatch");
        }
        if (tid >= insns_by_tid->size()) {
            insns_by_tid->resize(tid + 1, 0);
        }
        (*insns_by_tid)[tid] = (uint32_t)n_insns;
        if (tid > max_tid) max_tid = (uint32_t)tid;
    }
    *out_section_bytes = p - st;
}

void skip_lp_section(const uint8_t *m, size_t &p)
{
    uint64_t n = read_uleb(m, p);
    p += n;
}

void walk_body(const uint8_t *m, size_t body_off, size_t body_end,
               const std::vector<uint32_t> &insns_by_tid, Stats *s)
{
    static const FidTables fid;
    size_t p = body_off;
    int32_t prev_cp_tid = 0;
    auto &cpfd_b = s->cp_fd;
    auto &wpfd_b = s->wp_fd;

    while (p < body_end) {
        size_t tag_pos = p;
        uint8_t tag = m[p++];

        if (tag == cst::BODY_TAG_ENTRY) {
            int64_t tdelta = read_sleb(m, p);
            prev_cp_tid += (int32_t)tdelta;
            s->cp_entry_framing.bytes += p - tag_pos;
            s->cp_entries++;
            if (prev_cp_tid >= 0 &&
                (uint32_t)prev_cp_tid < insns_by_tid.size()) {
                s->cp_total_insns += insns_by_tid[prev_cp_tid];
            }

            /* CP field-delta section. */
            size_t sec_st = p;
            uint64_t paylen = read_uleb(m, p);
            size_t payload_st = p;
            size_t payload_end = payload_st + paylen;
            s->cp_field_delta.bytes += payload_end - sec_st;
            cpfd_b[BIDX_OVERHEAD].bytes += payload_st - sec_st;
            cpfd_b[BIDX_OVERHEAD].count += 1;

            size_t rec_st = p;
            uint64_t n_records = read_uleb(m, p);
            cpfd_b[BIDX_OVERHEAD].bytes += p - rec_st;
            cpfd_b[BIDX_OVERHEAD].count += 1;

            for (uint64_t r = 0; r < n_records; r++) {
                size_t rec_p0 = p;
                skip_uleb(m, p);                /* ipos delta */
                uint8_t f = m[p++];
                if (fid.is_extra[f]) {
                    uint64_t nv = read_uleb(m, p);
                    for (uint64_t k = 0; k < nv; k++) skip_uleb(m, p);
                } else {
                    skip_uleb(m, p);             /* delta */
                }
                if (f == cst::FID_EXTENDED) skip_uleb(m, p);
                int idx = fid.bucket[f];
                cpfd_b[idx].bytes += p - rec_p0;
                cpfd_b[idx].count += 1;
            }
            if (p != payload_end) {
                throw std::runtime_error("CP field-delta had trailing bytes");
            }

            /* WP chain envelope. */
            size_t wp_st = p;
            uint64_t wp_paylen = read_uleb(m, p);
            size_t wp_payload_end = p + wp_paylen;
            s->wp_chain_envelope.bytes += wp_payload_end - wp_st;
            uint64_t num_wp = read_uleb(m, p);
            int32_t prev_wp_tid = 0;
            for (uint64_t w = 0; w < num_wp; w++) {
                size_t wfs = p;
                int64_t wd = read_sleb(m, p);
                prev_wp_tid += (int32_t)wd;
                s->wp_entry_framing.bytes += p - wfs;
                s->wp_entry_framing.count += 1;
                if (prev_wp_tid >= 0 &&
                    (uint32_t)prev_wp_tid < insns_by_tid.size()) {
                    s->wp_total_insns += insns_by_tid[prev_wp_tid];
                }

                size_t wp_sec_st = p;
                uint64_t wpl = read_uleb(m, p);
                size_t wp_payload_st = p;
                size_t wp_payload_end_inner = wp_payload_st + wpl;
                s->wp_field_delta.bytes += wp_payload_end_inner - wp_sec_st;
                wpfd_b[BIDX_OVERHEAD].bytes += wp_payload_st - wp_sec_st;
                wpfd_b[BIDX_OVERHEAD].count += 1;

                size_t wp_rec_st = p;
                uint64_t wp_nrec = read_uleb(m, p);
                wpfd_b[BIDX_OVERHEAD].bytes += p - wp_rec_st;
                wpfd_b[BIDX_OVERHEAD].count += 1;
                for (uint64_t r = 0; r < wp_nrec; r++) {
                    size_t rec_p0 = p;
                    skip_uleb(m, p);
                    uint8_t f = m[p++];
                    if (fid.is_extra[f]) {
                        uint64_t nv = read_uleb(m, p);
                        for (uint64_t k = 0; k < nv; k++) skip_uleb(m, p);
                    } else {
                        skip_uleb(m, p);
                    }
                    if (f == cst::FID_EXTENDED) skip_uleb(m, p);
                    int idx = fid.bucket[f];
                    wpfd_b[idx].bytes += p - rec_p0;
                    wpfd_b[idx].count += 1;
                }
                if (p != wp_payload_end_inner) {
                    throw std::runtime_error("WP field-delta had trailing bytes");
                }
            }
            s->wp_entries_total += num_wp;
            if (p != wp_payload_end) {
                throw std::runtime_error("WP chain had trailing bytes");
            }

            /* WP events sub-section: opaque to audit. */
            size_t ev_st = p;
            skip_lp_section(m, p);
            s->wp_events.bytes += p - ev_st;
            continue;
        }

        if (tag == cst::BODY_TAG_THREAD_SWITCH) {
            skip_uleb(m, p);                 /* signed delta */
            s->thread_switch.bytes += p - tag_pos;
            s->thread_switch.count += 1;
            continue;
        }

        if (tag == cst::BODY_TAG_IFRAME) {
            skip_lp_section(m, p);
            skip_lp_section(m, p);
            skip_lp_section(m, p);
            s->iframe_count++;
            s->iframe_bytes.bytes += p - tag_pos;
            continue;
        }

        if (tag == cst::BODY_TAG_END) {
            skip_uleb(m, p);                 /* num_entries */
            s->body_terminator = p - tag_pos;
            break;
        }

        throw std::runtime_error("unknown body tag");
    }

    s->cp_entry_framing.count = s->cp_entries;
    s->cp_field_delta.count = s->cp_entries;
    s->wp_chain_envelope.count = s->cp_entries;
    s->wp_field_delta.count = s->wp_entries_total;
    s->wp_events.count = s->cp_entries;
    s->iframe_bytes.count = s->iframe_count;
}

/* ===== Output formatting ===== */

std::string human(double n)
{
    char buf[32];
    if (n < 1024.0) { std::snprintf(buf, sizeof(buf), "%d B", (int)n); return buf; }
    static const char *units[] = {"KiB", "MiB", "GiB", "TiB", "PiB"};
    for (auto u : units) {
        n /= 1024.0;
        if (n < 1024.0) {
            std::snprintf(buf, sizeof(buf), "%.2f %s", n, u);
            return buf;
        }
    }
    std::snprintf(buf, sizeof(buf), "%.2f PiB", n);
    return buf;
}

/* Format a long integer with thousands separators (en_US locale-style). */
std::string fmt_n(uint64_t v)
{
    char raw[32];
    int len = std::snprintf(raw, sizeof(raw), "%llu", (unsigned long long)v);
    std::string out;
    int g = ((len - 1) % 3) + 1;
    for (int i = 0; i < len; i++) {
        if (i > 0 && (i - g) % 3 == 0) out.push_back(',');
        out.push_back(raw[i]);
    }
    return out;
}

std::string row(const std::string &label, uint64_t b, uint64_t total,
                uint64_t count = 0, const char *per = nullptr)
{
    double pct = total ? 100.0 * b / total : 0.0;
    char buf[256];
    std::string lbl = label;
    if (lbl.size() < 34) lbl.resize(34, ' ');
    std::string hb = human((double)b);
    if (count) {
        std::snprintf(buf, sizeof(buf),
                      "  %s %14s  %6.2f%%  [%10s %s, avg %6.1f B]",
                      lbl.c_str(), hb.c_str(), pct,
                      fmt_n(count).c_str(),
                      per ? per : "evt",
                      (double)b / count);
    } else {
        std::snprintf(buf, sizeof(buf), "  %s %14s  %6.2f%%",
                      lbl.c_str(), hb.c_str(), pct);
    }
    return buf;
}

std::string fd_row(const std::string &label, const Bucket &cp,
                   const Bucket &wp, uint64_t total)
{
    uint64_t b = cp.bytes + wp.bytes;
    uint64_t count = cp.count + wp.count;
    double pct = total ? 100.0 * b / total : 0.0;
    double avg = count ? (double)b / count : 0.0;
    char buf[512];
    std::string lbl = label;
    if (lbl.size() < 20) lbl.resize(20, ' ');
    std::snprintf(buf, sizeof(buf),
                  "  %s %12s  %6.2f%%  cp=%10s  wp=%10s  [%10s rec, avg %5.1f B]",
                  lbl.c_str(), human((double)b).c_str(), pct,
                  human((double)cp.bytes).c_str(),
                  human((double)wp.bytes).c_str(),
                  fmt_n(count).c_str(), avg);
    return buf;
}

void print_report(const Stats &s)
{
    uint64_t total = s.file_size;
    std::printf("FILE                                %14s  100.00%%\n",
                human((double)total).c_str());
    std::printf("\n=== TOP-LEVEL SECTIONS ===\n");
    std::printf("%s\n", row("HEADER", s.header_bytes, total).c_str());
    std::printf("%s\n", row("TEMPLATES", s.templates_section, total,
                             s.templates_count, "tmpl").c_str());
    std::printf("%s\n", row("BODY", s.body_total, total).c_str());
    std::printf("%s\n", row("TRAILER", s.trailer_bytes, total).c_str());

    uint64_t body = s.body_total;
    std::printf("\n=== BODY BREAKDOWN (%s) ===\n", human((double)body).c_str());
    std::printf("%s\n", row("CP entry framing",
                             s.cp_entry_framing.bytes, body,
                             s.cp_entries, "entry").c_str());
    std::printf("%s\n", row("CP field-delta section",
                             s.cp_field_delta.bytes, body,
                             s.cp_entries, "entry").c_str());
    std::printf("%s\n", row("thread-switch records",
                             s.thread_switch.bytes, body,
                             s.thread_switch.count, "switch").c_str());
    std::printf("%s\n", row("WP chain envelope (incl. inner)",
                             s.wp_chain_envelope.bytes, body,
                             s.cp_entries, "entry").c_str());
    std::printf("    expanded:\n");
    std::printf("%s\n", row("    WP entry framing",
                             s.wp_entry_framing.bytes, body,
                             s.wp_entry_framing.count, "WP").c_str());
    std::printf("%s\n", row("    WP field-delta section",
                             s.wp_field_delta.bytes, body,
                             s.wp_entries_total, "WP").c_str());
    std::printf("%s\n", row("WP events", s.wp_events.bytes, body,
                             s.cp_entries, "entry").c_str());
    std::printf("%s\n", row("IFRAME records (validation redundancy)",
                             s.iframe_bytes.bytes, body,
                             s.iframe_count, "iframe").c_str());
    std::printf("%s\n", row("BODY terminator", s.body_terminator, body).c_str());

    uint64_t fd_total = s.cp_field_delta.bytes + s.wp_field_delta.bytes;
    std::printf("\n=== FIELD-DELTA RECORD BREAKDOWN (%s) ===\n",
                human((double)fd_total).c_str());
    static const struct { const char *label; int idx; } rows[] = {
        {"section overhead",     BIDX_OVERHEAD},
        {"memop counts",         BIDX_MEM_COUNTS},
        {"load addresses",       BIDX_LOAD_ADDR},
        {"store addresses",      BIDX_STORE_ADDR},
        {"load data",            BIDX_LOAD_DATA},
        {"store data",           BIDX_STORE_DATA},
        {"dest registers",       BIDX_DST_REG},
        {"instruction metadata", BIDX_INSN_META},
        {"extended",             BIDX_EXTENDED},
        {"other",                BIDX_OTHER},
    };
    for (auto &r : rows) {
        std::printf("%s\n", fd_row(r.label, s.cp_fd[r.idx], s.wp_fd[r.idx],
                                    fd_total).c_str());
    }

    std::printf("\n=== ENTRIES & INSNS ===\n");
    std::printf("  CP entries           %14s\n", fmt_n(s.cp_entries).c_str());
    std::printf("  WP entries (total)   %14s\n", fmt_n(s.wp_entries_total).c_str());
    std::printf("  CP insns (total)     %14s\n", fmt_n(s.cp_total_insns).c_str());
    std::printf("  WP insns (total)     %14s\n", fmt_n(s.wp_total_insns).c_str());
    if (s.cp_total_insns) {
        std::printf("  bytes / CP insn      %14.2f\n",
                    (double)body / s.cp_total_insns);
    }
    uint64_t all_insns = s.cp_total_insns + s.wp_total_insns;
    if (all_insns) {
        std::printf("  bytes / any insn     %14.2f\n",
                    (double)body / all_insns);
    }
    if (s.cp_entries) {
        std::printf("  WPs / CP entry       %14.2f\n",
                    (double)s.wp_entries_total / s.cp_entries);
    }
}

}  /* namespace */

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <trace.cst>\n", argv[0]);
        return 2;
    }

    int fd = ::open(argv[1], O_RDONLY);
    if (fd < 0) {
        std::fprintf(stderr, "cst_audit: cannot open %s: %s\n",
                     argv[1], std::strerror(errno));
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        std::fprintf(stderr, "cst_audit: empty or unstattable trace\n");
        ::close(fd);
        return 1;
    }
    void *map = mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    ::close(fd);
    if (map == MAP_FAILED) {
        std::fprintf(stderr, "cst_audit: mmap failed: %s\n",
                     std::strerror(errno));
        return 1;
    }
    const uint8_t *m = (const uint8_t *)map;
    size_t size = (size_t)st.st_size;

    try {
        cst::Trailer t = cst::parse_trailer(m, size);
        cst::Header h = cst::parse_header(m, size, t.body_off, t.magic);

        Stats s;
        s.file_size = size;
        s.trailer_bytes = cst::TRAILER_SIZE;
        s.body_total = t.body_byte_count;
        s.header_bytes = t.body_off;
        s.templates_count = t.templates_count;

        std::vector<uint32_t> insns_by_tid;
        if (t.templates_count > 0) {
            walk_templates(m, t.templates_off, t.templates_count,
                           &insns_by_tid, &s.templates_section);
        }

        walk_body(m, t.body_off, t.body_off + t.body_byte_count,
                  insns_by_tid, &s);

        print_report(s);
    } catch (const std::exception &e) {
        std::fprintf(stderr, "cst_audit: %s\n", e.what());
        munmap(map, size);
        return 1;
    }

    munmap(map, size);
    return 0;
}
