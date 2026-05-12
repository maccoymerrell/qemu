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

    explicit FidTables(const cst::ResolvedIds &ids) {
        bucket.fill(BIDX_OTHER);
        is_extra.fill(false);
        bucket[ids.fid_n_loads]  = BIDX_MEM_COUNTS;
        bucket[ids.fid_n_stores] = BIDX_MEM_COUNTS;
        for (int i = 0; i < cst::FID_SLOT_COUNT; i++) {
            bucket[ids.fid_load_addr_base  + i] = BIDX_LOAD_ADDR;
            bucket[ids.fid_store_addr_base + i] = BIDX_STORE_ADDR;
            bucket[ids.fid_load_data_base  + i] = BIDX_LOAD_DATA;
            bucket[ids.fid_store_data_base + i] = BIDX_STORE_DATA;
            bucket[ids.fid_dst_reg_base    + i] = BIDX_DST_REG;
        }
        bucket[ids.fid_extra_load_addr]  = BIDX_LOAD_ADDR;
        bucket[ids.fid_extra_store_addr] = BIDX_STORE_ADDR;
        bucket[ids.fid_extra_load_data]  = BIDX_LOAD_DATA;
        bucket[ids.fid_extra_store_data] = BIDX_STORE_DATA;
        for (int f = ids.fid_insn_bytes_lo; f <= ids.fid_insn_size; f++) {
            bucket[f] = BIDX_INSN_META;
        }
        bucket[ids.fid_extended] = BIDX_EXTENDED;
        is_extra[ids.fid_extra_load_addr]  = true;
        is_extra[ids.fid_extra_store_addr] = true;
        is_extra[ids.fid_extra_load_data]  = true;
        is_extra[ids.fid_extra_store_data] = true;
    }
};

struct Bucket {
    uint64_t bytes = 0;
    uint64_t count = 0;
};

struct Stats {
    uint64_t file_size         = 0;
    uint64_t header_bytes      = 0;
    uint64_t templates_count   = 0;
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
    /* BODY_TAG_REGFILE: per-thread initial regfile snapshot,
     * one record per (segment, thread_id). */
    uint64_t regfile_count = 0;
    Bucket   regfile_bytes;

    /* Per-bucket detail across CP and WP field-delta streams. */
    std::array<Bucket, NUM_BUCKETS> cp_fd{};
    std::array<Bucket, NUM_BUCKETS> wp_fd{};
};

/* Tally the bytes consumed by a single field-delta record into the
 * caller's bucket table.  Used by both the CP and WP record loops
 * (only difference is which bucket table they're aggregating into). */
static inline void tally_fd_record(
    cst::Reader &sec, const FidTables &fid, const cst::ResolvedIds &ids,
    std::array<Bucket, NUM_BUCKETS> *fd_b)
{
    size_t before = sec.consumed();
    sec.uleb();                              /* ipos delta */
    uint8_t f = sec.u8();
    if (fid.is_extra[f]) {
        uint64_t nv = sec.uleb();
        for (uint64_t k = 0; k < nv; k++) sec.uleb();
    } else {
        sec.uleb();                          /* delta */
    }
    if (f == ids.fid_extended) sec.uleb();
    int idx = fid.bucket[f];
    (*fd_b)[idx].bytes += sec.consumed() - before;
    (*fd_b)[idx].count += 1;
}

/* Walk the body record stream through a Reader.  Works identically
 * for memory-backed (uncompressed body) and stream-backed
 * (decompressor-piped) inputs; the Reader handles refilling. */
void walk_body(cst::Reader &body, const cst::ResolvedIds &ids,
               const std::vector<uint32_t> &insns_by_tid, Stats *s)
{
    const FidTables fid(ids);
    int32_t prev_cp_tid = 0;
    auto &cpfd_b = s->cp_fd;
    auto &wpfd_b = s->wp_fd;

    while (!body.eof()) {
        size_t tag_start = body.consumed();
        uint8_t tag = body.u8();

        if (tag == ids.body_tag_entry) {
            int64_t tdelta = body.sleb();
            prev_cp_tid += (int32_t)tdelta;
            s->cp_entry_framing.bytes += body.consumed() - tag_start;
            s->cp_entries++;
            if (prev_cp_tid >= 0 &&
                (uint32_t)prev_cp_tid < insns_by_tid.size()) {
                s->cp_total_insns += insns_by_tid[prev_cp_tid];
            }

            /* CP field-delta section.  sub() consumes the ULEB
             * payload length + payload bytes; we account for the
             * length prefix separately by subtracting the sub's
             * payload size from the parent's bytes-consumed delta. */
            size_t sec_in_start = body.consumed();
            cst::Reader sec = body.sub();
            size_t sec_total = body.consumed() - sec_in_start;
            s->cp_field_delta.bytes += sec_total;
            cpfd_b[BIDX_OVERHEAD].bytes += sec_total - sec.end();
            cpfd_b[BIDX_OVERHEAD].count += 1;

            size_t rec_st = sec.consumed();
            uint64_t n_records = sec.uleb();
            cpfd_b[BIDX_OVERHEAD].bytes += sec.consumed() - rec_st;
            cpfd_b[BIDX_OVERHEAD].count += 1;

            for (uint64_t r = 0; r < n_records; r++) {
                tally_fd_record(sec, fid, ids, &cpfd_b);
            }
            if (!sec.eof()) {
                throw std::runtime_error("CP field-delta had trailing bytes");
            }

            /* WP chain envelope. */
            size_t wp_in_start = body.consumed();
            cst::Reader wpb = body.sub();
            s->wp_chain_envelope.bytes += body.consumed() - wp_in_start;

            uint64_t num_wp = wpb.uleb();
            int32_t prev_wp_tid = 0;
            for (uint64_t w = 0; w < num_wp; w++) {
                size_t wfs = wpb.consumed();
                int64_t wd = wpb.sleb();
                prev_wp_tid += (int32_t)wd;
                s->wp_entry_framing.bytes += wpb.consumed() - wfs;
                s->wp_entry_framing.count += 1;
                if (prev_wp_tid >= 0 &&
                    (uint32_t)prev_wp_tid < insns_by_tid.size()) {
                    s->wp_total_insns += insns_by_tid[prev_wp_tid];
                }

                size_t wp_sec_in = wpb.consumed();
                cst::Reader wpsec = wpb.sub();
                size_t wp_sec_total = wpb.consumed() - wp_sec_in;
                s->wp_field_delta.bytes += wp_sec_total;
                wpfd_b[BIDX_OVERHEAD].bytes += wp_sec_total - wpsec.end();
                wpfd_b[BIDX_OVERHEAD].count += 1;

                size_t wp_rec_st = wpsec.consumed();
                uint64_t wp_nrec = wpsec.uleb();
                wpfd_b[BIDX_OVERHEAD].bytes += wpsec.consumed() - wp_rec_st;
                wpfd_b[BIDX_OVERHEAD].count += 1;
                for (uint64_t r = 0; r < wp_nrec; r++) {
                    tally_fd_record(wpsec, fid, ids, &wpfd_b);
                }
                if (!wpsec.eof()) {
                    throw std::runtime_error("WP field-delta had trailing bytes");
                }
            }
            s->wp_entries_total += num_wp;
            if (!wpb.eof()) {
                throw std::runtime_error("WP chain had trailing bytes");
            }

            /* WP events sub-section: opaque to audit. */
            size_t ev_in = body.consumed();
            (void)body.sub();
            s->wp_events.bytes += body.consumed() - ev_in;
            continue;
        }

        if (tag == ids.body_tag_thread_switch) {
            body.sleb();                 /* signed delta */
            s->thread_switch.bytes += body.consumed() - tag_start;
            s->thread_switch.count += 1;
            continue;
        }

        if (tag == ids.body_tag_iframe) {
            (void)body.sub();
            (void)body.sub();
            (void)body.sub();
            s->iframe_count++;
            s->iframe_bytes.bytes += body.consumed() - tag_start;
            continue;
        }

        if (tag == ids.body_tag_regfile) {
            (void)body.uleb();                  /* thread_id */
            uint64_t n_regs = body.uleb();
            for (uint64_t i = 0; i < n_regs; i++) {
                (void)body.u8();                /* gen_id */
                uint8_t width = body.u8();
                uint8_t scratch[256];
                while (width > 0) {
                    size_t take = std::min<size_t>(width, sizeof(scratch));
                    body.raw(scratch, take);
                    width = (uint8_t)(width - take);
                }
            }
            s->regfile_count++;
            s->regfile_bytes.bytes += body.consumed() - tag_start;
            continue;
        }

        if (tag == ids.body_tag_end) {
            body.uleb();                     /* num_entries */
            s->body_terminator = body.consumed() - tag_start;
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
    s->regfile_bytes.count = s->regfile_count;
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
    std::printf("\n=== MEMBER SIZES (uncompressed) ===\n");
    std::printf("%s\n", row("HEADER member", s.header_bytes, total,
                             s.templates_count, "tmpl").c_str());
    std::printf("%s\n", row("BODY member (records)", s.body_total, total).c_str());

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
    std::printf("%s\n", row("REGFILE records (per-thread initial state)",
                             s.regfile_bytes.bytes, body,
                             s.regfile_count, "regfile").c_str());
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

    try {
        /* New tar-of-(body,header) container; cst_file_open
         * resolves both members and decompresses on the fly. */
        std::unique_ptr<cst::CstFile> cf = cst::cst_file_open(argv[1]);

        struct stat st;
        if (::stat(argv[1], &st) != 0) {
            throw std::runtime_error("stat failed");
        }

        std::vector<cst::Template> templates;
        std::unordered_map<uint32_t, size_t> by_id;
        cst::Header h = cst::parse_header(cf->header(), &templates, &by_id);

        /* Body: stream the records through a Reader.  For compressed
         * bodies this spawns the decompressor subprocess; for
         * uncompressed bodies the Reader is a cheap view into the
         * mmap.  Audit walks the entire body so we don't get the
         * "skip the body" win that --templates-only does, but
         * streaming still avoids the 100 GB-of-decompressed-RAM
         * problem. */
        auto body_stream = cst::body_stream_open(*cf);

        Stats s;
        s.file_size = (size_t)st.st_size;
        s.header_bytes = cf->header().size;
        s.templates_count = templates.size();

        std::vector<uint32_t> insns_by_tid;
        insns_by_tid.reserve(templates.size());
        for (const auto &t : templates) {
            insns_by_tid.push_back((uint32_t)t.insns.size());
        }

        walk_body(body_stream->reader(), h.ids, insns_by_tid, &s);
        body_stream->finalize();
        /* body_total is the consumed byte count for the record
         * stream (everything between the leading and trailing
         * CST_MAGIC), summed across all records walked.  Equivalent
         * to body_records.size in the old code. */
        s.body_total = s.cp_entry_framing.bytes
                     + s.cp_field_delta.bytes
                     + s.thread_switch.bytes
                     + s.wp_chain_envelope.bytes
                     + s.wp_events.bytes
                     + s.iframe_bytes.bytes
                     + s.regfile_bytes.bytes
                     + s.body_terminator;

        print_report(s);
    } catch (const std::exception &e) {
        std::fprintf(stderr, "cst_audit: %s\n", e.what());
        return 1;
    }
    return 0;
}
