/*
 * ChampSim Tracer offline tools — trace visualizer.
 *
 * Streams a .cst body through cst::BodyWalker, accumulates a chosen
 * metric into instruction-window bins, and renders the result as an
 * SVG to stdout (or @ -o FILE).
 *
 * Metrics:
 *
 *   branch_mpki    Branch mispredictions per 1k CP insns under gshare
 *                  with a configurable set of history lengths.  One
 *                  line per history length.
 *   wp_insns       Wasted wrong-path instructions per 1k CP insns.
 *                  A WP chain is "wasted" only when the gshare
 *                  predictor mispredicts the branch at the WP chain's
 *                  origin.  One line per history length.
 *   wp_memops      Wasted wrong-path memory accesses per 1k CP insns.
 *                  Same gating as wp_insns; counts mem-side dyn_params
 *                  across the WP chain.  One line per history length.
 *   mem_pat        Per-instruction memory-access-pattern fraction
 *                  ([none / regular / irregular / random]) from the
 *                  trace's per-template profile block.  Stacked area.
 *   branch_dir     Per-CP-branch direction breakdown
 *                  (taken / not-taken) split by branch class
 *                  (conditional, unconditional, indirect, syscall,
 *                  return).  Stacked area.
 *   gen_op         Per-CP-insn opcode fraction by GenericOpcode name.
 *                  Top-K layers + "other".
 *   gen_reg        Per-CP-insn destination-register fraction by
 *                  generic-register name.  Top-K layers + "other".
 *
 * Output is self-contained SVG (no external resources / scripts).
 * Binning is fixed-width in CP-insn units; the number of bins
 * defaults to 200 across the entire trace.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <list>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "cst_common.h"
#include "cst_decode.h"
#include "cst_format.h"
#include "cst_reader.h"

/* ===================================================================
 *                            CLI parsing
 * =================================================================== */

enum class Metric {
    BranchMpki,
    WpInsns,
    WpMemops,
    MemPat,
    BranchDir,
    GenOp,
    GenReg,
    BtbMiss,
    WpDivergence,
    CacheMiss,
};

enum class CachePolicy { LRU, MRU, Random };

struct Options {
    const char *input        = nullptr;
    const char *output       = nullptr;   /* nullptr -> stdout */
    Metric      metric       = Metric::BranchMpki;
    /* History lengths used by the gshare predictor variants.  Multiple
     * values produce overlaid lines on the same chart.  Ignored for
     * non-gshare metrics. */
    std::vector<int> histories = {4, 8, 12, 16, 24};
    int         pht_bits     = 14;       /* PHT entries = 2^pht_bits */
    int         bins         = 200;
    int         width        = 1280;
    int         height       = 600;
    int         top_k        = 10;       /* top-K layers for gen_op / gen_reg */
    const char *title        = nullptr;  /* derived from metric if null */
    /* Predictor / BTB warm-up.  The first @warmup_bins bins drive
     * predictor state up but are excluded from y_max scaling so the
     * un-trained transient doesn't dominate the chart's vertical
     * range.  The warmup region is drawn with a subtle overlay so
     * the viewer can see it was deliberately de-emphasised. */
    int         warmup_bins  = 5;
    /* BTB entry counts to compare (analogous to gshare histories).
     * Power-of-two friendly defaults span typical front-end sizes. */
    std::vector<int> btb_entries = {64, 128, 256, 512, 1024};

    /* cache_miss: a single set-associative cache.  block_size /
     * sets / policy are scalars; @cache_assocs is the varied axis —
     * one chart line per associativity value.  Total cache size for
     * a given line is (block_size * sets * assoc) bytes; the
     * default sweep walks 4 KiB ... 64 KiB at block=64, sets=64. */
    int                 cache_block_size = 64;
    int                 cache_sets       = 64;
    std::vector<int>    cache_assocs     = {1, 2, 4, 8, 16};
    CachePolicy         cache_policy     = CachePolicy::LRU;
};

[[noreturn]] static void usage(int rc)
{
    std::fprintf(rc == 0 ? stdout : stderr,
"Usage: cst_visualize -m METRIC [options] TRACE.cst\n"
"\n"
"Metric (required):\n"
"  -m branch_mpki   Branch MPKI under gshare (lines per --history)\n"
"  -m wp_insns      Wasted WP insns/1k under gshare (lines per --history)\n"
"  -m wp_memops     Wasted WP memops/1k under gshare (lines per --history)\n"
"  -m btb_miss      BTB miss rate (lines per --btb-entries)\n"
"  -m cache_miss    CP-side cache miss rate (lines per --cache-assoc),\n"
"                   CP-only top vs WP-polluted bottom\n"
"  -m wp_divergence Fraction of WP branches whose predicted next-PC\n"
"                   differs from the recorded WP chain target (i.e.\n"
"                   the speculative path a real predictor would take\n"
"                   that the trace's single WP path does not cover)\n"
"  -m mem_pat       Memory-access-pattern breakdown (CP top / WP bottom)\n"
"  -m branch_dir    Branch direction / class breakdown (CP top / WP bottom)\n"
"  -m gen_op        GenericOpcode breakdown, top-K + other\n"
"  -m gen_reg       Generic destination-register breakdown, top-K + other\n"
"\n"
"Options:\n"
"  -H, --history=L,L,...   Gshare history lengths (default 4,8,12,16,24)\n"
"      --pht-bits=B        PHT log2 entries (default 14)\n"
"      --btb-entries=N,... BTB sizes for btb_miss (default 64,128,256,512,1024)\n"
"      --cache-block-size=N  Cache line size in bytes (default 64)\n"
"      --cache-sets=N      Cache sets (default 64)\n"
"      --cache-assoc=A,... Cache associativities (default 1,2,4,8,16)\n"
"      --cache-policy=P    Replacement: lru | mru | random (default lru)\n"
"      --warmup-bins=N     Bins excluded from y_max scaling (default 5)\n"
"  -b, --bins=N            Number of bins (default 200)\n"
"  -w, --width=PX          SVG width  (default 1280)\n"
"  -h, --height=PX         SVG height (default 600)\n"
"  -k, --top-k=N           Top-K layers for gen_op / gen_reg (default 10)\n"
"  -t, --title=STR         Override chart title\n"
"  -o, --output=FILE       Write SVG to FILE (default stdout)\n"
"      --help              Show this help and exit\n");
    std::exit(rc);
}

static int parse_int(const char *s, const char *opt)
{
    char *end = nullptr;
    long v = std::strtol(s, &end, 10);
    if (!end || *end || v < 0 || v > (1L << 30)) {
        std::fprintf(stderr, "cst_visualize: bad value for %s: %s\n",
                     opt, s);
        std::exit(2);
    }
    return (int)v;
}

static std::vector<int> parse_int_list(const char *s, const char *opt)
{
    std::vector<int> out;
    const char *p = s;
    while (*p) {
        char *end = nullptr;
        long v = std::strtol(p, &end, 10);
        if (!end || end == p || v < 0 || v > 64) {
            std::fprintf(stderr, "cst_visualize: bad %s entry near '%s'\n",
                         opt, p);
            std::exit(2);
        }
        out.push_back((int)v);
        p = end;
        if (*p == ',') p++;
        else if (*p != '\0') {
            std::fprintf(stderr, "cst_visualize: bad %s separator '%c'\n",
                         opt, *p);
            std::exit(2);
        }
    }
    if (out.empty()) {
        std::fprintf(stderr, "cst_visualize: empty list for %s\n", opt);
        std::exit(2);
    }
    return out;
}

static Metric parse_metric(const char *s)
{
    if (!std::strcmp(s, "branch_mpki")) return Metric::BranchMpki;
    if (!std::strcmp(s, "wp_insns"))    return Metric::WpInsns;
    if (!std::strcmp(s, "wp_memops"))   return Metric::WpMemops;
    if (!std::strcmp(s, "mem_pat"))     return Metric::MemPat;
    if (!std::strcmp(s, "branch_dir"))  return Metric::BranchDir;
    if (!std::strcmp(s, "gen_op"))      return Metric::GenOp;
    if (!std::strcmp(s, "gen_reg"))     return Metric::GenReg;
    if (!std::strcmp(s, "btb_miss"))    return Metric::BtbMiss;
    if (!std::strcmp(s, "wp_divergence")) return Metric::WpDivergence;
    if (!std::strcmp(s, "cache_miss"))  return Metric::CacheMiss;
    std::fprintf(stderr, "cst_visualize: unknown metric '%s'\n", s);
    std::exit(2);
}

static CachePolicy parse_cache_policy(const char *s)
{
    if (!std::strcmp(s, "lru"))    return CachePolicy::LRU;
    if (!std::strcmp(s, "mru"))    return CachePolicy::MRU;
    if (!std::strcmp(s, "random")) return CachePolicy::Random;
    std::fprintf(stderr, "cst_visualize: bad cache policy '%s'\n", s);
    std::exit(2);
}

static const char *cache_policy_name(CachePolicy p)
{
    switch (p) {
        case CachePolicy::LRU:    return "lru";
        case CachePolicy::MRU:    return "mru";
        case CachePolicy::Random: return "random";
    }
    return "?";
}

/* Predictor histories / BTB sizes can both grow large enough to make
 * parse_int_list's 64-cap insufficient; this variant skips that gate. */
static std::vector<int> parse_int_list_unbounded(const char *s,
                                                  const char *opt)
{
    std::vector<int> out;
    const char *p = s;
    while (*p) {
        char *end = nullptr;
        long v = std::strtol(p, &end, 10);
        if (!end || end == p || v <= 0 || v > (1L << 24)) {
            std::fprintf(stderr, "cst_visualize: bad %s entry near '%s'\n",
                         opt, p);
            std::exit(2);
        }
        out.push_back((int)v);
        p = end;
        if (*p == ',') p++;
        else if (*p != '\0') {
            std::fprintf(stderr, "cst_visualize: bad %s separator '%c'\n",
                         opt, *p);
            std::exit(2);
        }
    }
    if (out.empty()) {
        std::fprintf(stderr, "cst_visualize: empty list for %s\n", opt);
        std::exit(2);
    }
    return out;
}

static Options parse_args(int argc, char **argv)
{
    Options o;
    int i = 1;
    auto need = [&](int j, const char *name) {
        if (j >= argc) {
            std::fprintf(stderr, "cst_visualize: %s requires a value\n",
                         name);
            std::exit(2);
        }
    };
    while (i < argc) {
        const char *a = argv[i];
        if (!std::strcmp(a, "--help")) {
            usage(0);
        } else if (!std::strcmp(a, "-m") || !std::strcmp(a, "--metric")) {
            need(i + 1, a); o.metric = parse_metric(argv[++i]);
        } else if (!std::strncmp(a, "--metric=", 9)) {
            o.metric = parse_metric(a + 9);
        } else if (!std::strcmp(a, "-H") || !std::strcmp(a, "--history")) {
            need(i + 1, a); o.histories = parse_int_list(argv[++i], a);
        } else if (!std::strncmp(a, "--history=", 10)) {
            o.histories = parse_int_list(a + 10, "--history");
        } else if (!std::strncmp(a, "--pht-bits=", 11)) {
            o.pht_bits = parse_int(a + 11, "--pht-bits");
        } else if (!std::strncmp(a, "--btb-entries=", 14)) {
            o.btb_entries = parse_int_list_unbounded(a + 14, "--btb-entries");
        } else if (!std::strncmp(a, "--cache-block-size=", 19)) {
            o.cache_block_size = parse_int(a + 19, "--cache-block-size");
        } else if (!std::strncmp(a, "--cache-sets=", 13)) {
            o.cache_sets = parse_int(a + 13, "--cache-sets");
        } else if (!std::strncmp(a, "--cache-assoc=", 14)) {
            o.cache_assocs = parse_int_list_unbounded(a + 14, "--cache-assoc");
        } else if (!std::strncmp(a, "--cache-policy=", 15)) {
            o.cache_policy = parse_cache_policy(a + 15);
        } else if (!std::strncmp(a, "--warmup-bins=", 14)) {
            o.warmup_bins = parse_int(a + 14, "--warmup-bins");
        } else if (!std::strcmp(a, "-b") || !std::strcmp(a, "--bins")) {
            need(i + 1, a); o.bins = parse_int(argv[++i], a);
        } else if (!std::strncmp(a, "--bins=", 7)) {
            o.bins = parse_int(a + 7, "--bins");
        } else if (!std::strcmp(a, "-w") || !std::strcmp(a, "--width")) {
            need(i + 1, a); o.width = parse_int(argv[++i], a);
        } else if (!std::strncmp(a, "--width=", 8)) {
            o.width = parse_int(a + 8, "--width");
        } else if (!std::strcmp(a, "-h") || !std::strcmp(a, "--height")) {
            need(i + 1, a); o.height = parse_int(argv[++i], a);
        } else if (!std::strncmp(a, "--height=", 9)) {
            o.height = parse_int(a + 9, "--height");
        } else if (!std::strcmp(a, "-k") || !std::strcmp(a, "--top-k")) {
            need(i + 1, a); o.top_k = parse_int(argv[++i], a);
        } else if (!std::strncmp(a, "--top-k=", 8)) {
            o.top_k = parse_int(a + 8, "--top-k");
        } else if (!std::strcmp(a, "-t") || !std::strcmp(a, "--title")) {
            need(i + 1, a); o.title = argv[++i];
        } else if (!std::strncmp(a, "--title=", 8)) {
            o.title = a + 8;
        } else if (!std::strcmp(a, "-o") || !std::strcmp(a, "--output")) {
            need(i + 1, a); o.output = argv[++i];
        } else if (!std::strncmp(a, "--output=", 9)) {
            o.output = a + 9;
        } else if (a[0] == '-') {
            std::fprintf(stderr, "cst_visualize: unknown option '%s'\n", a);
            usage(2);
        } else {
            if (o.input) {
                std::fprintf(stderr, "cst_visualize: extra positional '%s'\n",
                             a);
                usage(2);
            }
            o.input = a;
        }
        i++;
    }
    if (!o.input) {
        std::fprintf(stderr, "cst_visualize: missing TRACE.cst\n");
        usage(2);
    }
    return o;
}

/* ===================================================================
 *                               gshare
 * =================================================================== */

/* Set-associative cache with LRU / MRU / random replacement.  A
 * single Cache instance is exactly one cache configuration; the
 * cache_miss metric instantiates one Cache per --cache-assoc value
 * and feeds all of them the same access stream so the lines on the
 * chart compare apples-to-apples.  No cache hierarchy is modelled. */
struct Cache {
    int block_log2;     /* log2(block_size_bytes) */
    int n_sets;
    int assoc;
    CachePolicy policy;
    /* sets x assoc, row-major.  tag == UINT64_MAX marks an invalid
     * (cold) way.  rank counts: a way's recency within its set,
     * 0 = LRU, assoc-1 = MRU.  Random policy ignores rank. */
    std::vector<uint64_t> tags;
    std::vector<int>      rank;
    uint64_t              rng_state = 0x9E3779B97F4A7C15ULL;

    Cache(int block_size, int sets, int a, CachePolicy p)
        : n_sets(sets), assoc(a), policy(p),
          tags((size_t)sets * a, ~uint64_t(0)),
          rank((size_t)sets * a, 0)
    {
        block_log2 = 0;
        while ((1 << block_log2) < block_size) block_log2++;
    }

    uint64_t set_of(uint64_t addr) const {
        return (addr >> block_log2) % (uint64_t)n_sets;
    }
    uint64_t tag_of(uint64_t addr) const {
        return (addr >> block_log2) / (uint64_t)n_sets;
    }

    /* Single access; returns true on hit, false on miss.  In either
     * case the touched way becomes MRU (rank=assoc-1) so the recency
     * order tracks usage.  Misses install the new tag, evicting the
     * per-policy victim. */
    bool access(uint64_t addr) {
        uint64_t s = set_of(addr);
        uint64_t t = tag_of(addr);
        size_t base = (size_t)s * (size_t)assoc;
        for (int w = 0; w < assoc; w++) {
            if (tags[base + w] == t) {
                /* hit: promote */
                int old = rank[base + w];
                for (int w2 = 0; w2 < assoc; w2++) {
                    if (rank[base + w2] > old) rank[base + w2]--;
                }
                rank[base + w] = assoc - 1;
                return true;
            }
        }
        /* miss: evict and install */
        int victim = 0;
        if (policy == CachePolicy::LRU) {
            for (int w = 1; w < assoc; w++) {
                if (rank[base + w] < rank[base + victim]) victim = w;
            }
        } else if (policy == CachePolicy::MRU) {
            for (int w = 1; w < assoc; w++) {
                if (rank[base + w] > rank[base + victim]) victim = w;
            }
        } else {
            rng_state = rng_state * 6364136223846793005ULL
                      + 1442695040888963407ULL;
            victim = (int)(rng_state % (uint64_t)assoc);
        }
        int old = rank[base + victim];
        for (int w2 = 0; w2 < assoc; w2++) {
            if (rank[base + w2] > old) rank[base + w2]--;
        }
        tags[base + victim] = t;
        rank[base + victim] = assoc - 1;
        return false;
    }
};

/* Branch Target Buffer — LRU map from branch PC to last-seen target.
 * Hit = PC present AND target matches the just-observed actual target.
 * Miss = PC absent OR cached target stale.  On any access we touch
 * the entry to most-recent; on miss we insert (evicting LRU when
 * full).  Models the front-end's BTB sizing question: how many
 * branches keep their targets predicted correctly? */
struct BTB {
    int                       max_entries;
    /* LRU order: front = most-recently-used, back = LRU candidate. */
    std::list<uint64_t>       order;
    struct Entry {
        std::list<uint64_t>::iterator it;
        uint64_t target;
    };
    std::unordered_map<uint64_t, Entry> table;

    explicit BTB(int n) : max_entries(n) { table.reserve(n * 2); }

    /* Look up @pc + observe @target.  Returns true on a useful hit
     * (PC present AND cached target equals @target); updates the
     * cache to reflect the new most-recent state in either case. */
    bool access(uint64_t pc, uint64_t target) {
        auto it = table.find(pc);
        if (it != table.end()) {
            bool match = (it->second.target == target);
            order.erase(it->second.it);
            order.push_front(pc);
            it->second.it = order.begin();
            it->second.target = target;
            return match;
        }
        if ((int)table.size() >= max_entries) {
            uint64_t victim = order.back();
            order.pop_back();
            table.erase(victim);
        }
        order.push_front(pc);
        table[pc] = {order.begin(), target};
        return false;
    }
};

struct GShare {
    int               history_bits;
    int               pht_bits;
    uint64_t          ghr        = 0;
    std::vector<uint8_t> pht;          /* 2-bit saturating counters */
    uint64_t          history_mask;
    uint64_t          pht_mask;

    GShare(int hb, int pb)
        : history_bits(hb), pht_bits(pb),
          pht(size_t{1} << pb, /* weakly not-taken */ 1)
    {
        history_mask = hb >= 64 ? ~uint64_t{0}
                                 : ((uint64_t{1} << hb) - 1);
        pht_mask     = (uint64_t{1} << pb) - 1;
    }

    /* PCs are typically 4-aligned (or 2 on Thumb / RVC).  Shift by 2
     * to drop the always-zero low bit cluster before XOR'ing with
     * the global history. */
    uint64_t index(uint64_t pc) const {
        return ((ghr & history_mask) ^ (pc >> 2)) & pht_mask;
    }

    bool predict(uint64_t pc) const { return pht[index(pc)] >= 2; }

    void update(uint64_t pc, bool taken) {
        uint64_t i = index(pc);
        if (taken) { if (pht[i] < 3) pht[i]++; }
        else       { if (pht[i] > 0) pht[i]--; }
        ghr = ((ghr << 1) | (taken ? 1u : 0u)) & history_mask;
    }
};

/* ===================================================================
 *                        Encoding-map name resolver
 * =================================================================== */

/* Maps from numeric ids in the trace to human-readable names from
 * the trace's encoding maps.  Falls back to a hex id when a name is
 * missing (e.g., trace built with a newer enum the consumer doesn't
 * recognise). */
static std::string lookup_name(
    const std::unordered_map<uint64_t, std::string> &m, uint64_t id)
{
    auto it = m.find(id);
    if (it != m.end()) return it->second;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%" PRIx64, id);
    return buf;
}

/* ===================================================================
 *                            SVG renderer
 * =================================================================== */

struct Series {
    std::string         label;
    std::string         color;
    std::vector<double> y;
};

struct ChartPlan {
    /* Chart geometry — describes where in the SVG this plan
     * renders.  Default (0/0/W/H) fills the whole canvas; dual-plot
     * mode sets up two ChartPlans whose viewports share the SVG. */
    int     viewport_x   = 0;
    int     viewport_y   = 0;
    int     viewport_w   = 1280;
    int     viewport_h   = 600;
    int     margin_left  = 80;
    int     margin_right = 220; /* room for legend */
    int     margin_top   = 50;
    int     margin_bot   = 60;
    /* When false, the x-axis tick numbers (instruction-count
     * labels) are suppressed — useful when stacking plots so only
     * the bottom plot prints the shared x-axis. */
    bool    show_x_labels = true;

    std::string title;
    std::string x_label;
    std::string y_label;

    /* X-axis: instruction-window position; each bin spans
     * x_bin_size insns; we render 0..nbins*x_bin_size on the axis. */
    uint64_t x_bin_size = 1;
    int      n_bins     = 0;

    /* Y-axis: fixed [0, y_max].  For stacked-area charts whose
     * layers sum to 100% per bin, set y_max = 1.0 and percent=true. */
    double y_max   = 1.0;
    bool   percent = false;

    /* mode: "lines" (one polyline per series) or "stacked"
     * (cumulative stacked polygons, layer 0 at bottom). */
    enum class Mode { Lines, Stacked };
    Mode mode = Mode::Lines;

    /* Bins [0, warmup_bins) are excluded from y_max scaling and
     * drawn under a translucent overlay so the viewer can see the
     * predictor / cache warm-up region was deliberately
     * de-emphasised.  Zero disables the overlay. */
    int warmup_bins = 0;

    std::vector<Series> series;
};

/* CSS-style palette: distinguishable hues + monotonic luminance for
 * stacked layers.  Wraps via modulo when more series than entries. */
static const char *palette_color(size_t i)
{
    static const char *p[] = {
        "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728",
        "#9467bd", "#8c564b", "#e377c2", "#7f7f7f",
        "#bcbd22", "#17becf", "#aec7e8", "#ffbb78",
        "#98df8a", "#ff9896", "#c5b0d5", "#c49c94",
        "#f7b6d2", "#c7c7c7", "#dbdb8d", "#9edae5",
    };
    return p[i % (sizeof(p) / sizeof(p[0]))];
}

static std::string xml_escape(const std::string &s)
{
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '<': o += "&lt;"; break;
            case '>': o += "&gt;"; break;
            case '&': o += "&amp;"; break;
            case '"': o += "&quot;"; break;
            default:  o += c;
        }
    }
    return o;
}

static std::string fmt_count(uint64_t v)
{
    char buf[32];
    if (v >= 1'000'000'000ULL) {
        std::snprintf(buf, sizeof(buf), "%.1fB", v / 1e9);
    } else if (v >= 1'000'000ULL) {
        std::snprintf(buf, sizeof(buf), "%.1fM", v / 1e6);
    } else if (v >= 1'000ULL) {
        std::snprintf(buf, sizeof(buf), "%.1fK", v / 1e3);
    } else {
        std::snprintf(buf, sizeof(buf), "%" PRIu64, v);
    }
    return buf;
}

static std::string fmt_double(double v, bool percent)
{
    char buf[32];
    if (percent) {
        std::snprintf(buf, sizeof(buf), "%.1f%%", v * 100);
    } else if (v >= 100) {
        std::snprintf(buf, sizeof(buf), "%.0f", v);
    } else if (v >= 10) {
        std::snprintf(buf, sizeof(buf), "%.1f", v);
    } else {
        std::snprintf(buf, sizeof(buf), "%.2f", v);
    }
    return buf;
}

/* Write the <svg ...> opening tag + background.  Caller follows with
 * one or more render_plan() calls and a write_svg_footer(). */
static void write_svg_header(std::FILE *out, int width, int height)
{
    std::fprintf(out,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<svg xmlns=\"http://www.w3.org/2000/svg\" "
        "viewBox=\"0 0 %d %d\" width=\"%d\" height=\"%d\" "
        "font-family=\"-apple-system, system-ui, sans-serif\" "
        "font-size=\"12\">\n",
        width, height, width, height);
    std::fprintf(out,
        "<rect width=\"%d\" height=\"%d\" fill=\"#ffffff\"/>\n",
        width, height);
}

static void write_svg_footer(std::FILE *out)
{
    std::fprintf(out, "</svg>\n");
}

/* Render one ChartPlan into its viewport.  Multiple plans can be
 * rendered into the same SVG by giving them disjoint viewports. */
static void render_plan(std::FILE *out, const ChartPlan &plan)
{
    const int VX = plan.viewport_x;
    const int VY = plan.viewport_y;
    const int VW = plan.viewport_w;
    const int VH = plan.viewport_h;
    /* L/R/T are absolute SVG coords; plot_w/plot_h are plot-area
     * extents inside the per-plan margins. */
    const int L = VX + plan.margin_left;
    const int R_edge = VX + VW - plan.margin_right;
    const int T = VY + plan.margin_top;
    const int B_edge = VY + VH - plan.margin_bot;
    const int plot_w = R_edge - L;
    const int plot_h = B_edge - T;

    auto x_of = [&](double bin_idx) {
        return L + (bin_idx / std::max(plan.n_bins, 1)) * plot_w;
    };
    auto y_of = [&](double v) {
        double frac = plan.y_max > 0 ? v / plan.y_max : 0.0;
        if (frac < 0) frac = 0;
        if (frac > 1) frac = 1;
        return T + plot_h - frac * plot_h;
    };

    /* Plot frame. */
    std::fprintf(out,
        "<rect x=\"%d\" y=\"%d\" width=\"%d\" height=\"%d\" "
        "fill=\"#fafafa\" stroke=\"#cccccc\"/>\n",
        L, T, plot_w, plot_h);

    /* Y-axis gridlines + labels. */
    int y_ticks = 5;
    for (int t = 0; t <= y_ticks; t++) {
        double v = (plan.y_max * t) / y_ticks;
        double y = y_of(v);
        std::fprintf(out,
            "<line x1=\"%d\" y1=\"%.2f\" x2=\"%d\" y2=\"%.2f\" "
            "stroke=\"#e0e0e0\" stroke-width=\"1\"/>\n",
            L, y, L + plot_w, y);
        std::fprintf(out,
            "<text x=\"%d\" y=\"%.2f\" text-anchor=\"end\" "
            "dominant-baseline=\"middle\" fill=\"#555\">%s</text>\n",
            L - 6, y, xml_escape(fmt_double(v, plan.percent)).c_str());
    }

    /* X-axis labels. */
    int x_ticks = 6;
    for (int t = 0; t <= x_ticks; t++) {
        double bin = (plan.n_bins * (double)t) / x_ticks;
        uint64_t insn = (uint64_t)(plan.x_bin_size * bin);
        double x = x_of(bin);
        std::fprintf(out,
            "<line x1=\"%.2f\" y1=\"%d\" x2=\"%.2f\" y2=\"%d\" "
            "stroke=\"#cccccc\" stroke-width=\"1\"/>\n",
            x, T + plot_h, x, T + plot_h + 4);
        if (plan.show_x_labels) {
            std::fprintf(out,
                "<text x=\"%.2f\" y=\"%d\" text-anchor=\"middle\" "
                "fill=\"#555\">%s</text>\n",
                x, T + plot_h + 18,
                xml_escape(fmt_count(insn)).c_str());
        }
    }

    /* Axis labels. */
    if (!plan.x_label.empty() && plan.show_x_labels) {
        std::fprintf(out,
            "<text x=\"%d\" y=\"%d\" text-anchor=\"middle\" "
            "fill=\"#333\" font-size=\"13\">%s</text>\n",
            L + plot_w / 2, B_edge - 8, xml_escape(plan.x_label).c_str());
    }
    if (!plan.y_label.empty()) {
        int yx = 22, yy = T + plot_h / 2;
        std::fprintf(out,
            "<text x=\"%d\" y=\"%d\" text-anchor=\"middle\" fill=\"#333\" "
            "font-size=\"13\" transform=\"rotate(-90, %d, %d)\">%s</text>\n",
            yx, yy, yx, yy, xml_escape(plan.y_label).c_str());
    }

    /* Title. */
    if (!plan.title.empty()) {
        std::fprintf(out,
            "<text x=\"%d\" y=\"%d\" text-anchor=\"middle\" "
            "fill=\"#222\" font-size=\"16\" font-weight=\"600\">%s</text>\n",
            L + plot_w / 2, T - 22, xml_escape(plan.title).c_str());
    }

    /* Warm-up overlay: a translucent rectangle over the first
     * @warmup_bins bins, plus a small "warmup" label at the top of
     * the overlay so it's clear the data isn't missing — it's
     * deliberately excluded from scaling. */
    if (plan.warmup_bins > 0 && plan.warmup_bins < plan.n_bins) {
        double x0 = x_of(0);
        double x1 = x_of(plan.warmup_bins);
        std::fprintf(out,
            "<rect x=\"%.2f\" y=\"%d\" width=\"%.2f\" height=\"%d\" "
            "fill=\"#000000\" fill-opacity=\"0.05\"/>\n",
            x0, T, x1 - x0, plot_h);
        std::fprintf(out,
            "<text x=\"%.2f\" y=\"%d\" text-anchor=\"start\" "
            "fill=\"#666\" font-size=\"10\" font-style=\"italic\">"
            "warmup</text>\n", x0 + 3, T + 12);
    }

    /* Plot. */
    if (plan.mode == ChartPlan::Mode::Lines) {
        for (size_t si = 0; si < plan.series.size(); si++) {
            const Series &s = plan.series[si];
            std::fprintf(out, "<polyline fill=\"none\" stroke=\"%s\" "
                "stroke-width=\"1.5\" points=\"",
                s.color.c_str());
            for (int b = 0; b < plan.n_bins; b++) {
                double v = (b < (int)s.y.size()) ? s.y[b] : 0.0;
                std::fprintf(out, "%.2f,%.2f ",
                             x_of(b + 0.5), y_of(v));
            }
            std::fprintf(out, "\"/>\n");
        }
    } else {
        /* Stacked area: layer 0 at the bottom; cumulative y per bin. */
        std::vector<double> cum(plan.n_bins, 0.0);
        for (size_t si = 0; si < plan.series.size(); si++) {
            const Series &s = plan.series[si];
            std::fprintf(out,
                "<polygon fill=\"%s\" fill-opacity=\"0.9\" "
                "stroke=\"%s\" stroke-width=\"0.5\" points=\"",
                s.color.c_str(), s.color.c_str());
            /* upper edge */
            for (int b = 0; b < plan.n_bins; b++) {
                double v = (b < (int)s.y.size()) ? s.y[b] : 0.0;
                std::fprintf(out, "%.2f,%.2f ",
                             x_of(b + 0.5), y_of(cum[b] + v));
            }
            /* lower edge (reverse) */
            for (int b = plan.n_bins - 1; b >= 0; b--) {
                std::fprintf(out, "%.2f,%.2f ",
                             x_of(b + 0.5), y_of(cum[b]));
            }
            std::fprintf(out, "\"/>\n");

            for (int b = 0; b < plan.n_bins; b++) {
                double v = (b < (int)s.y.size()) ? s.y[b] : 0.0;
                cum[b] += v;
            }
        }
    }

    /* Legend. */
    int lx = L + plot_w + 16;
    int ly = T + 8;
    for (size_t si = 0; si < plan.series.size(); si++) {
        const Series &s = plan.series[si];
        std::fprintf(out,
            "<rect x=\"%d\" y=\"%d\" width=\"12\" height=\"12\" "
            "fill=\"%s\"/>\n",
            lx, ly, s.color.c_str());
        std::fprintf(out,
            "<text x=\"%d\" y=\"%d\" dominant-baseline=\"middle\" "
            "fill=\"#222\">%s</text>\n",
            lx + 18, ly + 6, xml_escape(s.label).c_str());
        ly += 18;
        /* Wrap into a second column if the legend overflows the
         * plot height — keeps the SVG readable even with many top-K
         * layers. */
        if (ly > T + plot_h - 12 && si + 1 < plan.series.size()) {
            lx += 120;
            ly = T + 8;
        }
    }
}

/* ===================================================================
 *                          Bin accumulator
 * =================================================================== */

/* Generic per-bin matrix: rows = series, cols = bins.  Grows
 * dynamically (resizes both dims) so the walker doesn't need to know
 * the final trace length up-front. */
struct BinMatrix {
    int     n_series = 0;
    int     n_bins   = 0;
    std::vector<double> data;             /* row-major: series * n_bins + bin */

    void ensure_size(int series, int bins) {
        if (series <= n_series && bins <= n_bins) return;
        int new_s = std::max(n_series, series);
        int new_b = std::max(n_bins,   bins);
        std::vector<double> nd((size_t)new_s * new_b, 0.0);
        for (int s = 0; s < n_series; s++) {
            for (int b = 0; b < n_bins; b++) {
                nd[(size_t)s * new_b + b] = data[(size_t)s * n_bins + b];
            }
        }
        data = std::move(nd);
        n_series = new_s;
        n_bins   = new_b;
    }
    double &at(int s, int b) {
        ensure_size(s + 1, b + 1);
        return data[(size_t)s * n_bins + b];
    }
    double get(int s, int b) const {
        if (s >= n_series || b >= n_bins) return 0.0;
        return data[(size_t)s * n_bins + b];
    }
};

/* ===================================================================
 *                  Walker callback: dispatch per metric
 * =================================================================== */

/* Shared per-walk state. */
struct WalkCtx {
    const cst::Header *h;
    const std::vector<cst::Template> *templates;
    const std::unordered_map<uint32_t, size_t> *by_id;
    Options            opts;

    /* Bin width in CP insns.  Pulled from header.total_target_insns
     * when available; otherwise estimated from a first-pass count
     * heuristic before the walk (see main()). */
    uint64_t bin_width = 1;

    /* Cumulative CP-insn counter; the entry's bin index is the bin
     * containing the START of the entry's CP insns. */
    uint64_t cp_insns_so_far = 0;
    int      n_bins_total    = 0;  /* set when total_target known */

    /* Per-bin instruction count, so we can convert raw counters to
     * per-1k rates without a second pass. */
    std::vector<uint64_t> cp_insns_per_bin;

    /* Branch-PC + classification cache for gshare: each template's
     * terminating branch index + conditionality cached so the
     * per-entry hot path is index-free. */
    struct TermBranch {
        bool     is_branch          = false;
        bool     is_conditional     = false;
        bool     is_indirect_class  = false; /* indirect / return / syscall */
        uint64_t pc                 = 0;
        uint64_t fall_through       = 0;
        std::string class_name;
    };
    std::vector<TermBranch> term;

    /* Per-template precomputed accumulator updates for non-gshare
     * metrics (avoids re-classifying every visit). */
    struct OpcodeInsnCounts {
        /* Indexed by series-index; precomputed insns-per-series for
         * this template.  Populated for gen_op / gen_reg / mem_pat /
         * branch_dir as appropriate. */
        std::vector<std::pair<int, uint32_t>> series_increments;
    };
    std::vector<OpcodeInsnCounts> precomp;

    /* Predictors (only populated for gshare-driven metrics).  The
     * second set is CP+WP-pulluted: WP branches in each entry's
     * chain also update it, modelling the speculative pollution a
     * real predictor sees but a stat-tool driving only on CP
     * outcomes would not. */
    std::vector<GShare> predictors;
    std::vector<GShare> predictors_corrupted;
    /* BTBs (only populated for btb_miss / wp_divergence).  One per
     * --btb-entries value; a single per-entry walk feeds all of
     * them so distinct sizes see identical access streams. */
    std::vector<BTB>    btbs;
    std::vector<BTB>    btbs_corrupted;
    /* Caches (only populated for cache_miss).  caches[] are
     * CP-only; caches_corrupted[] are also walked by WP memops.
     * Both ALWAYS measure CP miss rate — the WP accesses to the
     * corrupted set only pollute LRU / tag occupancy. */
    std::vector<Cache>  caches;
    std::vector<Cache>  caches_corrupted;
    /* Per-bin CP memop count, denominator for cache miss rate. */
    std::vector<uint64_t> cp_memops_per_bin;
    /* Per-bin total branches observed by BTB, used to convert raw
     * miss counters to miss-rate (misses/branch). */
    std::vector<uint64_t> btb_branches_per_bin;

    /* Parallel bin matrix for the bottom pane in dual-plot metrics.
     * bins_wp.n_series == bins.n_series for predictor metrics
     * (corrupted variant) and may differ for breakdown metrics
     * (different label set / count). */
    BinMatrix bins_wp;
    /* Per-bin total WP memops / WP branches observed, used as
     * normalisers for the wp_divergence metric and as the
     * denominator for the WP breakdown panes' percent-stacking. */
    std::vector<uint64_t> wp_branches_per_bin;

    /* For wp_divergence: per-CP-bin vector of "match depth"
     * observations — how many WP-chain edges the BP+BTB model
     * predicts correctly before it diverges from the recorded chain
     * (or runs the chain to completion).  One observation per CP
     * branch whose chain has at least one edge.  Sorted later to
     * compute min / median / max along with the running mean. */
    std::vector<std::vector<int>> wp_depth_per_bin;

    /* For branch_dir / gen_op / gen_reg: dynamic label -> series-id
     * mapping built as we encounter new names. */
    std::unordered_map<std::string, int> label_to_series;
    std::vector<std::string>             label_names;
    int add_label(const std::string &name) {
        auto it = label_to_series.find(name);
        if (it != label_to_series.end()) return it->second;
        int id = (int)label_names.size();
        label_names.push_back(name);
        label_to_series[name] = id;
        return id;
    }

    BinMatrix bins;

    /* For branch_mpki / wp_insns / wp_memops we need next-entry
     * resolution (taken/not-taken from the next BB's start_pc).
     * Buffer the previous entry's classification, evaluate when the
     * next arrives. */
    bool      have_pending      = false;
    uint64_t  pending_bin       = 0;
    uint64_t  pending_branch_pc = 0;
    uint64_t  pending_fall_pc   = 0;
    bool      pending_is_branch = false;
    uint32_t  pending_wp_insns  = 0;
    uint32_t  pending_wp_memops = 0;
    /* Index into @term for the previous entry's template; lets
     * handle_branch_dir_entry recover the previous branch's class
     * (conditional / unconditional / indirect / etc.) when resolving
     * its taken/not-taken edge against this entry's start_pc. */
    size_t    pending_term_index = 0;
};

/* Helper: classify a template's terminating instruction for
 * gshare-vs-direction accounting. */
static WalkCtx::TermBranch classify_term(
    const cst::Template &t,
    const std::unordered_map<uint64_t, std::string> &bt_map)
{
    WalkCtx::TermBranch tb;
    if (t.insns.empty()) return tb;
    const auto &last = t.insns.back();
    tb.pc            = last.pc;
    tb.fall_through  = t.fall_through_pc;
    tb.is_branch     = (last.branch_type != 0);
    if (!tb.is_branch) return tb;

    /* Look up the name to identify direct vs indirect vs return vs
     * syscall.  The trace's encoding map carries the canonical
     * BRANCH_* names. */
    std::string n = lookup_name(bt_map, last.branch_type);
    tb.class_name = n;
    bool name_says_indirect =
        n.find("INDIRECT") != std::string::npos ||
        n.find("RETURN")   != std::string::npos ||
        n.find("SYSCALL")  != std::string::npos ||
        n.find("REP")      != std::string::npos;
    tb.is_indirect_class = name_says_indirect;
    bool unconditional =
        n.find("DIRECT_JUMP") != std::string::npos ||
        n.find("SYSCALL")     != std::string::npos ||
        n.find("RETURN")      != std::string::npos ||
        n.find("INDIRECT")    != std::string::npos;
    tb.is_conditional =
        last.branch_conditional && !name_says_indirect && !unconditional;
    /* COND_DIRECT explicitly marks conditional even if the template
     * flag is set differently. */
    if (n.find("COND") != std::string::npos) {
        tb.is_conditional = true;
    }
    return tb;
}

/* ===================================================================
 *                         Per-metric handlers
 * =================================================================== */

/* Map @cp_insns to the bin index used by all handlers.  Capped at
 * opts.bins - 1 so any trailing overflow (the deferred-exit fix lets
 * the trace cover slightly more than the configured window_stop)
 * folds into the last bin instead of growing the chart by one
 * extra mostly-empty bin on the right. */
static int bin_of(const WalkCtx &ctx, uint64_t cp_insns)
{
    int b = (int)(cp_insns / ctx.bin_width);
    if (b >= ctx.opts.bins) b = ctx.opts.bins - 1;
    return b;
}

static void handle_gshare_entry(WalkCtx &ctx, const cst::DecodedEntry &e)
{
    const cst::Template &t = (*ctx.templates)[ctx.by_id->at(e.template_id)];
    uint32_t n_insns = (uint32_t)t.insns.size();
    int bin = bin_of(ctx, ctx.cp_insns_so_far);

    /* Resolve the PREVIOUS entry's branch outcome now that we know
     * this entry's start_pc.  Taken iff this start_pc != previous
     * fall_through.  Drive both predictor variants: pred[*] sees
     * only CP outcomes; pred_corrupted[*] also sees the just-
     * completed WP chain's branches (loop below). */
    auto resolve_cp = [&](int pi, bool taken) {
        GShare &g = ctx.predictors[pi];
        bool pred = g.predict(ctx.pending_branch_pc);
        bool mispred = (pred != taken);
        if (ctx.opts.metric == Metric::BranchMpki) {
            if (mispred) ctx.bins.at(pi, (int)ctx.pending_bin) += 1.0;
        } else if (ctx.opts.metric == Metric::WpInsns) {
            if (mispred) ctx.bins.at(pi, (int)ctx.pending_bin)
                            += ctx.pending_wp_insns;
        } else if (ctx.opts.metric == Metric::WpMemops) {
            if (mispred) ctx.bins.at(pi, (int)ctx.pending_bin)
                            += ctx.pending_wp_memops;
        }
        g.update(ctx.pending_branch_pc, taken);
    };
    auto resolve_corrupted = [&](int pi, bool taken) {
        GShare &g = ctx.predictors_corrupted[pi];
        bool pred = g.predict(ctx.pending_branch_pc);
        bool mispred = (pred != taken);
        if (ctx.opts.metric == Metric::BranchMpki) {
            if (mispred) ctx.bins_wp.at(pi, (int)ctx.pending_bin) += 1.0;
        } else if (ctx.opts.metric == Metric::WpInsns) {
            if (mispred) ctx.bins_wp.at(pi, (int)ctx.pending_bin)
                            += ctx.pending_wp_insns;
        } else if (ctx.opts.metric == Metric::WpMemops) {
            if (mispred) ctx.bins_wp.at(pi, (int)ctx.pending_bin)
                            += ctx.pending_wp_memops;
        }
        g.update(ctx.pending_branch_pc, taken);
    };
    if (ctx.have_pending && ctx.pending_is_branch) {
        bool taken = (t.start_pc != ctx.pending_fall_pc);
        for (size_t pi = 0; pi < ctx.predictors.size(); pi++) {
            resolve_cp((int)pi, taken);
            resolve_corrupted((int)pi, taken);
        }
    }

    /* Per-bin CP insn count keeps the normaliser correct (per-1k
     * uses insns_in_bin, not total). */
    if ((int)ctx.cp_insns_per_bin.size() <= bin) {
        ctx.cp_insns_per_bin.resize(bin + 1, 0);
    }
    ctx.cp_insns_per_bin[bin] += n_insns;

    /* Capture this entry's terminating branch so the NEXT entry can
     * close it.  Only conditional / non-indirect-class branches are
     * accounted (those gshare can usefully predict). */
    const WalkCtx::TermBranch &tb =
        ctx.term[ctx.by_id->at(e.template_id)];
    ctx.have_pending = true;
    ctx.pending_bin  = (uint64_t)bin;
    ctx.pending_branch_pc = tb.pc;
    ctx.pending_fall_pc   = tb.fall_through;
    ctx.pending_is_branch = tb.is_branch && tb.is_conditional;

    /* Wasted-WP scoring: WP chain insns / memops contributed by this
     * BB get attributed to its own branch.  Sum across WP entries. */
    ctx.pending_wp_insns  = 0;
    ctx.pending_wp_memops = 0;
    for (const auto &wp : e.wp_entries) {
        ctx.pending_wp_insns += wp.n_insns;
        for (const auto &dp : wp.dyn_params) {
            (void)dp;
            ctx.pending_wp_memops++;
        }
    }

    /* WP-side predictor pollution.  Walk the just-completed WP
     * chain pairwise: WP entry i's terminating branch resolved to
     * WP entry i+1's start_pc.  For each such branch, update the
     * CORRUPTED predictors only (the CP-only set is by design
     * insulated from WP).  The chain's last entry's branch has no
     * recorded successor, so we drop it. */
    for (size_t i = 0; i + 1 < e.wp_entries.size(); i++) {
        const auto &cur_wp  = e.wp_entries[i];
        const auto &next_wp = e.wp_entries[i + 1];
        auto it = ctx.by_id->find(cur_wp.template_id);
        if (it == ctx.by_id->end()) continue;
        auto nit = ctx.by_id->find(next_wp.template_id);
        if (nit == ctx.by_id->end()) continue;
        const WalkCtx::TermBranch &wtb = ctx.term[it->second];
        if (!wtb.is_branch || !wtb.is_conditional) continue;
        const cst::Template &nt = (*ctx.templates)[nit->second];
        bool taken = (nt.start_pc != wtb.fall_through);
        for (auto &g : ctx.predictors_corrupted) {
            g.update(wtb.pc, taken);
        }
    }

    ctx.cp_insns_so_far += n_insns;
}

/* BTB drive: track every CP branch's (PC, target) pair through each
 * configured BTB size.  The target is observed from the NEXT entry's
 * start_pc (taken edge) or the current BB's fall_through (not-taken),
 * resolved via the same pending-branch mechanism the gshare path
 * uses. */
static void handle_btb_entry(WalkCtx &ctx, const cst::DecodedEntry &e)
{
    const cst::Template &t = (*ctx.templates)[ctx.by_id->at(e.template_id)];
    uint32_t n_insns = (uint32_t)t.insns.size();
    int bin = bin_of(ctx, ctx.cp_insns_so_far);

    /* Resolve previous branch's observed target via this entry's
     * start_pc, then drive each BTB and tally misses into the
     * previous bin.  Two parallel sets of BTBs: cp_only sees CP
     * targets exclusively; corrupted sees CP + WP. */
    if (ctx.have_pending && ctx.pending_is_branch) {
        uint64_t actual_target = t.start_pc;
        int  pbin = (int)ctx.pending_bin;
        if (pbin < ctx.opts.bins) {
            if ((int)ctx.btb_branches_per_bin.size() <= pbin) {
                ctx.btb_branches_per_bin.resize(pbin + 1, 0);
            }
            ctx.btb_branches_per_bin[pbin]++;
        }
        for (size_t bi = 0; bi < ctx.btbs.size(); bi++) {
            bool hit = ctx.btbs[bi].access(ctx.pending_branch_pc,
                                            actual_target);
            if (!hit && pbin < ctx.opts.bins) {
                ctx.bins.at((int)bi, pbin) += 1.0;
            }
        }
        for (size_t bi = 0; bi < ctx.btbs_corrupted.size(); bi++) {
            bool hit = ctx.btbs_corrupted[bi].access(
                ctx.pending_branch_pc, actual_target);
            if (!hit && pbin < ctx.opts.bins) {
                ctx.bins_wp.at((int)bi, pbin) += 1.0;
            }
        }
    }

    if ((int)ctx.cp_insns_per_bin.size() <= bin) {
        ctx.cp_insns_per_bin.resize(bin + 1, 0);
    }
    ctx.cp_insns_per_bin[bin] += n_insns;

    /* Cache this entry's terminating branch for next resolution.  BTB
     * gets ALL branches (direct, indirect, conditional, ret) — the
     * BTB caches every kind of branch target, not just predictable
     * ones. */
    const WalkCtx::TermBranch &tb =
        ctx.term[ctx.by_id->at(e.template_id)];
    ctx.have_pending      = true;
    ctx.pending_bin       = (uint64_t)bin;
    ctx.pending_branch_pc = tb.pc;
    ctx.pending_fall_pc   = tb.fall_through;
    ctx.pending_is_branch = tb.is_branch;

    /* WP-side BTB pollution.  Walk this entry's WP chain pairwise:
     * WP entry i's terminating branch resolved to WP entry i+1's
     * start_pc.  Feed each (PC, target) into the corrupted BTBs
     * only.  These accesses pollute the LRU but DO NOT count toward
     * the displayed CP miss rate (which only measures CP branches). */
    for (size_t i = 0; i + 1 < e.wp_entries.size(); i++) {
        const auto &cur_wp  = e.wp_entries[i];
        const auto &next_wp = e.wp_entries[i + 1];
        auto it = ctx.by_id->find(cur_wp.template_id);
        if (it == ctx.by_id->end()) continue;
        auto nit = ctx.by_id->find(next_wp.template_id);
        if (nit == ctx.by_id->end()) continue;
        const WalkCtx::TermBranch &wtb = ctx.term[it->second];
        if (!wtb.is_branch) continue;
        const cst::Template &nt = (*ctx.templates)[nit->second];
        for (auto &b : ctx.btbs_corrupted) {
            (void)b.access(wtb.pc, nt.start_pc);
        }
    }

    ctx.cp_insns_so_far += n_insns;
}

/* cache_miss: drive a set-associative cache per --cache-assoc value
 * with this CP entry's memops, counting CP misses.  WP memops of
 * the same entry get fed into the corrupted-variant caches only —
 * those caches measure CP miss rate but their tag/LRU state is
 * polluted by every speculative access the WP chain recorded. */
static void handle_cache_miss_entry(WalkCtx &ctx,
                                     const cst::DecodedEntry &e)
{
    const cst::Template &t = (*ctx.templates)[ctx.by_id->at(e.template_id)];
    int bin = bin_of(ctx, ctx.cp_insns_so_far);

    /* CP memops drive BOTH cache variants, counted only in their
     * respective bin matrices for CP miss-rate computation. */
    uint64_t n_cp_memops = 0;
    for (const auto &dp : e.dyn_params) {
        n_cp_memops++;
        for (size_t ci = 0; ci < ctx.caches.size(); ci++) {
            bool hit = ctx.caches[ci].access(dp.addr);
            if (!hit) ctx.bins.at((int)ci, bin) += 1.0;
        }
        for (size_t ci = 0; ci < ctx.caches_corrupted.size(); ci++) {
            bool hit = ctx.caches_corrupted[ci].access(dp.addr);
            if (!hit) ctx.bins_wp.at((int)ci, bin) += 1.0;
        }
    }
    if ((int)ctx.cp_memops_per_bin.size() <= bin) {
        ctx.cp_memops_per_bin.resize(bin + 1, 0);
    }
    ctx.cp_memops_per_bin[bin] += n_cp_memops;

    /* WP memops pollute the corrupted variant only, no counting. */
    for (const auto &wp : e.wp_entries) {
        for (const auto &dp : wp.dyn_params) {
            for (auto &c : ctx.caches_corrupted) (void)c.access(dp.addr);
        }
    }

    ctx.cp_insns_so_far += t.insns.size();
}

static void handle_mem_pat_entry(WalkCtx &ctx, const cst::DecodedEntry &e)
{
    const cst::Template &t = (*ctx.templates)[ctx.by_id->at(e.template_id)];
    int bin = bin_of(ctx, ctx.cp_insns_so_far);
    /* Layers: 0=none, 1=regular, 2=irregular, 3=random.  CP-side
     * counted in units of memops on this visit (one CP memop per
     * dyn_param entry); WP-side aggregates the same way over each
     * WP entry's dyn_params, using its own template's pat_wp. */
    for (const auto &dp : e.dyn_params) {
        if (dp.insn_index >= t.insns.size()) continue;
        if (dp.insn_index >= t.profile.insns.size()) continue;
        uint8_t pat = t.profile.insns[dp.insn_index].pat_cp;
        if (pat > 3) pat = 0;
        ctx.bins.at((int)pat, bin) += 1.0;
    }
    for (const auto &wp : e.wp_entries) {
        auto it = ctx.by_id->find(wp.template_id);
        if (it == ctx.by_id->end()) continue;
        const cst::Template &wt = (*ctx.templates)[it->second];
        for (const auto &dp : wp.dyn_params) {
            if (dp.insn_index >= wt.profile.insns.size()) continue;
            uint8_t pat = wt.profile.insns[dp.insn_index].pat_wp;
            if (pat > 3) pat = 0;
            ctx.bins_wp.at((int)pat, bin) += 1.0;
        }
    }
    ctx.cp_insns_so_far += t.insns.size();
}

static void handle_branch_dir_entry(WalkCtx &ctx, const cst::DecodedEntry &e)
{
    const cst::Template &t = (*ctx.templates)[ctx.by_id->at(e.template_id)];
    int bin = bin_of(ctx, ctx.cp_insns_so_far);

    /* Resolve the PREVIOUS entry's direction now we know start_pc. */
    if (ctx.have_pending && ctx.pending_is_branch) {
        bool taken = (t.start_pc != ctx.pending_fall_pc);
        /* Series labels are "<branch_class> <taken|notTaken>" for
         * the conditional family, and "<branch_class>" for the
         * always-taken families (unconditional / indirect / return /
         * syscall). */
        const WalkCtx::TermBranch &ptb =
            ctx.term[/* by_id was looked up when pending was set */
                     ctx.pending_term_index];
        std::string label;
        if (ptb.is_conditional) {
            label = ptb.class_name + (taken ? " taken" : " not-taken");
        } else {
            label = ptb.class_name;
        }
        int sid = ctx.add_label(label);
        ctx.bins.at(sid, (int)ctx.pending_bin) += 1.0;
    }

    /* Stash this entry's classification for the next resolution.  We
     * defer the series-id allocation until resolution-time so the
     * label encodes taken/not-taken. */
    const size_t tidx = ctx.by_id->at(e.template_id);
    const WalkCtx::TermBranch &tb = ctx.term[tidx];
    ctx.have_pending      = tb.is_branch;
    ctx.pending_bin       = (uint64_t)bin;
    ctx.pending_term_index = tidx;
    ctx.pending_branch_pc = tb.pc;
    ctx.pending_fall_pc   = tb.fall_through;
    ctx.pending_is_branch = tb.is_branch;

    /* WP-side branch direction breakdown.  Walk the chain pairwise
     * to recover each WP branch's taken/not-taken; the chain's last
     * entry has no recorded successor and is dropped. */
    for (size_t i = 0; i + 1 < e.wp_entries.size(); i++) {
        const auto &cur_wp  = e.wp_entries[i];
        const auto &next_wp = e.wp_entries[i + 1];
        auto it = ctx.by_id->find(cur_wp.template_id);
        if (it == ctx.by_id->end()) continue;
        auto nit = ctx.by_id->find(next_wp.template_id);
        if (nit == ctx.by_id->end()) continue;
        const WalkCtx::TermBranch &wtb = ctx.term[it->second];
        if (!wtb.is_branch) continue;
        const cst::Template &nt = (*ctx.templates)[nit->second];
        bool wp_taken = (nt.start_pc != wtb.fall_through);
        std::string label = wtb.is_conditional
            ? wtb.class_name + (wp_taken ? " taken" : " not-taken")
            : wtb.class_name;
        int sid = ctx.add_label(label);
        ctx.bins_wp.at(sid, bin) += 1.0;
    }

    ctx.cp_insns_so_far += t.insns.size();
}

static void handle_genop_entry(WalkCtx &ctx, const cst::DecodedEntry &e)
{
    const cst::Template &t = (*ctx.templates)[ctx.by_id->at(e.template_id)];
    int bin = bin_of(ctx, ctx.cp_insns_so_far);
    const auto &precomp = ctx.precomp[ctx.by_id->at(e.template_id)];
    for (const auto &p : precomp.series_increments) {
        ctx.bins.at(p.first, bin) += p.second;
    }
    ctx.cp_insns_so_far += t.insns.size();
}

/* wp_divergence: for each CP branch's WP chain, how many edges does
 * a real-hardware predictor (BP + BTB) follow before its predicted
 * next-PC stops matching the recorded WP chain?  That depth tells
 * us how far the trace's single recorded wrong-path covers the
 * paths a real machine would actually take.  Per CP-insn bin we
 * collect the depths into a vector and render min / mean / median /
 * max over the run.
 *
 * Uses a single BP variant (largest --history) and a single BTB
 * (largest --btb-entries); sensitivity to those parameters is left
 * to the dedicated branch_mpki / btb_miss metrics.
 */
static void handle_wp_divergence_entry(WalkCtx &ctx,
                                        const cst::DecodedEntry &e)
{
    const cst::Template &t = (*ctx.templates)[ctx.by_id->at(e.template_id)];
    int bin = bin_of(ctx, ctx.cp_insns_so_far);

    /* Train predictors / BTB on the previous CP branch, before
     * stepping the WP chain. */
    if (ctx.have_pending && ctx.pending_is_branch) {
        bool taken = (t.start_pc != ctx.pending_fall_pc);
        for (auto &g : ctx.predictors) g.update(ctx.pending_branch_pc, taken);
        for (auto &b : ctx.btbs)       b.access(ctx.pending_branch_pc, t.start_pc);
    }
    const WalkCtx::TermBranch &tb =
        ctx.term[ctx.by_id->at(e.template_id)];
    ctx.have_pending      = true;
    ctx.pending_bin       = (uint64_t)bin;
    ctx.pending_branch_pc = tb.pc;
    ctx.pending_fall_pc   = tb.fall_through;
    ctx.pending_is_branch = tb.is_branch;

    if (e.wp_entries.size() < 2) {
        ctx.cp_insns_so_far += t.insns.size();
        return;
    }

    /* Walk the chain pairwise: count how many leading edges the
     * BP+BTB predicts to the recorded successor before the first
     * mismatch.  Walk to the END if every prediction matches; the
     * depth then equals (chain_size - 1) and represents "the trace's
     * WP recording is consistent with what a real predictor would
     * have taken." */
    int matched = 0;
    bool diverged = false;
    for (size_t i = 0; i + 1 < e.wp_entries.size(); i++) {
        const auto &cur_wp  = e.wp_entries[i];
        const auto &next_wp = e.wp_entries[i + 1];
        auto it = ctx.by_id->find(cur_wp.template_id);
        if (it == ctx.by_id->end()) break;
        auto nit = ctx.by_id->find(next_wp.template_id);
        if (nit == ctx.by_id->end()) break;
        const WalkCtx::TermBranch &wtb = ctx.term[it->second];
        if (!wtb.is_branch) break;
        const cst::Template &nt = (*ctx.templates)[nit->second];
        uint64_t actual_target = nt.start_pc;
        bool wp_taken = (actual_target != wtb.fall_through);

        GShare &g = ctx.predictors[0];
        BTB    &b = ctx.btbs[0];
        bool pred_taken = wtb.is_conditional ? g.predict(wtb.pc) : true;
        auto btb_it = b.table.find(wtb.pc);
        uint64_t pred_target = pred_taken
            ? (btb_it != b.table.end() ? btb_it->second.target
                                        : wtb.fall_through)
            : wtb.fall_through;
        if (pred_target == actual_target) {
            matched++;
        } else {
            diverged = true;
        }
        g.update(wtb.pc, wp_taken);
        b.access(wtb.pc, actual_target);
        if (diverged) break;
    }

    /* Record the observation in the bin's depth list, growing it as
     * needed. */
    if ((int)ctx.wp_depth_per_bin.size() <= bin) {
        ctx.wp_depth_per_bin.resize(bin + 1);
    }
    ctx.wp_depth_per_bin[bin].push_back(matched);

    ctx.cp_insns_so_far += t.insns.size();
}

/* gen_reg uses the same shape as genop — precomputed per-template
 * series increments. */
static void handle_genreg_entry(WalkCtx &ctx, const cst::DecodedEntry &e)
{
    handle_genop_entry(ctx, e);   /* same precomp shape */
}

/* ===================================================================
 *                            Main driver
 * =================================================================== */

int main(int argc, char **argv)
{
    Options opts = parse_args(argc, argv);

    std::unique_ptr<cst::CstFile> cf;
    try {
        cf = cst::cst_file_open(opts.input);
    } catch (const std::exception &ex) {
        std::fprintf(stderr, "cst_visualize: open '%s': %s\n",
                     opts.input, ex.what());
        return 1;
    }

    std::vector<cst::Template> templates;
    std::unordered_map<uint32_t, size_t> by_id;
    cst::Header h;
    try {
        h = cst::parse_header(cf->header(), &templates, &by_id);
    } catch (const std::exception &ex) {
        std::fprintf(stderr, "cst_visualize: parse header: %s\n",
                     ex.what());
        return 1;
    }

    /* Decide bin width up front.  total_target_insns is the
     * configured-stop number from the header; for unbounded
     * (icount-mode without stop) it's 0 and we fall back to a
     * profile-summed estimate via t.profile.exec_cp * t.insns.size().
     * In both cases we know the bin width before the walk so the
     * x-axis is stable. */
    uint64_t total_cp_insns = 0;
    if (h.total_target_insns > 0) {
        total_cp_insns = h.total_target_insns;
    } else {
        for (const auto &t : templates) {
            total_cp_insns += (uint64_t)t.profile.exec_cp * t.insns.size();
        }
        if (total_cp_insns == 0) total_cp_insns = 1;
    }
    uint64_t bin_width = total_cp_insns / (uint64_t)opts.bins;
    if (bin_width == 0) bin_width = 1;

    /* Pre-classify every template's terminating branch so per-entry
     * dispatch stays O(1).  Also precompute the gen_op / gen_reg /
     * mem_pat / branch_dir per-template series-increments. */
    WalkCtx ctx;
    ctx.h         = &h;
    ctx.templates = &templates;
    ctx.by_id     = &by_id;
    ctx.opts      = opts;
    ctx.bin_width = bin_width;

    ctx.term.resize(templates.size());
    for (size_t i = 0; i < templates.size(); i++) {
        ctx.term[i] = classify_term(templates[i], h.maps.branch_type);
    }

    /* Build per-template series increments for the metrics that use
     * them.  Done up-front so the per-entry hot path is just one
     * matrix update per (series, bin). */
    if (opts.metric == Metric::GenOp || opts.metric == Metric::GenReg) {
        /* First pass: count per-name occurrences (opcode or
         * destination register) across the trace, weighted by
         * exec_cp so we can pick the top-K names to render and
         * group the rest into "other". */
        std::unordered_map<std::string, uint64_t> name_weight;
        for (const auto &t : templates) {
            uint64_t w = t.profile.exec_cp;
            if (w == 0) continue;
            for (const auto &ins : t.insns) {
                if (opts.metric == Metric::GenOp) {
                    name_weight[lookup_name(h.maps.opcode, ins.opcode)] += w;
                } else {
                    for (uint8_t r : ins.dst_regs) {
                        name_weight[lookup_name(h.maps.reg, r)] += w;
                    }
                }
            }
        }
        std::vector<std::pair<std::string, uint64_t>> sorted(
            name_weight.begin(), name_weight.end());
        std::sort(sorted.begin(), sorted.end(),
            [](const auto &a, const auto &b) {
                return a.second > b.second;
            });
        int top = std::min((int)sorted.size(), opts.top_k);
        for (int i = 0; i < top; i++) {
            ctx.add_label(sorted[i].first);
        }
        int other_id = ctx.add_label("other");

        ctx.precomp.resize(templates.size());
        for (size_t i = 0; i < templates.size(); i++) {
            const auto &t = templates[i];
            std::unordered_map<int, uint32_t> per_series;
            for (const auto &ins : t.insns) {
                if (opts.metric == Metric::GenOp) {
                    std::string n = lookup_name(h.maps.opcode, ins.opcode);
                    auto it = ctx.label_to_series.find(n);
                    int sid = (it != ctx.label_to_series.end()
                                   && it->second < top)
                              ? it->second : other_id;
                    per_series[sid]++;
                } else {
                    /* gen_reg counts each dst-reg occurrence as 1
                     * (an instruction with two dst regs contributes
                     * one to each). */
                    for (uint8_t r : ins.dst_regs) {
                        std::string n = lookup_name(h.maps.reg, r);
                        auto it = ctx.label_to_series.find(n);
                        int sid = (it != ctx.label_to_series.end()
                                       && it->second < top)
                                  ? it->second : other_id;
                        per_series[sid]++;
                    }
                }
            }
            for (auto &p : per_series) {
                ctx.precomp[i].series_increments.push_back(
                    {p.first, p.second});
            }
        }
    } else if (opts.metric == Metric::MemPat) {
        ctx.add_label("none");
        ctx.add_label("regular");
        ctx.add_label("irregular");
        ctx.add_label("random");
    } else if (opts.metric == Metric::BranchMpki ||
               opts.metric == Metric::WpInsns    ||
               opts.metric == Metric::WpMemops) {
        for (int hl : opts.histories) {
            ctx.predictors.emplace_back(hl, opts.pht_bits);
            ctx.predictors_corrupted.emplace_back(hl, opts.pht_bits);
            char b[32];
            std::snprintf(b, sizeof(b), "history=%d", hl);
            ctx.add_label(b);
        }
    } else if (opts.metric == Metric::BtbMiss) {
        ctx.btbs.reserve(opts.btb_entries.size());
        ctx.btbs_corrupted.reserve(opts.btb_entries.size());
        for (int n : opts.btb_entries) {
            ctx.btbs.emplace_back(n);
            ctx.btbs_corrupted.emplace_back(n);
            char b[32];
            std::snprintf(b, sizeof(b), "%d entries", n);
            ctx.add_label(b);
        }
    } else if (opts.metric == Metric::CacheMiss) {
        ctx.caches.reserve(opts.cache_assocs.size());
        ctx.caches_corrupted.reserve(opts.cache_assocs.size());
        for (int a : opts.cache_assocs) {
            ctx.caches.emplace_back(opts.cache_block_size,
                                     opts.cache_sets, a,
                                     opts.cache_policy);
            ctx.caches_corrupted.emplace_back(opts.cache_block_size,
                                               opts.cache_sets, a,
                                               opts.cache_policy);
            uint64_t kib = (uint64_t)opts.cache_block_size *
                           (uint64_t)opts.cache_sets *
                           (uint64_t)a / 1024;
            char b[64];
            std::snprintf(b, sizeof(b), "assoc=%d (%" PRIu64 " KiB)",
                          a, kib);
            ctx.add_label(b);
        }
    } else if (opts.metric == Metric::WpDivergence) {
        /* BP variants: one line per history.  A single BTB (the
         * largest configured size) plays the role of an oracle
         * target store; sensitivity to BTB capacity is left to
         * the dedicated btb_miss metric. */
        for (int hl : opts.histories) {
            ctx.predictors.emplace_back(hl, opts.pht_bits);
            char b[32];
            std::snprintf(b, sizeof(b), "history=%d", hl);
            ctx.add_label(b);
        }
        int biggest = 0;
        for (int n : opts.btb_entries) {
            if (n > biggest) biggest = n;
        }
        if (biggest > 0) ctx.btbs.emplace_back(biggest);
    }
    /* branch_dir labels are allocated lazily as classes appear.  Pre-
     * seed with "no branch" series so it always renders even when no
     * trailing non-branch BBs exist (it just won't accumulate). */

    /* Walk. */
    auto body_stream = cst::body_stream_open(*cf);
    cst::BodyWalker walker(h, templates, by_id, body_stream->reader());

    using EntryFn = void (*)(WalkCtx &, const cst::DecodedEntry &);
    EntryFn fn = nullptr;
    switch (opts.metric) {
        case Metric::BranchMpki:
        case Metric::WpInsns:
        case Metric::WpMemops:
            fn = handle_gshare_entry; break;
        case Metric::MemPat:
            fn = handle_mem_pat_entry; break;
        case Metric::BranchDir:
            fn = handle_branch_dir_entry; break;
        case Metric::GenOp:
            fn = handle_genop_entry; break;
        case Metric::GenReg:
            fn = handle_genreg_entry; break;
        case Metric::BtbMiss:
            fn = handle_btb_entry; break;
        case Metric::WpDivergence:
            fn = handle_wp_divergence_entry; break;
        case Metric::CacheMiss:
            fn = handle_cache_miss_entry; break;
    }

    walker.walk([&](const cst::DecodedEntry &e) { fn(ctx, e); });
    try { body_stream->finalize(); }
    catch (...) {}

    /* Finalize the trailing pending-branch resolution for the gshare
     * metrics — there's no next entry to peek at, so we drop the
     * uninspected last branch.  Bin count is always exactly the
     * configured @opts.bins (bin_of caps any overflow). */
    int actual_bins = opts.bins;

    /* Build the chart plan and render. */
    ChartPlan plan;
    plan.viewport_w = opts.width;
    plan.viewport_h = opts.height;
    plan.n_bins = actual_bins;
    plan.x_bin_size = bin_width;
    plan.x_label = "CP instruction window";

    auto pick_title = [&]() -> std::string {
        if (opts.title) return opts.title;
        switch (opts.metric) {
            case Metric::BranchMpki:
                return "Branch MPKI under gshare";
            case Metric::WpInsns:
                return "Wasted wrong-path insns / 1k CP";
            case Metric::WpMemops:
                return "Wasted wrong-path memops / 1k CP";
            case Metric::BtbMiss:
                return "BTB miss rate";
            case Metric::WpDivergence:
                return "Wrong-path divergence vs trace's recorded WP";
            case Metric::CacheMiss: {
                char b[96];
                std::snprintf(b, sizeof(b),
                    "Cache miss rate (block=%d sets=%d policy=%s)",
                    opts.cache_block_size, opts.cache_sets,
                    cache_policy_name(opts.cache_policy));
                return b;
            }
            case Metric::MemPat:
                return "Memory-access pattern breakdown";
            case Metric::BranchDir:
                return "Branch direction breakdown";
            case Metric::GenOp:
                return "GenericOpcode breakdown";
            case Metric::GenReg:
                return "Destination-register breakdown";
        }
        return "";
    };
    plan.title = pick_title();

    /* Convert raw bin counters to display series.  Per-1k metrics
     * normalise by per-bin CP-insn count so a final partial bin
     * doesn't read low. */
    auto per_kilo = [&](double v, int bin) {
        uint64_t n = (bin < (int)ctx.cp_insns_per_bin.size())
                         ? ctx.cp_insns_per_bin[bin] : 0;
        return n == 0 ? 0.0 : v * 1000.0 / (double)n;
    };

    /* For metrics that produce a second pane (CP+WP variant) we
     * build a parallel ChartPlan that gets stacked below the main
     * one in the same SVG.  has_second_pane stays false for
     * single-pane metrics. */
    ChartPlan plan2 = plan;
    bool has_second_pane = false;
    auto build_lines_plan = [&](ChartPlan &p, const BinMatrix &mat,
                                const std::vector<int> &series_count_list,
                                std::function<double(double, int)> normalize,
                                const std::string &y_label_str,
                                bool cap_at_one) -> double {
        p.mode = ChartPlan::Mode::Lines;
        p.y_label = y_label_str;
        double y_max = 0.0;
        p.series.resize(series_count_list.size());
        for (size_t i = 0; i < series_count_list.size(); i++) {
            p.series[i].label = ctx.label_names[i];
            p.series[i].color = palette_color(i);
            p.series[i].y.resize(actual_bins);
            for (int b = 0; b < actual_bins; b++) {
                double v = normalize(mat.get((int)i, b), b);
                p.series[i].y[b] = v;
                if (b >= opts.warmup_bins && v > y_max) y_max = v;
            }
        }
        double scaled = (y_max > 0) ? y_max * 1.1 : 1.0;
        p.y_max = cap_at_one ? std::min(1.0, scaled) : scaled;
        p.warmup_bins = opts.warmup_bins;
        return p.y_max;
    };

    switch (opts.metric) {
        case Metric::BranchMpki: {
            /* Dual: CP-only-trained predictor vs CP+WP-polluted
             * predictor.  Same y-scale so the gap is read directly
             * as the speculative-pollution cost. */
            double m1 = build_lines_plan(plan, ctx.bins, opts.histories,
                                          per_kilo,
                                          "Mispredictions per 1k CP", false);
            double m2 = build_lines_plan(plan2, ctx.bins_wp,
                                          opts.histories,
                                          per_kilo,
                                          "Mispredictions per 1k CP", false);
            double yshared = std::max(m1, m2);
            plan.y_max = plan2.y_max = yshared;
            plan.title  = std::string(pick_title()) + " (CP-only)";
            plan2.title = std::string(pick_title()) + " (CP + WP-polluted)";
            has_second_pane = true;
            break;
        }
        case Metric::WpInsns:
        case Metric::WpMemops: {
            /* Single pane.  These count *the recorded WP chain's
             * work that would have been wasted on mispredicted CP
             * branches*, weighted by misprediction under each
             * --history.  A CP-only-vs-polluted-predictor split
             * doesn't add interpretable information here because the
             * underlying WP chain lengths are fixed by the trace —
             * the predictor only gates whether to count them.  Use
             * branch_mpki to see the polluted-vs-clean predictor
             * quality directly. */
            std::string ylab = (opts.metric == Metric::WpInsns)
                ? "Wasted WP insns / 1k CP"
                : "Wasted WP memops / 1k CP";
            build_lines_plan(plan, ctx.bins, opts.histories,
                             per_kilo, ylab, false);
            break;
        }
        case Metric::BtbMiss: {
            auto miss_rate = [&](double v, int b) {
                uint64_t d = b < (int)ctx.btb_branches_per_bin.size()
                                ? ctx.btb_branches_per_bin[b] : 0;
                return d == 0 ? 0.0 : v / (double)d;
            };
            double m1 = build_lines_plan(plan, ctx.bins, opts.btb_entries,
                                          miss_rate, "Miss rate", true);
            double m2 = build_lines_plan(plan2, ctx.bins_wp,
                                          opts.btb_entries,
                                          miss_rate, "Miss rate", true);
            double yshared = std::max(m1, m2);
            plan.y_max = plan2.y_max = yshared;
            plan.percent = plan2.percent = true;
            plan.title  = std::string(pick_title()) + " (CP-only)";
            plan2.title = std::string(pick_title()) + " (CP + WP-polluted)";
            has_second_pane = true;
            break;
        }
        case Metric::CacheMiss: {
            auto miss_rate = [&](double v, int b) {
                uint64_t d = b < (int)ctx.cp_memops_per_bin.size()
                                ? ctx.cp_memops_per_bin[b] : 0;
                return d == 0 ? 0.0 : v / (double)d;
            };
            double m1 = build_lines_plan(plan, ctx.bins, opts.cache_assocs,
                                          miss_rate, "Miss rate", true);
            double m2 = build_lines_plan(plan2, ctx.bins_wp,
                                          opts.cache_assocs,
                                          miss_rate, "Miss rate", true);
            double yshared = std::max(m1, m2);
            plan.y_max = plan2.y_max = yshared;
            plan.percent = plan2.percent = true;
            plan.title  = std::string(pick_title()) + " (CP-only)";
            plan2.title = std::string(pick_title()) + " (CP + WP-polluted)";
            has_second_pane = true;
            break;
        }
        case Metric::WpDivergence: {
            /* Per CP-bin, compute (min, mean, median, max) match-
             * depth across all CP branches whose WP chain we sized
             * up against the BP+BTB model.  Renders as four
             * overlaid lines so the centre tendency and the spread
             * are both visible — bins where the model usually
             * follows the recorded WP deep have all four lines
             * high; bins where it diverges early have low values
             * with a wide min/max gap. */
            plan.mode = ChartPlan::Mode::Lines;
            plan.y_label = "WP chain match depth (edges)";
            plan.series.resize(4);
            plan.series[0].label = "min";
            plan.series[1].label = "median";
            plan.series[2].label = "mean";
            plan.series[3].label = "max";
            const char *colors[] = {
                "#999999",  /* min: gray */
                "#1f77b4",  /* median: blue */
                "#ff7f0e",  /* mean: orange */
                "#999999",  /* max: gray */
            };
            for (int s = 0; s < 4; s++) {
                plan.series[s].color = colors[s];
                plan.series[s].y.assign((size_t)actual_bins, 0.0);
            }
            double y_max = 0.0;
            for (int b = 0; b < actual_bins; b++) {
                if (b >= (int)ctx.wp_depth_per_bin.size() ||
                    ctx.wp_depth_per_bin[b].empty()) {
                    continue;
                }
                auto v = ctx.wp_depth_per_bin[b];
                std::sort(v.begin(), v.end());
                double mn = v.front();
                double mx = v.back();
                double median = v[v.size() / 2];
                double sum = 0;
                for (int x : v) sum += x;
                double mean = sum / (double)v.size();
                plan.series[0].y[b] = mn;
                plan.series[1].y[b] = median;
                plan.series[2].y[b] = mean;
                plan.series[3].y[b] = mx;
                if (b >= opts.warmup_bins && mx > y_max) y_max = mx;
            }
            plan.y_max = (y_max > 0) ? y_max * 1.1 : 1.0;
            plan.warmup_bins = opts.warmup_bins;
            break;
        }
        case Metric::MemPat:
        case Metric::BranchDir:
        case Metric::GenOp:
        case Metric::GenReg: {
            const char *cp_y_axis;
            const char *wp_y_axis;
            switch (opts.metric) {
                case Metric::MemPat:
                    cp_y_axis = "CP memops"; wp_y_axis = "WP memops"; break;
                case Metric::BranchDir:
                    cp_y_axis = "CP branches"; wp_y_axis = "WP branches"; break;
                case Metric::GenOp:
                    cp_y_axis = "CP insns"; wp_y_axis = "WP insns"; break;
                default:
                    cp_y_axis = "CP dst-reg refs";
                    wp_y_axis = "WP dst-reg refs"; break;
            }
            auto build_stacked = [&](ChartPlan &p, const BinMatrix &mat,
                                     const char *y_axis_str) {
                p.mode = ChartPlan::Mode::Stacked;
                p.y_label = y_axis_str;
                p.y_max   = 1.0;
                p.percent = true;
                int S = (int)ctx.label_names.size();
                p.series.resize(S);
                std::vector<double> col_total((size_t)actual_bins, 0.0);
                for (int b = 0; b < actual_bins; b++) {
                    for (int s = 0; s < S; s++) {
                        col_total[b] += mat.get(s, b);
                    }
                }
                for (int s = 0; s < S; s++) {
                    p.series[s].label = ctx.label_names[s];
                    p.series[s].color = palette_color(s);
                    p.series[s].y.resize(actual_bins);
                    for (int b = 0; b < actual_bins; b++) {
                        double v = mat.get(s, b);
                        p.series[s].y[b] =
                            col_total[b] > 0 ? v / col_total[b] : 0.0;
                    }
                }
            };
            build_stacked(plan, ctx.bins, cp_y_axis);
            if (opts.metric == Metric::MemPat ||
                opts.metric == Metric::BranchDir) {
                build_stacked(plan2, ctx.bins_wp, wp_y_axis);
                plan.title  = std::string(pick_title()) + " (CP)";
                plan2.title = std::string(pick_title()) + " (WP)";
                has_second_pane = true;
            }
            break;
        }
    }

    std::FILE *out = stdout;
    if (opts.output) {
        out = std::fopen(opts.output, "wb");
        if (!out) {
            std::fprintf(stderr, "cst_visualize: cannot open '%s'\n",
                         opts.output);
            return 1;
        }
    }

    if (has_second_pane) {
        /* Two panes stacked vertically.  The top pane suppresses
         * its x-axis tick labels and x_label; the shared instruction
         * axis is printed once under the bottom pane. */
        plan.viewport_x  = 0;
        plan.viewport_y  = 0;
        plan.viewport_w  = opts.width;
        plan.viewport_h  = opts.height / 2;
        plan.show_x_labels = false;
        plan.x_label = "";

        plan2.viewport_x = 0;
        plan2.viewport_y = opts.height / 2;
        plan2.viewport_w = opts.width;
        plan2.viewport_h = opts.height - opts.height / 2;
        plan2.n_bins     = actual_bins;
        plan2.x_bin_size = bin_width;
        plan2.x_label    = "CP instruction window";
        plan2.show_x_labels = true;

        write_svg_header(out, opts.width, opts.height);
        render_plan(out, plan);
        render_plan(out, plan2);
        write_svg_footer(out);
    } else {
        plan.viewport_w = opts.width;
        plan.viewport_h = opts.height;
        write_svg_header(out, opts.width, opts.height);
        render_plan(out, plan);
        write_svg_footer(out);
    }
    if (opts.output) std::fclose(out);
    return 0;
}
