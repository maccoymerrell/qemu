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
};

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
"  -m mem_pat       Memory-access-pattern breakdown (CP+WP stacked area)\n"
"  -m branch_dir    Branch direction / class breakdown (CP+WP stacked area)\n"
"  -m gen_op        GenericOpcode breakdown, top-K + other\n"
"  -m gen_reg       Generic destination-register breakdown, top-K + other\n"
"\n"
"Options:\n"
"  -H, --history=L,L,...   Gshare history lengths (default 4,8,12,16,24)\n"
"      --pht-bits=B        PHT log2 entries (default 14)\n"
"      --btb-entries=N,... BTB sizes for btb_miss (default 64,128,256,512,1024)\n"
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
    std::fprintf(stderr, "cst_visualize: unknown metric '%s'\n", s);
    std::exit(2);
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
    /* Chart geometry. */
    int     width        = 1280;
    int     height       = 600;
    int     margin_left  = 80;
    int     margin_right = 220; /* room for legend */
    int     margin_top   = 50;
    int     margin_bot   = 60;

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

static void render_svg(std::FILE *out, const ChartPlan &plan)
{
    const int W = plan.width;
    const int H = plan.height;
    const int L = plan.margin_left;
    const int R = plan.margin_right;
    const int T = plan.margin_top;
    const int B = plan.margin_bot;
    const int plot_w = W - L - R;
    const int plot_h = H - T - B;

    auto x_of = [&](double bin_idx) {
        return L + (bin_idx / std::max(plan.n_bins, 1)) * plot_w;
    };
    auto y_of = [&](double v) {
        double frac = plan.y_max > 0 ? v / plan.y_max : 0.0;
        if (frac < 0) frac = 0;
        if (frac > 1) frac = 1;
        return T + plot_h - frac * plot_h;
    };

    std::fprintf(out,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<svg xmlns=\"http://www.w3.org/2000/svg\" "
        "viewBox=\"0 0 %d %d\" width=\"%d\" height=\"%d\" "
        "font-family=\"-apple-system, system-ui, sans-serif\" "
        "font-size=\"12\">\n",
        W, H, W, H);

    /* Background. */
    std::fprintf(out,
        "<rect width=\"%d\" height=\"%d\" fill=\"#ffffff\"/>\n", W, H);

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
    uint64_t total_insns = plan.x_bin_size * (uint64_t)plan.n_bins;
    for (int t = 0; t <= x_ticks; t++) {
        double bin = (plan.n_bins * (double)t) / x_ticks;
        uint64_t insn = (uint64_t)(plan.x_bin_size * bin);
        double x = x_of(bin);
        std::fprintf(out,
            "<line x1=\"%.2f\" y1=\"%d\" x2=\"%.2f\" y2=\"%d\" "
            "stroke=\"#cccccc\" stroke-width=\"1\"/>\n",
            x, T + plot_h, x, T + plot_h + 4);
        std::fprintf(out,
            "<text x=\"%.2f\" y=\"%d\" text-anchor=\"middle\" "
            "fill=\"#555\">%s</text>\n",
            x, T + plot_h + 18, xml_escape(fmt_count(insn)).c_str());
    }
    (void)total_insns;

    /* Axis labels. */
    if (!plan.x_label.empty()) {
        std::fprintf(out,
            "<text x=\"%d\" y=\"%d\" text-anchor=\"middle\" "
            "fill=\"#333\" font-size=\"13\">%s</text>\n",
            L + plot_w / 2, H - 12, xml_escape(plan.x_label).c_str());
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

    std::fprintf(out, "</svg>\n");
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

    /* Predictors (only populated for gshare-driven metrics). */
    std::vector<GShare> predictors;
    /* BTBs (only populated for btb_miss).  One per --btb-entries value;
     * a single per-entry walk feeds all of them so distinct sizes
     * see identical access streams. */
    std::vector<BTB>    btbs;
    /* Per-bin total branches observed by BTB, used to convert raw
     * miss counters to miss-rate (misses/branch). */
    std::vector<uint64_t> btb_branches_per_bin;

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
     * fall_through. */
    if (ctx.have_pending && ctx.pending_is_branch) {
        bool taken = (t.start_pc != ctx.pending_fall_pc);
        int  pbin  = (int)ctx.pending_bin;
        for (size_t pi = 0; pi < ctx.predictors.size(); pi++) {
            GShare &g = ctx.predictors[pi];
            bool pred = g.predict(ctx.pending_branch_pc);
            bool mispred = (pred != taken);
            if (ctx.opts.metric == Metric::BranchMpki) {
                if (mispred) ctx.bins.at((int)pi, pbin) += 1.0;
            } else if (ctx.opts.metric == Metric::WpInsns) {
                if (mispred) {
                    ctx.bins.at((int)pi, pbin) += ctx.pending_wp_insns;
                }
            } else if (ctx.opts.metric == Metric::WpMemops) {
                if (mispred) {
                    ctx.bins.at((int)pi, pbin) += ctx.pending_wp_memops;
                }
            }
            g.update(ctx.pending_branch_pc, taken);
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
     * previous bin. */
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

    ctx.cp_insns_so_far += n_insns;
}

static void handle_mem_pat_entry(WalkCtx &ctx, const cst::DecodedEntry &e)
{
    const cst::Template &t = (*ctx.templates)[ctx.by_id->at(e.template_id)];
    int bin = bin_of(ctx, ctx.cp_insns_so_far);
    /* Layers: 0=none, 1=regular, 2=irregular, 3=random.  Counted in
     * units of (memops_on_this_visit) per insn — i.e. how many CP
     * load/store operations of each pattern class ran in this bin. */
    for (const auto &dp : e.dyn_params) {
        if (dp.insn_index >= t.insns.size()) continue;
        /* Per-insn profile is template-static (pat_cp). */
        if (dp.insn_index >= t.profile.insns.size()) continue;
        uint8_t pat = t.profile.insns[dp.insn_index].pat_cp;
        if (pat > 3) pat = 0;
        ctx.bins.at((int)pat, bin) += 1.0;
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
            char b[32];
            std::snprintf(b, sizeof(b), "history=%d", hl);
            ctx.add_label(b);
        }
    } else if (opts.metric == Metric::BtbMiss) {
        ctx.btbs.reserve(opts.btb_entries.size());
        for (int n : opts.btb_entries) {
            ctx.btbs.emplace_back(n);
            char b[32];
            std::snprintf(b, sizeof(b), "%d entries", n);
            ctx.add_label(b);
        }
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
    plan.width  = opts.width;
    plan.height = opts.height;
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

    switch (opts.metric) {
        case Metric::BranchMpki:
        case Metric::WpInsns:
        case Metric::WpMemops: {
            plan.mode = ChartPlan::Mode::Lines;
            plan.y_label = (opts.metric == Metric::BranchMpki)
                ? "Mispredictions per 1k CP insns"
                : (opts.metric == Metric::WpInsns
                    ? "Wasted WP insns / 1k CP" :
                    "Wasted WP memops / 1k CP");
            double y_max = 0.0;
            plan.series.resize(opts.histories.size());
            for (size_t i = 0; i < opts.histories.size(); i++) {
                plan.series[i].label = ctx.label_names[i];
                plan.series[i].color = palette_color(i);
                plan.series[i].y.resize(actual_bins);
                for (int b = 0; b < actual_bins; b++) {
                    double v = per_kilo(ctx.bins.get((int)i, b), b);
                    plan.series[i].y[b] = v;
                    /* Skip warmup bins from y_max scaling — the
                     * predictor's untrained transient would otherwise
                     * dominate the chart's vertical range. */
                    if (b >= opts.warmup_bins && v > y_max) y_max = v;
                }
            }
            plan.y_max = (y_max > 0) ? y_max * 1.1 : 1.0;
            plan.warmup_bins = opts.warmup_bins;
            break;
        }
        case Metric::BtbMiss: {
            plan.mode = ChartPlan::Mode::Lines;
            plan.y_label = "Miss rate";
            plan.percent = true;
            double y_max = 0.0;
            plan.series.resize(opts.btb_entries.size());
            for (size_t i = 0; i < opts.btb_entries.size(); i++) {
                plan.series[i].label = ctx.label_names[i];
                plan.series[i].color = palette_color(i);
                plan.series[i].y.resize(actual_bins);
                for (int b = 0; b < actual_bins; b++) {
                    uint64_t denom = b < (int)ctx.btb_branches_per_bin.size()
                        ? ctx.btb_branches_per_bin[b] : 0;
                    double v = denom == 0 ? 0.0
                        : ctx.bins.get((int)i, b) / (double)denom;
                    plan.series[i].y[b] = v;
                    if (b >= opts.warmup_bins && v > y_max) y_max = v;
                }
            }
            plan.y_max = std::min(1.0, (y_max > 0) ? y_max * 1.1 : 1.0);
            plan.warmup_bins = opts.warmup_bins;
            break;
        }
        case Metric::MemPat:
        case Metric::BranchDir:
        case Metric::GenOp:
        case Metric::GenReg: {
            plan.mode = ChartPlan::Mode::Stacked;
            plan.y_label = (opts.metric == Metric::MemPat)
                ? "CP memops" :
                  (opts.metric == Metric::BranchDir
                      ? "CP branches"
                      : (opts.metric == Metric::GenOp
                            ? "CP insns" : "CP dst-reg refs"));
            /* For stacked-area we want each bin to sum to 100% (the
             * fraction of activity in each layer) so the chart reads
             * as composition, not magnitude. */
            plan.y_max   = 1.0;
            plan.percent = true;
            int S = (int)ctx.label_names.size();
            plan.series.resize(S);
            std::vector<double> col_total((size_t)actual_bins, 0.0);
            for (int b = 0; b < actual_bins; b++) {
                for (int s = 0; s < S; s++) {
                    col_total[b] += ctx.bins.get(s, b);
                }
            }
            for (int s = 0; s < S; s++) {
                plan.series[s].label = ctx.label_names[s];
                plan.series[s].color = palette_color(s);
                plan.series[s].y.resize(actual_bins);
                for (int b = 0; b < actual_bins; b++) {
                    double v = ctx.bins.get(s, b);
                    plan.series[s].y[b] = col_total[b] > 0
                        ? v / col_total[b] : 0.0;
                }
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
    render_svg(out, plan);
    if (opts.output) std::fclose(out);
    return 0;
}
