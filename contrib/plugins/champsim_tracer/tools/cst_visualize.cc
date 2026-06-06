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
#include <deque>
#include <fstream>
#include <functional>
#include <iomanip>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <ext/pb_ds/assoc_container.hpp>
#include <ext/pb_ds/tree_policy.hpp>

#include "cst_common.h"
#include "cst_decode.h"
#include "cst_format.h"
#include "cst_reader.h"

/* Order-statistic tree (libstdc++ extension) used by reuse_distance: a
 * red-black tree augmented with subtree-size counters so order_of_key
 * is O(log N).  Lets stack-distance lookups beat the std::list + linear
 * std::distance approach (O(working_set) per memop). */
using OrderStatTree = __gnu_pbds::tree<
    uint64_t,
    __gnu_pbds::null_type,
    std::less<uint64_t>,
    __gnu_pbds::rb_tree_tag,
    __gnu_pbds::tree_order_statistics_node_update>;

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
    /* Static, header-derived characterizations.  Histograms over
     * templates; no body walk required. */
    BbLength,
    IndirectTargets,
    BranchEntropy,
    /* Body-walk additions: characterizations that need the full memop
     * / insn stream. */
    WorkingSet,
    DepDepth,
    Ilp,
    ReuseDistance,
};

enum class CachePolicy { LRU, MRU, Random };

struct Options {
    /* One or more input traces.  A single trace renders as before; two
     * or more (or an explicit --aggregate) trigger aggregate mode, which
     * combines traces of one program into a single representative SVG. */
    std::vector<const char *> inputs;
    const char *output       = nullptr;   /* nullptr -> stdout */
    Metric      metric       = Metric::BranchMpki;
    /* Aggregate mode controls.  @aggregate forces it even for one input.
     * @weights overrides the per-trace header simpoint_weight (CLI order);
     * empty -> use header weights, all-zero -> even split.  @agg_name is
     * the program label used in aggregate titles. */
    bool        aggregate    = false;
    std::vector<double> weights;
    const char *agg_name     = nullptr;
    /* History lengths used by the gshare predictor variants.  Multiple
     * values produce overlaid lines on the same chart.  Ignored for
     * non-gshare metrics.  history=0 collapses gshare to a pure
     * bimodal predictor (PC-indexed counter, no history XOR); history=2
     * is a short-history point between bimodal and the normal range. */
    std::vector<int> histories = {0, 2, 4, 8, 12, 16, 24};
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

    /* working_set: size of the sliding instruction window over which
     * to count unique cache lines / 4 KiB pages.  Measuring since
     * program start gives a cumulative footprint curve; a fixed
     * window gives the true "working set" — addresses live within
     * the recent past.  Default 100K matches an L1-ish scale. */
    uint64_t            ws_window         = 100000;
    /* dep_depth: size of the sliding reorder-buffer window.  Insns
     * older than this drop out of the dependency-tracking state, so
     * chain depth measures critical path WITHIN the buffer (the
     * natural ILP-relevant scale) instead of compounding forever
     * through e.g. a long-running loop counter.  Default is a
     * forward-looking 1024 — larger than current Intel / AMD ROBs
     * (~600) but in the range upcoming designs are reaching for. */
    uint32_t            rob_size          = 1024;
    /* Histogram tail-clipping: fold the rightmost bins that
     * cumulatively account for less than @hist_tail_pct percent of
     * the total into a single ">N" overflow bin.  Keeps the chart's
     * x-axis labeled-and-readable when a distribution has a long
     * sparse tail (typical for bb_length, reuse_distance).  Set 0
     * to keep every bin un-clipped. */
    double              hist_tail_pct     = 0.5;

    /* Diagnostic.  When > 0 and metric is branch_mpki, the gshare
     * handler dumps the first @debug_branches (pc, taken, bin,
     * pred_h0, pred_h12) tuples it actually feeds to its predictors
     * to stderr, and at end-of-walk prints per-PC aggregates so we
     * can verify whether the outcome derivation is sane. */
    int                 debug_branches   = 0;
};

[[noreturn]] static void usage(int rc)
{
    std::fprintf(rc == 0 ? stdout : stderr,
"Usage: cst_visualize -m METRIC [options] TRACE.cst [TRACE2.cst ...]\n"
"\n"
"Passing more than one trace (or --aggregate) combines simpoint traces of\n"
"one program into a single representative SVG: instruction-window charts\n"
"become a weighted composition montage (one segment per trace, in program\n"
"order, width proportional to weight); histograms become a weighted-mean\n"
"distribution.\n"
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
"  -m bb_length        Histogram: # of basic blocks by length (insns)\n"
"  -m indirect_targets Histogram: # of indirect branches by distinct-target count\n"
"  -m branch_entropy   Histogram: # of conditional branches by direction entropy (%%)\n"
"  -m working_set      Cumulative unique cache lines + 4KB pages touched over time\n"
"  -m dep_depth        Per-bin avg + p90 Wall-style RAW chain depth\n"
"                      (rename-aware tumbling window of --rob-size insns)\n"
"  -m ilp              Ideal IPC under perfect rename: top pane = per-bin\n"
"                      avg + p90 IPC across tumbling --rob-size windows;\n"
"                      bottom pane = in-window issue-cycle histogram\n"
"  -m reuse_distance   Histogram: log-bucketed memop reuse (stack) distance\n"
"\n"
"Options:\n"
"  -H, --history=L,L,...   Gshare history lengths (default 0,2,4,8,12,16,24;\n"
"                          0 = pure bimodal, 2 = short-history)\n"
"      --pht-bits=B        PHT log2 entries (default 14)\n"
"      --btb-entries=N,... BTB sizes for btb_miss (default 64,128,256,512,1024)\n"
"      --cache-block-size=N  Cache line size in bytes (default 64)\n"
"      --cache-sets=N      Cache sets (default 64)\n"
"      --cache-assoc=A,... Cache associativities (default 1,2,4,8,16)\n"
"      --cache-policy=P    Replacement: lru | mru | random (default lru)\n"
"      --warmup-bins=N     Bins excluded from y_max scaling (default 5)\n"
"      --ws-window=N       working_set sliding-window size in CP insns (default 100000)\n"
"      --rob-size=N        dep_depth / ilp reorder-buffer window size in insns (default 1024)\n"
"      --hist-tail-pct=F   fold histogram bins past 100-F%% cumulative into a ‘>N’\n"
"                          overflow bin so the x-axis stays readable (default 0.5; 0 = off)\n"
"  -b, --bins=N            Number of bins (default 200)\n"
"  -w, --width=PX          SVG width  (default 1280)\n"
"  -h, --height=PX         SVG height (default 600)\n"
"  -k, --top-k=N           Top-K layers for gen_op / gen_reg (default 10)\n"
"  -t, --title=STR         Override chart title\n"
"  -o, --output=FILE       Write SVG to FILE (default stdout)\n"
"      --aggregate         Force aggregate mode (implied for >1 trace)\n"
"      --weights=W,W,...   Per-trace weights (CLI order; default = header\n"
"                          simpoint_weight; all-zero -> even split)\n"
"      --name=STR          Program label used in aggregate titles\n"
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

/* Parse a comma-separated list of non-negative doubles (--weights). */
static std::vector<double> parse_double_list(const char *s)
{
    std::vector<double> out;
    const char *p = s;
    while (*p) {
        char *end = nullptr;
        double v = std::strtod(p, &end);
        if (!end || end == p || v < 0) {
            std::fprintf(stderr, "cst_visualize: bad --weights entry "
                         "near '%s'\n", p);
            std::exit(2);
        }
        out.push_back(v);
        p = end;
        if (*p == ',') p++;
        else if (*p != '\0') {
            std::fprintf(stderr, "cst_visualize: bad --weights separator "
                         "'%c'\n", *p);
            std::exit(2);
        }
    }
    if (out.empty()) {
        std::fprintf(stderr, "cst_visualize: empty --weights list\n");
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
    if (!std::strcmp(s, "bb_length"))        return Metric::BbLength;
    if (!std::strcmp(s, "indirect_targets")) return Metric::IndirectTargets;
    if (!std::strcmp(s, "branch_entropy"))   return Metric::BranchEntropy;
    if (!std::strcmp(s, "working_set"))      return Metric::WorkingSet;
    if (!std::strcmp(s, "dep_depth"))        return Metric::DepDepth;
    if (!std::strcmp(s, "ilp"))              return Metric::Ilp;
    if (!std::strcmp(s, "reuse_distance"))   return Metric::ReuseDistance;
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
        } else if (!std::strncmp(a, "--debug-branches=", 17)) {
            o.debug_branches = parse_int(a + 17, "--debug-branches");
        } else if (!std::strncmp(a, "--ws-window=", 12)) {
            o.ws_window = (uint64_t)parse_int(a + 12, "--ws-window");
        } else if (!std::strncmp(a, "--rob-size=", 11)) {
            o.rob_size = (uint32_t)parse_int(a + 11, "--rob-size");
        } else if (!std::strncmp(a, "--hist-tail-pct=", 16)) {
            char *end = nullptr;
            double v = std::strtod(a + 16, &end);
            if (!end || *end || v < 0.0 || v > 50.0) {
                std::fprintf(stderr,
                    "cst_visualize: bad value for --hist-tail-pct: %s\n",
                    a + 16);
                std::exit(2);
            }
            o.hist_tail_pct = v;
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
        } else if (!std::strcmp(a, "--aggregate")) {
            o.aggregate = true;
        } else if (!std::strcmp(a, "--weights")) {
            need(i + 1, a); o.weights = parse_double_list(argv[++i]);
        } else if (!std::strncmp(a, "--weights=", 10)) {
            o.weights = parse_double_list(a + 10);
        } else if (!std::strcmp(a, "--name")) {
            need(i + 1, a); o.agg_name = argv[++i];
        } else if (!std::strncmp(a, "--name=", 7)) {
            o.agg_name = a + 7;
        } else if (a[0] == '-') {
            std::fprintf(stderr, "cst_visualize: unknown option '%s'\n", a);
            usage(2);
        } else {
            o.inputs.push_back(a);
        }
        i++;
    }
    if (o.inputs.empty()) {
        std::fprintf(stderr, "cst_visualize: missing TRACE.cst\n");
        usage(2);
    }
    if (!o.weights.empty() && o.weights.size() != o.inputs.size()) {
        std::fprintf(stderr, "cst_visualize: --weights count (%zu) != "
                     "number of input traces (%zu)\n",
                     o.weights.size(), o.inputs.size());
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
    int                       max_entries = 0;
    /* LRU order: front = most-recently-used, back = LRU candidate. */
    std::list<uint64_t>       order;
    struct Entry {
        std::list<uint64_t>::iterator it;
        uint64_t target;
    };
    std::unordered_map<uint64_t, Entry> table;

    BTB() = default;
    explicit BTB(int n) : max_entries(n) { table.reserve(n * 2); }

    /* Look-up-only with LRU touch on hit.  Returns true if @pc has
     * any entry, regardless of target.  Used for the conditional-
     * branch fetch-time question "does the BTB even know this PC?";
     * without an entry, real hardware can't fetch a taken target and
     * the front-end defaults to predicting fall-through. */
    bool lookup(uint64_t pc) {
        auto it = table.find(pc);
        if (it == table.end()) return false;
        order.erase(it->second.it);
        order.push_front(pc);
        it->second.it = order.begin();
        return true;
    }

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
     * the global history.  When history_bits > pht_bits, XOR-fold
     * the upper history bits down into the pht_bits-wide window so
     * they actually influence the index — without folding, the high
     * bits would be masked away and any history >= pht_bits would be
     * indistinguishable from a history of pht_bits (i.e. h=14, 16,
     * 24 would all behave identically with the default 14-bit PHT). */
    uint64_t index(uint64_t pc) const {
        uint64_t h = ghr & history_mask;
        while (h > pht_mask) {
            h = (h >> pht_bits) ^ (h & pht_mask);
        }
        return (h ^ (pc >> 2)) & pht_mask;
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

/* Special-register predicate shared by dep_depth (chain-walk exclusion)
 * and gen_reg (top-K destination-register breakdown).  Names matched
 * here are architectural side-effects implicit on every instruction —
 * the program counter / instruction pointer, the flags / condition
 * register, the hardwired zero, and the placeholder for "no operand".
 * They aren't true reg dependencies and dominate the histogram when
 * counted; SP / FP and any architectural GPR / FPR / VEC / PRED / SEG
 * bank are kept. */
static bool reg_is_special_excluded(const std::string &name)
{
    return (name.find("ZERO") != std::string::npos)
        || (name.find("FLAGS") != std::string::npos)
        || (name == "REG_IP" || name == "IP"
            || name == "REG_PC" || name == "PC")
        || (name == "REG_NONE" || name == "NONE");
}

/* ===================================================================
 *                            SVG renderer
 * =================================================================== */

struct Series {
    std::string         label;
    std::string         color;
    std::vector<double> y;
    /* When true the series renders as a dashed horizontal/polyline
     * reference (e.g. a saturation marker), distinguishing it from
     * the actual data series at a glance. */
    bool                dashed = false;
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
    int     margin_bot   = 75; /* tick labels (+18) + x-axis title (+38) */
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
     * layers sum to 100% per bin, set y_max = 1.0 and percent=true.
     * y_is_count switches y-tick labels to fmt_count() — integer-
     * friendly with K/M suffixes — for histograms whose y values are
     * raw counts. */
    double y_max     = 1.0;
    bool   percent   = false;
    bool   y_is_count = false;

    /* mode: "lines" (one polyline per series), "stacked" (cumulative
     * stacked polygons, layer 0 at bottom), or "bars" (per-bin filled
     * rectangles; histogram style — one series, no legend). */
    enum class Mode { Lines, Stacked, Bars };
    Mode mode = Mode::Lines;

    /* Bins [0, warmup_bins) are excluded from y_max scaling and
     * drawn under a translucent overlay so the viewer can see the
     * predictor / cache warm-up region was deliberately
     * de-emphasised.  Zero disables the overlay. */
    int warmup_bins = 0;

    /* Override the auto-generated x-axis tick labels.  When non-empty,
     * size() drives the tick count (x_ticks = size()-1) and the
     * strings are printed verbatim under each tick.  Used by static-
     * summary plots whose x-axis is not an instruction count. */
    std::vector<std::string> x_tick_labels;
    /* Suffix appended to auto-generated Bars-mode tick labels (e.g.
     * "%" for the entropy histogram). */
    std::string x_unit_suffix;
    /* When true the rightmost bin is an overflow (folded tail of
     * the distribution).  Bars-mode rendering replaces the last bin
     * tick label with @overflow_label (e.g. ">64") so readers can
     * tell it's a fold-up, not just another value. */
    bool        has_overflow_bin = false;
    std::string overflow_label;

    /* Trace-encoded warmup->simulation boundary (header §2.13
     * warmup_end_arch_insns), in the SAME architectural CP-insn units
     * as the x-axis.  Drawn as a single dashed vertical marker on
     * instruction-window plots so the reader can see how much of the
     * trace is warmup.  Sentinels UINT64_MAX (uncrossed) and 0 (no
     * warmup configured) suppress the marker. */
    uint64_t    warmup_end_insns = UINT64_MAX;

    std::vector<Series> series;

    /* Aggregate (composition) mode: when non-empty, this pane is a montage
     * of per-trace segments laid out left-to-right, each occupying a
     * weight-proportional fraction of the plot width and rendering its own
     * native-bin series.  @series above is then used only as the unified
     * legend (label + colour per global series); the actual data lives in
     * the segments.  Empty -> ordinary single-trace pane (unchanged). */
    struct CompSegment {
        std::vector<Series> series;   /* this trace's series, global colours */
        int         n_bins      = 0;  /* trace's native bin count */
        double      x0_frac     = 0;  /* [0,1] sub-range of the plot width */
        double      x1_frac     = 1;
        std::string label;            /* e.g. "545.2B  18%" */
        double      warmup_frac = -1; /* -1 = none; else pos within the slice */
    };
    std::vector<CompSegment> segments;
};

/* CSS-style palette: distinguishable hues + monotonic luminance for
 * stacked layers.  Wraps via modulo when more series than entries. */
static const char *palette_color(size_t i)
{
    static const char *p[] = {
        /* tab20 (indices 0..19 unchanged so index-keyed series keep their
         * historical colours). */
        "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728",
        "#9467bd", "#8c564b", "#e377c2", "#7f7f7f",
        "#bcbd22", "#17becf", "#aec7e8", "#ffbb78",
        "#98df8a", "#ff9896", "#c5b0d5", "#c49c94",
        "#f7b6d2", "#c7c7c7", "#dbdb8d", "#9edae5",
        /* tab20b — extends the wheel to 40 so name-keyed category colours
         * (color_for_label) collide far less within a single plot. */
        "#393b79", "#5254a3", "#6b6ecf", "#9c9ede",
        "#637939", "#8ca252", "#b5cf6b", "#cedb9c",
        "#8c6d31", "#bd9e39", "#e7ba52", "#e7cb94",
        "#843c39", "#ad494a", "#d6616b", "#e7969c",
        "#7b4173", "#a55194", "#ce6dbd", "#de9ed6",
    };
    return p[i % (sizeof(p) / sizeof(p[0]))];
}

/*
 * Deterministic colour for a category label: a stable hash of the NAME into
 * the palette, so a given category (opcode, dst-reg, branch class, memory
 * pattern, ...) draws in the SAME colour in every plot and every pane —
 * regardless of discovery order, top-K selection, or which other categories
 * happen to be present.  Index-based colouring drifted across traces and
 * across the CP/WP panes whenever that set or its order changed, which made
 * cross-plot comparison confusing.  Dense single-pane breakdowns can collide
 * within one plot (more categories than palette slots), but each series is
 * still named in the legend, and cross-plot/pane stability is the property
 * that matters here.  FNV-1a so the mapping is fixed across builds/runs.
 */
static const char *color_for_label(const std::string &label)
{
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : label) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    return palette_color((size_t)h);
}

/*
 * Branch-direction coloring.  Unlike opcodes or registers, the branch
 * classes are a small, closed, format-defined set (the BRANCH_* enum,
 * plus a taken/not-taken pair for the conditional class and a
 * "no branch" filler).  Hashing the name (color_for_label) scatters
 * these across the whole 40-slot palette — including the muted tab20b
 * half — so the handful of classes that actually appear usually drew
 * in hard-to-distinguish, often near-duplicate colors, and which slot
 * a class landed on changed whenever the classifier renamed it (e.g.
 * splitting BRANCH_*_CALL out of the jump classes).  Pin each class to
 * a fixed slot in the vivid tab20 head instead, ordered so the classes
 * that dominate real traces (the conditional pair, then jumps /
 * returns / calls) take the most distinct colors first.  Keying on the
 * class name keeps the mapping stable across panes, traces and prune
 * levels; unknown labels fall back to the name hash.
 */
static const char *branch_dir_color(const std::string &label)
{
    static const struct { const char *name; size_t slot; } fixed[] = {
        { "BRANCH_COND_DIRECT taken",     0 },  /* blue   */
        { "BRANCH_COND_DIRECT not-taken", 1 },  /* orange */
        { "BRANCH_DIRECT_JUMP",           2 },  /* green  */
        { "BRANCH_RETURN",                3 },  /* red    */
        { "BRANCH_DIRECT_CALL",           4 },  /* purple */
        { "BRANCH_INDIRECT_CALL",         5 },  /* brown  */
        { "BRANCH_INDIRECT_JUMP",         6 },  /* pink   */
        { "BRANCH_REP",                   8 },  /* olive  */
        { "BRANCH_SYSCALL_TYPE",          9 },  /* cyan   */
        { "no branch",                    7 },  /* gray (de-emphasised) */
        { "BRANCH_NONE",                  7 },
    };
    for (const auto &f : fixed) {
        if (label == f.name) return palette_color(f.slot);
    }
    return color_for_label(label);
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
/*
 * Renders one ChartPlan into an SVG <g> body.  The geometry (plot-area
 * coords L/R/T/B and the x_of/y_of mappings) is shared state across every
 * rendering pass, so it lives on the emitter rather than being recomputed
 * or threaded through free functions.  render() dispatches between the two
 * top-level layouts: the composition/aggregate pane (montage of
 * weight-proportional per-trace segments) and the normal single-axis plot.
 * Output is byte-identical to the former monolithic render_plan().
 */
class SvgEmitter {
public:
    SvgEmitter(std::FILE *out, const ChartPlan &plan)
        : out_(out), plan_(plan),
          VX(plan.viewport_x), VY(plan.viewport_y),
          VW(plan.viewport_w), VH(plan.viewport_h),
          L(VX + plan.margin_left), R_edge(VX + VW - plan.margin_right),
          T(VY + plan.margin_top), B_edge(VY + VH - plan.margin_bot),
          plot_w(R_edge - L), plot_h(B_edge - T) {}

    void render()
    {
        emit_frame();
        emit_y_axis();
        if (!plan_.segments.empty()) {
            emit_composition_pane();
            return;
        }
        emit_x_axis();
        emit_axis_titles();
        emit_title();
        emit_warmup_overlay();
        emit_data();
        emit_warmup_end_marker();
        /* Normal legend suppresses the wrap after the final series. */
        emit_legend(true);
    }

private:
    double x_of(double bin_idx) const
    {
        return L + (bin_idx / std::max(plan_.n_bins, 1)) * plot_w;
    }
    double y_of(double v) const
    {
        double frac = plan_.y_max > 0 ? v / plan_.y_max : 0.0;
        if (frac < 0) frac = 0;
        if (frac > 1) frac = 1;
        return T + plot_h - frac * plot_h;
    }

    void emit_frame()
    {
        std::fprintf(out_,
            "<rect x=\"%d\" y=\"%d\" width=\"%d\" height=\"%d\" "
            "fill=\"#fafafa\" stroke=\"#cccccc\"/>\n",
            L, T, plot_w, plot_h);
    }

    void emit_y_axis()
    {
        int y_ticks = 5;
        for (int t = 0; t <= y_ticks; t++) {
            double v = (plan_.y_max * t) / y_ticks;
            double y = y_of(v);
            std::fprintf(out_,
                "<line x1=\"%d\" y1=\"%.2f\" x2=\"%d\" y2=\"%.2f\" "
                "stroke=\"#e0e0e0\" stroke-width=\"1\"/>\n",
                L, y, L + plot_w, y);
            std::string lab = plan_.y_is_count
                                  ? fmt_count((uint64_t)(v + 0.5))
                                  : fmt_double(v, plan_.percent);
            std::fprintf(out_,
                "<text x=\"%d\" y=\"%.2f\" text-anchor=\"end\" "
                "dominant-baseline=\"middle\" fill=\"#555\">%s</text>\n",
                L - 6, y, xml_escape(lab).c_str());
        }
    }

    /* Composition (aggregate) pane: a montage of weight-proportional
     * per-trace segments, each rendering its own native bins inside its
     * pixel sub-range.  Replaces the normal x-axis / data / single-marker
     * path entirely; the shared frame, y-axis, title and legend are still
     * drawn here.  Decorations (per-segment label + warmup rule) are gated
     * on segment pixel width so the chart stays readable for any K. */
    void emit_composition_pane()
    {
        const double LABEL_MIN_PX  = 46.0;  /* show segment label if wider */
        const double WARMUP_MIN_PX = 14.0;  /* show warmup rule if wider */

        /* Per-segment data first, so dividers / markers land on top. */
        for (const auto &seg : plan_.segments) {
            double sxl = L + seg.x0_frac * plot_w;
            double sxr = L + seg.x1_frac * plot_w;
            double sw  = sxr - sxl;
            int nb = seg.n_bins > 0 ? seg.n_bins : 1;
            /* Bin b's true center x.  The drawn path additionally anchors
             * explicit vertices at the segment edges (sxl/sxr) so the
             * fill/line spans the full slice — otherwise the half-bin
             * margin at each end leaves a visible gap on either side of
             * every divider.  Edge anchoring is robust for nb==1. */
            auto ctr = [&](int b) {
                return sxl + ((b + 0.5) / (double)nb) * sw;
            };
            auto val = [&](const Series &s, int b) {
                return (b < (int)s.y.size()) ? s.y[b] : 0.0;
            };
            if (plan_.mode == ChartPlan::Mode::Stacked) {
                std::vector<double> cum((size_t)nb, 0.0);
                for (const Series &s : seg.series) {
                    std::fprintf(out_,
                        "<polygon fill=\"%s\" fill-opacity=\"0.9\" "
                        "stroke=\"%s\" stroke-width=\"0.5\" points=\"",
                        s.color.c_str(), s.color.c_str());
                    /* upper edge: left edge, centers L→R, right edge */
                    std::fprintf(out_, "%.2f,%.2f ",
                                 sxl, y_of(cum[0] + val(s, 0)));
                    for (int b = 0; b < nb; b++) {
                        std::fprintf(out_, "%.2f,%.2f ",
                                     ctr(b), y_of(cum[b] + val(s, b)));
                    }
                    std::fprintf(out_, "%.2f,%.2f ",
                                 sxr, y_of(cum[nb - 1] + val(s, nb - 1)));
                    /* lower edge: right edge, centers R→L, left edge */
                    std::fprintf(out_, "%.2f,%.2f ", sxr, y_of(cum[nb - 1]));
                    for (int b = nb - 1; b >= 0; b--) {
                        std::fprintf(out_, "%.2f,%.2f ", ctr(b), y_of(cum[b]));
                    }
                    std::fprintf(out_, "%.2f,%.2f ", sxl, y_of(cum[0]));
                    std::fprintf(out_, "\"/>\n");
                    for (int b = 0; b < nb; b++) cum[b] += val(s, b);
                }
            } else { /* Lines */
                for (const Series &s : seg.series) {
                    const char *dash = s.dashed
                        ? " stroke-dasharray=\"6 4\"" : "";
                    std::fprintf(out_, "<polyline fill=\"none\" stroke=\"%s\" "
                        "stroke-width=\"1.5\"%s points=\"",
                        s.color.c_str(), dash);
                    std::fprintf(out_, "%.2f,%.2f ", sxl, y_of(val(s, 0)));
                    for (int b = 0; b < nb; b++) {
                        std::fprintf(out_, "%.2f,%.2f ", ctr(b), y_of(val(s, b)));
                    }
                    std::fprintf(out_, "%.2f,%.2f ",
                                 sxr, y_of(val(s, nb - 1)));
                    std::fprintf(out_, "\"/>\n");
                }
            }
        }

        /* Boundary dividers, x-axis cumulative-weight ticks, gated
         * per-segment labels, and gated per-segment warmup rules. */
        double last_lbl_x = -1e9;
        for (size_t si = 0; si < plan_.segments.size(); si++) {
            const auto &seg = plan_.segments[si];
            double sxl = L + seg.x0_frac * plot_w;
            double sxr = L + seg.x1_frac * plot_w;
            double sw  = sxr - sxl;

            /* Divider at the segment's left boundary (skip the very left
             * edge, which is the frame).  Solid and dark so simpoint edges
             * read at least as strongly as the dashed warmup rules and
             * don't fade into the plot background. */
            if (si > 0) {
                std::fprintf(out_,
                    "<line x1=\"%.2f\" y1=\"%d\" x2=\"%.2f\" y2=\"%d\" "
                    "stroke=\"#444444\" stroke-width=\"1.5\"/>\n",
                    sxl, T, sxl, T + plot_h);
            }
            /* Cumulative-weight x tick at the left boundary, labelled if
             * there's room since the last label. */
            if (plan_.show_x_labels) {
                std::fprintf(out_,
                    "<line x1=\"%.2f\" y1=\"%d\" x2=\"%.2f\" y2=\"%d\" "
                    "stroke=\"#cccccc\" stroke-width=\"1\"/>\n",
                    sxl, T + plot_h, sxl, T + plot_h + 4);
                if (sxl - last_lbl_x > 40.0) {
                    char buf[16];
                    std::snprintf(buf, sizeof(buf), "%.0f%%",
                                  seg.x0_frac * 100.0);
                    std::fprintf(out_,
                        "<text x=\"%.2f\" y=\"%d\" text-anchor=\"middle\" "
                        "fill=\"#555\">%s</text>\n",
                        sxl, T + plot_h + 18, buf);
                    last_lbl_x = sxl;
                }
            }

            /* Per-segment warmup rule (the trace's own §2.13 boundary,
             * placed at its relative position within the slice). */
            if (seg.warmup_frac >= 0.0 && sw >= WARMUP_MIN_PX) {
                double wx = sxl + seg.warmup_frac * sw;
                std::fprintf(out_,
                    "<line x1=\"%.2f\" y1=\"%d\" x2=\"%.2f\" y2=\"%d\" "
                    "stroke=\"#000000\" stroke-width=\"2\" "
                    "stroke-dasharray=\"9,5\"/>\n",
                    wx, T, wx, T + plot_h);
            }
            /* Per-segment label above the frame, if the slice is wide
             * enough to hold it. */
            if (!seg.label.empty() && sw >= LABEL_MIN_PX) {
                std::fprintf(out_,
                    "<text x=\"%.2f\" y=\"%d\" text-anchor=\"middle\" "
                    "fill=\"#333\" font-size=\"10\">%s</text>\n",
                    sxl + sw / 2.0, T - 5, xml_escape(seg.label).c_str());
            }
        }
        /* Final right-edge cumulative tick (100%). */
        if (plan_.show_x_labels) {
            std::fprintf(out_,
                "<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" "
                "stroke=\"#cccccc\" stroke-width=\"1\"/>\n",
                L + plot_w, T + plot_h, L + plot_w, T + plot_h + 4);
            std::fprintf(out_,
                "<text x=\"%d\" y=\"%d\" text-anchor=\"middle\" "
                "fill=\"#555\">100%%</text>\n", L + plot_w, T + plot_h + 18);
        }

        emit_axis_titles();
        emit_title();
        /* Composition legend wraps even after the final series. */
        emit_legend(false);
    }

    /* X-axis labels.  Three modes:
     *  (a) x_tick_labels non-empty: use the verbatim label list.
     *  (b) Bars mode: bin-centered ticks at a "nice" integer step so
     *      each label sits under its bar instead of between bars.
     *  (c) Lines / Stacked: 6 evenly-spaced ticks labelled via
     *      fmt_count(bin * x_bin_size). */
    void emit_x_axis()
    {
        if (!plan_.x_tick_labels.empty()) {
            int x_ticks = std::max(1, (int)plan_.x_tick_labels.size() - 1);
            /* When a Bars-mode plot supplies exactly one label per bin,
             * center each label on its bar (instead of placing labels at
             * bin EDGES, which leaves them visually offset half a bar from
             * what they describe). */
            bool center_on_bin =
                (plan_.mode == ChartPlan::Mode::Bars
                 && (int)plan_.x_tick_labels.size() == plan_.n_bins);
            for (int t = 0; t <= x_ticks; t++) {
                double bin = center_on_bin
                    ? (double)t + 0.5
                    : (plan_.n_bins * (double)t) / x_ticks;
                double x = x_of(bin);
                std::fprintf(out_,
                    "<line x1=\"%.2f\" y1=\"%d\" x2=\"%.2f\" y2=\"%d\" "
                    "stroke=\"#cccccc\" stroke-width=\"1\"/>\n",
                    x, T + plot_h, x, T + plot_h + 4);
                if (plan_.show_x_labels && t < (int)plan_.x_tick_labels.size()) {
                    std::fprintf(out_,
                        "<text x=\"%.2f\" y=\"%d\" text-anchor=\"middle\" "
                        "fill=\"#555\">%s</text>\n",
                        x, T + plot_h + 18,
                        xml_escape(plan_.x_tick_labels[t]).c_str());
                }
            }
        } else if (plan_.mode == ChartPlan::Mode::Bars) {
            /* Bin-centered ticks.  Pick a "nice" step (1/2/5 × 10^k)
             * targeting ~6 ticks across n_bins; label = bin index, with
             * optional unit suffix.  When an overflow bin is present at
             * the right edge, skip any auto-tick that would land on it
             * (its label would mis-describe a folded tail) and draw an
             * explicit ">N" tick at the rightmost bin instead. */
            int last_b = plan_.n_bins - 1;
            bool has_overflow = plan_.has_overflow_bin
                                && !plan_.overflow_label.empty()
                                && plan_.n_bins > 0;
            int step = std::max(1, plan_.n_bins / 6);
            static const int snap[] = {1, 2, 5, 10, 20, 50, 100, 200,
                                       500, 1000, 2000, 5000, 10000};
            for (int s : snap) { if (s >= step) { step = s; break; } }
            for (int b = 0; b < plan_.n_bins; b += step) {
                if (has_overflow && b == last_b) continue;
                double x = x_of((double)b + 0.5);
                std::fprintf(out_,
                    "<line x1=\"%.2f\" y1=\"%d\" x2=\"%.2f\" y2=\"%d\" "
                    "stroke=\"#cccccc\" stroke-width=\"1\"/>\n",
                    x, T + plot_h, x, T + plot_h + 4);
                if (plan_.show_x_labels) {
                    char buf[32];
                    std::snprintf(buf, sizeof(buf), "%d", b);
                    std::string lab = buf;
                    lab += plan_.x_unit_suffix;
                    std::fprintf(out_,
                        "<text x=\"%.2f\" y=\"%d\" text-anchor=\"middle\" "
                        "fill=\"#555\">%s</text>\n",
                        x, T + plot_h + 18, xml_escape(lab).c_str());
                }
            }
            if (has_overflow) {
                double x = x_of((double)last_b + 0.5);
                std::fprintf(out_,
                    "<line x1=\"%.2f\" y1=\"%d\" x2=\"%.2f\" y2=\"%d\" "
                    "stroke=\"#cccccc\" stroke-width=\"1\"/>\n",
                    x, T + plot_h, x, T + plot_h + 4);
                if (plan_.show_x_labels) {
                    std::fprintf(out_,
                        "<text x=\"%.2f\" y=\"%d\" text-anchor=\"middle\" "
                        "fill=\"#555\">%s</text>\n",
                        x, T + plot_h + 18,
                        xml_escape(plan_.overflow_label).c_str());
                }
            }
        } else {
            int x_ticks = 6;
            for (int t = 0; t <= x_ticks; t++) {
                double bin = (plan_.n_bins * (double)t) / x_ticks;
                uint64_t insn = (uint64_t)(plan_.x_bin_size * bin);
                double x = x_of(bin);
                std::fprintf(out_,
                    "<line x1=\"%.2f\" y1=\"%d\" x2=\"%.2f\" y2=\"%d\" "
                    "stroke=\"#cccccc\" stroke-width=\"1\"/>\n",
                    x, T + plot_h, x, T + plot_h + 4);
                if (plan_.show_x_labels) {
                    std::fprintf(out_,
                        "<text x=\"%.2f\" y=\"%d\" text-anchor=\"middle\" "
                        "fill=\"#555\">%s</text>\n",
                        x, T + plot_h + 18,
                        xml_escape(fmt_count(insn)).c_str());
                }
            }
        }
    }

    /* Axis labels.  The x-axis title sits below the tick labels
     * (~B_edge + 38), outside the plot frame, so it never overlaps data
     * (histogram bars, or any series approaching zero). */
    void emit_axis_titles()
    {
        if (!plan_.x_label.empty() && plan_.show_x_labels) {
            std::fprintf(out_,
                "<text x=\"%d\" y=\"%d\" text-anchor=\"middle\" "
                "fill=\"#333\" font-size=\"13\">%s</text>\n",
                L + plot_w / 2, B_edge + 38,
                xml_escape(plan_.x_label).c_str());
        }
        if (!plan_.y_label.empty()) {
            int yx = 22, yy = T + plot_h / 2;
            std::fprintf(out_,
                "<text x=\"%d\" y=\"%d\" text-anchor=\"middle\" fill=\"#333\" "
                "font-size=\"13\" transform=\"rotate(-90, %d, %d)\">%s</text>\n",
                yx, yy, yx, yy, xml_escape(plan_.y_label).c_str());
        }
    }

    void emit_title()
    {
        if (!plan_.title.empty()) {
            std::fprintf(out_,
                "<text x=\"%d\" y=\"%d\" text-anchor=\"middle\" "
                "fill=\"#222\" font-size=\"16\" font-weight=\"600\">%s</text>\n",
                L + plot_w / 2, T - 22, xml_escape(plan_.title).c_str());
        }
    }

    /* Warm-up overlay: a translucent rectangle over the first
     * @warmup_bins bins, plus a small "warmup" label at the top of
     * the overlay so it's clear the data isn't missing — it's
     * deliberately excluded from scaling. */
    void emit_warmup_overlay()
    {
        if (plan_.warmup_bins > 0 && plan_.warmup_bins < plan_.n_bins) {
            double x0 = x_of(0);
            double x1 = x_of(plan_.warmup_bins);
            std::fprintf(out_,
                "<rect x=\"%.2f\" y=\"%d\" width=\"%.2f\" height=\"%d\" "
                "fill=\"#000000\" fill-opacity=\"0.05\"/>\n",
                x0, T, x1 - x0, plot_h);
            std::fprintf(out_,
                "<text x=\"%.2f\" y=\"%d\" text-anchor=\"start\" "
                "fill=\"#666\" font-size=\"10\" font-style=\"italic\">"
                "warmup</text>\n", x0 + 3, T + 12);
        }
    }

    /* Plot. */
    void emit_data()
    {
        if (plan_.mode == ChartPlan::Mode::Bars) {
            /* Histogram bars.  With a single series this is one filled rect
             * per bin (top = y_of(value), bottom = y_of(0)).  With multiple
             * series (aggregate mode: one per simpoint) the bars STACK, so
             * each bucket shows how each simpoint contributes to the overall
             * shape while the total height stays the weighted-mean
             * distribution.  Single-series plots are unaffected (the stack of
             * one == the old single bar). */
            std::vector<double> cum((size_t)plan_.n_bins, 0.0);
            for (size_t si = 0; si < plan_.series.size(); si++) {
                const Series &s = plan_.series[si];
                for (int b = 0; b < plan_.n_bins; b++) {
                    double v = (b < (int)s.y.size()) ? s.y[b] : 0.0;
                    if (v <= 0) continue;
                    double xl = x_of(b);
                    double xr = x_of(b + 1);
                    double yt = y_of(cum[b] + v);
                    double yb = y_of(cum[b]);
                    cum[b] += v;
                    std::fprintf(out_,
                        "<rect x=\"%.2f\" y=\"%.2f\" width=\"%.2f\" "
                        "height=\"%.2f\" fill=\"%s\" fill-opacity=\"0.85\" "
                        "stroke=\"%s\" stroke-width=\"0.5\"/>\n",
                        xl, yt, std::max(0.5, xr - xl), yb - yt,
                        s.color.c_str(), s.color.c_str());
                }
            }
        } else if (plan_.mode == ChartPlan::Mode::Lines) {
            for (size_t si = 0; si < plan_.series.size(); si++) {
                const Series &s = plan_.series[si];
                const char *dash_attr = s.dashed
                    ? " stroke-dasharray=\"6 4\""
                    : "";
                std::fprintf(out_, "<polyline fill=\"none\" stroke=\"%s\" "
                    "stroke-width=\"1.5\"%s points=\"",
                    s.color.c_str(), dash_attr);
                for (int b = 0; b < plan_.n_bins; b++) {
                    double v = (b < (int)s.y.size()) ? s.y[b] : 0.0;
                    std::fprintf(out_, "%.2f,%.2f ",
                                 x_of(b + 0.5), y_of(v));
                }
                std::fprintf(out_, "\"/>\n");
            }
        } else {
            /* Stacked area: layer 0 at the bottom; cumulative y per bin. */
            std::vector<double> cum(plan_.n_bins, 0.0);
            for (size_t si = 0; si < plan_.series.size(); si++) {
                const Series &s = plan_.series[si];
                std::fprintf(out_,
                    "<polygon fill=\"%s\" fill-opacity=\"0.9\" "
                    "stroke=\"%s\" stroke-width=\"0.5\" points=\"",
                    s.color.c_str(), s.color.c_str());
                /* upper edge */
                for (int b = 0; b < plan_.n_bins; b++) {
                    double v = (b < (int)s.y.size()) ? s.y[b] : 0.0;
                    std::fprintf(out_, "%.2f,%.2f ",
                                 x_of(b + 0.5), y_of(cum[b] + v));
                }
                /* lower edge (reverse) */
                for (int b = plan_.n_bins - 1; b >= 0; b--) {
                    std::fprintf(out_, "%.2f,%.2f ",
                                 x_of(b + 0.5), y_of(cum[b]));
                }
                std::fprintf(out_, "\"/>\n");

                for (int b = 0; b < plan_.n_bins; b++) {
                    double v = (b < (int)s.y.size()) ? s.y[b] : 0.0;
                    cum[b] += v;
                }
            }
        }
    }

    /* Trace-encoded warmup->simulation boundary marker (header §2.13).
     * Drawn AFTER the series so the rule sits on top of the (opaque)
     * stacked-area / line data rather than being painted over.  Only
     * meaningful on instruction-window axes — Bars-mode histograms and
     * custom-tick static-summary plots measure something other than CP
     * insns, so skip them.  The value is an arch CP-insn count mapped to
     * a bin via x_bin_size, clamped to the plotted range. */
    void emit_warmup_end_marker()
    {
        if (plan_.warmup_end_insns != UINT64_MAX && plan_.warmup_end_insns != 0 &&
            plan_.mode != ChartPlan::Mode::Bars && plan_.x_tick_labels.empty() &&
            plan_.x_bin_size > 0 && plan_.n_bins > 0) {
            double bin = (double)plan_.warmup_end_insns / (double)plan_.x_bin_size;
            if (bin > 0 && bin <= plan_.n_bins) {
                double x = x_of(bin);
                /* Heavy solid black dashed rule, full opacity, drawn over the
                 * data so it's unmistakable. */
                std::fprintf(out_,
                    "<line x1=\"%.2f\" y1=\"%d\" x2=\"%.2f\" y2=\"%d\" "
                    "stroke=\"#000000\" stroke-width=\"2.5\" "
                    "stroke-dasharray=\"9,5\"/>\n",
                    x, T, x, T + plot_h);
                /* Label ABOVE the plot frame, centred on the rule, on the
                 * white canvas margin where it's always legible.  Nudge it
                 * inward at the extreme right edge so it doesn't collide with
                 * the legend / clip off-canvas. */
                const char *lbl = "end of warmup";
                const char *anchor = "middle";
                double lx = x;
                if (x > R_edge - 40) { anchor = "end"; lx = x; }
                std::fprintf(out_,
                    "<text x=\"%.2f\" y=\"%d\" text-anchor=\"%s\" "
                    "fill=\"#000000\" font-size=\"11\" font-weight=\"700\">"
                    "%s</text>\n", lx, T - 6, anchor, lbl);
            }
        }
    }

    /* Legend.  Entries with empty labels are skipped — used by single-series
     * histograms whose y-axis label already names the data, so a legend
     * square would just be noise.  Entries wrap into a second column when
     * they overflow the plot height; @guard_last suppresses the wrap after
     * the final series (the normal path's behaviour, vs the composition
     * pane which always evaluates the wrap). */
    void emit_legend(bool guard_last)
    {
        int lx = L + plot_w + 16;
        int ly = T + 8;
        for (size_t si = 0; si < plan_.series.size(); si++) {
            const Series &s = plan_.series[si];
            if (s.label.empty()) continue;
            std::fprintf(out_,
                "<rect x=\"%d\" y=\"%d\" width=\"12\" height=\"12\" "
                "fill=\"%s\"/>\n",
                lx, ly, s.color.c_str());
            std::fprintf(out_,
                "<text x=\"%d\" y=\"%d\" dominant-baseline=\"middle\" "
                "fill=\"#222\">%s</text>\n",
                lx + 18, ly + 6, xml_escape(s.label).c_str());
            ly += 18;
            bool wrap = ly > T + plot_h - 12;
            if (guard_last) {
                wrap = wrap && si + 1 < plan_.series.size();
            }
            if (wrap) { lx += 120; ly = T + 8; }
        }
    }

    std::FILE *out_;
    const ChartPlan &plan_;
    const int VX, VY, VW, VH, L, R_edge, T, B_edge, plot_w, plot_h;
};

static void render_plan(std::FILE *out, const ChartPlan &plan)
{
    SvgEmitter(out, plan).render();
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

    /* For wp_divergence: per-CP-bin histogram of "match depth" — how many
     * WP-chain edges the BP+BTB model predicts correctly before it diverges
     * from the recorded chain (or runs it to completion), one observation
     * per CP branch whose chain has at least one edge.  A histogram (not a
     * per-branch vector) because depths are bounded by max_wrong_path_depth,
     * so a small fixed bucket array per bin suffices where one int per CP
     * branch would be 200MB+ on a 300M trace; finalize derives min / median
     * / max / mean from it. */
    std::vector<std::vector<uint64_t>> wp_depth_per_bin;

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

    /* WP-pollution gating.  Realistic hardware only steers fetch to
     * the wrong path when the front-end mispredicts the branch; if
     * the predictor gets it right, no WP is observed.  The trace
     * records WP for every CP branch regardless, so handlers that
     * model WP pollution (btb_miss / cache_miss / mem_pat /
     * branch_dir) over-count unless they gate by a prediction.
     *
     * BTB and BP gate JOINTLY:
     *   Conditional branch:
     *     BTB miss → no target available; front-end defaults to
     *                fall-through.  WP iff actually taken.
     *     BTB hit  → gshare picks direction.  WP iff direction wrong.
     *   Non-conditional (uncond / indirect / return / syscall):
     *     BTB hit (target match) → no WP.
     *     BTB miss or stale-target → WP.
     *
     * bp_btb_gate is sized at walk-init to max(--btb-entries),
     * default 1024 if --btb-entries was not specified.
     *
     * The gate's outcome is only knowable at the NEXT entry (when
     * this entry's branch outcome is observed via that entry's
     * start_pc), so the current entry's wp_entries are deferred by
     * one position: stash here, replay at the next entry's resolve
     * step.  pending_should_pollute is set during the resolve step
     * and read by handlers that consume pending_wp_entries. */
    GShare    bp_gate{14, 2};
    BTB       bp_btb_gate{1024};
    bool      pending_is_conditional = false;
    bool      pending_should_pollute = false;

    /* Streaming path: minimal structural projection of one CP entry's
     * wrong-path chain, accumulated live as the WP BBs stream in (never
     * the decoder's BB objects).  Replayed at the NEXT CP BB, where the
     * misprediction gate is finally resolvable.  start_pc / n_insns are
     * the only per-WP-BB fields the gated pairwise replay needs;
     * tidx == UINT32_MAX marks an unknown template (replay skips it,
     * mirroring the batch by_id miss). */
    struct WpProjBB {
        uint32_t tidx;
        uint64_t start_pc;
        uint32_t n_insns;
    };
    std::vector<WpProjBB> wp_chain;

    /* mem_pat streaming: the wrong-path memory-pattern contribution is
     * additive (bins_wp[pat] += 1 per WP memop), so it accumulates into
     * a tentative per-pattern tally as the chain streams and commits at
     * the next CP BB iff the gate passed — no address retention. */
    uint64_t wp_pat_tally[4] = {0, 0, 0, 0};
    /* cache_miss streaming: the corrupted-cache pollution mutates LRU
     * state in arrival order, so it can't be folded into a counter; the
     * WP memop addresses are retained for in-order replay (still scalar
     * addresses, never the BBs). */
    std::vector<uint64_t> wp_addrs;

    /* Branch-stream diagnostics enabled via --debug-branches=N.  We
     * capture exactly what the gshare predictor sees so we can
     * verify, post-walk, that the outcomes the handler derived match
     * what the branches actually did. */
    struct DebugBranchState {
        struct PcAgg {
            uint64_t taken      = 0;
            uint64_t nottaken   = 0;
            uint64_t mispred_h0 = 0;
            uint64_t mispred_h12 = 0;
        };
        std::unordered_map<uint64_t, PcAgg> per_pc;
        uint64_t                            dumped = 0;
    };
    DebugBranchState dbg;

    /* --- working_set state.  Sliding-window accounting: each access
     * is recorded with the cp_insn position at which it happened;
     * accesses older than (cp_insns_so_far - ws_window) get retired
     * from the per-line / per-page counts, so the maps' sizes are
     * the LIVE working set, not a since-start cumulative footprint. */
    struct WorkingSetState {
        std::deque<std::pair<uint64_t, uint64_t>> line_accesses; /* (cp_insn, line) */
        std::deque<std::pair<uint64_t, uint64_t>> page_accesses;
        std::unordered_map<uint64_t, uint32_t>    line_count;    /* line -> count in window */
        std::unordered_map<uint64_t, uint32_t>    page_count;
        std::vector<uint64_t> lines_per_bin;
        std::vector<uint64_t> pages_per_bin;
    };
    WorkingSetState ws;

    /* --- dep_depth / ilp shared state.  Wall's ideal-rename data-
     * flow model: each insn's complete cycle = 1 + max over its
     * architectural sources of (producer's complete cycle), with
     * the producer table maintained per arch dst — exactly what a
     * physical-register-file rename eliminates the WAW/WAR hazards
     * of, leaving only RAW edges to bound parallelism.
     *
     * Special regs (FLAGS/IP/ZERO/NONE) are excluded from both
     * sides so the metric is dominated by real GPR/FPR/VEC data
     * flow rather than the implicit FLAGS chain every arithmetic
     * op would otherwise serialize through.  Self-RMW IS counted:
     * `add rcx, 1` truly serializes through rcx (each iteration
     * reads the previous iteration's value); rename removes the
     * WAR/WAW hazards but not the RAW edge.
     *
     * Tumbling window of --rob-size insns: at every window
     * boundary we clear the producer table and reset chunk
     * state.  This bounds chain depth to the window (matching the
     * "scheduling window a real OoO core can see at once") and
     * lets us emit a per-window summary for the ilp metric:
     * ideal IPC = window / max_complete_cycle_in_chunk.
     *
     *   dd_*:  per-insn complete-cycle histogram (dep_depth metric)
     *   ilp_*: per-chunk IPC samples + global issue-cycle hist
     *
     * Memory RAW is modelled alongside register RAW: a store
     * publishes its completion cycle for its address, and a load
     * aliasing that address in the same window takes a dependency on
     * it (store→load forwarding latency folded into the 1-cycle
     * model).  Disambiguation is by exact byte address — the standard
     * true-dependence proxy; partial overlaps are treated as
     * independent.  WAR/WAW through memory are removed by the same
     * ideal-rename assumption as registers, so only store→load (RAW)
     * carries a chain. */
    struct DataflowState {
        std::array<bool, 256> excluded_reg{};
        bool                  excluded_built = false;
        std::unordered_map<uint8_t, uint32_t>  producer_complete;
        std::unordered_map<uint64_t, uint32_t> mem_producer_complete;
        uint32_t                              chunk_insns      = 0;
        uint32_t                              chunk_max_cycle  = 0;
        std::vector<std::vector<uint64_t>>    dd_depth_hist_per_bin;
        /* Per-bin per-chunk samples of (ipc × 1000).  uint32_t is enough
         * since ipc <= window_size <= 2^30. */
        std::vector<std::vector<uint32_t>>    ilp_samples_per_bin;
        /* Global issue-cycle histogram: count of insns that issued at
         * each in-window cycle, summed across all chunks. */
        std::vector<uint64_t>                 ilp_cycle_hist;
    };
    DataflowState df;

    /* --- reuse_distance state.  An order-statistic tree (RB-tree
     * augmented with subtree sizes) holds one entry per currently-live
     * cache line, keyed by a monotonic access-time counter so younger
     * keys are larger.  Stack distance = #entries above L = ru_tree
     * size - order_of_key(L's last time) - 1; both lookup and
     * promote-to-top run in O(log N) rather than the O(N) of a
     * list + linear scan per memop.  Histogram counts log2-bucketed
     * distances plus a "cold" bucket for first-access lines. */
    struct ReuseDistState {
        OrderStatTree                          tree;
        std::unordered_map<uint64_t, uint64_t> last_t;  /* line → tree key */
        uint64_t                               clock = 0;
        std::vector<uint64_t>                  hist;    /* grown lazily */
        uint64_t                               cold = 0; /* first-access cnt */
    };
    ReuseDistState ru;
};

/* Helper: classify a template's terminating instruction for
 * gshare-vs-direction accounting. */
/* The terminating branch is the highest-indexed branch-type insn:
 * n-1 normally, or n-2 on a delay-slot ISA where the delay slot is the
 * last insn (templates are stored in true execution order). */
static const cst::InsnTemplate *find_term_branch(const cst::Template &t)
{
    for (size_t i = t.insns.size(); i-- > 0; ) {
        if (t.insns[i].branch_type != 0) {
            return &t.insns[i];
        }
    }
    return nullptr;
}

static WalkCtx::TermBranch classify_term(
    const cst::Template &t,
    const std::unordered_map<uint64_t, std::string> &bt_map)
{
    WalkCtx::TermBranch tb;
    tb.fall_through  = t.fall_through_pc;
    const cst::InsnTemplate *last = find_term_branch(t);
    if (!last) return tb;        /* is_branch stays false */
    tb.pc            = last->pc;
    tb.is_branch     = true;

    /* Look up the name to identify direct vs indirect vs return vs
     * syscall.  The trace's encoding map carries the canonical
     * BRANCH_* names. */
    std::string n = lookup_name(bt_map, last->branch_type);
    tb.class_name = n;
    bool name_says_indirect =
        n.find("INDIRECT") != std::string::npos ||
        n.find("RETURN")   != std::string::npos ||
        n.find("SYSCALL")  != std::string::npos ||
        n.find("REP")      != std::string::npos;
    tb.is_indirect_class = name_says_indirect;
    bool unconditional =
        n.find("DIRECT_JUMP") != std::string::npos ||
        n.find("CALL")        != std::string::npos ||
        n.find("SYSCALL")     != std::string::npos ||
        n.find("RETURN")      != std::string::npos ||
        n.find("INDIRECT")    != std::string::npos;
    tb.is_conditional =
        last->branch_conditional && !name_says_indirect && !unconditional;
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

/* Push one streaming WP BB's structural projection (template index,
 * start_pc, insn count) onto the current chain — never the BB object.
 * Shared by every deferred branch handler's WP-accumulation step. */
static inline void wp_chain_push(WalkCtx &ctx, const cst::BodyWalker::BB &bb)
{
    ctx.wp_chain.push_back({bb.template_index,
                            bb.tmpl ? bb.tmpl->start_pc : 0,
                            bb.n_insns});
}

/* Accumulate one streaming WP BB into the current chain projection +
 * the wasted-WP running sums.  Memop count is only meaningful when the
 * BB carries field data (WpMemops level); at Structure it stays 0,
 * which is all branch_mpki / wp_insns need. */
static inline void handle_gshare_wp(WalkCtx &ctx, const cst::BodyWalker::BB &bb)
{
    wp_chain_push(ctx, bb);
    ctx.pending_wp_insns += bb.n_insns;
    if (bb.has_fields()) {
        for (uint32_t i = 0; i < bb.n_insns; i++) {
            uint64_t nl = bb.load_count(i);
            if (nl > cst::FID_SLOT_COUNT) nl = cst::FID_SLOT_COUNT;
            uint64_t ns = bb.store_count(i);
            if (ns > cst::FID_SLOT_COUNT) ns = cst::FID_SLOT_COUNT;
            ctx.pending_wp_memops += (uint32_t)(nl + ns);
        }
    }
}

static void handle_gshare_bb(WalkCtx &ctx, const cst::BodyWalker::BB &bb)
{
    if (bb.is_wp) { handle_gshare_wp(ctx, bb); return; }
    const cst::Template &t = *bb.tmpl;
    uint32_t n_insns = bb.n_insns;
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
        /* Per-predictor pollution gate.  WP only actually executes
         * (and pollutes the predictor) when THIS predictor itself
         * would have mispredicted — that's what causes the front-end
         * to fetch the wrong-path branches in real hardware.  Gating
         * by a fixed external predictor would decouple the metric
         * from the predictor under measurement and is what previous
         * versions of this handler effectively did (unconditional
         * WP training of every corrupted variant). */
        if (mispred) {
            for (size_t i = 0; i + 1 < ctx.wp_chain.size(); i++) {
                const auto &cur_wp  = ctx.wp_chain[i];
                const auto &next_wp = ctx.wp_chain[i + 1];
                if (cur_wp.tidx == 0xFFFFFFFFu) continue;
                if (next_wp.tidx == 0xFFFFFFFFu) continue;
                const WalkCtx::TermBranch &wtb = ctx.term[cur_wp.tidx];
                if (!wtb.is_branch || !wtb.is_conditional) continue;
                bool wp_taken = (next_wp.start_pc != wtb.fall_through);
                g.update(wtb.pc, wp_taken);
            }
        }
        g.update(ctx.pending_branch_pc, taken);
    };
    if (ctx.have_pending && ctx.pending_is_branch) {
        bool taken = (t.start_pc != ctx.pending_fall_pc);
        /* Diagnostic: capture per-PC outcomes BEFORE the predictor
         * loop mutates state.  --debug-branches=N enables dumping
         * the first N tuples + per-PC aggregates at end-of-walk. */
        bool dbg_on = ctx.opts.debug_branches > 0
                   && ctx.opts.metric == Metric::BranchMpki;
        int  pi_h0 = -1, pi_h12 = -1;
        bool pred_h0 = false, pred_h12 = false;
        if (dbg_on) {
            for (size_t k = 0; k < ctx.opts.histories.size(); k++) {
                if (ctx.opts.histories[k] == 0)  pi_h0  = (int)k;
                if (ctx.opts.histories[k] == 12) pi_h12 = (int)k;
            }
            if (pi_h0 >= 0) {
                pred_h0 = ctx.predictors[pi_h0].predict(
                    ctx.pending_branch_pc);
            }
            if (pi_h12 >= 0) {
                pred_h12 = ctx.predictors[pi_h12].predict(
                    ctx.pending_branch_pc);
            }
        }
        for (size_t pi = 0; pi < ctx.predictors.size(); pi++) {
            resolve_cp((int)pi, taken);
            resolve_corrupted((int)pi, taken);
        }
        if (dbg_on) {
            if (ctx.dbg.dumped < (uint64_t)ctx.opts.debug_branches) {
                std::fprintf(stderr,
                    "BR pc=0x%lx taken=%d bin=%d pred_h0=%d pred_h12=%d\n",
                    (unsigned long)ctx.pending_branch_pc, taken ? 1 : 0,
                    (int)ctx.pending_bin, pred_h0 ? 1 : 0,
                    pred_h12 ? 1 : 0);
                ctx.dbg.dumped++;
            }
            auto &agg = ctx.dbg.per_pc[ctx.pending_branch_pc];
            if (taken) agg.taken++; else agg.nottaken++;
            if (pi_h0  >= 0 && pred_h0  != taken) agg.mispred_h0++;
            if (pi_h12 >= 0 && pred_h12 != taken) agg.mispred_h12++;
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
    const WalkCtx::TermBranch &tb = ctx.term[bb.template_index];
    ctx.have_pending = true;
    ctx.pending_bin  = (uint64_t)bin;
    ctx.pending_branch_pc = tb.pc;
    ctx.pending_fall_pc   = tb.fall_through;
    ctx.pending_is_branch = tb.is_branch && tb.is_conditional;

    /* Reset the wasted-WP sums and chain projection; THIS entry's WP
     * BBs stream in next and refill them via handle_gshare_wp, to be
     * gated and replayed at the next CP BB's resolve.  (The CP-only
     * predictor set is never trained on WP — by design.) */
    ctx.pending_wp_insns  = 0;
    ctx.pending_wp_memops = 0;
    ctx.wp_chain.clear();

    ctx.cp_insns_so_far += n_insns;
}

/* BTB drive: track every CP branch's (PC, target) pair through each
 * configured BTB size.  The target is observed from the NEXT entry's
 * start_pc (taken edge) or the current BB's fall_through (not-taken),
 * resolved via the same pending-branch mechanism the gshare path
 * uses. */
/* Resolve the previous-entry pending branch through the front-end
 * gates and decide whether the previous entry's WP chain should be
 * replayed as pollution.  Mirrors real hardware: WP only executes
 * when the front-end actually steered fetch to a wrong path, which
 * requires both a BTB result AND (for conditionals) a direction
 * prediction.
 *
 *   Conditional:
 *     BTB miss → no target known, default to fall-through.
 *                Pollute iff branch was actually taken.
 *     BTB hit  → gshare predicts direction.  Pollute iff direction
 *                wrong.  (Direct conditional → BTB target is the
 *                encoded immediate, never stale.)
 *     BTB is only trained on TAKEN conditionals — real BTBs cache
 *     taken-branch targets.
 *
 *   Unconditional / indirect / return / syscall:
 *     Always taken; no direction prediction.
 *     BTB miss or stale-target → pollute.
 *
 * Must be called from any handler that replays the deferred WP chain
 * (the streaming wp_chain projection). */
static void resolve_bp_gate(WalkCtx &ctx, const cst::Template &t_now)
{
    if (!ctx.have_pending || !ctx.pending_is_branch) {
        ctx.pending_should_pollute = false;
        return;
    }
    uint64_t actual_target = t_now.start_pc;
    if (ctx.pending_is_conditional) {
        bool taken = (actual_target != ctx.pending_fall_pc);
        bool btb_hit = ctx.bp_btb_gate.lookup(ctx.pending_branch_pc);
        bool pred_taken = btb_hit
            ? ctx.bp_gate.predict(ctx.pending_branch_pc)
            : false;
        ctx.pending_should_pollute = (pred_taken != taken);
        ctx.bp_gate.update(ctx.pending_branch_pc, taken);
        if (taken) {
            ctx.bp_btb_gate.access(ctx.pending_branch_pc,
                                   actual_target);
        }
    } else {
        bool hit = ctx.bp_btb_gate.access(ctx.pending_branch_pc,
                                          actual_target);
        ctx.pending_should_pollute = !hit;
    }
}

static void handle_btb_bb(WalkCtx &ctx, const cst::BodyWalker::BB &bb)
{
    if (bb.is_wp) { wp_chain_push(ctx, bb); return; }
    const cst::Template &t = *bb.tmpl;
    uint32_t n_insns = bb.n_insns;
    int bin = bin_of(ctx, ctx.cp_insns_so_far);

    /* BP gate: decide whether the PREVIOUS entry's WP chain should
     * replay as pollution.  Resolution depends on this entry's
     * start_pc (the taken edge), so it has to live here, not in the
     * previous handler call. */
    resolve_bp_gate(ctx, t);

    /* Resolve previous branch's observed target via this entry's
     * start_pc, then drive each BTB and tally misses into the
     * previous bin.  Two parallel sets of BTBs: cp_only sees CP
     * targets exclusively; corrupted sees CP + (BP-mispredicted) WP. */
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

        /* Pollute the corrupted BTBs with the PREVIOUS entry's WP
         * chain, but ONLY if the BP would have mispredicted —
         * mirrors real hardware where WP execution is conditional on
         * BP failure.  Walk pairwise: WP entry i's terminating
         * branch resolved to WP entry i+1's start_pc. */
        if (ctx.pending_should_pollute) {
            for (size_t i = 0; i + 1 < ctx.wp_chain.size(); i++) {
                const auto &cur_wp  = ctx.wp_chain[i];
                const auto &next_wp = ctx.wp_chain[i + 1];
                if (cur_wp.tidx == 0xFFFFFFFFu) continue;
                if (next_wp.tidx == 0xFFFFFFFFu) continue;
                const WalkCtx::TermBranch &wtb = ctx.term[cur_wp.tidx];
                if (!wtb.is_branch) continue;
                for (auto &b : ctx.btbs_corrupted) {
                    (void)b.access(wtb.pc, next_wp.start_pc);
                }
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
    const WalkCtx::TermBranch &tb = ctx.term[bb.template_index];
    ctx.have_pending      = true;
    ctx.pending_bin       = (uint64_t)bin;
    ctx.pending_branch_pc = tb.pc;
    ctx.pending_fall_pc   = tb.fall_through;
    ctx.pending_is_branch = tb.is_branch;
    ctx.pending_is_conditional = tb.is_conditional;

    /* Reset the chain projection; THIS entry's WP BBs stream next and
     * refill it, gated and replayed at the next CP BB's resolve. */
    ctx.wp_chain.clear();

    ctx.cp_insns_so_far += n_insns;
}

/* cache_miss: drive a set-associative cache per --cache-assoc value
 * with this CP entry's memops, counting CP misses.  WP memops of
 * the same entry get fed into the corrupted-variant caches only —
 * those caches measure CP miss rate but their tag/LRU state is
 * polluted by every speculative access the WP chain recorded. */
/* Visit each memop of a streaming BB in the same order the batch
 * decoder materialised dyn_params: per instruction, loads (slot 0..N)
 * then stores.  @f receives (insn_index, addr).  Counts are clamped to
 * FID_SLOT_COUNT exactly as the batch path's materialise_slotted_memops
 * does, so a malformed over-count drops the excess instead of reading
 * out-of-range slots. */
template <class F>
static inline void for_each_cp_memop(const cst::BodyWalker::BB &bb, F &&f)
{
    for (uint32_t i = 0; i < bb.n_insns; i++) {
        uint64_t nl = bb.load_count(i);
        if (nl > cst::FID_SLOT_COUNT) nl = cst::FID_SLOT_COUNT;
        for (uint32_t k = 0; k < nl; k++) f(i, bb.load_addr(i, k));
        uint64_t ns = bb.store_count(i);
        if (ns > cst::FID_SLOT_COUNT) ns = cst::FID_SLOT_COUNT;
        for (uint32_t k = 0; k < ns; k++) f(i, bb.store_addr(i, k));
    }
}

static void handle_cache_miss_bb(WalkCtx &ctx, const cst::BodyWalker::BB &bb)
{
    if (bb.is_wp) {
        /* Retain WP memop addresses in chain order for the gated,
         * order-dependent corrupted-cache replay at the next CP BB. */
        for_each_cp_memop(bb, [&](uint32_t, uint64_t addr) {
            ctx.wp_addrs.push_back(addr);
        });
        return;
    }
    const cst::Template &t = *bb.tmpl;
    int bin = bin_of(ctx, ctx.cp_insns_so_far);

    /* BP gate: decide whether the PREVIOUS entry's WP memops should
     * pollute the corrupted caches.  Replay the retained WP addresses
     * when the BP would have mispredicted. */
    resolve_bp_gate(ctx, t);
    if (ctx.pending_should_pollute) {
        for (uint64_t addr : ctx.wp_addrs) {
            for (auto &c : ctx.caches_corrupted) (void)c.access(addr);
        }
    }
    ctx.wp_addrs.clear();   /* ready for THIS entry's WP chain */

    /* CP memops drive BOTH cache variants, counted only in their
     * respective bin matrices for CP miss-rate computation. */
    uint64_t n_cp_memops = 0;
    for_each_cp_memop(bb, [&](uint32_t, uint64_t addr) {
        n_cp_memops++;
        for (size_t ci = 0; ci < ctx.caches.size(); ci++) {
            bool hit = ctx.caches[ci].access(addr);
            if (!hit) ctx.bins.at((int)ci, bin) += 1.0;
        }
        for (size_t ci = 0; ci < ctx.caches_corrupted.size(); ci++) {
            bool hit = ctx.caches_corrupted[ci].access(addr);
            if (!hit) ctx.bins_wp.at((int)ci, bin) += 1.0;
        }
    });
    if ((int)ctx.cp_memops_per_bin.size() <= bin) {
        ctx.cp_memops_per_bin.resize(bin + 1, 0);
    }
    ctx.cp_memops_per_bin[bin] += n_cp_memops;

    /* Cache this entry's terminating branch so the next entry's resolve
     * step can gate the just-streamed WP chain's pollution by BP. */
    const WalkCtx::TermBranch &tb = ctx.term[bb.template_index];
    ctx.have_pending      = true;
    ctx.pending_bin       = (uint64_t)bin;
    ctx.pending_branch_pc = tb.pc;
    ctx.pending_fall_pc   = tb.fall_through;
    ctx.pending_is_branch = tb.is_branch;
    ctx.pending_is_conditional = tb.is_conditional;

    ctx.cp_insns_so_far += bb.n_insns;
}

/* Accumulate one streaming WP BB's per-pattern memop counts into the
 * tentative tally (committed at the next CP BB iff the gate passes). */
static inline void handle_mem_pat_wp(WalkCtx &ctx, const cst::BodyWalker::BB &bb)
{
    if (!bb.tmpl) return;
    const cst::Template &wt = *bb.tmpl;
    for_each_cp_memop(bb, [&](uint32_t insn_index, uint64_t) {
        if (insn_index >= wt.profile.insns.size()) return;
        uint8_t pat = wt.profile.insns[insn_index].pat_wp;
        if (pat > 3) pat = 0;
        ctx.wp_pat_tally[pat]++;
    });
}

static void handle_mem_pat_bb(WalkCtx &ctx, const cst::BodyWalker::BB &bb)
{
    if (bb.is_wp) { handle_mem_pat_wp(ctx, bb); return; }
    const cst::Template &t = *bb.tmpl;
    int bin = bin_of(ctx, ctx.cp_insns_so_far);

    /* BP gate: commit the previous chain's tentative WP tally only on a
     * mispredicted CP branch.  Without the gate, every CP entry's WP
     * memops would contribute to bins_wp regardless of whether the BP
     * would have triggered the speculation in real hw.  Attributed to
     * the resolved entry's bin (pending_bin) — the BB the mispredict
     * fired from. */
    resolve_bp_gate(ctx, t);
    if (ctx.pending_should_pollute) {
        for (int pat = 0; pat < 4; pat++) {
            ctx.bins_wp.at(pat, (int)ctx.pending_bin) +=
                (double)ctx.wp_pat_tally[pat];
        }
    }
    ctx.wp_pat_tally[0] = ctx.wp_pat_tally[1] =
        ctx.wp_pat_tally[2] = ctx.wp_pat_tally[3] = 0;

    /* Layers: 0=none, 1=regular, 2=irregular, 3=random.  CP-side
     * counted in units of memops on this visit (one CP memop per
     * dyn_param entry). */
    for_each_cp_memop(bb, [&](uint32_t insn_index, uint64_t) {
        if (insn_index >= t.profile.insns.size()) return;
        uint8_t pat = t.profile.insns[insn_index].pat_cp;
        if (pat > 3) pat = 0;
        ctx.bins.at((int)pat, bin) += 1.0;
    });

    const WalkCtx::TermBranch &tb = ctx.term[bb.template_index];
    ctx.have_pending      = true;
    ctx.pending_bin       = (uint64_t)bin;
    ctx.pending_branch_pc = tb.pc;
    ctx.pending_fall_pc   = tb.fall_through;
    ctx.pending_is_branch = tb.is_branch;
    ctx.pending_is_conditional = tb.is_conditional;

    ctx.cp_insns_so_far += bb.n_insns;
}

static void handle_branch_dir_bb(WalkCtx &ctx, const cst::BodyWalker::BB &bb)
{
    if (bb.is_wp) { wp_chain_push(ctx, bb); return; }
    const cst::Template &t = *bb.tmpl;
    int bin = bin_of(ctx, ctx.cp_insns_so_far);

    /* BP gate: decide if the PREVIOUS entry's WP branches should
     * contribute to the WP-direction breakdown.  Drops WP for
     * branches the BP would have predicted correctly. */
    resolve_bp_gate(ctx, t);

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

    /* Replay deferred WP-direction breakdown for the previous entry,
     * only if BP would have mispredicted. */
    if (ctx.pending_should_pollute) {
        for (size_t i = 0; i + 1 < ctx.wp_chain.size(); i++) {
            const auto &cur_wp  = ctx.wp_chain[i];
            const auto &next_wp = ctx.wp_chain[i + 1];
            if (cur_wp.tidx == 0xFFFFFFFFu) continue;
            if (next_wp.tidx == 0xFFFFFFFFu) continue;
            const WalkCtx::TermBranch &wtb = ctx.term[cur_wp.tidx];
            if (!wtb.is_branch) continue;
            bool wp_taken = (next_wp.start_pc != wtb.fall_through);
            std::string label = wtb.is_conditional
                ? wtb.class_name + (wp_taken ? " taken" : " not-taken")
                : wtb.class_name;
            int sid = ctx.add_label(label);
            ctx.bins_wp.at(sid, (int)ctx.pending_bin) += 1.0;
        }
    }

    /* Stash this entry's classification for the next resolution.  We
     * defer the series-id allocation until resolution-time so the
     * label encodes taken/not-taken. */
    const size_t tidx = bb.template_index;
    const WalkCtx::TermBranch &tb = ctx.term[tidx];
    ctx.have_pending      = tb.is_branch;
    ctx.pending_bin       = (uint64_t)bin;
    ctx.pending_term_index = tidx;
    ctx.pending_branch_pc = tb.pc;
    ctx.pending_fall_pc   = tb.fall_through;
    ctx.pending_is_branch = tb.is_branch;
    ctx.pending_is_conditional = tb.is_conditional;

    /* Reset the chain projection; THIS entry's WP BBs stream next. */
    ctx.wp_chain.clear();

    ctx.cp_insns_so_far += bb.n_insns;
}

/* working_set: SLIDING-WINDOW unique cache lines and 4 KiB pages
 * touched within the last @ws_window CP instructions.  Each access
 * is timestamped at cp_insns_so_far; accesses older than the window
 * are retired from the live count when they fall off the back.  Per-
 * bin we record the live |set| sizes so the chart shows working-set
 * size over program phases (not a since-start cumulative footprint
 * — that would just trend upward forever). */
static void handle_working_set_bb(WalkCtx &ctx, const cst::BodyWalker::BB &bb)
{
    auto &ws = ctx.ws;
    int bin = bin_of(ctx, ctx.cp_insns_so_far);
    uint64_t now = ctx.cp_insns_so_far;
    uint64_t window = ctx.opts.ws_window;
    uint64_t cutoff = now > window ? now - window : 0;
    /* Retire accesses that have aged out of the window.  Each line /
     * page exits the live count when its last in-window reference
     * does — count reaches 0 → erase from map. */
    while (!ws.line_accesses.empty() &&
           ws.line_accesses.front().first < cutoff) {
        uint64_t line = ws.line_accesses.front().second;
        ws.line_accesses.pop_front();
        auto it = ws.line_count.find(line);
        if (it != ws.line_count.end() && --it->second == 0) {
            ws.line_count.erase(it);
        }
    }
    while (!ws.page_accesses.empty() &&
           ws.page_accesses.front().first < cutoff) {
        uint64_t page = ws.page_accesses.front().second;
        ws.page_accesses.pop_front();
        auto it = ws.page_count.find(page);
        if (it != ws.page_count.end() && --it->second == 0) {
            ws.page_count.erase(it);
        }
    }
    for_each_cp_memop(bb, [&](uint32_t, uint64_t addr) {
        uint64_t line = addr >> 6;
        uint64_t page = addr >> 12;
        ws.line_accesses.emplace_back(now, line);
        ws.page_accesses.emplace_back(now, page);
        ws.line_count[line]++;
        ws.page_count[page]++;
    });
    if ((int)ws.lines_per_bin.size() <= bin) {
        ws.lines_per_bin.resize(bin + 1, 0);
        ws.pages_per_bin.resize(bin + 1, 0);
    }
    ws.lines_per_bin[bin] = ws.line_count.size();
    ws.pages_per_bin[bin] = ws.page_count.size();
    ctx.cp_insns_so_far += bb.n_insns;
}

/* Shared between dep_depth and ilp: build the special-reg lookup
 * once from the trace's reg-name map.  Excludes FLAGS / IP / ZERO /
 * NONE so they neither carry nor break chains. */
static void df_ensure_excluded_built(WalkCtx &ctx)
{
    if (ctx.df.excluded_built) return;
    for (const auto &kv : ctx.h->maps.reg) {
        if (kv.first > 255) continue;
        if (reg_is_special_excluded(kv.second)) {
            ctx.df.excluded_reg[(size_t)kv.first] = true;
        }
    }
    ctx.df.excluded_built = true;
}

/* Gather instruction @i's dynamic load/store addresses into caller
 * buffers (each sized FID_SLOT_COUNT), returning the counts.  Mirrors
 * for_each_cp_memop's per-insn slot ordering + clamp.  Requires the BB
 * to carry field data (cp_fields). */
static inline void df_gather_addrs(const cst::BodyWalker::BB &bb, uint32_t i,
                                   uint64_t *la, uint32_t *nl,
                                   uint64_t *sa, uint32_t *ns)
{
    uint64_t cl = bb.load_count(i);
    if (cl > cst::FID_SLOT_COUNT) cl = cst::FID_SLOT_COUNT;
    for (uint32_t k = 0; k < cl; k++) la[k] = bb.load_addr(i, k);
    *nl = (uint32_t)cl;
    uint64_t cs = bb.store_count(i);
    if (cs > cst::FID_SLOT_COUNT) cs = cst::FID_SLOT_COUNT;
    for (uint32_t k = 0; k < cs; k++) sa[k] = bb.store_addr(i, k);
    *ns = (uint32_t)cs;
}

/* Wall-style RAW depth (register + memory) under perfect rename,
 * bounded to a tumbling --rob-size window:
 *   complete_i = 1 + max(producer_complete[r] for r in real srcs)
 *   producer_complete[r] := complete_i for r in real dsts
 * "Real" = NOT one of FLAGS / IP / ZERO / NONE.  Self-RMW IS a
 * real chain (rename removes only WAR/WAW; the RAW through the
 * arch reg survives).  When the chunk reaches window_size insns
 * we tally the just-completed window's IPC sample (for the ilp
 * metric) and clear producer state so the next chunk starts
 * with all sources cycle-0-ready.
 *
 * Returns the per-insn complete cycle (clamped to window).  Both
 * metrics consume it: dep_depth bins it; ilp also tracks the per-
 * chunk max for the IPC summary. */
static inline uint32_t df_step_insn(WalkCtx &ctx,
                                    const cst::InsnTemplate &insn,
                                    const uint64_t *load_addrs, uint32_t n_load,
                                    const uint64_t *store_addrs, uint32_t n_store,
                                    uint32_t window,
                                    int bin,
                                    bool record_ipc_samples)
{
    uint32_t max_src = 0;
    for (uint8_t r : insn.src_regs) {
        if (ctx.df.excluded_reg[r]) continue;
        auto it = ctx.df.producer_complete.find(r);
        if (it != ctx.df.producer_complete.end() && it->second > max_src) {
            max_src = it->second;
        }
    }
    /* Memory RAW: a load takes a dependency on the most recent store
     * to the same address in this window (read before the store side
     * below publishes, so a same-insn RMW sees the prior writer). */
    for (uint32_t k = 0; k < n_load; k++) {
        auto it = ctx.df.mem_producer_complete.find(load_addrs[k]);
        if (it != ctx.df.mem_producer_complete.end() && it->second > max_src) {
            max_src = it->second;
        }
    }
    uint32_t this_complete = max_src + 1;
    if (this_complete > window) this_complete = window;
    for (uint8_t r : insn.dst_regs) {
        if (ctx.df.excluded_reg[r]) continue;
        ctx.df.producer_complete[r] = this_complete;
    }
    /* A store publishes its completion cycle for its address so a later
     * aliasing load in this window chains off it. */
    for (uint32_t k = 0; k < n_store; k++) {
        ctx.df.mem_producer_complete[store_addrs[k]] = this_complete;
    }
    if (this_complete > ctx.df.chunk_max_cycle) {
        ctx.df.chunk_max_cycle = this_complete;
    }
    ctx.df.chunk_insns++;
    if (ctx.df.chunk_insns >= window) {
        if (record_ipc_samples && ctx.df.chunk_max_cycle > 0) {
            /* Ideal IPC × 1000 in fixed-point: window insns retired
             * in chunk_max_cycle cycles assuming unlimited-width
             * issue.  An infinite-renamer / infinite-issue model
             * has no other bound, so this is the upper bound on
             * what better rename or wider issue could buy. */
            uint64_t ipc_x1000 =
                ((uint64_t)window * 1000) / ctx.df.chunk_max_cycle;
            if (ipc_x1000 > UINT32_MAX) ipc_x1000 = UINT32_MAX;
            if ((int)ctx.df.ilp_samples_per_bin.size() <= bin) {
                ctx.df.ilp_samples_per_bin.resize(bin + 1);
            }
            ctx.df.ilp_samples_per_bin[bin].push_back((uint32_t)ipc_x1000);
        }
        ctx.df.producer_complete.clear();
        ctx.df.mem_producer_complete.clear();
        ctx.df.chunk_insns = 0;
        ctx.df.chunk_max_cycle = 0;
    }
    return this_complete;
}

/* dep_depth: per-insn RAW chain depth (register + memory),
 * histogrammed per bin.  Same dataflow model as ilp (Wall's ideal
 * rename, tumbling --rob-size window) but the chart summarizes the
 * *distribution* of per-insn depths (avg + p90) rather than the
 * per-chunk critical path.  Useful for seeing how many insns are stuck
 * deep in chains vs. how many start fresh chains each cycle. */
static void handle_dep_depth_bb(WalkCtx &ctx, const cst::BodyWalker::BB &bb)
{
    df_ensure_excluded_built(ctx);
    const cst::Template &t = *bb.tmpl;
    int bin = bin_of(ctx, ctx.cp_insns_so_far);
    uint32_t window = ctx.opts.rob_size;
    if ((int)ctx.df.dd_depth_hist_per_bin.size() <= bin) {
        ctx.df.dd_depth_hist_per_bin.resize(bin + 1);
    }
    auto &bin_hist = ctx.df.dd_depth_hist_per_bin[bin];
    if (bin_hist.empty()) {
        bin_hist.assign((size_t)window + 1, 0);
    }
    uint64_t la[cst::FID_SLOT_COUNT], sa[cst::FID_SLOT_COUNT];
    for (uint32_t i = 0; i < bb.n_insns; i++) {
        uint32_t nl, ns;
        df_gather_addrs(bb, i, la, &nl, sa, &ns);
        uint32_t d = df_step_insn(ctx, t.insns[i], la, nl, sa, ns,
                                  window, bin, /*record_ipc_samples=*/false);
        bin_hist[d]++;
    }
    ctx.cp_insns_so_far += bb.n_insns;
}

/* ilp: ideal IPC under perfect rename.  Drives the same Wall
 * dataflow walk as dep_depth but summarizes each chunk by
 *   ipc = window / max_complete_cycle_in_chunk
 * and emits a global issue-cycle histogram showing how many
 * insns issue at each in-window cycle (cycle 0 = no deps in
 * chunk, ...).  Top pane is the per-bin IPC time-series;
 * bottom pane is the issue-cycle distribution. */
static void handle_ilp_bb(WalkCtx &ctx, const cst::BodyWalker::BB &bb)
{
    df_ensure_excluded_built(ctx);
    const cst::Template &t = *bb.tmpl;
    int bin = bin_of(ctx, ctx.cp_insns_so_far);
    uint32_t window = ctx.opts.rob_size;
    if (ctx.df.ilp_cycle_hist.empty()) {
        ctx.df.ilp_cycle_hist.assign((size_t)window + 1, 0);
    }
    uint64_t la[cst::FID_SLOT_COUNT], sa[cst::FID_SLOT_COUNT];
    for (uint32_t i = 0; i < bb.n_insns; i++) {
        uint32_t nl, ns;
        df_gather_addrs(bb, i, la, &nl, sa, &ns);
        uint32_t complete = df_step_insn(ctx, t.insns[i], la, nl, sa, ns,
                                         window, bin,
                                         /*record_ipc_samples=*/true);
        /* Issue cycle is one less than complete (1-cycle latency
         * model).  cycle_hist[k] = insns that issued at in-chunk
         * cycle k across the whole trace. */
        uint32_t issue_cycle = complete - 1;
        if (issue_cycle >= ctx.df.ilp_cycle_hist.size()) {
            issue_cycle = (uint32_t)ctx.df.ilp_cycle_hist.size() - 1;
        }
        ctx.df.ilp_cycle_hist[issue_cycle]++;
    }
    ctx.cp_insns_so_far += bb.n_insns;
}

/* reuse_distance: for each CP memop's cache line, count how many
 * unique lines were accessed since this line was last seen (LRU
 * stack distance).  Bucket the distance log2 and tally into a
 * histogram.  First-access lines go to a separate "cold" bucket.
 *
 * Backed by an order-statistic tree keyed by a monotonic access-time
 * counter: each line's last access time is one entry; stack distance
 * is the count of entries with larger keys.  Both order_of_key and
 * erase/insert are O(log N), so per-memop cost is O(log working_set)
 * — a dramatic improvement over the prior std::list scan whose
 * std::distance was O(working_set). */
static constexpr int RU_BUCKETS = 24;  /* covers distance up to ~16M */
static int ru_bucket_of(uint64_t distance) {
    if (distance == 0) return 0;
    int b = 0;
    uint64_t v = distance;
    while (v > 0) { b++; v >>= 1; }
    if (b >= RU_BUCKETS) b = RU_BUCKETS - 1;
    return b;
}
static void handle_reuse_distance_bb(WalkCtx &ctx,
                                     const cst::BodyWalker::BB &bb)
{
    auto &ru = ctx.ru;
    for_each_cp_memop(bb, [&](uint32_t, uint64_t addr) {
        uint64_t line = addr >> 6;
        uint64_t t_new = ++ru.clock;
        auto it = ru.last_t.find(line);
        if (it == ru.last_t.end()) {
            ru.cold++;
            ru.last_t.emplace(line, t_new);
        } else {
            uint64_t t_prev = it->second;
            /* order_of_key(t_prev) = #entries with key < t_prev
             * (older accesses, lower in the LRU stack).  Stack
             * distance = entries strictly above L = size minus the
             * below count minus 1 for L's own entry. */
            size_t below = ru.tree.order_of_key(t_prev);
            size_t distance = ru.tree.size() - below - 1;
            int b = ru_bucket_of(distance);
            if (b >= (int)ru.hist.size()) {
                ru.hist.resize(b + 1, 0);
            }
            ru.hist[b]++;
            ru.tree.erase(t_prev);
            it->second = t_new;
        }
        ru.tree.insert(t_new);
    });
    ctx.cp_insns_so_far += bb.n_insns;
}

static void handle_genop_bb(WalkCtx &ctx, const cst::BodyWalker::BB &bb)
{
    int bin = bin_of(ctx, ctx.cp_insns_so_far);
    const auto &precomp = ctx.precomp[bb.template_index];
    for (const auto &p : precomp.series_increments) {
        ctx.bins.at(p.first, bin) += p.second;
    }
    ctx.cp_insns_so_far += bb.n_insns;
}

/* wp_divergence: for each CP branch's WP chain, how many WP
 * INSTRUCTIONS does a real-hardware predictor (BP + BTB) follow
 * before its predicted next-PC stops matching the recorded WP
 * chain?  Reported in instructions (not BB edges) so the chart
 * reads directly against a configured --wpdepth: a curve that
 * plateaus at insn 60 tells you a wpdepth >> 60 is wasted.
 *
 * Uses a single BP variant (largest --history) and a single BTB
 * (largest --btb-entries); sensitivity to those parameters is left
 * to the dedicated branch_mpki / btb_miss metrics.
 */
/* Process one CP entry's accumulated WP chain at its last WP BB:
 * pairwise edge-follow depth into wp_depth_per_bin[pending_bin].  The
 * batch handler ran this at the CP entry (step 3), AFTER training the
 * previous CP branch (step 1); in the stream the equivalent point is
 * the chain's last WP BB, which lands after this entry's CP BB and
 * before the next — preserving the predictors[0]/btbs[0] mutation
 * order exactly. */
static void wp_divergence_process_chain(WalkCtx &ctx)
{
    if (ctx.wp_chain.size() < 2) return;

    uint32_t matched_insns = ctx.wp_chain[0].n_insns;
    bool diverged = false;
    for (size_t i = 0; i + 1 < ctx.wp_chain.size(); i++) {
        const auto &cur_wp  = ctx.wp_chain[i];
        const auto &next_wp = ctx.wp_chain[i + 1];
        if (cur_wp.tidx == 0xFFFFFFFFu) break;
        if (next_wp.tidx == 0xFFFFFFFFu) break;
        const WalkCtx::TermBranch &wtb = ctx.term[cur_wp.tidx];
        if (!wtb.is_branch) break;
        uint64_t actual_target = next_wp.start_pc;
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
            matched_insns += next_wp.n_insns;
        } else {
            diverged = true;
        }
        g.update(wtb.pc, wp_taken);
        b.access(wtb.pc, actual_target);
        if (diverged) break;
    }

    int bin = (int)ctx.pending_bin;
    if ((int)ctx.wp_depth_per_bin.size() <= bin) {
        ctx.wp_depth_per_bin.resize(bin + 1);
    }
    auto &bin_hist = ctx.wp_depth_per_bin[bin];
    size_t d = (size_t)matched_insns;
    if (bin_hist.size() <= d) {
        bin_hist.resize(d + 1, 0);
    }
    bin_hist[d]++;
}

static void handle_wp_divergence_bb(WalkCtx &ctx, const cst::BodyWalker::BB &bb)
{
    if (bb.is_wp) {
        wp_chain_push(ctx, bb);
        if (bb.wp_chain_last) wp_divergence_process_chain(ctx);
        return;
    }
    const cst::Template &t = *bb.tmpl;
    int bin = bin_of(ctx, ctx.cp_insns_so_far);

    /* Train predictors / BTB on the previous CP branch, before
     * stepping the WP chain. */
    if (ctx.have_pending && ctx.pending_is_branch) {
        bool taken = (t.start_pc != ctx.pending_fall_pc);
        for (auto &g : ctx.predictors) g.update(ctx.pending_branch_pc, taken);
        for (auto &b : ctx.btbs)       b.access(ctx.pending_branch_pc, t.start_pc);
    }
    const WalkCtx::TermBranch &tb = ctx.term[bb.template_index];
    ctx.have_pending      = true;
    ctx.pending_bin       = (uint64_t)bin;
    ctx.pending_branch_pc = tb.pc;
    ctx.pending_fall_pc   = tb.fall_through;
    ctx.pending_is_branch = tb.is_branch;

    /* Reset the chain projection; THIS entry's WP BBs stream next and
     * are processed at the chain's last BB. */
    ctx.wp_chain.clear();

    ctx.cp_insns_so_far += bb.n_insns;
}

/* gen_reg uses the same shape as genop — precomputed per-template
 * series increments. */
static void handle_genreg_bb(WalkCtx &ctx, const cst::BodyWalker::BB &bb)
{
    handle_genop_bb(ctx, bb);   /* same precomp shape */
}

/* ===================================================================
 *                            Main driver
 * =================================================================== */

/* The finished, render-ready result of processing one trace.  Aggregate
 * mode collects one of these per input (compact: just the built plans +
 * a little metadata) and combines them, so only one trace's heavy decode
 * state is ever live at a time. */
struct TraceResult {
    ChartPlan   plan, plan2;
    bool        has_second_pane = false;
    double      weight          = 0.0;        /* header simpoint_weight   */
    uint64_t    start_insn      = 0;          /* program-order sort key   */
    uint64_t    warmup_end_insns = UINT64_MAX;/* header §2.13             */
    uint64_t    total_insns     = 0;          /* x-axis span (CP insns)   */
    std::string label;                        /* short trace name         */
};

/* Lightweight header-only view of a trace, gathered in a pre-pass so we
 * can size each trace's bin count by its (normalised) weight before the
 * full decode — no body walk, so it's cheap. */
struct TraceMeta {
    double   weight     = 0.0;
    uint64_t start_insn = 0;
    uint64_t warmup_end = UINT64_MAX;
    uint64_t total_insns = 1;
    bool     ok         = false;
};

static TraceResult process_trace(const char *path, const Options &opts);
static TraceResult aggregate_results(std::vector<TraceResult> &rs,
                                     const Options &opts);
static TraceMeta   peek_trace_meta(const char *path);

/* Derive a short human label for a trace from its file path: basename with
 * any ".cst" suffix and a common "<prog>_(cp|full)-" prefix stripped, so a
 * file like ".../mcf_full-545_2B.cst" labels as "545_2B". */
static std::string short_trace_label(const char *path)
{
    std::string s = path;
    size_t slash = s.find_last_of('/');
    if (slash != std::string::npos) s = s.substr(slash + 1);
    if (s.size() > 4 && s.substr(s.size() - 4) == ".cst") {
        s = s.substr(0, s.size() - 4);
    }
    size_t dash = s.find('-');
    if (dash != std::string::npos) s = s.substr(dash + 1);
    return s;
}

/* Lay out a finished TraceResult into the SVG and render it.  Shared by the
 * single-trace and aggregate paths; the plans are already fully built (the
 * dual-pane axis finalisation happened upstream). */
static int render_result(const TraceResult &tr, const Options &opts)
{
    std::FILE *out = stdout;
    if (opts.output) {
        out = std::fopen(opts.output, "wb");
        if (!out) {
            std::fprintf(stderr, "cst_visualize: cannot open '%s'\n",
                         opts.output);
            return 1;
        }
    }
    ChartPlan plan  = tr.plan;
    ChartPlan plan2 = tr.plan2;
    if (tr.has_second_pane) {
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

int main(int argc, char **argv)
{
    Options opts = parse_args(argc, argv);
    bool aggregate = opts.aggregate || opts.inputs.size() > 1;

    if (!aggregate) {
        try {
            TraceResult tr = process_trace(opts.inputs[0], opts);
            return render_result(tr, opts);
        } catch (const std::exception &ex) {
            std::fprintf(stderr, "cst_visualize: %s: %s\n",
                         opts.inputs[0], ex.what());
            return 1;
        }
    }

    /* Aggregate mode.
     *
     * Pass 1 (cheap, header-only): peek every trace's weight + warmup
     * boundary.  A trace's NORMALISED weight (hence its segment width) is
     * only knowable once all headers are read, so this can't be folded
     * into the decode.
     *
     * Then size each trace's bin count by its weight, so the rendered
     * data-point density is uniform across the montage: a wide (high-
     * weight) segment is decoded at higher resolution and a narrow one at
     * lower, instead of every trace getting the same bins stretched to
     * different widths (which made wide segments look blocky).  The target
     * is ~DISPLAY_BUDGET post-warmup points spread across the montage by
     * weight; we divide by the simulation fraction because only the
     * post-warmup region is plotted.
     *
     * Pass 2: decode traces ONE AT A TIME (peak memory ~ one trace's
     * working set), keeping only the compact TraceResults. */
    const size_t N = opts.inputs.size();
    std::vector<TraceMeta> metas(N);
    for (size_t i = 0; i < N; i++) {
        try { metas[i] = peek_trace_meta(opts.inputs[i]); metas[i].ok = true; }
        catch (const std::exception &ex) {
            std::fprintf(stderr, "cst_visualize: skipping %s: %s\n",
                         opts.inputs[i], ex.what());
        }
    }
    /* Effective (un-normalised) weights, then normalise over OK traces. */
    std::vector<double> wraw(N, 0.0);
    double wsum = 0.0;
    int nok = 0;
    for (size_t i = 0; i < N; i++) {
        if (!metas[i].ok) continue;
        wraw[i] = !opts.weights.empty() ? opts.weights[i] : metas[i].weight;
        wsum += wraw[i];
        nok++;
    }
    if (nok == 0) {
        std::fprintf(stderr, "cst_visualize: no traces processed\n");
        return 1;
    }
    std::vector<double> wnorm(N, 0.0);
    for (size_t i = 0; i < N; i++) {
        if (!metas[i].ok) continue;
        wnorm[i] = (wsum > 0.0) ? wraw[i] / wsum : 1.0 / (double)nok;
    }

    const double DISPLAY_BUDGET = 1000.0;  /* post-warmup points / montage */
    std::vector<TraceResult> rs;
    rs.reserve(N);
    for (size_t i = 0; i < N; i++) {
        if (!metas[i].ok) continue;
        double sim_frac = 1.0;
        if (metas[i].warmup_end != UINT64_MAX && metas[i].total_insns > 0) {
            double wf = (double)metas[i].warmup_end /
                        (double)metas[i].total_insns;
            sim_frac = 1.0 - wf;
            if (sim_frac < 0.05) sim_frac = 0.05;   /* avoid blow-up */
        }
        int bins_i = (int)std::ceil(DISPLAY_BUDGET * wnorm[i] / sim_frac);
        if (bins_i < 40)   bins_i = 40;
        if (bins_i > 6000) bins_i = 6000;
        Options o = opts;
        o.bins = bins_i;
        try {
            TraceResult t = process_trace(opts.inputs[i], o);
            t.weight = wraw[i];          /* carry the effective weight */
            rs.push_back(std::move(t));
        } catch (const std::exception &ex) {
            std::fprintf(stderr, "cst_visualize: skipping %s: %s\n",
                         opts.inputs[i], ex.what());
        }
    }
    if (rs.empty()) {
        std::fprintf(stderr, "cst_visualize: no traces processed\n");
        return 1;
    }
    TraceResult agg = aggregate_results(rs, opts);
    return render_result(agg, opts);
}

/*
 * Per-metric state setup, run once before the body walk: pre-register
 * the breakdown series in a stable order and allocate the predictors /
 * BTBs / caches the chosen metric needs.  Pulled out of process_trace so
 * that 1300-line function reads as setup -> walk -> finalize; the label
 * registration order here is load-bearing (see the branch_dir note) and
 * is preserved verbatim.
 */
static void build_metric_state(WalkCtx &ctx,
                               const std::vector<cst::Template> &templates,
                               const cst::Header &h)
{
    const Options &opts = ctx.opts;

    /* branch_dir: pre-register the direction-breakdown series in a
     * canonical, trace-independent order BEFORE the walk.  The handler
     * otherwise allocates a series the first time each (class,
     * direction) is resolved — and because the CP and WP panes share
     * one label set, a trace that carries WP chains discovers classes
     * in a different order than a CP-only trace of the same region.
     * That made the SAME class land on a DIFFERENT series/colour across
     * the two plots, so the (identical) correct-path breakdowns looked
     * completely different.  Keying registration on the branch_type
     * code (a fixed format enum value, identical across traces) pins
     * each class to a stable colour.  Conditional classes get a
     * taken/not-taken pair; every other family is always-taken and gets
     * a single bare-name series.  A code that appears both ways (rare;
     * name-vs-flag disagreement in classify_term) registers all
     * variants so the runtime never has to append out of order. */
    if (opts.metric == Metric::BranchDir) {
        struct ClassVariants {
            std::string class_name;
            bool any_conditional   = false;
            bool any_unconditional = false;
        };
        std::map<uint64_t, ClassVariants> by_code;
        for (size_t i = 0; i < templates.size(); i++) {
            const WalkCtx::TermBranch &tb = ctx.term[i];
            if (!tb.is_branch || templates[i].insns.empty()) continue;
            const cst::InsnTemplate *brins = find_term_branch(templates[i]);
            if (!brins) continue;
            uint64_t code = brins->branch_type;
            ClassVariants &cv = by_code[code];
            cv.class_name = tb.class_name;
            if (tb.is_conditional) cv.any_conditional = true;
            else                   cv.any_unconditional = true;
        }
        for (const auto &kv : by_code) {
            const ClassVariants &cv = kv.second;
            if (cv.any_conditional) {
                ctx.add_label(cv.class_name + " taken");
                ctx.add_label(cv.class_name + " not-taken");
            }
            if (cv.any_unconditional) {
                ctx.add_label(cv.class_name);
            }
        }
    }

    /* Build per-template series increments for the metrics that use
     * them.  Done up-front so the per-entry hot path is just one
     * matrix update per (series, bin). */
    if (opts.metric == Metric::GenOp || opts.metric == Metric::GenReg) {
        /* gen_reg drops architectural side-effect regs (IP/PC/FLAGS/
         * ZERO/NONE) from the histogram — they appear on virtually
         * every insn and would otherwise drown out the named GPR /
         * FPR / VEC traffic that the chart is supposed to surface.
         * SP/FP and other normal regs are kept.  Build the mask once
         * by id so the per-insn loop is just an array lookup. */
        std::array<bool, 256> reg_excluded{};
        if (opts.metric == Metric::GenReg) {
            for (const auto &kv : h.maps.reg) {
                if (kv.first > 255) continue;
                if (reg_is_special_excluded(kv.second)) {
                    reg_excluded[(size_t)kv.first] = true;
                }
            }
        }

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
                        if (reg_excluded[r]) continue;
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
                     * one to each).  Architectural side-effect regs
                     * are excluded; an insn whose only dst is one of
                     * those (e.g. a flag-only update) contributes
                     * nothing to gen_reg. */
                    for (uint8_t r : ins.dst_regs) {
                        if (reg_excluded[r]) continue;
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

    /* Size the WP-gate BTB from --btb-entries (use the largest
     * configured size) so non-conditional WP pollution is gated by a
     * realistic target predictor.  Falls back to the WalkCtx default
     * (1024) if --btb-entries was not specified. */
    {
        int gate_size = 0;
        for (int n : opts.btb_entries) if (n > gate_size) gate_size = n;
        if (gate_size > 0) ctx.bp_btb_gate = BTB(gate_size);
    }
}

/*
 * Build the TraceResult (chart plan + optional second pane + metadata)
 * from the walked WalkCtx state.  Split out of process_trace so that
 * function reads as parse -> build_metric_state -> walk -> finalize; this
 * holds the per-metric plan-construction ladders (title/axis/series), the
 * dual-pane assembly, and the header-only static-summary metrics.
 */
/* Chart title for a metric (or the user's --title override).  Depends only
 * on Options, so it lives outside finalize_metric instead of as an inline
 * 80-line lambda in the middle of the per-metric build. */
static std::string title_for(const Options &opts)
{
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
            return "WP chain insns followed before BP+BTB diverges from trace's recorded WP";
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
        case Metric::BbLength:
            return "Basic-block length distribution";
        case Metric::IndirectTargets:
            return "Indirect-branch target diversity";
        case Metric::BranchEntropy:
            return "Conditional-branch direction entropy";
        case Metric::WorkingSet: {
            /* Title spells out the sliding-window bound — the curve is the
             * working-set size over the last @ws_window insns, NOT the
             * cumulative footprint since program start. */
            char buf[128];
            uint64_t w = opts.ws_window;
            if (w >= 1000000 && w % 1000000 == 0) {
                std::snprintf(buf, sizeof(buf),
                    "Working set (sliding window: %luM insns)",
                    (unsigned long)(w / 1000000));
            } else if (w >= 1000 && w % 1000 == 0) {
                std::snprintf(buf, sizeof(buf),
                    "Working set (sliding window: %luK insns)",
                    (unsigned long)(w / 1000));
            } else {
                std::snprintf(buf, sizeof(buf),
                    "Working set (sliding window: %lu insns)",
                    (unsigned long)w);
            }
            return std::string(buf);
        }
        case Metric::DepDepth: {
            char b[96];
            std::snprintf(b, sizeof(b),
                "Dependency-chain depth (Wall ideal-rename, window=%u)",
                (unsigned)opts.rob_size);
            return std::string(b);
        }
        case Metric::Ilp: {
            char b[96];
            std::snprintf(b, sizeof(b),
                "Ideal IPC under perfect rename (window=%u)",
                (unsigned)opts.rob_size);
            return std::string(b);
        }
        case Metric::ReuseDistance:
            return "Memory reuse-distance histogram";
    }
    return "";
}

static TraceResult finalize_metric(const char *path, WalkCtx &ctx,
                                   const std::vector<cst::Template> &templates,
                                   const cst::Header &h,
                                   uint64_t total_cp_insns)
{
    const Options &opts = ctx.opts;
    const uint64_t bin_width = ctx.bin_width;

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
    /* Trace-encoded warmup boundary (header §2.13, arch CP insns).
     * render_plan() draws it as a dashed marker on instruction-window
     * axes and ignores it on the bin-indexed / static-summary panes. */
    plan.warmup_end_insns = h.warmup_end_arch_insns;

    auto pick_title = [&]{ return title_for(opts); };
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
             * predictor.  INDEPENDENT y-scales: this metric is
             * non-normalized (mispredictions per 1k), and the polluted
             * pane's magnitude is routinely many times the CP-only
             * pane's, so a shared scale flattens the CP-only curve into a
             * single line and hides its behavior.  Each pane keeps the
             * own y_max build_lines_plan computed from its own data; both
             * panes' axes are labeled and ticked from their own y_max, so
             * each is legible on its own scale.  (The rate / percent
             * dual-pane metrics below stay shared, where the cross-pane
             * value comparison is the point.) */
            build_lines_plan(plan, ctx.bins, opts.histories,
                             per_kilo, "Mispredictions per 1k CP", false);
            build_lines_plan(plan2, ctx.bins_wp, opts.histories,
                             per_kilo, "Mispredictions per 1k CP", false);
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
            plan.y_label = "WP chain match depth (insns)";
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
                /* Compute min / max / median / mean directly from
                 * the per-bin depth histogram.  Index = depth, value
                 * = count. */
                const auto &hist = ctx.wp_depth_per_bin[b];
                uint64_t total = 0, sum = 0;
                int mn = -1, mx = -1;
                for (size_t d = 0; d < hist.size(); d++) {
                    if (hist[d] == 0) continue;
                    if (mn < 0) mn = (int)d;
                    mx = (int)d;
                    total += hist[d];
                    sum   += hist[d] * (uint64_t)d;
                }
                if (total == 0) continue;
                uint64_t mid = total / 2;
                uint64_t cum = 0;
                int median = mn;
                for (size_t d = 0; d < hist.size(); d++) {
                    cum += hist[d];
                    if (cum > mid) { median = (int)d; break; }
                }
                double mean = (double)sum / (double)total;
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
                /* Colour by series position so the most-distinct palette
                 * colours land on the most important categories first.
                 * These metrics register their series in a meaningful
                 * order — gen_op / gen_reg by descending frequency,
                 * mem_pat in a fixed none/regular/irregular/random order
                 * — so position 0 is the dominant category and gets the
                 * vivid head of the palette.  Both panes share one label
                 * set, so a category keeps its colour across CP/WP.
                 * branch_dir instead pins each class to a fixed slot by
                 * name (branch_dir_color), which is stable regardless of
                 * order. */
                const bool is_branch_dir = (opts.metric == Metric::BranchDir);
                for (int s = 0; s < S; s++) {
                    p.series[s].label = ctx.label_names[s];
                    p.series[s].color = is_branch_dir
                        ? branch_dir_color(ctx.label_names[s])
                        : palette_color((size_t)s);
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
        case Metric::BbLength:
        case Metric::IndirectTargets:
        case Metric::BranchEntropy: {
            /* Header-derived histograms.  Dual-pane: top is one count
             * per static template / branch, bottom weights each by
             * its CP execution count so rare-but-numerous static
             * templates don't dominate when only a few of them
             * actually run.  Both panes share the same x-axis. */
            std::vector<uint64_t> hist_static;
            std::vector<uint64_t> hist_dynamic;
            const char *x_lab = "";
            const char *y_lab_static = "";
            const char *y_lab_dynamic = "";
            int max_x = 1;
            if (opts.metric == Metric::BbLength) {
                for (const auto &t : templates) {
                    int L = (int)t.insns.size();
                    if (L > max_x) max_x = L;
                }
                hist_static.assign((size_t)max_x + 1, 0);
                hist_dynamic.assign((size_t)max_x + 1, 0);
                for (const auto &t : templates) {
                    int L = (int)t.insns.size();
                    if (L < 0 || L > max_x) continue;
                    hist_static[(size_t)L] += 1;
                    hist_dynamic[(size_t)L] += t.profile.exec_cp;
                }
                x_lab = "Basic-block length (insns)";
                y_lab_static = "basic blocks";
                y_lab_dynamic = "basic-block executions";
            } else if (opts.metric == Metric::IndirectTargets) {
                /* Only CP-observed indirect / return branches.  WP-only
                 * BBs (exec_cp == 0) have target_pcs empty by
                 * construction and would create a spurious 0-targets
                 * bar.  Syscalls classify as "indirect" but their next
                 * BB lives in kernel space and is never linked into
                 * target_pcs — skip them so the metric reflects what a
                 * user-space branch predictor actually sees. */
                auto include = [&](size_t i) {
                    if (!ctx.term[i].is_branch ||
                        !ctx.term[i].is_indirect_class) return false;
                    if (templates[i].profile.exec_cp == 0) return false;
                    const std::string &cn = ctx.term[i].class_name;
                    if (cn.find("SYSCALL") != std::string::npos) return false;
                    return true;
                };
                for (size_t i = 0; i < templates.size(); i++) {
                    if (!include(i)) continue;
                    int n = (int)templates[i].target_pcs.size();
                    if (n > max_x) max_x = n;
                }
                hist_static.assign((size_t)max_x + 1, 0);
                hist_dynamic.assign((size_t)max_x + 1, 0);
                for (size_t i = 0; i < templates.size(); i++) {
                    if (!include(i)) continue;
                    int n = (int)templates[i].target_pcs.size();
                    if (n < 0 || n > max_x) continue;
                    hist_static[(size_t)n] += 1;
                    hist_dynamic[(size_t)n] += templates[i].profile.exec_cp;
                }
                x_lab = "Distinct targets observed";
                y_lab_static = "indirect / return branches";
                y_lab_dynamic = "indirect / return executions";
            } else { /* BranchEntropy */
                /* 101 bins: bucket b covers entropy in [b/100,
                 * (b+1)/100).  The terminal bucket (b=100) catches
                 * H == 1.0 exactly.  Dynamic-weight uses the per-
                 * branch (taken_cp + nottaken_cp) — exactly the
                 * executions whose direction the predictor would
                 * have to call. */
                max_x = 100;
                hist_static.assign(101, 0);
                hist_dynamic.assign(101, 0);
                for (size_t i = 0; i < templates.size(); i++) {
                    if (!ctx.term[i].is_branch ||
                        !ctx.term[i].is_conditional) continue;
                    const auto &prof = templates[i].profile;
                    if (prof.targets.empty()) continue;
                    uint64_t taken = prof.targets[0].taken_cp;
                    uint64_t nott  = prof.targets[0].nottaken_cp;
                    uint64_t total = taken + nott;
                    if (total == 0) continue;
                    double pr = (double)taken / (double)total;
                    double e = 0.0;
                    if (pr > 0.0 && pr < 1.0) {
                        e = -pr * std::log2(pr)
                            - (1.0 - pr) * std::log2(1.0 - pr);
                    }
                    int bucket = (int)(e * 100.0);
                    if (bucket < 0) bucket = 0;
                    if (bucket > 100) bucket = 100;
                    hist_static[(size_t)bucket]  += 1;
                    hist_dynamic[(size_t)bucket] += total;
                }
                x_lab = "Direction entropy";
                y_lab_static = "conditional branches";
                y_lab_dynamic = "conditional-branch executions";
            }

            /* Tail-clip: long sparse right-tails make the x-axis
             * unreadable (BB length in particular has the occasional
             * outlier in the thousands).  Fold the rightmost bins
             * whose CUMULATIVE share is under hist_tail_pct percent
             * into a single ">N" overflow bin.  Skip for the entropy
             * histogram (0-100% is semantically bounded — each
             * bucket represents a specific entropy level that you
             * lose if you fold) and for indirect_targets (already
             * bounded by BRANCH_TARGET_HISTORY). */
            int clip_idx = (int)hist_static.size() - 1;
            if (opts.metric == Metric::BbLength
                && opts.hist_tail_pct > 0.0
                && !hist_static.empty()) {
                auto clip_one = [&](const std::vector<uint64_t> &h) -> int {
                    uint64_t total = 0;
                    for (auto v : h) total += v;
                    if (total == 0) return (int)h.size() - 1;
                    uint64_t thresh =
                        (uint64_t)((double)total
                                   * (1.0 - opts.hist_tail_pct / 100.0));
                    uint64_t cum = 0;
                    for (size_t i = 0; i < h.size(); i++) {
                        cum += h[i];
                        if (cum >= thresh) return (int)i;
                    }
                    return (int)h.size() - 1;
                };
                /* Take the WIDER of the two panes' clips so both
                 * panes' tails are preserved up to whichever pane
                 * needs more. */
                int c = std::max(clip_one(hist_static),
                                 clip_one(hist_dynamic));
                if (c + 2 < (int)hist_static.size()) {
                    auto fold = [&](std::vector<uint64_t> &h) {
                        uint64_t over = 0;
                        for (int i = c + 1; i < (int)h.size(); i++) {
                            over += h[i];
                        }
                        h.resize(c + 2);
                        h[c + 1] = over;
                    };
                    fold(hist_static);
                    fold(hist_dynamic);
                    clip_idx = c;
                }
            }

            auto fill_plan = [&](ChartPlan &p,
                                 const std::vector<uint64_t> &h,
                                 const char *y_lab) {
                p.mode = ChartPlan::Mode::Bars;
                p.n_bins = (int)h.size();
                p.x_bin_size = 1;
                p.x_label = x_lab;
                p.y_label = y_lab;
                p.warmup_bins = 0;
                p.percent = false;
                p.y_is_count = true;
                p.series.resize(1);
                p.series[0].label = "";
                p.series[0].color = palette_color(0);
                p.series[0].y.assign(h.size(), 0.0);
                uint64_t y_peak = 0;
                for (size_t b = 0; b < h.size(); b++) {
                    p.series[0].y[b] = (double)h[b];
                    if (h[b] > y_peak) y_peak = h[b];
                }
                p.y_max = (y_peak > 0) ? (double)y_peak * 1.1 : 1.0;
                if (opts.metric == Metric::BranchEntropy) {
                    p.x_unit_suffix = "%";
                }
                /* If a tail was folded above, mark the rightmost bin
                 * as an overflow so the tick reads ">N" instead of
                 * just "N". */
                if (opts.metric == Metric::BbLength
                    && clip_idx + 2 == p.n_bins) {
                    char buf[32];
                    std::snprintf(buf, sizeof(buf), ">%d", clip_idx);
                    p.has_overflow_bin = true;
                    p.overflow_label   = buf;
                }
                /* Single-series histograms have no legend — reclaim
                 * the legend margin so the chart fills the canvas. */
                p.margin_right = 40;
            };
            fill_plan(plan,  hist_static,  y_lab_static);
            fill_plan(plan2, hist_dynamic, y_lab_dynamic);
            plan.title  = std::string(pick_title()) + " (static)";
            plan2.title = std::string(pick_title()) + " (execution-weighted)";
            has_second_pane = true;
            break;
        }
        case Metric::WorkingSet: {
            /* Two lines (cache lines + 4 KiB pages) over the CP
             * instruction window.  Y values are cumulative — strictly
             * non-decreasing — so the curve shows the workload
             * exiting / entering its memory working set. */
            plan.mode = ChartPlan::Mode::Lines;
            plan.y_label = "unique addresses touched";
            plan.y_is_count = true;
            plan.series.resize(2);
            plan.series[0].label = "cache lines (64B)";
            plan.series[0].color = palette_color(0);
            plan.series[1].label = "pages (4 KiB)";
            plan.series[1].color = palette_color(1);
            plan.series[0].y.assign(actual_bins, 0.0);
            plan.series[1].y.assign(actual_bins, 0.0);
            uint64_t last_lines = 0, last_pages = 0, y_peak = 0;
            for (int b = 0; b < actual_bins; b++) {
                if (b < (int)ctx.ws.lines_per_bin.size()) {
                    last_lines = ctx.ws.lines_per_bin[b];
                }
                if (b < (int)ctx.ws.pages_per_bin.size()) {
                    last_pages = ctx.ws.pages_per_bin[b];
                }
                plan.series[0].y[b] = (double)last_lines;
                plan.series[1].y[b] = (double)last_pages;
                if (last_lines > y_peak) y_peak = last_lines;
            }
            plan.y_max = (y_peak > 0) ? (double)y_peak * 1.1 : 1.0;
            plan.warmup_bins = 0;
            break;
        }
        case Metric::Ilp: {
            /* Top pane: per-bin ideal IPC (avg + p90) from the
             * per-chunk samples emitted by df_step_insn.  Bottom
             * pane: global issue-cycle histogram aggregating
             * every insn's in-chunk issue cycle across all
             * tumbling windows.  The two panes describe the same
             * dataflow walk from different angles: the time
             * series tells you HOW MUCH parallelism is available
             * over the trace; the histogram tells you WHERE in
             * the chunk that parallelism sits (heavy bar at
             * cycle 0 = many no-dep "fresh chain starts"; long
             * tail = critical path dominated by a few serialized
             * chains). */
            plan.mode = ChartPlan::Mode::Lines;
            plan.y_label = "ideal IPC (window/critical-path)";
            plan.series.resize(2);
            plan.series[0].label = "avg";
            plan.series[0].color = palette_color(0);
            plan.series[1].label = "p90";
            plan.series[1].color = palette_color(1);
            plan.series[0].y.assign(actual_bins, 0.0);
            plan.series[1].y.assign(actual_bins, 0.0);
            double y_peak = 0;
            std::vector<uint32_t> sorted_scratch;
            for (int b = 0; b < actual_bins; b++) {
                if (b >= (int)ctx.df.ilp_samples_per_bin.size()) continue;
                const auto &samples = ctx.df.ilp_samples_per_bin[b];
                if (samples.empty()) continue;
                uint64_t sum = 0;
                for (uint32_t v : samples) sum += v;
                double avg = (double)sum / (double)samples.size() / 1000.0;
                sorted_scratch.assign(samples.begin(), samples.end());
                std::sort(sorted_scratch.begin(), sorted_scratch.end());
                size_t p90_idx = (size_t)((double)sorted_scratch.size() * 0.9);
                if (p90_idx >= sorted_scratch.size()) {
                    p90_idx = sorted_scratch.size() - 1;
                }
                double p90 = (double)sorted_scratch[p90_idx] / 1000.0;
                plan.series[0].y[b] = avg;
                plan.series[1].y[b] = p90;
                if (p90 > y_peak) y_peak = p90;
            }
            plan.y_max = (y_peak > 0) ? y_peak * 1.1 : 1.0;
            plan.warmup_bins = 0;

            /* Bottom pane: issue-cycle histogram.  Trim trailing zeros so
             * the x-axis isn't dominated by an empty tail (chunks typically
             * complete well before cycle = window). */
            size_t n_cycles = ctx.df.ilp_cycle_hist.size();
            while (n_cycles > 1 &&
                   ctx.df.ilp_cycle_hist[n_cycles - 1] == 0) {
                n_cycles--;
            }
            /* Then fold the sparse high-cycle tail into a ">N" overflow bin
             * (same hist_tail_pct rule as the other histograms) so a few
             * long chains don't stretch the axis into illegibility. */
            std::vector<uint64_t> cyc(ctx.df.ilp_cycle_hist.begin(),
                                      ctx.df.ilp_cycle_hist.begin()
                                          + (long)n_cycles);
            /* The issue-cycle distribution is latency-like — a long thin
             * tail of a few deep dependency chains — so the global 0.5%
             * fold (tuned for concentrated histograms like bb_length) barely
             * clips it and the axis sprawls.  Fold at least the top 2% (p98)
             * here so the informative low-cycle bulk stays legible; a larger
             * user --hist-tail-pct still wins. */
            int ilp_clip = -1;
            double ilp_tail = std::max(opts.hist_tail_pct, 2.0);
            if (ilp_tail > 0.0) {
                uint64_t total = 0;
                for (uint64_t v : cyc) total += v;
                if (total > 0) {
                    uint64_t thresh = (uint64_t)((double)total
                        * (1.0 - ilp_tail / 100.0));
                    uint64_t cum = 0;
                    int c = (int)cyc.size() - 1;
                    for (size_t i = 0; i < cyc.size(); i++) {
                        cum += cyc[i];
                        if (cum >= thresh) { c = (int)i; break; }
                    }
                    if (c + 2 < (int)cyc.size()) {
                        uint64_t over = 0;
                        for (int i = c + 1; i < (int)cyc.size(); i++) {
                            over += cyc[i];
                        }
                        cyc.resize(c + 2);
                        cyc[c + 1] = over;
                        ilp_clip = c;
                    }
                }
            }
            n_cycles = cyc.size();
            plan2.mode = ChartPlan::Mode::Bars;
            plan2.n_bins = (int)n_cycles;
            plan2.x_bin_size = 1;
            plan2.x_label = "in-window issue cycle";
            plan2.y_label = "insns issued (all chunks)";
            plan2.y_is_count = true;
            plan2.percent = false;
            plan2.warmup_bins = 0;
            plan2.series.resize(1);
            plan2.series[0].label = "";
            plan2.series[0].color = palette_color(0);
            plan2.series[0].y.assign(n_cycles, 0.0);
            uint64_t y_peak2 = 0;
            for (size_t c = 0; c < n_cycles; c++) {
                plan2.series[0].y[c] = (double)cyc[c];
                if (cyc[c] > y_peak2) y_peak2 = cyc[c];
            }
            plan2.y_max = (y_peak2 > 0) ? (double)y_peak2 * 1.1 : 1.0;
            if (ilp_clip >= 0) {
                char buf[32];
                std::snprintf(buf, sizeof(buf), ">%d", ilp_clip);
                plan2.has_overflow_bin = true;
                plan2.overflow_label   = buf;
            }
            plan2.margin_right = 40;
            plan.title  = pick_title() + " (per-bin IPC)";
            plan2.title = pick_title() + " (issue-cycle histogram)";
            has_second_pane = true;
            break;
        }
        case Metric::DepDepth: {
            /* Per-bin avg + p90 dep-chain depth.  Both lines on the
             * same axis (depth in cycles, if we treat each chain
             * link as one cycle of dependency).  No warmup overlay
             * — depth has no transient. */
            plan.mode = ChartPlan::Mode::Lines;
            plan.y_label = "dependency-chain depth";
            plan.y_is_count = true;
            plan.series.resize(2);
            plan.series[0].label = "avg";
            plan.series[0].color = palette_color(0);
            plan.series[1].label = "p90";
            plan.series[1].color = palette_color(1);
            plan.series[0].y.assign(actual_bins, 0.0);
            plan.series[1].y.assign(actual_bins, 0.0);
            double y_peak = 0;
            for (int b = 0; b < actual_bins; b++) {
                if (b >= (int)ctx.df.dd_depth_hist_per_bin.size()) continue;
                const auto &hist = ctx.df.dd_depth_hist_per_bin[b];
                if (hist.empty()) continue;
                /* Avg + p90 directly from the histogram — depths are
                 * the index, counts are the values. */
                uint64_t total = 0;
                uint64_t sum   = 0;
                for (size_t d = 0; d < hist.size(); d++) {
                    total += hist[d];
                    sum   += (uint64_t)d * hist[d];
                }
                if (total == 0) continue;
                double avg = (double)sum / (double)total;
                uint64_t cum = 0;
                uint64_t p90_thresh = (uint64_t)((double)total * 0.90);
                uint32_t p90 = 0;
                for (size_t d = 0; d < hist.size(); d++) {
                    cum += hist[d];
                    if (cum >= p90_thresh) { p90 = (uint32_t)d; break; }
                }
                plan.series[0].y[b] = avg;
                plan.series[1].y[b] = (double)p90;
                if (p90 > y_peak) y_peak = (double)p90;
            }
            plan.y_max = (y_peak > 0) ? y_peak * 1.1 : 1.0;
            plan.warmup_bins = 0;
            break;
        }
        case Metric::ReuseDistance: {
            /* Log-bucketed histogram: bucket b covers distance
             * [2^(b-1), 2^b - 1] (with bucket 0 = distance 0, which
             * doesn't happen since same-line back-to-back accesses
             * have distance 0 only on the SAME insn).  An additional
             * "cold" bar at the leftmost slot holds first-touch
             * accesses where no prior reference exists. */
            size_t n_buckets = ctx.ru.hist.size();
            if (n_buckets < (size_t)RU_BUCKETS) n_buckets = RU_BUCKETS;
            /* +1 leading slot for the cold bucket. */
            std::vector<uint64_t> h(n_buckets + 1, 0);
            h[0] = ctx.ru.cold;
            for (size_t b = 0; b < ctx.ru.hist.size(); b++) {
                h[b + 1] = ctx.ru.hist[b];
            }

            /* Tail-clip: log buckets at the high end are typically
             * tiny — fold them into an ">N" overflow at the right.
             * Apply the same hist_tail_pct rule as the linear
             * histograms.  Build the x-axis label list against the
             * post-clip bin layout below. */
            int clip_idx = (int)h.size() - 1; /* "no clip" sentinel */
            if (opts.hist_tail_pct > 0.0) {
                uint64_t total = 0;
                for (auto v : h) total += v;
                if (total > 0) {
                    uint64_t thresh = (uint64_t)((double)total
                        * (1.0 - opts.hist_tail_pct / 100.0));
                    uint64_t cum = 0;
                    int c = (int)h.size() - 1;
                    for (size_t i = 0; i < h.size(); i++) {
                        cum += h[i];
                        if (cum >= thresh) { c = (int)i; break; }
                    }
                    if (c + 2 < (int)h.size()) {
                        uint64_t over = 0;
                        for (int i = c + 1; i < (int)h.size(); i++) {
                            over += h[i];
                        }
                        h.resize(c + 2);
                        h[c + 1] = over;
                        clip_idx = c;
                    }
                }
            }

            plan.mode = ChartPlan::Mode::Bars;
            plan.n_bins = (int)h.size();
            plan.x_bin_size = 1;
            plan.x_label = "Reuse distance (unique cache lines)";
            plan.y_label = "memops";
            plan.warmup_bins = 0;
            plan.percent = false;
            plan.y_is_count = true;
            plan.series.resize(1);
            plan.series[0].label = "";
            plan.series[0].color = palette_color(0);
            plan.series[0].y.assign(h.size(), 0.0);
            uint64_t y_peak = 0;
            for (size_t b = 0; b < h.size(); b++) {
                plan.series[0].y[b] = (double)h[b];
                if (h[b] > y_peak) y_peak = h[b];
            }
            plan.y_max = (y_peak > 0) ? (double)y_peak * 1.1 : 1.0;
            /* Custom x labels: "cold", "0", "1", "2-3", "4-7", ...
             * For the post-clip layout, plan.n_bins = clip_idx + 2
             * when an overflow bin is present (1 for "cold" + clip_idx
             * data bins + 1 for ">N"); otherwise plan.n_bins ==
             * 1 + n_buckets and no overflow tick is set. */
            int data_bins = plan.n_bins - 1; /* exclude "cold" */
            bool overflow = (clip_idx + 2 == plan.n_bins
                             && clip_idx + 1 < (int)n_buckets);
            int draw_bins = overflow ? clip_idx : (data_bins);
            plan.x_tick_labels.clear();
            plan.x_tick_labels.push_back("cold");
            /* Standardised to the bucket's LOW BOUND only (e.g. 256, 1K, 1M).
             * The prior code alternated "lo-hi" ranges for small buckets and
             * a bare low bound for large ones, which crowded the small-bucket
             * end of the x-axis and read inconsistently. */
            auto bucket_label = [](size_t b) -> std::string {
                char buf[32];
                if (b == 0) {
                    std::snprintf(buf, sizeof(buf), "0");
                } else {
                    uint64_t lo = uint64_t{1} << (b - 1);   /* b==1 -> 1 */
                    if (lo < 1024) std::snprintf(buf, sizeof(buf),
                        "%lu", (unsigned long)lo);
                    else if (lo < 1024 * 1024) std::snprintf(buf, sizeof(buf),
                        "%luK", (unsigned long)(lo / 1024));
                    else std::snprintf(buf, sizeof(buf),
                        "%luM", (unsigned long)(lo / (1024 * 1024)));
                }
                return std::string(buf);
            };
            for (int b = 0; b < draw_bins; b++) {
                plan.x_tick_labels.push_back(bucket_label((size_t)b));
            }
            if (overflow) {
                /* The overflow bin folds buckets [clip_idx .. n_buckets-1];
                 * label it ">{low bound of the first folded bucket}". */
                plan.x_tick_labels.push_back(
                    ">" + bucket_label((size_t)clip_idx));
            }
            plan.margin_right = 40;
            break;
        }
    }

    /* Finalise the dual-pane bottom axis for time-series panes (histogram
     * panes already set their own axis in the build switch above).  Done
     * here so both the single-trace and aggregate render paths receive a
     * fully-formed plan2. */
    if (has_second_pane && plan2.mode != ChartPlan::Mode::Bars) {
        plan2.n_bins     = actual_bins;
        plan2.x_bin_size = bin_width;
        plan2.x_label    = "CP instruction window";
        plan2.warmup_end_insns = h.warmup_end_arch_insns;
    }

    TraceResult tr;
    tr.has_second_pane  = has_second_pane;
    tr.weight           = h.weight;
    tr.start_insn       = h.start_insn;
    tr.warmup_end_insns = h.warmup_end_arch_insns;
    tr.total_insns      = total_cp_insns;
    tr.label            = short_trace_label(path);
    tr.plan             = std::move(plan);
    tr.plan2            = std::move(plan2);
    return tr;
}

static TraceResult process_trace(const char *path, const Options &opts)
{
    std::unique_ptr<cst::CstFile> cf = cst::cst_file_open(path);

    std::vector<cst::Template> templates;
    std::unordered_map<uint32_t, size_t> by_id;
    cst::Header h = cst::parse_header(cf->header(), &templates, &by_id);

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

    build_metric_state(ctx, templates, h);

    /* Header-derived static-summary metrics (bb_length /
     * indirect_targets / branch_entropy) compute purely from the
     * template list and skip the body walk entirely. */
    bool is_header_only = (opts.metric == Metric::BbLength ||
                           opts.metric == Metric::IndirectTargets ||
                           opts.metric == Metric::BranchEntropy);

    /* --debug-branches early-exit dump.  Aggregates the tracer-side
     * profile counts (taken_cp, nottaken_cp) PER Jcc PC across every
     * template that ends at that PC, sorted by total executions.
     * This is purely header-derived — no body walk needed — so it
     * runs in seconds and lets us see what the trace ITSELF claims
     * about each branch's outcome distribution before paying the
     * full-walk cost. */
    if (opts.debug_branches > 0 && opts.metric == Metric::BranchMpki) {
        struct PcTruth {
            uint64_t taken = 0, nottaken = 0;
            uint64_t fall_through = 0;
            uint64_t taken_target = 0;
            uint64_t pc_plus_size = 0; /* sanity: where fall-through SHOULD be */
            uint32_t templates_seen = 0;
        };
        std::unordered_map<uint64_t, PcTruth> truth;
        for (size_t i = 0; i < templates.size(); i++) {
            if (!ctx.term[i].is_branch ||
                !ctx.term[i].is_conditional) continue;
            const auto &tmpl = templates[i];
            const auto &prof = tmpl.profile;
            if (prof.targets.empty()) continue;
            auto &tt = truth[ctx.term[i].pc];
            tt.taken    += prof.targets[0].taken_cp;
            tt.nottaken += prof.targets[0].nottaken_cp;
            tt.fall_through = tmpl.fall_through_pc;
            tt.taken_target = tmpl.target_pcs.empty() ? 0 : tmpl.target_pcs[0];
            /* Compute the architectural-next-PC for the terminator
             * (= last insn's PC + its byte length).  raw_bytes carries
             * the actual instruction encoding when available; if it
             * was omitted (insn_size==0 in the trace), leave 0. */
            const auto &last_insn = tmpl.insns.back();
            tt.pc_plus_size = last_insn.raw_bytes.empty()
                ? 0
                : last_insn.pc + (uint64_t)last_insn.raw_bytes.size();
            tt.templates_seen++;
        }
        /* Per-template sanity: for every conditional template, check
         * whether its stored fall_through_pc matches the architectural
         * fall-through (last_insn.pc + last_insn.raw_bytes.size()). */
        size_t tpl_total = 0, tpl_ft_ok = 0, tpl_ft_bad = 0, tpl_unknown = 0;
        for (size_t i = 0; i < templates.size(); i++) {
            if (!ctx.term[i].is_branch ||
                !ctx.term[i].is_conditional) continue;
            tpl_total++;
            const auto &tmpl = templates[i];
            if (tmpl.insns.empty()) { tpl_unknown++; continue; }
            const auto &li = tmpl.insns.back();
            if (li.raw_bytes.empty()) { tpl_unknown++; continue; }
            uint64_t expected = li.pc + (uint64_t)li.raw_bytes.size();
            if (expected == tmpl.fall_through_pc) tpl_ft_ok++;
            else tpl_ft_bad++;
        }
        std::fprintf(stderr,
            "=== PER-TEMPLATE fall_through sanity (all conditional templates) ===\n"
            "  total: %zu | ft_ok (matches pc+size): %zu | ft_bad: %zu | unknown size: %zu\n\n",
            tpl_total, tpl_ft_ok, tpl_ft_bad, tpl_unknown);

        std::vector<std::pair<uint64_t, PcTruth>> rows(
            truth.begin(), truth.end());
        std::sort(rows.begin(), rows.end(),
            [](const auto &a, const auto &b) {
                return (a.second.taken + a.second.nottaken) >
                       (b.second.taken + b.second.nottaken);
            });
        std::fprintf(stderr,
            "=== TRACER-SIDE per-Jcc-PC truth (header-only, top 40 by total exec) ===\n"
            "%-18s %12s %12s %10s %18s %18s %18s %5s %s\n",
            "pc", "taken_cp", "nottaken_cp", "tk_rate",
            "fall_through", "pc+size_(expected_fall)",
            "taken_target", "ntpl", "OK?");
        size_t top = std::min((size_t)40, rows.size());
        uint64_t grand_taken = 0, grand_total = 0;
        size_t   biased_99 = 0, mixed_30_70 = 0, ft_bad = 0;
        for (const auto &row : rows) {
            uint64_t t = row.second.taken, n = row.second.nottaken;
            uint64_t tot = t + n;
            grand_taken += t;
            grand_total += tot;
            if (tot > 0) {
                double r = (double)t / tot;
                if (r >= 0.99 || r <= 0.01) biased_99++;
                else if (r >= 0.30 && r <= 0.70) mixed_30_70++;
            }
            if (row.second.fall_through != row.second.pc_plus_size) ft_bad++;
        }
        for (size_t i = 0; i < top; i++) {
            uint64_t pc = rows[i].first;
            const auto &tt = rows[i].second;
            uint64_t tot = tt.taken + tt.nottaken;
            double rate = tot ? (double)tt.taken / tot : 0.0;
            bool ft_ok = (tt.fall_through == tt.pc_plus_size);
            std::fprintf(stderr,
                "0x%016lx %12lu %12lu %10.4f 0x%016lx 0x%016lx 0x%016lx %5u %s\n",
                (unsigned long)pc, (unsigned long)tt.taken,
                (unsigned long)tt.nottaken, rate,
                (unsigned long)tt.fall_through,
                (unsigned long)tt.pc_plus_size,
                (unsigned long)tt.taken_target,
                (unsigned)tt.templates_seen,
                ft_ok ? "✓" : "★FT_MISMATCH");
        }
        std::fprintf(stderr,
            "(%zu of %zu distinct Jcc PCs shown)\n"
            "  grand total executions: %lu, grand taken: %lu (rate %.4f)\n"
            "  >=99%% biased PCs: %zu (%.1f%%);  30-70%% mixed: %zu (%.1f%%)\n"
            "  PCs where stored fall_through != pc+insn_size: %zu (%.1f%%)\n\n",
            top, rows.size(),
            (unsigned long)grand_total, (unsigned long)grand_taken,
            grand_total ? (double)grand_taken / grand_total : 0.0,
            biased_99,    rows.empty() ? 0.0 : 100.0 * biased_99    / rows.size(),
            mixed_30_70,  rows.empty() ? 0.0 : 100.0 * mixed_30_70  / rows.size(),
            ft_bad,       rows.empty() ? 0.0 : 100.0 * ft_bad       / rows.size());
    }

    if (!is_header_only) {
        /* Walk. */
        auto body_stream = cst::body_stream_open(*cf);
        cst::BodyWalker walker(h, templates, by_id,
                               body_stream->reader());

        /* Every body-walk metric uses the streaming BB walk: it
         * allocates nothing per BB and parse-skips field deltas a metric
         * doesn't read.  Each case picks the minimum it needs —
         * cp_fields (apply CP deltas, enable CP accessors) and a WP
         * decode level (skip / structure / fields). */
        using BBFn    = void (*)(WalkCtx &, const cst::BodyWalker::BB &);
        using Wp          = cst::BodyWalker::WpDecode;
        BBFn    bb_fn     = nullptr;
        bool    cp_fields = false;       /* streaming-path: apply CP deltas */
        Wp      wp_mode   = Wp::Skip;    /* streaming-path: WP decode level */
        switch (opts.metric) {
            /* --- streaming BB path: CP structure only, no wrong-path --- */
            case Metric::GenOp:
                bb_fn = handle_genop_bb; break;
            case Metric::GenReg:
                bb_fn = handle_genreg_bb; break;
            /* --- streaming BB path: CP fields, no wrong-path --- */
            case Metric::DepDepth:
                /* needs memop addresses for the memory-RAW dependency */
                bb_fn = handle_dep_depth_bb; cp_fields = true; break;
            case Metric::Ilp:
                bb_fn = handle_ilp_bb; cp_fields = true; break;
            case Metric::WorkingSet:
                bb_fn = handle_working_set_bb; cp_fields = true; break;
            case Metric::ReuseDistance:
                bb_fn = handle_reuse_distance_bb; cp_fields = true; break;
            /* --- streaming BB path: CP + WP structure --- */
            case Metric::BranchMpki:
            case Metric::WpInsns:
                bb_fn = handle_gshare_bb; wp_mode = Wp::Structure; break;
            case Metric::WpMemops:
                /* needs per-WP-BB memop counts -> WP field deltas */
                bb_fn = handle_gshare_bb; wp_mode = Wp::Fields; break;
            case Metric::BranchDir:
                bb_fn = handle_branch_dir_bb; wp_mode = Wp::Structure; break;
            case Metric::BtbMiss:
                bb_fn = handle_btb_bb; wp_mode = Wp::Structure; break;
            case Metric::WpDivergence:
                bb_fn = handle_wp_divergence_bb; wp_mode = Wp::Structure; break;
            /* --- streaming BB path: CP + WP fields --- */
            case Metric::MemPat:
                bb_fn = handle_mem_pat_bb;
                cp_fields = true; wp_mode = Wp::Fields; break;
            case Metric::CacheMiss:
                bb_fn = handle_cache_miss_bb;
                cp_fields = true; wp_mode = Wp::Fields; break;
            case Metric::BbLength:
            case Metric::IndirectTargets:
            case Metric::BranchEntropy:
                break; /* unreachable: gated above */
        }

        if (!bb_fn) {
            /* All body-walk metrics set bb_fn; the header-only metrics
             * never reach here (gated by is_header_only).  A null here
             * means a newly-added metric wasn't wired — fail loudly
             * rather than silently emit an empty chart. */
            throw std::runtime_error(
                "internal error: metric has no walk handler");
        }
        walker.walk_bb(cp_fields, wp_mode,
                       [&](const cst::BodyWalker::BB &bb) {
                           bb_fn(ctx, bb);
                       });
        try { body_stream->finalize(); }
        catch (...) {}

        /* Branch-stream diagnostics dump (per-PC aggregates).  Sorted
         * by total executions descending so the dominant branches
         * appear first.  --debug-branches=N is the gate; the first
         * N raw tuples already went to stderr during the walk. */
        if (opts.debug_branches > 0 && opts.metric == Metric::BranchMpki
            && !ctx.dbg.per_pc.empty()) {
            /* Build a tracer-side ground-truth: per Jcc PC, sum
             * profile.targets[0].{taken_cp, nottaken_cp} across every
             * template whose terminator is at this PC.  If the
             * visualizer's handler-derived per-PC totals don't match
             * this, the outcome derivation has a bug. */
            std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> tracer_truth;
            for (size_t i = 0; i < templates.size(); i++) {
                if (!ctx.term[i].is_branch ||
                    !ctx.term[i].is_conditional) continue;
                const auto &prof = templates[i].profile;
                if (prof.targets.empty()) continue;
                uint64_t pc = ctx.term[i].pc;
                auto &tt = tracer_truth[pc];
                tt.first  += prof.targets[0].taken_cp;
                tt.second += prof.targets[0].nottaken_cp;
            }

            std::vector<std::pair<uint64_t, WalkCtx::DebugBranchState::PcAgg>>
                rows(ctx.dbg.per_pc.begin(), ctx.dbg.per_pc.end());
            std::sort(rows.begin(), rows.end(),
                [](const auto &a, const auto &b) {
                    return (a.second.taken + a.second.nottaken) >
                           (b.second.taken + b.second.nottaken);
                });
            std::fprintf(stderr,
                "\n=== branch-stream per-PC aggregate (top 40 by exec; ★ = handler vs tracer profile mismatch) ===\n"
                "%-18s %12s %12s %12s %10s %10s | %12s %12s %s\n",
                "pc", "h_taken", "h_nottaken", "h_total", "miss_h0",
                "miss_h12", "t_taken", "t_nottaken", "match?");
            size_t top = std::min((size_t)40, rows.size());
            size_t mismatch_count = 0;
            for (size_t i = 0; i < top; i++) {
                uint64_t pc = rows[i].first;
                const auto &a = rows[i].second;
                uint64_t h_total = a.taken + a.nottaken;
                auto it = tracer_truth.find(pc);
                uint64_t t_t = (it != tracer_truth.end()) ? it->second.first : 0;
                uint64_t t_n = (it != tracer_truth.end()) ? it->second.second : 0;
                bool match = (t_t == a.taken && t_n == a.nottaken);
                if (!match) mismatch_count++;
                std::fprintf(stderr,
                    "0x%016lx %12lu %12lu %12lu %10lu %10lu | %12lu %12lu %s\n",
                    (unsigned long)pc, (unsigned long)a.taken,
                    (unsigned long)a.nottaken, (unsigned long)h_total,
                    (unsigned long)a.mispred_h0, (unsigned long)a.mispred_h12,
                    (unsigned long)t_t, (unsigned long)t_n,
                    match ? "ok" : "★ MISMATCH");
            }
            /* Also count mismatches across the FULL per-PC set, not just top-40. */
            size_t full_mismatch = 0;
            for (const auto &row : ctx.dbg.per_pc) {
                auto it = tracer_truth.find(row.first);
                uint64_t t_t = (it != tracer_truth.end()) ? it->second.first : 0;
                uint64_t t_n = (it != tracer_truth.end()) ? it->second.second : 0;
                if (t_t != row.second.taken || t_n != row.second.nottaken) {
                    full_mismatch++;
                }
            }
            std::fprintf(stderr,
                "(showing %zu of %zu distinct PCs; mismatches in top: %zu; mismatches total: %zu)\n",
                top, rows.size(), mismatch_count, full_mismatch);
        }
    }

    return finalize_metric(path, ctx, templates, h, total_cp_insns);
}

/* Combine one pane (plan or plan2) across traces.  @panes[i] is trace i's
 * pane, @w[i] its normalised weight, @meta[i] its source TraceResult.  The
 * pane's shape decides the strategy: an instruction-window time-series
 * (mode != Bars, no custom x ticks) becomes a weight-proportional
 * composition montage; anything else (Bars histogram / custom-tick
 * static-summary) becomes a weighted average of each trace's normalised
 * distribution. */
static ChartPlan aggregate_pane(const std::vector<const ChartPlan *> &panes,
                                const std::vector<double> &w,
                                const std::vector<const TraceResult *> &meta,
                                const Options &opts,
                                const std::string &progname)
{
    ChartPlan out;
    if (panes.empty()) return out;
    const ChartPlan &first = *panes[0];
    bool timeline = (first.mode != ChartPlan::Mode::Bars &&
                     first.x_tick_labels.empty());

    if (timeline) {
        /* Global series order by aggregate magnitude (Σ wᵢ·Σy), so colours
         * and legend are consistent across all segments.  gen_op/gen_reg
         * additionally cap to a global top-K with the rest folded into
         * "other". */
        std::unordered_map<std::string, double> mag;
        std::vector<std::string> seen;
        for (size_t i = 0; i < panes.size(); i++) {
            for (const Series &s : panes[i]->series) {
                double t = 0; for (double v : s.y) t += v;
                if (mag.find(s.label) == mag.end()) seen.push_back(s.label);
                mag[s.label] += w[i] * t;
            }
        }
        std::vector<std::string> labels;
        bool need_other = false;
        if (first.mode == ChartPlan::Mode::Stacked) {
            /* Category breakdown (gen_op / gen_reg / branch_dir / mem_pat):
             * the categories have no natural order, so order the legend by
             * aggregate magnitude and cap gen_op/gen_reg to a global top-K,
             * folding the rest into "other". */
            std::stable_sort(seen.begin(), seen.end(),
                [&](const std::string &a, const std::string &b) {
                    return mag[a] > mag[b];
                });
            bool capk = (opts.metric == Metric::GenOp ||
                         opts.metric == Metric::GenReg);
            for (const std::string &name : seen) {
                if (name == "other") { need_other = true; continue; }
                if (capk && (int)labels.size() >= opts.top_k) {
                    need_other = true; continue;
                }
                labels.push_back(name);
            }
            if (need_other) labels.push_back("other");
        } else {
            /* Parameter-sweep lines (branch_mpki history lengths, btb_miss
             * sizes, cache_miss assocs, wp_divergence min/median/mean/max,
             * working_set) have a natural series order.  Preserve the
             * per-pane order instead of scrambling the legend by magnitude;
             * every pane shares the same series in the same order, so
             * pane[0] is canonical.  This also matches the single-trace
             * legend (and colour) order. */
            for (const Series &s : first.series) {
                if (s.label.empty()) continue;
                if (s.label == "other") { need_other = true; continue; }
                labels.push_back(s.label);
            }
            if (need_other) labels.push_back("other");
        }
        /* Colour assignment mirrors the single-trace renderer.  For the
         * stacked category breakdowns colour by legend position so the
         * most distinct palette colours fall on the most important
         * categories (the legend is magnitude-ordered above, so
         * position 0 is the dominant category), and pin branch_dir
         * classes to fixed slots by name.  Parameter-sweep line metrics
         * (branch_mpki / btb / cache / wp_divergence / working_set) keep
         * their established colours — wp_divergence in particular hand-
         * picks its min/median/mean/max hues — so leave those on the
         * name-stable mapping. */
        const bool stacked_cat = (first.mode == ChartPlan::Mode::Stacked);
        const bool is_branch_dir = (opts.metric == Metric::BranchDir);
        std::unordered_map<std::string, std::string> color;
        std::unordered_map<std::string, int> label_idx;
        for (size_t i = 0; i < labels.size(); i++) {
            color[labels[i]] = !stacked_cat   ? color_for_label(labels[i])
                             : is_branch_dir  ? branch_dir_color(labels[i])
                             :                  palette_color(i);
            label_idx[labels[i]] = (int)i;
        }
        /* Unified legend (label + colour, no data). */
        for (const std::string &l : labels) {
            Series s; s.label = l; s.color = color[l];
            out.series.push_back(s);
        }

        double cum = 0.0;
        double y_max = 0.0;
        for (size_t i = 0; i < panes.size(); i++) {
            ChartPlan::CompSegment seg;
            int full_nb = panes[i]->n_bins > 0 ? panes[i]->n_bins : 1;
            /* Warmup is not part of the simpoint region, so for a
             * composition view we plot only the post-warmup bins (decode
             * still ran the warmup in-order; we just don't draw it).  The
             * segment keeps its weight-proportional width — the simpoint
             * region is stretched across it — and carries no warmup rule,
             * leaving a clean simpoint separator. */
            int wb = 0;
            if (meta[i]->warmup_end_insns != UINT64_MAX &&
                meta[i]->total_insns > 0) {
                double f = (double)meta[i]->warmup_end_insns /
                           (double)meta[i]->total_insns;
                if (f < 0) f = 0;
                if (f > 1) f = 1;
                wb = (int)(f * full_nb);
                if (wb >= full_nb) wb = full_nb - 1;   /* keep >=1 bin */
            }
            int nb = full_nb - wb;
            if (nb < 1) nb = 1;
            seg.n_bins  = nb;
            seg.warmup_frac = -1;          /* warmup excluded → no marker */
            seg.x0_frac = cum; cum += w[i]; seg.x1_frac = cum;
            char wbuf[16];
            std::snprintf(wbuf, sizeof(wbuf), "  %.0f%%", w[i] * 100.0);
            seg.label = meta[i]->label + wbuf;
            /* One output series per global label, in label order. */
            seg.series.resize(labels.size());
            for (size_t li = 0; li < labels.size(); li++) {
                seg.series[li].label = labels[li];
                seg.series[li].color = color[labels[li]];
                seg.series[li].y.assign((size_t)nb, 0.0);
            }
            int other_li = need_other ? label_idx["other"] : -1;
            for (const Series &s : panes[i]->series) {
                auto it = label_idx.find(s.label);
                int dst;
                if (it != label_idx.end() && s.label != "other") {
                    dst = it->second;
                } else {
                    dst = other_li;           /* folded / explicit other */
                }
                if (dst < 0) continue;
                std::vector<double> &y = seg.series[dst].y;
                for (int b = 0; b < nb; b++) {
                    int src = wb + b;
                    if (src < (int)s.y.size()) y[b] += s.y[src];
                }
            }
            /* Track y_max for non-percent panes (stacked → per-bin sum). */
            if (!first.percent) {
                for (int b = 0; b < nb; b++) {
                    double col = 0.0;
                    for (const Series &s : seg.series) {
                        if (first.mode == ChartPlan::Mode::Stacked) {
                            col += (b < (int)s.y.size()) ? s.y[b] : 0.0;
                        } else {
                            double v = (b < (int)s.y.size()) ? s.y[b] : 0.0;
                            if (v > col) col = v;
                        }
                    }
                    if (col > y_max) y_max = col;
                }
            }
            out.segments.push_back(std::move(seg));
        }

        out.mode       = first.mode;
        out.percent    = first.percent;
        out.y_is_count = first.y_is_count;
        out.y_label    = first.y_label;
        out.x_label    = "program composition (weighted)";
        out.y_max      = first.percent ? 1.0 : (y_max > 0 ? y_max * 1.1 : 1.0);
        out.title      = progname + ": " + first.title;
        return out;
    }

    /* Histogram / static-summary → per-simpoint STACKED distribution.
     * Each trace contributes one output series (label = simpoint name,
     * colour = per-simpoint hue in program order) holding its
     * weighted-normalised distribution; the stacked bars show how each
     * simpoint shapes the whole, and the total height is the weighted-mean
     * distribution.  Use the widest pane as the canonical x-axis (bucket
     * index b has the same meaning across traces of one program); fold any
     * longer tails into the canonical last bucket. */
    size_t canon = 0;
    for (size_t i = 1; i < panes.size(); i++) {
        if (panes[i]->n_bins > panes[canon]->n_bins) canon = i;
    }
    out = *panes[canon];        /* copy x ticks / overflow / n_bins / mode */
    out.segments.clear();
    out.series.clear();
    int cn = out.n_bins > 0 ? out.n_bins : 1;
    std::vector<double> stack((size_t)cn, 0.0);
    for (size_t i = 0; i < panes.size(); i++) {
        Series s;
        s.label = meta[i]->label;
        s.color = palette_color(i);          /* per-simpoint hue */
        s.y.assign((size_t)cn, 0.0);
        if (!panes[i]->series.empty()) {
            const Series &ts = panes[i]->series[0];
            double tot = 0; for (double v : ts.y) tot += v;
            if (tot > 0) {
                for (int b = 0; b < (int)ts.y.size(); b++) {
                    int idx = b < cn ? b : cn - 1;
                    s.y[idx] += w[i] * (ts.y[b] / tot);
                }
            }
        }
        for (int b = 0; b < cn; b++) stack[b] += s.y[b];
        out.series.push_back(std::move(s));
    }
    double mx = 0.0; for (double v : stack) if (v > mx) mx = v;
    out.percent      = true;
    out.y_is_count   = false;
    out.y_max        = mx > 0 ? mx * 1.1 : 1.0;
    out.margin_right = 150;     /* room for the per-simpoint legend */
    out.title        = progname + ": " + panes[canon]->title;
    return out;
}

static TraceResult aggregate_results(std::vector<TraceResult> &rs,
                                     const Options &opts)
{
    /* Program order so the montage reads left-to-right as execution. */
    std::stable_sort(rs.begin(), rs.end(),
        [](const TraceResult &a, const TraceResult &b) {
            return a.start_insn < b.start_insn;
        });

    /* Normalise weights; all-zero (or missing) → even split. */
    std::vector<double> w(rs.size());
    double sum = 0.0;
    for (size_t i = 0; i < rs.size(); i++) { w[i] = rs[i].weight; sum += w[i]; }
    if (sum <= 0.0) {
        for (double &x : w) x = 1.0 / (double)rs.size();
    } else {
        for (double &x : w) x /= sum;
    }

    std::string progname = opts.agg_name ? opts.agg_name : "aggregate";

    std::vector<const ChartPlan *> p1, p2;
    std::vector<const TraceResult *> meta;
    bool dual = rs[0].has_second_pane;
    for (const TraceResult &r : rs) {
        p1.push_back(&r.plan);
        meta.push_back(&r);
        if (dual) p2.push_back(&r.plan2);
    }

    TraceResult out;
    out.has_second_pane = dual;
    out.plan = aggregate_pane(p1, w, meta, opts, progname);
    if (dual) out.plan2 = aggregate_pane(p2, w, meta, opts, progname);
    return out;
}

/* Header-only peek: open + parse header (no body walk) to read the
 * simpoint weight, start_insn, and warmup boundary, plus the trace's CP
 * instruction span (total_target_insns, or a profile-summed estimate when
 * unbounded — mirrors process_trace's bin-width derivation). */
static TraceMeta peek_trace_meta(const char *path)
{
    std::unique_ptr<cst::CstFile> cf = cst::cst_file_open(path);
    std::vector<cst::Template> templates;
    std::unordered_map<uint32_t, size_t> by_id;
    cst::Header h = cst::parse_header(cf->header(), &templates, &by_id);

    TraceMeta m;
    m.weight     = h.weight;
    m.start_insn = h.start_insn;
    m.warmup_end = h.warmup_end_arch_insns;
    uint64_t total = h.total_target_insns;
    if (total == 0) {
        for (const auto &t : templates) {
            total += (uint64_t)t.profile.exec_cp * t.insns.size();
        }
        if (total == 0) total = 1;
    }
    m.total_insns = total;
    return m;
}
