/*
 * wptrace_sync_classify.h — Sync Region Classification Engine
 *
 * Self-contained header that implements all sync-region detection
 * heuristics for the wptrace plugin.  Every classification decision
 * is driven by the tunable parameters below.  Users can override any
 * parameter by defining it before including this header, or via
 * -D on the compiler command line.
 *
 * The core function is sync_classify_segments(), called once during
 * footer finalization.  It takes the completed segment directory and
 * populates:
 *   - Extended segment flags (is_spin_wait, is_acquire, is_release, etc.)
 *   - Happens-before edges on each SegmentDirEntry
 *   - A list of SyncRegionInfo describing detected regions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WPTRACE_SYNC_CLASSIFY_H
#define WPTRACE_SYNC_CLASSIFY_H

#include <glib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* =========================================================================
 * Section 1: Tunable Parameters
 *
 * Override any of these by defining them before including this header
 * or via -DPARAM=VALUE on the compiler command line.
 *
 * Runtime overrides (from plugin options) take precedence; see
 * SyncClassifyConfig below.
 * ========================================================================= */

/* --- Detector Enable Flags --- */

/* Master enable for each detector.  Set to 0 to disable at compile time. */
#ifndef SYNC_DETECT_SPIN_ACQUIRE
#define SYNC_DETECT_SPIN_ACQUIRE        1
#endif

#ifndef SYNC_DETECT_CRITICAL_SECTION
#define SYNC_DETECT_CRITICAL_SECTION    1
#endif

#ifndef SYNC_DETECT_RELEASE
#define SYNC_DETECT_RELEASE             1
#endif

#ifndef SYNC_DETECT_BARRIER_WAIT
#define SYNC_DETECT_BARRIER_WAIT        1
#endif

#ifndef SYNC_DETECT_HB_EDGES
#define SYNC_DETECT_HB_EDGES            1
#endif


/* --- Spin-Wait Detection Thresholds --- */

/*
 * Minimum consecutive same-address atomic segments from the same thread
 * before the run is classified as a spin-wait.
 *
 * Rationale: a single retry is common for uncontended CAS (spurious
 * failure on LL/SC architectures).  Requiring >= 2 reduces false
 * positives while catching real contention.
 */
#ifndef SPIN_MIN_ITERATIONS
#define SPIN_MIN_ITERATIONS             2
#endif

/*
 * Maximum distinct atomic addresses in a single atomic segment for it
 * to be considered part of a spin loop.  Spin loops typically access
 * only the lock word (1 address).  An atomic segment that touches 3+
 * distinct addresses is more likely real work (e.g., a lock-free
 * data structure operation) than a spin poll.
 */
#ifndef SPIN_MAX_DISTINCT_ADDRS
#define SPIN_MAX_DISTINCT_ADDRS         2
#endif


/* --- Critical Section Detection --- */

/*
 * Maximum number of segments between a spin-acquire success and the
 * matching release (same address, same thread) before abandoning the
 * pairing.  This prevents a missed release from keeping the critical-
 * section tracker open for the rest of the trace.
 *
 * 1000 segments is generous — a critical section with 1000 BBs is
 * very long.  Reduce for tighter pairing in workloads with many
 * fine-grained locks.
 */
#ifndef CRITICAL_SECTION_MAX_GAP_SEGS
#define CRITICAL_SECTION_MAX_GAP_SEGS   1000
#endif


/* --- Barrier Detection --- */

/*
 * Minimum number of distinct threads that must touch the same atomic
 * address in a clustered region for it to be classified as a barrier.
 *
 * 2 is the minimum meaningful barrier (two threads synchronizing).
 */
#ifndef BARRIER_MIN_THREADS
#define BARRIER_MIN_THREADS             2
#endif

/*
 * Maximum segment-index distance between the first and last atomic
 * segment on a candidate barrier address before the cluster is
 * considered too spread out to be a barrier.
 */
#ifndef BARRIER_MAX_CLUSTER_SPAN
#define BARRIER_MAX_CLUSTER_SPAN        500
#endif


/* --- Happens-Before Edge Control --- */

#ifndef HB_EDGE_RELEASE_ACQUIRE_ENABLED
#define HB_EDGE_RELEASE_ACQUIRE_ENABLED 1
#endif

#ifndef HB_EDGE_SPAWN_ENABLED
#define HB_EDGE_SPAWN_ENABLED           1
#endif

#ifndef HB_EDGE_BARRIER_ENABLED
#define HB_EDGE_BARRIER_ENABLED         1
#endif


/* =========================================================================
 * Section 2: Types
 * ========================================================================= */

/* Sync region types (4 bits, fits in SYNC body record) */
typedef enum {
    SYNC_REGION_NONE             = 0,
    SYNC_REGION_SPIN_ACQUIRE     = 1,  /* CAS retry / test-and-set loop */
    SYNC_REGION_CRITICAL_SECTION = 2,  /* code between acquire & release */
    SYNC_REGION_RELEASE          = 3,  /* lock release / store-release */
    SYNC_REGION_BARRIER_WAIT     = 4,  /* barrier polling loop */
} SyncRegionType;

/* Outcome of a sync region (4 bits) */
typedef enum {
    SYNC_OUTCOME_ACQUIRED = 0,  /* lock/flag successfully acquired */
    SYNC_OUTCOME_RELEASED = 1,  /* lock/flag released */
    SYNC_OUTCOME_TIMEOUT  = 2,  /* reserved: timed-out spin */
} SyncRegionOutcome;

/* Happens-before edge types (4 bits) */
typedef enum {
    HB_RELEASE_ACQUIRE = 0,  /* A released, this segment acquired */
    HB_SPAWN           = 1,  /* predecessor spawned this thread */
    HB_JOIN            = 2,  /* reserved: thread exit → join */
    HB_BARRIER         = 3,  /* barrier completion edge */
} HBEdgeType;

/* A single happens-before edge in the segment directory */
typedef struct {
    uint32_t   pred_seg_idx;  /* index into segment directory */
    HBEdgeType edge_type;
} HBEdge;

/* Detected sync region (serialized into the Sync Region Table) */
typedef struct {
    SyncRegionType    type;
    SyncRegionOutcome outcome;
    uint64_t          sync_addr;       /* primary sync address */
    uint32_t          thread_id;
    uint32_t          begin_seg_idx;   /* first segment in region */
    uint32_t          end_seg_idx;     /* last segment in region */
    uint32_t          iteration_count; /* spin/barrier iterations */
} SyncRegionInfo;

/*
 * Runtime configuration — allows plugin options to override
 * compile-time defaults without recompilation.  Zero values
 * mean "use compile-time default".
 */
typedef struct {
    /* Detector enables (tristate: -1 = compile-time, 0 = off, 1 = on) */
    int detect_spin_acquire;
    int detect_critical_section;
    int detect_release;
    int detect_barrier_wait;
    int detect_hb_edges;

    /* Threshold overrides (0 = use compile-time default) */
    uint32_t spin_min_iterations;
    uint32_t spin_max_distinct_addrs;
    uint32_t cs_max_gap_segs;
    uint32_t barrier_min_threads;
    uint32_t barrier_max_cluster_span;

    /* HB edge sub-enables */
    int hb_release_acquire;
    int hb_spawn;
    int hb_barrier;
} SyncClassifyConfig;

/* Extended segment flags (bits in the 8-bit flags field) */
#define SEG_FLAG_ATOMIC      (1 << 0)  /* existing */
#define SEG_FLAG_SPIN_WAIT   (1 << 1)  /* new: part of spin-wait loop */
#define SEG_FLAG_ACQUIRE     (1 << 2)  /* new: successful acquire (CAS ok) */
#define SEG_FLAG_RELEASE     (1 << 3)  /* new: store-release */
#define SEG_FLAG_BARRIER     (1 << 4)  /* new: barrier increment/wait */

/* SYNC body event sub-types (extensions to SyncEventType, 4-bit field) */
#define SYNC_REGION_BEGIN_TYPE  6
#define SYNC_REGION_END_TYPE    7


/* =========================================================================
 * Section 3: Internal Per-Thread Tracking State
 * ========================================================================= */

/* Per-thread state maintained during the classification pass */
typedef struct {
    /* Spin-wait tracking */
    uint64_t last_atomic_addr;       /* address of most recent atomic seg */
    uint32_t last_atomic_seg_idx;    /* seg_dir index of most recent */
    uint32_t spin_run_start;         /* first seg idx in current run */
    uint32_t spin_run_count;         /* consecutive same-addr atomic segs */

    /* Critical section tracking */
    bool     in_critical_section;
    uint64_t cs_lock_addr;           /* address of the lock */
    uint32_t cs_start_seg_idx;       /* segment where CS begins */
    uint32_t cs_acquire_seg_idx;     /* the acquire segment */

    /* General */
    uint32_t first_seg_idx;          /* first segment for this thread */
    bool     seen;                   /* have we seen any segment? */
} ThreadSyncState;


/* =========================================================================
 * Section 4: Effective Configuration Helpers
 *
 * Resolve runtime overrides vs compile-time defaults.
 * ========================================================================= */

static inline bool sc_detect_spin(const SyncClassifyConfig *cfg)
{
    if (cfg && cfg->detect_spin_acquire != -1) {
        return cfg->detect_spin_acquire != 0;
    }
    return SYNC_DETECT_SPIN_ACQUIRE != 0;
}

static inline bool sc_detect_cs(const SyncClassifyConfig *cfg)
{
    if (cfg && cfg->detect_critical_section != -1) {
        return cfg->detect_critical_section != 0;
    }
    return SYNC_DETECT_CRITICAL_SECTION != 0;
}

static inline bool sc_detect_release(const SyncClassifyConfig *cfg)
{
    if (cfg && cfg->detect_release != -1) {
        return cfg->detect_release != 0;
    }
    return SYNC_DETECT_RELEASE != 0;
}

static inline bool sc_detect_barrier(const SyncClassifyConfig *cfg)
{
    if (cfg && cfg->detect_barrier_wait != -1) {
        return cfg->detect_barrier_wait != 0;
    }
    return SYNC_DETECT_BARRIER_WAIT != 0;
}

static inline bool sc_detect_hb(const SyncClassifyConfig *cfg)
{
    if (cfg && cfg->detect_hb_edges != -1) {
        return cfg->detect_hb_edges != 0;
    }
    return SYNC_DETECT_HB_EDGES != 0;
}

static inline uint32_t sc_spin_min_iter(const SyncClassifyConfig *cfg)
{
    if (cfg && cfg->spin_min_iterations > 0) {
        return cfg->spin_min_iterations;
    }
    return SPIN_MIN_ITERATIONS;
}

static inline uint32_t sc_spin_max_addrs(const SyncClassifyConfig *cfg)
{
    if (cfg && cfg->spin_max_distinct_addrs > 0) {
        return cfg->spin_max_distinct_addrs;
    }
    return SPIN_MAX_DISTINCT_ADDRS;
}

static inline uint32_t sc_cs_max_gap(const SyncClassifyConfig *cfg)
{
    if (cfg && cfg->cs_max_gap_segs > 0) {
        return cfg->cs_max_gap_segs;
    }
    return CRITICAL_SECTION_MAX_GAP_SEGS;
}

static inline uint32_t sc_barrier_min_threads(const SyncClassifyConfig *cfg)
{
    if (cfg && cfg->barrier_min_threads > 0) {
        return cfg->barrier_min_threads;
    }
    return BARRIER_MIN_THREADS;
}

static inline uint32_t sc_barrier_max_span(const SyncClassifyConfig *cfg)
{
    if (cfg && cfg->barrier_max_cluster_span > 0) {
        return cfg->barrier_max_cluster_span;
    }
    return BARRIER_MAX_CLUSTER_SPAN;
}

static inline bool sc_hb_release_acquire(const SyncClassifyConfig *cfg)
{
    if (cfg && cfg->hb_release_acquire != -1) {
        return cfg->hb_release_acquire != 0;
    }
    return HB_EDGE_RELEASE_ACQUIRE_ENABLED != 0;
}

static inline bool sc_hb_spawn(const SyncClassifyConfig *cfg)
{
    if (cfg && cfg->hb_spawn != -1) {
        return cfg->hb_spawn != 0;
    }
    return HB_EDGE_SPAWN_ENABLED != 0;
}

static inline bool sc_hb_barrier(const SyncClassifyConfig *cfg)
{
    if (cfg && cfg->hb_barrier != -1) {
        return cfg->hb_barrier != 0;
    }
    return HB_EDGE_BARRIER_ENABLED != 0;
}


/* =========================================================================
 * Section 5: Default Config Initializer
 * ========================================================================= */

static inline SyncClassifyConfig sync_classify_config_default(void)
{
    SyncClassifyConfig cfg;
    memset(&cfg, 0, sizeof(cfg));

    /* -1 = use compile-time default for all tristate enables */
    cfg.detect_spin_acquire    = -1;
    cfg.detect_critical_section = -1;
    cfg.detect_release         = -1;
    cfg.detect_barrier_wait    = -1;
    cfg.detect_hb_edges        = -1;
    cfg.hb_release_acquire     = -1;
    cfg.hb_spawn               = -1;
    cfg.hb_barrier             = -1;

    /* 0 = use compile-time default for all thresholds */
    cfg.spin_min_iterations    = 0;
    cfg.spin_max_distinct_addrs = 0;
    cfg.cs_max_gap_segs        = 0;
    cfg.barrier_min_threads    = 0;
    cfg.barrier_max_cluster_span = 0;

    return cfg;
}


/* =========================================================================
 * Section 6: Segment Directory Helpers
 *
 * These operate on the SegmentDirEntry struct defined in wptrace.c.
 * To avoid a circular dependency, the classifier accesses entries
 * through a minimal interface struct.
 * ========================================================================= */

/*
 * Lightweight view of a segment directory entry.
 * The classifier reads this; it does not own the data.
 */
typedef struct {
    uint32_t    thread_id;
    uint64_t    body_bit_offset;
    uint32_t    num_entries;
    uint8_t     flags;           /* bit 0 = is_atomic */
    uint32_t    num_atomic_addrs;
    uint64_t   *atomic_addrs;    /* array of addresses, num_atomic_addrs long */
} SyncSegView;

/*
 * Result structure: the classifier fills this in and the caller
 * (wptrace.c) uses it to update SegmentDirEntry fields and emit
 * the footer tables.
 */
typedef struct {
    /* Per-segment outputs (parallel array, one per segment) */
    uint8_t   *seg_flags;        /* extended flags to OR into each segment */
    GArray   **seg_hb_edges;     /* GArray of HBEdge per segment (or NULL) */

    /* Detected sync regions */
    GArray    *regions;          /* GArray of SyncRegionInfo */
} SyncClassifyResult;


/* =========================================================================
 * Section 7: Internal Helpers
 * ========================================================================= */

/*
 * Get the single atomic address from a segment view, or 0 if the
 * segment has 0 or >1 addresses.
 */
static inline uint64_t seg_single_addr(const SyncSegView *sv)
{
    if (sv->num_atomic_addrs == 1) {
        return sv->atomic_addrs[0];
    }
    return 0;
}

/*
 * Check if a segment view contains a specific address.
 */
static inline bool seg_has_addr(const SyncSegView *sv, uint64_t addr)
{
    for (uint32_t i = 0; i < sv->num_atomic_addrs; i++) {
        if (sv->atomic_addrs[i] == addr) {
            return true;
        }
    }
    return false;
}

/*
 * Append an HB edge to a segment's edge list, allocating the GArray
 * on first use.
 */
static inline void add_hb_edge(GArray **edges_arr, uint32_t pred_idx,
                               HBEdgeType edge_type)
{
    if (*edges_arr == NULL) {
        *edges_arr = g_array_new(FALSE, FALSE, sizeof(HBEdge));
    }
    HBEdge e = { .pred_seg_idx = pred_idx, .edge_type = edge_type };
    g_array_append_val(*edges_arr, e);
}


/* =========================================================================
 * Section 8: Finalize a Spin-Wait Run
 * ========================================================================= */

static void finalize_spin_run(ThreadSyncState *tstate,
                              SyncSegView *segs,
                              SyncClassifyResult *result,
                              const SyncClassifyConfig *cfg)
{
    if (tstate->spin_run_count < sc_spin_min_iter(cfg)) {
        tstate->spin_run_count = 0;
        return;
    }

    /* Mark all segments in the run as spin-wait */
    for (uint32_t j = tstate->spin_run_start;
         j < tstate->spin_run_start + tstate->spin_run_count; j++) {
        result->seg_flags[j] |= SEG_FLAG_SPIN_WAIT;
    }

    /* Emit a SPIN_ACQUIRE region */
    SyncRegionInfo region = {
        .type            = SYNC_REGION_SPIN_ACQUIRE,
        .outcome         = SYNC_OUTCOME_ACQUIRED,
        .sync_addr       = tstate->last_atomic_addr,
        .thread_id       = segs[tstate->spin_run_start].thread_id,
        .begin_seg_idx   = tstate->spin_run_start,
        .end_seg_idx     = tstate->spin_run_start + tstate->spin_run_count - 1,
        .iteration_count = tstate->spin_run_count,
    };
    g_array_append_val(result->regions, region);

    tstate->spin_run_count = 0;
}


/* =========================================================================
 * Section 9: Main Classification Entry Point
 *
 * sync_classify_segments()
 *
 * Arguments:
 *   segs       — array of SyncSegView, one per segment, in body order
 *   num_segs   — number of segments
 *   cfg        — configuration (NULL for all compile-time defaults)
 *
 * Returns:
 *   SyncClassifyResult* — caller must free with sync_classify_result_free()
 *
 * This function performs a single linear pass over the segment directory
 * to detect spin-waits, critical sections, releases, and barriers.
 * A second pass generates happens-before edges.
 * ========================================================================= */

static SyncClassifyResult *sync_classify_segments(
    SyncSegView *segs, uint32_t num_segs,
    const SyncClassifyConfig *cfg)
{
    SyncClassifyResult *result = g_new0(SyncClassifyResult, 1);
    result->seg_flags   = g_new0(uint8_t, num_segs);
    result->seg_hb_edges = g_new0(GArray *, num_segs);
    result->regions     = g_array_new(FALSE, FALSE, sizeof(SyncRegionInfo));

    if (num_segs == 0) {
        return result;
    }

    /* Determine the maximum thread_id to size per-thread state */
    uint32_t max_tid = 0;
    for (uint32_t i = 0; i < num_segs; i++) {
        if (segs[i].thread_id > max_tid) {
            max_tid = segs[i].thread_id;
        }
    }
    uint32_t num_threads = max_tid + 1;
    ThreadSyncState *tstate = g_new0(ThreadSyncState, num_threads);

    for (uint32_t t = 0; t < num_threads; t++) {
        tstate[t].seen = false;
        tstate[t].in_critical_section = false;
        tstate[t].spin_run_count = 0;
    }

    /*
     * ---------------------------------------------------------------
     * Pass 1: Spin-wait, critical section, and release detection
     * ---------------------------------------------------------------
     */
    for (uint32_t i = 0; i < num_segs; i++) {
        const SyncSegView *sv = &segs[i];
        uint32_t tid = sv->thread_id;
        ThreadSyncState *ts = &tstate[tid];

        /* Record first segment per thread (for spawn edges) */
        if (!ts->seen) {
            ts->first_seg_idx = i;
            ts->seen = true;
        }

        bool is_atomic = (sv->flags & SEG_FLAG_ATOMIC) != 0;

        if (is_atomic && sc_detect_spin(cfg)) {
            uint64_t single = seg_single_addr(sv);
            bool few_addrs = sv->num_atomic_addrs <= sc_spin_max_addrs(cfg);

            if (few_addrs && single != 0 &&
                single == ts->last_atomic_addr &&
                ts->spin_run_count > 0) {
                /* Continue existing spin run */
                ts->spin_run_count++;
            } else {
                /* New address or too many addrs — finalize any pending run */
                finalize_spin_run(ts, segs, result, cfg);

                ts->spin_run_start = i;
                ts->spin_run_count = 1;
                ts->last_atomic_addr = single;
            }
            ts->last_atomic_seg_idx = i;

        } else {
            /* Non-atomic segment (or spin detection disabled) */
            if (ts->spin_run_count > 0 && sc_detect_spin(cfg)) {
                /*
                 * The spin run just ended.  The previous atomic segment
                 * was the last retry; THIS non-atomic segment is the
                 * start of the critical section (if the last atomic
                 * segment was a successful acquire).
                 */
                uint32_t run_end = ts->spin_run_start + ts->spin_run_count - 1;
                finalize_spin_run(ts, segs, result, cfg);

                /* Mark the segment after the spin run as an acquire */
                if (run_end + 1 < num_segs &&
                    segs[run_end + 1].thread_id == tid &&
                    (segs[run_end + 1].flags & SEG_FLAG_ATOMIC)) {
                    result->seg_flags[run_end + 1] |= SEG_FLAG_ACQUIRE;
                }

                /* Open a critical section */
                if (sc_detect_cs(cfg)) {
                    ts->in_critical_section = true;
                    ts->cs_lock_addr = ts->last_atomic_addr;
                    ts->cs_start_seg_idx = i;
                    ts->cs_acquire_seg_idx = run_end;
                }
            }
        }

        /* Check for critical section release */
        if (ts->in_critical_section && is_atomic && sc_detect_release(cfg)) {
            if (seg_has_addr(sv, ts->cs_lock_addr)) {
                /* This atomic access to the lock addr is the release */
                result->seg_flags[i] |= SEG_FLAG_RELEASE;

                /* Emit CRITICAL_SECTION region */
                SyncRegionInfo cs_region = {
                    .type          = SYNC_REGION_CRITICAL_SECTION,
                    .outcome       = SYNC_OUTCOME_ACQUIRED,
                    .sync_addr     = ts->cs_lock_addr,
                    .thread_id     = tid,
                    .begin_seg_idx = ts->cs_start_seg_idx,
                    .end_seg_idx   = i - 1,
                    .iteration_count = 0,
                };
                g_array_append_val(result->regions, cs_region);

                /* Emit RELEASE region (single segment) */
                SyncRegionInfo rel_region = {
                    .type          = SYNC_REGION_RELEASE,
                    .outcome       = SYNC_OUTCOME_RELEASED,
                    .sync_addr     = ts->cs_lock_addr,
                    .thread_id     = tid,
                    .begin_seg_idx = i,
                    .end_seg_idx   = i,
                    .iteration_count = 0,
                };
                g_array_append_val(result->regions, rel_region);

                ts->in_critical_section = false;
            }
            /* Check for CS timeout (too many segments without release) */
            else if (i - ts->cs_start_seg_idx > sc_cs_max_gap(cfg)) {
                ts->in_critical_section = false;
            }
        }
    }

    /* Finalize any still-open spin runs at end of trace */
    for (uint32_t t = 0; t < num_threads; t++) {
        if (tstate[t].spin_run_count > 0) {
            finalize_spin_run(&tstate[t], segs, result, cfg);
        }
    }

    /*
     * ---------------------------------------------------------------
     * Pass 2: Barrier detection
     *
     * Build a map of atomic address → list of (thread_id, seg_idx).
     * Addresses accessed by >= BARRIER_MIN_THREADS distinct threads
     * with spin-wait runs on them are candidate barriers.
     * ---------------------------------------------------------------
     */
    if (sc_detect_barrier(cfg)) {
        /* addr → GArray of {tid, seg_idx} */
        GHashTable *addr_map = g_hash_table_new_full(
            g_int64_hash, g_int64_equal, g_free, (GDestroyNotify)g_array_unref);

        for (uint32_t i = 0; i < num_segs; i++) {
            if (!(segs[i].flags & SEG_FLAG_ATOMIC)) {
                continue;
            }
            for (uint32_t a = 0; a < segs[i].num_atomic_addrs; a++) {
                uint64_t addr = segs[i].atomic_addrs[a];
                uint64_t *key = g_new(uint64_t, 1);
                *key = addr;

                GArray *entries = g_hash_table_lookup(addr_map, key);
                if (!entries) {
                    entries = g_array_new(FALSE, FALSE,
                                         sizeof(uint64_t) * 2); /* [tid, idx] */
                    g_hash_table_insert(addr_map, key, entries);
                } else {
                    g_free(key);
                }
                uint64_t pair[2] = { segs[i].thread_id, i };
                g_array_append_vals(entries, pair, 1);
            }
        }

        GHashTableIter iter;
        gpointer k, v;
        g_hash_table_iter_init(&iter, addr_map);
        while (g_hash_table_iter_next(&iter, &k, &v)) {
            GArray *entries = v;
            if (entries->len < 2) {
                continue;
            }

            /* Count distinct threads */
            GHashTable *tids = g_hash_table_new(g_direct_hash, g_direct_equal);
            uint32_t min_idx = UINT32_MAX, max_idx = 0;

            for (guint e = 0; e < entries->len; e++) {
                uint64_t *pair = &g_array_index(entries, uint64_t, e * 2);
                uint32_t t = (uint32_t)pair[0];
                uint32_t idx = (uint32_t)pair[1];
                g_hash_table_add(tids, GUINT_TO_POINTER(t + 1));
                if (idx < min_idx) min_idx = idx;
                if (idx > max_idx) max_idx = idx;
            }

            uint32_t n_tids = g_hash_table_size(tids);
            uint32_t span = max_idx - min_idx;

            if (n_tids >= sc_barrier_min_threads(cfg) &&
                span <= sc_barrier_max_span(cfg)) {
                /*
                 * Reclassify any SPIN_ACQUIRE regions on this address
                 * as BARRIER_WAIT.
                 */
                uint64_t addr = *(uint64_t *)k;
                for (guint r = 0; r < result->regions->len; r++) {
                    SyncRegionInfo *ri = &g_array_index(result->regions,
                                                        SyncRegionInfo, r);
                    if (ri->type == SYNC_REGION_SPIN_ACQUIRE &&
                        ri->sync_addr == addr) {
                        ri->type = SYNC_REGION_BARRIER_WAIT;
                    }
                }

                /* Flag the segments */
                for (guint e = 0; e < entries->len; e++) {
                    uint64_t *pair = &g_array_index(entries, uint64_t, e * 2);
                    uint32_t idx = (uint32_t)pair[1];
                    result->seg_flags[idx] |= SEG_FLAG_BARRIER;
                }
            }

            g_hash_table_unref(tids);
        }

        g_hash_table_unref(addr_map);
    }

    /*
     * ---------------------------------------------------------------
     * Pass 3: Happens-before edge generation
     * ---------------------------------------------------------------
     */
    if (sc_detect_hb(cfg)) {
        /* 3a: Spawn edges — first segment of each thread T>0 gets an
         *     HB edge from the preceding segment of a different thread. */
        if (sc_hb_spawn(cfg)) {
            for (uint32_t t = 0; t < num_threads; t++) {
                if (!tstate[t].seen || tstate[t].first_seg_idx == 0) {
                    continue;
                }
                uint32_t first = tstate[t].first_seg_idx;
                /* The segment immediately before this thread's first
                 * appearance is from the parent thread. */
                if (first > 0) {
                    add_hb_edge(&result->seg_hb_edges[first],
                                first - 1, HB_SPAWN);
                }
            }
        }

        /* 3b: Release → Acquire edges.
         *     For each address, track the most recent RELEASE segment.
         *     When a different thread next accesses the same address
         *     (acquire), add an HB edge. */
        if (sc_hb_release_acquire(cfg)) {
            /* addr → last release seg_idx */
            GHashTable *last_release = g_hash_table_new_full(
                g_int64_hash, g_int64_equal, g_free, g_free);

            for (uint32_t i = 0; i < num_segs; i++) {
                if (!(segs[i].flags & SEG_FLAG_ATOMIC)) {
                    continue;
                }

                bool is_release = (result->seg_flags[i] & SEG_FLAG_RELEASE) != 0;
                uint32_t tid = segs[i].thread_id;

                for (uint32_t a = 0; a < segs[i].num_atomic_addrs; a++) {
                    uint64_t addr = segs[i].atomic_addrs[a];

                    if (is_release) {
                        /* Record this as the latest release on addr */
                        uint64_t *key = g_new(uint64_t, 1);
                        *key = addr;
                        uint64_t *val = g_new(uint64_t, 1);
                        /* Pack seg_idx and thread_id */
                        *val = ((uint64_t)tid << 32) | i;
                        g_hash_table_insert(last_release, key, val);
                    } else {
                        /* Check for a preceding release from another thread */
                        uint64_t *prev = g_hash_table_lookup(last_release,
                                                             &addr);
                        if (prev) {
                            uint32_t rel_tid = (uint32_t)(*prev >> 32);
                            uint32_t rel_idx = (uint32_t)(*prev & 0xFFFFFFFF);
                            if (rel_tid != tid) {
                                add_hb_edge(&result->seg_hb_edges[i],
                                            rel_idx, HB_RELEASE_ACQUIRE);
                            }
                        }
                    }
                }
            }

            g_hash_table_unref(last_release);
        }

        /* 3c: Barrier HB edges.
         *     For each barrier region, the last barrier-increment segment
         *     from each thread gets edges to all other threads' first
         *     post-barrier segments. */
        if (sc_hb_barrier(cfg)) {
            for (guint r = 0; r < result->regions->len; r++) {
                SyncRegionInfo *ri = &g_array_index(result->regions,
                                                    SyncRegionInfo, r);
                if (ri->type != SYNC_REGION_BARRIER_WAIT) {
                    continue;
                }

                /*
                 * Collect the last barrier segment per thread in the
                 * region's span.
                 */
                GHashTable *last_per_thread = g_hash_table_new(
                    g_direct_hash, g_direct_equal);

                for (uint32_t j = ri->begin_seg_idx;
                     j <= ri->end_seg_idx && j < num_segs; j++) {
                    if (segs[j].flags & SEG_FLAG_ATOMIC) {
                        g_hash_table_insert(last_per_thread,
                            GUINT_TO_POINTER(segs[j].thread_id + 1),
                            GUINT_TO_POINTER(j + 1));
                    }
                }

                /*
                 * For each pair (t1, t2), the segment after t1's last
                 * barrier seg gets an HB edge from t2's last barrier seg
                 * (and vice versa).
                 */
                GHashTableIter it1, it2;
                gpointer k1, v1, k2, v2;

                g_hash_table_iter_init(&it1, last_per_thread);
                while (g_hash_table_iter_next(&it1, &k1, &v1)) {
                    uint32_t seg1 = GPOINTER_TO_UINT(v1) - 1;

                    /* Find the first post-barrier segment for this thread */
                    uint32_t post1 = seg1 + 1;
                    uint32_t tid1 = GPOINTER_TO_UINT(k1) - 1;
                    while (post1 < num_segs &&
                           segs[post1].thread_id != tid1) {
                        post1++;
                    }
                    if (post1 >= num_segs) continue;

                    g_hash_table_iter_init(&it2, last_per_thread);
                    while (g_hash_table_iter_next(&it2, &k2, &v2)) {
                        if (k1 == k2) continue; /* skip self */
                        uint32_t seg2 = GPOINTER_TO_UINT(v2) - 1;
                        add_hb_edge(&result->seg_hb_edges[post1],
                                    seg2, HB_BARRIER);
                    }
                }

                g_hash_table_unref(last_per_thread);
            }
        }
    }

    g_free(tstate);
    return result;
}


/* =========================================================================
 * Section 10: Result Cleanup
 * ========================================================================= */

static void sync_classify_result_free(SyncClassifyResult *result,
                                      uint32_t num_segs)
{
    if (!result) return;

    g_free(result->seg_flags);

    if (result->seg_hb_edges) {
        for (uint32_t i = 0; i < num_segs; i++) {
            if (result->seg_hb_edges[i]) {
                g_array_unref(result->seg_hb_edges[i]);
            }
        }
        g_free(result->seg_hb_edges);
    }

    if (result->regions) {
        g_array_unref(result->regions);
    }

    g_free(result);
}


#endif /* WPTRACE_SYNC_CLASSIFY_H */
