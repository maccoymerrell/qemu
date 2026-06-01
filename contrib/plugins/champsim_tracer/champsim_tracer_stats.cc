/*
 * Wrong-Path Tracing Plugin — per-thread stats accumulator and registry.
 *
 * Each thread bumps its own thread-local Stats slot via the `g_stats`
 * macro.  First touch heap-allocates the slot and registers it under
 * stats_registry_lock; later bumps are unsynchronized TLS stores.
 *
 * stats_snapshot() sums the live registry plus a graveyard
 * accumulator (contributions of cleanly-exited threads).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <vector>

#include "champsim_tracer_stats.h"

namespace {

GMutex stats_registry_lock;
std::vector<Stats *> stats_registry;
Stats stats_graveyard;  /* sums of threads that have exited */

void stats_add(Stats *dst, const Stats &src)
{
    static_assert(sizeof(Stats) % sizeof(uint64_t) == 0,
                  "Stats must be a packed array of uint64_t fields");
    uint64_t *pd = reinterpret_cast<uint64_t *>(dst);
    const uint64_t *ps = reinterpret_cast<const uint64_t *>(&src);
    size_t n = sizeof(Stats) / sizeof(uint64_t);
    for (size_t i = 0; i < n; i++) {
        pd[i] += ps[i];
    }
}

/* Per-thread owner: ctor heap-allocates + registers the Stats slot;
 * dtor folds it into the graveyard, unregisters, frees.  Heap (not a
 * thread_local Stats) keeps the registry pointer stable across
 * compiler TLS-layout optimizations. */
struct ThreadStats {
    Stats *slot;

    ThreadStats() : slot(new Stats{})
    {
        g_mutex_lock(&stats_registry_lock);
        stats_registry.push_back(slot);
        g_mutex_unlock(&stats_registry_lock);
    }

    ~ThreadStats()
    {
        g_mutex_lock(&stats_registry_lock);
        stats_add(&stats_graveyard, *slot);
        for (auto it = stats_registry.begin();
             it != stats_registry.end(); ++it) {
            if (*it == slot) {
                stats_registry.erase(it);
                break;
            }
        }
        g_mutex_unlock(&stats_registry_lock);
        delete slot;
    }
};

}  /* namespace */

Stats &thread_stats_get()
{
    static thread_local ThreadStats tls;
    return *tls.slot;
}

void stats_registry_reserve(size_t n)
{
    /*
     * Pre-size the registry on the calling thread (intended: the main
     * thread, at plugin install, while still single-threaded).
     *
     * Why this matters in system emulation: the registry grows lazily as
     * each thread first touches g_stats, so without this its backing
     * buffer is first allocated by whichever *vCPU* thread traces first —
     * landing in that thread's glibc per-thread malloc arena.  At
     * plugin_exit the main thread bumps g_stats (body_stream_finish), which
     * triggers a push_back; if that reallocates, the main thread relocates
     * and frees a buffer owned by a (possibly exited) vCPU arena ->
     * cross-arena free of a transient-arena chunk at teardown -> SIGSEGV /
     * "corrupted double-linked list".  In linux-user there is only one
     * thread/arena, so the bug never surfaced.
     *
     * Reserving once up front, on the main thread, keeps the buffer in the
     * main arena and guarantees no reallocation for any realistic thread
     * count, so every later (lock-guarded) push_back advances in place.
     */
    g_mutex_lock(&stats_registry_lock);
    if (stats_registry.capacity() < n) {
        stats_registry.reserve(n);
    }
    g_mutex_unlock(&stats_registry_lock);
}

Stats stats_snapshot()
{
    Stats out{};
    g_mutex_lock(&stats_registry_lock);
    stats_add(&out, stats_graveyard);
    for (Stats *p : stats_registry) {
        stats_add(&out, *p);
    }
    g_mutex_unlock(&stats_registry_lock);
    return out;
}
