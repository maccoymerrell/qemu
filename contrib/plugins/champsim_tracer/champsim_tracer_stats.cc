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
