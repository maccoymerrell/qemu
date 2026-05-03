/*
 * Wrong-Path Tracing Plugin — per-vCPU register-handle cache.
 *
 * QEMU exposes register descriptors via qemu_plugin_get_registers(),
 * which returns one descriptor per readable architectural register on
 * the calling vCPU.  Reading a register through the plugin API takes a
 * descriptor handle, so on every reg-data capture the plugin needs to
 * map a (feature, name) key to the right handle.
 *
 * RegHandleCache caches that lookup, both per-vCPU (each vCPU has its
 * own handle space) and per-thread (the most recently used per-vCPU
 * cache is held in thread_local storage so the common case avoids the
 * lock).  Cache entries are populated lazily on first use.
 *
 * AArch64 SVE z-registers are aliased to FPU v-registers in the cache,
 * because Capstone reports v-names but QEMU may register only the SVE
 * descriptors.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_REG_HANDLE_CACHE_H
#define CHAMPSIM_TRACER_REG_HANDLE_CACHE_H

#include <memory>
#include <vector>

#include "champsim_tracer.h"

class RegHandleCache {
public:
    RegHandleCache();
    ~RegHandleCache();

    RegHandleCache(const RegHandleCache &) = delete;
    RegHandleCache &operator=(const RegHandleCache &) = delete;

    /* Look up the register handle for @key on @cpu_index.  Returns
     * nullptr if @key is invalid or QEMU does not expose the named
     * register.  Initializes the per-vCPU cache on first call. */
    struct qemu_plugin_register *lookup(unsigned int cpu_index,
                                        const QemuRegKey *key);

    /* Pre-warm the per-vCPU cache for @cpu_index.  Idempotent. */
    void ensure_initialized(unsigned int cpu_index);

private:
    /* The inner GHashTable maps (feature, name) -> qemu_plugin_register*
     * via QemuRegKey-pointer keys with custom hash/equal/free callbacks
     * defined in the .cc.  Hot path: one lookup per source register
     * per insn during reg-data capture, so we keep glib's hash here
     * rather than risk std::unordered_map's allocation-per-lookup
     * without C++20 heterogeneous lookup. */
    struct VCPUCache {
        GHashTable *handles = nullptr;
        VCPUCache();
        ~VCPUCache();
        VCPUCache(const VCPUCache &) = delete;
        VCPUCache &operator=(const VCPUCache &) = delete;
    };

    /* Per-vCPU caches indexed by cpu_index.  unique_ptr's auto cleanup
     * replaces the GPtrArray's free_func.  Empty slots stay null until
     * a vCPU first calls in. */
    std::vector<std::unique_ptr<VCPUCache>> vcpu_caches_;
    GMutex                                  lock_;

    /* Hot-path TLS shortcut for the most-recent (cpu_index, cache) pair. */
    static thread_local VCPUCache    *tls_cache_;
    static thread_local unsigned int  tls_cache_cpu_index_;

    /* Hot-path TLS direct-mapped cache.  Keyed by const QemuRegKey *
     * pointer identity (a single QemuRegKey instance lives in each
     * BBTemplate's InsnRegNames, so re-running the same template — the
     * common hot-loop case — passes the same pointer back).  Index is
     * the low bits of the pointer.  Hits avoid the GHashTable + the
     * g_str_hash + strcmp chain, which dominated reg-data-on profiles
     * (~7-9% of plugin time on register-heavy workloads). */
    enum { TLS_PTR_CACHE_SIZE = 256 };
    struct TlsPtrEntry {
        const QemuRegKey            *key;
        struct qemu_plugin_register *handle;
    };
    static thread_local TlsPtrEntry  tls_ptr_cache_[TLS_PTR_CACHE_SIZE];
    static thread_local unsigned int tls_ptr_cache_cpu_index_;

    VCPUCache *get_or_create(unsigned int cpu_index);
    static void populate_cache(VCPUCache &cache);
};

extern RegHandleCache g_reg_handle_cache;

#endif /* CHAMPSIM_TRACER_REG_HANDLE_CACHE_H */
