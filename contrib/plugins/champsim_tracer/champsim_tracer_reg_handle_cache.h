/*
 * Wrong-Path Tracing Plugin — per-vCPU register-handle cache.
 *
 * Caches the (feature, name) -> qemu_plugin_register* lookup needed on
 * every reg-data capture.  Cached per-vCPU (each vCPU has its own
 * handle space) and per-thread (MRU per-vCPU cache in TLS so the
 * common case avoids the lock).  Entries populated lazily.
 *
 * AArch64 SVE z-registers are aliased to FPU v-registers because
 * Capstone reports v-names but QEMU may register only the SVE
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
    /* Inner GHashTable maps (feature, name) -> qemu_plugin_register*
     * via QemuRegKey keys (hash/equal/free in the .cc).  glib hash
     * kept over std::unordered_map to avoid allocation-per-lookup
     * absent C++20 heterogeneous lookup. */
    struct VCPUCache {
        GHashTable *handles = nullptr;
        VCPUCache();
        ~VCPUCache();
        VCPUCache(const VCPUCache &) = delete;
        VCPUCache &operator=(const VCPUCache &) = delete;
    };

    /* Per-vCPU caches indexed by cpu_index; empty slots stay null
     * until a vCPU first calls in. */
    std::vector<std::unique_ptr<VCPUCache>> vcpu_caches_;
    GMutex                                  lock_;

    /* Hot-path TLS shortcut for the most-recent (cpu_index, cache) pair. */
    static thread_local VCPUCache    *tls_cache_ CST_TLS_HOT;
    static thread_local unsigned int  tls_cache_cpu_index_ CST_TLS_HOT;

    /* Hot-path TLS direct-mapped cache, keyed by const QemuRegKey *
     * pointer identity (one instance per BBTemplate InsnRegNames, so
     * re-running a template passes the same pointer).  Index = low
     * bits of the pointer.  Hits skip the GHashTable + g_str_hash +
     * strcmp chain (~7-9% of plugin time on register-heavy workloads
     * with reg-data on). */
    enum { TLS_PTR_CACHE_SIZE = 256 };
    struct TlsPtrEntry {
        const QemuRegKey            *key;
        struct qemu_plugin_register *handle;
    };
    /* The cache table (~4 KiB) lives on the heap, reached through a
     * thread_local pointer, rather than as an inline thread_local
     * array.  A single IE-model thread_local forces the loader to
     * place this module's ENTIRE TLS segment into the finite static-TLS
     * surplus; keeping a 4 KiB array there would overflow it and break
     * dlopen.  The pointer + cpu-index guard are tiny, so they stay in
     * TLS (and IE); the table they point at does not.  The block is
     * allocated lazily on first lookup per thread and intentionally
     * leaked at thread exit (vCPU threads live for the whole run). */
    static thread_local TlsPtrEntry *tls_ptr_cache_ CST_TLS_HOT;
    static thread_local unsigned int tls_ptr_cache_cpu_index_ CST_TLS_HOT;

    VCPUCache *get_or_create(unsigned int cpu_index);
    static void populate_cache(VCPUCache &cache);
};

extern RegHandleCache g_reg_handle_cache;

/* Read the low 8 bytes of the named register on @cpu_index, host-
 * endian.  Returns true and writes *out on success; false on lookup
 * or read failure.  Used by the lane_mask runtime dispatch in
 * champsim_tracer_output.cc to read CSRs like RISC-V vtype.VL or
 * x86 EVEX k-registers at field-delta emit time. */
bool cst_reg_read_u64(unsigned cpu_index, const QemuRegKey *key,
                      uint64_t *out);

#endif /* CHAMPSIM_TRACER_REG_HANDLE_CACHE_H */
