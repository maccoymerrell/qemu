/*
 * Wrong-Path Tracing Plugin — register-handle cache implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "champsim_tracer_reg_handle_cache.h"

RegHandleCache g_reg_handle_cache;

thread_local RegHandleCache::VCPUCache *RegHandleCache::tls_cache_
    CST_TLS_HOT = nullptr;
thread_local unsigned int RegHandleCache::tls_cache_cpu_index_
    CST_TLS_HOT = (unsigned int)-1;

thread_local RegHandleCache::TlsPtrEntry *RegHandleCache::tls_ptr_cache_
    CST_TLS_HOT = nullptr;
thread_local unsigned int RegHandleCache::tls_ptr_cache_cpu_index_
    CST_TLS_HOT = (unsigned int)-1;

namespace {

bool key_valid(const QemuRegKey *key)
{
    return key && key->name;
}

unsigned int key_hash(const void * data)
{
    const QemuRegKey *key = (const QemuRegKey *)data;
    const char *feature = key->feature ? key->feature : "";
    const char *name = key->name ? key->name : "";
    return g_str_hash(feature) ^ (g_str_hash(name) << 1);
}

/* GEqualFunc returns int (gboolean). */
int key_equal(const void *lhs, const void *rhs)
{
    const QemuRegKey *a = (const QemuRegKey *)lhs;
    const QemuRegKey *b = (const QemuRegKey *)rhs;
    return cst_str_eq(a->feature, b->feature) &&
           cst_str_eq(a->name, b->name);
}

void key_free(void * data)
{
    QemuRegKey *key = (QemuRegKey *)data;
    if (!key) {
        return;
    }
    g_free((char *)key->feature);
    g_free((char *)key->name);
    g_free(key);
}

void cache_insert(GHashTable *handles,
                  const char *feature, const char *name,
                  struct qemu_plugin_register *handle)
{
    if (!handles || !name || !handle) {
        return;
    }
    QemuRegKey *key = g_new(QemuRegKey, 1);
    key->feature = g_strdup(feature);
    key->name = g_strdup(name);
    g_hash_table_insert(handles, key, handle);
}

} /* namespace */

RegHandleCache::VCPUCache::VCPUCache()
    : handles(g_hash_table_new_full(key_hash, key_equal, key_free, nullptr))
{
}

RegHandleCache::VCPUCache::~VCPUCache()
{
    if (handles) {
        g_hash_table_destroy(handles);
    }
}

RegHandleCache::RegHandleCache()
{
    g_mutex_init(&lock_);
}

RegHandleCache::~RegHandleCache()
{
    g_mutex_clear(&lock_);
}

void RegHandleCache::populate_cache(VCPUCache &cache)
{
    RegAliasInserterFn alias_inserter =
        isa_properties[trace_isa].reg_alias_inserter;
    g_autoptr(GArray) regs = qemu_plugin_get_registers();
    for (unsigned int i = 0; i < regs->len; i++) {
        const qemu_plugin_reg_descriptor *desc =
            &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        cache_insert(cache.handles, desc->feature, desc->name, desc->handle);
        if (alias_inserter) {
            alias_inserter(cache.handles, desc);
        }
    }
}

RegHandleCache::VCPUCache *RegHandleCache::get_or_create(unsigned int cpu_index)
{
    if (tls_cache_ && tls_cache_cpu_index_ == cpu_index) {
        return tls_cache_;
    }

    g_mutex_lock(&lock_);
    if (cpu_index >= vcpu_caches_.size()) {
        vcpu_caches_.resize(cpu_index + 1);
    }
    if (!vcpu_caches_[cpu_index]) {
        vcpu_caches_[cpu_index] = std::make_unique<VCPUCache>();
        populate_cache(*vcpu_caches_[cpu_index]);
    }
    VCPUCache *cache = vcpu_caches_[cpu_index].get();
    g_mutex_unlock(&lock_);

    tls_cache_ = cache;
    tls_cache_cpu_index_ = cpu_index;
    return cache;
}

void RegHandleCache::ensure_initialized(unsigned int cpu_index)
{
    (void)get_or_create(cpu_index);
}

struct qemu_plugin_register *RegHandleCache::lookup(unsigned int cpu_index,
                                                    const QemuRegKey *key)
{
    if (!key_valid(key)) {
        return nullptr;
    }

    /* Direct-mapped cache by key-pointer identity: the same QemuRegKey
     * instance recurs per template run, so hot loops hit after warm-up.
     * The table is a heap block reached through a thread_local pointer
     * (see header); allocate it on first use, invalidate on cpu_index
     * change. */
    TlsPtrEntry *ptab = tls_ptr_cache_;
    if (!ptab) {
        ptab = new TlsPtrEntry[TLS_PTR_CACHE_SIZE]();
        tls_ptr_cache_ = ptab;
        tls_ptr_cache_cpu_index_ = cpu_index;
    } else if (tls_ptr_cache_cpu_index_ != cpu_index) {
        memset(ptab, 0, sizeof(TlsPtrEntry) * TLS_PTR_CACHE_SIZE);
        tls_ptr_cache_cpu_index_ = cpu_index;
    }
    unsigned int slot = (unsigned int)(((uintptr_t)key) >> 4)
                        & (TLS_PTR_CACHE_SIZE - 1);
    TlsPtrEntry *e = &ptab[slot];
    if (e->key == key) {
        return e->handle;
    }

    VCPUCache *cache = get_or_create(cpu_index);
    struct qemu_plugin_register *handle =
        (struct qemu_plugin_register *)g_hash_table_lookup(cache->handles, key);
    e->key = key;
    e->handle = handle;
    return handle;
}

bool cst_reg_read_u64(unsigned cpu_index, const QemuRegKey *key, uint64_t *out)
{
    if (!key || !out || !key->feature || !key->name) return false;
    struct qemu_plugin_register *handle =
        g_reg_handle_cache.lookup(cpu_index, key);
    if (!handle) return false;
    GByteArray *buf = g_byte_array_new();
    int n = qemu_plugin_read_register(handle, buf);
    bool ok = false;
    if (n > 0) {
        cst_normalize_reg_bytes_to_le(buf->data, (size_t)n);
        uint64_t v = 0;
        size_t take = (size_t)n < sizeof(v) ? (size_t)n : sizeof(v);
        memcpy(&v, buf->data, take);
        *out = v;
        ok = true;
    }
    g_byte_array_unref(buf);
    return ok;
}
