/*
 * Wrong-Path Tracing Plugin — register-handle cache implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "champsim_tracer_reg_handle_cache.h"

RegHandleCache g_reg_handle_cache;

thread_local RegHandleCache::VCPUCache *RegHandleCache::tls_cache_ = nullptr;
thread_local unsigned int RegHandleCache::tls_cache_cpu_index_ = (unsigned int)-1;

namespace {

bool key_valid(const QemuRegKey *key)
{
    return key && key->name;
}

guint key_hash(gconstpointer data)
{
    const QemuRegKey *key = (const QemuRegKey *)data;
    const char *feature = key->feature ? key->feature : "";
    const char *name = key->name ? key->name : "";
    return g_str_hash(feature) ^ (g_str_hash(name) << 1);
}

gboolean key_equal(gconstpointer lhs, gconstpointer rhs)
{
    const QemuRegKey *a = (const QemuRegKey *)lhs;
    const QemuRegKey *b = (const QemuRegKey *)rhs;
    return g_strcmp0(a->feature, b->feature) == 0 &&
           g_strcmp0(a->name, b->name) == 0;
}

void key_free(gpointer data)
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

bool parse_numbered_reg(const char *name, char prefix,
                        unsigned int limit, unsigned int *num)
{
    char *end = nullptr;
    if (!name || name[0] != prefix || !g_ascii_isdigit(name[1])) {
        return false;
    }
    guint64 value = g_ascii_strtoull(name + 1, &end, 10);
    if (!end || *end || value >= limit) {
        return false;
    }
    *num = (unsigned int)value;
    return true;
}

void insert_aarch64_aliases(GHashTable *handles,
                            const qemu_plugin_reg_descriptor *desc)
{
    static const char fpu_feature[] = "org.gnu.gdb.aarch64.fpu";
    static const char sve_feature[] = "org.gnu.gdb.aarch64.sve";

    if (trace_isa != TRACE_ISA_AARCH64 ||
        g_strcmp0(desc->feature, sve_feature) != 0) {
        return;
    }

    unsigned int num;
    if (parse_numbered_reg(desc->name, 'z', 32, &num)) {
        char alias[8];
        g_snprintf(alias, sizeof(alias), "v%u", num);
        cache_insert(handles, fpu_feature, alias, desc->handle);
    } else if (g_strcmp0(desc->name, "fpsr") == 0 ||
               g_strcmp0(desc->name, "fpcr") == 0) {
        cache_insert(handles, fpu_feature, desc->name, desc->handle);
    }
}

} /* namespace */

RegHandleCache::RegHandleCache()
    : vcpu_caches_(nullptr)
{
    g_mutex_init(&lock_);
}

RegHandleCache::~RegHandleCache()
{
    if (vcpu_caches_) {
        g_ptr_array_unref(vcpu_caches_);
    }
    g_mutex_clear(&lock_);
}

void RegHandleCache::destroy_cache(gpointer data)
{
    VCPUCache *cache = (VCPUCache *)data;
    if (!cache) {
        return;
    }
    g_hash_table_destroy(cache->handles);
    g_free(cache);
}

RegHandleCache::VCPUCache *RegHandleCache::make_cache()
{
    VCPUCache *cache = g_new0(VCPUCache, 1);
    cache->handles = g_hash_table_new_full(key_hash, key_equal,
                                           key_free, nullptr);

    g_autoptr(GArray) regs = qemu_plugin_get_registers();
    for (guint i = 0; i < regs->len; i++) {
        const qemu_plugin_reg_descriptor *desc =
            &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        cache_insert(cache->handles, desc->feature, desc->name, desc->handle);
        insert_aarch64_aliases(cache->handles, desc);
    }
    return cache;
}

RegHandleCache::VCPUCache *RegHandleCache::get_or_create(unsigned int cpu_index)
{
    if (tls_cache_ && tls_cache_cpu_index_ == cpu_index) {
        return tls_cache_;
    }

    VCPUCache *cache = nullptr;
    g_mutex_lock(&lock_);
    if (!vcpu_caches_) {
        vcpu_caches_ = g_ptr_array_new_with_free_func(&destroy_cache);
    }
    if (cpu_index < vcpu_caches_->len) {
        cache = (VCPUCache *)g_ptr_array_index(vcpu_caches_, cpu_index);
    }
    if (!cache) {
        cache = make_cache();
        while (vcpu_caches_->len <= cpu_index) {
            g_ptr_array_add(vcpu_caches_, nullptr);
        }
        g_ptr_array_index(vcpu_caches_, cpu_index) = cache;
    }
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
    VCPUCache *cache = get_or_create(cpu_index);
    return (struct qemu_plugin_register *)g_hash_table_lookup(cache->handles,
                                                              key);
}
