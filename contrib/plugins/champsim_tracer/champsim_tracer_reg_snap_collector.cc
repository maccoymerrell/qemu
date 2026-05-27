/*
 * Wrong-Path Tracing Plugin — register-value snapshot collector
 * implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>

#include "champsim_tracer_reg_handle_cache.h"
#include "champsim_tracer_reg_snap_collector.h"

RegSnapCollector g_reg_snaps;

namespace {

bool key_valid(const QemuRegKey *key)
{
    return key && key->name;
}

bool key_equal(const QemuRegKey *a, const QemuRegKey *b)
{
    return cst_str_eq(a->feature, b->feature) &&
           cst_str_eq(a->name, b->name);
}

typedef struct {
    QemuRegKey qemu_reg;
    RegSnap snap;
} WideRegEntry;

/* Per-thread scratch backing for the wide snap and the read buffer. */
thread_local GByteArray *tls_read_buf = nullptr;
thread_local WideRegEntry *tls_wide_entries = nullptr;
thread_local unsigned tls_wide_n = 0;
thread_local unsigned tls_wide_cap = 0;

GByteArray *read_scratch()
{
    if (!tls_read_buf) {
        /* Size the buffer up-front to the largest architectural reg
         * we ever read (vector reg widths: x86 ZMM=64, RVV vlen up
         * to 256, SVE Z up to 256 bytes).  Avoids the g_byte_array
         * realloc that fired on the first wide-reg read each thread
         * and again whenever the previous read had been narrower. */
        tls_read_buf = g_byte_array_sized_new(256);
    } else {
        g_byte_array_set_size(tls_read_buf, 0);
    }
    return tls_read_buf;
}

bool wide_contains(const QemuRegKey *qemu_reg)
{
    for (unsigned i = 0; i < tls_wide_n; i++) {
        if (key_equal(&tls_wide_entries[i].qemu_reg, qemu_reg)) {
            return true;
        }
    }
    return false;
}

void wide_lookup(const QemuRegKey *qemu_reg, RegSnap *out)
{
    cst_wide_zero(&out->value);
    if (!key_valid(qemu_reg)) {
        return;
    }
    for (unsigned i = 0; i < tls_wide_n; i++) {
        if (key_equal(&tls_wide_entries[i].qemu_reg, qemu_reg)) {
            *out = tls_wide_entries[i].snap;
            return;
        }
    }
}

} /* namespace */

/*
 * Opaque handle (forward-declared in champsim_tracer.h).  The wide snap
 * actually lives in tls_wide_* above; capture_wide() returns a pointer
 * to a thread_local sentinel of this type so the caller has something
 * opaque to null-check and pass back.
 */
struct _WideRegSnap {
    char unused;
};

static thread_local _WideRegSnap tls_wide_handle;

void RegSnapCollector::read_into_snap(unsigned int cpu_index,
                                      const QemuRegKey *qemu_reg,
                                      RegSnap *out)
{
    cst_wide_zero(&out->value);
    struct qemu_plugin_register *handle =
        g_reg_handle_cache.lookup(cpu_index, qemu_reg);
    if (!handle) {
        return;
    }
    GByteArray *buf = read_scratch();
    int n = qemu_plugin_read_register(handle, buf);
    if (n <= 0) {
        return;
    }
    cst_wide_from_le_bytes(&out->value, buf->data, (size_t)n);
}


WideRegSnap *RegSnapCollector::capture_wide(unsigned int cpu_index)
{
    if (!enable_reg_data) {
        return nullptr;
    }
    if (!active_reg_table || active_reg_table_size == 0) {
        return nullptr;
    }

    tls_wide_n = 0;
    for (unsigned i = 0; i < active_reg_table_size; i++) {
        const QemuRegKey *qemu_reg = &active_reg_table[i].qemu_reg;
        if (!key_valid(qemu_reg) || wide_contains(qemu_reg)) {
            continue;
        }
        if (tls_wide_n == tls_wide_cap) {
            tls_wide_cap = tls_wide_cap ? tls_wide_cap * 2 : 64;
            tls_wide_entries = g_renew(WideRegEntry, tls_wide_entries,
                                       tls_wide_cap);
        }
        unsigned slot = tls_wide_n++;
        tls_wide_entries[slot].qemu_reg = *qemu_reg;
        read_into_snap(cpu_index, qemu_reg,
                       &tls_wide_entries[slot].snap);
    }
    return tls_wide_n ? &tls_wide_handle : nullptr;
}

void RegSnapCollector::capture_insn_snaps(const WideRegSnap *wide,
                                          const BBTemplate *tmpl,
                                          uint32_t insn_idx,
                                          std::vector<RegSnap> &out_snaps)
{
    if (!enable_reg_data || !tmpl ||
        !tmpl->insn_reg_names || insn_idx >= tmpl->n_insns) {
        return;
    }
    (void)wide;  /* values come from the thread_local wide snap. */

    const InsnFields *f = &tmpl->insn_fields[insn_idx];
    const InsnRegNames *names = &tmpl->insn_reg_names[insn_idx];
    for (uint8_t i = 0; i < f->n_dst_regs; i++) {
        RegSnap s;
        wide_lookup(names->dst_qemu_reg_keys[i], &s);
        out_snaps.push_back(s);
    }
}

void RegSnapCollector::capture_insn_snaps_live(unsigned int cpu_index,
                                               const BBTemplate *tmpl,
                                               uint32_t insn_idx,
                                               std::vector<RegSnap> &out_snaps)
{
    /* Permit WP-only callers: champsim_tracer_wp.cc falls back to a
     * live read for the trailing insn of each WP fragment even when
     * CP regdata is off, so this gate must accept either flag. */
    if ((!enable_reg_data && !enable_wp_reg_data) || !tmpl ||
        !tmpl->insn_reg_names || insn_idx >= tmpl->n_insns) {
        return;
    }
    const InsnFields *f = &tmpl->insn_fields[insn_idx];
    const InsnRegNames *names = &tmpl->insn_reg_names[insn_idx];
    for (uint8_t i = 0; i < f->n_dst_regs; i++) {
        RegSnap s;
        read_into_snap(cpu_index, names->dst_qemu_reg_keys[i], &s);
        out_snaps.push_back(s);
    }
}

void RegSnapCollector::cleanup_current_thread()
{
    if (tls_read_buf) {
        g_byte_array_unref(tls_read_buf);
        tls_read_buf = nullptr;
    }
    g_free(tls_wide_entries);
    tls_wide_entries = nullptr;
    tls_wide_n = 0;
    tls_wide_cap = 0;
}
