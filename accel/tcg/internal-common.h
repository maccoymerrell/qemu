/*
 * Internal execution defines for qemu (target agnostic)
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef ACCEL_TCG_INTERNAL_COMMON_H
#define ACCEL_TCG_INTERNAL_COMMON_H

#include "exec/cpu-common.h"
#include "exec/translation-block.h"

extern int64_t max_delay;
extern int64_t max_advance;

extern bool one_insn_per_tb;

extern bool icount_align_option;

/*
 * Return true if CS is not running in parallel with other cpus, either
 * because there are no other cpus or we are within an exclusive context.
 */
static inline bool cpu_in_serial_context(CPUState *cs)
{
    return !tcg_cflags_has(cs, CF_PARALLEL) || cpu_in_exclusive_context(cs);
}

/**
 * cpu_plugin_mem_cbs_enabled() - are plugin memory callbacks enabled?
 * @cs: CPUState pointer
 *
 * The memory callbacks are installed if a plugin has instrumented an
 * instruction for memory. This can be useful to know if you want to
 * force a slow path for a series of memory accesses.
 */
static inline bool cpu_plugin_mem_cbs_enabled(const CPUState *cpu)
{
#ifdef CONFIG_PLUGIN
    return !!cpu->neg.plugin_mem_cbs;
#else
    return false;
#endif
}

TranslationBlock *tb_gen_code(CPUState *cpu, vaddr pc,
                              uint64_t cs_base, uint32_t flags,
                              int cflags);
void page_init(void);
void tb_htable_init(void);
void tb_reset_jump(TranslationBlock *tb, int n);
TranslationBlock *tb_link_page(TranslationBlock *tb);
void cpu_restore_state_from_tb(CPUState *cpu, TranslationBlock *tb,
                               uintptr_t host_pc);

/**
 * tlb_init - initialize a CPU's TLB
 * @cpu: CPU whose TLB should be initialized
 */
void tlb_init(CPUState *cpu);
/**
 * tlb_destroy - destroy a CPU's TLB
 * @cpu: CPU whose TLB should be destroyed
 */
void tlb_destroy(CPUState *cpu);

bool tcg_exec_realizefn(CPUState *cpu, Error **errp);
void tcg_exec_unrealizefn(CPUState *cpu);

/* current cflags for hashing/comparison */
uint32_t curr_cflags(CPUState *cpu);

void tb_check_watchpoint(CPUState *cpu, uintptr_t retaddr);

/*
 * Speculative store buffer helpers for wrong-path execution.
 *
 * When a plugin enters speculative mode (cpu->plugin_spec_mode == true),
 * all guest memory writes are redirected to a per-cache-line buffer
 * (cpu->plugin_spec_store_buf) instead of modifying real guest memory.
 * Loads check the buffer first for store-to-load forwarding, falling
 * back to real memory for bytes not in the buffer.
 *
 * The buffer is a GHashTable keyed by line_addr = addr & ~63, with
 * value = PluginSpecLine* containing a 64-byte payload plus a 64-bit
 * valid_mask (bit k = byte k of this line has a speculative value).
 * Lines are bump-allocated from cpu->plugin_spec_store_pool to avoid
 * per-line g_malloc traffic; spec_mode_end clears the hash table and
 * resets pool_used = 0, retaining the underlying storage for reuse.
 *
 * Prior implementation keyed the hash table by individual byte
 * address, costing one g_hash_table_insert per byte stored and one
 * lookup per byte loaded.  On mcf with wp=1 wpdepth=64 memdata=1 the
 * per-byte hash ops were ~6% of total runtime.  The cache-line layout
 * makes a 64-byte vector store one map op + one memcpy, an 8-byte
 * store one map op + an 8-byte memcpy, and a load within a hit line
 * one map op + a single byte read with a bit test.
 */
#ifdef CONFIG_PLUGIN

#include "exec/plugin-spec.h"

static inline bool cpu_plugin_spec_active(CPUState *cpu)
{
    return unlikely(cpu->plugin_spec_mode && cpu->plugin_spec_store_buf);
}

/* spec_line_get_or_alloc is declared in include/exec/plugin-spec.h. */

static inline PluginSpecLine *spec_line_lookup(CPUState *cpu, vaddr line_addr)
{
    return (PluginSpecLine *)g_hash_table_lookup(
        cpu->plugin_spec_store_buf, GUINT_TO_POINTER((guintptr)line_addr));
}

static inline void spec_store_byte(CPUState *cpu, vaddr addr, uint8_t val)
{
    vaddr  line_addr = addr & ~(vaddr)PLUGIN_SPEC_LINE_MASK;
    unsigned idx     = (unsigned)(addr & PLUGIN_SPEC_LINE_MASK);
    PluginSpecLine *line = spec_line_get_or_alloc(cpu, line_addr);
    if (!line) {
        return;
    }
    line->bytes[idx] = val;
    line->valid_mask |= (uint64_t)1 << idx;
}

static inline bool spec_load_byte(CPUState *cpu, vaddr addr, uint8_t *val)
{
    vaddr  line_addr = addr & ~(vaddr)PLUGIN_SPEC_LINE_MASK;
    unsigned idx     = (unsigned)(addr & PLUGIN_SPEC_LINE_MASK);
    PluginSpecLine *line = spec_line_lookup(cpu, line_addr);
    if (!line || !(line->valid_mask & ((uint64_t)1 << idx))) {
        return false;
    }
    *val = line->bytes[idx];
    return true;
}

/* Bulk store: stays within a single cache line in the common case
 * (size <= 16 for SIMD, naturally aligned).  Cross-line stores fall
 * back to per-line chunks; that path is rare on real workloads but
 * still O(size / 64) hash ops, not O(size) as before. */
static inline void spec_store_bytes(CPUState *cpu, vaddr addr,
                                    const void *buf, int size)
{
    const uint8_t *p = buf;
    while (size > 0) {
        vaddr  line_addr = addr & ~(vaddr)PLUGIN_SPEC_LINE_MASK;
        unsigned idx     = (unsigned)(addr & PLUGIN_SPEC_LINE_MASK);
        unsigned remain  = PLUGIN_SPEC_LINE_SIZE - idx;
        unsigned chunk   = (unsigned)size < remain ? (unsigned)size : remain;

        PluginSpecLine *line = spec_line_get_or_alloc(cpu, line_addr);
        if (!line) {
            /* Sandbox capped — drop remaining bytes.  See header
             * comment on PLUGIN_SPEC_STORE_LINE_MAX. */
            return;
        }
        memcpy(&line->bytes[idx], p, chunk);
        /* Set bits [idx, idx+chunk).  chunk is 1..64 inclusive so the
         * shift is well-defined when normalised through uint64_t. */
        uint64_t mask = chunk >= 64
            ? ~(uint64_t)0
            : ((((uint64_t)1 << chunk) - 1) << idx);
        line->valid_mask |= mask;
        addr += chunk;
        p    += chunk;
        size -= chunk;
    }
}

/*
 * Redirect an atomic read-modify-write's memory pointer into the
 * speculative sandbox.  Atomic helpers (atomic_template.h) obtain a raw
 * host pointer from atomic_mmu_lookup and RMW it in place with real host
 * atomic primitives; left unsandboxed that mutates real guest memory on
 * the discarded wrong path (kernel spinlocks, refcounts, page-table
 * cmpxchg — and user-mode futexes / lock cmpxchg alike).
 *
 * We pre-fill the @size accessed bytes of the line from real memory
 * wherever they are not already speculatively dirty (so the RMW reads
 * the correct store-to-load-forwarded baseline), mark them valid, and
 * return a pointer into the line.  The in-place RMW then mutates the
 * shadow, never real memory, and later speculative loads forward from
 * it; spec_mode_end discards the whole line.
 *
 * A naturally-aligned atomic of size <= 16 never crosses a 64-byte line,
 * so idx + size <= 64 and the returned pointer carries the same
 * alignment the guest access guaranteed (PluginSpecLine is 16-aligned
 * with bytes[] at offset 0 — see plugin-spec.h).  Returns NULL when the
 * sandbox line cap is reached; the caller falls back to the real
 * pointer, bounding a dropped speculative atomic exactly as a dropped
 * speculative store is bounded.
 */
static inline void *spec_atomic_shadow(CPUState *cpu, vaddr addr,
                                       const void *real_host, int size)
{
    vaddr  line_addr = addr & ~(vaddr)PLUGIN_SPEC_LINE_MASK;
    unsigned idx     = (unsigned)(addr & PLUGIN_SPEC_LINE_MASK);
    PluginSpecLine *line = spec_line_get_or_alloc(cpu, line_addr);
    if (!line) {
        return NULL;
    }
    const uint8_t *src = real_host;
    for (int k = 0; k < size; k++) {
        uint64_t bit = (uint64_t)1 << (idx + k);
        if (!(line->valid_mask & bit)) {
            line->bytes[idx + k] = src[k];
        }
    }
    /* The RMW will write all @size bytes: mark them valid up front. */
    uint64_t span = size >= 64
        ? ~(uint64_t)0
        : ((((uint64_t)1 << size) - 1) << idx);
    line->valid_mask |= span;
    return &line->bytes[idx];
}
#endif /* CONFIG_PLUGIN */

#endif
