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
 * all guest memory writes are redirected to a per-byte hash table
 * (cpu->plugin_spec_store_buf) instead of modifying real guest memory.
 * Loads check the buffer first for store-to-load forwarding, falling
 * back to real memory for bytes not in the buffer.
 */
#ifdef CONFIG_PLUGIN
/*
 * Hard cap on the per-byte speculative store buffer.  Wrong-path
 * execution is bounded by the plugin's speculation depth, so a
 * legitimate spec-mode store set is small (tens to thousands of
 * bytes).  A single instruction that loops a register-sized memory
 * set/copy entirely inside one TCG helper — e.g. an AArch64
 * FEAT_MOPS SETM/CPYM reached on the wrong path with a speculative
 * (garbage) size register — would otherwise insert unboundedly here
 * (one node per byte) and exhaust memory / crash inside glib before
 * the plugin ever regains control to bound it.  Past the cap we stop
 * *growing* the buffer (existing keys still update, so forwarding
 * stays correct for the already-tracked working set); further
 * speculative stores simply aren't forwarded — acceptable for a
 * speculative wrong path, and vastly preferable to an OOM.  64 MiB
 * worth of byte entries is orders of magnitude above any real
 * wrong-path store set.
 */
#define PLUGIN_SPEC_STORE_BUF_MAX (64u << 20)

static inline bool cpu_plugin_spec_active(CPUState *cpu)
{
    return unlikely(cpu->plugin_spec_mode && cpu->plugin_spec_store_buf);
}

static inline void spec_store_byte(CPUState *cpu, vaddr addr, uint8_t val)
{
    if (unlikely(g_hash_table_size(cpu->plugin_spec_store_buf)
                 >= PLUGIN_SPEC_STORE_BUF_MAX)
        && !g_hash_table_contains(cpu->plugin_spec_store_buf,
                                  GUINT_TO_POINTER((guintptr)addr))) {
        /* Buffer full: drop this speculative byte rather than grow
         * unboundedly.  A runaway wrong-path bulk memset/memcpy is
         * itself a sign speculation has run into garbage. */
        return;
    }
    g_hash_table_insert(cpu->plugin_spec_store_buf,
                        GUINT_TO_POINTER((guintptr)addr),
                        GUINT_TO_POINTER((guint)val));
}

static inline bool spec_load_byte(CPUState *cpu, vaddr addr, uint8_t *val)
{
    gpointer v;
    if (g_hash_table_lookup_extended(cpu->plugin_spec_store_buf,
                                     GUINT_TO_POINTER((guintptr)addr),
                                     NULL, &v)) {
        *val = (uint8_t)GPOINTER_TO_UINT(v);
        return true;
    }
    return false;
}

static inline void spec_store_bytes(CPUState *cpu, vaddr addr,
                                    const void *buf, int size)
{
    const uint8_t *p = buf;
    for (int i = 0; i < size; i++) {
        spec_store_byte(cpu, addr + i, p[i]);
    }
}
#endif /* CONFIG_PLUGIN */

#endif
