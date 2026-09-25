/*
 * Plugin speculative-store sandbox: shared cache-line type
 *
 * Both the TCG memory helpers (accel/tcg/internal-common.h) and the
 * plugin API forwarding loop (plugins/api.c) need the cache-line
 * layout.  The hot store/load inlines stay in internal-common.h; this
 * header just defines the type so both translation units agree on the
 * shape of CPUState::plugin_spec_store_buf's values.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_PLUGIN_SPEC_H
#define QEMU_PLUGIN_SPEC_H

#ifdef CONFIG_PLUGIN

#include <stdint.h>
#include "qemu/compiler.h"
#include "exec/vaddr.h"

#define PLUGIN_SPEC_LINE_SHIFT 6
#define PLUGIN_SPEC_LINE_SIZE  (1u << PLUGIN_SPEC_LINE_SHIFT)
#define PLUGIN_SPEC_LINE_MASK  (PLUGIN_SPEC_LINE_SIZE - 1u)

/* Hard cap: the sandbox grows up to this many lines per vCPU (each
 * 80 bytes, ~ 80 MiB at the cap); once it is reached, further
 * speculative stores are dropped rather than buffered. */
#define PLUGIN_SPEC_STORE_LINE_MAX (1u << 20)

/* Soft per-excursion budget (~ 20 MiB of lines).  A normal wrong-path excursion
 * (depth-bounded, ~hundreds of lines) never approaches this; crossing it means
 * a single instruction wrote a garbage-size region into the sandbox without
 * faulting (AArch64 FEAT_MOPS / x86 REP / vector with a wrong-path-garbage
 * size/count).  The allocator flags it (qemu_plugin_spec_store_overflowed) so
 * the plugin driving the excursion can end it before the hard cap above starts
 * dropping speculative stores. */
#define PLUGIN_SPEC_STORE_SOFT_BUDGET (1u << 18)

/*
 * bytes[] is placed first and the line is 16-byte aligned so that a
 * naturally-aligned guest atomic (size <= 16, never crossing a 64-byte
 * line) yields a correspondingly-aligned pointer into bytes[] when an
 * atomic RMW is redirected into the sandbox (spec_atomic_shadow).  The
 * host atomic primitives -- notably x86 cmpxchg16b and AArch64 128-bit
 * LDXP/STXP -- fault on a misaligned operand, so the shadow target must
 * satisfy the same alignment the guest access already guaranteed.
 */
typedef struct CPUPluginSpecLine {
    uint8_t  bytes[PLUGIN_SPEC_LINE_SIZE];
    uint64_t valid_mask;                       /* bit k = byte k stored */
} QEMU_ALIGNED(16) CPUPluginSpecLine;

/* Defined in plugins/api.c; declared here so the inline helpers in
 * accel/tcg/internal-common.h can call it. */
struct CPUState;
CPUPluginSpecLine *spec_line_get_or_alloc(struct CPUState *cpu,
                                          vaddr line_addr);

/*
 * Deterministic pseudo-random placeholder for a wrong-path speculative
 * access to an absent/unreadable page.  On the wrong path the faulting
 * instruction never retires, so this value is never architecturally
 * forwarded in a real simulation -- it is a pure placeholder that only
 * drives further wrong-path exploration.  Garbage (not zero) so a
 * data-dependent branch on it is not systematically biased.  Keyed on
 * each byte's guest address for reproducibility and read-consistency.
 */
static inline void plugin_spec_garbage_fill(void *out, unsigned size,
                                            vaddr addr)
{
    uint8_t *op = out;
    for (unsigned i = 0; i < size; i++) {
        uint64_t z = (uint64_t)(addr + i) + 0x9E3779B97F4A7C15ULL;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        z =  z ^ (z >> 31);
        op[i] = (uint8_t)z;
    }
}

/*
 * Wrong-path execution entry points, defined in the plugins-only TUs
 * accel/tcg/plugin-exec.c and plugin-window.c (plus the softmmu TLB
 * bookkeeping in cputlb.c) and called from the common plugins/api.c.
 */
bool cpu_plugin_exec_inline(CPUState *cpu);
bool cpu_plugin_exec_tb(CPUState *cpu);
/*
 * Translate (and keep) the block at @pc without executing it, so a plugin's
 * translation-time callbacks state QEMU's answer about code the guest has not
 * reached.  See the definition in accel/tcg/plugin-exec.c.
 */
bool cpu_plugin_translate_tb(CPUState *cpu, vaddr pc);
size_t cpu_plugin_arch_state_size(void);
void cpu_plugin_arch_state_restore(void *saved, size_t size);
/*
 * Wrong-path containment helpers with system-only side effects.  Defined in
 * plugin-window.c (compiled per-target, so the CONFIG_USER_ONLY split
 * applies); no-ops in user-mode emulation.  Called from the common
 * plugins/api.c, which itself must not reference softmmu-only symbols
 * directly.
 */
void cpu_plugin_excursion_open(CPUState *cpu);
void cpu_plugin_excursion_close(CPUState *cpu);
void cpu_plugin_spec_tlb_flush(CPUState *cpu);
void cpu_plugin_spec_tlb_flush_enter(CPUState *cpu);
/*
 * Excursion-scoped softmmu TLB bookkeeping: _note snapshots the per-mmu_idx
 * large-page escalation region at entry; _flush_logged invalidates exactly the
 * entries the wrong path installed and restores that region at exit.
 */
void cpu_plugin_spec_tlb_note(CPUState *cpu);
void cpu_plugin_spec_tlb_flush_logged(CPUState *cpu);
bool cpu_plugin_spec_mode_supported(void);
void cpu_plugin_cb_window_open(CPUState *cpu);
void cpu_plugin_cb_window_close(CPUState *cpu);
/*
 * Code-buffer pressure a wrong-path (speculative) walk put on the shared
 * translation cache.  _opens counts walks that overflowed the normal
 * highwater and had to open the spec reserve -- each of those owes a full
 * tb_flush the moment the walk unwinds, so a nonzero count is a walk that
 * evicted the whole correct-path cache.  _exhausted counts walks the
 * reserve itself could not hold: tb_gen_code returned NULL and the chain
 * was truncated at a point that depends on how full the buffer happened to
 * be, not on anything architectural.  Both are host-side, cross-vCPU
 * process-wide totals; the plugin reads them through
 * qemu_plugin_spec_reserve_opens()/_exhausted().
 */
extern unsigned long plugin_spec_reserve_opens;
extern unsigned long plugin_spec_reserve_exhausted;
/*
 * Translate-on-demand translations (cpu_plugin_translate_tb) that could not
 * get a TB because the code buffer was full.  The flag exists so that case
 * DECLINES instead of taking tb_gen_code's ordinary tb_flush + cpu_loop_exit
 * arm, which would longjmp out of the plugin callback the translation was
 * driven from.  Host-side, cross-vCPU, process-wide; read through
 * qemu_plugin_decode_only_nobuf().
 */
extern unsigned long plugin_decode_only_nobuf;

#endif /* CONFIG_PLUGIN */

#endif /* QEMU_PLUGIN_SPEC_H */
