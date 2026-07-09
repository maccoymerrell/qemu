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

/* Sandbox grows up to this many lines per vCPU (each 80 bytes ≈ 80 MiB
 * at the cap) before further speculative stores are dropped.  Matches
 * the prior per-byte buffer's overflow semantics — see the AArch64
 * FEAT_MOPS / x86 REP-on-garbage-size case comment in
 * accel/tcg/internal-common.h. */
#define PLUGIN_SPEC_STORE_LINE_MAX (1u << 20)

/* Soft per-excursion budget (≈ 16 MiB of lines).  A normal wrong-path excursion
 * (wpdepth-bounded, ~hundreds of lines) never approaches this; crossing it means
 * a single instruction wrote a garbage-size region into the sandbox without
 * faulting (AArch64 FEAT_MOPS / x86 REP / vector with a wrong-path-garbage
 * size/count).  The allocator flags it and the WP loop terminates the excursion,
 * so the hard cap above is never reached and speculative stores are never
 * silently dropped in normal operation. */
#define PLUGIN_SPEC_STORE_SOFT_BUDGET (1u << 18)

/*
 * bytes[] is placed first and the line is 16-byte aligned so that a
 * naturally-aligned guest atomic (size <= 16, never crossing a 64-byte
 * line) yields a correspondingly-aligned pointer into bytes[] when an
 * atomic RMW is redirected into the sandbox (spec_atomic_shadow).  The
 * host atomic primitives — notably x86 cmpxchg16b and AArch64 128-bit
 * LDXP/STXP — fault on a misaligned operand, so the shadow target must
 * satisfy the same alignment the guest access already guaranteed.
 */
typedef struct PluginSpecLine {
    uint8_t  bytes[PLUGIN_SPEC_LINE_SIZE];
    uint64_t valid_mask;                       /* bit k = byte k stored */
} QEMU_ALIGNED(16) PluginSpecLine;

/* Defined in plugins/api.c; declared here so the inline helpers in
 * accel/tcg/internal-common.h can call it. */
struct CPUState;
PluginSpecLine *spec_line_get_or_alloc(struct CPUState *cpu, vaddr line_addr);

#endif /* CONFIG_PLUGIN */

#endif /* QEMU_PLUGIN_SPEC_H */
