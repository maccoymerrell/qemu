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
#include "exec/vaddr.h"

#define PLUGIN_SPEC_LINE_SHIFT 6
#define PLUGIN_SPEC_LINE_SIZE  (1u << PLUGIN_SPEC_LINE_SHIFT)
#define PLUGIN_SPEC_LINE_MASK  (PLUGIN_SPEC_LINE_SIZE - 1u)

/* Sandbox grows up to this many lines per vCPU (each 72 bytes ≈ 72 MiB
 * at the cap) before further speculative stores are dropped.  Matches
 * the prior per-byte buffer's overflow semantics — see the AArch64
 * FEAT_MOPS / x86 REP-on-garbage-size case comment in
 * accel/tcg/internal-common.h. */
#define PLUGIN_SPEC_STORE_LINE_MAX (1u << 20)

typedef struct PluginSpecLine {
    uint64_t valid_mask;                       /* bit k = byte k stored */
    uint8_t  bytes[PLUGIN_SPEC_LINE_SIZE];
} PluginSpecLine;

/* Defined in plugins/api.c; declared here so the inline helpers in
 * accel/tcg/internal-common.h can call it. */
struct CPUState;
PluginSpecLine *spec_line_get_or_alloc(struct CPUState *cpu, vaddr line_addr);

#endif /* CONFIG_PLUGIN */

#endif /* QEMU_PLUGIN_SPEC_H */
