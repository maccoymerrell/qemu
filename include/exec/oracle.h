/*
 * Behavioural oracle -- derive an instruction's architectural write set from
 * QEMU's own emulation rather than from a static decoder.
 *
 * The oracle is compiled in only when configured with --enable-oracle.  When
 * the option is off this header declares nothing and every call site compiles
 * away, so a normal build is unaffected.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXEC_ORACLE_H
#define EXEC_ORACLE_H

#ifdef CONFIG_ORACLE

#include "tcg/helper-info.h"

struct TCGTemp;

/*
 * Lifecycle.  oracle_init() must be called once, after the target has
 * registered its TCG globals (i.e. after TCGCPUOps::initialize), and from
 * per-target code so that sizeof(CPUArchState) is the real thing.
 */
void oracle_init(size_t env_size, const char *target_name);

/* True once oracle_init() has run and QEMU_ORACLE named an output file. */
bool oracle_active(void);

/*
 * Choke point 2 of 2 in the translator: emit the per-instruction boundary
 * probe.  Called from translator_loop() before each guest instruction is
 * translated, so it covers every target with a single call site.
 */
void oracle_gen_insn_boundary(uint64_t pc);

/*
 * Choke point 1: helper call interposition, driven from tcg_gen_callN().
 * oracle_gen_helper_probe_wanted() keeps the generator from probing its own
 * probes and lets us skip uninteresting helpers.
 */
bool oracle_gen_helper_probe_wanted(const TCGHelperInfo *info);
void oracle_gen_helper_probe(const TCGHelperInfo *info, bool pre,
                             struct TCGTemp *ret);

#endif /* CONFIG_ORACLE */
#endif /* EXEC_ORACLE_H */
