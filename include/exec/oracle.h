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
 *
 * The probe goes only into a TB whose cflags carry CF_ORACLE, so a TB outside
 * the observation window costs nothing at all rather than costing a call that
 * returns immediately.
 */
void oracle_gen_insn_boundary(uint64_t pc, bool first_insn);

/*
 * Translation-time gating.  Returns the cflags a TB starting at @pc must
 * carry: CF_ORACLE, or nothing.  The answer is a pure function of @pc, so one
 * pc always gets one decision and an armed and an unarmed TB for the same pc
 * can never both be cached.
 */
uint32_t oracle_tb_cflags(uint64_t pc);

/*
 * Chaining.  An armed TB may only jump straight into another armed TB; the
 * destination's first instruction is what closes out the source's last one.
 * Both take TranslationBlock pointers, as void, so that a caller does not need
 * the oracle's headers in scope.
 */
bool oracle_tb_chain_ok(const void *from, const void *to);
bool oracle_must_exit_before(const void *to);

/*
 * Called when a TB returns to the execution loop.  A boundary probe reports an
 * instruction's writes at the *next* boundary, so the last instruction of an
 * armed TB has no probe left to close it; this is that probe.
 */
void oracle_tb_exit(void *env);

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
