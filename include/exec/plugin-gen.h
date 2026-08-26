/*
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * plugin-gen.h - TCG-dependent definitions for generating plugin code
 *
 * This header should be included only from plugin.c and C files that emit
 * TCG code.
 */
#ifndef QEMU_PLUGIN_GEN_H
#define QEMU_PLUGIN_GEN_H

#include "tcg/tcg.h"

struct DisasContextBase;

#ifdef CONFIG_PLUGIN

bool plugin_gen_tb_start(CPUState *cpu, const struct DisasContextBase *db);
void plugin_gen_tb_end(CPUState *cpu, size_t num_insns);
void plugin_gen_insn_start(CPUState *cpu, const struct DisasContextBase *db);
void plugin_gen_insn_end(void);

void plugin_gen_disable_mem_helpers(void);

/*
 * Record the static control-transfer target the translator has just
 * resolved for the instruction currently being translated.  Called
 * by per-ISA translators at every direct-branch / unconditional-jump
 * decode site, passing the same target value handed to gen_goto_tb.
 *
 * Plugins consume this via qemu_plugin_insn_branch_target_pc().  It
 * is the canonical source for wrong-path target selection on direct
 * branches: a tracer must NOT redecode the branch immediate itself,
 * since per-ISA encoding (PC-relative vs absolute, sign extension,
 * delay-slot accounting, Thumb interworking bit) varies and is
 * already correctly resolved here.
 *
 * Indirect branches do not have a static target; translators must
 * not call this for them, so plugins see branch_target_pc == 0 and
 * fall back to their observed-target history.
 */
void plugin_gen_record_branch_target(uint64_t target_pc);

/*
 * plugin_gen_record_insn_identity: state QEMU's own decode-table
 * identity for the instruction currently being translated.
 *
 * @id:   the decode-table SLOT.  Unique per slot within one build of
 *        one target; 0 is reserved for "no identity".  Not stable
 *        across source edits and not comparable across targets.
 * @name: the slot's name in QEMU's own source vocabulary -- the
 *        `op` of an X86_OP_ENTRY on i386, the decodetree pattern name
 *        elsewhere.  Stable and greppable, but NOT unique: several
 *        slots routinely share one name.
 *
 * Called by target translators at the point the slot is selected,
 * immediately before code is generated from it.  Plugins consume the
 * pair via qemu_plugin_insn_decode_id() / _decode_name().
 */
void plugin_gen_record_insn_identity(uint32_t id, const char *name);

/*
 * plugin_gen_record_tb_stop: close the last instruction's op range over
 * whatever ops->tb_stop() just emitted on its behalf.  Called from
 * translator_loop() immediately after tb_stop() and before gen_tb_end().
 */
void plugin_gen_record_tb_stop(void);

#else /* !CONFIG_PLUGIN */

static inline
bool plugin_gen_tb_start(CPUState *cpu, const struct DisasContextBase *db)
{
    return false;
}

static inline
void plugin_gen_insn_start(CPUState *cpu, const struct DisasContextBase *db)
{ }

static inline void plugin_gen_insn_end(void)
{ }

static inline void plugin_gen_tb_end(CPUState *cpu, size_t num_insns)
{ }

static inline void plugin_gen_disable_mem_helpers(void)
{ }

static inline void plugin_gen_record_branch_target(uint64_t target_pc)
{ }

static inline void plugin_gen_record_tb_stop(void)
{ }

static inline void plugin_gen_record_insn_identity(uint32_t id,
                                                   const char *name)
{ }

#endif /* CONFIG_PLUGIN */

#endif /* QEMU_PLUGIN_GEN_H */

