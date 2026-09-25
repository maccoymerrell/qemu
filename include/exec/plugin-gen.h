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

/*
 * One architectural register, as the per-instruction register statement
 * names it (qemu_plugin_insn_reg_list()): @cls is an enum
 * qemu_plugin_reg_class, @name the target's (gdb) name.
 */
typedef struct PluginRegDesc {
    uint8_t cls;
    uint8_t index;
    uint16_t width;
    char name[14];
} PluginRegDesc;

/* What a TCGCPUOps.plugin_reg_resolve hook says a CPU-state field is. */
enum PluginRegResolve {
    PLUGIN_REG_UNKNOWN,     /* no register the target knows of */
    PLUGIN_REG_ARCH,        /* @desc names the register */
    PLUGIN_REG_DROP,        /* translator bookkeeping, not a register */
};

/* For resolve hooks: CPU-state offset @off lies in field @f of @T ... */
#define PLUGIN_REG_IN(T, f, off) \
    ((uintptr_t)((off) - (intptr_t)offsetof(T, f)) < sizeof_field(T, f))
/* ... at element number */
#define PLUGIN_REG_ELT(T, f, off) \
    ((int)(((off) - (intptr_t)offsetof(T, f)) / sizeof_field(T, f[0])))

/* Fill @d; returns PLUGIN_REG_ARCH */
static inline int G_GNUC_PRINTF(5, 6)
plugin_reg_desc(PluginRegDesc *d, int cls, int index, int width,
                const char *fmt, ...)
{
    va_list ap;

    d->cls = cls;
    d->index = index;
    d->width = width;
    va_start(ap, fmt);
    vsnprintf(d->name, sizeof(d->name), fmt, ap);
    va_end(ap);
    return PLUGIN_REG_ARCH;
}

/* plugin_gen_reg_mute() modes */
enum {
    PLUGIN_REG_MUTE_OFF,
    PLUGIN_REG_MUTE_WRITES, /* the ops only rematerialise state: no writes */
    PLUGIN_REG_MUTE_ALL,    /* the ops are stated otherwise (plugin_gen_reg) */
};

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
 * The instruction being translated lowers a control transfer with no
 * static target: INDIRECT (a jump, call or return to a run-time value)
 * or COND_NO_TARGET (a trap taken only on a condition).  Plugins read it
 * via qemu_plugin_insn_transfer_kind().
 */
void plugin_gen_record_transfer(enum qemu_plugin_transfer_kind kind);

/*
 * The register statement's translator side (the transfer-kind pattern).
 * The ops an instruction emits state most of its register accesses by
 * themselves; plugin_gen_insn_end() collects them.  These calls state
 * what the ops cannot show:
 *
 * plugin_gen_reg: the instruction accesses @d (@access: QEMU_PLUGIN_REG_*
 *   bits; 0 says it does NOT access @d, e.g. a pointer the helper is
 *   passed but does not use).  Authoritative over a CPU-state pointer
 *   whose direction the ops leave unknown.
 * plugin_gen_reg_env: the same, for the register at CPU-state @offset.
 * plugin_gen_reg_temp: temp @t stands for register @d from here on (a
 *   register with no CPU-state field, e.g. a zero register).
 * plugin_gen_reg_covered: the statements made for this instruction cover
 *   every effect of the helpers it calls.
 * plugin_gen_reg_mute: PLUGIN_REG_MUTE_* for the ops that follow.
 * plugin_gen_reg_opaque: the instruction has an effect on registers no
 *   statement names yet (@what, a static string naming the class): the
 *   statement is counted incomplete, covered or not.
 */
void plugin_gen_reg(const PluginRegDesc *d, unsigned access);
void plugin_gen_reg_env(intptr_t offset, unsigned access);
void plugin_gen_reg_temp(TCGTemp *t, const PluginRegDesc *d);
void plugin_gen_reg_covered(void);
void plugin_gen_reg_mute(int mode);
void plugin_gen_reg_opaque(const char *what);

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

static inline
void plugin_gen_record_transfer(enum qemu_plugin_transfer_kind kind)
{ }

static inline void plugin_gen_reg(const PluginRegDesc *d, unsigned access)
{ }

static inline void plugin_gen_reg_env(intptr_t offset, unsigned access)
{ }

static inline void plugin_gen_reg_temp(TCGTemp *t, const PluginRegDesc *d)
{ }

static inline void plugin_gen_reg_covered(void)
{ }

static inline void plugin_gen_reg_mute(int mode)
{ }

static inline void plugin_gen_reg_opaque(const char *what)
{ }

#endif /* CONFIG_PLUGIN */

#endif /* QEMU_PLUGIN_GEN_H */

