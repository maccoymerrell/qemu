/*
 * The registers QEMU names, and what each one is on the wire.
 *
 * The dataflow statement ABI hands a consumer a provenance bit.  A bit below
 * qemu_plugin_dataflow_nregs() is a TCG global and resolves to the NAME the
 * target registered it under; a bit above is an env byte range, which
 * qemu_plugin_dataflow_field_reg() resolves to the name of the register file
 * entry that contains it when the target declared its layout; and three bits
 * are atoms that are not storage at all.  Every one of those is a spelling
 * chosen by the target -- "at" and "v0" on MIPS, "x0/zero" on RISC-V, "lr"
 * for AArch64's X30 -- and the wire publishes a GenericRegId instead.
 *
 * This is the whole of the translation between them.  One sorted table per
 * ISA, generated from a checked-in adjudication file whose completeness the
 * BUILD enforces in both directions (scripts/cst-regmap.py), plus the three
 * atoms, which are the same on every target because they are not registers.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_REGMAP_H
#define CHAMPSIM_TRACER_REGMAP_H

#include <stdint.h>

#include "champsim_tracer_generic_ids.h"

/*
 * Translate @name for @isa.
 *
 * Returns false, and writes nothing, for a name this build's table does not
 * carry.  A caller must treat that as "QEMU named a register I cannot read",
 * never as REG_NONE: the two differ, and the difference is the whole value of
 * the table.  REG_NONE is an ADJUDICATED answer -- the name is QEMU's own
 * lowering or a piece of emulation state that is not an architectural
 * register, and the rows that carry it say so -- while a missing row means
 * this plugin and this emulator were built from different register
 * namespaces, and publishing REG_NONE for that would hide a skewed build
 * behind a plausible classification.
 *
 * @name may be NULL, which returns false.
 */
bool cst_regmap_lookup(unsigned isa, const char *name, uint8_t *reg_id);

/*
 * Translate one of the three provenance atoms
 * (QEMU_PLUGIN_DF_ATOM_ZERO / _IMM / _CONST).
 *
 * The zero register is a register on the wire and the other two are not, so
 * only the first writes @reg_id; the immediate and the constant return true
 * with @reg_id untouched, because "this value came from the encoding" is a
 * true answer that names no register and a caller must be able to tell it
 * from a name it failed to read.  @is_reg says which happened.
 */
bool cst_regmap_atom(uint32_t atom, uint8_t *reg_id, bool *is_reg);

/*
 * Check the tables' own invariants: every ISA's rows sorted by name, no
 * duplicate name, no empty name, and every generic id inside the enum.
 * Returns the number of defects so a caller can refuse rather than bisect a
 * table that is not ordered.
 */
unsigned cst_regmap_selfcheck(void);

/*
 * Walk the emulator's whole TCG-global namespace and count the names this
 * build's table cannot translate.  Returns the count; @n_walked, when given,
 * receives how many names were examined, so a zero can be read as coverage
 * rather than as a walk that found nothing to look at.
 *
 * WHAT THIS CAN AND CANNOT SAY.  It is exhaustive over TCG globals, which the
 * ABI enumerates.  It is silent about the names a target DECLARED with
 * insn_dataflow_declare_regfile(), because the ABI resolves an env range to a
 * declared name but has no way to list the declarations -- those names reach
 * a consumer only when an instruction touches one.  Their coverage is
 * measured where it can be, per instruction, and counted there.
 */
unsigned cst_regmap_walk_globals(unsigned isa, unsigned *n_walked);

/* How many names this build knows for @isa, for a census that must not be
 * vacuous. */
unsigned cst_regmap_size(unsigned isa);

/*
 * The gdbstub namespace's route: the (feature, name) pair
 * qemu_plugin_get_registers() publishes for @reg_id on @isa.
 *
 * This is the VALUE-READ route, and it is a different question from
 * cst_regmap_lookup()'s.  That one answers "QEMU's ops named this TCG global;
 * which register is it"; this one answers "the wire wants this register's
 * value; which descriptor do I read".  The two namespaces disagree on real
 * registers -- AArch64 X30 is `lr` to TCG and `x30` to gdb, and the program
 * counter is a TCG global on neither target while gdb names it on both --
 * which is why the join is generated twice from two registration sites
 * rather than once from a spelling that happens to match.
 *
 * Returns false when this build's table carries NO row for @reg_id, and also
 * when it carries MORE THAN ONE: several gdb names can name parts of one
 * generic register (MIPS `lo`/`hi` are accumulator 0's halves), and reading
 * one of them would publish a partial value under a whole register's name.
 * A caller must treat false as "no route", never as "no such register".
 */
bool cst_gdbmap_unique_name(unsigned isa, uint8_t reg_id,
                            const char **feature, const char **name);

/* How many gdb names this build knows for @isa, so a census cannot be
 * vacuous. */
unsigned cst_gdbmap_size(unsigned isa);

#endif /* CHAMPSIM_TRACER_REGMAP_H */
