/*
 * The gdbstub register namespace: QEMU's gdb NAME -> the wire's GenericRegId.
 *
 * A SECOND table, and a second file, because it answers a different question
 * from champsim_tracer_regmap.cc's.  That one translates the name a TCG
 * global was registered under, which is what QEMU's dataflow statements
 * carry.  This one translates the (feature, name) pair
 * qemu_plugin_get_registers() publishes, which is what a VALUE READ has to
 * go through -- and the two namespaces genuinely differ: AArch64's X30 is
 * `lr` to TCG and `x30` to gdb, and the program counter is a TCG global on
 * neither AArch64 nor RISC-V while gdb names it on both.
 *
 * It is its own translation unit because it must link into the offline tools
 * as well as the plugin, and the TCG-namespace file reaches the running
 * emulator's plugin ABI (qemu_plugin_dataflow_reg_name) for its coverage
 * census.  Nothing here touches the ABI: the table is generated data and a
 * linear scan.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdint.h>
#include <string.h>

#include "champsim_tracer_generic_ids.h"
#include "champsim_tracer_regmap.h"

namespace {

/*
 * The gdbstub namespace's row.  It carries the FEATURE as well as the name
 * because qemu_plugin_get_registers() keys on the pair: two features can
 * spell a register the same way, and the plugin's handle cache has always
 * looked one up by (feature, name).
 */
struct CstGdbMapRow {
    const char *feature;
    const char *name;
    uint8_t reg;                /* GenericRegId */
};

#include "champsim_tracer_gdbmap_x86_64.h"
#include "champsim_tracer_gdbmap_aarch64.h"
#include "champsim_tracer_gdbmap_riscv64.h"
#include "champsim_tracer_gdbmap_mipsel.h"

struct CstGdbMapTable {
    const CstGdbMapRow *rows;
    unsigned n;
};

const CstGdbMapTable gdb_tables[] = {
    [TRACE_ISA_UNKNOWN] = { nullptr, 0 },
    [TRACE_ISA_X86]     = { cst_gdbmap_x86_64,
                            (unsigned)(sizeof(cst_gdbmap_x86_64) /
                                       sizeof(cst_gdbmap_x86_64[0])) },
    [TRACE_ISA_AARCH64] = { cst_gdbmap_aarch64,
                            (unsigned)(sizeof(cst_gdbmap_aarch64) /
                                       sizeof(cst_gdbmap_aarch64[0])) },
    [TRACE_ISA_RISCV]   = { cst_gdbmap_riscv64,
                            (unsigned)(sizeof(cst_gdbmap_riscv64) /
                                       sizeof(cst_gdbmap_riscv64[0])) },
    [TRACE_ISA_MIPS]    = { cst_gdbmap_mipsel,
                            (unsigned)(sizeof(cst_gdbmap_mipsel) /
                                       sizeof(cst_gdbmap_mipsel[0])) },
};

const unsigned n_gdb_tables =
    (unsigned)(sizeof(gdb_tables) / sizeof(gdb_tables[0]));

} /* namespace */

bool cst_gdbmap_unique_name(unsigned isa, uint8_t reg_id,
                            const char **feature, const char **name)
{
    if (isa >= n_gdb_tables) {
        return false;
    }
    const CstGdbMapRow *rows = gdb_tables[isa].rows;
    unsigned n = gdb_tables[isa].n;
    const CstGdbMapRow *hit = nullptr;

    if (!rows) {
        return false;
    }
    /*
     * UNIQUE, and that is the whole contract.  Several gdb names can carry
     * one generic id -- MIPS `lo` and `hi` are the two halves of accumulator
     * 0, and `fp` and `s8` are two spellings of $30 -- and reading ONE of
     * them would publish a partial value under a name that promises the
     * whole register.  So an id with more than one name gets no route from
     * here and keeps whatever route it already had; the caller counts both
     * outcomes rather than letting the ambiguous ones read as absent.
     */
    for (unsigned i = 0; i < n; i++) {
        if (rows[i].reg != reg_id) {
            continue;
        }
        if (hit) {
            return false;
        }
        hit = &rows[i];
    }
    if (!hit || hit->reg == REG_NONE) {
        return false;
    }
    if (feature) {
        *feature = hit->feature;
    }
    if (name) {
        *name = hit->name;
    }
    return true;
}

unsigned cst_gdbmap_size(unsigned isa)
{
    return isa < n_gdb_tables ? gdb_tables[isa].n : 0;
}

