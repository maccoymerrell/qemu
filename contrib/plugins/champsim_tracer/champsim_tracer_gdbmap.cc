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
#include "champsim_tracer.h"

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
    /*
     * Whether a VALUE READ for @reg resolves through THIS name.  Several
     * names can carry one generic id, and the pick between them is an
     * adjudication written in the TSV, not a property of the row -- see
     * check_route_adjudications() in scripts/cst-regmap.py, which refuses
     * to generate an ambiguous id that nobody has decided.
     */
    bool route;
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

bool cst_gdbmap_value_route(unsigned isa, uint8_t reg_id,
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
     * THE ADJUDICATED ROUTE, and that is the whole contract.  Several gdb
     * names can carry one generic id -- MIPS `lo` and `hi` are the two halves
     * of accumulator 0, `fp` and `s8` are two spellings of $30, and x86's
     * REG_CTRL is carried by every CR plus EFER -- and reading the wrong one
     * publishes another register's bytes, or half a container, under a name
     * that promises the whole register.  Which name a read goes through is
     * therefore decided per id in regmap/<isa>.gdb.tsv with a ground behind
     * it; the generator refuses to emit an ambiguous id that carries no
     * verdict, so at most one row here can be the route and an id whose rows
     * all decline leaves it correctly unrouted.
     *
     * Exactly one route is still asserted rather than assumed: two would mean
     * the table and the generator disagree, and the honest answer to that is
     * no route, not the first one found.
     */
    for (unsigned i = 0; i < n; i++) {
        if (rows[i].reg != reg_id || !rows[i].route) {
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

/* ==================================================================
 * The value-read reverse index: GenericRegId -> the (feature, name) pair
 * a value read goes through.  It lives here because this file owns the
 * namespace it is built from.
 * ================================================================== */

/*
 * Reverse index GenericRegId → QemuRegKey, built once at install by
 * walking active_reg_table.  Recovers the per-element QemuRegKey for
 * multi-reg encodings (RISC-V V*M* tuples) so each constituent reg's
 * value is captured under regdata=1 — without it multi-reg operands
 * land in src/dst correctly but their values aren't read (the multi-reg
 * path passed nullptr for the QemuRegKey).
 */
static QemuRegKey g_qemu_reg_by_gen[REG_ID_COUNT];

unsigned g_qemu_reg_routes_from_gdbmap;
/*
 * Kept, and permanently zero: the second source it counted is gone.  See
 * build_qemu_reg_reverse_index() -- the census prints this column so the
 * zero has its comparand beside it rather than vanishing from the report.
 */
unsigned g_qemu_reg_routes_from_reg_table;
uint8_t g_qemu_reg_route_src[REG_ID_COUNT];

void build_qemu_reg_reverse_index(void)
{
    for (unsigned i = 0; i < REG_ID_COUNT; i++) {
        g_qemu_reg_by_gen[i] = QemuRegKey{};
        g_qemu_reg_route_src[i] = CST_REG_ROUTE_NONE;
    }
    g_qemu_reg_routes_from_gdbmap = 0;
    g_qemu_reg_routes_from_reg_table = 0;

    /*
     * THE GENERATED gdbstub TABLE IS THE ONLY SOURCE.
     *
     * This index answers "which descriptor do I read for this generic
     * register", and qemu_plugin_get_registers() publishes exactly the
     * (feature, name) pairs the target's gdbstub declares.  The table is
     * generated from those declarations -- the feature XML the target ships,
     * plus the two register files it builds in C -- with a both-directions
     * refusal (scripts/cst-regmap.py --namespace gdb), so a register the
     * target declares cannot go missing from it without failing the build.
     *
     * There used to be a second source behind this one: the per-ISA
     * classification table, a Capstone-shaped structure that happened to
     * carry a gdb key on its rows.  It supplied 122 routes when it was first
     * counted and 0 once the generator's scope was widened to cover every
     * register file the target declares, measured live on all four targets
     * before this arm was removed.  Both counters are kept, and the reg-route
     * census still prints both columns, because a zero is only readable
     * beside the number it replaced.
     */
    for (unsigned i = 0; i < REG_ID_COUNT; i++) {
        const char *feature = nullptr;
        const char *name = nullptr;
        if (cst_gdbmap_value_route((unsigned)trace_isa, (uint8_t)i,
                                   &feature, &name)) {
            g_qemu_reg_by_gen[i].feature = feature;
            g_qemu_reg_by_gen[i].name = name;
            g_qemu_reg_route_src[i] = CST_REG_ROUTE_GDBMAP;
            g_qemu_reg_routes_from_gdbmap++;
        }
    }

}

const QemuRegKey *qemu_reg_for_generic_id(uint8_t gen_id)
{
    if (gen_id >= REG_ID_COUNT) {
        return nullptr;
    }
    const QemuRegKey *k = &g_qemu_reg_by_gen[gen_id];
    return qemu_reg_key_valid(k) ? k : nullptr;
}
