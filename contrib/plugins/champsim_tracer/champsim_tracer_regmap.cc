/*
 * The register map: QEMU's register NAME -> the wire's GenericRegId.
 *
 * WHY A NAME AND NOT AN INDEX.  The ABI's own header says the provenance
 * indices are stable for the life of a process and not across QEMU versions
 * or targets, and that a consumer wanting to persist one must record the name
 * or the offset alongside.  The wire persists a register for the life of a
 * trace, so the name is what this plugin keys on.
 *
 * WHY THE ROWS ARE GENERATED.  The name universe is the target's, not this
 * plugin's: it is whatever strings reach tcg_global_mem_new() and
 * insn_dataflow_declare_regfile().  A hand-written table would go quietly
 * short the first time a target added a register, and a register with no row
 * cannot be published at all.  scripts/cst-regmap.py reads the universe out
 * of the target's own registration sites and refuses to generate when the
 * adjudication file is short a name or carries one the target never
 * registers, so the completeness is a BUILD property in both directions
 * rather than a claim in a comment.
 *
 * WHAT THE TABLE DOES NOT DECIDE.  Nothing about dataflow.  A row says which
 * architectural register a QEMU name stands for and nothing else; whether an
 * instruction reads or writes it is the statement layer's answer, and what
 * the trace does with it is the classifier's.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <stdio.h>
#include <string.h>

/*
 * The plugin ABI headers are C, and this file is C++.  Without the linkage
 * bracket the declarations mangle and the .so fails to dlopen on a symbol
 * whose name reads like the right one -- measured here as
 * `undefined symbol: _Z26qemu_plugin_dataflow_nregsv`, which names the
 * function and is still the wrong symbol.  glib comes FIRST and outside the
 * bracket: qemu-plugin.h includes it, and glib reaches C++ templates that a C
 * linkage block rejects outright.
 */
extern "C" {
#include <qemu-plugin.h>
#include <qemu-plugin-dataflow.h>
}

#include "champsim_tracer_generic_ids.h"
#include "champsim_tracer_regmap.h"

namespace {

struct CstRegMapRow {
    const char *name;
    uint8_t reg;                /* GenericRegId */
};

#include "champsim_tracer_regmap_x86_64.h"
#include "champsim_tracer_regmap_aarch64.h"
#include "champsim_tracer_regmap_riscv64.h"
#include "champsim_tracer_regmap_mipsel.h"

struct CstRegMapTable {
    const CstRegMapRow *rows;
    unsigned n;
};

/*
 * Indexed by TraceISA.  TRACE_ISA_UNKNOWN has no table, and a lookup against
 * it fails rather than falling back to another ISA's spelling: "at" is $1 on
 * MIPS and nothing at all elsewhere, so a wrong-ISA answer would be a
 * confident wrong register.
 */
const CstRegMapTable tables[] = {
    [TRACE_ISA_UNKNOWN] = { nullptr, 0 },
    [TRACE_ISA_X86]     = { cst_regmap_x86_64,
                            (unsigned)(sizeof(cst_regmap_x86_64) /
                                       sizeof(cst_regmap_x86_64[0])) },
    [TRACE_ISA_AARCH64] = { cst_regmap_aarch64,
                            (unsigned)(sizeof(cst_regmap_aarch64) /
                                       sizeof(cst_regmap_aarch64[0])) },
    [TRACE_ISA_RISCV]   = { cst_regmap_riscv64,
                            (unsigned)(sizeof(cst_regmap_riscv64) /
                                       sizeof(cst_regmap_riscv64[0])) },
    [TRACE_ISA_MIPS]    = { cst_regmap_mipsel,
                            (unsigned)(sizeof(cst_regmap_mipsel) /
                                       sizeof(cst_regmap_mipsel[0])) },
};

const unsigned n_tables = (unsigned)(sizeof(tables) / sizeof(tables[0]));

} /* namespace */

bool cst_regmap_lookup(unsigned isa, const char *name, uint8_t *reg_id)
{
    if (isa >= n_tables || !name) {
        return false;
    }

    const CstRegMapRow *rows = tables[isa].rows;
    unsigned lo = 0;
    unsigned hi = tables[isa].n;

    if (!rows) {
        return false;
    }
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2;
        int c = strcmp(name, rows[mid].name);

        if (c == 0) {
            if (reg_id) {
                *reg_id = rows[mid].reg;
            }
            return true;
        }
        if (c < 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return false;
}

bool cst_regmap_atom(uint32_t atom, uint8_t *reg_id, bool *is_reg)
{
    switch (atom) {
    case QEMU_PLUGIN_DF_ATOM_ZERO:
        if (reg_id) {
            *reg_id = REG_ZERO;
        }
        if (is_reg) {
            *is_reg = true;
        }
        return true;
    case QEMU_PLUGIN_DF_ATOM_IMM:
    case QEMU_PLUGIN_DF_ATOM_CONST:
        if (is_reg) {
            *is_reg = false;
        }
        return true;
    default:
        return false;
    }
}

unsigned cst_regmap_selfcheck(void)
{
    unsigned defects = 0;

    for (unsigned t = 0; t < n_tables; t++) {
        const CstRegMapRow *rows = tables[t].rows;

        if (!rows) {
            continue;
        }
        if (tables[t].n == 0) {
            defects++;
            continue;
        }
        for (unsigned i = 0; i < tables[t].n; i++) {
            if (!rows[i].name || !rows[i].name[0]) {
                defects++;
                continue;
            }
            if (rows[i].reg >= REG_ID_COUNT) {
                defects++;
            }
            /*
             * Strictly increasing, which covers both the order the bisection
             * needs and the absence of a duplicate name.  A duplicate would
             * make one of the two rows unreachable and which one depends on
             * where the bisection landed, so it would read as a table that
             * answers correctly most of the time.
             */
            if (i && strcmp(rows[i - 1].name, rows[i].name) >= 0) {
                defects++;
            }
        }
    }
    return defects;
}

unsigned cst_regmap_walk_globals(unsigned isa, unsigned *n_walked)
{
    unsigned n = qemu_plugin_dataflow_nregs();
    unsigned walked = 0;
    unsigned missing = 0;

    for (unsigned r = 0; r < n; r++) {
        const char *name = qemu_plugin_dataflow_reg_name(r, nullptr, nullptr);

        /*
         * A bit below nregs whose temp is not an env-based global answers
         * NULL.  That is not a register the map owes a row for, so it is not
         * walked and not counted -- counting it would make the walk report a
         * gap the table cannot close.
         */
        if (!name) {
            continue;
        }
        walked++;
        if (!cst_regmap_lookup(isa, name, nullptr)) {
            missing++;
        }
    }
    if (n_walked) {
        *n_walked = walked;
    }
    return missing;
}

unsigned cst_regmap_size(unsigned isa)
{
    return isa < n_tables ? tables[isa].n : 0;
}
