/*
 * isaxcheck_fields — the tracer's own dependency model, reachable from a
 * host tool.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * WHY THIS EXISTS
 * ---------------
 * isaxcheck compares LLVM against `cap_disas_raw_detail()` — the decode
 * BOUNDARY.  That is not the last word on what the trace records.  The
 * plugin repairs some defects one layer further in, inside
 * decode_detail_to_generic(): apply_isa_branch_fixups() restores the `ra`
 * read RISC-V `ret` loses and the `ra` write `jal`/`jalr` lose, and the
 * operand walker, the dependency refiners and the lane-mask refiners all
 * rewrite what the boundary handed over.  Roughly 1.08 G dynamic
 * instructions per reference trace depend on that RISC-V repair alone.
 *
 * A gate that stops at the boundary is wrong about those twice.  It
 * reports a disagreement that the trace does not actually contain — and,
 * far worse, IF THE REPAIR REGRESSED THE GATE WOULD NOT NOTICE, because
 * the defect it would reintroduce is already in the gate's expected
 * output.  A repair the gate cannot see is a repair nothing is holding in
 * place.
 *
 * This header is the narrow seam that lets the gate reach the other side.
 * It exposes the InsnFields the dependency model actually records —
 * generic register ids, branch class, lane-mask kind, memop counts — with
 * NO plugin header in its interface, so the LLVM-facing translation unit
 * never has to include champsim_tracer.h.
 */
#ifndef ISAXCHECK_FIELDS_H
#define ISAXCHECK_FIELDS_H

#include <cstdint>
#include <vector>

struct qemu_plugin_insn_info;

/*
 * What the tracer's dependency model records for one instruction.
 * Deliberately a projection of InsnFields, not a copy: everything here is
 * something an independent decoder can be asked about.
 */
struct IsaxFieldsView {
    bool ok = false;
    uint8_t opcode = 0;             /* GenericOpcode */
    uint8_t branch_type = 0;        /* BranchType */
    bool branch_conditional = false;
    bool is_atomic = false;
    bool has_reg_deps = false;
    bool has_addr_deps = false;
    bool has_vec_lanes = false;
    uint8_t lane_mask_kind = 0;     /* LaneMaskKind */
    uint8_t max_dep_loads = 0;
    uint8_t max_dep_stores = 0;
    std::vector<uint8_t> src;       /* GenericRegId, in slot order */
    std::vector<uint8_t> dst;       /* GenericRegId, in slot order */
};

/* Select the per-ISA classification tables.  @isa_name is isaxcheck's
 * spelling ("aarch64" / "riscv64" / "mipsel" / "x86_64").  Returns false
 * for a name the tracer has no tables for. */
bool isax_fields_init(const char *isa_name);

/* Run the plugin's decode_detail_to_generic() over boundary output. */
bool isax_fields_decode(const struct qemu_plugin_insn_info *info,
                        IsaxFieldsView *out);

/* The tracer's own Capstone-register-id -> GenericRegId classification,
 * i.e. active_reg_table.  REG_NONE (0) for an id the table does not
 * classify or that is out of range. */
uint8_t isax_generic_reg(unsigned cap_reg_id);

/* Number of rows in the active register table; the caller enumerates it
 * to build a register-NAME -> GenericRegId map without duplicating the
 * table's contents. */
unsigned isax_reg_table_size(void);

/* Symbolic names, for signature keys a human has to read. */
const char *isax_generic_reg_name(unsigned gen_id);
const char *isax_branch_name(unsigned branch_type);
const char *isax_opcode_name(unsigned opcode);

/* GenericRegId values the comparison folds out on both sides, for the
 * same reasons is_dropped_reg() does at the boundary: the architectural
 * zero register is a dataflow no-op, and control flow travels through the
 * branch taxonomy rather than a REG_IP dependency edge. */
bool isax_generic_reg_dropped(unsigned gen_id);

#endif /* ISAXCHECK_FIELDS_H */
