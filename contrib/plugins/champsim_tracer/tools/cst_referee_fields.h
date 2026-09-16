/*
 * cst_referee_fields — the Capstone side of the comparison, reachable from a
 * host tool with no emulator and no plugin .so in the process.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * WHY THIS EXISTS
 * ---------------
 * The comparison capture used to write BOTH sides from inside a running
 * emulator: QEMU's statements as the emulator made them, and Capstone's
 * answer as the plugin's operand walk produced it.  That arrangement made
 * the second source a dependent of the thing being retired -- when the wire
 * stopped consulting the walk, the walk stopped being called, and with it
 * every corpus row the Capstone column was built from.  A join with one arm
 * is not a join, and the bar it carries reads "no subject" rather than zero.
 *
 * So the Capstone side is produced OFFLINE, here, from the encoding bytes the
 * QEMU-side corpus already records, by a binary that links its own copy of
 * the same pinned Capstone the tree names and nothing else.  Nothing on the
 * tracer's path can make this stop answering.
 *
 * WHAT IS REAL AND WHAT IS STUBBED
 * --------------------------------
 * Real, compiled verbatim and never reimplemented:
 *
 *   - champsim_tracer_decode.cc, the operand walk and the refiners;
 *   - champsim_tracer_mnemonic_tables.cc, the per-ISA classification rows;
 *   - champsim_tracer_capture.cc under -DCST_CAPTURE, so the corpora this
 *     writes are written by the SAME code that wrote them in-process and
 *     cannot drift into a second format;
 *   - disas/capstone.c, linked into the driver, so the boundary's defect
 *     workarounds (the PEXTR access flag, the MIPS MSA and unaligned
 *     access==0 rows, the x86 store-move destinations) apply exactly where
 *     they applied before.
 *
 * Stubbed, and every stub ABORTS rather than answering:
 *
 *   - QEMU's dataflow statement ABI.  Those entry points serve the capture's
 *     QEMU-side corpora, which an offline tool has no business writing: it
 *     has no emulator, so there are no statements to record.  A stub that
 *     returned an empty answer would let this tool write a QEMU column of
 *     silence that a scorer would read as a decoder saying nothing.  An abort
 *     says which entry point was reached instead.
 */
#ifndef CST_REFEREE_FIELDS_H
#define CST_REFEREE_FIELDS_H

#include <cstddef>
#include <cstdint>

struct qemu_plugin_insn_info;

/*
 * Select the per-ISA tables the way the plugin selects them at install time,
 * and resolve the Capstone arch/mode pair from the same ISA property row the
 * plugin reads.  @isa is "x86_64" / "aarch64" / "riscv64" / "mipsel".
 * False for a name there are no tables for.
 */
bool cstref_init(const char *isa);

/* The arch/mode this ISA's property row selects, for the boundary call. */
int cstref_cap_arch(void);
unsigned cstref_cap_mode(void);

/* What the walk recorded for one instruction, for the facts corpus. */
struct CstRefFacts {
    bool ok;                    /* false = the mnemonic is not in the table */
    uint8_t opcode;
    uint8_t branch_type;
    bool branch_conditional;
    bool is_atomic;
    bool has_reg_deps;
    bool has_addr_deps;
    bool has_vec_lanes;
    uint8_t lane_mask_kind;
    uint8_t lane_bytes;
    uint8_t max_dep_loads;
    uint8_t max_dep_stores;
    uint8_t n_src_regs;
    uint8_t n_dst_regs;
};

/*
 * Run the plugin's decode_detail_to_generic() over boundary output.
 *
 * The capture hooks fire from inside it, so this is also what writes the
 * Capstone-side corpus rows -- the same call, in the same order, from the
 * same source as the in-process arm.  @bytes/@nbytes are the encoding, which
 * the capture keys its rows on.
 */
bool cstref_decode(uint64_t pc, const void *bytes, size_t nbytes,
                   const struct qemu_plugin_insn_info *info,
                   CstRefFacts *out);

/* Symbolic names, for a row a human has to read. */
const char *cstref_opcode_name(unsigned opcode);
const char *cstref_branch_name(unsigned branch_type);
const char *cstref_reg_name(unsigned gen_id);

#endif /* CST_REFEREE_FIELDS_H */
