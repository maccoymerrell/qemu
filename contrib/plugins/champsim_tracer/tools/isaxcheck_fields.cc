/*
 * isaxcheck_fields — run the tracer's own decode_detail_to_generic() from a
 * host tool, so the decode gate can compare what the DEPENDENCY MODEL
 * records rather than what the decode boundary handed it.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This translation unit is the only one that sees both champsim_tracer.h
 * and the tool side.  Everything it exports is in isaxcheck_fields.h, which
 * names no plugin type — isaxcheck.cc pulls in the whole LLVM MC headers,
 * and putting the two include worlds in one file buys nothing but grief.
 *
 * WHAT IS AND IS NOT STUBBED
 * --------------------------
 * champsim_tracer_decode.cc is compiled here verbatim; there is no second
 * copy of the dependency model and no reimplementation of one, because a
 * gate that measured a reimplementation would measure the wrong thing.
 * What it needs from the rest of the plugin splits cleanly in two:
 *
 *   - The classification tables and the ISA property row.  Real, from
 *     champsim_tracer_mnemonic_tables.cc, selected here exactly the way
 *     the plugin selects them at install time.
 *
 *   - The RUNNING plugin: live vCPU register reads, the per-thread stats
 *     registry, the sidecar warning log.  Those are stubbed, and they are
 *     stubbable precisely because decode_detail_to_generic() does not
 *     consult any of them.  It reads an insn_info and the tables and
 *     writes an InsnFields; the only paths that touch a vCPU are
 *     capture_initial_regfile() (a different entry point in the same file)
 *     and the unknown-mnemonic warning, which counts and logs.
 *
 * If a future change makes the decode path depend on live machine state,
 * this file stops linking, which is the right failure: the gate would
 * otherwise start measuring a decode that never happens.
 */

#include "champsim_tracer.h"
#include "champsim_tracer_mnemonics.h"
#include "champsim_tracer_reg_handle_cache.h"
#include "champsim_tracer_stats.h"

#include "isaxcheck_fields.h"

#include <cstring>

/* ------------------------------------------------------------------ */
/* Plugin globals the decode path reads.                               */
/* ------------------------------------------------------------------ */

TraceISA trace_isa = TRACE_ISA_UNKNOWN;
bool target_big_endian = false;
const InsnClassification *active_insn_table = nullptr;
unsigned active_insn_table_size = 0;
const RegClassification *active_reg_table = nullptr;
unsigned active_reg_table_size = 0;
GMutex unknown_warn_lock;
FILE *unknown_warn_file = nullptr;

/* ------------------------------------------------------------------ */
/* Plugin runtime the decode path does NOT read (see the file header). */
/* ------------------------------------------------------------------ */

/* g_reg_handle_cache comes from champsim_tracer_reg_handle_cache.cc, which
 * is linked in rather than stubbed: a stub would have to reimplement the
 * cache's construction, and a class whose lifetime the tool got wrong
 * would fail in a way that looked like a decode difference.  With no vCPU
 * present its lookups find nothing, which is exactly how its one caller
 * (capture_initial_regfile(), not on the decode path) already treats a
 * register it cannot read. */

Stats &thread_stats_get()
{
    static Stats s;
    return s;
}

extern "C" {

int qemu_plugin_read_register(struct qemu_plugin_register *, GByteArray *)
{
    return 0;
}

GArray *qemu_plugin_get_registers(void)
{
    return nullptr;
}

/*
 * The tables TU sniffs the guest ELF through this to pick a Capstone mode
 * from the binary's actual extension set.  There is no guest here; the
 * tables then fall back to the same default cap_mode_*() set isaxcheck's
 * kIsaTable mirrors, which is what makes the two sides comparable.
 */
const char *qemu_plugin_path_to_binary(void)
{
    return nullptr;
}

} /* extern "C" */

/* ------------------------------------------------------------------ */

static bool table_ready;

bool isax_fields_init(const char *isa_name)
{
    TraceISA isa = TRACE_ISA_UNKNOWN;
    if (!strcmp(isa_name, "aarch64")) {
        isa = TRACE_ISA_AARCH64;
    } else if (!strcmp(isa_name, "riscv64")) {
        isa = TRACE_ISA_RISCV;
    } else if (!strcmp(isa_name, "mipsel")) {
        isa = TRACE_ISA_MIPS;
    } else if (!strcmp(isa_name, "x86_64")) {
        isa = TRACE_ISA_X86;
    } else {
        return false;
    }

    /* The same four assignments champsim_tracer.cc makes at install time,
     * followed by the same reverse-index build.  Kept in this order and
     * with no additions on purpose: if the plugin grows a fifth thing it
     * must set before decoding, the difference belongs here, visibly. */
    trace_isa = isa;
    active_insn_table = isa_insn_class[isa];
    active_insn_table_size = isa_insn_class_size[isa];
    active_reg_table = isa_reg_class[isa];
    active_reg_table_size = isa_reg_class_size[isa];
    build_qemu_reg_reverse_index();
    table_ready = active_insn_table && active_reg_table;
    return table_ready;
}

bool isax_fields_decode(const struct qemu_plugin_insn_info *info,
                        IsaxFieldsView *out)
{
    if (!table_ready || !info || !out) {
        return false;
    }
    InsnFieldsScratch scratch;
    insn_fields_scratch_reset(&scratch);
    decode_detail_to_generic(0x100000, info, &scratch.f, nullptr);

    const InsnFields &f = scratch.f;
    /* GEN_OP_UNKNOWN is decode_detail_to_generic()'s early return: the
     * mnemonic is not in the ISA table, so nothing downstream of the
     * classification ran and the fields are empty by construction, not by
     * dataflow.  Reporting that as "the dependency model records no
     * registers" would be a lie about a case the tracer already logs. */
    out->ok = f.opcode != GEN_OP_UNKNOWN;
    out->opcode = f.opcode;
    out->branch_type = f.branch_type;
    out->branch_conditional = f.branch_conditional;
    out->is_atomic = f.is_atomic;
    out->has_reg_deps = f.has_reg_deps;
    out->has_addr_deps = f.has_addr_deps;
    out->has_vec_lanes = f.has_vec_lanes;
    out->lane_mask_kind = f.lane_mask_kind;
    out->max_dep_loads = f.max_dep_loads;
    out->max_dep_stores = f.max_dep_stores;
    out->src.assign(f.src_regs, f.src_regs + f.n_src_regs);
    out->dst.assign(f.dst_regs, f.dst_regs + f.n_dst_regs);
    out->load_addr_dep.assign(f.load_addr_dep_mask,
                              f.load_addr_dep_mask + f.max_dep_loads);
    out->store_addr_dep.assign(f.store_addr_dep_mask,
                               f.store_addr_dep_mask + f.max_dep_stores);
    return true;
}

uint8_t isax_generic_reg(unsigned cap_reg_id)
{
    if (!active_reg_table || cap_reg_id >= active_reg_table_size) {
        return REG_NONE;
    }
    return active_reg_table[cap_reg_id].reg_id;
}

/*
 * A QEMU_PLUGIN_OP_SYSREG operand carries an architectural role rather
 * than a register id, because Capstone has ids for almost none of these
 * registers.  It resolves through the same role rename the decoder
 * itself uses, not through the register table.
 */
uint8_t isax_generic_sysreg(unsigned sysreg_class)
{
    return generic_reg_for_sysreg_class((uint8_t)sysreg_class);
}

unsigned isax_reg_table_size(void)
{
    return active_reg_table_size;
}

const char *isax_generic_reg_name(unsigned gen_id)
{
    return generic_reg_name_or_unknown(gen_id);
}

bool isax_generic_reg_indexed_file(unsigned gen_id)
{
    return generic_reg_is_indexed_file(gen_id);
}

const char *isax_branch_name(unsigned branch_type)
{
    return branch_type_name_or_unknown(branch_type);
}

const char *isax_opcode_name(unsigned opcode)
{
    return generic_opcode_name_or_unknown(opcode);
}

static bool fields_drop_zero = true;

void isax_fields_set_drop_zero(bool drop)
{
    fields_drop_zero = drop;
}

bool isax_generic_reg_dropped(unsigned gen_id)
{
    /* Mirrors is_dropped_reg() on the boundary side: the architectural
     * zero register is a dataflow no-op whichever decoder names it, and
     * the tracer carries control flow through the BRANCH_* taxonomy and
     * the entry stream, never through a REG_IP dependency edge.
     *
     * REG_ZERO used to be struck here UNCONDITIONALLY while the boundary
     * side honoured --keep-zero, so the flag was inert on this layer and
     * the gate had no arm for the whole class -- measured, not inferred:
     * on the binary that still had Capstone's fabricated $zero destination
     * for `div`/`divu`, a mipsel fields sweep reported the identical
     * 534/534 with the flag and without it.  The mirror is now exact. */
    if (gen_id == REG_ZERO) {
        return fields_drop_zero;
    }
    return gen_id == REG_NONE || gen_id == REG_IP;
}
