/*
 * Wrong-Path Tracing Plugin — Capstone detail → ISA-agnostic decode.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <array>
#include <string.h>
#include <stdlib.h>

#include "champsim_tracer.h"
#include "champsim_tracer_stats.h"

/*
 * Direct register ID lookup: O(1) array index into the per-ISA
 * RegClassification table.
 */
static const RegClassification *lookup_reg_class(uint16_t cap_id)
{
    if (cap_id == 0 || cap_id >= active_reg_table_size) {
        return nullptr;
    }
    return &active_reg_table[cap_id];
}

static inline bool qemu_reg_key_valid(const QemuRegKey *key)
{
    return key && key->name;
}

static inline void add_src_reg(InsnFields *f, InsnRegNames *refs,
                               uint8_t reg_id, const QemuRegKey *qemu_reg)
{
    if (reg_id == REG_NONE || f->n_src_regs >= MAX_SRC_REGS) {
        return;
    }
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        if (f->src_regs[i] == reg_id) {
            if (refs && !refs->src_qemu_reg_keys[i].name &&
                qemu_reg_key_valid(qemu_reg)) {
                refs->src_qemu_reg_keys[i] = *qemu_reg;
            }
            return;
        }
    }
    uint8_t slot = f->n_src_regs++;
    f->src_regs[slot] = reg_id;
    if (refs && qemu_reg_key_valid(qemu_reg)) {
        refs->src_qemu_reg_keys[slot] = *qemu_reg;
    }
}

static inline void add_dst_reg(InsnFields *f, InsnRegNames *refs,
                               uint8_t reg_id, const QemuRegKey *qemu_reg)
{
    if (reg_id == REG_NONE || f->n_dst_regs >= MAX_DST_REGS) {
        return;
    }
    for (uint8_t i = 0; i < f->n_dst_regs; i++) {
        if (f->dst_regs[i] == reg_id) {
            if (refs && !refs->dst_qemu_reg_keys[i].name &&
                qemu_reg_key_valid(qemu_reg)) {
                refs->dst_qemu_reg_keys[i] = *qemu_reg;
            }
            return;
        }
    }
    uint8_t slot = f->n_dst_regs++;
    f->dst_regs[slot] = reg_id;
    if (refs && qemu_reg_key_valid(qemu_reg)) {
        refs->dst_qemu_reg_keys[slot] = *qemu_reg;
    }
}

static inline void add_src_cap_reg(InsnFields *f, InsnRegNames *refs,
                                   uint16_t cap_id)
{
    const RegClassification *rc = lookup_reg_class(cap_id);
    if (!rc) {
        return;
    }
    if (rc->n_regs) {
        for (uint8_t i = 0; i < rc->n_regs && i < MAX_REG_ALIASES; i++) {
            add_src_reg(f, refs, rc->regs[i], nullptr);
        }
        return;
    }
    add_src_reg(f, refs, rc->reg_id, &rc->qemu_reg);
}

static inline void add_dst_cap_reg(InsnFields *f, InsnRegNames *refs,
                                   uint16_t cap_id)
{
    const RegClassification *rc = lookup_reg_class(cap_id);
    if (!rc) {
        return;
    }
    if (rc->n_regs) {
        for (uint8_t i = 0; i < rc->n_regs && i < MAX_REG_ALIASES; i++) {
            add_dst_reg(f, refs, rc->regs[i], nullptr);
        }
        return;
    }
    add_dst_reg(f, refs, rc->reg_id, &rc->qemu_reg);
}

static void warn_unknown_instruction(uint64_t pc, const char *reason,
                                     const char *mnem, const char *disas)
{
    if (!unknown_warn_file) {
        return;
    }

    g_mutex_lock(&unknown_warn_lock);
    fprintf(unknown_warn_file,
            "pc=0x%" PRIx64 " isa=%u reason=%s mnemonic=%s disas=\"%s\"\n",
            pc, (unsigned int)trace_isa, reason,
            mnem ? mnem : "<none>", disas ? disas : "");
    fflush(unknown_warn_file);
    g_stats.unknown_insn_warnings++;
    g_mutex_unlock(&unknown_warn_lock);
}

/*
 * Classify an instruction via direct insn_id array lookup (O(1)).
 * Returns the table row (or nullptr if out of range / no table) so
 * callers can also access the optional .refine callback.
 */
static const InsnClassification *classify_insn_id(
    const qemu_plugin_insn_info *info,
    uint8_t *opcode, uint8_t *branch_type, uint16_t *flags)
{
    uint32_t id = info->insn_id;

    if (active_insn_table && id < active_insn_table_size) {
        const InsnClassification *c = &active_insn_table[id];
        *opcode = c->opcode;
        *branch_type = c->branch_type;
        *flags = c->flags;
        return c;
    }

    *opcode = GEN_OP_UNKNOWN;
    *branch_type = BRANCH_NONE;
    *flags = MF_NONE;
    return nullptr;
}

/*
 * Decode structured Capstone detail into ISA-agnostic InsnFields.
 * Operand roles, implicit registers, and prefixes come directly from
 * Capstone's structured output.  Opcode and branch type come from the
 * mnemonic classification table.
 */
void decode_detail_to_generic(uint64_t pc,
                              const qemu_plugin_insn_info *info,
                              InsnFields *out,
                              InsnRegNames *out_names)
{
    memset(out, 0, sizeof(*out));
    if (out_names) {
        memset(out_names, 0, sizeof(*out_names));
    }

    if (!info || !info->mnemonic[0]) {
        return;
    }

    uint16_t flags = MF_NONE;
    const InsnClassification *cls =
        classify_insn_id(info, &out->opcode, &out->branch_type, &flags);

    if (info->has_lock || (flags & MF_ATOMIC)) {
        out->sync_hint = SYNC_ATOMIC;
    }

    if (out->opcode == GEN_OP_UNKNOWN) {
        char disas_buf[256];
        g_snprintf(disas_buf, sizeof(disas_buf), "%s %s",
                   info->mnemonic, info->op_str);
        warn_unknown_instruction(pc, "unknown_mnemonic",
                                 info->mnemonic, disas_buf);
        return;
    }

    if (flags & MF_CONDITIONAL) {
        out->branch_conditional = true;
    }
    if (out->branch_type == BRANCH_COND_DIRECT) {
        out->branch_conditional = true;
    }

    /*
     * Operand processing: use Capstone access flags where available
     * (x86/AArch64); otherwise fall back to an opcode-indexed lookup
     * where the first register operand is the destination for most
     * opcodes (not stores/cmp/branches/ret/syscall/nop).
     */
    static const auto opcode_first_is_dst = []() {
        std::array<bool, GEN_OP_COUNT> a{};
        a.fill(true);
        a[GEN_OP_STORE]   = false;
        a[GEN_OP_CMP]     = false;
        a[GEN_OP_BRANCH]  = false;
        a[GEN_OP_RET]     = false;
        a[GEN_OP_SYSCALL] = false;
        a[GEN_OP_NOP]     = false;
        return a;
    }();

    bool have_access_info = false;
    for (uint8_t i = 0; i < info->n_operands && !have_access_info; i++) {
        if (info->operands[i].access != 0) {
            have_access_info = true;
        }
    }

    bool first_is_dst = opcode_first_is_dst[out->opcode];
    bool seen_first_reg = false;
    for (uint8_t i = 0; i < info->n_operands; i++) {
        const qemu_plugin_operand *op = &info->operands[i];

        switch (op->type) {
        case QEMU_PLUGIN_OP_REG: {
            if (have_access_info) {
                if (op->access & QEMU_PLUGIN_OP_ACC_READ) {
                    add_src_cap_reg(out, out_names, op->reg_id);
                }
                if (op->access & QEMU_PLUGIN_OP_ACC_WRITE) {
                    add_dst_cap_reg(out, out_names, op->reg_id);
                }
            } else {
                if (first_is_dst && !seen_first_reg) {
                    add_dst_cap_reg(out, out_names, op->reg_id);
                } else {
                    add_src_cap_reg(out, out_names, op->reg_id);
                }
                seen_first_reg = true;
            }
            break;
        }
        case QEMU_PLUGIN_OP_IMM:
            if (!out->has_immediate) {
                out->has_immediate = true;
                out->immediate = op->imm;
            }
            break;
        case QEMU_PLUGIN_OP_MEM: {
            add_src_cap_reg(out, out_names, op->reg_id);
            add_src_cap_reg(out, out_names, op->index_id);
            break;
        }
        default:
            break;
        }
    }

    if (trace_isa != TRACE_ISA_RISCV && trace_isa != TRACE_ISA_MIPS) {
        for (uint8_t i = 0; i < info->n_regs_read; i++) {
            add_src_cap_reg(out, out_names, info->regs_read_id[i]);
        }
        for (uint8_t i = 0; i < info->n_regs_write; i++) {
            add_dst_cap_reg(out, out_names, info->regs_write_id[i]);
        }
    }

    /*
     * Optional ISA-specific post-classification refinement.  Each row
     * in the per-ISA mnemonic table may attach a .refine callback that
     * fixes up opcode/branch_type/etc. based on the operand-walk
    * result above.  Used for cases where one Capstone insn_id covers
    * multiple distinct operand encodings or target forms.
     */
    if (cls && cls->refine) {
        cls->refine(info, out);
    }

    /*
     * Normalize direct-branch immediate to absolute target.
     *
     * Capstone's convention differs by arch:
     *   - x86, ARM64: op->imm holds the resolved absolute target for
     *     direct (PC-relative-encoded) branches; no fixup needed.
     *   - RISC-V, MIPS: op->imm holds the raw signed PC-relative offset
     *     from the branch instruction; we add `pc` to produce the
     *     absolute target.
     *
     * After this step, InsnFields.immediate is always an absolute
    * branch target for direct conditional / direct unconditional
    * branches, which lets the WP-target derivation in
     * champsim_tracer.cc be ISA-agnostic.
     */
    if (out->has_immediate &&
        isa_properties[trace_isa].pc_relative_branch_imm) {
        bool is_direct_branch =
            out->branch_type == BRANCH_COND_DIRECT ||
            out->branch_type == BRANCH_DIRECT_JUMP;
        if (is_direct_branch) {
            out->immediate = (int64_t)((uint64_t)pc + (uint64_t)out->immediate);
        }
    }

}
