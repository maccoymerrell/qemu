/*
 * Wrong-Path Tracing Plugin — Capstone detail → ISA-agnostic decode.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <array>
#include <string.h>
#include <stdlib.h>

#include "champsim_tracer.h"

/*
 * Direct register ID lookup: O(1) array index into the per-ISA
 * RegClassification table.
 */
static uint8_t parse_reg_id(uint16_t cap_id)
{
    if (cap_id == 0 || cap_id >= active_reg_table_size) {
        return REG_NONE;
    }
    return active_reg_table[cap_id].reg_id;
}

static inline void add_src_reg(InsnFields *f, uint8_t reg_id,
                               InsnRegNames *names, const char *name)
{
    if (reg_id == REG_NONE || f->n_src_regs >= MAX_SRC_REGS) {
        return;
    }
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        if (f->src_regs[i] == reg_id) {
            return;
        }
    }
    if (names && name) {
        g_strlcpy(names->src[f->n_src_regs], name,
                  sizeof(names->src[0]));
    }
    f->src_regs[f->n_src_regs++] = reg_id;
}

static inline void add_dst_reg(InsnFields *f, uint8_t reg_id,
                               InsnRegNames *names, const char *name)
{
    if (reg_id == REG_NONE || f->n_dst_regs >= MAX_DST_REGS) {
        return;
    }
    for (uint8_t i = 0; i < f->n_dst_regs; i++) {
        if (f->dst_regs[i] == reg_id) {
            return;
        }
    }
    if (names && name) {
        g_strlcpy(names->dst[f->n_dst_regs], name,
                  sizeof(names->dst[0]));
    }
    f->dst_regs[f->n_dst_regs++] = reg_id;
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
    stat_unknown_insn_warnings++;
    g_mutex_unlock(&unknown_warn_lock);
}

/*
 * Derive BranchType from Capstone instruction groups and MNEM-table
 * flags, without any string parsing.
 */
static uint8_t branch_type_from_groups(uint16_t groups, uint16_t mf_flags)
{
    bool is_jump = (groups & QEMU_PLUGIN_GRP_JUMP) != 0;
    bool is_call = (groups & QEMU_PLUGIN_GRP_CALL) != 0;
    bool is_ret  = (groups & QEMU_PLUGIN_GRP_RET) != 0;
    bool is_rel  = (groups & QEMU_PLUGIN_GRP_BRANCH_REL) != 0;
    bool is_int  = (groups & QEMU_PLUGIN_GRP_INT) != 0;

    if (is_int) {
        return BRANCH_SYSCALL_TYPE;
    }

    if (is_ret) {
        return BRANCH_RETURN;
    }

    if (is_call) {
        if (is_rel) {
            return BRANCH_DIRECT_CALL;
        }
        return BRANCH_INDIRECT_CALL;
    }

    if (is_jump) {
        bool type_conditional = (mf_flags & MF_CONDITIONAL) != 0;
        if (is_rel) {
            return type_conditional ? BRANCH_COND_DIRECT
                                    : BRANCH_DIRECT_JUMP;
        }
        return BRANCH_INDIRECT_JUMP;
    }

    return BRANCH_NONE;
}

/*
 * Classify an instruction via direct insn_id array lookup (O(1)).
 * Returns the table row (or NULL if out of range / no table) so
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
    return NULL;
}

/*
 * Decode structured Capstone detail into ISA-agnostic InsnFields.
 * Operand roles, branch type, implicit registers, and prefixes all come
 * directly from Capstone's structured output — no disassembly parsing.
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

    if (flags & MF_VARIABLE_MEMOP) {
        out->variable_memop = true;
    }

    if (out->opcode == GEN_OP_UNKNOWN) {
        char disas_buf[256];
        g_snprintf(disas_buf, sizeof(disas_buf), "%s %s",
                   info->mnemonic, info->op_str);
        warn_unknown_instruction(pc, "unknown_mnemonic",
                                 info->mnemonic, disas_buf);
        return;
    }

    /*
     * Prefer Capstone group-based branch classification; only keep the
     * MNEM table's branch_type when it identifies an INDIRECT variant
     * that Capstone would otherwise downgrade to DIRECT (some Capstone
     * builds set BRANCH_RELATIVE on BLR/BR).
     */
    uint8_t cap_branch = branch_type_from_groups(info->groups, flags);
    uint8_t mnem_branch = out->branch_type;
    if (cap_branch != BRANCH_NONE) {
        bool mnem_indirect = (mnem_branch == BRANCH_INDIRECT_CALL ||
                              mnem_branch == BRANCH_INDIRECT_JUMP);
        bool cap_direct = (cap_branch == BRANCH_DIRECT_CALL ||
                           cap_branch == BRANCH_DIRECT_JUMP);
        if (!(mnem_indirect && cap_direct)) {
            out->branch_type = cap_branch;
        }
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
    bool saw_mem_op = false;

    for (uint8_t i = 0; i < info->n_operands; i++) {
        const qemu_plugin_operand *op = &info->operands[i];

        switch (op->type) {
        case QEMU_PLUGIN_OP_REG: {
            uint8_t r = parse_reg_id(op->reg_id);
            if (r == REG_NONE) {
                break;
            }
            if (have_access_info) {
                if (op->access & QEMU_PLUGIN_OP_ACC_READ) {
                    add_src_reg(out, r, out_names, op->reg_name);
                }
                if (op->access & QEMU_PLUGIN_OP_ACC_WRITE) {
                    add_dst_reg(out, r, out_names, op->reg_name);
                }
            } else {
                if (first_is_dst && !seen_first_reg) {
                    add_dst_reg(out, r, out_names, op->reg_name);
                } else {
                    add_src_reg(out, r, out_names, op->reg_name);
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
            saw_mem_op = true;
            uint8_t base = parse_reg_id(op->reg_id);
            if (base != REG_NONE) {
                add_src_reg(out, base, out_names, op->reg_name);
            }
            uint8_t idx = parse_reg_id(op->index_id);
            if (idx != REG_NONE) {
                add_src_reg(out, idx, out_names, op->index_name);
            }
            /*
             * Populate per-insn observed-max load/store count from
             * Capstone operand access flags.  Missing flag info (some
             * ISAs, or operand type without access) falls back to the
             * opcode category below.
             *
             * LEA has an OP_MEM operand for address computation but
             * does not actually access memory.  Capstone may report
             * CS_AC_READ on that operand; ignore the access flags for
             * pure address-compute opcodes.
             */
            if (out->opcode != GEN_OP_LEA) {
                if (op->access & QEMU_PLUGIN_OP_ACC_READ) {
                    if (out->n_loads < 0xFF) out->n_loads++;
                }
                if (op->access & QEMU_PLUGIN_OP_ACC_WRITE) {
                    if (out->n_stores < 0xFF) out->n_stores++;
                }
            }
            break;
        }
        default:
            break;
        }
    }

    /* Implicit registers from Capstone detail. */
    for (uint8_t i = 0; i < info->n_regs_read; i++) {
        uint8_t r = parse_reg_id(info->regs_read_id[i]);
        if (r != REG_NONE) {
            add_src_reg(out, r, out_names, info->regs_read[i]);
        }
    }
    for (uint8_t i = 0; i < info->n_regs_write; i++) {
        uint8_t r = parse_reg_id(info->regs_write_id[i]);
        if (r != REG_NONE) {
            add_dst_reg(out, r, out_names, info->regs_write[i]);
        }
    }

    /*
     * Optional ISA-specific post-classification refinement.  Each row
     * in the per-ISA mnemonic table may attach a .refine callback that
     * fixes up opcode/branch_type/etc. based on the operand-walk
     * result above.  Used for cases where one Capstone insn_id covers
     * multiple distinct semantics (e.g. RISC-V JALR: indirect call vs.
     * indirect jump vs. ret).
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
     * branch target for direct conditional / direct unconditional /
     * direct call branches, which lets the WP-target derivation in
     * champsim_tracer.cc be ISA-agnostic.
     */
    if (out->has_immediate &&
        isa_properties[trace_isa].pc_relative_branch_imm) {
        bool is_direct_branch =
            out->branch_type == BRANCH_COND_DIRECT ||
            out->branch_type == BRANCH_DIRECT_JUMP ||
            out->branch_type == BRANCH_DIRECT_CALL;
        if (is_direct_branch) {
            out->immediate = (int64_t)((uint64_t)pc + (uint64_t)out->immediate);
        }
    }

    /*
     * Fallback: when Capstone reported a memory operand but did not
     * populate its per-operand access flags (some ISAs, or operand
     * types without access info), infer a single load/store from the
     * opcode category.  Only applies when an OP_MEM was actually
     * seen — a register-only insn (e.g. "cmp %rax, %rdx") must keep
     * n_loads = n_stores = 0.
     */
    if (saw_mem_op && out->n_loads == 0 && out->n_stores == 0) {
        if (out->opcode == GEN_OP_LOAD || out->opcode == GEN_OP_CMP) {
            out->n_loads = 1;
        } else if (out->opcode == GEN_OP_STORE) {
            out->n_stores = 1;
        }
    }
}
