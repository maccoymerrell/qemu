/*
 * Interface to the capstone disassembler.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu/qemu-plugin.h"
#include "disas/dis-asm.h"
#include "disas/capstone.h"


/*
 * Temporary storage for the capstone library.  This will be alloced via
 * malloc with a size private to the library; thus there's no reason not
 * to share this across calls and across host vs target disassembly.
 */
static __thread cs_insn *cap_insn;

/*
 * The capstone library always skips 2 bytes for S390X.
 * This is less than ideal, since we can tell from the first two bits
 * the size of the insn and thus stay in sync with the insn stream.
 */
static size_t CAPSTONE_API
cap_skipdata_s390x_cb(const uint8_t *code, size_t code_size,
                      size_t offset, void *user_data)
{
    size_t ilen;

    /* See get_ilen() in target/s390x/internal.h.  */
    switch (code[offset] >> 6) {
    case 0:
        ilen = 2;
        break;
    case 1:
    case 2:
        ilen = 4;
        break;
    default:
        ilen = 6;
        break;
    }

    return ilen;
}

static const cs_opt_skipdata cap_skipdata_s390x = {
    .mnemonic = ".byte",
    .callback = cap_skipdata_s390x_cb
};

/*
 * Initialize the Capstone library.
 *
 * ??? It would be nice to cache this.  We would need one handle for the
 * host and one for the target.  For most targets we can reset specific
 * parameters via cs_option(CS_OPT_MODE, new_mode), but we cannot change
 * CS_ARCH_* in this way.  Thus we would need to be able to close and
 * re-open the target handle with a different arch for the target in order
 * to handle AArch64 vs AArch32 mode switching.
 */
static cs_err cap_disas_start(disassemble_info *info, csh *handle)
{
    cs_mode cap_mode = info->cap_mode;
    cs_err err;

    cap_mode += (info->endian == BFD_ENDIAN_BIG ? CS_MODE_BIG_ENDIAN
                 : CS_MODE_LITTLE_ENDIAN);

    err = cs_open(info->cap_arch, cap_mode, handle);
    if (err != CS_ERR_OK) {
        return err;
    }

    /* "Disassemble" unknown insns as ".byte W,X,Y,Z".  */
    cs_option(*handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    switch (info->cap_arch) {
    case CS_ARCH_SYSZ:
        cs_option(*handle, CS_OPT_SKIPDATA_SETUP,
                  (uintptr_t)&cap_skipdata_s390x);
        break;

    case CS_ARCH_X86:
        /*
         * We don't care about errors (if for some reason the library
         * is compiled without AT&T syntax); the user will just have
         * to deal with the Intel syntax.
         */
        cs_option(*handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
        break;
    }

    /* Allocate temp space for cs_disasm_iter.  */
    if (cap_insn == NULL) {
        cap_insn = cs_malloc(*handle);
        if (cap_insn == NULL) {
            cs_close(handle);
            return CS_ERR_MEM;
        }
    }
    return CS_ERR_OK;
}

static void cap_dump_insn_units(disassemble_info *info, cs_insn *insn,
                                int i, int n)
{
    fprintf_function print = info->fprintf_func;
    FILE *stream = info->stream;

    switch (info->cap_insn_unit) {
    case 4:
        if (info->endian == BFD_ENDIAN_BIG) {
            for (; i < n; i += 4) {
                print(stream, " %08x", ldl_be_p(insn->bytes + i));

            }
        } else {
            for (; i < n; i += 4) {
                print(stream, " %08x", ldl_le_p(insn->bytes + i));
            }
        }
        break;

    case 2:
        if (info->endian == BFD_ENDIAN_BIG) {
            for (; i < n; i += 2) {
                print(stream, " %04x", lduw_be_p(insn->bytes + i));
            }
        } else {
            for (; i < n; i += 2) {
                print(stream, " %04x", lduw_le_p(insn->bytes + i));
            }
        }
        break;

    default:
        for (; i < n; i++) {
            print(stream, " %02x", insn->bytes[i]);
        }
        break;
    }
}

static void cap_dump_insn(disassemble_info *info, cs_insn *insn)
{
    fprintf_function print = info->fprintf_func;
    FILE *stream = info->stream;
    int i, n, split;

    print(stream, "0x%08" PRIx64 ": ", insn->address);

    n = insn->size;
    split = info->cap_insn_split;

    /* Dump the first SPLIT bytes of the instruction.  */
    cap_dump_insn_units(info, insn, 0, MIN(n, split));

    /* Add padding up to SPLIT so that mnemonics line up.  */
    if (n < split) {
        int width = (split - n) / info->cap_insn_unit;
        width *= (2 * info->cap_insn_unit + 1);
        print(stream, "%*s", width, "");
    }

    /* Print the actual instruction.  */
    print(stream, "  %-8s %s\n", insn->mnemonic, insn->op_str);

    /* Dump any remaining part of the insn on subsequent lines.  */
    for (i = split; i < n; i += split) {
        print(stream, "0x%08" PRIx64 ": ", insn->address + i);
        cap_dump_insn_units(info, insn, i, MIN(n, i + split));
        print(stream, "\n");
    }
}

/* Disassemble SIZE bytes at PC for the target.  */
bool cap_disas_target(disassemble_info *info, uint64_t pc, size_t size)
{
    uint8_t cap_buf[1024];
    csh handle;
    cs_insn *insn;
    size_t csize = 0;

    if (cap_disas_start(info, &handle) != CS_ERR_OK) {
        return false;
    }
    insn = cap_insn;

    while (1) {
        size_t tsize = MIN(sizeof(cap_buf) - csize, size);
        const uint8_t *cbuf = cap_buf;

        if (info->read_memory_func(pc + csize, cap_buf + csize, tsize, info) == 0) {
            csize += tsize;
            size -= tsize;

            while (cs_disasm_iter(handle, &cbuf, &csize, &pc, insn)) {
                cap_dump_insn(info, insn);
            }

            /* If the target memory is not consumed, go back for more... */
            if (size != 0) {
                /*
                 * ... taking care to move any remaining fractional insn
                 * to the beginning of the buffer.
                 */
                if (csize != 0) {
                    memmove(cap_buf, cbuf, csize);
                }
                continue;
            }

            /*
             * Since the target memory is consumed, we should not have
             * a remaining fractional insn.
             */
            if (csize != 0) {
                info->fprintf_func(info->stream,
                                   "Disassembler disagrees with translator "
                                   "over instruction decoding\n"
                                   "Please report this to qemu-devel@nongnu.org\n");
            }
            break;

        } else {
            info->fprintf_func(info->stream,
                               "0x%08" PRIx64 ": unable to read memory\n", pc);
            break;
        }
    }

    cs_close(&handle);
    return true;
}

/* Disassemble SIZE bytes at CODE for the host.  */
bool cap_disas_host(disassemble_info *info, const void *code, size_t size)
{
    csh handle;
    const uint8_t *cbuf;
    cs_insn *insn;
    uint64_t pc;

    if (cap_disas_start(info, &handle) != CS_ERR_OK) {
        return false;
    }
    insn = cap_insn;

    cbuf = code;
    pc = (uintptr_t)code;

    while (cs_disasm_iter(handle, &cbuf, &size, &pc, insn)) {
        cap_dump_insn(info, insn);
    }
    if (size != 0) {
        info->fprintf_func(info->stream,
            "Disassembler disagrees with TCG over instruction encoding\n"
            "Please report this to qemu-devel@nongnu.org\n");
    }

    cs_close(&handle);
    return true;
}

/* Disassemble COUNT insns at PC for the target.  */
bool cap_disas_monitor(disassemble_info *info, uint64_t pc, int count)
{
    uint8_t cap_buf[32];
    csh handle;
    cs_insn *insn;
    size_t csize = 0;

    if (cap_disas_start(info, &handle) != CS_ERR_OK) {
        return false;
    }
    insn = cap_insn;

    while (1) {
        /*
         * We want to read memory for one insn, but generically we do not
         * know how much memory that is.  We have a small buffer which is
         * known to be sufficient for all supported targets.  Try to not
         * read beyond the page, Just In Case.  For even more simplicity,
         * ignore the actual target page size and use a 1k boundary.  If
         * that turns out to be insufficient, we'll come back around the
         * loop and read more.
         */
        uint64_t epc = QEMU_ALIGN_UP(pc + csize + 1, 1024);
        size_t tsize = MIN(sizeof(cap_buf) - csize, epc - pc);
        const uint8_t *cbuf = cap_buf;

        /* Make certain that we can make progress.  */
        assert(tsize != 0);
        if (info->read_memory_func(pc + csize, cap_buf + csize,
                                   tsize, info) == 0)
        {
            csize += tsize;

            if (cs_disasm_iter(handle, &cbuf, &csize, &pc, insn)) {
                cap_dump_insn(info, insn);
                if (--count <= 0) {
                    break;
                }
            }
            memmove(cap_buf, cbuf, csize);
        } else {
            info->fprintf_func(info->stream,
                               "0x%08" PRIx64 ": unable to read memory\n", pc);
            break;
        }
    }

    cs_close(&handle);
    return true;
}

/* Disassemble a single instruction directly into plugin output */
bool cap_disas_plugin(disassemble_info *info, uint64_t pc, size_t size)
{
    uint8_t cap_buf[32];
    const uint8_t *cbuf = cap_buf;
    csh handle;

    if (cap_disas_start(info, &handle) != CS_ERR_OK) {
        return false;
    }

    assert(size < sizeof(cap_buf));
    info->read_memory_func(pc, cap_buf, size, info);

    if (cs_disasm_iter(handle, &cbuf, &size, &pc, cap_insn)) {
        info->fprintf_func(info->stream, "%s %s",
                           cap_insn->mnemonic, cap_insn->op_str);
    }

    cs_close(&handle);
    return true;
}

/*
 * Map a Capstone generic group ID (CS_GRP_*) to a QEMU_PLUGIN_GRP_* bit.
 */
static uint16_t cap_group_to_plugin_bit(uint8_t grp)
{
    switch (grp) {
    case CS_GRP_JUMP:            return QEMU_PLUGIN_GRP_JUMP;
    case CS_GRP_CALL:            return QEMU_PLUGIN_GRP_CALL;
    case CS_GRP_RET:             return QEMU_PLUGIN_GRP_RET;
    case CS_GRP_INT:             return QEMU_PLUGIN_GRP_INT;
    case CS_GRP_IRET:            return QEMU_PLUGIN_GRP_IRET;
    case CS_GRP_PRIVILEGE:       return QEMU_PLUGIN_GRP_PRIVILEGE;
    case CS_GRP_BRANCH_RELATIVE: return QEMU_PLUGIN_GRP_BRANCH_REL;
    default:                     return 0;
    }
}

/*
 * Per-arch upper bound on the register-ID space used by Capstone's
 * generated getRegisterName() asm-printer table.  Each Capstone arch
 * has its own enum that ends in `<ARCH>_REG_ENDING`, and the auto-
 * generated `getRegisterName()` asserts `RegNo && RegNo < N`.  When
 * Capstone is built with CAPSTONE_DEBUG (the default for a meson
 * `Debug` build-type) that assertion abort()s the host process —
 * even though `cs_reg_name()` would otherwise return NULL for the
 * same input.  In Capstone 6.0-Alpha7 the upstream RISC-V decoder
 * occasionally produces out-of-range IDs in the implicit
 * regs_read[] / regs_write[] arrays attached to vector pseudo-ops,
 * which is what triggers the abort under wrong-path execution.
 */
static unsigned int cap_arch_reg_upper(int cap_arch)
{
    switch (cap_arch) {
    case CS_ARCH_X86:      return X86_REG_ENDING;
    case CS_ARCH_ARM64:  return AARCH64_REG_ENDING;
    case CS_ARCH_ARM:      return ARM_REG_ENDING;
    case CS_ARCH_RISCV:    return RISCV_REG_ENDING;
    case CS_ARCH_MIPS:     return MIPS_REG_ENDING;
    case CS_ARCH_PPC:      return PPC_REG_ENDING;
    case CS_ARCH_SPARC:    return SPARC_REG_ENDING;
    case CS_ARCH_SYSZ:  return SYSTEMZ_REG_ENDING;
    default:               return 0;
    }
}

/*
 * Copy a Capstone register name into a fixed-size buffer.  See
 * cap_arch_reg_upper() for why the bound check is necessary.
 */
static void cap_copy_reg_name(char *dst, size_t dstsz,
                              csh handle, unsigned int reg_id,
                              int cap_arch)
{
    if (reg_id == 0) {
        dst[0] = '\0';
        return;
    }
    unsigned int upper = cap_arch_reg_upper(cap_arch);
    if (upper && reg_id >= upper) {
        dst[0] = '\0';
        return;
    }
    const char *name = cs_reg_name(handle, reg_id);
    if (name) {
        g_strlcpy(dst, name, dstsz);
    } else {
        dst[0] = '\0';
    }
}

/*
 * Extract per-operand detail for x86 into the plugin operand struct.
 */
static void cap_fill_x86_operands(csh handle, const cs_insn *insn,
                                  qemu_plugin_insn_info *out)
{
    const cs_x86 *x86 = &insn->detail->x86;
    uint8_t n = MIN(x86->op_count, QEMU_PLUGIN_INSN_DETAIL_MAX_OPS);
    out->n_operands = n;

    for (uint8_t i = 0; i < n; i++) {
        const cs_x86_op *cop = &x86->operands[i];
        qemu_plugin_operand *op = &out->operands[i];

        op->access = cop->access;
        op->size = cop->size;

        switch (cop->type) {
        case X86_OP_REG:
            op->type = QEMU_PLUGIN_OP_REG;
            cap_copy_reg_name(op->reg_name,
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                              handle, cop->reg, CS_ARCH_X86);
            op->reg_id     = cop->reg;
            op->index_name[0] = '\0';
            op->index_id   = 0;
            op->imm = 0;
            break;
        case X86_OP_IMM:
            op->type = QEMU_PLUGIN_OP_IMM;
            op->imm = cop->imm;
            op->reg_name[0] = '\0';
            op->reg_id     = 0;
            op->index_name[0] = '\0';
            op->index_id   = 0;
            break;
        case X86_OP_MEM:
            op->type = QEMU_PLUGIN_OP_MEM;
            cap_copy_reg_name(op->reg_name,
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                              handle, cop->mem.base, CS_ARCH_X86);
            op->reg_id     = cop->mem.base;
            cap_copy_reg_name(op->index_name,
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                              handle, cop->mem.index, CS_ARCH_X86);
            op->index_id   = cop->mem.index;
            op->imm = cop->mem.disp;
            break;
        default:
            op->type = QEMU_PLUGIN_OP_INVALID;
            op->reg_name[0] = '\0';
            op->reg_id     = 0;
            op->index_name[0] = '\0';
            op->index_id   = 0;
            op->imm = 0;
            break;
        }
    }

    /* x86 prefixes */
    out->has_lock = (x86->prefix[0] == X86_PREFIX_LOCK);
    out->has_rep = (x86->prefix[0] == X86_PREFIX_REP ||
                    x86->prefix[0] == X86_PREFIX_REPNE);
}

/*
 * Extract per-operand detail for AArch64 into the plugin operand struct.
 */
static void cap_fill_arm64_operands(csh handle, const cs_insn *insn,
                                    qemu_plugin_insn_info *out)
{
    const cs_arm64 *a64 = &insn->detail->arm64;
    uint8_t n = MIN(a64->op_count, QEMU_PLUGIN_INSN_DETAIL_MAX_OPS);
    out->n_operands = n;

    for (uint8_t i = 0; i < n; i++) {
        const cs_arm64_op *cop = &a64->operands[i];
        qemu_plugin_operand *op = &out->operands[i];

        op->access = cop->access;
        op->size = 0; /* AArch64 Capstone doesn't provide per-op size */

        switch (cop->type) {
        case ARM64_OP_REG:
            op->type = QEMU_PLUGIN_OP_REG;
            cap_copy_reg_name(op->reg_name,
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                              handle, cop->reg, CS_ARCH_ARM64);
            op->reg_id     = cop->reg;
            op->index_name[0] = '\0';
            op->index_id   = 0;
            op->imm = 0;
            break;
        case ARM64_OP_IMM:
            op->type = QEMU_PLUGIN_OP_IMM;
            op->imm = cop->imm;
            op->reg_name[0] = '\0';
            op->reg_id     = 0;
            op->index_name[0] = '\0';
            op->index_id   = 0;
            break;
        case ARM64_OP_MEM:
            op->type = QEMU_PLUGIN_OP_MEM;
            cap_copy_reg_name(op->reg_name,
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                              handle, cop->mem.base, CS_ARCH_ARM64);
            op->reg_id     = cop->mem.base;
            cap_copy_reg_name(op->index_name,
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                              handle, cop->mem.index, CS_ARCH_ARM64);
            op->index_id   = cop->mem.index;
            op->imm = cop->mem.disp;
            break;
        default:
            op->type = QEMU_PLUGIN_OP_INVALID;
            op->reg_name[0] = '\0';
            op->reg_id     = 0;
            op->index_name[0] = '\0';
            op->index_id   = 0;
            op->imm = 0;
            break;
        }
    }
}

/*
 * Extract per-operand detail for RISC-V or MIPS (no access info).
 */
static void cap_fill_generic_operands(csh handle, const cs_insn *insn,
                                      qemu_plugin_insn_info *out,
                                      int cap_arch)
{
    const cs_detail *detail = insn->detail;
    uint8_t n;

    if (cap_arch == CS_ARCH_RISCV) {
        n = MIN(detail->riscv.op_count, QEMU_PLUGIN_INSN_DETAIL_MAX_OPS);
        out->n_operands = n;
        for (uint8_t i = 0; i < n; i++) {
            const cs_riscv_op *cop = &detail->riscv.operands[i];
            qemu_plugin_operand *op = &out->operands[i];
            op->access = 0; /* RISC-V Capstone lacks access info */
            op->size = 0;
            switch (cop->type) {
            case RISCV_OP_REG:
                op->type = QEMU_PLUGIN_OP_REG;
                cap_copy_reg_name(op->reg_name,
                                  QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                                  handle, cop->reg, cap_arch);
                op->reg_id     = cop->reg;
                op->index_name[0] = '\0';
                op->index_id   = 0;
                op->imm = 0;
                break;
            case RISCV_OP_IMM:
                op->type = QEMU_PLUGIN_OP_IMM;
                op->imm = cop->imm;
                op->reg_name[0] = '\0';
                op->reg_id     = 0;
                op->index_name[0] = '\0';
                op->index_id   = 0;
                break;
            case RISCV_OP_MEM:
                op->type = QEMU_PLUGIN_OP_MEM;
                cap_copy_reg_name(op->reg_name,
                                  QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                                  handle, cop->mem.base, cap_arch);
                op->reg_id     = cop->mem.base;
                op->index_name[0] = '\0';
                op->index_id   = 0;
                op->imm = cop->mem.disp;
                break;
            default:
                op->type = QEMU_PLUGIN_OP_INVALID;
                op->reg_name[0] = '\0';
                op->reg_id     = 0;
                op->index_name[0] = '\0';
                op->index_id   = 0;
                op->imm = 0;
                break;
            }
        }
    } else if (cap_arch == CS_ARCH_MIPS) {
        n = MIN(detail->mips.op_count, QEMU_PLUGIN_INSN_DETAIL_MAX_OPS);
        out->n_operands = n;
        for (uint8_t i = 0; i < n; i++) {
            const cs_mips_op *cop = &detail->mips.operands[i];
            qemu_plugin_operand *op = &out->operands[i];
            op->access = 0; /* MIPS Capstone lacks access info */
            op->size = 0;
            switch (cop->type) {
            case MIPS_OP_REG:
                op->type = QEMU_PLUGIN_OP_REG;
                cap_copy_reg_name(op->reg_name,
                                  QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                                  handle, cop->reg, cap_arch);
                op->reg_id     = cop->reg;
                op->index_name[0] = '\0';
                op->index_id   = 0;
                op->imm = 0;
                break;
            case MIPS_OP_IMM:
                op->type = QEMU_PLUGIN_OP_IMM;
                op->imm = cop->imm;
                op->reg_name[0] = '\0';
                op->reg_id     = 0;
                op->index_name[0] = '\0';
                op->index_id   = 0;
                break;
            case MIPS_OP_MEM:
                op->type = QEMU_PLUGIN_OP_MEM;
                cap_copy_reg_name(op->reg_name,
                                  QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                                  handle, cop->mem.base, cap_arch);
                op->reg_id     = cop->mem.base;
                op->index_name[0] = '\0';
                op->index_id   = 0;
                op->imm = cop->mem.disp;
                break;
            default:
                op->type = QEMU_PLUGIN_OP_INVALID;
                op->reg_name[0] = '\0';
                op->reg_id     = 0;
                op->index_name[0] = '\0';
                op->index_id   = 0;
                op->imm = 0;
                break;
            }
        }
    } else {
        out->n_operands = 0;
    }
}

/*
 * Disassemble a single instruction with Capstone CS_OPT_DETAIL enabled
 * and fill a qemu_plugin_insn_info struct with the structured results.
 */
bool cap_disas_plugin_detail(disassemble_info *info, uint64_t pc, size_t size,
                             struct qemu_plugin_insn_info *out)
{
    uint8_t cap_buf[32];
    const uint8_t *cbuf = cap_buf;
    csh handle;
    cs_insn *insn;

    memset(out, 0, sizeof(*out));

    if (cap_disas_start(info, &handle) != CS_ERR_OK) {
        return false;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    /*
     * Allocate a fresh cs_insn AFTER enabling detail mode.
     * In Capstone 5, cs_malloc only allocates the detail sub-struct
     * when CS_OPT_DETAIL is already enabled on the handle.  The
     * module-level cap_insn was allocated without detail and has
     * detail == NULL.
     */
    insn = cs_malloc(handle);
    if (!insn) {
        cs_close(&handle);
        return false;
    }

    assert(size < sizeof(cap_buf));
    info->read_memory_func(pc, cap_buf, size, info);

    if (insn->detail) {
        memset(insn->detail, 0, sizeof(*insn->detail));
    }

    if (!cs_disasm_iter(handle, &cbuf, &size, &pc, insn)) {
        cs_free(insn, 1);
        cs_close(&handle);
        return false;
    }

    /* Copy mnemonic and operand string */
    g_strlcpy(out->mnemonic, insn->mnemonic,
              QEMU_PLUGIN_INSN_DETAIL_MNEMSZ);
    g_strlcpy(out->op_str, insn->op_str,
              QEMU_PLUGIN_INSN_DETAIL_OPSTRSZ);
    out->insn_id = insn->id;

    if (insn->detail) {
        const cs_detail *detail = insn->detail;

        /* Groups → bitmask */
        for (uint8_t i = 0; i < detail->groups_count; i++) {
            out->groups |= cap_group_to_plugin_bit(detail->groups[i]);
        }

        /* Implicit register reads */
        out->n_regs_read = MIN(detail->regs_read_count,
                               QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS);
        for (uint8_t i = 0; i < out->n_regs_read; i++) {
            cap_copy_reg_name(out->regs_read[i],
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                              handle, detail->regs_read[i],
                              info->cap_arch);
            out->regs_read_id[i] = detail->regs_read[i];
        }

        /* Implicit register writes */
        out->n_regs_write = MIN(detail->regs_write_count,
                                QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS);
        for (uint8_t i = 0; i < out->n_regs_write; i++) {
            cap_copy_reg_name(out->regs_write[i],
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                              handle, detail->regs_write[i],
                              info->cap_arch);
            out->regs_write_id[i] = detail->regs_write[i];
        }

        /* Per-operand detail — ISA-specific extraction */
        switch (info->cap_arch) {
        case CS_ARCH_X86:
            cap_fill_x86_operands(handle, insn, out);
            break;
        case CS_ARCH_ARM64:
            cap_fill_arm64_operands(handle, insn, out);
            break;
        default:
            cap_fill_generic_operands(handle, insn, out,
                                      info->cap_arch);
            break;
        }
    }

    cs_free(insn, 1);
    cs_close(&handle);
    return true;
}

/*
 * Decode raw instruction bytes with a standalone Capstone handle.
 *
 * Unlike cap_disas_plugin_detail() this does not need a disassemble_info
 * (no CPU state) — it opens its own Capstone context with the caller-
 * supplied arch/mode and decodes directly from the byte buffer.  This
 * lets plugins decode any ISA that Capstone supports, regardless of
 * whether QEMU's per-target code uses Capstone internally.
 */
bool cap_disas_raw_detail(int cap_arch, unsigned int cap_mode,
                          const uint8_t *data, size_t data_size,
                          uint64_t pc, struct qemu_plugin_insn_info *out)
{
    csh handle;
    cs_insn *insn;
    cs_err err;

    memset(out, 0, sizeof(*out));

    err = cs_open(cap_arch, cap_mode, &handle);
    if (err != CS_ERR_OK) {
        return false;
    }

    /* x86 AT&T syntax to match QEMU's default disassembly style */
    if (cap_arch == CS_ARCH_X86) {
        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    insn = cs_malloc(handle);
    if (!insn) {
        cs_close(&handle);
        return false;
    }

    const uint8_t *code = data;
    size_t sz = data_size;
    uint64_t addr = pc;

    if (insn->detail) {
        memset(insn->detail, 0, sizeof(*insn->detail));
    }

    if (!cs_disasm_iter(handle, &code, &sz, &addr, insn)) {
        cs_free(insn, 1);
        cs_close(&handle);
        return false;
    }

    /* Copy mnemonic and operand string */
    g_strlcpy(out->mnemonic, insn->mnemonic,
              QEMU_PLUGIN_INSN_DETAIL_MNEMSZ);
    g_strlcpy(out->op_str, insn->op_str,
              QEMU_PLUGIN_INSN_DETAIL_OPSTRSZ);
    out->insn_id = insn->id;

    if (insn->detail) {
        const cs_detail *detail = insn->detail;

        /* Groups → bitmask */
        for (uint8_t i = 0; i < detail->groups_count; i++) {
            out->groups |= cap_group_to_plugin_bit(detail->groups[i]);
        }

        /* Implicit register reads */
        out->n_regs_read = MIN(detail->regs_read_count,
                               QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS);
        for (uint8_t i = 0; i < out->n_regs_read; i++) {
            cap_copy_reg_name(out->regs_read[i],
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                              handle, detail->regs_read[i], cap_arch);
            out->regs_read_id[i] = detail->regs_read[i];
        }

        /* Implicit register writes */
        out->n_regs_write = MIN(detail->regs_write_count,
                                QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS);
        for (uint8_t i = 0; i < out->n_regs_write; i++) {
            cap_copy_reg_name(out->regs_write[i],
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                              handle, detail->regs_write[i], cap_arch);
            out->regs_write_id[i] = detail->regs_write[i];
        }

        /* Per-operand detail — ISA-specific extraction */
        switch (cap_arch) {
        case CS_ARCH_X86:
            cap_fill_x86_operands(handle, insn, out);
            break;
        case CS_ARCH_ARM64:
            cap_fill_arm64_operands(handle, insn, out);
            break;
        default:
            cap_fill_generic_operands(handle, insn, out, cap_arch);
            break;
        }
    }

    cs_free(insn, 1);
    cs_close(&handle);
    return true;
}
