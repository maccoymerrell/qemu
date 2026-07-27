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

/* Forward decls — definitions live just past cap_fill_x86_operands so
 * the AArch64 helper (which is what they're nearest to) lands grouped
 * with its primary consumer. */
static bool cap_decode_aarch64_vas(unsigned vas,
                                   uint8_t *lane_bytes,
                                   uint8_t *total_bytes);
static uint8_t cap_lane_bytes_from_mnemonic(const char *mnem);
static bool cap_aarch64_is_block_zero_sysop(const cs_arm64 *a64, uint8_t n);
static bool cap_x86_is_extract_store(const char *mnem);
static bool cap_x86_is_move_family(const char *mnem);
static bool cap_x86_is_test(const char *mnem);
static uint8_t cap_x86_string_mem_access(const char *mnem, unsigned base_reg);
static bool cap_x86_is_string_op(const char *mnem);
static bool cap_x86_is_scalar_round(const char *mnem);
static bool cap_x86_is_shadow_stack_store(const char *mnem);
static bool cap_x86_mem_is_never_accessed(const char *mnem);
static bool cap_x86_is_push(const char *mnem);

/*
 * Extract per-operand detail for x86 into the plugin operand struct.
 */
static void cap_fill_x86_operands(csh handle, const cs_insn *insn,
                                  qemu_plugin_insn_info *out)
{
    const cs_x86 *x86 = &insn->detail->x86;
    uint8_t n = MIN(x86->op_count, QEMU_PLUGIN_INSN_DETAIL_MAX_OPS);
    out->n_operands = n;

    /* x86 SIMD: lane width is encoded in the mnemonic suffix and
     * applies uniformly across all operands of the insn. */
    uint8_t insn_lane_bytes = cap_lane_bytes_from_mnemonic(insn->mnemonic);
    /* Capstone-6.0.0-Alpha7 bug: store-form extract (PEXTR / EXTRACTPS
     * family) reports its r/m destination READ-only.  Force WRITE on
     * the MEM operand below. */
    bool extract_store = cap_x86_is_extract_store(insn->mnemonic);
    /* Capstone-6.0.0 bug: some store-form data moves (VMOVDQA /
     * MOVUPS / VMOVUPS ...) report the MEM destination READ-only and
     * also report no register written, so the whole insn looks
     * read-only.  Operand order cannot disambiguate — QEMU runs
     * Capstone in AT&T syntax, which reverses the detail operand
     * array, so a load's MEM operand is also operand 0.  Use the
     * access pattern instead: a move-family insn that has both a MEM
     * and a register operand yet no operand carries WRITE access is
     * a store whose MEM target lost its WRITE flag (a real load
     * always has its destination register marked WRITE).  Correctly
     * reported stores (MOVAPS / MOVDQU, MEM already WRITE) and all
     * loads keep an operand with WRITE and are left untouched. */
    bool mv_fam = cap_x86_is_move_family(insn->mnemonic);
    bool mv_has_mem = false, mv_has_reg = false, mv_any_write = false;
    if (mv_fam) {
        for (uint8_t k = 0; k < n; k++) {
            const cs_x86_op *o = &x86->operands[k];
            if (o->type == X86_OP_MEM) {
                mv_has_mem = true;
            } else if (o->type == X86_OP_REG) {
                mv_has_reg = true;
            }
            if (o->access & QEMU_PLUGIN_OP_ACC_WRITE) {
                mv_any_write = true;
            }
        }
    }
    bool move_store = mv_fam && mv_has_mem && mv_has_reg
        && !mv_any_write;
    /* Capstone-6.0.0 access-flag bugs on TEST — see cap_x86_is_test.
     * TEST computes `src1 AND src2`, discards the result and writes
     * only EFLAGS: it never writes an operand.  Two distinct defects
     * violate that, in opposite directions, so force plain READ on
     * every TEST operand below.  Architecturally exact, and a no-op on
     * the encodings Capstone already reports correctly. */
    bool test_read = cap_x86_is_test(insn->mnemonic);
    /* Capstone-6.0.0-Alpha7 access-flag bugs across the string family —
     * see cap_x86_string_mem_access.  Every string op's MEM operands get
     * their architectural access forced from the (mnemonic, base
     * register) pair below. */
    bool string_op = cap_x86_is_string_op(insn->mnemonic);
    /* Capstone-6.0.0-Alpha7 bug: the MEM source of the scalar ROUNDSS /
     * ROUNDSD comes back access == 0 — see cap_x86_is_scalar_round. */
    bool scalar_round = cap_x86_is_scalar_round(insn->mnemonic);
    /* Capstone-6.0.0-Alpha7 bug: WRSS / WRUSS report both operands
     * access == 0 — see cap_x86_is_shadow_stack_store. */
    bool shstk_store = cap_x86_is_shadow_stack_store(insn->mnemonic);
    /* Capstone-6.0.0-Alpha7 bug: the multi-byte NOP's MEM operand comes
     * back READ although the insn performs no memory access at all —
     * see cap_x86_mem_is_never_accessed. */
    bool mem_unused = cap_x86_mem_is_never_accessed(insn->mnemonic);
    /* Capstone-6.0.0-Alpha7 bug: PUSH of a segment register reports its
     * operand access == 0 — see cap_x86_is_push. */
    bool push_read = cap_x86_is_push(insn->mnemonic);

    for (uint8_t i = 0; i < n; i++) {
        const cs_x86_op *cop = &x86->operands[i];
        qemu_plugin_operand *op = &out->operands[i];

        op->access = cop->access;
        if (test_read) {
            op->access = QEMU_PLUGIN_OP_ACC_READ;
        }
        op->size = cop->size;
        op->lane_bytes = insn_lane_bytes;
        op->scale = 1;
        op->shift_type = 0;
        op->shift_amount = 0;
        op->segment_id = 0;   /* MEM branch fills the override, if any */

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
            /* Capstone-6.0.0-Alpha7: register operands that lost their
             * access.  The port number of an INS / OUTS, the data source
             * of a WRSS / WRUSS and the operand of a PUSH are all pure
             * reads; saying so is architecturally exact and therefore a
             * no-op on the encodings already reported correctly. */
            if ((string_op || shstk_store || push_read) &&
                op->access == 0) {
                op->access = QEMU_PLUGIN_OP_ACC_READ;
            }
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
            op->scale = (uint8_t)cop->mem.scale;
            /*
             * Segment override (%fs: / %gs: ...).  Capstone reports it
             * only here -- it is absent from the implicit regs_read[]
             * list -- and its base is a real input to the effective
             * address, so surface it as its own operand field.  0 when
             * the access uses the default segment.
             */
            op->segment_id = cop->mem.segment;
            /* Capstone-6.0.0-Alpha7 bugs: the r/m destination of a
             * store-form extract is a write target, not a read. */
            if (extract_store || move_store) {
                op->access = QEMU_PLUGIN_OP_ACC_WRITE;
            }
            /* Capstone-6.0.0-Alpha7 bugs across the string family: STOS
             * reports its (%rdi) destination READ, the 32-bit CMPS
             * reports both operands access == 0, and INS / OUTS report
             * theirs access == 0 at every size.  The architectural
             * access follows from the mnemonic and the base register,
             * so set it for the whole family. */
            if (string_op) {
                uint8_t a = cap_x86_string_mem_access(insn->mnemonic,
                                                      cop->mem.base);
                if (a) {
                    op->access = a;
                }
            }
            /* The MEM operand of a scalar ROUNDSS / ROUNDSD is the
             * source; these never write memory. */
            if (scalar_round) {
                op->access = QEMU_PLUGIN_OP_ACC_READ;
            }
            /* WRSS / WRUSS store to the shadow stack. */
            if (shstk_store) {
                op->access = QEMU_PLUGIN_OP_ACC_WRITE;
            }
            /* The multi-byte NOP names a memory operand it never
             * touches; leaving Capstone's phantom READ in place mints a
             * load lane and an address dependency for an access that
             * can never happen. */
            if (mem_unused) {
                op->access = 0;
            }
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
 * Lane-width helpers — see qemu_plugin_operand.lane_bytes.  Tracer-
 * internal metadata derived from whatever Capstone surfaces per ISA:
 *   AArch64: per-operand vector arrangement specifier (vas) — gives
 *            both lane bytes and total operand size.
 *   x86 / MIPS MSA: mnemonic suffix (PS=4, PD=8, PH=2, single-letter
 *            integer suffix B/W/D/Q = 1/2/4/8).
 *   RISC-V V: SEW is a runtime CSR, not derivable from disassembly;
 *            stays at 0 here, runtime path handles via FID deltas.
 */
static bool cap_decode_aarch64_vas(unsigned vas,
                                   uint8_t *lane_bytes,
                                   uint8_t *total_bytes)
{
    if (vas == AARCH64LAYOUT_INVALID) return false;
    /* vas low byte encodes lane bit-width (B=8/H=16/S=32/D=64/Q=128);
     * high byte encodes lane count (0 = bare arrangement, 1 lane). */
    unsigned lane_bits = vas & 0xff;
    if (lane_bits != 8 && lane_bits != 16 &&
        lane_bits != 32 && lane_bits != 64 && lane_bits != 128) {
        return false;
    }
    unsigned count = (vas >> 8) & 0xff;
    if (count == 0) count = 1;
    unsigned lb = lane_bits / 8;
    unsigned tb = lb * count;
    if (tb > 255) return false; /* SVE matrix tile (COMPLETE). */
    *lane_bytes  = (uint8_t)lb;
    *total_bytes = (uint8_t)tb;
    return true;
}

/*
 * Capstone 6.0.0-Alpha7 x86 access-flag bug workaround.
 *
 * Store-form extract instructions write their r/m operand
 * (PEXTRD r/m32, xmm, imm8 -- Intel SDM: "store the result in
 * r/m32"), but this Capstone version reports that memory operand as
 * READ-only (CS_AC_WRITE missing).  Load-form PINSRD is reported
 * correctly, so the defect is specific to the extract-to-memory
 * family: PEXTR{B,W,D,Q}, EXTRACTPS, and the VEX/EVEX VPEXTR* /
 * VEXTRACTPS forms.  Without correction the operand walker treats
 * the store destination as a phantom load and never emits the
 * store-data dependency on the source vector register.
 *
 * Detect by mnemonic and, for the MEM operand, force WRITE access.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify
 * with `cstool -d x64 660f3a160001` (bytes `66 0f 3a 16 00 01`,
 * `pextrd $1,%xmm0,(%rax)`) -- the MEM operand must show WRITE.  Note
 * `cstool` here means one built from `subprojects/capstone`: a system
 * package `cstool` is routinely a different Capstone major version
 * (this host's is v5.0.1, which cannot reproduce Alpha7-specific
 * defects at all) and gives no evidence either way.  Simplest is
 * `contrib/plugins/champsim_tracer/tools/capstone_workaround_probe`,
 * which links the pinned copy and checks this exact case
 * (`cap_x86_is_extract_store`) automatically -- see
 * docs/troubleshooting.rst ("Retiring a Capstone workaround").
 */
static bool cap_x86_is_extract_store(const char *mnem)
{
    if (!mnem || !mnem[0]) return false;
    if (mnem[0] == 'v') mnem++;            /* VEX/EVEX prefix */
    return g_str_has_prefix(mnem, "pextr") ||
           g_str_equal(mnem, "extractps");
}

/*
 * Capstone 6.0.0-Alpha7 x86 access-flag bugs on TEST.
 *
 * TEST (`test r/m, r` / `test r/m, imm`) ANDs its two operands, throws
 * the result away and writes EFLAGS only -- it never writes an operand.
 * This Capstone version breaks that in two ways:
 *
 *   1. LOST READ.  Some register-source encodings report EVERY operand
 *      with empty access, so a MEM operand's READ is lost and the insn
 *      mints no load slot (the offline lint then flags the observed
 *      load as impossible).
 *
 *   2. PHANTOM WRITE.  Opcode A9 (`test eAX, imm32`) AT 32-BIT OPERAND
 *      SIZE ONLY reports its accumulator operand CS_AC_READ|CS_AC_WRITE
 *      and additionally lists eax in regs_access()'s write set:
 *
 *        a9 00 00 20 00     testl $0x200000,%eax   op1 eax access=RW  <-- WRONG
 *        a8 01              testb $1,%al           op1 al   access=READ
 *        66 a9 00 20        testw $0x2000,%ax      op1 ax   access=READ
 *        48 a9 00 00 20 00  testq $0x200000,%rax   op1 rax  access=READ
 *        f7 c0 ...          testl $0x200000,%eax   op1 eax  access=READ
 *        85 c0 / 84 c0      test %eax,%eax         both     access=READ
 *
 *      The 8-bit (A8), 16-bit (66 A9), 64-bit (REX.W A9) and every
 *      ModRM form (F6/F7 /0, 84, 85) are correct; only A9-32 is
 *      mis-flagged.  Left uncorrected it mints a phantom destination
 *      register on one of the hottest insns in an interpreter loop --
 *      false WAW/RAW edges and a wasted ChampSim destination slot
 *      (34,096 insns, 0.68% of the cross-validated perlbench span;
 *      PIN/XED reports dst={flags}, this reports dst={flags,rax}).
 *
 * Both are corrected the same way and at the same boundary as the
 * PEXTR and store-move access-flag defects: identify the family by
 * mnemonic and force plain CS_AC_READ on every operand, which is what
 * the architecture says and therefore cannot disturb the encodings
 * Capstone already reports correctly.  Revisit / remove when Capstone
 * is bumped past 6.0.0-Alpha7.
 */
static bool cap_x86_is_test(const char *mnem)
{
    /* AT&T syntax (QEMU's) size-suffixes the mnemonic: testb/testw/
     * testl/testq.  Prefix-match — no other x86 mnemonic starts with
     * "test" (ktest/vptest begin with k/v). */
    return mnem && g_str_has_prefix(mnem, "test");
}

/*
 * Capstone 6.0.0-Alpha7 x86 access-flag bugs across the string family.
 *
 * The seven string instructions address memory only through (%rSI) and
 * (%rDI), and which of the two they read and write is fixed by the
 * architecture:
 *
 *   insn    (%rSI)   (%rDI)    what it does
 *   ------  -------  -------   -----------------------------------------
 *   MOVS    READ     WRITE     ES:[rDI] <- DS:[rSI]
 *   CMPS    READ     READ      compare DS:[rSI] with ES:[rDI], flags only
 *   SCAS    --       READ      compare AL/AX/EAX/RAX with ES:[rDI]
 *   LODS    READ     --        AL/AX/EAX/RAX <- DS:[rSI]
 *   STOS    --       WRITE     ES:[rDI] <- AL/AX/EAX/RAX
 *   INS     --       WRITE     ES:[rDI] <- port DX
 *   OUTS    READ     --        port DX <- DS:[rSI]
 *
 * (Intel SDM Vol. 2, the individual instruction pages.)  This Capstone
 * version breaks that in three separate ways:
 *
 *   1. INVERTED.  STOS reports its (%rdi) destination CS_AC_READ, at
 *      every operand size and with or without a REP prefix:
 *
 *        f3 48 ab     rep stosq %rax,(%rdi)   op0 MEM base=rdi READ  <-- WRONG
 *        48 ab        stosq %rax,(%rdi)       op0 MEM base=rdi READ  <-- WRONG
 *        aa/ab/66 ab  stosb/stosl/stosw       op0 MEM base=rdi READ  <-- WRONG
 *
 *   2. LOST, OPERAND-SIZE-SPECIFIC.  CMPS at 32-bit operand size --
 *      opcode A7 with neither the 66 prefix nor REX.W -- reports BOTH
 *      MEM operands access == 0.  Every other CMPS size is correct:
 *
 *        a7           cmpsl (%rdi),(%rsi)     op0/op1 access=0       <-- WRONG
 *        f3 a7        repz cmpsl              op0/op1 access=0       <-- WRONG
 *        f2 a7        repnz cmpsl             op0/op1 access=0       <-- WRONG
 *        a6           cmpsb                   op0/op1 access=READ
 *        66 a7        cmpsw                   op0/op1 access=READ
 *        48 a7        cmpsq                   op0/op1 access=READ
 *
 *      This is the same shape of defect as the TEST A9-32 one above:
 *      one operand size of one opcode, everything around it correct.
 *
 *   3. LOST, EVERY SIZE.  INS and OUTS report their MEM operand
 *      access == 0 at every operand size, and the 32-bit forms
 *      additionally drop the READ on the %dx port operand:
 *
 *        6c / 66 6d   insb / insw    op1 MEM access=0                <-- WRONG
 *        6d           insl           op0 REG(dx)=0, op1 MEM=0        <-- WRONG
 *        6e / 66 6f   outsb / outsw  op0 MEM access=0                <-- WRONG
 *        6f           outsl          op0 MEM=0, op1 REG(dx)=0        <-- WRONG
 *
 * Consequences, in increasing order of damage.  An inverted flag (1)
 * makes the operand walker mint a load slot instead of a store slot, so
 * the dependency model attributes a memset's traffic to the LOAD lane.
 * A lost flag on one MEM operand of a multi-operand insn (3) makes that
 * operand contribute no lane at all, because the walker treats a zero
 * access as "no information" and another operand still carries one.
 * Worst is (2): a REP-prefixed string op derives its per-iteration
 * memop count from exactly these flags (rep_loads_per_iter /
 * rep_stores_per_iter in the consuming tracer), so losing them makes
 * that count zero, and a zero count disables the per-iteration fan-out
 * entirely -- a `rep cmpsl` over N dwords collapses from N body entries
 * of two loads each into a single entry carrying all 2N memops, none of
 * which the template says the instruction can perform.
 *
 * In every case the emitted memop records themselves are correct: they
 * come from QEMU's memory callbacks, not from Capstone, which is why
 * PIN and this tracer already agree 100% on string-op memop counts and
 * addresses.  Only the operand / lane / fan-out model was wrong.
 *
 * All three are corrected the same way and at the same boundary as the
 * PEXTR, store-move and TEST defects: identify the family by mnemonic
 * and set the access the architecture specifies, which cannot disturb
 * the encodings Capstone already reports correctly.  Returns 0 when
 * @mnem is not a string op or @base_reg is not one of the two string
 * pointers, in which case the caller leaves the operand alone.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify
 * with `cstool -d x64 a7` (both MEM operands must show READ) and
 * `cstool -d x64 6c` (the MEM operand must show WRITE).
 */

/* Step over the repeat prefix Capstone folds INTO the mnemonic string
 * ("rep stosq", "repne scasb") rather than leaving to prefix[] alone. */
static const char *cap_x86_skip_rep(const char *mnem)
{
    const char *sp = strchr(mnem, ' ');
    if (sp && (g_str_has_prefix(mnem, "rep ") ||
               g_str_has_prefix(mnem, "repe ") ||
               g_str_has_prefix(mnem, "repz ") ||
               g_str_has_prefix(mnem, "repne ") ||
               g_str_has_prefix(mnem, "repnz "))) {
        return sp + 1;
    }
    return mnem;
}

/*
 * Match a string-op mnemonic EXACTLY: one of the seven bases followed by
 * exactly one AT&T size suffix.  Prefix matching is NOT safe here --
 * several SSE mnemonics share these prefixes and take ordinary memory
 * operands whose base register may perfectly well be %rsi or %rdi:
 *
 *   movss / movsd    scalar FP moves      ("movs" + s/d)
 *   cmpss / cmpsd    scalar FP compares   ("cmps" + s/d)
 *   movsx / movsxd   sign-extending moves
 *   insertps         ("ins" + ...)
 *
 * Treating `movsd (%rdi), %xmm0` -- a load, and %rdi is the first
 * argument register -- as a string op would give its memory operand the
 * (%rDI) direction and so turn a load into a store.  The string size
 * suffixes (b/w/l/q) are disjoint from the scalar-FP ones (s/d), and the
 * 32-bit string compare is spelled `cmpsl` in AT&T and never `cmpsd`, so
 * an exact base+suffix match separates the two families cleanly.
 */
static bool cap_x86_is_string_op(const char *mnem)
{
    static const char *const bases[] = {
        "movs", "cmps", "scas", "lods", "stos", "ins", "outs",
    };
    if (!mnem) {
        return false;
    }
    mnem = cap_x86_skip_rep(mnem);
    size_t len = strlen(mnem);
    for (size_t i = 0; i < ARRAY_SIZE(bases); i++) {
        size_t bl = strlen(bases[i]);
        if (len != bl + 1 || memcmp(mnem, bases[i], bl) != 0) {
            continue;
        }
        switch (mnem[bl]) {
        case 'b': case 'w': case 'l': case 'q':
            return true;
        default:
            return false;
        }
    }
    return false;
}

static uint8_t cap_x86_string_mem_access(const char *mnem, unsigned base_reg)
{
    if (!mnem) {
        return 0;
    }
    mnem = cap_x86_skip_rep(mnem);

    /* The address-size prefix picks rSI/eSI/SI and rDI/eDI/DI. */
    bool via_si = (base_reg == X86_REG_RSI || base_reg == X86_REG_ESI ||
                   base_reg == X86_REG_SI);
    bool via_di = (base_reg == X86_REG_RDI || base_reg == X86_REG_EDI ||
                   base_reg == X86_REG_DI);
    if (!via_si && !via_di) {
        return 0;
    }

    /* (%rSI) is the source of every string op that names it. */
    if (via_si) {
        return QEMU_PLUGIN_OP_ACC_READ;
    }
    /* (%rDI) is compared by CMPS and SCAS, written by everything else
     * that names it (MOVS, STOS, INS). */
    if (g_str_has_prefix(mnem, "cmps") || g_str_has_prefix(mnem, "scas")) {
        return QEMU_PLUGIN_OP_ACC_READ;
    }
    return QEMU_PLUGIN_OP_ACC_WRITE;
}

/*
 * Capstone 6.0.0-Alpha7 x86 access-flag bug workaround: scalar ROUND.
 *
 * ROUNDSS / ROUNDSD round one scalar element of their source into the
 * low element of their destination, leaving the destination's upper
 * bits intact.  Their memory form reads 4 or 8 bytes.  This Capstone
 * version reports that MEM source access == 0, while the packed forms
 * of the very same instruction group are correct:
 *
 *   66 0f 3a 0a  roundss $imm,(%rip),%xmm1   op1 MEM access=0   <-- WRONG
 *   66 0f 3a 0b  roundsd $imm,(%rip),%xmm1   op1 MEM access=0   <-- WRONG
 *   c4 e3 .. 0a  vroundss $imm,(%rip),..     op1 MEM access=0   <-- WRONG
 *   c4 e3 .. 0b  vroundsd $imm,(%rip),..     op1 MEM access=0   <-- WRONG
 *   66 0f 3a 08  roundps $imm,(%rip),%xmm1   op1 MEM access=READ
 *   66 0f 3a 09  roundpd $imm,(%rip),%xmm1   op1 MEM access=READ
 *
 * The register form is also correct (op1 REG access=READ), so the
 * defect is specific to the scalar memory form.  Because the
 * destination operand does carry an access, the walker sees "access
 * info present" and simply drops the source: a real load gets no load
 * lane, no address dependency, and any memop observed on it is an
 * impossible attribution.  The register-form neighbours (ADDSS, CMPSS,
 * DPPS, INSERTPS, BLENDVPS, PCMPISTRI) are all reported correctly.
 *
 * These instructions never write memory -- their destination is always
 * an XMM register -- so forcing READ on the MEM operand is exact.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify
 * with `cstool -d x64 660f3a0a0d0000000000` (the MEM operand must show
 * READ).
 */
static bool cap_x86_is_scalar_round(const char *mnem)
{
    if (!mnem || !mnem[0]) {
        return false;
    }
    if (mnem[0] == 'v') {
        mnem++;                        /* VEX/EVEX prefix */
    }
    return g_str_equal(mnem, "roundss") || g_str_equal(mnem, "roundsd");
}

/*
 * Capstone 6.0.0-Alpha7 x86 access-flag bug workaround: WRSS / WRUSS.
 *
 * The CET shadow-stack writes store their register source to the
 * shadow stack at the memory operand's effective address.  This
 * Capstone version reports BOTH operands access == 0:
 *
 *   0f 38 f6     wrssd %ecx,(%rip)    op0 REG=0, op1 MEM=0       <-- WRONG
 *   48 0f 38 f6  wrssq %rcx,(%rip)    op0 REG=0, op1 MEM=0       <-- WRONG
 *   66 0f 38 f5  wrussd %ecx,(%rip)   op0 REG=0, op1 MEM=0       <-- WRONG
 *
 * With no operand carrying an access at all the walker falls back to
 * its opcode-indexed heuristic, and a genuine store is modelled with
 * no store lane.  The register operand is the data source and the MEM
 * operand is the store target, unconditionally, so setting them is
 * exact.  Rare in practice -- only CET-enabled binaries on a
 * shadow-stack-enabled kernel reach these -- but a dropped store is a
 * dropped store.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify
 * with `cstool -d x64 0f38f60d00000000` (REG must show READ, MEM
 * WRITE).
 */
static bool cap_x86_is_shadow_stack_store(const char *mnem)
{
    return mnem && (g_str_has_prefix(mnem, "wrss") ||
                    g_str_has_prefix(mnem, "wruss"));
}

/*
 * Capstone 6.0.0-Alpha7 x86 access-flag bug workaround: multi-byte NOP.
 *
 * The 0F 1F multi-byte NOP takes a ModRM and therefore names a memory
 * operand, but it performs no memory access whatsoever -- Intel SDM
 * Vol. 2B, NOP: "This instruction does not affect the ... memory".
 * The recommended alignment padding a compiler emits is exactly this
 * form.  This Capstone version reports the operand CS_AC_READ at the
 * sizes that matter, and access == 0 (correct) only for the REX.W one:
 *
 *   66 0f 1f 44 00 00  nopw 0(%rax,%rax,1)   op0 MEM access=READ  <-- WRONG
 *   0f 1f 40 00        nopl 0(%rax)          op0 MEM access=READ  <-- WRONG
 *   48 0f 1f 0d ..     nopq (%rip)           op0 MEM access=0
 *
 * This is the opposite direction to the defects above -- a phantom
 * access rather than a lost one -- so it does not lose data, but it
 * mints a load lane and an address dependency on the base and index
 * registers for a load that can never occur, on one of the most
 * frequent instructions in any optimised binary.
 *
 * Forcing access == 0 on the operand matches the architecture and
 * leaves the instruction with no memory lane, which is what the
 * REX.W-prefixed sibling already produces.
 *
 * Note this is deliberately NOT applied to the cache-hint instructions
 * (PREFETCH*, CLFLUSH, CLWB, CLDEMOTE), whose MEM operand Capstone also
 * reports READ: those DO name a real address that a memory-system
 * consumer wants, and the tracer routes them through its synthetic-EA
 * path precisely because their TCG translation emits no memop.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify
 * with `cstool -d x64 660f1f440000` (the MEM operand must show no
 * access).
 */
static bool cap_x86_mem_is_never_accessed(const char *mnem)
{
    /* AT&T size-suffixes it: nop / nopw / nopl / nopq.  No other x86
     * mnemonic starts with "nop". */
    return mnem && g_str_has_prefix(mnem, "nop");
}

/*
 * Capstone 6.0.0-Alpha7 x86 access-flag bug workaround: PUSH %seg.
 *
 * PUSH reads its operand and writes it to the stack.  This Capstone
 * version reports the segment-register forms with access == 0, while
 * the general-register form and every POP are correct:
 *
 *   0f a0  pushq %fs   op0 REG(fs) access=0     <-- WRONG
 *   0f a8  pushq %gs   op0 REG(gs) access=0     <-- WRONG
 *   50     pushq %rax  op0 REG(rax) access=READ
 *   0f a1  popq %fs    op0 REG(fs) access=WRITE
 *
 * The segment register is genuinely a source of the instruction (it is
 * the value pushed), so without the correction it is dropped from the
 * dependency model.  A PUSH operand is a read in every encoding, so
 * setting READ where Capstone reported nothing is exact.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify
 * with `cstool -d x64 0fa0` (the operand must show READ).
 */
static bool cap_x86_is_push(const char *mnem)
{
    /* AT&T size-suffixes it: pushw / pushq.  POP is a separate
     * mnemonic and is reported correctly. */
    return mnem && g_str_has_prefix(mnem, "push");
}

/*
 * Sweep note -- x86-64 encodings whose REG/MEM operands Capstone
 * 6.0.0-Alpha7 reports access == 0 and which are deliberately NOT
 * corrected here, because 0 is either right or unknowable:
 *
 *   CLDEMOTE     a cache hint that reads and writes no data; the
 *                tracer classifies it with the other hint opcodes and
 *                takes its address from the synthetic-EA path.
 *   BSWAPW       66-prefixed BSWAP is an undefined encoding (Intel
 *                SDM: "the result is undefined"); no compiler emits
 *                it and there is no architectural access to state.
 *   FFREEP       an undocumented x87 opcode (DF C0+i) with no
 *                architectural definition of its operand access; it
 *                touches no memory, so nothing is lost.
 *
 * The IMM operands of many instructions also report access == 0; that
 * is correct and universal -- an immediate is not a state access -- and
 * the operand walker never derives a lane from an IMM.
 */

/*
 * Capstone 6.0.0 x86 store-move access-flag bug workaround.
 *
 * The pure data-move family (MOV{APS,UPS,APD,UPD,DQA,DQU},
 * MOVNT{PS,PD,DQ}, MOVSS/MOVSD, MOVLPS/HPS/LPD/HPD and their VEX
 * forms) can be either a load ("mov xmm, [mem]") or a store
 * ("mov [mem], xmm").  This Capstone version is inconsistent on the
 * store form: VMOVDQA / MOVUPS / VMOVUPS report the MEM destination
 * READ-only (and no register written) while MOVAPS / MOVDQU report
 * it WRITE.  This predicate only identifies family membership; the
 * load/store disambiguation is done by the caller from the operand
 * access pattern (operand order is unusable — QEMU drives Capstone
 * in AT&T syntax, which reverses the detail operand array).  Without
 * the correction the operand walker models a vector store as a
 * phantom load (laddr/ld block instead of sdata/saddr) — the
 * dropped-store / wrong-latency footgun.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0; verify with
 * `cstool -d x64 c5fd7f00` (bytes `c5 fd 7f 00`, `vmovdqa
 * %ymm0,(%rax)`) -- no operand should be left without WRITE once
 * fixed.  As with the other x86 workarounds in this file, use a
 * `cstool` built from `subprojects/capstone` (capstone.wrap's pinned
 * revision), not a system package, or run
 * `capstone_workaround_probe` (`cap_x86_is_move_family` case); see
 * docs/troubleshooting.rst.
 */
static bool cap_x86_is_move_family(const char *mnem)
{
    if (!mnem || !mnem[0]) return false;
    if (mnem[0] == 'v') mnem++;            /* VEX/EVEX prefix */
    if (!g_str_has_prefix(mnem, "mov")) return false;
    /* Sign/zero-extending moves never take a MEM operand 0 (their
     * destination is a register); excluding them keeps the rule
     * "MEM op0 of a move ⇒ store target" exact.
     *
     * QEMU drives Capstone in AT&T syntax, which does NOT print these
     * as movsx / movzx / movsxd -- it spells them with a source and a
     * destination size suffix: movsbl / movsbw / movsbq / movswl /
     * movswq / movslq, and movzbl / movzbw / movzbq / movzwl / movzwq.
     * Match that shape ("mov" + s|z + b|w|l + w|l|q) rather than the
     * Intel names, which never appear and so never excluded anything.
     * (Today this exclusion is belt-and-braces -- the caller's
     * "no operand carries WRITE" test already rejects an extending
     * move, whose destination register is written -- but the predicate
     * should mean what it says.) */
    if ((mnem[3] == 's' || mnem[3] == 'z') &&
        (mnem[4] == 'b' || mnem[4] == 'w' || mnem[4] == 'l') &&
        (mnem[5] == 'w' || mnem[5] == 'l' || mnem[5] == 'q') &&
        mnem[6] == '\0') {
        return false;
    }
    return !g_str_has_prefix(mnem, "movsx") &&
           !g_str_has_prefix(mnem, "movzx") &&
           !g_str_has_prefix(mnem, "movbe") &&
           !g_str_has_prefix(mnem, "movmsk");
}

static uint8_t cap_lane_bytes_from_mnemonic(const char *mnem)
{
    if (!mnem || !mnem[0]) return 0;
    size_t n = strlen(mnem);
    if (n < 3) return 0;
    /* Scalar-FP forms (…ss / …sd, e.g. ADDSS, VFMADD132SD): only the
     * low element is computed, the rest of the register passes
     * through.  These are not lane-parallel SIMD ops — report no
     * lane width so the tracer treats them as scalar (consistent with
     * the non-VEX ADDSS/ADDSD path, which also returns 0 here).  Must
     * precede the generic single-letter suffix check below, otherwise
     * the trailing 'd' of "sd" on a v-prefixed mnemonic is mistaken
     * for the 4-byte integer-dword suffix. */
    if (mnem[n - 2] == 's' && (mnem[n - 1] == 's' || mnem[n - 1] == 'd')) {
        return 0;
    }
    if (mnem[n - 2] == 'p') {
        char c = mnem[n - 1];
        if (c == 's') return 4;
        if (c == 'd') return 8;
        if (c == 'h') return 2;
    }
    if (n >= 4) {
        char prev = mnem[n - 2];
        char c    = mnem[n - 1];
        bool dot_form    = (prev == '.');
        bool simd_prefix = (mnem[0] == 'v' || (mnem[0] == 'p' && n >= 5));
        if (dot_form) {
            /* MIPS MSA element suffix: B/H/W/D = byte/half/word/
             * double = 1/2/4/8 bytes (W is a 32-bit word here, not
             * the x86 16-bit "word").  The dot-form is MSA-exclusive
             * — x86 never uses a '.'-separated element suffix. */
            switch (c) {
            case 'b': return 1;
            case 'h': return 2;
            case 'w': return 4;
            case 'd': return 8;
            }
        } else if (simd_prefix) {
            /* x86 integer-suffix convention: B/W/D/Q = byte/word/
             * dword/qword = 1/2/4/8 bytes (PEXTRW etc.). */
            switch (c) {
            case 'b': return 1;
            case 'w': return 2;
            case 'd': return 4;
            case 'q': return 8;
            }
        }
    }
    return 0;
}

/*
 * AArch64 DC ZVA / DC GZVA: Capstone models no memory operand.
 *
 * `DC ZVA, Xt` zeroes a whole naturally-aligned block of memory whose
 * size comes from DCZID_EL0.BS and whose address is Xt (rounded down to
 * the block).  Architecturally it is a block store, and Linux's
 * clear_page() is built on it, so it carries a large share of a
 * system-mode trace's store traffic.
 *
 * Capstone decodes the whole SYS alias space -- DC, IC, AT, TLBI -- with
 * insn->id == AARCH64_INS_SYS, printing the alias as the mnemonic
 * ("dc") with the operation in op_str ("zva, x0").  The structured
 * detail identifies the operation exactly:
 *
 *   operands[0].type            == AARCH64_OP_SYSALIAS
 *   operands[0].sysop.sub_type  == AARCH64_OP_DC
 *   operands[0].sysop.alias.dc  == AARCH64_DC_ZVA   (0x1ba1)
 *   operands[1]                 == AARCH64_OP_REG, Xt, access READ
 *
 * (IC / TLBI use AARCH64_OP_SYSREG and sysop.reg instead; a SYS
 * encoding Capstone does not recognise as an alias keeps mnemonic
 * "sys" and sets no sysop at all.)  So the operation is unambiguous --
 * but there is no AARCH64_OP_MEM operand anywhere in it, and Xt is
 * described as a plain register read rather than as an address.
 *
 * That is not an access-flag bug like the ones above; it is a modelling
 * gap.  Its effect is the same, though: with no memory operand the
 * consumer mints no store lane, and every store the instruction
 * performs is an attribution to an instruction that -- as far as the
 * decoded operands go -- cannot perform one.
 *
 * The correction is to present Xt as what it is: the base register of a
 * written memory operand.  The block size is deliberately NOT encoded
 * here -- it is a runtime CPU property (DCZID_EL0), not a property of
 * the encoding, and disas/ is target-independent code.  The emitted
 * memop records carry the true addresses and sizes; they come from
 * HELPER(dc_zva) via arm_plugin_bulk_mem_cb(), which reads the block
 * size from the CPU.
 *
 * DC GZVA (the MTE tag-and-data zeroing form) writes the same block and
 * is treated identically.  Every other DC operation (CVAC, CVAU, CIVAC,
 * IVAC ...) is cache maintenance that moves no architectural data, and
 * IC / AT / TLBI touch no data at all, so none of them gets a memory
 * operand.
 *
 * Revisit when Capstone grows a memory operand for DC ZVA; verify with
 * `cstool -d arm64 200774d5` (dc zva, x0), whose operands should then
 * include a MEM form.
 */
static bool cap_aarch64_is_block_zero_sysop(const cs_arm64 *a64, uint8_t n)
{
    if (n < 2) {
        return false;
    }
    const cs_arm64_op *o = &a64->operands[0];
    if (o->type != AARCH64_OP_SYSALIAS ||
        o->sysop.sub_type != AARCH64_OP_DC) {
        return false;
    }
    return o->sysop.alias.dc == AARCH64_DC_ZVA ||
           o->sysop.alias.dc == AARCH64_DC_GZVA;
}

/*
 * AArch64 MRS / MSR: the system register the instruction exists to move.
 *
 * `mrs x3, nzcv` reads PSTATE.NZCV into x3 and `msr nzcv, x3` writes it
 * back, and the conditional branch that follows reads NZCV again.  Both
 * halves of that chain live in the system-register field, and Capstone
 * models it with an operand type of its own:
 *
 *   operands[k].type           == AARCH64_OP_SYSREG
 *   operands[k].sysop.sub_type == AARCH64_OP_REG_MRS   (a read)
 *                              or AARCH64_OP_REG_MSR   (a write)
 *   operands[k].sysop.reg.sysreg == AARCH64_SYSREG_NZCV (0xda10)
 *
 * Presented as an unmodelled operand, an MRS reads nothing and an MSR
 * writes nothing, so the branch after `msr nzcv, x3` reads a register no
 * instruction in the trace produced -- the same severance MIPS suffered
 * on its FP condition codes, on the ISA where it costs the most (18.7 M
 * dynamic MRS/MSR executions in the survey population).
 *
 * Two things make this a translation rather than a fix.  Capstone leaves
 * the operand's access bits empty, so the direction is taken from
 * sub_type, which states it exactly.  And the system-register numbering
 * is disjoint from aarch64_reg -- AARCH64_SYSREG_NZCV is 0xda10 while
 * AARCH64_REG_NZCV is 5 -- so the value cannot be handed over as a
 * register id.  It goes out as QEMU_PLUGIN_OP_SYSREG, whose reg_id is
 * documented to carry the raw encoding, leaving the ISA-specific
 * encoding->register mapping to the consumer.
 *
 * IC / TLBI reuse AARCH64_OP_SYSREG with a TLBI or IC sub_type for a
 * maintenance operation rather than a register, and are left alone.
 */
static bool cap_aarch64_sysreg_operand(const cs_arm64_op *o, uint8_t *access)
{
    if (o->type != AARCH64_OP_SYSREG &&
        o->type != AARCH64_OP_REG_MRS &&
        o->type != AARCH64_OP_REG_MSR) {
        return false;
    }
    switch (o->sysop.sub_type) {
    case AARCH64_OP_REG_MRS:
        *access = QEMU_PLUGIN_OP_ACC_READ;
        return true;
    case AARCH64_OP_REG_MSR:
        *access = QEMU_PLUGIN_OP_ACC_WRITE;
        return true;
    default:
        /* TLBI / IC / an operand Capstone left unclassified. */
        return false;
    }
}

/*
 * Recover the printed system-register name from the instruction text.
 * Capstone exposes no name lookup for aarch64_sysreg, but it prints the
 * register in op_str -- "x3, NZCV" for MRS, "NZCV, x3" for MSR -- so the
 * name is the operand on the side sub_type already identified.
 * Lower-cased to match every other register name crossing this boundary,
 * and truncated to the field width like any other (the ABI's authority
 * on WHICH register this is, is reg_id).
 */
static void cap_aarch64_copy_sysreg_name(char *dst, size_t dstsz,
                                         const char *op_str, bool is_read)
{
    const char *start = op_str;
    const char *end;
    size_t n;

    dst[0] = '\0';
    if (!op_str || !op_str[0]) {
        return;
    }
    if (is_read) {
        /* MRS: "<Xt>, <sysreg>" -- the text after the last comma. */
        const char *comma = strrchr(op_str, ',');
        if (!comma) {
            return;
        }
        start = comma + 1;
        while (*start == ' ') {
            start++;
        }
        end = start + strlen(start);
    } else {
        /* MSR: "<sysreg>, <Xt>" -- the text before the first comma. */
        end = strchr(op_str, ',');
        if (!end) {
            return;
        }
    }
    n = (size_t)(end - start);
    if (n == 0) {
        return;
    }
    if (n >= dstsz) {
        n = dstsz - 1;
    }
    for (size_t i = 0; i < n; i++) {
        dst[i] = (char)g_ascii_tolower(start[i]);
    }
    dst[n] = '\0';
}

static bool cap_aarch64_is_cas(const char *mnem)
{
    return g_str_has_prefix(mnem, "cas")
        || g_str_has_prefix(mnem, "rcwcas")
        || g_str_has_prefix(mnem, "rcwscas");
}

static bool cap_aarch64_is_single_cas(const char *mnem)
{
    if (!g_str_has_prefix(mnem, "cas")) {
        return false;
    }
    /* casp / caspa / caspl / caspal are the pair forms.  Their result
     * registers are already reported READ|WRITE; only the phantom base
     * write applies to them. */
    return mnem[3] != 'p';
}

/*
 * Capstone 6.0.0-Alpha7 bug: FEAT_MOPS memset (SETP / SETM / SETE and
 * the tag-setting SETG*, unprivileged *T, non-temporal *N and *TN
 * variants) reports its memory operand as READ|WRITE.  A memset only
 * writes; LLVM agrees (mayStore without mayLoad).  Uncorrected the
 * operand walker mints a load lane on a memset — a phantom load, with a
 * phantom address dependency and a phantom cache access, on the
 * instruction sequence newer glibc uses for memset() whenever
 * HWCAP2_MOPS is present.
 *
 * The scoping is exact: the memcpy forms (CPYP / CPYM / CPYE and their
 * variants) genuinely both load and store, and both decoders agree on
 * them.  Only the *set* forms are wrong.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify
 * with `cstool -d arm64 2004c219` (bytes `20 04 c2 19`,
 * `setp [x0]!, x1!, x2`) -- fixed, the MEM operand must show WRITE
 * without READ.  Use a `cstool` built from `subprojects/capstone`, not a
 * system package, or run `capstone_workaround_probe`; see
 * docs/troubleshooting.rst.
 */
static bool cap_aarch64_is_mops_set(const char *mnem)
{
    /* SETF8 / SETF16 (FEAT_FlagM2) also start with "set" but have no
     * memory operand, so they never reach the correction; excluded
     * explicitly so the intent is legible. */
    return g_str_has_prefix(mnem, "set") && !g_str_has_prefix(mnem, "setf");
}

/*
 * FEAT_MOPS prologue: the half of the P -> M -> E chain Capstone drops.
 *
 * A bulk copy or set is three instructions that hand state to each other
 * through PSTATE.NZCV — the prologue records how much of the operation
 * it performed and which direction it chose, and the main and epilogue
 * forms resume from that.  Capstone reports the prologue's NZCV WRITE
 * and the main/epilogue forms' NZCV READ, but not the prologue's own
 * read: the MRA's SETP and CPYP pseudocode consults PSTATE.NZCV to tell
 * a fresh start from a re-entry after an interrupt, so the P form reads
 * the register it then rewrites.
 *
 * Without it the prologue looks like a pure producer, and a re-executed
 * P form — which is exactly what happens when the operation is
 * interrupted and restarted — appears independent of the state that
 * says how far it already got.  glibc's memcpy() and memset() use these
 * whenever HWCAP2_MOPS is present, so this is 3.2 M executions in the
 * survey population, not a corner.
 *
 * The prologue mnemonics are CPYP / CPYFP / SETP / SETGP and their
 * suffixed variants (…wn, …rn, …n, …t, …tn).  SETF8 / SETF16 share the
 * "set" stem but are FEAT_FlagM2 flag-setters with no MOPS chain, and
 * are excluded by requiring the "p" that names the prologue.
 */
static bool cap_aarch64_is_mops_prologue(const char *mnem)
{
    return g_str_has_prefix(mnem, "cpyp") ||
           g_str_has_prefix(mnem, "cpyfp") ||
           g_str_has_prefix(mnem, "setp") ||
           g_str_has_prefix(mnem, "setgp");
}

/*
 * FP forms whose FPCR read Capstone reports on their siblings and not
 * on them.
 *
 * The implicit-register table is inconsistent here rather than
 * deliberately silent: FCMP and FCMPE carry `fpcr`, FCCMP and FCCMPE
 * — the same comparison under a condition — carry none; SQDMULH
 * carries it, SQADD and UQADD do not.  The MRA has all of them reading
 * FPCR, and for the one-source sign forms it is not incidental:
 * FEAT_AFP's FPCR.AH changes what FABS and FNEG do to a NaN, and
 * FPCR.NEP changes whether they merge from Vd.
 *
 * Over-reporting an FPCR read is the safe direction.  FPCR is written
 * once at process start and then read by everything, so a spurious read
 * adds an edge onto a producer that retired long ago; a spurious FPSR
 * *write* would instead chain every FP instruction to the last one,
 * which is why the cumulative-status half of this stays unmodelled.
 */
static bool cap_aarch64_reads_fpcr_unreported(const char *mnem)
{
    /* Conditional FP compares — siblings FCMP/FCMPE report FPCR. */
    if (g_str_has_prefix(mnem, "fccmp")) {
        return true;
    }
    /* One-source sign manipulation — FPCR.AH / FPCR.NEP dependent. */
    if (g_str_has_prefix(mnem, "fabs") || g_str_has_prefix(mnem, "fneg")) {
        return true;
    }
    /* SVE strictly-ordered FP reduction. */
    if (g_str_has_prefix(mnem, "fadda")) {
        return true;
    }
    /* Saturating integer arithmetic — sibling SQDMULH reports FPCR.
     * The whole family writes FPSR.QC and takes its saturation
     * behaviour from FPCR, and Capstone reports it on only part of it. */
    if ((mnem[0] == 's' || mnem[0] == 'u') && mnem[1] == 'q') {
        return true;
    }
    return false;
}

/* Append @reg to the implicit-read list unless it is already there. */
static void cap_aarch64_add_implicit_read(qemu_plugin_insn_info *out,
                                          csh handle, unsigned int reg)
{
    for (uint8_t i = 0; i < out->n_regs_read; i++) {
        if (out->regs_read_id[i] == reg) {
            return;
        }
    }
    if (out->n_regs_read >= QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS) {
        return;
    }
    cap_copy_reg_name(out->regs_read[out->n_regs_read],
                      QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                      handle, reg, CS_ARCH_ARM64);
    out->regs_read_id[out->n_regs_read] = reg;
    out->n_regs_read++;
}

/*
 * Capstone-6.0.0 bug: when UBFM/SBFM/EXTR resolves to one of the
 * three-operand alias mnemonics whose printed form is `Rd, Rn, #imm`
 * (LSL #imm, LSR #imm, ASR #imm, ROR #imm), the disassembler emits the
 * shift count in op_str but DROPS the IMM operand from the structured
 * operand array — so HAS_IMM never gets surfaced to plugins.  The
 * 4-operand aliases (UBFX/SBFX/BFI/BFXIL) and the register-form ROR
 * (RORV) are unaffected because they print as `Rd, Rn, #imm, #imm` or
 * `Rd, Rn, Rm` and keep the operands.
 *
 * Capstone still parks the shift count in operands[1].shift.value when
 * this happens, so the fix is to detect the broken alias by mnemonic +
 * op_count==2 and synthesise the missing IMM from operands[1].shift.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0; verify with
 * `cstool -d arm64 20701d53` (bytes `20 70 1d 53`, `lsl w0,w1,#3`) --
 * fixed, op_count must be 3 with operands[2] a HAS_IMM of value 3; as
 * long as the bug holds, op_count stays 2.  Use a `cstool` built from
 * `subprojects/capstone` (capstone.wrap's pinned revision), not a
 * system package, or run `capstone_workaround_probe`
 * (`cap_aarch64_is_buggy_shift_imm_alias` case); see
 * docs/troubleshooting.rst.
 */
static bool cap_aarch64_is_buggy_shift_imm_alias(const char *mnem)
{
    return !strcmp(mnem, "lsl") || !strcmp(mnem, "lsr") ||
           !strcmp(mnem, "asr") || !strcmp(mnem, "ror");
}

/*
 * Capstone 6.0.0-Alpha7 AArch64 access-flag bug workaround.
 *
 * The generated per-operand table (AArch64GenCSMappingInsnOp.inc)
 * carries CS_AC_INVALID (0) on the MEM-tagged operands of the
 * register-offset / extended-register load-store forms (LDRWroX,
 * STRWroX, ...: "ldr w3, [x1, x2]", "str w3, [x1, w2, uxtw #2]") and
 * of the LSE SWP family.  Capstone's own repair pass
 * (AArch64_correct_mem_access) patches the MEM operand from a
 * per-instruction mem_acc fallback table, but in Alpha7 that table is
 * CS_AC_INVALID for the same rows, so the MEM operand reaches us with
 * access == 0.  The immediate-offset, pre/post-index, exclusive,
 * CAS/LD<op> atomic, and vector structure forms all report correctly.
 * Without correction the operand walker mints no static load/store
 * slot at all for the affected instructions — the trace template
 * claims a plain load/store/atomic cannot touch memory, dropping its
 * address/store-data dependencies along with it.
 *
 * Upstream regenerated the mem_acc rows for the register-offset forms
 * in commit e5c6e09 ("Fix AArch64 register-offset load/store memory
 * operand access", #2802), first released in 6.0.0-Alpha8; the SWP
 * rows are still CS_AC_INVALID on master as of 857e556 (2026-07).
 *
 * Infer the missing access from the mnemonic class: atomic
 * read-modify-write families (SWP / CAS / LD<op> / ST<op>) ->
 * READ|WRITE, other ld* -> READ, other st* -> WRITE.  Prefetch
 * (prfm / prf*) and non-memory classes stay untouched (return 0).
 * The caller applies this ONLY when Capstone reported access == 0,
 * so once a Capstone bump starts reporting real access bits for
 * these forms, its answer wins and this inference is dead code.
 * Revisit / remove on a Capstone bump past 6.0.0-Alpha7 (the SWP
 * rows need a fix that has not landed upstream yet).
 *
 * Verify with `cstool -d arm64 408021b8` (bytes `40 80 21 b8`, `swp
 * w1,w0,[x2]`) -- fixed, the MEM operand (operands[2]) must show
 * READ|WRITE instead of access == 0.  Use a `cstool` built from
 * `subprojects/capstone` (capstone.wrap's pinned revision), not a
 * system package, or run `capstone_workaround_probe`
 * (`cap_aarch64_infer_mem_access (SWP)` case); see
 * docs/troubleshooting.rst.
 */
static unsigned cap_aarch64_infer_mem_access(const char *mnem)
{
    static const char *const rmw_prefixes[] = {
        "swp", "cas",
        "ldadd", "ldclr", "ldeor", "ldset",
        "ldsmax", "ldsmin", "ldumax", "ldumin",
        "stadd", "stclr", "steor", "stset",
        "stsmax", "stsmin", "stumax", "stumin",
    };

    if (!mnem || !mnem[0]) {
        return 0;
    }
    for (size_t i = 0; i < ARRAY_SIZE(rmw_prefixes); i++) {
        if (g_str_has_prefix(mnem, rmw_prefixes[i])) {
            return QEMU_PLUGIN_OP_ACC_READ | QEMU_PLUGIN_OP_ACC_WRITE;
        }
    }
    if (g_str_has_prefix(mnem, "ld")) {
        return QEMU_PLUGIN_OP_ACC_READ;
    }
    if (g_str_has_prefix(mnem, "st")) {
        return QEMU_PLUGIN_OP_ACC_WRITE;
    }
    return 0;
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

    /* Capstone models no memory operand for the block-zeroing data-cache
     * maintenance ops — see cap_aarch64_is_block_zero_sysop.  Detect them
     * up front so the Xt operand can be turned into the store target it
     * really is. */
    bool block_zero = cap_aarch64_is_block_zero_sysop(a64, n);

    for (uint8_t i = 0; i < n; i++) {
        const cs_arm64_op *cop = &a64->operands[i];
        qemu_plugin_operand *op = &out->operands[i];

        op->access = cop->access;
        op->size = 0;
        op->lane_bytes = 0;
        /* AArch64 Capstone surfaces vector arrangement (vas) per
         * operand; decode it into (size, lane_bytes) when present.
         * Non-vector operands stay zero. */
        {
            uint8_t lb = 0, tb = 0;
            if (cap_decode_aarch64_vas(cop->vas, &lb, &tb)) {
                op->size       = tb;
                op->lane_bytes = lb;
            }
        }
        op->scale = 1;
        op->shift_type = (uint8_t)cop->shift.type;
        op->shift_amount = (uint8_t)cop->shift.value;

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
            /* DC ZVA / DC GZVA: Xt is not a value the instruction reads,
             * it is the address of the block the instruction zeroes.
             * Capstone gives no MEM operand at all, so present this one
             * as the store target — base = Xt, no index, no
             * displacement.  The operand walker then mints the store
             * lane and its address dependency exactly as it would for
             * any other store, and the block's stores stop being
             * impossible attributions. */
            if (block_zero) {
                op->type   = QEMU_PLUGIN_OP_MEM;
                op->access = QEMU_PLUGIN_OP_ACC_WRITE;
                op->imm    = 0;
            }
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
            /* Capstone-6.0.0-Alpha7 bug: register-offset /
             * extended-register forms and the SWP family leave the
             * MEM operand's access empty.  Infer it from the
             * mnemonic class — only when Capstone reported nothing,
             * so a fixed Capstone's own access bits take precedence
             * (see cap_aarch64_infer_mem_access). */
            if (cop->access == 0) {
                op->access = cap_aarch64_infer_mem_access(insn->mnemonic);
            }
            break;
        case ARM64_OP_PRED:
            /*
             * SVE / SME governing predicate.  Capstone rewrites every
             * p0..p15 / pn0..pn15 operand out of the REG type into its own
             * PRED type, parking the register in cop->pred.reg — see
             * AArch64_set_detail_op_reg() in the Capstone tree.  It is not a
             * defect, it is a different representation, but presenting it as
             * an unmodelled operand loses the whole predicated dataflow
             * edge: the governing predicate of every masked SVE operation,
             * and the destination of every predicate producer (ptrue,
             * whilelt, the predicate-writing compares).
             *
             * The generic register space already carries predicate registers
             * (REG_PRED0..REG_PRED31) and the plugin's AArch64 register table
             * already maps AARCH64_REG_P0..P15 / PN0..PN15 onto them; those
             * rows were simply unreachable while this arm dropped the
             * operand.  Present the predicate as an ordinary REG operand so
             * they become reachable.  The access flags Capstone attaches to
             * the PRED operand are correct and are forwarded verbatim.
             *
             * SME's second predicate field, pred.vec_select, has no second
             * register slot in the plugin operand and is not represented.
             * That is an SME-only gap, recorded in docs/limitations.rst.
             */
            op->type = QEMU_PLUGIN_OP_REG;
            cap_copy_reg_name(op->reg_name,
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                              handle, cop->pred.reg, CS_ARCH_ARM64);
            op->reg_id     = cop->pred.reg;
            op->index_name[0] = '\0';
            op->index_id   = 0;
            op->imm = 0;
            break;
        case AARCH64_OP_SME:
            /*
             * SME matrix operand.  Capstone parks the ZA tile in
             * cop->sme.tile and the GPR that selects the slice in
             * cop->sme.slice_reg, neither of which is reachable through
             * the ordinary REG arm — so `str za[w12, 0], [x0]` arrives
             * with a store whose data comes from nowhere and whose
             * slice index is not read at all.
             *
             * The tile is a real register the generic model already
             * names (AARCH64_REG_ZA maps to REG_MATRIX), so present it
             * as one and carry Capstone's access verbatim.  The slice
             * register is an ordinary GPR read that selects which slice
             * of the array moves; it joins the implicit read list
             * rather than claiming a second operand slot, because the
             * operand ABI has one register field per operand.
             *
             * pred.vec_select — SME's second predicate field — remains
             * unrepresented; that gap is recorded in
             * docs/limitations.rst.
             */
            op->type = QEMU_PLUGIN_OP_REG;
            cap_copy_reg_name(op->reg_name,
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                              handle, cop->sme.tile, CS_ARCH_ARM64);
            op->reg_id     = cop->sme.tile;
            op->index_name[0] = '\0';
            op->index_id   = 0;
            op->imm = 0;
            if (cop->sme.slice_reg != AARCH64_REG_INVALID) {
                cap_aarch64_add_implicit_read(out, handle,
                                              cop->sme.slice_reg);
            }
            break;
        default: {
            /*
             * The system register an MRS / MSR moves -- see
             * cap_aarch64_sysreg_operand.  reg_id carries the raw
             * aarch64_sysreg encoding, not a Capstone register id.
             */
            uint8_t sysacc = 0;
            if (cap_aarch64_sysreg_operand(cop, &sysacc)) {
                op->type   = QEMU_PLUGIN_OP_SYSREG;
                op->access = sysacc;
                op->reg_id = (uint16_t)cop->sysop.reg.sysreg;
                cap_aarch64_copy_sysreg_name(
                    op->reg_name, QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                    insn->op_str,
                    sysacc == QEMU_PLUGIN_OP_ACC_READ);
                op->index_name[0] = '\0';
                op->index_id   = 0;
                op->imm = 0;
                break;
            }
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
     * Capstone 6.0.0-Alpha7 SIMD writeback bug workaround.
     *
     * A pre-/post-index addressing mode updates its base register:
     * `st1 { v0.16b }, [x1], #16` leaves x1 sixteen bytes higher.  That
     * update is the induction variable of every hand-written and
     * autovectorised NEON loop, so losing it makes each iteration's
     * address look independent of the last.
     *
     * Capstone sets detail->writeback for these forms but populates the
     * implicit regs_write[] list only for the SCALAR ones: `ldr x0,
     * [x1], #16` reports the x1 write, `ld1 { v2.b }[0], [x1], #1` and
     * the whole LD1..LD4 / ST1..ST4 structure family report nothing.
     * Add the base register when writeback is claimed and the write is
     * not already listed, so a Capstone that starts reporting it cannot
     * be double-counted.
     *
     * This runs BEFORE the CAS correction below on purpose: CAS sets
     * writeback spuriously, and the CAS block is what removes the base
     * register again for that one family.
     *
     * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify
     * with `cstool -d arm64 20709f4c` (bytes `20 70 9f 4c`,
     * `st1 {v0.16b},[x1],#16`) -- fixed, x1 must appear in the implicit
     * write list as it already does for the scalar `ldr` post-index
     * form.  Use a `cstool` built from `subprojects/capstone`, not a
     * system package, or run `capstone_workaround_probe`; see
     * docs/troubleshooting.rst.
     */
    if (insn->detail->writeback) {
        for (uint8_t i = 0; i < n; i++) {
            if (out->operands[i].type != QEMU_PLUGIN_OP_MEM
                || out->operands[i].reg_id == 0) {
                continue;
            }
            /* detail->writeback is set on SIMD structure accesses that
             * have no writeback at all (`ld1 { v2.b }[0], [x1]` claims
             * it), so the flag alone would fabricate the very phantom
             * this is meant to avoid.  Require an actual index amount as
             * well: a real pre-/post-index form always carries the
             * increment, either as the MEM displacement or as an index
             * register. */
            if (out->operands[i].imm == 0 && out->operands[i].index_id == 0) {
                break;
            }
            uint16_t base = out->operands[i].reg_id;
            bool listed = false;
            for (uint8_t k = 0; k < out->n_regs_write; k++) {
                if (out->regs_write_id[k] == base) {
                    listed = true;
                    break;
                }
            }
            if (!listed
                && out->n_regs_write < QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS) {
                cap_copy_reg_name(out->regs_write[out->n_regs_write],
                                  QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                                  handle, base, CS_ARCH_ARM64);
                out->regs_write_id[out->n_regs_write] = base;
                out->n_regs_write++;
            }
            break;
        }
    }

    /*
     * Capstone 6.0.0-Alpha7 single-register CAS workaround
     * (see cap_aarch64_is_single_cas).  Restore the write to the
     * compare/result register and drop the phantom write of the address
     * base that detail->writeback fabricates.
     */
    if (cap_aarch64_is_cas(insn->mnemonic)) {
        unsigned base_reg = 0;
        for (uint8_t i = 0; i < n; i++) {
            if (out->operands[i].type == QEMU_PLUGIN_OP_MEM) {
                base_reg = out->operands[i].reg_id;
                break;
            }
        }
        if (cap_aarch64_is_single_cas(insn->mnemonic)) {
            for (uint8_t i = 0; i < n; i++) {
                if (out->operands[i].type == QEMU_PLUGIN_OP_REG) {
                    out->operands[i].access |= QEMU_PLUGIN_OP_ACC_READ
                                             | QEMU_PLUGIN_OP_ACC_WRITE;
                    break;
                }
            }
        }
        if (base_reg) {
            uint8_t keep = 0;
            for (uint8_t i = 0; i < out->n_regs_write; i++) {
                if (out->regs_write_id[i] == base_reg) {
                    continue;
                }
                if (keep != i) {
                    memcpy(out->regs_write[keep], out->regs_write[i],
                           QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ);
                    out->regs_write_id[keep] = out->regs_write_id[i];
                }
                keep++;
            }
            out->n_regs_write = keep;
        }
    }

    /*
     * Capstone 6.0.0-Alpha7 FEAT_MOPS memset workaround
     * (see cap_aarch64_is_mops_set).  A memset stores; it does not load.
     */
    if (cap_aarch64_is_mops_set(insn->mnemonic)) {
        for (uint8_t i = 0; i < n; i++) {
            if (out->operands[i].type == QEMU_PLUGIN_OP_MEM) {
                out->operands[i].access = QEMU_PLUGIN_OP_ACC_WRITE;
            }
        }
    }

    /*
     * Capstone 6.0.0-Alpha7 bug: the SVE merging-predicated move
     * `mov <Zd>.<T>, <Pg>/M, <Zn>.<T>` is an alias of
     * `SEL <Zd>, <Pg>, <Zn>, <Zd>`.  Under /M the inactive lanes keep
     * Zd's previous value, so Zd is genuinely a source — the fourth
     * operand of the underlying SEL.  Capstone's alias printer drops that
     * operand and the metadata follows the printed alias, so Zd reports
     * WRITE only and the merge's dependency on its own previous value
     * disappears.
     *
     * The scoping is exact: the printed SEL form keeps all four operands
     * and is correct, and the CPY-based `mov <Zd>.<T>, <Pg>/M, #imm` /
     * `..., <Wn>` forms already report READ|WRITE.  Detect the alias by
     * insn id SEL with a three-operand shape and restore Zd's read.
     *
     * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify
     * with `cstool -d arm64 e0c32005` (bytes `e0 c3 20 05`,
     * `mov z0.b, p0/m, z31.b`) -- fixed, operands[0] must show READ|WRITE,
     * or the alias must expand to four operands.  Use a `cstool` built
     * from `subprojects/capstone`, not a system package, or run
     * `capstone_workaround_probe`; see docs/troubleshooting.rst.
     */
    if (insn->id == ARM64_INS_SEL && out->n_operands == 3 &&
        out->operands[0].type == QEMU_PLUGIN_OP_REG &&
        out->operands[2].type == QEMU_PLUGIN_OP_REG) {
        out->operands[0].access |= QEMU_PLUGIN_OP_ACC_READ;
    }


    /*
     * Capstone-6.0.0 LSL/LSR/ASR/ROR alias bug workaround
     * (see cap_aarch64_is_buggy_shift_imm_alias).  When the shape
     * matches, synthesise the dropped third operand from
     * operands[1].shift.
     *
     * The shift *type* says how to read shift.value, and both cases
     * occur here.  For the immediate aliases (`lsl w0, w1, #3`) it is a
     * shift count and the synthesised operand is an IMM, so plugins see
     * HAS_IMM and the correct count.  For the REGISTER aliases
     * (`lsl x2, x1, x9` — LSLV / LSRV / ASRV / RORV) Capstone sets one
     * of the *_REG shift types and parks the shift-amount REGISTER in
     * the same field: `lsl x2, x1, x9` yields shift.value == 247 ==
     * AARCH64_REG_X9.  Reading that as an immediate loses the third
     * source register from the dependency model AND fabricates a
     * constant shift of a nonsensical amount, on an instruction
     * ordinary compiler output emits constantly.  Synthesise a REG
     * operand in that case, as the header's own note on shift.value
     * prescribes.
     *
     * Verify the register half with `cstool -d arm64 2220c99a` (bytes
     * `22 20 c9 9a`, `lsl x2,x1,x9`) -- fixed, op_count must be 3 with
     * operands[2] a REG naming x9.
     */
    /*
     * Capstone 6.0.0-Alpha7 aliased-RET workaround.
     *
     * `ret` with no printed operand is the alias of `RET X30`: the
     * return address comes from the link register, and that is the ONE
     * register dependency every AArch64 return carries.  Capstone's
     * detail follows the printed alias, so the operand disappears and
     * `detail->regs_read` is left empty — the boundary sees an
     * instruction that reads nothing, and the return of every function
     * in the trace floats free of the `ldp`/`mov` that restored x30.
     * The non-aliased `ret x1` keeps its operand and is correct.
     *
     * Capstone knows the answer but only exposes it through
     * cs_regs_access(), which special-cases AARCH64_INS_ALIAS_RET
     * (AArch64_reg_access() in the Capstone tree).  The boundary cannot
     * adopt that entry point wholesale: it MERGES the explicit operand
     * registers into one flat list, which would double-count every
     * operand the walker already consumes, and it switches on
     * insn->alias_id WITHOUT consulting insn->is_alias — a field
     * Capstone leaves stale across decodes on a reused handle, so after
     * one `ret` it fabricates an x30 read on every later `eret`, `drps`,
     * `braa`, `blraa` and even `ret x1`.  (That staleness is a second
     * upstream defect; report it with this one.)
     *
     * Restore the read directly instead, keyed on the exact shape that
     * cannot be anything else: AARCH64_INS_RET printed with no operand.
     * This mirrors the RISC-V aliased-link restore in
     * refine_branch_type() (champsim_tracer_decode.cc), which repairs
     * the same class of loss on the other ISA — placed HERE rather than
     * in the plugin so isaxcheck, which drives this boundary, verifies
     * it.  x30 joins the implicit read list, which is exactly how
     * Capstone already reports the same dependency for `retaa`/`retab`.
     *
     * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify
     * with `cstool -d aarch64 c0035fd6` (bytes `c0 03 5f d6`, `ret`) --
     * fixed, either operands[0] must name x30 or the implicit read list
     * must carry it.  Use a `cstool` built from `subprojects/capstone`,
     * not a system package, or run `capstone_workaround_probe`; see
     * docs/troubleshooting.rst.
     */
    /*
     * The FEAT_MOPS prologue's own NZCV read (see
     * cap_aarch64_is_mops_prologue) and the FPCR read Capstone reports
     * on these forms' siblings but not on them (see
     * cap_aarch64_reads_fpcr_unreported).  Both are architectural facts
     * from the MRA rather than version-specific Capstone defects, so
     * neither is conditional on a Capstone revision; both add only when
     * the register is not already listed, so a Capstone that starts
     * reporting them cannot double-count.
     */
    if (cap_aarch64_is_mops_prologue(insn->mnemonic)) {
        cap_aarch64_add_implicit_read(out, handle, AARCH64_REG_NZCV);
    }
    if (cap_aarch64_reads_fpcr_unreported(insn->mnemonic)) {
        cap_aarch64_add_implicit_read(out, handle, AARCH64_REG_FPCR);
    }

    if (insn->id == ARM64_INS_RET && a64->op_count == 0) {
        bool listed = false;
        for (uint8_t i = 0; i < out->n_regs_read; i++) {
            if (out->regs_read_id[i] == AARCH64_REG_LR) {
                listed = true;
                break;
            }
        }
        if (!listed
            && out->n_regs_read < QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS) {
            cap_copy_reg_name(out->regs_read[out->n_regs_read],
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                              handle, AARCH64_REG_LR, CS_ARCH_ARM64);
            out->regs_read_id[out->n_regs_read] = AARCH64_REG_LR;
            out->n_regs_read++;
        }
    }

    if (out->n_operands == 2 &&
        out->n_operands < QEMU_PLUGIN_INSN_DETAIL_MAX_OPS &&
        cap_aarch64_is_buggy_shift_imm_alias(insn->mnemonic) &&
        a64->op_count >= 2 &&
        a64->operands[1].shift.type != AARCH64_SFT_INVALID) {
        uint8_t k = out->n_operands;
        unsigned shift_type = a64->operands[1].shift.type;
        unsigned shift_val = a64->operands[1].shift.value;
        qemu_plugin_operand *op = &out->operands[k];
        memset(op, 0, sizeof(*op));
        op->scale = 1;
        if (shift_type >= AARCH64_SFT_LSL_REG) {
            op->type = QEMU_PLUGIN_OP_REG;
            op->access = QEMU_PLUGIN_OP_ACC_READ;
            op->reg_id = (uint16_t)shift_val;
            cap_copy_reg_name(op->reg_name,
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                              handle, shift_val, CS_ARCH_ARM64);
        } else {
            op->type = QEMU_PLUGIN_OP_IMM;
            op->imm = (int64_t)shift_val;
        }
        out->n_operands = k + 1;
    }
}

/*
 * MIPS tied-destination family test.  Every member writes its first
 * register operand while PRESERVING part of its previous value — a
 * bit-field insert, a lane insert/shuffle, a masked select, a
 * multiply-accumulate, or a conditional move that leaves the
 * destination alone when the condition fails.  LLVM records the tie;
 * Capstone reports the operand WRITE-only, so the read-modify-write
 * looks like a full overwrite and a real RAW edge is reported as WAW.
 *
 * The membership list was derived from the isaxcheck sweep (every MIPS
 * `R-rd-missing` signature whose missing read is the instruction's own
 * destination), not from guesswork; re-derive it the same way on a
 * Capstone bump.  Prefixes are used where a family has per-element-size
 * spellings (maddv.b/.h/.w/.d).  Note what is deliberately NOT here:
 * the two-operand `madd $rs, $rt` / `msub` accumulate into the implicit
 * HI:LO pair rather than into an operand, so their first register
 * operand is a pure source.
 */
static bool cap_mips_is_tied_dst(const char *mnem)
{
    static const char *const stems[] = {
        /* scalar and DSP bit-field insert / concatenate */
        "ins", "dins", "append", "prepend", "insv",
        /* MSA bit insert / select */
        "binsl", "binsr", "bmnz", "bmz", "bsel",
        /* MSA lane insert / shift-and-insert / shuffle */
        "insert", "insve", "sld", "vshf",
        /* MSA and DSP multiply-accumulate (integer, fixed-point, FP) */
        "maddv", "msubv", "madd_q", "maddr_q", "msub_q", "msubr_q",
        "fmadd", "fmsub", "dpa", "dps",
        /* conditional moves: the destination survives a failed condition */
        "movn", "movz", "movt", "movf",
    };

    if (!mnem || !mnem[0]) {
        return false;
    }
    for (size_t i = 0; i < ARRAY_SIZE(stems); i++) {
        if (g_str_has_prefix(mnem, stems[i])) {
            return true;
        }
    }
    return false;
}

/*
 * RVV multiply-accumulate family test — see the tied-operand workaround
 * in cap_fill_generic_operands().  Capstone spells the whole family
 * v[f][w][n]m{acc,add,sac,sub}.{vv,vx,vf}; matching on the accumulate
 * infix covers vmacc/vmadd/vnmsac/vnmsub, vwmacc{,u,su,us}, and every
 * vf[w][n]m{acc,add,sac,sub} without enumerating 55 mnemonics.  The
 * single-element inserts vmv.s.x / vfmv.s.f share the tied shape but not
 * the infix, so they are named explicitly.
 */
static bool cap_riscv_is_tied_vd(const char *mnem)
{
    if (!mnem || mnem[0] != 'v') {
        return false;
    }
    if (!strcmp(mnem, "vmv.s.x") || !strcmp(mnem, "vfmv.s.f")) {
        return true;
    }
    return strstr(mnem, "macc") || strstr(mnem, "madd") ||
           strstr(mnem, "msac") || strstr(mnem, "msub");
}

/*
 * RVV unconditionally-masked carry / merge family test.
 *
 * Almost every RVV instruction takes an OPTIONAL mask, spelled `, v0.t`
 * when present; Capstone models that one correctly as a fourth operand
 * reading v0.  Six families are different: their mask is not optional
 * and not a predicate but a DATA input — the carry-in of vadc/vmadc,
 * the borrow-in of vsbc/vmsbc, the select control of vmerge/vfmerge —
 * so the assembler spells it with a trailing `m` on the operand-shape
 * suffix (`.vvm` / `.vxm` / `.vim` / `.vfm`) and v0 is a mandatory,
 * non-maskable operand.  That is the complete closure: these four
 * suffixes exist on RISC-V for these six families and nothing else
 * (vadc, vmadc, vsbc, vmsbc, vmerge, vfmerge — 14 mnemonics), and the
 * unmasked siblings that omit the carry-in are spelled without the `m`
 * (`vmadc.vv`, `vmsbc.vx`), so the suffix test cannot over-reach.
 */
static bool cap_riscv_reads_v0_mask(const char *mnem)
{
    size_t len;

    if (!mnem || mnem[0] != 'v') {
        return false;
    }
    len = strlen(mnem);
    if (len < 5 || mnem[len - 1] != 'm' || mnem[len - 3] != 'v'
        || mnem[len - 4] != '.') {
        return false;
    }
    switch (mnem[len - 2]) {
    case 'v':   /* .vvm */
    case 'x':   /* .vxm */
    case 'i':   /* .vim */
    case 'f':   /* .vfm */
        return true;
    default:
        return false;
    }
}

/*
 * RVV mask-destination family test — the one statically decidable case
 * of "the vector destination is also a source".
 *
 * Under tail-undisturbed or mask-undisturbed the destination keeps its
 * old contents in the inactive elements, so architecturally vd is a
 * source of nearly every vector op.  That general case is NOT decidable
 * from the instruction word: it depends on vtype.vta, vtype.vma and vl
 * against VLMAX, all written by an earlier vsetvl, so a per-opcode
 * template cannot express it without carrying vtype in its key.  It is
 * deliberately left unmodelled.
 *
 * The sub-case where the destination is a MASK register is different:
 * Sail's write_vmask leaves the mask tail undisturbed unconditionally,
 * regardless of vta, so vd is a source no matter what the runtime
 * configuration says.  That covers the integer and FP compares, the
 * carry/borrow-out producers vmadc/vmsbc, the mask-logical ops, the
 * set-before/including/only-first scans, and the mask load vlm.v.
 *
 * The mnemonic space is closed: every RVV instruction whose destination
 * is a mask register is spelled vms* (compares, vmsbc, vmsbf/vmsif/
 * vmsof), vmf* (FP compares), vmadc*, a mask-logical vm*.mm, or vlm.v.
 * Instructions that merely *read* a mask into a scalar (vcpop.m,
 * vfirst.m) write a GPR and are not in any of those shapes.
 */
static bool cap_riscv_is_mask_dst(const char *mnem)
{
    size_t len;

    if (!mnem || mnem[0] != 'v') {
        return false;
    }
    if (!strcmp(mnem, "vlm.v")) {
        return true;
    }
    /* Mask-logical pseudo-instructions Capstone prints in place of the
     * .mm form they encode: vmmv.m (vmand.mm vd,vs,vs), vmnot.m
     * (vmnand.mm vd,vs,vs), vmclr.m (vmxor.mm vd,vd,vd), vmset.m
     * (vmxnor.mm vd,vd,vd). */
    if (!strcmp(mnem, "vmmv.m") || !strcmp(mnem, "vmnot.m") ||
        !strcmp(mnem, "vmclr.m") || !strcmp(mnem, "vmset.m")) {
        return true;
    }
    if (g_str_has_prefix(mnem, "vms") || g_str_has_prefix(mnem, "vmf") ||
        g_str_has_prefix(mnem, "vmadc")) {
        return true;
    }
    /* Mask-logical: vmand/vmnand/vmandn/vmor/vmnor/vmorn/vmxor/vmxnor,
     * all spelled with a .mm operand-shape suffix. */
    len = strlen(mnem);
    return len > 5 && mnem[1] == 'm' && !strcmp(mnem + len - 3, ".mm");
}

/*
 * RISC-V scalar FP dynamic rounding: the frm read with no encoded field.
 *
 * An FP instruction's 3-bit rm field names a rounding mode directly
 * except for the value 0b111 (DYN), which means "use the rounding mode
 * in fcsr.frm".  Sail states it exactly -- select_instr_or_fcsr_rm reads
 * fcsr[FRM] only in that case -- and it is the case a compiler emits for
 * every ordinary FP operation, so essentially all scalar FP arithmetic
 * in a trace depends on the last fsrm/fscsr and the boundary said it
 * depended on nothing.
 *
 * Read from the instruction word rather than the mnemonic because the
 * mnemonic does not carry it: `fcvt.w.d a0, fa0` and `fcvt.w.d a0, fa0,
 * rtz` are the same mnemonic with different rm, and only the first
 * reads frm.  The rm field doubles as a function selector on the
 * compare / sign-inject / min-max / class / move forms, but none of
 * those uses the value 0b111, so testing for DYN excludes them without
 * having to enumerate them.
 *
 * Restricted to the five FP major opcodes -- OP-FP and the four
 * fused-multiply-add forms -- and to 32-bit encodings, so the
 * compressed FP loads and stores (which have no rm field and no
 * rounding) cannot match.
 */
static bool cap_riscv_reads_dynamic_frm(const cs_insn *insn)
{
    uint32_t word;
    uint32_t opcode;

    if (insn->size != 4) {
        return false;
    }
    word = (uint32_t)insn->bytes[0] | ((uint32_t)insn->bytes[1] << 8) |
           ((uint32_t)insn->bytes[2] << 16) | ((uint32_t)insn->bytes[3] << 24);
    opcode = word & 0x7f;
    /* MADD / MSUB / NMSUB / NMADD / OP-FP. */
    if (opcode != 0x43 && opcode != 0x47 && opcode != 0x4b &&
        opcode != 0x4f && opcode != 0x53) {
        return false;
    }
    return ((word >> 12) & 0x7) == 0x7;   /* rm == DYN */
}

/*
 * RISC-V scalar tied-destination families -- see the workaround in
 * cap_fill_generic_operands().
 *
 * The same Capstone tied-operand handling that loses the RVV
 * multiply-accumulate destination (cap_riscv_is_tied_vd) also loses two
 * families outside the vector unit, and there it loses the destination
 * ENTIRELY: the operand arrives READ-only, so the instruction reports no
 * write at all and produces nothing anything can depend on.
 *
 * Zacas `amocas.w/.d/.q rd, rs2, (rs1)` is a compare-and-swap, and rd
 * carries both directions of it.  The unprivileged ISA manual's Zacas
 * chapter states the operation as: load the word addressed by rs1,
 * compare it with rd, store rs2 if they matched, and write the loaded
 * word to rd -- rd is the COMPARAND on the way in and the OBSERVED
 * MEMORY VALUE on the way out.  Reporting it READ-only makes the "did
 * my CAS win" comparison that follows every compare-and-swap loop read
 * a register nothing in the trace ever wrote.  The double-width forms
 * (amocas.d on RV32, amocas.q on RV64) name an even-odd register pair,
 * which does not change the direction question: Capstone prints the
 * even register and it is read and written either way.
 *
 * CORE-V (XCValu) `cv.{add,sub}[u][r]nr rD, rs1, rs2` normalises in
 * place -- rD = (rD +/- rs1) >> rs2[4:0], `u` selecting the unsigned
 * (logical) shift and `r` adding the round-to-nearest half before it --
 * so rD is an accumulator, exactly like the RVV multiply-accumulate
 * shape.  The trailing `nr` is what separates them from the
 * immediate-shift siblings `cv.addn` / `cv.addun` / ..., which take the
 * shift amount as an immediate and write a fresh rD; Capstone's XCValu
 * name table contains exactly eight `nr` mnemonics and they are the
 * whole family, so the suffix test is closed and cannot over-reach.
 * The XCVmac multiply-accumulates (`cv.mac`, `cv.macsn`, ...) are the
 * same accumulator shape but the tracer's Capstone mode does not enable
 * XCVmac, so they never reach this path and are deliberately not named
 * here.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify
 * with `isaxcheck --isa=riscv64 --hex=af221328` (`amocas.w t0, ra,
 * (t1)`) and `--hex=ab321380` (`cv.addnr t0, t1, ra`) -- fixed, the
 * boundary's WR set must name r5 without this workaround.
 */
static bool cap_riscv_is_tied_rd(const char *mnem)
{
    size_t len;

    if (!mnem) {
        return false;
    }
    if (g_str_has_prefix(mnem, "amocas.")) {
        return true;
    }
    if (!g_str_has_prefix(mnem, "cv.")) {
        return false;
    }
    len = strlen(mnem);
    return len > 5 && !strcmp(mnem + len - 2, "nr");
}

/*
 * Is this encoding in the RVV instruction space?
 *
 * The vl/vtype restore in cap_fill_generic_operands() keys off the
 * mnemonic, and a mnemonic is not enough: RISC-V vendor extensions put
 * non-vector instructions in the `v` namespace.  XVentanaCondOps spells
 * its two SCALAR conditional moves `vt.maskc` / `vt.maskcn` -- GPR in,
 * GPR out, major opcode custom-3, the vendor precursor of Zicond's
 * `czero.nez` / `czero.eqz` -- so a name test files them with the
 * vector unit and hangs the RVV configuration CSRs on them, inventing a
 * dependency on the last `vsetvli` for an instruction that has nothing
 * to do with the vector unit and does not change behaviour with vl.
 *
 * Decide it from the encoding instead, which is the architecture rather
 * than a second guess at a name table.  RVV v1.0 occupies exactly three
 * major opcodes: OP-V (0b1010111) holds the arithmetic, permute, mask
 * and `vsetvl*` configuration instructions, and LOAD-FP (0b0000111) /
 * STORE-FP (0b0100111) hold the vector loads and stores, told apart
 * from the scalar FP loads and stores that share those opcodes by the
 * width field -- vector uses 0b000/0b101/0b110/0b111 for 8/16/32/64-bit
 * elements, scalar FP uses 0b001/0b010/0b011/0b100 for h/w/d/q.
 * Nothing else in RVV 1.0 is encoded outside those three (the vector
 * AMOs that would have been were dropped before ratification), and
 * there are no compressed vector encodings, so a 2-byte instruction
 * cannot be one.
 */
static bool cap_riscv_is_vector_encoding(const cs_insn *insn)
{
    uint32_t word;

    if (insn->size != 4) {
        return false;
    }
    word = (uint32_t)insn->bytes[0] | ((uint32_t)insn->bytes[1] << 8) |
           ((uint32_t)insn->bytes[2] << 16) | ((uint32_t)insn->bytes[3] << 24);

    switch (word & 0x7f) {
    case 0x57:                              /* OP-V */
        return true;
    case 0x07:                              /* LOAD-FP  */
    case 0x27:                              /* STORE-FP */
        switch ((word >> 12) & 0x7) {       /* width */
        case 0:                             /* 8-bit elements  */
        case 5:                             /* 16-bit elements */
        case 6:                             /* 32-bit elements */
        case 7:                             /* 64-bit elements */
            return true;
        default:                            /* scalar flh/flw/fld/flq */
            return false;
        }
    default:
        return false;
    }
}

/*
 * Zfa `fli` table index.
 *
 * `fli.h/s/d/q rd, <constant>` materialises one of 32 constants, and the
 * constant is not what the instruction encodes: the Zfa chapter defines
 * the 5-bit rs1 field as an INDEX into a fixed table (row 0 is -1.0, row
 * 1 the smallest positive normal number of the format, rows 2..29 a
 * fixed ladder of powers and simple fractions, row 30 +inf and row 31 a
 * canonical NaN), and QEMU's own translator says the same thing in one
 * line -- `tcg_gen_movi_i64(dest, fli_s_table[a->rs1])` in
 * target/riscv/insn_trans/trans_rvzfa.c.inc.  Both disassemblers print
 * the decoded constant (`fli.s ft5, 0.0625`, `fli.s ft5, min`), which is
 * the assembly syntax, not the operand's encoded value.
 *
 * Recognise the shape rather than trusting the operand type alone:
 * OP-FP with rm = 0, the rs2 field holding the fli selector 1, and a
 * funct7 in the fmv/fli block 0b11110xx that names the format.  A
 * RISCV_OP_FP operand on anything else is a Capstone representation the
 * boundary has not been taught, and the caller leaves it unmodelled so
 * the decode gate reports it rather than silently inventing a number.
 */
static bool cap_riscv_fli_index(const cs_insn *insn, int64_t *index)
{
    uint32_t word;

    if (insn->size != 4) {
        return false;
    }
    word = (uint32_t)insn->bytes[0] | ((uint32_t)insn->bytes[1] << 8) |
           ((uint32_t)insn->bytes[2] << 16) | ((uint32_t)insn->bytes[3] << 24);

    if ((word & 0x7f) != 0x53) {            /* not OP-FP */
        return false;
    }
    if (((word >> 12) & 0x7) != 0) {        /* rm != 0 */
        return false;
    }
    if (((word >> 20) & 0x1f) != 1) {       /* rs2 != the fli selector */
        return false;
    }
    if ((word >> 27) != 0x1e) {             /* funct7 not 0b11110xx */
        return false;
    }
    *index = (int64_t)((word >> 15) & 0x1f);
    return true;
}

/*
 * Zicsr access direction.
 *
 * Capstone reports every CSR operand as READ|WRITE, but the ISA
 * suppresses one side by encoding: CSRRW / CSRRWI with rd == x0 does not
 * read the CSR, and CSRRS / CSRRC / CSRRSI / CSRRCI with a zero rs1 or
 * uimm does not write it (Sail's csr_access_type states the whole
 * table).  The suppression is not cosmetic -- `csrr a0, vl` is the
 * spelling of "read vl", and reporting it as a write of vl would make
 * every following vector instruction depend on it instead of on the
 * vsetvli that configured them.
 *
 * The alias mnemonics Capstone prints (csrr, csrw, frflags, fsrm, ...)
 * omit the x0 operand that decides this, so the fields come from the
 * instruction word.
 */
/*
 * Name for a CSR operand.  Capstone has no CSR-number lookup and
 * prints an unrecognised CSR as its bare number, so the user-level
 * CSRs the generic model names are spelled here and everything else is
 * left unnamed -- "0x1a0" is not a register name, and carrying it would
 * put 4096 meaningless tokens into every name-keyed comparison.  Purely
 * informational either way: the consumer maps from the number.
 */
static const char *cap_riscv_csr_name(unsigned csr)
{
    switch (csr) {
    case 0x001: return "fflags";
    case 0x002: return "frm";
    case 0x003: return "fcsr";
    case 0x008: return "vstart";
    case 0x009: return "vxsat";
    case 0x00a: return "vxrm";
    case 0x00f: return "vcsr";
    case 0xc20: return "vl";
    case 0xc21: return "vtype";
    case 0xc22: return "vlenb";
    default:    return NULL;
    }
}

static uint8_t cap_riscv_csr_access(const cs_insn *insn)
{
    uint32_t word;
    unsigned funct3, rd, rs1;

    if (insn->size != 4) {
        return QEMU_PLUGIN_OP_ACC_READ | QEMU_PLUGIN_OP_ACC_WRITE;
    }
    word = (uint32_t)insn->bytes[0] | ((uint32_t)insn->bytes[1] << 8) |
           ((uint32_t)insn->bytes[2] << 16) | ((uint32_t)insn->bytes[3] << 24);
    if ((word & 0x7f) != 0x73) {           /* not SYSTEM */
        return QEMU_PLUGIN_OP_ACC_READ | QEMU_PLUGIN_OP_ACC_WRITE;
    }
    funct3 = (word >> 12) & 0x7;
    rd     = (word >> 7) & 0x1f;
    rs1    = (word >> 15) & 0x1f;          /* also the uimm of the I forms */

    switch (funct3) {
    case 1:                                 /* CSRRW  */
    case 5:                                 /* CSRRWI */
        return QEMU_PLUGIN_OP_ACC_WRITE |
               (rd ? QEMU_PLUGIN_OP_ACC_READ : 0);
    case 2:                                 /* CSRRS  */
    case 3:                                 /* CSRRC  */
    case 6:                                 /* CSRRSI */
    case 7:                                 /* CSRRCI */
        return QEMU_PLUGIN_OP_ACC_READ |
               (rs1 ? QEMU_PLUGIN_OP_ACC_WRITE : 0);
    default:
        return QEMU_PLUGIN_OP_ACC_READ | QEMU_PLUGIN_OP_ACC_WRITE;
    }
}

/*
 * MIPS accumulator read-modify-write family.
 *
 * A multiply-accumulate adds its product to what the accumulator
 * already holds -- QEMU's DP_NOFUNC_PH and its siblings read
 * env->active_tc.HI[ac] / LO[ac] before writing them back -- so the
 * accumulator is a source as well as the destination.  Capstone gets
 * this right for the base-MIPS forms that leave the accumulator
 * implicit (`madd $4, $5` reports ac0 in both lists) and wrong for
 * every form that NAMES the accumulator, which is all of DSP: `madd
 * $ac2, $4, $5` reports the write and drops the read, so a
 * multiply-accumulate loop's carried dependency -- the whole point of
 * the instruction -- does not exist.
 *
 * SHILO and MTHLIP are the same shape without the multiply: they shift
 * the accumulator's current contents, so they read what they write.
 *
 * The mnemonic test is deliberately paired with a structural one at the
 * use site (the operand must actually name an accumulator register), so
 * the FP fused forms `madd.s` / `msub.d`, which share the stem but
 * write an FP register, cannot match.
 */
static bool cap_mips_is_acc_rmw(const char *mnem)
{
    return g_str_has_prefix(mnem, "madd")  || g_str_has_prefix(mnem, "msub") ||
           g_str_has_prefix(mnem, "dpa")   || g_str_has_prefix(mnem, "dps")  ||
           g_str_has_prefix(mnem, "maq")   || g_str_has_prefix(mnem, "mulsa") ||
           g_str_has_prefix(mnem, "shilo") || g_str_has_prefix(mnem, "mthlip");
}

static bool cap_mips_is_acc_reg(uint16_t reg)
{
    return (reg >= MIPS_REG_AC0 && reg <= MIPS_REG_AC3) ||
           (reg >= MIPS_REG_HI0 && reg <= MIPS_REG_HI3) ||
           (reg >= MIPS_REG_LO0 && reg <= MIPS_REG_LO3);
}

/* Append @reg to the implicit write (@is_write) or read list of a MIPS
 * decode unless it is already there. */
static void cap_mips_add_implicit(qemu_plugin_insn_info *out, csh handle,
                                  unsigned int reg, bool is_write)
{
    uint16_t *ids   = is_write ? out->regs_write_id : out->regs_read_id;
    uint8_t  *cnt   = is_write ? &out->n_regs_write : &out->n_regs_read;
    char (*names)[QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ] =
        is_write ? out->regs_write : out->regs_read;

    for (uint8_t i = 0; i < *cnt; i++) {
        if (ids[i] == reg) {
            return;
        }
    }
    if (*cnt >= QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS) {
        return;
    }
    cap_copy_reg_name(names[*cnt], QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                      handle, reg, CS_ARCH_MIPS);
    ids[*cnt] = reg;
    (*cnt)++;
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
            /* CS_AC_READ/WRITE == QEMU_PLUGIN_OP_ACC_READ/WRITE (1/2);
             * forward Capstone's per-operand access verbatim, same as
             * the x86/arm64 fillers.  Crucial for memory operands:
             * the plugin's HAS_ADDR address-dependency block (and the
             * dst<-load-slot wiring) is gated on a MEM operand
             * reporting READ/WRITE, so without this every RISC-V load
             * collapses to the all-to-all fallback and a consumer
             * sees a load result as a 1-cycle register move. */
            op->access = cop->access;
            op->size = 0;
            /* V-extension SEW is a runtime CSR; not derivable here. */
            op->lane_bytes = 0;
            op->scale = 1;
            op->shift_type = 0;
            op->shift_amount = 0;
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
            case RISCV_OP_FP:
                /*
                 * The constant a Zfa `fli` names.  Capstone rewrites
                 * this operand out of the immediate type into its own
                 * FP type, parking the DECODED constant in cop->dimm as
                 * a C double -- so presented as anything else the
                 * instruction arrives with an unmodelled operand and no
                 * immediate at all, and presented as cop->dimm cast to
                 * an integer every constant below 1.0 would arrive as
                 * zero.
                 *
                 * Carry the encoded field, exactly as the CSR arm below
                 * carries the raw 12-bit CSR number rather than a name:
                 * what `fli` encodes is a 5-bit index into the Zfa
                 * constant table (see cap_riscv_fli_index), and the
                 * decoded value the disassembly prints is a property of
                 * that table and the format suffix, not of the operand.
                 *
                 * An FP operand on any other encoding is a Capstone
                 * representation this boundary has not been taught, and
                 * is deliberately left unmodelled so the decode gate
                 * reports it instead of it arriving as a plausible
                 * number.
                 */
                {
                    int64_t fli_index;
                    if (cap_riscv_fli_index(insn, &fli_index)) {
                        op->type = QEMU_PLUGIN_OP_IMM;
                        op->imm  = fli_index;
                    } else {
                        op->type = QEMU_PLUGIN_OP_INVALID;
                        op->imm  = 0;
                    }
                }
                op->reg_name[0] = '\0';
                op->reg_id     = 0;
                op->index_name[0] = '\0';
                op->index_id   = 0;
                break;
            case RISCV_OP_CSR:
                /*
                 * The control and status register a Zicsr instruction
                 * exists to move.  Capstone carries it as a bare 12-bit
                 * number in its own operand type -- a numbering space
                 * disjoint from riscv_reg -- so presented as anything
                 * else `csrr a0, vl` reads nothing and `fscsr a0, a1`
                 * writes nothing, and a vector kernel's edge onto the
                 * vsetvli that configured it, or an FP kernel's onto
                 * the fsrm that set its rounding mode, does not exist.
                 * It goes out as QEMU_PLUGIN_OP_SYSREG carrying the raw
                 * CSR number, with the direction refined from the
                 * encoding (see cap_riscv_csr_access).
                 */
                op->type = QEMU_PLUGIN_OP_SYSREG;
                op->access = cap_riscv_csr_access(insn);
                op->reg_id = (uint16_t)cop->csr;
                {
                    /* Only a real name.  Capstone prints an unrecognised
                     * CSR as its bare number, and "0x1a0" is not a
                     * register name -- carrying it here would put 4096
                     * distinct tokens into every name-keyed comparison
                     * for no information, since the consumer maps from
                     * reg_id anyway. */
                    const char *nm = cap_riscv_csr_name(cop->csr);
                    if (nm) {
                        g_strlcpy(op->reg_name, nm,
                                  QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ);
                    } else {
                        op->reg_name[0] = '\0';
                    }
                }
                op->index_name[0] = '\0';
                op->index_id   = 0;
                op->imm = 0;
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
        /*
         * Zicsr alias forms drop the CSR operand altogether.
         *
         * With the F/D extension enabled Capstone prints `csrrw a0,
         * frm, a1` as its alias `fsrm a0, a1` and `csrrs a2, frm, x0`
         * as `frrm a2` -- and the structured detail follows the printed
         * alias, so the CSR operand disappears from the operand array
         * exactly as x30 disappears from an aliased AArch64 `ret`.  The
         * plain `csrr a3, vstart` form keeps it.  The result is that
         * every fsrm/frrm/fscsr/frflags -- the instructions a program
         * uses to set and read the FP rounding mode -- moves nothing,
         * while the same access spelled without an alias is correct.
         *
         * Recover it from the encoding, which states it plainly: for a
         * SYSTEM opcode with a Zicsr funct3, the CSR number is the top
         * 12 bits.  funct3 0 (ECALL / EBREAK / xRET / WFI) and 4 are
         * not CSR accesses and are excluded.  Synthesised only when
         * Capstone reported no CSR operand, so the non-aliased forms
         * keep their own.
         */
        if (insn->size == 4) {
            uint32_t word = (uint32_t)insn->bytes[0] |
                            ((uint32_t)insn->bytes[1] << 8) |
                            ((uint32_t)insn->bytes[2] << 16) |
                            ((uint32_t)insn->bytes[3] << 24);
            unsigned funct3 = (word >> 12) & 0x7;
            if ((word & 0x7f) == 0x73 && funct3 != 0 && funct3 != 4) {
                bool has_csr = false;
                for (uint8_t i = 0; i < out->n_operands; i++) {
                    if (out->operands[i].type == QEMU_PLUGIN_OP_SYSREG) {
                        has_csr = true;
                        break;
                    }
                }
                if (!has_csr &&
                    out->n_operands < QEMU_PLUGIN_INSN_DETAIL_MAX_OPS) {
                    unsigned csr = (word >> 20) & 0xfff;
                    const char *name = cap_riscv_csr_name(csr);
                    qemu_plugin_operand *op = &out->operands[out->n_operands];
                    op->type   = QEMU_PLUGIN_OP_SYSREG;
                    op->access = cap_riscv_csr_access(insn);
                    op->reg_id = (uint16_t)csr;
                    op->scale  = 1;
                    if (name) {
                        g_strlcpy(op->reg_name, name,
                                  QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ);
                    }
                    out->n_operands++;
                    n = out->n_operands;
                }
            }
        }
        /*
         * A mask destination is read as well as written, whatever the
         * runtime tail policy says (see cap_riscv_is_mask_dst).  Set
         * before the tied-vd correction below so the two cannot fight;
         * both only ever add the READ|WRITE pair.
         */
        if (cap_riscv_is_mask_dst(insn->mnemonic) && n >= 1
            && out->operands[0].type == QEMU_PLUGIN_OP_REG) {
            out->operands[0].access |= QEMU_PLUGIN_OP_ACC_READ
                                     | QEMU_PLUGIN_OP_ACC_WRITE;
        }
        /*
         * Capstone 6.0.0-Alpha7 RVV tied-operand bug workaround.
         *
         * Every RVV multiply-accumulate form takes `vd` as BOTH an
         * accumulator source and the destination — the tied-operand
         * constraint LLVM records on the instruction description.
         * Capstone honours the read but drops the write, so `vd` reports
         * READ-only and the accumulation chain has no producer at all:
         * a reduction loop's carried dependency vanishes and every
         * iteration looks independent.  `vmv.s.x` / `vfmv.s.f` have the
         * same shape (they write element 0 and preserve the rest) and the
         * same defect.
         *
         * The scoping is exact: every non-accumulating vector op
         * (`vadd.vv`, `vmul.vv`, `vxor.vv`, `vwsub.wv`, `vwredsum.vs`, …)
         * reports `WR{vd}` correctly.  Detect the family by the
         * accumulate infix that names it — Capstone spells these
         * v[f][w][n]m{acc,add,sac,sub}.{vv,vx,vf} — and restore the write.
         *
         * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7;
         * verify with `cstool -d riscv64 57a4a4b6` (bytes
         * `57 a4 a4 b6`, `vmacc.vv v8,v9,v10`) -- fixed, operands[0] must
         * show READ|WRITE.  Use a `cstool` built from
         * `subprojects/capstone`, not a system package, or run
         * `capstone_workaround_probe`; see docs/troubleshooting.rst.
         */
        if (cap_riscv_is_tied_vd(insn->mnemonic) && n >= 1
            && out->operands[0].type == QEMU_PLUGIN_OP_REG) {
            out->operands[0].access |= QEMU_PLUGIN_OP_ACC_READ
                                     | QEMU_PLUGIN_OP_ACC_WRITE;
        }
        /*
         * Capstone 6.0.0-Alpha7 scalar tied-destination bug workaround.
         *
         * The same defect as the RVV one above, outside the vector unit
         * and one step worse: Zacas `amocas.*` and CORE-V `cv.*nr`
         * arrive with their destination operand marked READ-only, so
         * the instruction reports NO destination at all -- `amocas.w
         * t0, ra, (t1)` says csWR{} where the architecture and LLVM
         * both say t0 is written.  A compare-and-swap that produces
         * nothing breaks the retry loop it exists to serialise, and an
         * accumulate that produces nothing breaks the chain it
         * accumulates along.
         *
         * See cap_riscv_is_tied_rd for what each family does with the
         * register and why the mnemonic sets are closed.  Restoring the
         * pair (not just the write) is correct for both: the read
         * Capstone reports is real -- the comparand for Zacas, the
         * accumulator for CORE-V.
         */
        if (cap_riscv_is_tied_rd(insn->mnemonic) && n >= 1
            && out->operands[0].type == QEMU_PLUGIN_OP_REG) {
            out->operands[0].access |= QEMU_PLUGIN_OP_ACC_READ
                                     | QEMU_PLUGIN_OP_ACC_WRITE;
        }
        /*
         * Capstone 6.0.0-Alpha7 RVV vector-configuration bug workaround.
         *
         * Every RVV instruction's behaviour is a function of the `vl` and
         * `vtype` CSRs that the preceding `vsetvli` wrote, so the
         * configuration edge is a real dependency and LLVM records it on
         * both ends.  Capstone reports it for the integer vector ops but
         * omits it from the floating-point ones, which name only `frm` —
         * so an FP vector kernel's ops float free of the `vsetvli` that
         * configured them.
         *
         * Supply the missing reads, and only the missing ones: an
         * instruction that already names `vl` keeps Capstone's answer.
         * Every RISC-V mnemonic beginning with `v` is a vector
         * instruction (the base ISA has none), and `vsetvl*` is excluded
         * because it *writes* the configuration rather than consuming it.
         *
         * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7;
         * verify with `cstool -d riscv64 5794a4b2` (bytes
         * `57 94 a4 b2`, `vfmacc.vv v8,v9,v10`) -- fixed, the implicit
         * read list must name vl and vtype alongside frm.  Use a `cstool`
         * built from `subprojects/capstone`, not a system package, or run
         * `capstone_workaround_probe`; see docs/troubleshooting.rst.
         */
        /*
         * RVV unconditionally-masked carry/merge v0 restore
         * (see cap_riscv_reads_v0_mask for the family and its closure).
         *
         * This one is NOT a Capstone-only defect and it is not verifiable
         * by cross-checking a second decoder: Capstone and LLVM both PRINT
         * `v0` in the operand string and NEITHER reports it as a read, so
         * isaxcheck sees two decoders agreeing and can never flag it.  It
         * is fixed from the ISA specification instead — RVV v1.0 §11.4
         * (vadc/vsbc), §11.5 (vmadc/vmsbc) and §11.15 (vmerge/vfmerge) all
         * define v0 as an operand the instruction reads, not as a mask
         * that may be disabled — and it carries its own regression check
         * (probe_rv_v0_carry_mask) for the same reason.
         *
         * Without it a carry-propagating multiword add chain
         * (vadc/vmadc alternating through v0) reports no dependency on
         * the carry at all: each limb looks independent of the one
         * below it, which is the whole serialisation the chain exists
         * to express.  The optional `, v0.t` mask is unaffected —
         * Capstone models that one correctly as a fourth operand, and
         * SVE governing predicates are likewise correct.
         *
         * Not revisitable on a Capstone bump: the printed alias is not
         * a defect, the metadata simply does not describe a mandatory
         * mask operand.  Removable only if Capstone starts reporting
         * v0 for this family, which the sweep would then show as a
         * duplicate read (harmless — the guard below is idempotent).
         */
        if (cap_riscv_reads_v0_mask(insn->mnemonic)) {
            bool has_v0 = false;
            for (uint8_t i = 0; i < out->n_regs_read; i++) {
                if (out->regs_read_id[i] == RISCV_REG_V0) {
                    has_v0 = true;
                    break;
                }
            }
            for (uint8_t i = 0; !has_v0 && i < n; i++) {
                if (out->operands[i].type == QEMU_PLUGIN_OP_REG
                    && out->operands[i].reg_id == RISCV_REG_V0
                    && (out->operands[i].access
                        & QEMU_PLUGIN_OP_ACC_READ)) {
                    has_v0 = true;
                }
            }
            if (!has_v0
                && out->n_regs_read < QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS) {
                cap_copy_reg_name(out->regs_read[out->n_regs_read],
                                  QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                                  handle, RISCV_REG_V0, cap_arch);
                out->regs_read_id[out->n_regs_read] = RISCV_REG_V0;
                out->n_regs_read++;
            }
        }
        /*
         * Scalar FP with a dynamic rounding mode reads frm (see
         * cap_riscv_reads_dynamic_frm).  Architectural, from Sail, not
         * a Capstone-version defect: the rm field is in the encoding
         * and no disassembler reports the fcsr read it implies.  Added
         * only when absent, so a decoder that starts reporting it
         * cannot be double-counted.
         */
        if (cap_riscv_reads_dynamic_frm(insn)) {
            bool has_frm = false;
            for (uint8_t i = 0; i < out->n_regs_read; i++) {
                if (out->regs_read_id[i] == RISCV_REG_FRM) {
                    has_frm = true;
                    break;
                }
            }
            if (!has_frm
                && out->n_regs_read < QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS) {
                cap_copy_reg_name(out->regs_read[out->n_regs_read],
                                  QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                                  handle, RISCV_REG_FRM, cap_arch);
                out->regs_read_id[out->n_regs_read] = RISCV_REG_FRM;
                out->n_regs_read++;
            }
        }
        /*
         * ... and only for instructions that are actually in the vector
         * unit.  `insn->mnemonic[0] == 'v'` is the family the defect
         * lives in, but it is not the family boundary: XVentanaCondOps
         * spells two SCALAR conditional moves `vt.maskc` / `vt.maskcn`,
         * and attaching the RVV configuration reads to those invents a
         * dependency on a `vsetvli` for an instruction whose result does
         * not depend on vl or vtype at all.  cap_riscv_is_vector_encoding
         * settles it from the major opcode instead of from a name.
         */
        if (insn->mnemonic[0] == 'v'
            && !g_str_has_prefix(insn->mnemonic, "vsetvl")
            && cap_riscv_is_vector_encoding(insn)) {
            bool has_vl = false;
            for (uint8_t i = 0; i < out->n_regs_read; i++) {
                if (out->regs_read_id[i] == RISCV_REG_VL
                    || out->regs_read_id[i] == RISCV_REG_VTYPE) {
                    has_vl = true;
                    break;
                }
            }
            if (!has_vl) {
                static const uint16_t vcfg[] = { RISCV_REG_VL,
                                                 RISCV_REG_VTYPE };
                for (size_t k = 0; k < ARRAY_SIZE(vcfg); k++) {
                    if (out->n_regs_read
                        >= QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS) {
                        break;
                    }
                    cap_copy_reg_name(out->regs_read[out->n_regs_read],
                                      QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                                      handle, vcfg[k], cap_arch);
                    out->regs_read_id[out->n_regs_read] = vcfg[k];
                    out->n_regs_read++;
                }
            }
        }
    } else if (cap_arch == CS_ARCH_MIPS) {
        n = MIN(detail->mips.op_count, QEMU_PLUGIN_INSN_DETAIL_MAX_OPS);
        out->n_operands = n;
        /* MIPS MSA encodes lane width in the mnemonic dot-form
         * suffix (addv.b / mulv.w / etc.); shared across operands. */
        uint8_t insn_lane_bytes = cap_lane_bytes_from_mnemonic(insn->mnemonic);
        for (uint8_t i = 0; i < n; i++) {
            const cs_mips_op *cop = &detail->mips.operands[i];
            qemu_plugin_operand *op = &out->operands[i];
            /* See the RISC-V branch: forward Capstone's per-operand
             * access (CS_AC_* == QEMU_PLUGIN_OP_ACC_*) so memory
             * operands gate the HAS_ADDR address-dependency block
             * instead of collapsing to the all-to-all fallback. */
            op->access = cop->access;
            op->size = 0;
            op->lane_bytes = insn_lane_bytes;
            op->scale = 1;
            op->shift_type = 0;
            op->shift_amount = 0;
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
            /* Capstone exposes no operand size for MIPS, but MSA
             * vector registers (MIPS_REG_W0..W31) are a fixed
             * 128-bit width and an MSA load/store moves the whole
             * 16-byte vector; the per-element width is the
             * .b/.h/.w/.d suffix already in insn_lane_bytes.  Derive
             * op->size so the lane-mask refiner computes the exact
             * lane count (lanes = 16 / lane_bytes) instead of
             * skipping on size==0.  GPR operands of MSA insns
             * (insert/copy/ctcmsa) keep size 0 — they are scalar. */
            if (op->type == QEMU_PLUGIN_OP_REG
                && op->reg_id >= MIPS_REG_W0
                && op->reg_id <= MIPS_REG_W31) {
                op->size = 16;
            } else if (op->type == QEMU_PLUGIN_OP_MEM
                       && insn_lane_bytes) {
                op->size = 16;
            }
        }
        /*
         * Capstone 6.0.0 MIPS access-flag bug workaround.
         *
         * Scalar aligned MIPS loads/stores get a correct
         * CS_AC_READ/WRITE on their MEM operand, but two families
         * report the MEM operand with access == 0:
         *   - MSA vector LD/ST (LD.{B,H,W,D} / ST.{B,H,W,D});
         *   - unaligned scalar LWL/LWR/LDL/LDR/SWL/SWR/SDL/SDR.
         * Uncorrected, the operand walker never gates the HAS_ADDR
         * address-dependency block, so the load is modelled as a
         * bare base-register move (no ld slot / laddr group) — the
         * dropped-load-latency footgun the scalar access forwarding
         * fixed for the aligned forms.  MIPS has no address-only
         * MEM-operand form (no LEA equivalent — addresses are
         * computed with ADDIU), so a 0-access MIPS MEM operand is
         * always this defect and the direction can be inferred from
         * the data register operand: a load writes it (MEM is READ),
         * a store reads it (MEM is WRITTEN).
         *
         * Revisit / remove when Capstone is bumped past 6.0.0; verify
         * with `cstool -d mips64el 20200078` (bytes `20 20 00 78`,
         * `ld.b $w0,0($a0)`, MSA) and `cstool -d mips64el 03008888`
         * (bytes `03 00 88 88`, `lwl $t0,3($a0)`, unaligned scalar) --
         * fixed, the MEM operand of both must show READ (loads) once
         * corrected.  Use a `cstool` built from `subprojects/capstone`
         * (capstone.wrap's pinned revision), not a system package, or
         * run `capstone_workaround_probe`
         * (`cap_fill_mips_operands (MSA access==0)` /
         * `(unaligned access==0)` cases); see docs/troubleshooting.rst.
         */
        for (uint8_t i = 0; i < n; i++) {
            qemu_plugin_operand *mem = &out->operands[i];
            if (mem->type != QEMU_PLUGIN_OP_MEM || mem->access != 0) {
                continue;
            }
            for (uint8_t j = 0; j < n; j++) {
                const qemu_plugin_operand *reg = &out->operands[j];
                if (reg->type != QEMU_PLUGIN_OP_REG
                    || reg->access == 0) {
                    continue;
                }
                mem->access = (reg->access & QEMU_PLUGIN_OP_ACC_WRITE)
                    ? QEMU_PLUGIN_OP_ACC_READ
                    : QEMU_PLUGIN_OP_ACC_WRITE;
                break;
            }
        }
        /*
         * Capstone 6.0.0 MIPS store-conditional bug workaround.
         *
         * MIPS store-conditional (sc / scd / sce / scwp) atomically
         * stores the source register and overwrites it with a
         * success/failure bit (1 = paired ll's monitor still set,
         * 0 = lost the monitor).  Capstone reports the $rt operand
         * as CS_AC_READ only — it sees the store-from but misses
         * the success-bit write-back.  Without WRITE access the
         * destination snap chain (regdata_reconstruction) sees stale
         * pre-SC values for $rt on every successor BB.
         *
         * Promote $rt's access to READ|WRITE for the SC family.
         * The first register operand is the data/result register.
         *
         * Revisit / remove when Capstone is bumped past 6.0.0; verify
         * with `cstool -d mips64el 000088e0` (bytes `00 00 88 e0`,
         * `sc $t0,0($a0)`) -- fixed, $t0 (operands[0]) must show
         * READ|WRITE instead of READ-only.  Use a `cstool` built from
         * `subprojects/capstone` (capstone.wrap's pinned revision),
         * not a system package, or run `capstone_workaround_probe`
         * (`cap_fill_mips_operands (SC success-bit write)` case); see
         * docs/troubleshooting.rst.
         */
        if (insn->id == MIPS_INS_SC || insn->id == MIPS_INS_SCD
            || insn->id == MIPS_INS_SCE || insn->id == MIPS_INS_SCWP) {
            for (uint8_t i = 0; i < n; i++) {
                qemu_plugin_operand *op = &out->operands[i];
                if (op->type != QEMU_PLUGIN_OP_REG) {
                    continue;
                }
                op->access = QEMU_PLUGIN_OP_ACC_READ
                           | QEMU_PLUGIN_OP_ACC_WRITE;
                break;
            }
        }
        /*
         * Capstone 6.0.0 MIPS unaligned-load merge bug workaround.
         *
         * LWL/LWR (and the 64-bit LDL/LDR) merge selected bytes of the
         * loaded word into the destination register, preserving the
         * rest — architecturally the old $rt value is an INPUT.
         * Capstone reports $rt as CS_AC_WRITE only, so the partial
         * write's dependency on the previous register value is lost
         * and consumers see the pair as a full overwrite.  Promote
         * $rt to READ|WRITE.  The stores of the family (SWL/SWR/...)
         * already read $rt and need no correction.
         *
         * Revisit / remove when Capstone is bumped past 6.0.0; verify
         * with `cstool -d mips64el 03008888` (bytes `03 00 88 88`,
         * `lwl $t0,3($a0)`) -- fixed, $t0 (operands[0]) must show
         * READ|WRITE instead of WRITE-only.  Use a `cstool` built
         * from `subprojects/capstone` (capstone.wrap's pinned
         * revision), not a system package, or run
         * `capstone_workaround_probe`
         * (`cap_fill_mips_operands (LWL/LWR partial write)` case);
         * see docs/troubleshooting.rst.
         */
        if (insn->id == MIPS_INS_LWL || insn->id == MIPS_INS_LWR
            || insn->id == MIPS_INS_LDL || insn->id == MIPS_INS_LDR) {
            for (uint8_t i = 0; i < n; i++) {
                qemu_plugin_operand *op = &out->operands[i];
                if (op->type != QEMU_PLUGIN_OP_REG) {
                    continue;
                }
                op->access = QEMU_PLUGIN_OP_ACC_READ
                           | QEMU_PLUGIN_OP_ACC_WRITE;
                break;
            }
        }
        /*
         * Capstone 6.0.0 MIPS tied-destination bug workaround
         * (see cap_mips_is_tied_dst for the family).
         *
         * `INS rt, rs, pos, size` copies a bit field out of $rs into $rt
         * and PRESERVES every bit of $rt outside that field, so $rt is a
         * genuine source as well as the destination.  Capstone reports it
         * WRITE-only, which turns a read-modify-write into a full
         * overwrite: two INS into the same register look WAW when the
         * second really carries a RAW edge from the first.
         *
         * Revisit / remove when Capstone is bumped past 6.0.0; verify with
         * `cstool -d mips32r2 0459287d` (bytes `04 59 28 7d`,
         * `ins $t0,$t1,4,8`) -- fixed, $t0 (operands[0]) must show
         * READ|WRITE instead of WRITE-only.  Use a `cstool` built from
         * `subprojects/capstone`, not a system package, or run
         * `capstone_workaround_probe`; see docs/troubleshooting.rst.
         */
        if (cap_mips_is_tied_dst(insn->mnemonic)) {
            for (uint8_t i = 0; i < n; i++) {
                qemu_plugin_operand *op = &out->operands[i];
                if (op->type != QEMU_PLUGIN_OP_REG) {
                    continue;
                }
                op->access |= QEMU_PLUGIN_OP_ACC_READ
                            | QEMU_PLUGIN_OP_ACC_WRITE;
                break;
            }
        }
        /*
         * The accumulate half of a multiply-accumulate that names its
         * accumulator (see cap_mips_is_acc_rmw).  Structural on both
         * sides: the mnemonic must be in the family AND the operand must
         * be an accumulator register, so `madd.s` cannot match.
         */
        if (cap_mips_is_acc_rmw(insn->mnemonic)) {
            for (uint8_t i = 0; i < n; i++) {
                qemu_plugin_operand *op = &out->operands[i];
                if (op->type != QEMU_PLUGIN_OP_REG ||
                    !cap_mips_is_acc_reg(op->reg_id)) {
                    continue;
                }
                op->access |= QEMU_PLUGIN_OP_ACC_READ
                            | QEMU_PLUGIN_OP_ACC_WRITE;
                break;
            }
        }
        /*
         * DSPControl on the four instructions that exist to move it.
         *
         * Capstone's DSP table names DSPControl on most of the ASE --
         * ADDQ_S reports the outflag write, EXTP the pos read, PICK the
         * condition read -- and omits it from the four forms whose whole
         * purpose is DSPControl: RDDSP reads it into a GPR, WRDSP writes
         * it from one, BPOSGE32 branches on its pos field, and MTHLIP
         * reads the pos it then updates.  The absence is an
         * inconsistency in that table, not a statement that these do not
         * touch the register.
         *
         * DSPControl has no whole-register id in Capstone's enum, only
         * per-field ones; they all map to the one generic REG_DSPCTRL,
         * so the field named here is chosen to describe the access
         * (DSPPos for the pos readers, DSPCCond standing for the whole
         * word on the two register moves).
         */
        if (insn->id == MIPS_INS_RDDSP) {
            cap_mips_add_implicit(out, handle, MIPS_REG_DSPCCOND, false);
        } else if (insn->id == MIPS_INS_WRDSP) {
            cap_mips_add_implicit(out, handle, MIPS_REG_DSPCCOND, true);
        } else if (insn->id == MIPS_INS_BPOSGE32 ||
                   insn->id == MIPS_INS_MTHLIP) {
            cap_mips_add_implicit(out, handle, MIPS_REG_DSPPOS, false);
        }
        /*
         * `ctcmsa $1, $6` writes the MSA control register named by its
         * first operand; Capstone reports that operand as a READ, which
         * both loses the definition and fabricates a dependency on
         * whatever last wrote it.  Its sibling `cfcmsa $6, $1` reports
         * the read correctly.
         */
        if (insn->id == MIPS_INS_CTCMSA && n >= 1 &&
            out->operands[0].type == QEMU_PLUGIN_OP_REG) {
            out->operands[0].access = QEMU_PLUGIN_OP_ACC_WRITE;
        }
        /*
         * Capstone 6.0.0 MIPS register-indexed load/store bug workaround.
         *
         * The indexed FP forms (LWXC1 / LDXC1 / LUXC1 / SWXC1 / SDXC1 /
         * SUXC1) and the DSP indexed integer loads (LWX / LHX / LBUX)
         * address memory as `index(base)` — two registers, no
         * displacement.  Capstone models the pair as two bare REG operands
         * and emits NO MEM operand at all, so the operand walker never
         * gates the HAS_ADDR address-dependency block: the effective
         * address still arrives from QEMU's memory callback and is
         * correct, but the address-generation chain feeding it
         * (`lw $a0` -> `addiu $a0` -> `lwxc1`) does not exist in the
         * trace.  On the FP forms the two address registers additionally
         * carry access == 0, so they are not even read.
         *
         * Fold the pair into the MEM operand it describes: base from the
         * second register operand, index from the first, direction
         * inferred from the data register exactly as the MSA/unaligned
         * correction above does (a load writes it, a store reads it).
         * The now-redundant second register operand is retired.
         *
         * Revisit / remove when Capstone is bumped past 6.0.0; verify with
         * `cstool -d mips32r2 8000854c` (bytes `80 00 85 4c`,
         * `lwxc1 $f2,$a1($a0)`) -- fixed, the instruction must expose a
         * MEM operand with base $a0 and index $a1.  Use a `cstool` built
         * from `subprojects/capstone`, not a system package, or run
         * `capstone_workaround_probe`; see docs/troubleshooting.rst.
         */
        if ((insn->id == MIPS_INS_LWXC1 || insn->id == MIPS_INS_LDXC1
             || insn->id == MIPS_INS_LUXC1 || insn->id == MIPS_INS_SWXC1
             || insn->id == MIPS_INS_SDXC1 || insn->id == MIPS_INS_SUXC1
             || insn->id == MIPS_INS_LWX || insn->id == MIPS_INS_LHX
             || insn->id == MIPS_INS_LBUX)
            && n == 3
            && out->operands[0].type == QEMU_PLUGIN_OP_REG
            && out->operands[1].type == QEMU_PLUGIN_OP_REG
            && out->operands[2].type == QEMU_PLUGIN_OP_REG) {
            uint16_t index_id = out->operands[1].reg_id;
            uint16_t base_id  = out->operands[2].reg_id;
            char index_name[QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ];
            char base_name[QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ];
            memcpy(index_name, out->operands[1].reg_name, sizeof(index_name));
            memcpy(base_name, out->operands[2].reg_name, sizeof(base_name));

            qemu_plugin_operand *mem = &out->operands[1];
            mem->type = QEMU_PLUGIN_OP_MEM;
            mem->access = (out->operands[0].access & QEMU_PLUGIN_OP_ACC_WRITE)
                ? QEMU_PLUGIN_OP_ACC_READ
                : QEMU_PLUGIN_OP_ACC_WRITE;
            mem->reg_id = base_id;
            memcpy(mem->reg_name, base_name, sizeof(base_name));
            mem->index_id = index_id;
            memcpy(mem->index_name, index_name, sizeof(index_name));
            mem->imm = 0;

            /* The second address register now lives in the MEM operand's
             * index field, so the operand it came from is retired rather
             * than left behind as an unmodelled slot. */
            memset(&out->operands[2], 0, sizeof(out->operands[2]));
            out->n_operands = 2;
            n = 2;
        }
        /*
         * Capstone 6.0.0 MIPS FP-control-register bank bug workaround.
         *
         * `CTC1 rt, fs` / `CFC1 rt, fs` move to and from a *floating-point*
         * control register (FCR0 / FCR25 / FCR26 / FCR28 / FCR31).
         * Capstone names the low-numbered ones as COP0 registers instead
         * — `ctc1 $zero, $3` reports MIPS_REG_COP03 where it should report
         * MIPS_REG_FCR3 — which lands the dependency in the tracer's
         * REG_SYS bucket (system coprocessor) rather than REG_FCSR (FP
         * control/status).  The high-numbered forms are named correctly,
         * so `ctc1 $t0, $31` already reports FCR31; only the aliasing
         * range is wrong.  Remap the bank while keeping the index.
         *
         * Revisit / remove when Capstone is bumped past 6.0.0; verify with
         * `cstool -d mips32r2 0018c044` (bytes `00 18 c0 44`,
         * `ctc1 $zero,$3`) -- fixed, the control operand must name $f3's
         * control register (FCR3), not COP0 register 3.  Use a `cstool`
         * built from `subprojects/capstone`, not a system package, or run
         * `capstone_workaround_probe`; see docs/troubleshooting.rst.
         */
        if (!strcmp(insn->mnemonic, "ctc1") || !strcmp(insn->mnemonic, "cfc1")) {
            for (uint8_t i = 0; i < n; i++) {
                qemu_plugin_operand *op = &out->operands[i];
                if (op->type != QEMU_PLUGIN_OP_REG
                    || op->reg_id < MIPS_REG_COP00
                    || op->reg_id > MIPS_REG_COP09) {
                    continue;
                }
                op->reg_id = MIPS_REG_FCR0 + (op->reg_id - MIPS_REG_COP00);
                cap_copy_reg_name(op->reg_name,
                                  QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                                  handle, op->reg_id, cap_arch);
            }
        }
        /*
         * Capstone 6.0.0 MIPS floating-point condition-code bug
         * workaround.
         *
         * The FP compare/branch pair is the only dependency edge between
         * a `c.<cond>.<fmt>` and the `bc1t`/`bc1f` that consumes it.  In
         * the forms that name the condition code explicitly
         * (`c.eq.s $fcc1, $f0, $f1`, `bc1t $fcc1, label`) Capstone models
         * the edge correctly.  In the far more common implicit-$fcc0
         * forms it models neither end: the compare reports no destination
         * and the branch reports no source, so EVERY MIPS
         * floating-point conditional branch is dependency-free — the
         * branch does not depend on the compare that decides it.  The
         * integer compare/branch pair is unaffected (it carries a real
         * GPR edge), which is why no self-consistency check has ever seen
         * this.
         *
         * The branch forms additionally carry a phantom implicit WRITE of
         * $at: Capstone's implicit list for BC1T/BC1F names register 1,
         * and a conditional branch writes no GPR at all.  Left in, it
         * fabricates a WAW/RAW hazard on $at against the surrounding code.
         *
         * Supply the missing $fcc0 read/write and drop the phantom.  Both
         * corrections are conditional on Capstone having modelled nothing,
         * so a fixed Capstone's own answer wins.
         *
         * Revisit / remove when Capstone is bumped past 6.0.0; verify with
         * `cstool -d mips32r2 32000146` (bytes `32 00 01 46`,
         * `c.eq.s $f0,$f1`) -- fixed, $fcc0 must appear as a written
         * register -- and `cstool -d mips32r2 03000145` (bytes
         * `03 00 01 45`, `bc1t`) -- fixed, $fcc0 must appear as a read and
         * $at must NOT appear as a write.  Use a `cstool` built from
         * `subprojects/capstone`, not a system package, or run
         * `capstone_workaround_probe`; see docs/troubleshooting.rst.
         */
        {
            bool is_fp_cmp = g_str_has_prefix(insn->mnemonic, "c.");
            bool is_fp_br = insn->id == MIPS_INS_BC1T
                         || insn->id == MIPS_INS_BC1F
                         || insn->id == MIPS_INS_BC1TL
                         || insn->id == MIPS_INS_BC1FL;
            bool names_cc = false;
            for (uint8_t i = 0; i < n; i++) {
                if (out->operands[i].type == QEMU_PLUGIN_OP_REG
                    && out->operands[i].reg_id >= MIPS_REG_FCC0
                    && out->operands[i].reg_id <= MIPS_REG_FCC7) {
                    names_cc = true;
                    break;
                }
            }
            if (is_fp_br) {
                /* Drop the phantom $at write. */
                uint8_t keep = 0;
                for (uint8_t i = 0; i < out->n_regs_write; i++) {
                    if (out->regs_write_id[i] == MIPS_REG_AT) {
                        continue;
                    }
                    if (keep != i) {
                        memcpy(out->regs_write[keep], out->regs_write[i],
                               QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ);
                        out->regs_write_id[keep] = out->regs_write_id[i];
                    }
                    keep++;
                }
                out->n_regs_write = keep;
            }
            if ((is_fp_cmp || is_fp_br) && !names_cc) {
                uint16_t *ids = is_fp_cmp ? out->regs_write_id
                                          : out->regs_read_id;
                uint8_t *cnt = is_fp_cmp ? &out->n_regs_write
                                         : &out->n_regs_read;
                char (*names)[QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ] =
                    is_fp_cmp ? out->regs_write : out->regs_read;
                if (*cnt < QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS) {
                    cap_copy_reg_name(names[*cnt],
                                      QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                                      handle, MIPS_REG_FCC0, cap_arch);
                    ids[*cnt] = MIPS_REG_FCC0;
                    (*cnt)++;
                }
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
    out->insn_size = insn->size;

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
    /*
     * Thread-local handle cache.  cs_open()/cs_malloc()/cs_close() per call
     * dominates a bulk decode (the static-template sweep linear-decodes an
     * entire executable region), so reuse the handle across calls with the
     * same arch/mode — Capstone supports repeated cs_disasm_iter() on one
     * handle.  Thread-local because the decode runs on any vCPU thread and a
     * Capstone handle is not safe for concurrent iteration.  The handle is
     * never explicitly freed (one per thread per arch/mode, released at
     * thread/process exit); a mode change closes the stale one first.
     */
    static __thread csh th_handle;
    static __thread cs_insn *th_insn;
    static __thread int th_arch = -1;
    static __thread unsigned int th_mode;
    static __thread bool th_valid;

    csh handle;
    cs_insn *insn;

    memset(out, 0, sizeof(*out));

    if (th_valid && th_arch == cap_arch && th_mode == cap_mode) {
        handle = th_handle;
        insn = th_insn;
    } else {
        if (th_valid) {
            cs_free(th_insn, 1);
            cs_close(&th_handle);
            th_valid = false;
        }
        if (cs_open(cap_arch, cap_mode, &handle) != CS_ERR_OK) {
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
        th_handle = handle;
        th_insn   = insn;
        th_arch   = cap_arch;
        th_mode   = cap_mode;
        th_valid  = true;
    }

    const uint8_t *code = data;
    size_t sz = data_size;
    uint64_t addr = pc;

    if (insn->detail) {
        memset(insn->detail, 0, sizeof(*insn->detail));
    }

    if (!cs_disasm_iter(handle, &code, &sz, &addr, insn)) {
        return false;   /* handle stays cached for the next call */
    }

    /* Copy mnemonic and operand string */
    g_strlcpy(out->mnemonic, insn->mnemonic,
              QEMU_PLUGIN_INSN_DETAIL_MNEMSZ);
    g_strlcpy(out->op_str, insn->op_str,
              QEMU_PLUGIN_INSN_DETAIL_OPSTRSZ);
    out->insn_id = insn->id;
    out->insn_size = insn->size;

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

    /* handle / insn stay cached in the thread-local slots for reuse */
    return true;
}
