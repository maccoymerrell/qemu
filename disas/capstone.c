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
static bool cap_x86_is_extract_store(const char *mnem);
static bool cap_x86_is_move_family(const char *mnem);
static bool cap_x86_is_test(const char *mnem);

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
    /* Capstone-6.0.0 bug: the register-source form of TEST (opcodes
     * 84/85, `test r/m, r`) reports EVERY operand with empty access, so
     * its MEM operand's READ is lost and it mints no load slot (the
     * offline lint then flags the observed load as impossible).  TEST
     * only reads its operands — it writes flags, never memory or a
     * register — so force READ on any empty-access operand below.  The
     * immediate forms (F6/F7) already report the MEM operand READ and
     * are left untouched (their access is non-zero). */
    bool test_read = cap_x86_is_test(insn->mnemonic);

    for (uint8_t i = 0; i < n; i++) {
        const cs_x86_op *cop = &x86->operands[i];
        qemu_plugin_operand *op = &out->operands[i];

        op->access = cop->access;
        if (test_read && op->access == 0) {
            op->access = QEMU_PLUGIN_OP_ACC_READ;
        }
        op->size = cop->size;
        op->lane_bytes = insn_lane_bytes;
        op->scale = 1;
        op->shift_type = 0;
        op->shift_amount = 0;

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
            op->scale = (uint8_t)cop->mem.scale;
            /* Capstone-6.0.0-Alpha7 bug: the r/m destination of a
             * store-form extract is the write target, not a read. */
            if (extract_store || move_store) {
                op->access = QEMU_PLUGIN_OP_ACC_WRITE;
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
 * Revisit / remove when Capstone is bumped past Alpha7.
 */
static bool cap_x86_is_extract_store(const char *mnem)
{
    if (!mnem || !mnem[0]) return false;
    if (mnem[0] == 'v') mnem++;            /* VEX/EVEX prefix */
    return g_str_has_prefix(mnem, "pextr") ||
           g_str_equal(mnem, "extractps");
}

/* The scalar integer TEST (`test r/m, r` / `test r/m, imm`).  Its
 * register-source encodings lose all Capstone access flags (see the
 * test_read workaround in cap_fill_x86_operands); TEST never writes an
 * operand, so any empty-access operand is a lost READ. */
static bool cap_x86_is_test(const char *mnem)
{
    /* AT&T syntax (QEMU's) size-suffixes the mnemonic: testb/testw/
     * testl/testq.  Prefix-match — no other x86 mnemonic starts with
     * "test" (ktest/vptest begin with k/v). */
    return mnem && g_str_has_prefix(mnem, "test");
}

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
 * dropped-store / wrong-latency footgun.  Revisit when Capstone is
 * bumped past 6.0.0.
 */
static bool cap_x86_is_move_family(const char *mnem)
{
    if (!mnem || !mnem[0]) return false;
    if (mnem[0] == 'v') mnem++;            /* VEX/EVEX prefix */
    if (!g_str_has_prefix(mnem, "mov")) return false;
    /* Sign/zero-extending and string moves never take a MEM
     * operand 0 (their destination is a register); excluding them
     * keeps the rule "MEM op0 of a move ⇒ store target" exact. */
    return !g_str_has_prefix(mnem, "movsx") &&
           !g_str_has_prefix(mnem, "movzx") &&
           !g_str_has_prefix(mnem, "movsxd") &&
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
     * Capstone-6.0.0 LSL/LSR/ASR/ROR-#imm alias bug workaround
     * (see cap_aarch64_is_buggy_shift_imm_alias).  When the shape
     * matches, synthesise the dropped IMM from operands[1].shift.value
     * so plugins see HAS_IMM and the correct shift count.
     */
    if (out->n_operands == 2 &&
        out->n_operands < QEMU_PLUGIN_INSN_DETAIL_MAX_OPS &&
        cap_aarch64_is_buggy_shift_imm_alias(insn->mnemonic) &&
        a64->op_count >= 2 &&
        a64->operands[1].shift.type != AARCH64_SFT_INVALID) {
        uint8_t k = out->n_operands;
        qemu_plugin_operand *op = &out->operands[k];
        memset(op, 0, sizeof(*op));
        op->type = QEMU_PLUGIN_OP_IMM;
        op->scale = 1;
        op->imm = (int64_t)a64->operands[1].shift.value;
        out->n_operands = k + 1;
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
         * a store reads it (MEM is WRITTEN).  Revisit when Capstone
         * is bumped past 6.0.0.
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
         * already read $rt and need no correction.  Revisit when
         * Capstone is bumped past 6.0.0.
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
