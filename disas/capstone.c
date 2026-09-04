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
/*
 * The Capstone mode a disassemble_info really asks for: the target's
 * declared cap_mode plus the endianness bit.  Named because a second
 * handle opened for the same instruction (see
 * cap_aarch64_restore_alias_zero_reg) has to be opened in exactly the
 * mode the first one was, and an endianness that is added in one place
 * and forgotten in the other decodes different bytes.
 */
static cs_mode cap_effective_mode(const disassemble_info *info)
{
    return info->cap_mode + (info->endian == BFD_ENDIAN_BIG
                             ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN);
}

static cs_err cap_disas_start(disassemble_info *info, csh *handle)
{
    cs_mode cap_mode = cap_effective_mode(info);
    cs_err err;

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
static bool cap_aarch64_is_va_cache_maint_sysop(const cs_arm64 *a64, uint8_t n);
static bool cap_x86_is_extract_store(const char *mnem);
static bool cap_x86_is_move_family(const char *mnem);
static bool cap_x86_is_test(const char *mnem);
static uint8_t cap_x86_string_mem_access(const char *mnem, unsigned base_reg);
static bool cap_x86_is_string_op(const char *mnem);
static bool cap_x86_is_scalar_round(const char *mnem);
static bool cap_x86_is_shadow_stack_store(const char *mnem);
static bool cap_x86_mem_is_never_accessed(const char *mnem);
static bool cap_x86_is_push(const char *mnem);
static bool cap_x86_is_erased_mem_load(const char *mnem);
static bool cap_x86_is_lost_mem_store(const char *mnem);
static bool cap_x86_is_gather(const char *mnem);
static uint8_t cap_x86_x87_mem_access(const char *mnem);
static bool cap_x86_is_mask_arith_dest_last(const char *mnem);
static bool cap_x86_is_ktest(const char *mnem);
static bool cap_x86_is_ssp_read(const char *mnem);
static bool cap_x86_is_ssp_dest(const char *mnem);
static bool cap_x86_is_x87_tag_only(const char *mnem);
static const char *cap_x86_mnem_stem(const char *mnem);
static bool cap_x86_is_cmov(const char *mnem);

/*
 * The EVEX prefix's own view of an instruction, decoded from the
 * encoding rather than from Capstone's operand table -- see
 * cap_x86_evex_classify for why the table cannot be trusted here.
 */
typedef struct {
    bool is_evex;    /* the encoding really carries an EVEX prefix     */
    bool merging;    /* EVEX.aaa != 0 and EVEX.z == 0: merge-masking   */
    int  mask_idx;   /* operand index of the {kN} writemask, or -1     */
    int  dest_idx;   /* AT&T dest-last with the writemask excluded, -1 */
} cap_x86_evex;

/*
 * Capstone-6.0.0-Alpha7 bug: with more than one segment-override prefix
 * on the same instruction, cs_x86_op.mem.segment reports the FIRST one.
 * The hardware, and QEMU with it, takes the LAST: every override byte
 * assigns s->override unconditionally in the prefix loop
 * (target/i386/tcg/decode-new.c.inc, `case 0x64: s->override = R_FS`),
 * so `65 64 ...` reads FS while Capstone says GS.  A dependency model
 * built on the first prefix names a segment base the guest never reads
 * and misses the one it does.
 *
 * The bytes decide it, being the only place the ORDER of the prefixes
 * survives -- Capstone's own prefix[] array keeps one byte per group.
 * Returns the Capstone register id of the last override in the leading
 * legacy-prefix run, or 0 when the instruction carries none.
 */
static unsigned cap_x86_last_segment_override(const cs_insn *insn)
{
    unsigned last = 0;

    for (uint16_t k = 0; k < insn->size; k++) {
        switch (insn->bytes[k]) {
        case 0x26: last = X86_REG_ES; break;
        case 0x2e: last = X86_REG_CS; break;
        case 0x36: last = X86_REG_SS; break;
        case 0x3e: last = X86_REG_DS; break;
        case 0x64: last = X86_REG_FS; break;
        case 0x65: last = X86_REG_GS; break;
        case 0x66: case 0x67: case 0xf0: case 0xf2: case 0xf3:
            break;              /* other legacy prefixes, keep scanning */
        default:
            return last;        /* REX / opcode: the prefix run ended */
        }
    }
    return last;
}

/*
 * Is this an x87 escape, opcode byte D8..DF?  Taken from the bytes past
 * the legacy prefixes and the REX byte, so it does not depend on the
 * mnemonic spelling of any one form.
 */
static bool cap_x86_is_x87_escape(const cs_insn *insn)
{
    uint16_t k = 0;

    while (k < insn->size) {
        uint8_t b = insn->bytes[k];
        if (b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e ||
            b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67 ||
            b == 0xf0 || b == 0xf2 || b == 0xf3 ||
            (b >= 0x40 && b <= 0x4f)) {
            k++;
        } else {
            return b >= 0xd8 && b <= 0xdf;
        }
    }
    return false;
}

static void cap_x86_evex_classify(const cs_insn *insn, uint8_t n,
                                  cap_x86_evex *e);
static bool cap_x86_reg_is_vector(unsigned int reg);
static bool cap_x86_evex_clears_mask(const char *mnem);
static void cap_x86_drop_implicit(qemu_plugin_insn_info *out,
                                  unsigned int reg, bool is_write);
static bool cap_x86_is_sign_extend_to_d(const char *mnem);
static void cap_x86_add_implicit(qemu_plugin_insn_info *out, csh handle,
                                 unsigned int reg, bool is_write);
static void cap_x86_eflags_from_bitmask(csh handle, const cs_insn *insn,
                                       qemu_plugin_insn_info *out);
static void cap_x86_zero_count_shift_contract(const cs_insn *insn,
                                             qemu_plugin_insn_info *out);
static void cap_x86_add_sysregs(const cs_insn *insn,
                                qemu_plugin_insn_info *out);
/*
 * -------------------------------------------------------------------------
 * The x87 escape space: the implicit dataflow Capstone does not publish.
 *
 * Capstone-6.0.0-Alpha7 names the ARCHITECTURALLY EXPLICIT st(i) operand of
 * an x87 instruction and almost nothing else.  `fadd %st(1)` comes back
 * reading st1 and writing NOTHING -- no ST(0) read, no ST(0) write, no
 * status word -- for an instruction whose entire effect is
 * ST(0) <- ST(0) + ST(1).  `fld1` reports no destination at all.  The whole
 * D9 E0..FF transcendental and constant group reports an empty operand list.
 * A consumer reading those sets sees an FP program with no dependency chain
 * through the x87 stack whatsoever.
 *
 * GROUND TRUTH IS QEMU'S OWN TRANSLATOR, and this table is keyed the way
 * QEMU keys it.  gen_x87() (target/i386/tcg/translate.c) computes
 *
 *      mod = (modrm >> 6) & 3;
 *      rm  = modrm & 7;
 *      op  = ((b & 7) << 3) | ((modrm >> 3) & 7);
 *
 * and dispatches on exactly (mod == 3, op, rm).  cap_x86_x87_effects()
 * recomputes those three from the instruction bytes and mirrors the same
 * switch, so each row below is the operand set of the helper sequence QEMU
 * emits for that case rather than a transcription of a manual:
 *
 *   gen_helper_*_ST0 / fp_arith_ST0_FT0   touches ST(0)
 *   gen_helper_fp_arith_STN_ST0           reads ST(0), writes the named st(i)
 *   gen_helper_fpush / fpop               moves env->fpstt -- the TOP field
 *                                         of the status word -- so the status
 *                                         word is read AND written
 *   gen_helper_fcom_/fucom_ST0_FT0        writes the condition codes
 *
 * The status word is where TOP lives, so a push or a pop is a genuine
 * read-modify-write of it and a later `fnstsw` must wait on it -- and, for
 * the same reason, EVERY form that NAMES a slot of the stack reads it,
 * because TOP is what selects the slot.  That read is stated once, in
 * cap_x86_x87_effects(), rather than repeated on forty rows of the table
 * below; the comment on that function carries its derivation.  The R7
 * regfile-dependency test is satisfied for every edge stated here.
 * FLDENV / FNSTENV move the control and tag words together and are stated
 * through cap_x86_add_x87_env().
 *
 * X87F_CWR IS THE CONTROL-WORD READ, and it is derived from QEMU the same
 * way the rest of this table is rather than from the manual or from LLVM's
 * MCInstrDesc.  The control word reaches an x87 helper by two routes:
 * directly, where the helper switches on `env->fpuc & FPU_RC_MASK` (the
 * five rounding-dependent constant loads FLDL2T / FLDL2E / FLDPI / FLDLG2
 * / FLDLN2 do exactly that), and through `env->fp_status`, which is the
 * DECODED FORM of the control word -- update_fp_status() writes the
 * rounding mode and the precision control into it out of `env->fpuc`, and
 * merge_exception_flags() consults `~env->fpuc & FPUC_EM` to decide
 * whether a raised flag becomes an unmasked exception.  So a helper that
 * hands `&env->fp_status` to softfloat, or that merges exception flags,
 * READS the control word; one that only moves floatx80 bit patterns does
 * not.  Resolved through the call graph (helper_fdiv_ST0_FT0 reaches
 * helper_fdiv, fprem/fprem1 reach fprem_common, fyl2x/fyl2xp1 reach
 * fyl2x_common), that criterion says YES for every arithmetic, compare,
 * convert and transcendental form and NO for the pure moves: FLD %st(i),
 * FST/FSTP %st(i), FXCH, FCHS, FABS, FLD1, FLDZ, FXAM, FFREE, FDECSTP /
 * FINCSTP, FLDT/FSTPT (the m80 pair, which is a bit-pattern copy) and
 * FNSTSW.
 *
 * It is a SOURCE and never a destination on these forms, which is why it
 * needed an id of its own: on the status word's REG_FCSR, every x87
 * arithmetic instruction would have read the register the one before it
 * had just written and an FP program would serialise through an edge the
 * hardware does not have.  See REG_FPCW in champsim_tracer_generic_ids.h.
 */
#define X87F_R0    0x0001u   /* reads  ST(0) implicitly                    */
#define X87F_W0    0x0002u   /* writes ST(0) implicitly                    */
#define X87F_R1    0x0004u   /* reads  ST(1) implicitly                    */
#define X87F_W1    0x0008u   /* writes ST(1) implicitly                    */
#define X87F_SWR   0x0010u   /* reads  the status word                     */
#define X87F_SWW   0x0020u   /* writes the status word                     */
#define X87F_OPW   0x0040u   /* the LAST st(i) operand is a PURE write     */
#define X87F_OPRW  0x0080u   /* the LAST st(i) operand is read-modify-write*/
#define X87F_ENVR  0x0100u   /* reads  the control + tag words             */
#define X87F_ENVW  0x0200u   /* writes the control + tag words             */
#define X87F_CWR   0x0400u   /* reads  the CONTROL word (rounding mode,
                              * precision control, exception masks)        */
#define X87F_CWW   0x0800u   /* writes the CONTROL word                    */
#define X87F_ANY   0x0fffu

/* fpush / fpop / fpop2 all move env->fpstt, which lives in the status word. */
#define X87F_PUSH  (X87F_SWR | X87F_SWW)
#define X87F_POP   (X87F_SWR | X87F_SWW)
/*
 * The bits that say "this row NAMES a slot of the x87 stack".  Every one of
 * them implies a read of the status word, because the slot is selected by
 * TOP and TOP is a field of it; cap_x86_x87_effects() adds X87F_SWR to any
 * row carrying one.
 */
#define X87F_STACK (X87F_R0 | X87F_W0 | X87F_R1 | X87F_W1 | \
                    X87F_OPW | X87F_OPRW)
static void cap_x86_add_pcmpstr_implicit(const cs_insn *insn,
                                        qemu_plugin_insn_info *out,
                                        csh handle);
static unsigned int cap_x86_x87_effects(const cs_insn *insn);
static unsigned int cap_x86_x87_effects_table(const cs_insn *insn);
static void cap_x86_add_x87_implicit(unsigned int fx,
                                     qemu_plugin_insn_info *out, csh handle);
static bool cap_x86_reg_is_x87_stack(unsigned int reg);

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
    /* Capstone-6.0.0-Alpha7 bug: VBROADCASTI128 and VCVTPD2PSX report
     * access == 0 on both operands, erasing their memory source rather
     * than mis-pointing it — see cap_x86_is_erased_mem_load. */
    bool erased_load = cap_x86_is_erased_mem_load(insn->mnemonic);
    /* Capstone-6.0.0-Alpha7 bug: STMXCSR / VSTMXCSR and fourteen of the
     * sixteen SETcc condition codes report their sole MEM operand READ
     * when it is the destination — see cap_x86_is_lost_mem_store. */
    bool lost_store = cap_x86_is_lost_mem_store(insn->mnemonic);
    /* Capstone-6.0.0-Alpha7 bug: the AVX2 gathers lose the WRITE to the
     * mask register they zero on completion — see cap_x86_is_gather. */
    bool gather = cap_x86_is_gather(insn->mnemonic);
    /* Capstone-6.0.0-Alpha7 bugs across the x87 escape space: twelve of
     * the eighteen forms whose memory operand is their DESTINATION report
     * it READ, and FRSTOR reports its memory SOURCE written — see
     * cap_x86_x87_mem_access. */
    uint8_t x87_mem = cap_x86_x87_mem_access(insn->mnemonic);
    /* Capstone-6.0.0-Alpha7 publishes almost none of an x87 instruction's
     * dataflow: no implicit ST(0), no status word on the register forms,
     * and an empty operand list for the whole D9 E0..FF group.  The set is
     * recomputed from the bytes with QEMU's own gen_x87() dispatch key --
     * see cap_x86_x87_effects.  X87F_OPW / X87F_OPRW repair the access on
     * the NAMED st(i), which is the destination of the `fxxx %st,%st(i)`,
     * `fxxxp`, `fst`/`fstp %st(i)` and `fxch` forms and comes back READ. */
    unsigned int x87fx = cap_x86_x87_effects(insn);
    int x87_last_st = -1;
    if (x87fx & (X87F_OPW | X87F_OPRW)) {
        for (uint8_t i = 0; i < n; i++) {
            if (x86->operands[i].type == X86_OP_REG &&
                cap_x86_reg_is_x87_stack(x86->operands[i].reg)) {
                x87_last_st = i;
            }
        }
    }
    /* Capstone-6.0.0-Alpha7 bug: the AVX-512 mask-arithmetic KADD* /
     * KUNPCK* and the XOP VPERMIL2P* forms report access == 0 on every
     * operand — see cap_x86_is_mask_arith_dest_last.  Their dataflow is
     * fixed by the encoding: the last operand (AT&T order — QEMU's
     * Capstone syntax — lists the destination last) is written, every
     * other register or memory operand is read.  Without this the
     * VPERMIL2P* memory source also loses its load lane entirely. */
    bool dest_last = cap_x86_is_mask_arith_dest_last(insn->mnemonic);
    /* Capstone-6.0.0-Alpha7 bug: SHLD / SHRD report EVERY operand READ, so
     * the register or memory location they shift in place has no write at
     * all and the double-precision shift produces nothing.  The last
     * operand in AT&T order is the destination, and it is read-modify-write
     * by construction -- the instruction shifts it and fills the vacated
     * bits from the second operand, so both halves are real.  Intel XED
     * marks the memory form RW4 and names the register form a destination;
     * QEMU's gen_SHLD() writes it through gen_shiftd_rm_T1(). */
    bool shiftd_rmw = g_str_has_prefix(cap_x86_mnem_stem(insn->mnemonic),
                                       "shld")
                   || g_str_has_prefix(cap_x86_mnem_stem(insn->mnemonic),
                                       "shrd");
    /* Capstone-6.0.0-Alpha7 bug: KTEST* reports access == 0 on both
     * operands AND an empty implicit regs_write[].  KTEST reads both mask
     * registers and writes only EFLAGS, so force READ below and restore
     * the implicit EFLAGS write here.
     *
     * That comment used to add "unlike TEST, which carries EFLAGS there",
     * and it was FALSE for half of TEST: `testb %dl, %al` carries the
     * implicit EFLAGS write, `testb %dl, 0x1122(%rbx, %rsi)` does not.
     * The memory-operand form is the one compilers emit constantly, and
     * without the write the Jcc that reads those flags has no producer in
     * the trace at all -- a broken dependency chain on one of the most
     * common instruction pairs in x86.  XADD is the same shape and worse:
     * it loses the EFLAGS write in BOTH forms, and `lock xadd` is how
     * every atomic increment is written.  TEST and XADD always write the
     * flags, so restoring it unconditionally is architecturally exact and
     * a no-op wherever Capstone already reports it. */
    bool ktest_op = cap_x86_is_ktest(insn->mnemonic);
    bool xadd_op = g_str_has_prefix(cap_x86_mnem_stem(insn->mnemonic), "xadd");
    /* Capstone-6.0.0-Alpha7 bug: INCSSPD / INCSSPQ report their sole
     * register operand access == 0.  The register supplies the pop
     * count — a pure READ; the write target is SSP, which is not an
     * operand. */
    bool ssp_read = cap_x86_is_ssp_read(insn->mnemonic);
    /* Capstone-6.0.0-Alpha7 bug: RDSSPD / RDSSPQ report their sole
     * register operand -- the instruction's DESTINATION -- access == 0.
     * See cap_x86_is_ssp_dest for why the repair is a write and not a
     * drop. */
    bool ssp_dest = cap_x86_is_ssp_dest(insn->mnemonic);
    /* FFREEP names an st(i) operand it never reads or writes as data —
     * it only marks the x87 tag word empty.  Capstone reports
     * access == 0, which downstream would repair into a fabricated
     * access; drop the operand instead (the multi-byte-NOP treatment,
     * for a register). */
    bool tag_only = cap_x86_is_x87_tag_only(insn->mnemonic);
    /* Capstone-6.0.0-Alpha7 bugs on the conditional moves, two of them.
     * CMOVcc reports its destination WRITE-only: a conditional move
     * whose condition is false leaves the destination holding the value
     * it already had, so the old value is an input and the instruction
     * is a three-input op (source, old destination, flags).  Reported as
     * a pure write, the trace carries no RAW edge from whatever produced
     * that value -- and cmov is not a corner of the ISA, it is what a
     * compiler emits wherever it removes a branch.  FCMOVcc is worse:
     * its two operand roles come back INVERTED, ST(0) read and ST(i)
     * written, when the instruction moves ST(i) into ST(0).  See
     * cap_x86_is_cmov. */
    bool cmov = cap_x86_is_cmov(insn->mnemonic);
    bool fcmov = cmov && cap_x86_mnem_stem(insn->mnemonic)[0] == 'f';
    /* Capstone-6.0.0-Alpha7 access-flag bugs on the EVEX prefix: the
     * write-mask operand always comes back access == 0, and on some
     * iforms the whole operand list does — see cap_x86_evex_classify. */
    cap_x86_evex evex;
    cap_x86_evex_classify(insn, n, &evex);
    bool evex_clears_mask = cap_x86_evex_clears_mask(insn->mnemonic);

    if (ktest_op || test_read || xadd_op) {
        cap_x86_add_implicit(out, handle, X86_REG_EFLAGS, true);
    }
    /*
     * A REP-prefixed string instruction whose count is already zero
     * performs NO iteration, so every register it would have written keeps
     * the value it had: the write is conditional and the register is
     * therefore also a read (R4).  Intel XED and iced-x86 both name it --
     * `rep lodsq` reads RAX where the unprefixed `lodsq` does not -- and
     * LODS is where it shows, because its accumulator is the family's only
     * register that is a pure destination; rSI, rDI and rCX are read-write
     * in every form and already carry the read.
     */
    if (string_op && (x86->prefix[0] == X86_PREFIX_REP ||
                      x86->prefix[0] == X86_PREFIX_REPNE)) {
        uint8_t nw = out->n_regs_write;
        for (uint8_t k = 0; k < nw; k++) {
            cap_x86_add_implicit(out, handle, out->regs_write_id[k], false);
        }
    }
    /* Capstone-6.0.0-Alpha7 bug: the two SEGMENT pushes lose the stack
     * pointer READ.  `pushq %rax`, `pushq (%rax)` and `pushq $0` all come
     * back reading AND writing rsp, and `popq %fs` reads it too; only
     * `pushq %fs` and `pushq %gs` report the write alone.  A push computes
     * its store address from the current rsp, so the read is not optional
     * -- without it the trace carries no dependency from whatever last set
     * the stack pointer. */
    if (push_read && insn->id == X86_INS_PUSH) {
        for (uint8_t k = 0; k < out->n_regs_write; k++) {
            if (out->regs_write_id[k] == X86_REG_RSP ||
                out->regs_write_id[k] == X86_REG_ESP ||
                out->regs_write_id[k] == X86_REG_SP) {
                cap_x86_add_implicit(out, handle, out->regs_write_id[k],
                                     false);
                break;
            }
        }
    }
    /*
     * Capstone-6.0.0-Alpha7 bug: the x87 escapes name a SEGMENT REGISTER
     * in their implicit read list.  `fcoms (%rax)` comes back reading SS
     * and `ficoms (%rax)` reading DS, for the same encoding shape that
     * `movl (%rax), %eax` reports no segment for at all -- and SS is not
     * even the segment that access uses, since the default follows the
     * BASE register and %rax means DS.  Whichever way it lands it is a
     * dependency the guest does not have, on a register the instruction
     * cannot read: the only segment an access genuinely takes an input
     * from is an override, and an override arrives as the memory
     * operand's segment_id, never through this list.
     */
    if (cap_x86_is_x87_escape(insn)) {
        static const unsigned int segs[] = {
            X86_REG_CS, X86_REG_DS, X86_REG_ES,
            X86_REG_FS, X86_REG_GS, X86_REG_SS,
        };
        for (size_t j = 0; j < ARRAY_SIZE(segs); j++) {
            cap_x86_drop_implicit(out, segs[j], false);
        }
    }
    if (cap_x86_is_sign_extend_to_d(insn->mnemonic)) {
        static const unsigned int acc[] = {
            X86_REG_AL, X86_REG_AH, X86_REG_AX, X86_REG_EAX, X86_REG_RAX,
        };
        for (size_t j = 0; j < ARRAY_SIZE(acc); j++) {
            cap_x86_drop_implicit(out, acc[j], true);
        }
    }

    for (uint8_t i = 0; i < n; i++) {
        const cs_x86_op *cop = &x86->operands[i];
        qemu_plugin_operand *op = &out->operands[i];

        op->access = cop->access;
        if (test_read || ktest_op || ssp_read) {
            op->access = QEMU_PLUGIN_OP_ACC_READ;
        }
        if (dest_last && cop->type != X86_OP_IMM) {
            op->access = (i == n - 1) ? QEMU_PLUGIN_OP_ACC_WRITE
                                      : QEMU_PLUGIN_OP_ACC_READ;
        }
        if (shiftd_rmw && i == n - 1 && cop->type != X86_OP_IMM) {
            op->access = QEMU_PLUGIN_OP_ACC_READ | QEMU_PLUGIN_OP_ACC_WRITE;
        }
        if (evex.is_evex) {
            /* The writemask selects the lanes that are written, so a
             * masked instruction reads it; a gather also zeroes it. */
            if (i == evex.mask_idx) {
                op->access = QEMU_PLUGIN_OP_ACC_READ
                           | (evex_clears_mask ? QEMU_PLUGIN_OP_ACC_WRITE
                                               : 0);
            } else if (op->access == 0 && cop->type != X86_OP_IMM) {
                op->access = (i == evex.dest_idx)
                           ? QEMU_PLUGIN_OP_ACC_WRITE
                           : QEMU_PLUGIN_OP_ACC_READ;
            }
            /* Merge-masking keeps the suppressed lanes of a vector
             * destination, so that destination is also a source. */
            if (evex.merging && i != evex.mask_idx &&
                cop->type == X86_OP_REG &&
                cap_x86_reg_is_vector(cop->reg) &&
                (op->access & QEMU_PLUGIN_OP_ACC_WRITE)) {
                op->access |= QEMU_PLUGIN_OP_ACC_READ;
            }
        }
        if (tag_only) {
            op->type = QEMU_PLUGIN_OP_INVALID;
            op->reg_name[0] = '\0';
            op->reg_id     = 0;
            op->index_name[0] = '\0';
            op->index_id   = 0;
            op->imm = 0;
            op->access = 0;
            op->size = cop->size;
            op->lane_bytes = 0;
            op->scale = 1;
            op->shift_type = 0;
            op->shift_amount = 0;
            op->segment_id = 0;
            continue;
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
            /* VBROADCASTI128's and VCVTPD2PSX's sole register operand is
             * the destination (the source is the memory operand);
             * Capstone erases its WRITE along with the memory access. */
            if (erased_load && op->access == 0) {
                op->access = QEMU_PLUGIN_OP_ACC_WRITE;
            }
            /* RDSSPD / RDSSPQ load the shadow-stack pointer into the
             * GPR their sole register operand names: that operand is the
             * instruction's DESTINATION and Capstone reports it with no
             * access at all.  Saying so is architecturally exact -- XED
             * `SRC {SSP} DST {RAX}`, iced-x86 `DST {RAX}`, PIN's dstset
             * `ref_only=rax` -- and it is a no-op on every encoding
             * Capstone already reports correctly. */
            if (ssp_dest && op->access == 0) {
                op->access = QEMU_PLUGIN_OP_ACC_WRITE;
            }
            /* A gather zeroes its mask register on completion, so the
             * mask -- always operand 0 in AT&T order -- is read-modify-
             * write, not the pure read Capstone reports.  ORing the WRITE
             * in leaves the correctly-reported READ and the destination's
             * own WRITE alone, and self-retires the moment Capstone marks
             * the mask written. */
            if (gather && i == 0 && !evex.is_evex) {
                op->access |= QEMU_PLUGIN_OP_ACC_WRITE;
            }
            /* ... and its DESTINATION -- last in AT&T order -- merges:
             * an element whose mask bit is clear keeps the value the
             * destination already held, so the destination is a source
             * too.  XED reports it CRW.  This is the VEX gather's half
             * of the same rule EVEX merge-masking gets above, and it is
             * the reachable half: QEMU TCG advertises AVX2, not AVX-512. */
            if (gather && !evex.is_evex && i == n - 1) {
                op->access |= QEMU_PLUGIN_OP_ACC_READ;
            }
            /* The conditional-move destination -- last in AT&T order --
             * is read-modify-write, and its source is a pure read.
             * Stated in full rather than ORed in, because FCMOVcc needs
             * both halves: Capstone hands it the two roles the wrong way
             * round, so ORing would leave ST(i) still marked written. */
            if (cmov && i == n - 1) {
                op->access = QEMU_PLUGIN_OP_ACC_READ
                           | QEMU_PLUGIN_OP_ACC_WRITE;
            } else if (fcmov && i == 0) {
                op->access = QEMU_PLUGIN_OP_ACC_READ;
            }
            /* Capstone-6.0.0-Alpha7 reports the XMM DESTINATION of the
             * scalar ROUNDSS / ROUNDSD read-modify-write, alone in its
             * family: `sqrtsd`, `cvtsd2ss`, `cvtsi2ss` and every other
             * legacy scalar form that computes its result from the source
             * alone come back WRITE-only on the same operand shape.  The
             * rounding takes no input from the destination; the only part
             * of it that survives is the upper lane, and a narrow write
             * does not make a register a source (R7.1).  Left as reported,
             * every `roundsd` in a trace carries a false RAW edge to
             * whatever last wrote that register. */
            if (scalar_round && i == n - 1) {
                op->access = QEMU_PLUGIN_OP_ACC_WRITE;
            }
            /* The x87 destination register.  `fst %st(i)` and
             * `fstp %st(i)` lower to gen_helper_fmov_STN_ST0, which
             * assigns the named slot outright, so it is a PURE write;
             * `fadd %st,%st(i)`, `faddp` and `fxch` read it as well. */
            if (i == x87_last_st) {
                if (x87fx & X87F_OPW) {
                    op->access = QEMU_PLUGIN_OP_ACC_WRITE;
                } else {
                    op->access |= QEMU_PLUGIN_OP_ACC_WRITE;
                }
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
             * Segment override (%fs: / %gs: ...).  Its base is a real
             * input to the effective address, so it is surfaced as its
             * own operand field; 0 when the access uses the default
             * segment.  Capstone decides
             * WHETHER this access carries one -- it folds away the
             * overrides that select a segment whose base is
             * architecturally zero in the current mode, and that fold is
             * kept, because a register whose value cannot reach the
             * address is not an input.
             *
             * WHICH register it is comes off the prefix bytes.  Alpha7
             * keeps the FIRST of several overrides where the hardware
             * keeps the LAST: `65 64 ...` is reported %gs and executes
             * %fs, because every override byte assigns s->override in
             * QEMU's own prefix loop (decode-new.c.inc, `case 0x64:
             * s->override = R_FS`).  A model built on the first prefix
             * names a segment base the guest never reads and misses the
             * one it does.  The bytes cannot be wrong about the order.
             */
            op->segment_id = cop->mem.segment
                           ? cap_x86_last_segment_override(insn) : 0;
            /* Capstone-6.0.0-Alpha7 bugs: the r/m destination of a
             * store-form extract is a write target, not a read; so is the
             * sole memory operand of STMXCSR / VSTMXCSR and of a SETcc
             * with a memory destination. */
            if (extract_store || move_store || lost_store) {
                op->access = QEMU_PLUGIN_OP_ACC_WRITE;
            }
            /* Capstone-6.0.0-Alpha7 bugs across the x87 escape space: no
             * x87 memory operand is read-modify-write, so its direction
             * follows from the mnemonic alone, and the escape space is
             * small enough to state in full.  Twelve of the eighteen
             * memory-destination forms are reported READ and FRSTOR's
             * memory source is reported WRITE. */
            if (x87_mem) {
                op->access = x87_mem;
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
            /* VBROADCASTI128's memory source came back with no access
             * at all; without this the load lane and the address
             * dependency are both dropped. */
            if (erased_load && op->access == 0) {
                op->access = QEMU_PLUGIN_OP_ACC_READ;
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
    /* A group-1 F3/F2 byte carries REP/REPNE semantics only on the
     * string and IO-string family.  On every other instruction the
     * same byte is a different prefix that shares the encoding — BND
     * (MPX) on near CALL/RET/JMP/Jcc, XACQUIRE/XRELEASE on locked
     * forms, inert padding on `repz ret` — none of which iterate, so
     * publishing them as REP turns a return into a conditional
     * self-loop.  Gate on the family, not on Capstone's branch
     * groups: Capstone drops the RET group entirely on the imm16
     * return forms (`bnd retq $0x1c04` reports no group at all), so
     * the groups cannot carry this decision. */
    out->has_rep = (x86->prefix[0] == X86_PREFIX_REP ||
                    x86->prefix[0] == X86_PREFIX_REPNE) &&
                   string_op;

    cap_x86_eflags_from_bitmask(handle, insn, out);
    cap_x86_zero_count_shift_contract(insn, out);
    cap_x86_add_sysregs(insn, out);
    cap_x86_add_x87_implicit(x87fx, out, handle);
    cap_x86_add_pcmpstr_implicit(insn, out, handle);
}

/*
 * The x86 system registers, as QEMU_PLUGIN_OP_SYSREG operands.
 *
 * Fourteen registers reach the dependency model through no other door.
 * Capstone's x86 register enum has no id for any of them -- GDTR, IDTR,
 * LDTR, TR, MXCSR, the x87 control and tag words, the MSR file, TSC,
 * IA32_TSC_AUX, XCR0 and SSP are all absent from capstone/x86.h -- so
 * there is no row a register table could carry and no operand Capstone
 * could hand over.  QEMU_PLUGIN_OP_SYSREG exists for exactly this: the
 * register lives outside the ISA's ordinary file, the boundary resolves
 * its architectural ROLE, and the dependency model renames the role.
 *
 * WHAT THAT COSTS TODAY, stated rather than assumed.  Without this,
 * `lgdt` writes nothing and `sgdt` reads nothing, so a kernel's
 * descriptor-table setup is dependency-free; `ldmxcsr` writes nothing
 * and `stmxcsr` reads nothing, so the rounding mode an SSE kernel
 * installs has no producer; `rdtsc` reads nothing, so every timing loop
 * is input-less; and `wrmsr`/`rdmsr` are unordered against each other.
 *
 * THE FACTS ARE QEMU'S.  Each register below is one QEMU names in its
 * own modelling of the instruction, cited at the case:
 *
 *   GDTR/IDTR    env->gdt / env->idt.  SGDT/SIDT load gdt.base and
 *                idt.base (target/i386/tcg/translate.c:3318, :3373),
 *                LGDT/LIDT store them (:3524, :3540).
 *   LDTR/TR      env->ldt / env->tr.  SLDT/STR load ldt.selector and
 *                tr.selector (translate.c:3252, :3274); helper_lldt
 *                and helper_ltr write them (seg_helper.c:1288, :1342)
 *                AND read env->gdt on the way -- `dt = &env->gdt`
 *                (:1304, :1359) -- because the selector they take
 *                indexes the GDT, so the GDT base is a real input.
 *   MXCSR        env->mxcsr.  helper_ldmxcsr writes it
 *                (fpu_helper.c:3294), STMXCSR reads it after
 *                helper_update_mxcsr (emit.c.inc:4063-4064).
 *   X87 control  env->fpuc, written by cpu_set_fpuc.  helper_fldcw
 *                (fpu_helper.c:796), FNSTCW reads it, do_fninit resets
 *                it (:832), do_xsave_fpu stores it (:2626 region),
 *                do_fldenv restores it.
 *   X87 tag      env->fptags[].  helper_ffree_STN (fpu_helper.c:490),
 *                do_fninit (:832), do_xsave_fpu / do_fldenv.
 *   MSR file     helper_rdmsr / helper_wrmsr.  The MSR is selected at
 *                RUNTIME by ECX, so a decode cannot name which one --
 *                every MSR access is ordered against every other, which
 *                is what one id for the file says.  RDPMC is in the
 *                same file: IA32_PMCn are MSRs and RDMSR reads them.
 *   TSC          cpu_get_tsc + env->tsc_offset (misc_helper.c:64-73).
 *   IA32_TSC_AUX env->tsc_aux, returned by helper_rdpid
 *                (misc_helper.c:134) and by RDTSCP's ECX result.  It is
 *                an MSR (0xc0000103), so it takes the MSR id and the
 *                edge from a WRMSR that writes it is REAL, not folded.
 *   XCR0         env->xcr0.  helper_xgetbv (fpu_helper.c:3186),
 *                helper_xsetbv (:3229), and `rfbm &= env->xcr0` in
 *                helper_xsave (:2795) and helper_xrstor (:3077).
 *
 * SSP IS THE EXCEPTION AND IT IS NAMED AS ONE.  QEMU's TCG i386 target
 * does not model CET at all -- there is no U_CET/S_CET MSR, no PL0_SSP,
 * no shadow-stack push on a call -- so the eight SSP-bearing CET
 * instructions (RDSSPD/Q, INCSSPD/Q, RSTORSSP, SAVEPREVSSP, SETSSBSY,
 * CLRSSBSY) execute as the NOPs their encodings occupy when CET is off,
 * and the register facts here come from the Intel SDM rather than from
 * QEMU.  They are recorded anyway because the set is ARCHITECTURAL
 * (R2): a trace of a CET binary must say that `sspopchk`'s x86 sibling
 * family reads and writes the shadow-stack pointer, and REG_SSP is the
 * id RISC-V Zicfiss's `ssp` already carries -- one register, two ISAs
 * (R8.6).  The per-instruction direction, and the SDM step that
 * produces each access, is at the CET arm of the switch below.
 *
 * WHAT IS NOT HERE, and why it is a finding rather than an omission:
 * CLUI, STUI and ERETU carry UIF and IA32_KERNEL_GS_BASE, and this
 * Capstone DOES NOT DECODE THEM.  It ignores the F3 prefix that
 * distinguishes them, so `f3 0f 01 ee` comes back `rdpkru`, `f3 0f 01
 * ef` comes back `wrpkru` and `f3 0f 01 ca` comes back `clac` --
 * measured, not assumed.  Keying UIF off X86_INS_RDPKRU would attribute
 * a register to an instruction that is not the one executing.  Those
 * two registers are unreachable until Capstone decodes the UINTR
 * space, which is R8.7's rule applied: a register the decoder cannot
 * reach is not a mapped register.
 */
typedef enum {
    CAP_X86_SYSREG_NONE = 0,
    CAP_X86_SYSREG_GDTR,
    CAP_X86_SYSREG_IDTR,
    CAP_X86_SYSREG_LDTR,
    CAP_X86_SYSREG_TR,
    CAP_X86_SYSREG_MXCSR,
    CAP_X86_SYSREG_X87CW,
    CAP_X86_SYSREG_X87TAG,
    CAP_X86_SYSREG_MSR,
    CAP_X86_SYSREG_TSC,
    CAP_X86_SYSREG_TSCAUX,
    CAP_X86_SYSREG_XCR0,
    CAP_X86_SYSREG_SSP,
} cap_x86_sysreg;

/*
 * Architectural name and role for each.  The NUMBER above is local to
 * this boundary -- x86 gives these registers no architectural encoding,
 * and the MSRs are numbered but selected at runtime, so there is
 * nothing else to put in reg_id (see qemu_plugin_operand.reg_id).  The
 * NAME is architectural and is what identifies the register; the ROLE
 * is what the dependency model schedules against.
 */
static const struct {
    const char *name;
    uint8_t     role;
} cap_x86_sysreg_tab[] = {
    [CAP_X86_SYSREG_GDTR]   = { "gdtr",   QEMU_PLUGIN_SYSREG_MMU },
    [CAP_X86_SYSREG_IDTR]   = { "idtr",   QEMU_PLUGIN_SYSREG_MMU },
    [CAP_X86_SYSREG_LDTR]   = { "ldtr",   QEMU_PLUGIN_SYSREG_MMU },
    [CAP_X86_SYSREG_TR]     = { "tr",     QEMU_PLUGIN_SYSREG_MMU },
    [CAP_X86_SYSREG_MXCSR]  = { "mxcsr",  QEMU_PLUGIN_SYSREG_FPCTRL },
    [CAP_X86_SYSREG_X87CW]  = { "fpcw",   QEMU_PLUGIN_SYSREG_FPCW },
    [CAP_X86_SYSREG_X87TAG] = { "fptag",  QEMU_PLUGIN_SYSREG_FPCTRL },
    [CAP_X86_SYSREG_MSR]    = { "msr",    QEMU_PLUGIN_SYSREG_OTHER },
    [CAP_X86_SYSREG_TSC]    = { "tsc",    QEMU_PLUGIN_SYSREG_TIMER },
    [CAP_X86_SYSREG_TSCAUX] = { "tscaux", QEMU_PLUGIN_SYSREG_OTHER },
    [CAP_X86_SYSREG_XCR0]   = { "xcr0",   QEMU_PLUGIN_SYSREG_OTHER },
    [CAP_X86_SYSREG_SSP]    = { "ssp",    QEMU_PLUGIN_SYSREG_SHADOWSTK },
};

/*
 * Append one x86 system register as a SYSREG operand.  Idempotent on
 * the register, so a decoder that starts naming one of these cannot be
 * double-counted, and a no-op once the operand array is full -- the
 * cap_riscv_add_csr contract, for CS_ARCH_X86.
 */
static void cap_x86_add_sysreg(qemu_plugin_insn_info *out,
                               cap_x86_sysreg reg, uint8_t access)
{
    qemu_plugin_operand *op;

    for (uint8_t i = 0; i < out->n_operands; i++) {
        if (out->operands[i].type == QEMU_PLUGIN_OP_SYSREG
            && out->operands[i].reg_id == (uint16_t)reg) {
            out->operands[i].access |= access;
            return;
        }
    }
    if (out->n_operands >= QEMU_PLUGIN_INSN_DETAIL_MAX_OPS) {
        return;
    }
    op = &out->operands[out->n_operands];
    memset(op, 0, sizeof(*op));
    op->type         = QEMU_PLUGIN_OP_SYSREG;
    op->access       = access;
    op->reg_id       = (uint16_t)reg;
    op->sysreg_class = cap_x86_sysreg_tab[reg].role;
    op->scale        = 1;
    g_strlcpy(op->reg_name, cap_x86_sysreg_tab[reg].name,
              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ);
    out->n_operands++;
}

#define CAP_X86_SYS_R  QEMU_PLUGIN_OP_ACC_READ
#define CAP_X86_SYS_W  QEMU_PLUGIN_OP_ACC_WRITE

/*
 * The x87 environment triple.  FNSAVE / FRSTOR / FXSAVE / FXRSTOR move
 * the control word, the tag word and (the FX pair) MXCSR together, and
 * all three carry the FPCTRL role, so the generic set they produce is
 * one id either way; they are named individually because reg_name is
 * what identifies a system register on x86 and a consumer reading the
 * operand list should see what the instruction actually moves.
 *
 * The x87 and SSE DATA registers those four instructions also move are
 * NOT here, and that is a separate open question rather than a decision
 * taken quietly: FXSAVE stores ST0-ST7 and XMM0-15, XSAVE stores
 * whichever components EDX:EAX selects, and neither XED nor LLVM MC
 * models that either.  Attributing it means naming the whole
 * architectural register file on one instruction, which is true and is
 * a ruling nobody has given.
 */
static void cap_x86_add_x87_env(qemu_plugin_insn_info *out, uint8_t access,
                                bool with_mxcsr)
{
    cap_x86_add_sysreg(out, CAP_X86_SYSREG_X87CW, access);
    cap_x86_add_sysreg(out, CAP_X86_SYSREG_X87TAG, access);
    if (with_mxcsr) {
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_MXCSR, access);
    }
}



static bool cap_x86_reg_is_x87_stack(unsigned int reg)
{
    return (reg >= X86_REG_ST0 && reg <= X86_REG_ST7) ||
           (reg >= X86_REG_FP0 && reg <= X86_REG_FP7);
}

/*
 * Byte index of the x87 escape opcode (0xd8..0xdf), or -1.  Same prefix
 * skip as cap_x86_is_x87_escape, which is written in terms of this.
 */
static int cap_x86_x87_escape_at(const cs_insn *insn)
{
    uint16_t k = 0;

    while (k < insn->size) {
        uint8_t b = insn->bytes[k];
        if (b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e ||
            b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67 ||
            b == 0xf0 || b == 0xf2 || b == 0xf3 ||
            (b >= 0x40 && b <= 0x4f)) {
            k++;
        } else {
            return (b >= 0xd8 && b <= 0xdf) ? (int)k : -1;
        }
    }
    return -1;
}

static unsigned int cap_x86_x87_effects_table(const cs_insn *insn)
{
    int k = cap_x86_x87_escape_at(insn);
    uint8_t b, modrm;
    int mod, rm, op;

    if (k < 0 || (uint16_t)(k + 1) >= insn->size) {
        return 0;
    }
    b     = insn->bytes[k];
    modrm = insn->bytes[k + 1];
    mod   = (modrm >> 6) & 3;
    rm    = modrm & 7;
    op    = ((b & 7) << 3) | ((modrm >> 3) & 7);

    if (mod != 3) {
        /* ---- memory forms ------------------------------------------- */
        switch (op) {
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x04: case 0x05: case 0x06: case 0x07:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x14: case 0x15: case 0x16: case 0x17:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x24: case 0x25: case 0x26: case 0x27:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x34: case 0x35: case 0x36: case 0x37:
            /* fxxx{s,l} / fixxx{l,s}: the memory operand becomes FT0 and
             * gen_helper_fp_arith_ST0_FT0(op & 7) combines it with ST(0).
             * op1 == 2 is fcom (no result written), op1 == 3 is fcomp
             * (fcom + gen_helper_fpop). */
            if ((op & 7) == 2) {
                return X87F_R0 | X87F_SWW | X87F_CWR;
            }
            if ((op & 7) == 3) {
                return X87F_R0 | X87F_POP | X87F_SWW | X87F_CWR;
            }
            return X87F_R0 | X87F_W0 | X87F_SWW | X87F_CWR;
        case 0x08: case 0x18: case 0x28: case 0x38:
            /* flds / fildl / fldl / filds -- gen_helper_f{ld,ild}*_ST0
             * after the implicit push the ST0 name performs. */
            return X87F_PUSH | X87F_W0 | X87F_SWW | X87F_CWR;
        case 0x09: case 0x19: case 0x29: case 0x39:
            /* fisttp{s,l,ll} -- gen_helper_fistt*_ST0 then fpop. */
            return X87F_R0 | X87F_POP | X87F_SWW | X87F_CWR;
        case 0x0a: case 0x1a: case 0x2a: case 0x3a:
            /* fsts / fistl / fstl / fists -- read ST(0), no pop. */
            return X87F_R0 | X87F_SWW | X87F_CWR;
        case 0x0b: case 0x1b: case 0x2b: case 0x3b:
            /* fstps / fistpl / fstpl / fistps -- read ST(0) then fpop. */
            return X87F_R0 | X87F_POP | X87F_SWW | X87F_CWR;
        case 0x0c:
            /* fldenv: do_fldenv() assigns fpuc, fpus, fpstt and every
             * fptags[] entry and reads none of them. */
            return X87F_ENVW | X87F_SWW;
        case 0x0e:
            /* fnstenv: do_fstenv() READS fpuc, fpus, fpstt and fptags[]
             * to build the image, and then MASKS every FP exception --
             * `cpu_set_fpuc(env, env->fpuc | FPUC_EM)`, SDM Vol.1 8.1.10.
             * So the control word is read AND written, and a later
             * `fnstcw` must wait on the FNSTENV before it.  XED names
             * only a status-word write; LLVM MC names the read as well
             * and QEMU settles both halves. */
            return X87F_ENVR | X87F_SWR | X87F_CWW;
        case 0x1d: case 0x3d:
            /* fldt (m80) / fildll -- gen_helper_fldt_ST0 / fildll_ST0.
             * do_fldt() copies the 80-bit pattern and touches no
             * float_status; fildll_ST0 converts through one. */
            return X87F_PUSH | X87F_W0 | X87F_SWW |
                   (op == 0x3d ? X87F_CWR : 0);
        case 0x1f: case 0x3f:
            /* fstpt (m80) / fistpll -- ST0 then fpop.  Same asymmetry:
             * do_fstt() is a bit-pattern store, fistll_ST0 rounds. */
            return X87F_R0 | X87F_POP | X87F_SWW |
                   (op == 0x3f ? X87F_CWR : 0);
        case 0x2f:
            /* fnstsw m16 -- helper_fnstsw() returns a rearrangement of
             * env->fpus and assigns nothing. */
            return X87F_SWR;
        case 0x3c:
            /* fbld -- gen_helper_fbld_ST0, which pushes. */
            return X87F_PUSH | X87F_W0 | X87F_SWW | X87F_CWR;
        case 0x3e:
            /* fbstp -- gen_helper_fbst_ST0 then fpop. */
            return X87F_R0 | X87F_POP | X87F_SWW | X87F_CWR;
        /* 0x0d fldcw, 0x0f fnstcw, 0x2c frstor, 0x2e fnsave are already
         * stated in full by cap_x86_add_sysregs(). */
        default:
            return 0;
        }
    }

    /* ---- register forms --------------------------------------------- */
    switch (op) {
    case 0x00: case 0x01: case 0x04: case 0x05: case 0x06: case 0x07:
        /* fxxx %st(i), %st -- fmov_FT0_STN(i) then fp_arith_ST0_FT0:
         * ST(0) is both the other addend and the destination. */
        return X87F_R0 | X87F_W0 | X87F_SWW | X87F_CWR;
    case 0x20: case 0x21: case 0x24: case 0x25: case 0x26: case 0x27:
        /* fxxx %st, %st(i) -- fp_arith_STN_ST0: reads ST(0), and the
         * NAMED register is the destination as well as an addend. */
        return X87F_R0 | X87F_OPRW | X87F_SWW | X87F_CWR;
    case 0x30: case 0x31: case 0x34: case 0x35: case 0x36: case 0x37:
        /* fxxxp %st, %st(i) -- the same, then fpop. */
        return X87F_R0 | X87F_OPRW | X87F_POP | X87F_SWW | X87F_CWR;
    case 0x02: case 0x22:
        /* fcom %st(i) */
        return X87F_R0 | X87F_SWW | X87F_CWR;
    case 0x03: case 0x23: case 0x32:
        /* fcomp %st(i) -- fcom then fpop. */
        return X87F_R0 | X87F_POP | X87F_SWW | X87F_CWR;
    case 0x08:
        /* fld %st(i) -- fpush then fmov_ST0_STN. */
        return X87F_PUSH | X87F_W0 | X87F_SWW;
    case 0x09: case 0x29: case 0x39:
        /* fxch %st(i) -- gen_helper_fxchg_ST0_STN swaps the two, so both
         * are read and both are written. */
        return X87F_R0 | X87F_W0 | X87F_OPRW | X87F_SWW;
    case 0x0b: case 0x2b: case 0x3a: case 0x3b:
        /* fstp %st(i) and its three undocumented aliases --
         * fmov_STN_ST0 (a PURE write of the named register) then fpop. */
        return X87F_R0 | X87F_OPW | X87F_POP | X87F_SWW;
    case 0x0c:
        switch (rm) {
        case 0: case 1:
            return X87F_R0 | X87F_W0 | X87F_SWW;   /* fchs, fabs      */
        case 4:
            /* ftst -- fldz_FT0 then fcom_ST0_FT0, which merges. */
            return X87F_R0 | X87F_SWW | X87F_CWR;
        case 5:
            /* fxam -- reads the bit pattern, no float_status. */
            return X87F_R0 | X87F_SWW;
        default:
            return 0;
        }
    case 0x0d:
        /* fld1 / fldl2t / fldl2e / fldpi / fldlg2 / fldln2 / fldz --
         * fpush then the constant into ST(0).  The five middle ones pick
         * their 80-bit pattern by switching on env->fpuc & FPU_RC_MASK;
         * fld1 and fldz are exact in every rounding mode and read
         * nothing. */
        if (rm > 6) {
            return 0;
        }
        return X87F_PUSH | X87F_W0 | X87F_SWW |
               ((rm >= 1 && rm <= 5) ? X87F_CWR : 0);
    case 0x0e:
        switch (rm) {
        case 0: return X87F_R0 | X87F_W0 | X87F_SWW |
                       X87F_CWR;                                  /* f2xm1   */
        case 1: return X87F_R0 | X87F_R1 | X87F_W1 |
                       X87F_POP | X87F_SWW | X87F_CWR;            /* fyl2x   */
        case 2: return X87F_R0 | X87F_W0 | X87F_W1 |
                       X87F_PUSH | X87F_SWW | X87F_CWR;           /* fptan   */
        case 3: return X87F_R0 | X87F_R1 | X87F_W1 |
                       X87F_POP | X87F_SWW | X87F_CWR;            /* fpatan  */
        case 4: return X87F_R0 | X87F_W0 | X87F_W1 |
                       X87F_PUSH | X87F_SWW | X87F_CWR;           /* fxtract */
        case 5: return X87F_R0 | X87F_R1 | X87F_W0 | X87F_SWW |
                       X87F_CWR;                                  /* fprem1  */
        default: return X87F_SWR | X87F_SWW;             /* fdecstp/fincstp */
        }
    case 0x0f:
        switch (rm) {
        case 0: return X87F_R0 | X87F_R1 | X87F_W0 | X87F_SWW |
                       X87F_CWR;                                  /* fprem   */
        case 1: return X87F_R0 | X87F_R1 | X87F_W1 |
                       X87F_POP | X87F_SWW | X87F_CWR;            /* fyl2xp1 */
        case 3: return X87F_R0 | X87F_W0 | X87F_W1 |
                       X87F_PUSH | X87F_SWW | X87F_CWR;           /* fsincos */
        case 5: return X87F_R0 | X87F_R1 | X87F_W0 | X87F_SWW |
                       X87F_CWR;                                  /* fscale  */
        default: return X87F_R0 | X87F_W0 | X87F_SWW | X87F_CWR;
                                          /* fsqrt, frndint, fsin, fcos */
        }
    case 0x15:
        /* fucompp -- fucom then TWO fpops. */
        return (rm == 1) ? (X87F_R0 | X87F_R1 | X87F_POP | X87F_SWW |
                            X87F_CWR) : 0;
    case 0x1d: case 0x1e:
        /* fucomi / fcomi -- read ST(0), write EFLAGS (Capstone's) and the
         * status word; no pop. */
        return X87F_R0 | X87F_SWW | X87F_CWR;
    case 0x2a:
        /* fst %st(i) -- fmov_STN_ST0 is a PURE write of the named
         * register; Capstone reports it READ. */
        return X87F_R0 | X87F_OPW | X87F_SWW;
    case 0x2c:
        return X87F_R0 | X87F_SWW | X87F_CWR;             /* fucom %st(i)  */
    case 0x2d:
        return X87F_R0 | X87F_POP | X87F_SWW |
               X87F_CWR;                                  /* fucomp %st(i) */
    case 0x33:
        /* fcompp -- fcom then TWO fpops. */
        return (rm == 1) ? (X87F_R0 | X87F_R1 | X87F_POP | X87F_SWW |
                            X87F_CWR) : 0;
    case 0x38:
        /* ffreep %st(i) -- ffree_STN (tag word only, already stated by
         * cap_x86_add_sysregs) then fpop. */
        return X87F_POP;
    case 0x3c:
        /* fnstsw %ax */
        return (rm == 0) ? X87F_SWR : 0;
    case 0x3d: case 0x3e:
        /* fucomip / fcomip -- the comparison then fpop. */
        return X87F_R0 | X87F_POP | X87F_SWW | X87F_CWR;
    case 0x10: case 0x11: case 0x12: case 0x13:
    case 0x18: case 0x19: case 0x1a: case 0x1b:
        /* FCMOVcc %st(i), %st -- cap_x86_is_cmov() states the st(i) source
         * and the ST(0) destination, so no X87F_STACK bit is set here and
         * the read of TOP that SELECTS them would go unstated.
         * gen_helper_fmov_ST0_STN(i) resolves both through env->fpstt at
         * execution, so the status word is a source on these forms exactly
         * as it is on the arithmetic ones.  Stated on its own line so that
         * nothing cap_x86_is_cmov() already publishes is published twice. */
        return X87F_SWR;
    case 0x28:
        /* ffree %st(i) -- helper_ffree_STN clears
         * env->fptags[(env->fpstt + i) & 7].  cap_x86_add_sysregs() states
         * the tag-word write; the env->fpstt read that picks WHICH tag it
         * clears is stated here. */
        return X87F_SWR;
    /* 0x0a fnop and 0x1c (feni/fdisi/fclex/fninit/fsetpm) are already
     * stated in full by cap_x86_add_sysregs(). */
    default:
        return 0;
    }
}

/*
 * THE READ OF TOP, stated once for every row that names a stack slot.
 *
 * QEMU addresses the x87 stack through three macros at the top of
 * target/i386/tcg/fpu_helper.c:
 *
 *     #define FT0    (env->ft0)
 *     #define ST0    (env->fpregs[env->fpstt].d)
 *     #define ST(n)  (env->fpregs[(env->fpstt + (n)) & 7].d)
 *     #define ST1    ST(1)
 *
 * so `helper_fabs_ST0` is `ST0 = floatx80_abs(ST0)` in full, and the read
 * of `env->fpstt` -- the TOP field of the status word, which decides WHICH
 * physical register `%st(0)` denotes -- appears nowhere in the helper's own
 * text.  A reading of the source that does not expand the macro concludes
 * that fabs, fchs, fadd, fcom, fst, fxch and every other non-pushing form
 * is independent of the top of stack.  That conclusion is a property of the
 * reading, not of the machine.
 *
 * The R7 regfile-dependency test settles it: an `fld` between two
 * instructions makes the second one's `%st(0)` a DIFFERENT physical
 * register, so a renaming regfile must respect the edge from whatever last
 * wrote TOP to every instruction that names a slot.  Only the forms that
 * name no slot are exempt.
 *
 * DERIVED, NOT ASSERTED.  The subject is
 * contrib/plugins/champsim_tracer/tools/arc3_cov/x86_64/x87_cw_derive.py,
 * which expands those macros and walks fpu_helper.c to a fixed point over
 * an OBSERVED `-one-insn-per-tb -d op` dump, and fails the run if the
 * macros ever stop hiding the read.  Over its 153-encoding x87 denominator
 * it reports 140 encodings reading {fpus, fpstt, fptags} and 13 not; the
 * thirteen are FLDCW, FNSTCW, FLDENV, FRSTOR, FXRSTOR, FNCLEX, FNINIT and
 * the three 8087 NOPs -- the pure control- and environment-word forms,
 * none of which names a stack slot.
 *
 * NOT INCLUDED, and named rather than left silent: FNOP (D9 D0) and FWAIT
 * (9B) both run helper_fwait, which reads env->fpus to test FPUS_SE.  That
 * is the exception-summary bit and not TOP, neither instruction names a
 * stack slot, and QEMU's own comment on the FNOP case says the check is
 * there for a FreeBSD FPU probe -- a QEMU-modelling fact rather than an ISA
 * one.  They are a different mechanism and are left to the question that
 * owns them.
 */
static unsigned int cap_x86_x87_effects(const cs_insn *insn)
{
    unsigned int fx = cap_x86_x87_effects_table(insn);

    if (fx & X87F_STACK) {
        fx |= X87F_SWR;
    }
    return fx;
}

/*
 * Publish the implicit half of an x87 instruction's register set.  The
 * explicit st(i) operand's own access is repaired in the operand loop of
 * cap_fill_x86_operands (X87F_OPW / X87F_OPRW).
 */
static void cap_x86_add_x87_implicit(unsigned int fx,
                                     qemu_plugin_insn_info *out, csh handle)
{
    if (fx & X87F_R0) {
        cap_x86_add_implicit(out, handle, X86_REG_ST0, false);
    }
    if (fx & X87F_W0) {
        cap_x86_add_implicit(out, handle, X86_REG_ST0, true);
    }
    if (fx & X87F_R1) {
        cap_x86_add_implicit(out, handle, X86_REG_ST1, false);
    }
    if (fx & X87F_W1) {
        cap_x86_add_implicit(out, handle, X86_REG_ST1, true);
    }
    if (fx & X87F_SWR) {
        cap_x86_add_implicit(out, handle, X86_REG_FPSW, false);
    }
    if (fx & X87F_SWW) {
        cap_x86_add_implicit(out, handle, X86_REG_FPSW, true);
    }
    if (fx & X87F_CWR) {
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_X87CW, CAP_X86_SYS_R);
    }
    if (fx & X87F_CWW) {
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_X87CW, CAP_X86_SYS_W);
    }
    if (fx & X87F_ENVR) {
        cap_x86_add_x87_env(out, CAP_X86_SYS_R, false);
    }
    if (fx & X87F_ENVW) {
        cap_x86_add_x87_env(out, CAP_X86_SYS_W, false);
    }
}


/*
 * SSE4.2 string compare -- PCMPESTRI / PCMPESTRM / PCMPISTRI / PCMPISTRM
 * and their VEX forms.  Capstone-6.0.0-Alpha7 publishes the two explicit
 * operands and NOTHING else: no EFLAGS write, no result register, and on
 * the explicit-length pair no length register either.  `pcmpistrm` comes
 * back with an EMPTY write list for an instruction whose entire purpose is
 * producing a mask.
 *
 * QEMU's helpers state the whole set (target/i386/ops_sse.h):
 *
 *   pcmpxstrx()            assigns CC_SRC                      -> EFLAGS
 *   helper_pcmpestr[im]    pcmp_elen(env, R_EDX, ...) and
 *                          pcmp_elen(env, R_EAX, ...)          -> EAX, EDX read
 *   helper_pcmpxstri       env->regs[R_ECX] = ...              -> ECX write
 *   helper_pcmpxstrm       env->xmm_regs[0].Q/B/W(...) = ...   -> XMM0 write
 *
 * The implicit-length pair takes its lengths from the operands themselves
 * (pcmp_ilen), so only the explicit-length pair reads EAX and EDX.  LLVM MC
 * names the EFLAGS write and the XMM0 write and corroborates both.
 */
static void cap_x86_add_pcmpstr_implicit(const cs_insn *insn,
                                         qemu_plugin_insn_info *out,
                                         csh handle)
{
    const char *m = insn->mnemonic;
    bool explicit_len, mask_form;

    if (!m || !m[0]) {
        return;
    }
    if (m[0] == 'v') {
        m++;
    }
    if (strncmp(m, "pcmp", 4) != 0 || strncmp(m + 5, "str", 3) != 0) {
        return;
    }
    if (m[4] != 'e' && m[4] != 'i') {
        return;
    }
    if (m[8] != 'i' && m[8] != 'm') {
        return;
    }
    explicit_len = (m[4] == 'e');
    mask_form    = (m[8] == 'm');

    cap_x86_add_implicit(out, handle, X86_REG_EFLAGS, true);
    if (explicit_len) {
        cap_x86_add_implicit(out, handle, X86_REG_EAX, false);
        cap_x86_add_implicit(out, handle, X86_REG_EDX, false);
    }
    if (mask_form) {
        cap_x86_add_implicit(out, handle, X86_REG_XMM0, true);
    } else {
        cap_x86_add_implicit(out, handle, X86_REG_ECX, true);
    }
}

static void cap_x86_add_sysregs(const cs_insn *insn,
                                qemu_plugin_insn_info *out)
{
    switch (insn->id) {
    /* ---- descriptor tables ------------------------------------- */
    case X86_INS_SGDT:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_GDTR, CAP_X86_SYS_R);
        break;
    case X86_INS_LGDT:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_GDTR, CAP_X86_SYS_W);
        break;
    case X86_INS_SIDT:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_IDTR, CAP_X86_SYS_R);
        break;
    case X86_INS_LIDT:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_IDTR, CAP_X86_SYS_W);
        break;
    case X86_INS_SLDT:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_LDTR, CAP_X86_SYS_R);
        break;
    case X86_INS_LLDT:
        /* helper_lldt: `dt = &env->gdt` then write env->ldt. */
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_GDTR, CAP_X86_SYS_R);
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_LDTR, CAP_X86_SYS_W);
        break;
    case X86_INS_STR:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_TR, CAP_X86_SYS_R);
        break;
    case X86_INS_LTR:
        /* helper_ltr: same GDT read, then write env->tr. */
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_GDTR, CAP_X86_SYS_R);
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_TR, CAP_X86_SYS_W);
        break;
    /* ---- SSE control word --------------------------------------- */
    case X86_INS_LDMXCSR:
    case X86_INS_VLDMXCSR:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_MXCSR, CAP_X86_SYS_W);
        break;
    case X86_INS_STMXCSR:
    case X86_INS_VSTMXCSR:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_MXCSR, CAP_X86_SYS_R);
        break;
    /* ---- x87 control and tag words ------------------------------ */
    case X86_INS_FLDCW:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_X87CW, CAP_X86_SYS_W);
        break;
    case X86_INS_FNSTCW:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_X87CW, CAP_X86_SYS_R);
        break;
    case X86_INS_FFREE:
    case X86_INS_FFREEP:
        /* helper_ffree_STN marks the slot empty and touches nothing
         * else: the tag word is the whole architectural effect. */
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_X87TAG, CAP_X86_SYS_W);
        break;
    case X86_INS_FNINIT:
        cap_x86_add_x87_env(out, CAP_X86_SYS_W, false);
        break;
    case X86_INS_FRSTOR:
        cap_x86_add_x87_env(out, CAP_X86_SYS_W, false);
        break;
    case X86_INS_FNSAVE:
        /* do_fsave = do_fstenv (reads them) + do_fninit (writes them). */
        cap_x86_add_x87_env(out, CAP_X86_SYS_R | CAP_X86_SYS_W, false);
        break;
    case X86_INS_FXSAVE:
    case X86_INS_FXSAVE64:
        cap_x86_add_x87_env(out, CAP_X86_SYS_R, true);
        break;
    case X86_INS_FXRSTOR:
    case X86_INS_FXRSTOR64:
        cap_x86_add_x87_env(out, CAP_X86_SYS_W, true);
        break;
    /* ---- the MSR file ------------------------------------------- */
    case X86_INS_RDMSR:
    case X86_INS_RDPMC:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_MSR, CAP_X86_SYS_R);
        break;
    case X86_INS_WRMSR:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_MSR, CAP_X86_SYS_W);
        break;
    /* ---- the time-stamp counter and its companion --------------- */
    case X86_INS_RDTSC:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_TSC, CAP_X86_SYS_R);
        break;
    case X86_INS_RDTSCP:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_TSC, CAP_X86_SYS_R);
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_TSCAUX, CAP_X86_SYS_R);
        break;
    case X86_INS_RDPID:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_TSCAUX, CAP_X86_SYS_R);
        break;
    /* ---- the extended control register -------------------------- */
    case X86_INS_XGETBV:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_XCR0, CAP_X86_SYS_R);
        break;
    case X86_INS_XSETBV:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_XCR0, CAP_X86_SYS_W);
        break;
    case X86_INS_XSAVE:
    case X86_INS_XSAVE64:
    case X86_INS_XSAVEC:
    case X86_INS_XSAVEC64:
    case X86_INS_XSAVEOPT:
    case X86_INS_XSAVEOPT64:
    case X86_INS_XSAVES:
    case X86_INS_XSAVES64:
    case X86_INS_XRSTOR:
    case X86_INS_XRSTOR64:
    case X86_INS_XRSTORS:
    case X86_INS_XRSTORS64:
        /* `rfbm &= env->xcr0` gates every component. */
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_XCR0, CAP_X86_SYS_R);
        break;
    /* ---- CET: the shadow-stack pointer --------------------------
     *
     * SEVEN instructions name SSP, and the direction is per instruction.
     * QEMU's TCG i386 target does not model CET (see the block comment
     * above), so the authority is the SDM Vol. 2 operation section and
     * the step of it that produces each access is cited here.
     *
     *   RDSSPD/Q      `IF ShadowStackEnabled(CPL): dest := SSP` -- read
     *                 only; the destination is an ordinary GPR operand
     *                 Capstone already carries.
     *   INCSSPD/Q     `SSP := SSP + (imm * 8)` -- read AND write.
     *   RSTORSSP      the token at the memory operand is rewritten to
     *                 carry the CURRENT SSP before `SSP := SSP_LA`
     *                 installs the new one, so the old value is consumed
     *                 as well as replaced -- read AND write.  The write
     *                 alone was recorded.
     *   SAVEPREVSSP   `previous_ssp_token := ShadowStackPop8B(SSP)`
     *                 advances SSP by 8 before pushing the token onto
     *                 the previous shadow stack -- read AND write.  The
     *                 read alone was recorded.
     *   SETSSBSY      `IF SSP != 0 THEN #GP(0)` reads it, and
     *                 `SSP := IA32_PL0_SSP` writes it -- read AND write,
     *                 plus the MSR the value comes FROM.  Nothing at all
     *                 was recorded: an instruction whose entire
     *                 architectural effect is a shadow-stack pointer
     *                 assignment was depending on nothing.
     *   CLRSSBSY      clears the token's busy bit and then `SSP := 0`
     *                 -- write only; no step of it reads SSP.  Nothing
     *                 at all was recorded.
     *
     * IA32_PL0_SSP (MSR 0x6A4) IS THE SOURCE OPERAND OF SETSSBSY and
     * takes the MSR-file id for the reason IA32_TSC_AUX does above: it
     * is an MSR, a WRMSR that writes it must resolve before SETSSBSY may
     * read it, and one id for the file is what a decode can honestly say
     * about a register selected at runtime.  Recording the SSP write
     * without it would leave the written value with no producer, which
     * is the half of the defect that a `RD{ssp} WR{ssp}` repair alone
     * does not close.
     *
     * WRSS / WRUSS ARE ABSENT ON PURPOSE.  They store to the shadow
     * stack at the linear address their memory operand names and never
     * consult SSP, so they carry the memory access (handled by the
     * store-repair predicate above) and no system register.  LLVM MC
     * agrees: `--hex=0f38f608` gives RD{r0,r1} WR{} on both sides.
     */
    case X86_INS_RDSSPD:
    case X86_INS_RDSSPQ:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_SSP, CAP_X86_SYS_R);
        break;
    case X86_INS_INCSSPD:
    case X86_INS_INCSSPQ:
    case X86_INS_RSTORSSP:
    case X86_INS_SAVEPREVSSP:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_SSP,
                           CAP_X86_SYS_R | CAP_X86_SYS_W);
        break;
    case X86_INS_SETSSBSY:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_SSP,
                           CAP_X86_SYS_R | CAP_X86_SYS_W);
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_MSR, CAP_X86_SYS_R);
        break;
    case X86_INS_CLRSSBSY:
        cap_x86_add_sysreg(out, CAP_X86_SYSREG_SSP, CAP_X86_SYS_W);
        break;
    default:
        break;
    }
}

#undef CAP_X86_SYS_R
#undef CAP_X86_SYS_W

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
 * The VEX LANE extracts VEXTRACTF128 / VEXTRACTI128 have the same
 * defect and are matched here too.  Their EVEX relatives
 * VEXTRACT{F,I}{32X4,64X2,32X8,64X4} are reported CORRECTLY by this
 * Capstone (checked: `62f37d28190001` = `vextractf32x4 $1,%ymm0,(%rax)`
 * already shows MEM WRITE); they fall inside the stem match anyway and
 * the repair is a no-op on them, which is safe for the same reason the
 * other unconditional repairs in this file are -- it sets the access the
 * architecture specifies, so it cannot disturb an encoding Capstone
 * already gets right.  Ground truth is QEMU's own translator rather than
 * plausibility:
 * target/i386/tcg/decode-new.c.inc gives 0F3A 19 / 39 as
 * `X86_OP_ENTRY3(VEXTRACTx128, W,dq, V,qq, I,b, ...)` -- operand 0, the
 * r/m, is the DESTINATION -- and emit.c.inc's gen_VEXTRACTx128() takes
 * the `decode->op[0].has_ea` arm to gen_sto_env_A0(), an unambiguous
 * store.  Matching on the stem cannot pick up a load: every x86
 * mnemonic stemmed `extract` extracts INTO its r/m operand, the insert
 * direction is spelled VINSERT*, and SSE4a's EXTRQ has no `extract`
 * stem.
 *
 * VCVTPS2PH joins them for the same structural reason and NOT by family
 * resemblance: decode-new.c.inc has 0F3A 1D as
 * `X86_OP_ENTRY3(VCVTPS2PH, W,xh, V,x, I,b, ...)`, r/m destination
 * again, so its memory form is a pure store.  It is matched by exact
 * spelling because its LOAD counterpart VCVTPH2PS (0F38 13,
 * `X86_OP_ENTRY2(VCVTPH2PS, V,x, W,xh, ...)`) differs only in the
 * transposed digits and IS reported correctly by Capstone -- treating
 * `cvt..ph..` as a family would invert it.
 *
 * Detect by mnemonic and, for the MEM operand, force WRITE access.
 * Unconditional for this set: an extract's -- or VCVTPS2PH's -- sole
 * memory operand is always the r/m destination, never a source.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify
 * with `cstool -d x64 660f3a160001` (bytes `66 0f 3a 16 00 01`,
 * `pextrd $1,%xmm0,(%rax)`), `cstool -d x64 c4037d190000`
 * (`vextractf128 $0,%ymm8,(%r8)`) and `cstool -d x64 c4e37d1d0000`
 * (`vcvtps2ph $0,%ymm0,(%rax)`) -- the MEM operand must show WRITE in
 * all three.  Note
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
           g_str_has_prefix(mnem, "extract") ||
           g_str_equal(mnem, "cvtps2ph");
}

/*
 * Capstone 6.0.0-Alpha7 x86 access-flag bug workaround.
 *
 * The same defect as the extract stores above -- a sole memory operand
 * that is the instruction's DESTINATION reported READ -- on two families
 * that have nothing else in common with them, and that are grouped here
 * because the repair and its proof obligation are identical: the memory
 * operand is unconditionally the write target, so forcing WRITE is
 * architecturally exact and is a no-op wherever Capstone already says so.
 *
 * STMXCSR / VSTMXCSR.  Ground truth from QEMU's translator:
 * target/i386/tcg/decode-new.c.inc gives 0F AE /3 as
 * `X86_OP_ENTRYw(STMXCSR, E,d, ...)`.  The `w` is what settles it --
 * X86_OP_ENTRYw expands to X86_OP_ENTRY3(op, op0, s0, None, None, None,
 * None), so E (the r/m operand) is op0, the DESTINATION, and the
 * instruction has no source operand at all.  gen_STMXCSR in emit.c.inc
 * loads CPUX86State::mxcsr into s->T0 and leaves the generic writeback to
 * store it through op0.
 *
 * MATCHED BY EXACT SPELLING, and the sibling that makes it necessary is
 * one ModRM.reg value away: 0F AE /2 is `X86_OP_ENTRYr(LDMXCSR, E,d)` --
 * `r`, so E is a SOURCE -- and Capstone reports ITS memory operand READ
 * CORRECTLY.  ldmxcsr and stmxcsr share the `mxcsr` stem and the whole of
 * their encoding but the ModRM.reg field, so a stem match would invert
 * the one that is right in order to fix the one that is wrong.  vldmxcsr
 * and vstmxcsr stand in the same relation to each other.
 *
 * SETcc TO MEMORY.  All sixteen condition codes are
 * `X86_OP_ENTRYw(SETcc, E,b)` in decode-new.c.inc (0F 90 through 0F 9F,
 * across the two tables at lines 1226 and 1363), so E is again op0 and
 * again the destination; gen_SETcc emits gen_setcc() into s->T0 for the
 * generic writeback.  Every one of the sixteen writes its byte operand.
 *
 * EACH CONDITION CODE WAS CHECKED SEPARATELY rather than by matching the
 * `set` stem, because Capstone does not get them uniformly wrong:
 * `sete` (0F 94) and `setne` (0F 95) report their MEM operand WRITE
 * CORRECTLY and the other fourteen -- seta, setae, setb, setbe, setg,
 * setge, setl, setle, setno, setnp, setns, seto, setp, sets -- report it
 * READ.  A per-condition-code split is exactly the shape in which a
 * benign convention difference and a real defect look alike, so the
 * sixteen are listed out.  Listing all sixteen rather than only the
 * fourteen is deliberate: forcing WRITE on sete/setne changes nothing
 * (they already carry it), which keeps the predicate a statement about
 * the architecture rather than about this Capstone's bug list, and makes
 * the repair self-retiring in the same way the move-family one is.
 * The register-destination forms of all sixteen are reported correctly
 * and are untouched -- this branch only ever rewrites a MEM operand.
 *
 * `setssbsy` (F3 0F 01 E8) is the only other x86 mnemonic Capstone spells
 * with a leading `set`; it carries no operand at all, so it could not be
 * affected either way, and the exact match excludes it regardless.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify with
 * `--hex=0fae1c24` (`stmxcsr (%rsp)`), `--hex=c5f8ae5dd8`
 * (`vstmxcsr -0x28(%rbp)`) and `--hex=0f9200` (`setb (%rax)`) -- the MEM
 * operand must show WRITE in all three, while `--hex=0fae1424`
 * (`ldmxcsr (%rsp)`) must still show READ.  Use a `cstool` built from
 * `subprojects/capstone`, or run `capstone_workaround_probe`; see
 * docs/troubleshooting.rst.
 */
static bool cap_x86_is_lost_mem_store(const char *mnem)
{
    if (!mnem || !mnem[0]) return false;
    if (g_str_equal(mnem, "stmxcsr") || g_str_equal(mnem, "vstmxcsr")) {
        return true;
    }
    /* The sixteen SETcc spellings Capstone emits in AT&T syntax, listed
     * individually -- see the note above on why this is not a stem
     * match. */
    return g_str_equal(mnem, "seta")   || g_str_equal(mnem, "setae") ||
           g_str_equal(mnem, "setb")   || g_str_equal(mnem, "setbe") ||
           g_str_equal(mnem, "sete")   || g_str_equal(mnem, "setg")  ||
           g_str_equal(mnem, "setge")  || g_str_equal(mnem, "setl")  ||
           g_str_equal(mnem, "setle")  || g_str_equal(mnem, "setne") ||
           g_str_equal(mnem, "setno")  || g_str_equal(mnem, "setnp") ||
           g_str_equal(mnem, "setns")  || g_str_equal(mnem, "seto")  ||
           g_str_equal(mnem, "setp")   || g_str_equal(mnem, "sets");
}

/*
 * Capstone 6.0.0-Alpha7 x86 access-flag bug workaround.
 *
 * The AVX2 gather family loses the WRITE to its mask register.  A gather
 * has two destinations: it merges the loaded elements into the
 * destination vector and it ZEROES the mask register on completion, so
 * that a gather interrupted by a fault can be restarted from what the
 * mask still holds.  Capstone reports the mask operand READ only, which
 * drops that second write and with it every WAR and WAW edge that
 * depends on the mask being dead after the gather.
 *
 * Ground truth from QEMU's translator, on both halves:
 * target/i386/tcg/decode-new.c.inc gives 0F38 90..93 as
 * `X86_OP_ENTRY3(VPGATHERD, V,x, H,x, M,d, ...)` and relatives -- op1 is
 * H, the VEX.vvvv register, which is the mask.  `helper_vpgatherdd` in
 * target/i386/ops_sse.h takes it as `Reg *v` and both READS it (`if
 * (v->L(i) >> 31)` selects the element) and WRITES it (`v->L(i) = 0`,
 * inside the loop and OUTSIDE the mask test, so it runs for every
 * element).  gen_vsib_avx in emit.c.inc adds a second write for the
 * VEX.128 case, zeroing OP_PTR1's high 128 bits explicitly under the
 * comment "There are two output operands".  The mask is therefore
 * READ-MODIFY-WRITE, and the repair ADDS write access rather than
 * replacing the read.
 *
 * THE MASK IS OPERAND 0, uniformly.  QEMU drives Capstone in AT&T syntax,
 * which prints the gather as `mask, vsib-memory, destination`; all
 * sixteen forms of the family (four opcodes x VEX.W x VEX.L) were
 * checked and every one yields exactly [0]REG [1]MEM [2]REG, mask first
 * and destination last.  The destination's WRITE is reported correctly
 * and is not touched.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify with
 * `--hex=c4e269900c08` (`vpgatherdd %xmm2,(%rax,%xmm1),%xmm1`) -- the
 * first operand must show READ | WRITE.  Use a `cstool` built from
 * `subprojects/capstone`, or run `capstone_workaround_probe`; see
 * docs/troubleshooting.rst.
 */
/*
 * CMOVcc / FCMOVcc: does this mnemonic move conditionally?
 *
 * Capstone marks the destination of every conditional move WRITE-only,
 * which is only true when the condition holds.  When it does not the
 * destination keeps its previous value -- architecturally the
 * instruction is defined as "if (cc) dest <- src", so dest is live on
 * entry either way, and every out-of-order model treats it as a third
 * input.  Without the READ the trace claims a WAW where the hardware has
 * a RAW, on an instruction compilers emit specifically to avoid a
 * branch, so the shape it distorts is the one it appears in most.
 *
 * FCMOVcc carries a second, larger defect: `fcmovb %st(1), %st(0)` comes
 * back RD{st0} WR{st1} -- the roles of the two operands exchanged, as if
 * the Intel-order description had been applied to the AT&T-order operand
 * array.  That does not merely lose an edge, it publishes a definition of
 * a register the instruction never writes and drops the one it does, so
 * the destination is forced read-write and the source read.
 *
 * A prefix test is exact here: the mnemonic space beginning `cmov` is
 * the sixteen condition codes crossed with the operand-size suffix, and
 * `fcmov` is the eight x87 forms.  Nothing else in x86 starts either
 * way.  Owed upstream as a bug report, not yet sent.
 */
/*
 * Capstone puts the prefix words INSIDE the mnemonic: the locked form of XADD
 * is "lock xaddq", not "xaddq".  A predicate that prefix-matches the bare
 * stem therefore misses exactly the encodings that carry a prefix -- and for
 * XADD that is `lock xadd`, the atomic increment, which is the form worth
 * caring about.  This skips the prefix words so the stem test means what it
 * says.  (Found by the behavioural oracle's IR comparison within an hour of
 * the XADD fix landing without it.)
 */
static const char *cap_x86_mnem_stem(const char *mnem)
{
    static const char *const prefixes[] = {
        "lock ", "rep ", "repe ", "repz ", "repne ", "repnz ",
        "bnd ", "notrack ", "xacquire ", "xrelease ",
        "data16 ", "addr32 ", "rex64 ",
    };
    bool moved = true;

    if (!mnem) return "";
    while (moved) {
        moved = false;
        for (size_t i = 0; i < ARRAY_SIZE(prefixes); i++) {
            if (g_str_has_prefix(mnem, prefixes[i])) {
                mnem += strlen(prefixes[i]);
                moved = true;
                break;
            }
        }
    }
    return mnem;
}

static bool cap_x86_is_cmov(const char *mnem)
{
    const char *stem = cap_x86_mnem_stem(mnem);

    if (!stem[0]) return false;
    return g_str_has_prefix(stem, "cmov") || g_str_has_prefix(stem, "fcmov");
}

/*
 * Capstone-6.0.0-Alpha7 access-flag bug workaround: the EVEX prefix.
 *
 * An EVEX-encoded instruction carries its write-mask register in
 * EVEX.aaa rather than in the ModRM/VEX operand fields, and Capstone
 * appends it as a trailing operand.  That operand comes back with
 * access == 0 on EVERY masked EVEX encoding -- measured 2570 of 2570
 * over the x86_64 opcode space -- so the walker, which contributes a
 * register by its access flag, drops the mask and the trace records no
 * dependency on it at all.  A masked instruction genuinely reads the
 * mask: it selects which lanes are written.
 *
 * Two further shapes of the same defect strand operands other than the
 * mask.  On 172 encodings the access flags of the WHOLE instruction are
 * erased, which costs the memory operand its load lane as well as
 * costing every register its role; the downstream fallback then reads
 * AT&T order and takes the last register operand as the destination --
 * which, on an EVEX encoding, is the write-mask, so the mask is
 * published as a WRITE and the real vector destination becomes a
 * source.  On a further 82 the instruction is annotated except for its
 * destination, and that destination is an OPMASK register every time
 * (VPTESTM*, VPTESTNM*, VPMOV*2M, VFPCLASS*, VPSHUFBITQMB), so the
 * trace carries the compare but not the k register it produces.
 *
 * Both are the same repair: an EVEX operand Capstone left without an
 * access takes its role from AT&T order once the write-mask is set
 * aside.  Every one of those 254 operands is either the dest-last
 * operand or a source, so the rule never has to guess.
 *
 * Both are repaired here, from the prefix rather than from a mnemonic
 * list, because the prefix is what states the facts:
 *
 *   - EVEX.aaa names the writemask.  Non-zero means masked; the mask
 *     is a READ.  The VSIB gathers and scatters additionally clear it
 *     as they retire elements, so there it is READ-WRITE -- see
 *     cap_x86_evex_clears_mask.
 *   - EVEX.z distinguishes merging from zeroing.  Under merge-masking
 *     the lanes the mask suppresses keep the destination's previous
 *     value, so a VECTOR register destination is read-modify-write.
 *     XED reports exactly that and no more: RCW on a vector
 *     destination, plain W on an opmask destination (whose suppressed
 *     bits are zeroed, not preserved) and CW on a memory destination
 *     (suppressed bytes are simply not written -- no load happens).
 *     The repair therefore covers vector register destinations only.
 *   - With the writemask set aside, the remaining operands follow the
 *     ordinary AT&T dest-last rule, which is what recovers the
 *     all-access-zero shape.
 *
 * Detection reads the encoding directly.  Capstone exposes no EVEX
 * flag, and its operand table is precisely the thing under repair, so
 * neither can be the source of truth.  0x62 introduces EVEX and is not
 * a legal opcode in 64-bit mode; the two reserved-bit checks (P[3:2]
 * must be 00, P[10] must be 1) reject the 32-bit BOUND that shares the
 * byte.  The writemask operand is then accepted only when Capstone's
 * own last operand IS k[EVEX.aaa], so a Capstone operand-order change
 * retires the repair instead of misdirecting it.
 */
static void cap_x86_evex_classify(const cs_insn *insn, uint8_t n,
                                  cap_x86_evex *e)
{
    const cs_x86 *x86 = &insn->detail->x86;

    e->is_evex  = false;
    e->merging  = false;
    e->mask_idx = -1;
    e->dest_idx = -1;

    /* Skip the legacy prefixes EVEX may follow (segment override,
     * address size); 66/F2/F3/REX are folded into EVEX itself and
     * cannot appear, but skipping them costs nothing. */
    uint16_t k = 0;
    while (k < insn->size) {
        uint8_t b = insn->bytes[k];
        if (b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e ||
            b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67 ||
            b == 0xf0 || b == 0xf2 || b == 0xf3) {
            k++;
        } else {
            break;
        }
    }
    if (k + 3 >= insn->size || insn->bytes[k] != 0x62) {
        return;
    }
    uint8_t p0 = insn->bytes[k + 1];
    uint8_t p1 = insn->bytes[k + 2];
    uint8_t p2 = insn->bytes[k + 3];
    if ((p0 & 0x0c) != 0 || (p1 & 0x04) == 0) {
        return;                 /* reserved bits say this is not EVEX */
    }
    e->is_evex = true;

    unsigned aaa = p2 & 0x07;
    bool zeroing = (p2 & 0x80) != 0;

    /* The writemask is Capstone's last operand -- but only trust that
     * when the whole operand list survived truncation and the register
     * it names is the one EVEX.aaa selects. */
    if (aaa != 0 && n > 0 && x86->op_count == n) {
        const cs_x86_op *last = &x86->operands[n - 1];
        if (last->type == X86_OP_REG &&
            last->reg >= X86_REG_K0 && last->reg <= X86_REG_K7 &&
            (unsigned)(last->reg - X86_REG_K0) == aaa) {
            e->mask_idx = n - 1;
            e->merging = !zeroing;
        }
    }

    for (int i = (int)n - 1; i >= 0; i--) {
        if (i == e->mask_idx || x86->operands[i].type == X86_OP_IMM) {
            continue;
        }
        e->dest_idx = i;
        break;
    }
}

/*
 * Capstone's XMM / YMM / ZMM register ids are three contiguous banks.
 * Used to keep the EVEX merge-masking preserve-read off opmask and
 * memory destinations, which do not preserve.
 */
static bool cap_x86_reg_is_vector(unsigned int reg)
{
    return reg >= X86_REG_XMM0 && reg <= X86_REG_ZMM31;
}

/*
 * The EVEX VSIB forms whose write-mask is READ-WRITE: a gather or a
 * scatter clears each mask bit as it retires that element, so a fault
 * part-way through leaves the mask naming exactly the work still to do
 * (Intel SDM Vol. 2, VPSCATTERDD "Operation": `k1[j] := 0` inside the
 * element loop, then `k1[MAX_KL-1:KL] := 0`).
 *
 * The gather/scatter PREFETCH forms share the VSIB shape and most of
 * the mnemonic but not this behaviour: VGATHERPF0DPD's pseudocode
 * reads `k1[j]` to decide whether to prefetch and never assigns to it.
 * XED marks their mask RW anyway; LLVM MC and iced-x86 both report it
 * read-only, and the manual settles it -- so the list is spelled out
 * per mnemonic rather than taken on a "vscatter" prefix, which would
 * swallow the eight VSCATTERPF forms.
 */
static bool cap_x86_evex_clears_mask(const char *mnem)
{
    if (!mnem || !mnem[0]) {
        return false;
    }
    return cap_x86_is_gather(mnem)         ||
           g_str_equal(mnem, "vpscatterdd") ||
           g_str_equal(mnem, "vpscatterdq") ||
           g_str_equal(mnem, "vpscatterqd") ||
           g_str_equal(mnem, "vpscatterqq") ||
           g_str_equal(mnem, "vscatterdps") ||
           g_str_equal(mnem, "vscatterdpd") ||
           g_str_equal(mnem, "vscatterqps") ||
           g_str_equal(mnem, "vscatterqpd");
}

static bool cap_x86_is_gather(const char *mnem)
{
    if (!mnem || !mnem[0]) return false;
    return g_str_equal(mnem, "vpgatherdd") ||
           g_str_equal(mnem, "vpgatherdq") ||
           g_str_equal(mnem, "vpgatherqd") ||
           g_str_equal(mnem, "vpgatherqq") ||
           g_str_equal(mnem, "vgatherdps") ||
           g_str_equal(mnem, "vgatherdpd") ||
           g_str_equal(mnem, "vgatherqps") ||
           g_str_equal(mnem, "vgatherqpd");
}

/*
 * Capstone 6.0.0-Alpha7 x86 access-flag bug workaround: the x87 escape
 * space.
 *
 * The same defect as STMXCSR above -- a memory operand that is the
 * instruction's DESTINATION reported READ -- on TWELVE x87 forms, plus
 * FRSTOR, which is the inverse: a memory SOURCE reported WRITE.  What
 * makes the x87 space worth stating in full rather than one spelling at a
 * time is that its memory operand's direction is decided ENTIRELY by the
 * opcode.  NO x87 instruction read-modify-writes memory: within the
 * escape opcodes 0xD8-0xDF every memory operand is either a pure load or
 * a pure store, and which one it is follows from the mnemonic alone.
 * That makes the repair a statement about the architecture -- and a no-op
 * on the six memory-destination forms and every memory-source form this
 * Capstone already reports correctly -- so it self-retires when the
 * decoder is fixed, in the same way the SETcc one does.
 *
 * Ground truth is QEMU's own translator, gen_x87() in
 * target/i386/tcg/translate.c.  Its `if (mod != 3)` arm is the memory
 * form, keyed by `op = ((b & 7) << 3) | ModRM.reg` exactly as the table
 * below is, and every store arm ends in a `tcg_gen_qemu_st_*` or in a
 * helper whose access_prepare() names MMU_DATA_STORE:
 *
 *   D9 /2 fsts     D9 /3 fstps    op 0x0a 0x0b  st_i32
 *   D9 /6 fnstenv                 op 0x0e       helper_fstenv, DATA_STORE
 *   D9 /7 fnstcw                  op 0x0f       st_i32
 *   DB /1 fisttpl  DB /2 fistl    op 0x19 0x1a  st_i32
 *   DB /3 fistpl                  op 0x1b       st_i32
 *   DB /7 fstpt                   op 0x1f       helper_fstt_ST0, DATA_STORE
 *   DD /1 fisttpll                op 0x29       st_i64
 *   DD /2 fstl     DD /3 fstpl    op 0x2a 0x2b  st_i64
 *   DD /6 fnsave                  op 0x2e       helper_fsave, DATA_STORE
 *   DD /7 fnstsw                  op 0x2f       st_i32
 *   DF /1 fisttps  DF /2 fists    op 0x39 0x3a  st_i32
 *   DF /3 fistps                  op 0x3b       st_i32
 *   DF /6 fbstp                   op 0x3e       helper_fbst_ST0, DATA_STORE
 *   DF /7 fistpll                 op 0x3f       st_i64
 *
 * WHICH OF THE EIGHTEEN CAPSTONE GETS WRONG IS NOT A FAMILY, WHICH IS WHY
 * ALL EIGHTEEN ARE LISTED.  The twelve reported READ are fsts, fstps,
 * fnstcw, fisttpl, fistl, fistpl, fisttpll, fstl, fstpl, fisttps, fists
 * and fistps; the six already reported WRITE are fnstenv, fstpt, fnsave,
 * fnstsw, fbstp and fistpll.  The split follows nothing architectural --
 * D9 /6 (fnstenv) is right and D9 /7 (fnstcw) is wrong, DB /7 (fstpt) is
 * right and DB /3 (fistpl) is wrong -- so a list of the broken twelve
 * would be a list of this Capstone's bugs rather than a description of
 * the instruction set, and would not go quiet when they are fixed.
 *
 * FRSTOR (DD /4, op 0x2c) IS THE OPPOSITE INVERSION and is repaired here
 * with its own direction rather than left alone: Capstone reports its
 * memory operand WRITE, and it only ever reads.  Intel SDM: "FRSTOR
 * m94/108byte -- Load FPU state from m94byte or m108byte".  QEMU's
 * helper_frstor() prepares its access MMU_DATA_LOAD and reaches memory
 * only through access_ldw() and do_fldt().  Left uncorrected the tracer
 * emits a phantom 108-byte store and loses the load, which is the same
 * damage as the fnstcw case with the sign flipped.
 *
 * FLDENV (D9 /4, op 0x0c) rides along for the reason the six
 * already-correct stores do: it is FNSTENV's twin, one ModRM.reg value
 * from FRSTOR's, and naming the environment quartet with its true
 * direction keeps this a rule about the group.  Capstone reports it
 * correctly today, so forcing READ changes nothing.  Note that QEMU's
 * helper_fldenv() passes MMU_DATA_STORE to access_prepare(), which reads
 * like a contradiction: it is a probe-permission argument, do_fldenv()
 * only calls access_ldw(), and FLDENV loads.  (That mismatch is a
 * separate, real QEMU bug -- FLDENV against a read-only mapping would
 * raise a spurious #PF -- not evidence about direction.)
 *
 * THE SPELLINGS ARE AT&T'S, WITH THE OPERAND-WIDTH SUFFIX THE PRINTER
 * APPENDS, because QEMU drives Capstone in AT&T syntax.  All eighteen
 * were read off cs_insn::mnemonic for the encodings above rather than
 * from Capstone's instruction-id table, which carries the unsuffixed
 * `fst` / `fist` / `fisttp` stems and would not match.
 *
 * THE FWAIT-PREFIXED SPELLINGS ARE DELIBERATELY ABSENT.  `fstcw`,
 * `fstsw`, `fstenv` and `fsave` (9B D9 /7, 9B DD /7, 9B D9 /6, 9B DD /6)
 * are the checked forms of four of the entries above, but this Capstone
 * never emits them: it decodes 9B as a standalone `wait` and the escape
 * as the following instruction (verify with `--hex=9bd938`, which
 * disassembles as `wait`, not `fstcw`).  Listing them would add a rule
 * that matches nothing, which is the shape a stale justification takes.
 *
 * THE REGISTER FORMS ARE UNREACHABLE FROM HERE.  `fnstsw %ax` (DF E0),
 * `fstp %st(i)` and the rest take the mod == 3 arm and carry no MEM
 * operand; this branch only ever rewrites a MEM operand's access.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify with
 * `--hex=d93c24` (`fnstcw (%rsp)`), `--hex=dd5c2420` (`fstpl 0x20(%rsp)`)
 * and `--hex=db4c2450` (`fisttpl 0x50(%rsp)`) -- the MEM operand must
 * show WRITE in all three -- and with `--hex=dd20` (`frstor (%rax)`),
 * whose MEM operand must show READ.  `--hex=d9742470` (`fnstenv`) and
 * `--hex=d9642470` (`fldenv`) must be unchanged.  Use a `cstool` built
 * from `subprojects/capstone`, or run `capstone_workaround_probe`; see
 * docs/troubleshooting.rst.
 */
static uint8_t cap_x86_x87_mem_access(const char *mnem)
{
    /* Every x87 mnemonic starts with `f`; the test keeps the whole table
     * off the path of every other x86 instruction. */
    if (!mnem || mnem[0] != 'f') {
        return 0;
    }
    /* The eighteen forms whose memory operand is the destination. */
    if (g_str_equal(mnem, "fsts")     || g_str_equal(mnem, "fstl")     ||
        g_str_equal(mnem, "fstps")    || g_str_equal(mnem, "fstpl")    ||
        g_str_equal(mnem, "fstpt")    ||
        g_str_equal(mnem, "fists")    || g_str_equal(mnem, "fistl")    ||
        g_str_equal(mnem, "fistps")   || g_str_equal(mnem, "fistpl")   ||
        g_str_equal(mnem, "fistpll")  ||
        g_str_equal(mnem, "fisttps")  || g_str_equal(mnem, "fisttpl")  ||
        g_str_equal(mnem, "fisttpll") ||
        g_str_equal(mnem, "fbstp")    ||
        g_str_equal(mnem, "fnstcw")   || g_str_equal(mnem, "fnstsw")   ||
        g_str_equal(mnem, "fnstenv")  || g_str_equal(mnem, "fnsave")) {
        return QEMU_PLUGIN_OP_ACC_WRITE;
    }
    /* The FPU-environment loads: FRSTOR is the inversion this repairs,
     * FLDENV its correctly-reported twin. */
    if (g_str_equal(mnem, "frstor") || g_str_equal(mnem, "fldenv")) {
        return QEMU_PLUGIN_OP_ACC_READ;
    }
    return 0;
}

/*
 * Capstone 6.0.0-Alpha7 x86 access-flag bug workaround.
 *
 * A stronger form of the flag defects above: VBROADCASTI128 comes back
 * with access == 0 on BOTH its operands, so the memory operand does not
 * point the wrong way — it vanishes.  The operand walker derives its
 * load lane from the access flag, so the trace records loads=0
 * stores=0 for an instruction whose only job is to read 16 bytes of
 * memory and splat them, and the effective address never appears.
 *
 * Ground truth from QEMU's translator: target/i386/tcg/decode-new.c.inc
 * gives 0F38 5A as `X86_OP_ENTRY3(VBROADCASTx128, V,qq, None,None,
 * WM,dq, ...)` — destination V is the vector register, source WM is
 * memory.  There is no register-source encoding of VBROADCASTI128 at
 * all; the memory form is the only form.
 *
 * MATCHED BY EXACT SPELLING, and that is the whole point.  This is NOT
 * a `vbroadcast*` family defect: the sibling encodings were checked one
 * by one against this same Capstone and VBROADCASTSS (0F38 18),
 * VBROADCASTSD (19), VBROADCASTF128 (1A), VPBROADCASTD (58),
 * VPBROADCASTQ (59), VPBROADCASTB (78) and VPBROADCASTW (79) all report
 * MEM READ and REG WRITE CORRECTLY.  VBROADCASTF128 in particular is
 * the exact 128-bit twin of the broken one, one opcode byte away and
 * correct — so a stem match on `vbroadcast` would be a repair applied
 * to seven encodings that do not need it, which is how a benign
 * convention difference and a real defect get conflated.
 *
 * BOTH OPERANDS ARE REPAIRED, and repairing only one is worse than
 * repairing neither -- this was measured, not assumed.  The plugin's
 * operand walker used to recover the lost vector destination on its own
 * (asserted as `x86_64 W-wr-added vbroadcasti128 +REG_VEC#` in
 * isaxcheck_fixups.txt), and the tempting minimal change was to fix the
 * MEM half only and leave that recovery in place.  It does not survive
 * contact: with MEM alone marked READ the walker reclassifies the insn
 * as an ordinary load and stops synthesising the destination, so the
 * fields layer goes from `loads=0 stores=0 DST{REG_VEC0}` to `loads=1
 * stores=0 DST{-}` -- one defect traded for another.  Marking the
 * register WRITE as well gives `loads=1 DST{REG_VEC0}`, which is the
 * instruction.  The walker's recovery correspondingly becomes dead and
 * its fixups line is removed in the same change, which is the intended
 * lifecycle for a repair the boundary has taken over.
 *
 * Both repairs are gated on `access == 0`, so an encoding Capstone
 * reports correctly is never touched.
 *
 * VCVTPD2PSX HAS THE SAME ERASURE AND THE SAME SHAPE, so it is repaired
 * here rather than given its own predicate: two operands, both back with
 * access == 0, memory the source and the sole register the destination.
 * Ground truth from QEMU's translator: decode-new.c.inc's decode_0F5A
 * table gives `X86_OP_ENTRY2(VCVTPD2PS, V,x, W,x, vex2)`, which expands
 * to X86_OP_ENTRY3(op, V,x, 2op,x, W,x) -- V is op0, the vector
 * destination, and W is op2, the r/m source -- and gen_VCVTPD2PS in
 * emit.c.inc calls gen_helper_cvtpd2ps_xmm(tcg_env, OP_PTR0, OP_PTR2),
 * reading the memory operand and writing the register.
 *
 * MATCHED BY EXACT SPELLING for the same reason vbroadcasti128 is, and
 * the collision here is even tighter than an opcode byte.  `vcvtpd2psx`
 * and `vcvtpd2psy` are AT&T's two spellings of the SAME OPCODE -- the
 * suffix disambiguates the memory operand's width, so they differ only in
 * VEX.L -- and `vcvtpd2psy` is reported CORRECTLY (MEM READ, REG WRITE),
 * as are the register-source forms of both and the legacy SSE
 * `cvtpd2ps`.  The transposed twin `vcvtps2pd` is correct as well.  A
 * stem match on `vcvtpd2ps` would take the healthy 256-bit spelling with
 * the broken 128-bit one.
 *
 * Its walker recovery is retired by this change exactly as
 * vbroadcasti128's was: `x86_64 W-wr-added vcvtpd2psx +REG_VEC#` in
 * isaxcheck_fixups.txt goes dead once the boundary supplies the
 * destination write, and is deleted with the change that retires it.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0-Alpha7; verify
 * with `cstool -d x64 c4e27d5a00` (`vbroadcasti128 (%rax),%ymm0`) and
 * `--hex=c5f95a00` (`vcvtpd2psx (%rax),%xmm0`) -- the MEM operand must
 * show READ and the REG operand WRITE, while `--hex=c5fd5a00`
 * (`vcvtpd2psy`) must be unchanged.  Use a `cstool` built from
 * `subprojects/capstone`, or run `capstone_workaround_probe`; see
 * docs/troubleshooting.rst.
 */
static bool cap_x86_is_erased_mem_load(const char *mnem)
{
    if (!mnem || !mnem[0]) return false;
    return g_str_equal(mnem, "vbroadcasti128") ||
           g_str_equal(mnem, "vcvtpd2psx");
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
     * testl/testq.  Prefix-match on the STEM — no other x86 mnemonic starts
     * with "test" (ktest/vptest begin with k/v), and the stem skip is what
     * keeps a prefixed form from slipping past (see cap_x86_mnem_stem). */
    return g_str_has_prefix(cap_x86_mnem_stem(mnem), "test");
}

/*
 * Capstone 6.0.0-Alpha7 x86 access-flag bugs: whole families whose
 * every operand comes back access == 0.
 *
 * The three-operand AVX-512 mask arithmetic (KADDB/W/D/Q, KUNPCKBW/
 * WD/DQ) and the XOP permutes (VPERMIL2PD/PS) write exactly one
 * operand — the destination, which AT&T operand order lists LAST —
 * and read every other register or memory operand.  No form of any
 * of these mnemonics deviates, so the (position, access) repair is
 * architecturally exact.  "vpermil2" is disjoint from the AVX
 * "vpermilp*" prefix, which Capstone reports correctly.
 */
static bool cap_x86_is_mask_arith_dest_last(const char *mnem)
{
    return mnem && (g_str_has_prefix(mnem, "kadd") ||
                    g_str_has_prefix(mnem, "kunpck") ||
                    g_str_has_prefix(mnem, "vpermil2"));
}

/* KTESTB/W/D/Q: mask-register TEST — reads both operands, writes only
 * EFLAGS.  Excluded from cap_x86_is_test by its prefix, and unlike
 * TEST its Capstone detail carries an EMPTY implicit regs_write[], so
 * the EFLAGS write needs restoring as well (see cap_x86_add_implicit
 * at the caller). */
static bool cap_x86_is_ktest(const char *mnem)
{
    return mnem && g_str_has_prefix(mnem, "ktest");
}

/* INCSSPD/INCSSPQ: the register operand supplies the shadow-stack pop
 * count — a pure READ.  The architectural write target is SSP, which
 * never appears in the operand array. */
static bool cap_x86_is_ssp_read(const char *mnem)
{
    return mnem && g_str_has_prefix(mnem, "incssp");
}

/*
 * Capstone-6.0.0-Alpha7 bug: RDSSPD / RDSSPQ lose the access on the GPR
 * they load the shadow-stack pointer into.
 *
 * `IF ShadowStackEnabled(CPL): dest := SSP` -- Intel SDM Vol. 2B,
 * RDSSPD/RDSSPQ "Operation".  The named GPR is the destination and the
 * only architectural effect the instruction has; Capstone returns it
 * with access == 0, naming the operand while saying nothing about what
 * the instruction does to it.
 *
 * WHY A WRITE AND NOT A DROP, and why it is not left alone.  An operand
 * with no access reaches the plugin's POSITIONAL FALLBACK, which places
 * by operand order and has no destination slot to hand out while the
 * instruction classifies GEN_OP_NOP -- so the register landed on the
 * wire as a SOURCE, in the one role all three static references and PIN
 * agree it does not have.  A drop would lose the register entirely,
 * which is the R12.1 direction that is never available.  Stating the
 * architectural access is the only repair that adds no information the
 * ISA does not define and removes none that it does: it is R16 applied
 * at the boundary, where the defect is.
 *
 * ALL THREE STATIC REFERENCES AND THE EXECUTION REFERENCE, measured:
 *   XED       f3480f1ec8  SRC {SSP}      DST {RAX}
 *   iced-x86  f3480f1ec8  SRC {}         DST {RAX}
 *   LLVM MC   f3480f1ec8  SRC {RAX,SSP}  DST {RAX}
 *   PIN       f3480f1ec8  srcset ref_only={} tracer_only=rax;
 *                         dstset ref_only=rax tracer_only={}
 * LLVM MC alone ALSO keeps the GPR as a source, modelling the SDM's
 * conditional write (with CET disabled the old value survives, so the
 * write merges).  That reading is R17.1c's, it is a strictly wider set,
 * and it is NOT taken here: R16's consequence for this row is that the
 * GPR MOVES to the destination list, and a register published in both
 * roles would leave the XED and PIN legs disagreeing in the SRC-EXTRA
 * direction they disagree in today.  The dissent is recorded rather
 * than resolved by silence.
 *
 * The SSP system register is appended separately as a READ by
 * cap_x86_add_sysreg; the two halves of the instruction's dataflow are
 * stated in the two places that can state them.
 */
static bool cap_x86_is_ssp_dest(const char *mnem)
{
    return mnem && (strcmp(mnem, "rdsspd") == 0 ||
                    strcmp(mnem, "rdsspq") == 0);
}

/* FFREEP: tags st(i) empty and pops — the named register is neither
 * read nor written as data.  (FFREE reports the same access == 0 but
 * is untouched here until proven mis-repaired: the fields sweep that
 * established this family only ever observed FFREEP.) */
static bool cap_x86_is_x87_tag_only(const char *mnem)
{
    return mnem && strcmp(mnem, "ffreep") == 0;
}

/* Append @reg to the implicit write (@is_write) or read list of an x86
 * decode unless it is already there — the cap_mips_add_implicit
 * pattern, for CS_ARCH_X86. */
/*
 * Capstone-6.0.0-Alpha7 bug: CWD / CDQ / CQO report the accumulator as
 * WRITTEN as well as read.
 *
 * These instructions sign-extend the accumulator into the D register
 * and leave the accumulator alone -- Intel SDM Vol. 2, CWD/CDQ/CQO
 * "Operation": `DX := SignExtend(AX)`, `EDX := SignExtend(EAX)`,
 * `RDX := SignExtend(RAX)`, with no assignment to the source.  XED,
 * iced-x86 and LLVM MC all name only the D register as written.
 *
 * The phantom matters because these sit immediately before a signed
 * IDIV: with rax marked written, the trace shows the divide's dividend
 * being produced by the CQO rather than by whatever actually computed
 * it, so a real RAW edge is replaced by a false one.
 *
 * Only the D-writing forms are listed.  Their siblings CBW / CWDE /
 * CDQE (`cbtw` / `cwtl` / `cltq` in AT&T) DO write the accumulator --
 * that is the whole instruction -- and must keep it.
 */
static bool cap_x86_is_sign_extend_to_d(const char *mnem)
{
    if (!mnem || !mnem[0]) {
        return false;
    }
    return g_str_equal(mnem, "cwtd") ||   /* CWD  ax  -> dx  */
           g_str_equal(mnem, "cltd") ||   /* CDQ  eax -> edx */
           g_str_equal(mnem, "cqto");     /* CQO  rax -> rdx */
}

/*
 * Remove a register from an implicit list.  The counterpart of
 * cap_x86_add_implicit, for the defects where Capstone names a
 * register the instruction does not touch.
 */
static void cap_x86_drop_implicit(qemu_plugin_insn_info *out,
                                  unsigned int reg, bool is_write)
{
    uint16_t *ids = is_write ? out->regs_write_id : out->regs_read_id;
    uint8_t  *cnt = is_write ? &out->n_regs_write : &out->n_regs_read;
    char (*names)[QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ] =
        is_write ? out->regs_write : out->regs_read;

    for (uint8_t i = 0; i < *cnt; i++) {
        if (ids[i] != reg) {
            continue;
        }
        for (uint8_t j = (uint8_t)(i + 1); j < *cnt; j++) {
            ids[j - 1] = ids[j];
            memcpy(names[j - 1], names[j],
                   QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ);
        }
        (*cnt)--;
        return;
    }
}

static void cap_x86_add_implicit(qemu_plugin_insn_info *out, csh handle,
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
                      handle, reg, CS_ARCH_X86);
    ids[*cnt] = reg;
    (*cnt)++;
}

/*
 * Capstone 6.0.0-Alpha7 x86: the EFLAGS dependency is COMPUTED and never
 * PUBLISHED as a register.
 *
 * cs_x86 carries a per-flag bitmask -- detail->x86.eflags -- built from
 * the same tables that fill the operand list.  It is the only place the
 * boundary can learn that `cli` writes IF, that `lar` writes ZF or that
 * `shld` preserves OF.  None of it reaches detail->regs_read /
 * regs_write: for every one of those three the implicit register lists
 * come back EMPTY, so a consumer that reads only the register lists sees
 * an instruction with no flag dependency at all, and the Jcc that
 * consumes those flags has no producer anywhere in the trace.  `xadd`
 * and `test` are the same shape on the hot path -- eflags carries their
 * whole flag write and regs_write is empty or partial.
 *
 * The mapping is fixed by the architecture, not chosen here:
 *
 *   TEST_x       the instruction reads flag x               -> READ
 *   PRIOR_x      flag x keeps the value it already had      -> READ + WRITE
 *   MODIFY_x     read-modify-write of flag x                -> WRITE
 *   SET_x        flag x forced to 1                         -> WRITE
 *   RESET_x      flag x forced to 0                         -> WRITE
 *   UNDEFINED_x  flag x left architecturally undefined      -> WRITE
 *
 * PRIOR_x is a READ because the dependency model has ONE flags register:
 * an instruction that rewrites part of the word and preserves the rest
 * takes the preserved part as an input.  UNDEFINED_x is a WRITE because
 * the flag's value afterwards does not depend on its value before, so a
 * later reader depends on THIS instruction and on nothing earlier.
 *
 * detail->x86.eflags is a UNION with fpu_flags, so the field is only
 * EFLAGS off the x87 escape space; cap_x86_is_x87_escape() decides that
 * from the instruction bytes rather than from a mnemonic list.
 *
 * This never removes anything: an EFLAGS access Capstone already names
 * in regs_read / regs_write is left exactly where it is, and
 * cap_x86_add_implicit() is idempotent.
 */
#define CAP_X86_EFLAGS_PRIOR                                            \
    (X86_EFLAGS_PRIOR_OF | X86_EFLAGS_PRIOR_SF | X86_EFLAGS_PRIOR_ZF |  \
     X86_EFLAGS_PRIOR_AF | X86_EFLAGS_PRIOR_PF | X86_EFLAGS_PRIOR_CF |  \
     X86_EFLAGS_PRIOR_TF | X86_EFLAGS_PRIOR_IF | X86_EFLAGS_PRIOR_DF |  \
     X86_EFLAGS_PRIOR_NT)

#define CAP_X86_EFLAGS_TEST                                             \
    (X86_EFLAGS_TEST_OF | X86_EFLAGS_TEST_SF | X86_EFLAGS_TEST_ZF |     \
     X86_EFLAGS_TEST_PF | X86_EFLAGS_TEST_CF | X86_EFLAGS_TEST_NT |     \
     X86_EFLAGS_TEST_DF | X86_EFLAGS_TEST_RF | X86_EFLAGS_TEST_IF |     \
     X86_EFLAGS_TEST_TF | X86_EFLAGS_TEST_AF)

#define CAP_X86_EFLAGS_MODIFY                                           \
    (X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_SF | \
     X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_OF | \
     X86_EFLAGS_MODIFY_TF | X86_EFLAGS_MODIFY_IF | X86_EFLAGS_MODIFY_DF | \
     X86_EFLAGS_MODIFY_NT | X86_EFLAGS_MODIFY_RF)

#define CAP_X86_EFLAGS_RESET                                            \
    (X86_EFLAGS_RESET_OF | X86_EFLAGS_RESET_CF | X86_EFLAGS_RESET_DF |  \
     X86_EFLAGS_RESET_IF | X86_EFLAGS_RESET_SF | X86_EFLAGS_RESET_AF |  \
     X86_EFLAGS_RESET_TF | X86_EFLAGS_RESET_NT | X86_EFLAGS_RESET_PF |  \
     X86_EFLAGS_RESET_RF | X86_EFLAGS_RESET_ZF | X86_EFLAGS_RESET_0F |  \
     X86_EFLAGS_RESET_AC)

#define CAP_X86_EFLAGS_SET                                              \
    (X86_EFLAGS_SET_CF | X86_EFLAGS_SET_DF | X86_EFLAGS_SET_IF |        \
     X86_EFLAGS_SET_OF | X86_EFLAGS_SET_SF | X86_EFLAGS_SET_ZF |        \
     X86_EFLAGS_SET_AF | X86_EFLAGS_SET_PF)

#define CAP_X86_EFLAGS_UNDEF                                            \
    (X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF |                \
     X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_PF |                \
     X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_CF)

#define CAP_X86_EFLAGS_READS  (CAP_X86_EFLAGS_TEST | CAP_X86_EFLAGS_PRIOR)
#define CAP_X86_EFLAGS_WRITES                                           \
    (CAP_X86_EFLAGS_MODIFY | CAP_X86_EFLAGS_RESET | CAP_X86_EFLAGS_SET | \
     CAP_X86_EFLAGS_UNDEF | CAP_X86_EFLAGS_PRIOR)

/*
 * The four families where Capstone's own eflags bitmask is WRONG, found by
 * sweeping the whole x86_64 opcode denominator (8,873 encodings) and keeping
 * every encoding whose bitmask-derived EFLAGS access is contradicted by BOTH
 * Intel XED and LLVM MC.  That sweep returns 19 encodings outside the x87
 * escape space, and they are exactly these four families -- so the list is
 * exhaustive by measurement rather than by inspection:
 *
 *   cmp<cc>{ps,pd,ss,sd}   eflags = MODIFY AF/CF/SF/ZF/PF/OF (0x3f), the
 *                          INTEGER `cmp`'s flag table.  The SSE compares
 *                          write an all-ones / all-zeros MASK into their
 *                          vector destination and touch no flag at all.
 *   movss / movsd          eflags = TEST_DF, the STRING `movs`'s flag table.
 *                          The scalar SSE moves read no flag.
 *   prefetchw              eflags = 0x7ff (MODIFY AF..RF).  A prefetch hint
 *                          affects no flag; PREFETCH (/0) correctly reports 0
 *                          and PREFETCHWT1 (/2) does too, so only /1 is wrong.
 *   sysexit                eflags = 0x7ff.  SYSEXIT loads CS/SS/RSP/RIP and
 *                          does not modify RFLAGS; SYSENTER, which does clear
 *                          IF, correctly reports MODIFY_IF alone.
 *
 * The VEX spellings of the first two -- vcmpltps, vmovss, vmovsd -- report a
 * ZERO bitmask and are correct, so the repair is scoped to the legacy forms
 * and does not need to reach them.
 */
static bool cap_x86_eflags_bitmask_is_wrong(const char *mnem)
{
    const char *m = cap_x86_mnem_stem(mnem);
    size_t len = strlen(m);

    if (g_str_has_prefix(m, "sysexit") || g_str_equal(m, "prefetchw")) {
        return true;
    }
    if (g_str_equal(m, "movss") || g_str_equal(m, "movsd")) {
        return true;
    }
    /* cmp<cc>ps / cmp<cc>pd / cmp<cc>ss / cmp<cc>sd, every condition code,
     * including the `cmpps $0xa` spelling Capstone falls back to for the
     * immediates that have no mnemonic of their own. */
    if (g_str_has_prefix(m, "cmp") && len >= 5) {
        const char *sfx = m + len - 2;
        if (g_str_equal(sfx, "ps") || g_str_equal(sfx, "pd") ||
            g_str_equal(sfx, "ss") || g_str_equal(sfx, "sd")) {
            return true;
        }
    }
    return false;
}

/*
 * Capstone 6.0.0-Alpha7 x86: five families whose EFLAGS READ is missing from
 * the eflags bitmask as well as from regs_read, so no amount of reading
 * Capstone recovers it.  Every one is a dependency QEMU's own translator
 * emits, cited here rather than argued:
 *
 *   cmc              gen_CMC() is `gen_compute_eflags(s); xori(cc_src, CC_C)`
 *                    -- it computes the flags and flips CF, so the old word
 *                    is an input (target/i386/tcg/emit.c.inc).
 *   rcl / rcr        rotate THROUGH carry.  gen_RCL()/gen_RCR() call
 *                    gen_eflags_adcox() and fold the incoming carry into the
 *                    high part; CF is an input at every count and in every
 *                    operand form.
 *   popf / popfq     gen_POPF() emits write_eflags(T0, mask) -- a MASKED
 *                    write.  Every bit outside the mask keeps the value it
 *                    already had, which is a read of the old word.
 *   in / out         the I/O permission check is against RFLAGS.IOPL.  QEMU
 *                    hoists IOPL into DisasContext at translation time
 *                    (translate.c: dc->iopl = (flags >> IOPL_SHIFT) & 3),
 *                    which makes the read invisible in the emitted ops -- but
 *                    that is a translator optimisation, not the architecture,
 *                    and IOPL is RFLAGS bits 12-13.
 *   shift/rotate     a shift or rotate BY CL whose count comes out zero
 *   by CL            leaves every flag untouched.  gen_shift_dynamic_flags()
 *                    emits movcond(count == 0 ? cpu_cc_dst : new) for cc_dst,
 *                    cc_src AND cc_op, so the old flag state is selected at
 *                    run time and is a genuine input.  QEMU draws the line in
 *                    exactly the same place the architecture does:
 *                    gen_shift_count() sets can_be_zero ONLY for the CL form
 *                    (X86_OP_INT); a non-zero immediate cannot preserve, and
 *                    a zero immediate skips the operation entirely.  That is
 *                    why this repair is scoped to the CL forms and the
 *                    immediate forms are left alone.
 */
static bool cap_x86_eflags_read_lost(const cs_insn *insn)
{
    static const char *const shifts[] = {
        "rol", "ror", "rcl", "rcr", "shl", "sal", "shr", "sar",
        "shld", "shrd",
    };
    const cs_x86 *x86 = &insn->detail->x86;
    const char *m = cap_x86_mnem_stem(insn->mnemonic);
    size_t mlen = strlen(m);

    if (g_str_equal(m, "cmc")) {
        return true;
    }
    if (g_str_has_prefix(m, "rcl") || g_str_has_prefix(m, "rcr")) {
        return true;                              /* rotate through carry */
    }
    if (g_str_has_prefix(m, "popf")) {
        return true;                              /* masked write */
    }
    /* CLI / STI clear or set IF and leave every other flag alone, which
     * QEMU emits literally: gen_CLI() is gen_reset_eflags(s, IF_MASK), and
     * gen_reset_eflags() LOADS env->eflags, masks one bit and stores it
     * back (target/i386/tcg/translate.c).  The load is the read.  Their
     * decode entries also carry chk(iopl), so RFLAGS.IOPL gates them --
     * the same IOPL dependency the port I/O instructions have. */
    if (g_str_equal(m, "cli") || g_str_equal(m, "sti")) {
        return true;
    }
    /* FCMOVcc TESTS CF / ZF / PF and moves ST(i) into ST(0) when the
     * condition holds.  Capstone's eflags bitmask is empty for the whole
     * family and its implicit read list names no flag, so the condition the
     * move depends on appears nowhere.  Intel XED names RFLAGS a source;
     * the harness's own ADJ-5 already settled the other half (FCMOVcc does
     * not WRITE the flags), so the read is the only thing missing. */
    if (g_str_has_prefix(m, "fcmov")) {
        return true;
    }
    /* The port I/O instructions, and NOT the string forms (insb / outsb),
     * which already read DF and whose flag dependency Capstone reports. */
    if ((g_str_has_prefix(m, "in") || g_str_has_prefix(m, "out")) &&
        mlen <= 4 && !g_str_has_prefix(m, "ins") && !g_str_has_prefix(m, "outs")
        && !g_str_has_prefix(m, "inc") && !g_str_has_prefix(m, "int")
        && !g_str_has_prefix(m, "inv")) {
        return true;
    }
    /* A shift or rotate whose COUNT is CL: the count can be zero, and a
     * zero count preserves every flag. */
    for (size_t i = 0; i < ARRAY_SIZE(shifts); i++) {
        if (!g_str_has_prefix(m, shifts[i])) {
            continue;
        }
        /*
         * The COUNT operand, and NOT any operand.  Capstone is configured
         * for AT&T syntax here, so the destination is the LAST operand and
         * the count is one of the ones before it; scanning the whole array
         * makes `shrb $5, %cl` -- whose count is the immediate and whose
         * DESTINATION happens to be CL -- read as a CL-count shift and
         * publish an EFLAGS source the instruction does not have.  That was
         * measured on the wire (two rows, ld.so's `shrb $0x5,%cl`), and it
         * is the exact case the paragraph above says this repair excludes:
         * "a non-zero immediate cannot preserve".
         */
        for (uint8_t k = 0; k + 1 < x86->op_count; k++) {
            if (x86->operands[k].type == X86_OP_REG &&
                x86->operands[k].reg == X86_REG_CL) {
                return true;
            }
        }
        /* On the MEMORY forms Capstone drops the count operand from the
         * operand list entirely -- `rolb %cl, (%rax)` comes back with ONE
         * operand, the memory one -- and CL survives only in the implicit
         * read list.  Look there too, or the memory forms of every shift
         * keep the defect the register forms just lost. */
        for (uint8_t k = 0; k < insn->detail->regs_read_count; k++) {
            unsigned int r = insn->detail->regs_read[k];
            if (r == X86_REG_CL || r == X86_REG_CX ||
                r == X86_REG_ECX || r == X86_REG_RCX) {
                return true;
            }
        }
        return false;
    }
    return false;
}

static void cap_x86_eflags_from_bitmask(csh handle, const cs_insn *insn,
                                        qemu_plugin_insn_info *out)
{
    uint64_t ef;
    bool x87;

    /* The enumerated lost READS are decided from the instruction, not from
     * the bitmask, so they are settled FIRST -- FCMOVcc lives in the x87
     * escape space and the union guard below would otherwise swallow it. */
    if (cap_x86_eflags_read_lost(insn)) {
        cap_x86_add_implicit(out, handle, X86_REG_EFLAGS, false);
    }

    /* The field is fpu_flags on the x87 side of the union.  The byte test
     * catches the D8..DF escape; Capstone's own FPU group catches FWAIT,
     * whose 0x9B opcode is outside it and whose 0xF000 would otherwise be
     * read as MODIFY_IF|MODIFY_DF|MODIFY_NT|MODIFY_RF. */
    x87 = cap_x86_is_x87_escape(insn);
    for (uint8_t g = 0; g < insn->detail->groups_count && !x87; g++) {
        x87 = insn->detail->groups[g] == X86_GRP_FPU;
    }
    if (x87 || cap_x86_eflags_bitmask_is_wrong(insn->mnemonic)) {
        return;
    }
    ef = insn->detail->x86.eflags;
    if (ef & CAP_X86_EFLAGS_WRITES) {
        cap_x86_add_implicit(out, handle, X86_REG_EFLAGS, true);
    }
    if (ef & CAP_X86_EFLAGS_READS) {
        cap_x86_add_implicit(out, handle, X86_REG_EFLAGS, false);
    }
}

/*
 * A SHIFT OR ROTATE WHOSE ENCODED COUNT IS ZERO TOUCHES NO FLAG -- NEITHER
 * AS A SOURCE NOR AS A DESTINATION.
 *
 * The SDM states it on every page of the family, in the same words:
 *
 *   SAL/SAR/SHL/SHR (Vol. 2B 4-687), Flags Affected: "If the count is 0,
 *       the flags are not affected."
 *   RCL/RCR/ROL/ROR (Vol. 2B 4-543), Flags Affected: "If the masked count
 *       is 0, the flags are not affected."  RCL's Operation makes the read
 *       side of that explicit as well -- "WHILE (tempCOUNT != 0) DO
 *       tempCF := MSB(DEST); DEST := (DEST * 2) + CF; ..." -- so the CF
 *       the rotate-through-carry consumes is read INSIDE a loop that a
 *       zero count never enters.
 *   SHLD (Vol. 2B 4-706) / SHRD (4-709): "If the count operand is 0, the
 *       flags are not affected."
 *
 * Capstone reports the dependency anyway.  detail->x86.eflags is filled
 * from the per-mnemonic tables and knows nothing about the immediate, so
 * `shlb $0,%al` comes back writing EFLAGS and `rclb $0,%al` comes back
 * reading and writing it, and the operand walk mints a producer and a
 * consumer for a register the instruction does not touch.
 *
 * QEMU DRAWS THE SAME LINE THE SDM DOES, which is why these rows are in the
 * bar at all: gen_shift_count() returns *count = NULL when
 * `(decode->immediate & mask) == 0`, and gen_RCL(), gen_RCR() and the shift
 * emitters return immediately on it, emitting no op whatsoever.  QEMU's read
 * list holds the r/m operand alone and its write list is EMPTY -- not
 * refused, empty -- on all nine rules.
 *
 * READ OFF THE ENCODING, not off the mnemonic.  The two spaces that can
 * carry a zero count are the group-2 imm8 opcodes C0 and C1 (whose ModRM.reg
 * selects ROL/ROR/RCL/RCR/SHL/SHR/SAL/SAR, all eight of them this family)
 * and the double-precision shifts 0F A4 (SHLD) and 0F AC (SHRD).  The
 * CL-counted forms (D2/D3, 0F A5, 0F AD) and the count-1 forms (D0/D1) are
 * NOT here and must not be: a count that is only known at run time can be
 * zero or not, and R17 says a conditional carries all its potential sources.
 * The mask is the architecture's own -- 3FH under REX.W, 1FH otherwise
 * (SDM, RCL/RCR/ROL/ROR, "determine count") -- which is the same number
 * gen_shift_count() uses, so `rclq $0x20,%rax` (count 32, real) and
 * `rcll $0x20,%eax` (count 0 after masking) are told apart the way both the
 * reference and the emulator tell them apart.
 *
 * The DESTINATION REGISTER is deliberately left alone.  Whether an operand
 * the encoding names and no execution assigns is still a destination is the
 * frozen-encoded-operand question, which is open and is not this one; what
 * is settled here is the FLAGS, which the reference says in one sentence.
 */
static void cap_x86_zero_count_shift_contract(const cs_insn *insn,
                                              qemu_plugin_insn_info *out)
{
    const cs_x86 *x86;
    uint64_t mask;
    bool found = false;
    uint64_t imm = 0;

    if (insn->detail == NULL) {
        return;
    }
    x86 = &insn->detail->x86;

    if (x86->opcode[0] == 0xC0 || x86->opcode[0] == 0xC1) {
        if (x86->opcode[1] != 0) {
            return;                     /* not the one-byte group-2 space */
        }
    } else if (x86->opcode[0] == 0x0F &&
               (x86->opcode[1] == 0xA4 || x86->opcode[1] == 0xAC)) {
        if (x86->opcode[2] != 0) {
            return;
        }
    } else {
        return;
    }

    /*
     * The count is the LAST immediate operand: SHLD/SHRD's other operands
     * are registers, and the group-2 forms have exactly one.  A form that
     * reaches here with no immediate at all is not the imm8 encoding this
     * contract is about, and it is left alone rather than guessed at.
     */
    for (uint8_t i = 0; i < x86->op_count; i++) {
        if (x86->operands[i].type == X86_OP_IMM) {
            imm = (uint64_t)x86->operands[i].imm;
            found = true;
        }
    }
    if (!found) {
        return;
    }

    mask = (x86->rex & 0x08) ? 0x3Fu : 0x1Fu;
    if ((imm & mask) != 0) {
        return;
    }

    cap_x86_drop_implicit(out, X86_REG_EFLAGS, false);
    cap_x86_drop_implicit(out, X86_REG_EFLAGS, true);
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
 * ACCESS PATTERN: a member with both a MEM and a REG operand where no
 * operand carries WRITE is the store form whose MEM lost its flag,
 * because a real load always has its destination register marked
 * WRITE.  Without the correction the operand walker models a vector
 * store as a phantom load (laddr/ld block instead of sdata/saddr) —
 * the dropped-store / wrong-latency footgun.
 *
 * The access pattern is used in preference to operand ORDER, which
 * would also separate the two: QEMU drives Capstone in AT&T syntax
 * (cs_option CS_OPT_SYNTAX_ATT above), and the detail operand array
 * follows the printed AT&T order — reversed with respect to the Intel
 * manuals, so the DESTINATION is the last operand, and a load's MEM is
 * operand 0 while a store's MEM is the final one (`488b00` = `movq
 * (%rax),%rax` gives [0]MEM [1]REG, `488900` = `movq %rax,(%rax)`
 * gives [0]REG [1]MEM).  The access test is preferred because it is
 * self-retiring: the moment Capstone marks the store's MEM operand
 * WRITE, `mv_any_write` becomes true and the repair stops firing on
 * its own, which is what makes the dead-rule half of
 * `isaxcheck --fixups` able to see the workaround become unnecessary.
 *
 * MEMBERSHIP EXTENDS BEYOND `mov`, to the two other move families whose
 * mnemonic is identical in both directions and whose store form has the
 * same lost WRITE:
 *
 *   AVX/AVX2 masked moves — VMASKMOV{PS,PD} and VPMASKMOV{D,Q}.
 *   target/i386/tcg/decode-new.c.inc separates them by opcode, not by
 *   name: 0F38 2E/2F/8E are `X86_OP_ENTRY3(VMASKMOVPS_st, M,x, V,x,
 *   H,x, ...)` and friends, whose operand 0 is `M` — memory ONLY, a
 *   store — while 0F38 2C/2D/8C are `X86_OP_ENTRY3(VMASKMOVPS, V,x,
 *   H,x, WM,x, ...)`, register destination and memory source.  Capstone
 *   spells both `vmaskmovps`, so nothing but the access pattern can
 *   tell them apart, and it does: the load form marks its destination
 *   register WRITE, the store form marks nothing WRITE at all.
 *
 *   AVX-512 mask-register moves — KMOV{B,W,D,Q}.  Opcode 0F 91 stores
 *   a mask register to m8/16/32/64 and 0F 90 loads one; both print as
 *   `kmovw` and only the load marks its %k destination WRITE.  These
 *   begin `k`, not `mov` after the `v` strip, which is why the original
 *   predicate missed them.  NOTE these are decode-only coverage: QEMU's
 *   i386 TCG front end implements no AVX-512 and no EVEX, so a KMOV can
 *   never be translated and never reaches a trace — the entry keeps the
 *   boundary honest for the offline decoders and for a future front
 *   end, and is not load-bearing for any trace produced today.
 *
 * MASKMOVDQU / MASKMOVQ / VMASKMOVDQU (0F F7) also match the `maskmov`
 * stem -- those three plus the four above are the whole of Capstone's
 * `*maskmov*` mnemonic set -- and that is harmless rather than lucky:
 * they store through an IMPLICIT (%rdi) and Capstone reports two REG
 * operands and no MEM at all, so the caller's `mv_has_mem` test is false
 * and no repair fires.  Their missing implicit store is a separate
 * defect, not this one.
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
    /* AVX-512 mask-register moves are spelled `kmov*`, before any `v`
     * strip could apply. */
    if (g_str_has_prefix(mnem, "kmov")) return true;
    if (mnem[0] == 'v') mnem++;            /* VEX/EVEX prefix */
    /* AVX/AVX2 masked moves: `maskmov{ps,pd}` and `pmaskmov{d,q}` after
     * the strip.  MASKMOVDQU / MASKMOVQ land here too and are inert —
     * they carry no MEM operand for the caller's test to act on. */
    if (g_str_has_prefix(mnem, "maskmov") ||
        g_str_has_prefix(mnem, "pmaskmov")) {
        return true;
    }
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
 * AArch64 cache maintenance BY VIRTUAL ADDRESS: Capstone models no
 * memory operand, so the address the instruction was given goes
 * nowhere.
 *
 * `DC CVAU, Xt` and `IC IVAU, Xt` name an effective address and act on
 * the cache line that contains it.  They move no architectural data --
 * QEMU implements every one of them as ARM_CP_NOP except `IC IVAU`,
 * which under CONFIG_USER_ONLY invalidates translations rather than
 * touching data (target/arm/helper.c:5199, :5259-5310) -- so there is
 * no load and no store to report, and the Arm MRA agrees (mr=0, mw=0).
 * What there IS, and what was being dropped, is the ADDRESS.  A cache
 * model is the consumer of these traces; a cache-maintenance operation
 * delivered to it without the line it operates on is not a reduced
 * record, it is an unusable one.
 *
 * The tracer already has exactly one vocabulary for "an address the
 * guest computed, with no data moved": the synthetic-EA class that
 * `PRFM` / `PREF` / `SYNCI` ride on (decode_synthetic_ea() in
 * champsim_tracer_decode.cc), which mints an address-only memop at
 * execution time from a MEM operand.  It needs a MEM operand to fire.
 * So present Xt as what the architecture says it is -- the base of a
 * memory operand -- and leave the access flags EMPTY, which is the
 * literal truth here and is also the discriminator the synthetic-EA
 * decoder and the static-slot allocator both key on.  The DC ZVA arm
 * above sets WRITE instead, because that one really does store.
 *
 * The set is closed over the operations whose register operand is a
 * VIRTUAL ADDRESS.  Deliberately excluded:
 *
 *   - DC ZVA / DC GZVA: data-writing, handled as stores above.
 *   - DC GVA: writes allocation tags rather than performing cache
 *     maintenance; it belongs with ZVA, not here, and is left alone
 *     until the tag-memory axis has a reference.
 *   - the by-SET/WAY forms (DC ISW / CSW / CISW and the tag variants):
 *     the register holds a set/way/level encoding, not an address.
 *   - the by-PHYSICAL-ADDRESS forms (DC CIPAE / CIGDPAE): the register
 *     holds a PA, and every address on the wire is virtual.
 *   - IC IALLU / IALLUIS, AT, TLBI: no address operand at all (TLBI's
 *     register is a packed VA-range-and-ASID descriptor, not an EA).
 *
 * Revisit when Capstone grows a memory operand for the DC/IC by-VA
 * space; verify with `cstool -d arm64 207b0bd5` (dc cvau, x0), whose
 * operands should then include a MEM form.
 */
static bool cap_aarch64_is_va_cache_maint_sysop(const cs_arm64 *a64, uint8_t n)
{
    if (n < 2) {
        return false;
    }
    const cs_arm64_op *o = &a64->operands[0];

    if (o->type == AARCH64_OP_SYSALIAS &&
        o->sysop.sub_type == AARCH64_OP_DC) {
        switch (o->sysop.alias.dc) {
        case AARCH64_DC_IVAC:
        case AARCH64_DC_CVAC:
        case AARCH64_DC_CVAU:
        case AARCH64_DC_CVAP:
        case AARCH64_DC_CVADP:
        case AARCH64_DC_CIVAC:
        case AARCH64_DC_IGVAC:
        case AARCH64_DC_IGDVAC:
        case AARCH64_DC_CGVAC:
        case AARCH64_DC_CGDVAC:
        case AARCH64_DC_CGVAP:
        case AARCH64_DC_CGDVAP:
        case AARCH64_DC_CGVADP:
        case AARCH64_DC_CGDVADP:
        case AARCH64_DC_CIGVAC:
        case AARCH64_DC_CIGDVAC:
            return true;
        default:
            return false;
        }
    }

    /* IC uses the SYSREG operand form, with the operation in
     * sysop.reg.ic; only IVAU carries an address. */
    if (o->type == AARCH64_OP_SYSREG &&
        o->sysop.sub_type == AARCH64_OP_IC) {
        return o->sysop.reg.ic == AARCH64_IC_IVAU;
    }

    return false;
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
 * sub_type, which states it exactly.  And the register cannot be handed
 * over as a register id, because Capstone has almost none of them --
 * see cap_aarch64_sysreg_class.
 *
 * IC / TLBI reuse AARCH64_OP_SYSREG with a TLBI or IC sub_type for a
 * maintenance operation rather than a register, and are left alone.
 */
/*
 * MSR (immediate) -- the PSTATE fields, and SMSTART / SMSTOP.
 *
 * `msr daifset, #2` is how every AArch64 kernel critical section masks
 * interrupts, and `smstart` / `smstop` exist for nothing but to write
 * SVCR.  Capstone hands all of them over as a SYSALIAS operand carrying
 * a PSTATE-field or SVCR selector -- never a register -- so before this
 * translation the whole family reached the dependency model reading and
 * writing NOTHING AT ALL:
 *
 *   cstool -d aarch64 7f4303d5   smstart sm
 *     op_count: 1
 *     operands[0].type: SYS ALIAS:  operands[0].svcr: BIT = SM
 *   cstool -d aarch64 df4703d5   msr DAIFSet, #7
 *     operands[0].type: SYS ALIAS:  subtype PSTATEIMM0_15 = 0x1e
 *
 * That is the same severance MRS / MSR (register) already has a
 * translation for, on the forms a system trace sees most.
 *
 * Every one of these fields IS an addressable system register in its own
 * right -- DAIF, SPSel, PAN, UAO, DIT, SSBS, TCO, ALLINT, PM, SVCR --
 * and the register form of each writes exactly the state the immediate
 * form writes.  So the immediate form is given the SAME sysreg
 * encoding, which is what makes `msr daifset, #2` and `msr daif, x0`
 * one dependency node instead of two unrelated ones, and routes it
 * through cap_aarch64_sysreg_class like any other MSR.
 *
 * DIRECTION comes from the architecture, not from a convention.
 * msr_imm.xml's `case field of` is explicit:
 *
 *   DAIFSet   PSTATE.D = PSTATE.D OR operand<3>;   ... a read-modify-
 *   DAIFClr   PSTATE.D = PSTATE.D AND NOT(...);        write, so DAIF
 *                                                      is a source too
 *   SPSel / PAN / UAO / DIT / TCO / SSBS / ALLINT / PM
 *             PSTATE.<f> = operand<0>;             ... a whole write of
 *                                                      a one-bit field
 *   SVCRSM    CheckSMEAccess(); SetPSTATE_SM(operand<0>);
 *
 * The SVCR forms read SVCR as well as writing it, and that is not the
 * narrow-write shape R7.1 excludes: SetPSTATE_SM compares the OLD value
 * and calls ResetSVEState() only when the mode actually changes, so
 * whether the Z, P and FFR registers are zeroed is a function of the
 * previous SVCR.  The dependency is real.
 */
static bool cap_aarch64_pstate_field(const cs_arm64_op *o, uint8_t *access,
                                     unsigned *sysreg, const char **name)
{
    switch (o->sysop.sub_type) {
    case AARCH64_OP_SVCR:
        /* smstart / smstop / msr svcrsm|svcrza|svcrsmza, #imm */
        *sysreg = AARCH64_SYSREG_SVCR;
        *name   = "svcr";
        *access = QEMU_PLUGIN_OP_ACC_READ | QEMU_PLUGIN_OP_ACC_WRITE;
        return true;
    case AARCH64_OP_PSTATEIMM0_15:
        switch (o->sysop.alias.pstateimm0_15) {
        case AARCH64_PSTATEIMM0_15_DAIFSET:
        case AARCH64_PSTATEIMM0_15_DAIFCLR:
            *sysreg = AARCH64_SYSREG_DAIF;
            *name   = "daif";
            *access = QEMU_PLUGIN_OP_ACC_READ | QEMU_PLUGIN_OP_ACC_WRITE;
            return true;
        case AARCH64_PSTATEIMM0_15_SPSEL:
            *sysreg = AARCH64_SYSREG_SPSEL;
            *name   = "spsel";
            break;
        case AARCH64_PSTATEIMM0_15_PAN:
            *sysreg = AARCH64_SYSREG_PAN;
            *name   = "pan";
            break;
        case AARCH64_PSTATEIMM0_15_UAO:
            *sysreg = AARCH64_SYSREG_UAO;
            *name   = "uao";
            break;
        case AARCH64_PSTATEIMM0_15_DIT:
            *sysreg = AARCH64_SYSREG_DIT;
            *name   = "dit";
            break;
        case AARCH64_PSTATEIMM0_15_SSBS:
            *sysreg = AARCH64_SYSREG_SSBS;
            *name   = "ssbs";
            break;
        case AARCH64_PSTATEIMM0_15_TCO:
            *sysreg = AARCH64_SYSREG_TCO;
            *name   = "tco";
            break;
        default:
            return false;
        }
        *access = QEMU_PLUGIN_OP_ACC_WRITE;
        return true;
    case AARCH64_OP_PSTATEIMM0_1:
        switch (o->sysop.alias.pstateimm0_1) {
        case AARCH64_PSTATEIMM0_1_ALLINT:
            *sysreg = AARCH64_SYSREG_ALLINT;
            *name   = "allint";
            break;
        case AARCH64_PSTATEIMM0_1_PM:
            *sysreg = AARCH64_SYSREG_PM;
            *name   = "pm";
            break;
        default:
            return false;
        }
        *access = QEMU_PLUGIN_OP_ACC_WRITE;
        return true;
    default:
        /* AT / DC / IC / TLBI / PRFM / BTI ... -- not a register. */
        return false;
    }
}

static bool cap_aarch64_sysreg_operand(const cs_arm64_op *o, uint8_t *access,
                                       unsigned *sysreg, const char **name)
{
    *name = NULL;
    if (o->type == AARCH64_OP_SYSALIAS) {
        return cap_aarch64_pstate_field(o, access, sysreg, name);
    }
    if (o->type != AARCH64_OP_SYSREG &&
        o->type != AARCH64_OP_REG_MRS &&
        o->type != AARCH64_OP_REG_MSR) {
        return false;
    }
    switch (o->sysop.sub_type) {
    case AARCH64_OP_REG_MRS:
        *access = QEMU_PLUGIN_OP_ACC_READ;
        *sysreg = o->sysop.reg.sysreg;
        return true;
    case AARCH64_OP_REG_MSR:
        *access = QEMU_PLUGIN_OP_ACC_WRITE;
        *sysreg = o->sysop.reg.sysreg;
        return true;
    default:
        /* TLBI / IC / an operand Capstone left unclassified. */
        return false;
    }
}

/*
 * The architectural role of an AArch64 system register.
 *
 * This is the boundary-side translation table the register enum cannot
 * provide.  Capstone 6.0.0-Alpha7's aarch64_sysreg has 1214 entries; its
 * aarch64_reg has a same-named id for exactly two of them, NZCV (5) and
 * FPCR (3).  There is no AARCH64_REG_TPIDR_EL0, no AARCH64_REG_FPSR, no
 * AARCH64_REG_FPMR, and nothing at all for the EL1 control space --
 * `cstool -d arm64 44d03bd5` (mrs x4, tpidr_el0) reports the operand as
 * AARCH64_OP_SYSREG with sysop.reg.sysreg = 0xde82 and no register.
 * Capstone does hold the names internally
 * (AArch64SysReg_lookupSysRegByEncoding in arch/AArch64/AArch64BaseInfo.h)
 * but exports neither them nor any encoding->register mapping; cstool
 * itself prints the bare number.  Revisit on a Capstone bump: if the
 * register enum grows these, they become ordinary REG operands and this
 * table shrinks to nothing.
 *
 * WHY THE WHOLE FILE IS CLASSIFIED AND NOT JUST THE HOT NAMES.  Every
 * role that is not named here folds onto the residual generic ID, and
 * on AArch64 that residual is the entire privileged register space.  A
 * consumer given one ID for 1,200 registers is told that a TTBR write,
 * a VBAR write, a PMU counter read and a timer read are all the same
 * dependency, and an instruction that genuinely reads one of them
 * acquires an edge from every write to the other 1,199.  That is the
 * mapping defect the MIPS CP0 split closed for that ISA; this is the
 * same split for this one, into the same groups -- the sets whose
 * members a consumer must order against the SAME event.
 *
 * THE GROUPING IS BY ENCODING, not by a list of 1,214 names, because
 * the AArch64 system space IS organised that way: op0 separates the
 * debug/trace file from the rest, and CRn separates the functional
 * groups within it.  A name list would be a transcription of that
 * structure with 1,214 chances to mistype it.  The exceptions -- the
 * places where one CRn holds two groups -- are named as CRm/op1/op2
 * tests and are the only hand-maintained rows.  The classification of
 * all 1,213 defined encodings is checked against the decoder itself,
 * not against this comment: see the a64_split census in the commit that
 * introduced it.
 *
 *   op0 = 2  is the debug, trace and record file in its entirety.
 *            CRn 0-3 and 7 are the breakpoint / watchpoint registers
 *            and the ETM trace unit, CRn 8 the branch-record buffer;
 *            CRn 9 splits (CRm < 12 is BRBE control, CRm >= 12 the
 *            system PMU) and CRn 14 is the system PMU counters.
 *   op0 = 3  is everything else, by CRn:
 *            0   identification -- MIDR, MPIDR, the ID_AA64* and
 *                AArch32 ID space, MVFR, CTR, DCZID.  A read of one
 *                depends on nothing, which is why they may not share
 *                an ID with writable state.  CSSELR/CCSIDR/CLIDR are
 *                the exception: CCSIDR reads back whatever CSSELR
 *                selected, so they are a window and its selector.
 *            1   execution control.  CPACR_EL1 and CPTR_EL{2,3} are
 *                the FP/SIMD/SVE/SME ENABLE gate and take their own
 *                role; ZCR/SMCR are vector configuration; TRFCR,
 *                TRCITECR, MDCR and SDER32 are debug/trace control;
 *                SCTLR, HCR, SCR and the fine-grained trap registers
 *                stay residual -- nothing in the model reads them, and
 *                putting them beside the FP gate would order every FP
 *                instruction behind an SCTLR write.
 *            2   translation control -- TTBR, TCR, VTTBR, VTCR, the
 *                granule protection tables.  Not the pointer-auth keys
 *                (op1 = 0, CRm 1-3), not RNDR/RNDRRS, and not the
 *                guarded control stack: GCSPR_ELx IS a shadow-stack
 *                pointer and takes that role, the same one x86 CET SSP
 *                and RISC-V ssp already carry.
 *            3   AArch32 and fine-grained trap control -- residual.
 *            4   PSTATE and exception-return state.  SPSR/ELR are
 *                exception state; FPCR/FPSR/FPMR the FP control word;
 *                DSPSR/DLR the debug-state save registers; SVCR vector
 *                configuration.  The PSTATE bit selectors (SPSel, PAN,
 *                UAO, DIT, DAIF, ...) are residual: they are not a
 *                register file a consumer renames.
 *            5   fault status -- ESR, AFSR, TFSR, plus the RAS error
 *                record window (op1 = 0, CRm 3-5) which is a selector
 *                and a window like CSSELR/CCSIDR.
 *            6   fault address (CRm 0) and the PMSA MPU regions.
 *            7   PAR_EL1, the address-translation result.
 *            9   performance monitors and statistical profiling, minus
 *                the trace buffer (CRm 11).
 *            10  memory attributes, permission indirection, LORegions,
 *                memory encryption.  MPAM is partitioning, not
 *                translation, and stays residual.
 *            12  exception vectors (VBAR) and interrupt/SError status.
 *                The GIC CPU and hypervisor interfaces stay residual:
 *                they are device state reached through a system
 *                register, not part of the exception file a fault
 *                writes.
 *            13  CONTEXTIDR (translation context) and the activity
 *                monitors.  TPIDR_EL0/TPIDRRO_EL0 are the user thread
 *                pointer; TPIDR_EL{1,2,3} deliberately are NOT -- the
 *                kernel per-CPU base is a different register serving a
 *                different purpose that merely shares a name stem.
 *            14  the generic timer (CRm < 8) and the PMU event
 *                counters.
 *
 * Reproducers (`cstool -d arm64 <hex>`):
 *   200420d5  msr nzcv, x0        sysreg 0xda10  FLAGS
 *   00443bd5  mrs x0, fpcr        sysreg 0xda20  FPCTRL
 *   44d03bd5  mrs x4, tpidr_el0   sysreg 0xde82  THREADPTR
 *   401038d5  mrs x0, cpacr_el1   sysreg 0xc082  FPENABLE
 *   002038d5  mrs x0, ttbr0_el1   sysreg 0xc100  MMU
 *   004038d5  mrs x0, spsr_el1    sysreg 0xc200  EXC
 *   e0003bd5  mrs x0, dczid_el0   sysreg 0xd807  IDENT
 */
#define A64_SYSREG_OP0(e) (((e) >> 14) & 0x3)
#define A64_SYSREG_OP1(e) (((e) >> 11) & 0x7)
#define A64_SYSREG_CRN(e) (((e) >> 7) & 0xf)
#define A64_SYSREG_CRM(e) (((e) >> 3) & 0xf)
#define A64_SYSREG_OP2(e) ((e) & 0x7)

static uint8_t cap_aarch64_sysreg_class(unsigned sysreg)
{
    unsigned op1 = A64_SYSREG_OP1(sysreg);
    unsigned crn = A64_SYSREG_CRN(sysreg);
    unsigned crm = A64_SYSREG_CRM(sysreg);
    unsigned op2 = A64_SYSREG_OP2(sysreg);

    switch (sysreg) {
    case AARCH64_SYSREG_NZCV:
        return QEMU_PLUGIN_SYSREG_FLAGS;
    case AARCH64_SYSREG_FPCR:
        /*
         * THE CONTROL WORD IS NOT THE STATUS WORD, and on AArch64 the two
         * are different architectural registers: FPCR (S3_3_C4_C4_0) holds
         * the rounding mode, the FP exception masks and the flush-to-zero
         * and default-NaN controls; FPSR (S3_3_C4_C4_1) holds the accrued
         * exception flags and QC.  Every FP and AdvSIMD arithmetic
         * instruction READS FPCR and WRITES FPSR, so one role for both
         * gives each one a read-after-write edge from the one before it
         * through a register nothing modified -- the defect
         * QEMU_PLUGIN_SYSREG_FPCW was added to remove, and whose own
         * definition (qemu-plugin.h) already names "AArch64 FPCR" as its
         * occupant.  Only x86 was routed when the role landed; this is
         * the AArch64 half of the same repair.
         *
         * FPMR stays on FPCTRL.  It is the FP8 mode register, written by
         * MSR and read by the FP8 forms, and the ABI's own text assigns
         * it there; it takes no false edge from FPSR because no FP
         * instruction writes it.
         */
        return QEMU_PLUGIN_SYSREG_FPCW;
    case AARCH64_SYSREG_FPSR:
    case AARCH64_SYSREG_FPMR:
        return QEMU_PLUGIN_SYSREG_FPCTRL;
    case AARCH64_SYSREG_TPIDR_EL0:
    case AARCH64_SYSREG_TPIDRRO_EL0:
        return QEMU_PLUGIN_SYSREG_THREADPTR;
    default:
        break;
    }

    if (A64_SYSREG_OP0(sysreg) == 2) {
        /* The debug / trace / record file. */
        if (crn == 9) {
            /* BRBE control (CRm 0-2) against the system PMU (CRm 12-14). */
            return crm >= 12 ? QEMU_PLUGIN_SYSREG_PERF
                             : QEMU_PLUGIN_SYSREG_DBG;
        }
        if (crn == 14) {
            return QEMU_PLUGIN_SYSREG_PERF;
        }
        return QEMU_PLUGIN_SYSREG_DBG;
    }

    switch (crn) {
    case 0:
        /* CCSIDR / CLIDR / CCSIDR2 (op1 1) read back what CSSELR
         * (op1 2) selected; the rest of CRn 0 is read-only ID. */
        if ((op1 == 1 && crm == 0 && op2 <= 2) ||
            (op1 == 2 && crm == 0 && op2 == 0)) {
            return QEMU_PLUGIN_SYSREG_CACHE;
        }
        return QEMU_PLUGIN_SYSREG_IDENT;
    case 1:
        if (crm == 0 && op2 == 2) {
            return QEMU_PLUGIN_SYSREG_FPENABLE;   /* CPACR_EL1 / _EL12 */
        }
        if (crm == 1 && op2 == 2) {
            return QEMU_PLUGIN_SYSREG_FPENABLE;   /* CPTR_EL2 / CPTR_EL3 */
        }
        if (crm == 2 && (op2 == 0 || op2 == 6)) {
            return QEMU_PLUGIN_SYSREG_VECCTRL;    /* ZCR_ELx / SMCR_ELx */
        }
        if (crm == 2 && (op2 == 1 || op2 == 3)) {
            return QEMU_PLUGIN_SYSREG_DBG;        /* TRFCR / TRCITECR */
        }
        if ((crm == 1 || crm == 3) && op2 == 1 && (op1 == 4 || op1 == 6)) {
            return QEMU_PLUGIN_SYSREG_DBG;        /* MDCR / SDER32 */
        }
        return QEMU_PLUGIN_SYSREG_OTHER;
    case 2:
        if (op1 == 0 && crm >= 1 && crm <= 3) {
            return QEMU_PLUGIN_SYSREG_OTHER;      /* pointer-auth keys */
        }
        if (crm == 4) {
            return QEMU_PLUGIN_SYSREG_OTHER;      /* RNDR / RNDRRS */
        }
        if (crm == 5) {
            /* GCSPR_ELx (op2 1) is the guarded-control-stack pointer;
             * GCSCR / GCSCRE0 are its control registers. */
            return op2 == 1 ? QEMU_PLUGIN_SYSREG_SHADOWSTK
                            : QEMU_PLUGIN_SYSREG_OTHER;
        }
        return QEMU_PLUGIN_SYSREG_MMU;
    case 4:
        if (crm == 0) {
            return QEMU_PLUGIN_SYSREG_EXC;        /* SPSR_ELx / ELR_ELx */
        }
        if (crm == 3 && op1 == 4 && op2 <= 3) {
            return QEMU_PLUGIN_SYSREG_EXC;        /* the AArch32 banked SPSRs */
        }
        if (crm == 4) {
            /* The FPCR/FPSR/FPMR alias encodings, split the same way the
             * canonical ones are above: op2 0 is the CONTROL word. */
            return op2 == 0 ? QEMU_PLUGIN_SYSREG_FPCW
                            : QEMU_PLUGIN_SYSREG_FPCTRL;
        }
        if (crm == 5) {
            return QEMU_PLUGIN_SYSREG_DBG;        /* DSPSR_EL0 / DLR_EL0 */
        }
        if (crm == 2 && op2 == 2 && op1 == 3) {
            return QEMU_PLUGIN_SYSREG_VECCTRL;    /* SVCR */
        }
        return QEMU_PLUGIN_SYSREG_OTHER;
    case 5:
        if (op1 == 0 && crm >= 3 && crm <= 5) {
            return QEMU_PLUGIN_SYSREG_CACHE;      /* RAS error records */
        }
        return QEMU_PLUGIN_SYSREG_EXC;
    case 6:
        return crm == 0 ? QEMU_PLUGIN_SYSREG_EXC   /* FAR / PFAR / HPFAR */
                        : QEMU_PLUGIN_SYSREG_MMU;  /* PMSA MPU regions */
    case 7:
        return QEMU_PLUGIN_SYSREG_MMU;             /* PAR_EL1 */
    case 9:
        return crm == 11 ? QEMU_PLUGIN_SYSREG_DBG  /* trace buffer */
                         : QEMU_PLUGIN_SYSREG_PERF;
    case 10:
        if (crm == 5 || crm == 6) {
            return QEMU_PLUGIN_SYSREG_OTHER;       /* MPAM partitioning */
        }
        if (crm == 4) {
            if (op1 == 0 && (op2 <= 3 || op2 == 7)) {
                return QEMU_PLUGIN_SYSREG_MMU;     /* LORegions */
            }
            return QEMU_PLUGIN_SYSREG_OTHER;       /* MPAM */
        }
        return QEMU_PLUGIN_SYSREG_MMU;
    case 12:
        if (crm == 0 && op2 == 0) {
            return QEMU_PLUGIN_SYSREG_EXC;         /* VBAR_ELx */
        }
        if (crm == 1) {
            return QEMU_PLUGIN_SYSREG_EXC;         /* ISR / DISR / VDISR */
        }
        return QEMU_PLUGIN_SYSREG_OTHER;           /* GIC CPU interface */
    case 13:
        if (crm == 0) {
            if (op2 == 1 && (op1 == 0 || op1 == 4 || op1 == 5)) {
                return QEMU_PLUGIN_SYSREG_MMU;     /* CONTEXTIDR_ELx */
            }
            return QEMU_PLUGIN_SYSREG_OTHER;
        }
        return QEMU_PLUGIN_SYSREG_PERF;            /* activity monitors */
    case 14:
        return crm < 8 ? QEMU_PLUGIN_SYSREG_TIMER
                       : QEMU_PLUGIN_SYSREG_PERF;
    default:
        return QEMU_PLUGIN_SYSREG_OTHER;
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
 * Which register file an AArch64 operand names.
 *
 * Capstone's aarch64_reg enum is laid out one contiguous run per file:
 * B0..B31 at 15, D0 at 47, H0 at 79, P0 at 111, Q0 at 143, S0 at 175,
 * W0 at 207, X0 at 238, Z0 at 267, and the SME tiles ZAB0..ZT0 at 299.
 * A 128-bit V register arrives as its Q form.  The file separates
 * instruction FORMS that share a mnemonic and do not share a register
 * contract -- `fabs d2, d1` from `fabs v4.4s, v3.4s`, `sqadd v5.4s, ...`
 * from `sqadd z4.h, ...` -- which is what the FP status/control contract
 * below turns on.
 */
typedef enum {
    CAP_A64_FILE_NONE = 0,
    CAP_A64_FILE_GPR,
    CAP_A64_FILE_ADVSIMD,   /* B / H / S / D / Q (the V file) */
    CAP_A64_FILE_SVE_Z,
    CAP_A64_FILE_SVE_P,
    CAP_A64_FILE_ZA,
    CAP_A64_FILE_OTHER,
} CapA64RegFile;

static CapA64RegFile cap_aarch64_reg_file(unsigned reg)
{
    if ((reg >= AARCH64_REG_B0 && reg < AARCH64_REG_B0 + 32) ||
        (reg >= AARCH64_REG_D0 && reg < AARCH64_REG_D0 + 32) ||
        (reg >= AARCH64_REG_H0 && reg < AARCH64_REG_H0 + 32) ||
        (reg >= AARCH64_REG_Q0 && reg < AARCH64_REG_Q0 + 32) ||
        (reg >= AARCH64_REG_S0 && reg < AARCH64_REG_S0 + 32)) {
        return CAP_A64_FILE_ADVSIMD;
    }
    if (reg >= AARCH64_REG_P0 && reg < AARCH64_REG_P0 + 32) {
        return CAP_A64_FILE_SVE_P;
    }
    if (reg >= AARCH64_REG_Z0 && reg < AARCH64_REG_Z0 + 32) {
        return CAP_A64_FILE_SVE_Z;
    }
    if (reg == AARCH64_REG_ZA || reg == AARCH64_REG_Z_MATRIX ||
        (reg >= AARCH64_REG_ZAB0 && reg <= AARCH64_REG_ZT0)) {
        /* ZAB0 .. ZT0 is one contiguous run holding every tile spelling
         * (ZAB0, ZAD0..7, ZAH0..1, ZAQ0..15, ZAS0..3) and the ZT0
         * lookup-table register. */
        return CAP_A64_FILE_ZA;
    }
    if ((reg >= AARCH64_REG_W0 && reg < AARCH64_REG_W0 + 31) ||
        (reg >= AARCH64_REG_X0 && reg < AARCH64_REG_X0 + 29) ||
        reg == AARCH64_REG_WZR || reg == AARCH64_REG_XZR ||
        reg == AARCH64_REG_LR || reg == AARCH64_REG_SP ||
        reg == AARCH64_REG_WSP) {
        return CAP_A64_FILE_GPR;
    }
    return reg ? CAP_A64_FILE_OTHER : CAP_A64_FILE_NONE;
}

/* The register files this instruction's operands name, as a set. */
typedef struct {
    bool advsimd;
    bool sve;               /* a Z or a P operand */
    bool za;
    bool arranged;          /* an operand carries a `.4s`-style arrangement */
} CapA64FileSet;

static void cap_aarch64_note_file(CapA64FileSet *fs, unsigned reg)
{
    switch (cap_aarch64_reg_file(reg)) {
    case CAP_A64_FILE_ADVSIMD:
        fs->advsimd = true;
        break;
    case CAP_A64_FILE_SVE_Z:
    case CAP_A64_FILE_SVE_P:
        fs->sve = true;
        break;
    case CAP_A64_FILE_ZA:
        fs->za = true;
        break;
    default:
        break;
    }
}

/*
 * @out is consulted alongside the operand array because the SME array
 * accumulate forms name ZA only in the IMPLICIT lists -- Capstone
 * reports `fmla za.d[w10, 5, vgx2], { z8.d, z9.d }, z1.d[1]` with four
 * operands, none of them ZA, and `za` in regs_read / regs_write.  Read
 * from the operands alone the form looks like ordinary SVE FMLA and
 * takes the FPSR write it must not have.
 */
static CapA64FileSet cap_aarch64_file_set(const cs_arm64 *a64, uint8_t n,
                                          const qemu_plugin_insn_info *out)
{
    CapA64FileSet fs = { false, false, false, false };

    for (uint8_t i = 0; i < out->n_regs_read; i++) {
        cap_aarch64_note_file(&fs, out->regs_read_id[i]);
    }
    for (uint8_t i = 0; i < out->n_regs_write; i++) {
        cap_aarch64_note_file(&fs, out->regs_write_id[i]);
    }
    for (uint8_t i = 0; i < n; i++) {
        const cs_arm64_op *o = &a64->operands[i];
        unsigned reg = 0;

        if (o->type == AARCH64_OP_REG) {
            reg = o->reg;
        } else if (o->type == AARCH64_OP_MEM) {
            reg = o->mem.base;
        } else if (o->type == AARCH64_OP_SME) {
            /* An SME array operand names its tile in sme.tile, not in
             * .reg; without this the ZA accumulate forms read as plain
             * SVE and take an FPSR write they do not have. */
            reg = o->sme.tile;
        } else {
            continue;
        }
        cap_aarch64_note_file(&fs, reg);
        if (o->vas != AARCH64LAYOUT_INVALID) {
            fs.arranged = true;
        }
    }
    return fs;
}

/*
 * The FP control and status word, as an operand contract.
 *
 * AArch64 splits the word in two: FPCR carries the rounding mode, the
 * flush-to-zero and default-NaN controls, FEAT_AFP's AH / NEP / FIZ and
 * FEAT_EBF16's EBF, and is an INPUT to the FP datapath; FPSR carries the
 * cumulative IEEE exception bits IXC / IOC / OFC / UFC / IDC and the
 * Advanced SIMD saturation bit QC, and is an OUTPUT of it.  The generic
 * register space folds both onto REG_FCSR (see
 * champsim_tracer_generic_ids.h -- the fold is deliberate and predates
 * this), so what this contract settles is DIRECTION: which side of the
 * instruction the word sits on.
 *
 * Capstone reports part of the input half and none of the output half.
 * Its aarch64_reg enum has AARCH64_REG_FPCR and no AARCH64_REG_FPSR at
 * all, so the FPSR write cannot be named as itself and rides the FPCR
 * id, which reaches the same generic register either way.
 *
 * Three rules, each keyed on the operand FORM rather than the mnemonic
 * alone, because one mnemonic covers forms with different contracts:
 *
 *  1. The FP datapath reads FPCR.  Capstone reports this on most FP
 *     instructions and misses a scattering -- FCMP carries it, FCCMP
 *     does not; SQDMULH carries it and has no business doing so.  Scalar
 *     FABS / FNEG read it too, through a different door: fabs_float's
 *     execute ASL opens with `FPCRType fpcr = FPCR[]` and asks
 *     IsMerging(fpcr), so FPCR.NEP decides whether the result merges
 *     with Vd.  The Advanced SIMD and SVE forms of those two mnemonics
 *     have no such read -- their ASL is
 *     `Elem[result,e,esize] = FPAbs(Elem[operand,e,esize])` and nothing
 *     else -- and QEMU agrees: gen_gvec_fabs() is a `gvec_andi` of the
 *     sign mask while the scalar path is selected on s->fpcr_ah
 *     (translate-a64.c).  The rule this replaces put the read on all
 *     three forms.
 *
 *     FMOV IS NOT ONE OF THEM, ON ANY ENCODING.  It shares the merging
 *     door's shape and does not go through it, and QEMU says so in one
 *     line: FABS and FNEG are dispatched through do_fp1_scalar_int_2fn,
 *     which passes merging=true and writes through
 *     write_fp_{d,s,h}reg_merging(); FMOV is
 *     `TRANS(FMOV_s, do_fp1_scalar_int, a, &f_scalar_fmov, false)`
 *     (translate-a64.c) -- merging=FALSE, a plain write_fp_dreg.  The
 *     commit that introduced the parameter states the reason as its
 *     justification for needing one: "this requires an extra parameter
 *     to do_fp1_scalar_int(), since FMOV scalar does not have the
 *     merging behaviour" (64339259a9).
 *
 *     THE OTHER FMOV FORMS, so the rule is not an over-correction that
 *     happens to be right about one encoding.  There are four families
 *     and NONE of them reads FPCR in QEMU's modelling:
 *       FMOV (register)   `fmov s0, s1`  -- TRANS(FMOV_s, ...) above.
 *       FMOV (general)    `fmov s0, w0`, `fmov x0, d0`, `fmov v0.d[1],
 *                         x0` -- trans_FMOV_{hx,sw,dx,ux,xh,ws,xd,xu},
 *                         eight functions that are a zero-extend and a
 *                         write_fp_dreg, or a load out of the register
 *                         file into cpu_reg.  This is the encoding the
 *                         defect was measured on: a BIT COPY between
 *                         files performs no conversion, so there is no
 *                         rounding mode to consult and no result to
 *                         merge.
 *       FMOV (scalar imm) `fmov s0, #1.0` -- trans_FMOVI_s: vfp_expand_imm
 *                         at translate time, write_fp_dreg.
 *       FMOV (vector imm) `fmov v0.4s, #1.0` -- trans_FMOVI_v_*, a gvec
 *                         dup of a translate-time constant.
 *     The SVE spelling `fmov z0.s, p0/m, #1.0` is an alias of FCPY and
 *     reaches this function under its own operand shape; it has no read
 *     either.  So the withdrawal below is unconditional on the operand
 *     form, unlike FABS's and FNEG's, and that asymmetry is the point.
 *
 *  2. Integer saturating arithmetic reads NOTHING and writes FPSR.QC.
 *     `sqadd`, `sqdmulh`, `uqsub` and the rest compute
 *     `(Elem[result,e,esize], sat) = SatQ(...); if sat then FPSR.QC='1'`
 *     -- no FPCR read on any path.  The rule this replaces had the
 *     direction exactly backwards, naming the status word as a SOURCE
 *     and dropping the write.  The QC write belongs to the Advanced
 *     SIMD forms alone: the SVE and SVE2 spellings of the same
 *     mnemonics (`sqadd z4.h, z3.h, z2.h`, `sqdecd x3, vl2`) saturate
 *     without touching FPSR, so the scope is by register file, not by
 *     name.
 *
 *  3. Everything that can raise an IEEE exception writes FPSR: the whole
 *     FP datapath except the operations that only move or alter bits
 *     (FMOV / FABS / FNEG / FCSEL / FDUP / FEXPA / FTSSEL), the BF16
 *     dot-product and matrix family, which the architecture defines as
 *     neither generating exceptions nor updating FPSR, and the SME ZA
 *     accumulate forms, whose ASL routes through FPAdd_ZA rather than
 *     FPAdd for exactly that reason.
 *
 * Rule 3 ADDS what the tracer did not record before, and the direction
 * is deliberate.  The comment this replaces declined to model the
 * cumulative-status half on the grounds that a status write chains every
 * FP instruction to the last one.  It does -- FPSR.IXC really is an
 * accumulator, and the chain is the architecture's, not the model's.  R5
 * governs: a write that only sometimes changes the value is still a
 * write, and whether an FP status accumulator is worth scheduling
 * against is the consumer's decision, not the tracer's.
 */
static bool cap_aarch64_is_saturating_int(const char *mnem)
{
    /* sq* / uq* -- SQADD, SQDMULH, UQSHL, SQXTN, ... -- plus the two
     * mixed-sign accumulates SUQADD / USQADD.  No FP mnemonic on this
     * ISA begins `sq` or `uq` (square root is FSQRT), so the two-letter
     * test cannot catch one. */
    if ((mnem[0] == 's' || mnem[0] == 'u') && mnem[1] == 'q') {
        return true;
    }
    return g_str_has_prefix(mnem, "suqadd") || g_str_has_prefix(mnem, "usqadd");
}

/*
 * The BF16 dot-product and matrix family: defined not to generate
 * floating-point exceptions and not to update FPSR.  Only these.  The
 * FEAT_B16B16 arithmetic -- BFADD, BFSUB, BFMUL, BFMLA, BFMLS, BFMAX,
 * BFMIN, BFCLAMP -- and the widening multiply-accumulates BFMLALB /
 * BFMLALT / BFMLSLB / BFMLSLT round through FPMulAdd and do update it,
 * as do the conversions BFCVT / BFCVTN.  All of them, this family
 * included, READ FPCR: FPCR.EBF selects the BF16 arithmetic mode.
 */
static bool cap_aarch64_is_bf16_nonieee(const char *mnem)
{
    static const char *const bf[] = {
        "bfdot", "bfmmla", "bfmopa", "bfmops", "bfvdot",
    };
    for (size_t i = 0; i < ARRAY_SIZE(bf); i++) {
        if (g_str_has_prefix(mnem, bf[i])) {
            return true;
        }
    }
    return false;
}

/*
 * An IEEE floating-point operation: one whose result is produced by the
 * FP datapath and can therefore raise IXC / IOC / OFC / UFC / IDC.
 *
 * The `f`-initial mnemonics minus the ones that only move bits, the
 * BF16 arithmetic, and the integer/FP conversions spelled from the
 * integer side (SCVTF / UCVTF).
 */
static bool cap_aarch64_is_ieee_fp_op(const char *mnem)
{
    static const char *const bitonly[] = {
        "fmov", "fabs", "fneg", "fcsel", "fdup", "fmovi", "fcpy",
        "fexpa", "ftssel",
    };
    for (size_t i = 0; i < ARRAY_SIZE(bitonly); i++) {
        if (g_strcmp0(mnem, bitonly[i]) == 0) {
            return false;
        }
    }
    if (g_str_has_prefix(mnem, "scvtf") || g_str_has_prefix(mnem, "ucvtf")) {
        return true;
    }
    if (mnem[0] == 'b' && mnem[1] == 'f') {
        /* BFI / BFXIL / BFC / BFM are bitfield moves that merely share
         * the prefix; they are integer instructions. */
        if (g_strcmp0(mnem, "bfi") == 0 || g_strcmp0(mnem, "bfxil") == 0 ||
            g_strcmp0(mnem, "bfc") == 0 || g_strcmp0(mnem, "bfm") == 0) {
            return false;
        }
        return !cap_aarch64_is_bf16_nonieee(mnem);
    }
    return mnem[0] == 'f';
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

/* Append @reg to the implicit-write list unless it is already there. */
static void cap_aarch64_add_implicit_write(qemu_plugin_insn_info *out,
                                           csh handle, unsigned int reg)
{
    for (uint8_t i = 0; i < out->n_regs_write; i++) {
        if (out->regs_write_id[i] == reg) {
            return;
        }
    }
    if (out->n_regs_write >= QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS) {
        return;
    }
    cap_copy_reg_name(out->regs_write[out->n_regs_write],
                      QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                      handle, reg, CS_ARCH_ARM64);
    out->regs_write_id[out->n_regs_write] = reg;
    out->n_regs_write++;
}

/*
 * Drop @reg from the implicit-read list if Capstone put it there, for
 * the forms where Capstone reports a read the instruction does not
 * perform and the operand walk would otherwise mint a dependency.
 */
static void cap_aarch64_drop_implicit_read(qemu_plugin_insn_info *out,
                                           unsigned int reg)
{
    for (uint8_t i = 0; i < out->n_regs_read; i++) {
        if (out->regs_read_id[i] != reg) {
            continue;
        }
        for (uint8_t j = (uint8_t)(i + 1); j < out->n_regs_read; j++) {
            out->regs_read_id[j - 1] = out->regs_read_id[j];
            memcpy(out->regs_read[j - 1], out->regs_read[j],
                   QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ);
        }
        out->n_regs_read--;
        return;
    }
}

static void cap_aarch64_add_sysreg(qemu_plugin_insn_info *out,
                                   unsigned sysreg, const char *name,
                                   uint8_t access);

/*
 * Record the FPSR write as FPSR.
 *
 * Capstone's aarch64_reg enum has no AARCH64_REG_FPSR, so the write used
 * to ride AARCH64_REG_FPCR: the same generic register either way, and
 * for the dependency edge that was enough.  It is not enough for the
 * VALUE.  A destination's content is read from the QEMU register the
 * operand names, so an FPSR write named FPCR published the CONTROL
 * word -- constant across a run that never writes it -- in place of the
 * cumulative exception state the instruction had just changed.
 * Measured on `fdiv s0, s1, s2`: the trace showed %fcsr = 0 while the
 * guest's own `mrs x10, fpsr` two instructions later returned 0x10
 * (IXC).
 *
 * The system-register operand carries what the register enum cannot:
 * AARCH64_SYSREG_FPSR is a real encoding, cap_aarch64_sysreg_class()
 * already maps it (with FPCR and FPMR) to QEMU_PLUGIN_SYSREG_FPCTRL, so
 * the generic id is unchanged, and the name reaches QEMU's descriptor
 * list.  Idempotent, like every other appended system register.
 */
static void cap_aarch64_add_fpsr_write(qemu_plugin_insn_info *out)
{
    cap_aarch64_add_sysreg(out, AARCH64_SYSREG_FPSR, "fpsr",
                           QEMU_PLUGIN_OP_ACC_WRITE);
}

/*
 * Apply the FP status/control contract described above to one decoded
 * instruction: repair the FPCR reads Capstone reports inconsistently,
 * withdraw the ones it reports for an operand shape that has none, and
 * add the FPSR write it has no register id to express.
 */
static void cap_aarch64_fp_status_contract(const cs_insn *insn,
                                           const cs_arm64 *a64,
                                           csh handle,
                                           qemu_plugin_insn_info *out)
{
    const char *mnem = insn->mnemonic;
    uint8_t n;
    CapA64FileSet fs;
    bool reads_fpcr = false;
    bool writes_fpsr = false;

    if (!mnem || !mnem[0]) {
        return;
    }
    n = MIN(a64->op_count, QEMU_PLUGIN_INSN_DETAIL_MAX_OPS);
    fs = cap_aarch64_file_set(a64, n, out);

    if (cap_aarch64_is_saturating_int(mnem)) {
        /* Rule 2.  Withdraw whatever Capstone reported -- it names FPCR
         * on SQDMULH and not on SQADD, and neither reads it. */
        cap_aarch64_drop_implicit_read(out, AARCH64_REG_FPCR);
        if (fs.advsimd && !fs.sve && !fs.za) {
            cap_aarch64_add_fpsr_write(out);
        }
        return;
    }

    /* Rule 1: the input half. */
    if (cap_aarch64_is_ieee_fp_op(mnem) ||
        cap_aarch64_is_bf16_nonieee(mnem)) {
        reads_fpcr = true;
    }
    if (g_strcmp0(mnem, "fmov") == 0) {
        /* NO FMOV FORM READS FPCR -- see the FMOV note above.  The
         * merging door FABS and FNEG go through is shut for this
         * mnemonic, so whatever Capstone reported is withdrawn on every
         * form rather than on the vector and SVE ones only. */
        cap_aarch64_drop_implicit_read(out, AARCH64_REG_FPCR);
    } else if (g_str_has_prefix(mnem, "fabs") ||
               g_str_has_prefix(mnem, "fneg")) {
        /* Scalar float form only -- no arrangement specifier, no Z or P
         * operand. */
        if (!fs.arranged && !fs.sve) {
            reads_fpcr = true;
        } else {
            cap_aarch64_drop_implicit_read(out, AARCH64_REG_FPCR);
        }
    }

    /* Rule 3: the output half.  The SME ZA accumulate forms route
     * through FPAdd_ZA and leave FPSR alone. */
    if (cap_aarch64_is_ieee_fp_op(mnem) && !fs.za) {
        writes_fpsr = true;
    }

    if (reads_fpcr) {
        cap_aarch64_add_implicit_read(out, handle, AARCH64_REG_FPCR);
    }
    if (writes_fpsr) {
        cap_aarch64_add_fpsr_write(out);
    }
}

/*
 * The FP / SIMD / SVE / SME execution-enable gate, as a source.
 *
 * R7.4: "if a write to the CSR would block that instruction due to a
 * dependency, it should be recorded".  CPACR_EL1.FPEN, CPTR_EL2.FPEN
 * and CPTR_EL3.TFP decide whether an FP, Advanced SIMD, SVE or SME
 * instruction executes or takes a trap, so a pending write to one of
 * them has to resolve before any of those instructions may proceed.
 * That is an edge a renaming regfile must respect, which is the test
 * R7 states, and it is the same fact this boundary already records on
 * RISC-V for wfi/mstatus.TW and the cbo/Zicfiss envcfg triple.
 *
 * ALL THREE ARE NAMED, not just the one the current exception level
 * consults, for the reason R4 gives and the RISC-V envcfg triple
 * already follows: which gate applies is a runtime value and a static
 * register set names every candidate.  They share one generic ID
 * (REG_SYSFPEN) because they are one behaviour group -- see
 * cap_aarch64_sysreg_class -- so the generic register set is the same
 * whichever of them a run actually traps on; what the three operands
 * carry that one would not is the identification, in reg_id and
 * reg_name, of which register a consumer is looking at.
 *
 * WHICH INSTRUCTIONS.  The gate belongs to exactly the instructions the
 * architecture routes through CheckFPAdvSIMDEnabled / CheckSVEEnabled /
 * CheckSMEEnabled, and that population is the FP, SIMD, SVE and SME
 * extensions in their entirety.  The discriminator is Capstone's
 * per-ENCODING feature list, not the mnemonic and not the operand
 * register files: one mnemonic spans forms in different extensions
 * (`fadd d0, d1, d2` is FPARMv8, `fadd z0.d, p0/m, z0.d, z1.d` is SVE,
 * `fadd za.d[w8, 0, vgx2], {z0.d, z1.d}` is SME2), and the SVE count
 * and vector-length forms (CNTB, RDVL) are gated while naming nothing
 * but a GPR.  Feature membership is instruction TAXONOMY, which is what
 * Capstone is kept for; it is not operand or access-flag information,
 * so nothing here reaches the dependency model through a Capstone
 * decision about registers.
 *
 * The list is the FP/SIMD/vector/matrix extensions.  The integer and
 * system extensions that sit beside them in the enum -- CRC, CSSC, LSE,
 * RAS, SPE, MOPS, MTE, PAUTH -- are NOT gated and are not here.
 */
static bool cap_aarch64_feature_is_fp_gated(uint16_t g)
{
    switch (g) {
    /* Scalar FP and Advanced SIMD, and the V-register crypto. */
    case AARCH64_FEATURE_HASFPARMV8:
    case AARCH64_FEATURE_HASNEON:
    case AARCH64_FEATURE_HASFULLFP16:
    case AARCH64_FEATURE_HASFP16FML:
    case AARCH64_FEATURE_HASFUSEAES:
    case AARCH64_FEATURE_HASAES:
    case AARCH64_FEATURE_HASSHA2:
    case AARCH64_FEATURE_HASSHA3:
    case AARCH64_FEATURE_HASSM4:
    case AARCH64_FEATURE_HASDOTPROD:
    case AARCH64_FEATURE_HASRDM:
    case AARCH64_FEATURE_HASCOMPLXNUM:
    case AARCH64_FEATURE_HASJS:
    case AARCH64_FEATURE_HASFRINT3264:
    case AARCH64_FEATURE_HASBF16:
    case AARCH64_FEATURE_HASB16B16:
    case AARCH64_FEATURE_HASMATMULINT8:
    case AARCH64_FEATURE_HASMATMULFP32:
    case AARCH64_FEATURE_HASMATMULFP64:
    case AARCH64_FEATURE_HASLUT:
    case AARCH64_FEATURE_HASFAMINMAX:
    /* FEAT_FP8 and its dot/FMA companions. */
    case AARCH64_FEATURE_HASFP8:
    case AARCH64_FEATURE_HASFP8FMA:
    case AARCH64_FEATURE_HASFP8DOT2:
    case AARCH64_FEATURE_HASFP8DOT4:
    case AARCH64_FEATURE_HASSSVE_FP8FMA:
    case AARCH64_FEATURE_HASSSVE_FP8DOT2:
    case AARCH64_FEATURE_HASSSVE_FP8DOT4:
    /* SVE. */
    case AARCH64_FEATURE_HASSVE:
    case AARCH64_FEATURE_HASSVE2:
    case AARCH64_FEATURE_HASSVE2P1:
    case AARCH64_FEATURE_HASSVE2AES:
    case AARCH64_FEATURE_HASSVE2SM4:
    case AARCH64_FEATURE_HASSVE2SHA3:
    case AARCH64_FEATURE_HASSVE2BITPERM:
    /* SME. */
    case AARCH64_FEATURE_HASSME:
    case AARCH64_FEATURE_HASSME2:
    case AARCH64_FEATURE_HASSME2P1:
    case AARCH64_FEATURE_HASSMEF64F64:
    case AARCH64_FEATURE_HASSMEF16F16:
    case AARCH64_FEATURE_HASSMEFA64:
    case AARCH64_FEATURE_HASSMEI16I64:
    case AARCH64_FEATURE_HASSMEF8F16:
    case AARCH64_FEATURE_HASSMEF8F32:
    case AARCH64_FEATURE_HASSME_LUTV2:
    /* The "either extension provides it" spellings. */
    case AARCH64_FEATURE_HASSVEORSME:
    case AARCH64_FEATURE_HASSVE2ORSME:
    case AARCH64_FEATURE_HASSVE2ORSME2:
    case AARCH64_FEATURE_HASSVE2P1_OR_HASSME:
    case AARCH64_FEATURE_HASSVE2P1_OR_HASSME2:
    case AARCH64_FEATURE_HASSVE2P1_OR_HASSME2P1:
    case AARCH64_FEATURE_HASNEONORSME:
        return true;
    default:
        return false;
    }
}

static bool cap_aarch64_is_fp_gated(const cs_insn *insn)
{
    const cs_detail *d = insn->detail;

    if (!d) {
        return false;
    }
    for (uint8_t i = 0; i < d->groups_count; i++) {
        if (cap_aarch64_feature_is_fp_gated(d->groups[i])) {
            return true;
        }
    }
    return false;
}

/*
 * Append a system register the ENCODING implies but no operand names.
 *
 * The AArch64 counterpart of cap_riscv_add_csr: an MRS/MSR operand is
 * the only way a system register reaches the plugin from this
 * disassembler, so a register that is architecturally part of an
 * instruction's footprint without being printed can only be added
 * here.  Idempotent on the sysreg encoding, and a no-op once the
 * operand array is full.
 */
static void cap_aarch64_add_sysreg_class(qemu_plugin_insn_info *out,
                                         unsigned sysreg, const char *name,
                                         uint8_t access, uint8_t cls)
{
    qemu_plugin_operand *op;
    char buf[32];

    for (uint8_t i = 0; i < out->n_operands; i++) {
        if (out->operands[i].type == QEMU_PLUGIN_OP_SYSREG
            && out->operands[i].reg_id == (uint16_t)sysreg) {
            out->operands[i].access |= access;
            return;
        }
    }
    if (out->n_operands >= QEMU_PLUGIN_INSN_DETAIL_MAX_OPS) {
        return;
    }
    if (!name) {
        /* An operation rather than a register: name it by its encoding,
         * which is how the architecture names it too. */
        snprintf(buf, sizeof(buf), "s%u_%u_c%u_c%u_%u",
                 (sysreg >> 14) & 0x3u, (sysreg >> 11) & 0x7u,
                 (sysreg >> 7) & 0xFu, (sysreg >> 3) & 0xFu, sysreg & 0x7u);
        name = buf;
    }
    op = &out->operands[out->n_operands];
    memset(op, 0, sizeof(*op));
    op->type   = QEMU_PLUGIN_OP_SYSREG;
    op->access = access;
    op->reg_id = (uint16_t)sysreg;
    op->sysreg_class = cls;
    op->scale  = 1;
    g_strlcpy(op->reg_name, name, QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ);
    out->n_operands++;
}

static void cap_aarch64_add_sysreg(qemu_plugin_insn_info *out,
                                   unsigned sysreg, const char *name,
                                   uint8_t access)
{
    cap_aarch64_add_sysreg_class(out, sysreg, name, access,
                                 cap_aarch64_sysreg_class(sysreg));
}

/*
 * ZT0 has a SECOND gate, and it is not CPACR.
 *
 * SMCR_ELx.EZT0 decides on its own whether an instruction that touches
 * the SME2 lookup-table register traps -- CheckSMEZT0Enabled reads it
 * after CheckSMEEnabled has already passed -- so by the same R7.4 test
 * it is a second source on exactly the ZT0 forms.  It is NOT the
 * FP-enable gate and does not share its ID: SMCR is vector
 * configuration (it also carries the streaming vector length), which is
 * the role REG_VCTRL names, and folding the two would order every FP
 * instruction behind a vector-length write.
 */
static bool cap_aarch64_touches_zt0(const cs_arm64 *a64, uint8_t n,
                                    const qemu_plugin_insn_info *out)
{
    for (uint8_t i = 0; i < n; i++) {
        const cs_arm64_op *o = &a64->operands[i];

        if ((o->type == AARCH64_OP_REG && o->reg == AARCH64_REG_ZT0) ||
            (o->type == AARCH64_OP_SME && o->sme.tile == AARCH64_REG_ZT0)) {
            return true;
        }
    }
    for (uint8_t i = 0; i < out->n_regs_read; i++) {
        if (out->regs_read_id[i] == AARCH64_REG_ZT0) {
            return true;
        }
    }
    for (uint8_t i = 0; i < out->n_regs_write; i++) {
        if (out->regs_write_id[i] == AARCH64_REG_ZT0) {
            return true;
        }
    }
    return false;
}

static void cap_aarch64_add_fp_enable_gate(const cs_insn *insn,
                                           const cs_arm64 *a64, uint8_t n,
                                           qemu_plugin_insn_info *out)
{
    if (!cap_aarch64_is_fp_gated(insn)) {
        return;
    }
    cap_aarch64_add_sysreg(out, AARCH64_SYSREG_CPACR_EL1, "cpacr_el1",
                           QEMU_PLUGIN_OP_ACC_READ);
    cap_aarch64_add_sysreg(out, AARCH64_SYSREG_CPTR_EL2, "cptr_el2",
                           QEMU_PLUGIN_OP_ACC_READ);
    cap_aarch64_add_sysreg(out, AARCH64_SYSREG_CPTR_EL3, "cptr_el3",
                           QEMU_PLUGIN_OP_ACC_READ);
    if (cap_aarch64_touches_zt0(a64, n, out)) {
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_SMCR_EL1, "smcr_el1",
                               QEMU_PLUGIN_OP_ACC_READ);
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_SMCR_EL2, "smcr_el2",
                               QEMU_PLUGIN_OP_ACC_READ);
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_SMCR_EL3, "smcr_el3",
                               QEMU_PLUGIN_OP_ACC_READ);
    }
}

/* Xn as a Capstone register id.  X29 and X30 are spelled FP and LR. */
static unsigned cap_aarch64_xreg(unsigned n)
{
    if (n == 29) {
        return AARCH64_REG_FP;
    }
    if (n == 30) {
        return AARCH64_REG_LR;
    }
    if (n == 31) {
        return AARCH64_REG_XZR;
    }
    return AARCH64_REG_X0 + n;
}

/*
 * LS64 -- the single-copy atomic 64-BYTE load and store.
 *
 * LD64B returns 512 bits into EIGHT consecutive X registers, Xt..Xt+7,
 * and ST64B / ST64BV / ST64BV0 send a 512-bit payload held in the same
 * eight.  Capstone reports one:
 *
 *   cstool -d aarch64 22d03ff8   ld64b x2, [x1]
 *     operands[0] x2 WRITE ... "Registers modified: x2"
 *
 * so seven eighths of the dataflow of the widest data-moving
 * instruction in the ISA was missing -- a consumer of x5 after an
 * `ld64b x2, [x1]` read a register no instruction in the trace wrote.
 * The register list is a property of the ENCODING, not of Capstone's
 * view of it: ld64b.xml names X[t+i] for i = 0 to 7 and the encoding
 * constrains Xt to be even, so the seven companions follow from Rt with
 * nothing to infer.
 *
 * A modelling gap rather than a bug -- Capstone's operand ABI has one
 * register per operand -- so no revision test.
 */
static void cap_aarch64_ls64_contract(const cs_insn *insn, csh handle,
                                      qemu_plugin_insn_info *out)
{
    uint32_t w;
    unsigned rt;
    bool load;

    switch (insn->id) {
    case AARCH64_INS_LD64B:
        load = true;
        break;
    case AARCH64_INS_ST64B:
    case AARCH64_INS_ST64BV:
    case AARCH64_INS_ST64BV0:
        load = false;
        break;
    default:
        return;
    }
    if (insn->size != 4) {
        return;
    }
    w = ldl_le_p(insn->bytes);
    rt = w & 0x1Fu;                    /* the payload base, always Rt */
    if (rt & 1u) {
        return;                        /* not an architectural encoding */
    }
    for (unsigned i = 1; i < 8; i++) {
        if (rt + i > 30) {
            break;
        }
        if (load) {
            cap_aarch64_add_implicit_write(out, handle,
                                           cap_aarch64_xreg(rt + i));
        } else {
            cap_aarch64_add_implicit_read(out, handle,
                                          cap_aarch64_xreg(rt + i));
        }
    }
}

/*
 * System registers an AArch64 encoding IMPLIES but never prints.
 *
 * Capstone reports the operands an instruction spells.  A dozen AArch64
 * instructions take a system register as a real operand without naming
 * it in the assembly, and every one of them reached the dependency model
 * without it: the tag-generation instructions do not depend on the tag
 * exclusion mask, ERET does not depend on the exception-return state it
 * returns to, and a barrier that updates the deferred-error register
 * writes nothing.  Each of those is an edge a renaming regfile must
 * respect, which is the test R7 states, and it is the same shape
 * cap_riscv_add_csr already covers for that ISA.
 *
 * Each row is the architecture's own statement, from the MRA page named
 * beside it -- not an inference from the mnemonic:
 *
 *   ADDG / SUBG   addg.xml: "Tags specified in GCR_EL1.Exclude are
 *                 excluded from the possible outputs when modifying the
 *                 Logical Address Tag."
 *   IRG           irg.xml: the same exclusion, plus RGSR_EL1, which is
 *                 the random-allocation seed the instruction both reads
 *                 and advances.
 *   LDGM / STGM   ldgm.xml: "a naturally aligned block of N Allocation
 *                 Tags, where the size of N is identified in
 *                 GMID_EL1.BS".
 *   STZGM         stzgm.xml: the same, "where the size of N is
 *                 identified in DCZID_EL0.BS".
 *   ERET, ERETAA, ERETAB
 *                 the exception-return state: ELR_ELx is where execution
 *                 resumes and SPSR_ELx is the PSTATE it restores.
 *   ESB           esb.xml: "an error synchronization event that might
 *                 also update DISR_EL1".
 *
 * ALL THREE exception levels are named for ELR / SPSR, for the reason R4
 * gives and the FP-enable triple above already follows: which one
 * applies is a runtime value, and a static register set names every
 * candidate.  They share one generic ID, so the generic register set is
 * the same whichever the run uses; what the three carry that one would
 * not is the identification in reg_id and reg_name.
 *
 * This is a modelling gap in Capstone rather than a bug in it -- there
 * is no operand to report -- so unlike the SMSTOP workaround below it
 * carries no revision test.
 */
static void cap_aarch64_implicit_sysregs(const cs_insn *insn,
                                         qemu_plugin_insn_info *out)
{
    const uint8_t rd = QEMU_PLUGIN_OP_ACC_READ;
    const uint8_t wr = QEMU_PLUGIN_OP_ACC_WRITE;

    switch (insn->id) {
    case AARCH64_INS_ADDG:
    case AARCH64_INS_SUBG:
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_GCR_EL1, "gcr_el1", rd);
        break;
    case AARCH64_INS_IRG:
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_GCR_EL1, "gcr_el1", rd);
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_RGSR_EL1, "rgsr_el1",
                               rd | wr);
        break;
    case AARCH64_INS_LDGM:
    case AARCH64_INS_STGM:
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_GMID_EL1, "gmid_el1", rd);
        break;
    case AARCH64_INS_STZGM:
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_DCZID_EL0, "dczid_el0",
                               rd);
        break;
    case AARCH64_INS_ST64BV0:
        /* st64bv0.xml: the value in ACCDATA_EL1 replaces bits<31:0> of
         * the first register of the 512-bit payload, so the register is
         * part of the data the instruction sends. */
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_ACCDATA_EL1,
                               "accdata_el1", rd);
        break;
    case AARCH64_INS_ERET:
    case AARCH64_INS_ERETAA:
    case AARCH64_INS_ERETAB:
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_ELR_EL1, "elr_el1", rd);
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_ELR_EL2, "elr_el2", rd);
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_ELR_EL3, "elr_el3", rd);
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_SPSR_EL1, "spsr_el1", rd);
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_SPSR_EL2, "spsr_el2", rd);
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_SPSR_EL3, "spsr_el3", rd);
        break;
    default:
        break;
    }
}

/*
 * SYS and SYSL -- the system-instruction group, whose whole result is
 * system state the operand list never names.
 *
 * `at s1e1r, x16` translates an address and leaves the answer in
 * PAR_EL1.  `sysl x5, #1, c2, c3, #4` moves system state INTO x5.  The
 * GCS push and pop forms move the guarded-control-stack pointer.  Every
 * one of them arrived recording only the Xt operand, so the instruction
 * whose entire purpose is to produce system state produced none, and --
 * worse -- SYSL's destination arrived as a source, because Capstone
 * reports operands[0].access READ for it (`cstool -d aarch64 852329d5`:
 * "operands[0].type: REG = x5, operands[0].access: READ", and
 * "Registers read: x5" with nothing modified).  A trace in which the
 * consumer of `sysl x5, ...` reads an x5 no instruction wrote is the
 * same severance the MRS/MSR translation already closed on the register
 * form.
 *
 * ENCODING, not alias id, for the same reason as the MSR (immediate)
 * contract: the family is a single fixed pattern and no Capstone alias
 * table stands in front of it.
 *
 *   SYS    1101 0101 0000 1 op1 CRn CRm op2 Rt
 *   SYSL   1101 0101 0010 1 op1 CRn CRm op2 Rt
 *
 * That one test covers the printed aliases too -- AT, DC, IC, TLBI, CFP,
 * CPP, DVP, COSP, TRCIT, BRB and the GCS forms are all SYS or SYSL
 * encodings -- which is why they need no per-alias row.
 *
 * The ROLE is taken from CRn:CRm the way cap_aarch64_sysreg_class takes
 * it from a register encoding, because the SYS space is organised the
 * same way.  It is deliberately not `cap_aarch64_sysreg_class(enc)`:
 * that function reads an encoding as a REGISTER address, and CRn 7 as a
 * register is the address-translation result while CRn 7 as an operation
 * is mostly cache maintenance.  Reading an operation with a register
 * table would put every DC CIVAC in the same dependency group as
 * PAR_EL1.
 *
 * Where the operation HAS an architectural result register, that
 * register is what reg_id names: AT produces PAR_EL1, and the GCS forms
 * read and write GCSPR_ELx -- both push and pop, since each has to know
 * where the stack pointer is before it can move it.  Elsewhere there is
 * no register to name and reg_id carries the SYS-space encoding, which
 * is the architecture's own identifier for the operation.
 */
static uint8_t cap_aarch64_sysinstr_class(unsigned crn, unsigned crm,
                                          unsigned op2, unsigned *reg,
                                          const char **name)
{
    *reg = 0;
    *name = NULL;
    if (crn == 8) {
        return QEMU_PLUGIN_SYSREG_MMU;             /* TLBI */
    }
    if (crn != 7) {
        return QEMU_PLUGIN_SYSREG_OTHER;
    }
    switch (crm) {
    case 8:
    case 9:
        /* AT -- the address-translation result. */
        *reg  = AARCH64_SYSREG_PAR_EL1;
        *name = "par_el1";
        return QEMU_PLUGIN_SYSREG_MMU;
    case 7:
        /* GCSPUSHM / GCSPUSHX / GCSPOPM / GCSPOPCX / GCSPOPX /
         * GCSSS1 / GCSSS2 -- the guarded control stack pointer, the
         * same role x86 CET SSP and RISC-V ssp carry. */
        *reg  = AARCH64_SYSREG_GCSPR_EL1;
        *name = "gcspr_el1";
        return QEMU_PLUGIN_SYSREG_SHADOWSTK;
    case 2:
        /* TRCIT (op2 7) and BRB (op2 4) -- trace and branch records. */
        return (op2 == 4 || op2 == 7) ? QEMU_PLUGIN_SYSREG_DBG
                                      : QEMU_PLUGIN_SYSREG_OTHER;
    case 3:
        /* CFP / CPP / DVP / COSP -- prediction restriction by context.
         * Predictor state, not a register file. */
        return QEMU_PLUGIN_SYSREG_OTHER;
    default:
        /* IC and DC: cache and cache-like maintenance. */
        return QEMU_PLUGIN_SYSREG_CACHE;
    }
}

static void cap_aarch64_sysinstr_contract(csh handle, const cs_insn *insn,
                                          qemu_plugin_insn_info *out)
{
    uint32_t w;
    unsigned op1, crn, crm, op2, enc, reg;
    const char *name;
    uint8_t cls, access;
    bool sysl;

    if (insn->size != 4) {
        return;
    }
    w = ldl_le_p(insn->bytes);
    if ((w & 0xFFF80000u) == 0xD5080000u) {
        sysl = false;
    } else if ((w & 0xFFF80000u) == 0xD5280000u) {
        sysl = true;
    } else {
        return;
    }
    op1 = (w >> 16) & 0x7u;
    crn = (w >> 12) & 0xFu;
    crm = (w >> 8) & 0xFu;
    op2 = (w >> 5) & 0x7u;

    cls = cap_aarch64_sysinstr_class(crn, crm, op2, &reg, &name);
    if (!reg) {
        /* No architectural result register: identify the OPERATION by
         * its own encoding, in the shape aarch64_sysreg uses (op0 = 1 is
         * the SYS instruction space). */
        enc = (1u << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2;
        reg = enc;
    }
    /* SYS produces system state; SYSL consumes it into Xt.  The GCS
     * forms do both: each reads GCSPR_ELx to find the stack and writes
     * it back moved. */
    if (cls == QEMU_PLUGIN_SYSREG_SHADOWSTK) {
        access = QEMU_PLUGIN_OP_ACC_READ | QEMU_PLUGIN_OP_ACC_WRITE;
    } else {
        access = sysl ? QEMU_PLUGIN_OP_ACC_READ : QEMU_PLUGIN_OP_ACC_WRITE;
    }
    cap_aarch64_add_sysreg_class(out, reg, name, access, cls);

    if (!sysl) {
        /*
         * Rt == 31 on a SYS-format encoding is the architectural zero
         * register, not an absent operand: the execute ASL reads X[t]
         * unconditionally, so at t = 31 it reads XZR.  Capstone prints
         * the no-operand alias (`gcspushx`, `ic ialluis`) and reports no
         * register at all, which is the same alias loss R7.3 ruled on --
         * REG_ZERO exists and is not to be dropped.
         */
        if ((w & 0x1Fu) == 31) {
            cap_aarch64_add_implicit_read(out, handle, AARCH64_REG_XZR);
        }
        return;
    }
    /*
     * SYSL's Xt is its DESTINATION.  Capstone reports it READ, and the
     * Rt field is at 4:0 exactly as it is for SYS, so the operand is
     * identified by the field rather than by trusting the access bits
     * that are wrong.
     *
     * Rt == 31 IS NOT A "NO REGISTER" FORM, whatever the earlier reading
     * here said.  SYS's Xt is optional and its absence is spelled Rt = 31,
     * which is why the branch above puts XZR in that instruction's READ
     * list; SYSL has no such variant.  ARM DDI 0487C.a, SYSL (C6-980):
     * "<Xt>  Is the 64-bit name of the general-purpose DESTINATION
     * register, encoded in the 'Rt' field", with the whole operation
     * being "X[t] = AArch64.SysInstrWithResult(1, sys_op1, sys_crn,
     * sys_crm, sys_op2);".  At Rt = 31 that destination is XZR and the
     * result is discarded -- a write nobody keeps, never a read.  So the
     * zero register takes the SAME correction every other Rt takes, and
     * the field is what selects it, exactly as above.
     */
    unsigned rt = w & 0x1Fu;
    for (uint8_t i = 0; i < out->n_operands; i++) {
        qemu_plugin_operand *op = &out->operands[i];
        if (op->type == QEMU_PLUGIN_OP_REG
            && (op->reg_id == cap_aarch64_xreg(rt)
                || op->reg_id == AARCH64_REG_W0 + rt)) {
            op->access = QEMU_PLUGIN_OP_ACC_WRITE;
        }
    }
    for (uint8_t i = 0; i < out->n_regs_read; i++) {
        if (out->regs_read_id[i] == cap_aarch64_xreg(rt)) {
            for (uint8_t j = i; j + 1 < out->n_regs_read; j++) {
                out->regs_read_id[j] = out->regs_read_id[j + 1];
                memcpy(out->regs_read[j], out->regs_read[j + 1],
                       QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ);
            }
            out->n_regs_read--;
            break;
        }
    }
}

/*
 * THE ALWAYS-CONDITIONS: B.cond and BC.cond with cond = AL or NV read no
 * flag at all.
 *
 * A64 gives the whole conditional-branch space one operation --
 * "if ConditionHolds(cond) then BranchTo(PC[] + offset, BranchType_JMP);"
 * (ARM DDI 0487C.a, B.cond) -- and ConditionHolds is where the flags are
 * or are not read (shared/functions/system/ConditionHolds, J1-6366):
 *
 *     case cond<3:1> of
 *         when '000' result = (PSTATE.Z == '1');
 *         ...
 *         when '111' result = TRUE;              // AL
 *     // Condition flag values in the set '111x' indicate always true
 *     if cond<0> == '1' && cond != '1111' then result = !result;
 *
 * The '111' arm names no PSTATE field, and the inversion that follows is
 * explicitly excluded for '1111', so at cond = 0b1110 (AL) and 0b1111 (NV)
 * NZCV is architecturally NOT AN INPUT.  Capstone reports the read anyway:
 * its condition-code operand carries the flags for every cond alike, and the
 * dependency it mints is on a register the branch never consults.  QEMU draws
 * the same line the ARM ARM does -- trans_B_cond() comments "0xe and 0xf are
 * both 'always' conditions" and emits gen_goto_tb() with no arm_gen_test_cc()
 * -- so with the operand walk's read arm removed the wire loses a source that
 * was never there, and 6,144 encodings in the swept population said so.
 *
 * READ OFF THE ENCODING, not off the mnemonic or the instruction id.  The
 * space is 0101010 0 imm19 o0 cond: o0 = 0 is B.cond and o0 = 1 is BC.cond
 * (FEAT_HBC), the cond field is at 3:0 in both, and a spelling table would
 * be a second decoder to keep in step with this one.
 */
static void cap_aarch64_always_cond_contract(const cs_insn *insn,
                                             qemu_plugin_insn_info *out)
{
    uint32_t w;

    if (insn->size != 4) {
        return;
    }
    w = ldl_le_p(insn->bytes);
    if ((w & 0xFF000000u) != 0x54000000u) {
        return;
    }
    /* cond<3:1> == '111': AL (0b1110) and NV (0b1111). */
    if ((w & 0xEu) != 0xEu) {
        return;
    }
    cap_aarch64_drop_implicit_read(out, AARCH64_REG_NZCV);
}

/*
 * ESB -- the HINT encoding that updates the deferred-error register.
 *
 * ESB is `hint #16` and Capstone reports it as AARCH64_INS_HINT, so the
 * discriminator is the immediate, read off the encoding (CRm:op2) rather
 * than off the alias id.
 */
static void cap_aarch64_hint_contract(csh handle, const cs_insn *insn,
                                      qemu_plugin_insn_info *out)
{
    uint32_t w;
    unsigned imm;

    if (insn->id != AARCH64_INS_HINT || insn->size != 4) {
        return;
    }
    w = ldl_le_p(insn->bytes);
    /* HINT: 1101 0101 0000 0011 0010 CRm op2 11111 */
    if ((w & 0xFFFFF01Fu) != 0xD503201Fu) {
        return;
    }
    imm = (((w >> 8) & 0xFu) << 3) | ((w >> 5) & 0x7u);
    if (imm == 16) {                       /* ESB */
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_DISR_EL1, "disr_el1",
                               QEMU_PLUGIN_OP_ACC_WRITE);
    } else if (imm == 40) {                /* CHKFEAT, `chkfeat x16` */
        /*
         * hint.xml: CRm:op2 == '0101 000' is SystemHintOp_CHKFEAT, whose
         * execute ASL is `X[16, 64] = AArch64.ChkFeat(X[16, 64])`.  The
         * register is nowhere in the printed operand list -- Capstone
         * reports `hint #0x28` with a single IMM operand -- so the
         * instruction that exists to hand software a feature mask in x16
         * depended on nothing and produced nothing.
         */
        cap_aarch64_add_implicit_read(out, handle, AARCH64_REG_X16);
        cap_aarch64_add_implicit_write(out, handle, AARCH64_REG_X16);
    }
}

/*
 * Capstone 6.0.0-Alpha7 bug: SMSTOP has an EMPTY alias operand set.
 *
 *   cstool -d  aarch64 7f4203d5   smstop sm   ->  no op_count line at all
 *   cstool -r -d aarch64 7f4203d5   smstop sm   ->  op_count: 2,
 *                                    operands[0].svcr: BIT = SM
 *
 * The REAL operand set carries the SVCR selector and the ALIAS operand
 * set does not, so with the default (alias) detail the instruction
 * arrives with zero operands.  The same hole swallows the argument-less
 * SMSTART / SMSTOP (`smstart` == SVCRSMZA, 7f4703d5): op_count 0.
 * SMSTART with an explicit SM or ZA argument is unaffected, which is
 * what makes it a defect in Capstone's alias operand table rather than
 * a modelling decision.  Reportable upstream as such; the fix there is
 * to give AARCH64_INS_ALIAS_SMSTOP the operand list SMSTART already
 * has.  Re-verify on a Capstone bump with the two cstool lines above.
 *
 * The workaround does not go through the alias id.  It reads the
 * ENCODING, which is the one description of an MSR (immediate) that no
 * Capstone table stands in front of:
 *
 *   31                    19  18 16 15 12 11  8 7  5 4   0
 *   1101 0101 0000 0        | op1  | 0100 | CRm | op2 | 11111
 *
 * op1:op2 selects the PSTATE field exactly as msr_imm.xml's
 * `case op1:op2 of` does, and for the SME forms (op1 = 3, op2 = 3) the
 * CRm<3:1> field distinguishes SVCRSM / SVCRZA / SVCRSMZA.  Deriving it
 * here also makes the operand-side translation self-checking: both
 * paths name the same sysreg encoding, and cap_aarch64_add_sysreg is
 * idempotent on it, so agreement merges and cannot double-count.
 *
 * The SME forms additionally carry the enable gate.  msr_imm.xml calls
 * CheckSMEAccess() before SetPSTATE_SM, and R7.4 makes that read a real
 * source -- but Capstone attaches this encoding NO feature group at all
 * ("Groups: privilege" and nothing else), so cap_aarch64_is_fp_gated,
 * which keys off the feature list, cannot see it.  The gate is added
 * from the encoding for the same reason the register is.
 */
static void cap_aarch64_msr_imm_contract(const cs_insn *insn,
                                         qemu_plugin_insn_info *out)
{
    uint32_t w;
    unsigned op1, crm, op2, sel;
    unsigned sysreg;
    const char *name;
    uint8_t access = QEMU_PLUGIN_OP_ACC_WRITE;

    if (insn->size != 4) {
        return;
    }
    w = ldl_le_p(insn->bytes);
    /* MSR (immediate): the fixed bits, CRn == 0b0100 and Rt == 0b11111. */
    if ((w & 0xFFF80000u) != 0xD5000000u ||
        ((w >> 12) & 0xFu) != 0x4u || (w & 0x1Fu) != 0x1Fu) {
        return;
    }
    op1 = (w >> 16) & 0x7u;
    crm = (w >> 8) & 0xFu;
    op2 = (w >> 5) & 0x7u;
    sel = (op1 << 3) | op2;

    switch (sel) {
    case (0 << 3) | 3: sysreg = AARCH64_SYSREG_UAO;   name = "uao";   break;
    case (0 << 3) | 4: sysreg = AARCH64_SYSREG_PAN;   name = "pan";   break;
    case (0 << 3) | 5: sysreg = AARCH64_SYSREG_SPSEL; name = "spsel"; break;
    case (1 << 3) | 0:
        /* CRm '000x' is ALLINT, '001x' is PM; nothing else is defined. */
        if ((crm >> 1) == 0) {
            sysreg = AARCH64_SYSREG_ALLINT;
            name = "allint";
        } else if ((crm >> 1) == 1) {
            sysreg = AARCH64_SYSREG_PM;
            name = "pm";
        } else {
            return;
        }
        break;
    case (3 << 3) | 1: sysreg = AARCH64_SYSREG_SSBS;  name = "ssbs";  break;
    case (3 << 3) | 2: sysreg = AARCH64_SYSREG_DIT;   name = "dit";   break;
    case (3 << 3) | 3:
        /* SVCRSM / SVCRZA / SVCRSMZA -- smstart, smstop. */
        if ((crm >> 1) < 1 || (crm >> 1) > 3) {
            return;
        }
        sysreg = AARCH64_SYSREG_SVCR;
        name = "svcr";
        /* SetPSTATE_SM zeroes the vector state only when the mode
         * CHANGES, so the previous value is a genuine source. */
        access = QEMU_PLUGIN_OP_ACC_READ | QEMU_PLUGIN_OP_ACC_WRITE;
        break;
    case (3 << 3) | 4: sysreg = AARCH64_SYSREG_TCO;   name = "tco";   break;
    case (3 << 3) | 6:
    case (3 << 3) | 7:
        /* DAIFSet / DAIFClr: OR / AND-NOT of the four bits. */
        sysreg = AARCH64_SYSREG_DAIF;
        name = "daif";
        access = QEMU_PLUGIN_OP_ACC_READ | QEMU_PLUGIN_OP_ACC_WRITE;
        break;
    default:
        return;
    }

    cap_aarch64_add_sysreg(out, sysreg, name, access);
    if (sysreg == AARCH64_SYSREG_SVCR) {
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_CPACR_EL1, "cpacr_el1",
                               QEMU_PLUGIN_OP_ACC_READ);
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_CPTR_EL2, "cptr_el2",
                               QEMU_PLUGIN_OP_ACC_READ);
        cap_aarch64_add_sysreg(out, AARCH64_SYSREG_CPTR_EL3, "cptr_el3",
                               QEMU_PLUGIN_OP_ACC_READ);
    }
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
 * CAS/LD<op> atomic, and vector structure forms report a non-zero
 * access.  Non-zero is not the same as correct: the EXCLUSIVE forms
 * report a superset -- see cap_aarch64_exclusive_mem_access below,
 * which corrects them.  This inference is only about the rows that
 * report NOTHING.
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
 * Capstone-6.0.0-Alpha7 reports READ|WRITE on the MEM operand of the
 * load-exclusive AND store-exclusive forms alike.  Both are supersets of
 * what the instruction does: a load-exclusive reads memory and marks the
 * exclusive monitor, and marking the monitor is not a memory write; a
 * store-exclusive conditionally writes and returns its status in a
 * register, and reads nothing.
 *
 * Measured with the wrap's own cstool (build/subprojects/capstone), MEM
 * operand access:
 *
 *   ldaxr x0,[x1]    c85ffc20   READ|WRITE   should be READ
 *   ldxr  x0,[x1]    c85f7c20   READ|WRITE   should be READ
 *   ldaxp x0,xzr,[x1] c87ffc20  READ|WRITE   should be READ
 *   ldar  x0,[x1]    c8dffc20   READ         correct -- the control that
 *                                            shows this is specific to the
 *                                            exclusives, not to acquire /
 *                                            release forms in general
 *   ldadd x0,x0,[x1] f8200020   READ|WRITE   correct, genuinely both
 *
 * It matters because the operand walker mints one slot per access bit off
 * the SAME MEM operand, so a load-exclusive template declares a STORE slot
 * the instruction never fills -- a dependency edge the guest never has,
 * handed to whatever models the trace.  Measured on a probe before this
 * correction: the ldaxr entry declared `st[%gp1]` with no address and every
 * execution delivered only `ld=`, never `st=`.
 *
 * ONLY THE LOAD SIDE IS CORRECTED, and that is a measurement, not a
 * conservatism.  Capstone reports READ|WRITE on the STORE-exclusives too,
 * and architecturally that is also a superset -- a store-exclusive writes
 * and returns status, it does not read.  But QEMU implements STXR/STLXR
 * with a cmpxchg helper that performs a REAL load, and the plugin's memop
 * callback sees it: the stlxr entry declares `ld[%gp1](0x410160)` WITH an
 * address and every execution delivers a matching `ld=`.  Declaring
 * WRITE-only there would leave that delivered access with no slot to land
 * in -- trading a phantom slot for an orphaned memop, which is worse.  The
 * trace records what executed.
 *
 * That leaves a real question this correction does not answer: QEMU's
 * store-exclusive reads memory where hardware does not, so a consumer sees
 * a read-modify-write for an instruction that architecturally only writes.
 * That is an emulation artefact, not a decoding one, and it needs its own
 * decision rather than being papered over here.
 *
 * The LSE read-modify-write families (swp / cas / ld<op> / st<op>) really
 * do both and must not be touched, which is why this matches the exclusive
 * mnemonics exactly rather than reasoning from "ld" / "st".
 *
 * Unlike cap_aarch64_infer_mem_access, this corrects a WRONG non-zero
 * access, so it cannot be folded into that helper's access == 0 guard.
 * Returns 0 when the mnemonic is not a load-exclusive, leaving Capstone's
 * answer alone.  Revisit on a Capstone bump: if a future release reports
 * READ here, this becomes dead code and should go.
 */
static unsigned cap_aarch64_exclusive_mem_access(const char *mnem)
{
    /* Load-exclusive: ldxr/ldaxr/ldxp/ldaxp and their b/h widths. */
    static const char *const load_ex[] = {
        "ldxr", "ldaxr", "ldxp", "ldaxp",
    };

    if (!mnem || !mnem[0]) {
        return 0;
    }
    for (size_t i = 0; i < ARRAY_SIZE(load_ex); i++) {
        if (g_str_has_prefix(mnem, load_ex[i])) {
            return QEMU_PLUGIN_OP_ACC_READ;
        }
    }
    return 0;
}

/*
 * AArch64 tag-multiple stores: Capstone reports the destination as READ.
 *
 * `STGM Xt, [Xn]` and `STZGM Xt, [Xn]` write a whole tag-granule block.
 * QEMU makes it literal -- trans_STGM / trans_STZGM call
 * gen_helper_stgm_tags / gen_helper_stzgm_tags, and STZGM additionally
 * runs gen_helper_dc_zva over the data (target/arm/tcg/translate-a64.c),
 * so both are unambiguously WRITES.  Capstone 6.0.0-Alpha7 gives their
 * sole MEM operand CS_AC_READ, which the operand walker then turns into
 * a load lane: a store recorded as a load, the one shape of disagreement
 * this project treats as disqualifying.  The Arm MRA convicts STZGM
 * directly (mr=0, mw=1).
 *
 * The single-tag forms of the same family -- STG / STZG / ST2G / STZ2G
 * -- are reported correctly (CS_AC_WRITE) and are not touched.  LDGM and
 * LDG are genuine reads and are not touched either.
 *
 * Revisit / remove when Capstone is bumped past 6.0.0; verify with
 * `cstool -d arm64 220020d9` (stzgm x2, [x1]), whose MEM operand must
 * then show WRITE instead of READ.  Use a `cstool` built from
 * `subprojects/capstone` (capstone.wrap's pinned revision), not a system
 * package, or run `capstone_workaround_probe`
 * (`cap_aarch64_tag_multiple_store` case); see docs/troubleshooting.rst.
 */
static bool cap_aarch64_tag_multiple_store(const char *mnem)
{
    return mnem && (!strcmp(mnem, "stgm") || !strcmp(mnem, "stzgm"));
}

/*
 * Extract per-operand detail for AArch64 into the plugin operand struct.
 */
/*
 * Operand directions Capstone states the wrong way round on AArch64.
 *
 * Each of these is a measured disagreement against the Arm MRA
 * ISA_A64_xml_A_profile-2022-12 execute pseudocode, not a guess at what
 * the disassembler meant.
 *
 * A WRITE TO XZR / WZR IS NOT ONE OF THEM.  `subps xzr, x2, x1`, `sbfiz
 * xzr, x8, #43, #1` and the CASP forms with an xzr in the result pair
 * report a write to the zero register, and that report is kept.  The
 * architecture discards the value, but register attribution is a
 * regfile-dependency question, not a value question: REG_ZERO exists in
 * the generic space, the wire has always carried it, and a consumer that
 * wants to collapse it can.  Dropping it here was tried and reverted;
 * the reference that dropped it on the other side was measuring its own
 * convention.  The READ side was never in question.
 *
 *   ERETAA / ERETAB read x30.  They do not.  The authenticated return
 *   address is ELR_ELx and the modifier is SP; x30 is untouched, and
 *   eretaa.xml's execute ASL names neither.  Capstone reports it because
 *   the plain RET alias handling leaks across the shared `ret`-family
 *   register table (see the AARCH64_INS_ALIAS_RET note above -- the same
 *   stale-alias defect, on the other side).
 *
 *   FCMP / FCMPE against #0.0 read the zero register.  The zero in
 *   `fcmp d1, #0.0` is an IMMEDIATE -- the encoding's op2 field, not a
 *   register operand -- and fcmp_float.xml compares against FPZero.  The
 *   fabricated read makes an FP compare depend on the integer file.
 *
 *   SME ZERO and the unpredicated MOVA into ZA read the array.  They
 *   write it and nothing else: zero_za1_ri.xml is `ZAvector[vec, VL] =
 *   Zeros(VL)`, mova_za2_z.xml is `ZAslice[...] = Z[n + r, VL]`.  The
 *   PREDICATED MOVA forms (`mov za0v.b[w14, 5], p3/m, z4.b`) do merge
 *   and keep their read, which is why the scope is the absence of a
 *   predicate operand rather than the mnemonic.  `zero {za0.d}` is
 *   reported the whole way round -- a read and no write at all -- so it
 *   needs the write put back, not just the read taken away.
 */
static bool cap_aarch64_has_pred_operand(const cs_arm64 *a64, uint8_t n)
{
    for (uint8_t i = 0; i < n; i++) {
        const cs_arm64_op *o = &a64->operands[i];
        if (o->type == AARCH64_OP_PRED) {
            return true;
        }
        if (o->type == AARCH64_OP_REG &&
            cap_aarch64_reg_file(o->reg) == CAP_A64_FILE_SVE_P) {
            return true;
        }
    }
    return false;
}

static void cap_aarch64_operand_direction(const cs_insn *insn,
                                          const cs_arm64 *a64,
                                          csh handle,
                                          qemu_plugin_insn_info *out)
{
    const char *mnem = insn->mnemonic;
    uint8_t n;

    if (!mnem || !mnem[0]) {
        return;
    }
    n = MIN(a64->op_count, QEMU_PLUGIN_INSN_DETAIL_MAX_OPS);

    if (g_strcmp0(mnem, "eretaa") == 0 || g_strcmp0(mnem, "eretab") == 0) {
        cap_aarch64_drop_implicit_read(out, AARCH64_REG_LR);
    }

    if (g_strcmp0(mnem, "fcmp") == 0 || g_strcmp0(mnem, "fcmpe") == 0) {
        cap_aarch64_drop_implicit_read(out, AARCH64_REG_XZR);
        cap_aarch64_drop_implicit_read(out, AARCH64_REG_WZR);
        for (uint8_t i = 0; i < n; i++) {
            qemu_plugin_operand *op = &out->operands[i];
            if (op->type == QEMU_PLUGIN_OP_REG &&
                (op->reg_id == AARCH64_REG_XZR ||
                 op->reg_id == AARCH64_REG_WZR)) {
                op->access = 0;
            }
        }
    }

    if (g_strcmp0(mnem, "zero") == 0 ||
        ((g_strcmp0(mnem, "mov") == 0 || g_strcmp0(mnem, "mova") == 0) &&
         !cap_aarch64_has_pred_operand(a64, n))) {
        /* Only when the array is the DESTINATION -- operand 0.  The
         * other direction, `mov { z8.b, z9.b }, za0v.b[w14, 6:7]`,
         * reads it, and the predicated forms merge into it. */
        const cs_arm64_op *d = n ? &a64->operands[0] : NULL;
        unsigned dreg = !d ? 0
                      : d->type == AARCH64_OP_SME ? d->sme.tile
                      : d->type == AARCH64_OP_REG ? d->reg : 0;
        bool touches_za = cap_aarch64_reg_file(dreg) == CAP_A64_FILE_ZA;

        if (touches_za) {
            out->operands[0].access &= (uint8_t)~QEMU_PLUGIN_OP_ACC_READ;
            out->operands[0].access |= QEMU_PLUGIN_OP_ACC_WRITE;
        }
        if (touches_za) {
            for (uint8_t i = 0; i < out->n_regs_read; i++) {
                unsigned r = out->regs_read_id[i];
                if (cap_aarch64_reg_file(r) == CAP_A64_FILE_ZA) {
                    cap_aarch64_add_implicit_write(out, handle, r);
                    cap_aarch64_drop_implicit_read(out, r);
                    i = (uint8_t)(i - 1);
                }
            }
        }
    }
}

/*
 * The zero register an alias spelling hides.
 *
 * `cmp x3, x2` IS `subs xzr, x3, x2`; `mov x2, x1` IS `orr x2, xzr, x1`;
 * `mul x3, x2, x1` IS `madd x3, x2, x1, xzr`; `cset x2, eq` IS
 * `csinc x2, xzr, xzr, ne`.  In each the architecture names the zero
 * register as an operand and the printed alias drops it.  Capstone
 * follows the printed form: with the ALIAS operand set `cmp` reports
 * `Registers modified: nzcv` and the xzr destination is simply not
 * there.  The same instruction spelled without the alias keeps it, so
 * the boundary named REG_ZERO on some encodings and not on others --
 * a silent reduction rather than a policy.
 *
 * A write to xzr changes no architectural value, and that is exactly
 * the argument this does NOT make.  Attribution is a regfile-dependency
 * question, not a question about the value: the generic space has
 * REG_ZERO, the ISA names it as this instruction's operand, so the set
 * says so.  Both independent references agree -- the MRA execute ASL
 * for CMP writes X[31], and LLVM MC reports WR{nzcv,zr} -- and the
 * reference harness stopped discarding it when the rule was settled.
 *
 * Capstone knows the answer and exposes it through CS_OPT_DETAIL_REAL,
 * which fills detail from the base instruction even when the printed
 * form is an alias.  It cannot be turned on for the primary handle:
 * cs_option() ORs CS_OPT_DETAIL values into handle->detail_opt and has
 * no way to clear the bit again (cs.c:1073), so the setting is one-way,
 * and turning it on reshapes op_count and the operand indices for every
 * AArch64 alias -- which is what the RET, MOPS, SVE-merging-MOV and
 * shift-immediate workarounds above are all written against.  So the
 * base form is decoded on a SECOND handle that lives permanently in
 * that mode, and only the zero-register operands it exposes are taken,
 * as implicit reads/writes.  The printed operand array keeps the alias
 * shape it has today; nothing else about the instruction moves.
 *
 * NOT covered, and a different mechanism: the forms whose zero operand
 * is fixed by the ENCODING rather than hidden by an alias -- PACIZA /
 * AUTIZB and the eleven others of that family (`n = 31` in the decode
 * ASL, so the execute reads X[31]), BRAAZ / BLRABZ, LDRAA / LDRAB.
 * Those are not aliases at all: Capstone models them as their own
 * instructions with no operand for the hardwired modifier, so the real
 * operand set is just as empty as the printed one and there is nothing
 * here to harvest.
 *
 * Revisit on a Capstone bump: if the ALIAS operand set starts carrying
 * the base form's zero register, the harvest becomes a no-op rather
 * than a double-count (both helpers below are idempotent), and this
 * can go.  Verify with `cstool -d aarch64 7f0002eb` against
 * `cstool -r -d aarch64 7f0002eb` -- today only the second says xzr.
 */
static bool cap_aarch64_is_zero_reg(unsigned int reg)
{
    return reg == AARCH64_REG_WZR || reg == AARCH64_REG_XZR;
}

static void cap_aarch64_restore_alias_zero_reg(csh handle,
                                               unsigned int cap_mode,
                                               const cs_insn *insn,
                                               qemu_plugin_insn_info *out)
{
    /*
     * Thread-local companion handle, opened once per thread per mode and
     * never explicitly freed -- the same lifetime the raw-decode cache
     * below uses, and for the same reason: a Capstone handle is not safe
     * for concurrent iteration and cs_open() per instruction would cost
     * more than the decode it wraps.
     */
    static __thread csh real_handle;
    static __thread cs_insn *real_insn;
    static __thread unsigned int real_mode;
    static __thread bool real_valid;

    const uint8_t *code;
    size_t sz;
    uint64_t addr;
    const cs_arm64 *real;
    unsigned int read_reg = AARCH64_REG_INVALID;
    unsigned int write_reg = AARCH64_REG_INVALID;

    if (!insn->is_alias || !insn->usesAliasDetails) {
        return;
    }

    /*
     * The one family where the alias is NOT a spelling of the same
     * access.  `staddb w1, [x2]` prints as an alias of `ldaddb w1, wzr,
     * [x2]`, and Capstone's real operand set duly reports a wzr WRITE --
     * but the atomic memory operations are the only A64 instructions
     * whose register write the DECODE guards on the register number:
     *
     *     data = MemAtomic(address, comparevalue, value, accdesc);
     *     if t != 31 then
     *         X[t, regsize] = ZeroExtend(data, regsize);
     *
     * With Rt = 31 the write does not happen at all, so the ST<op> form
     * genuinely has no destination register -- which is the whole reason
     * the architecture gives it its own name.  That is a different fact
     * from `subs xzr, x3, x2`, whose ASL says `X[d, datasize] = result;`
     * with no guard and therefore does write the zero register.
     *
     * The exclusion is exactly this family and no wider: a sweep of all
     * 2022-12 MRA instruction pages for a register access guarded on
     * `!= 31` returns 26 pages -- the 24 LD<op> atomics aliased here as
     * ST<op> (8 operations x ADD/CLR/EOR/SET/SMAX/SMIN/UMAX/UMIN, each
     * with byte, halfword and word/doubleword forms), plus ST64BV and
     * ST64BV0, whose guarded Rs status write Capstone prints explicitly
     * rather than through an alias and which therefore never reaches
     * here.  Everything else that names X[31] names it unconditionally.
     *
     * Keyed on the shape rather than a list of ids: the printed alias is
     * an `st...` and the base instruction Capstone decoded is an
     * `ld...`.  No other AArch64 alias inverts a load into a store.
     */
    if (g_str_has_prefix(insn->mnemonic, "st")) {
        const char *base = cs_insn_name(handle, insn->id);

        if (base && g_str_has_prefix(base, "ld")) {
            return;
        }
    }

    if (real_valid && real_mode != cap_mode) {
        cs_free(real_insn, 1);
        cs_close(&real_handle);
        real_valid = false;
    }
    if (!real_valid) {
        if (cs_open(CS_ARCH_ARM64, cap_mode, &real_handle) != CS_ERR_OK) {
            return;
        }
        cs_option(real_handle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(real_handle, CS_OPT_DETAIL, CS_OPT_DETAIL_REAL);
        real_insn = cs_malloc(real_handle);
        if (!real_insn) {
            cs_close(&real_handle);
            return;
        }
        real_mode = cap_mode;
        real_valid = true;
    }

    code = insn->bytes;
    sz = insn->size;
    addr = insn->address;
    if (real_insn->detail) {
        memset(real_insn->detail, 0, sizeof(*real_insn->detail));
    }
    if (!cs_disasm_iter(real_handle, &code, &sz, &addr, real_insn)
        || !real_insn->detail) {
        return;
    }

    real = &real_insn->detail->arm64;
    for (uint8_t i = 0; i < real->op_count; i++) {
        const cs_arm64_op *o = &real->operands[i];

        if (o->type != AARCH64_OP_REG || !cap_aarch64_is_zero_reg(o->reg)) {
            continue;
        }
        if (o->access & CS_AC_READ) {
            read_reg = o->reg;
        }
        if (o->access & CS_AC_WRITE) {
            write_reg = o->reg;
        }
    }

    if (read_reg != AARCH64_REG_INVALID) {
        cap_aarch64_add_implicit_read(out, handle, read_reg);
    }
    if (write_reg != AARCH64_REG_INVALID) {
        cap_aarch64_add_implicit_write(out, handle, write_reg);
    }
}

/*
 * The zero register an ENCODING fixes, which no alias is hiding.
 *
 * Three A64 families take a pointer-authentication modifier that the
 * encoding pins to register 31 and the assembler syntax therefore never
 * prints.  They are not aliases -- Capstone gives each its own
 * instruction id and its own mnemonic -- so the base-form operand set
 * is exactly as empty as the printed one and
 * cap_aarch64_restore_alias_zero_reg has nothing to harvest.  The
 * architecture is explicit that the modifier is the register and not a
 * literal zero:
 *
 *   PACIZA / AUTIZB and their ten siblings.  The decode sets `n = 31`
 *   (`if n != 31 then UNDEFINED` on the Z forms, `n = 31` outright on
 *   the HINT-space PACIAZ / AUTIBZ), and the execute is
 *   `X[d] = AddPACIA(X[d], X[n])` -- a read of X[31].
 *
 *   BRAAZ / BRABZ / BLRAAZ / BLRABZ.  `Z == '0'` forces `m == 31`, which
 *   also makes `source_is_sp` FALSE, so `modifier = X[m]` is X[31] --
 *   this is precisely what separates them from BRAA with Rm = 31 and
 *   Z = '1', whose modifier is SP.
 *
 *   LDRAA / LDRAB.  `address = AuthDA(address, X[31, 64], ...)` names
 *   X[31] literally in the execute ASL.
 *
 * Deliberately NOT here, each for a reason the same pages give:
 * PACIA1716 / AUTIA1716 take X[16]; PACIASP / RETAA and the rest of the
 * SP forms take SP[]; PACGA takes an explicit Xm; XPACI / XPACD /
 * XPACLRI take no modifier at all.
 *
 * The list is closed over the 2022-12 MRA rather than over Capstone's
 * mnemonic table, so a Capstone bump cannot silently add a member.
 */
static bool cap_aarch64_reads_zero_modifier(const char *mnem)
{
    static const char *const zero_modifier[] = {
        "autdza", "autdzb", "autiaz", "autibz", "autiza", "autizb",
        "blraaz", "blrabz", "braaz", "brabz",
        "ldraa", "ldrab",
        "pacdza", "pacdzb", "paciaz", "pacibz", "paciza", "pacizb",
    };

    for (size_t i = 0; i < ARRAY_SIZE(zero_modifier); i++) {
        if (!strcmp(mnem, zero_modifier[i])) {
            return true;
        }
    }
    return false;
}

/*
 * AArch64 PACKED-MEMORY-OPERAND corrections.
 *
 * Capstone 6.0.0-Alpha7 builds ONE `cs_arm64_op` of type MEM out of TWO
 * different things on three families, putting a register that is not an
 * address input into `mem.base` or `mem.index`.  The consequence reaches
 * the trace twice: the static store COUNT is inflated, and the
 * address-dependency mask the operand walker builds from base+index+segment
 * names registers the access does not compute its address from -- a
 * fabricated AGU edge, the same class as the mipsel conditional-branch
 * phantom destination removed at 95a0d89e92.
 *
 * FOUND by the address-dependency reference (arc3_cov/addrdep), which is
 * the first reference this project ever pointed at the HAS_ADDR sub-block.
 * Nothing else could see it: the register SETS are right on both sides
 * (the registers are all named, just in the wrong role), and the memop
 * ADDRESS axis compares values at execution, where a static operand
 * miscount does not show.
 *
 *   STLUR / STLURB / STLURH   `stlur w3, [x2, #1]`
 *       Capstone  op0 MEM{base=Rt, index=Xn, disp=0, W}
 *                 op1 MEM{base=0,  index=0,  disp=D, W}
 *       truth     op0 REG Rt (read)      op1 MEM{base=Xn, disp=D, W}
 *       Observed: two static stores where the instruction makes one, and
 *       store_addr_dep_mask[0] = {Rt, Xn} where the address depends on Xn
 *       alone.  `str x3,[x2]` two rows away is modelled correctly, which
 *       is what makes this a defect and not a representation.
 *
 *   STGP                      `stgp x4, x2, [x3, #0x10]`
 *       Capstone  op0 MEM{base=Rt1, index=Rt2, disp=0, W}
 *                 op1 MEM{base=Xn,  disp=D, W}
 *       truth     op0/op1 REG Rt1, Rt2 (read)   op2 MEM{base=Xn, disp=D, W}
 *       `stp w1,w0,[x2]` is modelled correctly.
 *
 *   MOPS CPY / CPYF families  `cpye [x17]!, [x25]!, x8!`   (96 encodings)
 *       Capstone  op0 MEM{base=Xd, index=Xs, disp=0, R|W}
 *       truth     op0 MEM{base=Xd, W}   op1 MEM{base=Xs, R}
 *       The copy's DESTINATION and SOURCE are two accesses at two
 *       addresses; packed into one operand, the walker gives the load and
 *       the store the SAME address dependency {Xd, Xs} and each acquires
 *       the other's base.  The UNION is right, which is why a reference
 *       without a per-access direction cannot see this -- stated as a
 *       blind spot where the aarch64 leg is scored.
 *
 * Each predicate tests the OBSERVED SHAPE as well as the instruction id,
 * so a fixed Capstone -- whose operands would not match the shape -- falls
 * straight through to the ordinary path instead of being re-broken here.
 * Retest with contrib/plugins/champsim_tracer/tools/capstone_workaround_probe
 * on a Capstone bump.
 */
static void cap_arm64_put_reg(csh handle, qemu_plugin_operand *op,
                              unsigned reg, unsigned access)
{
    memset(op, 0, sizeof(*op));
    op->type = QEMU_PLUGIN_OP_REG;
    cap_copy_reg_name(op->reg_name, QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                      handle, reg, CS_ARCH_ARM64);
    op->reg_id = reg;
    op->access = access;
    op->scale = 1;
}

static void cap_arm64_put_mem(csh handle, qemu_plugin_operand *op,
                              unsigned base, int64_t disp, unsigned access)
{
    memset(op, 0, sizeof(*op));
    op->type = QEMU_PLUGIN_OP_MEM;
    cap_copy_reg_name(op->reg_name, QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                      handle, base, CS_ARCH_ARM64);
    op->reg_id = base;
    op->imm = disp;
    op->access = access;
    op->scale = 1;
}

/* True when @insn is one of the packed-operand forms and was rewritten. */
static bool cap_arm64_unpack_mem_operands(csh handle, const cs_insn *insn,
                                          qemu_plugin_insn_info *out)
{
    const cs_arm64 *a64 = &insn->detail->arm64;
    const cs_arm64_op *o0 = &a64->operands[0];

    if (a64->op_count < 2 || o0->type != AARCH64_OP_MEM ||
        o0->mem.index == 0 || o0->mem.disp != 0) {
        return false;
    }

    if ((insn->id == AARCH64_INS_STLUR || insn->id == AARCH64_INS_STLURB ||
         insn->id == AARCH64_INS_STLURH) && a64->op_count == 2 &&
        a64->operands[1].type == AARCH64_OP_MEM &&
        a64->operands[1].mem.base == 0 && a64->operands[1].mem.index == 0) {
        cap_arm64_put_reg(handle, &out->operands[0], o0->mem.base,
                          QEMU_PLUGIN_OP_ACC_READ);
        cap_arm64_put_mem(handle, &out->operands[1], o0->mem.index,
                          a64->operands[1].mem.disp,
                          QEMU_PLUGIN_OP_ACC_WRITE);
        out->n_operands = 2;
        return true;
    }

    if (insn->id == AARCH64_INS_STGP && a64->op_count == 2 &&
        a64->operands[1].type == AARCH64_OP_MEM &&
        a64->operands[1].mem.base != 0 &&
        QEMU_PLUGIN_INSN_DETAIL_MAX_OPS >= 3) {
        cap_arm64_put_reg(handle, &out->operands[0], o0->mem.base,
                          QEMU_PLUGIN_OP_ACC_READ);
        cap_arm64_put_reg(handle, &out->operands[1], o0->mem.index,
                          QEMU_PLUGIN_OP_ACC_READ);
        cap_arm64_put_mem(handle, &out->operands[2],
                          a64->operands[1].mem.base,
                          a64->operands[1].mem.disp,
                          QEMU_PLUGIN_OP_ACC_WRITE);
        out->n_operands = 3;
        return true;
    }

    /* MOPS copy: the one operand carries the destination AND the source.
     * Keyed on the mnemonic because the family is 96 instruction ids wide
     * and every one of them spells the same shape; `cpy` also excludes the
     * memory-SET forms, which have one address and are modelled correctly.
     */
    if (o0->access == (CS_AC_READ | CS_AC_WRITE) &&
        strncmp(insn->mnemonic, "cpy", 3) == 0 &&
        a64->op_count + 1 <= QEMU_PLUGIN_INSN_DETAIL_MAX_OPS) {
        uint8_t n = MIN((uint8_t)(a64->op_count + 1),
                        (uint8_t)QEMU_PLUGIN_INSN_DETAIL_MAX_OPS);
        /* Carry the trailing operands (the size register) across unchanged,
         * from the back, so the two new memory operands can take slots 0
         * and 1 without overwriting anything still to be copied. */
        for (uint8_t i = n; i-- > 2; ) {
            const cs_arm64_op *src = &a64->operands[i - 1];
            qemu_plugin_operand *dst = &out->operands[i];
            memset(dst, 0, sizeof(*dst));
            dst->access = src->access;
            dst->scale = 1;
            if (src->type == AARCH64_OP_REG) {
                cap_arm64_put_reg(handle, dst, src->reg, src->access);
            } else if (src->type == AARCH64_OP_IMM) {
                dst->type = QEMU_PLUGIN_OP_IMM;
                dst->imm = src->imm;
            } else {
                dst->type = QEMU_PLUGIN_OP_INVALID;
            }
        }
        cap_arm64_put_mem(handle, &out->operands[0], o0->mem.base, 0,
                          QEMU_PLUGIN_OP_ACC_WRITE);
        cap_arm64_put_mem(handle, &out->operands[1], o0->mem.index, 0,
                          QEMU_PLUGIN_OP_ACC_READ);
        out->n_operands = n;
        return true;
    }
    return false;
}

static void cap_fill_arm64_operands(csh handle, unsigned int cap_mode,
                                    const cs_insn *insn,
                                    qemu_plugin_insn_info *out)
{
    if (cap_arm64_unpack_mem_operands(handle, insn, out)) {
        return;
    }

    const cs_arm64 *a64 = &insn->detail->arm64;
    uint8_t n = MIN(a64->op_count, QEMU_PLUGIN_INSN_DETAIL_MAX_OPS);
    out->n_operands = n;

    /* Capstone models no memory operand for the block-zeroing data-cache
     * maintenance ops — see cap_aarch64_is_block_zero_sysop.  Detect them
     * up front so the Xt operand can be turned into the store target it
     * really is. */
    bool block_zero = cap_aarch64_is_block_zero_sysop(a64, n);
    /* Same modelling gap, address-only half: the DC/IC operations that
     * act on the cache line containing a virtual address.  See
     * cap_aarch64_is_va_cache_maint_sysop. */
    bool va_cache_maint = cap_aarch64_is_va_cache_maint_sysop(a64, n);
    /*
     * AArch64 GCSSTR / GCSSTTR: Capstone models no memory operand.
     *
     * `GCSSTR Xt, [Xn]` stores Xt to the Guarded Control Stack at the
     * address in Xn.  Capstone 6.0.0-Alpha7 decodes both operands as
     * plain registers with READ access -- its own printer drops the
     * brackets ("gcsstr x2, x1") -- so the store had no memory operand
     * to be built from and the template claimed no store at all, while
     * the Arm MRA's execute-ASL resolves the row to mw=1.  The address
     * register is the SECOND operand; promote it to the written memory
     * operand it is.  QEMU implements no FEAT_GCS, so this is a
     * static-claim correction with no execution counterpart to
     * double-count against.
     *
     * Revisit when Capstone grows a memory operand for the GCS stores;
     * verify with `cstool -d arm64 220c1fd9` (gcsstr x2, x1), whose
     * operands should then include a MEM form.
     */
    bool gcs_store = (insn->id == AARCH64_INS_GCSSTR ||
                      insn->id == AARCH64_INS_GCSSTTR) && n >= 2;

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
            } else if (va_cache_maint) {
                /* Xt is the address the line is selected by, and no
                 * data crosses the interface: a MEM operand with no
                 * access flag, which is what the synthetic-EA class
                 * keys on (see cap_aarch64_is_va_cache_maint_sysop). */
                op->type   = QEMU_PLUGIN_OP_MEM;
                op->access = 0;
                op->imm    = 0;
            } else if (gcs_store && i == 1) {
                /* [Xn], the GCS slot being written (see gcs_store). */
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
            } else {
                /* Capstone reported something, but for the exclusive
                 * forms what it reported is a superset (see
                 * cap_aarch64_exclusive_mem_access). */
                unsigned ex =
                    cap_aarch64_exclusive_mem_access(insn->mnemonic);
                if (ex != 0) {
                    op->access = ex;
                } else if (cap_aarch64_tag_multiple_store(insn->mnemonic)) {
                    /* Reported READ; it is the block being written
                     * (see cap_aarch64_tag_multiple_store). */
                    op->access = QEMU_PLUGIN_OP_ACC_WRITE;
                }
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
             * pred.vec_select is the SECOND register some predicate
             * operands carry, and it means two different things.  On
             * PSEL it is the W register the slice index comes from --
             * `cstool -d aarch64 c154ac25` reports
             * "operands[2].pred.vec_select: w12" and lists w12 under
             * "Registers read", so the register is decoded and only this
             * arm dropped it.  Without it, `psel p1, p5, p6.b[w12, 9]`
             * depends on no general-purpose register at all and the
             * loop-control idiom the instruction exists for is severed
             * from the counter that drives it.
             *
             * On the predicate-PAIR forms the same field holds the
             * second predicate of the pair, which is a DESTINATION:
             * `whilegt { p14.b, p15.b }, x0, x0` parks p14 there and
             * writes both.  Taking it as a read there would invent a
             * dependency on a register the instruction only produces --
             * measured, on 16,384 whilegt/whilehi/whilele/whilels
             * encodings and 56 pext, before the W-register test below
             * was added.  The plugin operand ABI has one register field
             * per operand, so the slice index reaches the model the way
             * the SME slice register does a few cases up: as an implicit
             * read, and only when it is what PSEL puts there.
             */
            if (cop->pred.vec_select >= AARCH64_REG_W0
                && cop->pred.vec_select <= AARCH64_REG_W30) {
                cap_aarch64_add_implicit_read(out, handle,
                                              cop->pred.vec_select);
            }
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
             * cap_aarch64_sysreg_operand.  sysreg_class carries the
             * architectural role; reg_id carries the raw aarch64_sysreg
             * encoding for identification, not a Capstone register id.
             */
            uint8_t sysacc = 0;
            unsigned sysreg = 0;
            const char *sysname = NULL;
            if (cap_aarch64_sysreg_operand(cop, &sysacc, &sysreg,
                                           &sysname)) {
                op->type   = QEMU_PLUGIN_OP_SYSREG;
                op->access = sysacc;
                op->reg_id = (uint16_t)sysreg;
                op->sysreg_class = cap_aarch64_sysreg_class(sysreg);
                if (sysname) {
                    /* An MSR (immediate) prints the FIELD, not the
                     * register -- "DAIFSet, #7", "sm" -- so the name
                     * comes from the translation rather than from
                     * op_str. */
                    g_strlcpy(op->reg_name, sysname,
                              QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ);
                } else {
                    cap_aarch64_copy_sysreg_name(
                        op->reg_name, QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                        insn->op_str,
                        sysacc == QEMU_PLUGIN_OP_ACC_READ);
                }
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
     * refine_alias_fields() (champsim_tracer_decode.cc), which repairs
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
     * The FP status/control contract (see
     * cap_aarch64_fp_status_contract) is an architectural fact from the
     * MRA rather than a version-specific Capstone defect, so it is not
     * conditional on a Capstone revision; it adds only when the register
     * is not already listed, so a Capstone that starts reporting the
     * FPCR read cannot double-count.
     */
    cap_aarch64_fp_status_contract(insn, a64, handle, out);
    cap_aarch64_add_fp_enable_gate(insn, a64, n, out);
    cap_aarch64_msr_imm_contract(insn, out);
    cap_aarch64_implicit_sysregs(insn, out);
    cap_aarch64_hint_contract(handle, insn, out);
    cap_aarch64_always_cond_contract(insn, out);
    cap_aarch64_sysinstr_contract(handle, insn, out);
    cap_aarch64_ls64_contract(insn, handle, out);

    /*
     * Capstone 6.0.0-Alpha7 implicit-read gap: CTERMEQ / CTERMNE.
     *
     * The SVE loop-termination compares write N and V and leave Z and C
     * alone, and the V they write is a function of the C they did not --
     * ctermeq_rr.xml:
     *
     *   if term then PSTATE.N = '1'; PSTATE.V = '0';
     *   else         PSTATE.N = '0'; PSTATE.V = (NOT PSTATE.C);
     *
     * so NZCV is a source twice over: explicitly through PSTATE.C, and
     * because a partial write of a flag file a consumer renames as one
     * register has to merge with what was there.  Capstone reports
     * "Registers modified: nzcv" and "Registers read: x3 x2" -- the flag
     * read is missing.  It is NOT missing on the other partial-write
     * form: RMIF at the same revision reports "Registers read: nzcv x2"
     * (`cstool -d aarch64 "41 04 00 ba"`), which is what makes this a
     * two-instruction gap in Capstone rather than a modelling choice
     * here.  Verify on a bump with `cstool -d aarch64 6020e225`; when
     * nzcv appears in its read list this becomes a no-op, because
     * cap_aarch64_add_implicit_read will not duplicate it.
     */
    if (insn->id == AARCH64_INS_CTERMEQ || insn->id == AARCH64_INS_CTERMNE) {
        cap_aarch64_add_implicit_read(out, handle, AARCH64_REG_NZCV);
    }
    cap_aarch64_operand_direction(insn, a64, handle, out);

    cap_aarch64_restore_alias_zero_reg(handle, cap_mode, insn, out);

    if (cap_aarch64_reads_zero_modifier(insn->mnemonic)) {
        cap_aarch64_add_implicit_read(out, handle, AARCH64_REG_XZR);
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
 *
 * Every member promotes by POSITION -- the first register operand -- and
 * that is checked, not assumed: for each stem below Capstone prints the
 * tied destination first, which is what makes the loop's `break` land on
 * it.  MTHC1 is the one member of the wider family that could not be
 * carried here for exactly that reason; it has its own access-keyed
 * correction further down.
 *
 * `precr_sra` is spelled as a stem rather than as two names because it
 * has to be one: it must cover `precr_sra.ph.w` and `precr_sra_r.ph.w`
 * while NOT covering the five neighbouring DSP `precr*` forms
 * (precr.qb.ph, precrq.qb.ph, precrq.ph.w, precrq_rs.ph.w,
 * precrqu_s.qb.ph), none of which reads its destination -- QEMU's
 * translator passes cpu_gpr[ret] to their helpers as an output only.
 */
static bool cap_mips_is_tied_dst(const char *mnem)
{
    static const char *const stems[] = {
        /* scalar and DSP bit-field insert / concatenate */
        "ins", "dins", "append", "prepend", "insv", "balign",
        /* DSP precision-reduce that merges the destination's own half */
        "precr_sra",
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
 * RISC-V FP dynamic rounding: the frm read with no encoded field.
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
 *
 * THE VECTOR FP UNIT HAS NO rm FIELD AT ALL, so for it the scalar
 * DYN case is the ONLY case: OP-V funct3 = OPFVV (0b001) or OPFVF
 * (0b101) is the vector FP family, every member of it takes its
 * rounding mode from fcsr.frm, and a reserved frm makes the
 * instruction illegal.  Both authorities say so unconditionally and
 * per-clause: Sail opens every vector FP `execute` with `let rm_3b =
 * fcsr[FRM]` and hands it to illegal_fp_normal() /
 * illegal_fp_vd_unmasked(), and QEMU emits `gen_set_rm(s,
 * RISCV_FRM_DYN)` in every OPFVV/OPFVF translator, whose helper
 * "will return only if frm valid" (target/riscv/translate.c:744).
 *
 * That the read is a LEGALITY gate on the members which round nothing
 * -- vfsgnj[n|x], vfslide1up/down.vf, vfmerge.vfm, vfmv.v.f,
 * vfmv.f.s, vfmv.s.f, vfclass.v -- does not take it out of the set
 * (R7.4): a pending write to frm has to resolve before any of them
 * may proceed, which is an edge a renaming regfile must respect.  The
 * rounding members already carried REG_FCSR through the fflags
 * accumulate (cap_riscv_fp_signals); these thirteen carried nothing,
 * because they signal nothing either.
 */
static bool cap_riscv_reads_dynamic_frm(const cs_insn *insn)
{
    uint32_t word;
    uint32_t opcode;
    uint32_t funct3;

    if (insn->size != 4) {
        return false;
    }
    word = (uint32_t)insn->bytes[0] | ((uint32_t)insn->bytes[1] << 8) |
           ((uint32_t)insn->bytes[2] << 16) | ((uint32_t)insn->bytes[3] << 24);
    opcode = word & 0x7f;
    funct3 = (word >> 12) & 0x7;
    if (opcode == 0x57) {                 /* OP-V */
        return funct3 == 0x1 || funct3 == 0x5;   /* OPFVV / OPFVF */
    }
    /* MADD / MSUB / NMSUB / NMADD / OP-FP. */
    if (opcode != 0x43 && opcode != 0x47 && opcode != 0x4b &&
        opcode != 0x4f && opcode != 0x53) {
        return false;
    }
    return funct3 == 0x7;                 /* rm == DYN */
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
 * The vector AMOs that would have been a fourth were dropped before
 * ratification, and there are no compressed vector encodings, so a
 * 2-byte instruction cannot be one.
 *
 * The ratified vector-crypto extensions then added a fourth: OP-VE
 * (0b1110111), the major opcode Zvkned / Zvknh / Zvksh / Zvkg / Zvksed
 * encode in, always with funct3 = 0b010.  Both authorities spell it
 * out -- QEMU's target/riscv/insn32.decode gives all 21 of them
 * `1110111` (vaes*, vsha2*, vsm3*, vghsh/vgmul, vsm4*), and the Sail
 * model annotates the same encodings `OP-VE`.  Gated on funct3 so this
 * claims the vector-crypto space and not the whole custom-3 slot that
 * shares the opcode.
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
    case 0x77:                              /* OP-VE (vector crypto) */
        return ((word >> 12) & 0x7) == 0x2; /* funct3 = OPMVV */
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
 * Append an implicit register read Capstone did not report.
 */
static void cap_riscv_add_reg_read(csh handle, qemu_plugin_insn_info *out,
                                   uint16_t reg)
{
    for (uint8_t i = 0; i < out->n_regs_read; i++) {
        if (out->regs_read_id[i] == reg) {
            return;
        }
    }
    for (uint8_t i = 0; i < out->n_operands; i++) {
        if (out->operands[i].type == QEMU_PLUGIN_OP_REG
            && out->operands[i].reg_id == reg
            && (out->operands[i].access & QEMU_PLUGIN_OP_ACC_READ)) {
            return;
        }
    }
    if (out->n_regs_read >= QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS) {
        return;
    }
    cap_copy_reg_name(out->regs_read[out->n_regs_read],
                      QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                      handle, reg, CS_ARCH_RISCV);
    out->regs_read_id[out->n_regs_read] = reg;
    out->n_regs_read++;
}

/*
 * Append an implicit register write Capstone did not report.
 *
 * The mirror of cap_riscv_add_reg_read, and idempotent for the same
 * reason: a decoder that starts reporting one of these must not be
 * double-counted.  An operand already carrying the WRITE for the same
 * register counts as reported.
 */
static void cap_riscv_add_reg_write(csh handle, qemu_plugin_insn_info *out,
                                    uint16_t reg)
{
    for (uint8_t i = 0; i < out->n_regs_write; i++) {
        if (out->regs_write_id[i] == reg) {
            return;
        }
    }
    for (uint8_t i = 0; i < out->n_operands; i++) {
        if (out->operands[i].type == QEMU_PLUGIN_OP_REG
            && out->operands[i].reg_id == reg
            && (out->operands[i].access & QEMU_PLUGIN_OP_ACC_WRITE)) {
            return;
        }
    }
    if (out->n_regs_write >= QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS) {
        return;
    }
    cap_copy_reg_name(out->regs_write[out->n_regs_write],
                      QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                      handle, reg, CS_ARCH_RISCV);
    out->regs_write_id[out->n_regs_write] = reg;
    out->n_regs_write++;
}

/*
 * Replace the operand array with a single register operand.
 */
static void cap_riscv_push_reg_operand(csh handle, qemu_plugin_insn_info *out,
                                       uint16_t reg, uint8_t access)
{
    qemu_plugin_operand *op;

    if (out->n_operands >= QEMU_PLUGIN_INSN_DETAIL_MAX_OPS) {
        return;
    }
    op = &out->operands[out->n_operands];
    memset(op, 0, sizeof(*op));
    op->type   = QEMU_PLUGIN_OP_REG;
    op->access = access;
    op->reg_id = reg;
    op->scale  = 1;
    cap_copy_reg_name(op->reg_name, QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                      handle, reg, CS_ARCH_RISCV);
    out->n_operands++;
}

/*
 * Append a memory operand addressed by a single base register.
 *
 * Used by the Zicfiss shadow-stack forms, whose access Capstone reports
 * as no access at all.  Neither `size` nor `imm` is set: no RISC-V
 * memory operand on this boundary carries either (see the RISCV_OP_MEM
 * arm of cap_fill_generic_operands), and the dependency model reads
 * only the addressing registers and the access direction from a MEM
 * operand -- op->imm and op->size are not consulted for it.
 */
static void cap_riscv_push_mem_operand(csh handle, qemu_plugin_insn_info *out,
                                       uint16_t base, uint8_t access)
{
    qemu_plugin_operand *op;

    if (out->n_operands >= QEMU_PLUGIN_INSN_DETAIL_MAX_OPS) {
        return;
    }
    op = &out->operands[out->n_operands];
    memset(op, 0, sizeof(*op));
    op->type   = QEMU_PLUGIN_OP_MEM;
    op->access = access;
    op->reg_id = base;
    op->scale  = 1;
    cap_copy_reg_name(op->reg_name, QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                      handle, base, CS_ARCH_RISCV);
    out->n_operands++;
}

/*
 * Assembler aliases that hide an x0 SOURCE.
 *
 * `beqz a0, L` is `beq a0, x0, L`, `neg a0, a1` is `sub a0, x0, a1`,
 * `li a0, 1` is `addi a0, x0, 1` -- in each the architecture names x0 as
 * an operand and the alias spelling drops it, so Capstone's structured
 * detail drops it too.  Spelled without the alias the same instruction
 * keeps it: `add a0, zero, t0` reports RD{r0,r5}.  The boundary
 * therefore named x0 on some encodings and not on others, which is a
 * silent reduction (C4) rather than a policy -- reading x0 is inert for
 * a scheduler, but "this instruction has one source" and "this
 * instruction has two, one of which is the constant zero" are different
 * statements and only one of them is what the ISA says.
 *
 * The list is the closure of the LLVM/Capstone alias table over aliases
 * whose expansion has x0 in a SOURCE position.  Excluded on purpose:
 * `seqz` (sltiu rd, rs, 1), `not` (xori rd, rs, -1) and `sext.w`
 * (addiw rd, rs, 0), whose expansions have no x0 at all; and `ret` /
 * `j` / `jr` / `nop`, where x0 is the DESTINATION -- a write to x0
 * changes no architectural state, and the link-register side of those
 * is already restored by refine_alias_fields().
 *
 * `mv` is the one alias that must be told apart by width: the 32-bit
 * `mv rd, rs` is `addi rd, rs, 0` and reads no x0, while the compressed
 * `c.mv rd, rs2` is `add rd, x0, rs2` and does.
 */
static bool cap_riscv_alias_reads_x0(const cs_insn *insn)
{
    static const char *const x0_src_aliases[] = {
        "li", "neg", "negw", "snez", "sltz", "sgtz", "zext.w",
        "beqz", "bnez", "blez", "bgez", "bltz", "bgtz",
    };

    if (insn->size == 2 && !strcmp(insn->mnemonic, "mv")) {
        return true;
    }
    for (size_t i = 0; i < ARRAY_SIZE(x0_src_aliases); i++) {
        if (!strcmp(insn->mnemonic, x0_src_aliases[i])) {
            return true;
        }
    }
    return false;
}

/*
 * RISC-V FP / fixed-point status-word footprint.
 *
 * Four CSRs carry the arithmetic control and status word, and no
 * disassembler reports any of them as an implicit operand:
 *
 *   fflags (0x001)  the IEEE accrued-exception flags.  Every FP
 *                   operation that can signal accumulates into them --
 *                   `let new_fflags = fcsr[FFLAGS] | flags` in Sail's
 *                   accrue_fflags (model/extensions/FD/fdext_regs.sail
 *                   :448), and `status->float_exception_flags |= flags`
 *                   in QEMU's softfloat -- so the access is a
 *                   read-modify-write, not a write.
 *   vxsat  (0x009)  the fixed-point saturation flag, accumulated the
 *                   same way by the saturating vector ops.
 *   vxrm   (0x00a)  the fixed-point rounding mode, a genuine data
 *                   input: Sail reads `vcsr[vxrm]` inside
 *                   get_fixed_rounding_incr (vext_utils_insts.sail:601).
 *
 * All three fold onto one generic slot (QEMU_PLUGIN_SYSREG_FPCTRL), so
 * a consumer sees the arithmetic status word as one register; the
 * distinction is kept here because the boundary must name real CSRs.
 *
 * SCALAR: the FP major opcodes.  The four fused-multiply-add majors
 * always signal.  OP-FP signals except for three funct5 values, which
 * are the whole of the non-signalling scalar FP space: 0b00100 is the
 * sign-injection family (fsgnj/fsgnjn/fsgnjx), 0b11100 is the move-out
 * and classify family (fmv.x.w/fmv.x.d/fmv.x.h, fclass.*), and 0b11110
 * is the move-in family plus the Zfa constant load (fmv.w.x and
 * friends, fli.*).  Sign-injection, a bit-pattern move and a
 * classification raise no exception and round nothing; every other
 * OP-FP form -- arithmetic, conversion, comparison, min/max, the Zfa
 * fround / fleq / fcvtmod -- does at least one of the two.
 *
 * VECTOR FP: OP-V with funct3 = OPFVV (0b001) or OPFVF (0b101) is
 * exactly the vector FP space, so `vfirst.m` (OPMVV) cannot reach here
 * on the strength of its name.  Inside it the same five non-signalling
 * families are excluded by mnemonic: vfsgnj*, vfslide1*, vfmv*,
 * vfmerge*, vfclass* -- sign injection, a slide, a move and a merge,
 * plus the classify VFUNARY1 selects with vs1 = 0b10000.
 *
 * VECTOR FIXED-POINT: the rounding forms read vxrm (vaadd*, vasub*,
 * vssra*, vssrl*, vsmul*, vnclip*) and the saturating forms
 * read-modify-write vxsat (vsadd*, vssub*, vsmul*, vnclip*).  vsmul and
 * vnclip do both -- they round the product / narrowed value and then
 * saturate it.  The prefixes are chosen to be unambiguous against the
 * vector memory mnemonics that share a stem (`vsse8.v`, `vsseg2e8.v`)
 * and against the vector-crypto `vsm3*` / `vsm4*`.
 */
static bool cap_riscv_fp_signals(const cs_insn *insn, uint32_t word)
{
    unsigned major  = word & 0x7f;
    unsigned funct3 = (word >> 12) & 0x7;
    unsigned funct5 = (word >> 27) & 0x1f;

    switch (major) {
    case 0x43:                          /* MADD  */
    case 0x47:                          /* MSUB  */
    case 0x4b:                          /* NMSUB */
    case 0x4f:                          /* NMADD */
        return true;
    case 0x53:                          /* OP-FP */
        return funct5 != 0x04 && funct5 != 0x1c && funct5 != 0x1e;
    case 0x57:                          /* OP-V  */
        if (funct3 != 0x1 && funct3 != 0x5) {
            return false;               /* not OPFVV / OPFVF */
        }
        return !g_str_has_prefix(insn->mnemonic, "vfsgnj")
            && !g_str_has_prefix(insn->mnemonic, "vfslide1")
            && !g_str_has_prefix(insn->mnemonic, "vfmv")
            && !g_str_has_prefix(insn->mnemonic, "vfmerge")
            && !g_str_has_prefix(insn->mnemonic, "vfclass");
    default:
        return false;
    }
}

static bool cap_riscv_reads_vxrm(const char *mnem)
{
    return g_str_has_prefix(mnem, "vaadd") || g_str_has_prefix(mnem, "vasub")
        || g_str_has_prefix(mnem, "vssra") || g_str_has_prefix(mnem, "vssrl")
        || g_str_has_prefix(mnem, "vsmul") || g_str_has_prefix(mnem, "vnclip");
}

static bool cap_riscv_writes_vxsat(const char *mnem)
{
    return g_str_has_prefix(mnem, "vsadd") || g_str_has_prefix(mnem, "vssub")
        || g_str_has_prefix(mnem, "vsmul") || g_str_has_prefix(mnem, "vnclip");
}

/*
 * Is this Capstone register id a vector register?
 *
 * riscv_reg interleaves three vector runs with the GPR and FP files:
 * the 32 singles V0..V31, the LMUL=2 aliases V0M2..V30M2, and the
 * register GROUPS (V1_V2 .. V0_V1_V2_V3_V4_V5_V6_V7) a whole-register
 * or segment form names in one operand.  Each run is contiguous and
 * nothing else lives inside it, so the membership test is three range
 * checks; the alternative -- naming 305 enumerators -- would have to be
 * re-audited on every Capstone bump.
 */
static bool cap_riscv_is_vector_reg(uint16_t reg)
{
    return (reg >= RISCV_REG_V0 && reg <= RISCV_REG_V31)
        || (reg >= RISCV_REG_V0M2 && reg <= RISCV_REG_V30M2)
        || (reg >= RISCV_REG_V1_V2
            && reg <= RISCV_REG_V0_V1_V2_V3_V4_V5_V6_V7);
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
 * informational either way: the consumer maps from sysreg_class.
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
    case 0x017: return "jvt";
    case 0xc20: return "vl";
    case 0xc21: return "vtype";
    case 0xc22: return "vlenb";
    default:    return NULL;
    }
}

/*
 * The architectural role of a RISC-V CSR.
 *
 * Zicsr names its register in a 12-bit immediate field, so the CSR
 * space is its own numbering, disjoint from riscv_reg.  Capstone does
 * have register ids for the shadow forms of seven of these
 * (RISCV_REG_FFLAGS, FRM, VL, VTYPE, VXRM, VXSAT, VLENB) -- which is
 * how `fadd.d` reports its implicit rounding-mode read -- but none for
 * fcsr (0x003), vstart (0x008) or vcsr (0x00f), and none for the other
 * 4086 CSR numbers.  `cstool -d riscv64 73254000` (csrr a0, satp)
 * reports RISCV_OP_CSR with cop->csr = 0x180 and no register.  Rather
 * than split the operand class on which CSRs Capstone happens to
 * shadow, every one of them carries its role here.
 *
 *   The FP control and status word (fflags / frm / fcsr) is FPCTRL, so
 *   an `fsrm` and the `fadd.d` that consumes its rounding mode meet on
 *   one slot.
 *
 *   The fixed-point rounding mode and saturation flag (vxrm / vxsat,
 *   and the vcsr that is the two of them in one word) are FPCTRL too.
 *   That role already means "rounding mode and status for the
 *   arithmetic unit", and vcsr is fcsr's sibling CSR.
 *
 *   The vector CONFIGURATION -- vl and vtype, which a vsetvl writes as
 *   a pair and every vector instruction reads, plus the vstart resume
 *   index -- is VECCTRL, so `csrr a0, vl` reads what `vsetvli` wrote.
 *
 *   vlenb is VLEN in bytes, a read-only implementation constant nothing
 *   writes, so it belongs with the identification registers in OTHER.
 *   On VECCTRL a read of it would take an edge from the last vsetvli,
 *   which does not change VLEN.
 *
 * Reproducers (`cstool -d riscv64 <hex>`):
 *   73270010  frflags a4      csr 0x001
 *   73252000  csrr a0, vl     csr 0xc20
 *   73254000  csrr a0, satp   csr 0x180 (OTHER)
 */
static uint8_t cap_riscv_csr_class(unsigned csr)
{
    switch (csr) {
    case 0x001:  /* fflags */
    case 0x002:  /* frm    */
    case 0x003:  /* fcsr   */
    case 0x009:  /* vxsat  */
    case 0x00a:  /* vxrm   */
    case 0x00f:  /* vcsr   */
        return QEMU_PLUGIN_SYSREG_FPCTRL;
    case 0x008:  /* vstart */
    case 0xc20:  /* vl     */
    case 0xc21:  /* vtype  */
        return QEMU_PLUGIN_SYSREG_VECCTRL;
    case 0xc22:  /* vlenb    */
    case 0xf11:  /* mvendorid*/
    case 0xf12:  /* marchid  */
    case 0xf13:  /* mimpid   */
    case 0xf14:  /* mhartid  */
        /*
         * Read-only implementation constants.  These used to fall to
         * OTHER, whose comment said "a read-only implementation
         * constant" and then routed past the class that means it: the
         * classification table's REG_SYSID row for RISCV_REG_VLENB was
         * therefore read by nothing, because a Zicsr CSR does not take
         * the per-ISA register path at all.
         */
        return QEMU_PLUGIN_SYSREG_IDENT;
    default:
        return QEMU_PLUGIN_SYSREG_OTHER;
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
 * Append a CSR the ENCODING implies but no operand names.
 *
 * A RISC-V CSR reaches the plugin as a QEMU_PLUGIN_OP_SYSREG operand
 * carrying the raw 12-bit CSR number and its architectural role (see
 * cap_riscv_csr_class); Capstone has register ids for only seven of the
 * shadow forms and none at all for fcsr, vstart or vcsr, so a CSR that
 * is architecturally part of an instruction's footprint but absent from
 * its printed operand list can only be added this way.  Idempotent on
 * the CSR number, so a decoder that starts reporting one of these
 * cannot be double-counted, and a no-op once the operand array is full.
 */
static void cap_riscv_add_csr(qemu_plugin_insn_info *out, unsigned csr,
                              uint8_t access)
{
    qemu_plugin_operand *op;
    const char *name;

    for (uint8_t i = 0; i < out->n_operands; i++) {
        if (out->operands[i].type == QEMU_PLUGIN_OP_SYSREG
            && out->operands[i].reg_id == (uint16_t)csr) {
            out->operands[i].access |= access;
            return;
        }
    }
    if (out->n_operands >= QEMU_PLUGIN_INSN_DETAIL_MAX_OPS) {
        return;
    }
    op = &out->operands[out->n_operands];
    memset(op, 0, sizeof(*op));
    op->type   = QEMU_PLUGIN_OP_SYSREG;
    op->access = access;
    op->reg_id = (uint16_t)csr;
    op->sysreg_class = cap_riscv_csr_class(csr);
    op->scale  = 1;
    name = cap_riscv_csr_name(csr);
    if (name) {
        g_strlcpy(op->reg_name, name, QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ);
    }
    out->n_operands++;
}

/*
 * The environment-configuration triple, read as an enable gate.
 *
 * menvcfg / senvcfg / henvcfg carry the per-privilege enable bits for
 * several extensions -- Zicbom's CBCFE and CBIE, Zicboz's CBZE,
 * Zicfiss's SSE -- and which of the three is consulted depends on the
 * privilege the instruction executes at, a runtime value.  A static
 * register set names every candidate (R4), so all three go in; they
 * all carry QEMU_PLUGIN_SYSREG_OTHER and therefore meet on one generic
 * slot anyway.
 */
static void cap_riscv_add_envcfg_gate(qemu_plugin_insn_info *out)
{
    cap_riscv_add_csr(out, 0x30a /* menvcfg */, QEMU_PLUGIN_OP_ACC_READ);
    cap_riscv_add_csr(out, 0x10a /* senvcfg */, QEMU_PLUGIN_OP_ACC_READ);
    cap_riscv_add_csr(out, 0x60a /* henvcfg */, QEMU_PLUGIN_OP_ACC_READ);
}

/*
 * The register list a Zcmp push/pop encodes, as x-register numbers.
 *
 * `cm.push` / `cm.pop` name their transfer set with a 4-bit `rlist`
 * field standing for a RANGE, not a bitmap: 4 is {ra}, 5 is {ra, s0},
 * and each further value extends the s-register run by one -- except
 * 15, which jumps from s9 to s11 because s10 cannot be transferred
 * without s11.  Values below 4 are reserved and decode to nothing;
 * QEMU refuses them (`reg_bitmap == 0` -> illegal instruction), so an
 * empty return here is the same answer the guest gets.
 *
 * Written out of QEMU's own decode_push_pop_list()
 * (target/riscv/insn_trans/trans_rvzce.c.inc:113-166), which is the
 * reference this footprint is measured against: X_S0 = 8, X_S1 = 9 and
 * X_Sn = 16, so s2..s11 are x18..x27 and the run is not contiguous with
 * s0/s1.  Returns the number of registers written into @regs, which is
 * at most 13.
 */
static unsigned cap_riscv_zcmp_rlist(unsigned rlist, uint8_t *regs)
{
    /* ra, then s0, s1, s2 .. s11 in transfer order. */
    static const uint8_t sregs[12] = {
        8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    };
    unsigned n = 0;
    unsigned nsreg;

    if (rlist < 4 || rlist > 15) {
        return 0;
    }
    regs[n++] = 1;                              /* ra is always present */
    nsreg = (rlist == 15) ? 12 : (rlist - 4);   /* 15 adds s10 AND s11 */
    for (unsigned i = 0; i < nsreg; i++) {
        regs[n++] = sregs[i];
    }
    return n;
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

/*
 * The MIPS floating-point control/status word, on the arithmetic that
 * maintains it.
 *
 * Neither Capstone nor the LLVM tables it descends from name a status
 * register on ordinary floating-point arithmetic: `add.s $f4,$f5,$f6`
 * comes back reading two FP registers and writing one, and nothing
 * else.  The architecture and QEMU both say otherwise, and they say
 * the same thing.  Every COP1 arithmetic helper in
 * target/mips/tcg/fpu_helper.c ends in update_fcr31(), whose first act
 * is SET_FP_CAUSE(env->active_fpu.fcr31, ...) -- and SET_FP_CAUSE is a
 * read-modify-write (`(reg) = ((reg) & ~(0x3f << 12)) | ...`,
 * target/mips/cpu.h:83) executed on EVERY call, not only on an
 * exceptional one -- after which it reads GET_FP_ENABLE(fcr31) to
 * decide whether the exception traps.  MSA is the same shape one word
 * over: update_msacsr() in target/mips/tcg/msa_helper.c reads
 * GET_FP_ENABLE(env->active_tc.msacsr) unconditionally and SET_FP_CAUSEs
 * that word on both arms of its branch.  So the control register is a
 * SOURCE and a DESTINATION on every member of both families, which is
 * why the caller adds it to both lists.
 *
 * What it costs to omit: FCSR is the accumulating Cause/Flags word an
 * FP exception handler reads and `cfc1` copies out, and its rounding
 * mode is an input to every rounded result.  With no edge at all, a
 * `ctc1` that changes the rounding mode is a dead write, every FP
 * instruction in a block is mutually independent, and the handler reads
 * a register nothing in the trace ever produced.
 *
 * The class is QEMU's own call graph rather than a judgement about which
 * instructions "look arithmetic": it is the set of helpers that reach
 * update_fcr31() / update_msacsr(), extracted from the translator's C by
 * contrib/plugins/champsim_tracer/tools/arc3_cov/mipsel/attrib/
 * qemu_classes.py.  What the class EXCLUDES is load-bearing and is not
 * an oversight:
 *
 *   - abs / neg take no CPUMIPSState at all (helper_float_abs_s(uint32_t)
 *     is a bit clear), and mov / movf / movt / movn / movz / class are
 *     pure moves.  None can signal, so none maintains the word.
 *   - `cvt.ps.s` is the single member of the cvt family with no helper:
 *     it concatenates two singles, rounds nothing and cannot raise.
 *   - MSA's fclass / fill / ldi never reach update_msacsr().
 *
 * The suffix tests carry the same weight as the stem lists.  `.s` / `.d`
 * / `.ps` is what separates the COP1 compares from the DSP compares --
 * `cmp.eq.ph`, `cmpu.le.qb` and `cmpgu.lt.qb` share the `cmp` stem and
 * touch no FP status -- and the `b|h|w|d` suffix plus the leading `f` is
 * what keeps the MSA test off the scalar family.  Measured over the
 * tracer's whole mipsel opcode space (953 distinct mnemonics) the pair
 * of tests selects exactly the 189 members of the two classes, with no
 * false positive and no false negative.
 *
 * This is a modelling gap in the decoder lineage rather than a decode
 * bug, so it will not go away on a Capstone bump: LLVM MC does not
 * declare FCR31 on MIPS FP arithmetic either.  Verify with
 * `isaxcheck --isa=mipsel --hex=00290646` (`add.s $f4,$f5,$f6`), whose
 * `SRC{}` and `DST{}` must both name REG_FCSR, and `--hex=05290046`
 * (`abs.s $f4,$f5`), which must name it in neither.
 */
static const char *const cap_mips_fcr31_stems[] = {
    "add", "addr", "div", "madd", "maddf", "max", "maxa", "min", "mina",
    "msub", "msubf", "mul", "mulr", "nmadd", "nmsub", "recip", "recip1",
    "recip2", "rint", "rsqrt", "rsqrt1", "rsqrt2", "sqrt", "sub",
};

static const char *const cap_mips_msacsr_stems[] = {
    "fadd", "fcaf", "fceq", "fcle", "fclt", "fcne", "fcor", "fcueq",
    "fcule", "fcult", "fcun", "fcune", "fdiv", "fexdo", "fexp2", "fexupl",
    "fexupr", "ffint_s", "ffint_u", "ffql", "ffqr", "flog2", "fmadd",
    "fmax", "fmax_a", "fmin", "fmin_a", "fmsub", "fmul", "frcp", "frint",
    "frsqrt", "fsaf", "fseq", "fsle", "fslt", "fsne", "fsor", "fsqrt",
    "fsub", "fsueq", "fsule", "fsult", "fsun", "fsune", "ftint_s",
    "ftint_u", "ftq", "ftrunc_s", "ftrunc_u",
};

static bool cap_mips_stem_is(const char *const *tab, size_t n,
                             const char *mnem, size_t len)
{
    for (size_t i = 0; i < n; i++) {
        if (!strncmp(tab[i], mnem, len) && tab[i][len] == '\0') {
            return true;
        }
    }
    return false;
}

/* The FP control/status register this mnemonic reads and writes, or 0. */
static unsigned int cap_mips_fp_ctrl_reg(const char *mnem)
{
    const char *dot;
    size_t stem;
    bool cop1_fmt;

    if (!mnem || !mnem[0]) {
        return 0;
    }
    dot = strrchr(mnem, '.');
    if (!dot) {
        return 0;
    }
    stem = (size_t)(dot - mnem);

    /* MSA: `f<stem>.<b|h|w|d>`. */
    if (mnem[0] == 'f' && dot[1] && !dot[2] &&
        (dot[1] == 'b' || dot[1] == 'h' || dot[1] == 'w' || dot[1] == 'd') &&
        cap_mips_stem_is(cap_mips_msacsr_stems,
                         ARRAY_SIZE(cap_mips_msacsr_stems), mnem, stem)) {
        return MIPS_REG_MSACSR;
    }
    /* COP1 conversions; `cvt.` cannot be reached by the `c.` test below
     * because that one matches the dot in position 1. */
    if (g_str_has_prefix(mnem, "cvt.")) {
        return strcmp(mnem, "cvt.ps.s") ? MIPS_REG_FCR31 : 0;
    }
    if (g_str_has_prefix(mnem, "round.") || g_str_has_prefix(mnem, "ceil.") ||
        g_str_has_prefix(mnem, "floor.") || g_str_has_prefix(mnem, "trunc.")) {
        return MIPS_REG_FCR31;
    }
    cop1_fmt = !strcmp(dot, ".s") || !strcmp(dot, ".d") || !strcmp(dot, ".ps");
    /* COP1 compares, legacy `c.<cond>.<fmt>` and r6 `cmp.<cond>.<fmt>`. */
    if (g_str_has_prefix(mnem, "c.") || g_str_has_prefix(mnem, "cmp.")) {
        return cop1_fmt ? MIPS_REG_FCR31 : 0;
    }
    if (cop1_fmt && cap_mips_stem_is(cap_mips_fcr31_stems,
                                     ARRAY_SIZE(cap_mips_fcr31_stems),
                                     mnem, stem)) {
        return MIPS_REG_FCR31;
    }
    return 0;
}

/*
 * Capstone's MIPS register enum is ordered alphabetically by NAME, not
 * numerically ($zero is 26 and $at is 3), so a register number has to be
 * recovered by naming each one.  Returns 0..31, or -1 for anything that
 * is not a GPR.
 */
static int cap_mips_gpr_index(unsigned int reg)
{
    switch (reg) {
    case MIPS_REG_ZERO: return 0;
    case MIPS_REG_AT:   return 1;
    case MIPS_REG_V0:   return 2;
    case MIPS_REG_V1:   return 3;
    case MIPS_REG_A0:   return 4;
    case MIPS_REG_A1:   return 5;
    case MIPS_REG_A2:   return 6;
    case MIPS_REG_A3:   return 7;
    case MIPS_REG_T0:   return 8;
    case MIPS_REG_T1:   return 9;
    case MIPS_REG_T2:   return 10;
    case MIPS_REG_T3:   return 11;
    case MIPS_REG_T4:   return 12;
    case MIPS_REG_T5:   return 13;
    case MIPS_REG_T6:   return 14;
    case MIPS_REG_T7:   return 15;
    case MIPS_REG_S0:   return 16;
    case MIPS_REG_S1:   return 17;
    case MIPS_REG_S2:   return 18;
    case MIPS_REG_S3:   return 19;
    case MIPS_REG_S4:   return 20;
    case MIPS_REG_S5:   return 21;
    case MIPS_REG_S6:   return 22;
    case MIPS_REG_S7:   return 23;
    case MIPS_REG_T8:   return 24;
    case MIPS_REG_T9:   return 25;
    case MIPS_REG_K0:   return 26;
    case MIPS_REG_K1:   return 27;
    case MIPS_REG_GP:   return 28;
    case MIPS_REG_SP:   return 29;
    case MIPS_REG_FP:   return 30;
    case MIPS_REG_RA:   return 31;
    default:            return -1;
    }
}

/*
 * MT ASE MFTR / MTTR: the far operand is not a GPR, and (u, sel) says
 * which file it lives in.
 *
 * `MFTR rd, rt, u, sel, h` reads register `rt` of ANOTHER thread
 * context and writes GPR `rd`; MTTR is the reverse.  The far register's
 * FILE is selected by the (u, sel) pair, and Capstone -- like LLVM, and
 * like the tracer behind it -- prints the far operand as a GPR whatever
 * the pair says, collapsing all 24 named forms of the family into one
 * GPR<->GPR move.  So `mftc0 $a0, $5` is recorded as a read of $a1,
 * which is a register the instruction never touches, while the CP0
 * register it does read is recorded nowhere: one fabricated dependency
 * and one deleted one, out of a single wrong register class.
 *
 * The decode is QEMU's own (R6), read straight out of gen_mftr /
 * gen_mttr in target/mips/tcg/translate.c:8077 and :8301, which switch
 * on exactly this pair:
 *
 *   u == 0                CP0 register (rt, sel)          -> mftc0
 *   u == 1, sel == 0      GPR rt                          -> mftgpr
 *   u == 1, sel == 1      rt 0/1/2 -> AC0 lo/hi/acx,
 *                         4/5/6 -> AC1, 8/9/10 -> AC2,
 *                         12/13/14 -> AC3, 16 -> DSPControl
 *   u == 1, sel == 2      FPR rt (h picks the half)       -> mftc1
 *   u == 1, sel == 3      FP control register rt          -> cftc1
 *   u == 1, sel == 4/5    COP2 data / control register rt -> mftc2
 *
 * Note the accumulator index is rt >> 2, not rt & 3: QEMU's switch
 * spells the sixteen rt values out one at a time and the group of three
 * (lo, hi, acx) advances by four.  `h` selects the upper half of a
 * 64-bit FPR or COP2 register and so names the same architectural
 * register either way.
 *
 * mftgpr/mttgpr genuinely ARE GPR-to-GPR and are returned unchanged,
 * which is why the family is not corrected wholesale.  QEMU raises a
 * reserved-instruction exception on the COP2 selectors rather than
 * modelling them; the register class is still what the ASE defines, and
 * the tracer folds every COP0 and COP2 register onto one REG_SYS
 * bucket, so that fold is what the correction actually buys.
 *
 * Verify with `isaxcheck --isa=mipsel --hex=00200541` (`mftc0 $a0, $5`),
 * whose SRC{} must be REG_SYS and must NOT contain REG_GPR5, and
 * `--hex=20200541` (`mftgpr $a0, $a1`), which must still read REG_GPR5.
 */
static unsigned int cap_mips_mt_far_reg(int64_t u, int64_t sel, int idx)
{
    if (idx < 0 || idx > 31) {
        return 0;
    }
    if (u == 0) {
        return idx <= 9 ? MIPS_REG_COP00 + idx
                        : MIPS_REG_COP010 + (idx - 10);
    }
    switch (sel) {
    case 0:
        return 0;                       /* really a GPR; leave it alone */
    case 1:
        if (idx == 16) {
            return MIPS_REG_DSPCCOND;   /* stands for the DSPControl word */
        }
        if (idx <= 14 && (idx & 3) <= 2) {
            return MIPS_REG_AC0 + (idx >> 2);
        }
        return 0;
    case 2:
        return MIPS_REG_F0 + idx;
    case 3:
        return MIPS_REG_FCR0 + idx;
    case 4:
    case 5:
        return idx <= 9 ? MIPS_REG_COP20 + idx
                        : MIPS_REG_COP210 + (idx - 10);
    default:
        return 0;
    }
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
                 * It goes out as QEMU_PLUGIN_OP_SYSREG with its role in
                 * sysreg_class (see cap_riscv_csr_class), the raw CSR
                 * number in reg_id, and the direction refined from the
                 * encoding (see cap_riscv_csr_access).
                 */
                op->type = QEMU_PLUGIN_OP_SYSREG;
                op->access = cap_riscv_csr_access(insn);
                op->reg_id = (uint16_t)cop->csr;
                op->sysreg_class = cap_riscv_csr_class(cop->csr);
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
                    op->sysreg_class = cap_riscv_csr_class(csr);
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
         * An RVV vector DESTINATION is also a source.
         *
         * A vector instruction does not write the whole of vd.  Three
         * separate architectural rules leave part of it standing, and
         * every one of them is settled at RUNTIME, by state a preceding
         * `vsetvli` wrote and the encoding cannot name:
         *
         *   - tail-undisturbed (vtype.vta = 0): elements from vl up to
         *     VLMAX keep their previous values;
         *   - mask-undisturbed (vtype.vma = 0): masked-off elements keep
         *     their previous values;
         *   - prestart: elements below vstart are never written, whatever
         *     vta and vma say.
         *
         * So there is no encoding for which the dependency can be ruled
         * out, and under R5 -- a conditional form records every candidate
         * -- vd is a source of the instruction.  This is the same shape as
         * the mask-destination case the boundary already handled
         * (cap_riscv_is_mask_dst), generalised: that one was singled out
         * because write_vmask leaves the tail undisturbed unconditionally,
         * which made it decidable without vtype.  The general case is not
         * decidable in the other direction either -- "vd is not read" is
         * exactly as much a runtime claim -- and a template that omits the
         * read is a silent reduction (C4) rather than a neutral choice.
         *
         * Both authorities model it: Sail folds `vd_val` into
         * `init_masked_result` before the element loop, and QEMU's
         * vector helpers run `for (i = env->vstart; i < vl; i++)` and
         * then fill the tail from vd via `vext_set_elems_1s(vd, vta, ..)`.
         *
         * The rule is structural, not a name list: any operand that the
         * instruction WRITES and that names a vector register is also
         * read.  It therefore cannot fire on the forms whose destination
         * is a GPR or an FP register (`vcpop.m`, `vfirst.m`, `vmv.x.s`,
         * `vfmv.f.s`, `vsetvli`) or on a store, whose vector operand is
         * read-only to begin with.
         */
        if (cap_riscv_is_vector_encoding(insn)) {
            for (uint8_t i = 0; i < n; i++) {
                qemu_plugin_operand *op = &out->operands[i];
                if (op->type == QEMU_PLUGIN_OP_REG
                    && (op->access & QEMU_PLUGIN_OP_ACC_WRITE)
                    && cap_riscv_is_vector_reg(op->reg_id)) {
                    op->access |= QEMU_PLUGIN_OP_ACC_READ;
                }
            }
        }
        /*
         * A segment load or store names nf vector registers, not one.
         *
         * `vlseg6e64.v v8, (a1)` transfers SIX fields per segment, and
         * the fields live in six consecutive vector register groups
         * starting at vd -- RVV v1.0 sec 7.8, and Sail says it in one
         * call: VLSEGTYPE reads `read_vreg_seg(.., nf, vd)`, which loops
         * `foreach (j from 0 to (nf - 1))` over `vregidx_offset(vrid,
         * j * LMUL_reg)`, and writes back through the same offsets.
         * Capstone names only the base, so five of the six registers a
         * `vsseg6e64.v` reads -- and five of the six a `vlseg6e64.v`
         * produces -- are absent from the trace: the consumer of v13
         * never sees the load that wrote it.
         *
         * nf is in the encoding (bits 31:29, biased by one) for every
         * vector load and store, so the group size is static here even
         * though the per-field EMUL width is not; the boundary names one
         * register per field, which is the same convention it already
         * uses for the LMUL-sized operands elsewhere.
         *
         * The whole-register forms (`vl2re8.v`, `vs4r.v`) put nf in the
         * same field but Capstone already reports THEIR group as one
         * grouped register id, so the structural test is whether the
         * operand names a single vector register: a group id means
         * Capstone has already expanded it and this must not fire twice.
         * The appended operands inherit the base operand's access, which
         * by this point carries the vd-as-source correction above, so a
         * segment load's fields come out read-and-written and a segment
         * store's read-only, exactly as the base does.
         */
        if (insn->size == 4 && cap_riscv_is_vector_encoding(insn)
            && n >= 1
            && out->operands[0].type == QEMU_PLUGIN_OP_REG
            && out->operands[0].reg_id >= RISCV_REG_V0
            && out->operands[0].reg_id <= RISCV_REG_V31) {
            uint32_t word = (uint32_t)insn->bytes[0] |
                            ((uint32_t)insn->bytes[1] << 8) |
                            ((uint32_t)insn->bytes[2] << 16) |
                            ((uint32_t)insn->bytes[3] << 24);
            unsigned major = word & 0x7f;
            unsigned nf    = ((word >> 29) & 0x7) + 1;
            if ((major == 0x07 || major == 0x27) && nf > 1) {
                uint16_t base = out->operands[0].reg_id;
                uint8_t access = out->operands[0].access;
                for (unsigned k = 1; k < nf; k++) {
                    qemu_plugin_operand *op;
                    if (base + k > RISCV_REG_V31
                        || out->n_operands
                           >= QEMU_PLUGIN_INSN_DETAIL_MAX_OPS) {
                        break;
                    }
                    op = &out->operands[out->n_operands];
                    memset(op, 0, sizeof(*op));
                    op->type   = QEMU_PLUGIN_OP_REG;
                    op->access = access;
                    op->reg_id = (uint16_t)(base + k);
                    op->scale  = 1;
                    cap_copy_reg_name(op->reg_name,
                                      QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                                      handle, op->reg_id, cap_arch);
                    out->n_operands++;
                }
                n = out->n_operands;
            }
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
         * FP with a dynamic rounding mode reads frm -- scalar when the
         * rm field says DYN, vector always, since the vector unit has
         * no rm field (see cap_riscv_reads_dynamic_frm).  Architectural,
         * from Sail and from QEMU's own gen_set_rm(), not a
         * Capstone-version defect: the mode is in the encoding and no
         * disassembler reports the fcsr read it implies.  Added only
         * when absent, so a decoder that starts reporting it cannot be
         * double-counted.
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
        /*
         * Every RVV instruction WRITES vstart.
         *
         * vstart is the resume index a trap leaves behind so a partially
         * executed vector instruction can be restarted, and the flip side
         * of that contract is that a vector instruction which runs to
         * completion must clear it -- RVV v1.0 sec 3.7: "the vstart CSR is
         * reset to zero at the end of execution of any vector
         * instruction".  Both authorities say it unconditionally and in
         * one line each: Sail closes every vector `execute` clause with
         * `set_vstart(zeros())`, and QEMU writes `env->vstart = 0` at the
         * tail of every vector helper (66 sites, plus
         * `tcg_gen_movi_tl(cpu_vstart, 0)` in the translated forms).
         *
         * The tracer already named the vector configuration as a SOURCE
         * (vl / vtype, restored just above) and never as a destination, so
         * a `vsetvli` and the ops it configures had a dependency edge but
         * the vector stream itself produced nothing on that register: an
         * instruction that traps mid-vector resumes off a value the trace
         * says nobody wrote.  vl, vtype and vstart all carry
         * QEMU_PLUGIN_SYSREG_VECCTRL, so they meet on one generic slot and
         * this is that slot's producer.
         *
         * `vsetvl*` is excluded for the same reason it is excluded above:
         * it writes vl and vtype (which Capstone reports) and does not
         * touch vstart.
         */
        if (insn->mnemonic[0] == 'v'
            && !g_str_has_prefix(insn->mnemonic, "vsetvl")
            && cap_riscv_is_vector_encoding(insn)) {
            cap_riscv_add_csr(out, 0x008 /* vstart */,
                              QEMU_PLUGIN_OP_ACC_WRITE);
        }
        /*
         * The FP and fixed-point status word (see cap_riscv_fp_signals).
         *
         * fflags is accumulated, so the access is READ|WRITE: an FP
         * instruction depends on the flags standing when it starts and
         * leaves the union behind.  Reported by nothing -- Capstone
         * names frm on some of the vector FP forms and no decoder names
         * fflags anywhere -- so an `fdiv.s` that raises DZ and the
         * `frflags` that reads it back had no dependency between them at
         * all, and a saturating vector loop's vxsat was likewise
         * produced by no instruction in the trace.
         */
        if (insn->size == 4) {
            uint32_t word = (uint32_t)insn->bytes[0] |
                            ((uint32_t)insn->bytes[1] << 8) |
                            ((uint32_t)insn->bytes[2] << 16) |
                            ((uint32_t)insn->bytes[3] << 24);
            if (cap_riscv_fp_signals(insn, word)) {
                cap_riscv_add_csr(out, 0x001 /* fflags */,
                                  QEMU_PLUGIN_OP_ACC_READ
                                  | QEMU_PLUGIN_OP_ACC_WRITE);
            }
            if (cap_riscv_is_vector_encoding(insn)) {
                if (cap_riscv_reads_vxrm(insn->mnemonic)) {
                    cap_riscv_add_csr(out, 0x00a /* vxrm */,
                                      QEMU_PLUGIN_OP_ACC_READ);
                }
                if (cap_riscv_writes_vxsat(insn->mnemonic)) {
                    cap_riscv_add_csr(out, 0x009 /* vxsat */,
                                      QEMU_PLUGIN_OP_ACC_READ
                                      | QEMU_PLUGIN_OP_ACC_WRITE);
                }
            }
        }
        /*
         * The x0 an assembler alias spells out of existence
         * (see cap_riscv_alias_reads_x0).
         */
        if (cap_riscv_alias_reads_x0(insn)) {
            cap_riscv_add_reg_read(handle, out, RISCV_REG_X0);
        }
        /*
         * Zimop reads nothing, and the Zicfiss shadow stack is carved
         * out of it.
         *
         * The May-Be-Operations occupy SYSTEM with funct3 = 0b100, the
         * one funct3 Zicsr does not use.  Unimplemented, a MOP is
         * defined to write zero to rd and read NOTHING -- QEMU says it
         * in one line, `gen_set_gpr(ctx, a->rd, ctx->zero)` in
         * trans_rvzimop.c.inc, and Sail names the parameters `_rs1` /
         * `_rs2` to mark them unused.  Capstone reports rs1 and rs2 as
         * read because it prints them, which manufactures a dependency
         * on registers the instruction never looks at.
         *
         * Zicfiss then carves five encodings out of that space, and
         * Capstone 6.0.0-Alpha7 cannot decode them -- it prints
         * `sspush x1` as `mop.rr.7 zero, zero, ra` and `ssrdp a0` as
         * `mop.r.28 a0, zero`.  The register consequence is worse than
         * a missing read: the shadow-stack pointer is absent from both
         * sets and x0 is reported as a DESTINATION, so a shadow-stack
         * push produced a write to the register that cannot be written.
         * The encodings are fixed constants -- QEMU's own
         * target/riscv/insn32.decode lines 1033-1043 and
         * insn16.decode 143-146 give them bit for bit, and Sail agrees
         * -- so they are recognised here from the instruction word and
         * the footprint is stated outright.
         *
         *   sspush rs2    reads ssp and rs2, writes ssp, STORES to
         *                 the shadow stack at ssp - XLEN/8
         *   sspopchk rs1  reads ssp and rs1, writes ssp, LOADS from the
         *                 shadow stack at ssp
         *   ssrdp rd      reads ssp, writes rd
         *   c.sspush x1 / c.sspopchk x5   the compressed pair, carved
         *                 out of c.mop.1 and c.mop.5
         *
         * THE MEMORY ACCESS IS THE INSTRUCTION.  A shadow stack lives in
         * memory, and the first footprint written here named only the
         * registers: `sspush`/`sspopchk` arrived with loads=0 stores=0,
         * so a consumer driving a cache saw a push that touched nothing
         * and the shadow stack generated no traffic at all.  QEMU's own
         * translation is unambiguous -- trans_sspush emits
         * `tcg_gen_qemu_st_tl`, trans_sspopchk emits `tcg_gen_qemu_ld_tl`
         * (target/riscv/insn_trans/trans_rvzicfiss.c.inc) -- and the
         * address is ssp, which is why ssp is the MEM operand's base and
         * so becomes an address dependency as well as a data one.
         * `ssrdp` genuinely touches no memory: it moves ssp to a GPR.
         *
         * ssp carries REG_SSP, an ID of its own: folding it onto REG_SP
         * manufactured an edge with every spill and local, and folding
         * it onto REG_LR collapsed `sspopchk ra` -- whose whole purpose
         * is comparing the two -- to a self-dependency (R8.1, R8.6).
         *
         * All five also read the environment-configuration triple.
         * menvcfg.SSE (senvcfg.SSE at U, henvcfg.SSE under H) is the
         * Zicfiss enable bit, and Sail puts it in the encdec guard as
         * well as at the head of every clause: with it clear the
         * encoding is not a shadow-stack instruction at all but the
         * Zimop it is carved out of, which writes zero to rd.  A pending
         * write to that CSR therefore has to resolve before the
         * instruction can be said to do anything, which is R7.4's test.
         *
         * Revisit when Capstone gains Zicfiss: the mnemonic will still
         * be wrong until then, and only the register footprint is
         * repaired here.
         */
        if (insn->size == 4) {
            uint32_t word = (uint32_t)insn->bytes[0] |
                            ((uint32_t)insn->bytes[1] << 8) |
                            ((uint32_t)insn->bytes[2] << 16) |
                            ((uint32_t)insn->bytes[3] << 24);
            if ((word & 0x7f) == 0x73 && ((word >> 12) & 0x7) == 0x4
                && (word >> 31) == 1) {
                unsigned rd    = (word >> 7) & 0x1f;
                unsigned rs1   = (word >> 15) & 0x1f;
                unsigned rs2   = (word >> 20) & 0x1f;
                unsigned f7    = (word >> 25) & 0x7f;
                unsigned csr12 = (word >> 20) & 0xfff;
                bool push = f7 == 0x67 && rs1 == 0 && rd == 0
                            && (rs2 == 1 || rs2 == 5);
                bool popchk = csr12 == 0xcdc && rd == 0
                              && (rs1 == 1 || rs1 == 5);
                bool rdp = csr12 == 0xcdc && rs1 == 0 && rd != 0;
                out->n_operands = 0;
                out->n_regs_read = 0;
                out->n_regs_write = 0;
                if (push || popchk) {
                    cap_riscv_push_reg_operand(handle, out, RISCV_REG_SSP,
                                               QEMU_PLUGIN_OP_ACC_READ
                                               | QEMU_PLUGIN_OP_ACC_WRITE);
                    cap_riscv_push_reg_operand(
                        handle, out,
                        (uint16_t)(RISCV_REG_X0 + (push ? rs2 : rs1)),
                        QEMU_PLUGIN_OP_ACC_READ);
                    cap_riscv_push_mem_operand(handle, out, RISCV_REG_SSP,
                                               push
                                               ? QEMU_PLUGIN_OP_ACC_WRITE
                                               : QEMU_PLUGIN_OP_ACC_READ);
                    cap_riscv_add_envcfg_gate(out);
                } else if (rdp) {
                    cap_riscv_push_reg_operand(handle, out, RISCV_REG_SSP,
                                               QEMU_PLUGIN_OP_ACC_READ);
                    cap_riscv_push_reg_operand(handle, out,
                                               (uint16_t)(RISCV_REG_X0 + rd),
                                               QEMU_PLUGIN_OP_ACC_WRITE);
                    cap_riscv_add_envcfg_gate(out);
                } else if (rd != 0) {
                    cap_riscv_push_reg_operand(handle, out,
                                               (uint16_t)(RISCV_REG_X0 + rd),
                                               QEMU_PLUGIN_OP_ACC_WRITE);
                }
                n = out->n_operands;
            }
        }
        if (insn->size == 2) {
            uint16_t half = (uint16_t)insn->bytes[0] |
                            ((uint16_t)insn->bytes[1] << 8);
            if (half == 0x6081 || half == 0x6281) {
                out->n_operands = 0;
                out->n_regs_read = 0;
                out->n_regs_write = 0;
                cap_riscv_push_reg_operand(handle, out, RISCV_REG_SSP,
                                           QEMU_PLUGIN_OP_ACC_READ
                                           | QEMU_PLUGIN_OP_ACC_WRITE);
                cap_riscv_push_reg_operand(
                    handle, out,
                    (uint16_t)(RISCV_REG_X0 + (half == 0x6081 ? 1 : 5)),
                    QEMU_PLUGIN_OP_ACC_READ);
                cap_riscv_push_mem_operand(handle, out, RISCV_REG_SSP,
                                           half == 0x6081
                                           ? QEMU_PLUGIN_OP_ACC_WRITE
                                           : QEMU_PLUGIN_OP_ACC_READ);
                cap_riscv_add_envcfg_gate(out);
                n = out->n_operands;
            }
        }
        /*
         * A trap return reads the PC it returns to.
         *
         * `mret` jumps to mepc and restores the privilege level from
         * mstatus.MPP/MPIE, writing MPP/MPIE/MIE back as it does -- the
         * privileged manual states both halves, and Sail's MRET clause
         * reads mepc and mstatus and writes mstatus.  The boundary
         * reported the instruction as reading and writing NOTHING, so
         * the one indirect jump in the kernel whose target is
         * architecturally named had no dependency on the register that
         * names it, and the privilege restore had no producer.  `sret`
         * is the same instruction one level down (sepc, sstatus).
         *
         * Sail reads further CSRs here -- menvcfg, mseccfg, hstatus,
         * vsstatus -- that decide whether the instruction is legal at
         * the current privilege.  Under R7.4 those are sources too, and
         * they are not named here for one measured reason: every RISC-V
         * CSR outside the FP, vector and identification roles folds onto
         * REG_SYS (generic_reg_for_sysreg_class), which mepc and mstatus
         * already put on this instruction, so naming them would move
         * nothing a consumer can see.  They get named when the RISC-V
         * CSR file is split into the REG_SYS* behaviour classes; adding
         * an unobservable operand before that would be a table row
         * standing in for a decode (R8.7).
         */
        if (!strcmp(insn->mnemonic, "mret")) {
            cap_riscv_add_csr(out, 0x341 /* mepc */,
                              QEMU_PLUGIN_OP_ACC_READ);
            cap_riscv_add_csr(out, 0x300 /* mstatus */,
                              QEMU_PLUGIN_OP_ACC_READ
                              | QEMU_PLUGIN_OP_ACC_WRITE);
        } else if (!strcmp(insn->mnemonic, "sret")) {
            cap_riscv_add_csr(out, 0x141 /* sepc */,
                              QEMU_PLUGIN_OP_ACC_READ);
            cap_riscv_add_csr(out, 0x100 /* sstatus */,
                              QEMU_PLUGIN_OP_ACC_READ
                              | QEMU_PLUGIN_OP_ACC_WRITE);
        }
        /*
         * `fence` reads menvcfg.
         *
         * FIOM -- "Fence of I/O implies Memory" -- makes the I and O
         * bits of a fence's predecessor and successor sets imply R and
         * W, so the same encoding orders a different set of accesses
         * depending on what menvcfg (or senvcfg, one level down) holds.
         * Sail says it in two lines: `let fiom = is_fiom_active(); let
         * pred = effective_fence_set(pred, fiom)`.  This is a change of
         * semantics, not a legality gate, which is why it is named here
         * and the CBO / WFI / Zicfiss enable bits are not.
         *
         * `fence.tso` and `fence.i` have their own clauses and no FIOM
         * term, so the test is on the exact mnemonic.
         *
         * FIOM is a change of SEMANTICS rather than a legality gate,
         * which is why this one was named while the CBO, WFI and
         * Zicfiss enable bits were not.  R7.4 retired that distinction
         * -- a CSR that decides whether an instruction TRAPS is a
         * source, because a pending write to it must resolve before the
         * instruction may proceed -- and those three are named below.
         */
        if (!strcmp(insn->mnemonic, "fence")) {
            cap_riscv_add_csr(out, 0x30a /* menvcfg */,
                              QEMU_PLUGIN_OP_ACC_READ);
        }
        /*
         * The enable bits that decide whether WFI and a cache-block
         * operation TRAP (R7.4).
         *
         * `wfi` is legal at M and S; in a virtual context mstatus.TW
         * decides between executing, an Illegal Instruction and a
         * Virtual Instruction trap -- Sail's WFI clause reads
         * `mstatus[TW]` in both virtual arms.  The Zicbom and Zicboz
         * operations are gated per privilege by the CBCFE / CBIE / CBZE
         * fields of the environment-configuration triple, through
         * `feature_enabled_for_priv(cur_privilege, menvcfg[..],
         * read_senvcfg()[..], read_henvcfg()[..])`: with the bit clear
         * the instruction raises Illegal Instruction (or Virtual
         * Instruction) instead of touching the cache.
         *
         * All three envcfg registers are named, not just the one the
         * current privilege will consult, because the privilege is a
         * RUNTIME value and a static set records every candidate (R4) --
         * the same rule that puts both arms of a conditional write in
         * the set.
         *
         * Read from the instruction word: CBO is MISC-MEM with funct3 =
         * 0b010, rd = 0 and the operation in the 12-bit immediate
         * (0 inval, 1 clean, 2 flush, 4 zero).  Zicbop's `prefetch.*`
         * shares the major opcode with funct3 = 0b110 and is NOT here:
         * a prefetch is a hint that traps on nothing.
         */
        if (insn->size == 4) {
            uint32_t word = (uint32_t)insn->bytes[0] |
                            ((uint32_t)insn->bytes[1] << 8) |
                            ((uint32_t)insn->bytes[2] << 16) |
                            ((uint32_t)insn->bytes[3] << 24);
            if (word == 0x10500073) {           /* wfi */
                cap_riscv_add_csr(out, 0x300 /* mstatus */,
                                  QEMU_PLUGIN_OP_ACC_READ);
            }
            if ((word & 0x7f) == 0x0f && ((word >> 12) & 0x7) == 0x2
                && ((word >> 7) & 0x1f) == 0) {
                unsigned cbo = word >> 20;
                if (cbo == 0 || cbo == 1 || cbo == 2 || cbo == 4) {
                    cap_riscv_add_envcfg_gate(out);
                }
            }
        }
        /*
         * The privilege gate and the flush scope of a TLB-maintenance or
         * hypervisor load/store (R7.4).
         *
         * `sfence.vma` is an Illegal Instruction at U, and at S when
         * mstatus.TVM is set; at VS the same decision is hstatus.VTVM.
         * `hfence.gvma` reads mstatus.TVM the same way.  So a pending
         * write to those CSRs decides whether the instruction executes at
         * all, which is R7.4's test exactly, and Sail says it in the
         * clause head (`match mstatus[TVM] { 0b1 => Illegal_Instruction()
         * ...`, base_insts.sail:727).
         *
         * The scope of the flush is the second half and is not a
         * legality gate: `sfence.vma` and `hfence.vvma` take the VMID
         * from hgatp (`get_vmid(VS_Stage)`), so which TLB entries the
         * instruction removes depends on it.  That is an ordinary R7
         * dependency on a CSR the instruction's OWN semantics consult.
         *
         * `hlv` / `hlvx` / `hsv` read hstatus twice over: HU decides
         * whether U-mode may execute them at all, and SPVP selects the
         * effective privilege the access is performed at -- a change of
         * semantics, not just of legality.
         *
         * WHY THESE AND NOT `prefetch.i`.  The riscv64 comparison
         * excludes address translation, PMP/PMA and platform state on
         * BOTH sides, and Zicbop's prefetch reads mstatus only through
         * `effectivePrivilege(access, mstatus, cur_privilege)` inside the
         * translation of its own operand -- every arm of which is a
         * no-op, so the instruction cannot trap and its result does not
         * depend on the CSR.  The line is: a CSR the instruction's own
         * semantics consult (including its trap gate) is a source; a CSR
         * consulted only by the translation of its memory operand is not.
         *
         * Every RISC-V CSR outside the FP, vector and identification
         * roles folds onto REG_SYS, so the three named here arrive as one
         * generic source.  They are named individually anyway because the
         * fold is a property of the current generic space and not of the
         * architecture (R8), and because a reader has to be able to check
         * the claim against the model.
         *
         * Selected by mnemonic: Capstone decodes all of these natively
         * and correctly, so there is no encoding to re-derive, and
         * `sfence.w.inval` / `sfence.inval.ir` -- which share the prefix
         * and read nothing -- are excluded by the exact match.
         */
        if (!strcmp(insn->mnemonic, "sfence.vma")
            || !strcmp(insn->mnemonic, "sinval.vma")) {
            cap_riscv_add_csr(out, 0x300 /* mstatus: TVM  */,
                              QEMU_PLUGIN_OP_ACC_READ);
            cap_riscv_add_csr(out, 0x600 /* hstatus: VTVM */,
                              QEMU_PLUGIN_OP_ACC_READ);
            cap_riscv_add_csr(out, 0x680 /* hgatp:   VMID */,
                              QEMU_PLUGIN_OP_ACC_READ);
        } else if (!strcmp(insn->mnemonic, "hfence.gvma")
                   || !strcmp(insn->mnemonic, "hinval.gvma")) {
            cap_riscv_add_csr(out, 0x300 /* mstatus: TVM */,
                              QEMU_PLUGIN_OP_ACC_READ);
        } else if (!strcmp(insn->mnemonic, "hfence.vvma")
                   || !strcmp(insn->mnemonic, "hinval.vvma")) {
            cap_riscv_add_csr(out, 0x680 /* hgatp: VMID */,
                              QEMU_PLUGIN_OP_ACC_READ);
        } else if (!strncmp(insn->mnemonic, "hlv.", 4)
                   || !strncmp(insn->mnemonic, "hlvx.", 5)
                   || !strncmp(insn->mnemonic, "hsv.", 4)) {
            cap_riscv_add_csr(out, 0x600 /* hstatus: HU, SPVP */,
                              QEMU_PLUGIN_OP_ACC_READ);
        }
        /*
         * Zicfiss `ssamoswap.w` / `ssamoswap.d` read the same enable bit
         * every other shadow-stack instruction reads.
         *
         * Capstone decodes these two natively once CS_MODE_RISCV_ZICFISS
         * is set -- rd, rs1 and rs2 are all correct -- so unlike sspush /
         * sspopchk / ssrdp above there is no operand list to rebuild.  What
         * is missing is the gate: the instruction is only legal where
         * menvcfg.SSE (senvcfg.SSE at U, henvcfg.SSE under H) is set, and
         * Sail's SSAMOSWAP clause reads it exactly as the other five do.
         * Under R7.4 a CSR that decides whether the instruction traps is a
         * source, because a pending write to it must resolve before the
         * instruction may proceed.
         *
         * This is the one Zicfiss instruction the R7.4 pass missed, and the
         * reason is worth recording: the pair sat in the coverage
         * denominator's excluded.tsv under "neither decoder in the tracer
         * boundary decodes this encoding", a justification that stopped
         * being true the moment CS_MODE_RISCV_ZICFISS was switched on.  A
         * stale exclusion does not merely understate a denominator; it
         * hides whatever the excluded rows would have measured.
         */
        if (!strncmp(insn->mnemonic, "ssamoswap.", 10)) {
            cap_riscv_add_envcfg_gate(out);
        }
        /*
         * Zacas `amocas.q` names two register PAIRS.
         *
         * The 16-byte compare-and-swap on RV64 takes an even-odd pair
         * for the comparand/result rd and another for the swap value
         * rs2: rd holds the low half and rd+1 the high half, likewise
         * rs2.  Capstone prints and reports only the even register of
         * each pair, so half of the value being compared and half of
         * the value being stored are absent, and the high half of the
         * observed memory word is produced by nothing.  Sail models the
         * pairs directly (rX_pair_bits / wX_pair_bits); amocas.w and
         * amocas.d on RV64 are single registers and are already right.
         *
         * The write side of rd is restored above by
         * cap_riscv_is_tied_rd(); this adds the odd half of both pairs.
         * Capstone's structured operand order is not its printed order
         * here -- the memory operand sits between rd and rs2 -- so the
         * pair bases are the first and second REGISTER operands, not
         * operands[0] and operands[1].
         */
        if (!strcmp(insn->mnemonic, "amocas.q")) {
            uint16_t rd = 0, rs2 = 0;
            unsigned seen = 0;
            for (uint8_t i = 0; i < n && seen < 2; i++) {
                if (out->operands[i].type != QEMU_PLUGIN_OP_REG) {
                    continue;
                }
                if (seen == 0) {
                    rd = out->operands[i].reg_id;
                } else {
                    rs2 = out->operands[i].reg_id;
                }
                seen++;
            }
            if (seen == 2
                && rd >= RISCV_REG_X0 && rd < RISCV_REG_X31
                && rs2 >= RISCV_REG_X0 && rs2 < RISCV_REG_X31) {
                if (out->n_operands < QEMU_PLUGIN_INSN_DETAIL_MAX_OPS) {
                    qemu_plugin_operand *op =
                        &out->operands[out->n_operands];
                    memset(op, 0, sizeof(*op));
                    op->type   = QEMU_PLUGIN_OP_REG;
                    op->access = QEMU_PLUGIN_OP_ACC_READ
                               | QEMU_PLUGIN_OP_ACC_WRITE;
                    op->reg_id = (uint16_t)(rd + 1);
                    op->scale  = 1;
                    cap_copy_reg_name(op->reg_name,
                                      QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                                      handle, op->reg_id, cap_arch);
                    out->n_operands++;
                    n = out->n_operands;
                }
                cap_riscv_add_reg_read(handle, out, (uint16_t)(rs2 + 1));
            }
        }
        /*
         * Zicfilp `lpad` reads x7 and consumes the landing-pad state.
         *
         * A landing pad checks the label the indirect branch left in
         * x7 (t2) against the one in its own encoding and traps on a
         * mismatch, then clears the expected-landing-pad state the
         * branch set.  Capstone reports the instruction as touching no
         * register at all, so the label handshake -- the whole of
         * Zicfilp's forward-edge integrity -- was invisible.  ELP has
         * no CSR address of its own (its architectural homes are the
         * status word's MPELP / SPELP fields), so the state effect is
         * named on mstatus.
         */
        if (!strcmp(insn->mnemonic, "lpad")) {
            cap_riscv_add_reg_read(handle, out, RISCV_REG_X7);
            cap_riscv_add_csr(out, 0x300 /* mstatus: ELP */,
                              QEMU_PLUGIN_OP_ACC_READ
                              | QEMU_PLUGIN_OP_ACC_WRITE);
        }
        /*
         * Zcmp / Zcmt -- a whole function prologue that moved nothing.
         *
         * `cm.push {ra, s0-s11}, -112` saves thirteen registers and
         * adjusts the stack pointer; `cm.popret` restores them and
         * returns.  These are the instructions a -Os RISC-V compiler
         * emits at the head and tail of EVERY function once Zcmp is on,
         * so a trace that drops them drops the entire call-frame
         * dataflow of the program.  Measured before this change with
         * `isaxcheck --isa=riscv64 --cs-mode-add=zcmp --hex=42b8`: the
         * boundary reports RD{-} WR{-} and the dependency model records
         * SRC{-} DST{-} with loads=0 stores=0.  Nothing at all.
         *
         * NEITHER DECODER CAN SUPPLY IT AND NEITHER IS AT FAULT.  The
         * transfer set is a 4-bit `rlist` field naming a RANGE of
         * registers, and LLVM's MCInstrDesc has no way to express "the
         * registers this immediate names": its description carries no
         * operand and no implicit def/use for the list, so LLVM MC
         * reports RD{} WR{} for `cm.push` exactly as Capstone does.  A
         * second decoder cannot adjudicate what both spell the same way,
         * which is why this footprint is written from QEMU's own
         * translation (`trans_rvzce.c.inc`) rather than cross-checked
         * against LLVM.
         *
         *   cm.push     reads sp and every register in the list, writes
         *               sp, and STORES each listed register
         *               (trans_cm_push: dest_gpr(xSP), get_gpr(i) per
         *               list member, tcg_gen_qemu_st_tl, gen_set_gpr(xSP))
         *   cm.pop      reads sp, writes sp and every listed register,
         *               and LOADS each of them (gen_pop, ret=false)
         *   cm.popret   the same, plus the return jump
         *   cm.popretz  the same, plus a0 = 0 (gen_pop ret_val=true)
         *
         * `ra` is NOT a source of the popret forms even though the jump
         * reads it: rlist >= 4 always contains ra, so the instruction
         * DEFINES ra from memory before `get_gpr(ctx, xRA)` reads it
         * back, and a value produced and consumed inside one instruction
         * is no edge a register file has to respect (R7).
         *
         * The stack traffic is named per transferred register rather
         * than as one access because that is what QEMU emits -- one
         * `qemu_st_tl` / `qemu_ld_tl` per list member -- and the static
         * claim is what sizes the dependency lane mask.  sp is the base
         * of every one of them, so it is an address dependency as well
         * as a data one.
         *
         * Zcmt's `cm.jt` / `cm.jalt` index a jump-vector table whose
         * base and mode live in the JVT CSR (0x017): QEMU's helper
         * `cm_jalt` (zce_helper.c) reads `env->jvt` before it can compute
         * a target at all, so a pending write to JVT must resolve before
         * this branch resolves.  Capstone reports the index immediate
         * and nothing else.  The table ENTRY is fetched with
         * `cpu_ld*_code`, i.e. from code space, which is outside the
         * memop scope on both sides of the comparison and is therefore
         * not named as a load.  `cm.jalt`'s write of ra is already
         * reported and is left alone.
         *
         * `cm.mvsa01 rs1', rs2'` moves a0 -> rs1' and a1 -> rs2', so a0
         * and a1 are SOURCES.  Both decoders put them in the implicit
         * DEF list instead: the boundary reports WR{r8,r9,r10,r11} and
         * RD{}, which makes an argument-marshalling move produce four
         * registers and consume none -- every caller's argument setup
         * detached from the callee that reads it.  `cm.mva01s`, the
         * opposite direction, is the control and is correct in both
         * decoders (RD{r8,r9} WR{r10,r11}), so this is one wrong
         * implicit list rather than a family-wide gap, and it is
         * repaired by rebuilding the pair from the encoding: rs1' and
         * rs2' are the 3-bit s-register fields at 9:7 and 4:2, mapped by
         * QEMU's ex_sreg_register (n < 2 ? n + 8 : n + 16).
         *
         * Upstream is owed a report for that last one.
         *
         * The whole block is gated on the `cm.` mnemonic prefix, not on
         * the encoding: Zcmp/Zcmt occupy the compressed FP-store space
         * and are mutually exclusive with the Zcd that C+D implies, so
         * the same halfwords decode as `c.fsdsp` unless the guest ELF's
         * Tag_RISCV_arch turned CS_MODE_RISCV_ZCMP_ZCMT_ZCE on
         * (cap_mode_riscv).  Only Capstone knows which ISA it was told
         * to decode, and the mnemonic is where it says so.
         */
        if (insn->size == 2 && !strncmp(insn->mnemonic, "cm.", 3)) {
            uint16_t half = (uint16_t)insn->bytes[0] |
                            ((uint16_t)insn->bytes[1] << 8);
            bool is_push  = !strcmp(insn->mnemonic, "cm.push");
            bool is_pop   = !strcmp(insn->mnemonic, "cm.pop");
            bool is_pret  = !strcmp(insn->mnemonic, "cm.popret");
            bool is_pretz = !strcmp(insn->mnemonic, "cm.popretz");

            if (is_push || is_pop || is_pret || is_pretz) {
                uint8_t list[13];
                unsigned nreg = cap_riscv_zcmp_rlist((half >> 4) & 0xf, list);
                if (nreg) {
                    /* Capstone's second operand is the stack adjustment
                     * it prints; keep it rather than recompute it. */
                    int64_t adj = 0;
                    bool has_adj = false;
                    for (uint8_t i = 0; i < out->n_operands; i++) {
                        if (out->operands[i].type == QEMU_PLUGIN_OP_IMM) {
                            adj = out->operands[i].imm;
                            has_adj = true;
                            break;
                        }
                    }
                    out->n_operands  = 0;
                    out->n_regs_read = 0;
                    out->n_regs_write = 0;
                    if (has_adj) {
                        qemu_plugin_operand *op = &out->operands[0];
                        memset(op, 0, sizeof(*op));
                        op->type  = QEMU_PLUGIN_OP_IMM;
                        op->imm   = adj;
                        op->scale = 1;
                        out->n_operands = 1;
                    }
                    cap_riscv_push_reg_operand(handle, out, RISCV_REG_X2,
                                               QEMU_PLUGIN_OP_ACC_READ
                                               | QEMU_PLUGIN_OP_ACC_WRITE);
                    for (unsigned i = 0; i < nreg; i++) {
                        cap_riscv_push_mem_operand(handle, out, RISCV_REG_X2,
                                                   is_push
                                                   ? QEMU_PLUGIN_OP_ACC_WRITE
                                                   : QEMU_PLUGIN_OP_ACC_READ);
                    }
                    for (unsigned i = 0; i < nreg; i++) {
                        uint16_t r = (uint16_t)(RISCV_REG_X0 + list[i]);
                        if (is_push) {
                            cap_riscv_add_reg_read(handle, out, r);
                        } else {
                            cap_riscv_add_reg_write(handle, out, r);
                        }
                    }
                    if (is_pretz) {
                        cap_riscv_add_reg_write(handle, out, RISCV_REG_X10);
                    }
                    n = out->n_operands;
                }
            } else if (!strcmp(insn->mnemonic, "cm.jt")
                       || !strcmp(insn->mnemonic, "cm.jalt")) {
                cap_riscv_add_csr(out, 0x017 /* jvt */,
                                  QEMU_PLUGIN_OP_ACC_READ);
                n = out->n_operands;
            } else if (!strcmp(insn->mnemonic, "cm.mvsa01")) {
                unsigned r1 = (half >> 7) & 0x7;
                unsigned r2 = (half >> 2) & 0x7;
                out->n_operands   = 0;
                out->n_regs_read  = 0;
                out->n_regs_write = 0;
                cap_riscv_push_reg_operand(
                    handle, out,
                    (uint16_t)(RISCV_REG_X0 + (r1 < 2 ? r1 + 8 : r1 + 16)),
                    QEMU_PLUGIN_OP_ACC_WRITE);
                cap_riscv_push_reg_operand(
                    handle, out,
                    (uint16_t)(RISCV_REG_X0 + (r2 < 2 ? r2 + 8 : r2 + 16)),
                    QEMU_PLUGIN_OP_ACC_WRITE);
                cap_riscv_push_reg_operand(handle, out, RISCV_REG_X10,
                                           QEMU_PLUGIN_OP_ACC_READ);
                cap_riscv_push_reg_operand(handle, out, RISCV_REG_X11,
                                           QEMU_PLUGIN_OP_ACC_READ);
                n = out->n_operands;
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
         * Capstone 6.0.0 MIPS PREFETCH-HINT over-claim workaround.
         *
         * `pref hint,offset(base)` is a HINT.  MIPS64 vol II defines it
         * as performing no data access and raising no addressing
         * exception, and QEMU agrees at the only place that can settle
         * it -- OPC_PREF, OPC_PREFE and R6_OPC_PREF each fall through to
         * a bare "Treat as NOP" in target/mips/tcg/translate.c
         * (:18284, :17585, :16405) and emit no op at all.  Capstone
         * nevertheless flags the MEM operand CS_AC_READ, i.e. claims a
         * LOAD that no data access corresponds to.
         *
         * Under R2 the wire records ARCHITECTURAL dependencies, and a
         * hint that moves no data has no load to record.  So the READ is
         * cleared HERE, at the boundary, and not by a mnemonic-table row
         * -- per the table-scope rule a Capstone over-claim is a boundary
         * defect, while the table carries per-ISA vocabulary.
         *
         * WHAT THE TRACE STILL PUBLISHES, and why this is not a loss.
         * The address-only memop a prefetch carries is the TRACER's own
         * record, minted by vcpu_insn_synth_ea_cb from the synthetic-EA
         * class (GEN_OP_PREFETCH), so a cache model still learns which
         * line was hinted.  Clearing the flag moves the slot's SOURCE
         * from a Capstone access flag to that class -- which is where
         * the claim always belonged, because it is the tracer that mints
         * the record.  synthetic_ea_slotless_mem_operand() allocates the
         * slot exactly when the walk did not, so the count is unchanged;
         * measured on the four-ISA workload, max_dep_loads stays 1 on
         * every `pref` row.
         *
         * Placed AFTER the access==0 inference above so the two cannot
         * fight: that loop reads a 0-access MEM operand as the MSA /
         * unaligned defect and infers a direction from the data register
         * operand.  `pref` has no register operand -- its operands are
         * (IMM hint, MEM) -- so it could not reach that inference even
         * if the order were reversed, but depending on that would be a
         * coincidence rather than a rule.
         *
         * Revisit / remove when Capstone is bumped past 6.0.0; verify
         * with `cstool -d mips64el 0000b08c`-style bytes for `pref` --
         * fixed, the MEM operand must show no access flag.  Use a
         * `cstool` built from `subprojects/capstone` (capstone.wrap's
         * pinned revision), not a system package.
         */
        if (insn->id == MIPS_INS_PREF || insn->id == MIPS_INS_PREFE
            || insn->id == MIPS_INS_PREFX) {
            for (uint8_t i = 0; i < n; i++) {
                qemu_plugin_operand *op = &out->operands[i];
                if (op->type == QEMU_PLUGIN_OP_MEM) {
                    op->access = 0;
                }
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
         * LWL/LWR (and the 64-bit LDL/LDR, and the EVA LWLE/LWRE)
         * merge selected bytes of the loaded word into the destination
         * register, preserving the rest — architecturally the old $rt
         * value is an INPUT.  The EVA pair is the same instruction with
         * a user-mode access, and QEMU's translator makes that literal:
         * `case OPC_LWLE:` only sets mem_idx and falls straight through
         * into `case OPC_LWL:`, whose body opens with
         * `gen_load_gpr(t1, rt)` (target/mips/tcg/translate.c:2128).
         * LLVM's MCInstrDesc carries TIED_TO on all six members;
         * Capstone carries it on none.
         * Capstone reports $rt as CS_AC_WRITE only, so the partial
         * write's dependency on the previous register value is lost
         * and consumers see the pair as a full overwrite.  Promote
         * $rt to READ|WRITE.  The stores of the family (SWL/SWR/...)
         * already read $rt and need no correction.
         *
         * Revisit / remove when Capstone is bumped past 6.0.0; verify
         * with `cstool -d mips64el 03008888` (bytes `03 00 88 88`,
         * `lwl $t0,3($a0)`) -- fixed, $t0 (operands[0]) must show
         * READ|WRITE instead of WRITE-only.  A family member can be
         * fixed alone, so the EVA pair needs its own encodings:
         * `isaxcheck --isa=mipsel --hex=1900a47c` (`lwle $a0, 0($a1)`)
         * and `--hex=1a00a47c` (`lwre $a0, 0($a1)`) must each show $a0
         * in the boundary's `RD{}` set, matching the `llvm` line above
         * it.  Use a `cstool` built
         * from `subprojects/capstone` (capstone.wrap's pinned
         * revision), not a system package, or run
         * `capstone_workaround_probe`
         * (`cap_fill_mips_operands (LWL/LWR partial write)` case);
         * see docs/troubleshooting.rst.
         */
        if (insn->id == MIPS_INS_LWL || insn->id == MIPS_INS_LWR
            || insn->id == MIPS_INS_LDL || insn->id == MIPS_INS_LDR
            || insn->id == MIPS_INS_LWLE || insn->id == MIPS_INS_LWRE) {
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
         * The DSP members `BALIGN rt, rs, bp` and
         * `PRECR_SRA[_R].PH.W rt, rs, sa` are the same shape and were
         * verified against QEMU's own translator rather than against the
         * other decoder: OPC_BALIGN emits
         * `tcg_gen_shli_tl(cpu_gpr[rt], cpu_gpr[rt], 8 * sa)` and ORs the
         * shifted-down $rs into it, and OPC_PRECR_SRA[_R]_PH_W passes
         * cpu_gpr[ret] to its helper as the `rt` INPUT as well as the
         * result (`helper_precr_sra_ph_w` builds its low halfword out of
         * `(int32_t)rt >> sa`).  Both keep half of the destination, so
         * the destination is an input; Capstone reported both WRITE-only
         * and the architectural read was deleted all the way through to
         * the recorded InsnFields.
         *
         * Revisit / remove when Capstone is bumped past 6.0.0; verify with
         * `cstool -d mips32r2 0459287d` (bytes `04 59 28 7d`,
         * `ins $t0,$t1,4,8`) -- fixed, $t0 (operands[0]) must show
         * READ|WRITE instead of WRITE-only.  The two DSP members need
         * their own encodings, because a family member can be fixed
         * alone: `isaxcheck --isa=mipsel --hex=311c017c`
         * (`balign $at, $zero, 3`) and `--hex=9117817c`
         * (`precr_sra.ph.w $at, $a0, 2`) must each show $at in the
         * boundary's `RD{}` set, matching the `llvm` line above it.  Use a
         * `cstool` built from `subprojects/capstone`, not a system
         * package, or run `capstone_workaround_probe`; see
         * docs/troubleshooting.rst.
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
         * A prefetch hint reads memory, and mipsel was the only ISA that
         * did not say so.
         *
         * `pref hint, off(base)` names a MEM operand and Capstone reports
         * access == 0 on it -- no read, no write -- so the operand walker
         * counted neither, `has_addr_deps` stayed false, and the template
         * claimed loads=0 stores=0.  The runtime access happens anyway:
         * decode_synthetic_ea mints the effective address, and the decoded
         * trace shows `ld(0x410180)` -- ORPHANED, in parentheses, an access
         * with no declared slot -- exactly the shape the store-conditional
         * had below.
         *
         * SAME CONSTRUCT, THREE ANSWERS, which is what makes this a defect
         * rather than a policy.  Measured at 2ef652ee6b:
         *
         *   x86_64   prefetcht1 (%rcx)      mem r=1  loads=1 addrdeps=1
         *   aarch64  prfm pldl1keep, [x0]   mem r=1  loads=1 addrdeps=1
         *   mipsel   pref 0, 0($a0)         mem r=0 w=0 unkMEM=1
         *                                   loads=0 addrdeps=0
         *
         * binutils agrees with the other two: the `pref` entry carries
         * INSN_LOAD_MEMORY.  A prefetch with no address is useless to the
         * cache model that consumes this trace, and the static claim is
         * what sizes the dependency lane mask, so the slot is declared.
         *
         * `synci` is NOT here and its row stays open.  binutils flags it
         * INSN_STORE_MEMORY -- it is a cache write-back -- while
         * decode_synthetic_ea mints a LOAD for it, so declaring a slot here
         * would trade a missing store for an extra load rather than settle
         * the direction.  That needs its own decision.
         *
         * Guarded on access == 0, so an encoding Capstone reports properly
         * keeps its own answer, and on the MEM operand only.
         */
        if (!strcmp(insn->mnemonic, "pref")
            || !strcmp(insn->mnemonic, "prefe")) {
            for (uint8_t i = 0; i < n; i++) {
                qemu_plugin_operand *op = &out->operands[i];
                if (op->type != QEMU_PLUGIN_OP_MEM || op->access != 0) {
                    continue;
                }
                op->access = QEMU_PLUGIN_OP_ACC_READ;
                break;
            }
        }
        /*
         * QEMU's store-conditional READS the line it stores to, and the
         * memop callback delivers that read.
         *
         * `sc`, `scd` and their EVA forms are lowered by
         * `gen_st_cond()` (target/mips/tcg/translate.c:2219-2244) onto
         * `tcg_gen_atomic_cmpxchg_tl`, which performs a REAL load before
         * the store.  Architecturally a store-conditional writes and
         * returns a status bit; it does not read.  Capstone reports the
         * architecture -- the MEM operand is WRITE only -- so the
         * template declared loads=0 stores=1 while the run delivered
         * two accesses, and the load had NO SLOT TO LAND IN.
         *
         * Measured before this change, mipsel probe at 0x400144
         * (`sc $t2, 0($a1)`), decoded:
         *
         *   st %gp10 -> st[%gp5](0x410180)  ld(0x410180)   memops_cp=2
         *
         * `ld(...)`, in parentheses, is the decoder's rendering of an
         * ORPHANED runtime memop: an access that executed against no
         * declared slot.  riscv64's `sc.d`, whose Capstone MEM operand
         * happens to carry READ|WRITE, renders the same access as
         * `ld[%gp31](0x111c0)` with its datum -- matched.  Two ISAs, one
         * QEMU lowering, two different answers.
         *
         * THIS IS THE #177 DECISION APPLIED WHERE IT WAS OWED.  That
         * commit corrected AArch64's load-exclusive, whose Capstone MEM
         * operand claimed a store QEMU never performs, and deliberately
         * left the STORE-exclusive alone: "QEMU implements STXR/STLXR
         * with a cmpxchg helper that performs a REAL load, and the memop
         * callback sees it ... trading a phantom slot for a delivered
         * access with nowhere to land is worse, and the trace records
         * what executed."  MIPS is the same instruction class under the
         * same lowering and had the opposite treatment only because
         * Capstone's flags happened to differ.
         *
         * What that leaves is the question #177 also left open and this
         * does not close either: QEMU's store-conditional reads memory
         * where the hardware does not, so a consumer sees a
         * read-modify-write for an instruction the ISA says only writes.
         * That is an emulation artefact, not a decoding one.  It is now
         * named on both ISAs instead of showing up as an orphan on one
         * of them, and the riscv64 execution leg charges it to
         * `emulation-artefact` against Spike rather than to
         * `needs-ruling`.
         *
         * The load-linked side needs nothing: `ll` reports mem r=1 w=0
         * and `lr.d` likewise, so neither ISA has the phantom-store
         * shape #177 removed from `ldxr`.
         *
         * Three mnemonics and no more: `sc`, `scd` (MIPS64) and the EVA
         * `sce`.  There is no `scde` -- neither Capstone nor
         * target/mips/tcg/translate.c has one -- so listing it would be
         * a rule that matches nothing.
         *
         * Structural on both sides, like the accumulator rule below: the
         * mnemonic must be in the family AND the operand must actually
         * be a MEM operand that Capstone marked as a write.
         */
        if (!strcmp(insn->mnemonic, "sc") || !strcmp(insn->mnemonic, "scd")
            || !strcmp(insn->mnemonic, "sce")) {
            for (uint8_t i = 0; i < n; i++) {
                qemu_plugin_operand *op = &out->operands[i];
                if (op->type != QEMU_PLUGIN_OP_MEM
                    || !(op->access & QEMU_PLUGIN_OP_ACC_WRITE)) {
                    continue;
                }
                op->access |= QEMU_PLUGIN_OP_ACC_READ;
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
         * The classic `div rs, rt` / `divu rs, rt` have NO destination
         * register field.
         *
         * Bits 15:11 are architecturally zero for the MIPS32 two-operand
         * divide, and an encoding with them set does not decode at all
         * (`--hex=1a088500` is rejected; `--hex=1a008500` is
         * `div $zero, $a0, $a1`).  Capstone's AsmString for these forms
         * spells the destination literally -- "div\t$$zero, $rs, $rt" --
         * and then materialises that literal as operand 0: a
         * MIPS_REG_ZERO carrying CS_AC_WRITE.  The instruction writes
         * HI/LO, so the operand fabricates a destination the ISA does not
         * have.  LLVM MC, whose table the string comes from, reads it as
         * text and reports RD{rs,rt} WR{ac0} with no $0.  `mult`/`multu`,
         * spelled without the literal, are already right.
         *
         * GATED ON THE ACCUMULATOR WRITE, not on the mnemonic alone.
         * MIPS R6 -- a mode cap_mode_mips() selects from the guest ELF's
         * e_flags, so it is reachable -- redefines DIV/DIVU as genuine
         * three-operand instructions with a real rd and no HI/LO write.
         * There the destination is architectural and must survive, and
         * the accumulator write is exactly what tells the two apart.
         *
         * Invisible until the coverage harness stopped suppressing
         * REG_ZERO on both sides of the comparison (R7.3): with the
         * suppression in place a fabricated write to $0 and a correct
         * absence of one compared equal.
         */
        if (n >= 1
            && (insn->id == MIPS_INS_DIV || insn->id == MIPS_INS_DIVU
                || insn->id == MIPS_INS_DDIV || insn->id == MIPS_INS_DDIVU)
            && out->operands[0].type == QEMU_PLUGIN_OP_REG
            && out->operands[0].reg_id == MIPS_REG_ZERO
            && (out->operands[0].access & QEMU_PLUGIN_OP_ACC_WRITE)) {
            bool writes_acc = false;
            for (uint8_t i = 0; i < out->n_regs_write; i++) {
                if (cap_mips_is_acc_reg(out->regs_write_id[i])) {
                    writes_acc = true;
                    break;
                }
            }
            if (writes_acc) {
                for (uint8_t i = 1; i < n; i++) {
                    out->operands[i - 1] = out->operands[i];
                }
                n--;
                out->n_operands = n;
            }
        }
        /*
         * `MTHC1 rt, fs` writes the UPPER half of the FP register and
         * preserves the lower half, so the destination is also a source.
         * The MIPS32r2 pseudocode says so literally --
         * StoreFPR(fs, UNINTERPRETED_DOUBLEWORD,
         *          ValueFPR(fs, UNINTERPRETED_DOUBLEWORD)_31..0 ||
         *          GPR[rt]_31..0)
         * -- and QEMU's translator agrees: gen_store_fpr32h() emits
         * tcg_gen_deposit_i64(fpu_f64[reg], fpu_f64[reg], t64, 32, 32).
         * Capstone reports the FP operand WRITE-only.
         *
         * This belongs to the same family as cap_mips_is_tied_dst(), and
         * it is a member that list could not carry: that loop promotes the
         * FIRST register operand because the family writes operand zero,
         * while MTHC1 prints the GPR source first and the tied FP
         * destination second.  Promoting by ACCESS rather than by position
         * is what makes it structural -- the operand corrected is the one
         * Capstone itself calls the destination.
         *
         * What it costs to omit: `mtc1 lo,$fN ; mthc1 hi,$fN` is THE way a
         * 64-bit double is assembled from a register pair on a 32-bit
         * MIPS, and without the read the two halves share no dependency at
         * all -- the `mtc1` reads as a dead write and the pair is free to
         * reorder.  (`mfhc1` is deliberately absent: it writes a whole GPR
         * from the upper half and merges nothing.  So is `mtc1`, whose
         * upper half the architecture leaves UNPREDICTABLE rather than
         * preserved -- QEMU happens to deposit, but modelling a dependency
         * the ISA does not define would invent a serialisation.  `mthc2`
         * has the same shape on paper, but COP2 is implementation-defined
         * and neither decoder accepts the encoding in this subtarget.)
         *
         * Revisit / remove when Capstone is bumped past 6.0.0; verify with
         * `cstool -d mips32r2 0010e144` (bytes `00 10 e1 44`,
         * `mthc1 $at, $f2`) -- fixed, $f2 (operands[1]) must show
         * READ|WRITE instead of WRITE-only.  Use a `cstool` built from
         * `subprojects/capstone`, not a system package; see
         * docs/troubleshooting.rst.
         */
        if (insn->id == MIPS_INS_MTHC1) {
            for (uint8_t i = 0; i < n; i++) {
                qemu_plugin_operand *op = &out->operands[i];
                if (op->type != QEMU_PLUGIN_OP_REG ||
                    !(op->access & QEMU_PLUGIN_OP_ACC_WRITE)) {
                    continue;
                }
                op->access |= QEMU_PLUGIN_OP_ACC_READ;
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
        /*
         * The FP control/status word, on the arithmetic that maintains
         * it (see cap_mips_fp_ctrl_reg for the class and its
         * derivation).  Both directions on every member: the Cause
         * field is rewritten by a read-modify-write, and the enables
         * and rounding mode are read.
         */
        {
            unsigned int fpctl = cap_mips_fp_ctrl_reg(insn->mnemonic);
            if (fpctl) {
                cap_mips_add_implicit(out, handle, fpctl, false);
                cap_mips_add_implicit(out, handle, fpctl, true);
            }
        }
        /*
         * The CP0 registers an instruction names in its OWN definition,
         * and the CP0 state written by the exception it RAISES.
         *
         * Two classes, and the line between them is which instructions
         * these are -- not which registers.
         *
         * (a) The instruction whose entire architectural effect IS a CP0
         *     access: tlb*, di/ei, eret, deret, wait, dvpe/evpe, dmt/emt.
         *
         * (b) The instruction whose architectural effect IS to raise an
         *     exception: syscall, break, sdbbp, the twelve conditional
         *     traps, and the six trapping-arithmetic opcodes whose ISA
         *     definition includes Integer Overflow (add, addi, sub and
         *     their 64-bit forms -- see the case group for why they are
         *     class (b) and a faulting load is not).  R7.6 puts the state
         *     that exception writes in the raising instruction's set,
         *     because a later `mfc0` of EPC, Cause or Status must wait on
         *     the write -- an edge a renaming regfile has to respect (R7).
         *     R4 covers the conditional members: `teq` names the write as
         *     a candidate whether or not the comparison fires, `add` names
         *     it whether or not the sum overflows, and user mode, where
         *     the write never happens at all, is the same inert case.
         *
         * A load that MISSES THE TLB is neither.  Its architectural
         * effect is the load; the fault is a property of the address it
         * computed, not of the instruction, and admitting it would put
         * REG_SYSEXC in the set of every memory instruction -- and then,
         * by the same argument, of every instruction, since any of them
         * can take a bus error.  That is a manufactured edge of exactly
         * the class R8.1 forbids, so the line is drawn at (b).
         *
         * QEMU's helpers name the registers one by one:
         *
         *   tlbwi / tlbwr        read Index, EntryHi, EntryLo0/1, PageMask
         *   tlbinv / tlbinvf     read Index, EntryHi
         *   tlbr                 read Index; write EntryHi, EntryLo0/1,
         *                        PageMask (r4k_helper_tlbr,
         *                        target/mips/tcg/system/tlb_helper.c:240)
         *   tlbp                 read EntryHi; write Index
         *   di / ei              read and write Status
         *                        (helper_di/helper_ei,
         *                        system/special_helper.c:30 -- literally
         *                        `t0 = env->CP0_Status; env->CP0_Status =
         *                        t0 & ~(1 << CP0St_IE); return t0;`)
         *   eret                 read Status, EPC, ErrorEPC; write Status
         *   deret                read DEPC; write Debug
         *   wait                 read Status, Cause
         *   dvpe / evpe          read and write MVPControl
         *   dmt / emt            read and write VPEControl
         *
         * `dmt`/`emt` are the one pair taken from the MT ASE definition
         * instead of from QEMU: helper_dmt is a bare `return 0;` with a TODO
         * stub (target/mips/tcg/system/cp0_helper.c:1868), so there is no
         * modelling there to read.  Their siblings dvpe/evpe ARE modelled
         * and read-modify-write MVPControl, which is what the ASE says
         * dmt/emt do to VPEControl.
         *
         * The exception footprint, from the same source -- the general
         * entry path in target/mips/tcg/system/tlb_helper.c:
         *
         *   syscall (cause 8), break (cause 9) and teq/teqi/tge/tgei/
         *   tgeiu/tgeu/tlt/tlti/tltiu/tltu/tne/tnei (EXCP_TRAP, cause 13)
         *   all reach `set_EPC:` (:1420).  There it READS CP0_Status --
         *   `if (!(env->CP0_Status & (1 << CP0St_EXL)))` is the gate on
         *   the whole write, and Status.BEV then selects the vector --
         *   and READ-MODIFY-WRITES it (`|= 1 << CP0St_EXL`); it
         *   read-modify-writes CP0_Cause twice, once for the BD bit
         *   (qatomic_or/qatomic_and, :1427-1430) and once for the
         *   exception code (mips_cause_set_field, :1456, a cmpxchg loop
         *   over the whole word -- target/mips/internal.h:172); and it
         *   writes CP0_EPC (:1422).
         *
         *   sdbbp is NOT on that path.  It raises EXCP_DBp
         *   (translate.c:13049 and :13454, both dispatches), which goes
         *   to `set_DEPC:` / `enter_debug_mode:` (:1204-1233): DExcCode
         *   is a read-modify-write of CP0_Debug, CP0_DEPC takes the
         *   resume PC, and the BD clear is the same Status-gated
         *   read-modify-write of CP0_Cause.  So its set is Debug and
         *   DEPC on top of Status and Cause, and NOT EPC.
         *
         *   The microMIPS 16-bit forms carry their OWN Capstone ids and
         *   are listed with their base forms.  `syscall` and the twelve
         *   traps do not need this -- Mips_SYSCALL_MM and Mips_TEQ_MM map
         *   onto MIPS_INS_SYSCALL and MIPS_INS_TEQ -- but Mips_BREAK16_MM
         *   and Mips_SDBBP16_MM map onto MIPS_INS_BREAK16 and
         *   MIPS_INS_SDBBP16 (MipsMappingInsn.inc:1433, :7463), so
         *   omitting them would drop the footprint on a microMIPS guest.
         *   Both are REACHABLE, measured rather than assumed: a per-word
         *   sweep of the POOL16C page 0x4400-0x47ff in `cstool micromipsel`
         *   decodes 16 `break16` encodings (0x4680-0x468f) and 16
         *   `sdbbp16` (0x46c0-0x46cf).  isaxcheck's mipsel row is pinned to
         *   CS_MODE_MIPS32R2 (isaxcheck.cc:331) and the plugin only ORs in
         *   CS_MODE_MICRO for a microMIPS ELF, so the gate cannot exercise
         *   these two ids; that is a gate limit, stated, not a claim that
         *   they do not decode.
         *
         *   CP0_BadInstr (register 8, sel 1) is written for all fourteen
         *   of the set_EPC members -- each sets update_badinstr and
         *   set_badinstr_registers (:1043) stores the faulting word when
         *   Config3.BI is set.  It is not named below because register 8
         *   carries the same generic id as 12/13/14; naming it would add
         *   a boundary phantom and no edge.
         *
         * Capstone's implicit lists are empty for all of these, so before
         * this `eret` was an instruction with no inputs and no outputs,
         * `tlbwi` read nothing -- a kernel's whole TLB-refill path was
         * dependency-free -- and a `syscall` was ordered against nothing
         * the handler that follows it reads.
         *
         * The CP0 file is no longer one bucket.  Since the split these
         * numbers resolve by register number into REG_SYSMMU (0, 10),
         * REG_SYSEXC (8, 12, 13, 14), REG_SYSDBG (23, 24) and REG_SYS
         * (1), so each number below is the register QEMU actually names
         * and the class it lands in is a consequence of that, not a
         * convenience.  Where a read and a write are the same register
         * it is named on both sides, because the model is a
         * read-modify-write and not a clobber.
         *
         * Verify with `isaxcheck --isa=mipsel --hex=02000042` (`tlbwi`),
         * whose `SRC{}` must name REG_SYSMMU and whose `DST{}` must stay
         * empty; `--hex=18000042` (`eret`), which must name REG_SYSEXC in
         * both; `--hex=0c000000` (`syscall`) and `--hex=34008500`
         * (`teq $4, $5`), whose `SRC{}` and `DST{}` must both carry
         * REG_SYSEXC; and `--hex=3f000070` (`sdbbp`), which must carry
         * REG_SYSDBG and REG_SYSEXC in both and is the row that proves
         * the split is doing work.
         */
        switch (insn->id) {
        case MIPS_INS_TLBWI:
        case MIPS_INS_TLBWR:
        case MIPS_INS_TLBINV:
        case MIPS_INS_TLBINVF:
            cap_mips_add_implicit(out, handle, MIPS_REG_COP00, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP010, false);
            break;
        case MIPS_INS_TLBR:
            cap_mips_add_implicit(out, handle, MIPS_REG_COP00, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP010, true);
            break;
        case MIPS_INS_TLBP:
            cap_mips_add_implicit(out, handle, MIPS_REG_COP010, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP00, true);
            break;
        case MIPS_INS_DI:
        case MIPS_INS_EI:
            cap_mips_add_implicit(out, handle, MIPS_REG_COP012, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP012, true);
            break;
        case MIPS_INS_ERET:
            cap_mips_add_implicit(out, handle, MIPS_REG_COP012, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP014, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP012, true);
            break;
        case MIPS_INS_DERET:
            cap_mips_add_implicit(out, handle, MIPS_REG_COP024, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP023, true);
            break;
        case MIPS_INS_WAIT:
            cap_mips_add_implicit(out, handle, MIPS_REG_COP012, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP013, false);
            break;
        case MIPS_INS_DVPE:
        case MIPS_INS_EVPE:
            cap_mips_add_implicit(out, handle, MIPS_REG_COP00, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP00, true);
            break;
        case MIPS_INS_DMT:
        case MIPS_INS_EMT:
            cap_mips_add_implicit(out, handle, MIPS_REG_COP01, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP01, true);
            break;
        /* (b) the exception an instruction raises -- set_EPC members */
        case MIPS_INS_SYSCALL:
        case MIPS_INS_BREAK:
        case MIPS_INS_BREAK16:
        case MIPS_INS_TEQ:
        case MIPS_INS_TEQI:
        case MIPS_INS_TGE:
        case MIPS_INS_TGEI:
        case MIPS_INS_TGEIU:
        case MIPS_INS_TGEU:
        case MIPS_INS_TLT:
        case MIPS_INS_TLTI:
        case MIPS_INS_TLTIU:
        case MIPS_INS_TLTU:
        case MIPS_INS_TNE:
        case MIPS_INS_TNEI:
            cap_mips_add_implicit(out, handle, MIPS_REG_COP012, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP013, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP012, true);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP013, true);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP014, true);
            break;
        /*
         * The TRAPPING ARITHMETIC, which is the same class and the same
         * write set, reached through cause 12 instead of 8 or 13.
         *
         * `add`, `addi`, `sub` and their 64-bit forms are DEFINED to raise
         * Integer Overflow: the ISA leaves the destination unmodified and
         * takes the exception.  QEMU emits that inline --
         * `generate_exception(ctx, EXCP_OVERFLOW)` in gen_arith
         * (target/mips/tcg/translate.c:2599, :2635, :2916, :2958, :2998,
         * :3038 and the two 64-bit sites :4684, :4708) -- and EXCP_OVERFLOW
         * reaches the SAME `set_EPC:` label as syscall and the traps
         * (target/mips/tcg/system/tlb_helper.c:1372, `cause = 12`), so the
         * state written is identical: CP0_Status read and read-modify-written
         * for EXL, CP0_Cause read-modify-written twice, CP0_EPC written.
         * R7.6 puts that state in the raising instruction's set and R4 covers
         * the conditional part exactly as it covers `teq`: the write is a
         * candidate whether or not the operands overflow.
         *
         * THIS IS NOT THE TLB-MISS CASE the paragraph above excludes, and
         * the discriminator is the ISA's own, not a judgement call.  MIPS
         * ships each of these as a PAIR whose only difference is the trap --
         * add/addu, addi/addiu, sub/subu, dadd/daddu, daddi/daddiu,
         * dsub/dsubu -- so the exception is part of what the OPCODE means,
         * and the non-trapping sibling correctly gets nothing.  A load that
         * misses the TLB has no such sibling: its fault is a property of the
         * address it computed, which is why admitting it would put
         * REG_SYSEXC in the set of every instruction.  The set here is
         * closed and enumerated by the ISA at six opcodes.
         *
         * WHICH IDS, MEASURED rather than assumed (R8.7), with the wrap
         * Capstone's own `cstool`; the table is in
         * cst_runs/p3/arc3/exec30/negrow/CSTOOL_IDS.txt:
         *
         *   `neg $t2,$t3` (0x000b5022) decodes with ID **MIPS_INS_SUB**, not
         *   MIPS_INS_NEG -- `neg` is an alias the printer spells, and
         *   `dneg` is likewise MIPS_INS_DSUB.  MIPS_INS_NEG is therefore NOT
         *   listed: nothing in the sweep reaches it, and an unreachable case
         *   is not a mapped one.
         *
         *   The microMIPS 32-bit encodings map onto the SAME base ids
         *   (add 0x41100149 -> 98, addi 0x00041109 -> 146,
         *   sub 0x41900149 -> 1250, assembled with `as -mmicromips`), so
         *   unlike break16/sdbbp16 these need no separate rows.
         *
         *   The non-trapping siblings decode to their own distinct ids
         *   (addu 128, addiu 64, subu 66, daddu 488, daddiu 487, dsubu 579)
         *   and are absent from this list by construction.
         *
         * Verify with `isaxcheck --isa=mipsel --hex=22500b00` (`neg`), whose
         * `DST{}` must carry REG_SYSEXC beside REG_GPR10, and
         * `--hex=23402a01` (`subu`), whose `DST{}` must not.
         */
        case MIPS_INS_ADD:
        case MIPS_INS_ADDI:
        case MIPS_INS_SUB:
        case MIPS_INS_DADD:
        case MIPS_INS_DADDI:
        case MIPS_INS_DSUB:
            cap_mips_add_implicit(out, handle, MIPS_REG_COP012, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP013, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP012, true);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP013, true);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP014, true);
            break;
        /* sdbbp raises EXCP_DBp, which is a different footprint */
        case MIPS_INS_SDBBP:
        case MIPS_INS_SDBBP16:
            cap_mips_add_implicit(out, handle, MIPS_REG_COP023, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP012, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP013, false);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP023, true);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP024, true);
            cap_mips_add_implicit(out, handle, MIPS_REG_COP013, true);
            break;
        default:
            break;
        }
        /*
         * The MT ASE far operand's register file (see
         * cap_mips_mt_far_reg).  Operand 1 is the far one in both
         * directions -- MFTR prints `rd, rt, u, sel, h` and MTTR prints
         * `rt, rd, u, sel, h`, so the near GPR is first and the far
         * register second either way -- and operands 2 and 3 carry u and
         * sel.  Capstone's access flags already point the right way
         * (read for MFTR, write for MTTR); only the class is wrong.
         */
        if ((insn->id == MIPS_INS_MFTR || insn->id == MIPS_INS_MTTR)
            && n >= 4
            && out->operands[1].type == QEMU_PLUGIN_OP_REG
            && out->operands[2].type == QEMU_PLUGIN_OP_IMM
            && out->operands[3].type == QEMU_PLUGIN_OP_IMM) {
            qemu_plugin_operand *far = &out->operands[1];
            unsigned int rep =
                cap_mips_mt_far_reg(out->operands[2].imm,
                                    out->operands[3].imm,
                                    cap_mips_gpr_index(far->reg_id));
            if (rep) {
                far->reg_id = rep;
                cap_copy_reg_name(far->reg_name,
                                  QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                                  handle, rep, cap_arch);
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
/*
 * What the operand half of the decode costs.
 *
 * The plan is to stop asking Capstone for operands at all once the dataflow
 * comes from the TCG capture points, which makes the operand walk, the
 * access-flag reads and every boundary repair that exists to correct a
 * register fact dead code rather than merely unused input.  Whether that is
 * also a speed-up is a question with an answer, not an assumption, so the
 * boundary can be asked to time itself:
 *
 *   QEMU_CAP_PROFILE=1     count calls and split the time between the whole
 *                          decode and the operand half of it
 *   QEMU_CAP_NODETAIL=1    run Capstone with CS_OPT_DETAIL off, which is the
 *                          floor an identification-only decode could reach
 *
 * Both are read once and both are off by default.
 */
static bool cap_prof_on;
static bool cap_prof_read;
static bool cap_nodetail_on;
static bool cap_nodetail_read;
static int64_t cap_prof_calls;
static int64_t cap_prof_ns_total;
static int64_t cap_prof_ns_operands;

static int64_t cap_prof_now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

/*
 * linux-user services the guest's exit syscall with _exit(), so an atexit
 * handler is not reached; the reading is taken every cap_prof_every calls
 * instead, which also makes two configurations comparable at the same call
 * count rather than at whatever count each happened to reach.
 */
static int64_t cap_prof_every = 10000;

static void cap_prof_dump(void)
{
    if (!cap_prof_calls) {
        return;
    }
    fprintf(stderr,
            "cap_profile: calls=%" PRId64 " total_ns=%" PRId64
            " operands_ns=%" PRId64 " total_per_call=%.0f"
            " operands_per_call=%.0f operands_share=%.1f%%\n",
            cap_prof_calls, cap_prof_ns_total, cap_prof_ns_operands,
            (double)cap_prof_ns_total / cap_prof_calls,
            (double)cap_prof_ns_operands / cap_prof_calls,
            100.0 * cap_prof_ns_operands / cap_prof_ns_total);
}

static bool cap_profiling(void)
{
    if (!cap_prof_read) {
        const char *s = getenv("QEMU_CAP_PROFILE");

        cap_prof_on = s && atoi(s) != 0;
        cap_prof_read = true;
        if (cap_prof_on) {
            const char *e = getenv("QEMU_CAP_PROFILE_EVERY");

            if (e) {
                cap_prof_every = strtoll(e, NULL, 0);
            }
            atexit(cap_prof_dump);
        }
    }
    return cap_prof_on;
}

/*
 * Identification needs insn->id and insn->mnemonic, and both come out of the
 * base decode.  Everything under insn->detail -- operands, implicit register
 * lists, and the instruction groups the branch class is cross-checked against
 * -- is the second pass this turns off.
 */
static bool cap_nodetail(void)
{
    if (!cap_nodetail_read) {
        const char *s = getenv("QEMU_CAP_NODETAIL");

        cap_nodetail_on = s && atoi(s) != 0;
        cap_nodetail_read = true;
    }
    return cap_nodetail_on;
}

/* Registers Capstone omits for a family of x86-64 instructions whose
 * whole dependency is implicit; the table and the reasoning are down
 * with the other Capstone workarounds. */
static void cap_x86_apply_implicit_table(qemu_plugin_insn_info *out,
                                         csh handle, const cs_insn *insn);

/*
 * Deliberate corruption of what Capstone says, for testing that a consumer
 * does not depend on it.
 *
 * The tracer's dependency model is meant to take its dataflow -- which
 * registers are read, which are written, which memory operand is a load --
 * from QEMU's own translation, and to take only the instruction's identity
 * from Capstone.  That is a claim about the absence of a path, and the only
 * honest way to test the absence of a path is to break the input and check
 * that the output does not move.
 *
 * Both of the boundary's exits call it -- cap_disas_plugin_detail(), which is
 * what a plugin running live under qemu-* goes through, and
 * cap_disas_raw_detail(), which is what the offline tools and
 * qemu_plugin_cap_decode() use.  Corrupting one and not the other would leave
 * the live tracer untouched while the test reported a pass.  It is driven by
 * QEMU_CAP_MUTATE and reads it once; with the variable unset the whole thing
 * is one predictable branch and the boundary behaves exactly as before.
 *
 * The modes are the failure classes Capstone has actually produced here:
 *
 *   access    every operand's read/write bits inverted
 *   drop      the last operand removed
 *   addreg    a register operand appended that the instruction has not got
 *   implicit  the implicit read and write lists exchanged
 *   memdir    every memory operand's direction inverted
 *   mnem      the mnemonic replaced -- the one thing a consumer IS allowed
 *             to depend on, so this is the control that must move
 *   all       every mode above except mnem
 */
static void cap_mutate_detail(struct qemu_plugin_insn_info *out)
{
    static int mode = -1;

    if (mode < 0) {
        const char *s = getenv("QEMU_CAP_MUTATE");

        mode = 0;
        if (s && *s) {
            if (!strcmp(s, "access")) {
                mode = 1;
            } else if (!strcmp(s, "drop")) {
                mode = 2;
            } else if (!strcmp(s, "addreg")) {
                mode = 3;
            } else if (!strcmp(s, "implicit")) {
                mode = 4;
            } else if (!strcmp(s, "memdir")) {
                mode = 5;
            } else if (!strcmp(s, "mnem")) {
                mode = 6;
            } else if (!strcmp(s, "all")) {
                mode = 7;
            }
        }
    }
    if (mode == 0) {
        return;
    }

    if (mode == 1 || mode == 7) {
        for (uint8_t i = 0; i < out->n_operands; i++) {
            uint8_t a = out->operands[i].access;

            out->operands[i].access =
                (uint8_t)(((a & QEMU_PLUGIN_OP_ACC_READ)
                           ? QEMU_PLUGIN_OP_ACC_WRITE : 0) |
                          ((a & QEMU_PLUGIN_OP_ACC_WRITE)
                           ? QEMU_PLUGIN_OP_ACC_READ : 0));
        }
    }
    if ((mode == 5 || mode == 7)) {
        for (uint8_t i = 0; i < out->n_operands; i++) {
            if (out->operands[i].type != QEMU_PLUGIN_OP_MEM) {
                continue;
            }
            out->operands[i].access ^= (QEMU_PLUGIN_OP_ACC_READ |
                                        QEMU_PLUGIN_OP_ACC_WRITE);
        }
    }
    if (mode == 4 || mode == 7) {
        char nm[QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS]
               [QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ];
        uint16_t id[QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS];
        uint8_t n = out->n_regs_read;

        memcpy(nm, out->regs_read, sizeof(nm));
        memcpy(id, out->regs_read_id, sizeof(id));
        memcpy(out->regs_read, out->regs_write, sizeof(nm));
        memcpy(out->regs_read_id, out->regs_write_id, sizeof(id));
        memcpy(out->regs_write, nm, sizeof(nm));
        memcpy(out->regs_write_id, id, sizeof(id));
        out->n_regs_read = out->n_regs_write;
        out->n_regs_write = n;
    }
    if ((mode == 3 || mode == 7) &&
        out->n_operands < QEMU_PLUGIN_INSN_DETAIL_MAX_OPS) {
        struct qemu_plugin_operand *op = &out->operands[out->n_operands++];

        memset(op, 0, sizeof(*op));
        op->type = QEMU_PLUGIN_OP_REG;
        op->access = QEMU_PLUGIN_OP_ACC_READ | QEMU_PLUGIN_OP_ACC_WRITE;
        op->size = 8;
        /* A register id every ISA in the table has, so it always lands. */
        /*
         * A register id the ISA's table has a row for, so the operand lands
         * somewhere rather than being dropped as unknown -- a mutation that
         * is quietly discarded proves nothing.  x86 X86_REG_R15 = 113.
         */
        op->reg_id = 113;
        g_strlcpy(op->reg_name, "r15", sizeof(op->reg_name));
    }
    if ((mode == 2 || mode == 7) && out->n_operands > 0) {
        out->n_operands--;
    }
    if (mode == 6) {
        /*
         * Identity, which is the one thing a consumer is allowed to take from
         * here.  Both halves of it move: the printed mnemonic and the numeric
         * insn_id the opcode taxonomy is actually keyed on.
         */
        g_strlcpy(out->mnemonic, "mutant", QEMU_PLUGIN_INSN_DETAIL_MNEMSZ);
        out->insn_id = 0;
    }
}

bool cap_disas_plugin_detail(disassemble_info *info, uint64_t pc, size_t size,
                             struct qemu_plugin_insn_info *out)
{
    uint8_t cap_buf[32];
    const uint8_t *cbuf = cap_buf;
    csh handle;
    cs_insn *insn;
    bool prof = cap_profiling();
    int64_t t0 = prof ? cap_prof_now() : 0;

    memset(out, 0, sizeof(*out));

    if (cap_disas_start(info, &handle) != CS_ERR_OK) {
        return false;
    }

    cs_option(handle, CS_OPT_DETAIL,
              cap_nodetail() ? CS_OPT_OFF : CS_OPT_ON);

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
        int64_t t_op = prof ? cap_prof_now() : 0;

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
            if (cap_effective_mode(info) & CS_MODE_64) {
                cap_x86_apply_implicit_table(out, handle, insn);
            }
            break;
        case CS_ARCH_ARM64:
            cap_fill_arm64_operands(handle, cap_effective_mode(info),
                                    insn, out);
            break;
        default:
            cap_fill_generic_operands(handle, insn, out,
                                      info->cap_arch);
            break;
        }
        if (prof) {
            cap_prof_ns_operands += cap_prof_now() - t_op;
        }
    }

    cap_mutate_detail(out);

    cs_free(insn, 1);
    cs_close(&handle);
    if (prof) {
        cap_prof_calls++;
        cap_prof_ns_total += cap_prof_now() - t0;
        if (cap_prof_calls % cap_prof_every == 0) {
            cap_prof_dump();
        }
    }
    return true;
}

/*
 * ---------------------------------------------------------------------
 * x86-64 DECODE-GAP REPAIR
 *
 * Everything above this point repairs what Capstone SAYS about an
 * instruction.  This repairs the case where it says nothing: bytes a
 * QEMU x86_64 guest executes and cs_disasm_iter() refuses outright.
 * That failure is the most damaging shape the defect has -- the plugin
 * boundary produces no qemu_plugin_insn_info at all, so the instruction
 * reaches the trace with no opcode class, no register sets and no
 * memops, and nothing downstream can tell the difference between "this
 * instruction depends on nothing" and "this decoder could not read it".
 *
 * Measured against Intel XED over the whole x86_64 opcode space
 * (contrib/plugins/champsim_tracer/tools/arc3_cov/x86_64), Capstone
 * 6.0.0-Alpha7 rejects 349 opcodes whose XED extension QEMU advertises.
 * 128 of those are the APX (EVEX-promoted) forms of otherwise-ordinary
 * instructions, and no QEMU x86_64 guest can execute them -- QEMU TCG
 * has no APX and every one of the 128 raises SIGILL when executed under
 * qemu-x86_64 -cpu max.  The remaining 221 were executed the same way;
 * 63 ran.  Those 63 are the whole reachable gap and are what this
 * repairs, in seven families:
 *
 *   CMPccXADD (32)  VEX.128.66.0F38.W0/W1 E0..EF /r.  Capstone has no
 *                   entry and no X86_INS_ id for the extension at all,
 *                   yet TCG_7_1_EAX_FEATURES advertises CMPCCXADD.
 *   x87 aliases (7) DC D0+i / DC D8+i / DD C8+i / DE D0+i / DF C8+i /
 *                   DF D0+i / DF D8+i -- the reserved alias encodings of
 *                   FCOM, FCOMP, FXCH and FSTP.  Capstone decodes the
 *                   canonical spelling of each and refuses the alias.
 *   hint NOPs (9)   0F 18 /0../3 and 0F 1A..1E, register form.  Capstone
 *                   decodes 0F 18 /4../7 and 0F 19 but not these.
 *   VEX.W=1 (6)     VPCMPESTRI/ESTRM/ISTRI in their 64-bit-operand form.
 *   prefetch (5)    0F 0D /3../7, the reserved 3DNow! prefetch hints.
 *   MOVSXD (2)      63 /r without REX.W.
 *   SALC (1)        D6.  QEMU MODELS this (X86_OP_ENTRYw(SALC, 0,b) in
 *                   decode-new.c.inc) where XED calls it an undefined
 *                   byte, so it executes and must be described.
 *
 * Six of the seven are repaired by SURROGATE ENCODING rather than by a
 * hand-written operand walk: the bytes are rewritten into an encoding
 * that is architecturally equivalent in its register operands and that
 * Capstone does decode, Capstone decodes THAT, and the result goes
 * through the ordinary cap_fill_x86_operands() path -- so every access-
 * flag workaround above applies unchanged and no second ModRM/SIB/VEX
 * operand decoder is introduced that could drift from the first.  Each
 * surrogate is chosen to have the SAME LENGTH as the encoding it stands
 * in for, so insn_size stays the truth about the bytes.  Where the
 * surrogate's identity or access flags differ from the real
 * instruction's, the difference is named in the plan and applied
 * afterwards; nothing else is touched.
 *
 * SALC has no equivalent of its length and is filled directly.
 *
 * All of this is a workaround for an upstream gap and should be
 * re-measured on a Capstone version bump: an encoding Capstone learns to
 * decode never reaches this code, so a family that stops firing is
 * upstream having fixed it -- which the coverage harness will show as
 * the row leaving the tracer_decode_fail bucket either way.
 */

/* ModRM/VEX register number -> Capstone id, for the two views this needs. */
static const uint16_t cap_x86_gpr32_by_num[16] = {
    X86_REG_EAX, X86_REG_ECX, X86_REG_EDX,  X86_REG_EBX,
    X86_REG_ESP, X86_REG_EBP, X86_REG_ESI,  X86_REG_EDI,
    X86_REG_R8D, X86_REG_R9D, X86_REG_R10D, X86_REG_R11D,
    X86_REG_R12D, X86_REG_R13D, X86_REG_R14D, X86_REG_R15D,
};
static const uint16_t cap_x86_gpr64_by_num[16] = {
    X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX,
    X86_REG_RSP, X86_REG_RBP, X86_REG_RSI, X86_REG_RDI,
    X86_REG_R8,  X86_REG_R9,  X86_REG_R10, X86_REG_R11,
    X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
};

/* E0..EF condition suffixes, in encoding order (Intel SDM CMPccXADD). */
static const char *const cap_x86_cmpccxadd_mnem[16] = {
    "cmpoxadd",  "cmpnoxadd",  "cmpbxadd",  "cmpnbxadd",
    "cmpzxadd",  "cmpnzxadd",  "cmpbexadd", "cmpnbexadd",
    "cmpsxadd",  "cmpnsxadd",  "cmppxadd",  "cmpnpxadd",
    "cmplxadd",  "cmpnlxadd",  "cmplexadd", "cmpnlexadd",
};

typedef struct CapX86Pfx {
    unsigned op_at;     /* index of the first opcode byte */
    uint8_t  rex;       /* the REX byte, 0 when absent */
    bool     p66, pf2, pf3;
} CapX86Pfx;

/*
 * Locate the opcode inside a legacy-prefix run.  Only the position and
 * the three mandatory-prefix bits are needed; nothing here decodes an
 * operand, so an unrecognised byte simply ends the run.
 */
static bool cap_x86_scan_prefixes(const uint8_t *d, size_t n, CapX86Pfx *p)
{
    unsigned i = 0;

    memset(p, 0, sizeof(*p));
    while (i < n) {
        uint8_t b = d[i];
        if (b == 0x66) { p->p66 = true; i++; continue; }
        if (b == 0xf2) { p->pf2 = true; i++; continue; }
        if (b == 0xf3) { p->pf3 = true; i++; continue; }
        if (b == 0x67 || b == 0xf0 || b == 0x2e || b == 0x36 ||
            b == 0x3e || b == 0x26 || b == 0x64 || b == 0x65) {
            i++;
            continue;
        }
        break;
    }
    /* A REX prefix is only a REX when it immediately precedes the opcode. */
    if (i < n && (d[i] & 0xf0) == 0x40) {
        p->rex = d[i];
        i++;
    }
    p->op_at = i;
    return i < n;
}

/*
 * What a repaired decode has to change once Capstone has decoded the
 * surrogate.  An empty plan (mnem NULL, insn_id 0, no flags) means the
 * surrogate already describes the instruction exactly.
 */
typedef struct CapX86GapPlan {
    uint8_t  bytes[16];   /* the surrogate encoding */
    unsigned len;         /* bytes valid in ->bytes; == the true length */
    const char *mnem;     /* true mnemonic, or NULL to keep Capstone's */
    unsigned insn_id;     /* true X86_INS_*, or 0 to keep Capstone's */
    bool     mem_rw;      /* the MEM operand is read-modify-write */
    bool     dest_rw;     /* the written REG operand is also a source */
    bool     no_reg_write;/* the surrogate writes a register and this does not */
    uint16_t extra_read;  /* Capstone reg id to add to regs_read[], 0 none */
} CapX86GapPlan;

/*
 * Decide whether these bytes are one of the seven families and, if so,
 * build the surrogate.  Returns false for everything else, which leaves
 * the decode failed exactly as before.
 */
static bool cap_x86_gap_plan(const uint8_t *d, size_t n, CapX86GapPlan *r)
{
    CapX86Pfx p;
    unsigned o, len;
    uint8_t op, modrm;

    memset(r, 0, sizeof(*r));
    if (n < 1 || !cap_x86_scan_prefixes(d, n, &p)) {
        return false;
    }
    o = p.op_at;
    op = d[o];
    len = MIN(n, sizeof(r->bytes));

    /*
     * VEX families.  A VEX prefix is only a VEX when no REX and no
     * mandatory prefix precedes it, and C4 needs three payload bytes
     * plus a ModRM.
     */
    if (op == 0xc4 && !p.rex && !p.p66 && !p.pf2 && !p.pf3 && o + 4 < n) {
        unsigned map = d[o + 1] & 0x1f;
        unsigned pp  = d[o + 2] & 0x03;
        bool     w   = (d[o + 2] & 0x80) != 0;
        bool     l   = (d[o + 2] & 0x04) != 0;
        uint8_t  vop = d[o + 3];

        modrm = d[o + 4];

        /*
         * CMPccXADD -- VEX.128.66.0F38.W0/W1 E0..EF /r, memory form only
         * (the register form does not exist).  The surrogate is ANDN,
         * VEX.LZ.0F38.W0/W1 F2 /r: the same three-operand
         * (ModRM.reg, VEX.vvvv, ModRM.r/m) shape over the same register
         * class at the same width, reached by clearing pp and swapping
         * the opcode byte, so ModRM/SIB/displacement decoding and the
         * instruction length are Capstone's own.
         *
         * ANDN and CMPccXADD differ in exactly two places, both stated
         * here rather than left to a reader: ANDN's memory operand is a
         * pure source where CMPccXADD's is read-modify-write, and ANDN's
         * ModRM.reg is a pure destination where CMPccXADD's carries the
         * loaded value back out and so is both.  The implicit RFLAGS
         * write is common to both and needs no repair.
         *
         * insn_id: Capstone has no id for the extension, and insn_id is
         * consumed only by the classification table's O(1) lookup.  XADD
         * is what that table must be asked -- an atomic memory add whose
         * register operand is exchanged with the loaded value -- and the
         * mnemonic below stays the true one, so nothing downstream is
         * told this instruction IS an xadd.
         */
        if (map == 0x02 && pp == 1 && !l && (vop & 0xf0) == 0xe0 &&
            (modrm & 0xc0) != 0xc0) {
            memcpy(r->bytes, d, len);
            r->bytes[o + 2] &= (uint8_t)~0x03;
            r->bytes[o + 3] = 0xf2;
            r->len = len;
            r->mnem = cap_x86_cmpccxadd_mnem[vop & 0x0f];
            r->insn_id = X86_INS_XADD;
            r->mem_rw = true;
            r->dest_rw = true;
            return true;
        }

        /*
         * VPCMPESTRI / VPCMPESTRM / VPCMPISTRI / VPCMPISTRM in their
         * VEX.W=1 form.  W selects whether the implicit length operands
         * are read as RAX/RDX or EAX/EDX; it changes no operand's
         * identity, so clearing it yields the same register sets from an
         * encoding Capstone accepts.
         */
        if (map == 0x03 && pp == 1 && w && vop >= 0x60 && vop <= 0x63) {
            memcpy(r->bytes, d, len);
            r->bytes[o + 2] &= (uint8_t)0x7f;
            r->len = len;
            return true;
        }
        return false;
    }

    /*
     * x87 alias escapes.  Each of these is a second encoding of an
     * instruction Capstone decodes under its canonical escape byte, so
     * the surrogate is that canonical spelling at the same length; the
     * ST(i) operand rides in the low three bits of the ModRM byte and is
     * carried across unchanged.
     */
    if (op >= 0xdc && op <= 0xdf && o + 1 < n && d[o + 1] >= 0xc0) {
        uint8_t sop = 0, smod = 0;

        modrm = d[o + 1];
        if (op == 0xdc && modrm >= 0xd0) {
            sop = 0xd8; smod = modrm;                 /* FCOM / FCOMP  */
        } else if (op == 0xdd && modrm >= 0xc8 && modrm <= 0xcf) {
            sop = 0xd9; smod = modrm;                 /* FXCH          */
        } else if (op == 0xde && modrm >= 0xd0 && modrm <= 0xd7) {
            sop = 0xd8; smod = modrm | 0x08;          /* FCOMP         */
        } else if (op == 0xdf && modrm >= 0xc8 && modrm <= 0xcf) {
            sop = 0xd9; smod = modrm;                 /* FXCH          */
        } else if (op == 0xdf && modrm >= 0xd0 && modrm <= 0xdf) {
            sop = 0xdd; smod = modrm | 0x08;          /* FSTP          */
        }
        if (sop) {
            memcpy(r->bytes, d, len);
            r->bytes[o] = sop;
            r->bytes[o + 1] = smod;
            r->len = len;
            return true;
        }
        return false;
    }

    /* SALC.  No operands and no equivalent one-byte encoding: filled
     * directly by the caller, which is what a zero-length plan means. */
    if (op == 0xd6) {
        r->len = 0;
        r->insn_id = X86_INS_SALC;
        r->mnem = "salc";
        return true;
    }

    /* MOVSXD without REX.W: a 32-bit move, and the 8B /r encoding of
     * that move has the identical ModRM shape and length.  Only the
     * identity is restored afterwards -- MOVSXD is its own generic
     * opcode class and must not be recorded as a plain MOV. */
    if (op == 0x63 && !(p.rex & 0x08)) {
        memcpy(r->bytes, d, len);
        r->bytes[o] = 0x8b;
        r->len = len;
        r->mnem = "movslq";
        r->insn_id = X86_INS_MOVSXD;
        return true;
    }

    if (op != 0x0f || o + 2 >= n) {
        return false;
    }
    modrm = d[o + 2];

    /*
     * Reserved hint NOPs.  0F 1F /r is the architecturally defined
     * multi-byte NOP and has the same ModRM shape at the same length.
     *
     * XED gives 0F 18 one operand (the r/m) and 0F 1A..1E two (the r/m
     * AND the ModRM.reg field), and 0F 1F -- the surrogate -- has one.
     * The second register is therefore added back for the 1A..1E forms,
     * because dropping it would make the trace's set a strict subset of
     * the reference's, which is the one direction this project treats as
     * a defect.
     *
     * A MANDATORY PREFIX TAKES THE WHOLE SPACE SOMEWHERE ELSE, so one
     * carried here means these bytes are not a hint NOP and must not be
     * repaired into one.  66/F3/F2 with 0F 1A and 0F 1B are the four MPX
     * BND forms; F3 0F 1E /1 is RDSSPD / RDSSPQ, which READS the shadow
     * stack pointer and WRITES its r/m register; F3 0F 1E FA / FB are
     * ENDBR64 / ENDBR32.  Calling any of those a NOP would replace a
     * missing register set with a WRONG one, which is the worse defect
     * -- it reads as agreement.  This exclusion is not a guess: without
     * it the boundary sweep reports 66 F3 0F 1E C8 as `nopw %ax` against
     * LLVM's `rdsspd %eax`, losing the destination write outright.
     *
     * The test guards the 3DNow! prefetch family below as well.  0F 0D
     * has no prefix-dependent meaning, so nothing is known to be lost
     * there -- but a repair whose whole justification is that the code
     * point is architecturally reserved has no business claiming a
     * prefixed form nobody has enumerated.
     */
    /*
     * ONE code point in the F3 half of that space is a reserved NOP and
     * not an assignment: IBHF, F3 REX.W 0F 1E F8.  QEMU's decoder agrees
     * -- [0x1e] = X86_OP_ENTRY1(NOP, nop,v) is ungated and prefix-blind,
     * so a guest executes these bytes as a plain reserved NOP -- and XED
     * decodes them as NOP reading the r/m and the ModRM.reg register,
     * which is exactly what the repair below produces.  Measured, not
     * assumed: qemu-x86_64 -cpu max RUNS f3 48 0f 1e f8 where it raises
     * SIGILL on every other encoding in this arc's gap set, and the
     * surrogate f3 48 0f 1f f8 keeps the F3 prefix, so the length stays
     * 5.  The exception is written as ONE code point rather than as "F3
     * with 0F 1E", because /1 is RDSSPD/RDSSPQ and FA/FB are
     * ENDBR64/ENDBR32 and those must keep refusing.
     */
    if (!(p.pf3 && !p.p66 && !p.pf2 && d[o + 1] == 0x1e && modrm == 0xf8) &&
        (p.p66 || p.pf2 || p.pf3)) {
        return false;
    }
    if (d[o + 1] == 0x18 && modrm >= 0xc0 && ((modrm >> 3) & 7) <= 3) {
        memcpy(r->bytes, d, len);
        r->bytes[o + 1] = 0x1f;
        r->len = len;
        return true;
    }
    if (d[o + 1] >= 0x1a && d[o + 1] <= 0x1e && modrm >= 0xc0) {
        unsigned reg = ((modrm >> 3) & 7) | ((p.rex & 0x04) ? 8 : 0);

        memcpy(r->bytes, d, len);
        r->bytes[o + 1] = 0x1f;
        r->len = len;
        r->extra_read = (p.rex & 0x08) ? cap_x86_gpr64_by_num[reg]
                                       : cap_x86_gpr32_by_num[reg];
        return true;
    }

    /*
     * UD0, 0F FF /r.  Capstone 6.0.0-Alpha7 decodes it as TWO bytes with
     * NO operands; it has a ModRM and is three or more.  Everything else
     * that has an opinion agrees against Capstone -- XED and iced both
     * read 3 bytes, binutils prints `ud0 %ebx,%ecx` for 0f ff cb, and
     * QEMU's own [0xff] = X86_OP_ENTRYr(UD, nop,v) takes a ModRM operand
     * -- so this is a wrong answer, not a missing one, and it costs the
     * ModRM.reg and r/m registers AND the instruction length.
     *
     * UD1, 0F B9 /r, is the same instruction shape with the same defect
     * and takes the same repair; XED and LLVM both read 3 bytes and both
     * name the ModRM.reg and r/m registers for it.
     *
     * The surrogate is BT, 0F A3 /r: the same two-byte opcode and ModRM
     * shape, both operands READ, nothing written but flags.  The one
     * difference is named and undone below -- BT writes RFLAGS and UD0
     * writes nothing, which XED confirms (BT -> dst RFLAGS, UD0 -> dst
     * empty, same operands otherwise, memory form included).
     */
    if (d[o + 1] == 0xff || d[o + 1] == 0xb9) {
        bool one = d[o + 1] == 0xb9;

        memcpy(r->bytes, d, len);
        r->bytes[o + 1] = 0xa3;
        r->len = len;
        r->mnem = one ? "ud1" : "ud0";
        r->insn_id = one ? X86_INS_UD1 : X86_INS_UD0;
        r->no_reg_write = true;
        return true;
    }

    /*
     * Reserved 3DNow! prefetch hints, 0F 0D /3../7.  AMD defines every
     * reserved code point in the group to behave as PREFETCH, and /0 is
     * PREFETCH itself, so clearing the ModRM.reg field is both the
     * surrogate and the architectural answer.  The register form is
     * excluded deliberately: qemu-x86_64 raises SIGILL on 0F 0D /r with
     * mod == 11, so there is nothing there to describe.
     */
    if (d[o + 1] == 0x0d && (modrm & 0xc0) != 0xc0 &&
        ((modrm >> 3) & 7) >= 3) {
        memcpy(r->bytes, d, len);
        r->bytes[o + 2] = modrm & 0xc7;
        r->len = len;
        return true;
    }

    return false;
}

/*
 * Byte patterns Capstone decodes SUCCESSFULLY and wrongly, which a
 * decode-failure test can never reach.  Kept to the single family that
 * has been measured against three other decoders and against QEMU's own
 * tables: 0F FF, UD0.
 */
static bool cap_x86_misdecoded(const uint8_t *d, size_t n)
{
    CapX86Pfx p;

    if (!cap_x86_scan_prefixes(d, n, &p) || p.op_at + 2 >= n) {
        return false;
    }
    if (p.p66 || p.pf2 || p.pf3) {
        return false;
    }
    return d[p.op_at] == 0x0f &&
           (d[p.op_at + 1] == 0xff || d[p.op_at + 1] == 0xb9);
}

/*
 * Apply the plan's corrections to a filled qemu_plugin_insn_info.  Runs
 * after cap_fill_x86_operands() so that every access-flag workaround
 * above has already had its say about the surrogate.
 */
static void cap_x86_gap_apply(csh handle, const CapX86GapPlan *r,
                              struct qemu_plugin_insn_info *out)
{
    if (r->mnem) {
        g_strlcpy(out->mnemonic, r->mnem, QEMU_PLUGIN_INSN_DETAIL_MNEMSZ);
    }
    if (r->insn_id) {
        out->insn_id = r->insn_id;
    }
    for (uint8_t k = 0; k < out->n_operands; k++) {
        qemu_plugin_operand *op = &out->operands[k];
        if (r->mem_rw && op->type == QEMU_PLUGIN_OP_MEM) {
            op->access = QEMU_PLUGIN_OP_ACC_READ | QEMU_PLUGIN_OP_ACC_WRITE;
        }
        if (r->dest_rw && op->type == QEMU_PLUGIN_OP_REG &&
            (op->access & QEMU_PLUGIN_OP_ACC_WRITE)) {
            op->access |= QEMU_PLUGIN_OP_ACC_READ;
        }
    }
    if (r->no_reg_write) {
        out->n_regs_write = 0;
        for (uint8_t k = 0; k < out->n_operands; k++) {
            qemu_plugin_operand *op = &out->operands[k];
            if (op->type == QEMU_PLUGIN_OP_REG) {
                op->access &= ~QEMU_PLUGIN_OP_ACC_WRITE;
            }
        }
    }
    if (r->extra_read &&
        out->n_regs_read < QEMU_PLUGIN_INSN_DETAIL_MAX_IREGS) {
        uint8_t i = out->n_regs_read;

        cap_copy_reg_name(out->regs_read[i],
                          QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                          handle, r->extra_read, CS_ARCH_X86);
        out->regs_read_id[i] = r->extra_read;
        out->n_regs_read = i + 1;
    }
}

/*
 * IMPLICIT REGISTERS CAPSTONE DOES NOT REPORT.
 *
 * Capstone fills regs_read[]/regs_write[] from its own implicit-operand
 * tables, and for a family of instructions whose whole dependency IS
 * implicit those tables are empty or short.  The result is not a decode
 * failure -- the instruction decodes, with the right mnemonic and the
 * right length -- so nothing above catches it: it is a SUBSET answer,
 * the one direction this project treats as disqualifying, arriving
 * dressed as a successful decode.
 *
 * Every row below is the architectural dependency, and every row was
 * measured against BOTH reference decoders on the encoding named beside
 * it.  Where XED and LLVM disagree the row follows XED, which is this
 * arc's primary reference, and the disagreement is named:
 *   MWAITX  XED reads RAX,RCX and writes RAX; LLVM reads RAX,RBX,RCX and
 *           writes nothing.  AMD's EBX timer operand is real but only
 *           consulted when ECX[1] is set, and a conditional source is
 *           still a source (R4) -- so RBX is INCLUDED, which makes this
 *           row a named superset of XED rather than a subset of LLVM.
 *   SMSW / LMSW / SWAPGS / RD*BASE / WR*BASE / LFS / LGS
 *           LLVM names no implicit register at all for these; XED names
 *           the control or segment register, and QEMU's own translation
 *           reads or writes exactly that state.
 *
 * A register already present as an explicit operand is listed anyway --
 * the file's own cap_x86_add_implicit() drops the duplicate -- so the
 * table reads as the architectural statement it is rather than as a
 * diff against whatever Capstone happened to supply.
 */
typedef struct CapX86Implicit {
    unsigned insn_id;
    bool     bare;        /* only when NO mandatory prefix is present */
    uint16_t read[5];
    uint16_t write[3];
} CapX86Implicit;

static const CapX86Implicit cap_x86_implicit[] = {
    /* d7            XLAT: AL := [RBX + AL], through DS */
    { X86_INS_XLATB,      false, { X86_REG_RAX, X86_REG_RBX },
                                 { X86_REG_RAX } },
    /* 0f c7 /1      EDX:EAX compared, ECX:EBX stored, both halves written */
    { X86_INS_CMPXCHG8B,  false, { X86_REG_RAX, X86_REG_RBX, X86_REG_RCX,
                                   X86_REG_RDX },
                                 { X86_REG_RDX } },
    /* 48 0f c7 /1   the 128-bit form, same shape */
    { X86_INS_CMPXCHG16B, false, { X86_REG_RAX, X86_REG_RBX, X86_REG_RCX,
                                   X86_REG_RDX },
                                 { X86_REG_RDX } },
    /* 0f 01 /4      SMSW: the machine status word IS the low half of CR0 */
    { X86_INS_SMSW,       false, { X86_REG_CR0 },      { 0 } },
    /* 0f 01 /6      LMSW writes it */
    { X86_INS_LMSW,       false, { 0 },                { X86_REG_CR0 } },
    /* 0f 01 f8      SWAPGS exchanges GS.base with KernelGSbase */
    { X86_INS_SWAPGS,     false, { X86_REG_GS },       { X86_REG_GS } },
    /* f3 0f ae /0../3   the FS/GS base accessors */
    { X86_INS_RDFSBASE,   false, { X86_REG_FS },       { 0 } },
    { X86_INS_WRFSBASE,   false, { 0 },                { X86_REG_FS } },
    { X86_INS_RDGSBASE,   false, { X86_REG_GS },       { 0 } },
    { X86_INS_WRGSBASE,   false, { 0 },                { X86_REG_GS } },
    /* 0f b4 /r, 0f b5 /r   LFS/LGS load the SELECTOR as well as the offset */
    { X86_INS_LFS,        false, { 0 },                { X86_REG_FS } },
    { X86_INS_LGS,        false, { 0 },                { X86_REG_GS } },
    /* 0f 01 fc      CLZERO zeroes the line RAX addresses */
    { X86_INS_CLZERO,     false, { X86_REG_RAX },      { 0 } },
    /*
     * 0f 01 fa / fb   MONITORX and MWAITX, the AMD MONITOR pair, and the
     * only rows here that are `bare`.  A MANDATORY PREFIX TAKES THIS SPACE
     * ELSEWHERE and Capstone does not notice: it decodes f3 0f 01 fa as
     * `monitorx`, and those bytes are MCOMMIT.  XED reads them as MCOMMIT
     * writing RFLAGS and reading nothing; LLVM MC repeats Capstone's
     * mistake.  Putting MONITORX's three reads on an instruction that has
     * none would be a WRONG set standing in for a missing one, so the
     * prefix disqualifies the row.  The misnaming itself is not repaired
     * here and stays visible as one disagreeing opcode.
     */
    { X86_INS_MONITORX,   true,  { X86_REG_RAX, X86_REG_RCX, X86_REG_RDX },
                                 { 0 } },
    { X86_INS_MWAITX,     true,  { X86_REG_RAX, X86_REG_RBX, X86_REG_RCX },
                                 { X86_REG_RAX } },
    /*
     * The leaf-dispatch instructions.  Capstone hands every one of these
     * over with NO operands and NO implicit registers at all -- the whole
     * dependency is the register convention, and without it the trace shows
     * an instruction that reads nothing and writes nothing.  Each set below
     * is Intel XED's, and where a second reference exists it is named.
     *
     * EVERY ONE OF THESE IS `bare`, for the reason the MONITORX row above
     * gives: Capstone's group-7 decoder does not look at the mandatory
     * prefix, so it returns `encls` for 66 0F 01 CF (SEAMCALL) and for
     * F3 0F 01 CF, `rdpkru` for F3 0F 01 EE (CLUI), `wrpkru` for
     * F3 0F 01 EF (STUI), and `vmfunc` and `enclu` for their prefixed code
     * points too -- all measured, and LLVM MC disagrees with Capstone on
     * each.  Attaching this table's registers to those bytes would put a
     * WRONG set where a missing one is, which is the worse defect; the
     * prefix disqualifies the row and the misnaming stays visible.
     *
     * 0f 01 cf/d7/c0  ENCLS / ENCLU / ENCLV: the leaf number is in EAX and
     *                 RBX/RCX/RDX are the leaf-specific in/out registers.
     *                 iced-x86 agrees on the reads and adds RAX and RFLAGS
     *                 to the writes; the narrower XED set is used.
     */
    { X86_INS_ENCLS,      true,  { X86_REG_RAX, X86_REG_RBX, X86_REG_RCX,
                                   X86_REG_RDX },
                                 { X86_REG_RBX, X86_REG_RCX, X86_REG_RDX } },
    { X86_INS_ENCLU,      true,  { X86_REG_RAX, X86_REG_RBX, X86_REG_RCX,
                                   X86_REG_RDX },
                                 { X86_REG_RBX, X86_REG_RCX, X86_REG_RDX } },
    { X86_INS_ENCLV,      true,  { X86_REG_RAX, X86_REG_RBX, X86_REG_RCX,
                                   X86_REG_RDX },
                                 { X86_REG_RBX, X86_REG_RCX, X86_REG_RDX } },
    /* 0f 01 ee/ef   the protection-key register accessors.  XED, iced-x86
     *               and LLVM MC give byte-identical sets for RDPKRU. */
    { X86_INS_RDPKRU,     true,  { X86_REG_RCX },
                                 { X86_REG_RAX, X86_REG_RDX } },
    { X86_INS_WRPKRU,     true,  { X86_REG_RAX, X86_REG_RCX, X86_REG_RDX },
                                 { 0 } },
    /* c6 f8 ib / c7 f8   the TSX pair.  XABORT hands its imm8 status to the
     *                    fallback in EAX, and XBEGIN's fallback path writes
     *                    EAX too, so on both the register is a conditional
     *                    write and therefore also a read (R4). */
    { X86_INS_XABORT,     false, { X86_REG_RAX },      { X86_REG_RAX } },
    { X86_INS_XBEGIN,     false, { X86_REG_RAX },      { X86_REG_RAX } },
    /* 0f 01 d4   VMFUNC: EAX selects the function.  ECX is the parameter --
     *            the EPTP-list index for function 0 -- and iced-x86 names
     *            it where XED does not, so it is carried as a superset. */
    { X86_INS_VMFUNC,     true,  { X86_REG_RAX, X86_REG_RCX }, { 0 } },
};

static void cap_x86_apply_implicit_table(qemu_plugin_insn_info *out,
                                         csh handle, const cs_insn *insn)
{
    for (size_t i = 0; i < ARRAY_SIZE(cap_x86_implicit); i++) {
        const CapX86Implicit *e = &cap_x86_implicit[i];
        CapX86Pfx p;

        if (e->insn_id != insn->id) {
            continue;
        }
        if (e->bare) {
            if (!cap_x86_scan_prefixes(insn->bytes, insn->size, &p) ||
                p.p66 || p.pf2 || p.pf3) {
                return;
            }
        }
        for (size_t k = 0; k < ARRAY_SIZE(e->read) && e->read[k]; k++) {
            cap_x86_add_implicit(out, handle, e->read[k], false);
        }
        for (size_t k = 0; k < ARRAY_SIZE(e->write) && e->write[k]; k++) {
            cap_x86_add_implicit(out, handle, e->write[k], true);
        }
        return;
    }
}

/*
 * SALC: AL := CF ? 0xFF : 0.  One byte, no ModRM, no explicit operand;
 * the whole dependency is the implicit pair.
 */
static void cap_x86_gap_fill_salc(csh handle, const uint8_t *d, size_t n,
                                  struct qemu_plugin_insn_info *out)
{
    CapX86Pfx p;

    cap_x86_scan_prefixes(d, n, &p);
    g_strlcpy(out->mnemonic, "salc", QEMU_PLUGIN_INSN_DETAIL_MNEMSZ);
    out->op_str[0] = '\0';
    out->insn_id = X86_INS_SALC;
    out->insn_size = (uint8_t)(p.op_at + 1);
    out->n_operands = 0;
    out->n_regs_read = 1;
    out->regs_read_id[0] = X86_REG_EFLAGS;
    cap_copy_reg_name(out->regs_read[0], QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                      handle, X86_REG_EFLAGS, CS_ARCH_X86);
    out->n_regs_write = 1;
    out->regs_write_id[0] = X86_REG_AL;
    cap_copy_reg_name(out->regs_write[0], QEMU_PLUGIN_INSN_DETAIL_REG_NAMESZ,
                      handle, X86_REG_AL, CS_ARCH_X86);
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
    bool prof = cap_profiling();
    int64_t t0 = prof ? cap_prof_now() : 0;

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
        cs_option(handle, CS_OPT_DETAIL,
                  cap_nodetail() ? CS_OPT_OFF : CS_OPT_ON);
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
    CapX86GapPlan gap;
    const CapX86GapPlan *repaired = NULL;

    if (insn->detail) {
        memset(insn->detail, 0, sizeof(*insn->detail));
    }

    /*
     * Almost every repair below is reached because Capstone read NOTHING.
     * UD0 is reached because Capstone reads the WRONG THING and reports
     * success, which no failure test can catch; the byte pattern is the
     * only signal there is, so it is tested before the decode rather than
     * after it.
     */
    if (cap_arch == CS_ARCH_X86 && (cap_mode & CS_MODE_64) &&
        cap_x86_misdecoded(data, data_size)) {
        goto repair;
    }

    if (!cs_disasm_iter(handle, &code, &sz, &addr, insn)) {
    repair:
        /*
         * Capstone read nothing at all.  On x86-64 that is a decode gap
         * rather than an invalid instruction for the seven families
         * cap_x86_gap_plan() knows about; repair those and let the
         * ordinary fill below describe the result.  Everything else
         * fails exactly as before.
         */
        if (cap_arch != CS_ARCH_X86 || !(cap_mode & CS_MODE_64) ||
            !cap_x86_gap_plan(data, data_size, &gap)) {
            return false;   /* handle stays cached for the next call */
        }
        if (!gap.len) {
            cap_x86_gap_fill_salc(handle, data, data_size, out);
            cap_mutate_detail(out);
            return true;
        }
        code = gap.bytes;
        sz   = gap.len;
        addr = pc;
        if (insn->detail) {
            memset(insn->detail, 0, sizeof(*insn->detail));
        }
        if (!cs_disasm_iter(handle, &code, &sz, &addr, insn)) {
            return false;
        }
        repaired = &gap;
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
        int64_t t_op = prof ? cap_prof_now() : 0;

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
            if (cap_mode & CS_MODE_64) {
                cap_x86_apply_implicit_table(out, handle, insn);
            }
            break;
        case CS_ARCH_ARM64:
            cap_fill_arm64_operands(handle, cap_mode, insn, out);
            break;
        default:
            cap_fill_generic_operands(handle, insn, out, cap_arch);
            break;
        }
        if (prof) {
            cap_prof_ns_operands += cap_prof_now() - t_op;
        }
    }

    if (repaired) {
        cap_x86_gap_apply(handle, repaired, out);
    }

    cap_mutate_detail(out);

    if (prof) {
        cap_prof_calls++;
        cap_prof_ns_total += cap_prof_now() - t0;
        if (cap_prof_calls % cap_prof_every == 0) {
            cap_prof_dump();
        }
    }
    /* handle / insn stay cached in the thread-local slots for reuse */
    return true;
}
