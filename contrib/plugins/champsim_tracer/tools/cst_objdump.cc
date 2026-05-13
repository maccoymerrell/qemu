/*
 * ChampSim Tracer offline tools — Capstone-backed objdump-style disasm
 * (impl).
 *
 * Two builds:
 *
 *   -DCST_HAVE_CAPSTONE  real backend; this TU includes
 *                        <capstone/capstone.h> and emits cs_disasm_iter
 *                        per insn.
 *   (undefined)          stub backend; the methods compile to a small
 *                        constant return-false, no capstone include
 *                        and no link dependency.  Lets downstream
 *                        re-users compile this file unchanged in
 *                        environments without capstone — the --objdump
 *                        column is silently disabled at run time.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cst_objdump.h"

#ifdef CST_HAVE_CAPSTONE
#  include <capstone/capstone.h>
#endif

namespace cst {

#ifdef CST_HAVE_CAPSTONE

namespace {

/* Translate the trace's ISA byte to a (capstone arch, mode) pair.
 * Returns false for ISAs Capstone doesn't cover. */
bool cs_arch_for_trace_isa(uint8_t trace_isa, cs_arch *out_arch,
                           cs_mode *out_mode)
{
    switch (trace_isa) {
    case 1:
        *out_arch = CS_ARCH_X86;
        *out_mode = CS_MODE_64;
        return true;
    case 2:
        *out_arch = CS_ARCH_AARCH64;
        *out_mode = CS_MODE_LITTLE_ENDIAN;
        return true;
    case 3:
        *out_arch = CS_ARCH_RISCV;
        *out_mode = CS_MODE_RISCV64;
        return true;
    case 4:
        *out_arch = CS_ARCH_MIPS;
        *out_mode = (cs_mode)(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN);
        return true;
    default:
        return false;
    }
}

}  /* namespace */

ObjdumpRenderer::~ObjdumpRenderer()
{
    if (open_) {
        csh h = (csh)handle_;
        cs_close(&h);
    }
}

bool ObjdumpRenderer::open(uint8_t trace_isa)
{
    cs_arch arch;
    cs_mode mode;
    if (!cs_arch_for_trace_isa(trace_isa, &arch, &mode)) return false;

    csh h;
    if (cs_open(arch, mode, &h) != CS_ERR_OK) return false;
    cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    handle_ = (uintptr_t)h;
    open_   = true;
    return true;
}

bool ObjdumpRenderer::render_one(uint64_t pc, const uint8_t *bytes,
                                 size_t n_bytes, std::string *out) const
{
    if (!open_ || !bytes || n_bytes == 0) return false;

    csh h = (csh)handle_;
    cs_insn *insn = cs_malloc(h);
    if (!insn) return false;

    const uint8_t *code = bytes;
    size_t         size = n_bytes;
    uint64_t       addr = pc;
    bool ok = cs_disasm_iter(h, &code, &size, &addr, insn);
    if (ok) {
        size_t before = out->size();
        out->append(insn->mnemonic);
        while (out->size() - before < MNEM_COL) out->push_back(' ');
        if (insn->op_str[0]) {
            out->push_back(' ');
            out->append(insn->op_str);
        }
    }
    cs_free(insn, 1);
    return ok;
}

#else  /* !CST_HAVE_CAPSTONE — stub backend */

ObjdumpRenderer::~ObjdumpRenderer() = default;

bool ObjdumpRenderer::open(uint8_t trace_isa)
{
    (void)trace_isa;
    return false;
}

bool ObjdumpRenderer::render_one(uint64_t pc, const uint8_t *bytes,
                                 size_t n_bytes, std::string *out) const
{
    (void)pc; (void)bytes; (void)n_bytes; (void)out;
    return false;
}

#endif  /* CST_HAVE_CAPSTONE */

}  /* namespace cst */
