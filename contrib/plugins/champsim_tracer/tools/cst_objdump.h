/*
 * ChampSim Tracer offline tools — Capstone-backed objdump-style disasm.
 *
 * Optional component.  cst_decode uses it for the --objdump column;
 * the core body walker / Instruction builder does NOT depend on this
 * header.  The header itself is intentionally capstone-free: the
 * implementation file pulls libcapstone in only when
 * CST_HAVE_CAPSTONE is defined at build time.
 *
 * Build matrix:
 *
 *   -DCST_HAVE_CAPSTONE   The real backend; link against capstone.
 *   (undefined)           Stub backend: open() returns false and
 *                         render_one() is a no-op that returns false.
 *
 * Downstream consumers who rip cst_decode into their own simulator
 * can compile cst_objdump.cc without -DCST_HAVE_CAPSTONE and without
 * a capstone link dependency.  Calls into ObjdumpRenderer will
 * compile and link cleanly; the --objdump feature just stays
 * unavailable at run time.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace cst {

class ObjdumpRenderer {
public:
    ObjdumpRenderer() = default;
    ~ObjdumpRenderer();

    ObjdumpRenderer(const ObjdumpRenderer &)            = delete;
    ObjdumpRenderer &operator=(const ObjdumpRenderer &) = delete;

    /* Open the backend for the trace's ISA (1=x86_64, 2=aarch64,
     * 3=riscv64, 4=mipsel).  Returns true when ready to disassemble;
     * false for an unsupported ISA, on capstone open() failure, or
     * when this TU was built without CST_HAVE_CAPSTONE.  Callers
     * should suppress the objdump column on false. */
    bool open(uint8_t trace_isa);

    /* True after a successful open().  Cheap predicate the renderer
     * can check before calling render_one() per insn. */
    bool is_open() const { return open_; }

    /* Disassemble one instruction at @pc from @bytes (length
     * @n_bytes).  Appends "mnem  ops" to @out (mnemonic padded to
     * MNEM_COL chars so the operand column lines up).  Returns true
     * on success; false on capstone disasm error, on an unopened
     * renderer, or when this TU was built without CST_HAVE_CAPSTONE. */
    bool render_one(uint64_t pc, const uint8_t *bytes, size_t n_bytes,
                    std::string *out) const;

    /* Width of the mnemonic column written into @out by render_one(),
     * exposed so renderers can pad to a stable downstream column. */
    static constexpr size_t MNEM_COL = 8;

private:
    /* csh handle when built with capstone (typedef size_t csh in
     * libcapstone), 0 otherwise.  Stored as uintptr_t so the public
     * header stays capstone-free. */
    uintptr_t handle_ = 0;
    bool      open_   = false;
};

}  /* namespace cst */
