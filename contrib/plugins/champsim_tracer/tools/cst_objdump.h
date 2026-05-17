/*
 * ChampSim Tracer offline tools — Capstone-backed objdump-style disasm.
 *
 * Optional component for cst_decode's --objdump column; the core
 * walker does not depend on it.  Header is capstone-free.  With
 * -DCST_HAVE_CAPSTONE this is the real backend; undefined gives a
 * stub (open()/render_one() return false) so downstream re-users
 * link cleanly without a capstone dependency, --objdump just disabled
 * at run time.
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
     * 3=riscv64, 4=mipsel).  False for unsupported ISA, capstone
     * open() failure, or a no-capstone build; caller suppresses the
     * objdump column on false. */
    bool open(uint8_t trace_isa);

    bool is_open() const { return open_; }

    /* Disassemble one insn at @pc from @bytes[@n_bytes]; append
     * "mnem  ops" to @out (mnemonic padded to MNEM_COL).  False on
     * disasm error, unopened renderer, or a no-capstone build. */
    bool render_one(uint64_t pc, const uint8_t *bytes, size_t n_bytes,
                    std::string *out) const;

    /* Mnemonic column width render_one() pads to. */
    static constexpr size_t MNEM_COL = 8;

private:
    /* csh handle (libcapstone typedefs csh = size_t), 0 otherwise.
     * uintptr_t so the public header stays capstone-free. */
    uintptr_t handle_ = 0;
    bool      open_   = false;
};

}  /* namespace cst */
