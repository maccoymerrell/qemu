/*
 * ChampSim Tracer offline tools — objdump-style cosmetic disassembly.
 *
 * Optional component for cst_decode's --objdump column; the core
 * walker does not depend on it, and nothing this renderer produces
 * reaches a verdict, a table or the wire (ruling J6, 2026-08-25).
 *
 * BACKEND: GNU binutils `objdump`, run as a CHILD PROCESS, one batch
 * per contiguous address region.  Not Capstone, and not libopcodes:
 *
 *   * libopcodes/BFD are GPL-3.0-or-later.  These tools are
 *     GPL-2.0-or-later inside a QEMU tree that is GPL-2.0-only in
 *     places; a subprocess is an arms-length boundary that raises no
 *     such question, and it is also the reason QEMU itself carries no
 *     bfd dependency.
 *   * A separate process cannot touch the decoder's structures, so
 *     "cosmetic only" is a property of the design rather than a
 *     promise about call sites.  The rendered text enters as a
 *     std::string and leaves through one printed column.
 *   * No new build-time dependency: cst_decode links nothing extra,
 *     and a host without the right objdump degrades to the same
 *     "column disabled" path an unsupported ISA already takes.
 *
 * QEMU's own disas/ directory was not reused: after the Capstone
 * migration it holds no x86_64 and no aarch64 disassembler, so it can
 * serve at most two of the four traced ISAs.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace cst {

class ObjdumpRenderer {
public:
    ObjdumpRenderer() = default;
    ~ObjdumpRenderer() = default;

    ObjdumpRenderer(const ObjdumpRenderer &)            = delete;
    ObjdumpRenderer &operator=(const ObjdumpRenderer &) = delete;

    /* Locate and probe a working objdump for the trace's ISA
     * (1=x86_64, 2=aarch64, 3=riscv64, 4=mipsel).  False for an
     * unsupported ISA or when no candidate program disassembles this
     * ISA's probe encoding.  $CST_OBJDUMP overrides the search.
     * The probe runs the production path end to end, so a program
     * that cannot decode the ISA fails here rather than silently
     * rendering "(undecoded)" for every instruction. */
    bool open(uint8_t trace_isa);

    bool is_open() const { return open_; }

    /* Program actually selected by open(), "" when not open. */
    const std::string &program() const { return prog_; }

    /* Register one instruction for batched disassembly.  Cheap; does
     * not spawn anything.  No-op when the renderer is not open. */
    void prefetch(uint64_t pc, const uint8_t *bytes, size_t n_bytes);

    /* Disassemble everything prefetch() collected, batching by
     * contiguous address region so a whole trace costs a handful of
     * objdump runs rather than one per instruction.  Returns the
     * number of instructions it could NOT decode. */
    size_t prefetch_run();

    /* Disassemble one insn at @pc from @bytes[@n_bytes]; append
     * "mnem  ops" to @out (mnemonic padded to MNEM_COL).  Served from
     * the prefetch cache when possible, otherwise by a single-
     * instruction objdump run.  False on disasm error or an unopened
     * renderer. */
    bool render_one(uint64_t pc, const uint8_t *bytes, size_t n_bytes,
                    std::string *out) const;

    /* Mnemonic column width render_one() pads to. */
    static constexpr size_t MNEM_COL = 8;

private:
    using Key = std::pair<uint64_t, std::string>;   /* (pc, raw bytes) */

    /* One objdump run over @items (all distinct pcs, sorted); fills
     * cache_.  Returns the number of items left unresolved. */
    size_t run_region(const std::vector<Key> &items) const;
    bool   lookup(const Key &k, std::string *out) const;

    std::string prog_;            /* objdump program path/name       */
    const void *spec_    = nullptr;  /* per-ISA IsaSpec, static      */
    bool        open_    = false;

    /* mutable: render_one() is const by contract with the callers,
     * but memoises and may fall back to a one-shot run. */
    mutable std::map<Key, std::string> cache_;  /* "" = undecodable  */
    std::set<Key>                      pending_;
};

}  /* namespace cst */
