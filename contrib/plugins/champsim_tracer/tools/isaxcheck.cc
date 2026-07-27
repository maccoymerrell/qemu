/*
 * isaxcheck — independent ground-truth cross-check of the decode metadata
 * the ChampSim Tracer actually consumes, against the LLVM MC layer.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * WHY THIS EXISTS
 * ---------------
 * Per instruction the tracer consumes (a) whether it touches memory and in
 * which direction, (b) its architectural register read/write sets, (c) its
 * branch taxonomy.  All three come from Capstone by way of the correction
 * boundary in disas/capstone.c.  Every self-consistency check the project
 * owns reads that same metadata, so a decoder defect is invisible to all of
 * them — it corrupts the trace and the checks agree with the corruption.
 * Intel PIN cross-validation broke that circle on x86 and found five real
 * defects.  PIN cannot reach aarch64 / riscv64 / mipsel; LLVM's MC layer can,
 * and is a second, independently maintained decoder plus instruction
 * description database.
 *
 * WHAT IS COMPARED — AND WHY IT IS THE BOUNDARY, NOT RAW CAPSTONE
 * ---------------------------------------------------------------
 * The Capstone side of this tool is `cap_disas_raw_detail()` from
 * disas/capstone.c: the exact entry point the plugin calls, with the exact
 * per-ISA operand fillers and defect workarounds applied.  Comparing raw
 * Capstone would be the wrong instrument twice over — every existing
 * workaround would show up as a permanent disagreement needing an allowlist
 * entry, and a newly added workaround would not be verified by the gate at
 * all.  Driving the boundary means:
 *
 *   - a workaround that works makes its defect *disappear* from the report,
 *     which is the proof the workaround is correct;
 *   - a workaround that stops being necessary after a Capstone bump keeps the
 *     gate green (it is then a no-op) — `capstone_workaround_probe` is the
 *     tool that tells you it has become removable;
 *   - a defect not yet worked around stays visible until it is either fixed
 *     or explicitly allowlisted with a justification.
 *
 * The register-set comparison also models the plugin's own
 * `include_implicit_regs` per-ISA policy (see kIncludeImplicitRegs below), so
 * "what LLVM says" is compared against "what the tracer's dependency model
 * would actually record", not against an intermediate that nothing consumes.
 *
 * TWO LAYERS, AND THE ASSERTION BETWEEN THEM
 * ------------------------------------------
 * The boundary is still not the last word.  The plugin repairs some defects
 * one layer further in, inside `decode_detail_to_generic()`:
 * `apply_isa_branch_fixups()` restores the `ra` read RISC-V `ret` loses and
 * the `ra` write `jal`/`jalr` lose — on the order of a billion dynamic
 * instructions per reference trace — and the operand walker, the dependency
 * refiners and the lane-mask refiners rewrite the rest.  Measured against
 * the boundary alone, a repaired defect looks exactly like an unrepaired
 * one, so the gate reports it as a disagreement it does not actually have;
 * and — the reason this matters — IF THE REPAIR REGRESSED THE GATE WOULD
 * NOT NOTICE, because the defect a regression reintroduces is already in
 * the gate's expected output.  A repair no check can see is a repair
 * nothing holds in place.
 *
 * So there are two layers and three modes:
 *
 *   --layer=boundary  (default)  LLVM vs cap_disas_raw_detail()
 *   --layer=fields               LLVM vs the InsnFields the dependency
 *                                model records — generic register ids,
 *                                branch class, memop counts, lane-mask
 *                                kind — obtained by compiling the plugin's
 *                                own champsim_tracer_decode.cc into this
 *                                tool (see isaxcheck_fields.h).  Signature
 *                                classes carry an `F` prefix.
 *   --fixups                     the difference BETWEEN the two layers,
 *                                which is the inventory of plugin-side
 *                                repairs.  Asserted both ways against
 *                                isaxcheck_fixups.txt: a listed repair
 *                                that stops happening fails, and a repair
 *                                nobody wrote down fails.  That is what
 *                                makes a regression in either layer
 *                                visible instead of cancelling out.
 *
 * WHAT IT CANNOT SEE
 * ------------------
 * Capstone's AArch64 / Mips / RISCV instruction tables are auto-synced from
 * LLVM TableGen, so a defect the two share is invisible here.  What this
 * catches is Capstone's *runtime detail path* — alias handling, tied-operand
 * handling, register-class mapping — which is where every defect found so far
 * has lived.  x86's tables are hand-maintained and independent.
 *
 * SUBTARGET MATCHING IS LOAD-BEARING — AND SELF-DETECTING
 * -------------------------------------------------------
 * The Capstone mode must be the one the tracer selects and the LLVM feature
 * set must match it, or "LLVM rejects it" degenerates into "feature not
 * enabled".  An early run with the default RISC-V subtarget produced 1.6M
 * spurious hits that vanished once the mode was aligned.  See kIsaTable and
 * its cross-reference to `cap_mode_*()`.
 *
 * A mismatch used to be silent in BOTH directions.  Too NARROW an LLVM
 * subtarget floods the report with "LLVM was not told about this extension"
 * — 84% of the aarch64 findings at one point — and, far worse, every
 * encoding LLVM rejects is one the register / memory / branch comparisons
 * never run on at all: a rejection short-circuits the whole compare.  Too
 * WIDE a subtarget is the mirror image, and both drift on their own when
 * either decoder is bumped.
 *
 * So the mismatch is now the gate's own instrument.  `D-cs-only` — the
 * boundary decodes it, LLVM rejects it — IS the subtarget-gap signal, and
 * it is reported as a first-class quantity (`subtarget_gap=` in the summary
 * line, counted in encodings as well as signatures) rather than as one
 * bucket among hundreds.  Two rules keep it honest:
 *
 *   - a `D-cs-only` signature can only be allowlisted by an EXACT entry.
 *     A wildcard there is refused at load time, because one `*` is enough
 *     to hide an entire ISA extension's worth of blindness — which is what
 *     `aarch64 D-cs-only *` did.
 *   - an allowlist rule that matches nothing is reported and fails the
 *     gate.  That is the other direction: when an LLVM bump grows a feature
 *     the subtarget now enables, the entry justifying the old gap goes
 *     dead, and a dead entry is an unmaintained one.
 *
 * The maintenance action for a new gap signature is to add the LLVM feature
 * to kIsaTable, not to add an allowlist line.  A line is correct only when
 * LLVM has no such feature to enable (a vendor extension, or Capstone
 * decoding a reserved encoding LLVM refuses); the allowlist says which.
 */

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <capstone/capstone.h>

#include "qemu/qemu-plugin.h"

/* The tracer's own dependency model, linked in as a static library so the
 * plugin's include world stays out of this file.  See isaxcheck_fields.h. */
#include "isaxcheck_fields.h"

/* Implemented by disas/capstone.c, which is compiled into this tool. */
extern "C" bool cap_disas_raw_detail(int cap_arch, unsigned int cap_mode,
                                     const uint8_t *data, size_t data_size,
                                     uint64_t pc,
                                     struct qemu_plugin_insn_info *out);

#include "llvm/Config/llvm-config.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrAnalysis.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/TargetParser/Triple.h"

// ---------------------------------------------------------------------------
// ISA description
// ---------------------------------------------------------------------------

enum Isa { ISA_AARCH64, ISA_RISCV64, ISA_MIPSEL, ISA_X86_64 };

struct IsaCfg {
    const char *name;
    const char *triple;
    const char *cpu;
    // Required subtarget features.  Verified after construction with
    // MCSubtargetInfo::checkFeatures(): LLVM only WARNS about a feature it
    // does not recognise, and a warning on stderr in the middle of a sweep
    // is exactly the silent drift this tool exists to prevent.
    const char *features;
    // Features whose LLVM spelling is version-dependent — extensions that
    // were `experimental-` when this gate was written and are named plainly
    // once they ratify.  Each is probed independently and kept only if it
    // takes; both spellings can be listed and the one that exists wins.
    // Which ones resolved is printed in the summary line, so a run is
    // reproducible from its own output.
    const char *opt_features;
    int cs_arch;
    unsigned cs_mode;
    // Mirrors IsaProperties::include_implicit_regs in
    // contrib/plugins/champsim_tracer/champsim_tracer_mnemonics.h.  The
    // plugin folds Capstone's implicit regs_read[]/regs_write[] into the
    // dependency sets only when this is set, so the comparison must model it
    // or the report describes a register set nothing consumes.
    bool include_implicit_regs;
};

static IsaCfg cfg;
static Isa isa;

/*
 * Capstone modes below are the fallback sets `cap_mode_aarch64()`,
 * `cap_mode_riscv()` and `cap_mode_mips()` select when no guest ELF is
 * available (champsim_tracer_mnemonics_<isa>.h).  Those functions cannot be
 * called from here — they resolve the extension set from the *guest binary*
 * via qemu_plugin_path_to_binary(), a plugin-runtime API — so the fallback is
 * restated.  WHEN cap_mode_*() CHANGES, CHANGE THIS TOO: a mode mismatch is
 * the single largest source of false positives in this tool, and it is silent.
 * The LLVM feature strings are chosen to describe the same ISA subset.
 *
 * THIS TABLE IS THE GATE'S SUBTARGET.  It used to be corrected by flags the
 * one calling harness passed on the command line, which left the tool itself
 * wrong: run bare (or from any other harness) it reported hundreds of
 * disagreements that were only "LLVM was not told about this extension", and
 * anything genuinely wrong inside a mis-modelled register file was invisible
 * underneath them.  The mipsel row is the worked example: a default MIPS
 * subtarget is FR=0, whose 64-bit FP values live in the AFGR64 pair file
 * (D0..D15), while Capstone, QEMU and every binary the tracer runs use FGR64
 * (f0..f31) -- so the whole MIPS FP-double space compared a register file
 * against a different register file.  Anything a caller needs to override to
 * make this tool correct belongs HERE, not in the caller.
 */
static const IsaCfg kIsaTable[] = {
    /* Capstone's AArch64 decoder gates nothing on features, so the matching
     * LLVM subtarget is the whole architecture, not a version snapshot.
     * There is nothing wider to select, so AArch64 is the one ISA whose
     * residual subtarget gap cannot be closed by a feature: what is left is
     * Capstone accepting encodings the architecture reserves, and it is
     * enumerated one signature at a time in the allowlist. */
    {"aarch64", "aarch64-unknown-linux-gnu", "generic", "+all", "",
     CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN, true},
    /*
     * RISC-V is where the subtarget-gap measurement pays for itself.
     * Capstone's RISC-V decoder does not gate on extension features at all
     * — it decodes every extension it was built with — so any extension
     * absent from this list is a hole the register/memory/branch
     * comparisons never look through.  The list is therefore "everything
     * Capstone decodes that LLVM can be told about", not "the extensions a
     * compiler emits", and it is complete: riscv64 reports
     * subtarget_gap=0/0.
     *
     * Two of the entries show why the gap has to be measured rather than
     * assumed.  `+zihintntl` is not a rejection case at all: without it
     * LLVM decodes `c.ntl.*` as `c.add`, inventing a register read the hint
     * does not perform, so a missing feature can be a WRONG decode that
     * looks exactly like a tracer defect.  And closing the last of the gap
     * is what made the Zacas `amocas.*` dropped destination visible — a
     * real defect that had been sitting inside "LLVM rejects this".
     */
    {"riscv64", "riscv64-unknown-linux-gnu", "generic-rv64",
     "+64bit,+i,+m,+a,+f,+d,+c,+v,+zicsr,+zifencei,+zba,+zbb,+zbc,"
     "+zbkb,+zbkc,+zbkx,+zbs,+zfh,+zfhmin,+zvl64b,+zve64d,+zvfh,"
     "+zcb,+zicond,+zihintntl,+zfa,+zknd,+zkne,+zknh,+zksed,+zksh,"
     "+zvbb,+zvbc,+zvkb,+zvkg,+zvkned,+zvknhb,+zvksed,+zvksh,"
     "+zicbom,+zicboz,+zicbop,+zawrs,+h,+svinval,+xventanacondops,"
     "+xcvalu,+xcvbitmanip,+xcvmac,+xcvsimd,+xcvmem,+xcvelw,+xcvbi",
     /* Ratified after LLVM 18, where they carry the `experimental-`
      * prefix; both spellings are offered so the gate keeps its coverage
      * across the bump instead of quietly regrowing a gap. */
     "experimental-zacas,zacas,experimental-zimop,zimop,"
     "experimental-zfbfmin,zfbfmin,experimental-zvfbfwma,zvfbfwma",
     CS_ARCH_RISCV,
     CS_MODE_RISCV64 | CS_MODE_RISCV_C | CS_MODE_RISCV_FD | CS_MODE_RISCV_A |
         CS_MODE_RISCV_V | CS_MODE_RISCV_ZBA | CS_MODE_RISCV_ZBB |
         CS_MODE_RISCV_ZBC | CS_MODE_RISCV_ZBKB | CS_MODE_RISCV_ZBKC |
         CS_MODE_RISCV_ZBKX | CS_MODE_RISCV_ZBS,
     true},
    /* `+fp64` is load-bearing, not decoration: without it LLVM selects the
     * FR=0 AFGR64 register file and names every 64-bit FP operand D0..D15
     * where Capstone and QEMU name f0..f31.  Every binary the tracer traces
     * is FPXX or better, so the tracer's 64-bit-FPR model is the correct
     * one.  The remaining features are the ASEs Capstone's MIPS32R2 mode
     * decodes; omitting one turns "LLVM was not told about this extension"
     * into a decode disagreement.  `+mips3d` closes the last four
     * (addr.ps / mulr.ps / cvt.ps.pw / cvt.pw.ps), taking mipsel to
     * subtarget_gap=0/0. */
    {"mipsel", "mipsel-unknown-linux-gnu", "mips32r2",
     "+mips32r2,+msa,+dsp,+dspr2,+dspr3,+fp64,+eva,+virt,+ginv,+crc,"
     "+abs2008,+nan2008,+mt,+mips3d",
     "", CS_ARCH_MIPS, CS_MODE_MIPS32R2 | CS_MODE_LITTLE_ENDIAN, true},
    {"x86_64", "x86_64-unknown-linux-gnu", "x86-64", "", "",
     CS_ARCH_X86, CS_MODE_64, true},
};

// ---------------------------------------------------------------------------
// Boundary (Capstone + disas/capstone.c) side
// ---------------------------------------------------------------------------

struct CsView {
    bool ok = false;
    unsigned size = 0;
    std::string mnem, ops;
    bool has_mem = false;
    bool mem_read = false;    // some MEM operand carries READ
    bool mem_write = false;   // some MEM operand carries WRITE
    bool mem_unknown = false; // some MEM operand has access == 0
    bool reg_unknown = false; // some REG operand has access == 0
    bool has_invalid_op = false; // an operand the boundary could not model
    unsigned n_ops = 0;
    std::set<std::string> rd, wr; // normalised architectural register names
    // The same two sets in the dependency model's own vocabulary
    // (GenericRegId), so the fields layer can be diffed against the
    // boundary without a second, hand-written correspondence table.
    std::set<unsigned> grd, gwr;
    bool g_jump = false, g_call = false, g_ret = false, g_branch_rel = false;
};

// ---------------------------------------------------------------------------
// Register-name normalisation.  Both decoders name the same architectural
// register differently; fold both onto one canonical token so set difference
// is meaningful.  Width is deliberately dropped (the tracer models the
// architectural register, not the access width) but the register *class* is
// kept so an integer/vector confusion still shows up.
// ---------------------------------------------------------------------------

static std::string lower(std::string s) {
    for (auto &c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

static bool all_digits(const char *p) {
    if (!*p) return false;
    for (; *p; p++) if (!std::isdigit((unsigned char)*p)) return false;
    return true;
}

static std::string norm_aarch64(std::string r) {
    r = lower(r);
    if (r.empty()) return r;
    if (r[0] == '$') r.erase(0, 1);
    if (r == "fp") return "r29";
    if (r == "lr" || r == "x30" || r == "w30") return "r30";
    if (r == "sp" || r == "wsp") return "sp";
    if (r == "xzr" || r == "wzr") return "zr";
    if (r == "nzcv" || r == "cpsr" || r == "pstate") return "nzcv";
    if ((r[0] == 'w' || r[0] == 'x') && all_digits(r.c_str() + 1))
        return "r" + r.substr(1);
    if ((r[0] == 'b' || r[0] == 'h' || r[0] == 's' || r[0] == 'd' ||
         r[0] == 'q' || r[0] == 'v') && all_digits(r.c_str() + 1))
        return "v" + r.substr(1);
    // SVE Z<n> and the SIMD&FP V<n>/Q<n>/D<n>/S<n>/H<n>/B<n> views name the
    // SAME architectural register (V<n> is the low 128 bits of Z<n>), and the
    // tracer maps both onto REG_VEC<n>.  The two decoders pick different
    // views for the same operand -- Capstone prints the reduction
    // `andv b2, p0, z1.b` destination as b2, LLVM as z2 -- so folding them
    // together is required for the set difference to mean anything.
    if (r[0] == 'z' && all_digits(r.c_str() + 1)) return "v" + r.substr(1);
    if (r[0] == 'p' && all_digits(r.c_str() + 1)) return "p" + r.substr(1);
    // PN<n> is the predicate-as-counter VIEW of predicate register P<n>
    // (SVE2.1 / SME2), not a separate register file.
    if (r.size() > 2 && r[0] == 'p' && r[1] == 'n' &&
        all_digits(r.c_str() + 2))
        return "p" + r.substr(2);
    if (r.compare(0, 2, "za") == 0) {
        std::string d;
        for (char ch : r) if (std::isdigit((unsigned char)ch)) d += ch;
        if (!d.empty()) return "za" + d;
    }
    size_t us = r.find('_');
    if (us != std::string::npos) return norm_aarch64(r.substr(0, us));
    return r;
}

static const char *rv_abi[32] = {
    "zero","ra","sp","gp","tp","t0","t1","t2","s0","s1","a0","a1","a2","a3",
    "a4","a5","a6","a7","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11",
    "t3","t4","t5","t6"};
static const char *rv_fabi[32] = {
    "ft0","ft1","ft2","ft3","ft4","ft5","ft6","ft7","fs0","fs1","fa0","fa1",
    "fa2","fa3","fa4","fa5","fa6","fa7","fs2","fs3","fs4","fs5","fs6","fs7",
    "fs8","fs9","fs10","fs11","ft8","ft9","ft10","ft11"};

static std::string norm_riscv(std::string r) {
    r = lower(r);
    if (r.empty()) return r;
    if (r[0] == '$') r.erase(0, 1);
    if (r[0] == 'x' && all_digits(r.c_str() + 1)) {
        int n = atoi(r.c_str() + 1);
        if (n >= 0 && n < 32) return std::string("r") + std::to_string(n);
    }
    if (r[0] == 'f' && r.size() > 1 && std::isdigit((unsigned char)r[1])) {
        int n = atoi(r.c_str() + 1);
        if (n >= 0 && n < 32) return std::string("f") + std::to_string(n);
    }
    if (r[0] == 'v' && all_digits(r.c_str() + 1)) return r;
    // LLVM names an LMUL>1 vector register GROUP with a single tuple name
    // (V0M2 / V0M4 / V0M8) where Capstone names the base register.  The
    // tracer models the base register, so fold the tuple onto it.
    if (r[0] == 'v' && r.size() > 2) {
        size_t m = r.find('m', 1);
        if (m != std::string::npos && m + 1 < r.size()) {
            std::string base = r.substr(1, m - 1);
            if (!base.empty() && all_digits(base.c_str()) &&
                all_digits(r.c_str() + m + 1))
                return "v" + base;
        }
    }
    if (r == "s0" || r == "fp") return "r8";
    for (int i = 0; i < 32; i++) if (r == rv_abi[i]) return std::string("r") + std::to_string(i);
    for (int i = 0; i < 32; i++) if (r == rv_fabi[i]) return std::string("f") + std::to_string(i);
    return r;
}

/*
 * MIPS names its coprocessor registers as bare numbers on the Capstone side
 * ("3" for COP0 register 3, "31" for FCR31) while LLVM names them "COP03" /
 * "FCR31".  Folding a bare number onto the GPR namespace — which an earlier
 * prototype of this tool did — manufactures a whole family of phantom
 * "coprocessor write attributed to a GPR" findings that do not exist: the
 * Capstone *register id* the boundary hands the plugin is MIPS_REG_COP03, and
 * the plugin maps it to REG_SYS correctly.  A bare number is therefore folded
 * onto the coprocessor namespace, which is what it is.  GPR operands always
 * arrive under an ABI name.
 */
static std::string norm_mips(std::string r) {
    r = lower(r);
    if (r.empty()) return r;
    if (r[0] == '$') r.erase(0, 1);
    if (all_digits(r.c_str())) return "cop" + r;
    static const char *abi[32] = {
        "zero","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4",
        "t5","t6","t7","s0","s1","s2","s3","s4","s5","s6","s7","t8","t9",
        "k0","k1","gp","sp","fp","ra"};
    for (int i = 0; i < 32; i++) if (r == abi[i]) return std::string("r") + std::to_string(i);
    if (r == "s8") return "r30";
    if (r.compare(0, 3, "cop") == 0) {
        // LLVM "COP03" / "COP21" -> cop<number>, dropping the LEADING
        // coprocessor index; the tracer folds every coprocessor register
        // onto REG_SYS, so distinguishing COP0 from COP2 here would report
        // a difference the dependency model cannot express.
        //
        // Take the index off the FRONT, not the number off the back.
        // Keeping only the last digit read "COP031" -- COP0 register 31 --
        // as `cop1`, so every COP0 register above 9 compared against the
        // wrong one.  It stayed invisible because the sweep filled Rd from
        // a list that never reached 31, which is the same blind spot the
        // fill sets above exist to close; adding (31, 0) to the MIPS fills
        // is what surfaced it.
        std::string d;
        for (char ch : r) if (std::isdigit((unsigned char)ch)) d += ch;
        if (d.empty()) return "cop0";
        return "cop" + (d.size() > 1 ? d.substr(1) : d);
    }
    if (r.compare(0, 3, "fcr") == 0 || r == "fcsr") return "fcsr";
    // DSPOutFlag<n> / DSPOutFlag<a>_<b> / DSPCCond / DSPCarry are bit fields
    // of the one DSPControl register; both decoders slice it differently and
    // the tracer folds every slice onto REG_FLAGS.
    if (r.compare(0, 3, "dsp") == 0) return "dsp";
    if (r.compare(0, 3, "fcc") == 0) {
        std::string d;
        for (char ch : r) if (std::isdigit((unsigned char)ch)) d += ch;
        return "fcc" + (d.empty() ? std::string("0") : d);
    }
    if (r[0] == 'f' && all_digits(r.c_str() + 1)) return r;
    if (r.size() > 3 && r[0] == 'd' && r.compare(r.size() - 3, 3, "_64") == 0 &&
        all_digits(r.substr(1, r.size() - 4).c_str()))
        return "f" + r.substr(1, r.size() - 4);
    // HI<n> and LO<n> are the two halves of accumulator <n>; the tracer maps
    // both onto the single REG_ACC<n> slot (champsim_tracer_mnemonics.h
    // documents the fold), so distinguishing them here would report a
    // difference the dependency model cannot express.
    if (r.compare(0, 2, "hi") == 0 || r.compare(0, 2, "lo") == 0 ||
        r.compare(0, 2, "ac") == 0) {
        std::string d;
        for (char ch : r) if (std::isdigit((unsigned char)ch)) d += ch;
        return "ac" + (d.empty() ? std::string("0") : d);
    }
    return r;
}

static std::string norm_x86(std::string r) {
    r = lower(r);
    if (r.empty()) return r;
    static const char *g64[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                                  "r8","r9","r10","r11","r12","r13","r14","r15"};
    static const char *g32[16] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi",
                                  "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
    static const char *g16[16] = {"ax","cx","dx","bx","sp","bp","si","di",
                                  "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
    static const char *g8[16]  = {"al","cl","dl","bl","spl","bpl","sil","dil",
                                  "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
    static const char *g8h[4]  = {"ah","ch","dh","bh"};
    for (int i = 0; i < 16; i++) {
        if (r == g64[i] || r == g32[i] || r == g16[i] || r == g8[i])
            return std::string("r") + std::to_string(i);
    }
    for (int i = 0; i < 4; i++) if (r == g8h[i]) return std::string("r") + std::to_string(i);
    if (r.size() > 3 && r.compare(0, 3, "xmm") == 0) return "v" + r.substr(3);
    if (r.size() > 3 && r.compare(0, 3, "ymm") == 0) return "v" + r.substr(3);
    if (r.size() > 3 && r.compare(0, 3, "zmm") == 0) return "v" + r.substr(3);
    if (r == "eflags" || r == "flags" || r == "rflags") return "flags";
    // Any segment register is an address input via its base; which one it is
    // does not change the dependency, and the plugin folds them all onto the
    // same REG_SEG bank.  Capstone surfaces the override only as the MEM
    // operand's segment_id (see cs_decode), never in a reg list, so both
    // sides are folded onto one token.
    if (r == "fs" || r == "gs" || r == "cs" || r == "ds" || r == "es" ||
        r == "ss")
        return "seg";
    return r;
}

static bool drop_zero = true;

/*
 * Registers folded out of BOTH sides before the set difference.  Each entry
 * is a place where the two decoders describe the same architecture with
 * different modelling conventions, so a difference there is not evidence of
 * a defect and would otherwise swamp the report:
 *
 *   - the architectural zero register: reads always yield 0 and writes are
 *     discarded, so it is a dataflow no-op.  LLVM names it in def/use lists,
 *     Capstone usually does not.
 *   - the program counter: the tracer carries control flow through the
 *     BRANCH_* taxonomy and the entry stream, never through a REG_IP
 *     dependency edge, and LLVM's MCInstrDesc does not model PC at all.
 *   - x86 MXCSR: LLVM gives every SSE/AVX instruction an implicit MXCSR use
 *     (rounding mode + exception mask); Capstone models none, and the
 *     tracer's x86 register classifier has no MXCSR slot to put it in.
 *   - x86 SSP (shadow stack pointer): an LLVM-side modelling artifact on
 *     call/ret, not an architectural GPR read a consumer can schedule on.
 */
static bool is_dropped_reg(const std::string &c)
{
    if (c == "pc" || c == "rip" || c == "eip" || c == "ip") return true;
    if (isa == ISA_X86_64 && (c == "mxcsr" || c == "ssp")) return true;
    if (!drop_zero) return false;
    switch (isa) {
    case ISA_AARCH64: return c == "zr";
    case ISA_RISCV64: return c == "r0";
    case ISA_MIPSEL:  return c == "r0";
    default:          return false;
    }
}

static std::string norm_reg(const std::string &r) {
    switch (isa) {
    case ISA_AARCH64: return norm_aarch64(r);
    case ISA_RISCV64: return norm_riscv(r);
    case ISA_MIPSEL:  return norm_mips(r);
    default:          return norm_x86(r);
    }
}

// ---------------------------------------------------------------------------
// Register NAME -> GenericRegId, derived from the tracer's own table
// ---------------------------------------------------------------------------

/*
 * The fields layer compares in GenericRegId space, which means LLVM's
 * register names have to reach it.  Rather than write a second
 * correspondence by hand -- a table that would drift the moment the
 * tracer's register classification changed, and drift silently -- the
 * index is built FROM the tracer's table: for every Capstone register id
 * the table classifies, ask Capstone for the name, run it through the same
 * normaliser both decoders' names go through, and record what the tracer
 * maps it to.  LLVM's "X30", Capstone's "lr" and Capstone's "x30" all
 * normalise to `r30` and land on the one entry the tracer wrote.
 *
 * A token two different generic ids both claim is recorded as ambiguous
 * and dropped rather than guessed at; the count is reported, because a
 * nonzero one would mean the normaliser is folding two register files
 * together and every finding downstream of it would be suspect.
 */
static std::map<std::string, std::set<unsigned>> name_to_generic;

/*
 * A token that lands on more than one GenericRegId is not a defect in this
 * index; it is the tracer's own classification splitting what the
 * normaliser considers one architectural register across two generic ids.
 * AArch64 is the live example: Capstone's `lr` maps to REG_LR while its
 * `w30` -- the 32-bit view of the SAME register -- maps to REG_GPR30, and
 * `fp` / `w29` split the same way.  The index keeps every candidate rather
 * than guessing, matching succeeds on any of them, and the count is
 * reported so the split itself stays visible.
 */
static unsigned regmap_ambiguous_tokens;

static const std::set<unsigned> *generic_candidates(const std::string &tok)
{
    auto it = name_to_generic.find(tok);
    return it == name_to_generic.end() ? nullptr : &it->second;
}

static void build_name_to_generic(void)
{
    csh h;
    if (cs_open((cs_arch)cfg.cs_arch, (cs_mode)cfg.cs_mode, &h) != CS_ERR_OK)
        return;
    for (unsigned i = 1; i < isax_reg_table_size(); i++) {
        unsigned g = isax_generic_reg(i);
        if (!g) continue;
        const char *nm = cs_reg_name(h, i);
        if (!nm || !nm[0]) continue;
        std::string tok = norm_reg(nm);
        if (tok.empty()) continue;
        name_to_generic[tok].insert(g);
    }
    cs_close(&h);
    for (const auto &kv : name_to_generic)
        if (kv.second.size() > 1) regmap_ambiguous_tokens++;
}

/* Render a GenericRegId set into a signature-friendly list, with the
 * bank index collapsed the way liststr() collapses register numbers. */
static std::string genliststr(const std::vector<unsigned> &v)
{
    std::set<std::string> cls;
    for (unsigned g : v) {
        std::string k = isax_generic_reg_name(g);
        std::string t;
        for (char ch : k) {
            if (std::isdigit((unsigned char)ch)) {
                if (t.empty() || t.back() != '#') t += '#';
            } else {
                t += ch;
            }
        }
        cls.insert(t);
    }
    std::string r;
    for (auto &e : cls) { if (!r.empty()) r += ","; r += e; }
    return r.empty() ? "-" : r;
}

static std::string gensetstr(const std::set<unsigned> &s)
{
    std::string r;
    for (unsigned g : s) {
        if (!r.empty()) r += ",";
        r += isax_generic_reg_name(g);
    }
    return r.empty() ? "-" : r;
}

/*
 * Build the view the plugin's operand walker would build from the boundary's
 * output.  Deliberately mirrors decode_detail_to_generic() in
 * champsim_tracer_decode.cc: REG operands contribute by access flag, MEM
 * base/index/segment registers are address inputs and contribute to the read
 * set, and implicit registers fold in only under include_implicit_regs.
 */
static void cs_decode(const uint8_t *b, size_t n, CsView &v,
                      qemu_plugin_insn_info *keep = nullptr)
{
    qemu_plugin_insn_info info;
    if (!cap_disas_raw_detail(cfg.cs_arch, cfg.cs_mode, b, n, 0x100000, &info))
        return;
    /* The fields layer re-runs the plugin's own decode over this same
     * struct, so the caller can ask to keep it rather than have the two
     * layers disassemble the bytes twice and risk describing different
     * instructions. */
    if (keep) *keep = info;
    v.ok = true;
    v.size = info.insn_size;
    v.mnem = info.mnemonic;
    v.ops = info.op_str;
    v.n_ops = info.n_operands;
    v.g_jump = (info.groups & QEMU_PLUGIN_GRP_JUMP) != 0;
    v.g_call = (info.groups & QEMU_PLUGIN_GRP_CALL) != 0;
    v.g_ret = (info.groups & QEMU_PLUGIN_GRP_RET) != 0;
    v.g_branch_rel = (info.groups & QEMU_PLUGIN_GRP_BRANCH_REL) != 0;

    for (unsigned k = 0; k < info.n_operands; k++) {
        const qemu_plugin_operand *op = &info.operands[k];
        switch (op->type) {
        case QEMU_PLUGIN_OP_MEM: {
            v.has_mem = true;
            if (op->access == 0) v.mem_unknown = true;
            if (op->access & QEMU_PLUGIN_OP_ACC_READ) v.mem_read = true;
            if (op->access & QEMU_PLUGIN_OP_ACC_WRITE) v.mem_write = true;
            if (op->reg_name[0]) {
                v.rd.insert(norm_reg(op->reg_name));
                v.grd.insert(isax_generic_reg(op->reg_id));
            }
            if (op->index_name[0]) {
                v.rd.insert(norm_reg(op->index_name));
                v.grd.insert(isax_generic_reg(op->index_id));
            }
            // An x86 segment override is a genuine address input the plugin
            // folds into the memop's source set; Capstone exposes it only
            // here, with no name field, so it is recorded by class.
            if (op->segment_id) {
                v.rd.insert("seg");
                v.grd.insert(isax_generic_reg(op->segment_id));
            }
            break;
        }
        case QEMU_PLUGIN_OP_REG: {
            if (op->access == 0) v.reg_unknown = true;
            if (!op->reg_name[0]) break;
            std::string nm = norm_reg(op->reg_name);
            unsigned g = isax_generic_reg(op->reg_id);
            if (op->access & QEMU_PLUGIN_OP_ACC_READ) {
                v.rd.insert(nm); v.grd.insert(g);
            }
            if (op->access & QEMU_PLUGIN_OP_ACC_WRITE) {
                v.wr.insert(nm); v.gwr.insert(g);
            }
            break;
        }
        case QEMU_PLUGIN_OP_SYSREG: {
            // A system / control register named outside the ISA's register
            // file: an AArch64 MRS/MSR operand, a RISC-V Zicsr CSR.  reg_id
            // is the raw architectural encoding, in a numbering space
            // disjoint from the Capstone register enum, so the generic id
            // comes from the per-ISA system-register mapper rather than
            // from the register table.  Dropping it here would leave the
            // comparison blind to exactly the operand class it exists to
            // catch: an instruction whose whole purpose is to move a
            // control register, appearing to move nothing.
            unsigned g = isax_generic_sysreg(op->reg_id);
            std::string nm = op->reg_name[0] ? norm_reg(op->reg_name)
                                             : std::string();
            if (op->access & QEMU_PLUGIN_OP_ACC_READ) {
                if (!nm.empty()) v.rd.insert(nm);
                v.grd.insert(g);
            }
            if (op->access & QEMU_PLUGIN_OP_ACC_WRITE) {
                if (!nm.empty()) v.wr.insert(nm);
                v.gwr.insert(g);
            }
            break;
        }
        case QEMU_PLUGIN_OP_INVALID:
            // An operand Capstone reported that the boundary has no
            // representation for.  Every register it names is silently lost
            // from the dependency model, so it is worth a class of its own.
            v.has_invalid_op = true;
            break;
        default:
            break;
        }
    }

    if (cfg.include_implicit_regs) {
        /* The implicit lists carry the Capstone register id alongside the
         * name, and the id is what the plugin classifies (add_src_cap_reg /
         * add_dst_cap_reg).  Using it here rather than re-deriving from the
         * name keeps the boundary's generic view identical to the one the
         * dependency model starts from, so any difference between the two
         * is a repair rather than a difference in how they were read. */
        for (unsigned k = 0; k < info.n_regs_read; k++)
            if (info.regs_read[k][0]) {
                v.rd.insert(norm_reg(info.regs_read[k]));
                v.grd.insert(isax_generic_reg(info.regs_read_id[k]));
            }
        for (unsigned k = 0; k < info.n_regs_write; k++)
            if (info.regs_write[k][0]) {
                v.wr.insert(norm_reg(info.regs_write[k]));
                v.gwr.insert(isax_generic_reg(info.regs_write_id[k]));
            }
    }
    v.grd.erase(0);
    v.gwr.erase(0);
}

// ---------------------------------------------------------------------------
// LLVM side
// ---------------------------------------------------------------------------

struct LlView {
    bool ok = false;
    unsigned size = 0;
    std::string text;
    unsigned opcode = 0;
    bool may_load = false, may_store = false;
    bool is_branch = false, is_call = false, is_ret = false,
         is_indirect = false, is_term = false;
    std::set<std::string> rd, wr;
};

static const llvm::Target *LT;
static std::string resolved_features;
static std::vector<std::string> opt_taken, opt_skipped;
static std::unique_ptr<llvm::MCSubtargetInfo> LSTI;
static std::unique_ptr<llvm::MCRegisterInfo> LMRI;
static std::unique_ptr<llvm::MCAsmInfo> LMAI;
static std::unique_ptr<llvm::MCContext> LCTX;
static std::unique_ptr<llvm::MCDisassembler> LDIS;
static std::unique_ptr<llvm::MCInstrInfo> LMII;
static std::unique_ptr<llvm::MCInstPrinter> LIP;
static std::unique_ptr<llvm::MCInstrAnalysis> LMIA;

static std::string join(const std::vector<std::string> &v)
{
    std::string r;
    for (const std::string &e : v) { if (!r.empty()) r += ","; r += e; }
    return r.empty() ? "-" : r;
}

static void llvm_init()
{
    LLVMInitializeAArch64TargetInfo(); LLVMInitializeAArch64TargetMC();
    LLVMInitializeAArch64Disassembler();
    LLVMInitializeRISCVTargetInfo();   LLVMInitializeRISCVTargetMC();
    LLVMInitializeRISCVDisassembler();
    LLVMInitializeMipsTargetInfo();    LLVMInitializeMipsTargetMC();
    LLVMInitializeMipsDisassembler();
    LLVMInitializeX86TargetInfo();     LLVMInitializeX86TargetMC();
    LLVMInitializeX86Disassembler();
    std::string err;
    LT = llvm::TargetRegistry::lookupTarget(cfg.triple, err);
    if (!LT) { fprintf(stderr, "llvm target %s: %s\n", cfg.triple, err.c_str()); exit(1); }
    llvm::Triple TT(cfg.triple);
    /*
     * Resolve the subtarget BEFORE anything is decoded, and prove it took.
     * LLVM answers an unrecognised feature with a warning on stderr and an
     * otherwise normal subtarget, so a renamed or dropped feature would
     * silently reopen a decode blind spot in the middle of an otherwise
     * green run.  checkFeatures() turns that into a hard failure naming the
     * feature; the optional list is where a version-dependent spelling is
     * allowed to be absent, and what resolved is reported.
     */
    std::unique_ptr<llvm::MCSubtargetInfo> bare(
        LT->createMCSubtargetInfo(cfg.triple, cfg.cpu, ""));
    if (!bare) { fprintf(stderr, "llvm subtarget init failed\n"); exit(1); }
    /* The target's own feature table, which is the only authority on
     * whether a name means anything.  checkFeatures() is NOT: an
     * unrecognised name contributes no bit, so a typo'd requirement passes
     * it trivially. */
    std::set<std::string> known;
    for (const auto &kv : bare->getAllProcessorFeatures()) known.insert(kv.Key);

    std::vector<std::string> missing;
    for (const char *p = cfg.features; p && *p; ) {
        const char *comma = strchr(p, ',');
        std::string f(p, comma ? (size_t)(comma - p) : strlen(p));
        p = comma ? comma + 1 : p + f.size();
        if (!f.empty() && (f[0] == '+' || f[0] == '-')) f.erase(0, 1);
        if (!f.empty() && !known.count(f)) missing.push_back(f);
    }
    if (!missing.empty()) {
        fprintf(stderr,
                "isaxcheck: LLVM %s has no such subtarget feature for %s: %s\n"
                "A feature this LLVM does not know is a decode blind spot, "
                "not a warning: every encoding it would have enabled becomes "
                "an LLVM rejection, and the register/memory/branch "
                "comparisons never run on it.  Either build against an LLVM "
                "that has it, or move it to the optional list in kIsaTable "
                "and re-derive the allowlist.\n",
                LLVM_VERSION_STRING, cfg.name, join(missing).c_str());
        exit(1);
    }

    resolved_features = cfg.features;
    for (const char *p = cfg.opt_features; p && *p; ) {
        const char *comma = strchr(p, ',');
        std::string f(p, comma ? (size_t)(comma - p) : strlen(p));
        p = comma ? comma + 1 : p + f.size();
        if (f.empty()) continue;
        if (known.count(f)) {
            resolved_features += ",+" + f;
            opt_taken.push_back(f);
        } else {
            opt_skipped.push_back(f);
        }
    }
    LSTI.reset(LT->createMCSubtargetInfo(cfg.triple, cfg.cpu,
                                         resolved_features));
    LMRI.reset(LT->createMCRegInfo(cfg.triple));
    llvm::MCTargetOptions opt;
    LMAI.reset(LT->createMCAsmInfo(*LMRI, cfg.triple, opt));
    LCTX.reset(new llvm::MCContext(TT, LMAI.get(), LMRI.get(), LSTI.get()));
    LDIS.reset(LT->createMCDisassembler(*LSTI, *LCTX));
    LMII.reset(LT->createMCInstrInfo());
    LIP.reset(LT->createMCInstPrinter(TT, LMAI->getAssemblerDialect(), *LMAI,
                                      *LMII, *LMRI));
    LMIA.reset(LT->createMCInstrAnalysis(LMII.get()));
    if (!LDIS || !LMII) { fprintf(stderr, "llvm mc init failed\n"); exit(1); }
}

static void ll_decode(const uint8_t *b, size_t n, LlView &v)
{
    llvm::MCInst I;
    uint64_t sz = 0;
    llvm::ArrayRef<uint8_t> bytes(b, n);
    auto st = LDIS->getInstruction(I, sz, bytes, 0x100000, llvm::nulls());
    if (st != llvm::MCDisassembler::Success) return;
    v.ok = true;
    v.size = (unsigned)sz;
    v.opcode = I.getOpcode();
    const llvm::MCInstrDesc &D = LMII->get(I.getOpcode());
    v.may_load = D.mayLoad();
    v.may_store = D.mayStore();
    v.is_branch = LMIA ? LMIA->isBranch(I) : D.isBranch();
    v.is_call = LMIA ? LMIA->isCall(I) : D.isCall();
    v.is_ret = LMIA ? LMIA->isReturn(I) : D.isReturn();
    v.is_indirect = LMIA ? LMIA->isIndirectBranch(I) : D.isIndirectBranch();
    v.is_term = D.isTerminator();

    std::string s;
    llvm::raw_string_ostream os(s);
    LIP->printInst(&I, 0x100000, "", *LSTI, os);
    os.flush();
    std::string t;
    bool sp = false;
    for (char c : s) {
        if (c == '\t' || c == ' ') { if (!t.empty()) sp = true; continue; }
        if (sp) { t += ' '; sp = false; }
        t += c;
    }
    v.text = t;

    unsigned ndefs = D.getNumDefs();
    for (unsigned i = 0; i < I.getNumOperands(); i++) {
        const llvm::MCOperand &O = I.getOperand(i);
        if (!O.isReg() || O.getReg() == 0) continue;
        // LLVM names register *tuples* (AArch64 Q2_Q3_Q4_Q5 lists, MIPS
        // D0_64) with a single super-register where Capstone names each
        // member.  Underscores are LLVM's tuple-naming convention, so expand
        // only those — expanding ordinary registers would drag in unrelated
        // sub-register views (Z0 -> Q0/D0/S0...) and manufacture noise.
        const char *nm = LMRI->getName(O.getReg());
        if (!nm) continue;
        std::vector<std::string> names;
        if (strchr(nm, '_')) {
            for (llvm::MCPhysReg sub : LMRI->subregs(O.getReg())) {
                const char *sn = LMRI->getName(sub);
                if (sn && !strchr(sn, '_')) names.push_back(norm_reg(sn));
            }
        }
        if (names.empty()) names.push_back(norm_reg(nm));
        for (const std::string &cn : names) {
            if (i < ndefs) {
                v.wr.insert(cn);
                if (i < D.getNumOperands() &&
                    D.getOperandConstraint(i, llvm::MCOI::TIED_TO) != -1)
                    v.rd.insert(cn);
            } else {
                v.rd.insert(cn);
                int tied = (i < D.getNumOperands())
                               ? D.getOperandConstraint(i, llvm::MCOI::TIED_TO) : -1;
                if (tied != -1) v.wr.insert(cn);
            }
        }
    }
    // LLVM's call instructions carry an ABI-modelling implicit use of SP that
    // is not an architectural read; Capstone (correctly) omits it.
    if (v.is_call) v.rd.erase(isa == ISA_AARCH64 ? "sp" : "r2");
    for (llvm::MCPhysReg r : D.implicit_defs()) {
        const char *nm = LMRI->getName(r); if (nm) v.wr.insert(norm_reg(nm));
    }
    for (llvm::MCPhysReg r : D.implicit_uses()) {
        const char *nm = LMRI->getName(r); if (nm) v.rd.insert(norm_reg(nm));
    }
}

// ---------------------------------------------------------------------------
// Disagreement bucketing
// ---------------------------------------------------------------------------

struct Bucket { std::string sample; unsigned long n = 0; };
static std::map<std::string, Bucket> buckets;

// A signature key is CLASS + mnemonic (+ a short qualifier).  It carries no
// counts, so an allowlist entry can name it exactly and stay stable as the
// sweep shape changes.
static void note(const std::string &key, const std::string &sample)
{
    auto &b = buckets[key];
    if (!b.n) b.sample = sample;
    b.n++;
}

static std::string hexbytes(const uint8_t *b, unsigned n)
{
    char t[64]; std::string s;
    for (unsigned i = 0; i < n && i < 16; i++) { snprintf(t, sizeof t, "%02x", b[i]); s += t; }
    return s;
}

/*
 * Render a difference set into a signature key.  Register *numbers* are
 * erased (r3 -> r#) because the sweep visits the same instruction with many
 * register fillings and the defect is never specific to one of them; the
 * register CLASS is kept, because an integer/vector confusion is a defect.
 */
static std::string liststr(const std::vector<std::string> &v)
{
    std::set<std::string> cls;
    for (const std::string &e : v) {
        std::string k;
        for (char ch : e) k += std::isdigit((unsigned char)ch) ? '#' : ch;
        // collapse runs of '#'
        std::string t;
        for (char ch : k) if (ch != '#' || t.empty() || t.back() != '#') t += ch;
        cls.insert(t);
    }
    std::string r;
    for (auto &e : cls) { if (!r.empty()) r += ","; r += e; }
    return r.empty() ? "-" : r;
}

static std::string setstr(const std::set<std::string> &s)
{
    std::string r;
    for (auto &e : s) { if (!r.empty()) r += ","; r += e; }
    return r.empty() ? "-" : r;
}

// Which comparison classes are enabled.
static bool want_decode = true, want_mem = true, want_branch = true,
            want_regs = true, want_zeroacc = true;

/*
 * WHICH LAYER IS ON THE CAPSTONE SIDE.
 *
 *   LAYER_BOUNDARY  cap_disas_raw_detail() -- Capstone plus the
 *                   disas/capstone.c corrections.
 *   LAYER_FIELDS    the InsnFields the dependency model records, i.e. the
 *                   boundary PLUS the plugin's own operand walker, branch
 *                   fixups and dep/lane refiners.  This is what the trace
 *                   is built from, so it is what a consumer sees.
 *   LAYER_FIXUPS    neither: the DIFFERENCE between the two, which is the
 *                   inventory of plugin-side repairs, asserted exactly.
 *
 * The three share every sweep, normaliser and allowlist mechanism; only
 * the Capstone-side view changes.  Signature classes are prefixed so one
 * allowlist file can carry all of them without collision.
 */
enum Layer { LAYER_BOUNDARY, LAYER_FIELDS, LAYER_FIXUPS };
static Layer layer = LAYER_BOUNDARY;

/* BranchType values from champsim_tracer_generic_ids.h.  Restated rather
 * than included: pulling that header in would drag the plugin's include
 * world into the translation unit that owns LLVM's.  The names are
 * resolved symbolically through isax_branch_name(), so a renumbering
 * shows up in every signature key rather than silently. */
enum { BR_NONE = 0, BR_RETURN = 3, BR_DIRECT_CALL = 7, BR_INDIRECT_CALL = 8 };

static void compare(const uint8_t *b, size_t n)
{
    CsView c; LlView l;
    qemu_plugin_insn_info info;
    IsaxFieldsView f;
    cs_decode(b, n, c, &info);
    ll_decode(b, n, l);
    if (c.ok && layer != LAYER_BOUNDARY) isax_fields_decode(&info, &f);

    if (!c.ok && !l.ok) return;

    unsigned bl = c.ok ? c.size : (l.ok ? l.size : (unsigned)n);
    std::string hx = hexbytes(b, bl);
    std::string cd = c.ok ? (c.mnem + " " + c.ops) : std::string("<cs-reject>");
    std::string ld = l.ok ? l.text : std::string("<llvm-reject>");
    std::string sample = hx + "  cs{" + cd + "}  llvm{" + ld + "}";
    std::string m = c.ok ? c.mnem : std::string("?");

    // --- class D: decode agreement -----------------------------------------
    // Not in fixups mode: that mode measures the tracer against itself, so
    // whether LLVM also accepted the bytes says nothing about whether the
    // plugin layer repaired something.
    if (want_decode && layer != LAYER_FIXUPS) {
        if (c.ok && !l.ok) note("D-cs-only " + m, sample);
        else if (!c.ok && l.ok) {
            std::string lm = l.text.substr(0, l.text.find(' '));
            note("D-llvm-only " + lm, sample);
        } else if (c.size != l.size)
            note("D-size-mismatch " + m,
                 sample + "  cs=" + std::to_string(c.size) +
                     " llvm=" + std::to_string(l.size));
    }
    /*
     * FIXUP INVENTORY.  Everything the plugin layer changes about the
     * boundary's register sets, expressed in GenericRegId space so the two
     * are directly comparable, and keyed by mnemonic + the class of what
     * moved.  This does not need LLVM at all -- it is the tracer measured
     * against itself -- so it runs whether or not LLVM accepted the
     * encoding, which matters: a repair on an encoding LLVM rejects is
     * exactly the kind the other layers cannot reach.
     */
    if (layer == LAYER_FIXUPS) {
        if (!c.ok || !f.ok) return;
        std::set<unsigned> fsrc(f.src.begin(), f.src.end());
        std::set<unsigned> fdst(f.dst.begin(), f.dst.end());
        std::set<unsigned> bsrc = c.grd, bdst = c.gwr;
        for (auto *S : {&fsrc, &fdst, &bsrc, &bdst}) {
            for (auto it = S->begin(); it != S->end(); )
                it = isax_generic_reg_dropped(*it) ? S->erase(it)
                                                   : std::next(it);
        }
        const struct {
            const char *name;
            std::set<unsigned> *plugin, *boundary;
        } dirs[] = {
            {"rd", &fsrc, &bsrc},
            {"wr", &fdst, &bdst},
        };
        std::string ctx = sample + "  boundary{RD " + gensetstr(bsrc) +
                          " | WR " + gensetstr(bdst) + "}  fields{RD " +
                          gensetstr(fsrc) + " | WR " + gensetstr(fdst) + "}";
        for (auto &d : dirs) {
            std::vector<unsigned> added, removed;
            std::set_difference(d.plugin->begin(), d.plugin->end(),
                                d.boundary->begin(), d.boundary->end(),
                                std::back_inserter(added));
            std::set_difference(d.boundary->begin(), d.boundary->end(),
                                d.plugin->begin(), d.plugin->end(),
                                std::back_inserter(removed));
            if (!added.empty())
                note(std::string("W-") + d.name + "-added " + m + " +" +
                         genliststr(added), ctx);
            if (!removed.empty())
                note(std::string("W-") + d.name + "-dropped " + m + " -" +
                         genliststr(removed), ctx);
        }
        /* A control transfer the boundary reports and the dependency model
         * does not classify (or the reverse) is the same kind of repair,
         * one layer over: the RISC-V aliased forms are the worked example,
         * where the branch class is what the link-register fixup keys off. */
        bool bflow = c.g_jump || c.g_call || c.g_ret;
        bool fflow = f.branch_type != BR_NONE;
        if (bflow != fflow)
            note(std::string("W-flow-") + (fflow ? "added " : "dropped ") + m +
                     " " + isax_branch_name(f.branch_type), ctx);
        else if (fflow && (c.g_ret != (f.branch_type == BR_RETURN) ||
                           c.g_call != (f.branch_type == BR_DIRECT_CALL ||
                                        f.branch_type == BR_INDIRECT_CALL)))
            note(std::string("W-flow-reclassed ") + m + " " +
                     isax_branch_name(f.branch_type), ctx);
        return;
    }

    if (!c.ok || !l.ok) return;

    /*
     * FIELDS LAYER.  Swap the Capstone side over to what the dependency
     * model records before any of the classes below run.  The register
     * sets move into GenericRegId space and LLVM's names are carried
     * across with them through the tracer's own register table, so the
     * comparison is stated in the vocabulary the trace is written in --
     * `REG_LR`, not `x30` on one side and `r30` on the other.
     */
    std::string fpfx;
    std::set<unsigned> lgrd, lgwr;
    if (layer == LAYER_FIELDS) {
        fpfx = "F";
        if (!f.ok) {
            /* decode_detail_to_generic() bailed at GEN_OP_UNKNOWN: the
             * mnemonic is not in the ISA table, so there is no dependency
             * model output to compare.  The tracer already logs this to
             * its sidecar; here it is a class of its own so the gate does
             * not silently score an empty set against LLVM's. */
            note("FU-unclassified " + m, sample);
            return;
        }
        std::set<unsigned> fsrc0(f.src.begin(), f.src.end());
        std::set<unsigned> fdst0(f.dst.begin(), f.dst.end());
        for (const auto *S : {&l.rd, &l.wr}) {
            bool is_rd = (S == &l.rd);
            std::set<unsigned> *out = is_rd ? &lgrd : &lgwr;
            const std::set<unsigned> &have = is_rd ? fsrc0 : fdst0;
            for (const std::string &tok : *S) {
                if (is_dropped_reg(tok)) continue;
                const std::set<unsigned> *cand = generic_candidates(tok);
                if (!cand || cand->empty()) {
                    /* A register LLVM names that the tracer's own table
                     * does not classify at all.  Dropping it quietly would
                     * be a blind spot of exactly the shape this tool exists
                     * to remove, so it gets a bucket. */
                    note("FN-unmapped-llvm-reg " + m + " " + tok, sample);
                    continue;
                }
                /* Where the token has several candidates -- the tracer
                 * splitting one architectural register across generic ids
                 * -- any of them counts as the register being present.
                 * Picking one arbitrarily would report a difference that
                 * only the choice created. */
                unsigned g = *cand->begin();
                for (unsigned k : *cand) if (have.count(k)) { g = k; break; }
                if (!isax_generic_reg_dropped(g)) out->insert(g);
            }
        }
    }

    // --- class Z: metadata holes the boundary hands the plugin --------------
    // Boundary-only.  An operand the boundary cannot model is missing from
    // the fields too, by construction; reporting it under both layers would
    // double-count one hole.  The fields layer's own version of "nothing to
    // compare" is FU-unclassified, above.
    if (want_zeroacc && layer == LAYER_BOUNDARY) {
        if (c.mem_unknown) note("Z-access0 " + m + " MEM", sample);
        if (c.reg_unknown) note("Z-access0 " + m + " REG", sample);
        if (c.has_invalid_op) note("Z-unmodelled-op " + m, sample);
    }

    // --- class M: memory direction ------------------------------------------
    if (want_mem) {
        // The fields layer's memory presence is the template-static memop
        // count the operand walker declared, which is what the trace
        // reserves slots for -- not the boundary's per-operand access bits.
        bool cl = layer == LAYER_FIELDS ? f.max_dep_loads > 0 : c.mem_read;
        bool cw = layer == LAYER_FIELDS ? f.max_dep_stores > 0 : c.mem_write;
        bool cm = layer == LAYER_FIELDS ? (cl || cw) : c.has_mem;
        bool ll = l.may_load, lw = l.may_store;
        if (cm && !ll && !lw)
            note(fpfx + "M-cs-mem-llvm-none " + m, sample);
        else if (!cm && (ll || lw))
            note(fpfx + "M-llvm-mem-cs-none " + m +
                     (ll ? " load" : "") + (lw ? " store" : ""), sample);
        else if (cm) {
            if (ll && !cl) note(fpfx + "M-miss-load " + m, sample);
            if (lw && !cw) note(fpfx + "M-miss-store " + m, sample);
            if (cl && !ll) note(fpfx + "M-extra-load " + m, sample);
            if (cw && !lw) note(fpfx + "M-extra-store " + m, sample);
        }
    }

    // --- class B: branch taxonomy -------------------------------------------
    if (want_branch) {
        bool cj, ccall, cret;
        if (layer == LAYER_FIELDS) {
            cj = f.branch_type != BR_NONE;
            ccall = f.branch_type == BR_DIRECT_CALL ||
                    f.branch_type == BR_INDIRECT_CALL;
            cret = f.branch_type == BR_RETURN;
        } else {
            cj = c.g_jump || c.g_call || c.g_ret;
            ccall = c.g_call;
            cret = c.g_ret;
        }
        bool lj = l.is_branch || l.is_call || l.is_ret;
        if (cj != lj)
            note(fpfx + "B-flow-presence " + m +
                     (cj ? " cs-yes" : " cs-no") + (lj ? " llvm-yes" : " llvm-no"),
                 sample);
        else if (cj) {
            if (l.is_call != ccall)
                note(fpfx + "B-call-mismatch " + m +
                         (ccall ? " cs-call" : " cs-nocall"), sample);
            if (l.is_ret != cret)
                note(fpfx + "B-ret-mismatch " + m +
                         (cret ? " cs-ret" : " cs-noret"), sample);
        }
    }

    // --- class R: register read/write sets ----------------------------------
    if (want_regs && layer == LAYER_FIELDS) {
        std::set<unsigned> fsrc(f.src.begin(), f.src.end());
        std::set<unsigned> fdst(f.dst.begin(), f.dst.end());
        for (auto *S : {&fsrc, &fdst}) {
            for (auto it = S->begin(); it != S->end(); )
                it = isax_generic_reg_dropped(*it) ? S->erase(it)
                                                   : std::next(it);
        }
        std::string ctx = sample + "  fieldsRD{" + gensetstr(fsrc) +
                          "} fieldsWR{" + gensetstr(fdst) + "} llvmRD{" +
                          gensetstr(lgrd) + "} llvmWR{" + gensetstr(lgwr) + "}";
        std::vector<unsigned> wonly, conly, ronly, cronly;
        std::set_difference(lgwr.begin(), lgwr.end(), fdst.begin(), fdst.end(),
                            std::back_inserter(wonly));
        std::set_difference(fdst.begin(), fdst.end(), lgwr.begin(), lgwr.end(),
                            std::back_inserter(conly));
        std::set_difference(lgrd.begin(), lgrd.end(), fsrc.begin(), fsrc.end(),
                            std::back_inserter(ronly));
        std::set_difference(fsrc.begin(), fsrc.end(), lgrd.begin(), lgrd.end(),
                            std::back_inserter(cronly));
        if (!wonly.empty())
            note("FR-wr-missing " + m + " +" + genliststr(wonly), ctx);
        if (!conly.empty())
            note("FR-wr-phantom " + m + " +" + genliststr(conly), ctx);
        if (!ronly.empty())
            note("FR-rd-missing " + m + " +" + genliststr(ronly), ctx);
        if (!cronly.empty())
            note("FR-rd-phantom " + m + " +" + genliststr(cronly), ctx);
    } else if (want_regs) {
        for (auto *S : {&c.rd, &c.wr, &l.rd, &l.wr}) {
            for (auto it = S->begin(); it != S->end(); )
                it = is_dropped_reg(*it) ? S->erase(it) : std::next(it);
        }
        std::vector<std::string> wonly, conly;
        std::set_difference(l.wr.begin(), l.wr.end(), c.wr.begin(), c.wr.end(),
                            std::back_inserter(wonly));
        std::set_difference(c.wr.begin(), c.wr.end(), l.wr.begin(), l.wr.end(),
                            std::back_inserter(conly));
        if (!wonly.empty())
            note("R-wr-missing " + m + " +" + liststr(wonly),
                 sample + "  csWR{" + setstr(c.wr) + "} llvmWR{" + setstr(l.wr) + "}");
        if (!conly.empty())
            note("R-wr-phantom " + m + " +" + liststr(conly),
                 sample + "  csWR{" + setstr(c.wr) + "} llvmWR{" + setstr(l.wr) + "}");
        std::vector<std::string> ronly, cronly;
        std::set_difference(l.rd.begin(), l.rd.end(), c.rd.begin(), c.rd.end(),
                            std::back_inserter(ronly));
        std::set_difference(c.rd.begin(), c.rd.end(), l.rd.begin(), l.rd.end(),
                            std::back_inserter(cronly));
        if (!ronly.empty())
            note("R-rd-missing " + m + " +" + liststr(ronly),
                 sample + "  csRD{" + setstr(c.rd) + "} llvmRD{" + setstr(l.rd) + "}");
        if (!cronly.empty())
            note("R-rd-phantom " + m + " +" + liststr(cronly),
                 sample + "  csRD{" + setstr(c.rd) + "} llvmRD{" + setstr(l.rd) + "}");
    }
}

// ---------------------------------------------------------------------------
// Sweeps
// ---------------------------------------------------------------------------

static unsigned long total_tried = 0;

static void try_word(uint32_t w)
{
    uint8_t b[8];
    b[0] = w & 0xff; b[1] = (w >> 8) & 0xff; b[2] = (w >> 16) & 0xff; b[3] = w >> 24;
    b[4] = b[5] = b[6] = b[7] = 0;
    total_tried++;
    compare(b, 4);
}

static void try_half(uint16_t h)
{
    uint8_t b[4];
    b[0] = h & 0xff; b[1] = h >> 8; b[2] = 0; b[3] = 0;
    total_tried++;
    compare(b, 2);
}

/*
 * THE FILL SETS ARE PART OF THE COVERAGE, NOT A CONVENIENCE.
 *
 * Each sweep walks the opcode-bearing bits exhaustively and fills the
 * register fields from a short list.  The rule that list has to satisfy:
 * ANY REGISTER VALUE THAT SELECTS A DIFFERENT DECODE MUST BE IN IT.  A
 * register field is usually just data, but where a particular value picks
 * an alias, a different printed form, or a different instruction outright,
 * omitting that value puts the whole form outside the swept space -- and a
 * defect there is not a finding this gate missed, it is a place the gate
 * never looked.
 *
 * That is not hypothetical.  AArch64 `ret` is the alias of `RET X30`, and
 * no Rn but 30 reaches it; the boundary's loss of the link-register read on
 * the most executed control transfer in any AArch64 trace sat outside the
 * sweep through every green run of this gate until (30, 0) was added.  The
 * same shape holds elsewhere and the fills below name it each time:
 * RISC-V's 32-bit `ret` is `jalr x0, x1, 0`, MIPS prints JALR with rd = 31
 * as the two-operand form, and x86's ModRM.reg field is an opcode
 * EXTENSION for the group opcodes, so sweeping two of its eight values
 * leaves six group members per opcode unreached.
 *
 * When adding an ISA, ask what a register value can change about the
 * decode before choosing the fills.
 *
 * aarch64: opcode-bearing bits are [31:10]; [9:5]=Rn, [4:0]=Rd/Rt.
 * (30, 0) reaches the `ret` alias.
 */
static void sweep_aarch64(unsigned shard, unsigned nshard)
{
    static const struct { unsigned rn, rd; } fills[] = {
        {1, 2}, {31, 31}, {0, 31}, {31, 0}, {30, 0},
    };
    for (uint32_t top = shard; top < (1u << 22); top += nshard)
        for (auto &f : fills)
            try_word((top << 10) | (f.rn << 5) | f.rd);
}

// riscv64: sweep [31:20] (funct7 + rs2 / I-imm) x [14:12] funct3 x [6:0] opcode
// = 2^22, with rs1/rd filled a few ways.  Plus every 16-bit compressed word.
//
// (1, 0) is the alias-selecting fill: `jalr x0, x1, 0` is what the
// uncompressed `ret` IS, and rs1 = ra with rd = zero is the only way to
// reach it.  The compressed sweep covers `c.jr ra` for free because it
// enumerates every halfword, which is exactly why the 32-bit form went
// unnoticed -- the alias appeared to be swept when only its short
// encoding was.
static void sweep_riscv(unsigned shard, unsigned nshard)
{
    static const struct { unsigned rs1, rd; } fills[] = {
        {6, 5}, {0, 0}, {2, 1}, {1, 0},
    };
    for (uint32_t i = shard; i < (1u << 22); i += nshard) {
        uint32_t hi12 = (i >> 10) & 0xfff;
        uint32_t f3   = (i >> 7) & 0x7;
        uint32_t opc  = i & 0x7f;
        for (auto &f : fills)
            try_word((hi12 << 20) | (f.rs1 << 15) | (f3 << 12) | (f.rd << 7) | opc);
    }
    if (shard == 0)
        for (uint32_t h = 0; h < (1u << 16); h++) try_half((uint16_t)h);
}

// mipsel: op[31:26], rs[25:21], rt[20:16], rd[15:11], sa[10:6], funct[5:0].
// op/rs/rt/funct all carry opcode meaning somewhere in the ISA; sweep those
// 2^22 with rd/sa filled a few ways.  rs and rt are swept exhaustively, so
// the `jr $ra` / `move` / `b` aliases that key off THEM are reached
// already; rd is not, and rd = 31 is what prints JALR in its two-operand
// form -- hence (31, 0).
static void sweep_mips(unsigned shard, unsigned nshard)
{
    static const struct { unsigned rd, sa; } fills[] = {
        {3, 0}, {0, 0}, {3, 1}, {0, 4}, {31, 0},
    };
    for (uint32_t i = shard; i < (1u << 22); i += nshard) {
        uint32_t op = (i >> 16) & 0x3f;
        uint32_t rs = (i >> 11) & 0x1f;
        uint32_t rt = (i >> 6) & 0x1f;
        uint32_t fn = i & 0x3f;
        for (auto &f : fills)
            try_word((op << 26) | (rs << 21) | (rt << 16) | (f.rd << 11) |
                     (f.sa << 6) | fn);
    }
}

// x86_64: prefix x escape x opcode x ModRM-tail shape x ModRM.reg.
//
// ModRM.reg is swept because on the group opcodes (0x80/0x81/0x83, 0xC0/
// 0xC1/0xD0-0xD3, 0xF6/0xF7, 0xFE/0xFF and most of the 0x0F groups) it is
// not a register at all, it is an OPCODE EXTENSION: `81 /0` is ADD and
// `81 /5` is SUB.  Two fixed tails reached two of its eight values, which
// left six members of every group opcode -- SUB, AND, XOR, CMP, the whole
// shift family, NOT/NEG/MUL/DIV, INC/DEC/CALL/JMP/PUSH -- outside the swept
// space entirely.
static void sweep_x86(unsigned shard, unsigned nshard)
{
    static const struct { unsigned char p[4]; int np; } pre[] = {
        {{0},0}, {{0x66},1}, {{0x48},1}, {{0xf3},1}, {{0xf2},1},
        {{0xf3,0x48},2}, {{0xf2,0x48},2}, {{0x66,0xf3},2}, {{0xf0},1}, {{0x64},1},
    };
    static const unsigned char tail_mem[] = {0x0d,0,0,0,0, 0x11,0x22,0x33,0x44, 0,0,0,0};
    static const unsigned char tail_reg[] = {0xc1, 0x11,0x22,0x33,0x44, 0,0,0,0,0,0,0,0};
    static const unsigned char tail_sib[] = {0x04,0x8d,0,0,0,0, 0x11,0x22,0x33,0x44, 0,0};
    unsigned idx = 0;
    uint8_t buf[24];
    for (unsigned pi = 0; pi < sizeof(pre)/sizeof(pre[0]); pi++)
      for (int esc = 0; esc < 4; esc++)
        for (unsigned op = 0; op < 256; op++)
          for (int t = 0; t < 3; t++)
            for (unsigned reg = 0; reg < 8; reg++) {
              if ((idx++ % nshard) != shard) continue;
              const unsigned char *tail = t==0?tail_mem : t==1?tail_reg : tail_sib;
              size_t n = 0;
              for (int k = 0; k < pre[pi].np; k++) buf[n++] = pre[pi].p[k];
              if (esc >= 1) buf[n++] = 0x0f;
              if (esc == 2) buf[n++] = 0x38;
              if (esc == 3) buf[n++] = 0x3a;
              buf[n++] = (uint8_t)op;
              memcpy(buf + n, tail, 13);
              /* ModRM is the tail's first byte; replace only its reg field. */
              buf[n] = (uint8_t)((buf[n] & ~0x38u) | (reg << 3));
              n += 13;
              total_tried++;
              compare(buf, n);
            }
}

static void run_sweep(unsigned shard, unsigned nshard)
{
    switch (isa) {
    case ISA_AARCH64: sweep_aarch64(shard, nshard); break;
    case ISA_RISCV64: sweep_riscv(shard, nshard); break;
    case ISA_MIPSEL:  sweep_mips(shard, nshard); break;
    case ISA_X86_64:  sweep_x86(shard, nshard); break;
    }
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

/*
 * Allowlist file format, one entry per line:
 *
 *     <isa> <signature key>
 *
 * A line whose first non-blank character is `#` is a comment; blank lines
 * are ignored.  `#` is NOT an inline comment introducer, because it occurs
 * inside signature keys (an elided register number).  `*` in the key is a glob
 * wildcard matching any run of characters, so one entry can name a family by
 * mnemonic stem and register class at once.  Every entry in the shipped
 * allowlist carries a comment naming the defect, the Capstone version it was
 * observed on, and how to verify it can be removed — see
 * isaxcheck_allow.txt.
 */
struct AllowRule { std::string isa, key; unsigned lineno; bool used = false; };
static std::vector<AllowRule> allow_rules;

/*
 * The signature class that means "the boundary decoded this and LLVM did
 * not".  It is the subtarget-gap signal (see the file header): every
 * encoding in it is one the register / memory / branch comparisons never
 * ran on, so it is the gate's own measure of how blind it is.
 */
static const char kGapClass[] = "D-cs-only ";
static bool is_gap_key(const std::string &k)
{
    return k.compare(0, sizeof(kGapClass) - 1, kGapClass) == 0;
}

/* Minimal glob: '*' matches any run of characters, everything else literal. */
static bool glob_match(const char *pat, const char *str)
{
    const char *star = nullptr, *mark = nullptr;
    while (*str) {
        if (*pat == '*') { star = pat++; mark = str; }
        else if (*pat == *str) { pat++; str++; }
        else if (star) { pat = star + 1; str = ++mark; }
        else return false;
    }
    while (*pat == '*') pat++;
    return *pat == '\0';
}

static bool load_allow(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char line[1024];
    unsigned lineno = 0;
    bool bad = false;
    while (fgets(line, sizeof line, f)) {
        lineno++;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        /* Comments are whole-line only: '#' also occurs INSIDE a key, where
         * it stands for an elided register number (`+ac#`), so an inline
         * comment rule would silently truncate half the allowlist. */
        if (*p == '#') continue;
        size_t len = strlen(p);
        while (len && (p[len-1] == '\n' || p[len-1] == '\r' ||
                       p[len-1] == ' ' || p[len-1] == '\t')) p[--len] = '\0';
        if (!len) continue;
        char *sp = strchr(p, ' ');
        if (!sp) continue;
        *sp = '\0';
        std::string i = p, k = sp + 1;
        while (!k.empty() && k[0] == ' ') k.erase(0, 1);
        /*
         * A wildcard is refused in the subtarget-gap class.  `aarch64
         * D-cs-only *` is one line, and it hid every encoding on which
         * this tool's register, memory and branch comparisons do not run
         * at all -- including whole ISA extensions arriving in a Capstone
         * bump.  Naming them one at a time is the whole mechanism: the
         * count of lines IS the size of the blind spot, and a new one has
         * to be justified by hand.
         */
        if (is_gap_key(k) && k.find('*') != std::string::npos) {
            fprintf(stderr,
                    "%s:%u: `%s' wildcards the subtarget-gap class.  Name "
                    "each signature exactly, or widen the LLVM subtarget in "
                    "kIsaTable so the gap closes.\n",
                    path, lineno, k.c_str());
            bad = true;
            continue;
        }
        allow_rules.push_back({i, k, lineno, false});
    }
    fclose(f);
    return !bad;
}

static bool is_allowed(const std::string &key)
{
    bool hit = false;
    for (auto &r : allow_rules) {
        if (r.isa != cfg.name && r.isa != "*") continue;
        if (glob_match(r.key.c_str(), key.c_str())) { r.used = true; hit = true; }
    }
    return hit;
}

// ---------------------------------------------------------------------------

static void usage(void)
{
    fprintf(stderr,
        "usage: isaxcheck --isa={aarch64|riscv64|mipsel|x86_64} [options]\n"
        "  --jobs=N        fork N sweep shards and merge (default 1)\n"
        "  --shard=I --nshard=N   run one shard only (used internally)\n"
        "  --classes=DZMBR        comparison classes to enable\n"
        "  --hex=BYTES     decode one encoding with both decoders and exit\n"
        "  --batch         read hex encodings on stdin; write one TSV row\n"
        "                  per encoding carrying both decoders' views\n"
        "  --layer=boundary|fields   compare LLVM against the decode\n"
        "                  boundary (default) or against the InsnFields the\n"
        "                  dependency model records\n"
        "  --fixups        report the difference BETWEEN the two layers --\n"
        "                  the plugin-side repairs -- and assert it exactly\n"
        "                  against --allow (a listed repair that stops\n"
        "                  happening fails, as does an unlisted one)\n"
        "  --allow=FILE    allowlist of justified residual signatures\n"
        "  --check         exit 1 if any non-allowlisted signature remains\n"
        "  --mattr=... --mcpu=...  override the LLVM subtarget\n"
        "  --keep-zero     do not fold the architectural zero register out\n");
}

int main(int argc, char **argv)
{
    const char *isaname = "aarch64";
    unsigned shard = 0, nshard = 1, jobs = 1;
    const char *classes = "DZMBR";
    const char *hexone = nullptr;
    const char *mattr = nullptr, *mcpu = nullptr, *allow = nullptr;
    bool check = false, emit_raw = false, batch = false;

    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "--isa=", 6)) isaname = argv[i] + 6;
        else if (!strncmp(argv[i], "--shard=", 8)) shard = atoi(argv[i] + 8);
        else if (!strncmp(argv[i], "--nshard=", 9)) nshard = atoi(argv[i] + 9);
        else if (!strncmp(argv[i], "--jobs=", 7)) jobs = atoi(argv[i] + 7);
        else if (!strncmp(argv[i], "--classes=", 10)) classes = argv[i] + 10;
        else if (!strncmp(argv[i], "--hex=", 6)) hexone = argv[i] + 6;
        else if (!strcmp(argv[i], "--batch")) batch = true;
        else if (!strncmp(argv[i], "--layer=", 8)) {
            if (!strcmp(argv[i] + 8, "boundary")) layer = LAYER_BOUNDARY;
            else if (!strcmp(argv[i] + 8, "fields")) layer = LAYER_FIELDS;
            else { usage(); return 2; }
        }
        else if (!strcmp(argv[i], "--fixups")) layer = LAYER_FIXUPS;
        else if (!strncmp(argv[i], "--mattr=", 8)) mattr = argv[i] + 8;
        else if (!strncmp(argv[i], "--mcpu=", 7)) mcpu = argv[i] + 7;
        else if (!strncmp(argv[i], "--allow=", 8)) allow = argv[i] + 8;
        else if (!strcmp(argv[i], "--check")) check = true;
        else if (!strcmp(argv[i], "--emit-raw")) emit_raw = true;
        else if (!strcmp(argv[i], "--keep-zero")) drop_zero = false;
        else { usage(); return 2; }
    }
    want_decode = strchr(classes, 'D');
    want_zeroacc = strchr(classes, 'Z');
    want_mem = strchr(classes, 'M');
    want_branch = strchr(classes, 'B');
    want_regs = strchr(classes, 'R');

    bool found = false;
    for (size_t i = 0; i < sizeof(kIsaTable)/sizeof(kIsaTable[0]); i++) {
        if (!strcmp(isaname, kIsaTable[i].name)) {
            isa = (Isa)i; cfg = kIsaTable[i]; found = true; break;
        }
    }
    if (!found) { fprintf(stderr, "unknown isa %s\n", isaname); return 2; }
    /* An explicit --mattr is an interactive experiment, not the shipped
     * subtarget: it replaces the optional list too, so what is compared is
     * exactly what was asked for. */
    if (mattr) { cfg.features = mattr; cfg.opt_features = ""; }
    if (mcpu)  cfg.cpu = mcpu;
    if (allow && !load_allow(allow)) {
        fprintf(stderr, "cannot read allowlist %s\n", allow); return 2;
    }

    llvm_init();

    /* The tracer's own tables and the register-name index derived from
     * them.  Unconditional: the boundary layer records generic ids too,
     * so `--hex` shows both vocabularies whichever layer is selected. */
    if (!isax_fields_init(cfg.name)) {
        fprintf(stderr,
                "isaxcheck: the tracer has no classification tables for %s\n",
                cfg.name);
        return 2;
    }
    build_name_to_generic();

    if (hexone) {
        uint8_t b[24]; unsigned n = 0;
        for (const char *p = hexone; p[0] && p[1] && n < 24; p += 2)
            b[n++] = (uint8_t)strtoul(std::string(p, p + 2).c_str(), nullptr, 16);
        CsView c; LlView l;
        qemu_plugin_insn_info info;
        IsaxFieldsView f;
        cs_decode(b, n, c, &info); ll_decode(b, n, l);
        if (c.ok) isax_fields_decode(&info, &f);
        printf("bytes    %s\n", hexbytes(b, n).c_str());
        printf("boundary ok=%d sz=%u  %s %s\n", c.ok, c.size, c.mnem.c_str(), c.ops.c_str());
        printf("   mem=%d r=%d w=%d unkMEM=%d unkREG=%d unmodelled-op=%d nops=%u\n",
               c.has_mem, c.mem_read, c.mem_write, c.mem_unknown, c.reg_unknown,
               c.has_invalid_op, c.n_ops);
        printf("   groups: jmp=%d call=%d ret=%d relbr=%d\n", c.g_jump, c.g_call,
               c.g_ret, c.g_branch_rel);
        printf("   RD{%s}\n   WR{%s}\n", setstr(c.rd).c_str(), setstr(c.wr).c_str());
        printf("llvm     ok=%d sz=%u  %s   (opc=%u)\n", l.ok, l.size, l.text.c_str(), l.opcode);
        printf("   mayLoad=%d mayStore=%d br=%d call=%d ret=%d indir=%d term=%d\n",
               l.may_load, l.may_store, l.is_branch, l.is_call, l.is_ret,
               l.is_indirect, l.is_term);
        printf("   RD{%s}\n   WR{%s}\n", setstr(l.rd).c_str(), setstr(l.wr).c_str());
        /* The third view: what the dependency model records, which is what
         * the trace is built from.  Where it differs from the boundary
         * above, the difference is a plugin-side repair -- `--fixups`
         * inventories and asserts them. */
        if (c.ok) {
            std::set<unsigned> fs(f.src.begin(), f.src.end());
            std::set<unsigned> fd(f.dst.begin(), f.dst.end());
            printf("fields   ok=%d  %s  %s%s%s\n", f.ok,
                   isax_opcode_name(f.opcode), isax_branch_name(f.branch_type),
                   f.branch_conditional ? " cond" : "",
                   f.is_atomic ? " atomic" : "");
            printf("   loads=%u stores=%u regdeps=%d addrdeps=%d vec=%d "
                   "lanekind=%u\n", f.max_dep_loads, f.max_dep_stores,
                   f.has_reg_deps, f.has_addr_deps, f.has_vec_lanes,
                   f.lane_mask_kind);
            printf("   SRC{%s}\n   DST{%s}\n", gensetstr(fs).c_str(),
                   gensetstr(fd).c_str());
            printf("boundary-in-generic\n   RD{%s}\n   WR{%s}\n",
                   gensetstr(c.grd).c_str(), gensetstr(c.gwr).c_str());
        }
        return 0;
    }

    /*
     * Batch mode: one TSV row per encoding read on stdin, carrying BOTH
     * decoders' views verbatim.  The sweep above answers "does anything
     * disagree"; this answers "what does each of them say about exactly
     * these bytes", which is what the checks that do not sweep need —
     * the implicit-operand assertion table (which has its own
     * spec-derived expectation and only needs the boundary's answer) and
     * the three-way version tripwire (which joins GNU binutils onto the
     * `hex` column, hence echoing the input bytes back).
     */
    if (batch) {
        printf("hex\tb_ok\tb_sz\tb_mnem\tb_ops\tb_mem\tb_r\tb_w\tb_unkmem\t"
               "b_unkreg\tb_unmodelled\tb_jmp\tb_call\tb_ret\tb_rd\tb_wr\t"
               "l_ok\tl_sz\tl_text\tl_ld\tl_st\tl_br\tl_call\tl_ret\t"
               "l_rd\tl_wr\n");
        char line[256];
        while (fgets(line, sizeof line, stdin)) {
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '#' || *p == '\n' || !*p) continue;
            uint8_t b[24]; unsigned n = 0;
            for (; p[0] && p[1] && isxdigit((unsigned char)p[0]) &&
                   isxdigit((unsigned char)p[1]) && n < 24; p += 2)
                b[n++] = (uint8_t)strtoul(std::string(p, p + 2).c_str(),
                                          nullptr, 16);
            if (!n) continue;
            CsView c; LlView l;
            cs_decode(b, n, c); ll_decode(b, n, l);
            /* The printer emits tabs inside operand lists; this is a TSV. */
            std::string t = l.text;
            for (auto &ch : t)
                if (ch == '\t' || ch == '\n' || ch == '\r') ch = ' ';
            printf("%s\t%d\t%u\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t"
                   "%s\t%s\t%d\t%u\t%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n",
                   hexbytes(b, n).c_str(), c.ok, c.size, c.mnem.c_str(),
                   c.ops.c_str(), c.has_mem, c.mem_read, c.mem_write,
                   c.mem_unknown, c.reg_unknown, c.has_invalid_op,
                   c.g_jump, c.g_call, c.g_ret,
                   setstr(c.rd).c_str(), setstr(c.wr).c_str(),
                   l.ok, l.size, t.c_str(), l.may_load, l.may_store,
                   l.is_branch, l.is_call, l.is_ret,
                   setstr(l.rd).c_str(), setstr(l.wr).c_str());
        }
        return 0;
    }

    // Child shard: dump machine-readable buckets and exit.
    if (emit_raw) {
        run_sweep(shard, nshard);
        printf("#tried\t%lu\n", total_tried);
        for (auto &kv : buckets)
            printf("%s\t%lu\t%s\n", kv.first.c_str(), kv.second.n,
                   kv.second.sample.c_str());
        return 0;
    }

    if (jobs > 1) {
        /*
         * Fork one child per shard.  Each child sweeps its stripe and writes
         * its bucket map to a pipe; the parent drains the pipes in order and
         * merges.  Draining sequentially cannot deadlock — a child that fills
         * its pipe simply blocks until the parent reaches it, and by then the
         * expensive part (the sweep itself) has already run concurrently.
         * Process isolation also means a decoder that faults on one hostile
         * encoding cannot take the whole sweep down silently.
         */
        std::vector<int> fds;
        std::vector<pid_t> pids;
        for (unsigned j = 0; j < jobs; j++) {
            int pfd[2];
            if (pipe(pfd) != 0) { perror("pipe"); return 2; }
            pid_t pid = fork();
            if (pid < 0) { perror("fork"); return 2; }
            if (pid == 0) {
                close(pfd[0]);
                dup2(pfd[1], STDOUT_FILENO);
                close(pfd[1]);
                run_sweep(j, jobs);
                printf("#tried\t%lu\n", total_tried);
                for (auto &kv : buckets)
                    printf("%s\t%lu\t%s\n", kv.first.c_str(), kv.second.n,
                           kv.second.sample.c_str());
                fflush(stdout);
                _exit(0);
            }
            close(pfd[1]);
            fds.push_back(pfd[0]);
            pids.push_back(pid);
        }
        buckets.clear();
        for (size_t j = 0; j < fds.size(); j++) {
            FILE *f = fdopen(fds[j], "r");
            if (!f) { perror("fdopen"); return 2; }
            std::string acc;
            char chunk[8192];
            size_t got;
            while ((got = fread(chunk, 1, sizeof chunk, f)) > 0)
                acc.append(chunk, got);
            fclose(f);
            size_t pos = 0;
            while (pos < acc.size()) {
                size_t nl = acc.find('\n', pos);
                if (nl == std::string::npos) nl = acc.size();
                std::string line = acc.substr(pos, nl - pos);
                pos = nl + 1;
                if (line.empty()) continue;
                size_t t1 = line.find('\t');
                if (t1 == std::string::npos) continue;
                size_t t2 = line.find('\t', t1 + 1);
                std::string key = line.substr(0, t1);
                unsigned long cnt = strtoul(line.c_str() + t1 + 1, nullptr, 10);
                std::string samp = (t2 == std::string::npos)
                                       ? std::string()
                                       : line.substr(t2 + 1);
                if (key == "#tried") { total_tried += cnt; continue; }
                auto &b = buckets[key];
                if (!b.n) b.sample = samp;
                b.n += cnt;
            }
        }
        int bad = 0;
        for (pid_t p : pids) {
            int st = 0;
            waitpid(p, &st, 0);
            if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) bad++;
        }
        if (bad) {
            fprintf(stderr, "isaxcheck: %d shard(s) failed\n", bad);
            return 2;
        }
    } else {
        run_sweep(shard, nshard);
    }

    unsigned long unallowed = 0;
    unsigned long gap_sigs = 0, gap_encodings = 0;
    std::map<std::string, bool> allowed_of;
    for (auto &kv : buckets) {
        bool ok = is_allowed(kv.first);
        allowed_of[kv.first] = ok;
        if (!ok) unallowed++;
        if (is_gap_key(kv.first)) { gap_sigs++; gap_encodings += kv.second.n; }
    }

    /*
     * A rule that matches nothing is not harmless.  It is a justification
     * for a disagreement that no longer happens, which means either the
     * disagreement was fixed and the note was left behind, or -- the case
     * that matters -- a decoder bump moved the signature and the rule now
     * silently protects nothing while the reader believes it does.
     */
    std::vector<const AllowRule *> dead;
    for (const auto &r : allow_rules)
        if (!r.used && r.isa == cfg.name) dead.push_back(&r);

    /* subtarget_gap only means anything where an LLVM rejection is one of
     * the outcomes.  --fixups compares the tracer against itself. */
    if (layer == LAYER_FIXUPS)
        printf("# isa=%s layer=fixups encodings_tried=%lu "
               "distinct_signatures=%zu allowlisted=%zu unallowed=%lu "
               "dead_allow_rules=%zu\n",
               cfg.name, total_tried, buckets.size(),
               buckets.size() - unallowed, unallowed, dead.size());
    else
        printf("# isa=%s layer=%s encodings_tried=%lu distinct_signatures=%zu "
               "allowlisted=%zu unallowed=%lu subtarget_gap=%lu/%lu "
               "dead_allow_rules=%zu ambiguous_reg_tokens=%u\n",
               cfg.name, layer == LAYER_FIELDS ? "fields" : "boundary",
               total_tried, buckets.size(),
               buckets.size() - unallowed, unallowed, gap_sigs, gap_encodings,
               dead.size(), regmap_ambiguous_tokens);
    if (!opt_taken.empty() || !opt_skipped.empty()) {
        printf("# llvm=%s optional_features_taken=%s skipped=%s\n",
               LLVM_VERSION_STRING, join(opt_taken).c_str(),
               join(opt_skipped).c_str());
    }
    for (auto &kv : buckets) {
        bool ok = allowed_of[kv.first];
        if (check && ok) continue;
        printf("%-4s %-46s n=%-9lu %s\n", ok ? "ALLOW" : "NEW",
               kv.first.c_str(), kv.second.n, kv.second.sample.c_str());
    }
    for (const AllowRule *r : dead)
        printf("DEAD %s:%u %s %s\n", allow ? allow : "-", r->lineno,
               r->isa.c_str(), r->key.c_str());

    return (check && (unallowed || !dead.empty())) ? 1 : 0;
}
