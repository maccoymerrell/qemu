/*
 * Mnemonic/register/ISA classification tables for champsim_tracer.
 *
 * The per-ISA tables use C99 designated array initialisers; g++ accepts
 * them with -Wno-pedantic so this TU compiles as C++ alongside the rest
 * of the plugin.  Refiners that need to read CPU state at exec time
 * (e.g. dep_riscv_v_* reading vtype.vl) can call into the C++ reg-handle
 * cache directly — no cross-language linkage anywhere inside the plugin.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <stdint.h>

extern "C" {
#include <qemu-plugin.h>
}

#define CHAMPSIM_MNEMONIC_TABLES_IMPL 1
#include "champsim_tracer_mnemonics.h"

/* ====================================================================
 * Shared dependency refiners
 *
 * Each refiner reads what the generic operand-walk and any optional
 * `.refine` callback left in @f, then populates the dep masks and
 * trips has_reg_deps.  The bit layout for every mask matches the
 * wire-format spec:
 *
 *   bits [0,             n_src_regs)                     src_reg[i]
 *   bits [n_src_regs,    n_src_regs + max_dep_loads)     load_data[i]
 *   bit   n_src_regs + max_dep_loads                      immediate
 *
 * @max_dep_loads / @max_dep_stores are populated by the operand
 * walker at template-build time from MEM-op access flags.  They are
 * the template-static MAX counts (the runtime per-iteration count
 * rides on CST_FID_N_LOADS / CST_FID_N_STORES deltas and can be
 * smaller, but never larger — they bound the static mask width).
 *
 * Refiners run once at template-construction time (per unique PC),
 * never during tracing.  Keep them branchy-but-cheap; consumers
 * tolerate broader-than-actual masks (false dependencies that hurt
 * accuracy) but not narrower ones (missed dependencies that break
 * regfile correctness).
 * ==================================================================== */

static uint64_t all_inputs_mask(const InsnFields *f)
{
    uint64_t m = 0;
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        m |= ((uint64_t)1 << i);
    }
    for (uint8_t i = 0; i < f->max_dep_loads; i++) {
        m |= ((uint64_t)1 << (f->n_src_regs + i));
    }
    if (f->has_immediate) {
        m |= ((uint64_t)1 << (f->n_src_regs + f->max_dep_loads));
    }
    return m;
}

/*
 * dep_all_to_all: explicit catch-all.  Every architectural dst and
 * every store_data depends on every input the operand-walk surfaced.
 *
 * Functionally identical to the consumer-side default (which is what
 * "no HAS_REG block on the wire" maps to), but emitting it explicitly
 * tells the audit script the row was intentionally classified rather
 * than left as an unclassified gap.  Use this for ops genuinely
 * everything-touches-everything (CPUID, RDTSC fan-out, arithmetic
 * with implicit-flags writers we don't model yet).
 */
void dep_all_to_all(const struct qemu_plugin_insn_info *info, InsnFields *f)
{
    (void)info;
    if (f->n_dst_regs == 0 && f->max_dep_stores == 0) {
        /* No architectural register/memory writes — nothing to
         * express on the wire.  Skip the HAS_REG block; the consumer
         * default already matches. */
        return;
    }
    const uint64_t m = all_inputs_mask(f);
    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        f->dst_dep_mask[d] = m;
    }
    for (uint8_t s = 0; s < f->max_dep_stores && s < MAX_STORES; s++) {
        f->store_data_dep_mask[s] = m;
    }
    f->has_reg_deps = true;
}

/*
 * dep_passthrough: single value input flows to a single output —
 * either a register dst or a memory store, with internal dispatch
 * by runtime shape.  Behavior group covers the MOV / load / store
 * family across all the operand-shape variants Capstone groups
 * under one insn id (e.g. X86_INS_MOV covers MOV32rr, MOV32rm,
 * MOV32mr, MOV32ri, MOV32mi — different runtime shapes, all
 * single-value-input, all single-output).
 *
 * Runtime shapes the walker produces, with the picked dependency:
 *
 *   rr-form  (n_dst=1, max_dep_stores=0, src_regs=[value])
 *     → dst[0] depends on src_regs[0]
 *
 *   rm-form  (n_dst=1, max_dep_loads=1, src_regs=[base, index?])
 *     → dst[0] depends on load_data[0]
 *
 *   ri-form  (n_dst=1, max_dep_loads=0, has_imm, src_regs=[])
 *     → dst[0] depends on imm
 *
 *   mr-form  (n_dst=0, max_dep_stores=1,
 *             src_regs=[base, index?, value])
 *     → store_data[0] depends on the LAST src_reg (the value).
 *       The walker adds MEM's address-mode regs first, then the
 *       value reg — so src_regs[n_src_regs - 1] is the value.
 *
 *   mi-form  (n_dst=0, max_dep_stores=1, has_imm,
 *             src_regs=[base, index?])
 *     → store_data[0] depends on imm
 *
 * Bails (leaves has_reg_deps=false → no HAS_REG block on the wire)
 * for shapes outside this behavior group; the audit-side classifier
 * is responsible for not pointing a multi-output or fan-out insn id
 * at dep_passthrough in the first place.
 */
/*
 * dep_lea: address-compute instructions (x86 LEA, AArch64 ADR/ADRP,
 * RISC-V AUIPC, ...).  Capstone marks the MEM operand on these as
 * CS_AC_READ, so the operand walker dutifully counts a load slot
 * and populates load_addr_dep_mask[0] from the addressing-mode
 * regs — but no actual load fires at runtime.  Left as-is, the
 * trace asserts a dst-dep on a phantom load_data slot the consumer
 * would wait on forever.
 *
 * This refiner undoes the misclassification:
 *   - max_dep_loads → 0 (no real load fires)
 *   - load_addr_dep_mask[*] cleared
 *   - has_addr_deps cleared when no real store remains either
 *   - dst[0] mask = every explicit src_reg (plus imm if present)
 *     — the dst literally IS the computed address, so it depends
 *     on every address-component reg the walker saw
 *
 * Net consumer benefit: rename slots for the addressing regs can
 * still be released at execute time (when the address is computed
 * and gp1 retires) rather than pinned alive waiting on a load that
 * never returns.
 */
void dep_lea(const struct qemu_plugin_insn_info *info, InsnFields *f)
{
    (void)info;
    /* Reverse the walker's phantom load(s).  We use max_dep_loads
     * as the bound, then zero it so the wire and the bit layout
     * agree on "no load slots." */
    for (uint8_t k = 0; k < f->max_dep_loads && k < MAX_LOADS; k++) {
        f->load_addr_dep_mask[k] = 0;
    }
    f->max_dep_loads = 0;
    if (f->max_dep_stores == 0) {
        f->has_addr_deps = false;
    }

    if (f->n_dst_regs == 0) {
        /* Defensive — every real address-compute opcode writes a
         * dst.  If we land here with none, just bail and let the
         * default HAS_REG emission stay off. */
        return;
    }

    /* dst[0] = address computation result, which depends on every
     * explicit src_reg the walker added plus the immediate if one
     * was surfaced.  Bit positions match the HAS_REG layout after
     * we zeroed max_dep_loads, so the imm bit sits at n_src + 0. */
    uint64_t m = 0;
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        m |= ((uint64_t)1 << i);
    }
    if (f->has_immediate) {
        m |= ((uint64_t)1 << f->n_src_regs);
    }
    f->dst_dep_mask[0] = m;
    f->has_reg_deps = true;
}

/*
 * Helpers for the stack-op refiner family.
 *
 * find_stack_ptr_src: locate a "stack pointer" candidate.  The
 * heuristic is "the first src_reg that's also a dst_reg" — the RMW
 * pattern that signals a pointer being read for addressing AND
 * written back after the implicit adjust.  This matches REG_SP for
 * PUSH/POP/CALL/RET/PUSHA/POPA, and matches REG_BP for LEAVE (which
 * uses RBP as the implicit address source while also clobbering it).
 * Returns the src-slot index, or -1 when no intersection exists.
 *
 * find_dst_slot: find a specific reg_id in dst_regs[] (used to
 * narrow the SP-dst's dep_mask to just the SP src bit).
 */
static int find_stack_ptr_src(const InsnFields *f)
{
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        for (uint8_t j = 0; j < f->n_dst_regs; j++) {
            if (f->src_regs[i] == f->dst_regs[j]) {
                return (int)i;
            }
        }
    }
    return -1;
}

static int find_dst_slot(const InsnFields *f, uint8_t reg_id)
{
    for (uint8_t i = 0; i < f->n_dst_regs; i++) {
        if (f->dst_regs[i] == reg_id) {
            return (int)i;
        }
    }
    return -1;
}

/*
 * dep_x86_stack_push: covers every "store one or more values to a
 * stack-style pointer, decrement the pointer" pattern Capstone
 * leaves under-tagged.
 *
 * Includes single-memop forms (PUSH reg, PUSH imm, CALL imm,
 * LCALL) and the multi-memop fan-outs (PUSHA / PUSHAL / PUSHAW
 * push 8 GPRs, ENTER pushes BP plus N saved pointers).
 *
 * The refiner identifies the stack pointer as the src_reg also
 * present in dst_regs (RMW pattern — read for addressing, written
 * after the adjust).  For every OTHER src_reg, it emits one
 * implicit store whose address depends on the stack pointer and
 * whose data depends on that src_reg.  For PUSH imm with no
 * other srcs, the imm itself becomes the store data.  CALL imm
 * has both the imm (branch target) and an implicit IP read; only
 * the IP becomes store_data — the imm is the target, not the
 * pushed value.
 *
 * Reg-side: the stack-pointer dst's dep narrows to "just the
 * stack-pointer src + imm-if-present" (a single-source decrement;
 * exposing this lets the consumer release rename slots for the
 * pushed src registers at AGU time rather than pinning them
 * until the SP retires).  Other dsts (CALL's IP write) stay on
 * the all-inputs over-approximation.
 *
 * If no stack-pointer candidate is found, bail to dep_all_to_all.
 */
void dep_x86_stack_push(const struct qemu_plugin_insn_info *info,
                        InsnFields *f)
{
    int sp_src = find_stack_ptr_src(f);
    if (sp_src < 0) {
        dep_all_to_all(info, f);
        return;
    }
    const uint64_t sp_bit = (uint64_t)1 << sp_src;
    /* The stack pointer's dst slot — there's always one (we found
     * the SP src via intersection with dst_regs). */
    int sp_dst = find_dst_slot(f, f->src_regs[sp_src]);

    /* Emit one implicit store per non-SP src.  Multi-memop ops
     * (PUSHA/ENTER) get N stores; single-memop PUSH/CALL get 1. */
    bool any_store = false;
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        if ((int)i == sp_src) continue;
        if (f->max_dep_stores >= MAX_STORES) break;
        uint8_t s = f->max_dep_stores++;
        f->store_addr_dep_mask[s] = sp_bit;
        f->store_data_dep_mask[s] = ((uint64_t)1 << i);
        any_store = true;
    }
    /* PUSH imm with no register srcs: the imm itself is the data.
     * (For CALL imm we skipped this because IP-as-src already
     * accounted for a store of the return address.) */
    if (!any_store && f->has_immediate &&
        f->max_dep_stores < MAX_STORES) {
        uint8_t s = f->max_dep_stores++;
        f->store_addr_dep_mask[s] = sp_bit;
        f->store_data_dep_mask[s] =
            ((uint64_t)1 << (f->n_src_regs + f->max_dep_loads));
        any_store = true;
    }
    if (any_store) {
        f->has_addr_deps = true;
    }

    /* SP-dst depends only on SP-src (single-source decrement) plus
     * imm if present (RETN imm16 family — unusual for push side but
     * harmless to mark conservatively).  Other dsts (CALL's IP)
     * keep the all-inputs over-approximation. */
    uint64_t imm_bit = f->has_immediate
        ? ((uint64_t)1 << (f->n_src_regs + f->max_dep_loads)) : 0;
    const uint64_t sp_dep_mask = sp_bit | imm_bit;
    uint64_t all_inputs = 0;
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        all_inputs |= ((uint64_t)1 << i);
    }
    for (uint8_t i = 0; i < f->max_dep_loads; i++) {
        all_inputs |= ((uint64_t)1 << (f->n_src_regs + i));
    }
    all_inputs |= imm_bit;
    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        f->dst_dep_mask[d] =
            ((int)d == sp_dst) ? sp_dep_mask : all_inputs;
    }
    f->has_reg_deps = true;
}

/*
 * dep_x86_stack_pop: mirror of dep_x86_stack_push.  Covers
 * single-memop forms (POP reg, RET, RETF) and multi-memop forms
 * (POPA / POPAL / POPAW pop 8 GPRs, IRET pops IP+CS+EFLAGS,
 * LEAVE pops RBP using RBP itself as the address — the
 * stack-pointer-candidate heuristic catches that variant via
 * src ∩ dst).
 *
 * Stack-pointer identification: same intersection heuristic as
 * dep_x86_stack_push.  For each NON-SP dst, the refiner emits one
 * implicit load and binds the dst to load_data[k].  The SP dst
 * narrows to "just SP src + imm" (a single-source increment,
 * exposing the rename release window).
 *
 * Bit position note: bumping max_dep_loads shifts the imm bit up
 * by 1 per iteration.  We compute dst masks AFTER all loads are
 * registered so the imm bit lands in its final position.
 */
void dep_x86_stack_pop(const struct qemu_plugin_insn_info *info,
                       InsnFields *f)
{
    int sp_src = find_stack_ptr_src(f);
    if (sp_src < 0) {
        dep_all_to_all(info, f);
        return;
    }
    const uint64_t sp_bit = (uint64_t)1 << sp_src;
    int sp_dst = find_dst_slot(f, f->src_regs[sp_src]);

    /* Track the dst → load_idx mapping as we go (mask bit positions
     * use n_src_regs + load_idx, locked in once we stop adding). */
    uint8_t load_for_dst[MAX_DST_REGS];
    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        load_for_dst[d] = UINT8_MAX;
    }
    bool any_load = false;
    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        if ((int)d == sp_dst) continue;
        if (f->max_dep_loads >= MAX_LOADS) break;
        uint8_t l = f->max_dep_loads++;
        f->load_addr_dep_mask[l] = sp_bit;
        load_for_dst[d] = l;
        any_load = true;
    }
    if (any_load) {
        f->has_addr_deps = true;
    }

    /* After all loads are registered the imm bit settles. */
    const uint64_t imm_bit = f->has_immediate
        ? ((uint64_t)1 << (f->n_src_regs + f->max_dep_loads)) : 0;
    const uint64_t sp_dep_mask = sp_bit | imm_bit;

    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        if ((int)d == sp_dst) {
            f->dst_dep_mask[d] = sp_dep_mask;
        } else if (load_for_dst[d] != UINT8_MAX) {
            f->dst_dep_mask[d] =
                (uint64_t)1 << (f->n_src_regs + load_for_dst[d]);
        } else {
            /* Ran out of MAX_LOADS slots — fall back to all-inputs
             * for this dst to stay conservative-correct. */
            uint64_t all_inputs = 0;
            for (uint8_t i = 0; i < f->n_src_regs; i++) {
                all_inputs |= ((uint64_t)1 << i);
            }
            for (uint8_t i = 0; i < f->max_dep_loads; i++) {
                all_inputs |= ((uint64_t)1 << (f->n_src_regs + i));
            }
            all_inputs |= imm_bit;
            f->dst_dep_mask[d] = all_inputs;
        }
    }
    f->has_reg_deps = true;
}

void dep_passthrough(const struct qemu_plugin_insn_info *info, InsnFields *f)
{
    (void)info;
    if (f->n_dst_regs == 1 && f->max_dep_stores == 0) {
        uint64_t m = 0;
        if (f->max_dep_loads > 0) {
            m = ((uint64_t)1 << f->n_src_regs);                        /* load[0] */
        } else if (f->n_src_regs > 0) {
            m = (uint64_t)1;                                           /* src_regs[0] */
        } else if (f->has_immediate) {
            m = ((uint64_t)1 << (f->n_src_regs + f->max_dep_loads));   /* imm */
        } else {
            return;
        }
        f->dst_dep_mask[0] = m;
        f->has_reg_deps = true;
        return;
    }
    if (f->n_dst_regs == 0 && f->max_dep_stores == 1) {
        uint64_t m = 0;
        if (f->has_immediate) {
            m = ((uint64_t)1 << (f->n_src_regs + f->max_dep_loads));   /* imm */
        } else if (f->n_src_regs > 0) {
            m = ((uint64_t)1 << (f->n_src_regs - 1));                  /* last = value */
        } else {
            return;
        }
        f->store_data_dep_mask[0] = m;
        f->has_reg_deps = true;
        return;
    }
    /* Shape outside this behavior group — bail. */
}

/* ====================================================================
 * Vector lane refiners
 *
 * Two families, distinguished only by lane_parallel:
 *
 *   dep_vec_lane_parallel — element-wise SIMD arith (VADDPS, VPADDD,
 *       VMULPS, VFMA*, NEON FADD .4S, RISC-V vadd.vv when SEW known,
 *       etc.).  Lane k of each dst depends only on lane k of its
 *       src masks; consumer can model independent per-lane chains.
 *
 *   dep_vec_lane_cross    — vec ops that touch lanes but cross-couple
 *       (VPSHUFB, VBROADCAST, VPERMD, VHADDPS, horizontal reductions).
 *       The masks describe which lanes participate, but the consumer
 *       must treat them as cross-coupled within the active set.
 *
 * Both refiners derive the baseline lane bitmap from Capstone-
 * surfaced info->operands[i].size and lane_bytes:
 *   lanes    = op->size / op->lane_bytes
 *   baseline = (1 << lanes) - 1
 *
 * For the common case (one memop per vec op feeds all lanes of the
 * matching reg), the per-memop lane masks just mirror the per-reg
 * baseline — both load_data_lane_mask[k] and store_data_lane_mask[s]
 * are set to the same value.  Gather/scatter (one memop per lane)
 * needs its own refiner that sets load_data_lane_mask[k] = (1<<k).
 *
 * Bails (leaves has_vec_lanes=false) when no operand carries a
 * recognisable lane width — RISC-V V (where SEW is a runtime CSR
 * not derivable from disassembly), or an unrecognised mnemonic
 * suffix.  decode.cc audits these silent fallbacks and logs them
 * via the existing unknown_warn pipe.
 */

static uint64_t lane_baseline_from_operand(
    const struct qemu_plugin_operand *op)
{
    if (!op || op->size == 0 || op->lane_bytes == 0) {
        return 0;
    }
    unsigned lanes = (unsigned)op->size / (unsigned)op->lane_bytes;
    if (lanes == 0 || lanes > 64) {
        return 0;
    }
    return (lanes == 64) ? ~(uint64_t)0
                         : (((uint64_t)1 << lanes) - 1);
}

/* Generic-statically-derivable shape: lane baseline comes from a
 * Capstone-surfaced REG operand's (size, lane_bytes).  Used by
 * dep_vec_lane_parallel / dep_vec_lane_cross — the shared library
 * refiners pointed at by audit rows on ISAs where the lane count
 * is fixed by the encoding (x86, aarch64 NEON, MIPS MSA). */
static void dep_vec_lane_common_static(
    const struct qemu_plugin_insn_info *info,
    InsnFields *f, bool lane_parallel)
{
    dep_all_to_all(info, f);

    if (!info) {
        return;
    }

    uint64_t baseline = 0;
    for (uint8_t i = 0; i < info->n_operands; i++) {
        const struct qemu_plugin_operand *op = &info->operands[i];
        if (op->type == QEMU_PLUGIN_OP_REG) {
            uint64_t m = lane_baseline_from_operand(op);
            if (m) {
                baseline = m;
                break;
            }
        }
    }
    if (!baseline) {
        /* Capstone didn't surface lane info for this ISA / variant.
         * Leave has_vec_lanes false; the audit script is responsible
         * for not pointing this row at a static-shape refiner when
         * lane info isn't statically derivable. */
        return;
    }
    f->lane_mask_kind = LANE_MASK_KIND_STATIC;
    f->lane_mask_base = baseline;
    f->has_vec_lanes  = true;
    f->lane_parallel  = lane_parallel;
}

void dep_vec_lane_parallel(const struct qemu_plugin_insn_info *info,
                           InsnFields *f)
{
    dep_vec_lane_common_static(info, f, /*lane_parallel=*/true);
}

void dep_vec_lane_cross(const struct qemu_plugin_insn_info *info,
                        InsnFields *f)
{
    dep_vec_lane_common_static(info, f, /*lane_parallel=*/false);
}

/*
 * RISC-V V refiner shape.  SEW + VL live in the runtime vtype CSR
 * (mutated by vsetvli / vsetvl / vsetivli), so lane info isn't
 * statically derivable from disassembly.  The refiner sets
 * LANE_MASK_KIND_RISCV_VTYPE and the source key for "vl"; the exec-
 * time dispatch reads vl and computes (1 << vl) - 1.  Covers both
 * vsetvli-immediate and vsetvl-register variants uniformly since
 * the CSR is read at body-emit time after any preceding vset* in
 * the same TB has run.
 */
static void dep_riscv_v_lane_common(const struct qemu_plugin_insn_info *info,
                                    InsnFields *f, bool lane_parallel)
{
    dep_all_to_all(info, f);
    f->lane_mask_kind = LANE_MASK_KIND_RISCV_VTYPE;
    f->lane_mask_base = 0;
    f->lane_mask_source_reg.feature = "org.gnu.gdb.riscv.csr";
    f->lane_mask_source_reg.name    = "vl";
    f->has_vec_lanes = true;
    f->lane_parallel = lane_parallel;
}

void dep_riscv_v_lane_parallel(const struct qemu_plugin_insn_info *info,
                               InsnFields *f)
{
    dep_riscv_v_lane_common(info, f, /*lane_parallel=*/true);
}

void dep_riscv_v_lane_cross(const struct qemu_plugin_insn_info *info,
                            InsnFields *f)
{
    dep_riscv_v_lane_common(info, f, /*lane_parallel=*/false);
}

