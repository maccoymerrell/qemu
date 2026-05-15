/*
 * Mnemonic/register/ISA classification tables for champsim_tracer.
 *
 * This translation unit is compiled as C (not C++) because the generated
 * Capstone mnemonic tables rely on non-monotonic designated array
 * initialisers, a C99/GNU-C feature that g++ does not fully implement
 * (it emits "sorry, unimplemented: non-trivial designated initializers
 * not supported").  All other champsim_tracer TUs are C++ and consume
 * these tables via the `extern` declarations in
 * champsim_tracer_mnemonics.h.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <stdint.h>

#include <qemu-plugin.h>

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
void dep_all_to_all(InsnFields *f)
{
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
void dep_lea(InsnFields *f)
{
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
 * Helpers for x86 stack-op refiners: locate REG_SP (the generic id
 * x86 RSP maps to in the operand walker) inside src_regs[] /
 * dst_regs[].  Returns the slot index or -1 if absent.
 */
static int find_src_slot(const InsnFields *f, uint8_t reg_id)
{
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        if (f->src_regs[i] == reg_id) {
            return (int)i;
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
 * dep_x86_stack_push: x86 PUSH / CALL / LCALL.  Capstone doesn't
 * enumerate the implicit `[rsp - N]` store as an explicit MEM
 * operand, so the walker leaves max_dep_stores at 0 even though a
 * runtime store fires.  This refiner reconstructs the implicit
 * store dependency:
 *
 *   - load_addr_dep_mask: unchanged (no load on push)
 *   - store_addr_dep_mask[k] = bit(rsp_src)
 *   - store_data_dep_mask[k] = every src_reg that ISN'T rsp + imm
 *       (for PUSH reg this is the value reg; for CALL it's the
 *        implicit IP read; for PUSH imm it's the immediate)
 *
 * Reg-side: rsp_dst's dep narrows to "just rsp_src" (rsp = rsp - N,
 * a single-source update — exposing this enables the consumer to
 * release the renamed src registers as soon as the AGU consumes
 * them rather than pinning them until rsp_new retires).
 *
 * Defensive: if REG_SP isn't found in src_regs (e.g. an exotic
 * variant the walker didn't tag with implicit RSP), bail and let
 * the row fall back to dep_all_to_all's mask.
 */
void dep_x86_stack_push(InsnFields *f)
{
    int sp_src = find_src_slot(f, REG_SP);
    if (sp_src < 0 || f->max_dep_stores >= MAX_STORES) {
        dep_all_to_all(f);
        return;
    }
    int sp_dst = find_dst_slot(f, REG_SP);
    const uint64_t sp_bit = (uint64_t)1 << sp_src;

    /* Add the implicit store: addr = rsp, data = "every src that's
     * not rsp" (the value being pushed) + imm. */
    uint64_t value_mask = 0;
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        if ((int)i != sp_src) {
            value_mask |= ((uint64_t)1 << i);
        }
    }
    if (f->has_immediate) {
        value_mask |= ((uint64_t)1 << (f->n_src_regs + f->max_dep_loads));
    }
    uint8_t s = f->max_dep_stores++;
    f->store_addr_dep_mask[s] = sp_bit;
    f->store_data_dep_mask[s] = value_mask;
    f->has_addr_deps = true;

    /* rsp_dst depends only on rsp_src (+ imm for adjusting variants).
     * Other dsts (CALL's IP write) depend on every input — leaving
     * them at the all-to-all over-approximation. */
    const uint64_t sp_dep_mask = sp_bit |
        (f->has_immediate
            ? ((uint64_t)1 << (f->n_src_regs + f->max_dep_loads)) : 0);
    uint64_t all_inputs = 0;
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        all_inputs |= ((uint64_t)1 << i);
    }
    for (uint8_t i = 0; i < f->max_dep_loads; i++) {
        all_inputs |= ((uint64_t)1 << (f->n_src_regs + i));
    }
    if (f->has_immediate) {
        all_inputs |= ((uint64_t)1 << (f->n_src_regs + f->max_dep_loads));
    }
    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        f->dst_dep_mask[d] =
            ((int)d == sp_dst) ? sp_dep_mask : all_inputs;
    }
    f->has_reg_deps = true;
}

/*
 * dep_x86_stack_pop: x86 POP / RET / RETF / IRET-style.  Mirror of
 * dep_x86_stack_push — Capstone doesn't enumerate the implicit
 * `[rsp]` load, so this refiner reconstructs it:
 *
 *   - load_addr_dep_mask[k] = bit(rsp_src)
 *   - load_data goes to whichever dst is the popped value (RIP for
 *     RET, the popped reg for POP).  We pick "every dst that isn't
 *     rsp" — POP has just one such dst (the popped reg), RET has
 *     RIP as that dst.
 *   - rsp_dst narrows to "just rsp_src" (+ imm for RETN imm16)
 *
 * Bit position note: when we bump max_dep_loads, the imm bit
 * position in subsequent masks shifts up by 1.  We compute dst
 * masks AFTER the bump so the imm bit lands in the right place.
 */
void dep_x86_stack_pop(InsnFields *f)
{
    int sp_src = find_src_slot(f, REG_SP);
    if (sp_src < 0 || f->max_dep_loads >= MAX_LOADS) {
        dep_all_to_all(f);
        return;
    }
    int sp_dst = find_dst_slot(f, REG_SP);
    const uint64_t sp_bit = (uint64_t)1 << sp_src;

    uint8_t l = f->max_dep_loads++;
    f->load_addr_dep_mask[l] = sp_bit;
    f->has_addr_deps = true;

    /* After bumping max_dep_loads, the imm bit moved up.  Recompute. */
    const uint64_t load_bit  = (uint64_t)1 << (f->n_src_regs + l);
    const uint64_t imm_bit   = f->has_immediate
        ? ((uint64_t)1 << (f->n_src_regs + f->max_dep_loads)) : 0;

    const uint64_t sp_dep_mask  = sp_bit | imm_bit;
    /* The popped value flows from the load to whichever architectural
     * dst isn't rsp (RIP for RET, the explicit dst reg for POP). */
    const uint64_t pop_dep_mask = load_bit;

    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        f->dst_dep_mask[d] =
            ((int)d == sp_dst) ? sp_dep_mask : pop_dep_mask;
    }
    f->has_reg_deps = true;
}

void dep_passthrough(InsnFields *f)
{
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

