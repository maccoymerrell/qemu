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

/* The isa_properties[] rows name the shared guest-marker encoders and
 * their byte sizes; pull in the contract before the table is defined. */
#include "champsim_marker.h"

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
 * REG_SP is matched explicitly first, rather than taken as whichever
 * intersection happens to come first, because "first" is an operand-
 * order accident and another register can wear the same RMW shape.
 * The form that exposed it is the PLT/GOT call `call *disp(%rip)`
 * (`ff 15`): RIP-relative addressing READS %ip and the call WRITES
 * it, so %ip intersects too and precedes %sp in the operand array.
 * The whole refiner then hung off the wrong register — the SP
 * destination took a dependency on the load, the IP destination
 * depended on itself instead of on the load, and the store carried
 * an %ip address where the architecture uses %sp.  LEAVE is why this
 * cannot simply REQUIRE REG_SP: its stack pointer really is RBP, so
 * the first-intersection scan remains as the fallback.
 *
 * find_dst_slot: find a specific reg_id in dst_regs[] (used to
 * narrow the SP-dst's dep_mask to just the SP src bit).
 */
static int find_stack_ptr_src(const InsnFields *f)
{
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        if (f->src_regs[i] != REG_SP) {
            continue;
        }
        for (uint8_t j = 0; j < f->n_dst_regs; j++) {
            if (f->dst_regs[j] == REG_SP) {
                return (int)i;
            }
        }
    }
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

static int find_src_slot(const InsnFields *f, uint8_t reg_id)
{
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        if (f->src_regs[i] == reg_id) {
            return (int)i;
        }
    }
    return -1;
}

/*
 * Source bits that exist only to COMPUTE AN ADDRESS, never to supply a
 * value.  The operand walker fills load_addr_dep_mask / store_addr_dep_mask
 * before any .dep_refine runs, so a refiner deciding "which of my sources
 * is the datum" can subtract these instead of guessing.  Without it a
 * stack push whose operand is in memory names its base register as the
 * pushed value.
 */
static uint64_t addr_only_input_mask(const InsnFields *f, uint8_t n_stores)
{
    uint64_t m = 0;
    for (uint8_t k = 0; k < f->max_dep_loads; k++) {
        m |= f->load_addr_dep_mask[k];
    }
    for (uint8_t s = 0; s < n_stores; s++) {
        m |= f->store_addr_dep_mask[s];
    }
    return m;
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
 * after the adjust).  It then has to answer one question per store:
 * WHICH INPUT IS THE PUSHED VALUE.  A source can be present for
 * three different reasons, and only one of them is the datum:
 *
 *   - it is the stack pointer (address, and the RMW destination);
 *   - it is an address input of a memory operand — `pushq -8(%rbp)`
 *     reads rbp to FORM an address, the value pushed is what the
 *     load returns;
 *   - it is the indirect branch target of a call — `callq *%rax`
 *     reads rax to decide WHERE TO GO, the value pushed is the
 *     return address.
 *
 * Naming any of the other two as the store's data is a false
 * dependency edge on some of the most frequent instructions a
 * program executes, so all three are separated here:
 *
 *   - the stack pointer is skipped, as it always was;
 *   - address inputs come from addr_only_input_mask(), which reads
 *     the load/store address masks the operand walker already
 *     filled in;
 *   - a CALL pushes exactly one value, its return address, so when
 *     an IP source is present it is the only store the call emits.
 *     (A 16/32-bit far call also pushes CS; that form carries no IP
 *     source here, so it falls through to the general rule
 *     unchanged.)
 *
 * What is left over is the datum.  When nothing is left over the
 * pushed value is the memory operand's load result (`push m64`) or,
 * failing that, the immediate (`push $imm`).
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

    /* Address-only sources, snapshotted before max_dep_stores grows. */
    const uint64_t addr_inputs = addr_only_input_mask(f, f->max_dep_stores);
    const bool is_call = (f->branch_type == BRANCH_DIRECT_CALL ||
                          f->branch_type == BRANCH_INDIRECT_CALL);

    bool any_store = false;
    int ip_src = is_call ? find_src_slot(f, REG_IP) : -1;
    if (ip_src >= 0 && f->max_dep_stores < MAX_STORES) {
        /* A call pushes its return address and nothing else, whatever
         * else it happens to read to find its target. */
        uint8_t s = f->max_dep_stores++;
        f->store_addr_dep_mask[s] = sp_bit;
        f->store_data_dep_mask[s] = ((uint64_t)1 << ip_src);
        any_store = true;
    } else {
        /* Emit one implicit store per non-SP, non-address-only src.
         * Multi-memop ops (PUSHA/ENTER) get N stores; single-memop
         * PUSH gets 1. */
        for (uint8_t i = 0; i < f->n_src_regs; i++) {
            if ((int)i == sp_src) continue;
            if (addr_inputs & ((uint64_t)1 << i)) continue;
            if (f->max_dep_stores >= MAX_STORES) break;
            uint8_t s = f->max_dep_stores++;
            f->store_addr_dep_mask[s] = sp_bit;
            f->store_data_dep_mask[s] = ((uint64_t)1 << i);
            any_store = true;
        }
    }
    /* PUSH m64: every register source went into the address, so the
     * pushed value is what the load returned. */
    if (!any_store && f->max_dep_loads > 0 &&
        f->max_dep_stores < MAX_STORES) {
        uint8_t s = f->max_dep_stores++;
        f->store_addr_dep_mask[s] = sp_bit;
        f->store_data_dep_mask[s] = ((uint64_t)1 << f->n_src_regs);
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
    /*
     * Multi-destination pure load.  Two real shapes land here with
     * n_dst_regs > 1:
     *   - SVE LD1* whose Capstone Z-register destination and the
     *     QEMU-side V-register alias are counted as two distinct
     *     generic dst slots (the z<->v aliasing);
     *   - NEON structure loads LD2/LD3/LD4 { vN..vN+k } with a
     *     register-list destination.
     * Both are "every destination register is produced by the load
     * data" — the same pass-through dataflow as the single-dst form,
     * just wider.  The strict n_dst_regs == 1 guard below would bail
     * and emit no HAS_REG block, which the consumer renders as a
     * dst that depends on nothing — i.e. a load with no load
     * latency (the register-move footgun).  Bind every dst to the
     * load-data slot(s).  OR-ing all load slots into each dst is a
     * sound over-approximation for the multi-load structure forms
     * (per-element precision would need structure metadata); the
     * correctness property that matters — the dst waits on memory,
     * not on a 1-cycle register move — is preserved.
     */
    if (f->max_dep_stores == 0 && f->max_dep_loads > 0
        && f->n_dst_regs > 1) {
        uint64_t m = 0;
        for (uint8_t l = 0; l < f->max_dep_loads; l++) {
            m |= ((uint64_t)1 << (f->n_src_regs + l));
        }
        for (uint8_t d = 0; d < f->n_dst_regs && d < MAX_DST_REGS;
             d++) {
            f->dst_dep_mask[d] = m;
        }
        f->has_reg_deps = true;
        return;
    }
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
            /*
             * Value-src is whatever is in src_regs[] that the walker
             * did NOT mark as part of the store's address-mode regs
             * (store_addr_dep_mask[0]).  Works uniformly regardless of
             * the Capstone operand order:
             *
             *   x86 ATT mov-store: ops = [MEM, REG] → src_regs =
             *     [BASE, VALUE], store_addr_dep[0] = bit 0 (BASE),
             *     value_mask = bit 1 (VALUE).
             *
             *   AArch64 STR / RISC-V SD / MIPS SW: ops = [REG, MEM]
             *     → src_regs = [VALUE, BASE], store_addr_dep[0] =
             *     bit 1 (BASE), value_mask = bit 0 (VALUE).
             *
             * The original "last src is value" heuristic only matched
             * the x86 case and silently mis-attributed the dep on the
             * other three ISAs; the exact-check probe
             * probe_exact_store_rm flags this directly.
             */
            uint64_t addr_mask = f->store_addr_dep_mask[0];
            uint64_t all_src = ((uint64_t)1 << f->n_src_regs) - 1;
            uint64_t value_mask = all_src & ~addr_mask;
            if (!value_mask) {
                /* Can't isolate a value src — fall back to the
                 * conservative-correct all-to-all rather than emit a
                 * wrong dep. */
                dep_all_to_all(info, f);
                return;
            }
            m = value_mask;
        } else {
            return;
        }
        f->store_data_dep_mask[0] = m;
        f->has_reg_deps = true;
        return;
    }
    /* Shape outside this behavior group — bail. */
}

/*
 * dep_vec_struct_load: structured multi-register vector load whose
 * memops partition contiguously across the dst registers (AArch64
 * LD1 multi-reg, LDP, NEON LDxxV-multi, x86 register-pair forms).
 * The ISA semantics say lanes-per-reg consecutive memops feed each
 * dst in dst_regs[] order — the refiner expresses that on the wire
 * so each dst's dst_dep marks only its own load slots, and the
 * encoder's per-memop lane attribution can read the correct host
 * register out of dst_dep instead of falling back to a global
 * offset that ends up outside any one dst's per-register lane span.
 *
 * Shape conditions: n_dst_regs >= 1, max_dep_stores == 0,
 * max_dep_loads divisible by n_dst_regs.  Anything else falls back
 * to dep_all_to_all — interleaved structure loads (LD2/LD3/LD4 /
 * VPGATHER) need their own per-mnemonic refiner expressing their
 * own memop -> dst mapping.
 */
void dep_vec_struct_load(const struct qemu_plugin_insn_info *info,
                         InsnFields *f)
{
    if (f->n_dst_regs == 0 || f->max_dep_loads == 0
        || f->max_dep_stores != 0
        || (f->max_dep_loads % f->n_dst_regs) != 0) {
        dep_all_to_all(info, f);
        return;
    }
    unsigned loads_per_reg = f->max_dep_loads / f->n_dst_regs;
    /* Address-mode srcs (base, index) feed every dst (every memop
     * needs the address-mode regs to compute its EA). */
    uint64_t addr_mask = 0;
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        addr_mask |= ((uint64_t)1 << i);
    }
    for (uint8_t d = 0; d < f->n_dst_regs && d < MAX_DST_REGS; d++) {
        uint64_t mask = addr_mask;
        for (unsigned k = 0; k < loads_per_reg; k++) {
            unsigned slot = (unsigned)d * loads_per_reg + k;
            mask |= ((uint64_t)1 << (f->n_src_regs + slot));
        }
        f->dst_dep_mask[d] = mask;
    }
    f->has_reg_deps = true;
}

/*
 * dep_vec_struct_store: mirror of dep_vec_struct_load for stores.
 * Identifies the value-side vec srcs (src_lane_mask[i] != 0 — set
 * by the lane-shape pass for vec REG operands) and partitions
 * store_data_dep[s] across them.  Address-mode srcs (zero
 * src_lane_mask) are skipped on the value side; they live in
 * store_addr_dep[] separately.
 */
void dep_vec_struct_store(const struct qemu_plugin_insn_info *info,
                          InsnFields *f)
{
    if (f->n_src_regs == 0 || f->max_dep_stores == 0
        || f->max_dep_loads != 0) {
        dep_all_to_all(info, f);
        return;
    }
    /* Walk src_regs[] in template order, picking the vec-value
     * entries (those with a non-zero lane mask). */
    uint8_t vec_src_idx[MAX_SRC_REGS];
    uint8_t n_vec_src = 0;
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        if (f->src_lane_mask[i] != 0) {
            if (n_vec_src < MAX_SRC_REGS) {
                vec_src_idx[n_vec_src++] = i;
            }
        }
    }
    if (n_vec_src == 0 || (f->max_dep_stores % n_vec_src) != 0) {
        dep_all_to_all(info, f);
        return;
    }
    unsigned stores_per_src = f->max_dep_stores / n_vec_src;
    for (uint8_t s = 0; s < f->max_dep_stores && s < MAX_STORES; s++) {
        uint8_t which = vec_src_idx[s / stores_per_src];
        f->store_data_dep_mask[s] = ((uint64_t)1 << which);
    }
    f->has_reg_deps = true;
}

/*
 * dep_vec_struct_load_interleaved: structured multi-register vector
 * load where the architectural element layout interleaves across the
 * destination registers (AArch64 LD2/LD3/LD4 multi-structure loads,
 * RISC-V V VLSEG2..VLSEG8 segment loads).  Memop slot k goes to
 * destination register (k % n_dst_regs) — slot 0 → dst[0], slot 1 →
 * dst[1], ..., slot n_dst_regs → dst[0] again at lane 1, etc.
 *
 * The sequential refiner dep_vec_struct_load above handles LD1
 * (whole-register-at-a-time) loads where slots partition contiguously
 * across dsts.  This one handles structure-deinterleave loads where
 * slots round-robin across dsts.
 */
void dep_vec_struct_load_interleaved(
    const struct qemu_plugin_insn_info *info, InsnFields *f)
{
    if (f->n_dst_regs == 0 || f->max_dep_loads == 0
        || f->max_dep_stores != 0
        || (f->max_dep_loads % f->n_dst_regs) != 0) {
        dep_all_to_all(info, f);
        return;
    }
    unsigned factor = f->n_dst_regs;
    unsigned lanes_per_reg = f->max_dep_loads / factor;
    uint64_t addr_mask = 0;
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        addr_mask |= ((uint64_t)1 << i);
    }
    for (uint8_t d = 0; d < f->n_dst_regs && d < MAX_DST_REGS; d++) {
        uint64_t mask = addr_mask;
        for (unsigned lane = 0; lane < lanes_per_reg; lane++) {
            unsigned slot = lane * factor + (unsigned)d;
            mask |= ((uint64_t)1 << (f->n_src_regs + slot));
        }
        f->dst_dep_mask[d] = mask;
    }
    f->has_reg_deps = true;
}

/*
 * dep_vec_struct_store_interleaved: mirror for interleaved stores
 * (ST2/ST3/ST4, VSSEG2..VSSEG8).  Store slot s sources from value
 * src (s % n_vec_value_srcs) at lane (s / n_vec_value_srcs).
 */
void dep_vec_struct_store_interleaved(
    const struct qemu_plugin_insn_info *info, InsnFields *f)
{
    if (f->n_src_regs == 0 || f->max_dep_stores == 0
        || f->max_dep_loads != 0) {
        dep_all_to_all(info, f);
        return;
    }
    uint8_t vec_src_idx[MAX_SRC_REGS];
    uint8_t n_vec_src = 0;
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        if (f->src_lane_mask[i] != 0) {
            if (n_vec_src < MAX_SRC_REGS) {
                vec_src_idx[n_vec_src++] = i;
            }
        }
    }
    if (n_vec_src == 0 || (f->max_dep_stores % n_vec_src) != 0) {
        dep_all_to_all(info, f);
        return;
    }
    for (uint8_t s = 0; s < f->max_dep_stores && s < MAX_STORES; s++) {
        uint8_t which = vec_src_idx[(unsigned)s % n_vec_src];
        f->store_data_dep_mask[s] = ((uint64_t)1 << which);
    }
    f->has_reg_deps = true;
}

/*
 * Instruction vector lane shape.  Slot-agnostic — decode.cc owns the
 * operand->slot mapping and applies this per operand.  Determines
 * lane element width + total lane set, and whether the op is a
 * uniform packed op or an element insert/extract whose touched lane
 * is the instruction immediate.
 *
 * Insert/extract detection (purely structural, no per-mnemonic
 * table): the op is vec-lane-classified, has an immediate, has
 * exactly ONE vec-register operand (lane_bytes != 0), and a non-vec
 * element-sized data operand (a MEM or GPR whose size == lane_bytes).
 * This matches PINSR{B,W,D,Q}/PEXTR{B,W,D,Q}/INSERTPS/EXTRACTPS (mem
 * and reg forms) while excluding shuffles (two vec-reg operands) and
 * scalar SS/SD ops (lane_bytes == 0 by the Capstone width helper).
 * INSERT vs EXTRACT is decided by the vec reg's access: a WRITE-
 * containing vec reg is the insert destination; a READ-only vec reg
 * is the extract source.  lane_sel = immediate mod total_lanes.
 *
 * Runtime-SEW kinds (RISC-V V, lane_bytes 0): full_mask = ~0,
 * UNIFORM; the exec gate (vl) narrows it.
 */
LaneShape lane_shape_from_operands(
    const struct qemu_plugin_insn_info *info, uint8_t lane_mask_kind)
{
    LaneShape sh = { LANE_SHAPE_NONE, 0, 0, -1 };
    if (!info) return sh;

    /* Element width + lane count from the first vec REG operand,
     * plus a census for the insert/extract structural test. */
    uint8_t  lane_bytes  = 0;
    unsigned total_lanes = 0;
    uint64_t full_mask   = 0;
    unsigned vec_reg_ops  = 0;
    const struct qemu_plugin_operand *vec_reg = nullptr;
    bool     have_imm     = false;
    int64_t  imm_val      = 0;

    for (uint8_t i = 0; i < info->n_operands; i++) {
        const struct qemu_plugin_operand *op = &info->operands[i];
        if (op->type == QEMU_PLUGIN_OP_IMM) {
            if (!have_imm) { have_imm = true; imm_val = op->imm; }
            continue;
        }
        if (op->type != QEMU_PLUGIN_OP_REG) continue;
        if (op->lane_bytes == 0 || op->size == 0) continue;
        unsigned lanes = (unsigned)op->size / (unsigned)op->lane_bytes;
        if (lanes == 0 || lanes > 64) continue;
        vec_reg_ops++;
        if (!lane_bytes) {
            lane_bytes  = op->lane_bytes;
            total_lanes = lanes;
            full_mask   = (lanes == 64) ? ~(uint64_t)0
                                        : (((uint64_t)1 << lanes) - 1);
            vec_reg     = op;
        }
    }

    if (!full_mask) {
        if (lane_mask_kind != LANE_MASK_KIND_STATIC) {
            /* Runtime-SEW (RISC-V V): all-ones structural, vl-gated. */
            sh.kind = LANE_SHAPE_UNIFORM;
            sh.lane_bytes = 0;
            sh.full_mask  = ~(uint64_t)0;
            sh.lane_sel   = -1;
        }
        return sh;   /* STATIC w/o usable width -> NONE */
    }

    sh.lane_bytes = lane_bytes;
    sh.full_mask  = full_mask;

    /* Element-sized non-vec data operand (mem or gpr) present? */
    bool elem_data = false;
    for (uint8_t i = 0; i < info->n_operands; i++) {
        const struct qemu_plugin_operand *op = &info->operands[i];
        if (op == vec_reg) continue;
        if (op->type == QEMU_PLUGIN_OP_MEM && op->size == lane_bytes) {
            elem_data = true; break;
        }
        if (op->type == QEMU_PLUGIN_OP_REG && op->lane_bytes == 0
            && op->size == lane_bytes) {
            elem_data = true; break;
        }
    }

    if (have_imm && vec_reg_ops == 1 && elem_data && total_lanes) {
        int16_t sel = (int16_t)((uint64_t)imm_val % total_lanes);
        bool vec_write = (vec_reg->access & QEMU_PLUGIN_OP_ACC_WRITE) != 0;
        sh.kind     = vec_write ? LANE_SHAPE_INSERT : LANE_SHAPE_EXTRACT;
        sh.lane_sel = sel;
        return sh;
    }

    sh.kind = LANE_SHAPE_UNIFORM;
    return sh;
}
