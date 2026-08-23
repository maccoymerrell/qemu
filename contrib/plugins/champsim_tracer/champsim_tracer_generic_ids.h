/*
 * Wrong-Path Tracing Plugin — generic ID enums.
 *
 * Glib-free subset of champsim_tracer_mnemonics.h: the ISA-agnostic
 * enum domains and their COUNT sentinels.  Carved out so the
 * lightweight POD champsim_tracer_stats.h can size its attribution
 * arrays without mnemonics.h's glib dependency.  mnemonics.h includes
 * this header; both stay in lockstep.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <stdio.h>  /* snprintf in generic_reg_name */

/*
 * Canonical metaflags byte (v1.12+): an ISA-agnostic subset of
 * arithmetic flags.  Carried on the wire as a per-insn
 * CST_FID_METAFLAGS side-channel record (not a synthetic reg slot),
 * populated from the REG_FLAGS dst snap via
 * isa_properties[trace_isa].flags_to_metaflags.  Bits unset by an ISA
 * stay zero (P is x86-only); RISC-V/MIPS have no flags reg and never
 * emit this record.  Defined here so the C-only mnemonic-tables TU
 * can supply the bit-shuffle helper without champsim_tracer.h.
 */
#define CST_METAFLAGS_Z    (1u << 0)  /* zero / equal */
#define CST_METAFLAGS_N    (1u << 1)  /* negative / sign */
#define CST_METAFLAGS_C    (1u << 2)  /* unsigned carry / borrow */
#define CST_METAFLAGS_V    (1u << 3)  /* signed overflow */
#define CST_METAFLAGS_P    (1u << 4)  /* parity (x86 only) */
/* bits 5..7 reserved */

/* ISA enum: add new ISAs here and extend isa_properties[] in mnemonics.h. */
typedef enum {
    TRACE_ISA_UNKNOWN = 0,
    TRACE_ISA_X86     = 1,
    TRACE_ISA_AARCH64 = 2,
    TRACE_ISA_RISCV   = 3,
    TRACE_ISA_MIPS    = 4,
} TraceISA;

/*
 * ISA-agnostic generic opcodes.
 * Each value encodes the generic function of an instruction's operation,
 * consistent across all ISAs supported by QEMU.
 */
enum GenericOpcode {
    GEN_OP_UNKNOWN = 0,
    GEN_OP_INT_ADD = 1,
    GEN_OP_INT_SUB = 2,
    GEN_OP_INT_MUL = 3,
    GEN_OP_INT_DIV = 4,
    GEN_OP_AND = 5,
    GEN_OP_OR = 6,
    GEN_OP_XOR = 7,
    GEN_OP_NOT = 8,
    GEN_OP_SHL = 9,
    GEN_OP_SHR = 10,   /* SAR folds here: arith vs logical shift is a
                        * value distinction, not latency/dataflow. */
    GEN_OP_ROL = 11,
    GEN_OP_ROR = 12,
    /* Scalar bit-field / bit-count manip: BMI/BMI2, POPCNT,
     * LZCNT/TZCNT, BSF/BSR.  Distinct from boolean AND/OR/...: these
     * rearrange/extract/count bits and sit on a different port with
     * multi-cycle latency on real cores. */
    GEN_OP_BITMANIP = 13,
    GEN_OP_MOV = 14,
    GEN_OP_LOAD = 15,
    GEN_OP_STORE = 16,
    GEN_OP_PUSH = 17,
    GEN_OP_POP = 18,
    GEN_OP_LEA = 19,
    GEN_OP_MOVSX = 20,
    GEN_OP_MOVZX = 21,
    GEN_OP_XCHG = 22,
    GEN_OP_CMP = 23,
    GEN_OP_TEST = 24,
    GEN_OP_BRANCH = 25,   /* call-shaped control flow uses this too;
                           * there is no separate call opcode. */
    GEN_OP_RET = 26,
    GEN_OP_FP_ADD = 27,
    GEN_OP_FP_SUB = 28,
    GEN_OP_FP_MUL = 29,
    GEN_OP_FP_DIV = 30,
    GEN_OP_FP_SQRT = 31,
    GEN_OP_FP_MOV = 32,
    GEN_OP_FP_CVT = 33,
    GEN_OP_FP_CMP = 34,
    GEN_OP_VEC_ADD = 35,
    GEN_OP_VEC_SUB = 36,
    GEN_OP_VEC_MUL = 37,
    GEN_OP_VEC_DIV = 38,    /* packed FP/int divide & reciprocal
                             * approximation (RCPPS, VRCP14P*). */
    GEN_OP_VEC_SQRT = 39,   /* packed sqrt & rsqrt approximation
                             * (SQRTPS, RSQRTPS, VRSQRT14P*). */
    GEN_OP_VEC_MOV = 40,
    /* Vector load/store: memory access is the defining behaviour but
     * moves a SIMD-width value or uses SIMD gather/scatter, so it is
     * distinguished from scalar LOAD/STORE.  Per the load/store-yield
     * rule, real-compute insns classify by the compute instead. */
    GEN_OP_VEC_LOAD = 41,
    GEN_OP_VEC_STORE = 42,
    GEN_OP_VEC_SHUF = 43,
    GEN_OP_VEC_LOGIC = 44,
    GEN_OP_NOP = 45,
    GEN_OP_SYSCALL = 46,
    GEN_OP_FENCE = 47,
    GEN_OP_CMOV = 48,
    GEN_OP_SETCC = 49,
    GEN_OP_NEG = 50,
    GEN_OP_INC = 51,
    GEN_OP_DEC = 52,
    GEN_OP_INT_MADD = 53,
    GEN_OP_INT_MSUB = 54,
    GEN_OP_FP_MADD = 55,
    GEN_OP_FP_MSUB = 56,
    GEN_OP_VEC_MADD = 57,
    GEN_OP_VEC_MSUB = 58,
    /*
     * Memory-side hint/management insns (PREFETCHh, CLFLUSH, INVLPG,
     * AArch64 PRFM, RISC-V CBO, ...).  These emit no TCG memop, so the
     * tracer synthesises a load memop slot carrying the effective
     * address (operand decoded at translation, base/index read at
     * exec).  Address rides the load slot; opcode carries the
     * semantic distinction (prefetch / cache-flush / TLB-flush /
     * vec-prefetch).
     */
    GEN_OP_PREFETCH = 59,
    GEN_OP_CACHE_FLUSH = 60,
    GEN_OP_TLB_FLUSH = 61,
    GEN_OP_VEC_PREFETCH = 62,
    /*
     * Coarse fallback latency buckets for external trace writers
     * lacking ISA-specific opcode metadata.  The in-tree tracer never
     * emits these (every Capstone-classified insn gets a specific
     * opcode above), but consumers should handle them so foreign
     * traces decode.  SHORT = single-cycle ALU; LONG = long-latency
     * unit (multiplier, divider, vector pipe, ...).
     */
    GEN_OP_INT_ALU_SHORT = 63,
    GEN_OP_INT_ALU_LONG  = 64,
    GEN_OP_FP_ALU_SHORT  = 65,
    GEN_OP_FP_ALU_LONG   = 66,
    GEN_OP_VEC_ALU_SHORT = 67,
    GEN_OP_VEC_ALU_LONG  = 68,
    GEN_OP_COUNT
};

/* Branch type classification. */
enum BranchType {
    BRANCH_NONE = 0,
    BRANCH_DIRECT_JUMP = 1,
    BRANCH_INDIRECT_JUMP = 2,
    BRANCH_RETURN = 3,
    BRANCH_SYSCALL_TYPE = 4,
    BRANCH_COND_DIRECT = 5,
    /*
     * Self-loop terminator for an instruction whose memory fan-out is
     * bounded only by a register value — an x86 REP / REPNZ string op
     * or an AArch64 FEAT_MOPS bulk copy/set.  A conditional self-loop
     * branch (target = self-PC, fall-through = next PC): the tracer
     * fans iterations into per-iteration entries on a 1-insn self-loop
     * sub-template (see docs/format.rst §"Bulk-memory self-loop BBs").
     * Kept distinct from BRANCH_COND_DIRECT so consumers see the
     * no-target-diversity self-loop semantics.
     */
    BRANCH_REP = 6,
    /*
     * Calls (link the return address): kept distinct from plain jumps so
     * a consumer can drive a return-address stack — direct/indirect call
     * pushes, BRANCH_RETURN pops.  The number of calls is ~the number of
     * returns (they pair, modulo tail calls / PIC thunks / setjmp).
     * Direct = static immediate/relative target; indirect = register or
     * memory target.  Classification:
     *   - aarch64: bl -> DIRECT, blr family -> INDIRECT (distinct opcodes)
     *   - mips:    jal/bal/... -> DIRECT, jalr/jialc -> INDIRECT
     *   - x86:     call/lcall -> DIRECT, refined to INDIRECT on a
     *              register/memory target (one X86_INS_CALL covers both)
     *   - riscv:   jal/jalr link-and-jump; the call/jump/return role is
     *              carried by rd and only visible at run time (one
     *              insn_id covers jal+j and jalr+jr+ret), so the decoder
     *              refines from the live mnemonic alias.
     */
    BRANCH_DIRECT_CALL = 7,
    BRANCH_INDIRECT_CALL = 8,
    BRANCH_TYPE_COUNT,
};

/*
 * ISA-agnostic register IDs.
 * Consistent numbering across ISAs with reserved special register IDs.
 */
enum GenericRegId {
    REG_NONE = 0,
    /*
     * General-purpose integer registers: 1-32.
     *
     * The bank was 64 wide.  No traced ISA has more than 32 GPRs
     * (RISC-V 32, AArch64 31 + SP/ZR, MIPS 32, x86-64 APX 32 mapped
     * onto 0-29), so 33-64 were measurably dead space and now carry
     * the x86 control and debug files below.  See the allocation note
     * further down.
     */
    REG_GPR0 = 1,
    REG_GPR1, REG_GPR2, REG_GPR3, REG_GPR4, REG_GPR5, REG_GPR6, REG_GPR7,
    REG_GPR8, REG_GPR9, REG_GPR10, REG_GPR11, REG_GPR12, REG_GPR13,
    REG_GPR14, REG_GPR15, REG_GPR16, REG_GPR17, REG_GPR18, REG_GPR19,
    REG_GPR20, REG_GPR21, REG_GPR22, REG_GPR23, REG_GPR24, REG_GPR25,
    REG_GPR26, REG_GPR27, REG_GPR28, REG_GPR29, REG_GPR30, REG_GPR31,
    /*
     * Control registers: 33-48.  x86-64 CR0-CR15, one ID each.  These
     * are sixteen architecturally distinct registers with unrelated
     * roles — CR0 mode bits, CR2 the faulting linear address, CR3 the
     * page-table base, CR4 feature enables, CR8 the task priority —
     * and folding them onto one ID made every `mov %cr3, %rax` take a
     * false edge from every CR0 write.
     */
    REG_CTRL0 = 33,
    REG_CTRL1, REG_CTRL2, REG_CTRL3, REG_CTRL4, REG_CTRL5, REG_CTRL6,
    REG_CTRL7, REG_CTRL8, REG_CTRL9, REG_CTRL10, REG_CTRL11, REG_CTRL12,
    REG_CTRL13, REG_CTRL14, REG_CTRL15,
    /*
     * Debug registers: 49-64.  x86-64 DR0-DR15, one ID each.  DR0-DR3
     * hold four independent breakpoint addresses; DR6 is the status
     * word and DR7 the control word.  DR4/DR5 are NOT separate
     * registers — when CR4.DE is clear they alias DR6/DR7, and when it
     * is set they fault — so they fold onto REG_DEBUG6/REG_DEBUG7 and
     * REG_DEBUG4/REG_DEBUG5 stay unused (R8.2: an alias is not an
     * overlap).
     */
    REG_DEBUG0 = 49,
    REG_DEBUG1, REG_DEBUG2, REG_DEBUG3, REG_DEBUG4, REG_DEBUG5,
    REG_DEBUG6, REG_DEBUG7, REG_DEBUG8, REG_DEBUG9, REG_DEBUG10,
    REG_DEBUG11, REG_DEBUG12, REG_DEBUG13, REG_DEBUG14, REG_DEBUG15,
    /*
     * Floating-point registers: 65-96.  Was 64 wide; no traced ISA has
     * more than 32 FP registers, so 97-128 now carry the accumulator
     * high halves and the privileged-state behaviour classes below.
     */
    REG_FPR0 = 65,
    REG_FPR1, REG_FPR2, REG_FPR3, REG_FPR4, REG_FPR5, REG_FPR6, REG_FPR7,
    REG_FPR8, REG_FPR9, REG_FPR10, REG_FPR11, REG_FPR12, REG_FPR13,
    REG_FPR14, REG_FPR15, REG_FPR16, REG_FPR17, REG_FPR18, REG_FPR19,
    REG_FPR20, REG_FPR21, REG_FPR22, REG_FPR23, REG_FPR24, REG_FPR25,
    REG_FPR26, REG_FPR27, REG_FPR28, REG_FPR29, REG_FPR30, REG_FPR31,
    /*
     * Accumulator high halves: 97-100.  REG_ACC<n> (237-240) names the
     * LOW half; REG_ACCHI<n> names the HIGH half of the same
     * accumulator.  MIPS `mfhi` and `mflo` read DIFFERENT hardware and
     * binutils separates them, so one ID for both was a conflation a
     * consumer could not undo.  An instruction that uses the whole
     * 64-bit accumulator (MULT, the DSP DPA/EXTR family) names both
     * IDs, which is the register-LIST shape, not a fold.
     */
    REG_ACCHI0 = 97,
    REG_ACCHI1, REG_ACCHI2, REG_ACCHI3,
    /*
     * Privileged / system state, grouped by DEPENDENCE BEHAVIOUR:
     * 101-109.  One ID per group of registers a consumer must order
     * against the same events; see the allocation note below for the
     * grouping and its reason.  REG_SYS (243) remains the residual.
     */
    REG_SYSEXC   = 101,  /* written by the exception an insn raises */
    REG_SYSMMU   = 102,  /* address translation / TLB state */
    REG_SYSTIMER = 103,  /* free-running counter and its compare */
    REG_SYSPERF  = 104,  /* performance counters and their control */
    REG_SYSDBG   = 105,  /* debug / watchpoint / trace state */
    REG_SYSCACHE = 106,  /* cache tag-and-data access, error state */
    REG_SYSID    = 107,  /* read-only implementation identification */
    REG_COPROC0  = 108,  /* implementation-defined coprocessor file 0 */
    REG_COPROC1  = 109,  /* implementation-defined coprocessor file 1 */
    /* 110-128 unallocated — reserve for further behaviour classes. */
    /* Vector/SIMD registers: 129-192 */
    REG_VEC0 = 129,
    REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7,
    REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13,
    REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19,
    REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25,
    REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30, REG_VEC31,
    REG_VEC32, REG_VEC33, REG_VEC34, REG_VEC35, REG_VEC36, REG_VEC37,
    REG_VEC38, REG_VEC39, REG_VEC40, REG_VEC41, REG_VEC42, REG_VEC43,
    REG_VEC44, REG_VEC45, REG_VEC46, REG_VEC47, REG_VEC48, REG_VEC49,
    REG_VEC50, REG_VEC51, REG_VEC52, REG_VEC53, REG_VEC54, REG_VEC55,
    REG_VEC56, REG_VEC57, REG_VEC58, REG_VEC59, REG_VEC60, REG_VEC61,
    REG_VEC62, REG_VEC63,
    /* Predicate/mask registers: 193-224 */
    REG_PRED0 = 193,
    REG_PRED1, REG_PRED2, REG_PRED3, REG_PRED4, REG_PRED5, REG_PRED6,
    REG_PRED7, REG_PRED8, REG_PRED9, REG_PRED10, REG_PRED11, REG_PRED12,
    REG_PRED13, REG_PRED14, REG_PRED15, REG_PRED16, REG_PRED17,
    REG_PRED18, REG_PRED19, REG_PRED20, REG_PRED21, REG_PRED22,
    REG_PRED23, REG_PRED24, REG_PRED25, REG_PRED26, REG_PRED27,
    REG_PRED28, REG_PRED29, REG_PRED30, REG_PRED31,
    /* Special-purpose hardware/value register classes: 225-249 */
    REG_SEG0 = 225,
    REG_SEG1, REG_SEG2, REG_SEG3, REG_SEG4, REG_SEG5,
    /* 231-232 unallocated.  They held REG_CTRL and REG_DEBUG, one ID
     * for the whole x86 control file and one for the whole debug file;
     * those are sixteen distinct registers each and now occupy
     * REG_CTRL0..15 / REG_DEBUG0..15 above.  Left as holes rather than
     * reused so nothing renumbers. */
    REG_BOUND0 = 233,
    REG_BOUND1, REG_BOUND2, REG_BOUND3,
    REG_ACC0 = 237,
    REG_ACC1, REG_ACC2, REG_ACC3,
    REG_ZERO = 241,
    REG_MATRIX = 242,
    REG_SYS = 243,
    REG_FCSR = 244,
    REG_VCTRL = 245,
    /*
     * These IDs are GENERIC.  They abstract a guest register onto the
     * behaviour class a consumer schedules against.  What they must
     * NOT do is put two architecturally distinct registers on one ID.
     *
     * A fold that manufactures a dependency the guest does not have is
     * a MAPPING DEFECT, not an accepted cost.  A consumer is misled as
     * badly by an edge onto a register the instruction never touched
     * as by a missing one, and it has no way to tell the false edge
     * from a real one.  When two registers land on one ID and a
     * renaming regfile would not have to order them against each
     * other, the mapping is wrong and gets reworked — the space has
     * room, and "we cannot afford an ID" is not an argument that can
     * be made here.
     *
     * The converse is equally binding: two ISA register NAMES that
     * denote the SAME hardware register belong on one ID and always
     * did.  AArch64 v0/z0, x86 xmm16/ymm16/zmm16, rax/eax/ax/al, the
     * AArch64 D0_D1 register-list and RISC-V V0M2 LMUL-group forms,
     * MIPS F_HI<n>, x86 DR4/DR5 under CR4.DE=0 — all aliases, all
     * folded.  Only distinct hardware sharing an ID is a collision.
     *
     * A register the harness cannot REACH is not a mapped register.
     * A table row proves nothing on its own: RISCV_REG_SSP sat mapped
     * and unreachable because nothing set CS_MODE_RISCV_ZICFISS, and
     * the mapping read as correct for as long as nobody decoded for
     * it.  A mapping claim has to name the decode that produced the
     * register.
     *
     * SPACE, measured across all four generated tables (2026-08-23):
     * the GPR and FPR banks were 64 wide and no traced ISA fills more
     * than 32 of either, the VEC bank is 64 wide and 32 are used, and
     * 248-249 are holes.  That is 98 IDs with nothing in them.  The
     * dead upper halves of GPR (33-64) and FPR (97-128) now carry the
     * x86 control/debug files and the accumulator-high and
     * privileged-state classes; VEC 32-63 and PRED 16-31 hold the
     * architecturally distinct registers that fall outside an ISA's
     * numbered file but belong to its behaviour class (AArch64 ZT0,
     * FFR).
     *
     *   REG_SYS*    the privileged file is grouped by DEPENDENCE
     *               BEHAVIOUR, not enumerated.  MIPS CP0 alone has 288
     *               entries and giving each an ID would fragment the
     *               space for no gain, but one ID for all 288 makes
     *               every exception-raising instruction depend on
     *               every unrelated CP0 access.  The groups are the
     *               sets whose members a consumer must order against
     *               the same event:
     *                 REG_SYSEXC    written together BY an exception
     *                               (EPC, Cause, Status, BadVAddr,
     *                               ErrorEPC).  An edge inside this
     *                               group is real — one event writes
     *                               them all — and an edge to anything
     *                               outside it is not.
     *                 REG_SYSMMU    read/written by TLB maintenance
     *                 REG_SYSTIMER  a counter that advances on its own
     *                 REG_SYSPERF   counters that advance on events
     *                 REG_SYSDBG    debug/watch/trace
     *                 REG_SYSCACHE  cache tag/data and error state
     *                 REG_SYSID     read-only implementation constants
     *                               (MIPS PRId/Config, RISC-V vlenb).
     *                               A read of one of these depends on
     *                               nothing, so it must not sit with
     *                               writable state.
     *
     *   REG_COPROC<n>  an implementation-defined coprocessor register
     *               file (MIPS CP2, CP3).  The architecture assigns
     *               these no semantics, so there is nothing to group
     *               BY; one ID per coprocessor keeps them out of the
     *               CP0 classes, which is the defect that mattered.
     *
     *   REG_TLS     the thread pointer — AArch64 TPIDR_EL0 /
     *               TPIDRRO_EL0, the MIPS CP0 UserLocal word that
     *               `rdhwr $29` reads, and x86-64 FS.base.  A POINTER
     *               the guest computes addresses from rather than a
     *               status word, so the CP0 / MRS population is the
     *               wrong neighbourhood for it.  On RISC-V the thread
     *               pointer is `tp` (x4), an ordinary GPR, and needs
     *               nothing here.
     *
     *   REG_SSP     the shadow-stack pointer — RISC-V Zicfiss `ssp`
     *               and x86-64 CET's SSP.  Neither fold on offer is
     *               honest: onto REG_SP it serialises shadow-stack
     *               traffic against every spill, local and frame
     *               adjustment; onto REG_LR, `sspopchk ra` reads
     *               {ra, ssp} and writes {ssp}, so a two-source
     *               compare collapses into one source with a
     *               self-dependency — on the instruction whose entire
     *               purpose is comparing those two.
     *
     * 248-249 are deliberately unallocated.  They briefly held
     * REG_VSTART (RISC-V vector start), REG_DSPCTRL (MIPS DSPControl)
     * and REG_VCSR (RISC-V vcsr / MIPS MSACSR) — the third of those
     * three slots is the one REG_SSP now occupies.  The first two
     * named a register from exactly one ISA whose behaviour an
     * existing class already covered; the third split a
     * rounding-mode-and-status word away from REG_FCSR, which already
     * is one.  They now fold to REG_VCTRL, REG_FLAGS and REG_FCSR
     * respectively — folds onto the SAME behaviour, which is what
     * distinguishes them from the collisions above.  Left as holes
     * rather than reused so nothing renumbers.
     */
    REG_TLS = 246,
    REG_SSP = 247,
    /* Common architectural special registers: 250-254 */
    REG_SP = 250,
    REG_FLAGS = 251,
    REG_IP = 252,
    REG_LR = 253,
    REG_FP_REG = 254,
    /* Sentinel: one past the highest defined register ID.  Sized so a
     * dense bitmap or per-register array spans the full enum range
     * (0..REG_ID_COUNT-1).  Must remain <= 256 so the encoded ID
     * still fits in a uint8_t on the wire. */
    REG_ID_COUNT = 255,
};

/*
 * Symbolic name lookups.  Single source of truth per enum, used by
 * both the wire-format encoding-map writer and the stats printer.
 * Return NULL for unallocated IDs; use the *_or_unknown wrappers when
 * a non-NULL string is required. */
static inline const char *generic_opcode_name(unsigned id)
{
    switch (id) {
    case GEN_OP_UNKNOWN:    return "GEN_OP_UNKNOWN";
    case GEN_OP_INT_ADD:    return "GEN_OP_INT_ADD";
    case GEN_OP_INT_SUB:    return "GEN_OP_INT_SUB";
    case GEN_OP_INT_MUL:    return "GEN_OP_INT_MUL";
    case GEN_OP_INT_DIV:    return "GEN_OP_INT_DIV";
    case GEN_OP_AND:        return "GEN_OP_AND";
    case GEN_OP_OR:         return "GEN_OP_OR";
    case GEN_OP_XOR:        return "GEN_OP_XOR";
    case GEN_OP_NOT:        return "GEN_OP_NOT";
    case GEN_OP_SHL:        return "GEN_OP_SHL";
    case GEN_OP_SHR:        return "GEN_OP_SHR";
    case GEN_OP_ROL:        return "GEN_OP_ROL";
    case GEN_OP_ROR:        return "GEN_OP_ROR";
    case GEN_OP_BITMANIP:   return "GEN_OP_BITMANIP";
    case GEN_OP_MOV:        return "GEN_OP_MOV";
    case GEN_OP_LOAD:       return "GEN_OP_LOAD";
    case GEN_OP_STORE:      return "GEN_OP_STORE";
    case GEN_OP_PUSH:       return "GEN_OP_PUSH";
    case GEN_OP_POP:        return "GEN_OP_POP";
    case GEN_OP_LEA:        return "GEN_OP_LEA";
    case GEN_OP_MOVSX:      return "GEN_OP_MOVSX";
    case GEN_OP_MOVZX:      return "GEN_OP_MOVZX";
    case GEN_OP_XCHG:       return "GEN_OP_XCHG";
    case GEN_OP_CMP:        return "GEN_OP_CMP";
    case GEN_OP_TEST:       return "GEN_OP_TEST";
    case GEN_OP_BRANCH:     return "GEN_OP_BRANCH";
    case GEN_OP_RET:        return "GEN_OP_RET";
    case GEN_OP_FP_ADD:     return "GEN_OP_FP_ADD";
    case GEN_OP_FP_SUB:     return "GEN_OP_FP_SUB";
    case GEN_OP_FP_MUL:     return "GEN_OP_FP_MUL";
    case GEN_OP_FP_DIV:     return "GEN_OP_FP_DIV";
    case GEN_OP_FP_SQRT:    return "GEN_OP_FP_SQRT";
    case GEN_OP_FP_MOV:     return "GEN_OP_FP_MOV";
    case GEN_OP_FP_CVT:     return "GEN_OP_FP_CVT";
    case GEN_OP_FP_CMP:     return "GEN_OP_FP_CMP";
    case GEN_OP_VEC_ADD:    return "GEN_OP_VEC_ADD";
    case GEN_OP_VEC_SUB:    return "GEN_OP_VEC_SUB";
    case GEN_OP_VEC_MUL:    return "GEN_OP_VEC_MUL";
    case GEN_OP_VEC_DIV:    return "GEN_OP_VEC_DIV";
    case GEN_OP_VEC_SQRT:   return "GEN_OP_VEC_SQRT";
    case GEN_OP_VEC_MOV:    return "GEN_OP_VEC_MOV";
    case GEN_OP_VEC_LOAD:   return "GEN_OP_VEC_LOAD";
    case GEN_OP_VEC_STORE:  return "GEN_OP_VEC_STORE";
    case GEN_OP_VEC_SHUF:   return "GEN_OP_VEC_SHUF";
    case GEN_OP_VEC_LOGIC:  return "GEN_OP_VEC_LOGIC";
    case GEN_OP_NOP:        return "GEN_OP_NOP";
    case GEN_OP_SYSCALL:    return "GEN_OP_SYSCALL";
    case GEN_OP_FENCE:      return "GEN_OP_FENCE";
    case GEN_OP_CMOV:       return "GEN_OP_CMOV";
    case GEN_OP_SETCC:      return "GEN_OP_SETCC";
    case GEN_OP_NEG:        return "GEN_OP_NEG";
    case GEN_OP_INC:        return "GEN_OP_INC";
    case GEN_OP_DEC:        return "GEN_OP_DEC";
    case GEN_OP_INT_MADD:   return "GEN_OP_INT_MADD";
    case GEN_OP_INT_MSUB:   return "GEN_OP_INT_MSUB";
    case GEN_OP_FP_MADD:    return "GEN_OP_FP_MADD";
    case GEN_OP_FP_MSUB:    return "GEN_OP_FP_MSUB";
    case GEN_OP_VEC_MADD:   return "GEN_OP_VEC_MADD";
    case GEN_OP_VEC_MSUB:   return "GEN_OP_VEC_MSUB";
    case GEN_OP_PREFETCH:   return "GEN_OP_PREFETCH";
    case GEN_OP_CACHE_FLUSH: return "GEN_OP_CACHE_FLUSH";
    case GEN_OP_TLB_FLUSH:  return "GEN_OP_TLB_FLUSH";
    case GEN_OP_VEC_PREFETCH: return "GEN_OP_VEC_PREFETCH";
    case GEN_OP_INT_ALU_SHORT: return "GEN_OP_INT_ALU_SHORT";
    case GEN_OP_INT_ALU_LONG:  return "GEN_OP_INT_ALU_LONG";
    case GEN_OP_FP_ALU_SHORT:  return "GEN_OP_FP_ALU_SHORT";
    case GEN_OP_FP_ALU_LONG:   return "GEN_OP_FP_ALU_LONG";
    case GEN_OP_VEC_ALU_SHORT: return "GEN_OP_VEC_ALU_SHORT";
    case GEN_OP_VEC_ALU_LONG:  return "GEN_OP_VEC_ALU_LONG";
    default:                return NULL;
    }
}

static inline const char *generic_opcode_name_or_unknown(unsigned id)
{
    const char *n = generic_opcode_name(id);
    return n ? n : "GEN_OP_???";
}

static inline const char *branch_type_name(unsigned id)
{
    switch (id) {
    case BRANCH_NONE:           return "BRANCH_NONE";
    case BRANCH_DIRECT_JUMP:    return "BRANCH_DIRECT_JUMP";
    case BRANCH_INDIRECT_JUMP:  return "BRANCH_INDIRECT_JUMP";
    case BRANCH_RETURN:         return "BRANCH_RETURN";
    case BRANCH_SYSCALL_TYPE:   return "BRANCH_SYSCALL_TYPE";
    case BRANCH_COND_DIRECT:    return "BRANCH_COND_DIRECT";
    case BRANCH_REP:            return "BRANCH_REP";
    case BRANCH_DIRECT_CALL:    return "BRANCH_DIRECT_CALL";
    case BRANCH_INDIRECT_CALL:  return "BRANCH_INDIRECT_CALL";
    default:                    return NULL;
    }
}

static inline const char *branch_type_name_or_unknown(unsigned id)
{
    const char *n = branch_type_name(id);
    return n ? n : "BRANCH_???";
}

/*
 * Symbolic register name: a well-known special name or a class+index
 * name for the dense banks (REG_GPR<N>, REG_FPR<N>, REG_CTRL<N>,
 * ...).  NULL for any ID the enum does not allocate — the holes are
 * real and a caller that prints them is telling the truth about a
 * trace written by a different epoch of this table.  The dense-bank
 * result lives in a thread_local buffer; don't retain the pointer
 * past the next call.
 */
static inline const char *generic_reg_name(unsigned id)
{
    /* Specials with explicit IDs first. */
    switch (id) {
    case REG_NONE:    return "REG_NONE";
    case REG_ZERO:    return "REG_ZERO";
    case REG_MATRIX:  return "REG_MATRIX";
    case REG_SYS:      return "REG_SYS";
    case REG_SYSEXC:   return "REG_SYSEXC";
    case REG_SYSMMU:   return "REG_SYSMMU";
    case REG_SYSTIMER: return "REG_SYSTIMER";
    case REG_SYSPERF:  return "REG_SYSPERF";
    case REG_SYSDBG:   return "REG_SYSDBG";
    case REG_SYSCACHE: return "REG_SYSCACHE";
    case REG_SYSID:    return "REG_SYSID";
    case REG_COPROC0:  return "REG_COPROC0";
    case REG_COPROC1:  return "REG_COPROC1";
    case REG_FCSR:    return "REG_FCSR";
    case REG_VCTRL:   return "REG_VCTRL";
    case REG_TLS:     return "REG_TLS";
    case REG_SSP:     return "REG_SSP";
    case REG_SP:      return "REG_SP";
    case REG_FLAGS:   return "REG_FLAGS";
    case REG_IP:      return "REG_IP";
    case REG_LR:      return "REG_LR";
    case REG_FP_REG:  return "REG_FP_REG";
    default: break;
    }
    /* Dense bank ranges — index relative to bank base. */
    static __thread char buf[24];
    if (id >= REG_GPR0 && id < REG_GPR0 + 32) {
        snprintf(buf, sizeof(buf), "REG_GPR%u", id - REG_GPR0);
    } else if (id >= REG_CTRL0 && id < REG_CTRL0 + 16) {
        snprintf(buf, sizeof(buf), "REG_CTRL%u", id - REG_CTRL0);
    } else if (id >= REG_DEBUG0 && id < REG_DEBUG0 + 16) {
        snprintf(buf, sizeof(buf), "REG_DEBUG%u", id - REG_DEBUG0);
    } else if (id >= REG_FPR0 && id < REG_FPR0 + 32) {
        snprintf(buf, sizeof(buf), "REG_FPR%u", id - REG_FPR0);
    } else if (id >= REG_ACCHI0 && id < REG_ACCHI0 + 4) {
        snprintf(buf, sizeof(buf), "REG_ACCHI%u", id - REG_ACCHI0);
    } else if (id >= REG_VEC0 && id < REG_VEC0 + 64) {
        snprintf(buf, sizeof(buf), "REG_VEC%u", id - REG_VEC0);
    } else if (id >= REG_PRED0 && id < REG_PRED0 + 32) {
        snprintf(buf, sizeof(buf), "REG_PRED%u", id - REG_PRED0);
    } else if (id >= REG_SEG0 && id < REG_SEG0 + 6) {
        snprintf(buf, sizeof(buf), "REG_SEG%u", id - REG_SEG0);
    } else if (id >= REG_BOUND0 && id < REG_BOUND0 + 4) {
        snprintf(buf, sizeof(buf), "REG_BOUND%u", id - REG_BOUND0);
    } else if (id >= REG_ACC0 && id < REG_ACC0 + 4) {
        snprintf(buf, sizeof(buf), "REG_ACC%u", id - REG_ACC0);
    } else {
        return NULL;  /* unallocated ID */
    }
    return buf;
}

static inline const char *generic_reg_name_or_unknown(unsigned id)
{
    const char *n = generic_reg_name(id);
    if (n) return n;
    static __thread char buf[24];
    snprintf(buf, sizeof(buf), "REG_%u", id);
    return buf;
}
