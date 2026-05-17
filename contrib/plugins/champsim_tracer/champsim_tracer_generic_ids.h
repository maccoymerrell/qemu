/*
 * Wrong-Path Tracing Plugin — generic ID enums.
 *
 * Glib-free subset of champsim_tracer_mnemonics.h: just the
 * ISA-agnostic enum domains and their COUNT sentinels.  Carved out
 * so champsim_tracer_stats.h (a lightweight POD header) can size its
 * per-CP-execution attribution arrays in lockstep with the enums
 * without dragging mnemonics.h's glib dependency through every TU.
 *
 * mnemonics.h includes this header; both stay in lockstep.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <stdio.h>  /* snprintf in generic_reg_name */

/*
 * Canonical metaflags byte layout (v1.12+).  An ISA-agnostic subset
 * of arithmetic flags that trace-based simulation consumers care
 * about.  Carried in the wire format as a per-insn side-channel
 * record under CST_FID_METAFLAGS (not as a synthetic register
 * slot), populated by the encoder from the architectural REG_FLAGS
 * dst snap via isa_properties[trace_isa].flags_to_metaflags.  Bits
 * not populated by a given ISA stay zero (e.g. P is x86-only).
 * RISC-V and MIPS have no integer flags register and never emit
 * CST_FID_METAFLAGS records.
 *
 * One byte on the wire — the encoder treats it like any other
 * scalar field, so the delta stream compresses it.
 *
 * Defined here in the lightweight header so the per-ISA mnemonic
 * tables (C-only TU) can supply the bit-shuffle helper without
 * pulling in champsim_tracer.h's plugin / glib surface.
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
    /* Scalar bit-field / bit-count manipulation: BMI/BMI2 (BEXTR,
     * BLSI/BLSMSK/BLSR, BZHI, PDEP, PEXT), POPCNT, LZCNT/TZCNT,
     * BSF/BSR.  Distinct from the boolean GEN_OP_AND/OR/... class:
     * these rearrange/extract/count bits rather than apply a
     * bitwise boolean, and on real cores sit on a different port
     * with multi-cycle latency. */
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
    /* Vector load/store: the memory access is the defining behaviour
     * (no substantial ALU/compute op), but it moves a SIMD-width
     * value or uses a SIMD indexed (gather/scatter) addressing mode,
     * so it is worth distinguishing from scalar GEN_OP_LOAD/STORE.
     * Per the load/store-yield rule, any instruction doing real
     * compute is classified by that compute, not as VEC_LOAD/STORE. */
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
     * Memory-side hint / management instructions.  These do not
     * normally generate a TCG memop in QEMU (PREFETCHh, CLFLUSH,
     * INVLPG, AArch64 PRFM, RISC-V CBO, ...), but the tracer
     * synthesises a load memop slot carrying the effective address by
     * decoding the operand at translation time and reading base/index
     * register values at exec time.  Consumers may treat:
     *   GEN_OP_PREFETCH      — software prefetch hint (warm cache line)
     *   GEN_OP_CACHE_FLUSH   — explicit cache-line clean/flush/invalidate
     *   GEN_OP_TLB_FLUSH     — explicit TLB-entry invalidation
     *   GEN_OP_VEC_PREFETCH  — SIMD / gather-prefetch hint (one or
     *                          more SIMD-indexed cache-line warms)
     * The address (when present) is in the load-memop slot; opcode
     * carries the semantic distinction.
     */
    GEN_OP_PREFETCH = 59,
    GEN_OP_CACHE_FLUSH = 60,
    GEN_OP_TLB_FLUSH = 61,
    GEN_OP_VEC_PREFETCH = 62,
    /*
     * Coarse fallback latency buckets, reserved for external trace
     * writers that lack ISA-specific opcode metadata.  The in-tree
     * tracer never emits these IDs (every Capstone-classified insn
     * lands in one of the specific opcodes above), but consumer code
     * is encouraged to handle them so foreign traces remain
     * decodable.  SHORT vs LONG is a single-bit hint that the
     * upstream classifier knows the op's pipeline latency class:
     * SHORT is a single-cycle ALU op; LONG is anything that occupies
     * a long-latency unit (multi-cycle multiplier, divider, vector
     * pipe, etc.).
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
     * x86 REP / REPNZ self-loop terminator.  The instruction is a
     * conditional self-loop branch (target = self-PC, fall-through
     * = next PC); the tracer fans architectural iterations out into
     * per-iteration body entries on a 1-insn self-loop sub-template
     * (see champsim_tracer_format.md §"REP-prefixed self-loop BBs").
     * Consumer simulators that want to model REP as a hot loop
     * should distinguish this from BRANCH_COND_DIRECT so the
     * self-loop semantics (no predictor target diversity) are
     * obvious in the trace.
     */
    BRANCH_REP = 6,
    BRANCH_TYPE_COUNT,
};

/*
 * ISA-agnostic register IDs.
 * Consistent numbering across ISAs with reserved special register IDs.
 */
enum GenericRegId {
    REG_NONE = 0,
    /* General-purpose integer registers: 1-64 */
    REG_GPR0 = 1,
    REG_GPR1, REG_GPR2, REG_GPR3, REG_GPR4, REG_GPR5, REG_GPR6, REG_GPR7,
    REG_GPR8, REG_GPR9, REG_GPR10, REG_GPR11, REG_GPR12, REG_GPR13,
    REG_GPR14, REG_GPR15, REG_GPR16, REG_GPR17, REG_GPR18, REG_GPR19,
    REG_GPR20, REG_GPR21, REG_GPR22, REG_GPR23, REG_GPR24, REG_GPR25,
    REG_GPR26, REG_GPR27, REG_GPR28, REG_GPR29, REG_GPR30, REG_GPR31,
    REG_GPR32, REG_GPR33, REG_GPR34, REG_GPR35, REG_GPR36, REG_GPR37,
    REG_GPR38, REG_GPR39, REG_GPR40, REG_GPR41, REG_GPR42, REG_GPR43,
    REG_GPR44, REG_GPR45, REG_GPR46, REG_GPR47, REG_GPR48, REG_GPR49,
    REG_GPR50, REG_GPR51, REG_GPR52, REG_GPR53, REG_GPR54, REG_GPR55,
    REG_GPR56, REG_GPR57, REG_GPR58, REG_GPR59, REG_GPR60, REG_GPR61,
    REG_GPR62, REG_GPR63,
    /* Floating-point registers: 65-128 */
    REG_FPR0 = 65,
    REG_FPR1, REG_FPR2, REG_FPR3, REG_FPR4, REG_FPR5, REG_FPR6, REG_FPR7,
    REG_FPR8, REG_FPR9, REG_FPR10, REG_FPR11, REG_FPR12, REG_FPR13,
    REG_FPR14, REG_FPR15, REG_FPR16, REG_FPR17, REG_FPR18, REG_FPR19,
    REG_FPR20, REG_FPR21, REG_FPR22, REG_FPR23, REG_FPR24, REG_FPR25,
    REG_FPR26, REG_FPR27, REG_FPR28, REG_FPR29, REG_FPR30, REG_FPR31,
    REG_FPR32, REG_FPR33, REG_FPR34, REG_FPR35, REG_FPR36, REG_FPR37,
    REG_FPR38, REG_FPR39, REG_FPR40, REG_FPR41, REG_FPR42, REG_FPR43,
    REG_FPR44, REG_FPR45, REG_FPR46, REG_FPR47, REG_FPR48, REG_FPR49,
    REG_FPR50, REG_FPR51, REG_FPR52, REG_FPR53, REG_FPR54, REG_FPR55,
    REG_FPR56, REG_FPR57, REG_FPR58, REG_FPR59, REG_FPR60, REG_FPR61,
    REG_FPR62, REG_FPR63,
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
    /* Special-purpose hardware/value register classes: 225-245 */
    REG_SEG0 = 225,
    REG_SEG1, REG_SEG2, REG_SEG3, REG_SEG4, REG_SEG5,
    REG_CTRL = 231,
    REG_DEBUG = 232,
    REG_BOUND0 = 233,
    REG_BOUND1, REG_BOUND2, REG_BOUND3,
    REG_ACC0 = 237,
    REG_ACC1, REG_ACC2, REG_ACC3,
    REG_ZERO = 241,
    REG_MATRIX = 242,
    REG_SYS = 243,
    REG_FCSR = 244,
    REG_VCTRL = 245,
    /* 246..249 unallocated. */
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
 * Symbolic name lookups.  Inline helpers — both the output-side
 * encoding-map writer (wire format) and the exit-time stats printer
 * (human-facing) call these so names live in exactly one place per
 * enum.  Return NULL for unallocated IDs (reserved holes, future
 * codepoints).  Use the *_or_unknown wrappers below when callers
 * need a guaranteed non-NULL printable string. */
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
    default:                    return NULL;
    }
}

static inline const char *branch_type_name_or_unknown(unsigned id)
{
    const char *n = branch_type_name(id);
    return n ? n : "BRANCH_???";
}

/*
 * Symbolic register name.  Returns one of the well-known special-
 * purpose names (REG_SP, REG_FLAGS, REG_IP, REG_LR, REG_FP_REG,
 * REG_NONE, REG_ZERO, REG_MATRIX, REG_SYS, REG_FCSR, REG_VCTRL),
 * a class+index name for the dense banks (REG_GPR<N>, REG_FPR<N>,
 * REG_VEC<N>, REG_PRED<N>, REG_SEG<N>, REG_BOUND<N>, REG_ACC<N>),
 * or REG_CTRL/REG_DEBUG for those singletons.  Returns NULL for IDs
 * in the unallocated holes (246..249).  Result for the dense-bank
 * case lives in a thread_local buffer so callers must not retain
 * the pointer beyond the next call.
 */
static inline const char *generic_reg_name(unsigned id)
{
    /* Specials with explicit IDs first. */
    switch (id) {
    case REG_NONE:    return "REG_NONE";
    case REG_CTRL:    return "REG_CTRL";
    case REG_DEBUG:   return "REG_DEBUG";
    case REG_ZERO:    return "REG_ZERO";
    case REG_MATRIX:  return "REG_MATRIX";
    case REG_SYS:     return "REG_SYS";
    case REG_FCSR:    return "REG_FCSR";
    case REG_VCTRL:   return "REG_VCTRL";
    case REG_SP:      return "REG_SP";
    case REG_FLAGS:   return "REG_FLAGS";
    case REG_IP:      return "REG_IP";
    case REG_LR:      return "REG_LR";
    case REG_FP_REG:  return "REG_FP_REG";
    default: break;
    }
    /* Dense bank ranges — index relative to bank base. */
    static __thread char buf[24];
    if (id >= REG_GPR0 && id < REG_GPR0 + 64) {
        snprintf(buf, sizeof(buf), "REG_GPR%u", id - REG_GPR0);
    } else if (id >= REG_FPR0 && id < REG_FPR0 + 64) {
        snprintf(buf, sizeof(buf), "REG_FPR%u", id - REG_FPR0);
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
        return NULL;  /* unallocated hole (247..249) */
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
