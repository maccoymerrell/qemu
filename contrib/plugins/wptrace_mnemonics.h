/*
 * ISA-specific mnemonic tables for wptrace.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* ISA enum: add new ISAs here and extend isa_properties[] at end of file */
typedef enum {
    TRACE_ISA_UNKNOWN = 0,
    TRACE_ISA_X86     = 1,   /* x86_64 and i386 */
    TRACE_ISA_AARCH64 = 2,   /* AArch64 (ARMv8+) */
    TRACE_ISA_RISCV   = 3,   /* RISC-V (RV32/RV64) */
    TRACE_ISA_MIPS    = 4,   /* MIPS (mips/mips64/mipsel/mips64el) */
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
    GEN_OP_SHR = 10,
    GEN_OP_SAR = 11,
    GEN_OP_ROL = 12,
    GEN_OP_ROR = 13,
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
    GEN_OP_BRANCH = 25,
    GEN_OP_CALL = 26,
    GEN_OP_RET = 27,
    GEN_OP_FP_ADD = 28,
    GEN_OP_FP_SUB = 29,
    GEN_OP_FP_MUL = 30,
    GEN_OP_FP_DIV = 31,
    GEN_OP_FP_SQRT = 32,
    GEN_OP_FP_MOV = 33,
    GEN_OP_FP_CVT = 34,
    GEN_OP_FP_CMP = 35,
    GEN_OP_VEC_ADD = 36,
    GEN_OP_VEC_SUB = 37,
    GEN_OP_VEC_MUL = 38,
    GEN_OP_VEC_MOV = 39,
    GEN_OP_VEC_SHUF = 40,
    GEN_OP_VEC_LOGIC = 41,
    GEN_OP_NOP = 42,
    GEN_OP_SYSCALL = 43,
    GEN_OP_FENCE = 44,
    GEN_OP_CMOV = 45,
    GEN_OP_SETCC = 46,
    GEN_OP_INT_ADC = 47,
    GEN_OP_INT_SBB = 48,
    GEN_OP_NEG = 49,
    GEN_OP_INC = 50,
    GEN_OP_DEC = 51,
    GEN_OP_COUNT
};

/*
 * Branch type classification.
 */
enum BranchType {
    BRANCH_NONE = 0,
    BRANCH_DIRECT_JUMP = 1,
    BRANCH_INDIRECT_JUMP = 2,
    BRANCH_DIRECT_CALL = 3,
    BRANCH_INDIRECT_CALL = 4,
    BRANCH_RETURN = 5,
    BRANCH_SYSCALL_TYPE = 6,
    BRANCH_COND_DIRECT = 7,
    BRANCH_TYPE_COUNT,
};

enum GenericExceptionId {
    GEN_EXC_NONE = 0,
    GEN_EXC_UNKNOWN = 1,
    GEN_EXC_INT_DIVIDE_BY_ZERO = 2,
    GEN_EXC_FP_DIVIDE_BY_ZERO = 3,
    GEN_EXC_MEMORY_ACCESS = 4,
    GEN_EXC_COUNT,
};

enum WPStopReason {
    WP_STOP_NONE = 0,
    WP_STOP_SYSCALL_USERMODE = 1,
    WP_STOP_REASON_COUNT,
};

/*
 * Sync event types.
 * SYNC_THREAD_SWITCH is emitted into the body stream when execution moves
 * to a different vCPU.  SYNC_ATOMIC is a template-level hint on instructions
 * that perform atomic/locked memory operations; the trace consumer uses the
 * memory addresses of those operations to build a conflict graph for
 * inter-thread scheduling.
 *
 * Synchronisation detection is based entirely on atomics — no syscall
 * interception is used.  Every userspace synchronisation primitive ultimately
 * resolves to atomic memory operations on shared addresses.
 */
typedef enum {
    SYNC_NONE            = 0,   /* no sync (default for InsnFields.sync_hint) */
    SYNC_THREAD_SWITCH   = 4,   /* context switch: new cpu_index takes over */
    SYNC_ATOMIC          = 5,   /* atomic / locked memory operation */
} SyncEventType;

/*
 * (OperandCaptureKind removed — Capstone structured operand detail
 *  now provides operand type (REG/IMM/MEM) and access (READ/WRITE)
 *  directly, eliminating the need for per-instruction regex capture
 *  semantic tags.)
 */

/*
 * Mnemonic entry flags.
 *
 * Only flags whose semantics cannot be derived from Capstone detail
 * are retained.  Capstone now provides operand access (READ/WRITE),
 * implicit regs_read/regs_write, and group membership (CALL, RET,
 * JUMP, BRANCH_REL, INT) for all ISAs, so most of the original
 * per-instruction flag bits are no longer needed.
 */
enum MnemonicFlags {
    MF_NONE         = 0,
    MF_CONDITIONAL  = (1 << 0),  /* Branch/CMOV/SETcc is conditional        */
    MF_ATOMIC       = (1 << 1),  /* Atomic/locked memory op → SYNC_ATOMIC   */
};

/*
 * ISA-agnostic register IDs.
 * Consistent numbering across ISAs with reserved special register IDs.
 */
enum GenericRegId {
    REG_NONE = 0,
    /* General-purpose integer registers: 1-64 */
    REG_GPR0 = 1,
    REG_GPR1 = 2,
    REG_GPR2 = 3,
    REG_GPR3 = 4,
    REG_GPR4 = 5,
    REG_GPR5 = 6,
    REG_GPR6 = 7,
    REG_GPR7 = 8,
    REG_GPR8 = 9,
    REG_GPR9 = 10,
    REG_GPR10 = 11,
    REG_GPR11 = 12,
    REG_GPR12 = 13,
    REG_GPR13 = 14,
    REG_GPR14 = 15,
    REG_GPR15 = 16,
    REG_GPR16 = 17,
    REG_GPR17 = 18,
    REG_GPR18 = 19,
    REG_GPR19 = 20,
    REG_GPR20 = 21,
    REG_GPR21 = 22,
    REG_GPR22 = 23,
    REG_GPR23 = 24,
    REG_GPR24 = 25,
    REG_GPR25 = 26,
    REG_GPR26 = 27,
    REG_GPR27 = 28,
    REG_GPR28 = 29,
    REG_GPR29 = 30,
    REG_GPR30 = 31,
    REG_GPR31 = 32,
    /* GPR32-GPR63 follow sequentially (33-64) */
    /* Floating-point registers: 65-128 */
    REG_FPR0 = 65,
    REG_FPR1, REG_FPR2, REG_FPR3, REG_FPR4, REG_FPR5, REG_FPR6, REG_FPR7,
    REG_FPR8, REG_FPR9, REG_FPR10, REG_FPR11, REG_FPR12, REG_FPR13,
    REG_FPR14, REG_FPR15, REG_FPR16, REG_FPR17, REG_FPR18, REG_FPR19,
    REG_FPR20, REG_FPR21, REG_FPR22, REG_FPR23, REG_FPR24, REG_FPR25,
    REG_FPR26, REG_FPR27, REG_FPR28, REG_FPR29, REG_FPR30, REG_FPR31,
    /* Vector/SIMD registers: 129-192 */
    REG_VEC0 = 129,
    REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7,
    REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13,
    REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19,
    REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25,
    REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30, REG_VEC31,
    /* Special registers: 250-254 */
    REG_SP = 250,
    REG_FLAGS = 251,
    REG_IP = 252,
    REG_LR = 253,
    REG_FP_REG = 254,
};

/*
 * Register classification: maps a Capstone register ID directly to
 * GenericRegId via designated-initializer arrays indexed by the Capstone
 * enum value.  Eliminates all string-based register matching (hash tables,
 * regex, name parsing).
 */
typedef struct {
    uint8_t reg_id;   /* GenericRegId */
} RegClassification;


/*
 * Instruction classification entry: maps a Capstone insn_id directly
 * to GenericOpcode + BranchType + MnemonicFlags via designated-initializer
 * arrays indexed by the Capstone enum value.  Eliminates all string-based
 * mnemonic matching (hash tables, regex, prefix stripping, caches).
 */
typedef struct {
    uint8_t  opcode;      /* GenericOpcode */
    uint8_t  branch_type; /* BranchType */
    uint16_t flags;       /* MnemonicFlags */
} InsnClassification;


#include "wptrace_mnemonics_x86.h"
#include "wptrace_mnemonics_aarch64.h"
#include "wptrace_mnemonics_riscv.h"
#include "wptrace_mnemonics_mips.h"

/* Classification table selectors (indexed by TraceISA) */
static const RegClassification *const isa_reg_class[] = {
    [TRACE_ISA_UNKNOWN] = NULL,
    [TRACE_ISA_X86]     = x86_reg_class,
    [TRACE_ISA_AARCH64] = arm64_reg_class,
    [TRACE_ISA_RISCV]   = riscv_reg_class,
    [TRACE_ISA_MIPS]    = mips_reg_class,
};

static const unsigned isa_reg_class_size[] = {
    [TRACE_ISA_UNKNOWN] = 0,
    [TRACE_ISA_X86]     = X86_REG_ENDING,
    [TRACE_ISA_AARCH64] = ARM64_REG_ENDING,
    [TRACE_ISA_RISCV]   = RISCV_REG_ENDING,
    [TRACE_ISA_MIPS]    = MIPS_REG_ENDING,
};


/* Classification table selector (indexed by TraceISA) */
static const InsnClassification *const isa_insn_class[] = {
    [TRACE_ISA_UNKNOWN] = NULL,
    [TRACE_ISA_X86]     = x86_insn_class,
    [TRACE_ISA_AARCH64] = arm64_insn_class,
    [TRACE_ISA_RISCV]   = riscv_insn_class,
    [TRACE_ISA_MIPS]    = mips_insn_class,
};

static const unsigned isa_insn_class_size[] = {
    [TRACE_ISA_UNKNOWN] = 0,
    [TRACE_ISA_X86]     = X86_INS_ENDING,
    [TRACE_ISA_AARCH64] = ARM64_INS_ENDING,
    [TRACE_ISA_RISCV]   = RISCV_INS_ENDING,
    [TRACE_ISA_MIPS]    = MIPS_INS_ENDING,
};


/*
 * Static ISA property table.
 *
 * Concentrates every ISA-specific knob into one place so that adding a
 * new ISA requires only a new row rather than scattered switch arms.
 *
 *   branch_delay_slots   — number of delay-slot instructions after a branch
 *                          (0 for most ISAs, 1 for MIPS)
 */
typedef struct {
    uint8_t              branch_delay_slots;
} IsaProperties;

static const IsaProperties isa_properties[] = {
    [TRACE_ISA_UNKNOWN] = { 0 },
    [TRACE_ISA_X86]     = { 0 },
    [TRACE_ISA_AARCH64] = { 0 },
    [TRACE_ISA_RISCV]   = { 0 },
    [TRACE_ISA_MIPS]    = { 1 },
};

