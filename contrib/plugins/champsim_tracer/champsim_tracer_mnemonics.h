/*
 * ISA-specific mnemonic tables for champsim_tracer.
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
    /* 26 reserved: call-shaped control flow is GEN_OP_BRANCH. */
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
    GEN_OP_INT_MADD = 52,
    GEN_OP_INT_MSUB = 53,
    GEN_OP_FP_MADD = 54,
    GEN_OP_FP_MSUB = 55,
    GEN_OP_VEC_MADD = 56,
    GEN_OP_VEC_MSUB = 57,
    GEN_OP_COUNT
};

/*
 * Branch type classification.
 */
enum BranchType {
    BRANCH_NONE = 0,
    BRANCH_DIRECT_JUMP = 1,
    BRANCH_INDIRECT_JUMP = 2,
    BRANCH_RETURN = 3,
    BRANCH_SYSCALL_TYPE = 4,
    BRANCH_COND_DIRECT = 5,
    BRANCH_TYPE_COUNT,
};

/*
 * Sync event types.
 * Sparse BODY_TAG_THREAD_SWITCH records identify execution movement between
 * traced vCPUs.  SYNC_THREAD_SWITCH is retained as a named synchronization
 * hint value for consumers that materialize such movements as instruction
 * events.  SYNC_ATOMIC is a template-level hint on instructions that perform
 * atomic/locked memory operations; the trace consumer uses the memory
 * addresses of those operations to build a conflict graph for inter-thread
 * scheduling.
 *
 * Synchronisation detection is based entirely on atomics — no syscall
 * interception is used.  Every userspace synchronisation primitive ultimately
 * resolves to atomic memory operations on shared addresses.
 */
typedef enum {
    SYNC_NONE            = 0,   /* no sync (default for InsnFields.sync_hint) */
    SYNC_THREAD_SWITCH   = 4,   /* context switch marker */
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
 * implicit regs_read/regs_write, and group membership (RET,
 * JUMP, BRANCH_REL, INT) for all ISAs, so most of the original
 * per-instruction flag bits are no longer needed.
 */
enum MnemonicFlags {
    MF_NONE             = 0,
    MF_CONDITIONAL      = (1 << 0),  /* x86: direct branch may be conditional */
    MF_ATOMIC           = (1 << 1),  /* Atomic/locked memory op → SYNC_ATOMIC   */
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
    /* Common architectural special registers: 250-254 */
    REG_SP = 250,
    REG_FLAGS = 251,
    REG_IP = 252,
    REG_LR = 253,
    REG_FP_REG = 254,
};

/*
 * Register classification: maps a Capstone register ID to one generic ID,
 * or to a small alias list when Capstone uses one enum value for a register
 * group.  Tables are indexed directly by the Capstone enum value.  qemu_reg
 * is the QEMU plugin register descriptor key for register-value reads, or
 * { NULL, NULL } when the Capstone register has no single readable QEMU
 * register.
 */
#define MAX_REG_ALIASES 8

typedef struct {
    const char *feature;
    const char *name;
} QemuRegKey;

typedef struct {
    uint8_t reg_id;                    /* GenericRegId */
    uint8_t n_regs;                    /* non-zero for composite aliases */
    uint8_t regs[MAX_REG_ALIASES];     /* GenericRegId[] */
    QemuRegKey qemu_reg;               /* qemu_plugin_reg_descriptor key */
} RegClassification;

/*
 * Decoded per-instruction generic fields.
 *
 * Lives in this header (rather than champsim_tracer.h) so per-ISA
 * mnemonic refiners — compiled in the C tables TU — can read and
 * mutate fields directly without needing the rest of the tracer
 * internals.
 */
#define MAX_SRC_REGS 16
#define MAX_DST_REGS 16

typedef struct InsnFields {
    uint8_t opcode;                 /* GenericOpcode */
    uint8_t branch_type;            /* BranchType */
    bool    branch_conditional;
    uint8_t n_src_regs;
    uint8_t n_dst_regs;
    uint8_t src_regs[MAX_SRC_REGS];
    uint8_t dst_regs[MAX_DST_REGS];
    bool    has_immediate;
    int64_t immediate;
    uint8_t sync_hint;              /* SyncEventType */
    uint8_t n_loads;                /* Template default; runtime uses QEMU mem callbacks */
    uint8_t n_stores;               /* Template default; runtime uses QEMU mem callbacks */
} InsnFields;


/*
 * Optional post-classification refiner.
 *
 * Some Capstone insn_ids cover several distinct semantics that only
 * differ in operand encoding (e.g. RISC-V JALR is "indirect branch",
 * "indirect jump", or "ret" depending on rd/rs1).  A row may set
 * .refine to a function that fixes up the decoded InsnFields after
 * the generic operand-walk has populated src_regs/dst_regs/etc.
 *
 * The refiner is ISA-local: it is defined in the per-ISA mnemonic
 * table file and never referenced from the ISA-agnostic decoder.
 */
struct qemu_plugin_insn_info; /* fwd-decl: full type from <qemu-plugin.h> */
typedef void (*InsnRefineFn)(const struct qemu_plugin_insn_info *info,
                             InsnFields *fields);

/*
 * Instruction classification entry: maps a Capstone insn_id directly
 * to GenericOpcode + BranchType + MnemonicFlags via designated-initializer
 * arrays indexed by the Capstone enum value.  Eliminates all string-based
 * mnemonic matching (hash tables, regex, prefix stripping, caches).
 *
 * `.refine` is optional (NULL by default); see InsnRefineFn above.
 */
typedef struct {
    uint8_t      opcode;      /* GenericOpcode */
    uint8_t      branch_type; /* BranchType */
    uint16_t     flags;       /* MnemonicFlags */
    InsnRefineFn refine;      /* optional, NULL if unused */
} InsnClassification;


#ifdef CHAMPSIM_MNEMONIC_TABLES_IMPL

#include "champsim_tracer_mnemonics_x86.h"
#include "champsim_tracer_mnemonics_aarch64.h"
#include "champsim_tracer_mnemonics_riscv.h"
#include "champsim_tracer_mnemonics_mips.h"

/* Classification table selectors (indexed by TraceISA) */
const RegClassification *const isa_reg_class[] = {
    [TRACE_ISA_UNKNOWN] = NULL,
    [TRACE_ISA_X86]     = x86_reg_class,
    [TRACE_ISA_AARCH64] = aarch64_reg_class,
    [TRACE_ISA_RISCV]   = riscv_reg_class,
    [TRACE_ISA_MIPS]    = mips_reg_class,
};

const unsigned isa_reg_class_size[] = {
    [TRACE_ISA_UNKNOWN] = 0,
    [TRACE_ISA_X86]     = X86_REG_ENDING,
    [TRACE_ISA_AARCH64] = AARCH64_REG_ENDING,
    [TRACE_ISA_RISCV]   = RISCV_REG_ENDING,
    [TRACE_ISA_MIPS]    = MIPS_REG_ENDING,
};

/* Classification table selector (indexed by TraceISA) */
const InsnClassification *const isa_insn_class[] = {
    [TRACE_ISA_UNKNOWN] = NULL,
    [TRACE_ISA_X86]     = x86_insn_class,
    [TRACE_ISA_AARCH64] = aarch64_insn_class,
    [TRACE_ISA_RISCV]   = riscv_insn_class,
    [TRACE_ISA_MIPS]    = mips_insn_class,
};

const unsigned isa_insn_class_size[] = {
    [TRACE_ISA_UNKNOWN] = 0,
    [TRACE_ISA_X86]     = X86_INS_ENDING,
    [TRACE_ISA_AARCH64] = AARCH64_INS_ENDING,
    [TRACE_ISA_RISCV]   = RISCV_INS_ENDING,
    [TRACE_ISA_MIPS]    = MIPS_INS_ENDING,
};

#else /* CHAMPSIM_MNEMONIC_TABLES_IMPL */

#ifdef __cplusplus
extern "C" {
#endif

extern const RegClassification *const isa_reg_class[TRACE_ISA_MIPS + 1];
extern const unsigned isa_reg_class_size[TRACE_ISA_MIPS + 1];
extern const InsnClassification *const isa_insn_class[TRACE_ISA_MIPS + 1];
extern const unsigned isa_insn_class_size[TRACE_ISA_MIPS + 1];

#ifdef __cplusplus
}
#endif

#endif /* CHAMPSIM_MNEMONIC_TABLES_IMPL */


/*
 * Static ISA property table.
 *
 * Concentrates every ISA-specific knob into one place so that adding a
 * new ISA requires only a new row rather than scattered switch arms.
 *
 *   branch_delay_slots       — number of delay-slot instructions after a
 *                              branch (0 for most ISAs, 1 for MIPS)
 *   pc_relative_branch_imm   — true if Capstone reports the immediate of
 *                              direct branches as a *relative* offset
 *                              from the branch PC (RISC-V, MIPS).  False
 *                              if Capstone resolves it to an absolute
 *                              target (x86, ARM64).  decode_detail_to_
 *                              generic() normalizes the field so
 *                              InsnFields.immediate is always the
 *                              absolute target on the wire.
 *   target_prefixes          — NULL-terminated list of QEMU target_name
 *                              prefixes that map to this ISA
 *   cap_arch                 — Capstone cs_arch enum value (CS_ARCH_*),
 *                              or -1 if unsupported
 *   cap_mode_for_target      — derives a Capstone cs_mode bitmask
 *                              (CS_MODE_*) from target_name (handles e.g.
 *                              RISC-V 32/64 split, MIPS endianness)
 */
typedef unsigned int (*CapModeForTargetFn)(const char *target_name);

typedef struct {
    uint8_t               branch_delay_slots;
    bool                  pc_relative_branch_imm;
    const char *const    *target_prefixes;
    int                   cap_arch;
    CapModeForTargetFn    cap_mode_for_target;
} IsaProperties;

#ifdef CHAMPSIM_MNEMONIC_TABLES_IMPL

static const char *const isa_prefixes_x86[]     = { "x86_64", "i386", NULL };
static const char *const isa_prefixes_aarch64[] = { "aarch64", NULL };
static const char *const isa_prefixes_riscv[]   = { "riscv64", "riscv32", NULL };
static const char *const isa_prefixes_mips[]    = { "mips64el", "mips64",
                                                    "mipsel", "mips", NULL };

const IsaProperties isa_properties[] = {
    [TRACE_ISA_UNKNOWN] = { 0 },
    [TRACE_ISA_X86]     = {
        .target_prefixes = isa_prefixes_x86,
        .cap_arch = CS_ARCH_X86,
        .cap_mode_for_target = cap_mode_x86,
    },
    [TRACE_ISA_AARCH64] = {
        .target_prefixes = isa_prefixes_aarch64,
        .cap_arch = CS_ARCH_AARCH64,
        .cap_mode_for_target = cap_mode_aarch64,
    },
    [TRACE_ISA_RISCV]   = {
        .target_prefixes = isa_prefixes_riscv,
        .cap_arch = CS_ARCH_RISCV,
        .cap_mode_for_target = cap_mode_riscv,
    },
    [TRACE_ISA_MIPS]    = {
        .branch_delay_slots = 1,
        .target_prefixes = isa_prefixes_mips,
        .cap_arch = CS_ARCH_MIPS,
        .cap_mode_for_target = cap_mode_mips,
    },
};

#else /* CHAMPSIM_MNEMONIC_TABLES_IMPL */

#ifdef __cplusplus
extern "C" {
#endif

extern const IsaProperties isa_properties[TRACE_ISA_MIPS + 1];

#ifdef __cplusplus
}
#endif

#endif /* CHAMPSIM_MNEMONIC_TABLES_IMPL */

