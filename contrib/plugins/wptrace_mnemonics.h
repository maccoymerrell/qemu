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
 * Regex capture semantic tags. Each regex capture group is assigned one
 * meaning in MnemonicEntry.capture_kinds.
 */
enum OperandCaptureKind {
    CAP_NONE = 0,
    CAP_SRC_REG,
    CAP_DST_REG,
    CAP_RW_REG,
    CAP_SRC_MEM,
    CAP_DST_MEM,
    CAP_MEM_ADDR,
    CAP_SRC_REG_OR_MEM,
    CAP_DST_REG_OR_MEM,
    CAP_RW_REG_OR_MEM,
    CAP_IMM,
    CAP_BRANCH_TARGET,
};

/*
 * Mnemonic entry flags.
 *
 * Each bit encodes an implicit property of the instruction so that all
 * instruction semantics are table-driven.  The operand-parsing code
 * applies these flags generically after capture-group processing,
 * eliminating per-opcode special-case logic.
 */
enum MnemonicFlags {
    MF_NONE         = 0,
    MF_CONDITIONAL  = (1 << 0),  /* Branch/CMOV/SETcc is conditional            */
    MF_FLAGS_DST    = (1 << 1),  /* Implicitly writes FLAGS / condition codes    */
    MF_FLAGS_SRC    = (1 << 2),  /* Implicitly reads  FLAGS / condition codes    */
    MF_SP_RW        = (1 << 3),  /* Implicitly reads+writes stack pointer (SP)   */
    MF_LR_DST       = (1 << 4),  /* Implicitly writes link register (LR / RA)   */
    MF_LR_SRC       = (1 << 5),  /* Implicitly reads  link register (LR / RA)   */
    MF_IP_DST       = (1 << 6),  /* Implicitly writes instruction pointer (IP)  */
    MF_MOV_PROMOTE  = (1 << 7),  /* Promote MOV→LOAD/STORE based on mem operand */
    MF_CHK_INDIRECT = (1 << 8),  /* Check for indirect branch/call (x86 '*')    */
    MF_CHK_LR_RET   = (1 << 9),  /* If target reg == LR treat as RET            */
    MF_ATOMIC        = (1 << 10), /* Atomic/locked memory op → SYNC_ATOMIC hint  */
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
    /* FPR1-FPR63 follow sequentially (66-128) */
    /* Vector/SIMD registers: 129-192 */
    REG_VEC0 = 129,
    /* VEC1-VEC63 follow sequentially (130-192) */
    /* Special registers: 250-254 */
    REG_SP = 250,
    REG_FLAGS = 251,
    REG_IP = 252,
    REG_LR = 253,
    REG_FP_REG = 254,
};

/*
 * Register name → GenericRegId mapping entry.
 *
 * Supports both exact-match and regex-fallback lookup, mirroring the
 * mnemonic lookup pattern:
 *   - Exact entries (name != NULL) go into a hash table for O(1) lookup.
 *   - Regex entries (reg_re != NULL) are compiled at init and tried in
 *     order when the hash table misses.  The first capture group is
 *     parsed as an integer and the result is:
 *         reg_id + captured_number + re_adj
 */
typedef struct {
    const char *name;       /* exact register name, or NULL for regex-only  */
    const char *reg_re;     /* regex pattern, or NULL for exact-only        */
    uint8_t     reg_id;     /* register ID (exact) or base ID (regex)       */
    int8_t      re_adj;     /* adjustment added to capture group for regex  */
} RegEntry;

/* Helper macros for building register tables */
#define REG(n, id)             { .name = (n), .reg_re = NULL, \
                                 .reg_id = (id), .re_adj = 0 }
#define REG_RE(re, base, adj)  { .name = NULL, .reg_re = (re), \
                                 .reg_id = (base), .re_adj = (adj) }
#define REG_END                { .name = NULL, .reg_re = NULL, \
                                 .reg_id = REG_NONE, .re_adj = 0 }

/*
 * x86 register table: exact entries for standard GPR/special names,
 * regex entries for extended GPRs (r8-r15), SIMD, and x87.
 */
static const RegEntry x86_reg_entries[] = {
    /* 64-bit GPRs */
    REG("rax", REG_GPR0), REG("rcx", REG_GPR1), REG("rdx", REG_GPR2),
    REG("rbx", REG_GPR3), REG("rsp", REG_SP),   REG("rbp", REG_FP_REG),
    REG("rsi", REG_GPR4), REG("rdi", REG_GPR5),
    /* 32-bit GPRs */
    REG("eax", REG_GPR0), REG("ecx", REG_GPR1), REG("edx", REG_GPR2),
    REG("ebx", REG_GPR3), REG("esp", REG_SP),   REG("ebp", REG_FP_REG),
    REG("esi", REG_GPR4), REG("edi", REG_GPR5),
    /* 16-bit GPRs */
    REG("ax", REG_GPR0), REG("cx", REG_GPR1), REG("dx", REG_GPR2),
    REG("bx", REG_GPR3), REG("sp", REG_SP),   REG("bp", REG_FP_REG),
    REG("si", REG_GPR4), REG("di", REG_GPR5),
    /* 8-bit GPRs */
    REG("al", REG_GPR0), REG("ah", REG_GPR0),
    REG("cl", REG_GPR1), REG("ch", REG_GPR1),
    REG("dl", REG_GPR2), REG("dh", REG_GPR2),
    REG("bl", REG_GPR3), REG("bh", REG_GPR3),
    REG("spl", REG_SP),  REG("bpl", REG_FP_REG),
    REG("sil", REG_GPR4), REG("dil", REG_GPR5),
    /* Special registers */
    REG("rip", REG_IP), REG("eip", REG_IP),
    REG("rflags", REG_FLAGS), REG("eflags", REG_FLAGS),
    REG("st", REG_FPR0),
    /* Extended GPRs r8-r15 (with optional b/w/d suffix) */
    REG_RE("^r((?:8|9|1[0-5]))[bwd]?$", REG_GPR0, -2),
    /* XMM/YMM/ZMM vector registers */
    REG_RE("^[xyz]mm(\\d+)$", REG_VEC0, 0),
    /* MMX registers */
    REG_RE("^mm(\\d+)$", REG_VEC0, 0),
    REG_END
};

/*
 * AArch64 register table: exact entries for special names,
 * regex entries for numbered x/w GPRs and v/d/s/q/h/b vector aliases.
 */
static const RegEntry aarch64_reg_entries[] = {
    REG("xzr", REG_NONE), REG("wzr", REG_NONE),
    REG("sp", REG_SP), REG("lr", REG_LR), REG("fp", REG_FP_REG),
    /* x0-x30, w0-w30 → GPR0+n */
    REG_RE("^[xw](\\d+)$", REG_GPR0, 0),
    /* v/d/s/q/h/b 0-31 → VEC0+n */
    REG_RE("^[vdsqhb](\\d+)$", REG_VEC0, 0),
    REG_END
};

/*
 * RISC-V register table: exact entries for special names,
 * regex entries for ABI (t/s/a) and raw (x/f) register forms.
 * Order matters: more specific patterns (ft, fs, fa) before generic (f).
 */
static const RegEntry riscv_reg_entries[] = {
    REG("zero", REG_NONE),
    REG("ra", REG_LR), REG("sp", REG_SP), REG("gp", REG_GPR3),
    REG("tp", REG_GPR4), REG("fp", REG_FP_REG),
    REG("x0", REG_NONE), REG("x1", REG_LR), REG("x2", REG_SP),
    REG("x8", REG_FP_REG), REG("s0", REG_FP_REG), REG("s1", REG_GPR9),
    /* GPR ranges */
    REG_RE("^t([0-2])$",  REG_GPR5,  0),     /* t0-2  → GPR5-7   */
    REG_RE("^t([3-6])$",  REG_GPR28, -3),    /* t3-6  → GPR28-31 */
    REG_RE("^s(\\d+)$",   REG_GPR18, -2),    /* s2-11 → GPR18-27 */
    REG_RE("^a([0-7])$",  REG_GPR10, 0),     /* a0-7  → GPR10-17 */
    REG_RE("^x(\\d+)$",   REG_GPR0,  0),     /* x3-31 → GPR3-31  */
    /* FPR ranges (specific before generic) */
    REG_RE("^ft([0-7])$", REG_FPR0,      0), /* ft0-7  → FPR0-7   */
    REG_RE("^ft(\\d+)$",  REG_FPR0,     20), /* ft8-11 → FPR28-31 */
    REG_RE("^fs([01])$",  REG_FPR0 + 8,  0), /* fs0-1  → FPR8-9   */
    REG_RE("^fs(\\d+)$",  REG_FPR0 + 18,-2), /* fs2-11 → FPR18-27 */
    REG_RE("^fa([0-7])$", REG_FPR0 + 10, 0), /* fa0-7  → FPR10-17 */
    REG_RE("^f(\\d+)$",   REG_FPR0,      0), /* f0-31  → FPR0-31  */
    REG_END
};

/*
 * MIPS register table: exact entries for special names,
 * regex entries for ABI (v/a/t/s/k) and numeric register forms.
 * Register names may have an optional $ prefix (stripped before lookup).
 */
static const RegEntry mips_reg_entries[] = {
    REG("zero", REG_NONE), REG("0", REG_NONE),
    REG("at", REG_GPR1), REG("sp", REG_SP), REG("fp", REG_FP_REG),
    REG("ra", REG_LR), REG("gp", REG_GPR28),
    REG("s8", REG_FP_REG),
    REG("29", REG_SP), REG("30", REG_FP_REG), REG("31", REG_LR),
    /* GPR ranges */
    REG_RE("^v([01])$",   REG_GPR2,  0),     /* v0-1  → GPR2-3   */
    REG_RE("^a([0-7])$",  REG_GPR4,  0),     /* a0-7  → GPR4-11  */
    REG_RE("^t([0-7])$",  REG_GPR8,  0),     /* t0-7  → GPR8-15  */
    REG_RE("^t([89])$",   REG_GPR24, -8),    /* t8-9  → GPR24-25 */
    REG_RE("^s([0-7])$",  REG_GPR16, 0),     /* s0-7  → GPR16-23 */
    REG_RE("^k([01])$",   REG_GPR26, 0),     /* k0-1  → GPR26-27 */
    REG_RE("^(\\d+)$",    REG_GPR0,  0),     /* $1-28 → GPR1-28  */
    /* FPR ranges */
    REG_RE("^f(\\d+)$",   REG_FPR0,  0),     /* f0-31 → FPR0-31  */
    REG_END
};

/* Mnemonic-to-opcode lookup table entry */
typedef struct {
    /*
     * Exact mnemonic string for O(1) hash-table lookup.
     * NULL when this entry uses mnem_re instead (pattern fallback).
     */
    const char *name;
    /*
     * POSIX-extended regex matching the mnemonic.
     * Used only when name == NULL; tried in array order after hash miss.
     * NULL when this entry uses exact name matching.
     */
    const char *mnem_re;
    uint8_t opcode;
    uint8_t branch_type;
    uint16_t flags;             /* MnemonicFlags bitfield */
    /* Regex used to capture operand fields (groups 1..4). */
    const char *operand_regex;
    uint8_t capture_kinds[4];
    /*
     * Per-instruction implicit register operands (GenericRegId).
     * These supplement capture_kinds for registers used/defined
     * by the instruction but not present in the Capstone disassembly text.
     * Example: x86 div implicitly reads/writes RAX and RDX.
     */
    uint8_t implicit_src_regs[2];
    uint8_t implicit_dst_regs[2];
} MnemonicEntry;

/*
 * Convenience macros for table entries.
 *
 * MNEM(name, op, br, fl, re, c0, c1, c2, c3)   – exact-match entry
 * MNEM_RE(pat, op, br, fl, re, c0, c1, c2, c3)  – regex-pattern entry
 * MNEM_END                                        – sentinel
 *
 * Common flag combinations:
 *   F_ALU     – ALU op that writes FLAGS
 *   F_CMP     – compare that writes FLAGS
 *   F_COND    – conditional on FLAGS (cmov, setcc, j<cc>)
 *   F_CALL    – call (SP r/w + IP dst + LR dst)
 *   F_RET     – return (SP r/w + IP dst + LR src)
 *   F_PUSH    – push (SP r/w)
 *   F_BRANCH  – unconditional branch (check-indirect)
 *   F_CBRANCH – conditional branch (check-indirect + conditional + flags-src)
 */
#define F_ALU       (MF_FLAGS_DST)
#define F_CMP       (MF_FLAGS_DST)
#define F_COND      (MF_CONDITIONAL | MF_FLAGS_SRC)
#define F_CALL_X86  (MF_CHK_INDIRECT | MF_SP_RW | MF_IP_DST)
#define F_RET_X86   (MF_SP_RW | MF_IP_DST)
#define F_CALL_RISC (MF_LR_DST)
#define F_RET_RISC  (MF_LR_SRC)
#define F_PUSH      (MF_SP_RW)
#define F_BRANCH    (MF_CHK_INDIRECT)
#define F_CBRANCH   (MF_CONDITIONAL | MF_FLAGS_SRC)

/* Shorthand pairs for implicit_src_regs / implicit_dst_regs fields */
#define I_NONE      REG_NONE, REG_NONE
#define I_AX        REG_GPR0, REG_NONE        /* {RAX}           */
#define I_AX_DX     REG_GPR0, REG_GPR2        /* {RAX, RDX}      */
#define I_AX_DI     REG_GPR0, REG_GPR5        /* {RAX, RDI}      */
#define I_DI        REG_GPR5, REG_NONE        /* {RDI}           */
#define I_AX_CX     REG_GPR0, REG_GPR1        /* {RAX, RCX}      */
#define I_CX        REG_GPR1, REG_NONE        /* {RCX}           */

#define MNEM(n, op, br, fl, re, c0, c1, c2, c3)  \
    { (n), NULL, (op), (br), (fl), (re), { (c0), (c1), (c2), (c3) }, \
      { I_NONE }, { I_NONE } }

#define MNEM_I(n, op, br, fl, re, c0, c1, c2, c3, IS, ID)  \
    { (n), NULL, (op), (br), (fl), (re), { (c0), (c1), (c2), (c3) }, \
      { IS }, { ID } }

#define MNEM_RE(pat, op, br, fl, re, c0, c1, c2, c3)  \
    { NULL, (pat), (op), (br), (fl), (re), { (c0), (c1), (c2), (c3) }, \
      { I_NONE }, { I_NONE } }

#define MNEM_RE_I(pat, op, br, fl, re, c0, c1, c2, c3, IS, ID)  \
    { NULL, (pat), (op), (br), (fl), (re), { (c0), (c1), (c2), (c3) }, \
      { IS }, { ID } }

#define MNEM_END  \
    { NULL, NULL, 0, 0, MF_NONE, WPT_OP_RE_STD, \
      { CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE }, { I_NONE }, { I_NONE } }

/*
 * Standard operand capture regex supporting commas inside one [] or () group.
 * Captures up to 4 top-level operands as groups 1..4.
 */
#define WPT_OP_RE_STD \
    "^\\s*((?:\\[[^\\]]*\\]|\\([^\\)]*\\)|[^,])+?)\\s*" \
    "(?:,\\s*((?:\\[[^\\]]*\\]|\\([^\\)]*\\)|[^,])+?)\\s*)?" \
    "(?:,\\s*((?:\\[[^\\]]*\\]|\\([^\\)]*\\)|[^,])+?)\\s*)?" \
    "(?:,\\s*((?:\\[[^\\]]*\\]|\\([^\\)]*\\)|[^,])+?)\\s*)?$"

/* x86 mnemonic table (exact matches + regex fallback patterns) */
static const MnemonicEntry x86_mnemonic_table[] = {
    /* Integer ALU */
    MNEM("add",  GEN_OP_INT_ADD, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("adc",  GEN_OP_INT_ADC, BRANCH_NONE, F_ALU|MF_FLAGS_SRC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sub",  GEN_OP_INT_SUB, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sbb",  GEN_OP_INT_SBB, BRANCH_NONE, F_ALU|MF_FLAGS_SRC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM_I("imul", GEN_OP_INT_MUL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, I_AX, I_AX_DX),
    MNEM_I("mul",  GEN_OP_INT_MUL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX, I_AX_DX),
    MNEM_I("idiv", GEN_OP_INT_DIV, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_DX, I_AX_DX),
    MNEM_I("div",  GEN_OP_INT_DIV, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_DX, I_AX_DX),
    MNEM("and",  GEN_OP_AND, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("or",   GEN_OP_OR,  BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("xor",  GEN_OP_XOR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("not",  GEN_OP_NOT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("neg",  GEN_OP_NEG, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("inc",  GEN_OP_INC, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("dec",  GEN_OP_DEC, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    /* Shifts/rotates */
    MNEM("shl", GEN_OP_SHL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sal", GEN_OP_SHL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("shr", GEN_OP_SHR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sar", GEN_OP_SAR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("rol", GEN_OP_ROL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("ror", GEN_OP_ROR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    /* Data movement */
    MNEM("mov",   GEN_OP_MOV, BRANCH_NONE, MF_MOV_PROMOTE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("lea",   GEN_OP_LEA, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_MEM_ADDR, CAP_DST_REG, CAP_NONE, CAP_NONE),
    MNEM("push",  GEN_OP_PUSH, BRANCH_NONE, F_PUSH, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("pop",   GEN_OP_POP,  BRANCH_NONE, F_PUSH, WPT_OP_RE_STD, CAP_DST_REG, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("xchg",  GEN_OP_XCHG, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    /* Sign/zero extend */
    MNEM("movsx",  GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movsxd", GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movsl",  GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movsbw", GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movsbl", GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movswl", GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movsbq", GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movswq", GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movslq", GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movzx",  GEN_OP_MOVZX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movzb",  GEN_OP_MOVZX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movzbw", GEN_OP_MOVZX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movzbl", GEN_OP_MOVZX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movzwl", GEN_OP_MOVZX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movzbq", GEN_OP_MOVZX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movzwq", GEN_OP_MOVZX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("cltq",   GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("cqto",   GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("cwtl",   GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("cdqe",   GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("cbw",    GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("cwde",   GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("cdq",    GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("cqo",    GEN_OP_MOVSX, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    /* Comparison */
    MNEM("cmp",  GEN_OP_CMP,  BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("test", GEN_OP_TEST, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    /* Control flow */
    MNEM("jmp",      GEN_OP_BRANCH, BRANCH_DIRECT_JUMP,  F_BRANCH, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("call",     GEN_OP_CALL,   BRANCH_DIRECT_CALL,  F_CALL_X86, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("ret",      GEN_OP_RET,    BRANCH_RETURN, F_RET_X86, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("nop",      GEN_OP_NOP,    BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("syscall",  GEN_OP_SYSCALL, BRANCH_SYSCALL_TYPE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("sysenter", GEN_OP_SYSCALL, BRANCH_SYSCALL_TYPE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("int",      GEN_OP_SYSCALL, BRANCH_SYSCALL_TYPE, MF_NONE, WPT_OP_RE_STD, CAP_IMM, CAP_NONE, CAP_NONE, CAP_NONE),
    /* Fences */
    MNEM("mfence", GEN_OP_FENCE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("lfence", GEN_OP_FENCE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("sfence", GEN_OP_FENCE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    /* Scalar FP */
    MNEM("addss",   GEN_OP_FP_ADD,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("addsd",   GEN_OP_FP_ADD,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("addps",   GEN_OP_FP_ADD,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("addpd",   GEN_OP_FP_ADD,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("subss",   GEN_OP_FP_SUB,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("subsd",   GEN_OP_FP_SUB,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("subps",   GEN_OP_FP_SUB,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("subpd",   GEN_OP_FP_SUB,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("mulss",   GEN_OP_FP_MUL,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("mulsd",   GEN_OP_FP_MUL,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("mulps",   GEN_OP_FP_MUL,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("mulpd",   GEN_OP_FP_MUL,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("divss",   GEN_OP_FP_DIV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("divsd",   GEN_OP_FP_DIV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("divps",   GEN_OP_FP_DIV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("divpd",   GEN_OP_FP_DIV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sqrtss",  GEN_OP_FP_SQRT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sqrtsd",  GEN_OP_FP_SQRT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sqrtps",  GEN_OP_FP_SQRT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sqrtpd",  GEN_OP_FP_SQRT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movss",   GEN_OP_FP_MOV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movsd",   GEN_OP_FP_MOV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("ucomiss", GEN_OP_FP_CMP,  BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("ucomisd", GEN_OP_FP_CMP,  BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("comiss",  GEN_OP_FP_CMP,  BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("comisd",  GEN_OP_FP_CMP,  BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    /* x87 FP */
    MNEM("fld",    GEN_OP_FP_MOV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("fld1",   GEN_OP_FP_MOV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("fldz",   GEN_OP_FP_MOV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("fldcw",  GEN_OP_FP_MOV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("fst",    GEN_OP_FP_MOV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("fstp",   GEN_OP_FP_MOV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("fnstcw", GEN_OP_STORE,   BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG, CAP_DST_MEM, CAP_NONE, CAP_NONE),
    MNEM("fsubr",  GEN_OP_FP_SUB,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("fdivr",  GEN_OP_FP_DIV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("fdivp",  GEN_OP_FP_DIV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("fdivrp", GEN_OP_FP_DIV,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("wait",   GEN_OP_FENCE,   BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("fwait",  GEN_OP_FENCE,   BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    /* Vector mov */
    MNEM("movaps",  GEN_OP_VEC_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movapd",  GEN_OP_VEC_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movups",  GEN_OP_VEC_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movupd",  GEN_OP_VEC_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movdqa",  GEN_OP_VEC_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movdqu",  GEN_OP_VEC_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movd",    GEN_OP_VEC_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movq",    GEN_OP_VEC_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("vmovd",   GEN_OP_VEC_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("vmovq",   GEN_OP_VEC_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("vmovdqa", GEN_OP_VEC_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("vmovdqu", GEN_OP_VEC_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("stmxcsr", GEN_OP_STORE,   BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG, CAP_DST_MEM, CAP_NONE, CAP_NONE),
    MNEM("ldmxcsr", GEN_OP_LOAD,    BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_MEM, CAP_DST_REG, CAP_NONE, CAP_NONE),
    /* Vector logic */
    MNEM("andps",  GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("andpd",  GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("orps",   GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("orpd",   GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("xorps",  GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("xorpd",  GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("andnps", GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("andnpd", GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("pand",   GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("pandn",  GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("por",    GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("pxor",   GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    /* Vector shuffle */
    MNEM("shufps", GEN_OP_VEC_SHUF, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_IMM, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE),
    MNEM("shufpd", GEN_OP_VEC_SHUF, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_IMM, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE),
    MNEM("pshufd", GEN_OP_VEC_SHUF, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_IMM, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE),
    MNEM("pshufb", GEN_OP_VEC_SHUF, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    /* Vector add/sub/mul */
    MNEM("paddb",  GEN_OP_VEC_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("paddw",  GEN_OP_VEC_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("paddd",  GEN_OP_VEC_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("paddq",  GEN_OP_VEC_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("psubb",  GEN_OP_VEC_SUB, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("psubw",  GEN_OP_VEC_SUB, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("psubd",  GEN_OP_VEC_SUB, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("psubq",  GEN_OP_VEC_SUB, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("pmulld", GEN_OP_VEC_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("pmullw", GEN_OP_VEC_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    /* Additional SSE/AVX vector ops */
    MNEM("movhps",       GEN_OP_VEC_MOV,   BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("pcmpeqd",      GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("punpckldq",    GEN_OP_VEC_SHUF,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("punpcklqdq",   GEN_OP_VEC_SHUF,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("vpor",         GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE),
    MNEM("vpxor",        GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE),
    MNEM("vpcmpeqb",     GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE),
    MNEM("vpminub",      GEN_OP_VEC_LOGIC, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE),
    MNEM("vpbroadcastb", GEN_OP_VEC_MOV,   BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("vpmovmskb",    GEN_OP_VEC_MOV,   BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("vzeroupper",   GEN_OP_NOP,       BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),

    /*
     * AT&T size-suffixed variants (b/w/l/q).
     * These come AFTER the base entries so that e.g. "movq" overrides
     * the earlier VEC_MOV "movq" in the hash table, mapping the
     * overwhelmingly common 64-bit MOV correctly.
     */
    /* Integer ALU suffixed */
    MNEM("addb",  GEN_OP_INT_ADD, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("addw",  GEN_OP_INT_ADD, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("addl",  GEN_OP_INT_ADD, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("addq",  GEN_OP_INT_ADD, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("adcb",  GEN_OP_INT_ADC, BRANCH_NONE, F_ALU|MF_FLAGS_SRC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("adcw",  GEN_OP_INT_ADC, BRANCH_NONE, F_ALU|MF_FLAGS_SRC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("adcl",  GEN_OP_INT_ADC, BRANCH_NONE, F_ALU|MF_FLAGS_SRC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("adcq",  GEN_OP_INT_ADC, BRANCH_NONE, F_ALU|MF_FLAGS_SRC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("subb",  GEN_OP_INT_SUB, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("subw",  GEN_OP_INT_SUB, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("subl",  GEN_OP_INT_SUB, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("subq",  GEN_OP_INT_SUB, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sbbb",  GEN_OP_INT_SBB, BRANCH_NONE, F_ALU|MF_FLAGS_SRC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sbbw",  GEN_OP_INT_SBB, BRANCH_NONE, F_ALU|MF_FLAGS_SRC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sbbl",  GEN_OP_INT_SBB, BRANCH_NONE, F_ALU|MF_FLAGS_SRC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sbbq",  GEN_OP_INT_SBB, BRANCH_NONE, F_ALU|MF_FLAGS_SRC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM_I("imulb", GEN_OP_INT_MUL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, I_AX, I_AX_DX),
    MNEM_I("imulw", GEN_OP_INT_MUL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, I_AX, I_AX_DX),
    MNEM_I("imull", GEN_OP_INT_MUL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, I_AX, I_AX_DX),
    MNEM_I("imulq", GEN_OP_INT_MUL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, I_AX, I_AX_DX),
    MNEM_I("mulb",  GEN_OP_INT_MUL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX, I_AX_DX),
    MNEM_I("mulw",  GEN_OP_INT_MUL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX, I_AX_DX),
    MNEM_I("mull",  GEN_OP_INT_MUL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX, I_AX_DX),
    MNEM_I("mulq",  GEN_OP_INT_MUL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX, I_AX_DX),
    MNEM_I("idivb", GEN_OP_INT_DIV, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_DX, I_AX_DX),
    MNEM_I("idivw", GEN_OP_INT_DIV, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_DX, I_AX_DX),
    MNEM_I("idivl", GEN_OP_INT_DIV, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_DX, I_AX_DX),
    MNEM_I("idivq", GEN_OP_INT_DIV, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_DX, I_AX_DX),
    MNEM_I("divb",  GEN_OP_INT_DIV, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_DX, I_AX_DX),
    MNEM_I("divw",  GEN_OP_INT_DIV, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_DX, I_AX_DX),
    MNEM_I("divl",  GEN_OP_INT_DIV, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_DX, I_AX_DX),
    MNEM_I("divq",  GEN_OP_INT_DIV, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_DX, I_AX_DX),
    MNEM("andb",  GEN_OP_AND, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("andw",  GEN_OP_AND, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("andl",  GEN_OP_AND, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("andq",  GEN_OP_AND, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("orb",   GEN_OP_OR,  BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("orw",   GEN_OP_OR,  BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("orl",   GEN_OP_OR,  BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("orq",   GEN_OP_OR,  BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("xorb",  GEN_OP_XOR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("xorw",  GEN_OP_XOR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("xorl",  GEN_OP_XOR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("xorq",  GEN_OP_XOR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("notb",  GEN_OP_NOT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("notw",  GEN_OP_NOT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("notl",  GEN_OP_NOT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("notq",  GEN_OP_NOT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("negb",  GEN_OP_NEG, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("negw",  GEN_OP_NEG, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("negl",  GEN_OP_NEG, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("negq",  GEN_OP_NEG, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("incb",  GEN_OP_INC, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("incw",  GEN_OP_INC, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("incl",  GEN_OP_INC, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("incq",  GEN_OP_INC, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("decb",  GEN_OP_DEC, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("decw",  GEN_OP_DEC, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("decl",  GEN_OP_DEC, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("decq",  GEN_OP_DEC, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    /* Shift/rotate suffixed */
    MNEM("shlb",  GEN_OP_SHL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("shlw",  GEN_OP_SHL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("shll",  GEN_OP_SHL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("shlq",  GEN_OP_SHL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("salb",  GEN_OP_SHL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("salw",  GEN_OP_SHL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sall",  GEN_OP_SHL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("salq",  GEN_OP_SHL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("shrb",  GEN_OP_SHR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("shrw",  GEN_OP_SHR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("shrl",  GEN_OP_SHR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("shrq",  GEN_OP_SHR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sarb",  GEN_OP_SAR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sarw",  GEN_OP_SAR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sarl",  GEN_OP_SAR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("sarq",  GEN_OP_SAR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("rolb",  GEN_OP_ROL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("rolw",  GEN_OP_ROL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("roll",  GEN_OP_ROL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("rolq",  GEN_OP_ROL, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("rorb",  GEN_OP_ROR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("rorw",  GEN_OP_ROR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("rorl",  GEN_OP_ROR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("rorq",  GEN_OP_ROR, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    /* Data movement suffixed */
    MNEM("movb",    GEN_OP_MOV, BRANCH_NONE, MF_MOV_PROMOTE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movw",    GEN_OP_MOV, BRANCH_NONE, MF_MOV_PROMOTE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movl",    GEN_OP_MOV, BRANCH_NONE, MF_MOV_PROMOTE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movq",    GEN_OP_MOV, BRANCH_NONE, MF_MOV_PROMOTE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movabsq", GEN_OP_MOV, BRANCH_NONE, MF_MOV_PROMOTE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("leal",    GEN_OP_LEA, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_MEM_ADDR, CAP_DST_REG, CAP_NONE, CAP_NONE),
    MNEM("leaq",    GEN_OP_LEA, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_MEM_ADDR, CAP_DST_REG, CAP_NONE, CAP_NONE),
    MNEM("leaw",    GEN_OP_LEA, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_MEM_ADDR, CAP_DST_REG, CAP_NONE, CAP_NONE),
    MNEM("pushb",   GEN_OP_PUSH, BRANCH_NONE, F_PUSH, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("pushw",   GEN_OP_PUSH, BRANCH_NONE, F_PUSH, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("pushl",   GEN_OP_PUSH, BRANCH_NONE, F_PUSH, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("pushq",   GEN_OP_PUSH, BRANCH_NONE, F_PUSH, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("popb",    GEN_OP_POP,  BRANCH_NONE, F_PUSH, WPT_OP_RE_STD, CAP_DST_REG, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("popw",    GEN_OP_POP,  BRANCH_NONE, F_PUSH, WPT_OP_RE_STD, CAP_DST_REG, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("popl",    GEN_OP_POP,  BRANCH_NONE, F_PUSH, WPT_OP_RE_STD, CAP_DST_REG, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("popq",    GEN_OP_POP,  BRANCH_NONE, F_PUSH, WPT_OP_RE_STD, CAP_DST_REG, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("xchgb",   GEN_OP_XCHG, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("xchgw",   GEN_OP_XCHG, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("xchgl",   GEN_OP_XCHG, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("xchgq",   GEN_OP_XCHG, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE),
    /* Comparison suffixed */
    MNEM("cmpb",  GEN_OP_CMP,  BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("cmpw",  GEN_OP_CMP,  BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("cmpl",  GEN_OP_CMP,  BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("cmpq",  GEN_OP_CMP,  BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("testb", GEN_OP_TEST, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("testw", GEN_OP_TEST, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("testl", GEN_OP_TEST, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("testq", GEN_OP_TEST, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    /* Control flow suffixed */
    MNEM("jmpb",    GEN_OP_BRANCH, BRANCH_DIRECT_JUMP,  F_BRANCH, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("jmpw",    GEN_OP_BRANCH, BRANCH_DIRECT_JUMP,  F_BRANCH, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("jmpl",    GEN_OP_BRANCH, BRANCH_DIRECT_JUMP,  F_BRANCH, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("jmpq",    GEN_OP_BRANCH, BRANCH_DIRECT_JUMP,  F_BRANCH, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("callb",   GEN_OP_CALL,   BRANCH_DIRECT_CALL,  F_CALL_X86, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("callw",   GEN_OP_CALL,   BRANCH_DIRECT_CALL,  F_CALL_X86, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("calll",   GEN_OP_CALL,   BRANCH_DIRECT_CALL,  F_CALL_X86, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("callq",   GEN_OP_CALL,   BRANCH_DIRECT_CALL,  F_CALL_X86, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("retb",    GEN_OP_RET,    BRANCH_RETURN, F_RET_X86, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("retw",    GEN_OP_RET,    BRANCH_RETURN, F_RET_X86, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("retl",    GEN_OP_RET,    BRANCH_RETURN, F_RET_X86, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("retq",    GEN_OP_RET,    BRANCH_RETURN, F_RET_X86, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    /* Atomic / misc suffixed */
    MNEM_I("cmpxchgb", GEN_OP_XCHG, BRANCH_NONE, F_CMP|MF_ATOMIC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, I_AX, I_AX),
    MNEM_I("cmpxchgw", GEN_OP_XCHG, BRANCH_NONE, F_CMP|MF_ATOMIC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, I_AX, I_AX),
    MNEM_I("cmpxchgl", GEN_OP_XCHG, BRANCH_NONE, F_CMP|MF_ATOMIC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, I_AX, I_AX),
    MNEM_I("cmpxchgq", GEN_OP_XCHG, BRANCH_NONE, F_CMP|MF_ATOMIC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE, CAP_NONE, I_AX, I_AX),
    /* Misc instructions seen in unknown logs */
    MNEM("endbr64",  GEN_OP_NOP,    BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("endbr32",  GEN_OP_NOP,    BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM_I("cpuid",    GEN_OP_NOP,    BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_CX, I_AX_DX),
    MNEM("rdsspq",   GEN_OP_NOP,    BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM_I("xgetbv",   GEN_OP_NOP,    BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE, I_CX, I_AX_DX),
    MNEM_I("stosb",    GEN_OP_STORE,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_DI, I_DI),
    MNEM_I("stosw",    GEN_OP_STORE,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_DI, I_DI),
    MNEM_I("stosl",    GEN_OP_STORE,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_DI, I_DI),
    MNEM_I("stosq",    GEN_OP_STORE,  BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE, I_AX_DI, I_DI),
    MNEM("bsfl",     GEN_OP_INT_ADD, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("bsfq",     GEN_OP_INT_ADD, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("bsrl",     GEN_OP_INT_ADD, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("bsrq",     GEN_OP_INT_ADD, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("btl",      GEN_OP_TEST,   BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("btq",      GEN_OP_TEST,   BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("tzcntl",   GEN_OP_INT_ADD, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("tzcntq",   GEN_OP_INT_ADD, BRANCH_NONE, F_ALU, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),

    /*
     * Regex fallback patterns – tried in order when exact lookup fails.
     * These replace the old prefix_class_table + the j<cc> special-case.
     */
    /* x86 conditional jumps: j<cc> but not jmp */
    MNEM_RE("^j(?!mp).+",  GEN_OP_BRANCH, BRANCH_DIRECT_JUMP, F_CBRANCH, WPT_OP_RE_STD, CAP_BRANCH_TARGET, CAP_NONE, CAP_NONE, CAP_NONE),
    /* x86 cmov<cc> */
    MNEM_RE("^cmov.+",     GEN_OP_CMOV,   BRANCH_NONE, F_COND, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),
    /* x86 set<cc> */
    MNEM_RE("^set.+",      GEN_OP_SETCC,  BRANCH_NONE, F_COND, WPT_OP_RE_STD, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    /* x86 NOP variants (e.g. nopl, nopw) */
    MNEM_RE("^nop.+",      GEN_OP_NOP,    BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    /* x86 cvt... and vcvt... conversion families */
    MNEM_RE("^v?cvt.+",    GEN_OP_FP_CVT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG_OR_MEM, CAP_NONE, CAP_NONE),

    MNEM_END
};

/* AArch64 mnemonic table */
static const MnemonicEntry aarch64_mnemonic_table[] = {
    /* AArch64 ALU */
    MNEM("add", GEN_OP_INT_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("adds", GEN_OP_INT_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("sub", GEN_OP_INT_SUB, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("subs", GEN_OP_INT_SUB, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("mul", GEN_OP_INT_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("madd", GEN_OP_INT_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("msub", GEN_OP_INT_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("sdiv", GEN_OP_INT_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("udiv", GEN_OP_INT_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("and", GEN_OP_AND, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("orr", GEN_OP_OR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("orn", GEN_OP_OR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("eor", GEN_OP_XOR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("eon", GEN_OP_XOR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("mvn", GEN_OP_NOT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bic", GEN_OP_AND, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("lsl", GEN_OP_SHL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("lsr", GEN_OP_SHR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("asr", GEN_OP_SAR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* AArch64 data movement */
    MNEM("mov", GEN_OP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("movz", GEN_OP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("movn", GEN_OP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("movk", GEN_OP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("adrp", GEN_OP_LEA, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("adr", GEN_OP_LEA, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("movi", GEN_OP_VEC_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("ldr", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("ldp", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("ldrb", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("ldrh", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("ldrsb", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("ldrsh", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("ldrsw", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("str", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("stp", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("strb", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("strh", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    /* AArch64 comparison */
    MNEM("cmp", GEN_OP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("cmn", GEN_OP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("tst", GEN_OP_TEST, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    /* AArch64 control flow */
    MNEM("b", GEN_OP_BRANCH, BRANCH_DIRECT_JUMP, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bl", GEN_OP_CALL, BRANCH_DIRECT_CALL, F_CALL_RISC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("blr", GEN_OP_CALL, BRANCH_INDIRECT_CALL, F_CALL_RISC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("br", GEN_OP_BRANCH, BRANCH_INDIRECT_JUMP, MF_CHK_LR_RET, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("ret", GEN_OP_RET, BRANCH_RETURN, F_RET_RISC, WPT_OP_RE_STD, CAP_SRC_REG, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("svc", GEN_OP_SYSCALL, BRANCH_SYSCALL_TYPE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("brk", GEN_OP_SYSCALL, BRANCH_SYSCALL_TYPE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    /* AArch64 conditional */
    MNEM("cbz", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("cbnz", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("tbz", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("tbnz", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("csel", GEN_OP_CMOV, BRANCH_NONE, F_COND, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("csinc", GEN_OP_CMOV, BRANCH_NONE, F_COND, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("csinv", GEN_OP_CMOV, BRANCH_NONE, F_COND, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("csneg", GEN_OP_CMOV, BRANCH_NONE, F_COND, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* AArch64 FP */
    MNEM("fadd", GEN_OP_FP_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("fsub", GEN_OP_FP_SUB, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("fmul", GEN_OP_FP_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("fdiv", GEN_OP_FP_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("fsqrt", GEN_OP_FP_SQRT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("fmov", GEN_OP_FP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("fcmp", GEN_OP_FP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("fcvt", GEN_OP_FP_CVT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("fcvtzs", GEN_OP_FP_CVT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("fcvtzu", GEN_OP_FP_CVT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("scvtf", GEN_OP_FP_CVT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("ucvtf", GEN_OP_FP_CVT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* Regex fallback patterns (merged from prefix table) */
    /* AArch64 conditional branches: b.eq, b.ne, b.gt, etc. */
    MNEM_RE("^b\\..+", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* Atomic / barrier instructions */
    MNEM("dmb",  GEN_OP_FENCE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("dsb",  GEN_OP_FENCE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("isb",  GEN_OP_FENCE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM_RE("^ldaxr.*",  GEN_OP_LOAD,  BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM_RE("^ldxr.*",   GEN_OP_LOAD,  BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM_RE("^stlxr.*",  GEN_OP_STORE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE),
    MNEM_RE("^stxr.*",   GEN_OP_STORE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE),
    MNEM_RE("^ldar.*",   GEN_OP_LOAD,  BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM_RE("^stlr.*",   GEN_OP_STORE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM_RE("^ldadd.*",  GEN_OP_XCHG,  BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE),
    MNEM_RE("^swp.*",    GEN_OP_XCHG,  BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE),
    MNEM_RE("^cas.*",    GEN_OP_XCHG,  BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_NONE),

    MNEM_END
};

/* RISC-V mnemonic table */
static const MnemonicEntry riscv_mnemonic_table[] = {
    /* Integer ALU */
    MNEM("add", GEN_OP_INT_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("addi", GEN_OP_INT_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("addw", GEN_OP_INT_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("addiw", GEN_OP_INT_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("sub", GEN_OP_INT_SUB, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("subw", GEN_OP_INT_SUB, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("and", GEN_OP_AND, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("andi", GEN_OP_AND, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("or", GEN_OP_OR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("ori", GEN_OP_OR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("xor", GEN_OP_XOR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("xori", GEN_OP_XOR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("not", GEN_OP_NOT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    /* Shifts */
    MNEM("sll", GEN_OP_SHL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("slli", GEN_OP_SHL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("sllw", GEN_OP_SHL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("slliw", GEN_OP_SHL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("srl", GEN_OP_SHR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("srli", GEN_OP_SHR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("srlw", GEN_OP_SHR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("srliw", GEN_OP_SHR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("sra", GEN_OP_SAR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("srai", GEN_OP_SAR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("sraw", GEN_OP_SAR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("sraiw", GEN_OP_SAR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* Multiply and divide */
    MNEM("mul", GEN_OP_INT_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("mulh", GEN_OP_INT_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("mulhu", GEN_OP_INT_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("mulhsu", GEN_OP_INT_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("mulw", GEN_OP_INT_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("div", GEN_OP_INT_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("divu", GEN_OP_INT_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("divw", GEN_OP_INT_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("divuw", GEN_OP_INT_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("rem", GEN_OP_INT_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("remu", GEN_OP_INT_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("remw", GEN_OP_INT_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("remuw", GEN_OP_INT_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* Compare */
    MNEM("slt", GEN_OP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("slti", GEN_OP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("sltu", GEN_OP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("sltiu", GEN_OP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* Data movement */
    MNEM("lui", GEN_OP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("auipc", GEN_OP_LEA, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("li", GEN_OP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("la", GEN_OP_LEA, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("mv", GEN_OP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* Loads/stores */
    MNEM("lb", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("lbu", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("lh", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("lhu", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("lw", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("lwu", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("ld", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("sb", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("sh", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("sw", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("sd", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("flw", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("fld", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("fsw", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("fsd", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    /* Control flow */
    MNEM("jal", GEN_OP_CALL, BRANCH_DIRECT_CALL, F_CALL_RISC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("jalr", GEN_OP_CALL, BRANCH_INDIRECT_CALL, F_CALL_RISC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("beq", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bne", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("blt", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bge", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bltu", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bgeu", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bgtu", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bleu", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bgt", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("ble", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("beqz", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bnez", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bgez", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("blez", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bltz", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bgtz", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("j", GEN_OP_BRANCH, BRANCH_DIRECT_JUMP, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("ret", GEN_OP_RET, BRANCH_RETURN, F_RET_RISC, WPT_OP_RE_STD, CAP_SRC_REG, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("nop", GEN_OP_NOP, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    /* System */
    MNEM("ecall", GEN_OP_SYSCALL, BRANCH_SYSCALL_TYPE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("ebreak", GEN_OP_SYSCALL, BRANCH_SYSCALL_TYPE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("fence", GEN_OP_FENCE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* Regex fallback patterns (merged from prefix table) */
    /* RISC-V FP instructions with dot suffix */
    MNEM_RE("^fadd\\..+", GEN_OP_FP_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^fsub\\..+", GEN_OP_FP_SUB, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^fmul\\..+", GEN_OP_FP_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^fdiv\\..+", GEN_OP_FP_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^fsqrt\\..+", GEN_OP_FP_SQRT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^fmv\\..+", GEN_OP_FP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^fsgnj\\..+", GEN_OP_FP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^fsgnjn\\..+", GEN_OP_FP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^fsgnjx\\..+", GEN_OP_FP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^fcvt\\..+", GEN_OP_FP_CVT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^feq\\..+", GEN_OP_FP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^flt\\..+", GEN_OP_FP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^fle\\..+", GEN_OP_FP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^fmadd\\..+", GEN_OP_FP_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^fmsub\\..+", GEN_OP_FP_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^fnmadd\\..+", GEN_OP_FP_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^fnmsub\\..+", GEN_OP_FP_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* RISC-V atomic ops */
    MNEM_RE("^lr\\..+", GEN_OP_LOAD, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM_RE("^sc\\..+", GEN_OP_STORE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM_RE("^fence\\..+", GEN_OP_FENCE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* Non-dot bare prefixes */
    MNEM_RE("^amo.+", GEN_OP_XCHG, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_RW_REG_OR_MEM, CAP_RW_REG_OR_MEM), /* RISC-V atomic */

    MNEM_END
};

/* MIPS mnemonic table */
static const MnemonicEntry mips_mnemonic_table[] = {
    /* Integer ALU */
    MNEM("add", GEN_OP_INT_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("addi", GEN_OP_INT_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("addiu", GEN_OP_INT_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("addu", GEN_OP_INT_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("sub", GEN_OP_INT_SUB, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("subu", GEN_OP_INT_SUB, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("and", GEN_OP_AND, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("andi", GEN_OP_AND, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("or", GEN_OP_OR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("ori", GEN_OP_OR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("xor", GEN_OP_XOR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("xori", GEN_OP_XOR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("nor", GEN_OP_OR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* Shifts */
    MNEM("sll", GEN_OP_SHL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("sllv", GEN_OP_SHL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("srl", GEN_OP_SHR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("srlv", GEN_OP_SHR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("sra", GEN_OP_SAR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("srav", GEN_OP_SAR, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* Multiply and divide */
    MNEM("mul", GEN_OP_INT_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("mult", GEN_OP_INT_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("multu", GEN_OP_INT_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("div", GEN_OP_INT_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("divu", GEN_OP_INT_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("rem", GEN_OP_INT_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("remu", GEN_OP_INT_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* Compare */
    MNEM("slt", GEN_OP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("slti", GEN_OP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("sltu", GEN_OP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("sltiu", GEN_OP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* Data movement */
    MNEM("lui", GEN_OP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("li", GEN_OP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("la", GEN_OP_LEA, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("move", GEN_OP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("mtc1", GEN_OP_FP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG, CAP_NONE, CAP_NONE),
    MNEM("mthc1", GEN_OP_FP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_DST_REG, CAP_NONE, CAP_NONE),
    MNEM("mfc1", GEN_OP_FP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("mfhc1", GEN_OP_FP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM("mfhi", GEN_OP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("mflo", GEN_OP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("mthi", GEN_OP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("mtlo", GEN_OP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* Loads/stores */
    MNEM("lb", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("lbu", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("lh", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("lhu", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("lw", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("lwl", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("lwr", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("ld", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("sb", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("sh", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("sw", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("swl", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("swr", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("sd", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("lwc1", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("ldc1", GEN_OP_LOAD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("swc1", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("sdc1", GEN_OP_STORE, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    /* Control flow */
    MNEM("j", GEN_OP_BRANCH, BRANCH_DIRECT_JUMP, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("b", GEN_OP_BRANCH, BRANCH_DIRECT_JUMP, MF_NONE, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("jal", GEN_OP_CALL, BRANCH_DIRECT_CALL, F_CALL_RISC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("jalr", GEN_OP_CALL, BRANCH_INDIRECT_CALL, F_CALL_RISC, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("jr", GEN_OP_BRANCH, BRANCH_INDIRECT_JUMP, MF_CHK_LR_RET, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("beq", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bne", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("blez", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bgtz", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bltz", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bgez", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("beqz", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bnez", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("beql", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bnel", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("blezl", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bgtzl", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bltzl", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bgezl", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bltzal", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM("bgezal", GEN_OP_BRANCH, BRANCH_COND_DIRECT, MF_CONDITIONAL, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    /* System */
    MNEM("syscall", GEN_OP_SYSCALL, BRANCH_SYSCALL_TYPE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("break", GEN_OP_SYSCALL, BRANCH_SYSCALL_TYPE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    MNEM("nop", GEN_OP_NOP, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    /* Atomic / barrier instructions */
    MNEM("ll",   GEN_OP_LOAD,  BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("lld",  GEN_OP_LOAD,  BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("sc",   GEN_OP_STORE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("scd",  GEN_OP_STORE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_RW_REG_OR_MEM, CAP_SRC_MEM, CAP_NONE, CAP_NONE),
    MNEM("sync", GEN_OP_FENCE, BRANCH_NONE, MF_ATOMIC, WPT_OP_RE_STD, CAP_NONE, CAP_NONE, CAP_NONE, CAP_NONE),
    /* Regex fallback patterns (merged from prefix table) */
    /* MIPS FP instructions with dot suffix */
    MNEM_RE("^add\\..+", GEN_OP_FP_ADD, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^sub\\..+", GEN_OP_FP_SUB, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^mul\\..+", GEN_OP_FP_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^div\\..+", GEN_OP_FP_DIV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^sqrt\\..+", GEN_OP_FP_SQRT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^mov\\..+", GEN_OP_FP_MOV, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^cvt\\..+", GEN_OP_FP_CVT, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^c\\..+", GEN_OP_FP_CMP, BRANCH_NONE, F_CMP, WPT_OP_RE_STD, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_NONE, CAP_NONE),
    MNEM_RE("^madd\\..+", GEN_OP_FP_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^msub\\..+", GEN_OP_FP_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^nmadd\\..+", GEN_OP_FP_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),
    MNEM_RE("^nmsub\\..+", GEN_OP_FP_MUL, BRANCH_NONE, MF_NONE, WPT_OP_RE_STD, CAP_DST_REG, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM, CAP_SRC_REG_OR_MEM),

    MNEM_END
};





/* x86 instruction prefixes stripped before mnemonic classification. */
static const char *const x86_insn_prefixes[] = {
    "lock", "rep", "repz", "repnz", "data16", "bnd", "notrack", NULL
};

/*
 * Static ISA property table.
 *
 * Concentrates every ISA-specific knob into one place so that adding a
 * new ISA requires only a new row rather than scattered switch arms.
 *
 *   mnemonic_table  — per-ISA MnemonicEntry array (NULL-terminated)
 *   reg_table       — per-ISA RegEntry   array (NULL-terminated)
 *   reg_prefix      — character prefixed to register names ('%' for x86)
 *   mem_open        — opening bracket for memory operands ('(' or '[')
 *   indirect_star   — x86 '*' marks indirect branches
 *   strip_dollar    — MIPS '$' stripped from register names
 *   branch_delay_slots — number of delay-slot instructions after a branch
 *                        (0 for most ISAs, 1 for MIPS)
 */
typedef struct {
    const MnemonicEntry *mnemonic_table;
    const RegEntry      *reg_table;
    char                 reg_prefix;
    char                 mem_open;
    bool                 indirect_star;
    bool                 strip_dollar;
    uint8_t              branch_delay_slots;
} IsaProperties;

static const IsaProperties isa_properties[] = {
    [TRACE_ISA_UNKNOWN] = { NULL, NULL, '\0', '\0', false, false, 0 },
    [TRACE_ISA_X86]     = { x86_mnemonic_table, x86_reg_entries,
                            '%', '(', true, false, 0 },
    [TRACE_ISA_AARCH64] = { aarch64_mnemonic_table, aarch64_reg_entries,
                            '\0', '[', false, false, 0 },
    [TRACE_ISA_RISCV]   = { riscv_mnemonic_table, riscv_reg_entries,
                            '\0', '(', false, false, 0 },
    [TRACE_ISA_MIPS]    = { mips_mnemonic_table, mips_reg_entries,
                            '\0', '(', false, true, 1 },
};
