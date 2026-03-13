/*
 * Wrong-Path Tracing Plugin for QEMU
 *
 * Extended trace format implementing the ChampSim wrong-path specification:
 *
 *   HEADER: A map of BB templates encoding all unique basic blocks within
 *           the traced window, with static instruction context (PCs, sizes,
 *           ISA-agnostic decoded instruction fields (operation type,
 *           branch type, source/destination registers).
 *
 *   BODY:   The execution trace of BBs as they executed on the correct-path,
 *           with dynamic context (branch targets, memory addresses) and
 *           wrong-path BB sequences per correct-path BB.
 *
 * Two output modes:
 *   - Packed binary (.bin): Compact ULEB128-based encoding of header + body
 *   - Debug text (.txt): Human-readable representation (toggleable)
 *
 * Features:
 *   - BB template deduplication (unique BBs stored once in header)
 *   - Wrong-path execution with real IF and DF addresses
 *   - Start/stop tracing by instruction number
 *   - ISA-agnostic instruction decode (x86 currently supported)
 *   - Compact LEB128 variable-length integer encoding
 *   - Extensible: additional ISA decoders can be added for ARM, RISC-V, etc.
 *
 * Usage:
 *   -plugin wptrace[,depth=N][,outfile=PATH][,debug=1]
 *                  [,wp=0|1][,start=N][,stop=N]
 *                  [,spfile=PATH][,program=NAME]
 *
 * Copyright (c) 2025
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* ========================= Configuration ========================= */

static int max_wrong_path_depth = 64;
static bool enable_wrong_path = true;
static bool enable_debug_text = false;
static char *output_base_path = NULL;
static char *program_name = NULL;
static uint64_t trace_start_insn = 0;
static uint64_t trace_stop_insn = UINT64_MAX;
static const char *target_name;
static bool is_x86 = false;

/* SimPoints-driven tracing */
static char *simpoints_file_path = NULL;

typedef struct {
    uint64_t interval_id;
    uint64_t start_insn;
    uint64_t stop_insn;
    int cluster_id;
    double weight;
} SimPointEntry;

static GArray *simpoints_list = NULL;  /* GArray of SimPointEntry, sorted */
static guint simpoints_current_idx = 0;

#define MAX_INSN_BYTES 16

/* Magic for binary format */
#define WPT_MAGIC  0x54505703  /* 'T','P','W',0x03 little-endian - version 3 */

/* ========================= ISA-Agnostic Instruction Fields ========================= */

/* Maximum source/destination registers per instruction */
#define MAX_SRC_REGS 4
#define MAX_DST_REGS 4

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
    BRANCH_COND_DIRECT = 6,
    BRANCH_SYSCALL_TYPE = 7,
};

/*
 * ISA-agnostic register IDs.
 * Consistent numbering across ISAs with reserved special register IDs.
 */
enum GenericRegId {
    REG_NONE = 0,
    /* General-purpose integer registers: 1-32 */
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
    /* Floating-point registers: 33-64 */
    REG_FPR0 = 33,
    /* FPR1-FPR31 follow sequentially (34-64) */
    /* Vector/SIMD registers: 65-96 */
    REG_VEC0 = 65,
    /* VEC1-VEC31 follow sequentially (66-96) */
    /* Special registers: 250-254 */
    REG_SP = 250,
    REG_FLAGS = 251,
    REG_IP = 252,
    REG_LR = 253,
    REG_FP_REG = 254,
};

/*
 * Decoded ISA-agnostic instruction fields.
 * Standardized per-instruction representation stored in BB templates.
 */
typedef struct {
    uint8_t opcode;                 /* GenericOpcode */
    uint8_t branch_type;            /* BranchType (BRANCH_NONE if not branch) */
    uint8_t n_src_regs;
    uint8_t n_dst_regs;
    uint8_t src_regs[MAX_SRC_REGS]; /* Source register IDs (GenericRegId) */
    uint8_t dst_regs[MAX_DST_REGS]; /* Destination register IDs (GenericRegId) */
    bool has_immediate;
    int64_t immediate;
} InsnFields;

/* ========================= Disassembly-Based Generic Decode ========================= */

static inline void add_src_reg(InsnFields *f, uint8_t reg_id)
{
    if (reg_id == REG_NONE || f->n_src_regs >= MAX_SRC_REGS) {
        return;
    }
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        if (f->src_regs[i] == reg_id) {
            return;
        }
    }
    f->src_regs[f->n_src_regs++] = reg_id;
}

static inline void add_dst_reg(InsnFields *f, uint8_t reg_id)
{
    if (reg_id == REG_NONE || f->n_dst_regs >= MAX_DST_REGS) {
        return;
    }
    for (uint8_t i = 0; i < f->n_dst_regs; i++) {
        if (f->dst_regs[i] == reg_id) {
            return;
        }
    }
    f->dst_regs[f->n_dst_regs++] = reg_id;
}

/*
 * Parse x86 register name (without % prefix) to GenericRegId.
 * Handles 64/32/16/8-bit variants and extended registers R8-R15.
 */
static uint8_t parse_x86_reg(const char *name)
{
    if (!name || !*name) {
        return REG_NONE;
    }

    /* 64-bit GPRs */
    if (strcmp(name, "rax") == 0) return REG_GPR0;
    if (strcmp(name, "rcx") == 0) return REG_GPR1;
    if (strcmp(name, "rdx") == 0) return REG_GPR2;
    if (strcmp(name, "rbx") == 0) return REG_GPR3;
    if (strcmp(name, "rsp") == 0) return REG_SP;
    if (strcmp(name, "rbp") == 0) return REG_FP_REG;
    if (strcmp(name, "rsi") == 0) return REG_GPR4;
    if (strcmp(name, "rdi") == 0) return REG_GPR5;

    /* 32-bit GPRs */
    if (strcmp(name, "eax") == 0) return REG_GPR0;
    if (strcmp(name, "ecx") == 0) return REG_GPR1;
    if (strcmp(name, "edx") == 0) return REG_GPR2;
    if (strcmp(name, "ebx") == 0) return REG_GPR3;
    if (strcmp(name, "esp") == 0) return REG_SP;
    if (strcmp(name, "ebp") == 0) return REG_FP_REG;
    if (strcmp(name, "esi") == 0) return REG_GPR4;
    if (strcmp(name, "edi") == 0) return REG_GPR5;

    /* 16-bit GPRs */
    if (strcmp(name, "ax") == 0) return REG_GPR0;
    if (strcmp(name, "cx") == 0) return REG_GPR1;
    if (strcmp(name, "dx") == 0) return REG_GPR2;
    if (strcmp(name, "bx") == 0) return REG_GPR3;
    if (strcmp(name, "sp") == 0) return REG_SP;
    if (strcmp(name, "bp") == 0) return REG_FP_REG;
    if (strcmp(name, "si") == 0) return REG_GPR4;
    if (strcmp(name, "di") == 0) return REG_GPR5;

    /* 8-bit GPRs */
    if (strcmp(name, "al") == 0 || strcmp(name, "ah") == 0) return REG_GPR0;
    if (strcmp(name, "cl") == 0 || strcmp(name, "ch") == 0) return REG_GPR1;
    if (strcmp(name, "dl") == 0 || strcmp(name, "dh") == 0) return REG_GPR2;
    if (strcmp(name, "bl") == 0 || strcmp(name, "bh") == 0) return REG_GPR3;
    if (strcmp(name, "spl") == 0) return REG_SP;
    if (strcmp(name, "bpl") == 0) return REG_FP_REG;
    if (strcmp(name, "sil") == 0) return REG_GPR4;
    if (strcmp(name, "dil") == 0) return REG_GPR5;

    /* Extended registers R8-R15 (with optional b/w/d suffix) */
    if (name[0] == 'r' && name[1] >= '0' && name[1] <= '9') {
        char *end;
        long n = strtol(name + 1, &end, 10);
        /* R8 maps to GPR6 (index = n - 8 + 6 = n - 2) */
        if (n >= 8 && n <= 15 &&
            (*end == '\0' || *end == 'b' || *end == 'w' || *end == 'd')) {
            return REG_GPR0 + (uint8_t)(n - 2);
        }
    }

    /* XMM/YMM/ZMM registers */
    if (strncmp(name, "xmm", 3) == 0 || strncmp(name, "ymm", 3) == 0 ||
        strncmp(name, "zmm", 3) == 0) {
        int n = atoi(name + 3);
        if (n >= 0 && n < 32) {
            return REG_VEC0 + (uint8_t)n;
        }
    }

    /* x87 FP stack */
    if (strncmp(name, "st", 2) == 0) return REG_FPR0;

    /* Special registers */
    if (strcmp(name, "rip") == 0 || strcmp(name, "eip") == 0) return REG_IP;
    if (strcmp(name, "rflags") == 0 || strcmp(name, "eflags") == 0) {
        return REG_FLAGS;
    }

    return REG_NONE;
}

/*
 * Parse AArch64 register name to GenericRegId.
 */
static uint8_t parse_aarch64_reg(const char *name)
{
    if (!name || !*name) {
        return REG_NONE;
    }

    /* General purpose: x0-x30, w0-w30 */
    if ((name[0] == 'x' || name[0] == 'w') &&
        name[1] >= '0' && name[1] <= '9') {
        int n = atoi(name + 1);
        if (n >= 0 && n <= 30) return REG_GPR0 + (uint8_t)n;
    }

    /* Zero register - reads as zero, no dependency */
    if (strcmp(name, "xzr") == 0 || strcmp(name, "wzr") == 0) {
        return REG_NONE;
    }

    /* Stack pointer */
    if (strcmp(name, "sp") == 0) return REG_SP;

    /* Link register (x30) */
    if (strcmp(name, "lr") == 0) return REG_LR;

    /* Frame pointer (x29) */
    if (strcmp(name, "fp") == 0) return REG_FP_REG;

    /* Vector/FP: v0-v31, d0-d31, s0-s31, q0-q31, h0-h31, b0-b31 */
    if ((name[0] == 'v' || name[0] == 'd' || name[0] == 's' ||
         name[0] == 'q' || name[0] == 'h' || name[0] == 'b') &&
        name[1] >= '0' && name[1] <= '9') {
        int n = atoi(name + 1);
        if (n >= 0 && n < 32) return REG_VEC0 + (uint8_t)n;
    }

    return REG_NONE;
}

/* Mnemonic-to-opcode lookup table entry */
typedef struct {
    const char *name;
    uint8_t opcode;
    uint8_t branch_type;
} MnemonicEntry;

/* Searched linearly (only called at translate time) */
static const MnemonicEntry mnemonic_table[] = {
    /* Integer ALU */
    {"add",      GEN_OP_INT_ADD,  BRANCH_NONE},
    {"adc",      GEN_OP_INT_ADC,  BRANCH_NONE},
    {"sub",      GEN_OP_INT_SUB,  BRANCH_NONE},
    {"sbb",      GEN_OP_INT_SBB,  BRANCH_NONE},
    {"imul",     GEN_OP_INT_MUL,  BRANCH_NONE},
    {"mul",      GEN_OP_INT_MUL,  BRANCH_NONE},
    {"idiv",     GEN_OP_INT_DIV,  BRANCH_NONE},
    {"div",      GEN_OP_INT_DIV,  BRANCH_NONE},
    {"and",      GEN_OP_AND,      BRANCH_NONE},
    {"or",       GEN_OP_OR,       BRANCH_NONE},
    {"xor",      GEN_OP_XOR,      BRANCH_NONE},
    {"not",      GEN_OP_NOT,      BRANCH_NONE},
    {"neg",      GEN_OP_NEG,      BRANCH_NONE},
    {"inc",      GEN_OP_INC,      BRANCH_NONE},
    {"dec",      GEN_OP_DEC,      BRANCH_NONE},
    /* Shifts/rotates */
    {"shl",      GEN_OP_SHL,      BRANCH_NONE},
    {"sal",      GEN_OP_SHL,      BRANCH_NONE},
    {"shr",      GEN_OP_SHR,      BRANCH_NONE},
    {"sar",      GEN_OP_SAR,      BRANCH_NONE},
    {"rol",      GEN_OP_ROL,      BRANCH_NONE},
    {"ror",      GEN_OP_ROR,      BRANCH_NONE},
    /* Data movement */
    {"mov",      GEN_OP_MOV,      BRANCH_NONE},
    {"lea",      GEN_OP_LEA,      BRANCH_NONE},
    {"push",     GEN_OP_PUSH,     BRANCH_NONE},
    {"pop",      GEN_OP_POP,      BRANCH_NONE},
    {"xchg",     GEN_OP_XCHG,     BRANCH_NONE},
    /* Sign/zero extend */
    {"movsx",    GEN_OP_MOVSX,    BRANCH_NONE},
    {"movsxd",   GEN_OP_MOVSX,    BRANCH_NONE},
    {"movsl",    GEN_OP_MOVSX,    BRANCH_NONE},
    {"movzx",    GEN_OP_MOVZX,    BRANCH_NONE},
    {"movzb",    GEN_OP_MOVZX,    BRANCH_NONE},
    {"cltq",     GEN_OP_MOVSX,    BRANCH_NONE},
    {"cqto",     GEN_OP_MOVSX,    BRANCH_NONE},
    {"cwtl",     GEN_OP_MOVSX,    BRANCH_NONE},
    {"cdqe",     GEN_OP_MOVSX,    BRANCH_NONE},
    {"cbw",      GEN_OP_MOVSX,    BRANCH_NONE},
    {"cwde",     GEN_OP_MOVSX,    BRANCH_NONE},
    {"cdq",      GEN_OP_MOVSX,    BRANCH_NONE},
    {"cqo",      GEN_OP_MOVSX,    BRANCH_NONE},
    /* Comparison */
    {"cmp",      GEN_OP_CMP,      BRANCH_NONE},
    {"test",     GEN_OP_TEST,     BRANCH_NONE},
    /* Control flow */
    {"jmp",      GEN_OP_BRANCH,   BRANCH_DIRECT_JUMP},
    {"call",     GEN_OP_CALL,     BRANCH_DIRECT_CALL},
    {"ret",      GEN_OP_RET,      BRANCH_RETURN},
    {"nop",      GEN_OP_NOP,      BRANCH_NONE},
    {"syscall",  GEN_OP_SYSCALL,  BRANCH_SYSCALL_TYPE},
    {"sysenter", GEN_OP_SYSCALL,  BRANCH_SYSCALL_TYPE},
    {"int",      GEN_OP_SYSCALL,  BRANCH_SYSCALL_TYPE},
    /* Fences */
    {"mfence",   GEN_OP_FENCE,    BRANCH_NONE},
    {"lfence",   GEN_OP_FENCE,    BRANCH_NONE},
    {"sfence",   GEN_OP_FENCE,    BRANCH_NONE},
    /* Scalar FP */
    {"addss",    GEN_OP_FP_ADD,   BRANCH_NONE},
    {"addsd",    GEN_OP_FP_ADD,   BRANCH_NONE},
    {"addps",    GEN_OP_FP_ADD,   BRANCH_NONE},
    {"addpd",    GEN_OP_FP_ADD,   BRANCH_NONE},
    {"subss",    GEN_OP_FP_SUB,   BRANCH_NONE},
    {"subsd",    GEN_OP_FP_SUB,   BRANCH_NONE},
    {"subps",    GEN_OP_FP_SUB,   BRANCH_NONE},
    {"subpd",    GEN_OP_FP_SUB,   BRANCH_NONE},
    {"mulss",    GEN_OP_FP_MUL,   BRANCH_NONE},
    {"mulsd",    GEN_OP_FP_MUL,   BRANCH_NONE},
    {"mulps",    GEN_OP_FP_MUL,   BRANCH_NONE},
    {"mulpd",    GEN_OP_FP_MUL,   BRANCH_NONE},
    {"divss",    GEN_OP_FP_DIV,   BRANCH_NONE},
    {"divsd",    GEN_OP_FP_DIV,   BRANCH_NONE},
    {"divps",    GEN_OP_FP_DIV,   BRANCH_NONE},
    {"divpd",    GEN_OP_FP_DIV,   BRANCH_NONE},
    {"sqrtss",   GEN_OP_FP_SQRT,  BRANCH_NONE},
    {"sqrtsd",   GEN_OP_FP_SQRT,  BRANCH_NONE},
    {"sqrtps",   GEN_OP_FP_SQRT,  BRANCH_NONE},
    {"sqrtpd",   GEN_OP_FP_SQRT,  BRANCH_NONE},
    {"movss",    GEN_OP_FP_MOV,   BRANCH_NONE},
    {"movsd",    GEN_OP_FP_MOV,   BRANCH_NONE},
    {"ucomiss",  GEN_OP_FP_CMP,   BRANCH_NONE},
    {"ucomisd",  GEN_OP_FP_CMP,   BRANCH_NONE},
    {"comiss",   GEN_OP_FP_CMP,   BRANCH_NONE},
    {"comisd",   GEN_OP_FP_CMP,   BRANCH_NONE},
    /* Vector mov */
    {"movaps",   GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"movapd",   GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"movups",   GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"movupd",   GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"movdqa",   GEN_OP_VEC_MOV,  BRANCH_NONE},
    {"movdqu",   GEN_OP_VEC_MOV,  BRANCH_NONE},
    /* Vector logic */
    {"andps",    GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"andpd",    GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"orps",     GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"orpd",     GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"xorps",    GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"xorpd",    GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"andnps",   GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"andnpd",   GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"pand",     GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"pandn",    GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"por",      GEN_OP_VEC_LOGIC, BRANCH_NONE},
    {"pxor",     GEN_OP_VEC_LOGIC, BRANCH_NONE},
    /* Vector shuffle */
    {"shufps",   GEN_OP_VEC_SHUF, BRANCH_NONE},
    {"shufpd",   GEN_OP_VEC_SHUF, BRANCH_NONE},
    {"pshufd",   GEN_OP_VEC_SHUF, BRANCH_NONE},
    {"pshufb",   GEN_OP_VEC_SHUF, BRANCH_NONE},
    /* Vector add/sub/mul */
    {"paddb",    GEN_OP_VEC_ADD,  BRANCH_NONE},
    {"paddw",    GEN_OP_VEC_ADD,  BRANCH_NONE},
    {"paddd",    GEN_OP_VEC_ADD,  BRANCH_NONE},
    {"paddq",    GEN_OP_VEC_ADD,  BRANCH_NONE},
    {"psubb",    GEN_OP_VEC_SUB,  BRANCH_NONE},
    {"psubw",    GEN_OP_VEC_SUB,  BRANCH_NONE},
    {"psubd",    GEN_OP_VEC_SUB,  BRANCH_NONE},
    {"psubq",    GEN_OP_VEC_SUB,  BRANCH_NONE},
    {"pmulld",   GEN_OP_VEC_MUL,  BRANCH_NONE},
    {"pmullw",   GEN_OP_VEC_MUL,  BRANCH_NONE},
    /* AArch64 ALU */
    {"adds",     GEN_OP_INT_ADD,  BRANCH_NONE},
    {"subs",     GEN_OP_INT_SUB,  BRANCH_NONE},
    {"madd",     GEN_OP_INT_MUL,  BRANCH_NONE},
    {"msub",     GEN_OP_INT_MUL,  BRANCH_NONE},
    {"sdiv",     GEN_OP_INT_DIV,  BRANCH_NONE},
    {"udiv",     GEN_OP_INT_DIV,  BRANCH_NONE},
    {"orr",      GEN_OP_OR,       BRANCH_NONE},
    {"orn",      GEN_OP_OR,       BRANCH_NONE},
    {"eor",      GEN_OP_XOR,      BRANCH_NONE},
    {"eon",      GEN_OP_XOR,      BRANCH_NONE},
    {"mvn",      GEN_OP_NOT,      BRANCH_NONE},
    {"bic",      GEN_OP_AND,      BRANCH_NONE},
    {"lsl",      GEN_OP_SHL,      BRANCH_NONE},
    {"lsr",      GEN_OP_SHR,      BRANCH_NONE},
    {"asr",      GEN_OP_SAR,      BRANCH_NONE},
    /* AArch64 data movement */
    {"movz",     GEN_OP_MOV,      BRANCH_NONE},
    {"movn",     GEN_OP_MOV,      BRANCH_NONE},
    {"movk",     GEN_OP_MOV,      BRANCH_NONE},
    {"ldr",      GEN_OP_LOAD,     BRANCH_NONE},
    {"ldp",      GEN_OP_LOAD,     BRANCH_NONE},
    {"ldrb",     GEN_OP_LOAD,     BRANCH_NONE},
    {"ldrh",     GEN_OP_LOAD,     BRANCH_NONE},
    {"ldrsb",    GEN_OP_LOAD,     BRANCH_NONE},
    {"ldrsh",    GEN_OP_LOAD,     BRANCH_NONE},
    {"ldrsw",    GEN_OP_LOAD,     BRANCH_NONE},
    {"str",      GEN_OP_STORE,    BRANCH_NONE},
    {"stp",      GEN_OP_STORE,    BRANCH_NONE},
    {"strb",     GEN_OP_STORE,    BRANCH_NONE},
    {"strh",     GEN_OP_STORE,    BRANCH_NONE},
    /* AArch64 comparison */
    {"cmn",      GEN_OP_CMP,      BRANCH_NONE},
    {"tst",      GEN_OP_TEST,     BRANCH_NONE},
    /* AArch64 control flow */
    {"bl",       GEN_OP_CALL,     BRANCH_DIRECT_CALL},
    {"blr",      GEN_OP_CALL,     BRANCH_INDIRECT_CALL},
    {"br",       GEN_OP_BRANCH,   BRANCH_INDIRECT_JUMP},
    {"svc",      GEN_OP_SYSCALL,  BRANCH_SYSCALL_TYPE},
    /* AArch64 conditional */
    {"csel",     GEN_OP_CMOV,     BRANCH_NONE},
    {"csinc",    GEN_OP_CMOV,     BRANCH_NONE},
    {"csinv",    GEN_OP_CMOV,     BRANCH_NONE},
    {"csneg",    GEN_OP_CMOV,     BRANCH_NONE},
    /* AArch64 FP */
    {"fadd",     GEN_OP_FP_ADD,   BRANCH_NONE},
    {"fsub",     GEN_OP_FP_SUB,   BRANCH_NONE},
    {"fmul",     GEN_OP_FP_MUL,   BRANCH_NONE},
    {"fdiv",     GEN_OP_FP_DIV,   BRANCH_NONE},
    {"fsqrt",    GEN_OP_FP_SQRT,  BRANCH_NONE},
    {"fmov",     GEN_OP_FP_MOV,   BRANCH_NONE},
    {"fcmp",     GEN_OP_FP_CMP,   BRANCH_NONE},
    {"fcvt",     GEN_OP_FP_CVT,   BRANCH_NONE},
    {"fcvtzs",   GEN_OP_FP_CVT,   BRANCH_NONE},
    {"fcvtzu",   GEN_OP_FP_CVT,   BRANCH_NONE},
    {"scvtf",    GEN_OP_FP_CVT,   BRANCH_NONE},
    {"ucvtf",    GEN_OP_FP_CVT,   BRANCH_NONE},
    {NULL,       0,               0}
};

/*
 * Look up a base mnemonic in the table.
 * Returns true if found, filling opcode and branch_type.
 */
static bool lookup_mnemonic(const char *mnem, uint8_t *opcode,
                            uint8_t *branch_type)
{
    for (int i = 0; mnemonic_table[i].name; i++) {
        if (strcmp(mnem, mnemonic_table[i].name) == 0) {
            *opcode = mnemonic_table[i].opcode;
            *branch_type = mnemonic_table[i].branch_type;
            return true;
        }
    }
    return false;
}

/*
 * Classify a mnemonic string to GenericOpcode + BranchType.
 * Handles x86 size suffixes, AVX v-prefix, conditional branches,
 * cmov/setcc variants, and AArch64 conditional branches.
 */
static void classify_mnemonic(const char *mnem, uint8_t *opcode,
                              uint8_t *branch_type)
{
    *opcode = GEN_OP_UNKNOWN;
    *branch_type = BRANCH_NONE;

    if (!mnem || !*mnem) {
        return;
    }

    /* Skip x86 lock/rep prefixes (appear before mnemonic separated by space) */
    if (strncmp(mnem, "lock ", 5) == 0) {
        mnem += 5;
    } else if (strncmp(mnem, "rep ", 4) == 0) {
        mnem += 4;
    } else if (strncmp(mnem, "repz ", 5) == 0) {
        mnem += 5;
    } else if (strncmp(mnem, "repnz ", 6) == 0) {
        mnem += 6;
    } else if (strncmp(mnem, "data16 ", 7) == 0) {
        mnem += 7;
    }

    /* x86 conditional branches: j<cc> (not jmp/jmpq) */
    if (is_x86 && mnem[0] == 'j') {
        char tmp[32];
        g_strlcpy(tmp, mnem, sizeof(tmp));
        size_t tlen = strlen(tmp);
        if (tlen > 1 && tmp[tlen - 1] == 'q') {
            tmp[tlen - 1] = '\0';
        }
        if (strcmp(tmp, "jmp") != 0) {
            *opcode = GEN_OP_BRANCH;
            *branch_type = BRANCH_COND_DIRECT;
            return;
        }
    }

    /* AArch64 conditional branches: b.eq, b.ne, b.gt, etc. */
    if (!is_x86 && mnem[0] == 'b' && mnem[1] == '.') {
        *opcode = GEN_OP_BRANCH;
        *branch_type = BRANCH_COND_DIRECT;
        return;
    }

    /* AArch64 unconditional branch */
    if (!is_x86 && strcmp(mnem, "b") == 0) {
        *opcode = GEN_OP_BRANCH;
        *branch_type = BRANCH_DIRECT_JUMP;
        return;
    }

    /* AArch64 ret */
    if (!is_x86 && strcmp(mnem, "ret") == 0) {
        *opcode = GEN_OP_RET;
        *branch_type = BRANCH_RETURN;
        return;
    }

    /* AArch64 compare and branch: cbz, cbnz, tbz, tbnz */
    if (!is_x86 && (strncmp(mnem, "cbz", 3) == 0 ||
                    strncmp(mnem, "cbnz", 4) == 0 ||
                    strncmp(mnem, "tbz", 3) == 0 ||
                    strncmp(mnem, "tbnz", 4) == 0)) {
        *opcode = GEN_OP_BRANCH;
        *branch_type = BRANCH_COND_DIRECT;
        return;
    }

    /* x86 cmov<cc> variants */
    if (is_x86 && strncmp(mnem, "cmov", 4) == 0) {
        *opcode = GEN_OP_CMOV;
        return;
    }

    /* x86 set<cc> variants */
    if (is_x86 && strncmp(mnem, "set", 3) == 0 && strlen(mnem) > 3) {
        *opcode = GEN_OP_SETCC;
        return;
    }

    /* FP conversion: cvt.../vcvt... (x86) */
    if (strncmp(mnem, "cvt", 3) == 0 || strncmp(mnem, "vcvt", 4) == 0) {
        *opcode = GEN_OP_FP_CVT;
        return;
    }

    /* NOP variants (x86: nopl, nopw, etc.) */
    if (strncmp(mnem, "nop", 3) == 0) {
        *opcode = GEN_OP_NOP;
        return;
    }

    /* Direct lookup in table */
    if (lookup_mnemonic(mnem, opcode, branch_type)) {
        return;
    }

    /* AVX v-prefix: strip 'v' and retry */
    if (mnem[0] == 'v' && strlen(mnem) > 1) {
        if (lookup_mnemonic(mnem + 1, opcode, branch_type)) {
            return;
        }
    }

    /* x86 size suffix: strip trailing q/l/w/b and retry */
    size_t len = strlen(mnem);
    if (len > 1) {
        char base[32];
        g_strlcpy(base, mnem, sizeof(base));
        char last = base[len - 1];
        if (last == 'q' || last == 'l' || last == 'w' || last == 'b') {
            base[len - 1] = '\0';
            if (lookup_mnemonic(base, opcode, branch_type)) {
                return;
            }
            /* Also try AVX v-prefix + stripped suffix */
            if (base[0] == 'v' && strlen(base) > 1) {
                if (lookup_mnemonic(base + 1, opcode, branch_type)) {
                    return;
                }
            }
        }
    }
}

/*
 * Split operand string by top-level commas (respecting parentheses/brackets).
 * Returns the number of operands found.
 */
#define MAX_OPS 4
#define MAX_OP_LEN 64

static int split_operands(const char *s, char ops[][MAX_OP_LEN], int max_ops)
{
    int n = 0, depth = 0, pos = 0;

    while (*s == ' ' || *s == '\t') {
        s++;
    }

    while (*s && n < max_ops) {
        if (*s == '(' || *s == '[') {
            depth++;
        } else if (*s == ')' || *s == ']') {
            depth--;
        } else if (*s == ',' && depth == 0) {
            ops[n][pos] = '\0';
            n++;
            pos = 0;
            s++;
            while (*s == ' ' || *s == '\t') {
                s++;
            }
            continue;
        }
        if (pos < MAX_OP_LEN - 1) {
            ops[n][pos++] = *s;
        }
        s++;
    }
    if (pos > 0 || n > 0) {
        ops[n][pos] = '\0';
        n++;
    }
    return n;
}

/* Check if an operand contains a memory reference */
static bool is_memory_operand(const char *op)
{
    return strchr(op, '(') != NULL || strchr(op, '[') != NULL;
}

/*
 * Extract the first register from an x86 AT&T operand.
 * Scans for %name pattern. Skips '*' prefix for indirect operands.
 */
static uint8_t extract_x86_reg(const char *op)
{
    while (*op == ' ' || *op == '\t' || *op == '*') {
        op++;
    }

    const char *pct = strchr(op, '%');
    if (!pct) {
        return REG_NONE;
    }

    /* If there's a '(' before the %, this is a memory operand base */
    for (const char *p = op; p < pct; p++) {
        if (*p == '(') {
            return REG_NONE;
        }
    }

    pct++;
    char name[16];
    int i = 0;
    while (*pct && *pct != ',' && *pct != ')' && *pct != ' ' &&
           *pct != '\t' && i < 15) {
        name[i++] = *pct++;
    }
    name[i] = '\0';
    return parse_x86_reg(name);
}

/*
 * Extract address registers from an x86 AT&T memory operand.
 * Format: disp(%base,%index,scale)
 */
static void extract_x86_mem_regs(const char *op, InsnFields *out)
{
    const char *p = strchr(op, '(');
    if (!p) {
        return;
    }
    p++;

    while (*p && *p != ')') {
        if (*p == '%') {
            p++;
            char name[16];
            int i = 0;
            while (*p && *p != ',' && *p != ')' && *p != ' ' && i < 15) {
                name[i++] = *p++;
            }
            name[i] = '\0';
            uint8_t reg_id = parse_x86_reg(name);
            add_src_reg(out, reg_id);
        } else {
            p++;
        }
    }
}

/*
 * Extract the first register from an AArch64 operand.
 */
static uint8_t extract_aarch64_reg(const char *op)
{
    while (*op == ' ' || *op == '\t') {
        op++;
    }

    if (*op == '#' || *op == '=') {
        return REG_NONE;
    }
    if (*op == '[') {
        return REG_NONE;
    }

    char name[16];
    int i = 0;
    while (*op && *op != ',' && *op != ']' && *op != '!' &&
           *op != ' ' && *op != '\t' && i < 15) {
        name[i++] = *op++;
    }
    name[i] = '\0';
    return parse_aarch64_reg(name);
}

/*
 * Extract address registers from an AArch64 memory operand.
 * Format: [base, #imm] or [base, Xn]
 */
static void extract_aarch64_mem_regs(const char *op, InsnFields *out)
{
    const char *p = strchr(op, '[');
    if (!p) {
        return;
    }
    p++;

    while (*p == ' ' || *p == '\t') {
        p++;
    }

    char name[16];
    int i = 0;
    while (*p && *p != ',' && *p != ']' && *p != ' ' &&
           *p != '\t' && i < 15) {
        name[i++] = *p++;
    }
    name[i] = '\0';
    uint8_t base = parse_aarch64_reg(name);
    add_src_reg(out, base);

    /* Look for index register after comma */
    const char *bracket_end = strchr(op, ']');
    const char *comma = strchr(p, ',');
    if (comma && bracket_end && comma < bracket_end) {
        comma++;
        while (*comma == ' ' || *comma == '\t') {
            comma++;
        }
        if (*comma != '#') {
            i = 0;
            while (*comma && *comma != ',' && *comma != ']' &&
                   *comma != ' ' && i < 15) {
                name[i++] = *comma++;
            }
            name[i] = '\0';
            uint8_t idx = parse_aarch64_reg(name);
            add_src_reg(out, idx);
        }
    }
}

/*
 * Parse x86 AT&T operands and populate source/destination registers.
 * In AT&T syntax, source comes first, destination last.
 */
static void parse_x86_operands(const char *operands, InsnFields *out)
{
    char ops[MAX_OPS][MAX_OP_LEN];
    int n_ops = split_operands(operands, ops, MAX_OPS);

    if (n_ops == 0) {
        return;
    }

    bool op_is_mem[MAX_OPS];
    for (int i = 0; i < n_ops; i++) {
        op_is_mem[i] = is_memory_operand(ops[i]);
    }

    /* Adjust opcode for MOV with memory operand */
    if (out->opcode == GEN_OP_MOV && n_ops >= 2) {
        if (op_is_mem[0]) {
            out->opcode = GEN_OP_LOAD;
        } else if (op_is_mem[1]) {
            out->opcode = GEN_OP_STORE;
        }
    }

    /* Check for indirect branch/call (operand starts with '*') */
    if (out->branch_type == BRANCH_DIRECT_JUMP ||
        out->branch_type == BRANCH_DIRECT_CALL) {
        const char *t = ops[0];
        while (*t == ' ' || *t == '\t') {
            t++;
        }
        if (*t == '*') {
            out->branch_type = (out->branch_type == BRANCH_DIRECT_JUMP) ?
                               BRANCH_INDIRECT_JUMP : BRANCH_INDIRECT_CALL;
        }
    }

    switch (out->opcode) {
    /* Two-operand ALU: src, src+dst; FLAGS is dst */
    case GEN_OP_INT_ADD: case GEN_OP_INT_SUB: case GEN_OP_AND:
    case GEN_OP_OR: case GEN_OP_XOR: case GEN_OP_INT_ADC:
    case GEN_OP_INT_SBB: case GEN_OP_SHL: case GEN_OP_SHR:
    case GEN_OP_SAR: case GEN_OP_ROL: case GEN_OP_ROR:
        if (n_ops >= 2) {
            uint8_t src = extract_x86_reg(ops[0]);
            uint8_t dst = extract_x86_reg(ops[1]);
            if (src != REG_NONE) add_src_reg(out, src);
            if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
            if (dst != REG_NONE) {
                add_src_reg(out, dst);
                add_dst_reg(out, dst);
            }
            if (op_is_mem[1]) extract_x86_mem_regs(ops[1], out);
        } else if (n_ops == 1) {
            uint8_t r = extract_x86_reg(ops[0]);
            if (r != REG_NONE) { add_src_reg(out, r); add_dst_reg(out, r); }
            if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
        }
        add_dst_reg(out, REG_FLAGS);
        break;

    /* Data movement: src -> dst */
    case GEN_OP_MOV: case GEN_OP_MOVSX: case GEN_OP_MOVZX:
    case GEN_OP_CMOV:
        if (n_ops >= 2) {
            uint8_t src = extract_x86_reg(ops[0]);
            uint8_t dst = extract_x86_reg(ops[1]);
            if (src != REG_NONE) add_src_reg(out, src);
            if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
            if (dst != REG_NONE) add_dst_reg(out, dst);
            if (op_is_mem[1]) extract_x86_mem_regs(ops[1], out);
        }
        if (out->opcode == GEN_OP_CMOV) add_src_reg(out, REG_FLAGS);
        break;

    /* Load from memory */
    case GEN_OP_LOAD:
        if (n_ops >= 2) {
            if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
            uint8_t dst = extract_x86_reg(ops[n_ops - 1]);
            if (dst != REG_NONE) add_dst_reg(out, dst);
        }
        break;

    /* Store to memory */
    case GEN_OP_STORE:
        if (n_ops >= 2) {
            uint8_t src = extract_x86_reg(ops[0]);
            if (src != REG_NONE) add_src_reg(out, src);
            if (op_is_mem[n_ops - 1]) {
                extract_x86_mem_regs(ops[n_ops - 1], out);
            }
        }
        break;

    /* LEA: addr regs as sources, register as dest */
    case GEN_OP_LEA:
        if (n_ops >= 2) {
            extract_x86_mem_regs(ops[0], out);
            uint8_t dst = extract_x86_reg(ops[1]);
            if (dst != REG_NONE) add_dst_reg(out, dst);
        }
        break;

    /* CMP/TEST: both operands are sources, FLAGS is dst */
    case GEN_OP_CMP: case GEN_OP_TEST:
        for (int i = 0; i < n_ops && i < 2; i++) {
            uint8_t r = extract_x86_reg(ops[i]);
            if (r != REG_NONE) add_src_reg(out, r);
            if (op_is_mem[i]) extract_x86_mem_regs(ops[i], out);
        }
        add_dst_reg(out, REG_FLAGS);
        break;

    /* PUSH: src + SP */
    case GEN_OP_PUSH:
        if (n_ops >= 1) {
            uint8_t r = extract_x86_reg(ops[0]);
            if (r != REG_NONE) add_src_reg(out, r);
            if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
        }
        add_src_reg(out, REG_SP);
        add_dst_reg(out, REG_SP);
        break;

    /* POP: dst + SP */
    case GEN_OP_POP:
        if (n_ops >= 1) {
            uint8_t r = extract_x86_reg(ops[0]);
            if (r != REG_NONE) add_dst_reg(out, r);
        }
        add_src_reg(out, REG_SP);
        add_dst_reg(out, REG_SP);
        break;

    /* XCHG: both operands are src+dst */
    case GEN_OP_XCHG:
        for (int i = 0; i < n_ops && i < 2; i++) {
            uint8_t r = extract_x86_reg(ops[i]);
            if (r != REG_NONE) {
                add_src_reg(out, r);
                add_dst_reg(out, r);
            }
            if (op_is_mem[i]) extract_x86_mem_regs(ops[i], out);
        }
        break;

    /* Unary: operand is both src and dst */
    case GEN_OP_NOT: case GEN_OP_NEG: case GEN_OP_INC: case GEN_OP_DEC:
        if (n_ops >= 1) {
            uint8_t r = extract_x86_reg(ops[0]);
            if (r != REG_NONE) {
                add_src_reg(out, r);
                add_dst_reg(out, r);
            }
            if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
        }
        if (out->opcode != GEN_OP_NOT) add_dst_reg(out, REG_FLAGS);
        break;

    /* CALL: may have indirect operand */
    case GEN_OP_CALL:
    {
        if (n_ops >= 1) {
            const char *t = ops[0];
            while (*t == ' ' || *t == '\t') t++;
            if (*t == '*') {
                if (op_is_mem[0]) {
                    extract_x86_mem_regs(ops[0], out);
                } else {
                    uint8_t r = extract_x86_reg(ops[0]);
                    if (r != REG_NONE) add_src_reg(out, r);
                }
            }
        }
        add_src_reg(out, REG_SP);
        add_dst_reg(out, REG_SP);
        add_dst_reg(out, REG_IP);
        break;
    }

    /* RET */
    case GEN_OP_RET:
        add_src_reg(out, REG_SP);
        add_dst_reg(out, REG_SP);
        add_dst_reg(out, REG_IP);
        break;

    /* Branch */
    case GEN_OP_BRANCH:
        if (out->branch_type == BRANCH_COND_DIRECT) {
            add_src_reg(out, REG_FLAGS);
        }
        if (out->branch_type == BRANCH_INDIRECT_JUMP && n_ops >= 1) {
            const char *t = ops[0];
            while (*t == ' ' || *t == '\t') t++;
            if (*t == '*') {
                if (op_is_mem[0]) {
                    extract_x86_mem_regs(ops[0], out);
                } else {
                    uint8_t r = extract_x86_reg(ops[0]);
                    if (r != REG_NONE) add_src_reg(out, r);
                }
            }
        }
        break;

    /* MUL/IMUL */
    case GEN_OP_INT_MUL:
        if (n_ops >= 2) {
            for (int i = 0; i < n_ops; i++) {
                uint8_t r = extract_x86_reg(ops[i]);
                if (r != REG_NONE) add_src_reg(out, r);
                if (op_is_mem[i]) extract_x86_mem_regs(ops[i], out);
            }
            uint8_t dst = extract_x86_reg(ops[n_ops - 1]);
            if (dst != REG_NONE) add_dst_reg(out, dst);
        } else if (n_ops == 1) {
            add_src_reg(out, REG_GPR0);
            uint8_t r = extract_x86_reg(ops[0]);
            if (r != REG_NONE) add_src_reg(out, r);
            if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
            add_dst_reg(out, REG_GPR0);
            add_dst_reg(out, REG_GPR2);
        }
        add_dst_reg(out, REG_FLAGS);
        break;

    /* DIV/IDIV */
    case GEN_OP_INT_DIV:
        add_src_reg(out, REG_GPR0);
        add_src_reg(out, REG_GPR2);
        if (n_ops >= 1) {
            uint8_t r = extract_x86_reg(ops[0]);
            if (r != REG_NONE) add_src_reg(out, r);
            if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
        }
        add_dst_reg(out, REG_GPR0);
        add_dst_reg(out, REG_GPR2);
        break;

    /* SETCC: FLAGS as src */
    case GEN_OP_SETCC:
        add_src_reg(out, REG_FLAGS);
        if (n_ops >= 1) {
            uint8_t r = extract_x86_reg(ops[0]);
            if (r != REG_NONE) add_dst_reg(out, r);
            if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
        }
        break;

    /* FP/Vector: AT&T srcs first, dst last */
    case GEN_OP_FP_ADD: case GEN_OP_FP_SUB: case GEN_OP_FP_MUL:
    case GEN_OP_FP_DIV: case GEN_OP_FP_SQRT: case GEN_OP_FP_MOV:
    case GEN_OP_FP_CVT: case GEN_OP_FP_CMP:
    case GEN_OP_VEC_ADD: case GEN_OP_VEC_SUB: case GEN_OP_VEC_MUL:
    case GEN_OP_VEC_MOV: case GEN_OP_VEC_SHUF: case GEN_OP_VEC_LOGIC:
        for (int i = 0; i < n_ops; i++) {
            uint8_t r = extract_x86_reg(ops[i]);
            if (r != REG_NONE) {
                if (i < n_ops - 1) {
                    add_src_reg(out, r);
                } else {
                    /*
                     * Last operand is the destination. For 2-operand SSE
                     * it is also an implicit source (e.g. addps %xmm0,%xmm1
                     * means xmm1 += xmm0). Conservative for 3-operand AVX.
                     */
                    add_src_reg(out, r);
                    add_dst_reg(out, r);
                }
            }
            if (op_is_mem[i]) extract_x86_mem_regs(ops[i], out);
        }
        if (out->opcode == GEN_OP_FP_CMP) add_dst_reg(out, REG_FLAGS);
        break;

    default:
        break;
    }

    /* Extract immediate value from operands */
    for (int i = 0; i < n_ops; i++) {
        const char *t = ops[i];
        while (*t == ' ' || *t == '\t') t++;
        if (*t == '$') {
            out->has_immediate = true;
            out->immediate = strtoll(t + 1, NULL, 0);
            break;
        }
    }
}

/*
 * Parse AArch64 operands and populate source/destination registers.
 * First operand is typically destination, rest are sources.
 */
static void parse_aarch64_operands(const char *operands, InsnFields *out)
{
    char ops[MAX_OPS][MAX_OP_LEN];
    int n_ops = split_operands(operands, ops, MAX_OPS);

    if (n_ops == 0) {
        return;
    }

    switch (out->opcode) {
    /* ALU: dst = op(src1, src2) */
    case GEN_OP_INT_ADD: case GEN_OP_INT_SUB: case GEN_OP_INT_MUL:
    case GEN_OP_INT_DIV: case GEN_OP_AND: case GEN_OP_OR:
    case GEN_OP_XOR: case GEN_OP_NOT: case GEN_OP_SHL:
    case GEN_OP_SHR: case GEN_OP_SAR:
    {
        if (n_ops >= 1) {
            uint8_t dst = extract_aarch64_reg(ops[0]);
            if (dst != REG_NONE) add_dst_reg(out, dst);
        }
        for (int i = 1; i < n_ops; i++) {
            uint8_t src = extract_aarch64_reg(ops[i]);
            if (src != REG_NONE) add_src_reg(out, src);
        }
        break;
    }

    /* MOV: dst, src */
    case GEN_OP_MOV: case GEN_OP_MOVSX: case GEN_OP_MOVZX:
    case GEN_OP_CMOV:
    {
        if (n_ops >= 1) {
            uint8_t dst = extract_aarch64_reg(ops[0]);
            if (dst != REG_NONE) add_dst_reg(out, dst);
        }
        for (int i = 1; i < n_ops; i++) {
            uint8_t src = extract_aarch64_reg(ops[i]);
            if (src != REG_NONE) add_src_reg(out, src);
        }
        break;
    }

    /* LOAD: dst, [base, offset] */
    case GEN_OP_LOAD:
    {
        if (n_ops >= 1) {
            uint8_t dst = extract_aarch64_reg(ops[0]);
            if (dst != REG_NONE) add_dst_reg(out, dst);
        }
        /* For ldp: second operand is also a dest */
        if (n_ops >= 3) {
            uint8_t dst2 = extract_aarch64_reg(ops[1]);
            if (dst2 != REG_NONE) add_dst_reg(out, dst2);
        }
        for (int i = 0; i < n_ops; i++) {
            if (is_memory_operand(ops[i])) {
                extract_aarch64_mem_regs(ops[i], out);
            }
        }
        break;
    }

    /* STORE: src, [base, offset] */
    case GEN_OP_STORE:
    {
        if (n_ops >= 1) {
            uint8_t src = extract_aarch64_reg(ops[0]);
            if (src != REG_NONE) add_src_reg(out, src);
        }
        /* For stp: second operand is also a source */
        if (n_ops >= 3) {
            uint8_t src2 = extract_aarch64_reg(ops[1]);
            if (src2 != REG_NONE) add_src_reg(out, src2);
        }
        for (int i = 0; i < n_ops; i++) {
            if (is_memory_operand(ops[i])) {
                extract_aarch64_mem_regs(ops[i], out);
            }
        }
        break;
    }

    /* CMP/TST: all operands are sources */
    case GEN_OP_CMP: case GEN_OP_TEST:
        for (int i = 0; i < n_ops; i++) {
            uint8_t r = extract_aarch64_reg(ops[i]);
            if (r != REG_NONE) add_src_reg(out, r);
        }
        add_dst_reg(out, REG_FLAGS);
        break;

    /* Branch: operand is src register or target */
    case GEN_OP_BRANCH:
        for (int i = 0; i < n_ops; i++) {
            uint8_t r = extract_aarch64_reg(ops[i]);
            if (r != REG_NONE) add_src_reg(out, r);
        }
        break;

    /* CALL (bl/blr): link register is dst */
    case GEN_OP_CALL:
        if (out->branch_type == BRANCH_INDIRECT_CALL && n_ops >= 1) {
            uint8_t r = extract_aarch64_reg(ops[0]);
            if (r != REG_NONE) add_src_reg(out, r);
        }
        add_dst_reg(out, REG_LR);
        break;

    /* RET */
    case GEN_OP_RET:
        add_src_reg(out, REG_LR);
        break;

    /* FP/Vector: dst, src1, src2 */
    case GEN_OP_FP_ADD: case GEN_OP_FP_SUB: case GEN_OP_FP_MUL:
    case GEN_OP_FP_DIV: case GEN_OP_FP_SQRT: case GEN_OP_FP_MOV:
    case GEN_OP_FP_CVT: case GEN_OP_FP_CMP:
    {
        if (out->opcode == GEN_OP_FP_CMP) {
            for (int i = 0; i < n_ops; i++) {
                uint8_t r = extract_aarch64_reg(ops[i]);
                if (r != REG_NONE) add_src_reg(out, r);
            }
            add_dst_reg(out, REG_FLAGS);
        } else {
            if (n_ops >= 1) {
                uint8_t dst = extract_aarch64_reg(ops[0]);
                if (dst != REG_NONE) add_dst_reg(out, dst);
            }
            for (int i = 1; i < n_ops; i++) {
                uint8_t src = extract_aarch64_reg(ops[i]);
                if (src != REG_NONE) add_src_reg(out, src);
            }
        }
        break;
    }

    default:
        if (n_ops >= 1) {
            uint8_t dst = extract_aarch64_reg(ops[0]);
            if (dst != REG_NONE) add_dst_reg(out, dst);
        }
        for (int i = 1; i < n_ops; i++) {
            uint8_t src = extract_aarch64_reg(ops[i]);
            if (src != REG_NONE) add_src_reg(out, src);
        }
        break;
    }

    /* Extract immediate value (#N) */
    for (int i = 0; i < n_ops; i++) {
        const char *t = ops[i];
        while (*t == ' ' || *t == '\t') t++;
        if (*t == '#') {
            out->has_immediate = true;
            out->immediate = strtoll(t + 1, NULL, 0);
            break;
        }
    }
}

/*
 * Decode a disassembly string into ISA-agnostic InsnFields.
 * Uses the disassembly from qemu_plugin_insn_disas().
 */
static void decode_disas_to_generic(const char *disas, InsnFields *out)
{
    memset(out, 0, sizeof(*out));

    if (!disas || !*disas) {
        return;
    }

    /* Extract mnemonic (first space-delimited token) */
    char mnem[64];
    const char *p = disas;
    int i = 0;
    while (*p && *p != ' ' && *p != '\t' && i < 63) {
        mnem[i++] = *p++;
    }
    mnem[i] = '\0';

    /* Classify mnemonic -> opcode + branch_type */
    classify_mnemonic(mnem, &out->opcode, &out->branch_type);

    /* Skip whitespace to get to operands */
    while (*p == ' ' || *p == '\t') {
        p++;
    }

    /* Parse operands for register and immediate extraction */
    if (*p) {
        if (is_x86) {
            parse_x86_operands(p, out);
        } else {
            parse_aarch64_operands(p, out);
        }
    }
}

/* ========================= String Helpers for Text Output ========================= */

static const char *generic_opcode_name(uint8_t op)
{
    static const char *names[] = {
        [GEN_OP_UNKNOWN]  = "UNKNOWN",
        [GEN_OP_INT_ADD]  = "INT_ADD",
        [GEN_OP_INT_SUB]  = "INT_SUB",
        [GEN_OP_INT_MUL]  = "INT_MUL",
        [GEN_OP_INT_DIV]  = "INT_DIV",
        [GEN_OP_AND]      = "AND",
        [GEN_OP_OR]       = "OR",
        [GEN_OP_XOR]      = "XOR",
        [GEN_OP_NOT]      = "NOT",
        [GEN_OP_SHL]      = "SHL",
        [GEN_OP_SHR]      = "SHR",
        [GEN_OP_SAR]      = "SAR",
        [GEN_OP_ROL]      = "ROL",
        [GEN_OP_ROR]      = "ROR",
        [GEN_OP_MOV]      = "MOV",
        [GEN_OP_LOAD]     = "LOAD",
        [GEN_OP_STORE]    = "STORE",
        [GEN_OP_PUSH]     = "PUSH",
        [GEN_OP_POP]      = "POP",
        [GEN_OP_LEA]      = "LEA",
        [GEN_OP_MOVSX]    = "MOVSX",
        [GEN_OP_MOVZX]    = "MOVZX",
        [GEN_OP_XCHG]     = "XCHG",
        [GEN_OP_CMP]      = "CMP",
        [GEN_OP_TEST]     = "TEST",
        [GEN_OP_BRANCH]   = "BRANCH",
        [GEN_OP_CALL]     = "CALL",
        [GEN_OP_RET]      = "RET",
        [GEN_OP_FP_ADD]   = "FP_ADD",
        [GEN_OP_FP_SUB]   = "FP_SUB",
        [GEN_OP_FP_MUL]   = "FP_MUL",
        [GEN_OP_FP_DIV]   = "FP_DIV",
        [GEN_OP_FP_SQRT]  = "FP_SQRT",
        [GEN_OP_FP_MOV]   = "FP_MOV",
        [GEN_OP_FP_CVT]   = "FP_CVT",
        [GEN_OP_FP_CMP]   = "FP_CMP",
        [GEN_OP_VEC_ADD]  = "VEC_ADD",
        [GEN_OP_VEC_SUB]  = "VEC_SUB",
        [GEN_OP_VEC_MUL]  = "VEC_MUL",
        [GEN_OP_VEC_MOV]  = "VEC_MOV",
        [GEN_OP_VEC_SHUF] = "VEC_SHUF",
        [GEN_OP_VEC_LOGIC] = "VEC_LOGIC",
        [GEN_OP_NOP]      = "NOP",
        [GEN_OP_SYSCALL]  = "SYSCALL",
        [GEN_OP_FENCE]    = "FENCE",
        [GEN_OP_CMOV]     = "CMOV",
        [GEN_OP_SETCC]    = "SETCC",
        [GEN_OP_INT_ADC]  = "INT_ADC",
        [GEN_OP_INT_SBB]  = "INT_SBB",
        [GEN_OP_NEG]      = "NEG",
        [GEN_OP_INC]      = "INC",
        [GEN_OP_DEC]      = "DEC",
    };
    return (op < GEN_OP_COUNT) ? names[op] : "UNKNOWN";
}

static const char *branch_type_name(uint8_t bt)
{
    static const char *names[] = {
        [BRANCH_NONE]          = "NONE",
        [BRANCH_DIRECT_JUMP]   = "DIRECT_JUMP",
        [BRANCH_INDIRECT_JUMP] = "INDIRECT_JUMP",
        [BRANCH_DIRECT_CALL]   = "DIRECT_CALL",
        [BRANCH_INDIRECT_CALL] = "INDIRECT_CALL",
        [BRANCH_RETURN]        = "RETURN",
        [BRANCH_COND_DIRECT]   = "COND_DIRECT",
        [BRANCH_SYSCALL_TYPE]  = "SYSCALL",
    };
    return (bt <= BRANCH_SYSCALL_TYPE) ? names[bt] : "UNKNOWN";
}

static const char *generic_reg_name(uint8_t reg_id)
{
    static char buf[16];

    if (reg_id == REG_NONE) {
        return "NONE";
    }
    if (reg_id >= REG_GPR0 && reg_id <= REG_GPR31) {
        snprintf(buf, sizeof(buf), "GPR%u", reg_id - REG_GPR0);
        return buf;
    }
    if (reg_id >= REG_FPR0 && reg_id <= REG_FPR0 + 31) {
        snprintf(buf, sizeof(buf), "FPR%u", reg_id - REG_FPR0);
        return buf;
    }
    if (reg_id >= REG_VEC0 && reg_id <= REG_VEC0 + 31) {
        snprintf(buf, sizeof(buf), "VEC%u", reg_id - REG_VEC0);
        return buf;
    }
    switch (reg_id) {
    case REG_SP:      return "SP";
    case REG_FLAGS:   return "FLAGS";
    case REG_IP:      return "IP";
    case REG_LR:      return "LR";
    case REG_FP_REG:  return "FP";
    default:
        snprintf(buf, sizeof(buf), "R%u", reg_id);
        return buf;
    }
}

/* ========================= Data Structures ========================= */

/*
 * BB Template - static instruction context for a unique basic block.
 * Each instruction is represented by its PC and ISA-agnostic decoded fields.
 */
typedef struct {
    uint32_t template_id;
    uint64_t start_pc;
    uint32_t n_insns;
    uint64_t *insn_pcs;
    uint64_t fall_through_pc;
    InsnFields *insn_fields;    /* Decoded ISA-agnostic fields per insn */
} BBTemplate;

/*
 * Dynamic parameter types for body entries.
 */
enum DynParamType {
    DYN_BRANCH_TARGET = 0,     /* Branch target address */
    DYN_LOAD_ADDR = 1,         /* Load memory address */
    DYN_STORE_ADDR = 2,        /* Store memory address */
};

typedef struct {
    uint8_t type;               /* DynParamType */
    uint64_t value;             /* Address value */
} DynParam;

/*
 * Wrong-path BB entry within a body entry.
 * Represents one BB executed on the wrong path.
 */
typedef struct {
    uint32_t template_id;       /* BB template ID (or UINT32_MAX if new) */
    uint64_t start_pc;          /* Start PC (for identification) */
    GArray *dyn_params;         /* GArray of DynParam */
    uint32_t n_insns_executed;  /* Number of insns executed in this WP BB */
    bool exception;             /* True if WP BB ended due to exception */
} WPBBEntry;

/*
 * Body entry - one correct-path BB execution.
 */
typedef struct {
    uint32_t seq_num;           /* Sequence number in trace */
    uint32_t template_id;       /* BB template ID */
    GArray *dyn_params;         /* GArray of DynParam (correct-path) */
    GArray *wp_entries;         /* GArray of WPBBEntry (wrong-path chain) */
} BodyEntry;

/*
 * Per-vCPU scoreboard for tracking execution state between blocks.
 */
typedef struct {
    uint64_t current_pc;        /* Current block's start PC */
    uint64_t prev_last_pc;      /* Last insn PC of previous block */
    uint64_t prev_fall_through; /* Expected sequential next from prev block */
    uint64_t insn_count;        /* Total instructions executed */
} VCPUScoreBoard;

/*
 * Branch record for Smith predictor.
 */
typedef struct {
    uint64_t pc;                /* Branch instruction PC */
    uint64_t fall_through;      /* Sequential next PC */
    uint64_t taken_target;      /* Observed taken target */
    bool has_taken_target;      /* Whether taken target has been seen */
    uint8_t smith_counter;      /* 2-bit saturating counter (0-3) */
} BranchRecord;

/*
 * Memory access during wrong-path execution.
 */
typedef struct {
    uint64_t insn_pc;           /* PC of the instruction making the access */
    uint64_t mem_vaddr;         /* Virtual address of the memory access */
    bool is_store;              /* Whether this was a store operation */
} WPMemAccess;

/*
 * Trace state - collects body entries for a single trace segment.
 */
typedef struct {
    GArray *body_entries;       /* GArray of BodyEntry */
    uint64_t start_insn;        /* Instruction number at trace start */
    uint64_t stop_insn;         /* Instruction number at trace end */
    char *label;                /* Label for output file naming */
    FILE *text_file;            /* Debug text output (NULL if disabled) */
    FILE *bin_file;             /* Binary output */
} TraceSegment;

/* ========================= Global State ========================= */

static GMutex data_lock;
static GHashTable *template_map;    /* start_pc (uint64*) → BBTemplate* */
static GHashTable *branch_map;      /* branch_pc (uint64*) → BranchRecord* */
static uint32_t next_template_id = 1;

/* Per-vCPU scoreboard */
static struct qemu_plugin_scoreboard *vcpu_sb;
static qemu_plugin_u64 sb_current_pc;
static qemu_plugin_u64 sb_prev_last_pc;
static qemu_plugin_u64 sb_prev_fall_through;
static qemu_plugin_u64 sb_insn_count;

/* Tracing state */
static bool trace_active = false;
static TraceSegment *current_segment = NULL;
static uint32_t body_seq_num = 0;

/* Wrong-path execution state */
static bool wp_in_progress = false;
static GArray *wp_mem_accesses = NULL;
static uint64_t wp_current_insn_pc = 0;

/* Correct-path memory accesses for current BB */
static GArray *cp_mem_accesses = NULL;

/* Statistics */
static uint64_t stat_blocks_translated;
static uint64_t stat_branches_observed;
static uint64_t stat_branches_taken;
static uint64_t stat_branches_not_taken;
static uint64_t stat_wp_simulations;
static uint64_t stat_wp_skipped;
static uint64_t stat_wp_total_insns;
static uint64_t stat_wp_early_exits;
static uint64_t stat_wp_total_mem_accesses;

/* ========================= Smith Predictor ========================= */

static inline uint8_t smith_update(uint8_t counter, bool taken)
{
    if (taken && counter < 3) {
        return counter + 1;
    } else if (!taken && counter > 0) {
        return counter - 1;
    }
    return counter;
}

/* ========================= Memory Management ========================= */

static void dyn_param_array_free(GArray *arr)
{
    if (arr) {
        g_array_unref(arr);
    }
}

static void wp_bb_entry_clear(WPBBEntry *entry)
{
    dyn_param_array_free(entry->dyn_params);
}

static void body_entry_clear(BodyEntry *entry)
{
    dyn_param_array_free(entry->dyn_params);
    if (entry->wp_entries) {
        for (guint i = 0; i < entry->wp_entries->len; i++) {
            wp_bb_entry_clear(&g_array_index(entry->wp_entries, WPBBEntry, i));
        }
        g_array_unref(entry->wp_entries);
    }
}

static void bb_template_free(gpointer data)
{
    BBTemplate *tmpl = data;
    g_free(tmpl->insn_fields);
    g_free(tmpl->insn_pcs);
    g_free(tmpl);
}

static TraceSegment *trace_segment_new(const char *label,
                                       uint64_t start, uint64_t stop)
{
    TraceSegment *seg = g_new0(TraceSegment, 1);
    seg->body_entries = g_array_new(false, false, sizeof(BodyEntry));
    seg->start_insn = start;
    seg->stop_insn = stop;
    seg->label = g_strdup(label);
    return seg;
}

static void trace_segment_free(TraceSegment *seg)
{
    if (!seg) {
        return;
    }
    for (guint i = 0; i < seg->body_entries->len; i++) {
        body_entry_clear(&g_array_index(seg->body_entries, BodyEntry, i));
    }
    g_array_unref(seg->body_entries);
    if (seg->text_file) {
        fclose(seg->text_file);
    }
    if (seg->bin_file) {
        fclose(seg->bin_file);
    }
    g_free(seg->label);
    g_free(seg);
}

/* ========================= BB Template Management ========================= */

/*
 * Look up a template by start PC.
 * Must be called with data_lock held.
 */
static BBTemplate *find_template(uint64_t start_pc)
{
    return g_hash_table_lookup(template_map, &start_pc);
}

/*
 * Find or create a BB template for the given start PC.
 * If a template already exists for this PC, returns it.
 * Otherwise creates a new one with the given instruction data.
 *
 * Must be called with data_lock held.
 */
static BBTemplate *get_or_create_template(uint64_t start_pc,
                                          uint32_t n_insns,
                                          uint64_t *insn_pcs,
                                          char **insn_disas,
                                          uint64_t fall_through_pc)
{
    BBTemplate *tmpl = find_template(start_pc);
    if (tmpl) {
        return tmpl;
    }

    tmpl = g_new0(BBTemplate, 1);
    tmpl->template_id = next_template_id++;
    tmpl->start_pc = start_pc;
    tmpl->n_insns = n_insns;
    tmpl->fall_through_pc = fall_through_pc;
    tmpl->insn_pcs = g_new0(uint64_t, n_insns);

    for (uint32_t i = 0; i < n_insns; i++) {
        tmpl->insn_pcs[i] = insn_pcs[i];
    }

    /* Decode all instructions to ISA-agnostic generic fields */
    tmpl->insn_fields = g_new0(InsnFields, n_insns);
    for (uint32_t i = 0; i < n_insns; i++) {
        if (insn_disas && insn_disas[i]) {
            decode_disas_to_generic(insn_disas[i], &tmpl->insn_fields[i]);
        }
    }

    g_hash_table_replace(template_map, &tmpl->start_pc, tmpl);
    stat_blocks_translated++;
    return tmpl;
}

/* ========================= Memory Access Tracking ========================= */

/*
 * Per-instruction memory access callback.
 * During wrong-path execution (wp_in_progress), records data addresses.
 * During correct-path execution with tracing active, records data addresses.
 */
static void vcpu_mem_cb(unsigned int cpu_index,
                        qemu_plugin_meminfo_t info,
                        uint64_t vaddr,
                        void *udata)
{
    uint64_t insn_pc = (uint64_t)(uintptr_t)udata;

    if (wp_in_progress && wp_mem_accesses) {
        WPMemAccess acc = {
            .insn_pc = wp_current_insn_pc ? wp_current_insn_pc : insn_pc,
            .mem_vaddr = vaddr,
            .is_store = qemu_plugin_mem_is_store(info),
        };
        g_array_append_val(wp_mem_accesses, acc);
        return;
    }

    if (trace_active && cp_mem_accesses) {
        WPMemAccess acc = {
            .insn_pc = insn_pc,
            .mem_vaddr = vaddr,
            .is_store = qemu_plugin_mem_is_store(info),
        };
        g_array_append_val(cp_mem_accesses, acc);
    }
}

/* ========================= Wrong-Path Simulation ========================= */

/*
 * Create a WPBBEntry from a sequence of wrong-path instructions.
 * Groups consecutive instructions into a BB and matches to a template.
 */
static WPBBEntry create_wp_bb_entry(uint64_t bb_start_pc,
                                    GArray *insn_pcs_arr,
                                    GArray *insn_sizes_arr,
                                    GArray *mem_accesses,
                                    guint mem_start_idx)
{
    WPBBEntry entry;
    uint32_t n_insns = insn_pcs_arr->len;

    entry.start_pc = bb_start_pc;
    entry.dyn_params = g_array_new(false, false, sizeof(DynParam));
    entry.n_insns_executed = n_insns;
    entry.exception = false;

    /* Try to find existing template */
    g_mutex_lock(&data_lock);
    BBTemplate *tmpl = find_template(bb_start_pc);

    if (!tmpl && n_insns > 0) {
        /* Create template from wrong-path data (no disassembly available) */
        uint64_t *pcs = g_new0(uint64_t, n_insns);
        uint64_t ft_pc = 0;

        for (uint32_t i = 0; i < n_insns; i++) {
            pcs[i] = g_array_index(insn_pcs_arr, uint64_t, i);
        }
        uint32_t last_size = g_array_index(insn_sizes_arr, uint32_t,
                                            n_insns - 1);
        ft_pc = pcs[n_insns - 1] + last_size;

        tmpl = get_or_create_template(bb_start_pc, n_insns, pcs,
                                      NULL, ft_pc);

        g_free(pcs);
    }

    entry.template_id = tmpl ? tmpl->template_id : UINT32_MAX;
    g_mutex_unlock(&data_lock);

    /* Collect memory access dynamic params for this WP BB */
    if (mem_accesses) {
        for (guint m = mem_start_idx; m < mem_accesses->len; m++) {
            WPMemAccess *acc = &g_array_index(mem_accesses, WPMemAccess, m);
            /* Check if this access belongs to an instruction in this BB */
            bool in_bb = false;
            for (uint32_t i = 0; i < n_insns; i++) {
                if (acc->insn_pc == g_array_index(insn_pcs_arr, uint64_t, i)) {
                    in_bb = true;
                    break;
                }
            }
            if (in_bb) {
                DynParam dp = {
                    .type = acc->is_store ? DYN_STORE_ADDR : DYN_LOAD_ADDR,
                    .value = acc->mem_vaddr,
                };
                g_array_append_val(entry.dyn_params, dp);
            }
        }
    }

    return entry;
}

/*
 * Derive instruction size from consecutive PCs in a BB template.
 * For the last instruction, uses fall_through_pc.
 */
static inline uint32_t template_insn_size(const BBTemplate *tmpl, uint32_t idx)
{
    if (idx >= tmpl->n_insns) {
        return 0;
    }
    if (idx + 1 < tmpl->n_insns) {
        return (uint32_t)(tmpl->insn_pcs[idx + 1] - tmpl->insn_pcs[idx]);
    }
    return (uint32_t)(tmpl->fall_through_pc - tmpl->insn_pcs[idx]);
}

/*
 * Execute wrong-path instructions starting from @wrong_target.
 * Returns a GArray of WPBBEntry representing the wrong-path BB chain.
 */
static GArray *simulate_wrong_path_ext(uint64_t branch_pc,
                                       uint64_t correct_target,
                                       uint64_t wrong_target,
                                       unsigned int cpu_index)
{
    GArray *wp_chain = g_array_new(false, false, sizeof(WPBBEntry));
    uint64_t sim_insns = 0;
    bool early_exit = false;
    GByteArray *insn_buf = g_byte_array_new();

    /* State for grouping instructions into BBs */
    GArray *bb_insn_pcs = g_array_new(false, false, sizeof(uint64_t));
    GArray *bb_insn_sizes = g_array_new(false, false, sizeof(uint32_t));
    uint64_t bb_start_pc = wrong_target;
    guint bb_mem_start_idx = 0;

    /* Save complete CPU state for rollback */
    struct qemu_plugin_cpu_state *saved_state = qemu_plugin_cpu_state_save();
    if (!saved_state) {
        stat_wp_early_exits++;
        stat_wp_simulations++;
        g_byte_array_unref(insn_buf);
        g_array_unref(bb_insn_pcs);
        g_array_unref(bb_insn_sizes);
        return wp_chain;
    }

    /* Initialize wrong-path memory access collection */
    wp_mem_accesses = g_array_new(false, false, sizeof(WPMemAccess));
    wp_in_progress = true;

    /* Enter speculative mode, providing saved state for exception recovery */
    qemu_plugin_spec_mode_begin(saved_state);

    /* Set PC to wrong-path target */
    qemu_plugin_set_pc(wrong_target);

    for (int depth = 0; depth < max_wrong_path_depth; depth++) {
        uint64_t pre_pc = qemu_plugin_get_pc();

        /* Read instruction bytes at current PC */
        g_byte_array_set_size(insn_buf, 0);
        qemu_plugin_read_memory_vaddr(pre_pc, insn_buf, MAX_INSN_BYTES);

        wp_current_insn_pc = pre_pc;

        /* Execute exactly one instruction */
        if (!qemu_plugin_exec_inline_insn()) {
            early_exit = true;
            break;
        }

        sim_insns++;
        uint64_t post_pc = qemu_plugin_get_pc();

        /* Determine instruction size */
        uint32_t insn_size;
        bool is_sequential;
        if (post_pc > pre_pc && (post_pc - pre_pc) <= MAX_INSN_BYTES) {
            insn_size = (uint32_t)(post_pc - pre_pc);
            is_sequential = true;
        } else {
            /* Branch or backwards jump - use template_map if available */
            g_mutex_lock(&data_lock);
            BBTemplate *known = find_template(bb_start_pc);
            g_mutex_unlock(&data_lock);

            insn_size = 0;
            if (known) {
                uint32_t idx_in_bb = bb_insn_pcs->len;
                if (idx_in_bb < known->n_insns) {
                    insn_size = template_insn_size(known, idx_in_bb);
                }
            }
            if (insn_size == 0) {
                insn_size = insn_buf->len < MAX_INSN_BYTES ?
                            insn_buf->len : MAX_INSN_BYTES;
            }
            is_sequential = false;
        }

        /* Record instruction in current BB */
        g_array_append_val(bb_insn_pcs, pre_pc);
        g_array_append_val(bb_insn_sizes, insn_size);

        /* Track memory accesses */
        for (guint m = bb_mem_start_idx; m < wp_mem_accesses->len; m++) {
            WPMemAccess *acc = &g_array_index(wp_mem_accesses, WPMemAccess, m);
            if (acc->insn_pc == pre_pc) {
                stat_wp_total_mem_accesses++;
            }
        }

        /* Check for BB boundary (non-sequential PC) */
        if (!is_sequential) {
            /* Finalize current WP BB */
            WPBBEntry wp_bb = create_wp_bb_entry(
                bb_start_pc, bb_insn_pcs, bb_insn_sizes,
                wp_mem_accesses, bb_mem_start_idx);

            /* Add branch target as dynamic param */
            DynParam target_dp = {
                .type = DYN_BRANCH_TARGET,
                .value = post_pc,
            };
            g_array_append_val(wp_bb.dyn_params, target_dp);
            g_array_append_val(wp_chain, wp_bb);

            /* Start new BB */
            bb_mem_start_idx = wp_mem_accesses->len;
            g_array_set_size(bb_insn_pcs, 0);
            g_array_set_size(bb_insn_sizes, 0);
            bb_start_pc = post_pc;
        }
    }

    /* Finalize any remaining instructions as a WP BB */
    if (bb_insn_pcs->len > 0) {
        WPBBEntry wp_bb = create_wp_bb_entry(
            bb_start_pc, bb_insn_pcs, bb_insn_sizes,
            wp_mem_accesses, bb_mem_start_idx);
        if (early_exit) {
            wp_bb.exception = true;
        }
        g_array_append_val(wp_chain, wp_bb);
    } else if (early_exit && wp_chain->len > 0) {
        /* Exception on first insn of new BB - mark previous BB */
        WPBBEntry *last = &g_array_index(wp_chain, WPBBEntry,
                                          wp_chain->len - 1);
        last->exception = true;
    }

    /* Stop wrong-path collection */
    wp_in_progress = false;

    /* Exit speculative mode */
    qemu_plugin_spec_mode_end();

    /* Restore CPU state */
    qemu_plugin_cpu_state_restore(saved_state);
    qemu_plugin_cpu_state_free(saved_state);

    /* Clean up */
    g_array_unref(wp_mem_accesses);
    wp_mem_accesses = NULL;
    g_byte_array_unref(insn_buf);

    g_array_unref(bb_insn_pcs);
    g_array_unref(bb_insn_sizes);

    /* Update statistics */
    stat_wp_simulations++;
    stat_wp_total_insns += sim_insns;
    if (early_exit) {
        stat_wp_early_exits++;
    }

    return wp_chain;
}

/* ========================= Output: Text Format ========================= */

/*
 * Write the header section (BB templates) in human-readable text format.
 */
static void write_text_header(FILE *f)
{
    if (!f) {
        return;
    }
    GHashTableIter iter;
    gpointer value;

    fprintf(f, "HEADER\n------\n");

    g_hash_table_iter_init(&iter, template_map);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        BBTemplate *tmpl = value;
        fprintf(f, "BB%" PRIu32 " [pc=0x%" PRIx64 ", insns=%" PRIu32
                ", fall_through=0x%" PRIx64 "]\n",
                tmpl->template_id, tmpl->start_pc,
                tmpl->n_insns, tmpl->fall_through_pc);

        for (uint32_t i = 0; i < tmpl->n_insns; i++) {
            InsnFields *fld = &tmpl->insn_fields[i];
            fprintf(f, "  [%u] 0x%" PRIx64 ": op=%s",
                    i, tmpl->insn_pcs[i], generic_opcode_name(fld->opcode));

            if (fld->branch_type != BRANCH_NONE) {
                fprintf(f, " br=%s", branch_type_name(fld->branch_type));
            }

            fprintf(f, " src=[");
            for (uint8_t s = 0; s < fld->n_src_regs; s++) {
                if (s > 0) fprintf(f, ",");
                fprintf(f, "%s", generic_reg_name(fld->src_regs[s]));
            }
            fprintf(f, "] dst=[");
            for (uint8_t d = 0; d < fld->n_dst_regs; d++) {
                if (d > 0) fprintf(f, ",");
                fprintf(f, "%s", generic_reg_name(fld->dst_regs[d]));
            }
            fprintf(f, "]");

            if (fld->has_immediate) {
                fprintf(f, " imm=%" PRId64, fld->immediate);
            }
            fprintf(f, "\n");
        }
        fprintf(f, "\n");
    }
}

/*
 * Write the body section (execution trace) in human-readable text format.
 */
static void write_text_body(FILE *f, GArray *body_entries)
{
    if (!f) {
        return;
    }
    fprintf(f, "BODY\n----\n");

    for (guint i = 0; i < body_entries->len; i++) {
        BodyEntry *entry = &g_array_index(body_entries, BodyEntry, i);

        fprintf(f, "%04u BB%" PRIu32 " [",
                entry->seq_num, entry->template_id);

        /* Write dynamic parameters */
        for (guint d = 0; d < entry->dyn_params->len; d++) {
            DynParam *dp = &g_array_index(entry->dyn_params, DynParam, d);
            if (d > 0) {
                fprintf(f, " ");
            }
            switch (dp->type) {
            case DYN_BRANCH_TARGET:
                fprintf(f, "target=0x%" PRIx64, dp->value);
                break;
            case DYN_LOAD_ADDR:
                fprintf(f, "load=0x%" PRIx64, dp->value);
                break;
            case DYN_STORE_ADDR:
                fprintf(f, "store=0x%" PRIx64, dp->value);
                break;
            }
        }
        fprintf(f, "]");

        /* Write wrong-path BB chain */
        if (entry->wp_entries) {
            for (guint w = 0; w < entry->wp_entries->len; w++) {
                WPBBEntry *wp = &g_array_index(entry->wp_entries,
                                               WPBBEntry, w);
                if (wp->template_id != UINT32_MAX) {
                    fprintf(f, " [wp%u=BB%" PRIu32, w, wp->template_id);
                } else {
                    fprintf(f, " [wp%u=0x%" PRIx64, w, wp->start_pc);
                }

                /* WP dynamic params */
                for (guint d = 0; d < wp->dyn_params->len; d++) {
                    DynParam *dp = &g_array_index(wp->dyn_params,
                                                  DynParam, d);
                    switch (dp->type) {
                    case DYN_BRANCH_TARGET:
                        fprintf(f, " target=0x%" PRIx64, dp->value);
                        break;
                    case DYN_LOAD_ADDR:
                        fprintf(f, " load=0x%" PRIx64, dp->value);
                        break;
                    case DYN_STORE_ADDR:
                        fprintf(f, " store=0x%" PRIx64, dp->value);
                        break;
                    }
                }
                if (wp->exception) {
                    fprintf(f, " EXCEPTION");
                }
                fprintf(f, " n_insns=%" PRIu32, wp->n_insns_executed);
                fprintf(f, "]");
            }
        }
        fprintf(f, "\n");
    }
}

/*
 * Write a complete trace in text format (header + body).
 */
static void write_text_trace(FILE *f, GArray *body_entries)
{
    g_mutex_lock(&data_lock);
    write_text_header(f);
    g_mutex_unlock(&data_lock);
    write_text_body(f, body_entries);
}

/* ========================= Output: Binary Format ========================= */

/*
 * Helper to write packed little-endian values.
 */
static void write_uleb128(FILE *f, uint64_t v)
{
    if (!f) {
        return;
    }
    do {
        uint8_t byte = v & 0x7F;
        v >>= 7;
        if (v != 0) {
            byte |= 0x80;
        }
        fwrite(&byte, 1, 1, f);
    } while (v != 0);
}

static inline void write_u8(FILE *f, uint8_t v)
{
    if (!f) {
        return;
    }
    fwrite(&v, 1, 1, f);
}

static inline void write_u16(FILE *f, uint16_t v)
{
    if (!f) {
        return;
    }
    uint8_t buf[2] = { v & 0xFF, (v >> 8) & 0xFF };
    fwrite(buf, 1, 2, f);
}

static inline void write_u32(FILE *f, uint32_t v)
{
    if (!f) {
        return;
    }
    uint8_t buf[4] = {
        v & 0xFF, (v >> 8) & 0xFF,
        (v >> 16) & 0xFF, (v >> 24) & 0xFF
    };
    fwrite(buf, 1, 4, f);
}

static inline void write_u64(FILE *f, uint64_t v)
{
    if (!f) {
        return;
    }
    uint8_t buf[8] = {
        v & 0xFF, (v >> 8) & 0xFF,
        (v >> 16) & 0xFF, (v >> 24) & 0xFF,
        (v >> 32) & 0xFF, (v >> 40) & 0xFF,
        (v >> 48) & 0xFF, (v >> 56) & 0xFF,
    };
    fwrite(buf, 1, 8, f);
}

/*
 * Write the header section in packed binary format (v3 ULEB128).
 *
 * Binary header layout:
 *   magic:            uint32 (WPT_MAGIC v3)
 *   num_templates:    ULEB128
 *   For each template:
 *     template_id:      ULEB128
 *     start_pc:         uint64
 *     num_insns:        ULEB128
 *     fall_through_pc:  uint64
 *     For each instruction:
 *       pc:             uint64
 *       opcode:         uint8 (GenericOpcode)
 *       branch_type:    uint8 (BranchType)
 *       n_src:          uint8
 *       n_dst:          uint8
 *       src_regs:       [n_src bytes] (GenericRegId)
 *       dst_regs:       [n_dst bytes] (GenericRegId)
 *       has_imm:        uint8 (0 or 1)
 *       imm:            uint64 (only if has_imm == 1)
 */
static void write_bin_header(FILE *f)
{
    if (!f) {
        return;
    }
    GHashTableIter iter;
    gpointer value;

    write_u32(f, WPT_MAGIC);
    write_uleb128(f, g_hash_table_size(template_map));

    g_hash_table_iter_init(&iter, template_map);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        BBTemplate *tmpl = value;
        write_uleb128(f, tmpl->template_id);
        write_u64(f, tmpl->start_pc);
        write_uleb128(f, tmpl->n_insns);
        write_u64(f, tmpl->fall_through_pc);

        for (uint32_t i = 0; i < tmpl->n_insns; i++) {
            InsnFields *fld = &tmpl->insn_fields[i];

            /* Per-insn: pc + generic decoded fields */
            write_u64(f, tmpl->insn_pcs[i]);
            write_u8(f, fld->opcode);
            write_u8(f, fld->branch_type);
            write_u8(f, fld->n_src_regs);
            write_u8(f, fld->n_dst_regs);
            for (uint8_t s = 0; s < fld->n_src_regs; s++) {
                write_u8(f, fld->src_regs[s]);
            }
            for (uint8_t d = 0; d < fld->n_dst_regs; d++) {
                write_u8(f, fld->dst_regs[d]);
            }
            write_u8(f, fld->has_immediate ? 1 : 0);
            if (fld->has_immediate) {
                write_u64(f, (uint64_t)fld->immediate);
            }
        }
    }
}

/*
 * Write the body section in packed binary format (v3 ULEB128).
 *
 * Binary body layout:
 *   num_entries:      ULEB128
 *   For each entry:
 *     template_id:      ULEB128  (seq_num implicit from position)
 *     num_dyn:          ULEB128
 *     For each dyn_param:
 *       type:           uint8
 *       value:          uint64
 *     num_wp:           ULEB128
 *     For each wp_bb:
 *       template_id:    ULEB128
 *       start_pc:       uint64
 *       num_dyn:        ULEB128
 *       n_insns_executed: ULEB128
 *       exception:      uint8
 *       For each dyn_param:
 *         type:         uint8
 *         value:        uint64
 */
static void write_bin_body(FILE *f, GArray *body_entries)
{
    if (!f) {
        return;
    }
    write_uleb128(f, body_entries->len);

    for (guint i = 0; i < body_entries->len; i++) {
        BodyEntry *entry = &g_array_index(body_entries, BodyEntry, i);

        write_uleb128(f, entry->template_id);
        write_uleb128(f, entry->dyn_params->len);

        for (guint d = 0; d < entry->dyn_params->len; d++) {
            DynParam *dp = &g_array_index(entry->dyn_params, DynParam, d);
            write_u8(f, dp->type);
            write_u64(f, dp->value);
        }

        uint32_t num_wp = entry->wp_entries ? entry->wp_entries->len : 0;
        write_uleb128(f, num_wp);

        for (uint32_t w = 0; w < num_wp; w++) {
            WPBBEntry *wp = &g_array_index(entry->wp_entries, WPBBEntry, w);
            write_uleb128(f, wp->template_id);
            write_u64(f, wp->start_pc);
            write_uleb128(f, wp->dyn_params->len);
            write_uleb128(f, wp->n_insns_executed);
            write_u8(f, wp->exception ? 1 : 0);

            for (guint d = 0; d < wp->dyn_params->len; d++) {
                DynParam *dp = &g_array_index(wp->dyn_params, DynParam, d);
                write_u8(f, dp->type);
                write_u64(f, dp->value);
            }
        }
    }
}

/*
 * Write a complete trace in binary format (header + body).
 */
static void write_bin_trace(FILE *f, GArray *body_entries)
{
    g_mutex_lock(&data_lock);
    write_bin_header(f);
    g_mutex_unlock(&data_lock);
    write_bin_body(f, body_entries);
}

/* ========================= Trace State Management ========================= */

static gint simpoint_entry_compare(gconstpointer a, gconstpointer b)
{
    const SimPointEntry *sa = a;
    const SimPointEntry *sb = b;
    if (sa->start_insn < sb->start_insn) {
        return -1;
    }
    if (sa->start_insn > sb->start_insn) {
        return 1;
    }
    return 0;
}

/*
 * Parse a simpoints CSV file produced by the simpoints plugin.
 * Format: interval_id,start_insn,stop_insn,cluster_id,weight
 * Lines starting with '#' are comments.
 */
static GArray *parse_simpoints_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "wptrace: cannot open simpoints file: %s\n", path);
        return NULL;
    }

    GArray *entries = g_array_new(false, false, sizeof(SimPointEntry));
    char line[512];

    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and blank lines */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }

        SimPointEntry sp;
        if (sscanf(line, "%" SCNu64 ",%" SCNu64 ",%" SCNu64 ",%d,%lf",
                   &sp.interval_id, &sp.start_insn, &sp.stop_insn,
                   &sp.cluster_id, &sp.weight) == 5) {
            g_array_append_val(entries, sp);
        }
    }

    fclose(f);

    /* Sort by start_insn ascending */
    g_array_sort(entries, simpoint_entry_compare);

    return entries;
}

/*
 * Start a new trace segment with the given label and instruction range.
 */
static void start_trace_segment(const char *label,
                                uint64_t start, uint64_t stop)
{
    if (current_segment) {
        trace_segment_free(current_segment);
    }

    current_segment = trace_segment_new(label, start, stop);
    body_seq_num = 0;

    /* Determine output file paths based on mode */
    g_autofree char *bin_path = NULL;
    g_autofree char *txt_path = NULL;

    if (output_base_path) {
        if (simpoints_list) {
            /* Per-simpoint output files: outfile_sp0.bin, outfile_sp1.bin, ... */
            bin_path = g_strdup_printf("%s_%s.bin", output_base_path, label);
            if (enable_debug_text) {
                txt_path = g_strdup_printf("%s_%s.txt",
                                           output_base_path, label);
            }
        } else {
            bin_path = g_strdup_printf("%s.bin", output_base_path);
            if (enable_debug_text) {
                txt_path = g_strdup_printf("%s.txt", output_base_path);
            }
        }
    }

    if (bin_path) {
        current_segment->bin_file = fopen(bin_path, "wb");
        if (!current_segment->bin_file) {
            fprintf(stderr, "wptrace: cannot open binary output: %s\n",
                    bin_path);
        }
    }

    if (txt_path) {
        current_segment->text_file = fopen(txt_path, "w");
        if (!current_segment->text_file) {
            fprintf(stderr, "wptrace: cannot open text output: %s\n",
                    txt_path);
        }
    }

    trace_active = true;
}

/*
 * Finalize and write the current trace segment.
 */
static void finish_trace_segment(void)
{
    if (!current_segment) {
        return;
    }

    trace_active = false;

    /* Write outputs */
    if (current_segment->bin_file) {
        write_bin_trace(current_segment->bin_file,
                        current_segment->body_entries);
    }
    if (current_segment->text_file) {
        write_text_trace(current_segment->text_file,
                         current_segment->body_entries);
    }

    trace_segment_free(current_segment);
    current_segment = NULL;
}

/* ========================= Execution Callback ========================= */

/*
 * Called at the start of each basic block on the correct path.
 */
static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    uint64_t current_pc = qemu_plugin_u64_get(sb_current_pc, cpu_index);
    uint64_t prev_last = qemu_plugin_u64_get(sb_prev_last_pc, cpu_index);
    uint64_t prev_ft = qemu_plugin_u64_get(sb_prev_fall_through, cpu_index);
    uint64_t icount = qemu_plugin_u64_get(sb_insn_count, cpu_index);

    /* Don't trigger inside wrong-path execution */
    if (wp_in_progress) {
        return;
    }

    /* --- Tracing window management --- */
    if (simpoints_list) {
        /* SimPoints-driven tracing: cycle through simpoint intervals */
        if (trace_active && icount >= trace_stop_insn) {
            finish_trace_segment();
            simpoints_current_idx++;
        }
        if (!trace_active && simpoints_current_idx < simpoints_list->len) {
            SimPointEntry *sp = &g_array_index(simpoints_list,
                                               SimPointEntry,
                                               simpoints_current_idx);
            if (icount >= sp->start_insn && icount < sp->stop_insn) {
                trace_start_insn = sp->start_insn;
                trace_stop_insn = sp->stop_insn;
                g_autofree char *label =
                    g_strdup_printf("sp%u", simpoints_current_idx);
                start_trace_segment(label, sp->start_insn, sp->stop_insn);
            }
        }
        if (!trace_active && simpoints_current_idx >= simpoints_list->len) {
            /* All simpoints traced */
            exit(0);
        }
    } else {
        /* Simple start/stop mode */
        if (!trace_active && icount >= trace_start_insn &&
            icount < trace_stop_insn) {
            start_trace_segment("trace", trace_start_insn, trace_stop_insn);
        }
        if (trace_active && icount >= trace_stop_insn) {
            finish_trace_segment();
            exit(0);
        }
    }

    /* Skip initial block (no previous context) */
    if (prev_ft == 0) {
        return;
    }

    bool branch_taken = (current_pc != prev_ft);

    g_mutex_lock(&data_lock);

    stat_branches_observed++;
    if (branch_taken) {
        stat_branches_taken++;
    } else {
        stat_branches_not_taken++;
    }

    /* Find or create branch record */
    BranchRecord *br = g_hash_table_lookup(branch_map, &prev_last);
    if (!br) {
        br = g_new0(BranchRecord, 1);
        br->pc = prev_last;
        br->fall_through = prev_ft;
        br->smith_counter = 1;
        g_hash_table_replace(branch_map, &br->pc, br);
    }

    if (branch_taken) {
        br->taken_target = current_pc;
        br->has_taken_target = true;
    }

    br->smith_counter = smith_update(br->smith_counter, branch_taken);

    /* Determine wrong-path target */
    uint64_t wrong_target = 0;
    if (branch_taken) {
        wrong_target = prev_ft;
    } else if (br->has_taken_target) {
        wrong_target = br->taken_target;
    }

    /* Find template for correct-path BB */
    BBTemplate *cp_tmpl = find_template(current_pc);

    g_mutex_unlock(&data_lock);

    /* --- Collect body entry if tracing is active --- */
    if (trace_active && current_segment) {
        BodyEntry entry;
        entry.seq_num = ++body_seq_num;
        entry.template_id = cp_tmpl ? cp_tmpl->template_id : 0;
        entry.dyn_params = g_array_new(false, false, sizeof(DynParam));
        entry.wp_entries = NULL;

        /* Add branch target dynamic param if branch was taken */
        if (branch_taken) {
            DynParam dp = {
                .type = DYN_BRANCH_TARGET,
                .value = current_pc,
            };
            g_array_append_val(entry.dyn_params, dp);
        }

        /* Collect correct-path memory accesses */
        if (cp_mem_accesses) {
            for (guint m = 0; m < cp_mem_accesses->len; m++) {
                WPMemAccess *acc = &g_array_index(cp_mem_accesses,
                                                  WPMemAccess, m);
                DynParam dp = {
                    .type = acc->is_store ? DYN_STORE_ADDR : DYN_LOAD_ADDR,
                    .value = acc->mem_vaddr,
                };
                g_array_append_val(entry.dyn_params, dp);
            }
            g_array_set_size(cp_mem_accesses, 0);
        }

        /* Run wrong-path execution if enabled and target is known */
        if (enable_wrong_path && wrong_target != 0) {
            entry.wp_entries = simulate_wrong_path_ext(
                prev_last, current_pc, wrong_target, cpu_index);
        } else if (wrong_target == 0) {
            stat_wp_skipped++;
        }

        g_array_append_val(current_segment->body_entries, entry);
    } else {
        /* Clear any accumulated memory accesses when not tracing */
        if (cp_mem_accesses) {
            g_array_set_size(cp_mem_accesses, 0);
        }
    }
}

/* ========================= Translation Callback ========================= */

/*
 * Called when a basic block is translated.
 * Creates BB templates with instruction bytes and instruments the block.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t n_insns = qemu_plugin_tb_n_insns(tb);
    struct qemu_plugin_insn *first_insn = qemu_plugin_tb_get_insn(tb, 0);
    struct qemu_plugin_insn *last_insn = qemu_plugin_tb_get_insn(tb,
                                                                  n_insns - 1);
    uint64_t last_insn_pc = qemu_plugin_insn_vaddr(last_insn);
    size_t last_insn_size = qemu_plugin_insn_size(last_insn);
    uint64_t fall_through = last_insn_pc + last_insn_size;

    /* Collect instruction data for BB template */
    uint64_t *insn_pcs = g_new0(uint64_t, n_insns);
    char **insn_disas_arr = g_new0(char *, n_insns);

    for (size_t i = 0; i < n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        insn_pcs[i] = qemu_plugin_insn_vaddr(insn);

        /* Get disassembly string from QEMU's internal disassembler */
        insn_disas_arr[i] = qemu_plugin_insn_disas(insn);

        /* Register per-instruction memory callback with PC as udata */
        qemu_plugin_register_vcpu_mem_cb(
            insn, vcpu_mem_cb, QEMU_PLUGIN_CB_NO_REGS,
            QEMU_PLUGIN_MEM_RW, (void *)(uintptr_t)insn_pcs[i]);
    }

    /* Create or update BB template */
    g_mutex_lock(&data_lock);
    get_or_create_template(pc, (uint32_t)n_insns, insn_pcs,
                           insn_disas_arr, fall_through);
    g_mutex_unlock(&data_lock);

    /* Free temporary arrays (template made copies) */
    for (size_t i = 0; i < n_insns; i++) {
        g_free(insn_disas_arr[i]);
    }
    g_free(insn_pcs);
    g_free(insn_disas_arr);

    /*
     * Instrument the block for execution tracking.
     * Step 1: Store current block's start PC into scoreboard.
     */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_STORE_U64, sb_current_pc, pc);

    /*
     * Step 2: Add instruction count for this block.
     */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_ADD_U64, sb_insn_count, n_insns);

    /*
     * Step 3: Register execution callback.
     */
    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, vcpu_tb_exec, QEMU_PLUGIN_CB_RW_REGS, NULL);

    /*
     * Step 4: Update prev_* values for the NEXT block's callback.
     */
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        sb_prev_last_pc, last_insn_pc);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        sb_prev_fall_through, fall_through);
}

/* ========================= Flush Callback ========================= */

/*
 * Called when the TB cache is flushed.
 *
 * During wrong-path execution, tb_gen_code() may trigger tb_flush() when
 * the code buffer is full. This causes cpu_loop_exit() → longjmp back to
 * the outer cpu_exec_setjmp() handler, bypassing simulate_wrong_path_ext()'s
 * cleanup code. The QEMU core recovers spec_mode via cpu_exec_longjmp_cleanup(),
 * but the plugin's wp_in_progress flag and wp_mem_accesses array are left
 * in a stale state. Reset them here so subsequent vcpu_tb_exec() callbacks
 * are not permanently suppressed.
 */
static void vcpu_tb_flush(qemu_plugin_id_t id)
{
    if (wp_in_progress) {
        wp_in_progress = false;
        if (wp_mem_accesses) {
            g_array_unref(wp_mem_accesses);
            wp_mem_accesses = NULL;
        }
    }
}

/* ========================= Exit / Statistics ========================= */

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    /* Finish any active trace segment */
    if (trace_active) {
        finish_trace_segment();
    }

    /* Print statistics */
    g_autoptr(GString) report = g_string_new("");

    g_mutex_lock(&data_lock);

    g_string_append_printf(report,
        "\n=== Wrong-Path Trace Plugin Statistics ===\n");
    g_string_append_printf(report,
        "Target architecture: %s\n", target_name ? target_name : "unknown");
    g_string_append_printf(report,
        "Max wrong-path depth: %d instructions\n", max_wrong_path_depth);
    g_string_append_printf(report,
        "BB templates created: %u\n", g_hash_table_size(template_map));

    g_string_append_printf(report,
        "\nCorrect-path:\n");
    g_string_append_printf(report,
        "  Basic blocks translated: %" PRIu64 "\n", stat_blocks_translated);
    g_string_append_printf(report,
        "  Branch transitions observed: %" PRIu64 "\n",
        stat_branches_observed);
    g_string_append_printf(report,
        "    Taken: %" PRIu64 "\n", stat_branches_taken);
    g_string_append_printf(report,
        "    Not-taken: %" PRIu64 "\n", stat_branches_not_taken);
    g_string_append_printf(report,
        "  Unique branch PCs (Smith predictor entries): %u\n",
        g_hash_table_size(branch_map));

    g_string_append_printf(report,
        "\nWrong-path execution:\n");
    g_string_append_printf(report,
        "  Simulations performed: %" PRIu64 "\n", stat_wp_simulations);
    g_string_append_printf(report,
        "  Simulations skipped (unknown target): %" PRIu64 "\n",
        stat_wp_skipped);
    g_string_append_printf(report,
        "  Total wrong-path instructions executed: %" PRIu64 "\n",
        stat_wp_total_insns);
    g_string_append_printf(report,
        "  Total wrong-path data accesses: %" PRIu64 "\n",
        stat_wp_total_mem_accesses);
    g_string_append_printf(report,
        "  Early exits (execution fault): %" PRIu64 "\n",
        stat_wp_early_exits);

    if (stat_wp_simulations > 0) {
        g_string_append_printf(report,
            "  Average wrong-path length: %.1f instructions\n",
            (double)stat_wp_total_insns / stat_wp_simulations);
    }

    if (simpoints_list) {
        g_string_append_printf(report,
            "\nSimPoints tracing:\n");
        g_string_append_printf(report,
            "  SimPoints loaded: %u\n", simpoints_list->len);
        g_string_append_printf(report,
            "  SimPoints traced: %u\n", simpoints_current_idx);
    }

    g_string_append_printf(report,
        "==========================================\n");

    g_mutex_unlock(&data_lock);

    qemu_plugin_outs(report->str);

    /* Cleanup */
    if (cp_mem_accesses) {
        g_array_unref(cp_mem_accesses);
    }
    if (simpoints_list) {
        g_array_unref(simpoints_list);
    }
    g_hash_table_unref(template_map);
    g_hash_table_unref(branch_map);
    qemu_plugin_scoreboard_free(vcpu_sb);
    g_free(output_base_path);
    g_free(program_name);
    g_free(simpoints_file_path);
}

/* ========================= Plugin Installation ========================= */

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    target_name = info->target_name;
    is_x86 = (g_str_has_prefix(target_name, "x86_64") ||
              g_str_has_prefix(target_name, "i386"));

    /* Parse arguments */
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);

        if (g_strcmp0(tokens[0], "depth") == 0) {
            max_wrong_path_depth = atoi(tokens[1]);
            if (max_wrong_path_depth <= 0) {
                fprintf(stderr, "wptrace: invalid depth: %s\n", tokens[1]);
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "outfile") == 0) {
            output_base_path = g_strdup(tokens[1]);
        } else if (g_strcmp0(tokens[0], "debug") == 0) {
            enable_debug_text = (atoi(tokens[1]) != 0);
        } else if (g_strcmp0(tokens[0], "wp") == 0) {
            enable_wrong_path = (atoi(tokens[1]) != 0);
        } else if (g_strcmp0(tokens[0], "start") == 0) {
            trace_start_insn = g_ascii_strtoull(tokens[1], NULL, 10);
        } else if (g_strcmp0(tokens[0], "stop") == 0) {
            trace_stop_insn = g_ascii_strtoull(tokens[1], NULL, 10);
        } else if (g_strcmp0(tokens[0], "program") == 0) {
            program_name = g_strdup(tokens[1]);
        } else if (g_strcmp0(tokens[0], "spfile") == 0) {
            simpoints_file_path = g_strdup(tokens[1]);
        } else {
            fprintf(stderr, "wptrace: unknown option: %s\n", opt);
            return -1;
        }
    }

    /* Validate configuration */
    if (!output_base_path) {
        /* Default output base path */
        output_base_path = g_strdup("wptrace_out");
    }

    /* Load simpoints file if provided */
    if (simpoints_file_path) {
        simpoints_list = parse_simpoints_file(simpoints_file_path);
        if (!simpoints_list || simpoints_list->len == 0) {
            fprintf(stderr, "wptrace: no valid simpoints in: %s\n",
                    simpoints_file_path);
            g_free(simpoints_file_path);
            return -1;
        }
        fprintf(stderr, "wptrace: loaded %u simpoints from %s\n",
                simpoints_list->len, simpoints_file_path);
        simpoints_current_idx = 0;

        /* spfile overrides manual start/stop */
        trace_start_insn = 0;
        trace_stop_insn = UINT64_MAX;
    }

    /* Initialize data structures */
    g_mutex_init(&data_lock);
    template_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                         NULL, bb_template_free);
    branch_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                       NULL, g_free);

    /* Initialize per-vCPU scoreboard */
    vcpu_sb = qemu_plugin_scoreboard_new(sizeof(VCPUScoreBoard));
    sb_current_pc = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, current_pc);
    sb_prev_last_pc = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, prev_last_pc);
    sb_prev_fall_through = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, prev_fall_through);
    sb_insn_count = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, insn_count);

    /* Initialize correct-path memory access collection */
    cp_mem_accesses = g_array_new(false, false, sizeof(WPMemAccess));

    /* For simple start/stop, auto-start if start is 0 (not simpoints mode) */
    if (!simpoints_list && trace_start_insn == 0) {
        start_trace_segment("trace", 0, trace_stop_insn);
    }

    /* Register callbacks */
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_flush_cb(id, vcpu_tb_flush);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
