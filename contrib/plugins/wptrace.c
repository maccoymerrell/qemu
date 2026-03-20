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
 *   - Packed binary (.bin): Compact ULEB128-based encoding with streamed body
 *     records and a template footer
 *   - Debug text (.txt): Human-readable representation (toggleable)
 *
 * Features:
 *   - BB template deduplication (unique BBs stored once in header)
 *   - Wrong-path execution with real IF and DF addresses
 *   - Start/stop tracing by instruction number
 *   - ISA-agnostic instruction decode (x86, AArch64, RISC-V, MIPS)
 *   - Compact LEB128 variable-length integer encoding
 *   - Extensible: additional ISA decoders can be added
 *
 * Usage:
 *   -plugin wptrace[,depth=N][,outfile=PATH][,debug=1]
 *                  [,wp=0|1][,start=N][,stop=N]
 *                  [,spfile=PATH][,spinterval=N][,program=NAME]
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

/* ISA enum for extensibility: add new ISAs here */
typedef enum {
    TRACE_ISA_UNKNOWN = 0,
    TRACE_ISA_X86     = 1,   /* x86_64 and i386 */
    TRACE_ISA_AARCH64 = 2,   /* AArch64 (ARMv8+) */
    TRACE_ISA_RISCV   = 3,   /* RISC-V (RV32/RV64) */
    TRACE_ISA_MIPS    = 4,   /* MIPS (mips/mips64/mipsel/mips64el) */
} TraceISA;

static TraceISA trace_isa = TRACE_ISA_UNKNOWN;

/* SimPoints-driven tracing */
static char *simpoints_file_path = NULL;
static uint64_t simpoint_interval_insns = 100000000ULL;

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

/* Binary format magic/version 0.4 */
#define WPT_MAGIC  0x54505704  /* 'T','P','W',0x04 little-endian - version 0.4 */

#define WPT_ISA_BITS 3
#define WPT_OPCODE_BITS 8
#define WPT_BRANCH_BITS 8
#define WPT_REG_COUNT_BITS 3
#define WPT_REG_BITS 8
#define WPT_DYN_TYPE_BITS 1

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

_Static_assert(TRACE_ISA_MIPS < (1U << WPT_ISA_BITS),
               "TraceISA no longer fits packed width");
_Static_assert(GEN_OP_COUNT <= (1U << WPT_OPCODE_BITS),
               "GenericOpcode no longer fits packed width");
_Static_assert(BRANCH_TYPE_COUNT <= (1U << WPT_BRANCH_BITS),
               "BranchType no longer fits packed width");
_Static_assert(MAX_SRC_REGS <= ((1U << WPT_REG_COUNT_BITS) - 1),
               "MAX_SRC_REGS no longer fits packed width");
_Static_assert(MAX_DST_REGS <= ((1U << WPT_REG_COUNT_BITS) - 1),
               "MAX_DST_REGS no longer fits packed width");

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
 * Decoded ISA-agnostic instruction fields.
 * Standardized per-instruction representation stored in BB templates.
 */
typedef struct {
    uint8_t opcode;                 /* GenericOpcode */
    uint8_t branch_type;            /* BranchType (BRANCH_NONE if not branch) */
    bool branch_conditional;
    uint8_t n_src_regs;
    uint8_t n_dst_regs;
    uint8_t src_regs[MAX_SRC_REGS]; /* Source register IDs (GenericRegId) */
    uint8_t dst_regs[MAX_DST_REGS]; /* Destination register IDs (GenericRegId) */
    bool has_immediate;
    int64_t immediate;
} InsnFields;

/* ========================= Disassembly-Based Generic Decode ========================= */

/*
 * Register name → GenericRegId mapping entry.
 * Used to build per-ISA hash tables for O(1) register name lookups.
 */
typedef struct {
    const char *name;
    uint8_t reg_id;
} RegEntry;

/*
 * x86 register name table: maps all 64/32/16/8-bit GPR variants
 * and special registers to GenericRegId for hash table initialization.
 */

/* Static data tables (register and mnemonic mappings) */
#include "wptrace_data.inc"


/*
 * Look up a base mnemonic in the hash table (O(1) average case).
 * Returns true if found, filling opcode and branch_type.
 */
static bool lookup_mnemonic(const char *mnem, uint8_t *opcode,
                            uint8_t *branch_type,
                            bool *branch_conditional)
{
    const MnemonicEntry *entry = g_hash_table_lookup(mnemonic_ht, mnem);
    if (entry) {
        *opcode = entry->opcode;
        *branch_type = entry->branch_type;
        *branch_conditional = entry->branch_conditional;
        return true;
    }
    return false;
}

/*
 * Try to classify a mnemonic by prefix match using O(1) hash lookups.
 * Two strategies:
 *   1. Dot-prefix: extract the portion up to and including the first '.'
 *      and look it up (e.g., "fadd.s" → key "fadd.").
 *   2. Bare-prefix: truncate the mnemonic to lengths 4 then 3, requiring
 *      the mnemonic to be strictly longer than the prefix. This handles
 *      patterns like "cmov<cc>", "set<cc>", "amo*", etc.
 */
static bool lookup_prefix_class(const char *mnem, uint8_t *opcode,
                                uint8_t *branch_type,
                                bool *branch_conditional)
{
    char buf[16];

    /* Dot-prefix: extract up to first '.' inclusive */
    const char *dot = strchr(mnem, '.');
    if (dot) {
        size_t plen = (size_t)(dot - mnem) + 1;
        if (plen < sizeof(buf)) {
            memcpy(buf, mnem, plen);
            buf[plen] = '\0';
            const MnemonicEntry *e = g_hash_table_lookup(prefix_ht, buf);
            if (e) {
                *opcode = e->opcode;
                *branch_type = e->branch_type;
                *branch_conditional = e->branch_conditional;
                return true;
            }
        }
    }

    /* Bare-prefix: try lengths 4 then 3 (covers all known non-dot patterns) */
    size_t mlen = strlen(mnem);
    for (int plen = 4; plen >= 3; plen--) {
        if ((size_t)plen < mlen) {
            memcpy(buf, mnem, plen);
            buf[plen] = '\0';
            const MnemonicEntry *e = g_hash_table_lookup(prefix_ht, buf);
            if (e) {
                *opcode = e->opcode;
                *branch_type = e->branch_type;
                *branch_conditional = e->branch_conditional;
                return true;
            }
        }
    }

    return false;
}

/*
 * Classify a mnemonic string to GenericOpcode + BranchType.
 *
 * Uses a three-level lookup strategy:
 *   1. Exact match via mnemonic hash table (O(1)).
 *   2. Prefix match via prefix hash table (O(1) per probe, at most 3 probes).
 *   3. AVX v-prefix stripping and x86 size-suffix stripping with retry.
 *
 * The only remaining strcmp is for the x86 j<cc>/jmp disambiguation,
 * which requires character manipulation that can't be table-driven.
 */
static void classify_mnemonic(const char *mnem, uint8_t *opcode,
                              uint8_t *branch_type,
                              bool *branch_conditional)
{
    *opcode = GEN_OP_UNKNOWN;
    *branch_type = BRANCH_NONE;
    *branch_conditional = false;

    if (!mnem || !*mnem) {
        return;
    }

    /* Strip x86 instruction prefixes (lock, rep, etc.) via hash lookup */
    const char *sp = strchr(mnem, ' ');
    if (sp) {
        size_t plen = (size_t)(sp - mnem);
        if (plen < 16) {
            char pfx[16];
            memcpy(pfx, mnem, plen);
            pfx[plen] = '\0';
            if (g_hash_table_contains(insn_prefix_ht, pfx)) {
                mnem = sp + 1;
            }
        }
    }

    /* x86 conditional branches: j<cc> (not jmp/jmpq) */
    if (trace_isa == TRACE_ISA_X86 && mnem[0] == 'j') {
        char tmp[32];
        g_strlcpy(tmp, mnem, sizeof(tmp));
        size_t tlen = strlen(tmp);
        if (tlen > 1 && tmp[tlen - 1] == 'q') {
            tmp[tlen - 1] = '\0';
        }
        if (strcmp(tmp, "jmp") != 0) {
            *opcode = GEN_OP_BRANCH;
            *branch_type = BRANCH_DIRECT_JUMP;
            *branch_conditional = true;
            return;
        }
    }

    /* Exact match in mnemonic hash table */
    if (lookup_mnemonic(mnem, opcode, branch_type, branch_conditional)) {
        return;
    }

    /* Prefix-based classification (dot-prefix and bare-prefix) */
    if (lookup_prefix_class(mnem, opcode, branch_type, branch_conditional)) {
        return;
    }

    /* AVX v-prefix: strip 'v' and retry (x86 only) */
    if (trace_isa == TRACE_ISA_X86 && mnem[0] == 'v' && strlen(mnem) > 1) {
        if (lookup_mnemonic(mnem + 1, opcode, branch_type,
                            branch_conditional)) {
            return;
        }
        if (lookup_prefix_class(mnem + 1, opcode, branch_type,
                                branch_conditional)) {
            return;
        }
    }

    /* x86 size suffix: strip trailing q/l/w/b and retry */
    if (trace_isa == TRACE_ISA_X86) {
        size_t len = strlen(mnem);
        if (len > 1) {
            char base[32];
            g_strlcpy(base, mnem, sizeof(base));
            char last = base[len - 1];
            if (last == 'q' || last == 'l' || last == 'w' || last == 'b') {
                base[len - 1] = '\0';
                if (lookup_mnemonic(base, opcode, branch_type,
                                    branch_conditional)) {
                    return;
                }
                if (lookup_prefix_class(base, opcode, branch_type,
                                        branch_conditional)) {
                    return;
                }
                /* Also try AVX v-prefix + stripped suffix */
                if (base[0] == 'v' && strlen(base) > 1) {
                    if (lookup_mnemonic(base + 1, opcode, branch_type,
                                        branch_conditional)) {
                        return;
                    }
                    if (lookup_prefix_class(base + 1, opcode, branch_type,
                                            branch_conditional)) {
                        return;
                    }
                }
            }
        }
    }

    /* Backward table compatibility: conditional-direct maps to type+flag. */
    if (*branch_type == BRANCH_COND_DIRECT) {
        *branch_type = BRANCH_DIRECT_JUMP;
        *branch_conditional = true;
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
/* ========================= Unified Operand Parsing Macros ========================= */

/*
 * These macros eliminate duplication across ISA-specific operand parsers by
 * providing common patterns for register extraction and classification.
 */

/* Common pattern: dst = op(src, src) for ALU/FP/VEC operations */
#define PARSE_ALU_DSTS(n_ops, ops, extract_fn) \
    do { \
        if (n_ops >= 1) { \
            uint8_t dst = extract_fn(ops[0]); \
            if (dst != REG_NONE) add_dst_reg(out, dst); \
        } \
        for (int i = 1; i < n_ops; i++) { \
            uint8_t src = extract_fn(ops[i]); \
            if (src != REG_NONE) add_src_reg(out, src); \
        } \
    } while(0)

#define PARSE_MOV_OPS(n_ops, ops, extract_fn) PARSE_ALU_DSTS(n_ops, ops, extract_fn)
#define PARSE_FP_OPS(n_ops, ops, extract_fn) PARSE_ALU_DSTS(n_ops, ops, extract_fn)
#define PARSE_VEC_OPS(n_ops, ops, extract_fn) PARSE_ALU_DSTS(n_ops, ops, extract_fn)

/* LOAD: dst, [mem] with optional second dst for pair loads */
#define PARSE_LOAD_OPS(n_ops, ops, extract_fn, extract_mem_fn, support_pair) \
    do { \
        if (n_ops >= 1) { \
            uint8_t dst = extract_fn(ops[0]); \
            if (dst != REG_NONE) add_dst_reg(out, dst); \
        } \
        if (support_pair && n_ops >= 3) { \
            uint8_t dst2 = extract_fn(ops[1]); \
            if (dst2 != REG_NONE) add_dst_reg(out, dst2); \
        } \
        for (int i = 0; i < n_ops; i++) { \
            if (is_memory_operand(ops[i])) { \
                extract_mem_fn(ops[i], out); \
            } \
        } \
    } while(0)

/* STORE: src, [mem] with optional second src for pair stores */
#define PARSE_STORE_OPS(n_ops, ops, extract_fn, extract_mem_fn, support_pair) \
    do { \
        if (n_ops >= 1) { \
            uint8_t src = extract_fn(ops[0]); \
            if (src != REG_NONE) add_src_reg(out, src); \
        } \
        if (support_pair && n_ops >= 3) { \
            uint8_t src2 = extract_fn(ops[1]); \
            if (src2 != REG_NONE) add_src_reg(out, src2); \
        } \
        for (int i = 0; i < n_ops; i++) { \
            if (is_memory_operand(ops[i])) { \
                extract_mem_fn(ops[i], out); \
            } \
        } \
    } while(0)

/* CMP/TEST: all operands are sources, FLAGS is destination */
#define PARSE_CMP_OPS(n_ops, ops, extract_fn) \
    do { \
        for (int i = 0; i < n_ops; i++) { \
            uint8_t r = extract_fn(ops[i]); \
            if (r != REG_NONE) add_src_reg(out, r); \
        } \
        add_dst_reg(out, REG_FLAGS); \
    } while(0)

/* BRANCH: potential register operands as sources */
#define PARSE_BRANCH_OPS(n_ops, ops, extract_fn) \
    do { \
        for (int i = 0; i < n_ops; i++) { \
            uint8_t r = extract_fn(ops[i]); \
            if (r != REG_NONE) add_src_reg(out, r); \
        } \
    } while(0)

/* CALL: link register as destination, operands as sources */
#define PARSE_CALL_OPS(n_ops, ops, extract_fn, link_reg) \
    do { \
        add_dst_reg(out, link_reg); \
        for (int i = 0; i < n_ops; i++) { \
            uint8_t r = extract_fn(ops[i]); \
            if (r != REG_NONE) add_src_reg(out, r); \
        } \
    } while(0)

/* ========================= ISA-Specific Operand Parsers ========================= */

/*
 * Parse x86 AT&T operands and populate source/destination registers.
 * In AT&T syntax, source comes first, destination last.
 */
static void parse_x86_operands(const char *operands, InsnFields *out)
{
    char ops[MAX_OPS][MAX_OP_LEN];
    int n_ops = split_operands(operands, ops, MAX_OPS);
    if (n_ops == 0) return;

    /* Pre-compute memory operands for x86 AT&T syntax */
    bool op_is_mem[MAX_OPS];
    for (int i = 0; i < n_ops; i++) {
        op_is_mem[i] = is_memory_operand(ops[i]);
    }

    /* Adjust opcode for MOV with memory operand */
    if (out->opcode == GEN_OP_MOV && n_ops >= 2) {
        if (op_is_mem[0]) out->opcode = GEN_OP_LOAD;
        else if (op_is_mem[1]) out->opcode = GEN_OP_STORE;
    }

    /* Check for indirect branch/call (operand starts with '*') */
    if (out->branch_type == BRANCH_DIRECT_JUMP || out->branch_type == BRANCH_DIRECT_CALL) {
        const char *t = ops[0];
        while (*t == ' ' || *t == '\t') t++;
        if (*t == '*') {
            out->branch_type = (out->branch_type == BRANCH_DIRECT_JUMP) ?
                               BRANCH_INDIRECT_JUMP : BRANCH_INDIRECT_CALL;
        }
    }

    switch (out->opcode) {
    /* Two-operand ALU: src, src+dst; FLAGS is dst (AT&T syntax) */
    case GEN_OP_INT_ADD: case GEN_OP_INT_SUB: case GEN_OP_AND: case GEN_OP_OR:
    case GEN_OP_XOR: case GEN_OP_INT_ADC: case GEN_OP_INT_SBB:
    case GEN_OP_SHL: case GEN_OP_SHR: case GEN_OP_SAR: case GEN_OP_ROL: case GEN_OP_ROR:
        if (n_ops >= 2) {
            uint8_t src = extract_x86_reg(ops[0]);
            uint8_t dst = extract_x86_reg(ops[1]);
            if (src != REG_NONE) add_src_reg(out, src);
            if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
            if (dst != REG_NONE) { add_src_reg(out, dst); add_dst_reg(out, dst); }
            if (op_is_mem[1]) extract_x86_mem_regs(ops[1], out);
        } else if (n_ops == 1) {
            uint8_t r = extract_x86_reg(ops[0]);
            if (r != REG_NONE) { add_src_reg(out, r); add_dst_reg(out, r); }
            if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
        }
        add_dst_reg(out, REG_FLAGS);
        break;

    /* Data movement: src -> dst */
    case GEN_OP_MOV: case GEN_OP_MOVSX: case GEN_OP_MOVZX: case GEN_OP_CMOV:
        if (n_ops >= 2) {
            uint8_t src = extract_x86_reg(ops[0]), dst = extract_x86_reg(ops[1]);
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
            if (op_is_mem[n_ops - 1]) extract_x86_mem_regs(ops[n_ops - 1], out);
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
        add_src_reg(out, REG_SP); add_dst_reg(out, REG_SP);
        break;

    /* POP: dst + SP */
    case GEN_OP_POP:
        if (n_ops >= 1) {
            uint8_t r = extract_x86_reg(ops[0]);
            if (r != REG_NONE) add_dst_reg(out, r);
        }
        add_src_reg(out, REG_SP); add_dst_reg(out, REG_SP);
        break;

    /* XCHG: both operands are src+dst */
    case GEN_OP_XCHG:
        for (int i = 0; i < n_ops && i < 2; i++) {
            uint8_t r = extract_x86_reg(ops[i]);
            if (r != REG_NONE) { add_src_reg(out, r); add_dst_reg(out, r); }
            if (op_is_mem[i]) extract_x86_mem_regs(ops[i], out);
        }
        break;

    /* Unary: operand is both src and dst */
    case GEN_OP_NOT: case GEN_OP_NEG: case GEN_OP_INC: case GEN_OP_DEC:
        if (n_ops >= 1) {
            uint8_t r = extract_x86_reg(ops[0]);
            if (r != REG_NONE) { add_src_reg(out, r); add_dst_reg(out, r); }
            if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
        }
        if (out->opcode != GEN_OP_NOT) add_dst_reg(out, REG_FLAGS);
        break;

    /* CALL: may have indirect operand */
    case GEN_OP_CALL:
        if (n_ops >= 1) {
            const char *t = ops[0];
            while (*t == ' ' || *t == '\t') t++;
            if (*t == '*') {
                if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
                else {
                    uint8_t r = extract_x86_reg(ops[0]);
                    if (r != REG_NONE) add_src_reg(out, r);
                }
            }
        }
        add_src_reg(out, REG_SP); add_dst_reg(out, REG_SP); add_dst_reg(out, REG_IP);
        break;

    /* RET */
    case GEN_OP_RET:
        add_src_reg(out, REG_SP); add_dst_reg(out, REG_SP); add_dst_reg(out, REG_IP);
        break;

    /* Branch */
    case GEN_OP_BRANCH:
        if (out->branch_conditional) add_src_reg(out, REG_FLAGS);
        if (out->branch_type == BRANCH_INDIRECT_JUMP && n_ops >= 1) {
            const char *t = ops[0];
            while (*t == ' ' || *t == '\t') t++;
            if (*t == '*') {
                if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
                else {
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
            add_dst_reg(out, REG_GPR0); add_dst_reg(out, REG_GPR2);
        }
        add_dst_reg(out, REG_FLAGS);
        break;

    /* DIV/IDIV */
    case GEN_OP_INT_DIV:
        add_src_reg(out, REG_GPR0); add_src_reg(out, REG_GPR2);
        if (n_ops >= 1) {
            uint8_t r = extract_x86_reg(ops[0]);
            if (r != REG_NONE) add_src_reg(out, r);
            if (op_is_mem[0]) extract_x86_mem_regs(ops[0], out);
        }
        add_dst_reg(out, REG_GPR0); add_dst_reg(out, REG_GPR2);
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
    case GEN_OP_FP_ADD: case GEN_OP_FP_SUB: case GEN_OP_FP_MUL: case GEN_OP_FP_DIV:
    case GEN_OP_FP_SQRT: case GEN_OP_FP_MOV: case GEN_OP_FP_CVT: case GEN_OP_FP_CMP:
    case GEN_OP_VEC_ADD: case GEN_OP_VEC_SUB: case GEN_OP_VEC_MUL:
    case GEN_OP_VEC_MOV: case GEN_OP_VEC_SHUF: case GEN_OP_VEC_LOGIC:
        for (int i = 0; i < n_ops; i++) {
            uint8_t r = extract_x86_reg(ops[i]);
            if (r != REG_NONE) {
                if (i < n_ops - 1) add_src_reg(out, r);
                else { add_src_reg(out, r); add_dst_reg(out, r); }
            }
            if (op_is_mem[i]) extract_x86_mem_regs(ops[i], out);
        }
        if (out->opcode == GEN_OP_FP_CMP) add_dst_reg(out, REG_FLAGS);
        break;

    default: break;
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
    if (n_ops == 0) return;

    switch (out->opcode) {
    case GEN_OP_INT_ADD: case GEN_OP_INT_SUB: case GEN_OP_INT_MUL:
    case GEN_OP_INT_DIV: case GEN_OP_AND: case GEN_OP_OR:
    case GEN_OP_XOR: case GEN_OP_NOT: case GEN_OP_SHL:
    case GEN_OP_SHR: case GEN_OP_SAR:
        PARSE_ALU_DSTS(n_ops, ops, extract_aarch64_reg); break;
    case GEN_OP_MOV: case GEN_OP_MOVSX: case GEN_OP_MOVZX: case GEN_OP_CMOV:
        PARSE_MOV_OPS(n_ops, ops, extract_aarch64_reg); break;
    case GEN_OP_LOAD:
        PARSE_LOAD_OPS(n_ops, ops, extract_aarch64_reg, extract_aarch64_mem_regs, true); break;
    case GEN_OP_STORE:
        PARSE_STORE_OPS(n_ops, ops, extract_aarch64_reg, extract_aarch64_mem_regs, true); break;
    case GEN_OP_CMP: case GEN_OP_TEST:
        PARSE_CMP_OPS(n_ops, ops, extract_aarch64_reg); break;
    case GEN_OP_BRANCH:
        PARSE_BRANCH_OPS(n_ops, ops, extract_aarch64_reg); break;
    case GEN_OP_CALL:
        if (out->branch_type == BRANCH_INDIRECT_CALL && n_ops >= 1) {
            uint8_t r = extract_aarch64_reg(ops[0]);
            if (r != REG_NONE) add_src_reg(out, r);
        }
        add_dst_reg(out, REG_LR); break;
    case GEN_OP_RET:
        add_src_reg(out, REG_LR); break;
    case GEN_OP_FP_ADD: case GEN_OP_FP_SUB: case GEN_OP_FP_MUL:
    case GEN_OP_FP_DIV: case GEN_OP_FP_SQRT: case GEN_OP_FP_MOV:
    case GEN_OP_FP_CVT: case GEN_OP_FP_CMP:
        if (out->opcode == GEN_OP_FP_CMP) {
            PARSE_CMP_OPS(n_ops, ops, extract_aarch64_reg);
        } else {
            PARSE_FP_OPS(n_ops, ops, extract_aarch64_reg);
        }
        break;
    default:
        PARSE_ALU_DSTS(n_ops, ops, extract_aarch64_reg); break;
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
 * Extract the first register from a RISC-V operand.
 * RISC-V uses bare ABI names (a0, sp, ra, t0, etc.) without prefix.
 */
static uint8_t extract_riscv_reg(const char *op)
{
    while (*op == ' ' || *op == '\t') {
        op++;
    }

    /* Skip immediate-only operands (numeric or hex) */
    if ((*op >= '0' && *op <= '9') || *op == '-') {
        return REG_NONE;
    }

    /* Skip memory operand brackets */
    if (*op == '(') {
        return REG_NONE;
    }

    char name[16];
    int i = 0;
    while (*op && *op != ',' && *op != '(' && *op != ')' &&
           *op != ' ' && *op != '\t' && i < 15) {
        name[i++] = *op++;
    }
    name[i] = '\0';
    return parse_riscv_reg(name);
}

/*
 * Extract address registers from a RISC-V memory operand.
 * Format: offset(base)  e.g., 0(sp) or 100(a0)
 */
static void extract_riscv_mem_regs(const char *op, InsnFields *out)
{
    const char *p = strchr(op, '(');
    if (!p) {
        return;
    }
    p++;

    while (*p == ' ' || *p == '\t') {
        p++;
    }

    char name[16];
    int i = 0;
    while (*p && *p != ')' && *p != ',' && *p != ' ' && i < 15) {
        name[i++] = *p++;
    }
    name[i] = '\0';
    uint8_t base = parse_riscv_reg(name);
    add_src_reg(out, base);
}

/*
 * Parse RISC-V operands and populate source/destination registers.
 * RISC-V convention: first operand is typically destination.
 * Loads: rd, offset(rs1)   Stores: rs2, offset(rs1)
 * ALU:   rd, rs1, rs2/imm  Branches: rs1, rs2, target
 */
static void parse_riscv_operands(const char *operands, InsnFields *out)
{
    char ops[MAX_OPS][MAX_OP_LEN];
    int n_ops = split_operands(operands, ops, MAX_OPS);
    if (n_ops == 0) return;

    switch (out->opcode) {
    case GEN_OP_INT_ADD: case GEN_OP_INT_SUB: case GEN_OP_INT_MUL:
    case GEN_OP_INT_DIV: case GEN_OP_AND: case GEN_OP_OR:
    case GEN_OP_XOR: case GEN_OP_SHL: case GEN_OP_SHR:
    case GEN_OP_SAR: case GEN_OP_ROL: case GEN_OP_ROR:
    case GEN_OP_MOV: case GEN_OP_MOVSX: case GEN_OP_MOVZX:
    case GEN_OP_CMP: case GEN_OP_LEA:
        PARSE_ALU_DSTS(n_ops, ops, extract_riscv_reg); break;
    case GEN_OP_LOAD:
        PARSE_LOAD_OPS(n_ops, ops, extract_riscv_reg, extract_riscv_mem_regs, false); break;
    case GEN_OP_STORE:
        PARSE_STORE_OPS(n_ops, ops, extract_riscv_reg, extract_riscv_mem_regs, false); break;
    case GEN_OP_BRANCH:
        PARSE_BRANCH_OPS(n_ops, ops, extract_riscv_reg); break;
    case GEN_OP_CALL:
        if (out->branch_type == BRANCH_INDIRECT_CALL && n_ops >= 1) {
            for (int i = 0; i < n_ops; i++) {
                if (is_memory_operand(ops[i])) {
                    extract_riscv_mem_regs(ops[i], out);
                } else {
                    uint8_t r = extract_riscv_reg(ops[i]);
                    if (r != REG_NONE) add_src_reg(out, r);
                }
            }
        }
        add_dst_reg(out, REG_LR); break;
    case GEN_OP_RET:
        add_src_reg(out, REG_LR); break;
    case GEN_OP_FP_ADD: case GEN_OP_FP_SUB: case GEN_OP_FP_MUL:
    case GEN_OP_FP_DIV: case GEN_OP_FP_SQRT: case GEN_OP_FP_MOV:
    case GEN_OP_FP_CVT: case GEN_OP_FP_CMP:
        PARSE_FP_OPS(n_ops, ops, extract_riscv_reg); break;
    case GEN_OP_XCHG:
        for (int i = 0; i < n_ops; i++) {
            uint8_t r = extract_riscv_reg(ops[i]);
            if (r != REG_NONE) { add_src_reg(out, r); add_dst_reg(out, r); }
            if (is_memory_operand(ops[i])) extract_riscv_mem_regs(ops[i], out);
        }
        break;
    default:
        PARSE_ALU_DSTS(n_ops, ops, extract_riscv_reg); break;
    }

    /* Extract immediate value (bare number) */
    for (int i = 0; i < n_ops; i++) {
        const char *t = ops[i];
        while (*t == ' ' || *t == '\t') t++;
        if ((*t >= '0' && *t <= '9') || *t == '-') {
            const char *paren = strchr(t, '(');
            if (!paren) {
                out->has_immediate = true;
                out->immediate = strtoll(t, NULL, 0);
                break;
            }
        }
    }
}

/*
 * Extract the first register from a MIPS operand.
 * QEMU's MIPS disassembler outputs ABI names without $ prefix for GPRs.
 */
static uint8_t extract_mips_reg(const char *op)
{
    while (*op == ' ' || *op == '\t') {
        op++;
    }

    /* Skip immediate-only operands */
    if (*op == '0' && op[1] == 'x') {
        return REG_NONE;  /* hex literal */
    }
    if ((*op >= '0' && *op <= '9') || *op == '-') {
        return REG_NONE;
    }
    if (*op == '(') {
        return REG_NONE;
    }

    /* $ prefix indicates a register in some MIPS outputs */
    const char *start = op;

    char name[16];
    int i = 0;
    /* Include $ in name if present, parse_mips_reg handles it */
    const char *p = start;
    while (*p && *p != ',' && *p != '(' && *p != ')' &&
           *p != ' ' && *p != '\t' && i < 15) {
        name[i++] = *p++;
    }
    name[i] = '\0';
    return parse_mips_reg(name);
}

/*
 * Extract address registers from a MIPS memory operand.
 * Format: offset(base) e.g., 0(sp) or 100(t0)
 */
static void extract_mips_mem_regs(const char *op, InsnFields *out)
{
    const char *p = strchr(op, '(');
    if (!p) {
        return;
    }
    p++;

    while (*p == ' ' || *p == '\t') {
        p++;
    }

    char name[16];
    int i = 0;
    while (*p && *p != ')' && *p != ',' && *p != ' ' && i < 15) {
        name[i++] = *p++;
    }
    name[i] = '\0';
    uint8_t base = parse_mips_reg(name);
    add_src_reg(out, base);
}

/*
 * Parse MIPS operands and populate source/destination registers.
 * MIPS convention: first operand is typically destination.
 * Loads: rt, offset(base)  Stores: rt, offset(base)
 * ALU:   rd, rs, rt/imm    Branches: rs, rt, target
 */
static void parse_mips_operands(const char *operands, InsnFields *out)
{
    char ops[MAX_OPS][MAX_OP_LEN];
    int n_ops = split_operands(operands, ops, MAX_OPS);
    if (n_ops == 0) return;

    switch (out->opcode) {
    case GEN_OP_INT_ADD: case GEN_OP_INT_SUB: case GEN_OP_INT_MUL:
    case GEN_OP_INT_DIV: case GEN_OP_AND: case GEN_OP_OR:
    case GEN_OP_XOR: case GEN_OP_NOT: case GEN_OP_SHL:
    case GEN_OP_SHR: case GEN_OP_SAR:
    case GEN_OP_MOV: case GEN_OP_MOVSX: case GEN_OP_MOVZX:
    case GEN_OP_CMP: case GEN_OP_LEA:
        PARSE_ALU_DSTS(n_ops, ops, extract_mips_reg); break;
    case GEN_OP_LOAD:
        PARSE_LOAD_OPS(n_ops, ops, extract_mips_reg, extract_mips_mem_regs, false); break;
    case GEN_OP_STORE:
        PARSE_STORE_OPS(n_ops, ops, extract_mips_reg, extract_mips_mem_regs, false); break;
    case GEN_OP_BRANCH:
        PARSE_BRANCH_OPS(n_ops, ops, extract_mips_reg);
        /* MIPS jr $ra is a return */
        if (out->branch_type == BRANCH_INDIRECT_JUMP && n_ops >= 1) {
            uint8_t r = extract_mips_reg(ops[0]);
            if (r == REG_LR) {
                out->opcode = GEN_OP_RET;
                out->branch_type = BRANCH_RETURN;
            }
        }
        break;
    case GEN_OP_CALL:
        if (out->branch_type == BRANCH_INDIRECT_CALL && n_ops >= 1) {
            uint8_t r = extract_mips_reg(ops[0]);
            if (r != REG_NONE) add_src_reg(out, r);
        }
        add_dst_reg(out, REG_LR); break;
    case GEN_OP_RET:
        add_src_reg(out, REG_LR); break;
    case GEN_OP_FP_ADD: case GEN_OP_FP_SUB: case GEN_OP_FP_MUL:
    case GEN_OP_FP_DIV: case GEN_OP_FP_SQRT: case GEN_OP_FP_MOV:
    case GEN_OP_FP_CVT:
        PARSE_FP_OPS(n_ops, ops, extract_mips_reg); break;
    case GEN_OP_FP_CMP:
        PARSE_CMP_OPS(n_ops, ops, extract_mips_reg); break;
    default:
        PARSE_ALU_DSTS(n_ops, ops, extract_mips_reg); break;
    }

    /* Extract immediate value (bare number or hex) */
    for (int i = 0; i < n_ops; i++) {
        const char *t = ops[i];
        while (*t == ' ' || *t == '\t') t++;
        if ((*t >= '0' && *t <= '9') || *t == '-') {
            const char *paren = strchr(t, '(');
            if (!paren) {
                out->has_immediate = true;
                out->immediate = strtoll(t, NULL, 0);
                break;
            }
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

    /* Classify mnemonic -> opcode + branch type + conditional flag */
    classify_mnemonic(mnem, &out->opcode, &out->branch_type,
                      &out->branch_conditional);

    if (out->branch_type != BRANCH_NONE && strchr(disas, ' ')) {
        char pfx[16];
        const char *sp = strchr(disas, ' ');
        size_t plen = (size_t)(sp - disas);

        if (plen < sizeof(pfx)) {
            memcpy(pfx, disas, plen);
            pfx[plen] = '\0';
            if (g_strcmp0(pfx, "bnd") == 0 ||
                g_strcmp0(pfx, "pt") == 0 ||
                g_strcmp0(pfx, "pn") == 0) {
                out->branch_conditional = true;
            }
        }
    }

    /* Skip whitespace to get to operands */
    while (*p == ' ' || *p == '\t') {
        p++;
    }

    /* Parse operands for register and immediate extraction */
    if (*p) {
        switch (trace_isa) {
        case TRACE_ISA_X86:
            parse_x86_operands(p, out);
            break;
        case TRACE_ISA_AARCH64:
            parse_aarch64_operands(p, out);
            break;
        case TRACE_ISA_RISCV:
            parse_riscv_operands(p, out);
            break;
        case TRACE_ISA_MIPS:
            parse_mips_operands(p, out);
            break;
        default:
            /* Unknown ISA: no operand parsing */
            break;
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
        [BRANCH_SYSCALL_TYPE]  = "SYSCALL",
        [BRANCH_COND_DIRECT]   = "COND_DIRECT",
    };
    return (bt < BRANCH_TYPE_COUNT) ? names[bt] : "UNKNOWN";
}

static const char *generic_reg_name(uint8_t reg_id)
{
    static char buf[16];

    if (reg_id == REG_NONE) {
        return "NONE";
    }
    if (reg_id >= REG_GPR0 && reg_id <= (REG_GPR0 + 63)) {
        snprintf(buf, sizeof(buf), "GPR%u", reg_id - REG_GPR0);
        return buf;
    }
    if (reg_id >= REG_FPR0 && reg_id <= (REG_FPR0 + 63)) {
        snprintf(buf, sizeof(buf), "FPR%u", reg_id - REG_FPR0);
        return buf;
    }
    if (reg_id >= REG_VEC0 && reg_id <= (REG_VEC0 + 63)) {
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

static const char *generic_exception_name(uint8_t exid)
{
    static const char *names[] = {
        [GEN_EXC_NONE] = "NONE",
        [GEN_EXC_UNKNOWN] = "UNKNOWN",
        [GEN_EXC_INT_DIVIDE_BY_ZERO] = "INT_DIVIDE_BY_ZERO",
        [GEN_EXC_FP_DIVIDE_BY_ZERO] = "FP_DIVIDE_BY_ZERO",
        [GEN_EXC_MEMORY_ACCESS] = "MEMORY_ACCESS",
    };

    return (exid < GEN_EXC_COUNT) ? names[exid] : "UNKNOWN";
}

static const char *wp_stop_reason_name(uint8_t reason)
{
    static const char *names[] = {
        [WP_STOP_NONE] = "NONE",
        [WP_STOP_SYSCALL_USERMODE] = "SYSCALL_USERMODE",
    };

    return (reason < WP_STOP_REASON_COUNT) ? names[reason] : "UNKNOWN";
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
    char *symbol_name;         /* Best-effort symbol for first instruction */
    uint8_t *insn_sizes;       /* Size per instruction */
    uint8_t *insn_bytes;       /* Flat buffer: n_insns * MAX_INSN_BYTES */
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
    bool fault;                 /* True if WP BB ended due to fault/stop */
    bool translation_unavailable; /* Template lookup failed for this WP PC */
    uint8_t stop_reason;        /* WPStopReason */
    uint8_t exception_id;       /* GenericExceptionId */
    uint8_t exception_reg_id;   /* Register impacted by exception */
    bool has_exception_reg;
    bool has_exception_class;
    GByteArray *poison_mask;    /* Per-insn mask: 1 marks the faulting insn */
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
    uint64_t prev_start_pc;     /* Previous block's start PC */
    uint64_t prev_last_pc;      /* Last insn PC of previous block */
    uint64_t prev_fall_through; /* Expected sequential next from prev block */
    uint64_t prev_bb_ends_in_branch; /* Previous BB ended in a branch */
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

typedef struct BodyStreamState BodyStreamState;

/*
 * Trace state for a single trace segment.
 */
typedef struct {
    uint64_t start_insn;        /* Instruction number at trace start */
    uint64_t stop_insn;         /* Instruction number at trace end */
    char *label;                /* Label for output file naming */
    FILE *text_file;            /* Debug text output (NULL if disabled) */
    FILE *text_body_tmp;        /* Streaming text body staging */
    FILE *bin_file;             /* Binary output */
    BodyStreamState *bin_stream;
} TraceSegment;

/* ========================= Global State ========================= */

static GMutex data_lock;
static GMutex exec_lock;
static GHashTable *template_map;    /* start_pc (uint64*) → BBTemplate* */
static GHashTable *branch_map;      /* branch_pc (uint64*) → BranchRecord* */
static uint32_t next_template_id = 1;

/* Per-vCPU scoreboard */
static struct qemu_plugin_scoreboard *vcpu_sb;
static qemu_plugin_u64 sb_current_pc;
static qemu_plugin_u64 sb_prev_start_pc;
static qemu_plugin_u64 sb_prev_last_pc;
static qemu_plugin_u64 sb_prev_fall_through;
static qemu_plugin_u64 sb_prev_bb_ends_in_branch;
static qemu_plugin_u64 sb_insn_count;

/* Tracing state */
static bool trace_active = false;
static TraceSegment *current_segment = NULL;
static uint32_t body_seq_num = 0;

/* Wrong-path execution state */
static __thread bool wp_in_progress = false;
static __thread GArray *wp_mem_accesses = NULL;
static __thread uint64_t wp_saved_insn_count = 0;
static __thread unsigned int wp_saved_cpu_index = 0;
static __thread uint64_t wp_saved_prev_start_pc = 0;
static __thread uint64_t wp_saved_prev_last_pc = 0;
static __thread uint64_t wp_saved_prev_fall_through = 0;
static __thread uint64_t wp_saved_prev_bb_ends_in_branch = 0;

/* Correct-path memory accesses for current BB */
static __thread GArray *cp_mem_accesses = NULL;

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

/* Binary format accounting */
static uint64_t stat_bin_total_bits;
static uint64_t stat_bin_header_bits;
static uint64_t stat_bin_body_bits;
static uint64_t stat_bin_dyn_cp_bits;
static uint64_t stat_bin_dyn_wp_bits;
static uint64_t stat_bin_wp_exception_bits;
static uint64_t stat_bin_wp_poison_bits;

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
    if (entry->poison_mask) {
        g_byte_array_unref(entry->poison_mask);
    }
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
    g_free(tmpl->symbol_name);
    g_free(tmpl->insn_sizes);
    g_free(tmpl->insn_bytes);
    g_free(tmpl);
}

static TraceSegment *trace_segment_new(const char *label,
                                       uint64_t start, uint64_t stop)
{
    TraceSegment *seg = g_new0(TraceSegment, 1);
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
    if (seg->bin_stream) {
        g_free(seg->bin_stream);
    }
    if (seg->text_body_tmp) {
        fclose(seg->text_body_tmp);
    }
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

static uint8_t choose_exception_reg_id(const BBTemplate *tmpl)
{
    /* Prefer FP division destinations for exception bookkeeping. */
    for (uint32_t i = 0; i < tmpl->n_insns; i++) {
        const InsnFields *fld = &tmpl->insn_fields[i];
        if (fld->opcode != GEN_OP_FP_DIV) {
            continue;
        }
        for (uint8_t d = 0; d < fld->n_dst_regs; d++) {
            if (fld->dst_regs[d] != REG_NONE) {
                return fld->dst_regs[d];
            }
        }
        for (uint8_t s = 0; s < fld->n_src_regs; s++) {
            if (fld->src_regs[s] != REG_NONE) {
                return fld->src_regs[s];
            }
        }
    }

    for (uint32_t i = 0; i < tmpl->n_insns; i++) {
        const InsnFields *fld = &tmpl->insn_fields[i];
        for (uint8_t d = 0; d < fld->n_dst_regs; d++) {
            if (fld->dst_regs[d] != REG_NONE) {
                return fld->dst_regs[d];
            }
        }
    }
    return REG_NONE;
}

static uint8_t infer_generic_exception_id(const BBTemplate *tmpl)
{
    bool saw_mem = false;
    bool saw_fp_div = false;
    bool saw_int_div = false;

    if (!tmpl) {
        return GEN_EXC_UNKNOWN;
    }

    for (uint32_t i = 0; i < tmpl->n_insns; i++) {
        const InsnFields *fld = &tmpl->insn_fields[i];

        if (fld->opcode == GEN_OP_FP_DIV) {
            saw_fp_div = true;
        }
        if (fld->opcode == GEN_OP_INT_DIV) {
            saw_int_div = true;
        }
        if (fld->opcode == GEN_OP_LOAD || fld->opcode == GEN_OP_STORE) {
            saw_mem = true;
        }
    }

    if (saw_fp_div) {
        return GEN_EXC_FP_DIVIDE_BY_ZERO;
    }
    if (saw_int_div) {
        return GEN_EXC_INT_DIVIDE_BY_ZERO;
    }
    if (saw_mem) {
        return GEN_EXC_MEMORY_ACCESS;
    }
    return GEN_EXC_UNKNOWN;
}

static bool template_has_syscall(const BBTemplate *tmpl)
{
    if (!tmpl) {
        return false;
    }

    for (uint32_t i = 0; i < tmpl->n_insns; i++) {
        if (tmpl->insn_fields[i].opcode == GEN_OP_SYSCALL) {
            return true;
        }
    }

    return false;
}

static uint32_t find_faulting_insn_index(const BBTemplate *tmpl, uint8_t exid)
{
    if (!tmpl || tmpl->n_insns == 0) {
        return 0;
    }

    for (uint32_t i = 0; i < tmpl->n_insns; i++) {
        const InsnFields *fld = &tmpl->insn_fields[i];

        switch (exid) {
        case GEN_EXC_FP_DIVIDE_BY_ZERO:
            if (fld->opcode == GEN_OP_FP_DIV) {
                return i;
            }
            break;
        case GEN_EXC_INT_DIVIDE_BY_ZERO:
            if (fld->opcode == GEN_OP_INT_DIV) {
                return i;
            }
            break;
        case GEN_EXC_MEMORY_ACCESS:
            if (fld->opcode == GEN_OP_LOAD || fld->opcode == GEN_OP_STORE) {
                return i;
            }
            break;
        default:
            break;
        }
    }

    return tmpl->n_insns - 1;
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
                                          uint8_t *insn_sizes,
                                          uint8_t *insn_bytes,
                                          const char *symbol_name,
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
    tmpl->insn_sizes = g_new0(uint8_t, n_insns);
    tmpl->insn_bytes = g_new0(uint8_t, n_insns * MAX_INSN_BYTES);
    tmpl->symbol_name = symbol_name ? g_strdup(symbol_name) : NULL;

    for (uint32_t i = 0; i < n_insns; i++) {
        tmpl->insn_pcs[i] = insn_pcs[i];
        tmpl->insn_sizes[i] = insn_sizes[i];
        memcpy(&tmpl->insn_bytes[(size_t)i * MAX_INSN_BYTES],
               &insn_bytes[(size_t)i * MAX_INSN_BYTES],
               MAX_INSN_BYTES);
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
 * The insn_pc comes from udata set during vcpu_tb_trans registration.
 */
static void vcpu_mem_cb(unsigned int cpu_index,
                        qemu_plugin_meminfo_t info,
                        uint64_t vaddr,
                        void *udata)
{
    uint64_t insn_pc = (uint64_t)(uintptr_t)udata;

    if (wp_in_progress && wp_mem_accesses) {
        WPMemAccess acc = {
            .insn_pc = insn_pc,
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

static bool wp_target_is_poisoned(const GArray *poisoned_targets, uint64_t pc)
{
    for (guint i = 0; i < poisoned_targets->len; i++) {
        uint64_t poisoned_pc = g_array_index(poisoned_targets, uint64_t, i);
        if (poisoned_pc == pc) {
            return true;
        }
    }
    return false;
}

static void wp_poison_target(GArray *poisoned_targets, uint64_t pc)
{
    if (!wp_target_is_poisoned(poisoned_targets, pc)) {
        g_array_append_val(poisoned_targets, pc);
    }
}

/* ========================= Wrong-Path Simulation ========================= */

/*
 * Execute wrong-path basic blocks starting from @wrong_target.
 *
 * Flow per iteration:
 *   1. Execute one full TB at current PC via qemu_plugin_exec_tb().
 *      This triggers vcpu_tb_trans (template creation) and vcpu_mem_cb
 *      (memory access recording), but NOT vcpu_tb_exec or inline stores.
 *   2. Look up the template created by vcpu_tb_trans.
 *   3. Build a WPBBEntry from the template and collected memory accesses.
 *   4. Decide the next PC: not-taken for conditional branches, natural
 *      execution for unconditional/call/return.
 *   5. Repeat until instruction depth reached or fault.
 *
 * Returns a GArray of WPBBEntry representing the wrong-path BB chain.
 */
static GArray *simulate_wrong_path_ext(uint64_t branch_pc,
                                       uint64_t correct_target,
                                       uint64_t wrong_target,
                                       bool use_smith_prediction,
                                       unsigned int cpu_index)
{
    GArray *wp_chain = g_array_new(false, false, sizeof(WPBBEntry));
    GArray *poisoned_targets = g_array_new(false, false, sizeof(uint64_t));
    uint64_t sim_insns = 0;
    bool early_exit = false;
    uint64_t last_fault_pc = UINT64_MAX;
    unsigned int repeated_fault_pc = 0;

    /* Save complete CPU state for rollback */
    struct qemu_plugin_cpu_state *saved_state = qemu_plugin_cpu_state_save();
    if (!saved_state) {
        stat_wp_early_exits++;
        stat_wp_simulations++;
        return wp_chain;
    }

    /* Initialize wrong-path memory access collection */
    wp_mem_accesses = g_array_new(false, false, sizeof(WPMemAccess));

    /*
     * Save the correct-path instruction count before entering wrong-path.
     * Inline stores are suppressed by CF_MEMI_ONLY during TB execution,
     * but vcpu_tb_trans still fires and may trigger inline registration.
     */
    wp_saved_cpu_index = cpu_index;
    wp_saved_insn_count = qemu_plugin_u64_get(sb_insn_count, cpu_index);
    wp_saved_prev_start_pc = qemu_plugin_u64_get(sb_prev_start_pc, cpu_index);
    wp_saved_prev_last_pc = qemu_plugin_u64_get(sb_prev_last_pc, cpu_index);
    wp_saved_prev_fall_through = qemu_plugin_u64_get(sb_prev_fall_through,
                                                     cpu_index);
    wp_saved_prev_bb_ends_in_branch =
        qemu_plugin_u64_get(sb_prev_bb_ends_in_branch, cpu_index);
    wp_in_progress = true;

    /* Enter speculative mode, providing saved state for exception recovery */
    qemu_plugin_spec_mode_begin(saved_state);

    /* Set PC to wrong-path target */
    qemu_plugin_set_pc(wrong_target);

    while (sim_insns < (uint64_t)max_wrong_path_depth) {
        uint64_t pre_pc = qemu_plugin_get_pc();
        guint mem_start_idx = wp_mem_accesses->len;
        BBTemplate *tmpl = NULL;
        bool tb_ok;

        if (wp_target_is_poisoned(poisoned_targets, pre_pc)) {
            early_exit = true;
            break;
        }

        tb_ok = qemu_plugin_exec_tb();

        g_mutex_lock(&data_lock);
        tmpl = find_template(pre_pc);
        g_mutex_unlock(&data_lock);

        if (!tmpl) {
            early_exit = true;
            break;
        }

        if (!tb_ok) {
            uint64_t recovery_pc = qemu_plugin_get_pc();
            uint8_t exception_id;
            bool has_syscall;

            if (pre_pc == last_fault_pc) {
                repeated_fault_pc++;
            } else {
                repeated_fault_pc = 0;
                last_fault_pc = pre_pc;
            }

            exception_id = infer_generic_exception_id(tmpl);
            has_syscall = template_has_syscall(tmpl);

            WPBBEntry fault_wp = {
                .template_id = tmpl->template_id,
                .start_pc = pre_pc,
                .dyn_params = g_array_new(false, false, sizeof(DynParam)),
                .n_insns_executed = tmpl->n_insns,
                .fault = true,
                .translation_unavailable = false,
                .stop_reason = has_syscall ? WP_STOP_SYSCALL_USERMODE
                                           : WP_STOP_NONE,
                .exception_id = (exception_id == GEN_EXC_UNKNOWN)
                    ? GEN_EXC_NONE : exception_id,
                .exception_reg_id = REG_NONE,
                .has_exception_reg = false,
                .has_exception_class = false,
                .poison_mask = NULL,
            };

            if (!has_syscall && exception_id != GEN_EXC_UNKNOWN) {
                fault_wp.has_exception_class = true;
                fault_wp.exception_reg_id = choose_exception_reg_id(tmpl);
                fault_wp.has_exception_reg = (fault_wp.exception_reg_id != REG_NONE);
            }

            /* Collect memory access dynamic params for this faulting WP BB. */
            for (guint m = mem_start_idx; m < wp_mem_accesses->len; m++) {
                WPMemAccess *acc = &g_array_index(wp_mem_accesses,
                                                  WPMemAccess, m);
                DynParam dp = {
                    .type = acc->is_store ? DYN_STORE_ADDR : DYN_LOAD_ADDR,
                    .value = acc->mem_vaddr,
                };
                g_array_append_val(fault_wp.dyn_params, dp);
                stat_wp_total_mem_accesses++;
            }

            g_array_append_val(wp_chain, fault_wp);
            sim_insns += tmpl->n_insns;
            recovery_pc = tmpl->fall_through_pc;

            fault_wp.poison_mask = g_byte_array_sized_new(tmpl->n_insns);
            if (tmpl->n_insns > 0) {
                uint32_t fault_idx = tmpl->n_insns - 1;

                if (fault_wp.stop_reason == WP_STOP_SYSCALL_USERMODE) {
                    for (uint32_t i = 0; i < tmpl->n_insns; i++) {
                        if (tmpl->insn_fields[i].opcode == GEN_OP_SYSCALL) {
                            fault_idx = i;
                            break;
                        }
                    }
                } else if (fault_wp.has_exception_class) {
                    fault_idx = find_faulting_insn_index(
                        tmpl, fault_wp.exception_id);
                }
                if (fault_idx < tmpl->n_insns) {
                    g_byte_array_set_size(fault_wp.poison_mask,
                                          (guint)fault_idx + 1);
                    memset(fault_wp.poison_mask->data, 0,
                           fault_wp.poison_mask->len);
                    fault_wp.poison_mask->data[fault_idx] = 1;

                    if (fault_idx + 1 < tmpl->n_insns) {
                        recovery_pc = tmpl->insn_pcs[fault_idx]
                                    + tmpl->insn_sizes[fault_idx];
                    } else {
                        recovery_pc = tmpl->fall_through_pc;
                    }
                }
            }

            g_array_index(wp_chain, WPBBEntry, wp_chain->len - 1) = fault_wp;

            /*
             * Syscalls are terminal for speculative wrong-path continuation in
             * user mode; recovering to fall-through can walk into non-code
             * bytes and produce bogus templates.
             */
            if (fault_wp.stop_reason == WP_STOP_SYSCALL_USERMODE) {
                early_exit = true;
                break;
            }

            wp_poison_target(poisoned_targets, pre_pc);
            repeated_fault_pc = 0;
            last_fault_pc = UINT64_MAX;

            if (sim_insns < (uint64_t)max_wrong_path_depth) {
                if (repeated_fault_pc >= 16) {
                    early_exit = true;
                    break;
                }
                if (wp_target_is_poisoned(poisoned_targets, recovery_pc)) {
                    early_exit = true;
                    break;
                }
                /* Re-arm speculative mode and continue past the faulting TB. */
                qemu_plugin_spec_mode_end();
                qemu_plugin_cpu_state_restore(saved_state);
                qemu_plugin_spec_mode_begin(saved_state);
                qemu_plugin_set_pc(recovery_pc);
                continue;
            }

            early_exit = true;
            break;
        }

        uint64_t post_pc = qemu_plugin_get_pc();
        repeated_fault_pc = 0;
        last_fault_pc = UINT64_MAX;

        sim_insns += tmpl->n_insns;

        /* Build WPBBEntry from template */
        WPBBEntry wp_bb;
        wp_bb.start_pc = pre_pc;
        wp_bb.template_id = tmpl->template_id;
        wp_bb.n_insns_executed = tmpl->n_insns;
        wp_bb.fault = false;
        wp_bb.translation_unavailable = false;
        wp_bb.stop_reason = WP_STOP_NONE;
        wp_bb.exception_id = GEN_EXC_NONE;
        wp_bb.exception_reg_id = REG_NONE;
        wp_bb.has_exception_reg = false;
        wp_bb.has_exception_class = false;
        wp_bb.poison_mask = NULL;
        wp_bb.dyn_params = g_array_new(false, false, sizeof(DynParam));

        /* Collect memory access dynamic params for this WP BB */
        for (guint m = mem_start_idx; m < wp_mem_accesses->len; m++) {
            WPMemAccess *acc = &g_array_index(wp_mem_accesses,
                                              WPMemAccess, m);
            DynParam dp = {
                .type = acc->is_store ? DYN_STORE_ADDR : DYN_LOAD_ADDR,
                .value = acc->mem_vaddr,
            };
            g_array_append_val(wp_bb.dyn_params, dp);
            stat_wp_total_mem_accesses++;
        }

        /*
         * Decide next PC from the last instruction's branch type.
         * On wrong-path conditional branches, follow Smith predictor when
         * requested; otherwise keep natural execution.
         */
        InsnFields *last_fld = &tmpl->insn_fields[tmpl->n_insns - 1];
        uint8_t last_br = last_fld->branch_type;
        uint64_t chosen_target;
        bool conditional = (last_br != BRANCH_NONE && last_fld->branch_conditional);

        if (conditional && use_smith_prediction) {
            bool pred_taken = false;
            bool has_inner_br = false;
            bool natural_taken = (post_pc != tmpl->fall_through_pc);
            BranchRecord *inner_br;

            g_mutex_lock(&data_lock);
            inner_br = g_hash_table_lookup(branch_map, &tmpl->insn_pcs[tmpl->n_insns - 1]);
            if (inner_br) {
                has_inner_br = true;
                pred_taken = (inner_br->smith_counter >= 2);
            }
            g_mutex_unlock(&data_lock);

            if (!has_inner_br) {
                /* No predictor history yet: preserve natural execution path. */
                chosen_target = post_pc;
            } else if (pred_taken == natural_taken) {
                chosen_target = post_pc;
            } else if (pred_taken) {
                chosen_target = inner_br->has_taken_target
                    ? inner_br->taken_target
                    : post_pc;
            } else {
                chosen_target = tmpl->fall_through_pc;
            }
        } else {
            chosen_target = post_pc;
        }

        g_array_append_val(wp_chain, wp_bb);

        if (wp_target_is_poisoned(poisoned_targets, chosen_target)) {
            early_exit = true;
            break;
        }

        /* Redirect PC if prediction differs from natural execution */
        if (chosen_target != post_pc) {
            qemu_plugin_set_pc(chosen_target);
        }

    }

    /* Stop wrong-path collection */
    wp_in_progress = false;

    /* Restore correct-path instruction count */
    qemu_plugin_u64_set(sb_insn_count, cpu_index, wp_saved_insn_count);
    qemu_plugin_u64_set(sb_prev_start_pc, cpu_index, wp_saved_prev_start_pc);
    qemu_plugin_u64_set(sb_prev_last_pc, cpu_index, wp_saved_prev_last_pc);
    qemu_plugin_u64_set(sb_prev_fall_through, cpu_index,
                        wp_saved_prev_fall_through);
    qemu_plugin_u64_set(sb_prev_bb_ends_in_branch, cpu_index,
                        wp_saved_prev_bb_ends_in_branch);

    /* Exit speculative mode */
    qemu_plugin_spec_mode_end();

    /* Restore CPU state */
    qemu_plugin_cpu_state_restore(saved_state);
    qemu_plugin_cpu_state_free(saved_state);

    /* Clean up */
    g_array_unref(wp_mem_accesses);
    wp_mem_accesses = NULL;
    g_array_unref(poisoned_targets);

    /* Update statistics */
    stat_wp_simulations++;
    stat_wp_total_insns += sim_insns;
    if (early_exit) {
        stat_wp_early_exits++;
    }

    return wp_chain;
}

/* ========================= Output: Text Format ========================= */

static bool is_wait_prefix_insn(const BBTemplate *t, uint32_t idx);
static bool is_x87_opcode_byte(uint8_t b);
static BBTemplate *find_wait_prefix_predecessor(uint64_t start_pc);

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

    fprintf(f, "ENUMS\n-----\n");
    fprintf(f, "OPCODES %u\n", GEN_OP_COUNT);
    for (uint32_t i = 0; i < GEN_OP_COUNT; i++) {
        fprintf(f, "O %u %s\n", i, generic_opcode_name(i));
    }
    fprintf(f, "BRANCHES %u\n", BRANCH_TYPE_COUNT);
    for (uint32_t i = 0; i < BRANCH_TYPE_COUNT; i++) {
        fprintf(f, "B %u %s\n", i, branch_type_name(i));
    }
    fprintf(f, "WP_STOP_REASONS %u\n", WP_STOP_REASON_COUNT);
    for (uint32_t i = 0; i < WP_STOP_REASON_COUNT; i++) {
        fprintf(f, "S %u %s\n", i, wp_stop_reason_name(i));
    }
    fprintf(f, "EXCEPTIONS %u\n", GEN_EXC_COUNT);
    for (uint32_t i = 0; i < GEN_EXC_COUNT; i++) {
        fprintf(f, "E %u %s\n", i, generic_exception_name(i));
    }
    fprintf(f, "REGS 198\n");
    fprintf(f, "R %u %s\n", REG_NONE, generic_reg_name(REG_NONE));
    for (uint32_t i = 0; i < 64; i++) {
        uint8_t rid = REG_GPR0 + i;
        fprintf(f, "R %u %s\n", rid, generic_reg_name(rid));
    }
    for (uint32_t i = 0; i < 64; i++) {
        uint8_t rid = REG_FPR0 + i;
        fprintf(f, "R %u %s\n", rid, generic_reg_name(rid));
    }
    for (uint32_t i = 0; i < 64; i++) {
        uint8_t rid = REG_VEC0 + i;
        fprintf(f, "R %u %s\n", rid, generic_reg_name(rid));
    }
    fprintf(f, "R %u %s\n", REG_SP, generic_reg_name(REG_SP));
    fprintf(f, "R %u %s\n", REG_FLAGS, generic_reg_name(REG_FLAGS));
    fprintf(f, "R %u %s\n", REG_IP, generic_reg_name(REG_IP));
    fprintf(f, "R %u %s\n", REG_LR, generic_reg_name(REG_LR));
    fprintf(f, "R %u %s\n", REG_FP_REG, generic_reg_name(REG_FP_REG));
    fprintf(f, "\n");

    fprintf(f, "HEADER\n------\n");

    g_hash_table_iter_init(&iter, template_map);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        BBTemplate *tmpl = value;
        BBTemplate *pred_wait = find_wait_prefix_predecessor(tmpl->start_pc);
        bool skip_first_as_merged_suffix = false;
        fprintf(f, "BB%" PRIu32 " [pc=0x%" PRIx64 ", insns=%" PRIu32
                ", fall_through=0x%" PRIx64 "]\n",
                tmpl->template_id, tmpl->start_pc,
                tmpl->n_insns, tmpl->fall_through_pc);
        if (tmpl->symbol_name) {
            fprintf(f, "  symbol=%s\n", tmpl->symbol_name);
        }

        if (pred_wait && tmpl->n_insns > 0 && tmpl->insn_sizes[0] > 0) {
            uint8_t first_b = tmpl->insn_bytes[0];
            skip_first_as_merged_suffix = is_x87_opcode_byte(first_b);
        }

        for (uint32_t i = 0; i < tmpl->n_insns; i++) {
            InsnFields *fld = &tmpl->insn_fields[i];
            const InsnFields *print_fld = fld;
            uint64_t print_pc = tmpl->insn_pcs[i];
            bool merged_wait_prefix = false;
            uint8_t merged_bytes[MAX_INSN_BYTES] = {0};
            uint8_t merged_size = 0;

            if (skip_first_as_merged_suffix && i == 0) {
                continue;
            }

            if (i == tmpl->n_insns - 1 && is_wait_prefix_insn(tmpl, i)) {
                BBTemplate *succ = find_template(tmpl->fall_through_pc);
                if (succ && succ->n_insns > 0 && succ->insn_sizes[0] > 0 &&
                    succ->insn_pcs[0] == tmpl->insn_pcs[i] + 1 &&
                    is_x87_opcode_byte(succ->insn_bytes[0])) {
                    uint8_t succ_size = succ->insn_sizes[0];
                    merged_size = (uint8_t)MIN((int)MAX_INSN_BYTES,
                                               1 + (int)succ_size);
                    merged_bytes[0] = 0x9b;
                    if (merged_size > 1) {
                        memcpy(&merged_bytes[1], &succ->insn_bytes[0],
                               merged_size - 1);
                    }
                    print_fld = &succ->insn_fields[0];
                    merged_wait_prefix = true;
                }
            }

            fprintf(f, "  [%u] 0x%" PRIx64 ": op=%s",
                    i, print_pc, generic_opcode_name(print_fld->opcode));

            if (print_fld->branch_type != BRANCH_NONE) {
                fprintf(f, " br=%s", branch_type_name(print_fld->branch_type));
                fprintf(f, " cond=%u", print_fld->branch_conditional ? 1 : 0);
            }

            fprintf(f, " src=[");
            for (uint8_t s = 0; s < print_fld->n_src_regs; s++) {
                if (s > 0) fprintf(f, ",");
                fprintf(f, "%s", generic_reg_name(print_fld->src_regs[s]));
            }
            fprintf(f, "] dst=[");
            for (uint8_t d = 0; d < print_fld->n_dst_regs; d++) {
                if (d > 0) fprintf(f, ",");
                fprintf(f, "%s", generic_reg_name(print_fld->dst_regs[d]));
            }
            fprintf(f, "]");

            if (print_fld->has_immediate) {
                fprintf(f, " imm=%" PRId64, print_fld->immediate);
            }
            fprintf(f, " bytes=");
            if (merged_wait_prefix) {
                for (uint8_t b = 0; b < merged_size; b++) {
                    fprintf(f, "%02x", merged_bytes[b]);
                }
            } else {
                for (uint8_t b = 0; b < tmpl->insn_sizes[i]; b++) {
                    fprintf(f, "%02x",
                            tmpl->insn_bytes[(size_t)i * MAX_INSN_BYTES + b]);
                }
            }
            fprintf(f, "\n");
        }
        fprintf(f, "\n");
    }
}

/*
 * Write the body section (execution trace) in human-readable text format.
 */
static void write_text_body_entry(FILE *f, const BodyEntry *entry)
{
    if (!f) {
        return;
    }
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
            if (wp->fault) {
                fprintf(f, " FAULT");
                if (wp->stop_reason != WP_STOP_NONE) {
                    fprintf(f, " stop=%s",
                            wp_stop_reason_name(wp->stop_reason));
                }
                if (wp->has_exception_class) {
                    fprintf(f, " exid=%s",
                            generic_exception_name(wp->exception_id));
                    if (wp->has_exception_reg) {
                        fprintf(f, " exreg=%s",
                                generic_reg_name(wp->exception_reg_id));
                    }
                }
            }
            if (wp->translation_unavailable) {
                fprintf(f, " TRANSLATION_UNAVAILABLE");
            }
            if (wp->poison_mask && wp->poison_mask->len > 0) {
                fprintf(f, " poison=");
                for (guint p = 0; p < wp->poison_mask->len; p++) {
                    fprintf(f, "%u", wp->poison_mask->data[p] ? 1 : 0);
                }
            }
            fprintf(f, " n_insns=%" PRIu32, wp->n_insns_executed);
            fprintf(f, "]");
        }
    }
    fprintf(f, "\n");
}

static bool is_wait_prefix_insn(const BBTemplate *t, uint32_t idx)
{
    return t && idx < t->n_insns &&
           t->insn_sizes[idx] == 1 &&
           t->insn_bytes[(size_t)idx * MAX_INSN_BYTES] == 0x9b;
}

static bool is_x87_opcode_byte(uint8_t b)
{
    return b >= 0xd8 && b <= 0xdf;
}

/* Find predecessor template that ends with standalone 0x9b before @start_pc. */
static BBTemplate *find_wait_prefix_predecessor(uint64_t start_pc)
{
    GHashTableIter it;
    gpointer v;

    g_hash_table_iter_init(&it, template_map);
    while (g_hash_table_iter_next(&it, NULL, &v)) {
        BBTemplate *cand = v;
        uint32_t last;

        if (!cand || cand->n_insns == 0 || cand->fall_through_pc != start_pc) {
            continue;
        }

        last = cand->n_insns - 1;
        if (cand->insn_pcs[last] + 1 == start_pc &&
            is_wait_prefix_insn(cand, last)) {
            return cand;
        }
    }

    return NULL;
}

/*
 * Write a complete trace in text format (header + streamed body).
 */
static void write_text_trace(FILE *f, FILE *body_tmp)
{
    uint8_t buf[8192];
    size_t nread;

    g_mutex_lock(&data_lock);
    write_text_header(f);
    g_mutex_unlock(&data_lock);
    fprintf(f, "BODY\n----\n");
    if (!body_tmp) {
        return;
    }
    fflush(body_tmp);
    rewind(body_tmp);
    while ((nread = fread(buf, 1, sizeof(buf), body_tmp)) > 0) {
        fwrite(buf, 1, nread, f);
    }
}

/* ========================= Output: Binary Format ========================= */

/*
 * Bit writer for tightly packed binary output.
 * Bits are appended least-significant-bit first.
 */
typedef struct {
    FILE *f;
    uint8_t cur;
    uint8_t used;
    uint64_t total_bits;
} BitWriter;

static inline void bw_init(BitWriter *bw, FILE *f)
{
    bw->f = f;
    bw->cur = 0;
    bw->used = 0;
    bw->total_bits = 0;
}

static inline uint64_t bw_tell_bits(const BitWriter *bw)
{
    return bw->total_bits;
}

static inline void bw_flush(BitWriter *bw)
{
    if (bw->used > 0) {
        fwrite(&bw->cur, 1, 1, bw->f);
        bw->cur = 0;
        bw->used = 0;
    }
}

static void bw_write_bits(BitWriter *bw, uint64_t value, uint8_t nbits)
{
    while (nbits > 0) {
        uint8_t avail = 8 - bw->used;
        uint8_t take = MIN(avail, nbits);
        uint8_t mask = (1U << take) - 1U;

        bw->cur |= (uint8_t)((value & mask) << bw->used);
        value >>= take;
        bw->used += take;
        bw->total_bits += take;
        nbits -= take;

        if (bw->used == 8) {
            fwrite(&bw->cur, 1, 1, bw->f);
            bw->cur = 0;
            bw->used = 0;
        }
    }
}

static uint32_t bits_for_uleb128(uint64_t v)
{
    uint32_t bits = 0;

    do {
        bits += 8;
        v >>= 7;
    } while (v != 0);

    return bits;
}

static void bw_write_uleb128(BitWriter *bw, uint64_t v)
{
    do {
        uint8_t byte = v & 0x7F;
        v >>= 7;
        if (v != 0) {
            byte |= 0x80;
        }
        bw_write_bits(bw, byte, 8);
    } while (v != 0);
}

static void bw_write_sleb128(BitWriter *bw, int64_t v)
{
    bool more = true;

    while (more) {
        uint8_t byte = (uint8_t)(v & 0x7F);
        bool sign = (byte & 0x40) != 0;
        v >>= 7;
        more = !((v == 0 && !sign) || (v == -1 && sign));
        if (more) {
            byte |= 0x80;
        }
        bw_write_bits(bw, byte, 8);
    }
}

static void bw_write_bytes(BitWriter *bw, const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        bw_write_bits(bw, buf[i], 8);
    }
}

struct BodyStreamState {
    BitWriter bw;
    int64_t prev_entry_template;
    GHashTable *cp_dyn_state;   /* template_id -> last dyn params */
    GHashTable *wp_dyn_state;   /* wp template_id -> last dyn params */
    uint64_t num_entries;
};

/*
 * Write template metadata section in packed binary format.
 *
 * Template metadata layout:
 *   num_templates:    ULEB128
 *   For each template:
 *     template_id:      ULEB128
 *     start_pc:         ULEB128
 *     num_insns:        ULEB128
 *     fall_through_pc:  ULEB128
 *     For each instruction:
 *       pc:             ULEB128
 *       opcode:         8 bits (GenericOpcode)
 *       branch_type:    8 bits (BranchType)
 *       branch_cond:    1 bit
 *       n_src:          3 bits
 *       n_dst:          3 bits
 *       src_regs:       [n_src bytes] (GenericRegId)
 *       dst_regs:       [n_dst bytes] (GenericRegId)
 *       has_imm:        1 bit
 *       imm:            SLEB128 (only if has_imm == 1)
 */
static void write_bin_templates(BitWriter *bw)
{
    GHashTableIter iter;
    gpointer value;

    bw_write_uleb128(bw, g_hash_table_size(template_map));

    g_hash_table_iter_init(&iter, template_map);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        BBTemplate *tmpl = value;
        bw_write_uleb128(bw, tmpl->template_id);
        bw_write_uleb128(bw, tmpl->start_pc);
        bw_write_uleb128(bw, tmpl->n_insns);
        bw_write_uleb128(bw, tmpl->fall_through_pc);

        for (uint32_t i = 0; i < tmpl->n_insns; i++) {
            InsnFields *fld = &tmpl->insn_fields[i];

            /* Per-insn: pc + compact decoded fields */
            bw_write_uleb128(bw, tmpl->insn_pcs[i]);
            bw_write_bits(bw, fld->opcode, WPT_OPCODE_BITS);
            bw_write_bits(bw, fld->branch_type, WPT_BRANCH_BITS);
            bw_write_bits(bw, fld->branch_conditional ? 1 : 0, 1);
            bw_write_bits(bw, fld->n_src_regs, WPT_REG_COUNT_BITS);
            bw_write_bits(bw, fld->n_dst_regs, WPT_REG_COUNT_BITS);
            bw_write_bits(bw, fld->has_immediate ? 1 : 0, 1);

            for (uint8_t s = 0; s < fld->n_src_regs; s++) {
                bw_write_bits(bw, fld->src_regs[s], WPT_REG_BITS);
            }
            for (uint8_t d = 0; d < fld->n_dst_regs; d++) {
                bw_write_bits(bw, fld->dst_regs[d], WPT_REG_BITS);
            }
            if (fld->has_immediate) {
                bw_write_sleb128(bw, fld->immediate);
            }
            bw_write_uleb128(bw, tmpl->insn_sizes[i]);
        }
    }
}

static gboolean dyn_param_array_equal(const GArray *a, const GArray *b)
{
    if (a == b) {
        return true;
    }
    if (!a || !b || a->len != b->len) {
        return false;
    }

    for (guint i = 0; i < a->len; i++) {
        const DynParam *da = &g_array_index(a, DynParam, i);
        const DynParam *db = &g_array_index(b, DynParam, i);
        if (da->type != db->type || da->value != db->value) {
            return false;
        }
    }

    return true;
}

static GArray *dyn_param_array_clone(const GArray *src)
{
    GArray *dst = g_array_sized_new(false, false, sizeof(DynParam),
                                    src ? src->len : 0);

    if (!src) {
        return dst;
    }

    for (guint i = 0; i < src->len; i++) {
        const DynParam *d = &g_array_index(src, DynParam, i);
        DynParam copy = {
            .type = d->type,
            .value = d->value,
        };
        g_array_append_val(dst, copy);
    }

    return dst;
}

static void dyn_param_array_unref_value(gpointer value)
{
    if (value) {
        g_array_unref((GArray *)value);
    }
}

static inline uint8_t dyn_param_type_bit(const DynParam *dp)
{
    g_assert(dp->type == DYN_LOAD_ADDR || dp->type == DYN_STORE_ADDR);
    return (dp->type == DYN_STORE_ADDR) ? 1 : 0;
}

static void dyn_param_collect_changed_positions(const GArray *prev_dyn,
                                                const GArray *cur_dyn,
                                                GArray *changed_positions)
{
    guint prev_len = prev_dyn ? prev_dyn->len : 0;
    guint cur_len = cur_dyn ? cur_dyn->len : 0;
    guint common = MIN(prev_len, cur_len);

    for (guint i = 0; i < common; i++) {
        const DynParam *prev = &g_array_index(prev_dyn, DynParam, i);
        const DynParam *cur = &g_array_index(cur_dyn, DynParam, i);

        if (prev->type != cur->type || prev->value != cur->value) {
            g_array_append_val(changed_positions, i);
        }
    }

    for (guint i = common; i < cur_len; i++) {
        g_array_append_val(changed_positions, i);
    }
}

static void write_dyn_param_patch(BitWriter *bw,
                                  const GArray *prev_dyn,
                                  const GArray *cur_dyn,
                                  const GArray *changed_positions,
                                  bool is_wp)
{
    int64_t prev_pos = -1;
    uint64_t patch_start_bits = bw_tell_bits(bw);

    bw_write_uleb128(bw, cur_dyn->len);
    bw_write_uleb128(bw, changed_positions->len);

    for (guint c = 0; c < changed_positions->len; c++) {
        guint pos = g_array_index(changed_positions, guint, c);
        const DynParam *cur = &g_array_index(cur_dyn, DynParam, pos);
        uint64_t pos_gap = (uint64_t)(pos - (guint)(prev_pos + 1));
        int64_t base_value = 0;
        int64_t delta;

        if (prev_dyn && pos < prev_dyn->len) {
            const DynParam *prev = &g_array_index(prev_dyn, DynParam, pos);
            base_value = prev->value;
        }
        delta = (int64_t)cur->value - base_value;

        bw_write_uleb128(bw, pos_gap);
        bw_write_bits(bw, dyn_param_type_bit(cur), WPT_DYN_TYPE_BITS);
        bw_write_sleb128(bw, delta);

        prev_pos = pos;
    }

    if (is_wp) {
        stat_bin_dyn_wp_bits += bw_tell_bits(bw) - patch_start_bits;
    } else {
        stat_bin_dyn_cp_bits += bw_tell_bits(bw) - patch_start_bits;
    }
}

/* Return the number of poison bytes that carry useful data. */
static guint poison_mask_effective_len(const GByteArray *poison_mask)
{
    if (!poison_mask || poison_mask->len == 0) {
        return 0;
    }

    for (gint i = (gint)poison_mask->len - 1; i >= 0; i--) {
        if (poison_mask->data[i] != 0) {
            return (guint)i + 1;
        }
    }

    return 0;
}

static BodyStreamState *body_stream_new(FILE *f)
{
    BodyStreamState *st = g_new0(BodyStreamState, 1);

    bw_init(&st->bw, f);
    bw_write_bits(&st->bw, WPT_MAGIC, 32);
    bw_write_bits(&st->bw, (uint8_t)trace_isa, WPT_ISA_BITS);
    st->cp_dyn_state = g_hash_table_new_full(g_int_hash, g_int_equal,
                                             g_free,
                                             dyn_param_array_unref_value);
    st->wp_dyn_state = g_hash_table_new_full(g_int_hash, g_int_equal,
                                             g_free,
                                             dyn_param_array_unref_value);
    return st;
}

static void body_stream_write_entry(BodyStreamState *st, const BodyEntry *entry)
{
    int64_t entry_tmpl = entry->template_id;
    uint32_t num_wp = entry->wp_entries ? entry->wp_entries->len : 0;
    uint64_t body_start_bits = bw_tell_bits(&st->bw);

    bw_write_bits(&st->bw, 1, 1); /* entry marker */
    bw_write_sleb128(&st->bw, entry_tmpl - st->prev_entry_template);
    st->prev_entry_template = entry_tmpl;
    {
        GArray *prev_dyn = g_hash_table_lookup(st->cp_dyn_state,
                                               &entry->template_id);
        gboolean unchanged = prev_dyn &&
            dyn_param_array_equal(prev_dyn, entry->dyn_params);
        bw_write_bits(&st->bw, unchanged ? 1 : 0, 1);

        if (!unchanged) {
            g_autoptr(GArray) changed_positions = g_array_new(false,
                                                              false,
                                                              sizeof(guint));

            dyn_param_collect_changed_positions(prev_dyn,
                                                entry->dyn_params,
                                                changed_positions);
            write_dyn_param_patch(&st->bw, prev_dyn, entry->dyn_params,
                                  changed_positions, false);

            {
                uint32_t *key = g_new(uint32_t, 1);
                *key = entry->template_id;
                g_hash_table_replace(st->cp_dyn_state, key,
                                     dyn_param_array_clone(entry->dyn_params));
            }
        }
    }

    bw_write_uleb128(&st->bw, num_wp);
    /*
     * We intentionally encode only one wrong-path chain per correct-path BB:
     * the Smith-predicted continuation. Encoding the full wrong-path tree up
     * to depth 64 is not tractable in the presence of indirect control-flow
     * because fanout can explode and target sets are runtime-dependent.
     */
    {
        int64_t prev_wp_tid = 0;

        for (uint32_t w = 0; w < num_wp; w++) {
            const WPBBEntry *wp = &g_array_index(entry->wp_entries, WPBBEntry, w);
            uint32_t wp_tmpl = wp->template_id;
            GArray *prev_dyn = g_hash_table_lookup(st->wp_dyn_state, &wp_tmpl);
            gboolean unchanged = prev_dyn &&
                dyn_param_array_equal(prev_dyn, wp->dyn_params);

            bw_write_sleb128(&st->bw, (int64_t)wp_tmpl - prev_wp_tid);
            prev_wp_tid = wp_tmpl;
            bw_write_bits(&st->bw, unchanged ? 1 : 0, 1);

            if (!unchanged) {
                g_autoptr(GArray) changed_positions = g_array_new(false,
                                                                  false,
                                                                  sizeof(guint));

                dyn_param_collect_changed_positions(prev_dyn,
                                                    wp->dyn_params,
                                                    changed_positions);
                write_dyn_param_patch(&st->bw, prev_dyn, wp->dyn_params,
                                      changed_positions, true);

                {
                    uint32_t *key = g_new(uint32_t, 1);
                    *key = wp_tmpl;
                    g_hash_table_replace(st->wp_dyn_state, key,
                                         dyn_param_array_clone(wp->dyn_params));
                }
            }
        }
    }

    {
        uint32_t num_events = 0;
        int64_t prev_event_idx = -1;
        uint64_t exc_start_bits;

        for (uint32_t w = 0; w < num_wp; w++) {
            const WPBBEntry *wp = &g_array_index(entry->wp_entries, WPBBEntry, w);
            if (wp->fault || wp->translation_unavailable) {
                num_events++;
            }
        }

        bw_write_uleb128(&st->bw, num_events);
        exc_start_bits = bw_tell_bits(&st->bw);

        for (uint32_t w = 0; w < num_wp; w++) {
            const WPBBEntry *wp = &g_array_index(entry->wp_entries, WPBBEntry, w);

            if (!wp->fault && !wp->translation_unavailable) {
                continue;
            }

            bw_write_uleb128(&st->bw, (uint64_t)(w - (uint32_t)(prev_event_idx + 1)));
            bw_write_bits(&st->bw, wp->translation_unavailable ? 1 : 0, 1);
            bw_write_bits(&st->bw, wp->fault ? 1 : 0, 1);

            if (wp->fault) {
                bw_write_bits(&st->bw, wp->stop_reason, 8);
                bw_write_bits(&st->bw, wp->has_exception_class ? 1 : 0, 1);
                if (wp->has_exception_class) {
                    bw_write_bits(&st->bw, wp->exception_id, 8);
                    bw_write_bits(&st->bw, wp->has_exception_reg ? 1 : 0, 1);
                    if (wp->has_exception_reg) {
                        bw_write_bits(&st->bw, wp->exception_reg_id, WPT_REG_BITS);
                    }
                }
                if (wp->poison_mask) {
                    guint poison_len = poison_mask_effective_len(wp->poison_mask);

                    bw_write_uleb128(&st->bw, poison_len);
                    if (poison_len > 0) {
                        bw_write_bytes(&st->bw, wp->poison_mask->data, poison_len);
                    }
                    stat_bin_wp_poison_bits += bits_for_uleb128(poison_len)
                                             + ((uint64_t)poison_len * 8);
                } else {
                    bw_write_uleb128(&st->bw, 0);
                    stat_bin_wp_poison_bits += bits_for_uleb128(0);
                }
            }

            prev_event_idx = w;
        }

        stat_bin_wp_exception_bits += bw_tell_bits(&st->bw) - exc_start_bits;
    }

    st->num_entries++;
    stat_bin_body_bits += bw_tell_bits(&st->bw) - body_start_bits;
}

static void body_stream_finish(BodyStreamState *st)
{
    uint64_t footer_start_bits;
    uint64_t end_bits;

    bw_write_bits(&st->bw, 0, 1); /* footer marker */
    footer_start_bits = bw_tell_bits(&st->bw);
    bw_write_uleb128(&st->bw, st->num_entries);
    g_mutex_lock(&data_lock);
    write_bin_templates(&st->bw);
    g_mutex_unlock(&data_lock);
    bw_flush(&st->bw);
    end_bits = bw_tell_bits(&st->bw);

    stat_bin_header_bits += end_bits - footer_start_bits;
    stat_bin_total_bits += end_bits;

    g_hash_table_unref(st->cp_dyn_state);
    g_hash_table_unref(st->wp_dyn_state);
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

static void load_simpoint_weights_file(const char *path, GArray *entries)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        double weight;
        int cluster;

        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }

        if (sscanf(line, "%lf %d", &weight, &cluster) == 2) {
            for (guint i = 0; i < entries->len; i++) {
                SimPointEntry *sp = &g_array_index(entries, SimPointEntry, i);
                if (sp->cluster_id == cluster) {
                    sp->weight = weight;
                }
            }
        }
    }

    fclose(f);
}

/*
 * Parse native SimPoint selections.
 * Input format:
 *   <interval_id> <cluster_id>
 * where start/stop are derived from
 *   interval_id * simpoint_interval_insns.
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

        SimPointEntry sp = {0};

        {
            uint64_t interval_id;
            int cluster_id = -1;
            int parsed = sscanf(line, "%" SCNu64 " %d", &interval_id,
                                &cluster_id);

            if (parsed >= 1) {
                uint64_t start = interval_id * simpoint_interval_insns;
                uint64_t stop = (simpoint_interval_insns > UINT64_MAX - start)
                    ? UINT64_MAX
                    : start + simpoint_interval_insns;

                sp.interval_id = interval_id;
                sp.start_insn = start;
                sp.stop_insn = stop;
                sp.cluster_id = (parsed == 2) ? cluster_id : (int)entries->len;
                sp.weight = 0.0;
                g_array_append_val(entries, sp);
            }
        }
    }

    fclose(f);

    {
        g_autofree char *weights_path = NULL;
        if (g_str_has_suffix(path, ".simpoints")) {
            weights_path = g_strndup(path, strlen(path) - strlen(".simpoints"));
            weights_path = g_strconcat(weights_path, ".weights", NULL);
        } else {
            weights_path = g_strdup_printf("%s.weights", path);
        }
        load_simpoint_weights_file(weights_path, entries);
    }

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
        } else {
            current_segment->bin_stream = body_stream_new(current_segment->bin_file);
            if (!current_segment->bin_stream) {
                fprintf(stderr, "wptrace: cannot initialize binary stream\n");
            }
        }
    }

    if (txt_path) {
        current_segment->text_file = fopen(txt_path, "w");
        if (!current_segment->text_file) {
            fprintf(stderr, "wptrace: cannot open text output: %s\n",
                    txt_path);
        } else {
            current_segment->text_body_tmp = tmpfile();
            if (!current_segment->text_body_tmp) {
                fprintf(stderr, "wptrace: cannot create text body staging file\n");
            }
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
    if (current_segment->bin_stream) {
        body_stream_finish(current_segment->bin_stream);
    }
    if (current_segment->text_file) {
        write_text_trace(current_segment->text_file,
                         current_segment->text_body_tmp);
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
    uint64_t n_insns = (uint64_t)(uintptr_t)udata;

    g_mutex_lock(&exec_lock);

    if (!wp_in_progress) {
        uint64_t icount_prev = qemu_plugin_u64_get(sb_insn_count, cpu_index);
        qemu_plugin_u64_set(sb_insn_count, cpu_index, icount_prev + n_insns);
    }

    uint64_t icount = qemu_plugin_u64_get(sb_insn_count, cpu_index);

    /* Don't trigger inside wrong-path execution */
    if (wp_in_progress) {
        g_mutex_unlock(&exec_lock);
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
            g_mutex_unlock(&exec_lock);
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
            g_mutex_unlock(&exec_lock);
            exit(0);
        }
    }

    if (!trace_active || !current_segment) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    if (!cp_mem_accesses) {
        cp_mem_accesses = g_array_new(false, false, sizeof(WPMemAccess));
    }

    uint64_t current_pc = qemu_plugin_u64_get(sb_current_pc, cpu_index);
    uint64_t prev_start = qemu_plugin_u64_get(sb_prev_start_pc, cpu_index);
    uint64_t prev_last = qemu_plugin_u64_get(sb_prev_last_pc, cpu_index);
    uint64_t prev_ft = qemu_plugin_u64_get(sb_prev_fall_through, cpu_index);
    bool prev_is_branch = qemu_plugin_u64_get(sb_prev_bb_ends_in_branch,
                                              cpu_index);

    /* Skip initial block (no previous context) */
    if (prev_ft == 0) {
        g_mutex_unlock(&exec_lock);
        return;
    }

    bool branch_taken = (current_pc != prev_ft);

    g_mutex_lock(&data_lock);

    if (prev_is_branch) {
        stat_branches_observed++;
        if (branch_taken) {
            stat_branches_taken++;
        } else {
            stat_branches_not_taken++;
        }
    }

    /* Find or create branch record */
    BranchRecord *br = g_hash_table_lookup(branch_map, &prev_last);
    if (prev_is_branch && !br) {
        br = g_new0(BranchRecord, 1);
        br->pc = prev_last;
        br->fall_through = prev_ft;
        br->smith_counter = 1;
        g_hash_table_replace(branch_map, &br->pc, br);
    }

    if (prev_is_branch && branch_taken) {
        br->taken_target = current_pc;
        br->has_taken_target = true;
    }

    if (prev_is_branch) {
        br->smith_counter = smith_update(br->smith_counter, branch_taken);
    }

    /* Determine wrong-path target */
    uint64_t wrong_target = 0;
    if (!prev_is_branch) {
        wrong_target = 0;
    } else if (branch_taken) {
        wrong_target = prev_ft;
    } else if (br->has_taken_target) {
        wrong_target = br->taken_target;
    } else {
        /* Always explore a speculative path when wrong-path tracing is enabled. */
        wrong_target = prev_ft;
    }

    /* Find template for previous BB (the one whose dynamic params we carry). */
    BBTemplate *cp_tmpl = find_template(prev_start);

    g_mutex_unlock(&data_lock);

    /* --- Collect body entry if tracing is active --- */
    if (trace_active && current_segment) {
        BodyEntry entry;
        guint cp_mem_len = cp_mem_accesses ? cp_mem_accesses->len : 0;
        entry.seq_num = ++body_seq_num;
        entry.template_id = cp_tmpl ? cp_tmpl->template_id : 0;
        entry.dyn_params = g_array_sized_new(false, false,
                             sizeof(DynParam), cp_mem_len);
        entry.wp_entries = NULL;

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
                prev_last, current_pc, wrong_target,
                true,
                cpu_index);
        } else if (wrong_target == 0) {
            stat_wp_skipped++;
        }

        if (current_segment->bin_stream) {
            body_stream_write_entry(current_segment->bin_stream, &entry);
        }
        if (current_segment->text_body_tmp) {
            write_text_body_entry(current_segment->text_body_tmp, &entry);
        }
        body_entry_clear(&entry);
    }

    g_mutex_unlock(&exec_lock);
}

/* ========================= Translation Callback ========================= */

static bool disas_starts_with_fp_mnemonic(const char *disas)
{
    if (!disas) {
        return false;
    }

    while (*disas && g_ascii_isspace(*disas)) {
        disas++;
    }

    return (disas[0] == 'f' || disas[0] == 'F');
}

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
    uint64_t bb_ends_in_branch = 0;

    /* Collect raw instruction data for BB template and callbacks */
    uint64_t *raw_insn_pcs = g_new0(uint64_t, n_insns);
    char **raw_insn_disas_arr = g_new0(char *, n_insns);
    uint8_t *raw_insn_sizes = g_new0(uint8_t, n_insns);
    uint8_t *raw_insn_bytes = g_new0(uint8_t, n_insns * MAX_INSN_BYTES);
    uint64_t *tmpl_insn_pcs = g_new0(uint64_t, n_insns);
    char **tmpl_insn_disas_arr = g_new0(char *, n_insns);
    uint8_t *tmpl_insn_sizes = g_new0(uint8_t, n_insns);
    uint8_t *tmpl_insn_bytes = g_new0(uint8_t, n_insns * MAX_INSN_BYTES);
    size_t tmpl_n_insns = 0;
    const char *symbol_name = qemu_plugin_insn_symbol(first_insn);

    for (size_t i = 0; i < n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        raw_insn_pcs[i] = qemu_plugin_insn_vaddr(insn);

        /* Get disassembly string from QEMU's internal disassembler */
        raw_insn_disas_arr[i] = qemu_plugin_insn_disas(insn);
        raw_insn_sizes[i] = (uint8_t)MIN(qemu_plugin_insn_size(insn), MAX_INSN_BYTES);
        qemu_plugin_insn_data(insn,
                      &raw_insn_bytes[i * MAX_INSN_BYTES],
                      raw_insn_sizes[i]);

        /* Register per-instruction memory callback with PC as udata */
        qemu_plugin_register_vcpu_mem_cb(
            insn, vcpu_mem_cb, QEMU_PLUGIN_CB_NO_REGS,
            QEMU_PLUGIN_MEM_RW, (void *)(uintptr_t)raw_insn_pcs[i]);
    }

    /*
     * Normalize template instruction stream for x86 x87 wait-prefix encoding.
     * Binutils often prints "9b dd d8" as a single prefixed instruction,
     * while QEMU disassembly can surface a standalone "9b" followed by the
     * x87 op. Coalesce these into one traced instruction so bytes/opcode align
     * with disassembly expectations.
     */
    for (size_t i = 0; i < n_insns; i++) {
        bool can_merge_wait_prefix =
            (trace_isa == TRACE_ISA_X86) &&
            (i + 1 < n_insns) &&
            (raw_insn_sizes[i] == 1) &&
            (raw_insn_bytes[i * MAX_INSN_BYTES] == 0x9b) &&
            (raw_insn_pcs[i] + 1 == raw_insn_pcs[i + 1]) &&
            disas_starts_with_fp_mnemonic(raw_insn_disas_arr[i + 1]);

        if (can_merge_wait_prefix) {
            uint8_t next_sz = raw_insn_sizes[i + 1];
            uint8_t merged_sz = (uint8_t)MIN((int)MAX_INSN_BYTES,
                                             1 + (int)next_sz);

            tmpl_insn_pcs[tmpl_n_insns] = raw_insn_pcs[i];
            tmpl_insn_disas_arr[tmpl_n_insns] = raw_insn_disas_arr[i + 1];
            raw_insn_disas_arr[i + 1] = NULL;
            tmpl_insn_sizes[tmpl_n_insns] = merged_sz;
            memset(&tmpl_insn_bytes[tmpl_n_insns * MAX_INSN_BYTES], 0,
                   MAX_INSN_BYTES);
            tmpl_insn_bytes[tmpl_n_insns * MAX_INSN_BYTES] = 0x9b;
            if (merged_sz > 1) {
                memcpy(&tmpl_insn_bytes[tmpl_n_insns * MAX_INSN_BYTES + 1],
                       &raw_insn_bytes[(i + 1) * MAX_INSN_BYTES],
                       merged_sz - 1);
            }

            tmpl_n_insns++;
            i++;
            continue;
        }

        tmpl_insn_pcs[tmpl_n_insns] = raw_insn_pcs[i];
        tmpl_insn_disas_arr[tmpl_n_insns] = raw_insn_disas_arr[i];
        raw_insn_disas_arr[i] = NULL;
        tmpl_insn_sizes[tmpl_n_insns] = raw_insn_sizes[i];
        memcpy(&tmpl_insn_bytes[tmpl_n_insns * MAX_INSN_BYTES],
               &raw_insn_bytes[i * MAX_INSN_BYTES],
               MAX_INSN_BYTES);
        tmpl_n_insns++;
    }

    /* Create or update BB template */
    g_mutex_lock(&data_lock);
    {
        BBTemplate *tmpl = get_or_create_template(pc,
                                                  (uint32_t)tmpl_n_insns,
                                                  tmpl_insn_pcs,
                                                  tmpl_insn_disas_arr,
                                                  tmpl_insn_sizes,
                                                  tmpl_insn_bytes,
                                                  symbol_name, fall_through);
        if (tmpl && tmpl->n_insns > 0) {
            InsnFields *last_fld = &tmpl->insn_fields[tmpl->n_insns - 1];
            bb_ends_in_branch = (last_fld->branch_type != BRANCH_NONE) ? 1 : 0;
        }
    }
    g_mutex_unlock(&data_lock);

    /* Free temporary arrays (template made copies) */
    for (size_t i = 0; i < n_insns; i++) {
        g_free(raw_insn_disas_arr[i]);
    }
    for (size_t i = 0; i < tmpl_n_insns; i++) {
        g_free(tmpl_insn_disas_arr[i]);
    }
    g_free(raw_insn_pcs);
    g_free(raw_insn_disas_arr);
    g_free(raw_insn_sizes);
    g_free(raw_insn_bytes);
    g_free(tmpl_insn_pcs);
    g_free(tmpl_insn_disas_arr);
    g_free(tmpl_insn_sizes);
    g_free(tmpl_insn_bytes);

    /*
    * Instrument the block for execution tracking.
    * Store current block's start PC into scoreboard.
     */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_STORE_U64, sb_current_pc, pc);

    /* Register execution callback.
     * The callback updates sb_insn_count only when not in speculative mode.
     */
    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, vcpu_tb_exec, QEMU_PLUGIN_CB_RW_REGS,
        (void *)(uintptr_t)n_insns);

    /* Update prev_* values for the next block's callback. */
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        sb_prev_start_pc, pc);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        sb_prev_last_pc, last_insn_pc);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        sb_prev_fall_through, fall_through);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        sb_prev_bb_ends_in_branch, bb_ends_in_branch);
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
    g_mutex_lock(&exec_lock);

    if (wp_in_progress) {
        wp_in_progress = false;
        /* Restore the correct-path instruction count that was saved before
         * wrong-path execution began. */
        qemu_plugin_u64_set(sb_insn_count, wp_saved_cpu_index,
                            wp_saved_insn_count);
        qemu_plugin_u64_set(sb_prev_start_pc, wp_saved_cpu_index,
                            wp_saved_prev_start_pc);
        qemu_plugin_u64_set(sb_prev_last_pc, wp_saved_cpu_index,
                            wp_saved_prev_last_pc);
        qemu_plugin_u64_set(sb_prev_fall_through, wp_saved_cpu_index,
                            wp_saved_prev_fall_through);
        qemu_plugin_u64_set(sb_prev_bb_ends_in_branch, wp_saved_cpu_index,
                            wp_saved_prev_bb_ends_in_branch);
        if (wp_mem_accesses) {
            g_array_unref(wp_mem_accesses);
            wp_mem_accesses = NULL;
        }
    }

    g_mutex_unlock(&exec_lock);
}

/* ========================= Exit / Statistics ========================= */

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_mutex_lock(&exec_lock);

    /* Finish any active trace segment */
    if (trace_active) {
        finish_trace_segment();
    }

    g_mutex_unlock(&exec_lock);

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

    if (stat_bin_total_bits > 0) {
        g_string_append_printf(report,
            "\nBinary accounting:\n");
        g_string_append_printf(report,
            "  Total bits: %" PRIu64 " (%.2f MiB)\n",
            stat_bin_total_bits,
            (double)stat_bin_total_bits / 8.0 / (1024.0 * 1024.0));
        g_string_append_printf(report,
            "  Header bits: %" PRIu64 " (%.2f%%)\n",
            stat_bin_header_bits,
            100.0 * (double)stat_bin_header_bits / stat_bin_total_bits);
        g_string_append_printf(report,
            "  Body bits: %" PRIu64 " (%.2f%%)\n",
            stat_bin_body_bits,
            100.0 * (double)stat_bin_body_bits / stat_bin_total_bits);
        g_string_append_printf(report,
            "  Dyn bits (CP/WP): %" PRIu64 " / %" PRIu64 "\n",
            stat_bin_dyn_cp_bits, stat_bin_dyn_wp_bits);
        g_string_append_printf(report,
            "  WP exception bits: %" PRIu64 "\n",
            stat_bin_wp_exception_bits);
        g_string_append_printf(report,
            "  WP poison bits: %" PRIu64 "\n",
            stat_bin_wp_poison_bits);
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
    g_hash_table_unref(x86_reg_ht);
    g_hash_table_unref(aarch64_reg_ht);
    g_hash_table_unref(riscv_reg_ht);
    g_hash_table_unref(mips_reg_ht);
    g_hash_table_unref(mnemonic_ht);
    g_hash_table_unref(prefix_ht);
    g_hash_table_unref(insn_prefix_ht);
    g_hash_table_unref(option_ht);
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
    if (g_str_has_prefix(target_name, "x86_64") ||
        g_str_has_prefix(target_name, "i386")) {
        trace_isa = TRACE_ISA_X86;
    } else if (g_str_has_prefix(target_name, "aarch64")) {
        trace_isa = TRACE_ISA_AARCH64;
    } else if (g_str_has_prefix(target_name, "riscv64") ||
               g_str_has_prefix(target_name, "riscv32")) {
        trace_isa = TRACE_ISA_RISCV;
    } else if (g_str_has_prefix(target_name, "mips64el") ||
               g_str_has_prefix(target_name, "mips64") ||
               g_str_has_prefix(target_name, "mipsel") ||
               g_str_has_prefix(target_name, "mips")) {
        trace_isa = TRACE_ISA_MIPS;
    } else {
        trace_isa = TRACE_ISA_UNKNOWN;
        fprintf(stderr, "wptrace: warning: unsupported ISA '%s', "
                "instruction decode will be limited\n", target_name);
    }

    /*
     * Build plugin option hash table early, before argument parsing.
     * Maps option name strings to PluginOptId for O(1) dispatch.
     */
    option_ht = g_hash_table_new(g_str_hash, g_str_equal);
    {
        static const struct { const char *name; int id; }
        opt_entries[] = {
            {"depth",   OPT_DEPTH},   {"outfile", OPT_OUTFILE},
            {"debug",   OPT_DEBUG},   {"wp",      OPT_WP},
            {"start",   OPT_START},   {"stop",    OPT_STOP},
            {"program", OPT_PROGRAM}, {"spfile",  OPT_SPFILE},
            {"spinterval", OPT_SPINTERVAL},
            {NULL, 0}
        };
        for (int i = 0; opt_entries[i].name; i++) {
            g_hash_table_insert(option_ht,
                                (gpointer)opt_entries[i].name,
                                GINT_TO_POINTER(opt_entries[i].id));
        }
    }

    /* Parse arguments via hash table dispatch */
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);

        gpointer val = tokens[0] ?
            g_hash_table_lookup(option_ht, tokens[0]) : NULL;
        if (!val) {
            fprintf(stderr, "wptrace: unknown option: %s\n", opt);
            return -1;
        }

        switch (GPOINTER_TO_INT(val)) {
        case OPT_DEPTH:
            max_wrong_path_depth = atoi(tokens[1]);
            if (max_wrong_path_depth <= 0) {
                fprintf(stderr, "wptrace: invalid depth: %s\n", tokens[1]);
                return -1;
            }
            break;
        case OPT_OUTFILE:
            output_base_path = g_strdup(tokens[1]);
            break;
        case OPT_DEBUG:
            enable_debug_text = (atoi(tokens[1]) != 0);
            break;
        case OPT_WP:
            enable_wrong_path = (atoi(tokens[1]) != 0);
            break;
        case OPT_START:
            trace_start_insn = g_ascii_strtoull(tokens[1], NULL, 10);
            break;
        case OPT_STOP:
            trace_stop_insn = g_ascii_strtoull(tokens[1], NULL, 10);
            break;
        case OPT_PROGRAM:
            program_name = g_strdup(tokens[1]);
            break;
        case OPT_SPFILE:
            simpoints_file_path = g_strdup(tokens[1]);
            break;
        case OPT_SPINTERVAL:
            simpoint_interval_insns = g_ascii_strtoull(tokens[1], NULL, 10);
            if (simpoint_interval_insns == 0) {
                fprintf(stderr, "wptrace: invalid spinterval: %s\n", tokens[1]);
                return -1;
            }
            break;
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
    g_mutex_init(&exec_lock);
    template_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                         NULL, bb_template_free);
    branch_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                       NULL, g_free);

    /* Build per-ISA register hash tables: values are biased uint8_t IDs */
    x86_reg_ht = build_reg_hash_table(x86_reg_entries);
    aarch64_reg_ht = build_reg_hash_table(aarch64_reg_entries);
    riscv_reg_ht = build_reg_hash_table(riscv_reg_entries);
    mips_reg_ht = build_reg_hash_table(mips_reg_entries);

    /*
     * Build mnemonic hash table: values are pointers to the static
     * mnemonic_table[] entries (not encoded integers like the register
     * tables), since each entry carries both opcode and branch_type.
     */
    mnemonic_ht = g_hash_table_new(g_str_hash, g_str_equal);
    for (int i = 0; mnemonic_table[i].name; i++) {
        g_hash_table_insert(mnemonic_ht, (gpointer)mnemonic_table[i].name,
                            (gpointer)&mnemonic_table[i]);
    }

    /*
     * Build prefix classification hash table: maps prefix strings to
     * MnemonicEntry pointers for O(1) prefix-based lookup.
     */
    prefix_ht = g_hash_table_new(g_str_hash, g_str_equal);
    for (int i = 0; prefix_class_table[i].name; i++) {
        g_hash_table_insert(prefix_ht, (gpointer)prefix_class_table[i].name,
                            (gpointer)&prefix_class_table[i]);
    }

    /*
     * Build x86 instruction prefix set for lock/rep/data16 stripping.
     * Values are non-NULL sentinels; only membership is checked.
     */
    insn_prefix_ht = g_hash_table_new(g_str_hash, g_str_equal);
    {
        static const char *const insn_prefixes[] = {
            "lock", "rep", "repz", "repnz", "data16", NULL
        };
        for (int i = 0; insn_prefixes[i]; i++) {
            g_hash_table_insert(insn_prefix_ht,
                                (gpointer)insn_prefixes[i],
                                GINT_TO_POINTER(1));
        }
    }

    /* Initialize per-vCPU scoreboard */
    vcpu_sb = qemu_plugin_scoreboard_new(sizeof(VCPUScoreBoard));
    sb_current_pc = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, current_pc);
    sb_prev_start_pc = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, prev_start_pc);
    sb_prev_last_pc = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, prev_last_pc);
    sb_prev_fall_through = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, prev_fall_through);
    sb_prev_bb_ends_in_branch = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, prev_bb_ends_in_branch);
    sb_insn_count = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, insn_count);

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
