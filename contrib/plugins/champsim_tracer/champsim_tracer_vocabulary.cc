/*
 * The words QEMU states, and what each one means on the wire.
 *
 * Every row below is one generic word a QEMU decode rule may carry, beside
 * the GenericOpcode and BranchType the wire publishes for it.  That is the
 * entire QEMU-to-generic translation: a sorted array and a bisection.
 *
 * Three properties are worth stating because each one was a design choice
 * with a rejected alternative.
 *
 * It is ONE table, not four.  A per-ISA table would have to be generated from
 * each target's rules, and the generated rows -- thousands of them -- would
 * then be the reviewable artefact, which they are not: what a reader can
 * actually check is that "int.add" means an integer addition, and that check
 * does not get better by being repeated once per architecture.  The per-rule
 * decision is made at the decode site, in the target's own source, where the
 * encoding is in view.  This file only says what the vocabulary means.
 *
 * It does NOT infer.  No row consults an operand, a register class or a
 * vector shape to decide between an integer, floating-point or vector form;
 * the word already carries the domain, stated by the rule.  Inference was the
 * alternative and it fails on the interesting instructions -- a scalar
 * operation in the vector file, a vector compare writing a general register --
 * and fails plausibly, which is worse than failing loudly.
 *
 * It REFUSES an unknown word.  A word this build cannot read means the
 * emulator and the plugin disagree about the vocabulary, which is a skewed
 * build and not an unclassifiable instruction.  The lookup returns false and
 * writes nothing, so the caller cannot mistake the two.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "exec/insn-dataflow-words.h"

#include "champsim_tracer_generic_ids.h"
#include "champsim_tracer_vocabulary.h"

namespace {

struct VocabularyRow {
    const char *word;
    uint8_t opcode;         /* GenericOpcode */
    uint8_t branch_type;    /* BranchType */
};

/*
 * Sorted by word, because the lookup bisects.  cst_vocabulary_selfcheck()
 * proves the order rather than trusting this comment.
 *
 * Control-transfer rows carry both columns: the opcode a consumer schedules
 * against (one GEN_OP_BRANCH for every transfer that is not a return, by the
 * wire's own taxonomy) and the branch class it drives a predictor and a
 * return-address stack with.  Everything else carries BRANCH_NONE, and a
 * transfer QEMU's ops show on an instruction whose word is not a control word
 * is a disagreement for the consumer to resolve -- not something this table
 * papers over.
 */
const VocabularyRow rows[] = {
    { INSN_DF_WORD_AND,          GEN_OP_AND,          BRANCH_NONE },
    { INSN_DF_WORD_BITMANIP,     GEN_OP_BITMANIP,     BRANCH_NONE },
    { INSN_DF_WORD_CACHEFLUSH,   GEN_OP_CACHE_FLUSH,  BRANCH_NONE },
    { INSN_DF_WORD_CALL,         GEN_OP_BRANCH,       BRANCH_DIRECT_CALL },
    { INSN_DF_WORD_CALL_REG,     GEN_OP_BRANCH,       BRANCH_INDIRECT_CALL },
    { INSN_DF_WORD_CMOV,         GEN_OP_CMOV,         BRANCH_NONE },
    { INSN_DF_WORD_CMP,          GEN_OP_CMP,          BRANCH_NONE },
    { INSN_DF_WORD_FENCE,        GEN_OP_FENCE,        BRANCH_NONE },
    { INSN_DF_WORD_FP_ADD,       GEN_OP_FP_ADD,       BRANCH_NONE },
    { INSN_DF_WORD_FP_CMP,       GEN_OP_FP_CMP,       BRANCH_NONE },
    { INSN_DF_WORD_FP_CVT,       GEN_OP_FP_CVT,       BRANCH_NONE },
    { INSN_DF_WORD_FP_DIV,       GEN_OP_FP_DIV,       BRANCH_NONE },
    { INSN_DF_WORD_FP_MADD,      GEN_OP_FP_MADD,      BRANCH_NONE },
    { INSN_DF_WORD_FP_MOV,       GEN_OP_FP_MOV,       BRANCH_NONE },
    { INSN_DF_WORD_FP_MSUB,      GEN_OP_FP_MSUB,      BRANCH_NONE },
    { INSN_DF_WORD_FP_MUL,       GEN_OP_FP_MUL,       BRANCH_NONE },
    { INSN_DF_WORD_FP_SQRT,      GEN_OP_FP_SQRT,      BRANCH_NONE },
    { INSN_DF_WORD_FP_SUB,       GEN_OP_FP_SUB,       BRANCH_NONE },
    { INSN_DF_WORD_INT_ADD,      GEN_OP_INT_ADD,      BRANCH_NONE },
    { INSN_DF_WORD_INT_DEC,      GEN_OP_DEC,          BRANCH_NONE },
    { INSN_DF_WORD_INT_DIV,      GEN_OP_INT_DIV,      BRANCH_NONE },
    { INSN_DF_WORD_INT_INC,      GEN_OP_INC,          BRANCH_NONE },
    { INSN_DF_WORD_INT_MADD,     GEN_OP_INT_MADD,     BRANCH_NONE },
    { INSN_DF_WORD_INT_MSUB,     GEN_OP_INT_MSUB,     BRANCH_NONE },
    { INSN_DF_WORD_INT_MUL,      GEN_OP_INT_MUL,      BRANCH_NONE },
    { INSN_DF_WORD_INT_NEG,      GEN_OP_NEG,          BRANCH_NONE },
    { INSN_DF_WORD_INT_SUB,      GEN_OP_INT_SUB,      BRANCH_NONE },
    { INSN_DF_WORD_JUMP,         GEN_OP_BRANCH,       BRANCH_DIRECT_JUMP },
    { INSN_DF_WORD_JUMP_COND,    GEN_OP_BRANCH,       BRANCH_COND_DIRECT },
    { INSN_DF_WORD_JUMP_REG,     GEN_OP_BRANCH,       BRANCH_INDIRECT_JUMP },
    { INSN_DF_WORD_LEA,          GEN_OP_LEA,          BRANCH_NONE },
    { INSN_DF_WORD_LOAD,         GEN_OP_LOAD,         BRANCH_NONE },
    { INSN_DF_WORD_MOV,          GEN_OP_MOV,          BRANCH_NONE },
    { INSN_DF_WORD_MOVSX,        GEN_OP_MOVSX,        BRANCH_NONE },
    { INSN_DF_WORD_MOVZX,        GEN_OP_MOVZX,        BRANCH_NONE },
    { INSN_DF_WORD_NOP,          GEN_OP_NOP,          BRANCH_NONE },
    { INSN_DF_WORD_NOT,          GEN_OP_NOT,          BRANCH_NONE },
    { INSN_DF_WORD_OR,           GEN_OP_OR,           BRANCH_NONE },
    { INSN_DF_WORD_POP,          GEN_OP_POP,          BRANCH_NONE },
    { INSN_DF_WORD_PREFETCH,     GEN_OP_PREFETCH,     BRANCH_NONE },
    { INSN_DF_WORD_PUSH,         GEN_OP_PUSH,         BRANCH_NONE },
    { INSN_DF_WORD_RET,          GEN_OP_RET,          BRANCH_RETURN },
    { INSN_DF_WORD_ROL,          GEN_OP_ROL,          BRANCH_NONE },
    { INSN_DF_WORD_ROR,          GEN_OP_ROR,          BRANCH_NONE },
    { INSN_DF_WORD_SETCC,        GEN_OP_SETCC,        BRANCH_NONE },
    { INSN_DF_WORD_SHL,          GEN_OP_SHL,          BRANCH_NONE },
    { INSN_DF_WORD_SHR,          GEN_OP_SHR,          BRANCH_NONE },
    { INSN_DF_WORD_STORE,        GEN_OP_STORE,        BRANCH_NONE },
    { INSN_DF_WORD_SYSCALL,      GEN_OP_SYSCALL,      BRANCH_SYSCALL_TYPE },
    { INSN_DF_WORD_TEST,         GEN_OP_TEST,         BRANCH_NONE },
    { INSN_DF_WORD_TLBFLUSH,     GEN_OP_TLB_FLUSH,    BRANCH_NONE },
    { INSN_DF_WORD_VEC_ADD,      GEN_OP_VEC_ADD,      BRANCH_NONE },
    { INSN_DF_WORD_VEC_DIV,      GEN_OP_VEC_DIV,      BRANCH_NONE },
    { INSN_DF_WORD_VEC_LOAD,     GEN_OP_VEC_LOAD,     BRANCH_NONE },
    { INSN_DF_WORD_VEC_LOGIC,    GEN_OP_VEC_LOGIC,    BRANCH_NONE },
    { INSN_DF_WORD_VEC_MADD,     GEN_OP_VEC_MADD,     BRANCH_NONE },
    { INSN_DF_WORD_VEC_MOV,      GEN_OP_VEC_MOV,      BRANCH_NONE },
    { INSN_DF_WORD_VEC_MSUB,     GEN_OP_VEC_MSUB,     BRANCH_NONE },
    { INSN_DF_WORD_VEC_MUL,      GEN_OP_VEC_MUL,      BRANCH_NONE },
    { INSN_DF_WORD_VEC_PREFETCH, GEN_OP_VEC_PREFETCH, BRANCH_NONE },
    { INSN_DF_WORD_VEC_SHUFFLE,  GEN_OP_VEC_SHUF,     BRANCH_NONE },
    { INSN_DF_WORD_VEC_SQRT,     GEN_OP_VEC_SQRT,     BRANCH_NONE },
    { INSN_DF_WORD_VEC_STORE,    GEN_OP_VEC_STORE,    BRANCH_NONE },
    { INSN_DF_WORD_VEC_SUB,      GEN_OP_VEC_SUB,      BRANCH_NONE },
    { INSN_DF_WORD_XCHG,         GEN_OP_XCHG,         BRANCH_NONE },
    { INSN_DF_WORD_XOR,          GEN_OP_XOR,          BRANCH_NONE },
};

const unsigned n_rows = (unsigned)(sizeof(rows) / sizeof(rows[0]));

} /* namespace */

bool cst_vocabulary_lookup(const char *word, uint8_t *opcode,
                           uint8_t *branch_type)
{
    unsigned lo = 0;
    unsigned hi = n_rows;

    if (!word) {
        return false;
    }

    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2;
        int c = strcmp(word, rows[mid].word);

        if (c == 0) {
            if (opcode) {
                *opcode = rows[mid].opcode;
            }
            if (branch_type) {
                *branch_type = rows[mid].branch_type;
            }
            return true;
        }
        if (c < 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return false;
}

unsigned cst_vocabulary_selfcheck(void)
{
    unsigned defects = 0;

    for (unsigned i = 0; i < n_rows; i++) {
        if (!rows[i].word || !rows[i].word[0]) {
            defects++;
            continue;
        }
        if (rows[i].opcode >= GEN_OP_COUNT ||
            rows[i].branch_type >= BRANCH_TYPE_COUNT) {
            defects++;
        }
        /*
         * Strictly increasing, which covers both the ordering the bisection
         * needs and the absence of a duplicate word -- a duplicate would make
         * one of the two rows unreachable, and which one is unreachable would
         * depend on where the bisection landed.
         */
        if (i && strcmp(rows[i - 1].word, rows[i].word) >= 0) {
            defects++;
        }
    }
    return defects;
}

unsigned cst_vocabulary_size(void)
{
    return n_rows;
}
