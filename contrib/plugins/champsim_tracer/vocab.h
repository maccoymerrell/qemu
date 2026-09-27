/*
 * ChampSim Tracer - the decode-word vocabulary.
 *
 * Copyright (C) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * QEMU's decode sites state what an instruction IS as a generic word
 * (qemu_plugin_insn_decode(): "int.add", "mem.load.wb", "branch.cond"); this
 * one table maps each word to the wire's GenericOpcode and BranchType.  It
 * infers nothing from operands or register classes -- the word's first part
 * already carries the domain -- and it refuses a word it has no row for:
 * the caller counts and names every refusal, and never guesses.
 *
 * The two vocabularies are the canonical sets of docs/reference.rst (carried
 * from the original tree's docs/reference.rst, "Generic opcodes" and "Branch
 * types"), whose names the encoding maps publish; the wire numbers are this
 * writer's, resolved through the maps (format.rst Step 3).  Per row, C sets
 * CST_INSN_FLAG_BRANCH_COND and A CST_INSN_FLAG_ATOMIC, which reference.rst
 * gives every XCHG, FENCE, CACHE_FLUSH and TLB_FLUSH.  The rows implement
 * format.rst's fall-through rules ("LOAD / STORE as fall-through
 * classifications"): an arithmetic RMW keeps its arithmetic word and gains
 * ATOMIC from QEMU's atomic statement, a writeback load or store is INT_ADD
 * and never LOAD / STORE, x86 LODS / STOS / INS / OUTS advance a pointer
 * (INT_ADD) while MOVS keeps MOV and CMPS / SCAS keep CMP.
 */
#ifndef CHAMPSIM_TRACER_VOCAB_H
#define CHAMPSIM_TRACER_VOCAB_H

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace cst {

/* insn_flag values this writer assigns (format.rst section 2) */
enum : uint8_t { kInsnCond = 1, kInsnImm = 2, kInsnAtomic = 4 };

/* GenericOpcode and BranchType, in the writer's wire-value order */
inline const std::vector<std::string> &vocabulary(bool branch)
{
    static const char *const text[2] = {
        "UNKNOWN INT_ADD INT_SUB INT_MUL INT_DIV AND OR XOR NOT SHL SHR ROL ROR "
        "BITMANIP MOV LOAD STORE PUSH POP LEA MOVSX MOVZX XCHG CMP TEST BRANCH RET "
        "FP_ADD FP_SUB FP_MUL FP_DIV FP_SQRT FP_MOV FP_CVT FP_CMP VEC_ADD VEC_SUB "
        "VEC_MUL VEC_DIV VEC_SQRT VEC_MOV VEC_LOAD VEC_STORE VEC_SHUF VEC_LOGIC NOP "
        "SYSCALL FENCE CMOV SETCC NEG INC DEC INT_MADD INT_MSUB FP_MADD FP_MSUB "
        "VEC_MADD VEC_MSUB PREFETCH CACHE_FLUSH TLB_FLUSH VEC_PREFETCH INT_ALU_SHORT "
        "INT_ALU_LONG FP_ALU_SHORT FP_ALU_LONG VEC_ALU_SHORT VEC_ALU_LONG",
        "NONE DIRECT_JUMP INDIRECT_JUMP DIRECT_CALL INDIRECT_CALL RETURN "
        "SYSCALL_TYPE COND_DIRECT REP",
    };
    static const std::vector<std::string> sets[2] = {
        [] { std::istringstream s(text[0]); return std::vector<std::string>(
                 std::istream_iterator<std::string>(s), {}); }(),
        [] { std::istringstream s(text[1]); return std::vector<std::string>(
                 std::istream_iterator<std::string>(s), {}); }(),
    };
    return sets[branch];
}

/*
 * The dependency refiner a word selects (wire.cc dep_block()): a move of a
 * value between register and memory (and one that writes its base back); a
 * stack push / pop.  From the decode word -- never the opcode.
 */
enum : uint8_t { kDepNone, kDepMove, kDepPush, kDepPop, kDepMoveWb };

/*
 * Its vector shape (qemu_plugin_insn_vector_shape()): none, lanes all active or
 * below vl, the emission held several shapes, more than 64 lanes (or a
 * selector outside them), or retranslations stated different shapes.
 */
enum : uint8_t { kVecNone, kVecStatic, kVecVl, kVecMixed, kVecWide, kVecVaries };

/* An instruction's class: opcode, branch type, insn_flag bits, immediate */
struct Class {
    uint8_t op = 0, br = 0, flags = 0;
    int64_t imm = 0;
    uint8_t kind = 0;   /* its dependency refiner family (wire.cc), by word */
    /* the shape: @vn lanes of @vesz bytes a register, the element selected (-1: all) */
    uint8_t vkind = kVecNone, vesz = 0, vn = 0, vgroup = 1;  /* registers an operand */
    int8_t dsel = -1, ssel = -1;
    bool ew = false, vword = false;     /* element-wise; a "vec." word */
    bool dup = false;                   /* a ".dup" word: one element to every lane */
    bool same_shape(const Class &o) const
    {
        return vkind == o.vkind && vesz == o.vesz && vn == o.vn && vgroup == o.vgroup &&
               dsel == o.dsel && ssel == o.ssel && ew == o.ew;
    }
    bool operator==(const Class &o) const
    {
        return op == o.op && br == o.br && flags == o.flags && imm == o.imm &&
               kind == o.kind;
    }
};

/*
 * The table: one row per word, sorted -- "word OPCODE [BRANCHTYPE] [C|A]".
 * A word's domain: int (general registers), fp (scalar floating point), vec
 * (vector / SIMD register file), mem, str (x86 string ops), io, branch, sys.
 */
inline const char *vocab_rows()
{
    return
        "branch.call BRANCH DIRECT_CALL\n"          "branch.call.cond BRANCH DIRECT_CALL C\n"
        "branch.call.ind BRANCH INDIRECT_CALL\n"    "branch.cond BRANCH COND_DIRECT C\n"
        "branch.jump BRANCH DIRECT_JUMP\n"          "branch.jump.ind BRANCH INDIRECT_JUMP\n"
        "branch.ret RET RETURN\n"
        "fp.add FP_ADD\n"       "fp.cmov CMOV\n"        "fp.cmp FP_CMP\n"
        "fp.cvt FP_CVT\n"       "fp.div FP_DIV\n"       "fp.madd FP_MADD\n"
        "fp.minmax FP_CMP\n"    "fp.mov FP_MOV\n"       "fp.msub FP_MSUB\n"
        "fp.mul FP_MUL\n"       "fp.recip FP_DIV\n"     "fp.rsqrt FP_SQRT\n"
        "fp.sqrt FP_SQRT\n"     "fp.sub FP_SUB\n"       "fp.transc FP_MOV\n"
        "int.abs NEG\n"         "int.add INT_ADD\n"     "int.and AND\n"
        "int.andn AND\n"        "int.bitfield BITMANIP\n" "int.bitrev BITMANIP\n"
        "int.bits BITMANIP\n"   "int.bswap BITMANIP\n"  "int.cmov CMOV\n"
        "int.cmp CMP\n"         "int.count BITMANIP\n"  "int.crc BITMANIP\n"
        "int.dec DEC\n"         "int.decimal INT_ADD\n" "int.div INT_DIV\n"
        "int.flags NOP\n"       "int.inc INC\n"         "int.lea LEA\n"
        "int.madd INT_MADD\n"   "int.minmax CMOV\n"     "int.mov MOV\n"
        "int.movsx MOVSX\n"     "int.movzx MOVZX\n"     "int.msub INT_MSUB\n"
        "int.mul INT_MUL\n"     "int.neg NEG\n"         "int.not NOT\n"
        "int.or OR\n"           "int.orn OR\n"          "int.rol ROL\n"
        "int.ror ROR\n"         "int.sar SHR\n"         "int.setcc SETCC\n"
        "int.shl SHL\n"         "int.shr SHR\n"         "int.sub INT_SUB\n"
        "int.test TEST\n"       "int.xchg XCHG NONE A\n" "int.xnor XOR\n"
        "int.xor XOR\n"
        "io.in LOAD\n"          "io.out STORE\n"
        "mem.cache CACHE_FLUSH NONE A\n"            "mem.copy MOV\n"
        "mem.fence FENCE NONE A\n"                  "mem.load LOAD\n"
        "mem.load.wb INT_ADD\n"                     "mem.minmax XCHG NONE A\n"
        "mem.pop POP\n"         "mem.prefetch PREFETCH\n" "mem.push PUSH\n"
        "mem.set STORE\n"       "mem.store STORE\n"     "mem.store.wb INT_ADD\n"
        "mem.tlb TLB_FLUSH NONE A\n"                "mem.zero STORE\n"
        "str.cmps CMP\n"        "str.ins INT_ADD\n"     "str.lods INT_ADD\n"
        "str.movs MOV\n"        "str.outs INT_ADD\n"    "str.scas CMP\n"
        "str.stos INT_ADD\n"
        "sys.eret RET RETURN\n" "sys.misc NOP\n"        "sys.nop NOP\n"
        "sys.pac BITMANIP\n"    "sys.reg MOV\n"         "sys.syscall SYSCALL SYSCALL_TYPE\n"
        "sys.trap SYSCALL SYSCALL_TYPE\n"           "sys.trap.cond CMP\n"
        "vec.abs VEC_LOGIC\n"   "vec.add VEC_ADD\n"     "vec.cmp VEC_LOGIC\n"
        "vec.config MOV\n"      "vec.count VEC_LOGIC\n" "vec.crypto VEC_LOGIC\n"
        "vec.div VEC_DIV\n"     "vec.fcmp FP_CMP\n"     "vec.fcvt FP_CVT\n"
        "vec.gather VEC_LOAD\n" "vec.load VEC_LOAD\n"   "vec.load.dup VEC_LOAD\n"
        "vec.logic VEC_LOGIC\n" "vec.madd VEC_MADD\n"   "vec.minmax VEC_LOGIC\n"
        "vec.mov VEC_MOV\n"     "vec.mov.dup VEC_MOV\n" "vec.msub VEC_MSUB\n"
        "vec.mul VEC_MUL\n"     "vec.pred VEC_LOGIC\n"
        "vec.prefetch VEC_PREFETCH\n"               "vec.scatter VEC_STORE\n"
        "vec.shift VEC_LOGIC\n" "vec.shuf VEC_SHUF\n"   "vec.sqrt VEC_SQRT\n"
        "vec.store VEC_STORE\n" "vec.sub VEC_SUB\n";
}

/* The class of @word: false for no word, or one the table refuses */
inline bool classify(const char *word, Class &c)
{
    static const std::map<std::string, Class> table = [] {
        std::map<std::string, Class> t;
        std::istringstream rows(vocab_rows());
        for (std::string line; std::getline(rows, line);) {
            std::istringstream f(line);
            std::vector<std::string> x((std::istream_iterator<std::string>(f)), {});
            x.resize(4);
            Class &k = t[x[0]];
            for (int b = 0; b < 2; b++) {
                const auto &v = vocabulary(b);
                const std::string &n = b && x[2].empty() ? v[0] : x[1 + b];
                (b ? k.br : k.op) = uint8_t(std::find(v.begin(), v.end(), n) - v.begin());
            }
            k.flags = (x[3] == "C" ? kInsnCond : 0) | (x[3] == "A" ? kInsnAtomic : 0);
        }
        return t;
    }();
    auto it = word ? table.find(word) : table.end();
    c = it != table.end() ? it->second : Class();
    return it != table.end();
}

} /* namespace cst */

#endif
