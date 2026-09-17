#ifndef CHAMPSIM_TRACER_CAPSTONE_TABLES_H
#define CHAMPSIM_TRACER_CAPSTONE_TABLES_H

/*
 * The Capstone classification tables, and why the plugin does not have them.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Everything the wire publishes is QEMU's own statement about the ops it
 * emitted: the generic word, the register lists, the memory operands, the
 * dependency blocks, the lane shape, the immediates, the block boundaries.
 * These tables answer to one thing and one thing only -- the COMPARISON that
 * scores that classifier against a second decoder -- and a comparison belongs
 * outside its subject.
 *
 * So they are not built into the plugin.  They are compiled into the two
 * offline tool libraries that need them, cst_referee_fields and
 * isaxcheck_fields, and champsim_tracer_decode.cc, the operand walk that
 * reads them, goes with them.  The shipped plugin links no Capstone; `ldd`
 * on libchampsim_tracer.so says so, which is a fact a reader can check rather
 * than a promise in a comment.
 *
 * INCLUDE ORDER: champsim_tracer_mnemonics.h defines InsnFields and the ISA
 * property table, which these declarations build on and which the plugin DOES
 * have.  Include that first, or include this, which does it for you.
 */

#include "champsim_tracer_mnemonics.h"

/*
 * Mnemonic entry flags.  Only flags whose semantics Capstone detail
 * cannot supply are kept (Capstone provides operand access, implicit
 * regs, and group membership for all ISAs).
 */
enum MnemonicFlags {
    MF_NONE             = 0,
    MF_CONDITIONAL      = (1 << 0),  /* x86: direct branch may be conditional */
    MF_ATOMIC           = (1 << 1),  /* Atomic/locked memory op (LOCK prefix,
                                      * x86 XCHG, AArch64 LDXR/STXR, RISC-V A
                                      * extension, MIPS LL/SC) — sets the
                                      * CST_INSN_FLAG_ATOMIC bit on the wire. */
};

/*
 * Register classification: a Capstone register ID -> one generic ID (or a
 * small alias list when Capstone groups several regs under one enum value).
 * Indexed by the Capstone enum value.  qemu_reg is the QEMU register
 * descriptor key, or { NULL, NULL } when there is no single readable QEMU
 * register.
 */
typedef struct {
    uint8_t reg_id;                    /* GenericRegId */
    uint8_t n_regs;                    /* non-zero for composite aliases */
    uint8_t regs[MAX_REG_ALIASES];     /* GenericRegId[] */
    QemuRegKey qemu_reg;               /* qemu_plugin_reg_descriptor key */
    /*
     * True on the *one* row whose Capstone reg id is the ISA's
     * integer-flags register (x86 EFLAGS, AArch64 NZCV); drives the
     * REG_METAFLAGS mirror (see generic_ids.h metaflags note).  False
     * on all other rows, including non-integer flags writers (x86
     * FPSW) and ISAs without an integer flags reg.
     */
    bool is_int_flags;
} RegClassification;

/*
 * Optional post-classification refiner.  Some Capstone insn_ids cover
 * several semantics differing only in operand encoding (e.g. RISC-V
 * JALR = indirect branch / jump / ret by rd/rs1).  .refine fixes up
 * the decoded InsnFields after the generic operand-walk.  ISA-local:
 * defined in the per-ISA table, never referenced by the decoder.
 */
struct qemu_plugin_insn_info; /* fwd-decl: full type from <qemu-plugin.h> */
typedef void (*InsnRefineFn)(const struct qemu_plugin_insn_info *info,
                             InsnFields *fields);

/*
 * Optional dependency refiner.  Reads what the operand-walk and
 * `.refine` populated, then writes dst_dep_mask[] /
 * store_data_dep_mask[], sets n_dep_stores, flips has_reg_deps.
 * Refiner library is small and shared (champsim_tracer_mnemonic_
 * tables.c).  .dep_refine NULL -> no HAS_REG block -> consumer uses
 * the legacy implicit all-to-all fallback (the audit coverage report
 * flags these).  Runs once per unique PC at template build, not hot.
 */
typedef void (*InsnDepRefineFn)(const struct qemu_plugin_insn_info *info,
                                InsnFields *fields);

/*
 * Shared refiners (champsim_tracer_mnemonic_tables.c), referenced in
 * rows via `.dep_refine = dep_<name>`.  Each targets a *dataflow
 * behavior group* — wide coverage across the operand-shape variants
 * (rr / rm / mr / ri / mi / ...) Capstone groups under one insn id.
 * A small complementary set covers the full surface; the audit
 * classifier picks one refiner per Capstone id handling all variants.
 */
void dep_all_to_all(const struct qemu_plugin_insn_info *info,
                    InsnFields *fields);
void dep_passthrough(const struct qemu_plugin_insn_info *info,
                     InsnFields *fields);
void dep_lea(const struct qemu_plugin_insn_info *info,
             InsnFields *fields);
void dep_x86_stack_push(const struct qemu_plugin_insn_info *info,
                        InsnFields *fields);
void dep_x86_stack_pop(const struct qemu_plugin_insn_info *info,
                       InsnFields *fields);
void dep_vec_struct_load(const struct qemu_plugin_insn_info *info,
                         InsnFields *fields);
void dep_vec_struct_store(const struct qemu_plugin_insn_info *info,
                          InsnFields *fields);
void dep_vec_struct_load_interleaved(
    const struct qemu_plugin_insn_info *info, InsnFields *fields);
void dep_vec_struct_store_interleaved(
    const struct qemu_plugin_insn_info *info, InsnFields *fields);

/*
 * Instruction-level vector lane shape from the Capstone operand
 * layout + lane-selecting immediate.  Slot-agnostic; the caller
 * (decode.cc) applies it per operand.
 *
 *   NONE     no usable lane width (consumer falls back to all-to-all).
 *   UNIFORM  packed op (PADDD, NEON ADD, vadd.vv): all lanes live.
 *   INSERT   element insert (PINSR/INSERTPS): WRITE touches only
 *            lane_sel; same-reg READ supplies the other lanes.
 *   EXTRACT  element extract (PEXTR/EXTRACTPS): READ touches only
 *            lane_sel.
 *
 * full_mask = (1<<total_lanes)-1 (~0 for runtime-CSR widths, gated
 * later).
 */
enum LaneShapeKind {
    LANE_SHAPE_NONE = 0,
    LANE_SHAPE_UNIFORM,
    LANE_SHAPE_INSERT,
    LANE_SHAPE_EXTRACT,
};
typedef struct {
    uint8_t  kind;        /* LaneShapeKind */
    uint8_t  lane_bytes;  /* vec element width; 0 = runtime SEW */
    uint64_t full_mask;   /* all participating lanes */
    int16_t  lane_sel;    /* INSERT/EXTRACT selected lane; else -1 */
} LaneShape;

LaneShape lane_shape_from_operands(
    const struct qemu_plugin_insn_info *info, uint8_t lane_mask_kind);

/*
 * Instruction classification entry: Capstone insn_id ->
 * GenericOpcode + BranchType + MnemonicFlags via arrays indexed by
 * the Capstone enum value.  No string-based mnemonic matching.
 * .refine and .dep_refine are independent; when both set, .refine
 * runs first then .dep_refine reads the refined fields.
 */
typedef struct {
    uint8_t         opcode;      /* GenericOpcode */
    uint8_t         branch_type; /* BranchType */
    uint16_t        flags;       /* MnemonicFlags */
    InsnRefineFn    refine;      /* optional, NULL if unused */
    InsnDepRefineFn dep_refine;  /* optional, NULL → emit no HAS_REG block */
    /*
     * Vector lane info, orthogonal to .dep_refine (dep maps are
     * static; existing refiners work for vec ops too).  Drives the
     * dynamic lane-mask FID stream and CST_INSN_FLAG_LANE_PARALLEL:
     *
     *   lane_mask_kind  — NONE (non-vec); STATIC (x86 / NEON / MSA,
     *                     Capstone surfaces the lane count); RISCV_
     *                     VTYPE (RISC-V V, dispatch reads vl at exec).
     *   lane_parallel   — sets the wire bit.  True for element-wise
     *                     vec arith; false for cross-lane ops.
     *
     * decode.cc populates InsnFields.lane_mask_* after .dep_refine;
     * STATIC baseline from the first vec REG operand's (size,
     * lane_bytes) at template build.
     */
    uint8_t         lane_mask_kind;
    bool            lane_parallel;
} InsnClassification;

#ifdef CHAMPSIM_MNEMONIC_TABLES_IMPL

#include "champsim_tracer_mnemonics_x86.h"
#include "champsim_tracer_mnemonics_aarch64.h"
#include "champsim_tracer_mnemonics_riscv.h"
#include "champsim_tracer_mnemonics_mips.h"

/* Classification table selectors (indexed by TraceISA).  Explicit
 * `extern` so the const namespace-scope arrays get external linkage
 * under C++ (default is internal); the #else declarations match. */
extern const RegClassification *const isa_reg_class[];
const RegClassification *const isa_reg_class[] = {
    [TRACE_ISA_UNKNOWN] = NULL,
    [TRACE_ISA_X86]     = x86_reg_class,
    [TRACE_ISA_AARCH64] = aarch64_reg_class,
    [TRACE_ISA_RISCV]   = riscv_reg_class,
    [TRACE_ISA_MIPS]    = mips_reg_class,
};

extern const unsigned isa_reg_class_size[];
const unsigned isa_reg_class_size[] = {
    [TRACE_ISA_UNKNOWN] = 0,
    [TRACE_ISA_X86]     = X86_REG_ENDING,
    [TRACE_ISA_AARCH64] = AARCH64_REG_ENDING,
    [TRACE_ISA_RISCV]   = RISCV_REG_ENDING,
    [TRACE_ISA_MIPS]    = MIPS_REG_ENDING,
};

extern const InsnClassification *const isa_insn_class[];
const InsnClassification *const isa_insn_class[] = {
    [TRACE_ISA_UNKNOWN] = NULL,
    [TRACE_ISA_X86]     = x86_insn_class,
    [TRACE_ISA_AARCH64] = aarch64_insn_class,
    [TRACE_ISA_RISCV]   = riscv_insn_class,
    [TRACE_ISA_MIPS]    = mips_insn_class,
};

extern const unsigned isa_insn_class_size[];
const unsigned isa_insn_class_size[] = {
    [TRACE_ISA_UNKNOWN] = 0,
    [TRACE_ISA_X86]     = X86_INS_ENDING,
    [TRACE_ISA_AARCH64] = AARCH64_INS_ENDING,
    [TRACE_ISA_RISCV]   = RISCV_INS_ENDING,
    [TRACE_ISA_MIPS]    = MIPS_INS_ENDING,
};

#else /* CHAMPSIM_MNEMONIC_TABLES_IMPL */

extern const RegClassification *const isa_reg_class[TRACE_ISA_MIPS + 1];
extern const unsigned isa_reg_class_size[TRACE_ISA_MIPS + 1];
extern const InsnClassification *const isa_insn_class[TRACE_ISA_MIPS + 1];
extern const unsigned isa_insn_class_size[TRACE_ISA_MIPS + 1];

#endif /* CHAMPSIM_MNEMONIC_TABLES_IMPL */

/*
 * The active per-ISA tables, selected at init from the arrays above.  Each
 * tool defines them; the plugin does not have them at all.
 */
extern const InsnClassification *active_insn_table;
extern unsigned active_insn_table_size;
extern const RegClassification *active_reg_table;
extern unsigned active_reg_table_size;

/* Both are defined in champsim_tracer.h; only pointers to them appear here. */
struct InsnRegNames;
struct SyntheticEAInfo;

/* Defined in champsim_tracer_decode.cc, which is built into the tools. */
void decode_detail_to_generic(uint64_t pc,
                              const void *bytes, size_t nbytes,
                              const qemu_plugin_insn_info *info,
                              InsnFields *out,
                              struct InsnRegNames *out_names);

/* Defined in champsim_tracer_decode.cc, which is built into the tools. */
bool decode_synthetic_ea(const qemu_plugin_insn_info *info,
                         uint8_t opcode,
                         uint64_t pc,
                         uint8_t insn_size,
                         struct SyntheticEAInfo *out);

#endif /* CHAMPSIM_TRACER_CAPSTONE_TABLES_H */
