/*
 * Wrong-Path Tracing Plugin — shared internal declarations.
 *
 * This header is private to the plugin: it declares the types and globals
 * that are referenced across the plugin's translation units
 * (champsim_tracer.cc, champsim_tracer_decode.cc, champsim_tracer_wp.cc,
 * champsim_tracer_output.cc).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_H
#define CHAMPSIM_TRACER_H

#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

extern "C" {
#include <qemu-plugin.h>
}

#include "champsim_tracer_mnemonics.h"

/* ===== Constants ===== */
#define MAX_INSN_BYTES 16
/* MAX_SRC_REGS / MAX_DST_REGS now live in champsim_tracer_mnemonics.h
 * (alongside the InsnFields struct they size) so per-ISA mnemonic refiners
 * compiled in the C tables TU can manipulate InsnFields directly. */

/*
 * Binary format magic/version 1.7.
 * Bytes in file order: 'C','S','T',0x17 → u32 LE 0x17545343.
 * ASCII: C=0x43 S=0x53 T=0x54.  "CST" = ChampSimTracer.
 *
 * v1.7 replaces the per-entry dyn-patch / mem-data / reg-data
 * sub-sections (and the variable-memop preamble) with a single
 * unified field-typed delta stream.  Each BB entry carries:
 *
 *   n_records : ULEB
 *   { ins_pos_gap : ULEB,  field_id : u8,  delta : SLEB128 }*
 *
 * Records are emitted in non-descending (ins_pos, field_id) order;
 * unchanged fields contribute zero bytes.  Field IDs identify what
 * changed about an instruction (memop count/addr/data, src/dst reg
 * value, opcode/encoding/immediate etc. — see the FID_* constants
 * below).  The delta is `(cur128 − baseline128) mod 2**128`,
 * written as one SLEB128 of any width.  Baseline = the most-recent
 * correct-path observation for (template_id, ins_pos, field_id),
 * or the field's template-default on first appearance.  WP state
 * is forked from CP at chain start and discarded at chain end so
 * speculative effects never leak forward.
 *
 * Templates track true basic blocks (start_pc to first branch,
 * immutable, unique by start_pc).  Memory-operation counts are runtime
 * sparse fields populated from QEMU memory callbacks; template count
 * defaults are zero.
 */
#define CST_MAGIC          0x17545343u
#define CST_TRAILER_MAGIC  0x17545343FFFFFFFFull
#define CST_TRAILER_SIZE   64

/* Body entry tags (1 byte) */
#define BODY_TAG_END             0
#define BODY_TAG_ENTRY           1
#define BODY_TAG_THREAD_SWITCH   2

/* Per-insn template flags byte */
#define CST_INSN_FLAG_BRANCH_COND   (1u << 0)
#define CST_INSN_FLAG_HAS_IMM       (1u << 1)
#define CST_INSN_FLAG_SYNC_SHIFT    2
#define CST_INSN_FLAG_SYNC_MASK     0x3Cu
/* bits 6..7 reserved */

/* WP event flags byte */
#define CST_WP_EVENT_TRANSLATION_UNAVAIL (1u << 0)
#define CST_WP_EVENT_FAULT               (1u << 1)

/* WP-invocation envelope flags byte */
#define CST_WP_INV_CHAIN_REF      (1u << 0)
/* bits 1..7 reserved */

/* Header feature flags (templates always present, deltas always present).
 *
 * These bits are advisory hints to consumers about optional payload
 * families.  The wire format itself is uniform — a reader that sees
 * an unexpected field_id MUST tolerate it (see
 * champsim_tracer_format.md §4 and the CST_FID_* constants below).
 * Sparse instruction metadata records are always allowed and do not
 * need a feature bit. */
#define CST_FLAG_MEM_DATA      (1 << 0)  /* CST_FID_LOAD_DATA / STORE_DATA */
#define CST_FLAG_REG_DATA      (1 << 1)  /* CST_FID_SRC_REG values        */
#define CST_FLAG_RESERVED_2    (1 << 2)
/* bits 3..7 reserved */

/* ===== Field-ID space (v1.7 unified delta stream) =====
 *
 * Every per-entry observation (memop addresses, memop data, register
 * values, instruction-encoding mutations) is encoded as one
 * (ins_pos, field_id, delta) record.  Slotted families occupy
 * contiguous 16-wide ranges to leave room for SVE / RVV / wide-AVX
 * memop counts.  Adding a new dynamic field is a one-line addition
 * to FieldDescriptor table in champsim_tracer_output.cc; the wire
 * format does not need to change as long as the new field gets a
 * fresh FID_* constant from the reserved space below.
 */
#define CST_FID_SLOT_COUNT       16    /* slots per slotted family */

#define CST_FID_N_LOADS         0x00  /* current valid load slots */

#define CST_FID_LOAD_ADDR_BASE   0x01  /* +k for load slot k ∈ 0..15 */
#define CST_FID_STORE_ADDR_BASE  0x11
#define CST_FID_LOAD_DATA_BASE   0x21  /* gated by CST_FLAG_MEM_DATA  */
#define CST_FID_STORE_DATA_BASE  0x31
#define CST_FID_SRC_REG_BASE     0x41  /* gated by CST_FLAG_REG_DATA  */
/* 0x51..0x60 reserved for post-exec destination register values. */
#define CST_FID_N_STORES        0x61  /* current valid store slots */
/* 0x62..0x6F reserved for future slotted memop metadata             */

/* Insn-encoding-mutable fields. Baseline = template's static value,
 * so unchanged-from-template fields cost zero record bytes. */
#define CST_FID_INSN_BYTES_LO    0x70  /* low  8 bytes of insn_bytes, LE u64  */
#define CST_FID_INSN_BYTES_HI    0x71  /* high 8 bytes (only x86 long enc.)   */
#define CST_FID_INSN_OPCODE      0x72  /* GenericOpcode (u8)                  */
#define CST_FID_INSN_BRANCH_TYPE 0x73  /* BranchType (u8)                     */
#define CST_FID_INSN_FLAGS       0x74  /* template flags byte                 */
#define CST_FID_INSN_IMMEDIATE   0x75  /* signed immediate                    */
#define CST_FID_INSN_SIZE        0x76  /* u8 insn_size                        */
/* 0x77..0xFE reserved for future fields                                       */
#define CST_FID_EXTENDED         0xFF  /* reserved escape; not used in v1.7   */

/* ===== Types ===== */

/* InsnFields is defined in champsim_tracer_mnemonics.h. */

/*
 * Per-register snapshot, captured immediately before the issuing
 * instruction executes.  `lo` carries the low 8 bytes (LE); `hi`
 * carries the high 8 bytes for registers larger than 8 bytes and is
 * 0 otherwise.  Registers the plugin could not resolve to a runtime
 * handle on this target are emitted as lo=hi=0 (and do not advance
 * the per-reg delta state).
 */
typedef struct {
    uint64_t lo;
    uint64_t hi;
} RegSnap;

/*
 * Per-insn parallel name table for InsnFields.src_regs[] and
 * InsnFields.dst_regs[].  Populated by the decoder only when
 * enable_reg_data is true at translation time.  The current dynamic
 * reg-data path consumes source names only; destination names are kept
 * alongside template destination identities for future post-exec value
 * capture.  Empty source names emit zero snaps.
 */
typedef struct {
    char src[MAX_SRC_REGS][16];
    char dst[MAX_DST_REGS][16];
} InsnRegNames;

typedef struct {
    uint32_t template_id;
    uint64_t start_pc;
    uint32_t n_insns;
    uint64_t *insn_pcs;
    uint64_t fall_through_pc;
    char *symbol_name;
    uint8_t *insn_sizes;
    uint8_t *insn_bytes;
    InsnFields *insn_fields;
    /* Optional: parallel Capstone-name array, one entry per insn.
     * Allocated only when reg-data capture is enabled at translation
     * time. */
    InsnRegNames *insn_reg_names;
    /* Per-insn opaque udata for the reg-snap exec callback; lifetime
     * equals the BBTemplate's.  Allocated only when reg-data is on. */
    void *insn_snap_refs;
} BBTemplate;

/*
 * Chain template: an ordered sequence of true-BB template_ids that
 * occurs as a wrong-path or correct-path sequence.  Used as a
 * shorthand to compress the per-WP-invocation BB-id list.  Built
 * lazily on first sight of a multi-BB sequence; keyed in chain_map
 * by an internal hash of the bb_ids[] tuple.
 */
typedef struct {
    uint32_t chain_id;
    uint32_t n_bbs;
    uint32_t *bb_ids;
} ChainTemplate;

enum DynParamType {
    DYN_LOAD_ADDR  = 0,
    DYN_STORE_ADDR = 1,
};

/*
 * Runtime memory-access record emitted as a dyn-param.
 *
 * Only `value` is written to disk; `type`, `insn_index`, and data_*
 * are writer-internal bookkeeping used to:
 *  - group memops by owning instruction (insn_index),
 *  - split each instruction's memops into loads-then-stores (type),
 *  - update the per-entry observed counts (N_LOADS, N_STORES),
 *  - emit mem-data section values.
 *
 * The owning instruction and load/store type are *implicit* on disk —
 * the consumer reconstructs them by walking the template's per-insn
 * (n_loads, n_stores) schema.
 */
typedef struct {
    uint8_t  type;         /* DynParamType (writer-internal)        */
    uint16_t insn_index;   /* Index in owning template's insn array */
    uint64_t value;        /* vaddr of the access                   */
    uint8_t  data_size;
    uint64_t data_lo;
    uint64_t data_hi;
} DynParam;

typedef struct {
    uint32_t template_id;       /* TRUE BB id (start_pc → first branch) */
    uint64_t start_pc;
    GArray *dyn_params;         /* dyn_params for THIS BB only */
    uint32_t n_insns_executed;  /* BB length when complete; partial on fault */
    bool fault;
    bool translation_unavailable;
    /*
     * Index (within THIS basic block) of the instruction that raised
     * the synchronous exception when `fault` is true.  Undefined
     * otherwise.  Consumers (e.g. ChampSim) use this to flag the
     * specific uop as non-completing so its dependent slice is
     * naturally squashed.
     */
    uint32_t fault_insn_index;
    BBTemplate *tmpl;  /* Non-owning; for per-insn schema access */
    /* RegSnap array, ordered: for each insn in this BB, n_src snaps
    * snaps only.  Captured pre-insn via a per-fragment wide regfile
    * dump (see wp_capture_insn_snaps).  NULL when reg-data is disabled. */
    GArray *reg_snaps;
} WPBBEntry;

typedef struct {
    uint32_t seq_num;
    uint32_t template_id;
    GArray *dyn_params;
    /* RegSnap array, ordered: for each insn in the template, n_src
     * snaps only.  Only populated when enable_reg_data is true; emitted
     * in the register-data section. */
    GArray *reg_snaps;
    GArray *wp_entries;
    BBTemplate *tmpl;  /* Non-owning; for per-insn schema access */
    uint32_t thread_id;
} BodyEntry;

typedef struct {
    uint64_t current_pc;
    uint64_t prev_start_pc;
    uint64_t prev_last_pc;
    uint64_t prev_fall_through;
    uint64_t prev_bb_ends_in_branch;
    uint64_t insn_count;
} VCPUScoreBoard;

typedef struct {
    uint64_t pc;
    uint64_t fall_through;
    /* Two-entry LRU of distinct taken targets observed at this branch
     * PC.  `taken_target` is the most-recently-taken target;
     * `prev_taken_target` is the most-recently-taken target that
     * differed from it (or 0 if only one target has ever been seen).
     * `has_taken_target` gates `taken_target`; `has_prev_taken_target`
     * gates `prev_taken_target`.  Used by indirect-branch wrong-path
     * derivation: when CP fell through (rare conditional indirect) or
     * when CP took an indirect to a known target, WP picks the *other*
     * LRU slot if available, otherwise falls through. */
    uint64_t taken_target;
    uint64_t prev_taken_target;
    bool has_taken_target;
    bool has_prev_taken_target;
} BranchRecord;

typedef struct {
    uint64_t insn_pc;
    uint64_t mem_vaddr;
    bool is_store;
    uint8_t data_size;
    uint64_t data_lo;
    uint64_t data_hi;
} WPMemAccess;

typedef struct BodyStreamState BodyStreamState;
typedef struct WriterCtx WriterCtx;

typedef struct {
    uint64_t start_insn;
    uint64_t stop_insn;
    char *label;
    FILE *bin_file;
    bool bin_file_is_pipe;   /* true if opened with popen() */
    WriterCtx *writer;       /* async writer thread feeding bin_file */
    BodyStreamState *bin_stream;
    uint32_t body_seq_num;
    char start_datetime[64];
} TraceSegment;

typedef struct {
    uint64_t interval_id;
    uint64_t start_insn;
    uint64_t stop_insn;
    int cluster_id;
    double weight;
} SimPointEntry;

typedef struct {
    FILE *f;
    GByteArray *buf;
    WriterCtx *w;          /* async writer; mutually exclusive with f/buf */
    uint64_t total_bytes;
} BitWriter;

/* ===== Globals ===== */

extern TraceISA trace_isa;
extern int cst_cap_arch;
extern unsigned int cst_cap_mode;

extern GMutex data_lock;
extern GMutex unknown_warn_lock;
extern FILE *unknown_warn_file;

extern GHashTable *tb_map;
extern GHashTable *bb_map;
extern GHashTable *chain_map;
extern GHashTable *branch_map;
extern uint32_t next_template_id;
extern uint32_t next_chain_id;

extern struct qemu_plugin_scoreboard *vcpu_sb;
extern qemu_plugin_u64 sb_current_pc;
extern qemu_plugin_u64 sb_prev_start_pc;
extern qemu_plugin_u64 sb_prev_last_pc;
extern qemu_plugin_u64 sb_prev_fall_through;
extern qemu_plugin_u64 sb_prev_bb_ends_in_branch;
extern qemu_plugin_u64 sb_insn_count;

extern int max_wrong_path_depth;
extern bool enable_mem_data;
extern bool enable_reg_data;
extern const char *target_name;
extern char *qemu_command_line;
extern char *trace_comment;

extern __thread bool wp_in_progress;
extern __thread GArray *wp_mem_accesses;
extern __thread unsigned int wp_saved_cpu_index;
extern __thread uint64_t wp_saved_insn_count;
extern __thread uint64_t wp_saved_prev_start_pc;
extern __thread uint64_t wp_saved_prev_last_pc;
extern __thread uint64_t wp_saved_prev_fall_through;
extern __thread uint64_t wp_saved_prev_bb_ends_in_branch;

extern const InsnClassification *active_insn_table;
extern unsigned active_insn_table_size;
extern const RegClassification *active_reg_table;
extern unsigned active_reg_table_size;

extern uint64_t stat_unknown_insn_warnings;
extern uint64_t stat_wp_simulations;
extern uint64_t stat_wp_skipped;
extern uint64_t stat_wp_total_insns;
extern uint64_t stat_wp_early_exits;
extern uint64_t stat_wp_total_mem_accesses;
extern uint64_t stat_bin_total_bits;
extern uint64_t stat_bin_header_bits;
extern uint64_t stat_bin_body_bits;
extern uint64_t stat_bin_dyn_cp_bits;
extern uint64_t stat_bin_dyn_wp_bits;
extern uint64_t stat_bin_wp_exception_bits;

/* ===== Cross-TU functions ===== */

/* Defined in champsim_tracer_decode.cc */
void decode_detail_to_generic(uint64_t pc,
                              const qemu_plugin_insn_info *info,
                              InsnFields *out,
                              InsnRegNames *out_names);

/* Defined in champsim_tracer.cc (BB template management) */
BBTemplate *find_template(uint64_t start_pc);
BBTemplate *get_or_create_bb_template(uint64_t entry_pc,
                                      BBTemplate * const *fragments,
                                      guint n_fragments);
int template_branch_index(const BBTemplate *tmpl);

/*
 * Commit a TRUE basic block by start_pc.  The BB is identified by
 * start_pc; if an entry exists in bb_map at start_pc with the same
 * insn_pcs[] sequence, return it.  If start_pc is new, build a new
 * BBTemplate by copying the provided per-insn metadata.  If start_pc
 * exists with a different insn_pcs[] (impossible without
 * self-modifying code or a tracer bug), log a warning and return the
 * existing template unchanged — BBs are immutable once committed.
 *
 * insn_bytes[] is a flat array sized n_insns * MAX_INSN_BYTES.
 * insn_reg_names may be NULL when reg-data capture is disabled.
 * Caller must hold data_lock.
 */
BBTemplate *commit_true_bb(uint64_t start_pc,
                           uint32_t n_insns,
                           const uint64_t *insn_pcs,
                           const InsnFields *insn_fields,
                           const uint8_t *insn_sizes,
                           const uint8_t *insn_bytes,
                           const InsnRegNames *insn_reg_names,
                           const char *symbol_name,
                           uint64_t fall_through_pc);

/*
 * Look up or create a chain template for a given ordered list of bb_ids.
 * Returns NULL if n_bbs < 2 (no shorthand benefit).
 * Caller must hold data_lock.
 */
ChainTemplate *commit_chain(const uint32_t *bb_ids, uint32_t n_bbs);

/*
 * Look up a register handle by Capstone-style register name
 * (case-insensitive) for @cpu_index.  Returns NULL when @name is
 * empty or not exposed by qemu_plugin_get_registers() on this
 * target.  Only meaningful when enable_reg_data is true.
 */
struct qemu_plugin_register *
lookup_reg_handle(unsigned int cpu_index, const char *cap_reg_name);

/*
 * Wide regfile snapshot: opaque GHashTable<lowercase reg name -> RegSnap*>.
 * Used by the wrong-path loop to capture pre-fragment register state
 * (since CF_MEMI_ONLY in spec mode suppresses per-insn exec callbacks).
 */
typedef struct _WideRegSnap WideRegSnap;

/*
 * Capture a snapshot of every register exposed by the vCPU's
 * reg-handle map.  Returns NULL when reg-data is disabled or the
 * map is unavailable.  Caller must free with wide_reg_snap_free().
 */
WideRegSnap *wide_reg_snap_capture(unsigned int cpu_index);
void         wide_reg_snap_free(WideRegSnap *w);

/*
 * Append per-insn source RegSnap records sourced from a wide snapshot to
 * @out_snaps, using @tmpl->insn_reg_names[insn_idx].src as the lookup
 * keys.  Missing names yield zero snaps.  No-op when reg-data is disabled.
 */
void wp_capture_insn_snaps(const WideRegSnap *wide,
                           const BBTemplate *tmpl,
                           uint32_t insn_idx,
                           GArray *out_snaps);

/* Defined in champsim_tracer_wp.cc */
GArray *simulate_wrong_path_ext(uint64_t branch_pc,
                                uint64_t correct_target,
                                uint64_t wrong_target,
                                unsigned int cpu_index);

/* Defined in champsim_tracer_output.cc */
BodyStreamState *body_stream_new(WriterCtx *w, const char *seg_datetime);
void body_stream_write_entry(BodyStreamState *st, const BodyEntry *entry);
void body_stream_finish(BodyStreamState *st);

#endif /* CHAMPSIM_TRACER_H */
