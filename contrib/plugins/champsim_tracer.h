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
#define MAX_SRC_REGS 4
#define MAX_DST_REGS 4

/*
 * Binary format magic/version 1.1.
 * Bytes in file order: 'C','S','T',0x11 → u32 LE 0x11545343.
 * ASCII: C=0x43 S=0x53 T=0x54.  "CST" = ChampSimTracer.
 */
#define CST_MAGIC          0x11545343u
#define CST_TRAILER_MAGIC  0x11545343FFFFFFFFull
#define CST_TRAILER_SIZE   64

/* Body entry tags (1 byte) */
#define BODY_TAG_END      0
#define BODY_TAG_ENTRY    1

/* Per-insn template flags byte */
#define CST_INSN_FLAG_BRANCH_COND   (1u << 0)
#define CST_INSN_FLAG_HAS_IMM       (1u << 1)
#define CST_INSN_FLAG_SYNC_SHIFT    2
#define CST_INSN_FLAG_SYNC_MASK     0x3Cu
/*
 * Dynamic-memop: the instruction's (n_loads, n_stores) vary at runtime
 * (e.g. REP-prefixed string ops).  Per-entry dyn-params for this insn
 * are prefixed with ULEB actual_n_loads, ULEB actual_n_stores; the
 * template's n_loads/n_stores are observed-max and only advisory.
 */
#define CST_INSN_FLAG_DYNAMIC_MEMOP (1u << 6)

/* WP event flags byte */
#define CST_WP_EVENT_TRANSLATION_UNAVAIL (1u << 0)
#define CST_WP_EVENT_FAULT               (1u << 1)

/* Dyn-patch flags byte */
#define CST_DYN_FLAG_UNCHANGED (1u << 0)

/* Header feature flags (v1.1: templates are always present) */
#define CST_FLAG_MEM_DATA      (1 << 0)
#define CST_FLAG_REG_DATA      (1 << 1)
/* bits 2..7 reserved */

/* ===== Types ===== */

typedef struct {
    uint8_t opcode;                 /* GenericOpcode */
    uint8_t branch_type;            /* BranchType */
    bool branch_conditional;
    uint8_t n_src_regs;
    uint8_t n_dst_regs;
    uint8_t src_regs[MAX_SRC_REGS];
    uint8_t dst_regs[MAX_DST_REGS];
    bool has_immediate;
    int64_t immediate;
    uint8_t sync_hint;              /* SyncEventType */
    uint8_t n_loads;                /* Observed max loads per execution  */
    uint8_t n_stores;               /* Observed max stores per execution */
    bool dynamic_memop;             /* Runtime observed > Capstone static */
} InsnFields;

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
} BBTemplate;

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
 *  - update the template's observed-max (n_loads, n_stores),
 *  - emit mem-data section values.
 *
 * The owning instruction and load/store type are *implicit* on disk —
 * the consumer reconstructs them by walking the template's per-insn
 * (n_loads, n_stores) schema. For dynamic-memop insns the entry
 * carries per-occurrence ULEB (actual_n_loads, actual_n_stores).
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
    uint32_t template_id;
    uint64_t start_pc;
    GArray *dyn_params;
    uint32_t n_insns_executed;
    bool fault;
    bool translation_unavailable;
    BBTemplate *tmpl;  /* Non-owning; for per-insn schema access */
} WPBBEntry;

typedef struct {
    uint32_t seq_num;
    uint32_t template_id;
    GArray *dyn_params;
    GArray *wp_entries;
    BBTemplate *tmpl;  /* Non-owning; for per-insn schema access */
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
    uint64_t taken_target;
    bool has_taken_target;
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

typedef struct {
    uint64_t start_insn;
    uint64_t stop_insn;
    char *label;
    FILE *bin_file;
    BodyStreamState *bin_stream;
    uint32_t thread_id;
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
extern GHashTable *branch_map;
extern uint32_t next_template_id;

extern struct qemu_plugin_scoreboard *vcpu_sb;
extern qemu_plugin_u64 sb_current_pc;
extern qemu_plugin_u64 sb_prev_start_pc;
extern qemu_plugin_u64 sb_prev_last_pc;
extern qemu_plugin_u64 sb_prev_fall_through;
extern qemu_plugin_u64 sb_prev_bb_ends_in_branch;
extern qemu_plugin_u64 sb_insn_count;

extern int max_wrong_path_depth;
extern bool enable_mem_data;
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
                              InsnFields *out);

/* Defined in champsim_tracer.cc (BB template management) */
BBTemplate *find_template(uint64_t start_pc);
BBTemplate *get_or_create_bb_template(uint64_t entry_pc,
                                      BBTemplate * const *fragments,
                                      guint n_fragments);
int template_branch_index(const BBTemplate *tmpl);

/* Defined in champsim_tracer_wp.cc */
GArray *simulate_wrong_path_ext(uint64_t branch_pc,
                                uint64_t correct_target,
                                uint64_t wrong_target,
                                unsigned int cpu_index);

/* Defined in champsim_tracer_output.cc */
BodyStreamState *body_stream_new(FILE *f, uint32_t thread_id,
                                 const char *seg_datetime);
void body_stream_write_entry(BodyStreamState *st, const BodyEntry *entry);
void body_stream_finish(BodyStreamState *st);

#endif /* CHAMPSIM_TRACER_H */
