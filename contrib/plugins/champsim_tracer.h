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
 * Binary format magic/version 1.2.
 * Bytes in file order: 'C','S','T',0x12 → u32 LE 0x12545343.
 * ASCII: C=0x43 S=0x53 T=0x54.  "CST" = ChampSimTracer.
 *
 * v1.2 adds a ULEB fault_insn_index to WP event records when
 * CST_WP_EVENT_FAULT is set (see format spec §3.1.2).
 */
#define CST_MAGIC          0x12545343u
#define CST_TRAILER_MAGIC  0x12545343FFFFFFFFull
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

/* Header feature flags (templates are always present since v1.1) */
#define CST_FLAG_MEM_DATA      (1 << 0)
#define CST_FLAG_REG_DATA      (1 << 1)
/* bits 2..7 reserved */

/* ===== Types ===== */

/* InsnFields is defined in champsim_tracer_mnemonics.h. */

/*
 * Per-register snapshot, captured immediately before the issuing
 * instruction executes.  size_code values:
 *   0 = 4 bytes,  1 = 8 bytes,  2 = 16 bytes.
 * `lo` carries the low 8 bytes (LE); `hi` carries the high 8 bytes
 * for 16-byte registers and is 0 otherwise.  Registers the plugin
 * could not resolve to a runtime handle on this target are emitted
 * as size_code=0 lo=0 hi=0 (and do not advance the per-reg delta
 * state).
 */
typedef struct {
    uint8_t  size_code;
    uint64_t lo;
    uint64_t hi;
} RegSnap;

/*
 * Per-insn parallel name table for InsnFields.src_regs[] and
 * InsnFields.dst_regs[].  Populated by the decoder only when
 * enable_reg_data is true at translation time; consumed by the
 * per-insn reg-snap callback to look up QEMU register handles via
 * lookup_reg_handle().  Empty string means no Capstone runtime name
 * is associated with that slot (→ emitted as a zero snap).
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
    /*
     * Index (within the merged BB template, i.e. chain-relative) of the
     * instruction that raised the synchronous exception when `fault`
     * is true. Undefined otherwise. Consumers (e.g. ChampSim) use this
     * to flag the specific uop as non-completing so its dependent
     * slice is naturally squashed.
     */
    uint32_t fault_insn_index;
    BBTemplate *tmpl;  /* Non-owning; for per-insn schema access */
    /* RegSnap array, ordered: for each insn in the merged WP
     * template, n_src snaps then n_dst snaps.  Captured pre-insn via
     * a per-fragment wide regfile dump (see wp_capture_insn_snaps).
     * NULL when reg-data is disabled. */
    GArray *reg_snaps;
} WPBBEntry;

typedef struct {
    uint32_t seq_num;
    uint32_t template_id;
    GArray *dyn_params;
    /* RegSnap array, ordered: for each insn in the template, n_src
     * snaps then n_dst snaps.  Only populated when enable_reg_data
     * is true; emitted in the §5.2 reg-data section. */
    GArray *reg_snaps;
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
 * Append per-insn (n_src + n_dst) RegSnap records sourced from a
 * wide snapshot to @out_snaps, using @tmpl->insn_reg_names[insn_idx]
 * as the lookup keys.  Missing names yield zero snaps.  No-op when
 * reg-data is disabled.
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
BodyStreamState *body_stream_new(FILE *f, uint32_t thread_id,
                                 const char *seg_datetime);
void body_stream_write_entry(BodyStreamState *st, const BodyEntry *entry);
void body_stream_finish(BodyStreamState *st);

#endif /* CHAMPSIM_TRACER_H */
