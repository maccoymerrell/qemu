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
#include <string.h>

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
 * Binary format magic/version 1.8.
 * Bytes in file order: 'C','S','T',0x18 → u32 LE 0x18545343.
 * ASCII: C=0x43 S=0x53 T=0x54.  "CST" = ChampSimTracer.
 *
 * v1.7 replaced the per-entry dyn-patch / mem-data / reg-data
 * sub-sections (and the variable-memop preamble) with a single
 * unified field-typed delta stream.  v1.8 widens scalar dynamic
 * values to 512 bits and adds raw overflow vectors for memops beyond
 * the first 16 fixed slots.  Each BB entry carries:
 *
 *   n_records : ULEB
 *   { ins_pos_gap : ULEB,  field_id : u8,  payload }*
 *
 * Records are emitted in non-descending (ins_pos, field_id) order;
 * unchanged fields contribute zero bytes.  Field IDs identify what
 * changed about an instruction (memop count/addr/data, src/dst reg
 * value, opcode/encoding/immediate etc. — see the FID_* constants
 * below).  Normal scalar fields carry one signed LEB delta:
 * `(cur512 - baseline512) mod 2**512`.  The EXTRA_* memop fields
 * carry raw unsigned LEB vectors and have no persistent state.
 * Baseline = the most-recent
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
#define CST_MAGIC          0x18545343u
#define CST_TRAILER_MAGIC  0x18545343FFFFFFFFull
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

/* ===== Field-ID space (v1.8 unified delta stream) =====
 *
 * Every per-entry observation (memop addresses, memop data, register
 * values, instruction-encoding mutations) is encoded as one record.
 * Slotted scalar families occupy
 * contiguous 16-wide ranges to leave room for SVE / RVV / wide-AVX
 * memop counts.  Memops beyond those 16 slots are emitted through
 * EXTRA_* raw vector fields.
 */
#define CST_FID_SLOT_COUNT       16    /* slots per slotted family */
#define CST_MAX_WIDE_BYTES       64    /* 512-bit data/reg scalar cap */

#define CST_FID_N_LOADS         0x00  /* current valid load slots */

#define CST_FID_LOAD_ADDR_BASE   0x01  /* +k for load slot k ∈ 0..15 */
#define CST_FID_STORE_ADDR_BASE  0x11
#define CST_FID_LOAD_DATA_BASE   0x21  /* gated by CST_FLAG_MEM_DATA  */
#define CST_FID_STORE_DATA_BASE  0x31
#define CST_FID_SRC_REG_BASE     0x41  /* gated by CST_FLAG_REG_DATA  */
/* 0x51..0x60 reserved for post-exec destination register values. */
#define CST_FID_N_STORES        0x61  /* current valid store slots */
#define CST_FID_EXTRA_LOAD_ADDR  0x62  /* raw ULEB vector, slots 16+ */
#define CST_FID_EXTRA_STORE_ADDR 0x63
#define CST_FID_EXTRA_LOAD_DATA  0x64  /* raw ULEB vector, slots 16+ */
#define CST_FID_EXTRA_STORE_DATA 0x65
/* 0x66..0x6F reserved for future slotted memop metadata             */

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
#define CST_FID_EXTENDED         0xFF  /* reserved escape; not used in v1.8   */

/* ===== Types ===== */

/* InsnFields is defined in champsim_tracer_mnemonics.h. */

/*
 * Little-endian unsigned scalar used for dynamic data/register values.
 * The wire format deltas this modulo 2**512 and emits the signed LEB
 * two's-complement result; small values still take the usual short LEB.
 */
typedef struct {
    uint64_t limb[CST_MAX_WIDE_BYTES / sizeof(uint64_t)];
} CSTWideValue;

static inline void cst_wide_zero(CSTWideValue *v)
{
    memset(v, 0, sizeof(*v));
}

static inline CSTWideValue cst_wide_from_u64(uint64_t x)
{
    CSTWideValue v;
    cst_wide_zero(&v);
    v.limb[0] = x;
    return v;
}

static inline CSTWideValue cst_wide_from_i64(int64_t x)
{
    CSTWideValue v;
    uint64_t fill = x < 0 ? UINT64_MAX : 0;
    for (size_t i = 0; i < G_N_ELEMENTS(v.limb); i++) {
        v.limb[i] = fill;
    }
    v.limb[0] = (uint64_t)x;
    return v;
}

static inline void cst_wide_from_le_bytes(CSTWideValue *out,
                                          const uint8_t *bytes,
                                          size_t len)
{
    cst_wide_zero(out);
    if (!bytes || len == 0) {
        return;
    }
    if (len > CST_MAX_WIDE_BYTES) {
        len = CST_MAX_WIDE_BYTES;
    }
    memcpy(out->limb, bytes, len);
}

/*
 * Per-register snapshot, captured immediately before the issuing
 * instruction executes.  Registers the plugin could not resolve to a
 * runtime handle on this target are emitted as zero.
 */
typedef struct {
    CSTWideValue value;
} RegSnap;

/*
 * Per-insn QEMU register descriptor keys for InsnFields.src_regs[] and
 * InsnFields.dst_regs[].  A NULL name means the corresponding generic
 * register has no single QEMU register that can be read directly.
 */
typedef struct {
    QemuRegKey src_qemu_reg_keys[MAX_SRC_REGS];
    QemuRegKey dst_qemu_reg_keys[MAX_DST_REGS];
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
    CSTWideValue data;
} DynParam;

typedef struct {
    uint32_t template_id;       /* TRUE BB id (start_pc → first branch) */
    uint64_t start_pc;
    GArray *dyn_params;         /* dyn_params for THIS BB only; NULL if empty */
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

enum { BRANCH_TARGET_HISTORY = 16 };

typedef struct {
    uint64_t target;
    uint32_t count;
    uint32_t last_seen;
    bool valid;
} BranchTargetHistoryEntry;

typedef struct {
    uint64_t pc;
    uint64_t fall_through;
    /* Counted distinct taken-target history.  Indirect wrong-path
     * selection treats one observed target as monomorphic and uses
     * fall-through; with multiple observed targets it chooses the most
     * frequent target that is not the CP target for this execution. */
    BranchTargetHistoryEntry targets[BRANCH_TARGET_HISTORY];
    uint8_t n_targets;
    uint32_t target_tick;
} BranchRecord;

typedef struct {
    uint64_t insn_pc;
    uint64_t mem_vaddr;
    bool is_store;
    uint8_t data_size;
    CSTWideValue data;
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

/*
 * Wide regfile snapshot: opaque thread-local scratch keyed by the QEMU
 * register descriptors present in the active Capstone register table.  Used by the
 * wrong-path loop to capture pre-fragment register state (since CF_MEMI_ONLY
 * in spec mode suppresses per-insn exec callbacks).
 */
typedef struct _WideRegSnap WideRegSnap;

/*
 * Capture a snapshot of every readable register referenced by the active
 * register classification table.  Returns NULL when reg-data is disabled or
 * no readable registers exist.  The returned pointer is thread-local scratch
 * and remains valid until the next wide_reg_snap_capture() on the same thread.
 */
WideRegSnap *wide_reg_snap_capture(unsigned int cpu_index);
void         wide_reg_snap_free(WideRegSnap *w);

/*
 * Append per-insn source RegSnap records sourced from a wide snapshot to
 * @out_snaps, using @tmpl->insn_reg_names[insn_idx].src_qemu_reg_keys as the
 * lookup keys.  Missing handles yield zero snaps.  No-op when reg-data is
 * disabled.
 */
void wp_capture_insn_snaps(const WideRegSnap *wide,
                           const BBTemplate *tmpl,
                           uint32_t insn_idx,
                           GArray *out_snaps);
void wp_capture_insn_snaps_live(unsigned int cpu_index,
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
