/*
 * Wrong-Path Tracing Plugin — shared types and plugin-wide globals.
 *
 * Private header; included by every plugin TU.  After the C++ refactor
 * this header carries only:
 *   - Wire-format constants (CST_*, BODY_TAG_*, CST_FID_*).
 *   - Shared POD types (CSTWideValue, BBTemplate, BodyEntry, ...).
 *   - A short list of plugin-wide globals (ISA resolution, plugin
 *     config flags, synchronization).  Subsystem-private state lives
 *     in each subsystem's own header.
 *   - A handful of cross-TU function declarations whose owners haven't
 *     been wrapped in classes (decode_detail_to_generic,
 *     simulate_wrong_path_ext, body_stream_*).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_H
#define CHAMPSIM_TRACER_H

/* <atomic> is C++-only; pull it in first so its transitive includes
 * resolve before glib does. */
#ifdef __cplusplus
#include <atomic>
#endif

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
 * Binary format magic/version 1.9.
 * Bytes in file order: 'C','S','T',0x19 → u32 LE 0x19545343.
 * ASCII: C=0x43 S=0x53 T=0x54.  "CST" = ChampSimTracer.
 *
 * v1.7 replaced the per-entry dyn-patch / mem-data / reg-data
 * sub-sections (and the variable-memop preamble) with a single
 * unified field-typed delta stream.  v1.8 widens scalar dynamic
 * values to 512 bits and adds raw overflow vectors for memops beyond
 * the first 16 fixed slots.  v1.9 changes the WP delta-encoding
 * baseline: WP state now persists across chains (rather than being
 * forked from CP per chain and discarded), with an unobserved-WP-key
 * fallback to the CP state.  Hot WP templates that are visited many
 * times across chains delta against the prior WP-observed value
 * instead of paying first-observation cost on every chain — typically
 * cuts trace size 3x on real workloads.  No effect on CP encoding or
 * on the architectural meaning of WP (the writer still discards
 * speculative architectural effects at chain end; this is purely a
 * compression-cache change).
 *
 * Each BB entry carries:
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
 * Baseline = the most-recent observation in the active overlay
 * (CP state for CP records; WP state for WP records, falling back
 * to CP if the WP overlay never observed this key); template-default
 * on first appearance.
 *
 * Templates track true basic blocks (start_pc to first branch,
 * immutable, unique by start_pc).  Memory-operation counts are runtime
 * sparse fields populated from QEMU memory callbacks; template count
 * defaults are zero.
 */
#define CST_MAGIC          0x19545343u
#define CST_TRAILER_MAGIC  0x19545343FFFFFFFFull
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

/*
 * BodyEntry / WPBBEntry use std::vector for their dynamic arrays, so
 * they are visible only to C++ TUs.  The C-only mnemonic_tables.c
 * does not consume them.
 */
#ifdef __cplusplus
#include <vector>

struct WPBBEntry {
    uint32_t template_id;       /* TRUE BB id (start_pc → first branch) */
    uint64_t start_pc;
    std::vector<DynParam> dyn_params;  /* memops captured during this WP BB */
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
    /* RegSnap vector, ordered: for each insn in this BB, n_src snaps
     * only.  Captured pre-insn via a per-fragment wide regfile dump.
     * Empty when reg-data is disabled. */
    std::vector<RegSnap> reg_snaps;
};

struct BodyEntry {
    uint32_t seq_num;
    uint32_t template_id;
    std::vector<DynParam> dyn_params;
    /* RegSnap vector, ordered: for each insn in the template, n_src
     * snaps only.  Only populated when enable_reg_data is true. */
    std::vector<RegSnap> reg_snaps;
    std::vector<WPBBEntry> wp_entries;
    BBTemplate *tmpl;  /* Non-owning; for per-insn schema access */
    uint32_t thread_id;
};
#endif  /* __cplusplus */

typedef struct {
    uint64_t current_pc;
    uint64_t prev_start_pc;
    uint64_t prev_last_pc;
    uint64_t prev_fall_through;
    uint64_t prev_bb_ends_in_branch;
    uint64_t insn_count;
    /* Start PC of the most recent TB whose insns we counted toward
     * insn_count.  When QEMU re-enters the same TB without
     * architectural progress (the canonical case is x86 REP-prefixed
     * string ops, where each iteration of the rep is exposed to the
     * plugin as a separate exec_tb call against a single-insn TB at
     * the same start_pc), we hold insn_count steady so it tracks
     * *unique-PC visits* rather than dispatcher entries.  This keeps
     * the icount aligned with PIN-style "one count per architectural
     * insn" accounting on workloads that use REP MOVSB / STOSB / etc. */
    uint64_t last_counted_start_pc;
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

/* ===== Plugin-wide globals ===== */

/* ISA resolution: set once during qemu_plugin_install based on the
 * guest target_name. */
extern TraceISA trace_isa;
extern int cst_cap_arch;
extern unsigned int cst_cap_mode;
extern const char *target_name;
extern const InsnClassification *active_insn_table;
extern unsigned active_insn_table_size;
extern const RegClassification *active_reg_table;
extern unsigned active_reg_table_size;

/* Plugin configuration: parsed from -plugin args, immutable after
 * qemu_plugin_install. */
extern int max_wrong_path_depth;
extern bool enable_mem_data;
extern bool enable_reg_data;
/* WP-side data toggles.  Default to the matching CP-side flag at
 * qemu_plugin_install time when the user didn't explicitly set them.
 *
 * enable_wp_mem_data: gates the VALUE half of WP memops only.  WP
 *   memop addresses are always recorded so the speculative path's
 *   memory footprint is preserved (the typical use case for cache
 *   sims / prefetcher work); the data values are dropped when off.
 *
 * enable_wp_reg_data: gates the per-insn register-value snapshots on
 *   the WP path.  Register identifiers come from the template either
 *   way; only the captured value stream is suppressed when off. */
extern bool enable_wp_mem_data;
extern bool enable_wp_reg_data;
extern char *qemu_command_line;
extern char *trace_comment;

/* Synchronization & diagnostics.  GMutex stays (rather than
 * std::mutex) because <mutex>'s transitive include chain pulls
 * <cctype> -> <ctype.h>, and QEMU's include/qemu/ctype.h shadows the
 * system header on the plugin's -I search path.  That breaks
 * libstdc++'s `using ::isalnum;` declarations and the build fails. */
extern GMutex data_lock;
extern GMutex unknown_warn_lock;
extern FILE *unknown_warn_file;

/* Null-safe string equality (cst_str_eq) is defined in
 * champsim_tracer_mnemonics.h, which this header pulls in below. */

/* ===== Cross-TU functions ===== */

/* Defined in champsim_tracer_decode.cc */
void decode_detail_to_generic(uint64_t pc,
                              const qemu_plugin_insn_info *info,
                              InsnFields *out,
                              InsnRegNames *out_names);

/* Build the GenericRegId → QemuRegKey reverse index used by the
 * multi-reg path of add_src_cap_reg / add_dst_cap_reg.  Must run
 * after active_reg_table is set; idempotent.  Defined in
 * champsim_tracer_decode.cc. */
void build_qemu_reg_reverse_index(void);

/*
 * Wide regfile snapshot: opaque thread-local scratch keyed by the QEMU
 * register descriptors present in the active Capstone register table.  Used by the
 * wrong-path loop to capture pre-fragment register state (since CF_MEMI_ONLY
 * in spec mode suppresses per-insn exec callbacks).
 */
typedef struct _WideRegSnap WideRegSnap;

/* Reg-snap capture is provided by RegSnapCollector; see
 * champsim_tracer_reg_snap_collector.h. */

/* Defined in champsim_tracer_wp.cc.  Returns the speculative chain by
 * value; callers move it into BodyEntry::wp_entries. */
#ifdef __cplusplus
std::vector<WPBBEntry> simulate_wrong_path_ext(uint64_t branch_pc,
                                               uint64_t correct_target,
                                               uint64_t wrong_target,
                                               unsigned int cpu_index);
#endif

/* Defined in champsim_tracer_output.cc */
BodyStreamState *body_stream_new(WriterCtx *w, const char *seg_datetime);
void body_stream_write_entry(BodyStreamState *st, BodyEntry *entry);
void body_stream_finish(BodyStreamState *st);

#endif /* CHAMPSIM_TRACER_H */
