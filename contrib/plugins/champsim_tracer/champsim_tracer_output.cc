/*
 * Wrong-Path Tracing Plugin - binary format v1.8 writer.
 *
 * BitWriter primitives, template dictionary serializer, dyn-param
 * patch emitter, body entry streamer, and trailer writer for the
 * packed binary (.cst) format.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <inttypes.h>
#include <string.h>

#include <algorithm>
#include <vector>

#include "champsim_tracer.h"
#include "champsim_tracer_bb_template_cache.h"
#include "champsim_tracer_stats.h"
#include "champsim_tracer_writer.h"

/* ========================= BitWriter primitives ========================= */

static inline void bw_init_writer(BitWriter *bw, WriterCtx *w)
{
    bw->f = nullptr;
    bw->buf = nullptr;
    bw->w = w;
    bw->total_bytes = 0;
}

static inline void bw_init_file(BitWriter *bw, FILE *f)
{
    bw->f = f;
    bw->buf = nullptr;
    bw->w = nullptr;
    bw->total_bytes = 0;
}

static inline void bw_init_buf(BitWriter *bw)
{
    bw->f = nullptr;
    bw->buf = g_byte_array_new();
    bw->w = nullptr;
    bw->total_bytes = 0;
}

static inline GByteArray *bw_finish_buf(BitWriter *bw)
{
    GByteArray *out = bw->buf;
    bw->buf = nullptr;
    bw->total_bytes = 0;
    return out;
}

static inline uint64_t bw_tell_bytes(const BitWriter *bw)
{
    return bw->total_bytes;
}

static inline void bw_raw(BitWriter *bw, const uint8_t *buf, size_t len)
{
    if (len == 0) {
        return;
    }
    if (bw->w) {
        writer_submit(bw->w, buf, len);
    } else if (bw->f) {
        fwrite(buf, 1, len, bw->f);
    } else {
        g_byte_array_append(bw->buf, buf, (unsigned int)len);
    }
    bw->total_bytes += len;
}

/* Self-documenting no-op: the stream is byte-aligned by construction. */
static inline void bw_byte_align(BitWriter *bw)
{
    (void)bw;
}

static inline void bw_flush(BitWriter *bw)
{
    if (bw->f) {
        fflush(bw->f);
    }
    /* WriterCtx flushes on writer_finish; nothing to do mid-stream. */
}

static inline void bw_write_u8(BitWriter *bw, uint8_t v)
{
    bw_raw(bw, &v, 1);
}

static inline void bw_write_u32_le(BitWriter *bw, uint32_t v)
{
    uint8_t b[4] = {
        (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF),
        (uint8_t)((v >> 16) & 0xFF), (uint8_t)((v >> 24) & 0xFF),
    };
    bw_raw(bw, b, 4);
}

static inline void bw_write_u64_le(BitWriter *bw, uint64_t v)
{
    uint8_t b[8];
    for (int i = 0; i < 8; i++) {
        b[i] = (uint8_t)((v >> (i * 8)) & 0xFF);
    }
    bw_raw(bw, b, 8);
}

static inline void bw_write_bytes(BitWriter *bw, const uint8_t *buf, size_t len)
{
    bw_raw(bw, buf, len);
}

static void bw_write_uleb128(BitWriter *bw, uint64_t v);

static void bw_write_string(BitWriter *bw, const char *str)
{
    size_t len = str ? strlen(str) : 0;
    bw_write_uleb128(bw, len);
    if (len) {
        bw_write_bytes(bw, (const uint8_t *)str, len);
    }
}

static void bw_write_uleb128(BitWriter *bw, uint64_t v)
{
    uint8_t buf[10];
    size_t n = 0;
    do {
        uint8_t byte = v & 0x7F;
        v >>= 7;
        if (v != 0) {
            byte |= 0x80;
        }
        buf[n++] = byte;
    } while (v != 0);
    bw_raw(bw, buf, n);
}

static void bw_write_sleb128(BitWriter *bw, int64_t v)
{
    uint8_t buf[10];
    size_t n = 0;
    bool more = true;
    while (more) {
        uint8_t byte = (uint8_t)(v & 0x7F);
        bool sign = (byte & 0x40) != 0;
        v >>= 7;
        more = !((v == 0 && !sign) || (v == -1 && sign));
        if (more) {
            byte |= 0x80;
        }
        buf[n++] = byte;
    }
    bw_raw(bw, buf, n);
}

/*
 * Emit a length-prefixed sub-section (ULEB byte length + buffer bytes).
 * Takes ownership of @data and frees it.
 */
static void bw_write_section(BitWriter *main_bw, GByteArray *data)
{
    bw_write_uleb128(main_bw, data->len);
    bw_raw(main_bw, data->data, data->len);
    g_byte_array_unref(data);
}

typedef struct EncodingMapEntry {
    uint64_t value;
    const char *name;
} EncodingMapEntry;

static void write_encoding_entry(BitWriter *bw, uint64_t value,
                                 const char *name)
{
    bw_write_uleb128(bw, value);
    bw_write_string(bw, name);
}

static void write_encoding_map(BitWriter *bw, const char *map_name,
                               const EncodingMapEntry *entries,
                               size_t n_entries)
{
    bw_write_string(bw, map_name);
    bw_write_uleb128(bw, n_entries);
    for (size_t i = 0; i < n_entries; i++) {
        write_encoding_entry(bw, entries[i].value, entries[i].name);
    }
}

static void write_reg_encoding_map(BitWriter *bw)
{
    /* Walk the full GenericRegId space.  generic_reg_name() returns
     * NULL for unallocated holes; valid IDs (the dense banks plus all
     * specials) get their canonical name from the shared helper. */
    bw_write_string(bw, "reg");
    uint64_t n = 0;
    for (unsigned i = 0; i < REG_ID_COUNT; i++) {
        if (generic_reg_name(i)) n++;
    }
    bw_write_uleb128(bw, n);
    for (unsigned i = 0; i < REG_ID_COUNT; i++) {
        const char *name = generic_reg_name(i);
        if (name) {
            write_encoding_entry(bw, i, name);
        }
    }
}

static void write_field_id_encoding_map(BitWriter *bw)
{
    bw_write_string(bw, "field_id");
    bw_write_uleb128(bw, 94);
    write_encoding_entry(bw, CST_FID_N_LOADS, "CST_FID_N_LOADS");
    for (uint64_t i = 0; i < CST_FID_SLOT_COUNT; i++) {
        g_autofree char *name = g_strdup_printf("CST_FID_LOAD_ADDR%" PRIu64, i);
        write_encoding_entry(bw, CST_FID_LOAD_ADDR_BASE + i, name);
    }
    for (uint64_t i = 0; i < CST_FID_SLOT_COUNT; i++) {
        g_autofree char *name = g_strdup_printf("CST_FID_STORE_ADDR%" PRIu64, i);
        write_encoding_entry(bw, CST_FID_STORE_ADDR_BASE + i, name);
    }
    for (uint64_t i = 0; i < CST_FID_SLOT_COUNT; i++) {
        g_autofree char *name = g_strdup_printf("CST_FID_LOAD_DATA%" PRIu64, i);
        write_encoding_entry(bw, CST_FID_LOAD_DATA_BASE + i, name);
    }
    for (uint64_t i = 0; i < CST_FID_SLOT_COUNT; i++) {
        g_autofree char *name = g_strdup_printf("CST_FID_STORE_DATA%" PRIu64, i);
        write_encoding_entry(bw, CST_FID_STORE_DATA_BASE + i, name);
    }
    for (uint64_t i = 0; i < CST_FID_SLOT_COUNT; i++) {
        g_autofree char *name = g_strdup_printf("CST_FID_SRC_REG%" PRIu64, i);
        write_encoding_entry(bw, CST_FID_SRC_REG_BASE + i, name);
    }
    static const EncodingMapEntry insn_fields[] = {
        { CST_FID_N_STORES, "CST_FID_N_STORES" },
        { CST_FID_EXTRA_LOAD_ADDR, "CST_FID_EXTRA_LOAD_ADDR" },
        { CST_FID_EXTRA_STORE_ADDR, "CST_FID_EXTRA_STORE_ADDR" },
        { CST_FID_EXTRA_LOAD_DATA, "CST_FID_EXTRA_LOAD_DATA" },
        { CST_FID_EXTRA_STORE_DATA, "CST_FID_EXTRA_STORE_DATA" },
        { CST_FID_INSN_BYTES_LO, "CST_FID_INSN_BYTES_LO" },
        { CST_FID_INSN_BYTES_HI, "CST_FID_INSN_BYTES_HI" },
        { CST_FID_INSN_OPCODE, "CST_FID_INSN_OPCODE" },
        { CST_FID_INSN_BRANCH_TYPE, "CST_FID_INSN_BRANCH_TYPE" },
        { CST_FID_INSN_FLAGS, "CST_FID_INSN_FLAGS" },
        { CST_FID_INSN_IMMEDIATE, "CST_FID_INSN_IMMEDIATE" },
        { CST_FID_INSN_SIZE, "CST_FID_INSN_SIZE" },
        { CST_FID_EXTENDED, "CST_FID_EXTENDED" },
    };
    for (size_t i = 0; i < G_N_ELEMENTS(insn_fields); i++) {
        write_encoding_entry(bw, insn_fields[i].value, insn_fields[i].name);
    }
}

/* Write all (id, name) pairs for an enum range whose name lookup is
 * provided by @name_of, skipping unallocated IDs (where the lookup
 * returns NULL).  The wire format expects: string(map_name) +
 * uleb(n_entries) + n_entries * (uleb(id), string(name)). */
static void write_named_enum_map(BitWriter *bw, const char *map_name,
                                 unsigned id_count,
                                 const char *(*name_of)(unsigned))
{
    bw_write_string(bw, map_name);
    uint64_t n = 0;
    for (unsigned i = 0; i < id_count; i++) {
        if (name_of(i)) n++;
    }
    bw_write_uleb128(bw, n);
    for (unsigned i = 0; i < id_count; i++) {
        const char *name = name_of(i);
        if (name) {
            write_encoding_entry(bw, i, name);
        }
    }
}

/* Wrapper for sync_event_name to fit the unsigned->const char* shape. */
static const char *sync_event_name_for_map(unsigned id)
{
    return sync_event_name(id);
}

static void write_header_encoding_maps(BitWriter *main_bw)
{
    /* opcode / branch_type / sync_hint / reg encoding maps are now
     * driven by the shared name helpers in champsim_tracer_generic_ids.h
     * (write_named_enum_map + the helper) so the symbolic names live
     * in exactly one place across the wire-format encoder and the
     * exit-time stats printer. */
    static const EncodingMapEntry header_flag_entries[] = {
        { CST_FLAG_MEM_DATA, "CST_FLAG_MEM_DATA" },
        { CST_FLAG_REG_DATA, "CST_FLAG_REG_DATA" },
        { CST_FLAG_RESERVED_2, "CST_FLAG_RESERVED_2" },
    };
    static const EncodingMapEntry insn_flag_entries[] = {
        { CST_INSN_FLAG_BRANCH_COND, "CST_INSN_FLAG_BRANCH_COND" },
        { CST_INSN_FLAG_HAS_IMM, "CST_INSN_FLAG_HAS_IMM" },
        { CST_INSN_FLAG_SYNC_MASK, "CST_INSN_FLAG_SYNC_MASK" },
    };
    static const EncodingMapEntry body_tag_entries[] = {
        { BODY_TAG_END, "BODY_TAG_END" },
        { BODY_TAG_ENTRY, "BODY_TAG_ENTRY" },
        { BODY_TAG_THREAD_SWITCH, "BODY_TAG_THREAD_SWITCH" },
    };
    static const EncodingMapEntry wp_event_flag_entries[] = {
        { CST_WP_EVENT_TRANSLATION_UNAVAIL,
          "CST_WP_EVENT_TRANSLATION_UNAVAIL" },
        { CST_WP_EVENT_FAULT, "CST_WP_EVENT_FAULT" },
    };

    BitWriter sub;
    bw_init_buf(&sub);
    bw_write_uleb128(&sub, 9);
    write_named_enum_map(&sub, "opcode", GEN_OP_COUNT, generic_opcode_name);
    write_named_enum_map(&sub, "branch_type", BRANCH_TYPE_COUNT,
                         branch_type_name);
    /* SyncEventType has sparse codepoints (0, 4, 5); iterate over the
     * defined enum range and let sync_event_name skip the holes. */
    write_named_enum_map(&sub, "sync_hint", SYNC_EVENT_COUNT,
                         sync_event_name_for_map);
    write_reg_encoding_map(&sub);
    write_field_id_encoding_map(&sub);
    write_encoding_map(&sub, "header_flag", header_flag_entries,
                       G_N_ELEMENTS(header_flag_entries));
    write_encoding_map(&sub, "insn_flag", insn_flag_entries,
                       G_N_ELEMENTS(insn_flag_entries));
    write_encoding_map(&sub, "body_tag", body_tag_entries,
                       G_N_ELEMENTS(body_tag_entries));
    write_encoding_map(&sub, "wp_event_flag", wp_event_flag_entries,
                       G_N_ELEMENTS(wp_event_flag_entries));
    bw_write_section(main_bw, bw_finish_buf(&sub));
}

typedef struct FieldStateTable FieldStateTable;

typedef struct {
    uint32_t *actual_n_loads;
    uint32_t *actual_n_stores;
    uint32_t *insn_dp_off;
    uint32_t *insn_rs_off;
    const DynParam **load_slots;
    const DynParam **store_slots;
    uint32_t n_cap;
    size_t slot_cap;
} EntryViewScratch;

struct BodyStreamState {
    BitWriter bw;
    int64_t prev_entry_template;
    int64_t current_thread;
    /* v1.8 unified field-state tables: keyed by template_id, then dense
     * indexed by (ins_pos, field_id).  CP state persists across the body.
     * WP state is a per-chain overlay that falls back to CP state. */
    FieldStateTable *cp_field_state;
    FieldStateTable *wp_field_state;
    EntryViewScratch ev_scratch;
    uint64_t num_entries;
    uint64_t body_off;
    uint8_t  header_flags;   /* CST_FLAG_* bits emitted in header */
};

/* ========================= Template dictionary ========================= */

/*
 * Write the template dictionary section.
 *
 * Layout:
 *   num_templates : ULEB128
 *   { tmpl_len : ULEB128 , tmpl_bytes[tmpl_len] } *
 *
 * Each template record (buffered separately so its length is known):
 *   template_id      : ULEB128
 *   start_pc         : ULEB128
 *   num_insns        : ULEB128
 *   fall_through_pc  : ULEB128
 *   symbol_name      : string (ULEB128 len + UTF-8 bytes)
 *   { insn_record } *
 *
 * Per-insn record (byte-aligned):
 *   pc_delta    : ULEB128  (delta from previous insn PC within template;
 *                           first insn uses delta from start_pc)
 *   opcode      : u8
 *   branch_type : u8
 *   flags       : u8       bit0=branch_conditional, bit1=has_immediate,
 *                          bits 2..5 = sync_hint (4 bits),
 *                          bits 6..7 = reserved
 *   n_src       : u8
 *   n_dst       : u8
 *   src_regs[n_src] : u8 each
 *   dst_regs[n_dst] : u8 each
 *   n_loads     : u8       zero; runtime count is sparse N_LOADS
 *   n_stores    : u8       zero; runtime count is sparse N_STORES
 *   [imm]       : SLEB128  (iff has_immediate)
 *   insn_size   : u8
 *   insn_bytes[insn_size]
 */
static void write_bin_templates(BitWriter *bw)
{
    bw_write_uleb128(bw, g_bb_template_cache.bb_count());

    g_bb_template_cache.for_each_bb([bw](BBTemplate &tmpl_ref) {
        BBTemplate *tmpl = &tmpl_ref;
        BitWriter sub;
        bw_init_buf(&sub);

        bw_write_uleb128(&sub, tmpl->template_id);
        bw_write_uleb128(&sub, tmpl->start_pc);
        bw_write_uleb128(&sub, tmpl->n_insns);
        bw_write_uleb128(&sub, tmpl->fall_through_pc);
        {
            const char *sym = tmpl->symbol_name ? tmpl->symbol_name : "";
            size_t sym_len = strlen(sym);
            bw_write_uleb128(&sub, sym_len);
            bw_write_bytes(&sub, (const uint8_t *)sym, sym_len);
        }

        uint64_t prev_pc = tmpl->start_pc;
        for (uint32_t i = 0; i < tmpl->n_insns; i++) {
            InsnFields *fld = &tmpl->insn_fields[i];
            uint64_t pc = tmpl->insn_pcs[i];
            uint64_t delta = pc - prev_pc;
            prev_pc = pc;

            bw_write_uleb128(&sub, delta);
            bw_write_u8(&sub, fld->opcode);
            bw_write_u8(&sub, fld->branch_type);

            uint8_t flags = 0;
            if (fld->branch_conditional) {
                flags |= CST_INSN_FLAG_BRANCH_COND;
            }
            if (fld->has_immediate) {
                flags |= CST_INSN_FLAG_HAS_IMM;
            }
            flags |= (uint8_t)((fld->sync_hint & 0x0F)
                               << CST_INSN_FLAG_SYNC_SHIFT);
            bw_write_u8(&sub, flags);

            bw_write_u8(&sub, fld->n_src_regs);
            bw_write_u8(&sub, fld->n_dst_regs);
            for (uint8_t s = 0; s < fld->n_src_regs; s++) {
                bw_write_u8(&sub, fld->src_regs[s]);
            }
            for (uint8_t d = 0; d < fld->n_dst_regs; d++) {
                bw_write_u8(&sub, fld->dst_regs[d]);
            }
            bw_write_u8(&sub, 0);
            bw_write_u8(&sub, 0);
            if (fld->has_immediate) {
                bw_write_sleb128(&sub, fld->immediate);
            }
            bw_write_u8(&sub, tmpl->insn_sizes[i]);
            bw_write_bytes(&sub,
                           &tmpl->insn_bytes[(size_t)i * MAX_INSN_BYTES],
                           tmpl->insn_sizes[i]);
        }

        bw_byte_align(&sub);
        GByteArray *data = bw_finish_buf(&sub);
        bw_write_section(bw, data);
    });
}

/* ========================= Dyn param helpers ========================= */

/* ============== Unified field-typed delta stream ==============
 *
 * Each BB entry carries a single
 * length-prefixed `delta_section`:
 *
 *     n_records : ULEB
 *     for r in 0..n_records:
 *       ins_pos_gap : ULEB        (cur_ins_pos − prev_ins_pos)
 *       field_id    : u8          (CST_FID_*)
 *       payload     : scalar SLEB512 delta, or raw vector for EXTRA_*
 *
 * Records are emitted in non-descending (ins_pos, field_id) order;
 * unchanged fields contribute zero bytes.  Per-(template_id, ins_pos,
 * field_id) state tables track the most-recent observed value and
 * supply the baseline.  CP state advances on every CP entry; WP
 * state is forked from CP at chain start and discarded at chain end.
 *
 * Scalar fields are represented as modulo-2**512 little-endian values.
 * EXTRA_* memop fields are rare raw vectors and do not update scalar
 * state.
 */

typedef CSTWideValue U512;

static inline bool u512_is_zero(U512 v)
{
    for (size_t i = 0; i < G_N_ELEMENTS(v.limb); i++) {
        if (v.limb[i] != 0) {
            return false;
        }
    }
    return true;
}

static inline bool u512_is_minus_one(U512 v)
{
    for (size_t i = 0; i < G_N_ELEMENTS(v.limb); i++) {
        if (v.limb[i] != UINT64_MAX) {
            return false;
        }
    }
    return true;
}

static inline bool u512_equal(U512 a, U512 b)
{
    return memcmp(&a, &b, sizeof(a)) == 0;
}

static inline U512 u512_sub(U512 a, U512 b)
{
    U512 r;
    uint64_t borrow = 0;
    for (size_t i = 0; i < G_N_ELEMENTS(r.limb); i++) {
        unsigned __int128 sub = (unsigned __int128)b.limb[i] + borrow;
        r.limb[i] = a.limb[i] - (uint64_t)sub;
        borrow = ((unsigned __int128)a.limb[i] < sub) ? 1 : 0;
    }
    return r;
}

static inline void u512_shr7(U512 *v)
{
    for (size_t i = 0; i < G_N_ELEMENTS(v->limb); i++) {
        uint64_t next = (i + 1 < G_N_ELEMENTS(v->limb)) ? v->limb[i + 1] : 0;
        v->limb[i] = (v->limb[i] >> 7) | (next << 57);
    }
}

static inline void u512_sar7(U512 *v)
{
    bool negative = (v->limb[G_N_ELEMENTS(v->limb) - 1] >> 63) != 0;
    for (size_t i = 0; i < G_N_ELEMENTS(v->limb); i++) {
        uint64_t next = (i + 1 < G_N_ELEMENTS(v->limb))
            ? v->limb[i + 1]
            : (negative ? UINT64_MAX : 0);
        v->limb[i] = (v->limb[i] >> 7) | (next << 57);
    }
}

static inline void u512_mask_bytes(U512 *v, uint8_t size)
{
    uint8_t n = size ? size : 1;
    if (n >= CST_MAX_WIDE_BYTES) {
        return;
    }
    uint8_t full = n / 8;
    uint8_t rem = n % 8;
    if (rem != 0) {
        uint64_t mask = ((uint64_t)1 << (rem * 8)) - 1;
        v->limb[full] &= mask;
        full++;
    }
    for (uint8_t i = full; i < G_N_ELEMENTS(v->limb); i++) {
        v->limb[i] = 0;
    }
}

static void bw_write_uleb128_u512(BitWriter *bw, U512 v)
{
    uint8_t buf[80];
    size_t n = 0;
    do {
        uint8_t byte = (uint8_t)(v.limb[0] & 0x7F);
        u512_shr7(&v);
        if (!u512_is_zero(v)) {
            byte |= 0x80;
        }
        buf[n++] = byte;
    } while (!u512_is_zero(v));
    bw_raw(bw, buf, n);
}

static void bw_write_sleb128_u512(BitWriter *bw, U512 v)
{
    uint8_t buf[80];
    size_t n = 0;
    bool more = true;
    while (more) {
        uint8_t byte = (uint8_t)(v.limb[0] & 0x7F);
        bool sign = (byte & 0x40) != 0;
        u512_sar7(&v);
        more = !((u512_is_zero(v) && !sign) ||
                 (u512_is_minus_one(v) && sign));
        if (more) {
            byte |= 0x80;
        }
        buf[n++] = byte;
    }
    bw_raw(bw, buf, n);
}

enum {
    FIELD_STATE_SLOT_INVALID = 0xFF,
    FIELD_STATE_SLOT_COUNT = 1 + (5 * CST_FID_SLOT_COUNT) + 1 + 7,
};

typedef struct FieldStateBlock {
    uint32_t n_insns;
    U512 *values;
    uint32_t *generations;
} FieldStateBlock;

struct FieldStateTable {
    GHashTable *blocks;
    uint32_t generation;
};

static uint8_t field_state_slot_index(uint8_t field_id)
{
    if (field_id == CST_FID_N_LOADS) {
        return 0;
    }
    if (field_id >= CST_FID_LOAD_ADDR_BASE &&
        field_id < CST_FID_LOAD_ADDR_BASE + CST_FID_SLOT_COUNT) {
        return 1 + (field_id - CST_FID_LOAD_ADDR_BASE);
    }
    if (field_id >= CST_FID_STORE_ADDR_BASE &&
        field_id < CST_FID_STORE_ADDR_BASE + CST_FID_SLOT_COUNT) {
        return 1 + CST_FID_SLOT_COUNT
               + (field_id - CST_FID_STORE_ADDR_BASE);
    }
    if (field_id >= CST_FID_LOAD_DATA_BASE &&
        field_id < CST_FID_LOAD_DATA_BASE + CST_FID_SLOT_COUNT) {
        return 1 + (2 * CST_FID_SLOT_COUNT)
               + (field_id - CST_FID_LOAD_DATA_BASE);
    }
    if (field_id >= CST_FID_STORE_DATA_BASE &&
        field_id < CST_FID_STORE_DATA_BASE + CST_FID_SLOT_COUNT) {
        return 1 + (3 * CST_FID_SLOT_COUNT)
               + (field_id - CST_FID_STORE_DATA_BASE);
    }
    if (field_id >= CST_FID_SRC_REG_BASE &&
        field_id < CST_FID_SRC_REG_BASE + CST_FID_SLOT_COUNT) {
        return 1 + (4 * CST_FID_SLOT_COUNT)
               + (field_id - CST_FID_SRC_REG_BASE);
    }
    if (field_id == CST_FID_N_STORES) {
        return 1 + (5 * CST_FID_SLOT_COUNT);
    }
    if (field_id >= CST_FID_INSN_BYTES_LO &&
        field_id <= CST_FID_INSN_SIZE) {
        return 2 + (5 * CST_FID_SLOT_COUNT)
               + (field_id - CST_FID_INSN_BYTES_LO);
    }
    return FIELD_STATE_SLOT_INVALID;
}

static void field_state_block_free(void * data)
{
    FieldStateBlock *block = (FieldStateBlock *)data;
    if (!block) {
        return;
    }
    g_free(block->values);
    g_free(block->generations);
    g_free(block);
}

static FieldStateTable *field_state_table_new(void)
{
    FieldStateTable *table = g_new0(FieldStateTable, 1);
    table->blocks = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                          nullptr, field_state_block_free);
    table->generation = 1;
    return table;
}

static void field_state_table_free(FieldStateTable *table)
{
    if (!table) {
        return;
    }
    g_hash_table_unref(table->blocks);
    g_free(table);
}

static FieldStateBlock *field_state_table_get_block(FieldStateTable *table,
                                                    uint32_t template_id,
                                                    const BBTemplate *tmpl,
                                                    bool create)
{
    FieldStateBlock *block = (FieldStateBlock *)
        g_hash_table_lookup(table->blocks, GUINT_TO_POINTER(template_id));
    if (block || !create || !tmpl) {
        return block;
    }

    block = g_new0(FieldStateBlock, 1);
    block->n_insns = tmpl->n_insns;
    size_t n_slots = (size_t)block->n_insns * FIELD_STATE_SLOT_COUNT;
    block->values = g_new0(U512, n_slots ? n_slots : 1);
    block->generations = g_new0(uint32_t, n_slots ? n_slots : 1);
    g_hash_table_insert(table->blocks, GUINT_TO_POINTER(template_id), block);
    return block;
}

static inline bool field_state_block_get(FieldStateBlock *block,
                                         uint32_t table_generation,
                                         uint32_t ins_pos,
                                         uint8_t slot_index,
                                         U512 *out)
{
    if (!block || ins_pos >= block->n_insns ||
        slot_index == FIELD_STATE_SLOT_INVALID) {
        return false;
    }
    size_t index = ((size_t)ins_pos * FIELD_STATE_SLOT_COUNT) + slot_index;
    if (block->generations[index] != table_generation) {
        return false;
    }
    *out = block->values[index];
    return true;
}

/*
 * A FieldDescriptor describes one *family* of related field IDs.
 * The emitter walks the descriptor table once per instruction and
 * lets each family produce zero or more (slot, value) observations;
 * every observation that differs from its prior state (or template
 * default) becomes one record on the wire.
 *
 * Adding a new dynamic field family means: add a fresh CST_FID_*
 * constant in champsim_tracer.h, plus one entry in field_descriptors[]
 * with `extract` (writer-side current value) and `template_default`
 * (baseline for first sighting).  The decoder dispatch table in
 * champsim_tracer_decode.py mirrors this 1:1.
 */
struct EntryView {
    const BBTemplate *tmpl;
    const std::vector<DynParam> *dyn_params; /* sorted (insn_index, type) */
    const std::vector<RegSnap>  *reg_snaps;  /* template-walk order        */
    const uint32_t *actual_n_loads;
    const uint32_t *actual_n_stores;
    /* Pre-walked dyn_param index of the first load slot for insn i
     * (length = tmpl->n_insns + 1, last entry = total dyn_params). */
    const uint32_t *insn_dp_off;
    /* Pre-walked reg_snap index of the first src snap for insn i
     * (length = tmpl->n_insns + 1, last entry = total reg_snaps). */
    const uint32_t *insn_rs_off;
    const DynParam **load_slots;
    const DynParam **store_slots;
};

typedef struct EntryView EntryView;

typedef struct {
    uint8_t base_field_id;
    uint8_t slot_count;        /* 1 for non-slotted families */
    bool gated_by_mem_data;
    bool gated_by_reg_data;
    /* extract: returns true and writes *out_val if (ins_pos, slot)
     * has an observable value in this entry; returns false to skip
     * (e.g. unused memop slot). */
    bool (*extract)(const EntryView *ev, uint32_t ins_pos, uint8_t slot,
                    U512 *out_val);
    /* template_default: baseline used on first sighting of
     * (template_id, ins_pos, field_id).  For dynamic-runtime fields
     * (addresses, data, reg values) this is 0; for insn-encoding
     * fields it's the template's static value, so unchanged-from-
     * template fields cost zero record bytes. */
    U512 (*template_default)(const BBTemplate *tmpl,
                             uint32_t ins_pos, uint8_t slot);
    /* runtime_slot_cap: optional callback that returns the actual upper
     * bound on slots-with-content for instruction @i.  Used by the
     * memop and SRC_REG families to skip slots that the fixed
     * slot_count loop would visit only to have extract() return
     * false.  Null for families whose slot_count is the real bound
     * (or trivially 1). */
    uint8_t (*runtime_slot_cap)(const EntryView *ev, uint32_t i);
    const char *name;          /* debug only */
} FieldDescriptor;

/* ---------- Per-family runtime slot caps ----------
 *
 * Memop families (LOAD_ADDR, STORE_ADDR, LOAD_DATA, STORE_DATA) and
 * SRC_REG have CST_FID_SLOT_COUNT (16) wire slots but typical
 * instructions use 0-2 of them.  Iterating the full 16 just to call
 * extract() and have it return false is the dominant per-instruction
 * cost in emit_field_delta_section (~30% of plugin runtime).  These
 * caps let the emitter terminate the slot loop at the actual count. */
static inline uint8_t cap_min(uint32_t v)
{
    return v < CST_FID_SLOT_COUNT ? (uint8_t)v : (uint8_t)CST_FID_SLOT_COUNT;
}
static uint8_t cap_loads(const EntryView *ev, uint32_t i)
{
    return ev->actual_n_loads ? cap_min(ev->actual_n_loads[i]) : 0;
}
static uint8_t cap_stores(const EntryView *ev, uint32_t i)
{
    return ev->actual_n_stores ? cap_min(ev->actual_n_stores[i]) : 0;
}
static uint8_t cap_src_regs(const EntryView *ev, uint32_t i)
{
    if (!ev->tmpl) return 0;
    return ev->tmpl->insn_fields[i].n_src_regs;
}

/* ---------- Per-family extract/default callbacks ---------- */

static bool extr_n_loads(const EntryView *ev, uint32_t i, uint8_t slot,
                         U512 *out)
{
    (void)slot;
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return false;
    *out = cst_wide_from_u64(ev->actual_n_loads[i]);
    return true;
}
static U512 deflt_n_loads(const BBTemplate *t, uint32_t i, uint8_t slot)
{
    (void)t;
    (void)i;
    (void)slot;
    return cst_wide_from_u64(0);
}

static bool extr_n_stores(const EntryView *ev, uint32_t i, uint8_t slot,
                          U512 *out)
{
    (void)slot;
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return false;
    *out = cst_wide_from_u64(ev->actual_n_stores[i]);
    return true;
}
static U512 deflt_n_stores(const BBTemplate *t, uint32_t i, uint8_t slot)
{
    (void)t;
    (void)i;
    (void)slot;
    return cst_wide_from_u64(0);
}

/* Locate the @slot-th memop of @insn matching @want_type
 * (DYN_LOAD_ADDR or DYN_STORE_ADDR).  Returns nullptr if absent. */
static const DynParam *find_memop_slot(const EntryView *ev, uint32_t i,
                                       uint8_t slot, uint8_t want_type)
{
    if (!ev->dyn_params || slot >= CST_FID_SLOT_COUNT) return nullptr;
    size_t idx = ((size_t)i * CST_FID_SLOT_COUNT) + slot;
    if (want_type == DYN_LOAD_ADDR) {
        return ev->load_slots[idx];
    }
    return ev->store_slots[idx];
}

static bool extr_load_addr(const EntryView *ev, uint32_t i, uint8_t slot,
                           U512 *out)
{
    const DynParam *dp = find_memop_slot(ev, i, slot, DYN_LOAD_ADDR);
    if (!dp) return false;
    *out = cst_wide_from_u64(dp->value);
    return true;
}
static bool extr_store_addr(const EntryView *ev, uint32_t i, uint8_t slot,
                            U512 *out)
{
    const DynParam *dp = find_memop_slot(ev, i, slot, DYN_STORE_ADDR);
    if (!dp) return false;
    *out = cst_wide_from_u64(dp->value);
    return true;
}
static U512 deflt_zero(const BBTemplate *t, uint32_t i, uint8_t slot)
{ (void)t; (void)i; (void)slot; return cst_wide_from_u64(0); }

static bool extr_load_data(const EntryView *ev, uint32_t i, uint8_t slot,
                           U512 *out)
{
    const DynParam *dp = find_memop_slot(ev, i, slot, DYN_LOAD_ADDR);
    if (!dp) return false;
    *out = dp->data;
    u512_mask_bytes(out, dp->data_size);
    return true;
}
static bool extr_store_data(const EntryView *ev, uint32_t i, uint8_t slot,
                            U512 *out)
{
    const DynParam *dp = find_memop_slot(ev, i, slot, DYN_STORE_ADDR);
    if (!dp) return false;
    *out = dp->data;
    u512_mask_bytes(out, dp->data_size);
    return true;
}

/* Reg-snap families: the captured reg_snaps array is laid out per-insn
 * source operands only, in template-walk order.  Destination register
 * identities remain in the template but destination values are not emitted
 * from the pre-exec snapshot path. */
static bool extr_src_reg(const EntryView *ev, uint32_t i, uint8_t slot,
                         U512 *out)
{
    if (!ev->reg_snaps || !ev->tmpl) return false;
    const InsnFields *f = &ev->tmpl->insn_fields[i];
    if (slot >= f->n_src_regs) return false;
    uint32_t pos = ev->insn_rs_off[i] + slot;
    if (pos >= ev->reg_snaps->size()) return false;
    *out = (*ev->reg_snaps)[pos].value;
    return true;
}

/* Insn-encoding-mutable families.  The plugin's capture path does not
 * yet observe these (no SMC detector wired up) — extract returns the
 * template's static value, so the delta is always zero and no record
 * is emitted.  When an SMC observer is added later, point extract at
 * the runtime value and keep template_default unchanged. */
static U512 deflt_insn_bytes_lo(const BBTemplate *t, uint32_t i, uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return cst_wide_from_u64(0);
    uint64_t v = 0;
    uint8_t sz = t->insn_sizes[i];
    if (sz > 8) sz = 8;
    const uint8_t *p = &t->insn_bytes[(size_t)i * MAX_INSN_BYTES];
    for (int b = 0; b < sz; b++) v |= ((uint64_t)p[b]) << (b * 8);
    return cst_wide_from_u64(v);
}
static bool extr_insn_bytes_lo(const EntryView *ev, uint32_t i, uint8_t slot,
                               U512 *out)
{ *out = deflt_insn_bytes_lo(ev->tmpl, i, slot); return true; }

static U512 deflt_insn_bytes_hi(const BBTemplate *t, uint32_t i, uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return cst_wide_from_u64(0);
    uint8_t sz = t->insn_sizes[i];
    if (sz <= 8) return cst_wide_from_u64(0);
    uint64_t v = 0;
    const uint8_t *p = &t->insn_bytes[(size_t)i * MAX_INSN_BYTES + 8];
    int extra = sz - 8;
    if (extra > 8) extra = 8;
    for (int b = 0; b < extra; b++) v |= ((uint64_t)p[b]) << (b * 8);
    return cst_wide_from_u64(v);
}
static bool extr_insn_bytes_hi(const EntryView *ev, uint32_t i, uint8_t slot,
                               U512 *out)
{ *out = deflt_insn_bytes_hi(ev->tmpl, i, slot); return true; }

static U512 deflt_insn_opcode(const BBTemplate *t, uint32_t i, uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return cst_wide_from_u64(0);
    return cst_wide_from_u64((uint8_t)t->insn_fields[i].opcode);
}
static bool extr_insn_opcode(const EntryView *ev, uint32_t i, uint8_t slot,
                             U512 *out)
{ *out = deflt_insn_opcode(ev->tmpl, i, slot); return true; }

static U512 deflt_insn_branch_type(const BBTemplate *t, uint32_t i,
                                   uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return cst_wide_from_u64(0);
    return cst_wide_from_u64((uint8_t)t->insn_fields[i].branch_type);
}
static bool extr_insn_branch_type(const EntryView *ev, uint32_t i, uint8_t slot,
                                  U512 *out)
{ *out = deflt_insn_branch_type(ev->tmpl, i, slot); return true; }

static U512 deflt_insn_flags(const BBTemplate *t, uint32_t i, uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return cst_wide_from_u64(0);
    const InsnFields *f = &t->insn_fields[i];
    uint8_t flags = 0;
    if (f->branch_conditional) flags |= CST_INSN_FLAG_BRANCH_COND;
    if (f->has_immediate)      flags |= CST_INSN_FLAG_HAS_IMM;
    flags |= (uint8_t)((f->sync_hint & 0x0F) << CST_INSN_FLAG_SYNC_SHIFT);
    return cst_wide_from_u64(flags);
}
static bool extr_insn_flags(const EntryView *ev, uint32_t i, uint8_t slot,
                            U512 *out)
{ *out = deflt_insn_flags(ev->tmpl, i, slot); return true; }

static U512 deflt_insn_imm(const BBTemplate *t, uint32_t i, uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return cst_wide_from_u64(0);
    const InsnFields *f = &t->insn_fields[i];
    if (!f->has_immediate) return cst_wide_from_u64(0);
    return cst_wide_from_i64((int64_t)f->immediate);
}
static bool extr_insn_imm(const EntryView *ev, uint32_t i, uint8_t slot,
                          U512 *out)
{ *out = deflt_insn_imm(ev->tmpl, i, slot); return true; }

static U512 deflt_insn_size(const BBTemplate *t, uint32_t i, uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return cst_wide_from_u64(0);
    return cst_wide_from_u64(t->insn_sizes[i]);
}
static bool extr_insn_size(const EntryView *ev, uint32_t i, uint8_t slot,
                           U512 *out)
{ *out = deflt_insn_size(ev->tmpl, i, slot); return true; }

/* Field family registry.  Order MUST be ascending by base_field_id so
 * the emitter walks records in (ins_pos, field_id) order. */
static const FieldDescriptor field_descriptors[] = {
        { CST_FID_N_LOADS,          1,  false, false,
            extr_n_loads,        deflt_n_loads,         nullptr,
            "N_LOADS" },
        { CST_FID_LOAD_ADDR_BASE,   CST_FID_SLOT_COUNT, false, false,
            extr_load_addr,      deflt_zero,            cap_loads,
            "LOAD_ADDR" },
        { CST_FID_STORE_ADDR_BASE,  CST_FID_SLOT_COUNT, false, false,
            extr_store_addr,     deflt_zero,            cap_stores,
            "STORE_ADDR" },
        { CST_FID_LOAD_DATA_BASE,   CST_FID_SLOT_COUNT, true,  false,
            extr_load_data,      deflt_zero,            cap_loads,
            "LOAD_DATA" },
        { CST_FID_STORE_DATA_BASE,  CST_FID_SLOT_COUNT, true,  false,
            extr_store_data,     deflt_zero,            cap_stores,
            "STORE_DATA" },
        { CST_FID_SRC_REG_BASE,     CST_FID_SLOT_COUNT, false, true,
            extr_src_reg,        deflt_zero,            cap_src_regs,
            "SRC_REG" },
        { CST_FID_N_STORES,         1,  false, false,
            extr_n_stores,       deflt_n_stores,        nullptr,
            "N_STORES" },
        { CST_FID_INSN_BYTES_LO,    1,  false, false,
            extr_insn_bytes_lo,  deflt_insn_bytes_lo,   nullptr,
            "INSN_BYTES_LO" },
        { CST_FID_INSN_BYTES_HI,    1,  false, false,
            extr_insn_bytes_hi,  deflt_insn_bytes_hi,   nullptr,
            "INSN_BYTES_HI" },
        { CST_FID_INSN_OPCODE,      1,  false, false,
            extr_insn_opcode,    deflt_insn_opcode,     nullptr,
            "OPCODE" },
        { CST_FID_INSN_BRANCH_TYPE, 1,  false, false,
            extr_insn_branch_type, deflt_insn_branch_type, nullptr,
            "BRANCH_TYPE" },
        { CST_FID_INSN_FLAGS,       1,  false, false,
            extr_insn_flags,     deflt_insn_flags,      nullptr,
            "INSN_FLAGS" },
        { CST_FID_INSN_IMMEDIATE,   1,  false, false,
            extr_insn_imm,       deflt_insn_imm,        nullptr,
            "IMMEDIATE" },
        { CST_FID_INSN_SIZE,        1,  false, false,
            extr_insn_size,      deflt_insn_size,       nullptr,
            "INSN_SIZE" },
};

#define N_FIELD_DESCRIPTORS (sizeof(field_descriptors) / sizeof(field_descriptors[0]))

/* Sort dyn_params so each insn's loads precede its stores, matching
 * the slot indexing used by find_memop_slot(). */
static void dyn_params_sort_template_order(std::vector<DynParam> &dyn_params)
{
    if (dyn_params.size() < 2) return;
    std::sort(dyn_params.begin(), dyn_params.end(),
              [](const DynParam &a, const DynParam &b) {
                  if (a.insn_index != b.insn_index) {
                      return a.insn_index < b.insn_index;
                  }
                  return a.type < b.type;
              });
}

/* Build per-insn offset arrays into dyn_params and reg_snaps so
 * descriptor extracts run in O(1) per slot. */
static void build_entry_view(EntryView *ev, const BBTemplate *tmpl,
                             const std::vector<DynParam> *dyn_params,
                             const std::vector<RegSnap> *reg_snaps,
                             uint32_t *actual_n_loads,
                             uint32_t *actual_n_stores,
                             uint32_t *insn_dp_off,
                             uint32_t *insn_rs_off,
                             const DynParam **load_slots,
                             const DynParam **store_slots)
{
    ev->tmpl = tmpl;
    ev->dyn_params = dyn_params;
    ev->reg_snaps = reg_snaps;
    ev->actual_n_loads = actual_n_loads;
    ev->actual_n_stores = actual_n_stores;
    ev->insn_dp_off = insn_dp_off;
    ev->insn_rs_off = insn_rs_off;
    ev->load_slots = load_slots;
    ev->store_slots = store_slots;

    if (!tmpl) return;

    uint32_t n = tmpl->n_insns;
    /* Walk dyn_params (already sorted by insn_index, type) once. */
    uint32_t k = 0;
    uint32_t total_dp = dyn_params ? (uint32_t)dyn_params->size() : 0;
    for (uint32_t i = 0; i < n; i++) {
        actual_n_loads[i] = 0;
        actual_n_stores[i] = 0;
        insn_dp_off[i] = k;
        while (k < total_dp) {
            const DynParam *dp = &(*dyn_params)[k];
            if (dp->insn_index != i) break;
            if (dp->type == DYN_LOAD_ADDR) {
                uint32_t slot = actual_n_loads[i]++;
                if (slot < CST_FID_SLOT_COUNT) {
                    load_slots[(size_t)i * CST_FID_SLOT_COUNT + slot] = dp;
                }
            } else {
                uint32_t slot = actual_n_stores[i]++;
                if (slot < CST_FID_SLOT_COUNT) {
                    store_slots[(size_t)i * CST_FID_SLOT_COUNT + slot] = dp;
                }
            }
            k++;
        }
    }
    insn_dp_off[n] = k;

    /* Reg_snaps: per-insn source operands only, in template-walk order. */
    uint32_t r = 0;
    for (uint32_t i = 0; i < n; i++) {
        insn_rs_off[i] = r;
        const InsnFields *f = &tmpl->insn_fields[i];
        r += f->n_src_regs;
    }
    insn_rs_off[n] = r;
}

static void entry_view_scratch_ensure(EntryViewScratch *scratch, uint32_t n)
{
    uint32_t need_n = n ? n : 1;
    if (scratch->n_cap < need_n) {
        uint32_t new_cap = scratch->n_cap ? scratch->n_cap : 16;
        while (new_cap < need_n) {
            new_cap *= 2;
        }
        scratch->actual_n_loads = g_renew(uint32_t,
                                          scratch->actual_n_loads,
                                          new_cap);
        scratch->actual_n_stores = g_renew(uint32_t,
                                           scratch->actual_n_stores,
                                           new_cap);
        scratch->insn_dp_off = g_renew(uint32_t,
                                       scratch->insn_dp_off,
                                       (size_t)new_cap + 1);
        scratch->insn_rs_off = g_renew(uint32_t,
                                       scratch->insn_rs_off,
                                       (size_t)new_cap + 1);
        scratch->n_cap = new_cap;
    }

    size_t need_slots = (size_t)need_n * CST_FID_SLOT_COUNT;
    if (scratch->slot_cap < need_slots) {
        size_t new_cap = scratch->slot_cap ? scratch->slot_cap :
            (16 * CST_FID_SLOT_COUNT);
        while (new_cap < need_slots) {
            new_cap *= 2;
        }
        scratch->load_slots = g_renew(const DynParam *,
                                      scratch->load_slots, new_cap);
        scratch->store_slots = g_renew(const DynParam *,
                                       scratch->store_slots, new_cap);
        scratch->slot_cap = new_cap;
    }

    memset(scratch->load_slots, 0, need_slots *
           sizeof(*scratch->load_slots));
    memset(scratch->store_slots, 0, need_slots *
           sizeof(*scratch->store_slots));
}

static void entry_view_scratch_free(EntryViewScratch *scratch)
{
    g_free(scratch->actual_n_loads);
    g_free(scratch->actual_n_stores);
    g_free(scratch->insn_dp_off);
    g_free(scratch->insn_rs_off);
    g_free(scratch->load_slots);
    g_free(scratch->store_slots);
    memset(scratch, 0, sizeof(*scratch));
}

/* Look up baseline value for (template_id, ins_pos, field_id).  Falls
 * back to the descriptor's template_default if no prior observation. */
static U512 field_state_get(FieldStateBlock *state_block,
                            uint32_t state_generation,
                            FieldStateBlock *base_block,
                            uint32_t base_generation,
                            uint32_t ins_pos,
                            uint8_t field_id,
                            const FieldDescriptor *fd,
                            const BBTemplate *tmpl,
                            uint8_t slot)
{
    U512 cur;
    uint8_t slot_index = field_state_slot_index(field_id);
    if (field_state_block_get(state_block, state_generation, ins_pos,
                              slot_index, &cur)) {
        return cur;
    }

    if (field_state_block_get(base_block, base_generation, ins_pos,
                              slot_index, &cur)) {
        return cur;
    }
    return fd->template_default(tmpl, ins_pos, slot);
}

static void field_state_put(FieldStateBlock *state_block,
                            uint32_t state_generation,
                            uint32_t ins_pos,
                            uint8_t field_id,
                            U512 v)
{
    uint8_t slot_index = field_state_slot_index(field_id);
    if (!state_block || ins_pos >= state_block->n_insns ||
        slot_index == FIELD_STATE_SLOT_INVALID) {
        return;
    }
    size_t index = ((size_t)ins_pos * FIELD_STATE_SLOT_COUNT) + slot_index;
    state_block->values[index] = v;
    state_block->generations[index] = state_generation;
}

typedef enum StageRecKind {
    STAGE_REC_SCALAR,
    STAGE_REC_VECTOR,
} StageRecKind;

typedef struct StageRec {
    uint32_t pos;
    uint8_t fid;
    StageRecKind kind;
    U512 delta;
} StageRec;

static void stage_rec_append(StageRec **stage, unsigned int *stage_len,
                             unsigned int *stage_cap, StageRec rec)
{
    if (*stage_len == *stage_cap) {
        *stage_cap *= 2;
        *stage = (StageRec *)g_realloc_n(*stage, *stage_cap,
                                         sizeof(**stage));
    }
    (*stage)[(*stage_len)++] = rec;
}

static void stage_extra_memop_vectors(StageRec **stage, unsigned int *stage_len,
                                      unsigned int *stage_cap, const EntryView *ev,
                                      uint32_t i, uint8_t header_flags)
{
    if (!ev->actual_n_loads || !ev->actual_n_stores) {
        return;
    }
    bool has_mem_data = (header_flags & CST_FLAG_MEM_DATA) != 0;
    if (ev->actual_n_loads[i] > CST_FID_SLOT_COUNT) {
        StageRec rec = {};
        rec.pos = i;
        rec.fid = CST_FID_EXTRA_LOAD_ADDR;
        rec.kind = STAGE_REC_VECTOR;
        stage_rec_append(stage, stage_len, stage_cap,
                         rec);
    }
    if (ev->actual_n_stores[i] > CST_FID_SLOT_COUNT) {
        StageRec rec = {};
        rec.pos = i;
        rec.fid = CST_FID_EXTRA_STORE_ADDR;
        rec.kind = STAGE_REC_VECTOR;
        stage_rec_append(stage, stage_len, stage_cap,
                         rec);
    }
    if (has_mem_data && ev->actual_n_loads[i] > CST_FID_SLOT_COUNT) {
        StageRec rec = {};
        rec.pos = i;
        rec.fid = CST_FID_EXTRA_LOAD_DATA;
        rec.kind = STAGE_REC_VECTOR;
        stage_rec_append(stage, stage_len, stage_cap,
                         rec);
    }
    if (has_mem_data && ev->actual_n_stores[i] > CST_FID_SLOT_COUNT) {
        StageRec rec = {};
        rec.pos = i;
        rec.fid = CST_FID_EXTRA_STORE_DATA;
        rec.kind = STAGE_REC_VECTOR;
        stage_rec_append(stage, stage_len, stage_cap,
                         rec);
    }
}

static uint32_t extra_memop_count(const EntryView *ev, uint32_t i,
                                  uint8_t want_type)
{
    uint32_t total = want_type == DYN_LOAD_ADDR
        ? ev->actual_n_loads[i]
        : ev->actual_n_stores[i];
    return total > CST_FID_SLOT_COUNT ? total - CST_FID_SLOT_COUNT : 0;
}

static void bw_write_extra_memop_vector(BitWriter *bw, const EntryView *ev,
                                        uint32_t i, uint8_t fid)
{
    uint8_t want_type;
    bool want_data;

    switch (fid) {
    case CST_FID_EXTRA_LOAD_ADDR:
        want_type = DYN_LOAD_ADDR;
        want_data = false;
        break;
    case CST_FID_EXTRA_STORE_ADDR:
        want_type = DYN_STORE_ADDR;
        want_data = false;
        break;
    case CST_FID_EXTRA_LOAD_DATA:
        want_type = DYN_LOAD_ADDR;
        want_data = true;
        break;
    case CST_FID_EXTRA_STORE_DATA:
        want_type = DYN_STORE_ADDR;
        want_data = true;
        break;
    default:
        g_assert_not_reached();
    }

    uint32_t extra = extra_memop_count(ev, i, want_type);
    bw_write_uleb128(bw, extra);
    if (extra == 0 || !ev->dyn_params || !ev->insn_dp_off) {
        return;
    }

    uint32_t seen = 0;
    uint32_t written = 0;
    uint32_t begin = ev->insn_dp_off[i];
    uint32_t end = ev->insn_dp_off[i + 1];
    for (uint32_t k = begin; k < end && written < extra; k++) {
        const DynParam *dp = &(*ev->dyn_params)[k];
        if (dp->type != want_type) {
            continue;
        }
        if (seen++ < CST_FID_SLOT_COUNT) {
            continue;
        }
        if (want_data) {
            U512 data = dp->data;
            u512_mask_bytes(&data, dp->data_size);
            bw_write_uleb128_u512(bw, data);
        } else {
            bw_write_uleb128(bw, dp->value);
        }
        written++;
    }

    while (written++ < extra) {
        bw_write_uleb128(bw, 0);
    }
}

/*
 * The single emitter.  Walks the template insn-by-insn; for each insn,
 * walks the descriptor table; for each (descriptor, slot), pulls the
 * current value and emits a record iff it differs from the prior
 * observation (or template default on first sighting).
 *
 * The (ins_pos, field_id) wire ordering is a natural consequence of
 * the loop nesting (insn outer, descriptor table inner ascending,
 * slot inner ascending) — no sort needed.
 */
static void emit_field_delta_section(BitWriter *main_bw,
                                     FieldStateTable *state,
                                     FieldStateTable *base_state,
                                     uint32_t template_id,
                                     const EntryView *ev,
                                     bool is_wp,
                                     uint8_t header_flags)
{
    BitWriter rec_bw;
    bw_init_buf(&rec_bw);

    /* Buffer records into a small staging vec so the ULEB record count can
     * precede the payload without a second descriptor walk. */
    unsigned int stage_len = 0;
    unsigned int stage_cap = 16;
    g_autofree StageRec *stage = g_new(StageRec, stage_cap);

    uint32_t prev_pos = 0;
    if (ev->tmpl) {
        FieldStateBlock *state_block =
            field_state_table_get_block(state, template_id, ev->tmpl, true);
        FieldStateBlock *base_block = base_state ?
            field_state_table_get_block(base_state, template_id, ev->tmpl,
                                        false) : nullptr;
        uint32_t state_generation = state->generation;
        uint32_t base_generation = base_state ? base_state->generation : 0;

        for (uint32_t i = 0; i < ev->tmpl->n_insns; i++) {
            for (size_t d = 0; d < N_FIELD_DESCRIPTORS; d++) {
                const FieldDescriptor *fd = &field_descriptors[d];
                if (fd->gated_by_mem_data && !(header_flags & CST_FLAG_MEM_DATA))
                    continue;
                if (fd->gated_by_reg_data && !(header_flags & CST_FLAG_REG_DATA))
                    continue;

                uint8_t cap = fd->runtime_slot_cap
                    ? fd->runtime_slot_cap(ev, i)
                    : fd->slot_count;
                for (uint8_t slot = 0; slot < cap; slot++) {
                    U512 cur;
                    if (!fd->extract(ev, i, slot, &cur)) continue;
                    uint8_t fid = fd->base_field_id + slot;
                    U512 base =
                        field_state_get(state_block, state_generation,
                                        base_block, base_generation,
                                        i, fid, fd, ev->tmpl, slot);
                    if (u512_equal(cur, base)) continue;
                    StageRec rec = {};
                    rec.pos = i;
                    rec.fid = fid;
                    rec.kind = STAGE_REC_SCALAR;
                    rec.delta = u512_sub(cur, base);
                    stage_rec_append(&stage, &stage_len, &stage_cap, rec);
                    field_state_put(state_block, state_generation, i, fid, cur);
                }
                if (fd->base_field_id == CST_FID_N_STORES) {
                    stage_extra_memop_vectors(&stage, &stage_len, &stage_cap,
                                              ev, i, header_flags);
                }
            }
        }
    }

    uint64_t section_start = bw_tell_bytes(main_bw);

    /* Build payload in rec_bw, then emit as length-prefixed section. */
    bw_write_uleb128(&rec_bw, stage_len);
    for (unsigned int r = 0; r < stage_len; r++) {
        StageRec *s = &stage[r];
        uint64_t gap = (uint64_t)(s->pos - prev_pos);
        bw_write_uleb128(&rec_bw, gap);
        bw_write_u8(&rec_bw, s->fid);
        if (s->kind == STAGE_REC_VECTOR) {
            bw_write_extra_memop_vector(&rec_bw, ev, s->pos, s->fid);
        } else {
            bw_write_sleb128_u512(&rec_bw, s->delta);
        }
        prev_pos = s->pos;
    }
    bw_byte_align(&rec_bw);
    bw_write_section(main_bw, bw_finish_buf(&rec_bw));

    uint64_t bits = (bw_tell_bytes(main_bw) - section_start) * 8;
    if (is_wp) g_stats.bin_dyn_wp_bits += bits;
    else       g_stats.bin_dyn_cp_bits += bits;
}

/* ========================= Body stream ========================= */

BodyStreamState *body_stream_new(WriterCtx *w, const char *seg_datetime)
{
    BodyStreamState *st = g_new0(BodyStreamState, 1);

    bw_init_writer(&st->bw, w);

    bw_write_u32_le(&st->bw, CST_MAGIC);
    bw_write_u8(&st->bw, (uint8_t)trace_isa);

    uint8_t flags = 0;
    if (enable_mem_data) {
        flags |= CST_FLAG_MEM_DATA;
    }
    if (enable_reg_data) {
        flags |= CST_FLAG_REG_DATA;
    }
    bw_write_u8(&st->bw, flags);
    st->header_flags = flags;

    {
        const char *cmd = qemu_command_line ? qemu_command_line : "";
        size_t len = strlen(cmd);
        bw_write_uleb128(&st->bw, len);
        bw_write_bytes(&st->bw, (const uint8_t *)cmd, len);
    }
    {
        const char *dt_str = (seg_datetime && *seg_datetime) ? seg_datetime : "";
        size_t len = strlen(dt_str);
        bw_write_uleb128(&st->bw, len);
        bw_write_bytes(&st->bw, (const uint8_t *)dt_str, len);
    }
    {
        const char *comment = trace_comment ? trace_comment : "";
        size_t len = strlen(comment);
        bw_write_uleb128(&st->bw, len);
        bw_write_bytes(&st->bw, (const uint8_t *)comment, len);
    }
    {
        const char *tname = target_name ? target_name : "";
        size_t len = strlen(tname);
        bw_write_uleb128(&st->bw, len);
        bw_write_bytes(&st->bw, (const uint8_t *)tname, len);
    }

    write_header_encoding_maps(&st->bw);

    bw_byte_align(&st->bw);
    bw_flush(&st->bw);
    /* Use BitWriter's running byte count rather than ftello() so the
     * writer works on non-seekable streams (e.g. popen() pipes used
     * for streaming compression). */
    st->body_off = bw_tell_bytes(&st->bw);

    st->current_thread = 0;

    st->cp_field_state = field_state_table_new();
    st->wp_field_state = field_state_table_new();

    return st;
}

/*
 * v1.8: build an EntryView wrapping the captured per-entry data and
 * emit one length-prefixed delta_section.  The descriptor table in
 * field_descriptors[] is the single source of truth for which fields
 * exist on the wire and how each is reconstructed.
 */
static void emit_one_bb_delta_with_base(BitWriter *bw, BodyStreamState *st,
                                        FieldStateTable *state,
                                        FieldStateTable *base_state,
                                        uint32_t template_id,
                                        const BBTemplate *tmpl,
                                        const std::vector<DynParam> *dyn_params,
                                        const std::vector<RegSnap> *reg_snaps,
                                        bool is_wp);

static void emit_one_bb_delta(BitWriter *bw, BodyStreamState *st,
                              FieldStateTable *state, uint32_t template_id,
                              const BBTemplate *tmpl,
                              const std::vector<DynParam> *dyn_params,
                              const std::vector<RegSnap> *reg_snaps,
                              bool is_wp)
{
    emit_one_bb_delta_with_base(bw, st, state, nullptr, template_id,
                                tmpl, dyn_params, reg_snaps, is_wp);
}

static void emit_one_bb_delta_with_base(BitWriter *bw, BodyStreamState *st,
                                        FieldStateTable *state,
                                        FieldStateTable *base_state,
                                        uint32_t template_id,
                                        const BBTemplate *tmpl,
                                        const std::vector<DynParam> *dyn_params,
                                        const std::vector<RegSnap> *reg_snaps,
                                        bool is_wp)
{
    EntryView ev;
    uint32_t n = tmpl ? tmpl->n_insns : 0;
    EntryViewScratch *scratch = &st->ev_scratch;
    entry_view_scratch_ensure(scratch, n);
    build_entry_view(&ev, tmpl, dyn_params, reg_snaps,
                     scratch->actual_n_loads,
                     scratch->actual_n_stores,
                     scratch->insn_dp_off,
                     scratch->insn_rs_off,
                     scratch->load_slots,
                     scratch->store_slots);
    emit_field_delta_section(bw, state, base_state, template_id, &ev, is_wp,
                             st->header_flags);
}

void body_stream_write_entry(BodyStreamState *st, BodyEntry *entry)
{
    int64_t entry_tmpl = entry->template_id;
    uint32_t num_wp = (uint32_t)entry->wp_entries.size();
    uint64_t body_start = bw_tell_bytes(&st->bw);

    dyn_params_sort_template_order(entry->dyn_params);
    for (uint32_t w = 0; w < num_wp; w++) {
        WPBBEntry &wp = entry->wp_entries[w];
        dyn_params_sort_template_order(wp.dyn_params);
    }

    if ((int64_t)entry->thread_id != st->current_thread) {
        bw_write_u8(&st->bw, BODY_TAG_THREAD_SWITCH);
        bw_write_sleb128(&st->bw,
                         (int64_t)entry->thread_id - st->current_thread);
        st->current_thread = entry->thread_id;
    }

    bw_write_u8(&st->bw, BODY_TAG_ENTRY);
    bw_write_sleb128(&st->bw, entry_tmpl - st->prev_entry_template);
    st->prev_entry_template = entry_tmpl;

    emit_one_bb_delta(&st->bw, st, st->cp_field_state, entry->template_id,
                      entry->tmpl, &entry->dyn_params, &entry->reg_snaps,
                      false);

    /* WP chain sub-section */
    {
        BitWriter sub;
        bw_init_buf(&sub);
        bw_write_uleb128(&sub, num_wp);
        int64_t prev_wp_template = 0;
        /* v1.9: WP overlay accumulates across the whole body stream
         * like cp_field_state.  Repeat WP visits of the same template
         * (very common for shared library code) delta against the
         * prior WP observation instead of falling back to CP every
         * chain — typically 3x smaller traces on real workloads.
         * Fallback chain is unchanged: lookup WP overlay first,
         * then CP overlay, then template_default. */
        for (uint32_t w = 0; w < num_wp; w++) {
            const WPBBEntry *wp = &entry->wp_entries[w];
            uint32_t wp_tmpl = wp->template_id;
            bw_write_sleb128(&sub, (int64_t)wp_tmpl - prev_wp_template);
            prev_wp_template = wp_tmpl;
            emit_one_bb_delta_with_base(&sub, st, st->wp_field_state,
                                        st->cp_field_state, wp_tmpl,
                                        wp->tmpl, &wp->dyn_params,
                                        &wp->reg_snaps, true);
        }
        bw_byte_align(&sub);
        bw_write_section(&st->bw, bw_finish_buf(&sub));
    }

    /* WP events sub-section */
    {
        uint32_t num_events = 0;
        for (uint32_t w = 0; w < num_wp; w++) {
            const WPBBEntry *wp = &entry->wp_entries[w];
            if (wp->fault || wp->translation_unavailable) {
                num_events++;
            }
        }

        BitWriter sub;
        bw_init_buf(&sub);
        bw_write_uleb128(&sub, num_events);

        int64_t prev_event_idx = -1;
        uint64_t ev_start = bw_tell_bytes(&sub);
        for (uint32_t w = 0; w < num_wp; w++) {
            const WPBBEntry *wp = &entry->wp_entries[w];
            if (!wp->fault && !wp->translation_unavailable) {
                continue;
            }
            bw_write_uleb128(&sub,
                (uint64_t)(w - (uint32_t)(prev_event_idx + 1)));
            uint8_t evf = 0;
            if (wp->translation_unavailable) {
                evf |= CST_WP_EVENT_TRANSLATION_UNAVAIL;
            }
            if (wp->fault) {
                evf |= CST_WP_EVENT_FAULT;
            }
            bw_write_u8(&sub, evf);
            /* Emit the chain-relative index of the faulting instruction so
             * consumers can flag that specific uop as non-completing. */
            if (wp->fault) {
                bw_write_uleb128(&sub, (uint64_t)wp->fault_insn_index);
            }
            prev_event_idx = w;
        }
        g_stats.bin_wp_exception_bits += (bw_tell_bytes(&sub) - ev_start) * 8;

        bw_byte_align(&sub);
        bw_write_section(&st->bw, bw_finish_buf(&sub));
    }

    bw_byte_align(&st->bw);

    st->num_entries++;
    g_stats.bin_body_bits += (bw_tell_bytes(&st->bw) - body_start) * 8;
}

/*
 * Finish the body stream: end-of-body sentinel, mandatory template
 * section, and a fixed 64-byte trailer.
 *
 * Trailer layout (all u64 little-endian):
 *   templates_off    : file offset of templates section
 *   templates_count  : number of templates
 *   body_off         : file offset where body stream starts
 *   body_byte_count  : bytes from body_off up to end of last body record
 *   trailer_magic    : CST_TRAILER_MAGIC
 *   zero padding up to 64 bytes
 */
void body_stream_finish(BodyStreamState *st)
{
    uint64_t stats_start = bw_tell_bytes(&st->bw);

    bw_write_u8(&st->bw, BODY_TAG_END);
    bw_write_uleb128(&st->bw, st->num_entries);
    bw_byte_align(&st->bw);
    bw_flush(&st->bw);

    /* Pipe-friendly: trust the BitWriter's running counter rather than
     * calling ftello() (which fails on non-seekable streams). */
    uint64_t body_end = bw_tell_bytes(&st->bw);
    uint64_t body_byte_count = body_end - st->body_off;

    uint64_t templates_off = body_end;
    uint64_t templates_count = 0;

    g_mutex_lock(&data_lock);
    templates_count = g_bb_template_cache.bb_count();
    write_bin_templates(&st->bw);
    g_mutex_unlock(&data_lock);
    bw_byte_align(&st->bw);
    bw_flush(&st->bw);

    uint64_t tr_start = bw_tell_bytes(&st->bw);
    bw_write_u64_le(&st->bw, templates_off);
    bw_write_u64_le(&st->bw, templates_count);
    bw_write_u64_le(&st->bw, st->body_off);
    bw_write_u64_le(&st->bw, body_byte_count);
    bw_write_u64_le(&st->bw, CST_TRAILER_MAGIC);
    uint64_t trailer_written = bw_tell_bytes(&st->bw) - tr_start;
    g_assert(trailer_written <= CST_TRAILER_SIZE);
    {
        uint8_t zero[CST_TRAILER_SIZE] = {0};
        bw_write_bytes(&st->bw, zero,
                       (size_t)(CST_TRAILER_SIZE - trailer_written));
    }
    bw_flush(&st->bw);

    uint64_t end_bytes = bw_tell_bytes(&st->bw);
    g_stats.bin_header_bits += (end_bytes - stats_start) * 8;
    g_stats.bin_total_bits += end_bytes * 8;

    field_state_table_free(st->cp_field_state);
    field_state_table_free(st->wp_field_state);
    entry_view_scratch_free(&st->ev_scratch);
}
