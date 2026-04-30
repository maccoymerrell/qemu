/*
 * Wrong-Path Tracing Plugin - binary format v1.7 writer.
 *
 * BitWriter primitives, template dictionary serializer, dyn-param
 * patch emitter, body entry streamer, and trailer writer for the
 * packed binary (.cst) format.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <inttypes.h>
#include <string.h>

#include "champsim_tracer.h"
#include "champsim_tracer_writer.h"

/* ========================= BitWriter primitives ========================= */

static inline void bw_init_writer(BitWriter *bw, WriterCtx *w)
{
    bw->f = NULL;
    bw->buf = NULL;
    bw->w = w;
    bw->total_bytes = 0;
}

static inline void bw_init_file(BitWriter *bw, FILE *f)
{
    bw->f = f;
    bw->buf = NULL;
    bw->w = NULL;
    bw->total_bytes = 0;
}

static inline void bw_init_buf(BitWriter *bw)
{
    bw->f = NULL;
    bw->buf = g_byte_array_new();
    bw->w = NULL;
    bw->total_bytes = 0;
}

static inline GByteArray *bw_finish_buf(BitWriter *bw)
{
    GByteArray *out = bw->buf;
    bw->buf = NULL;
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
        g_byte_array_append(bw->buf, buf, (guint)len);
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
 * Same as bw_write_sleb128 but accepts a signed 128-bit value.
 * Used for reg-data and mem-data deltas, where 16-byte snapshots
 * (XMM-class regs, 16-byte memops) require >64 bits of dynamic
 * range.  Max encoded length is 19 bytes (⌈128/7⌉).
 */
static void bw_write_sleb128_i128(BitWriter *bw, __int128 v)
{
    uint8_t buf[19];
    size_t n = 0;
    bool more = true;
    while (more) {
        uint8_t byte = (uint8_t)((unsigned __int128)v & 0x7F);
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
    bw_write_string(bw, "reg");
    bw_write_uleb128(bw, 251);
    write_encoding_entry(bw, REG_NONE, "REG_NONE");
    for (uint64_t i = 0; i < 64; i++) {
        g_autofree char *name = g_strdup_printf("REG_GPR%" PRIu64, i);
        write_encoding_entry(bw, REG_GPR0 + i, name);
    }
    for (uint64_t i = 0; i < 64; i++) {
        g_autofree char *name = g_strdup_printf("REG_FPR%" PRIu64, i);
        write_encoding_entry(bw, REG_FPR0 + i, name);
    }
    for (uint64_t i = 0; i < 64; i++) {
        g_autofree char *name = g_strdup_printf("REG_VEC%" PRIu64, i);
        write_encoding_entry(bw, REG_VEC0 + i, name);
    }
    for (uint64_t i = 0; i < 32; i++) {
        g_autofree char *name = g_strdup_printf("REG_PRED%" PRIu64, i);
        write_encoding_entry(bw, REG_PRED0 + i, name);
    }
    for (uint64_t i = 0; i < 6; i++) {
        g_autofree char *name = g_strdup_printf("REG_SEG%" PRIu64, i);
        write_encoding_entry(bw, REG_SEG0 + i, name);
    }
    static const EncodingMapEntry special_regs[] = {
        { REG_CTRL, "REG_CTRL" },
        { REG_DEBUG, "REG_DEBUG" },
        { REG_BOUND0, "REG_BOUND0" },
        { REG_BOUND1, "REG_BOUND1" },
        { REG_BOUND2, "REG_BOUND2" },
        { REG_BOUND3, "REG_BOUND3" },
        { REG_ACC0, "REG_ACC0" },
        { REG_ACC1, "REG_ACC1" },
        { REG_ACC2, "REG_ACC2" },
        { REG_ACC3, "REG_ACC3" },
        { REG_ZERO, "REG_ZERO" },
        { REG_MATRIX, "REG_MATRIX" },
        { REG_SYS, "REG_SYS" },
        { REG_FCSR, "REG_FCSR" },
        { REG_VCTRL, "REG_VCTRL" },
        { REG_SP, "REG_SP" },
        { REG_FLAGS, "REG_FLAGS" },
        { REG_IP, "REG_IP" },
        { REG_LR, "REG_LR" },
        { REG_FP_REG, "REG_FP_REG" },
    };
    for (size_t i = 0; i < G_N_ELEMENTS(special_regs); i++) {
        write_encoding_entry(bw, special_regs[i].value, special_regs[i].name);
    }
}

static void write_field_id_encoding_map(BitWriter *bw)
{
    bw_write_string(bw, "field_id");
    bw_write_uleb128(bw, 90);
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

static void write_header_encoding_maps(BitWriter *main_bw)
{
    static const EncodingMapEntry opcode_entries[] = {
        { GEN_OP_UNKNOWN, "GEN_OP_UNKNOWN" },
        { GEN_OP_INT_ADD, "GEN_OP_INT_ADD" },
        { GEN_OP_INT_SUB, "GEN_OP_INT_SUB" },
        { GEN_OP_INT_MUL, "GEN_OP_INT_MUL" },
        { GEN_OP_INT_DIV, "GEN_OP_INT_DIV" },
        { GEN_OP_AND, "GEN_OP_AND" },
        { GEN_OP_OR, "GEN_OP_OR" },
        { GEN_OP_XOR, "GEN_OP_XOR" },
        { GEN_OP_NOT, "GEN_OP_NOT" },
        { GEN_OP_SHL, "GEN_OP_SHL" },
        { GEN_OP_SHR, "GEN_OP_SHR" },
        { GEN_OP_SAR, "GEN_OP_SAR" },
        { GEN_OP_ROL, "GEN_OP_ROL" },
        { GEN_OP_ROR, "GEN_OP_ROR" },
        { GEN_OP_MOV, "GEN_OP_MOV" },
        { GEN_OP_LOAD, "GEN_OP_LOAD" },
        { GEN_OP_STORE, "GEN_OP_STORE" },
        { GEN_OP_PUSH, "GEN_OP_PUSH" },
        { GEN_OP_POP, "GEN_OP_POP" },
        { GEN_OP_LEA, "GEN_OP_LEA" },
        { GEN_OP_MOVSX, "GEN_OP_MOVSX" },
        { GEN_OP_MOVZX, "GEN_OP_MOVZX" },
        { GEN_OP_XCHG, "GEN_OP_XCHG" },
        { GEN_OP_CMP, "GEN_OP_CMP" },
        { GEN_OP_TEST, "GEN_OP_TEST" },
        { GEN_OP_BRANCH, "GEN_OP_BRANCH" },
        { GEN_OP_RET, "GEN_OP_RET" },
        { GEN_OP_FP_ADD, "GEN_OP_FP_ADD" },
        { GEN_OP_FP_SUB, "GEN_OP_FP_SUB" },
        { GEN_OP_FP_MUL, "GEN_OP_FP_MUL" },
        { GEN_OP_FP_DIV, "GEN_OP_FP_DIV" },
        { GEN_OP_FP_SQRT, "GEN_OP_FP_SQRT" },
        { GEN_OP_FP_MOV, "GEN_OP_FP_MOV" },
        { GEN_OP_FP_CVT, "GEN_OP_FP_CVT" },
        { GEN_OP_FP_CMP, "GEN_OP_FP_CMP" },
        { GEN_OP_VEC_ADD, "GEN_OP_VEC_ADD" },
        { GEN_OP_VEC_SUB, "GEN_OP_VEC_SUB" },
        { GEN_OP_VEC_MUL, "GEN_OP_VEC_MUL" },
        { GEN_OP_VEC_MOV, "GEN_OP_VEC_MOV" },
        { GEN_OP_VEC_SHUF, "GEN_OP_VEC_SHUF" },
        { GEN_OP_VEC_LOGIC, "GEN_OP_VEC_LOGIC" },
        { GEN_OP_NOP, "GEN_OP_NOP" },
        { GEN_OP_SYSCALL, "GEN_OP_SYSCALL" },
        { GEN_OP_FENCE, "GEN_OP_FENCE" },
        { GEN_OP_CMOV, "GEN_OP_CMOV" },
        { GEN_OP_SETCC, "GEN_OP_SETCC" },
        { GEN_OP_INT_ADC, "GEN_OP_INT_ADC" },
        { GEN_OP_INT_SBB, "GEN_OP_INT_SBB" },
        { GEN_OP_NEG, "GEN_OP_NEG" },
        { GEN_OP_INC, "GEN_OP_INC" },
        { GEN_OP_DEC, "GEN_OP_DEC" },
        { GEN_OP_INT_MADD, "GEN_OP_INT_MADD" },
        { GEN_OP_INT_MSUB, "GEN_OP_INT_MSUB" },
        { GEN_OP_FP_MADD, "GEN_OP_FP_MADD" },
        { GEN_OP_FP_MSUB, "GEN_OP_FP_MSUB" },
        { GEN_OP_VEC_MADD, "GEN_OP_VEC_MADD" },
        { GEN_OP_VEC_MSUB, "GEN_OP_VEC_MSUB" },
    };
    static const EncodingMapEntry branch_entries[] = {
        { BRANCH_NONE, "BRANCH_NONE" },
        { BRANCH_DIRECT_JUMP, "BRANCH_DIRECT_JUMP" },
        { BRANCH_INDIRECT_JUMP, "BRANCH_INDIRECT_JUMP" },
        { BRANCH_RETURN, "BRANCH_RETURN" },
        { BRANCH_SYSCALL_TYPE, "BRANCH_SYSCALL_TYPE" },
        { BRANCH_COND_DIRECT, "BRANCH_COND_DIRECT" },
    };
    static const EncodingMapEntry sync_entries[] = {
        { SYNC_NONE, "SYNC_NONE" },
        { SYNC_THREAD_SWITCH, "SYNC_THREAD_SWITCH" },
        { SYNC_ATOMIC, "SYNC_ATOMIC" },
    };
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
    write_encoding_map(&sub, "opcode", opcode_entries,
                       G_N_ELEMENTS(opcode_entries));
    write_encoding_map(&sub, "branch_type", branch_entries,
                       G_N_ELEMENTS(branch_entries));
    write_encoding_map(&sub, "sync_hint", sync_entries,
                       G_N_ELEMENTS(sync_entries));
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

struct BodyStreamState {
    BitWriter bw;
    int64_t prev_entry_template;
    int64_t current_thread;
    /* v1.7 unified field-state tables: keyed by (template_id, ins_pos,
     * field_id) → most-recent observed u128 value.  CP state persists
     * across the body.  WP state is overwritten by a snapshot of CP
     * state at the start of each CP entry's WP chain and discarded
     * implicitly at chain end (the next chain re-forks from CP). */
    GHashTable *cp_field_state;
    GHashTable *wp_field_state;
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
    GHashTableIter iter;
    gpointer value;

    bw_write_uleb128(bw, g_hash_table_size(bb_map));

    g_hash_table_iter_init(&iter, bb_map);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        BBTemplate *tmpl = (BBTemplate *)value;
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
    }
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
 *       delta       : SLEB128     (i128 modular cur − baseline)
 *
 * Records are emitted in non-descending (ins_pos, field_id) order;
 * unchanged fields contribute zero bytes.  Per-(template_id, ins_pos,
 * field_id) state tables track the most-recent observed value and
 * supply the baseline.  CP state advances on every CP entry; WP
 * state is forked from CP at chain start and discarded at chain end.
 *
 * Adding a new dynamic field is a single FieldDescriptor table entry
 * (and a fresh FID_* in champsim_tracer.h).  The wire format does
 * not change.
 */

/* Composite key for the per-field state table. */
typedef struct {
    uint32_t template_id;
    uint16_t ins_pos;
    uint8_t  field_id;
    uint8_t  _pad;
} FieldStateKey;

typedef struct {
    uint64_t lo;
    uint64_t hi;
} U128;

static inline unsigned __int128 u128_pack(U128 v) {
    return ((unsigned __int128)v.hi << 64) | v.lo;
}
static inline U128 u128_unpack(unsigned __int128 v) {
    U128 r = { (uint64_t)v, (uint64_t)(v >> 64) };
    return r;
}

static guint field_key_hash(gconstpointer kv) {
    const FieldStateKey *k = (const FieldStateKey *)kv;
    /* fold to 32 bits */
    uint32_t h = k->template_id * 2654435761u;
    h ^= ((uint32_t)k->ins_pos << 8) ^ (uint32_t)k->field_id;
    return (guint)h;
}
static gboolean field_key_equal(gconstpointer aa, gconstpointer bb) {
    const FieldStateKey *a = (const FieldStateKey *)aa;
    const FieldStateKey *b = (const FieldStateKey *)bb;
    return a->template_id == b->template_id
        && a->ins_pos == b->ins_pos
        && a->field_id == b->field_id;
}

/* Mask `lo` to its low @sz bytes (sz ≤ 8) so a u8 store of 0xFF is
 * encoded as 255, not −1.  Keeps deltas well-defined. */
static inline uint64_t mem_data_mask_lo(uint64_t lo, uint8_t sz) {
    if (sz >= 8) return lo;
    uint64_t mask = (sz == 0) ? 0xFFu : ((uint64_t)1 << (sz * 8)) - 1;
    return lo & mask;
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
    const GArray *dyn_params;   /* DynParam[]; sorted (insn_index,type)  */
    const GArray *reg_snaps;    /* RegSnap[]; template-walk order        */
    const uint8_t *actual_n_loads;
    const uint8_t *actual_n_stores;
    /* Pre-walked dyn_param index of the first load slot for insn i
     * (length = tmpl->n_insns + 1, last entry = total dyn_params). */
    const uint32_t *insn_dp_off;
    /* Pre-walked reg_snap index of the first src snap for insn i
     * (length = tmpl->n_insns + 1, last entry = total reg_snaps). */
    const uint32_t *insn_rs_off;
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
                    unsigned __int128 *out_val);
    /* template_default: baseline used on first sighting of
     * (template_id, ins_pos, field_id).  For dynamic-runtime fields
     * (addresses, data, reg values) this is 0; for insn-encoding
     * fields it's the template's static value, so unchanged-from-
     * template fields cost zero record bytes. */
    unsigned __int128 (*template_default)(const BBTemplate *tmpl,
                                          uint32_t ins_pos, uint8_t slot);
    const char *name;          /* debug only */
} FieldDescriptor;

/* ---------- Per-family extract/default callbacks ---------- */

static bool extr_n_loads(const EntryView *ev, uint32_t i, uint8_t slot,
                         unsigned __int128 *out)
{
    (void)slot;
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return false;
    *out = (unsigned __int128)ev->actual_n_loads[i];
    return true;
}
static unsigned __int128 deflt_n_loads(const BBTemplate *t, uint32_t i,
                                       uint8_t slot)
{
    (void)t;
    (void)i;
    (void)slot;
    return 0;
}

static bool extr_n_stores(const EntryView *ev, uint32_t i, uint8_t slot,
                          unsigned __int128 *out)
{
    (void)slot;
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return false;
    *out = (unsigned __int128)ev->actual_n_stores[i];
    return true;
}
static unsigned __int128 deflt_n_stores(const BBTemplate *t, uint32_t i,
                                        uint8_t slot)
{
    (void)t;
    (void)i;
    (void)slot;
    return 0;
}

/* Locate the @slot-th memop of @insn matching @want_type
 * (DYN_LOAD_ADDR or DYN_STORE_ADDR).  Returns NULL if absent. */
static const DynParam *find_memop_slot(const EntryView *ev, uint32_t i,
                                       uint8_t slot, uint8_t want_type)
{
    if (!ev->dyn_params) return NULL;
    uint32_t lo = ev->insn_dp_off[i];
    uint32_t hi = ev->insn_dp_off[i + 1];
    uint8_t seen = 0;
    for (uint32_t k = lo; k < hi; k++) {
        const DynParam *dp = &g_array_index(ev->dyn_params, DynParam, k);
        if (dp->type != want_type) continue;
        if (seen == slot) return dp;
        seen++;
    }
    return NULL;
}

static bool extr_load_addr(const EntryView *ev, uint32_t i, uint8_t slot,
                           unsigned __int128 *out)
{
    const DynParam *dp = find_memop_slot(ev, i, slot, DYN_LOAD_ADDR);
    if (!dp) return false;
    *out = (unsigned __int128)dp->value;
    return true;
}
static bool extr_store_addr(const EntryView *ev, uint32_t i, uint8_t slot,
                            unsigned __int128 *out)
{
    const DynParam *dp = find_memop_slot(ev, i, slot, DYN_STORE_ADDR);
    if (!dp) return false;
    *out = (unsigned __int128)dp->value;
    return true;
}
static unsigned __int128 deflt_zero(const BBTemplate *t, uint32_t i,
                                    uint8_t slot)
{ (void)t; (void)i; (void)slot; return 0; }

static bool extr_load_data(const EntryView *ev, uint32_t i, uint8_t slot,
                           unsigned __int128 *out)
{
    const DynParam *dp = find_memop_slot(ev, i, slot, DYN_LOAD_ADDR);
    if (!dp) return false;
    uint8_t sz = dp->data_size ? dp->data_size : 1;
    uint64_t lo = mem_data_mask_lo(dp->data_lo, sz);
    uint64_t hi = (sz > 8) ? dp->data_hi : 0;
    *out = ((unsigned __int128)hi << 64) | lo;
    return true;
}
static bool extr_store_data(const EntryView *ev, uint32_t i, uint8_t slot,
                            unsigned __int128 *out)
{
    const DynParam *dp = find_memop_slot(ev, i, slot, DYN_STORE_ADDR);
    if (!dp) return false;
    uint8_t sz = dp->data_size ? dp->data_size : 1;
    uint64_t lo = mem_data_mask_lo(dp->data_lo, sz);
    uint64_t hi = (sz > 8) ? dp->data_hi : 0;
    *out = ((unsigned __int128)hi << 64) | lo;
    return true;
}

/* Reg-snap families: the captured reg_snaps array is laid out per-insn
 * source operands only, in template-walk order.  Destination register
 * identities remain in the template but destination values are not emitted
 * from the pre-exec snapshot path. */
static bool extr_src_reg(const EntryView *ev, uint32_t i, uint8_t slot,
                         unsigned __int128 *out)
{
    if (!ev->reg_snaps || !ev->tmpl) return false;
    const InsnFields *f = &ev->tmpl->insn_fields[i];
    if (slot >= f->n_src_regs) return false;
    uint32_t pos = ev->insn_rs_off[i] + slot;
    if (pos >= ev->reg_snaps->len) return false;
    const RegSnap *s = &g_array_index(ev->reg_snaps, RegSnap, pos);
    *out = ((unsigned __int128)s->hi << 64) | s->lo;
    return true;
}

/* Insn-encoding-mutable families.  The plugin's capture path does not
 * yet observe these (no SMC detector wired up) — extract returns the
 * template's static value, so the delta is always zero and no record
 * is emitted.  When an SMC observer is added later, point extract at
 * the runtime value and keep template_default unchanged. */
static unsigned __int128 deflt_insn_bytes_lo(const BBTemplate *t,
                                             uint32_t i, uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return 0;
    uint64_t v = 0;
    uint8_t sz = t->insn_sizes[i];
    if (sz > 8) sz = 8;
    const uint8_t *p = &t->insn_bytes[(size_t)i * MAX_INSN_BYTES];
    for (int b = 0; b < sz; b++) v |= ((uint64_t)p[b]) << (b * 8);
    return (unsigned __int128)v;
}
static bool extr_insn_bytes_lo(const EntryView *ev, uint32_t i, uint8_t slot,
                               unsigned __int128 *out)
{ *out = deflt_insn_bytes_lo(ev->tmpl, i, slot); return true; }

static unsigned __int128 deflt_insn_bytes_hi(const BBTemplate *t,
                                             uint32_t i, uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return 0;
    uint8_t sz = t->insn_sizes[i];
    if (sz <= 8) return 0;
    uint64_t v = 0;
    const uint8_t *p = &t->insn_bytes[(size_t)i * MAX_INSN_BYTES + 8];
    int extra = sz - 8;
    if (extra > 8) extra = 8;
    for (int b = 0; b < extra; b++) v |= ((uint64_t)p[b]) << (b * 8);
    return (unsigned __int128)v;
}
static bool extr_insn_bytes_hi(const EntryView *ev, uint32_t i, uint8_t slot,
                               unsigned __int128 *out)
{ *out = deflt_insn_bytes_hi(ev->tmpl, i, slot); return true; }

static unsigned __int128 deflt_insn_opcode(const BBTemplate *t,
                                           uint32_t i, uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return 0;
    return (unsigned __int128)(uint8_t)t->insn_fields[i].opcode;
}
static bool extr_insn_opcode(const EntryView *ev, uint32_t i, uint8_t slot,
                             unsigned __int128 *out)
{ *out = deflt_insn_opcode(ev->tmpl, i, slot); return true; }

static unsigned __int128 deflt_insn_branch_type(const BBTemplate *t,
                                                uint32_t i, uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return 0;
    return (unsigned __int128)(uint8_t)t->insn_fields[i].branch_type;
}
static bool extr_insn_branch_type(const EntryView *ev, uint32_t i, uint8_t slot,
                                  unsigned __int128 *out)
{ *out = deflt_insn_branch_type(ev->tmpl, i, slot); return true; }

static unsigned __int128 deflt_insn_flags(const BBTemplate *t,
                                          uint32_t i, uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return 0;
    const InsnFields *f = &t->insn_fields[i];
    uint8_t flags = 0;
    if (f->branch_conditional) flags |= CST_INSN_FLAG_BRANCH_COND;
    if (f->has_immediate)      flags |= CST_INSN_FLAG_HAS_IMM;
    flags |= (uint8_t)((f->sync_hint & 0x0F) << CST_INSN_FLAG_SYNC_SHIFT);
    return (unsigned __int128)flags;
}
static bool extr_insn_flags(const EntryView *ev, uint32_t i, uint8_t slot,
                            unsigned __int128 *out)
{ *out = deflt_insn_flags(ev->tmpl, i, slot); return true; }

static unsigned __int128 deflt_insn_imm(const BBTemplate *t,
                                        uint32_t i, uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return 0;
    const InsnFields *f = &t->insn_fields[i];
    if (!f->has_immediate) return 0;
    return (unsigned __int128)(int64_t)f->immediate;
}
static bool extr_insn_imm(const EntryView *ev, uint32_t i, uint8_t slot,
                          unsigned __int128 *out)
{ *out = deflt_insn_imm(ev->tmpl, i, slot); return true; }

static unsigned __int128 deflt_insn_size(const BBTemplate *t,
                                         uint32_t i, uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return 0;
    return (unsigned __int128)t->insn_sizes[i];
}
static bool extr_insn_size(const EntryView *ev, uint32_t i, uint8_t slot,
                           unsigned __int128 *out)
{ *out = deflt_insn_size(ev->tmpl, i, slot); return true; }

/* Field family registry.  Order MUST be ascending by base_field_id so
 * the emitter walks records in (ins_pos, field_id) order. */
static const FieldDescriptor field_descriptors[] = {
        { CST_FID_N_LOADS,          1,  false, false,
            extr_n_loads,        deflt_n_loads,         "N_LOADS" },
        { CST_FID_LOAD_ADDR_BASE,   CST_FID_SLOT_COUNT, false, false,
      extr_load_addr,      deflt_zero,           "LOAD_ADDR" },
        { CST_FID_STORE_ADDR_BASE,  CST_FID_SLOT_COUNT, false, false,
      extr_store_addr,     deflt_zero,           "STORE_ADDR" },
        { CST_FID_LOAD_DATA_BASE,   CST_FID_SLOT_COUNT, true,  false,
      extr_load_data,      deflt_zero,           "LOAD_DATA" },
        { CST_FID_STORE_DATA_BASE,  CST_FID_SLOT_COUNT, true,  false,
      extr_store_data,     deflt_zero,           "STORE_DATA" },
        { CST_FID_SRC_REG_BASE,     CST_FID_SLOT_COUNT, false, true,
      extr_src_reg,        deflt_zero,           "SRC_REG" },
        { CST_FID_N_STORES,         1,  false, false,
            extr_n_stores,       deflt_n_stores,        "N_STORES" },
        { CST_FID_INSN_BYTES_LO,    1,  false, false,
      extr_insn_bytes_lo,  deflt_insn_bytes_lo,  "INSN_BYTES_LO" },
        { CST_FID_INSN_BYTES_HI,    1,  false, false,
      extr_insn_bytes_hi,  deflt_insn_bytes_hi,  "INSN_BYTES_HI" },
        { CST_FID_INSN_OPCODE,      1,  false, false,
      extr_insn_opcode,    deflt_insn_opcode,    "OPCODE" },
        { CST_FID_INSN_BRANCH_TYPE, 1,  false, false,
      extr_insn_branch_type, deflt_insn_branch_type, "BRANCH_TYPE" },
        { CST_FID_INSN_FLAGS,       1,  false, false,
      extr_insn_flags,     deflt_insn_flags,     "INSN_FLAGS" },
        { CST_FID_INSN_IMMEDIATE,   1,  false, false,
      extr_insn_imm,       deflt_insn_imm,       "IMMEDIATE" },
        { CST_FID_INSN_SIZE,        1,  false, false,
      extr_insn_size,      deflt_insn_size,      "INSN_SIZE" },
};

#define N_FIELD_DESCRIPTORS (sizeof(field_descriptors) / sizeof(field_descriptors[0]))

/* Sort dyn_params so each insn's loads precede its stores, matching
 * the slot indexing used by find_memop_slot(). */
static gint dyn_param_cmp(gconstpointer aa, gconstpointer bb)
{
    const DynParam *a = (const DynParam *)aa;
    const DynParam *b = (const DynParam *)bb;
    if (a->insn_index != b->insn_index)
        return (a->insn_index < b->insn_index) ? -1 : 1;
    if (a->type != b->type)
        return (a->type < b->type) ? -1 : 1;
    return 0;
}
static void dyn_params_sort_template_order(GArray *dyn_params)
{
    if (!dyn_params || dyn_params->len < 2) return;
    g_array_sort(dyn_params, dyn_param_cmp);
}

/* Build per-insn offset arrays into dyn_params and reg_snaps so
 * descriptor extracts run in O(1) per slot. */
static void build_entry_view(EntryView *ev, const BBTemplate *tmpl,
                             const GArray *dyn_params,
                             const GArray *reg_snaps,
                             uint8_t *actual_n_loads,
                             uint8_t *actual_n_stores,
                             uint32_t *insn_dp_off,
                             uint32_t *insn_rs_off)
{
    ev->tmpl = tmpl;
    ev->dyn_params = dyn_params;
    ev->reg_snaps = reg_snaps;
    ev->actual_n_loads = actual_n_loads;
    ev->actual_n_stores = actual_n_stores;
    ev->insn_dp_off = insn_dp_off;
    ev->insn_rs_off = insn_rs_off;

    if (!tmpl) return;

    uint32_t n = tmpl->n_insns;
    /* Walk dyn_params (already sorted by insn_index, type) once. */
    uint32_t k = 0;
    uint32_t total_dp = dyn_params ? dyn_params->len : 0;
    for (uint32_t i = 0; i < n; i++) {
        actual_n_loads[i] = 0;
        actual_n_stores[i] = 0;
        insn_dp_off[i] = k;
        while (k < total_dp) {
            const DynParam *dp = &g_array_index(dyn_params, DynParam, k);
            if (dp->insn_index != i) break;
            if (dp->type == DYN_LOAD_ADDR) actual_n_loads[i]++;
            else                            actual_n_stores[i]++;
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

/* Look up baseline value for (template_id, ins_pos, field_id).  Falls
 * back to the descriptor's template_default if no prior observation. */
static unsigned __int128 field_state_get(GHashTable *state,
                                         uint32_t template_id,
                                         uint32_t ins_pos,
                                         uint8_t field_id,
                                         const FieldDescriptor *fd,
                                         const BBTemplate *tmpl,
                                         uint8_t slot)
{
    FieldStateKey k = { template_id, (uint16_t)ins_pos, field_id, 0 };
    U128 *cur = (U128 *)g_hash_table_lookup(state, &k);
    if (cur) return u128_pack(*cur);
    return fd->template_default(tmpl, ins_pos, slot);
}

static void field_state_put(GHashTable *state,
                            uint32_t template_id,
                            uint32_t ins_pos,
                            uint8_t field_id,
                            unsigned __int128 v)
{
    FieldStateKey *k = g_new(FieldStateKey, 1);
    k->template_id = template_id;
    k->ins_pos = (uint16_t)ins_pos;
    k->field_id = field_id;
    k->_pad = 0;
    U128 *val = g_new(U128, 1);
    *val = u128_unpack(v);
    g_hash_table_replace(state, k, val);
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
                                     GHashTable *state,
                                     uint32_t template_id,
                                     const EntryView *ev,
                                     bool is_wp,
                                     uint8_t header_flags)
{
    BitWriter rec_bw;
    bw_init_buf(&rec_bw);

    /* Two-pass: pass 1 buffers records into a small staging vec to
     * count them, pass 2 writes the count + records.  Cheaper would
     * be to lazily fix up the count, but ULEB-sized count can grow,
     * so we pre-count.  Records are typically small. */
    typedef struct { uint32_t pos; uint8_t fid; __int128 delta; } StageRec;
    g_autoptr(GArray) stage =
        g_array_sized_new(false, false, sizeof(StageRec), 16);

    uint32_t prev_pos = 0;
    if (ev->tmpl) {
        for (uint32_t i = 0; i < ev->tmpl->n_insns; i++) {
            for (size_t d = 0; d < N_FIELD_DESCRIPTORS; d++) {
                const FieldDescriptor *fd = &field_descriptors[d];
                if (fd->gated_by_mem_data && !(header_flags & CST_FLAG_MEM_DATA))
                    continue;
                if (fd->gated_by_reg_data && !(header_flags & CST_FLAG_REG_DATA))
                    continue;

                for (uint8_t slot = 0; slot < fd->slot_count; slot++) {
                    unsigned __int128 cur;
                    if (!fd->extract(ev, i, slot, &cur)) continue;
                    uint8_t fid = fd->base_field_id + slot;
                    unsigned __int128 base =
                        field_state_get(state, template_id, i, fid,
                                        fd, ev->tmpl, slot);
                    if (cur == base) continue;
                    StageRec rec = { i, fid, (__int128)(cur - base) };
                    g_array_append_val(stage, rec);
                    field_state_put(state, template_id, i, fid, cur);
                }
            }
        }
    }

    uint64_t section_start = bw_tell_bytes(main_bw);

    /* Build payload in rec_bw, then emit as length-prefixed section. */
    bw_write_uleb128(&rec_bw, stage->len);
    for (guint r = 0; r < stage->len; r++) {
        StageRec *s = &g_array_index(stage, StageRec, r);
        uint64_t gap = (uint64_t)(s->pos - prev_pos);
        bw_write_uleb128(&rec_bw, gap);
        bw_write_u8(&rec_bw, s->fid);
        bw_write_sleb128_i128(&rec_bw, s->delta);
        prev_pos = s->pos;
    }
    bw_byte_align(&rec_bw);
    bw_write_section(main_bw, bw_finish_buf(&rec_bw));

    uint64_t bits = (bw_tell_bytes(main_bw) - section_start) * 8;
    if (is_wp) stat_bin_dyn_wp_bits += bits;
    else       stat_bin_dyn_cp_bits += bits;
}

/* Snapshot CP field-state into WP field-state at the start of a WP
 * chain.  WP entries delta against this fork; the fork is discarded
 * at chain end (via wp state hashtable rebuild) so wrong-path effects
 * never leak into subsequent CP entries. */
static void field_state_fork_wp(GHashTable *cp_state, GHashTable *wp_state)
{
    g_hash_table_remove_all(wp_state);
    GHashTableIter it;
    gpointer pk, pv;
    g_hash_table_iter_init(&it, cp_state);
    while (g_hash_table_iter_next(&it, &pk, &pv)) {
        FieldStateKey *k = g_new(FieldStateKey, 1);
        *k = *(FieldStateKey *)pk;
        U128 *v = g_new(U128, 1);
        *v = *(U128 *)pv;
        g_hash_table_insert(wp_state, k, v);
    }
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

    st->cp_field_state = g_hash_table_new_full(field_key_hash,
                                               field_key_equal,
                                               g_free, g_free);
    st->wp_field_state = g_hash_table_new_full(field_key_hash,
                                               field_key_equal,
                                               g_free, g_free);

    return st;
}

/*
 * v1.7: build an EntryView wrapping the captured per-entry data and
 * emit one length-prefixed delta_section.  The descriptor table in
 * field_descriptors[] is the single source of truth for which fields
 * exist on the wire and how each is reconstructed.
 */
static void emit_one_bb_delta(BitWriter *bw, BodyStreamState *st,
                              GHashTable *state, uint32_t template_id,
                              const BBTemplate *tmpl,
                              const GArray *dyn_params,
                              const GArray *reg_snaps,
                              bool is_wp)
{
    EntryView ev;
    uint32_t n = tmpl ? tmpl->n_insns : 0;
    g_autofree uint8_t *anl = g_new0(uint8_t, n ? n : 1);
    g_autofree uint8_t *ans = g_new0(uint8_t, n ? n : 1);
    g_autofree uint32_t *dpoff = g_new0(uint32_t, (n ? n : 0) + 1);
    g_autofree uint32_t *rsoff = g_new0(uint32_t, (n ? n : 0) + 1);
    build_entry_view(&ev, tmpl, dyn_params, reg_snaps, anl, ans,
                     dpoff, rsoff);
    emit_field_delta_section(bw, state, template_id, &ev, is_wp,
                             st->header_flags);
}

void body_stream_write_entry(BodyStreamState *st, const BodyEntry *entry)
{
    int64_t entry_tmpl = entry->template_id;
    uint32_t num_wp = entry->wp_entries ? entry->wp_entries->len : 0;
    uint64_t body_start = bw_tell_bytes(&st->bw);

    dyn_params_sort_template_order(entry->dyn_params);
    for (uint32_t w = 0; w < num_wp; w++) {
        WPBBEntry *wp = &g_array_index(entry->wp_entries, WPBBEntry, w);
        dyn_params_sort_template_order(wp->dyn_params);
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
                      entry->tmpl, entry->dyn_params, entry->reg_snaps,
                      false);

    /* WP chain sub-section */
    {
        BitWriter sub;
        bw_init_buf(&sub);
        bw_write_uleb128(&sub, num_wp);
        int64_t prev_wp_template = 0;
        if (num_wp > 0) {
            /* Seed WP field-state from CP: speculative execution
             * starts at the CP architectural state and is rolled
             * back at chain end. */
            field_state_fork_wp(st->cp_field_state, st->wp_field_state);
        }
        for (uint32_t w = 0; w < num_wp; w++) {
            const WPBBEntry *wp = &g_array_index(entry->wp_entries,
                                                 WPBBEntry, w);
            uint32_t wp_tmpl = wp->template_id;
            bw_write_sleb128(&sub, (int64_t)wp_tmpl - prev_wp_template);
            prev_wp_template = wp_tmpl;
            emit_one_bb_delta(&sub, st, st->wp_field_state, wp_tmpl,
                              wp->tmpl, wp->dyn_params, wp->reg_snaps,
                              true);
        }
        bw_byte_align(&sub);
        bw_write_section(&st->bw, bw_finish_buf(&sub));
    }

    /* WP events sub-section */
    {
        uint32_t num_events = 0;
        for (uint32_t w = 0; w < num_wp; w++) {
            const WPBBEntry *wp = &g_array_index(entry->wp_entries,
                                                 WPBBEntry, w);
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
            const WPBBEntry *wp = &g_array_index(entry->wp_entries,
                                                 WPBBEntry, w);
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
        stat_bin_wp_exception_bits += (bw_tell_bytes(&sub) - ev_start) * 8;

        bw_byte_align(&sub);
        bw_write_section(&st->bw, bw_finish_buf(&sub));
    }

    bw_byte_align(&st->bw);

    st->num_entries++;
    stat_bin_body_bits += (bw_tell_bytes(&st->bw) - body_start) * 8;
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
    templates_count = g_hash_table_size(bb_map);
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
    stat_bin_header_bits += (end_bytes - stats_start) * 8;
    stat_bin_total_bits += end_bytes * 8;

    g_hash_table_unref(st->cp_field_state);
    g_hash_table_unref(st->wp_field_state);
}
