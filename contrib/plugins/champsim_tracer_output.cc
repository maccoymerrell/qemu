/*
 * Wrong-Path Tracing Plugin — binary format v1.2 writer.
 *
 * BitWriter primitives, template dictionary serializer, dyn-param
 * patch emitter, body entry streamer, and trailer writer for the
 * packed binary (.wpt) format.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>

#include "champsim_tracer.h"

/* ========================= BitWriter primitives ========================= */

static inline void bw_init_file(BitWriter *bw, FILE *f)
{
    bw->f = f;
    bw->buf = NULL;
    bw->total_bytes = 0;
}

static inline void bw_init_buf(BitWriter *bw)
{
    bw->f = NULL;
    bw->buf = g_byte_array_new();
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
    if (bw->f) {
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

struct BodyStreamState {
    BitWriter bw;
    int64_t prev_entry_template;
    GHashTable *cp_dyn_state;
    GHashTable *wp_dyn_state;
    /* Per-GenericRegId last-seen value, for SLEB-delta encoding of
     * the §5.2 reg-data section.  Indexed 0..255; REG_NONE (0) is
     * unused.  Reset to zero at body_stream_new. */
    int64_t cp_reg_state_lo[256];
    int64_t cp_reg_state_hi[256];
    /* Same, but for the WP sub-section.  Re-seeded from cp state at
     * the start of each CP entry's WP chain (since wrong-path
     * execution begins from the CP register state and is rolled back
     * when the chain ends, so cross-WP-chain accumulation would be
     * incorrect). */
    int64_t wp_reg_state_lo[256];
    int64_t wp_reg_state_hi[256];
    uint64_t num_entries;
    uint32_t thread_id;
    uint64_t body_off;
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
 *                          bit6 = dynamic_memop (runtime > static count)
 *   n_src       : u8
 *   n_dst       : u8
 *   src_regs[n_src] : u8 each
 *   dst_regs[n_dst] : u8 each
 *   n_loads     : u8       (observed-max loads per execution)
 *   n_stores    : u8       (observed-max stores per execution)
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
            if (fld->dynamic_memop) {
                flags |= CST_INSN_FLAG_DYNAMIC_MEMOP;
            }
            bw_write_u8(&sub, flags);

            bw_write_u8(&sub, fld->n_src_regs);
            bw_write_u8(&sub, fld->n_dst_regs);
            for (uint8_t s = 0; s < fld->n_src_regs; s++) {
                bw_write_u8(&sub, fld->src_regs[s]);
            }
            for (uint8_t d = 0; d < fld->n_dst_regs; d++) {
                bw_write_u8(&sub, fld->dst_regs[d]);
            }
            bw_write_u8(&sub, fld->n_loads);
            bw_write_u8(&sub, fld->n_stores);
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

/* ========================= Dyn param patching ========================= */

static gboolean dyn_param_array_equal(const GArray *a, const GArray *b)
{
    if (a == b) {
        return true;
    }
    if (!a || !b || a->len != b->len) {
        return false;
    }

    for (guint i = 0; i < a->len; i++) {
        const DynParam *da = &g_array_index(a, DynParam, i);
        const DynParam *db = &g_array_index(b, DynParam, i);
        if (da->type != db->type ||
            da->insn_index != db->insn_index ||
            da->value != db->value) {
            return false;
        }
    }

    return true;
}

static GArray *dyn_param_array_clone(const GArray *src)
{
    GArray *dst = g_array_sized_new(false, false, sizeof(DynParam),
                                    src ? src->len : 0);

    if (!src) {
        return dst;
    }

    for (guint i = 0; i < src->len; i++) {
        const DynParam *d = &g_array_index(src, DynParam, i);
        DynParam copy = {
            .type = d->type,
            .insn_index = d->insn_index,
            .value = d->value,
        };
        g_array_append_val(dst, copy);
    }

    return dst;
}

static void dyn_param_array_unref_value(gpointer value)
{
    if (value) {
        g_array_unref((GArray *)value);
    }
}

/*
 * Stable-sort dyn_params so that entries are ordered by (insn_index,
 * type): for each instruction, all loads precede all stores.  v1.1
 * consumers determine load/store attribution positionally using the
 * template's per-insn (n_loads, n_stores) schema.
 */
static gint dyn_param_cmp(gconstpointer aa, gconstpointer bb)
{
    const DynParam *a = (const DynParam *)aa;
    const DynParam *b = (const DynParam *)bb;
    if (a->insn_index != b->insn_index) {
        return (a->insn_index < b->insn_index) ? -1 : 1;
    }
    if (a->type != b->type) {
        return (a->type < b->type) ? -1 : 1;
    }
    return 0;
}

static void dyn_params_sort_template_order(GArray *dyn_params)
{
    if (!dyn_params || dyn_params->len < 2) {
        return;
    }
    g_array_sort(dyn_params, dyn_param_cmp);
}

static void dyn_param_collect_changed_positions(const GArray *prev_dyn,
                                                const GArray *cur_dyn,
                                                GArray *changed_positions)
{
    guint prev_len = prev_dyn ? prev_dyn->len : 0;
    guint cur_len = cur_dyn ? cur_dyn->len : 0;
    guint common = MIN(prev_len, cur_len);

    for (guint i = 0; i < common; i++) {
        const DynParam *prev = &g_array_index(prev_dyn, DynParam, i);
        const DynParam *cur = &g_array_index(cur_dyn, DynParam, i);

        if (prev->type != cur->type || prev->value != cur->value) {
            g_array_append_val(changed_positions, i);
        }
    }

    for (guint i = common; i < cur_len; i++) {
        g_array_append_val(changed_positions, i);
    }
}

/*
 * Write a dyn-param patch record.
 *
 *   flags        : u8   bit0 = CST_DYN_FLAG_UNCHANGED
 *   (if not unchanged)
 *     cur_len     : ULEB128
 *     changed_len : ULEB128
 *     { pos_gap : ULEB128 , delta : SLEB128 } *
 */
static void write_dyn_param_patch(BitWriter *bw,
                                  const GArray *prev_dyn,
                                  const GArray *cur_dyn,
                                  const GArray *changed_positions,
                                  bool is_wp)
{
    int64_t prev_pos = -1;
    uint64_t patch_start = bw_tell_bytes(bw);

    bw_write_u8(bw, 0 /* flags: not unchanged */);
    bw_write_uleb128(bw, cur_dyn->len);
    bw_write_uleb128(bw, changed_positions->len);

    for (guint c = 0; c < changed_positions->len; c++) {
        guint pos = g_array_index(changed_positions, guint, c);
        const DynParam *cur = &g_array_index(cur_dyn, DynParam, pos);
        uint64_t pos_gap = (uint64_t)(pos - (guint)(prev_pos + 1));
        int64_t base_value = 0;
        int64_t delta;

        if (prev_dyn && pos < prev_dyn->len) {
            const DynParam *prev = &g_array_index(prev_dyn, DynParam, pos);
            base_value = prev->value;
        }
        delta = (int64_t)cur->value - base_value;

        bw_write_uleb128(bw, pos_gap);
        bw_write_sleb128(bw, delta);

        prev_pos = pos;
    }

    uint64_t written = (bw_tell_bytes(bw) - patch_start) * 8;
    if (is_wp) {
        stat_bin_dyn_wp_bits += written;
    } else {
        stat_bin_dyn_cp_bits += written;
    }
}

static bool body_stream_emit_dyn_patch(BitWriter *bw,
                                       GHashTable *dyn_state,
                                       uint32_t template_id,
                                       const GArray *cur_dyn,
                                       bool is_wp)
{
    GArray *prev_dyn = (GArray *)g_hash_table_lookup(dyn_state, &template_id);
    bool unchanged = prev_dyn && dyn_param_array_equal(prev_dyn, cur_dyn);

    if (unchanged) {
        bw_write_u8(bw, CST_DYN_FLAG_UNCHANGED);
        return true;
    }

    g_autoptr(GArray) changed_positions = g_array_new(false, false,
                                                      sizeof(guint));
    uint32_t *key = g_new(uint32_t, 1);

    dyn_param_collect_changed_positions(prev_dyn, cur_dyn, changed_positions);
    write_dyn_param_patch(bw, prev_dyn, cur_dyn, changed_positions, is_wp);

    *key = template_id;
    g_hash_table_replace(dyn_state, key, dyn_param_array_clone(cur_dyn));
    return false;
}

/* ========================= Mem-data values ========================= */

/* Encode data_size into 3-bit code: 0=1B, 1=2B, 2=4B, 3=8B, 4=16B */
static inline uint8_t mem_data_size_code(uint8_t data_size)
{
    switch (data_size) {
    case 1:  return 0;
    case 2:  return 1;
    case 4:  return 2;
    case 8:  return 3;
    case 16: return 4;
    default: return 0;
    }
}

static void write_mem_data_values(BitWriter *bw, const GArray *dyn_params)
{
    guint count = dyn_params ? dyn_params->len : 0;
    for (guint i = 0; i < count; i++) {
        const DynParam *dp = &g_array_index(dyn_params, DynParam, i);
        uint8_t sz = dp->data_size;
        if (sz == 0) {
            sz = 1;
        }
        bw_write_u8(bw, mem_data_size_code(sz));
        for (uint8_t b = 0; b < sz && b < 8; b++) {
            bw_write_u8(bw, (uint8_t)((dp->data_lo >> (b * 8)) & 0xFF));
        }
        if (sz > 8) {
            for (uint8_t b = 0; b < sz - 8; b++) {
                bw_write_u8(bw, (uint8_t)((dp->data_hi >> (b * 8)) & 0xFF));
            }
        }
    }
}

static void emit_mem_data_section(BitWriter *main_bw, const GArray *dyn_params)
{
    BitWriter sub;
    bw_init_buf(&sub);
    write_mem_data_values(&sub, dyn_params);
    bw_byte_align(&sub);
    bw_write_section(main_bw, bw_finish_buf(&sub));
}

/* ========================= Reg-data values =========================
 *
 * Emit per-instruction src then dst register snapshots.  Each snap:
 *   u8 size_code   (0=4B, 1=8B, 2=16B)
 *   SLEB128 delta_lo  (snap.lo - state[reg_id].lo)
 *   SLEB128 delta_hi  (only when size_code==2)
 *
 * Per-reg-id state is carried across entries on BodyStreamState so
 * static / loop-invariant register values cost a single 0-byte SLEB
 * after the first capture.  REG_NONE (id 0) is skipped entirely.
 *
 * Snap ordering inside reg_snaps mirrors the template walk:
 *   for each insn i in template:
 *     for r in 0..n_src_regs[i]: one snap
 *     for r in 0..n_dst_regs[i]: one snap
 */

static void write_one_reg_snap(BitWriter *bw,
                               const RegSnap *s,
                               uint8_t reg_id,
                               int64_t *state_lo,
                               int64_t *state_hi)
{
    bw_write_u8(bw, s->size_code);
    if (reg_id == REG_NONE) {
        /* No state slot; emit raw value as zero-baseline delta. */
        bw_write_sleb128(bw, (int64_t)s->lo);
        if (s->size_code == 2) {
            bw_write_sleb128(bw, (int64_t)s->hi);
        }
        return;
    }
    int64_t cur_lo = (int64_t)s->lo;
    int64_t delta_lo = cur_lo - state_lo[reg_id];
    bw_write_sleb128(bw, delta_lo);
    state_lo[reg_id] = cur_lo;
    if (s->size_code == 2) {
        int64_t cur_hi = (int64_t)s->hi;
        int64_t delta_hi = cur_hi - state_hi[reg_id];
        bw_write_sleb128(bw, delta_hi);
        state_hi[reg_id] = cur_hi;
    }
}

static void emit_reg_data_section(BitWriter *main_bw,
                                  int64_t *state_lo,
                                  int64_t *state_hi,
                                  const BBTemplate *tmpl,
                                  const GArray *reg_snaps)
{
    BitWriter sub;
    bw_init_buf(&sub);

    if (tmpl) {
        /*
         * Always emit one snap per template src/dst slot.  If the
         * captured `reg_snaps` array is short — e.g. because a
         * per-insn callback didn't fire for some reason — pad missing
         * entries with a zero-baseline 4B snap (size_code=0,
         * delta_lo=0) so the decoder's per-reg-id state stays
         * unchanged.  Otherwise the decoder would read fewer bytes
         * than we wrote (or vice versa) and lose stream sync.
         */
        const RegSnap zero_snap = { 0, 0, 0 };
        guint pos = 0;
        guint avail = reg_snaps ? reg_snaps->len : 0;
        for (uint32_t i = 0; i < tmpl->n_insns; i++) {
            const InsnFields *f = &tmpl->insn_fields[i];
            for (uint8_t r = 0; r < f->n_src_regs; r++) {
                const RegSnap *s = (pos < avail)
                    ? &g_array_index(reg_snaps, RegSnap, pos)
                    : &zero_snap;
                pos++;
                write_one_reg_snap(&sub, s, f->src_regs[r],
                                   state_lo, state_hi);
            }
            for (uint8_t r = 0; r < f->n_dst_regs; r++) {
                const RegSnap *s = (pos < avail)
                    ? &g_array_index(reg_snaps, RegSnap, pos)
                    : &zero_snap;
                pos++;
                write_one_reg_snap(&sub, s, f->dst_regs[r],
                                   state_lo, state_hi);
            }
        }
    }

    bw_byte_align(&sub);
    bw_write_section(main_bw, bw_finish_buf(&sub));
}

/* ========================= Body stream ========================= */

BodyStreamState *body_stream_new(FILE *f, uint32_t thread_id,
                                 const char *seg_datetime)
{
    BodyStreamState *st = g_new0(BodyStreamState, 1);

    bw_init_file(&st->bw, f);

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

    bw_write_uleb128(&st->bw, (uint64_t)thread_id);

    bw_byte_align(&st->bw);
    bw_flush(&st->bw);
    st->body_off = (uint64_t)ftello(f);

    st->thread_id = thread_id;

    st->cp_dyn_state = g_hash_table_new_full(g_int_hash, g_int_equal,
                                             g_free,
                                             dyn_param_array_unref_value);
    st->wp_dyn_state = g_hash_table_new_full(g_int_hash, g_int_equal,
                                             g_free,
                                             dyn_param_array_unref_value);

    return st;
}

/*
 * Update the template's observed-max (n_loads, n_stores) per insn from
 * this entry's dyn_params (which must already be sorted by insn_index).
 * If any insn's observed count exceeds its current static count, bump
 * the count and set the DYNAMIC_MEMOP flag so the consumer knows this
 * insn's entries carry a per-entry count preamble.
 */
static void update_template_observed_max(BBTemplate *tmpl,
                                         const GArray *dyn_params)
{
    if (!tmpl) {
        return;
    }
    /*
     * Build per-insn observed (n_loads, n_stores) for this entry.
     * dyn_params must be sorted by (insn_index, type).  Insns not
     * appearing in dyn_params have observed counts (0, 0).
     */
    uint32_t n_insns = tmpl->n_insns;
    g_autofree uint32_t *obs_l = g_new0(uint32_t, n_insns);
    g_autofree uint32_t *obs_s = g_new0(uint32_t, n_insns);
    if (dyn_params) {
        for (guint i = 0; i < dyn_params->len; i++) {
            const DynParam *dp = &g_array_index(dyn_params, DynParam, i);
            if (dp->insn_index >= n_insns) continue;
            if (dp->type == DYN_LOAD_ADDR) obs_l[dp->insn_index]++;
            else obs_s[dp->insn_index]++;
        }
    }
    /*
     * For each insn, compare observed (n_l, n_s) against the template's
     * current values.  Bump UP if observed exceeds current; mark
     * DYNAMIC_MEMOP whenever observed differs from current (in either
     * direction) so the per-entry preamble carries the actual counts.
     */
    for (uint32_t ii = 0; ii < n_insns; ii++) {
        InsnFields *fld = &tmpl->insn_fields[ii];
        uint32_t n_l = obs_l[ii];
        uint32_t n_s = obs_s[ii];
        if (n_l > fld->n_loads) {
            fld->n_loads = (n_l > 255 ? 255 : (uint8_t)n_l);
        }
        if (n_s > fld->n_stores) {
            fld->n_stores = (n_s > 255 ? 255 : (uint8_t)n_s);
        }
        if (n_l != fld->n_loads || n_s != fld->n_stores) {
            fld->dynamic_memop = true;
        }
    }
}

/*
 * Emit the dynamic-memop preamble for this entry: for each template
 * insn with DYNAMIC_MEMOP flag, write (actual_n_loads, actual_n_stores)
 * as ULEB pair, in template-insn order.  dyn_params must be sorted.
 */
static void emit_dynamic_memop_preamble(BitWriter *bw,
                                        const BBTemplate *tmpl,
                                        const GArray *dyn_params)
{
    if (!tmpl) {
        return;
    }
    for (uint32_t i = 0; i < tmpl->n_insns; i++) {
        if (!tmpl->insn_fields[i].dynamic_memop) {
            continue;
        }
        uint32_t n_l = 0, n_s = 0;
        if (dyn_params) {
            for (guint k = 0; k < dyn_params->len; k++) {
                const DynParam *dp = &g_array_index(dyn_params, DynParam, k);
                if (dp->insn_index != i) continue;
                if (dp->type == DYN_LOAD_ADDR) n_l++;
                else n_s++;
            }
        }
        bw_write_uleb128(bw, n_l);
        bw_write_uleb128(bw, n_s);
    }
}

void body_stream_write_entry(BodyStreamState *st, const BodyEntry *entry)
{
    int64_t entry_tmpl = entry->template_id;
    uint32_t num_wp = entry->wp_entries ? entry->wp_entries->len : 0;
    uint64_t body_start = bw_tell_bytes(&st->bw);

    dyn_params_sort_template_order(entry->dyn_params);
    update_template_observed_max(entry->tmpl, entry->dyn_params);
    for (uint32_t w = 0; w < num_wp; w++) {
        WPBBEntry *wp = &g_array_index(entry->wp_entries, WPBBEntry, w);
        dyn_params_sort_template_order(wp->dyn_params);
        update_template_observed_max(wp->tmpl, wp->dyn_params);
    }

    bw_write_u8(&st->bw, BODY_TAG_ENTRY);
    bw_write_sleb128(&st->bw, entry_tmpl - st->prev_entry_template);
    st->prev_entry_template = entry_tmpl;

    emit_dynamic_memop_preamble(&st->bw, entry->tmpl, entry->dyn_params);
    body_stream_emit_dyn_patch(&st->bw, st->cp_dyn_state,
                               entry->template_id, entry->dyn_params,
                               false);
    if (enable_mem_data) {
        emit_mem_data_section(&st->bw, entry->dyn_params);
    }
    if (enable_reg_data) {
        emit_reg_data_section(&st->bw,
                              st->cp_reg_state_lo, st->cp_reg_state_hi,
                              entry->tmpl, entry->reg_snaps);
    }

    /* WP chain sub-section */
    {
        BitWriter sub;
        bw_init_buf(&sub);
        bw_write_uleb128(&sub, num_wp);
        int64_t prev_wp_tid = 0;
        if (enable_reg_data) {
            /* Seed WP reg-state from CP reg-state: WP execution starts
             * from the CP architectural state and is rolled back at
             * the end of the chain. */
            memcpy(st->wp_reg_state_lo, st->cp_reg_state_lo,
                   sizeof(st->wp_reg_state_lo));
            memcpy(st->wp_reg_state_hi, st->cp_reg_state_hi,
                   sizeof(st->wp_reg_state_hi));
        }
        for (uint32_t w = 0; w < num_wp; w++) {
            const WPBBEntry *wp = &g_array_index(entry->wp_entries,
                                                 WPBBEntry, w);
            uint32_t wp_tmpl = wp->template_id;
            bw_write_sleb128(&sub, (int64_t)wp_tmpl - prev_wp_tid);
            prev_wp_tid = wp_tmpl;
            emit_dynamic_memop_preamble(&sub, wp->tmpl, wp->dyn_params);
            body_stream_emit_dyn_patch(&sub, st->wp_dyn_state, wp_tmpl,
                                       wp->dyn_params, true);
            if (enable_mem_data) {
                emit_mem_data_section(&sub, wp->dyn_params);
            }
            if (enable_reg_data) {
                emit_reg_data_section(&sub,
                                      st->wp_reg_state_lo,
                                      st->wp_reg_state_hi,
                                      wp->tmpl, wp->reg_snaps);
            }
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
            /*
             * v1.2: when CST_WP_EVENT_FAULT is set, emit the
             * chain-relative index of the faulting instruction so
             * consumers can flag that specific uop as non-completing.
             */
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
    FILE *f = st->bw.f;
    uint64_t stats_start = bw_tell_bytes(&st->bw);

    bw_write_u8(&st->bw, BODY_TAG_END);
    bw_write_uleb128(&st->bw, st->num_entries);
    bw_byte_align(&st->bw);
    bw_flush(&st->bw);

    uint64_t body_end = (uint64_t)ftello(f);
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

    g_hash_table_unref(st->cp_dyn_state);
    g_hash_table_unref(st->wp_dyn_state);
}
