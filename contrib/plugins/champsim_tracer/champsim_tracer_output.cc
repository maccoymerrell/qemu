/*
 * ChampSim Tracer Plugin — binary (.cst) format writer.
 *
 * BitWriter primitives, template dictionary serializer, dyn-param
 * patch emitter, body entry streamer, and trailer writer.
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
    bw->rb = nullptr;
    bw->w = w;
    bw->total_bytes = 0;
}

static inline void bw_init_file(BitWriter *bw, FILE *f)
{
    bw->f = f;
    bw->buf = nullptr;
    bw->rb = nullptr;
    bw->w = nullptr;
    bw->total_bytes = 0;
}

static inline void bw_init_buf(BitWriter *bw)
{
    bw->f = nullptr;
    bw->buf = g_byte_array_new();
    bw->rb = nullptr;
    bw->w = nullptr;
    bw->total_bytes = 0;
}

/* RawBuf primitives.  Out-of-line grow path; inlined fast path lives
 * in bw_raw below. */
static inline void raw_buf_init(RawBuf *rb)
{
    rb->data = nullptr;
    rb->len = 0;
    rb->cap = 0;
}

static inline void raw_buf_reserve(RawBuf *rb, size_t want)
{
    if (rb->cap >= want) {
        return;
    }
    size_t new_cap = rb->cap ? rb->cap * 2 : 64;
    while (new_cap < want) new_cap *= 2;
    rb->data = (uint8_t *)g_realloc(rb->data, new_cap);
    rb->cap = new_cap;
}

static inline void raw_buf_free(RawBuf *rb)
{
    g_free(rb->data);
    rb->data = nullptr;
    rb->len = 0;
    rb->cap = 0;
}

static inline void raw_buf_clear(RawBuf *rb)
{
    rb->len = 0;
}

static inline void bw_init_rb(BitWriter *bw, RawBuf *rb)
{
    bw->f = nullptr;
    bw->buf = nullptr;
    bw->rb = rb;
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
    if (bw->rb) {
        /* Hot path for the per-entry encoder scratch.  Inlined so the
         * uleb / sleb hot loops bottom out in a memcpy + length bump
         * with no function call.  Profiling showed ~1.5 % of total
         * runtime in g_byte_array_append before this; the inlined
         * version trades that for a branch-free fast path with an
         * out-of-line grow when capacity runs out. */
        if (bw->rb->len + len > bw->rb->cap) {
            raw_buf_reserve(bw->rb, bw->rb->len + len);
        }
        memcpy(bw->rb->data + bw->rb->len, buf, len);
        bw->rb->len += len;
    } else if (bw->w) {
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
     * specials) get their canonical name from the shared helper.  Each
     * entry carries its initial value (width_bytes + LE bytes); a
     * zero width means "no live snapshot for this ID at segment
     * start" (e.g. install-time pre-vCPU start, or a register the
     * plugin couldn't resolve via the QEMU register API).
     *
     * The "reg" map carries (id, name) pairs only.  Per-segment initial
     * register-file snapshots are emitted inline as BODY_TAG_REGFILE
     * records, one per (thread, segment). */
    bw_write_string(bw, "reg");
    uint64_t n = 0;
    for (unsigned i = 0; i < REG_ID_COUNT; i++) {
        if (generic_reg_name(i)) n++;
    }
    bw_write_uleb128(bw, n);
    for (unsigned i = 0; i < REG_ID_COUNT; i++) {
        const char *name = generic_reg_name(i);
        if (!name) {
            continue;
        }
        write_encoding_entry(bw, i, name);
    }
}

static void write_field_id_encoding_map(BitWriter *bw)
{
    /* Count: 3 hot singletons + 5 slotted families × CST_FID_SLOT_COUNT
     * + 7 insn-metadata + 1 EXTENDED. */
    const uint64_t n_entries =
        3 + (uint64_t)5 * CST_FID_SLOT_COUNT + 7 + 1;
    bw_write_string(bw, "field_id");
    bw_write_uleb128(bw, n_entries);

    /* Hot singletons. */
    write_encoding_entry(bw, CST_FID_N_LOADS,   "CST_FID_N_LOADS");
    write_encoding_entry(bw, CST_FID_N_STORES,  "CST_FID_N_STORES");
    write_encoding_entry(bw, CST_FID_METAFLAGS, "CST_FID_METAFLAGS");

    /* Slotted families.  Slot k of family <F> sits at
     * CST_FID_<F>_BASE + k * CST_FID_SLOT_STRIDE; the encoding map
     * emits one (id → name) pair per slot so decoders can look up
     * by name without needing to know the stride. */
    static const struct { uint8_t base; const char *prefix; } fam[] = {
        { CST_FID_LOAD_ADDR_BASE,   "CST_FID_LOAD_ADDR"   },
        { CST_FID_STORE_ADDR_BASE,  "CST_FID_STORE_ADDR"  },
        { CST_FID_LOAD_DATA_BASE,   "CST_FID_LOAD_DATA"   },
        { CST_FID_STORE_DATA_BASE,  "CST_FID_STORE_DATA"  },
        { CST_FID_DST_REG_BASE,     "CST_FID_DST_REG"     },
    };
    for (uint64_t k = 0; k < CST_FID_SLOT_COUNT; k++) {
        for (size_t f = 0; f < G_N_ELEMENTS(fam); f++) {
            unsigned id = fam[f].base + (unsigned)k * CST_FID_SLOT_STRIDE;
            g_autofree char *name = g_strdup_printf("%s%" PRIu64,
                                                    fam[f].prefix, k);
            write_encoding_entry(bw, id, name);
        }
    }

    /* Cold insn-metadata singletons + EXTENDED. */
    static const EncodingMapEntry insn_fields[] = {
        { CST_FID_INSN_BYTES_LO,    "CST_FID_INSN_BYTES_LO" },
        { CST_FID_INSN_BYTES_HI,    "CST_FID_INSN_BYTES_HI" },
        { CST_FID_INSN_OPCODE,      "CST_FID_INSN_OPCODE" },
        { CST_FID_INSN_BRANCH_TYPE, "CST_FID_INSN_BRANCH_TYPE" },
        { CST_FID_INSN_FLAGS,       "CST_FID_INSN_FLAGS" },
        { CST_FID_INSN_IMMEDIATE,   "CST_FID_INSN_IMMEDIATE" },
        { CST_FID_INSN_SIZE,        "CST_FID_INSN_SIZE" },
        { CST_FID_EXTENDED,         "CST_FID_EXTENDED" },
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
        { CST_INSN_FLAG_VEC, "CST_INSN_FLAG_VEC" },
        { CST_INSN_FLAG_LANE_PARALLEL, "CST_INSN_FLAG_LANE_PARALLEL" },
        { CST_INSN_FLAG_HAS_DEP_BLOCK, "CST_INSN_FLAG_HAS_DEP_BLOCK" },
    };
    static const EncodingMapEntry dep_block_flag_entries[] = {
        { CST_DEP_BLOCK_HAS_REG,  "CST_DEP_BLOCK_HAS_REG" },
        { CST_DEP_BLOCK_HAS_ADDR, "CST_DEP_BLOCK_HAS_ADDR" },
    };
    static const EncodingMapEntry body_tag_entries[] = {
        { BODY_TAG_END, "BODY_TAG_END" },
        { BODY_TAG_ENTRY, "BODY_TAG_ENTRY" },
        { BODY_TAG_THREAD_SWITCH, "BODY_TAG_THREAD_SWITCH" },
        { BODY_TAG_IFRAME, "BODY_TAG_IFRAME" },
        { BODY_TAG_REGFILE, "BODY_TAG_REGFILE" },
    };
    static const EncodingMapEntry wp_event_flag_entries[] = {
        { CST_WP_EVENT_TRANSLATION_UNAVAIL,
          "CST_WP_EVENT_TRANSLATION_UNAVAIL" },
        { CST_WP_EVENT_FAULT, "CST_WP_EVENT_FAULT" },
    };
    static const EncodingMapEntry metaflags_entries[] = {
        { CST_METAFLAGS_Z, "CST_METAFLAGS_Z" },
        { CST_METAFLAGS_N, "CST_METAFLAGS_N" },
        { CST_METAFLAGS_C, "CST_METAFLAGS_C" },
        { CST_METAFLAGS_V, "CST_METAFLAGS_V" },
        { CST_METAFLAGS_P, "CST_METAFLAGS_P" },
    };

    BitWriter sub;
    bw_init_buf(&sub);
    bw_write_uleb128(&sub, 11);
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
    write_encoding_map(&sub, "metaflags", metaflags_entries,
                       G_N_ELEMENTS(metaflags_entries));
    write_encoding_map(&sub, "dep_block_flag", dep_block_flag_entries,
                       G_N_ELEMENTS(dep_block_flag_entries));
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
    /* Body stream — writes through @bw to the segment's body output
     * (file or compression pipe).  Body bytes start with CST_MAGIC,
     * stream BODY_TAG_* records as the workload runs, and end with
     * a BODY_TAG_END + entry count + trailing CST_MAGIC marker so
     * truncation is detectable from either end.                    */
    BitWriter bw;
    /* Header BitWriter — backed by an in-memory GByteArray.  All
     * header content (magic, isa, flags, window descriptors,
     * strings, encoding maps, and the full templates section
     * appended at body_stream_finish) goes here.  The buffer is
     * pulled out via bw_finish_buf at finish time and handed to the
     * segment manager for write-out to the separate header member.  */
    BitWriter header_bw;
    int64_t prev_entry_template;
    int64_t current_thread;
    /* Per-vCPU field-state tables: each thread's deltas are computed
     * against its own prior emission, not the cross-thread sequence.
     * Keyed by thread_id (dense small ints handed out by
     * get_or_assign_thread_id, starting at 0), lazy-grown on first
     * emit.  Slot may be null until the thread first emits.  CP state
     * persists across body entries within a thread; WP state is a
     * per-chain overlay that falls back to that thread's CP state. */
    std::vector<FieldStateTable *> cp_field_state;
    std::vector<FieldStateTable *> wp_field_state;
    /*
     * Per-thread regfile bookkeeping.  Each entry tracks whether
     * thread_id has emitted its BODY_TAG_REGFILE record in this
     * segment yet.  Indexed by thread_id; resized on demand.  Cleared
     * by reset_segment_local_state via body_stream_reset_per_thread.
     */
    std::vector<bool> regfile_emitted;
    /*
     * The segment-starting vCPU's pre-first-BB regfile.  Captured by
     * start_trace_segment when the segment opens (before any traced
     * BB executes on that thread); consumed when that thread emits
     * its first body entry, then cleared.  Threads that join after
     * segment open capture their regfile live at first emit (post-
     * first-BB on their side) — slight asymmetry, but the segment-
     * starting thread is the common case where pre-state is most
     * valuable.
     */
    std::vector<InitialRegSnap> seed_regfile;
    int32_t                     seed_thread = -1;  /* -1 = unset */
    /* Scratch overlays used to emit IFRAMEs.  An IFRAME is a full
     * body-record dump (CP + WP chain + WP events) encoded against
     * fresh "nothing observed yet" overlays so every record carries
     * absolute values.  The generations are bumped before each IFRAME
     * emission to invalidate all prior cells lazily; the IFRAME pass
     * then writes deltas from template_default.  IFRAMEs do not
     * affect the persistent cp/wp_field_state — the next regular
     * ENTRY continues from where the previous ENTRY left off.
     * Allocated lazily on first IFRAME. */
    FieldStateTable *iframe_cp_scratch;
    FieldStateTable *iframe_wp_scratch;
    EntryViewScratch ev_scratch;
    /* Per-body-entry scratch.  Reused across millions of entries to
     * eliminate the malloc/free pair the encoder previously paid on
     * every record.  rec_scratch is a RawBuf whose length is reset
     * to 0 at the start of each delta-section emit and whose bytes
     * are then copied into the main stream; the underlying
     * allocation grows once to the largest record observed and
     * stays put for the rest of the trace.  Switched from GByteArray
     * to RawBuf so the per-byte append in the encoder hot loop
     * bottoms out in an inlined memcpy instead of a glib function
     * call (saved ~1.5 % of total runtime).  stage_buf is the
     * StageRec[] the descriptor walk fills in, also reused.  Raw
     * pointer because StageRec's type definition lives further
     * down this TU and a vector<StageRec> here would force a
     * file-order rearrangement. */
    RawBuf rec_scratch;
    struct StageRec *stage_buf;
    size_t stage_cap;
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
 *   max_dep_loads  : u8    template-static MAX load count.  Bounds
 *                          the dep-mask bit layout: load slots
 *                          occupy bits [n_src, n_src+max_dep_loads).
 *                          Runtime per-iter count rides on
 *                          CST_FID_N_LOADS and may be smaller.
 *   max_dep_stores : u8    template-static MAX store count.  Sizes
 *                          the store_data_dep_mask[] array in the
 *                          HAS_REG sub-block.  Runtime per-iter
 *                          count rides on CST_FID_N_STORES.
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
            flags |= (uint8_t)((fld->sync_hint & 0x3)
                               << CST_INSN_FLAG_SYNC_SHIFT);
            if (fld->has_reg_deps || fld->has_addr_deps) {
                flags |= CST_INSN_FLAG_HAS_DEP_BLOCK;
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
            bw_write_u8(&sub, fld->max_dep_loads);
            bw_write_u8(&sub, fld->max_dep_stores);
            if (fld->has_immediate) {
                bw_write_sleb128(&sub, fld->immediate);
            }
            bw_write_u8(&sub, tmpl->insn_sizes[i]);
            bw_write_bytes(&sub,
                           &tmpl->insn_bytes[(size_t)i * MAX_INSN_BYTES],
                           tmpl->insn_sizes[i]);

            /*
             * Optional dependency sub-block.  Two independent
             * families inside one block, controlled by dep_block_flags:
             *
             *   HAS_REG  — refiner-produced: which inputs feed each
             *              dst reg / each store's data
             *   HAS_ADDR — walker-produced: which src_regs feed each
             *              load/store ADDRESS (so the consumer knows
             *              when each memop can fire)
             *
             * Mask array sizes all come from the outer template
             * header (n_dst, max_dep_loads, max_dep_stores); the
             * block carries only the dep_block_flags byte + masks.
             * Bit layouts diverge: HAS_REG masks address the full
             * input pool (src_regs + load_data + imm); HAS_ADDR
             * masks omit the load_data band because addresses are
             * computed before any load fires.
             */
            if (fld->has_reg_deps || fld->has_addr_deps) {
                uint8_t dep_flags = 0;
                if (fld->has_reg_deps)  dep_flags |= CST_DEP_BLOCK_HAS_REG;
                if (fld->has_addr_deps) dep_flags |= CST_DEP_BLOCK_HAS_ADDR;
                bw_write_u8(&sub, dep_flags);
                if (fld->has_reg_deps) {
                    for (uint8_t d = 0; d < fld->n_dst_regs; d++) {
                        bw_write_uleb128(&sub, fld->dst_dep_mask[d]);
                    }
                    for (uint8_t s = 0; s < fld->max_dep_stores; s++) {
                        bw_write_uleb128(&sub, fld->store_data_dep_mask[s]);
                    }
                }
                if (fld->has_addr_deps) {
                    for (uint8_t l = 0; l < fld->max_dep_loads; l++) {
                        bw_write_uleb128(&sub, fld->load_addr_dep_mask[l]);
                    }
                    for (uint8_t s = 0; s < fld->max_dep_stores; s++) {
                        bw_write_uleb128(&sub, fld->store_addr_dep_mask[s]);
                    }
                }
            }
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

/*
 * Materialise a U512 holding (cur - base) in mod 2^512 / two's-
 * complement form, given two u64 inputs.  Equivalent to
 * u512_sub(cst_wide_from_u64(cur), cst_wide_from_u64(base)) but
 * skips the round-trip through two stack-resident U512s — used by
 * the narrow extract fast path in emit_field_delta_section so the
 * dominant scalar-unchanged case never materialises a U512 at all
 * and the rare staged-record case materialises one directly.
 */
static inline U512 u512_from_u64_diff(uint64_t cur, uint64_t base)
{
    U512 r;
    r.limb[0] = cur - base;
    /* Sign-extend the borrow.  When cur >= base the diff fits in u64
     * and the upper limbs are 0; when cur < base the diff is
     * negative and 2's-complement-extends to all 1s. */
    uint64_t fill = (cur < base) ? UINT64_MAX : 0;
    for (size_t i = 1; i < G_N_ELEMENTS(r.limb); i++) {
        r.limb[i] = fill;
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
    FIELD_STATE_SLOT_INVALID = 0xFFFFu,
    /* Layout: 1 (N_LOADS) + 1 (N_STORES) + 1 (METAFLAGS) + 5
     * (slotted families) × CST_FID_SLOT_COUNT + 7 (insn-metadata
     * bytes_lo..size).  EXTENDED has no persistent state cell.
     * Keep the matching FIELD_STATE_SLOT_COUNT in tools/cst_decode.h
     * in sync when this grows.                                       */
    FIELD_STATE_SLOT_COUNT = 3 + (5 * CST_FID_SLOT_COUNT) + 7,
    /* Field-ID space is now ULEB128 — FIDs reach ~330 for slot 63 of
     * the last family.  Round up to the next power of two so the
     * fid -> slot lookup stays a single load with no bounds dance. */
    FIELD_STATE_LUT_SIZE   = 512,
};

typedef struct FieldStateBlock {
    uint32_t n_insns;
    U512 *values;
    uint32_t *generations;
} FieldStateBlock;

/*
 * Per-(template_id) FieldStateBlock cache.  Template IDs are dense
 * positive integers handed out by BBTemplateCache starting from 1,
 * so a vector indexed by template_id replaces the per-entry glib
 * hash lookup that profiling at ~10 % of total runtime on mcf.
 * Slot 0 is unused (template_id 0 is reserved as "no template").
 * The vector grows on demand when a never-seen-before template_id
 * arrives; existing pointers are stable across grows because
 * std::vector<T*> only reallocates the pointer array.
 */
struct FieldStateTable {
    std::vector<FieldStateBlock *> blocks;  /* index = template_id */
    uint32_t generation;
};

/*
 * Field-id → slot-index lookup table.  Built once at first call so
 * the hot encoder loop does a single byte-load per record instead of
 * the eight-branch chain the original implementation used.  At ~80 M
 * calls on a 5 M-insn mcf trace, the chain showed up as 2.6 % of
 * total runtime; the table form drops that to a rounding error.
 */
static uint16_t g_field_state_slot_lut[FIELD_STATE_LUT_SIZE];
static bool     g_field_state_slot_lut_built = false;

/* FIELD_STATE_SLOT_COUNT layout (matches the LUT below):
 *   slot 0:   N_LOADS
 *   slot 1:   N_STORES
 *   slot 2:   METAFLAGS
 *   slot 3:   LOAD_ADDR[0]      ... slot (3 + 5*k):     LOAD_ADDR[k]
 *   slot 4:   STORE_ADDR[0]     ... slot (3 + 5*k + 1): STORE_ADDR[k]
 *   slot 5:   LOAD_DATA[0]      ... slot (3 + 5*k + 2): LOAD_DATA[k]
 *   slot 6:   STORE_DATA[0]     ... slot (3 + 5*k + 3): STORE_DATA[k]
 *   slot 7:   DST_REG[0]        ... slot (3 + 5*k + 4): DST_REG[k]
 *   slot (3 + 5*N): INSN_BYTES_LO ... INSN_SIZE  (N = CST_FID_SLOT_COUNT)
 * Total = 3 + 5*N + 7 = FIELD_STATE_SLOT_COUNT. */
static void field_state_slot_lut_build(void)
{
    for (unsigned i = 0; i < FIELD_STATE_LUT_SIZE; i++) {
        g_field_state_slot_lut[i] = FIELD_STATE_SLOT_INVALID;
    }
    g_field_state_slot_lut[CST_FID_N_LOADS]   = 0;
    g_field_state_slot_lut[CST_FID_N_STORES]  = 1;
    g_field_state_slot_lut[CST_FID_METAFLAGS] = 2;

    static const uint8_t fam_base[5] = {
        CST_FID_LOAD_ADDR_BASE,
        CST_FID_STORE_ADDR_BASE,
        CST_FID_LOAD_DATA_BASE,
        CST_FID_STORE_DATA_BASE,
        CST_FID_DST_REG_BASE,
    };
    for (unsigned k = 0; k < CST_FID_SLOT_COUNT; k++) {
        for (unsigned f = 0; f < G_N_ELEMENTS(fam_base); f++) {
            unsigned fid = fam_base[f] + k * CST_FID_SLOT_STRIDE;
            g_field_state_slot_lut[fid] = (uint16_t)(3 + 5 * k + f);
        }
    }
    unsigned slotted_dense_end = 3 + 5 * CST_FID_SLOT_COUNT;
    for (unsigned f = CST_FID_INSN_BYTES_LO; f <= CST_FID_INSN_SIZE; f++) {
        g_field_state_slot_lut[f] =
            (uint16_t)(slotted_dense_end + (f - CST_FID_INSN_BYTES_LO));
    }
    g_field_state_slot_lut_built = true;
}

static inline uint16_t field_state_slot_index(unsigned field_id)
{
    if (field_id >= FIELD_STATE_LUT_SIZE) return FIELD_STATE_SLOT_INVALID;
    return g_field_state_slot_lut[field_id];
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
    FieldStateTable *table = new FieldStateTable();
    table->generation = 1;
    return table;
}

static void field_state_table_free(FieldStateTable *table)
{
    if (!table) {
        return;
    }
    for (FieldStateBlock *b : table->blocks) {
        field_state_block_free(b);
    }
    delete table;
}

static FieldStateBlock *field_state_table_get_block(FieldStateTable *table,
                                                    uint32_t template_id,
                                                    const BBTemplate *tmpl,
                                                    bool create)
{
    if (template_id < table->blocks.size()) {
        FieldStateBlock *block = table->blocks[template_id];
        if (block) {
            return block;
        }
    }
    if (!create || !tmpl) {
        return nullptr;
    }

    if (template_id >= table->blocks.size()) {
        table->blocks.resize((size_t)template_id + 1, nullptr);
    }

    FieldStateBlock *block = g_new0(FieldStateBlock, 1);
    block->n_insns = tmpl->n_insns;
    size_t n_slots = (size_t)block->n_insns * FIELD_STATE_SLOT_COUNT;
    block->values = g_new0(U512, n_slots ? n_slots : 1);
    block->generations = g_new0(uint32_t, n_slots ? n_slots : 1);
    table->blocks[template_id] = block;
    return block;
}

static inline bool field_state_block_get(FieldStateBlock *block,
                                         uint32_t table_generation,
                                         uint32_t ins_pos,
                                         uint16_t slot_index,
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
 * Narrow accessors over the same FieldStateBlock storage.  Field
 * families whose semantic value fits in u64 (memop counts /
 * addresses, opcode, branch type, instruction flags / immediates /
 * sizes, instruction byte words) read and write only ``limb[0]`` and
 * skip the 56-byte zeroing that the wide get/put would do — so the
 * dominant per-record cost of the encoder loop drops out.  Upper
 * limbs in narrow-family storage are never inspected; the family is
 * either narrow or wide for the lifetime of a trace, decided by
 * ``FieldDescriptor::extract_u64`` being non-null.
 */
static inline bool field_state_block_get_u64(FieldStateBlock *block,
                                             uint32_t table_generation,
                                             uint32_t ins_pos,
                                             uint16_t slot_index,
                                             uint64_t *out)
{
    if (!block || ins_pos >= block->n_insns ||
        slot_index == FIELD_STATE_SLOT_INVALID) {
        return false;
    }
    size_t index = ((size_t)ins_pos * FIELD_STATE_SLOT_COUNT) + slot_index;
    if (block->generations[index] != table_generation) {
        return false;
    }
    *out = block->values[index].limb[0];
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
    /* Base field ID for slot 0 of this family.  Wide enough to hold
     * the ULEB128 wire encoding's full range; values up to ~330
     * appear in practice for high-slot DST_REG entries. */
    uint16_t base_field_id;
    /* Distance in the FID space between slot k and slot k+1 of this
     * family.  1 for non-slotted singletons; CST_FID_SLOT_STRIDE for
     * the slotted families that share an interleaved range. */
    uint8_t  slot_stride;
    uint8_t  slot_count;        /* 1 for non-slotted families */
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
     * memop and DST_REG families to skip slots that the fixed
     * slot_count loop would visit only to have extract() return
     * false.  Null for families whose slot_count is the real bound
     * (or trivially 1). */
    uint8_t (*runtime_slot_cap)(const EntryView *ev, uint32_t i);

    /* Narrow (u64) fast-path siblings of extract / template_default.
     *
     * When non-null, the emitter takes a path that avoids
     * materialising a 64-byte U512 on the stack, comparing two u64s
     * by register value and only materialising a U512 at staging
     * time (rare — only when the field actually changed).  Profile
     * showed the U512 stack round-trip dominating the encoder hot
     * loop on mcf-like workloads.
     *
     * Both must be set together; when either is null the wide
     * extract/template_default pair is used (LOAD_DATA, STORE_DATA,
     * DST_REG — the families whose payload genuinely needs >64 bits). */
    bool (*extract_u64)(const EntryView *ev, uint32_t ins_pos, uint8_t slot,
                        uint64_t *out_val);
    uint64_t (*template_default_u64)(const BBTemplate *tmpl,
                                     uint32_t ins_pos, uint8_t slot);

    /* True iff the family's extract value equals its template_default
     * for every body entry of a given (template, ins_pos) — i.e. the
     * field is purely a function of the template, not of the run-time
     * entry.  Such families never produce wire records (cur == base
     * always), so the encoder hot loop can skip them entirely.
     * Differential timing showed these probes were ~50 % of the per-
     * slot cost on full-config mcf despite emitting nothing. */
    bool template_static;

    const char *name;          /* debug only */
} FieldDescriptor;

/* ---------- Per-family runtime slot caps ----------
 *
 * Memop families (LOAD_ADDR, STORE_ADDR, LOAD_DATA, STORE_DATA) and
 * DST_REG have CST_FID_SLOT_COUNT (16) wire slots but typical
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
static uint8_t cap_dst_regs(const EntryView *ev, uint32_t i)
{
    if (!ev->tmpl) return 0;
    return ev->tmpl->insn_fields[i].n_dst_regs;
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
 * destination operands only, in template-walk order.  The values are
 * captured POST-execution (the per-insn callback is registered on the
 * NEXT instruction, so it fires after the current insn completes;
 * for the LAST insn of a TB the next TB's tb_exec callback handles
 * the snap).  Source register identities remain in the template;
 * source values are not emitted on the wire — consumers can derive
 * any register's value at any point from the most recent post-exec
 * destination observation, which strictly dominates the pre-exec
 * source view (covers every architectural write, not just reads,
 * and there are typically fewer destinations than sources per insn). */
static bool extr_dst_reg(const EntryView *ev, uint32_t i, uint8_t slot,
                         U512 *out)
{
    if (!ev->reg_snaps || !ev->tmpl) return false;
    const InsnFields *f = &ev->tmpl->insn_fields[i];
    if (slot >= f->n_dst_regs) return false;
    uint32_t pos = ev->insn_rs_off[i] + slot;
    if (pos >= ev->reg_snaps->size()) return false;
    *out = (*ev->reg_snaps)[pos].value;
    return true;
}

/* ---------- Metaflags (CST_FID_METAFLAGS) -----------------------
 *
 * Per-insn canonical-flags byte derived from the architectural REG_FLAGS
 * dst snap.  The encoder finds the REG_FLAGS slot in the insn's dst_regs
 * list, reads its captured value, and applies the per-ISA bit-shuffle
 * via isa_properties[trace_isa].flags_to_metaflags.  Gated by both:
 *   - CST_FLAG_REG_DATA on the trace (no flags reg means no snap)
 *   - InsnFields.writes_int_flags (set during template build only on
 *     insns whose dst maps to the ISA's int-flags reg row, i.e.
 *     RegClassification.is_int_flags = true).
 * Emitted as a side-channel FID rather than a synthetic dst-register
 * so templates' dst_regs lists stay free of phantom architectural slots.
 */
static int find_flags_slot(const InsnFields *f)
{
    for (uint8_t k = 0; k < f->n_dst_regs; k++) {
        if (f->dst_regs[k] == REG_FLAGS) {
            return (int)k;
        }
    }
    return -1;
}

static bool extr_metaflags(const EntryView *ev, uint32_t i, uint8_t slot,
                           U512 *out)
{
    if (slot != 0 || !ev->reg_snaps || !ev->tmpl) return false;
    const InsnFields *f = &ev->tmpl->insn_fields[i];
    if (!f->writes_int_flags) return false;
    int fs = find_flags_slot(f);
    if (fs < 0) return false;
    MetaFlagsMapperFn mapper = isa_properties[trace_isa].flags_to_metaflags;
    if (!mapper) return false;
    uint32_t pos = ev->insn_rs_off[i] + (uint32_t)fs;
    if (pos >= ev->reg_snaps->size()) return false;
    uint64_t raw = (*ev->reg_snaps)[pos].value.limb[0];
    *out = cst_wide_from_u64(mapper(raw));
    return true;
}

static bool extr_u64_metaflags(const EntryView *ev, uint32_t i, uint8_t slot,
                               uint64_t *out)
{
    if (slot != 0 || !ev->reg_snaps || !ev->tmpl) return false;
    const InsnFields *f = &ev->tmpl->insn_fields[i];
    if (!f->writes_int_flags) return false;
    int fs = find_flags_slot(f);
    if (fs < 0) return false;
    MetaFlagsMapperFn mapper = isa_properties[trace_isa].flags_to_metaflags;
    if (!mapper) return false;
    uint32_t pos = ev->insn_rs_off[i] + (uint32_t)fs;
    if (pos >= ev->reg_snaps->size()) return false;
    uint64_t raw = (*ev->reg_snaps)[pos].value.limb[0];
    *out = mapper(raw);
    return true;
}

static U512 deflt_metaflags(const BBTemplate *t, uint32_t i, uint8_t slot)
{
    (void)t; (void)i; (void)slot;
    return cst_wide_from_u64(0);
}
static uint64_t deflt_u64_metaflags(const BBTemplate *t, uint32_t i,
                                    uint8_t slot)
{
    (void)t; (void)i; (void)slot;
    return 0;
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
    flags |= (uint8_t)((f->sync_hint & 0x3) << CST_INSN_FLAG_SYNC_SHIFT);
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

/* ---------- Narrow (u64) extract/default callbacks ----------
 *
 * Mirror the wide callbacks above for every family whose semantic
 * value fits in u64 (everything except the 512-bit-wide LOAD_DATA /
 * STORE_DATA / DST_REG payloads).  These are what the emitter's
 * fast path uses; they avoid the U512 stack round-trip that
 * dominated profiling of emit_field_delta_section on mcf.
 */
static bool extr_u64_n_loads(const EntryView *ev, uint32_t i, uint8_t slot,
                             uint64_t *out)
{
    (void)slot;
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return false;
    *out = ev->actual_n_loads[i];
    return true;
}
static uint64_t deflt_u64_zero(const BBTemplate *t, uint32_t i, uint8_t slot)
{ (void)t; (void)i; (void)slot; return 0; }

static bool extr_u64_n_stores(const EntryView *ev, uint32_t i, uint8_t slot,
                              uint64_t *out)
{
    (void)slot;
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return false;
    *out = ev->actual_n_stores[i];
    return true;
}

static bool extr_u64_load_addr(const EntryView *ev, uint32_t i, uint8_t slot,
                               uint64_t *out)
{
    const DynParam *dp = find_memop_slot(ev, i, slot, DYN_LOAD_ADDR);
    if (!dp) return false;
    *out = dp->value;
    return true;
}

static bool extr_u64_store_addr(const EntryView *ev, uint32_t i, uint8_t slot,
                                uint64_t *out)
{
    const DynParam *dp = find_memop_slot(ev, i, slot, DYN_STORE_ADDR);
    if (!dp) return false;
    *out = dp->value;
    return true;
}

static uint64_t deflt_u64_insn_bytes_lo(const BBTemplate *t, uint32_t i,
                                        uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return 0;
    uint64_t v = 0;
    uint8_t sz = t->insn_sizes[i];
    if (sz > 8) sz = 8;
    const uint8_t *p = &t->insn_bytes[(size_t)i * MAX_INSN_BYTES];
    for (int b = 0; b < sz; b++) v |= ((uint64_t)p[b]) << (b * 8);
    return v;
}
static bool extr_u64_insn_bytes_lo(const EntryView *ev, uint32_t i,
                                   uint8_t slot, uint64_t *out)
{ *out = deflt_u64_insn_bytes_lo(ev->tmpl, i, slot); return true; }

static uint64_t deflt_u64_insn_bytes_hi(const BBTemplate *t, uint32_t i,
                                        uint8_t slot)
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
    return v;
}
static bool extr_u64_insn_bytes_hi(const EntryView *ev, uint32_t i,
                                   uint8_t slot, uint64_t *out)
{ *out = deflt_u64_insn_bytes_hi(ev->tmpl, i, slot); return true; }

static uint64_t deflt_u64_insn_opcode(const BBTemplate *t, uint32_t i,
                                      uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return 0;
    return (uint8_t)t->insn_fields[i].opcode;
}
static bool extr_u64_insn_opcode(const EntryView *ev, uint32_t i, uint8_t slot,
                                 uint64_t *out)
{ *out = deflt_u64_insn_opcode(ev->tmpl, i, slot); return true; }

static uint64_t deflt_u64_insn_branch_type(const BBTemplate *t, uint32_t i,
                                           uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return 0;
    return (uint8_t)t->insn_fields[i].branch_type;
}
static bool extr_u64_insn_branch_type(const EntryView *ev, uint32_t i,
                                      uint8_t slot, uint64_t *out)
{ *out = deflt_u64_insn_branch_type(ev->tmpl, i, slot); return true; }

static uint64_t deflt_u64_insn_flags(const BBTemplate *t, uint32_t i,
                                     uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return 0;
    const InsnFields *f = &t->insn_fields[i];
    uint8_t flags = 0;
    if (f->branch_conditional) flags |= CST_INSN_FLAG_BRANCH_COND;
    if (f->has_immediate)      flags |= CST_INSN_FLAG_HAS_IMM;
    flags |= (uint8_t)((f->sync_hint & 0x3) << CST_INSN_FLAG_SYNC_SHIFT);
    return flags;
}
static bool extr_u64_insn_flags(const EntryView *ev, uint32_t i, uint8_t slot,
                                uint64_t *out)
{ *out = deflt_u64_insn_flags(ev->tmpl, i, slot); return true; }

static uint64_t deflt_u64_insn_imm(const BBTemplate *t, uint32_t i,
                                   uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return 0;
    const InsnFields *f = &t->insn_fields[i];
    if (!f->has_immediate) return 0;
    return (uint64_t)(int64_t)f->immediate;
}
static bool extr_u64_insn_imm(const EntryView *ev, uint32_t i, uint8_t slot,
                              uint64_t *out)
{ *out = deflt_u64_insn_imm(ev->tmpl, i, slot); return true; }

static uint64_t deflt_u64_insn_size(const BBTemplate *t, uint32_t i,
                                    uint8_t slot)
{
    (void)slot;
    if (!t || i >= t->n_insns) return 0;
    return t->insn_sizes[i];
}
static bool extr_u64_insn_size(const EntryView *ev, uint32_t i, uint8_t slot,
                               uint64_t *out)
{ *out = deflt_u64_insn_size(ev->tmpl, i, slot); return true; }

/* Field family registry.
 *
 * Order matters for two reasons:
 *
 *  1. The per-insn emitter walks this table left-to-right and emits
 *     records in (ins_pos, descriptor-order) order.  The on-wire
 *     order is enforced as non-descending (ins_pos, field_id);
 *     within a single insn, the descriptor order must match the
 *     ascending field_id order the wire expects.  With the new
 *     interleaved-by-slot layout the bases are 0..7 (singletons +
 *     slot 0 of every family), so a table order of
 *
 *         N_LOADS, N_STORES, METAFLAGS,
 *         LOAD_ADDR, STORE_ADDR, LOAD_DATA, STORE_DATA, DST_REG,
 *         INSN_BYTES_LO, INSN_BYTES_HI, INSN_OPCODE, INSN_BRANCH_TYPE,
 *         INSN_FLAGS, INSN_IMMEDIATE, INSN_SIZE
 *
 *     matches what a decoder that resorted by field_id would expect.
 *
 *  2. The five slotted families share the same stride-5 ID space.
 *     Each slot k contributes one record per family that has an
 *     observation; the emitter visits descriptors in family order
 *     for slot k=0, then k=1, ... which produces ascending fids
 *     thanks to the interleave.  See the slot-stride note on
 *     FieldDescriptor.slot_stride. */
static const FieldDescriptor field_descriptors[] = {
        { CST_FID_N_LOADS,          1, 1,  false, false,
            extr_n_loads,        deflt_n_loads,         nullptr,
            extr_u64_n_loads,    deflt_u64_zero,
            false /* dynamic: actual_n_loads[i] */,
            "N_LOADS" },
        { CST_FID_N_STORES,         1, 1,  false, false,
            extr_n_stores,       deflt_n_stores,        nullptr,
            extr_u64_n_stores,   deflt_u64_zero,
            false /* dynamic: actual_n_stores[i] */,
            "N_STORES" },
        { CST_FID_METAFLAGS,        1, 1,  false, true,
            extr_metaflags,      deflt_metaflags,       nullptr,
            extr_u64_metaflags,  deflt_u64_metaflags,
            false /* dynamic: derived from REG_FLAGS snap per exec */,
            "METAFLAGS" },
        { CST_FID_LOAD_ADDR_BASE,   CST_FID_SLOT_STRIDE, CST_FID_SLOT_COUNT,
            false, false,
            extr_load_addr,      deflt_zero,            cap_loads,
            extr_u64_load_addr,  deflt_u64_zero,
            false /* dynamic: dyn_param value */,
            "LOAD_ADDR" },
        { CST_FID_STORE_ADDR_BASE,  CST_FID_SLOT_STRIDE, CST_FID_SLOT_COUNT,
            false, false,
            extr_store_addr,     deflt_zero,            cap_stores,
            extr_u64_store_addr, deflt_u64_zero,
            false /* dynamic: dyn_param value */,
            "STORE_ADDR" },
        { CST_FID_LOAD_DATA_BASE,   CST_FID_SLOT_STRIDE, CST_FID_SLOT_COUNT,
            true,  false,
            extr_load_data,      deflt_zero,            cap_loads,
            nullptr,             nullptr,
            false /* dynamic: memdata payload */,
            "LOAD_DATA" },
        { CST_FID_STORE_DATA_BASE,  CST_FID_SLOT_STRIDE, CST_FID_SLOT_COUNT,
            true,  false,
            extr_store_data,     deflt_zero,            cap_stores,
            nullptr,             nullptr,
            false /* dynamic: memdata payload */,
            "STORE_DATA" },
        { CST_FID_DST_REG_BASE,     CST_FID_SLOT_STRIDE, CST_FID_SLOT_COUNT,
            false, true,
            extr_dst_reg,        deflt_zero,            cap_dst_regs,
            nullptr,             nullptr,
            false /* dynamic: post-exec reg value */,
            "DST_REG" },
        { CST_FID_INSN_BYTES_LO,    1, 1,  false, false,
            extr_insn_bytes_lo,  deflt_insn_bytes_lo,   nullptr,
            extr_u64_insn_bytes_lo, deflt_u64_insn_bytes_lo,
            true /* extract == template_default */,
            "INSN_BYTES_LO" },
        { CST_FID_INSN_BYTES_HI,    1, 1,  false, false,
            extr_insn_bytes_hi,  deflt_insn_bytes_hi,   nullptr,
            extr_u64_insn_bytes_hi, deflt_u64_insn_bytes_hi,
            true /* extract == template_default */,
            "INSN_BYTES_HI" },
        { CST_FID_INSN_OPCODE,      1, 1,  false, false,
            extr_insn_opcode,    deflt_insn_opcode,     nullptr,
            extr_u64_insn_opcode, deflt_u64_insn_opcode,
            true /* extract == template_default */,
            "OPCODE" },
        { CST_FID_INSN_BRANCH_TYPE, 1, 1,  false, false,
            extr_insn_branch_type, deflt_insn_branch_type, nullptr,
            extr_u64_insn_branch_type, deflt_u64_insn_branch_type,
            true /* extract == template_default */,
            "BRANCH_TYPE" },
        { CST_FID_INSN_FLAGS,       1, 1,  false, false,
            extr_insn_flags,     deflt_insn_flags,      nullptr,
            extr_u64_insn_flags, deflt_u64_insn_flags,
            true /* extract == template_default */,
            "INSN_FLAGS" },
        { CST_FID_INSN_IMMEDIATE,   1, 1,  false, false,
            extr_insn_imm,       deflt_insn_imm,        nullptr,
            extr_u64_insn_imm,   deflt_u64_insn_imm,
            true /* extract == template_default */,
            "IMMEDIATE" },
        { CST_FID_INSN_SIZE,        1, 1,  false, false,
            extr_insn_size,      deflt_insn_size,       nullptr,
            extr_u64_insn_size,  deflt_u64_insn_size,
            true /* extract == template_default */,
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

    /* Reg_snaps: per-insn destination operands only, in template-walk
     * order.  Each entry's reg_snaps array is sized n_dst_regs per
     * insn (post-exec destination values). */
    uint32_t r = 0;
    for (uint32_t i = 0; i < n; i++) {
        insn_rs_off[i] = r;
        const InsnFields *f = &tmpl->insn_fields[i];
        r += f->n_dst_regs;
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
                            uint16_t field_id,
                            const FieldDescriptor *fd,
                            const BBTemplate *tmpl,
                            uint8_t slot)
{
    U512 cur;
    uint16_t slot_index = field_state_slot_index(field_id);
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
                            uint16_t field_id,
                            U512 v)
{
    uint16_t slot_index = field_state_slot_index(field_id);
    if (!state_block || ins_pos >= state_block->n_insns ||
        slot_index == FIELD_STATE_SLOT_INVALID) {
        return;
    }
    size_t index = ((size_t)ins_pos * FIELD_STATE_SLOT_COUNT) + slot_index;
    state_block->values[index] = v;
    state_block->generations[index] = state_generation;
}

typedef struct StageRec {
    uint32_t pos;
    /* Wire-format FID, widened from u8 since 0x1D — slot 63 of the
     * last slotted family reaches ID 322. */
    uint16_t fid;
    U512     delta;
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

/* CP memop overflow warning.  When an instruction's dynamic
 * memop count would exceed CST_FID_SLOT_COUNT, the slot loop
 * silently clamps and we emit one line to unknown_warnings.log
 * per entry — the cap is set well above realistic ISA ceilings
 * (AVX-512 ≤ 16, max-VLEN SVE ≤ 64), so any overflow is worth
 * a per-occurrence breadcrumb. */
static void warn_memop_overflow(const BBTemplate *tmpl, uint32_t insn_i,
                                uint32_t n_loads, uint32_t n_stores)
{
    if (!unknown_warn_file || !tmpl || insn_i >= tmpl->n_insns) return;
    if (n_loads <= CST_FID_SLOT_COUNT && n_stores <= CST_FID_SLOT_COUNT) {
        return;
    }
    const InsnFields *f = &tmpl->insn_fields[insn_i];
    uint64_t pc = tmpl->insn_pcs ? tmpl->insn_pcs[insn_i] : 0;
    g_mutex_lock(&unknown_warn_lock);
    fprintf(unknown_warn_file,
            "pc=0x%" PRIx64 " isa=%u reason=memop_overflow "
            "n_loads=%u n_stores=%u cap=%u opcode=%u\n",
            pc, (unsigned)trace_isa,
            n_loads, n_stores, (unsigned)CST_FID_SLOT_COUNT,
            (unsigned)f->opcode);
    fflush(unknown_warn_file);
    g_mutex_unlock(&unknown_warn_lock);
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
                                     BodyStreamState *st,
                                     FieldStateTable *state,
                                     FieldStateTable *base_state,
                                     uint32_t template_id,
                                     const EntryView *ev,
                                     bool is_wp,
                                     uint8_t header_flags)
{
    /* rec_bw is a thin BitWriter wrapping st->rec_scratch (now a
     * RawBuf, not a GByteArray).  Reset the buffer's length to 0 so
     * the previous entry's payload is overwritten without freeing
     * the underlying allocation. */
    BitWriter rec_bw;
    bw_init_rb(&rec_bw, &st->rec_scratch);
    raw_buf_clear(&st->rec_scratch);

    /* Reuse the per-stream StageRec buffer.  Length resets each call;
     * capacity grows on demand via stage_rec_append's g_realloc_n
     * path and is synced back to BodyStreamState before return so
     * the next entry sees the larger capacity too. */
    unsigned int stage_len = 0;
    unsigned int stage_cap = (unsigned int)st->stage_cap;
    StageRec *stage = st->stage_buf;

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
            /* Diagnostic: warn when the dynamic memop count would
             * exceed CST_FID_SLOT_COUNT.  The slot loop below will
             * silently clamp to the cap; this log line surfaces the
             * truncation so it doesn't get lost. */
            uint32_t insn_n_loads  = ev->actual_n_loads
                ? ev->actual_n_loads[i]  : 0;
            uint32_t insn_n_stores = ev->actual_n_stores
                ? ev->actual_n_stores[i] : 0;
            warn_memop_overflow(ev->tmpl, i, insn_n_loads, insn_n_stores);

            for (size_t d = 0; d < N_FIELD_DESCRIPTORS; d++) {
                const FieldDescriptor *fd = &field_descriptors[d];
                /* Template-static families (OPCODE, BRANCH_TYPE,
                 * INSN_BYTES_*, IMMEDIATE, FLAGS, SIZE) have
                 * extract == template_default for every body entry of
                 * a given (template, ins_pos), so cur == base always
                 * and they never produce a wire record.  Skip the
                 * probe entirely — the wire output is identical to
                 * iterating them and seeing every probe land on the
                 * cur == base continue. */
                if (fd->template_static)
                    continue;
                if (fd->gated_by_mem_data && !(header_flags & CST_FLAG_MEM_DATA))
                    continue;
                if (fd->gated_by_reg_data && !(header_flags & CST_FLAG_REG_DATA))
                    continue;

                uint8_t cap = fd->runtime_slot_cap
                    ? fd->runtime_slot_cap(ev, i)
                    : fd->slot_count;
                if (fd->extract_u64) {
                    /* Narrow fast path.  Compares two u64s in
                     * registers; only materialises a U512 (via
                     * u512_from_u64_diff) when the field actually
                     * changed and we're staging a record.  Skips
                     * the per-probe stack round-trip that
                     * dominated the wide path on mcf. */
                    for (uint8_t slot = 0; slot < cap; slot++) {
                        uint64_t cur;
                        if (!fd->extract_u64(ev, i, slot, &cur)) continue;
                        uint16_t fid = (uint16_t)(fd->base_field_id +
                                                  slot * fd->slot_stride);
                        uint16_t slot_index = field_state_slot_index(fid);
                        uint64_t base;
                        if (!field_state_block_get_u64(state_block,
                                                       state_generation,
                                                       i, slot_index, &base) &&
                            !field_state_block_get_u64(base_block,
                                                       base_generation,
                                                       i, slot_index, &base)) {
                            base = fd->template_default_u64(ev->tmpl, i, slot);
                        }
                        if (cur == base) continue;
                        StageRec rec = {};
                        rec.pos = i;
                        rec.fid = fid;
                        rec.delta = u512_from_u64_diff(cur, base);
                        stage_rec_append(&stage, &stage_len, &stage_cap, rec);
                        /* Update narrow state: limb[0] only.  Wide
                         * fields use a different family so this
                         * residue-in-upper-limbs is invisible to
                         * any subsequent read. */
                        if (state_block && i < state_block->n_insns &&
                            slot_index != FIELD_STATE_SLOT_INVALID) {
                            size_t idx = ((size_t)i * FIELD_STATE_SLOT_COUNT)
                                         + slot_index;
                            state_block->values[idx].limb[0] = cur;
                            state_block->generations[idx] = state_generation;
                        }
                    }
                } else {
                    /* Wide path: 64-byte payload families
                     * (LOAD_DATA, STORE_DATA, DST_REG). */
                    for (uint8_t slot = 0; slot < cap; slot++) {
                        U512 cur;
                        if (!fd->extract(ev, i, slot, &cur)) continue;
                        uint16_t fid = (uint16_t)(fd->base_field_id +
                                                  slot * fd->slot_stride);
                        U512 base =
                            field_state_get(state_block, state_generation,
                                            base_block, base_generation,
                                            i, fid, fd, ev->tmpl, slot);
                        if (u512_equal(cur, base)) continue;
                        StageRec rec = {};
                        rec.pos = i;
                        rec.fid = fid;
                        rec.delta = u512_sub(cur, base);
                        stage_rec_append(&stage, &stage_len, &stage_cap, rec);
                        field_state_put(state_block, state_generation,
                                        i, fid, cur);
                    }
                }
            }
        }
    }

    /* Wire format requires non-descending (ins_pos, fid) order.  The
     * collection loop above visits descriptors in family-major order,
     * which produces ascending fids per-insn EXCEPT for the slotted
     * families' interleaved layout (slot k of LOAD_ADDR is at the
     * same FID range as slot 0 of STORE_ADDR + stride, etc.).  Sort
     * by (pos, fid) here so the wire emit can rely on monotonicity. */
    if (stage_len > 1) {
        std::stable_sort(stage, stage + stage_len,
            [](const StageRec &a, const StageRec &b) {
                if (a.pos != b.pos) return a.pos < b.pos;
                return a.fid < b.fid;
            });
    }

    uint64_t section_start = bw_tell_bytes(main_bw);

    /* Build payload in rec_bw, then emit as length-prefixed section.
     * Format version 0x1D: fid is ULEB128 (was u8 through 0x1C). */
    bw_write_uleb128(&rec_bw, stage_len);
    for (unsigned int r = 0; r < stage_len; r++) {
        StageRec *s = &stage[r];
        uint64_t gap = (uint64_t)(s->pos - prev_pos);
        bw_write_uleb128(&rec_bw, gap);
        bw_write_uleb128(&rec_bw, s->fid);
        bw_write_sleb128_u512(&rec_bw, s->delta);
        prev_pos = s->pos;
    }
    bw_byte_align(&rec_bw);
    /* Write the section directly from the scratch buffer without
     * freeing it — st->rec_scratch persists for the next entry. */
    bw_write_uleb128(main_bw, st->rec_scratch.len);
    bw_raw(main_bw, st->rec_scratch.data, st->rec_scratch.len);

    /* Sync any stage_buf growth back to BodyStreamState. */
    st->stage_buf = stage;
    st->stage_cap = stage_cap;

    uint64_t bits = (bw_tell_bytes(main_bw) - section_start) * 8;
    if (is_wp) g_stats.bin_dyn_wp_bits += bits;
    else       g_stats.bin_dyn_cp_bits += bits;
}

/* ========================= Body stream ========================= */

BodyStreamState *body_stream_new(WriterCtx *w, const char *seg_datetime,
                                 uint64_t start_insn,
                                 uint64_t warmup_insns,
                                 uint64_t total_target_insns,
                                 const std::vector<InitialRegSnap> *regfile)
{
    if (!g_field_state_slot_lut_built) {
        field_state_slot_lut_build();
    }

    /*
     * BodyStreamState contains std::vector members, so we use new
     * instead of g_new0.  body_stream_finish frees inner resources
     * (per-thread FSTs, scratch arrays) but does not delete the
     * struct itself — it lives until segment-manager swap (next
     * body_stream_new) at which point the previous one is dropped on
     * the floor.  One-shot single-segment runs leak it to process
     * exit either way.
     */
    BodyStreamState *st = new BodyStreamState();

    /* Body destination — bw streams directly to the body member's
     * compression pipe / file via @w.  Body contents start with
     * CST_MAGIC (so a stripped body member is still recognisable)
     * and end with a trailing CST_MAGIC at body_stream_finish so
     * truncation is detectable from either end. */
    bw_init_writer(&st->bw, w);
    bw_write_u32_le(&st->bw, CST_MAGIC);

    /* Header destination — buffered in memory until body_stream_
     * finish flushes it to the segment manager's header writer.
     * Layout: magic, isa, flags, window descriptors, strings,
     * encoding maps, then (appended at finish) the templates
     * section.  No trailer.  All offsets are implicit since the
     * header is its own self-contained file in the tar. */
    bw_init_buf(&st->header_bw);
    bw_write_u32_le(&st->header_bw, CST_MAGIC);
    bw_write_u8(&st->header_bw, (uint8_t)trace_isa);

    uint8_t flags = 0;
    if (enable_mem_data) {
        flags |= CST_FLAG_MEM_DATA;
    }
    if (enable_reg_data) {
        flags |= CST_FLAG_REG_DATA;
    }
    bw_write_u8(&st->header_bw, flags);
    st->header_flags = flags;

    /* Segment instruction-window descriptors:
     *   start_insn          : architectural icount where this segment
     *                         begins.  Lets consumers anchor body
     *                         records to a global insn timeline.
     *   warmup_insns        : insns at the start of this trace meant
     *                         to prime caches/predictors and not be
     *                         evaluated.  Zero for non-simpoint runs.
     *   total_target_insns  : the configured length of the segment.
     *                         simpoint mode = warmup + simulation;
     *                         non-simpoint with explicit stop =
     *                         stop - start; non-simpoint without an
     *                         explicit stop = 0 (meaning unbounded:
     *                         the trace runs until process exit).
     *                         This is the targeted value, not the
     *                         observed one — overshoot due to TB
     *                         granularity is not reflected here. */
    bw_write_uleb128(&st->header_bw, start_insn);
    bw_write_uleb128(&st->header_bw, warmup_insns);
    bw_write_uleb128(&st->header_bw, total_target_insns);

    {
        const char *cmd = qemu_command_line ? qemu_command_line : "";
        size_t len = strlen(cmd);
        bw_write_uleb128(&st->header_bw, len);
        bw_write_bytes(&st->header_bw, (const uint8_t *)cmd, len);
    }
    {
        const char *dt_str = (seg_datetime && *seg_datetime) ? seg_datetime : "";
        size_t len = strlen(dt_str);
        bw_write_uleb128(&st->header_bw, len);
        bw_write_bytes(&st->header_bw, (const uint8_t *)dt_str, len);
    }
    {
        const char *comment = trace_comment ? trace_comment : "";
        size_t len = strlen(comment);
        bw_write_uleb128(&st->header_bw, len);
        bw_write_bytes(&st->header_bw, (const uint8_t *)comment, len);
    }
    {
        const char *tname = target_name ? target_name : "";
        size_t len = strlen(tname);
        bw_write_uleb128(&st->header_bw, len);
        bw_write_bytes(&st->header_bw, (const uint8_t *)tname, len);
    }

    write_header_encoding_maps(&st->header_bw);
    bw_byte_align(&st->header_bw);

    /* Flush the body magic prefix.  Body content (BODY_TAG_*
     * records) starts at offset 4 in the body member; consumers
     * verify the leading u32 against CST_MAGIC before parsing. */
    bw_byte_align(&st->bw);
    bw_flush(&st->bw);

    st->current_thread = 0;

    /*
     * Per-thread FieldStateTables are lazy-allocated on first emit
     * for each thread (see get_or_create_per_thread_fst).  vectors
     * start empty.
     */
    st->iframe_cp_scratch = nullptr;  /* lazy on first IFRAME */
    st->iframe_wp_scratch = nullptr;

    /*
     * The segment-starting vCPU's regfile, if the caller supplied one
     * with at least one live (width>0) value, is held until that
     * thread's first body emit (where it's written out as
     * BODY_TAG_REGFILE).  Threads other than the seed capture their
     * regfile live at first emit.  Install-time segment opens
     * (cpu_index = -1, no vCPU context yet) produce a stub regfile
     * with all width=0; we treat those as absent and let every thread
     * capture live, which gets meaningful values rather than the
     * empty stub.
     *
     * The seed thread is whichever vCPU triggered start_trace_
     * segment; thread_id 0 is assigned to the first vCPU observed
     * in the segment by get_or_assign_thread_id, which is also the
     * segment-starting vCPU in single-threaded launches.  For
     * multi-vCPU launches where another thread races in before the
     * seed thread's first body emit, the seed thread gets a higher
     * thread_id and we lose the seed; the regfile for the seed vCPU
     * is then re-captured live at its first emit (post-first-BB),
     * same fallback as for joiners.
     */
    bool any_live = false;
    if (regfile) {
        for (const InitialRegSnap &s : *regfile) {
            if (s.width_bytes > 0) { any_live = true; break; }
        }
    }
    if (any_live) {
        st->seed_regfile = *regfile;
        st->seed_thread = 0;
    }

    /* Pre-allocate the encoder's per-entry scratch.  Sized
     * generously enough that the typical body record never
     * triggers a realloc; growth on demand handles outliers. */
    raw_buf_init(&st->rec_scratch);
    raw_buf_reserve(&st->rec_scratch, 256);
    st->stage_cap = 64;
    st->stage_buf = (StageRec *)g_malloc(sizeof(StageRec) * st->stage_cap);

    return st;
}

/*
 * Build an EntryView wrapping the captured per-entry data and emit
 * one length-prefixed delta_section.  The descriptor table in
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
    emit_field_delta_section(bw, st, state, base_state, template_id,
                             &ev, is_wp, st->header_flags);
}

/*
 * Emit one body-record payload (CP section + WP chain + WP events) using
 * the supplied overlays.  The header tag (BODY_TAG_ENTRY/IFRAME) is the
 * caller's responsibility, as is any tmpl_delta the record format
 * requires (ENTRY uses one; IFRAME omits it because it always inherits
 * the immediately-preceding ENTRY's template).
 *
 * cp_state / wp_state / wp_base are the FieldStateTable instances used
 * for delta encoding.  ENTRY passes the persistent overlays (so the
 * encoded deltas compress well and the post-record state reflects the
 * observation).  IFRAME passes per-IFRAME scratch overlays whose
 * generations have been bumped, so all baselines fall through to
 * template_default and every encoded value is absolute.  The scratch
 * overlays absorb the writes and are discarded by the next IFRAME's
 * generation bump — the persistent overlays are untouched, which is
 * what makes IFRAMEs validation-only redundant records.
 */
static void emit_body_record_payload(
    BodyStreamState *st, BitWriter *bw, BodyEntry *entry, uint32_t num_wp,
    FieldStateTable *cp_state, FieldStateTable *wp_state,
    FieldStateTable *wp_base)
{
    emit_one_bb_delta(bw, st, cp_state, entry->template_id, entry->tmpl,
                      &entry->dyn_params, &entry->reg_snaps, false);

    /* WP chain sub-section */
    {
        BitWriter sub;
        bw_init_buf(&sub);
        bw_write_uleb128(&sub, num_wp);
        int64_t prev_wp_template = 0;
        for (uint32_t w = 0; w < num_wp; w++) {
            const WPBBEntry *wp = &entry->wp_entries[w];
            uint32_t wp_tmpl = wp->template_id;
            bw_write_sleb128(&sub, (int64_t)wp_tmpl - prev_wp_template);
            prev_wp_template = wp_tmpl;
            emit_one_bb_delta_with_base(&sub, st, wp_state, wp_base,
                                        wp_tmpl, wp->tmpl,
                                        &wp->dyn_params, &wp->reg_snaps,
                                        true);
        }
        bw_byte_align(&sub);
        bw_write_section(bw, bw_finish_buf(&sub));
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
            if (wp->fault) {
                bw_write_uleb128(&sub, (uint64_t)wp->fault_insn_index);
            }
            prev_event_idx = w;
        }
        g_stats.bin_wp_exception_bits += (bw_tell_bytes(&sub) - ev_start) * 8;

        bw_byte_align(&sub);
        bw_write_section(bw, bw_finish_buf(&sub));
    }
}

/*
 * Lazily allocate or fetch the per-thread FieldStateTable at @vec[tid].
 * Resizes the vector to fit and creates a fresh table the first time
 * @tid is seen.  Result is stable across grows because the vector
 * holds pointers, not the table itself.
 */
static FieldStateTable *get_or_create_per_thread_fst(
    std::vector<FieldStateTable *> &vec, uint32_t tid)
{
    if (tid >= vec.size()) {
        vec.resize((size_t)tid + 1, nullptr);
    }
    if (!vec[tid]) {
        vec[tid] = field_state_table_new();
    }
    return vec[tid];
}

/*
 * Emit a BODY_TAG_REGFILE record for @thread_id carrying the absolute
 * register file in @snaps.  Wire format: tag, thread_id (varuint),
 * n_present (varuint), then for each present register
 * (gen_id u8, width u8, bytes[width]).  Only entries with
 * width_bytes > 0 are written; width=0 means "no live snapshot for
 * this gen-id at first-emit time" and the decoder leaves its slot
 * untouched.
 */
static void emit_regfile_record(BitWriter *bw, uint32_t thread_id,
                                const std::vector<InitialRegSnap> &snaps)
{
    uint64_t n_present = 0;
    for (const InitialRegSnap &s : snaps) {
        if (s.width_bytes > 0) n_present++;
    }
    bw_write_u8(bw, BODY_TAG_REGFILE);
    bw_write_uleb128(bw, thread_id);
    bw_write_uleb128(bw, n_present);
    for (const InitialRegSnap &s : snaps) {
        if (s.width_bytes == 0) continue;
        bw_write_u8(bw, s.gen_id);
        bw_write_u8(bw, s.width_bytes);
        bw_raw(bw, s.bytes, s.width_bytes);
    }
}

void body_stream_write_entry(BodyStreamState *st, BodyEntry *entry)
{
    int64_t entry_tmpl = entry->template_id;
    uint32_t num_wp = (uint32_t)entry->wp_entries.size();
    uint64_t body_start = bw_tell_bytes(&st->bw);
    uint32_t tid = entry->thread_id;

    dyn_params_sort_template_order(entry->dyn_params);
    for (uint32_t w = 0; w < num_wp; w++) {
        WPBBEntry &wp = entry->wp_entries[w];
        dyn_params_sort_template_order(wp.dyn_params);
    }

    if ((int64_t)tid != st->current_thread) {
        bw_write_u8(&st->bw, BODY_TAG_THREAD_SWITCH);
        bw_write_sleb128(&st->bw, (int64_t)tid - st->current_thread);
        st->current_thread = tid;
    }

    /*
     * Per-thread regfile emission.  The first body entry contributed
     * by each thread in a segment is preceded by a BODY_TAG_REGFILE
     * record so the consumer can prime that thread's simulator state
     * with absolute register values.
     * For the segment-starting thread we use the pre-first-BB
     * snapshot captured by start_trace_segment (seed_regfile);
     * threads joining later capture live registers at this point
     * (post-first-BB on their side — slightly later than the seed
     * thread but the best the plugin can do without a per-thread
     * pre-execution hook).
     */
    if (tid >= st->regfile_emitted.size()) {
        st->regfile_emitted.resize((size_t)tid + 1, false);
    }
    if (!st->regfile_emitted[tid]) {
        if ((int32_t)tid == st->seed_thread && !st->seed_regfile.empty()) {
            emit_regfile_record(&st->bw, tid, st->seed_regfile);
            st->seed_regfile.clear();
            st->seed_thread = -1;
        } else {
            std::vector<InitialRegSnap> snaps;
            capture_initial_regfile(entry->cpu_index, &snaps);
            emit_regfile_record(&st->bw, tid, snaps);
        }
        st->regfile_emitted[tid] = true;
    }

    /* Regular delta-encoded entry, against this thread's persistent
     * per-vCPU overlays.  Cross-thread interleaving uses different
     * FSTs so deltas stay within-thread (smaller, compressible). */
    FieldStateTable *cp_fst = get_or_create_per_thread_fst(
        st->cp_field_state, tid);
    FieldStateTable *wp_fst = get_or_create_per_thread_fst(
        st->wp_field_state, tid);

    bw_write_u8(&st->bw, BODY_TAG_ENTRY);
    bw_write_sleb128(&st->bw, entry_tmpl - st->prev_entry_template);
    st->prev_entry_template = entry_tmpl;
    emit_body_record_payload(st, &st->bw, entry, num_wp,
                             cp_fst, wp_fst, cp_fst);

    /*
     * IFRAME trigger.  When iframe_rate is set and this CP template's
     * per-template emission counter divides evenly, emit a redundant
     * BODY_TAG_IFRAME body record with the same payload (CP + WP chain
     * + WP events) but encoded against fresh scratch overlays — every
     * value lands as an absolute delta-from-template-default.  The
     * IFRAME does NOT advance st->prev_entry_template and does NOT
     * write a tmpl_delta (its template is implicitly the immediately-
     * preceding ENTRY's), so it is purely a validation/resync record
     * the decoder may cross-check against the regular ENTRY.
     */
    if (iframe_rate > 0 && entry->tmpl) {
        entry->tmpl->emit_count++;
        if ((entry->tmpl->emit_count % iframe_rate) == 0) {
            if (!st->iframe_cp_scratch) {
                st->iframe_cp_scratch = field_state_table_new();
            }
            if (!st->iframe_wp_scratch) {
                st->iframe_wp_scratch = field_state_table_new();
            }
            st->iframe_cp_scratch->generation++;
            st->iframe_wp_scratch->generation++;
            bw_write_u8(&st->bw, BODY_TAG_IFRAME);
            emit_body_record_payload(st, &st->bw, entry, num_wp,
                                     st->iframe_cp_scratch,
                                     st->iframe_wp_scratch,
                                     st->iframe_cp_scratch);
        }
    }

    bw_byte_align(&st->bw);

    st->num_entries++;
    g_stats.bin_body_bits += (bw_tell_bytes(&st->bw) - body_start) * 8;
}

/*
 * Finish the body stream and produce the header buffer.
 *
 * Body member layout (already in @st->bw, an open stream to the
 * body output destination):
 *
 *     CST_MAGIC  (already written at body_stream_new)
 *     BODY_TAG_* records ...
 *     BODY_TAG_END  num_entries
 *     CST_MAGIC   (trailing sentinel for truncation detection)
 *
 * Header buffer layout (in @st->header_bw, returned via the out-
 * param @header_bytes):
 *
 *     CST_MAGIC  isa  flags
 *     start_insn  warmup_insns  total_target_insns
 *     command-string  datetime-string  comment-string  target_name-string
 *     encoding-maps-section
 *     templates-section
 *
 * No trailer.  Each member is its own self-contained file in the
 * outer ustar archive that the segment manager assembles after
 * this call returns.  The two-magic bracket on the body member
 * makes truncation visible without reading the whole stream; the
 * header is small enough to round-trip in its entirety.
 *
 * Caller-owned @header_bytes receives the header buffer's bytes;
 * the BodyStreamState releases its reference to the underlying
 * GByteArray, so the caller is responsible for freeing it via
 * g_byte_array_unref.
 */
void body_stream_finish(BodyStreamState *st, GByteArray **header_bytes)
{
    uint64_t stats_start = bw_tell_bytes(&st->bw);

    /* --- Finalise the body member. --- */
    bw_write_u8(&st->bw, BODY_TAG_END);
    bw_write_uleb128(&st->bw, st->num_entries);
    bw_byte_align(&st->bw);
    /* Trailing CST_MAGIC: a consumer who reaches end-of-stream
     * without seeing this knows the body member was truncated.
     * Cheaper than a checksum and sufficient for our use case
     * (truncation is by far the most common corruption mode for
     * pipe-compressed traces — uncaught SIGPIPE, OOM, etc.). */
    bw_write_u32_le(&st->bw, CST_MAGIC);
    bw_flush(&st->bw);

    /* --- Append the templates section to the header buffer. --- */
    g_mutex_lock(&data_lock);
    write_bin_templates(&st->header_bw);
    g_mutex_unlock(&data_lock);
    bw_byte_align(&st->header_bw);

    /* Hand the accumulated header buffer to the caller.  bw_finish_
     * buf transfers ownership; we null out our pointer so subsequent
     * operations on @st can't accidentally touch the buffer. */
    *header_bytes = bw_finish_buf(&st->header_bw);

    uint64_t end_bytes = bw_tell_bytes(&st->bw);
    g_stats.bin_header_bits += (end_bytes - stats_start) * 8;
    g_stats.bin_total_bits += end_bytes * 8;

    for (FieldStateTable *t : st->cp_field_state) {
        if (t) field_state_table_free(t);
    }
    st->cp_field_state.clear();
    for (FieldStateTable *t : st->wp_field_state) {
        if (t) field_state_table_free(t);
    }
    st->wp_field_state.clear();
    if (st->iframe_cp_scratch) {
        field_state_table_free(st->iframe_cp_scratch);
    }
    if (st->iframe_wp_scratch) {
        field_state_table_free(st->iframe_wp_scratch);
    }
    entry_view_scratch_free(&st->ev_scratch);
    raw_buf_free(&st->rec_scratch);
    g_free(st->stage_buf);
    st->stage_buf = nullptr;
}

void body_stream_free(BodyStreamState *st)
{
    /* BodyStreamState is allocated with `new`; its std::vector
     * members need their destructors called.  body_stream_finish
     * already releases owned resources (FSTs, scratch arrays, the
     * header buffer); calling free here just tears down the C++
     * object itself. */
    if (!st) {
        return;
    }
    delete st;
}
