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
#include <unordered_map>
#include <unordered_set>

#include "champsim_tracer.h"
#include "champsim_tracer_bb_template_cache.h"
#include "champsim_tracer_branch_history.h"
#include "champsim_tracer_reg_handle_cache.h"
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
        /* Hot path: per-entry encoder scratch.  Inlined memcpy + length
         * bump with out-of-line grow (was ~1.5% of runtime in
         * g_byte_array_append). */
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

/*
 * RawBuf variant of the above: bind @sub to a reused scratch buffer
 * (cleared, no allocation), let the caller fill it, then emit it as a
 * length-prefixed sub-section.  No ownership transfer / free — the
 * scratch persists for the next record.  Pair bw_section_begin_rb with
 * bw_section_end_rb around the section body.
 */
static inline void bw_section_begin_rb(BitWriter *sub, RawBuf *scratch)
{
    raw_buf_clear(scratch);
    bw_init_rb(sub, scratch);
}

static inline void bw_section_end_rb(BitWriter *main_bw, RawBuf *scratch)
{
    bw_write_uleb128(main_bw, scratch->len);
    bw_raw(main_bw, scratch->data, scratch->len);
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
    /* "reg" map carries (id, name) pairs only; generic_reg_name()
     * returns NULL for unallocated holes.  Per-segment initial
     * register-file snapshots ride inline as BODY_TAG_REGFILE records,
     * one per (thread, segment). */
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

/*
 * Field-state storage class for a field-id (which plane it lands in).
 * Lifted above the encoding-map writer so the single slotted/lane family
 * table below can name the classes; FidLoc (which carries a cls) stays with
 * the field-state machinery.
 */
enum { FS_LOC_INVALID = 0, FS_LOC_SCALAR_FIXED = 1,
       FS_LOC_SCALAR_SLOT = 2, FS_LOC_WIDE_SLOT = 3 };

/*
 * The 8 stride-CST_FID_SLOT_STRIDE slotted field-id families, in wire order.
 * ONE source of truth shared by write_field_id_encoding_map (which needs the
 * base id + name prefix) and field_state_slot_lut_build (base + storage
 * class + ordinal within that class's plane), so the encoding map the trace
 * advertises and the writer's slot layout can never drift apart.
 */
struct SlottedFamily {
    uint16_t    base;
    const char *prefix;
    uint8_t     cls;   /* FS_LOC_SCALAR_SLOT | FS_LOC_WIDE_SLOT */
    uint8_t     ord;   /* ordinal within the cls plane */
};
static const SlottedFamily kSlottedFamilies[] = {
    { CST_FID_LOAD_ADDR_BASE,     "CST_FID_LOAD_ADDR",     FS_LOC_SCALAR_SLOT, 0 },
    { CST_FID_STORE_ADDR_BASE,    "CST_FID_STORE_ADDR",    FS_LOC_SCALAR_SLOT, 1 },
    { CST_FID_LOAD_DATA_BASE,     "CST_FID_LOAD_DATA",     FS_LOC_WIDE_SLOT,   0 },
    { CST_FID_STORE_DATA_BASE,    "CST_FID_STORE_DATA",    FS_LOC_WIDE_SLOT,   1 },
    { CST_FID_DST_REG_BASE,       "CST_FID_DST_REG",       FS_LOC_WIDE_SLOT,   2 },
    { CST_FID_LOAD_SIZE_BASE,     "CST_FID_LOAD_SIZE",     FS_LOC_SCALAR_SLOT, 2 },
    { CST_FID_STORE_SIZE_BASE,    "CST_FID_STORE_SIZE",    FS_LOC_SCALAR_SLOT, 3 },
    { CST_FID_DST_REG_WIDTH_BASE, "CST_FID_DST_REG_WIDTH", FS_LOC_SCALAR_SLOT, 4 },
};
/*
 * The 4 stride-CST_FID_LANE_BLOCK_STRIDE lane-mask families, in wire order.
 * All land in the scalar plane at ordinals 5 + index (continuing after the
 * slotted scalars).  Shared by the same two consumers.
 */
struct LaneFamily { uint16_t base; const char *prefix; };
static const LaneFamily kLaneFamilies[] = {
    { CST_FID_SRC_LANE_MASK_BASE,        "CST_FID_SRC_LANE_MASK"        },
    { CST_FID_DST_LANE_MASK_BASE,        "CST_FID_DST_LANE_MASK"        },
    { CST_FID_LOAD_DATA_LANE_MASK_BASE,  "CST_FID_LOAD_DATA_LANE_MASK"  },
    { CST_FID_STORE_DATA_LANE_MASK_BASE, "CST_FID_STORE_DATA_LANE_MASK" },
};
/*
 * The 2 stride-CST_FID_PPAGE_BLOCK_STRIDE physical-page families, in wire
 * order.  Both land in the scalar plane at ordinals 9 + index (continuing
 * after the lane masks).  Emitted only when g_features.physaddr — a
 * non-physaddr trace advertises none, so its field_id map is byte-identical
 * to a writer that predates the feature.  Shared by
 * write_field_id_encoding_map and field_state_slot_lut_build.
 */
struct PpageFamily { uint16_t base; const char *prefix; uint8_t ord; };
static const PpageFamily kPpageFamilies[] = {
    { CST_FID_LOAD_PPAGE_BASE,  "CST_FID_LOAD_PPAGE",  9  },
    { CST_FID_STORE_PPAGE_BASE, "CST_FID_STORE_PPAGE", 10 },
};

static void write_field_id_encoding_map(BitWriter *bw)
{
    /* Count: 3 hot singletons + 8 slotted families × CST_FID_SLOT_COUNT
     * + 4 lane-mask families × CST_FID_SLOT_COUNT + 7 insn-metadata
     * + 1 EXTENDED + 2 branch-outcome singletons (always present), plus
     * (physaddr only) 2 ppage families × slot count.  The ppage families are
     * advertised only when physical-page capture is active, so a
     * non-physaddr trace's map differs from a pre-branch writer's only by the
     * two always-on branch entries. */
    uint64_t n_entries =
        3 + (uint64_t)8 * CST_FID_SLOT_COUNT
          + (uint64_t)4 * CST_FID_SLOT_COUNT + 7 + 1 + 2;
    if (g_features.physaddr) {
        n_entries += (uint64_t)G_N_ELEMENTS(kPpageFamilies) * CST_FID_SLOT_COUNT;
    }
    bw_write_string(bw, "field_id");
    bw_write_uleb128(bw, n_entries);

    /* Hot singletons. */
    write_encoding_entry(bw, CST_FID_N_LOADS,   "CST_FID_N_LOADS");
    write_encoding_entry(bw, CST_FID_N_STORES,  "CST_FID_N_STORES");
    write_encoding_entry(bw, CST_FID_METAFLAGS, "CST_FID_METAFLAGS");

    /* Slotted families (shared kSlottedFamilies, wire order).  Slot k of
     * <F> is at base + k*CST_FID_SLOT_STRIDE; one (id, name) pair per slot
     * so decoders need not know the stride. */
    for (uint64_t k = 0; k < CST_FID_SLOT_COUNT; k++) {
        for (size_t f = 0; f < G_N_ELEMENTS(kSlottedFamilies); f++) {
            unsigned id = kSlottedFamilies[f].base
                + (unsigned)k * CST_FID_SLOT_STRIDE;
            g_autofree char *name = g_strdup_printf(
                "%s%" PRIu64, kSlottedFamilies[f].prefix, k);
            write_encoding_entry(bw, id, name);
        }
    }

    /* Lane-mask block (shared kLaneFamilies; separate from the hot slotted
     * block so it doesn't shift the cheaper 1-byte ULEB range). */
    for (uint64_t k = 0; k < CST_FID_SLOT_COUNT; k++) {
        for (size_t f = 0; f < G_N_ELEMENTS(kLaneFamilies); f++) {
            unsigned id = kLaneFamilies[f].base
                + (unsigned)k * CST_FID_LANE_BLOCK_STRIDE;
            g_autofree char *name = g_strdup_printf(
                "%s%" PRIu64, kLaneFamilies[f].prefix, k);
            write_encoding_entry(bw, id, name);
        }
    }

    /* Physical-page block (shared kPpageFamilies; separate stride-2 block
     * after EXTENDED so it shifts no pre-existing field-id).  Advertised
     * only under physaddr. */
    if (g_features.physaddr) {
        for (uint64_t k = 0; k < CST_FID_SLOT_COUNT; k++) {
            for (size_t f = 0; f < G_N_ELEMENTS(kPpageFamilies); f++) {
                unsigned id = kPpageFamilies[f].base
                    + (unsigned)k * CST_FID_PPAGE_BLOCK_STRIDE;
                g_autofree char *name = g_strdup_printf(
                    "%s%" PRIu64, kPpageFamilies[f].prefix, k);
                write_encoding_entry(bw, id, name);
            }
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
        /* Branch-outcome singletons: always advertised (unlike the gated
         * ppage families) so every branch-terminated entry can carry its
         * direction/target.  FID numbers sit after the ppage block, so no
         * pre-existing id moves. */
        { CST_FID_BRANCH_TAKEN,     "CST_FID_BRANCH_TAKEN" },
        { CST_FID_BRANCH_TARGET,    "CST_FID_BRANCH_TARGET" },
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

/* Whether the DEVIO_* body-tag names are advertised in the header
 * encoding map: true only when the disk-I/O hook is registered (system
 * mode + devio enabled), set via devio_set_map_active().  A device-free
 * trace keeps the historical body_tag vocabulary and stays
 * byte-identical. */
static bool g_devio_map_active = false;

static void write_header_encoding_maps(BitWriter *main_bw)
{
    /* opcode / branch_type / reg maps are driven by the shared name
     * helpers in champsim_tracer_generic_ids.h so symbolic names live
     * in one place across the encoder and the stats printer. */
    static const EncodingMapEntry header_flag_entries[] = {
        { CST_FLAG_MEM_DATA, "CST_FLAG_MEM_DATA" },
        { CST_FLAG_REG_DATA, "CST_FLAG_REG_DATA" },
        { CST_FLAG_PROFILE, "CST_FLAG_PROFILE" },
        { CST_FLAG_WP, "CST_FLAG_WP" },
        { CST_FLAG_FAULT, "CST_FLAG_FAULT" },
        /* PHYSADDR MUST stay last: advertised only when physical-page
         * capture is active (g_features.physaddr, system mode) so a
         * non-physaddr trace keeps the historical 5-entry header_flag
         * vocabulary and stays byte-identical.  The count is trimmed
         * below. */
        { CST_FLAG_PHYSADDR, "CST_FLAG_PHYSADDR" },
    };
    static const EncodingMapEntry insn_flag_entries[] = {
        { CST_INSN_FLAG_BRANCH_COND, "CST_INSN_FLAG_BRANCH_COND" },
        { CST_INSN_FLAG_HAS_IMM, "CST_INSN_FLAG_HAS_IMM" },
        { CST_INSN_FLAG_ATOMIC, "CST_INSN_FLAG_ATOMIC" },
        { CST_INSN_FLAG_VEC, "CST_INSN_FLAG_VEC" },
        { CST_INSN_FLAG_LANE_PARALLEL, "CST_INSN_FLAG_LANE_PARALLEL" },
        { CST_INSN_FLAG_HAS_DEP_BLOCK, "CST_INSN_FLAG_HAS_DEP_BLOCK" },
        { CST_INSN_FLAG_SYSTEM, "CST_INSN_FLAG_SYSTEM" },
    };
    static const EncodingMapEntry dep_block_flag_entries[] = {
        { CST_DEP_BLOCK_HAS_REG,  "CST_DEP_BLOCK_HAS_REG" },
        { CST_DEP_BLOCK_HAS_ADDR, "CST_DEP_BLOCK_HAS_ADDR" },
    };
    /* Template-profile-block self-description (format §6). */
    static const EncodingMapEntry mem_access_pattern_entries[] = {
        { CST_PAT_NONE,      "CST_PAT_NONE" },
        { CST_PAT_REGULAR,   "CST_PAT_REGULAR" },
        { CST_PAT_IRREGULAR, "CST_PAT_IRREGULAR" },
        { CST_PAT_RANDOM,    "CST_PAT_RANDOM" },
    };
    static const EncodingMapEntry profile_flag_entries[] = {
        { CST_PROFILE_ADDR_CP, "CST_PROFILE_ADDR_CP" },
        { CST_PROFILE_ADDR_WP, "CST_PROFILE_ADDR_WP" },
    };
    static const EncodingMapEntry body_tag_entries[] = {
        { BODY_TAG_END, "BODY_TAG_END" },
        { BODY_TAG_ENTRY, "BODY_TAG_ENTRY" },
        { BODY_TAG_THREAD_SWITCH, "BODY_TAG_THREAD_SWITCH" },
        { BODY_TAG_IFRAME, "BODY_TAG_IFRAME" },
        { BODY_TAG_REGFILE, "BODY_TAG_REGFILE" },
        { BODY_TAG_ASID_SWITCH, "BODY_TAG_ASID_SWITCH" },
        /* DEVIO_* MUST stay last: they are advertised only when the disk-I/O
         * hook is active (g_devio_map_active) so a device-free trace — every
         * user-mode trace — keeps the historical 6-entry body_tag vocabulary
         * and stays byte-identical.  The count is trimmed below. */
        { BODY_TAG_DEVIO_START, "BODY_TAG_DEVIO_START" },
        { BODY_TAG_DEVIO_STOP, "BODY_TAG_DEVIO_STOP" },
    };
    static const EncodingMapEntry wp_event_flag_entries[] = {
        { CST_WP_EVENT_TRANSLATION_UNAVAIL,
          "CST_WP_EVENT_TRANSLATION_UNAVAIL" },
        { CST_WP_EVENT_FAULT, "CST_WP_EVENT_FAULT" },
        /* CST_WP_EVENT_DEP_BRANCH_KILL (bit 2) retired — never emitted. */
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
    bw_write_uleb128(&sub, 12);
    write_named_enum_map(&sub, "opcode", GEN_OP_COUNT, generic_opcode_name);
    write_named_enum_map(&sub, "branch_type", BRANCH_TYPE_COUNT,
                         branch_type_name);
    write_reg_encoding_map(&sub);
    write_field_id_encoding_map(&sub);
    size_t n_header_flags = G_N_ELEMENTS(header_flag_entries);
    if (!g_features.physaddr) {
        n_header_flags -= 1;    /* omit the trailing CST_FLAG_PHYSADDR name */
    }
    write_encoding_map(&sub, "header_flag", header_flag_entries,
                       n_header_flags);
    write_encoding_map(&sub, "insn_flag", insn_flag_entries,
                       G_N_ELEMENTS(insn_flag_entries));
    size_t n_body_tags = G_N_ELEMENTS(body_tag_entries);
    if (!g_devio_map_active) {
        n_body_tags -= 2;   /* omit the trailing DEVIO_START / _STOP names */
    }
    write_encoding_map(&sub, "body_tag", body_tag_entries, n_body_tags);
    write_encoding_map(&sub, "wp_event_flag", wp_event_flag_entries,
                       G_N_ELEMENTS(wp_event_flag_entries));
    write_encoding_map(&sub, "metaflags", metaflags_entries,
                       G_N_ELEMENTS(metaflags_entries));
    write_encoding_map(&sub, "dep_block_flag", dep_block_flag_entries,
                       G_N_ELEMENTS(dep_block_flag_entries));
    write_encoding_map(&sub, "mem_access_pattern",
                       mem_access_pattern_entries,
                       G_N_ELEMENTS(mem_access_pattern_entries));
    write_encoding_map(&sub, "profile_flag", profile_flag_entries,
                       G_N_ELEMENTS(profile_flag_entries));
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
    /* Body stream — writes through @bw to the segment body output.
     * CST_MAGIC + BODY_TAG_* records + BODY_TAG_END/count/trailing
     * CST_MAGIC (truncation detectable from either end). */
    BitWriter bw;
    /* Header — in-memory GByteArray; templates section appended at
     * body_stream_finish, then handed to the segment manager. */
    BitWriter header_bw;
    int64_t prev_entry_template;
    int64_t current_thread;
    /* Active address-space (ASID) index, the second half of the body
     * context pair (thread_id, asid).  Base 0; the body's first record
     * is forced to be a BODY_TAG_ASID_SWITCH (see asid_announced), so
     * the starting asid arrives as an ordinary delta from 0. */
    int64_t current_asid;
    /* False until the first BODY_TAG_ASID_SWITCH; forces it so the
     * opening asid is an explicit delta-from-0, no implicit base — the
     * mandatory initial (asid, thread) declaration. */
    bool    asid_announced;
    /* Whether each asid index has already emitted its inline identity
     * (root_phys + sig).  Indexed by asid_index, grown on demand like
     * regfile_emitted: the identity rides an index's FIRST sighting
     * only, repeats carry the bare index. */
    std::vector<bool> asid_identity_emitted;
    /* Previous CP entry's template, so the *next* CP entry can
     * classify the prior BB's terminal-branch outcome for §6. */
    BBTemplate *prev_cp_tmpl;
    /* False until the first BODY_TAG_THREAD_SWITCH; forces it so the
     * starting thread is an explicit delta-from-0, no implicit base. */
    bool    thread_announced;
    /* Per-context field-state tables, keyed by the (asid_index,
     * thread_id) PAIR — a guest thread-pointer can collide across address
     * spaces, so the address space is part of the identity.  The combined
     * key is ((uint64_t)asid_index << 32) | thread_id; single-address-space
     * traces (asid_index == 0) key on thread_id exactly as before.  Tables
     * lazy-allocate on first emit.  Deltas stay within-context — a thread
     * that migrates across vCPUs keeps one id and one continuous overlay.
     * CP state persists across a context's entries; WP state is a per-chain
     * overlay falling back to that context's CP state. */
    std::unordered_map<uint64_t, FieldStateTable *> cp_field_state;
    std::unordered_map<uint64_t, FieldStateTable *> wp_field_state;
    /* Which (asid_index, thread_id) contexts have emitted their
     * BODY_TAG_REGFILE this segment (same combined key as the field-state
     * maps); presence == emitted. */
    std::unordered_set<uint64_t> regfile_emitted;
    /* Segment-starting vCPU's pre-first-BB regfile (captured by
     * start_trace_segment before any traced BB on that thread),
     * consumed at that thread's first emit then cleared.  Threads
     * joining later capture live at first emit (post-first-BB on
     * their side) — slight asymmetry; the seed thread is the common
     * case where pre-state matters most. */
    std::vector<InitialRegSnap> seed_regfile;
    int32_t                     seed_thread = -1;  /* -1 = unset */
    /* IFRAME scratch overlays: an IFRAME is a full body-record dump
     * encoded against fresh "nothing observed" overlays so every
     * record is absolute (generations bumped per IFRAME to invalidate
     * lazily).  Persistent cp/wp_field_state is untouched — the next
     * ENTRY continues uninterrupted.  Lazy on first IFRAME. */
    FieldStateTable *iframe_cp_scratch;
    FieldStateTable *iframe_wp_scratch;
    EntryViewScratch ev_scratch;
    /* Per-body-entry scratch reused across all entries (no per-record
     * malloc/free).  rec_scratch: RawBuf reset to len 0 per emit, then
     * copied into the main stream; allocation grows once to the
     * largest record (RawBuf not GByteArray so the encoder hot loop
     * bottoms out in an inlined memcpy — ~1.5% of runtime).  stage_buf:
     * reused StageRec[] the descriptor walk fills; raw pointer because
     * StageRec is defined further down this TU. */
    RawBuf rec_scratch;
    /* Reused scratch for the per-record WP chain / events sub-sections
     * (emit_body_record_payload).  Distinct from rec_scratch, which the
     * inner per-BB delta emit uses while this one accumulates the
     * enclosing section — both are live at once during WP-chain build.
     * Replaces a per-record g_byte_array_new/unref (~5.5% of cache
     * misses on a wp+memdata+regdata profile). */
    RawBuf sub_scratch;
    struct StageRec *stage_buf;
    size_t stage_cap;
    uint64_t num_entries;
    uint64_t body_off;
    uint8_t  header_flags;   /* CST_FLAG_* bits emitted in header */
    /* In-trace architectural CP-insn count at the warmup→simulation
     * transition for this segment.  Stashed by the segment manager
     * just before body_stream_finish so the value lands in the
     * header (right before the templates section).  Consumer counts
     * body-entry arch insns and switches to "simulation" once it
     * passes this count.  0 = no warmup configured. */
    uint64_t warmup_end_arch_insns;
};

/* ========================= Template dictionary ========================= */

/*
 * Terminal-branch target table entry (header target list + the §6
 * per-target taken/not-taken counts share this).
 */
struct ProfTgt {
    uint64_t pc, t_cp, nt_cp, t_wp, nt_wp;
};

/*
 * Build the terminal-branch target table.  Target history is a
 * per-PC property: BranchRecord is a per-PC pool shared by every
 * template whose last insn sits at that PC, so a WP-discovered
 * template may surface a co-located branch's CP history (accepted,
 * not a violation).  Uniform layout:
 *   - not a branch        -> empty
 *   - non-indirect branch -> 1 entry, taken edge (tmpl->taken_pc;
 *                            0 if never resolved)
 *   - indirect / return   -> #distinct CP-observed targets
 *                            (<= BRANCH_TARGET_HISTORY)
 * fall_through_pc is the not-taken edge and its single source of
 * truth — never repeated here.  note_target() never runs during WP,
 * so the indirect set is CP-only; the WP indirect aggregate (no
 * per-target WP distribution) is attributed to target[0].
 */
static std::vector<ProfTgt> build_prof_targets(const BBTemplate *tmpl)
{
    std::vector<ProfTgt> prof_tgts;
    const TemplateProfile *pp = tmpl->profile;
    /* Terminating branch (n-1 normally, n-2 on delay-slot ISAs). */
    int bidx = TemplateStore::template_branch_index(tmpl);
    const InsnFields *last = bidx >= 0
        ? &tmpl->insn_fields[bidx] : nullptr;
    uint64_t bt_cp = pp ? pp->br_taken_cp : 0;
    uint64_t bnt_cp = pp ? pp->br_nottaken_cp : 0;
    uint64_t bt_wp = pp ? pp->br_taken_wp : 0;
    uint64_t bnt_wp = pp ? pp->br_nottaken_wp : 0;
    if (last && last->branch_type != BRANCH_NONE) {
        bool indirect =
            last->branch_type == BRANCH_INDIRECT_JUMP ||
            last->branch_type == BRANCH_RETURN ||
            last->branch_type == BRANCH_INDIRECT_CALL;
        if (indirect) {
            /* Per-template indirect target distribution.  Overlapping
             * BBs sharing a terminal branch PC each maintain their own
             * tally (TemplateProfile::indirect_targets) so the per-PC
             * g_branch_history aggregate is never over-attributed.  WP
             * aggregate (not per-target-tracked) attaches to target[0]
             * per the format contract.  Total visits = taken + not-
             * taken so a conditional-indirect form's fall-throughs
             * land in each target's nottaken_cp split. */
            uint64_t tot_cp = bt_cp + bnt_cp;
            if (pp) {
                for (uint8_t k = 0; k < pp->n_indirect_targets; k++) {
                    uint64_t c = pp->indirect_targets[k].count_cp;
                    bool first = prof_tgts.empty();
                    prof_tgts.push_back({
                        pp->indirect_targets[k].target,
                        c, tot_cp - c,
                        first ? bt_wp : 0,
                        first ? bnt_wp : 0,
                    });
                }
            }
        } else {
            /* Non-indirect: one taken edge; its split IS the
             * terminal branch's aggregate outcome. */
            prof_tgts.push_back({
                tmpl->taken_pc,
                bt_cp, bnt_cp, bt_wp, bnt_wp,
            });
        }
    }
    return prof_tgts;
}

/*
 * Per-insn descriptor records.  Optional dependency sub-block is
 * dep_block_flags-gated: HAS_REG (refiner inputs feeding each dst /
 * each store's data) and HAS_ADDR (walker src_regs feeding each
 * load/store address).  Mask array sizes come from the template
 * header; bit layouts diverge — HAS_REG addresses the full input
 * pool (src + load_data + imm), HAS_ADDR omits the load_data band.
 */
static void write_insn_descriptors(BitWriter *sub, const BBTemplate *tmpl)
{
    uint64_t prev_pc = tmpl->start_pc;
    for (uint32_t i = 0; i < tmpl->n_insns; i++) {
        const InsnFields *fld = &tmpl->insn_fields[i];
        uint64_t pc = tmpl->insn_pcs[i];
        uint64_t delta = pc - prev_pc;
        prev_pc = pc;

        bw_write_uleb128(sub, delta);
        bw_write_u8(sub, fld->opcode);
        bw_write_u8(sub, fld->branch_type);

        uint8_t flags = 0;
        if (fld->branch_conditional) {
            flags |= CST_INSN_FLAG_BRANCH_COND;
        }
        if (fld->has_immediate) {
            flags |= CST_INSN_FLAG_HAS_IMM;
        }
        if (fld->is_atomic) {
            flags |= CST_INSN_FLAG_ATOMIC;
        }
        if (fld->has_vec_lanes) {
            flags |= CST_INSN_FLAG_VEC;
        }
        if (fld->lane_parallel) {
            flags |= CST_INSN_FLAG_LANE_PARALLEL;
        }
        if (fld->has_reg_deps || fld->has_addr_deps) {
            flags |= CST_INSN_FLAG_HAS_DEP_BLOCK;
        }
        if (tmpl->is_system) {
            flags |= CST_INSN_FLAG_SYSTEM;
        }
        bw_write_u8(sub, flags);

        bw_write_u8(sub, fld->n_src_regs);
        bw_write_u8(sub, fld->n_dst_regs);
        for (uint8_t s = 0; s < fld->n_src_regs; s++) {
            bw_write_u8(sub, fld->src_regs[s]);
        }
        for (uint8_t d = 0; d < fld->n_dst_regs; d++) {
            bw_write_u8(sub, fld->dst_regs[d]);
        }
        bw_write_u8(sub, fld->max_dep_loads);
        bw_write_u8(sub, fld->max_dep_stores);
        if (fld->has_immediate) {
            bw_write_sleb128(sub, fld->immediate);
        }
        bw_write_u8(sub, tmpl->insn_sizes[i]);
        bw_write_bytes(sub,
                       &tmpl->insn_bytes[(size_t)i * MAX_INSN_BYTES],
                       tmpl->insn_sizes[i]);

        if (fld->has_reg_deps || fld->has_addr_deps) {
            uint8_t dep_flags = 0;
            if (fld->has_reg_deps)  dep_flags |= CST_DEP_BLOCK_HAS_REG;
            if (fld->has_addr_deps) dep_flags |= CST_DEP_BLOCK_HAS_ADDR;
            bw_write_u8(sub, dep_flags);
            if (fld->has_reg_deps) {
                for (uint8_t d = 0; d < fld->n_dst_regs; d++) {
                    bw_write_uleb128(sub, fld->dst_dep_mask[d]);
                }
                for (uint8_t s = 0; s < fld->max_dep_stores; s++) {
                    bw_write_uleb128(sub, fld->store_data_dep_mask[s]);
                }
            }
            if (fld->has_addr_deps) {
                for (uint8_t l = 0; l < fld->max_dep_loads; l++) {
                    bw_write_uleb128(sub, fld->load_addr_dep_mask[l]);
                }
                for (uint8_t s = 0; s < fld->max_dep_stores; s++) {
                    bw_write_uleb128(sub, fld->store_addr_dep_mask[s]);
                }
            }
        }
    }
}

/*
 * Template profile block (format §6) — always present, after the
 * last per-insn descriptor.  Run-aggregated PGO metadata; final
 * totals (templates serialized at segment finish).  Per-target
 * counts are 1:1 with the header target list (n_targets not
 * repeated).
 */
static uint8_t profile_argmax_bin(const uint32_t bins[3]);

static void write_template_profile(BitWriter *sub,
                                   const BBTemplate *tmpl,
                                   const std::vector<ProfTgt> &prof_tgts)
{
    static const TemplateProfile EMPTY_PROFILE = {};
    const TemplateProfile *p =
        tmpl->profile ? tmpl->profile : &EMPTY_PROFILE;

    bw_write_uleb128(sub, p->exec_cp);
    bw_write_uleb128(sub, p->exec_wp);

    for (const ProfTgt &tg : prof_tgts) {
        bw_write_uleb128(sub, tg.t_cp);
        bw_write_uleb128(sub, tg.nt_cp);
        bw_write_uleb128(sub, tg.t_wp);
        bw_write_uleb128(sub, tg.nt_wp);
    }

    for (uint32_t i = 0; i < tmpl->n_insns; i++) {
        const InsnProfile zero = {};
        const InsnProfile *ip =
            tmpl->profile ? &p->insns[i] : &zero;
        bw_write_uleb128(sub, ip->memops_cp);
        bw_write_uleb128(sub, ip->memops_wp);
        /* Resolve each stream's dominant class via argmax over the
         * per-access bin histograms, then compose PC-side and spatial-
         * side: the LOWER (more regular) wins, so either tracker may
         * rescue the other.  A NONE on either side means "no signal
         * from that tracker" and is treated as the identity (don't
         * drag the composed class down). */
        uint8_t pc_pat_cp = profile_argmax_bin(ip->pc_bins_cp);
        uint8_t sp_pat_cp = profile_argmax_bin(ip->spatial_bins_cp);
        uint8_t pc_pat_wp = profile_argmax_bin(ip->pc_bins_wp);
        uint8_t sp_pat_wp = profile_argmax_bin(ip->spatial_bins_wp);
        uint8_t emit_pat_cp = pc_pat_cp;
        if (sp_pat_cp != CST_PAT_NONE &&
            (emit_pat_cp == CST_PAT_NONE || sp_pat_cp < emit_pat_cp)) {
            emit_pat_cp = sp_pat_cp;
        }
        uint8_t emit_pat_wp = pc_pat_wp;
        if (sp_pat_wp != CST_PAT_NONE &&
            (emit_pat_wp == CST_PAT_NONE || sp_pat_wp < emit_pat_wp)) {
            emit_pat_wp = sp_pat_wp;
        }
        uint8_t pf = 0;
        pf |= (emit_pat_cp & CST_PROFILE_PAT_MASK)
              << CST_PROFILE_PAT_CP_SHIFT;
        pf |= (emit_pat_wp & CST_PROFILE_PAT_MASK)
              << CST_PROFILE_PAT_WP_SHIFT;
        if (ip->addr_cp) pf |= CST_PROFILE_ADDR_CP;
        if (ip->addr_wp) pf |= CST_PROFILE_ADDR_WP;
        bw_write_u8(sub, pf);
        if (ip->memops_cp > 0) {
            bw_write_uleb128(sub, ip->lo_cp);
            bw_write_uleb128(sub, ip->hi_cp - ip->lo_cp);
        }
        if (ip->memops_wp > 0) {
            bw_write_uleb128(sub, ip->lo_wp);
            bw_write_uleb128(sub, ip->hi_wp - ip->lo_wp);
        }
    }
}

/*
 * Write the template dictionary section.  Wire layout (template and
 * per-insn record fields) is specified in champsim_tracer_format.md.
 *
 * Encoding gotcha: max_dep_loads / max_dep_stores are template-static
 * MAX counts, not per-iter.  max_dep_loads bounds the dep-mask bit
 * layout (load slots occupy bits [n_src, n_src+max_dep_loads));
 * max_dep_stores sizes store_data_dep_mask[] in the HAS_REG sub-block.
 * The runtime per-iter counts ride separately on CST_FID_N_LOADS /
 * CST_FID_N_STORES and may be smaller.
 */
static void write_bin_templates(BitWriter *bw)
{
    bw_write_uleb128(bw, g_template_store.bb_count());

    g_template_store.for_each_bb([bw](BBTemplate &tmpl_ref) {
        BBTemplate *tmpl = &tmpl_ref;
        BitWriter sub;
        bw_init_buf(&sub);

        bw_write_uleb128(&sub, tmpl->template_id);
        bw_write_uleb128(&sub, tmpl->start_pc);
        bw_write_uleb128(&sub, tmpl->n_insns);
        bw_write_uleb128(&sub, tmpl->fall_through_pc);

        std::vector<ProfTgt> prof_tgts = build_prof_targets(tmpl);
        bw_write_uleb128(&sub, prof_tgts.size());
        for (const ProfTgt &tg : prof_tgts) {
            bw_write_uleb128(&sub, tg.pc);
        }
        {
            const char *sym = tmpl->symbol_name ? tmpl->symbol_name : "";
            size_t sym_len = strlen(sym);
            bw_write_uleb128(&sub, sym_len);
            bw_write_bytes(&sub, (const uint8_t *)sym, sym_len);
        }

        write_insn_descriptors(&sub, tmpl);

        write_template_profile(&sub, tmpl, prof_tgts);

        bw_byte_align(&sub);
        GByteArray *data = bw_finish_buf(&sub);
        bw_write_section(bw, data);
    });
}

/* ========================= Dyn param helpers ========================= */

/* ============== Unified field-typed delta stream ==============
 *
 * Wire layout of the per-entry delta_section: see
 * champsim_tracer_format.md.  Records are non-descending
 * (ins_pos, field_id); unchanged fields cost zero bytes.
 * Per-(template_id, ins_pos, field_id) state tables hold the
 * most-recent value as the baseline.  CP state advances on every CP
 * entry; WP state forks from CP at chain start, discarded at chain
 * end.  Scalars are mod-2^512 little-endian; EXTRA_* memop fields are
 * rare raw vectors that do not update scalar state.
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
 * U512 holding (cur - base) mod 2^512, from two u64s.  Equivalent to
 * u512_sub(cst_wide_from_u64(cur), cst_wide_from_u64(base)) without
 * the two-stack-U512 round-trip; used by the narrow fast path so the
 * scalar-unchanged case never materialises a U512.
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
    /* Narrow fast path: u512_from_u64_diff() produces a U512 whose
     * upper 7 limbs are all-0 (positive) or all-1s (negative) — those
     * are the deltas for every u64 family (N_LOADS, N_STORES,
     * METAFLAGS, LOAD/STORE_ADDR, lane masks).  In that case the wide
     * sleb128 loop reduces to a single int64 sleb128 encode: each of
     * its iterations does an 8-limb arithmetic shift and an 8-limb
     * zero/minus-one check, which is wasted work above limb[0] when
     * the upper limbs are uniform.
     *
     * The wide path is still needed for LOAD_DATA / STORE_DATA /
     * DST_REG where the delta legitimately fills multiple limbs. */
    if ((v.limb[1] == 0 && v.limb[2] == 0 && v.limb[3] == 0 &&
         v.limb[4] == 0 && v.limb[5] == 0 && v.limb[6] == 0 &&
         v.limb[7] == 0 && (int64_t)v.limb[0] >= 0) ||
        (v.limb[1] == ~(uint64_t)0 && v.limb[2] == ~(uint64_t)0 &&
         v.limb[3] == ~(uint64_t)0 && v.limb[4] == ~(uint64_t)0 &&
         v.limb[5] == ~(uint64_t)0 && v.limb[6] == ~(uint64_t)0 &&
         v.limb[7] == ~(uint64_t)0 && (int64_t)v.limb[0] < 0)) {
        bw_write_sleb128(bw, (int64_t)v.limb[0]);
        return;
    }

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

/*
 * Per-template prev-value store (the baseline each entry's deltas are
 * computed against).  Sparse by design: the wire reserves
 * CST_FID_SLOT_COUNT (64) slots per family, but real BBs touch a tiny
 * fraction (mcf: ≤1 load + ≤1 store + ≤2 dst regs per insn), so rather than
 * a dense [insn × family × 64] array the store is split into two planes,
 * each sized to the runtime high-water slot occupancy (max_slots) and grown
 * on demand:
 *
 *   - scalar plane (u64 cells): the 3 singletons (N_LOADS / N_STORES /
 *     METAFLAGS) + 7 insn-metadata cells in a fixed [0..9] prefix, then
 *     9 scalar slotted families × max_slots.
 *   - wide plane (U512 cells): the 3 genuinely-wide families
 *     (LOAD_DATA / STORE_DATA / DST_REG) × max_slots.
 *
 * The slot *space* on the wire is still CST_FID_SLOT_COUNT (64) — the
 * cap on memops/dst-regs per insn — but a block only ever materialises
 * cells up to the largest slot index it has actually observed.  This is
 * a producer-internal representation; the wire format is unchanged, so
 * the decoder's own state tracking is unaffected.
 */
enum {
    FIELD_STATE_SLOT_INVALID = 0xFFFFu,
    /* Scalar fixed prefix: N_LOADS, N_STORES, METAFLAGS, the 7
     * insn-metadata cells (BYTES_LO..SIZE), then the 2 branch-outcome
     * singletons (BRANCH_TAKEN, BRANCH_TARGET) at offsets 10..11.
     * N_SCALAR_SLOTTED scalar slotted families and N_WIDE_SLOTTED wide
     * families follow. */
    FIELD_STATE_SCALAR_FIXED = 12,
    FIELD_STATE_N_SCALAR_FAM = 11,  /* load/store addr, load/store size,
                                     * dst_reg_width, 4 lane masks,
                                     * load/store ppage */
    FIELD_STATE_N_WIDE_FAM   = 3,   /* load_data, store_data, dst_reg */
    /* Power-of-two so fid -> location is a single load.  Largest FID
     * ~906 at slot count 64 / stride-8 slotted, stride-4 lane block,
     * stride-2 ppage block. */
    FIELD_STATE_LUT_SIZE     = 1024,
};

/* Per-insn cell counts for a block sized to @ms high-water slots. */
static inline uint32_t fs_scalar_stride(uint32_t ms)
{
    return FIELD_STATE_SCALAR_FIXED + FIELD_STATE_N_SCALAR_FAM * ms;
}
static inline uint32_t fs_wide_stride(uint32_t ms)
{
    return FIELD_STATE_N_WIDE_FAM * ms;
}

typedef struct FieldStateBlock {
    uint32_t  n_insns;
    uint32_t  max_slots;       /* high-water slot occupancy (>=1 once live) */
    uint64_t *scalar_values;   /* [n_insns * fs_scalar_stride(max_slots)] */
    uint32_t *scalar_gen;
    U512     *wide_values;     /* [n_insns * fs_wide_stride(max_slots)]   */
    uint32_t *wide_gen;
} FieldStateBlock;

/*
 * Resolved location of a field-id within the two-plane block.  Built
 * once into g_fid_loc[].  cls picks the plane/kind; for fixed scalar
 * fields `a` is the [0..9] prefix offset; for slotted families `a` is
 * the family ordinal within its plane and `slot` the slot index.
 */
/* FS_LOC_* enum lifted up next to kSlottedFamilies (see above). */
typedef struct FidLoc {
    uint8_t cls;
    uint8_t a;       /* fixed: prefix offset; slotted: family ordinal */
    uint8_t slot;    /* slotted only */
    uint8_t _pad;
} FidLoc;

/*
 * Per-(template_id) FieldStateBlock cache, vector indexed by
 * template_id (dense ints from 1; slot 0 = "no template").  Replaced
 * a per-entry glib hash lookup that was ~10% of runtime on mcf.
 * Pointers stable across grows (vector<T*> only reallocs the pointer
 * array).
 */
struct FieldStateTable {
    std::vector<FieldStateBlock *> blocks;  /* index = template_id */
    uint32_t generation;
};

/*
 * Field-id -> FidLoc LUT, built once.  Maps every wire field-id to its
 * plane/family/slot in the two-plane block.  Replaces an eight-branch
 * chain that was 2.6% of runtime (~80M calls on a 5M-insn mcf trace).
 *
 * Scalar fixed prefix (offsets 0..9):
 *   0 N_LOADS  1 N_STORES  2 METAFLAGS  3..9 INSN_BYTES_LO..INSN_SIZE
 * Scalar slotted families (ordinals 0..8):
 *   0 LOAD_ADDR  1 STORE_ADDR  2 LOAD_SIZE  3 STORE_SIZE  4 DST_REG_WIDTH
 *   5 SRC_LANE  6 DST_LANE  7 LOAD_DATA_LANE  8 STORE_DATA_LANE
 * Wide slotted families (ordinals 0..2):
 *   0 LOAD_DATA  1 STORE_DATA  2 DST_REG
 */
static FidLoc g_fid_loc[FIELD_STATE_LUT_SIZE];
static bool   g_field_state_slot_lut_built = false;

static void field_state_slot_lut_build(void)
{
    for (unsigned i = 0; i < FIELD_STATE_LUT_SIZE; i++) {
        g_fid_loc[i] = FidLoc{ FS_LOC_INVALID, 0, 0, 0 };
    }
    auto set_fixed = [](unsigned fid, uint8_t off) {
        g_fid_loc[fid] = FidLoc{ FS_LOC_SCALAR_FIXED, off, 0, 0 };
    };
    set_fixed(CST_FID_N_LOADS,   0);
    set_fixed(CST_FID_N_STORES,  1);
    set_fixed(CST_FID_METAFLAGS, 2);
    for (unsigned f = CST_FID_INSN_BYTES_LO; f <= CST_FID_INSN_SIZE; f++) {
        set_fixed(f, (uint8_t)(3 + (f - CST_FID_INSN_BYTES_LO)));
    }
    /* Branch-outcome singletons ride the branch insn's position like
     * METAFLAGS; prefix offsets 10..11 (see FIELD_STATE_SCALAR_FIXED). */
    set_fixed(CST_FID_BRANCH_TAKEN,  10);
    set_fixed(CST_FID_BRANCH_TARGET, 11);

    /* The 8 stride-CST_FID_SLOT_STRIDE slotted families (shared
     * kSlottedFamilies): cls + family ordinal within plane. */
    for (unsigned k = 0; k < CST_FID_SLOT_COUNT; k++) {
        for (unsigned f = 0; f < G_N_ELEMENTS(kSlottedFamilies); f++) {
            unsigned fid = kSlottedFamilies[f].base + k * CST_FID_SLOT_STRIDE;
            g_fid_loc[fid] = FidLoc{ kSlottedFamilies[f].cls,
                                     kSlottedFamilies[f].ord, (uint8_t)k, 0 };
        }
    }
    /* The 4 stride-CST_FID_LANE_BLOCK_STRIDE lane families (shared
     * kLaneFamilies): scalar plane, ordinals 5..8. */
    for (unsigned k = 0; k < CST_FID_SLOT_COUNT; k++) {
        for (unsigned f = 0; f < G_N_ELEMENTS(kLaneFamilies); f++) {
            unsigned fid = kLaneFamilies[f].base + k * CST_FID_LANE_BLOCK_STRIDE;
            g_fid_loc[fid] = FidLoc{ FS_LOC_SCALAR_SLOT, (uint8_t)(5 + f),
                                     (uint8_t)k, 0 };
        }
    }
    /* The 2 stride-CST_FID_PPAGE_BLOCK_STRIDE physical-page families
     * (shared kPpageFamilies): scalar plane, ordinals 9..10.  Registered
     * unconditionally — the cells are simply never written on a
     * non-physaddr trace (the ppage FIDs are never staged), so the wire is
     * unaffected while the reverse LUT stays a single build. */
    for (unsigned k = 0; k < CST_FID_SLOT_COUNT; k++) {
        for (unsigned f = 0; f < G_N_ELEMENTS(kPpageFamilies); f++) {
            unsigned fid = kPpageFamilies[f].base
                + k * CST_FID_PPAGE_BLOCK_STRIDE;
            g_fid_loc[fid] = FidLoc{ FS_LOC_SCALAR_SLOT,
                                     kPpageFamilies[f].ord, (uint8_t)k, 0 };
        }
    }
    g_field_state_slot_lut_built = true;
}

static inline FidLoc field_state_loc(unsigned field_id)
{
    if (field_id >= FIELD_STATE_LUT_SIZE) {
        return FidLoc{ FS_LOC_INVALID, 0, 0, 0 };
    }
    return g_fid_loc[field_id];
}

static void field_state_block_free(void * data)
{
    FieldStateBlock *block = (FieldStateBlock *)data;
    if (!block) {
        return;
    }
    g_free(block->scalar_values);
    g_free(block->scalar_gen);
    g_free(block->wide_values);
    g_free(block->wide_gen);
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
    /* Start at one slot per family — covers the overwhelmingly common
     * scalar BB (≤1 load/store/dst per insn) with no growth.  Variable
     * memop / vector insns grow the block lazily (see ..._ensure_slots). */
    block->max_slots = 1;
    uint32_t n = block->n_insns;
    size_t ss = (size_t)n * fs_scalar_stride(block->max_slots);
    size_t ws = (size_t)n * fs_wide_stride(block->max_slots);
    block->scalar_values = g_new0(uint64_t, ss ? ss : 1);
    block->scalar_gen    = g_new0(uint32_t, ss ? ss : 1);
    block->wide_values   = g_new0(U512,     ws ? ws : 1);
    block->wide_gen      = g_new0(uint32_t, ws ? ws : 1);
    table->blocks[template_id] = block;
    return block;
}

/*
 * Grow a block's high-water slot occupancy to at least @need slots,
 * preserving every already-observed cell (deltas are computed against
 * these — losing one would desync the decoder).  Both planes are
 * family-major with a per-slot stride, so growth re-lays-out into
 * wider strides and copies each family's live [0, old_ms) cells across.
 * Rare after warm-up; never called on a read-only base block.
 */
static void field_state_block_ensure_slots(FieldStateBlock *b, uint32_t need)
{
    if (need <= b->max_slots) {
        return;
    }
    uint32_t n = b->n_insns;
    uint32_t old_ms = b->max_slots, new_ms = need;
    uint32_t old_ss = fs_scalar_stride(old_ms), new_ss = fs_scalar_stride(new_ms);
    uint32_t old_ws = fs_wide_stride(old_ms),   new_ws = fs_wide_stride(new_ms);

    size_t nsv = (size_t)n * new_ss, nwv = (size_t)n * new_ws;
    uint64_t *sv = g_new0(uint64_t, nsv ? nsv : 1);
    uint32_t *sg = g_new0(uint32_t, nsv ? nsv : 1);
    U512     *wv = g_new0(U512,     nwv ? nwv : 1);
    uint32_t *wg = g_new0(uint32_t, nwv ? nwv : 1);

    for (uint32_t i = 0; i < n; i++) {
        /* scalar: fixed prefix is layout-stable; slotted families shift. */
        memcpy(sv + (size_t)i * new_ss, b->scalar_values + (size_t)i * old_ss,
               FIELD_STATE_SCALAR_FIXED * sizeof(uint64_t));
        memcpy(sg + (size_t)i * new_ss, b->scalar_gen + (size_t)i * old_ss,
               FIELD_STATE_SCALAR_FIXED * sizeof(uint32_t));
        for (uint32_t f = 0; f < FIELD_STATE_N_SCALAR_FAM; f++) {
            size_t o = (size_t)i * old_ss + FIELD_STATE_SCALAR_FIXED + (size_t)f * old_ms;
            size_t nn = (size_t)i * new_ss + FIELD_STATE_SCALAR_FIXED + (size_t)f * new_ms;
            memcpy(sv + nn, b->scalar_values + o, (size_t)old_ms * sizeof(uint64_t));
            memcpy(sg + nn, b->scalar_gen + o,    (size_t)old_ms * sizeof(uint32_t));
        }
        for (uint32_t f = 0; f < FIELD_STATE_N_WIDE_FAM; f++) {
            size_t o = (size_t)i * old_ws + (size_t)f * old_ms;
            size_t nn = (size_t)i * new_ws + (size_t)f * new_ms;
            memcpy(wv + nn, b->wide_values + o, (size_t)old_ms * sizeof(U512));
            memcpy(wg + nn, b->wide_gen + o,    (size_t)old_ms * sizeof(uint32_t));
        }
    }
    g_free(b->scalar_values); g_free(b->scalar_gen);
    g_free(b->wide_values);   g_free(b->wide_gen);
    b->scalar_values = sv; b->scalar_gen = sg;
    b->wide_values = wv;   b->wide_gen = wg;
    b->max_slots = new_ms;
}

/* Resolve a FidLoc to its flat cell index within @block's scalar plane.
 * Returns false for the wide plane / invalid / a slot beyond this
 * block's occupancy (an unobserved high slot — treat as a state miss). */
static inline bool fs_scalar_index(const FieldStateBlock *block,
                                   uint32_t ins_pos, FidLoc loc, size_t *idx)
{
    uint32_t off;
    if (loc.cls == FS_LOC_SCALAR_FIXED) {
        off = loc.a;
    } else if (loc.cls == FS_LOC_SCALAR_SLOT) {
        if (loc.slot >= block->max_slots) return false;
        off = FIELD_STATE_SCALAR_FIXED + (uint32_t)loc.a * block->max_slots
              + loc.slot;
    } else {
        return false;
    }
    *idx = (size_t)ins_pos * fs_scalar_stride(block->max_slots) + off;
    return true;
}

static inline bool fs_wide_index(const FieldStateBlock *block,
                                 uint32_t ins_pos, FidLoc loc, size_t *idx)
{
    if (loc.cls != FS_LOC_WIDE_SLOT || loc.slot >= block->max_slots) {
        return false;
    }
    *idx = (size_t)ins_pos * fs_wide_stride(block->max_slots)
           + (size_t)loc.a * block->max_slots + loc.slot;
    return true;
}

static inline bool field_state_get_scalar(FieldStateBlock *block,
                                           uint32_t table_generation,
                                           uint32_t ins_pos, FidLoc loc,
                                           uint64_t *out)
{
    size_t index;
    if (!block || ins_pos >= block->n_insns ||
        !fs_scalar_index(block, ins_pos, loc, &index) ||
        block->scalar_gen[index] != table_generation) {
        return false;
    }
    *out = block->scalar_values[index];
    return true;
}

static inline bool field_state_get_wide(FieldStateBlock *block,
                                         uint32_t table_generation,
                                         uint32_t ins_pos, FidLoc loc,
                                         U512 *out)
{
    size_t index;
    if (!block || ins_pos >= block->n_insns ||
        !fs_wide_index(block, ins_pos, loc, &index) ||
        block->wide_gen[index] != table_generation) {
        return false;
    }
    *out = block->wide_values[index];
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
    /* vCPU the entry executed on.  Used by lane-mask extractors when
     * the InsnFields lane_mask_kind is dynamic (reads a runtime CSR
     * via cst_reg_read_u64). */
    unsigned int cpu_index;
    /* Terminal-branch outcome for the CST_FID_BRANCH_* singletons.
     * branch_known gates emission; branch_successor_pc is the architectural
     * landing PC (== next entry's start_pc).  Direction/target are derived
     * from it and the template's fall-through at staging time. */
    bool     branch_known;
    uint64_t branch_successor_pc;
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
     * When non-null the emitter compares two u64s in registers and
     * only materialises a U512 when the field changed (the U512 stack
     * round-trip dominated the encoder hot loop on mcf).  Both set
     * together; either null -> wide pair (LOAD_DATA, STORE_DATA,
     * DST_REG genuinely need >64 bits). */
    bool (*extract_u64)(const EntryView *ev, uint32_t ins_pos, uint8_t slot,
                        uint64_t *out_val);
    uint64_t (*template_default_u64)(const BBTemplate *tmpl,
                                     uint32_t ins_pos, uint8_t slot);

    /* True iff extract == template_default for every entry of a
     * (template, ins_pos) — purely template-derived, never produces a
     * wire record, so the hot loop skips it (these probes were ~50% of
     * per-slot cost on full-config mcf despite emitting nothing). */
    bool template_static;

    const char *name;          /* debug only */
} FieldDescriptor;

/* ---------- Per-family runtime slot caps ----------
 *
 * Memop families and DST_REG have CST_FID_SLOT_COUNT wire slots but
 * typical insns use 0-2.  Iterating all of them just to have extract()
 * return false was ~30% of plugin runtime; these caps terminate the
 * slot loop at the actual count. */
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

static bool extr_n_stores(const EntryView *ev, uint32_t i, uint8_t slot,
                          U512 *out)
{
    (void)slot;
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return false;
    *out = cst_wide_from_u64(ev->actual_n_stores[i]);
    return true;
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

/* Reg-snap families: reg_snaps holds per-insn destination operands
 * only, template-walk order, captured POST-execution (per-insn
 * callback registered on the NEXT insn; last TB insn snapped by the
 * next TB's tb_exec).  Source values are never on the wire — a
 * consumer derives any reg's value from the most recent post-exec dst
 * observation, which dominates the pre-exec source view (every
 * architectural write, fewer dsts than srcs per insn). */
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
 * Per-insn canonical-flags byte from the REG_FLAGS dst snap, via
 * isa_properties[trace_isa].flags_to_metaflags.  Gated by both
 * CST_FLAG_REG_DATA and InsnFields.writes_int_flags.  A side-channel
 * FID, not a synthetic dst-register, so dst_regs lists stay free of
 * phantom architectural slots.
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

/* Insn-encoding-mutable families.  No SMC observer wired up — extract
 * returns the template's static value (delta always zero, no record).
 * If SMC is added, point extract at the runtime value; keep
 * template_default. */
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
    if (f->is_atomic)          flags |= CST_INSN_FLAG_ATOMIC;
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
 * Mirror the wide callbacks for every u64-fitting family (all except
 * LOAD_DATA / STORE_DATA / DST_REG).  The emitter's fast path uses
 * these to avoid the U512 stack round-trip.
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
    if (f->is_atomic)          flags |= CST_INSN_FLAG_ATOMIC;
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

/* ---------- Lane-mask families ---------- */

/* Lane-mask slot caps.  0 when the insn has no lane info (most
 * non-vec insns), suppressing emission; else only the actual
 * reg/memop slots are walked. */
static uint8_t cap_src_lane_masks(const EntryView *ev, uint32_t i)
{
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return 0;
    const InsnFields *f = &ev->tmpl->insn_fields[i];
    if (!f->has_vec_lanes) return 0;
    return f->n_src_regs;
}
static uint8_t cap_dst_lane_masks(const EntryView *ev, uint32_t i)
{
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return 0;
    const InsnFields *f = &ev->tmpl->insn_fields[i];
    if (!f->has_vec_lanes) return 0;
    return f->n_dst_regs;
}
static uint8_t cap_load_data_lane_masks(const EntryView *ev, uint32_t i)
{
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return 0;
    const InsnFields *f = &ev->tmpl->insn_fields[i];
    if (!f->has_vec_lanes) return 0;
    return f->max_dep_loads;
}
static uint8_t cap_store_data_lane_masks(const EntryView *ev, uint32_t i)
{
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return 0;
    const InsnFields *f = &ev->tmpl->insn_fields[i];
    if (!f->has_vec_lanes) return 0;
    return f->max_dep_stores;
}

/*
 * Active-lane gate.  lane_mask_kind decides ONLY where the live-lane
 * count comes from:
 *   STATIC      — fixed by the insn; gate all-ones (structural masks
 *                 are final).
 *   RISCV_VTYPE — vl read from CSR at exec; gate (1<<vl)-1, AND-ed
 *                 into every per-slot mask.
 * (future EVEX-k / SVE-pred: same shape, read their reg.)
 */
static uint64_t lane_active_gate(const InsnFields *f, unsigned cpu_index)
{
    if (!f) return 0;
    switch ((enum LaneMaskKind)f->lane_mask_kind) {
    case LANE_MASK_KIND_STATIC:
        return ~(uint64_t)0;
    case LANE_MASK_KIND_RISCV_VTYPE: {
        uint64_t vl = 0;
        if (!cst_reg_read_u64(cpu_index, &f->lane_mask_source_reg, &vl)) {
            return 0;
        }
        if (vl == 0) return 0;
        if (vl >= 64) return ~(uint64_t)0;
        return ((uint64_t)1 << vl) - 1;
    }
    case LANE_MASK_KIND_NONE:
    default:
        return 0;
    }
}

/*
 * Per-memop data lane mask: which lanes of the associated vector reg
 * this access feeds (load) / drains (store).  From the memop byte
 * Lane mask attribution flow:
 *
 *   1. The dep refiner (template-build time, per-mnemonic) records on
 *      each dst's dst_dep / each store's store_data_dep which load /
 *      store slots feed that operand — the ACTUAL ISA semantics, e.g.
 *      AArch64 LD1 multi-reg → first lanes_per_reg slots feed dst[0],
 *      next lanes_per_reg feed dst[1], etc.  Without a precise refiner
 *      the bits collapse to all-to-all and we have no per-memop
 *      attribution.
 *   2. At emit time, this routine looks up memop slot k in the
 *      dep masks to find its OWNING operand-side register r, then
 *      assigns it the rank-th set bit (or contiguous span of bits)
 *      of side_lane_mask[r], where rank is k's position among r's
 *      memop slots sorted in slot order (== address order for the
 *      sequential layouts the partitioning refiners model).
 *   3. Element insert/extract (PINSR/PEXTR/INSERTPS) is a structural
 *      exception: one element-sized memop targeting the immediate-
 *      selected lane.
 *   4. lane_bytes == 0 (runtime-SEW, e.g. RISC-V V) gives no static
 *      lane width, so we fall back to one-lane-per-memop in slot
 *      order — narrowed by the exec gate.
 *
 * When the dep masks are all-to-all (no precise refiner bound), no
 * per-memop attribution is recoverable: we emit an empty mask
 * (consumer's "no lane info") rather than guessing, since the wrong
 * guess would lie about the dataflow.
 */
static uint64_t memop_data_lane_mask(const EntryView *ev, uint32_t i,
                                     uint8_t slot, uint8_t want_type,
                                     const InsnFields *f)
{
    const DynParam *dp = find_memop_slot(ev, i, slot, want_type);
    if (!dp) return 0;

    uint8_t lane_bytes = f->lane_bytes;
    if (lane_bytes == 0) {
        /* Runtime-SEW ISA: associate by memop order. */
        return (slot < 64) ? ((uint64_t)1 << slot) : 0;
    }

    /* Element insert/extract: one element-sized memop whose target
     * lane is the instruction immediate (PINSR, PEXTR, INSERTPS,
     * etc.).  The immediate is already a valid in-range lane index
     * for these ops, so the memop feeds/drains exactly that lane,
     * matching the decode-time INSERT/EXTRACT reg-mask narrowing.
     *
     * Single-memop check goes through actual_n_loads/n_stores instead
     * of probing load_slots[i*64+1] for null: the slot-array entries
     * past actual_n_loads[i] aren't guaranteed cleared (the scratch
     * skips that memset for cost, see entry_view_scratch_ensure), so
     * a stale pointer from a prior emit would mis-trigger the probe. */
    uint32_t n_same_type = (want_type == DYN_LOAD_ADDR
                             ? (ev->actual_n_loads
                                ? ev->actual_n_loads[i] : 0)
                             : (ev->actual_n_stores
                                ? ev->actual_n_stores[i] : 0));
    if (f->has_immediate && dp->data_size == lane_bytes
        && n_same_type == 1) {
        uint64_t lane = (uint64_t)f->immediate;
        return (lane < 64) ? ((uint64_t)1 << lane) : 0;
    }

    /* Find this memop's host register by reading the dep masks the
     * refiner produced.  Loads land in dst_dep[]; stores in
     * store_data_dep[].  Each mask's bits in [n_src, n_src + max_loads)
     * point to load slots; for store_data_dep[s], one of its src_reg
     * bits points to the vec-value src.  The host register is the one
     * whose dep mask includes this memop's slot index. */
    uint8_t host_reg_idx = 0xFF;
    uint64_t host_lane_mask = 0;
    unsigned slots_before = 0;   /* count of earlier memop slots that
                                  * also feed the same host register */
    if (!f->has_reg_deps) {
        /* No precise refiner bound for this mnemonic; can't recover
         * the per-memop -> per-register attribution.  Empty mask. */
        return 0;
    }
    if (want_type == DYN_LOAD_ADDR) {
        const uint64_t load_bit_k = (uint64_t)1 <<
            ((uint64_t)f->n_src_regs + (uint64_t)slot);
        for (uint8_t d = 0; d < f->n_dst_regs; d++) {
            if (!(f->dst_dep_mask[d] & load_bit_k)) continue;
            host_reg_idx = d;
            host_lane_mask = f->dst_lane_mask[d];
            /* Rank among d's load slots: count earlier slots also in
             * dst_dep[d]'s load-bit range. */
            uint64_t load_range = f->dst_dep_mask[d]
                >> (uint64_t)f->n_src_regs;
            uint64_t earlier = load_range & (((uint64_t)1 << slot) - 1);
            slots_before = (unsigned)__builtin_popcountll(earlier);
            break;
        }
    } else {
        /* Stores: store_data_dep[slot] points to the value src_reg.
         * Among same-slot-mask stores in store_data_dep[], rank by
         * how many earlier slots reference the same src. */
        const uint64_t this_slot_mask = f->store_data_dep_mask[slot]
            & ((((uint64_t)1 << f->n_src_regs) - 1));
        if (!this_slot_mask) return 0;
        /* Lowest set bit selects the vec-value src for this store. */
        uint8_t which = (uint8_t)__builtin_ctzll(this_slot_mask);
        host_reg_idx = which;
        host_lane_mask = f->src_lane_mask[which];
        for (uint8_t s = 0; s < slot && s < MAX_STORES; s++) {
            if (f->store_data_dep_mask[s] & this_slot_mask) {
                slots_before++;
            }
        }
    }
    if (host_reg_idx == 0xFF || host_lane_mask == 0) return 0;

    uint64_t size  = dp->data_size ? dp->data_size : lane_bytes;
    uint64_t span  = size / lane_bytes;
    if (span == 0) span = 1;

    /* slots_before-th set bit of host_lane_mask is the first lane
     * this memop fills; extend by `span` consecutive set bits for
     * wide memops (data_size > lane_bytes). */
    uint64_t result = 0;
    unsigned seen = 0, taken = 0;
    for (unsigned b = 0; b < 64 && taken < span; b++) {
        if (!(host_lane_mask & ((uint64_t)1 << b))) continue;
        if (seen >= slots_before) {
            result |= (uint64_t)1 << b;
            taken++;
        }
        seen++;
    }
    return result;
}

static bool extr_u64_src_lane_mask(const EntryView *ev, uint32_t i,
                                   uint8_t slot, uint64_t *out)
{
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return false;
    const InsnFields *f = &ev->tmpl->insn_fields[i];
    if (!f->has_vec_lanes || slot >= f->n_src_regs) return false;
    *out = f->src_lane_mask[slot] & lane_active_gate(f, ev->cpu_index);
    return true;
}
static bool extr_u64_dst_lane_mask(const EntryView *ev, uint32_t i,
                                   uint8_t slot, uint64_t *out)
{
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return false;
    const InsnFields *f = &ev->tmpl->insn_fields[i];
    if (!f->has_vec_lanes || slot >= f->n_dst_regs) return false;
    *out = f->dst_lane_mask[slot] & lane_active_gate(f, ev->cpu_index);
    return true;
}
static bool extr_u64_load_data_lane_mask(const EntryView *ev, uint32_t i,
                                         uint8_t slot, uint64_t *out)
{
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return false;
    const InsnFields *f = &ev->tmpl->insn_fields[i];
    if (!f->has_vec_lanes || slot >= f->max_dep_loads) return false;
    *out = memop_data_lane_mask(ev, i, slot, DYN_LOAD_ADDR, f)
           & lane_active_gate(f, ev->cpu_index);
    return true;
}
static bool extr_u64_store_data_lane_mask(const EntryView *ev, uint32_t i,
                                          uint8_t slot, uint64_t *out)
{
    if (!ev->tmpl || i >= ev->tmpl->n_insns) return false;
    const InsnFields *f = &ev->tmpl->insn_fields[i];
    if (!f->has_vec_lanes || slot >= f->max_dep_stores) return false;
    *out = memop_data_lane_mask(ev, i, slot, DYN_STORE_ADDR, f)
           & lane_active_gate(f, ev->cpu_index);
    return true;
}

/* template_default = 0 — the consumer's initial baseline.  Refiner-set
 * baselines flow on the wire as the first observation's delta-from-zero;
 * subsequent observations with the same value cost zero bytes. */
static U512 deflt_lane_mask_zero(const BBTemplate *t, uint32_t i,
                                 uint8_t slot)
{ (void)t; (void)i; (void)slot; return cst_wide_from_u64(0); }

static bool extr_src_lane_mask(const EntryView *ev, uint32_t i, uint8_t slot,
                               U512 *out)
{
    uint64_t v;
    if (!extr_u64_src_lane_mask(ev, i, slot, &v)) return false;
    *out = cst_wide_from_u64(v);
    return true;
}
static bool extr_dst_lane_mask(const EntryView *ev, uint32_t i, uint8_t slot,
                               U512 *out)
{
    uint64_t v;
    if (!extr_u64_dst_lane_mask(ev, i, slot, &v)) return false;
    *out = cst_wide_from_u64(v);
    return true;
}
static bool extr_load_data_lane_mask(const EntryView *ev, uint32_t i,
                                     uint8_t slot, U512 *out)
{
    uint64_t v;
    if (!extr_u64_load_data_lane_mask(ev, i, slot, &v)) return false;
    *out = cst_wide_from_u64(v);
    return true;
}
static bool extr_store_data_lane_mask(const EntryView *ev, uint32_t i,
                                      uint8_t slot, U512 *out)
{
    uint64_t v;
    if (!extr_u64_store_data_lane_mask(ev, i, slot, &v)) return false;
    *out = cst_wide_from_u64(v);
    return true;
}

/* Field family registry.  Order is load-bearing: the emitter walks
 * this table left-to-right per insn and the wire requires
 * non-descending (ins_pos, field_id).  Table order must match
 * ascending field_id; the slotted families share an interleaved
 * stride-N ID space so the family-major / slot-minor walk produces
 * ascending fids (a final (pos,fid) sort backstops the interleave).
 * See FieldDescriptor.slot_stride. */
static const FieldDescriptor field_descriptors[] = {
        { CST_FID_N_LOADS,          1, 1,  false, false,
            extr_n_loads,        deflt_zero,            nullptr,
            extr_u64_n_loads,    deflt_u64_zero,
            false /* dynamic: actual_n_loads[i] */,
            "N_LOADS" },
        { CST_FID_N_STORES,         1, 1,  false, false,
            extr_n_stores,       deflt_zero,            nullptr,
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
        /* Lane-mask block.  cap_*_lane_masks gates per-insn so non-vec
         * insns iterate zero slots.  template_default = 0; refiner's
         * baseline rides the wire as the first emission's delta. */
        { CST_FID_SRC_LANE_MASK_BASE, CST_FID_LANE_BLOCK_STRIDE,
            CST_FID_SLOT_COUNT,
            false, false,
            extr_src_lane_mask,  deflt_lane_mask_zero,  cap_src_lane_masks,
            extr_u64_src_lane_mask, deflt_u64_zero,
            false /* dynamic: runtime mask register read (future) */,
            "SRC_LANE_MASK" },
        { CST_FID_DST_LANE_MASK_BASE, CST_FID_LANE_BLOCK_STRIDE,
            CST_FID_SLOT_COUNT,
            false, false,
            extr_dst_lane_mask,  deflt_lane_mask_zero,  cap_dst_lane_masks,
            extr_u64_dst_lane_mask, deflt_u64_zero,
            false /* dynamic: runtime mask register read (future) */,
            "DST_LANE_MASK" },
        { CST_FID_LOAD_DATA_LANE_MASK_BASE, CST_FID_LANE_BLOCK_STRIDE,
            CST_FID_SLOT_COUNT,
            false, false,
            extr_load_data_lane_mask, deflt_lane_mask_zero,
            cap_load_data_lane_masks,
            extr_u64_load_data_lane_mask, deflt_u64_zero,
            false /* dynamic: gather/scatter may vary per-iter */,
            "LOAD_DATA_LANE_MASK" },
        { CST_FID_STORE_DATA_LANE_MASK_BASE, CST_FID_LANE_BLOCK_STRIDE,
            CST_FID_SLOT_COUNT,
            false, false,
            extr_store_data_lane_mask, deflt_lane_mask_zero,
            cap_store_data_lane_masks,
            extr_u64_store_data_lane_mask, deflt_u64_zero,
            false /* dynamic: scatter may vary per-iter */,
            "STORE_DATA_LANE_MASK" },
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

/* Named indices into field_descriptors[].  The sparse emit_field_delta
 * walker visits each family directly via these (rather than scanning
 * all descriptors per insn and falling back on per-call cap == 0 to
 * skip non-applicable families), so the order here is load-bearing
 * for that walker — must match field_descriptors[] above. */
enum FieldDescIndex {
    FD_IDX_N_LOADS = 0,
    FD_IDX_N_STORES,
    FD_IDX_METAFLAGS,
    FD_IDX_LOAD_ADDR,
    FD_IDX_STORE_ADDR,
    FD_IDX_LOAD_DATA,
    FD_IDX_STORE_DATA,
    FD_IDX_DST_REG,
    FD_IDX_SRC_LANE_MASK,
    FD_IDX_DST_LANE_MASK,
    FD_IDX_LOAD_DATA_LANE_MASK,
    FD_IDX_STORE_DATA_LANE_MASK,
    /* remaining entries are template_static; never iterated by the
     * sparse walker */
};

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

    /* No per-emit memset: load_slots[]/store_slots[] entries past
     * actual_n_loads[i] / actual_n_stores[i] are never read by the
     * emit hot loop (its iteration is `for (s = 0; s < cap_min(actual);
     * s++)`), and the one site that DID probe past the actual count
     * (memop_data_lane_mask's PINSR/PEXTR detect) was rewritten to
     * consult actual_n_loads/n_stores directly.  The g_renew above
     * leaves stale data in newly-grown regions, but those are bounded
     * by the same per-insn actual count so the hot loop never reads
     * them.  perf attributed ~2 KB-30 KB of per-emit memset traffic
     * (per template's n_insns × 64 slots × 8 bytes × 2 arrays); for
     * mcf with 2M emits this is multiple GB of writes per run that
     * were producing no observable effect. */
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
/* Look up baseline value for (ins_pos, field_id) in the wide plane.
 * Falls back to the WP base overlay, then the descriptor's template
 * default.  Wide families only (LOAD_DATA / STORE_DATA / DST_REG). */
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
    FidLoc loc = field_state_loc(field_id);
    if (field_state_get_wide(state_block, state_generation, ins_pos,
                             loc, &cur)) {
        return cur;
    }
    if (field_state_get_wide(base_block, base_generation, ins_pos,
                             loc, &cur)) {
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
    size_t index;
    FidLoc loc = field_state_loc(field_id);
    if (!state_block || ins_pos >= state_block->n_insns ||
        !fs_wide_index(state_block, ins_pos, loc, &index)) {
        return;
    }
    state_block->wide_values[index] = v;
    state_block->wide_gen[index] = state_generation;
}

typedef struct StageRec {
    uint32_t pos;
    /* Wire-format FID, widened from u8 since 0x1D — slot 63 of the
     * last slotted family reaches ID 322. */
    uint16_t fid;
    U512     delta;
} StageRec;

/* Reserve the next slot and return a pointer to it, growing on demand.
 * Lets the caller fill fields directly instead of materialising a
 * 72-byte StageRec on the stack and passing it by value — that copy
 * (movdqa stack→reg + reg→stage) and the zero-init `rec = {}`
 * cleared the bigger stalls in this hot loop on mcf. */
[[gnu::always_inline]] static inline StageRec *
stage_rec_reserve(StageRec **stage, unsigned int *stage_len,
                  unsigned int *stage_cap)
{
    if (*stage_len == *stage_cap) {
        *stage_cap *= 2;
        *stage = (StageRec *)g_realloc_n(*stage, *stage_cap,
                                         sizeof(**stage));
    }
    return &(*stage)[(*stage_len)++];
}

/* CP memop overflow warning.  The slot loop silently clamps a
 * dynamic memop count exceeding CST_FID_SLOT_COUNT; the cap is well
 * above realistic ISA ceilings (AVX-512 <=16, max-VLEN SVE <=64) so
 * any overflow gets a per-occurrence breadcrumb. */
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

/* Stage a u64 delta record for (i, fid, cur).  The caller has already
 * decided this slot has content and extracted `cur` directly — no
 * fd->extract_u64() indirect dispatch.  always_inline so the per-family
 * blocks below see this body inlined at -O.
 *
 * @deflt is the template default for this field (0 for runtime
 * fields, the template's static value for INSN_BYTES/OPCODE/etc.).
 * The state-block lookups below are family-agnostic. */
[[gnu::always_inline]] static inline void
stage_u64_delta(StageRec **stage_p, unsigned int *stage_len,
                unsigned int *stage_cap,
                FieldStateBlock *state_block, uint32_t state_generation,
                FieldStateBlock *base_block, uint32_t base_generation,
                uint32_t i, uint16_t fid,
                uint64_t cur, uint64_t deflt)
{
    FidLoc loc = field_state_loc(fid);
    uint64_t base;
    if (!field_state_get_scalar(state_block, state_generation,
                                i, loc, &base) &&
        !field_state_get_scalar(base_block, base_generation,
                                i, loc, &base)) {
        base = deflt;
    }
    if (cur == base) return;
    StageRec *rec = stage_rec_reserve(stage_p, stage_len, stage_cap);
    rec->pos = i;
    rec->fid = fid;
    rec->delta = u512_from_u64_diff(cur, base);
    size_t idx;
    if (state_block && i < state_block->n_insns &&
        fs_scalar_index(state_block, i, loc, &idx)) {
        state_block->scalar_values[idx] = cur;
        state_block->scalar_gen[idx] = state_generation;
    }
}

/* Wide variant: takes the already-extracted U512 value.  fd is kept
 * for the field_state_get pathway (it walks fd->template_default for
 * the template-derived families — wide families today are all runtime
 * with template_default == 0, but field_state_get still consults it). */
[[gnu::always_inline]] static inline void
stage_wide_delta(StageRec **stage_p, unsigned int *stage_len,
                 unsigned int *stage_cap,
                 FieldStateBlock *state_block, uint32_t state_generation,
                 FieldStateBlock *base_block, uint32_t base_generation,
                 const EntryView *ev, uint32_t i, uint16_t fid,
                 const FieldDescriptor *fd, uint8_t slot, const U512 &cur)
{
    U512 base = field_state_get(state_block, state_generation,
                                base_block, base_generation,
                                i, fid, fd, ev->tmpl, slot);
    if (u512_equal(cur, base)) return;
    StageRec *rec = stage_rec_reserve(stage_p, stage_len, stage_cap);
    rec->pos = i;
    rec->fid = fid;
    rec->delta = u512_sub(cur, base);
    field_state_put(state_block, state_generation, i, fid, cur);
}

/*
 * The single emitter.  Sparse per-insn walk: for each insn, visit
 * exactly the descriptor/slot tuples that have observable content
 * (per-insn N_LOADS/N_STORES; memop slots gated by actual_n_loads /
 * actual_n_stores; DST_REG / METAFLAGS / lane-masks gated by the
 * immutable per-insn schema in InsnFields).  Skips entire families
 * for insns where the template schema or runtime count guarantees
 * extract() would return false; visiting every (insn, descriptor) pair
 * unconditionally would let the per-pair dispatch overhead dominate on
 * scalar-heavy traces (mcf).
 *
 * A final (pos, fid) sort produces the wire's required non-descending
 * order, since the per-insn sub-walks emit family-major within each
 * insn but the slotted families share interleaved FID ranges.
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
    /* rec_bw wraps st->rec_scratch (RawBuf); reset len to 0 to
     * overwrite the previous payload without freeing the allocation. */
    BitWriter rec_bw;
    bw_init_rb(&rec_bw, &st->rec_scratch);
    raw_buf_clear(&st->rec_scratch);

    /* Reuse the per-stream StageRec buffer; capacity grows on demand
     * and is synced back to BodyStreamState before return. */
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

        const bool want_memdata = (header_flags & CST_FLAG_MEM_DATA) != 0;
        const bool want_regdata = (header_flags & CST_FLAG_REG_DATA) != 0;
        const bool want_physaddr = (header_flags & CST_FLAG_PHYSADDR) != 0;

        /* Locked-in descriptor pointers — only the wide families
         * (LOAD_DATA, STORE_DATA, DST_REG) still need fd for the
         * field_state_get path; the u64 families inline their extract
         * directly, so the table lookup is gone for them. */
        const FieldDescriptor *fd_load_data   = &field_descriptors[FD_IDX_LOAD_DATA];
        const FieldDescriptor *fd_store_data  = &field_descriptors[FD_IDX_STORE_DATA];
        const FieldDescriptor *fd_dst_reg     = &field_descriptors[FD_IDX_DST_REG];
        const FieldDescriptor *fd_src_lm      = &field_descriptors[FD_IDX_SRC_LANE_MASK];
        const FieldDescriptor *fd_dst_lm      = &field_descriptors[FD_IDX_DST_LANE_MASK];
        const FieldDescriptor *fd_load_lm     = &field_descriptors[FD_IDX_LOAD_DATA_LANE_MASK];
        const FieldDescriptor *fd_store_lm    = &field_descriptors[FD_IDX_STORE_DATA_LANE_MASK];

#define STAGE_U64(I, FID, CUR, DEFLT) \
    stage_u64_delta(&stage, &stage_len, &stage_cap, \
                    state_block, state_generation, \
                    base_block, base_generation, \
                    (I), (FID), (CUR), (DEFLT))
#define STAGE_WIDE(I, FID, FD, SLOT, CUR) \
    stage_wide_delta(&stage, &stage_len, &stage_cap, \
                     state_block, state_generation, \
                     base_block, base_generation, \
                     ev, (I), (FID), (FD), (SLOT), (CUR))

        /* Pre-resolve the metaflags mapper once — devirtualizes the
         * per-insn `mapper(raw)` call into a hot loop where the ISA
         * never changes within a trace. */
        MetaFlagsMapperFn metaflags_mapper = want_regdata
            ? isa_properties[trace_isa].flags_to_metaflags
            : nullptr;

        const DynParam *const *load_slots  = ev->load_slots;
        const DynParam *const *store_slots = ev->store_slots;
        const uint32_t *insn_rs_off        = ev->insn_rs_off;
        const auto *reg_snaps              = ev->reg_snaps;

        /* Grow the writable block to this entry's high-water slot count
         * once, up front, so per-field staging never relayouts mid-loop.
         * Bounded by CST_FID_SLOT_COUNT.  base_block is read-only and is
         * never grown — an unobserved high slot there misses to default. */
        {
            uint32_t needed = 1;
            for (uint32_t i = 0; i < ev->tmpl->n_insns; i++) {
                const InsnFields *f = &ev->tmpl->insn_fields[i];
                uint32_t m = ev->actual_n_loads ? cap_min(ev->actual_n_loads[i]) : 0;
                uint32_t s = ev->actual_n_stores ? cap_min(ev->actual_n_stores[i]) : 0;
                if (s > m) m = s;
                if (want_regdata && f->n_dst_regs > m) m = f->n_dst_regs;
                if (f->has_vec_lanes) {
                    if (f->n_src_regs > m)     m = f->n_src_regs;
                    if (f->n_dst_regs > m)     m = f->n_dst_regs;
                    if (f->max_dep_loads > m)  m = f->max_dep_loads;
                    if (f->max_dep_stores > m) m = f->max_dep_stores;
                }
                if (m > needed) needed = m;
            }
            if (needed > CST_FID_SLOT_COUNT) needed = CST_FID_SLOT_COUNT;
            if (needed > state_block->max_slots) {
                field_state_block_ensure_slots(state_block, needed);
            }
        }

        for (uint32_t i = 0; i < ev->tmpl->n_insns; i++) {
            const InsnFields *f = &ev->tmpl->insn_fields[i];
            uint32_t insn_n_loads  = ev->actual_n_loads
                ? ev->actual_n_loads[i]  : 0;
            uint32_t insn_n_stores = ev->actual_n_stores
                ? ev->actual_n_stores[i] : 0;
            warn_memop_overflow(ev->tmpl, i, insn_n_loads, insn_n_stores);

            /* N_LOADS / N_STORES — per-iter runtime counts, always
             * visited.  Default 0 (template carries no static count). */
            if (ev->actual_n_loads) {
                STAGE_U64(i, CST_FID_N_LOADS, insn_n_loads, 0);
            }
            if (ev->actual_n_stores) {
                STAGE_U64(i, CST_FID_N_STORES, insn_n_stores, 0);
            }

            /* METAFLAGS — gated by regdata + writes_int_flags + reg
             * snap availability.  Mapper resolved per-ISA above. */
            if (metaflags_mapper && f->writes_int_flags &&
                reg_snaps && insn_rs_off) {
                for (uint8_t k = 0; k < f->n_dst_regs; k++) {
                    if (f->dst_regs[k] != REG_FLAGS) continue;
                    uint32_t pos = insn_rs_off[i] + (uint32_t)k;
                    if (pos < reg_snaps->size()) {
                        uint64_t raw = (*reg_snaps)[pos].value.limb[0];
                        STAGE_U64(i, CST_FID_METAFLAGS,
                                  metaflags_mapper(raw), 0);
                    }
                    break;
                }
            }

            /* Memop families — sparse over actual_n_loads / n_stores.
             * Inlined extract: load_slots[i*SLOT_COUNT + s] is the
             * authoritative source (see find_memop_slot). */
            uint8_t n_loads_cap  = cap_min(insn_n_loads);
            uint8_t n_stores_cap = cap_min(insn_n_stores);
            if (load_slots) {
                size_t la_base = (size_t)i * CST_FID_SLOT_COUNT;
                for (uint8_t s = 0; s < n_loads_cap; s++) {
                    const DynParam *dp = load_slots[la_base + s];
                    if (!dp) continue;
                    uint16_t la_fid = (uint16_t)(CST_FID_LOAD_ADDR_BASE +
                                                 s * CST_FID_SLOT_STRIDE);
                    STAGE_U64(i, la_fid, dp->value, 0);
                    /* Physical PAGE base (physaddr, system mode).  Omitted
                     * when no translation was observable (ppage_valid=false:
                     * user mode, MMIO, garbage-filled wrong path) so the
                     * delta stream keeps the last real translation and an
                     * in-page walk costs zero bytes. */
                    if (want_physaddr && dp->ppage_valid) {
                        uint16_t lpp_fid =
                            (uint16_t)(CST_FID_LOAD_PPAGE_BASE +
                                       s * CST_FID_PPAGE_BLOCK_STRIDE);
                        STAGE_U64(i, lpp_fid, dp->ppage, 0);
                    }
                    if (want_memdata) {
                        U512 cur = dp->data;
                        u512_mask_bytes(&cur, dp->data_size);
                        uint16_t ld_fid =
                            (uint16_t)(CST_FID_LOAD_DATA_BASE +
                                       s * CST_FID_SLOT_STRIDE);
                        STAGE_WIDE(i, ld_fid, fd_load_data, s, cur);
                        /* Byte width of the access, for value prediction.
                         * Narrow (1..64), mostly static -> ~one delta per
                         * slot per segment. */
                        uint16_t lsz_fid =
                            (uint16_t)(CST_FID_LOAD_SIZE_BASE +
                                       s * CST_FID_SLOT_STRIDE);
                        STAGE_U64(i, lsz_fid, dp->data_size, 0);
                    }
                }
            }
            if (store_slots) {
                size_t sa_base = (size_t)i * CST_FID_SLOT_COUNT;
                for (uint8_t s = 0; s < n_stores_cap; s++) {
                    const DynParam *dp = store_slots[sa_base + s];
                    if (!dp) continue;
                    uint16_t sa_fid = (uint16_t)(CST_FID_STORE_ADDR_BASE +
                                                 s * CST_FID_SLOT_STRIDE);
                    STAGE_U64(i, sa_fid, dp->value, 0);
                    /* Physical PAGE base (physaddr, system mode); see the
                     * load path above. */
                    if (want_physaddr && dp->ppage_valid) {
                        uint16_t spp_fid =
                            (uint16_t)(CST_FID_STORE_PPAGE_BASE +
                                       s * CST_FID_PPAGE_BLOCK_STRIDE);
                        STAGE_U64(i, spp_fid, dp->ppage, 0);
                    }
                    if (want_memdata) {
                        U512 cur = dp->data;
                        u512_mask_bytes(&cur, dp->data_size);
                        uint16_t sd_fid =
                            (uint16_t)(CST_FID_STORE_DATA_BASE +
                                       s * CST_FID_SLOT_STRIDE);
                        STAGE_WIDE(i, sd_fid, fd_store_data, s, cur);
                        uint16_t ssz_fid =
                            (uint16_t)(CST_FID_STORE_SIZE_BASE +
                                       s * CST_FID_SLOT_STRIDE);
                        STAGE_U64(i, ssz_fid, dp->data_size, 0);
                    }
                }
            }

            /* DST_REG — wide family, gated by regdata + per-insn n_dst.
             * Inline extract: reg_snaps[insn_rs_off[i] + slot]. */
            if (want_regdata && reg_snaps && insn_rs_off) {
                uint8_t n_dsts = f->n_dst_regs;
                uint32_t rs_off = insn_rs_off[i];
                for (uint8_t s = 0; s < n_dsts; s++) {
                    uint32_t pos = rs_off + (uint32_t)s;
                    if (pos >= reg_snaps->size()) break;
                    uint16_t fid = (uint16_t)(CST_FID_DST_REG_BASE +
                                              s * CST_FID_SLOT_STRIDE);
                    STAGE_WIDE(i, fid, fd_dst_reg, s,
                               (*reg_snaps)[pos].value);
                    /* Architectural write width, for value prediction. */
                    uint16_t dw_fid =
                        (uint16_t)(CST_FID_DST_REG_WIDTH_BASE +
                                   s * CST_FID_SLOT_STRIDE);
                    STAGE_U64(i, dw_fid, (*reg_snaps)[pos].width_bytes, 0);
                }
            }

            /* Lane masks — only for vec insns.  These still go through
             * the fd dispatch because each family has its own non-
             * trivial extraction (memop_data_lane_mask vs reg-side
             * lookups); the cost is negligible on scalar code. */
            if (f->has_vec_lanes) {
                uint8_t n_src = f->n_src_regs;
                uint8_t n_dst = f->n_dst_regs;
                uint8_t n_ml  = f->max_dep_loads;
                uint8_t n_ms  = f->max_dep_stores;
                for (uint8_t s = 0; s < n_src; s++) {
                    uint64_t cur;
                    if (!fd_src_lm->extract_u64(ev, i, s, &cur)) continue;
                    uint16_t fid = (uint16_t)(CST_FID_SRC_LANE_MASK_BASE +
                                              s * CST_FID_LANE_BLOCK_STRIDE);
                    STAGE_U64(i, fid, cur, 0);
                }
                for (uint8_t s = 0; s < n_dst; s++) {
                    uint64_t cur;
                    if (!fd_dst_lm->extract_u64(ev, i, s, &cur)) continue;
                    uint16_t fid = (uint16_t)(CST_FID_DST_LANE_MASK_BASE +
                                              s * CST_FID_LANE_BLOCK_STRIDE);
                    STAGE_U64(i, fid, cur, 0);
                }
                for (uint8_t s = 0; s < n_ml; s++) {
                    uint64_t cur;
                    if (!fd_load_lm->extract_u64(ev, i, s, &cur)) continue;
                    uint16_t fid =
                        (uint16_t)(CST_FID_LOAD_DATA_LANE_MASK_BASE +
                                   s * CST_FID_LANE_BLOCK_STRIDE);
                    STAGE_U64(i, fid, cur, 0);
                }
                for (uint8_t s = 0; s < n_ms; s++) {
                    uint64_t cur;
                    if (!fd_store_lm->extract_u64(ev, i, s, &cur)) continue;
                    uint16_t fid =
                        (uint16_t)(CST_FID_STORE_DATA_LANE_MASK_BASE +
                                   s * CST_FID_LANE_BLOCK_STRIDE);
                    STAGE_U64(i, fid, cur, 0);
                }
            }
        }

        /* Branch-outcome singletons (CST_FID_BRANCH_TAKEN / _TARGET).  Once
         * per entry, on the terminating branch of a branch-terminated BB —
         * on BOTH the correct path and every wrong-path chain block — when
         * the successor is known (see BodyEntry / WPBBEntry
         * branch_successor_*).  A page-split continuation (no branch) or the
         * segment-final flush stages neither, so those entries carry no
         * direction/target.
         *
         * TAKEN  = the successor diverged from the template's fall-through,
         *          with unconditional terminators always "taken" — identical
         *          to profile_branch's classification and to the decoder's
         *          successor-derived cross-check.
         * TARGET = the branch's landing PC encoded as a SIGNED DISPLACEMENT
         *          from the branch instruction's own PC (successor -
         *          branch_pc), NOT the raw PC.  A direct branch's displacement
         *          is a tiny sleb even on its first sighting; an indirect
         *          target is still far smaller than a full 64-bit PC.  The
         *          decoder reconstructs successor = branch_pc + displacement.
         *
         * Both delta-encode against the branch insn's own prior value
         * (default 0) through the same overlay as every other family: on the
         * correct path that is cp_state; on the wrong path it is
         * wp_state -> wp_base(CP) -> default, exactly like LOAD_ADDR, so a WP
         * branch repeating a CP or earlier-WP displacement costs zero record
         * bytes and WP overhead tracks CP overhead. */
        if (ev->branch_known && ev->tmpl) {
            int bidx = TemplateStore::template_branch_index(ev->tmpl);
            if (bidx >= 0) {
                const InsnFields *bf = &ev->tmpl->insn_fields[bidx];
                uint64_t target = ev->branch_successor_pc;
                bool taken = (target != ev->tmpl->fall_through_pc);
                if (!bf->branch_conditional) taken = true;
                uint64_t branch_pc = ev->tmpl->insn_pcs
                    ? ev->tmpl->insn_pcs[bidx] : ev->tmpl->start_pc;
                /* Signed displacement held two's-complement in a u64; the
                 * delta model sleb-encodes it small in either direction. */
                uint64_t disp = target - branch_pc;
                STAGE_U64((uint32_t)bidx, CST_FID_BRANCH_TAKEN,
                          (uint64_t)(taken ? 1 : 0), 0);
                STAGE_U64((uint32_t)bidx, CST_FID_BRANCH_TARGET, disp, 0);
            }
        }
#undef STAGE_U64
#undef STAGE_WIDE
    }

    /* Wire requires non-descending (ins_pos, fid).  The family-major
     * collection loop is ascending per-insn except for the slotted
     * families' interleave, so sort by (pos, fid) here. */
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
    /* Emit from the scratch buffer without freeing it. */
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
                                 uint32_t seed_thread_id,
                                 double simpoint_weight,
                                 const std::vector<InitialRegSnap> *regfile)
{
    if (!g_field_state_slot_lut_built) {
        field_state_slot_lut_build();
    }

    /*
     * new (not g_new0) — BodyStreamState has std::vector members.
     * body_stream_finish frees inner resources but not the struct;
     * body_stream_free deletes it.
     */
    BodyStreamState *st = new BodyStreamState();

    /* Body destination — streams via @w; leading + trailing CST_MAGIC
     * make truncation detectable from either end. */
    bw_init_writer(&st->bw, w);
    bw_write_u32_le(&st->bw, CST_MAGIC);

    /* Header — buffered in memory until body_stream_finish flushes it.
     * Layout: magic, isa, flags, window descriptors, strings, encoding
     * maps, templates section (appended at finish).  Own tar member,
     * no trailer, implicit offsets. */
    bw_init_buf(&st->header_bw);
    bw_write_u32_le(&st->header_bw, CST_MAGIC);
    bw_write_u8(&st->header_bw, (uint8_t)trace_isa);

    uint8_t flags = 0;
    if (g_features.mem_data) {
        flags |= CST_FLAG_MEM_DATA;
    }
    if (g_features.reg_data) {
        flags |= CST_FLAG_REG_DATA;
    }
    /* Set when each template carries the §6 profile block; clear
     * when the block is omitted. */
    flags |= CST_FLAG_PROFILE;
    /* Set when entries carry the wrong-path chain + events
     * sections; clear when wrong-path simulation is off, so a
     * no-WP trace pays no per-entry WP framing. */
    if (enable_wrong_path) {
        flags |= CST_FLAG_WP;
    }
    /* System-mode sync-fault trailer: each entry carries its
     * exception-nesting depth (+ anchor on a faulting BB).  This is the
     * kernel-privilege depth machinery; the wrong-path synthetic-fault
     * marking policy (wp_synthetic_marking) is independent and adds no
     * trailer. */
    if (g_features.fault_depth_trailer) {
        flags |= CST_FLAG_FAULT;
    }
    /* Physical-page families present (system mode, physaddr=1).  Advertised
     * only when on, so a non-physaddr trace's field_id map + flag vocabulary
     * are byte-identical to a writer that predates the feature. */
    if (g_features.physaddr) {
        flags |= CST_FLAG_PHYSADDR;
    }
    bw_write_u8(&st->header_bw, flags);
    st->header_flags = flags;

    /* Segment instruction-window descriptors:
     *   start_insn         : global icount anchor for body records.
     *   warmup_insns       : cache/predictor priming, not evaluated;
     *                        0 for non-simpoint.
     *   total_target_insns : configured (targeted, not observed —
     *                        TB-granularity overshoot not reflected)
     *                        length.  simpoint = warmup+sim;
     *                        non-simpoint w/ stop = stop-start;
     *                        unbounded = 0. */
    bw_write_uleb128(&st->header_bw, start_insn);
    bw_write_uleb128(&st->header_bw, warmup_insns);
    bw_write_uleb128(&st->header_bw, total_target_insns);

    /* SimPoint weight: whole-program execution fraction this segment
     * represents (weighted-sum reconstruction without the .weights
     * file).  0.0 for non-simpoint.  Raw LE IEEE-754 double, not a
     * varint (non-integer, one per header). */
    {
        uint64_t bits;
        memcpy(&bits, &simpoint_weight, sizeof(bits));
        bw_write_u64_le(&st->header_bw, bits);
    }

    /* Header strings: bw_write_string writes uleb len + bytes, and
     * treats null as the empty string (len 0) — same wire bytes the
     * inline form produced. */
    bw_write_string(&st->header_bw, qemu_command_line);
    bw_write_string(&st->header_bw, seg_datetime);
    bw_write_string(&st->header_bw, trace_comment);
    bw_write_string(&st->header_bw, target_name);

    write_header_encoding_maps(&st->header_bw);
    bw_byte_align(&st->header_bw);

    /* Flush the body magic prefix; BODY_TAG_* records start at
     * offset 4. */
    bw_byte_align(&st->bw);
    bw_flush(&st->bw);

    /* Base 0.  The first body record is forced to be a THREAD_SWITCH
     * (see thread_announced), so the starting thread is an ordinary
     * delta-from-0 with no special-case base. */
    st->current_thread = 0;
    st->thread_announced = false;

    /* Base 0.  The first body record is forced to be an ASID_SWITCH
     * (see asid_announced), so the starting asid is an ordinary
     * delta-from-0 declaring the opening (asid, thread) context.  The
     * identity tracker starts empty and grows on first sighting. */
    st->current_asid = 0;
    st->asid_announced = false;
    st->asid_identity_emitted.clear();

    /* Per-thread FieldStateTables lazy-allocate on first emit. */
    st->iframe_cp_scratch = nullptr;  /* lazy on first IFRAME */
    st->iframe_wp_scratch = nullptr;

    /*
     * Seed regfile: held until @seed_thread_id's first body emit
     * (written as BODY_TAG_REGFILE) iff the caller supplied one with
     * a live (width>0) value.  Other threads capture live at first
     * emit.  Install-time opens (cpu_index=-1) yield an all-width-0
     * stub treated as absent so every thread captures live.  A joiner
     * racing in before the seed's first emit just captures its own;
     * the seed regfile stays pinned to @seed_thread_id.
     */
    bool any_live = false;
    if (regfile) {
        for (const InitialRegSnap &s : *regfile) {
            if (s.width_bytes > 0) { any_live = true; break; }
        }
    }
    if (any_live) {
        st->seed_regfile = *regfile;
        st->seed_thread = (int32_t)seed_thread_id;
    }

    /* Pre-allocate the per-entry scratch; growth on demand. */
    raw_buf_init(&st->rec_scratch);
    raw_buf_reserve(&st->rec_scratch, 256);
    raw_buf_init(&st->sub_scratch);
    raw_buf_reserve(&st->sub_scratch, 256);
    st->stage_cap = 64;
    st->stage_buf = (StageRec *)g_malloc(sizeof(StageRec) * st->stage_cap);

    return st;
}

/*
 * Build an EntryView and emit one length-prefixed delta_section.
 * field_descriptors[] is the single source of truth for the wire
 * fields.
 */
/*
 * The four pieces that identify one BB record to delta-encode: its template
 * id, the template itself, and the dynamic params / register snapshots
 * observed for this execution.  Grouped so they travel together through the
 * emit_one_bb_delta* path instead of as a four-argument clump.
 */
struct BBDeltaInput {
    uint32_t                     template_id;
    const BBTemplate            *tmpl;
    const std::vector<DynParam> *dyn_params;
    const std::vector<RegSnap>  *reg_snaps;
    /* Terminal-branch outcome, threaded to the CST_FID_BRANCH_* staging. */
    bool                         branch_known = false;
    uint64_t                     branch_successor_pc = 0;
};

static void emit_one_bb_delta_with_base(BitWriter *bw, BodyStreamState *st,
                                        FieldStateTable *state,
                                        FieldStateTable *base_state,
                                        const BBDeltaInput &rec,
                                        bool is_wp,
                                        unsigned int cpu_index)
{
    EntryView ev;
    uint32_t n = rec.tmpl ? rec.tmpl->n_insns : 0;
    EntryViewScratch *scratch = &st->ev_scratch;
    entry_view_scratch_ensure(scratch, n);
    build_entry_view(&ev, rec.tmpl, rec.dyn_params, rec.reg_snaps,
                     scratch->actual_n_loads,
                     scratch->actual_n_stores,
                     scratch->insn_dp_off,
                     scratch->insn_rs_off,
                     scratch->load_slots,
                     scratch->store_slots);
    ev.cpu_index = cpu_index;
    ev.branch_known         = rec.branch_known;
    ev.branch_successor_pc  = rec.branch_successor_pc;
    emit_field_delta_section(bw, st, state, base_state, rec.template_id,
                             &ev, is_wp, st->header_flags);
}

static void emit_one_bb_delta(BitWriter *bw, BodyStreamState *st,
                              FieldStateTable *state, const BBDeltaInput &rec,
                              bool is_wp, unsigned int cpu_index)
{
    emit_one_bb_delta_with_base(bw, st, state, nullptr, rec, is_wp, cpu_index);
}

/*
 * Emit one body-record payload (CP section + WP chain + WP events)
 * using the supplied overlays.  The header tag and any tmpl_delta are
 * the caller's responsibility (ENTRY has a tmpl_delta; IFRAME omits
 * it, inheriting the preceding ENTRY's template).
 *
 * ENTRY passes the persistent overlays (deltas compress, post-record
 * state reflects the observation).  IFRAME passes generation-bumped
 * scratch overlays so all baselines fall to template_default (every
 * value absolute); the persistent overlays are untouched, which is
 * what makes IFRAMEs validation-only.
 */
static void emit_body_record_payload(
    BodyStreamState *st, BitWriter *bw, BodyEntry *entry, uint32_t num_wp,
    FieldStateTable *cp_state, FieldStateTable *wp_state,
    FieldStateTable *wp_base)
{
    emit_one_bb_delta(bw, st, cp_state,
                      {entry->template_id, entry->tmpl,
                       &entry->dyn_params, &entry->reg_snaps,
                       entry->branch_successor_known,
                       entry->branch_successor_pc},
                      false, entry->cpu_index);

    /* Per-entry synchronous-fault trailer (CST_FLAG_FAULT, system mode):
     * the exception-nesting depth at which this BB executed.  0 = normal
     * (non-handler) code; >=1 = synchronous-fault handler code that detoured
     * execution at that nesting level.  Written before the WP sections so it
     * is present whether or not CST_FLAG_WP is set. */
    if (st->header_flags & CST_FLAG_FAULT) {
        bw_write_uleb128(bw, (uint64_t)entry->fault_depth);
        /* Faulting-instruction anchors for a whole-BB-merged faulting BB
         * (one index per fault excursion, in order).  n=0 on ordinary
         * entries and on handler entries. */
        bw_write_uleb128(bw, (uint64_t)entry->fault_anchors.size());
        for (uint32_t a : entry->fault_anchors) {
            bw_write_uleb128(bw, (uint64_t)a);
        }
    }

    /* The wrong-path chain + events sections follow only when
     * CST_FLAG_WP is set.  With wrong-path simulation off the entry
     * is just its CP delta — no per-entry WP framing. */
    if (!(st->header_flags & CST_FLAG_WP)) {
        return;
    }

    /* WP chain sub-section */
    {
        BitWriter sub;
        bw_section_begin_rb(&sub, &st->sub_scratch);
        bw_write_uleb128(&sub, num_wp);
        int64_t prev_wp_template = 0;
        for (uint32_t w = 0; w < num_wp; w++) {
            const WPBBEntry *wp = &entry->wp_entries[w];
            uint32_t wp_tmpl = wp->template_id;
            bw_write_sleb128(&sub, (int64_t)wp_tmpl - prev_wp_template);
            prev_wp_template = wp_tmpl;
            /* WP branch-outcome singletons ride here too: the WP block's
             * successor (walker's commit_post_pc) is threaded through so the
             * CST_FID_BRANCH_* deltas resolve against wp_state -> wp_base(CP)
             * -> default — the same overlay LOAD_ADDR uses — instead of a
             * fresh baseline per chain. */
            emit_one_bb_delta_with_base(&sub, st, wp_state, wp_base,
                                        {wp_tmpl, wp->tmpl,
                                         &wp->dyn_params, &wp->reg_snaps,
                                         wp->branch_successor_known,
                                         wp->branch_successor_pc},
                                        true, entry->cpu_index);
        }
        bw_byte_align(&sub);
        bw_section_end_rb(bw, &st->sub_scratch);
    }

    /* WP events sub-section */
    {
        /* Chain-level event (§4.4): the excursion was kicked but its
         * FIRST wrong-path target could not be fetched/translated, so
         * the chain is empty and no per-block event can carry the
         * marker.  Encoded as a single event whose resolved index (0)
         * is >= num_wp (0) — the index-past-the-chain convention that
         * addresses the unrealized first target itself. */
        bool chain_unavail = (num_wp == 0) && entry->wp_first_tb_unavail;

        uint32_t num_events = chain_unavail ? 1 : 0;
        for (uint32_t w = 0; w < num_wp; w++) {
            const WPBBEntry *wp = &entry->wp_entries[w];
            if (wp->fault || wp->translation_unavailable) {
                num_events++;
            }
        }

        BitWriter sub;
        bw_section_begin_rb(&sub, &st->sub_scratch);
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
        if (chain_unavail) {
            bw_write_uleb128(&sub, 0);   /* pos_gap: index 0 == num_wp */
            bw_write_u8(&sub, CST_WP_EVENT_TRANSLATION_UNAVAIL);
        }
        g_stats.bin_wp_exception_bits += (bw_tell_bytes(&sub) - ev_start) * 8;

        bw_byte_align(&sub);
        bw_section_end_rb(bw, &st->sub_scratch);
    }
}

/*
 * Lazily fetch/allocate the per-context FieldStateTable for @ctx_key (the
 * combined (asid_index, thread_id) key).  The returned table is heap-owned
 * and stable across further map insertions.
 */
static FieldStateTable *get_or_create_per_thread_fst(
    std::unordered_map<uint64_t, FieldStateTable *> &m, uint64_t ctx_key)
{
    FieldStateTable *&slot = m[ctx_key];
    if (!slot) {
        slot = field_state_table_new();
    }
    return slot;
}

/*
 * Emit a BODY_TAG_REGFILE record for @thread_id (absolute reg file).
 * Wire: tag, thread_id, n_present, then (gen_id, width, bytes[width])
 * per present register.  Only width>0 entries are written; width=0
 * means "no live snapshot", decoder leaves its slot untouched.
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

/* ===================== Template profile (§6) ===================== */

static TemplateProfile *profile_get(BBTemplate *t)
{
    if (!t->profile) {
        t->profile = g_new0(TemplateProfile, 1);
        uint32_t n = t->n_insns ? t->n_insns : 1;
        t->profile->insns = g_new0(InsnProfile, n);
        for (uint32_t i = 0; i < t->n_insns; i++) {
            t->profile->insns[i].lo_cp = UINT64_MAX;
            t->profile->insns[i].lo_wp = UINT64_MAX;
        }
    }
    return t->profile;
}

/* Pages touched by a real CORRECT-PATH mem-op.  NEVER from WP — WP is
 * speculative and must not define the legitimate address space.  The
 * data-is-address flag (CP and WP) resolves against this CP-only set.
 * Page numbers are taken after ISA canonicalization, so a tagged or
 * signed pointer is keyed against the address space its access
 * actually defined (see AddrCanonicalizeFn). */
static std::unordered_set<uint64_t> g_obs_pages;

/* Canonicalize @addr for the current ISA, then reduce it to a page
 * number.  Both g_obs_pages inserts and the data-is-address lookup go
 * through this so the two sides share one address form. */
static inline uint64_t profile_canon_page(uint64_t addr)
{
    AddrCanonicalizeFn fn = isa_properties[trace_isa].canonicalize_addr;
    uint64_t canon = fn ? fn(addr) : addr;
    return canon >> CST_PROFILE_PAGE_SHIFT;
}

static inline void profile_note_page(uint64_t ea)
{
    g_obs_pages.insert(profile_canon_page(ea));
}

/* item 5: a loaded/stored value is an "address" when — interpreted in
 * the ISA's canonical address form — its page is one a real CP mem-op
 * touched.  Accesses narrower than 4 bytes cannot hold an address and
 * are never classified as one. */
static bool profile_value_is_addr(const DynParam &dp)
{
    if (dp.data_size < 4) {
        return false;            /* no data, or too narrow for an addr */
    }
    uint64_t v = dp.data.limb[0];           /* low 64 bits, LE */
    if (dp.data_size < 8) {
        v &= (~(uint64_t)0) >> (8 * (8 - dp.data_size));
    }
    return g_obs_pages.count(profile_canon_page(v)) != 0;
}

/* Per-step derivative-convergence classifier on @ea.  Returns the bin
 * (CST_PAT_REGULAR / IRREGULAR / RANDOM) for THIS step and rolls the
 * state forward.  Bins are tallied per-insn (see profile_step); the
 * insn's emitted class is the argmax bin — the regime the insn spends
 * most of its lifetime in.
 *
 * Two complementary tests run per step (see champsim_tracer.h, the
 * "Access-pattern class" block, for the full design rationale):
 *
 *  1. POLYNOMIAL CHAIN in absolute-magnitude space.  Walk derivative
 *     levels 0..CST_PAT_POLY_DEPTH-1, where each level k stores the
 *     previously-seen |Δ^(k+1)f| and the next level's "cur" is the
 *     abs difference of this level's cur and the stored value.
 *     Convergence at level 0 ⇒ REGULAR; convergence at any deeper
 *     level ⇒ IRREGULAR.  K=4 covers up to degree-4 polynomial
 *     access streams.  Taking abs at every level prevents bounded-
 *     complexity patterns whose signed deltas oscillate from being
 *     misclassified as a higher order than they structurally are
 *     (e.g. 0,1,3,4,6,7 ⇒ |d|=1,2,1,2,1 ⇒ |ddelta|=1 everywhere ⇒
 *     IRREGULAR; signed-only would mark this RANDOM).
 *
 *  2. GEOMETRIC RESCUE (constant-ratio detection).  Applied at EVERY
 *     polynomial level the walk descends past — exponential
 *     components survive any number of differences while polynomial
 *     components annihilate after enough, so testing at every walked
 *     level catches any (polynomial of degree <= K-2) + (exponential)
 *     mixture (the polynomial annihilates by some level k <= K-2 and
 *     the exponential shows a constant ratio at that level).  Test
 *     in exact-integer cross-multiply form at level k:
 *         |Δ^(k+1)|_n * |Δ^(k+1)|_{n-2}  ==  |Δ^(k+1)|_{n-1}^2
 *     128-bit multiply keeps the test safe up to magnitudes of 2^64
 *     (real-world deltas comfortably fit in 32–48 bits).  Requires
 *     |Δ^(k+1)|_{n-2} > 0 to exclude the degenerate all-zero case
 *     (which the polynomial test already classifies as REGULAR).
 *     Fires the rescue only when the polynomial chain returned
 *     RANDOM; otherwise the polynomial result wins.
 *
 * No magnitude threshold: convergence is a structural property, not a
 * size one.  A 1-byte and a 1-MiB constant stride are both REGULAR. */
static inline uint64_t profile_abs_i64(int64_t v)
{
    /* Safe abs for two's-complement: avoids UB on INT64_MIN.  EAs in
     * practice live in 48-bit canonical space so deltas comfortably
     * fit in int64; this is defensive only. */
    return v < 0 ? (uint64_t)(-(v + 1)) + 1u : (uint64_t)v;
}

static uint8_t profile_stride_step(StrideState *s, uint64_t ea)
{
    if (!s->have_addr) {
        s->prev_addr = ea;
        s->have_addr = 1;
        return CST_PAT_REGULAR;
    }
    int64_t d = (int64_t)(ea - s->prev_addr);
    s->prev_addr = ea;
    uint64_t ad = profile_abs_i64(d);

    /* Walk the polynomial-convergence chain.  At each level k:
     *  - !have at level k ⇒ store cur, default REGULAR (k=0) /
     *    IRREGULAR (k>=1), stop.
     *  - cur == prev_abs_d[k] ⇒ convergence at level k, return
     *    REGULAR (k=0) / IRREGULAR (k>=1), stop.
     *  - otherwise: run the level-k geometric cross-multiply test
     *    on cur, prev_abs_d[k], prev_prev_abs_d[k] (skipped until
     *    have_pprev_d_mask bit is set — needs three consecutive
     *    samples at this level), then shift prev_prev_abs_d[k] :=
     *    prev_abs_d[k], compute next = ||cur - prev_abs_d[k]|, and
     *    descend to level k+1.
     *
     * If the polynomial walk reaches the end of the chain without
     * converging (cls_set still false), cls is RANDOM by default,
     * overridden to IRREGULAR if any per-level geo test fired. */
    uint8_t cls = CST_PAT_RANDOM;
    bool cls_set = false;
    bool geo_fired = false;
    uint64_t cur = ad;
    for (int k = 0; k < CST_PAT_POLY_DEPTH; k++) {
        uint8_t bit = (uint8_t)(1u << k);
        if (!(s->have_d_mask & bit)) {
            s->prev_abs_d[k] = cur;
            s->have_d_mask = (uint8_t)(s->have_d_mask | bit);
            cls = (k == 0) ? CST_PAT_REGULAR : CST_PAT_IRREGULAR;
            cls_set = true;
            break;
        }
        uint64_t prev_k = s->prev_abs_d[k];
        if (cur == prev_k) {
            cls = (k == 0) ? CST_PAT_REGULAR : CST_PAT_IRREGULAR;
            cls_set = true;
            break;
        }
        /* Level-k geometric test: cur * prev_prev[k] == prev[k]^2.
         * Needs three level-k samples (the third one is cur right
         * now); also requires prev_prev > 0 so the degenerate
         * (0,0,0) sequence does not fire (already REGULAR via the
         * convergence path anyway). */
        if (!geo_fired && (s->have_pprev_d_mask & bit) != 0 &&
            s->prev_prev_abs_d[k] > 0) {
            __uint128_t lhs = (__uint128_t)cur *
                              (__uint128_t)s->prev_prev_abs_d[k];
            __uint128_t rhs = (__uint128_t)prev_k * (__uint128_t)prev_k;
            if (lhs == rhs) {
                geo_fired = true;
            }
        }
        /* Shift level-k state forward: today's prev becomes
         * tomorrow's prev-prev; cur becomes the new prev. */
        s->prev_prev_abs_d[k] = prev_k;
        s->have_pprev_d_mask = (uint8_t)(s->have_pprev_d_mask | bit);
        s->prev_abs_d[k] = cur;
        cur = (cur >= prev_k) ? cur - prev_k : prev_k - cur;
    }
    if (!cls_set) {
        cls = geo_fired ? CST_PAT_IRREGULAR : CST_PAT_RANDOM;
    }
    return cls;
}

/* Spatial (cross-instruction) classifier — per-page StrideState keyed
 * by page number.  Within a page, every memop's offset feeds the same
 * StrideState, so a stencil sweep registers REGULAR even when the
 * individual insns alternate.  Two maps (CP / WP) because wrong-path
 * memops on a page must not bleed into the committed-path picture.
 * Lifetime parallels g_obs_pages (per-process cumulative). */
static std::unordered_map<uint64_t, StrideState> g_page_stride_cp;
static std::unordered_map<uint64_t, StrideState> g_page_stride_wp;

/* Feed @ea (canonicalized within its page) to the spatial classifier
 * and return the bin assigned to THIS step.  Uses within-page offset
 * (not absolute ea) so deltas reflect movement within the page; page
 * selection itself is captured by the map keying, not the delta. */
static uint8_t profile_spatial_step(uint64_t ea, bool wp)
{
    uint64_t page = profile_canon_page(ea);
    uint64_t offset = ea & ((((uint64_t)1) << CST_PROFILE_PAGE_SHIFT) - 1);
    auto &m = wp ? g_page_stride_wp : g_page_stride_cp;
    StrideState &s = m[page];
    return profile_stride_step(&s, offset);
}

/* Per-insn memop step (items 3/4/6).  Classifies THIS access against
 * the PC-keyed and page-keyed stride machines and tallies both bins
 * into the insn's per-stream histograms; write_template_profile takes
 * argmax to pick the dominant class per stream and composes both with
 * a min (lower = more regular wins). */
static void profile_step(InsnProfile *ip, uint64_t ea, bool wp,
                         bool is_addr)
{
    uint64_t *lo  = wp ? &ip->lo_wp : &ip->lo_cp;
    uint64_t *hi  = wp ? &ip->hi_wp : &ip->hi_cp;
    uint64_t *mc  = wp ? &ip->memops_wp : &ip->memops_cp;
    StrideState *s = wp ? &ip->stride_wp : &ip->stride_cp;
    uint32_t *pc_bins = wp ? ip->pc_bins_wp : ip->pc_bins_cp;
    uint32_t *sp_bins = wp ? ip->spatial_bins_wp : ip->spatial_bins_cp;
    uint8_t *adr  = wp ? &ip->addr_wp : &ip->addr_cp;

    (*mc)++;
    if (ea < *lo) *lo = ea;
    if (ea > *hi) *hi = ea;

    uint8_t pc_bin = profile_stride_step(s, ea);
    uint8_t sp_bin = profile_spatial_step(ea, wp);
    pc_bins[pc_bin - CST_PAT_REGULAR]++;
    sp_bins[sp_bin - CST_PAT_REGULAR]++;

    if (is_addr) *adr = 1;
}

/* Pick the highest-count bin from a [REGULAR, IRREGULAR, RANDOM]
 * histogram.  Ties resolve toward the LOWER class (more regular) by
 * walking REGULAR → IRREGULAR → RANDOM and updating only on a strict
 * win; an insn with no memops returns CST_PAT_NONE so callers can
 * suppress the bit. */
static uint8_t profile_argmax_bin(const uint32_t bins[3])
{
    if (bins[0] == 0 && bins[1] == 0 && bins[2] == 0) {
        return CST_PAT_NONE;
    }
    uint32_t best = bins[0];
    uint8_t  cls  = CST_PAT_REGULAR;
    if (bins[1] > best) { best = bins[1]; cls = CST_PAT_IRREGULAR; }
    if (bins[2] > best) { best = bins[2]; cls = CST_PAT_RANDOM; }
    return cls;
}

static void profile_accumulate(BBTemplate *t,
                               const std::vector<DynParam> &dps,
                               bool wp)
{
    if (!t) return;
    TemplateProfile *p = profile_get(t);
    if (wp) p->exec_wp++; else p->exec_cp++;
    for (const DynParam &dp : dps) {
        if (dp.insn_index >= t->n_insns) continue;
        if (!wp) profile_note_page(dp.value);   /* CP defines pages */
        profile_step(&p->insns[dp.insn_index], dp.value, wp,
                     profile_value_is_addr(dp));
    }
}

/* Terminal-branch outcome (item 2) for the BB whose template is
 * @t, given the next executed PC @next_pc.  taken == control did
 * NOT fall through.  Unconditional/call/ret terminators are always
 * "taken".  No-op when the BB does not end in a branch. */
static void profile_branch(BBTemplate *t, uint64_t next_pc, bool wp)
{
    if (!t || t->n_insns == 0) return;
    /* The terminating branch is at template_branch_index (n-1 normally,
     * n-2 on delay-slot ISAs where the delay slot is last). */
    int bidx = TemplateStore::template_branch_index(t);
    if (bidx < 0) return;
    const InsnFields *last = &t->insn_fields[bidx];
    TemplateProfile *p = profile_get(t);
    bool taken = (next_pc != t->fall_through_pc);
    if (!last->branch_conditional) taken = true;
    if (wp) {
        if (taken) p->br_taken_wp++; else p->br_nottaken_wp++;
    } else {
        if (taken) p->br_taken_cp++; else p->br_nottaken_cp++;
        /* Indirect terminator: keep a per-template target tally so
         * overlapping BBs sharing the same terminal branch PC don't
         * over-attribute the per-PC g_branch_history aggregate.  The
         * tally is only built for indirect/return (multi-target) BBs;
         * non-indirect BBs have exactly one taken edge captured by
         * br_taken_cp / br_nottaken_cp. */
        bool indirect =
            last->branch_type == BRANCH_INDIRECT_JUMP ||
            last->branch_type == BRANCH_RETURN ||
            last->branch_type == BRANCH_INDIRECT_CALL;
        if (indirect && taken) {
            for (uint8_t k = 0; k < p->n_indirect_targets; k++) {
                if (p->indirect_targets[k].target == next_pc) {
                    p->indirect_targets[k].count_cp++;
                    return;
                }
            }
            if (p->n_indirect_targets < CST_PROFILE_INDIRECT_TARGETS_CAP) {
                p->indirect_targets[p->n_indirect_targets].target = next_pc;
                p->indirect_targets[p->n_indirect_targets].count_cp = 1;
                p->n_indirect_targets++;
            }
            /* Capacity exhausted: silently drop.  Matches BranchRecord's
             * LRU behaviour at the per-PC layer; the profile block is
             * advisory metadata, not replay state. */
        }
    }
}

/*
 * Template profile accumulation (§6).  Pure metadata, serialized later in
 * write_bin_templates.
 *   - CP: the prev CP BB's terminal branch is now resolvable (its
 *     successor is this BB's start_pc); classify and remember.
 *   - WP: chain order gives each non-final WP BB's successor.
 */
static void accumulate_template_profiles(BodyStreamState *st, BodyEntry *entry,
                                         uint32_t num_wp)
{
    profile_accumulate(entry->tmpl, entry->dyn_params, false);
    if (st->prev_cp_tmpl && entry->tmpl) {
        profile_branch(st->prev_cp_tmpl, entry->tmpl->start_pc, false);
    }
    if (entry->tmpl) {
        st->prev_cp_tmpl = entry->tmpl;
    }
    for (uint32_t w = 0; w < num_wp; w++) {
        WPBBEntry &wp = entry->wp_entries[w];
        profile_accumulate(wp.tmpl, wp.dyn_params, true);
        if (!wp.fault && w + 1 < num_wp) {
            profile_branch(wp.tmpl, entry->wp_entries[w + 1].start_pc, true);
        }
    }
}

/*
 * Announce a BODY_TAG_ASID_SWITCH when the active address space changes
 * (and on the very first entry, giving every trace a mandatory opening
 * (asid, thread) declaration).  The switch carries an sleb128 delta of
 * the compact asid index; the FIRST sighting of an index additionally
 * writes its identity — @root_phys (page-table root physical address)
 * and @sig (content signature) — inline, mirroring the per-thread
 * regfile's first-sighting emission.  Phase 1 is single-ASID: index 0 is
 * declared once and never switches again.
 */
static void emit_asid_switch_if_needed(BodyStreamState *st,
                                       uint64_t asid_index,
                                       uint64_t root_phys, uint64_t sig)
{
    if (!st->asid_announced || (int64_t)asid_index != st->current_asid) {
        bw_write_u8(&st->bw, BODY_TAG_ASID_SWITCH);
        bw_write_sleb128(&st->bw, (int64_t)asid_index - st->current_asid);
        st->current_asid = asid_index;
        st->asid_announced = true;
    }
    /* Identity rides the index's first sighting only. */
    if (asid_index >= st->asid_identity_emitted.size()) {
        st->asid_identity_emitted.resize((size_t)asid_index + 1, false);
    }
    if (!st->asid_identity_emitted[asid_index]) {
        bw_write_u64_le(&st->bw, root_phys);
        bw_write_u64_le(&st->bw, sig);
        st->asid_identity_emitted[asid_index] = true;
    }
}

/* Announce a BODY_TAG_THREAD_SWITCH when the active thread changes (and on
 * the very first entry). */
static void emit_thread_switch_if_needed(BodyStreamState *st, uint32_t tid)
{
    if (!st->thread_announced || (int64_t)tid != st->current_thread) {
        bw_write_u8(&st->bw, BODY_TAG_THREAD_SWITCH);
        bw_write_sleb128(&st->bw, (int64_t)tid - st->current_thread);
        st->current_thread = tid;
        st->thread_announced = true;
    }
}

/*
 * Per-thread regfile emission: each thread's first body entry is preceded
 * by a BODY_TAG_REGFILE so the consumer can prime that thread's simulator
 * state.  Seed thread uses the pre-first-BB snapshot (seed_regfile);
 * joiners capture live here (post-first-BB on their side — best without a
 * per-thread pre-exec hook).
 */
static void emit_regfile_if_first(BodyStreamState *st, BodyEntry *entry,
                                  uint32_t tid, uint64_t ctx_key)
{
    /* Keyed on the (asid, thread) context, but the wire record still
     * carries the bare thread_id — the register file is thread state. */
    if (st->regfile_emitted.count(ctx_key)) {
        return;
    }
    if ((int32_t)tid == st->seed_thread && !st->seed_regfile.empty()) {
        emit_regfile_record(&st->bw, tid, st->seed_regfile);
        st->seed_regfile.clear();
        st->seed_thread = -1;
    } else {
        std::vector<InitialRegSnap> snaps;
        capture_initial_regfile(entry->cpu_index, &snaps);
        emit_regfile_record(&st->bw, tid, snaps);
    }
    st->regfile_emitted.insert(ctx_key);
}

/*
 * IFRAME trigger.  Every g_features.iframe_rate emissions of this CP template, emit a
 * redundant BODY_TAG_IFRAME with the same payload but encoded against fresh
 * scratch overlays (all values absolute).  It neither advances
 * prev_entry_template nor writes a tmpl_delta (template = the preceding
 * ENTRY's) — a pure validation/resync record.
 *
 * The CP register families are re-encoded from the PERSISTENT overlay's
 * post-ENTRY state, not from the entry's own reg_snaps.  The two differ
 * whenever an entry carries no (or partial) register snapshots for a
 * template whose block already holds observed values — e.g. a REP
 * fan-out sub-entry, or any capture-miss revisit of a reg-observed
 * template: the decoder's ENTRY materialisation always reads the running
 * state for every declared dst slot, so an IFRAME re-encoded from an
 * empty snap vector emits no register records at all, decodes to
 * template-baseline values, and trips the decoder's self-validation
 * ("cp reg_snaps mismatch").  Sourcing the values from the persistent
 * block reproduces exactly what the decoder materialised for the
 * preceding ENTRY — byte-identical to the entry-sourced encoding
 * whenever the entry did carry snaps (staging wrote those same values
 * into the block), and a genuinely complete absolute dump when it
 * didn't.
 */
static void emit_iframe_if_due(BodyStreamState *st, BodyEntry *entry,
                               uint32_t num_wp, FieldStateTable *cp_persist)
{
    if (g_features.iframe_rate <= 0 || !entry->tmpl) {
        return;
    }
    entry->tmpl->emit_count++;
    if ((entry->tmpl->emit_count % g_features.iframe_rate) != 0) {
        return;
    }
    if (!st->iframe_cp_scratch) {
        st->iframe_cp_scratch = field_state_table_new();
    }
    if (!st->iframe_wp_scratch) {
        st->iframe_wp_scratch = field_state_table_new();
    }
    st->iframe_cp_scratch->generation++;
    st->iframe_wp_scratch->generation++;

    /* Synthesise the decoder-visible register snapshot from the
     * persistent CP overlay (see the function comment).  Missing cells
     * read as the template default (zero value / zero width), matching
     * the decoder's miss-to-default lookup, so the synthesised vector is
     * the decoder's ENTRY materialisation verbatim. */
    std::vector<RegSnap> synth_snaps;
    bool swapped = false;
    if ((st->header_flags & CST_FLAG_REG_DATA) && cp_persist) {
        FieldStateBlock *blk = field_state_table_get_block(
            cp_persist, entry->template_id, entry->tmpl, false);
        uint32_t gen = cp_persist->generation;
        const BBTemplate *t = entry->tmpl;
        uint32_t total = 0;
        for (uint32_t i = 0; i < t->n_insns; i++) {
            total += t->insn_fields[i].n_dst_regs;
        }
        synth_snaps.reserve(total);
        for (uint32_t i = 0; i < t->n_insns; i++) {
            uint8_t n_dsts = t->insn_fields[i].n_dst_regs;
            for (uint8_t s = 0; s < n_dsts; s++) {
                uint16_t vfid = (uint16_t)(CST_FID_DST_REG_BASE +
                                           s * CST_FID_SLOT_STRIDE);
                uint16_t wfid = (uint16_t)(CST_FID_DST_REG_WIDTH_BASE +
                                           s * CST_FID_SLOT_STRIDE);
                RegSnap rs;
                cst_wide_zero(&rs.value);
                field_state_get_wide(blk, gen, i, field_state_loc(vfid),
                                     &rs.value);
                uint64_t w = 0;
                field_state_get_scalar(blk, gen, i, field_state_loc(wfid),
                                       &w);
                rs.width_bytes = (uint8_t)w;
                synth_snaps.push_back(rs);
            }
        }
        entry->reg_snaps.swap(synth_snaps);
        swapped = true;
    }

    bw_write_u8(&st->bw, BODY_TAG_IFRAME);
    emit_body_record_payload(st, &st->bw, entry, num_wp,
                             st->iframe_cp_scratch, st->iframe_wp_scratch,
                             st->iframe_cp_scratch);

    if (swapped) {
        /* Restore the entry's own snaps (the REP fan-out loop reuses
         * the entry object across sub-iterations). */
        entry->reg_snaps.swap(synth_snaps);
    }
}

/*
 * ---- Block-device (disk) I/O records (DEVIO) ----
 *
 * Process-wide state: there is one block backend, doorbells fire on the
 * issuing vCPU thread, and completions land on the main loop thread, so
 * a GMutex guards the queues, the per-segment id counter, the live-id
 * set, and the per-vCPU doorbell slots.  The plugin's devio hooks call
 * devio_note_doorbell (vCPU context, at the virtqueue kick) /
 * devio_note_start (block backend, issue) / devio_note_stop (block
 * backend, completion); the queued START/STOP records are drained into
 * the body stream at the next body entry (devio_drain, under exec_lock).
 *
 * Attribution is PER-VCPU.  Under the canonical ioeventfd=off
 * configuration the virtqueue kick (virtio_queue_notify) and the block
 * backend's blk_aio_* issue run on the SAME vCPU thread, back to back
 * with no yield, so the kick records the issuing owner (thread, asid)
 * and the device token in that vCPU's slot, and the immediately
 * following issue reads it by vCPU index.  The token guards the slot: a
 * non-virtio (IDE/AHCI) or kernel-internal blk_aio on that vCPU carries
 * a different / absent device and stays POSITIONAL (no owner on the
 * wire; the consumer uses the record's stream-position context).  A
 * per-DEVICE queue would instead race — two vCPUs kicking one shared
 * device concurrently can interleave push/pop and cross-attribute, the
 * exact multi-vCPU case this is built to get right — so the correlation
 * key is the vCPU, not the device.
 *
 * Starts are drained before stops so a request's START always precedes
 * its STOP on the wire; a STOP whose START never reached the wire is
 * dropped (the live-id set).
 */
namespace {

struct DevioStart {
    uint64_t request_id;
    uint8_t  rw;        /* CST_DEVIO_* */
    uint64_t bytes;
    uint64_t block;     /* disk block number = offset >> CST_DEVIO_LBA_SHIFT */
    bool     exact;     /* owner correlated from a doorbell */
    uint32_t owner_thread_id;   /* valid iff exact */
    uint32_t owner_asid;        /* valid iff exact */
};

/* Per-vCPU record of the most recent block-device kick: the device it
 * kicked and the owning (thread, asid) captured in that vCPU's context.
 * The immediately following blk_aio_* issue on the same vCPU reads it. */
struct DevioKick {
    uint64_t token = 0;         /* device token, 0 = slot empty */
    uint32_t thread_id = 0;
    uint32_t asid = 0;
};

struct DevioState {
    GMutex   mtx;
    uint64_t next_id = 1;               /* compact per-segment, reset at open */
    std::vector<DevioStart> pending_starts;
    std::vector<uint64_t>   pending_stops;
    std::unordered_set<uint64_t> live_ids;  /* START emitted, STOP not yet */
    /* Last block-device kick per vCPU, keyed by vCPU index (a map, so no
     * dependency on the plugin's vCPU cap and no bound to police). */
    std::unordered_map<int, DevioKick> vcpu_kick;
};

DevioState g_devio;

} /* namespace */

void devio_set_map_active(bool on)
{
    g_devio_map_active = on;
}

void devio_note_doorbell(int vcpu_index, uint64_t dev_token,
                         uint32_t owner_thread_id, uint32_t owner_asid)
{
    if (!dev_token || vcpu_index < 0) {
        return;
    }
    g_mutex_lock(&g_devio.mtx);
    DevioKick &k = g_devio.vcpu_kick[vcpu_index];
    k.token = dev_token;
    k.thread_id = owner_thread_id;
    k.asid = owner_asid;
    g_mutex_unlock(&g_devio.mtx);
}

uint64_t devio_note_start(int vcpu_index, int dir,
                          uint64_t offset, uint64_t bytes,
                          uint64_t dev_token)
{
    DevioStart s;
    s.rw = (uint8_t)dir;   /* CST_DEVIO_* == enum qemu_plugin_devio_dir */
    s.bytes = bytes;
    s.block = offset >> CST_DEVIO_LBA_SHIFT;
    s.exact = false;
    s.owner_thread_id = 0;
    s.owner_asid = 0;
    g_mutex_lock(&g_devio.mtx);
    s.request_id = g_devio.next_id++;
    /* Exact attribution: the request was issued on a vCPU thread whose
     * most recent kick was to this same device — the kick captured the
     * issuing owner (they run back to back on that vCPU). */
    if (vcpu_index >= 0 && dev_token) {
        auto it = g_devio.vcpu_kick.find(vcpu_index);
        if (it != g_devio.vcpu_kick.end() && it->second.token == dev_token) {
            s.exact = true;
            s.owner_thread_id = it->second.thread_id;
            s.owner_asid = it->second.asid;
        }
    }
    g_devio.pending_starts.push_back(s);
    g_mutex_unlock(&g_devio.mtx);
    return s.request_id;
}

void devio_note_stop(uint64_t request_id)
{
    if (!request_id) {
        return;
    }
    g_mutex_lock(&g_devio.mtx);
    g_devio.pending_stops.push_back(request_id);
    g_mutex_unlock(&g_devio.mtx);
}

void devio_reset_segment(void)
{
    g_mutex_lock(&g_devio.mtx);
    g_devio.next_id = 1;
    g_devio.pending_starts.clear();
    g_devio.pending_stops.clear();
    g_devio.live_ids.clear();
    g_devio.vcpu_kick.clear();
    g_mutex_unlock(&g_devio.mtx);
}

/* Drain pending DEVIO records into @st's body stream at an inter-entry
 * boundary.  Caller holds exec_lock (body_stream_write_entry); the byte
 * stream is byte-aligned here (the previous entry ended with
 * bw_byte_align), and every DEVIO field is a byte-granular write, so
 * the records stay byte-aligned. */
static void devio_drain(BodyStreamState *st)
{
    std::vector<DevioStart> starts;
    std::vector<uint64_t> stops;

    g_mutex_lock(&g_devio.mtx);
    if (g_devio.pending_starts.empty() && g_devio.pending_stops.empty()) {
        g_mutex_unlock(&g_devio.mtx);
        return;
    }
    starts.swap(g_devio.pending_starts);
    for (const DevioStart &s : starts) {
        g_devio.live_ids.insert(s.request_id);
    }
    /* Partition stops into emit / drop under the lock: a stop whose id is
     * live (its START has now been queued for this drain, or reached the
     * wire in a prior drain) is emitted and retired; otherwise dropped. */
    for (uint64_t id : g_devio.pending_stops) {
        auto it = g_devio.live_ids.find(id);
        if (it != g_devio.live_ids.end()) {
            g_devio.live_ids.erase(it);
            stops.push_back(id);
        }
    }
    g_devio.pending_stops.clear();
    g_mutex_unlock(&g_devio.mtx);

    for (const DevioStart &s : starts) {
        bw_write_u8(&st->bw, BODY_TAG_DEVIO_START);
        bw_write_uleb128(&st->bw, s.request_id);
        bw_write_u8(&st->bw, s.rw);
        bw_write_uleb128(&st->bw, s.bytes);
        bw_write_uleb128(&st->bw, s.block);
        if (s.exact) {
            bw_write_u8(&st->bw, CST_DEVIO_ATTR_EXACT);
            bw_write_uleb128(&st->bw, s.owner_thread_id);
            bw_write_uleb128(&st->bw, s.owner_asid);
        } else {
            bw_write_u8(&st->bw, CST_DEVIO_ATTR_POSITIONAL);
        }
    }
    for (uint64_t id : stops) {
        bw_write_u8(&st->bw, BODY_TAG_DEVIO_STOP);
        bw_write_uleb128(&st->bw, id);
    }
}

void body_stream_write_entry(BodyStreamState *st, BodyEntry *entry)
{
    /* Flush any pending disk-I/O records at this inter-entry boundary,
     * before this entry's context declaration, so they land in the
     * owning thread's stream where the doorbell / completion occurred. */
    devio_drain(st);

    int64_t entry_tmpl = entry->template_id;
    uint32_t num_wp = (uint32_t)entry->wp_entries.size();
    uint64_t body_start = bw_tell_bytes(&st->bw);
    uint32_t tid = entry->thread_id;

    /* Wire asid tag (KPTI-off canonical model, multiasid_plan §0/§7): a
     * kernel (priv>0) block carries the OWNING PROCESS asid on the wire, not
     * the live page-table root.  entry->tmpl->is_system is the per-block
     * privilege stamp — the SAME flag serialised as CST_INSN_FLAG_SYSTEM on
     * this block's insns — so the block's system bit and its asid tag always
     * agree.  Under the canonical KPTI-off baseline the kernel shares the
     * process root, so ctx_asid_index == asid_index for kernel blocks too and
     * this is a no-op; forcing it makes the trace KPTI-INVARIANT — an isolated
     * kernel root (if the guest runs KPTI, the unsupported config) never
     * reaches the wire as an asid — and, crucially, defers a process's FIRST
     * wire sighting to its first traced USER block, where its content
     * signature is latchable.  User blocks are unchanged (ctx == live at
     * priv 0), so user-mode and single-address-space traces stay
     * byte-identical. */
    uint32_t wire_asid = entry->asid_index;
    if (entry->tmpl && entry->tmpl->is_system) {
        wire_asid = entry->ctx_asid_index;
    }

    /* The (asid, thread) context key for the per-context field-state and
     * regfile tables — the WIRE asid, so the writer's delta baselines and
     * the decoder's replay tables are keyed identically BY CONSTRUCTION.
     * Kernel blocks carry the owning process on the wire (above), so a
     * thread still keeps ONE register-file context across a user<->kernel
     * excursion.  User blocks key by their live address space — which is
     * the executing process — even where the per-vCPU ctx latch lags (the
     * latch advances only on user-owned TBs, so under multi-process
     * gating another owned process's user run would otherwise be keyed to
     * the stale latch context while its wire tag says the live process:
     * writer and decoder would then delta against different histories,
     * corrupting decoded values and tripping IFRAME validation).  User
     * mode / a single address space: wire_asid == 0 → key == tid, so
     * those traces stay byte-identical. */
    uint64_t ctx_key = ((uint64_t)wire_asid << 32) | tid;

    dyn_params_sort_template_order(entry->dyn_params);
    for (uint32_t w = 0; w < num_wp; w++) {
        dyn_params_sort_template_order(entry->wp_entries[w].dyn_params);
    }

    accumulate_template_profiles(st, entry, num_wp);
    /* Declare the (asid, thread) context before the entry it scopes.
     * ASID first so the opening pair is [ASID_SWITCH][THREAD_SWITCH].
     * Single-ASID: index 0 declared once, carrying the pinned address
     * space's REAL identity — its page-table root physical address and a
     * representative code-page content signature (both 0 in user mode /
     * unpinned, so those traces stay byte-identical).  The index and its
     * identity come from the entry itself (resolved and stored at capture):
     * single-address-space traces carry index 0 with a {0,0} or pinned
     * identity, exactly as the hardcoded emit did; Stage B's multi-process
     * gating is what makes the index vary and switch mid-stream. */
    uint64_t asid_root = 0, asid_sig = 0;
    cst_asid_identity(wire_asid, &asid_root, &asid_sig);
    emit_asid_switch_if_needed(st, wire_asid, asid_root, asid_sig);
    emit_thread_switch_if_needed(st, tid);
    emit_regfile_if_first(st, entry, tid, ctx_key);

    /* Regular delta-encoded entry against this context's persistent
     * per-(asid,thread) overlays (deltas stay within-context, compressible). */
    FieldStateTable *cp_fst = get_or_create_per_thread_fst(
        st->cp_field_state, ctx_key);
    FieldStateTable *wp_fst = get_or_create_per_thread_fst(
        st->wp_field_state, ctx_key);

    bw_write_u8(&st->bw, BODY_TAG_ENTRY);
    bw_write_sleb128(&st->bw, entry_tmpl - st->prev_entry_template);
    st->prev_entry_template = entry_tmpl;
    emit_body_record_payload(st, &st->bw, entry, num_wp,
                             cp_fst, wp_fst, cp_fst);

    emit_iframe_if_due(st, entry, num_wp, cp_fst);

    bw_byte_align(&st->bw);

    st->num_entries++;
    g_stats.bin_body_bits += (bw_tell_bytes(&st->bw) - body_start) * 8;
}

/*
 * Finish the body stream and produce the header buffer.  Member
 * layouts are specified in champsim_tracer_format.md; each is its
 * own self-contained ustar member (no trailer) assembled by the
 * segment manager after this returns.  The body's two-magic bracket
 * makes truncation visible without reading the whole stream.
 *
 * @header_bytes receives the header buffer (ownership transferred);
 * caller frees it via g_byte_array_unref.
 */
void body_stream_set_warmup_end_arch_insns(BodyStreamState *st,
                                           uint64_t value)
{
    st->warmup_end_arch_insns = value;
}

void body_stream_finish(BodyStreamState *st, GByteArray **header_bytes)
{
    /* Flush any disk-I/O records still pending at segment close (a
     * request that completed after this segment's last body entry), so
     * they are not lost across the finish. */
    devio_drain(st);

    uint64_t stats_start = bw_tell_bytes(&st->bw);

    /* --- Finalise the body member. --- */
    bw_write_u8(&st->bw, BODY_TAG_END);
    bw_write_uleb128(&st->bw, st->num_entries);
    bw_byte_align(&st->bw);
    /* Trailing CST_MAGIC: absence at end-of-stream means the body
     * was truncated.  Cheaper than a checksum; truncation is the
     * dominant corruption mode for pipe-compressed traces. */
    bw_write_u32_le(&st->bw, CST_MAGIC);
    bw_flush(&st->bw);

    /* --- warmup→simulation arch-insn marker (header §2.13). --- */
    bw_write_uleb128(&st->header_bw, st->warmup_end_arch_insns);

    /* --- Append the templates section to the header buffer. --- */
    g_mutex_lock(&data_lock);
    write_bin_templates(&st->header_bw);
    g_mutex_unlock(&data_lock);
    bw_byte_align(&st->header_bw);

    /* Transfer header buffer ownership to the caller (pointer nulled). */
    *header_bytes = bw_finish_buf(&st->header_bw);

    uint64_t end_bytes = bw_tell_bytes(&st->bw);
    g_stats.bin_header_bits += (end_bytes - stats_start) * 8;
    g_stats.bin_total_bits += end_bytes * 8;

    for (auto &kv : st->cp_field_state) {
        if (kv.second) field_state_table_free(kv.second);
    }
    st->cp_field_state.clear();
    for (auto &kv : st->wp_field_state) {
        if (kv.second) field_state_table_free(kv.second);
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
    raw_buf_free(&st->sub_scratch);
    g_free(st->stage_buf);
    st->stage_buf = nullptr;
}

void body_stream_free(BodyStreamState *st)
{
    /* `new`-allocated; body_stream_finish already released owned
     * resources, so this just runs the C++ destructors. */
    if (!st) {
        return;
    }
    delete st;
}
