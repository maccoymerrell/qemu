/*
 * ChampSim Tracer offline tools — format parsers (impl).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cst_format.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>

namespace cst {

/*
 * LEB128 slow path (out-of-line).  The uleb()/sleb() fast paths in the
 * header handle the dominant single-byte-resident case inline; these cover
 * multi-byte values and values straddling a streaming buffer refill.
 * Byte-for-byte equivalent to the original in-header loops.
 */
uint64_t Reader::uleb_slow() {
    uint64_t out = 0;
    unsigned shift = 0;
    while (true) {
        uint8_t b = u8();
        out |= uint64_t(b & 0x7F) << shift;
        if (!(b & 0x80)) return out;
        shift += 7;
        if (shift >= 64) throw std::runtime_error("ULEB128 too large");
    }
}

int64_t Reader::sleb_slow() {
    uint64_t out = 0;
    unsigned shift = 0;
    while (true) {
        uint8_t b = u8();
        out |= uint64_t(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) {
            if (shift < 64 && (b & 0x40)) {
                out |= ~uint64_t(0) << shift;
            }
            return static_cast<int64_t>(out);
        }
        if (shift >= 64) throw std::runtime_error("SLEB128 too large");
    }
}

/* ===== Template parsing (shared) ========================================= */

namespace {

void parse_encoding_maps(Reader &r, EncodingMaps *out)
{
    uint64_t n_maps = r.uleb();
    for (uint64_t i = 0; i < n_maps; i++) {
        std::string name = r.string();
        uint64_t n_entries = r.uleb();
        std::unordered_map<uint64_t, std::string> *target = nullptr;
        if      (name == "opcode")         target = &out->opcode;
        else if (name == "branch_type")    target = &out->branch_type;
        else if (name == "reg")            target = &out->reg;
        else if (name == "field_id")       target = &out->field_id;
        else if (name == "header_flag")    target = &out->header_flag;
        else if (name == "insn_flag")      target = &out->insn_flag;
        else if (name == "body_tag")       target = &out->body_tag;
        else if (name == "wp_event_flag")  target = &out->wp_event_flag;
        else if (name == "metaflags")      target = &out->metaflags;
        else if (name == "dep_block_flag") target = &out->dep_block_flag;
        else if (name == "mem_access_pattern")
            target = &out->mem_access_pattern;
        else if (name == "profile_flag")   target = &out->profile_flag;

        for (uint64_t j = 0; j < n_entries; j++) {
            uint64_t value = r.uleb();
            std::string ename = r.string();
            if (target) (*target)[value] = std::move(ename);
        }
    }
}

void parse_templates_at(Reader &r,
                        const ResolvedIds &ids,
                        uint8_t header_flags,
                        std::vector<Template> *out,
                        std::unordered_map<uint32_t, size_t> *out_by_id)
{
    /* The §6 profile block follows each template's insn descriptors
     * only when the CST_FLAG_PROFILE header bit is set;
     * otherwise t.profile is left default-constructed. */
    const bool have_profile =
        (header_flags & ids.flag_profile) != 0;
    uint64_t n = r.uleb();
    out->reserve(n);
    for (uint64_t i = 0; i < n; i++) {
        Reader sub = r.sub();
        Template t;
        t.template_id     = (uint32_t)sub.uleb();
        t.start_pc        = sub.uleb();
        uint64_t n_insns  = sub.uleb();
        t.fall_through_pc = sub.uleb();
        uint64_t n_targets = sub.uleb();
        t.target_pcs.resize(n_targets);
        for (auto &tp : t.target_pcs) {
            tp = sub.uleb();
        }
        t.symbol_name     = sub.string();

        uint64_t prev_pc = t.start_pc;
        t.insns.reserve(n_insns);
        for (uint64_t k = 0; k < n_insns; k++) {
            uint64_t delta = sub.uleb();
            uint64_t pc = (prev_pc + delta) & UINT64_MAX;
            prev_pc = pc;

            InsnTemplate I;
            I.pc          = pc;
            I.opcode      = sub.u8();
            I.branch_type = sub.u8();
            uint8_t flags = sub.u8();
            uint8_t n_src = sub.u8();
            uint8_t n_dst = sub.u8();
            I.src_regs.resize(n_src);
            for (auto &x : I.src_regs) x = sub.u8();
            I.dst_regs.resize(n_dst);
            for (auto &x : I.dst_regs) x = sub.u8();
            I.max_dep_loads  = sub.u8();
            I.max_dep_stores = sub.u8();
            I.branch_conditional = (flags & ids.insn_flag_branch_cond) != 0;
            I.has_imm            = (flags & ids.insn_flag_has_imm) != 0;
            I.is_atomic          = (flags & ids.insn_flag_atomic) != 0;
            I.lane_parallel      = (flags & ids.insn_flag_lane_parallel) != 0;
            I.is_system          = (flags & ids.insn_flag_system) != 0;
            if (I.has_imm) I.imm = sub.sleb();
            uint8_t insn_size = sub.u8();
            I.raw_bytes.resize(insn_size);
            sub.raw(I.raw_bytes.data(), insn_size);

            /* Optional dependency sub-block (HAS_REG / HAS_ADDR
             * families).  Both are parsed to keep the cursor
             * aligned. */
            if (flags & ids.insn_flag_has_dep_block) {
                uint8_t dep_flags = sub.u8();
                /* Mask array sizes come from the outer header (n_dst,
                 * max_dep_loads, max_dep_stores); masks are ULEBs. */
                if (dep_flags & ids.dep_block_has_reg) {
                    I.has_reg_deps = true;
                    I.dst_dep_mask.resize(n_dst);
                    for (uint8_t d = 0; d < n_dst; d++) {
                        I.dst_dep_mask[d] = (uint64_t)sub.uleb();
                    }
                    I.store_data_dep_mask.resize(I.max_dep_stores);
                    for (uint32_t s = 0; s < I.max_dep_stores; s++) {
                        I.store_data_dep_mask[s] = (uint64_t)sub.uleb();
                    }
                }
                if (dep_flags & ids.dep_block_has_addr) {
                    I.has_addr_deps = true;
                    I.load_addr_dep_mask.resize(I.max_dep_loads);
                    for (uint32_t l = 0; l < I.max_dep_loads; l++) {
                        I.load_addr_dep_mask[l] = (uint64_t)sub.uleb();
                    }
                    I.store_addr_dep_mask.resize(I.max_dep_stores);
                    for (uint32_t s = 0; s < I.max_dep_stores; s++) {
                        I.store_addr_dep_mask[s] = (uint64_t)sub.uleb();
                    }
                }
            }

            t.insns.push_back(std::move(I));
        }

        /* Template profile block (format §6).  pat_flags bit layout
         * is fixed; class/flag values resolve via the
         * mem_access_pattern / profile_flag maps. */
        if (have_profile) {
            TemplateProfileInfo &P = t.profile;
            P.exec_cp          = sub.uleb();
            P.exec_wp          = sub.uleb();
            /* Per-target taken/not-taken counts, 1:1 with the header
             * target list (count comes from there, not re-encoded). */
            P.targets.resize(t.target_pcs.size());
            for (auto &tc : P.targets) {
                tc.taken_cp    = sub.uleb();
                tc.nottaken_cp = sub.uleb();
                tc.taken_wp    = sub.uleb();
                tc.nottaken_wp = sub.uleb();
            }
            P.insns.resize(n_insns);
            for (uint64_t k = 0; k < n_insns; k++) {
                InsnProfileInfo &ip = P.insns[k];
                ip.memops_cp = sub.uleb();
                ip.memops_wp = sub.uleb();
                uint8_t pf   = sub.u8();
                ip.pat_cp  = (uint8_t)(pf & 0x3);
                ip.pat_wp  = (uint8_t)((pf >> 2) & 0x3);
                ip.addr_cp = (pf & 0x10) != 0;
                ip.addr_wp = (pf & 0x20) != 0;
                if (ip.memops_cp > 0) {
                    ip.has_cp_bounds = true;
                    ip.lo_cp = sub.uleb();
                    ip.hi_cp = ip.lo_cp + sub.uleb();
                }
                if (ip.memops_wp > 0) {
                    ip.has_wp_bounds = true;
                    ip.lo_wp = sub.uleb();
                    ip.hi_wp = ip.lo_wp + sub.uleb();
                }
            }
        }

        if (out_by_id) (*out_by_id)[t.template_id] = out->size();
        out->push_back(std::move(t));
    }
}

/* Reverse-resolve a well-known name in @m into @out; throws if
 * absent.  u8 overload for bit-mask maps, uint16_t for field_id
 * (ULEB space reaches ~330). */
static void resolve_one(const std::unordered_map<uint64_t, std::string> &m,
                        const char *map_name, const char *want,
                        uint8_t *out)
{
    for (const auto &kv : m) {
        if (kv.second == want) {
            *out = (uint8_t)kv.first;
            return;
        }
    }
    throw std::runtime_error(std::string("encoding map '") + map_name
                             + "' missing well-known name '" + want + "'");
}

/* Like resolve_one but tolerant: per the format spec (Step 3.3), no
 * field_id name is structurally required — a trace need only name the
 * fields it actually uses (e.g. a memdata-off trace omits LOAD_DATA /
 * STORE_DATA; a scalar trace omits the lane masks).  A name the trace
 * does not carry resolves to an out-of-range sentinel so the slot LUT
 * and per-fid lookups skip it (and it can never collide with a real fid
 * such as N_LOADS == 0).  If such a fid nonetheless appears in the body
 * it is an open-map violation caught at parse time, not here. */
static void resolve_optional(const std::unordered_map<uint64_t,
                                                      std::string> &m,
                             const char *want, uint16_t *out)
{
    for (const auto &kv : m) {
        if (kv.second == want) {
            *out = (uint16_t)kv.first;
            return;
        }
    }
    *out = 0xFFFFu;   /* absent: out-of-range sentinel */
}

/* Optional bit-mask resolution: a flag bit added after a trace was
 * written is simply absent from that trace's map, and resolves to 0 so
 * the bit never tests set.  (resolve_optional's 0xFFFF sentinel is for
 * field IDs, not u8 masks.) */
static void resolve_optional_mask(const std::unordered_map<uint64_t,
                                                           std::string> &m,
                                  const char *want, uint8_t *out)
{
    for (const auto &kv : m) {
        if (kv.second == want) {
            *out = (uint8_t)kv.first;
            return;
        }
    }
    *out = 0;
}

/* Populate @ids from the well-known names in @maps.  Throws on any
 * missing name — the wire format is the single source of truth, so a
 * trace that omits a name the decoder needs is malformed. */
static void resolve_ids(const EncodingMaps &maps, ResolvedIds *ids)
{
    /* body_tag */
    resolve_one(maps.body_tag, "body_tag", "BODY_TAG_END",
                &ids->body_tag_end);
    resolve_one(maps.body_tag, "body_tag", "BODY_TAG_ENTRY",
                &ids->body_tag_entry);
    resolve_one(maps.body_tag, "body_tag", "BODY_TAG_THREAD_SWITCH",
                &ids->body_tag_thread_switch);
    resolve_one(maps.body_tag, "body_tag", "BODY_TAG_IFRAME",
                &ids->body_tag_iframe);
    resolve_one(maps.body_tag, "body_tag", "BODY_TAG_REGFILE",
                &ids->body_tag_regfile);
    resolve_one(maps.body_tag, "body_tag", "BODY_TAG_ASID_SWITCH",
                &ids->body_tag_asid_switch);
    /* Disk-I/O tags are optional (absent in device-free traces and in
     * traces predating the feature); leave the 0xFF sentinel when a
     * name is not present so dispatch on them simply never fires. */
    for (const auto &kv : maps.body_tag) {
        if (kv.second == "BODY_TAG_DEVIO_START") {
            ids->body_tag_devio_start = (uint8_t)kv.first;
        } else if (kv.second == "BODY_TAG_DEVIO_STOP") {
            ids->body_tag_devio_stop = (uint8_t)kv.first;
        }
    }

    /* field_id (per-slot families + singletons): each looked up by
     * full CST_FID_<family><k> name, no stride/ordering assumption.
     * Per Step 3.3 NO field_id name is structurally required — a trace
     * names only the fields it uses — so every one resolves tolerantly
     * (absent -> sentinel).  CST_FID_EXTENDED is "required iff present";
     * its absence is likewise fine, and a stray EXTENDED record with no
     * name is caught at parse time. */
    resolve_optional(maps.field_id, "CST_FID_N_LOADS",   &ids->fid_n_loads);
    resolve_optional(maps.field_id, "CST_FID_N_STORES",  &ids->fid_n_stores);
    resolve_optional(maps.field_id, "CST_FID_METAFLAGS", &ids->fid_metaflags);
    static const struct { const char *prefix;
                          std::array<uint16_t, 64> ResolvedIds::*arr; } fam[] = {
        { "CST_FID_LOAD_ADDR",            &ResolvedIds::fid_load_addr            },
        { "CST_FID_STORE_ADDR",           &ResolvedIds::fid_store_addr           },
        { "CST_FID_LOAD_DATA",            &ResolvedIds::fid_load_data            },
        { "CST_FID_STORE_DATA",           &ResolvedIds::fid_store_data           },
        { "CST_FID_DST_REG",              &ResolvedIds::fid_dst_reg              },
        { "CST_FID_LOAD_SIZE",            &ResolvedIds::fid_load_size            },
        { "CST_FID_STORE_SIZE",           &ResolvedIds::fid_store_size           },
        { "CST_FID_DST_REG_WIDTH",        &ResolvedIds::fid_dst_reg_width        },
        { "CST_FID_SRC_LANE_MASK",        &ResolvedIds::fid_src_lane_mask        },
        { "CST_FID_DST_LANE_MASK",        &ResolvedIds::fid_dst_lane_mask        },
        { "CST_FID_LOAD_DATA_LANE_MASK",  &ResolvedIds::fid_load_data_lane_mask  },
        { "CST_FID_STORE_DATA_LANE_MASK", &ResolvedIds::fid_store_data_lane_mask },
        { "CST_FID_LOAD_PPAGE",           &ResolvedIds::fid_load_ppage           },
        { "CST_FID_STORE_PPAGE",          &ResolvedIds::fid_store_ppage          },
    };
    for (const auto &f : fam) {
        for (uint16_t k = 0; k < FID_SLOT_COUNT; k++) {
            std::string name = std::string(f.prefix) + std::to_string(k);
            resolve_optional(maps.field_id, name.c_str(), &(ids->*f.arr)[k]);
        }
    }
    resolve_optional(maps.field_id, "CST_FID_INSN_BYTES_LO",
                     &ids->fid_insn_bytes_lo);
    resolve_optional(maps.field_id, "CST_FID_INSN_BYTES_HI",
                     &ids->fid_insn_bytes_hi);
    resolve_optional(maps.field_id, "CST_FID_INSN_OPCODE",
                     &ids->fid_insn_opcode);
    resolve_optional(maps.field_id, "CST_FID_INSN_BRANCH_TYPE",
                     &ids->fid_insn_branch_type);
    resolve_optional(maps.field_id, "CST_FID_INSN_FLAGS",
                     &ids->fid_insn_flags);
    resolve_optional(maps.field_id, "CST_FID_INSN_IMMEDIATE",
                     &ids->fid_insn_immediate);
    resolve_optional(maps.field_id, "CST_FID_INSN_SIZE",
                     &ids->fid_insn_size);
    resolve_optional(maps.field_id, "CST_FID_EXTENDED",
                     &ids->fid_extended);

    /* insn_flag (bit masks) */
    resolve_one(maps.insn_flag, "insn_flag", "CST_INSN_FLAG_BRANCH_COND",
                &ids->insn_flag_branch_cond);
    resolve_one(maps.insn_flag, "insn_flag", "CST_INSN_FLAG_HAS_IMM",
                &ids->insn_flag_has_imm);
    resolve_one(maps.insn_flag, "insn_flag", "CST_INSN_FLAG_ATOMIC",
                &ids->insn_flag_atomic);
    resolve_one(maps.insn_flag, "insn_flag", "CST_INSN_FLAG_VEC",
                &ids->insn_flag_vec);
    resolve_one(maps.insn_flag, "insn_flag", "CST_INSN_FLAG_LANE_PARALLEL",
                &ids->insn_flag_lane_parallel);
    resolve_one(maps.insn_flag, "insn_flag", "CST_INSN_FLAG_HAS_DEP_BLOCK",
                &ids->insn_flag_has_dep_block);
    resolve_optional_mask(maps.insn_flag, "CST_INSN_FLAG_SYSTEM",
                          &ids->insn_flag_system);

    /* dep_block_flag (bit masks inside the optional dependency sub-block) */
    resolve_one(maps.dep_block_flag, "dep_block_flag",
                "CST_DEP_BLOCK_HAS_REG",  &ids->dep_block_has_reg);
    resolve_one(maps.dep_block_flag, "dep_block_flag",
                "CST_DEP_BLOCK_HAS_ADDR", &ids->dep_block_has_addr);

    /* header_flag (bit masks) */
    resolve_one(maps.header_flag, "header_flag", "CST_FLAG_MEM_DATA",
                &ids->flag_mem_data);
    resolve_one(maps.header_flag, "header_flag", "CST_FLAG_REG_DATA",
                &ids->flag_reg_data);
    resolve_one(maps.header_flag, "header_flag",
                "CST_FLAG_PROFILE",
                &ids->flag_profile);
    resolve_one(maps.header_flag, "header_flag", "CST_FLAG_WP",
                &ids->flag_wp);
    /* Optional: present only in system-mode traces with the fault trailer;
     * resolves to 0 (never tests set) when absent. */
    resolve_optional_mask(maps.header_flag, "CST_FLAG_FAULT",
                          &ids->flag_fault);
    /* Optional: present only in system-mode physaddr traces; resolves to 0
     * (never tests set) when absent. */
    resolve_optional_mask(maps.header_flag, "CST_FLAG_PHYSADDR",
                          &ids->flag_physaddr);

    /* wp_event_flag (bit masks) */
    resolve_one(maps.wp_event_flag, "wp_event_flag",
                "CST_WP_EVENT_TRANSLATION_UNAVAIL",
                &ids->wp_event_translation_unavail);
    resolve_one(maps.wp_event_flag, "wp_event_flag", "CST_WP_EVENT_FAULT",
                &ids->wp_event_fault);
    /* Optional: chain terminator introduced with the dep-branch-kill
     * wrong-path fault policy; resolves to 0 (never tests set) when the
     * writing tracer predates it. */
    resolve_optional_mask(maps.wp_event_flag, "CST_WP_EVENT_DEP_BRANCH_KILL",
                          &ids->wp_event_dep_branch_kill);

    /* metaflags (bit positions inside the FID_METAFLAGS byte) */
    resolve_one(maps.metaflags, "metaflags", "CST_METAFLAGS_Z",
                &ids->metaflags_z);
    resolve_one(maps.metaflags, "metaflags", "CST_METAFLAGS_N",
                &ids->metaflags_n);
    resolve_one(maps.metaflags, "metaflags", "CST_METAFLAGS_C",
                &ids->metaflags_c);
    resolve_one(maps.metaflags, "metaflags", "CST_METAFLAGS_V",
                &ids->metaflags_v);
    resolve_one(maps.metaflags, "metaflags", "CST_METAFLAGS_P",
                &ids->metaflags_p);
}

/* ===== POSIX-ustar reader ================================================
 *
 * Pure-memory scan of @data for tar members.  Accepts POSIX ustar
 * ("ustar\0"/"00"), GNU ("ustar "/" \0"), PAX 'x'/'g' extended
 * headers (payload skipped), and GNU base-256 sizes (>8 GiB), so a
 * .cst re-tarred by any standard tar still reads.  Long-filename
 * extensions ('L', PAX path=) unsupported — our names are short.
 */
struct UstarHeader {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char checksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char padding[12];
};
static_assert(sizeof(UstarHeader) == 512, "ustar header size");

uint64_t parse_octal(const char *field, size_t n)
{
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        char c = field[i];
        if (c == '\0' || c == ' ') break;
        if (c < '0' || c > '7') {
            throw std::runtime_error("tar: bad octal digit");
        }
        v = (v << 3) | (uint64_t)(c - '0');
    }
    return v;
}

/* Decode the @size field: standard octal, or GNU base-256 for large
 * members (high bit of byte 0 set; remaining 7 bits treated as
 * positive since sizes are unsigned). */
uint64_t parse_size_field(const char *field, size_t n)
{
    auto leading = (unsigned char)field[0];
    if (leading & 0x80) {
        uint64_t v = (uint64_t)(leading & 0x7F);
        for (size_t i = 1; i < n; i++) {
            v = (v << 8) | (uint64_t)(unsigned char)field[i];
        }
        return v;
    }
    return parse_octal(field, n);
}

/* Verify the ustar checksum: sum of all 512 bytes with the checksum
 * field counted as spaces.  Accept both unsigned and signed sums
 * (older tars wrote signed). */
bool verify_ustar_checksum(const UstarHeader *h)
{
    constexpr size_t checksum_off  = offsetof(UstarHeader, checksum);
    constexpr size_t checksum_size = sizeof(((UstarHeader *)0)->checksum);

    uint32_t unsigned_sum = 0;
    int32_t  signed_sum   = 0;
    const unsigned char *p = (const unsigned char *)h;
    for (size_t i = 0; i < sizeof(*h); i++) {
        unsigned char v =
            (i >= checksum_off && i < checksum_off + checksum_size)
                ? (unsigned char)' '
                : p[i];
        unsigned_sum += v;
        signed_sum   += (int32_t)(int8_t)v;
    }
    uint64_t want = parse_octal(h->checksum, checksum_size);
    return want == unsigned_sum || want == (uint32_t)signed_sum;
}

/* True if @h's magic field identifies it as ustar.  Accepts both the
 * POSIX form ("ustar\0", version "00") and the GNU form ("ustar ",
 * version " \0") by matching on the 5-byte "ustar" prefix only. */
bool ustar_magic_ok(const UstarHeader *h)
{
    return std::memcmp(h->magic, "ustar", 5) == 0;
}

struct TarMember {
    std::string name;
    const uint8_t *data;
    size_t size;
};

std::vector<TarMember> walk_tar(const uint8_t *data, size_t size)
{
    std::vector<TarMember> out;
    size_t off = 0;
    while (off + 512 <= size) {
        const UstarHeader *h = (const UstarHeader *)(data + off);

        /* Two consecutive zero blocks = end-of-archive. */
        bool all_zero = true;
        for (size_t i = 0; i < 512; i++) {
            if (((const uint8_t *)h)[i] != 0) { all_zero = false; break; }
        }
        if (all_zero) break;

        if (!ustar_magic_ok(h)) {
            throw std::runtime_error("tar: header missing 'ustar' magic");
        }
        if (!verify_ustar_checksum(h)) {
            throw std::runtime_error("tar: header checksum mismatch");
        }

        size_t name_len = strnlen(h->name, sizeof(h->name));
        if (name_len == 0) {
            throw std::runtime_error("tar: header with empty name");
        }
        uint64_t member_size = parse_size_field(h->size, sizeof(h->size));
        off += 512;
        if (off + member_size > size) {
            throw std::runtime_error("tar: member extends past EOF");
        }
        size_t padded = (member_size + 511) & ~(size_t)511;

        char tf = h->typeflag;
        if (tf == 'x' || tf == 'g') {
            /* PAX extended header ('x' per-file / 'g' global): skip
             * the payload so a `tar --format=pax` re-tar still
             * reads. */
            off += padded;
            continue;
        }
        if (tf == '\0' || tf == '0') {
            TarMember m;
            m.name = std::string(h->name, name_len);
            m.data = data + off;
            m.size = (size_t)member_size;
            out.push_back(std::move(m));
        }
        /* Other typeflags (symlinks, dirs, GNU 'L', ...) skipped. */
        off += padded;
    }
    return out;
}

std::string codec_from_suffix(const std::string &member_name)
{
    auto ends_with = [&](const char *suf) {
        size_t n = strlen(suf);
        return member_name.size() >= n &&
               member_name.compare(member_name.size() - n, n, suf) == 0;
    };
    if (ends_with(".zst")) return "zstd";
    if (ends_with(".xz"))  return "xz";
    if (ends_with(".gz"))  return "gzip";
    if (ends_with(".bz2")) return "bzip2";
    if (ends_with(".lz4")) return "lz4";
    return "";
}

/*
 * "-T<n>" flag for the xz decompressor.  CST_DECODE_THREADS overrides the
 * count (0 = one thread per core); unset uses a bounded auto of
 * min(online_cpus, 8) — most of the multi-block decode speedup without the
 * memory/thread blow-up of -T0 on a many-core host or when several tools
 * run at once.  Set CST_DECODE_THREADS=1 to force serial (lowest memory),
 * e.g. for a high-concurrency batch sweep.
 */
std::string decode_thread_flag()
{
    long n;
    const char *e = getenv("CST_DECODE_THREADS");
    if (e && *e) {
        n = strtol(e, nullptr, 10);
        if (n < 0) {
            n = 0;
        }
    } else {
        long cpus = sysconf(_SC_NPROCESSORS_ONLN);
        if (cpus < 1) {
            cpus = 1;
        }
        n = cpus < 8 ? cpus : 8;
    }
    return "-T" + std::to_string(n);
}

/* Source pulling bytes from a subprocess decompressor's stdout.
 * ctor forks the decompressor + a feeder child (writes compressed
 * bytes to its stdin); dtor closes stdout, SIGTERMs + reaps both
 * (handles --max early exit).
 *
 * The feeder is a separate process because a single-thread parent
 * doing write(in)+read(out) deadlocks the moment the decompressor's
 * stdin buffer fills before any output is produced. */
class ChildProcessSource : public Source {
public:
    ChildProcessSource(const std::string &codec,
                       const uint8_t *data, size_t size)
        : codec_(codec)
    {
        /*
         * xz can decode a multi-block stream in parallel, and the writer
         * compresses bodies with -T so they ARE multi-block; serial decode
         * is otherwise the dominant cost of every offline tool (lzma_decode
         * was ~45% of cst_audit cycles).  Pass -T so the decompressor uses
         * threads.  Compute the flag BEFORE fork() so the child does no
         * allocation between fork and exec.  zstd decode does not parallelize
         * this way, so it is left alone. */
        std::string xz_tflag;
        if (codec == "xz") {
            xz_tflag = decode_thread_flag();
        }

        int in_pipe[2], out_pipe[2];
        if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0) {
            throw std::runtime_error("decompress pipe(): "
                                     + std::string(strerror(errno)));
        }
        pid_ = fork();
        if (pid_ < 0) {
            throw std::runtime_error("decompress fork(): "
                                     + std::string(strerror(errno)));
        }
        if (pid_ == 0) {
            dup2(in_pipe[0], 0);
            dup2(out_pipe[1], 1);
            close(in_pipe[0]); close(in_pipe[1]);
            close(out_pipe[0]); close(out_pipe[1]);
            if (!xz_tflag.empty()) {
                execlp(codec.c_str(), codec.c_str(), "-d", "-c",
                       xz_tflag.c_str(), (char *)nullptr);
            } else {
                execlp(codec.c_str(), codec.c_str(), "-d", "-c",
                       (char *)nullptr);
            }
            _exit(127);
        }
        close(in_pipe[0]);
        close(out_pipe[1]);

        feeder_ = fork();
        if (feeder_ < 0) {
            close(in_pipe[1]);
            close(out_pipe[0]);
            kill(pid_, SIGTERM);
            waitpid(pid_, nullptr, 0);
            throw std::runtime_error("decompress feeder fork(): "
                                     + std::string(strerror(errno)));
        }
        if (feeder_ == 0) {
            close(out_pipe[0]);
            const uint8_t *p = data;
            size_t remaining = size;
            /* On --max early teardown the feeder may see EPIPE;
             * treat as a normal early exit. */
            signal(SIGPIPE, SIG_IGN);
            while (remaining > 0) {
                ssize_t n = write(in_pipe[1], p, remaining);
                if (n <= 0) break;
                p += n;
                remaining -= (size_t)n;
            }
            close(in_pipe[1]);
            _exit(0);
        }
        close(in_pipe[1]);
        out_fd_ = out_pipe[0];
    }

    ~ChildProcessSource() override
    {
        if (out_fd_ >= 0) {
            close(out_fd_);
        }
        /* Tear children down in case the consumer bailed early. */
        if (pid_ > 0) {
            kill(pid_, SIGTERM);
            waitpid(pid_, nullptr, 0);
        }
        if (feeder_ > 0) {
            kill(feeder_, SIGTERM);
            waitpid(feeder_, nullptr, 0);
        }
    }

    size_t read(uint8_t *out, size_t n) override
    {
        if (out_fd_ < 0) return 0;
        for (;;) {
            ssize_t r = ::read(out_fd_, out, n);
            if (r > 0) return (size_t)r;
            if (r == 0) return 0;
            if (errno == EINTR) continue;
            throw std::runtime_error("decompress (" + codec_ +
                                     ") read: " +
                                     std::string(strerror(errno)));
        }
    }

    /* Wait for the decompressor to finish and check its exit status.
     * Call only after the consumer has drained the stream to EOF. */
    void finalize() override
    {
        if (pid_ <= 0) return;
        int status = 0;
        waitpid(pid_, &status, 0);
        pid_ = 0;
        if (feeder_ > 0) {
            waitpid(feeder_, nullptr, 0);
            feeder_ = 0;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            throw std::runtime_error("decompress (" + codec_ +
                                     ") exited with non-zero status");
        }
    }

private:
    std::string codec_;
    pid_t pid_    = -1;
    pid_t feeder_ = -1;
    int   out_fd_ = -1;
};

/* Memory-backed Source: hands out bytes from a contiguous in-memory
 * buffer.  Used for body_stream_open's uncompressed-body path so
 * mem-backed and stream-backed bodies share the same Reader API. */
class MemorySource : public Source {
public:
    MemorySource(const uint8_t *data, size_t size)
        : data_(data), end_(size), pos_(0) {}
    size_t read(uint8_t *out, size_t n) override
    {
        size_t take = end_ - pos_;
        if (take > n) take = n;
        std::memcpy(out, data_ + pos_, take);
        pos_ += take;
        return take;
    }
private:
    const uint8_t *data_;
    size_t end_;
    size_t pos_;
};

/* Synchronous decompress into @out_buf.  Used for the small header
 * member so eager decompression avoids streaming bookkeeping. */
void decompress_to_buffer(const std::string &codec,
                          const uint8_t *data, size_t size,
                          std::vector<uint8_t> *out_buf)
{
    ChildProcessSource src(codec, data, size);
    uint8_t buf[64 * 1024];
    for (;;) {
        size_t n = src.read(buf, sizeof(buf));
        if (n == 0) break;
        out_buf->insert(out_buf->end(), buf, buf + n);
    }
    src.finalize();
}

}  /* namespace */

/* ===== CstFile loader ==================================================== */

CstFile::~CstFile()
{
    if (map_) {
        munmap((void *)map_, map_size_);
    }
}

CstFile::CstFile(CstFile &&o) noexcept
    : path_(std::move(o.path_)),
      map_(o.map_), map_size_(o.map_size_),
      header_buf_(std::move(o.header_buf_)),
      header_(o.header_),
      body_raw_(o.body_raw_),
      body_codec_(std::move(o.body_codec_))
{
    o.map_ = nullptr;
    o.map_size_ = 0;
    o.header_ = {};
    o.body_raw_ = {};
}

CstFile &CstFile::operator=(CstFile &&o) noexcept
{
    if (this != &o) {
        if (map_) munmap((void *)map_, map_size_);
        path_ = std::move(o.path_);
        map_ = o.map_;
        map_size_ = o.map_size_;
        header_buf_ = std::move(o.header_buf_);
        header_ = o.header_;
        body_raw_ = o.body_raw_;
        body_codec_ = std::move(o.body_codec_);
        o.map_ = nullptr;
        o.map_size_ = 0;
        o.body_raw_ = {};
    }
    return *this;
}

std::unique_ptr<CstFile> cst_file_open(const std::string &path)
{
    std::unique_ptr<CstFile> cf(new CstFile());
    cf->path_ = path;

    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        throw std::runtime_error("open(" + path + "): " + strerror(errno));
    }
    struct stat st{};
    if (fstat(fd, &st) != 0) {
        ::close(fd);
        throw std::runtime_error("fstat: " + std::string(strerror(errno)));
    }
    void *map = mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    ::close(fd);
    if (map == MAP_FAILED) {
        throw std::runtime_error("mmap: " + std::string(strerror(errno)));
    }
    cf->map_ = (const uint8_t *)map;
    cf->map_size_ = (size_t)st.st_size;

    auto members = walk_tar(cf->map_, cf->map_size_);
    const TarMember *body_m = nullptr;
    const TarMember *header_m = nullptr;
    for (const auto &m : members) {
        /* Strip optional path prefix (rare; we never write one). */
        size_t slash = m.name.find_last_of('/');
        std::string base = (slash == std::string::npos)
            ? m.name : m.name.substr(slash + 1);
        if (base.compare(0, 9, "body.cst") == 0 ||
            base.compare(0, 8, "body.cst") == 0) {
            if (base == "body.cst" ||
                base.compare(0, 9, "body.cst.") == 0) {
                body_m = &m;
                continue;
            }
        }
        if (base == "header.cst" ||
            base.compare(0, 11, "header.cst.") == 0) {
            header_m = &m;
        }
    }
    if (!body_m || !header_m) {
        throw std::runtime_error("missing required tar member(s): " + path);
    }

    /* Header: eagerly decompress (small).  Body: keep the raw byte
     * range + codec; body_stream_open will spawn the decompressor
     * lazily so consumers like --templates-only never pay the cost. */
    std::string header_codec = codec_from_suffix(header_m->name);
    if (header_codec.empty()) {
        cf->header_.data = header_m->data;
        cf->header_.size = header_m->size;
    } else {
        decompress_to_buffer(header_codec, header_m->data, header_m->size,
                             &cf->header_buf_);
        cf->header_.data = cf->header_buf_.data();
        cf->header_.size = cf->header_buf_.size();
    }

    cf->body_raw_.data = body_m->data;
    cf->body_raw_.size = body_m->size;
    cf->body_codec_    = codec_from_suffix(body_m->name);
    return cf;
}

/* ===== Body streaming reader ============================================ */

BodyStream::BodyStream(BodyStream &&) noexcept = default;
BodyStream &BodyStream::operator=(BodyStream &&) noexcept = default;
BodyStream::~BodyStream() = default;

std::unique_ptr<BodyStream> body_stream_open(const CstFile &cf)
{
    auto bs = std::unique_ptr<BodyStream>(new BodyStream());
    MemberView raw = cf.body_raw();
    if (raw.size < 8) {
        throw std::runtime_error("body member too small");
    }
    std::unique_ptr<Source> src;
    if (cf.body_codec().empty()) {
        src = std::make_unique<MemorySource>(raw.data, raw.size);
    } else {
        src = std::make_unique<ChildProcessSource>(
            cf.body_codec(), raw.data, raw.size);
    }
    /* Reader owns `src` for normal pulls; finalize() routes through
     * it to wait+check the ChildProcessSource. */
    Reader reader(std::move(src));

    /* Verify leading magic and strip it from the consumer-visible
     * record stream. */
    uint32_t lead = reader.u32_le();
    if (lead != CST_MAGIC) {
        throw std::runtime_error("body member: bad leading magic");
    }
    bs->reader_ = std::move(reader);
    return bs;
}

void BodyStream::finalize()
{
    /* The walker has consumed BODY_TAG_END + num_entries; the only
     * remaining bytes should be the trailing CST_MAGIC. */
    uint32_t trail = reader_.u32_le();
    if (trail != CST_MAGIC) {
        throw std::runtime_error("body member truncated "
                                 "(bad trailing magic)");
    }
    /* Drain any trailing padding (defensive; normally none). */
    uint8_t scratch[64];
    while (!reader_.eof()) {
        size_t take = reader_.remaining();
        if (take == 0) break;
        if (take > sizeof(scratch)) take = sizeof(scratch);
        reader_.raw(scratch, take);
    }
    /* If the body was streamed through a subprocess decompressor,
     * wait for it and re-throw on non-zero exit. */
    reader_.finalize_source();
}

/* ===== Header + templates ================================================ */

Header parse_header(MemberView view,
                    std::vector<Template> *out_templates,
                    std::unordered_map<uint32_t, size_t> *out_by_id)
{
    if (view.size < 8) {
        throw std::runtime_error("header member too small");
    }
    Header h;
    Reader r(view.data, 0, view.size);
    h.magic = r.u32_le();
    if (h.magic != CST_MAGIC) {
        throw std::runtime_error("Bad header magic");
    }
    h.format_version = (uint8_t)((h.magic >> 24) & 0xFF);
    h.isa            = r.u8();
    h.flags          = r.u8();
    h.start_insn         = r.uleb();
    h.warmup_insns       = r.uleb();
    h.total_target_insns = r.uleb();
    {
        uint64_t bits = r.u64_le();
        std::memcpy(&h.weight, &bits, sizeof(h.weight));
    }
    h.command     = r.string();
    h.datetime    = r.string();
    h.comment     = r.string();
    h.target_name = r.string();

    /* Length-prefixed encoding-maps section. */
    Reader maps_sub = r.sub();
    parse_encoding_maps(maps_sub, &h.maps);
    if (!maps_sub.eof()) {
        throw std::runtime_error("encoding-map section has trailing bytes");
    }

    /* §2.13: in-trace architectural CP-insn count at the
     * warmup→simulation boundary.  Lets consumers skip warmup
     * without re-counting BBV-vs-architectural insns under REP
     * fan-out.  See champsim_tracer_format.md. */
    h.warmup_end_arch_insns = r.uleb();

    /* Reverse-resolve every well-known name in the encoding maps to
     * its wire-format ID.  Tools dispatch off @h.ids from here on. */
    resolve_ids(h.maps, &h.ids);

    /* Templates section consumes the remainder of the header
     * member.  No length prefix on the section itself — it ends at
     * end-of-buffer. */
    if (!r.eof() && out_templates) {
        parse_templates_at(r, h.ids, h.flags, out_templates, out_by_id);
    }
    if (!r.eof()) {
        throw std::runtime_error("header member has trailing bytes after templates");
    }
    return h;
}

MemberView body_records_view(MemberView body_member)
{
    if (body_member.size < 8) {
        throw std::runtime_error("body member too small");
    }
    Reader r(body_member.data, 0, body_member.size);
    uint32_t lead = r.u32_le();
    if (lead != CST_MAGIC) {
        throw std::runtime_error("Bad body leading magic");
    }
    /* Trailing-magic check: last 4 bytes must be CST_MAGIC. */
    if (body_member.size < 8) {
        throw std::runtime_error("body member truncated (no trailing magic)");
    }
    const uint8_t *tail = body_member.data + body_member.size - 4;
    uint32_t trail = (uint32_t)tail[0]
                   | ((uint32_t)tail[1] << 8)
                   | ((uint32_t)tail[2] << 16)
                   | ((uint32_t)tail[3] << 24);
    if (trail != CST_MAGIC) {
        throw std::runtime_error("body member truncated (bad trailing magic)");
    }
    MemberView records;
    records.data = body_member.data + 4;
    records.size = body_member.size - 4 - 4;  /* strip leading + trailing magic */
    return records;
}

/* ===== Name lookups ====================================================== */

static std::string lookup_or(const std::unordered_map<uint64_t, std::string> &m,
                             uint64_t id, const std::string &fallback)
{
    auto it = m.find(id);
    return it == m.end() ? fallback : it->second;
}

std::string opcode_name(const Header &h, uint64_t id)
{
    return lookup_or(h.maps.opcode, id, "OP_" + std::to_string(id));
}
std::string branch_type_name(const Header &h, uint64_t id)
{
    return lookup_or(h.maps.branch_type, id, "BR_" + std::to_string(id));
}
std::string reg_name_or_unknown(const Header &h, uint64_t id)
{
    auto it = h.maps.reg.find(id);
    if (it != h.maps.reg.end()) return it->second;
    return std::string("UNKNOWN_") + std::to_string(id);
}
std::string field_id_name(const Header &h, uint64_t id)
{
    auto it = h.maps.field_id.find(id);
    if (it != h.maps.field_id.end()) return it->second;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "FID_0x%02x", (unsigned)id);
    return buf;
}

}  /* namespace cst */
