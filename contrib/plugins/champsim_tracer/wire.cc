/*
 * ChampSim Tracer - wire encoding of the .cst members.
 *
 * Copyright (C) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "wire.h"

#include <algorithm>
#include <cstring>
#include <initializer_list>
#include <map>
#include <utility>

namespace cst {

void Bytes::u32(uint32_t v)
{
    for (int i = 0; i < 4; i++) {
        u8(uint8_t(v >> (8 * i)));
    }
}

void Bytes::u64(uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        u8(uint8_t(v >> (8 * i)));
    }
}

void Bytes::f64(double v)
{
    uint64_t bits;
    static_assert(sizeof(bits) == sizeof(v), "binary64 is eight bytes");
    std::memcpy(&bits, &v, sizeof(bits));
    u64(bits);
}

void Bytes::uleb(uint64_t v)
{
    do {
        uint8_t b = v & 0x7f;
        v >>= 7;
        u8(v ? (b | 0x80) : b);
    } while (v);
}

void Bytes::sleb(int64_t v)
{
    for (;;) {
        uint8_t b = v & 0x7f;
        v >>= 7;    /* arithmetic: sign-propagating */
        bool done = (v == 0 && !(b & 0x40)) || (v == -1 && (b & 0x40));
        u8(done ? b : (b | 0x80));
        if (done) {
            return;
        }
    }
}

void Bytes::sleb_wide(const uint64_t limb[3])
{
    uint64_t v[3] = { limb[0], limb[1], limb[2] };
    for (;;) {
        uint8_t b = v[0] & 0x7f;
        v[0] = (v[0] >> 7) | (v[1] << 57);
        v[1] = (v[1] >> 7) | (v[2] << 57);
        v[2] = uint64_t(int64_t(v[2]) >> 7);    /* sign-propagating */
        bool zero = !(v[0] | v[1] | v[2]), ones = !~(v[0] & v[1] & v[2]);
        bool done = (zero && !(b & 0x40)) || (ones && (b & 0x40));
        u8(done ? b : (b | 0x80));
        if (done) {
            return;
        }
    }
}

void Bytes::str(const std::string &s)
{
    uleb(s.size());
    buf_.insert(buf_.end(), s.begin(), s.end());
}

void Bytes::section(const Bytes &payload)
{
    uleb(payload.buf_.size());
    buf_.insert(buf_.end(), payload.buf_.begin(), payload.buf_.end());
}

int isa_for_target(const std::string &target_name)
{
    /* TraceISA; the four ISAs the purpose statement names. */
    static const std::pair<const char *, int> table[] = {
        { "x86_64", 1 }, { "aarch64", 2 }, { "riscv64", 3 }, { "mipsel", 4 },
    };
    for (const auto &e : table) {
        if (target_name == e.first) {
            return e.second;
        }
    }
    return -1;
}

namespace {

/*
 * Body-tag values: the ones section 2 says the writer assigns.  The
 * decoder resolves them through the body_tag map, never by number.
 */
enum : uint8_t {
    kTagEnd = 0, kTagEntry = 1, kTagThread = 2, kTagIframe = 3,
    kTagRegfile = 4, kTagAsid = 5,
};

constexpr uint8_t kUnclassified = 0;    /* opcode and branch_type value */
constexpr uint8_t kFlagMemData = 1;     /* header_flag CST_FLAG_MEM_DATA */
constexpr size_t kSlotCount = 512;      /* CST_FID_SLOT_COUNT, section 2 */

/*
 * Field ids: the block-level five take 0..4 (encoding_maps()), the two
 * counts 5 and 6, then slot k of the six memop families 7 + 6k + family,
 * interleaved by slot as section 5.1's layout intent describes.
 */
enum : uint32_t { kFidNLoads = 5, kFidNStores = 6, kFidSlot0 = 7 };
const char *const kSlotFamilies[] = {
    "CST_FID_LOAD_ADDR", "CST_FID_STORE_ADDR", "CST_FID_LOAD_DATA",
    "CST_FID_STORE_DATA", "CST_FID_LOAD_SIZE", "CST_FID_STORE_SIZE",
};
uint32_t slot_fid(size_t k, bool store, int family)     /* 0 addr 1 data 2 size */
{
    return kFidSlot0 + 6 * uint32_t(k) + 2 * family + store;
}

using MapEntries = std::vector<std::pair<uint64_t, std::string>>;

/* Enumerated names take 0, 1, 2 ...; flag names take bits 0, 1, 2 ... */
MapEntries numbered(std::initializer_list<const char *> names, bool bits,
                    unsigned skip_bit = 64)
{
    MapEntries out;
    unsigned i = 0;
    for (const char *n : names) {
        i += (bits && i == skip_bit) ? 1 : 0;
        out.push_back({ bits ? uint64_t(1) << i : i, n });
        i++;
    }
    return out;
}

/*
 * The encoding maps (Step 3).  The contract requires the Step 3.3(a)
 * names plus a name for every value the trace uses; the maps are open.
 * The canonical decoder and auditor additionally demand the rest of the
 * section-2 flag vocabularies, the other block-level field-ids of 5.7
 * and the IFRAME / REGFILE tags, so those names are carried too.  A name
 * is vocabulary, not a claim: of the flags only MEM_DATA is set, and the
 * memop field-ids are named for exactly the @slots the body addresses.
 * Values are this writer's choice, except the body tags, which are the
 * ones section 2 says the writer assigns.
 */
Bytes encoding_maps(size_t slots)
{
    MapEntries fids = numbered({ "CST_FID_BB_START", "CST_FID_BB_STOP",
                                 "CST_FID_BB_FLAGS", "CST_FID_BB_FAULT_DEPTH",
                                 "CST_FID_BB_FAULT_INSN" }, false);
    fids.push_back({ kFidNLoads, "CST_FID_N_LOADS" });
    fids.push_back({ kFidNStores, "CST_FID_N_STORES" });
    for (size_t k = 0; k < slots; k++) {
        for (int f = 0; f < 6; f++) {
            fids.push_back({ slot_fid(k, f & 1, f / 2),
                             kSlotFamilies[f] + std::to_string(k) });
        }
    }
    const std::pair<const char *, MapEntries> maps[] = {
        { "body_tag", { { kTagEnd, "BODY_TAG_END" },
                        { kTagEntry, "BODY_TAG_ENTRY" },
                        { kTagThread, "BODY_TAG_THREAD_SWITCH" },
                        { kTagIframe, "BODY_TAG_IFRAME" },
                        { kTagRegfile, "BODY_TAG_REGFILE" },
                        { kTagAsid, "BODY_TAG_ASID_SWITCH" } } },
        { "header_flag", numbered({ "CST_FLAG_MEM_DATA", "CST_FLAG_REG_DATA",
                                    "CST_FLAG_PROFILE", "CST_FLAG_WP" },
                                  true) },
        /* Bit 3 stays unassigned: section 2 reserves it. */
        { "insn_flag", numbered({ "CST_INSN_FLAG_BRANCH_COND",
                                  "CST_INSN_FLAG_HAS_IMM",
                                  "CST_INSN_FLAG_ATOMIC",
                                  "CST_INSN_FLAG_VEC",
                                  "CST_INSN_FLAG_LANE_PARALLEL",
                                  "CST_INSN_FLAG_HAS_DEP_BLOCK" },
                                true, 3) },
        { "dep_block_flag", numbered({ "CST_DEP_BLOCK_HAS_REG",
                                       "CST_DEP_BLOCK_HAS_ADDR" }, true) },
        { "bb_flag", numbered({ "CST_BB_FLAG_SYNTHETIC_FAULT",
                                "CST_BB_FLAG_TRANSLATION_UNAVAIL",
                                "CST_BB_FLAG_WP_FIRST_TARGET_UNAVAIL",
                                "CST_BB_FLAG_THREAD_END",
                                "CST_BB_FLAG_BRANCH_UNRESOLVED" }, true) },
        { "metaflags", numbered({ "CST_METAFLAGS_Z", "CST_METAFLAGS_N",
                                  "CST_METAFLAGS_C", "CST_METAFLAGS_V",
                                  "CST_METAFLAGS_P" }, true) },
        { "field_id", fids },
        /*
         * Every template instruction carries these two values: this
         * writer classifies nothing yet, and says so by name.
         */
        { "opcode", { { kUnclassified, "GEN_OP_UNKNOWN" } } },
        { "branch_type", { { kUnclassified, "BRANCH_UNCLASSIFIED" } } },
    };
    Bytes b;
    b.uleb(sizeof(maps) / sizeof(maps[0]));
    for (const auto &m : maps) {
        b.str(m.first);
        b.uleb(m.second.size());
        for (const auto &e : m.second) {
            b.uleb(e.first);
            b.str(e.second);
        }
    }
    return b;
}

/* One template payload (section 6); its id is its index. */
Bytes template_payload(uint64_t id, const WireTemplate &t)
{
    Bytes b;
    const WireInsn &last = t.insns.back();
    b.uleb(id);
    b.uleb(t.insns.front().pc);
    b.uleb(t.insns.size());
    b.uleb(t.terminated ? last.pc + last.size : 0);     /* fall_through_pc */
    b.uleb(0);          /* n_targets: branch-target history absent */
    b.str("");          /* symbol_name */
    uint64_t prev = t.insns.front().pc;
    for (const WireInsn &i : t.insns) {
        b.uleb(i.pc - prev);
        prev = i.pc;
        b.u8(kUnclassified);    /* opcode */
        b.u8(kUnclassified);    /* branch_type */
        /* flags, n_src, n_dst, max_dep_loads, max_dep_stores: unclaimed */
        for (int k = 0; k < 5; k++) {
            b.u8(0);
        }
        b.u8(i.size);
        for (unsigned k = 0; k < i.size; k++) {
            b.u8(i.bytes[k]);
        }
    }
    return b;
}

/* One field-delta record (section 5): its field id and SLEB_WIDE delta. */
struct Record { uint32_t fid; uint64_t delta[3]; };

/* A record for @fid when (lo, hi) differs from its state (plo, phi). */
void change(std::vector<Record> &r, uint32_t fid, uint64_t &plo, uint64_t &phi,
            uint64_t lo, uint64_t hi)
{
    if (lo == plo && hi == phi) {
        return;
    }
    Record x{ fid, {} };
    uint64_t borrow = lo < plo, t = hi - phi;
    x.delta[0] = lo - plo;
    x.delta[1] = t - borrow;
    x.delta[2] = -uint64_t(hi < phi || t < borrow);
    r.push_back(x);
    plo = lo;
    phi = hi;
}

/* The field state of one (template, ipos): baseline 0 everywhere. */
struct InsnState {
    struct Slot { uint64_t addr, lo, hi, size; };
    uint64_t count[2] = { 0, 0 };
    std::vector<Slot> slot[2];

    /* Loads (@d 0) or stores (1) of one execution; returns their number. */
    size_t observe(const std::vector<const Memop *> &ms, int d,
                   std::vector<Record> &r)
    {
        size_t c = std::min(ms.size(), kSlotCount), k;
        uint64_t z = 0;
        change(r, d ? kFidNStores : kFidNLoads, count[d], z, c, 0);
        slot[d].resize(std::max(slot[d].size(), c));
        for (k = 0; k < c; k++) {
            const Memop &m = *ms[k];
            Slot &s = slot[d][k];
            change(r, slot_fid(k, d, 0), s.addr, z, m.addr, 0);
            if (m.data_ok) {
                change(r, slot_fid(k, d, 1), s.lo, s.hi, m.lo, m.hi);
            }
            change(r, slot_fid(k, d, 2), s.size, z, m.size, 0);
        }
        return ms.size();
    }
};

} /* namespace */

Bytes header_member(const HeaderFacts &facts,
                    const std::vector<WireTemplate> &templates, size_t slots)
{
    Bytes h;
    h.u32(kMagic);
    h.u8(facts.isa);
    h.u8(kFlagMemData); /* flags: memop values are the one optional content */
    h.uleb(0);          /* start_insn: no window, the timeline starts at 0 */
    h.uleb(0);          /* warmup_insns: none configured */
    h.uleb(0);          /* total_target_insns: 0 = unbounded */
    h.f64(0.0);         /* simpoint_weight: not a simpoint segment */
    h.str(facts.command);
    h.str(facts.datetime);
    h.str(facts.comment);
    h.str(facts.target_name);
    h.section(encoding_maps(std::min(slots, kSlotCount)));
    h.uleb(0);          /* warmup_end_trace_insn_idx: no warmup, ends at 0 */
    h.uleb(templates.size());   /* templates section, to member EOF */
    for (size_t id = 0; id < templates.size(); id++) {
        h.section(template_payload(id, templates[id]));
    }
    return h;
}

Bytes body_member(uint64_t root_phys, const std::vector<WireTemplate> &templates,
                  const std::vector<WireEntry> &entries,
                  const std::vector<Memop> &memops, size_t &slots)
{
    Bytes b;
    b.u32(kMagic);
    b.u8(kTagAsid);     /* opening context, section 4: asid index 0 ... */
    b.sleb(0);
    b.u64(root_phys);   /* ... whose first sighting carries its label */
    b.u64(0);           /* sig: reserved, always 0 */
    b.u8(kTagThread);   /* ... then thread 0 */
    b.sleb(0);
    /* Field state is per thread (Step 6: overlays key on the thread id). */
    std::map<uint32_t, std::vector<std::vector<InsnState>>> state;
    slots = 0;
    int64_t tid = 0, tmpl = 0;
    for (const WireEntry &e : entries) {
        if (e.tid != tid) {
            b.u8(kTagThread);
            b.sleb(int64_t(e.tid) - tid);
            tid = e.tid;
        }
        b.u8(kTagEntry);
        b.sleb(int64_t(e.template_id) - tmpl);
        tmpl = e.template_id;
        /* cp_delta_section: memop records; the range defaults to the block */
        auto &per = state[e.tid];
        per.resize(templates.size());
        std::vector<InsnState> &st = per[e.template_id];
        st.resize(templates[e.template_id].insns.size());
        Bytes recs;
        uint64_t n = 0, last = 0;
        size_t m = e.begin;
        for (uint32_t ipos = 0; ipos < st.size(); ipos++) {
            std::vector<Record> r;
            std::vector<const Memop *> dir[2];
            for (; m < e.end && memops[m].pos - e.base == ipos; m++) {
                dir[memops[m].store].push_back(&memops[m]);
            }
            for (int d = 0; d < 2; d++) {
                slots = std::max(slots, st[ipos].observe(dir[d], d, r));
            }
            std::sort(r.begin(), r.end(), [](const Record &x, const Record &y) {
                return x.fid < y.fid;
            });
            for (const Record &x : r) {
                recs.uleb(ipos - last);
                last = ipos;
                recs.uleb(x.fid);
                recs.sleb_wide(x.delta);
                n++;
            }
        }
        Bytes sec;
        sec.uleb(n);
        sec.raw(recs);
        b.section(sec);
    }
    b.u8(kTagEnd);
    b.uleb(entries.size());
    b.u32(kMagic);
    return b;
}

} /* namespace cst */
