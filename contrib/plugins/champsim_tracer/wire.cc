/*
 * ChampSim Tracer - wire encoding of the .cst members.
 *
 * Copyright (C) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "wire.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <initializer_list>
#include <unordered_map>
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

void Bytes::sleb_wide(const uint64_t *limb, int n)
{
    uint64_t v[9] = {}; /* n <= 9 */
    std::copy(limb, limb + n, v);
    for (;;) {
        uint8_t b = v[0] & 0x7f;
        bool zero = true, ones = true;
        for (int k = 0; k < n; k++) {
            v[k] = k + 1 < n ? (v[k] >> 7) | (v[k + 1] << 57) :
                   uint64_t(int64_t(v[k]) >> 7);    /* sign-propagating */
            zero = zero && !v[k];
            ones = ones && !~v[k];
        }
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
constexpr uint8_t kFlagRegData = 2;     /* header_flag CST_FLAG_REG_DATA */
constexpr uint8_t kFlagWp = 8;          /* header_flag CST_FLAG_WP */
constexpr size_t kSlotCount = 512;      /* CST_FID_SLOT_COUNT, section 2 */

/*
 * Field ids: the block-level five take 0..4 (encoding_maps()), the two
 * counts 5 and 6, then slot k of the six memop families 7 + 6k + family,
 * interleaved by slot as section 5.1's layout intent describes.
 */
enum : uint32_t {
    kFidStop = 1, kFidFlags = 2, kFidFaultInsn = 4,
    kFidNLoads = 5, kFidNStores = 6, kFidSlot0 = 7,
    /* after every memop slot: METAFLAGS, then DST_REG{k}, DST_REG_WIDTH{k} */
    kFidMeta = kFidSlot0 + 6 * 512, kFidReg0,
};
const char *const kSlotFamilies[] = {
    "CST_FID_LOAD_ADDR", "CST_FID_STORE_ADDR", "CST_FID_LOAD_DATA",
    "CST_FID_STORE_DATA", "CST_FID_LOAD_SIZE", "CST_FID_STORE_SIZE",
};
uint32_t slot_fid(size_t k, bool store, int family)     /* 0 addr 1 data 2 size */
{
    return kFidSlot0 + 6 * uint32_t(k) + 2 * family + store;
}
uint32_t reg_fid(size_t k, bool width) { return kFidReg0 + 2 * uint32_t(k) + width; }

/* The name section 5.4 gives GenericRegId @id */
std::string reg_name(unsigned id)
{
    static const char *const one[] = {
        "CTRL", "DEBUG", "BOUND0", "BOUND1", "BOUND2", "BOUND3", "ACC0", "ACC1",
        "ACC2", "ACC3", "ZERO", "MATRIX", "SYS", "FCSR", "VCTRL", "TLS",
        "VSTART", "DSPCTRL", "VCSR", "SP", "FLAGS", "IP", "LR", "FP_REG",
    };
    static const std::pair<unsigned, const char *> bank[] = {
        { kRegGpr, "GPR" }, { kRegAccHi, "ACCHI" }, { kRegFpr, "FPR" },
        { kRegVec, "VEC" }, { kRegPred, "PRED" }, { kRegSeg, "SEG" },
    };
    if (id >= kRegCtrl) {
        return std::string("REG_") + one[id - kRegCtrl];
    }
    for (int b = 5; b >= 0; b--) {
        if (id >= bank[b].first) {
            return std::string("REG_") + bank[b].second +
                   std::to_string(id - bank[b].first);
        }
    }
    return "REG_NONE";
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
 * is vocabulary, not a claim: of the flags only MEM_DATA, REG_DATA and WP
 * are set, the memop field-ids are named for exactly the @slots the body
 * addresses, the register ones for the widest destination list, and the
 * reg map for every register a template names.
 * Values are this writer's choice, except the body tags, which are the
 * ones section 2 says the writer assigns.
 */
Bytes encoding_maps(size_t slots, const std::vector<WireTemplate> &templates,
                    bool regdata)
{
    std::map<unsigned, bool> regs;   /* every id the templates use */
    size_t ndst = 0;
    for (const WireTemplate &t : templates) {
        for (const WireInsn &i : t.insns) {
            for (const auto *l : { &i.regs->src, &i.regs->dst }) {
                for (uint8_t r : *l) {
                    regs[r] = true;
                }
            }
            ndst = std::max(ndst, i.regs->dst.size());
        }
    }
    MapEntries names;
    for (const auto &r : regs) {
        names.push_back({ r.first, reg_name(r.first) });
    }
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
    if (regdata) {
        fids.push_back({ kFidMeta, "CST_FID_METAFLAGS" });
        for (size_t k = 0; k < ndst; k++) {
            fids.push_back({ reg_fid(k, false), "CST_FID_DST_REG" + std::to_string(k) });
            fids.push_back({ reg_fid(k, true),
                             "CST_FID_DST_REG_WIDTH" + std::to_string(k) });
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
        { "reg", names },
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
        b.u8(0);                /* flags: unclaimed */
        b.u8(uint8_t(i.regs->src.size()));
        b.u8(uint8_t(i.regs->dst.size()));
        for (const auto *l : { &i.regs->src, &i.regs->dst }) {
            for (uint8_t r : *l) {
                b.u8(r);
            }
        }
        b.u8(i.dep_mask_len[0]);    /* max_dep_loads */
        b.u8(i.dep_mask_len[1]);    /* max_dep_stores */
        b.u8(i.size);
        for (unsigned k = 0; k < i.size; k++) {
            b.u8(i.bytes[k]);
        }
    }
    return b;
}

/*
 * One overlay of field state (section 5): (thread, template, ipos, fid) ->
 * value.  Per thread, as the decoder keys it (Step 6: overlays key on the
 * thread id).
 */
struct Cell {
    uint32_t tid, tmpl, ipos, fid;
    bool operator==(const Cell &o) const
    {
        return tid == o.tid && tmpl == o.tmpl && ipos == o.ipos && fid == o.fid;
    }
};
struct CellHash {
    size_t operator()(const Cell &c) const
    {
        return std::hash<uint64_t>()((uint64_t(c.tid) << 44) ^ (uint64_t(c.tmpl) << 24) ^
                                     (uint64_t(c.ipos) << 12) ^ c.fid);
    }
};
using Value = std::array<uint64_t, 8>;     /* 512 bits, little-endian limbs */
using Overlay = std::unordered_map<Cell, Value, CellHash>;

/*
 * One delta section: records against @own, resolving a cell @own lacks
 * through @fallback (the CP overlay, for a WP section), then the default.
 */
class Section {
public:
    Section(Overlay &own, const Overlay *fallback, uint32_t tid, uint32_t tmpl)
        : own_(own), fb_(fallback), tid_(tid), tmpl_(tmpl) {}

    void put(uint32_t ipos, uint32_t fid, uint64_t lo, uint64_t hi = 0,
             uint64_t def = 0)
    {
        put(ipos, fid, Value{ lo, hi }, Value{ def });
    }

    void put(uint32_t ipos, uint32_t fid, const Value &v, const Value &def)
    {
        Cell c{ tid_, tmpl_, ipos, fid };
        Value p = def;
        auto it = own_.find(c);
        if (it != own_.end()) {
            p = it->second;
        } else if (fb_) {
            auto f = fb_->find(c);
            p = f != fb_->end() ? f->second : p;
        }
        if (v == p) {
            return;
        }
        Record x{ ipos, fid, {} };  /* two's-complement difference, sign limb */
        uint64_t borrow = 0;
        for (int k = 0; k < 8; k++) {
            uint64_t t = v[k] - p[k];
            x.delta[k] = t - borrow;
            borrow = v[k] < p[k] || t < borrow;
        }
        x.delta[8] = -borrow;
        recs_.push_back(x);
        own_[c] = v;
    }

    Bytes bytes()
    {
        std::sort(recs_.begin(), recs_.end(), [](const Record &x, const Record &y) {
            return x.ipos != y.ipos ? x.ipos < y.ipos : x.fid < y.fid;
        });
        Bytes b;
        b.uleb(recs_.size());
        uint32_t last = 0;
        for (const Record &x : recs_) {
            b.uleb(x.ipos - last);
            last = x.ipos;
            b.uleb(x.fid);
            b.sleb_wide(x.delta, 9);
        }
        return b;
    }

private:
    struct Record { uint32_t ipos, fid; uint64_t delta[9]; };
    Overlay &own_;
    const Overlay *fb_;
    uint32_t tid_, tmpl_;
    std::vector<Record> recs_;
};

/*
 * Destination register @x.reg - 1's value and width (section 5.4), and for
 * the integer flags register of x86 / AArch64 the canonical METAFLAGS byte
 * (section 2): Z N C V P, from EFLAGS ZF SF CF OF PF / NZCV.
 */
void put_reg(Section &sec, uint32_t ipos, const Memop &x, uint8_t id,
             const std::vector<uint8_t> &arena, int isa)
{
    static const int bit[2][5] = { { 6, 7, 0, 11, 2 }, { 30, 31, 29, 28, -1 } };
    Value v{ x.lo, x.hi };
    if (x.size > 16) {
        std::memcpy(&v[2], &arena[x.addr], x.size - 16);
    }
    sec.put(ipos, reg_fid(x.reg - 1, false), v, Value{});
    sec.put(ipos, reg_fid(x.reg - 1, true), x.size);
    if (id == kRegFlags && (isa == 1 || isa == 2)) {
        uint64_t mf = 0;
        for (int f = 0; f < 5; f++) {
            int b = bit[isa - 1][f];
            mf |= b >= 0 && (x.lo >> b & 1) ? 1u << f : 0;
        }
        sec.put(ipos, kFidMeta, mf);
    }
}

/*
 * The delta section of entry or chain block @e: its memops and register
 * values over the range it ran, then its block-level cells at BLOCK_POS
 * (section 5.7).
 */
Bytes entry_section(Overlay &own, const Overlay *fallback, const WireEntry &e,
                    std::vector<WireTemplate> &templates,
                    const std::vector<Memop> &memops, size_t &slots,
                    MemopCensus &census, const std::vector<uint8_t> &arena,
                    int isa)
{
    WireTemplate &t = templates[e.template_id];
    uint32_t n = uint32_t(t.insns.size()), stop = e.stop ? e.stop : n;
    Section sec(own, fallback, e.tid, e.template_id);
    size_t m = e.begin;
    for (uint32_t ipos = 0; ipos < stop; ipos++) {
        std::vector<const Memop *> dir[2];
        for (; m < e.end && memops[m].pos - e.base == ipos; m++) {
            const Memop &x = memops[m];
            if (x.reg) {    /* a slot the template declares (variance aside) */
                const std::vector<uint8_t> &dst = t.insns[ipos].regs->dst;
                if (x.reg <= dst.size()) {
                    put_reg(sec, ipos, x, dst[x.reg - 1], arena, isa);
                }
            } else {
                dir[x.store].push_back(&x);
            }
        }
        for (int d = 0; d < 2; d++) {
            size_t c = std::min(dir[d].size(), kSlotCount);
            sec.put(ipos, d ? kFidNStores : kFidNLoads, c);
            for (size_t k = 0; k < c; k++) {
                const Memop &x = *dir[d][k];
                sec.put(ipos, slot_fid(k, d, 0), x.addr);
                if (x.data_ok) {
                    sec.put(ipos, slot_fid(k, d, 1), x.lo, x.hi);
                }
                sec.put(ipos, slot_fid(k, d, 2), x.size);
            }
            slots = std::max(slots, c);
            /* the mask spans the widest count; u8, a larger one shows as over */
            uint8_t &len = t.insns[ipos].dep_mask_len[d];
            len = uint8_t(std::min<size_t>(std::max<size_t>(len, dir[d].size()), 255));
        }
        MemopCensus::Row &row = census.rows[t.insns[ipos].id];
        row.insn = &t.insns[ipos];
        row.hist[int32_t(ipos) == e.fault ? 2 : fallback != nullptr]
            [uint64_t(dir[0].size()) << 32 | dir[1].size()]++;
    }
    sec.put(n, kFidStop, stop, 0, n);
    sec.put(n, kFidFlags, e.flags);
    if (e.fault >= 0) {
        sec.put(n, kFidFaultInsn, uint64_t(e.fault));
    }
    return sec.bytes();
}

} /* namespace */

Bytes header_member(const HeaderFacts &facts,
                    const std::vector<WireTemplate> &templates, size_t slots,
                    bool wp, bool regdata)
{
    Bytes h;
    h.u32(kMagic);
    h.u8(facts.isa);
    /* flags: memop values, register values, and the wrong-path chains */
    h.u8(kFlagMemData | (regdata ? kFlagRegData : 0) | (wp ? kFlagWp : 0));
    h.uleb(0);          /* start_insn: no window, the timeline starts at 0 */
    h.uleb(0);          /* warmup_insns: none configured */
    h.uleb(0);          /* total_target_insns: 0 = unbounded */
    h.f64(0.0);         /* simpoint_weight: not a simpoint segment */
    h.str(facts.command);
    h.str(facts.datetime);
    h.str(facts.comment);
    h.str(facts.target_name);
    h.section(encoding_maps(std::min(slots, kSlotCount), templates, regdata));
    h.uleb(0);          /* warmup_end_trace_insn_idx: no warmup, ends at 0 */
    h.uleb(templates.size());   /* templates section, to member EOF */
    for (size_t id = 0; id < templates.size(); id++) {
        h.section(template_payload(id, templates[id]));
    }
    return h;
}

Bytes body_member(uint64_t root_phys, std::vector<WireTemplate> &templates,
                  const std::vector<WireEntry> &entries,
                  const std::vector<WireEntry> &chains,
                  const std::vector<Memop> &memops, size_t &slots, bool wp,
                  MemopCensus &census, const std::vector<uint8_t> &arena,
                  int isa)
{
    Bytes b;
    b.u32(kMagic);
    b.u8(kTagAsid);     /* opening context, section 4: asid index 0 ... */
    b.sleb(0);
    b.u64(root_phys);   /* ... whose first sighting carries its label */
    b.u64(0);           /* sig: reserved, always 0 */
    b.u8(kTagThread);   /* ... then thread 0 */
    b.sleb(0);
    Overlay cp, spec;   /* WP resolves WP -> CP -> default (section 5) */
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
        b.section(entry_section(cp, nullptr, e, templates, memops, slots,
                                census, arena, isa));
        if (wp) {
            Bytes ch;
            ch.uleb(e.wp_e - e.wp_b);
            int64_t prev = 0;   /* delta-coded within the chain */
            for (size_t w = e.wp_b; w < e.wp_e; w++) {
                ch.sleb(int64_t(chains[w].template_id) - prev);
                prev = chains[w].template_id;
                ch.section(entry_section(spec, &cp, chains[w], templates, memops,
                                         slots, census, arena, isa));
            }
            b.section(ch);
        }
    }
    b.u8(kTagEnd);
    b.uleb(entries.size());
    b.u32(kMagic);
    return b;
}

} /* namespace cst */
