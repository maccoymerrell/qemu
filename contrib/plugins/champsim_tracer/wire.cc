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
#include <set>
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

void MemSpill::push_back(const Memop &m)
{
    uint8_t b[40], *p = b + 2;
    uint32_t pos = m.pos;
    do {
        *p++ = uint8_t((pos & 0x7f) | (pos > 0x7f ? 0x80 : 0));
        pos >>= 7;
    } while (pos);
    *p++ = m.size;
    *p++ = m.reg;
    auto sig = [&p](uint64_t v) {     /* its significant bytes; how many */
        uint8_t n = 0;
        for (; v; v >>= 8, n++) {
            *p++ = uint8_t(v);
        }
        return n;
    };
    b[1] = sig(m.addr);
    b[0] = uint8_t(m.store | m.data_ok << 1 | m.fault << 2 | sig(m.lo) << 3);
    b[1] |= uint8_t(sig(m.hi) << 4);
    put(size(), b, size_t(p - b));
}

Memop MemSpill::read(size_t &at) const
{
    uint8_t b[40] = {};
    get(at, b, std::min(sizeof(b), size() - at));
    Memop m{};
    m.store = b[0] & 1;
    m.data_ok = b[0] >> 1 & 1;
    m.fault = b[0] >> 2 & 1;
    const uint8_t *p = b + 2;
    for (unsigned sh = 0; sh == 0 || p[-1] & 0x80; sh += 7) {
        m.pos |= uint32_t(*p++ & 0x7f) << sh;
    }
    m.size = *p++;
    m.reg = *p++;
    auto take = [&p](unsigned n) {
        uint64_t v = 0;
        for (unsigned k = 0; k < n; k++) {
            v |= uint64_t(*p++) << 8 * k;
        }
        return v;
    };
    m.addr = take(b[1] & 15);
    m.lo = take(b[0] >> 3);
    m.hi = take(b[1] >> 4);
    at += size_t(p - b);
    return m;
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

constexpr uint8_t kFlagMemData = 1;     /* header_flag CST_FLAG_MEM_DATA */
constexpr uint8_t kFlagRegData = 2;     /* header_flag CST_FLAG_REG_DATA */
constexpr uint8_t kFlagWp = 8;          /* header_flag CST_FLAG_WP */
constexpr uint8_t kFlagFault = 16;      /* header_flag CST_FLAG_FAULT */
constexpr uint8_t kInsnSystem = 128;    /* insn_flag CST_INSN_FLAG_SYSTEM */
constexpr uint8_t kInsnDeps = 64;       /* insn_flag CST_INSN_FLAG_HAS_DEP_BLOCK */
constexpr size_t kSlotCount = 512;      /* CST_FID_SLOT_COUNT, section 2 */

/*
 * Field ids: the block-level five take 0..4 (encoding_maps()), the two
 * counts 5 and 6, then slot k of the six memop families 7 + 6k + family,
 * interleaved by slot as section 5.1's layout intent describes.
 */
enum : uint32_t {
    kFidStop = 1, kFidFlags = 2, kFidDepth = 3, kFidFaultInsn = 4,
    kFidNLoads = 5, kFidNStores = 6, kFidSlot0 = 7,
    /* after every memop slot: METAFLAGS, then DST_REG{k}, DST_REG_WIDTH{k} */
    kFidMeta = kFidSlot0 + 6 * 512, kFidReg0,
    kFidTaken = kFidReg0 + 512, kFidTarget,     /* past every register pair */
    kFidLane0,      /* slot k of the SRC / DST / LOAD / STORE lane masks: + 4k + f */
};
const char *const kLaneFamilies[] = {
    "CST_FID_SRC_LANE_MASK", "CST_FID_DST_LANE_MASK",
    "CST_FID_LOAD_DATA_LANE_MASK", "CST_FID_STORE_DATA_LANE_MASK",
};
uint32_t lane_fid(size_t k, int family) { return kFidLane0 + 4 * uint32_t(k) + family; }
constexpr uint8_t kInsnVec = 16, kInsnLaneParallel = 32;    /* insn_flag */

/* CST_INSN_FLAG_VEC: a stated shape and a vector register to mask */
bool vec(uint8_t id) { return id >= kRegVec && id < kRegPred; }
bool vec_masked(const WireInsn &i)
{
    return (i.cls->vkind == kVecStatic || i.cls->vkind == kVecVl) &&
           (std::any_of(i.regs->src.begin(), i.regs->src.end(), vec) ||
            std::any_of(i.regs->dst.begin(), i.regs->dst.end(), vec));
}

/*
 * CST_INSN_FLAG_LANE_PARALLEL: the ruled family list (a family whose lanes
 * may be independent), for an emission QEMU states element-wise on every
 * element.
 */
bool lane_parallel(const WireInsn &i)
{
    static const std::set<std::string> ruled = { "VEC_ADD", "VEC_SUB", "VEC_MUL",
        "VEC_DIV", "VEC_SQRT", "VEC_MADD", "VEC_MSUB", "VEC_LOGIC" };
    return vec_masked(i) && i.cls->ew && i.cls->dsel < 0 && i.cls->ssel < 0 &&
           ruled.count(vocabulary(false)[i.cls->op]);
}
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
                    bool regdata, bool system)
{
    std::map<unsigned, bool> regs;   /* every id the templates use */
    size_t ndst = 0, lanes[4] = {};     /* ... and the lane slots they mask */
    for (const WireTemplate &t : templates) {
        for (const WireInsn &i : t.insns) {
            for (const auto *l : { &i.regs->src, &i.regs->dst }) {
                for (uint8_t r : *l) {
                    regs[r] = true;
                }
            }
            ndst = std::max(ndst, i.regs->dst.size());
            if (vec_masked(i)) {
                lanes[0] = std::max(lanes[0], i.regs->src.size());
                lanes[1] = std::max(lanes[1], i.regs->dst.size());
                lanes[2] = lanes[3] = slots;
            }
        }
    }
    MapEntries names, vocab[2];
    for (const auto &r : regs) {
        names.push_back({ r.first, reg_name(r.first) });
    }
    for (int b = 0; b < 2; b++) {
        for (const std::string &n : vocabulary(b)) {
            vocab[b].push_back({ vocab[b].size(), (b ? "BRANCH_" : "GEN_OP_") + n });
        }
    }
    MapEntries fids = numbered({ "CST_FID_BB_START", "CST_FID_BB_STOP",
                                 "CST_FID_BB_FLAGS", "CST_FID_BB_FAULT_DEPTH",
                                 "CST_FID_BB_FAULT_INSN" }, false);
    fids.push_back({ kFidNLoads, "CST_FID_N_LOADS" });
    fids.push_back({ kFidTaken, "CST_FID_BRANCH_TAKEN" });   /* always (5.6) */
    fids.push_back({ kFidTarget, "CST_FID_BRANCH_TARGET" });
    fids.push_back({ kFidNStores, "CST_FID_N_STORES" });
    for (size_t k = 0; k < slots; k++) {
        for (int f = 0; f < 6; f++) {
            fids.push_back({ slot_fid(k, f & 1, f / 2),
                             kSlotFamilies[f] + std::to_string(k) });
        }
    }
    for (int f = 0; f < 4; f++) {
        for (size_t k = 0; k < lanes[f]; k++) {
            fids.push_back({ lane_fid(k, f), kLaneFamilies[f] + std::to_string(k) });
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
    /* system mode's own names; a user trace omits them (section 2) */
    MapEntries hflags = numbered({ "CST_FLAG_MEM_DATA", "CST_FLAG_REG_DATA",
                                   "CST_FLAG_PROFILE", "CST_FLAG_WP" }, true);
    MapEntries iflags = numbered({ "CST_INSN_FLAG_BRANCH_COND", "CST_INSN_FLAG_HAS_IMM",
                                   "CST_INSN_FLAG_ATOMIC", "CST_INSN_FLAG_VEC",
                                   "CST_INSN_FLAG_LANE_PARALLEL",
                                   "CST_INSN_FLAG_HAS_DEP_BLOCK" }, true, 3);
    if (system) {
        hflags.push_back({ kFlagFault, "CST_FLAG_FAULT" });
        iflags.push_back({ kInsnSystem, "CST_INSN_FLAG_SYSTEM" });
    }
    const std::pair<const char *, MapEntries> maps[] = {
        { "body_tag", { { kTagEnd, "BODY_TAG_END" },
                        { kTagEntry, "BODY_TAG_ENTRY" },
                        { kTagThread, "BODY_TAG_THREAD_SWITCH" },
                        { kTagIframe, "BODY_TAG_IFRAME" },
                        { kTagRegfile, "BODY_TAG_REGFILE" },
                        { kTagAsid, "BODY_TAG_ASID_SWITCH" } } },
        { "header_flag", hflags },
        { "insn_flag", iflags },    /* bit 3 stays unassigned: section 2 */
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
        { "opcode", vocab[0] },         /* the canonical sets (vocab.h) */
        { "branch_type", vocab[1] },
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

/*
 * The dependency sub-block (format.rst Step 4.5, Reference section 3) of
 * @i, appended to @b; returns the family it carries or why it carries
 * none.  The default -- no block -- is all-to-all and always true; every
 * mask here is a SUBSET of it, and only from what QEMU stated: the access
 * statement's address compositions and moved registers, the decode word's
 * refiner kind, the register slots.  An access list is trusted for a
 * direction only when it is complete there: no helper could add accesses
 * (or every execution delivered exactly the listed count and no branch
 * could skip one), and a per-slot claim only when slot k is surely the
 * k-th listed access (no branch, every execution the listed count).
 */
using Bits = std::array<uint64_t, 8>;   /* up to 512 positions */
std::string dep_block(const WireInsn &i, const MemopCensus::Row *row, Bytes &b)
{
    const Regs &r = *i.regs;
    const size_t n = r.src.size(), L = i.dep_mask_len[0], S = i.dep_mask_len[1];
    const bool imm = i.cls->flags & kInsnImm;
    auto bit = [](Bits &m, size_t k) { m[k / 64] |= uint64_t(1) << (k % 64); };
    auto range = [&](size_t lo, size_t hi) { Bits m{}; for (; lo < hi; lo++) bit(m, lo); return m; };
    auto either = [](Bits a, const Bits &o) { for (int k = 0; k < 8; k++) a[k] |= o[k]; return a; };
    Bits full = range(0, n + L), afull = range(0, n);
    if (imm) { bit(full, n + L); bit(afull, n); }
    if (n + L + 1 > 512 || r.acc_varies) {
        return r.acc_varies ? "none:access-variance" : "none:wide";
    }
    /* the listed accesses per direction: loads (a prefetch's named one) */
    const std::string &op = vocabulary(false)[i.cls->op];
    bool synth = op == "PREFETCH" || op == "CACHE_FLUSH" || op == "TLB_FLUSH" ||
                 op == "VEC_PREFETCH";
    std::vector<const Acc *> dir[2], named;
    for (const Acc &a : r.acc) {
        (a.dir ? dir[a.dir != 1] : named).push_back(&a);
    }
    if (synth) {
        dir[0] = named;
    }
    const size_t lim[2] = { L, S };
    bool valid[2], slotted[2];
    for (int d = 0; d < 2; d++) {
        bool exact = true;
        for (int p = 0; row && p < 2; p++) {
            for (const auto &h : row->hist[p]) {
                exact &= (d ? uint32_t(h.first) : h.first >> 32) == dir[d].size();
            }
        }
        bool helpers = r.aflags & 1, branches = r.aflags & 2;
        valid[d] = lim[d] && lim[d] <= dir[d].size() &&
                   (!helpers || (exact && !branches)) && !i.fanout;
        slotted[d] = valid[d] && exact && !branches;
    }
    auto amask = [&](const Acc *a) {
        Bits m{};
        for (int8_t k : { a->base, a->index, a->seg }) {
            if (k >= 0) bit(m, size_t(k));
        }
        return a->form == 1 ? m : a->form == 2 ? Bits{} : afull;   /* REGS CONST */
    };
    std::vector<Bits> addr[2];
    bool has_addr = false;
    for (int d = 0; d < 2; d++) {
        Bits u{};
        for (const Acc *a : dir[d]) u = either(u, amask(a));
        for (size_t k = 0; k < lim[d]; k++) {
            addr[d].push_back(!valid[d] ? afull : slotted[d] ? amask(dir[d][k]) : u);
            has_addr |= addr[d].back() != afull;
        }
    }
    /* the register masks, by the word's refiner kind */
    std::vector<Bits> dst(r.dst.size(), full), sd(S, full);
    auto in_src = [&](uint8_t id) {
        return int(std::find(r.src.begin(), r.src.end(), id) - r.src.begin()); };
    Bits loads = range(n, n + L);
    std::string fam = "address";
    const uint8_t kind = r.opaque ? kDepNone : i.cls->kind;
    const bool move = kind == kDepMove || kind == kDepMoveWb;
    /*
     * A written-back base (mem.*.wb) moves by its offset: it depends on the
     * sources less the registers the accesses move, and itself.
     */
    std::set<int> base;
    Bits wbm = range(0, n);
    if (imm) bit(wbm, n + L);
    for (const Acc &a : r.acc) {
        for (int8_t k : { a.base, a.index, a.seg }) {
            if (a.form == 1 && k >= 0) base.insert(k);
        }
        if (a.dir > 1 && a.reg >= 0) wbm[a.reg / 64] &= ~(uint64_t(1) << (a.reg % 64));
    }
    auto wb = [&](size_t d) {
        int s = in_src(r.dst[d]);
        if (kind != kDepMoveWb || !base.count(s)) return false;
        dst[d] = wbm;
        bit(dst[d], size_t(s));
        return true;
    };
    if (move && valid[0] && dir[1].empty() && !S) {
        /*
         * passthrough: a loaded value moves to its register.  A destination
         * no access names takes the loads and the sources no load's address
         * reads (a merge from another register, vmovhps' second source).
         */
        std::set<int8_t> tgt;
        Bits rest = range(0, n);
        bool known = true;
        for (const Acc *a : dir[0]) {
            known &= a->form != 0;
            for (int8_t k : { a->base, a->index, a->seg }) {
                if (a->form == 1 && k >= 0) rest[k / 64] &= ~(uint64_t(1) << (k % 64));
            }
        }
        for (size_t d = 0; d < r.dst.size(); d++) {
            Bits m{};
            int s = in_src(r.dst[d]);
            for (size_t k = 0; slotted[0] && k < L; k++) {
                if (dir[0][k]->reg == int8_t(d)) {
                    bit(m, n + k);
                    m = s < int(n) ? either(m, amask(dir[0][k])) : m;
                    tgt.insert(int8_t(d));
                }
            }
            bool data = r.dst[d] < kRegSeg || r.dst[d] == kRegSp ||
                        r.dst[d] == kRegLr || r.dst[d] == kRegFp;
            if (m != Bits{}) {
                if (s < int(n)) bit(m, size_t(s));   /* a merge keeps its old value */
                dst[d] = m;
            } else if (wb(d)) {
            } else if (s == int(n) && data && known) {
                dst[d] = slotted[0] && std::all_of(dir[0].begin(), dir[0].end(),
                    [](const Acc *a) { return a->reg >= 0; }) ? full : either(loads, rest);
            }
        }
        fam = tgt.size() > 1 && op.compare(0, 4, "VEC_") == 0 ? "vec-struct" : "passthrough";
    } else if (move && valid[1] && dir[0].empty() && !L) {
        /* passthrough: a register's value moves to memory */
        bool all = std::all_of(dir[1].begin(), dir[1].end(), [](const Acc *a) {
            return a->reg != -1; });
        auto moved = [&](const Acc *a) {    /* a constant: the zero reg or imm */
            Bits m{};
            int z = in_src(kRegZero);
            if (a->reg >= 0) bit(m, size_t(a->reg));
            if (a->reg == -2 && imm) bit(m, n);
            if (a->reg == -2 && z < int(n)) bit(m, size_t(z));
            return m;
        };
        Bits u{};
        for (const Acc *a : dir[1]) u = either(u, moved(a));
        for (size_t k = 0; k < S; k++) {
            const Acc *a = slotted[1] ? dir[1][k] : nullptr;
            sd[k] = a ? (a->reg == -1 ? full : moved(a)) : all ? u : full;
        }
        for (size_t d = 0; d < r.dst.size(); d++) {
            wb(d);
        }
        fam = "passthrough";
    } else if ((kind == kDepPush || kind == kDepPop) && in_src(kRegSp) < int(n)) {
        /* stack: the pointer moves by a constant; the datum is the rest */
        int sp = in_src(kRegSp);
        Bits spm{};
        bit(spm, size_t(sp));
        if (imm) bit(spm, n + L);
        bool alone = r.dst.size() == 1 && !S;       /* pop %sp */
        for (size_t d = 0; d < r.dst.size(); d++) {
            if (r.dst[d] == kRegSp && !(kind == kDepPush && dir[1].size() != 1)) {
                dst[d] = kind == kDepPop && alone ? either(spm, loads) : spm;
            } else if (kind == kDepPop && L) {
                Bits m = loads;
                if (in_src(r.dst[d]) < int(n)) bit(m, size_t(in_src(r.dst[d])));
                dst[d] = m;
            }
        }
        Bits data = kind == kDepPop ? loads : either(range(0, n), loads);
        if (kind == kDepPush) {     /* less the pointer and a load's address */
            if (imm) bit(data, n + L);
            data[sp / 64] &= ~(uint64_t(1) << (sp % 64));
            for (const Acc *a : dir[0]) {
                for (int8_t k : { a->base, a->index, a->seg }) {
                    if (a->form == 1 && k >= 0) data[k / 64] &= ~(uint64_t(1) << (k % 64));
                }
            }
        }
        for (size_t k = 0; k < S; k++) {
            sd[k] = (kind == kDepPush && dir[1].size() != 1) || data == Bits{} ? full : data;
        }
        fam = "stack";
    }
    bool has_reg = false, sat = false;
    for (const auto *v : { &dst, &sd }) {
        for (const Bits &m : *v) {
            has_reg |= m != full;
            sat |= m == full;
        }
    }
    /*
     * A source only an address mask names reaches a sink through the memop
     * alone (format.rst, lane-granularity resolution, rule 2), so a
     * saturated sink loses one that only a store's address names -- no
     * load carries it.  Such a block states no address masks.
     */
    Bits lda{}, sta{};
    for (const Bits &m : addr[0]) lda = either(lda, m);
    for (const Bits &m : addr[1]) sta = either(sta, m);
    bool cut = false;
    for (size_t k = 0; k < n; k++) {
        cut |= sat && has_addr && (sta[k / 64] & ~lda[k / 64]) >> (k % 64) & 1;
    }
    has_addr &= !cut;
    if (!has_reg && !has_addr) {
        return cut ? "none:store-address" : L + S ? (valid[0] || valid[1] ?
               "none:no-gain" : "none:list-incomplete") : "none";
    }
    auto uleb = [&b](const Bits &m) {     /* a multi-limb ULEB */
        size_t top = 512;
        while (top && !(m[(top - 1) / 64] >> ((top - 1) % 64) & 1)) top--;
        for (size_t k = 0; k == 0 || k < top; k += 7) {
            uint8_t v = uint8_t(m[k / 64] >> (k % 64) | (k % 64 > 57 && k / 64 < 7 ?
                                                         m[k / 64 + 1] << (64 - k % 64) : 0)) & 0x7f;
            b.u8(v | (k + 7 < top ? 0x80 : 0));
        }
    };
    b.u8(uint8_t((has_reg ? 1 : 0) | (has_addr ? 2 : 0)));
    if (has_reg) {
        for (const auto *v : { &dst, &sd }) for (const Bits &m : *v) uleb(m);
    }
    if (has_addr) {
        for (int d = 0; d < 2; d++) for (const Bits &m : addr[d]) uleb(m);
    }
    return has_reg ? fam : "address";
}

/*
 * Whether a vector instruction's lanes are masked (and lane-parallel), or
 * why not -- no shape stated, several, more than 64 lanes, another per
 * retranslation, no vector register -- by opcode family; "-": not vector.
 */
std::string lane_status(const WireInsn &i)
{
    static const char *const why[] = { "none", "no-vector-reg", "no-vector-reg",
                                       "mixed", "wide", "varies" };
    const Class &c = *i.cls;
    if (!c.vword && c.vkind == kVecNone) {
        return "-";
    }
    return (vec_masked(i) ? lane_parallel(i) ? "masked-parallel" : "masked" :
            std::string("refused-") + why[c.vkind]) + ":" + vocabulary(false)[c.op];
}

/* One template payload (section 6); its id is its index. */
Bytes template_payload(uint64_t id, const WireTemplate &t, const MemopCensus &census,
                       std::map<uint32_t, std::string> &deps)
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
        /* a bulk op is the self-loop of its fan-out (format.rst) */
        static const auto &br = vocabulary(true);
        static const uint8_t rep = uint8_t(std::find(br.begin(), br.end(), "REP") -
                                           br.begin());
        b.u8(i.cls->op);
        b.u8(i.fanout ? rep : i.cls->br);
        uint8_t flags = i.cls->flags | (i.fanout ? kInsnCond : 0);
        auto row = census.rows.find(i.id);
        Bytes dep;
        deps[i.id] = dep_block(i, row != census.rows.end() ? &row->second : nullptr, dep);
        deps[i.id] += '\t' + lane_status(i);
        flags |= dep.data().empty() ? 0 : kInsnDeps;
        flags |= vec_masked(i) ? kInsnVec | (lane_parallel(i) ? kInsnLaneParallel : 0) : 0;
        b.u8(flags | (i.sys ? kInsnSystem : 0));  /* and the privilege it ran at */
        b.u8(uint8_t(i.regs->src.size()));
        b.u8(uint8_t(i.regs->dst.size()));
        for (const auto *l : { &i.regs->src, &i.regs->dst }) {
            for (uint8_t r : *l) {
                b.u8(r);
            }
        }
        b.u8(i.dep_mask_len[0]);    /* max_dep_loads */
        b.u8(i.dep_mask_len[1]);    /* max_dep_stores */
        if (flags & kInsnImm) {
            b.sleb(i.cls->imm);
        }
        b.u8(i.size);
        for (unsigned k = 0; k < i.size; k++) {
            b.u8(i.bytes[k]);
        }
        b.raw(dep);
    }
    return b;
}

/*
 * One overlay of field state (section 5): (asid index, thread, template,
 * ipos, fid) -> value.  Per context, as section 5 keys it.
 */
struct Cell {
    uint32_t asid, tid, tmpl, ipos, fid;
    bool operator==(const Cell &o) const
    {
        return asid == o.asid && tid == o.tid && tmpl == o.tmpl &&
               ipos == o.ipos && fid == o.fid;
    }
};
struct CellHash {
    size_t operator()(const Cell &c) const
    {
        return std::hash<uint64_t>()((uint64_t(c.asid) << 54) ^ (uint64_t(c.tid) << 44) ^
                                     (uint64_t(c.tmpl) << 24) ^ (uint64_t(c.ipos) << 12) ^
                                     c.fid);
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
    Section(Overlay &own, const Overlay *fallback, uint32_t asid, uint32_t tid,
            uint32_t tmpl)
        : own_(own), fb_(fallback), asid_(asid), tid_(tid), tmpl_(tmpl) {}

    void put(uint32_t ipos, uint32_t fid, uint64_t lo, uint64_t hi = 0,
             uint64_t def = 0)
    {
        put(ipos, fid, Value{ lo, hi }, Value{ def });
    }

    void put(uint32_t ipos, uint32_t fid, const Value &v, const Value &def)
    {
        Cell c{ asid_, tid_, tmpl_, ipos, fid };
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
        Record x{ ipos, fid, {} };  /* (v - p) mod 2**512, as an i512 */
        uint64_t borrow = 0;
        for (int k = 0; k < 8; k++) {
            uint64_t t = v[k] - p[k];
            x.delta[k] = t - borrow;
            borrow = v[k] < p[k] || t < borrow;
        }
        x.delta[8] = uint64_t(int64_t(x.delta[7]) >> 63);
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
    uint32_t asid_, tid_, tmpl_;
    std::vector<Record> recs_;
};

/*
 * Destination register @x.reg - 1's value and width (section 5.4), and for
 * the integer flags register of x86 / AArch64 the canonical METAFLAGS byte
 * (section 2): Z N C V P, from EFLAGS ZF SF CF OF PF / NZCV.
 */
void put_reg(Section &sec, uint32_t ipos, const Memop &x, uint8_t id,
             const Spill<uint8_t> &arena, int isa)
{
    static const int bit[2][5] = { { 6, 7, 0, 11, 2 }, { 30, 31, 29, 28, -1 } };
    Value v{ x.lo, x.hi };
    for (unsigned k = 16; k < x.size; k++) {
        v[k / 8] |= uint64_t(arena[x.addr + k - 16]) << (k % 8 * 8);
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
 * The lane masks of instruction @i at @ipos, this execution (format.rst
 * "Vector lane masks"), @dir its loads and stores, @vl what an RVV one read.
 * A vector register slot takes the shape's lanes -- those below vl for an
 * RVV one, the members of a register group holding the elements after the
 * base's -- or the element a single-element form selects; a source that is
 * also the destination is read whole, less that element.  A memop takes, by
 * the rank rule, the next lanes its size spans among its register's active
 * ones (a group's base: the elements past it take none).  Its register is
 * the one the dependency block names: the stated one where dep_block()
 * names it per slot (a move whose accesses are complete, branch-free, one
 * direction), else every one, whose masks are the same -- and a memop moving
 * every register counts in each one's rank.
 */
void put_lanes(Section &sec, uint32_t ipos, const WireInsn &i,
               const std::vector<Memop> *dir, const Memop *vl, MemopCensus &census)
{
    const Class &c = *i.cls;
    const Regs &r = *i.regs;
    if (!vec_masked(i) || (c.vkind == kVecVl && !(vl && vl->data_ok))) {
        census.vl_unread += vec_masked(i);
        return;
    }
    auto run = [](uint64_t n) { return n >= 64 ? ~uint64_t(0) : (uint64_t(1) << n) - 1; };
    /* member m of an aligned register group holds elements m * vn on */
    auto act = [&](uint8_t id, int8_t sel) {
        uint64_t m = uint64_t(id - kRegVec) % c.vgroup * c.vn;
        uint64_t n = c.vkind == kVecVl ? vl->lo : uint64_t(c.vn) * c.vgroup;
        return sel >= 0 ? uint64_t(1) << sel : run(n > m ? std::min<uint64_t>(n - m, c.vn) : 0);
    };
    const uint64_t full = run(c.vn), dmask = act(kRegVec, c.dsel), smask = act(kRegVec, c.ssel);
    for (size_t k = 0; k < r.src.size(); k++) {
        bool merge = std::find(r.dst.begin(), r.dst.end(), r.src[k]) != r.dst.end();
        if (vec(r.src[k])) {
            sec.put(ipos, lane_fid(k, 0), merge ? full & ~(c.dsel >= 0 ? dmask : 0) :
                                          act(r.src[k], c.ssel));
        }
    }
    for (size_t k = 0; k < r.dst.size(); k++) {
        if (vec(r.dst[k])) {
            sec.put(ipos, lane_fid(k, 1), act(r.dst[k], c.dsel));
        }
    }
    std::vector<const Acc *> listed[2];
    for (const Acc &a : r.acc) {
        if (a.dir) {
            listed[a.dir != 1].push_back(&a);
        }
    }
    const bool move = c.kind == kDepMove || c.kind == kDepMoveWb;
    for (int d = 0; d < 2; d++) {
        bool per = move && !(r.aflags & 3) && !i.fanout && !r.acc_varies &&
                   listed[d].size() == dir[d].size() && listed[!d].empty() && dir[!d].empty();
        /* per register slot the lanes taken so far; -1: by memops moving every one */
        std::map<int, unsigned> used;
        const std::vector<uint8_t> &regs = d ? r.src : r.dst;
        const int first = int(std::find_if(regs.begin(), regs.end(), vec) - regs.begin());
        for (size_t k = 0; k < std::min(dir[d].size(), kSlotCount); k++) {
            const int reg = per ? listed[d][k]->reg : -1;
            unsigned u = used[-1] + used[reg >= 0 ? reg : first];
            unsigned span = std::max(1u, unsigned(dir[d][k].size / c.vesz)), rank = 0;
            uint64_t m = 0, lanes = d ? smask : dmask;
            for (unsigned j = 0; j < 64; j++) {
                if (lanes >> j & 1 && rank++ - u < span) {
                    m |= uint64_t(1) << j;
                }
            }
            used[reg] += span;
            sec.put(ipos, lane_fid(k, 2 + d), m);
        }
    }
}

/*
 * The delta section of entry or chain block @e: its memops and register
 * values over the range it ran, then its block-level cells at BLOCK_POS
 * (section 5.7).
 */
Bytes entry_section(Overlay &own, const Overlay *fallback, const WireEntry &e,
                    uint32_t asid, uint32_t tid,
                    std::vector<WireTemplate> &templates,
                    const MemSpill &memops, size_t &slots,
                    MemopCensus &census, const Spill<uint8_t> &arena, int isa)
{
    WireTemplate &t = templates[e.template_id];
    uint32_t n = uint32_t(t.insns.size()), stop = e.stop ? e.stop : n;
    Section sec(own, fallback, asid, tid, e.template_id);
    size_t m = e.begin, next = m;
    Memop x = m < e.end ? memops.read(next) : Memop{};
    for (uint32_t ipos = 0; ipos < stop; ipos++) {
        std::vector<Memop> dir[2];
        Memop vl{}, *vlp = nullptr;
        for (; m < e.end && x.pos - e.base == ipos;
             x = (m = next) < e.end ? memops.read(next) : x) {
            if (x.reg == kVlRecord) {
                vl = x;
                vlp = &vl;
            } else if (x.reg) {    /* a slot the template declares (variance aside) */
                const std::vector<uint8_t> &dst = t.insns[ipos].regs->dst;
                if (x.reg <= dst.size()) {
                    put_reg(sec, ipos, x, dst[x.reg - 1], arena, isa);
                }
            } else {
                dir[x.store].push_back(x);
            }
        }
        for (int d = 0; d < 2; d++) {
            size_t c = std::min(dir[d].size(), kSlotCount);
            sec.put(ipos, d ? kFidNStores : kFidNLoads, c);
            for (size_t k = 0; k < c; k++) {
                const Memop &a = dir[d][k];
                sec.put(ipos, slot_fid(k, d, 0), a.addr);
                if (a.data_ok) {
                    sec.put(ipos, slot_fid(k, d, 1), a.lo, a.hi);
                }
                sec.put(ipos, slot_fid(k, d, 2), a.size);
            }
            slots = std::max(slots, c);
            /* the mask spans the widest count; u8, a larger one shows as over */
            uint8_t &len = t.insns[ipos].dep_mask_len[d];
            len = uint8_t(std::min<size_t>(std::max<size_t>(len, dir[d].size()), 255));
        }
        put_lanes(sec, ipos, t.insns[ipos], dir, vlp, census);
        MemopCensus::Row &row = census.rows[t.insns[ipos].id];
        row.insn = &t.insns[ipos];
        row.hist[int32_t(ipos) == e.fault ? 2 : fallback != nullptr]
            [uint64_t(dir[0].size()) << 32 | dir[1].size()]++;
    }
    if (e.bpos >= 0 && e.succ) {    /* 5.6: direction, signed displacement */
        const WireInsn &l = t.insns.back(), &br = t.insns[e.bpos];
        Value d;
        d.fill(e.succ < br.pc ? ~uint64_t(0) : 0);
        d[0] = e.succ - br.pc;
        sec.put(e.bpos, kFidTaken, e.succ != l.pc + l.size);
        sec.put(e.bpos, kFidTarget, d, Value{});
    }
    sec.put(n, kFidStop, stop, 0, n);
    sec.put(n, kFidFlags, e.flags);
    sec.put(n, kFidDepth, e.depth);
    if (e.fault >= 0) {
        sec.put(n, kFidFaultInsn, uint64_t(e.fault));
    }
    return sec.bytes();
}

} /* namespace */

Bytes header_member(const HeaderFacts &facts,
                    const std::vector<WireTemplate> &templates, size_t slots,
                    bool wp, bool regdata, const MemopCensus &census,
                    std::map<uint32_t, std::string> &deps)
{
    Bytes h;
    h.u32(kMagic);
    h.u8(facts.isa);
    /* flags: memop values, register values, and the wrong-path chains */
    h.u8(kFlagMemData | (regdata ? kFlagRegData : 0) | (wp ? kFlagWp : 0) |
         (facts.system ? kFlagFault : 0));
    h.uleb(facts.start);    /* the window as configured; 0s: none */
    h.uleb(facts.warmup);
    h.uleb(facts.total);    /* 0 = unbounded */
    h.f64(facts.weight);    /* 0.0: not a simpoint segment */
    h.str(facts.command);
    h.str(facts.datetime);
    h.str(facts.comment);
    h.str(facts.target_name);
    h.section(encoding_maps(std::min(slots, kSlotCount), templates, regdata,
                            facts.system));
    h.uleb(facts.warm_end);     /* warmup_end_trace_insn_idx */
    h.uleb(templates.size());   /* templates section, to member EOF */
    for (size_t id = 0; id < templates.size(); id++) {
        h.section(template_payload(id, templates[id], census, deps));
    }
    return h;
}

bool body_member(int fd, std::vector<WireTemplate> &templates,
                 const EntryFeed &feed, const MemSpill &memops,
                 size_t &slots, size_t &count, bool wp, MemopCensus &census,
                 const Spill<uint8_t> &arena, int isa, bool ordinals,
                 const std::vector<Bytes> &regfiles)
{
    Bytes b;
    bool ok = true;
    auto drain = [&](size_t above) {    /* to the file in 1 MiB strides */
        if (b.data().size() >= above) {
            ok = ok && write_all(fd, b.data().data(), b.data().size());
            b.clear();
        }
    };
    b.u32(kMagic);
    Overlay cp, spec;   /* WP resolves WP -> CP -> default (section 5) */
    slots = count = 0;
    int64_t tid = 0, asid = 0, tmpl = 0;
    std::map<uint64_t, uint32_t> labels;    /* first-sighting indices */
    std::map<uint32_t, uint32_t> tids;
    /*
     * Section 4: the opening ASID_SWITCH + THREAD_SWITCH pair states the
     * first context; later ones follow either dimension's change.  A
     * label rides its index's first sighting (root_phys, sig 0).
     */
    auto context = [&](uint64_t label, uint32_t t) {
        auto a = labels.emplace(label, uint32_t(labels.size()));
        if (count == 1 || a.first->second != asid) {
            b.u8(kTagAsid);
            b.sleb(int64_t(a.first->second) - asid);
            asid = a.first->second;
            if (a.second) {
                b.u64(label);
                b.u64(0);
            }
        }
        int64_t w = ordinals ? tids.emplace(t, uint32_t(tids.size())).first->second : t;
        if (count == 1 || w != tid) {
            b.u8(kTagThread);
            b.sleb(w - tid);
            tid = w;
        }
    };
    feed([&](const WireEntry &e, const std::vector<WireEntry> &chain) {
        count++;
        context(e.asid, e.tid);
        if (e.rf) {         /* section 4.6: the context's registers at entry */
            b.u8(kTagRegfile);
            b.uleb(uint64_t(tid));
            b.raw(regfiles[e.rf - 1]);
        }
        b.u8(kTagEntry);
        b.sleb(int64_t(e.template_id) - tmpl);
        tmpl = e.template_id;
        b.section(entry_section(cp, nullptr, e, uint32_t(asid), uint32_t(tid),
                                templates, memops, slots, census, arena, isa));
        if (wp) {
            Bytes ch;
            ch.uleb(chain.size());
            int64_t prev = 0;   /* delta-coded within the chain */
            for (const WireEntry &c : chain) {
                ch.sleb(int64_t(c.template_id) - prev);
                prev = c.template_id;
                ch.section(entry_section(spec, &cp, c, uint32_t(asid), uint32_t(tid),
                                         templates, memops, slots, census, arena,
                                         isa));
            }
            b.section(ch);
        }
        drain(1u << 20);
    });
    if (!count) {       /* nothing ran: the opening context is asid 0, thread 0 */
        count = 1;
        context(0, 0);
        count = 0;
    }
    b.u8(kTagEnd);
    b.uleb(count);
    b.u32(kMagic);
    drain(0);
    return ok;
}

} /* namespace cst */
