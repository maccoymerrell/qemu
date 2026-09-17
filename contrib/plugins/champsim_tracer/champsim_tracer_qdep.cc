/*
 * The wire's facts, taken from QEMU.  See champsim_tracer_qdep.h.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>
#include <vector>

#include "champsim_tracer.h"
#include "champsim_tracer_qdep.h"
#include "champsim_tracer_regmap.h"
#include "champsim_tracer_vocabulary.h"

extern "C" {
#include <qemu-plugin-dataflow.h>
}

namespace {

QdepCounters g_qdep;

/*
 * Provenance bitmaps come back as 64-bit words and their width is a target
 * property.  One reusable buffer per thread, grown rather than guessed: the
 * ABI refuses to write a partial set, so a buffer that is too small costs one
 * extra call and never a short answer.
 */
struct SetBuf {
    std::vector<uint64_t> w;

    uint64_t *data() { return w.data(); }
    unsigned words() const { return (unsigned)w.size(); }
    void ensure(unsigned n)
    {
        if (w.size() < n) {
            w.resize(n);
        }
    }
};

thread_local SetBuf tls_set;

/*
 * Ask @fn for a set and leave it in tls_set.  Returns the number of WORDS
 * written, or 0 when the instruction could not be recorded in full or the
 * accessor refused.  The retry is the ABI's contract: a first call with a
 * short buffer writes nothing and returns the size needed.
 */
template <typename F>
unsigned read_set(F fn)
{
    tls_set.ensure(4);
    unsigned need = fn(tls_set.data(), tls_set.words());

    if (need == QEMU_PLUGIN_DF_INCOMPLETE) {
        return 0;
    }
    if (need > tls_set.words()) {
        tls_set.ensure(need);
        need = fn(tls_set.data(), tls_set.words());
        if (need == QEMU_PLUGIN_DF_INCOMPLETE || need > tls_set.words()) {
            return 0;
        }
    }
    return need;
}

/*
 * What a provenance bit stands for on the wire.
 *
 * Three namespaces share the one index and each answers differently.  A bit
 * below nregs is a TCG global and carries the name the target registered it
 * under; a bit at or above is a CPUArchState byte range, which resolves to a
 * declared register-file entry's name when the target declared its layout and
 * to nothing when it did not; and three bits are atoms that are not storage.
 *
 * NOTHING IS SILENTLY DROPPED.  A member with no wire spelling is counted --
 * as an unmapped name or as an unnamed range -- because a set that quietly
 * omitted one would compare equal to a set that genuinely lacks it, which is
 * the discount R12.1 forbids.  The counters are the honest record of what the
 * wire could not carry.
 */
enum BitKind {
    BIT_REG,        /* a register the wire can name  */
    BIT_LOAD,       /* the value a guest load returned */
    BIT_IMM,        /* the encoding's own value      */
    BIT_CONST,      /* any other constant            */
    BIT_NOTHING,    /* counted, not publishable      */
};

/*
 * The load-data slot a memop index occupies, for the translation in hand.
 *
 * The wire numbers LOADS; QEMU numbers ACCESSES, loads and stores together in
 * program order.  `movq %rax,(%rdi)` followed by a load in the same
 * instruction makes those two numberings differ, so the map is built from the
 * same walk that assigns the wire's load slots and never assumed to be the
 * identity.  0xff means the access is not a load this template publishes --
 * a store, or a load past the template's slot ceiling.
 */
thread_local uint8_t tls_load_slot[QEMU_PLUGIN_DF_MAX_MEMOPS];

BitKind classify_bit(unsigned bit, uint8_t *reg_out)
{
    uint32_t atom = 0, off = 0, size = 0;

    if (qemu_plugin_dataflow_prov_memop(bit, &atom)) {
        *reg_out = atom < QEMU_PLUGIN_DF_MAX_MEMOPS
                   ? tls_load_slot[atom] : (uint8_t)0xff;
        return BIT_LOAD;
    }
    if (qemu_plugin_dataflow_prov_atom(bit, &atom)) {
        uint8_t reg = REG_NONE;
        bool is_reg = false;

        if (cst_regmap_atom(atom, &reg, &is_reg)) {
            if (is_reg) {
                *reg_out = reg;
                return BIT_REG;
            }
            return atom == QEMU_PLUGIN_DF_ATOM_IMM ? BIT_IMM : BIT_CONST;
        }
        g_qdep.unnamed_ranges++;
        return BIT_NOTHING;
    }

    const char *name = nullptr;

    if (bit < qemu_plugin_dataflow_nregs()) {
        name = qemu_plugin_dataflow_reg_name(bit, nullptr, nullptr);
    } else if (qemu_plugin_dataflow_prov_field(bit, &off, &size)) {
        name = qemu_plugin_dataflow_field_reg(off, size);
        if (!name) {
            /* The target declared no register file containing this range.
             * There is no name for the map to have a row for, so this is not
             * a map gap -- it is state QEMU touched that no register
             * describes. */
            g_qdep.unnamed_ranges++;
            return BIT_NOTHING;
        }
    } else {
        g_qdep.unnamed_ranges++;
        return BIT_NOTHING;
    }

    uint8_t reg = REG_NONE;

    if (!name || !cst_regmap_lookup((unsigned)trace_isa, name, &reg)) {
        /* QEMU named a register this build's map cannot read.  That is a
         * skewed build, not an unclassifiable register, and it is counted
         * rather than published as REG_NONE. */
        g_qdep.unmapped_names++;
        return BIT_NOTHING;
    }
    if (reg == REG_NONE) {
        /* An ADJUDICATED answer: the name is QEMU's own lowering or a piece
         * of emulation state that is not an architectural register.  The row
         * says so; it is not a gap. */
        return BIT_NOTHING;
    }
    *reg_out = reg;
    return BIT_REG;
}

/* The slot holding @reg, existing on dedup or newly allocated; UINT8_MAX when
 * the table is full (counted) or the id is REG_NONE. */
uint8_t seat_src(InsnFields *f, InsnRegNames *rn, uint8_t reg)
{
    if (reg == REG_NONE) {
        return UINT8_MAX;
    }
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        if (f->src_regs[i] == reg) {
            return i;
        }
    }
    if (f->n_src_regs >= MAX_SRC_REGS) {
        g_qdep.dropped_srcs++;
        return UINT8_MAX;
    }
    uint8_t slot = f->n_src_regs++;

    f->src_regs[slot] = reg;
    if (rn) {
        rn->src_qemu_reg_keys[slot] = qemu_reg_for_generic_id(reg);
    }
    return slot;
}

uint8_t seat_dst(InsnFields *f, InsnRegNames *rn, uint8_t reg)
{
    if (reg == REG_NONE) {
        return UINT8_MAX;
    }
    for (uint8_t i = 0; i < f->n_dst_regs; i++) {
        if (f->dst_regs[i] == reg) {
            return i;
        }
    }
    if (f->n_dst_regs >= MAX_DST_REGS) {
        g_qdep.dropped_dsts++;
        return UINT8_MAX;
    }
    uint8_t slot = f->n_dst_regs++;

    f->dst_regs[slot] = reg;
    if (rn) {
        rn->dst_qemu_reg_keys[slot] = qemu_reg_for_generic_id(reg);
    }
    /*
     * The integer-flags marker, which decides whether the encoder emits a
     * METAFLAGS side record.  Gated on the ISA supplying a mapper, exactly as
     * the per-ISA .is_int_flags marker was: on MIPS the same generic id names
     * DSP status bits, which no mapper turns into Z/N/C/V.
     */
    if (reg == REG_FLAGS && isa_properties[trace_isa].flags_to_metaflags) {
        f->writes_int_flags = true;
    }
    return slot;
}

/*
 * Seat every member of the set now in tls_set as a SOURCE, and return the
 * mask of src slots it landed in plus whether the immediate atom was among
 * them.  The mask is what the address and data families index.
 */
struct SeatedSet {
    uint64_t src_mask;
    bool     has_imm;
};

SeatedSet seat_set_as_src(InsnFields *f, InsnRegNames *rn, unsigned nwords)
{
    SeatedSet out = { 0, false };

    for (unsigned w = 0; w < nwords; w++) {
        uint64_t word = tls_set.data()[w];

        while (word) {
            unsigned b = (unsigned)__builtin_ctzll(word);

            word &= word - 1;

            uint8_t reg = REG_NONE;

            switch (classify_bit(w * 64 + b, &reg)) {
            case BIT_REG: {
                uint8_t slot = seat_src(f, rn, reg);

                if (slot < MAX_SRC_REGS) {
                    out.src_mask |= (uint64_t)1 << slot;
                }
                break;
            }
            case BIT_IMM:
                out.has_imm = true;
                break;
            case BIT_LOAD:
                /* A READ SET holds registers, never the value one of this
                 * instruction's own accesses returned.  Reaching here would
                 * mean the emulator had named a load's datum as an input to
                 * the instruction that performs it; there is no src_reg[]
                 * slot for such a thing and inventing one would put a
                 * non-register in the wire's register list. */
                break;
            case BIT_CONST:
            case BIT_NOTHING:
                break;
            }
        }
    }
    return out;
}

/*
 * Translate a provenance set into a dependency mask over THIS instruction's
 * already-seated inputs.
 *
 * The layout is the wire's and is not this file's to choose (see InsnFields):
 * bits [0, n_src_regs) index src_regs[], bits [n_src_regs, +max_dep_loads)
 * index the loaded data, and the bit above them is the immediate.  A
 * provenance member that is not one of this instruction's inputs contributes
 * nothing -- it cannot, because the wire has no slot for it -- and that is
 * counted as an unmapped name or an unnamed range where it is one.
 */
uint64_t prov_to_mask(const InsnFields *f, unsigned nwords)
{
    uint64_t mask = 0;

    for (unsigned w = 0; w < nwords; w++) {
        uint64_t word = tls_set.data()[w];

        while (word) {
            unsigned b = (unsigned)__builtin_ctzll(word);

            word &= word - 1;

            uint8_t reg = REG_NONE;

            switch (classify_bit(w * 64 + b, &reg)) {
            case BIT_REG:
                for (uint8_t i = 0; i < f->n_src_regs; i++) {
                    if (f->src_regs[i] == reg) {
                        mask |= (uint64_t)1 << i;
                        break;
                    }
                }
                break;
            case BIT_LOAD:
                /* The value came out of one of this instruction's own loads;
                 * @reg carries that load's wire slot. */
                if (reg < f->max_dep_loads) {
                    mask |= (uint64_t)1 << (f->n_src_regs + reg);
                    g_qdep.load_datum_seated++;
                }
                break;
            case BIT_IMM:
                mask |= (uint64_t)1 << (f->n_src_regs + f->max_dep_loads);
                break;
            case BIT_CONST:
            case BIT_NOTHING:
                break;
            }
        }
    }
    return mask;
}

/* The same, for an ADDRESS mask, whose layout omits the loaded-data slots
 * because an address computes before any load of the same instruction fires. */
uint64_t prov_to_addr_mask(const InsnFields *f, unsigned nwords)
{
    uint64_t mask = 0;

    for (unsigned w = 0; w < nwords; w++) {
        uint64_t word = tls_set.data()[w];

        while (word) {
            unsigned b = (unsigned)__builtin_ctzll(word);

            word &= word - 1;

            uint8_t reg = REG_NONE;

            switch (classify_bit(w * 64 + b, &reg)) {
            case BIT_REG:
                for (uint8_t i = 0; i < f->n_src_regs; i++) {
                    if (f->src_regs[i] == reg) {
                        mask |= (uint64_t)1 << i;
                        break;
                    }
                }
                break;
            case BIT_LOAD:
                /* An address computed from a datum this same instruction
                 * loaded.  The address layout reserves no load-data bits --
                 * addresses compute before any load of the instruction fires
                 * -- so there is nothing to set; it is counted so the absence
                 * is a measured zero rather than an unasked question. */
                g_qdep.load_datum_in_addr++;
                break;
            case BIT_IMM:
                mask |= (uint64_t)1 << f->n_src_regs;
                break;
            case BIT_CONST:
            case BIT_NOTHING:
                break;
            }
        }
    }
    return mask;
}

/*
 * The lane shape, from what the decode site stated.
 *
 * The four facts are carried apart on purpose (qemu-plugin-dataflow.h): the
 * element size says how wide a lane is and nothing about which lanes the
 * instruction touches, and a packed add and an element insert of the same
 * width expand into ops that look alike and do not depend alike.  Turning
 * them into the wire's per-slot masks is this file's job.
 *
 * WHICH SLOTS GET LANES.  A lane set belongs to a REGISTER, not to a slot
 * (Finding 194-B), and the register lists are already seated when this runs.
 * Only registers wide enough to hold more than one lane participate: a
 * general register feeding a vector operation carries no lanes, and giving it
 * the full mask would tie a scalar to every lane of the result.  Width comes
 * from the declared register file, which is the only place it is stated.
 */
bool reg_is_vector_wide(unsigned bit_unused, uint8_t reg, unsigned oprsz)
{
    (void)bit_unused;
    (void)reg;
    return oprsz > 8;
}

void seat_lanes(InsnFields *f, const qemu_plugin_dataflow_status *st)
{
    if (st->vec_vece == QEMU_PLUGIN_DF_VECE_NONE || st->vec_oprsz == 0) {
        return;
    }
    unsigned lane_bytes = 1u << st->vec_vece;
    unsigned nlanes = st->vec_oprsz / (lane_bytes ? lane_bytes : 1);

    if (nlanes == 0) {
        return;
    }
    if (nlanes > 64) {
        nlanes = 64;
    }

    uint64_t full = nlanes >= 64 ? ~(uint64_t)0
                                 : (((uint64_t)1 << nlanes) - 1);
    uint64_t sel = 0;

    if (st->vec_lane >= 0 && st->vec_lane < 64) {
        sel = (uint64_t)1 << st->vec_lane;
    }

    uint64_t src_lane = full, dst_lane = full;
    bool parallel = true;

    switch (st->vec_kind) {
    case QEMU_PLUGIN_DF_VEC_KIND_UNIFORM:
        /* lane i of the result is a function of lane i of the sources. */
        break;
    case QEMU_PLUGIN_DF_VEC_KIND_INSERT:
        /* Only the named lane is produced; the same register read supplies
         * the pass-through lanes, which is everything but that one. */
        if (!sel) {
            return;             /* the selector was refused; state nothing */
        }
        dst_lane = sel;
        src_lane = full & ~sel;
        parallel = false;
        break;
    case QEMU_PLUGIN_DF_VEC_KIND_EXTRACT:
        if (!sel) {
            return;
        }
        src_lane = sel;
        dst_lane = sel;
        parallel = false;
        break;
    case QEMU_PLUGIN_DF_VEC_KIND_BROADCAST:
        /* Every lane of the write takes one value.  When the source has
         * lanes, the named one is where it was read from. */
        dst_lane = full;
        src_lane = sel ? sel : full;
        parallel = false;
        break;
    default:
        return;                 /* KIND_NONE: no lane statement to seat */
    }

    f->lane_mask_kind = LANE_MASK_KIND_STATIC;
    f->lane_parallel  = parallel;
    f->lane_bytes     = (uint8_t)(lane_bytes > 255 ? 0 : lane_bytes);

    bool any = false;

    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        if (reg_is_vector_wide(0, f->src_regs[i], st->vec_oprsz)) {
            f->src_lane_mask[i] = src_lane;
            any = true;
        }
    }
    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        if (reg_is_vector_wide(0, f->dst_regs[d], st->vec_oprsz)) {
            f->dst_lane_mask[d] = dst_lane;
            any = true;
        }
    }
    /*
     * has_vec_lanes is decided HERE and not by the seating, because making it
     * depend on a non-empty destination list retracts the vector flag from
     * every structured load whose destination list QEMU leaves empty.  The
     * shape was stated; the flag records that, whatever the lists hold.
     */
    f->has_vec_lanes = true;
    if (!any) {
        f->lane_mask_kind = LANE_MASK_KIND_STATIC;
    }
}

} /* namespace */

const QdepCounters *qdep_counters(void)
{
    return &g_qdep;
}

unsigned qdep_selfcheck(void)
{
    return cst_vocabulary_selfcheck() + cst_regmap_selfcheck();
}

QdepRefusal qdep_apply(const struct qemu_plugin_tb *tb, size_t idx,
                       uint64_t pc, InsnFields *out, InsnRegNames *out_names)
{
    (void)pc;

    /* CONTRACT, unchanged from the walk this replaces: @out is a freshly
     * reset InsnFieldsScratch::f, spans wired to zeroed full-size backing. */
    g_assert(out->src_regs && out->dst_dep_mask);
    g_assert(!out_names || out_names->src_qemu_reg_keys);

    qemu_plugin_dataflow_status st;

    /* No load slot is known until the memop walk below assigns them; a stale
     * map from the previous instruction must never be readable. */
    memset(tls_load_slot, 0xff, sizeof(tls_load_slot));

    memset(&st, 0, sizeof(st));
    st.struct_size = sizeof(st);
    if (!qemu_plugin_insn_dataflow_status(tb, idx, &st)) {
        g_qdep.no_status++;
        return QDEP_NO_STATUS;
    }
    if (qemu_plugin_insn_undecoded(tb, idx)) {
        /* The bytes reached no rule.  That is a different answer from a rule
         * with nothing to say, and the caller must be able to tell them
         * apart. */
        g_qdep.no_rule++;
        return QDEP_NO_RULE;
    }
    if (st.incomplete) {
        /* QEMU could not record this instruction whole, so the set accessors
         * refuse to hand anything back.  Publishing a partial set would be a
         * dependency missed, which is the failure direction the ABI is built
         * to prevent. */
        g_qdep.incomplete++;
        return QDEP_INCOMPLETE;
    }

    /* ---- classification ------------------------------------------------ */

    const char *word = qemu_plugin_insn_decode_word(tb, idx);
    uint8_t opcode = GEN_OP_UNKNOWN, branch_type = BRANCH_NONE;

    if (!cst_vocabulary_lookup(word, &opcode, &branch_type)) {
        /*
         * Two conditions reach here and they are not the same.  A rule that
         * states NO word has nothing generic to say about itself -- SYS on
         * aarch64 dispatches over four different things, and one word would
         * be wrong for three of them -- and the honest answer is the unknown
         * opcode with the instruction still admitted.  A word this build
         * cannot READ means the emulator and the plugin were built from
         * different vocabularies, and publishing a plausible classification
         * for that hides a skewed build.
         */
        if (word) {
            g_qdep.unknown_word++;
            return QDEP_UNKNOWN_WORD;
        }
        opcode = GEN_OP_UNKNOWN;
        branch_type = BRANCH_NONE;
    }
    out->opcode = opcode;
    out->branch_type = branch_type;

    /*
     * Conditional-ness is the ops', not the word's.  The rule says what kind
     * of transfer this is; whether the translator emitted one edge or two is
     * what a predictor needs, and _X_MULTI is exactly that fact.  A word that
     * names a conditional class keeps it when the ops agree.
     */
    if (branch_type == BRANCH_COND_DIRECT) {
        out->branch_conditional = true;
    }
    if ((st.xfer & QEMU_PLUGIN_DF_X_MULTI) && branch_type != BRANCH_NONE &&
        branch_type != BRANCH_RETURN) {
        out->branch_conditional = true;
    }

    if (st.properties & QEMU_PLUGIN_DF_P_ATOMIC) {
        out->is_atomic = true;
    }

    /* ---- the encoded immediate ----------------------------------------- */

    for (unsigned i = 0; i < st.n_immediates; i++) {
        uint64_t value = 0;
        uint32_t role = 0;

        if (!qemu_plugin_insn_immediate(tb, idx, i, &value, &role)) {
            continue;
        }
        if (!out->has_immediate) {
            out->has_immediate = true;
            out->immediate = (int64_t)value;
        }
        if (role == QEMU_PLUGIN_DF_IMM_OPERAND) {
            /* The operand role wins over a displacement when both are
             * stated: the wire's single slot is the value the instruction
             * computes with, and a displacement is an address term the
             * address family already carries. */
            out->immediate = (int64_t)value;
            break;
        }
    }

    /* ---- the register lists -------------------------------------------- */

    unsigned nw = read_set([&](uint64_t *w, unsigned n) {
        return qemu_plugin_insn_reg_reads(tb, idx, w, n);
    });

    seat_set_as_src(out, out_names, nw);

    nw = read_set([&](uint64_t *w, unsigned n) {
        return qemu_plugin_insn_reg_writes(tb, idx, w, n);
    });
    /* The write set has to be captured before it is walked: the same buffer
     * serves the per-destination provenance queries below. */
    std::vector<uint8_t> dst_bits_reg;
    std::vector<unsigned> dst_bits;

    for (unsigned w = 0; w < nw; w++) {
        uint64_t word = tls_set.data()[w];

        while (word) {
            unsigned b = (unsigned)__builtin_ctzll(word);

            word &= word - 1;
            dst_bits.push_back(w * 64 + b);
        }
    }
    for (unsigned bit : dst_bits) {
        uint8_t reg = REG_NONE;

        if (classify_bit(bit, &reg) == BIT_REG) {
            dst_bits_reg.push_back(reg);
        } else {
            dst_bits_reg.push_back(REG_NONE);
        }
    }

    /*
     * The env-resident state no TCG global names: x86's vector file and x87
     * stack, ARM's Z registers, every FP status word.  They reach a consumer
     * only through the field rows, and a target that declared its layout
     * resolves each range to the register that contains it.
     */
    std::vector<qemu_plugin_dataflow_field> fields;

    if (st.n_fields) {
        fields.resize(st.n_fields);
        for (auto &fl : fields) {
            fl.struct_size = sizeof(fl);
        }
        unsigned got = qemu_plugin_insn_fields(tb, idx, fields.data(),
                                               (unsigned)fields.size());
        if (got == QEMU_PLUGIN_DF_INCOMPLETE || got > fields.size()) {
            fields.clear();
        } else {
            fields.resize(got);
        }
    }
    for (const auto &fl : fields) {
        const char *name = qemu_plugin_dataflow_field_reg(fl.env_offset,
                                                          fl.size);
        uint8_t reg = REG_NONE;

        if (!name) {
            g_qdep.unnamed_ranges++;
            continue;
        }
        if (!cst_regmap_lookup((unsigned)trace_isa, name, &reg)) {
            g_qdep.unmapped_names++;
            continue;
        }
        if (reg == REG_NONE) {
            continue;
        }
        if (fl.dir & QEMU_PLUGIN_DF_RD) {
            seat_src(out, out_names, reg);
        }
        if (fl.dir & QEMU_PLUGIN_DF_WR) {
            seat_dst(out, out_names, reg);
        }
    }

    /* Destinations seat AFTER the whole read side, so a dependency mask can
     * be expressed over inputs that are all in place. */
    for (uint8_t reg : dst_bits_reg) {
        seat_dst(out, out_names, reg);
    }

    /* ---- the memory operands ------------------------------------------- */

    std::vector<qemu_plugin_dataflow_memop> memops;

    if (st.n_memops) {
        memops.resize(st.n_memops);
        for (auto &m : memops) {
            m.struct_size = sizeof(m);
        }
        unsigned got = qemu_plugin_insn_memops(tb, idx, memops.data(),
                                               (unsigned)memops.size());
        if (got == QEMU_PLUGIN_DF_INCOMPLETE || got > memops.size()) {
            memops.clear();
        } else {
            memops.resize(got);
        }
    }

    /* Per-access, in the order the instruction performs them; the wire keeps
     * loads and stores in two families and each keeps its own order. */
    std::vector<unsigned> load_rows, store_rows;

    memset(tls_load_slot, 0xff, sizeof(tls_load_slot));
    for (unsigned m = 0; m < memops.size(); m++) {
        if (memops[m].dir & QEMU_PLUGIN_DF_RD) {
            if (out->max_dep_loads < MAX_LOADS) {
                if (m < QEMU_PLUGIN_DF_MAX_MEMOPS) {
                    tls_load_slot[m] = (uint8_t)load_rows.size();
                }
                out->max_dep_loads++;
                load_rows.push_back(m);
                out->has_addr_deps = true;
            } else {
                g_qdep.dropped_loads++;
            }
        }
        if (memops[m].dir & QEMU_PLUGIN_DF_WR) {
            if (out->max_dep_stores < MAX_STORES) {
                out->max_dep_stores++;
                store_rows.push_back(m);
                out->has_addr_deps = true;
            } else {
                g_qdep.dropped_stores++;
            }
        }
    }

    for (unsigned k = 0; k < load_rows.size(); k++) {
        unsigned n = read_set([&](uint64_t *w, unsigned nn) {
            return qemu_plugin_insn_memop_addr_prov(tb, idx, load_rows[k],
                                                    w, nn);
        });
        out->load_addr_dep_mask[k] = prov_to_addr_mask(out, n);
    }
    for (unsigned k = 0; k < store_rows.size(); k++) {
        unsigned n = read_set([&](uint64_t *w, unsigned nn) {
            return qemu_plugin_insn_memop_addr_prov(tb, idx, store_rows[k],
                                                    w, nn);
        });
        out->store_addr_dep_mask[k] = prov_to_addr_mask(out, n);

        n = read_set([&](uint64_t *w, unsigned nn) {
            return qemu_plugin_insn_memop_data_prov(tb, idx, store_rows[k],
                                                    w, nn);
        });
        out->store_data_dep_mask[k] = prov_to_mask(out, n);
    }

    /* ---- the intra-instruction register dataflow ------------------------ */

    /*
     * Where each written register's value came from.  This is per DESTINATION
     * and is strictly finer than a per-opcode refiner: it is the set QEMU's
     * own ops read to produce that register, not a rule about instructions
     * that look like this one.
     *
     * The block exists iff at least one destination has a provenance QEMU
     * stated.  An EMPTY provenance is a fact and not an absence -- it says
     * the value came from nothing, which is what a zeroing idiom does -- so a
     * destination whose set is empty still publishes a zero mask, and the
     * block is what makes that readable as "no inputs" rather than as the
     * consumer's all-to-all default.
     */
    bool any_prov = false;

    for (unsigned k = 0; k < dst_bits.size(); k++) {
        if (dst_bits_reg[k] == REG_NONE) {
            continue;
        }
        uint8_t slot = UINT8_MAX;

        for (uint8_t i = 0; i < out->n_dst_regs; i++) {
            if (out->dst_regs[i] == dst_bits_reg[k]) {
                slot = i;
                break;
            }
        }
        if (slot == UINT8_MAX) {
            continue;
        }
        unsigned n = read_set([&](uint64_t *w, unsigned nn) {
            return qemu_plugin_insn_write_prov(tb, idx, dst_bits[k], w, nn);
        });
        /*
         * A destination reached through two provenance bits -- the same
         * architectural register QEMU represents in more than one field --
         * accumulates rather than overwrites.  Overwriting would publish the
         * last field's inputs as the whole register's.
         */
        out->dst_dep_mask[slot] |= prov_to_mask(out, n);
        any_prov = true;
    }
    if (any_prov || out->n_dst_regs || out->max_dep_stores) {
        out->has_reg_deps = true;
    }

    /* ---- the lane shape and the self-loop unit -------------------------- */

    seat_lanes(out, &st);

    if (st.self_loop_memops) {
        unsigned unit = st.self_loop_memops;

        if (unit > 255) {
            unit = 255;
        }
        out->rep_memops_per_iter = (uint8_t)unit;
        /*
         * A self-looping instruction is a tracer-defined self-loop branch:
         * the chain assembler ends the true BB and restarts at the same PC,
         * so the trace identifies the loop structurally instead of carrying
         * one block with a variable memop count.  Conditional because the
         * loop exits on a register value -- an architectural count for the
         * iterated family, a size register for the family that has none --
         * so a zero-length transfer runs the block once and falls through.
         *
         * A word that already named a transfer wins: the rule knows what the
         * instruction is, and a REP-prefixed branch is still a branch.
         */
        if (out->branch_type == BRANCH_NONE) {
            out->branch_type = BRANCH_REP;
        }
        out->branch_conditional = true;
    }

    g_qdep.seated++;
    return QDEP_OK;
}

/*
 * The address an instruction NAMES and the emulation computes nothing for.
 *
 * A prefetch or a cache-maintenance operation lowers to a NOP or a bare block
 * exit, so its memop row exists only because the decode site stated it, and
 * there are no ops to read the address off.  The components are therefore
 * carried across the ABI -- the registers, the left shift applied to each,
 * any narrowing extend, and the displacement -- and this turns them into the
 * per-instruction descriptor the exec-time callback evaluates.
 *
 * WHY THE SHIFT IS NOT OPTIONAL.  `prefetcht0 0x20(%rax,%rbx,8)` and the
 * same instruction at scale 1 have the same registers and the same
 * displacement and name addresses 0x77 apart.  A descriptor without the shift
 * says which registers an address came from while leaving its reader unable
 * to say which address.
 *
 * WHAT IS REFUSED.  The descriptor evaluates base + (index << shift) + disp,
 * and has no way to express a narrowing extend of a part.  An address missing
 * one term is a DIFFERENT address, not an approximate one, so a row carrying
 * an extend is withheld whole and counted rather than published short.  Same
 * for a third addressing part, which the descriptor cannot hold either.
 */
bool qdep_synthetic_ea(const struct qemu_plugin_tb *tb, size_t idx,
                       uint8_t opcode, SyntheticEAInfo *out)
{
    memset(out, 0, sizeof(*out));
    if (opcode != GEN_OP_PREFETCH && opcode != GEN_OP_CACHE_FLUSH &&
        opcode != GEN_OP_TLB_FLUSH) {
        return false;
    }

    qemu_plugin_dataflow_status st;

    memset(&st, 0, sizeof(st));
    st.struct_size = sizeof(st);
    if (!qemu_plugin_insn_dataflow_status(tb, idx, &st) || !st.n_synth_ea) {
        return false;
    }

    std::vector<qemu_plugin_dataflow_ea> eas(st.n_synth_ea);

    for (auto &e : eas) {
        e.struct_size = sizeof(e);
    }
    unsigned got = qemu_plugin_insn_synthetic_eas(tb, idx, eas.data(),
                                                  (unsigned)eas.size());

    if (got == QEMU_PLUGIN_DF_INCOMPLETE || got == 0 || got > eas.size()) {
        return false;
    }

    const qemu_plugin_dataflow_ea &ea = eas[0];

    if (ea.n_parts > 2) {
        g_qdep.synth_ea_refused++;
        return false;
    }
    for (unsigned p = 0; p < ea.n_parts; p++) {
        if (ea.part_ext[p] != QEMU_PLUGIN_DF_EA_EXT_NONE) {
            g_qdep.synth_ea_refused++;
            return false;
        }
    }

    const QemuRegKey *keys[2] = { nullptr, nullptr };
    uint8_t shifts[2] = { 0, 0 };
    unsigned n = 0;

    for (unsigned p = 0; p < ea.n_parts && n < 2; p++) {
        uint8_t reg = REG_NONE;

        if (classify_bit(ea.part_reg[p], &reg) != BIT_REG) {
            g_qdep.synth_ea_refused++;
            return false;
        }
        keys[n] = qemu_reg_for_generic_id(reg);
        if (!keys[n]) {
            /* The register is nameable on the wire and has no GDB handle to
             * read a VALUE from, so the address cannot be evaluated. */
            g_qdep.synth_ea_refused++;
            return false;
        }
        shifts[n] = ea.part_shift[p];
        n++;
    }

    /*
     * The unshifted part is the base and the shifted one the index, because
     * that is the only asymmetry the descriptor has.  With neither shifted the
     * order is the statement's, which is the order the decode site named them
     * in.
     */
    unsigned base_i = 0, index_i = 1;

    if (n == 2 && shifts[0] != 0 && shifts[1] == 0) {
        base_i = 1;
        index_i = 0;
    }
    if (n >= 1) {
        out->base_key = keys[base_i];
    }
    if (n == 2) {
        out->index_key = keys[index_i];
        if (shifts[index_i]) {
            out->shift_amount = shifts[index_i];
            out->shift_type = 1;        /* a left shift; see the evaluator */
        }
    }
    if (n == 1 && shifts[base_i]) {
        /* One part, and it is shifted: it is the index, with no base. */
        out->index_key = out->base_key;
        out->base_key = nullptr;
        out->shift_amount = shifts[base_i];
        out->shift_type = 1;
    }
    out->scale = 1;
    out->disp = ea.disp;
    out->has_addr = 1;
    g_qdep.synth_ea_seated++;
    return true;
}
