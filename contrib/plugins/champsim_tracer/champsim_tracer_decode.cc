/*
 * Wrong-Path Tracing Plugin — Capstone detail → ISA-agnostic decode.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <array>
#include <string.h>
#include <stdlib.h>

#include "champsim_tracer.h"
#include "champsim_tracer_reg_handle_cache.h"
#include "champsim_tracer_stats.h"

/*
 * Direct register ID lookup: O(1) array index into the per-ISA
 * RegClassification table.
 */
static const RegClassification *lookup_reg_class(uint16_t cap_id)
{
    if (cap_id == 0 || cap_id >= active_reg_table_size) {
        return nullptr;
    }
    return &active_reg_table[cap_id];
}

static inline bool qemu_reg_key_valid(const QemuRegKey *key)
{
    return key && key->name;
}

/*
 * Reverse index: GenericRegId → QemuRegKey for the active ISA.
 * Built once at plugin-install time by walking active_reg_table; used
 * to recover the per-element QemuRegKey for multi-reg encodings (RISC-V
 * V*M* tuples, future register-group additions on other ISAs) so their
 * source-register value snapshots can read each constituent register
 * via the GDB feature/name pair.  Without this, multi-reg encodings
 * would land in src_regs[]/dst_regs[] correctly but their values
 * wouldn't be captured under regdata=1 because the multi-reg path
 * passed nullptr for the QemuRegKey.
 */
static QemuRegKey g_qemu_reg_by_gen[REG_ID_COUNT];

void build_qemu_reg_reverse_index(void)
{
    for (unsigned i = 0; i < REG_ID_COUNT; i++) {
        g_qemu_reg_by_gen[i] = QemuRegKey{};
    }
    if (!active_reg_table || active_reg_table_size == 0) {
        return;
    }
    for (unsigned i = 0; i < active_reg_table_size; i++) {
        const RegClassification *rc = &active_reg_table[i];
        if (rc->n_regs != 0) {
            /* Multi-reg rows don't carry a singleton QemuRegKey
             * themselves — their constituent generic IDs are
             * supplied by other rows that have the matching
             * .reg_id with .qemu_reg set. */
            continue;
        }
        if (!qemu_reg_key_valid(&rc->qemu_reg)) {
            continue;
        }
        if (rc->reg_id >= REG_ID_COUNT) {
            continue;
        }
        /* First singleton row wins — multiple Capstone aliases (e.g.
         * x86 AH/AL/AX/EAX/RAX all → REG_GPR0) share one underlying
         * QemuRegKey, and any of them is correct for value reads. */
        if (!qemu_reg_key_valid(&g_qemu_reg_by_gen[rc->reg_id])) {
            g_qemu_reg_by_gen[rc->reg_id] = rc->qemu_reg;
        }
    }
}

static inline const QemuRegKey *qemu_reg_for_generic(uint8_t gen_id)
{
    if (gen_id >= REG_ID_COUNT) {
        return nullptr;
    }
    const QemuRegKey *k = &g_qemu_reg_by_gen[gen_id];
    return qemu_reg_key_valid(k) ? k : nullptr;
}

void capture_initial_regfile(unsigned int cpu_index,
                             std::vector<InitialRegSnap> *out)
{
    if (!out) {
        return;
    }
    out->clear();
    g_autoptr(GByteArray) buf = g_byte_array_new();
    for (unsigned i = 0; i < REG_ID_COUNT; i++) {
        const QemuRegKey *key = qemu_reg_for_generic((uint8_t)i);
        if (!key) {
            continue;
        }
        InitialRegSnap snap;
        snap.gen_id = (uint8_t)i;
        snap.width_bytes = 0;
        memset(snap.bytes, 0, sizeof(snap.bytes));

        /* No vCPU context yet (install-time start_trace_segment): pin
         * the generic ID without a live value.  Decoder still gets the
         * (gen_id, name) mapping, just with width_bytes=0. */
        if (cpu_index != (unsigned int)-1) {
            struct qemu_plugin_register *handle =
                g_reg_handle_cache.lookup(cpu_index, key);
            if (handle) {
                g_byte_array_set_size(buf, 0);
                int n = qemu_plugin_read_register(handle, buf);
                if (n > 0) {
                    size_t w = (size_t)n;
                    if (w > CST_MAX_WIDE_BYTES) {
                        w = CST_MAX_WIDE_BYTES;
                    }
                    snap.width_bytes = (uint8_t)w;
                    memcpy(snap.bytes, buf->data, w);
                }
            }
        }
        out->push_back(snap);
    }
}

/*
 * Returns the src_regs[] slot that ends up holding @reg_id (either
 * the existing slot if the reg was already present — dedup — or the
 * newly-allocated slot), or UINT8_MAX when the reg was skipped
 * (REG_NONE / table full).  The slot index lets callers feed
 * structural bookkeeping like HAS_ADDR address-dep masks.
 */
static inline uint8_t add_src_reg(InsnFields *f, InsnRegNames *refs,
                                  uint8_t reg_id, const QemuRegKey *qemu_reg)
{
    if (reg_id == REG_NONE || f->n_src_regs >= MAX_SRC_REGS) {
        return UINT8_MAX;
    }
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        if (f->src_regs[i] == reg_id) {
            if (refs && !refs->src_qemu_reg_keys[i] &&
                qemu_reg_key_valid(qemu_reg)) {
                refs->src_qemu_reg_keys[i] = qemu_reg;
            }
            return i;
        }
    }
    uint8_t slot = f->n_src_regs++;
    f->src_regs[slot] = reg_id;
    if (refs && qemu_reg_key_valid(qemu_reg)) {
        refs->src_qemu_reg_keys[slot] = qemu_reg;
    }
    return slot;
}

static inline void add_dst_reg(InsnFields *f, InsnRegNames *refs,
                               uint8_t reg_id, const QemuRegKey *qemu_reg)
{
    if (reg_id == REG_NONE || f->n_dst_regs >= MAX_DST_REGS) {
        return;
    }
    for (uint8_t i = 0; i < f->n_dst_regs; i++) {
        if (f->dst_regs[i] == reg_id) {
            if (refs && !refs->dst_qemu_reg_keys[i] &&
                qemu_reg_key_valid(qemu_reg)) {
                refs->dst_qemu_reg_keys[i] = qemu_reg;
            }
            return;
        }
    }
    uint8_t slot = f->n_dst_regs++;
    f->dst_regs[slot] = reg_id;
    if (refs && qemu_reg_key_valid(qemu_reg)) {
        refs->dst_qemu_reg_keys[slot] = qemu_reg;
    }
}

/*
 * For pointer-stable QemuRegKey identity per logical register, every
 * call into add_{src,dst}_reg routes through qemu_reg_for_generic(),
 * which returns the singleton pointer in g_qemu_reg_by_gen[].  The
 * RegClassification's own .qemu_reg may live at a different address
 * (active_reg_table backing) but holds an identical (feature, name)
 * pair, since g_qemu_reg_by_gen[gen] was populated from one such row.
 */
/*
 * Returns a mask of src_regs[] slots that ended up holding the
 * registers behind @cap_id.  A single Capstone reg id can expand
 * into multiple aliases (rc->n_regs > 0), each landing in its own
 * slot; the caller may need any/all of those slots when building
 * structural address-dep masks for HAS_ADDR.
 */
static inline uint64_t add_src_cap_reg(InsnFields *f, InsnRegNames *refs,
                                       uint16_t cap_id)
{
    const RegClassification *rc = lookup_reg_class(cap_id);
    if (!rc) {
        return 0;
    }
    uint64_t mask = 0;
    if (rc->n_regs) {
        for (uint8_t i = 0; i < rc->n_regs && i < MAX_REG_ALIASES; i++) {
            uint8_t gen = rc->regs[i];
            uint8_t slot = add_src_reg(f, refs, gen,
                                       qemu_reg_for_generic(gen));
            if (slot < MAX_SRC_REGS) {
                mask |= (uint64_t)1 << slot;
            }
        }
        return mask;
    }
    uint8_t slot = add_src_reg(f, refs, rc->reg_id,
                               qemu_reg_for_generic(rc->reg_id));
    if (slot < MAX_SRC_REGS) {
        mask |= (uint64_t)1 << slot;
    }
    return mask;
}

static inline void add_dst_cap_reg(InsnFields *f, InsnRegNames *refs,
                                   uint16_t cap_id)
{
    const RegClassification *rc = lookup_reg_class(cap_id);
    if (!rc) {
        return;
    }
    if (rc->n_regs) {
        for (uint8_t i = 0; i < rc->n_regs && i < MAX_REG_ALIASES; i++) {
            uint8_t gen = rc->regs[i];
            add_dst_reg(f, refs, gen, qemu_reg_for_generic(gen));
        }
        return;
    }
    add_dst_reg(f, refs, rc->reg_id, qemu_reg_for_generic(rc->reg_id));
    /*
     * Mark this insn as an integer-flags writer so the wire-format
     * encoder can emit a side-channel CST_FID_METAFLAGS record with
     * the canonical Z/N/C/V/P byte derived from the architectural
     * REG_FLAGS dst snap.  Gated on the per-ISA RegClassification's
     * .is_int_flags marker — set only on x86 EFLAGS / AArch64 NZCV
     * rows; never on x86 FPSW, mips DSP-flag co-processor regs, or
     * any ISA without an integer flags reg.
     */
    if (rc->is_int_flags) {
        f->writes_int_flags = true;
    }
}

/* OR @lane into every src_regs[] slot the Capstone reg @cap_id maps
 * to.  Used by the per-operand vector lane-mask assignment so a
 * scalar (non-vec) operand never gets a lane mask (its slots stay
 * 0) — only the vec-register operands the caller iterates. */
static void assign_src_lane(InsnFields *f, uint16_t cap_id, uint64_t lane)
{
    const RegClassification *rc = lookup_reg_class(cap_id);
    if (!rc) return;
    auto apply = [&](uint8_t gen) {
        for (uint8_t i = 0; i < f->n_src_regs; i++) {
            if (f->src_regs[i] == gen) f->src_lane_mask[i] |= lane;
        }
    };
    if (rc->n_regs) {
        for (uint8_t i = 0; i < rc->n_regs && i < MAX_REG_ALIASES; i++) {
            apply(rc->regs[i]);
        }
    } else {
        apply(rc->reg_id);
    }
}
static void assign_dst_lane(InsnFields *f, uint16_t cap_id, uint64_t lane)
{
    const RegClassification *rc = lookup_reg_class(cap_id);
    if (!rc) return;
    auto apply = [&](uint8_t gen) {
        for (uint8_t d = 0; d < f->n_dst_regs; d++) {
            if (f->dst_regs[d] == gen) f->dst_lane_mask[d] |= lane;
        }
    };
    if (rc->n_regs) {
        for (uint8_t i = 0; i < rc->n_regs && i < MAX_REG_ALIASES; i++) {
            apply(rc->regs[i]);
        }
    } else {
        apply(rc->reg_id);
    }
}

static void warn_unknown_instruction(uint64_t pc, const char *reason,
                                     const char *mnem, const char *disas)
{
    g_mutex_lock(&unknown_warn_lock);
    g_stats.unknown_insn_warnings++;

    /* Surface the first unknown instruction on stderr so the run
     * isn't silently missing classifications, then go quiet (the
     * per-insn detail keeps flowing to the .unknown_warnings.log
     * file, and the exit summary's "Unknown-instruction warnings"
     * line is the running total). */
    static bool warned_once = false;
    if (!warned_once) {
        warned_once = true;
        fprintf(stderr,
                "champsim_tracer: unknown instruction at pc=0x%" PRIx64
                " (mnemonic=%s) — traced with opcode=GEN_OP_UNKNOWN.\n"
                "  Further occurrences are silent; see the exit-summary "
                "count and %s for the full list.  Run "
                "champsim_tracer_mnemonic_audit.py on a sample trace to "
                "find mnemonics needing classification rows.\n",
                pc, mnem ? mnem : "<none>",
                unknown_warn_file ? "the .unknown_warnings.log file"
                                  : "(no warn-log file open)");
    }

    if (unknown_warn_file) {
        fprintf(unknown_warn_file,
                "pc=0x%" PRIx64 " isa=%u reason=%s mnemonic=%s disas=\"%s\"\n",
                pc, (unsigned int)trace_isa, reason,
                mnem ? mnem : "<none>", disas ? disas : "");
        fflush(unknown_warn_file);
    }
    g_mutex_unlock(&unknown_warn_lock);
}

/*
 * Classify an instruction via direct insn_id array lookup (O(1)).
 * Returns the table row (or nullptr if out of range / no table) so
 * callers can also access the optional .refine callback.
 */
static const InsnClassification *classify_insn_id(
    const qemu_plugin_insn_info *info,
    uint8_t *opcode, uint8_t *branch_type, uint16_t *flags)
{
    uint32_t id = info->insn_id;

    if (active_insn_table && id < active_insn_table_size) {
        const InsnClassification *c = &active_insn_table[id];
        *opcode = c->opcode;
        *branch_type = c->branch_type;
        *flags = c->flags;
        return c;
    }

    *opcode = GEN_OP_UNKNOWN;
    *branch_type = BRANCH_NONE;
    *flags = MF_NONE;
    return nullptr;
}

/*
 * Decode structured Capstone detail into ISA-agnostic InsnFields.
 * Operand roles, implicit registers, and prefixes come directly from
 * Capstone's structured output.  Opcode and branch type come from the
 * mnemonic classification table.
 */
void decode_detail_to_generic(uint64_t pc,
                              const qemu_plugin_insn_info *info,
                              InsnFields *out,
                              InsnRegNames *out_names)
{
    memset(out, 0, sizeof(*out));
    if (out_names) {
        memset(out_names, 0, sizeof(*out_names));
    }

    if (!info || !info->mnemonic[0]) {
        return;
    }

    uint16_t flags = MF_NONE;
    const InsnClassification *cls =
        classify_insn_id(info, &out->opcode, &out->branch_type, &flags);

    if (info->has_lock || (flags & MF_ATOMIC)) {
        out->is_atomic = true;
    }

    if (out->opcode == GEN_OP_UNKNOWN) {
        char disas_buf[256];
        g_snprintf(disas_buf, sizeof(disas_buf), "%s %s",
                   info->mnemonic, info->op_str);
        warn_unknown_instruction(pc, "unknown_mnemonic",
                                 info->mnemonic, disas_buf);
        return;
    }

    if (flags & MF_CONDITIONAL) {
        out->branch_conditional = true;
    }
    if (out->branch_type == BRANCH_COND_DIRECT) {
        out->branch_conditional = true;
    }

    /*
     * x86 REP/REPNZ prefix promotes the instruction to a self-looping
     * branch.  Each iteration of the architectural REP loop is a
     * tracer-defined true-BB: the chain assembler ends the BB here
     * and starts the next one at the same PC, so the trace
     * structurally identifies the loop instead of treating it as one
     * BB with a variable memop count.
     *
     * Branch type is BRANCH_REP — distinct from BRANCH_COND_DIRECT —
     * so consumer simulators can tell at template-parse time that
     * this is a self-loop (target=self-PC, fall-through=next-PC)
     * rather than a generic conditional direct branch.  Predictors
     * modelling REP don't need to bother with target diversity; the
     * REP-specific branch type makes the self-loop semantics
     * obvious in the trace.
     *
     * Capstone reports the prefix via info->has_rep on x86 (returns
     * false on every other ISA, so this is a no-op for those).  The
     * branch is conditional (the loop exits when ECX == 0 or when
     * the REPZ/REPNZ comparison breaks).
     *
     * rep_{loads,stores}_per_iter capture how many memops the insn
     * issues per architectural REP iteration.  Derived by counting
     * Capstone MEM operands' access flags, so the result is
     * mnemonic-agnostic:
     *   - MOVS  → 1 load + 1 store
     *   - CMPS  → 2 loads
     *   - STOS  → 1 store
     *   - LODS  → 1 load
     *   - SCAS  → 1 load
     *   - INS   → 1 store (port in → mem)
     *   - OUTS  → 1 load (mem out → port)
     * These counts let the body emitter fan a single TB-exec's
     * memop stream into N iteration entries.
     */
    if (info->has_rep) {
        out->branch_type        = BRANCH_REP;
        out->branch_conditional = true;
        for (unsigned i = 0; i < info->n_operands; i++) {
            const qemu_plugin_operand *op = &info->operands[i];
            if (op->type != QEMU_PLUGIN_OP_MEM) {
                continue;
            }
            if (op->access & QEMU_PLUGIN_OP_ACC_READ) {
                out->rep_loads_per_iter++;
            }
            if (op->access & QEMU_PLUGIN_OP_ACC_WRITE) {
                out->rep_stores_per_iter++;
            }
        }
    }

    /*
     * Operand processing: use Capstone access flags where available
     * (x86/AArch64); otherwise fall back to an opcode-indexed lookup
     * where the first register operand is the destination for most
     * opcodes (not stores/cmp/branches/ret/syscall/nop).
     */
    static const auto opcode_first_is_dst = []() {
        std::array<bool, GEN_OP_COUNT> a{};
        a.fill(true);
        a[GEN_OP_STORE]   = false;
        a[GEN_OP_CMP]     = false;
        a[GEN_OP_BRANCH]  = false;
        a[GEN_OP_RET]     = false;
        a[GEN_OP_SYSCALL] = false;
        a[GEN_OP_NOP]     = false;
        return a;
    }();

    bool have_access_info = false;
    for (uint8_t i = 0; i < info->n_operands && !have_access_info; i++) {
        if (info->operands[i].access != 0) {
            have_access_info = true;
        }
    }

    bool first_is_dst = opcode_first_is_dst[out->opcode];
    bool seen_first_reg = false;
    for (uint8_t i = 0; i < info->n_operands; i++) {
        const qemu_plugin_operand *op = &info->operands[i];

        switch (op->type) {
        case QEMU_PLUGIN_OP_REG: {
            if (have_access_info) {
                if (op->access & QEMU_PLUGIN_OP_ACC_READ) {
                    add_src_cap_reg(out, out_names, op->reg_id);
                }
                if (op->access & QEMU_PLUGIN_OP_ACC_WRITE) {
                    add_dst_cap_reg(out, out_names, op->reg_id);
                }
            } else {
                if (first_is_dst && !seen_first_reg) {
                    add_dst_cap_reg(out, out_names, op->reg_id);
                } else {
                    add_src_cap_reg(out, out_names, op->reg_id);
                }
                seen_first_reg = true;
            }
            break;
        }
        case QEMU_PLUGIN_OP_IMM:
            if (!out->has_immediate) {
                out->has_immediate = true;
                out->immediate = op->imm;
            }
            break;
        case QEMU_PLUGIN_OP_MEM: {
            /*
             * Track which src_regs[] slots this MEM operand's
             * addressing-mode regs (base + index) land in.  The
             * resulting mask is used to populate
             * load_addr_dep_mask[k] / store_addr_dep_mask[k] —
             * structural per-memop "when can this fire?" data the
             * consumer needs to schedule loads/stores precisely
             * (avoid waiting on dst-as-src for RMW forms, etc.).
             *
             * add_src_cap_reg returns a mask of slots taken (after
             * dedup), which we OR together across base + index.
             */
            uint64_t addr_mask = 0;
            addr_mask |= add_src_cap_reg(out, out_names, op->reg_id);
            addr_mask |= add_src_cap_reg(out, out_names, op->index_id);

            /*
             * Count this mem-op against the template-static MAX
             * load/store totals.  These bound the dep-mask bit
             * layout: loads occupy mask bits [n_src_regs,
             * n_src_regs + max_dep_loads) and stores feed into the
             * store_data_dep_mask[] array of length max_dep_stores.
             *
             * Runtime per-iteration counts can be smaller (e.g. a
             * conditional load that didn't fire) and ride on
             * CST_FID_N_LOADS / CST_FID_N_STORES, but never larger.
             *
             * Some ops (LEA, prefetch hints) carry a MEM operand
             * whose access flags lack both READ and WRITE — those
             * never issue a real memop and don't count.
             */
            if (op->access & QEMU_PLUGIN_OP_ACC_READ) {
                if (out->max_dep_loads < MAX_LOADS) {
                    out->load_addr_dep_mask[out->max_dep_loads] = addr_mask;
                    out->max_dep_loads++;
                    out->has_addr_deps = true;
                }
            }
            if (op->access & QEMU_PLUGIN_OP_ACC_WRITE) {
                if (out->max_dep_stores < MAX_STORES) {
                    out->store_addr_dep_mask[out->max_dep_stores] = addr_mask;
                    out->max_dep_stores++;
                    out->has_addr_deps = true;
                }
            }
            break;
        }
        default:
            break;
        }
    }

    if (isa_properties[trace_isa].include_implicit_regs) {
        for (uint8_t i = 0; i < info->n_regs_read; i++) {
            add_src_cap_reg(out, out_names, info->regs_read_id[i]);
        }
        for (uint8_t i = 0; i < info->n_regs_write; i++) {
            add_dst_cap_reg(out, out_names, info->regs_write_id[i]);
        }
    }

    /*
     * Optional ISA-specific post-classification refinement.  Each row
     * in the per-ISA mnemonic table may attach a .refine callback that
     * fixes up opcode/branch_type/etc. based on the operand-walk
    * result above.  Used for cases where one Capstone insn_id covers
    * multiple distinct operand encodings or target forms.
     */
    if (cls && cls->refine) {
        cls->refine(info, out);
    }

    /*
     * Optional dependency refinement.  Reads the refined InsnFields
     * and writes dst_dep_mask[] / store_data_dep_mask[].  Rows that
     * leave .dep_refine NULL emit no HAS_REG block — the consumer
     * falls back to all-to-all.  See champsim_tracer_mnemonic_tables.c
     * for the shared refiner library.
     */
    if (cls && cls->dep_refine) {
        cls->dep_refine(info, out);
    }

    /*
     * Lane info — orthogonal to .dep_refine.  Row carries the static
     * (lane_mask_kind, lane_parallel) classification; we resolve the
     * baseline mask / source reg from Capstone detail here so the
     * dep refiners stay focused on dst→src dataflow.
     */
    if (cls && cls->lane_mask_kind != LANE_MASK_KIND_NONE) {
        /* Instruction-level shape (slot-agnostic); we own the
         * operand->slot mapping so we apply it per vec-reg operand. */
        LaneShape sh = lane_shape_from_operands(info, cls->lane_mask_kind);
        if (sh.kind != LANE_SHAPE_NONE) {
            out->lane_mask_kind = cls->lane_mask_kind;
            out->lane_parallel  = cls->lane_parallel;
            out->lane_bytes     = sh.lane_bytes;
            /* The kind decides ONLY where the active-lane value is
             * read from; register-sourced kinds record their reg. */
            if (cls->lane_mask_kind == LANE_MASK_KIND_RISCV_VTYPE) {
                out->lane_mask_source_reg.feature = "org.gnu.gdb.riscv.csr";
                out->lane_mask_source_reg.name    = "vl";
            }
            uint64_t sel = (sh.lane_sel >= 0 && sh.lane_sel < 64)
                               ? ((uint64_t)1 << sh.lane_sel) : 0;
            for (uint8_t k = 0; k < info->n_operands; k++) {
                const qemu_plugin_operand *op = &info->operands[k];
                if (op->type != QEMU_PLUGIN_OP_REG) continue;
                /* Scalar (address / GPR) operands carry no lanes —
                 * leave their slots at 0; only vec regs participate. */
                if (op->lane_bytes == 0) continue;
                bool rd = (op->access & QEMU_PLUGIN_OP_ACC_READ)  != 0;
                bool wr = (op->access & QEMU_PLUGIN_OP_ACC_WRITE) != 0;
                if (!rd && !wr) { rd = wr = true; }  /* no flags: both */
                uint64_t src_lane = 0, dst_lane = 0;
                switch (sh.kind) {
                case LANE_SHAPE_UNIFORM:
                    src_lane = dst_lane = sh.full_mask;
                    break;
                case LANE_SHAPE_INSERT:
                    /* Only the inserted lane is produced; the same
                     * reg read supplies the untouched pass-through
                     * lanes (everything but the selected lane). */
                    dst_lane = sel;
                    src_lane = sh.full_mask & ~sel;
                    break;
                case LANE_SHAPE_EXTRACT:
                    /* Only the selected lane is read; the extract
                     * sink is a scalar (no vec dst). */
                    src_lane = sel;
                    dst_lane = sel;
                    break;
                }
                if (rd) assign_src_lane(out, op->reg_id, src_lane);
                if (wr) assign_dst_lane(out, op->reg_id, dst_lane);
                out->has_vec_lanes = true;
            }
        }
    }

    /*
     * Normalize direct-branch immediate to absolute target.
     *
     * Capstone's convention differs by arch:
     *   - x86, ARM64: op->imm holds the resolved absolute target for
     *     direct (PC-relative-encoded) branches; no fixup needed.
     *   - RISC-V, MIPS: op->imm holds the raw signed PC-relative offset
     *     from the branch instruction; we add `pc` to produce the
     *     absolute target.
     *
     * After this step, InsnFields.immediate is always an absolute
    * branch target for direct conditional / direct unconditional
    * branches, which lets the WP-target derivation in
     * champsim_tracer.cc be ISA-agnostic.
     */
    if (out->has_immediate &&
        isa_properties[trace_isa].pc_relative_branch_imm) {
        bool is_direct_branch =
            out->branch_type == BRANCH_COND_DIRECT ||
            out->branch_type == BRANCH_DIRECT_JUMP;
        if (is_direct_branch) {
            out->immediate = (int64_t)((uint64_t)pc + (uint64_t)out->immediate);
        }
    }

}

/*
 * Synthetic-EA decoder for prefetch / cache-flush / TLB-flush
 * instructions whose canonical TCG translation does not emit a memop.
 * Returns true (and fills @out) when @opcode is one of the new
 * memory-hint classes AND the insn carries a Capstone memory operand
 * we can compute an EA from.  Returns false in every other case;
 * callers should leave @out zeroed.
 *
 * @pc / @insn_size carry the current instruction's PC and length so we
 * can resolve PC-relative base registers (notably x86 RIP-relative,
 * where Capstone reports the encoded displacement and the CPU folds in
 * the *next*-insn PC).  In that case the base reg is dropped and the
 * absolute next-insn-PC is folded into the displacement, which is both
 * correct and avoids a needless register read at exec time.
 */
bool decode_synthetic_ea(const qemu_plugin_insn_info *info,
                         uint8_t opcode,
                         uint64_t pc,
                         uint8_t insn_size,
                         SyntheticEAInfo *out)
{
    memset(out, 0, sizeof(*out));
    if (!info ||
        (opcode != GEN_OP_PREFETCH &&
         opcode != GEN_OP_CACHE_FLUSH &&
         opcode != GEN_OP_TLB_FLUSH)) {
        return false;
    }
    for (uint8_t i = 0; i < info->n_operands; i++) {
        const qemu_plugin_operand *op = &info->operands[i];
        if (op->type != QEMU_PLUGIN_OP_MEM) {
            continue;
        }
        const RegClassification *base_rc = lookup_reg_class(op->reg_id);
        const RegClassification *index_rc = lookup_reg_class(op->index_id);
        bool base_is_pc =
            base_rc && base_rc->n_regs == 0 && base_rc->reg_id == REG_IP;
        if (base_is_pc) {
            /* Fold next-insn-PC into the displacement; no base read
             * needed at exec time.  Matches x86 RIP-relative semantics
             * (target = next_insn_PC + disp). */
            out->disp = (int64_t)((uint64_t)pc + insn_size + (uint64_t)op->imm);
        } else {
            if (base_rc) {
                out->base_key = qemu_reg_for_generic(base_rc->reg_id);
            }
            out->disp = op->imm;
        }
        if (index_rc) {
            out->index_key = qemu_reg_for_generic(index_rc->reg_id);
        }
        out->scale = op->scale;
        out->shift_type = op->shift_type;
        out->shift_amount = op->shift_amount;
        out->has_addr = 1;
        return true;
    }
    return false;
}
