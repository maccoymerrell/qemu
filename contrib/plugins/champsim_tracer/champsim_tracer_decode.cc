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

/* O(1) array index into the per-ISA RegClassification table. */
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
 * Reverse index GenericRegId → QemuRegKey, built once at install by
 * walking active_reg_table.  Recovers the per-element QemuRegKey for
 * multi-reg encodings (RISC-V V*M* tuples) so each constituent reg's
 * value is captured under regdata=1 — without it multi-reg operands
 * land in src/dst correctly but their values aren't read (the multi-reg
 * path passed nullptr for the QemuRegKey).
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
        /* First singleton row wins — Capstone aliases (x86
         * AH/AL/AX/EAX/RAX → REG_GPR0) share one QemuRegKey; any is
         * correct for value reads. */
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
         * the generic ID with width_bytes=0 (no live value). */
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
                    cst_normalize_reg_bytes_to_le(buf->data, w);
                    snap.width_bytes = (uint8_t)w;
                    memcpy(snap.bytes, buf->data, w);
                }
            }
        }
        out->push_back(snap);
    }
}

/*
 * Returns the src_regs[] slot holding @reg_id (existing on dedup, else
 * newly allocated), or UINT8_MAX when skipped (REG_NONE / table full).
 * The slot index feeds HAS_ADDR address-dep masks.
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
 * Pointer-stable QemuRegKey identity: add_{src,dst}_reg routes through
 * qemu_reg_for_generic(), returning the g_qemu_reg_by_gen[] singleton
 * (RegClassification's own .qemu_reg may differ in address but holds an
 * identical (feature, name) pair).
 *
 * Returns a mask of src_regs[] slots holding the registers behind
 * @cap_id.  One Capstone reg id can expand into multiple aliases
 * (rc->n_regs > 0), each in its own slot; the caller needs them for
 * HAS_ADDR address-dep masks.
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
     * Mark integer-flags writer so the encoder emits a CST_FID_METAFLAGS
     * record (Z/N/C/V/P from the REG_FLAGS dst snap).  Gated on the
     * per-ISA .is_int_flags marker — set only on x86 EFLAGS / AArch64
     * NZCV, never x86 FPSW / mips DSP-flag / flagless ISAs.
     */
    if (rc->is_int_flags) {
        f->writes_int_flags = true;
    }
}

/* OR @lane into every src_regs[] slot @cap_id maps to.  Per-operand
 * lane-mask assignment: scalar operands keep slot mask 0, only the
 * vec-register operands the caller iterates get lanes. */
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

    /* Surface the first unknown instruction on stderr, then go quiet
     * (per-insn detail still goes to .unknown_warnings.log; the exit
     * summary carries the running total). */
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
 * Classify via direct insn_id array lookup (O(1)).  Returns the table
 * row (nullptr if out of range / no table) for the .refine callback.
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
 * Repair the fields a single insn_id cannot resolve, using the per-instance
 * detail Capstone printed.
 *
 * The classification table is keyed by insn_id, so wherever one id covers
 * several architectural behaviours the table can only carry one of them and
 * the discriminator is what Capstone printed for THIS instance -- the alias,
 * or an operand the alias implies.  Every arm below exists for that reason:
 *
 *  - riscv: one insn_id covers jal+j and jalr+jr+ret, and the
 *    call/jump/return role is carried by rd (Capstone prints the alias):
 *    "jal"/"jalr" link (call), "j"/"jr" do not (jump), "ret" returns.
 *  - aarch64: plain "b" and every conditional "b.<cc>" share
 *    AARCH64_INS_B (the table's static default is the unconditional
 *    DIRECT_JUMP); the condition lives only in the printed mnemonic.
 *  - mips: every "jr <rs>" shares MIPS_INS_JR (static default
 *    INDIRECT_JUMP); "jr $ra" is the architectural return idiom and the
 *    register is only visible per instance.  `bal` is the always-taken
 *    alias of `bgezal $zero`, so it inherits a condition it does not have.
 *
 * BRANCH TYPE IS NOT THE ONLY FIELD IT REPAIRS, which is why it is not
 * named for one.  The same alias that hides a RISC-V call's role also hides
 * its link register completely, so the register sets are repaired here too:
 * REG_LR is added back to an aliased call's destinations and an aliased
 * return's sources, and the C-extension HINT code points -- whose insn_id
 * they share with a real ADDI or shift -- have their read dropped, because
 * a HINT's register field is payload and not a value it consumes.  Both are
 * the same problem as the branch class: one id, several behaviours, and only
 * the printed form tells them apart.
 *
 * x86 (call direct/indirect) is handled by the per-row .refine callback
 * refine_x86_call_branch in the generated table; the remaining aarch64 /
 * mips control transfers (bl/blr/ret, jal/jalr/j) have distinct insn_ids
 * and need no refinement.
 */
static void refine_alias_fields(const qemu_plugin_insn_info *info,
                                InsnFields *out, InsnRegNames *out_names)
{
    switch (trace_isa) {
    case TRACE_ISA_AARCH64: {
        /* "b.eq", "b.ne", ... and the FEAT_HBC "bc.<cc>" form.  The
         * refine runs after the MF_CONDITIONAL/branch_type-derived flag
         * assignment, so set branch_conditional here as well. */
        const char *m = info->mnemonic;
        if ((m[0] == 'b' && m[1] == '.') ||
            (m[0] == 'b' && m[1] == 'c' && m[2] == '.')) {
            out->branch_type        = BRANCH_COND_DIRECT;
            out->branch_conditional = true;
        }
        break;
    }
    case TRACE_ISA_MIPS: {
        const char *m = info->mnemonic;
        if ((!strcmp(m, "jr") || !strcmp(m, "jr.hb")) &&
            !strcmp(info->op_str, "$ra")) {
            out->branch_type = BRANCH_RETURN;
        }
        /*
         * `bal target` is the alias of `bgezal $zero, target`, and
         * Capstone decodes it to that instruction id — so it inherits
         * the row's MF_CONDITIONAL along with the link.  The condition
         * is `$zero >= 0`, which is always true: BAL is an
         * unconditional call, and reporting it as conditional hands a
         * branch predictor a decision that does not exist.  The
         * printed alias is the only thing that distinguishes it.
         */
        if (!strcmp(m, "bal") || !strcmp(m, "balc")) {
            out->branch_conditional = false;
        }
        break;
    }
    case TRACE_ISA_RISCV: {
        const char *m = info->mnemonic;
        /*
         * The C-extension HINT code points: C.ADDI with nzimm == 0, and
         * C.SLLI / C.SRLI / C.SRAI with shamt == 0.  Capstone gives the
         * degenerate member of each family its own mnemonic and prints the
         * ordinary member expanded (`addi rd, rd, imm`, `slli rd, rd,
         * shamt`), so the name alone separates them; the n_dst_regs guard
         * is the belt to that brace.
         *
         * The unprivileged spec is explicit that a HINT does not modify
         * architectural state, and Capstone already agrees on the write
         * half: it reports no destination for any of them.  It leaves the
         * READ on, and half a no-op is worse than either whole — a source
         * with no destination is an instruction that waits for a producer
         * and then delivers nothing.  The register field on a HINT is
         * PAYLOAD, selecting which hint this is, not a value the
         * instruction consumes; modelling it as a read fabricates a RAW
         * edge onto an instruction that architecturally does nothing.
         *
         * The read is dropped here rather than at the decode boundary
         * because clearing an operand's access bits there means something
         * else: an operand with no flags is how the boundary says Capstone
         * SUPPLIED no direction, which sends the whole instruction down
         * the !have_access_info positional path in the operand walk above
         * and turns the payload register into a DESTINATION — the opposite
         * of the intent.
         *
         * Weight is zero on the correct path; no compiler emits these.
         * The wrong path decodes arbitrary bytes, which is where an
         * instruction with an unbalanced operand shape gets to matter.
         */
        if (!strcmp(m, "c.addi") || !strcmp(m, "c.slli64") ||
            !strcmp(m, "c.srli64") || !strcmp(m, "c.srai64")) {
            if (out->n_dst_regs == 0) {
                for (uint8_t i = 0; i < out->n_src_regs; i++) {
                    out->src_regs[i] = REG_NONE;
                    if (out_names) {
                        out_names->src_qemu_reg_keys[i] = nullptr;
                    }
                }
                out->n_src_regs = 0;
            }
            break;
        }
        /*
         * Whether THIS mnemonic is one of the aliases that hides the
         * link register.  The fixup below has to key on that and not on
         * the resulting branch_type: the trap returns MRET / SRET /
         * DRET are also BRANCH_RETURN and also carry no operands, but
         * they resume from mepc / sepc / dpc and never read ra at all.
         * Keyed on branch_type, the fixup invented a return-address
         * dependency on every exception return in a system trace.
         */
        bool aliased_link = false;
        if (!strcmp(m, "jal") || !strcmp(m, "c_jal") ||
            !strcmp(m, "call") || !strcmp(m, "tail")) {
            out->branch_type = BRANCH_DIRECT_CALL;
            aliased_link = true;
        } else if (!strcmp(m, "jalr") || !strcmp(m, "c_jalr")) {
            out->branch_type = BRANCH_INDIRECT_CALL;
            aliased_link = true;
        } else if (!strcmp(m, "j") || !strcmp(m, "c_j") ||
                   !strcmp(m, "jump")) {
            out->branch_type = BRANCH_DIRECT_JUMP;
        } else if (!strcmp(m, "jr") || !strcmp(m, "c_jr")) {
            out->branch_type = BRANCH_INDIRECT_JUMP;
        } else if (!strcmp(m, "ret")) {
            out->branch_type = BRANCH_RETURN;
            aliased_link = true;
        }
        /*
         * Aliased link forms hide ra COMPLETELY in Capstone 6 — it is
         * in neither the operand list nor the (always-empty for
         * RISC-V) implicit regs_read/regs_write — so without a fixup
         * the call's return-address write and the return's read
         * vanish from the dataflow.  Non-aliased forms ("jal t0, ..."
         * / "jalr t0, t1") carry the link register explicitly, which
         * the n_dst/n_src==0 guards leave untouched.  (Caught by
         * probe_rv_link_dataflow.)
         */
        if (!aliased_link) {
            break;
        }
        if (out->branch_type == BRANCH_DIRECT_CALL ||
            out->branch_type == BRANCH_INDIRECT_CALL) {
            if (out->n_dst_regs == 0) {
                add_dst_reg(out, out_names, REG_LR,
                            qemu_reg_for_generic(REG_LR));
            }
        } else if (out->branch_type == BRANCH_RETURN) {
            if (out->n_src_regs == 0) {
                add_src_reg(out, out_names, REG_LR,
                            qemu_reg_for_generic(REG_LR));
            }
        }
        break;
    }
    default:
        break;
    }
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
    /* CONTRACT: @out is a freshly-reset InsnFieldsScratch::f — all scalars
     * zero and every span wired to zeroed full-size backing (see
     * insn_fields_scratch_reset).  The walker and the dep/lane refiners
     * append and compact through those spans; a whole-struct memset here
     * would sever them.  Committed templates are never passed in (their
     * spans are immutable, pool- or zero-array-backed). */
    g_assert(out->src_regs && out->dst_dep_mask);
    /* Same contract for @out_names: a freshly-reset InsnRegNamesScratch::rn
     * with spans wired to full-size backing. */
    g_assert(!out_names || out_names->src_qemu_reg_keys);

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
     * x86 REP/REPNZ promotes the insn to a self-looping branch.  Each
     * architectural REP iteration is a tracer-defined true-BB (chain
     * assembler ends the BB and restarts at the same PC) so the trace
     * structurally identifies the loop instead of one BB with a
     * variable memop count.  Branch type is BRANCH_REP (distinct from
     * BRANCH_COND_DIRECT) so consumers see self-loop semantics
     * (target=self-PC, fall-through=next-PC) at template-parse time.
     * Conditional: the loop exits when ECX==0 or the REPZ/REPNZ compare
     * breaks.  info->has_rep is x86-only (false elsewhere → no-op).
     *
     * rep_{loads,stores}_per_iter = memops per REP iteration, counted
     * from Capstone MEM operand access flags (mnemonic-agnostic: MOVS
     * 1L+1S, CMPS 2L, STOS 1S, LODS/SCAS 1L, INS 1S, OUTS 1L).  Lets
     * the body emitter fan one TB-exec's memop stream into N entries.
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

    /* refine_alias_fields moved below the operand walk: its riscv arm
     * inspects n_src/n_dst_regs to detect alias-hidden link registers,
     * so it needs the explicit operands already populated. */

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
        case QEMU_PLUGIN_OP_SYSREG: {
            /*
             * A system / control register named by the encoding but
             * living outside the ordinary register file: an AArch64
             * MRS/MSR system register, a RISC-V Zicsr CSR.  Capstone
             * has register ids for almost none of them, so the
             * boundary resolves the architectural role and this side
             * only renames it: no ISA table is consulted and no
             * per-ISA branch is taken.  Direction likewise comes from
             * the boundary, which derives it from the instruction form
             * because Capstone leaves the AArch64 system operand's own
             * access bits empty.
             */
            uint8_t gen = generic_reg_for_sysreg_class(op->sysreg_class);
            if (gen == REG_NONE) {
                break;
            }
            if (op->access & QEMU_PLUGIN_OP_ACC_READ) {
                add_src_reg(out, out_names, gen, qemu_reg_for_generic(gen));
            }
            if (op->access & QEMU_PLUGIN_OP_ACC_WRITE) {
                add_dst_reg(out, out_names, gen, qemu_reg_for_generic(gen));
                /*
                 * `msr nzcv, x3` really does define the arithmetic
                 * flags, so it owes the CST_FID_METAFLAGS record an
                 * arithmetic flag-setter emits.  The condition mirrors
                 * the .is_int_flags marker on the reg table: REG_FLAGS
                 * carries arithmetic condition flags only on the ISAs
                 * that supply a metaflags mapper — on MIPS the same ID
                 * names DSP status bits, which no mapper turns into
                 * Z/N/C/V.
                 */
                if (gen == REG_FLAGS &&
                    isa_properties[trace_isa].flags_to_metaflags) {
                    out->writes_int_flags = true;
                }
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
             * Track which src_regs[] slots this MEM operand's base +
             * index + segment addressing regs land in, OR'd together, to
             * populate load/store_addr_dep_mask[k] — structural
             * per-memop "when can this fire?" data for precise
             * load/store scheduling (avoid waiting on dst-as-src for RMW
             * forms, etc.).
             *
             * The segment register belongs in that set for the same
             * reason base and index do: on x86 the linear address is
             * seg.base + base + index * scale + disp, so a `%fs:`- or
             * `%gs:`-prefixed access genuinely reads the segment
             * register.  It has to be taken from the operand because
             * Capstone does NOT list x86 segment overrides among the
             * implicit regs_read[] the fold below consumes — leaving it
             * out made every TLS and stack-protector access look
             * address-input-less (`ld[]`), which is what PIN's source
             * sets disagreed with.  Non-x86 ISAs have no segmented
             * addressing and always report 0 here.
             */
            uint64_t addr_mask = 0;
            addr_mask |= add_src_cap_reg(out, out_names, op->reg_id);
            addr_mask |= add_src_cap_reg(out, out_names, op->index_id);
            addr_mask |= add_src_cap_reg(out, out_names, op->segment_id);

            /*
             * Count against the template-static MAX load/store totals,
             * which bound the dep-mask layout (loads at bits
             * [n_src_regs, n_src_regs+max_dep_loads); stores feed
             * store_data_dep_mask[max_dep_stores]).  Runtime
             * per-iteration counts can be smaller (conditional load
             * that didn't fire) via CST_FID_N_LOADS/N_STORES, never
             * larger.  LEA / prefetch-hint MEM operands lack both
             * READ and WRITE — no real memop, don't count.
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

    /* Resolve call vs jump vs return for the ISAs where one insn_id is
     * ambiguous (x86 call direct/indirect, riscv jal/jalr/j/jr/ret,
     * aarch64 b vs b.<cc>, mips jr $ra).  Runs after the operand walk
     * (the riscv arm needs n_src/n_dst populated) and before the
     * per-row .refine (whose x86 call body overrides this one). */
    refine_alias_fields(info, out, out_names);

    /*
     * Optional ISA-specific post-classification .refine: fixes up
     * opcode/branch_type/etc. from the operand walk, for when one
     * Capstone insn_id covers multiple operand encodings / target forms.
     */
    if (cls && cls->refine) {
        cls->refine(info, out);
    }

    /*
     * Lane info populated BEFORE .dep_refine so structured-vec dep
     * refiners (e.g. dep_vec_struct_store) can identify vec-value
     * operands by src/dst_lane_mask[i] != 0 rather than reconstruct
     * that classification from Capstone again.  Lane population only
     * reads operand-walk outputs; it doesn't depend on dep masks.
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
     * Optional .dep_refine: reads refined InsnFields (including the
     * just-populated lane masks), writes dst_dep_mask[] /
     * store_data_dep_mask[].  NULL → no HAS_REG block (consumer
     * falls back to all-to-all).  Refiner library in
     * champsim_tracer_mnemonic_tables.cc.
     */
    if (cls && cls->dep_refine) {
        cls->dep_refine(info, out);
    }
}

/*
 * Synthetic-EA decoder for prefetch / cache-flush / TLB-flush insns
 * whose TCG translation emits no memop.  Returns true (fills @out) when
 * @opcode is a memory-hint class AND the insn carries a Capstone MEM
 * operand we can compute an EA from; false otherwise (@out zeroed).
 * For x86 RIP-relative (PC-relative base) the base reg is dropped and
 * the absolute next-insn-PC folded into the displacement — correct and
 * avoids a needless register read at exec time.
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
