/*
 * Wrong-Path Tracing Plugin — Capstone detail → ISA-agnostic decode.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <array>
#include <atomic>
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

/*
 * True where the table's rows for one generic ID name DIFFERENT QEMU
 * registers.
 *
 * The reverse index above holds one register per generic ID, which is
 * exactly right for a Capstone alias set -- AH/AL/AX/EAX/RAX are five
 * rows and one register -- and exactly wrong for a generic ID that
 * deliberately folds several registers into one dependency slot.
 * RISC-V is the live case: REG_FCSR carries fflags, frm, vxrm and
 * vxsat, and REG_VCTRL carries vl and vtype, so "first singleton row
 * wins" would publish fflags' content under frm's name.  Where the
 * rows disagree the value is read from the ROW the decode matched
 * (qemu_reg_for_row); where they agree the singleton keeps its pointer
 * identity, and with it the register-handle cache's hit rate.
 */
static bool g_qemu_reg_gen_ambiguous[REG_ID_COUNT];

/*
 * The QEMU-indexed register table for the running ISA: one row per
 * register in QEMU's GDB-stub namespace, sorted by (feature, name).
 * Set beside active_reg_table at install.
 */
const QemuRegRow *active_qemu_regs = nullptr;
unsigned          active_qemu_regs_count = 0;

static int qemu_reg_row_cmp(const char *feature, const char *name,
                            const QemuRegRow *row)
{
    int c = strcmp(feature, row->feature);
    return c ? c : strcmp(name, row->name);
}

/*
 * Find a register BY QEMU IDENTITY -- no Capstone enum involved.
 *
 * This is the lookup a QEMU-fed operand wants: the IR path resolves a
 * TCG global or an env offset to a (feature, name) pair and asks what
 * generic slot it is, without a second decoder's register enumeration
 * standing in between.  Rows are sorted, so it bisects.
 */
const QemuRegRow *qemu_reg_row_find(const char *feature, const char *name)
{
    if (!active_qemu_regs || !feature || !name) {
        return nullptr;
    }
    unsigned lo = 0, hi = active_qemu_regs_count;
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2;
        int c = qemu_reg_row_cmp(feature, name, &active_qemu_regs[mid]);
        if (c == 0) {
            return &active_qemu_regs[mid];
        }
        if (c < 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return nullptr;
}

/*
 * Cross-check: every Capstone row that names a QEMU register must agree
 * with that register's own row about what it IS.
 *
 * Without this the Capstone-keyed table is a second, independent
 * statement of the same fact, and a defect in it reaches the wire
 * silently wherever it happens to be consulted.  With it the
 * Capstone key is a ROUTE and the QEMU row is the authority: a
 * divergence is a build-time fact the generator already refuses to
 * emit (qemu_reg_rows in champsim_tracer_mnemonic_audit.py), and this
 * is the runtime restatement of the same guard against a stale or
 * hand-edited table.  Returns the number of disagreements; the caller
 * reports rather than silently continuing.
 */
unsigned qemu_reg_rows_check(void)
{
    unsigned bad = 0;
    if (!active_reg_table || !active_qemu_regs) {
        return 0;
    }
    for (unsigned i = 0; i < active_reg_table_size; i++) {
        const RegClassification *rc = &active_reg_table[i];
        if (!qemu_reg_key_valid(&rc->qemu_reg)) {
            continue;
        }
        const QemuRegRow *row = qemu_reg_row_find(rc->qemu_reg.feature,
                                                  rc->qemu_reg.name);
        if (!row) {
            fprintf(stderr, "champsim_tracer: capstone reg row %u names "
                    "%s:%s, which QEMU does not carry\n",
                    i, rc->qemu_reg.feature, rc->qemu_reg.name);
            bad++;
            continue;
        }
        if (row->reg_id != rc->reg_id || row->n_regs != rc->n_regs ||
            row->is_int_flags != rc->is_int_flags ||
            (rc->n_regs &&
             memcmp(row->regs, rc->regs, rc->n_regs) != 0)) {
            fprintf(stderr, "champsim_tracer: capstone reg row %u and "
                    "QEMU register %s:%s disagree (%u vs %u)\n",
                    i, rc->qemu_reg.feature, rc->qemu_reg.name,
                    rc->reg_id, row->reg_id);
            bad++;
        }
    }
    return bad;
}

/*
 * Build the GenericRegId -> QemuRegKey reverse index FROM THE QEMU
 * TABLE.
 *
 * It used to be built by walking the Capstone-indexed array and taking
 * the first singleton row, which made Capstone's ENUM ORDER decide
 * which QEMU register's value is published for a generic id -- x86
 * REG_GPR0 is named by AH, AL, AX, EAX and RAX, and the winner was
 * whichever the enum listed first.  Walking QEMU's namespace instead
 * makes the choice QEMU's, in QEMU's own (feature, name) order, and it
 * reaches registers no Capstone id names at all.
 *
 * The ambiguity rule is unchanged and still load-bearing: where several
 * DIFFERENT QEMU registers fold into one generic id (RISC-V REG_FCSR
 * carries fflags, frm, vxrm and vxsat) no singleton is correct, and
 * qemu_reg_for_row falls back to the row the decode actually matched.
 */
void build_qemu_reg_reverse_index(void)
{
    for (unsigned i = 0; i < REG_ID_COUNT; i++) {
        g_qemu_reg_by_gen[i] = QemuRegKey{};
        g_qemu_reg_gen_ambiguous[i] = false;
    }
    if (!active_qemu_regs || active_qemu_regs_count == 0) {
        return;
    }
    for (unsigned i = 0; i < active_qemu_regs_count; i++) {
        const QemuRegRow *row = &active_qemu_regs[i];
        if (row->n_regs != 0) {
            /* Composite rows do not stand for one register's value;
             * their constituents are named by their own rows. */
            continue;
        }
        if (row->reg_id == REG_NONE || row->reg_id >= REG_ID_COUNT) {
            continue;
        }
        QemuRegKey key = { row->feature, row->name };
        if (!qemu_reg_key_valid(&g_qemu_reg_by_gen[row->reg_id])) {
            g_qemu_reg_by_gen[row->reg_id] = key;
        } else if (!cst_str_eq(g_qemu_reg_by_gen[row->reg_id].feature,
                               key.feature) ||
                   !cst_str_eq(g_qemu_reg_by_gen[row->reg_id].name,
                               key.name)) {
            g_qemu_reg_gen_ambiguous[row->reg_id] = true;
        }
    }
}

/*
 * The pre-re-index build, kept as the instrument that PROVES the
 * re-index changed no published value: it reconstructs the
 * Capstone-enum-order winner and reports every generic id whose winner
 * moved.  A non-zero count is a wire-visible change and must be named,
 * not absorbed.
 */
unsigned qemu_reg_reverse_index_drift(void)
{
    QemuRegKey by_gen[REG_ID_COUNT] = {};
    bool ambiguous[REG_ID_COUNT] = {};
    unsigned drift = 0;

    if (!active_reg_table || active_reg_table_size == 0) {
        return 0;
    }
    for (unsigned i = 0; i < active_reg_table_size; i++) {
        const RegClassification *rc = &active_reg_table[i];
        if (rc->n_regs != 0 || !qemu_reg_key_valid(&rc->qemu_reg) ||
            rc->reg_id >= REG_ID_COUNT) {
            continue;
        }
        if (!qemu_reg_key_valid(&by_gen[rc->reg_id])) {
            by_gen[rc->reg_id] = rc->qemu_reg;
        } else if (!cst_str_eq(by_gen[rc->reg_id].feature,
                               rc->qemu_reg.feature) ||
                   !cst_str_eq(by_gen[rc->reg_id].name,
                               rc->qemu_reg.name)) {
            ambiguous[rc->reg_id] = true;
        }
    }
    for (unsigned g = 0; g < REG_ID_COUNT; g++) {
        bool old_valid = qemu_reg_key_valid(&by_gen[g]);
        bool now_valid = qemu_reg_key_valid(&g_qemu_reg_by_gen[g]);
        bool same = (old_valid == now_valid) &&
                    ambiguous[g] == g_qemu_reg_gen_ambiguous[g] &&
                    (!old_valid ||
                     (cst_str_eq(by_gen[g].feature,
                                 g_qemu_reg_by_gen[g].feature) &&
                      cst_str_eq(by_gen[g].name,
                                 g_qemu_reg_by_gen[g].name)));
        if (!same) {
            fprintf(stderr, "champsim_tracer: reg-index drift on generic %u: "
                    "capstone-order %s:%s (amb=%d) vs qemu-order %s:%s "
                    "(amb=%d)\n", g,
                    old_valid ? by_gen[g].feature : "-",
                    old_valid ? by_gen[g].name : "-", ambiguous[g],
                    now_valid ? g_qemu_reg_by_gen[g].feature : "-",
                    now_valid ? g_qemu_reg_by_gen[g].name : "-",
                    g_qemu_reg_gen_ambiguous[g]);
            drift++;
        }
    }
    return drift;
}

/*
 * Interned QemuRegKey for a SYSTEM register named by its own operand.
 *
 * A QEMU_PLUGIN_OP_SYSREG operand reaches the generic vocabulary
 * through its ROLE, and a role is a class: REG_FCSR stands for RISC-V's
 * fflags, frm, fcsr, vxsat, vxrm and vcsr all at once, REG_VCTRL for vl,
 * vtype and vstart, and on AArch64 the whole 209-register privileged
 * file arrives as a handful of roles.  That fold is correct for the
 * dependency edge -- a consumer scheduling against "the FP control
 * word" wants one slot -- and wrong for the VALUE, because
 * g_qemu_reg_by_gen[] holds at most ONE register per class.  Where the
 * class has no member with a readable QEMU register the destination is
 * published with width 0, which reads back as zero and therefore agrees
 * with any reference whenever the truth happens to be zero; where it
 * has several, one member's content is published under all of their
 * names.
 *
 * So the value is keyed on the register the operand actually names.
 * The key must be POINTER-STABLE -- InsnRegNames stores the pointer and
 * RegHandleCache's direct-mapped cache is keyed on its identity -- so
 * keys are interned here and live for the process.  Returns nullptr
 * when the ISA exposes no system-register feature, when the boundary
 * had no name for the register, or when the rename says QEMU does not
 * carry it; every one of those falls back to the class-level index,
 * which is what happened before this existed.
 */
static GMutex             g_sysreg_key_lock;
static GHashTable        *g_sysreg_keys;        /* name -> QemuRegKey * */
static GHashTable        *g_sysreg_exposed;     /* name -> (gpointer)1 */

/*
 * Does QEMU carry a register by this name at all?
 *
 * A key that names nothing resolves to a null handle and publishes a
 * width-0 field -- the very defect this resolver exists to remove -- and
 * it would do so on registers the CLASS index could still have placed
 * (AArch64 `nzcv` is not in the descriptor list, but REG_FLAGS' index
 * entry is `cpsr`, which holds it).  So the descriptor list is consulted
 * once and the resolver declines names it does not carry, leaving those
 * to the fallback.  Both spellings go in because the AArch64 boundary
 * lower-cases what QEMU spells in upper case.  An empty list is NOT
 * cached: decode can run before any vCPU has registers to report, and a
 * cached "nothing exists" would be permanent.
 */
static bool sysreg_name_exposed(const char *name)
{
    if (!g_sysreg_exposed) {
        g_autoptr(GArray) regs = qemu_plugin_get_registers();
        if (!regs || regs->len == 0) {
            return false;
        }
        GHashTable *set = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                g_free, nullptr);
        for (unsigned i = 0; i < regs->len; i++) {
            const qemu_plugin_reg_descriptor *d =
                &g_array_index(regs, qemu_plugin_reg_descriptor, i);
            if (!d->name || !d->name[0]) {
                continue;
            }
            g_hash_table_add(set, g_strdup(d->name));
            g_hash_table_add(set, g_ascii_strdown(d->name, -1));
        }
        g_sysreg_exposed = set;
    }
    return g_hash_table_contains(g_sysreg_exposed, name);
}

static const QemuRegKey *qemu_reg_for_sysreg(const char *boundary_name)
{
    const IsaProperties *props = &isa_properties[trace_isa];
    const char *feature = props->sysreg_feature;
    const char *name = boundary_name;

    if (!feature || !name || !name[0]) {
        return nullptr;
    }
    if (props->sysreg_qemu_name) {
        name = props->sysreg_qemu_name(name);
        if (!name || !name[0]) {
            return nullptr;
        }
    }

    g_mutex_lock(&g_sysreg_key_lock);
    if (!sysreg_name_exposed(name)) {
        g_mutex_unlock(&g_sysreg_key_lock);
        return nullptr;
    }
    if (!g_sysreg_keys) {
        g_sysreg_keys = g_hash_table_new(g_str_hash, g_str_equal);
    }
    QemuRegKey *key = (QemuRegKey *)g_hash_table_lookup(g_sysreg_keys, name);
    if (!key) {
        key = g_new0(QemuRegKey, 1);
        key->feature = g_strdup(feature);
        key->name = g_strdup(name);
        g_hash_table_insert(g_sysreg_keys, (gpointer)key->name, key);
    }
    g_mutex_unlock(&g_sysreg_key_lock);
    return key;
}

static inline const QemuRegKey *qemu_reg_for_generic(uint8_t gen_id)
{
    if (gen_id >= REG_ID_COUNT) {
        return nullptr;
    }
    const QemuRegKey *k = &g_qemu_reg_by_gen[gen_id];
    return qemu_reg_key_valid(k) ? k : nullptr;
}

/*
 * The same resolution, published.  See champsim_tracer.h: the QEMU-owned
 * source index can seat a register in src_regs[] that the Capstone operand
 * walk never listed, and that slot needs the same key every walk-built slot
 * carries or its VALUE never reaches the wire.
 */
const QemuRegKey *qemu_reg_key_for_generic(uint8_t gen_id)
{
    return qemu_reg_for_generic(gen_id);
}

/*
 * The QEMU register whose VALUE this table row stands for.  Both
 * candidates are pointer-stable -- the row lives in a static table and
 * the singleton in a static array -- so either can key the handle
 * cache; the row is preferred only where the singleton would name a
 * DIFFERENT register (see g_qemu_reg_gen_ambiguous).
 */
static inline const QemuRegKey *qemu_reg_for_row(const RegClassification *rc)
{
    if (!rc) {
        return nullptr;
    }
    if (rc->reg_id < REG_ID_COUNT && g_qemu_reg_gen_ambiguous[rc->reg_id]) {
        /*
         * Once the rows disagree the singleton is some OTHER register,
         * so a row that names none of its own publishes nothing rather
         * than a neighbour's content.  A missing value is a gap a
         * reference can see; a confidently wrong one is not.
         */
        return qemu_reg_key_valid(&rc->qemu_reg) ? &rc->qemu_reg : nullptr;
    }
    return qemu_reg_for_generic(rc->reg_id);
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
 * qemu_reg_for_row(), which returns the g_qemu_reg_by_gen[] singleton
 * whenever every row for the generic ID holds the same (feature, name)
 * pair -- the Capstone-alias case -- and the row's own key when they
 * do not.
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
    uint8_t slot = add_src_reg(f, refs, rc->reg_id, qemu_reg_for_row(rc));
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
    add_dst_reg(f, refs, rc->reg_id, qemu_reg_for_row(rc));
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

/*
 * Set while an instruction is being decoded for MEASUREMENT rather than for
 * the wire.  decode_detail_to_generic() is not a pure function of its
 * scratch: an unclassified mnemonic bumps g_stats.unknown_insn_warnings and
 * appends a line to the sidecar log.  A second call on the same instruction
 * -- which is exactly what scoring the tracer's branch class against QEMU's
 * needs -- therefore DOUBLES both, and the counter is one an acceptance gate
 * reads.  An instrument that moves the number it is standing next to is not
 * an instrument.
 */
thread_local bool g_unknown_warn_suppressed = false;

static void warn_unknown_instruction(uint64_t pc, const char *reason,
                                     const char *mnem, const char *disas)
{
    if (g_unknown_warn_suppressed) {
        return;
    }
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
 * A whole basic block was refused because the boundary could not decode
 * one of its instructions.  This is a strictly worse loss than an
 * unknown mnemonic -- there the instruction is still traced, with
 * opcode=GEN_OP_UNKNOWN and whatever registers the operands gave -- so
 * it says so in its own words rather than borrowing that message.
 */
void report_undecodable_block(uint64_t pc)
{
    g_mutex_lock(&unknown_warn_lock);

    static bool warned_once = false;
    if (!warned_once) {
        warned_once = true;
        fprintf(stderr,
                "champsim_tracer: no decode for the instruction at pc=0x%"
                PRIx64 " — the WHOLE basic block containing it is refused "
                "and does not appear in the trace.\n"
                "  Further occurrences are silent; the exit summary counts "
                "them under \"BBs refused, boundary could not decode\", "
                "and %s lists each one.  On the correct path this is a "
                "boundary decoder gap to close in disas/capstone.c, not a "
                "property of the guest.\n",
                pc,
                unknown_warn_file ? "the .unknown_warnings.log file"
                                  : "(no warn-log file open)");
    }

    if (unknown_warn_file) {
        fprintf(unknown_warn_file,
                "pc=0x%" PRIx64 " isa=%u reason=undecodable_block "
                "mnemonic=<none> disas=\"\"\n",
                pc, (unsigned int)trace_isa);
        fflush(unknown_warn_file);
    }
    g_mutex_unlock(&unknown_warn_lock);
}

/*
 * Classify via direct insn_id array lookup (O(1)).  Returns the table
 * row (nullptr if out of range / no table) for the .refine callback.
 *
 * QEMU'S OWN IDENTITY WINS WHERE THE TWO KEYS DISAGREE.  The Capstone
 * constant and QEMU's decode-table slot are two accounts of the same
 * instruction, and on every row where both can speak they agree -- zero
 * opcode and zero branch-class disagreements over the census workloads,
 * on all four ISAs.  The exception is the set of rules several Capstone
 * constants decode through with different classifications, and there the
 * Capstone key is not finer, it is WRONG: x86 slot 0x6ca is opcode 0xA5,
 * the string move, and Capstone's X86_INS_MOVSD covers both that and the
 * SSE scalar-double move, so `rep movsl` was published as a lane-parallel
 * FP vector move.
 *
 * SO THE DECODE RULE IS THE KEY, and the Capstone id is the fallback.
 * qemu_ident_classify() answers for every rule whose own row carries a
 * classification -- tier QID_OBSERVED (QEMU was seen decoding through the
 * rule and one classification was seen with it) and tier QID_ADJUDICATED
 * (several were, and QEMU's own table row settles which, each carrying the
 * source fact that decided it).  Those are the rows where the identity
 * decides, and they are the overwhelming majority.
 *
 * THE REST ARE NAMED SURVIVORS and keep publishing Capstone's answer,
 * because the rule genuinely does not state one:
 *
 *   QID_SPLIT         several classifications were observed through the one
 *                     rule and nothing in QEMU's row picks between them;
 *                     the row carries GEN_OP_UNKNOWN by construction.
 *   QID_NAME_MATCHED  no decode through the rule was ever observed, so the
 *                     row's payload rests on its NAME matching a Capstone
 *                     mnemonic -- which is Capstone's answer wearing the
 *                     identity's key, not an independent one.  Coverage
 *                     path: a generator corpus that reaches the rule
 *                     promotes it to QID_OBSERVED.
 *   QID_NONE          residue: no classification at all.
 *   no row / id 0     the identity is absent.  An offline decode of raw
 *                     bytes always is (no insn handle, so no decode id),
 *                     which is why the offline tools take the Capstone
 *                     path in full.
 *
 * Every one of those is COUNTED, per class, so a survivor population is a
 * number in the report rather than a silent fallback.  See
 * champsim_tracer_qemu_ident.h.
 */
extern thread_local bool g_dep_refine_suppressed;

/*
 * Rows are sorted by id -- the generator emits them that way and the
 * identity reader PROVES it at install (qemu_ident_install returns the
 * count of out-of-order and duplicate ids, and a non-zero count is
 * reported), so a bisect here cannot silently miss a row.
 */
static std::atomic<uint64_t> g_qid_adjudicated_hits{0};

/*
 * PER ROW, not only in total, and for EVERY row rather than only the
 * adjudicated ones.  A single total cannot say WHICH rule a run
 * exercised, and that matters in both directions: an adjudication that
 * never fires is a ruling this run does not evidence, and a SURVIVOR row
 * that fires is a named population with a coverage path -- reportable by
 * name, not inferable from a sum.  Indexed by the row's position in the
 * (sorted, per-ISA) identity table.
 */
static std::atomic<uint64_t> g_qid_row_hits[CST_QID_MAX_ROW_HITS];

/*
 * The survivor census: one counter per reason the identity did not decide.
 * A survivor is not a failure and it is not a silent fallback -- it is a
 * named population with a coverage path, and the only way that stays true
 * is if each class is counted separately.  A single "fell back" total
 * cannot say whether a run met three split rules or three thousand rows
 * the generator has never seen.
 */
static std::atomic<uint64_t> g_qid_decided_observed{0};
static std::atomic<uint64_t> g_qid_surv_split{0};
static std::atomic<uint64_t> g_qid_surv_name_matched{0};
static std::atomic<uint64_t> g_qid_surv_none{0};
static std::atomic<uint64_t> g_qid_surv_no_row{0};
static std::atomic<uint64_t> g_qid_surv_no_ident{0};
/*
 * MUST BE 0.  A row the classifier accepted as deciding, carrying no
 * classification, would publish GEN_OP_UNKNOWN under the identity's
 * authority.  QID_SPLIT is the tier that carries GEN_OP_UNKNOWN and it is
 * a survivor, so this cannot happen -- which is exactly why it is counted
 * rather than asserted away.
 */
static std::atomic<uint64_t> g_qid_decided_unknown{0};
/*
 * The rule DECIDED and the Capstone row it was joined through says
 * something else.  MEASURED, and the reason this counter exists at all:
 * QID_OBSERVED rests on the generator's observation corpus, and a rule
 * reached by a SPELLING that corpus never saw is asserted to decide on
 * evidence that does not cover the instance.  Two were caught by the
 * golden net's coverage probes at the flip --
 *
 *   translate_mips/OPC_SLL  observed only as `sll`; MIPS `nop` is
 *                           `sll $zero,$zero,0` and reaches the same rule
 *   decode_insn32/ori       observed only as `ori`; Zicbop
 *                           `prefetch.r/w/i` are `ori x0,rs1,imm`
 *
 * -- and in both the row carries cap_split=false, so nothing in the table
 * says the join was partial.  A disagreement here is not by itself a
 * defect (the identity is RIGHT about x86 `rdsspq`, which QEMU decodes
 * through its NOP slot and Capstone names as a move); it is the exact
 * population an adjudication has to be written for, so it is counted and
 * reported rather than resolved by a rule of thumb.
 */
static std::atomic<uint64_t> g_qid_cap_disagree{0};
/*
 * Decodes on an ISA whose flip is HELD.  Not a silent fallback: the hold
 * is a per-ISA decision with a number beside it, and this is the number.
 */
static std::atomic<uint64_t> g_qid_isa_held{0};

/*
 * WHICH ISAs THE CLASSIFICATION KEY IS FLIPPED ON, and the rule is
 * per-ISA because a half-keyed ISA is the one thing this may not be: an
 * instruction stream whose opcodes come from two decoders depending on
 * which rule happened to be reached is not a taxonomy anybody can read.
 *
 * x86_64 and aarch64 are flipped.  riscv64 and mipsel are HELD, and the
 * reason is measured rather than cautious: the golden net's w3_coverage
 * opcode probes go RED on exactly those two, on the two rules named
 * above, because the identity would publish GEN_OP_SHL for a MIPS `nop`
 * and GEN_OP_OR for a RISC-V `prefetch.r`.  Under R12.1 that is
 * information lost, and no discount applies.
 *
 * COVERAGE PATH, and it needs no table edit: the generator decides the
 * tier from what it OBSERVED decoding through each rule.  A corpus that
 * reaches `nop` and `prefetch.r` turns both rows into QID_SPLIT -- rows
 * that state they do not classify -- which makes them survivors on the
 * Capstone answer they already publish, and the hold lifts.  What the
 * hold must NOT become is a permanent per-ISA carve-out: the two probes
 * are the acceptance test, and they exist.
 */
static bool qemu_ident_key_flipped(TraceISA isa)
{
    return isa == TRACE_ISA_X86 || isa == TRACE_ISA_AARCH64;
}

static const QemuIdentRow *qemu_ident_lookup(uint32_t id, unsigned *index_out)
{
    if (id == 0 || !active_qemu_ident || active_qemu_ident_size == 0) {
        return nullptr;
    }
    unsigned lo = 0, hi = active_qemu_ident_size;
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2;
        if (active_qemu_ident[mid].id < id) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo >= active_qemu_ident_size || active_qemu_ident[lo].id != id) {
        return nullptr;
    }
    *index_out = lo;
    return &active_qemu_ident[lo];
}

const InsnClassification *qemu_ident_classify(
    uint32_t id, const InsnClassification *cap_row)
{
    unsigned idx = 0;

    if (!qemu_ident_key_flipped(trace_isa)) {
        g_qid_isa_held.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }

    const QemuIdentRow *row = qemu_ident_lookup(id, &idx);

    if (!row) {
        (id == 0 ? g_qid_surv_no_ident : g_qid_surv_no_row)
            .fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    if (idx < CST_QID_MAX_ROW_HITS) {
        g_qid_row_hits[idx].fetch_add(1, std::memory_order_relaxed);
    }
    switch (row->tier) {
    case QID_ADJUDICATED:
        g_qid_adjudicated_hits.fetch_add(1, std::memory_order_relaxed);
        break;
    case QID_OBSERVED:
        g_qid_decided_observed.fetch_add(1, std::memory_order_relaxed);
        break;
    case QID_SPLIT:
        g_qid_surv_split.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    case QID_NAME_MATCHED:
        g_qid_surv_name_matched.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    default:
        g_qid_surv_none.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    if (row->cls.opcode == GEN_OP_UNKNOWN) {
        g_qid_decided_unknown.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    if (cap_row && cap_row->opcode != row->cls.opcode) {
        g_qid_cap_disagree.fetch_add(1, std::memory_order_relaxed);
    }
    return &row->cls;
}

uint64_t qemu_ident_decided_observed(void)
{
    return g_qid_decided_observed.load(std::memory_order_relaxed);
}

void qemu_ident_survivors(QemuIdentSurvivors *out)
{
    out->split        = g_qid_surv_split.load(std::memory_order_relaxed);
    out->name_matched = g_qid_surv_name_matched.load(std::memory_order_relaxed);
    out->none         = g_qid_surv_none.load(std::memory_order_relaxed);
    out->no_row       = g_qid_surv_no_row.load(std::memory_order_relaxed);
    out->no_ident     = g_qid_surv_no_ident.load(std::memory_order_relaxed);
    out->decided_unknown =
        g_qid_decided_unknown.load(std::memory_order_relaxed);
    out->isa_held     = g_qid_isa_held.load(std::memory_order_relaxed);
    out->cap_disagree = g_qid_cap_disagree.load(std::memory_order_relaxed);
}

uint64_t qemu_ident_adjudicated_hits(void)
{
    return g_qid_adjudicated_hits.load(std::memory_order_relaxed);
}

uint64_t qemu_ident_row_hits(unsigned row_index)
{
    if (row_index >= CST_QID_MAX_ROW_HITS) {
        return 0;
    }
    return g_qid_row_hits[row_index].load(std::memory_order_relaxed);
}

static const InsnClassification *classify_insn_id(
    const qemu_plugin_insn_info *info,
    uint8_t *opcode, uint8_t *branch_type, uint16_t *flags)
{
    uint32_t id = info->insn_id;
    const InsnClassification *cap =
        (active_insn_table && id < active_insn_table_size)
            ? &active_insn_table[id] : nullptr;

    const InsnClassification *q = qemu_ident_classify(info->decode_id, cap);
    if (q) {
        *opcode = q->opcode;
        *branch_type = q->branch_type;
        *flags = q->flags;
        return q;
    }

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
 * THESE ARE THE NAMED SURVIVORS OF THE IDENTITY FLIP.  The classification
 * now comes from QEMU's decode rule, and a rule is a STATIC fact: where one
 * rule covers several architectural behaviours told apart by a REGISTER
 * FIELD, the rule cannot say which, and the discriminator is what Capstone
 * printed for THIS instance -- the alias, or an operand the alias implies.
 * Each arm below is one such class, and each has a coverage path that
 * would retire it: a per-instance fact from QEMU's own translation (the
 * link register and successor the ops published), which the identity
 * reader already derives for its audit but the wire does not yet take.
 *
 *  - riscv: decode_insn32/jal covers jal and j, and decode_insn16/jalr
 *    covers jr and ret; the call/jump/return role is carried by rd, a
 *    field the rule leaves free (Capstone prints the alias): "jal"/"jalr"
 *    link (call), "j"/"jr" do not (jump), "ret" returns.  Measured at the
 *    flip: 113 ret + 18 j.
 *  - mips: translate_mips/OPC_JR covers every "jr <rs>" (static default
 *    INDIRECT_JUMP); "jr $ra" is the architectural return idiom and the
 *    register is only visible per instance.  Measured at the flip: 93.
 *    `bal` is the always-taken alias of `bgezal $zero`, so it inherits a
 *    condition it does not have.  `mfhi` and `mflo` read different halves
 *    of the accumulator, and Capstone reports both as reading the whole
 *    pair, so the half the mnemonic does not name is dropped here.
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
 * refine_x86_call_branch in the generated table, which reads the OPERAND
 * shape rather than the printed name and so rides the identity's payload
 * unchanged; the remaining aarch64 / mips control transfers (bl/blr/ret,
 * jal/jalr/j) have distinct decode rules and need no refinement.
 */
static void refine_alias_fields(const qemu_plugin_insn_info *info,
                                InsnFields *out, InsnRegNames *out_names)
{
    switch (trace_isa) {
    /*
     * aarch64 HAS NO ARM HERE ANY MORE.  It used to recover the
     * conditional branch class from the printed "b.<cc>" / "bc.<cc>",
     * because Capstone spells every one of them AARCH64_INS_B -- the same
     * constant it gives the unconditional `b` -- and the condition lives
     * in a field the constant does not carry.  QEMU's rule does carry it:
     * a64.decode:199 extracts a 4-bit `cond`, and the identity row for
     * disas_a64/B_cond states BRANCH_COND_DIRECT outright.  With the
     * classification keyed on that rule the arm could only ever re-derive
     * an answer the row already gives, so it is deleted rather than left
     * as a second, quieter opinion.  Measured at the flip: 367 rows where
     * the identity and the pre-refinement Capstone row disagreed, 0 where
     * the identity and the WIRE did.
     */
    case TRACE_ISA_MIPS: {
        const char *m = info->mnemonic;
        if ((!strcmp(m, "jr") || !strcmp(m, "jr.hb")) &&
            !strcmp(info->op_str, "$ra")) {
            out->branch_type = BRANCH_RETURN;
        }
        /*
         * `mfhi rd[, ac]` reads the HIGH half of the accumulator and
         * `mflo rd[, ac]` the LOW half -- two different registers,
         * which is why the generic space gives them REG_ACCHI<n> and
         * REG_ACC<n>.  Capstone reports both as reading the WHOLE
         * pair: MIPS_REG_AC<n>, for either mnemonic.  (Measured on
         * Capstone 6.0.0-Alpha7: `mfhi $t0` and `mflo $t0` both yield
         * regs_read = {ac0}, while `mult` correctly writes
         * MIPS_REG_HI0 and MIPS_REG_LO0 as separate registers, and
         * `mthi`/`mtlo` correctly name the single half they write.)
         *
         * The register table cannot fix this -- it is keyed by
         * REGISTER and the discriminator is the INSTRUCTION -- so the
         * AC<n> row names both halves (which is right for the DSP
         * DPA/EXTR family, whose operations genuinely use all 64
         * bits) and the two move-from forms drop the half they do not
         * read here.  Without this, every `mfhi` takes a false edge
         * from every producer of LO, and vice versa: the exact class
         * of manufactured dependency the split exists to remove.
         *
         * Upstream: Capstone's MIPS move-from-accumulator operands
         * should name MIPS_REG_HI<n> / MIPS_REG_LO<n>, as the
         * move-to forms already do.  Revisit on a Capstone bump.
         */
        if (!strcmp(m, "mfhi") || !strcmp(m, "mflo")) {
            const bool want_hi = (m[2] == 'h');
            const uint8_t lo_first = REG_ACC0, lo_last = REG_ACC3;
            const uint8_t hi_first = REG_ACCHI0, hi_last = REG_ACCHI3;
            const uint8_t drop_first = want_hi ? lo_first : hi_first;
            const uint8_t drop_last  = want_hi ? lo_last  : hi_last;
            /*
             * Compaction shifts src slot indices, and the address-dep
             * masks are indexed by them.  These instructions have no
             * memory operand so the masks are never populated; refuse
             * rather than silently renumber if that ever changes.
             */
            if (!out->has_addr_deps) {
                uint8_t keep = 0;
                for (uint8_t i = 0; i < out->n_src_regs; i++) {
                    uint8_t id = out->src_regs[i];
                    if (id >= drop_first && id <= drop_last) {
                        continue;
                    }
                    if (keep != i) {
                        out->src_regs[keep]      = id;
                        out->src_lane_mask[keep] = out->src_lane_mask[i];
                        if (out_names) {
                            out_names->src_qemu_reg_keys[keep] =
                                out_names->src_qemu_reg_keys[i];
                        }
                    }
                    keep++;
                }
                out->n_src_regs = keep;
            }
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
/*
 * The MEM operand decode_synthetic_ea() would build an address from,
 * WHEN that operand carries no access flag of its own.  Such an operand
 * contributed no load and no store slot during the operand walk, yet the
 * execution-time callback mints a memop from it -- so the template's
 * static claim and the wire disagree unless a slot is allocated for it.
 * Returns NULL when no synthetic EA is minted, or when the operand it
 * would be minted from already owns a slot.
 *
 * The selection MIRRORS decode_synthetic_ea() below, including its
 * narrower GEN_OP_FENCE rule; the two must be read together.
 */
static const qemu_plugin_operand *
synthetic_ea_slotless_mem_operand(const qemu_plugin_insn_info *info,
                                  uint8_t opcode)
{
    bool hint_class = opcode == GEN_OP_PREFETCH ||
                      opcode == GEN_OP_CACHE_FLUSH ||
                      opcode == GEN_OP_TLB_FLUSH;
    if (!info || (!hint_class && opcode != GEN_OP_FENCE)) {
        return nullptr;
    }
    for (uint8_t i = 0; i < info->n_operands; i++) {
        const qemu_plugin_operand *op = &info->operands[i];
        if (op->type != QEMU_PLUGIN_OP_MEM) {
            continue;
        }
        bool accessed = (op->access & (QEMU_PLUGIN_OP_ACC_READ |
                                       QEMU_PLUGIN_OP_ACC_WRITE)) != 0;
        if (!hint_class && accessed) {
            continue;       /* decode_synthetic_ea keeps looking too */
        }
        /* This is the operand the EA comes from.  It only needs a slot
         * when the walk gave it none. */
        return accessed ? nullptr : op;
    }
    return nullptr;
}

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
     * rep_memops_per_iter = memops per REP iteration, counted from
     * Capstone MEM operand access flags (mnemonic-agnostic: MOVS
     * 1L+1S, CMPS 2L, STOS 1S, LODS/SCAS 1L, INS 1S, OUTS 1L).  Lets
     * the body emitter fan one TB-exec's memop stream into N entries.
     *
     * Guarded on the mnemonic table not already naming a branch: the
     * boundary only reports has_rep on the string family, whose rows
     * are all BRANCH_NONE, so on correct input the guard never bites.
     * It exists because the F2/F3 prefix byte is overloaded (BND on
     * CALL/RET/JMP/Jcc, XACQUIRE/XRELEASE, `repz ret` padding): if a
     * boundary regression ever reports has_rep on one of those again,
     * the resolved CALL/RET/JUMP taxonomy must win over the REP
     * self-loop promotion, not be overwritten by it.
     */
    if (info->has_rep && out->branch_type == BRANCH_NONE) {
        out->branch_type        = BRANCH_REP;
        out->branch_conditional = true;
        for (unsigned i = 0; i < info->n_operands; i++) {
            const qemu_plugin_operand *op = &info->operands[i];
            if (op->type != QEMU_PLUGIN_OP_MEM) {
                continue;
            }
            if (op->access & QEMU_PLUGIN_OP_ACC_READ) {
                out->rep_memops_per_iter++;
            }
            if (op->access & QEMU_PLUGIN_OP_ACC_WRITE) {
                out->rep_memops_per_iter++;
            }
        }
    } else if (out->branch_type == BRANCH_REP) {
        /*
         * Fan-out declared by the mnemonic table rather than by a
         * prefix: an instruction whose memory fan-out is bounded only
         * by a register, so no slot ceiling can hold it.  The AArch64
         * FEAT_MOPS bulk copy/set family (CPYP/CPYM/CPYE, CPYFP/CPYFM/
         * CPYFE, SETP/SETM/SETE, SETGP/SETGM/SETGE and their
         * option-suffixed variants) is the whole of this class today —
         * every other wide issuer is bounded well below the ceiling
         * (XSAVE ~320, AVX-512 gather/scatter 16, SVE2 64, RISC-V V
         * 64) and keeps using slots.
         *
         * These have no architectural iteration to count elements
         * against, so the fan-out unit is one memory access; see
         * rep_memops_per_iter in champsim_tracer_mnemonics.h.  Marked
         * conditional for the same reason a REP is: the self-loop
         * exits on a register value (here the size register Xn), so a
         * zero-size transfer executes the block exactly once and falls
         * straight through.
         */
        out->branch_conditional  = true;
        out->rep_memops_per_iter = 1;
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
        /* TEST discards its result and writes only the flags register
         * — it never writes an operand, so the fallback must not
         * invent a destination (ktest* fabricated a k-register write
         * through this hole). */
        a[GEN_OP_TEST]    = false;
        return a;
    }();

    /*
     * "Does Capstone tell us the direction of this instruction's
     * operands?"  Only the operands Capstone itself reported can
     * answer that.  A QEMU_PLUGIN_OP_SYSREG operand is APPENDED by the
     * boundary -- an x86 system register or a RISC-V CSR the encoding
     * implies but the disassembler does not name -- and it always
     * carries a boundary-derived access, so counting it here would let
     * one appended operand switch the whole instruction out of the
     * positional fallback and silently drop every register Capstone
     * reported with access == 0.  Measured: without this exclusion,
     * naming SSP on `rdsspq %rax` costs the %rax operand entirely
     * (SRC{REG_GPR0} -> SRC{}), because Capstone reports that operand
     * access == 0 and the fallback is what was placing it.
     */
    bool have_access_info = false;
    for (uint8_t i = 0; i < info->n_operands && !have_access_info; i++) {
        if (info->operands[i].type == QEMU_PLUGIN_OP_SYSREG) {
            continue;
        }
        if (info->operands[i].access != 0) {
            have_access_info = true;
        }
    }

    /*
     * Fallback destination slot: the operand ORDER is the syntax's,
     * and QEMU runs Capstone in AT&T syntax for x86, which lists the
     * destination LAST — so the x86 fallback destination is the last
     * register operand.  The dest-first ISAs (MIPS / RISC-V / AArch64)
     * keep the first register operand.  Getting this wrong assigns
     * the write to a source and drops the true destination (the
     * kadd/kunpck/vpermil2 defect class).
     */
    uint8_t dst_reg_idx = UINT8_MAX;
    if (!have_access_info && opcode_first_is_dst[out->opcode]) {
        for (uint8_t i = 0; i < info->n_operands; i++) {
            if (info->operands[i].type != QEMU_PLUGIN_OP_REG) {
                continue;
            }
            dst_reg_idx = i;
            if (trace_isa != TRACE_ISA_X86) {
                break;          /* dest-first: first REG operand */
            }                   /* AT&T: last REG operand wins */
        }
    }
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
                if (i == dst_reg_idx) {
                    add_dst_cap_reg(out, out_names, op->reg_id);
                } else {
                    add_src_cap_reg(out, out_names, op->reg_id);
                }
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
            /*
             * The NAME is the class; the VALUE is the register the
             * operand names (see qemu_reg_for_sysreg).  The
             * class-level index remains the fallback for every
             * register that resolver cannot place.
             */
            const QemuRegKey *sys_key = qemu_reg_for_sysreg(op->reg_name);
            if (!sys_key) {
                sys_key = qemu_reg_for_generic(gen);
            }
            if (op->access & QEMU_PLUGIN_OP_ACC_READ) {
                add_src_reg(out, out_names, gen, sys_key);
            }
            if (op->access & QEMU_PLUGIN_OP_ACC_WRITE) {
                add_dst_reg(out, out_names, gen, sys_key);
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
             * An INTERIM count, and it does not reach the wire.
             * qdep_apply() runs after this walk and after every refiner
             * and overwrites both totals with the number of memory
             * ACCESS RECORDS QEMU's own emitters stated -- see
             * champsim_tracer_qdep.h.  What the walk still decides is
             * the dep-mask layout the refiners write into
             * (loads at bits [n_src_regs, n_src_regs+max_dep_loads);
             * stores feed store_data_dep_mask[max_dep_stores]), which
             * qdep_apply() then re-seats onto its own count.  LEA /
             * prefetch-hint MEM operands lack both READ and WRITE — no
             * real memop, don't count.
             *
             * THIS IS A COUNT OF STATIC MEMORY OPERANDS, NOT OF
             * ACCESSES, and the runtime count is routinely LARGER.  One
             * operand expands into as many architectural accesses as the
             * form performs: `ld4 {v0.16b-v3.16b}, [x1]` is one Capstone
             * MEM operand and was OBSERVED publishing 64 memops covering
             * exactly 0x4919c0..0x4919ff, with `Memops over slot ceiling`
             * and `CP orphan memops dropped` both 0
             * (cst_runs/p3/arc3/staticdyn).  The comment that used to sit
             * here said the runtime count could be smaller "never
             * larger", which contradicted the header that defines these
             * fields — champsim_tracer_mnemonics.h says in as many words
             * that they are "deliberately NOT the same quantity" and
             * names x86 XSAVEOPT, one static store operand issuing 88
             * stores.  The header is right; the invariant was never true.
             *
             * The array this sizes is the per-STATIC-OPERAND address
             * dependency (load_addr_dep_mask[] / store_addr_dep_mask[]),
             * and one mask describes every access the operand expands
             * into, because they all compute their address from the same
             * input registers.  The per-ACCESS stream rides
             * CST_FID_N_LOADS / CST_FID_N_STORES up to
             * CST_FID_SLOT_COUNT, whose overflow has its own must-be-0
             * counter (stats' memops_over_slot_ceiling).
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
            /*
             * MIPS branches do not write $at, and LLVM's MIPS tables say
             * they do.  Every conditional branch -- `bne`, `beq`, `bgez`,
             * `bltz`, `blez`, `bgtz`, and the `b` macro -- carries an
             * implicit definition of AT, which Capstone reports verbatim in
             * regs_write.  Both decoders agree because both read the same
             * table: `isaxcheck --isa=mipsel --hex=feff0915` prints WR{r1}
             * on the Capstone line AND on the LLVM MC line, for
             * `bne $t0, $t1`.  The implicit def is there for the
             * long-branch expansion, where the ASSEMBLER may clobber $at
             * while rewriting an out-of-range branch into a jump -- but
             * that rewrite emits its own instructions, and the branch
             * itself never touches the register.
             *
             * Published, this is a destination write that did not happen:
             * it manufactures a WAW edge against every real producer of
             * $at and a RAW edge into every consumer.  It measures as
             * TRACER-SUPERSET, which is why nothing caught it until an
             * execution reference was put beside the trace -- gem5 names
             * no destination for these instructions, on all seven mipsel
             * branch forms in `arc3_cov/gem5`.
             *
             * Upstream: LLVM's MIPS branch instruction definitions should
             * not carry `Defs = [AT]`; the expansion that clobbers it is
             * the assembler's, not the instruction's.  Dropped here, at the
             * boundary, because the register table cannot express it -- the
             * table is keyed by REGISTER and the discriminator is the
             * INSTRUCTION.  Revisit on a Capstone bump.
             */
            if (trace_isa == TRACE_ISA_MIPS &&
                out->branch_type != BRANCH_NONE) {
                const RegClassification *rc =
                    lookup_reg_class(info->regs_write_id[i]);
                if (rc && !rc->n_regs && rc->reg_id == REG_GPR1) {
                    continue;
                }
            }
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
     * A MEMOP THE TRACE PUBLISHES MUST BE A MEMOP THE TEMPLATE CLAIMS.
     *
     * The synthetic-EA class -- prefetch hints, cache maintenance by
     * address, TLB maintenance by address -- performs no access QEMU's
     * translation emits, so Capstone leaves the access flags on its MEM
     * operand empty and the walk above allocates nothing.  The execution
     * path does not agree: vcpu_insn_synth_ea_cb computes the address and
     * g_mem_recorder.record_synthetic_load() puts an address-only memop on
     * the wire for it.  Left as it was, the template said `loads=0` for an
     * instruction whose entries carry a load, and a consumer sizing its
     * dependency lane mask from that claim is given less than the guest
     * did -- the one direction of disagreement this decoder is not allowed
     * to have.
     *
     * The slot is a LOAD slot because that is the direction the recorder
     * mints and the wire format has no third one; the memop carries an
     * address and no data (data_size 0), which is exactly what `PRFM` and
     * mipsel `PREF` have always published.  Nothing here claims the
     * instruction reads memory: MIPS `SYNCI` lowers to a bare
     * `ctx->base.is_jmp = DISAS_STOP` (target/mips/tcg/translate.c:14403)
     * and AArch64 `DC CVAU` / `IC IVAU` are ARM_CP_NOP
     * (target/arm/helper.c:5259-5310) -- no data crosses the interface in
     * either direction, and the record exists so the cache model that
     * consumes these traces learns WHICH LINE was operated on.
     *
     * Only the flagless operand qualifies.  A prefetch whose MEM operand
     * Capstone does flag READ (mipsel `PREF`, AArch64 `PRFM`) already
     * owns its slot, and allocating a second would double-count the one
     * memop the callback mints.
     */
    if (const qemu_plugin_operand *sea_op =
            synthetic_ea_slotless_mem_operand(info, out->opcode)) {
        if (out->max_dep_loads < MAX_LOADS) {
            uint64_t addr_mask = 0;
            addr_mask |= add_src_cap_reg(out, out_names, sea_op->reg_id);
            addr_mask |= add_src_cap_reg(out, out_names, sea_op->index_id);
            addr_mask |= add_src_cap_reg(out, out_names, sea_op->segment_id);
            out->load_addr_dep_mask[out->max_dep_loads] = addr_mask;
            out->max_dep_loads++;
            out->has_addr_deps = true;
        }
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
    if (cls && cls->dep_refine && !g_dep_refine_suppressed) {
        cls->dep_refine(info, out);
    }
}

/*
 * Which refiner a row carries, by name, and the switch that withholds it.
 *
 * The names are taken from the function pointers themselves rather than from
 * a string in the table, so the list cannot drift away from what actually
 * runs: a refiner that is added and not listed here reports "dep_?" and is
 * visible as an unnamed row in the measurement, which is the failure mode to
 * prefer over a stale name that silently mislabels a verdict.
 */
/*
 * THREAD-LOCAL, and it has to be.  Template build and the instrument's second
 * decode both run at translation time, and under MTTCG two vCPUs translate at
 * once -- a process-wide flag would let one thread's measurement withhold the
 * refiner from another thread's real template, silently, in exactly the window
 * the measurement is open.  Per-thread, the suppression cannot leave the
 * thread that asked for it.
 */
thread_local bool g_dep_refine_suppressed = false;

void dep_refine_set_suppressed(bool on)
{
    g_dep_refine_suppressed = on;
}

const char *dep_refine_name_for(const qemu_plugin_insn_info *info)
{
    uint8_t op = 0, br = 0;
    uint16_t fl = 0;
    const InsnClassification *cls = classify_insn_id(info, &op, &br, &fl);
    if (!cls || !cls->dep_refine) {
        return nullptr;
    }
    static const struct { InsnDepRefineFn fn; const char *name; } kTab[] = {
        { dep_passthrough,                  "dep_passthrough" },
        { dep_lea,                          "dep_lea" },
        { dep_x86_stack_push,               "dep_x86_stack_push" },
        { dep_x86_stack_pop,                "dep_x86_stack_pop" },
        { dep_vec_struct_store,             "dep_vec_struct_store" },
    };
    for (const auto &e : kTab) {
        if (e.fn == cls->dep_refine) {
            return e.name;
        }
    }
    return "dep_?";
}

/*
 * Synthetic-EA decoder for prefetch / cache-flush / TLB-flush insns
 * whose TCG translation emits no memop.  Returns true (fills @out) when
 * @opcode is a memory-hint class AND the insn carries a Capstone MEM
 * operand we can compute an EA from; false otherwise (@out zeroed).
 * For x86 RIP-relative (PC-relative base) the base reg is dropped and
 * the absolute next-insn-PC folded into the displacement — correct and
 * avoids a needless register read at exec time.
 *
 * GEN_OP_FENCE joins the set on a narrower rule: only when the MEM
 * operand carries NEITHER read NOR write access.  Address-based cache
 * maintenance is spelled as a fence on some targets — MIPS `synci`
 * names an effective address and binutils flags it STORE_MEM, yet the
 * classifier calls it a fence, so its address was recorded nowhere.
 * The access-flag condition is what keeps the widening honest: x86's
 * `invept` / `invpcid` / `invvpid` are also fences with a MEM operand,
 * but that operand is a real descriptor READ that already has a static
 * slot and a runtime memop, and minting a second, synthetic access for
 * it would double-count.  Measured across all four opcode spaces, the
 * pair of conditions selects exactly one row (mipsel `synci`) and
 * leaves every other fence — 9 of 10 on aarch64, 8 of 8 on riscv64,
 * 6 of 9 on x86_64, 3 of 4 on mipsel with no MEM operand at all —
 * untouched.
 */
bool decode_synthetic_ea(const qemu_plugin_insn_info *info,
                         uint8_t opcode,
                         uint64_t pc,
                         uint8_t insn_size,
                         SyntheticEAInfo *out)
{
    memset(out, 0, sizeof(*out));
    bool hint_class = opcode == GEN_OP_PREFETCH ||
                      opcode == GEN_OP_CACHE_FLUSH ||
                      opcode == GEN_OP_TLB_FLUSH;
    if (!info || (!hint_class && opcode != GEN_OP_FENCE)) {
        return false;
    }
    for (uint8_t i = 0; i < info->n_operands; i++) {
        const qemu_plugin_operand *op = &info->operands[i];
        if (op->type != QEMU_PLUGIN_OP_MEM) {
            continue;
        }
        if (!hint_class &&
            (op->access & (QEMU_PLUGIN_OP_ACC_READ |
                           QEMU_PLUGIN_OP_ACC_WRITE))) {
            continue;   /* a real access, already counted; see above */
        }
        const RegClassification *base_rc = lookup_reg_class(op->reg_id);
        const RegClassification *index_rc = lookup_reg_class(op->index_id);
        bool base_is_pc =
            base_rc && base_rc->n_regs == 0 && base_rc->reg_id == REG_PC;
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
