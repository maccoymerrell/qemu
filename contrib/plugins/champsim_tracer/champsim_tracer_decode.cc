/*
 * Wrong-Path Tracing Plugin — Capstone detail → ISA-agnostic decode.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <array>
#include <atomic>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "champsim_tracer.h"
#include "champsim_tracer_qdep.h"
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
        if (row->tier == QREG_PREDICATED || row->tier == QREG_DECLARED) {
            /*
             * A register the running CPU may not expose at all cannot
             * stand for its class's value: it resolves to a null handle,
             * publishes a width-0 field that reads back as zero, and --
             * because the index keeps at most one member per class --
             * would displace a member that IS exposed.  RISC-V's 363
             * predicate-gated CSRs would otherwise take REG_SYSID from
             * `vlenb` and hand it to `marchid`.  The row is still read
             * by generic_for_qemu_name(), which is what it is for.
             *
             * QREG_DECLARED is the same exclusion for the same reason one
             * step earlier: the register is outside the stub's namespace
             * ALWAYS, not just on some CPUs, so its key resolves to a
             * null handle on every machine.  aarch64 is the live case --
             * `fpsr_qc` and the eight `fp_status<n>` rows would otherwise
             * take REG_FCSR from `fpsr`, and `svcr` REG_VCTRL from `vg`.
             */
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

/*
 * FIELD-INSIDE-A-REGISTER: the key whose VALUE a snapshot must carry.
 *
 * Some architectural registers are not registers beside their
 * neighbours but named FIELDS of a wider one -- RISC-V fflags and frm
 * inside fcsr, vxsat and vxrm inside vcsr.  The generic vocabulary folds
 * the whole group onto one id (REG_FCSR) because that is the dependency
 * a consumer schedules against, and the wire has no discriminator to say
 * which member a given snapshot was taken at.  Publishing the field's
 * own content therefore makes one wire name carry three registers'
 * histories at three granularities, and the guest's own readback of the
 * container disagrees with every field row -- R13/Spike measured
 * %fcsr[0x1] published where `csrr fcsr` next returned 0x20, and
 * %fcsr[0x18] where it returned 0x38 (item #277).
 *
 * So the VALUE published for a field is the CONTAINER's.  One wire name,
 * one register's history, and the register the guest can read back.  The
 * identity is untouched: the member still folds to REG_FCSR.
 *
 * Naming the member on the wire instead is the other repair and it is an
 * EPOCH change (a per-slot member discriminator the format has no room
 * for while frozen); it is filed for the next epoch list rather than
 * approximated here.
 *
 * When the ISA has no such nesting -- x86 fctrl/fstat/ftag/mxcsr,
 * AArch64 fpcr/fpsr and MIPS fcr31 are each whole registers, MEASURED,
 * not assumed -- sysreg_value_container is NULL and every key passes
 * through untouched.
 */
static GHashTable *g_value_container_keys;   /* "feature\0name" -> QemuRegKey * */

/*
 * qemu_plugin_get_registers() asserts on `current_cpu`, so it may only be
 * called from a vCPU context.  The key producers below run at install
 * time too -- the generic-ID reverse index and the width-0 REGFILE
 * pinning both resolve keys before any vCPU exists -- so the descriptor
 * list is off limits until a vCPU has reported in.  vcpu_init_cb flips
 * this; before it does, the exposure question has no answer, which is
 * NOT the same as "QEMU does not carry it".
 */
static bool g_reg_namespace_ready;

void cst_reg_namespace_ready(void)
{
    g_reg_namespace_ready = true;
}

/*
 * Tri-state form of sysreg_name_exposed(): 1 present, 0 absent,
 * -1 the descriptor list is not reachable yet so the question has no
 * answer.  The third value exists so a redirect declined before any vCPU
 * has registers is never counted as a register QEMU does not carry.
 * Caller holds g_sysreg_key_lock.
 */
static int sysreg_name_exposure(const char *name)
{
    if (!g_reg_namespace_ready) {
        return -1;
    }
    if (!g_sysreg_exposed) {
        g_autoptr(GArray) probe = qemu_plugin_get_registers();
        if (!probe || probe->len == 0) {
            return -1;
        }
    }
    return sysreg_name_exposed(name) ? 1 : 0;
}

static const QemuRegKey *qemu_reg_value_key(const QemuRegKey *key)
{
    if (!qemu_reg_key_valid(key)) {
        return key;
    }
    SysregValueContainerFn fn = isa_properties[trace_isa].sysreg_value_container;
    if (!fn) {
        return key;
    }
    const char *container = fn(key->name);
    if (!container || cst_str_eq(container, key->name)) {
        return key;
    }

    g_mutex_lock(&g_sysreg_key_lock);
    int exposed = sysreg_name_exposure(container);
    if (exposed != 1) {
        g_mutex_unlock(&g_sysreg_key_lock);
        /*
         * The container is not in QEMU's descriptor list, so redirecting
         * would publish a width-0 field -- strictly worse than the
         * member's own value.  Keep the member and SAY SO: a silent
         * fallback here would be a fold-value defect that reads as
         * fixed.  exposed == -1 (list not up yet) is not a refusal and
         * is not counted.
         */
        if (exposed == 0) {
            g_stats.reg_value_container_unresolved++;
        }
        return key;
    }
    if (!g_value_container_keys) {
        g_value_container_keys = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                       g_free, nullptr);
    }
    g_autofree char *lookup = g_strdup_printf("%s\n%s", key->feature, container);
    QemuRegKey *out =
        (QemuRegKey *)g_hash_table_lookup(g_value_container_keys, lookup);
    if (!out) {
        out = g_new0(QemuRegKey, 1);
        out->feature = g_strdup(key->feature);
        out->name = g_strdup(container);
        g_hash_table_insert(g_value_container_keys, g_strdup(lookup), out);
    }
    g_mutex_unlock(&g_sysreg_key_lock);
    return out;
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
    return qemu_reg_value_key(key);
}

static inline const QemuRegKey *qemu_reg_for_generic(uint8_t gen_id)
{
    if (gen_id >= REG_ID_COUNT) {
        return nullptr;
    }
    const QemuRegKey *k = &g_qemu_reg_by_gen[gen_id];
    return qemu_reg_key_valid(k) ? qemu_reg_value_key(k) : nullptr;
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
        return qemu_reg_key_valid(&rc->qemu_reg)
                   ? qemu_reg_value_key(&rc->qemu_reg) : nullptr;
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
 * THE ENUM TABLE'S TWO REGISTER-LIST ENTRY POINTS ARE GONE.
 *
 * `add_src_cap_reg()` and `add_dst_cap_reg()` translated a CAPSTONE REGISTER
 * ID, through `lookup_reg_class()` and the per-ISA `<isa>_reg_class[]` table,
 * into generic register slots on `src_regs[]` / `dst_regs[]`.  They were the
 * only route by which a register reached either published list without QEMU
 * or a survivor row naming it.
 *
 * The write one lost its last caller at bd2848c450 (the operand walk's WRITE
 * arm).  The read one kept ONE caller after f9ce637d94 deleted the read arm:
 * the MEM operand's base / index / segment, folded into
 * `load_addr_dep_mask[]` / `store_addr_dep_mask[]`.  That call is deleted
 * with this comment, and the reason it could be is that qdep_apply() had
 * already taken the whole family: `f->max_dep_loads` / `max_dep_stores` are
 * QEMU's access counts (never the walk's -- see champsim_tracer_qdep.cc's
 * "It never falls back to the operand walk's number"), and EVERY slot below
 * those counts is written from `q->load_addr_regs[]` / `q->store_addr_regs[]`
 * or from the format's all-inputs default.  The walk's mask was overwritten
 * before it could be serialised; what the call still did was ADD the address
 * registers to `src_regs[]`, where reindex_src_for_qemu() keeps a walk-only
 * source as a trailing slot -- a Capstone-sourced register on the wire.
 *
 * MEASURED, both directions, before deleting it.  `qemu-x86_64 /bin/echo hi`
 * at wpdepth=16 under `setarch -R` at matched output-path length: 309,170
 * facts on each arm, CHANGED 0, REAL-LOST 0, REAL-GAIN 0 over 24,100 compared
 * pcs -- so no address mask and no source list moved.  The address census on
 * the same pair is identical to the row: 10,452 accesses with "QEMU stated
 * every access's address and the block carries them", 0 partial, 0 refused,
 * and "QEMU addresses STATED minus CARRIED" 0.  The other three ISAs read the
 * same shape under `validator all --seed 4242` (a64 221, rv 221, mipsel 442,
 * all STATED-and-CARRIED, 0 refused), which is the arm that would have to
 * move if a walk-supplied register had been holding a mask up: a register
 * absent from `src_regs[]` makes `regs_to_mask()` refuse the slot by name.
 */

/* OR @lane into every src_regs[] slot @cap_id maps to.  Per-operand
 * lane-mask assignment: scalar operands keep slot mask 0, only the
 * vec-register operands the caller iterates get lanes. */
/*
 * RECORD ONE REGISTER'S LANE SETS, keyed on the register (see InsnFields::
 * lane_carry_reg).  ORed, because one encoding can name the same register
 * in two operands -- `punpcklqdq %xmm1,%xmm1` -- and each contributes.
 *
 * The slot writes below stay, and they are not redundant with this: the
 * refiners that run between the walk and the seating identify vec-value
 * operands by src/dst_lane_mask[i] != 0, and they read the slots.  The
 * carry is what survives to the wire.
 */
static void lane_carry_or(InsnFields *f, uint8_t gen,
                          uint64_t src_lane, uint64_t dst_lane)
{
    if (gen == REG_NONE || !f->lane_carry_reg) {
        return;
    }
    for (uint8_t i = 0; i < f->n_lane_carry; i++) {
        if (f->lane_carry_reg[i] == gen) {
            f->lane_carry_src[i] |= src_lane;
            f->lane_carry_dst[i] |= dst_lane;
            return;
        }
    }
    if (f->n_lane_carry >= MAX_SRC_REGS) {
        return;
    }
    uint8_t k = f->n_lane_carry++;
    f->lane_carry_reg[k] = gen;
    f->lane_carry_src[k] = src_lane;
    f->lane_carry_dst[k] = dst_lane;
}

/*
 * WHICH REGISTER FILES CARRY LANES, asked of the generic register the
 * PUBLISHED list holds -- not of a Capstone operand.
 *
 * A lane set belongs to a register (7c9dfe83c2), and the register lists the
 * wire publishes are QEMU's: `src_regs[]` is seated from QEMU's ordered read
 * list and `dst_regs[]` from its write list, with the operand walk's three
 * arms deleted at f9ce637d94 / bd2848c450 / 431aebed10.  So the question
 * "does this published register hold vector elements" is answerable from the
 * generic id the plugin itself assigned, and the answer does not need the
 * Capstone register enumerator the per-ISA tables used to index.
 *
 * THE TWO FILES ARE BOTH REQUIRED, and which one an ISA uses is a fact of
 * that ISA's register map, not a choice here: aarch64 v0-v31 / z0-z31 and
 * x86 xmm0-15 and riscv v0-v31 are REG_VEC*, while mipsel has NO REG_VEC row
 * at all -- MSA's W registers alias the FP file and are declared REG_FPR*
 * (champsim_tracer_qemu_regs_mips.h), as are riscv's f0-f31 under the FP
 * arrangement forms.  Naming only one file would silently drop every mipsel
 * MSA lane mask.
 *
 * THE INSTRUCTION-LEVEL GATE IS UNCHANGED.  This predicate decides only WHO
 * receives the shape, never WHETHER there is one: `lane_shape_from_operands()`
 * still decides that, and on a row it answers LANE_SHAPE_NONE for -- every
 * scalar x87 and scalar FP form, whose REG_FPR* registers would otherwise
 * qualify here -- nothing below runs at all.
 */
static inline bool generic_reg_carries_lanes(uint8_t gen)
{
    return (gen >= REG_VEC0 && gen < REG_VEC0 + 64) ||
           (gen >= REG_FPR0 && gen < REG_FPR0 + 32);
}

/*
 * SEAT THE SHAPE ON THE PUBLISHED LISTS, BY ROLE.
 *
 * The per-operand loop these replaced read `op->reg_id` -- a Capstone
 * register enumerator -- and mapped it through `lookup_reg_class()` and the
 * 2,043-row per-ISA tables to find which published slots to touch.  That map
 * was the last thing keeping the operand array joined to the wire's register
 * lists, and the join it performed is exactly the one the ROLE already makes:
 * a register on the read list receives the shape's source mask, a register on
 * the write list receives its destination mask.  A read-and-written vector
 * register is on both lists and receives both, which is what the walk's
 * `rd`/`wr` pair produced.
 */
static unsigned seat_src_lanes_one(InsnFields *f, uint64_t lane)
{
    unsigned n = 0;
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        uint8_t gen = f->src_regs[i];
        if (!generic_reg_carries_lanes(gen)) {
            continue;
        }
        f->src_lane_mask[i] |= lane;
        lane_carry_or(f, gen, lane, 0);
        n++;
    }
    return n;
}
static unsigned seat_dst_lanes_one(InsnFields *f, uint64_t lane)
{
    unsigned n = 0;
    for (uint8_t d = 0; d < f->n_dst_regs; d++) {
        uint8_t gen = f->dst_regs[d];
        if (!generic_reg_carries_lanes(gen)) {
            continue;
        }
        f->dst_lane_mask[d] |= lane;
        lane_carry_or(f, gen, 0, lane);
        n++;
    }
    return n;
}

/*
 * THE SECOND HALF OF THE LANE PROGRAM -- run it after qdep_apply().
 *
 * Called from the template build loop once QEMU's read and write lists are
 * in `f`, and doing nothing on a row whose classification produced no shape.
 *
 * IT DOES NOT DECIDE `has_vec_lanes`.  That flag is the CP-V census's
 * denominator and the wire's CST_INSN_FLAG_VEC, and it answers "is this a
 * vector row", which the classification already knew; deciding it here on
 * whether a register happened to receive a mask would have retracted it from
 * every structured aarch64 load whose destination list QEMU leaves empty
 * (`ld3` / `ld4` at p_simd, measured: 12 rows losing the flag).  The flag is
 * set where the shape is computed, from the same fact the deleted per-operand
 * loop used.
 */
void seat_vec_lanes(InsnFields *f)
{
    if (!f || !f->lane_seed_valid) {
        return;
    }
    seat_src_lanes_one(f, f->lane_seed_src);
    seat_dst_lanes_one(f, f->lane_seed_dst);
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
/*
 * Rows whose class QEMU's own decode RULE states, and which nothing
 * independent has yet been read against -- see qemu_ident_classify() in
 * champsim_tracer.h.  DECIDED, not a survivor: under R20 the statement IS
 * the classification, and a tier that carries the answer and is refused
 * anyway publishes a disassembler's opinion over the emulator's own.
 * Counted apart from QID_VERIFIED so the census keeps saying how much of
 * the decided population has an independent reading behind it.
 */
static std::atomic<uint64_t> g_qid_decided_stated{0};
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
 * ALL FOUR are flipped.  riscv64 and mipsel were held, and the hold was
 * a MEASURED CORPUS GAP rather than a design boundary: the generator
 * decides a row's tier from the spellings it OBSERVED decoding through
 * that rule, and two rules had been observed under one spelling each
 * while a second spelling reaches them --
 *
 *   translate_mips/OPC_SLL  observed only as `sll`; `ssnop` is
 *                           `sll $zero,$zero,1` and reaches the same rule
 *   decode_insn32/ori       observed only as `ori`; Zicbop
 *                           `prefetch.r/w/i` are `ori x0,rs1,imm`
 *
 * -- with both rows carrying cap_split=false, so nothing in the table
 * said the join was partial.  The hold lifted by WIDENING THE CORPUS,
 * not by editing a row: the validator's own --coverage workload decodes
 * `ssnop` and all three Zicbop prefetches, and adding it to the pair
 * census turns both rows into QID_SPLIT -- rows that state they do not
 * classify -- which makes them survivors on the Capstone answer they
 * already publish.  A third row moved with them, `translate_mips/OPC_JR`
 * (jr and jr.hb differ in .dep_refine), for the same reason and to the
 * same effect.
 *
 * ONE CORRECTION TO THE RECORD, because it was stated the other way and
 * a corpus fact has to be exact: a plain MIPS `nop` IS `sll $zero,
 * $zero,0` architecturally, but it is NOT a second spelling AT THIS
 * BOUNDARY.  Capstone 6 reports it under MIPS_INS_SLL and carries `nop`
 * in alias_id, and the pair census is keyed on insn_id, so a nop and an
 * sll arrive as the same Capstone constant.  MIPS_INS_NOP appears
 * nowhere in the whole corpus; MIPS_INS_SSNOP is what splits the row,
 * and ssnop is a distinct encoding rather than an alias.
 *
 * WHAT THE FLIP DOES NOT ORPHAN on these two ISAs, stated because J7
 * asks and the answer here is "nothing": QID_BRANCH_CLASS -- the table
 * of transfer classes read off QEMU's own .decode files -- carries no
 * riscv or mips entry at all, so no row on either ISA states a branch
 * class from a source independent of Capstone.  Every surviving
 * Capstone read in refine_alias_fields() below is either a WITHIN-RULE
 * discriminator (mips `jr $ra` and `bal`, riscv `j`/`jr`/`ret`/`call`
 * -- forms that share one trans_ function with the instruction they are
 * aliases of, and are told apart only by a register field the rule does
 * not carry) or a Capstone register-LIST repair (mips mfhi/mflo
 * accumulator halves, riscv C-extension HINT reads, the aliased link
 * register).  Neither kind is a classification the rule could state, so
 * neither is a second opinion, and deleting one would lose information
 * the wire carries today.
 */
static bool qemu_ident_key_flipped(TraceISA isa)
{
    return isa == TRACE_ISA_X86 || isa == TRACE_ISA_AARCH64 ||
           isa == TRACE_ISA_RISCV || isa == TRACE_ISA_MIPS;
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

const InsnClassification *qemu_ident_classify(uint32_t id)
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
    /*
     * QID_VERIFIED is what QID_OBSERVED became on a table whose classes
     * QEMU's own rules state (R20).  It is admitted on exactly the same
     * terms and counted in the same column, because it is the same
     * population: a rule QEMU was seen decoding through, whose class an
     * independent reading agreed with.  What changed is which of the two
     * is the SOURCE, and that is not something this gate can see.
     */
    case QID_VERIFIED:
    case QID_OBSERVED:
        g_qid_decided_observed.fetch_add(1, std::memory_order_relaxed);
        break;
    /*
     * A STATED row's class is a compile-time property of QEMU's decode
     * rule, read from the rule's own words, so there is nothing an
     * execution could add to it and nothing for this gate to wait for.
     * It is ADMITTED, and counted in a column of its own: what separates
     * it from QID_VERIFIED is whether an independent reading has agreed,
     * which is a fact about the CHECK and not about the answer.
     */
    case QID_STATED:
        g_qid_decided_stated.fetch_add(1, std::memory_order_relaxed);
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
    return &row->cls;
}

uint64_t qemu_ident_decided_observed(void)
{
    return g_qid_decided_observed.load(std::memory_order_relaxed);
}

uint64_t qemu_ident_decided_stated(void)
{
    return g_qid_decided_stated.load(std::memory_order_relaxed);
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

/*
 * THE SHADOW LOOKUP IS GONE, WITH THE TABLE IT WAS WATCHING.
 *
 * What stood here was the A/B that had to pass before the four
 * champsim_tracer_mnemonics_<isa>.h classification tables could be
 * deleted: every instruction was classified TWICE -- once by QEMU's
 * decode identity and once by the Capstone-enum row -- and the two
 * answers compared per column, with the disagreeing signatures named
 * and the ENUM-PUBLISHED count carried as the deletion bar.
 *
 * THE BAR IS MET, AND THE INSTRUMENT THAT SAYS SO IS NOT THIS ONE.
 * `arc3_cov/instruments/enumocc.py`, over the whole enumerated encoding
 * population on all four ISAs in both wp arms, reads
 * `ENUM-OCCUPANCY total=0 key=STATED`: no encoding anywhere has the enum
 * row as its published classification.  It reads the STATED key
 * (`IDK`: QEMU / ENUM / NONE) rather than inferring it from a
 * coincidence of two columns, and it REFUSES -- rather than reporting 0
 * -- on a corpus that is absent, empty, or not the mechanism corpus,
 * which is the control that makes its zero mean something.
 *
 * An A/B needs two answers.  With the enum key retired there is one, so
 * this comparison is not weakened, it has no second operand: it would
 * report "no enum row for this insn_id at all" for every instruction in
 * every run, which reads like a measurement and is not one.  It goes
 * with its subject.
 */

/*
 * THE LAST ROUTE TO THE ENUM TABLE IS CLOSED, AND `decode_id == 0` NO
 * LONGER HAS A SECOND ANSWER BEHIND IT.
 *
 * With the STATED tier admitted, every reason a decode identity could
 * carry no class -- SPLIT, NAME_MATCHED, NONE, an id with no row -- reads
 * 0 on all four targets.  What was left was `decode_id == 0`: QEMU
 * exported NO identity, and the Capstone-enum row answered instead.  That
 * route is what `enumocc.py` counts, and it counts 0 on all four ISAs in
 * both wp arms -- so nothing is re-keyed by removing it, and nothing that
 * was published stops being published.
 *
 * TWO MECHANISMS EMPTIED IT, EACH AT ITS OWN SOURCE, and they are named
 * because a zero with no cause is not a proof:
 *
 *   mipsel  94,704 -> 0   `mips_ident_fault()` DISCARDED a committed
 *                         identity at EXCP_RI / CpU / DSPDIS / MSADIS; a
 *                         decline is a decision and the arm now states it
 *                         (d8466387e9).
 *   x86_64   1,459 -> 0   `decode_insn()` returning false is "no rule
 *                         matched" by the other door -- validate_sse_prefix,
 *                         X86_TYPE_C/D/S/R/M -- and it took `goto
 *                         illegal_op`, which set no flag (cf6bf3b64f).
 *
 * aarch64 and riscv64 were already 0.  The aarch64 `udf` floor this note
 * used to describe as "the whole live dependency on the four
 * champsim_tracer_mnemonics_<isa>.h tables" is gone with D14 (7b23579707):
 * there are no `udf` rows in the corpus and `00000000` is REFUSED.
 *
 * What remains, and is counted below, is a row that would once have been
 * quietly answered by the enum table and now publishes GEN_OP_UNKNOWN.
 */
static std::atomic<uint64_t> g_qid_enum_no_ident{0};
/*
 * MUST BE 0.  An identity WAS exported, and the row for it still carries
 * no class.  Before the admission wave this was the ordinary case and the
 * Capstone row quietly answered for it; now it is a defect with a
 * generator that should have refused to emit the table, so it is REFUSED
 * at the point of use rather than papered over -- the instruction
 * publishes GEN_OP_UNKNOWN and says so in the sidecar.
 *
 * Falling back here would be the failure mode this whole arc is against:
 * a second, quieter answer arriving from the key that is being retired,
 * on exactly the rows nobody has looked at.
 */
static std::atomic<uint64_t> g_qid_abstain_refused{0};

uint64_t qemu_ident_enum_no_ident(void)
{
    return g_qid_enum_no_ident.load(std::memory_order_relaxed);
}

uint64_t qemu_ident_abstain_refused(void)
{
    return g_qid_abstain_refused.load(std::memory_order_relaxed);
}

/*
 * WHICH KEY ANSWERED, as a word, for the per-encoding record -- FINDING
 * 97 / the enum-table retirement.
 *
 * The occupancy census (enumocc.py) has to say who the enum table is still
 * the classification for, and it had to INFER that from two corpus columns:
 * `decode_id == 0` and a published opcode that is not GEN_OP_UNKNOWN.  The
 * inference is not the condition.  The condition below is
 * `q == nullptr && decode_id == 0 && cap != nullptr`, and a row where
 * QEMU's identity DID answer for a zero decode id satisfies the inference
 * while the enum table answered nothing -- counted as an occupant, it makes
 * the retirement look more expensive than it is, and no column could tell
 * the two apart.  So the key states itself here, where the choice is made,
 * and the census reads a statement instead of guessing from a coincidence.
 */
const char *qid_key_name(uint8_t key)
{
    switch (key) {
    case QID_KEY_QEMU: return "QEMU";
    case QID_KEY_NONE: return "NONE";
    default:           return "-";
    }
}

static const InsnClassification *classify_insn_id(
    const qemu_plugin_insn_info *info,
    uint8_t *opcode, uint8_t *branch_type, uint16_t *flags,
    uint8_t *key = nullptr)
{
    const InsnClassification *q = qemu_ident_classify(info->decode_id);
    if (q) {
        *opcode = q->opcode;
        *branch_type = q->branch_type;
        *flags = q->flags;
        if (key) {
            *key = QID_KEY_QEMU;
        }
        return q;
    }

    if (info->decode_id == 0) {
        /*
         * THE ROW THE ENUM TABLE USED TO ANSWER FOR.  It is still counted,
         * under the same name, so the retirement's own cost stays visible:
         * what used to return the Capstone row here now publishes
         * GEN_OP_UNKNOWN.  The occupancy census reads 0 for this
         * population over the whole enumerated encoding space, so the
         * counter is a tripwire on a route that is measured empty rather
         * than a running loss.
         */
        g_qid_enum_no_ident.fetch_add(1, std::memory_order_relaxed);
    } else {
        /*
         * Counted here and reported as a must-be-0 row; the SIDECAR line
         * comes from the caller, which already warns on every instruction
         * it publishes as GEN_OP_UNKNOWN.  Warning again here would double
         * both the log and the acceptance counter that reads it, which is
         * the defect the note on warn_unknown_instruction describes.
         */
        g_qid_abstain_refused.fetch_add(1, std::memory_order_relaxed);
    }

    *opcode = GEN_OP_UNKNOWN;
    *branch_type = BRANCH_NONE;
    *flags = MF_NONE;
    if (key) {
        *key = QID_KEY_NONE;
    }
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
         * THE mfhi / mflo ACCUMULATOR-HALF COMPACTION IS GONE.
         *
         * It walked `src_regs[]` dropping REG_ACC<n> from an `mfhi` and
         * REG_ACCHI<n> from an `mflo`, because Capstone 6.0.0-Alpha7 reports
         * both move-from forms as reading the WHOLE pair (MIPS_REG_AC<n>)
         * while the generic space splits the halves.  That repair was over
         * the walk's read list, which f9ce637d94 deleted: the loop runs over
         * zero entries and removes nothing.
         *
         * The fact it repaired belongs to QEMU now and is already right
         * there -- `gen_HILO()` reads `cpu_HI[acc]` for an mfhi and
         * `cpu_LO[acc]` for an mflo (target/mips/tcg/translate.c), two
         * distinct env fields with two distinct generic words, so the read
         * list QEMU states names one half and not the pair.  Leaving an
         * inert repair in place would be a second opinion with no subject.
         */
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
         * THE C-EXTENSION HINT READ-CLEAR IS GONE, AND SO IS THE
         * ALIASED-LINK FIXUP BELOW IT.  Both asked the OPERAND WALK a
         * question -- "did the walk put a destination here?", "did it put a
         * source here?" -- and with the read arm deleted (f9ce637d94) and
         * the write arm deleted (bd2848c450) the answer is NO for every
         * instruction on every ISA.  A guard that is universally true is not
         * a guard; `n_dst_regs == 0` had stopped meaning "Capstone named no
         * destination" and started meaning nothing at all.
         *
         * The HINT arm zeroed `src_regs[]` because Capstone left a READ on
         * an encoding the unprivileged spec says modifies no architectural
         * state.  There is no such read to clear: `src_regs[]` is empty
         * here on every path, and QEMU's own read list -- seated later by
         * reindex_src_for_qemu() -- is what the wire publishes.  If QEMU
         * states a read for a HINT, THAT is the fact to argue with, at
         * QEMU's decoder, and it is not this arm's to erase.
         */
        /*
         * The branch TAXONOMY stays: one Capstone id covers jal / j /
         * call / tail and jalr / jr / ret, and the printed alias is what
         * separates a call from a jump from a return.  It writes
         * branch_type only, which is classification, not dataflow.
         */
        if (!strcmp(m, "jal") || !strcmp(m, "c_jal") ||
            !strcmp(m, "call") || !strcmp(m, "tail")) {
            out->branch_type = BRANCH_DIRECT_CALL;
        } else if (!strcmp(m, "jalr") || !strcmp(m, "c_jalr")) {
            out->branch_type = BRANCH_INDIRECT_CALL;
        } else if (!strcmp(m, "j") || !strcmp(m, "c_j") ||
                   !strcmp(m, "jump")) {
            out->branch_type = BRANCH_DIRECT_JUMP;
        } else if (!strcmp(m, "jr") || !strcmp(m, "c_jr")) {
            out->branch_type = BRANCH_INDIRECT_JUMP;
        } else if (!strcmp(m, "ret")) {
            out->branch_type = BRANCH_RETURN;
        }
        /*
         * THE LINK-REGISTER FIXUP IS GONE.  It appended REG_LR to
         * `dst_regs[]` on a call and to `src_regs[]` on a return whenever
         * the walk had left the list empty, because Capstone 6 hides `ra`
         * on the aliased forms -- in neither the operand list nor the
         * (always empty for RISC-V) implicit arrays.
         *
         * IT HAD BECOME UNCONDITIONAL, and that is a fabrication route, not
         * a repair.  With both walk arms deleted the guards are true for
         * every instruction, so every `jal`/`jalr`/`call`/`tail` appended a
         * REG_LR destination that seat_dst_for_qemu() then has to reconcile
         * with QEMU's write rows -- and it REFUSES the whole row when
         * `took != ndst`.  `tail` is `jalr x0`: QEMU states no link write
         * for it, so the fabricated REG_LR would refuse that row's entire
         * destination list the moment a reachable encoding produced one.
         *
         * QEMU states both halves where they happen.  `gen_jal()` writes
         * `gpr[rd]` and the write note names it; `ret` is `jalr x0, ra, 0`
         * and the read of `ra` is in QEMU's ordered read list.  So the fact
         * the fixup existed to restore is on the wire from its own source,
         * and re-adding it here could only ever disagree.
         */
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
                              InsnRegNames *out_names,
                              const QDepInsn *q)
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

    /*
     * ATOMICITY, FROM THE TWO PLACES THE ARCHITECTURE PUTS IT.
     *
     * MF_ATOMIC is the classification's flag, and it covers every family
     * whose indivisibility is in the OPCODE -- aarch64 LDADD/SWP/CAS,
     * RISC-V's AMO/LR/SC, MIPS' LL/SC.  The row is selected by QEMU's own
     * decode identity, so that half needs no second opinion.
     *
     * The other half is the family where atomicity is in a PREFIX and the
     * same mnemonic without it is not atomic: x86's LOCK.  That was
     * `info->has_lock`, the prefix byte as Capstone reported it, and it is
     * now QEMU's -- stated at the decoder arm that adjudicated the lock,
     * after #UD has already been thrown for an encoding that does not accept
     * one.  It is the better fact and not merely the allowed one, because
     * the arm that states it is the arm that DECIDED, whereas the ops it
     * goes on to emit do not carry the answer at all: without CF_PARALLEL
     * TCG lowers an atomic RMW to a plain load-modify-store, so on a
     * single-threaded run `lock xadd` and `xadd` emit the same ops.
     *
     * Without @q there is no statement and no promotion: the prefix-derived
     * claim is exactly what this replaces, so a caller with no QEMU
     * statement gets the opcode half only.
     */
    if ((q && q->x_atomic) || (flags & MF_ATOMIC)) {
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
     * A string operation that re-enters its own address promotes the insn
     * to a self-looping branch.  Each architectural iteration is a
     * tracer-defined true-BB (the chain assembler ends the BB and restarts
     * at the same PC) so the trace structurally identifies the loop instead
     * of one BB with a variable memop count.  Branch type is BRANCH_REP
     * (distinct from BRANCH_COND_DIRECT) so consumers see self-loop
     * semantics (target=self-PC, fall-through=next-PC) at template-parse
     * time.  Conditional: the loop exits when ECX==0 or the REPZ/REPNZ
     * compare breaks.
     *
     * BOTH HALVES ARE QEMU'S, AND THE PREFIX BYTE IS NOT CONSULTED.
     *
     * The self-loop is `QEMU_PLUGIN_CTRL_SELF` with a static successor and
     * no computed one -- "one of the instruction's own goto_tb edges is its
     * own address", which is what the x86 translator emits to continue a
     * REP and is stated in qemu-plugin.h as the structural spelling of this
     * class.  It replaces the boundary's REP-prefix flag, which was the
     * F2/F3 PREFIX BYTE as Capstone reported it, and it is better on
     * the case that byte gets wrong: F2/F3 is overloaded (BND on
     * CALL/RET/JMP/Jcc, XACQUIRE/XRELEASE, `repz ret` padding) and the
     * prefix is present on encodings that do not loop at all.  0be51eb312
     * is the commit that had to repair exactly that, by hand, from the
     * mnemonic table; a successor edge equal to the instruction's own pc
     * cannot make the same mistake, because a `repz ret` has no such edge.
     *
     * rep_memops_per_iter is QEMU's ACCESS COUNT for the instruction --
     * what one translated iteration performs, which is what the body
     * emitter fans a TB-exec's memop stream out by.  It replaces a walk
     * over the Capstone MEM operands' access flags.
     *
     * THE REFUSAL IS EXPLICIT.  Without @q there is no statement, and the
     * promotion is NOT made: a self-loop the tracer invents from a prefix
     * byte is the fabrication this program exists to remove, and the
     * callers that pass nullptr (the IR oracle, the census probes) do not
     * publish a template.  Same for an access list QEMU could not give:
     * `have_list` false leaves the fan-out at 0, which the body emitter
     * reads as "not stated" rather than as "no accesses".
     *
     * Guarded on the classification not already naming a branch, which is
     * unchanged: a resolved CALL/RET/JUMP taxonomy must win over the
     * self-loop promotion, not be overwritten by it.
     */
    const bool q_self_loop =
        q && qemu_ctrl_states_self_loop(q->ctrl_flags);

    if (q_self_loop && out->branch_type == BRANCH_NONE) {
        out->branch_type        = BRANCH_REP;
        out->branch_conditional = true;
        if (q->have_list) {
            unsigned n = (unsigned)q->n_loads + (unsigned)q->n_stores;
            out->rep_memops_per_iter = (uint8_t)(n > 255u ? 255u : n);
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
     * Operand processing.  What survives the walk is the MEM operand's
     * address-register set and the immediate; the register arms are both
     * gone (R14.2 / J7) and so is everything that fed them.
     *
     * THREE DEAD THINGS LEFT WITH THE WRITE ARM and are named because each
     * was load-bearing until it was not.  `opcode_first_is_dst[]` decided,
     * for the ISAs whose Capstone operands carry no access flags, WHICH
     * register operand was the destination -- the kadd/kunpck/vpermil2
     * defect class is what getting it wrong looked like.  `have_access_info`
     * chose between the flags and that positional fallback, excluding the
     * boundary's own appended SYSREG operands so one of them could not
     * switch a whole instruction out of the fallback.  `dst_reg_idx` carried
     * the fallback's answer into the loop.  All three answer "which operand
     * does this instruction WRITE", and QEMU answers that now.
     */
    for (uint8_t i = 0; i < info->n_operands; i++) {
        const qemu_plugin_operand *op = &info->operands[i];

        switch (op->type) {
        case QEMU_PLUGIN_OP_REG:
            /*
             * BOTH ARMS ARE GONE (R14.2 / J7), and the second one is why
             * this case still exists rather than falling to `default`: it
             * is the one place that says so.
             *
             * The READ arm went at f9ce637d94.  qemu_named_regs() seats
             * QEMU's own ordered read list and the survivor rows carry what
             * QEMU does not state, so the call added nothing the wire did
             * not already have -- it only kept a live Capstone route into
             * the source side, which J7 forbids ("Capstone not demoted,
             * Capstone REMOVED ... if you leave it there, you will rely on
             * it").
             *
             * The WRITE arm went here, with the SYSREG arm below and the
             * implicit regs_write[] fold: the wire's destination list is
             * QEMU's write rows, built by seat_dst_for_qemu() and admitted
             * by dst_precheck(), and R10.1's block-epilogue separation is
             * QEMU's own statement (dst_row_seated()).  exec184 measured
             * what removing it cost BEFORE those three existed -- `mov %sp`
             * where the wire published `mov %sp -> %gp5`, `jcc` with no
             * `-> %pc`, every destination on every instruction -- which is
             * the reading that named them.
             */
            break;
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
            /*
             * READ arm deleted with the register one above: a system
             * register the encoding names and the instruction reads is in
             * QEMU's ordered read list where QEMU states it, and in the
             * survivor table where it does not.  The WRITE arm stays with
             * the rest of the destination walk.
             */
            (void)gen; (void)sys_key;
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

    /*
     * THE IMPLICIT-REGISTER FOLD IS GONE, BOTH HALVES.
     *
     * Capstone's regs_read[] was the last route by which a register reached
     * src_regs[] without QEMU or a survivor row saying so (f9ce637d94);
     * regs_write[] was the same for the destination list, and it goes here
     * with the two operand arms.
     *
     * ONE WORKAROUND DIES WITH IT AND IS RECORDED RATHER THAN DROPPED.  LLVM's
     * MIPS tables give every conditional branch -- `bne`, `beq`, `bgez`,
     * `bltz`, `blez`, `bgtz` and the `b` macro -- an implicit definition of
     * $at, which Capstone reports verbatim; both decoders agree because both
     * read the same table (`isaxcheck --isa=mipsel --hex=feff0915` prints
     * WR{r1} on the Capstone line AND the LLVM MC line).  The definition is
     * there for the long-branch expansion, where the ASSEMBLER may clobber
     * $at while rewriting an out-of-range branch into a jump; the branch
     * itself never touches the register, gem5 names no destination for any
     * of the seven forms, and published it manufactured a WAW edge against
     * every real producer of $at and a RAW edge into every consumer.  It
     * measured as TRACER-SUPERSET, which is why nothing caught it until an
     * execution reference was put beside the trace.  The correction was a
     * boundary-side drop because the register table could not express it --
     * keyed by REGISTER, discriminated by INSTRUCTION.  QEMU's write list
     * never contained the row, so there is nothing left to drop.
     */

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
        (void)sea_op;
        if (out->max_dep_loads < MAX_LOADS) {
            uint64_t addr_mask = 0;
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
            /*
             * The shape is a fact of the INSTRUCTION -- one element width,
             * one selected lane -- and it was already computed slot-agnostic
             * above.  The loop it replaces recomputed these same two values
             * once per operand and differed between iterations only in which
             * register it landed on; that join is now the role's.
             */
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
            /*
             * HELD, NOT APPLIED.  The registers this lands on are QEMU's and
             * are not in `out` yet -- qdep_apply() fills the read and write
             * lists after this function returns.  seat_vec_lanes() is called
             * there with the shape these two carry.
             */
            out->lane_seed_valid = true;
            out->lane_seed_src   = src_lane;
            out->lane_seed_dst   = dst_lane;
            /*
             * THE ROW IS A VECTOR ROW, AND THAT IS DECIDED HERE.
             *
             * `sh.lane_bytes` is the element width of the FIRST vector
             * register operand the shape walk found, and
             * lane_shape_from_operands() leaves it 0 on exactly the path
             * where it found none -- the runtime-SEW branch it takes for a
             * RISC-V V form whose width is not static.  So this condition is
             * the same one the deleted per-operand loop applied by setting
             * the flag inside a body it only entered for an operand with a
             * lane width, and it is written from the shape rather than from
             * a second walk of the operand array.
             */
            if (sh.lane_bytes != 0) {
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

const char *dep_refine_name_for(const qemu_plugin_insn_info *info,
                               uint8_t *ident_key)
{
    uint8_t op = 0, br = 0, key = QID_KEY_UNSET;
    uint16_t fl = 0;
    /*
     * ONE classify_insn_id CALL, TWO ANSWERS.  The per-encoding record
     * wants the refiner's name AND which identity key decided the class,
     * and classify_insn_id() is not free of observable effect -- it scores
     * the read-only QID shadow A/B on every call.  Asking twice would
     * double that census for exactly the rows a sweep dumps, which is a
     * measurement changing the number it reports.  So the key rides out of
     * the call that was already being made.
     */
    const InsnClassification *cls =
        classify_insn_id(info, &op, &br, &fl, &key);
    if (ident_key) {
        *ident_key = key;
    }
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
