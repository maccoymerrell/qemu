/*
 * QEMU Plugin API
 *
 * This provides the API that is available to the plugins to interact
 * with QEMU. We have to be careful not to expose internal details of
 * how QEMU works so we abstract out things like translation and
 * instructions to anonymous data types:
 *
 *  qemu_plugin_tb
 *  qemu_plugin_insn
 *  qemu_plugin_register
 *
 * Which can then be passed back into the API to do additional things.
 * As such all the public functions in here are exported in
 * qemu-plugin.h.
 *
 * The general life-cycle of a plugin is:
 *
 *  - plugin is loaded, public qemu_plugin_install called
 *    - the install func registers callbacks for events
 *    - usually an atexit_cb is registered to dump info at the end
 *  - when a registered event occurs the plugin is called
 *     - some events pass additional info
 *     - during translation the plugin can decide to instrument any
 *       instruction
 *  - when QEMU exits all the registered atexit callbacks are called
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019, Linaro
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/plugin.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "tcg/tcg.h"
#include "accel/tcg/cpu-ops.h"
#include "hw/core/cpu.h"
#include "exec/gdbstub.h"
#include "exec/plugin-spec.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "exec/translator.h"
#include "exec/tb-flush.h"
#include "exec/cpu-common.h"
#include "system/cpu-timers.h"
#include "disas/disas.h"
#include "plugin.h"

/* Uninstall and Reset handlers */

void qemu_plugin_uninstall(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb)
{
    plugin_reset_uninstall(id, cb, false);
}

void qemu_plugin_reset(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb)
{
    plugin_reset_uninstall(id, cb, true);
}

void qemu_plugin_request_tb_flush(void)
{
    /* Plugin callbacks run inside a translation (tb_trans) or an
     * executing TB (tb_exec) — contexts where tb_flush's serial-mode
     * synchronous dispatch would reset the code region under an
     * in-flight tb_gen_code.  Always defer: do_tb_flush runs at the
     * vCPU thread-loop safe point, after any plugin excursion unwinds,
     * and fires registered flush callbacks from there.  Callers are
     * expected to be on a vCPU thread (current_cpu set); no-op when
     * tcg_enabled() is false. */
    tb_flush_deferred(current_cpu);
}

/*
 * Plugin Register Functions
 *
 * This allows the plugin to register callbacks for various events
 * during the translation.
 */

void qemu_plugin_register_vcpu_init_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_INIT, cb);
}

void qemu_plugin_register_vcpu_exit_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_EXIT, cb);
}

static bool tb_is_mem_only(void)
{
    return tb_cflags(tcg_ctx->gen_tb) & CF_MEMI_ONLY;
}

void qemu_plugin_register_vcpu_tb_exec_cb(struct qemu_plugin_tb *tb,
                                          qemu_plugin_vcpu_udata_cb_t cb,
                                          enum qemu_plugin_cb_flags flags,
                                          void *udata)
{
    if (!tb_is_mem_only()) {
        plugin_register_dyn_cb__udata(&tb->cbs, cb, flags, udata);
    }
}

void qemu_plugin_register_vcpu_tb_exec_cond_cb(struct qemu_plugin_tb *tb,
                                               qemu_plugin_vcpu_udata_cb_t cb,
                                               enum qemu_plugin_cb_flags flags,
                                               enum qemu_plugin_cond cond,
                                               qemu_plugin_u64 entry,
                                               uint64_t imm,
                                               void *udata)
{
    if (cond == QEMU_PLUGIN_COND_NEVER || tb_is_mem_only()) {
        return;
    }
    if (cond == QEMU_PLUGIN_COND_ALWAYS) {
        qemu_plugin_register_vcpu_tb_exec_cb(tb, cb, flags, udata);
        return;
    }
    plugin_register_dyn_cond_cb__udata(&tb->cbs, cb, flags,
                                       cond, entry, imm, udata);
}

void qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
    struct qemu_plugin_tb *tb,
    enum qemu_plugin_op op,
    qemu_plugin_u64 entry,
    uint64_t imm)
{
    if (!tb_is_mem_only()) {
        plugin_register_inline_op_on_entry(&tb->cbs, 0, op, entry, imm);
    }
}

void qemu_plugin_register_vcpu_insn_exec_cb(struct qemu_plugin_insn *insn,
                                            qemu_plugin_vcpu_udata_cb_t cb,
                                            enum qemu_plugin_cb_flags flags,
                                            void *udata)
{
    if (!tb_is_mem_only()) {
        plugin_register_dyn_cb__udata(&insn->insn_cbs, cb, flags, udata);
    }
}

void qemu_plugin_register_vcpu_insn_exec_cond_cb(
    struct qemu_plugin_insn *insn,
    qemu_plugin_vcpu_udata_cb_t cb,
    enum qemu_plugin_cb_flags flags,
    enum qemu_plugin_cond cond,
    qemu_plugin_u64 entry,
    uint64_t imm,
    void *udata)
{
    if (cond == QEMU_PLUGIN_COND_NEVER || tb_is_mem_only()) {
        return;
    }
    if (cond == QEMU_PLUGIN_COND_ALWAYS) {
        qemu_plugin_register_vcpu_insn_exec_cb(insn, cb, flags, udata);
        return;
    }
    plugin_register_dyn_cond_cb__udata(&insn->insn_cbs, cb, flags,
                                       cond, entry, imm, udata);
}

void qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
    struct qemu_plugin_insn *insn,
    enum qemu_plugin_op op,
    qemu_plugin_u64 entry,
    uint64_t imm)
{
    if (!tb_is_mem_only()) {
        plugin_register_inline_op_on_entry(&insn->insn_cbs, 0, op, entry, imm);
    }
}


/*
 * We always plant memory instrumentation because they don't finalise until
 * after the operation has complete.
 */
void qemu_plugin_register_vcpu_mem_cb(struct qemu_plugin_insn *insn,
                                      qemu_plugin_vcpu_mem_cb_t cb,
                                      enum qemu_plugin_cb_flags flags,
                                      enum qemu_plugin_mem_rw rw,
                                      void *udata)
{
    plugin_register_vcpu_mem_cb(&insn->mem_cbs, cb, flags, rw, udata);
}

void qemu_plugin_register_vcpu_mem_inline_per_vcpu(
    struct qemu_plugin_insn *insn,
    enum qemu_plugin_mem_rw rw,
    enum qemu_plugin_op op,
    qemu_plugin_u64 entry,
    uint64_t imm)
{
    plugin_register_inline_op_on_entry(&insn->mem_cbs, rw, op, entry, imm);
}

void qemu_plugin_register_vcpu_tb_trans_cb(qemu_plugin_id_t id,
                                           qemu_plugin_vcpu_tb_trans_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_TB_TRANS, cb);
}

void qemu_plugin_register_vcpu_syscall_cb(qemu_plugin_id_t id,
                                          qemu_plugin_vcpu_syscall_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_SYSCALL, cb);
}

void
qemu_plugin_register_vcpu_syscall_ret_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_syscall_ret_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_SYSCALL_RET, cb);
}

/*
 * Plugin Queries
 *
 * These are queries that the plugin can make to gauge information
 * from our opaque data types. We do not want to leak internal details
 * here just information useful to the plugin.
 */

/*
 * Translation block information:
 *
 * A plugin can query the virtual address of the start of the block
 * and the number of instructions in it. It can also get access to
 * each translated instruction.
 */

size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb)
{
    return tb->n;
}

uint64_t qemu_plugin_tb_vaddr(const struct qemu_plugin_tb *tb)
{
    const DisasContextBase *db = tcg_ctx->plugin_db;
    return db->pc_first;
}

struct qemu_plugin_insn *
qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t idx)
{
    struct qemu_plugin_insn *insn;
    if (unlikely(idx >= tb->n)) {
        return NULL;
    }
    insn = g_ptr_array_index(tb->insns, idx);
    return insn;
}

/*
 * Instruction information
 *
 * These queries allow the plugin to retrieve information about each
 * instruction being translated.
 */

size_t qemu_plugin_insn_data(const struct qemu_plugin_insn *insn,
                             void *dest, size_t len)
{
    const DisasContextBase *db = tcg_ctx->plugin_db;

    len = MIN(len, insn->len);
    return translator_st(db, dest, insn->vaddr, len) ? len : 0;
}

size_t qemu_plugin_insn_size(const struct qemu_plugin_insn *insn)
{
    return insn->len;
}

uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *insn)
{
    return insn->vaddr;
}

uint64_t qemu_plugin_insn_branch_target_pc(const struct qemu_plugin_insn *insn)
{
    return insn->branch_target_pc;
}

void *qemu_plugin_insn_haddr(const struct qemu_plugin_insn *insn)
{
    const DisasContextBase *db = tcg_ctx->plugin_db;
    vaddr page0_last = db->pc_first | ~qemu_target_page_mask();

    if (db->fake_insn) {
        return NULL;
    }

    /*
     * ??? The return value is not intended for use of host memory,
     * but as a proxy for address space and physical address.
     * Thus we are only interested in the first byte and do not
     * care about spanning pages.
     */
    if (insn->vaddr <= page0_last) {
        if (db->host_addr[0] == NULL) {
            return NULL;
        }
        return db->host_addr[0] + insn->vaddr - db->pc_first;
    } else {
        if (db->host_addr[1] == NULL) {
            return NULL;
        }
        return db->host_addr[1] + insn->vaddr - (page0_last + 1);
    }
}

char *qemu_plugin_insn_disas(const struct qemu_plugin_insn *insn)
{
    return plugin_disas(tcg_ctx->cpu, tcg_ctx->plugin_db,
                        insn->vaddr, insn->len);
}

bool qemu_plugin_insn_detail(const struct qemu_plugin_insn *insn,
                             qemu_plugin_insn_info *info)
{
    return plugin_disas_detail(tcg_ctx->cpu, tcg_ctx->plugin_db,
                               insn->vaddr, insn->len, info);
}

bool qemu_plugin_cap_decode(int cap_arch, unsigned int cap_mode,
                            const uint8_t *data, size_t size,
                            uint64_t pc, qemu_plugin_insn_info *info)
{
    return cap_disas_raw_detail(cap_arch, cap_mode, data, size, pc, info);
}

const char *qemu_plugin_insn_symbol(const struct qemu_plugin_insn *insn)
{
    const char *sym = lookup_symbol(insn->vaddr);
    return sym[0] != 0 ? sym : NULL;
}

/*
 * The memory queries allow the plugin to query information about a
 * memory access.
 */

unsigned qemu_plugin_mem_size_shift(qemu_plugin_meminfo_t info)
{
    MemOp op = get_memop(info);
    return op & MO_SIZE;
}

bool qemu_plugin_mem_is_sign_extended(qemu_plugin_meminfo_t info)
{
    MemOp op = get_memop(info);
    return op & MO_SIGN;
}

bool qemu_plugin_mem_is_big_endian(qemu_plugin_meminfo_t info)
{
    MemOp op = get_memop(info);
    return (op & MO_BSWAP) == MO_BE;
}

bool qemu_plugin_mem_is_store(qemu_plugin_meminfo_t info)
{
    return get_plugin_meminfo_rw(info) & QEMU_PLUGIN_MEM_W;
}

qemu_plugin_mem_value qemu_plugin_mem_get_value(qemu_plugin_meminfo_t info)
{
    uint64_t low = current_cpu->neg.plugin_mem_value_low;
    qemu_plugin_mem_value value;

    switch (qemu_plugin_mem_size_shift(info)) {
    case 0:
        value.type = QEMU_PLUGIN_MEM_VALUE_U8;
        value.data.u8 = (uint8_t)low;
        break;
    case 1:
        value.type = QEMU_PLUGIN_MEM_VALUE_U16;
        value.data.u16 = (uint16_t)low;
        break;
    case 2:
        value.type = QEMU_PLUGIN_MEM_VALUE_U32;
        value.data.u32 = (uint32_t)low;
        break;
    case 3:
        value.type = QEMU_PLUGIN_MEM_VALUE_U64;
        value.data.u64 = low;
        break;
    case 4:
        value.type = QEMU_PLUGIN_MEM_VALUE_U128;
        value.data.u128.low = low;
        value.data.u128.high = current_cpu->neg.plugin_mem_value_high;
        break;
    default:
        g_assert_not_reached();
    }
    return value;
}

int qemu_plugin_num_vcpus(void)
{
    return plugin_num_vcpus();
}

/*
 * Plugin output
 */
void qemu_plugin_outs(const char *string)
{
    qemu_log_mask(CPU_LOG_PLUGIN, "%s", string);
}

bool qemu_plugin_bool_parse(const char *name, const char *value, bool *ret)
{
    return name && value && qapi_bool_parse(name, value, ret, NULL);
}

/*
 * Create register handles.
 *
 * We need to create a handle for each register so the plugin
 * infrastructure can call gdbstub to read a register. They are
 * currently just a pointer encapsulation of the gdb_reg but in
 * future may hold internal plugin state so its important plugin
 * authors are not tempted to treat them as numbers.
 *
 * We also construct a result array with those handles and some
 * ancillary data the plugin might find useful.
 */

static GArray *create_register_handles(GArray *gdbstub_regs)
{
    GArray *find_data = g_array_new(true, true,
                                    sizeof(qemu_plugin_reg_descriptor));

    for (int i = 0; i < gdbstub_regs->len; i++) {
        GDBRegDesc *grd = &g_array_index(gdbstub_regs, GDBRegDesc, i);
        qemu_plugin_reg_descriptor desc;

        /* skip "un-named" regs */
        if (!grd->name) {
            continue;
        }

        /* Create a record for the plugin */
        desc.handle = GINT_TO_POINTER(grd->gdb_reg + 1);
        desc.name = g_intern_string(grd->name);
        desc.feature = g_intern_string(grd->feature_name);
        g_array_append_val(find_data, desc);
    }

    return find_data;
}

GArray *qemu_plugin_get_registers(void)
{
    g_assert(current_cpu);

    g_autoptr(GArray) regs = gdb_get_register_list(current_cpu);
    return create_register_handles(regs);
}

bool qemu_plugin_read_memory_vaddr(uint64_t addr, GByteArray *data, size_t len)
{
    g_assert(current_cpu);

    if (len == 0) {
        return false;
    }

    g_byte_array_set_size(data, len);

    int result = cpu_memory_rw_debug(current_cpu, addr, data->data,
                                     data->len, false);

    if (result < 0) {
        return false;
    }

    /*
     * If in speculative mode, overlay any bytes from the speculative
     * store buffer on top of the data just read from real memory.
     * This provides store-to-load forwarding for plugin API reads.
     */
    if (current_cpu->plugin_spec_mode &&
        current_cpu->plugin_spec_store_buf) {
        /* Overlay speculative bytes; walk by cache line to amortise
         * the hash lookup across (up to 64) bytes within each line. */
        size_t off = 0;
        while (off < len) {
            vaddr cur = addr + off;
            vaddr  line_addr = cur & ~(vaddr)PLUGIN_SPEC_LINE_MASK;
            unsigned idx     = (unsigned)(cur & PLUGIN_SPEC_LINE_MASK);
            unsigned remain  = PLUGIN_SPEC_LINE_SIZE - idx;
            unsigned chunk   = (unsigned)(len - off) < remain
                ? (unsigned)(len - off) : remain;
            PluginSpecLine *line = (PluginSpecLine *)g_hash_table_lookup(
                current_cpu->plugin_spec_store_buf,
                GUINT_TO_POINTER((guintptr)line_addr));
            if (line) {
                uint64_t mask = line->valid_mask >> idx;
                for (unsigned k = 0; k < chunk; k++) {
                    if (mask & ((uint64_t)1 << k)) {
                        data->data[off + k] = line->bytes[idx + k];
                    }
                }
            }
            off += chunk;
        }
    }

    return true;
}

int qemu_plugin_read_register(struct qemu_plugin_register *reg, GByteArray *buf)
{
    g_assert(current_cpu);

    return gdb_read_register(current_cpu, buf, GPOINTER_TO_INT(reg) - 1);
}

int qemu_plugin_write_register(struct qemu_plugin_register *reg,
                               GByteArray *buf)
{
    g_assert(current_cpu);

    return gdb_write_register(current_cpu, buf->data,
                              GPOINTER_TO_INT(reg) - 1);
}

/*
 * CPU state save/restore for speculative execution rollback.
 * Snapshots execution state (up to end_reset_fields) via memcpy,
 * capturing all internal state (lazy flags, FPU, etc.) that the
 * GDB register interface would miss.  Static config (CPUID, features)
 * and externally-managed pointers (timers, buffers) are excluded.
 */
struct qemu_plugin_cpu_state {
    void *arch_state;       /* Raw copy of CPUArchState execution fields */
    size_t arch_state_size; /* offsetof(CPUArchState, end_reset_fields) */
    /*
     * A few CPUState (not CPUArchState) execution fields that a wrong-path
     * walk can dirty and that the arch_state copy above does NOT cover.
     * Without restoring these, a speculative exception/halt leaks to the
     * correct path: the main loop then delivers a spurious exception whose
     * delivery faults against the restored arch state and double/triple-
     * faults the guest (a real reset in system mode).
     */
    int exception_index;
    uint32_t halted;
};

struct qemu_plugin_cpu_state *qemu_plugin_cpu_state_save(void)
{
    g_assert(current_cpu);

    struct qemu_plugin_cpu_state *state = g_new(struct qemu_plugin_cpu_state,
                                                1);
    state->arch_state_size = cpu_plugin_arch_state_size();
    state->arch_state = g_memdup2((void *)(current_cpu + 1),
                                  state->arch_state_size);
    state->exception_index = current_cpu->exception_index;
    state->halted = current_cpu->halted;

    return state;
}

bool qemu_plugin_cpu_state_restore(struct qemu_plugin_cpu_state *state)
{
    g_assert(current_cpu);

    if (!state) {
        return false;
    }

    cpu_plugin_arch_state_restore(state->arch_state, state->arch_state_size);
    current_cpu->exception_index = state->exception_index;
    current_cpu->halted = state->halted;
    return true;
}

void qemu_plugin_cpu_state_free(struct qemu_plugin_cpu_state *state)
{
    if (!state) {
        return;
    }
    g_free(state->arch_state);
    g_free(state);
}

void qemu_plugin_set_pc(uint64_t pc)
{
    g_assert(current_cpu);
    g_assert(current_cpu->cc->set_pc);
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
    /*
     * Diagnostic (#77): a wrong-path PC redirect must only happen inside a
     * speculative excursion (plugin_spec_mode set).  If set_pc runs with the
     * flag OFF, it is steering the REAL guest PC -- a spec-mode escape that
     * corrupts real execution.
     */
    if (unlikely(!current_cpu->plugin_spec_mode) && getenv("CST_SPEC_ESCAPE_DIAG")) {
        fprintf(stderr, "[setpc-real] set_pc(0x%" PRIx64 ") with "
                "plugin_spec_mode=0\n", pc);
    }
#endif
    current_cpu->cc->set_pc(current_cpu, (vaddr)pc);
}

uint64_t qemu_plugin_get_pc(void)
{
    g_assert(current_cpu);
    g_assert(current_cpu->cc->get_pc);
    return (uint64_t)current_cpu->cc->get_pc(current_cpu);
}

/* Fill (priv, asid, mmu_on) from the per-target hook; defaults
 * (0, 0, true) when the target provides none (e.g. *-linux-user, where a
 * process always has a valid address space, so "paging" is effectively
 * on for the purpose of bounding speculative fetches). */
static void plugin_cpu_state(int *priv, uint64_t *asid, bool *mmu_on)
{
    *priv = 0;
    *asid = 0;
    *mmu_on = true;
    g_assert(current_cpu);
    const TCGCPUOps *ops = current_cpu->cc->tcg_ops;
    if (ops && ops->get_plugin_state) {
        ops->get_plugin_state(current_cpu, priv, asid, mmu_on);
    }
}

int qemu_plugin_get_priv_level(void)
{
    int priv;
    uint64_t asid;
    bool mmu_on;
    plugin_cpu_state(&priv, &asid, &mmu_on);
    return priv;
}

uint64_t qemu_plugin_get_addr_space_id(void)
{
    int priv;
    uint64_t asid;
    bool mmu_on;
    plugin_cpu_state(&priv, &asid, &mmu_on);
    return asid;
}

bool qemu_plugin_paging_enabled(void)
{
    int priv;
    uint64_t asid;
    bool mmu_on;
    plugin_cpu_state(&priv, &asid, &mmu_on);
    return mmu_on;
}

bool qemu_plugin_icount_enabled(void)
{
#ifdef CONFIG_USER_ONLY
    return false;
#else
    return icount_enabled();
#endif
}

uint64_t qemu_plugin_get_thread_ptr(void)
{
    g_assert(current_cpu);
    const TCGCPUOps *ops = current_cpu->cc->tcg_ops;
    if (ops && ops->get_plugin_thread_ptr) {
        return ops->get_plugin_thread_ptr(current_cpu);
    }
    return 0;
}

bool qemu_plugin_vaddr_is_kernel(uint64_t vaddr)
{
    /* Defensive: the classification needs the live vCPU's paging config, but
     * a plugin may also consult it from a non-vCPU housekeeping context (e.g.
     * an end-of-run diagnostic).  With no current vCPU there is no address
     * space to classify against — report user-domain rather than abort. */
    if (!current_cpu) {
        return false;
    }
    const TCGCPUOps *ops = current_cpu->cc->tcg_ops;
    if (ops && ops->vaddr_is_kernel) {
        return ops->vaddr_is_kernel(current_cpu, vaddr);
    }
    /* No target classifier (user-mode, or an ISA without a kernel/user VA
     * split visible to the tracer): everything is user-domain. */
    return false;
}

bool qemu_plugin_exec_inline_insn(void)
{
    g_assert(current_cpu);
    return cpu_plugin_exec_inline(current_cpu);
}

bool qemu_plugin_exec_tb(void)
{
    g_assert(current_cpu);
    return cpu_plugin_exec_tb(current_cpu);
}

/*
 * Bump-allocate (or reuse) the PluginSpecLine for @line_addr.  The
 * pool is a flat PluginSpecLine[] that grows on demand and is reset
 * (used = 0) at spec_mode_end — entries from prior simulations are
 * never freed, just overwritten on reuse.  Returns NULL when the
 * sandbox line cap is reached and the line isn't already tracked.
 */
PluginSpecLine *spec_line_get_or_alloc(CPUState *cpu, vaddr line_addr)
{
    PluginSpecLine *line = (PluginSpecLine *)g_hash_table_lookup(
        cpu->plugin_spec_store_buf, GUINT_TO_POINTER((guintptr)line_addr));
    if (line) {
        return line;
    }
    if (cpu->plugin_spec_store_pool_used >= PLUGIN_SPEC_STORE_LINE_MAX) {
        return NULL;
    }
    if (cpu->plugin_spec_store_pool_used >= PLUGIN_SPEC_STORE_SOFT_BUDGET) {
        /* Wild wrong-path store (a garbage-size memop buffered without faulting):
         * flag the excursion for prompt termination by the WP loop
         * (qemu_plugin_spec_store_overflowed).  Keep allocating up to the hard
         * cap meanwhile so the in-flight store is not torn mid-region. */
        cpu->plugin_spec_store_overflow = true;
    }
    if (cpu->plugin_spec_store_pool_used >= cpu->plugin_spec_store_pool_cap) {
        size_t new_cap = cpu->plugin_spec_store_pool_cap
            ? cpu->plugin_spec_store_pool_cap * 2 : 256;
        cpu->plugin_spec_store_pool = g_realloc_n(
            cpu->plugin_spec_store_pool, new_cap, sizeof(PluginSpecLine));
        cpu->plugin_spec_store_pool_cap = new_cap;
    }
    PluginSpecLine *pool = (PluginSpecLine *)cpu->plugin_spec_store_pool;
    line = &pool[cpu->plugin_spec_store_pool_used++];
    line->valid_mask = 0;
    /* bytes[] left uninitialised; valid_mask gates reads, so unused
     * bytes are never observed. */
    g_hash_table_insert(cpu->plugin_spec_store_buf,
                        GUINT_TO_POINTER((guintptr)line_addr), line);
    return line;
}

void qemu_plugin_spec_mode_begin(struct qemu_plugin_cpu_state *saved_state)
{
    g_assert(current_cpu);
    g_assert(!current_cpu->plugin_spec_mode);

    /*
     * Fail-safe host-capability guard.  Wrong-path tracing routes speculative
     * inline stores through the slow-path do_st helpers via CF_FORCE_SLOW so
     * they land in the spec store sandbox instead of real guest RAM.  Only
     * host TCG backends that honour CF_FORCE_SLOW (currently x86/i386)
     * implement that redirection for inline qemu_st; on any other host an
     * inline TLB-hit speculative store would silently commit to guest memory.
     * Refuse loudly at the first spec-mode request rather than corrupt guest
     * RAM, and rather than silently disabling wrong-path tracing (which would
     * leave the caller believing the speculative excursion ran).  On x86 the
     * capability is a compile-time 1, so this collapses to a no-op.
     *
     * Terminate with _exit(): this fires from deep inside the plugin's WP
     * excursion setup (locks held, a half-built speculative session), so the
     * plugin's registered atexit dump must not run against that inconsistent
     * state.  _exit() skips atexit handlers and stdio flush; error_report has
     * already written the diagnostic to the unbuffered stderr.
     */
    if (!TCG_TARGET_HAS_SPEC_FORCE_SLOW) {
        error_report("champsim_tracer wrong-path tracing requires a host TCG "
                     "backend that honors CF_FORCE_SLOW (only x86/i386 hosts); "
                     "on this host speculative stores would corrupt guest "
                     "memory - refusing to enable.");
        _exit(1);
    }

    /* Slow-path memory routing is enforced by CF_FORCE_SLOW on
     * spec-mode TB cflags (see cpu_plugin_exec_inline /
     * cpu_plugin_exec_tb); that makes the spec-mode translation a
     * distinct TB-cache entry whose tb_gen_code emits slow-path
     * mem helpers directly, with no dependence on TLB state.  A
     * tlb_flush here would be a no-op anyway in CONFIG_USER_ONLY
     * (the cputlb.h stub is empty) and pure overhead in
     * system-mode. */

    /* Reuse existing hash table (cleared on previous spec_mode_end) */
    if (!current_cpu->plugin_spec_store_buf) {
        current_cpu->plugin_spec_store_buf = g_hash_table_new(g_direct_hash,
                                                               g_direct_equal);
    }
    current_cpu->plugin_spec_saved_state = saved_state;
    current_cpu->plugin_spec_store_overflow = false;
    current_cpu->plugin_spec_mode = true;
}

/*
 * Checkpoint / restore the guest virtual clock around a whole wrong-path
 * excursion.  A WP excursion executes (bounded by wpdepth) in real host
 * wall-clock time, but it is *outside* guest time: it must not advance the
 * guest's perception of time any more than it advances the guest's registers.
 * QEMU_CLOCK_VIRTUAL with icount off tracks host time, and every target reads
 * its architected counter from it — aarch64 CNTVCT_EL0, x86 TSC, riscv `time`,
 * mips Count — so a single freeze checkpoints the timer count for all ISAs at
 * once.
 *
 * Driven from the plugin's OUTER excursion boundary (wp_enter/wp_end), not
 * from spec_mode_begin/end: a wrong-path fault-skip tears down and re-enters
 * spec mode mid-excursion, and pausing per spec-mode-entry would re-enable
 * ticks across that gap and leak time per skip.  The real per-CPU work
 * (cpu_disable_ticks/enable_ticks) lives in cpu_plugin_spec_vtime_* in
 * cpu-exec.c, which is compiled per-target so it is a no-op in user mode;
 * this common file must not reference the softmmu-only timer symbols.
 */
void qemu_plugin_spec_vtime_pause(void)
{
    g_assert(current_cpu);
    cpu_plugin_spec_vtime_pause(current_cpu);
}

void qemu_plugin_spec_vtime_resume(void)
{
    g_assert(current_cpu);
    cpu_plugin_spec_vtime_resume(current_cpu);
}

/*
 * Nestable guest-clock freeze for correct-path instrumentation windows
 * (translation-time decode, per-TB emission).  Same transparency rule as the
 * WP pause above: plugin work is outside guest execution, so its host cost
 * must not advance guest time.  Per-target impl in cpu-exec.c; no-op in user
 * mode.
 */
void qemu_plugin_vclock_pause(void)
{
    g_assert(current_cpu);
    cpu_plugin_vclock_pause(current_cpu);
}

void qemu_plugin_vclock_resume(void)
{
    g_assert(current_cpu);
    cpu_plugin_vclock_resume(current_cpu);
}

bool qemu_plugin_in_async_int(void)
{
#ifdef CONFIG_USER_ONLY
    return false;
#else
    return current_cpu && current_cpu->plugin_in_async_int;
#endif
}

bool qemu_plugin_in_spec_mode(void)
{
    return current_cpu && current_cpu->plugin_spec_mode;
}

/* The wire and plugin-facing event layouts are kept field-for-field
 * identical; the drain below converts explicitly all the same, so a
 * layout drift shows up as a compile break here rather than corruption.
 * The KIND VALUES pass through raw as well: the two enums
 * (QemuPluginCpuEventKind in hw/core/cpu.h, qemu_plugin_cpu_event_kind
 * in qemu-plugin.h) must stay value-aligned member for member —
 * FAULT_ENTER/RETURN = 0/1, ASYNC_ENTER/RETURN = 2/3, ASID_WRITE = 4. */
QEMU_BUILD_BUG_ON(sizeof(struct qemu_plugin_cpu_event) !=
                  sizeof(QemuPluginCpuEvent));
QEMU_BUILD_BUG_ON((int)QEMU_PLUGIN_CPU_EV_ASID_WRITE !=
                  (int)QEMU_PLUGIN_CPU_EVENT_ASID_WRITE);

void qemu_plugin_cpu_events_set(unsigned int vcpu_index, bool enabled)
{
    CPUState *cpu = qemu_get_cpu(vcpu_index);
    if (!cpu) {
        return;
    }
    cpu->plugin_evq.enabled = enabled;
    cpu->plugin_evq.len = 0;
}

size_t qemu_plugin_drain_cpu_events(unsigned int vcpu_index,
                                    const struct qemu_plugin_cpu_event **evs)
{
    CPUState *cpu = qemu_get_cpu(vcpu_index);
    if (!cpu || !cpu->plugin_evq.buf) {
        *evs = NULL;
        return 0;
    }
    QemuPluginCpuEventQueue *q = &cpu->plugin_evq;
    size_t n = q->len;
    /* Single producer/consumer == this vCPU thread; handing out the
     * internal buffer is race-free until the next push, which cannot
     * happen before the consumer's tb_exec callback returns. */
    *evs = (const struct qemu_plugin_cpu_event *)q->buf;
    q->len = 0;
    return n;
}

void qemu_plugin_async_int_reset(void)
{
#ifndef CONFIG_USER_ONLY
    if (current_cpu) {
        current_cpu->plugin_in_async_int = false;
    }
#endif
}

uint32_t qemu_plugin_fault_depth(void)
{
#ifdef CONFIG_USER_ONLY
    return 0;
#else
    return current_cpu ? current_cpu->plugin_fault_depth : 0;
#endif
}

bool qemu_plugin_spec_store_overflowed(void)
{
#ifdef CONFIG_USER_ONLY
    return false;
#else
    return current_cpu && current_cpu->plugin_spec_store_overflow;
#endif
}

bool qemu_plugin_spec_mem_faulted_take(void)
{
    if (!current_cpu || !current_cpu->plugin_spec_mem_faulted) {
        return false;
    }
    current_cpu->plugin_spec_mem_faulted = false;
    return true;
}

void qemu_plugin_spec_clear_exception(void)
{
    g_assert(current_cpu);
    /*
     * Drop a pending guest exception latched by a wrong-path execution-time
     * fault (x86 #DE/#UD/#GP/#AC, INTO/BOUND; MIPS arithmetic overflow, a
     * teq-family trap) that longjmped out of a speculative exec_tb.  The raise
     * path (raise_exception_ra / cpu_loop_exit_restore) already restored the
     * guest PC to the faulting instruction and left exception_index set; the
     * wrong-path walker skips that insn and re-dispatches, so the next
     * speculative exec_tb must start clean with no exception pending.
     *
     * EXCP_NONE is -1 in common code (cpu_loop_exit_noexc); this mirrors the
     * exception_index field access qemu_plugin_cpu_state_save/_restore already
     * use.  Arch-specific latches (x86 error_code, etc.) live inside the
     * CPUArchState snapshot restored wholesale at excursion end
     * (qemu_plugin_cpu_state_restore) and are inert unless an exception is
     * actually delivered, which the speculative walker never does.
     */
    current_cpu->exception_index = -1;
}

void qemu_plugin_spec_mode_end(void)
{
    g_assert(current_cpu);
    /* May already be false in the longjmp cleanup path */
    if (!current_cpu->plugin_spec_mode) {
        return;
    }

    current_cpu->plugin_spec_mode = false;
    current_cpu->plugin_spec_saved_state = NULL;

    /* Flush sandbox: clear the line index and reset the pool's
     * high-water mark.  The pool buffer itself stays allocated for
     * reuse on the next spec-mode entry. */
    if (current_cpu->plugin_spec_store_buf) {
        g_hash_table_remove_all(current_cpu->plugin_spec_store_buf);
    }
    current_cpu->plugin_spec_store_pool_used = 0;

    /*
     * Flush the softmmu TLB on spec-mode exit (no-op in user mode).  Spec-mode
     * accesses still run tlb_fill on a miss and install entries that a regime
     * change on the wrong path can invalidate for the correct path; the
     * register snapshot can't undo them (the TLB lives in CPUState).  The
     * actual flush is in cpu_plugin_spec_tlb_flush (cpu-exec.c, per-target) so
     * this common file does not reference softmmu-only tlb_flush.
     */
    cpu_plugin_spec_tlb_flush(current_cpu);
}

struct qemu_plugin_scoreboard *qemu_plugin_scoreboard_new(size_t element_size)
{
    return plugin_scoreboard_new(element_size);
}

void qemu_plugin_scoreboard_free(struct qemu_plugin_scoreboard *score)
{
    plugin_scoreboard_free(score);
}

void *qemu_plugin_scoreboard_find(struct qemu_plugin_scoreboard *score,
                                  unsigned int vcpu_index)
{
    g_assert(vcpu_index < qemu_plugin_num_vcpus());
    /* we can't use g_array_index since entry size is not statically known */
    char *base_ptr = score->data->data;
    return base_ptr + vcpu_index * g_array_get_element_size(score->data);
}

static uint64_t *plugin_u64_address(qemu_plugin_u64 entry,
                                    unsigned int vcpu_index)
{
    char *ptr = qemu_plugin_scoreboard_find(entry.score, vcpu_index);
    return (uint64_t *)(ptr + entry.offset);
}

void qemu_plugin_u64_add(qemu_plugin_u64 entry, unsigned int vcpu_index,
                         uint64_t added)
{
    *plugin_u64_address(entry, vcpu_index) += added;
}

uint64_t qemu_plugin_u64_get(qemu_plugin_u64 entry,
                             unsigned int vcpu_index)
{
    return *plugin_u64_address(entry, vcpu_index);
}

void qemu_plugin_u64_set(qemu_plugin_u64 entry, unsigned int vcpu_index,
                         uint64_t val)
{
    *plugin_u64_address(entry, vcpu_index) = val;
}

uint64_t qemu_plugin_u64_sum(qemu_plugin_u64 entry)
{
    uint64_t total = 0;
    for (int i = 0, n = qemu_plugin_num_vcpus(); i < n; ++i) {
        total += qemu_plugin_u64_get(entry, i);
    }
    return total;
}

