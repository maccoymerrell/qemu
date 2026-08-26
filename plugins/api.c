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
#include "qemu/timer.h"
#include "tcg/tcg.h"
#include "accel/tcg/cpu-ops.h"
#include "hw/core/cpu.h"
#include "exec/gdbstub.h"
#include "exec/plugin-spec.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "exec/translator.h"
#include "exec/insn-dataflow.h"
#include "qemu/qemu-plugin-dataflow.h"
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
 * Per-instruction dataflow, derived from the IR the target's translator
 * emitted.  See include/qemu/qemu-plugin-dataflow.h for the contract; the
 * three properties this implementation has to hold up are that no bitmap
 * crosses by value, that a set is never handed back partially, and that an
 * instruction the extraction could not record in full yields nothing at all
 * rather than a plausible subset.
 */

/*
 * The extraction lives in thread-local storage belonging to the translation
 * in progress, so it is readable only while that translation's callback is
 * running.  Rather than document that and hope, every accessor checks that
 * @tb is the block being translated now: a plugin that stashes a tb and asks
 * later gets a refusal instead of another block's answer.
 */
static const InsnDataflow *plugin_df(const struct qemu_plugin_tb *tb,
                                     size_t idx)
{
    if (unlikely(tb == NULL || tb != tcg_ctx->plugin_tb || idx >= tb->n)) {
        return NULL;
    }
    return insn_dataflow_get(idx);
}

/* Would a set from this instruction be a whole one? */
static bool plugin_df_complete(const InsnDataflow *d)
{
    return !d->fields_overflow && !d->writes_overflow;
}

static unsigned plugin_df_copy(const uint64_t *src, uint64_t *words,
                               unsigned nwords)
{
    unsigned n = (insn_dataflow_nregs() + 63) / 64;

    if (n > INSN_DF_REG_WORDS) {
        n = INSN_DF_REG_WORDS;
    }
    /*
     * Refuse rather than truncate.  A short set is a set with dependencies
     * missing from it, and it is the shape most likely to pass for a whole
     * one; an empty answer is not.
     */
    if (nwords >= n && words != NULL) {
        memcpy(words, src, n * sizeof(uint64_t));
    }
    return n;
}

/*
 * Copy a PROVENANCE set, which is not the same size as a register set.
 *
 * A read/write/kill set holds only TCG globals, so ceil(nregs/64) words hold
 * it exactly.  A provenance set spans the whole namespace: globals, then the
 * env byte ranges interned for the block, then the load-data bits at the top
 * of it.  Sizing a provenance copy by nregs therefore drops every bit above
 * the globals -- on x86_64, where nregs is 37, it copied ONE word and every
 * field bit from 64 up and every load-data bit went missing, with the return
 * value reporting the truncated size as the whole one.  That is the exact
 * shape this API's own preamble refuses to hand out: a partial set that
 * looks complete.
 */
static unsigned plugin_df_copy_prov(const uint64_t *src, uint64_t *words,
                                    unsigned nwords)
{
    if (nwords >= INSN_DF_REG_WORDS && words != NULL) {
        memcpy(words, src, INSN_DF_REG_WORDS * sizeof(uint64_t));
    }
    return INSN_DF_REG_WORDS;
}

unsigned qemu_plugin_dataflow_prov_words(void)
{
    return INSN_DF_REG_WORDS;
}

bool qemu_plugin_dataflow_abi_ok(uint32_t plugin_version,
                                 uint32_t field_struct_size,
                                 uint32_t status_struct_size)
{
    return plugin_version == QEMU_PLUGIN_DATAFLOW_VERSION &&
           field_struct_size == sizeof(qemu_plugin_dataflow_field) &&
           status_struct_size == sizeof(qemu_plugin_dataflow_status);
}

unsigned qemu_plugin_dataflow_nregs(void)
{
    return insn_dataflow_nregs();
}

const char *qemu_plugin_dataflow_reg_name(unsigned reg, uint32_t *env_offset,
                                          uint32_t *size)
{
    return insn_dataflow_reg_name(reg, env_offset, size);
}

bool qemu_plugin_dataflow_prov_field(unsigned bit, uint32_t *env_offset)
{
    bool valid;
    uint32_t off = insn_dataflow_prov_field(bit, &valid);

    if (valid && env_offset) {
        *env_offset = off;
    }
    return valid;
}

#define PLUGIN_DF_SET(name, member)                                          \
unsigned name(const struct qemu_plugin_tb *tb, size_t idx,                   \
              uint64_t *words, unsigned nwords)                              \
{                                                                            \
    const InsnDataflow *d = plugin_df(tb, idx);                              \
                                                                             \
    if (d == NULL) {                                                         \
        return QEMU_PLUGIN_DF_INCOMPLETE;                                    \
    }                                                                        \
    if (!plugin_df_complete(d)) {                                            \
        return QEMU_PLUGIN_DF_INCOMPLETE;                                    \
    }                                                                        \
    return plugin_df_copy(d->member, words, nwords);                         \
}

PLUGIN_DF_SET(qemu_plugin_insn_reg_reads,  rd)
PLUGIN_DF_SET(qemu_plugin_insn_reg_writes, wr)
PLUGIN_DF_SET(qemu_plugin_insn_reg_kills,  kill)

unsigned qemu_plugin_insn_write_prov(const struct qemu_plugin_tb *tb,
                                     size_t idx, unsigned reg,
                                     uint64_t *words, unsigned nwords)
{
    const InsnDataflow *d = plugin_df(tb, idx);

    if (d == NULL || !plugin_df_complete(d)) {
        return QEMU_PLUGIN_DF_INCOMPLETE;
    }
    for (unsigned i = 0; i < d->n_writes; i++) {
        if (d->writes[i].reg == reg) {
            return plugin_df_copy_prov(d->writes[i].prov, words, nwords);
        }
    }
    /* Not a register this instruction wrote: no provenance to give. */
    return QEMU_PLUGIN_DF_INCOMPLETE;
}

unsigned qemu_plugin_insn_fields(const struct qemu_plugin_tb *tb, size_t idx,
                                 qemu_plugin_dataflow_field *out,
                                 unsigned nfields)
{
    const InsnDataflow *d = plugin_df(tb, idx);

    if (d == NULL || !plugin_df_complete(d)) {
        return QEMU_PLUGIN_DF_INCOMPLETE;
    }
    if (nfields < d->n_fields || out == NULL) {
        return d->n_fields;
    }
    for (unsigned i = 0; i < d->n_fields; i++) {
        /*
         * The caller stated its own struct size; write only that much and
         * zero nothing beyond it, so a plugin built against an older header
         * gets a correct prefix rather than a stomped stack.
         */
        uint32_t want = out[i].struct_size;
        qemu_plugin_dataflow_field f = {
            .struct_size = sizeof(f),
            .env_offset = d->fields[i].off,
            .size = d->fields[i].size,
            .dir = d->fields[i].dir,
        };

        if (want == 0 || want > sizeof(f)) {
            want = sizeof(f);
        }
        memcpy(&out[i], &f, want);
    }
    return d->n_fields;
}

unsigned qemu_plugin_insn_field_prov(const struct qemu_plugin_tb *tb,
                                     size_t idx, unsigned field,
                                     uint64_t *words, unsigned nwords)
{
    const InsnDataflow *d = plugin_df(tb, idx);

    if (d == NULL || !plugin_df_complete(d) || field >= d->n_fields) {
        return QEMU_PLUGIN_DF_INCOMPLETE;
    }
    return plugin_df_copy_prov(d->fields[field].prov, words, nwords);
}

/*
 * Are this instruction's ACCESS records whole?
 *
 * Separate from plugin_df_complete() because the two limits are separate: an
 * instruction can exceed the register-write capacity while its accesses are
 * recorded exactly, and the reverse.  Provenance truncation counts against
 * both, since an access's addr_prov is a set in the same namespace and a
 * short one is a dependency missing.
 */
static bool plugin_df_memops_complete(const InsnDataflow *d)
{
    return !d->memops_overflow && !d->memops_unnoted &&
           !insn_dataflow_prov_truncated();
}

unsigned qemu_plugin_insn_memops(const struct qemu_plugin_tb *tb, size_t idx,
                                 qemu_plugin_dataflow_memop *out,
                                 unsigned nmemops)
{
    const InsnDataflow *d = plugin_df(tb, idx);

    if (d == NULL || !plugin_df_memops_complete(d)) {
        return QEMU_PLUGIN_DF_INCOMPLETE;
    }
    if (nmemops < d->n_memops || out == NULL) {
        return d->n_memops;
    }
    for (unsigned i = 0; i < d->n_memops; i++) {
        /*
         * The caller stated its own struct size; write only that much, so a
         * plugin built against an older header gets a correct prefix rather
         * than a stomped stack.
         */
        uint32_t want = out[i].struct_size;
        qemu_plugin_dataflow_memop m = {
            .struct_size = sizeof(m),
            .size = d->memops[i].size,
            .is_store = d->memops[i].is_store,
        };

        if (want == 0 || want > sizeof(m)) {
            want = sizeof(m);
        }
        memcpy(&out[i], &m, want);
    }
    return d->n_memops;
}

#define PLUGIN_DF_MEMOP_PROV(name, member)                                   \
unsigned name(const struct qemu_plugin_tb *tb, size_t idx, unsigned memop,   \
              uint64_t *words, unsigned nwords)                              \
{                                                                            \
    const InsnDataflow *d = plugin_df(tb, idx);                              \
                                                                             \
    if (d == NULL || !plugin_df_memops_complete(d) ||                        \
        memop >= d->n_memops) {                                              \
        return QEMU_PLUGIN_DF_INCOMPLETE;                                    \
    }                                                                        \
    return plugin_df_copy_prov(d->memops[memop].member, words, nwords);      \
}

PLUGIN_DF_MEMOP_PROV(qemu_plugin_insn_memop_addr_prov, addr_prov)
PLUGIN_DF_MEMOP_PROV(qemu_plugin_insn_memop_data_prov, data_prov)

bool qemu_plugin_dataflow_prov_memop(unsigned bit, unsigned *slot)
{
    return insn_dataflow_prov_memop(bit, slot);
}

bool qemu_plugin_insn_dataflow_status(const struct qemu_plugin_tb *tb,
                                      size_t idx,
                                      qemu_plugin_dataflow_status *out)
{
    const InsnDataflow *d = plugin_df(tb, idx);
    qemu_plugin_dataflow_status st = {
        .struct_size = sizeof(st),
        .version = QEMU_PLUGIN_DATAFLOW_VERSION,
    };
    uint32_t want;

    if (d == NULL || out == NULL) {
        return false;
    }
    st.n_calls = d->n_calls;
    st.n_mem_reads = d->n_mem_rd;
    st.n_mem_writes = d->n_mem_wr;
    st.fields_truncated = d->fields_overflow;
    st.writes_truncated = d->writes_overflow;
    st.prov_truncated = insn_dataflow_prov_truncated();
    st.helper_model = d->helper_model;
    st.n_helper_unknown = d->n_helper_unknown;
    st.n_helper_unbounded = d->n_helper_unbounded;
    st.memops_truncated = d->memops_overflow;
    st.memops_unnoted = d->memops_unnoted;

    want = out->struct_size;
    if (want == 0 || want > sizeof(st)) {
        want = sizeof(st);
    }
    memcpy(out, &st, want);
    return true;
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

uint32_t qemu_plugin_insn_decode_id(const struct qemu_plugin_insn *insn)
{
    return insn->decode_id;
}

const char *qemu_plugin_insn_decode_name(const struct qemu_plugin_insn *insn)
{
    return insn->decode_name;
}

uint32_t qemu_plugin_insn_ctrl_flags(const struct qemu_plugin_insn *insn)
{
    return insn->ctrl_flags;
}

uint64_t qemu_plugin_insn_ctrl_target(const struct qemu_plugin_insn *insn)
{
    return insn->ctrl_target;
}

int32_t qemu_plugin_insn_ctrl_target_reg(const struct qemu_plugin_insn *insn)
{
    return insn->ctrl_target_reg;
}

int32_t qemu_plugin_insn_ctrl_addr_reg(const struct qemu_plugin_insn *insn)
{
    return insn->ctrl_addr_reg;
}

int32_t qemu_plugin_insn_ctrl_link_reg(const struct qemu_plugin_insn *insn)
{
    return insn->ctrl_link_reg;
}

int32_t qemu_plugin_insn_ctrl_link_addr_reg(const struct qemu_plugin_insn *insn)
{
    return insn->ctrl_link_addr_reg;
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
        /*
         * No in-tree target emits a MemOp whose size shift exceeds
         * MO_128, and CPUState only ever latches the low 128 bits of an
         * access into plugin_mem_value_low/high (tcg_gen_plugin_mem_cb()
         * in tcg/tcg-op-ldst.c) — a wider access has already lost its
         * upper bits before this function is reached, so there is
         * nothing correct to return.  Degrade instead of aborting the
         * whole emulator: report the access as unrepresentable and let
         * the plugin decide what to do with it.
         */
        warn_report_once("qemu_plugin_mem_get_value: access wider than "
                          "128 bits (size shift %u) is not representable; "
                          "returning QEMU_PLUGIN_MEM_VALUE_INVALID",
                          qemu_plugin_mem_size_shift(info));
        value.type = QEMU_PLUGIN_MEM_VALUE_INVALID;
        memset(&value.data, 0, sizeof(value.data));
        break;
    }
    return value;
}

int qemu_plugin_num_vcpus(void)
{
    return plugin_num_vcpus();
}

/*
 * The vCPU the caller is running on, which is the one every state API
 * that takes no vCPU argument resolves through.  Those APIs assert on
 * current_cpu; this reports the same fact and lets a plugin ask instead
 * of finding out by aborting.
 */
int qemu_plugin_current_vcpu_index(void)
{
    return current_cpu ? current_cpu->cpu_index : QEMU_PLUGIN_VCPU_NONE;
}

/*
 * One-shot per-vCPU work item (qemu_plugin_async_run_on_vcpu): a small
 * heap closure carried through async_run_on_cpu, so the callback runs on
 * the target vCPU's own thread with that vCPU's live context (registers,
 * address space) resolvable through current_cpu.
 */
struct plugin_vcpu_async_closure {
    qemu_plugin_vcpu_async_cb_t cb;
    void *userdata;
};

static void plugin_vcpu_async_tramp(CPUState *cpu, run_on_cpu_data data)
{
    struct plugin_vcpu_async_closure *cl = data.host_ptr;

    cl->cb(cpu->cpu_index, cl->userdata);
    g_free(cl);
}

void qemu_plugin_async_run_on_vcpu(unsigned int vcpu_index,
                                   qemu_plugin_vcpu_async_cb_t cb,
                                   void *userdata)
{
    CPUState *cpu = qemu_get_cpu(vcpu_index);

    if (!cpu || !cb) {
        return;
    }
    struct plugin_vcpu_async_closure *cl = g_new(struct plugin_vcpu_async_closure, 1);
    cl->cb = cb;
    cl->userdata = userdata;
    async_run_on_cpu(cpu, plugin_vcpu_async_tramp, RUN_ON_CPU_HOST_PTR(cl));
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
            /* Hash value = pool index + 1 (see spec_line_get_or_alloc). */
            gpointer val = g_hash_table_lookup(
                current_cpu->plugin_spec_store_buf,
                GUINT_TO_POINTER((guintptr)line_addr));
            PluginSpecLine *line = val
                ? &((PluginSpecLine *)current_cpu->plugin_spec_store_pool)
                      [GPOINTER_TO_SIZE(val) - 1]
                : NULL;
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
    /*
     * The per-execution self-loop report (the plugin_rep_* block), for the
     * same reason and by the same rule as the two fields above: a wrong-path
     * walk dirties it, and the correct path reads it.
     *
     * It is a PUBLICATION CHANNEL, not scratch.  A fan-out instruction
     * publishes its architectural facts here as it executes, and the consumer
     * reads them at the NEXT dispatch, because the fields describe the
     * execution that finished before the callback -- so the value is in flight
     * across exactly the boundary a speculative excursion is kicked from.  An
     * excursion that executes any fan-out instruction overwrites the channel
     * mid-flight, and what the correct path then reads is the wrong path's
     * count.
     *
     * The consumer cannot defend itself.  plugin_rep_pc names the instruction
     * the report describes, and that is the whole identity: it is an ADDRESS.
     * A speculative walk that re-enters the very instruction it was launched
     * from -- the ordinary case, since the excursion starts at the untaken
     * side of the block that instruction ended -- republishes the same
     * address with a different count, and no reader can tell the two apart.
     * Provenance would have to travel with the value, which means it belongs
     * here, at the excursion boundary, and not in any one consumer.
     *
     * Restoring the whole block also keeps a genuine mid-instruction state
     * intact: a fan-out split by a fault leaves retired-iteration facts
     * pending for the piece still to come, and an excursion taken in between
     * must give that state back untouched rather than leave the resumed
     * instruction reading the speculation's numbers.
     *
     * Target-independent on purpose.  x86 REP publishes from generated code
     * in do_gen_rep(); AArch64 FEAT_MOPS publishes from its step helpers.
     * Both write these fields, and neither is gated on speculation, so the
     * repair belongs at the one boundary both cross.
     */
    uint64_t rep_iters;
    uint64_t rep_pc;
    uint64_t rep_bytes;
    bool rep_complete;
    bool rep_reenter;
    bool rep_chunk;
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
    state->rep_iters = current_cpu->plugin_rep_iters;
    state->rep_pc = current_cpu->plugin_rep_pc;
    state->rep_bytes = current_cpu->plugin_rep_bytes;
    state->rep_complete = current_cpu->plugin_rep_complete;
    state->rep_reenter = current_cpu->plugin_rep_reenter;
    state->rep_chunk = current_cpu->plugin_rep_chunk;

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
    /*
     * Hand the self-loop report back exactly as the correct path left it.
     * A consumer inside the excursion has already read the speculative
     * values it wanted (it reads them per speculative execution, before this
     * runs); what must not survive is the wrong path's last publication
     * sitting in the channel when the correct path next looks.
     */
    current_cpu->plugin_rep_iters = state->rep_iters;
    current_cpu->plugin_rep_pc = state->rep_pc;
    current_cpu->plugin_rep_bytes = state->rep_bytes;
    current_cpu->plugin_rep_complete = state->rep_complete;
    current_cpu->plugin_rep_reenter = state->rep_reenter;
    current_cpu->plugin_rep_chunk = state->rep_chunk;
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

bool qemu_plugin_thread_ptr_tracks_current(void)
{
    g_assert(current_cpu);
    const TCGCPUOps *ops = current_cpu->cc->tcg_ops;
    return ops && ops->get_plugin_thread_ptr &&
           ops->plugin_thread_ptr_tracks_current &&
           ops->plugin_thread_ptr_tracks_current(current_cpu);
}

void qemu_plugin_set_current_task_offset(uint64_t offset)
{
    /* Stored process-globally (see plugins/core.c); consumed by targets
     * whose kernels keep no per-task pointer in a register at kernel
     * privilege — today x86-64's thread-pointer hooks.  Deliberately
     * accepted on every target and in user mode: the declaration is
     * inert where nothing consumes it, and the declaring plugin — which
     * knows the target it runs on — is the right place to tell its user
     * the hint has no consumer here. */
    qemu_plugin_current_task_offset_store(offset);
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
 *
 * The hash table's value is the line's POOL INDEX plus one, never a
 * pointer into the pool.  The pool grows by g_realloc_n, which moves
 * the array: a stored pointer would dangle into the freed copy at the
 * first growth inside an excursion, and every later hit on a
 * pre-growth line would read — and worse, WRITE — freed heap.
 * Measured exactly so under ASAN (riscv64, tb-size=4, wpdepth=65536:
 * heap-use-after-free in spec_load_bytes against a 20 KiB region this
 * function's realloc freed), and the writes are the mechanism behind
 * the downstream free(): invalid pointer aborts the same configuration
 * produced.  An index is stable across growth by construction; each
 * lookup resolves it against the pool base of the moment.
 */
PluginSpecLine *spec_line_get_or_alloc(CPUState *cpu, vaddr line_addr)
{
    PluginSpecLine *pool = (PluginSpecLine *)cpu->plugin_spec_store_pool;
    gpointer val = g_hash_table_lookup(
        cpu->plugin_spec_store_buf, GUINT_TO_POINTER((guintptr)line_addr));
    if (val) {
        return &pool[GPOINTER_TO_SIZE(val) - 1];
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
        pool = (PluginSpecLine *)cpu->plugin_spec_store_pool;
    }
    size_t idx = cpu->plugin_spec_store_pool_used++;
    PluginSpecLine *line = &pool[idx];
    line->valid_mask = 0;
    /* bytes[] left uninitialised; valid_mask gates reads, so unused
     * bytes are never observed. */
    g_hash_table_insert(cpu->plugin_spec_store_buf,
                        GUINT_TO_POINTER((guintptr)line_addr),
                        GSIZE_TO_POINTER(idx + 1));
    return line;
}

void qemu_plugin_spec_mode_begin(struct qemu_plugin_cpu_state *saved_state)
{
    g_assert(current_cpu);
    g_assert(!current_cpu->plugin_spec_mode);

    /*
     * @saved_state was added inside version 5, which therefore names both a
     * no-argument and a one-argument spelling of this function; version 6 is
     * the first that distinguishes them.  A caller built before the change
     * passes nothing and QEMU reads the first argument register, so
     * plugin_spec_saved_state below would be an arbitrary pointer that
     * qemu_plugin_spec_mode_end() later restores the vCPU from.  This entry
     * point carries no plugin id, so ask the floor across loaded plugins.
     */
    if (plugin_declared_version_floor() < 6) {
        error_report("plugin: qemu_plugin_spec_mode_begin() gained its "
                     "saved_state argument at plugin API version 6, and a "
                     "loaded plugin declares version %d.  QEMU would restore "
                     "vCPU state from an argument that plugin never passed.  "
                     "Rebuild the plugin against this qemu-plugin.h.",
                     plugin_declared_version_floor());
        _exit(1);
    }

    /*
     * Fail-safe containment guard.  Wrong-path tracing routes speculative
     * stores through the slow-path do_st helpers so they land in the spec
     * store sandbox instead of real guest RAM.  Two mechanisms provide that
     * routing (see cpu_plugin_spec_mode_supported): a host backend that
     * honours CF_FORCE_SLOW bypasses the inline fast path directly (any mode),
     * and in system mode the portable TLB_FORCE_SLOW path contains stores on
     * any host backend.  Only user-mode tracing on a backend without
     * CF_FORCE_SLOW is unsupported — there is no softmmu TLB to carry the flag,
     * so an inline store would commit to the guest image.  Refuse loudly at
     * the first spec-mode request there rather than corrupt guest memory, and
     * rather than silently disabling wrong-path tracing (which would leave the
     * caller believing the speculative excursion ran).  On x86 the capability
     * is a compile-time constant, so this collapses to a no-op.
     *
     * Terminate with _exit(): this fires from deep inside the plugin's WP
     * excursion setup (locks held, a half-built speculative session), so the
     * plugin's registered atexit dump must not run against that inconsistent
     * state.  _exit() skips atexit handlers and stdio flush; error_report has
     * already written the diagnostic to the unbuffered stderr.
     */
    if (!cpu_plugin_spec_mode_supported()) {
        error_report("champsim_tracer wrong-path tracing is not supported on "
                     "this build: user-mode tracing on a host TCG backend that "
                     "does not honor CF_FORCE_SLOW has no way to sandbox "
                     "speculative stores, which would corrupt the guest image "
                     "- refusing to enable.");
        _exit(1);
    }

    /* Reuse existing hash table (cleared on previous spec_mode_end) */
    if (!current_cpu->plugin_spec_store_buf) {
        current_cpu->plugin_spec_store_buf = g_hash_table_new(g_direct_hash,
                                                               g_direct_equal);
    }
    current_cpu->plugin_spec_saved_state = saved_state;
    current_cpu->plugin_spec_store_overflow = false;
    current_cpu->plugin_spec_mode = true;

    /*
     * Slow-path memory routing.  On a backend that honours CF_FORCE_SLOW the
     * spec-mode TB cflag (see cpu_plugin_exec_inline / cpu_plugin_exec_tb)
     * makes the spec-mode translation a distinct TB-cache entry whose
     * tb_gen_code emits slow-path mem helpers directly, independent of TLB
     * state, and the flush below is a no-op.  On other host backends (system
     * mode) the portable TLB_FORCE_SLOW path carries the routing instead: flush
     * the softmmu TLB here so any correct-path entries resident at excursion
     * start refill — with TLB_FORCE_SLOW — inside the excursion, rather than
     * being hit on the inline fast path.  A no-op in user mode (no softmmu
     * TLB).  The per-target impl lives in cpu-exec.c so this common file does
     * not reference softmmu-only tlb_flush.
     */
    cpu_plugin_spec_tlb_flush_enter(current_cpu);
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

/*
 * Read side of the same clock the pause above freezes.  A plugin that pauses
 * for its own cost needs to be able to see what the guest was left believing:
 * guest-ns per host-ns is the guest realtime factor, and guest instructions
 * per guest-second is the rate the guest's periodic tick load is charged
 * against.  Read-only, so no BQL and no runstate interaction.
 */
int64_t qemu_plugin_vclock_ns(void)
{
#ifdef CONFIG_USER_ONLY
    return 0;
#else
    if (icount_enabled()) {
        /*
         * Under icount the virtual clock IS the instruction counter, and
         * reading it from a vCPU callback with cpu->running && !can_do_io
         * aborts ("Bad icount read").  There is also nothing to learn: icount
         * pins guest time to instructions by construction, so the factor this
         * call exists to measure is a constant of the configuration.
         */
        return 0;
    }
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
#endif
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
    if (cpu->plugin_evq.enabled != enabled) {
        cpu_plugin_async_probe(cpu, enabled ? "QON" : "QOFF", 0, false);
    }
    /*
     * This function used to zero @len on BOTH arms -- a silent discard of
     * however many events were pending.  Nothing may be dropped here: a
     * non-empty queue at this point is a consumer that stopped consuming
     * while events were still owed, i.e. the unbounded-growth defect this
     * plumbing exists to make impossible.  Report it as the bug it is.
     *
     * The obligation this places on the caller is exact and cheap to meet:
     * disable (or re-enable) only where the queue is provably empty, which
     * with a per-TB absorber registered means anywhere at all -- the
     * preceding TB drained it, and no guest instruction has run since.
     */
    if (cpu->plugin_evq.len != 0) {
        fprintf(stderr,
                "qemu: FATAL qemu_plugin_cpu_events_set(%d) with %u undrained "
                "events on cpu %u -- this call would silently discard them\n",
                (int)enabled, cpu->plugin_evq.len, vcpu_index);
        fflush(stderr);
        abort();
    }
    cpu->plugin_evq.enabled = enabled;
    cpu->plugin_evq.len = 0;
    plugin_evq_note_drained(cpu);
}

void qemu_plugin_cpu_events_pending_slot(qemu_plugin_u64 slot)
{
    plugin_set_evq_pending_slot(slot, true);
}

void qemu_plugin_cpu_events_stats(unsigned int vcpu_index,
                                  uint64_t *max_len, uint64_t *pushes,
                                  uint64_t *drains)
{
    CPUState *cpu = qemu_get_cpu(vcpu_index);
    if (max_len) {
        *max_len = cpu ? cpu->plugin_evq.max_len : 0;
    }
    if (pushes) {
        *pushes = cpu ? cpu->plugin_evq.n_push : 0;
    }
    if (drains) {
        *drains = cpu ? cpu->plugin_evq.n_drain : 0;
    }
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
    q->n_drain++;
    /* The queue is empty: retract the drain-owed flag so the consumer's
     * per-TB conditional callback stops dispatching until the next push. */
    plugin_evq_note_drained(cpu);
    return n;
}

void qemu_plugin_async_int_reset(void)
{
#ifndef CONFIG_USER_ONLY
    if (current_cpu) {
        cpu_plugin_async_probe(current_cpu, "RESET", 0, false);
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

/*
 * Self-loop accounting for the fan-out instruction most recently executed on
 * this vCPU.  Both fields are written by target-generated TCG from the
 * instruction's architectural state; targets with no fan-out instruction
 * never write them, so the pair reads {0, false} there.  Unlike the fault
 * stack these are meaningful in *-linux-user too, which is where the
 * single-iteration REP translation is reachable through EFLAGS.TF and the
 * interrupt shadow.
 */
uint64_t qemu_plugin_rep_iterations(void)
{
    return current_cpu ? current_cpu->plugin_rep_iters : 0;
}

bool qemu_plugin_rep_complete(void)
{
    return current_cpu ? current_cpu->plugin_rep_complete : false;
}

uint64_t qemu_plugin_rep_pc(void)
{
    return current_cpu ? current_cpu->plugin_rep_pc : 0;
}

bool qemu_plugin_rep_reenter(void)
{
    return current_cpu ? current_cpu->plugin_rep_reenter : false;
}

uint64_t qemu_plugin_rep_bytes(void)
{
    return current_cpu ? current_cpu->plugin_rep_bytes : 0;
}

bool qemu_plugin_rep_chunk_boundary(void)
{
    return current_cpu ? current_cpu->plugin_rep_chunk : false;
}

bool qemu_plugin_spec_store_overflowed(void)
{
#ifdef CONFIG_USER_ONLY
    return false;
#else
    return current_cpu && current_cpu->plugin_spec_store_overflow;
#endif
}

uint64_t qemu_plugin_spec_reserve_opens(void)
{
    return qatomic_read(&plugin_spec_reserve_opens);
}

uint64_t qemu_plugin_spec_reserve_exhausted(void)
{
    return qatomic_read(&plugin_spec_reserve_exhausted);
}

bool qemu_plugin_spec_mem_faulted_take(void)
{
    if (!current_cpu || !current_cpu->plugin_spec_mem_faulted) {
        return false;
    }
    current_cpu->plugin_spec_mem_faulted = false;
    return true;
}

uint64_t qemu_plugin_spec_syscall_blocked_count(void)
{
    return qemu_plugin_spec_syscall_blocked;
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
     * The fault flag belongs to the memop that raised it, and the excursion
     * it belonged to is over.  It is set only under cpu_plugin_spec_active()
     * and consumed by qemu_plugin_spec_mem_faulted_take(), whose contract is
     * that the memory callback takes it immediately after the access — but
     * two constructions break that pairing and leave it set: an instruction
     * FETCH raises it with no memory callback behind it to take it, and a
     * consumer that returns before its take (a per-instruction slot cap, a
     * muted segment) never reaches one.  Left set, it is read by the FIRST
     * memop of the NEXT excursion, which is tagged faulted and stripped of
     * its physical page though nothing faulted for it.
     *
     * Cleared at END, not at BEGIN: a fault skip tears spec mode down and
     * re-enters it mid-excursion, so clearing on entry would erase a flag
     * that is still live.
     */
    current_cpu->plugin_spec_mem_faulted = false;

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

