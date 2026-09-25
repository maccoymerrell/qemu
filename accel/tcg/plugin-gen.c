/*
 * plugin-gen.c - TCG-related bits of plugin infrastructure
 *
 * Copyright (C) 2018, Emilio G. Cota <cota@braap.org>
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * We support instrumentation at an instruction granularity. That is,
 * if a plugin wants to instrument the memory accesses performed by a
 * particular instruction, it can just do that instead of instrumenting
 * all memory accesses. Thus, in order to do this we first have to
 * translate a TB, so that plugins can decide what/where to instrument.
 *
 * Injecting the desired instrumentation could be done with a second
 * translation pass that combined the instrumentation requests, but that
 * would be ugly and inefficient since we would decode the guest code twice.
 * Instead, during TB translation we add "plugin_cb" marker opcodes
 * for all possible instrumentation events, and then once we collect the
 * instrumentation requests from plugins, we generate code for those markers
 * or remove them if they have no requests.
 */
#include "qemu/osdep.h"
#include "qemu/plugin.h"
#include "qemu/log.h"
#include "cpu.h"
#include "tcg/tcg.h"
#include "tcg/tcg-temp-internal.h"
#include "tcg/tcg-op.h"
#include "exec/exec-all.h"
#include "exec/plugin-gen.h"
#include "exec/translator.h"
#include "accel/tcg/cpu-ops.h"
#include "tcg/tcg-internal.h"

/* the vCPU translating: its resolve hook names registers (reg_walk()) */
static __thread CPUState *reg_cpu;

enum plugin_gen_from {
    PLUGIN_GEN_FROM_TB,
    PLUGIN_GEN_FROM_INSN,
    PLUGIN_GEN_AFTER_INSN,
    PLUGIN_GEN_AFTER_TB,
};

/* called before finishing a TB with exit_tb, goto_tb or goto_ptr */
void plugin_gen_disable_mem_helpers(void)
{
    if (tcg_ctx->plugin_insn) {
        tcg_gen_plugin_cb(PLUGIN_GEN_AFTER_TB);
    }
}

static void gen_enable_mem_helper(struct qemu_plugin_tb *ptb,
                                  struct qemu_plugin_insn *insn)
{
    GArray *arr;
    size_t len;

    /*
     * Tracking memory accesses performed from helpers requires extra work.
     * If an instruction is emulated with helpers, we do two things:
     * (1) copy the CB descriptors, and keep track of it so that they can be
     * freed later on, and (2) point CPUState.neg.plugin_mem_cbs to the
     * descriptors, so that we can read them at run-time
     * (i.e. when the helper executes).
     * This run-time access is performed from qemu_plugin_vcpu_mem_cb.
     *
     * Note that plugin_gen_disable_mem_helpers undoes (2). Since it
     * is possible that the code we generate after the instruction is
     * dead, we also add checks before generating tb_exit etc.
     */
    if (!insn->calls_helpers) {
        return;
    }

    if (!insn->mem_cbs || !insn->mem_cbs->len) {
        insn->mem_helper = false;
        return;
    }
    insn->mem_helper = true;
    ptb->mem_helper = true;

    /*
     * TODO: It seems like we should be able to use ref/unref
     * to avoid needing to actually copy this array.
     * Alternately, perhaps we could allocate new memory adjacent
     * to the TranslationBlock itself, so that we do not have to
     * actively manage the lifetime after this.
     */
    len = insn->mem_cbs->len;
    arr = g_array_sized_new(false, false,
                            sizeof(struct qemu_plugin_dyn_cb), len);
    g_array_append_vals(arr, insn->mem_cbs->data, len);
    qemu_plugin_add_dyn_cb_arr(arr);

    tcg_gen_st_ptr(tcg_constant_ptr((intptr_t)arr), tcg_env,
                   offsetof(CPUState, neg.plugin_mem_cbs) -
                   offsetof(ArchCPU, env));
}

static void gen_disable_mem_helper(void)
{
    tcg_gen_st_ptr(tcg_constant_ptr(0), tcg_env,
                   offsetof(CPUState, neg.plugin_mem_cbs) -
                   offsetof(ArchCPU, env));
}

static TCGv_i32 gen_cpu_index(void)
{
    /*
     * Optimize when we run with a single vcpu. All values using cpu_index,
     * including scoreboard index, will be optimized out.
     * User-mode calls tb_flush when setting this flag. In system-mode, all
     * vcpus are created before generating code.
     *
     * The single-vcpu check is load-bearing: !CF_PARALLEL alone also
     * holds under round-robin TCG (-accel tcg,thread=single, and
     * therefore under -icount), where several vCPUs share one host
     * thread AND share translations.  Baking the translating vCPU's
     * index into a TB other vCPUs will execute routes every per-vCPU
     * scoreboard access and callback argument to the wrong vCPU.
     *
     * The flush above only reclaims space, and lands late: what keeps a
     * pre-clone TB from another vCPU is the lookup key, since every later
     * correct-path lookup carries CF_PARALLEL.  The plugin executors
     * (cpu_plugin_exec_tb, CF_SINGLE_ITER; cpu_plugin_exec_inline,
     * CF_MEMI_ONLY) clear CF_PARALLEL from their key, so the next thread's
     * wrong path finds the blocks vCPU 0's wrong path minted alone.  Their
     * TBs load the index; the correct path keeps the fold.
     */
    if (!tcg_cflags_has(current_cpu, CF_PARALLEL) &&
        CPU_NEXT(first_cpu) == NULL &&
        !(tb_cflags(tcg_ctx->gen_tb) & (CF_SINGLE_ITER | CF_MEMI_ONLY))) {
        return tcg_constant_i32(current_cpu->cpu_index);
    }
    TCGv_i32 cpu_index = tcg_temp_ebb_new_i32();
    tcg_gen_ld_i32(cpu_index, tcg_env,
                   -offsetof(ArchCPU, env) + offsetof(CPUState, cpu_index));
    return cpu_index;
}

static void gen_udata_cb(struct qemu_plugin_regular_cb *cb)
{
    TCGv_i32 cpu_index = gen_cpu_index();
    tcg_gen_call2(cb->f.vcpu_udata, cb->info, NULL,
                  tcgv_i32_temp(cpu_index),
                  tcgv_ptr_temp(tcg_constant_ptr(cb->userp)));
    tcg_temp_free_i32(cpu_index);
}

static TCGv_ptr gen_plugin_u64_ptr(qemu_plugin_u64 entry)
{
    TCGv_ptr ptr = tcg_temp_ebb_new_ptr();

    GArray *arr = entry.score->data;
    char *base_ptr = arr->data + entry.offset;
    size_t entry_size = g_array_get_element_size(arr);

    /*
     * gen_cpu_index() may return the CANONICAL CONSTANT temp for
     * cpu_index (single-vcpu fast path).  Constant temps are shared by
     * value across the whole TB, so they must never be written: scaling
     * in place would silently retarget every later use of that integer
     * constant in the TB -- plugin scoreboard addresses compound
     * xentry_size per op and walk off the array (observed as SIGSEGV in
     * code_gen_buffer), and the cpu_index argument delivered to
     * callbacks becomes the scaled garbage.  Scale into a fresh temp.
     */
    TCGv_i32 cpu_index = gen_cpu_index();
    TCGv_i32 scaled = tcg_temp_ebb_new_i32();
    tcg_gen_muli_i32(scaled, cpu_index, entry_size);
    tcg_gen_ext_i32_ptr(ptr, scaled);
    tcg_temp_free_i32(scaled);
    tcg_temp_free_i32(cpu_index);
    tcg_gen_addi_ptr(ptr, ptr, (intptr_t) base_ptr);

    return ptr;
}

static TCGCond plugin_cond_to_tcgcond(enum qemu_plugin_cond cond)
{
    switch (cond) {
    case QEMU_PLUGIN_COND_EQ:
        return TCG_COND_EQ;
    case QEMU_PLUGIN_COND_NE:
        return TCG_COND_NE;
    case QEMU_PLUGIN_COND_LT:
        return TCG_COND_LTU;
    case QEMU_PLUGIN_COND_LE:
        return TCG_COND_LEU;
    case QEMU_PLUGIN_COND_GT:
        return TCG_COND_GTU;
    case QEMU_PLUGIN_COND_GE:
        return TCG_COND_GEU;
    default:
        /* ALWAYS and NEVER conditions should never reach */
        g_assert_not_reached();
    }
}

static void gen_udata_cond_cb(struct qemu_plugin_conditional_cb *cb)
{
    TCGv_ptr ptr = gen_plugin_u64_ptr(cb->entry);
    TCGv_i64 val = tcg_temp_ebb_new_i64();
    TCGLabel *after_cb = gen_new_label();

    /* Condition should be negated, as calling the cb is the "else" path */
    TCGCond cond = tcg_invert_cond(plugin_cond_to_tcgcond(cb->cond));

    tcg_gen_ld_i64(val, ptr, 0);
    tcg_gen_brcondi_i64(cond, val, cb->imm, after_cb);
    TCGv_i32 cpu_index = gen_cpu_index();
    tcg_gen_call2(cb->f.vcpu_udata, cb->info, NULL,
                  tcgv_i32_temp(cpu_index),
                  tcgv_ptr_temp(tcg_constant_ptr(cb->userp)));
    tcg_temp_free_i32(cpu_index);
    gen_set_label(after_cb);

    tcg_temp_free_i64(val);
    tcg_temp_free_ptr(ptr);
}

static void gen_inline_add_u64_cb(struct qemu_plugin_inline_cb *cb)
{
    TCGv_ptr ptr = gen_plugin_u64_ptr(cb->entry);
    TCGv_i64 val = tcg_temp_ebb_new_i64();

    tcg_gen_ld_i64(val, ptr, 0);
    tcg_gen_addi_i64(val, val, cb->imm);
    tcg_gen_st_i64(val, ptr, 0);

    tcg_temp_free_i64(val);
    tcg_temp_free_ptr(ptr);
}

static void gen_inline_store_u64_cb(struct qemu_plugin_inline_cb *cb)
{
    TCGv_ptr ptr = gen_plugin_u64_ptr(cb->entry);
    TCGv_i64 val = tcg_constant_i64(cb->imm);

    tcg_gen_st_i64(val, ptr, 0);

    tcg_temp_free_ptr(ptr);
}

static void gen_mem_cb(struct qemu_plugin_regular_cb *cb,
                       qemu_plugin_meminfo_t meminfo, TCGv_i64 addr)
{
    TCGv_i32 cpu_index = gen_cpu_index();
    tcg_gen_call4(cb->f.vcpu_mem, cb->info, NULL,
                  tcgv_i32_temp(cpu_index),
                  tcgv_i32_temp(tcg_constant_i32(meminfo)),
                  tcgv_i64_temp(addr),
                  tcgv_ptr_temp(tcg_constant_ptr(cb->userp)));
    tcg_temp_free_i32(cpu_index);
}

static void inject_cb(struct qemu_plugin_dyn_cb *cb)

{
    switch (cb->type) {
    case PLUGIN_CB_REGULAR:
        gen_udata_cb(&cb->regular);
        break;
    case PLUGIN_CB_COND:
        gen_udata_cond_cb(&cb->cond);
        break;
    case PLUGIN_CB_INLINE_ADD_U64:
        gen_inline_add_u64_cb(&cb->inline_insn);
        break;
    case PLUGIN_CB_INLINE_STORE_U64:
        gen_inline_store_u64_cb(&cb->inline_insn);
        break;
    default:
        g_assert_not_reached();
    }
}

static void inject_mem_cb(struct qemu_plugin_dyn_cb *cb,
                          enum qemu_plugin_mem_rw rw,
                          qemu_plugin_meminfo_t meminfo, TCGv_i64 addr)
{
    switch (cb->type) {
    case PLUGIN_CB_MEM_REGULAR:
        if (rw & cb->regular.rw) {
            gen_mem_cb(&cb->regular, meminfo, addr);
        }
        break;
    case PLUGIN_CB_INLINE_ADD_U64:
    case PLUGIN_CB_INLINE_STORE_U64:
        if (rw & cb->inline_insn.rw) {
            inject_cb(cb);
        }
        break;
    default:
        g_assert_not_reached();
    }
}

static void plugin_gen_inject(struct qemu_plugin_tb *plugin_tb)
{
    TCGOp *op, *next;
    int insn_idx = -1;

    if (unlikely(qemu_loglevel_mask(LOG_TB_OP_PLUGIN)
                 && qemu_log_in_addr_range(tcg_ctx->plugin_db->pc_first))) {
        FILE *logfile = qemu_log_trylock();
        if (logfile) {
            fprintf(logfile, "OP before plugin injection:\n");
            tcg_dump_ops(tcg_ctx, logfile, false);
            fprintf(logfile, "\n");
            qemu_log_unlock(logfile);
        }
    }

    /*
     * While injecting code, we cannot afford to reuse any ebb temps
     * that might be live within the existing opcode stream.
     * The simplest solution is to release them all and create new.
     */
    tcg_temp_ebb_reset_freed(tcg_ctx);

    QTAILQ_FOREACH_SAFE(op, &tcg_ctx->ops, link, next) {
        switch (op->opc) {
        case INDEX_op_insn_start:
            insn_idx++;
            break;

        case INDEX_op_plugin_cb:
        {
            enum plugin_gen_from from = op->args[0];
            struct qemu_plugin_insn *insn = NULL;
            const GArray *cbs;
            int i, n;

            if (insn_idx >= 0) {
                insn = g_ptr_array_index(plugin_tb->insns, insn_idx);
            }

            tcg_ctx->emit_before_op = op;

            switch (from) {
            case PLUGIN_GEN_AFTER_TB:
                if (plugin_tb->mem_helper) {
                    gen_disable_mem_helper();
                }
                break;

            case PLUGIN_GEN_AFTER_INSN:
                assert(insn != NULL);
                if (insn->mem_helper) {
                    gen_disable_mem_helper();
                }
                break;

            case PLUGIN_GEN_FROM_TB:
                assert(insn == NULL);

                cbs = plugin_tb->cbs;
                for (i = 0, n = (cbs ? cbs->len : 0); i < n; i++) {
                    inject_cb(
                        &g_array_index(cbs, struct qemu_plugin_dyn_cb, i));
                }
                break;

            case PLUGIN_GEN_FROM_INSN:
                assert(insn != NULL);

                gen_enable_mem_helper(plugin_tb, insn);

                cbs = insn->insn_cbs;
                for (i = 0, n = (cbs ? cbs->len : 0); i < n; i++) {
                    inject_cb(
                        &g_array_index(cbs, struct qemu_plugin_dyn_cb, i));
                }
                break;

            default:
                g_assert_not_reached();
            }

            tcg_ctx->emit_before_op = NULL;
            tcg_op_remove(tcg_ctx, op);
            break;
        }

        case INDEX_op_plugin_mem_cb:
        {
            TCGv_i64 addr = temp_tcgv_i64(arg_temp(op->args[0]));
            qemu_plugin_meminfo_t meminfo = op->args[1];
            enum qemu_plugin_mem_rw rw =
                (qemu_plugin_mem_is_store(meminfo)
                 ? QEMU_PLUGIN_MEM_W : QEMU_PLUGIN_MEM_R);
            struct qemu_plugin_insn *insn;
            const GArray *cbs;
            int i, n;

            assert(insn_idx >= 0);
            insn = g_ptr_array_index(plugin_tb->insns, insn_idx);

            tcg_ctx->emit_before_op = op;

            cbs = insn->mem_cbs;
            for (i = 0, n = (cbs ? cbs->len : 0); i < n; i++) {
                inject_mem_cb(&g_array_index(cbs, struct qemu_plugin_dyn_cb, i),
                              rw, meminfo, addr);
            }

            tcg_ctx->emit_before_op = NULL;
            tcg_op_remove(tcg_ctx, op);
            break;
        }

        default:
            /* plugins don't care about any other ops */
            break;
        }
    }
}

bool plugin_gen_tb_start(CPUState *cpu, const DisasContextBase *db)
{
    struct qemu_plugin_tb *ptb;

    if (!test_bit(QEMU_PLUGIN_EV_VCPU_TB_TRANS,
                  cpu->plugin_state->event_mask)) {
        return false;
    }

    tcg_ctx->plugin_db = db;
    tcg_ctx->plugin_insn = NULL;
    ptb = tcg_ctx->plugin_tb;

    if (ptb) {
        /* Reset callbacks */
        if (ptb->cbs) {
            g_array_set_size(ptb->cbs, 0);
        }
        ptb->n = 0;
        ptb->mem_helper = false;
    } else {
        ptb = g_new0(struct qemu_plugin_tb, 1);
        tcg_ctx->plugin_tb = ptb;
        ptb->insns = g_ptr_array_new();
    }

    tcg_gen_plugin_cb(PLUGIN_GEN_FROM_TB);
    return true;
}

void plugin_gen_insn_start(CPUState *cpu, const DisasContextBase *db)
{
    struct qemu_plugin_tb *ptb = tcg_ctx->plugin_tb;
    struct qemu_plugin_insn *insn;
    size_t n = db->num_insns;
    vaddr pc;

    assert(n >= 1);
    ptb->n = n;
    if (n <= ptb->insns->len) {
        insn = g_ptr_array_index(ptb->insns, n - 1);
    } else {
        assert(n - 1 == ptb->insns->len);
        insn = g_new0(struct qemu_plugin_insn, 1);
        g_ptr_array_add(ptb->insns, insn);
    }

    tcg_ctx->plugin_insn = insn;
    insn->calls_helpers = false;
    insn->mem_helper = false;
    if (insn->insn_cbs) {
        g_array_set_size(insn->insn_cbs, 0);
    }
    if (insn->mem_cbs) {
        g_array_set_size(insn->mem_cbs, 0);
    }

    pc = db->pc_next;
    insn->vaddr = pc;
    /*
     * Cleared per-insn -- set by plugin_gen_record_branch_target() if
     * the target translator resolves a static branch target while
     * decoding this instruction.  Insn structs are reused across
     * translations, so failing to reset would leak a stale target
     * onto a later, unrelated insn.
     */
    insn->branch_target_pc = 0;
    insn->transfer_kind = QEMU_PLUGIN_TRANSFER_NONE;
    /* the register statement, likewise */
    reg_cpu = cpu;
    if (insn->regs) {
        g_array_set_size(insn->regs, 0);
    }
    if (insn->reg_notes) {
        g_array_set_size(insn->reg_notes, 0);
    }
    insn->reg_opaque = NULL;
    insn->reg_covered = false;
    insn->reg_mute = PLUGIN_REG_MUTE_OFF;

    tcg_gen_plugin_cb(PLUGIN_GEN_FROM_INSN);
}

void plugin_gen_record_branch_target(uint64_t target_pc)
{
    struct qemu_plugin_insn *insn = tcg_ctx->plugin_insn;
    if (insn) {
        insn->branch_target_pc = target_pc;
        insn->transfer_kind = QEMU_PLUGIN_TRANSFER_STATIC;
    }
}

void plugin_gen_record_transfer(enum qemu_plugin_transfer_kind kind)
{
    struct qemu_plugin_insn *insn = tcg_ctx->plugin_insn;
    if (insn) {
        insn->transfer_kind = kind;
    }
}

/*
 * The register statement (qemu_plugin_insn_reg_list()).
 *
 * The ops an instruction emits ARE its register accesses: a TCG global of
 * CPU state read or written, a load or store at a CPU-state offset, a
 * CPU-state pointer handed to a helper.  plugin_gen_insn_end() walks them
 * (reg_walk()) and the target's resolve hook names the register behind
 * each field.  Ops behind a branch are in the list too, so the result is
 * what the instruction MAY read and write.  The translator adds what the
 * ops cannot show -- implicit and constant-indexed helper operands, zero
 * registers -- through plugin_gen_reg*(), recorded as notes anchored at
 * the last op emitted, so statement order is emission order.
 */
typedef struct PluginRegNote {
    TCGOp *anchor;
    enum { NOTE_REG, NOTE_TEMP, NOTE_MUTE } kind;
    uint8_t access;         /* NOTE_REG: bits; NOTE_MUTE: mode */
    TCGTemp *temp;
    PluginRegDesc d;
} PluginRegNote;

/*
 * One register being collected: the accesses the ops showed, the notes
 * stated, and whether it was only handed to a helper by pointer.  @wdef:
 * written on every path so far, so a later read sees the instruction's
 * own result, not an input.
 */
typedef struct RegAcc {
    PluginRegDesc d;
    uint8_t ops, stated;
    bool ptr, noted, wdef;
} RegAcc;

static void reg_note(PluginRegNote *n)
{
    struct qemu_plugin_insn *insn = tcg_ctx->plugin_insn;

    if (!insn) {
        return;
    }
    if (!insn->reg_notes) {
        insn->reg_notes = g_array_new(false, false, sizeof(PluginRegNote));
    }
    n->anchor = tcg_last_op();
    g_array_append_val(insn->reg_notes, *n);
}

void plugin_gen_reg(const PluginRegDesc *d, unsigned access)
{
    struct qemu_plugin_insn *insn = tcg_ctx->plugin_insn;
    PluginRegNote n = { .kind = NOTE_REG, .access = access, .d = *d };

    if (insn && insn->reg_mute) {   /* a muted span states nothing */
        n.access &= insn->reg_mute == PLUGIN_REG_MUTE_ALL ? 0 :
                    QEMU_PLUGIN_REG_READ;
        if (!n.access) {
            return;
        }
    }
    reg_note(&n);
}

static int reg_resolve(intptr_t off, unsigned size, PluginRegDesc *d)
{
    const TCGCPUOps *ops = reg_cpu ? reg_cpu->cc->tcg_ops : NULL;

    memset(d, 0, sizeof(*d));
    return ops && ops->plugin_reg_resolve ?
           ops->plugin_reg_resolve(reg_cpu, off, size, d) : PLUGIN_REG_UNKNOWN;
}

void plugin_gen_reg_env(intptr_t offset, unsigned access)
{
    PluginRegDesc d;

    if (tcg_ctx->plugin_insn &&
        reg_resolve(offset, 1, &d) == PLUGIN_REG_ARCH) {
        plugin_gen_reg(&d, access);
    }
}

void plugin_gen_reg_temp(TCGTemp *t, const PluginRegDesc *d)
{
    PluginRegNote n = { .kind = NOTE_TEMP, .temp = t, .d = *d };

    reg_note(&n);
}

void plugin_gen_reg_covered(void)
{
    if (tcg_ctx->plugin_insn) {
        tcg_ctx->plugin_insn->reg_covered = true;
    }
}

void plugin_gen_reg_mute(int mode)
{
    PluginRegNote n = { .kind = NOTE_MUTE, .access = mode };

    if (tcg_ctx->plugin_insn) {
        tcg_ctx->plugin_insn->reg_mute = mode;
        reg_note(&n);
    }
}

static void reg_add(GArray *acc, const PluginRegDesc *d, unsigned access,
                    bool ptr, bool noted)
{
    RegAcc *a = NULL;

    for (guint i = 0; i < acc->len && !a; i++) {
        RegAcc *e = &g_array_index(acc, RegAcc, i);
        a = e->d.cls == d->cls && e->d.index == d->index ? e : NULL;
    }
    if (!a) {
        RegAcc z = { .d = *d };
        g_array_append_val(acc, z);
        a = &g_array_index(acc, RegAcc, acc->len - 1);
    }
    a->d.width = MAX(a->d.width, d->width);
    a->ptr |= ptr;
    a->noted |= noted;
    if (noted) {
        a->stated |= access;
    } else if (!ptr) {
        access &= a->wdef ? ~QEMU_PLUGIN_REG_READ : ~0;
        a->ops |= access;
        a->wdef |= access & QEMU_PLUGIN_REG_WRITE;
    }
}

static void reg_opaque(struct qemu_plugin_insn *insn, const char *what)
{
    if (!insn->reg_opaque) {
        insn->reg_opaque = g_intern_string(what);
    }
}

/* A CPU-state field accessed by an op: add its register, or say why not */
static void reg_field(struct qemu_plugin_insn *insn, GArray *acc,
                      intptr_t off, unsigned size, unsigned access, bool ptr)
{
    PluginRegDesc d;
    char what[40];

    switch (reg_resolve(off, size, &d)) {
    case PLUGIN_REG_ARCH:
        reg_add(acc, &d, access, ptr, false);
        break;
    case PLUGIN_REG_UNKNOWN:
        snprintf(what, sizeof(what), "cpu-state+%#" PRIxPTR, off);
        reg_opaque(insn, what);
        break;
    }
}

static unsigned reg_ldst_size(TCGOp *op)
{
    switch (op->opc) {
    case INDEX_op_ld8u_i32: case INDEX_op_ld8s_i32: case INDEX_op_st8_i32:
    case INDEX_op_ld8u_i64: case INDEX_op_ld8s_i64: case INDEX_op_st8_i64:
        return 1;
    case INDEX_op_ld16u_i32: case INDEX_op_ld16s_i32: case INDEX_op_st16_i32:
    case INDEX_op_ld16u_i64: case INDEX_op_ld16s_i64: case INDEX_op_st16_i64:
        return 2;
    case INDEX_op_ld_i32: case INDEX_op_st_i32: case INDEX_op_ld32u_i64:
    case INDEX_op_ld32s_i64: case INDEX_op_st32_i64:
        return 4;
    case INDEX_op_ld_i64: case INDEX_op_st_i64:
        return 8;
    case INDEX_op_ld_vec: case INDEX_op_st_vec: case INDEX_op_dupm_vec:
        return tcg_type_size(TCGOP_TYPE(op));
    default:
        return 0;
    }
}

/* Offset from env that temp @t holds, per @ptrs; INTPTR_MIN if unknown */
static bool reg_ptr(GHashTable *ptrs, TCGTemp *t, intptr_t *off)
{
    gpointer v;

    if (t == tcgv_ptr_temp(tcg_env)) {
        *off = 0;
        return true;
    }
    if (g_hash_table_lookup_extended(ptrs, t, NULL, &v)) {
        *off = (intptr_t)v;
        return true;
    }
    return false;
}

/*
 * The TCG runtime's own helpers (accel/tcg/tcg-runtime.h) take env for a
 * block exit or a memory access, never for a register.
 */
static bool reg_runtime_helper(const char *name)
{
    return !strcmp(name, "lookup_tb_ptr") || !strcmp(name, "exit_atomic") ||
           g_str_has_prefix(name, "atomic_");
}

static void reg_walk(const DisasContextBase *db, struct qemu_plugin_insn *insn)
{
    TCGTemp *env = tcgv_ptr_temp(tcg_env);
    g_autoptr(GArray) acc = g_array_new(false, false, sizeof(RegAcc));
    g_autoptr(GHashTable) ptrs = g_hash_table_new(NULL, NULL);
    g_autoptr(GHashTable) temps = g_hash_table_new(NULL, NULL);
    GArray *notes = insn->reg_notes;
    guint next = 0;
    int mute = 0;
    TCGOp *op = db->insn_start;

    for (; op; op = QTAILQ_NEXT(op, link)) {
        const TCGOpDef *def = &tcg_op_defs[op->opc];
        bool call = op->opc == INDEX_op_call;
        unsigned no = call ? TCGOP_CALLO(op) : def->nb_oargs;
        unsigned ni = call ? TCGOP_CALLI(op) : def->nb_iargs;
        unsigned size = reg_ldst_size(op);
        bool takes_env = false;
        intptr_t off;

        if (op->opc == INDEX_op_insn_start || op->opc == INDEX_op_discard ||
            op->opc == INDEX_op_plugin_cb || mute == PLUGIN_REG_MUTE_ALL) {
            goto notes;
        }
        if (size) {         /* host load/store: base is the last input */
            TCGTemp *base = arg_temp(op->args[no + ni - 1]);
            if (reg_ptr(ptrs, base, &off)) {
                if (off == INTPTR_MIN) {
                    reg_opaque(insn, "cpu-state[run-time index]");
                } else {
                    reg_field(insn, acc, off + op->args[no + ni], size,
                              no ? QEMU_PLUGIN_REG_READ :
                              mute ? 0 : QEMU_PLUGIN_REG_WRITE, false);
                }
            }
        }
        if (op->opc == INDEX_op_set_label) {     /* a join: paths merge */
            for (guint i = 0; i < acc->len; i++) {
                g_array_index(acc, RegAcc, i).wdef = false;
            }
        }
        for (unsigned k = 0; k < no + ni; k++) {
            unsigned i = (k + no) % (no + ni);  /* inputs, then outputs */
            TCGTemp *t = arg_temp(op->args[i]);
            unsigned access = i < no ? (mute ? 0 : QEMU_PLUGIN_REG_WRITE) :
                              QEMU_PLUGIN_REG_READ;
            PluginRegDesc *d = g_hash_table_lookup(temps, t);

            if (!t) {
                continue;
            }
            if (d) {
                reg_add(acc, d, access, false, false);
            } else if (t->kind == TEMP_GLOBAL && t->mem_base == env) {
                reg_field(insn, acc, t->mem_offset,
                          tcg_type_size(t->base_type), access, false);
            } else if (call && i >= no && reg_ptr(ptrs, t, &off)) {
                takes_env |= t == env;
                if (off == INTPTR_MIN) {
                    reg_opaque(insn, "cpu-state[run-time index]");
                } else if (t != env) {
                    reg_field(insn, acc, off, 1, QEMU_PLUGIN_REG_READ |
                              QEMU_PLUGIN_REG_WRITE, true);
                }
            }
        }
        if (call && takes_env && !insn->reg_covered &&
            !reg_runtime_helper(tcg_call_info(op)->name)) {
            reg_opaque(insn, tcg_call_info(op)->name);
        }
        /* track pointers into CPU state: env + constant */
        if (no == 1 && !call) {
            TCGTemp *out = arg_temp(op->args[0]);
            intptr_t base;
            bool derived = false;
            if ((op->opc == INDEX_op_mov_i64 || op->opc == INDEX_op_mov_i32) &&
                reg_ptr(ptrs, arg_temp(op->args[1]), &base)) {
                derived = true;
            } else if (op->opc == INDEX_op_add_i64 ||
                       op->opc == INDEX_op_add_i32) {
                TCGTemp *a = arg_temp(op->args[1]), *b = arg_temp(op->args[2]);
                if (!reg_ptr(ptrs, a, &base)) {
                    TCGTemp *s = a; a = b; b = s;
                }
                if (reg_ptr(ptrs, a, &base)) {
                    derived = true;
                    base = b->kind == TEMP_CONST && base != INTPTR_MIN ?
                           base + b->val : INTPTR_MIN;
                }
            }
            if (derived && out->kind != TEMP_GLOBAL) {
                g_hash_table_insert(ptrs, out, (gpointer)base);
            } else {
                g_hash_table_remove(ptrs, out);
            }
        }
    notes:
        for (; notes && next < notes->len; next++) {
            PluginRegNote *n = &g_array_index(notes, PluginRegNote, next);
            if (n->anchor != op && QTAILQ_NEXT(op, link)) {
                break;
            }
            if (n->kind == NOTE_MUTE) {
                mute = n->access;
            } else if (n->kind == NOTE_TEMP) {
                g_hash_table_insert(temps, n->temp, &n->d);
            } else {
                reg_add(acc, &n->d, n->access, false, true);
            }
        }
    }

    if (!insn->regs) {
        insn->regs = g_array_new(false, false,
                                 sizeof(struct qemu_plugin_insn_reg));
    }
    for (guint i = 0; i < acc->len; i++) {
        RegAcc *a = &g_array_index(acc, RegAcc, i);
        unsigned access = a->ops | a->stated |
            (a->ptr && !a->noted ? QEMU_PLUGIN_REG_READ |
                                   QEMU_PLUGIN_REG_WRITE : 0);
        struct qemu_plugin_insn_reg r = {
            .reg_class = a->d.cls, .access = access, .index = a->d.index,
            .width = a->d.width, .name = g_intern_string(a->d.name),
        };
        if (access) {
            g_array_append_val(insn->regs, r);
        }
    }
}

void plugin_gen_insn_end(void)
{
    const DisasContextBase *db = tcg_ctx->plugin_db;
    struct qemu_plugin_insn *pinsn = tcg_ctx->plugin_insn;

    pinsn->len = db->fake_insn ? db->record_len : db->pc_next - pinsn->vaddr;
    reg_walk(db, pinsn);

    tcg_gen_plugin_cb(PLUGIN_GEN_AFTER_INSN);
}

/*
 * There are cases where we never get to finalise a translation - for
 * example a page fault during translation. As a result we shouldn't
 * do any clean-up here and make sure things are reset in
 * plugin_gen_tb_start.
 */
void plugin_gen_tb_end(CPUState *cpu, size_t num_insns)
{
    struct qemu_plugin_tb *ptb = tcg_ctx->plugin_tb;

    /* translator may have removed instructions, update final count */
    g_assert(num_insns <= ptb->n);
    ptb->n = num_insns;

    /* collect instrumentation requests */
    qemu_plugin_tb_trans_cb(cpu, ptb);

    /* inject the instrumentation at the appropriate places */
    plugin_gen_inject(ptb);

    /* reset plugin translation state (plugin_tb is reused between blocks) */
    tcg_ctx->plugin_db = NULL;
    tcg_ctx->plugin_insn = NULL;
}
