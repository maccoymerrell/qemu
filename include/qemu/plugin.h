/*
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#ifndef QEMU_PLUGIN_H
#define QEMU_PLUGIN_H

#include "qemu/config-file.h"
#include "qemu/qemu-plugin.h"
#include "qemu/error-report.h"
#include "qemu/queue.h"
#include "qemu/option.h"
#include "qemu/plugin-event.h"
#include "qemu/bitmap.h"
#include "exec/memopidx.h"
#include "hw/core/cpu.h"

/*
 * Option parsing/processing.
 * Note that we can load an arbitrary number of plugins.
 */
struct qemu_plugin_desc;
typedef QTAILQ_HEAD(, qemu_plugin_desc) QemuPluginList;

/*
 * Construct a qemu_plugin_meminfo_t.
 */
static inline qemu_plugin_meminfo_t
make_plugin_meminfo(MemOpIdx oi, enum qemu_plugin_mem_rw rw)
{
    return oi | (rw << 16);
}

/*
 * Extract the memory operation direction from a qemu_plugin_meminfo_t.
 * Other portions may be extracted via get_memop and get_mmuidx.
 */
static inline enum qemu_plugin_mem_rw
get_plugin_meminfo_rw(qemu_plugin_meminfo_t i)
{
    return i >> 16;
}

#ifdef CONFIG_PLUGIN
extern QemuOptsList qemu_plugin_opts;

/**
 * qemu_plugin_any_loaded() - true once at least one plugin has been loaded
 *
 * Valid from qemu_plugin_load_list() onwards, i.e. for every device realize
 * function.  Machine/device code uses it where a plugin changes a contract the
 * device depends on (see the RTC's guest-time-transparency note).
 */
bool qemu_plugin_any_loaded(void);

static inline void qemu_plugin_add_opts(void)
{
    qemu_add_opts(&qemu_plugin_opts);
}

void qemu_plugin_opt_parse(const char *optstr, QemuPluginList *head);
int qemu_plugin_load_list(QemuPluginList *head, Error **errp);

union qemu_plugin_cb_sig {
    qemu_plugin_simple_cb_t          simple;
    qemu_plugin_udata_cb_t           udata;
    qemu_plugin_vcpu_simple_cb_t     vcpu_simple;
    qemu_plugin_vcpu_udata_cb_t      vcpu_udata;
    qemu_plugin_vcpu_tb_trans_cb_t   vcpu_tb_trans;
    qemu_plugin_vcpu_mem_cb_t        vcpu_mem;
    qemu_plugin_vcpu_syscall_cb_t    vcpu_syscall;
    qemu_plugin_vcpu_syscall_ret_cb_t vcpu_syscall_ret;
    void *generic;
};

enum plugin_dyn_cb_type {
    PLUGIN_CB_REGULAR,
    PLUGIN_CB_COND,
    PLUGIN_CB_MEM_REGULAR,
    PLUGIN_CB_INLINE_ADD_U64,
    PLUGIN_CB_INLINE_STORE_U64,
};

struct qemu_plugin_regular_cb {
    union qemu_plugin_cb_sig f;
    TCGHelperInfo *info;
    void *userp;
    enum qemu_plugin_mem_rw rw;
};

struct qemu_plugin_inline_cb {
    qemu_plugin_u64 entry;
    uint64_t imm;
    enum qemu_plugin_mem_rw rw;
};

struct qemu_plugin_conditional_cb {
    union qemu_plugin_cb_sig f;
    TCGHelperInfo *info;
    void *userp;
    qemu_plugin_u64 entry;
    enum qemu_plugin_cond cond;
    uint64_t imm;
};

/*
 * A dynamic callback has an insertion point that is determined at run-time.
 * Usually the insertion point is somewhere in the code cache; think for
 * instance of a callback to be called upon the execution of a particular TB.
 */
struct qemu_plugin_dyn_cb {
    enum plugin_dyn_cb_type type;
    union {
        struct qemu_plugin_regular_cb regular;
        struct qemu_plugin_conditional_cb cond;
        struct qemu_plugin_inline_cb inline_insn;
    };
};

/* Internal context for instrumenting an instruction */
struct qemu_plugin_insn {
    uint64_t vaddr;
    /*
     * Static control-transfer target the target translator resolved
     * for this instruction (the same value handed to gen_goto_tb).
     * Populated by per-ISA translators via
     * plugin_gen_record_branch_target() at branch-decode time.  0
     * means "no static target": either this insn is not a branch, or
     * it's an indirect branch whose target is only known at runtime
     * (those route through the plugin's BranchHistory instead).
     */
    uint64_t branch_target_pc;
    /*
     * QEMU's own decode-table identity for this instruction: the slot
     * the target decoder dispatched on, and that slot's name in QEMU
     * source vocabulary.  Populated by per-ISA translators via
     * plugin_gen_record_insn_identity() at the point the slot is
     * selected.  decode_id == 0 means "this target recorded nothing";
     * decode_name is then NULL.
     *
     * decode_name is NOT unique -- on x86_64 472 of 854 table slots
     * share a name with another slot.  decode_id is the unique half.
     * See include/qemu/qemu-plugin.h for the full contract.
     */
    uint32_t decode_id;
    const char *decode_name;
    GArray *insn_cbs;
    GArray *mem_cbs;
    uint8_t len;
    bool calls_helpers;

    /* if set, the instruction calls helpers that might access guest memory */
    bool mem_helper;
    /*
     * The op range this instruction's translate_insn() emitted, and the
     * control-transfer classification read back out of it by
     * insn_ctrl_classify() (accel/tcg/insn-ctrl.h).
     *
     * ctrl_first_op is the PLUGIN_GEN_FROM_INSN marker emitted by
     * plugin_gen_insn_start(); the range starts at the op AFTER it.
     * ctrl_last_op is the op list's tail at the moment translate_insn()
     * returned, taken in plugin_gen_insn_end() before that function emits
     * anything of its own.  Bounding by the NEXT insn_start instead would
     * hand the block's epilogue -- the interrupt exit, and the goto_tb
     * emitted when a block merely ran out of room -- to whichever
     * instruction happened to be last, which reads as a branch.
     *
     * Both are TCGOp pointers into tcg_ctx->ops and are valid only until
     * plugin_gen_inject() rewrites that list.  They are cleared once the
     * classification has been taken.
     *
     * APPENDED, and every future addition must be too.  These fields were
     * first written into the middle of the struct, above insn_cbs, and the
     * result was a build in which one object still held the old offsets: the
     * very next translation read insn_cbs out of ctrl_link_reg's bytes and
     * handed the garbage to g_array_set_size().  It is the same failure the
     * plugin dataflow ABI was designed around (see qemu-plugin-dataflow.h),
     * met again inside QEMU's own tree, and the same rule answers it.
     */
    const void *ctrl_first_op;
    const void *ctrl_last_op;
    uint32_t ctrl_flags;        /* QEMU_PLUGIN_CTRL_* */
    uint64_t ctrl_target;       /* the taken edge's constant, 0 if none */
    int32_t  ctrl_target_reg;   /* TCG global the target was read from, -1 */
    int32_t  ctrl_addr_reg;     /* the load's address register, -1 */
    /*
     * Where the LINK value went: the guest register the fall-through
     * constant was assigned to, or -- when it was stored to memory -- the
     * register the store's address was computed from.  Both -1 when the
     * instruction publishes no return address.  This is what lets a consumer
     * LEARN which register is the link register and which is the stack
     * pointer, from the calls it sees, instead of being told their names.
     */
    int32_t  ctrl_link_reg;
    int32_t  ctrl_link_addr_reg;
};

/* A scoreboard is an array of values, indexed by vcpu_index */
struct qemu_plugin_scoreboard {
    GArray *data;
    QLIST_ENTRY(qemu_plugin_scoreboard) entry;
};

/* Internal context for this TranslationBlock */
struct qemu_plugin_tb {
    GPtrArray *insns;
    size_t n;

    /* if set, the TB calls helpers that might access guest memory */
    bool mem_helper;

    GArray *cbs;
};

/**
 * struct CPUPluginState - per-CPU state for plugins
 * @event_mask: plugin event bitmap. Modified only via async work.
 */
struct CPUPluginState {
    DECLARE_BITMAP(event_mask, QEMU_PLUGIN_EV_MAX);
};

/**
 * qemu_plugin_create_vcpu_state: allocate plugin state
 *
 * The returned data must be released with g_free()
 * when no longer required.
 */
CPUPluginState *qemu_plugin_create_vcpu_state(void);

void qemu_plugin_vcpu_init_hook(CPUState *cpu);
void qemu_plugin_vcpu_exit_hook(CPUState *cpu);
void qemu_plugin_tb_trans_cb(CPUState *cpu, struct qemu_plugin_tb *tb);
void qemu_plugin_vcpu_idle_cb(CPUState *cpu);
void qemu_plugin_vcpu_resume_cb(CPUState *cpu);
void
qemu_plugin_vcpu_syscall(CPUState *cpu, int64_t num, uint64_t a1,
                         uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5,
                         uint64_t a6, uint64_t a7, uint64_t a8);
void qemu_plugin_vcpu_syscall_ret(CPUState *cpu, int64_t num, int64_t ret);

/*
 * Count of syscalls refused because the vCPU was on a plugin wrong path.
 * The suppression is structural (see plugins/core.c); this counter is the
 * standing proof that it holds, and stays 0 on a healthy run.
 */
extern uint64_t qemu_plugin_spec_syscall_blocked;

void qemu_plugin_vcpu_mem_cb(CPUState *cpu, uint64_t vaddr,
                             uint64_t value_low,
                             uint64_t value_high,
                             MemOpIdx oi, enum qemu_plugin_mem_rw rw);

void qemu_plugin_flush_cb(void);

/*
 * Block-device I/O notification, dispatched to a plugin's registered
 * devio hooks (qemu_plugin_register_devio_cb).
 *
 * qemu_plugin_devio_doorbell is called from the virtqueue notify (kick)
 * chokepoint, which runs in vCPU context; it resolves the issuing vCPU
 * from current_cpu and passes @dev_token (the block device's DeviceState
 * pointer as an integer) so the plugin can correlate the later issue.
 *
 * qemu_plugin_devio_start / _stop are called from the block backend's
 * blk_aio_* issue and completion chokepoints (which may run off the vCPU
 * thread); the issue passes @dev_token so the plugin can match the
 * doorbell captured in vCPU context.  qemu_plugin_devio_start returns
 * the plugin's request id, or 0 when unregistered / not tracked (no stop
 * is then dispatched for this request).
 */
void qemu_plugin_devio_doorbell(uint64_t dev_token);
uint64_t qemu_plugin_devio_start(int dir, uint64_t offset, uint64_t bytes,
                                 uint64_t dev_token);
void qemu_plugin_devio_stop(uint64_t request_id);

void qemu_plugin_atexit_cb(void);

/*
 * The machine is going down.  Dispatched to a plugin's registered
 * shutdown hook (qemu_plugin_register_vm_shutdown_cb) from the shutdown
 * request and from the main loop's shutdown acknowledge — whichever
 * happens first; the second is a no-op.  Both run before qemu_cleanup(),
 * so the machine is still assembled and the vCPUs still exist, which is
 * what makes this the last usable point for a plugin that must CLOSE
 * something: guest memory, registers and the privilege/address-space
 * APIs all resolve through current_cpu, which is NULL at atexit time.
 */
void qemu_plugin_vm_shutdown(void);

/*
 * The two halves of that dispatch.  _armed reports whether a plugin
 * registered a hook that has not yet fired; _dispatch delivers it at most
 * once per run, claiming the single delivery atomically because more than
 * one thread may offer it.
 *
 * @vcpu_index names the vCPU the shutdown CAME FROM, not the vCPU the
 * callback ended up on: QEMU_PLUGIN_VCPU_UNNAMED where the request came
 * from outside the machine and a vCPU was borrowed to run the callback,
 * QEMU_PLUGIN_VCPU_NONE where there was no vCPU to borrow.
 */
bool qemu_plugin_vm_shutdown_dispatch(int vcpu_index,
                                     bool in_guest_insn);
bool qemu_plugin_vm_shutdown_armed(void);

/*
 * The machine is about to RESET: torn down and booted again inside the
 * same process.  Dispatched to a plugin's registered reset hook
 * (qemu_plugin_register_vm_reset_cb) from the reset request — the one
 * funnel every delivery path (guest reset device writes, x86 triple
 * fault, watchdog reset action, monitor/QMP system_reset) passes
 * through — before the main loop pauses the vCPUs and resets the
 * machine.  A request that -no-reboot converts into a shutdown takes
 * the shutdown dispatch instead and never reaches this one.  Unlike
 * the shutdown dispatch this can fire more than once per run: each
 * teardown is its own event, and only concurrent duplicates of the
 * SAME event are folded.
 */
void qemu_plugin_vm_reset(void);
bool qemu_plugin_vm_reset_dispatch(int vcpu_index, bool in_guest_insn);
bool qemu_plugin_vm_reset_armed(void);

/*
 * Wait for a guest-route reset dispatch to be DELIVERED before the reset
 * is performed.  A guest-initiated reset arrives on the writing vCPU with
 * the BQL held, so qemu_plugin_vm_reset() queues the callback on that
 * vCPU rather than run it under the write's own lock (the AB/BA against a
 * plugin lock a peer holds across a wrong-path excursion) — and the
 * pause that precedes the reset does not wait for work queues.  Called
 * from the reset performance, under the BQL, before the machine the
 * callback must report on is torn down; a no-op when nothing was
 * deferred.
 */
void qemu_plugin_vm_reset_wait_placed(void);

/*
 * Guest-kernel current-task location hint, declared by a plugin via
 * qemu_plugin_set_current_task_offset() and consumed by a target's
 * plugin-state hooks (today: x86-64's get_plugin_thread_ptr /
 * plugin_thread_ptr_tracks_current, which dereference the kernel
 * per-CPU base at this offset to name the running task at CPL0).
 * Returns the declared offset; *@set reports whether one was declared
 * at all — an undeclared hint MUST leave the target's legacy
 * register-only behaviour untouched.
 */
uint64_t qemu_plugin_current_task_offset(bool *set);
void qemu_plugin_current_task_offset_store(uint64_t offset);

/*
 * Never-split (atomic) code byte sequences registered by a plugin
 * (qemu_plugin_register_nosplit_code_sequences).  The translator consults
 * them at every clean TB-end decision and continues translating through a
 * sequence a TB boundary would otherwise cut.  Returns the number of
 * registered sequences (0 = feature off) and fills @seqs[] (up to
 * QEMU_PLUGIN_NOSPLIT_MAX pointers, valid for the process lifetime) and
 * *@seq_len (all sequences share one length).
 */
#define QEMU_PLUGIN_NOSPLIT_MAX 2
size_t qemu_plugin_nosplit_seqs(const uint8_t **seqs, size_t *seq_len);

void qemu_plugin_add_dyn_cb_arr(GArray *arr);

static inline void qemu_plugin_disable_mem_helpers(CPUState *cpu)
{
    cpu->neg.plugin_mem_cbs = NULL;
}

/**
 * qemu_plugin_user_exit(): clean-up callbacks before calling exit callbacks
 *
 * This is a user-mode only helper that ensure we have fully cleared
 * callbacks from all threads before calling the exit callbacks. This
 * is so the plugins themselves don't have to jump through hoops to
 * guard against race conditions.
 */
void qemu_plugin_user_exit(void);

/**
 * qemu_plugin_user_prefork_lock(): take plugin lock before forking
 *
 * This is a user-mode only helper to take the internal plugin lock
 * before a fork event. This is ensure a consistent lock state
 */
void qemu_plugin_user_prefork_lock(void);

/**
 * qemu_plugin_user_postfork(): reset the plugin lock
 * @is_child: is this thread the child
 *
 * This user-mode only helper resets the lock state after a fork so we
 * can continue using the plugin interface.
 */
void qemu_plugin_user_postfork(bool is_child);

#else /* !CONFIG_PLUGIN */

#define QEMU_PLUGIN_NOSPLIT_MAX 2
static inline size_t qemu_plugin_nosplit_seqs(const uint8_t **seqs,
                                              size_t *seq_len)
{
    return 0;
}

static inline void qemu_plugin_add_opts(void)
{ }

static inline void qemu_plugin_opt_parse(const char *optstr,
                                         QemuPluginList *head)
{
    error_report("plugin interface not enabled in this build");
    exit(1);
}

static inline int qemu_plugin_load_list(QemuPluginList *head, Error **errp)
{
    return 0;
}

static inline void qemu_plugin_vcpu_init_hook(CPUState *cpu)
{ }

static inline void qemu_plugin_vcpu_exit_hook(CPUState *cpu)
{ }

static inline void qemu_plugin_tb_trans_cb(CPUState *cpu,
                                           struct qemu_plugin_tb *tb)
{ }

static inline void qemu_plugin_vcpu_idle_cb(CPUState *cpu)
{ }

static inline void qemu_plugin_vcpu_resume_cb(CPUState *cpu)
{ }

static inline void
qemu_plugin_vcpu_syscall(CPUState *cpu, int64_t num, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                         uint64_t a7, uint64_t a8)
{ }

static inline
void qemu_plugin_vcpu_syscall_ret(CPUState *cpu, int64_t num, int64_t ret)
{ }

static inline void qemu_plugin_vcpu_mem_cb(CPUState *cpu, uint64_t vaddr,
                                           uint64_t value_low,
                                           uint64_t value_high,
                                           MemOpIdx oi,
                                           enum qemu_plugin_mem_rw rw)
{ }

static inline void qemu_plugin_flush_cb(void)
{ }

static inline void qemu_plugin_devio_doorbell(uint64_t dev_token)
{ }

static inline uint64_t qemu_plugin_devio_start(int dir, uint64_t offset,
                                               uint64_t bytes,
                                               uint64_t dev_token)
{
    return 0;
}

static inline void qemu_plugin_devio_stop(uint64_t request_id)
{ }

static inline void qemu_plugin_atexit_cb(void)
{ }

static inline void qemu_plugin_vm_shutdown(void)
{ }

static inline void qemu_plugin_vm_reset(void)
{ }

static inline void qemu_plugin_vm_reset_wait_placed(void)
{ }

static inline
void qemu_plugin_add_dyn_cb_arr(GArray *arr)
{ }

static inline void qemu_plugin_disable_mem_helpers(CPUState *cpu)
{ }

static inline void qemu_plugin_user_exit(void)
{ }

static inline void qemu_plugin_user_prefork_lock(void)
{ }

static inline void qemu_plugin_user_postfork(bool is_child)
{ }

#endif /* !CONFIG_PLUGIN */

#endif /* QEMU_PLUGIN_H */
