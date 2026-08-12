/*
 * QEMU Plugin Core code
 *
 * This is the core code that deals with injecting instrumentation into the code
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019, Linaro
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/lockable.h"
#include "qemu/main-loop.h"
#include "qemu/option.h"
#include "qemu/plugin.h"
#include "qemu/queue.h"
#include "qemu/rcu_queue.h"
#include "qemu/rcu.h"
#include "exec/tb-flush.h"
#include "tcg/tcg-op-common.h"
#include "plugin.h"
#include "accel/tcg/cpu-ops.h"

/*
 * Ordered per-vCPU path-event producer (see QemuPluginCpuEventQueue in
 * hw/core/cpu.h).  Called from the fault push/pop helpers and the async
 * delivery/close chokepoints, always on the owning vCPU thread.  (asid,
 * priv) are stamped HERE, at the event instant, via the same per-target
 * hook that backs qemu_plugin_get_asid — a later drain sees the address
 * space the event actually happened in, not whatever is live at the next
 * TB boundary.
 */
/* Synchronous ASID-write hook (qemu_plugin_register_asid_write_cb).
 * A single slot suffices: the path-event machinery is already
 * effectively single-consumer (the queue drain hands the whole buffer
 * to whichever plugin asks). */
static qemu_plugin_asid_write_cb_t asid_write_hook;

/*
 * ADDRESS-SPACE AND THREAD IDENTITY (opaque monotonic ids).
 *
 * Base QEMU keys its TLB on the translation regime (mmu_idx) and maintains
 * no notion of WHICH address space a vCPU is in, so this is a new primitive
 * rather than a re-export of an existing one.  It is deliberately the whole
 * mechanism: the target hook reports the RAW architectural key
 * (TCGCPUOps::get_plugin_identity) and this layer maps each distinct key to
 * a monotonically increasing id.  Plugins never see the key, so nothing
 * they do can depend on interpreting it.
 *
 * The map is process-wide, not per-vCPU: the same address space seen on two
 * vCPUs must produce the SAME id, which a per-vCPU table could not do.  It
 * is written only when a vCPU's architectural key changes (a context
 * switch, not a TB), so the mutex is uncontended in practice; every hot-path
 * read is served by the per-vCPU memo in CPUState.
 *
 * Key 0 is reserved for "no identity" and is never interned: a target with
 * no hook, and a CPU model with no thread-pointer register, both land on it
 * and must report id 0 so a consumer can see the architecture named nothing.
 */
static GMutex plugin_identity_lock;
static GHashTable *plugin_space_id_map;     /* raw key -> id */
static GHashTable *plugin_thread_id_map;    /* raw key -> id */
static uint64_t plugin_space_id_next = 1;
static uint64_t plugin_thread_id_next = 1;

static uint64_t plugin_intern_locked(GHashTable **map, uint64_t *next,
                                     uint64_t key)
{
    if (key == 0) {
        return 0;
    }
    if (!*map) {
        *map = g_hash_table_new(g_int64_hash, g_int64_equal);
    }
    gpointer v = g_hash_table_lookup(*map, &key);
    if (v) {
        return *(uint64_t *)v;
    }
    uint64_t *k = g_new(uint64_t, 1);
    uint64_t *id = g_new(uint64_t, 1);
    *k = key;
    *id = (*next)++;
    g_hash_table_insert(*map, k, id);
    return *id;
}

/*
 * Re-read this vCPU's architectural identity keys and refresh its interned
 * ids.  Cheap and idempotent: the common case is two loads out of the CPU
 * state, two comparisons against the memo, and no lock at all.
 *
 * Call sites must be places where the target's architectural state is
 * coherent for the executing vCPU — the address-space commit points (which
 * run in a helper, after the store) and the plugin API (called from
 * callbacks whose registration decides whether TCG globals have been
 * spilled).  Registers that live in TCG globals (x86 segment bases, RISC-V
 * tp) are only guaranteed current in a CB_RW_REGS callback; the memo makes
 * a stale read self-correcting at the next coherent sample rather than
 * sticky.
 */
void plugin_identity_sample(CPUState *cpu)
{
    const TCGCPUOps *ops = cpu->cc->tcg_ops;
    uint64_t space_key = 0, thread_key = 0;

    if (ops && ops->get_plugin_identity) {
        ops->get_plugin_identity(cpu, &space_key, &thread_key);
    }
    if (cpu->plugin_identity_valid &&
        cpu->plugin_space_key == space_key &&
        cpu->plugin_thread_key == thread_key) {
        return;
    }
    bool space_changed = !cpu->plugin_identity_valid ||
                         cpu->plugin_space_key != space_key;
    bool thread_changed = !cpu->plugin_identity_valid ||
                          cpu->plugin_thread_key != thread_key;

    g_mutex_lock(&plugin_identity_lock);
    if (space_changed) {
        cpu->plugin_process_id = plugin_intern_locked(&plugin_space_id_map,
                                                      &plugin_space_id_next,
                                                      space_key);
    }
    if (thread_changed) {
        cpu->plugin_thread_id = plugin_intern_locked(&plugin_thread_id_map,
                                                     &plugin_thread_id_next,
                                                     thread_key);
    }
    g_mutex_unlock(&plugin_identity_lock);
    cpu->plugin_space_key = space_key;
    cpu->plugin_thread_key = thread_key;
    cpu->plugin_identity_valid = true;
}

void qemu_plugin_register_asid_write_cb(qemu_plugin_id_t id,
                                        qemu_plugin_asid_write_cb_t cb)
{
    asid_write_hook = cb;
}

/*
 * Machine-shutdown hook (qemu_plugin_register_vm_shutdown_cb).  One slot,
 * for the same reason as the hooks above.
 *
 * The dispatch below is the whole point of the hook: it must reach the
 * plugin while the machine is still ASSEMBLED and, wherever possible, on
 * a vCPU thread, because everything a plugin needs to close a capture
 * (guest memory, registers, privilege level, address space) resolves
 * through current_cpu.  qemu_plugin_atexit_cb() cannot offer any of that
 * — it runs from atexit(3), after qemu_cleanup() has stopped the vCPUs
 * and torn the machine down, on a thread where current_cpu is NULL.
 */
static qemu_plugin_vm_shutdown_cb_t vm_shutdown_hook;
static bool vm_shutdown_dispatched;

static int plugin_version_floor = QEMU_PLUGIN_VERSION;

void plugin_note_declared_version(int version)
{
    if (version < plugin_version_floor) {
        plugin_version_floor = version;
    }
}

int plugin_declared_version_floor(void)
{
    return plugin_version_floor;
}

/*
 * Refuse an entry point whose SIGNATURE changed after the API version the
 * calling plugin was built against.
 *
 * The loader accepts every declared version in [QEMU_PLUGIN_MIN_VERSION,
 * QEMU_PLUGIN_VERSION], and a signature change leaves no other trace: the
 * symbol still resolves, the call still links, and the argument the caller
 * never passed is read from whatever the calling convention left in that
 * register.  For an argument APPENDED to a callback type the result is
 * benign on every mainstream ABI, because the callee ignores what it does
 * not declare.  For an argument INSERTED into a registrar the arguments
 * MISALIGN, and QEMU stores a hook it was never given.
 *
 * @since is the first version that both carries the current signature and
 * is distinguishable from the previous one.  Where the change itself went
 * in without moving QEMU_PLUGIN_VERSION, the version in force at the time
 * names two incompatible ABIs and cannot be honoured either way, so @since
 * is the NEXT version — the ambiguous one is refused with the rest.
 *
 * Defined below, next to the plugin registry it reads.
 */
static void plugin_require_abi(qemu_plugin_id_t id, const char *api, int since);

void qemu_plugin_register_vm_shutdown_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vm_shutdown_cb_t cb)
{
    /* @in_guest_insn appended inside version 19; 20 is the first that says so */
    plugin_require_abi(id, "qemu_plugin_vm_shutdown_cb_t", 20);
    vm_shutdown_hook = cb;
}

/*
 * Deliver the notification, at most once per run.  The two callers live in
 * plugins/system.c because the placement they do (run_on_cpu) is
 * system-only; this half is here so the hook slot has one owner.
 *
 * Idempotent because the shutdown REQUEST and the main loop's shutdown
 * ACKNOWLEDGE are BOTH dispatch points, and neither alone covers every
 * cause: a guest poweroff and a monitor/QMP request go through
 * qemu_system_shutdown_request(), while a host signal does not — the
 * signal handler cannot call it and sets shutdown_requested directly, so
 * the main loop is the only place SIGINT/SIGTERM is seen.  Whichever
 * arrives first wins; the other is a no-op.
 */
QEMU_DISABLE_CFI
bool qemu_plugin_vm_shutdown_dispatch(int vcpu_index, bool in_guest_insn)
{
    qemu_plugin_vm_shutdown_cb_t cb = vm_shutdown_hook;

    if (!cb || vm_shutdown_dispatched) {
        return false;
    }
    vm_shutdown_dispatched = true;
    cb(0, vcpu_index, in_guest_insn);
    return true;
}

bool qemu_plugin_vm_shutdown_armed(void)
{
    return vm_shutdown_hook && !vm_shutdown_dispatched;
}

/*
 * Guest-kernel current-task location hint
 * (qemu_plugin_set_current_task_offset).  Process-global: one guest
 * kernel per emulation, and the declaring plugin runs before any vCPU
 * exists, so no per-CPU state is needed.  Written once at plugin
 * install (vCPUs are not running yet); read from vCPU threads through
 * the target's plugin-state hooks.
 */
static uint64_t current_task_off;
static bool current_task_off_set;

void qemu_plugin_current_task_offset_store(uint64_t offset)
{
    current_task_off = offset;
    current_task_off_set = true;
}

uint64_t qemu_plugin_current_task_offset(bool *set)
{
    *set = current_task_off_set;
    return current_task_off;
}

/*
 * Block-device I/O hooks (qemu_plugin_register_devio_cb).  Like the
 * ASID-write hook, a single slot per stage suffices: the block backend
 * has one issue and one completion chokepoint, the virtqueue has one
 * notify chokepoint, and the consuming plugin serialises its own state.
 * The dispatch entry points are called from hw/virtio/virtio.c (the
 * doorbell) and block/block-backend.c (issue / completion) and are
 * no-ops until a plugin registers.
 */
static qemu_plugin_devio_doorbell_cb_t devio_doorbell_hook;
static qemu_plugin_devio_start_cb_t devio_start_hook;
static qemu_plugin_devio_stop_cb_t devio_stop_hook;

void qemu_plugin_register_devio_cb(qemu_plugin_id_t id,
                                   qemu_plugin_devio_doorbell_cb_t doorbell_cb,
                                   qemu_plugin_devio_start_cb_t start_cb,
                                   qemu_plugin_devio_stop_cb_t stop_cb)
{
    /*
     * @doorbell_cb INSERTED, and @dev_token appended to the start callback,
     * inside version 12; 13 is the first version that says so.  A version-12
     * caller passes three arguments, so start_cb would land in the doorbell
     * slot, stop_cb in the start slot, and the stop slot would take whatever
     * the fourth argument register happened to hold.
     */
    plugin_require_abi(id, "qemu_plugin_register_devio_cb", 13);
    devio_doorbell_hook = doorbell_cb;
    devio_start_hook = start_cb;
    devio_stop_hook = stop_cb;
}

QEMU_DISABLE_CFI
void qemu_plugin_devio_doorbell(uint64_t dev_token)
{
    if (devio_doorbell_hook) {
        /* The virtqueue kick runs in vCPU context (an MMIO/PIO write the
         * guest driver performs), so current_cpu is the doorbell-writing
         * vCPU — the one datum the later, possibly main-loop, issue hook
         * cannot recover.  Report -1 if somehow not on a vCPU thread. */
        int vcpu_index = current_cpu ? current_cpu->cpu_index : -1;
        devio_doorbell_hook(vcpu_index, dev_token);
    }
}

QEMU_DISABLE_CFI
uint64_t qemu_plugin_devio_start(int dir, uint64_t offset, uint64_t bytes,
                                 uint64_t dev_token)
{
    if (devio_start_hook) {
        /* current_cpu is the issuing vCPU only when the block layer is
         * entered synchronously on a vCPU thread; the canonical no-iothread
         * virtio-blk path defers to the main loop, where it is NULL (-1).
         * The plugin recovers the true owner from @dev_token instead. */
        int vcpu_index = current_cpu ? current_cpu->cpu_index : -1;
        return devio_start_hook(vcpu_index, dir, offset, bytes, dev_token);
    }
    return 0;
}

QEMU_DISABLE_CFI
void qemu_plugin_devio_stop(uint64_t request_id)
{
    if (devio_stop_hook) {
        devio_stop_hook(request_id);
    }
}

/*
 * "Queue non-empty" scoreboard slot.  The queue's single consumer is a
 * plugin, and its ONLY JIT-testable way to know whether a drain is owed is
 * a per-vCPU scoreboard entry the producer maintains: 1 the instant an
 * event is appended, 0 the instant the queue is drained.  With it, a plugin
 * can register a per-TB conditional callback that costs one load and one
 * brcond when the queue is empty -- which makes EVERY TB entry a drain
 * point and turns the queue length into a bounded quantity (see
 * CPU_PLUGIN_EVQ_STRUCTURAL_MAX).
 *
 * One slot process-wide, like the queue's own enable and like
 * asid_write_hook: the queue already assumes a single consuming plugin.
 * Stored by value; the scoreboard's backing GArray may be reallocated on
 * vCPU hotplug, so the address is resolved per access rather than cached.
 */
static qemu_plugin_u64 evq_pending_slot;
static bool evq_pending_slot_set;

void plugin_set_evq_pending_slot(qemu_plugin_u64 slot, bool set)
{
    evq_pending_slot = slot;
    evq_pending_slot_set = set;
}

bool plugin_evq_pending_slot_armed(void)
{
    return evq_pending_slot_set;
}

void plugin_evq_note_drained(CPUState *cpu)
{
    if (evq_pending_slot_set) {
        qemu_plugin_u64_set(evq_pending_slot, cpu->cpu_index, 0);
    }
}

QEMU_DISABLE_CFI
void cpu_plugin_evq_push(CPUState *cpu, int kind, uint64_t pc,
                         uint32_t depth_after)
{
    QemuPluginCpuEventQueue *q = &cpu->plugin_evq;

    if (cpu->plugin_spec_mode) {
        return;
    }
    /*
     * The synchronous ASID-write hook fires BEFORE the queue-enabled
     * check: it exists precisely for phases where nothing drains the
     * queue (so it stays disabled) but the plugin still needs to
     * observe address-space transitions — e.g. fast-forward counting
     * gated on a pinned process.  Same spec-mode suppression as the
     * queued event; the value passed is the just-committed one the
     * per-target state hook reports.
     */
    if (kind == QEMU_PLUGIN_CPU_EVENT_ASID_WRITE) {
        /*
         * The architectural commit point for the address space: the store
         * has retired and the TLB flush decision has been made, so this is
         * where the vCPU's process identity changes.  Sampling here (not
         * only from the API) means a consumer reading the id inside this
         * very hook already sees the NEW address space.
         */
        plugin_identity_sample(cpu);
    }
    if (kind == QEMU_PLUGIN_CPU_EVENT_ASID_WRITE && asid_write_hook) {
        int hpriv = 0;
        uint64_t hasid = 0;
        bool hmmu_on = true;
        const TCGCPUOps *hops = cpu->cc->tcg_ops;
        if (hops && hops->get_plugin_state) {
            hops->get_plugin_state(cpu, &hpriv, &hasid, &hmmu_on);
        }
        asid_write_hook(cpu->cpu_index, hasid);
    }
    if (!q->enabled) {
        return;
    }
    if (q->len == q->cap) {
        q->cap = q->cap ? q->cap * 2 : 64;
        q->buf = g_realloc(q->buf, q->cap * sizeof(*q->buf));
    }

    int priv = 0;
    uint64_t asid = 0;
    bool mmu_on = true;
    const TCGCPUOps *ops = cpu->cc->tcg_ops;
    if (ops && ops->get_plugin_state) {
        ops->get_plugin_state(cpu, &priv, &asid, &mmu_on);
    }

    /*
     * The thread pointer at the event instant, with whether it names the
     * executing thread here (user privilege always does; above it the
     * target's tracks-current hook answers for this exact state).  For an
     * ASYNC_ENTER this is the DELIVERING thread — the do_interrupt hooks
     * push before any guest state switches — which the consumer cannot
     * recover at drain time: by then the vCPU is inside the handler, and
     * on an SMP guest the delivered-into context may never be sampled
     * again.
     */
    uint64_t tp = 0;
    bool tp_ok = false;
    if (ops && ops->get_plugin_thread_ptr) {
        tp = ops->get_plugin_thread_ptr(cpu);
        tp_ok = priv == 0 ||
                (ops->plugin_thread_ptr_tracks_current &&
                 ops->plugin_thread_ptr_tracks_current(cpu));
    }

    q->buf[q->len++] = (QemuPluginCpuEvent) {
        .kind = (uint8_t)kind,
        .priv = (uint8_t)priv,
        .tp_ok = tp_ok,
        .depth_after = depth_after,
        .pc = pc,
        .asid = asid,
        .tp = tp,
    };
    q->n_push++;
    if (q->len > q->max_len) {
        q->max_len = q->len;
    }

    /*
     * Tell the consumer a drain is owed.  One store per push; the consumer
     * is the same vCPU thread, so no ordering beyond program order is
     * needed (documented single-producer/single-consumer, cpu.h).
     *
     * A consumer that never published a slot gets the historical behaviour
     * -- and, deliberately, NOT the tripwire below: the ceiling is a claim
     * about what the per-TB drain point makes impossible, so it is only
     * asserted where that drain point exists.
     */
    if (evq_pending_slot_set) {
        qemu_plugin_u64_set(evq_pending_slot, cpu->cpu_index, 1);
    }

    /*
     * STRUCTURAL TRIPWIRE.  Never a cap: nothing is dropped, truncated or
     * rate-limited here.  Reaching this length means the per-TB drain point
     * argued for at CPU_PLUGIN_EVQ_STRUCTURAL_MAX did not happen, which is a
     * broken invariant in the tracer, so the run dies loudly rather than
     * silently accumulating (and silently costing one guest instruction the
     * whole backlog's worth of work).  Everything needed to diagnose it in
     * one shot is printed.
     */
    if (unlikely(evq_pending_slot_set &&
                 q->len > CPU_PLUGIN_EVQ_STRUCTURAL_MAX)) {
        fprintf(stderr,
                "qemu: FATAL plugin event-queue invariant broken: cpu=%d "
                "len=%u > %u cap=%u pushes=%" PRIu64 " drains=%" PRIu64
                " kind=%d pc=0x%" PRIx64 " slot_armed=%d\n"
                "  (the consumer's per-TB drain point did not run; this is a "
                "tracer bug, not a workload)\n",
                cpu->cpu_index, q->len, (unsigned)CPU_PLUGIN_EVQ_STRUCTURAL_MAX,
                q->cap, q->n_push, q->n_drain, kind, pc,
                (int)evq_pending_slot_set);
        fflush(stderr);
        abort();
    }
}

void cpu_plugin_async_enter(CPUState *cpu, uint64_t departure_pc)
{
    const TCGCPUOps *ops = cpu->cc->tcg_ops;

    /*
     * The flag and the ASYNC_ENTER event are ONE latch: never open a window
     * no consumer can be told about.  plugin_in_async_int gates every
     * producer on the outermost edge (!plugin_in_async_int), and the only
     * thing that clears it is the departure PC being re-fetched, in the
     * departure thread, ON THIS vCPU.  Latching it while the event queue is
     * disabled — the whole pre-marker boot, and any inter-segment gap —
     * therefore arms a window the plugin never learns of and cannot reap: if
     * that departure context never resumes here (a boot/idle/kthread context
     * on a vCPU the guest later parks, the common case once there is more
     * than one vCPU), the flag stays true for the rest of the run and every
     * later interrupt is swallowed by the edge gate.  Measured on aarch64
     * --smp 2: both vCPUs entered the traced segment already latched, and 135
     * of 135 in-segment deliveries were swallowed — the async-window feature
     * silently inert on every SMP trace.
     *
     * With no consumer there is nothing for the window to mean: the tracer's
     * own readers (qemu_plugin_in_async_int) only act while it is emitting,
     * which is exactly when the queue is enabled.
     */
    static int nogate = -1;      /* CST_ASYNC_NOGATE: A/B the latch gate */
    if (nogate < 0) {
        nogate = getenv("CST_ASYNC_NOGATE") != NULL;
    }
    if (!cpu->plugin_evq.enabled && !nogate) {
        return;
    }

    cpu->plugin_in_async_int = true;
    cpu->plugin_async_departure_pc = departure_pc;
    /*
     * The departure context, for the return check in cpu_exec_loop: the
     * guest thread-pointer register still names the INTERRUPTED thread here
     * (exception delivery does not touch it; only the guest kernel's
     * context switch does), and a genuine resume restores exactly this
     * value before the exception return lands on @departure_pc.  Targets
     * without the hook record 0 on both sides — the return check then
     * degrades to the historical bare PC equality.
     */
    cpu->plugin_async_departure_tp =
        (ops && ops->get_plugin_thread_ptr) ? ops->get_plugin_thread_ptr(cpu)
                                            : 0;
    cpu_plugin_evq_push(cpu, QEMU_PLUGIN_CPU_EVENT_ASYNC_ENTER, departure_pc,
                        cpu->plugin_fault_depth);
}

void cpu_plugin_async_probe(CPUState *cpu, const char *tag, int exc_index,
                            bool is_async)
{
    static int on = -1;
    static uint64_t n;
    static uint64_t cap = 40000;

    if (on < 0) {
        const char *v = getenv("CST_ASYNCPROD_DIAG");
        on = v != NULL;
        /*
         * A numeric value raises the line cap ("1" keeps the historical
         * 40000): a whole-boot delivery stream exhausts 40000 lines long
         * before a marker window opens, silencing the probe exactly where
         * the investigation needs it.
         */
        if (on && v[0] && strtoull(v, NULL, 0) > 1) {
            cap = strtoull(v, NULL, 0);
        }
    }
    if (!on || n >= cap) {
        return;
    }
    n++;
    fprintf(stderr, "[asyncprod] %-6s vcpu=%d exc=%d async=%d spec=%d "
            "inasync=%d evq=%d fdepth=%u pc=0x%" PRIx64 "\n",
            tag, cpu->cpu_index, exc_index, (int)is_async,
            (int)cpu->plugin_spec_mode, (int)cpu->plugin_in_async_int,
            (int)cpu->plugin_evq.enabled, cpu->plugin_fault_depth,
            (uint64_t)cpu->cc->get_pc(cpu));
}

struct qemu_plugin_cb {
    struct qemu_plugin_ctx *ctx;
    union qemu_plugin_cb_sig f;
    void *udata;
    QLIST_ENTRY(qemu_plugin_cb) entry;
};

struct qemu_plugin_state plugin;

static void plugin_require_abi(qemu_plugin_id_t id, const char *api, int since)
{
    struct qemu_plugin_ctx *ctx;
    int version;

    qemu_rec_mutex_lock(&plugin.lock);
    ctx = plugin_id_to_ctx_locked(id);
    version = ctx->version;
    qemu_rec_mutex_unlock(&plugin.lock);

    if (version < since) {
        error_report("plugin: %s changed signature at plugin API version %d; "
                     "this plugin declares version %d, so QEMU would call "
                     "through a function type that no longer matches its "
                     "definition.  Rebuild the plugin against this "
                     "qemu-plugin.h.", api, since, version);
        exit(1);
    }
}

/*
 * Whether any plugin was loaded.  Machine models need this to decide whether
 * the guest-time-transparency contract a freezing plugin relies on applies to
 * them; qemu_plugin_load_list() runs before machine_run_board_init(), so a
 * device realize function sees the final answer.
 */
bool qemu_plugin_any_loaded(void)
{
    return !QTAILQ_EMPTY(&plugin.ctxs);
}

struct qemu_plugin_ctx *plugin_id_to_ctx_locked(qemu_plugin_id_t id)
{
    struct qemu_plugin_ctx *ctx;
    qemu_plugin_id_t *id_p;

    id_p = g_hash_table_lookup(plugin.id_ht, &id);
    ctx = container_of(id_p, struct qemu_plugin_ctx, id);
    if (ctx == NULL) {
        error_report("plugin: invalid plugin id %" PRIu64, id);
        abort();
    }
    return ctx;
}

static void plugin_cpu_update__async(CPUState *cpu, run_on_cpu_data data)
{
    bitmap_copy(cpu->plugin_state->event_mask,
                &data.host_ulong, QEMU_PLUGIN_EV_MAX);
    tcg_flush_jmp_cache(cpu);
}

static void plugin_cpu_update__locked(gpointer k, gpointer v, gpointer udata)
{
    CPUState *cpu = container_of(k, CPUState, cpu_index);
    run_on_cpu_data mask = RUN_ON_CPU_HOST_ULONG(*plugin.mask);

    async_run_on_cpu(cpu, plugin_cpu_update__async, mask);
}

void plugin_unregister_cb__locked(struct qemu_plugin_ctx *ctx,
                                  enum qemu_plugin_event ev)
{
    struct qemu_plugin_cb *cb = ctx->callbacks[ev];

    if (cb == NULL) {
        return;
    }
    QLIST_REMOVE_RCU(cb, entry);
    g_free(cb);
    ctx->callbacks[ev] = NULL;
    if (QLIST_EMPTY_RCU(&plugin.cb_lists[ev])) {
        clear_bit(ev, plugin.mask);
        g_hash_table_foreach(plugin.cpu_ht, plugin_cpu_update__locked, NULL);
    }
}

/*
 * Disable CFI checks.
 * The callback function has been loaded from an external library so we do not
 * have type information
 */
QEMU_DISABLE_CFI
static void plugin_vcpu_cb__simple(CPUState *cpu, enum qemu_plugin_event ev)
{
    struct qemu_plugin_cb *cb, *next;

    switch (ev) {
    case QEMU_PLUGIN_EV_VCPU_INIT:
    case QEMU_PLUGIN_EV_VCPU_EXIT:
    case QEMU_PLUGIN_EV_VCPU_IDLE:
    case QEMU_PLUGIN_EV_VCPU_RESUME:
        /* iterate safely; plugins might uninstall themselves at any time */
        QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
            qemu_plugin_vcpu_simple_cb_t func = cb->f.vcpu_simple;

            func(cb->ctx->id, cpu->cpu_index);
        }
        break;
    default:
        g_assert_not_reached();
    }
}

/*
 * Disable CFI checks.
 * The callback function has been loaded from an external library so we do not
 * have type information
 */
QEMU_DISABLE_CFI
static void plugin_cb__simple(enum qemu_plugin_event ev)
{
    struct qemu_plugin_cb *cb, *next;

    switch (ev) {
    case QEMU_PLUGIN_EV_FLUSH:
        QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
            qemu_plugin_simple_cb_t func = cb->f.simple;

            func(cb->ctx->id);
        }
        break;
    default:
        g_assert_not_reached();
    }
}

/*
 * Disable CFI checks.
 * The callback function has been loaded from an external library so we do not
 * have type information
 */
QEMU_DISABLE_CFI
static void plugin_cb__udata(enum qemu_plugin_event ev)
{
    struct qemu_plugin_cb *cb, *next;

    switch (ev) {
    case QEMU_PLUGIN_EV_ATEXIT:
        QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
            qemu_plugin_udata_cb_t func = cb->f.udata;

            func(cb->ctx->id, cb->udata);
        }
        break;
    default:
        g_assert_not_reached();
    }
}

static void
do_plugin_register_cb(qemu_plugin_id_t id, enum qemu_plugin_event ev,
                      void *func, void *udata)
{
    struct qemu_plugin_ctx *ctx;

    QEMU_LOCK_GUARD(&plugin.lock);
    ctx = plugin_id_to_ctx_locked(id);
    /* if the plugin is on its way out, ignore this request */
    if (unlikely(ctx->uninstalling)) {
        return;
    }
    if (func) {
        struct qemu_plugin_cb *cb = ctx->callbacks[ev];

        if (cb) {
            cb->f.generic = func;
            cb->udata = udata;
        } else {
            cb = g_new(struct qemu_plugin_cb, 1);
            cb->ctx = ctx;
            cb->f.generic = func;
            cb->udata = udata;
            ctx->callbacks[ev] = cb;
            QLIST_INSERT_HEAD_RCU(&plugin.cb_lists[ev], cb, entry);
            if (!test_bit(ev, plugin.mask)) {
                set_bit(ev, plugin.mask);
                g_hash_table_foreach(plugin.cpu_ht, plugin_cpu_update__locked,
                                     NULL);
            }
        }
    } else {
        plugin_unregister_cb__locked(ctx, ev);
    }
}

void plugin_register_cb(qemu_plugin_id_t id, enum qemu_plugin_event ev,
                        void *func)
{
    do_plugin_register_cb(id, ev, func, NULL);
}

void
plugin_register_cb_udata(qemu_plugin_id_t id, enum qemu_plugin_event ev,
                         void *func, void *udata)
{
    do_plugin_register_cb(id, ev, func, udata);
}

CPUPluginState *qemu_plugin_create_vcpu_state(void)
{
    return g_new0(CPUPluginState, 1);
}

static void plugin_grow_scoreboards__locked(CPUState *cpu)
{
    size_t scoreboard_size = plugin.scoreboard_alloc_size;
    bool need_realloc = false;

    if (cpu->cpu_index < scoreboard_size) {
        return;
    }

    while (cpu->cpu_index >= scoreboard_size) {
        scoreboard_size *= 2;
        need_realloc = true;
    }

    if (!need_realloc) {
        return;
    }

    if (QLIST_EMPTY(&plugin.scoreboards)) {
        /* just update size for future scoreboards */
        plugin.scoreboard_alloc_size = scoreboard_size;
        return;
    }

    /*
     * A scoreboard creation/deletion might be in progress. If a new vcpu is
     * initialized at the same time, we are safe, as the new
     * plugin.scoreboard_alloc_size was not yet written.
     */
    qemu_rec_mutex_unlock(&plugin.lock);

    /* cpus must be stopped, as tb might still use an existing scoreboard. */
    start_exclusive();
    /* re-acquire lock */
    qemu_rec_mutex_lock(&plugin.lock);
    /* in case another vcpu is created between unlock and exclusive section. */
    if (scoreboard_size > plugin.scoreboard_alloc_size) {
        struct qemu_plugin_scoreboard *score;
        QLIST_FOREACH(score, &plugin.scoreboards, entry) {
            g_array_set_size(score->data, scoreboard_size);
        }
        plugin.scoreboard_alloc_size = scoreboard_size;
        /* force all tb to be flushed, as scoreboard pointers were changed. */
        tb_flush(cpu);
    }
    end_exclusive();
}

static void qemu_plugin_vcpu_init__async(CPUState *cpu, run_on_cpu_data unused)
{
    bool success;

    assert(cpu->cpu_index != UNASSIGNED_CPU_INDEX);
    qemu_rec_mutex_lock(&plugin.lock);
    plugin.num_vcpus = MAX(plugin.num_vcpus, cpu->cpu_index + 1);
    plugin_cpu_update__locked(&cpu->cpu_index, NULL, NULL);
    success = g_hash_table_insert(plugin.cpu_ht, &cpu->cpu_index,
                                  &cpu->cpu_index);
    g_assert(success);
    plugin_grow_scoreboards__locked(cpu);
    qemu_rec_mutex_unlock(&plugin.lock);

    plugin_vcpu_cb__simple(cpu, QEMU_PLUGIN_EV_VCPU_INIT);
}

void qemu_plugin_vcpu_init_hook(CPUState *cpu)
{
    /* Plugin initialization must wait until the cpu start executing code */
    async_run_on_cpu(cpu, qemu_plugin_vcpu_init__async, RUN_ON_CPU_NULL);
}

void qemu_plugin_vcpu_exit_hook(CPUState *cpu)
{
    bool success;

    plugin_vcpu_cb__simple(cpu, QEMU_PLUGIN_EV_VCPU_EXIT);

    assert(cpu->cpu_index != UNASSIGNED_CPU_INDEX);
    qemu_rec_mutex_lock(&plugin.lock);
    success = g_hash_table_remove(plugin.cpu_ht, &cpu->cpu_index);
    g_assert(success);
    qemu_rec_mutex_unlock(&plugin.lock);
}

struct plugin_for_each_args {
    struct qemu_plugin_ctx *ctx;
    qemu_plugin_vcpu_simple_cb_t cb;
};

static void plugin_vcpu_for_each(gpointer k, gpointer v, gpointer udata)
{
    struct plugin_for_each_args *args = udata;
    int cpu_index = *(int *)k;

    args->cb(args->ctx->id, cpu_index);
}

void qemu_plugin_vcpu_for_each(qemu_plugin_id_t id,
                               qemu_plugin_vcpu_simple_cb_t cb)
{
    struct plugin_for_each_args args;

    if (cb == NULL) {
        return;
    }
    qemu_rec_mutex_lock(&plugin.lock);
    args.ctx = plugin_id_to_ctx_locked(id);
    args.cb = cb;
    g_hash_table_foreach(plugin.cpu_ht, plugin_vcpu_for_each, &args);
    qemu_rec_mutex_unlock(&plugin.lock);
}

/* Allocate and return a callback record */
static struct qemu_plugin_dyn_cb *plugin_get_dyn_cb(GArray **arr)
{
    GArray *cbs = *arr;

    if (!cbs) {
        cbs = g_array_sized_new(false, true,
                                sizeof(struct qemu_plugin_dyn_cb), 1);
        *arr = cbs;
    }

    g_array_set_size(cbs, cbs->len + 1);
    return &g_array_index(cbs, struct qemu_plugin_dyn_cb, cbs->len - 1);
}

static enum plugin_dyn_cb_type op_to_cb_type(enum qemu_plugin_op op)
{
    switch (op) {
    case QEMU_PLUGIN_INLINE_ADD_U64:
        return PLUGIN_CB_INLINE_ADD_U64;
    case QEMU_PLUGIN_INLINE_STORE_U64:
        return PLUGIN_CB_INLINE_STORE_U64;
    default:
        g_assert_not_reached();
    }
}

void plugin_register_inline_op_on_entry(GArray **arr,
                                        enum qemu_plugin_mem_rw rw,
                                        enum qemu_plugin_op op,
                                        qemu_plugin_u64 entry,
                                        uint64_t imm)
{
    struct qemu_plugin_dyn_cb *dyn_cb;

    struct qemu_plugin_inline_cb inline_cb = { .rw = rw,
                                               .entry = entry,
                                               .imm = imm };
    dyn_cb = plugin_get_dyn_cb(arr);
    dyn_cb->type = op_to_cb_type(op);
    dyn_cb->inline_insn = inline_cb;
}

void plugin_register_dyn_cb__udata(GArray **arr,
                                   qemu_plugin_vcpu_udata_cb_t cb,
                                   enum qemu_plugin_cb_flags flags,
                                   void *udata)
{
    static TCGHelperInfo info[3] = {
        [QEMU_PLUGIN_CB_NO_REGS].flags = TCG_CALL_NO_RWG,
        [QEMU_PLUGIN_CB_R_REGS].flags = TCG_CALL_NO_WG,
        /*
         * Match qemu_plugin_vcpu_udata_cb_t:
         *   void (*)(uint32_t, void *)
         */
        [0 ... 2].typemask = (dh_typemask(void, 0) |
                              dh_typemask(i32, 1) |
                              dh_typemask(ptr, 2))
    };
    assert((unsigned)flags < ARRAY_SIZE(info));

    struct qemu_plugin_dyn_cb *dyn_cb = plugin_get_dyn_cb(arr);
    struct qemu_plugin_regular_cb regular_cb = { .f.vcpu_udata = cb,
                                                 .userp = udata,
                                                 .info = &info[flags] };
    dyn_cb->type = PLUGIN_CB_REGULAR;
    dyn_cb->regular = regular_cb;
}

void plugin_register_dyn_cond_cb__udata(GArray **arr,
                                        qemu_plugin_vcpu_udata_cb_t cb,
                                        enum qemu_plugin_cb_flags flags,
                                        enum qemu_plugin_cond cond,
                                        qemu_plugin_u64 entry,
                                        uint64_t imm,
                                        void *udata)
{
    static TCGHelperInfo info[3] = {
        [QEMU_PLUGIN_CB_NO_REGS].flags = TCG_CALL_NO_RWG,
        [QEMU_PLUGIN_CB_R_REGS].flags = TCG_CALL_NO_WG,
        /*
         * Match qemu_plugin_vcpu_udata_cb_t:
         *   void (*)(uint32_t, void *)
         */
        [0 ... 2].typemask = (dh_typemask(void, 0) |
                              dh_typemask(i32, 1) |
                              dh_typemask(ptr, 2))
    };
    assert((unsigned)flags < ARRAY_SIZE(info));

    struct qemu_plugin_dyn_cb *dyn_cb = plugin_get_dyn_cb(arr);
    struct qemu_plugin_conditional_cb cond_cb = { .userp = udata,
                                                  .f.vcpu_udata = cb,
                                                  .cond = cond,
                                                  .entry = entry,
                                                  .imm = imm,
                                                  .info = &info[flags] };
    dyn_cb->type = PLUGIN_CB_COND;
    dyn_cb->cond = cond_cb;
}

void plugin_register_vcpu_mem_cb(GArray **arr,
                                 void *cb,
                                 enum qemu_plugin_cb_flags flags,
                                 enum qemu_plugin_mem_rw rw,
                                 void *udata)
{
    /*
     * Expect that the underlying type for enum qemu_plugin_meminfo_t
     * is either int32_t or uint32_t, aka int or unsigned int.
     */
    QEMU_BUILD_BUG_ON(
        !__builtin_types_compatible_p(qemu_plugin_meminfo_t, uint32_t) &&
        !__builtin_types_compatible_p(qemu_plugin_meminfo_t, int32_t));

    static TCGHelperInfo info[3] = {
        [QEMU_PLUGIN_CB_NO_REGS].flags = TCG_CALL_NO_RWG,
        [QEMU_PLUGIN_CB_R_REGS].flags = TCG_CALL_NO_WG,
        /*
         * Match qemu_plugin_vcpu_mem_cb_t:
         *   void (*)(uint32_t, qemu_plugin_meminfo_t, uint64_t, void *)
         */
        [0 ... 2].typemask =
            (dh_typemask(void, 0) |
             dh_typemask(i32, 1) |
             (__builtin_types_compatible_p(qemu_plugin_meminfo_t, uint32_t)
              ? dh_typemask(i32, 2) : dh_typemask(s32, 2)) |
             dh_typemask(i64, 3) |
             dh_typemask(ptr, 4))
    };
    assert((unsigned)flags < ARRAY_SIZE(info));

    struct qemu_plugin_dyn_cb *dyn_cb = plugin_get_dyn_cb(arr);
    struct qemu_plugin_regular_cb regular_cb = { .userp = udata,
                                                 .rw = rw,
                                                 .f.vcpu_mem = cb,
                                                 .info = &info[flags] };
    dyn_cb->type = PLUGIN_CB_MEM_REGULAR;
    dyn_cb->regular = regular_cb;
}

/*
 * Disable CFI checks.
 * The callback function has been loaded from an external library so we do not
 * have type information
 */
QEMU_DISABLE_CFI
void qemu_plugin_tb_trans_cb(CPUState *cpu, struct qemu_plugin_tb *tb)
{
    struct qemu_plugin_cb *cb, *next;
    enum qemu_plugin_event ev = QEMU_PLUGIN_EV_VCPU_TB_TRANS;

    /* no plugin_state->event_mask check here; caller should have checked */

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
        qemu_plugin_vcpu_tb_trans_cb_t func = cb->f.vcpu_tb_trans;

        func(cb->ctx->id, tb);
    }
}

/*
 * Disable CFI checks.
 * The callback function has been loaded from an external library so we do not
 * have type information
 */
QEMU_DISABLE_CFI
void
qemu_plugin_vcpu_syscall(CPUState *cpu, int64_t num, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5,
                         uint64_t a6, uint64_t a7, uint64_t a8)
{
    struct qemu_plugin_cb *cb, *next;
    enum qemu_plugin_event ev = QEMU_PLUGIN_EV_VCPU_SYSCALL;

    if (!test_bit(ev, cpu->plugin_state->event_mask)) {
        return;
    }

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
        qemu_plugin_vcpu_syscall_cb_t func = cb->f.vcpu_syscall;

        func(cb->ctx->id, cpu->cpu_index, num, a1, a2, a3, a4, a5, a6, a7, a8);
    }
}

/*
 * Wrong-path (speculative) syscalls refused before they could reach the host.
 *
 * A plugin walking a mispredicted path fetches and executes whatever the guest
 * has there, including a syscall instruction.  The wrong-path policy is that
 * such an instruction is fetched and its wrong-path successors keep executing,
 * but the call itself is NEVER performed: in *-linux-user a syscall is served
 * by the host, so performing one speculatively would write files, send packets
 * or kill the process on a path the guest never takes.  Suppression is
 * structural — every target's syscall instruction unwinds through
 * cpu_plugin_exec_tb()'s own landing pad, so do_syscall() is unreachable while
 * cpu->plugin_spec_mode is set — and this counter is the standing proof: the
 * guard in do_syscall() bumps it instead of executing, so a non-zero value
 * means the structural suppression developed a hole.  Read through
 * qemu_plugin_spec_syscall_blocked_count().
 */
uint64_t qemu_plugin_spec_syscall_blocked;

/*
 * Disable CFI checks.
 * The callback function has been loaded from an external library so we do not
 * have type information
 */
QEMU_DISABLE_CFI
void qemu_plugin_vcpu_syscall_ret(CPUState *cpu, int64_t num, int64_t ret)
{
    struct qemu_plugin_cb *cb, *next;
    enum qemu_plugin_event ev = QEMU_PLUGIN_EV_VCPU_SYSCALL_RET;

    if (!test_bit(ev, cpu->plugin_state->event_mask)) {
        return;
    }

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
        qemu_plugin_vcpu_syscall_ret_cb_t func = cb->f.vcpu_syscall_ret;

        func(cb->ctx->id, cpu->cpu_index, num, ret);
    }
}

void qemu_plugin_vcpu_idle_cb(CPUState *cpu)
{
    /* idle and resume cb may be called before init, ignore in this case */
    if (cpu->cpu_index < plugin.num_vcpus) {
        plugin_vcpu_cb__simple(cpu, QEMU_PLUGIN_EV_VCPU_IDLE);
    }
}

void qemu_plugin_vcpu_resume_cb(CPUState *cpu)
{
    if (cpu->cpu_index < plugin.num_vcpus) {
        plugin_vcpu_cb__simple(cpu, QEMU_PLUGIN_EV_VCPU_RESUME);
    }
}

void qemu_plugin_register_vcpu_idle_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_IDLE, cb);
}

void qemu_plugin_register_vcpu_resume_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_RESUME, cb);
}

void qemu_plugin_register_flush_cb(qemu_plugin_id_t id,
                                   qemu_plugin_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_FLUSH, cb);
}

static bool free_dyn_cb_arr(void *p, uint32_t h, void *userp)
{
    g_array_free((GArray *) p, true);
    return true;
}

void qemu_plugin_flush_cb(void)
{
    qht_iter_remove(&plugin.dyn_cb_arr_ht, free_dyn_cb_arr, NULL);
    qht_reset(&plugin.dyn_cb_arr_ht);

    plugin_cb__simple(QEMU_PLUGIN_EV_FLUSH);
}

void exec_inline_op(enum plugin_dyn_cb_type type,
                    struct qemu_plugin_inline_cb *cb,
                    int cpu_index)
{
    char *ptr = cb->entry.score->data->data;
    size_t elem_size = g_array_get_element_size(
        cb->entry.score->data);
    size_t offset = cb->entry.offset;
    uint64_t *val = (uint64_t *)(ptr + offset + cpu_index * elem_size);

    switch (type) {
    case PLUGIN_CB_INLINE_ADD_U64:
        *val += cb->imm;
        break;
    case PLUGIN_CB_INLINE_STORE_U64:
        *val = cb->imm;
        break;
    default:
        g_assert_not_reached();
    }
}

void qemu_plugin_vcpu_mem_cb(CPUState *cpu, uint64_t vaddr,
                             uint64_t value_low,
                             uint64_t value_high,
                             MemOpIdx oi, enum qemu_plugin_mem_rw rw)
{
    GArray *arr = cpu->neg.plugin_mem_cbs;
    size_t i;

    if (arr == NULL) {
        return;
    }

    cpu->neg.plugin_mem_value_low = value_low;
    cpu->neg.plugin_mem_value_high = value_high;

    for (i = 0; i < arr->len; i++) {
        struct qemu_plugin_dyn_cb *cb =
            &g_array_index(arr, struct qemu_plugin_dyn_cb, i);

        switch (cb->type) {
        case PLUGIN_CB_MEM_REGULAR:
            if (rw & cb->regular.rw) {
                cb->regular.f.vcpu_mem(cpu->cpu_index,
                                       make_plugin_meminfo(oi, rw),
                                       vaddr, cb->regular.userp);
            }
            break;
        case PLUGIN_CB_INLINE_ADD_U64:
        case PLUGIN_CB_INLINE_STORE_U64:
            if (rw & cb->inline_insn.rw) {
                exec_inline_op(cb->type, &cb->inline_insn, cpu->cpu_index);
            }
            break;
        default:
            g_assert_not_reached();
        }
    }
}

void qemu_plugin_atexit_cb(void)
{
    plugin_cb__udata(QEMU_PLUGIN_EV_ATEXIT);
}

void qemu_plugin_register_atexit_cb(qemu_plugin_id_t id,
                                    qemu_plugin_udata_cb_t cb,
                                    void *udata)
{
    plugin_register_cb_udata(id, QEMU_PLUGIN_EV_ATEXIT, cb, udata);
}

/*
 * Handle exit from linux-user. Unlike the normal atexit() mechanism
 * we need to handle the clean-up manually as it's possible threads
 * are still running. We need to remove all callbacks from code
 * generation, flush the current translations and then we can safely
 * trigger the exit callbacks.
 */

void qemu_plugin_user_exit(void)
{
    enum qemu_plugin_event ev;
    CPUState *cpu;

    /*
     * Locking order: we must acquire locks in an order that is consistent
     * with the one in fork_start(). That is:
     * - start_exclusive(), which acquires qemu_cpu_list_lock,
     *   must be called before acquiring plugin.lock.
     * - tb_flush(), which acquires mmap_lock(), must be called
     *   while plugin.lock is not held.
     */
    start_exclusive();

    qemu_rec_mutex_lock(&plugin.lock);
    /* un-register all callbacks except the final AT_EXIT one */
    for (ev = 0; ev < QEMU_PLUGIN_EV_MAX; ev++) {
        if (ev != QEMU_PLUGIN_EV_ATEXIT) {
            struct qemu_plugin_cb *cb, *next;

            QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
                plugin_unregister_cb__locked(cb->ctx, ev);
            }
        }
    }
    CPU_FOREACH(cpu) {
        qemu_plugin_disable_mem_helpers(cpu);
    }
    qemu_rec_mutex_unlock(&plugin.lock);

    tb_flush(current_cpu);
    end_exclusive();

    /* now it's safe to handle the exit case */
    qemu_plugin_atexit_cb();
}

/*
 * Helpers for *-user to ensure locks are sane across fork() events.
 */

void qemu_plugin_user_prefork_lock(void)
{
    qemu_rec_mutex_lock(&plugin.lock);
}

void qemu_plugin_user_postfork(bool is_child)
{
    if (is_child) {
        /* should we just reset via plugin_init? */
        qemu_rec_mutex_init(&plugin.lock);
    } else {
        qemu_rec_mutex_unlock(&plugin.lock);
    }
}

static bool plugin_dyn_cb_arr_cmp(const void *ap, const void *bp)
{
    return ap == bp;
}

static void __attribute__((__constructor__)) plugin_init(void)
{
    int i;

    for (i = 0; i < QEMU_PLUGIN_EV_MAX; i++) {
        QLIST_INIT(&plugin.cb_lists[i]);
    }
    qemu_rec_mutex_init(&plugin.lock);
    plugin.id_ht = g_hash_table_new(g_int64_hash, g_int64_equal);
    plugin.cpu_ht = g_hash_table_new(g_int_hash, g_int_equal);
    QLIST_INIT(&plugin.scoreboards);
    plugin.scoreboard_alloc_size = 16; /* avoid frequent reallocation */
    QTAILQ_INIT(&plugin.ctxs);
    qht_init(&plugin.dyn_cb_arr_ht, plugin_dyn_cb_arr_cmp, 16,
             QHT_MODE_AUTO_RESIZE);
    atexit(qemu_plugin_atexit_cb);
}

int plugin_num_vcpus(void)
{
    return plugin.num_vcpus;
}

struct qemu_plugin_scoreboard *plugin_scoreboard_new(size_t element_size)
{
    struct qemu_plugin_scoreboard *score =
        g_malloc0(sizeof(struct qemu_plugin_scoreboard));
    score->data = g_array_new(FALSE, TRUE, element_size);
    g_array_set_size(score->data, plugin.scoreboard_alloc_size);

    qemu_rec_mutex_lock(&plugin.lock);
    QLIST_INSERT_HEAD(&plugin.scoreboards, score, entry);
    qemu_rec_mutex_unlock(&plugin.lock);

    return score;
}

void plugin_scoreboard_free(struct qemu_plugin_scoreboard *score)
{
    qemu_rec_mutex_lock(&plugin.lock);
    QLIST_REMOVE(score, entry);
    qemu_rec_mutex_unlock(&plugin.lock);

    g_array_free(score->data, TRUE);
    g_free(score);
}
