/*
 * Wrong-path excursion diagnostics (CST_* instruments).  The interface,
 * and what each instrument is for, is in plugin-diag.h.
 *
 * Copyright (C) 2026, Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "exec/cpu-common.h"
#include "tcg/tcg.h"
#include "qemu/atomic.h"
#include "qemu/main-loop.h"
#include "exec/cpu-all.h"
#include "exec/exec-all.h"
#include "system/cpu-timers.h"
#ifndef CONFIG_USER_ONLY
#include "system/system.h"      /* rtc_clock, for the excursion clock audit */
#endif
#include "qemu/qemu-plugin.h"
#include "internal-common.h"
#include "internal-target.h"
#include "exec/cputlb.h"
#include "plugin-diag.h"

#if defined(TARGET_RISCV) && !defined(CONFIG_USER_ONLY)
/*
 * Render @bits into the CALLER's buffer.  Not a shared static: the one line
 * below names two different masks, and a single buffer makes both names show
 * whichever call the compiler happened to evaluate last -- a diagnostic that
 * quietly reports the wrong thing is worse than none.
 */
static const char *cst_mip_bit_names(uint64_t bits, char *buf, size_t buflen)
{
    static const struct { uint64_t bit; const char *name; } tab[] = {
        { MIP_MSIP,   " MIP_MSIP"   }, { MIP_SSIP,   " MIP_SSIP"   },
        { MIP_MEIP,   " MIP_MEIP"   }, { MIP_SEIP,   " MIP_SEIP"   },
        { MIP_SGEIP,  " MIP_SGEIP"  }, { MIP_LCOFIP, " MIP_LCOFIP" },
        { MIP_VSSIP,  " MIP_VSSIP"  }, { MIP_VSEIP,  " MIP_VSEIP"  },
    };
    size_t n = 0;
    buf[0] = '\0';
    for (size_t i = 0; i < ARRAY_SIZE(tab); i++) {
        if (bits & tab[i].bit) {
            n += snprintf(buf + n, buflen - n, "%s", tab[i].name);
            if (n >= buflen) {
                break;
            }
        }
    }
    return buf;
}

/*
 * CST_MIPERASE=<n> -- pending-interrupt erasure detector (diagnostic, off by
 * default; <n> caps the printed detail lines, default 64.  The counters keep
 * running past the cap and a TOTALS line is printed at every power-of-two
 * event, so a run killed by a watchdog while wedged still reports its totals).
 *
 * Runs immediately before the wrong-path restore's memcpy and reports two
 * different things, because the condition and the outcome can be closed
 * separately and only measuring the outcome would hide a regression:
 *
 *   UNRECORDED -- a bit that is live-set in env->mip, absent from the
 *      snapshot, and absent from the replay record.  That is the RACE
 *      signature: a device raise the excursion neither snapshotted nor logged,
 *      i.e. one that landed in a window where the excursion was not yet (or no
 *      longer) recording.  It is what the entry/exit ordering fixes close, and
 *      it is measurable independently of what the restore then decides to do
 *      with the bit.
 *
 *   ERASED -- a bit that is live-set now and will be zero after the restore
 *      writes env->mip.  That is the outcome the guest actually suffers.
 *      Computed from the same expression the restore uses, device carry-forward
 *      included, so it stays honest as that expression changes.
 *
 * Timer bits are excluded from both: the excursion-exit reconcile re-derives
 * them from the architected compare registers.  Every other bit in mip is
 * parked there by a device (the ACLINT's MSIP/SSIP, the PLIC's MEIP/SEIP,
 * hgeip's SGEIP, the PMU's LCOFIP) with no second source to recover from -- an
 * erasure there is an interrupt the guest never sees and a device that waits
 * forever for an acknowledgement.
 */
void cst_miperase_check(const CPURISCVState *env,
                        const CPURISCVState *saved,
                        uint64_t replay_set, uint64_t replay_clear)
{
    static int lim = -1;
    static uint64_t n_events, n_unrec, n_lost, n_msip_unrec, n_msip_lost;
    const uint64_t timer = MIP_MTIP | MIP_STIP | MIP_VSTIP;
    uint64_t post, lost, unrec, ev;
    char unrec_names[96], lost_names[96];

    if (unlikely(lim < 0)) {
        const char *e = getenv("CST_MIPERASE");
        int v = e ? atoi(e) : 0;
        qatomic_set(&lim, e ? (v > 0 ? v : 64) : 0);
    }
    if (likely(!lim)) {
        return;
    }

    /* Exactly the value the restore is about to write. */
    post = (((saved->mip | replay_set) & ~replay_clear)
            & ~RISCV_MIP_DEVICE_OWNED) | (env->mip & RISCV_MIP_DEVICE_OWNED);

    lost  = (env->mip & ~post) & ~timer;
    unrec = (env->mip & ~saved->mip & ~replay_set) & ~timer;
    if (likely(!lost && !unrec)) {
        return;
    }

    ev = qatomic_fetch_inc(&n_events) + 1;
    if (unrec) {
        qatomic_inc(&n_unrec);
        if (unrec & MIP_MSIP) {
            qatomic_inc(&n_msip_unrec);
        }
    }
    if (lost) {
        qatomic_inc(&n_lost);
        if (lost & MIP_MSIP) {
            qatomic_inc(&n_msip_lost);
        }
    }

    if (ev <= (uint64_t)lim) {
        fprintf(stderr, "[miperase] cpu%d unrecorded=0x%" PRIx64 "%s"
                " erased=0x%" PRIx64 "%s live=0x%" PRIx64 " saved=0x%" PRIx64
                " set=0x%" PRIx64 " clr=0x%" PRIx64 " pc=0x%" PRIx64
                " spec=%d vtp=%d gw=%d\n",
                current_cpu->cpu_index,
                unrec, cst_mip_bit_names(unrec, unrec_names,
                                         sizeof(unrec_names)),
                lost, cst_mip_bit_names(lost, lost_names,
                                        sizeof(lost_names)),
                env->mip, saved->mip, replay_set, replay_clear,
                (uint64_t)env->pc,
                (int)current_cpu->plugin_spec_mode,
                (int)current_cpu->plugin_excursion_active,
                (int)env->plugin_mip_guest_write);
    }
    if ((ev & (ev - 1)) == 0) {
        fprintf(stderr, "[miperase] TOTALS events=%" PRIu64
                " unrecorded=%" PRIu64 " (msip=%" PRIu64 ")"
                " erased=%" PRIu64 " (msip=%" PRIu64 ")\n",
                ev, qatomic_read(&n_unrec), qatomic_read(&n_msip_unrec),
                qatomic_read(&n_lost), qatomic_read(&n_msip_lost));
    }
}
#endif

#if !defined(CONFIG_USER_ONLY)
/*
 * Wrong-path write-leak detector (diagnostic, gated on CST_WPROTECT=<delay_s>).
 * Host-MMU based: write-protect ALL guest RAM for the duration of each wrong-
 * path excursion.  Reads and sandboxed (buffered) stores never touch real RAM,
 * so they don't fault; ANY real write -- from ANY code path, known or not --
 * traps in wprot_handler, which prints the leaking guest-physical address and
 * the wrong-path PC of the instruction that did it, then aborts.  No guessing
 * where to place a probe.  Armed after <delay_s> seconds (default 0: from the
 * first excursion), so an early phase can be left unslowed.
 */
#include <sys/mman.h>
typedef struct { void *host; size_t len; uint64_t off; } WProtBlk;
static WProtBlk g_wprot_blk[16];
static int      g_wprot_nblk = 0;
static bool     g_wprot_collected = false;
static bool     g_wprot_installed = false;
bool            g_wprot_active = false;
static int      g_wprot_enabled = -1;
static long     g_wprot_delay = 0;
static time_t   g_wprot_start = 0;
static long     g_wprot_pgsz = 0;
static struct sigaction g_wprot_old_sa;

static int wprot_collect_cb(RAMBlock *rb, void *opaque)
{
    void *h = qemu_ram_get_host_addr(rb);
    if (h && g_wprot_nblk < 16) {
        g_wprot_blk[g_wprot_nblk].host = h;
        g_wprot_blk[g_wprot_nblk].len  = qemu_ram_get_used_length(rb);
        g_wprot_blk[g_wprot_nblk].off  = qemu_ram_get_offset(rb);
        g_wprot_nblk++;
    }
    return 0;
}

static void wprot_handler(int sig, siginfo_t *si, void *uc)
{
    char *a = (char *)si->si_addr;
    for (int i = 0; i < g_wprot_nblk; i++) {
        char *base = (char *)g_wprot_blk[i].host;
        if (a >= base && a < base + g_wprot_blk[i].len) {
            bool spec = current_cpu && current_cpu->plugin_spec_mode;
            bool vtp  = current_cpu && current_cpu->plugin_excursion_active;
            if (spec || vtp) {
                uint64_t phys = g_wprot_blk[i].off + (uint64_t)(a - base);
                uint64_t pc = current_cpu ? current_cpu->cc->get_pc(current_cpu)
                                          : 0;
                fprintf(stderr, "[wpleak] WP wrote guest RAM phys=0x%" PRIx64
                        " host=%p wp_pc=0x%" PRIx64 " spec=%d vtp=%d\n",
                        phys, (void *)a, pc, (int)spec, (int)vtp);
                fflush(stderr);
                abort();
            }
            /* concurrent non-WP write (iothread/DMA): unprotect + continue */
            void *pg = (void *)((uintptr_t)a & ~(uintptr_t)(g_wprot_pgsz - 1));
            mprotect(pg, g_wprot_pgsz, PROT_READ | PROT_WRITE);
            return;
        }
    }
    /* Not guest RAM: chain to QEMU's previous SIGSEGV handler. */
    if (g_wprot_old_sa.sa_flags & SA_SIGINFO) {
        if (g_wprot_old_sa.sa_sigaction) {
            g_wprot_old_sa.sa_sigaction(sig, si, uc);
            return;
        }
    } else if (g_wprot_old_sa.sa_handler &&
               g_wprot_old_sa.sa_handler != SIG_DFL &&
               g_wprot_old_sa.sa_handler != SIG_IGN) {
        g_wprot_old_sa.sa_handler(sig);
        return;
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

void wprot_setprot(int prot)
{
    for (int i = 0; i < g_wprot_nblk; i++) {
        mprotect(g_wprot_blk[i].host, g_wprot_blk[i].len, prot);
    }
}

bool wprot_ready(void)
{
    if (g_wprot_enabled < 0) {
        const char *e = getenv("CST_WPROTECT");
        g_wprot_enabled = e ? 1 : 0;
        /* delay in seconds before arming; default 0 = arm on the first WP
         * excursion. */
        g_wprot_delay = (e && *e) ? atol(e) : 0;
        g_wprot_pgsz = qemu_real_host_page_size();
    }
    if (!g_wprot_enabled) {
        return false;
    }
    if (g_wprot_start == 0) {
        g_wprot_start = time(NULL);
    }
    if (time(NULL) - g_wprot_start < g_wprot_delay) {
        return false;
    }
    if (!g_wprot_collected) {
        qemu_ram_foreach_block(wprot_collect_cb, NULL);
        g_wprot_collected = true;
    }
    if (!g_wprot_installed) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = wprot_handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, &g_wprot_old_sa);
        g_wprot_installed = true;
        fprintf(stderr, "[wpleak] armed: %d RAM block(s) write-protected "
                "during WP\n", g_wprot_nblk);
    }
    return g_wprot_nblk > 0;
}

/*
 * CPU-state leak detector (diagnostic, gated on CST_STATEDIFF).  The WP
 * snapshot saves/restores only CPUArchState[0..end_reset_fields] + halted +
 * exception_index.  ANY other CPUState/env byte a wrong-path excursion mutates
 * persists into the correct path.  This snapshots the whole CPUState
 * (including the neg.tlb descriptors) and the un-restored env tail at
 * excursion start, compares after the restore, and logs each distinct
 * changed-and-not-restored byte once -- revealing the leaked field with no
 * guessing.
 */
#define SDIFF_CPU_SZ  sizeof(CPUState)   /* includes neg.tlb descriptors */
#define SDIFF_ENV_OFF offsetof(CPUArchState, end_reset_fields)
#define SDIFF_ENV_SZ  (sizeof(CPUArchState) - offsetof(CPUArchState, end_reset_fields))
/*
 * The snapshot buffers are per-vCPU-thread.  They hold one specific CPUState's
 * bytes, and the pair that produces a verdict is a snapshot on one thread and
 * the compare that follows it on that same thread; a process-wide buffer makes
 * that pair depend on no peer vCPU opening an excursion in between, which is
 * not a property this file can assert -- the serialisation that would grant it
 * belongs to a plugin's lock, not to QEMU.  Shared, a peer's snapshot would be
 * compared against this vCPU's registers and every byte where the two vCPUs
 * legitimately differ would be reported as a leak.  The `seen` filters stay
 * per-thread with them, so first-occurrence reporting is per-vCPU too.
 */
static __thread uint8_t g_sdiff_cpu[SDIFF_CPU_SZ];
static __thread uint8_t g_sdiff_env[SDIFF_ENV_SZ];
static __thread uint8_t g_sdiff_cpu_seen[SDIFF_CPU_SZ];
static __thread uint8_t g_sdiff_env_seen[SDIFF_ENV_SZ];
static __thread bool    g_sdiff_have = false;
static int     g_sdiff_on = -1;
static long    g_sdiff_delay = 0;
static time_t  g_sdiff_start = 0;
static bool    g_sdiff_printed_off = false;

static bool sdiff_enabled(void)
{
    if (g_sdiff_on < 0) {
        const char *e = getenv("CST_STATEDIFF");
        g_sdiff_on = e ? 1 : 0;
        g_sdiff_delay = (e && *e) ? atol(e) : 0;
    }
    if (g_sdiff_on <= 0) {
        return false;
    }
    if (g_sdiff_start == 0) {
        g_sdiff_start = time(NULL);
    }
    if (time(NULL) - g_sdiff_start < g_sdiff_delay) {
        return false;
    }
    if (!g_sdiff_printed_off) {
        g_sdiff_printed_off = true;
        fprintf(stderr, "[statediff] armed. offsetof: interrupt_request=%zu "
                "neg=%zu plugin_spec_tlb_log=%zu sizeof(CPUState)=%zu\n",
                offsetof(CPUState, interrupt_request),
                offsetof(CPUState, neg),
                offsetof(CPUState, plugin_spec_tlb_log),
                sizeof(CPUState));
        fflush(stderr);
    }
    return true;
}

/*
 * Name every byte that differs across an excursion BY CONSTRUCTION, so an
 * un-named offset is the finding.  Left unnamed, these bury a real leak: they
 * are reported on essentially every excursion, and the reader who has learned
 * to scroll past them scrolls past the one line that matters.
 *
 * Four groups, and none of them is an un-restored wrong-path mutation:
 *
 *  - ASYNC SIGNALLING (exit_request, interrupt_request, work_list).  These are
 *    written by OTHER threads -- the iothread's device models raise an
 *    interrupt line, cpu_exit() sets the kick, async_run_on_cpu() queues an
 *    item -- while this vCPU sits in the excursion.  They MUST survive it:
 *    restoring them would discard a device interrupt the guest is owed, which
 *    is the failure the RISC-V mip and MIPS CP0_Cause work exists to prevent.
 *    On x86 the excursion holds the BQL end to end, so the iothread cannot
 *    interleave and this group does not appear; on the other targets it does.
 *
 *  - THE PER-EXECUTION REPORT'S LAZILY ALLOCATED ACCUMULATOR
 *    (plugin_mops_report).  A pointer to per-vCPU storage the FEAT_MOPS byte
 *    fallbacks allocate on first use and keep for the vCPU's lifetime, so it
 *    goes NULL -> heap on the first excursion that needs it.  What it HOLDS is
 *    already path-separated inside the allocation (the accumulator carries a
 *    correct-path and a wrong-path context and selects on plugin_spec_mode),
 *    so the surviving pointer carries no wrong-path value into the correct
 *    path.
 *
 *    The scalar report beside it -- the plugin_rep_* block -- is NOT in this
 *    group and must not be added to it.  It is a publication channel read one
 *    dispatch after the execution that wrote it, which is across the boundary
 *    an excursion is kicked from, and its only identity is an address; a
 *    speculative re-entry of the same instruction is therefore indis-
 *    tinguishable from the correct-path execution it displaced.  It is saved
 *    and restored with the rest of the rollback (qemu_plugin_cpu_state_save /
 *    _restore) and so does not differ here.  If it ever appears in this
 *    detector's output again, that is the finding.
 *
 *  - THE WRONG-PATH STORE SANDBOX (plugin_spec_store_buf, _pool, _pool_used,
 *    _pool_cap, _atomic_scratch, _store_overflow).  The sandbox that holds the
 *    excursion's speculative stores is an allocator, and its buffer is kept
 *    across excursions on purpose: qemu_plugin_spec_mode_end empties the line
 *    index and resets the high-water mark but does NOT free the pool, so the
 *    next excursion reuses it.  The pointers therefore go NULL -> heap on the
 *    first excursion that stores, and the cap grows when a wider one needs
 *    more lines.  What the sandbox HOLDS is discarded at excursion exit --
 *    that is the sandbox's whole purpose -- so the surviving allocation
 *    carries no wrong-path value into the correct path.
 *
 *  - EXCURSION BOOKKEEPING (plugin_excursion_active, plugin_spec_tlb_log and
 *    its siblings).  plugin_excursion_active is this detector's own bracket:
 *    set before the snapshot, cleared before the compare, so it differs on
 *    every excursion.
 *
 * The rest of the plugin block is DELIBERATELY left unnamed -- the fault stack
 * and its depth, the event queue, plugin_spec_saved_state, the identity memo.
 * A change there across an excursion is exactly the finding this detector is
 * for, and naming the block wholesale to quieten the sandbox lines would hide
 * it.
 */
static const char *sdiff_cpu_field(size_t off)
{
    if (off == offsetof(CPUState, interrupt_request)) {
        return "interrupt_request (async: raised by another thread - must survive)";
    }
    if (off == offsetof(CPUState, exit_request)) {
        return "exit_request (async: kick from another thread - must survive)";
    }
    if (off >= offsetof(CPUState, work_list) &&
        off <  offsetof(CPUState, work_list) + sizeof(((CPUState *)0)->work_list)) {
        return "work_list (async: queued by another thread - must survive)";
    }
    if (off == offsetof(CPUState, cflags_next_tb))     return "cflags_next_tb";
    /*
     * plugin_mops_report AND NOTHING BEFORE IT.  The plugin_rep_* fields
     * before it are the self-loop publication channel, which the rollback
     * restores; naming them would hide exactly the leak that restore exists
     * to prevent.
     */
    if (off >= offsetof(CPUState, plugin_mops_report) &&
        off <  offsetof(CPUState, plugin_mops_report) + sizeof(void *)) {
        return "(FEAT_MOPS report accumulator - lazily allocated, vCPU "
               "lifetime; its contents are path-separated internally)";
    }
    if (off >= offsetof(CPUState, plugin_spec_store_buf) &&
        off <  offsetof(CPUState, plugin_spec_store_overflow) +
               sizeof(((CPUState *)0)->plugin_spec_store_overflow)) {
        return "(wrong-path store sandbox - a pool DELIBERATELY reused across "
               "excursions: qemu_plugin_spec_mode_end clears the line index "
               "and resets pool_used, and keeps the buffer)";
    }
    if (off == offsetof(CPUState, plugin_excursion_active)) {
        return "plugin_excursion_active (this detector's own bracket)";
    }
    /*
     * The TLB log AND NOTHING PAST IT.  The fields after the log's overflow
     * flag (plugin_spec_absent, plugin_spec_mem_faulted, cpu_index,
     * tcg_cflags, halted, exception_index, iommu_notifiers) are not
     * bookkeeping: tcg_cflags, for one, selects the TB the correct path
     * looks up, so a perturbation there is a real finding.  A name is a
     * claim that a difference is understood; it must cover only what it
     * names.
     */
    if (off >= offsetof(CPUState, plugin_spec_tlb_log) &&
        off <= offsetof(CPUState, plugin_spec_tlb_log_overflow)) {
        return "(plugin_spec_tlb_log - intentional)";
    }
    if (off >= offsetof(CPUState, neg)) {
        return "(neg/TLB)";
    }
    return NULL;
}

void sdiff_snapshot(CPUState *cpu)
{
    if (!sdiff_enabled()) {
        return;
    }
    memcpy(g_sdiff_cpu, cpu, SDIFF_CPU_SZ);
    memcpy(g_sdiff_env, (uint8_t *)cpu_env(cpu) + SDIFF_ENV_OFF, SDIFF_ENV_SZ);
    g_sdiff_have = true;
}

void sdiff_compare(CPUState *cpu)
{
    if (!sdiff_enabled() || !g_sdiff_have) {
        return;
    }
    const uint8_t *now = (const uint8_t *)cpu;
    for (size_t i = 0; i < SDIFF_CPU_SZ; i++) {
        if (now[i] != g_sdiff_cpu[i] && !g_sdiff_cpu_seen[i]) {
            g_sdiff_cpu_seen[i] = 1;
            const char *f = sdiff_cpu_field(i);
            fprintf(stderr, "[statediff] CPUState off=%zu%s%s changed across WP "
                    "(0x%02x->0x%02x) NOT restored\n", i,
                    f ? " field=" : "", f ? f : "",
                    g_sdiff_cpu[i], now[i]);
            fflush(stderr);
        }
    }
    const uint8_t *enow = (const uint8_t *)cpu_env(cpu) + SDIFF_ENV_OFF;
    /*
     * "!=" rather than "<": on targets whose CPUArchState ends at
     * end_reset_fields (alpha, avr, microblaze, tricore, xtensa)
     * SDIFF_ENV_SZ is compile-time 0 and an unsigned "< 0" trips
     * -Wtype-limits under -Werror.
     */
    for (size_t i = 0; i != SDIFF_ENV_SZ; i++) {
        if (enow[i] != g_sdiff_env[i] && !g_sdiff_env_seen[i]) {
            g_sdiff_env_seen[i] = 1;
            fprintf(stderr, "[statediff] env tail off=%zu (env+%zu) changed "
                    "across WP (0x%02x->0x%02x) NOT restored\n",
                    i, SDIFF_ENV_OFF + i, g_sdiff_env[i], enow[i]);
            fflush(stderr);
        }
    }
}

/*
 * TLB causation test (diagnostic, gated on CST_TLB_SAVE): snapshot the ENTIRE
 * softmmu TLB at wrong-path entry and fully restore it at exit --
 * descriptors, the inline victim tables, AND the heap fast-table / fulltlb
 * arrays (which statediff cannot see, being behind pointers).  A symptom
 * that vanishes when the TLB is forced byte-identical across every
 * excursion is carried by TLB state.  Heavy (per-excursion memcpy of the
 * tables).
 */
static int  g_tlbsave_on = -1;
static bool g_tlbsave_have = false;
static CPUTLBDesc      g_tlbsave_d[NB_MMU_MODES];
static uintptr_t       g_tlbsave_mask[NB_MMU_MODES];
static size_t          g_tlbsave_nent[NB_MMU_MODES];
static CPUTLBEntry    *g_tlbsave_table[NB_MMU_MODES];
static CPUTLBEntryFull *g_tlbsave_fulltlb[NB_MMU_MODES];
static uint16_t        g_tlbsave_dirty;
static size_t          g_tlbsave_ffc, g_tlbsave_pfc, g_tlbsave_efc;

static bool tlbsave_enabled(void)
{
    if (g_tlbsave_on < 0) {
        g_tlbsave_on = getenv("CST_TLB_SAVE") ? 1 : 0;
    }
    return g_tlbsave_on > 0;
}

void tlbsave_snapshot(CPUState *cpu)
{
    if (!tlbsave_enabled()) {
        return;
    }
    CPUTLB *tlb = &cpu->neg.tlb;
    qemu_spin_lock(&tlb->c.lock);
    g_tlbsave_dirty = tlb->c.dirty;
    g_tlbsave_ffc = tlb->c.full_flush_count;
    g_tlbsave_pfc = tlb->c.part_flush_count;
    g_tlbsave_efc = tlb->c.elide_flush_count;
    for (int i = 0; i < NB_MMU_MODES; i++) {
        size_t nent = (tlb->f[i].mask >> CPU_TLB_ENTRY_BITS) + 1;
        g_tlbsave_d[i] = tlb->d[i];
        g_tlbsave_mask[i] = tlb->f[i].mask;
        g_tlbsave_nent[i] = nent;
        g_tlbsave_table[i] = g_realloc(g_tlbsave_table[i],
                                       nent * sizeof(CPUTLBEntry));
        memcpy(g_tlbsave_table[i], tlb->f[i].table,
               nent * sizeof(CPUTLBEntry));
        g_tlbsave_fulltlb[i] = g_realloc(g_tlbsave_fulltlb[i],
                                         nent * sizeof(CPUTLBEntryFull));
        memcpy(g_tlbsave_fulltlb[i], tlb->d[i].fulltlb,
               nent * sizeof(CPUTLBEntryFull));
    }
    qemu_spin_unlock(&tlb->c.lock);
    g_tlbsave_have = true;
}

void tlbsave_restore(CPUState *cpu)
{
    if (!tlbsave_enabled() || !g_tlbsave_have) {
        return;
    }
    CPUTLB *tlb = &cpu->neg.tlb;
    qemu_spin_lock(&tlb->c.lock);
    tlb->c.dirty = g_tlbsave_dirty;
    tlb->c.full_flush_count = g_tlbsave_ffc;
    tlb->c.part_flush_count = g_tlbsave_pfc;
    tlb->c.elide_flush_count = g_tlbsave_efc;
    for (int i = 0; i < NB_MMU_MODES; i++) {
        size_t saved_nent = g_tlbsave_nent[i];
        size_t cur_nent = (tlb->f[i].mask >> CPU_TLB_ENTRY_BITS) + 1;
        CPUTLBEntry *table = tlb->f[i].table;
        CPUTLBEntryFull *fulltlb = tlb->d[i].fulltlb;
        if (cur_nent != saved_nent) {
            /* WP resized this mmu_idx: the saved heap pointers were freed.
             * Reallocate the live buffers back to the saved geometry. */
            g_free(table);
            g_free(fulltlb);
            table = g_new(CPUTLBEntry, saved_nent);
            fulltlb = g_new(CPUTLBEntryFull, saved_nent);
        }
        memcpy(table, g_tlbsave_table[i], saved_nent * sizeof(CPUTLBEntry));
        memcpy(fulltlb, g_tlbsave_fulltlb[i],
               saved_nent * sizeof(CPUTLBEntryFull));
        tlb->d[i] = g_tlbsave_d[i];        /* restores inline victim + scalars */
        tlb->d[i].fulltlb = fulltlb;       /* but keep the LIVE heap pointer */
        tlb->f[i].mask = g_tlbsave_mask[i];
        tlb->f[i].table = table;
    }
    qemu_spin_unlock(&tlb->c.lock);
    g_tlbsave_have = false;
}

/*
 * CST_NOFREEZE lever (diagnostic): run excursions WITHOUT freezing the guest
 * virtual clock.  CST_NO_VTPAUSE is accepted as an alias.  Only the freeze is
 * skipped: the excursion window (plugin_excursion_active) still opens, so
 * everything that keys on it -- the RISC-V external-mip record, the
 * RISC-V/MIPS/Arm timer expiry gates, the interrupt-line suppression, the
 * wrong-path kick re-arm and the excursion-exit clock resync -- stays in
 * force.
 *
 * Cached: called on every excursion.
 */
bool cst_nofreeze(void)
{
    static int v = -1;
    if (v < 0) {
        v = getenv("CST_NOFREEZE") != NULL || getenv("CST_NO_VTPAUSE") != NULL;
    }
    return v;
}

/*
 * CST_CLKAUDIT (diagnostic): can a guest observe ANY time discontinuity
 * across a wrong-path excursion?  Answered at the clocks' ROOTS rather than
 * per guest clock: every guest-visible timebase in QEMU is computed on
 * demand, when the guest reads it, from one of the six host-side quantities
 * below, so sampling those six covers every derived source.  That closure is
 * a source property: every qemu_clock_get_{ns,ms,us}() caller in hw/,
 * target/ and system/ names a literal QEMU_CLOCK_* or rtc_clock, and the
 * tick readers are cpu_get_host_ticks(), cpu_get_ticks() and
 * cpus_get_elapsed_ticks().  A new root is a new row here.
 *
 * The rows, and what each is allowed to do across an excursion:
 *
 *   VIRTUAL     cpus_get_virtual_clock()   HPET, ACPI PM, PIT, LAPIC timer,
 *                                          Arm CNTVCT/CNTPCT, MIPS CP0 Count,
 *                                          RISC-V ACLINT mtime.  MUST NOT MOVE.
 *   VMTICKS     cpu_get_ticks()            x86 TSC (cpus_get_elapsed_ticks),
 *                                          RISC-V mcycle/minstret.  MUST NOT
 *                                          MOVE -- x86 additionally re-pins it
 *                                          to the virtual clock at every thaw,
 *                                          so this row also checks that pin.
 *   VIRTUAL_RT  cpu_get_clock()            QEMU_CLOCK_VIRTUAL_RT.  MUST NOT
 *                                          MOVE (same gate as the above).
 *   HOST        get_clock_realtime()       host wall time.  Guest-visible ONLY
 *                                          through an RTC model, and only when
 *                                          rtc_clock names it -- so the
 *                                          exemption is COMPUTED from
 *                                          rtc_clock, never assumed.
 *   REALTIME    get_clock()                host monotonic.  Same rule.
 *   HOSTTICKS   cpu_get_host_ticks()       raw host cycle counter.  No target
 *                                          reads it in system mode; sampled
 *                                          so that holds by measurement, and
 *                                          reported as an unconditional
 *                                          exemption.
 *
 * A row that must not move and moved is named, with its delta, in both halves:
 * ADVANCED (it moved while the window was open -- the freeze did not hold) and
 * NOTRESTORED (it did not come back across the thaw and the per-target
 * resync).  Exempt rows are still sampled and reported once, with the reason.
 *
 * Positive control: under CST_NOFREEZE every must-not-move row must report
 * ADVANCED; silence there means a broken instrument.
 */
static const char * const cst_clkroot_name[CST_CLKROOT__COUNT] = {
    [CST_CLKROOT_VIRTUAL]    = "QEMU_CLOCK_VIRTUAL",
    [CST_CLKROOT_VMTICKS]    = "VM_TICKS",
    [CST_CLKROOT_VIRTUAL_RT] = "QEMU_CLOCK_VIRTUAL_RT",
    [CST_CLKROOT_HOST]       = "QEMU_CLOCK_HOST",
    [CST_CLKROOT_REALTIME]   = "QEMU_CLOCK_REALTIME",
    [CST_CLKROOT_HOSTTICKS]  = "HOST_TICKS",
};

bool cst_clkaudit_on(void)
{
    static int on = -1;
    if (on < 0) {
        /* CST_CLKEQ is accepted as an alias of CST_CLKAUDIT. */
        on = getenv("CST_CLKAUDIT") != NULL || getenv("CST_CLKEQ") != NULL;
    }
    return on > 0;
}

/*
 * Whether a moving root is a guest-visible discontinuity.  For the three
 * gated roots the answer is fixed.  For the two host clocks it depends on
 * whether an RTC model is currently pointed at them, which is what rtc_clock
 * says -- so the exemption is derived from live configuration, and an
 * operator who passes -rtc clock=host (or runs without a plugin, so the
 * adoption in rtc_adopt_vm_clock_for_plugin() does not fire) gets the row
 * enforced instead of excused.
 */
static bool cst_clkroot_must_hold(CstClkRoot r, const char **why)
{
    switch (r) {
    case CST_CLKROOT_VIRTUAL:
    case CST_CLKROOT_VMTICKS:
    case CST_CLKROOT_VIRTUAL_RT:
        *why = "guest-visible";
        return true;
    case CST_CLKROOT_HOST:
        if (rtc_clock == QEMU_CLOCK_HOST) {
            *why = "guest-visible: rtc_clock == QEMU_CLOCK_HOST";
            return true;
        }
        *why = "host-only: no RTC points at it";
        return false;
    case CST_CLKROOT_REALTIME:
        if (rtc_clock == QEMU_CLOCK_REALTIME) {
            *why = "guest-visible: rtc_clock == QEMU_CLOCK_REALTIME";
            return true;
        }
        *why = "host-only: no RTC points at it";
        return false;
    case CST_CLKROOT_HOSTTICKS:
    default:
        *why = "host-only: no system-mode target reads the raw host counter";
        return false;
    }
}

void cst_clkaudit_sample(int64_t v[CST_CLKROOT__COUNT])
{
    v[CST_CLKROOT_VIRTUAL]    = cpus_get_virtual_clock();
    v[CST_CLKROOT_VMTICKS]    = cpu_get_ticks();
    v[CST_CLKROOT_VIRTUAL_RT] = cpu_get_clock();
    /*
     * The two host clocks are read through their raw accessors rather than
     * qemu_clock_get_ns(), which wraps them in REPLAY_CLOCK: an instrument
     * must not consume a replay event.
     */
    v[CST_CLKROOT_HOST]       = get_clock_realtime();
    v[CST_CLKROOT_REALTIME]   = get_clock();
    v[CST_CLKROOT_HOSTTICKS]  = cpu_get_host_ticks();
}

static __thread int64_t g_clkaudit_pause[CST_CLKROOT__COUNT];

void cst_clkaudit_note_pause(void)
{
    if (cst_clkaudit_on()) {
        cst_clkaudit_sample(g_clkaudit_pause);
    }
}

void cst_clkaudit_check(CPUState *cpu,
                        const int64_t pre_thaw[CST_CLKROOT__COUNT])
{
    if (!cst_clkaudit_on()) {
        return;
    }
    int64_t post[CST_CLKROOT__COUNT];
    static __thread uint64_t n_adv[CST_CLKROOT__COUNT];
    static __thread uint64_t n_not[CST_CLKROOT__COUNT];
    static __thread bool exempt_said[CST_CLKROOT__COUNT];

    cst_clkaudit_sample(post);

    for (int r = 0; r < CST_CLKROOT__COUNT; r++) {
        const char *why = NULL;
        bool must = cst_clkroot_must_hold(r, &why);
        int64_t d_in  = pre_thaw[r] - g_clkaudit_pause[r];
        int64_t d_out = post[r]     - g_clkaudit_pause[r];

        if (!must) {
            /* Said once per row per thread, with the movement it was excused
             * for, so the exemption is visible and its size is on the record. */
            if (!exempt_said[r]) {
                exempt_said[r] = true;
                fprintf(stderr, "[clkaudit] cpu%d EXEMPT root=%s reason=\"%s\" "
                        "in_excursion_delta=%" PRId64 "\n", cpu->cpu_index,
                        cst_clkroot_name[r], why, d_in);
                fflush(stderr);
            }
            continue;
        }
        if (d_in != 0) {
            n_adv[r]++;
            if ((n_adv[r] & (n_adv[r] - 1)) == 0) {
                fprintf(stderr, "[clkaudit] cpu%d ADVANCED root=%s (%s) "
                        "pause=%" PRId64 " in_excursion=%" PRId64
                        " delta=%" PRId64 " n=%" PRIu64 "\n", cpu->cpu_index,
                        cst_clkroot_name[r], why, g_clkaudit_pause[r],
                        pre_thaw[r], d_in, n_adv[r]);
                fflush(stderr);
            }
        }
        if (d_out != 0) {
            n_not[r]++;
            if ((n_not[r] & (n_not[r] - 1)) == 0) {
                fprintf(stderr, "[clkaudit] cpu%d NOTRESTORED root=%s (%s) "
                        "pause=%" PRId64 " resume=%" PRId64
                        " delta=%" PRId64 " n=%" PRIu64 "\n", cpu->cpu_index,
                        cst_clkroot_name[r], why, g_clkaudit_pause[r],
                        post[r], d_out, n_not[r]);
                fflush(stderr);
            }
        }
    }

    /*
     * The CONDITION, reported next to the outcome: how many plugin freezes so
     * far ended with every remaining freeze held by a DIFFERENT vCPU.  Each is
     * an occasion on which a per-vCPU thaw would have restarted the guest clock
     * inside a peer's window, so a large figure alongside zero ADVANCED lines
     * is the measurement that the machine-wide reference count is what holds
     * the requirement, not luck.  advanced/notrestored are the VIRTUAL_RT
     * row's counts (cpu_get_clock()).
     *
     * CST_CLKEQ_EVERY sets the per-vCPU reporting period (the count it gates
     * is per-vCPU-thread, so choose it against one vCPU's excursions); an
     * invalid value is announced, once per process, and replaced by the
     * default.
     */
#define CST_CLKEQ_EVERY_DEFAULT 20000
    static __thread uint64_t n_excursions;
    static __thread int every = -1;
    if (every < 0) {
        const char *s = getenv("CST_CLKEQ_EVERY");
        every = s ? atoi(s) : CST_CLKEQ_EVERY_DEFAULT;
        if (every <= 0) {
            static int refusal_announced;
            if (qatomic_xchg(&refusal_announced, 1) == 0) {
                fprintf(stderr, "[clkeq] CST_CLKEQ_EVERY=\"%s\" is not a "
                        "positive period; refused, reporting every %d "
                        "excursions per vcpu instead\n",
                        s ? s : "", CST_CLKEQ_EVERY_DEFAULT);
                fflush(stderr);
            }
            every = CST_CLKEQ_EVERY_DEFAULT;
        }
    }
    if ((++n_excursions % (unsigned)every) == 0) {
        fprintf(stderr, "[clkeq] cpu%d excursions=%" PRIu64 " advanced=%" PRIu64
                " notrestored=%" PRIu64 " peer_only_thaws=%" PRIu64 "\n",
                cpu->cpu_index, n_excursions, n_adv[CST_CLKROOT_VIRTUAL_RT],
                n_not[CST_CLKROOT_VIRTUAL_RT],
                cpu_plugin_ticks_peer_only_thaws());
        fflush(stderr);
    }
}
/*
 * CST_CLKPROBE (diagnostic): measure the guest-visible TSC-vs-monotonic
 * skew the WP time-freeze accumulates.  Every excursion the freeze excludes a
 * host-TSC interval (cpu_get_host_ticks = rdtsc) from the guest TSC and a
 * host-monotonic interval (get_clock) from the guest HPET clock; if those two
 * host clocks drift, the guest's clocksource watchdog eventually marks the TSC
 * unstable.  tsc_hz is self-calibrated from the correct-path intervals between
 * excursions (both host clocks measured over the same real interval), so
 * "SKEW" is exactly the divergence the guest sees.  Off unless CST_CLKPROBE.
 */
static __thread int64_t  g_clkp_ht_pause, g_clkp_hm_pause;
static __thread int64_t  g_clkp_ht_resume, g_clkp_hm_resume;
static __thread int64_t  g_clkp_cp_tsc, g_clkp_cp_ns;
static __thread int64_t  g_clkp_excl_tsc, g_clkp_excl_ns;
static __thread int64_t  g_clkp_gt_pause, g_clkp_gc_pause;   /* GUEST tsc/clock */
static __thread int64_t  g_clkp_gleak_tsc, g_clkp_gleak_ns;  /* guest-visible leak */
static __thread uint64_t g_clkp_n;
void cst_clkprobe(bool resume)
{
    static int on = -1;
    if (on < 0) {
        on = getenv("CST_CLKPROBE") != NULL;
    }
    if (!on) {
        return;
    }
    int64_t ht = cpu_get_host_ticks();
    int64_t hm = get_clock();
    int64_t gt = cpu_get_ticks();      /* guest TSC source */
    int64_t gc = cpu_get_clock();      /* guest QEMU_CLOCK_VIRTUAL source */
    if (!resume) {
        if (g_clkp_ht_resume) {          /* correct-path interval for calibration */
            g_clkp_cp_tsc += ht - g_clkp_ht_resume;
            g_clkp_cp_ns  += hm - g_clkp_hm_resume;
        }
        g_clkp_ht_pause = ht;
        g_clkp_hm_pause = hm;
        g_clkp_gt_pause = gt;
        g_clkp_gc_pause = gc;
        return;
    }
    g_clkp_excl_tsc += ht - g_clkp_ht_pause;   /* frozen (excluded) this excursion */
    g_clkp_excl_ns  += hm - g_clkp_hm_pause;
    g_clkp_gleak_tsc += gt - g_clkp_gt_pause;  /* guest TSC that LEAKED across WP */
    g_clkp_gleak_ns  += gc - g_clkp_gc_pause;  /* guest clock that LEAKED across WP */
    g_clkp_ht_resume = ht;
    g_clkp_hm_resume = hm;
    if (++g_clkp_n % 20000 == 0 && g_clkp_cp_ns > 0) {
        double tsc_hz = (double)g_clkp_cp_tsc / (double)g_clkp_cp_ns * 1e9;
        double excl_tsc_s  = (double)g_clkp_excl_tsc / tsc_hz;
        double excl_mono_s = (double)g_clkp_excl_ns / 1e9;
        double gleak_tsc_s = (double)g_clkp_gleak_tsc / tsc_hz;
        double gleak_ns_s  = (double)g_clkp_gleak_ns / 1e9;
        fprintf(stderr, "[clkprobe] n=%llu tsc=%.3fGHz host_skew=%.4fms "
                "GUEST_leak_tsc=%.4fms GUEST_leak_clk=%.4fms GUEST_skew=%.4fms\n",
                (unsigned long long)g_clkp_n, tsc_hz / 1e9,
                (excl_tsc_s - excl_mono_s) * 1e3,
                gleak_tsc_s * 1e3, gleak_ns_s * 1e3,
                (gleak_tsc_s - gleak_ns_s) * 1e3);
    }
}
#endif

