/*
 * Wrong-Path Tracing Plugin — wrong-path excursion delay attribution.
 *
 * See champsim_tracer_delay.h for what this measures and why it is a
 * different question from the one every other wrong-path instrument answers.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <new>

#include "champsim_tracer_delay.h"

/* CST_PIN_MAX_VCPUS and friends.  The delay instrument needs nothing else
 * from the tracer: it is deliberately free of tracer state so it cannot
 * perturb any of it. */
#include "champsim_tracer.h"

int g_cst_delay_armed = -1;

namespace {

/* ------------------------------------------------------------------ */
/* Clocks                                                              */
/* ------------------------------------------------------------------ */

static inline uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/*
 * CLOCK_THREAD_CPUTIME_ID on the calling thread.  Read at the same boundaries
 * as the wall clock so the pair yields the on-CPU fraction: without it a wall
 * reading cannot distinguish tracer cost from host contention, and a
 * contention-confounded number is not evidence of anything.
 */
static inline uint64_t thread_cpu_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* ------------------------------------------------------------------ */
/* Per-vCPU accumulators                                               */
/* ------------------------------------------------------------------ */

/*
 * One cache-line-isolated slot per vCPU.  Every field is written only by the
 * vCPU that owns it and read only by the sampler, so relaxed ordering is
 * sufficient: the sampler is a monitor, not a synchroniser, and a counter
 * observed one window late costs nothing a diagnostic cares about.
 */
struct alignas(64) DelaySlot {
    std::atomic<uint64_t> exc_n{0};           /* excursions completed */
    std::atomic<uint64_t> exc_wall_ns{0};     /* wall time inside them */
    std::atomic<uint64_t> exc_cpu_ns{0};      /* thread CPU time inside them */
    std::atomic<uint64_t> exc_wall_max_ns{0}; /* longest single excursion */
    std::atomic<uint64_t> exc_tbs{0};         /* spec exec_tb calls */
    std::atomic<uint64_t> exc_insns{0};       /* spec insns walked */
    std::atomic<uint64_t> exc_early{0};       /* excursions ending early */
    std::atomic<uint64_t> gap_wall_ns{0};     /* wall time between them */
    std::atomic<uint64_t> gap_cpu_ns{0};      /* thread CPU time between them */
    std::atomic<uint64_t> last_end_wall{0};   /* absolute, at last end */
    std::atomic<uint64_t> last_end_cpu{0};    /* absolute, at last end */
    /* In-flight excursion: wall timestamp of its begin, 0 when idle.  This is
     * the field that makes an excursion visible WHILE it runs — the sampler
     * reports its age, so a single long excursion is distinguishable from a
     * storm of short ones without waiting for it to finish. */
    std::atomic<uint64_t> open_wall{0};
    std::atomic<uint64_t> open_target{0};
    std::atomic<uint64_t> seen{0};            /* slot ever used */
};

DelaySlot *g_slots;

/* Config, resolved once at arm. */
uint64_t g_sample_ns   = 250ull * 1000 * 1000;
uint64_t g_inject_ns;      /* CST_DELAY_DIAG_INJECT_US: positive control */
double   g_min_occ;        /* CST_DELAY_DIAG_MIN_OCC: report threshold */

/*
 * In-flight excursion state.  An excursion runs to completion on the vCPU
 * thread that started it, so thread-local is the correct and cheapest home;
 * the values are small enough not to matter to the static-TLS budget the
 * build guard enforces.
 */
thread_local uint64_t t_begin_wall;
thread_local uint64_t t_begin_cpu;
thread_local uint64_t t_tbs;
/* Excursions do not nest — the correct-path step refuses to kick one while
 * g_wp_in_progress — but the accounting refuses to depend on that: only the
 * outermost bracket bills, so a future nesting cannot silently double-count
 * wall time and inflate the very number this instrument exists to report. */
thread_local unsigned t_depth;

/* ------------------------------------------------------------------ */
/* Reporting                                                           */
/* ------------------------------------------------------------------ */

/*
 * Emit with write(2) to fd 2 rather than fprintf(stderr).
 *
 * The sampler outlives no teardown it can observe: the process can leave
 * through plugin_exit, through the realtime gate's _exit, or through a guest
 * shutdown, and in some of those the stdio layer has already been torn down
 * or flushed while this thread is between two lines.  A FILE* touched after
 * that is a crash in a diagnostic — which would make the instrument a hazard
 * to the runs it is supposed to observe.  fd 2 stays valid until the process
 * is gone, and snprintf into a stack buffer touches no shared state, so the
 * worst a teardown can do is truncate the final line.
 */
static void emit(const char *buf, size_t len)
{
    while (len) {
        ssize_t n = write(2, buf, len);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            return;
        }
        buf += n;
        len -= (size_t)n;
    }
}

struct SamplerPrev {
    uint64_t exc_n, exc_wall, exc_cpu, exc_tbs, exc_insns, exc_early;
    uint64_t gap_wall, gap_cpu, end_wall, end_cpu;
    bool     valid;
};

void *sampler_main(void *)
{
    const uint64_t t0 = mono_ns();
    SamplerPrev *prev =
        (SamplerPrev *)calloc(CST_PIN_MAX_VCPUS, sizeof(SamplerPrev));
    if (!prev) {
        return nullptr;
    }

    uint64_t prev_now = t0;

    for (;;) {
        struct timespec req;
        req.tv_sec  = (time_t)(g_sample_ns / 1000000000ull);
        req.tv_nsec = (long)(g_sample_ns % 1000000000ull);
        while (nanosleep(&req, &req) < 0 && errno == EINTR) {
            /* resume the remainder */
        }

        const uint64_t now = mono_ns();
        /* The window the sampler actually slept, not the one it asked for:
         * on a contended host these differ, and every per-second rate below
         * is divided by the measured one so contention cannot inflate it. */
        const uint64_t win = now > prev_now ? now - prev_now : g_sample_ns;
        prev_now = now;
        unsigned reported = 0;

        for (unsigned i = 0; i < CST_PIN_MAX_VCPUS; i++) {
            DelaySlot &s = g_slots[i];
            if (!s.seen.load(std::memory_order_relaxed)) {
                continue;
            }

            const uint64_t exc_n     = s.exc_n.load(std::memory_order_relaxed);
            const uint64_t exc_wall  = s.exc_wall_ns.load(std::memory_order_relaxed);
            const uint64_t exc_cpu   = s.exc_cpu_ns.load(std::memory_order_relaxed);
            const uint64_t exc_max   = s.exc_wall_max_ns.load(std::memory_order_relaxed);
            const uint64_t exc_tbs   = s.exc_tbs.load(std::memory_order_relaxed);
            const uint64_t exc_ins   = s.exc_insns.load(std::memory_order_relaxed);
            const uint64_t exc_early = s.exc_early.load(std::memory_order_relaxed);
            const uint64_t gap_wall  = s.gap_wall_ns.load(std::memory_order_relaxed);
            const uint64_t gap_cpu   = s.gap_cpu_ns.load(std::memory_order_relaxed);
            const uint64_t end_wall  = s.last_end_wall.load(std::memory_order_relaxed);
            const uint64_t end_cpu   = s.last_end_cpu.load(std::memory_order_relaxed);
            const uint64_t open      = s.open_wall.load(std::memory_order_relaxed);
            const uint64_t target    = s.open_target.load(std::memory_order_relaxed);

            SamplerPrev &p = prev[i];
            if (!p.valid) {
                p.valid = true;
                p.exc_n = exc_n; p.exc_wall = exc_wall; p.exc_cpu = exc_cpu;
                p.exc_tbs = exc_tbs; p.exc_insns = exc_ins;
                p.exc_early = exc_early;
                p.gap_wall = gap_wall; p.gap_cpu = gap_cpu;
                p.end_wall = end_wall; p.end_cpu = end_cpu;
                continue;
            }

            const uint64_t d_n     = exc_n     - p.exc_n;
            const uint64_t d_wall  = exc_wall  - p.exc_wall;
            const uint64_t d_cpu   = exc_cpu   - p.exc_cpu;
            const uint64_t d_tbs   = exc_tbs   - p.exc_tbs;
            const uint64_t d_ins   = exc_ins   - p.exc_insns;
            const uint64_t d_early = exc_early - p.exc_early;
            const uint64_t d_gapw  = gap_wall  - p.gap_wall;
            const uint64_t d_gapc  = gap_cpu   - p.gap_cpu;

            p.exc_n = exc_n; p.exc_wall = exc_wall; p.exc_cpu = exc_cpu;
            p.exc_tbs = exc_tbs; p.exc_insns = exc_ins;
            p.exc_early = exc_early;
            p.gap_wall = gap_wall; p.gap_cpu = gap_cpu;
            p.end_wall = end_wall; p.end_cpu = end_cpu;

            /*
             * The span this window accounts for is the vCPU's own timeline
             * between the two excursion ends that bracket it, and it is
             * partitioned exactly: span = excursion wall + gap wall, both
             * measured, neither modelled.  occ is the headline — the
             * fraction of the vCPU's wall clock the wrong-path walker held.
             */
            const uint64_t span_wall = d_wall + d_gapw;
            const uint64_t span_cpu  = d_cpu  + d_gapc;
            const double occ   = span_wall ? (double)d_wall / (double)span_wall : 0.0;
            const double sched = span_wall ? (double)span_cpu / (double)span_wall : 0.0;
            const double cpuocc = span_cpu ? (double)d_cpu / (double)span_cpu : 0.0;
            /* How much of the sampler's own window the span covers.  Below 1
             * the vCPU spent the remainder somewhere this instrument cannot
             * see the end of — idle, or still inside the open excursion. */
            const double cover = win ? (double)span_wall / (double)win : 0.0;

            const double inflight_ms =
                open && now > open ? (double)(now - open) / 1e6 : 0.0;

            if (occ < g_min_occ && !open && d_n == 0) {
                continue;
            }

            /* runmax_us is the longest single excursion seen since the
             * process started, not a per-window figure — the per-window view
             * of a long excursion is inflight_ms, which reports it while it
             * is still running rather than after it ends. */
            char line[640];
            int n = snprintf(line, sizeof(line),
                "[cstdelay] t=%.3f cpu=%u occ=%.4f sched=%.4f cpuocc=%.4f "
                "cover=%.3f exc=%" PRIu64 " exc_s=%.1f avg_us=%.2f "
                "runmax_us=%.1f tb_exc=%.2f ins_exc=%.2f early=%" PRIu64 " "
                "inflight_ms=%.1f target=0x%" PRIx64 " | tot_exc=%" PRIu64
                " tot_exc_s=%.2f tot_occ=%.4f\n",
                (double)(now - t0) / 1e9, i, occ, sched, cpuocc, cover,
                d_n,
                (double)d_n / ((double)win / 1e9),
                d_n ? (double)d_wall / (double)d_n / 1e3 : 0.0,
                (double)exc_max / 1e3,
                d_n ? (double)d_tbs / (double)d_n : 0.0,
                d_n ? (double)d_ins / (double)d_n : 0.0,
                d_early,
                inflight_ms, target,
                exc_n, (double)exc_wall / 1e9,
                (exc_wall + gap_wall)
                    ? (double)exc_wall / (double)(exc_wall + gap_wall) : 0.0);
            if (n > 0) {
                emit(line, (size_t)n > sizeof(line) - 1 ? sizeof(line) - 1
                                                        : (size_t)n);
                reported++;
            }
        }

        /*
         * SILENCE IS NOT A READING.  An armed instrument that prints nothing
         * is indistinguishable from one that was never armed — the operator
         * cannot tell "no excursion has ever run" from "the variable did not
         * take", and the first of those is a fact worth having (wp=0, a
         * window that never opened, a target that refuses to speculate).
         * Say it explicitly instead of leaving an absence to be read as
         * health.
         */
        if (!reported) {
            char line[192];
            int n = snprintf(line, sizeof(line),
                "[cstdelay] t=%.3f no wrong-path excursion has been observed "
                "on any vCPU since arming\n",
                (double)(now - t0) / 1e9);
            if (n > 0) {
                emit(line, (size_t)n);
            }
        }
    }
    return nullptr;
}

} /* namespace */

/* ------------------------------------------------------------------ */
/* Arming                                                              */
/* ------------------------------------------------------------------ */

bool cst_delay_arm_probe(void)
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&lock);
    if (__atomic_load_n(&g_cst_delay_armed, __ATOMIC_RELAXED) >= 0) {
        bool on = __atomic_load_n(&g_cst_delay_armed, __ATOMIC_RELAXED) != 0;
        pthread_mutex_unlock(&lock);
        return on;
    }

    const char *e = getenv("CST_DELAY_DIAG");
    if (!e || !*e) {
        __atomic_store_n(&g_cst_delay_armed, 0, __ATOMIC_RELAXED);
        pthread_mutex_unlock(&lock);
        return false;
    }

    if (const char *ms = getenv("CST_DELAY_DIAG_MS")) {
        unsigned long v = strtoul(ms, nullptr, 0);
        if (v) {
            g_sample_ns = (uint64_t)v * 1000000ull;
        }
    }
    /*
     * CST_DELAY_DIAG_INJECT_US=<n> — POSITIVE CONTROL, not a feature.  Burn
     * <n> microseconds of host CPU inside every excursion.  An instrument
     * whose zero is quoted as evidence has to be shown capable of a non-zero,
     * and a synthetic delay of a KNOWN size does better than that: the
     * reported occupancy can be checked against the size that was injected,
     * so the instrument is calibrated rather than merely seen to twitch.
     * Distorts the run it is used on, by design; never set it on a cell whose
     * output matters.
     */
    if (const char *inj = getenv("CST_DELAY_DIAG_INJECT_US")) {
        unsigned long v = strtoul(inj, nullptr, 0);
        g_inject_ns = (uint64_t)v * 1000ull;
    }
    if (const char *mo = getenv("CST_DELAY_DIAG_MIN_OCC")) {
        g_min_occ = strtod(mo, nullptr);
    }

    g_slots = new (std::nothrow) DelaySlot[CST_PIN_MAX_VCPUS]();
    if (!g_slots) {
        __atomic_store_n(&g_cst_delay_armed, 0, __ATOMIC_RELAXED);
        pthread_mutex_unlock(&lock);
        return false;
    }

    char banner[320];
    int bn = snprintf(banner, sizeof(banner),
        "[cstdelay] armed: window=%" PRIu64 "ms inject=%" PRIu64 "us "
        "min_occ=%.3f  (occ = fraction of a vCPU's wall clock held by "
        "wrong-path excursions)\n",
        (uint64_t)(g_sample_ns / 1000000ull),
        (uint64_t)(g_inject_ns / 1000ull), g_min_occ);
    if (bn > 0) {
        emit(banner, (size_t)bn);
    }

    pthread_t th;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    /* A monitor thread must not itself become a reason the guest is delayed:
     * a small stack keeps it cheap, and it does nothing but sleep, read
     * relaxed counters and write(2). */
    pthread_attr_setstacksize(&attr, 256 * 1024);
    if (pthread_create(&th, &attr, sampler_main, nullptr) != 0) {
        static const char msg[] =
            "[cstdelay] sampler thread failed to start; per-excursion "
            "accounting is live but nothing will report it\n";
        emit(msg, sizeof(msg) - 1);
    }
    pthread_attr_destroy(&attr);

    __atomic_store_n(&g_cst_delay_armed, 1, __ATOMIC_RELAXED);
    pthread_mutex_unlock(&lock);
    return true;
}

/*
 * Arm at load, not at the first excursion.
 *
 * Lazy arming made the instrument's own arming unobservable: a run with no
 * excursions at all (wp=0, a window that never opened) never reached the
 * probe, so it printed nothing — not even the banner — and an operator had
 * no way to distinguish that from a mistyped variable.  Resolving the gate
 * when the plugin is loaded means the banner is the receipt that the
 * instrument is live, and the sampler's "no excursion observed" line then
 * carries the negative result instead of silence carrying it.
 *
 * A constructor rather than a C++ static object: it has no destructor, so it
 * cannot participate in the static-teardown ordering the plugin has to be
 * careful of, and it runs before any vCPU thread exists.
 */
__attribute__((constructor))
static void cst_delay_ctor(void)
{
    cst_delay_arm_probe();
}

/* ------------------------------------------------------------------ */
/* Excursion boundaries                                                */
/* ------------------------------------------------------------------ */

void cst_delay_excursion_begin(unsigned int cpu_index, uint64_t wrong_target)
{
    if (t_depth++ || cpu_index >= CST_PIN_MAX_VCPUS || !g_slots) {
        return;
    }

    /*
     * Thread clock FIRST, wall clock second, and the wall read last before
     * the interval opens.  CLOCK_THREAD_CPUTIME_ID is ~215ns here against
     * ~31ns for CLOCK_MONOTONIC (no vDSO fast path), so reading it after the
     * wall clock would put its whole cost inside the excursion interval it
     * is timing and inflate every duration this instrument reports by that
     * much — ~3% of a healthy 6-7us excursion.  In this order the only
     * instrument work inside the measured interval is the two gap
     * fetch_adds below, tens of nanoseconds.  (The end boundary already
     * reads wall before thread, for the same reason.)
     */
    const uint64_t c = thread_cpu_ns();
    const uint64_t w = mono_ns();
    DelaySlot &s = g_slots[cpu_index];

    /* Bill the interval since the previous excursion ended on this vCPU as
     * gap: correct-path instrumentation, guest execution and off-CPU time,
     * which this instrument does not claim to separate.  The first excursion
     * on a vCPU has no predecessor and opens the accounting instead. */
    const uint64_t prev_end_w = s.last_end_wall.load(std::memory_order_relaxed);
    if (prev_end_w && w > prev_end_w) {
        const uint64_t prev_end_c =
            s.last_end_cpu.load(std::memory_order_relaxed);
        s.gap_wall_ns.fetch_add(w - prev_end_w, std::memory_order_relaxed);
        if (c > prev_end_c) {
            s.gap_cpu_ns.fetch_add(c - prev_end_c, std::memory_order_relaxed);
        }
    }

    t_begin_wall = w;
    t_begin_cpu  = c;
    t_tbs        = 0;

    s.open_target.store(wrong_target, std::memory_order_relaxed);
    s.open_wall.store(w, std::memory_order_relaxed);
    s.seen.store(1, std::memory_order_relaxed);
}

void cst_delay_excursion_end(unsigned int cpu_index, uint64_t sim_insns,
                             bool early_exit)
{
    if (t_depth == 0) {
        return;
    }
    if (--t_depth || cpu_index >= CST_PIN_MAX_VCPUS || !g_slots) {
        return;
    }

    /* Positive control: spend a known amount of host CPU here, so the
     * occupancy the sampler reports can be checked against a delay whose
     * size is known independently of anything the tracer does. */
    if (g_inject_ns) {
        const uint64_t until = thread_cpu_ns() + g_inject_ns;
        while (thread_cpu_ns() < until) {
            /* busy: the point is to consume this vCPU thread's CPU */
        }
    }

    const uint64_t w = mono_ns();
    const uint64_t c = thread_cpu_ns();
    DelaySlot &s = g_slots[cpu_index];

    const uint64_t dw = w > t_begin_wall ? w - t_begin_wall : 0;
    const uint64_t dc = c > t_begin_cpu ? c - t_begin_cpu : 0;

    s.exc_n.fetch_add(1, std::memory_order_relaxed);
    s.exc_wall_ns.fetch_add(dw, std::memory_order_relaxed);
    s.exc_cpu_ns.fetch_add(dc, std::memory_order_relaxed);
    s.exc_tbs.fetch_add(t_tbs, std::memory_order_relaxed);
    s.exc_insns.fetch_add(sim_insns, std::memory_order_relaxed);
    if (early_exit) {
        s.exc_early.fetch_add(1, std::memory_order_relaxed);
    }
    if (dw > s.exc_wall_max_ns.load(std::memory_order_relaxed)) {
        s.exc_wall_max_ns.store(dw, std::memory_order_relaxed);
    }

    s.last_end_wall.store(w, std::memory_order_relaxed);
    s.last_end_cpu.store(c, std::memory_order_relaxed);
    /* Clear last: while this is non-zero the sampler reports an excursion as
     * still open, and it must not do so after the accounting has closed. */
    s.open_wall.store(0, std::memory_order_relaxed);
}

void cst_delay_note_spec_tb(void)
{
    t_tbs++;
}
