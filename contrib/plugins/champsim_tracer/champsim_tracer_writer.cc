/*
 * Wrong-Path Tracing Plugin — async output writer thread.
 *
 * Decouples the QEMU CPU thread producing trace bytes from the FILE*
 * sink (typically popen'd to xz -T0).  Without it the ~64 KiB kernel
 * pipe buffer is the only absorber, so every compressor stall blocks
 * the QEMU thread and deforms the guest workload's timing.
 *
 * Design
 * ------
 * SPSC chunked queue.  Producer (QEMU CPU thread holding data_lock)
 * fills a chunk, publishes it to the fill queue, pops a fresh one
 * from the free queue.  The writer thread drains fill, fwrite()s,
 * recycles onto free.  In-flight = WRITER_CHUNK_BYTES *
 * WRITER_NUM_CHUNKS = 64 MiB.
 *
 * The queue uses pthread mutex + condvars, not std::mutex /
 * std::condition_variable: libstdc++'s <mutex> transitively includes
 * <cctype>, which pulls QEMU's include/qemu/ctype.h shadow header on
 * the plugin's search path and breaks the build (see
 * champsim_tracer.h note).
 *
 * Lifecycle is per-TraceSegment: writer_start() after the FILE* is
 * opened, writer_finish() before pclose/fclose.
 *
 * A SINK THAT STOPS READING
 * -------------------------
 * Everything here is a blocking interaction with a process the tracer does
 * not control, and a compressor that stops consuming stops all of it: the
 * writer thread parks in fwrite() on a full pipe, the 64 MiB of chunks fill,
 * and the producer -- a vCPU thread -- parks in cq_pop() waiting for a free
 * chunk with the guest frozen mid-instruction.  At the close the same stall
 * parks writer_finish() in pthread_join().  None of that needs a broken
 * compressor to happen: a full output filesystem, a stopped process, or a
 * command that never reads its stdin all produce it, and it used to produce
 * it in total silence, with no bound and nothing on stderr, for as long as
 * the operator was willing to wait.
 *
 * So every wait on the sink is now watched, and what is watched is
 * PROGRESS, not elapsed time: bytes_out counts what the sink has actually
 * taken, and a wait is only called stalled when that number has not moved
 * for the whole interval.  A slow compressor is never accused of anything,
 * however long it takes.  A stalled one is named on stderr, with the phase,
 * the seconds, and the byte count, and named again every interval so the
 * message cannot be lost in scrollback.  CST_SINK_STALL_SECS sets the
 * interval (default 60, 0 disables the report); CST_SINK_STALL_ABORT_SECS
 * is off unless set and turns the report into a termination for operators
 * who need the run to end rather than wait.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atomic>

#include "champsim_tracer.h"
#include "champsim_tracer_writer.h"

/* Total in-flight: 16 * 4 MiB = 64 MiB per active segment. */
#define WRITER_CHUNK_BYTES (4u * 1024u * 1024u)
#define WRITER_NUM_CHUNKS  16u
#define WRITER_FILE_BUFSZ  (4u * 1024u * 1024u)

/* Queue capacity must hold every chunk plus the EOF sentinel.  +2 gives
 * one slack slot so push never has to wait on a non-full queue path. */
#define WRITER_QUEUE_CAP   (WRITER_NUM_CHUNKS + 2u)

typedef struct {
    uint8_t *data;
    size_t   len;     /* bytes filled                                  */
    size_t   cap;     /* always WRITER_CHUNK_BYTES (kept for clarity)  */
    bool     eof;     /* sentinel chunk: tells consumer to exit        */
} WriterChunk;

/*
 * Bounded blocking SPSC queue of WriterChunk*.  Uses a fixed-size
 * circular buffer; push waits on `not_full`, pop on `not_empty`.
 */
typedef struct {
    WriterChunk    *slots[WRITER_QUEUE_CAP];
    unsigned        head;
    unsigned        tail;
    unsigned        count;
    pthread_mutex_t lock;
    pthread_cond_t  not_full;
    pthread_cond_t  not_empty;
} ChunkQueue;

struct WriterCtx {
    FILE        *f;
    bool         is_pipe;

    pthread_t    thr;
    bool         thr_started;

    /* Owned chunks.  Each lives in exactly one of: producer's
     * `current` pointer, the fill_q, or the free_q. */
    WriterChunk *chunks;
    /* Sentinel chunk pushed to fill_q on shutdown.  Statically
     * separate from `chunks` so it never re-enters free_q. */
    WriterChunk  sentinel;

    ChunkQueue   free_q;
    ChunkQueue   fill_q;

    /* Producer-private cursor.  When nullptr (post-finish), bw_raw
     * shouldn't be called any more. */
    WriterChunk *current;

    /* Bytes the SINK has taken, bumped by the writer thread after each
     * fwrite returns.  This is the progress a stall watch tests: it moves
     * for a slow compressor and stands still for a stopped one. */
    std::atomic<unsigned long long> bytes_out;
};

/* ===== Sink stall reporting =====
 *
 * Interval in seconds between one report and the next, 0 to disable, and
 * the optional no-progress deadline after which the run is ended rather
 * than continued.  Read once. */
static unsigned sink_stall_secs(void)
{
    static const unsigned v = []() {
        const char *e = getenv("CST_SINK_STALL_SECS");
        return (e && *e) ? (unsigned)strtoul(e, nullptr, 0) : 60u;
    }();
    return v;
}

static unsigned sink_stall_abort_secs(void)
{
    static const unsigned v = []() {
        const char *e = getenv("CST_SINK_STALL_ABORT_SECS");
        return (e && *e) ? (unsigned)strtoul(e, nullptr, 0) : 0u;
    }();
    return v;
}

/*
 * Report one stalled interval, and end the run when the operator asked for
 * a deadline.  @waited is the whole time this wait has been making no
 * progress, not the time since the last report.
 */
static void sink_stall_report(const char *phase, unsigned long long waited,
                              unsigned long long bytes, bool have_bytes)
{
    char taken[64];
    if (have_bytes) {
        snprintf(taken, sizeof taken, " (%llu bytes taken by the sink so far)",
                 bytes);
    } else {
        taken[0] = '\0';
    }
    fprintf(stderr,
            "champsim_tracer: *** OUTPUT SINK STALLED *** %s has made no "
            "progress for %llu s%s.  The compression command is not "
            "finishing; a full output filesystem, a stopped compressor, or a "
            "command that never reads stdin all look like this.  The guest is "
            "frozen until it resumes.\n",
            phase, waited, taken);
    unsigned deadline = sink_stall_abort_secs();
    if (deadline && waited >= deadline) {
        fprintf(stderr,
                "champsim_tracer: CST_SINK_STALL_ABORT_SECS=%u reached; "
                "ending the run with the trace INCOMPLETE.\n", deadline);
        fflush(stderr);
        _exit(97);
    }
}

static unsigned long long mono_secs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec;
}

/* ===== Stall watch for a wait with no queue of its own =====
 *
 * pclose() waits for the compressor to EXIT, which is a third way the same
 * failure lands: the writer has drained, the join has returned, and the
 * child still never finishes.  There is no timed pclose, so the watch is a
 * thread that reports until the wait it is watching ends.  Only ever armed
 * at a close, so its cost is irrelevant.
 */
struct SinkStallWatch {
    pthread_t       thr;
    bool            started;
    pthread_mutex_t m;
    pthread_cond_t  c;
    bool            done;
    const char     *phase;
    unsigned long long t0;
};

static void *sink_stall_watch_main(void *arg)
{
    SinkStallWatch *sw = (SinkStallWatch *)arg;
    const unsigned interval = sink_stall_secs();
    pthread_mutex_lock(&sw->m);
    while (!sw->done) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (time_t)interval;
        if (pthread_cond_timedwait(&sw->c, &sw->m, &ts) == ETIMEDOUT &&
            !sw->done) {
            sink_stall_report(sw->phase, mono_secs() - sw->t0, 0, false);
        }
    }
    pthread_mutex_unlock(&sw->m);
    return nullptr;
}

void *sink_stall_watch_begin(const char *phase)
{
    if (!sink_stall_secs()) {
        return nullptr;
    }
    SinkStallWatch *sw = (SinkStallWatch *)calloc(1, sizeof(SinkStallWatch));
    if (!sw) {
        return nullptr;
    }
    pthread_mutex_init(&sw->m, nullptr);
    pthread_cond_init(&sw->c, nullptr);
    sw->phase = phase;
    sw->t0 = mono_secs();
    /* Blocked signal mask, for the reason writer_start documents. */
    sigset_t all, saved;
    sigfillset(&all);
    pthread_sigmask(SIG_SETMASK, &all, &saved);
    sw->started = (pthread_create(&sw->thr, nullptr,
                                  sink_stall_watch_main, sw) == 0);
    pthread_sigmask(SIG_SETMASK, &saved, nullptr);
    if (!sw->started) {
        pthread_cond_destroy(&sw->c);
        pthread_mutex_destroy(&sw->m);
        free(sw);
        return nullptr;
    }
    return sw;
}

void sink_stall_watch_end(void *handle)
{
    SinkStallWatch *sw = (SinkStallWatch *)handle;
    if (!sw) {
        return;
    }
    pthread_mutex_lock(&sw->m);
    sw->done = true;
    pthread_cond_signal(&sw->c);
    pthread_mutex_unlock(&sw->m);
    pthread_join(sw->thr, nullptr);
    pthread_cond_destroy(&sw->c);
    pthread_mutex_destroy(&sw->m);
    free(sw);
}

/* ===== Queue primitives ===== */

static void cq_init(ChunkQueue *q)
{
    memset(q->slots, 0, sizeof(q->slots));
    q->head = q->tail = q->count = 0;
    pthread_mutex_init(&q->lock, nullptr);
    pthread_cond_init(&q->not_full, nullptr);
    pthread_cond_init(&q->not_empty, nullptr);
}

static void cq_destroy(ChunkQueue *q)
{
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
    pthread_mutex_destroy(&q->lock);
}

static void cq_push(ChunkQueue *q, WriterChunk *c)
{
    pthread_mutex_lock(&q->lock);
    while (q->count == WRITER_QUEUE_CAP) {
        pthread_cond_wait(&q->not_full, &q->lock);
    }
    q->slots[q->tail] = c;
    q->tail = (q->tail + 1) % WRITER_QUEUE_CAP;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}

/*
 * cq_pop with a stall report.  @w may be null, which disables the report
 * (the writer thread's own wait on fill_q is an IDLE wait -- there is
 * nothing to produce -- and must never be called a stall).  The producer's
 * wait on free_q is the one that matters: reaching it means the sink is
 * 64 MiB behind and a vCPU thread is parked here with the guest stopped.
 */
static WriterChunk *cq_pop_watched(ChunkQueue *q, WriterCtx *w,
                                   const char *phase)
{
    pthread_mutex_lock(&q->lock);
    const unsigned interval = w ? sink_stall_secs() : 0u;
    bool waiting = false;
    unsigned long long last_bytes = 0, stalled_since = 0;
    while (q->count == 0) {
        if (!interval) {
            pthread_cond_wait(&q->not_empty, &q->lock);
            continue;
        }
        if (!waiting) {
            waiting = true;
            stalled_since = mono_secs();
            last_bytes = w->bytes_out.load(std::memory_order_relaxed);
        }
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (time_t)interval;
        if (pthread_cond_timedwait(&q->not_empty, &q->lock, &ts) == ETIMEDOUT) {
            unsigned long long b = w->bytes_out.load(std::memory_order_relaxed);
            if (b != last_bytes) {
                last_bytes = b;                    /* the sink is moving */
                stalled_since = mono_secs();
            } else {
                sink_stall_report(phase, mono_secs() - stalled_since, b, true);
            }
        }
    }
    WriterChunk *c = q->slots[q->head];
    q->head = (q->head + 1) % WRITER_QUEUE_CAP;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return c;
}

static WriterChunk *cq_pop(ChunkQueue *q)
{
    return cq_pop_watched(q, nullptr, nullptr);
}

/* ===== Internals ===== */

static void *writer_thread_main(void *arg)
{
    WriterCtx *w = (WriterCtx *)arg;
    for (;;) {
        WriterChunk *c = cq_pop(&w->fill_q);
        if (c->eof) {
            break;
        }
        if (c->len) {
            size_t n = fwrite(c->data, 1, c->len, w->f);
            w->bytes_out.fetch_add(n, std::memory_order_relaxed);
            if (n != c->len) {
                /* Disk-full or broken pipe.  Best we can do is keep
                 * draining so the producer doesn't deadlock; bytes
                 * are dropped.  Stderr message keeps it visible. */
                fprintf(stderr,
                        "champsim_tracer: writer fwrite short (%zu/%zu)\n",
                        n, c->len);
            }
        }
        c->len = 0;
        cq_push(&w->free_q, c);
    }
    fflush(w->f);
    return nullptr;
}

/* ===== Public API ===== */

WriterCtx *writer_start(FILE *f, bool is_pipe)
{
    if (!f) {
        return nullptr;
    }

    /* Coalesce small fwrite() calls inside the writer thread into
     * fewer syscalls / pipe writes. */
    setvbuf(f, nullptr, _IOFBF, WRITER_FILE_BUFSZ);

    WriterCtx *w = (WriterCtx *)calloc(1, sizeof(WriterCtx));
    w->f = f;
    w->is_pipe = is_pipe;
    cq_init(&w->free_q);
    cq_init(&w->fill_q);
    w->chunks = (WriterChunk *)calloc(WRITER_NUM_CHUNKS, sizeof(WriterChunk));
    for (unsigned i = 0; i < WRITER_NUM_CHUNKS; i++) {
        w->chunks[i].data = (uint8_t *)malloc(WRITER_CHUNK_BYTES);
        w->chunks[i].cap  = WRITER_CHUNK_BYTES;
        w->chunks[i].len  = 0;
        w->chunks[i].eof  = false;
        cq_push(&w->free_q, &w->chunks[i]);
    }
    w->sentinel.data = nullptr;
    w->sentinel.cap  = 0;
    w->sentinel.len  = 0;
    w->sentinel.eof  = true;

    /* Pull the first chunk for the producer. */
    w->current = cq_pop(&w->free_q);

    /*
     * Create the writer with EVERY signal blocked, and restore the
     * caller's mask afterwards (the new thread inherits the mask in
     * force at pthread_create).
     *
     * A guest signal in linux-user mode arrives as a host signal, and a
     * process-directed one (the guest's own setitimer/alarm, or anything
     * kill(2) sends to the process) may be delivered to ANY host thread
     * whose mask allows it — including this one.  qemu-user's
     * host_signal_handler then reads the executing thread's TaskState
     * (linux-user/signal.c: `TaskState *ts = get_task_state(cpu)`),
     * which does not exist on a thread that is not a guest vCPU: the
     * process dies with SIGSEGV inside the handler.  Reproduced on
     * pristine HEAD at 4 of 6 runs of a guest that arms a 1 ms
     * ITIMER_REAL/ITIMER_VIRTUAL storm, and never without the plugin
     * loaded (cst_runs/fence).  Blocking here removes this thread as a
     * delivery target, which is what a helper thread should do anyway;
     * the underlying qemu-user assumption that every signal-taking host
     * thread is a guest thread is reported separately.
     */
    sigset_t all, saved;
    sigfillset(&all);
    pthread_sigmask(SIG_SETMASK, &all, &saved);
    int rc = pthread_create(&w->thr, nullptr, writer_thread_main, w);
    pthread_sigmask(SIG_SETMASK, &saved, nullptr);
    if (rc != 0) {
        fprintf(stderr,
                "champsim_tracer: pthread_create(writer): %d\n", rc);
        /* Fall through with thr_started=false; writer_submit will
         * still memcpy and writer_finish will drop bytes safely. */
    } else {
        w->thr_started = true;
    }
    return w;
}

void writer_submit(WriterCtx *w, const uint8_t *buf, size_t len)
{
    if (!w || !w->current || len == 0) {
        return;
    }
    size_t off = 0;
    WriterChunk *c = w->current;
    while (off < len) {
        size_t room = c->cap - c->len;
        if (room == 0) {
            cq_push(&w->fill_q, c);
            c = cq_pop_watched(&w->free_q, w,
                               "a vCPU thread waiting for a free output chunk");
            c->len = 0;
            w->current = c;
            continue;
        }
        size_t n = MIN(room, len - off);
        memcpy(c->data + c->len, buf + off, n);
        c->len += n;
        off    += n;
    }
}

void writer_finish(WriterCtx *w)
{
    if (!w) {
        return;
    }
    /* Flush partial last chunk, then sentinel. */
    if (w->current && w->current->len) {
        cq_push(&w->fill_q, w->current);
        w->current = nullptr;
    } else if (w->current) {
        /* Empty: return it to free list rather than the consumer. */
        cq_push(&w->free_q, w->current);
        w->current = nullptr;
    }
    cq_push(&w->fill_q, &w->sentinel);

    if (w->thr_started) {
        const unsigned interval = sink_stall_secs();
        if (!interval) {
            pthread_join(w->thr, nullptr);
        } else {
            /* Same rule as the producer's wait: only a sink that has taken
             * no bytes for the whole interval is stalled.  The join itself
             * is never given up on unless the operator set a deadline --
             * a compressor that is merely slow must be allowed to finish,
             * because what it is finishing is the trace. */
            unsigned long long last_bytes =
                w->bytes_out.load(std::memory_order_relaxed);
            unsigned long long stalled_since = mono_secs();
            for (;;) {
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_sec += (time_t)interval;
                int rc = pthread_timedjoin_np(w->thr, nullptr, &ts);
                if (rc == 0) {
                    break;
                }
                if (rc != ETIMEDOUT) {
                    pthread_join(w->thr, nullptr);
                    break;
                }
                unsigned long long b =
                    w->bytes_out.load(std::memory_order_relaxed);
                if (b != last_bytes) {
                    last_bytes = b;
                    stalled_since = mono_secs();
                } else {
                    sink_stall_report("the close draining the output writer",
                                      mono_secs() - stalled_since, b, true);
                }
            }
        }
        w->thr_started = false;
    }

    /* Free chunks.  Anything left in free_q is owned by us; fill_q
     * should be empty (consumer drained or never started). */
    if (w->chunks) {
        for (unsigned i = 0; i < WRITER_NUM_CHUNKS; i++) {
            free(w->chunks[i].data);
        }
        free(w->chunks);
        w->chunks = nullptr;
    }
    cq_destroy(&w->free_q);
    cq_destroy(&w->fill_q);
    free(w);
}
