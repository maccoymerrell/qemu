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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

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
};

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

static WriterChunk *cq_pop(ChunkQueue *q)
{
    pthread_mutex_lock(&q->lock);
    while (q->count == 0) {
        pthread_cond_wait(&q->not_empty, &q->lock);
    }
    WriterChunk *c = q->slots[q->head];
    q->head = (q->head + 1) % WRITER_QUEUE_CAP;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return c;
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

    int rc = pthread_create(&w->thr, nullptr, writer_thread_main, w);
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
            c = cq_pop(&w->free_q);
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
        pthread_join(w->thr, nullptr);
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
