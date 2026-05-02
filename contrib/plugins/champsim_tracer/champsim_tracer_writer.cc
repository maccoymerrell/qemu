/*
 * Wrong-Path Tracing Plugin — async output writer thread.
 *
 * Decouples the QEMU CPU thread that produces trace bytes (via bw_raw)
 * from the FILE* sink (which is typically popen()'d to xz -T0 and
 * therefore subject to compressor stalls).  Without this the kernel
 * pipe buffer (~64 KiB) is the only absorber: every time xz falls
 * behind, fwrite() blocks the QEMU thread and the guest workload's
 * timing is deformed.
 *
 * Design
 * ------
 * Single-producer / single-consumer chunked queue.  Producer (the
 * QEMU CPU thread holding plugin data_lock) writes into a
 * preallocated chunk; when the chunk fills, it is published to a
 * GAsyncQueue and a fresh chunk is popped from the free list.  The
 * dedicated writer thread drains the fill queue, fwrite()s each
 * chunk, and recycles it onto the free list.  Total in-flight bytes
 * = WRITER_CHUNK_BYTES * WRITER_NUM_CHUNKS = 64 MiB.
 *
 * Lifecycle is per-TraceSegment: writer_start() is called after the
 * FILE* is opened (popen or fopen), writer_finish() before
 * pclose/fclose.  Simpoint mode creates one writer thread per
 * segment, exactly mirroring today's per-segment popen().
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <pthread.h>
#include <string.h>

#include "champsim_tracer.h"
#include "champsim_tracer_writer.h"

/* Total in-flight: 16 * 4 MiB = 64 MiB per active segment. */
#define WRITER_CHUNK_BYTES (4u * 1024u * 1024u)
#define WRITER_NUM_CHUNKS  16u
#define WRITER_FILE_BUFSZ  (4u * 1024u * 1024u)

typedef struct {
    uint8_t *data;
    size_t   len;     /* bytes filled                                  */
    size_t   cap;     /* always WRITER_CHUNK_BYTES (kept for clarity)  */
    bool     eof;     /* sentinel chunk: tells consumer to exit        */
} WriterChunk;

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

    GAsyncQueue *free_q;
    GAsyncQueue *fill_q;

    /* Producer-private cursor.  When nullptr (post-finish), bw_raw
     * shouldn't be called any more. */
    WriterChunk *current;
};

/* ===== Internals ===== */

static void *writer_thread_main(void *arg)
{
    WriterCtx *w = (WriterCtx *)arg;
    for (;;) {
        WriterChunk *c = (WriterChunk *)g_async_queue_pop(w->fill_q);
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
        g_async_queue_push(w->free_q, c);
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

    WriterCtx *w = g_new0(WriterCtx, 1);
    w->f = f;
    w->is_pipe = is_pipe;
    w->free_q = g_async_queue_new();
    w->fill_q = g_async_queue_new();
    w->chunks = g_new0(WriterChunk, WRITER_NUM_CHUNKS);
    for (unsigned i = 0; i < WRITER_NUM_CHUNKS; i++) {
        w->chunks[i].data = (uint8_t *)g_malloc(WRITER_CHUNK_BYTES);
        w->chunks[i].cap  = WRITER_CHUNK_BYTES;
        w->chunks[i].len  = 0;
        w->chunks[i].eof  = false;
        g_async_queue_push(w->free_q, &w->chunks[i]);
    }
    w->sentinel.data = nullptr;
    w->sentinel.cap  = 0;
    w->sentinel.len  = 0;
    w->sentinel.eof  = true;

    /* Pull the first chunk for the producer. */
    w->current = (WriterChunk *)g_async_queue_pop(w->free_q);

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
            g_async_queue_push(w->fill_q, c);
            c = (WriterChunk *)g_async_queue_pop(w->free_q);
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
        g_async_queue_push(w->fill_q, w->current);
        w->current = nullptr;
    } else if (w->current) {
        /* Empty: return it to free list rather than the consumer. */
        g_async_queue_push(w->free_q, w->current);
        w->current = nullptr;
    }
    g_async_queue_push(w->fill_q, &w->sentinel);

    if (w->thr_started) {
        pthread_join(w->thr, nullptr);
        w->thr_started = false;
    }

    /* Free chunks.  Anything left in free_q is owned by us; fill_q
     * should be empty (consumer drained or never started). */
    if (w->chunks) {
        for (unsigned i = 0; i < WRITER_NUM_CHUNKS; i++) {
            g_free(w->chunks[i].data);
        }
        g_free(w->chunks);
        w->chunks = nullptr;
    }
    if (w->free_q) {
        g_async_queue_unref(w->free_q);
    }
    if (w->fill_q) {
        g_async_queue_unref(w->fill_q);
    }
    g_free(w);
}
