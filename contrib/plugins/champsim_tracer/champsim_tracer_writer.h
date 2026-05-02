/*
 * Wrong-Path Tracing Plugin — async output writer thread API.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_WRITER_H
#define CHAMPSIM_TRACER_WRITER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct WriterCtx WriterCtx;

/*
 * Spawn a writer thread that drains chunks into @f.  Takes shared
 * ownership of @f; caller still owns the FILE* and must
 * pclose/fclose it AFTER writer_finish() returns.  @is_pipe is
 * informational (kept for symmetry with TraceSegment).  Returns
 * NULL only if @f is NULL.
 */
WriterCtx *writer_start(FILE *f, bool is_pipe);

/*
 * Enqueue @len bytes from @buf into the writer's chunk queue.
 * May block when the free-list is empty (i.e. consumer is at least
 * 64 MiB behind).  Caller must hold the producer-side serialization
 * (e.g. plugin data_lock).
 */
void writer_submit(WriterCtx *w, const uint8_t *buf, size_t len);

/*
 * Flush any partial chunk, push EOF sentinel, join the writer
 * thread, and free all writer state.  After this returns it is safe
 * for the caller to pclose/fclose the underlying FILE*.
 */
void writer_finish(WriterCtx *w);

#endif /* CHAMPSIM_TRACER_WRITER_H */
