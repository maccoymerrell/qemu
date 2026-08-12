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
 *
 * A sink that has stopped taking bytes parks this call.  It is not given
 * up on -- a slow compressor is still writing the trace -- but it is
 * reported on stderr every CST_SINK_STALL_SECS for as long as the sink's
 * byte count stands still.  See the TU comment.
 */
void writer_finish(WriterCtx *w);

/*
 * Arm / disarm a stall report around a blocking wait on the output sink
 * that has no progress counter of its own -- pclose() waiting for the
 * compressor to exit.  begin() returns a handle (null when reporting is
 * disabled, which end() accepts); end() stops the report and must be
 * called on every path out of the wait.
 */
void *sink_stall_watch_begin(const char *phase);
void  sink_stall_watch_end(void *handle);

/*
 * Write @len bytes to a sink with no writer thread behind it -- the header
 * member -- under the same stall watch and the same progress rule as the
 * writer thread's own writes.  Returns the bytes written; a short return is
 * the sink failing, not stalling.
 */
size_t sink_write_watched(FILE *f, const void *data, size_t len,
                          const char *phase);

#endif /* CHAMPSIM_TRACER_WRITER_H */
