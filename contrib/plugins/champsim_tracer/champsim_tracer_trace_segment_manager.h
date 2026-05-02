/*
 * Wrong-Path Tracing Plugin — trace segment lifecycle.
 *
 * Owns one in-flight TraceSegment at a time plus the start/stop window
 * and the active-flag pair (a regular bool for use under exec_lock and
 * an atomic int for callbacks that run lock-free).  Handles output-
 * destination resolution (file vs popen pipe) when a segment starts
 * and the writer/body-stream teardown when one finishes.
 *
 * The body emitter calls body_stream() and next_seq_num() on the
 * currently-active segment.  Lifecycle:
 *
 *   start("trace", lo, hi)          -> opens output, marks active
 *   ... emit body entries ...
 *   finish(flush_hook)              -> deactivates, runs hook, seals
 *
 * The hook fires between deactivating the segment and closing the
 * binary stream so it can flush a pending final entry while the stream
 * is still writable.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_TRACE_SEGMENT_MANAGER_H
#define CHAMPSIM_TRACER_TRACE_SEGMENT_MANAGER_H

#include <functional>

#include "champsim_tracer.h"

class TraceSegmentManager {
public:
    TraceSegmentManager() = default;
    ~TraceSegmentManager();

    TraceSegmentManager(const TraceSegmentManager &) = delete;
    TraceSegmentManager &operator=(const TraceSegmentManager &) = delete;

    /* Configuration: set once at plugin install time. */
    void set_output_path(const char *path);
    void set_output_pipe(const char *cmd);
    void set_window(uint64_t start_insn, uint64_t stop_insn);

    uint64_t window_start() const { return start_insn_; }
    uint64_t window_stop() const { return stop_insn_; }

    /* Lifecycle. */
    void start(const char *label, uint64_t start_insn, uint64_t stop_insn);
    void finish(const std::function<void()> &flush_hook);

    /* State queries. */
    bool is_active() const { return active_; }
    bool is_active_atomic() const {
        return g_atomic_int_get(&active_atomic_) != 0;
    }
    bool is_shutting_down() const {
        return g_atomic_int_get(&shutting_down_) != 0;
    }
    void set_shutting_down() { g_atomic_int_set(&shutting_down_, 1); }
    bool has_active_segment() const { return current_ != nullptr; }

    /* Body-emitter access points.  Both return null/0 when no segment
     * is active. */
    BodyStreamState *body_stream() const;
    uint32_t next_seq_num();

private:
    static TraceSegment *segment_new(const char *label,
                                     uint64_t start, uint64_t stop);
    static void segment_free(TraceSegment *seg);
    void open_output(const char *label);

    TraceSegment    *current_         = nullptr;
    bool             active_          = false;
    volatile gint    active_atomic_   = 0;
    volatile gint    shutting_down_   = 0;
    char            *output_path_     = nullptr;
    char            *output_pipe_     = nullptr;
    uint64_t         start_insn_      = 0;
    uint64_t         stop_insn_       = UINT64_MAX;
};

extern TraceSegmentManager g_trace_segments;

#endif /* CHAMPSIM_TRACER_TRACE_SEGMENT_MANAGER_H */
