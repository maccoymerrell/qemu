/*
 * Wrong-Path Tracing Plugin — trace segment lifecycle.
 *
 * Owns one in-flight TraceSegment plus the start/stop window and the
 * active-flag pair (a bool for use under exec_lock, an atomic int for
 * lock-free callbacks).  Resolves the output sink (file vs popen
 * pipe) on start and tears down writer/body-stream on finish.
 *
 * Lifecycle:
 *   start("trace", lo, hi)  -> opens output, marks active
 *   ... emit body entries ...
 *   finish(flush_hook)      -> deactivates, runs hook, seals
 *
 * The hook fires after deactivation but before the stream closes, so
 * it can flush a pending final entry while still writable.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_TRACE_SEGMENT_MANAGER_H
#define CHAMPSIM_TRACER_TRACE_SEGMENT_MANAGER_H

#include <atomic>
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
    /* Per-member compression command.  Each member (body + header)
     * is independently piped through this command before landing on
     * disk.  The command should read from stdin and write to stdout
     * (e.g., "zstd -3", "gzip -3", "xz -3 -c").  Nullptr / empty
     * disables compression and writes the members uncompressed. */
    void set_compress_cmd(const char *cmd);
    void set_window(uint64_t start_insn, uint64_t stop_insn);

    uint64_t window_start() const { return start_insn_; }
    uint64_t window_stop() const { return stop_insn_; }

    /* Lifecycle.
     *
     * @warmup_insns       : pre-simpoint warmup length (0 outside
     *                       simpoint mode); copied verbatim into the
     *                       header.
     * @total_target_insns : the configured length of the segment;
     *                       copied verbatim into the header.  Zero
     *                       means "unbounded" (non-simpoint run with
     *                       no explicit stop). */
    void start(const char *label, uint64_t start_insn, uint64_t stop_insn,
               uint64_t warmup_insns,
               uint64_t total_target_insns,
               uint32_t seed_thread_id,
               double simpoint_weight,
               const std::vector<InitialRegSnap> *initial_regfile);
    void finish(const std::function<void()> &flush_hook);

    /* State queries. */
    bool is_active() const { return active_; }
    bool is_active_atomic() const {
        return active_atomic_.load() != 0;
    }
    bool is_shutting_down() const {
        return shutting_down_.load() != 0;
    }
    void set_shutting_down() { shutting_down_.store(1); }
    bool has_active_segment() const { return current_ != nullptr; }

    /* Body-emitter access points.  Both return null/0 when no segment
     * is active. */
    BodyStreamState *body_stream() const;
    uint32_t next_seq_num();

private:
    static TraceSegment *segment_new(const char *label,
                                     uint64_t start, uint64_t stop);
    static void segment_free(TraceSegment *seg);
    void open_output(const char *label,
                     uint64_t warmup_insns,
                     uint64_t total_target_insns,
                     uint32_t seed_thread_id,
                     double simpoint_weight,
                     const std::vector<InitialRegSnap> *regfile);

    TraceSegment        *current_       = nullptr;
    bool                 active_        = false;
    std::atomic<int>     active_atomic_{0};
    std::atomic<int>     shutting_down_{0};
    char                *output_path_   = nullptr;
    /* User-configured compression command (verbatim from
     * compress=...); nullptr or empty means raw uncompressed
     * members.  See set_compress_cmd. */
    char                *compress_cmd_  = nullptr;
    uint64_t             start_insn_    = 0;
    uint64_t             stop_insn_     = UINT64_MAX;
};

extern TraceSegmentManager g_trace_segments;

#endif /* CHAMPSIM_TRACER_TRACE_SEGMENT_MANAGER_H */
