/*
 * Wrong-Path Tracing Plugin — trace segment lifecycle implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "champsim_tracer_simpoint_manager.h"
#include "champsim_tracer_trace_segment_manager.h"
#include "champsim_tracer_writer.h"

TraceSegmentManager g_trace_segments;

TraceSegmentManager::~TraceSegmentManager()
{
    if (current_) {
        segment_free(current_);
    }
    g_free(output_path_);
    g_free(output_pipe_);
}

void TraceSegmentManager::set_output_path(const char *path)
{
    g_free(output_path_);
    output_path_ = path ? g_strdup(path) : nullptr;
}

void TraceSegmentManager::set_output_pipe(const char *cmd)
{
    g_free(output_pipe_);
    output_pipe_ = cmd ? g_strdup(cmd) : nullptr;
}

void TraceSegmentManager::set_window(uint64_t start_insn, uint64_t stop_insn)
{
    start_insn_ = start_insn;
    stop_insn_ = stop_insn;
}

BodyStreamState *TraceSegmentManager::body_stream() const
{
    return current_ ? current_->bin_stream : nullptr;
}

uint32_t TraceSegmentManager::next_seq_num()
{
    if (!current_) {
        return 0;
    }
    return ++current_->body_seq_num;
}

TraceSegment *TraceSegmentManager::segment_new(const char *label,
                                               uint64_t start,
                                               uint64_t stop)
{
    TraceSegment *seg = g_new0(TraceSegment, 1);
    seg->start_insn = start;
    seg->stop_insn = stop;
    seg->label = g_strdup(label);
    return seg;
}

void TraceSegmentManager::segment_free(TraceSegment *seg)
{
    if (!seg) {
        return;
    }
    if (seg->bin_stream) {
        g_free(seg->bin_stream);
    }
    /* Drain async writer queue and join its thread BEFORE closing the
     * underlying FILE*, so all enqueued bytes hit xz/disk and the
     * writer can fflush cleanly. */
    if (seg->writer) {
        writer_finish(seg->writer);
        seg->writer = nullptr;
    }
    if (seg->bin_file) {
        if (seg->bin_file_is_pipe) {
            int rc = pclose(seg->bin_file);
            if (rc != 0) {
                fprintf(stderr,
                        "champsim_tracer: output pipe child exited with status %d\n",
                        rc);
            }
        } else {
            fclose(seg->bin_file);
        }
    }
    g_free(seg->label);
    g_free(seg);
}

void TraceSegmentManager::open_output(const char *label,
                                      uint64_t warmup_insns,
                                      uint64_t total_target_insns,
                                      const std::vector<InitialRegSnap> *regfile)
{
    /*
     * Output destination resolution:
     *   - outpipe=CMD   -> popen(CMD, "w").  "%s" in CMD is replaced
     *                      with the segment label so simpoint runs land
     *                      in distinct files.
     *   - outfile=PATH  -> fopen(PATH[.cst|_LABEL.cst], "wb"), with the
     *                      "_LABEL" suffix added when simpoints are
     *                      active so each simpoint segment gets its own
     *                      file.
     * outpipe takes precedence when both are set.
     */
    if (output_pipe_) {
        g_autofree char *cmd = strstr(output_pipe_, "%s")
            ? g_strdup_printf(output_pipe_, label)
            : g_strdup(output_pipe_);
        current_->bin_file = popen(cmd, "w");
        if (!current_->bin_file) {
            fprintf(stderr,
                    "champsim_tracer: cannot open output pipe: %s\n", cmd);
            return;
        }
        current_->bin_file_is_pipe = true;
        current_->writer = writer_start(current_->bin_file, true);
        current_->bin_stream =
            body_stream_new(current_->writer, current_->start_datetime,
                            current_->start_insn, warmup_insns,
                            total_target_insns, regfile);
        if (!current_->bin_stream) {
            fprintf(stderr,
                    "champsim_tracer: cannot initialize binary stream\n");
        }
        return;
    }

    if (!output_path_) {
        return;
    }

    /* Strip a trailing ".cst" before appending segment labels and the
     * extension, so a user passing ``outfile=trace.cst`` gets
     * ``trace.cst`` (single segment) or ``trace_sp0.cst`` (per-
     * simpoint) rather than ``trace.cst.cst`` / ``trace.cst_sp0.cst``. */
    size_t base_len = strlen(output_path_);
    if (base_len >= 4 &&
        strcmp(output_path_ + base_len - 4, ".cst") == 0) {
        base_len -= 4;
    }
    g_autofree char *base = g_strndup(output_path_, base_len);
    g_autofree char *bin_path = g_simpoints.is_active()
        ? g_strdup_printf("%s_%s.cst", base, label)
        : g_strdup_printf("%s.cst", base);
    current_->bin_file = fopen(bin_path, "wb");
    if (!current_->bin_file) {
        fprintf(stderr, "champsim_tracer: cannot open binary output: %s\n",
                bin_path);
        return;
    }
    current_->writer = writer_start(current_->bin_file, false);
    current_->bin_stream =
        body_stream_new(current_->writer, current_->start_datetime,
                        current_->start_insn, warmup_insns,
                        total_target_insns, regfile);
    if (!current_->bin_stream) {
        fprintf(stderr,
                "champsim_tracer: cannot initialize binary stream\n");
    }
}

void TraceSegmentManager::start(const char *label,
                                uint64_t start, uint64_t stop,
                                uint64_t warmup_insns,
                                uint64_t total_target_insns,
                                const std::vector<InitialRegSnap> *regfile)
{
    if (current_) {
        segment_free(current_);
    }
    current_ = segment_new(label, start, stop);
    current_->body_seq_num = 0;

    {
        time_t now = time(nullptr);
        struct tm tm_buf;
        localtime_r(&now, &tm_buf);
        strftime(current_->start_datetime, sizeof(current_->start_datetime),
                 "%Y-%m-%d %H:%M:%S", &tm_buf);
    }

    open_output(label, warmup_insns, total_target_insns, regfile);

    active_ = true;
    active_atomic_.store(1);
}

void TraceSegmentManager::finish(const std::function<void()> &flush_hook)
{
    if (!current_) {
        return;
    }

    active_ = false;
    active_atomic_.store(0);

    if (flush_hook) {
        flush_hook();
    }

    if (current_->bin_stream) {
        body_stream_finish(current_->bin_stream);
    }

    segment_free(current_);
    current_ = nullptr;
}
