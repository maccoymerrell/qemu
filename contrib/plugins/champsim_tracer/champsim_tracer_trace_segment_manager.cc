/*
 * Wrong-Path Tracing Plugin — trace segment lifecycle implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "champsim_tracer_simpoint_manager.h"
#include "champsim_tracer_tar.h"
#include "champsim_tracer_trace_segment_manager.h"
#include "champsim_tracer_writer.h"

TraceSegmentManager g_trace_segments;

TraceSegmentManager::~TraceSegmentManager()
{
    /*
     * Intentionally a no-op.  g_trace_segments is a process-lifetime
     * global, so this destructor runs as a C++ static destructor at
     * process teardown.  Its ordering versus QEMU's libc-registered
     * atexit handler that fires our QEMU_PLUGIN_EV_ATEXIT callback
     * (plugin_exit -> finish_trace_segment -> TraceSegmentManager::finish)
     * is not guaranteed.
     *
     * In system-emulation teardown (qemu_default_main -> exit) this
     * destructor runs *before* plugin_exit.  Freeing current_ here
     * therefore (a) left plugin_exit's finish() walking a freed segment
     * whose temp-path strings had been reused -> cst_tar stat()/open()
     * failures on a garbage path and a double free at segment_free, and
     * (b) freed compress_cmd_, which finish() still reads to open the
     * header sink.  In linux-user the order was the reverse, masking the
     * bug.  plugin_exit is the authoritative finalize hook and runs while
     * this manager is still valid in both modes; it frees the segment and
     * nulls current_.  Anything not finalized by then is a single
     * allocation reclaimed by the OS at exit, so leaving teardown to
     * plugin_exit removes the ordering dependency entirely.
     */
}

void TraceSegmentManager::set_output_path(const char *path)
{
    g_free(output_path_);
    output_path_ = path ? g_strdup(path) : nullptr;
}

void TraceSegmentManager::set_compress_cmd(const char *cmd)
{
    g_free(compress_cmd_);
    compress_cmd_ = (cmd && *cmd) ? g_strdup(cmd) : nullptr;
}

/* Map a compression command to the file-extension suffix its bytes
 * carry inside the tar.  Unknown utilities return "" (no suffix). */
static const char *compress_suffix(const char *cmd)
{
    if (!cmd || !*cmd) {
        return "";
    }
    /* Look at the leading whitespace-delimited token. */
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    const char *end = cmd;
    while (*end && *end != ' ' && *end != '\t') end++;
    size_t n = (size_t)(end - cmd);
    /* Match on the basename of the program token. */
    const char *base = cmd;
    for (size_t i = 0; i < n; i++) {
        if (cmd[i] == '/') base = cmd + i + 1;
    }
    size_t blen = (size_t)(end - base);
    auto eq = [&](const char *s) {
        return strlen(s) == blen && memcmp(base, s, blen) == 0;
    };
    if (eq("zstd"))  return ".zst";
    if (eq("xz"))    return ".xz";
    if (eq("gzip"))  return ".gz";
    if (eq("bzip2")) return ".bz2";
    if (eq("lz4"))   return ".lz4";
    /* Unknown utility — keep the bytes as-is, no extension. */
    return "";
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

/* Close a member's FILE* (pipe or regular).  Returns true on
 * success.  For pipes, a non-zero child exit code is logged. */
static bool close_member_file(FILE *f, bool is_pipe, const char *label)
{
    if (!f) {
        return true;
    }
    if (is_pipe) {
        /* pclose waits for the compressor to EXIT.  A compressor that has
         * taken every byte and then never finishes parks the close here,
         * after the writer drain has already returned -- the same silence,
         * one step further on.  Watched, for the same reason. */
        void *watch = sink_stall_watch_begin(
            "the close waiting for the compression pipe to exit");
        int rc = pclose(f);
        sink_stall_watch_end(watch);
        if (rc != 0) {
            fprintf(stderr,
                    "champsim_tracer: %s compression pipe exited with status %d\n",
                    label, rc);
            return false;
        }
        return true;
    }
    return fclose(f) == 0;
}

void TraceSegmentManager::segment_free(TraceSegment *seg)
{
    if (!seg) {
        return;
    }
    if (seg->bin_stream) {
        body_stream_free(seg->bin_stream);
        seg->bin_stream = nullptr;
    }
    /* Drain + join the async body writer BEFORE closing its FILE*, so
     * enqueued bytes hit the pipe/disk cleanly. */
    if (seg->body_writer) {
        writer_finish(seg->body_writer);
        seg->body_writer = nullptr;
    }
    close_member_file(seg->body_file, seg->body_is_pipe, "body");
    seg->body_file = nullptr;
    /* Header writer is synchronous; finish() already closed it. */
    close_member_file(seg->header_file, seg->header_is_pipe, "header");
    seg->header_file = nullptr;
    /* Temp files are unlinked only on finish()'s success path; an
     * abandoned segment leaves them for postmortem. */
    g_free(seg->body_temp_path);
    g_free(seg->body_member_name);
    g_free(seg->header_temp_path);
    g_free(seg->header_member_name);
    g_free(seg->outfile_path);
    g_free(seg->label);
    g_free(seg);
}

/* Open a per-member output sink.  With @compress_cmd, popen the
 * recipe `<compress_cmd> > <temp_path>` (shell handles the redirect
 * so flags like "-3 -T0" pass through verbatim); otherwise fopen
 * @temp_path.  Caller closes via close_member_file with the matching
 * @*is_pipe flag. */
static FILE *open_member_sink(const char *temp_path,
                              const char *compress_cmd,
                              bool *out_is_pipe,
                              const char *member_label)
{
    if (compress_cmd && *compress_cmd) {
        g_autofree char *quoted_path = g_shell_quote(temp_path);
        g_autofree char *cmd = g_strdup_printf("%s > %s",
                                               compress_cmd, quoted_path);
        FILE *f = popen(cmd, "w");
        if (!f) {
            fprintf(stderr,
                    "champsim_tracer: cannot open %s compression pipe: %s\n",
                    member_label, cmd);
            return nullptr;
        }
        *out_is_pipe = true;
        return f;
    }
    FILE *f = fopen(temp_path, "wb");
    if (!f) {
        fprintf(stderr, "champsim_tracer: cannot open %s output: %s\n",
                member_label, temp_path);
        return nullptr;
    }
    *out_is_pipe = false;
    return f;
}

void TraceSegmentManager::open_output(const char *label,
                                      uint64_t warmup_insns,
                                      uint64_t total_target_insns,
                                      uint32_t seed_thread_id,
                                      double simpoint_weight,
                                      const std::vector<InitialRegSnap> *regfile)
{
    /*
     * Each segment is one outer .cst ustar tarball with two members:
     *   body.cst[.<codec>]    streamed body bytes
     *   header.cst[.<codec>]  buffered header + templates
     * Each member is independently piped through compress_cmd_ into a
     * temp file; finish() assembles them via cst_tar_pack then unlinks
     * the temps.
     */
    if (!output_path_) {
        return;
    }

    /* Strip a trailing ".cst" before re-appending label + extension,
     * so outfile=mcf.cst yields mcf.cst (single) or mcf-734B.cst
     * (per-simpoint) rather than mcf.cst.cst. */
    size_t base_len = strlen(output_path_);
    if (base_len >= 4 &&
        strcmp(output_path_ + base_len - 4, ".cst") == 0) {
        base_len -= 4;
    }
    g_autofree char *base = g_strndup(output_path_, base_len);
    g_autofree char *outfile_path = g_simpoints.is_active()
        ? g_strdup_printf("%s-%s.cst", base, label)
        : g_strdup_printf("%s.cst", base);
    const char *ext = compress_suffix(compress_cmd_);

    current_->outfile_path = g_strdup(outfile_path);
    current_->body_temp_path =
        g_strdup_printf("%s.body_tmp%s", outfile_path, ext);
    current_->header_temp_path =
        g_strdup_printf("%s.header_tmp%s", outfile_path, ext);
    current_->body_member_name = g_strdup_printf("body.cst%s", ext);
    current_->header_member_name = g_strdup_printf("header.cst%s", ext);

    /* Open the body sink up front.  The header sink is opened
     * lazily at finish() (after we have the buffered header bytes
     * to drain into it). */
    current_->body_file = open_member_sink(current_->body_temp_path,
                                           compress_cmd_,
                                           &current_->body_is_pipe,
                                           "body");
    if (!current_->body_file) {
        return;
    }
    current_->body_writer = writer_start(current_->body_file,
                                         current_->body_is_pipe);
    current_->bin_stream =
        body_stream_new(current_->body_writer, current_->start_datetime,
                        current_->start_insn, warmup_insns,
                        total_target_insns, seed_thread_id,
                        simpoint_weight, regfile);
    if (!current_->bin_stream) {
        fprintf(stderr,
                "champsim_tracer: cannot initialize binary stream\n");
    }
}

void TraceSegmentManager::start(const char *label,
                                uint64_t start, uint64_t stop,
                                uint64_t warmup_insns,
                                uint64_t total_target_insns,
                                uint32_t seed_thread_id,
                                double simpoint_weight,
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

    open_output(label, warmup_insns, total_target_insns,
                seed_thread_id, simpoint_weight, regfile);

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

    /* Finalise the body member (END marker + trailing magic) and
     * collect the header bytes the encoder buffered up during the
     * segment. */
    GByteArray *header_bytes = nullptr;
    if (current_->bin_stream) {
        body_stream_finish(current_->bin_stream, &header_bytes);
    }

    /* Drain + close the body writer / file so the body temp is
     * fully on disk before we read it back into the tar. */
    if (current_->body_writer) {
        writer_finish(current_->body_writer);
        current_->body_writer = nullptr;
    }
    if (current_->body_file) {
        close_member_file(current_->body_file,
                          current_->body_is_pipe, "body");
        current_->body_file = nullptr;
    }

    /* Write the header buffer to its own temp file (optionally
     * through compression). */
    if (header_bytes && current_->header_temp_path) {
        current_->header_file =
            open_member_sink(current_->header_temp_path, compress_cmd_,
                             &current_->header_is_pipe, "header");
        if (current_->header_file) {
            size_t n = header_bytes->len;
            /* The header goes down its own pipe with no writer thread behind
             * it, so a header sink that stops reading parks the close right
             * here -- the body having already drained perfectly.  Same watch,
             * same progress rule; it used to be the one wait on the sink that
             * said nothing at all. */
            if (n && sink_write_watched(
                        current_->header_file, header_bytes->data, n,
                        "the close writing the header member to its sink")
                     != n) {
                fprintf(stderr,
                        "champsim_tracer: header write failed: %s\n",
                        current_->header_temp_path);
            }
            close_member_file(current_->header_file,
                              current_->header_is_pipe, "header");
            current_->header_file = nullptr;
        }
    }
    if (header_bytes) {
        g_byte_array_unref(header_bytes);
    }

    /* Assemble the outer tarball and clean up temp files. */
    if (current_->outfile_path
        && current_->body_temp_path && current_->header_temp_path
        && cst_tar_pack(current_->outfile_path,
                        current_->body_temp_path,
                        current_->body_member_name,
                        current_->header_temp_path,
                        current_->header_member_name)) {
        /* Success: remove the now-archived temp files. */
        unlink(current_->body_temp_path);
        unlink(current_->header_temp_path);
    } else if (current_->outfile_path) {
        fprintf(stderr,
                "champsim_tracer: tar assembly failed; temp files left "
                "in place: %s, %s\n",
                current_->body_temp_path ? current_->body_temp_path : "(?)",
                current_->header_temp_path ? current_->header_temp_path : "(?)");
    }

    segment_free(current_);
    current_ = nullptr;
}
