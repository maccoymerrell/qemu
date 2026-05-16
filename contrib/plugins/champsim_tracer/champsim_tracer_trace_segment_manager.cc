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
    if (current_) {
        segment_free(current_);
    }
    g_free(output_path_);
    g_free(compress_cmd_);
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

/* Map a compression command to the file-extension suffix the
 * resulting bytes should carry inside the tar.  Recognises zstd,
 * xz, gzip; otherwise returns "" and the member is named without a
 * codec suffix (the consumer would have to know how to decompress
 * by other means — strongly discouraged for unknown codecs). */
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
        int rc = pclose(f);
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
    /* Body writer: drain the async queue and join the thread BEFORE
     * closing the underlying FILE*, so enqueued bytes hit the
     * compression pipe / disk cleanly. */
    if (seg->body_writer) {
        writer_finish(seg->body_writer);
        seg->body_writer = nullptr;
    }
    close_member_file(seg->body_file, seg->body_is_pipe, "body");
    seg->body_file = nullptr;
    /* Header writer is synchronous; finish() already closed it. */
    close_member_file(seg->header_file, seg->header_is_pipe, "header");
    seg->header_file = nullptr;
    /* Leave the temp files in place if they exist — finish() unlinks
     * them only on the success path so a partial / abandoned segment
     * leaves the debris on disk for postmortem. */
    g_free(seg->body_temp_path);
    g_free(seg->body_member_name);
    g_free(seg->header_temp_path);
    g_free(seg->header_member_name);
    g_free(seg->outfile_path);
    g_free(seg->label);
    g_free(seg);
}

/* Open a per-member output sink.  If @compress_cmd is non-null,
 * spawn a popen pipe whose stdout is redirected (by the shell into
 * the parent command line) to write @temp_path; otherwise just
 * fopen(@temp_path).  Returns the FILE* (caller closes via
 * close_member_file with the matching @*is_pipe flag).
 *
 * The popen recipe is `<compress_cmd> > <temp_path>` — we let the
 * shell handle the redirect so any flags / options inside
 * compress_cmd (like "-3 -T0") flow through verbatim. */
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
     * Output destination: each segment becomes a single outer .cst
     * tarball.  Inside that ustar archive sit two regular-file
     * members:
     *
     *     body.cst[.<codec>]    streamed body bytes
     *     header.cst[.<codec>]  buffered header + templates
     *
     * Each member is independently piped through compress_cmd_ (if
     * set) into a temp file alongside the user's outfile.  At
     * finish() we close both temp files and assemble them into the
     * final tarball via cst_tar_pack, then unlink the temp files.
     */
    if (!output_path_) {
        return;
    }

    /* Strip a trailing ".cst" before appending segment labels and
     * the extension, so a user passing ``outfile=mcf.cst`` gets
     * ``mcf.cst`` (single segment) or ``mcf-734B.cst`` (per-simpoint,
     * label = simpoint position in billions of insns) rather than
     * ``mcf.cst.cst`` / ``mcf.cst-734B.cst``. */
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
            if (n && fwrite(header_bytes->data, 1, n,
                             current_->header_file) != n) {
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
