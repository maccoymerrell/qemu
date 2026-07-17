/*
 * Wrong-Path Tracing Plugin — human-readable statistics report formatting.
 *
 * Formats a Stats aggregate (and an optional per-interval histogram) into
 * the textual end-of-segment / cumulative report.  Pure formatting: reads
 * Stats plus the process-wide target_name / max_wrong_path_depth; owns no
 * mutable plugin state.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_STATS_REPORT_H
#define CHAMPSIM_TRACER_STATS_REPORT_H

#include <vector>

#include <glib.h>

#include "champsim_tracer_stats.h"

/* Appends a formatted summary of @stats to @report. */
void append_stats_summary(GString *report, const char *label,
                          const Stats &stats);

/* Appends a per-interval breakdown of @buckets to @report.  No-op
 * when @buckets is empty. */
void append_histogram(GString *report, const char *segment_label,
                      const std::vector<Stats> &buckets,
                      uint64_t segment_start,
                      uint64_t interval_size);

#endif /* CHAMPSIM_TRACER_STATS_REPORT_H */
