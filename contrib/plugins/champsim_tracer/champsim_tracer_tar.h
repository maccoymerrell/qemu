/*
 * Minimal POSIX-ustar archive writer for the champsim_tracer split-
 * file output format.
 *
 * The plugin emits each segment as a single .cst file that is, on
 * the wire, an uncompressed tar archive containing exactly two
 * regular-file members:
 *
 *   body.cst[.<codec>]      streamed body content
 *   header.cst[.<codec>]    self-contained header (templates etc.)
 *
 * The `.<codec>` suffix is present when the user passed
 * compress=<cmd> and the per-member byte stream was piped through
 * that command before landing on disk.  Decoders dispatch
 * decompression off the suffix.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_TAR_H
#define CHAMPSIM_TRACER_TAR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Concatenate @body_src and @header_src into a POSIX-ustar archive
 * at @out_path.  Each member is appended with the supplied tar-
 * member name (which the segment manager pre-computes including the
 * compression suffix).
 *
 * Returns true on success.  On failure prints a diagnostic and
 * returns false; the partial @out_path is left in place for
 * postmortem inspection.
 */
bool cst_tar_pack(const char *out_path,
                  const char *body_src_path,   const char *body_member_name,
                  const char *header_src_path, const char *header_member_name);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* CHAMPSIM_TRACER_TAR_H */
