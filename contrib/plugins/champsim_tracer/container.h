/*
 * ChampSim Tracer - the .cst container: a two-member POSIX ustar archive.
 *
 * Copyright (C) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef CHAMPSIM_TRACER_CONTAINER_H
#define CHAMPSIM_TRACER_CONTAINER_H

#include <cstdint>
#include <string>
#include <vector>

namespace cst {

struct Member {
    std::string name;               /* "body.cst" / "header.cst" (+ codec) */
    std::vector<uint8_t> bytes;
};

/*
 * Stream @m through the shell command @filter (the compress= option) and
 * rename it after the codec its output actually is (File Layout: the
 * member's suffix names its payload).  An output whose codec cannot be
 * named is an error: a reader dispatches on the suffix and could not
 * decode it.  @scratch_dir holds the unlinked staging files.
 */
bool filter_member(Member &m, const std::string &filter,
                   const std::string &scratch_dir, std::string &err);

/*
 * Write the archive to @path, all or nothing: the bytes go to a sibling
 * staging file, are flushed to disk, and only then renamed onto @path, so
 * a reader never observes a torn container.
 */
bool publish_archive(const std::string &path,
                     const std::vector<Member> &members, std::string &err);

} /* namespace cst */

#endif
