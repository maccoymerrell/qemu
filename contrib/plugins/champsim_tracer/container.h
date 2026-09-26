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
#include <type_traits>
#include <vector>

namespace cst {

struct Member {
    std::string name;               /* "body.cst" / "header.cst" (+ codec) */
    std::vector<uint8_t> bytes;
    int fd = -1;                    /* >= 0: the payload is this file, owned */
};

bool write_all(int fd, const uint8_t *p, size_t n);

/* An anonymous file in @dir: created, then unlinked at once. */
int scratch_fd(const std::string &dir);

/*
 * An append-only array of fixed-size records in a named file.  What grows
 * with a run's length lives on disk, never in RAM: "Buffering the entire
 * trace inside the plugin is unacceptable ... It should be streaming to
 * disk." (maintainer, 2026-09-25).  RAM holds a 1 MiB write tail and a
 * 1 MiB read window; a record stays patchable by index wherever it is.
 * A failed read or write latches failed(): the close refuses the trace.
 */
class SpillFile {
public:
    explicit SpillFile(size_t rec) : rec_(rec), cap_((1u << 20) / rec) {}
    bool open(const std::string &path);
    void remove();                      /* close and unlink */
    void fork_child();                  /* a forked child takes its own copy */
    size_t size() const { return n_; }
    bool failed() const { return bad_; }
    /* @n records at @i: i == size() appends them, else patches (n == 1) */
    void put(size_t i, const void *rec, size_t n = 1);
    void get(size_t i, void *rec, size_t n = 1) const;  /* i + n <= size() */

private:
    size_t rec_, cap_, n_ = 0, disk_ = 0;   /* [0, disk_) is in the file */
    int fd_ = -1;
    std::string path_;
    std::vector<uint8_t> tail_;             /* records [disk_, n_) */
    mutable std::vector<uint8_t> win_;      /* records [win0_, win0_ + winn_) */
    mutable size_t win0_ = 0, winn_ = 0;
    mutable bool bad_ = false;
};

template <typename T> class Spill : public SpillFile {
    static_assert(std::is_trivially_copyable<T>::value, "a record is its bytes");
public:
    Spill() : SpillFile(sizeof(T)) {}
    void push_back(const T &v) { put(size(), &v); }
    void set(size_t i, const T &v) { put(i, &v); }
    T operator[](size_t i) const { T v; get(i, &v); return v; }
    T back() const { return (*this)[size() - 1]; }
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
 * staging file (<path>.part.<pid>), are flushed to disk, and only then
 * renamed onto @path, so a reader never observes a torn container.  A
 * member past the ustar size field (8 GiB) is refused, not truncated.
 */
bool publish_archive(const std::string &path,
                     const std::vector<Member> &members, std::string &err);

} /* namespace cst */

#endif
