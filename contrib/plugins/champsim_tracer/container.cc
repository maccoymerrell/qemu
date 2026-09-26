/*
 * ChampSim Tracer - the .cst container: a two-member POSIX ustar archive.
 *
 * Copyright (C) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "container.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>

#include <fcntl.h>
#include <spawn.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

namespace cst {

namespace {

std::string errno_text(const char *what)
{
    return std::string(what) + ": " + std::strerror(errno);
}

/* pread / pwrite (@off >= 0) or write (@off < 0) all @n bytes */
bool io_all(int fd, uint8_t *p, size_t n, off_t off, bool rd)
{
    while (n) {
        ssize_t w = rd ? pread(fd, p, n, off) : off < 0 ? write(fd, p, n) :
                    pwrite(fd, p, n, off);
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            return false;
        }
        p += w;
        n -= size_t(w);
        off += off < 0 ? 0 : w;
    }
    return true;
}

/* File Layout: the codecs a reader dispatches on, by their stream magic. */
const char *codec_suffix(const uint8_t *b, size_t n)
{
    static const struct { const char *suffix; std::vector<uint8_t> magic; }
    codecs[] = {
        { ".zst", { 0x28, 0xb5, 0x2f, 0xfd } },
        { ".xz", { 0xfd, '7', 'z', 'X', 'Z', 0x00 } },
        { ".gz", { 0x1f, 0x8b } },
        { ".bz2", { 'B', 'Z', 'h' } },
        { ".lz4", { 0x04, 0x22, 0x4d, 0x18 } },
    };
    for (const auto &c : codecs) {
        if (n >= c.magic.size() && std::equal(c.magic.begin(), c.magic.end(), b)) {
            return c.suffix;
        }
    }
    return nullptr;
}

/* One ustar header block for a regular file. */
void ustar_header(uint8_t blk[512], const std::string &name, size_t size)
{
    std::memset(blk, 0, 512);
    std::memcpy(blk, name.data(), name.size());          /* name[100] */
    std::snprintf((char *)blk + 100, 8, "%07o", 0644);    /* mode */
    std::snprintf((char *)blk + 108, 8, "%07o", 0);       /* uid */
    std::snprintf((char *)blk + 116, 8, "%07o", 0);       /* gid */
    std::snprintf((char *)blk + 124, 12, "%011llo", (unsigned long long)size);
    std::snprintf((char *)blk + 136, 12, "%011llo",
                  (unsigned long long)std::time(nullptr));
    blk[156] = '0';                                       /* typeflag */
    std::memcpy(blk + 257, "ustar", 6);                   /* magic */
    std::memcpy(blk + 263, "00", 2);                      /* version */
    std::memset(blk + 148, ' ', 8);                       /* chksum */
    unsigned sum = 0;
    for (int i = 0; i < 512; i++) {
        sum += blk[i];
    }
    std::snprintf((char *)blk + 148, 8, "%06o", sum);     /* NUL, then ' ' */
}

} /* namespace */

bool write_all(int fd, const uint8_t *p, size_t n)
{
    return io_all(fd, const_cast<uint8_t *>(p), n, -1, false);
}

int scratch_fd(const std::string &dir)
{
    std::string tmpl = dir + "/.cst_member.XXXXXX";
    int fd = mkstemp(&tmpl[0]);
    if (fd >= 0) {
        unlink(tmpl.c_str());
    }
    return fd;
}

bool SpillFile::open(const std::string &path)
{
    path_ = path;
    fd_ = ::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
    return fd_ >= 0;
}

void SpillFile::remove()
{
    if (fd_ >= 0) {
        close(fd_);
        unlink(path_.c_str());
    }
    fd_ = -1;
    tail_ = {};
    win_ = {};
}

/*
 * After fork() the file is shared with the parent, which goes on writing
 * it: the child copies what is on disk and continues in the copy, as it
 * continues in its copy of RAM.
 */
void SpillFile::fork_child()
{
    if (fd_ < 0) {
        return;
    }
    std::string path = path_ + "." + std::to_string(getpid());
    int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
    loff_t in = 0, out = 0;
    size_t left = disk_ * rec_;
    while (fd >= 0 && left) {
        ssize_t c = copy_file_range(fd_, &in, fd, &out, left, 0);
        if (c <= 0) {
            break;
        }
        left -= size_t(c);
    }
    bad_ |= fd < 0 || left;
    close(fd_);
    fd_ = fd;
    path_ = path;
}

void SpillFile::put(size_t i, const void *rec, size_t n)
{
    auto *b = static_cast<const uint8_t *>(rec);
    if (i < disk_) {
        bad_ |= !io_all(fd_, const_cast<uint8_t *>(b), rec_, off_t(i * rec_), false);
        if (i >= win0_ && i < win0_ + winn_) {
            std::memcpy(&win_[(i - win0_) * rec_], b, rec_);
        }
    } else if (i < n_) {
        std::memcpy(&tail_[(i - disk_) * rec_], b, rec_);
    } else {
        tail_.insert(tail_.end(), b, b + n * rec_);
        n_ += n;
        if (n_ - disk_ >= cap_) {
            bad_ |= fd_ < 0 ||
                    !io_all(fd_, tail_.data(), tail_.size(), off_t(disk_ * rec_), false);
            disk_ = n_;
            tail_.clear();
        }
    }
}

void SpillFile::get(size_t i, void *rec, size_t n) const
{
    auto *o = static_cast<uint8_t *>(rec);
    while (n) {
        if (i < disk_ && (i < win0_ || i >= win0_ + winn_)) {
            win0_ = i > cap_ / 8 ? i - cap_ / 8 : 0;    /* a little behind @i */
            winn_ = std::min(cap_, disk_ - win0_);
            win_.resize(winn_ * rec_);
            if (!io_all(fd_, win_.data(), win_.size(), off_t(win0_ * rec_), true)) {
                bad_ = true;
                winn_ = 0;
                std::memset(o, 0, n * rec_);
                return;
            }
        }
        const uint8_t *src = i < disk_ ? &win_[(i - win0_) * rec_] :
                             &tail_[(i - disk_) * rec_];
        size_t k = std::min(n, i < disk_ ? win0_ + winn_ - i : n_ - i);
        std::memcpy(o, src, k * rec_);
        o += k * rec_;
        i += k;
        n -= k;
    }
}

bool filter_member(Member &m, const std::string &filter,
                   const std::string &scratch_dir, std::string &err)
{
    /*
     * The filter reads a file and writes a file: no pipe, so no SIGPIPE
     * and no deadlock between our writes and its output, whatever it does.
     */
    int in = m.fd >= 0 ? m.fd : scratch_fd(scratch_dir), out = scratch_fd(scratch_dir);
    bool ok = in >= 0 && out >= 0 &&
              (m.fd >= 0 || write_all(in, m.bytes.data(), m.bytes.size())) &&
              lseek(in, 0, SEEK_SET) == 0;
    if (!ok) {
        err = errno_text("compress staging");
    }
    int status = -1;
    if (ok) {
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_adddup2(&fa, in, 0);
        posix_spawn_file_actions_adddup2(&fa, out, 1);
        const char *argv[] = { "sh", "-c", filter.c_str(), nullptr };
        pid_t pid;
        int rc = posix_spawn(&pid, "/bin/sh", &fa, nullptr,
                             const_cast<char **>(argv), environ);
        posix_spawn_file_actions_destroy(&fa);
        if (rc != 0) {
            errno = rc;
            err = errno_text("compress spawn");
            ok = false;
        } else {
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
            }
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                err = "compress command '" + filter + "' failed (status " +
                      std::to_string(status) + ")";
                ok = false;
            }
        }
    }
    uint8_t head[8];
    ssize_t got = ok ? pread(out, head, sizeof(head), 0) : 0;
    const char *suffix = got > 0 ? codec_suffix(head, size_t(got)) : nullptr;
    if (ok && !suffix) {
        err = "compress command '" + filter +
              "' produced no codec a reader can dispatch on";
        ok = false;
    }
    if (ok) {           /* the member is the output now; its input is done */
        m.name += suffix;
        m.bytes = {};
        m.fd = out;
        out = -1;
    } else if (in == m.fd) {
        in = -1;        /* still the member's */
    }
    if (in >= 0) {
        close(in);
    }
    if (out >= 0) {
        close(out);
    }
    return ok;
}

bool publish_archive(const std::string &path,
                     const std::vector<Member> &members, std::string &err)
{
    /* per process: a forked child closes its own segment onto @path too */
    std::string staging = path + ".part." + std::to_string(getpid());
    int fd = open(staging.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        err = errno_text(staging.c_str());
        return false;
    }
    static const uint8_t zeros[1024] = {};
    bool ok = true;
    std::vector<uint8_t> chunk(1u << 20);
    for (const Member &m : members) {
        struct stat st;
        size_t size = m.fd < 0 ? m.bytes.size() :
                      fstat(m.fd, &st) == 0 ? size_t(st.st_size) : 0;
        if (ok && size > 077777777777ull) {
            err = m.name + " is " + std::to_string(size) +
                  " bytes, past the ustar size field";
            ok = false;
        }
        uint8_t blk[512];
        ustar_header(blk, m.name, size);
        ok = ok && write_all(fd, blk, sizeof(blk)) &&
             write_all(fd, m.bytes.data(), m.bytes.size());
        for (size_t at = 0; ok && m.fd >= 0 && at < size; at += chunk.size()) {
            size_t n = std::min(chunk.size(), size - at);
            ok = io_all(m.fd, chunk.data(), n, off_t(at), true) &&
                 write_all(fd, chunk.data(), n);
        }
        ok = ok && write_all(fd, zeros, (512 - size % 512) % 512);
    }
    ok = ok && write_all(fd, zeros, sizeof(zeros));      /* end of archive */
    ok = ok && fsync(fd) == 0;
    if (!ok && err.empty()) {
        err = errno_text(staging.c_str());
    }
    if (close(fd) != 0 && ok) {
        err = errno_text(staging.c_str());
        ok = false;
    }
    if (ok && rename(staging.c_str(), path.c_str()) != 0) {
        err = errno_text(path.c_str());
        ok = false;
    }
    if (!ok) {
        unlink(staging.c_str());
    }
    return ok;
}

} /* namespace cst */
