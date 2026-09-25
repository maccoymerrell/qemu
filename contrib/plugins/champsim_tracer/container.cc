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

bool write_all(int fd, const uint8_t *p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            return false;
        }
        p += w;
        n -= size_t(w);
    }
    return true;
}

/* An anonymous file in @dir: created, then unlinked at once. */
int scratch_fd(const std::string &dir)
{
    std::string tmpl = dir + "/.cst_member.XXXXXX";
    int fd = mkstemp(&tmpl[0]);
    if (fd >= 0) {
        unlink(tmpl.c_str());
    }
    return fd;
}

/* File Layout: the codecs a reader dispatches on, by their stream magic. */
const char *codec_suffix(const std::vector<uint8_t> &b)
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
        if (b.size() >= c.magic.size() &&
            std::equal(c.magic.begin(), c.magic.end(), b.begin())) {
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

bool filter_member(Member &m, const std::string &filter,
                   const std::string &scratch_dir, std::string &err)
{
    /*
     * The filter reads a file and writes a file: no pipe, so no SIGPIPE
     * and no deadlock between our writes and its output, whatever it does.
     */
    int in = scratch_fd(scratch_dir), out = scratch_fd(scratch_dir);
    bool ok = in >= 0 && out >= 0 &&
              write_all(in, m.bytes.data(), m.bytes.size()) &&
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
    std::vector<uint8_t> packed;
    if (ok) {
        struct stat st;
        ok = fstat(out, &st) == 0 && lseek(out, 0, SEEK_SET) == 0;
        packed.resize(ok ? size_t(st.st_size) : 0);
        size_t got = 0;
        while (ok && got < packed.size()) {
            ssize_t r = read(out, packed.data() + got, packed.size() - got);
            if (r < 0 && errno == EINTR) {
                continue;
            }
            ok = r > 0;
            got += ok ? size_t(r) : 0;
        }
        if (!ok) {
            err = errno_text("compress readback");
        }
    }
    const char *suffix = ok ? codec_suffix(packed) : nullptr;
    if (ok && !suffix) {
        err = "compress command '" + filter +
              "' produced no codec a reader can dispatch on";
        ok = false;
    }
    if (ok) {
        m.name += suffix;
        m.bytes.swap(packed);
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
    std::string staging = path + ".part";
    int fd = open(staging.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        err = errno_text(staging.c_str());
        return false;
    }
    static const uint8_t zeros[1024] = {};
    bool ok = true;
    for (const Member &m : members) {
        uint8_t blk[512];
        ustar_header(blk, m.name, m.bytes.size());
        size_t pad = (512 - m.bytes.size() % 512) % 512;
        ok = ok && write_all(fd, blk, sizeof(blk)) &&
             write_all(fd, m.bytes.data(), m.bytes.size()) &&
             write_all(fd, zeros, pad);
    }
    ok = ok && write_all(fd, zeros, sizeof(zeros));      /* end of archive */
    ok = ok && fsync(fd) == 0;
    if (!ok) {
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
