/*
 * cst_attach — run an unmodified target so the ChampSim Tracer can attach.
 *
 * The plugin opens its trace window when it observes the marker sequence
 * (champsim_marker.h) execute, and pins the window to the address space the
 * marker runs in.  The marker therefore has to execute inside the target's
 * own address space.  This launcher gets it there for an arbitrary,
 * unmodified, statically- OR dynamically-linked binary by injecting it at
 * the entry point right after execve, via ptrace:
 *
 *   fork; child: PTRACE_TRACEME, execvp(target)
 *   parent: wait for the exec-stop  (target now mapped, stopped at its first
 *           userspace instruction, IN ITS OWN address space)
 *           save the bytes at the entry PC; poke the marker sequence there
 *           single-step the whole sequence  -> plugin observes it, pins ASID
 *           restore the original bytes and the PC; detach
 *           target runs from its real entry, on-disk binary never touched
 *
 * Why ptrace and not LD_PRELOAD: a preload-constructor only works for
 * dynamic binaries (no loader runs a static one), whereas ptrace reaches
 * into the post-execve image regardless of linkage.  Why not a launcher
 * that runs the marker then execs the target: execve replaces the address
 * space, so the marker's ASID would be the launcher's, not the target's.
 *
 * Portability: the injector is the only OS/arch-specific piece, isolated
 * behind inject_marker_at_entry().  Today: Linux + x86/x86-64 (ptrace).
 * Other guests are a new backend (Windows debug API, macOS Mach, BSD
 * ptrace) + a per-arch marker encoding in champsim_marker.h — not a
 * redesign.  Unsupported host/arch combinations fail loudly at build or
 * run rather than silently mis-attaching.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../champsim_marker.h"

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#define CST_ATTACH_SUPPORTED 1
#else
#define CST_ATTACH_SUPPORTED 0
#endif

#if CST_ATTACH_SUPPORTED

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/personality.h>
#include <unistd.h>

/* ptrace POKETEXT/PEEKTEXT operate on word granularity. */
typedef unsigned long cst_word;
#define CST_WORD sizeof(cst_word)

/* Read @len bytes at guest address @addr from the traced child @pid. */
static int peek_bytes(pid_t pid, unsigned long addr, uint8_t *buf, size_t len)
{
    for (size_t off = 0; off < len; off += CST_WORD) {
        errno = 0;
        long w = ptrace(PTRACE_PEEKTEXT, pid, addr + off, 0);
        if (w == -1 && errno) {
            return -1;
        }
        size_t n = (len - off < CST_WORD) ? len - off : CST_WORD;
        memcpy(buf + off, &w, n);
    }
    return 0;
}

/* Write @len bytes to guest address @addr in the traced child @pid,
 * preserving the bytes beyond @len within the final partial word. */
static int poke_bytes(pid_t pid, unsigned long addr, const uint8_t *buf,
                      size_t len)
{
    for (size_t off = 0; off < len; off += CST_WORD) {
        cst_word w;
        size_t n = (len - off < CST_WORD) ? len - off : CST_WORD;
        if (n < CST_WORD) {
            /* Partial trailing word: read-modify-write so we don't clobber
             * the instruction bytes that follow the injection site. */
            errno = 0;
            long cur = ptrace(PTRACE_PEEKTEXT, pid, addr + off, 0);
            if (cur == -1 && errno) {
                return -1;
            }
            w = (cst_word)cur;
        }
        memcpy(&w, buf + off, n);
        if (ptrace(PTRACE_POKETEXT, pid, addr + off, (void *)w) == -1) {
            return -1;
        }
    }
    return 0;
}

/*
 * Inject + single-step the marker sequence at the target's entry, then
 * restore.  At the exec-stop the child is at its first userspace
 * instruction in its own address space; the marker runs there, so the
 * plugin pins to the target's ASID.  Returns 0 on success.
 */
static int inject_marker_at_entry(pid_t pid)
{
    struct user_regs_struct regs, saved_regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        perror("cst_attach: PTRACE_GETREGS");
        return -1;
    }
    saved_regs = regs;
#if defined(__x86_64__)
    unsigned long entry = regs.rip;
#else
    unsigned long entry = regs.eip;
#endif

    uint8_t marker[CST_MARKER_X86_SEQ_BYTES];
    cst_marker_x86_encode_seq(marker);

    uint8_t orig[CST_MARKER_X86_SEQ_BYTES];
    if (peek_bytes(pid, entry, orig, sizeof(orig)) != 0) {
        perror("cst_attach: read entry bytes");
        return -1;
    }
    if (poke_bytes(pid, entry, marker, sizeof(marker)) != 0) {
        perror("cst_attach: write marker");
        return -1;
    }

    /* Single-step exactly the marker insns so the plugin observes the full
     * sequence execute (and arms/pins on the last).  Each is a 5-byte
     * `mov $imm,%eax`; CST_MARKER_SEQ_LEN steps cover them. */
    for (unsigned i = 0; i < CST_MARKER_SEQ_LEN; i++) {
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1) {
            perror("cst_attach: PTRACE_SINGLESTEP");
            return -1;
        }
        int status;
        if (waitpid(pid, &status, 0) < 0) {
            perror("cst_attach: waitpid(singlestep)");
            return -1;
        }
        if (WIFEXITED(status)) {
            fprintf(stderr, "cst_attach: target exited during marker step\n");
            return -1;
        }
    }

    /* Restore the original entry bytes and rewind the PC so the target
     * runs from its real first instruction, fully intact. */
    if (poke_bytes(pid, entry, orig, sizeof(orig)) != 0) {
        perror("cst_attach: restore entry bytes");
        return -1;
    }
    if (ptrace(PTRACE_SETREGS, pid, 0, &saved_regs) == -1) {
        perror("cst_attach: PTRACE_SETREGS");
        return -1;
    }
    return 0;
}

static int run(char **argv)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("cst_attach: fork");
        return 1;
    }
    if (pid == 0) {
        /* Child: become traceable, drop ASLR so the entry / stack are
         * reproducible (matches the tracer's setarch -R guidance), exec. */
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
            perror("cst_attach: PTRACE_TRACEME");
            _exit(127);
        }
        personality(ADDR_NO_RANDOMIZE);
        execvp(argv[0], argv);
        perror("cst_attach: execvp");
        _exit(127);
    }

    /* Parent: first stop is the exec-stop (target mapped, at its entry, in
     * its own address space). */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("cst_attach: waitpid(exec-stop)");
        return 1;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "cst_attach: target did not stop at exec\n");
        return 1;
    }

    if (inject_marker_at_entry(pid) != 0) {
        ptrace(PTRACE_KILL, pid, 0, 0);
        return 1;
    }

    /* Detach and let the target run to completion under the tracer. */
    if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
        perror("cst_attach: PTRACE_DETACH");
        return 1;
    }
    if (waitpid(pid, &status, 0) < 0) {
        perror("cst_attach: waitpid(target)");
        return 1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

#endif /* CST_ATTACH_SUPPORTED */

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "usage: cst_attach <target> [args...]\n"
            "\n"
            "Runs <target>, injecting the ChampSim Tracer marker at its\n"
            "entry point so the plugin attaches and pins to its address\n"
            "space.  Intended to run under qemu(-system) with the plugin\n"
            "loaded in trace_window=marker mode.\n");
        return 2;
    }
#if CST_ATTACH_SUPPORTED
    return run(argv + 1);
#else
    fprintf(stderr,
        "cst_attach: unsupported host/arch (need Linux + x86/x86-64).\n"
        "The ptrace injector is the only platform-specific piece; add a\n"
        "backend in this file + a marker encoding in champsim_marker.h.\n");
    (void)argv;
    return 3;
#endif
}
