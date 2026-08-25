/*
 * ARC 3 -- is this aarch64 encoding REACHABLE by a QEMU guest?
 *
 * The aarch64 memop reference (the Arm MRA execute-ASL) cannot probe 110
 * of the 3,920 opcode subjects: 106 have no MRA instruction page at all
 * (they are post-2022-12 architecture additions that entered the subject
 * list from LLVM MC), and 4 exhaust the ASL interpreter's loop budget.
 * A row a reference cannot probe is a hole in the three-valued split
 * unless the encoding is shown to be UNREACHABLE, which is what this
 * measures: the bytes are written into an executable page and called
 * under qemu-aarch64, where SIGILL is the TCG front end refusing them.
 *
 * Every general register except the frame and link registers is pointed
 * at a mapped, writable scratch page before the call, so a memory
 * operand addresses something real and a SIGSEGV is not read as a
 * refusal.  x30 is left holding the return address so an encoding that
 * turns out to be a return lands back in the harness.
 *
 * Each encoding is executed in a FORKED CHILD and the verdict is taken
 * from waitpid's status, never from a signal handler in the harness: an
 * encoding that turns out to be a branch leaves the handler's siglongjmp
 * unreachable and would otherwise take the whole run down mid-file, which
 * is a silent truncation rather than a measurement.
 *
 * THE ENABLE LEG.  A bare SIGILL also cannot separate "QEMU has no
 * decoder" from "the architectural ENABLE STATE this encoding requires was
 * not established".  The whole SME instruction set is UNDEFINED unless
 * PSTATE.SM and/or PSTATE.ZA are set, and this harness executed every
 * encoding with SVCR = 0, so an `smstart`-gated opcode refused for the
 * PSTATE and not for the opcode.  `--pre` selects the state the child
 * establishes before it calls the encoding:
 *
 *     off      SVCR = 0                    (the original leg, the default)
 *     smstart  SVCR = SM|ZA                (streaming vector + ZA storage)
 *     sm       SVCR = SM
 *     za       SVCR = ZA
 *
 * An encoding is REACHABLE if it runs under ANY legal enable state, so the
 * arms are a UNION and not a replacement: entering streaming mode makes the
 * non-streaming-only SVE forms UNDEFINED in exactly the same way, and the
 * `off` arm is what covers those.  The preamble is executed INSIDE the
 * forked child, so an arm whose own preamble is unsupported dies per row
 * rather than silently scoring the whole file.
 *
 * WHAT THIS STILL CANNOT SEE, and the report must not claim it does: an
 * encoding QEMU implements only at EL1 or above raises SIGILL here for
 * the privilege, not for the opcode.  That is the EL1 leg's question, and
 * `sysreach.S` under qemu-system-aarch64 is the leg that answers it.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* MSR (immediate) to the SVCR PSTATE fields.  Spelled as raw words so the
 * harness builds with a toolchain that predates SME: binutils in this tree
 * rejects `+sme` outright. */
#define SMSTART_SMZA 0xd503477f
#define SMSTART_SM   0xd503437f
#define SMSTART_ZA   0xd503457f

static uint32_t preamble_word(const char *name)
{
    if (!strcmp(name, "off")) {
        return 0;
    }
    if (!strcmp(name, "smstart")) {
        return SMSTART_SMZA;
    }
    if (!strcmp(name, "sm")) {
        return SMSTART_SM;
    }
    if (!strcmp(name, "za")) {
        return SMSTART_ZA;
    }
    fprintf(stderr, "unknown --pre arm '%s'\n", name);
    exit(2);
}

int main(int argc, char **argv)
{
    char line[64];
    int caught;
    const char *pre_name = "off";
    uint32_t pre = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "--pre=", 6)) {
            pre_name = argv[i] + 6;
        } else {
            fprintf(stderr, "usage: reach_probe_a64 [--pre=off|smstart|sm|za]"
                    " < encodings.hex\n");
            return 2;
        }
    }
    pre = preamble_word(pre_name);

    printf("hex\texec\tsignal\tpre\n");
    while (fgets(line, sizeof line, stdin)) {
        uint32_t *page;
        pid_t pid;
        uint8_t *scratch;
        uint8_t raw[8];
        unsigned n = 0;
        const char *p = line;

        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '#' || *p == '\n' || !*p) {
            continue;
        }
        page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        scratch = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED || scratch == MAP_FAILED) {
            return 2;
        }
        for (; p[0] && p[1] && isxdigit((unsigned char)p[0]) &&
               isxdigit((unsigned char)p[1]) && n < sizeof raw; p += 2) {
            char t[3] = { p[0], p[1], 0 };
            raw[n++] = (uint8_t)strtoul(t, NULL, 16);
        }
        if (n != 4) {
            fprintf(stderr, "not a 4-byte a64 encoding: %s", line);
            return 2;
        }
        /* The preamble rides in the SAME executable page, immediately
         * ahead of the encoding, so no separate control transfer and no
         * compiler-visible SME requirement is involved. */
        if (pre) {
            page[0] = pre;
            memcpy(&page[1], raw, 4);
            page[2] = 0xd65f03c0;               /* ret */
        } else {
            memcpy(&page[0], raw, 4);
            page[1] = 0xd65f03c0;               /* ret */
        }
        __builtin___clear_cache((char *)page, (char *)page + 12);

        caught = 0;
        pid = fork();
        if (pid < 0) {
            return 2;
        }
        if (pid == 0) {
            /* an encoding that turns out to be a self-branch would
             * otherwise hang the whole file; SIGALRM is a distinct
             * verdict, never a silent stall. */
            alarm(3);
            register uint64_t s asm("x0") = (uint64_t)(scratch + 32768);
            register uint64_t t asm("x9") = (uint64_t)page;
            __asm__ volatile(
                "mov x1, x0\n\t"  "mov x2, x0\n\t"  "mov x3, x0\n\t"
                "mov x4, x0\n\t"  "mov x5, x0\n\t"  "mov x6, x0\n\t"
                "mov x7, x0\n\t"  "mov x8, x0\n\t"  "mov x10, x0\n\t"
                "mov x11, x0\n\t" "mov x12, x0\n\t" "mov x13, x0\n\t"
                "mov x14, x0\n\t" "mov x15, x0\n\t" "mov x16, x0\n\t"
                "mov x17, x0\n\t" "mov x19, x0\n\t" "mov x20, x0\n\t"
                "mov x21, x0\n\t" "mov x22, x0\n\t" "mov x23, x0\n\t"
                "mov x24, x0\n\t" "mov x25, x0\n\t" "mov x26, x0\n\t"
                "mov x27, x0\n\t" "mov x28, x0\n\t"
                "blr x9\n\t"
                :: "r"(s), "r"(t)
                : "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
                  "x10", "x11", "x12", "x13", "x14", "x15", "x16",
                  "x17", "x18", "x19", "x20", "x21", "x22", "x23",
                  "x24", "x25", "x26", "x27", "x28", "x30",
                  "cc", "memory");
            _exit(0);
        } else {
            int st = 0;
            if (waitpid(pid, &st, 0) != pid) {
                return 2;
            }
            if (WIFSIGNALED(st)) {
                caught = WTERMSIG(st);
            } else if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
                caught = -1;
            }
        }
        line[strcspn(line, "\r\n")] = '\0';
        printf("%s\t%s\t%d\t%s\n", line, caught ? "no" : "yes", caught,
               pre_name);
        fflush(stdout);
        munmap(page, 4096);
        munmap(scratch, 65536);
    }
    return 0;
}
