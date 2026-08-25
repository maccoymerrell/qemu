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
 * WHAT THIS CANNOT SEE, and the report must not claim it does: an
 * encoding QEMU implements only at EL1 or above raises SIGILL here for
 * the privilege, not for the opcode.  Corroborate against
 * the target/arm/tcg decode files before quoting a row -- at the time of writing
 * every SIGILL row is absent from those files entirely.
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

int main(void)
{
    char line[64];
    int caught;

    printf("hex\texec\tsignal\n");
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
        memcpy(&page[0], raw, 4);
        page[1] = 0xd65f03c0;                   /* ret */
        __builtin___clear_cache((char *)page, (char *)page + 8);

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
        printf("%s\t%s\t%d\n", line, caught ? "no" : "yes", caught);
        fflush(stdout);
        munmap(page, 4096);
        munmap(scratch, 65536);
    }
    return 0;
}
