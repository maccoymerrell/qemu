/*
 * ARC 3 -- is this encoding REACHABLE by a QEMU x86_64 guest?
 *
 * The coverage report's reachability column decides whether a tracer
 * decode gap costs anything.  It used to be a guess off XED's EXTENSION
 * string, and the guess was wrong by 128 rows: the APX (EVEX-promoted)
 * forms of BMI1, BMI2, ADOX_ADCX, LZCNT, MOVBE, RAO, USER_MSR and the
 * rest keep their original extension name and carry APX only in their
 * ISA-SET, so a name test on the extension called every one of them
 * reachable.  QEMU TCG has no APX and executes none of them.
 *
 * So reachability is measured instead.  Each encoding is written into an
 * executable page, called, and the verdict is whether it ran: build this
 * for the guest and run it UNDER qemu-x86_64, where SIGILL is QEMU's TCG
 * front end refusing the bytes.
 *
 * WHAT THIS CANNOT SEE, and the report must not claim it does: an
 * instruction QEMU implements only at CPL 0 raises SIGILL here for the
 * privilege, not for the opcode.  Corroborate those against
 * target/i386/tcg/decode-new.c.inc before quoting them -- at the time of
 * writing every SIGILL row is absent from that file entirely, so the two
 * agree, and a future divergence is a finding rather than a footnote.
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
#include <setjmp.h>
#include <sys/mman.h>

static sigjmp_buf jb;
static volatile int caught;

static void handler(int s)
{
    caught = s;
    siglongjmp(jb, 1);
}

int main(void)
{
    char line[64];

    signal(SIGILL, handler);
    signal(SIGSEGV, handler);
    signal(SIGBUS, handler);
    signal(SIGFPE, handler);
    signal(SIGTRAP, handler);

    printf("hex\texec\tsignal\n");
    while (fgets(line, sizeof line, stdin)) {
        uint8_t *page, *scratch;
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
        scratch = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED || scratch == MAP_FAILED) {
            return 2;
        }
        for (; p[0] && p[1] && isxdigit((unsigned char)p[0]) &&
               isxdigit((unsigned char)p[1]) && n < 15; p += 2) {
            char t[3] = { p[0], p[1], 0 };
            page[n++] = (uint8_t)strtoul(t, NULL, 16);
        }
        page[n] = 0xc3;                 /* ret */

        caught = 0;
        if (!sigsetjmp(jb, 1)) {
            /* RAX points at writable scratch so a memory operand whose
             * base is r/m=000 addresses something mapped: a SIGSEGV
             * would otherwise be read as a refusal. */
            __asm__ volatile("mov %0, %%rax\n\t"
                             "call *%1\n\t"
                             :: "r"(scratch), "r"(page)
                             : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                               "memory");
        }
        line[strcspn(line, "\r\n")] = '\0';
        printf("%s\t%s\t%d\n", line, caught ? "no" : "yes", caught);
        fflush(stdout);
        munmap(page, 4096);
        munmap(scratch, 4096);
    }
    return 0;
}
