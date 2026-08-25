/*
 * ARC 3 -- WHICH HELPERS DOES QEMU EMIT FOR THIS x87 ENCODING?
 *
 * The x87 control word (env->fpuc) reaches an x87 instruction only through
 * the helper sequence gen_x87() emits for it.  Deciding whether a given
 * encoding READS the control word therefore has two halves, and this
 * program is the first: it makes QEMU translate each encoding so the
 * helper sequence can be READ OFF THE TCG OP DUMP rather than read off a
 * switch statement in translate.c by eye.  The second half -- does a named
 * helper reach env->fpuc or &env->fp_status -- is x87_cw_derive.py, which
 * walks the call graph of target/i386/tcg/fpu_helper.c.
 *
 * Neither half consults the tracer, which is the point: the tracer's
 * X87F_CWR table is the thing being scored.
 *
 * Each encoding is placed at its OWN fixed address, base + i * STRIDE, so
 * the `---- <pc>` marker the op dump prints for INDEX_op_insn_start
 * identifies which encoding a block belongs to with no ambiguity and no
 * dependence on translation order.  Reusing one address would leave the
 * result at the mercy of QEMU's SMC invalidation.
 *
 * Run it as
 *   qemu-x86_64 -one-insn-per-tb -d op -D dump.txt ./x87_cw_probe < enc.hex
 *
 * RAX points at a mapped, writable scratch page so a mod!=3 form whose
 * base is r/m=000 addresses something real; a SIGSEGV would otherwise cut
 * the sweep short.  Every fault is caught and the sweep continues, because
 * a form that faults has still been TRANSLATED, and translation is the
 * whole subject here.
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

#define CODE_BASE   0x70000000UL
#define CODE_STRIDE 0x10000UL
#define SCRATCH     0x60000000UL

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
    unsigned idx = 0;
    uint8_t *scratch;

    signal(SIGILL, handler);
    signal(SIGSEGV, handler);
    signal(SIGBUS, handler);
    signal(SIGFPE, handler);
    signal(SIGTRAP, handler);

    scratch = mmap((void *)SCRATCH, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (scratch == MAP_FAILED) {
        fprintf(stderr, "x87_cw_probe: scratch map failed\n");
        return 2;
    }

    printf("idx\tpc\thex\texec\tsignal\n");
    while (fgets(line, sizeof line, stdin)) {
        uint8_t *page;
        unsigned long addr;
        unsigned n = 0;
        const char *p = line;

        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '#' || *p == '\n' || !*p) {
            continue;
        }
        addr = CODE_BASE + (unsigned long)idx * CODE_STRIDE;
        page = mmap((void *)addr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (page == MAP_FAILED || (unsigned long)page != addr) {
            fprintf(stderr, "x87_cw_probe: fixed map failed at %#lx\n", addr);
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
            __asm__ volatile("mov %0, %%rax\n\t"
                             "call *%1\n\t"
                             :: "r"(scratch), "r"(page)
                             : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                               "memory");
        }
        line[strcspn(line, "\r\n")] = '\0';
        printf("%u\t%lx\t%s\t%s\t%d\n", idx, addr, line,
               caught ? "no" : "yes", caught);
        fflush(stdout);
        /* deliberately NOT unmapped: the address must stay unique */
        idx++;
    }
    return 0;
}
