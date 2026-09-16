/*
 * ARC 3 -- THE CONTROL-WORD DIFFERENTIAL.
 *
 * x87_cw_derive.py decides, from QEMU's own call graph, whether an x87
 * encoding READS the control word.  This program decides the same question
 * a second way and without reading a line of QEMU: it executes each
 * encoding TWICE from an identical starting state, differing only in the
 * x87 control word, and compares the whole 108-byte FNSAVE image
 * afterwards.  A result that MOVES when nothing but the control word moved
 * is a control-word read, observed.
 *
 *   CW_A  0x037f   round to nearest, extended (64-bit) precision
 *   CW_B  0x0c3f   round toward zero, single  (24-bit) precision
 *
 * Both fully mask every exception, so the difference is rounding and
 * precision alone and no unmasked exception can change control flow.
 *
 * THE ASYMMETRY IS DELIBERATE AND MUST BE READ CORRECTLY.  A moved result
 * PROVES a read.  An unmoved result proves only that these inputs did not
 * expose one, so this program can CONVICT and cannot ACQUIT -- which is
 * exactly the shape needed to falsify the derivation's YES rows and to
 * catch a MISSING edge among its NO rows.
 *
 * TWO FIELDS OF THE FNSAVE IMAGE ARE MASKED BEFORE COMPARISON, and each
 * would otherwise convict every row on the denominator:
 *
 *   bytes 0..1   the CONTROL WORD.  It is the INPUT that was varied.  An
 *                unmasked comparison reported 149 of 153 rows as moving,
 *                which is the differential reading its own stimulus back.
 *   bytes 12..27 the last-instruction and last-operand POINTERS.  They
 *                record where the instruction was, not what it computed.
 *
 * Everything that is a RESULT stays in: the status word with TOP, the
 * condition codes and the exception flags, the tag word, and all eight
 * 80-bit registers.
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

/* Eight rounding-sensitive doubles.  ST(0) ends up holding vals[0]. */
static const double vals[8] = {
    1.0 / 3.0, 2.0 / 3.0, 3.14159265358979323846, 2.71828182845904523536,
    1.41421356237309504880, 1e300, 1e-300, 12345.6789012345,
};

/*
 * FNSAVE's 108-byte image: control word, status word, tag word, then the
 * instruction pointer (4), opcode/selector (4), operand pointer (4),
 * operand selector (4), then eight 10-byte registers.  Bytes 12..27 are
 * the pointers and are masked out.
 */
static void mask_image(uint8_t *img)
{
    memset(img + 0, 0, 2);              /* control word: the stimulus */
    memset(img + 12, 0, 16);            /* last-insn / last-operand pointers */
}

static int run_once(uint8_t *page, uint8_t *scratch, uint16_t cw,
                    uint8_t *img)
{
    static const uint16_t std = 0x037f;
    static const uint8_t fill[8] = {
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0xd5, 0x3f
    };
    unsigned i;

    for (i = 0; i < 4096; i++) {
        scratch[i] = fill[i & 7];
    }
    memset(img, 0, 108);

    caught = 0;
    if (!sigsetjmp(jb, 1)) {
        /*
         * THE PRELOAD RUNS UNDER THE SAME CONTROL WORD IN BOTH ARMS, and
         * it has to.  With PC = 24 bits, `fldl` itself rounds the value it
         * pushes -- QEMU hands &env->fp_status to float64_to_floatx80, so
         * the precision control reaches the conversion -- and the two arms
         * then start from DIFFERENT stack contents.  Measured before this
         * was fixed: 149 of 153 rows "moved", including `fld %st(1)`, on a
         * differential that was comparing its own stimulus.  The tested
         * control word is installed AFTER the stack is built.
         */
        __asm__ volatile(
            "fninit\n\t"
            "fldcw %[std]\n\t"
            "fldl 56(%[v])\n\t" "fldl 48(%[v])\n\t"
            "fldl 40(%[v])\n\t" "fldl 32(%[v])\n\t"
            "fldl 24(%[v])\n\t" "fldl 16(%[v])\n\t"
            "fldl  8(%[v])\n\t" "fldl   (%[v])\n\t"
            "fnclex\n\t"
            "fldcw %[cw]\n\t"
            "mov %[s], %%rax\n\t"
            "call *%[p]\n\t"
            :: [cw] "m"(cw), [std] "m"(std), [v] "r"(vals),
               [s] "r"(scratch), [p] "r"(page)
            : "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "memory", "st",
              "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)");
    }
    __asm__ volatile("fnsave %0\n\t" : "=m"(*img) :: "memory");
    mask_image(img);
    return caught;
}

int main(int argc, char **argv)
{
    char line[64];
    uint8_t *page, *scratch;
    uint8_t a[108], b[108];
    int inject = (argc > 1 && !strcmp(argv[1], "--inject"));

    signal(SIGILL, handler);
    signal(SIGSEGV, handler);
    signal(SIGBUS, handler);
    signal(SIGFPE, handler);
    signal(SIGTRAP, handler);

    page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    scratch = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED || scratch == MAP_FAILED) {
        return 2;
    }

    printf("hex\tmoved\tsig_a\tsig_b\n");
    while (fgets(line, sizeof line, stdin)) {
        unsigned n = 0;
        int sa, sb;
        const char *p = line;

        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '#' || *p == '\n' || !*p) {
            continue;
        }
        for (; p[0] && p[1] && isxdigit((unsigned char)p[0]) &&
               isxdigit((unsigned char)p[1]) && n < 15; p += 2) {
            char t[3] = { p[0], p[1], 0 };
            page[n++] = (uint8_t)strtoul(t, NULL, 16);
        }
        page[n] = 0xc3;                 /* ret */

        sa = run_once(page, scratch, 0x037f, a);
        /*
         * --inject is the control on the CONTROL: it runs the SECOND arm
         * with the SAME control word as the first.  Every row must then
         * report moved=no.  A row that still moves is nondeterminism in
         * the harness, and the whole differential is worthless until it
         * is found.
         */
        sb = run_once(page, scratch, inject ? 0x037f : 0x0c3f, b);

        line[strcspn(line, "\r\n")] = '\0';
        printf("%s\t%s\t%d\t%d\n", line,
               memcmp(a, b, 108) ? "yes" : "no", sa, sb);
        fflush(stdout);
    }
    return 0;
}
