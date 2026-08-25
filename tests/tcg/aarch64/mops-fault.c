/*
 * Check that a FEAT_MOPS SET/CPY step which faults on its host-pointer
 * fast path delivers a *guest* fault, whether or not a plugin has asked
 * for memory callbacks.
 *
 * Author: Maccoy Merrell
 *
 * In linux-user tlb_vaddr_to_host() is g2h() with no mapping check, so
 * both the source and the destination of a CPY chunk always look like
 * usable host pointers.  The bulk move is therefore performed inside a
 * set_helper_retaddr() bracket, which is what lets the host SIGSEGV on an
 * unmapped page be unwound into a guest SIGSEGV.  Any *other* dereference
 * of those pointers has to sit inside the same bracket, or the emulator
 * dies with "QEMU internal SIGSEGV" instead of the guest taking its fault.
 *
 * Each case copies across a hole punched in an otherwise mapped region and
 * expects exactly one guest SIGSEGV.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>

static sigjmp_buf jb;
/* volatile: written in a signal handler, read after siglongjmp(). */
static volatile int caught;

static void handler(int sig)
{
    caught = sig;
    siglongjmp(jb, 1);
}

static size_t ps;

/* Map n pages and punch out page @hole. */
static char *region(int n, int hole)
{
    char *p = mmap(NULL, n * ps, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED) {
        return NULL;
    }
    memset(p, 0xa5, n * ps);
    if (hole >= 0 && munmap(p + hole * ps, ps) != 0) {
        return NULL;
    }
    return p;
}

#define CPY(d, s, n)                                                    \
    do {                                                                \
        register uint64_t x0 asm("x0") = (uint64_t)(d);                 \
        register uint64_t x1 asm("x1") = (uint64_t)(s);                 \
        register uint64_t x2 asm("x2") = (uint64_t)(n);                 \
        asm volatile(".arch armv8.8-a+mops\n\t"                         \
                     "cpyp [x0]!, [x1]!, x2!\n\t"                       \
                     "cpym [x0]!, [x1]!, x2!\n\t"                       \
                     "cpye [x0]!, [x1]!, x2!\n\t"                       \
                     : "+r"(x0), "+r"(x1), "+r"(x2) :: "memory");       \
    } while (0)

#define SET(d, v, n)                                                    \
    do {                                                                \
        register uint64_t x0 asm("x0") = (uint64_t)(d);                 \
        register uint64_t x1 asm("x1") = (uint64_t)(n);                 \
        register uint64_t x2 asm("x2") = (uint64_t)(v);                 \
        asm volatile(".arch armv8.8-a+mops\n\t"                         \
                     "setp [x0]!, x1!, x2\n\t"                          \
                     "setm [x0]!, x1!, x2\n\t"                          \
                     "sete [x0]!, x1!, x2\n\t"                          \
                     : "+r"(x0), "+r"(x1) : "r"(x2) : "memory");        \
    } while (0)

static int fails;

static void expect_segv(const char *name, void (*fn)(void))
{
    caught = 0;
    if (sigsetjmp(jb, 1) == 0) {
        fn();
        printf("%s: NO FAULT -- FAIL\n", name);
        fails++;
        return;
    }
    if (caught != SIGSEGV) {
        printf("%s: sig %d -- FAIL\n", name, caught);
        fails++;
        return;
    }
    printf("%s: ok\n", name);
}

/*
 * CPY forwards; the source runs into a hole.  The read of the chunk is
 * reported to the plugin before the move, so it is the dereference that
 * has to be unwound.
 */
static void cpy_fwd_src(void)
{
    char *src = region(3, 1);
    char *dst = region(3, -1);

    CPY(dst, src, 2 * ps);
}

/* CPY forwards; the destination runs into a hole. */
static void cpy_fwd_dst(void)
{
    char *src = region(3, -1);
    char *dst = region(3, 1);

    CPY(dst, src, 2 * ps);
}

/*
 * CPY backwards -- source below destination and overlapping -- with the
 * source running into a hole.  The first (highest) chunk is a clean fast
 * path, so this also proves the good path still moves bytes.
 */
static void cpy_rev_src(void)
{
    char *b = region(4, 0);

    CPY(b + ps, b, 2 * ps);
}

/*
 * SET across a hole: the store side has no pre-move dereference, so this
 * has always faulted correctly.  It is here to keep it that way.
 */
static void set_dst(void)
{
    char *dst = region(3, 1);

    SET(dst, 0x5a, 2 * ps);
}

int main(void)
{
    struct sigaction sa;

    ps = getpagesize();
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    expect_segv("cpy fwd, src hole", cpy_fwd_src);
    expect_segv("cpy fwd, dst hole", cpy_fwd_dst);
    expect_segv("cpy rev, src hole", cpy_rev_src);
    expect_segv("set, dst hole", set_dst);

    return fails != 0;
}
