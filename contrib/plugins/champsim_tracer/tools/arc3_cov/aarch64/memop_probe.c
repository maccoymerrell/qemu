/*
 * ARC 3 -- execute the aarch64 DENOMINATOR under the tracer, so the byte
 * axis has something to compare.
 *
 * The byte comparison keys on the encoding, and a real program's encodings
 * are not the denominator's: `opcodes.tsv` carries one REPRESENTATIVE
 * encoding per opcode with fixed register fields, and a workload uses
 * whatever fields the compiler chose.  Scoring a traced workload against the
 * denominator therefore intersects in almost nothing and reports a clean
 * zero -- an axis that compared nothing.  (C3: the coverage denominator is
 * the OPCODE space, not the encoding space; register fields are generic.)
 *
 * So the denominator is executed instead.  Every encoding the reachability
 * probe recorded as RUNNING is written into an executable page at its own
 * offset and called, once, in ONE process -- no fork, because the tracer
 * follows this process and a forked child's memops would not land in it.
 * Encodings that SIGILL, SIGSEGV or hang under the reachability probe are
 * the caller's to filter out; this program assumes its input list is the
 * exec=yes set and has no signal handling, so a stray one is a loud crash
 * rather than a silently short trace.
 *
 * Every general register except the frame and link registers points at a
 * mapped, writable scratch page, so a memory operand addresses something
 * real.  x30 holds the return address.  SP is saved and restored around
 * every call: an encoding that writes SP would otherwise corrupt the stack
 * for every encoding after it, and the run would end in a fault that says
 * nothing about the encoding it lands on.
 *
 * A fault handler exists for the same reason and not to hide anything: the
 * reachability probe forked, so a fault there cost one encoding; here a
 * fault would end the trace early and silently shorten the axis.  Each
 * fault is COUNTED and its encoding is REPORTED, so a run that faults is
 * visible as a shorter scored set rather than as agreement.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <signal.h>
#include <setjmp.h>

#define SLOT_WORDS 4                    /* encoding + ret + padding */
#define MAX_SLOTS  8192
#define PRE_WORDS  24                   /* the preamble occupies slot 0's page head */

/*
 * PREAMBLE, run immediately before every encoding, at its own PCs so it
 * never lands in the encoding's own template.
 *
 * It exists because the first version of this probe reported 36 encodings
 * publishing no memop at all, and every one of them was CONDITIONAL:
 *
 *   - the SVE load-and-replicate family (`ld1rb` … `ld1rqw`, 24 rows) is
 *     predicated, and whatever the predicate registers happened to hold was
 *     all-false, so no element was loaded.  `ptrue pN.b` makes the
 *     predicates all-true so the access actually fires.
 *   - the store-exclusive family (`stxr`/`stlxr`/`stxp`/`stlxp`, 12 rows)
 *     fails and performs NO access when no exclusive monitor is held, which
 *     is the architectural behaviour and not a tracer defect.  `ldxr x17,
 *     [x0]` takes a reservation on the very address the store will use --
 *     every general register points at the same scratch address, so the base
 *     register the encoding chose does not matter.
 *
 * The reference counts both arms of a condition it cannot resolve (R4/R5),
 * so without this the byte axis measures the probe's register state rather
 * than the tracer.
 */
static const uint32_t preamble[] = {
    0x2518e3e0, 0x2518e3e1, 0x2518e3e2, 0x2518e3e3,     /* ptrue p0..p3.b */
    0xc85f7c11,                                          /* ldxr x17, [x0] */
    0xd65f03c0,                                          /* ret */
};

static sigjmp_buf jb;
static volatile int faulted;
uint64_t cst_saved_sp;
uint64_t cst_probe_page;

static void onfault(int s)
{
    (void)s;
    faulted = s;
    siglongjmp(jb, 1);
}

int main(void)
{
    char line[64];
    uint32_t *page;
    uint8_t *scratch;
    unsigned n = 0, nfault = 0;

    page = mmap(NULL, MAX_SLOTS * SLOT_WORDS * 4,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    scratch = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED || scratch == MAP_FAILED) {
        return 2;
    }
    cst_probe_page = (uint64_t)page;
    memcpy(page, preamble, sizeof preamble);
    while (fgets(line, sizeof line, stdin) && n < MAX_SLOTS) {
        uint8_t raw[8];
        unsigned k = 0;
        const char *p = line;

        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '#' || *p == '\n' || !*p) {
            continue;
        }
        for (; p[0] && p[1] && isxdigit((unsigned char)p[0]) &&
               isxdigit((unsigned char)p[1]) && k < sizeof raw; p += 2) {
            char t[3] = { p[0], p[1], 0 };
            raw[k++] = (uint8_t)strtoul(t, NULL, 16);
        }
        if (k != 4) {
            fprintf(stderr, "not a 4-byte a64 encoding: %s", line);
            return 2;
        }
        memcpy(&page[PRE_WORDS + n * SLOT_WORDS], raw, 4);
        page[PRE_WORDS + n * SLOT_WORDS + 1] = 0xd65f03c0;      /* ret */
        page[PRE_WORDS + n * SLOT_WORDS + 2] = 0xd503201f;      /* nop */
        page[PRE_WORDS + n * SLOT_WORDS + 3] = 0xd503201f;      /* nop */
        n++;
    }
    __builtin___clear_cache((char *)page,
                            (char *)(page + PRE_WORDS + (size_t)n * SLOT_WORDS));

    /*
     * sigaction with SA_NODEFER + SA_ONSTACK, not signal(): with the
     * predicates forced all-true the SVE gather forms address garbage and
     * fault, and a second fault while the first was still masked -- or one
     * taken on an exhausted stack -- killed the process outright, ending the
     * trace early with no record of where.  An alternate stack and an
     * undeferred handler make a nested fault survivable, and every fault is
     * still counted and named.
     */
    {
        static char altstack[SIGSTKSZ * 4];
        stack_t ss = { .ss_sp = altstack, .ss_size = sizeof altstack,
                       .ss_flags = 0 };
        struct sigaction sa;
        int sig[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP };

        sigaltstack(&ss, NULL);
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = onfault;
        sa.sa_flags = SA_NODEFER | SA_ONSTACK;
        sigemptyset(&sa.sa_mask);
        for (unsigned k = 0; k < sizeof sig / sizeof sig[0]; k++) {
            sigaction(sig[k], &sa, NULL);
        }
    }

    for (unsigned i = 0; i < n; i++) {
        /* Everything the asm needs is recomputed AFTER sigsetjmp and held
         * in volatile locals across it.  A value the compiler cached in a
         * register before the jump is indeterminate after a siglongjmp, and
         * the first version of this loop lost the branch target that way:
         * every slot, including a bare NOP, faulted on a `blr` to garbage. */
        volatile uint64_t sv, tv;
        register uint64_t s asm("x0");
        register uint64_t t asm("x9");

        faulted = 0;
        if (sigsetjmp(jb, 1)) {
            nfault++;
            fprintf(stderr, "fault sig=%d on slot %u (%08x)\n", faulted, i,
                    page[PRE_WORDS + i * SLOT_WORDS]);
            continue;
        }
        sv = (uint64_t)(scratch + (1 << 19));
        tv = (uint64_t)&page[PRE_WORDS + i * SLOT_WORDS];
        s = sv;
        t = tv;
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
            /* stash SP through a symbol, so an encoding that writes SP
             * cannot corrupt every encoding after it. */
            "adrp x18, cst_saved_sp\n\t"
            "add  x18, x18, :lo12:cst_saved_sp\n\t"
            "mov  x17, sp\n\t"
            "str  x17, [x18]\n\t"
            "mov  x16, x9\n\t"
            "adrp x18, cst_probe_page\n\t"
            "add  x18, x18, :lo12:cst_probe_page\n\t"
            "ldr  x18, [x18]\n\t"
            "blr  x18\n\t"          /* preamble: predicates + reservation */
            "blr  x16\n\t"
            "adrp x18, cst_saved_sp\n\t"
            "add  x18, x18, :lo12:cst_saved_sp\n\t"
            "ldr  x17, [x18]\n\t"
            "mov  sp, x17\n\t"
            :: "r"(s), "r"(t)
            : "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
              "x10", "x11", "x12", "x13", "x14", "x15", "x16",
              "x17", "x18", "x19", "x20", "x21", "x22", "x23",
              "x24", "x25", "x26", "x27", "x28", "x30", "x16",
              "cc", "memory");
    }
    printf("executed %u encodings, %u faulted\n", n, nfault);
    return 0;
}
