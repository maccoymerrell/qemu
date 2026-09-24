/*
 * Wrong-path victim program for the wp-assert test plugin.
 *
 * The guest calls wp_trigger(test, target, buf, len) once per test.  The
 * trigger loads a known pattern into every register it can reach, then
 * executes a marker instruction (movabs $WP_MAGIC, %r11).  The wp-assert
 * plugin recognises the marker at translation time and, BEFORE the marker
 * executes, drives a wrong-path excursion at @target through the plugin
 * speculative-execution API.  After the marker the trigger checks, from
 * the guest's own point of view, that no register, flag, vector register,
 * MXCSR or x87 control word changed, and returns a bitmask of mismatches.
 *
 * The wrong-path routines (wp_*) are never executed by the correct path:
 * they store into the caller's buffer, into read-only data and into code,
 * clobber the whole register file, fault in every way user mode can, make
 * syscalls, and loop forever.  Whatever they do must be invisible here.
 *
 * Every line this program prints is a deterministic function of the
 * correct path, so its output must be byte-identical with and without the
 * plugin (T5, checked by the runner).
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define _GNU_SOURCE
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Keep in sync with tests/tcg/plugins/wp-assert.c */
enum {
    T1_STORE = 1,      /* stores into buf; forwarding; then clobber */
    T1_RO,             /* stores into read-only data and into code */
    T2_REGS,           /* clobber the whole register file */
    T3_FETCH_UNMAPPED, /* target is an unmapped page */
    T3_STRADDLE,       /* code runs into a PROT_NONE page */
    T3_UD,             /* ud2 */
    T3_DIV0,           /* divide by zero */
    T3_PRIV,           /* hlt at CPL3 (#GP) */
    T3_INT3,           /* int3 */
    T3_LOAD_UNMAPPED,  /* load from an unmapped page (NOT a fault) */
    T3_SYSCALL,        /* write(1, "LEAK") + exit(77) */
    T4_LOOP,           /* infinite loop */
    T4_REP,            /* rep stosb with RCX = 16 MiB */
    T5_REPEAT,         /* same excursion twice from one state */
    T_LAST
};

extern uint64_t wp_trigger(uint64_t test, uint64_t target, void *buf,
                           uint64_t len);
extern char wp_store[], wp_store_ro[], wp_clobber[], wp_ud[], wp_div[],
            wp_priv[], wp_int3[], wp_load_unmapped[], wp_syscall[],
            wp_loop[], wp_rep[], wp_victim_code[];
extern const uint64_t wp_rodata[8];
extern int wp_victim(void);

__asm__(
    ".section .rodata\n"
    ".p2align 4\n"
    "wp_pats:\n"
    "  .quad 0x0a0a0a0a0a0a0a0a\n"   /* 0  rax */
    "  .quad 0x0b0b0b0b0b0b0b0b\n"   /* 8  rbx */
    "  .quad 0x0c0c0c0c0c0c0c0c\n"   /* 16 rbp */
    "  .quad 0x0808080808080808\n"   /* 24 r8  */
    "  .quad 0x0909090909090909\n"   /* 32 r9  */
    "  .quad 0x1010101010101010\n"   /* 40 r10 */
    "  .quad 0x1212121212121212\n"   /* 48 r12 */
    "  .quad 0x1313131313131313\n"   /* 56 r13 */
    "  .quad 0x1414141414141414\n"   /* 64 r14 */
    "  .quad 0x1515151515151515\n"   /* 72 r15 */
    "  .quad 0x5750415353455254\n"   /* 80 r11 = marker magic */
    ".p2align 4\n"
    "wp_xpat:\n"
    "  .quad 0x0123456789abcdef, 0xfedcba9876543210\n"
    "wp_mxcsr_junk: .long 0x7f80\n"   /* round toward zero */
    "wp_fcw_junk:   .short 0x0c7f\n"  /* x87 round toward zero */
    "wp_leakmsg: .ascii \"LEAK-FROM-WRONG-PATH\\n\"\n"
    ".p2align 6\n"
    ".globl wp_rodata\n"
    "wp_rodata:\n"
    "  .quad 1, 2, 3, 4, 5, 6, 7, 8\n"
    ".section .data\n"
    ".p2align 3\n"
    "wp_saved_rsp: .quad 0\n"
    "wp_mask: .long 0\n"

    ".text\n"
    /*
     * uint64_t wp_trigger(test=rdi, target=rsi, buf=rdx, len=rcx)
     */
    ".globl wp_trigger\n"
    ".p2align 4\n"
    "wp_trigger:\n"
    "  push %rbx\n  push %rbp\n  push %r12\n  push %r13\n"
    "  push %r14\n  push %r15\n"
    "  push %rdi\n  push %rsi\n  push %rdx\n  push %rcx\n"
    "  sub $32, %rsp\n"
    /* scratch: 0 mxcsr pre, 4 fcw pre, 8 mxcsr post, 12 fcw post,
     *          16 rflags pre, 24 rflags post; args at 32..56 */
    "  movl $0, wp_mask(%rip)\n"
    "  stmxcsr 0(%rsp)\n"
    "  fnstcw 4(%rsp)\n"
    "  mov %rsp, wp_saved_rsp(%rip)\n"
    "  mov wp_pats+8(%rip), %rbx\n"
    "  mov wp_pats+16(%rip), %rbp\n"
    "  mov wp_pats+24(%rip), %r8\n"
    "  mov wp_pats+32(%rip), %r9\n"
    "  mov wp_pats+40(%rip), %r10\n"
    "  mov wp_pats+48(%rip), %r12\n"
    "  mov wp_pats+56(%rip), %r13\n"
    "  mov wp_pats+64(%rip), %r14\n"
    "  mov wp_pats+72(%rip), %r15\n"
    "  movdqa wp_xpat(%rip), %xmm0\n"
    "  movdqa %xmm0, %xmm1\n  movdqa %xmm0, %xmm2\n  movdqa %xmm0, %xmm3\n"
    "  movdqa %xmm0, %xmm4\n  movdqa %xmm0, %xmm5\n  movdqa %xmm0, %xmm6\n"
    "  movdqa %xmm0, %xmm7\n  movdqa %xmm0, %xmm8\n  movdqa %xmm0, %xmm9\n"
    "  movdqa %xmm0, %xmm10\n movdqa %xmm0, %xmm11\n movdqa %xmm0, %xmm12\n"
    "  movdqa %xmm0, %xmm13\n movdqa %xmm0, %xmm14\n movdqa %xmm0, %xmm15\n"
    "  cld\n"
    /* a non-trivial arithmetic flag state: CF ZF PF AF set */
    "  mov $-1, %eax\n"
    "  add $1, %eax\n"
    "  mov wp_pats+0(%rip), %rax\n"
    "  pushfq\n"
    "  popq 16(%rsp)\n"
    ".globl wp_marker\n"
    "wp_marker:\n"
    "  .byte 0x49, 0xbb\n"              /* movabs $WP_MAGIC, %r11 */
    "  .quad 0x5750415353455254\n"
    "  pushfq\n"
    "  popq 24(%rsp)\n"
#define CHK(reg, off, bit) \
    "  cmp wp_pats+" #off "(%rip), %" #reg "\n" \
    "  je 1f\n" \
    "  orl $" #bit ", wp_mask(%rip)\n" \
    "1:\n"
    CHK(rax, 0, 0x1)
    CHK(rbx, 8, 0x2)
    CHK(rbp, 16, 0x4)
    CHK(r8, 24, 0x8)
    CHK(r9, 32, 0x10)
    CHK(r10, 40, 0x20)
    CHK(r12, 48, 0x40)
    CHK(r13, 56, 0x80)
    CHK(r14, 64, 0x100)
    CHK(r15, 72, 0x200)
    CHK(r11, 80, 0x400)
    "  cmp 56(%rsp), %rdi\n  je 1f\n  orl $0x800, wp_mask(%rip)\n1:\n"
    "  cmp 48(%rsp), %rsi\n  je 1f\n  orl $0x1000, wp_mask(%rip)\n1:\n"
    "  cmp 40(%rsp), %rdx\n  je 1f\n  orl $0x2000, wp_mask(%rip)\n1:\n"
    "  cmp 32(%rsp), %rcx\n  je 1f\n  orl $0x4000, wp_mask(%rip)\n1:\n"
    "  cmp wp_saved_rsp(%rip), %rsp\n  je 1f\n"
    "  orl $0x8000, wp_mask(%rip)\n1:\n"
#define XCHK(n) \
    "  pcmpeqb wp_xpat(%rip), %xmm" #n "\n" \
    "  pmovmskb %xmm" #n ", %eax\n" \
    "  cmp $0xffff, %eax\n" \
    "  je 1f\n" \
    "  orl $0x10000, wp_mask(%rip)\n" \
    "1:\n"
    XCHK(0) XCHK(1) XCHK(2) XCHK(3) XCHK(4) XCHK(5) XCHK(6) XCHK(7)
    XCHK(8) XCHK(9) XCHK(10) XCHK(11) XCHK(12) XCHK(13) XCHK(14) XCHK(15)
    /* arithmetic flags + TF + DF + OF must match the pre-marker state */
    "  mov 24(%rsp), %rax\n"
    "  xor 16(%rsp), %rax\n"
    "  and $0xdd5, %rax\n"
    "  jz 1f\n  orl $0x20000, wp_mask(%rip)\n1:\n"
    "  stmxcsr 8(%rsp)\n"
    "  mov 8(%rsp), %eax\n  cmp 0(%rsp), %eax\n  je 1f\n"
    "  orl $0x40000, wp_mask(%rip)\n1:\n"
    "  fnstcw 12(%rsp)\n"
    "  movzwl 12(%rsp), %eax\n  cmpw 4(%rsp), %ax\n  je 1f\n"
    "  orl $0x80000, wp_mask(%rip)\n1:\n"
    "  mov wp_mask(%rip), %eax\n"
    "  add $32, %rsp\n"
    "  pop %rcx\n  pop %rdx\n  pop %rsi\n  pop %rdi\n"
    "  pop %r15\n  pop %r14\n  pop %r13\n  pop %r12\n  pop %rbp\n  pop %rbx\n"
    "  ret\n"

    /* ---------------- wrong-path-only code ---------------- */
    ".p2align 6\n"
    ".globl wp_store\n"
    "wp_store:\n"                       /* rdx = buf (len 4096) */
    "  movabs $0x1122334455667788, %rax\n"
    "  mov %rax, (%rdx)\n"
    "  mov (%rdx), %rbx\n"              /* must forward from the sandbox */
    "  mov %rbx, 8(%rdx)\n"
    "  movl $0xa5a5a5a5, 64(%rdx)\n"
    "  movb $0x5a, 4095(%rdx)\n"
    "  movdqu %xmm0, 128(%rdx)\n"
    "  jmp wp_clobber\n"

    ".p2align 6\n"
    ".globl wp_store_ro\n"
    "wp_store_ro:\n"                    /* rdx = wp_rodata */
    "  movq $-1, (%rdx)\n"
    "  movq $-1, 56(%rdx)\n"
    "  movq $-1, wp_victim_code(%rip)\n"
    "  mov (%rdx), %rbx\n"
    "  jmp wp_spin\n"

    ".p2align 6\n"
    ".globl wp_clobber\n"
    "wp_clobber:\n"
    "  movabs $0xdeadbeefcafe0001, %rax\n"
    "  movabs $0xdeadbeefcafe0002, %rbx\n"
    "  movabs $0xdeadbeefcafe0003, %rcx\n"
    "  movabs $0xdeadbeefcafe0004, %rdx\n"
    "  movabs $0xdeadbeefcafe0005, %rsi\n"
    "  movabs $0xdeadbeefcafe0006, %rdi\n"
    "  movabs $0xdeadbeefcafe0007, %rbp\n"
    "  movabs $0xdeadbeefcafe0008, %r8\n"
    "  movabs $0xdeadbeefcafe0009, %r9\n"
    "  movabs $0xdeadbeefcafe000a, %r10\n"
    "  movabs $0xdeadbeefcafe000b, %r11\n"
    "  movabs $0xdeadbeefcafe000c, %r12\n"
    "  movabs $0xdeadbeefcafe000d, %r13\n"
    "  movabs $0xdeadbeefcafe000e, %r14\n"
    "  movabs $0xdeadbeefcafe000f, %r15\n"
    "  pcmpeqb %xmm0, %xmm0\n  pcmpeqb %xmm1, %xmm1\n"
    "  pcmpeqb %xmm2, %xmm2\n  pcmpeqb %xmm3, %xmm3\n"
    "  pcmpeqb %xmm4, %xmm4\n  pcmpeqb %xmm5, %xmm5\n"
    "  pcmpeqb %xmm6, %xmm6\n  pcmpeqb %xmm7, %xmm7\n"
    "  pcmpeqb %xmm8, %xmm8\n  pcmpeqb %xmm9, %xmm9\n"
    "  pcmpeqb %xmm10, %xmm10\n pcmpeqb %xmm11, %xmm11\n"
    "  pcmpeqb %xmm12, %xmm12\n pcmpeqb %xmm13, %xmm13\n"
    "  pcmpeqb %xmm14, %xmm14\n pcmpeqb %xmm15, %xmm15\n"
    "  ldmxcsr wp_mxcsr_junk(%rip)\n"
    "  fldcw wp_fcw_junk(%rip)\n"
    "  std\n"
    "  mov $0x10000, %rsp\n"
    "  cmp %rbx, %rcx\n"                /* flags: CF SF etc. */
    "  jmp wp_spin\n"

    ".globl wp_spin\n"
    "wp_spin:\n"
    "  jmp wp_spin\n"

    ".p2align 4\n"
    ".globl wp_ud\n"
    "wp_ud:\n"
    "  ud2\n"
    "  jmp wp_spin\n"

    ".p2align 4\n"
    ".globl wp_div\n"
    "wp_div:\n"
    "  xor %ecx, %ecx\n  mov $1, %eax\n  xor %edx, %edx\n"
    "  div %rcx\n"
    "  jmp wp_spin\n"

    ".p2align 4\n"
    ".globl wp_priv\n"
    "wp_priv:\n"
    "  hlt\n"
    "  jmp wp_spin\n"

    ".p2align 4\n"
    ".globl wp_int3\n"
    "wp_int3:\n"
    "  int3\n"
    "  jmp wp_spin\n"

    ".p2align 4\n"
    ".globl wp_load_unmapped\n"
    "wp_load_unmapped:\n"
    "  mov $0x10, %eax\n"
    "  mov (%rax), %rbx\n"
    "  mov %rbx, 24(%rdx)\n"
    "  jmp wp_spin\n"

    ".p2align 4\n"
    ".globl wp_syscall\n"
    "wp_syscall:\n"
    "  mov $1, %eax\n  mov $1, %edi\n"
    "  lea wp_leakmsg(%rip), %rsi\n  mov $21, %edx\n"
    "  syscall\n"
    "  mov $60, %eax\n  mov $77, %edi\n"
    "  syscall\n"
    "  jmp wp_spin\n"

    ".p2align 4\n"
    ".globl wp_loop\n"
    "wp_loop:\n"
    "  incq 16(%rdx)\n"
    "  add $1, %rax\n"
    "  jmp wp_loop\n"

    ".p2align 4\n"
    ".globl wp_rep\n"
    "wp_rep:\n"
    "  mov %rdx, %rdi\n"
    "  mov $0x1000000, %rcx\n"
    "  mov $0x77, %eax\n"
    "  rep stosb\n"
    "  jmp wp_spin\n"

    /* correct-path code the wrong path tries to overwrite */
    ".p2align 6\n"
    ".globl wp_victim\n"
    ".globl wp_victim_code\n"
    "wp_victim:\n"
    "wp_victim_code:\n"
    "  mov $42, %eax\n"
    "  ret\n"
    "  .fill 16, 1, 0x90\n"
);

static uint8_t buf[4096] __attribute__((aligned(4096)));
static uint8_t victim_copy[16];
static uint64_t rodata_copy[8];
static int failures;

static void on_signal(int sig)
{
    /* async-signal-safe: the guest must never observe a wrong-path fault */
    static const char msg[] =
        "[wp-assert] FAIL T3: guest observed a signal from a wrong-path "
        "excursion\n";
    (void)!write(2, msg, sizeof(msg) - 1);
    (void)sig;
    _exit(99);
}

static void fill_buf(void)
{
    for (int i = 0; i < (int)sizeof(buf); i++) {
        buf[i] = (uint8_t)(i * 7 + 3);
    }
}

static uint64_t fnv(const void *p, size_t n)
{
    const uint8_t *b = p;
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < n; i++) {
        h = (h ^ b[i]) * 0x100000001b3ull;
    }
    return h;
}

static void check_world(int test)
{
    for (int i = 0; i < (int)sizeof(buf); i++) {
        if (buf[i] != (uint8_t)(i * 7 + 3)) {
            printf("[wp-victim] FAIL test %d: buf[%d]=0x%02x corrupted\n",
                   test, i, buf[i]);
            failures++;
            break;
        }
    }
    if (memcmp(wp_rodata, rodata_copy, sizeof(rodata_copy)) != 0) {
        printf("[wp-victim] FAIL test %d: read-only data corrupted\n", test);
        failures++;
    }
    if (memcmp(wp_victim_code, victim_copy, sizeof(victim_copy)) != 0 ||
        wp_victim() != 42) {
        printf("[wp-victim] FAIL test %d: code page corrupted\n", test);
        failures++;
    }
}

static void run(int test, void *target, void *b, uint64_t len)
{
    uint64_t mask = wp_trigger(test, (uint64_t)(uintptr_t)target, b, len);
    check_world(test);
    printf("[wp-victim] test %2d regmask=0x%05" PRIx64 " bufsum=%016" PRIx64
           "\n", test, mask, fnv(buf, sizeof(buf)));
    if (mask) {
        printf("[wp-victim] FAIL test %d: registers changed across the "
               "excursion (mask 0x%" PRIx64 ")\n", test, mask);
        failures++;
    }
}

int main(void)
{
    static const int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP };
    for (unsigned i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        signal(sigs[i], on_signal);
    }
    setvbuf(stdout, NULL, _IOLBF, 0);

    fill_buf();
    memcpy(victim_copy, wp_victim_code, sizeof(victim_copy));
    memcpy(rodata_copy, wp_rodata, sizeof(rodata_copy));

    /* an unmapped page */
    void *hole = mmap(NULL, 4096, PROT_READ | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(hole, 4096);

    /* 16 nops, then a 10-byte movabs straddling into a PROT_NONE page */
    uint8_t *pg = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pg == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    memset(pg, 0x90, 8192);
    uint8_t *st = pg + 4096 - 3;
    st[0] = 0x48;
    st[1] = 0xb8;
    mprotect(pg, 4096, PROT_READ | PROT_EXEC);
    mprotect(pg + 4096, 4096, PROT_NONE);

    run(T1_STORE, wp_store, buf, sizeof(buf));
    run(T1_RO, wp_store_ro, (void *)wp_rodata, sizeof(rodata_copy));
    run(T2_REGS, wp_clobber, buf, sizeof(buf));
    run(T3_FETCH_UNMAPPED, hole, buf, sizeof(buf));
    run(T3_STRADDLE, st - 16, buf, sizeof(buf));
    run(T3_UD, wp_ud, buf, sizeof(buf));
    run(T3_DIV0, wp_div, buf, sizeof(buf));
    run(T3_PRIV, wp_priv, buf, sizeof(buf));
    run(T3_INT3, wp_int3, buf, sizeof(buf));
    run(T3_LOAD_UNMAPPED, wp_load_unmapped, buf, sizeof(buf));
    run(T3_SYSCALL, wp_syscall, buf, sizeof(buf));
    run(T4_LOOP, wp_loop, buf, sizeof(buf));
    run(T4_REP, wp_rep, buf, sizeof(buf));
    run(T5_REPEAT, wp_store, buf, sizeof(buf));

    /* The correct path uses the same code the wrong path ran. */
    printf("[wp-victim] victim=%d\n", wp_victim());
    printf("[wp-victim] %s (%d failures)\n",
           failures ? "FAILED" : "done", failures);
    return failures ? 1 : 0;
}
