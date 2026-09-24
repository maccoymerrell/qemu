/*
 * Wrong-path victim program for the wp-assert test plugin (aarch64).
 *
 * The aarch64 port of tests/tcg/x86_64/wp-victim.c; see that file and
 * tests/tcg/plugins/wp-assert.c for the contract.  The guest calls
 * wp_trigger(test, target, buf, len) once per test.  The trigger loads a
 * known pattern into every general register it may, all 32 vector
 * registers and NZCV, then executes the marker (hint #0x7f, an
 * unallocated hint that executes as a NOP).  The plugin drives the
 * wrong-path excursion at @target before the marker executes.  After the
 * marker the trigger stores the whole register file and wp_check()
 * compares it with what was loaded, returning a bitmask of mismatches
 * (bit N = xN, bit 31 = sp, 32 = NZCV, 33 = FPCR, 34 = any vector
 * register).
 *
 * The wrong-path routines (wp_*) are never executed by the correct path.
 * Every line this program prints is a deterministic function of the
 * correct path, so its output must be byte-identical with and without the
 * plugin.
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
    T1_STORE = 1, T1_RO, T2_REGS, T3_FETCH_UNMAPPED, T3_STRADDLE, T3_UD,
    T3_DIV0,           /* udiv by zero: architecturally 0, no exception */
    T3_PRIV,           /* mrs sctlr_el1 at EL0 */
    T3_INT3,           /* brk #0 */
    T3_LOAD_UNMAPPED, T3_SYSCALL, T4_LOOP,
    T4_REP,            /* SETP/SETM/SETE (FEAT_MOPS), Xn = 16 MiB */
    T5_REPEAT, T_LAST
};

#define NZCV_PAT 0x60000000ull          /* Z and C set */

/* x-register patterns; x0..x3 carry the arguments and are not loaded */
const uint64_t wp_pats[31] = {
    0, 0, 0, 0,
    0x5750040404040404ull, 0x5750050505050505ull, 0x5750060606060606ull,
    0x5750070707070707ull, 0x5750080808080808ull, 0x5750090909090909ull,
    0x57500a0a0a0a0a0aull, 0x57500b0b0b0b0b0bull, 0x57500c0c0c0c0c0cull,
    0x57500d0d0d0d0d0dull, 0x57500e0e0e0e0e0eull, 0x57500f0f0f0f0f0full,
    0x5750101010101010ull, 0x5750111111111111ull, 0x5750121212121212ull,
    0x5750131313131313ull, 0x5750141414141414ull, 0x5750151515151515ull,
    0x5750161616161616ull, 0x5750171717171717ull, 0x5750181818181818ull,
    0x5750191919191919ull, 0x57501a1a1a1a1a1aull, 0x57501b1b1b1b1b1bull,
    0x57501c1c1c1c1c1cull, 0x57501d1d1d1d1d1dull, 0x57501e1e1e1e1e1eull,
};
const uint8_t wp_xpat[16] __attribute__((aligned(16))) = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
};

extern uint64_t wp_trigger(uint64_t test, uint64_t target, void *buf,
                           uint64_t len);
extern char wp_store[], wp_store_ro[], wp_clobber[], wp_ud[], wp_div[],
            wp_priv[], wp_int3[], wp_load_unmapped[], wp_syscall[],
            wp_loop[], wp_rep[], wp_victim_code[];
extern const uint64_t wp_rodata[8];
extern int wp_victim(void);

/*
 * Frame layout of wp_trigger (sp-relative):
 *   0  x19..x30 (callee-saved + lr)     96  d8..d15
 * 160  x0..x3 at entry                  192 sp at entry to the marker
 * 200  FPCR before                      256 POST: x0..x30
 * 504  sp after                         512 NZCV after
 * 520  FPCR after                       528 q0..q31 after (512 bytes)
 */
#define F_ARGS 160
#define F_SP   192
#define F_FPCR 200
#define F_POST 256
#define F_SPP  504
#define F_NZCV 512
#define F_FPCP 520
#define F_Q    528
#define F_SIZE 1152

uint64_t wp_check(const uint8_t *f);

__asm__(
    ".arch armv8.8-a+mops\n"
    ".section .rodata\n"
    ".p2align 3\n"
    "wp_leakmsg: .ascii \"LEAK-FROM-WRONG-PATH\\n\"\n"
    ".p2align 6\n"
    ".globl wp_rodata\n"
    "wp_rodata:\n"
    "  .quad 1, 2, 3, 4, 5, 6, 7, 8\n"

    ".text\n"
    ".globl wp_trigger\n"
    ".p2align 4\n"
    "wp_trigger:\n"
    "  sub sp, sp, #1152\n"
    "  stp x19, x20, [sp, #0]\n  stp x21, x22, [sp, #16]\n"
    "  stp x23, x24, [sp, #32]\n  stp x25, x26, [sp, #48]\n"
    "  stp x27, x28, [sp, #64]\n  stp x29, x30, [sp, #80]\n"
    "  stp d8, d9, [sp, #96]\n  stp d10, d11, [sp, #112]\n"
    "  stp d12, d13, [sp, #128]\n  stp d14, d15, [sp, #144]\n"
    "  stp x0, x1, [sp, #160]\n  stp x2, x3, [sp, #176]\n"
    "  mov x9, sp\n  str x9, [sp, #192]\n"
    "  mrs x9, fpcr\n  str x9, [sp, #200]\n"
    "  adrp x9, wp_xpat\n  add x9, x9, :lo12:wp_xpat\n"
    "  ld1 {v0.16b}, [x9]\n"
#define VMOV(n) "  mov v" #n ".16b, v0.16b\n"
    VMOV(1) VMOV(2) VMOV(3) VMOV(4) VMOV(5) VMOV(6) VMOV(7) VMOV(8)
    VMOV(9) VMOV(10) VMOV(11) VMOV(12) VMOV(13) VMOV(14) VMOV(15)
    VMOV(16) VMOV(17) VMOV(18) VMOV(19) VMOV(20) VMOV(21) VMOV(22)
    VMOV(23) VMOV(24) VMOV(25) VMOV(26) VMOV(27) VMOV(28) VMOV(29)
    VMOV(30) VMOV(31)
    "  mov x9, #0x60000000\n  msr nzcv, x9\n"
    "  adrp x9, wp_pats\n  add x9, x9, :lo12:wp_pats\n"
#define LDP(n) "  ldr x" #n ", [x9, #" #n "*8]\n"
    LDP(4) LDP(5) LDP(6) LDP(7) LDP(8) LDP(10) LDP(11) LDP(12) LDP(13)
    LDP(14) LDP(15) LDP(16) LDP(17) LDP(18) LDP(19) LDP(20) LDP(21)
    LDP(22) LDP(23) LDP(24) LDP(25) LDP(26) LDP(27) LDP(28) LDP(29)
    LDP(30)
    "  ldr x9, [x9, #9*8]\n"
    ".globl wp_marker\n"
    "wp_marker:\n"
    "  hint #0x7f\n"
    /*
     * End the marker's TB here, so an exception a faulty walker leaves
     * pending is taken with the wrong path's registers still in place
     * (the red controls rely on it); the branch changes no register.
     */
    "  b 1f\n"
    "1:\n"
    "  stp x0, x1, [sp, #256]\n  stp x2, x3, [sp, #272]\n"
    "  stp x4, x5, [sp, #288]\n  stp x6, x7, [sp, #304]\n"
    "  stp x8, x9, [sp, #320]\n  stp x10, x11, [sp, #336]\n"
    "  stp x12, x13, [sp, #352]\n  stp x14, x15, [sp, #368]\n"
    "  stp x16, x17, [sp, #384]\n  stp x18, x19, [sp, #400]\n"
    "  stp x20, x21, [sp, #416]\n  stp x22, x23, [sp, #432]\n"
    "  stp x24, x25, [sp, #448]\n  stp x26, x27, [sp, #464]\n"
    "  stp x28, x29, [sp, #480]\n  str x30, [sp, #496]\n"
    "  mov x9, sp\n  str x9, [sp, #504]\n"
    "  mrs x9, nzcv\n  str x9, [sp, #512]\n"
    "  mrs x9, fpcr\n  str x9, [sp, #520]\n"
    "  add x9, sp, #528\n"
    "  st1 {v0.16b, v1.16b, v2.16b, v3.16b}, [x9], #64\n"
    "  st1 {v4.16b, v5.16b, v6.16b, v7.16b}, [x9], #64\n"
    "  st1 {v8.16b, v9.16b, v10.16b, v11.16b}, [x9], #64\n"
    "  st1 {v12.16b, v13.16b, v14.16b, v15.16b}, [x9], #64\n"
    "  st1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x9], #64\n"
    "  st1 {v20.16b, v21.16b, v22.16b, v23.16b}, [x9], #64\n"
    "  st1 {v24.16b, v25.16b, v26.16b, v27.16b}, [x9], #64\n"
    "  st1 {v28.16b, v29.16b, v30.16b, v31.16b}, [x9], #64\n"
    "  mov x0, sp\n"
    "  bl wp_check\n"
    "  ldp x19, x20, [sp, #0]\n  ldp x21, x22, [sp, #16]\n"
    "  ldp x23, x24, [sp, #32]\n  ldp x25, x26, [sp, #48]\n"
    "  ldp x27, x28, [sp, #64]\n  ldp x29, x30, [sp, #80]\n"
    "  ldp d8, d9, [sp, #96]\n  ldp d10, d11, [sp, #112]\n"
    "  ldp d12, d13, [sp, #128]\n  ldp d14, d15, [sp, #144]\n"
    "  add sp, sp, #1152\n"
    "  ret\n"

    /* ---------------- wrong-path-only code ---------------- */
    ".p2align 6\n"
    ".globl wp_store\n"
    "wp_store:\n"                       /* x2 = buf (len 4096) */
    "  movz x4, #0x7788\n  movk x4, #0x5566, lsl #16\n"
    "  movk x4, #0x3344, lsl #32\n  movk x4, #0x1122, lsl #48\n"
    "  str x4, [x2]\n"
    "  ldr x5, [x2]\n"                  /* must forward from the sandbox */
    "  str x5, [x2, #8]\n"
    "  movz w6, #0xa5a5\n  movk w6, #0xa5a5, lsl #16\n"
    "  str w6, [x2, #64]\n"
    "  mov w7, #0x5a\n  strb w7, [x2, #4095]\n"
    "  str q0, [x2, #128]\n"
    "  b wp_clobber\n"

    ".p2align 6\n"
    ".globl wp_store_ro\n"
    "wp_store_ro:\n"                    /* x2 = wp_rodata */
    "  mov x4, #-1\n"
    "  str x4, [x2]\n"
    "  str x4, [x2, #56]\n"
    "  adr x5, wp_victim_code\n  str x4, [x5]\n"
    "  ldr x6, [x2]\n"
    "  b wp_spin\n"

    ".p2align 6\n"
    ".globl wp_clobber\n"
    "wp_clobber:\n"
    "  movi v0.16b, #0xff\n"
#define VCLOB(n) "  movi v" #n ".16b, #0xff\n"
    VCLOB(1) VCLOB(2) VCLOB(3) VCLOB(4) VCLOB(5) VCLOB(6) VCLOB(7)
    VCLOB(8) VCLOB(9) VCLOB(10) VCLOB(11) VCLOB(12) VCLOB(13) VCLOB(14)
    VCLOB(15) VCLOB(16) VCLOB(17) VCLOB(18) VCLOB(19) VCLOB(20) VCLOB(21)
    VCLOB(22) VCLOB(23) VCLOB(24) VCLOB(25) VCLOB(26) VCLOB(27) VCLOB(28)
    VCLOB(29) VCLOB(30) VCLOB(31)
    "  movz x9, #0x00c0, lsl #16\n  msr fpcr, x9\n"   /* RMode = RZ */
    "  movz x9, #0x9000, lsl #16\n  msr nzcv, x9\n"   /* N and V */
    "  movz x9, #1, lsl #16\n  mov sp, x9\n"
#define XCLOB(n) "  movz x" #n ", #0xbe" #n ", lsl #48\n"
    XCLOB(0) XCLOB(1) XCLOB(2) XCLOB(3) XCLOB(4) XCLOB(5) XCLOB(6)
    XCLOB(7) XCLOB(8) XCLOB(9) XCLOB(10) XCLOB(11) XCLOB(12) XCLOB(13)
    XCLOB(14) XCLOB(15) XCLOB(16) XCLOB(17) XCLOB(18) XCLOB(19)
    XCLOB(20) XCLOB(21) XCLOB(22) XCLOB(23) XCLOB(24) XCLOB(25)
    XCLOB(26) XCLOB(27) XCLOB(28) XCLOB(29) XCLOB(30)
    "  b wp_spin\n"

    ".globl wp_spin\n"
    "wp_spin:\n"
    "  b wp_spin\n"

    ".p2align 4\n"
    ".globl wp_ud\n"
    "wp_ud:\n"
    "  udf #0\n"
    "  b wp_spin\n"

    ".p2align 4\n"
    ".globl wp_div\n"
    "wp_div:\n"
    "  mov x4, #1\n  mov x5, #0\n"
    "  udiv x6, x4, x5\n"
    "  str x6, [x2, #24]\n"
    "  b wp_spin\n"

    ".p2align 4\n"
    ".globl wp_priv\n"
    "wp_priv:\n"
    "  mrs x4, sctlr_el1\n"
    "  b wp_spin\n"

    ".p2align 4\n"
    ".globl wp_int3\n"
    "wp_int3:\n"
    "  brk #0\n"
    "  b wp_spin\n"

    ".p2align 4\n"
    ".globl wp_load_unmapped\n"
    "wp_load_unmapped:\n"
    "  mov x4, #0x10\n"
    "  ldr x5, [x4]\n"
    "  str x5, [x2, #24]\n"
    "  b wp_spin\n"

    ".p2align 4\n"
    ".globl wp_syscall\n"
    "wp_syscall:\n"
    "  mov x8, #64\n  mov x0, #1\n"      /* write(1, msg, 21) */
    "  adr x1, wp_leakmsg\n  mov x2, #21\n"
    "  svc #0\n"
    "  mov x8, #93\n  mov x0, #77\n"     /* exit(77) */
    "  svc #0\n"
    "  b wp_spin\n"

    ".p2align 4\n"
    ".globl wp_loop\n"
    "wp_loop:\n"
    "  ldr x4, [x2, #16]\n"
    "  add x4, x4, #1\n"
    "  str x4, [x2, #16]\n"
    "  add x0, x0, #1\n"
    "  b wp_loop\n"

    ".p2align 4\n"
    ".globl wp_rep\n"
    "wp_rep:\n"
    "  mov x4, x2\n"
    "  movz x5, #0x100, lsl #16\n"      /* 16 MiB */
    "  mov x6, #0x77\n"
    "  setp [x4]!, x5!, x6\n"
    "  setm [x4]!, x5!, x6\n"
    "  sete [x4]!, x5!, x6\n"
    "  b wp_spin\n"

    /* correct-path code the wrong path tries to overwrite */
    ".p2align 6\n"
    ".globl wp_victim\n"
    ".globl wp_victim_code\n"
    "wp_victim:\n"
    "wp_victim_code:\n"
    "  mov w0, #42\n"
    "  ret\n"
    "  nop\n  nop\n  nop\n  nop\n"
);

uint64_t wp_check(const uint8_t *f)
{
    const uint64_t *post = (const uint64_t *)(f + F_POST);
    const uint64_t *args = (const uint64_t *)(f + F_ARGS);
    uint64_t mask = 0;

    for (int i = 0; i <= 30; i++) {
        uint64_t want = i < 4 ? args[i] : wp_pats[i];
        if (post[i] != want) {
            mask |= 1ull << i;
        }
    }
    if (*(const uint64_t *)(f + F_SPP) != *(const uint64_t *)(f + F_SP)) {
        mask |= 1ull << 31;
    }
    if ((*(const uint64_t *)(f + F_NZCV) & 0xf0000000ull) != NZCV_PAT) {
        mask |= 1ull << 32;
    }
    if (*(const uint64_t *)(f + F_FPCP) != *(const uint64_t *)(f + F_FPCR)) {
        mask |= 1ull << 33;
    }
    for (int i = 0; i < 32; i++) {
        if (memcmp(f + F_Q + 16 * i, wp_xpat, 16) != 0) {
            mask |= 1ull << 34;
        }
    }
    return mask;
}

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
    printf("[wp-victim] test %2d regmask=0x%09" PRIx64 " bufsum=%016" PRIx64
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

    /*
     * One reservation, three pages: [hole][code][PROT_NONE].  The hole is
     * unmapped out of the reservation after the other two pages exist, so
     * no later mapping of this program can land on it.  (A separate
     * mmap+munmap is not enough: qemu-mipsel hands the freed address
     * straight back to the next mmap.)
     */
    uint8_t *res = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (res == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    void *hole = res;
    uint32_t *pg = (uint32_t *)(res + 4096);
    munmap(hole, 4096);

    /* 16 nops running off the end of an executable page into PROT_NONE */
    for (int i = 0; i < 2048; i++) {
        pg[i] = 0xd503201f;             /* nop */
    }
    mprotect(pg, 4096, PROT_READ | PROT_EXEC);
    mprotect((uint8_t *)pg + 4096, 4096, PROT_NONE);
    __builtin___clear_cache((char *)pg, (char *)pg + 4096);

    run(T1_STORE, wp_store, buf, sizeof(buf));
    run(T1_RO, wp_store_ro, (void *)wp_rodata, sizeof(rodata_copy));
    run(T2_REGS, wp_clobber, buf, sizeof(buf));
    run(T3_FETCH_UNMAPPED, hole, buf, sizeof(buf));
    run(T3_STRADDLE, (uint8_t *)pg + 4096 - 64, buf, sizeof(buf));
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
