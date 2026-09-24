/*
 * Wrong-path victim program for the wp-assert test plugin (riscv64).
 *
 * The riscv64 port of tests/tcg/x86_64/wp-victim.c; see that file and
 * tests/tcg/plugins/wp-assert.c for the contract.  The guest calls
 * wp_trigger(test, target, buf, len) once per test.  The trigger loads a
 * known pattern into every integer register it may (all but zero, sp, gp,
 * tp and the four argument registers), all 32 FP registers, then executes
 * the marker (slti x0, x0, 0x575: a HINT encoding, architecturally a NOP).
 * The plugin drives the wrong-path excursion at @target before the marker
 * executes.  After the marker the trigger stores the whole register file
 * and wp_check() compares it with what was loaded, returning a bitmask of
 * mismatches (bit N = xN, bit 32 = any FP register, bit 33 = fcsr).
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
    T1_STORE = 1, T1_RO, T2_REGS, T3_FETCH_UNMAPPED, T3_STRADDLE,
    T3_UD,             /* the all-zero word: defined illegal */
    T3_DIV0,           /* div by zero: architecturally all-ones, no trap */
    T3_PRIV,           /* csrr mstatus in U-mode */
    T3_INT3,           /* ebreak */
    T3_LOAD_UNMAPPED, T3_SYSCALL, T4_LOOP,
    T4_REP,            /* no subject on RISC-V: never run (SKIP) */
    T5_REPEAT, T_LAST
};

/* x-register patterns; zero, sp, gp, tp and a0..a3 are not loaded */
const uint64_t wp_pats[32] = {
    0, 0x5750010101010101ull, 0, 0, 0,
    0x5750050505050505ull, 0x5750060606060606ull, 0x5750070707070707ull,
    0x5750080808080808ull, 0x5750090909090909ull, 0, 0, 0, 0,
    0x57500e0e0e0e0e0eull, 0x57500f0f0f0f0f0full, 0x5750101010101010ull,
    0x5750111111111111ull, 0x5750121212121212ull, 0x5750131313131313ull,
    0x5750141414141414ull, 0x5750151515151515ull, 0x5750161616161616ull,
    0x5750171717171717ull, 0x5750181818181818ull, 0x5750191919191919ull,
    0x57501a1a1a1a1a1aull, 0x57501b1b1b1b1b1bull, 0x57501c1c1c1c1c1cull,
    0x57501d1d1d1d1d1dull, 0x57501e1e1e1e1e1eull, 0x57501f1f1f1f1f1full,
};
const uint64_t wp_fpat = 0x0123456789abcdefull;

extern uint64_t wp_trigger(uint64_t test, uint64_t target, void *buf,
                           uint64_t len);
extern char wp_store[], wp_store_ro[], wp_clobber[], wp_ud[], wp_div[],
            wp_priv[], wp_int3[], wp_load_unmapped[], wp_syscall[],
            wp_loop[], wp_victim_code[];
extern const uint64_t wp_rodata[8];
extern int wp_victim(void);

/*
 * Frame layout of wp_trigger (sp-relative):
 *   0  ra, s0..s11, gp, tp (15 x 8)    128 fs0..fs11 (12 x 8)
 * 224  a0..a3 at entry                  256 sp at entry to the marker
 * 264  fcsr before                      272 gp  280 tp (before)
 * 288  POST: x0..x31 (256 bytes)        544 fcsr after
 * 552  f0..f31 after (256 bytes)
 */
#define F_ARGS 224
#define F_SP   256
#define F_FCSR 264
#define F_GP   272
#define F_TP   280
#define F_POST 288
#define F_FCSP 544
#define F_F    552

uint64_t wp_check(const uint8_t *f);

__asm__(
    ".option push\n"
    ".option norelax\n"
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
    "  addi sp, sp, -1024\n"
    "  sd ra, 0(sp)\n  sd s0, 8(sp)\n  sd s1, 16(sp)\n  sd s2, 24(sp)\n"
    "  sd s3, 32(sp)\n  sd s4, 40(sp)\n  sd s5, 48(sp)\n  sd s6, 56(sp)\n"
    "  sd s7, 64(sp)\n  sd s8, 72(sp)\n  sd s9, 80(sp)\n  sd s10, 88(sp)\n"
    "  sd s11, 96(sp)\n  sd gp, 104(sp)\n  sd tp, 112(sp)\n"
    "  fsd fs0, 128(sp)\n  fsd fs1, 136(sp)\n  fsd fs2, 144(sp)\n"
    "  fsd fs3, 152(sp)\n  fsd fs4, 160(sp)\n  fsd fs5, 168(sp)\n"
    "  fsd fs6, 176(sp)\n  fsd fs7, 184(sp)\n  fsd fs8, 192(sp)\n"
    "  fsd fs9, 200(sp)\n  fsd fs10, 208(sp)\n  fsd fs11, 216(sp)\n"
    "  sd a0, 224(sp)\n  sd a1, 232(sp)\n  sd a2, 240(sp)\n  sd a3, 248(sp)\n"
    "  sd sp, 256(sp)\n"
    "  frcsr t0\n  sd t0, 264(sp)\n"
    "  sd gp, 272(sp)\n  sd tp, 280(sp)\n"
    "  lla t0, wp_fpat\n"
#define FLD(n) "  fld f" #n ", 0(t0)\n"
    FLD(0) FLD(1) FLD(2) FLD(3) FLD(4) FLD(5) FLD(6) FLD(7) FLD(8) FLD(9)
    FLD(10) FLD(11) FLD(12) FLD(13) FLD(14) FLD(15) FLD(16) FLD(17)
    FLD(18) FLD(19) FLD(20) FLD(21) FLD(22) FLD(23) FLD(24) FLD(25)
    FLD(26) FLD(27) FLD(28) FLD(29) FLD(30) FLD(31)
    "  lla t0, wp_pats\n"
#define LDP(n) "  ld x" #n ", " #n "*8(t0)\n"
    LDP(1) LDP(6) LDP(7) LDP(8) LDP(9) LDP(14) LDP(15) LDP(16) LDP(17)
    LDP(18) LDP(19) LDP(20) LDP(21) LDP(22) LDP(23) LDP(24) LDP(25)
    LDP(26) LDP(27) LDP(28) LDP(29) LDP(30) LDP(31)
    "  ld x5, 5*8(x5)\n"
    ".globl wp_marker\n"
    "wp_marker:\n"
    "  .4byte 0x57502013\n"             /* slti x0, x0, 0x575 */
#define SDP(n) "  sd x" #n ", 288+" #n "*8(sp)\n"
    SDP(0) SDP(1) SDP(2) SDP(3) SDP(4) SDP(5) SDP(6) SDP(7) SDP(8) SDP(9)
    SDP(10) SDP(11) SDP(12) SDP(13) SDP(14) SDP(15) SDP(16) SDP(17)
    SDP(18) SDP(19) SDP(20) SDP(21) SDP(22) SDP(23) SDP(24) SDP(25)
    SDP(26) SDP(27) SDP(28) SDP(29) SDP(30) SDP(31)
    "  frcsr t0\n  sd t0, 544(sp)\n"
#define FSD(n) "  fsd f" #n ", 552+" #n "*8(sp)\n"
    FSD(0) FSD(1) FSD(2) FSD(3) FSD(4) FSD(5) FSD(6) FSD(7) FSD(8) FSD(9)
    FSD(10) FSD(11) FSD(12) FSD(13) FSD(14) FSD(15) FSD(16) FSD(17)
    FSD(18) FSD(19) FSD(20) FSD(21) FSD(22) FSD(23) FSD(24) FSD(25)
    FSD(26) FSD(27) FSD(28) FSD(29) FSD(30) FSD(31)
    "  ld gp, 104(sp)\n  ld tp, 112(sp)\n"
    "  mv a0, sp\n"
    "  call wp_check\n"
    "  ld ra, 0(sp)\n  ld s0, 8(sp)\n  ld s1, 16(sp)\n  ld s2, 24(sp)\n"
    "  ld s3, 32(sp)\n  ld s4, 40(sp)\n  ld s5, 48(sp)\n  ld s6, 56(sp)\n"
    "  ld s7, 64(sp)\n  ld s8, 72(sp)\n  ld s9, 80(sp)\n  ld s10, 88(sp)\n"
    "  ld s11, 96(sp)\n"
    "  fld fs0, 128(sp)\n  fld fs1, 136(sp)\n  fld fs2, 144(sp)\n"
    "  fld fs3, 152(sp)\n  fld fs4, 160(sp)\n  fld fs5, 168(sp)\n"
    "  fld fs6, 176(sp)\n  fld fs7, 184(sp)\n  fld fs8, 192(sp)\n"
    "  fld fs9, 200(sp)\n  fld fs10, 208(sp)\n  fld fs11, 216(sp)\n"
    "  addi sp, sp, 1024\n"
    "  ret\n"

    /* ---------------- wrong-path-only code ---------------- */
    ".p2align 6\n"
    ".globl wp_store\n"
    "wp_store:\n"                       /* a2 = buf (len 4096) */
    "  li t0, 0x1122334455667788\n"
    "  sd t0, 0(a2)\n"
    "  ld t1, 0(a2)\n"                  /* must forward from the sandbox */
    "  sd t1, 8(a2)\n"
    "  li t2, 0xa5a5a5a5\n  sw t2, 64(a2)\n"
    "  li t3, 0x5a\n  li t4, 4095\n  add t4, a2, t4\n  sb t3, 0(t4)\n"
    "  fsd ft0, 128(a2)\n"
    "  j wp_clobber\n"

    ".p2align 6\n"
    ".globl wp_store_ro\n"
    "wp_store_ro:\n"                    /* a2 = wp_rodata */
    "  li t0, -1\n"
    "  sd t0, 0(a2)\n"
    "  sd t0, 56(a2)\n"
    "  lla t1, wp_victim_code\n  sd t0, 0(t1)\n"
    "  ld t2, 0(a2)\n"
    "  j wp_spin\n"

    ".p2align 6\n"
    ".globl wp_clobber\n"
    "wp_clobber:\n"
    "  li t0, -1\n"
#define FCLOB(n) "  fmv.d.x f" #n ", t0\n"
    FCLOB(0) FCLOB(1) FCLOB(2) FCLOB(3) FCLOB(4) FCLOB(5) FCLOB(6)
    FCLOB(7) FCLOB(8) FCLOB(9) FCLOB(10) FCLOB(11) FCLOB(12) FCLOB(13)
    FCLOB(14) FCLOB(15) FCLOB(16) FCLOB(17) FCLOB(18) FCLOB(19) FCLOB(20)
    FCLOB(21) FCLOB(22) FCLOB(23) FCLOB(24) FCLOB(25) FCLOB(26) FCLOB(27)
    FCLOB(28) FCLOB(29) FCLOB(30) FCLOB(31)
    "  fsrmi 1\n"                       /* frm = RTZ */
    "  li sp, 0x10000\n"
#define XCLOB(n) "  li x" #n ", 0xdeadbeefcafe00" #n "\n"
    XCLOB(1) XCLOB(3) XCLOB(4) XCLOB(5) XCLOB(6) XCLOB(7) XCLOB(8)
    XCLOB(9) XCLOB(10) XCLOB(11) XCLOB(12) XCLOB(13) XCLOB(14) XCLOB(15)
    XCLOB(16) XCLOB(17) XCLOB(18) XCLOB(19) XCLOB(20) XCLOB(21)
    XCLOB(22) XCLOB(23) XCLOB(24) XCLOB(25) XCLOB(26) XCLOB(27)
    XCLOB(28) XCLOB(29) XCLOB(30) XCLOB(31)
    "  j wp_spin\n"

    ".globl wp_spin\n"
    "wp_spin:\n"
    "  j wp_spin\n"

    ".p2align 4\n"
    ".globl wp_ud\n"
    "wp_ud:\n"
    "  .4byte 0\n"
    "  j wp_spin\n"

    ".p2align 4\n"
    ".globl wp_div\n"
    "wp_div:\n"
    "  li t0, 1\n  li t1, 0\n"
    "  div t2, t0, t1\n"
    "  sd t2, 24(a2)\n"
    "  j wp_spin\n"

    ".p2align 4\n"
    ".globl wp_priv\n"
    "wp_priv:\n"
    "  csrr t0, mstatus\n"
    "  j wp_spin\n"

    ".p2align 4\n"
    ".globl wp_int3\n"
    "wp_int3:\n"
    "  ebreak\n"
    "  j wp_spin\n"

    ".p2align 4\n"
    ".globl wp_load_unmapped\n"
    "wp_load_unmapped:\n"
    "  li t0, 0x10\n"
    "  ld t1, 0(t0)\n"
    "  sd t1, 24(a2)\n"
    "  j wp_spin\n"

    ".p2align 4\n"
    ".globl wp_syscall\n"
    "wp_syscall:\n"
    "  li a7, 64\n  li a0, 1\n"         /* write(1, msg, 21) */
    "  lla a1, wp_leakmsg\n  li a2, 21\n"
    "  ecall\n"
    "  li a7, 93\n  li a0, 77\n"        /* exit(77) */
    "  ecall\n"
    "  j wp_spin\n"

    ".p2align 4\n"
    ".globl wp_loop\n"
    "wp_loop:\n"
    "  ld t0, 16(a2)\n"
    "  addi t0, t0, 1\n"
    "  sd t0, 16(a2)\n"
    "  addi a0, a0, 1\n"
    "  j wp_loop\n"

    /* correct-path code the wrong path tries to overwrite */
    ".p2align 6\n"
    ".globl wp_victim\n"
    ".globl wp_victim_code\n"
    "wp_victim:\n"
    "wp_victim_code:\n"
    "  li a0, 42\n"
    "  ret\n"
    "  .4byte 0x00000013, 0x00000013, 0x00000013\n"
    ".option pop\n"
);

uint64_t wp_check(const uint8_t *f)
{
    const uint64_t *post = (const uint64_t *)(f + F_POST);
    const uint64_t *args = (const uint64_t *)(f + F_ARGS);
    uint64_t mask = 0;

    for (int i = 1; i < 32; i++) {
        uint64_t want;
        switch (i) {
        case 2:  want = *(const uint64_t *)(f + F_SP); break;
        case 3:  want = *(const uint64_t *)(f + F_GP); break;
        case 4:  want = *(const uint64_t *)(f + F_TP); break;
        case 10: case 11: case 12: case 13: want = args[i - 10]; break;
        default: want = wp_pats[i]; break;
        }
        if (post[i] != want) {
            mask |= 1ull << i;
        }
    }
    for (int i = 0; i < 32; i++) {
        if (((const uint64_t *)(f + F_F))[i] != wp_fpat) {
            mask |= 1ull << 32;
        }
    }
    if (*(const uint64_t *)(f + F_FCSP) != *(const uint64_t *)(f + F_FCSR)) {
        mask |= 1ull << 33;
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

    /*
     * 16 compressed nops, then a 4-byte instruction whose second half lies
     * in a PROT_NONE page: a genuine page-straddling instruction (the C
     * extension allows 2-byte alignment), the same subject as x86's.
     */
    uint16_t *pgh = (uint16_t *)pg;
    for (int i = 0; i < 2048; i++) {
        pgh[i] = 0x0001;                /* c.nop */
    }
    pgh[2047] = 0x0013;                 /* low half of addi x0, x0, 0 */
    mprotect(pg, 4096, PROT_READ | PROT_EXEC);
    mprotect((uint8_t *)pg + 4096, 4096, PROT_NONE);
    __builtin___clear_cache((char *)pg, (char *)pg + 4096);

    run(T1_STORE, wp_store, buf, sizeof(buf));
    run(T1_RO, wp_store_ro, (void *)wp_rodata, sizeof(rodata_copy));
    run(T2_REGS, wp_clobber, buf, sizeof(buf));
    run(T3_FETCH_UNMAPPED, hole, buf, sizeof(buf));
    run(T3_STRADDLE, (uint8_t *)pg + 4096 - 2 - 32, buf, sizeof(buf));
    run(T3_UD, wp_ud, buf, sizeof(buf));
    run(T3_DIV0, wp_div, buf, sizeof(buf));
    run(T3_PRIV, wp_priv, buf, sizeof(buf));
    run(T3_INT3, wp_int3, buf, sizeof(buf));
    run(T3_LOAD_UNMAPPED, wp_load_unmapped, buf, sizeof(buf));
    run(T3_SYSCALL, wp_syscall, buf, sizeof(buf));
    run(T4_LOOP, wp_loop, buf, sizeof(buf));
    /* T4_REP: RISC-V has no repeat-string instruction; the plugin SKIPs it */
    run(T5_REPEAT, wp_store, buf, sizeof(buf));

    /* The correct path uses the same code the wrong path ran. */
    printf("[wp-victim] victim=%d\n", wp_victim());
    printf("[wp-victim] %s (%d failures)\n",
           failures ? "FAILED" : "done", failures);
    return failures ? 1 : 0;
}
