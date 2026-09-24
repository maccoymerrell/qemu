/*
 * Wrong-path victim program for the wp-assert test plugin (mipsel, o32).
 *
 * The mipsel port of tests/tcg/x86_64/wp-victim.c; see that file and
 * tests/tcg/plugins/wp-assert.c for the contract.  The guest calls
 * wp_trigger(test, target, buf, len) once per test.  The trigger loads a
 * known pattern into every general register it may (all but $zero, $gp,
 * $sp and the four argument registers), LO, HI and all 32 FP registers,
 * then executes the marker (ori $zero, $zero, 0x5750: a write to $zero,
 * architecturally a NOP).  The plugin drives the wrong-path excursion at
 * @target before the marker executes.  After the marker the trigger
 * stores the whole register file and wp_check() compares it with what was
 * loaded, returning a bitmask of mismatches (bit N = $N, bit 32 = LO,
 * 33 = HI, 34 = FCSR, 35 = any FP register).
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
    T3_UD,             /* SD: a MIPS64 opcode, reserved on MIPS32 */
    T3_DIV0,           /* div + teq $divisor, $zero, 7 (the gcc idiom) */
    T3_PRIV,           /* mfc0 in user mode: coprocessor unusable */
    T3_INT3,           /* break */
    T3_LOAD_UNMAPPED, T3_SYSCALL, T4_LOOP,
    T4_REP,            /* no subject on MIPS32: never run (SKIP) */
    T5_REPEAT, T_LAST
};

/* $N patterns; $zero, $a0..$a3, $gp and $sp are not loaded */
const uint32_t wp_pats[32] = {
    0, 0x57500101, 0x57500202, 0x57500303, 0, 0, 0, 0,
    0x57500808, 0x57500909, 0x57500a0a, 0x57500b0b, 0x57500c0c,
    0x57500d0d, 0x57500e0e, 0x57500f0f, 0x57501010, 0x57501111,
    0x57501212, 0x57501313, 0x57501414, 0x57501515, 0x57501616,
    0x57501717, 0x57501818, 0x57501919, 0x57501a1a, 0x57501b1b, 0,
    0, 0x57501e1e, 0x57501f1f,
};
const uint32_t wp_lohi[2] = { 0x5750aaaa, 0x5750bbbb };
const uint32_t wp_fpat = 0x01234567;

extern uint64_t wp_trigger(uint32_t test, uint32_t target, void *buf,
                           uint32_t len);
extern char wp_store[], wp_store_ro[], wp_clobber[], wp_ud[], wp_div[],
            wp_priv[], wp_int3[], wp_load_unmapped[], wp_syscall[],
            wp_loop[], wp_victim_code[];
extern const uint32_t wp_rodata[16];
extern int wp_victim(void);

/*
 * Frame layout of wp_trigger (sp-relative; 0..15 is the o32 argument
 * home area wp_check may write):
 *  16  $s0..$s7   48 $s8   52 $ra   56 $gp   60 FCSR before
 *  64  $sp at the marker                     68 $a0..$a3 at entry
 *  88  $f20..$f31 (callee-saved FP)
 * 144  POST: $0..$31 (128 bytes)
 * 272  LO after   276 HI after   280 FCSR after
 * 288  $f0..$f31 after (128 bytes)
 */
#define F_GP   56
#define F_FCSR 60
#define F_SP   64
#define F_ARGS 68
#define F_POST 144
#define F_LO   272
#define F_HI   276
#define F_FCSP 280
#define F_F    288

uint64_t wp_check(const uint8_t *f);

__asm__(
    ".set push\n"
    ".set noreorder\n"
    ".set noat\n"
    /* all 32 single-precision registers (qemu-mipsel's default CPU is FR=0) */
    ".set oddspreg\n"
    ".section .rodata\n"
    ".p2align 3\n"
    "wp_leakmsg: .ascii \"LEAK-FROM-WRONG-PATH\\n\"\n"
    ".p2align 6\n"
    ".globl wp_rodata\n"
    "wp_rodata:\n"
    "  .word 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0\n"

    ".text\n"
    ".globl wp_trigger\n"
    ".p2align 4\n"
    ".ent wp_trigger\n"
    "wp_trigger:\n"
    "  addiu $sp, $sp, -448\n"
    "  sw $16, 16($sp)\n  sw $17, 20($sp)\n  sw $18, 24($sp)\n"
    "  sw $19, 28($sp)\n  sw $20, 32($sp)\n  sw $21, 36($sp)\n"
    "  sw $22, 40($sp)\n  sw $23, 44($sp)\n  sw $30, 48($sp)\n"
    "  sw $31, 52($sp)\n  sw $28, 56($sp)\n"
    "  cfc1 $8, $31\n  sw $8, 60($sp)\n"
    "  sw $sp, 64($sp)\n"
    "  sw $4, 68($sp)\n  sw $5, 72($sp)\n  sw $6, 76($sp)\n  sw $7, 80($sp)\n"
#define SWF(n, o) "  swc1 $f" #n ", " #o "($sp)\n"
    SWF(20, 88) SWF(21, 92) SWF(22, 96) SWF(23, 100) SWF(24, 104)
    SWF(25, 108) SWF(26, 112) SWF(27, 116) SWF(28, 120) SWF(29, 124)
    SWF(30, 128) SWF(31, 132)
    "  lui $25, %hi(wp_lohi)\n  addiu $25, $25, %lo(wp_lohi)\n"
    "  lw $1, 0($25)\n  mtlo $1\n  lw $1, 4($25)\n  mthi $1\n"
    "  lui $25, %hi(wp_fpat)\n  addiu $25, $25, %lo(wp_fpat)\n"
#define LWF(n) "  lwc1 $f" #n ", 0($25)\n"
    LWF(0) LWF(1) LWF(2) LWF(3) LWF(4) LWF(5) LWF(6) LWF(7) LWF(8) LWF(9)
    LWF(10) LWF(11) LWF(12) LWF(13) LWF(14) LWF(15) LWF(16) LWF(17)
    LWF(18) LWF(19) LWF(20) LWF(21) LWF(22) LWF(23) LWF(24) LWF(25)
    LWF(26) LWF(27) LWF(28) LWF(29) LWF(30) LWF(31)
    "  lui $25, %hi(wp_pats)\n  addiu $25, $25, %lo(wp_pats)\n"
#define LWP(n) "  lw $" #n ", " #n "*4($25)\n"
    LWP(1) LWP(2) LWP(3) LWP(8) LWP(9) LWP(10) LWP(11) LWP(12) LWP(13)
    LWP(14) LWP(15) LWP(16) LWP(17) LWP(18) LWP(19) LWP(20) LWP(21)
    LWP(22) LWP(23) LWP(24) LWP(26) LWP(27) LWP(30) LWP(31)
    "  lw $25, 25*4($25)\n"
    ".globl wp_marker\n"
    "wp_marker:\n"
    "  .word 0x34005750\n"              /* ori $zero, $zero, 0x5750 */
#define SWP(n) "  sw $" #n ", 144+" #n "*4($sp)\n"
    SWP(0) SWP(1) SWP(2) SWP(3) SWP(4) SWP(5) SWP(6) SWP(7) SWP(8) SWP(9)
    SWP(10) SWP(11) SWP(12) SWP(13) SWP(14) SWP(15) SWP(16) SWP(17)
    SWP(18) SWP(19) SWP(20) SWP(21) SWP(22) SWP(23) SWP(24) SWP(25)
    SWP(26) SWP(27) SWP(28) SWP(29) SWP(30) SWP(31)
    "  mflo $1\n  sw $1, 272($sp)\n  mfhi $1\n  sw $1, 276($sp)\n"
    "  cfc1 $1, $31\n  sw $1, 280($sp)\n"
#define SWFP(n) "  swc1 $f" #n ", 288+" #n "*4($sp)\n"
    SWFP(0) SWFP(1) SWFP(2) SWFP(3) SWFP(4) SWFP(5) SWFP(6) SWFP(7)
    SWFP(8) SWFP(9) SWFP(10) SWFP(11) SWFP(12) SWFP(13) SWFP(14)
    SWFP(15) SWFP(16) SWFP(17) SWFP(18) SWFP(19) SWFP(20) SWFP(21)
    SWFP(22) SWFP(23) SWFP(24) SWFP(25) SWFP(26) SWFP(27) SWFP(28)
    SWFP(29) SWFP(30) SWFP(31)
    "  lw $28, 56($sp)\n"
    "  move $4, $sp\n"
    "  lui $25, %hi(wp_check)\n  addiu $25, $25, %lo(wp_check)\n"
    "  jalr $25\n"
    "  nop\n"
    "  lw $16, 16($sp)\n  lw $17, 20($sp)\n  lw $18, 24($sp)\n"
    "  lw $19, 28($sp)\n  lw $20, 32($sp)\n  lw $21, 36($sp)\n"
    "  lw $22, 40($sp)\n  lw $23, 44($sp)\n  lw $30, 48($sp)\n"
    "  lw $31, 52($sp)\n  lw $28, 56($sp)\n"
#define LWFR(n, o) "  lwc1 $f" #n ", " #o "($sp)\n"
    LWFR(20, 88) LWFR(21, 92) LWFR(22, 96) LWFR(23, 100) LWFR(24, 104)
    LWFR(25, 108) LWFR(26, 112) LWFR(27, 116) LWFR(28, 120) LWFR(29, 124)
    LWFR(30, 128) LWFR(31, 132)
    "  jr $31\n"
    "  addiu $sp, $sp, 448\n"
    ".end wp_trigger\n"

    /* ---------------- wrong-path-only code ---------------- */
    ".p2align 6\n"
    ".globl wp_store\n"
    "wp_store:\n"                       /* $a2 = buf (len 4096) */
    "  lui $8, 0x5566\n  ori $8, $8, 0x7788\n  sw $8, 0($6)\n"
    "  lui $9, 0x1122\n  ori $9, $9, 0x3344\n  sw $9, 4($6)\n"
    "  lw $10, 0($6)\n  lw $11, 4($6)\n"  /* must forward from the sandbox */
    "  sw $10, 8($6)\n  sw $11, 12($6)\n"
    "  lui $12, 0xa5a5\n  ori $12, $12, 0xa5a5\n  sw $12, 64($6)\n"
    "  ori $13, $0, 0x5a\n  sb $13, 4095($6)\n"
    "  swc1 $f0, 128($6)\n"
    "  b wp_clobber\n"
    "  nop\n"

    ".p2align 6\n"
    ".globl wp_store_ro\n"
    "wp_store_ro:\n"                    /* $a2 = wp_rodata */
    "  addiu $8, $0, -1\n"
    "  sw $8, 0($6)\n  sw $8, 4($6)\n"
    "  sw $8, 56($6)\n"
    "  lui $9, %hi(wp_victim_code)\n  addiu $9, $9, %lo(wp_victim_code)\n"
    "  sw $8, 0($9)\n"
    "  lw $10, 0($6)\n"
    "  b wp_spin\n"
    "  nop\n"

    ".p2align 6\n"
    ".globl wp_clobber\n"
    "wp_clobber:\n"
    "  addiu $8, $0, -1\n"
#define FCLOB(n) "  mtc1 $8, $f" #n "\n"
    FCLOB(0) FCLOB(1) FCLOB(2) FCLOB(3) FCLOB(4) FCLOB(5) FCLOB(6)
    FCLOB(7) FCLOB(8) FCLOB(9) FCLOB(10) FCLOB(11) FCLOB(12) FCLOB(13)
    FCLOB(14) FCLOB(15) FCLOB(16) FCLOB(17) FCLOB(18) FCLOB(19) FCLOB(20)
    FCLOB(21) FCLOB(22) FCLOB(23) FCLOB(24) FCLOB(25) FCLOB(26) FCLOB(27)
    FCLOB(28) FCLOB(29) FCLOB(30) FCLOB(31)
    "  ori $8, $0, 1\n  ctc1 $8, $31\n"   /* RM = round toward zero */
    "  lui $8, 0xdead\n  mtlo $8\n  mthi $8\n"
    "  lui $29, 0x1\n"                    /* sp = 0x10000 */
#define XCLOB(n) "  lui $" #n ", 0xbe" #n "\n"
    XCLOB(1) XCLOB(2) XCLOB(3) XCLOB(4) XCLOB(5) XCLOB(6) XCLOB(7)
    XCLOB(8) XCLOB(9) XCLOB(10) XCLOB(11) XCLOB(12) XCLOB(13) XCLOB(14)
    XCLOB(15) XCLOB(16) XCLOB(17) XCLOB(18) XCLOB(19) XCLOB(20)
    XCLOB(21) XCLOB(22) XCLOB(23) XCLOB(24) XCLOB(25) XCLOB(26)
    XCLOB(27) XCLOB(28) XCLOB(30) XCLOB(31)
    "  b wp_spin\n"
    "  nop\n"

    ".globl wp_spin\n"
    "wp_spin:\n"
    "  b wp_spin\n"
    "  nop\n"

    ".p2align 4\n"
    ".globl wp_ud\n"
    "wp_ud:\n"
    "  .word 0xfc000000\n"              /* sd $zero, 0($zero) */
    "  b wp_spin\n"
    "  nop\n"

    ".p2align 4\n"
    ".globl wp_div\n"
    "wp_div:\n"
    "  ori $8, $0, 1\n  move $9, $0\n"
    "  div $0, $8, $9\n"
    "  teq $9, $0, 7\n"
    "  mflo $10\n  sw $10, 24($6)\n"
    "  b wp_spin\n"
    "  nop\n"

    ".p2align 4\n"
    ".globl wp_priv\n"
    "wp_priv:\n"
    "  mfc0 $8, $12\n"
    "  b wp_spin\n"
    "  nop\n"

    ".p2align 4\n"
    ".globl wp_int3\n"
    "wp_int3:\n"
    "  break\n"
    "  b wp_spin\n"
    "  nop\n"

    ".p2align 4\n"
    ".globl wp_load_unmapped\n"
    "wp_load_unmapped:\n"
    "  ori $8, $0, 0x10\n"
    "  lw $9, 0($8)\n"
    "  sw $9, 24($6)\n"
    "  b wp_spin\n"
    "  nop\n"

    ".p2align 4\n"
    ".globl wp_syscall\n"
    "wp_syscall:\n"
    "  ori $2, $0, 4004\n  ori $4, $0, 1\n"   /* write(1, msg, 21) */
    "  lui $5, %hi(wp_leakmsg)\n  addiu $5, $5, %lo(wp_leakmsg)\n"
    "  ori $6, $0, 21\n"
    "  syscall\n"
    "  ori $2, $0, 4001\n  ori $4, $0, 77\n"  /* exit(77) */
    "  syscall\n"
    "  b wp_spin\n"
    "  nop\n"

    ".p2align 4\n"
    ".globl wp_loop\n"
    "wp_loop:\n"
    "  lw $8, 16($6)\n"
    "  addiu $8, $8, 1\n"
    "  sw $8, 16($6)\n"
    "  b wp_loop\n"
    "  addiu $4, $4, 1\n"

    /* correct-path code the wrong path tries to overwrite */
    ".p2align 6\n"
    ".globl wp_victim\n"
    ".globl wp_victim_code\n"
    ".ent wp_victim\n"
    "wp_victim:\n"
    "wp_victim_code:\n"
    "  jr $31\n"
    "  ori $2, $0, 42\n"
    "  nop\n  nop\n"
    ".end wp_victim\n"
    ".set pop\n"
);

uint64_t wp_check(const uint8_t *f)
{
    const uint32_t *post = (const uint32_t *)(f + F_POST);
    const uint32_t *args = (const uint32_t *)(f + F_ARGS);
    uint64_t mask = 0;

    for (int i = 1; i < 32; i++) {
        uint32_t want;
        switch (i) {
        case 4: case 5: case 6: case 7: want = args[i - 4]; break;
        case 28: want = *(const uint32_t *)(f + F_GP); break;
        case 29: want = *(const uint32_t *)(f + F_SP); break;
        default: want = wp_pats[i]; break;
        }
        if (post[i] != want) {
            mask |= 1ull << i;
        }
    }
    if (*(const uint32_t *)(f + F_LO) != wp_lohi[0]) {
        mask |= 1ull << 32;
    }
    if (*(const uint32_t *)(f + F_HI) != wp_lohi[1]) {
        mask |= 1ull << 33;
    }
    if (*(const uint32_t *)(f + F_FCSP) != *(const uint32_t *)(f + F_FCSR)) {
        mask |= 1ull << 34;
    }
    for (int i = 0; i < 32; i++) {
        if (((const uint32_t *)(f + F_F))[i] != wp_fpat) {
            mask |= 1ull << 35;
        }
    }
    return mask;
}

static uint8_t buf[4096] __attribute__((aligned(4096)));
static uint8_t victim_copy[16];
static uint32_t rodata_copy[16];
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

static void run(int test, void *target, void *b, uint32_t len)
{
    uint64_t mask = wp_trigger(test, (uint32_t)(uintptr_t)target, b, len);
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
    memset(pg, 0, 8192);                /* nop = sll $0, $0, 0 */
    mprotect(pg, 4096, PROT_READ | PROT_EXEC);
    mprotect((uint8_t *)pg + 4096, 4096, PROT_NONE);
    __builtin___clear_cache((char *)pg, (char *)pg + 4096);

    run(T1_STORE, wp_store, buf, sizeof(buf));
    run(T1_RO, wp_store_ro, (void *)wp_rodata, 64);
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
    /* T4_REP: MIPS32 has no repeat-string instruction; the plugin SKIPs it */
    run(T5_REPEAT, wp_store, buf, sizeof(buf));

    /* The correct path uses the same code the wrong path ran. */
    printf("[wp-victim] victim=%d\n", wp_victim());
    printf("[wp-victim] %s (%d failures)\n",
           failures ? "FAILED" : "done", failures);
    return failures ? 1 : 0;
}
